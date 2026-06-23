use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use tokio::sync::RwLock;

use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

/// Check whether a `dial_udp` error is an expected protocol limitation
/// (e.g. "UDP not supported") rather than a real connectivity failure.
/// Expected errors should NOT mark the child as failed.
fn is_udp_expected(msg: &str) -> bool {
    msg == crate::outbound::common::ERR_UDP_NOT_SUPPORTED
}

/// A single latency test result for one child outbound.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LatencyRecord {
    pub time: DateTime<Utc>,
    pub delay: u64,
}

/// Minimum improvement (%) required to switch away from the current urltest
/// child. Prevents flapping between nodes with similar latencies.
const HYSTERESIS_PCT: u64 = 30;

/// Shared mutable state for a urltest node, accessible from both the
/// `UrlTestOutboundClient` (background test task) and the UI handler.
pub struct UrlTestState {
    pub children: Vec<String>,
    pub current: AtomicUsize,
    pub records: Vec<RwLock<Option<LatencyRecord>>>,
    /// Failed children, tracked per-dial for immediate fallback.
    pub failed: Vec<AtomicBool>,
}

pub struct UrlTestOutboundClient {
    pub children: Vec<Arc<dyn OutboundClient>>,
    pub state: Arc<UrlTestState>,
    pub test_url: String,
}

impl UrlTestOutboundClient {
    /// Build from tag list, looking up each tag in the registry's clients map.
    pub fn new(
        children: Vec<String>,
        registry: &std::collections::HashMap<String, Arc<dyn OutboundClient>>,
        test_url: String,
    ) -> Self {
        let child_clients: Vec<Arc<dyn OutboundClient>> = children
            .iter()
            .map(|tag| {
                registry
                    .get(tag)
                    .unwrap_or_else(|| panic!("urltest: child outbound '{tag}' not found in registry"))
                    .clone()
            })
            .collect();

        let state = Arc::new(UrlTestState {
            children: children.clone(),
            current: AtomicUsize::new(0),
            records: children.iter().map(|_| RwLock::new(None)).collect(),
            failed: children.iter().map(|_| AtomicBool::new(false)).collect(),
        });

        Self {
            children: child_clients,
            state,
            test_url,
        }
    }

    fn best_child_index(&self) -> usize {
        let current_idx = self.state.current.load(Ordering::Relaxed);

        // Read the current node's last-recorded delay as the hysteresis baseline.
        let current_delay = self.state.records[current_idx]
            .try_read()
            .ok()
            .and_then(|r| r.as_ref().map(|rec| rec.delay));

        let mut best = current_idx;
        let mut best_delay = current_delay.unwrap_or(u64::MAX);
        for (i, record) in self.state.records.iter().enumerate() {
            // Skip children currently marked as failed.
            if self.state.failed[i].load(Ordering::Relaxed) {
                continue;
            }

            if let Ok(r) = record.try_read() {
                if let Some(rec) = r.as_ref() {
                    if i == current_idx {
                        if rec.delay < best_delay {
                            best_delay = rec.delay;
                        }
                        continue;
                    }

                    // Hysteresis: non-current child must beat current by at
                    // least HYSTERESIS_PCT% to avoid flapping.
                    let must_beat = current_delay
                        .map(|cur| cur.saturating_mul(100 - HYSTERESIS_PCT) / 100)
                        .unwrap_or(0);

                    if rec.delay < must_beat && rec.delay < best_delay {
                        best_delay = rec.delay;
                        best = i;
                    }
                }
            }
        }

        best
    }
}

#[async_trait]
impl OutboundClient for UrlTestOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let idx = self.best_child_index();
        match self.children[idx].dial(dest).await {
            Ok(relay) => {
                self.state.current.store(idx, Ordering::Relaxed);
                return Ok(relay);
            },
            Err(e) => {
                log::warn!(
                    "urltest: child '{}' dial failed: {e}",
                    self.state.children[idx]
                );
                self.state.failed[idx].store(true, Ordering::Relaxed);
            },
        }

        // Fallback: try other non-failed, non-direct children.
        for (i, child) in self.children.iter().enumerate() {
            if i == idx {
                continue;
            }
            if self.state.failed[i].load(Ordering::Relaxed) {
                continue;
            }
            if self.state.children[i] == "direct" {
                continue;
            }

            match child.dial(dest).await {
                Ok(relay) => {
                    log::info!(
                        "urltest: fallback to child '{}'",
                        self.state.children[i]
                    );
                    self.state.current.store(i, Ordering::Relaxed);
                    return Ok(relay);
                },
                Err(e) => {
                    log::warn!(
                        "urltest: fallback child '{}' dial failed: {e}",
                        self.state.children[i]
                    );
                    self.state.failed[i].store(true, Ordering::Relaxed);
                },
            }
        }

        // All children failed.
        Err("all urltest children unavailable".into())
    }

    async fn dial_udp(
        &self, initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        let idx = self.best_child_index();
        match self.children[idx].dial_udp(initial_dest).await {
            Ok(relay) => {
                self.state.current.store(idx, Ordering::Relaxed);
                return Ok(relay);
            },
            Err(e) => {
                let msg = e.to_string();
                if !is_udp_expected(&msg) {
                    log::warn!(
                        "urltest: child '{}' dial_udp failed: {msg}",
                        self.state.children[idx]
                    );
                }
                // Do NOT mark child as failed — UDP support is optional.
                // A dial_udp failure does not indicate the child is broken
                // for TCP traffic.
            },
        }

        for (i, child) in self.children.iter().enumerate() {
            if i == idx {
                continue;
            }
            if self.state.failed[i].load(Ordering::Relaxed) {
                continue;
            }
            if self.state.children[i] == "direct" {
                continue;
            }

            match child.dial_udp(initial_dest).await {
                Ok(relay) => {
                    log::info!(
                        "urltest: udp fallback to child '{}'",
                        self.state.children[i]
                    );
                    self.state.current.store(i, Ordering::Relaxed);
                    return Ok(relay);
                },
                Err(e) => {
                    let msg = e.to_string();
                    if is_udp_expected(&msg) {
                        log::warn!(
                            "urltest: udp fallback child '{}': {msg}",
                            self.state.children[i]
                        );
                    } else {
                        log::error!(
                            "urltest: udp fallback child '{}' failed: {msg}",
                            self.state.children[i]
                        );
                    }
                },
            }
        }

        Err("all urltest children unavailable".into())
    }

    async fn test_latency(&self, host: &str, port: u16) -> Option<u64> {
        // Clear all failed marks — latency test is the recovery signal.
        for f in &self.state.failed {
            f.store(false, Ordering::Relaxed);
        }
        let current_idx = self.state.current.load(Ordering::Relaxed);

        // Snapshot the current child's delay for hysteresis comparison.
        let current_delay = self.state.records[current_idx]
            .try_read()
            .ok()
            .and_then(|r| r.as_ref().map(|rec| rec.delay));

        let mut best_idx = current_idx;
        let mut best_delay = current_delay.unwrap_or(u64::MAX);

        for (i, child) in self.children.iter().enumerate() {
            // Skip latency test for the "direct" outbound — it has no proxy
            // to test against and always adds cost without useful signal.
            if self.state.children[i] == "direct" {
                continue;
            }

            let latency = child.test_latency(host, port).await;

            let record = latency.map(|d| LatencyRecord {
                time: Utc::now(),
                delay: d,
            });
            {
                let mut rec = self.state.records[i].write().await;
                *rec = record;
            }

            if let Some(d) = latency {
                if i == current_idx {
                    if d < best_delay {
                        best_delay = d;
                        best_idx = i;
                    }
                } else {
                    // Hysteresis: only switch to a non-current child if it
                    // beats the current by at least HYSTERESIS_PCT%.
                    let must_beat = current_delay
                        .map(|cur| cur.saturating_mul(100 - HYSTERESIS_PCT) / 100)
                        .unwrap_or(0);

                    if d < must_beat && d < best_delay {
                        best_delay = d;
                        best_idx = i;
                    }
                }
            }
        }

        self.state.current.store(best_idx, Ordering::Relaxed);
        log::info!(
            "urltest: selected child '{}' (delay={}ms)",
            self.state.children[best_idx],
            best_delay,
        );

        if best_delay == u64::MAX {
            None
        } else {
            Some(best_delay)
        }
    }
}

/// Spawns a background task that periodically tests all children and
/// selects the best one via the urltest client's `test_latency`. A
/// latency test runs immediately on start, then every `interval_secs`.
pub fn spawn_test_loop(
    client: Arc<dyn OutboundClient>, test_url: String, interval_secs: u64,
) {
    tokio::spawn(async move {
        // Test immediately, then every interval.
        loop {
            client.test_latency(&test_url, 443).await;
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    });
}
