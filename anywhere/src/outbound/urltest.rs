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

/// Selection strategy for a urltest group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SelectMode {
    /// Manual selection, no health check, no automatic failover.
    /// Pin is equivalent to manual selection.
    Select,
    /// Pick the lowest-latency child (with hysteresis to avoid flapping).
    Latency,
    /// Pick the first alive child in configured order (fallback semantics).
    Seq,
}

impl Default for SelectMode {
    fn default() -> Self {
        Self::Latency
    }
}

impl SelectMode {
    /// Parse from a config string.
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "seq" | "fallback" => Self::Seq,
            "select" | "selector" => Self::Select,
            _ => Self::Latency,
        }
    }

    /// Whether this mode runs a background health-check loop.
    pub fn needs_health_check(self) -> bool {
        self != Self::Select
    }
}

/// Shared mutable state for a urltest group, accessible from both the
/// `UrlTestOutboundClient` (dial path) and the UI handler (selection API).
pub struct UrlTestState {
    pub children: Vec<String>,
    pub current: AtomicUsize,
    pub records: Vec<RwLock<Option<LatencyRecord>>>,
    /// Failed children, tracked per-dial for immediate fallback.
    pub failed: Vec<AtomicBool>,
    /// Pinned child index (`usize::MAX` = not fixed / auto mode).
    /// When set, `dial` uses this child first. If the pinned child is
    /// marked failed, dial falls back to mode-based selection until the
    /// next `test_latency` clears the failure.
    pub fixed: AtomicUsize,
    /// Selection strategy.
    pub mode: SelectMode,
}

impl UrlTestState {
    /// Pin the group to a child by name. Returns `true` if found.
    pub fn set_fixed_by_name(&self, name: &str) -> bool {
        if let Some(idx) = self.children.iter().position(|c| c == name) {
            self.fixed.store(idx, Ordering::Relaxed);
            self.current.store(idx, Ordering::Relaxed);
            // Clear failed mark so dial uses the pinned child immediately.
            self.failed[idx].store(false, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Clear the pin, returning to auto mode.
    pub fn clear_fixed(&self) {
        self.fixed.store(usize::MAX, Ordering::Relaxed);
    }

    /// The pinned child index, if any.
    pub fn fixed_index(&self) -> Option<usize> {
        let f = self.fixed.load(Ordering::Relaxed);
        (f != usize::MAX).then_some(f)
    }

    /// The pinned child name, or empty string if not fixed.
    pub fn fixed_name(&self) -> String {
        self.fixed_index()
            .and_then(|i| self.children.get(i))
            .cloned()
            .unwrap_or_default()
    }
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
        mode: SelectMode,
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
            fixed: AtomicUsize::new(usize::MAX),
            mode,
        });

        Self {
            children: child_clients,
            state,
            test_url,
        }
    }

    /// Choose the best child index based on mode, skipping failed children.
    fn best_child_index(&self) -> usize {
        let current_idx = self.state.current.load(Ordering::Relaxed);

        // Select mode: no automatic selection — use current (manual).
        if self.state.mode == SelectMode::Select {
            return current_idx;
        }

        // Seq mode (fallback): first non-failed child in order.
        if self.state.mode == SelectMode::Seq {
            for (i, failed) in self.state.failed.iter().enumerate() {
                if !failed.load(Ordering::Relaxed) {
                    return i;
                }
            }
            // All failed — return the first child as a last resort.
            return 0;
        }

        // Latency mode: pick the lowest-latency child with hysteresis.
        let current_delay = self.state.records[current_idx]
            .try_read()
            .ok()
            .and_then(|r| r.as_ref().map(|rec| rec.delay));

        let mut best = current_idx;
        let mut best_delay = current_delay.unwrap_or(u64::MAX);
        for (i, record) in self.state.records.iter().enumerate() {
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

    /// Resolve the dial index: pinned child if available (not failed),
    /// otherwise mode-based selection.
    fn dial_index(&self) -> usize {
        if let Some(pin) = self.state.fixed_index() {
            if !self.state.failed[pin].load(Ordering::Relaxed) {
                return pin;
            }
            // Pinned child is failed — fall through to mode-based selection.
        }
        self.best_child_index()
    }
}

#[async_trait]
impl OutboundClient for UrlTestOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let idx = self.dial_index();
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

        // Select mode: no fallback — fail immediately.
        if self.state.mode == SelectMode::Select {
            return Err(format!(
                "select: child '{}' unavailable",
                self.state.children[idx]
            ).into());
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

        Err("all urltest children unavailable".into())
    }

    async fn dial_udp(
        &self, initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        let idx = self.dial_index();
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
            },
        }

        // Select mode: no fallback for UDP either.
        if self.state.mode == SelectMode::Select {
            return Err(format!(
                "select: child '{}' udp unavailable",
                self.state.children[idx]
            ).into());
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

        // Select mode: only test the current (manual) child.
        if self.state.mode == SelectMode::Select {
            let idx = self.state.current.load(Ordering::Relaxed);
            if self.state.children[idx] == "direct" {
                return None;
            }
            let latency = self.children[idx].test_latency(host, port).await;
            let record = latency.map(|d| LatencyRecord {
                time: Utc::now(),
                delay: d,
            });
            let mut rec = self.state.records[idx].write().await;
            *rec = record;
            return latency;
        }

        let current_idx = self.state.current.load(Ordering::Relaxed);
        let current_delay = self.state.records[current_idx]
            .try_read()
            .ok()
            .and_then(|r| r.as_ref().map(|rec| rec.delay));

        let mut best_idx = current_idx;
        let mut best_delay = current_delay.unwrap_or(u64::MAX);

        for (i, child) in self.children.iter().enumerate() {
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

        // Don't switch when pinned; still test all children to keep
        // their latency records fresh and clear failed marks so a
        // recovered pinned child is used on the next dial.
        if self.state.fixed_index().is_none() {
            if self.state.mode == SelectMode::Seq {
                let mut chosen = current_idx;
                for (i, failed) in self.state.failed.iter().enumerate() {
                    if !failed.load(Ordering::Relaxed)
                        && self.state.records[i].try_read()
                            .ok()
                            .and_then(|r| r.as_ref().map(|rec| rec.delay))
                            .is_some()
                    {
                        chosen = i;
                        break;
                    }
                }
                self.state.current.store(chosen, Ordering::Relaxed);
                log::info!(
                    "urltest(seq): selected child '{}'",
                    self.state.children[chosen],
                );
            } else {
                self.state.current.store(best_idx, Ordering::Relaxed);
                log::info!(
                    "urltest: selected child '{}' (delay={}ms)",
                    self.state.children[best_idx],
                    best_delay,
                );
            }
        }

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
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Test immediately, then every interval.
        loop {
            client.test_latency(&test_url, 443).await;
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    })
}
