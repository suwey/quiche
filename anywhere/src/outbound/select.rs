use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;

use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

/// Shared mutable state for a select node, accessible from both the
/// `SelectOutboundClient` (dial path) and the UI handler (selection API).
pub struct SelectState {
    /// Child outbound tags in configuration order.
    pub children: Vec<String>,
    /// Index into `children` of the currently selected outbound.
    pub current: AtomicUsize,
}

impl SelectState {
    /// Set the current selection by child tag name.
    /// Returns `true` if the name was found and selection updated.
    pub fn set_by_name(&self, name: &str) -> bool {
        if let Some(idx) = self.children.iter().position(|c| c == name) {
            self.current.store(idx, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Get the currently selected child's tag name.
    pub fn current_name(&self) -> String {
        let idx = self.current.load(Ordering::Relaxed);
        self.children.get(idx).cloned().unwrap_or_default()
    }
}

/// Manual-selection outbound group: routes all traffic through the
/// user-chosen child. No health checking, no automatic failover.
pub struct SelectOutboundClient {
    pub children: Vec<Arc<dyn OutboundClient>>,
    pub state: Arc<SelectState>,
}

impl SelectOutboundClient {
    /// Build from a tag list, looking up each tag in the registry's clients
    /// map. `initial` overrides the default first-child selection (used to
    /// restore persisted state).
    pub fn new(
        children: Vec<String>,
        registry: &HashMap<String, Arc<dyn OutboundClient>>,
        initial: Option<usize>,
    ) -> Self {
        let child_clients: Vec<Arc<dyn OutboundClient>> = children
            .iter()
            .map(|tag| {
                registry
                    .get(tag)
                    .unwrap_or_else(|| {
                        panic!("select: child outbound '{tag}' not found in registry")
                    })
                    .clone()
            })
            .collect();

        let initial = initial
            .filter(|&i| i < child_clients.len())
            .unwrap_or(0);

        let state = Arc::new(SelectState {
            children: children.clone(),
            current: AtomicUsize::new(initial),
        });

        Self {
            children: child_clients,
            state,
        }
    }
}

#[async_trait]
impl OutboundClient for SelectOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let idx = self.state.current.load(Ordering::Relaxed);
        self.children[idx].dial(dest).await
    }

    async fn dial_udp(
        &self, initial_dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        let idx = self.state.current.load(Ordering::Relaxed);
        self.children[idx].dial_udp(initial_dest).await
    }

    async fn test_latency(&self, host: &str, port: u16) -> Option<u64> {
        let idx = self.state.current.load(Ordering::Relaxed);
        self.children[idx].test_latency(host, port).await
    }
}
