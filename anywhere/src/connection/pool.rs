//! Generic connection pool lifecycle primitives.
//!
//! [`PoolLifecycle`] tracks the protocol-agnostic state of a pooled
//! connection: concurrency count, reuse budget, request budget, and TTL.
//! Protocol-specific resources (H2 `SendRequest`, H3 `QuicConnection`,
//! WebSocket, AnyTLS session) live alongside it in the caller's struct.
//!
//! Shared by `transport/xhttp/xmux.rs` (H2) and `transport/xhttp/h3.rs`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Configuration limits for a generic connection pool entry.
#[derive(Debug, Clone)]
pub struct PoolLimits {
    /// Max concurrent streams/requests per connection (0 = unlimited).
    pub max_concurrency: usize,
    /// Max times a connection can be reused (u32::MAX = unlimited).
    pub max_reuses: u32,
    /// Max total requests a connection can serve (u32::MAX = unlimited).
    pub max_requests: u32,
    /// Connection TTL (None = no expiry).
    pub ttl: Option<Duration>,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            max_concurrency: 0,
            max_reuses: u32::MAX,
            max_requests: u32::MAX,
            ttl: None,
        }
    }
}

/// Lifecycle state for a pooled connection.
///
/// Tracks concurrency, reuse budget, request budget, and expiration.
/// This struct is deliberately protocol-agnostic: the caller composes it
/// with their own connection resource and supplies a "is dead" check.
pub struct PoolLifecycle {
    pub(crate) running: AtomicU32,
    pub(crate) left_usage: AtomicU32,
    pub(crate) left_requests: AtomicU32,
    pub(crate) unreusable_at: Option<Instant>,
    #[allow(dead_code)]
    created_at: Instant,
}

impl PoolLifecycle {
    /// Create with full budgets derived from `limits`.
    pub fn new(limits: &PoolLimits) -> Self {
        let now = Instant::now();
        Self {
            running: AtomicU32::new(0),
            left_usage: AtomicU32::new(limits.max_reuses),
            left_requests: AtomicU32::new(limits.max_requests),
            unreusable_at: limits.ttl.map(|t| now + t),
            created_at: now,
        }
    }

    /// Whether this entry has budget and has not expired.
    /// Does NOT check concurrency or connection health (caller does).
    pub fn has_budget(&self) -> bool {
        self.left_usage.load(Ordering::Relaxed) > 0
            && self.left_requests.load(Ordering::Relaxed) > 0
    }

    /// Whether the TTL has elapsed.
    pub fn is_expired(&self) -> bool {
        self.unreusable_at
            .map(|t| Instant::now() >= t)
            .unwrap_or(false)
    }

    /// Whether all limits allow acquiring a new stream.
    /// Combines budget, TTL, and concurrency checks.
    pub fn is_available(&self, limits: &PoolLimits) -> bool {
        if !self.has_budget() {
            return false;
        }
        if self.is_expired() {
            return false;
        }
        if limits.max_concurrency > 0 {
            let running = self.running.load(Ordering::Relaxed);
            if running as usize >= limits.max_concurrency {
                return false;
            }
        }
        true
    }

    /// Record that a stream/request was acquired on this connection.
    /// Increments running, decrements usage and request budgets.
    pub fn acquire_slot(&self) {
        self.running.fetch_add(1, Ordering::Relaxed);
        self.left_usage.fetch_sub(1, Ordering::Relaxed);
        self.left_requests.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record that a stream/request completed on this connection.
    pub fn release_slot(&self) {
        self.running.fetch_sub(1, Ordering::Relaxed);
    }

    /// Current number of active concurrent streams.
    pub fn running_count(&self) -> u32 {
        self.running.load(Ordering::Relaxed)
    }
}
