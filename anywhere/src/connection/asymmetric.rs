//! AsymmetricConnectionManager: separate uplink and downlink connection pools.
//!
//! For stream-up / packet-up modes where uplink and downlink use different
//! servers, CDNs, or protocols. Each direction has its own `ConnectionManager`.
//!
//! ## Use cases (§11.1)
//!
//! - CDN optimization: uplink -> CDN-A (low latency), downlink -> CDN-B (high bandwidth)
//! - Protocol optimization: uplink -> H2 (compatible), downlink -> H3 (0-RTT)
//! - Censorship evasion: uplink -> CDN (domain fronting), downlink -> direct

use std::sync::Arc;

use async_trait::async_trait;

use crate::connection::{ConnError, ConnectionManager};
use crate::transport::TransportSession;

/// Connection manager that delegates uplink and downlink to separate
/// sub-managers.
///
/// `acquire_uplink()` delegates to the uplink manager, `acquire_downlink()`
/// delegates to the downlink manager. Health requires both to be healthy.
pub struct AsymmetricConnectionManager {
    uplink_mgr: Arc<dyn ConnectionManager>,
    downlink_mgr: Arc<dyn ConnectionManager>,
}

impl AsymmetricConnectionManager {
    pub fn new(
        uplink_mgr: Arc<dyn ConnectionManager>,
        downlink_mgr: Arc<dyn ConnectionManager>,
    ) -> Self {
        Self {
            uplink_mgr,
            downlink_mgr,
        }
    }
}

#[async_trait]
impl ConnectionManager for AsymmetricConnectionManager {
    async fn acquire_uplink(&self) -> Result<Box<dyn TransportSession>, ConnError> {
        self.uplink_mgr.acquire_uplink().await
    }

    async fn acquire_downlink(&self) -> Result<Box<dyn TransportSession>, ConnError> {
        self.downlink_mgr.acquire_downlink().await
    }

    async fn release(&self, _session: Box<dyn TransportSession>) {
        // Sub-managers handle their own release; we can't determine which
        // manager the session came from without inspecting session.kind().
        // In practice, sessions are dropped (not returned to the pool) for
        // asymmetric mode.
    }

    fn is_healthy(&self) -> bool {
        self.uplink_mgr.is_healthy() && self.downlink_mgr.is_healthy()
    }

    async fn shutdown(&self) {
        self.uplink_mgr.shutdown().await;
        self.downlink_mgr.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnError;

    /// A mock connection manager that tracks acquire calls.
    struct MockConnMgr {
        healthy: parking_lot::Mutex<bool>,
        acquire_count: std::sync::atomic::AtomicU32,
    }

    impl MockConnMgr {
        fn new(healthy: bool) -> Self {
            Self {
                healthy: parking_lot::Mutex::new(healthy),
                acquire_count: std::sync::atomic::AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl ConnectionManager for MockConnMgr {
        async fn acquire_uplink(&self) -> Result<Box<dyn TransportSession>, ConnError> {
            self.acquire_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(ConnError::NoAvailable) // Mock: no real session
        }
        async fn acquire_downlink(&self) -> Result<Box<dyn TransportSession>, ConnError> {
            Err(ConnError::NoAvailable)
        }
        async fn release(&self, _session: Box<dyn TransportSession>) {}
        fn is_healthy(&self) -> bool {
            *self.healthy.lock()
        }
        async fn shutdown(&self) {
            *self.healthy.lock() = false;
        }
    }

    #[tokio::test]
    async fn asymmetric_delegates_to_sub_managers() {
        let uplink = Arc::new(MockConnMgr::new(true));
        let downlink = Arc::new(MockConnMgr::new(true));
        let mgr = AsymmetricConnectionManager::new(uplink.clone(), downlink.clone());

        assert!(mgr.is_healthy());

        // acquire_uplink delegates to uplink manager
        let _ = mgr.acquire_uplink().await;
        assert_eq!(
            uplink.acquire_count.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            downlink.acquire_count.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn asymmetric_health_requires_both() {
        let uplink = Arc::new(MockConnMgr::new(true));
        let downlink = Arc::new(MockConnMgr::new(false));
        let mgr = AsymmetricConnectionManager::new(uplink, downlink);

        assert!(!mgr.is_healthy()); // downlink is unhealthy
    }

    #[tokio::test]
    async fn asymmetric_shutdown_both() {
        let uplink = Arc::new(MockConnMgr::new(true));
        let downlink = Arc::new(MockConnMgr::new(true));
        let mgr = AsymmetricConnectionManager::new(uplink.clone(), downlink.clone());

        mgr.shutdown().await;
        assert!(!mgr.is_healthy());
        assert!(!uplink.is_healthy());
        assert!(!downlink.is_healthy());
    }
}
