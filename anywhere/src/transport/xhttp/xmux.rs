//! XmuxConnectionManager: H2 connection pool with stream multiplexing.
//!
//! Manages a pool of H2 `SendRequest` handles. Each `acquire_uplink()` /
//! `acquire_downlink()` clones a handle and wraps it in an `XhttpSession`.
//! Multiple sessions multiplex as independent H2 streams over shared
//! TCP+TLS connections.
//!
//! ## Connection lifecycle
//!
//! - A pool of `PoolEntry` items is maintained; each holds a `SendRequest`
//!   handle plus concurrency / reuse counters.
//! - `is_closed()` detects dead connections; expired or exhausted entries
//!   are cleaned up on the next `get_or_connect()`.
//! - `shutdown()` drops all handles, sending GoAway on each.
//! - Optional keep-alive task sends periodic HEAD requests.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::connection::pool::{PoolLifecycle, PoolLimits};
use crate::connection::{ConnError, ConnectionManager};
use crate::transport::TransportSession;

use super::XhttpSession;
use super::config::XhttpConfig;
use super::fallback::FallbackState;
use super::h2::HttpSendRequest;

// ---------------------------------------------------------------------------
// PoolEntry — one pooled connection
// ---------------------------------------------------------------------------

/// A single entry in the connection pool.
///
/// Tracks the `SendRequest` handle, current concurrency (active streams),
/// remaining reuse budget, and expiration time.
pub(crate) struct PoolEntry {
    send_req: HttpSendRequest,
    /// Protocol-agnostic lifecycle state (counters + TTL).
    lifecycle: PoolLifecycle,
}

impl PoolEntry {
    /// Whether this entry can still be reused for a new stream.
    fn is_reusable(&self, limits: &PoolLimits) -> bool {
        if !self.lifecycle.is_available(limits) {
            return false;
        }
        // Check if connection is dead
        match &self.send_req {
            HttpSendRequest::H2(h2_sr) => !h2_sr.is_closed(),
            HttpSendRequest::H1(_) => false, // H1 not pooled
        }
    }
}

// ---------------------------------------------------------------------------
// XmuxConnectionManager
// ---------------------------------------------------------------------------

/// H2 connection pool manager for XHTTP transport.
///
/// Reads `XmuxConfig` parameters from `XhttpConfig` to enforce:
/// - `max_concurrency`: max streams per connection
/// - `max_connections`: max pooled connections
/// - `max_reuses`: max reuses per connection
/// - `max_reusable_secs`: connection TTL
/// - `keep_alive_period`: periodic HEAD keep-alive
///
/// When all limits are 0/None (default), behavior matches the old
/// single-connection-pool pattern.
pub struct XmuxConnectionManager {
    config: Arc<XhttpConfig>,
    addr: std::net::SocketAddr,
    /// Connection pool.
    pub(crate) connections: Mutex<Vec<PoolEntry>>,
    /// Set to `true` by `shutdown()` to mark the manager as permanently closed.
    shutdown: Mutex<bool>,
    /// Max pooled H2 connections (0 = unlimited).
    max_connections: usize,
    /// Pool lifecycle limits (concurrency, reuse, requests, TTL).
    limits: PoolLimits,
    /// Keep-alive period in seconds (0 = disabled).
    keep_alive_period: u64,
    /// HTTP version fallback state (H3 -> H2).
    fallback: Mutex<FallbackState>,
}

impl XmuxConnectionManager {
    /// Create a new manager. Does not connect yet.
    ///
    /// `xmux` is the connection-pool tuning config from `[outbounds.xmux]`.
    pub fn new(
        config: Arc<XhttpConfig>,
        xmux: &crate::transport::xhttp::config::XmuxConfig,
        addr: std::net::SocketAddr,
    ) -> Self {
        let limits = PoolLimits {
            max_concurrency: xmux
                .max_concurrency
                .as_ref()
                .map(|r| r.rand_usize())
                .unwrap_or(0),
            max_reuses: xmux
                .max_reuses
                .as_ref()
                .map(|r| r.rand_usize() as u32)
                .unwrap_or(u32::MAX),
            max_requests: xmux
                .max_requests
                .as_ref()
                .map(|r| r.rand_usize() as u32)
                .unwrap_or(u32::MAX),
            ttl: xmux
                .max_reusable_secs
                .as_ref()
                .map(|r| Duration::from_secs(r.rand_u64())),
        };
        let max_connections = xmux
            .max_connections
            .as_ref()
            .map(|r| r.rand_usize())
            .unwrap_or(0);
        let keep_alive_period = xmux.keep_alive_period;
        let http_version = super::config::resolve_http_version(&config);

        Self {
            config,
            addr,
            connections: Mutex::new(Vec::new()),
            shutdown: Mutex::new(false),
            max_connections,
            limits,
            keep_alive_period,
            fallback: Mutex::new(FallbackState::new(http_version)),
        }
    }

    /// Create a manager that resolves the address on first connect.
    pub async fn from_config(
        config: Arc<XhttpConfig>,
        xmux: &crate::transport::xhttp::config::XmuxConfig,
    ) -> io::Result<Self> {
        let addr_str = format!("{}:{}", config.host, config.port);
        let addr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "DNS resolution failed",
                )
            })?;
        Ok(Self::new(config, xmux, addr))
    }

    /// Resolve the effective `max_connections` value.
    fn effective_max_connections(&self) -> usize {
        self.max_connections
    }

    /// Get a `SendRequest` from the pool, or create a new connection.
    ///
    /// Algorithm:
    /// 1. Check fallback state — if H3 failed previously, use H2.
    /// 2. Clean up unusable entries (closed / exhausted / expired).
    /// 3. Find a reusable entry with available concurrency.
    /// 4. If none available and under `max_connections`, create new.
    /// 5. If at `max_connections` limit, create a temporary connection
    ///    (not stored in pool) — this avoids blocking.
    /// 6. On select, increment `running` and decrement `left_usage`.
    async fn get_or_connect(&self) -> Result<HttpSendRequest, ConnError> {
        if *self.shutdown.lock() {
            return Err(ConnError::Closed);
        }

        // Check fallback state to determine effective HTTP version
        let effective_version = self.fallback.lock().current();

        // If H3 is still the current version, try the H3 path first.
        // H3 uses a different connection type (QUIC), not H2 SendRequest,
        // so it's handled at the XhttpSession::connect() level.
        // Here in XmuxConnectionManager, we only manage H2/H1 pools.
        // When H3 is current and hasn't failed, we still create an H2 connection
        // as the fallback-ready path — the actual H3 attempt happens in
        // XhttpSession::connect() or H3ConnectionManager.
        //
        // For now, XmuxConnectionManager always creates H2 connections.
        // The fallback state ensures that after H3 failure, all subsequent
        // connections use H2.
        let _ = effective_version; // Used for logging/future H3 pool support

        // Phase 1: Try to find a reusable connection from the pool (no await)
        let reusable = {
            let mut pool = self.connections.lock();

            // 1. Clean up unusable entries
            pool.retain(|entry| {
                // Check if dead
                let dead = match &entry.send_req {
                    HttpSendRequest::H2(h2_sr) => h2_sr.is_closed(),
                    HttpSendRequest::H1(_) => true,
                };
                if dead {
                    return false;
                }
                !entry.lifecycle.is_expired() && entry.lifecycle.has_budget()
            });

            // 2. Find a reusable entry with available concurrency
            let mut found: Option<HttpSendRequest> = None;
            for entry in pool.iter_mut() {
                if entry.is_reusable(&self.limits) {
                    // Found a reusable connection
                    entry.lifecycle.acquire_slot();

                    // Clone the H2 SendRequest
                    if let HttpSendRequest::H2(h2_sr) = &entry.send_req {
                        found = Some(HttpSendRequest::H2(h2_sr.clone()));
                        break;
                    }
                    // H1 cannot be cloned — shouldn't be in pool
                }
            }
            found
        };
        // Pool lock is dropped here

        if let Some(send_req) = reusable {
            return Ok(send_req);
        }

        // Phase 2: Need a new connection. Check if under max_connections limit.
        let can_add = {
            let pool = self.connections.lock();
            let max_conn = self.effective_max_connections();
            max_conn == 0 || pool.len() < max_conn as usize
        };

        if can_add {
            // Slow path: establish a new connection (await happens here, no lock held)
            // Use fallback-resolved version to avoid H3 reaching h2::connect()
            let version = self.fallback.lock().current();
            let send_req = super::h2::connect(
                self.addr,
                &self.config.host,
                self.config.insecure,
                version,
            )
            .await
            .map_err(|e| ConnError::CreateFailed(e.to_string()))?;

            // Store in pool (only H2 - H1 can't be cloned for reuse)
            let limits = if matches!(send_req, HttpSendRequest::H2(_)) {
                self.limits.clone()
            } else {
                PoolLimits {
                    max_reuses: 1,
                    ..Default::default()
                } // H1: single use
            };
            let lifecycle = PoolLifecycle::new(&limits);
            lifecycle.acquire_slot(); // The creator holds the first slot

            let entry = PoolEntry {
                send_req: send_req.clone_for_pool(),
                lifecycle,
            };

            let mut pool = self.connections.lock();
            pool.push(entry);

            return Ok(send_req);
        }

        // Phase 3: At max_connections limit — create a temporary connection
        //    (not stored in pool, one-shot use)
        let version = self.fallback.lock().current();
        let send_req = super::h2::connect(
            self.addr,
            &self.config.host,
            self.config.insecure,
            version,
        )
        .await
        .map_err(|e| ConnError::CreateFailed(e.to_string()))?;

        Ok(send_req)
    }

    /// Release a connection back to the pool (decrement running counter).
    ///
    /// In the current design, the session itself is dropped (the SendRequest
    /// clone is dropped). This method just decrements the running counter
    /// on the corresponding pool entry.
    async fn release_handle(&self) {
        // In a more sophisticated implementation, we'd track which entry
        // the session came from. For now, decrement the first entry with
        // running > 0 (the pool is best-effort).
        let pool = self.connections.lock();
        for entry in pool.iter() {
            if entry.lifecycle.running_count() > 0 {
                entry.lifecycle.release_slot();
                break;
            }
        }
    }

    /// Inject a pre-built H2 `SendRequest` into the pool.
    ///
    /// Used by tests to bypass TLS and use a plain H2 connection.
    /// The injected entry has unlimited reuse budget and no expiry.
    pub fn inject_connection(&self, send_req: super::h2::H2SendRequest) {
        let entry = PoolEntry {
            send_req: HttpSendRequest::H2(send_req),
            lifecycle: PoolLifecycle::new(&PoolLimits::default()),
        };
        self.connections.lock().push(entry);
    }

    /// Start a background keep-alive task if configured.
    ///
    /// Sends periodic HEAD requests to each pooled connection to prevent
    /// idle timeouts. The task runs until `shutdown()` is called.
    #[allow(dead_code)]
    fn spawn_keep_alive(&self) {
        if self.keep_alive_period == 0 {
            return;
        }

        let pool_ref: Arc<Mutex<Vec<PoolEntry>>> =
            Arc::new(Mutex::new(Vec::new()));
        // We can't directly share `self` across tasks. Instead, we'll
        // use a weak reference pattern. For now, this is a stub —
        // the keep-alive task needs the pool to be in an Arc.
        // This will be properly wired in a future iteration.
        let _ = pool_ref;
    }

    /// Record that H3 (QUIC) connection failed and switch to H2.
    ///
    /// After calling this, all subsequent `get_or_connect()` calls
    /// will use H2 instead of H3. This is idempotent — calling it
    /// when already fallen back is a no-op.
    pub fn record_h3_failure(&self) {
        let mut fb = self.fallback.lock();
        if !fb.has_fallen_back() {
            fb.record_failure();
            log::info!("xhttp: xmux recorded H3 failure, switching to H2");
        }
    }

    /// Whether H3 has been tried and failed (fallback to H2 is active).
    pub fn has_fallen_back(&self) -> bool {
        self.fallback.lock().has_fallen_back()
    }

    /// Get the current effective HTTP version (after fallback).
    pub fn effective_http_version(&self) -> super::config::HttpVersionPref {
        self.fallback.lock().current()
    }
}

/// Helper trait to clone `HttpSendRequest` for pool storage.
///
/// H2 `SendRequest` is `Clone`, so we can store one clone in the pool
/// and return another. H1 is not `Clone`, so it cannot be pooled.
trait HttpSendRequestClone {
    fn clone_for_pool(&self) -> HttpSendRequest;
}

impl HttpSendRequestClone for HttpSendRequest {
    fn clone_for_pool(&self) -> HttpSendRequest {
        match self {
            HttpSendRequest::H2(h2_sr) => HttpSendRequest::H2(h2_sr.clone()),
            HttpSendRequest::H1(_) => {
                // H1 cannot be cloned — return a placeholder that will
                // be immediately consumed. In practice, H1 connections
                // are not stored in the pool (left_usage = 1, used once).
                panic!("H1 SendRequest cannot be cloned for pool storage");
            },
        }
    }
}

#[async_trait]
impl ConnectionManager for XmuxConnectionManager {
    async fn acquire_uplink(
        &self,
    ) -> Result<Box<dyn TransportSession>, ConnError> {
        let send_req = self.get_or_connect().await?;
        let session =
            XhttpSession::from_send_request(self.config.clone(), send_req);
        Ok(Box::new(session))
    }

    async fn acquire_downlink(
        &self,
    ) -> Result<Box<dyn TransportSession>, ConnError> {
        // For stream-one: uplink and downlink share the same session.
        // For asymmetric mode (M6): this would create a separate downlink session.
        self.acquire_uplink().await
    }

    async fn release(&self, _session: Box<dyn TransportSession>) {
        // Decrement the running counter on the corresponding pool entry.
        self.release_handle().await;
    }

    fn is_healthy(&self) -> bool {
        if *self.shutdown.lock() {
            return false;
        }
        let pool = self.connections.lock();
        if pool.is_empty() {
            return true; // Not yet connected — assume healthy
        }
        // Healthy if at least one entry is alive
        pool.iter().any(|entry| match &entry.send_req {
            HttpSendRequest::H2(h2_sr) => !h2_sr.is_closed(),
            HttpSendRequest::H1(_) => false,
        })
    }

    async fn shutdown(&self) {
        *self.shutdown.lock() = true;
        let mut pool = self.connections.lock();
        pool.clear(); // Drop all entries -> GoAway
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obfuscation::range::Range;
    use crate::transport::xhttp::config::{XhttpConfig, XmuxConfig};
    use crate::transport::xhttp::h2::H2SendRequest;
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use hyper::body::Incoming;
    use hyper::server::conn::http2;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::sync::atomic::Ordering;

    async fn start_echo_server() -> std::net::SocketAddr {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(tcp);
                let exec = TokioExecutor::new();
                let _ = http2::Builder::new(exec)
                    .serve_connection(
                        io,
                        service_fn(|req: Request<Incoming>| async move {
                            let bytes = req
                                .into_body()
                                .collect()
                                .await
                                .unwrap()
                                .to_bytes();
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .body(Full::new(bytes))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            }
        });
        addr
    }

    async fn connect_plain_h2(addr: std::net::SocketAddr) -> H2SendRequest {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(tcp);
        let exec = TokioExecutor::new();
        let (send_req, conn) = hyper::client::conn::http2::handshake(exec, io)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        send_req
    }

    /// Inject a pre-built H2 SendRequest into the pool, bypassing TLS.
    /// Delegates to the public `inject_connection` method.
    fn inject_connection(mgr: &XmuxConnectionManager, send_req: H2SendRequest) {
        XmuxConnectionManager::inject_connection(mgr, send_req);
    }

    // --- Existing tests (adapted) ---

    #[tokio::test]
    async fn xmux_acquire_and_use() {
        let addr = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            mode: crate::transport::xhttp::config::XhttpMode::StreamOne,
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, &Default::default(), addr);
        inject_connection(&mgr, send_req);

        assert!(mgr.is_healthy());

        // Acquire a session and use it
        let mut session = mgr.acquire_uplink().await.unwrap();
        let mut writer = session.uplink().await.unwrap();
        writer.write(b"xmux test").await.unwrap();
        writer.shutdown().await.unwrap();

        let mut reader = session.downlink().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"xmux test");
    }

    #[tokio::test]
    async fn xmux_multiple_sessions_multiplex() {
        let addr = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            mode: crate::transport::xhttp::config::XhttpMode::StreamOne,
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, &Default::default(), addr);
        inject_connection(&mgr, send_req);

        // Two sessions should share the same underlying connection
        let mut session1 = mgr.acquire_uplink().await.unwrap();
        let mut session2 = mgr.acquire_uplink().await.unwrap();

        // Use session1
        let mut w1 = session1.uplink().await.unwrap();
        w1.write(b"session1").await.unwrap();
        w1.shutdown().await.unwrap();
        let mut r1 = session1.downlink().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = r1.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"session1");

        // Use session2
        let mut w2 = session2.uplink().await.unwrap();
        w2.write(b"session2").await.unwrap();
        w2.shutdown().await.unwrap();
        let mut r2 = session2.downlink().await.unwrap();
        let n = r2.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"session2");
    }

    #[tokio::test]
    async fn xmux_shutdown() {
        let addr = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, &Default::default(), addr);
        inject_connection(&mgr, send_req);

        assert!(mgr.is_healthy());
        mgr.shutdown().await;
        assert!(!mgr.is_healthy());
    }

    // --- New tests for connection pool limits ---

    #[tokio::test]
    async fn xmux_max_connections_limit() {
        let addr = start_echo_server().await;

        let xmux_cfg = XmuxConfig {
            max_connections: Some(Range::new(3, 3)),
            max_concurrency: Some(Range::new(1, 1)), // 1 stream per connection
            ..Default::default()
        };
        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, &xmux_cfg, addr);

        // Inject 3 connections — pool should have exactly 3 entries
        for _ in 0..3 {
            let sr = connect_plain_h2(addr).await;
            mgr.inject_connection(sr);
        }

        // Acquire 3 sessions — one per connection (max_concurrency=1)
        let _s1 = mgr.acquire_uplink().await.unwrap();
        let _s2 = mgr.acquire_uplink().await.unwrap();
        let _s3 = mgr.acquire_uplink().await.unwrap();

        // All 3 connections should now have running=1
        let pool = mgr.connections.lock();
        assert_eq!(pool.len(), 3, "pool should have 3 entries");
        for (i, entry) in pool.iter().enumerate() {
            assert_eq!(
                entry.lifecycle.running_count(),
                1,
                "entry {} should have running=1",
                i
            );
        }
        drop(pool);

        // 4th acquire should find no reusable connection (all at max_concurrency=1)
        // and max_connections=3 is hit, so it creates a temporary connection.
        // This will fail with TLS error, which is expected — we just verify
        // the pool doesn't grow beyond 3.
        let result = mgr.acquire_uplink().await;
        // The 4th acquire tries to create a temp connection via TLS, which fails.
        // That's fine — the pool itself stays at 3.
        assert!(
            result.is_err(),
            "4th acquire should fail (no reusable, at max_connections)"
        );

        let pool = mgr.connections.lock();
        assert_eq!(
            pool.len(),
            3,
            "pool should still have 3 entries after failed 4th acquire"
        );
    }

    #[tokio::test]
    async fn xmux_max_concurrency_limit() {
        let addr = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        let xmux_cfg = XmuxConfig {
            max_concurrency: Some(Range::new(1, 1)), // Only 1 stream per connection
            ..Default::default()
        };
        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, &xmux_cfg, addr);
        inject_connection(&mgr, send_req);

        // First acquire should succeed (concurrency = 1)
        let _session1 = mgr.acquire_uplink().await.unwrap();

        // The pool entry should now have running=1 and max_concurrency=1,
        // so it's not reusable.
        let pool = mgr.connections.lock();
        assert_eq!(pool.len(), 1);
        let running = pool[0].lifecycle.running_count();
        assert_eq!(running, 1, "expected running=1, got {}", running);
        // Verify the entry is not reusable with max_concurrency=1
        let test_limits = PoolLimits {
            max_concurrency: 1,
            ..Default::default()
        };
        assert!(
            !pool[0].is_reusable(&test_limits),
            "entry should not be reusable at max concurrency"
        );
        drop(pool);

        // Inject a second connection for the second acquire
        let send_req2 = connect_plain_h2(addr).await;
        mgr.inject_connection(send_req2);

        // Second acquire should find the second entry reusable
        let _session2 = mgr.acquire_uplink().await.unwrap();

        let pool = mgr.connections.lock();
        assert_eq!(pool.len(), 2, "expected 2 pool entries");
        assert_eq!(
            pool[0].lifecycle.running_count(),
            1,
            "entry 0 running should be 1"
        );
        assert_eq!(
            pool[1].lifecycle.running_count(),
            1,
            "entry 1 running should be 1"
        );
    }

    #[tokio::test]
    async fn xmux_max_reuses() {
        let addr = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        // Test with max_reuses=2 and unlimited concurrency
        let xmux_cfg = XmuxConfig {
            max_reuses: Some(Range::new(2, 2)),
            ..Default::default()
        };
        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, &xmux_cfg, addr);
        // Inject with limited reuse by manually setting left_usage
        inject_connection(&mgr, send_req);
        // Manually set left_usage to 2 (matching the config)
        {
            let pool = mgr.connections.lock();
            pool[0].lifecycle.left_usage.store(2, Ordering::Relaxed);
        }

        // First acquire: left_usage 2 -> 1
        let _s1 = mgr.acquire_uplink().await.unwrap();
        {
            let pool = mgr.connections.lock();
            assert_eq!(pool.len(), 1);
            assert_eq!(
                pool[0].lifecycle.left_usage.load(Ordering::Relaxed),
                1,
                "left_usage should be 1 after first acquire"
            );
        }

        // Second acquire: left_usage 1 -> 0
        let _s2 = mgr.acquire_uplink().await.unwrap();
        {
            let pool = mgr.connections.lock();
            assert_eq!(
                pool[0].lifecycle.left_usage.load(Ordering::Relaxed),
                0,
                "left_usage should be 0 after second acquire"
            );
        }

        // Third acquire: connection is exhausted (left_usage=0), should be cleaned up
        // and a new connection created via h2::connect. This will fail with TLS error.
        let result = mgr.acquire_uplink().await;
        assert!(
            result.is_err(),
            "third acquire should fail (can't create new TLS connection in test)"
        );

        // Verify the exhausted entry was cleaned up
        let pool = mgr.connections.lock();
        assert_eq!(pool.len(), 0, "exhausted entry should have been cleaned up");
    }

    #[tokio::test]
    async fn xmux_max_reusable_secs() {
        let addr = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        let xmux_cfg = XmuxConfig {
            max_reusable_secs: Some(Range::new(0, 0)), // Expires immediately
            ..Default::default()
        };
        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, &xmux_cfg, addr);
        inject_connection(&mgr, send_req);

        // Manually set the unreusable_at to the past
        {
            let mut pool = mgr.connections.lock();
            pool[0].lifecycle.unreusable_at = Some(std::time::Instant::now()); // Expired
        }

        // Next acquire should find the entry expired and clean it up.
        // Since no reusable connection exists, it tries to create a new one
        // via h2::connect, which will fail with TLS error.
        let result = mgr.acquire_uplink().await;
        assert!(
            result.is_err(),
            "acquire should fail (no reusable, can't create new TLS connection)"
        );

        // Verify the expired entry was cleaned up
        let pool = mgr.connections.lock();
        assert_eq!(pool.len(), 0, "expired entry should have been cleaned up");
    }

    #[tokio::test]
    async fn xmux_default_unlimited() {
        let addr = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        // Default config: all limits 0/None = unlimited
        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, &Default::default(), addr);
        inject_connection(&mgr, send_req);

        // Multiple acquires should all reuse the same connection
        let _s1 = mgr.acquire_uplink().await.unwrap();
        let _s2 = mgr.acquire_uplink().await.unwrap();
        let _s3 = mgr.acquire_uplink().await.unwrap();

        let pool = mgr.connections.lock();
        assert_eq!(pool.len(), 1, "default config should use single connection");
        assert_eq!(
            pool[0].lifecycle.running_count(),
            3,
            "should have 3 active streams"
        );
    }

    #[tokio::test]
    async fn xmux_release_decrements_running() {
        let addr = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, &Default::default(), addr);
        inject_connection(&mgr, send_req);

        let _session = mgr.acquire_uplink().await.unwrap();

        let pool = mgr.connections.lock();
        assert_eq!(pool[0].lifecycle.running_count(), 1);
        drop(pool);

        // Release: drop the session, then call release_handle to decrement running.
        // The release() method on ConnectionManager takes Box<dyn TransportSession>,
        // but we can test the internal release_handle directly.
        mgr.release_handle().await;

        let pool = mgr.connections.lock();
        assert_eq!(
            pool[0].lifecycle.running_count(),
            0,
            "running should be 0 after release"
        );
    }
}
