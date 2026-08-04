//! XmuxConnectionManager: H2 connection pool with stream multiplexing.
//!
//! Manages a pool of H2 `SendRequest` handles. Each `acquire_uplink()` /
//! `acquire_downlink()` clones a handle and wraps it in an `XhttpSession`.
//! Multiple sessions multiplex as independent H2 streams over shared
//! TCP+TLS connections.
//!
//! ## Connection lifecycle
//!
//! - A "canonical" `SendRequest` is kept in the pool to prevent h2's
//!   idle GoAway (same pattern as the DoH client).
//! - `is_closed()` detects dead connections; the next acquire creates
//!   a new one.
//! - `shutdown()` drops all handles, sending GoAway on each.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::connection::{ConnError, ConnectionManager};
use crate::transport::TransportSession;

use super::config::XhttpConfig;
use super::h2::HttpSendRequest;
use super::XhttpSession;

/// H2 connection pool manager for XHTTP transport.
///
/// Uses a single H2 connection per server (like the DoH client pattern).
/// The connection is established lazily on first `acquire_*()` and reused
/// for all subsequent sessions via `SendRequest::clone()`.
pub struct XmuxConnectionManager {
    config: Arc<XhttpConfig>,
    addr: std::net::SocketAddr,
    /// Canonical SendRequest kept alive to prevent h2 idle GoAway.
    /// Cloned per-session; `None` when not yet connected or after shutdown.
    pub(crate) canonical: Mutex<Option<HttpSendRequest>>,
    /// Set to `true` by `shutdown()` to mark the manager as permanently closed.
    shutdown: Mutex<bool>,
}

impl XmuxConnectionManager {
    /// Create a new manager. Does not connect yet.
    pub fn new(config: Arc<XhttpConfig>, addr: std::net::SocketAddr) -> Self {
        Self {
            config,
            addr,
            canonical: Mutex::new(None),
            shutdown: Mutex::new(false),
        }
    }

    /// Create a manager that resolves the address on first connect.
    pub async fn from_config(
        config: Arc<XhttpConfig>,
    ) -> io::Result<Self> {
        let addr_str = format!("{}:{}", config.host, config.port);
        let addr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::AddrNotAvailable, "DNS resolution failed")
            })?;
        Ok(Self::new(config, addr))
    }

    /// Get a `SendRequest` from the pool, or create a new connection.
    async fn get_or_connect(&self) -> Result<HttpSendRequest, ConnError> {
        // Fast path: clone the canonical handle (H2 only - H1 is not Clone)
        {
            let guard = self.canonical.lock();
            if let Some(sr) = &*guard {
                match sr {
                    HttpSendRequest::H2(h2_sr) => {
                        if !h2_sr.is_closed() {
                            return Ok(HttpSendRequest::H2(h2_sr.clone()));
                        }
                    }
                    HttpSendRequest::H1(_) => {
                        // H1 SendRequest is not Clone; always create new
                    }
                }
            }
        }

        // Slow path: establish a new connection
        let send_req = super::h2::connect(self.addr, &self.config.host, self.config.insecure, self.config.http_version)
            .await
            .map_err(|e| ConnError::CreateFailed(e.to_string()))?;

        // Store H2 as canonical (H1 can't be cloned for reuse)
        if let HttpSendRequest::H2(h2_sr) = &send_req {
            let mut guard = self.canonical.lock();
            *guard = Some(HttpSendRequest::H2(h2_sr.clone()));
        }

        Ok(send_req)
    }
}

#[async_trait]
impl ConnectionManager for XmuxConnectionManager {
    async fn acquire_uplink(&self) -> Result<Box<dyn TransportSession>, ConnError> {
        let send_req = self.get_or_connect().await?;
        let session = XhttpSession::from_send_request(self.config.clone(), send_req);
        Ok(Box::new(session))
    }

    async fn acquire_downlink(&self) -> Result<Box<dyn TransportSession>, ConnError> {
        // For stream-one: uplink and downlink share the same session.
        // For asymmetric mode (M6): this would create a separate downlink session.
        self.acquire_uplink().await
    }

    async fn release(&self, _session: Box<dyn TransportSession>) {
        // Session is dropped; the SendRequest clone is also dropped.
        // The underlying H2 connection stays alive via the canonical handle.
    }

    fn is_healthy(&self) -> bool {
        if *self.shutdown.lock() {
            return false;
        }
        let guard = self.canonical.lock();
        match &*guard {
            Some(sr) => match sr {
                HttpSendRequest::H2(h2_sr) => !h2_sr.is_closed(),
                HttpSendRequest::H1(_) => false,
            },
            None => true, // Not yet connected - assume healthy
        }
    }

    async fn shutdown(&self) {
        *self.shutdown.lock() = true;
        let mut guard = self.canonical.lock();
        guard.take(); // Drop canonical -> GoAway
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::xhttp::config::XhttpConfig;
    use hyper::body::Incoming;
    use hyper::server::conn::http2;
    use hyper::service::service_fn;
    use hyper::Request;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use http_body_util::{BodyExt, Full};

    async fn start_echo_server() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { break };
                let io = TokioIo::new(tcp);
                let exec = TokioExecutor::new();
                let _ = http2::Builder::new(exec)
                    .serve_connection(
                        io,
                        service_fn(|req: Request<Incoming>| async move {
                            let bytes = req.into_body().collect().await.unwrap().to_bytes();
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
        let (send_req, conn) = hyper::client::conn::http2::handshake(exec, io).await.unwrap();
        tokio::spawn(async move { let _ = conn.await; });
        send_req
    }

    #[tokio::test]
    async fn xmux_acquire_and_use() {
        let addr = start_echo_server().await;
        let send_req = connect_plain_h2(addr).await;

        let config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, addr);
        // Inject the pre-built connection
        *mgr.canonical.lock() = Some(send_req);

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
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(config, addr);
        *mgr.canonical.lock() = Some(send_req);

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
        let mgr = XmuxConnectionManager::new(config, addr);
        *mgr.canonical.lock() = Some(send_req);

        assert!(mgr.is_healthy());
        mgr.shutdown().await;
        assert!(!mgr.is_healthy());
    }
}
