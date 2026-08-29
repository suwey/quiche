//! DNS-over-HTTPS (RFC 8484) client.
//!
//! The transport is `connect_tcp_bypass` + `tokio-rustls` TLS (ALPN `h2`) +
//! `hyper` HTTP/2 POST of the raw DNS wire-format body. Everything bypasses
//! the TUN route so the encrypted query never loops back through itself.
//!
//! To avoid a DoH-to-resolve-DoH deadlock, the DoH server hostname is itself
//! resolved via the plain UDP upstreams (`bootstrap`) — which also bypass TUN
//! — and cached with a TTL. If no plain upstream is available, the system
//! resolver is used as a last resort.

use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use tokio::sync::Mutex;

use tokio::time::timeout;

use crate::dns::upstream::Upstream;
use crate::dns::wire::{build_a_query, first_a_record};
use crate::inbound::Destination;
use crate::outbound::common::bind_udp_bypass;

/// Per-query upstream timeout. Shared with the DnsHijack resolver.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for establishing a fresh DoH connection (TCP + TLS + h2
/// handshake). Kept separate from `QUERY_TIMEOUT` so that a slow connect
/// doesn't eat the budget reserved for the actual DNS exchange.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// TTL for cached bootstrap resolutions. DoH server IPs move rarely; short
/// enough to recover from a stale record, long enough to avoid per-query
/// bootstrap latency.
const BOOTSTRAP_TTL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// TLS connector (rustls + webpki-roots, ALPN "h2")
// ---------------------------------------------------------------------------

use once_cell::sync::Lazy;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

static DOH_TLS_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
    // rustls 0.23 requires an explicit CryptoProvider. reqwest uses ring,
    // so we align with that to avoid pulling in aws-lc-rs (which needs
    // a C compiler for musl cross-compilation).
    let provider = tokio_rustls::rustls::crypto::ring::default_provider();
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
});

static DOH_TLS_CONNECTOR: Lazy<TlsConnector> =
    Lazy::new(|| TlsConnector::from(DOH_TLS_CONFIG.clone()));

// ---------------------------------------------------------------------------
// hyper types
// ---------------------------------------------------------------------------

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use hyper_util::rt::TokioIo;

/// Type alias for the hyper HTTP/2 client sender.
type H2SendRequest = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------
//
// h2's `Connection::poll` calls `maybe_close_connection_if_no_streams()`,
// which sends GoAway(NO_ERROR) only when there are zero active streams AND
// the shared inner state has a single reference (i.e. no `SendRequest`
// handle is still alive).  The previous code dropped its `SendRequest`
// after every query, so the next poll of the background `Connection` driver
// saw refs==1 and tore the connection down — defeating reuse.
//
// Keeping a `SendRequest` clone in `pool` pins the ref count at >= 2, so the
// connection stays open between queries.  Each query takes its own cheap
// `SendRequest` clone (a channel-handle bump, not a new connection) and the
// concurrent exchanges multiplex as independent HTTP/2 streams over a single
// TCP+TLS connection.  A dead connection is detected via `is_closed()` and
// evicted so the next query reconnects.

/// A single DNS-over-HTTPS client.
pub struct DohClient {
    bootstrap: Vec<Destination>,
    hosts: Mutex<HashMap<String, (std::net::IpAddr, Instant)>>,
    /// Pool of reusable h2 `SendRequest` handles keyed by
    /// `"{host}:{ip}:{port}"`.  The canonical entry is kept alive to prevent
    /// h2's idle GoAway; queries clone it so concurrent exchanges multiplex
    /// over one connection.
    pool: Mutex<HashMap<String, H2SendRequest>>,
}

impl DohClient {
    pub fn new(bootstrap: Vec<Destination>) -> Self {
        Self {
            bootstrap,
            hosts: Mutex::new(HashMap::new()),
            pool: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve a DNS query via DoH. Returns the raw DNS response bytes, or
    /// `None` on any transport/TLS/HTTP failure.
    pub async fn resolve(&self, query: &[u8], up: &Upstream) -> Option<Vec<u8>> {
        let (host, path, port) = match up {
            Upstream::Doh { host, path, port } => {
                (host.as_str(), path.as_str(), *port)
            },
            _ => return None,
        };

        let ip =
            match timeout(Duration::from_secs(8), self.bootstrap_resolve(host))
                .await
            {
                Ok(Some(ip)) => ip,
                Ok(None) => {
                    log::warn!("DoH: bootstrap resolve for '{host}' failed");
                    return None;
                },
                Err(_) => {
                    log::warn!("DoH: bootstrap resolve for '{host}' timed out");
                    return None;
                },
            };
        // Acquire a (possibly reused, multiplexed) h2 sender. Concurrent
        // queries to the same upstream share one TCP+TLS+h2 connection.
        let mut send_req =
            match timeout(CONNECT_TIMEOUT, self.get_send(ip, port, host)).await {
                Ok(Some(s)) => s,
                Ok(None) => return None,
                Err(_) => {
                    log::warn!("DoH: connect to {host} ({ip}) timed out");
                    return None;
                },
            };
        match timeout(
            QUERY_TIMEOUT,
            doh_h2_exchange(&mut send_req, host, path, query),
        )
        .await
        {
            Ok(Some(r)) => Some(r),
            Ok(None) => {
                // Exchange failed (HTTP error, send failure, etc.).
                // Evict the pooled entry unconditionally — even if the
                // connection isn't technically closed, a 429/502 response
                // means it's unhealthy and reusing it will just produce
                // more failures.  Evicting forces a reconnect (or fallback
                // to plain UDP) on the next query.
                self.evict(ip, port, host).await;
                None
            },
            Err(_) => {
                log::warn!("DoH: query to {host} timed out");
                self.evict(ip, port, host).await;
                None
            },
        }
    }

    /// Return a `SendRequest` for `{host}` at `{ip}:{port}`, reusing a pooled
    /// h2 connection when one is healthy and establishing a fresh one
    /// otherwise.  The returned handle is a cheap clone; concurrent callers
    /// each get their own clone and multiplex over the same connection.
    async fn get_send(
        &self, ip: std::net::IpAddr, port: u16, host: &str,
    ) -> Option<H2SendRequest> {
        let key = format!("{host}:{ip}:{port}");

        // Fast path: clone a live pooled connection (no network I/O).
        {
            let pool = self.pool.lock().await;
            if let Some(send) = pool.get(&key).filter(|s| !s.is_closed()) {
                return Some(send.clone());
            }
        }

        // Slow path: build a fresh TCP+TLS+h2 connection WITHOUT holding the
        // pool lock, so concurrent queries don't serialise on the handshake.
        // A benign race may build two connections for the same key; the
        // later insert wins and the loser drains and closes once its last
        // clone drops (refs falls to 1, h2 sends GoAway, the driver exits).
        let send = self.connect_h2(ip, port, host).await?;
        self.pool.lock().await.insert(key, send.clone());
        Some(send)
    }

    /// Remove the pooled entry for `{host}:{ip}:{port}` iff it still points
    /// at a closed connection.  A concurrently-reconnected (healthy) entry
    /// is preserved.
    async fn evict(&self, ip: std::net::IpAddr, port: u16, host: &str) {
        let key = format!("{host}:{ip}:{port}");
        let mut pool = self.pool.lock().await;
        if pool.get(&key).is_some_and(|s| s.is_closed()) {
            pool.remove(&key);
        }
    }

    /// Resolve `host` to an IP using cached result, a plain UDP bootstrap
    /// upstream, or (last resort) the system resolver.
    async fn bootstrap_resolve(&self, host: &str) -> Option<std::net::IpAddr> {
        if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
            return Some(std::net::IpAddr::V4(v4));
        }
        if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
            return Some(std::net::IpAddr::V6(v6));
        }

        {
            let cache = self.hosts.lock().await;
            if let Some((ip, _)) = cache
                .get(host)
                .copied()
                .filter(|&(_, exp)| exp > Instant::now())
            {
                return Some(ip);
            }
        }

        let q = build_a_query(host);
        if !self.bootstrap.is_empty() {
            let idx = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as usize % self.bootstrap.len())
                .unwrap_or(0);
            let up = &self.bootstrap[idx];
            if let Some(ip) = self
                .bootstrap_via_udp(&q, up)
                .await
                .and_then(|resp| first_a_record(&resp))
            {
                self.hosts.lock().await.insert(
                    host.to_string(),
                    (ip, Instant::now() + BOOTSTRAP_TTL),
                );
                return Some(ip);
            }
        }

        let host_owned = host.to_string();
        tokio::task::spawn_blocking(move || {
            std::net::ToSocketAddrs::to_socket_addrs(&(host_owned.as_str(), 0u16))
                .ok()
                .and_then(|mut it| it.next())
                .map(|sa| sa.ip())
        })
        .await
        .ok()
        .flatten()
    }

    /// Send a raw DNS query to a plain UDP bootstrap upstream.
    async fn bootstrap_via_udp(
        &self, query: &[u8], upstream: &Destination,
    ) -> Option<Vec<u8>> {
        let addr: std::net::SocketAddr = upstream.to_string().parse().ok()?;
        let sock = bind_udp_bypass("0.0.0.0:0".parse().unwrap()).await.ok()?;
        sock.connect(addr).await.ok()?;
        sock.send(query).await.ok()?;
        let mut buf = vec![0u8; 512];
        let n = timeout(Duration::from_secs(3), sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        Some(buf[..n].to_vec())
    }

    /// Build a fresh DoH h2 connection to `{ip}:{port}` (SNI = `host`).
    ///
    /// TCP connect uses `connect_tcp_bypass` (SO_MARK on Linux /
    /// VpnService.protect on Android) so the encrypted query never loops
    /// back through TUN. TLS uses rustls with ALPN "h2". HTTP/2 uses hyper's
    /// `client::conn::http2::handshake` which has more mature connection
    /// management than raw `h2::client::handshake`.
    async fn connect_h2(
        &self, ip: std::net::IpAddr, port: u16, host: &str,
    ) -> Option<H2SendRequest> {
        let addr = std::net::SocketAddr::new(ip, port);

        // 1) TCP connect (bypasses TUN via SO_MARK / VpnService.protect).
        let tcp = match crate::outbound::common::connect_tcp_bypass(addr).await {
            Ok(t) => t,
            Err(e) => {
                log::warn!("DoH: TCP connect to {ip}:{port} failed: {e}");
                return None;
            },
        };
        let _ = tcp.set_nodelay(true);

        // 2) TLS handshake with ALPN "h2" via tokio-rustls.
        let server_name = match ServerName::try_from(host.to_string()) {
            Ok(n) => n,
            Err(e) => {
                log::warn!("DoH: invalid server name '{host}': {e}");
                return None;
            },
        };
        let tls = match timeout(
            Duration::from_secs(5),
            DOH_TLS_CONNECTOR.connect(server_name, tcp),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                log::warn!("DoH: TLS handshake with {host} ({ip}) failed: {e}");
                return None;
            },
            Err(_) => {
                log::warn!(
                    "DoH: TLS handshake with {host} ({ip}) timed out (5s) — \
                     check bypass routing (table 100)"
                );
                return None;
            },
        };
        // Confirm ALPN negotiated h2.
        let (_, session) = tls.get_ref();
        if !matches!(session.alpn_protocol(), Some(b"h2")) {
            log::warn!("DoH: {host} did not negotiate h2 via ALPN");
            return None;
        }

        // 3) hyper HTTP/2 client handshake. The `Connection` future is
        //    driven in the background for the lifetime of the pooled entry.
        //    Wrap the TLS stream in TokioIo for hyper's Read/Write traits.
        let io = TokioIo::new(tls);
        let exec = hyper_util::rt::TokioExecutor::new();
        let (send_req, conn) =
            match hyper::client::conn::http2::handshake(exec, io).await {
                Ok(c) => c,
                Err(e) => {
                    log::warn!(
                        "DoH: hyper h2 handshake with {host} ({ip}) failed: {e}"
                    );
                    return None;
                },
            };
        // Drive the Connection future in the background. It stays alive as
        // long as the pooled canonical `SendRequest` (and any in-flight
        // clones) hold a reference; once all are dropped h2 sends
        // GoAway(NO_ERROR) and the driver task exits.
        let host_owned = host.to_string();
        tokio::spawn(async move {
            if let Err(_e) = conn.await {
                log::debug!("DoH: conn to {host_owned} ({ip}) closed");
            }
        });
        Some(send_req)
    }
}

/// Drive a single DoH POST over an established (and pooled) hyper h2
/// `SendRequest`.
async fn doh_h2_exchange(
    send_req: &mut H2SendRequest, host: &str, path: &str, query: &[u8],
) -> Option<Vec<u8>> {
    // Wait until the connection can open a new stream.
    if send_req.ready().await.is_err() {
        return None;
    }

    let uri = format!("https://{host}{path}");
    let req = Request::builder()
        .version(http::Version::HTTP_2)
        .method(http::Method::POST)
        .uri(&uri)
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::ACCEPT, "application/dns-message")
        .header(http::header::CONTENT_LENGTH, query.len().to_string())
        .body(Full::new(Bytes::copy_from_slice(query)))
        .ok()?;

    let resp = match send_req.send_request(req).await {
        Ok(r) => r,
        Err(e) => {
            log::warn!("DoH: send_request to {host} failed: {e}");
            return None;
        },
    };

    if resp.status() != http::StatusCode::OK {
        log::warn!("DoH: HTTP status {} from {host}", resp.status());
        return None;
    }

    // Collect the response body.
    let body = resp.into_body();
    let bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            log::warn!("DoH: body read from {host} failed: {e}");
            return None;
        },
    };
    if bytes.is_empty() {
        None
    } else {
        Some(bytes.to_vec())
    }
}
