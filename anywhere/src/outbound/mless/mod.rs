// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Mless outbound — VLESS over multiplexed WebSocket (Hermes protocol).

use std::sync::Arc;
use std::sync::Weak;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::config::OutboundConfig;
use crate::connection::ConnectionManager;
use crate::crypto::CryptoFactory;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::outbound::common::resolve_sni;
use crate::outbound::direct::DirectOutboundClient;
use crate::outbound::vless::parse_uuid;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

use self::frame::FLAG_FIRST;
use self::multiplexer::MlessMessage;
use self::multiplexer::MlessMultiplexer;
use self::multiplexer::MlessStreamHandle;
use self::vless::build_vless_header;

pub mod crypto;
pub mod frame;
pub mod multiplexer;
pub mod vless;

/// Mless outbound client.
///
/// M4: Uses pluggable `ConnectionManager` + `CryptoFactory` instead of
/// raw connection parameters. Supports both WS and XHTTP transports.
pub struct MlessOutboundClient {
    multiplexer: tokio::sync::Mutex<Arc<MlessMultiplexer>>,
    uuid: [u8; 16],
    uuid_str: String,
    /// Pluggable connection manager (for reconnection).
    conn_mgr: Arc<dyn ConnectionManager>,
    /// Pluggable crypto factory.
    crypto_factory: Arc<dyn CryptoFactory>,
    consecutive_fails: std::sync::atomic::AtomicU32,
    /// Direct outbound used for UDP ports that mless can't tunnel (e.g. NTP).
    direct_fallback: DirectOutboundClient,
}

impl MlessOutboundClient {
    pub async fn from_config(
        configs: Vec<&OutboundConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cfg = configs
            .into_iter()
            .next()
            .ok_or("mless: no config provided")?;
        let server =
            cfg.server.as_deref().ok_or("mless: missing server field")?;

        let tls_server = resolve_sni(cfg).map_err(|e| format!("mless: {e}"))?;
        let addr = crate::outbound::common::resolve_addr(server)
            .map_err(|e| format!("mless: {e}"))?;
        let uuid_str = cfg
            .password
            .as_deref()
            .ok_or("mless: missing password (uuid)")?;
        let uuid = parse_uuid(uuid_str)?;
        let uuid_str = uuid_str.to_string();

        // Build connection manager from nested [transport] config
        let transport = cfg.transport.as_ref().ok_or("mless: missing [transport] config")?;
        let conn_mgr: Arc<dyn ConnectionManager> = match transport.type_.as_str() {
            "ws" => {
                use crate::connection::SingleConnectionManager;
                use crate::transport::{TransportContext, ws::WsTransportFactory};
                let ws = transport.ws.as_ref().ok_or("mless: missing [transport.ws] config")?;
                let path = ws.path.clone().unwrap_or_else(|| "/".to_string());
                let mut headers = ws.headers.clone().unwrap_or_default();
                headers.entry("Host".to_string()).or_insert_with(|| tls_server.clone());
                let ctx = TransportContext {
                    server: addr.ip().to_string(),
                    port: addr.port(),
                    tls_server: tls_server.clone(),
                    insecure: cfg.insecure,
                    tls_fp: cfg.fp,
                    path,
                    headers,
                    fragment: if cfg.tls_fragment {
                        Some(crate::tlsfragment::FragmentConfig::default())
                    } else { None },
                };
                Arc::new(SingleConnectionManager::new(Box::new(WsTransportFactory), ctx))
            }
            "xhttp" => {
                use crate::transport::xhttp::{config::HttpVersionPref, xmux::XmuxConnectionManager};
                let xc = transport.xhttp.as_ref().ok_or("mless: missing [transport.xhttp] config")?;
                let mut xhttp_config = xc.clone();
                if xhttp_config.host.is_empty() { xhttp_config.host = tls_server.clone(); }
                if xhttp_config.port == 0 { xhttp_config.port = addr.port(); }
                xhttp_config.insecure = cfg.insecure;
                let xhttp_config = Arc::new(xhttp_config);
                if xhttp_config.http_version == HttpVersionPref::Http3 {
                    use crate::transport::xhttp::h3::H3ConnectionManager;
                    Arc::new(H3ConnectionManager::new(xhttp_config))
                } else {
                    Arc::new(XmuxConnectionManager::from_config(xhttp_config).await?)
                }
            }
            other => return Err(format!("mless: unsupported transport type '{other}'").into()),
        };

        // Build crypto factory
        let crypto_factory: Arc<dyn CryptoFactory> =
            Arc::new(self::crypto::AheadXorFactory);

        // Connect via pluggable architecture
        let multiplexer = MlessMultiplexer::connect_pluggable(
            conn_mgr.clone(),
            crypto_factory.clone(),
            &uuid_str,
        )
        .await?;

        Ok(Self {
            multiplexer: tokio::sync::Mutex::new(multiplexer),
            uuid,
            uuid_str,
            conn_mgr,
            crypto_factory,
            consecutive_fails: std::sync::atomic::AtomicU32::new(0),
            direct_fallback: DirectOutboundClient,
        })
    }

    async fn get_or_reconnect(&self) -> Arc<MlessMultiplexer> {
        {
            let mux = self.multiplexer.lock().await;
            if !mux.dead.load(std::sync::atomic::Ordering::Relaxed) {
                return mux.clone();
            }
            if mux
                .reconnecting
                .swap(true, std::sync::atomic::Ordering::Acquire)
            {
                drop(mux);
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                let mux = self.multiplexer.lock().await;
                return mux.clone();
            }
        }
        let fails = self
            .consecutive_fails
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let delay_secs = (2u64).pow(fails.min(5)).min(30);
        log::info!(
            "{}: reconnecting... (attempt {}, backoff {}s)",
            self.log_tag(),
            fails + 1,
            delay_secs,
        );
        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
        let result = MlessMultiplexer::connect_pluggable(
            self.conn_mgr.clone(),
            self.crypto_factory.clone(),
            &self.uuid_str,
        )
        .await;
        let new_mux = result.ok();
        let mut mux = self.multiplexer.lock().await;
        mux.reconnecting
            .store(false, std::sync::atomic::Ordering::Release);
        if let Some(new_mux) = new_mux {
            self.consecutive_fails
                .store(0, std::sync::atomic::Ordering::Relaxed);
            *mux = new_mux.clone();
            drop(mux);
            log::info!("{}: reconnected", self.log_tag());
            new_mux
        } else {
            log::warn!("{}: reconnect failed", self.log_tag());
            mux.clone()
        }
    }

    fn log_tag(&self) -> String {
        format!(
            "mless/{:02x}{:02x}{:02x}{:02x}",
            self.uuid[0], self.uuid[1], self.uuid[2], self.uuid[3]
        )
    }
}

#[async_trait]
impl OutboundClient for MlessOutboundClient {
    async fn dial(
        &self, dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        let mux = self.get_or_reconnect().await;
        if mux.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("mless: connection unavailable".into());
        }
        let vless_header = build_vless_header(&self.uuid, dest, false);
        let (stream_id, rx) = mux.register_stream();
        log::debug!(
            "{}: dial tcp {dest} -> stream#{}",
            self.log_tag(),
            stream_id
        );
        Ok(Box::new(MlessStreamRelay {
            stream_id,
            rx,
            multiplexer: Arc::downgrade(&mux),
            first_write: true,
            vless_header,
            read_buf: Vec::new(),
            read_pos: 0,
            ever_received: false,
            pending_vless_response: true,
            vless_resp_prefix: Vec::new(),
        }))
    }

    async fn dial_udp(
        &self, dest: &Destination,
    ) -> Result<Box<dyn PacketRelay>, Box<dyn std::error::Error>> {
        // Port-based UDP policy. Hermes server only forwards DNS (port 53)
        // because Cloudflare Workers has no outbound UDP socket API; DNS
        // works via the TCP fallback defined in RFC 7766.
        //
        // - 53 (DNS):       go through mless → hermes → TCP-53 upstream
        // - 443 (QUIC):     reject. Browsers retry over TCP automatically;
        //                   pretending to succeed would only stall HTTP/3.
        // - 123 (NTP), 5353 (mDNS), 137-139 (NetBIOS), 67/68 (DHCP):
        //                   direct. These talk to local/time services that
        //                   don't need proxying.
        // - Anything else:  reject (consistent with prior behavior).
        match dest.port {
            53 => {
                let mux = self.get_or_reconnect().await;
                if mux.dead.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err("mless: connection unavailable".into());
                }
                let header = build_vless_header(&self.uuid, dest, true);
                let (stream_id, rx) = mux.register_stream();
                log::debug!(
                    "{}: dial udp {dest} -> stream#{}",
                    self.log_tag(),
                    stream_id
                );
                Ok(Box::new(MlessPacketRelay {
                    handle: MlessStreamHandle {
                        stream_id,
                        rx,
                        multiplexer: Arc::downgrade(&mux),
                    },
                    vless_header: header,
                    first_write: true,
                }))
            },
            443 => {
                // QUIC: fail fast so the browser falls back to TCP/HTTP-2.
                log::debug!(
                    "{}: rejecting udp/443 (QUIC) — browser will fall back to TCP",
                    self.log_tag(),
                );
                Err(crate::outbound::common::ERR_UDP_NOT_SUPPORTED.into())
            },
            123 | 5353 | 137 | 138 | 139 | 67 | 68 => {
                log::debug!(
                    "{}: udp/{} -> direct (local/time service)",
                    self.log_tag(),
                    dest.port,
                );
                self.direct_fallback.dial_udp(dest).await
            },
            _ => Err(crate::outbound::common::ERR_UDP_NOT_SUPPORTED.into()),
        }
    }
}
/// TCP stream relay backed by a Mless multiplexed stream.
///
/// The first `write()` sends a combined FIRST+DATA frame so the server
/// has the TLS ClientHello to forward immediately after connecting.
///
/// Reads are internally buffered so callers see a byte-stream interface
/// regardless of how data arrives in channel messages.
///
/// The server prepends a 2-byte VLESS response header `[version, addon_len]`
/// to the first data frame. We must consume and discard it before returning
/// payload bytes to the caller.
pub struct MlessStreamRelay {
    stream_id: u64,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    multiplexer: Weak<MlessMultiplexer>,
    first_write: bool,
    vless_header: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
    ever_received: bool,
    /// Whether we still need to skip the 2-byte VLESS response header
    /// from the first received data chunk.
    pending_vless_response: bool,
    /// Partial buffer for accumulating the 2-byte VLESS response header
    /// when it arrives split across chunks.
    vless_resp_prefix: Vec<u8>,
}

#[async_trait]
impl StreamRelay for MlessStreamRelay {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read_pos >= self.read_buf.len() {
            // Two timeouts:
            // - First byte (`ever_received=false`): 30s. CF Worker cold
            //   start / concurrency limits can delay first response by
            //   10-40s. 30s balances patience vs. leaking stale streams.
            // - Subsequent reads (`ever_received=true`): 300s. This is an
            //   idle period in an established TLS stream (HTTP keep-alive,
            //   HTTP/2 PING gap, WebSocket idle, etc.). Hermes side has a
            //   120s session-wide idle timer that resets on any stream
            //   activity, so 300s here covers browser pool retention even
            //   for the single-stream-on-a-WS edge case.
            let read_timeout = if self.ever_received {
                std::time::Duration::from_secs(300)
            } else {
                std::time::Duration::from_secs(30)
            };
            match tokio::time::timeout(read_timeout, self.rx.recv()).await {
                Ok(Some(data)) => {
                    let mut data = data;
                    // Strip the 2-byte VLESS response header [version, addon_len]
                    // from the first data chunk(s).
                    if self.pending_vless_response {
                        let needed = 2 - self.vless_resp_prefix.len();
                        if data.len() < needed {
                            // Not enough bytes yet; buffer and wait for more.
                            self.vless_resp_prefix.extend_from_slice(&data);
                            self.ever_received = true;
                            // Recursively retry reading the next chunk.
                            return self.read(buf).await;
                        }
                        // Consume the remaining header bytes.
                        let header_rest = &data[..needed];
                        self.vless_resp_prefix.extend_from_slice(header_rest);
                        let header = &self.vless_resp_prefix;
                        log::debug!(
                            "mless: stream#{} vless response head={:02x?}",
                            self.stream_id,
                            header,
                        );
                        if header[1] != 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("vless response status {}", header[1]),
                            ));
                        }
                        data = data[needed..].to_vec();
                        self.vless_resp_prefix.clear();
                        self.pending_vless_response = false;
                    }
                    self.read_buf = data;
                    self.read_pos = 0;
                    self.ever_received = true;
                },
                Ok(None) => {
                    log::debug!(
                        "mless: stream#{} rx channel closed (server sent CLOSE or disconnected)",
                        self.stream_id,
                    );
                    return Ok(0);
                },
                Err(_) => {
                    log::debug!(
                        "mless: stream#{} timeout ({}s), closing",
                        self.stream_id,
                        if self.ever_received { 300 } else { 30 },
                    );
                    if let Some(mux) = self.multiplexer.upgrade() {
                        mux.close_stream(self.stream_id).await;
                    }
                    return Ok(0);
                },
            }
        }
        let available = self.read_buf.len() - self.read_pos;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(
            &self.read_buf[self.read_pos..self.read_pos + to_copy],
        );
        self.read_pos += to_copy;
        if self.read_pos >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_pos = 0;
        }
        Ok(to_copy)
    }

    async fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if let Some(mux) = self.multiplexer.upgrade() {
            if self.first_write {
                // First write: send VLESS header + data as a single FIRST frame.
                let mut combined =
                    Vec::with_capacity(self.vless_header.len() + buf.len());
                combined.extend_from_slice(&self.vless_header);
                combined.extend_from_slice(buf);
                // Send plaintext - io_loop handles encryption
                let _ = mux.ws_tx.send(MlessMessage::Data {
                    stream_id: self.stream_id,
                    flags: FLAG_FIRST,
                    payload: combined,
                });
                self.first_write = false;
            } else {
                mux.send_data(self.stream_id, buf);
            }
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        if let Some(mux) = self.multiplexer.upgrade() {
            mux.close_stream(self.stream_id).await;
        }
        Ok(())
    }
}

/// UDP packet relay backed by a Mless multiplexed stream.
pub struct MlessPacketRelay {
    handle: MlessStreamHandle,
    vless_header: Vec<u8>,
    /// First datagram still needs the VLESS header prepended; subsequent
    /// datagrams are raw payloads sent as plain DATA frames.
    first_write: bool,
}

#[async_trait]
impl PacketRelay for MlessPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> std::io::Result<(usize, Destination)> {
        match self.handle.rx.recv().await {
            Some(data) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                let dest = Destination {
                    address: crate::inbound::Address::Ipv4([8, 8, 4, 4]),
                    port: 53,
                    resolved_ip: None,
                };
                Ok((len, dest))
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "mless stream closed",
            )),
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], _dest: &Destination,
    ) -> std::io::Result<()> {
        if let Some(mux) = self.handle.multiplexer.upgrade() {
            if self.first_write {
                // First datagram: bundle VLESS header + payload into a single
                // FIRST frame so the server can connect to the upstream
                // immediately.
                let mut combined =
                    Vec::with_capacity(self.vless_header.len() + buf.len());
                combined.extend_from_slice(&self.vless_header);
                combined.extend_from_slice(buf);
                // Send plaintext - io_loop handles encryption
                let _ = mux.ws_tx.send(MlessMessage::Data {
                    stream_id: self.handle.stream_id,
                    flags: FLAG_FIRST,
                    payload: combined,
                });
                self.first_write = false;
            } else {
                mux.send_data(self.handle.stream_id, buf);
            }
        }
        Ok(())
    }

    async fn close(&mut self) -> std::io::Result<()> {
        self.handle.close().await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// End-to-end test: mless over XHTTP stream-one
// ---------------------------------------------------------------------------

#[cfg(test)]
mod mless_xhttp_tests {
    use super::*;
    use crate::crypto::CryptoFactory;
    use crate::transport::xhttp::h2::{make_stream_body, H2SendRequest};
    use crate::transport::xhttp::{config::XhttpConfig, xmux::XmuxConnectionManager};
    use bytes::Bytes;
    use http_body::Frame;
    use http_body_util::BodyExt;
    use hyper::body::Incoming;
    use hyper::server::conn::http2;
    use hyper::service::service_fn;
    use hyper::Request;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    /// Streaming echo server: echoes H2 POST body frames back as response
    /// body frames, without waiting for the full request body.
    async fn start_streaming_echo() -> std::net::SocketAddr {
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
                            let (tx, body) = make_stream_body(16);
                            let mut req_body = req.into_body();
                            tokio::spawn(async move {
                                loop {
                                    match req_body.frame().await {
                                        Some(Ok(frame)) => {
                                            if let Some(data) = frame.data_ref() {
                                                if tx
                                                    .send(Ok(Frame::data(data.clone())))
                                                    .await
                                                    .is_err()
                                                {
                                                    break;
                                                }
                                            }
                                        }
                                        Some(Err(_)) => break,
                                        None => break,
                                    }
                                }
                            });
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .body(body)
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
        let (send_req, conn) =
            hyper::client::conn::http2::handshake(exec, io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        send_req
    }

    #[tokio::test]
    async fn mless_over_xhttp_echo() {
        let addr = start_streaming_echo().await;
        let send_req = connect_plain_h2(addr).await;

        // Build XHTTP connection manager with injected SendRequest
        let xhttp_config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            port: addr.port(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(xhttp_config, addr);
        *mgr.canonical.lock() = Some(send_req);
        let conn_mgr: Arc<dyn ConnectionManager> = Arc::new(mgr);

        // Build crypto factory
        let crypto_factory: Arc<dyn CryptoFactory> =
            Arc::new(self::crypto::AheadXorFactory);
        let uuid_str = "00000000-0000-4000-8000-000000000000";

        // Connect multiplexer via pluggable architecture
        let mux = MlessMultiplexer::connect_pluggable(
            conn_mgr,
            crypto_factory,
            uuid_str,
        )
        .await
        .unwrap();

        // Register a stream
        let (stream_id, mut rx) = mux.register_stream();

        // Send plaintext data - io_loop will encrypt and write to transport
        mux.send_data(stream_id, b"hello mless over xhttp");

        // Read echoed data back (with timeout - the io_loop needs time to process)
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rx.recv(),
        )
        .await
        .expect("timeout waiting for echo")
        .expect("stream channel closed");

        assert_eq!(received, b"hello mless over xhttp");
    }

    #[tokio::test]
    async fn mless_over_xhttp_multiple_frames() {
        let addr = start_streaming_echo().await;
        let send_req = connect_plain_h2(addr).await;

        let xhttp_config = Arc::new(XhttpConfig {
            host: "localhost".to_string(),
            port: addr.port(),
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        let mgr = XmuxConnectionManager::new(xhttp_config, addr);
        *mgr.canonical.lock() = Some(send_req);
        let conn_mgr: Arc<dyn ConnectionManager> = Arc::new(mgr);

        let crypto_factory: Arc<dyn CryptoFactory> =
            Arc::new(self::crypto::AheadXorFactory);
        let uuid_str = "00000000-0000-4000-8000-000000000000";

        let mux = MlessMultiplexer::connect_pluggable(
            conn_mgr,
            crypto_factory,
            uuid_str,
        )
        .await
        .unwrap();

        let (stream_id, mut rx) = mux.register_stream();

        // Send multiple frames
        mux.send_data(stream_id, b"frame1");
        mux.send_data(stream_id, b"frame2");
        mux.send_data(stream_id, b"frame3");

        // Read all frames back
        let r1 = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout 1")
            .expect("channel closed 1");
        let r2 = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout 2")
            .expect("channel closed 2");
        let r3 = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout 3")
            .expect("channel closed 3");

        assert_eq!(r1, b"frame1");
        assert_eq!(r2, b"frame2");
        assert_eq!(r3, b"frame3");
    }
}
