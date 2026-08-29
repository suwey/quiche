// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Mless outbound — VLESS over multiplexed WebSocket (Hermes protocol).

use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use async_trait::async_trait;
use tokio::sync::Notify;
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
///
/// When `pool_size > 1`, multiple `MlessMultiplexer` instances are created,
/// each with its own WebSocket connection and independent crypto counters.
/// Streams are distributed round-robin across the pool, multiplying TCP
/// throughput and eliminating the single-connection bottleneck.
pub struct MlessOutboundClient {
    /// Pool of multiplexers. Each entry is `(multiplexer, consecutive_fails)`.
    /// A pool of size 1 is equivalent to the old single-multiplexer behavior.
    pool: tokio::sync::Mutex<Vec<MuxSlot>>,
    /// Round-robin index for stream distribution.
    next: AtomicUsize,
    /// Pool size (cached for reconnection logic).
    pool_size: usize,
    /// Maximum MLESS streams per physical connection (0 = unlimited).
    max_streams: usize,
    /// Notified when a stream permit is released.
    capacity_notify: Arc<Notify>,
    uuid: [u8; 16],
    uuid_str: String,
    /// Pluggable connection manager (shared across all pool slots).
    conn_mgr: Arc<dyn ConnectionManager>,
    /// Pluggable crypto factory (shared; each slot creates its own instance).
    crypto_factory: Arc<dyn CryptoFactory>,
    /// Direct outbound used for UDP ports that mless can't tunnel (e.g. NTP).
    direct_fallback: DirectOutboundClient,
}

/// One slot in the mless connection pool.
struct MuxSlot {
    mux: Arc<MlessMultiplexer>,
    consecutive_fails: AtomicU32,
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

        // Determine pool size from [outbounds.xmux].pool_size (default: 5).
        let pool_size = cfg
            .xmux
            .as_ref()
            .and_then(|x| x.pool_size)
            .unwrap_or(5)
            .max(1);
        let max_streams = cfg
            .xmux
            .as_ref()
            .and_then(|x| x.max_concurrency.as_ref())
            .map(|range| range.rand_usize())
            .unwrap_or(0);
        let capacity_notify = Arc::new(Notify::new());

        // Build connection manager from nested [transport] config
        let transport = cfg
            .transport
            .as_ref()
            .ok_or("mless: missing [transport] config")?;
        let conn_mgr: Arc<dyn ConnectionManager> = match transport.type_.as_str()
        {
            "ws" => {
                use crate::connection::SingleConnectionManager;
                use crate::transport::{
                    TransportContext, ws::WsTransportFactory,
                };
                let ws = transport
                    .ws
                    .as_ref()
                    .ok_or("mless: missing [transport.ws] config")?;
                let path = ws.path.clone().unwrap_or_else(|| "/".to_string());
                let mut headers = ws.headers.clone().unwrap_or_default();
                headers
                    .entry("Host".to_string())
                    .or_insert_with(|| tls_server.clone());
                let ctx = TransportContext {
                    server: addr.ip().to_string(),
                    port: addr.port(),
                    tls_server: tls_server.clone(),
                    insecure: cfg.insecure,
                    tls_fp: cfg.fp,
                    path,
                    headers,
                    fragment: if cfg.tls_fragment {
                        Some(cfg.tls_fragment_config.clone().unwrap_or_default())
                    } else {
                        None
                    },
                };
                Arc::new(SingleConnectionManager::new(
                    Box::new(WsTransportFactory),
                    ctx,
                ))
            },
            "xhttp" => {
                use crate::transport::xhttp::config::XmuxConfig;
                use crate::transport::xhttp::{
                    config::HttpVersionPref, xmux::XmuxConnectionManager,
                };
                let xc = transport
                    .xhttp
                    .as_ref()
                    .ok_or("mless: missing [transport.xhttp] config")?;
                let mut xhttp_config = xc.clone();
                if xhttp_config.host.is_empty() {
                    xhttp_config.host = tls_server.clone();
                }
                if xhttp_config.port == 0 {
                    xhttp_config.port = addr.port();
                }
                xhttp_config.insecure = cfg.insecure;
                // mless requires a bidirectional streaming transport (uplink POST
                // body + downlink response body). Force stream-one regardless of
                // the user's mode setting, since packet-up/stream-up would break
                // the mless frame io_loop.
                xhttp_config.mode =
                    crate::transport::xhttp::config::XhttpMode::StreamOne;
                // Hermes router intercepts UUID-like paths as logout
                // (router.ts: uuidRegex.test(访问路径) -> 302 redirect).
                // session_id is a UUID, so placing it in the path triggers
                // a 302. Force query placement to keep the path clean.
                xhttp_config.session_id_placement =
                    crate::transport::xhttp::config::SessionPlacement::Query;
                let xhttp_config = Arc::new(xhttp_config);
                let default_xmux = XmuxConfig::default();
                let xmux_cfg = cfg.xmux.as_ref().unwrap_or(&default_xmux);
                if xhttp_config.http_version == HttpVersionPref::Http3 {
                    use crate::transport::xhttp::h3::H3ConnectionManager;
                    Arc::new(
                        H3ConnectionManager::from_config(xhttp_config, xmux_cfg)
                            .await?,
                    )
                } else {
                    Arc::new(
                        XmuxConnectionManager::from_config(
                            xhttp_config,
                            xmux_cfg,
                        )
                        .await?,
                    )
                }
            },
            other => {
                return Err(format!(
                    "mless: unsupported transport type '{other}'"
                )
                .into());
            },
        };

        // Build crypto factory
        let crypto_factory: Arc<dyn CryptoFactory> =
            Arc::new(self::crypto::AheadXorFactory);

        // Connect all multiplexer instances in the pool.
        // Each gets its own WS connection and independent crypto state.
        let mut slots = Vec::with_capacity(pool_size);
        for i in 0..pool_size {
            let mux = MlessMultiplexer::connect_pluggable(
                conn_mgr.clone(),
                crypto_factory.clone(),
                &uuid_str,
                max_streams,
                capacity_notify.clone(),
            )
            .await?;
            if pool_size > 1 {
                log::info!("mless: pool slot {}/{} connected", i + 1, pool_size);
            }
            slots.push(MuxSlot {
                mux,
                consecutive_fails: AtomicU32::new(0),
            });
        }

        Ok(Self {
            pool: tokio::sync::Mutex::new(slots),
            next: AtomicUsize::new(0),
            pool_size,
            max_streams,
            capacity_notify,
            uuid,
            uuid_str,
            conn_mgr,
            crypto_factory,
            direct_fallback: DirectOutboundClient::default(),
        })
    }

    async fn try_register_stream(
        &self,
    ) -> Option<(Arc<MlessMultiplexer>, u64, mpsc::UnboundedReceiver<Vec<u8>>)>
    {
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.pool_size;
        let pool = self.pool.lock().await;
        for offset in 0..pool.len() {
            let slot = &pool[(start + offset) % pool.len()];
            if slot.mux.dead.load(Ordering::Relaxed) {
                continue;
            }
            if let Some((stream_id, rx)) = slot.mux.try_register_stream() {
                return Some((slot.mux.clone(), stream_id, rx));
            }
        }
        None
    }

    async fn claim_dead_slot(&self) -> (Option<usize>, bool) {
        let pool = self.pool.lock().await;
        let mut has_reconnecting = false;
        for (idx, slot) in pool.iter().enumerate() {
            if !slot.mux.dead.load(Ordering::Relaxed) {
                continue;
            }
            if slot.mux.reconnecting.load(Ordering::Acquire) {
                has_reconnecting = true;
                continue;
            }
            if !slot.mux.reconnecting.swap(true, Ordering::Acquire) {
                return (Some(idx), has_reconnecting);
            }
            has_reconnecting = true;
        }
        (None, has_reconnecting)
    }

    async fn reconnect_slot(&self, idx: usize) -> Option<Arc<MlessMultiplexer>> {
        let fails = {
            let pool = self.pool.lock().await;
            pool[idx].consecutive_fails.fetch_add(1, Ordering::Relaxed)
        };
        let delay_secs = (2u64).pow(fails.min(5)).min(30);
        log::info!(
            "{}: pool slot {} reconnecting... (attempt {}, backoff {}s)",
            self.log_tag(),
            idx,
            fails + 1,
            delay_secs,
        );
        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

        let result = MlessMultiplexer::connect_pluggable(
            self.conn_mgr.clone(),
            self.crypto_factory.clone(),
            &self.uuid_str,
            self.max_streams,
            self.capacity_notify.clone(),
        )
        .await;

        // Extract the result before locking the pool to avoid holding
        // a non-Send `Box<dyn StdError>` across an await boundary.
        let new_mux = result.ok();

        let mut pool = self.pool.lock().await;
        pool[idx].mux.reconnecting.store(false, Ordering::Release);

        if let Some(new_mux) = new_mux {
            pool[idx].consecutive_fails.store(0, Ordering::Relaxed);
            pool[idx].mux = new_mux.clone();
            drop(pool);
            log::info!("{}: pool slot {} reconnected", self.log_tag(), idx);
            Some(new_mux)
        } else {
            log::warn!("{}: pool slot {} reconnect failed", self.log_tag(), idx);
            None
        }
    }

    async fn open_stream(
        &self,
    ) -> Result<
        (Arc<MlessMultiplexer>, u64, mpsc::UnboundedReceiver<Vec<u8>>),
        Box<dyn std::error::Error>,
    > {
        loop {
            if let Some(stream) = self.try_register_stream().await {
                return Ok(stream);
            }

            let (claimed_slot, has_reconnecting) = self.claim_dead_slot().await;
            if let Some(idx) = claimed_slot {
                let mux = self
                    .reconnect_slot(idx)
                    .await
                    .ok_or("mless: connection unavailable")?;
                if let Some((stream_id, rx)) = mux.try_register_stream() {
                    return Ok((mux, stream_id, rx));
                }
                continue;
            }
            if has_reconnecting {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }

            let notified = self.capacity_notify.notified();
            tokio::pin!(notified);
            if let Some(stream) = self.try_register_stream().await {
                return Ok(stream);
            }
            notified.await;
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
        let (mux, stream_id, rx) = self.open_stream().await?;
        let vless_header = build_vless_header(&self.uuid, dest, false);
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
                let (mux, stream_id, rx) = self.open_stream().await?;
                let header = build_vless_header(&self.uuid, dest, true);
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
                        mux.close_stream(self.stream_id);
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
            mux.close_stream(self.stream_id);
        }
        Ok(())
    }
}

impl Drop for MlessStreamRelay {
    fn drop(&mut self) {
        if let Some(mux) = self.multiplexer.upgrade() {
            mux.close_stream(self.stream_id);
        }
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
