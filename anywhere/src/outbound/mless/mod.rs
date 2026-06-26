// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Mless outbound — VLESS over multiplexed WebSocket (Hermes protocol).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Weak;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::config::OutboundConfig;
use crate::inbound::Destination;
use crate::outbound::OutboundClient;
use crate::outbound::common::resolve_sni;
use crate::outbound::direct::DirectOutboundClient;
use crate::outbound::vless::parse_uuid;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

use self::frame::FLAG_FIRST;
use self::frame::encode_frame;
use self::multiplexer::MlessMultiplexer;
use self::multiplexer::MlessStreamHandle;
use self::vless::build_vless_header;

pub mod crypto;
pub mod frame;
pub mod multiplexer;
pub mod vless;

/// Mless outbound client.
pub struct MlessOutboundClient {
    multiplexer: tokio::sync::Mutex<Arc<MlessMultiplexer>>,
    uuid: [u8; 16],
    uuid_str: String,
    addr: SocketAddr,
    tls_server: String,
    insecure: bool,
    tls_fp: bool,
    transport_path: String,
    transport_headers: std::collections::HashMap<String, String>,
    consecutive_fails: std::sync::atomic::AtomicU32,
    /// Direct outbound used for UDP ports that mless can't tunnel (e.g. NTP).
    /// Hermes server only supports TCP, so non-DNS UDP must either drop
    /// (QUIC — forces browser TCP fallback) or go direct (NTP, mDNS).
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
        let insecure = cfg.insecure;
        let tls_fp = cfg.fp;

        let transport_type = cfg.transport_type.as_deref().unwrap_or("ws");
        if transport_type != "ws" {
            return Err(format!(
                "mless: unsupported transport type '{transport_type}'"
            )
            .into());
        }
        let transport_path = cfg
            .transport_path
            .clone()
            .unwrap_or_else(|| "/".to_string());
        let mut transport_headers =
            cfg.transport_headers.clone().unwrap_or_default();
        transport_headers
            .entry("Host".to_string())
            .or_insert_with(|| tls_server.clone());

        let multiplexer = MlessMultiplexer::connect(
            addr,
            &uuid_str,
            &tls_server,
            insecure,
            tls_fp,
            &transport_path,
            &transport_headers,
        )
        .await?;
        Ok(Self {
            multiplexer: tokio::sync::Mutex::new(multiplexer),
            uuid,
            uuid_str,
            addr,
            tls_server,
            insecure,
            tls_fp,
            transport_path,
            transport_headers,
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
        let result = MlessMultiplexer::connect(
            self.addr,
            &self.uuid_str,
            &self.tls_server,
            self.insecure,
            self.tls_fp,
            &self.transport_path,
            &self.transport_headers,
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
            // - First byte (`ever_received=false`): 10s. ClientHello is in
            //   flight; if no response in 10s the upstream is unreachable.
            // - Subsequent reads (`ever_received=true`): 300s. This is an
            //   idle period in an established TLS stream (HTTP keep-alive,
            //   HTTP/2 PING gap, WebSocket idle, etc.). Hermes side has a
            //   120s session-wide idle timer that resets on any stream
            //   activity, so 300s here covers browser pool retention even
            //   for the single-stream-on-a-WS edge case.
            let read_timeout = if self.ever_received {
                std::time::Duration::from_secs(300)
            } else {
                std::time::Duration::from_secs(10)
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
                        if self.ever_received { 300 } else { 10 },
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
                let encrypted = {
                    let mut inner = mux.inner.lock();
                    inner.obfuscation.encrypt(&combined)
                };
                let frame = encode_frame(self.stream_id, FLAG_FIRST, &encrypted);
                let _ = mux.ws_tx.send(frame);
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
                let encrypted = {
                    let mut inner = mux.inner.lock();
                    inner.obfuscation.encrypt(&combined)
                };
                let frame =
                    encode_frame(self.handle.stream_id, FLAG_FIRST, &encrypted);
                let _ = mux.ws_tx.send(frame);
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
