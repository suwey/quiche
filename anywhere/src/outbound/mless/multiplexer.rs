// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Mless stream multiplexer - pluggable transport, async io_loop.
//!
//! M4 refactoring: the multiplexer no longer directly calls `build_ws()`.
//! Instead, it accepts a `ConnectionManager` (for transport sessions) and
//! a `CryptoFactory` (for encryption). The `io_loop` is async and operates
//! on `TransportSession` + `CryptoLayer` trait objects.
//!
//! ## Data flow (refactored)
//!
//! ```text
//! send_data()  -> MlessMessage::Data(plaintext)  -> channel
//! io_loop: channel -> crypto.encrypt() -> encode_frame() -> uplink.write()
//! io_loop: downlink.read() -> decode_frame() -> crypto.decrypt() -> on_frame(plaintext)
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::sync::mpsc;

use crate::connection::ConnectionManager;
use crate::crypto::{CryptoFactory, CryptoLayer};
use crate::transport::TransportSession;

use super::crypto::AheadXorFactory;
use super::frame::*;

// ---------------------------------------------------------------------------
// MlessMessage - channel message from multiplexer to io_loop
// ---------------------------------------------------------------------------

/// Message sent from the multiplexer methods to the io_loop.
///
/// The io_loop handles encryption and frame encoding - callers send
/// plaintext payloads.
#[derive(Debug)]
pub enum MlessMessage {
    /// Data frame with plaintext payload (io_loop will encrypt).
    Data {
        stream_id: u64,
        flags: u8,
        payload: Vec<u8>,
    },
    /// Close frame (no payload, no encryption needed).
    Close {
        stream_id: u64,
    },
}

// ---------------------------------------------------------------------------
// MlessStreamHandle
// ---------------------------------------------------------------------------

/// Handle for an open Mless stream.
pub struct MlessStreamHandle {
    pub stream_id: u64,
    pub rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub(crate) multiplexer: Weak<MlessMultiplexer>,
}

impl MlessStreamHandle {
    pub async fn close(&mut self) {
        if let Some(mux) = self.multiplexer.upgrade() {
            mux.close_stream(self.stream_id).await;
        }
    }
}

// ---------------------------------------------------------------------------
// MlessMultiplexer
// ---------------------------------------------------------------------------

/// Shared multiplexer state.
pub(crate) struct MlessMultiplexerInner {
    pub(crate) streams: HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>,
    pub(crate) active_streams: std::collections::HashSet<u64>,
}

/// Mless stream multiplexer.
///
/// M4: Uses pluggable `ConnectionManager` + `CryptoFactory`. The io_loop
/// is async and operates on `TransportSession` + `CryptoLayer` trait objects.
pub struct MlessMultiplexer {
    pub(crate) inner: Mutex<MlessMultiplexerInner>,
    pub(crate) ws_tx: mpsc::UnboundedSender<MlessMessage>,
    pub disconnected: Notify,
    pub(crate) next_stream_id: AtomicU64,
    pub(crate) dead: AtomicBool,
    pub(crate) reject_count: AtomicU32,
    pub(crate) reconnecting: AtomicBool,
}

impl MlessMultiplexer {
    /// Connect using pluggable components.
    ///
    /// Acquires a `TransportSession` from the `ConnectionManager`, creates
    /// a `CryptoLayer` from the `CryptoFactory`, and spawns an async io_loop
    /// that handles encryption/decryption and frame I/O.
    pub async fn connect_pluggable(
        conn_mgr: Arc<dyn ConnectionManager>,
        crypto_factory: Arc<dyn CryptoFactory>,
        uuid_str: &str,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        log::debug!("mless: acquiring transport session...");
        let session = conn_mgr
            .acquire_uplink()
            .await
            .map_err(|e| format!("mless: acquire transport failed: {e}"))?;

        log::debug!("mless: creating crypto layer...");
        let crypto = crypto_factory.create(uuid_str);

        let (ws_tx, ws_rx): (mpsc::UnboundedSender<MlessMessage>, _) =
            mpsc::unbounded_channel();

        let mux = Arc::new(Self {
            inner: Mutex::new(MlessMultiplexerInner {
                streams: HashMap::new(),
                active_streams: std::collections::HashSet::new(),
            }),
            ws_tx,
            disconnected: Notify::new(),
            next_stream_id: AtomicU64::new(1),
            dead: AtomicBool::new(false),
            reject_count: AtomicU32::new(0),
            reconnecting: AtomicBool::new(false),
        });

        log::debug!("mless: spawning async io_loop...");
        let mux_clone = Arc::downgrade(&mux);
        tokio::spawn(async move {
            io_loop(session, crypto, ws_rx, mux_clone).await;
        });

        Ok(mux)
    }

    /// Backward-compatible connect using WS transport.
    ///
    /// Builds a `SingleConnectionManager` + `WsTransportFactory` and
    /// delegates to `connect_pluggable()`.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        addr: SocketAddr,
        uuid_str: &str,
        tls_server: &str,
        insecure: bool,
        tls_fp: bool,
        fragment: Option<&crate::tlsfragment::FragmentConfig>,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        use crate::connection::SingleConnectionManager;
        use crate::transport::{TransportContext, ws::WsTransportFactory};

        let ctx = TransportContext {
            server: format!("{}:{}", addr.ip(), addr.port()),
            port: addr.port(),
            tls_server: tls_server.to_string(),
            insecure,
            tls_fp,
            path: path.to_string(),
            headers: headers.clone(),
            fragment: fragment.cloned(),
        };
        let conn_mgr: Arc<dyn ConnectionManager> = Arc::new(SingleConnectionManager::new(
            Box::new(WsTransportFactory),
            ctx,
        ));
        let crypto_factory: Arc<dyn CryptoFactory> = Arc::new(AheadXorFactory);

        Self::connect_pluggable(conn_mgr, crypto_factory, uuid_str).await
    }

    /// Register a new stream without sending any frame.
    pub fn register_stream(
        self: &Arc<Self>,
    ) -> (u64, mpsc::UnboundedReceiver<Vec<u8>>) {
        let stream_id = self
            .next_stream_id
            .fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut inner = self.inner.lock();
            inner.streams.insert(stream_id, tx);
            log::debug!(
                "mless: NEW stream#{} (active: {})",
                stream_id,
                inner.streams.len(),
            );
        }
        (stream_id, rx)
    }

    pub async fn close_stream(&self, stream_id: u64) {
        let removed = {
            let mut inner = self.inner.lock();
            inner.streams.remove(&stream_id)
        };
        if removed.is_none() {
            return;
        }
        let active = {
            let inner = self.inner.lock();
            inner.streams.len()
        };
        log::debug!(
            "mless: CLOSE stream#{} sent (active: {})",
            stream_id,
            active,
        );
        let _ = self.ws_tx.send(MlessMessage::Close { stream_id });
    }

    /// Send plaintext data - the io_loop handles encryption.
    pub fn send_data(&self, stream_id: u64, data: &[u8]) {
        let _ = self.ws_tx.send(MlessMessage::Data {
            stream_id,
            flags: FLAG_DATA,
            payload: data.to_vec(),
        });
    }

    /// Called by the io_loop with **already-decrypted** payload.
    fn on_frame(&self, stream_id: u64, flags: u8, payload: Vec<u8>) {
        if stream_id == 0 {
            return;
        }

        if flags & FLAG_CLOSE != 0 {
            let mut inner = self.inner.lock();
            let was_active = inner.active_streams.remove(&stream_id);
            inner.streams.remove(&stream_id);
            if !was_active {
                let rejects = self
                    .reject_count
                    .fetch_add(1, Ordering::Relaxed) +
                    1;
                log::warn!(
                    "mless: CLOSE stream#{} rejected ({}, active: {})",
                    stream_id,
                    rejects,
                    inner.streams.len(),
                );
                if rejects >= 30 {
                    log::warn!(
                        "mless: {} consecutive rejections, marking dead",
                        rejects
                    );
                    self.dead.store(true, Ordering::Relaxed);
                    self.reject_count
                        .store(0, Ordering::Relaxed);
                }
            } else {
                self.reject_count
                    .store(0, Ordering::Relaxed);
                log::debug!(
                    "mless: CLOSE stream#{} (active: {})",
                    stream_id,
                    inner.streams.len(),
                );
            }
            return;
        }

        // payload is already decrypted by the io_loop
        let hex_preview = payload
            .iter()
            .take(16)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        log::debug!(
            "mless: DATA stream#{} {}B [{}] -> channel",
            stream_id,
            payload.len(),
            hex_preview,
        );

        let mut inner = self.inner.lock();
        // Only insert into active_streams if the stream channel still exists.
        // If the stream was already closed (CLOSE sent/received), the channel
        // is gone and we should not re-activate it.
        if let Some(tx) = inner.streams.get(&stream_id).cloned() {
            inner.active_streams.insert(stream_id);
            let _ = tx.send(payload);
        } else {
            // Stream already closed — silently discard late data from server.
            log::debug!(
                "mless: DATA stream#{} {}B discarded (stream closed)",
                stream_id,
                payload.len(),
            );
        }
    }

    fn on_disconnect(&self) {
        self.dead.store(true, Ordering::Relaxed);
        let mut inner = self.inner.lock();
        log::warn!(
            "mless: DISCONNECTED, clearing {} streams",
            inner.streams.len(),
        );
        inner.streams.clear();
        inner.active_streams.clear();
        self.disconnected.notify_waiters();
    }
}

// ---------------------------------------------------------------------------
// Async io_loop
// ---------------------------------------------------------------------------

/// Async I/O loop: encrypts outgoing data, decrypts incoming data.
///
/// Owns the `TransportSession` (kept alive for connection lifetime) and
/// the `CryptoLayer` (no sharing needed - crypto state is local to this
/// task).
async fn io_loop(
    mut session: Box<dyn TransportSession>,
    mut crypto: Box<dyn CryptoLayer>,
    mut ws_rx: mpsc::UnboundedReceiver<MlessMessage>,
    mux: Weak<MlessMultiplexer>,
) {
    log::debug!("mless: io_loop starting, getting uplink/downlink...");

    let mut uplink = match session.uplink().await {
        Ok(u) => u,
        Err(e) => {
            log::warn!("mless: uplink failed: {e}");
            if let Some(m) = mux.upgrade() {
                m.on_disconnect();
            }
            return;
        }
    };

    let mut downlink = match session.downlink().await {
        Ok(d) => d,
        Err(e) => {
            log::warn!("mless: downlink failed: {e}");
            if let Some(m) = mux.upgrade() {
                m.on_disconnect();
            }
            return;
        }
    };

    // Keep session alive to prevent connection closure.
    let _session = &mut session;

    let mut buf = vec![0u8; 16 * 1024];
    // Accumulation buffer for cross-read frame boundaries.
    // When a WS message is larger than `buf` or a mless frame spans
    // two WS messages, we need to buffer the incomplete tail and
    // prepend it to the next read.
    let mut accum: Vec<u8> = Vec::new();

    log::debug!("mless: io_loop ready, entering select loop");

    loop {
        tokio::select! {
            // Fair select (no `biased`): the downlink (incoming video) must be
            // polled even while the uplink (outgoing TCP ACKs) is busy, or a
            // continuous ACK stream starves the downlink and caps throughput.
            // (A `biased` select here prioritizes ws_rx and only reads the
            // downlink when ws_rx is momentarily empty.)
            // Outgoing: plaintext from channel -> encrypt -> frame -> transport
            msg = ws_rx.recv() => {
                let Some(m) = mux.upgrade() else { return; };
                match msg {
                    Some(MlessMessage::Data { stream_id, flags, payload }) => {
                        let encrypted = match crypto.encrypt(&payload).await {
                            Ok(e) => e,
                            Err(e) => {
                                log::warn!("mless: encrypt error: {e}");
                                m.on_disconnect();
                                return;
                            }
                        };
                        let frame = encode_frame(stream_id, flags, &encrypted);
                        if let Err(e) = uplink.write(&frame).await {
                            log::warn!("mless: transport write error: {e}");
                            m.on_disconnect();
                            return;
                        }
                    }
                    Some(MlessMessage::Close { stream_id }) => {
                        let frame = encode_frame(stream_id, FLAG_CLOSE, &[]);
                        if let Err(e) = uplink.write(&frame).await {
                            log::warn!("mless: transport write error (close): {e}");
                            m.on_disconnect();
                            return;
                        }
                    }
                    None => {
                        log::debug!("mless: ws_tx channel closed, io_loop exiting");
                        return;
                    }
                }
            }
            // Incoming: transport -> frame -> decrypt -> dispatch
            result = downlink.read(&mut buf) => {
                let Some(m) = mux.upgrade() else { return; };
                match result {
                    Ok(0) => {
                        log::warn!("mless: transport EOF");
                        m.on_disconnect();
                        return;
                    }
                    Ok(n) => {
                        // Prepend any leftover from previous read.
                        if !accum.is_empty() {
                            accum.extend_from_slice(&buf[..n]);
                        }
                        let data: &[u8] = if accum.is_empty() {
                            &buf[..n]
                        } else {
                            &accum[..]
                        };

                        let mut offset = 0;
                        while offset < data.len() {
                            let (stream_id, flags, payload, consumed) =
                                match decode_frame(&data[offset..]) {
                                    Some(v) => v,
                                    None => {
                                        // Incomplete frame — save the
                                        // remaining bytes for next read.
                                        break;
                                    }
                                };
                            log::debug!(
                                "mless: recv stream#{} flags={:#x} payload={}B",
                                stream_id,
                                flags,
                                payload.len(),
                            );
                            let decrypted = if payload.is_empty() {
                                Vec::new()
                            } else {
                                match crypto.decrypt(payload).await {
                                    Ok(d) => d,
                                    Err(e) => {
                                        log::warn!("mless: decrypt error: {e}");
                                        m.on_disconnect();
                                        return;
                                    }
                                }
                            };
                            m.on_frame(stream_id, flags, decrypted);
                            offset += consumed;
                        }

                        // Save unconsumed tail for next iteration.
                        if offset < data.len() {
                            if data.as_ptr() == accum.as_ptr() {
                                // data points to accum — drain consumed part.
                                accum.drain(..offset);
                            } else {
                                // data points to buf — copy tail to accum.
                                accum = data[offset..].to_vec();
                            }
                        } else {
                            // All consumed — clear accum.
                            accum.clear();
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                          || e.kind() == std::io::ErrorKind::TimedOut => {
                        // WS read timeout (100ms) - no data yet, continue loop.
                        // This is normal for WsDownlinkReader which uses
                        // blocking recv with timeout via spawn_blocking.
                        continue;
                    }
                    Err(e) => {
                        log::warn!("mless: transport read error: {e} ({:?})", e.kind());
                        m.on_disconnect();
                        return;
                    }
                }
            }
        }
    }
}
