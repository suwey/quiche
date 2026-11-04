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
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;

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
    Close { stream_id: u64 },
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

impl Drop for MlessStreamHandle {
    fn drop(&mut self) {
        if let Some(mux) = self.multiplexer.upgrade() {
            mux.close_stream(self.stream_id);
        }
    }
}

impl MlessStreamHandle {
    pub async fn close(&mut self) {
        if let Some(mux) = self.multiplexer.upgrade() {
            mux.close_stream(self.stream_id);
        }
    }
}

// ---------------------------------------------------------------------------
// MlessMultiplexer
// ---------------------------------------------------------------------------

/// Shared multiplexer state.
pub(crate) struct MlessStreamEntry {
    pub(crate) sender: mpsc::UnboundedSender<Vec<u8>>,
    /// Set once the server has delivered data on this stream. Dials that never
    /// get a first byte are what the unanswered-dial streak counts.
    pub(crate) answered: bool,
    _permit: MlessStreamPermit,
}

struct MlessStreamPermit {
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
    capacity_notify: Arc<Notify>,
}

impl Drop for MlessStreamPermit {
    fn drop(&mut self) {
        self.capacity_notify.notify_waiters();
    }
}

pub(crate) struct MlessMultiplexerInner {
    pub(crate) streams: HashMap<u64, MlessStreamEntry>,
    pub(crate) active_streams: std::collections::HashSet<u64>,
}

/// Mless stream multiplexer.
///
/// M4: Uses pluggable `ConnectionManager` + `CryptoFactory`. The io_loop
/// is async and operates on `TransportSession` + `CryptoLayer` trait objects.
pub struct MlessMultiplexer {
    /// 1-based pool slot, carried on every log line. Stream IDs restart at 1
    /// for each tunnel, so an untagged `stream#7` is ambiguous across the pool.
    pub(crate) slot: usize,
    pub(crate) inner: Mutex<MlessMultiplexerInner>,
    pub(crate) ws_tx: mpsc::UnboundedSender<MlessMessage>,
    stream_slots: Option<Arc<Semaphore>>,
    capacity_notify: Arc<Notify>,
    pub disconnected: Notify,
    pub(crate) next_stream_id: AtomicU64,
    pub(crate) dead: AtomicBool,
    pub(crate) reject_count: AtomicU32,
    unanswered_streak: AtomicU32,
    pub(crate) reconnecting: AtomicBool,
}

/// Dials on one tunnel that went unanswered back to back before the tunnel is
/// recycled. Two field runs put the threshold between the two populations:
/// healthy tunnels topped out at streaks of 2-3 (66-77% dial answer rate) while
/// dud tunnels ran 12 and 14 (35-61%).
const UNANSWERED_DIAL_LIMIT: u32 = 6;

impl MlessMultiplexer {
    /// Connect using pluggable components.
    ///
    /// Acquires a `TransportSession` from the `ConnectionManager`, creates
    /// a `CryptoLayer` from the `CryptoFactory`, and spawns an async io_loop
    /// that handles encryption/decryption and frame I/O.
    pub async fn connect_pluggable(
        conn_mgr: Arc<dyn ConnectionManager>,
        crypto_factory: Arc<dyn CryptoFactory>, uuid_str: &str,
        max_streams: usize, capacity_notify: Arc<Notify>, slot: usize,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        log::debug!("mless: [slot {slot}] acquiring transport session...");
        let session = conn_mgr
            .acquire_uplink()
            .await
            .map_err(|e| format!("mless: acquire transport failed: {e}"))?;

        log::debug!("mless: [slot {slot}] creating crypto layer...");
        let crypto = crypto_factory.create(uuid_str);

        let (ws_tx, ws_rx): (mpsc::UnboundedSender<MlessMessage>, _) =
            mpsc::unbounded_channel();

        let mux = Arc::new(Self {
            slot,
            inner: Mutex::new(MlessMultiplexerInner {
                streams: HashMap::new(),
                active_streams: std::collections::HashSet::new(),
            }),
            ws_tx,
            stream_slots: (max_streams > 0)
                .then(|| Arc::new(Semaphore::new(max_streams))),
            capacity_notify,
            disconnected: Notify::new(),
            next_stream_id: AtomicU64::new(1),
            dead: AtomicBool::new(false),
            reject_count: AtomicU32::new(0),
            unanswered_streak: AtomicU32::new(0),
            reconnecting: AtomicBool::new(false),
        });

        log::debug!("mless: [slot {slot}] spawning async io_loop...");
        let mux_clone = Arc::downgrade(&mux);
        tokio::spawn(async move {
            io_loop(session, crypto, ws_rx, mux_clone, slot).await;
        });

        Ok(mux)
    }

    /// Backward-compatible connect using WS transport.
    ///
    /// Builds a `SingleConnectionManager` + `WsTransportFactory` and
    /// delegates to `connect_pluggable()`.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        addr: SocketAddr, uuid_str: &str, tls_server: &str, insecure: bool,
        tls_fp: bool, fragment: Option<&crate::tlsfragment::FragmentConfig>,
        path: &str, headers: &HashMap<String, String>,
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
        let conn_mgr: Arc<dyn ConnectionManager> = Arc::new(
            SingleConnectionManager::new(Box::new(WsTransportFactory), ctx),
        );
        let crypto_factory: Arc<dyn CryptoFactory> = Arc::new(AheadXorFactory);

        Self::connect_pluggable(
            conn_mgr,
            crypto_factory,
            uuid_str,
            0,
            Arc::new(Notify::new()),
            1,
        )
        .await
    }

    /// Register a new stream without sending any frame.
    pub(crate) fn try_register_stream(
        self: &Arc<Self>,
    ) -> Option<(u64, UnboundedReceiver<Vec<u8>>)> {
        let permit = match self.stream_slots.as_ref() {
            Some(stream_slots) => {
                Some(stream_slots.clone().try_acquire_owned().ok()?)
            },
            None => None,
        };
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut inner = self.inner.lock();
            inner.streams.insert(
                stream_id,
                MlessStreamEntry {
                    sender: tx,
                    answered: false,
                    _permit: MlessStreamPermit {
                        _permit: permit,
                        capacity_notify: self.capacity_notify.clone(),
                    },
                },
            );
            log::debug!(
                "mless: [slot {}] NEW stream#{} (active: {})",
                self.slot,
                stream_id,
                inner.streams.len(),
            );
        }
        Some((stream_id, rx))
    }

    pub fn close_stream(&self, stream_id: u64) {
        let (entry, active) = {
            let mut inner = self.inner.lock();
            let entry = inner.streams.remove(&stream_id);
            let active = inner.streams.len();
            (entry, active)
        };
        let Some(entry) = entry else {
            return;
        };
        log::debug!(
            "mless: [slot {}] CLOSE stream#{} sent (active: {})",
            self.slot,
            stream_id,
            active,
        );
        self.note_dial_outcome(entry.answered);
        let _ = self.ws_tx.send(MlessMessage::Close { stream_id });
    }

    /// Record how one dial ended, taken from the stream being destroyed.
    /// Whoever removes the entry from `streams` owns the accounting, so our own
    /// close and a server CLOSE frame can never both count it.
    ///
    /// This exists alongside the CLOSE-rejection detector because that one only
    /// reacts to frames naming unknown streams; a tunnel that simply stops
    /// answering dials keeps its table clean and so never trips it.
    fn note_dial_outcome(&self, answered: bool) {
        if answered {
            self.unanswered_streak.store(0, Ordering::Relaxed);
            return;
        }
        let streak =
            self.unanswered_streak.fetch_add(1, Ordering::Relaxed) + 1;
        if streak < UNANSWERED_DIAL_LIMIT {
            return;
        }
        self.unanswered_streak.store(0, Ordering::Relaxed);
        log::warn!(
            "mless: [slot {}] {streak} consecutive unanswered dials, retiring tunnel",
            self.slot,
        );
        // Replacing the slot drops the pool's only strong Arc, so this
        // multiplexer is freed immediately: in-flight streams EOF on their next
        // read and the WebSocket closes. That cut is the point, and the server
        // frees this tunnel's origin sockets from its own close handler, so no
        // per-stream CLOSE is needed here.
        self.dead.store(true, Ordering::Relaxed);
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
            let (entry, was_active, active) = {
                let mut inner = self.inner.lock();
                let was_active = inner.active_streams.remove(&stream_id);
                let entry = inner.streams.remove(&stream_id);
                (entry, was_active, inner.streams.len())
            };
            if !was_active {
                let rejects =
                    self.reject_count.fetch_add(1, Ordering::Relaxed) + 1;
                log::warn!(
                    "mless: [slot {}] CLOSE stream#{} rejected ({}, active: {})",
                    self.slot,
                    stream_id,
                    rejects,
                    active,
                );
                if rejects >= 30 {
                    log::warn!(
                        "mless: [slot {}] {} consecutive rejections, marking dead",
                        self.slot,
                        rejects
                    );
                    self.dead.store(true, Ordering::Relaxed);
                    self.reject_count.store(0, Ordering::Relaxed);
                }
            } else {
                self.reject_count.store(0, Ordering::Relaxed);
                log::debug!(
                    "mless: [slot {}] CLOSE stream#{} (active: {})",
                    self.slot,
                    stream_id,
                    active,
                );
            }
            // A server CLOSE ends the dial as much as our own close does, so
            // the streak is accounted here whenever the server owned the
            // stream's removal. `close_stream` returns early for the same
            // stream afterwards, which is what keeps this counted once.
            if let Some(entry) = entry {
                self.note_dial_outcome(entry.answered);
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
        log::trace!(
            "mless: [slot {}] DATA stream#{} {}B [{}] -> channel",
            self.slot,
            stream_id,
            payload.len(),
            hex_preview,
        );

        let mut inner = self.inner.lock();
        // Only insert into active_streams if the stream channel still exists.
        // If the stream was already closed (CLOSE sent/received), the channel
        // is gone and we should not re-activate it.
        if let Some(entry) = inner.streams.get_mut(&stream_id) {
            let tx = entry.sender.clone();
            entry.answered = true;
            inner.active_streams.insert(stream_id);
            let _ = tx.send(payload);
        } else {
            // Stream already closed — silently discard late data from server.
            log::debug!(
                "mless: [slot {}] DATA stream#{} {}B discarded (stream closed)",
                self.slot,
                stream_id,
                payload.len(),
            );
        }
    }

    fn on_disconnect(&self) {
        self.dead.store(true, Ordering::Relaxed);
        let mut inner = self.inner.lock();
        log::warn!(
            "mless: [slot {}] DISCONNECTED, clearing {} streams",
            self.slot,
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
    mut session: Box<dyn TransportSession>, mut crypto: Box<dyn CryptoLayer>,
    mut ws_rx: mpsc::UnboundedReceiver<MlessMessage>,
    mux: Weak<MlessMultiplexer>, slot: usize,
) {
    log::debug!("mless: [slot {slot}] io_loop starting, getting uplink/downlink...");

    let mut uplink = match session.uplink().await {
        Ok(u) => u,
        Err(e) => {
            log::warn!("mless: [slot {slot}] uplink failed: {e}");
            if let Some(m) = mux.upgrade() {
                m.on_disconnect();
            }
            return;
        },
    };

    let mut downlink = match session.downlink().await {
        Ok(d) => d,
        Err(e) => {
            log::warn!("mless: [slot {slot}] downlink failed: {e}");
            if let Some(m) = mux.upgrade() {
                m.on_disconnect();
            }
            return;
        },
    };

    // Keep session alive to prevent connection closure.
    let _session = &mut session;

    let mut buf = vec![0u8; 16 * 1024];
    // Accumulation buffer for cross-read frame boundaries.
    // When a WS message is larger than `buf` or a mless frame spans
    // two WS messages, we need to buffer the incomplete tail and
    // prepend it to the next read.
    let mut accum: Vec<u8> = Vec::new();

    log::debug!("mless: [slot {slot}] io_loop ready, entering select loop");

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
                                log::warn!(
                                    "mless: [slot {slot}] encrypt error: {e}"
                                );
                                m.on_disconnect();
                                return;
                            }
                        };
                        let frame = encode_frame(stream_id, flags, &encrypted);
                        if let Err(e) = uplink.write(&frame).await {
                            log::warn!(
                                "mless: [slot {slot}] transport write error: {e}"
                            );
                            m.on_disconnect();
                            return;
                        }
                        // Confirms the dial request actually reached the
                        // transport. Without this, a stream that never gets
                        // answered is ambiguous between "the request stalled in
                        // our own write queue" and "the server ignored it".
                        if flags & FLAG_FIRST != 0 {
                            log::debug!(
                                "mless: [slot {slot}] FIRST stream#{stream_id} written to tunnel ({}B)",
                                encrypted.len(),
                            );
                        }
                    }
                    Some(MlessMessage::Close { stream_id }) => {
                        let frame = encode_frame(stream_id, FLAG_CLOSE, &[]);
                        if let Err(e) = uplink.write(&frame).await {
                            log::warn!(
                                "mless: [slot {slot}] transport write error (close): {e}"
                            );
                            m.on_disconnect();
                            return;
                        }
                        log::debug!(
                            "mless: [slot {slot}] CLOSE stream#{stream_id} written to tunnel",
                        );
                    }
                    None => {
                        log::debug!(
                            "mless: [slot {slot}] ws_tx channel closed, io_loop exiting"
                        );
                        return;
                    }
                }
            }
            // Incoming: transport -> frame -> decrypt -> dispatch
            result = downlink.read(&mut buf) => {
                let Some(m) = mux.upgrade() else { return; };
                match result {
                    Ok(0) => {
                        log::warn!("mless: [slot {slot}] transport EOF");
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
                            log::trace!(
                                "mless: [slot {slot}] recv stream#{} flags={:#x} payload={}B",
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
                                        log::warn!(
                                            "mless: [slot {slot}] decrypt error: {e}"
                                        );
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
                        log::warn!(
                            "mless: [slot {slot}] transport read error: {e} ({:?})",
                            e.kind()
                        );
                        m.on_disconnect();
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multiplexer(max_streams: usize) -> Arc<MlessMultiplexer> {
        let (ws_tx, _ws_rx) = mpsc::unbounded_channel();
        Arc::new(MlessMultiplexer {
            slot: 1,
            inner: Mutex::new(MlessMultiplexerInner {
                streams: HashMap::new(),
                active_streams: std::collections::HashSet::new(),
            }),
            ws_tx,
            stream_slots: (max_streams > 0)
                .then(|| Arc::new(Semaphore::new(max_streams))),
            capacity_notify: Arc::new(Notify::new()),
            disconnected: Notify::new(),
            next_stream_id: AtomicU64::new(1),
            dead: AtomicBool::new(false),
            reject_count: AtomicU32::new(0),
            unanswered_streak: AtomicU32::new(0),
            reconnecting: AtomicBool::new(false),
        })
    }

    /// Six dials on one tunnel that never saw a single byte back retire it;
    /// five do not. The threshold sits between the two populations seen in the
    /// field (healthy streaks of 2-3, dud tunnels at 12 and 14).
    #[test]
    fn unanswered_dial_streak_retires_tunnel() {
        let mux = multiplexer(0);
        for _ in 0..UNANSWERED_DIAL_LIMIT - 1 {
            let (stream_id, _rx) = mux.try_register_stream().unwrap();
            mux.close_stream(stream_id);
        }
        assert!(!mux.dead.load(Ordering::Relaxed));

        let (stream_id, _rx) = mux.try_register_stream().unwrap();
        mux.close_stream(stream_id);
        assert!(mux.dead.load(Ordering::Relaxed));
    }

    #[test]
    fn answered_dial_clears_the_unanswered_streak() {
        let mux = multiplexer(0);
        for _ in 0..UNANSWERED_DIAL_LIMIT - 1 {
            let (stream_id, _rx) = mux.try_register_stream().unwrap();
            mux.close_stream(stream_id);
        }
        // A dial the server did answer, even one byte, resets the count.
        let (answered, _rx) = mux.try_register_stream().unwrap();
        mux.on_frame(answered, 0, vec![0, 0]); // 0 == FLAG_DATA
        mux.close_stream(answered);

        for _ in 0..UNANSWERED_DIAL_LIMIT - 1 {
            let (stream_id, _rx) = mux.try_register_stream().unwrap();
            mux.close_stream(stream_id);
        }
        assert!(!mux.dead.load(Ordering::Relaxed));
    }

    #[test]
    fn server_close_of_an_unanswered_dial_counts_once() {
        let mux = multiplexer(0);
        for _ in 0..UNANSWERED_DIAL_LIMIT - 1 {
            let (stream_id, _rx) = mux.try_register_stream().unwrap();
            // The server ends the stream instead of us, then our relay drop
            // calls close_stream for the same id again.
            mux.on_frame(stream_id, FLAG_CLOSE, Vec::new());
            mux.close_stream(stream_id);
        }
        assert!(!mux.dead.load(Ordering::Relaxed));

        let (stream_id, _rx) = mux.try_register_stream().unwrap();
        mux.on_frame(stream_id, FLAG_CLOSE, Vec::new());
        mux.close_stream(stream_id);
        assert!(mux.dead.load(Ordering::Relaxed));
    }

    #[test]
    fn stream_limit_releases_on_close() {
        let mux = multiplexer(1);
        let (stream_id, _rx) = mux.try_register_stream().unwrap();
        assert_eq!(mux.stream_slots.as_ref().unwrap().available_permits(), 0);

        assert!(mux.try_register_stream().is_none());
        mux.close_stream(stream_id);
        assert!(mux.try_register_stream().is_some());
    }

    #[test]
    fn stream_limit_releases_when_handle_drops() {
        let mux = multiplexer(1);
        let (stream_id, rx) = mux.try_register_stream().unwrap();
        let handle = MlessStreamHandle {
            stream_id,
            rx,
            multiplexer: Arc::downgrade(&mux),
        };

        assert!(mux.try_register_stream().is_none());
        drop(handle);
        assert!(mux.try_register_stream().is_some());
    }

    #[test]
    fn zero_stream_limit_is_unlimited() {
        let mux = multiplexer(0);

        assert!(mux.try_register_stream().is_some());
        assert!(mux.try_register_stream().is_some());
        assert!(mux.try_register_stream().is_some());
    }
}
