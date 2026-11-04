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
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::connection::ConnectionManager;
use crate::crypto::{CryptoFactory, CryptoLayer};
use crate::transport::TransportSession;

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

/// Pool-side wiring shared by every multiplexer in a mless pool, built once
/// at client construction and cloned per slot dial: stream capacity, the
/// retire gate, and the pool-wide death signal.
#[derive(Clone)]
pub(crate) struct MuxPoolWiring {
    /// Maximum MLESS streams per physical connection (0 = unlimited).
    pub(crate) max_streams: usize,
    /// Notified when a stream permit is released.
    pub(crate) capacity_notify: Arc<Notify>,
    /// Bounds how often a streak of unanswered dials may retire a tunnel.
    pub(crate) pool_gate: Arc<PoolRetireGate>,
    /// Pool-wide wake-up fired on any tunnel death so the keepalive task
    /// reconnects immediately instead of waiting out its poll interval.
    pub(crate) disconnect_signal: Arc<Notify>,
}

/// Shared by every tunnel in the pool to throttle streak-driven retirements.
///
/// The streak test is per tunnel, but the damage it prevents is not: a
/// retirement frees that tunnel's multiplexer, which EOFs every stream still
/// downloading on it. When the whole path degrades at once - all five tunnels
/// answering ~40% - each tunnel independently reaches the streak limit, so an
/// ungated trigger recycles the pool every few tens of seconds and the remedy
/// itself becomes the stutter. One retirement at a time, and only once the
/// replacement has proven it can answer something, keeps the recovery without
/// the churn. Involuntary teardown (`transport EOF`) is not gated: that tunnel
/// is already gone.
pub(crate) struct PoolRetireGate {
    last_fire: Mutex<Option<Instant>>,
    good_since_fire: AtomicU32,
}

/// Shortest gap between two streak-driven retirements, pool-wide. Chosen from
/// the 21:34 field run, where ungated fires landed ~41 s apart.
const STREAK_RETIRE_COOLDOWN: std::time::Duration =
    std::time::Duration::from_secs(120);

impl PoolRetireGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            last_fire: Mutex::new(None),
            good_since_fire: AtomicU32::new(0),
        })
    }

    fn observe(&self, answered: bool) {
        if answered {
            self.good_since_fire.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Claims the right to retire a tunnel now, or refuses and leaves the
    /// previous claim in place.
    fn claim_at(&self, now: Instant) -> bool {
        let mut last = self.last_fire.lock();
        let ready = match *last {
            None => true,
            Some(t) => {
                now.duration_since(t) >= STREAK_RETIRE_COOLDOWN
                    && self.good_since_fire.load(Ordering::Relaxed) > 0
            }
        };
        if ready {
            *last = Some(now);
            self.good_since_fire.store(0, Ordering::Relaxed);
        }
        ready
    }
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
    /// Shared pool throttle for streak-driven retirements.
    pool_gate: Arc<PoolRetireGate>,
    pub(crate) reconnecting: AtomicBool,
    /// Pool-wide wake-up signal: fired whenever this tunnel dies so the
    /// keepalive task reconnects immediately instead of waiting out its
    /// 10 s poll (a full-pool EOF otherwise blackholes traffic for ~15 s).
    pub(crate) disconnect_signal: Arc<Notify>,
    /// Streams closed while `answered == false`, awaiting possible late data.
    /// Server bytes that land after our close still prove the tunnel answered,
    /// so late DATA for one of these corrects the dial accounting instead of
    /// letting a healthy-but-slow tunnel drift toward the retire limit.
    unanswered_recent: Mutex<VecDeque<u64>>,
    /// Streams closed by us. Hermes echoes a CLOSE for every client-initiated
    /// close; that echo names a stream we already tore down, so it must not
    /// feed the rejection detector.
    self_closed_recent: Mutex<VecDeque<u64>>,
}

/// Dials on one tunnel that go unanswered back to back before it is recycled.
///
/// Six is the value validated in the field (one-way-dead tunnels ran 5, 7, 8,
/// 11, 12 and 14 back-to-back). Four was tried and made the pool churn: with a
/// globally degraded path every tunnel reaches four quickly, and each
/// retirement cuts the streams still downloading on that tunnel, so the
/// remedy itself became visible as stutter.
const UNANSWERED_DIAL_LIMIT: u32 = 6;

/// How many recently-closed stream ids each of the two late-detection queues
/// remembers. Ids grow monotonically per tunnel and closes arrive at
/// browser speeds, so 128 covers several seconds of churn easily.
const RECENT_CLOSED_CAP: usize = 128;

/// Bounded push for the recently-closed id queues: drops the oldest entry
/// once the cap is reached.
fn push_recent(queue: &mut VecDeque<u64>, stream_id: u64) {
    if queue.len() >= RECENT_CLOSED_CAP {
        queue.pop_front();
    }
    queue.push_back(stream_id);
}

impl MlessMultiplexer {
    /// Connect using pluggable components.
    ///
    /// Acquires a `TransportSession` from the `ConnectionManager`, creates
    /// a `CryptoLayer` from the `CryptoFactory`, and spawns an async io_loop
    /// that handles encryption/decryption and frame I/O.
    pub(crate) async fn connect_pluggable(
        conn_mgr: Arc<dyn ConnectionManager>,
        crypto_factory: Arc<dyn CryptoFactory>, uuid_str: &str,
        wiring: MuxPoolWiring, slot: usize,
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

        let MuxPoolWiring {
            max_streams,
            capacity_notify,
            pool_gate,
            disconnect_signal,
        } = wiring;

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
            pool_gate,
            reconnecting: AtomicBool::new(false),
            disconnect_signal,
            unanswered_recent: Mutex::new(VecDeque::new()),
            self_closed_recent: Mutex::new(VecDeque::new()),
        });

        log::debug!("mless: [slot {slot}] spawning async io_loop...");
        let mux_clone = Arc::downgrade(&mux);
        tokio::spawn(async move {
            io_loop(session, crypto, ws_rx, mux_clone, slot).await;
        });

        Ok(mux)
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
        // Record that this stream was closed by us: hermes replies with a
        // CLOSE echo for every client-initiated close, and that echo must not
        // count as a protocol violation (field ③).
        push_recent(&mut self.self_closed_recent.lock(), stream_id);
        if !entry.answered {
            // The dial is about to be counted unanswered; keep the id around
            // so in-flight data arriving after the close can correct it.
            // Field run 2026-11-04: slot 5 was retired on 6 "unanswered"
            // dials whose responses only landed after the browser aborted.
            push_recent(&mut self.unanswered_recent.lock(), stream_id);
        }
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
        self.pool_gate.observe(answered);
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
        if !self.pool_gate.claim_at(Instant::now()) {
            log::debug!(
                "mless: [slot {}] {streak} consecutive unanswered dials, retirement held (pool cooldown)",
                self.slot,
            );
            return;
        }
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
        self.disconnect_signal.notify_waiters();
    }

    /// Late server data on a stream we already closed. The dial that opened
    /// it was counted unanswered at close time; bytes arriving now prove the
    /// tunnel did answer, so undo one unanswered count. At most one
    /// correction per stream id — the id is consumed on use.
    fn note_late_answer(&self, stream_id: u64) {
        let found = {
            let mut queue = self.unanswered_recent.lock();
            if let Some(pos) = queue.iter().position(|&id| id == stream_id) {
                queue.remove(pos);
                true
            } else {
                false
            }
        };
        if !found {
            return;
        }
        self.pool_gate.observe(true);
        // Decrement one unanswered count. CAS loop: concurrent closes on the
        // relay tasks also touch this counter.
        let mut cur = self.unanswered_streak.load(Ordering::Relaxed);
        while cur > 0 {
            match self.unanswered_streak.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        log::debug!(
            "mless: [slot {}] late data on stream#{}, dial re-counted as answered",
            self.slot,
            stream_id,
        );
    }

    /// Removes `stream_id` from the self-closed queue, returning whether it
    /// was there. A hit means this CLOSE frame is the hermes echo of our own
    /// close, not a duplicate or desync.
    fn take_self_closed(&self, stream_id: u64) -> bool {
        let mut queue = self.self_closed_recent.lock();
        if let Some(pos) = queue.iter().position(|&id| id == stream_id) {
            queue.remove(pos);
            true
        } else {
            false
        }
    }

    /// Send plaintext data - the io_loop handles encryption.
    pub fn send_data(&self, stream_id: u64, data: &[u8]) {
        // The obfuscation keystream is SHA-256(key || counter) with the counter
        // implicit: each side advances it once per payload-bearing frame, and
        // `encrypt` advances it even for an empty payload while hermes skips
        // empty ones. A zero-length frame would therefore shift the two
        // counters apart permanently and garble every later frame on this
        // tunnel, so nothing is sent at all.
        if data.is_empty() {
            return;
        }
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
                if self.take_self_closed(stream_id) {
                    // Hermes echoes a CLOSE for every client-initiated close.
                    // That echo names a stream we tore down ourselves — not a
                    // protocol violation, so keep it out of the rejection
                    // detector (a healthy browsing session previously drifted
                    // toward the 30-rejection kill switch on echoes alone).
                    log::debug!(
                        "mless: [slot {}] CLOSE stream#{} echo (own close) ignored",
                        self.slot,
                        stream_id,
                    );
                } else {
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
            // The bytes still prove the tunnel answered: if this dial was
            // counted unanswered at close time, correct the accounting.
            self.note_late_answer(stream_id);
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
        // Wake the pool keepalive task immediately: a transport EOF on a busy
        // tunnel cuts many streams at once, and the 10 s poll would leave the
        // whole pool degraded for that long before reviving this slot.
        self.disconnect_signal.notify_waiters();
    }
}

// ---------------------------------------------------------------------------
// Async io_loop
// ---------------------------------------------------------------------------

/// Period between mless keepalive frames.
///
/// Hermes tears a tunnel down after 120 s without traffic (`空闲超时ms` in
/// `deploy/hermes/src/transport-ws.ts`), and the client never originates
/// traffic on an idle tunnel — the next dial then lands on a half-open
/// connection and reads as an unanswered dial. The keepalive frame is an
/// empty CLOSE on stream 0: both sides skip stream 0, and because the payload
/// is empty neither side advances its obfuscation counter, so it is safe to
/// inject at any point in the frame stream.
const HEARTBEAT_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(30);

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

    // First tick of an interval is immediate; push it past the connect so the
    // tunnel does not emit a keepalive frame the moment it is born.
    let mut keepalive = tokio::time::interval(HEARTBEAT_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.reset();

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
            // Keepalive: reset the server's 120 s idle timer on an otherwise
            // quiet tunnel. Written directly here (never through send_data)
            // so the empty payload stays unencrypted and no obfuscation
            // counter moves on either side.
            _ = keepalive.tick() => {
                let Some(m) = mux.upgrade() else { return; };
                let frame = encode_frame(0, FLAG_CLOSE, &[]);
                if let Err(e) = uplink.write(&frame).await {
                    log::warn!(
                        "mless: [slot {slot}] transport write error (keepalive): {e}"
                    );
                    m.on_disconnect();
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_mux(
        max_streams: usize, gate: Arc<PoolRetireGate>,
    ) -> (Arc<MlessMultiplexer>, mpsc::UnboundedReceiver<MlessMessage>) {
        let (ws_tx, ws_rx) = mpsc::unbounded_channel();
        let mux = Arc::new(MlessMultiplexer {
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
            pool_gate: gate,
            reconnecting: AtomicBool::new(false),
            disconnect_signal: Arc::new(Notify::new()),
            unanswered_recent: Mutex::new(VecDeque::new()),
            self_closed_recent: Mutex::new(VecDeque::new()),
        });
        (mux, ws_rx)
    }

    fn multiplexer_with_rx(
        max_streams: usize,
    ) -> (Arc<MlessMultiplexer>, mpsc::UnboundedReceiver<MlessMessage>) {
        build_mux(max_streams, PoolRetireGate::new())
    }

    fn multiplexer_with_gate(
        max_streams: usize, gate: Arc<PoolRetireGate>,
    ) -> Arc<MlessMultiplexer> {
        build_mux(max_streams, gate).0
    }

    fn multiplexer(max_streams: usize) -> Arc<MlessMultiplexer> {
        multiplexer_with_rx(max_streams).0
    }

    /// The counter-safety rule behind `send_data`: an empty payload must not
    /// reach the io_loop, because encrypting it would advance our send counter
    /// while the peer leaves its receive counter untouched.
    #[test]
    fn empty_payload_produces_no_frame() {
        let (mux, mut ws_rx) = multiplexer_with_rx(0);

        mux.send_data(7, &[]);
        assert!(
            ws_rx.try_recv().is_err(),
            "an empty DATA frame would desynchronise the obfuscation counters"
        );

        mux.send_data(7, b"x");
        assert!(matches!(
            ws_rx.try_recv(),
            Ok(MlessMessage::Data { stream_id: 7, payload, .. })
                if payload == b"x"
        ));
    }

    /// A streak of unanswered dials retires the tunnel at the limit and not
    /// before. Healthy tunnels in the field never ran the streak past 3.
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

    /// Two tunnels share one gate: the second streak inside the cooldown is
    /// held, because a retirement cuts the streams the first tunnel is still
    /// downloading and a second one back-to-back cuts more for no gain.
    #[test]
    fn pool_cooldown_holds_the_second_retirement() {
        let gate = PoolRetireGate::new();
        let first = multiplexer_with_gate(0, Arc::clone(&gate));
        let second = multiplexer_with_gate(0, Arc::clone(&gate));
        for _ in 0..UNANSWERED_DIAL_LIMIT {
            let (id, _rx) = first.try_register_stream().unwrap();
            first.close_stream(id);
        }
        assert!(first.dead.load(Ordering::Relaxed));

        for _ in 0..UNANSWERED_DIAL_LIMIT {
            let (id, _rx) = second.try_register_stream().unwrap();
            second.close_stream(id);
        }
        assert!(!second.dead.load(Ordering::Relaxed));
    }

    /// The cooldown only reopens once something on the pool has actually been
    /// answered: while nothing answers, replacing tunnels cannot help.
    #[test]
    fn cooldown_reopens_only_after_a_dial_is_answered() {
        let gate = PoolRetireGate::new();
        let t0 = Instant::now();
        assert!(gate.claim_at(t0));
        let later = t0 + STREAK_RETIRE_COOLDOWN
            + std::time::Duration::from_secs(1);
        assert!(!gate.claim_at(later));
        gate.observe(true);
        assert!(gate.claim_at(later));
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

    /// Late data on a stream that was closed unanswered corrects the streak,
    /// so a slow-but-alive tunnel is not retired on browser fast-aborts.
    /// Field run 2026-11-04: slot 5 reached the 6-dial retire limit while its
    /// responses were only landing after each abort (logged as
    /// "DATA ... discarded").
    #[test]
    fn late_data_corrects_unanswered_streak() {
        let mux = multiplexer(0);
        let mut ids = Vec::new();
        for _ in 0..3 {
            let (id, _rx) = mux.try_register_stream().unwrap();
            mux.close_stream(id);
            ids.push(id);
        }
        // Late data for one of them: the tunnel did answer after all.
        mux.on_frame(ids[0], 0, vec![1, 2, 3]);
        // With one correction, three more unanswered closes must still fit
        // under the limit of 6 (3 - 1 + 3 = 5).
        for _ in 0..UNANSWERED_DIAL_LIMIT - 3 {
            let (id, _rx) = mux.try_register_stream().unwrap();
            mux.close_stream(id);
        }
        assert!(!mux.dead.load(Ordering::Relaxed));

        // The next unanswered close trips the limit again.
        let (id, _rx) = mux.try_register_stream().unwrap();
        mux.close_stream(id);
        assert!(mux.dead.load(Ordering::Relaxed));
    }

    /// A late correction is consumed once: the same id cannot be re-armed to
    /// suppress further unanswered counts.
    #[test]
    fn late_answer_correction_is_single_use() {
        let mux = multiplexer(0);
        let (id, _rx) = mux.try_register_stream().unwrap();
        mux.close_stream(id);
        assert_eq!(mux.unanswered_recent.lock().len(), 1);

        mux.on_frame(id, 0, vec![1]);
        assert_eq!(
            mux.unanswered_recent.lock().len(),
            0,
            "correction consumes the id"
        );

        // A duplicate late frame must not re-arm the id.
        mux.on_frame(id, 0, vec![1]);
        assert_eq!(mux.unanswered_recent.lock().len(), 0);
    }

    /// A server CLOSE for a stream we closed ourselves is the hermes echo and
    /// must not feed the rejection detector; a CLOSE for a stream we never
    /// closed still does (field run: 46 echoes logged as "rejected").
    #[test]
    fn close_echo_of_own_close_is_not_counted() {
        let mux = multiplexer(0);
        let (id, _rx) = mux.try_register_stream().unwrap();
        mux.close_stream(id);

        mux.on_frame(id, FLAG_CLOSE, Vec::new());
        assert_eq!(mux.reject_count.load(Ordering::Relaxed), 0);

        // A duplicate echo (id already consumed) counts again.
        mux.on_frame(id, FLAG_CLOSE, Vec::new());
        assert_eq!(mux.reject_count.load(Ordering::Relaxed), 1);
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
