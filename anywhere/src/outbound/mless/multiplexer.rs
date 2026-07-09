// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Mless stream multiplexer — single WebSocket, multiple streams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::sync::mpsc;

use crate::outbound::vless::WsStream;
use crate::outbound::vless::build_ws;

use super::crypto::Obfuscation;
use super::frame::*;

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

/// Shared multiplexer state.
pub(crate) struct MlessMultiplexerInner {
    pub(crate) streams: HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>,
    pub(crate) obfuscation: Obfuscation,
    pub(crate) active_streams: std::collections::HashSet<u64>,
}

/// Mless stream multiplexer.
pub struct MlessMultiplexer {
    pub(crate) inner: Mutex<MlessMultiplexerInner>,
    pub(crate) ws_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub disconnected: Notify,
    pub(crate) next_stream_id: std::sync::atomic::AtomicU64,
    pub(crate) dead: AtomicBool,
    pub(crate) reject_count: std::sync::atomic::AtomicU32,
    pub(crate) reconnecting: AtomicBool,
}

impl MlessMultiplexer {
    pub async fn connect(
        addr: SocketAddr, uuid_str: &str, tls_server: &str, insecure: bool,
        tls_fp: bool, path: &str, headers: &HashMap<String, String>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        log::debug!("mless: connecting to {addr}...");
        // Use bypass TCP to avoid TUN routing loop on Linux. Same pattern
        // as vless (connect_tcp_bypass sets SO_MARK on Linux / protect on
        // Android). Timeout is 8s to match previous behaviour.
        let tcp = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            crate::outbound::common::connect_tcp_bypass(addr),
        )
        .await
        .map_err(|_| "mless: connect timeout (8s)")?
        .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
        log::debug!("mless: tcp connected (bypass), building ws...");
        let tcp_std = tcp.into_std()?;
        tcp_std.set_nonblocking(false)?;
        let ws = build_ws(tcp_std, tls_server, insecure, tls_fp, path, headers)?;
        log::debug!("mless: ws built, spawning io_loop...");

        let (ws_tx, ws_rx): (mpsc::UnboundedSender<Vec<u8>>, _) =
            mpsc::unbounded_channel();

        let obfuscation = Obfuscation::new(uuid_str);

        let mux = Arc::new(Self {
            inner: Mutex::new(MlessMultiplexerInner {
                streams: HashMap::new(),
                obfuscation,
                active_streams: std::collections::HashSet::new(),
            }),
            ws_tx,
            disconnected: Notify::new(),
            next_stream_id: std::sync::atomic::AtomicU64::new(1),
            dead: AtomicBool::new(false),
            reject_count: std::sync::atomic::AtomicU32::new(0),
            reconnecting: AtomicBool::new(false),
        });

        let mux_clone = Arc::downgrade(&mux);
        std::thread::spawn(move || {
            io_loop(ws, ws_rx, mux_clone);
        });

        log::debug!("mless: io_loop spawned, connect done");
        Ok(mux)
    }

    /// Register a new stream without sending any frame.
    /// The caller is responsible for sending the FIRST frame
    /// (via MlessStreamRelay::write or manually).
    pub fn register_stream(
        self: &Arc<Self>,
    ) -> (u64, mpsc::UnboundedReceiver<Vec<u8>>) {
        let stream_id = self
            .next_stream_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        // Idempotent: if the stream is already gone (e.g. shutdown after
        // server-pushed CLOSE, or a duplicate timeout/shutdown race), skip
        // both the log and the redundant WS CLOSE frame.
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
        let frame = encode_frame(stream_id, FLAG_CLOSE, &[]);
        let _ = self.ws_tx.send(frame);
    }

    pub fn send_data(&self, stream_id: u64, data: &[u8]) {
        let encrypted = {
            let mut inner = self.inner.lock();
            inner.obfuscation.encrypt(data)
        };
        let frame = encode_frame(stream_id, FLAG_DATA, &encrypted);
        let _ = self.ws_tx.send(frame);
    }

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
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed) +
                    1;
                log::warn!(
                    "mless: CLOSE stream#{} rejected ({}, active: {})",
                    stream_id,
                    rejects,
                    inner.streams.len(),
                );
                // Threshold tuned for transient PROXYIP rejections: hermes
                // retries failed PROXYIP nodes internally with blacklisting,
                // but a single client-side burst can still surface several
                // CLOSEs before the server settles on a working node. Only
                // mark the multiplexer dead when failure is overwhelming.
                if rejects >= 30 {
                    log::warn!(
                        "mless: {} consecutive rejections, marking dead",
                        rejects
                    );
                    self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
                    self.reject_count
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                }
            } else {
                self.reject_count
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                log::debug!(
                    "mless: CLOSE stream#{} (active: {})",
                    stream_id,
                    inner.streams.len(),
                );
            }
            return;
        }

        let decrypted = if payload.is_empty() {
            payload
        } else {
            let mut inner = self.inner.lock();
            inner.obfuscation.decrypt(&payload)
        };

        let hex_preview = decrypted
            .iter()
            .take(16)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        log::debug!(
            "mless: DATA stream#{} {}B [{}] -> channel",
            stream_id,
            decrypted.len(),
            hex_preview,
        );

        let mut inner = self.inner.lock();
        inner.active_streams.insert(stream_id);
        if let Some(tx) = inner.streams.get(&stream_id) {
            let _ = tx.send(decrypted);
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

fn io_loop(
    mut ws: WsStream, mut ws_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mux: Weak<MlessMultiplexer>,
) {
    let _ = ws.set_read_timeout(std::time::Duration::from_millis(100));

    // If no data received within this window, the connection is considered
    // dead (half-open TCP). The server should send periodic keepalive frames
    // or close gracefully; if it doesn't, we detect silence here.
    const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    let mut last_data = std::time::Instant::now();

    loop {
        let Some(mux) = mux.upgrade() else {
            return;
        };

        loop {
            match ws_rx.try_recv() {
                Ok(frame) => {
                    if let Err(e) = ws.send(&frame) {
                        log::warn!("mless: ws write error: {e} ({:?}), closing", e.kind());
                        mux.on_disconnect();
                        return;
                    }
                    // Successful write resets the idle timer — the connection
                    // is clearly alive.
                    last_data = std::time::Instant::now();
                },
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    log::warn!("mless: ws_tx channel disconnected, closing");
                    let _ = ws.close();
                    mux.on_disconnect();
                    return;
                },
            }
        }

        match ws.recv() {
            Ok(data) if !data.is_empty() => {
                last_data = std::time::Instant::now();
                // A single WebSocket message may contain multiple
                // concatenated mless frames (the server's Grain sender
                // batches frames into one WS message). Parse them all.
                let mut offset = 0;
                while offset < data.len() {
                    let (stream_id, flags, payload, consumed) = match decode_frame(
                        &data[offset..],
                    ) {
                        Some(v) => v,
                        None => {
                            log::warn!(
                                "mless: invalid frame at offset {} in WS msg len {}",
                                offset,
                                data.len(),
                            );
                            break;
                        },
                    };
                    log::debug!(
                        "mless: recv stream#{} flags={:#x} payload={}B",
                        stream_id,
                        flags,
                        payload.len(),
                    );
                    mux.on_frame(stream_id, flags, payload.to_vec());
                    offset += consumed;
                }
            },
            Ok(_) => continue,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock ||
                    e.kind() == std::io::ErrorKind::TimedOut
                {
                    // Check for silent idle timeout — the server may have
                    // died without closing the TCP connection (half-open).
                    if last_data.elapsed() >= IDLE_TIMEOUT {
                        log::warn!(
                            "mless: no data for {:?}, treating as disconnected",
                            IDLE_TIMEOUT,
                        );
                        mux.on_disconnect();
                        return;
                    }
                    continue;
                }
                log::warn!("mless: ws read error: {e} ({:?}), closing", e.kind());
                mux.on_disconnect();
                return;
            },
        }
    }
}
