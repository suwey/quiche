// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Mless inbound server (server side of `outbound/mless`).
//!
//! Per TLS+WS connection:
//! - TLS accept (cert/key, optional) → HTTP/1.1 WebSocket upgrade
//!   ([`WsServerStream`], the server framing of `transport/ws.rs`);
//! - session loop: read ws messages, decode mless frames (varint stream_id,
//!   a flags byte, varint payload length, then payload — see
//!   `outbound/mless/frame`) and decrypt each payload with the per-frame
//!   XOR keystream (`outbound/mless/crypto`);
//! - the first frame authenticates the session: the client always opens a
//!   stream with a FIRST frame whose payload is a VLESS request header, and
//!   the obfuscation key is derived from the client's UUID string — so the
//!   server decrypts the frame with every `[[users]].password`-derived key
//!   and accepts the one whose result carries that user's UUID;
//! - every FIRST frame opens one multiplexed stream: the header's command
//!   selects TCP ([`InboundConn::Tcp`]) or UDP ([`InboundConn::Udp`]). TCP
//!   streams get the 2-byte VLESS response `[0, 0]` prepended to the first
//!   server→client data frame (the outbound's TCP relay strips it there;
//!   its UDP relay does not, so UDP streams carry raw datagrams);
//! - FLAG_CLOSE drops the session-map entry, EOF-ing the stream's relay.
//!
//! Crypto counters mirror the outbound's io_loop exactly: every non-CLOSE
//! frame consumes one keystream on decrypt (even empty payloads — the
//! client encrypts every Data message), while empty payloads are never
//! encrypted on send (the client's recv counter only advances on non-empty
//! frames). CLOSE frames carry no encryption and consume nothing.
//!
//! The blocking TLS/ws handshakes and the session loop run on
//! `spawn_blocking` — the same model as the anytls/vless inbounds.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Read;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use boring::ssl::Ssl;
use boring::ssl::SslContext;
use boring::ssl::SslStream;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::InboundConfig;
use crate::inbound::Destination;
use crate::inbound::Inbound;
use crate::inbound::InboundConn;
use crate::inbound::anytls::build_ssl_context;
use crate::inbound::vless::VlessIo;
use crate::inbound::vless::VlessRequest;
use crate::inbound::vless::WsInboundConfig;
use crate::inbound::vless::WsServerStream;
use crate::inbound::vless::try_parse_vless_request;
use crate::outbound::mless::crypto::Obfuscation;
use crate::outbound::mless::frame::FLAG_CLOSE;
use crate::outbound::mless::frame::FLAG_DATA;
use crate::outbound::mless::frame::FLAG_FIRST;
use crate::outbound::mless::frame::decode_frame;
use crate::outbound::mless::frame::encode_frame;
use crate::outbound::vless::parse_uuid;
use crate::protocol::vless::VlessCommand;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

/// Budget for the TLS + ws handshakes and the unauthenticated session head.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle read tick while relaying. The single blocking IO loop only drains
/// server→client writes between reads, so this tick bounds how long a
/// queued frame waits behind a parked `read` (same rationale as the vless
/// inbound's 100 ms tick).
const RELAY_READ_TIMEOUT: Duration = Duration::from_millis(100);

/// Sanity cap on the unparseable frame tail. Legit frames are bounded by
/// the ws frame cap (~1 MB); a tail beyond this is garbage, not a frame.
const MAX_ACCUM: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Users / authentication
// ---------------------------------------------------------------------------

/// One authenticatable user: the 16-byte VLESS UUID and the original
/// password string, which doubles as the obfuscation key material
/// (`Obfuscation::new` hashes the dashed UUID string).
struct MlessUser {
    uuid: [u8; 16],
    secret: String,
}

/// Decrypt `payload` (the session's first frame) with each user's key and
/// return the user whose result parses as a VLESS request header carrying
/// their own UUID.
///
/// The obfuscation key is derived from the client's UUID string, which the
/// server only learns by decrypting — so the FIRST frame doubles as the
/// authenticator: a wrong key yields garbage that cannot contain the UUID.
/// `flags` must carry FLAG_FIRST (the client's first write on a session is
/// always the VLESS header). Returns the crypto instance (its recv counter
/// has already consumed this frame), the parsed request and the payload
/// bytes that followed the header.
fn select_user(
    users: &[MlessUser], flags: u8, payload: &[u8],
) -> Option<(Obfuscation, VlessRequest, Vec<u8>)> {
    if flags & FLAG_FIRST == 0 {
        return None;
    }
    for user in users {
        let mut probe = Obfuscation::new(&user.secret);
        let plain = probe.decrypt(payload);
        let Ok(Some((req, consumed))) = try_parse_vless_request(&plain) else {
            continue;
        };
        if req.uuid != user.uuid {
            continue;
        }
        return Some((probe, req, plain[consumed..].to_vec()));
    }
    None
}

// ---------------------------------------------------------------------------
// Session internals
// ---------------------------------------------------------------------------

/// Message from a stream relay to the session loop. Payloads are plaintext;
/// the loop handles encryption and framing (as the outbound's io_loop does).
enum SessionMsg {
    Data {
        stream_id: u64,
        payload: Vec<u8>,
    },
    Close {
        stream_id: u64,
    },
}

struct SessionInner {
    outbound_tx: mpsc::UnboundedSender<SessionMsg>,
    streams: StdMutex<HashMap<u64, StreamEntry>>,
}

struct StreamEntry {
    data_tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// Removes the stream's session-map entry when the relay drops the stream.
///
/// The entry carries the `data_tx` the session loop forwards client DATA
/// frames through, so it must outlive the handoff in [`open_stream`] —
/// dropping it early closes the channel and the relay sees an instant EOF
/// instead of the client's data.
struct StreamEntryGuard {
    stream_id: u64,
    inner: Arc<SessionInner>,
}

impl Drop for StreamEntryGuard {
    fn drop(&mut self) {
        self.inner.streams.lock().unwrap().remove(&self.stream_id);
    }
}

// ---------------------------------------------------------------------------
// Server-side stream relays
// ---------------------------------------------------------------------------

/// TCP [`StreamRelay`] for one multiplexed mless stream.
struct MlessServerStream {
    stream_id: u64,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    outbound_tx: mpsc::UnboundedSender<SessionMsg>,
    /// Payload bytes from a channel message not yet consumed by `read`.
    pending: Vec<u8>,
    /// Set once the client closed the stream (read side EOF).
    read_eof: bool,
    /// Set once `shutdown` sent CLOSE (or the client already closed).
    write_closed: bool,
    /// The 2-byte VLESS response `[0, 0]` must be prepended to the first
    /// server→client data frame — the outbound's TCP relay strips it there,
    /// and a response arriving standalone reads back as a false EOF.
    resp_pending: bool,
    /// Keeps the session-map entry (and thus the data channel) alive for
    /// as long as the relay holds this stream.
    _entry_guard: StreamEntryGuard,
}

#[async_trait]
impl StreamRelay for MlessServerStream {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.len());
                buf[..n].copy_from_slice(&self.pending[..n]);
                self.pending.drain(..n);
                return Ok(n);
            }
            if self.read_eof {
                return Ok(0);
            }
            match self.rx.recv().await {
                Some(data) => self.pending = data,
                None => {
                    self.read_eof = true;
                },
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if self.write_closed {
            return Err(std::io::Error::new(
                ErrorKind::BrokenPipe,
                "mless inbound stream closed",
            ));
        }
        if buf.is_empty() {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(2 + buf.len());
        if self.resp_pending {
            payload.extend_from_slice(&[0x00, 0x00]);
            self.resp_pending = false;
        }
        payload.extend_from_slice(buf);
        self.outbound_tx
            .send(SessionMsg::Data {
                stream_id: self.stream_id,
                payload,
            })
            .map_err(|_| {
                std::io::Error::new(
                    ErrorKind::BrokenPipe,
                    "mless inbound session dead",
                )
            })
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        if self.write_closed {
            return Ok(());
        }
        self.write_closed = true;
        if self.read_eof {
            // The client already tore the stream down (its CLOSE removed the
            // session entry, which is what EOF'd this read side); echoing a
            // CLOSE would only register as a rejected close on the client.
            return Ok(());
        }
        let _ = self.outbound_tx.send(SessionMsg::Close {
            stream_id: self.stream_id,
        });
        Ok(())
    }
}

impl Drop for MlessServerStream {
    fn drop(&mut self) {
        // Mirror the outbound's relay: closing the stream without shutdown
        // still notifies the peer.
        if !self.read_eof && !self.write_closed {
            let _ = self.outbound_tx.send(SessionMsg::Close {
                stream_id: self.stream_id,
            });
        }
    }
}

/// UDP [`PacketRelay`] for one multiplexed mless stream (VLESS command 0x02).
///
/// Every datagram is associated with the request's fixed destination and
/// sent as a raw DATA frame payload — the outbound's UDP relay frames it
/// the same way (no length prefix, no VLESS response).
struct MlessServerPacketRelay {
    stream_id: u64,
    dest: Destination,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    outbound_tx: mpsc::UnboundedSender<SessionMsg>,
    read_eof: bool,
    write_closed: bool,
    _entry_guard: StreamEntryGuard,
}

#[async_trait]
impl PacketRelay for MlessServerPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> std::io::Result<(usize, Destination)> {
        loop {
            if self.read_eof {
                return Ok((0, self.dest.clone()));
            }
            match self.rx.recv().await {
                Some(data) => {
                    if data.is_empty() {
                        continue;
                    }
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    return Ok((n, self.dest.clone()));
                },
                None => {
                    self.read_eof = true;
                },
            }
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], _dest: &Destination,
    ) -> std::io::Result<()> {
        if self.write_closed {
            return Err(std::io::Error::new(
                ErrorKind::BrokenPipe,
                "mless inbound udp stream closed",
            ));
        }
        self.outbound_tx
            .send(SessionMsg::Data {
                stream_id: self.stream_id,
                payload: buf.to_vec(),
            })
            .map_err(|_| {
                std::io::Error::new(
                    ErrorKind::BrokenPipe,
                    "mless inbound session dead",
                )
            })
    }

    async fn close(&mut self) -> std::io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            if !self.read_eof {
                let _ = self.outbound_tx.send(SessionMsg::Close {
                    stream_id: self.stream_id,
                });
            }
        }
        Ok(())
    }
}

impl Drop for MlessServerPacketRelay {
    fn drop(&mut self) {
        if !self.read_eof && !self.write_closed {
            let _ = self.outbound_tx.send(SessionMsg::Close {
                stream_id: self.stream_id,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Session loop (blocking)
// ---------------------------------------------------------------------------

/// Drain the relay write channel and flush encrypted frames to the client.
fn drain_outbound(
    io: &mut dyn VlessIo,
    outbound_rx: &mut mpsc::UnboundedReceiver<SessionMsg>,
    crypto: &mut Obfuscation,
) -> std::io::Result<()> {
    let mut frames = Vec::new();
    loop {
        match outbound_rx.try_recv() {
            Ok(SessionMsg::Data {
                stream_id,
                payload,
            }) => {
                // The client's recv counter only advances on non-empty
                // payloads; an encrypted empty frame would desync it.
                if payload.is_empty() {
                    continue;
                }
                let encrypted = crypto.encrypt(&payload);
                frames.extend_from_slice(&encode_frame(
                    stream_id,
                    FLAG_DATA,
                    &encrypted,
                ));
            },
            Ok(SessionMsg::Close { stream_id }) => {
                // CLOSE frames are written unencrypted (as the outbound's
                // io_loop does) and consume no keystream.
                frames
                    .extend_from_slice(&encode_frame(stream_id, FLAG_CLOSE, &[]));
            },
            Err(_) => break,
        }
    }
    if !frames.is_empty() {
        io.write_all(&frames)?;
        io.flush()?;
    }
    Ok(())
}

/// Register a new multiplexed stream from a parsed VLESS request header and
/// hand the [`InboundConn`] to the runner's relay loop.
///
/// The session-map entry inserted here is removed by the
/// [`StreamEntryGuard`] inside the relay once the relay drops it.
fn open_stream(
    inner: &Arc<SessionInner>, stream_id: u64, req: VlessRequest,
    first_payload: Vec<u8>, conn_tx: &mpsc::Sender<InboundConn>,
    peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    let (data_tx, data_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    inner.streams.lock().unwrap().insert(
        stream_id,
        StreamEntry {
            data_tx: data_tx.clone(),
        },
    );
    if !first_payload.is_empty() {
        let _ = data_tx.send(first_payload);
    }

    let guard = StreamEntryGuard {
        stream_id,
        inner: inner.clone(),
    };

    if matches!(req.command, VlessCommand::Udp) {
        log::debug!(
            "mless inbound: udp stream {stream_id} to {} from {peer}",
            req.dest,
        );
        let conn = InboundConn::Udp {
            initial_destination: req.dest.clone(),
            packet: Box::new(MlessServerPacketRelay {
                stream_id,
                dest: req.dest,
                rx: data_rx,
                outbound_tx: inner.outbound_tx.clone(),
                read_eof: false,
                write_closed: false,
                _entry_guard: guard,
            }),
            source: peer,
            type_: "mless".to_string(),
        };
        if conn_tx.blocking_send(conn).is_err() {
            return Err(std::io::Error::other("mless inbound: relay loop gone"));
        }
        return Ok(());
    }

    log::debug!(
        "mless inbound: tcp stream {stream_id} to {} from {peer}",
        req.dest,
    );
    let conn = InboundConn::Tcp {
        destination: req.dest,
        stream: Box::new(MlessServerStream {
            stream_id,
            rx: data_rx,
            outbound_tx: inner.outbound_tx.clone(),
            pending: Vec::new(),
            read_eof: false,
            write_closed: false,
            resp_pending: true,
            _entry_guard: guard,
        }),
        source: peer,
        type_: "mless".to_string(),
        sniff: false,
    };
    if conn_tx.blocking_send(conn).is_err() {
        return Err(std::io::Error::other("mless inbound: relay loop gone"));
    }
    Ok(())
}

/// Single blocking IO loop serving one established mless session:
/// alternately drains server→client frames and reads client→server frames
/// (the same single-IO-loop model as the anytls/vless inbounds — boring's
/// `SslStream` must not be touched from two threads).
fn handle_mless_session(
    mut io: Box<dyn VlessIo>, users: Arc<Vec<MlessUser>>,
    conn_tx: mpsc::Sender<InboundConn>, peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<SessionMsg>();
    let inner = Arc::new(SessionInner {
        outbound_tx,
        streams: StdMutex::new(HashMap::new()),
    });

    io.set_read_timeout(RELAY_READ_TIMEOUT);
    let started = Instant::now();

    // Selected by the session's first frame (see `select_user`).
    let mut crypto: Option<Obfuscation> = None;
    // UUID of the authenticated user; later streams must carry the same one.
    let mut authed_uuid: Option<[u8; 16]> = None;
    let mut buf = vec![0u8; 64 * 1024];
    // Accumulation buffer for cross-read frame boundaries (a frame may span
    // ws messages; several frames may share one).
    let mut accum: Vec<u8> = Vec::new();

    loop {
        // 1. Flush queued server→client frames (VLESS responses, relay
        //    writes, stream closes).
        if let Some(c) = crypto.as_mut() {
            drain_outbound(io.as_mut(), &mut outbound_rx, c)?;
        }

        // 2. Read the next chunk from the client.
        let n = match io.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut =>
            {
                if crypto.is_none() && started.elapsed() > HANDSHAKE_TIMEOUT {
                    return Err(std::io::Error::new(
                        ErrorKind::TimedOut,
                        "mless inbound: client never authenticated",
                    ));
                }
                continue;
            },
            Err(e) => return Err(e),
        };
        if !accum.is_empty() {
            accum.extend_from_slice(&buf[..n]);
        }
        let data: &[u8] = if accum.is_empty() {
            &buf[..n]
        } else {
            &accum[..]
        };

        // 3. Decode frames from the byte stream.
        let mut offset = 0usize;
        while offset < data.len() {
            let Some((stream_id, flags, payload, consumed)) =
                decode_frame(&data[offset..])
            else {
                if data.len() - offset > MAX_ACCUM {
                    return Err(std::io::Error::other(
                        "mless inbound: oversized frame",
                    ));
                }
                break;
            };
            offset += consumed;

            // CLOSE frames carry no encrypted payload and consume no
            // keystream: dropping the entry EOFs the stream's relay.
            if flags & FLAG_CLOSE != 0 {
                inner.streams.lock().unwrap().remove(&stream_id);
                continue;
            }

            if crypto.is_none() {
                // Session handshake: the first frame authenticates the
                // client and selects the per-user obfuscation key.
                let Some((chosen, req, rest)) =
                    select_user(users.as_slice(), flags, payload)
                else {
                    return Err(std::io::Error::new(
                        ErrorKind::PermissionDenied,
                        "mless inbound: auth failed",
                    ));
                };
                crypto = Some(chosen);
                authed_uuid = Some(req.uuid);
                log::debug!("mless inbound: session from {peer} authenticated");
                open_stream(&inner, stream_id, req, rest, &conn_tx, peer)?;
                continue;
            }

            // The client's io_loop encrypts every Data message, so the recv
            // counter advances even for an empty payload.
            let plain = crypto.as_mut().unwrap().decrypt(payload);

            if flags & FLAG_FIRST != 0 {
                // A new stream on the authenticated session: same header
                // format, must carry the authenticated user's UUID.
                let Some((req, header_len)) = try_parse_vless_request(&plain)
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "mless inbound: bad stream header: {e}"
                        ))
                    })?
                else {
                    return Err(std::io::Error::other(
                        "mless inbound: truncated stream header",
                    ));
                };
                if authed_uuid != Some(req.uuid) {
                    return Err(std::io::Error::new(
                        ErrorKind::PermissionDenied,
                        "mless inbound: stream uuid does not match session user",
                    ));
                }
                let rest = plain[header_len..].to_vec();
                open_stream(&inner, stream_id, req, rest, &conn_tx, peer)?;
            } else if let Some(entry) =
                inner.streams.lock().unwrap().get(&stream_id)
            {
                let _ = entry.data_tx.send(plain);
            } else {
                // Stream already closed — discard late data (the outbound's
                // multiplexer does the same).
                log::debug!(
                    "mless inbound: data for closed stream {stream_id} discarded"
                );
            }
        }

        // 4. Keep only the unparseable tail for the next read.
        if offset < data.len() {
            if data.as_ptr() == accum.as_ptr() {
                accum.drain(..offset);
            } else {
                accum = data[offset..].to_vec();
            }
        } else {
            accum.clear();
        }
    }

    io.close();
    Ok(())
}

// ---------------------------------------------------------------------------
// MlessInbound
// ---------------------------------------------------------------------------

/// Server-side mless inbound. See the module docs for the protocol model.
pub struct MlessInbound {
    conn_rx: mpsc::Receiver<InboundConn>,
}

impl MlessInbound {
    /// Create a mless inbound from config.
    ///
    /// Requires `listen` and a `[transport.ws]` section (the mless outbound
    /// always tunnels its frames through a transport). TLS is enabled when
    /// both `cert` and `key` are set. Authentication and key material come
    /// from the global `[[users]]` section: each password is the VLESS UUID
    /// and the obfuscation key seed, exactly like the outbound's `password`.
    /// Returns `None` if the config is unusable.
    pub fn from_config(
        config: &InboundConfig, passwords: Vec<String>,
    ) -> Option<Self> {
        let listen = config.listen.as_ref()?;

        let tls = match (&config.cert, &config.key) {
            (Some(cert), Some(key)) => match build_ssl_context(cert, key) {
                Ok(ctx) => Some(Arc::new(ctx)),
                Err(e) => {
                    log::error!("mless inbound: failed to load cert/key: {e}");
                    return None;
                },
            },
            (None, None) => None,
            _ => {
                log::error!("mless inbound: cert and key must be set together");
                return None;
            },
        };

        let ws = match &config.transport {
            Some(t) => {
                if t.type_ != "ws" {
                    log::error!(
                        "mless inbound: unsupported transport type '{}'",
                        t.type_
                    );
                    return None;
                }
                let Some(ws_cfg) = t.ws.as_ref() else {
                    log::error!(
                        "mless inbound: [transport] present without [transport.ws]"
                    );
                    return None;
                };
                let path =
                    ws_cfg.path.clone().unwrap_or_else(|| "/".to_string());
                let host = ws_cfg
                    .headers
                    .as_ref()
                    .and_then(|h| h.get("Host"))
                    .cloned();
                Arc::new(WsInboundConfig { path, host })
            },
            None => {
                log::error!(
                    "mless inbound: requires [transport.ws] (the mless \
                     outbound always tunnels over a transport)"
                );
                return None;
            },
        };

        let mut users = Vec::new();
        for pw in &passwords {
            match parse_uuid(pw) {
                Ok(uuid) => users.push(MlessUser {
                    uuid,
                    secret: pw.clone(),
                }),
                Err(_) => {
                    log::debug!(
                        "mless inbound: user password is not a UUID, skipping"
                    );
                },
            }
        }
        if users.is_empty() {
            log::error!(
                "mless inbound: no [[users]] password parses as a VLESS UUID"
            );
            return None;
        }

        let (conn_tx, conn_rx) = mpsc::channel(256);
        let listen_addr = listen.clone();

        tokio::spawn(async move {
            Self::run(listen_addr, tls, ws, Arc::new(users), conn_tx).await;
        });

        Some(Self { conn_rx })
    }

    async fn run(
        listen_addr: String, tls: Option<Arc<SslContext>>,
        ws: Arc<WsInboundConfig>, users: Arc<Vec<MlessUser>>,
        conn_tx: mpsc::Sender<InboundConn>,
    ) {
        let listener = match TcpListener::bind(&listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                log::error!("mless inbound: failed to bind {listen_addr}: {e}");
                return;
            },
        };
        log::info!("mless inbound listening on {listen_addr}");

        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("mless inbound: accept error: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                },
            };

            log::debug!("mless inbound: new connection from {peer}");

            let tls = tls.clone();
            let ws = ws.clone();
            let users = users.clone();
            let tx = conn_tx.clone();

            // boring is synchronous: the TLS accept, the ws handshake and
            // the session loop below all block on std reads, so they must
            // run on the blocking pool — an async worker would be pinned
            // for the lifetime of the connection.
            tokio::task::spawn_blocking(move || {
                handle_mless_conn(tcp, peer, tls, ws, users, tx);
            });
        }
    }
}

/// Blocking handler for one accepted TCP connection: TLS (optional) → ws
/// upgrade → authenticated session loop.
fn handle_mless_conn(
    tcp: tokio::net::TcpStream, peer: std::net::SocketAddr,
    tls: Option<Arc<SslContext>>, ws: Arc<WsInboundConfig>,
    users: Arc<Vec<MlessUser>>, conn_tx: mpsc::Sender<InboundConn>,
) {
    let std_stream = match tcp.into_std() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("mless inbound: failed to convert stream from {peer}: {e}");
            return;
        },
    };
    // tokio hands the raw fd over in nonblocking mode; the blocking TLS
    // accept (and everything below) would fail with WANT_READ otherwise.
    if let Err(e) = std_stream.set_nonblocking(false) {
        log::warn!("mless inbound: failed to set blocking mode: {e}");
        return;
    }
    let _ = std_stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));

    // --- optional TLS ---
    let io: Box<dyn VlessIo> = match &tls {
        Some(ctx) => {
            let ssl = match Ssl::new(ctx) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("mless inbound: SSL new failed from {peer}: {e}");
                    return;
                },
            };
            let mut stream = match SslStream::new(ssl, std_stream) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!(
                        "mless inbound: SSL stream failed from {peer}: {e}"
                    );
                    return;
                },
            };
            if let Err(e) = stream.accept() {
                log::debug!(
                    "mless inbound: TLS handshake from {peer} failed: {e}"
                );
                return;
            }
            Box::new(stream)
        },
        None => Box::new(std_stream),
    };

    // --- ws upgrade ---
    let io = match WsServerStream::handshake(io, &ws.path, ws.host.as_deref()) {
        Ok(w) => Box::new(w),
        Err(e) => {
            log::debug!("mless inbound: ws handshake from {peer} failed: {e}");
            return;
        },
    };

    if let Err(e) = handle_mless_session(io, users, conn_tx, peer) {
        log::debug!("mless inbound: session from {peer} ended: {e}");
    }
}

#[async_trait]
impl Inbound for MlessInbound {
    async fn accept(&mut self) -> Option<InboundConn> {
        self.conn_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::Address;
    use crate::outbound::mless::vless::build_vless_header;

    const ALICE: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const BOB: &str = "23af8f9c-1e3f-4a7d-9b2e-6c5d4e3f2a1b";

    fn users() -> Vec<MlessUser> {
        vec![
            MlessUser {
                uuid: parse_uuid(ALICE).unwrap(),
                secret: ALICE.to_string(),
            },
            MlessUser {
                uuid: parse_uuid(BOB).unwrap(),
                secret: BOB.to_string(),
            },
        ]
    }

    /// The server must authenticate with exactly the key material the
    /// outbound derives from its `password`: a FIRST frame encrypted under a
    /// user's UUID string selects that user, and the trailing payload bytes
    /// survive intact.
    #[test]
    fn select_user_authenticates_outbound_first_frame() {
        let dest = Destination::new(Address::Ipv4([127, 0, 0, 1]), 8080);
        let mut payload =
            build_vless_header(&parse_uuid(ALICE).unwrap(), &dest, false);
        payload.extend_from_slice(b"GET / HTTP/1.1");

        // The client encrypts the payload with its own crypto instance.
        let mut client = Obfuscation::new(ALICE);
        let ct = client.encrypt(&payload);

        let (mut server, req, rest) =
            select_user(&users(), FLAG_FIRST, &ct).expect("alice authenticated");
        assert_eq!(req.uuid, parse_uuid(ALICE).unwrap());
        assert_eq!(req.dest, dest);
        assert_eq!(rest, b"GET / HTTP/1.1");

        // Frames after the handshake decrypt under the selected instance.
        let ct2 = client.encrypt(b"hello");
        assert_eq!(server.decrypt(&ct2), b"hello");
    }

    /// Multiple users: the frame encrypted under the second user's key must
    /// select that user; keys no user owns authenticate nobody.
    #[test]
    fn select_user_picks_matching_user_and_rejects_wrong_key() {
        let dest = Destination::new(Address::Domain("example.com".into()), 53);
        let payload =
            build_vless_header(&parse_uuid(BOB).unwrap(), &dest, true);
        let mut bob = Obfuscation::new(BOB);
        let ct = bob.encrypt(&payload);

        let (mut server, req, rest) =
            select_user(&users(), FLAG_FIRST, &ct).expect("bob authenticated");
        assert_eq!(req.uuid, parse_uuid(BOB).unwrap());
        assert!(rest.is_empty());
        // Frames after the handshake decrypt under the selected instance.
        let ct2 = bob.encrypt(b"ping");
        assert_eq!(server.decrypt(&ct2), b"ping");

        // A key no user owns yields garbage that cannot authenticate.
        let mut evil = Obfuscation::new("00000000-0000-4000-8000-000000000000");
        let ct = evil.encrypt(&payload);
        assert!(select_user(&users(), FLAG_FIRST, &ct).is_none());
    }

    /// The client's first write on a session is always a FIRST frame; a
    /// DATA flag alone must not authenticate.
    #[test]
    fn select_user_requires_first_flag() {
        let dest = Destination::new(Address::Ipv4([127, 0, 0, 1]), 80);
        let payload =
            build_vless_header(&parse_uuid(ALICE).unwrap(), &dest, false);
        let mut client = Obfuscation::new(ALICE);
        let ct = client.encrypt(&payload);
        assert!(select_user(&users(), FLAG_DATA, &ct).is_none());
        assert!(select_user(&users(), FLAG_FIRST, &ct).is_some());
    }

    /// Counter alignment contract: the client's io_loop encrypts every Data
    /// message (empty payloads included), so the server's recv counter must
    /// advance for every non-CLOSE frame; CLOSE frames are written
    /// unencrypted and must consume nothing.
    #[test]
    fn decrypt_counters_track_client_send_counters() {
        let mut client = Obfuscation::new(ALICE);
        let mut server = Obfuscation::new(ALICE);

        let f1 = client.encrypt(b"one");
        let f2 = client.encrypt(b""); // empty Data: counter still advances
        let f3 = client.encrypt(b"three");

        assert_eq!(server.decrypt(&f1), b"one");
        assert_eq!(server.decrypt(&f2), b"");
        assert_eq!(server.decrypt(&f3), b"three");
    }

    /// The shipped example must keep parsing with the exact field names the
    /// inbound reads (`listen`, `cert`, `key`, `[transport.ws]`).
    #[test]
    fn example_server_config_parses() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config/mless-server.toml");
        let raw = std::fs::read_to_string(&path).unwrap();
        let cfg: crate::config::Config = toml::from_str(&raw).unwrap();
        let inbound = cfg
            .inbounds_by_type("mless")
            .first()
            .copied()
            .expect("mless inbound in example");
        assert_eq!(inbound.listen.as_deref(), Some("0.0.0.0:8443"));
        assert!(inbound.cert.is_some() && inbound.key.is_some());
        let transport = inbound.transport.as_ref().expect("ws transport");
        assert_eq!(transport.type_, "ws");
        assert_eq!(
            transport.ws.as_ref().unwrap().path.as_deref(),
            Some("/ws")
        );
        // The example's [[users]].password must authenticate: parsed as the
        // VLESS UUID and used as the obfuscation key, like the outbound.
        let uuids: Vec<_> = cfg
            .passwords()
            .iter()
            .filter_map(|p| parse_uuid(p).ok())
            .collect();
        assert_eq!(uuids.len(), 1);
    }
}
