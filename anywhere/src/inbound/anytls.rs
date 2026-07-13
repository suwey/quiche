// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! AnyTLS inbound server.
//!
//! Accepts incoming TLS connections, authenticates via SHA-256 password hash,
//! negotiates padding settings, and multiplexes TCP streams. Each client stream
//! is relayed to an upstream destination decoded from the SOCKS5 address
//! format.

use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

use async_trait::async_trait;
use boring::ssl::Ssl;
use boring::ssl::SslContextBuilder;
use boring::ssl::SslFiletype;
use boring::ssl::SslMethod;
use boring::ssl::SslStream;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::InboundConfig;
use crate::inbound::Address;
use crate::inbound::Destination;
use crate::inbound::Inbound;
use crate::inbound::InboundConn;
use crate::protocol::anytls as proto;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

use proto::CHECK_MARK;
use proto::CMD_ALERT;
use proto::CMD_FIN;
use proto::CMD_HEART_REQUEST;
use proto::CMD_HEART_RESPONSE;
use proto::CMD_PSH;
use proto::CMD_SERVER_SETTINGS;
use proto::CMD_SETTINGS;
use proto::CMD_SYN;
use proto::CMD_SYNACK;
use proto::CMD_WASTE;
use proto::PROTOCOL_VERSION;
use proto::PaddingFactory;
use proto::cmd_name;
use proto::decode_socks_addr;
use proto::encode_frame;
use proto::read_frame_blocking;
use proto::target_addr_len;

// ========== Server-side stream I/O types ==========

/// Read half of a server-side multiplexed stream.
struct ServerStreamReader {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    buf: Vec<u8>,
    closed: bool,
}

/// Write half of a server-side multiplexed stream.
struct ServerStreamWriter {
    stream_id: u32,
    writer_tx: mpsc::UnboundedSender<OutboundMsg>,
    closed: bool,
}

/// Combined `StreamRelay` adapter for a server-side anytls stream.
struct ServerStream {
    reader: ServerStreamReader,
    writer: ServerStreamWriter,
}

#[async_trait]
impl StreamRelay for ServerStream {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.reader.buf.is_empty() {
                let n = self.reader.buf.len().min(buf.len());
                buf[..n].copy_from_slice(&self.reader.buf[..n]);
                self.reader.buf.drain(..n);
                return Ok(n);
            }
            if self.reader.closed {
                return Ok(0);
            }
            match self.reader.rx.recv().await {
                Some(data) => {
                    self.reader.buf = data;
                },
                None => {
                    self.reader.closed = true;
                },
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if self.writer.closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ));
        }
        self.writer
            .writer_tx
            .send(OutboundMsg::StreamData(self.writer.stream_id, buf.to_vec()))
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "session dead",
                )
            })?;
        Ok(())
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        if self.writer.closed {
            return Ok(());
        }
        let _ = self.writer.writer_tx.send(OutboundMsg::RawFrame(
            encode_frame(CMD_FIN, self.writer.stream_id, &[]).unwrap_or_default(),
        ));
        self.writer.closed = true;
        Ok(())
    }
}

// ========== UoT (UDP-over-TCP) server-side relay ==========

/// Read the UoT v2 request frame from the stream and return the initial
/// destination.  Uses SOCKS5 ATYP (0x01/0x03/0x04) per sing's
/// `protocol.go::WriteRequest`.
async fn read_uot_request(
    stream: &mut ServerStream,
) -> std::io::Result<Destination> {
    // Request: [isConnect:u8][ATYP:u8][addr...][port:u16]
    let mut is_connect_buf = [0u8; 1];
    stream.read(&mut is_connect_buf).await?;
    let _is_connect = is_connect_buf[0] != 0;

    let mut atyp_buf = [0u8; 1];
    stream.read(&mut atyp_buf).await?;
    let atyp = atyp_buf[0];

    let address = match atyp {
        proto::SOCKS_ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read(&mut octets).await?;
            Address::Ipv4(octets)
        },
        proto::SOCKS_ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read(&mut octets).await?;
            Address::Ipv6(octets)
        },
        proto::SOCKS_ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read(&mut len_buf).await?;
            let dlen = len_buf[0] as usize;
            let mut domain = vec![0u8; dlen];
            stream.read(&mut domain).await?;
            let s = std::str::from_utf8(&domain).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "uot bad domain utf8",
                )
            })?;
            Address::Domain(s.to_string())
        },
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("uot request bad ATYP {other:#04x}"),
            ));
        },
    };

    let mut port_buf = [0u8; 2];
    stream.read(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(Destination::new(address, port))
}

/// Server-side UoT `PacketRelay` wrapping a `ServerStream`.
///
/// Reads associate-mode datagrams from the client stream and writes
/// associate-mode datagrams back.  The initial UoT request is consumed
/// during construction via [`read_uot_request`].
struct UotServerPacketRelay {
    stream: ServerStream,
    read_buf: Vec<u8>,
}

#[async_trait]
impl PacketRelay for UotServerPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> std::io::Result<(usize, Destination)> {
        let mut scratch = [0u8; 4096];
        loop {
            if let Some((dest, data_range, consumed)) =
                proto::uot_try_parse_associate_packet(&self.read_buf)?
            {
                let data = &self.read_buf[data_range];
                if buf.len() < data.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "uot read buffer too small",
                    ));
                }
                let n = data.len();
                buf[..n].copy_from_slice(data);
                self.read_buf.drain(..consumed);
                return Ok((n, dest));
            }
            let n = self.stream.read(&mut scratch).await?;
            if n == 0 {
                return Ok((0, Destination::new(Address::Ipv4([0; 4]), 0)));
            }
            self.read_buf.extend_from_slice(&scratch[..n]);
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], dest: &Destination,
    ) -> std::io::Result<()> {
        let frame = proto::uot_encode_associate_packet(dest, buf)?;
        self.stream.write(&frame).await?;
        Ok(())
    }

    async fn close(&mut self) -> std::io::Result<()> {
        self.stream.shutdown().await
    }
}

// ========== Internal message types ==========

enum OutboundMsg {
    StreamData(u32, Vec<u8>),
    RawFrame(Vec<u8>),
}

// ========== Session internals ==========

struct SessionInner {
    outbound_tx: mpsc::UnboundedSender<OutboundMsg>,
    streams: StdMutex<HashMap<u32, StreamSender>>,
    closed: AtomicBool,
    padding: StdMutex<PaddingFactory>,
}

struct StreamSender {
    data_tx: mpsc::UnboundedSender<Vec<u8>>,
}

// ========== Write task (blocking) ==========

fn write_padded(
    stream: &mut SslStream<TcpStream>, mut data: Vec<u8>,
    padding: &StdMutex<PaddingFactory>, pkt: u32,
) -> std::io::Result<()> {
    let pf = padding.lock().unwrap();
    if pkt >= pf.stop() {
        drop(pf);
        stream.write_all(&data)?;
        stream.flush()?;
        return Ok(());
    }
    let sizes = pf.generate_sizes(pkt);
    drop(pf);
    if sizes.is_empty() {
        stream.write_all(&data)?;
        stream.flush()?;
        return Ok(());
    }
    for &size in &sizes {
        let remain = data.len();
        if size == CHECK_MARK {
            if remain == 0 {
                break;
            }
            continue;
        }
        let size = size.max(0) as usize;
        if remain > size {
            let rest = data.split_off(size);
            stream.write_all(&data)?;
            data = rest;
        } else if remain > 0 {
            let pad_len = size.saturating_sub(remain).saturating_sub(7);
            if pad_len > 0 {
                let mut pad = vec![0u8; 7 + pad_len];
                pad[0] = CMD_WASTE;
                pad[5..7].copy_from_slice(&(pad_len as u16).to_be_bytes());
                data.extend_from_slice(&pad);
            }
            stream.write_all(&data)?;
            data.clear();
        } else {
            let mut pad = vec![0u8; 7 + size];
            pad[0] = CMD_WASTE;
            pad[5..7].copy_from_slice(&(size as u16).to_be_bytes());
            stream.write_all(&pad)?;
        }
    }
    if !data.is_empty() {
        stream.write_all(&data)?;
    }
    stream.flush()?;
    Ok(())
}

// ========== Server session handler ==========

fn handle_connection_inner(
    mut stream: SslStream<TcpStream>, passwords: Arc<Vec<String>>,
    padding: PaddingFactory, conn_tx: mpsc::Sender<InboundConn>,
    peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    // --- Auth ---
    let mut auth_header = [0u8; 34]; // 32 hash + 2 pad_len
    stream.read_exact(&mut auth_header)?;
    let hash: [u8; 32] = auth_header[..32].try_into().unwrap();
    let pad_len = u16::from_be_bytes([auth_header[32], auth_header[33]]) as usize;

    // Read and discard padding.
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        stream.read_exact(&mut pad)?;
    }

    // Verify password.
    let mut auth_ok = false;
    for pw in passwords.iter() {
        if let Ok(pw_hash) = proto::sha256(pw.as_bytes()) {
            if hash == pw_hash {
                auth_ok = true;
                break;
            }
        }
    }
    if !auth_ok {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "auth failed",
        ));
    }

    // --- Build session ---
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<OutboundMsg>();

    let inner = Arc::new(SessionInner {
        outbound_tx: outbound_tx.clone(),
        streams: StdMutex::new(HashMap::new()),
        closed: AtomicBool::new(false),
        padding: StdMutex::new(padding.clone()),
    });

    // Split TLS stream: read half stays here, write half goes to write task.
    // We use the same SslStream for reading by setting a read timeout.
    // But we can't share one stream between threads, so we use a different
    // approach: read in this thread, write in a spawned thread via channels.
    //
    // Since `SslStream<TcpStream>` can't be split natively, we run the read
    // loop in this thread and the write loop in a separate thread. We use
    // `try_clone()` on the underlying TcpStream to get a separate fd for
    // writing, and wrap it in a new SslStream... but that doesn't work for
    // TLS since both sides share the TLS session state.
    //
    // The solution: run the write loop on a *channel-based* writer. The write
    // task drains the channel and writes to the TLS stream. The read loop
    // runs in this thread reading from the same TLS stream.
    //
    // However, TLS streams are NOT thread-safe for concurrent read/write on
    // the same object. We must either:
    //   a) use a single-threaded IO loop (like the outbound does), or
    //   b) use tokio::io::split on an async wrapper.
    //
    // Following the outbound's pattern (option a), we use a single IO loop
    // that handles both reading and writing. The "write task" sends frames
    // through the outbound channel, and the IO loop writes them.

    // Actually, the cleanest approach is a single IO loop that alternates
    // between reading frames and draining the outbound channel, similar to
    // the outbound's run_io_loop.

    // --- Read until we get CMD_SETTINGS ---
    stream
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();

    let mut client_version: u32 = 0;
    let mut pending_syn: HashMap<u32, Vec<u8>> = HashMap::new();

    loop {
        let (cmd, stream_id, data) = read_frame_blocking(&mut stream)?;
        match cmd {
            CMD_SETTINGS => {
                let settings = proto::parse_settings(&data)?;
                if let Some(v) = settings.get("v") {
                    client_version = v.parse().unwrap_or(0);
                }

                // Check padding md5; if mismatch, send update.
                let client_md5 =
                    settings.get("padding-md5").cloned().unwrap_or_default();
                let server_md5 = PaddingFactory::md5_hex(
                    proto::DEFAULT_PADDING_SCHEME.as_bytes(),
                );
                // For simplicity, we always compare against default for now.
                // If a custom scheme is configured, we'd use that instead.
                //
                // TODO: on `client_md5 != server_md5` mismatch, send a
                // padding scheme update to the client. For now always match
                // and skip the update.
                let _ = (client_md5, server_md5);

                // Send server settings if client v >= 2.
                if client_version >= PROTOCOL_VERSION {
                    let body = proto::build_server_settings_body();
                    if let Ok(frame) =
                        encode_frame(CMD_SERVER_SETTINGS, 0, body.as_bytes())
                    {
                        let _ = outbound_tx.send(OutboundMsg::RawFrame(frame));
                    }
                }

                break;
            },
            CMD_SYN | CMD_PSH => {
                // Client sent stream data before settings — reject.
                if let Ok(frame) =
                    encode_frame(CMD_ALERT, 0, b"settings required")
                {
                    let _ = outbound_tx.send(OutboundMsg::RawFrame(frame));
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "client sent stream data before settings",
                ));
            },
            CMD_WASTE => {},
            _ => {},
        }
        let _ = stream_id;
    }

    // Drain any queued outbound frames (e.g. server settings).
    drain_outbound(&mut stream, &mut outbound_rx, &inner, &mut 1u32);

    // --- Main session loop ---
    stream
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();

    loop {
        // First drain outbound channel.
        drain_outbound(&mut stream, &mut outbound_rx, &inner, &mut {
            // Use a simple counter starting from 2.
            2u32
        });

        match read_frame_blocking(&mut stream) {
            Ok((cmd, stream_id, data)) => {
                log::debug!(
                    "anytls inbound: recv cmd={} sid={stream_id} len={} from {peer}",
                    cmd_name(cmd),
                    data.len()
                );

                match cmd {
                    CMD_WASTE => {},
                    CMD_SYN => {
                        pending_syn.insert(stream_id, Vec::new());
                    },
                    CMD_PSH => {
                        if pending_syn.contains_key(&stream_id) {
                            let mut pending_data =
                                pending_syn.remove(&stream_id).unwrap();
                            pending_data.extend_from_slice(&data);

                            let addr_len = target_addr_len(&pending_data);
                            if addr_len > 0 && pending_data.len() >= addr_len {
                                let target = decode_socks_addr(&pending_data)?;
                                let remaining_data =
                                    pending_data[addr_len..].to_vec();

                                let (data_tx, data_rx) =
                                    mpsc::unbounded_channel::<Vec<u8>>();
                                {
                                    let mut streams =
                                        inner.streams.lock().unwrap();
                                    streams.insert(stream_id, StreamSender {
                                        data_tx: data_tx.clone(),
                                    });
                                }

                                if !remaining_data.is_empty() {
                                    let _ = data_tx.send(remaining_data);
                                }

                                // Spawn relay for this stream.
                                let inner_clone = inner.clone();
                                let writer_tx_clone = inner.outbound_tx.clone();
                                let client_ver = client_version;
                                let conn_tx_clone = conn_tx.clone();
                                let peer_clone = peer;
                                tokio::spawn(async move {
                                    if let Err(e) = handle_server_stream(
                                        stream_id,
                                        &target,
                                        data_rx,
                                        writer_tx_clone,
                                        client_ver,
                                        conn_tx_clone,
                                        peer_clone,
                                    )
                                    .await
                                    {
                                        log::debug!(
                                            "anytls inbound: stream {stream_id} relay ended: {e}"
                                        );
                                    }
                                    let mut streams =
                                        inner_clone.streams.lock().unwrap();
                                    streams.remove(&stream_id);
                                });
                            } else {
                                pending_syn.insert(stream_id, pending_data);
                            }
                        } else {
                            let streams = inner.streams.lock().unwrap();
                            if let Some(sender) = streams.get(&stream_id) {
                                let _ = sender.data_tx.send(data);
                            }
                        }
                    },
                    CMD_FIN =>
                        if pending_syn.contains_key(&stream_id) {
                            pending_syn.remove(&stream_id);
                        } else {
                            let mut streams = inner.streams.lock().unwrap();
                            if let Some(sender) = streams.remove(&stream_id) {
                                drop(sender.data_tx);
                            }
                        },
                    CMD_HEART_REQUEST => {
                        if let Ok(frame) =
                            encode_frame(CMD_HEART_RESPONSE, stream_id, &[])
                        {
                            let _ = inner
                                .outbound_tx
                                .send(OutboundMsg::RawFrame(frame));
                        }
                    },
                    CMD_ALERT => {
                        let msg = String::from_utf8_lossy(&data).to_string();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            format!("client alert: {msg}"),
                        ));
                    },
                    CMD_SETTINGS => {},
                    _ => {
                        log::debug!(
                            "anytls inbound: unknown cmd {cmd} from {peer}"
                        );
                    },
                }
            },
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock ||
                    e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Send heartbeat.
                if let Ok(frame) = encode_frame(CMD_HEART_REQUEST, 0, &[]) {
                    let _ = inner.outbound_tx.send(OutboundMsg::RawFrame(frame));
                }
                drain_outbound(&mut stream, &mut outbound_rx, &inner, &mut 2u32);
            },
            Err(e) => {
                log::debug!("anytls inbound: read error from {peer}: {e}");
                return Err(e);
            },
        }

        if inner.closed.load(SeqCst) {
            break;
        }
    }

    Ok(())
}

/// Drain the outbound channel and write any queued frames to the TLS stream.
fn drain_outbound(
    stream: &mut SslStream<TcpStream>,
    outbound_rx: &mut mpsc::UnboundedReceiver<OutboundMsg>, inner: &SessionInner,
    pkt_counter: &mut u32,
) {
    let mut buf = Vec::new();
    loop {
        match outbound_rx.try_recv() {
            Ok(OutboundMsg::StreamData(sid, data)) => {
                if let Ok(frame) = encode_frame(CMD_PSH, sid, &data) {
                    buf.extend_from_slice(&frame);
                }
            },
            Ok(OutboundMsg::RawFrame(frame)) => {
                buf.extend_from_slice(&frame);
            },
            Err(_) => break,
        }
    }
    if !buf.is_empty() {
        let pkt = *pkt_counter;
        *pkt_counter += 1;
        let _ = write_padded(stream, buf, &inner.padding, pkt);
    }
}

/// Handle a single server-side stream: parse destination, build ServerStream,
/// and send InboundConn so the main relay loop can dial outbound and proxy.
async fn handle_server_stream(
    stream_id: u32, target: &str, data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    writer_tx: mpsc::UnboundedSender<OutboundMsg>, client_version: u32,
    conn_tx: mpsc::Sender<InboundConn>, peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    // Parse destination.
    let destination: Destination = target.parse().map_err(|e: String| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
    })?;

    // Send SYNACK success if client v >= 2.
    if client_version >= PROTOCOL_VERSION {
        if let Ok(frame) = encode_frame(CMD_SYNACK, stream_id, &[]) {
            let _ = writer_tx.send(OutboundMsg::RawFrame(frame));
        }
    }

    // Build a ServerStream relay that reads from data_rx and writes via
    // writer_tx.
    let reader = ServerStreamReader {
        rx: data_rx,
        buf: Vec::new(),
        closed: false,
    };
    let writer = ServerStreamWriter {
        stream_id,
        writer_tx: writer_tx.clone(),
        closed: false,
    };
    let mut server_stream = ServerStream { reader, writer };

    // Check for UoT v2 magic address — if matched, enter UDP relay mode.
    if target.starts_with(proto::UOT_MAGIC_ADDRESS) {
        log::debug!("anytls inbound: stream {stream_id} UoT mode from {peer}");

        // Read the UoT request to get the initial destination.
        let initial_dest = read_uot_request(&mut server_stream).await?;

        let relay = UotServerPacketRelay {
            stream: server_stream,
            read_buf: Vec::with_capacity(2048),
        };

        let inbound_conn = InboundConn::Udp {
            initial_destination: initial_dest,
            packet: Box::new(relay),
            source: peer,
            type_: "anytls".to_string(),
        };

        if conn_tx.send(inbound_conn).await.is_err() {
            log::debug!(
                "anytls inbound: UoT stream {stream_id} failed to send InboundConn"
            );
        }
        return Ok(());
    }

    // TCP relay mode.
    log::debug!("anytls inbound: stream {stream_id} target {destination}");

    // Send InboundConn to the main relay loop. The relay loop will dial
    // the outbound via the registry and handle bidirectional relay.
    let inbound_conn = InboundConn::Tcp {
        destination,
        stream: Box::new(server_stream),
        source: peer,
        type_: "anytls".to_string(),
        sniff: false,
    };

    if conn_tx.send(inbound_conn).await.is_err() {
        log::debug!(
            "anytls inbound: stream {stream_id} failed to send InboundConn"
        );
    }

    Ok(())
}

// ========== TLS Acceptor ==========

fn build_ssl_context(
    cert_path: &str, key_path: &str,
) -> std::io::Result<boring::ssl::SslContext> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    builder
        .set_certificate_file(cert_path, SslFiletype::PEM)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to load cert {cert_path}: {e}"),
            )
        })?;
    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to load key {key_path}: {e}"),
            )
        })?;
    builder.check_private_key().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("private key check failed: {e}"),
        )
    })?;
    Ok(builder.build())
}

// ========== AnytlsInbound ==========

/// Server-side anytls inbound.
///
/// Listens for TLS connections, authenticates clients via SHA-256 password
/// hash, negotiates padding settings, and yields [`InboundConn`] values for
/// each multiplexed stream.
pub struct AnytlsInbound {
    conn_rx: mpsc::Receiver<InboundConn>,
}

impl AnytlsInbound {
    /// Create a new anytls inbound from config.
    ///
    /// Requires `listen`, `cert`, and `key` fields in the config. Passwords
    /// are taken from the global `[[users]]` section. Returns `None` if
    /// required fields are missing.
    pub fn from_config(
        config: &InboundConfig, passwords: Vec<String>,
    ) -> Option<Self> {
        let listen = config.listen.as_ref()?;
        let cert = config.cert.as_ref()?;
        let key = config.key.as_ref()?;

        let padding = if let Some(ref scheme_text) = config.padding_scheme {
            PaddingFactory::new(scheme_text.as_bytes()).unwrap_or_else(|e| {
                log::warn!(
                    "anytls inbound: failed to parse custom padding scheme: {e}, using default"
                );
                PaddingFactory::default_factory()
            })
        } else {
            PaddingFactory::default_factory()
        };

        let (conn_tx, conn_rx) = mpsc::channel(256);

        let listen_addr = listen.clone();
        let cert = cert.clone();
        let key = key.clone();

        tokio::spawn(async move {
            Self::run(listen_addr, cert, key, passwords, padding, conn_tx).await;
        });

        Some(Self { conn_rx })
    }

    async fn run(
        listen_addr: String, cert: String, key: String, passwords: Vec<String>,
        padding: PaddingFactory, conn_tx: mpsc::Sender<InboundConn>,
    ) {
        let ctx = match build_ssl_context(&cert, &key) {
            Ok(a) => a,
            Err(e) => {
                log::error!("anytls inbound: failed to build TLS acceptor: {e}");
                return;
            },
        };

        let listener = match TcpListener::bind(&listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                log::error!("anytls inbound: failed to bind {listen_addr}: {e}");
                return;
            },
        };
        log::info!("anytls inbound listening on {listen_addr}");

        let passwords = Arc::new(passwords);

        let ctx_arc = Arc::new(ctx);
        let ctx_clone = ctx_arc.clone();

        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("anytls inbound: accept error: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                },
            };

            log::debug!("anytls inbound: new connection from {peer}");

            let acceptor = ctx_clone.clone();
            let pw = passwords.clone();
            let pad = padding.clone();
            let tx = conn_tx.clone();

            tokio::spawn(async move {
                // Perform TLS accept in spawn_blocking (boring is sync).
                let std_stream = match tcp.into_std() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!(
                            "anytls inbound: failed to convert tcp stream: {e}"
                        );
                        return;
                    },
                };

                let ssl = match Ssl::new(&acceptor) {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("anytls inbound: SSL new failed: {e}");
                        return;
                    },
                };

                let mut ssl_stream = match SslStream::new(ssl, std_stream) {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("anytls inbound: SSL stream failed: {e}");
                        return;
                    },
                };

                if let Err(e) = ssl_stream.accept() {
                    log::warn!(
                        "anytls inbound: TLS handshake from {peer} failed: {e}"
                    );
                    return;
                }

                log::debug!("anytls inbound: TLS handshake OK from {peer}");

                // Run the session handler (blocking).
                if let Err(e) =
                    handle_connection_inner(ssl_stream, pw, pad, tx, peer)
                {
                    log::debug!("anytls inbound: session from {peer} ended: {e}");
                }
            });
        }
    }
}

#[async_trait]
impl Inbound for AnytlsInbound {
    async fn accept(&mut self) -> Option<InboundConn> {
        self.conn_rx.recv().await
    }
}
