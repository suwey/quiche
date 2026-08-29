// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! SIP003 `obfs-local` plugin for the Shadowsocks outbound.
//!
//! Wraps a [`TcpStream`] with simple-obfs traffic obfuscation so that the
//! Shadowsocks byte stream looks like ordinary HTTP/WebSocket or TLS traffic to
//! a passive observer. Two modes are supported, mirroring the sing-box
//! `transport/simple-obfs` implementation byte-for-byte:
//!
//! - **HTTP**: the first write is framed as an HTTP/1.1 `GET` upgrade request
//!   with the payload as the body; the first read strips the HTTP response
//!   headers. All subsequent I/O passes through unchanged.
//! - **TLS**: the first write embeds the payload in a fake TLS `ClientHello`
//!   (session-ticket extension); every write is framed as a TLS record. The
//!   first read skips the fake `ServerHello`+`Certificate` (105 bytes); every
//!   read strips the 5-byte TLS record header.
//!
//! The connection is consumed by [`super::SsConn`], which drives it through
//! `AsyncReadExt::read_exact` / `AsyncWriteExt::write_all`. Because the obfs
//! framing is *atomic* (the first write must emit its preamble before any
//! payload bytes can be reported as consumed), [`AsyncWrite::poll_write`]
//! buffers the fully-framed output and drains it to the inner stream, only
//! reporting success once the whole frame is on the wire.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Maximum payload embedded in a single TLS record, matching sing-box's
/// `chunkSize = 1 << 14`.
const CHUNK_SIZE: usize = 1 << 14;

/// Cipher suite list from the sing-box `makeClientHelloMsg`. The preceding
/// length prefix is `0x00 0x38` (56 bytes).
const CIPHER_SUITES: [u8; 56] = [
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0,
    0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23,
    0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0,
    0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35,
    0x00, 0x2f, 0x00, 0xff,
];

/// Parsed obfs-local plugin configuration.
pub enum ObfsPlugin {
    /// HTTP obfuscation. `port` is the server port used in the `Host` header.
    Http { host: String, port: String },
    /// TLS obfuscation. `host` is the SNI server name.
    Tls { host: String },
}

impl ObfsPlugin {
    /// Parse a SIP003 plugin specification.
    ///
    /// - `plugin` must be `"obfs-local"`.
    /// - `opts` is a semicolon-delimited list of `key=value` pairs. Recognised
    ///   keys: `obfs` (`"http"` | `"tls"`, default `"http"`), `obfs-host`
    ///   (hostname), `path` (ignored for HTTP).
    /// - `server_port` is the Shadowsocks server port, used for the HTTP
    ///   `Host` header.
    pub fn parse(
        plugin: &str, opts: &str, server_port: u16,
    ) -> Result<Self, String> {
        if plugin != "obfs-local" {
            return Err(format!(
                "unsupported plugin: {plugin} (expected obfs-local)"
            ));
        }

        let mut mode = String::from("http");
        let mut host = String::new();
        for part in opts.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (key, val) = match part.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            match key.trim() {
                "obfs" => mode = val.trim().to_string(),
                "obfs-host" => host = val.trim().to_string(),
                // `path` and any unknown keys are silently ignored, matching
                // the sing-box option parser.
                _ => {},
            }
        }

        match mode.as_str() {
            "http" => Ok(ObfsPlugin::Http {
                host,
                port: server_port.to_string(),
            }),
            "tls" => Ok(ObfsPlugin::Tls { host }),
            other => {
                Err(format!("unknown obfs mode: {other} (expected http or tls)"))
            },
        }
    }

    /// Wrap a raw [`TcpStream`] with the configured obfs transformation.
    pub fn wrap(&self, conn: TcpStream) -> ObfsConn {
        match self {
            ObfsPlugin::Http { host, port } => {
                ObfsConn::Http(ObfsHttp::new(conn, host.clone(), port.clone()))
            },
            ObfsPlugin::Tls { host } => {
                ObfsConn::Tls(ObfsTls::new(conn, host.clone()))
            },
        }
    }
}

/// An obfs-local wrapped connection. Dispatches [`AsyncRead`]/[`AsyncWrite`]
/// to the active mode.
pub enum ObfsConn {
    Http(ObfsHttp),
    Tls(ObfsTls),
}

impl AsyncRead for ObfsConn {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ObfsConn::Http(c) => Pin::new(c).poll_read(cx, buf),
            ObfsConn::Tls(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ObfsConn {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ObfsConn::Http(c) => Pin::new(c).poll_write(cx, buf),
            ObfsConn::Tls(c) => Pin::new(c).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ObfsConn::Http(c) => Pin::new(c).poll_flush(cx),
            ObfsConn::Tls(c) => Pin::new(c).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ObfsConn::Http(c) => Pin::new(c).poll_shutdown(cx),
            ObfsConn::Tls(c) => Pin::new(c).poll_shutdown(cx),
        }
    }
}

// Both inner types are `Unpin` (they own a `TcpStream` plus plain data), so the
// enum is `Unpin` and `Send` automatically; no unsafe is needed.

/// HTTP obfuscation wrapper.
pub struct ObfsHttp {
    conn: TcpStream,
    host: String,
    port: String,
    /// Decrypted/unframed payload buffered from the first response read.
    buf: Vec<u8>,
    /// Read cursor into `buf`.
    offset: usize,
    first_request: bool,
    first_response: bool,
    // --- write drain state ---
    /// Fully-framed output awaiting the inner stream.
    write_buf: Vec<u8>,
    /// Bytes of `write_buf` already written.
    write_pos: usize,
    /// Logical byte count to report once `write_buf` is fully drained.
    write_report: usize,
}

impl ObfsHttp {
    fn new(conn: TcpStream, host: String, port: String) -> Self {
        Self {
            conn,
            host,
            port,
            buf: Vec::new(),
            offset: 0,
            first_request: true,
            first_response: true,
            write_buf: Vec::new(),
            write_pos: 0,
            write_report: 0,
        }
    }
}

impl AsyncRead for ObfsHttp {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1. Serve buffered leftover from a previous first-response read.
            if this.offset < this.buf.len() {
                let avail = this.buf.len() - this.offset;
                let n = avail.min(buf.remaining());
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                buf.put_slice(&this.buf[this.offset..this.offset + n]);
                this.offset += n;
                if this.offset >= this.buf.len() {
                    this.buf.clear();
                    this.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. First response: strip the HTTP response headers.
            if this.first_response {
                let mut scratch = [0u8; 8192];
                let mut rb = ReadBuf::new(&mut scratch);
                ready!(Pin::new(&mut this.conn).poll_read(cx, &mut rb))?;
                let n = rb.filled().len();
                log::trace!("obfs http: first_response read {} bytes", n);
                if n == 0 {
                    return Poll::Ready(Ok(())); // EOF
                }
                let idx = match find_crlf_crlf(&scratch[..n]) {
                    Some(i) => {
                        log::trace!(
                            "obfs http: found CRLFCRLF at offset {}, payload after = {} bytes",
                            i,
                            n - i - 4
                        );
                        i
                    },
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "obfs http: incomplete response header",
                        )));
                    },
                };
                this.first_response = false;
                let payload = &scratch[idx + 4..n];
                if payload.is_empty() {
                    // Headers only in this packet; fall through to passthrough.
                    continue;
                }
                let n_copy = payload.len().min(buf.remaining());
                buf.put_slice(&payload[..n_copy]);
                if n_copy < payload.len() {
                    this.buf = payload[n_copy..].to_vec();
                    this.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 3. Subsequent reads pass straight through.
            log::trace!("obfs http: passthrough poll_read");
            return Pin::new(&mut this.conn).poll_read(cx, buf);
        }
    }
}

impl AsyncWrite for ObfsHttp {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Continue a partially-drained framed write first.
        if !this.write_buf.is_empty() {
            ready!(drain_write(
                &mut this.conn,
                &this.write_buf,
                &mut this.write_pos,
                cx
            ))?;
            this.write_buf.clear();
            this.write_pos = 0;
            let report = this.write_report;
            this.write_report = 0;
            return Poll::Ready(Ok(report));
        }

        if this.first_request {
            let out = build_http_request(&this.host, &this.port, buf);
            this.first_request = false;
            this.write_buf = out;
            this.write_pos = 0;
            this.write_report = buf.len();
            ready!(drain_write(
                &mut this.conn,
                &this.write_buf,
                &mut this.write_pos,
                cx
            ))?;
            this.write_buf.clear();
            this.write_pos = 0;
            let report = this.write_report;
            this.write_report = 0;
            return Poll::Ready(Ok(report));
        }

        // Passthrough: let the inner stream report its own progress; `write_all`
        // loops on partial writes.
        log::trace!("obfs http: passthrough poll_write {} bytes", buf.len());
        Pin::new(&mut this.conn).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.conn).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.conn).poll_shutdown(cx)
    }
}

/// TLS obfuscation wrapper.
pub struct ObfsTls {
    conn: TcpStream,
    server: String,
    /// Payload bytes remaining in the TLS record currently being read.
    remain: usize,
    first_request: bool,
    first_response: bool,
    // --- read framing state ---
    read_phase: TlsReadPhase,
    /// Bytes left to discard in the current record header.
    discard_left: usize,
    /// Accumulator for the 2-byte record payload length.
    len_buf: [u8; 2],
    /// Bytes of `len_buf` already filled.
    len_have: usize,
    // --- write drain state ---
    write_buf: Vec<u8>,
    write_pos: usize,
    write_report: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TlsReadPhase {
    /// At a record boundary; set up the next discard count.
    Start,
    /// Discarding `discard_left` header bytes.
    Discard,
    /// Reading the 2-byte payload length into `len_buf`.
    Length,
    /// Emitting `remain` payload bytes to the caller.
    Payload,
}

impl ObfsTls {
    fn new(conn: TcpStream, server: String) -> Self {
        Self {
            conn,
            server,
            remain: 0,
            first_request: true,
            first_response: true,
            read_phase: TlsReadPhase::Start,
            discard_left: 0,
            len_buf: [0, 0],
            len_have: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            write_report: 0,
        }
    }
}

impl AsyncRead for ObfsTls {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.read_phase {
                TlsReadPhase::Start => {
                    // First record skips the fake ServerHello+Certificate
                    // (105 bytes); every later record skips the 3-byte header.
                    this.discard_left = if this.first_response { 105 } else { 3 };
                    this.first_response = false;
                    this.len_have = 0;
                    this.read_phase = TlsReadPhase::Discard;
                },
                TlsReadPhase::Discard => {
                    if this.discard_left == 0 {
                        this.read_phase = TlsReadPhase::Length;
                        continue;
                    }
                    let mut scratch = [0u8; 128];
                    let want = this.discard_left.min(scratch.len());
                    let mut rb = ReadBuf::new(&mut scratch[..want]);
                    ready!(Pin::new(&mut this.conn).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.discard_left -= n;
                },
                TlsReadPhase::Length => {
                    if this.len_have >= 2 {
                        this.remain = u16::from_be_bytes(this.len_buf) as usize;
                        this.len_have = 0;
                        this.read_phase = TlsReadPhase::Payload;
                        continue;
                    }
                    let mut scratch = [0u8; 2];
                    let want = 2 - this.len_have;
                    let mut rb = ReadBuf::new(&mut scratch[..want]);
                    ready!(Pin::new(&mut this.conn).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.len_buf[this.len_have..this.len_have + n]
                        .copy_from_slice(&scratch[..n]);
                    this.len_have += n;
                },
                TlsReadPhase::Payload => {
                    if this.remain == 0 {
                        this.read_phase = TlsReadPhase::Start;
                        continue;
                    }
                    let cap = buf.remaining();
                    if cap == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    if this.remain >= cap {
                        // The whole caller buffer lies inside this record, so
                        // read directly without risking an over-read into the
                        // next record's header.
                        let before = buf.filled().len();
                        ready!(Pin::new(&mut this.conn).poll_read(cx, buf))?;
                        let n = buf.filled().len() - before;
                        if n == 0 {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        this.remain -= n;
                        return Poll::Ready(Ok(()));
                    } else {
                        // Record ends before the caller buffer fills; read only
                        // `remain` bytes via a scratch buffer to avoid
                        // consuming the next header.
                        let mut scratch = vec![0u8; this.remain];
                        let mut rb = ReadBuf::new(&mut scratch);
                        ready!(Pin::new(&mut this.conn).poll_read(cx, &mut rb))?;
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        buf.put_slice(&scratch[..n]);
                        this.remain -= n;
                        return Poll::Ready(Ok(()));
                    }
                },
            }
        }
    }
}

impl AsyncWrite for ObfsTls {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.write_buf.is_empty() {
            ready!(drain_write(
                &mut this.conn,
                &this.write_buf,
                &mut this.write_pos,
                cx
            ))?;
            let report = this.write_report;
            this.write_report = 0;
            return Poll::Ready(Ok(report));
        }

        let out = build_tls_output(buf, &this.server, this.first_request);
        this.first_request = false;
        this.write_buf = out;
        this.write_pos = 0;
        this.write_report = buf.len();
        ready!(drain_write(
            &mut this.conn,
            &this.write_buf,
            &mut this.write_pos,
            cx
        ))?;
        let report = this.write_report;
        this.write_report = 0;
        Poll::Ready(Ok(report))
    }

    fn poll_flush(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.conn).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.conn).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

/// Drain `write_buf` from `write_pos` to the inner stream, returning `Pending`
/// when the stream is not ready. Only reports success once every byte is sent.
fn drain_write(
    conn: &mut TcpStream, write_buf: &[u8], write_pos: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while *write_pos < write_buf.len() {
        let n = ready!(
            Pin::new(&mut *conn).poll_write(cx, &write_buf[*write_pos..])
        )?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "obfs: wrote zero bytes to inner stream",
            )));
        }
        *write_pos += n;
    }
    Poll::Ready(Ok(()))
}

/// Build the initial HTTP/1.1 upgrade request with `data` as the body.
fn build_http_request(host: &str, port: &str, data: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).expect("getrandom: system CSPRNG failed");
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);

    let mut ua = [0u8; 2];
    getrandom::fill(&mut ua).expect("getrandom: system CSPRNG failed");
    let user_agent = format!("curl/7.{}.{}", ua[0] % 54, ua[1] % 2);

    let host_header = if port == "80" {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };

    let mut out = Vec::with_capacity(256 + data.len());
    out.extend_from_slice(b"GET / HTTP/1.1\r\n");
    out.extend_from_slice(format!("Host: {host_header}\r\n").as_bytes());
    out.extend_from_slice(format!("User-Agent: {user_agent}\r\n").as_bytes());
    out.extend_from_slice(b"Upgrade: websocket\r\n");
    out.extend_from_slice(b"Connection: Upgrade\r\n");
    out.extend_from_slice(format!("Sec-WebSocket-Key: {key}\r\n").as_bytes());
    out.extend_from_slice(
        format!("Content-Length: {}\r\n", data.len()).as_bytes(),
    );
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out
}

/// Frame `data` as one or more TLS records. The first chunk of the very first
/// write is embedded in a fake `ClientHello`; every other chunk is an
/// application-data record.
fn build_tls_output(data: &[u8], server: &str, first_request: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = first_request;
    for chunk in data.chunks(CHUNK_SIZE) {
        if first {
            out.extend_from_slice(&make_client_hello(chunk, server));
            first = false;
        } else {
            out.extend_from_slice(&make_tls_record(chunk));
        }
    }
    out
}

/// Build a TLS 1.2 application-data record: `0x17 0x03 0x03` + BE16 len + data.
fn make_tls_record(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(0x17);
    out.push(0x03);
    out.push(0x03);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Build a fake TLS `ClientHello` carrying `data` in the session-ticket
/// extension, byte-for-byte matching sing-box `makeClientHelloMsg`.
fn make_client_hello(data: &[u8], server: &str) -> Vec<u8> {
    let mut random = [0u8; 28];
    getrandom::fill(&mut random).expect("getrandom: system CSPRNG failed");
    let mut session_id = [0u8; 32];
    getrandom::fill(&mut session_id).expect("getrandom: system CSPRNG failed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    let mut out = Vec::with_capacity(256 + data.len() + server.len());

    // Record: handshake, TLS 1.0, BE16 length.
    out.push(22);
    out.extend_from_slice(&[0x03, 0x01]);
    let rec_len = (212 + data.len() + server.len()) as u16;
    out.extend_from_slice(&rec_len.to_be_bytes());

    // Handshake: ClientHello, 3-byte length (high byte 0), TLS 1.2.
    out.push(1);
    out.push(0);
    let hs_len = (208 + data.len() + server.len()) as u16;
    out.extend_from_slice(&hs_len.to_be_bytes());
    out.extend_from_slice(&[0x03, 0x03]);

    // Random: 4-byte timestamp + 28 random bytes.
    out.extend_from_slice(&now.to_be_bytes());
    out.extend_from_slice(&random);
    // Session ID: length 32 + 32 bytes.
    out.push(32);
    out.extend_from_slice(&session_id);

    // Cipher suites: BE16 length (56) + list.
    out.extend_from_slice(&[0x00, 0x38]);
    out.extend_from_slice(&CIPHER_SUITES);

    // Compression methods: 1 byte, null.
    out.extend_from_slice(&[0x01, 0x00]);

    // Extensions: BE16 total length.
    let ext_len = (79 + data.len() + server.len()) as u16;
    out.extend_from_slice(&ext_len.to_be_bytes());

    // Session ticket extension (0x0023): carries the payload.
    out.extend_from_slice(&[0x00, 0x23]);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);

    // SNI extension (0x0000).
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&((server.len() + 5) as u16).to_be_bytes());
    out.extend_from_slice(&((server.len() + 3) as u16).to_be_bytes());
    out.push(0);
    out.extend_from_slice(&(server.len() as u16).to_be_bytes());
    out.extend_from_slice(server.as_bytes());

    // ec_point_formats (0x000b).
    out.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);

    // supported_groups (0x000a).
    out.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19,
        0x00, 0x18,
    ]);

    // signature_algorithms (0x000d).
    out.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03,
        0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03,
        0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);

    // encrypt_then_mac (0x0016).
    out.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);

    // extended_master_secret (0x0017).
    out.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    out
}

/// Find the offset of the first `\r\n\r\n` separator, if present.
fn find_crlf_crlf(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // --- parse ---

    #[test]
    fn parse_http() {
        let p = ObfsPlugin::parse(
            "obfs-local",
            "obfs=http;obfs-host=aws.amazon.com",
            8388,
        )
        .unwrap();
        match p {
            ObfsPlugin::Http { host, port } => {
                assert_eq!(host, "aws.amazon.com");
                assert_eq!(port, "8388");
            },
            _ => panic!("expected Http variant"),
        }
    }

    #[test]
    fn parse_tls() {
        let p = ObfsPlugin::parse(
            "obfs-local",
            "obfs=tls;obfs-host=example.com",
            443,
        )
        .unwrap();
        match p {
            ObfsPlugin::Tls { host } => assert_eq!(host, "example.com"),
            _ => panic!("expected Tls variant"),
        }
    }

    #[test]
    fn parse_unknown_mode() {
        assert!(
            ObfsPlugin::parse("obfs-local", "obfs=foo;obfs-host=x", 80).is_err()
        );
    }

    #[test]
    fn parse_wrong_plugin() {
        assert!(ObfsPlugin::parse("v2ray-plugin", "", 80).is_err());
    }

    #[test]
    fn parse_default_mode_is_http() {
        let p = ObfsPlugin::parse("obfs-local", "obfs-host=h.com", 80).unwrap();
        assert!(matches!(p, ObfsPlugin::Http { .. }));
    }

    #[test]
    fn parse_ignores_path_and_unknown_keys() {
        let p = ObfsPlugin::parse(
            "obfs-local",
            "obfs=http;obfs-host=h.com;path=/ws;unknown=1",
            8388,
        )
        .unwrap();
        match p {
            ObfsPlugin::Http { host, port } => {
                assert_eq!(host, "h.com");
                assert_eq!(port, "8388");
            },
            _ => panic!("expected Http variant"),
        }
    }

    // --- HTTP framing helpers ---

    #[test]
    fn http_request_format() {
        let req = build_http_request("aws.amazon.com", "8388", b"data");
        let s = String::from_utf8_lossy(&req);
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Host: aws.amazon.com:8388\r\n"));
        assert!(s.contains("Upgrade: websocket\r\n"));
        assert!(s.contains("Connection: Upgrade\r\n"));
        assert!(s.contains("Content-Length: 4\r\n"));
        assert!(s.contains("Sec-WebSocket-Key: "));
        assert!(s.ends_with("data"));
    }

    #[test]
    fn http_request_omits_port_for_80() {
        let req = build_http_request("h.com", "80", b"x");
        let s = String::from_utf8_lossy(&req);
        assert!(s.contains("Host: h.com\r\n"));
        assert!(!s.contains("h.com:80"));
    }

    // --- TLS ClientHello structure ---

    #[test]
    fn tls_client_hello_structure() {
        let data = b"payload";
        let server = "example.com";
        let msg = make_client_hello(data, server);

        // Record header.
        assert_eq!(msg[0], 22); // handshake
        assert_eq!(&msg[1..3], &[0x03, 0x01]); // TLS 1.0
        assert_eq!(
            u16::from_be_bytes([msg[3], msg[4]]) as usize,
            212 + data.len() + server.len()
        );

        // Handshake header.
        assert_eq!(msg[5], 1); // ClientHello
        assert_eq!(msg[6], 0); // high byte of 3-byte length
        assert_eq!(
            u16::from_be_bytes([msg[7], msg[8]]) as usize,
            208 + data.len() + server.len()
        );
        assert_eq!(&msg[9..11], &[0x03, 0x03]); // TLS 1.2

        // Session ID length.
        assert_eq!(msg[11 + 4 + 28], 32);

        // Session ticket extension (fixed offset 138) carries the payload.
        // Using a computed offset avoids false positives from the random
        // bytes and the compression/ext_len `0x00 0x00` boundary.
        let st = 138;
        assert_eq!(&msg[st..st + 2], &[0x00, 0x23]);
        let st_len = u16::from_be_bytes([msg[st + 2], msg[st + 3]]) as usize;
        assert_eq!(st_len, data.len());
        assert_eq!(&msg[st + 4..st + 4 + data.len()], data);

        // SNI extension immediately follows the session ticket.
        let sni = st + 4 + data.len();
        assert_eq!(&msg[sni..sni + 2], &[0x00, 0x00]);
        assert_eq!(
            u16::from_be_bytes([msg[sni + 2], msg[sni + 3]]) as usize,
            server.len() + 5
        );
        let name_start = sni + 9;
        assert_eq!(
            &msg[name_start..name_start + server.len()],
            server.as_bytes()
        );
    }

    // --- integration: HTTP first write ---

    #[tokio::test]
    async fn http_first_write_produces_valid_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = conn.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                if received.ends_with(b"hello world") {
                    break;
                }
            }
            received
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let mut obfs = ObfsHttp::new(
            client,
            "aws.amazon.com".to_string(),
            "8388".to_string(),
        );
        obfs.write_all(b"hello world").await.unwrap();
        obfs.shutdown().await.unwrap();

        let received = server.await.unwrap();
        let s = String::from_utf8_lossy(&received);
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Host: aws.amazon.com:8388\r\n"));
        assert!(s.contains("Upgrade: websocket\r\n"));
        assert!(s.contains("Connection: Upgrade\r\n"));
        assert!(s.contains("Sec-WebSocket-Key: "));
        assert!(s.contains("Content-Length: 11\r\n"));
        assert!(s.ends_with("hello world"));
    }

    // --- integration: HTTP first read strips headers ---

    #[tokio::test]
    async fn http_first_read_strips_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let resp = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/plain\r\n\
                         Content-Length: 5\r\n\
                         \r\n\
                         hello";
            conn.write_all(resp).await.unwrap();
            // Hold the connection open so the client can read.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let mut obfs = ObfsHttp::new(client, "h".to_string(), "80".to_string());
        let mut buf = [0u8; 32];
        let n = obfs.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        server.await.unwrap();
    }

    // --- integration: TLS first write ---

    #[tokio::test]
    async fn tls_first_write_produces_client_hello() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = conn.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                // Read enough to cover the session-ticket extension payload.
                if received.len() >= 138 + 4 + b"test data".len() {
                    break;
                }
            }
            received
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let mut obfs = ObfsTls::new(client, "example.com".to_string());
        obfs.write_all(b"test data").await.unwrap();
        obfs.shutdown().await.unwrap();

        let received = server.await.unwrap();
        assert_eq!(received[0], 22); // TLS handshake
        assert_eq!(&received[1..3], &[0x03, 0x01]); // TLS 1.0
        assert_eq!(received[5], 1); // ClientHello

        // The payload is embedded in the session-ticket extension (offset 138).
        let st = 138;
        assert_eq!(&received[st..st + 2], &[0x00, 0x23]);
        let st_len =
            u16::from_be_bytes([received[st + 2], received[st + 3]]) as usize;
        assert_eq!(st_len, b"test data".len());
        assert_eq!(&received[st + 4..st + 4 + st_len], b"test data");
    }

    // --- integration: TLS read strips framing across records ---

    #[tokio::test]
    async fn tls_read_strips_record_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            // The client's first read skips 105 bytes (fake ServerHello +
            // Certificate), then reads a 2-byte BE length, then the payload.
            let payload = b"obfs-payload";
            let mut out = vec![0xAAu8; 105]; // skipped preamble
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            out.extend_from_slice(payload);
            conn.write_all(&out).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let mut obfs = ObfsTls::new(client, "example.com".to_string());
        let mut buf = [0u8; 64];
        let n = obfs.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"obfs-payload");

        server.await.unwrap();
    }
}
