// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! VLESS inbound server.
//!
//! One TCP connection carries exactly one VLESS stream (no session
//! multiplexing). Per connection: optional TLS accept (boring, blocking) →
//! optional HTTP/1.1 WebSocket upgrade (compatible with the ws client in
//! `transport/ws.rs`: path + Host validation, masked client frames,
//! unmasked server frames) → VLESS request parse (version | UUID | addons |
//! command | port | address, same wire format as `protocol::vless`) → UUID
//! auth against `[[users]].password` (the outbound uses the password string
//! directly as the UUID, so the inbound parses each password the same way) →
//! the stream is handed to the runner as an [`InboundConn`].
//!
//! UDP follows the outbound's `dial_udp` contract exactly: VLESS
//! command 0x02, the request's destination is fixed for the whole session,
//! and datagrams are framed as `[2-byte BE length]+[packet]` in BOTH
//! directions (see `outbound/vless` `UdpDeframer`/`udp_frame_packet`).
//!
//! Vision (`flow=xtls-rprx-vision`, TCP + direct TLS 1.3 only — ws and UDP
//! reject it, other flows reject) swaps the plain relay loop for
//! [`vision_relay_loop`]: the padding-phase frames from
//! `obfuscation::vision` are decoded uplink and applied downlink, and each
//! direction splices the raw socket after its Direct handoff. The VLESS
//! response header is coalesced into the first downlink frame like xray
//! does (inbound.go:604-623). See `obfuscation::vision` for the frame
//! format and the buffer-drainage argument behind the raw handoff.
//!
//! The blocking TLS/WS handshakes and the relay loop run on
//! `spawn_blocking` — the same model as the anytls inbound.

use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use boring::ssl::Ssl;
use boring::ssl::SslContext;
use boring::ssl::SslStream;
use boring::ssl::SslVersion;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::InboundConfig;
use crate::inbound::Address;
use crate::inbound::Destination;
use crate::inbound::Inbound;
use crate::inbound::InboundConn;
use crate::inbound::anytls::build_ssl_context;
use crate::obfuscation::vision::ServerDownlinkWriter;
use crate::obfuscation::vision::ServerUplinkReader;
use crate::obfuscation::vision::VisionFilterState;
use crate::protocol::vless::VlessCommand;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;
use crate::transport::reality_server::PrefixStream;
use crate::transport::reality_server::RealityPeek;
use crate::transport::reality_server::BorrowedServerHello;
use crate::transport::reality_server::RealityServer;
use crate::transport::ws::compute_accept;
use crate::transport::ws::header_value;

/// Handshake budget (TLS accept + ws upgrade + VLESS request). Xray servers
/// reap idle handshakes at 60s; half of that bounds dead peers here.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle read tick while relaying. The single blocking IO loop only drains
/// upstream→client writes between reads, so this tick bounds how long a
/// queued response waits behind a parked `read` — with one stream per
/// connection (no multiplexing to drive reads) every request/response hop
/// would otherwise pay the full tick. 100 ms keeps interactive latency
/// bounded at a negligible wake-up cost.
const RELAY_READ_TIMEOUT: Duration = Duration::from_millis(100);

/// Server-side cap on one ws frame payload (relay chunks are 16 KB).
const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

/// Cap on the accumulated VLESS request header. The only addon is the
/// Vision flow (a few dozen bytes), so the header is well under this; the
/// cap exists to bound garbage, not legitimate headers.
const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// The one supported Vision flow (xray `vless.XRV`, proxy/vless/vless.go:10).
const FLOW_XRV: &str = "xtls-rprx-vision";

/// Server-side ws settings parsed from the inbound `[transport.ws]` section.
#[derive(Debug, Clone)]
pub(crate) struct WsInboundConfig {
    /// Accepted request path (default "/", matching the outbound default).
    pub(crate) path: String,
    /// Expected `Host` header. Taken from `[transport.ws] headers.Host` when
    /// configured; when absent any Host is accepted (a CDN in front of the
    /// server may rewrite it).
    pub(crate) host: Option<String>,
}

// ---------------------------------------------------------------------------
// Server-side WebSocket framing (blocking)
// ---------------------------------------------------------------------------

/// A blocking WebSocket **server** connection over any byte stream.
///
/// Mirrors the framing of the client-side `WsConn` in `transport/ws.rs` with
/// the roles swapped per RFC 6455: client frames arrive masked (unmasked
/// here), server frames are sent unmasked. Reads surface the stream as a
/// plain byte stream: each `read` returns the next buffered payload chunk,
/// frame boundaries included in the ordering but not exposed.
pub(crate) struct WsServerStream<T: VlessIo> {
    inner: T,
    /// Partial frame bytes (or control-frame payload bytes) not yet decoded.
    buf: Vec<u8>,
    /// Decoded binary payload waiting to be handed to the caller.
    payload: Vec<u8>,
}

/// Read one CRLF-terminated HTTP header line (byte-wise, so nothing past the
/// handshake is consumed from the stream).
fn read_http_line<R: Read>(r: &mut R, total: &mut usize) -> std::io::Result<String> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        r.read_exact(&mut byte)?;
        *total += 1;
        if *total > MAX_REQUEST_BYTES {
            return Err(std::io::Error::other(
                "vless ws: handshake headers too large",
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            line.push(byte[0]);
        }
    }
    String::from_utf8(line)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "non-utf8 HTTP header"))
}

impl<T: VlessIo> WsServerStream<T> {
    /// Perform the HTTP/1.1 Upgrade handshake. On a validation failure a
    /// 400 response is written (best effort) before the error is returned;
    /// read errors propagate untouched.
    pub(crate) fn handshake(
        mut inner: T, path: &str, expect_host: Option<&str>,
    ) -> std::io::Result<Self> {
        let mut total = 0usize;
        let request_line = read_http_line(&mut inner, &mut total)?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        let version = parts.next().unwrap_or("");

        let mut upgrade_ok = false;
        let mut connection_ok = false;
        let mut version_ok = false;
        let mut key: Option<String> = None;
        let mut host: Option<String> = None;
        loop {
            let line = read_http_line(&mut inner, &mut total)?;
            if line.is_empty() {
                break;
            }
            if let Some(v) = header_value(&line, "upgrade")
                && v.eq_ignore_ascii_case("websocket")
            {
                upgrade_ok = true;
            }
            if let Some(v) = header_value(&line, "connection")
                && v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            {
                connection_ok = true;
            }
            if let Some(v) = header_value(&line, "sec-websocket-key")
                && !v.is_empty()
            {
                key = Some(v.to_string());
            }
            if let Some(v) = header_value(&line, "sec-websocket-version")
                && v.trim() == "13"
            {
                version_ok = true;
            }
            if let Some(v) = header_value(&line, "host") {
                host = Some(v.to_string());
            }
        }

        // Validation happens after the full header block is read so a probe
        // gets a proper 400 instead of a truncated-connection error.
        let reason = if method != "GET" {
            Some("method is not GET")
        } else if version != "HTTP/1.1" {
            Some("not HTTP/1.1")
        } else if target.split('?').next().unwrap_or("") != path {
            Some("path mismatch")
        } else if !upgrade_ok || !connection_ok || !version_ok {
            Some("missing required websocket headers")
        } else if key.is_none() {
            Some("missing Sec-WebSocket-Key")
        } else {
            match expect_host {
                Some(expect) => match &host {
                    Some(h) if h.eq_ignore_ascii_case(expect) => None,
                    _ => Some("Host header mismatch"),
                },
                // Host is mandatory in HTTP/1.1; any value is accepted.
                None if host.is_none() => Some("missing Host header"),
                None => None,
            }
        };
        if let Some(reason) = reason {
            let _ = inner.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
            let _ = inner.flush();
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("vless ws: rejected ({reason})"),
            ));
        }

        let accept = compute_accept(key.as_deref().unwrap_or_default());
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             \r\n"
        );
        inner.write_all(response.as_bytes())?;
        inner.flush()?;
        Ok(Self {
            inner,
            buf: Vec::new(),
            payload: Vec::new(),
        })
    }

    /// Send one unmasked server frame (opcode + payload).
    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        let mut frame = Vec::with_capacity(10 + payload.len());
        frame.push(0x80 | opcode); // FIN=1
        let len = payload.len();
        if len < 126 {
            frame.push(len as u8);
        } else if len <= 0xFFFF {
            frame.push(126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        self.inner.write_all(&frame)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Buffer until `self.buf` holds at least `count` bytes. Partial reads
    /// survive timeouts: nothing is drained until a full frame is decoded,
    /// so a `WouldBlock`/`TimedOut` error keeps the accumulated prefix and
    /// the next `read` re-parses from scratch.
    fn ensure_bytes(&mut self, count: usize) -> std::io::Result<()> {
        while self.buf.len() < count {
            let missing = count - self.buf.len();
            let mut tmp = vec![0u8; missing.min(16 * 1024)];
            let n = self.inner.read(&mut tmp)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "ws: peer closed mid-frame",
                ));
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }
}

impl<T: VlessIo> Read for WsServerStream<T> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if !self.payload.is_empty() {
            let n = self.payload.len().min(out.len());
            out[..n].copy_from_slice(&self.payload[..n]);
            self.payload.drain(..n);
            return Ok(n);
        }
        loop {
            match self.ensure_bytes(2) {
                Ok(()) => {},
                // Clean EOF between frames is end-of-stream, not an error.
                Err(e) if e.kind() == ErrorKind::UnexpectedEof && self.buf.is_empty() => {
                    return Ok(0);
                },
                Err(e) => return Err(e),
            }
            let b0 = self.buf[0];
            let b1 = self.buf[1];
            let fin = (b0 & 0x80) != 0;
            let opcode = b0 & 0x0F;
            let masked = (b1 & 0x80) != 0;
            let len7 = (b1 & 0x7F) as u64;
            let ext: usize = match len7 {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            let hdr_len = 2 + ext + usize::from(masked) * 4;
            self.ensure_bytes(hdr_len)?;
            let payload_len = match len7 {
                126 => u16::from_be_bytes([self.buf[2], self.buf[3]]) as u64,
                127 => u64::from_be_bytes(self.buf[2..10].try_into().unwrap()),
                _ => len7,
            };
            if payload_len > MAX_FRAME_PAYLOAD as u64 {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "ws frame payload too large",
                ));
            }
            let frame_len = hdr_len + payload_len as usize;
            self.ensure_bytes(frame_len)?;

            match opcode {
                0x02 | 0x00 => {
                    if !fin {
                        return Err(std::io::Error::new(
                            ErrorKind::Unsupported,
                            "fragmented ws frames not supported",
                        ));
                    }
                    if !masked {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "client ws frame must be masked",
                        ));
                    }
                    let mask = [
                        self.buf[2 + ext],
                        self.buf[2 + ext + 1],
                        self.buf[2 + ext + 2],
                        self.buf[2 + ext + 3],
                    ];
                    for (i, b) in self.buf[hdr_len..frame_len].iter_mut().enumerate() {
                        *b ^= mask[i % 4];
                    }
                    self.payload.extend_from_slice(&self.buf[hdr_len..frame_len]);
                    self.buf.drain(..frame_len);
                    if self.payload.is_empty() {
                        continue; // zero-length data frame: not EOF
                    }
                    let n = self.payload.len().min(out.len());
                    out[..n].copy_from_slice(&self.payload[..n]);
                    self.payload.drain(..n);
                    return Ok(n);
                },
                0x09 => {
                    // Ping → pong (RFC 6455 caps control payloads at 125).
                    let body = self.buf[hdr_len..frame_len].to_vec();
                    self.buf.drain(..frame_len);
                    let _ = self.send_frame(0x0A, &body);
                },
                0x0A => {
                    self.buf.drain(..frame_len);
                },
                0x08 => {
                    let body = self.buf[hdr_len..frame_len].to_vec();
                    self.buf.drain(..frame_len);
                    let _ = self.send_frame(0x08, &body);
                    return Ok(0);
                },
                other => {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("unexpected ws opcode {other:#x}"),
                    ));
                },
            }
        }
    }
}

impl<T: VlessIo> Write for WsServerStream<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.send_frame(0x02, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Unified blocking transport
// ---------------------------------------------------------------------------

/// The blocking byte stream handed through the handshake stages. Adds the
/// timeout/close knobs the relay loop needs on top of `Read + Write`.
pub(crate) trait VlessIo: Read + Write + Send {
    fn set_read_timeout(&mut self, timeout: Duration);

    /// Best-effort graceful close (ws close frame / TLS close_notify / FIN).
    fn close(&mut self) {}
}

impl VlessIo for TcpStream {
    fn set_read_timeout(&mut self, timeout: Duration) {
        let _ = TcpStream::set_read_timeout(self, Some(timeout));
    }

    fn close(&mut self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

impl<T: VlessIo> VlessIo for SslStream<T> {
    fn set_read_timeout(&mut self, timeout: Duration) {
        self.get_mut().set_read_timeout(timeout);
    }

    fn close(&mut self) {
        let _ = self.shutdown();
        self.get_mut().close();
    }
}

impl<T: VlessIo> VlessIo for WsServerStream<T> {
    fn set_read_timeout(&mut self, timeout: Duration) {
        self.inner.set_read_timeout(timeout);
    }

    fn close(&mut self) {
        let _ = self.send_frame(0x08, &[]);
    }
}

impl<T: VlessIo + ?Sized> VlessIo for Box<T> {
    fn set_read_timeout(&mut self, timeout: Duration) {
        (**self).set_read_timeout(timeout);
    }

    fn close(&mut self) {
        (**self).close();
    }
}

/// TLS transport of one accepted connection: cert/key context, REALITY
/// (per-connection one-time certificate over the pre-authenticated socket)
/// or none.
enum TlsMode {
    None,
    Cert(Arc<SslContext>),
    /// Authenticated REALITY: the server (builds the per-connection SSL),
    /// this connection's AuthKey (drives the one-time certificate), the
    /// consumed ClientHello prefix to replay into `SSL_accept`, and — when
    /// the destination site answered the mirrored ClientHello with a usable
    /// TLS 1.3 ServerHello — the borrowed handshake parameters (xtls/reality
    /// ServerHello borrowing). `None` keeps boring's own selection.
    Reality(
        Arc<RealityServer>,
        [u8; 32],
        Vec<u8>,
        Option<BorrowedServerHello>,
    ),
}

// ---------------------------------------------------------------------------
// VLESS request parsing (wire format mirrors protocol::vless::encode_request)
// ---------------------------------------------------------------------------

pub(crate) struct VlessRequest {
    pub(crate) uuid: [u8; 16],
    pub(crate) command: VlessCommand,
    pub(crate) dest: Destination,
    /// Flow from the request addons, empty-string addons normalized to
    /// `None` (xray treats `Flow == ""` like no flow, inbound.go:592-596).
    pub(crate) flow: Option<String>,
}

/// Read one protobuf base-128 varint at `*pos` (advancing it).
fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *buf.get(*pos).ok_or("truncated varint")?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 63 {
            return Err("varint too long".to_string());
        }
    }
}

/// Parse the request addons — the protobuf `Addons` message (addons.proto:
/// `Flow = 1` string, `Seed = 2` bytes) — and return the requested flow.
/// Length-delimited fields 1 and 2 are accepted (Seed is ignored: it only
/// matters for the UDP length-packet framing Vision never reaches); any
/// other field is a protocol violation, mirroring a proto decode failure.
fn parse_addons_flow(addons: &[u8]) -> Result<Option<String>, String> {
    let mut pos = 0usize;
    let mut flow = None;
    while pos < addons.len() {
        let tag = read_varint(addons, &mut pos)?;
        let (field, wire_type) = (tag >> 3, tag & 0x7);
        if wire_type != 2 || !matches!(field, 1 | 2) {
            return Err(format!(
                "unsupported addon field {field} (wire type {wire_type})"
            ));
        }
        let len = read_varint(addons, &mut pos)? as usize;
        let end = pos
            .checked_add(len)
            .filter(|end| *end <= addons.len())
            .ok_or("truncated addon field")?;
        if field == 1 {
            let f = std::str::from_utf8(&addons[pos..end])
                .map_err(|_| "flow is not utf-8".to_string())?;
            flow = Some(f.to_string());
        }
        pos = end;
    }
    Ok(flow)
}

/// Incrementally parse a VLESS request header from `buf`. `Ok(None)` means
/// more bytes are needed; `Err` is a protocol violation (connection closed).
pub(crate) fn try_parse_vless_request(
    buf: &[u8],
) -> Result<Option<(VlessRequest, usize)>, String> {
    if buf.is_empty() {
        return Ok(None);
    }
    if buf[0] != 0x00 {
        return Err(format!("unsupported version {}", buf[0]));
    }
    if buf.len() < 18 {
        return Ok(None);
    }
    let uuid: [u8; 16] = buf[1..17].try_into().expect("uuid slice");
    let addons_len = buf[17] as usize;
    let hdr_end = 18 + addons_len;
    if buf.len() < hdr_end {
        return Ok(None);
    }
    let flow = if addons_len == 0 {
        None
    } else {
        parse_addons_flow(&buf[18..hdr_end])?.filter(|f| !f.is_empty())
    };
    // Command + port + ATYP all live before hdr_end + 4; check once so the
    // indexing below cannot go out of bounds on a split read.
    if buf.len() < hdr_end + 4 {
        return Ok(None);
    }
    let command = VlessCommand::try_from(buf[hdr_end]).map_err(|_| {
        format!("unsupported command {:#04x}", buf[hdr_end])
    })?;
    let port = u16::from_be_bytes([buf[hdr_end + 1], buf[hdr_end + 2]]);
    let atyp = buf[hdr_end + 3];
    let mut pos = hdr_end + 4;
    let address = match atyp {
        0x01 => {
            if buf.len() < pos + 4 {
                return Ok(None);
            }
            let a = Address::Ipv4(buf[pos..pos + 4].try_into().expect("v4 slice"));
            pos += 4;
            a
        },
        0x02 => {
            if buf.len() < pos + 1 {
                return Ok(None);
            }
            let dlen = buf[pos] as usize;
            pos += 1;
            if dlen == 0 {
                return Err("empty domain".to_string());
            }
            if buf.len() < pos + dlen {
                return Ok(None);
            }
            let d = std::str::from_utf8(&buf[pos..pos + dlen])
                .map_err(|_| "domain is not utf-8".to_string())?;
            pos += dlen;
            Address::Domain(d.to_string())
        },
        0x03 => {
            if buf.len() < pos + 16 {
                return Ok(None);
            }
            let a = Address::Ipv6(buf[pos..pos + 16].try_into().expect("v6 slice"));
            pos += 16;
            a
        },
        other => {
            return Err(format!("unsupported address type {other:#04x}"));
        },
    };
    Ok(Some((
        VlessRequest {
            uuid,
            command,
            dest: Destination::new(address, port),
            flow,
        },
        pos,
    )))
}

/// Read from the transport until the VLESS request header is complete.
/// Returns the request and the first-payload bytes that arrived with it.
fn read_vless_request(io: &mut dyn VlessIo) -> std::io::Result<(VlessRequest, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut tmp = [0u8; 512];
    loop {
        match try_parse_vless_request(&buf) {
            Ok(Some((req, consumed))) => {
                return Ok((req, buf[consumed..].to_vec()));
            },
            Ok(None) => {},
            Err(msg) => {
                return Err(std::io::Error::other(format!(
                    "vless inbound: bad request: {msg}"
                )));
            },
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(std::io::Error::other(
                "vless inbound: request header too large",
            ));
        }
        let n = io.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "vless inbound: EOF while reading request header",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

// ---------------------------------------------------------------------------
// UDP framing ([2-byte BE length]+[packet], both directions) — the same wire
// contract as the outbound's dial_udp (outbound/vless UdpDeframer).
// ---------------------------------------------------------------------------

fn udp_frame_packet(packet: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(packet.len() + 2);
    framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    framed.extend_from_slice(packet);
    framed
}

/// Incremental de-framer for the client's UDP frame stream.
struct UdpDeframer {
    hdr: [u8; 2],
    hdr_filled: usize,
    payload: Vec<u8>,
    payload_left: usize,
}

impl UdpDeframer {
    fn new() -> Self {
        Self {
            hdr: [0; 2],
            hdr_filled: 0,
            payload: Vec::new(),
            payload_left: 0,
        }
    }

    fn feed(&mut self, data: &[u8], out: &mut Vec<Vec<u8>>) {
        let mut pos = 0;
        while pos < data.len() {
            if self.hdr_filled < 2 {
                let take = (2 - self.hdr_filled).min(data.len() - pos);
                self.hdr[self.hdr_filled..self.hdr_filled + take]
                    .copy_from_slice(&data[pos..pos + take]);
                self.hdr_filled += take;
                pos += take;
                if self.hdr_filled < 2 {
                    break;
                }
                self.payload_left = u16::from_be_bytes(self.hdr) as usize;
                self.payload = Vec::with_capacity(self.payload_left);
            }
            if self.payload_left > 0 {
                let take = self.payload_left.min(data.len() - pos);
                self.payload.extend_from_slice(&data[pos..pos + take]);
                pos += take;
                self.payload_left -= take;
                if self.payload_left > 0 {
                    break;
                }
            }
            out.push(std::mem::take(&mut self.payload));
            self.hdr_filled = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Relay adapters (async side handed to the runner)
// ---------------------------------------------------------------------------

/// TCP `StreamRelay` for one VLESS connection. `read` yields what the
/// blocking IO loop read from the client; `write` queues chunks for the IO
/// loop to push to the client.
struct VlessServerStream {
    data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    write_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    /// Set on drop so the blocking loop notices a dead relay within one
    /// read-timeout tick even when no traffic flows.
    closed: Arc<AtomicBool>,
    pending: Vec<u8>,
}

#[async_trait]
impl StreamRelay for VlessServerStream {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        match self.data_rx.recv().await {
            Some(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    self.pending.extend_from_slice(&data[n..]);
                }
                Ok(n)
            },
            None => Ok(0),
        }
    }

    async fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let tx = self.write_tx.as_ref().ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::BrokenPipe,
                "vless inbound stream shut down",
            )
        })?;
        tx.send(buf.to_vec()).map_err(|_| {
            std::io::Error::new(ErrorKind::BrokenPipe, "vless inbound closed")
        })
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        // Half-close: stop writing to the client, keep reading from it.
        self.write_tx = None;
        Ok(())
    }
}

impl Drop for VlessServerStream {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

/// UDP `PacketRelay` for one VLESS command-0x02 connection. Every datagram
/// is associated with the request's fixed destination.
struct VlessServerPacketRelay {
    data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    write_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    closed: Arc<AtomicBool>,
    dest: Destination,
    pending: Vec<u8>,
}

#[async_trait]
impl PacketRelay for VlessServerPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> std::io::Result<(usize, Destination)> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok((n, self.dest.clone()));
        }
        match self.data_rx.recv().await {
            Some(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    self.pending.extend_from_slice(&data[n..]);
                }
                Ok((n, self.dest.clone()))
            },
            None => Ok((0, self.dest.clone())),
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], _dest: &Destination,
    ) -> std::io::Result<()> {
        let tx = self.write_tx.as_ref().ok_or_else(|| {
            std::io::Error::new(ErrorKind::BrokenPipe, "vless inbound udp closed")
        })?;
        tx.send(buf.to_vec()).map_err(|_| {
            std::io::Error::new(ErrorKind::BrokenPipe, "vless inbound udp closed")
        })
    }

    async fn close(&mut self) -> std::io::Result<()> {
        self.write_tx = None;
        self.closed.store(true, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for VlessServerPacketRelay {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Blocking IO loop
// ---------------------------------------------------------------------------

/// Forward raw transport bytes toward the relay (deframing UDP packets).
fn forward_bytes(
    deframer: Option<&mut UdpDeframer>, data: &[u8],
    data_tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), ()> {
    match deframer {
        Some(dfr) => {
            let mut packets = Vec::new();
            dfr.feed(data, &mut packets);
            for packet in packets {
                if data_tx.send(packet).is_err() {
                    return Err(());
                }
            }
        },
        None => {
            if !data.is_empty() && data_tx.send(data.to_vec()).is_err() {
                return Err(());
            }
        },
    }
    Ok(())
}

/// Single blocking IO loop serving one established VLESS connection:
/// alternately drains upstream→client writes and reads client→upstream
/// bytes (the same single-IO-loop model as the anytls inbound — boring's
/// `SslStream` must not be touched from two threads).
///
/// Half-close aware: after the client's side hits EOF the loop keeps
/// forwarding buffered upstream writes until the relay (and its write
/// channel) goes away, mirroring `relay::bidirectional_relay`.
fn relay_loop(
    mut io: Box<dyn VlessIo>, udp: bool, pending: Vec<u8>,
    data_tx: mpsc::UnboundedSender<Vec<u8>>,
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    closed: Arc<AtomicBool>,
) {
    io.set_read_timeout(RELAY_READ_TIMEOUT);
    let mut deframer = if udp { Some(UdpDeframer::new()) } else { None };
    let mut buf = vec![0u8; 64 * 1024];
    let mut read_eof = false;

    // First payload bundled with the request header.
    if forward_bytes(deframer.as_mut(), &pending, &data_tx).is_err() {
        return;
    }

    loop {
        // 1. Non-blocking drain of upstream→client chunks.
        let mut writes_open = true;
        loop {
            match write_rx.try_recv() {
                Ok(chunk) => {
                    let out = if udp {
                        udp_frame_packet(&chunk)
                    } else {
                        chunk
                    };
                    if io.write_all(&out).is_err() {
                        return;
                    }
                },
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    writes_open = false;
                    break;
                },
            }
        }

        if read_eof {
            if !writes_open {
                break;
            }
            // Client half-closed but the upstream is still writing: block
            // for the next chunk (relay shutdown/drop closes the channel).
            match write_rx.blocking_recv() {
                Some(chunk) => {
                    let out = if udp {
                        udp_frame_packet(&chunk)
                    } else {
                        chunk
                    };
                    if io.write_all(&out).is_err() {
                        return;
                    }
                },
                None => break,
            }
            continue;
        }

        // 2. Read client→upstream.
        match io.read(&mut buf) {
            Ok(0) => {
                read_eof = true;
                if !writes_open {
                    break;
                }
            },
            Ok(n) => {
                if forward_bytes(deframer.as_mut(), &buf[..n], &data_tx).is_err()
                {
                    return;
                }
            },
            Err(e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut =>
            {
                if closed.load(Ordering::Relaxed) {
                    break;
                }
            },
            Err(_) => break,
        }
    }
    io.close();
}

// ---------------------------------------------------------------------------
// Vision (flow=xtls-rprx-vision) server relay — xray
// proxy/vless/inbound/inbound.go:552-623 + proxy/proxy.go Vision machines.
// ---------------------------------------------------------------------------

/// Flow validation for one request (xray inbound.go:552-583). Returns
/// `Ok(true)` for the Vision path, `Ok(false)` for the plain path, `Err` to
/// reject the connection. Vision is TCP-only over a direct TLS 1.3
/// transport (cert/key TLS or REALITY — inbound.go:571-579); ws framing and
/// other transports cannot carry the Direct-phase raw splice, so they
/// reject like xray's non-TLS conns.
fn vision_flow(
    flow: Option<&str>, command: &VlessCommand, tls: bool, ws: bool,
    tls13: bool,
) -> Result<bool, String> {
    match flow {
        // Empty flow behaves like no flow (xray case "", inbound.go:592-596).
        None | Some("") => Ok(false),
        Some(FLOW_XRV) => {
            if matches!(command, VlessCommand::Udp) {
                // inbound.go:557-558.
                return Err(format!("{FLOW_XRV} doesn't support UDP"));
            }
            if ws || !tls {
                // inbound.go:581 — the outer transport must be TLS (or
                // REALITY) directly; ws sits between.
                return Err(
                    "XTLS only supports TLS and REALITY directly for now."
                        .to_string(),
                );
            }
            if !tls13 {
                // inbound.go:571-574.
                return Err(format!(
                    "failed to use {FLOW_XRV}: outer tls version is not 1.3"
                ));
            }
            Ok(true)
        },
        Some(other) => Err(format!("unknown request flow {other}")),
    }
}

/// Server-side Vision relay state: the two Inbound state lines (uplink
/// read / downlink write — xray `TrafficState.Inbound`, proxy.go:118-131)
/// sharing one TLS-detection block, plus the response-header and Direct
/// handoff bookkeeping.
struct VisionRelay {
    uplink: ServerUplinkReader,
    downlink: ServerDownlinkWriter,
    /// `Inbound.UplinkReaderDirectCopy`: the client asked for the raw splice.
    uplink_direct: bool,
    /// `Inbound.DownlinkWriterDirectCopy`: we told the client to splice.
    downlink_direct: bool,
    /// The VLESS response header (version 0 + addons_len 0), pending until
    /// the first downlink frame: xray buffers it below its VisionWriter and
    /// flushes header + frame together (inbound.go:604-623, SetFlushNext).
    response_pending: bool,
}

impl VisionRelay {
    fn new(uuid: [u8; 16]) -> Self {
        let filter = Arc::new(Mutex::new(VisionFilterState::new()));
        Self {
            uplink: ServerUplinkReader::new(uuid, filter.clone()),
            downlink: ServerDownlinkWriter::new(uuid, filter),
            uplink_direct: false,
            downlink_direct: false,
            response_pending: true,
        }
    }

    /// Uplink step: decode one client-side chunk and forward the content to
    /// the target. A chunk carrying a Direct frame also flips
    /// [`Self::uplink_direct`] — from the next read on the loop splices the
    /// raw socket (the switch-point TLS buffers are provably empty, see the
    /// `obfuscation::vision` module docs).
    fn forward_uplink(
        &mut self, chunk: &[u8], data_tx: &mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<(), ()> {
        let content = self.uplink.read_chunk(chunk);
        if self.uplink.take_direct_switch() {
            log::debug!("vision inbound: uplink Direct — raw-socket splice");
            self.uplink_direct = true;
        }
        if !content.is_empty() && data_tx.send(content).is_err() {
            return Err(());
        }
        Ok(())
    }

    /// Downlink step: encode one target-side chunk for the client. Returns
    /// `None` when the chunk belongs on the raw socket (Direct phase);
    /// otherwise the bytes to write through the outer TLS stream — the
    /// first non-empty output coalesces the pending response header.
    fn encode_downlink(&mut self, chunk: &[u8]) -> Option<Vec<u8>> {
        if self.downlink_direct {
            return None;
        }
        let framed = self.downlink.write_chunk(chunk);
        if framed.is_empty() {
            return Some(framed);
        }
        if self.downlink.take_direct_switch() {
            log::debug!("vision inbound: downlink Direct — raw-socket splice");
            self.downlink_direct = true;
        }
        if self.response_pending {
            self.response_pending = false;
            let mut out = Vec::with_capacity(2 + framed.len());
            out.extend_from_slice(&[0x00, 0x00]);
            out.extend_from_slice(&framed);
            return Some(out);
        }
        Some(framed)
    }
}

/// Push one target-side chunk toward the client: Vision framing through the
/// outer TLS stream during padding, raw socket splice after Direct.
fn write_downlink(
    io: &mut Box<dyn VlessIo>, raw: &mut TcpStream, relay: &mut VisionRelay,
    chunk: &[u8],
) -> std::io::Result<()> {
    match relay.encode_downlink(chunk) {
        None => {
            let mut w = &*raw;
            w.write_all(chunk)
        },
        Some(framed) if framed.is_empty() => Ok(()),
        Some(framed) => io.write_all(&framed),
    }
}

/// Graceful close for the Vision relay. Once the downlink spliced raw
/// bytes, no TLS close_notify may be injected into the byte stream the peer
/// reads raw (the same rule as the outbound's VisionReality shutdown); the
/// raw socket shutdown covers both directions.
fn close_vision(
    io: &mut Box<dyn VlessIo>, raw: &mut TcpStream, downlink_direct: bool,
) {
    if downlink_direct {
        let _ = raw.shutdown(Shutdown::Both);
    } else {
        io.close();
    }
}

/// Single blocking IO loop serving one Vision connection — the same
/// alternation model as [`relay_loop`], with the Vision machines in both
/// directions and the raw-socket splice after each Direct handoff.
fn vision_relay_loop(
    mut io: Box<dyn VlessIo>, mut raw: TcpStream, pending: Vec<u8>,
    uuid: [u8; 16], data_tx: mpsc::UnboundedSender<Vec<u8>>,
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>, closed: Arc<AtomicBool>,
) {
    io.set_read_timeout(RELAY_READ_TIMEOUT);
    // Only read after the uplink Direct handoff; the same tick keeps the
    // parked-read drain below behaving identically in both phases.
    let _ = raw.set_read_timeout(Some(RELAY_READ_TIMEOUT));
    let mut relay = VisionRelay::new(uuid);
    let mut buf = vec![0u8; 64 * 1024];
    let mut read_eof = false;

    // The first payload rides with the request header: clients write the
    // request header and the first (UUID-prefixed) Vision frame in one
    // flush (xray outbound.go:322-366), so these bytes are frame content.
    if relay.forward_uplink(&pending, &data_tx).is_err() {
        close_vision(&mut io, &mut raw, relay.downlink_direct);
        return;
    }

    loop {
        // 1. Non-blocking drain of upstream→client chunks.
        let mut writes_open = true;
        loop {
            match write_rx.try_recv() {
                Ok(chunk) => {
                    if write_downlink(&mut io, &mut raw, &mut relay, &chunk)
                        .is_err()
                    {
                        return;
                    }
                },
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    writes_open = false;
                    break;
                },
            }
        }

        if read_eof {
            if !writes_open {
                break;
            }
            // Client half-closed but the upstream is still writing: block
            // for the next chunk (relay shutdown/drop closes the channel).
            match write_rx.blocking_recv() {
                Some(chunk) => {
                    if write_downlink(&mut io, &mut raw, &mut relay, &chunk)
                        .is_err()
                    {
                        return;
                    }
                },
                None => break,
            }
            continue;
        }

        // 2. Read client→upstream (raw splice after the Direct handoff).
        let read = if relay.uplink_direct {
            let mut r = &raw;
            r.read(&mut buf)
        } else {
            io.read(&mut buf)
        };
        match read {
            Ok(0) => {
                read_eof = true;
                if !writes_open {
                    break;
                }
            },
            Ok(n) => {
                if relay.forward_uplink(&buf[..n], &data_tx).is_err() {
                    close_vision(&mut io, &mut raw, relay.downlink_direct);
                    return;
                }
            },
            Err(e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut =>
            {
                if closed.load(Ordering::Relaxed) {
                    break;
                }
            },
            Err(_) => break,
        }
    }
    close_vision(&mut io, &mut raw, relay.downlink_direct);
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

/// Blocking handler for one accepted TCP connection: TLS (cert/key or
/// pre-authenticated REALITY) → ws upgrade (optional) → VLESS request +
/// auth → response → relay loop.
fn handle_vless_conn(
    tcp: tokio::net::TcpStream, peer: std::net::SocketAddr, tls: TlsMode,
    ws: Option<Arc<WsInboundConfig>>, uuids: Arc<Vec<[u8; 16]>>,
    conn_tx: mpsc::Sender<InboundConn>,
) {
    let std_stream = match tcp.into_std() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("vless inbound: failed to convert stream from {peer}: {e}");
            return;
        },
    };
    // tokio hands the raw fd over in nonblocking mode; the blocking TLS
    // accept (and everything below) would fail with WANT_READ otherwise.
    if let Err(e) = std_stream.set_nonblocking(false) {
        log::warn!("vless inbound: failed to set blocking mode: {e}");
        return;
    }
    let _ = std_stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    // Raw duplicate for the Vision Direct-phase splice (the fd is dup'd;
    // dropping the SSL stream later does not close the socket). Same
    // pattern as the outbound's dup_reactor_stream, blocking flavor.
    let raw = match std_stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("vless inbound: failed to clone socket from {peer}: {e}");
            return;
        },
    };

    // --- optional TLS ---
    let mut tls13 = false;
    let tls_direct = !matches!(tls, TlsMode::None);
    let io: Box<dyn VlessIo> = match tls {
        TlsMode::Cert(ctx) => {
            let ssl = match Ssl::new(&ctx) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("vless inbound: SSL new failed from {peer}: {e}");
                    return;
                },
            };
            let mut stream = match SslStream::new(ssl, std_stream) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("vless inbound: SSL stream failed from {peer}: {e}");
                    return;
                },
            };
            if let Err(e) = stream.accept() {
                log::debug!("vless inbound: TLS handshake from {peer} failed: {e}");
                return;
            }
            // Vision requires TLS 1.3 exactly (inbound.go:571-574).
            tls13 = stream.ssl().version2() == Some(SslVersion::TLS1_3);
            Box::new(stream)
        },
        TlsMode::Reality(server, auth_key, prefix, borrowed) => {
            // The ClientHello was authenticated pre-handshake
            // (RealityServer::authenticate); finish a standard TLS 1.3
            // accept over the replayed prefix with the one-time
            // HMAC-signed Ed25519 certificate for this AuthKey. When the
            // ServerHello borrow succeeded, the SSL is pinned to the
            // destination site's key-share group and cipher suite so the
            // handshake's visible parameters match the camouflage site.
            let ssl = match server.new_ssl(borrowed.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("vless inbound: reality SSL from {peer} failed: {e}");
                    return;
                },
            };
            let mut stream =
                match SslStream::new(ssl, PrefixStream::new(prefix, std_stream))
                {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!(
                            "vless inbound: reality SSL stream from {peer} failed: {e}"
                        );
                        return;
                    },
                };
            if let Err(e) = server.inject_cert(stream.ssl_mut(), &auth_key) {
                log::warn!(
                    "vless inbound: reality certificate for {peer} failed: {e}"
                );
                return;
            }
            if let Err(e) = stream.accept() {
                log::debug!(
                    "vless inbound: reality TLS handshake from {peer} failed: {e}"
                );
                return;
            }
            // REALITY's accept context is TLS 1.3-only; the explicit check
            // keeps the vision_flow contract honest (inbound.go:571-574).
            tls13 = stream.ssl().version2() == Some(SslVersion::TLS1_3);
            if !tls13 {
                log::warn!(
                    "vless inbound: reality connection from {peer} is not TLS 1.3"
                );
                return;
            }
            Box::new(stream)
        },
        TlsMode::None => Box::new(std_stream),
    };

    // --- optional ws upgrade ---
    let io: Box<dyn VlessIo> = match &ws {
        Some(cfg) => match WsServerStream::handshake(
            io, &cfg.path, cfg.host.as_deref(),
        ) {
            Ok(w) => Box::new(w),
            Err(e) => {
                log::debug!("vless inbound: ws handshake from {peer} failed: {e}");
                return;
            },
        },
        None => io,
    };

    // --- VLESS request ---
    let mut io = io;
    let (req, pending) = match read_vless_request(&mut *io) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("vless inbound: request from {peer} failed: {e}");
            return;
        },
    };
    if !uuids.contains(&req.uuid) {
        log::warn!("vless inbound: auth failed from {peer}");
        return;
    }
    log::debug!(
        "vless inbound: {} request to {} from {peer}",
        match req.command {
            VlessCommand::Tcp => "tcp",
            VlessCommand::Udp => "udp",
        },
        req.dest,
    );

    // --- flow validation (inbound.go:552-583) ---
    // REALITY (like cert/key TLS) counts as the direct TLS transport and is
    // TLS 1.3-only, so flow=xtls-rprx-vision rides on it (inbound.go:577-579
    // accepts a reality.Conn alongside tls.Conn).
    let vision = match vision_flow(
        req.flow.as_deref(),
        &req.command,
        tls_direct,
        ws.is_some(),
        tls13,
    ) {
        Ok(vision) => vision,
        Err(reason) => {
            log::warn!("vless inbound: rejecting flow from {peer}: {reason}");
            return;
        },
    };

    // --- response: version(0) + addons_len(0) ---
    // The Vision path defers it: xray buffers the header below its
    // VisionWriter and flushes it with the first downlink frame
    // (inbound.go:604-623), hiding the 2-byte signature in that frame's
    // TLS record.
    if !vision && (io.write_all(&[0x00, 0x00]).is_err() || io.flush().is_err())
    {
        return;
    }

    // --- hand off to the runner ---
    let (data_tx, data_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let closed = Arc::new(AtomicBool::new(false));
    let udp = matches!(req.command, VlessCommand::Udp);
    match req.command {
        VlessCommand::Tcp => {
            let relay = Box::new(VlessServerStream {
                data_rx,
                write_tx: Some(write_tx),
                closed: closed.clone(),
                pending: Vec::new(),
            });
            let conn = InboundConn::Tcp {
                destination: req.dest,
                stream: relay,
                source: peer,
                type_: "vless".to_string(),
                sniff: false,
            };
            if conn_tx.blocking_send(conn).is_err() {
                return;
            }
        },
        VlessCommand::Udp => {
            let relay = Box::new(VlessServerPacketRelay {
                data_rx,
                write_tx: Some(write_tx),
                closed: closed.clone(),
                dest: req.dest.clone(),
                pending: Vec::new(),
            });
            let conn = InboundConn::Udp {
                initial_destination: req.dest,
                packet: relay,
                source: peer,
                type_: "vless".to_string(),
            };
            if conn_tx.blocking_send(conn).is_err() {
                return;
            }
        },
    }
    if vision {
        vision_relay_loop(io, raw, pending, req.uuid, data_tx, write_rx, closed);
    } else {
        relay_loop(io, udp, pending, data_tx, write_rx, closed);
    }
}

// ---------------------------------------------------------------------------
// VlessInbound
// ---------------------------------------------------------------------------

/// Server-side VLESS inbound. See the module docs for the protocol model.
pub struct VlessInbound {
    conn_rx: mpsc::Receiver<InboundConn>,
}

impl VlessInbound {
    /// Create a vless inbound from config. Requires `listen`; TLS is enabled
    /// when both `cert` and `key` are set; `[inbounds.reality]` switches the
    /// inbound to the REALITY transport (mutually exclusive with cert/key
    /// and with `[transport]`); `[transport]` (type "ws") enables the
    /// WebSocket handshake. `None` when the config is unusable.
    pub fn from_config(
        config: &InboundConfig, passwords: Vec<String>,
    ) -> Option<Self> {
        let listen = config.listen.as_ref()?;

        let reality = match &config.reality {
            Some(cfg) => match RealityServer::from_config(cfg) {
                Ok(server) => Some(Arc::new(server)),
                Err(e) => {
                    log::error!("vless inbound: invalid [inbounds.reality]: {e}");
                    return None;
                },
            },
            None => None,
        };
        // REALITY is bare TCP by definition: it borrows the target's TLS
        // handshake bytes and Vision's Direct splice needs the raw socket —
        // a terminated TLS layer (cert/key) or ws framing in between breaks
        // both (same exclusivity shape as the outbound's reality checks).
        if reality.is_some() && (config.cert.is_some() || config.key.is_some())
        {
            log::error!(
                "vless inbound: [inbounds.reality] and cert/key are mutually \
                 exclusive"
            );
            return None;
        }
        if reality.is_some() && config.transport.is_some() {
            log::error!(
                "vless inbound: [inbounds.reality] cannot be combined with a \
                 [transport] (ws) section"
            );
            return None;
        }

        let tls = match (&config.cert, &config.key) {
            (Some(cert), Some(key)) => match build_ssl_context(cert, key) {
                Ok(ctx) => Some(Arc::new(ctx)),
                Err(e) => {
                    log::error!("vless inbound: failed to load cert/key: {e}");
                    return None;
                },
            },
            (None, None) => None,
            _ => {
                log::error!("vless inbound: cert and key must be set together");
                return None;
            },
        };

        let ws = match &config.transport {
            Some(t) => {
                if t.type_ != "ws" {
                    log::error!(
                        "vless inbound: unsupported transport type '{}'",
                        t.type_
                    );
                    return None;
                }
                let Some(ws_cfg) = t.ws.as_ref() else {
                    log::error!(
                        "vless inbound: [transport] present without [transport.ws]"
                    );
                    return None;
                };
                let path = ws_cfg
                    .path
                    .clone()
                    .unwrap_or_else(|| "/".to_string());
                let host = ws_cfg
                    .headers
                    .as_ref()
                    .and_then(|h| h.get("Host"))
                    .cloned();
                Some(Arc::new(WsInboundConfig { path, host }))
            },
            None => None,
        };

        // The outbound uses the password string directly as the VLESS UUID
        // (parse_uuid), so the inbound authenticates the same way.
        let mut uuids = Vec::new();
        for pw in &passwords {
            match crate::outbound::vless::parse_uuid(pw) {
                Ok(u) => uuids.push(u),
                Err(_) => {
                    log::debug!(
                        "vless inbound: user password is not a UUID, skipping"
                    );
                },
            }
        }
        if uuids.is_empty() {
            log::error!(
                "vless inbound: no [[users]] password parses as a VLESS UUID"
            );
            return None;
        }

        let (conn_tx, conn_rx) = mpsc::channel(256);
        let listen_addr = listen.clone();

        tokio::spawn(async move {
            Self::run(
                listen_addr, tls, reality, ws, Arc::new(uuids), conn_tx,
            )
            .await;
        });

        Some(Self { conn_rx })
    }

    async fn run(
        listen_addr: String, tls: Option<Arc<SslContext>>,
        reality: Option<Arc<RealityServer>>,
        ws: Option<Arc<WsInboundConfig>>, uuids: Arc<Vec<[u8; 16]>>,
        conn_tx: mpsc::Sender<InboundConn>,
    ) {
        let listener = match TcpListener::bind(&listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                log::error!("vless inbound: failed to bind {listen_addr}: {e}");
                return;
            },
        };
        log::info!("vless inbound listening on {listen_addr}");

        loop {
            let (mut tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("vless inbound: accept error: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                },
            };

            log::debug!("vless inbound: new connection from {peer}");

            let ws = ws.clone();
            let uuids = uuids.clone();
            let tx = conn_tx.clone();

            match &reality {
                Some(server) => {
                    // REALITY path: peek + authenticate the ClientHello
                    // asynchronously (bounded by the peek timeout), then
                    // either finish the TLS accept on the blocking pool or
                    // splice the connection transparently to dest.
                    let server = server.clone();
                    tokio::spawn(async move {
                        match server.authenticate(&mut tcp).await {
                            Ok(RealityPeek::Authenticated {
                                auth_key,
                                prefix,
                                borrow_ctx,
                            }) => {
                                log::debug!(
                                    "vless inbound: REALITY client from {peer}"
                                );
                                // ServerHello borrow attempt: mirror the
                                // ClientHello to the real destination and
                                // adopt its handshake parameters; degrade
                                // to the local handshake when unusable.
                                let borrowed = server
                                    .borrow_server_hello(&prefix, &borrow_ctx)
                                    .await;
                                tokio::task::spawn_blocking(move || {
                                    handle_vless_conn(
                                        tcp,
                                        peer,
                                        TlsMode::Reality(
                                            server,
                                            auth_key,
                                            prefix,
                                            borrowed,
                                        ),
                                        ws,
                                        uuids,
                                        tx,
                                    );
                                });
                            },
                            Ok(RealityPeek::Fallback { prefix }) => {
                                log::debug!(
                                    "vless inbound: unauthenticated connection \
                                     from {peer}; falling back to {}",
                                    server.dest()
                                );
                                server.splice_fallback(tcp, prefix).await;
                            },
                            Err(e) => {
                                log::debug!(
                                    "vless inbound: reality peek from {peer} \
                                     failed: {e}"
                                );
                            },
                        }
                    });
                },
                None => {
                    let tls = tls.clone();

                    // boring is synchronous: the TLS accept, the ws handshake
                    // and the relay loop below all block on std reads, so
                    // they must run on the blocking pool — an async worker
                    // would be pinned for the lifetime of the connection.
                    tokio::task::spawn_blocking(move || {
                        let tls =
                            tls.map(TlsMode::Cert).unwrap_or(TlsMode::None);
                        handle_vless_conn(tcp, peer, tls, ws, uuids, tx);
                    });
                },
            }
        }
    }
}

#[async_trait]
impl Inbound for VlessInbound {
    async fn accept(&mut self) -> Option<InboundConn> {
        self.conn_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::vless::encode_request_bytes;

    /// The server parser must accept exactly what the outbound encoder
    /// produces (`protocol::vless::encode_request_bytes`), for every address
    /// type and command, and surface trailing bytes as the first payload.
    #[test]
    fn parses_outbound_encoded_requests() {
        for (command, addr, port) in [
            (
                VlessCommand::Tcp,
                Address::Ipv4([10, 0, 0, 1]),
                443u16,
            ),
            (
                VlessCommand::Udp,
                Address::Domain("example.com".into()),
                53u16,
            ),
            (
                VlessCommand::Tcp,
                Address::Ipv6([0x20; 16]),
                8080u16,
            ),
        ] {
            let dest = Destination::new(addr.clone(), port);
            let mut req =
                encode_request_bytes(&[0xab; 16], None, command.clone(), &dest);
            req.extend_from_slice(b"first-payload");

            let (parsed, consumed) =
                try_parse_vless_request(&req).unwrap().unwrap();
            assert_eq!(parsed.uuid, [0xab; 16]);
            assert_eq!(parsed.command as u8, command as u8);
            assert_eq!(parsed.dest, dest);
            // Trailing bytes after the header are the first payload.
            let payload_len = b"first-payload".len();
            assert_eq!(req.len() - consumed, payload_len);
            assert_eq!(&req[consumed..], b"first-payload");
        }
    }

    /// Byte-stream resilience: the header may be split across reads and must
    /// still parse identically.
    #[test]
    fn parses_request_split_across_reads() {
        let dest = Destination::new(Address::Ipv4([127, 0, 0, 1]), 80);
        let req =
            encode_request_bytes(&[0x42; 16], None, VlessCommand::Tcp, &dest);
        for i in 1..req.len() {
            let mut buf = req[..i].to_vec();
            assert!(try_parse_vless_request(&buf).unwrap().is_none());
            buf.extend_from_slice(&req[i..]);
            let (parsed, consumed) =
                try_parse_vless_request(&buf).unwrap().unwrap();
            assert_eq!(parsed.dest, dest);
            assert_eq!(consumed, buf.len());
        }
    }

    /// Addons carry the Vision flow — parsed out of the protobuf `Addons`
    /// message (field 1, length-delimited) with the header consumed
    /// correctly and trailing payload preserved.
    #[test]
    fn parses_vision_flow_addons() {
        let dest = Destination::new(Address::Ipv4([10, 0, 0, 1]), 443);
        let mut req = encode_request_bytes(
            &[0xab; 16],
            Some("xtls-rprx-vision"),
            VlessCommand::Tcp,
            &dest,
        );
        req.extend_from_slice(b"first-payload");

        let (parsed, consumed) =
            try_parse_vless_request(&req).unwrap().unwrap();
        assert_eq!(parsed.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(parsed.command as u8, VlessCommand::Tcp as u8);
        assert_eq!(parsed.dest, dest);
        assert_eq!(&req[consumed..], b"first-payload");
    }

    /// Empty addons parse to no flow; a Seed-only addons blob (field 2) is
    /// accepted and ignored (xray uses it for UDP framing only).
    #[test]
    fn parses_empty_and_seed_only_addons() {
        let dest = Destination::new(Address::Ipv4([10, 0, 0, 1]), 443);
        let req =
            encode_request_bytes(&[0xab; 16], None, VlessCommand::Tcp, &dest);
        let (parsed, _) = try_parse_vless_request(&req).unwrap().unwrap();
        assert_eq!(parsed.flow, None);

        // 0x12 = field 2, wire type 2 (Seed), 4 bytes; the addons blob is
        // 6 bytes long.
        let mut req = vec![0x00u8];
        req.extend_from_slice(&[0xab; 16]);
        req.extend_from_slice(&[0x06, 0x12, 0x04, 1, 2, 3, 4]);
        req.extend_from_slice(&[0x01, 0x00, 0x50, 0x01]); // TCP, port 80, ATYP v4
        req.extend_from_slice(&[10, 0, 0, 1]);
        let (parsed, consumed) =
            try_parse_vless_request(&req).unwrap().unwrap();
        assert_eq!(parsed.flow, None);
        assert_eq!(parsed.dest.port, 80);
        assert_eq!(consumed, req.len());
    }

    /// Malformed or unknown addon encodings are protocol violations, like a
    /// failed proto unmarshal in xray.
    #[test]
    fn rejects_malformed_addons() {
        let base = |addons: &[u8]| {
            let mut req = vec![0x00u8];
            req.extend_from_slice(&[0xab; 16]);
            req.push(addons.len() as u8);
            req.extend_from_slice(addons);
            req.extend_from_slice(&[0x01, 0x00, 0x00, 0x50, 0x01, 10, 0, 0, 1]);
            req
        };
        // Unknown field 3.
        assert!(try_parse_vless_request(&base(&[0x1a, 0x02, 1, 2])).is_err());
        // Truncated field body.
        assert!(try_parse_vless_request(&base(&[0x0a, 0x08, 1, 2])).is_err());
        // Truncated varint length.
        assert!(try_parse_vless_request(&base(&[0x0a, 0x80])).is_err());
        // Flow is not utf-8.
        assert!(try_parse_vless_request(&base(&[0x0a, 0x02, 0xff, 0xfe]))
            .is_err());
    }

    /// The flow matrix of xray inbound.go:552-583 as enforced server-side.
    #[test]
    fn vision_flow_matrix() {
        let tcp = VlessCommand::Tcp;
        let udp = VlessCommand::Udp;
        let xrv = Some("xtls-rprx-vision");
        // Plain: no flow is always accepted, in any transport.
        assert_eq!(vision_flow(None, &tcp, false, false, false), Ok(false));
        assert_eq!(
            vision_flow(None, &tcp, true, true, true),
            Ok(false),
            "ws without flow keeps working"
        );
        // Vision over direct TLS 1.3.
        assert_eq!(vision_flow(xrv, &tcp, true, false, true), Ok(true));
        // UDP + flow: rejected before the transport checks.
        assert!(vision_flow(xrv, &udp, true, false, true).is_err());
        // No TLS / ws / TLS 1.2: rejected.
        assert!(vision_flow(xrv, &tcp, false, false, true).is_err());
        assert!(vision_flow(xrv, &tcp, true, true, true).is_err());
        assert!(vision_flow(xrv, &tcp, true, false, false).is_err());
        // Any other flow: rejected.
        assert!(vision_flow(Some("dark"), &tcp, true, false, true).is_err());
        // Empty flow behaves like no flow (xray case "").
        assert_eq!(vision_flow(Some(""), &tcp, false, false, false), Ok(false));
    }

    /// UDP framing: [2-byte BE length]+[packet] in feed order, surviving
    /// torn boundaries (mirrors the outbound's `UdpDeframer` tests).
    #[test]
    fn udp_framing_roundtrip_with_torn_boundaries() {
        let packets: Vec<Vec<u8>> = vec![
            b"aaaa".to_vec(),
            b"bb".to_vec(),
            Vec::new(), // zero-length frame is legal
            vec![7u8; 1000],
        ];
        let mut stream = Vec::new();
        for p in &packets {
            stream.extend(udp_frame_packet(p));
        }
        let mut dfr = UdpDeframer::new();
        let mut out = Vec::new();
        for b in &stream {
            dfr.feed(std::slice::from_ref(b), &mut out);
        }
        assert_eq!(out, packets);
    }

    // -- Vision relay (server roles) ---------------------------------------

    use crate::obfuscation::vision::COMMAND_PADDING_CONTINUE;
    use crate::obfuscation::vision::COMMAND_PADDING_DIRECT;

    const VUUID: [u8; 16] = [7u8; 16];

    /// Build one Vision frame the way a peer's writer would.
    fn vision_frame(
        uuid: &[u8; 16], command: u8, content: &[u8], padding: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(uuid);
        out.push(command);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(padding as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.extend(std::iter::repeat_n(0u8, padding));
        out
    }

    /// Inner-TLS ServerHello carrying supported_versions + a TLS 1.3
    /// cipher — flips the shared filter into EnableXtls (proxy.go:649-655).
    fn inner_server_hello() -> Vec<u8> {
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAA; 32]);
        body.push(32);
        body.extend_from_slice(&[0xBB; 32]);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![0x02u8];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16u8, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// Inner-TLS AppData record wrapping `payload`.
    fn inner_app_data(payload: &[u8]) -> Vec<u8> {
        let mut rec = vec![0x17u8, 0x03, 0x03];
        rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        rec.extend_from_slice(payload);
        rec
    }

    /// Uplink: framed chunks are unpadded to the content; a Direct frame is
    /// delivered and then the relay flips to raw splice.
    #[test]
    fn vision_relay_uplink_unpads_and_switches() {
        let (data_tx, mut data_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut relay = VisionRelay::new(VUUID);

        let payload = b"inner client hello".to_vec();
        let framed = vision_frame(
            &VUUID,
            COMMAND_PADDING_CONTINUE,
            &payload,
            11,
        );
        relay.forward_uplink(&framed, &data_tx).unwrap();
        assert_eq!(data_rx.blocking_recv(), Some(payload));
        assert!(!relay.uplink_direct);

        // The UUID prefix is written once per direction; the Direct frame
        // is bare.
        let mut framed =
            vision_frame(&VUUID, COMMAND_PADDING_DIRECT, b"raw tail", 0);
        let framed = framed.split_off(16);
        relay.forward_uplink(&framed, &data_tx).unwrap();
        assert_eq!(data_rx.blocking_recv(), Some(b"raw tail".to_vec()));
        assert!(relay.uplink_direct);
    }

    /// Downlink: the response header rides with the first frame; the
    /// ServerHello arms EnableXtls; the first complete AppData record goes
    /// out as a Direct frame and every later chunk belongs on the raw
    /// socket.
    #[test]
    fn vision_relay_downlink_header_and_direct() {
        let mut relay = VisionRelay::new(VUUID);

        // First chunk: [00 00] + first frame with the UUID prefix.
        let out = relay.encode_downlink(b"plain").unwrap();
        assert_eq!(&out[..2], &[0x00, 0x00]);
        assert_eq!(&out[2..18], &VUUID);
        assert_eq!(out[18], COMMAND_PADDING_CONTINUE);
        assert_eq!(&out[23..28], b"plain");
        assert!(!relay.downlink_direct);

        // Header is written exactly once: later frames are bare.
        let out = relay.encode_downlink(b"more").unwrap();
        assert_eq!(out[0], COMMAND_PADDING_CONTINUE);
        assert_eq!(&out[1..3], &4u16.to_be_bytes());
        assert_eq!(&out[5..9], b"more");

        // ServerHello → shared filter EnableXtls (single frame, Continue).
        let sh = inner_server_hello();
        let out = relay.encode_downlink(&sh).unwrap();
        assert_eq!(out[0], COMMAND_PADDING_CONTINUE);
        assert_eq!(&out[5..5 + sh.len()], &sh[..]);

        // First complete AppData record → single Direct frame + switch.
        let ad = inner_app_data(&[9u8; 100]);
        let out = relay.encode_downlink(&ad).unwrap();
        assert_eq!(out[0], COMMAND_PADDING_DIRECT);
        assert_eq!(&out[5..5 + ad.len()], &ad[..]);
        assert!(relay.downlink_direct);

        // Post-switch: raw splice, nothing framed.
        assert_eq!(relay.encode_downlink(b"raw"), None);
        assert_eq!(relay.encode_downlink(&ad), None);
    }

    /// The shipped example must keep parsing with the exact field names the
    /// inbound reads (`listen`, `cert`, `key`, `[transport.ws]`).
    #[test]
    fn example_server_config_parses() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config/vless-server.toml");
        let raw = std::fs::read_to_string(&path).unwrap();
        let cfg: crate::config::Config = toml::from_str(&raw).unwrap();
        let inbound = cfg
            .inbounds_by_type("vless")
            .first()
            .copied()
            .expect("vless inbound in example");
        assert_eq!(inbound.listen.as_deref(), Some("0.0.0.0:8443"));
        assert!(inbound.cert.is_some() && inbound.key.is_some());
        let transport = inbound.transport.as_ref().expect("ws transport");
        assert_eq!(transport.type_, "ws");
        assert_eq!(transport.ws.as_ref().unwrap().path.as_deref(), Some("/ws"));
        // The example's [[users]].password must authenticate: it is parsed as
        // the VLESS UUID exactly like the outbound does.
        let uuids: Vec<_> = cfg
            .passwords()
            .iter()
            .filter_map(|p| crate::outbound::vless::parse_uuid(p).ok())
            .collect();
        assert_eq!(uuids.len(), 1);
    }
}
