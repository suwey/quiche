//! OpenRung WSS-front relay support (client side).
//!
//! Aligned with the Go client:
//!
//! | Go (openrung repo)                                | here                                  |
//! |---------------------------------------------------|---------------------------------------|
//! | `wsscore.Front`                                   | [`WssFront`]                          |
//! | `wsscore.NormalizeFrontID` / `ValidateFrontID`    | [`normalize_front_id`] / [`validate_front_id`] |
//! | `wsscore.NormalizeFrontURL` / `ValidateFrontURL`  | [`normalize_front_url`] / [`validate_front_url`] |
//! | `wsscore.NormalizeFronts`                         | [`normalize_fronts`]                  |
//! | `wsscore.validFrontID` / `validFrontDNSName`      | `valid_front_id` / `valid_front_dns_name` |
//! | `connectcore.supportedWSSFronts`                  | [`supported_wss_fronts`]              |
//! | `wsscore.BridgePath` / `Subprotocol` / limits     | [`BRIDGE_PATH`] / [`SUBPROTOCOL`] / [`MAX_FRONT_URL_BYTES`]... |
//!
//! The Go module docs are the authority (`wsscore/front.go`, `wsscore/protocol.go`,
//! `docs/wss-fallback.md`). The module also carries the client transport
//! (TLS + strict WebSocket upgrade + yamux session + loopback bridge) and the
//! broker ticket ladder (`brokerapi/wss_ticket.go`,
//! `connectcore/wss.go requestWSSSessionTicket`).
//!
//! Deliberate deviations from the Go client (none affect wire compatibility):
//!
//! - **No client-initiated keepalive pings.** The Go client sends WS pings
//!   every 30 s and yamux pings every 15 s. anywhere answers the sidecar's
//!   yamux pings (the rust yamux crate replies automatically, and the
//!   sidecar's `EnableKeepAlive` tears the session down on an unanswered
//!   ping), which both detects dead paths and keeps the CDN connection warm.
//!   Client-initiated pings are skipped as redundant.
//! - **Per-stream idle deadlines are server-enforced.** The sidecar bounds
//!   first-byte, idle, and session-lifetime; the client bridge adds only the
//!   5-minute shared idle deadline from `CopyOpaque`.
//! - **TUN mode is supported.** The Go desktop refuses WSS fallback under a
//!   full-device TUN (the front dial would loop into the tunnel). anywhere
//!   dials the CDN front through `connect_tcp_bypass`, the same
//!   route-bypass socket marking it already uses to reach relays in TUN
//!   mode, so the front connection does not re-enter the tunnel.
//! - **No broker identity headers.** Ticket requests carry
//!   `Accept`/`Content-Type`/`Cache-Control` only; anywhere has no
//!   telemetry client/session identity to attach.

// ---------------------------------------------------------------------------
// Protocol constants (wsscore/protocol.go)
// ---------------------------------------------------------------------------

/// `wsscore.BridgePath` — the only public path used by the WSS transport.
pub const BRIDGE_PATH: &str = "/api/v1/wss-bridge";

/// `wsscore.Subprotocol` — required on every WSS handshake.
pub const SUBPROTOCOL: &str = "openrung-wss-bridge-v1";

/// `wsscore.ProtocolVersion` — the only advertised front protocol version.
pub const PROTOCOL_VERSION: i64 = 1;

/// `wsscore.MaxFronts` — a capability carries at most four fronts.
pub const MAX_FRONTS: usize = 4;

/// `wsscore.MaxFrontIDBytes`.
pub const MAX_FRONT_ID_BYTES: usize = 64;

/// `wsscore.MaxFrontURLBytes`.
pub const MAX_FRONT_URL_BYTES: usize = 512;

/// `wsscore.MaxTicketBytes` — the opaque bearer bound accepted by client and
/// sidecar.
pub const MAX_TICKET_BYTES: usize = 4096;

/// `wsscore.TicketBearerPrefix`.
pub const TICKET_BEARER_PREFIX: &str = "Bearer ";

// ---------------------------------------------------------------------------
// Front wire shape (wsscore/protocol.go Front)
// ---------------------------------------------------------------------------

/// One signed, relay-specific CDN access path. It never names a destination
/// behind the relay-local sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WssFront {
    pub id: String,
    pub url: String,
    pub protocol_version: i64,
}

impl WssFront {
    pub fn new(id: &str, url: &str) -> Self {
        WssFront {
            id: id.to_string(),
            url: url.to_string(),
            protocol_version: PROTOCOL_VERSION,
        }
    }
}

// ---------------------------------------------------------------------------
// Front ID (wsscore/front.go NormalizeFrontID / validFrontID)
// ---------------------------------------------------------------------------

/// `wsscore.validFrontID` (front.go:128): 1..64 chars of [a-z0-9._-] with an
/// alphanumeric first and last character.
fn valid_front_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_FRONT_ID_BYTES {
        return false;
    }
    let is_alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes
        .iter()
        .all(|&c| is_alnum(c) || c == b'.' || c == b'_' || c == b'-')
}

/// `wsscore.NormalizeFrontID` (front.go:54): reject control whitespace, then
/// trim, lowercase, and validate.
pub fn normalize_front_id(value: &str) -> Result<String, String> {
    if value.contains(['\r', '\n', '\t']) {
        return Err("invalid WSS front: ID contains control whitespace".into());
    }
    let normalized = value.trim().to_lowercase();
    if !valid_front_id(&normalized) {
        return Err(format!(
            "invalid WSS front: ID must be 1..{MAX_FRONT_ID_BYTES} lowercase \
             letters, digits, '.', '_', or '-'"
        ));
    }
    Ok(normalized)
}

/// `wsscore.ValidateFrontID` (front.go:66): requires an already-canonical ID.
pub fn validate_front_id(value: &str) -> Result<(), String> {
    let normalized = normalize_front_id(value)?;
    if normalized != value {
        return Err("invalid WSS front: ID is not canonical".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Front URL (wsscore/front.go NormalizeFrontURL / validFrontDNSName)
// ---------------------------------------------------------------------------

/// `wsscore.validFrontDNSName` (front.go:148): a multi-label DNS name with an
/// alphabetic top-level label (which also rejects legacy numeric IPv4
/// spellings like `127.1` some resolvers treat as addresses).
fn valid_front_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return false;
        }
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return false;
        }
        if !bytes
            .iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return false;
        }
    }
    let final_label = labels[labels.len() - 1];
    final_label.as_bytes()[0].is_ascii_lowercase()
}

/// `wsscore.NormalizeFrontURL` (front.go:81): canonicalizes an
/// operator-provided production front URL. Accepts only WSS CDN DNS names on
/// the default port and the fixed bridge path; raw IPs, alternate ports,
/// credentials, queries, fragments, and escaped paths are rejected.
pub fn normalize_front_url(raw: &str) -> Result<String, String> {
    if raw.contains(['\r', '\n', '\t']) {
        return Err("invalid WSS front: URL contains control whitespace".into());
    }
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_FRONT_URL_BYTES {
        return Err("invalid WSS front: URL is empty or oversized".into());
    }
    let parsed = url::Url::parse(raw)
        .map_err(|_| "invalid WSS front: URL must be an absolute hierarchical URL".to_string())?;
    if !parsed.cannot_be_a_base() {
        // hierarchical http-style URL: fine (Go's Opaque check maps to
        // cannot_be_a_base here)
    } else {
        return Err("invalid WSS front: URL must be an absolute hierarchical URL".into());
    }
    let host = parsed
        .host_str()
        .ok_or("invalid WSS front: URL must be an absolute hierarchical URL")?;
    if parsed.scheme() != "wss" {
        return Err("invalid WSS front: URL must use wss".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("invalid WSS front: URL may not contain userinfo, a query, or a fragment".into());
    }
    if parsed.query().is_some() {
        return Err("invalid WSS front: URL may not contain userinfo, a query, or a fragment".into());
    }
    if parsed.fragment().is_some() {
        return Err("invalid WSS front: URL may not contain userinfo, a query, or a fragment".into());
    }
    // The url crate silently drops an explicit default port (`:443`), while
    // Go rejects any explicit port (`parsed.Port() != ""`). Inspect the raw
    // authority for a colon; bracketed IPv6 literals (also containing ':')
    // are rejected later by the DNS-name check either way.
    let after_scheme = raw
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(raw);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    if authority.contains(':') {
        return Err("invalid WSS front: URL must use the default WSS port".into());
    }
    if parsed.port().is_some() {
        return Err("invalid WSS front: URL must use the default WSS port".into());
    }
    let host = host.to_lowercase();
    let ip_ok = host.parse::<std::net::IpAddr>().is_ok();
    if ip_ok || !valid_front_dns_name(&host) {
        return Err(
            "invalid WSS front: URL host must be a CDN DNS name, not an IP literal".into(),
        );
    }
    // Escaped-path rejection: the url crate keeps percent-encoding in the
    // serialized path, so an exact comparison against the bridge path rejects
    // escapes the same way Go's `RawPath != ""` check does.
    if parsed.path() != BRIDGE_PATH {
        return Err(format!(
            "invalid WSS front: URL path must be {BRIDGE_PATH}"
        ));
    }
    Ok(format!("wss://{host}{BRIDGE_PATH}"))
}

/// `wsscore.ValidateFrontURL` (front.go:117): requires a production front URL
/// to be both valid and already canonical, so a dial never silently changes a
/// URL covered by a relay signature and ticket response.
pub fn validate_front_url(raw: &str) -> Result<(), String> {
    let normalized = normalize_front_url(raw)?;
    if normalized != raw {
        return Err("invalid WSS front: URL is not canonical".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Front set (wsscore/front.go NormalizeFronts)
// ---------------------------------------------------------------------------

/// `wsscore.NormalizeFronts` (front.go:16): validates, canonicalizes, and
/// sorts a complete advertised front set. IDs and URLs are unique after
/// normalization.
pub fn normalize_fronts(fronts: &[WssFront]) -> Result<Vec<WssFront>, String> {
    if fronts.is_empty() {
        return Ok(Vec::new());
    }
    if fronts.len() > MAX_FRONTS {
        return Err(format!(
            "invalid WSS front: at most {MAX_FRONTS} fronts are allowed"
        ));
    }
    let mut normalized = Vec::with_capacity(fronts.len());
    for (index, front) in fronts.iter().enumerate() {
        let id = normalize_front_id(&front.id)
            .map_err(|e| format!("invalid WSS front: front {index} ID: {e}"))?;
        if front.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "invalid WSS front: front \"{id}\" protocol_version must be \
                 {PROTOCOL_VERSION}"
            ));
        }
        let url = normalize_front_url(&front.url)
            .map_err(|e| format!("invalid WSS front: front \"{id}\" URL: {e}"))?;
        normalized.push(WssFront {
            id,
            url,
            protocol_version: PROTOCOL_VERSION,
        });
    }
    normalized.sort_by(|a, b| a.id.cmp(&b.id));
    let mut seen_urls = std::collections::HashSet::new();
    for (index, front) in normalized.iter().enumerate() {
        if index > 0 && normalized[index - 1].id == front.id {
            return Err(format!(
                "invalid WSS front: duplicate front ID \"{}\"",
                front.id
            ));
        }
        if !seen_urls.insert(front.url.clone()) {
            return Err("invalid WSS front: duplicate front URL".into());
        }
    }
    Ok(normalized)
}

/// Eligibility gate for one relay's advertised fronts — a port of
/// `connectcore.supportedWSSFronts` (connectcore/wss.go:134): fronts are only
/// usable on a direct-mode, direct-exit, Foundation-class relay at public port
/// 443, and the signed entries must already be canonical by wsscore's rules
/// and in canonical order; anything else is rejected rather than repaired.
///
/// `relay` is the generic descriptor slice the caller needs (`node_class`,
/// `exit_mode`, `transport`, `public_port`, fronts). Kept as free arguments so
/// both the OpenRung import path and the vless runtime can share it without a
/// dependency on the decoded relay type.
pub fn relay_eligible_for_wss(
    node_class: &str, exit_mode: &str, transport: &str, public_port: i64,
) -> bool {
    let transport = transport.trim().to_lowercase();
    let transport = if transport.is_empty() { "direct".to_string() } else { transport };
    transport == "direct"
        && node_class == "foundation"
        && exit_mode == "direct"
        && public_port == 443
}

/// `supportedWSSFronts` body: given the eligibility inputs and the raw signed
/// fronts, return the usable front list (empty when ineligible or
/// non-canonical — never a repaired set).
pub fn supported_wss_fronts(
    node_class: &str, exit_mode: &str, transport: &str, public_port: i64,
    fronts: &[WssFront],
) -> Vec<WssFront> {
    if !relay_eligible_for_wss(node_class, exit_mode, transport, public_port) {
        return Vec::new();
    }
    match normalize_fronts(fronts) {
        Ok(normalized) if normalized == fronts => normalized,
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// WebSocket byte stream (wsscore/websocket_conn.go)
// ---------------------------------------------------------------------------
//
// Consecutive binary WebSocket messages presented as one opaque byte stream,
// exactly like Go's `wsscore.WebSocketConn`:
//
// - binary messages only; a text message fails closed (Go answers with close
//   code 1003 and aborts);
// - message fragmentation (FIN=0 continuation frames) is transparent — the
//   payloads are concatenated into the stream;
// - server frames must be unmasked, client frames are always masked;
// - per-message read limit of 1 MiB (wsscore DefaultWebSocketReadMax);
// - pings are answered inline; pongs ignored; close frames abort the stream;
// - no compression extension is ever requested or accepted.
//
// The inner stream uses tokio's AsyncRead/AsyncWrite (tokio-boring TLS,
// tokio TcpStream); the outer impls use futures' traits because that is what
// the `yamux` crate consumes. All decode state lives on the struct, so a
// dropped poll (select! cancellation) never loses bytes.

use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

/// wsscore `DefaultWebSocketReadMax` (1 MiB) — reject oversized messages.
const DEFAULT_WS_READ_MAX: u64 = 1 << 20;

const WS_OP_CONT: u8 = 0x0;
const WS_OP_BINARY: u8 = 0x2;
const WS_OP_CLOSE: u8 = 0x8;
const WS_OP_PING: u8 = 0x9;
const WS_OP_PONG: u8 = 0xA;

/// TLS stream toward the CDN front (or plain TCP in mock-front tests).
pub(crate) enum FrontTlsStream {
    /// Ordinary-SNI TLS dial (crate::outbound::common::AsyncTlsStream).
    Fragmented(crate::outbound::common::AsyncTlsStream),
    /// No-SNI TLS dial: the certificate is still verified against the exact
    /// front hostname, but no SNI extension is sent (wsscore NativeFrontNoSNI).
    NoSni(tokio_boring::SslStream<tokio::net::TcpStream>),
    /// Plain TCP — mock-front tests only.
    PlainTcp(tokio::net::TcpStream),
}

impl tokio::io::AsyncRead for FrontTlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            FrontTlsStream::Fragmented(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            FrontTlsStream::NoSni(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            FrontTlsStream::PlainTcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for FrontTlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>, buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            FrontTlsStream::Fragmented(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            FrontTlsStream::NoSni(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            FrontTlsStream::PlainTcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            FrontTlsStream::Fragmented(s) => std::pin::Pin::new(s).poll_flush(cx),
            FrontTlsStream::NoSni(s) => std::pin::Pin::new(s).poll_flush(cx),
            FrontTlsStream::PlainTcp(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            FrontTlsStream::Fragmented(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            FrontTlsStream::NoSni(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            FrontTlsStream::PlainTcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Perform the strict WSS HTTP upgrade and return the byte stream.
///
/// Requires HTTP 101 with `Upgrade: websocket` and a matching
/// `Sec-WebSocket-Accept` (gorilla-grade validation), rejects any
/// `Sec-WebSocket-Extensions` in the response (compression must never be
/// negotiated), and requires the negotiated `Sec-WebSocket-Protocol` to be
/// exactly [`SUBPROTOCOL`]. The ticket travels ONLY in the
/// `Authorization: Bearer` header — never in the URL, query, cookies, or
/// subprotocol (docs/wss-fallback.md, ticket protocol).
pub(crate) async fn upgrade_wss<T>(
    inner: T, front_url: &url::Url, ticket: &str,
) -> std::io::Result<WsByteStream<T>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    use base64::Engine as _;

    if ticket.is_empty() || ticket.len() > MAX_TICKET_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "WSS ticket is missing or oversized",
        ));
    }
    if ticket.contains(['\r', '\n']) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "WSS ticket contains control characters",
        ));
    }

    let host = front_url.host_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "front URL has no host")
    })?;
    let path = if front_url.path().is_empty() {
        BRIDGE_PATH
    } else {
        front_url.path()
    };

    let key_bytes: [u8; 16] = rand_bytes();
    let key = base64::engine::general_purpose::STANDARD.encode(&key_bytes);

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\
         Authorization: {TICKET_BEARER_PREFIX}{ticket}\r\n\
         \r\n"
    );
    let mut inner = inner;
    inner.write_all(request.as_bytes()).await?;
    inner.flush().await?;

    let status_line = crate::transport::ws::read_line_async(&mut inner).await?;
    let code = crate::transport::ws::parse_status_line(&status_line)?;
    if code != 101 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("wss upgrade: expected 101, got {code}"),
        ));
    }
    let mut got_upgrade = false;
    let mut got_accept = false;
    let mut got_extensions = false;
    let mut negotiated_protocol: Option<String> = None;
    loop {
        let line = crate::transport::ws::read_line_async(&mut inner).await?;
        if line.is_empty() {
            break;
        }
        if let Some(val) = crate::transport::ws::header_value(&line, "upgrade") {
            if val.eq_ignore_ascii_case("websocket") {
                got_upgrade = true;
            }
        }
        if let Some(val) =
            crate::transport::ws::header_value(&line, "sec-websocket-accept")
        {
            if val == crate::transport::ws::compute_accept(&key) {
                got_accept = true;
            }
        }
        if crate::transport::ws::header_value(&line, "sec-websocket-extensions")
            .is_some()
        {
            got_extensions = true;
        }
        if let Some(val) =
            crate::transport::ws::header_value(&line, "sec-websocket-protocol")
        {
            negotiated_protocol = Some(val.to_string());
        }
    }
    if !got_upgrade {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "wss upgrade: missing Upgrade: websocket header",
        ));
    }
    if !got_accept {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "wss upgrade: Sec-WebSocket-Accept mismatch",
        ));
    }
    if got_extensions {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "wss upgrade: extensions were unexpectedly negotiated",
        ));
    }
    if negotiated_protocol.as_deref() != Some(SUBPROTOCOL) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "wss upgrade: required subprotocol was not negotiated",
        ));
    }
    Ok(WsByteStream::new(inner))
}

/// Byte-stream adapter over WebSocket binary frames — the transport half of
/// Go's `wsscore.WebSocketConn`.
pub(crate) struct WsByteStream<T> {
    inner: T,
    /// Decoded data-frame payload bytes not yet consumed by the reader.
    pending: Vec<u8>,
    /// Raw bytes read from the inner stream, not yet parsed into frames.
    raw: Vec<u8>,
    /// Parse offset into `raw`.
    raw_pos: usize,
    /// True while consuming the current frame's payload bytes.
    in_payload: bool,
    /// Current frame is a control frame (its payload never reaches the
    /// stream).
    cur_control: bool,
    /// Current control frame is a ping (a pong is queued once drained).
    cur_ping: bool,
    /// Current frame FIN flag.
    cur_fin: bool,
    /// Current frame opcode.
    cur_opcode: u8,
    /// Payload bytes of the current frame left to read.
    payload_left: u64,
    /// Bytes accumulated in the current message (read-limit accounting).
    msg_bytes: u64,
    /// Outgoing control bytes (pongs / close), flushed lazily.
    ctrl_out: Vec<u8>,
    ctrl_pos: usize,
    /// Close-frame payload captured so far (status code + reason), for
    /// diagnostics when the peer closes the session.
    close_buf: Vec<u8>,
    /// Outgoing data frame, written across polls.
    out: Option<Vec<u8>>,
    out_pos: usize,
    closed: bool,
}

impl<T> WsByteStream<T> {
    fn new(inner: T) -> Self {
        WsByteStream {
            inner,
            pending: Vec::new(),
            raw: Vec::with_capacity(16 * 1024),
            raw_pos: 0,
            in_payload: false,
            cur_control: false,
            cur_ping: false,
            cur_fin: true,
            cur_opcode: 0,
            payload_left: 0,
            msg_bytes: 0,
            ctrl_out: Vec::new(),
            ctrl_pos: 0,
            close_buf: Vec::new(),
            out: None,
            out_pos: 0,
            closed: false,
        }
    }
}

/// Read from `inner` into `raw` (after compaction) — at most one inner read
/// per poll, so the waker is registered on every Pending return.
fn poll_fill_raw<T: tokio::io::AsyncRead + Unpin>(
    inner: &mut T, cx: &mut Context<'_>, raw: &mut Vec<u8>,
) -> Poll<futures_util::io::Result<usize>> {
    let mut chunk = [0u8; 16 * 1024];
    let mut rb = tokio::io::ReadBuf::new(&mut chunk);
    match std::pin::Pin::new(&mut *inner).poll_read(cx, &mut rb) {
        Poll::Ready(Ok(())) => {
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "wss: peer closed mid-frame",
                )));
            }
            raw.extend_from_slice(rb.filled());
            Poll::Ready(Ok(n))
        },
        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
        Poll::Pending => Poll::Pending,
    }
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>
    WsByteStream<T>
{
    /// Try to flush buffered control bytes (pongs). Ready(()) when nothing
    /// is buffered or everything was written.
    fn poll_flush_ctrl(
        &mut self, cx: &mut Context<'_>,
    ) -> Poll<futures_util::io::Result<()>> {
        if self.ctrl_pos < self.ctrl_out.len() {
            match poll_write_all_from(
                &mut self.inner, cx, &self.ctrl_out, &mut self.ctrl_pos,
            ) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.ctrl_out.clear();
        self.ctrl_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Decode frames until at least one data-frame payload byte is available
    /// in `self.pending`. Returns Ready(()) only when `pending` is non-empty;
    /// Pending only when the inner stream would block (waker registered) —
    /// buffered-but-unparsed bytes are always consumed before parking, so no
    /// readiness event is ever missed.
    fn poll_decode(&mut self, cx: &mut Context<'_>) -> Poll<futures_util::io::Result<()>> {
        loop {
            let need_more = 'parse: {
                if !self.in_payload {
                    // ---- frame header ----
                    let avail = self.raw.len() - self.raw_pos;
                    if avail < 2 {
                        break 'parse true;
                    }
                    let b0 = self.raw[self.raw_pos];
                    let b1 = self.raw[self.raw_pos + 1];
                    let opcode = b0 & 0x0F;
                    let fin = (b0 & 0x80) != 0;
                    let masked = (b1 & 0x80) != 0;
                    let len7 = (b1 & 0x7F) as u64;
                    if b0 & 0x70 != 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "wss: RSV bits set although no extension was negotiated",
                        )));
                    }
                    if masked {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "wss: server frames must not be masked",
                        )));
                    }
                    let is_control = opcode & 0x8 != 0;
                    let need_ext: usize = match len7 {
                        126 => 2,
                        127 => 8,
                        _ => 0,
                    };
                    if is_control && (len7 > 125 || need_ext != 0) {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "wss: control frame payload exceeds 125 bytes",
                        )));
                    }
                    if avail < 2 + need_ext {
                        break 'parse true;
                    }
                    let payload_len: u64 = if need_ext == 0 {
                        len7
                    } else {
                        let ext =
                            &self.raw[self.raw_pos + 2..self.raw_pos + 2 + need_ext];
                        match need_ext {
                            2 => u16::from_be_bytes([ext[0], ext[1]]) as u64,
                            _ => u64::from_be_bytes([
                                ext[0], ext[1], ext[2], ext[3], ext[4], ext[5],
                                ext[6], ext[7],
                            ]),
                        }
                    };
                    self.raw_pos += 2 + need_ext;

                    self.cur_control = is_control;
                    self.cur_ping = is_control && opcode == WS_OP_PING;
                    self.cur_fin = fin;
                    self.cur_opcode = opcode;
                    self.payload_left = payload_len;
                    self.in_payload = true;

                    if is_control {
                        // CLOSE is consumed like any control frame (below)
                        // so the status code can be reported; the error is
                        // raised once the frame is fully read.
                        if opcode != WS_OP_CLOSE
                            && opcode != WS_OP_PING
                            && opcode != WS_OP_PONG
                        {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("wss: unsupported control opcode {opcode:#x}"),
                            )));
                        }
                    } else {
                        let is_new = opcode == WS_OP_BINARY;
                        let is_cont = opcode == WS_OP_CONT;
                        if !is_new && !is_cont {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "wss: WSS transport accepts binary WebSocket \
                                 messages only",
                            )));
                        }
                        if is_new {
                            self.msg_bytes = 0;
                        }
                        if self.msg_bytes + payload_len > DEFAULT_WS_READ_MAX {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "wss: WebSocket message exceeds the read limit",
                            )));
                        }
                        self.msg_bytes += payload_len;
                    }
                    break 'parse false;
                }

                // ---- frame payload ----
                if self.payload_left > 0 {
                    let avail = (self.raw.len() - self.raw_pos) as u64;
                    if avail == 0 {
                        break 'parse true;
                    }
                    let take = self.payload_left.min(avail) as usize;
                    if self.cur_control {
                        if self.cur_opcode == WS_OP_CLOSE && self.close_buf.len() < 2 {
                            // Close status code = first 2 payload bytes
                            // (network order); the remainder is the reason.
                            self.close_buf
                                .extend_from_slice(&self.raw[self.raw_pos..self.raw_pos + take]);
                        }
                    } else {
                        self.pending
                            .extend_from_slice(&self.raw[self.raw_pos..self.raw_pos + take]);
                    }
                    self.raw_pos += take;
                    self.payload_left -= take as u64;
                    if self.payload_left > 0 {
                        break 'parse true;
                    }
                }
                // frame fully consumed
                self.in_payload = false;
                if self.cur_control && self.cur_opcode == WS_OP_CLOSE {
                    let code = if self.close_buf.len() >= 2 {
                        u16::from_be_bytes([self.close_buf[0], self.close_buf[1]])
                    } else {
                        0
                    };
                    log::info!(
                        "wss: peer sent close frame (code {code}{})",
                        if code == 1000 || code == 1001 {
                            String::new()
                        } else {
                            " — non-normal closure".to_string()
                        },
                    );
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        format!("wss: received close frame (code {code})"),
                    )));
                }
                if self.cur_control && self.cur_ping {
                    // Queue the pong. gorilla echoes the ping payload; an
                    // empty pong is RFC-legal and satisfies the sidecar's
                    // keepalive. Flush it eagerly (gorilla answers from its
                    // read pump): during download-heavy phases the relay's
                    // next write may be seconds away, and a pong parked
                    // behind it trips the peer's ping timeout — observed as
                    // sessions closed every few seconds.
                    let pong = crate::transport::ws::encode_frame(WS_OP_PONG, &[]);
                    self.ctrl_out.extend_from_slice(&pong);
                    if self.ctrl_pos < self.ctrl_out.len() {
                        let _ = self.poll_flush_ctrl(cx);
                    }
                }
                if !self.cur_control {
                    if self.cur_fin {
                        self.msg_bytes = 0;
                    }
                    if !self.pending.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                }
                break 'parse false;
            };

            if need_more {
                // Compact consumed bytes, then read once. Ready = progress,
                // re-parse what arrived; Pending = inner blocked, and the
                // waker is now registered — safe to park.
                if self.raw_pos == self.raw.len() {
                    self.raw.clear();
                    self.raw_pos = 0;
                } else if self.raw_pos > 0 {
                    self.raw.drain(..self.raw_pos);
                    self.raw_pos = 0;
                }
                match poll_fill_raw(&mut self.inner, cx, &mut self.raw)? {
                    Poll::Ready(_) => continue,
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>
    futures_util::io::AsyncRead for WsByteStream<T>
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>, buf: &mut [u8],
    ) -> Poll<futures_util::io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Outgoing pongs first: they are small and must not starve behind
        // data writes.
        match this.poll_flush_ctrl(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        loop {
            if this.pending.is_empty() {
                match this.poll_decode(cx) {
                    Poll::Ready(Ok(())) => {},
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                if this.pending.is_empty() {
                    return Poll::Pending;
                }
            }
            let n = buf.len().min(this.pending.len());
            buf[..n].copy_from_slice(&this.pending[..n]);
            this.pending.drain(..n);
            return Poll::Ready(Ok(n));
        }
    }
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>
    futures_util::io::AsyncWrite for WsByteStream<T>
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>, buf: &[u8],
    ) -> Poll<futures_util::io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "wss: stream closed",
            )));
        }
        if buf.is_empty() {
            // Empty binary messages carry no yamux data; never frame them.
            return Poll::Ready(Ok(0));
        }
        loop {
            if this.out.is_none() {
                this.out =
                    Some(crate::transport::ws::encode_frame(WS_OP_BINARY, buf));
                this.out_pos = 0;
            }
            let out = this.out.as_ref().expect("frame buffered");
            match poll_write_all_from(&mut this.inner, cx, out, &mut this.out_pos)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {
                    let n = buf.len();
                    this.out = None;
                    this.out_pos = 0;
                    return Poll::Ready(Ok(n));
                },
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<futures_util::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner)
            .poll_flush(cx)
            .map_err(std::io::Error::into)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<futures_util::io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            let close = crate::transport::ws::encode_frame(WS_OP_CLOSE, &[]);
            match poll_write_all_inner(&mut this.inner, cx, &close) {
                Poll::Ready(Ok(())) => {
                    this.closed = true;
                },
                Poll::Ready(Err(e)) => {
                    this.closed = true;
                    return Poll::Ready(Err(e.into()));
                },
                Poll::Pending => return Poll::Pending,
            }
        }
        std::pin::Pin::new(&mut this.inner)
            .poll_shutdown(cx)
            .map_err(std::io::Error::into)
    }
}

/// Continue an interrupted write of `out` starting at `*pos`.
fn poll_write_all_from<T: tokio::io::AsyncWrite + Unpin>(
    inner: &mut T, cx: &mut Context<'_>, out: &[u8], pos: &mut usize,
) -> Poll<futures_util::io::Result<()>> {
    while *pos < out.len() {
        match std::pin::Pin::new(&mut *inner).poll_write(cx, &out[*pos..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "wss: inner stream accepted zero bytes",
                )));
            },
            Poll::Ready(Ok(n)) => *pos += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

/// Poll-based write_all on the inner stream.
fn poll_write_all_inner<T: tokio::io::AsyncWrite + Unpin>(
    inner: &mut T, cx: &mut Context<'_>, mut data: &[u8],
) -> Poll<std::io::Result<()>> {
    while !data.is_empty() {
        match std::pin::Pin::new(&mut *inner).poll_write(cx, data) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "wss: inner stream accepted zero bytes",
                )));
            },
            Poll::Ready(Ok(n)) => data = &data[n..],
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

/// 16 random bytes for the Sec-WebSocket-Key (crypto-quality, matching
/// gorilla's nonce generation).
fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("system RNG");
    out
}

// ---------------------------------------------------------------------------
// Yamux session + loopback bridge (wsscore/transport.go, client.go Serve)
// ---------------------------------------------------------------------------
//
// The sidecar runs a yamux SERVER session over the WebSocket byte stream and
// dials its fixed 127.0.0.1:443 Reality listener once per stream. The client
// (here) runs the yamux CLIENT session: one yamux stream carries one
// complete, unmodified VLESS + Reality + Vision byte stream.
//
// anywhere mirrors the Go client's loopback-bridge architecture instead of
// feeding yamux streams into the VLESS code directly: the bridge accepts
// local TCP connections on 127.0.0.1 and copies them opaquely into yamux
// streams, so the existing REALITY (and Vision Direct-splice) code runs
// against the bridge exactly like sing-box does behind wsscore's bridge.

/// wsscore's yamux profile (transport.go:13): 256 KiB stream windows
/// (the yamux spec default, also this crate's DEFAULT_CREDIT), 256 backlog
/// (MAX_ACK_BACKLOG), keepalive at the relay side. The rust client does not
/// send its own keepalive pings (see the module doc deviations); the sidecar
/// pings every 15 s and tears the session down when a ping goes unanswered,
/// which both detects dead paths and keeps the CDN connection warm.
pub(crate) fn yamux_config() -> yamux::Config {
    yamux::Config::default()
}

/// wsscore `DefaultStreamIdleTimeout` — opaque-copy idle deadline, refreshed
/// on activity in either direction (CopyOpaque's shared SetDeadline).
pub(crate) const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// wsscore `DefaultMaxConcurrentStreams` — per-session stream cap on the
/// client bridge.
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 128;

/// wsscore `DefaultSessionLifetime` — every session is closed after this
/// bound even if continuously active.
pub(crate) const SESSION_LIFETIME: Duration = Duration::from_secs(6 * 60 * 60);

/// wsscore `DefaultHandshakeTimeout` — bounded TLS + WebSocket handshake.
pub(crate) const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// yamux `StreamOpenTimeout` (transport.go:20) — enforced at the open call
/// site because the rust crate does not implement it.
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// One established WSS front session with its local bridge.
pub(crate) struct WssFrontSession {
    /// Loopback bridge address: `host:port` to point the vless outbound's
    /// REALITY transport at.
    pub bridge_addr: std::net::SocketAddr,
    /// Ticket-lifetime stream budget. The bridge accept loop decrements it
    /// for every opened yamux stream; the owner must stop feeding the
    /// session once it hits zero — the sidecar closes the session (and every
    /// in-flight stream) the moment one more stream arrives.
    streams_left: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    // Load-bearing even when never read: holding this sender keeps the
    // driver's open-request channel open for the bridge's accept loop.
    #[allow(dead_code)]
    open_tx: tokio::sync::mpsc::Sender<
        tokio::sync::oneshot::Sender<yamux::Result<yamux::Stream>>,
    >,
    death: tokio::sync::watch::Receiver<bool>,
    // Keep the accept loop alive as long as the session lives.
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl WssFrontSession {
    /// True once the yamux session (and therefore the whole WSS transport)
    /// has ended — the caller must re-run the direct-first ladder.
    pub fn is_dead(&self) -> bool {
        *self.death.borrow()
    }

    /// Remaining ticket-lifetime stream budget. Zero means the session must
    /// not be fed any new stream: rotate to a fresh session while the
    /// in-flight streams on this one keep running.
    pub fn budget_left(&self) -> usize {
        self.streams_left
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Establish one WSS session to `front_url` carrying `ticket`:
///
/// 1. validate the front URL (wsscore ValidateFrontURL — canonical only);
/// 2. TLS to the CDN front (no SNI for native one-label cloudfront/bunny
///    names when `native_no_sni`, ordinary SNI otherwise) — or a plain TCP
///    dial when `plain` (mock-front tests / cleartext development);
/// 3. strict WebSocket upgrade with the ticket in `Authorization`;
/// 4. yamux client session over the byte stream;
/// 5. local loopback bridge: every accepted TCP connection is copied
///    opaquely into one yamux stream.
///
/// `handshake_timeout` bounds DNS + TCP + TLS + WS upgrade.
pub(crate) async fn establish_wss_session(
    front_url: &str, ticket: &str, max_streams: usize,
    handshake_timeout: Duration, native_no_sni: bool, plain: bool,
) -> Result<WssFrontSession, String> {
    // 1. Canonical URL check (DialClient's first act). The plain-TCP path is
    // a mock-front/test channel: it may address 127.0.0.1:port directly.
    if !plain {
        validate_front_url(front_url)?;
    }
    let parsed = url::Url::parse(front_url)
        .map_err(|e| format!("wss: parse front URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "wss: front URL has no host".to_string())?
        .to_string();

    // 2. TLS (or plain TCP) to the front, inside the handshake budget.
    let started = tokio::time::Instant::now();
    let tls: FrontTlsStream = if plain {
        let port = parsed.port_or_known_default().unwrap_or(443);
        let addr = resolve_front_addr(&host, port).await?;
        let tcp = crate::outbound::common::connect_tcp_bypass(addr)
            .await
            .map_err(|e| format!("wss: TCP connect {addr}: {e}"))?;
        FrontTlsStream::PlainTcp(tcp)
    } else {
        connect_front_tls(&host, native_no_sni).await?
    };
    log::debug!(
        "wss: front TLS established in {:?}",
        started.elapsed()
    );

    // 3. Strict WS upgrade, still inside the handshake budget.
    let wsb = tokio::time::timeout_at(
        started + handshake_timeout,
        upgrade_wss(tls, &parsed, ticket),
    )
    .await
    .map_err(|_| "wss: handshake timeout".to_string())?
    .map_err(|e| format!("wss: upgrade {host}: {e}"))?;

    // 4. yamux client session.
    let mut conn = yamux::Connection::new(wsb, yamux_config(), yamux::Mode::Client);

    // 5. Driver + bridge.
    let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<
        tokio::sync::oneshot::Sender<yamux::Result<yamux::Stream>>,
    >(32);
    let (death_tx, death_rx) = tokio::sync::watch::channel(false);
    let mut death_rx_bridge = death_rx.clone();

    let driver = tokio::spawn(async move {
        let lifetime = tokio::time::sleep(SESSION_LIFETIME);
        tokio::pin!(lifetime);
        loop {
            tokio::select! {
                _ = &mut lifetime => {
                    log::debug!("wss: session lifetime elapsed");
                    break;
                },
                inbound = std::future::poll_fn(|cx| conn.poll_next_inbound(cx)) => {
                    match inbound {
                        // The sidecar never opens streams; drop any it does.
                        Some(Ok(_stream)) => {},
                        Some(Err(e)) => {
                            log::debug!("wss: yamux session ended: {e}");
                            break;
                        },
                        None => {
                            log::debug!("wss: yamux session closed");
                            break;
                        },
                    }
                },
                req = open_rx.recv() => match req {
                    None => break,
                    Some(tx) => {
                        let opened = std::future::poll_fn(|cx| {
                            conn.poll_new_outbound(cx)
                        })
                        .await;
                        let _ = tx.send(opened);
                    },
                },
            }
        }
        let _ = death_tx.send(true);
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("wss: bind local bridge: {e}"))?;
    let bridge_addr = listener
        .local_addr()
        .map_err(|e| format!("wss: bridge local addr: {e}"))?;

    let open_tx_for_bridge = open_tx.clone();
    let streams_left = Arc::new(std::sync::atomic::AtomicUsize::new(
        max_streams,
    ));
    let streams_left_for_accept = streams_left.clone();
    let accept = tokio::spawn(async move {
        let open_tx = open_tx_for_bridge;
        let streams_left = streams_left_for_accept;
        let slots = Arc::new(tokio::sync::Semaphore::new(
            MAX_CONCURRENT_STREAMS,
        ));
        loop {
            tokio::select! {
                _ = death_rx_bridge.changed() => break,
                accepted = listener.accept() => {
                    let Ok((tcp, _peer)) = accepted else {
                        break;
                    };
                    // Concurrency cap: a stream offered beyond the cap is
                    // dropped (Serve closes local connections without slots).
                    let Ok(permit) = slots.clone().try_acquire_owned() else {
                        continue;
                    };
                    // Ticket-lifetime budget accounting: the sidecar closes
                    // the whole session (in-flight streams included) the
                    // moment one more stream arrives after exhaustion, so
                    // every accepted connection burns exactly one unit.
                    let prev = streams_left.fetch_sub(
                        1, std::sync::atomic::Ordering::Relaxed,
                    );
                    if prev == 0 {
                        log::warn!(
                            "wss: ticket stream budget exhausted; closing \
                             the session before the sidecar does"
                        );
                        // Reject the connection and tear the session down
                        // ourselves — cleaner than letting the sidecar kill
                        // every in-flight stream.
                        drop(tcp);
                        drop(permit);
                        break;
                    }
                    let open_tx = open_tx.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let (otx, orx) = tokio::sync::oneshot::channel();
                        if open_tx.send(otx).await.is_err() {
                            return;
                        }
                        let stream = match tokio::time::timeout(
                            STREAM_OPEN_TIMEOUT, orx,
                        ).await {
                            Ok(Ok(Ok(s))) => s,
                            Ok(Ok(Err(e))) => {
                                log::debug!("wss: open stream failed: {e}");
                                return;
                            },
                            _ => {
                                log::debug!("wss: open stream timed out");
                                return;
                            },
                        };
                        copy_opaque(tcp, stream, STREAM_IDLE_TIMEOUT).await;
                    });
                },
            }
        }
        // Draining: a session whose budget ran out (or whose transport died)
        // must stop accepting, but in-flight streams may keep running until
        // the sidecar's idle timeout reaps the connection.
        drop(listener);
    });

    Ok(WssFrontSession {
        bridge_addr,
        streams_left,
        open_tx,
        death: death_rx,
        _tasks: vec![driver, accept],
    })
}

/// Resolve the front hostname for a bypass dial.
///
/// The resolution itself must also escape the engine: while the TUN DNS
/// hijack is up, the system resolver answers with fake-ip (198.18.0.0/15)
/// for non-CN CDN names, and a bypass TCP dial toward that fake address
/// leaves the physical interface toward a bogon and blackholes.
/// [`resolve_bypass`] queries the direct upstreams through a bypass-bound
/// socket instead, so the answer is the CDN's real address.
async fn resolve_front_addr(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    crate::outbound::common::resolve_bypass(host, port)
        .await
        .map_err(|e| format!("wss: DNS resolution failed for {host}: {e}"))
}

/// TLS to the CDN front. Ordinary SNI by default; `native_no_sni` omits the
/// ClientHello SNI for native one-label `*.cloudfront.net` / `*.b-cdn.net`
/// URLs while still verifying the certificate against the exact signed URL
/// hostname (wsscore NativeFrontNoSNI; the Go desktop client enables it).
async fn connect_front_tls(
    host: &str, native_no_sni: bool,
) -> Result<FrontTlsStream, String> {
    let addr = resolve_front_addr(host, 443).await?;
    let tcp = crate::outbound::common::connect_tcp_bypass(addr)
        .await
        .map_err(|e| format!("wss: TCP connect {addr}: {e}"))?;
    let _ = tcp.set_nodelay(true);

    let no_sni_eligible = native_no_sni && native_front_host(host).is_some();
    if no_sni_eligible {
        tls_no_sni(tcp, host)
            .await
            .map(FrontTlsStream::NoSni)
            .map_err(|e| format!("wss: TLS handshake {host} (no SNI): {e}"))
    } else {
        crate::outbound::common::create_tls_stream_async(
            tcp, host, false, false, None, &crate::ech::EchOffer::None,
        )
        .await
        .map(FrontTlsStream::Fragmented)
        .map_err(|e| format!("wss: TLS handshake {host}: {e}"))
    }
}

/// wsscore `nativeFrontHost` (nosni_tls.go): a one-label URL under a
/// recognized CDN zone returns the full signed host (the name the
/// certificate must verify against); anything else returns None.
pub(crate) fn native_front_host(host: &str) -> Option<&'static str> {
    const ZONES: [&str; 2] = [".cloudfront.net", ".b-cdn.net"];
    for zone in ZONES {
        if let Some(rest) = host.strip_suffix(zone) {
            // one label in `rest` (no dots) and non-empty
            if !rest.is_empty() && !rest.contains('.') {
                return Some("cloudfront");
            }
        }
    }
    None
}

/// TLS handshake without SNI but WITH hostname verification
/// (wsscore nosni_tls.go): boring derives SNI from the connect hostname, so
/// the SSL object is built manually — verify param set to the front host,
/// `set_hostname` never called. TLS 1.2+ is BoringSSL's client default for
/// verification-enabled contexts.
async fn tls_no_sni(
    tcp: tokio::net::TcpStream, verify_host: &str,
) -> std::io::Result<tokio_boring::SslStream<tokio::net::TcpStream>> {
    use boring::x509::verify::X509CheckFlags;
    let mut builder =
        boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    builder
        .set_default_verify_paths()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let ctx = builder.build();
    let mut ssl = boring::ssl::Ssl::new(&ctx)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    {
        let param = ssl.param_mut();
        param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
        param
            .set_host(verify_host)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }
    tokio_boring::SslStreamBuilder::new(ssl, tcp)
        .connect()
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("no-SNI handshake failed: {e}"),
            )
        })
}

/// wsscore `CopyOpaque` (transport.go:39): copy bytes in both directions
/// without inspecting them; activity in either direction refreshes one
/// shared idle deadline; a read EOF half-closes the other side (CloseWrite
/// on the yamux stream / shutdown on the local TCP socket); completion
/// closes both.
async fn copy_opaque(
    tcp: tokio::net::TcpStream, stream: yamux::Stream, idle: Duration,
) {
    let last = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
        now_millis(),
    ));
    let (tcp_r, tcp_w) = tokio::io::split(tcp);
    let (ys_r, ys_w) = futures_util::io::AsyncReadExt::split(stream);

    let up = pump_tcp_to_yamux(tcp_r, ys_w, idle, last.clone());
    let down = pump_yamux_to_tcp(ys_r, tcp_w, idle, last.clone());
    tokio::join!(up, down);
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn touch(last: &std::sync::Arc<std::sync::atomic::AtomicU64>) {
    last.store(now_millis(), std::sync::atomic::Ordering::Relaxed);
}

/// Uplink: local TCP -> yamux stream. Read EOF closes the yamux write side
/// (FIN half-close, CopyOpaque's CloseWrite); idle or I/O failure aborts.
async fn pump_tcp_to_yamux(
    mut r: tokio::io::ReadHalf<tokio::net::TcpStream>,
    mut w: futures_util::io::WriteHalf<yamux::Stream>, idle: Duration,
    last: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    use futures_util::io::AsyncWriteExt as _;
    use tokio::io::AsyncReadExt as _;
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match tokio::time::timeout(idle, r.read(&mut buf)).await {
            Err(_) => {
                log::debug!("wss: uplink idle timeout");
                return;
            },
            Ok(Err(e)) => {
                log::debug!("wss: uplink read error: {e}");
                return;
            },
            Ok(Ok(0)) => {
                // Half-close: the local side finished writing; signal the
                // peer with a yamux FIN and keep the downlink running.
                let _ = w.close().await;
                return;
            },
            Ok(Ok(n)) => {
                touch(&last);
                match tokio::time::timeout(idle, w.write_all(&buf[..n])).await {
                    Ok(Ok(())) => {
                        if w.flush().await.is_err() {
                            return;
                        }
                        touch(&last);
                    },
                    _ => {
                        log::debug!("wss: uplink write failed/idle");
                        return;
                    },
                }
            },
        }
    }
}

/// Downlink: yamux stream -> local TCP. Read EOF half-closes the local
/// socket (shutdown(Write)); idle or I/O failure aborts.
async fn pump_yamux_to_tcp(
    mut r: futures_util::io::ReadHalf<yamux::Stream>,
    mut w: tokio::io::WriteHalf<tokio::net::TcpStream>, idle: Duration,
    last: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    use tokio::io::AsyncWriteExt as _;
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match tokio::time::timeout(idle, futures_util::io::AsyncReadExt::read(&mut r, &mut buf)).await {
            Err(_) => {
                log::debug!("wss: downlink idle timeout");
                return;
            },
            Ok(Err(e)) => {
                log::debug!("wss: downlink read error: {e}");
                return;
            },
            Ok(Ok(0)) => {
                let _ = w.shutdown().await;
                return;
            },
            Ok(Ok(n)) => {
                touch(&last);
                match tokio::time::timeout(idle, w.write_all(&buf[..n])).await {
                    Ok(Ok(())) => {
                        touch(&last);
                    },
                    _ => {
                        log::debug!("wss: downlink write failed/idle");
                        return;
                    },
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Broker ticket acquisition (brokerapi/wss_ticket.go, connectcore/wss.go)
// ---------------------------------------------------------------------------

/// A broker-issued WSS session ticket.
#[derive(Debug, Clone)]
pub(crate) struct WssTicket {
    pub ticket: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub url: String,
    /// Ticket-lifetime stream budget from the signed claims (`max_streams`).
    /// The sidecar counts every yamux stream ever opened against this — it
    /// is NOT a concurrency cap — and gracefully closes the session the
    /// moment one more stream arrives after exhaustion (sidecar.go:468-475).
    pub max_streams: usize,
}

/// Fallback when the token claims cannot be decoded: the deployed broker
/// issues `max_streams: 64` (verified live), matching
/// wsscore's per-ticket authorization budget.
pub(crate) const DEFAULT_TICKET_MAX_STREAMS: usize = 64;

/// Decode `max_streams` from the opaque ticket token. Format:
/// `v1.<key-id-hex>.<base64url(JSON claims)>`; the claims carry
/// `max_streams`. Anything unexpected → [`DEFAULT_TICKET_MAX_STREAMS`].
fn ticket_max_streams(token: &str) -> usize {
    use base64::Engine as _;
    let Some(claims_b64) = token.split('.').nth(2) else {
        return DEFAULT_TICKET_MAX_STREAMS;
    };
    let Ok(claims) = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims_b64)
    else {
        return DEFAULT_TICKET_MAX_STREAMS;
    };
    serde_json::from_slice::<serde_json::Value>(&claims)
        .ok()
        .and_then(|v| v.get("max_streams")?.as_u64())
        .map(|n| (n as usize).max(1))
        .unwrap_or(DEFAULT_TICKET_MAX_STREAMS)
}

/// `brokerapi.WSSTicketStatusError`: non-2xx with an optional bounded
/// Retry-After.
#[derive(Debug, Clone)]
pub(crate) enum TicketError {
    Status { status: u16, retry_after: Duration },
    Other(String),
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TicketError::Status { status, .. } => {
                write!(f, "WSS ticket request failed with HTTP {status}")
            },
            TicketError::Other(m) => write!(f, "{m}"),
        }
    }
}

/// `wsscore`/`brokerapi` ceilings honored by the client ladder.
pub(crate) const TICKET_ATTEMPT_LIMIT: Duration = Duration::from_secs(5);
pub(crate) const TICKET_TOTAL_DEADLINE: Duration = Duration::from_secs(15);
pub(crate) const TICKET_DEFAULT_RETRY: Duration = Duration::from_secs(10);
pub(crate) const TICKET_MAX_RETRY: Duration = Duration::from_secs(30);

/// `parseRetryAfter` (brokerapi/errors.go:76): a bounded seconds value or a
/// bounded future HTTP-date; anything else (or beyond 24 h) is ignored.
fn parse_retry_after(value: &str, now: chrono::DateTime<chrono::Utc>) -> Duration {
    let value = value.trim();
    if value.is_empty() {
        return Duration::ZERO;
    }
    if let Ok(seconds) = value.parse::<i64>() {
        if !(0..=(24 * 3600)).contains(&seconds) {
            return Duration::ZERO;
        }
        return Duration::from_secs(seconds as u64);
    }
    if let Ok(when) =
        chrono::NaiveDateTime::parse_from_str(value, "%a, %d %b %Y %H:%M:%S GMT")
    {
        let when = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
            when,
            chrono::Utc,
        );
        if when > now {
            let delay = (when - now).to_std().unwrap_or(Duration::ZERO);
            if delay <= Duration::from_secs(24 * 3600) {
                return delay;
            }
        }
    }
    Duration::ZERO
}

/// POST {broker}/api/v1/wss/tickets — one attempt, one endpoint
/// (brokerapi/wss_ticket.go:56). HTTPS is enforced (plain http only to
/// loopback), redirects are never followed (the per-connection hyper setup
/// has no redirect support: a 3xx surfaces as a status error), and the
/// response is bounded and validated.
pub(crate) async fn request_wss_ticket_once(
    broker_base: &str, relay_id: &str, front_id: &str,
) -> Result<WssTicket, TicketError> {
    use hyper::body::Bytes;
    use hyper::Request;
    use hyper_util::rt::TokioIo;

    if relay_id.trim().is_empty() {
        return Err(TicketError::Other("WSS ticket relay_id is required".into()));
    }
    if front_id.trim().is_empty() {
        return Err(TicketError::Other("WSS ticket front_id is required".into()));
    }

    // wss_ticket_url: resolve the endpoint path from the base URL.
    let parsed = crate::openrung::enforce_secure_broker_url(broker_base)
        .map_err(TicketError::Other)?;
    let base_path = parsed.path().trim_matches('/').to_string();
    let endpoint_path = if base_path.is_empty() {
        "/api/v1/wss/tickets".to_string()
    } else {
        format!("/{base_path}/api/v1/wss/tickets")
    };
    let mut endpoint = parsed;
    endpoint.set_path(&endpoint_path);
    endpoint.set_query(None);
    endpoint.set_fragment(None);

    let host = endpoint
        .host_str()
        .ok_or_else(|| TicketError::Other("broker URL has no host".into()))?
        .to_string();
    let port = endpoint.port_or_known_default().unwrap_or(443);
    // Bypass resolution + dial: while the engine runs, the system resolver
    // answers with fake-ip for non-CN broker names and a plain connect is
    // routed back into the tunnel — the ticket request would be steered into
    // the very proxy whose dead direct path triggered this fallback.
    let addr =
        crate::outbound::common::resolve_bypass(&host, port).await.map_err(
            |e| TicketError::Other(format!("DNS resolution failed for {host}: {e}")),
        )?;

    let payload = format!(
        "{{\"relay_id\":{},\"front_id\":{}}}",
        serde_json::to_string(relay_id).unwrap_or_else(|_| "\"\"".into()),
        serde_json::to_string(front_id).unwrap_or_else(|_| "\"\"".into()),
    );

    let tcp = crate::outbound::common::connect_tcp_bypass(addr)
        .await
        .map_err(|e| TicketError::Other(format!("TCP connect {addr}: {e}")))?;
    let _ = tcp.set_nodelay(true);

    let req_body = payload.clone();
    let req = Request::builder()
        .method("POST")
        .uri(endpoint.path())
        .header("Host", host.as_str())
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-cache, no-store")
        .header("Pragma", "no-cache")
        .body(http_body_util::Full::new(Bytes::from(req_body)))
        .map_err(|e| TicketError::Other(format!("build request: {e}")))?;

    // HTTPS is the rule; plain HTTP is the loopback development allowance
    // (enforce_secure_broker_url already rejected non-loopback http).
    if endpoint.scheme() == "https" {
        let tls = tokio::time::timeout(
            Duration::from_secs(15),
            tls_connector_connect(&host, tcp),
        )
        .await
        .map_err(|_| {
            TicketError::Other(format!("TLS handshake timeout ({host})"))
        })?
        .map_err(|e| TicketError::Other(format!("TLS handshake {host}: {e}")))?;
        post_ticket(TokioIo::new(tls), req).await
    } else {
        post_ticket(TokioIo::new(tcp), req).await
    }
}

/// Drive one hyper HTTP/1.1 POST to completion and validate the response
/// shape (brokerapi/wss_ticket.go:96-132).
async fn post_ticket<S>(
    io: hyper_util::rt::TokioIo<S>,
    req: hyper::Request<http_body_util::Full<hyper::body::Bytes>>,
) -> Result<WssTicket, TicketError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use http_body_util::BodyExt;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| TicketError::Other(format!("hyper handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
        .await
        .map_err(|_| TicketError::Other("HTTP response timeout".into()))?
        .map_err(|e| TicketError::Other(format!("send request: {e}")))?;

    let status = resp.status().as_u16();
    let retry_after_header = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if !(200..300).contains(&status) {
        // Redirects and errors: never forwarded anywhere (Go drains the body
        // unread and discards it).
        return Err(TicketError::Status {
            status,
            retry_after: parse_retry_after(
                retry_after_header.as_deref().unwrap_or(""),
                chrono::Utc::now(),
            ),
        });
    }

    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| TicketError::Other(format!("read ticket response: {e}")))?
        .to_bytes();
    if body.len() > 64 * 1024 {
        return Err(TicketError::Other(format!(
            "WSS ticket response exceeds {} bytes",
            64 * 1024
        )));
    }

    #[derive(serde::Deserialize)]
    struct TicketWire {
        ticket: String,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        url: String,
    }
    let wire: TicketWire = serde_json::from_slice(&body)
        .map_err(|_| TicketError::Other("decode WSS ticket response".into()))?;
    // brokerapi/wss_ticket.go:119 checks — size, control characters, expiry.
    if wire.ticket.is_empty()
        || wire.ticket.len() > MAX_TICKET_BYTES
        || wire.ticket.contains(['\r', '\n'])
    {
        return Err(TicketError::Other(
            "WSS ticket response has a missing, oversized, or invalid ticket"
                .into(),
        ));
    }
    let expires_at = wire.expires_at.ok_or_else(|| {
        TicketError::Other("WSS ticket response has no expires_at".into())
    })?;
    if expires_at <= chrono::Utc::now() {
        return Err(TicketError::Other(
            "WSS ticket response is already expired".into(),
        ));
    }
    if wire.url.trim().is_empty() {
        return Err(TicketError::Other(
            "WSS ticket response has no url".into(),
        ));
    }
    Ok(WssTicket {
        max_streams: ticket_max_streams(&wire.ticket),
        ticket: wire.ticket,
        expires_at,
        url: wire.url,
    })
}

/// TLS connect for the ticket request (rustls + webpki roots, like the
/// broker directory fetch).
async fn tls_connector_connect(
    host: &str, tcp: tokio::net::TcpStream,
) -> Result<
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    std::io::Error,
> {
    use tokio_rustls::rustls::pki_types::ServerName;
    let provider = tokio_rustls::rustls::crypto::ring::default_provider();
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(
        std::sync::Arc::new(provider),
    )
    .with_safe_default_protocol_versions()
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("TLS config: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("invalid server name '{host}': {e}")))?;
    connector.connect(server_name, tcp).await
}

/// The broker-front ladder (connectcore/wss.go:212 requestWSSSessionTicket):
/// the recorded broker base first, then the built-in discovery fronts
/// (deduplicated); attempts shrink to the remaining shared budget; a valid
/// 429/503 Retry-After buys exactly one retry round, clamped and only when
/// the wait fits the budget; the first error wins.
pub(crate) async fn request_wss_session_ticket(
    broker_base: &str, relay_id: &str, front_id: &str, budget: Duration,
) -> Result<WssTicket, TicketError> {
    let mut fronts: Vec<String> = Vec::new();
    let mut push = |f: &str| {
        let f = f.trim();
        if !f.is_empty() && !fronts.iter().any(|x| x == f) {
            fronts.push(f.to_string());
        }
    };
    push(broker_base);
    for f in crate::openrung::DEFAULT_BROKER_URLS {
        push(f);
    }
    if fronts.is_empty() {
        return Err(TicketError::Other(
            "no HTTPS broker fronts configured for WSS ticket".into(),
        ));
    }

    let deadline = tokio::time::Instant::now() + budget;
    let mut first_err: Option<TicketError> = None;
    let mut retry_used = false;
    for round in 0..2 {
        let mut retry_after = Duration::ZERO;
        for broker in &fronts {
            let remaining = deadline.saturating_duration_since(
                tokio::time::Instant::now(),
            );
            if remaining.is_zero() {
                return Err(first_err.unwrap_or(TicketError::Other(
                    "WSS ticket request deadline exceeded".into(),
                )));
            }
            let attempt_limit = TICKET_ATTEMPT_LIMIT.min(remaining);
            let attempt = tokio::time::timeout(
                attempt_limit,
                request_wss_ticket_once(broker, relay_id, front_id),
            )
            .await;
            match attempt {
                Ok(Ok(ticket)) => return Ok(ticket),
                Ok(Err(err)) => {
                    if first_err.is_none() {
                        first_err = Some(err.clone());
                    }
                    if let TicketError::Status { status, retry_after: ra } = &err {
                        if (*status == 429 || *status == 503)
                            && *ra > retry_after
                        {
                            retry_after = *ra;
                        } else if *status == 429 || *status == 503 {
                            // no/bogus Retry-After: the default hint applies
                            if retry_after < TICKET_DEFAULT_RETRY {
                                retry_after = TICKET_DEFAULT_RETRY;
                            }
                        }
                    }
                },
                Err(_) => {
                    if first_err.is_none() {
                        first_err = Some(TicketError::Other(format!(
                            "WSS ticket attempt on {broker} timed out"
                        )));
                    }
                },
            }
        }
        if round > 0 || retry_after.is_zero() || retry_used {
            return Err(first_err.unwrap_or(TicketError::Other(
                "WSS ticket request failed".into(),
            )));
        }
        if retry_after > TICKET_MAX_RETRY {
            retry_after = TICKET_MAX_RETRY;
        }
        let remaining =
            deadline.saturating_duration_since(tokio::time::Instant::now());
        if retry_after >= remaining {
            // The wait cannot fit the shared budget: surface the first error
            // now (connectcore/wss.go:283, the strict wait-fits gate).
            return Err(first_err.unwrap_or(TicketError::Other(
                "WSS ticket request deadline exceeded".into(),
            )));
        }
        retry_used = true;
        tokio::time::sleep(retry_after).await;
    }
    Err(first_err.unwrap_or(TicketError::Other(
        "WSS ticket request failed".into(),
    )))
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Shared mock infrastructure: a WSS front + sidecar (plain TCP, the
    //! wire behavior of the relay sidecar minus TLS) and a configurable
    //! ticket broker. Used by the wssfront interop tests and the vless
    //! ladder tests.

    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// The mock computes Accept via the same production function the client
    /// verifies with — a duplicated constant here would let a wrong GUID pass
    /// every mock test while failing every real server (which is exactly what
    /// happened before the transport::ws MAGIC_STRING was fixed).
    pub fn ws_accept(key: &str) -> String {
        crate::transport::ws::compute_accept(key)
    }

    /// Encode an UNMASKED binary frame (server -> client direction).
    pub fn encode_frame_unmasked(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 10);
        out.push(0x82); // FIN=1, binary
        let len = payload.len();
        if len < 126 {
            out.push(len as u8);
        } else if len <= 0xFFFF {
            out.push(126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    /// Decode one masked client frame from the socket; returns the payload.
    pub async fn read_client_frame<R: tokio::io::AsyncRead + Unpin>(
        sock: &mut R,
    ) -> std::io::Result<Vec<u8>> {
        let mut hdr = [0u8; 2];
        sock.read_exact(&mut hdr).await?;
        let len7 = (hdr[1] & 0x7F) as usize;
        let ext = match len7 {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let mut rest = vec![0u8; ext + 4];
        sock.read_exact(&mut rest).await?;
        let payload_len = match ext {
            0 => len7,
            2 => u16::from_be_bytes([rest[0], rest[1]]) as usize,
            _ => u64::from_be_bytes([
                rest[0], rest[1], rest[2], rest[3], rest[4], rest[5],
                rest[6], rest[7],
            ]) as usize,
        };
        let mask = [rest[ext], rest[ext + 1], rest[ext + 2], rest[ext + 3]];
        let mut payload = vec![0u8; payload_len];
        sock.read_exact(&mut payload).await?;
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        Ok(payload)
    }

    /// Mock WSS front + sidecar: validates the upgrade (bridge path,
    /// required subprotocol, bearer ticket), answers 101, then runs a yamux
    /// SERVER session over the binary byte stream and echoes every stream —
    /// the wire behavior of wssbridge's sidecar against a loopback Reality
    /// listener, minus TLS.
    pub async fn spawn_mock_front(
        expect_ticket: &'static str,
    ) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    // --- HTTP upgrade ---
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head_str = String::from_utf8_lossy(&head);
                    let request_line =
                        head_str.lines().next().unwrap_or_default();
                    if !request_line.starts_with("GET /api/v1/wss-bridge ") {
                        let resp =
                            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n";
                        let _ = sock.write_all(resp).await;
                        return;
                    }
                    if !head_str.to_lowercase().contains(
                        "sec-websocket-protocol: openrung-wss-bridge-v1",
                    ) {
                        let resp =
                            b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n";
                        let _ = sock.write_all(resp).await;
                        return;
                    }
                    let want_auth =
                        format!("authorization: bearer {expect_ticket}");
                    if !head_str.to_lowercase().contains(&want_auth) {
                        let resp =
                            b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n";
                        let _ = sock.write_all(resp).await;
                        return;
                    }
                    let key = head_str
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("sec-websocket-key")
                                .then(|| v.trim().to_string())
                        })
                        .unwrap_or_default();
                    let resp = format!(
                        "HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: {}\r\n\
                         Sec-WebSocket-Protocol: openrung-wss-bridge-v1\r\n\
                         \r\n",
                        ws_accept(&key)
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }

                    // --- binary byte stream: client frames in, server
                    //     frames out, yamux server in between ---
                    let (payload_tx, payload_rx) =
                        tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                    let (frame_tx, mut frame_rx) =
                        tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

                    // split once: reader task owns the read half, writer
                    // task owns the write half
                    let (mut sock_r, mut sock_w) = tokio::io::split(sock);
                    let reader = tokio::spawn(async move {
                        loop {
                            match read_client_frame(&mut sock_r).await {
                                Ok(p) => {
                                    if payload_tx.send(p).is_err() {
                                        return;
                                    }
                                },
                                Err(_) => return,
                            }
                        }
                    });

                    // writer: frame yamux output as unmasked binary
                    let writer = tokio::spawn(async move {
                        while let Some(p) = frame_rx.recv().await {
                            if sock_w
                                .write_all(&encode_frame_unmasked(&p))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            let _ = sock_w.flush().await;
                        }
                    });

                    // adapter: decoded payloads in, yamux bytes out
                    struct Adapter {
                        rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
                        buf: Vec<u8>,
                        pos: usize,
                        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
                    }
                    // futures traits: that is what yamux consumes
                    impl futures_util::io::AsyncRead for Adapter {
                        fn poll_read(
                            mut self: std::pin::Pin<&mut Self>,
                            cx: &mut Context<'_>,
                            buf: &mut [u8],
                        ) -> Poll<std::io::Result<usize>> {
                            if buf.is_empty() {
                                return Poll::Ready(Ok(0));
                            }
                            if self.pos >= self.buf.len() {
                                match self.rx.poll_recv(cx) {
                                    Poll::Ready(Some(chunk)) => {
                                        self.buf = chunk;
                                        self.pos = 0;
                                    },
                                    Poll::Ready(None) => {
                                        return Poll::Ready(Ok(0))
                                    },
                                    Poll::Pending => return Poll::Pending,
                                }
                            }
                            let n =
                                buf.len().min(self.buf.len() - self.pos);
                            buf[..n].copy_from_slice(
                                &self.buf[self.pos..self.pos + n],
                            );
                            self.pos += n;
                            Poll::Ready(Ok(n))
                        }
                    }
                    impl futures_util::io::AsyncWrite for Adapter {
                        fn poll_write(
                            self: std::pin::Pin<&mut Self>,
                            _cx: &mut Context<'_>, buf: &[u8],
                        ) -> Poll<std::io::Result<usize>> {
                            if buf.is_empty() {
                                return Poll::Ready(Ok(0));
                            }
                            let this = self.get_mut();
                            if this.tx.send(buf.to_vec()).is_err() {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::BrokenPipe,
                                    "mock front closed",
                                )));
                            }
                            Poll::Ready(Ok(buf.len()))
                        }
                        fn poll_flush(
                            self: std::pin::Pin<&mut Self>,
                            _cx: &mut Context<'_>,
                        ) -> Poll<std::io::Result<()>> {
                            Poll::Ready(Ok(()))
                        }
                        fn poll_close(
                            self: std::pin::Pin<&mut Self>,
                            _cx: &mut Context<'_>,
                        ) -> Poll<std::io::Result<()>> {
                            Poll::Ready(Ok(()))
                        }
                    }

                    let adapter = Adapter {
                        rx: payload_rx,
                        buf: Vec::new(),
                        pos: 0,
                        tx: frame_tx,
                    };
                    let mut server_conn = yamux::Connection::new(
                        adapter,
                        yamux::Config::default(),
                        yamux::Mode::Server,
                    );
                    loop {
                        let inbound = std::future::poll_fn(|cx| {
                            server_conn.poll_next_inbound(cx)
                        })
                        .await;
                        match inbound {
                            Some(Ok(stream)) => {
                                tokio::spawn(async move {
                                    // echo: the sidecar's loopback Reality
                                    // dial copies bytes both ways
                                    use futures_util::io::{
                                        AsyncReadExt as _, AsyncWriteExt as _,
                                    };
                                    let (mut sr, mut sw) =
                                        futures_util::io::AsyncReadExt::split(stream);
                                    let mut buf = vec![0u8; 16 * 1024];
                                    loop {
                                        match sr.read(&mut buf).await {
                                            Ok(0) | Err(_) => break,
                                            Ok(n) => {
                                                if sw
                                                    .write_all(&buf[..n])
                                                    .await
                                                    .is_err()
                                                {
                                                    break;
                                                }
                                            },
                                        }
                                    }
                                });
                            },
                            _ => break,
                        }
                    }
                    reader.abort();
                    writer.abort();
                });
            }
        });
        addr
    }

    /// A loopback ticket broker whose response is chosen per request body:
    /// `route` receives the raw POST body (JSON with relay_id/front_id) and
    /// returns the raw HTTP response bytes.
    pub async fn spawn_mock_broker_router(
        route: impl Fn(Vec<u8>) -> Vec<u8> + Send + 'static,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                // Read the full request (headers + content-length body).
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];
                let mut clen = 0usize;
                loop {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            head.extend_from_slice(&chunk[..n]);
                            let text = String::from_utf8_lossy(&head);
                            if let Some(i) = text.find("content-length:") {
                                let v: String = text[i + 15..]
                                    .chars()
                                    .take_while(|c| c.is_ascii_digit())
                                    .collect();
                                clen = v.parse().unwrap_or(0);
                            }
                            if let Some(i) = text.find("\r\n\r\n") {
                                if head.len() >= i + 4 + clen {
                                    break;
                                }
                            }
                        },
                    }
                }
                let body_start = head
                    .windows(4)
                    .rposition(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(head.len());
                let response = route(head[body_start..].to_vec());
                let _ = sock.write_all(&response).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    /// A loopback HTTP broker answering every POST with `response`.
    pub async fn spawn_mock_broker(response: Vec<u8>) -> String {
        spawn_mock_broker_router(move |_| response.clone()).await
    }

    pub fn http_ok(body: &[u8]) -> Vec<u8> {
        let mut resp = format!(
            "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        resp.extend_from_slice(body);
        resp
    }

    pub fn http_status(status: u16, extra: &[(&str, &str)]) -> Vec<u8> {
        let mut head = format!("HTTP/1.1 {status} X\r\n");
        for (k, v) in extra {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("content-length: 0\r\n\r\n");
        head.into_bytes()
    }

    pub fn ticket_body(
        ticket: &str, expires_in_secs: i64, url: &str,
    ) -> Vec<u8> {
        let exp = chrono::Utc::now()
            + chrono::Duration::seconds(expires_in_secs);
        serde_json::json!({
            "ticket": ticket,
            "expires_at": exp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "url": url,
        })
        .to_string()
        .into_bytes()
    }

    /// Extract `front_id` from a ticket request body.
    pub fn front_id_of(body: &[u8]) -> String {
        serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| {
                v.get("front_id")
                    .and_then(|f| f.as_str().map(|s| s.to_string()))
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::testutil::*;

    /// LIVE stability probe (network, #[ignore] by default): runs the same
    /// scenario as the Go `wssprobe` harness against a real front — one
    /// bridge stream per second with a small write/read — and reports how
    /// long the session survives and what close code the peer sent.
    ///
    /// Run with:
    ///   WSS_PROBE_BROKER WSS_PROBE_RELAY_ID WSS_PROBE_FRONT_ID \
    ///   WSS_PROBE_FRONT_URL cargo test -p anywhere --lib -- --ignored \
    ///   live_wss
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn live_wss_session_stability_probe() {
        let Ok(broker) = std::env::var("WSS_PROBE_BROKER") else {
            return;
        };
        let Ok(relay_id) = std::env::var("WSS_PROBE_RELAY_ID") else {
            return;
        };
        let Ok(front_id) = std::env::var("WSS_PROBE_FRONT_ID") else {
            return;
        };
        let Ok(front_url) = std::env::var("WSS_PROBE_FRONT_URL") else {
            return;
        };
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("debug"),
        )
        .try_init();

        let ticket = request_wss_session_ticket(
            &broker,
            &relay_id,
            &front_id,
            Duration::from_secs(20),
        )
        .await
        .expect("ticket issued");
        assert_eq!(ticket.url, front_url, "ticket must bind the front");
        println!("ticket issued, len {}", ticket.ticket.len());

        let session = establish_wss_session(
            &ticket.url,
            &ticket.ticket,
            64,
            DEFAULT_HANDSHAKE_TIMEOUT,
            true,
            false,
        )
        .await
        .expect("session established");
        let addr = session.bridge_addr;
        println!("session up, bridge {addr}");

        let start = tokio::time::Instant::now();
        let mut i = 0u32;
        loop {
            if tokio::time::Instant::now() - start > Duration::from_secs(90)
                || session.is_dead()
            {
                break;
            }
            i += 1;
            let dial = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::TcpStream::connect(addr),
            )
            .await;
            let Ok(Ok(mut conn)) = dial else {
                println!("probe {i}: bridge dial failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            };
            use tokio::io::AsyncReadExt as _;
            use tokio::io::AsyncWriteExt as _;
            let _ = conn
                .write_all(b"probe-payload-0123456789\r\n\r\n")
                .await;
            let mut buf = [0u8; 256];
            let read = tokio::time::timeout(
                Duration::from_secs(3),
                conn.read(&mut buf),
            )
            .await;
            println!(
                "probe {i}: read {:?} at {:?}",
                read.map(|r| r.map(|n| n)),
                start.elapsed()
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        println!(
            "probe finished after {:?}, {i} streams, session dead: {}",
            start.elapsed(),
            session.is_dead(),
        );
        assert!(
            start.elapsed() >= Duration::from_secs(80),
            "session died after {:?} — see the close-code log above",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn wss_session_interop_with_mock_sidecar() {
        let addr = spawn_mock_front("ticket-abc123").await;
        // The plain-TCP channel addresses the mock directly (no TLS).
        let url = format!("wss://127.0.0.1:{}/api/v1/wss-bridge", addr.port());
        let session = establish_wss_session(
            &url,
            "ticket-abc123",
            64,
            DEFAULT_HANDSHAKE_TIMEOUT,
            false,
            true,
        )
        .await
        .expect("session established against the mock front");

        // A bridge connection must be copied opaquely into a yamux stream
        // and echoed back — VLESS+Reality bytes would flow identically.
        let client = tokio::net::TcpStream::connect(session.bridge_addr)
            .await
            .unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let payload: Vec<u8> = (0..100_000u32)
            .map(|i| (i % 251) as u8)
            .collect();
        let (mut cr, mut cw) = tokio::io::split(client);
        cw.write_all(&payload).await.unwrap();
        cw.flush().await.unwrap();

        let mut got = vec![0u8; payload.len()];
        cr.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);

        // Second concurrent stream over the same session (multiplexing).
        let mut c2 = tokio::net::TcpStream::connect(session.bridge_addr)
            .await
            .unwrap();
        c2.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        c2.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");

        assert!(!session.is_dead());
    }

    #[tokio::test]
    async fn wss_session_rejects_wrong_ticket() {
        let addr = spawn_mock_front("the-real-ticket").await;
        let url = format!("wss://127.0.0.1:{}/api/v1/wss-bridge", addr.port());
        let err = match establish_wss_session(
            &url,
            "wrong-ticket",
            64,
            DEFAULT_HANDSHAKE_TIMEOUT,
            false,
            true,
        )
        .await
        {
            Err(e) => e,
            Ok(_) => panic!("401 must fail the session"),
        };
        assert!(err.contains("101"), "{err}");
    }

    #[tokio::test]
    async fn wss_session_rejects_non_canonical_url() {
        // Production (non-plain) dials validate the URL first: an IP-literal
        // front URL is rejected before any dial.
        let err = match establish_wss_session(
            "wss://127.0.0.1/api/v1/wss-bridge",
            "t",
            64,
            DEFAULT_HANDSHAKE_TIMEOUT,
            false,
            false,
        )
        .await
        {
            Err(e) => e,
            Ok(_) => panic!("non-canonical front URL must fail"),
        };
        assert!(err.contains("not an IP literal"), "{err}");
    }

    // -- ticket response validation / retry-after ---------------------------

    #[tokio::test]
    async fn ticket_request_happy_path() {
        let url = "wss://edge.b-cdn.net/api/v1/wss-bridge";
        let body = ticket_body("v1.k.c.s", 120, url);
        let resp = format!(
            "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let mut resp = resp;
        resp.extend_from_slice(&body);
        let broker = spawn_mock_broker(resp).await;

        let t = request_wss_ticket_once(&broker, "relay_x", "front-a")
            .await
            .expect("valid ticket");
        assert_eq!(t.ticket, "v1.k.c.s");
        assert_eq!(t.url, url);
        assert!(t.expires_at > chrono::Utc::now());
    }

    #[tokio::test]
    async fn ticket_request_rejects_expired_and_oversized() {
        // already expired
        let body = ticket_body("v1.k.c.s", -1, "wss://edge.b-cdn.net/api/v1/wss-bridge");
        let resp = format!(
            "HTTP/1.1 201 Created\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let mut resp = resp;
        resp.extend_from_slice(&body);
        let broker = spawn_mock_broker(resp).await;
        let err = request_wss_ticket_once(&broker, "relay_x", "front-a")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");

        // oversized ticket (> 4096 bytes, brokerapi/wss_ticket.go:119)
        let big = "x".repeat(5000);
        let body = ticket_body(&big, 120, "wss://edge.b-cdn.net/api/v1/wss-bridge");
        let resp = format!(
            "HTTP/1.1 201 Created\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let mut resp = resp;
        resp.extend_from_slice(&body);
        let broker = spawn_mock_broker(resp).await;
        let err = request_wss_ticket_once(&broker, "relay_x", "front-a")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("oversized"), "{err}");
    }

    #[tokio::test]
    async fn ticket_request_surfaces_status_and_retry_after() {
        // 429 with a valid seconds Retry-After
        let resp = b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 7\r\ncontent-length: 0\r\n\r\n".to_vec();
        let broker = spawn_mock_broker(resp).await;
        let err = request_wss_ticket_once(&broker, "relay_x", "front-a")
            .await
            .unwrap_err();
        match err {
            TicketError::Status { status, retry_after } => {
                assert_eq!(status, 429);
                assert_eq!(retry_after, Duration::from_secs(7));
            },
            other => panic!("want status error, got {other:?}"),
        }

        // 404 (unknown relay/front) — no retry-after
        let resp = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_vec();
        let broker = spawn_mock_broker(resp).await;
        let err = request_wss_ticket_once(&broker, "relay_x", "front-a")
            .await
            .unwrap_err();
        match err {
            TicketError::Status { status, retry_after } => {
                assert_eq!(status, 404);
                assert_eq!(retry_after, Duration::ZERO);
            },
            other => panic!("want status error, got {other:?}"),
        }
    }

    #[test]
    fn parse_retry_after_matches_go() {
        let now = chrono::Utc::now();
        assert_eq!(parse_retry_after("", now), Duration::ZERO);
        assert_eq!(parse_retry_after("  ", now), Duration::ZERO);
        assert_eq!(parse_retry_after("7", now), Duration::from_secs(7));
        assert_eq!(parse_retry_after("-5", now), Duration::ZERO);
        // > 24h rejected
        assert_eq!(parse_retry_after("86401", now), Duration::ZERO);
        assert_eq!(parse_retry_after("86400", now), Duration::from_secs(86400));
        // garbage
        assert_eq!(parse_retry_after("soon", now), Duration::ZERO);
        // HTTP-date form
        let future = now + chrono::Duration::seconds(90);
        let formatted = future.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let d = parse_retry_after(&formatted, now);
        assert!(d > Duration::from_secs(80) && d <= Duration::from_secs(91), "{d:?}");
        // past HTTP-date rejected
        let past = now - chrono::Duration::seconds(90);
        let formatted = past.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        assert_eq!(parse_retry_after(&formatted, now), Duration::ZERO);
    }

    #[test]
    fn native_front_host_matches_go_zones() {
        // one-label under a recognized zone
        assert!(native_front_host("d111111abcdef8.cloudfront.net").is_some());
        assert!(native_front_host("edge10229024d7f3d9331809.b-cdn.net").is_some());
        // custom CNAMEs and deeper labels keep ordinary SNI
        assert!(native_front_host("cdn.example.com").is_none());
        assert!(native_front_host("a.b.cloudfront.net").is_none());
        assert!(native_front_host("cloudfront.net").is_none());
    }

    #[test]
    fn ticket_ladder_default_broker_urls_dedup() {
        // Compile-time sanity: the built-in fronts exist for the ladder.
        assert_eq!(crate::openrung::DEFAULT_BROKER_URLS.len(), 3);
    }

    #[test]
    fn front_id_canonicalization() {
        assert_eq!(normalize_front_id("  Iran-A ").unwrap(), "iran-a");
        assert_eq!(normalize_front_id("a1._-9").unwrap(), "a1._-9");
        // control whitespace rejected outright
        assert!(normalize_front_id("a\tb").is_err());
        assert!(normalize_front_id("a\nb").is_err());
        // shape rules
        assert!(normalize_front_id("").is_err());
        assert!(normalize_front_id("-abc").is_err());
        assert!(normalize_front_id("abc-").is_err());
        assert!(normalize_front_id(".abc").is_err());
        assert!(normalize_front_id("ABC").is_ok()); // normalize lowercases
        assert!(normalize_front_id(&"a".repeat(65)).is_err());
        assert!(normalize_front_id(&"a".repeat(64)).is_ok());
        // canonical check
        assert!(validate_front_id("iran-a").is_ok());
        assert!(validate_front_id("Iran-A").is_err());
        assert!(validate_front_id("  iran-a").is_err());
    }

    #[test]
    fn front_url_accepts_canonical_production_form() {
        let url = "wss://edge10229024d7f3d9331809.b-cdn.net/api/v1/wss-bridge";
        assert_eq!(normalize_front_url(url).unwrap(), url);
        assert!(validate_front_url(url).is_ok());
        // case normalization is applied (normalize, not validate)
        assert_eq!(
            normalize_front_url("WSS://EDGE10229024D7F3D9331809.B-CDN.NET/api/v1/wss-bridge")
                .unwrap(),
            url
        );
    }

    #[test]
    fn front_url_rejections_match_go() {
        // not wss
        assert!(normalize_front_url("https://a.b-cdn.net/api/v1/wss-bridge").is_err());
        // IP literal
        assert!(normalize_front_url("wss://127.0.0.1/api/v1/wss-bridge").is_err());
        assert!(normalize_front_url("wss://[::1]/api/v1/wss-bridge").is_err());
        // legacy numeric spelling a resolver may treat as an address
        assert!(normalize_front_url("wss://127.1/api/v1/wss-bridge").is_err());
        // port present
        assert!(normalize_front_url("wss://a.b-cdn.net:8443/api/v1/wss-bridge").is_err());
        assert!(normalize_front_url("wss://a.b-cdn.net:443/api/v1/wss-bridge").is_err());
        // wrong path
        assert!(normalize_front_url("wss://a.b-cdn.net/bridge").is_err());
        assert!(normalize_front_url("wss://a.b-cdn.net/api/v1/wss-bridge/").is_err());
        // escaped path
        assert!(normalize_front_url("wss://a.b-cdn.net/api%2Fv1%2Fwss-bridge").is_err());
        // query / fragment / userinfo
        assert!(normalize_front_url("wss://a.b-cdn.net/api/v1/wss-bridge?x=1").is_err());
        assert!(normalize_front_url("wss://a.b-cdn.net/api/v1/wss-bridge#frag").is_err());
        assert!(normalize_front_url("wss://u:p@a.b-cdn.net/api/v1/wss-bridge").is_err());
        // single-label host / trailing dot / numeric TLD
        assert!(normalize_front_url("wss://localhost/api/v1/wss-bridge").is_err());
        assert!(normalize_front_url("wss://a.b-cdn.net./api/v1/wss-bridge").is_err());
        assert!(normalize_front_url("wss://a.b-cdn.123/api/v1/wss-bridge").is_err());
        assert!(normalize_front_url("wss://a.b-cdn.1234/api/v1/wss-bridge").is_err());
        // control whitespace
        assert!(normalize_front_url("wss://a.b-cdn.net/api/v1/wss-bridge\n").is_err());
        // empty / oversized
        assert!(normalize_front_url("").is_err());
        assert!(normalize_front_url(&format!("wss://{}.b-cdn.net/api/v1/wss-bridge", "a".repeat(600))).is_err());
        // non-canonical (valid after normalization) fails the strict check
        assert!(validate_front_url("wss://A.B-CDN.NET/api/v1/wss-bridge").is_err());
    }

    #[test]
    fn front_set_normalization_sorts_and_dedups() {
        let mut set = vec![
            WssFront::new("b-front", "wss://b.b-cdn.net/api/v1/wss-bridge"),
            WssFront::new("A-Front", "wss://a.b-cdn.net/api/v1/wss-bridge"),
        ];
        let normalized = normalize_fronts(&set).unwrap();
        assert_eq!(normalized[0].id, "a-front");
        assert_eq!(normalized[1].id, "b-front");

        // > 4 fronts rejected
        set.push(WssFront::new("c", "wss://c.b-cdn.net/api/v1/wss-bridge"));
        set.push(WssFront::new("d", "wss://d.b-cdn.net/api/v1/wss-bridge"));
        set.push(WssFront::new("e", "wss://e.b-cdn.net/api/v1/wss-bridge"));
        assert!(normalize_fronts(&set).is_err());

        // duplicate ID / duplicate URL rejected
        assert!(normalize_fronts(&[
            WssFront::new("a", "wss://a.b-cdn.net/api/v1/wss-bridge"),
            WssFront::new("a", "wss://b.b-cdn.net/api/v1/wss-bridge"),
        ])
        .is_err());
        assert!(normalize_fronts(&[
            WssFront::new("a", "wss://a.b-cdn.net/api/v1/wss-bridge"),
            WssFront::new("B", "wss://a.b-cdn.net/api/v1/wss-bridge"),
        ])
        .is_err());

        // protocol_version must be 1
        assert!(normalize_fronts(&[WssFront {
            id: "a".into(),
            url: "wss://a.b-cdn.net/api/v1/wss-bridge".into(),
            protocol_version: 2,
        }])
        .is_err());
    }

    #[test]
    fn supported_fronts_gates_on_relay_eligibility() {
        let fronts = vec![WssFront::new(
            "a",
            "wss://a.b-cdn.net/api/v1/wss-bridge",
        )];
        // eligible foundation direct relay on 443
        assert_eq!(
            supported_wss_fronts("foundation", "direct", "direct", 443, &fronts),
            fronts
        );
        // empty transport string defaults to direct (Go: TransportDirect)
        assert_eq!(
            supported_wss_fronts("foundation", "direct", "", 443, &fronts),
            fronts
        );
        // ineligible: volunteer class, tunnel transport, hub exit, wrong port
        assert!(supported_wss_fronts("volunteer", "direct", "direct", 443, &fronts).is_empty());
        assert!(supported_wss_fronts("foundation", "direct", "tunnel", 443, &fronts).is_empty());
        assert!(supported_wss_fronts("foundation", "dedicated", "direct", 443, &fronts).is_empty());
        assert!(supported_wss_fronts("foundation", "direct", "direct", 8443, &fronts).is_empty());
        // non-canonical order is rejected, not repaired (Go: !slices.Equal)
        let unsorted = vec![
            WssFront::new("b", "wss://b.b-cdn.net/api/v1/wss-bridge"),
            WssFront::new("a", "wss://a.b-cdn.net/api/v1/wss-bridge"),
        ];
        assert!(supported_wss_fronts("foundation", "direct", "direct", 443, &unsorted).is_empty());
    }
}
