//! XHTTP transport configuration.
//!
//! Mirrors Xray-core's `splithttp` config: mode (stream-one/stream-up/packet-up),
//! HTTP version preference, session metadata placement, and throttling.

use std::collections::HashMap;

use crate::obfuscation::padding::XPaddingConfig;
use crate::obfuscation::range::Range;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// XHTTP transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    /// Automatically select the best mode.
    /// Resolves to `PacketUp` for non-REALITY (matching Xray-core),
    /// or `StreamOne` when used with REALITY.
    #[default]
    Auto,
    /// Single POST: body=uplink, response body=downlink (symmetric).
    StreamOne,
    /// Separate POST (uplink) + GET (downlink) streams (asymmetric).
    StreamUp,
    /// Multiple short POSTs (uplink) + GET (downlink) (asymmetric).
    PacketUp,
}

/// HTTP version preference for the XHTTP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpVersionPref {
    /// Try H3 -> H2 -> H1 in order.
    #[default]
    Auto,
    Http3,
    Http2,
    Http1,
}

/// Where to place session metadata (session_id, seq) in HTTP requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionPlacement {
    /// Append to URL path: `/path/session_id`.
    #[default]
    Path,
    /// URL query parameter: `?key=value`.
    Query,
    /// Standalone HTTP header.
    Header,
    /// Cookie value.
    Cookie,
}

/// HTTP method for uplink requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpMethod {
    #[default]
    Post,
    Get,
}

// ---------------------------------------------------------------------------
// Direction config (for asymmetric mode)
// ---------------------------------------------------------------------------

/// Per-direction overrides for asymmetric XHTTP (M6).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct XhttpDirectionConfig {
    pub server: Option<String>,
    pub port: Option<u16>,
    pub tls_server: Option<String>,
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub http_version: Option<HttpVersionPref>,
}

// ---------------------------------------------------------------------------
// Uplink data placement (packet-up)
// ---------------------------------------------------------------------------

/// Where to place uplink data in packet-up POSTs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UplinkDataPlacement {
    /// Auto: body (default).
    #[default]
    Auto,
    /// Data in POST body.
    Body,
    /// Data in HTTP header (packet-up only).
    Header,
    /// Data in cookie (packet-up only).
    Cookie,
}

// ---------------------------------------------------------------------------
// Uplink data control
// ---------------------------------------------------------------------------

/// Uplink data control: method, placement, chunk size.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UplinkDataConfig {
    /// HTTP method for uplink (default: POST).
    #[serde(default)]
    pub method: HttpMethod,
    /// Where to place uplink data (default: auto = body).
    #[serde(default)]
    pub data_placement: UplinkDataPlacement,
    /// Key name for header/cookie data placement.
    #[serde(default)]
    pub data_key: String,
    /// Chunk size for packet-up (default: 1MB-1MB, None = use Xray default).
    #[serde(default)]
    pub chunk_size: Option<Range>,
}

impl Default for UplinkDataConfig {
    fn default() -> Self {
        Self {
            method: HttpMethod::default(),
            data_placement: UplinkDataPlacement::default(),
            data_key: String::new(),
            chunk_size: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Throttle config (stream-up / packet-up)
// ---------------------------------------------------------------------------

/// Throttling for stream-up / packet-up mode.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ThrottleConfig {
    /// Max bytes per POST (default: 1MB-1MB).
    #[serde(default)]
    pub max_each_post_bytes: Option<Range>,
    /// Min interval between POSTs in ms (default: 30-30ms).
    #[serde(default)]
    pub min_posts_interval_ms: Option<Range>,
    /// Max buffered POSTs (default: 30).
    #[serde(default)]
    pub max_buffered_posts: Option<u32>,
    /// Stream-up server duration in seconds (default: 20-80s).
    #[serde(default)]
    pub stream_up_server_secs: Option<Range>,
}

// ---------------------------------------------------------------------------
// Xmux config (connection pool tuning)
// ---------------------------------------------------------------------------

/// Xmux connection pool tuning.
/// All defaults are 0 = unlimited (matching Xray defaults).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct XmuxConfig {
    /// Max concurrent streams per H2 connection (0 = unlimited).
    #[serde(default)]
    pub max_concurrency: Option<Range>,
    /// Max H2 connections (0 = unlimited).
    #[serde(default)]
    pub max_connections: Option<Range>,
    /// Max reuse times per connection (0 = unlimited).
    #[serde(default)]
    pub c_max_reuse_times: Option<Range>,
    /// Max requests per H2 stream (0 = unlimited).
    #[serde(default)]
    pub h_max_request_times: Option<Range>,
    /// Max reusable seconds (0 = unlimited).
    #[serde(default)]
    pub h_max_reusable_secs: Option<Range>,
    /// Keep-alive period in seconds (0 = default).
    #[serde(default)]
    pub h_keep_alive_period: u64,
}

// ---------------------------------------------------------------------------
// XhttpConfig (extended with all Xray parameters)
// ---------------------------------------------------------------------------

/// Configuration for the XHTTP transport layer.
///
/// All defaults match Xray-core splithttp defaults.
/// When no advanced parameters are specified, behavior is identical
/// to the current implementation.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct XhttpConfig {
    /// Target server hostname (also used for TLS SNI and Host header).
    pub host: String,

    /// Target server port (default: 443).
    #[serde(default = "default_port")]
    pub port: u16,

    /// Base URL path for XHTTP requests (default: `/`).
    #[serde(default = "default_path")]
    pub path: String,

    /// Transport mode (default: auto = packet-up, matching Xray-core).
    #[serde(default)]
    pub mode: XhttpMode,

    /// HTTP version preference (default: auto = H2).
    #[serde(default)]
    pub http_version: HttpVersionPref,

    /// Skip TLS certificate verification (default: false).
    #[serde(default)]
    pub insecure: bool,

    /// Extra HTTP headers to send with every request.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Suppress gRPC Content-Type header (default: false).
    #[serde(default)]
    pub no_grpc_header: bool,

    /// Whether the server is expected to suppress SSE response header
    /// (Content-Type: text/event-stream). Client-side hint only; does not
    /// affect request headers sent by anywhere. (default: false)
    #[serde(default)]
    pub no_sse_header: bool,

    // --- Session metadata placement ---

    /// Where to place the session_id in HTTP requests (default: path).
    #[serde(default)]
    pub session_id_placement: SessionPlacement,
    /// Header/cookie/query key name for session_id (default: "session").
    #[serde(default = "default_session_key")]
    pub session_id_key: String,
    /// Where to place the seq number (default: query).
    #[serde(default = "default_seq_placement")]
    pub seq_placement: SessionPlacement,
    /// Header/cookie/query key name for seq (default: "seq").
    #[serde(default = "default_seq_key")]
    pub seq_key: String,

    // --- Asymmetric direction config (M6) ---

    /// Override uplink target (for asymmetric mode).
    pub uplink_target: Option<XhttpDirectionConfig>,
    /// Override downlink target (for asymmetric mode).
    pub downlink_target: Option<XhttpDirectionConfig>,

    // --- Padding ---

    /// XPadding configuration. When present, XPadding is injected.
    pub padding: Option<XPaddingConfig>,

    // --- Uplink data control ---

    /// Uplink data method, placement, chunk size.
    #[serde(default)]
    pub uplink: UplinkDataConfig,

    // --- Throttling ---

    /// Throttling for stream-up / packet-up.
    #[serde(default)]
    pub throttle: ThrottleConfig,

    // --- Xmux ---

    /// Connection pool tuning.
    #[serde(default)]
    pub xmux: XmuxConfig,
}

fn default_port() -> u16 { 443 }
fn default_path() -> String { "/".to_string() }
fn default_session_key() -> String { "session".to_string() }
fn default_seq_placement() -> SessionPlacement { SessionPlacement::Query }
fn default_seq_key() -> String { "seq".to_string() }

impl Default for XhttpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: default_port(),
            path: default_path(),
            mode: XhttpMode::default(),
            http_version: HttpVersionPref::default(),
            insecure: false,
            headers: HashMap::new(),
            no_grpc_header: false,
            no_sse_header: false,
            session_id_placement: SessionPlacement::default(),
            session_id_key: default_session_key(),
            seq_placement: default_seq_placement(),
            seq_key: default_seq_key(),
            uplink_target: None,
            downlink_target: None,
            padding: None,
            uplink: UplinkDataConfig::default(),
            throttle: ThrottleConfig::default(),
            xmux: XmuxConfig::default(),
        }
    }
}
/// Resolve the effective mode.
///
/// `Auto` resolves to `PacketUp` to match Xray-core behavior, where
/// `mode: auto` (or empty) resolves to `packet-up` for non-REALITY
/// connections. When using REALITY, Xray resolves to `stream-one`,
/// but that is determined by the caller based on transport settings,
/// not here.
pub fn resolve_mode(cfg: &XhttpConfig) -> XhttpMode {
    match cfg.mode {
        XhttpMode::Auto => XhttpMode::PacketUp,
        m => m,
    }
}

/// Resolve the effective HTTP version: `Auto` becomes `Http2` for M3.
pub fn resolve_http_version(cfg: &XhttpConfig) -> HttpVersionPref {
    match cfg.http_version {
        HttpVersionPref::Auto => HttpVersionPref::Http2,
        HttpVersionPref::Http3 => HttpVersionPref::Http2, // H3 deferred to M6
        v => v,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = XhttpConfig::default();
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.path, "/");
        assert_eq!(cfg.mode, XhttpMode::Auto);
        assert_eq!(cfg.http_version, HttpVersionPref::Auto);
        assert!(!cfg.insecure);
        assert_eq!(cfg.session_id_placement, SessionPlacement::Path);
        assert_eq!(cfg.session_id_key, "session");
        assert_eq!(cfg.seq_placement, SessionPlacement::Query);
        assert_eq!(cfg.seq_key, "seq");
    }

    #[test]
    fn resolve_auto_mode() {
        // Auto resolves to PacketUp to match Xray-core non-REALITY behavior
        let cfg = XhttpConfig { mode: XhttpMode::Auto, ..Default::default() };
        assert_eq!(resolve_mode(&cfg), XhttpMode::PacketUp);

        let cfg = XhttpConfig { mode: XhttpMode::StreamUp, ..Default::default() };
        assert_eq!(resolve_mode(&cfg), XhttpMode::StreamUp);
    }

    #[test]
    fn resolve_auto_http_version() {
        let cfg = XhttpConfig { http_version: HttpVersionPref::Auto, ..Default::default() };
        assert_eq!(resolve_http_version(&cfg), HttpVersionPref::Http2);

        let cfg = XhttpConfig { http_version: HttpVersionPref::Http3, ..Default::default() };
        assert_eq!(resolve_http_version(&cfg), HttpVersionPref::Http2);

        let cfg = XhttpConfig { http_version: HttpVersionPref::Http1, ..Default::default() };
        assert_eq!(resolve_http_version(&cfg), HttpVersionPref::Http1);
    }

    #[test]
    fn deserialize_full_config() {
        let toml = r#"
host = "example.com"
port = 8443
path = "/xhttp"
mode = "stream-one"
http_version = "http2"
insecure = true

session_id_placement = "query"
[headers]
Host = "example.com"
User-Agent = "Mozilla/5.0"

[padding]
bytes = { from = 100, to = 1000 }
method = "tokenish"
"#;
        let cfg: XhttpConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.port, 8443);
        assert_eq!(cfg.path, "/xhttp");
        assert_eq!(cfg.mode, XhttpMode::StreamOne);
        assert_eq!(cfg.http_version, HttpVersionPref::Http2);
        assert!(cfg.insecure);
        assert_eq!(cfg.headers.get("Host").unwrap(), "example.com");
        assert!(cfg.padding.is_some());
    }
}
