//! OpenRung relay-directory import (`--sub-openrung`).
//!
//! Fetches the signed relay directory from an OpenRung broker, verifies the
//! detached Ed25519 signature over the exact response bytes against two pinned
//! signing keys, validates the wire schema, and converts the VLESS+REALITY+
//! Vision relays into an anywhere TOML config (default `openrung.toml`).
//!
//! The verification semantics are a line-by-line port of the Go client's
//! `brokerapi` package (`openrung/brokerapi/signing.go`), which is the sole
//! authority for this protocol:
//!
//! | Go                                            | here                                   |
//! |-----------------------------------------------|----------------------------------------|
//! | `RelaySignatureHeader`                        | [`RELAY_SIGNATURE_HEADER`]             |
//! | `relaySigningKey{Active,Standby}Hex`          | `SIGNING_KEY_{ACTIVE,STANDBY}_HEX`     |
//! | `signingKeyID` (sha256(pub)[:8] hex)          | [`signing_key_id`]                     |
//! | `verifyRelayList`                             | [`verify_relay_list`]                  |
//! | `parseRelaySignatureHeader`                   | [`parse_relay_signature_header`]       |
//! | `orderKeysByAdvisoryID`                       | `order_keys_by_advisory_id`            |
//! | `endpointIsLoopback` / `hostIsLoopback`       | [`endpoint_is_loopback`]               |
//! | `effectiveRelayLimit`                         | [`effective_relay_limit`]              |
//! | `validateRelayListWire`                       | [`validate_relay_list_wire`]           |
//! | `relayListEnvelope`                           | `RelayListEnvelope`                    |
//! | `verificationFailure` ("unsigned/invalid...") | error prefix on every check            |
//!
//! Deviations from Go (deliberate, minimal):
//! - Go's mirror/inventory channels are not fetched here — anywhere always
//!   talks to the API channel (`GET {base}/api/v1/relays?limit=20`) or reads a
//!   local file for offline/debugging. The `channel == "api"` check inside the
//!   signed body is still enforced, so a mirror/inventory artifact can never
//!   be replayed into this path.
//! - Broker fetches fail over across fronts in [`broker_candidates`] order:
//!   a genuine custom primary is tried first, then the built-ins — the
//!   Cloudflare front (fetched with the ECH offer), then the CloudFront and
//!   Azure Front Door CDN fronts (plain TLS). The first front to return the
//!   directory wins and its resolved URL becomes the authenticated endpoint;
//!   if every front fails, the error lists each front with its own reason.
//!   `file://`/local paths skip the network entirely (wire validation only).
//! - Local files are the same development channel as Go's loopback exemption:
//!   wire-schema validation only, no signature (a file has no HTTP response
//!   to carry one).
//! - Advertised `wss_fronts` are carried on the decoded relay and emitted
//!   into the generated TOML for relays passing the Go eligibility gate
//!   (`wssfront::supported_wss_fronts`); the broker base URL the directory
//!   was fetched from is recorded as the ticket endpoint
//!   (`[outbounds.wss_fallback]`). The WSS/CDN fallback itself lives in
//!   [`crate::wssfront`] and the vless outbound.

use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use once_cell::sync::Lazy;
use serde::Deserialize;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Protocol constants (openrung/brokerapi/signing.go, types.go, url.go)
// ---------------------------------------------------------------------------

/// `X-OpenRung-Relays-Signature`: `ed25519;<key_id>;<standard-base64 sig>`
/// over exact body bytes (signing.go:21).
pub const RELAY_SIGNATURE_HEADER: &str = "X-OpenRung-Relays-Signature";

/// Pinned relay-list signing keys (signing.go:23-24). Key rotation: the
/// standby key is promoted by publishing a body signed with it — the header
/// key_id only prioritizes which pinned key is tried first.
const SIGNING_KEY_ACTIVE_HEX: &str =
    "176c03cbc70833285abcea75f2a0e137bd687629142408c22806a86308bd4974";
const SIGNING_KEY_STANDBY_HEX: &str =
    "5b2698cfa7a796c671a30aabd5475d55095b91464221f051837eb8fe01f36ea2";

/// Clock-skew tolerance for the `not_after` freshness bound (signing.go:26:
/// `notAfterSkewAllowance = 5 * time.Minute`).
pub const NOT_AFTER_SKEW_ALLOWANCE_SECS: i64 = 5 * 60;

/// The only signed channel this import accepts (relay_schema.go:126
/// `ChannelAPI`). Enforced inside the signed body.
pub const CHANNEL_API: &str = "api";

/// The only relay protocol anywhere can represent (relay_schema.go:101).
pub const PROTOCOL_VLESS_REALITY_VISION: &str = "vless-reality-vision";

/// Default page size when none is requested (types.go:46
/// `DefaultRelayLimit = 5`, url.go:78 `effectiveRelayLimit`).
pub const DEFAULT_RELAY_LIMIT: i64 = 5;

/// anywhere always requests a full directory page. 20 is the broker's single
/// page maximum (internal/broker/server.go listRelaysHandler rejects
/// `limit` outside [1, 20]) and currently covers the whole production fleet.
pub const REQUESTED_RELAY_LIMIT: i64 = 20;

/// The Cloudflare broker front (types.go:28 `DefaultBrokerURL`).
pub const DEFAULT_BROKER_URL: &str = "https://broker.openrung.org/";

/// The CloudFront broker front (types.go:16-34, `CloudFrontBrokerURL`). A
/// one-label `*.cloudfront.net` distribution: with SNI the edge serves its
/// default certificate, which covers the distribution name, so an ordinary
/// HTTPS client reaches it without openrung's own no-SNI machinery. The
/// Ed25519 relay-list signature remains the binding authentication.
pub const CLOUDFRONT_BROKER_URL: &str = "https://d2r7mdpyevvs1m.cloudfront.net/";

/// The Azure Front Door broker front (types.go:36-40, `AzureBrokerURL`). With
/// SNI the shared edge certificate's `*.z02.azurefd.net` SAN covers this
/// endpoint name, so standard verification applies here too (openrung's own
/// client omits SNI for censorship resistance and leans on the signature —
/// anywhere keeps SNI; both authenticate the same signed body).
pub const AZURE_BROKER_URL: &str = "https://cdn-edge-cxdnhsg2aadmaubj.z02.azurefd.net/";

/// `DefaultBrokerURLs` (types.go:201): the built-in discovery order.
pub const DEFAULT_BROKER_URLS: [&str; 3] =
    [DEFAULT_BROKER_URL, CLOUDFRONT_BROKER_URL, AZURE_BROKER_URL];

/// Unix timestamp of Go's zero `time.Time` (0001-01-01T00:00:00Z): a missing
/// `not_after` decodes to this value in Go, where `IsZero()` rejects it.
const GO_ZERO_TIME_UNIX: i64 = -62135596800;

// ---------------------------------------------------------------------------
// Pinned keys
// ---------------------------------------------------------------------------

/// One pinned Ed25519 relay-list signing key plus its advisory key_id
/// (`sha256(pub)[:8]` lowercase hex, signing.go:49).
#[derive(Clone)]
pub struct PinnedKey {
    pub id: String,
    pub key: VerifyingKey,
}

impl std::fmt::Debug for PinnedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedKey").field("id", &self.id).finish()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `signingKeyID` (signing.go:49): lowercase hex of the first 8 bytes of
/// SHA-256 over the raw 32-byte Ed25519 public key.
pub fn signing_key_id(public_key: &[u8; 32]) -> String {
    let sum: [u8; 32] = Sha256::digest(public_key).into();
    hex_encode(&sum[..8])
}

/// Build pinned keys from hex-encoded public keys (Go `mustPinnedKeys`).
/// Malformed pins panic at startup, exactly like the Go helper.
pub fn pinned_keys_from_hex(keys_hex: &[&str]) -> Vec<PinnedKey> {
    keys_hex
        .iter()
        .map(|key_hex| {
            let raw = decode_hex_32(key_hex)
                .expect("pinned relay signing key must be 32 hex-encoded bytes");
            let key = VerifyingKey::from_bytes(&raw)
                .expect("pinned relay signing key must be a valid Ed25519 key");
            PinnedKey {
                id: signing_key_id(&raw),
                key,
            }
        })
        .collect()
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!("want 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("bad hex at byte {i}: {e}"))?;
    }
    Ok(out)
}

/// The production pinned keys (active first, standby second — Go
/// `productionRelayKeys`). The signature header's key_id only reorders the
/// verification attempts; it never gates them.
pub static PINNED_RELAY_KEYS: Lazy<Vec<PinnedKey>> = Lazy::new(|| {
    pinned_keys_from_hex(&[SIGNING_KEY_ACTIVE_HEX, SIGNING_KEY_STANDBY_HEX])
});

pub fn pinned_relay_keys() -> &'static [PinnedKey] {
    &PINNED_RELAY_KEYS
}

// ---------------------------------------------------------------------------
// Signature header (signing.go:121 parseRelaySignatureHeader)
// ---------------------------------------------------------------------------

/// Parse `ed25519;<key_id>;<standard-base64 signature>` — returns
/// `(key_id, signature_bytes)`. Every failure mirrors the Go message shape so
/// the alignment table in the module docs stays literal.
fn parse_relay_signature_header(header: &str) -> Result<(String, [u8; 64]), String> {
    if header.is_empty() {
        return Err(format!(
            "response carries no {RELAY_SIGNATURE_HEADER} header — this broker \
             has not enabled relay-list signing (this build requires a signing \
             broker; plain-JSON responses are accepted only from loopback \
             broker URLs for development)"
        ));
    }
    let fields: Vec<&str> = header.split(';').collect();
    if fields.len() != 3 {
        return Err(format!(
            "malformed {RELAY_SIGNATURE_HEADER} header: want 3 ';'-separated \
             fields, got {}",
            fields.len()
        ));
    }
    if fields[0] != "ed25519" {
        return Err(format!(
            "unsupported signature algorithm \"{}\" (want ed25519)",
            fields[0]
        ));
    }
    let sig = base64::engine::general_purpose::STANDARD
        .decode(fields[2])
        .map_err(|e| format!("signature is not valid standard base64: {e}"))?;
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|v: Vec<u8>| format!("signature is {} bytes, want 64", v.len()))?;
    Ok((fields[1].to_string(), sig))
}

/// `orderKeysByAdvisoryID` (signing.go:145): pinned keys whose key_id matches
/// the header first (stable), then the rest (stable). The header is advisory:
/// an unknown or lying key_id never blocks trying every pinned key.
fn order_keys_by_advisory_id<'a>(
    keys: &'a [PinnedKey], header_key_id: &str,
) -> Vec<&'a PinnedKey> {
    let mut ordered: Vec<&PinnedKey> =
        keys.iter().filter(|k| k.id == header_key_id).collect();
    ordered.extend(keys.iter().filter(|k| k.id != header_key_id));
    ordered
}

// ---------------------------------------------------------------------------
// Wire schema (relay_schema.go relayWireList / validateRelayListWire)
// ---------------------------------------------------------------------------

/// Mirrors Go's private `relayWireList` decode shape. Fields Go decodes into
/// pointers are `Option`s here: `None` == absent == the exact same rejection
/// Go issues for a nil pointer. Unknown fields are ignored (forward
/// compatibility), like Go's non-strict top-level/descriptor decoding.
// The descriptor/wss-front fields are read by serde during validation (a
// wrong-typed or missing field fails the decode) even where Rust never reads
// them afterwards — that is the point of the wire check.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct RelayWireList {
    #[serde(default)]
    count: Option<i64>,
    #[serde(default)]
    server_time: Option<DateTime<Utc>>,
    #[serde(default)]
    not_after: Option<DateTime<Utc>>,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    relays: Option<Vec<RelayWireDescriptor>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct RelayWireDescriptor {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    public_host: Option<String>,
    #[serde(default)]
    public_port: Option<i64>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    node_class: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    reality_public_key: Option<String>,
    #[serde(default)]
    short_id: Option<String>,
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    flow: Option<String>,
    #[serde(default)]
    exit_mode: Option<String>,
    #[serde(default)]
    max_sessions: Option<i64>,
    #[serde(default)]
    max_mbps: Option<i64>,
    #[serde(default)]
    relay_version: Option<String>,
    // The wire check requires the (deprecated) volunteer_version alias, not
    // relay_version — exactly like Go's relayWireDescriptor.
    #[serde(default)]
    volunteer_version: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    punch_capable: Option<bool>,
    #[serde(default)]
    punch_endpoint: Option<String>,
    #[serde(default)]
    wss_fronts: Option<Vec<RelayWssFront>>,
    #[serde(default)]
    registered_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_heartbeat_at: Option<DateTime<Utc>>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

/// Mirrors Go's `relayWSSFront.UnmarshalJSON`: strict (unknown fields
/// rejected) and all three fields required — the only strict decode in the
/// schema (relay_schema.go:68-88).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct RelayWssFront {
    id: String,
    url: String,
    protocol_version: i64,
}

/// `validateRelayListWire` (relay_schema.go:305): the complete client-facing
/// relay shape must decode with every security-relevant field present.
pub fn validate_relay_list_wire(body: &[u8]) -> Result<(), String> {
    let list: RelayWireList = serde_json::from_slice(body)
        .map_err(|e| format!("decode relay list: {e}"))?;
    if list.count.is_none() || list.server_time.is_none() || list.relays.is_none()
    {
        return Err("relay list requires count, server_time, and relays".into());
    }
    for (index, relay) in list.relays.unwrap_or_default().iter().enumerate() {
        let required_present = relay.id.is_some()
            && relay.public_host.is_some()
            && relay.public_port.is_some()
            && relay.protocol.is_some()
            && relay.client_id.is_some()
            && relay.reality_public_key.is_some()
            && relay.short_id.is_some()
            && relay.server_name.is_some()
            && relay.flow.is_some()
            && relay.exit_mode.is_some()
            && relay.max_sessions.is_some()
            && relay.max_mbps.is_some()
            && relay.volunteer_version.is_some()
            && relay.registered_at.is_some()
            && relay.last_heartbeat_at.is_some()
            && relay.expires_at.is_some();
        if !required_present {
            return Err(format!(
                "relay {index} is missing a required client field"
            ));
        }
    }
    Ok(())
}

/// Go's `relayListEnvelope` (signing.go:54): the minimal signed-body fields
/// checked before the full wire schema. Missing `channel`/`limit` decode to
/// Go's zero values ("" / 0); missing `not_after` is rejected as zero.
#[derive(Debug, Deserialize)]
struct RelayListEnvelope {
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    not_after: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// verify (signing.go:60 verifyRelayList)
// ---------------------------------------------------------------------------

/// Where the relay-list bytes came from. Broker URLs get the full Go
/// verification flow (with the loopback exemption); local files are the
/// offline/debug channel and carry no signature header to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayEndpoint {
    /// An http(s) broker URL — signed unless the URL host is loopback.
    Broker(String),
    /// A `file://` URL or filesystem path — wire-schema validation only.
    LocalFile(String),
}

/// The exact response bytes that passed verification, plus the metadata the
/// conversion header reports (Go `RelayList`).
#[derive(Debug, Clone)]
pub struct VerifiedRelayList {
    pub raw_json: Vec<u8>,
    pub key_id: String,
    pub signature_verified: bool,
}

/// `hostIsLoopback` (url.go:44): `localhost` (case-insensitive) or a parsed
/// loopback IP. `localhost.example` is NOT loopback.
fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    false
}

/// `endpointIsLoopback` (url.go:54): parse the endpoint URL and check its
/// host. Unparseable or host-less endpoints are not loopback.
pub fn endpoint_is_loopback(endpoint: &str) -> bool {
    let Ok(parsed) = url::Url::parse(endpoint) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(domain)) => host_is_loopback(&domain),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// `effectiveRelayLimit` (url.go:78): a non-positive limit means "default".
/// There is deliberately no upper clamp here — the broker rejects pages above
/// 20 with HTTP 400 — matching the Go client byte for byte.
pub fn effective_relay_limit(limit: i64) -> i64 {
    if limit < 1 {
        return DEFAULT_RELAY_LIMIT;
    }
    limit
}

fn verification_failure(reason: String) -> String {
    format!("unsigned/invalid relay list: {reason}")
}

/// Verify a relay list exactly like Go's `verifyRelayList` (signing.go:60):
///
/// 1. loopback broker URLs / local files: wire-schema validation only, no
///    signature (`SignatureVerified` stays false);
/// 2. parse `ed25519;<key_id>;<sig>` from the signature header;
/// 3. Ed25519-verify the exact body bytes under the pinned keys, header
///    key_id first (advisory ordering);
/// 4. envelope checks inside the signed body: `channel == "api"`, echoed
///    `limit` == effective limit, `not_after` present and not older than
///    `now - 5min` (skew tolerance);
/// 5. full wire-schema validation.
pub fn verify_relay_list(
    keys: &[PinnedKey],
    endpoint: &RelayEndpoint,
    requested_limit: i64,
    signature_header: Option<&str>,
    body: &[u8],
    now: DateTime<Utc>,
) -> Result<VerifiedRelayList, String> {
    let exempt = match endpoint {
        RelayEndpoint::LocalFile(_) => true,
        RelayEndpoint::Broker(url) => endpoint_is_loopback(url),
    };
    if exempt {
        validate_relay_list_wire(body)?;
        return Ok(VerifiedRelayList {
            raw_json: body.to_vec(),
            key_id: String::new(),
            signature_verified: false,
        });
    }

    let (header_key_id, signature) =
        parse_relay_signature_header(signature_header.unwrap_or(""))?;

    let mut verified_key_id = String::new();
    for candidate in order_keys_by_advisory_id(keys, &header_key_id) {
        if candidate.key.verify(body, &Signature::from(signature)).is_ok()
        {
            verified_key_id = candidate.id.clone();
            break;
        }
    }
    if verified_key_id.is_empty() {
        return Err(verification_failure(format!(
            "signature does not verify under any pinned key (header key_id \
             \"{header_key_id}\")"
        )));
    }

    let envelope: RelayListEnvelope = serde_json::from_slice(body)
        .map_err(|e| {
            verification_failure(format!("signed body is not valid JSON: {e}"))
        })?;

    let channel = envelope.channel.unwrap_or_default();
    if channel != CHANNEL_API {
        return Err(verification_failure(format!(
            "channel \"{channel}\" does not match the \"{CHANNEL_API}\" channel \
             this candidate was fetched from"
        )));
    }

    let effective = effective_relay_limit(requested_limit);
    let echoed = envelope.limit.unwrap_or(0);
    if echoed != effective {
        return Err(verification_failure(format!(
            "echoed limit {echoed} does not match requested limit {effective}"
        )));
    }

    let not_after = envelope.not_after.ok_or_else(|| {
        verification_failure(
            "signed body carries no not_after freshness bound".to_string(),
        )
    })?;
    if not_after.timestamp() == GO_ZERO_TIME_UNIX {
        return Err(verification_failure(
            "signed body carries no not_after freshness bound".to_string(),
        ));
    }
    let cutoff = now - Duration::seconds(NOT_AFTER_SKEW_ALLOWANCE_SECS);
    if not_after < cutoff {
        return Err(verification_failure(format!(
            "list expired: not_after {} is past even with the {}s clock-skew \
             allowance (local time {})",
            not_after.to_rfc3339_opts(SecondsFormat::Secs, true),
            NOT_AFTER_SKEW_ALLOWANCE_SECS,
            now.to_rfc3339_opts(SecondsFormat::Secs, true),
        )));
    }

    validate_relay_list_wire(body).map_err(|e| {
        verification_failure(format!(
            "signed body does not match the relay-list wire schema: {e}"
        ))
    })?;

    Ok(VerifiedRelayList {
        raw_json: body.to_vec(),
        key_id: verified_key_id,
        signature_verified: true,
    })
}

// ---------------------------------------------------------------------------
// Decode (relay_schema.go RelayDescriptor — the client-facing model)
// ---------------------------------------------------------------------------

/// The decoded, verified relay descriptor — only the fields the anywhere
/// conversion consumes.
#[derive(Debug, Clone)]
pub struct OpenrungRelay {
    pub id: String,
    pub label: String,
    pub public_host: String,
    pub public_port: i64,
    pub protocol: String,
    pub client_id: String,
    pub reality_public_key: String,
    pub short_id: String,
    pub server_name: String,
    pub flow: String,
    /// Broker-attested operator class ("foundation"/"volunteer"; missing ==
    /// volunteer). Gates WSS-front eligibility (`supported_wss_fronts`).
    pub node_class: String,
    /// `exit_mode` ("direct"/"dedicated"; required by the wire check).
    pub exit_mode: String,
    /// `transport` ("direct"/"tunnel"; absent == "direct", like Go).
    pub transport: String,
    /// Advertised WSS CDN fronts, verbatim from the signed descriptor (each
    /// front already strict-decoded by [`RelayWssFront`]). Usability is
    /// decided by [`crate::wssfront::supported_wss_fronts`], matching Go's
    /// use-time check — never repaired.
    pub wss_fronts: Vec<crate::wssfront::WssFront>,
}

/// Decode verified relay-list bytes into the model (Go decodes the same
/// `RelayList.JSON()` bytes into `RelayListResponse` after verification).
pub fn decode_relay_list(body: &[u8]) -> Result<Vec<OpenrungRelay>, String> {
    let list: RelayWireList = serde_json::from_slice(body)
        .map_err(|e| format!("decode relay list: {e}"))?;
    let relays = list
        .relays
        .ok_or_else(|| "relay list has no relays field".to_string())?;
    Ok(relays
        .into_iter()
        .map(|r| OpenrungRelay {
            id: r.id.unwrap_or_default(),
            label: r.label.unwrap_or_default(),
            public_host: r.public_host.unwrap_or_default(),
            public_port: r.public_port.unwrap_or(0),
            protocol: r.protocol.unwrap_or_default(),
            client_id: r.client_id.unwrap_or_default(),
            reality_public_key: r.reality_public_key.unwrap_or_default(),
            short_id: r.short_id.unwrap_or_default(),
            server_name: r.server_name.unwrap_or_default(),
            flow: r.flow.unwrap_or_default(),
            node_class: r.node_class.unwrap_or_default(),
            exit_mode: r.exit_mode.unwrap_or_default(),
            transport: r.transport.unwrap_or_default(),
            wss_fronts: r
                .wss_fronts
                .unwrap_or_default()
                .into_iter()
                .map(|f| crate::wssfront::WssFront {
                    id: f.id,
                    url: f.url,
                    protocol_version: f.protocol_version,
                })
                .collect(),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Conversion to anywhere TOML
// ---------------------------------------------------------------------------

/// Metadata rendered into the generated file's header comments.
#[derive(Debug, Clone, Default)]
pub struct ImportMeta {
    /// Fetch/generation time, UTC RFC3339.
    pub fetched_at_utc: String,
    /// Verified signing key id (empty when the source was unsigned).
    pub key_id: String,
    /// The signed body's not_after (RFC3339), or "none" when unsigned.
    pub not_after: String,
    /// Broker base URL the directory was fetched from (e.g.
    /// `https://broker.openrung.org/`), recorded on every WSS-capable node as
    /// the ticket endpoint. Empty for local-file imports — fronts are still
    /// emitted, but the fallback cannot run without a broker to mint tickets.
    pub broker_base_url: String,
}

/// Outcome of the conversion: rendered TOML plus import/skip accounting
/// (the subscription parser's silent-skip policy, counted).
pub struct ConvertResult {
    pub toml: String,
    pub imported: usize,
    pub skipped: usize,
    pub skips: Vec<String>,
}

/// Group tag of the generated urltest outbound, and the catch-all rule target.
const GROUP_TAG: &str = "openrung";

/// Render `server = host:port`, bracketing IPv6 literals so the address
/// parses as a SocketAddr (`[2408:..]:443`) instead of relying on the DNS
/// fallback path.
fn render_server(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Convert verified relay descriptors into an anywhere TOML config:
///
/// - one `[[outbounds]] type = "vless"` per relay whose protocol is
///   `vless-reality-vision` (others are skipped and counted);
/// - `tag = label`, deduplicated with an id suffix when missing/duplicated;
/// - `server = public_host:public_port`, `password = client_id`,
///   `sni = server_name` (only when non-empty), `flow` only when non-empty;
/// - `[outbounds.reality] public_key/short_id` validated through
///   `RealityConfig::parse` (invalid nodes are skipped and counted);
/// - for relays whose advertised WSS fronts pass the Go eligibility gate
///   (`wssfront::supported_wss_fronts`: direct-mode Foundation relay on 443
///   with a canonical front set), the fronts are emitted as
///   `[[outbounds.wss_fronts]]` entries; when a broker base URL is known
///   (non-empty [`ImportMeta::broker_base_url`]), a `[outbounds.wss_fallback]`
///   section records it as the ticket endpoint. Non-canonical front sets are
///   silently omitted (treated as "no fronts"), exactly like Go's
///   `supportedWSSFronts` returning nil;
/// - every imported node aggregated into one `urltest` group tagged
///   `openrung` (mode/interval/url left at anywhere's defaults);
/// - a catch-all `[[rules]] outbound = "openrung"`.
pub fn convert_relays(
    relays: &[OpenrungRelay], meta: &ImportMeta,
) -> Result<ConvertResult, String> {
    let mut outbounds: Vec<crate::subscription::TomlOutbound> = Vec::new();
    let mut tags: Vec<String> = Vec::new();
    let mut skips: Vec<String> = Vec::new();
    let mut used_tags: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for relay in relays {
        if relay.protocol != PROTOCOL_VLESS_REALITY_VISION {
            skips.push(format!(
                "protocol:{} (relay {})",
                if relay.protocol.is_empty() {
                    "unknown"
                } else {
                    &relay.protocol
                },
                relay.id
            ));
            continue;
        }
        if relay.public_host.is_empty() || relay.client_id.is_empty() {
            skips.push(format!("missing endpoint or client_id ({})", relay.id));
            continue;
        }
        let Ok(port) = u16::try_from(relay.public_port) else {
            skips.push(format!("invalid port {} ({})", relay.public_port, relay.id));
            continue;
        };

        // REALITY params must be representable in a handwritten config too:
        // pbk base64 (32 bytes), sid hex <= 8 bytes (`RealityConfig::parse`).
        let reality = crate::transport::reality::RealityConfig {
            public_key: relay.reality_public_key.clone(),
            short_id: relay.short_id.clone(),
        };
        if let Err(err) = reality.parse() {
            skips.push(format!("{err} ({})", relay.id));
            continue;
        }

        // Tag: label when present, else the relay id; duplicates get an id
        // suffix so every node tag stays unique.
        let base = if relay.label.is_empty() {
            relay.id.clone()
        } else {
            relay.label.clone()
        };
        let mut tag = base.clone();
        if used_tags.contains(&tag) {
            let suffix: String = relay
                .id
                .chars()
                .rev()
                .take(6)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            tag = format!("{base}.{suffix}");
            let mut n = 1;
            while used_tags.contains(&tag) {
                n += 1;
                tag = format!("{base}.{suffix}.{n}");
            }
        }
        used_tags.insert(tag.clone());

        let mut ob = crate::subscription::TomlOutbound::new("vless", &tag)
            .field("server", render_server(&relay.public_host, port))
            .field("password", relay.client_id.as_str());
        if !relay.server_name.is_empty() {
            ob = ob.field("sni", relay.server_name.as_str());
        }
        // Empty flow is legitimate (pure REALITY, no Vision) — omit the field.
        if !relay.flow.is_empty() {
            ob = ob.field("flow", relay.flow.as_str());
        }
        ob.set_reality(crate::subscription::RealitySection {
            public_key: relay.reality_public_key.clone(),
            short_id: relay.short_id.clone(),
        });

        // WSS fronts: only a direct-mode Foundation relay on 443 with an
        // already-canonical front set carries usable fronts (Go
        // connectcore.supportedWSSFronts); anything else silently means "no
        // fronts" — the direct REALITY path is untouched either way.
        let fronts = crate::wssfront::supported_wss_fronts(
            &relay.node_class,
            &relay.exit_mode,
            &relay.transport,
            relay.public_port,
            &relay.wss_fronts,
        );
        if !fronts.is_empty() {
            ob.wss_fronts = fronts
                .iter()
                .map(|f| crate::subscription::WssFrontSection {
                    id: f.id.clone(),
                    url: f.url.clone(),
                    protocol_version: f.protocol_version,
                })
                .collect();
            if !meta.broker_base_url.is_empty() {
                ob.wss_fallback = Some(crate::subscription::WssFallbackSection {
                    broker: meta.broker_base_url.clone(),
                    relay_id: relay.id.clone(),
                });
            }
        }

        tags.push(tag);
        outbounds.push(ob);
    }

    if tags.is_empty() {
        return Err(
            "no usable relays in the verified directory (all filtered out)"
                .to_string(),
        );
    }

    // One urltest group over every node; mode/interval/url keep anywhere's
    // defaults (latency / 300s / www.google.com).
    outbounds.push(
        crate::subscription::TomlOutbound::new("urltest", GROUP_TAG)
            .field("outbounds", tags),
    );

    let signature_note = if meta.key_id.is_empty() {
        "unsigned (loopback/local source)".to_string()
    } else {
        format!("key_id {}", meta.key_id)
    };
    let mut toml = String::new();
    toml.push_str("# Generated by anywhere --sub-openrung\n");
    toml.push_str(&format!("# Fetched: {} (UTC)\n", meta.fetched_at_utc));
    toml.push_str(&format!("# Signature: {signature_note}\n"));
    toml.push_str(&format!("# List not_after: {}\n", meta.not_after));
    toml.push_str(&format!(
        "# Nodes: {} imported, {} skipped\n",
        relays.len() - skips.len(),
        skips.len()
    ));
    toml.push('\n');
    toml.push_str(&crate::subscription::render_outbounds(&outbounds));

    // Catch-all rule: every connection goes through the urltest group.
    toml.push_str("[[rules]]\n");
    toml.push_str(&format!("outbound = \"{GROUP_TAG}\"\n"));

    // A local SOCKS5 inbound so the generated file is runnable as-is:
    // anywhere has no default inbound, and the directory import is meant to
    // produce a ready-to-start client config (curl --socks5-hostname
    // 127.0.0.1:10808 ...). Inbounds render after the tables above because
    // TOML array-of-tables order is irrelevant and the header comment must
    // stay first; put the inbound before the outbounds for readability by
    // splicing it right after the header block.
    let inbound = "[[inbounds]]\ntype = \"socks5\"\nlisten = \"127.0.0.1:10808\"\n\n";
    let header_end = toml
        .find("[[outbounds]]")
        .unwrap_or(toml.len());
    toml.insert_str(header_end, inbound);

    Ok(ConvertResult {
        toml,
        imported: relays.len() - skips.len(),
        skipped: skips.len(),
        skips,
    })
}

// ---------------------------------------------------------------------------
// Fetch + entry point (called from main.rs when --sub-openrung is given)
// ---------------------------------------------------------------------------

enum SourceKind {
    Broker(String),
    Local(String),
}

/// `BrokerCandidates` (types.go:208): the discovery order for a
/// `--sub-openrung` value. A genuine custom broker URL runs first, before the
/// built-in fronts ("a genuine custom primary runs alone before the built-in
/// fronts; merely persisting one of the defaults does not reorder them");
/// passing one of the built-in fronts (or the empty default) keeps the
/// built-in order. De-duplicated, order-preserving.
pub fn broker_candidates(primary: &str) -> Vec<String> {
    let trimmed = primary.trim();
    let is_custom_broker = matches!(
        classify_source(trimmed),
        Ok(SourceKind::Broker(url)) if !DEFAULT_BROKER_URLS.contains(&url.as_str())
    );
    let mut ordered: Vec<String> = Vec::new();
    if is_custom_broker {
        ordered.push(trimmed.to_string());
    }
    for url in DEFAULT_BROKER_URLS {
        if !ordered.iter().any(|c| c == url) {
            ordered.push(url.to_string());
        }
    }
    ordered
}

/// Classify `--sub-openrung`'s optional value: http(s) broker URL vs
/// `file://` URL / local filesystem path.
fn classify_source(source: &str) -> Result<SourceKind, String> {
    let source = source.trim();
    if let Some(path) = source.strip_prefix("file://") {
        return Ok(SourceKind::Local(path.to_string()));
    }
    if source.starts_with("http://") || source.starts_with("https://") {
        return Ok(SourceKind::Broker(source.to_string()));
    }
    if source.is_empty() {
        return Err("broker URL is required".into());
    }
    Ok(SourceKind::Local(source.to_string()))
}

/// `EnforceSecureBrokerURL` (url.go:16): HTTPS everywhere; plain HTTP only
/// for loopback development; no user info.
pub(crate) fn enforce_secure_broker_url(base_url: &str) -> Result<url::Url, String> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err("broker URL is required".into());
    }
    let parsed =
        url::Url::parse(trimmed).map_err(|e| format!("parse broker URL: {e}"))?;
    if !parsed.has_host() {
        return Err("broker URL must include scheme and host".into());
    }
    if !parsed.username().is_empty() {
        return Err("broker URL must not contain user information".into());
    }
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" => {
            if host_is_loopback(parsed.host_str().unwrap_or("")) {
                Ok(parsed)
            } else {
                Err(format!(
                    "refusing cleartext broker URL \"{trimmed}\": use https \
                     (plain http is allowed only to localhost)"
                ))
            }
        },
        other => Err(format!("broker URL scheme must be https, got \"{other}\"")),
    }
}

/// `RelayListURL` (url.go:87): resolve `GET {base}/api/v1/relays` with the
/// effective limit echoed into the query string.
fn relay_list_url(base_url: &str, limit: i64) -> Result<String, String> {
    let mut parsed = enforce_secure_broker_url(base_url)?;
    let base_path = parsed.path().trim_matches('/').to_string();
    let path = if base_path.is_empty() {
        "/api/v1/relays".to_string()
    } else {
        format!("/{base_path}/api/v1/relays")
    };
    parsed.set_path(&path);
    parsed.set_query(Some(&format!("limit={}", effective_relay_limit(limit))));
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

/// Per-front fetch outcome lines for the all-fronts-failed diagnostic.
type BrokerFetch = (Vec<u8>, Option<String>, RelayEndpoint);

/// Format the all-fronts-failed diagnostic: every candidate URL with its own
/// reason, so a dead primary never leaves anyone hunting for the backups.
fn format_front_failures(failures: &[(String, String)]) -> String {
    let mut out = format!(
        "all OpenRung broker fronts failed ({} tried):\n",
        failures.len()
    );
    for (url, err) in failures {
        out.push_str(&format!("  - {url}: {err}\n"));
    }
    out
}

/// Try every broker front in [`broker_candidates`] order, returning the first
/// successful `(body, signature header, endpoint)`. The built-in order is the
/// Cloudflare front, then the CloudFront mirror front, then the Azure Front
/// Door fallback; a genuine custom primary is tried before all of them. If
/// every candidate fails, the error lists each front with its own reason.
async fn fetch_broker_with_failover(
    base: &str, ua: &str,
) -> Result<BrokerFetch, String> {
    fetch_broker_fronts(&broker_candidates(base), ua).await
}

/// Whether this front is fetched with the embedded ECH offer. Only the
/// Cloudflare front needs it: its identity leaks through the ClientHello SNI
/// ("broker.openrung.org" is a project fingerprint) and is hidden behind the
/// ECH config's neutral public_name. The CloudFront/Azure fronts present
/// neutral, unguessable CDN names, so they take the plain-TLS path.
fn front_uses_ech(front: &str) -> bool {
    front == DEFAULT_BROKER_URL
}

/// Try each front in `candidates` order, returning the first successful
/// `(body, signature header, endpoint)`; the successful front's resolved
/// request URL becomes the [`RelayEndpoint::Broker`] endpoint. If every
/// candidate fails, the error lists each front with its own reason.
async fn fetch_broker_fronts(
    candidates: &[String], ua: &str,
) -> Result<BrokerFetch, String> {
    let mut failures: Vec<(String, String)> = Vec::new();
    for (index, front) in candidates.iter().enumerate() {
        let request_url = relay_list_url(front, REQUESTED_RELAY_LIMIT)?;
        if candidates.len() > 1 {
            eprintln!("OpenRung front {}/{}: {request_url}", index + 1, candidates.len());
        } else {
            eprintln!("Fetching OpenRung relay directory: {request_url}");
        }
        eprintln!("User-Agent: {ua}");
        // On ECH rejection this fetch fails closed and the failover chain
        // continues on a neutral-SNI front (see [`front_uses_ech`]).
        let fetch = if front_uses_ech(front) {
            crate::http_client::http_get_with_headers_ech(
                &request_url,
                ua,
                crate::ech::OPENRUNG_CLOUDFLARE_ECH_CONFIG_LIST,
            )
            .await
        } else {
            crate::http_client::http_get_with_headers(&request_url, ua).await
        };
        match fetch {
            Ok(resp) => {
                eprintln!("Downloaded {} bytes", resp.body.len());
                return Ok((
                    resp.body,
                    resp.relay_signature,
                    RelayEndpoint::Broker(request_url),
                ));
            },
            Err(err) => {
                eprintln!("front failed: {err}");
                failures.push((request_url, err));
            },
        }
    }
    Err(format_front_failures(&failures))
}

/// Derive the broker base URL (for WSS ticket requests) from the endpoint the
/// directory was fetched from: `https://host/api/v1/relays?limit=20` ->
/// `https://host/`. Local files have no broker.
fn broker_base_from_endpoint(endpoint: &RelayEndpoint) -> String {
    match endpoint {
        RelayEndpoint::LocalFile(_) => String::new(),
        RelayEndpoint::Broker(url) => {
            // The successful request URL is "{base}/api/v1/relays?limit=N";
            // strip everything from "/api/v1/relays" on (relay_list_url's
            // inverse, minus its query) and keep any custom base path prefix.
            match url::Url::parse(url) {
                Ok(mut parsed) => {
                    let base_path = match parsed.path().find("/api/v1/relays") {
                        Some(idx) => parsed.path()[..idx].to_string(),
                        None => parsed.path().to_string(),
                    };
                    parsed.set_path(&base_path);
                    parsed.set_query(None);
                    parsed.set_fragment(None);
                    // Keep a trailing slash so appending "/api/v1/wss/tickets"
                    // below is a plain concatenation.
                    if !parsed.path().ends_with('/') {
                        parsed.set_path(&format!("{}/", parsed.path()));
                    }
                    parsed.to_string()
                },
                Err(_) => String::new(),
            }
        },
    }
}

/// Fetch a URL/local file, verify, convert and write the anywhere config.
///
/// `source` semantics (the `--sub-openrung` value):
/// - empty / broker base URL (default [`DEFAULT_BROKER_URL`]): fetch
///   `GET {base}/api/v1/relays?limit=20` and require a valid signature;
/// - `file://` URL or local path: offline/debug import, wire validation only.
pub async fn run_openrung_import(
    source: &str, ua: &str, output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (body, signature_header, endpoint) = match classify_source(source)? {
        SourceKind::Broker(base) => fetch_broker_with_failover(&base, ua).await?,
        SourceKind::Local(path) => {
            eprintln!("Reading local OpenRung relay list: {path}");
            (std::fs::read(&path)?, None, RelayEndpoint::LocalFile(path))
        },
    };

    let now = Utc::now();
    let verified = verify_relay_list(
        pinned_relay_keys(),
        &endpoint,
        REQUESTED_RELAY_LIMIT,
        signature_header.as_deref(),
        &body,
        now,
    )?;
    if verified.signature_verified {
        eprintln!("Signature verified (key_id {})", verified.key_id);
    } else {
        eprintln!("Unsigned source accepted (loopback/local exemption)");
    }

    let relays = decode_relay_list(&verified.raw_json)?;
    eprintln!("{} relays in the verified directory", relays.len());

    let meta = ImportMeta {
        fetched_at_utc: now.to_rfc3339_opts(SecondsFormat::Secs, true),
        key_id: verified.key_id.clone(),
        not_after: serde_json::from_slice::<serde_json::Value>(
            &verified.raw_json,
        )?
        .get("not_after")
        .and_then(|v| v.as_str())
        .unwrap_or("none")
        .to_string(),
        broker_base_url: broker_base_from_endpoint(&endpoint),
    };
    let result = convert_relays(&relays, &meta)?;

    if !result.skips.is_empty() {
        eprintln!("skip: {}", result.skips.join(", "));
    }

    std::fs::write(output_path, &result.toml)?;
    eprintln!(
        "Written {output_path} ({} outbounds, {} rules; {} imported, {} skipped)",
        result.toml.matches("[[outbounds]]").count(),
        result.toml.matches("[[rules]]").count(),
        result.imported,
        result.skipped,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use chrono::TimeZone;
    use ed25519_dalek::Signer;

    const FIXTURE_BODY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/openrung_relay_list_limit5.json"
    ));
    const FIXTURE_SIG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/openrung_relay_list_limit5.signature"
    ));

    /// Deterministic test signer (not any production key).
    fn test_signer() -> (Vec<PinnedKey>, SigningKeyHelper) {
        let seed: [u8; 32] = Sha256::digest(b"anywhere openrung test seed").into();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vk = signing.verifying_key();
        (
            vec![PinnedKey {
                id: signing_key_id(&vk.to_bytes()),
                key: vk,
            }],
            SigningKeyHelper { signing },
        )
    }

    struct SigningKeyHelper {
        signing: ed25519_dalek::SigningKey,
    }

    impl SigningKeyHelper {
        fn sign_header(&self, key_id: &str, body: &[u8]) -> String {
            format!(
                "ed25519;{key_id};{}",
                STANDARD.encode(self.signing.sign(body).to_bytes())
            )
        }
        fn key_id(&self) -> String {
            signing_key_id(&self.signing.verifying_key().to_bytes())
        }
    }

    fn broker(url: &str) -> RelayEndpoint {
        RelayEndpoint::Broker(url.to_string())
    }

    /// The fixture's own not_after window: 2026-09-06T02:43:09Z..03:13:09Z.
    fn fixture_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 6, 2, 44, 0).unwrap()
    }

    // -- key derivation -----------------------------------------------------

    #[test]
    fn test_signing_key_id_matches_pinned_and_header() {
        // Independent derivation (python: sha256(unhexlify(pub)).hexdigest()[:16])
        assert_eq!(
            signing_key_id(&decode_hex_32(SIGNING_KEY_ACTIVE_HEX).unwrap()),
            "627405615601c589"
        );
        assert_eq!(
            signing_key_id(&decode_hex_32(SIGNING_KEY_STANDBY_HEX).unwrap()),
            "672f79aa99a573cd"
        );
        let keys = pinned_relay_keys();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].id, "627405615601c589");
        assert_eq!(keys[1].id, "672f79aa99a573cd");
    }

    #[test]
    fn test_effective_relay_limit() {
        // Go url.go:78 — exactly: <1 means default, no upper clamp.
        assert_eq!(effective_relay_limit(0), 5);
        assert_eq!(effective_relay_limit(-3), 5);
        assert_eq!(effective_relay_limit(1), 1);
        assert_eq!(effective_relay_limit(5), 5);
        assert_eq!(effective_relay_limit(20), 20);
        assert_eq!(effective_relay_limit(21), 21); // broker 400s, client never sends
    }

    // -- signature header ---------------------------------------------------

    #[test]
    fn test_parse_signature_header_ok_and_failures() {
        let sig = [7u8; 64];
        let header = format!("ed25519;627405615601c589;{}", STANDARD.encode(sig));
        let (key_id, decoded) = parse_relay_signature_header(&header).unwrap();
        assert_eq!(key_id, "627405615601c589");
        assert_eq!(decoded, sig);

        // missing header
        let err = parse_relay_signature_header("").unwrap_err();
        assert!(err.contains("has not enabled"), "{err}");
        // malformed (2 fields)
        assert!(parse_relay_signature_header("ed25519;short")
            .unwrap_err()
            .contains("want 3"));
        // wrong algorithm
        assert!(parse_relay_signature_header(&format!(
            "rsa;x;{}",
            STANDARD.encode(sig)
        ))
        .unwrap_err()
        .contains("unsupported"));
        // bad base64
        assert!(parse_relay_signature_header("ed25519;x;!!!")
            .unwrap_err()
            .contains("standard base64"));
        // 63-byte signature
        let short = STANDARD.encode(&sig[..63]);
        assert!(parse_relay_signature_header(&format!("ed25519;x;{short}"))
            .unwrap_err()
            .contains("63 bytes, want 64"));
    }

    // -- fixture对拍: real production body + real signature header ----------

    #[test]
    fn test_production_fixture_verifies_and_decodes() {
        let header = FIXTURE_SIG.trim();
        let verified = verify_relay_list(
            pinned_relay_keys(),
            &broker("https://broker.openrung.org/api/v1/relays?limit=5"),
            5,
            Some(header),
            FIXTURE_BODY,
            fixture_now(),
        )
        .expect("real production response must verify");
        assert!(verified.signature_verified);
        assert_eq!(verified.key_id, "627405615601c589");
        assert_eq!(verified.raw_json, FIXTURE_BODY);

        let relays = decode_relay_list(&verified.raw_json).unwrap();
        assert_eq!(relays.len(), 5);

        let first = &relays[0];
        assert_eq!(first.id, "relay_c11831d520b72eb2144df4e80f6035ce");
        assert_eq!(first.label, "breezy-yak");
        assert_eq!(first.public_host, "172.232.118.174");
        assert_eq!(first.public_port, 443);
        assert_eq!(first.protocol, "vless-reality-vision");
        assert_eq!(first.client_id, "a78f818d-a81a-478b-8d9d-2240424f1071");
        assert_eq!(first.server_name, "www.cloudflare.com");
        assert_eq!(first.flow, "xtls-rprx-vision");
        // base64url WITHOUT padding: must decode to exactly 32 bytes.
        assert!(!first.reality_public_key.contains('='));
        let pbk = URL_SAFE_NO_PAD
            .decode(&first.reality_public_key)
            .expect("reality_public_key is unpadded base64url");
        assert_eq!(pbk.len(), 32);
        assert_eq!(first.short_id, "70a0bddf9199d74f");

        let second = &relays[1];
        assert_eq!(second.label, "nimble-comet");
        assert_eq!(second.public_host, "167.233.174.156");
    }

    #[test]
    fn test_production_fixture_tampered_byte_fails() {
        let mut tampered = FIXTURE_BODY.to_vec();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 1;
        let err = verify_relay_list(
            pinned_relay_keys(),
            &broker("https://broker.openrung.org/api/v1/relays?limit=5"),
            5,
            Some(FIXTURE_SIG.trim()),
            &tampered,
            fixture_now(),
        )
        .unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn test_production_fixture_limit_echo_mismatch() {
        // Body echoes limit=5 (fetched with ?limit=5); a client claiming it
        // requested 20 must be rejected.
        let err = verify_relay_list(
            pinned_relay_keys(),
            &broker("https://broker.openrung.org/api/v1/relays?limit=5"),
            20,
            Some(FIXTURE_SIG.trim()),
            FIXTURE_BODY,
            fixture_now(),
        )
        .unwrap_err();
        assert!(err.contains("echoed limit 5"), "{err}");
    }

    #[test]
    fn test_production_fixture_freshness_window() {
        // not_after = 2026-09-06T03:13:09Z, skew = 5min.
        // exactly at the boundary (not_after == now - 5min) is allowed.
        let boundary = Utc.with_ymd_and_hms(2026, 9, 6, 3, 18, 9).unwrap();
        assert!(verify_relay_list(
            pinned_relay_keys(),
            &broker("https://broker.openrung.org/api/v1/relays?limit=5"),
            5,
            Some(FIXTURE_SIG.trim()),
            FIXTURE_BODY,
            boundary,
        )
        .is_ok());
        // one second past the boundary is expired
        let expired = Utc.with_ymd_and_hms(2026, 9, 6, 3, 18, 10).unwrap();
        let err = verify_relay_list(
            pinned_relay_keys(),
            &broker("https://broker.openrung.org/api/v1/relays?limit=5"),
            5,
            Some(FIXTURE_SIG.trim()),
            FIXTURE_BODY,
            expired,
        )
        .unwrap_err();
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn test_production_fixture_standby_key_ordering() {
        // The header key_id (active) is tried first; standby second — a valid
        // body must verify regardless of the order in the pinned list.
        let reversed: Vec<PinnedKey> =
            pinned_relay_keys().iter().rev().cloned().collect();
        assert!(verify_relay_list(
            &reversed,
            &broker("https://broker.openrung.org/api/v1/relays?limit=5"),
            5,
            Some(FIXTURE_SIG.trim()),
            FIXTURE_BODY,
            fixture_now(),
        )
        .is_ok());
    }

    // -- envelope / schema failures on synthetic bodies (Go parity) ---------

    #[test]
    fn test_envelope_rejections() {
        let (keys, signer) = test_signer();
        let key_id = signer.key_id();
        let endpoint = broker("https://broker.example/api/v1/relays");

        let mirror = br#"{"not_after":"2026-07-10T00:30:00Z","channel":"mirror","limit":1,"relays":[]}"#;
        let inventory = br#"{"not_after":"2026-07-10T00:30:00Z","channel":"inventory","relays":[]}"#;
        let no_expiry = br#"{"channel":"api","limit":1,"relays":[]}"#;
        let invalid_json = br#"{"channel":"#;
        let bad_port = br#"{"not_after":"2026-07-10T00:30:00Z","channel":"api","limit":1,"relays":[{"public_port":"not-an-integer"}]}"#;
        let valid_relay = br#"{"count":1,"server_time":"2026-07-10T00:00:00Z","not_after":"2026-07-10T00:30:00Z","channel":"api","limit":1,"relays":[{"id":"r","public_host":"192.0.2.1","public_port":443,"protocol":"vless-reality-vision","client_id":"c","reality_public_key":"key","short_id":"01","server_name":"example.com","flow":"xtls-rprx-vision","exit_mode":"direct","max_sessions":1,"max_mbps":10,"volunteer_version":"1.0.0","registered_at":"2026-07-10T00:00:00Z","last_heartbeat_at":"2026-07-10T00:00:00Z","expires_at":"2026-07-10T00:10:00Z","wss_fronts":[{"id":"front","url":"wss://relay.example/bridge","protocol_version":1}]}]}"#;
        let missing_field: Vec<u8> = String::from_utf8(valid_relay.to_vec())
            .unwrap()
            .replace("\"client_id\":\"c\",", "")
            .into_bytes();
        let unknown_wss: Vec<u8> = String::from_utf8(valid_relay.to_vec())
            .unwrap()
            .replace(
                "\"protocol_version\":1",
                "\"protocol_version\":1,\"unexpected\":true",
            )
            .into_bytes();
        assert!(validate_relay_list_wire(valid_relay).is_ok());

        let now = Utc.with_ymd_and_hms(2026, 7, 10, 0, 5, 0).unwrap();

        let case = |body: &[u8], limit: i64, want: &str| {
            let header = signer.sign_header(&key_id, body);
            let err = verify_relay_list(
                &keys, &endpoint, limit, Some(&header), body, now,
            )
            .unwrap_err();
            assert!(
                err.starts_with("unsigned/invalid relay list:"),
                "{err}"
            );
            assert!(err.contains(want), "error {err} lacks {want:?}");
        };

        // channel must be the API channel (mirror/inventory replay rejected)
        case(mirror, 1, "channel");
        case(inventory, 1, "channel");
        // missing expiry
        case(no_expiry, 1, "no not_after");
        // broken JSON
        case(invalid_json, 1, "not valid JSON");
        // wire schema
        case(bad_port, 1, "wire schema");
        case(&missing_field, 1, "wire schema");
        case(&unknown_wss, 1, "wire schema");
        // echoed limit mismatch
        case(valid_relay, 2, "echoed limit 1 does not match requested limit 2");
        // ...and the same body verifies at the matching limit
        let header = signer.sign_header(&key_id, valid_relay);
        let ok = verify_relay_list(
            &keys, &endpoint, 1, Some(&header), valid_relay, now,
        )
        .unwrap();
        assert!(ok.signature_verified);
        assert_eq!(ok.key_id, key_id);
    }

    #[test]
    fn test_unpinned_and_advisory_key_id() {
        let (keys, real_signer) = test_signer();
        let endpoint = broker("https://broker.example/api/v1/relays");
        let now = Utc.with_ymd_and_hms(2026, 7, 10, 0, 5, 0).unwrap();
        let body = br#"{"count":0,"server_time":"2026-07-10T00:00:00Z","not_after":"2026-07-10T00:30:00Z","channel":"api","limit":1,"relays":[]}"#;

        // signed under a key that is NOT pinned
        let outsider_seed: [u8; 32] = Sha256::digest(b"outsider seed").into();
        let outsider = ed25519_dalek::SigningKey::from_bytes(&outsider_seed);
        let header = format!(
            "ed25519;{};{}",
            signing_key_id(&outsider.verifying_key().to_bytes()),
            STANDARD.encode(outsider.sign(body).to_bytes())
        );
        let err =
            verify_relay_list(&keys, &endpoint, 1, Some(&header), body, now)
                .unwrap_err();
        assert!(err.contains("does not verify"), "{err}");

        // lying/unknown key_id in the header must not block the pinned key
        let decoy_seed: [u8; 32] = Sha256::digest(b"decoy seed").into();
        let decoy = ed25519_dalek::SigningKey::from_bytes(&decoy_seed);
        let mut keys_with_decoy = vec![PinnedKey {
            id: "deadbeefdeadbeef".to_string(),
            key: decoy.verifying_key(),
        }];
        keys_with_decoy.extend(keys.clone());
        let header = format!(
            "ed25519;deadbeefdeadbeef;{}",
            STANDARD.encode(real_signer.signing.sign(body).to_bytes())
        );
        let ok = verify_relay_list(
            &keys_with_decoy, &endpoint, 1, Some(&header), body, now,
        )
        .expect("advisory unknown key id must not block fallback");
        assert_eq!(ok.key_id, real_signer.key_id());
    }

    #[test]
    fn test_limit_echo_defaults_to_five() {
        // A body echoing limit=5 verifies with requested_limit 0 (default),
        // not with 1.
        let (keys, signer) = test_signer();
        let key_id = signer.key_id();
        let endpoint = broker("https://broker.example/api/v1/relays");
        let now = Utc.with_ymd_and_hms(2026, 7, 10, 0, 5, 0).unwrap();
        let body =
            br#"{"count":0,"server_time":"2026-07-10T00:00:00Z","not_after":"2026-07-10T00:30:00Z","channel":"api","limit":5,"relays":[]}"#;
        let header = signer.sign_header(&key_id, body);
        assert!(verify_relay_list(
            &keys, &endpoint, 0, Some(&header), body, now,
        )
        .is_ok());
        let err = verify_relay_list(
            &keys, &endpoint, 1, Some(&header), body, now,
        )
        .unwrap_err();
        assert!(err.contains("echoed limit 5"), "{err}");
    }

    // -- loopback exemption (Go parity) --------------------------------------

    #[test]
    fn test_loopback_only_exemption() {
        let body =
            br#"{"count":0,"server_time":"2026-07-24T00:00:00Z","relays":[]}"#;
        let now = Utc::now();

        // 127.0.0.1: unsigned accepted, wire schema enforced
        let ok = verify_relay_list(
            &[],
            &broker("http://127.0.0.1:8080/api/v1/relays"),
            5,
            None,
            body,
            now,
        )
        .unwrap();
        assert!(!ok.signature_verified);
        assert_eq!(ok.key_id, "");

        // localhost (exact) is loopback
        assert!(verify_relay_list(
            &[],
            &broker("http://localhost:8080/api/v1/relays"),
            5,
            None,
            body,
            now,
        )
        .is_ok());

        // localhost.example is NOT loopback: unsigned rejected
        let err = verify_relay_list(
            &[],
            &broker("http://localhost.example/api/v1/relays"),
            5,
            None,
            body,
            now,
        )
        .unwrap_err();
        assert!(err.contains("has not enabled"), "{err}");

        // real broker without header: rejected
        assert!(verify_relay_list(
            &[],
            &broker("https://broker.example/api/v1/relays"),
            5,
            None,
            body,
            now,
        )
        .is_err());

        // local file: same development channel, wire schema enforced
        let ok = verify_relay_list(
            &[],
            &RelayEndpoint::LocalFile("/tmp/relays.json".into()),
            5,
            None,
            body,
            now,
        )
        .unwrap();
        assert!(!ok.signature_verified);

        // loopback still rejects bodies failing the wire schema
        let err = verify_relay_list(
            &[],
            &broker("http://127.0.0.1:8080/api/v1/relays"),
            5,
            None,
            br#"{"count":0,"relays":[]}"#,
            now,
        )
        .unwrap_err();
        assert!(err.contains("requires count, server_time"), "{err}");
    }

    // -- conversion -----------------------------------------------------------

    fn sample_relay(id: &str, label: &str, pbk: &str, sid: &str) -> OpenrungRelay {
        OpenrungRelay {
            id: id.to_string(),
            label: label.to_string(),
            public_host: "192.0.2.1".to_string(),
            public_port: 443,
            protocol: PROTOCOL_VLESS_REALITY_VISION.to_string(),
            client_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            reality_public_key: pbk.to_string(),
            short_id: sid.to_string(),
            server_name: "www.cloudflare.com".to_string(),
            flow: "xtls-rprx-vision".to_string(),
            node_class: "foundation".to_string(),
            exit_mode: "direct".to_string(),
            transport: "direct".to_string(),
            wss_fronts: Vec::new(),
        }
    }

    const VALID_PBK: &str = "l0TU3ZZfpjse2yLir81_sdD_4sYrY73oYng_A0vyKS0";

    #[test]
    fn test_convert_roundtrip_via_config() {
        let relays = vec![
            sample_relay("relay_aaa111", "alpha", VALID_PBK, "70a0bddf9199d74f"),
            OpenrungRelay {
                // pure REALITY: empty flow is legal
                flow: String::new(),
                ..sample_relay("relay_bbb222", "beta", VALID_PBK, "")
            },
            sample_relay("relay_ccc333", "alpha", VALID_PBK, "01"),
        ];
        let meta = ImportMeta {
            fetched_at_utc: "2026-09-06T02:44:00+00:00".to_string(),
            key_id: "627405615601c589".to_string(),
            not_after: "2026-09-06T03:13:09Z".to_string(),
            broker_base_url: String::new(),
        };
        let result = convert_relays(&relays, &meta).unwrap();
        assert_eq!(result.imported, 3);
        assert_eq!(result.skipped, 0);

        let toml = &result.toml;
        assert!(toml.starts_with("# Generated by anywhere --sub-openrung"));
        assert!(toml.contains("# Signature: key_id 627405615601c589"));
        assert!(toml.contains("# List not_after: 2026-09-06T03:13:09Z"));
        assert!(toml.contains("# Nodes: 3 imported, 0 skipped"));
        assert_eq!(toml.matches("[[outbounds]]").count(), 4); // 3 nodes + group
        assert_eq!(toml.matches("[[rules]]").count(), 1);
        assert!(toml.contains("outbound = \"openrung\""));
        // label dedup with id suffix
        assert!(toml.contains("tag = \"alpha\""));
        assert!(toml.contains("tag = \"alpha.ccc333\""));
        assert!(toml.contains("tag = \"beta\""));
        assert!(toml.contains("server = \"192.0.2.1:443\""));
        assert!(toml.contains("password = \"01234567-89ab-cdef-0123-456789abcdef\""));
        assert!(toml.contains("[outbounds.reality]"));
        assert!(toml.contains(&format!("public_key = \"{VALID_PBK}\"")));

        // The output must load back through anywhere's config parser.
        let cfg = crate::config::Config::from_string(toml)
            .expect("generated TOML must parse as an anywhere config");
        // runnable as-is: one socks5 inbound on 10808
        assert_eq!(cfg.inbounds.len(), 1);
        assert_eq!(cfg.inbounds[0].type_, "socks5");
        assert_eq!(cfg.inbounds[0].listen.as_deref(), Some("127.0.0.1:10808"));
        assert_eq!(cfg.outbounds.len(), 4);
        let group = cfg
            .outbounds
            .iter()
            .find(|o| o.type_ == "urltest")
            .expect("urltest group");
        assert_eq!(group.tag.as_deref(), Some("openrung"));
        assert_eq!(
            group.outbounds.as_ref().unwrap(),
            &vec![
                "alpha".to_string(),
                "beta".to_string(),
                "alpha.ccc333".to_string()
            ]
        );
        // mode/interval/url left at anywhere's defaults
        assert!(group.mode.is_none());
        assert!(group.interval.is_none());
        assert!(group.url.is_none());
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].outbound, "openrung");

        // node fields survive the roundtrip
        let alpha = &cfg.outbounds[0];
        assert_eq!(alpha.type_, "vless");
        assert_eq!(alpha.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(alpha.sni.as_deref(), Some("www.cloudflare.com"));
        let reality = alpha.reality.as_ref().unwrap();
        assert!(reality.parse().is_ok());
        let beta = &cfg.outbounds[1];
        assert_eq!(beta.flow, None); // empty flow omitted
        assert!(beta.reality.is_some());
    }

    #[test]
    fn test_convert_skips_invalid_reality_and_other_protocols() {
        let relays = vec![
            sample_relay("relay_ok1", "ok", VALID_PBK, "01"),
            sample_relay("relay_badpbk", "badpbk", "not-base64!!", "01"),
            sample_relay("relay_badsid", "badsid", VALID_PBK, "zzzz"),
            sample_relay("relay_longsid", "longsid", VALID_PBK, "00112233445566778899"),
            OpenrungRelay {
                protocol: "anytls".to_string(),
                ..sample_relay("relay_other", "other", VALID_PBK, "01")
            },
            // empty reality_public_key fails RealityConfig::parse
            sample_relay("relay_nopbk", "nopbk", "", "01"),
        ];
        let result =
            convert_relays(&relays, &ImportMeta::default()).unwrap();
        assert_eq!(result.imported, 1);
        assert_eq!(result.skipped, 5);
        assert_eq!(result.toml.matches("[[outbounds]]").count(), 2); // 1 node + group
        assert!(result.toml.contains("tag = \"ok\""));
        assert!(!result.toml.contains("badpbk"));
    }

    #[test]
    fn test_convert_missing_label_uses_id() {
        let relays = vec![sample_relay("relay_xyz789", "", VALID_PBK, "01")];
        let result =
            convert_relays(&relays, &ImportMeta::default()).unwrap();
        assert!(result.toml.contains("tag = \"relay_xyz789\""));
    }

    #[test]
    fn test_ipv6_host_is_bracketed() {
        let mut relay = sample_relay("relay_v6", "v6node", VALID_PBK, "01");
        relay.public_host = "2408:8207:1942:c890:fa17:7e97:ce0a:a4e6".into();
        let result =
            convert_relays(&[relay], &ImportMeta::default()).unwrap();
        assert!(result
            .toml
            .contains("server = \"[2408:8207:1942:c890:fa17:7e97:ce0a:a4e6]:443\""));
        // the bracketed form must parse as a SocketAddr (anywhere resolve_addr)
        let cfg = crate::config::Config::from_string(&result.toml).unwrap();
        let server = cfg.outbounds[0].server.as_deref().unwrap();
        let addr: std::net::SocketAddr = server.parse().expect("bracketed IPv6 server parses");
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn test_convert_all_filtered_out_is_error() {
        let relays = vec![OpenrungRelay {
            protocol: "anytls".to_string(),
            ..sample_relay("relay_x", "x", VALID_PBK, "01")
        }];
        assert!(convert_relays(&relays, &ImportMeta::default()).is_err());
    }

    // -- wss fronts: decode / eligibility / TOML emission --------------------

    #[test]
    fn test_production_fixture_decodes_fronts() {
        let relays = decode_relay_list(FIXTURE_BODY).unwrap();
        let first = &relays[0];
        assert_eq!(first.node_class, "foundation");
        assert_eq!(first.exit_mode, "direct");
        assert_eq!(first.transport, "direct");
        assert_eq!(first.wss_fronts.len(), 1);
        assert_eq!(first.wss_fronts[0].id, "breezy-yak-bunny-a");
        assert_eq!(
            first.wss_fronts[0].url,
            "wss://edgefe20d6ac5ec5b414a3a8.b-cdn.net/api/v1/wss-bridge"
        );
        assert_eq!(first.wss_fronts[0].protocol_version, 1);
        // The fourth fixture relay advertises no fronts.
        assert!(relays[3].wss_fronts.is_empty());
    }

    #[test]
    fn test_convert_emits_fronts_and_fallback() {
        let mut relay = sample_relay("relay_wss1", "wssnode", VALID_PBK, "01");
        relay.wss_fronts = vec![
            crate::wssfront::WssFront::new(
                "a-front",
                "wss://a.b-cdn.net/api/v1/wss-bridge",
            ),
            crate::wssfront::WssFront::new(
                "b-front",
                "wss://b.b-cdn.net/api/v1/wss-bridge",
            ),
        ];
        let meta = ImportMeta {
            broker_base_url: "https://broker.openrung.org/".to_string(),
            ..Default::default()
        };
        let result = convert_relays(&[relay], &meta).unwrap();
        let toml = &result.toml;
        assert!(toml.contains("[[outbounds.wss_fronts]]"), "{toml}");
        assert!(toml.contains("id = \"a-front\""));
        assert!(toml.contains("id = \"b-front\""));
        assert!(toml.contains(
            "url = \"wss://a.b-cdn.net/api/v1/wss-bridge\""
        ));
        assert!(toml.contains("protocol_version = 1"));
        assert!(toml.contains("[outbounds.wss_fallback]"));
        assert!(toml.contains("broker = \"https://broker.openrung.org/\""));

        // Round-trip through anywhere's config parser.
        let cfg = crate::config::Config::from_string(toml).unwrap();
        let ob = &cfg.outbounds[0];
        let fronts = ob.wss_fronts.as_ref().unwrap();
        assert_eq!(fronts.len(), 2);
        assert_eq!(fronts[0].id, "a-front");
        assert_eq!(fronts[1].url, "wss://b.b-cdn.net/api/v1/wss-bridge");
        assert_eq!(fronts[1].protocol_version, 1);
        let fb = ob.wss_fallback.as_ref().unwrap();
        assert_eq!(fb.broker.as_deref(), Some("https://broker.openrung.org/"));
    }

    #[test]
    fn test_convert_fronts_without_broker_keeps_fronts_drops_fallback() {
        let mut relay = sample_relay("relay_wss2", "wssnode2", VALID_PBK, "01");
        relay.wss_fronts = vec![crate::wssfront::WssFront::new(
            "a-front",
            "wss://a.b-cdn.net/api/v1/wss-bridge",
        )];
        let result =
            convert_relays(std::slice::from_ref(&relay), &ImportMeta::default())
                .unwrap();
        assert!(result.toml.contains("[[outbounds.wss_fronts]]"));
        assert!(!result.toml.contains("[outbounds.wss_fallback]"));
    }

    #[test]
    fn test_convert_omits_unusable_front_sets() {
        // Volunteer class → fronts unusable (Go supportedWSSFronts).
        let mut relay = sample_relay("relay_vol", "vol", VALID_PBK, "01");
        relay.node_class = "volunteer".to_string();
        relay.wss_fronts = vec![crate::wssfront::WssFront::new(
            "a-front",
            "wss://a.b-cdn.net/api/v1/wss-bridge",
        )];
        let result =
            convert_relays(std::slice::from_ref(&relay), &ImportMeta::default())
                .unwrap();
        assert!(!result.toml.contains("[[outbounds.wss_fronts]]"));

        // Non-canonical front URL → silently no fronts (never repaired).
        let mut relay = sample_relay("relay_badurl", "badurl", VALID_PBK, "01");
        relay.wss_fronts = vec![crate::wssfront::WssFront::new(
            "a-front",
            "wss://a.b-cdn.net:8443/api/v1/wss-bridge",
        )];
        let result =
            convert_relays(std::slice::from_ref(&relay), &ImportMeta::default())
                .unwrap();
        assert!(!result.toml.contains("[[outbounds.wss_fronts]]"));

        // More than four fronts → no fronts.
        let mut relay = sample_relay("relay_many", "many", VALID_PBK, "01");
        relay.wss_fronts = (0..5)
            .map(|i| {
                crate::wssfront::WssFront::new(
                    &format!("f{i}"),
                    &format!("wss://f{i}.b-cdn.net/api/v1/wss-bridge"),
                )
            })
            .collect();
        let result =
            convert_relays(std::slice::from_ref(&relay), &ImportMeta::default())
                .unwrap();
        assert!(!result.toml.contains("[[outbounds.wss_fronts]]"));

        // Unsorted front set → no fronts (Go: !slices.Equal → nil).
        let mut relay =
            sample_relay("relay_unsorted", "unsorted", VALID_PBK, "01");
        relay.wss_fronts = vec![
            crate::wssfront::WssFront::new(
                "b-front",
                "wss://b.b-cdn.net/api/v1/wss-bridge",
            ),
            crate::wssfront::WssFront::new(
                "a-front",
                "wss://a.b-cdn.net/api/v1/wss-bridge",
            ),
        ];
        let result =
            convert_relays(std::slice::from_ref(&relay), &ImportMeta::default())
                .unwrap();
        assert!(!result.toml.contains("[[outbounds.wss_fronts]]"));
    }

    #[test]
    fn test_wire_decode_front_missing_field_rejected() {
        // The strict front decode (Go relayWSSFront.UnmarshalJSON) requires
        // all three fields: dropping the URL must fail the wire check.
        let with_front = br#"{"count":1,"server_time":"2026-07-10T00:00:00Z","not_after":"2026-07-10T00:30:00Z","channel":"api","limit":1,"relays":[{"id":"r","public_host":"192.0.2.1","public_port":443,"protocol":"vless-reality-vision","client_id":"c","reality_public_key":"key","short_id":"01","server_name":"example.com","flow":"xtls-rprx-vision","exit_mode":"direct","max_sessions":1,"max_mbps":10,"volunteer_version":"1.0.0","registered_at":"2026-07-10T00:00:00Z","last_heartbeat_at":"2026-07-10T00:00:00Z","expires_at":"2026-07-10T00:10:00Z","wss_fronts":[{"id":"front","protocol_version":1}]}]}"#;
        let err = validate_relay_list_wire(with_front).unwrap_err();
        assert!(err.contains("wire schema") || err.contains("decode"), "{err}");
    }

    #[test]
    fn test_broker_base_from_endpoint() {
        assert_eq!(
            broker_base_from_endpoint(&RelayEndpoint::Broker(
                "https://broker.openrung.org/api/v1/relays?limit=20".to_string()
            )),
            "https://broker.openrung.org/"
        );
        // Custom base path is preserved.
        assert_eq!(
            broker_base_from_endpoint(&RelayEndpoint::Broker(
                "https://cdn.example.com/or/api/v1/relays?limit=20".to_string()
            )),
            "https://cdn.example.com/or/"
        );
        assert_eq!(
            broker_base_from_endpoint(&RelayEndpoint::LocalFile(
                "/tmp/relays.json".to_string()
            )),
            ""
        );
    }

    // -- source classification / URL building --------------------------------

    #[test]
    fn test_classify_source() {
        assert!(matches!(
            classify_source("https://broker.openrung.org/"),
            Ok(SourceKind::Broker(_))
        ));
        assert!(matches!(
            classify_source("http://127.0.0.1:8080"),
            Ok(SourceKind::Broker(_))
        ));
        assert!(matches!(
            classify_source("file:///tmp/relays.json"),
            Ok(SourceKind::Local(path)) if path == "/tmp/relays.json"
        ));
        assert!(matches!(
            classify_source("/tmp/relays.json"),
            Ok(SourceKind::Local(_))
        ));
        assert!(classify_source("").is_err());
    }

    #[test]
    fn test_relay_list_url() {
        assert_eq!(
            relay_list_url("https://broker.openrung.org/", 20).unwrap(),
            "https://broker.openrung.org/api/v1/relays?limit=20"
        );
        assert_eq!(
            relay_list_url("https://broker.openrung.org", 0).unwrap(),
            "https://broker.openrung.org/api/v1/relays?limit=5"
        );
        // non-loopback cleartext is refused (Go EnforceSecureBrokerURL)
        assert!(relay_list_url("http://broker.openrung.org", 20).is_err());
        // loopback cleartext is allowed
        assert!(relay_list_url("http://127.0.0.1:8080", 20).is_ok());
        // user info refused
        assert!(relay_list_url("https://u:p@broker.openrung.org", 20).is_err());
    }

    #[test]
    fn broker_candidates_default_order() {
        assert_eq!(
            broker_candidates(""),
            vec![
                DEFAULT_BROKER_URL.to_string(),
                CLOUDFRONT_BROKER_URL.to_string(),
                AZURE_BROKER_URL.to_string(),
            ]
        );
        // passing a built-in front explicitly must not reorder or duplicate
        assert_eq!(
            broker_candidates(CLOUDFRONT_BROKER_URL),
            vec![
                DEFAULT_BROKER_URL.to_string(),
                CLOUDFRONT_BROKER_URL.to_string(),
                AZURE_BROKER_URL.to_string(),
            ]
        );
    }

    #[test]
    fn broker_candidates_custom_primary_leads_then_defaults() {
        let candidates = broker_candidates("https://broker.example.org/");
        assert_eq!(candidates[0], "https://broker.example.org/");
        assert_eq!(
            &candidates[1..],
            &[
                DEFAULT_BROKER_URL.to_string(),
                CLOUDFRONT_BROKER_URL.to_string(),
                AZURE_BROKER_URL.to_string(),
            ]
        );
    }

    #[test]
    fn format_front_failures_lists_every_front() {
        let failures = vec![
            (
                "https://a.example/api/v1/relays?limit=20".to_string(),
                "connect refused".to_string(),
            ),
            (
                "https://b.example/api/v1/relays?limit=20".to_string(),
                "timeout".to_string(),
            ),
        ];
        let text = format_front_failures(&failures);
        assert!(text.contains("2 tried"));
        assert!(text.contains("https://a.example/api/v1/relays?limit=20: connect refused"));
        assert!(text.contains("https://b.example/api/v1/relays?limit=20: timeout"));
    }

    // -- broker front failover (local loopback servers, no network) ----------

    /// Bind and immediately drop a loopback listener; its port now refuses
    /// connections deterministically (ECONNREFUSED on loopback, no packets
    /// leave the machine).
    fn refused_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    const HEAD_END: &[u8] = b"\r\n\r\n";

    /// Build an HTTP/1.1 response with extra headers and a fixed body.
    fn http_response(extra_headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut head = String::from("HTTP/1.1 200 OK\r\n");
        for (name, value) in extra_headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!("content-length: {}\r\n", body.len()));
        head.push_str("connection: close\r\n\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// A minimal loopback HTTP front answering every connection with
    /// `response` until dropped. Returns its base URL
    /// (`http://127.0.0.1:PORT/` — loopback cleartext is allowed by
    /// [`enforce_secure_broker_url`]).
    async fn spawn_local_front(response: Vec<u8>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let response = response.clone();
                tokio::spawn(async move {
                    // Drain the request head before answering; the client is
                    // hyper with Connection: close, one request per socket.
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while buf.windows(HEAD_END.len()).all(|w| w != HEAD_END) {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = sock.write_all(&response).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        format!("http://{addr}/")
    }

    #[test]
    fn ech_offer_only_on_the_default_front() {
        // The Cloudflare front's SNI is a project fingerprint, so it is the
        // only front fetched with the ECH offer; the CDN fronts present
        // neutral, unguessable names and take the plain-TLS path.
        assert!(front_uses_ech(DEFAULT_BROKER_URL));
        assert!(!front_uses_ech(CLOUDFRONT_BROKER_URL));
        assert!(!front_uses_ech(AZURE_BROKER_URL));
        assert!(!front_uses_ech("http://127.0.0.1:8080/"));
    }

    #[tokio::test]
    async fn fetch_failover_serves_from_next_front_with_its_url() {
        let (_, signer) = test_signer();
        let body = FIXTURE_BODY.to_vec();
        let sig = signer.sign_header(&signer.key_id(), &body);
        let dead = format!("http://127.0.0.1:{}/", refused_port());
        let live = spawn_local_front(http_response(
            &[("X-OpenRung-Relays-Signature", &sig)],
            &body,
        ))
        .await;

        // Dead primary first, live front second: the chain must move on.
        let candidates = vec![dead, live.clone()];
        let (fetched, fetched_sig, endpoint) =
            fetch_broker_fronts(&candidates, "anywhere-test").await.unwrap();

        // The live front's bytes and its relayed signature header came
        // through verbatim (the header is what verification binds to).
        assert_eq!(fetched, body);
        assert_eq!(fetched_sig.as_deref(), Some(sig.as_str()));
        // The successful front's URL is the authenticated endpoint.
        assert_eq!(
            endpoint,
            RelayEndpoint::Broker(format!("{live}api/v1/relays?limit=20"))
        );
    }

    #[tokio::test]
    async fn fetch_first_success_wins_over_later_fronts() {
        let (_, signer) = test_signer();
        let body = FIXTURE_BODY.to_vec();
        let sig = signer.sign_header(&signer.key_id(), &body);
        let response =
            http_response(&[("X-OpenRung-Relays-Signature", &sig)], &body);
        let first = spawn_local_front(response.clone()).await;
        let second = spawn_local_front(response).await;
        assert_ne!(first, second);

        // Both fronts work: the first candidate (a working custom primary
        // sitting ahead of the built-ins) must be used, not skipped.
        let candidates = vec![first.clone(), second];
        let (_, _, endpoint) =
            fetch_broker_fronts(&candidates, "anywhere-test").await.unwrap();
        assert_eq!(
            endpoint,
            RelayEndpoint::Broker(format!("{first}api/v1/relays?limit=20"))
        );
    }

    #[tokio::test]
    async fn fetch_all_fronts_failure_lists_each_front_reason() {
        let dead1 = format!("http://127.0.0.1:{}/", refused_port());
        let dead2 = format!("http://127.0.0.1:{}/", refused_port());
        let candidates = vec![dead1, dead2];
        let err = fetch_broker_fronts(&candidates, "anywhere-test")
            .await
            .unwrap_err();

        assert!(
            err.contains("all OpenRung broker fronts failed (2 tried)"),
            "{err}"
        );
        // Every front is listed with its own reason line.
        for base in &candidates {
            let url = relay_list_url(base, REQUESTED_RELAY_LIMIT).unwrap();
            assert!(err.contains(&format!("- {url}: ")), "{err}");
        }
        assert_eq!(err.matches("Connection refused").count(), 2, "{err}");
    }
}
