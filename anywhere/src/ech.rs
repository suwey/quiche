// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! ECH (Encrypted Client Hello) — shared handling for every outbound path.
//!
//! anywhere's TLS connections fall into two classes, and this module is the
//! single home for the ECH logic of the first one:
//!
//! - **anywhere is the TLS client** (proxy-node connections: vless+ws+tls,
//!   anytls, quic; and the `--sub-openrung` broker fetch): ECH applies, and
//!   every path goes through [`apply_ech_offer`] / [`verify_ech_outcome`]
//!   here.
//! - **anywhere only ferries bytes** (REALITY data path, end-to-end TLS of
//!   proxied target websites): the ClientHello is written by someone else —
//!   REALITY by design borrows the target's SNI, and proxied target TLS is
//!   written by the user's application. ECH must never be injected there.
//!
//! Semantics (aligned with Chrome / BoringSSL):
//!
//! - `ech = true` acquires the ECHConfigList from the outbound host's DNS
//!   **HTTPS (type 65) record** — the same bootstrap browsers use, served
//!   through anywhere's own DNS upstreams (DoH first). An explicit
//!   `ech_config` (base64) overrides the DNS lookup.
//! - No published config → connect without an ECH offer (nothing to hide
//!   behind, browser-identical behavior).
//! - Offer rejected by the server → **fail-closed**: the handshake completed
//!   against the config's public_name, not the node — connecting anyway would
//!   defeat the hiding. Never silently downgrade to plaintext SNI; that is
//!   exactly what an active downgrader wants. (One automatic re-offer with
//!   server-provided retry configs is future work; the auto path self-heals
//!   because the config comes fresh from DNS.)

use base64::Engine as _;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Cloudflare's ECH public name: the ClientHelloOuter SNI for any host whose
/// ECH offer uses Cloudflare's config. Neutral — hiding the real SNI hides it
/// even when the offer is rejected and the handshake falls back to outer
/// parameters.
pub const CLOUDFLARE_ECH_PUBLIC_NAME: &str = "cloudflare-ech.com";

/// openrung's embedded Cloudflare ECHConfigList (brokerapi/transport.go:33,
/// including the outer u16 length). Deliberately compiled in — resolving it
/// via DNS HTTPS/SVCB would reintroduce the plaintext bootstrap that ECH
/// exists to protect. Captured from an authenticated retry 2026-07-24
/// upstream; refresh from a new openrung release when they rotate it.
pub const OPENRUNG_CLOUDFLARE_ECH_CONFIG_LIST: &[u8] = &[
    0x00, 0x45, 0xfe, 0x0d, 0x00, 0x41, 0x19, 0x00, 0x20, 0x00, 0x20, 0xe2,
    0xaf, 0xd5, 0x98, 0x82, 0xdc, 0xb5, 0xfd, 0xcd, 0xc8, 0x84, 0x9c, 0x8e,
    0x40, 0x33, 0x7b, 0xff, 0xda, 0xad, 0xca, 0x65, 0xac, 0x36, 0xcf, 0xbf,
    0x38, 0x9c, 0x56, 0xd1, 0xb6, 0x99, 0x14, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72,
    0x65, 0x2d, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
];

// ---------------------------------------------------------------------------
// Promotable Cloudflare config (openrung transport.go echConfigState pattern)
// ---------------------------------------------------------------------------

/// The broker front's ECH configs rotate; a compiled-in list goes stale.
/// When the server rejects our offer it hands back fresh retry configs, and
/// after a retry handshake that authenticates (boring verifies the inner
/// name against the real certificate) the new config is promoted here so
/// subsequent fetches offer current keys.
static PROMOTED_CLOUDFLARE_ECH_CONFIG: std::sync::RwLock<Option<Vec<u8>>> =
    std::sync::RwLock::new(None);

/// Current Cloudflare ECHConfigList for the broker front: a config promoted
/// by a successful authenticated retry, else the embedded bootstrap list.
pub fn current_cloudflare_config() -> Vec<u8> {
    std::sync::RwLock::read(&PROMOTED_CLOUDFLARE_ECH_CONFIG)
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| OPENRUNG_CLOUDFLARE_ECH_CONFIG_LIST.to_vec())
}

/// Promote a fresh Cloudflare ECHConfigList obtained from an authenticated
/// retry handshake (openrung `echConfigState.promote`).
pub fn promote_cloudflare_config(fresh: &[u8]) {
    if fresh.is_empty() {
        return;
    }
    if let Ok(mut guard) = PROMOTED_CLOUDFLARE_ECH_CONFIG.write() {
        if guard.as_deref() != Some(fresh) {
            log::info!(
                "ECH: promoted fresh Cloudflare config ({} bytes)",
                fresh.len()
            );
            *guard = Some(fresh.to_vec());
        }
    }
}

// ---------------------------------------------------------------------------
// Config sources
// ---------------------------------------------------------------------------

/// Decode an explicit `ech_config` value: opaque ECHConfigList bytes in
/// standard or URL-safe base64, with or without padding.
pub fn decode_explicit_config(b64: &str) -> Option<Vec<u8>> {
    let s = b64.trim();
    if s.is_empty() {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()
        })
        .or_else(|| {
            let padded = match s.len() % 4 {
                2 => format!("{s}=="),
                3 => format!("{s}="),
                _ => s.to_string(),
            };
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(padded.as_bytes())
                .ok()
        })?;
    (!decoded.is_empty()).then_some(decoded)
}

/// Resolve the ECHConfigList for an outbound at build time.
///
/// Priority: explicit `ech_config` (base64) > DNS HTTPS record lookup for
/// `host` through `dns_upstreams` (DoH first, plain UDP fallback). Returns
/// `None` when ECH is disabled or no config can be obtained — callers then
/// connect without an offer, exactly like today.
pub async fn acquire_outbound_config(
    host: &str, ech: bool, ech_config_b64: Option<&str>,
    dns_upstreams: &[String],
) -> Option<Vec<u8>> {
    if let Some(b64) = ech_config_b64 {
        match decode_explicit_config(b64) {
            Some(bytes) => {
                log::debug!("ECH: explicit config for {host} ({} bytes)", bytes.len());
                return Some(bytes);
            },
            None => log::warn!("ECH: failed to decode ech_config for {host}"),
        }
    }
    if !ech {
        return None;
    }
    match crate::dns::https_record::resolve_echconfig(host, dns_upstreams).await {
        Some(bytes) => {
            log::info!(
                "ECH: acquired config for {host} from DNS HTTPS record ({} bytes)",
                bytes.len()
            );
            Some(bytes)
        },
        None => {
            log::info!(
                "ECH: no HTTPS-record echconfig for {host}; connecting without ECH"
            );
            None
        },
    }
}

// ---------------------------------------------------------------------------
// BoringSSL wiring (the single offer/verify point for every TLS path)
// ---------------------------------------------------------------------------

/// What a client handshake offers in the ECH extension.
///
/// - [`EchOffer::Config`] — a real offer with this ECHConfigList: the real
///   SNI is encrypted; a server rejection fails the connection closed (see
///   [`verify_ech_outcome`]).
/// - [`EchOffer::Grease`] — a fake offer (no published config, or offered on
///   a connection with nothing to hide): the real SNI stays visible, but
///   "carries an ECH extension" stops being a distinguisher. Rejection is
///   expected and harmless (Chrome sends grease the same way).
/// - [`EchOffer::None`] — no ECH extension at all (default; byte-identical
///   to pre-ECH anywhere).
#[derive(Clone, Debug)]
pub enum EchOffer<'a> {
    None,
    Config(std::borrow::Cow<'a, [u8]>),
    Grease,
}

impl EchOffer<'static> {
    /// Derive the offer for an outbound from its config: explicit
    /// `ech_config` (base64) wins; `ech = true` without a published config
    /// degrades to grease — participating in the ECH feature without
    /// pretending to have a config.
    pub fn for_outbound(ech: bool, ech_config_b64: Option<&str>) -> Self {
        match ech_config_b64.and_then(decode_explicit_config) {
            Some(bytes) => EchOffer::Config(std::borrow::Cow::Owned(bytes)),
            None if ech => EchOffer::Grease,
            None => EchOffer::None,
        }
    }
}

/// Apply an [`EchOffer`] to a client handshake before it starts.
pub fn apply_ech_offer(
    ssl: &mut boring::ssl::SslRef, offer: &EchOffer<'_>,
) -> Result<(), String> {
    match offer {
        EchOffer::None => Ok(()),
        EchOffer::Config(list) => ssl
            .set_ech_config_list(list)
            .map_err(|e| format!("set ECH config list: {e:?}")),
        EchOffer::Grease => {
            ssl.set_enable_ech_grease(true);
            Ok(())
        },
    }
}

/// Post-handshake outcome check: only a **real** offer must have negotiated
/// ECH. A completed handshake that did not means the server rejected the
/// offer and authenticated against the neutral public_name instead — treat
/// as a connection failure rather than silently exposing the real SNI.
/// Grease offers are expected to be rejected and always pass.
pub fn verify_ech_outcome(
    ssl: &boring::ssl::SslRef, offer: &EchOffer<'_>,
) -> Result<(), String> {
    match offer {
        EchOffer::Config(_) if !ssl.ech_accepted() => Err(
            "ECH rejected by server (handshake fell back to outer parameters); \
             refusing to continue with plaintext SNI"
                .to_string(),
        ),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_explicit_accepts_std_and_urlsafe() {
        let bytes = vec![0u8, 69, 254, 13];
        let std = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert_eq!(decode_explicit_config(&std), Some(bytes.clone()));
        let urlsafe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        assert_eq!(decode_explicit_config(&urlsafe), Some(bytes));
        assert_eq!(decode_explicit_config(""), None);
        assert_eq!(decode_explicit_config("!!!not-base64!!!"), None);
    }

    #[test]
    fn openrung_embedded_config_shape() {
        // outer u16 length must equal the remaining bytes
        let list = OPENRUNG_CLOUDFLARE_ECH_CONFIG_LIST;
        let declared = u16::from_be_bytes([list[0], list[1]]) as usize;
        assert_eq!(declared + 2, list.len());
        // public_name inside the config is cloudflare-ech.com
        let text = String::from_utf8_lossy(list);
        assert!(text.contains("cloudflare-ech.com"));
    }

}
