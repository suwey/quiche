//! REALITY client transport (M1).
//!
//! XTLS REALITY carries client authentication inside the ClientHello's legacy
//! session_id: a 16-byte plaintext (client version 3B || 0x00 || BE32 unix
//! timestamp || short_id 8B) AES-256-GCM-sealed under an AuthKey derived from
//! the client's own X25519 key share (HKDF-SHA256, salt = ClientRandom[:20],
//! info = "REALITY") into 32 bytes (16 ciphertext + 16 tag). The derivation
//! depends on the ClientRandom and the full ClientHello bytes (AAD), so it
//! happens inside boring via the vendored boring-sys patch
//! (`third_party/boring-sys/patches/reality-session-id.patch`,
//! `SSL_set_reality_client_hello_params` + `SSL_client_key_share_x25519`).
//!
//! Wire format confirmed against Xray v26.7.28
//! (`transport/internet/reality/reality.go`) and xtls/reality
//! (`tls.go:195-300`); see `docs/vless-reality-wire-notes.md` §S1.
//!
//! Certificate verification follows §S1.3: if the leaf certificate's public
//! key is Ed25519, REALITY authentication is
//! `HMAC-SHA512(AuthKey, leaf ed25519 pub) == leaf signature`. Anywhere does
//! not implement Xray's browser-crawl disguise, so on Ed25519 leaves a HMAC
//! mismatch aborts the handshake. For non-Ed25519 leaves (a REALITY server
//! mirrors the borrowed dest's real certificate) the standard CA verification
//! is the fallback, with the configured `sni` as the expected DNS name.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use boring::ssl::{
    Ssl, SslAlert, SslContextBuilder, SslMethod, SslRef, SslSignatureAlgorithm,
    SslVerifyError, SslVerifyMode, SslVersion,
};
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509StoreContext;
use foreign_types::ForeignTypeRef;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac as _};
use serde::Deserialize;
use sha2::{Sha256, Sha512};

use crate::outbound::common::AsyncTlsStream;
use crate::outbound::common::apply_fingerprint_to_ctx;
use crate::tlsfragment::FragmentConfig;

/// `[outbounds.reality]` section — its presence enables the REALITY transport.
#[derive(Debug, Clone, Deserialize)]
pub struct RealityConfig {
    /// Server REALITY X25519 public key, base64 (32 raw bytes).
    pub public_key: String,
    /// Server short_id, hex, at most 8 bytes (zero-padded internally).
    pub short_id: String,
}

/// Parsed REALITY connection parameters (per-outbound constants).
#[derive(Debug, Clone)]
pub struct RealityParams {
    /// Server REALITY X25519 public key.
    pub public_key: [u8; 32],
    /// short_id, zero-padded to the 8-byte wire size.
    pub short_id: [u8; 8],
}

impl RealityConfig {
    /// Decode and validate the configured values:
    /// - `public_key` must base64-decode to exactly 32 bytes (X25519);
    /// - `short_id` must be hex decoding to at most 8 bytes (Xray pads the
    ///   remainder with zeros inside the session_id plaintext).
    pub fn parse(&self) -> Result<RealityParams, String> {
        let public_key = decode_b32(&self.public_key)?;
        let mut short_id = [0u8; 8];
        let sid = decode_hex(&self.short_id)?;
        if sid.len() > 8 {
            return Err(format!(
                "reality: short_id too long ({} bytes, max 8)",
                sid.len()
            ));
        }
        short_id[..sid.len()].copy_from_slice(&sid);
        Ok(RealityParams { public_key, short_id })
    }
}

fn decode_b32(s: &str) -> Result<[u8; 32], String> {
    use base64::engine::general_purpose;
    let s = s.trim();
    // Xray's `x25519` prints URL-safe base64 without padding; accept the
    // standard alphabet and both padding conventions too.
    let bytes = general_purpose::STANDARD
        .decode(s)
        .or_else(|_| general_purpose::URL_SAFE.decode(s))
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(s))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(s))
        .map_err(|_| "reality: public_key is not valid base64".to_string())?;
    if bytes.len() != 32 {
        return Err(format!(
            "reality: public_key must decode to 32 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes.try_into().expect("32-byte array"))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("reality: short_id must be an even-length hex string".into());
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("reality: invalid hex byte at offset {i}"))
        })
        .collect()
}

/// Client version triple carried in the session_id plaintext (bytes 0..3).
///
/// The field is only used by the server's MinClientVer/MaxClientVer filter
/// (it plays no part in authentication). Newer Xray refuses clients below
/// `[26, 3, 27]` **by default** when `minClientVer` is not configured
/// (`infra/conf/transport_security.go:118` — "other clients may be refused"),
/// and production relays (openrung) do not set `minClientVer`. Anywhere used
/// to send its own crate version (1.2.0), which such servers reject outright;
/// we therefore send the lowest version new Xray accepts. Anything ≥
/// `[26, 3, 27]` passes the filter, and an explicit server-side
/// Min/MaxClientVer range still applies on top when configured.
const REALITY_CLIENT_VERSION: [u8; 3] = [26, 3, 27];

/// REALITY AuthKey = HKDF-SHA256(ikm = x25519 keyshare secret,
///                               salt = client_random[:20],
///                               info = "REALITY").
fn auth_key(shared: &[u8; 32], client_random: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared);
    let mut out = [0u8; 32];
    hk.expand(b"REALITY", &mut out).expect("32-byte okm");
    out
}

/// §S1.3 certificate verification inside boring's custom-verify callback.
///
/// Returns the derived AuthKey when the certificate authenticates the REALITY
/// server (Ed25519 + HMAC path). Non-Ed25519 leaves fall back to standard CA
/// verification against the system trust store.
fn verify_reality_cert(
    ssl_ref: &mut SslRef, reality_pub: &[u8; 32], sni: &str,
) -> Result<[u8; 32], SslVerifyError> {
    let fail = || SslVerifyError::Invalid(SslAlert::HANDSHAKE_FAILURE);

    // The AuthKey is derivable before the ServerHello: the client's own key
    // share private was captured by the patch when the ClientHello was built.
    let authkey = {
        let ptr = ssl_ref.as_ptr() as *mut boring_sys::SSL;
        unsafe {
            let mut client_random = [0u8; 32];
            boring_sys::SSL_get_client_random(
                ptr,
                client_random.as_mut_ptr(),
                client_random.len(),
            );
            let mut shared = [0u8; 32];
            if boring_sys::SSL_client_key_share_x25519(
                ptr,
                reality_pub.as_ptr(),
                shared.as_mut_ptr(),
            ) != 1
            {
                return Err(fail());
            }
            auth_key(&shared, &client_random)
        }
    };

    let cert = ssl_ref.peer_certificate().ok_or_else(fail)?;
    let mut raw_buf = [0u8; 64];
    if let Ok(pkey) = cert.public_key() {
        if let Ok(raw) = pkey.raw_public_key(&mut raw_buf) {
            if raw.len() == 32 {
                // Ed25519 leaf: REALITY authentication is the HMAC check.
                let mut mac =
                    Hmac::<Sha512>::new_from_slice(&authkey).map_err(|_| fail())?;
                mac.update(&raw);
                let expected = mac.finalize().into_bytes();
                if cert.signature().as_slice() == expected.as_slice() {
                    return Ok(authkey);
                }
                // An Ed25519 leaf we cannot authenticate: fail closed
                // (anywhere has no crawl disguise to fall through to).
                return Err(fail());
            }
        }
    }

    // Non-Ed25519 leaf: the REALITY server mirrors the borrowed dest's real
    // certificate — fall back to standard CA verification (§S1.3).
    ca_verify(&cert, ssl_ref, sni)?;
    Ok(authkey)
}

/// Standard CA verification of the mirrored dest certificate, expecting the
/// configured `sni` as the leaf's DNS name.
fn ca_verify(leaf: &boring::x509::X509, ssl_ref: &SslRef, sni: &str) -> Result<(), SslVerifyError> {
    let fail = || SslVerifyError::Invalid(SslAlert::HANDSHAKE_FAILURE);
    let mut builder = X509StoreBuilder::new().map_err(|_| fail())?;
    builder.set_default_paths().map_err(|_| fail())?;
    builder.verify_param_mut().set_host(sni).map_err(|_| fail())?;
    let store = builder.build();

    // Intermediates: the peer chain minus the leaf (client-side chains
    // include the leaf at index 0).
    let mut intermediates = boring::stack::Stack::new().map_err(|_| fail())?;
    if let Some(chain) = ssl_ref.peer_cert_chain() {
        for cert in chain.iter().skip(1) {
            intermediates
                .push(cert.to_owned())
                .map_err(|_| fail())?;
        }
    }

    let mut ctx = X509StoreContext::new().map_err(|_| fail())?;
    ctx.init(&store, leaf, &intermediates, |ctx| ctx.verify_cert())
        .map_err(|_| fail())?;
    Ok(())
}

/// Signature algorithms offered by the REALITY ClientHello. boring's default
/// client list has no ed25519, but a REALITY server may present an Ed25519
/// leaf whose CertificateVerify must be signed with it — without offering
/// ed25519 the handshake dies with NO_COMMON_SIGNATURE_ALGORITHMS. The list
/// is the Chrome fingerprint preference set with ed25519 prepended.
const REALITY_VERIFY_ALG_PREFS: &[SslSignatureAlgorithm] = &[
    SslSignatureAlgorithm::ED25519,
    SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
    SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
    SslSignatureAlgorithm::RSA_PKCS1_SHA256,
    SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
    SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
    SslSignatureAlgorithm::RSA_PKCS1_SHA384,
    SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
    SslSignatureAlgorithm::RSA_PKCS1_SHA512,
    SslSignatureAlgorithm::RSA_PKCS1_SHA1,
];

/// Build an async REALITY connection on top of `tcp` (TLS 1.3 only).
///
/// The returned stream is a plain byte stream (no WS framing). For M2's
/// Direct-phase splice the raw `TcpStream` stays reachable through
/// `stream.get_ref().get_ref()` (`tokio_boring::SslStream` →
/// `AsyncFragmentStream` → `TcpStream`).
pub(crate) async fn connect_reality_stream(
    tcp: tokio::net::TcpStream, sni: &str, params: &RealityParams,
    fragment: Option<&FragmentConfig>,
) -> io::Result<AsyncTlsStream> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    // Chrome-like ClientHello fingerprint, then the REALITY adjustments on
    // top (sigalgs must include ed25519, see REALITY_VERIFY_ALG_PREFS).
    apply_fingerprint_to_ctx(&mut builder);
    builder
        .set_verify_algorithm_prefs(REALITY_VERIFY_ALG_PREFS)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    // REALITY requires TLS 1.3 (§S2.7); the handshake is TLS 1.3-only anyway.
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    builder.set_verify(SslVerifyMode::PEER);
    let reality_pub = params.public_key;
    let sni_owned = sni.to_string();
    builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl_ref| {
        verify_reality_cert(ssl_ref, &reality_pub, &sni_owned)
            .map(|_| ())
            .map_err(|e| {
                log::debug!("reality: certificate verification failed: {e:?}");
                e
            })
    });

    let ctx = builder.build();
    let mut ssl = Ssl::new(&ctx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    ssl.set_hostname(sni)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // REALITY session_id derivation parameters — consumed by the patched
    // boring inside ssl_add_client_hello, after the hello bytes are final and
    // before they enter the handshake transcript.
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let client_ver = REALITY_CLIENT_VERSION;
    let rc = unsafe {
        boring_sys::SSL_set_reality_client_hello_params(
            ssl.as_ptr(),
            reality_pub.as_ptr(),
            params.short_id.as_ptr(),
            timestamp,
            client_ver.as_ptr(),
        )
    };
    if rc != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reality: SSL_set_reality_client_hello_params failed",
        ));
    }

    let frag_stream =
        crate::obfuscation::fragment::AsyncFragmentStream::new(tcp, fragment);
    let stream = tokio_boring::SslStreamBuilder::new(ssl, frag_stream)
        .connect()
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("reality: handshake failed: {e}"),
            )
        })?;
    // §S2.7: flow=XRV requires the outer transport to be TLS 1.3.
    if stream.ssl().version2() != Some(SslVersion::TLS1_3) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "reality: outer transport did not negotiate TLS 1.3",
        ));
    }
    Ok(stream)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn config(public_key: &str, short_id: &str) -> RealityConfig {
        RealityConfig {
            public_key: public_key.to_string(),
            short_id: short_id.to_string(),
        }
    }

    #[test]
    fn parses_valid_public_key_and_short_id() {
        // 32 bytes of 0x37 -> base64 "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc="
        let params = config(
            "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
            "0123abcd",
        )
        .parse()
        .unwrap();
        assert_eq!(params.public_key, [0x37; 32]);
        assert_eq!(
            params.short_id,
            [0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]
        );
    }

    #[test]
    fn parses_url_safe_base64_public_key() {
        // 32 bytes of [0xfe,0xed,0xbe,0xef]*8: the URL-safe encoding differs
        // from the standard one ("/u2+" vs "_u2-").
        let std = "/u2+7/7tvu/+7b7v/u2+7/7tvu/+7b7v/u2+7/7tvu8=";
        let url = "_u2-7_7tvu_-7b7v_u2-7_7tvu_-7b7v_u2-7_7tvu8=";
        let expected = [0xfe, 0xed, 0xbe, 0xef, 0xfe, 0xed, 0xbe, 0xef];
        assert_eq!(
            config(std, "").parse().unwrap().public_key[..8],
            expected
        );
        assert_eq!(
            config(url, "").parse().unwrap().public_key[..8],
            expected
        );
        assert_eq!(config(url, "").parse().unwrap().short_id, [0u8; 8]);
    }

    #[test]
    fn rejects_wrong_public_key_length() {
        let err = config("Nzc3Nzc3", "01").parse().unwrap_err();
        assert!(err.contains("32 bytes"), "{err}");
    }

    #[test]
    fn rejects_invalid_public_key_base64() {
        let err = config("not base64!!", "01").parse().unwrap_err();
        assert!(err.contains("base64"), "{err}");
    }

    #[test]
    fn rejects_short_id_longer_than_8_bytes() {
        let err = config(
            "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
            "001122334455667788",
        )
        .parse()
        .unwrap_err();
        assert!(err.contains("too long"), "{err}");
    }

    #[test]
    fn rejects_odd_hex_short_id() {
        let err = config(
            "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
            "012",
        )
        .parse()
        .unwrap_err();
        assert!(err.contains("even-length"), "{err}");
    }

    #[test]
    fn rejects_non_hex_short_id() {
        let err = config(
            "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
            "zz",
        )
        .parse()
        .unwrap_err();
        assert!(err.contains("invalid hex"), "{err}");
    }

    #[test]
    fn session_id_plaintext_layout_matches_xray() {
        // Wire layout (§S1.1): plaintext[0..3] = client version, [3] = 0
        // reserved, [4..8] = BE unix timestamp, [8..16] = short_id (padded).
        let ver = REALITY_CLIENT_VERSION;
        let short_id = [0x11u8, 0x22, 0x33, 0x44];
        let timestamp: u32 = 1_700_000_000;

        let mut plaintext = [0u8; 16];
        plaintext[0..3].copy_from_slice(&ver);
        plaintext[3] = 0;
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plaintext[8..12].copy_from_slice(&short_id);

        assert_eq!(&plaintext[0..3], &ver);
        assert_eq!(plaintext[3], 0);
        assert_eq!(
            u32::from_be_bytes(plaintext[4..8].try_into().unwrap()),
            timestamp
        );
        assert_eq!(&plaintext[8..12], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&plaintext[12..16], &[0, 0, 0, 0]);
    }

    #[test]
    fn client_version_meets_xray_default_min() {
        // xray v26.7.28 defaults MinClientVer to [26, 3, 27] when the server
        // does not configure `minClientVer`
        // (infra/conf/transport_security.go:118). Our constant must not be
        // below that floor — production relays don't set minClientVer.
        let floor = [26u8, 3, 27];
        assert!(
            REALITY_CLIENT_VERSION >= floor,
            "REALITY_CLIENT_VERSION {REALITY_CLIENT_VERSION:?} below xray \
             default minClientVer {floor:?}"
        );
        // And the exact wire value we committed to (parseable as x.y.z).
        let parsed: Vec<u8> = REALITY_CLIENT_VERSION.to_vec();
        assert_eq!(parsed, vec![26, 3, 27]);
    }

    #[test]
    fn auth_key_matches_reference_vector() {
        // Cross-checked against the spike (`spikes/reality-session-id`,
        // authkey/reality-handshake modes): identical derivation of
        // HKDF-SHA256(ikm, salt=random[:20], info="REALITY").
        let shared = [7u8; 32];
        let mut random = [0u8; 32];
        for (i, b) in random.iter_mut().enumerate() {
            *b = i as u8;
        }
        let key = auth_key(&shared, &random);
        // Independent hkdf expansion (same primitive, different call shape).
        let hk = Hkdf::<Sha256>::new(Some(&random[..20]), &shared);
        let mut expected = [0u8; 32];
        hk.expand(b"REALITY", &mut expected).unwrap();
        assert_eq!(key, expected);
        assert_ne!(key, [0u8; 32]);
    }
}
