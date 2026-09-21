// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! REALITY server transport.
//!
//! XTLS REALITY hides a VLESS endpoint behind a borrowed TLS server: the
//! client proves itself inside the ClientHello's legacy session_id, and
//! everyone else is transparently spliced to a real camouflage site
//! (`dest`). The server protocol has four interop-relevant pieces, all
//! mirrored from `xtls/reality` (the Go crypto/tls fork xray uses) and
//! `xray-core/transport/internet/reality`:
//!
//! 1. **Pre-handshake session_id authentication** (reality/tls.go:207-262):
//!    `AuthKey = HKDF-SHA256(ikm = X25519(serverPrivateKey, clientKeyShare),
//!    salt = ClientRandom[:20], info = "REALITY")`; the 32-byte session_id
//!    is `AES-256-GCM` ciphertext(16) || tag(16) over the 16-byte plaintext
//!    `client_ver[3] || 0x00 || BE32(unix ts) || short_id[8]`, with
//!    nonce = ClientRandom[20:] and AAD = the raw ClientHello handshake
//!    message with the session_id bytes zeroed. Anywhere's client does the
//!    sealing inside boring (`third_party/boring-sys/patches/
//!    reality-session-id.patch` zeroes `aad[39..71]`, the same offsets).
//! 2. **One-time certificate** (reality/handshake_server_tls13.go:73-81,
//!    :145-157): a global self-signed Ed25519 certificate whose 64-byte
//!    signature value is overwritten per connection with
//!    `HMAC-SHA512(AuthKey, ed25519 pubkey)`. The client (reality.rs
//!    §S1.3 / xray reality.go:76-115) authenticates the server by exactly
//!    that check. boring gets the per-connection certificate through
//!    `SslRef::set_certificate` + `set_private_key`.
//! 3. **Transparent fallback** (reality/tls.go:271-286, :430-447): any
//!    non-TLS, non-TLS1.3, wrong-SNI or unauthenticated connection is
//!    spliced byte-for-byte to `dest` (client FIN → dest half-close,
//!    errors → close), so a prober sees the real site.
//! 4. **Vision** (`flow=xtls-rprx-vision`) rides on top as on any TLS 1.3
//!    transport — REALITY only replaces the outer TLS accept.
//!
//! Unlike the xray fork, the post-ServerHello handshake is stock boring
//! (`SSL_accept` over the replayed ClientHello prefix): the fork's record
//! length mimicry and post-handshake NST synthesis are anti-probing
//! fidelity measures that no client verifies (plan doc §0.2/§4.1).

use std::io;
use std::net::Shutdown;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::time::Duration;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use boring::asn1::Asn1Integer;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use boring::rand::rand_bytes;
use boring::ssl::{Ssl, SslContextBuilder, SslMethod, SslOptions, SslRef, SslVersion};
use boring::x509::{X509, X509Builder, X509NameBuilder};
use foreign_types::ForeignType;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::config::RealityInboundConfig;

/// Read budget for the ClientHello peek. A legal ClientHello fits in one
/// 16 KB record; the cap only bounds garbage (xray has no cap but forwards
/// to dest via the MirrorConn instead of buffering).
const MAX_HELLO_BYTES: usize = 64 * 1024;

/// ClientHello peek budget (same rationale as the vless inbound's
/// HANDSHAKE_TIMEOUT; xray imposes none — the fork just blocks).
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);

/// Fallback dest dial budget (sing-box's handshake timeout default,
/// C.TCPTimeout): a blackholed dest must not wedge the fallback splice.
const DEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Budget for reading the destination site's ServerHello during the borrow
/// attempt. A healthy site answers in one RTT; exceeding the budget means
/// the borrow is unavailable and the connection falls back to the local
/// handshake (today's behavior).
const BORROW_SH_TIMEOUT: Duration = Duration::from_secs(5);

/// The TLS 1.3 cipher suites this boring build can negotiate (wire ids);
/// a borrowed ServerHello suite must be one of these.
const BORING_TLS13_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];

/// Key-share groups this boring build can negotiate.
const GROUP_X25519_WIRE: u16 = 0x001d;
const GROUP_X25519MLKEM768_WIRE: u16 = 0x11ec;

/// Test hook: wire id of the last cipher suite injected via the borrow FFI
/// (0 = no borrow applied). Hidden — integration tests read it to verify the
/// borrowing path end to end.
#[doc(hidden)]
pub static LAST_APPLIED_BORROW: AtomicU16 = AtomicU16::new(0);

/// TLS record header length.
const RECORD_HEADER: usize = 5;

/// HKDF info label (reality/tls.go:234).
const REALITY_INFO: &[u8] = b"REALITY";

/// key_share group ids (reality/common.go:151-152).
const GROUP_X25519: u16 = 29;
const GROUP_X25519MLKEM768: u16 = 4588;
/// ML-KEM-768 encapsulation key size (Go mlkem.EncapsulationKeySize768);
/// the hybrid share is `mlkem_ct(1184) || x25519(32)` and xray uses the
/// trailing 32 bytes as the X25519 public key (tls.go:221-228).
const MLKEM768_ENCAP_SIZE: usize = 1184;

/// X25519 public key matching a REALITY private key — pairs the inbound's
/// `private_key` with the outbound's `public_key` (and the `xray x25519`
/// keypair output).
pub fn public_key_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    XPublicKey::from(&XStaticSecret::from(*private_key)).to_bytes()
}

/// REALITY AuthKey = HKDF-SHA256(ikm = X25519 share secret,
///                               salt = ClientRandom[:20],
///                               info = "REALITY").
/// Identical to the client-side derivation (transport/reality.rs auth_key).
fn auth_key(shared: &[u8; 32], client_random: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared);
    let mut out = [0u8; 32];
    hk.expand(REALITY_INFO, &mut out).expect("32-byte okm");
    out
}

/// big-endian version value (xray `Value()`, reality/tls.go:153-158).
fn ver_value(ver: &[u8; 3]) -> u32 {
    ((ver[0] as u32) << 16) | ((ver[1] as u32) << 8) | ver[2] as u32
}

// ---------------------------------------------------------------------------
// ClientHello peek + parse
// ---------------------------------------------------------------------------

/// State of the first-flight bytes buffered so far.
enum Flight {
    /// A complete first handshake message (record headers stripped).
    Complete(Vec<u8>),
    /// More bytes could still complete it.
    NeedMore,
    /// Not a handshake record, or over budget — stop reading, fall back.
    Garbage,
}

/// Walk the complete TLS records in `prefix` reassembling handshake bytes
/// until the first handshake message is whole. The AAD is the reassembled
/// message, so a ClientHello split across records (or TCP segments) must be
/// reassembled before parsing (plan doc §6.6).
fn walk_hello_flight(prefix: &[u8]) -> Flight {
    if prefix.len() < RECORD_HEADER {
        return Flight::NeedMore;
    }
    if prefix[0] != 0x16 {
        return Flight::Garbage;
    }
    let mut hs: Vec<u8> = Vec::with_capacity(517);
    let mut pos = 0usize;
    loop {
        if hs.len() >= 4 {
            let want =
                4 + ((hs[1] as usize) << 16 | (hs[2] as usize) << 8 | hs[3] as usize);
            if hs.len() >= want {
                hs.truncate(want);
                return Flight::Complete(hs);
            }
        }
        let Some(rest) = prefix.get(pos..) else {
            return Flight::NeedMore;
        };
        if rest.len() < RECORD_HEADER {
            return Flight::NeedMore;
        }
        if rest[0] != 0x16 {
            // A non-handshake record before a complete ClientHello is not a
            // TLS flight we can authenticate.
            return Flight::Garbage;
        }
        let rec_len =
            u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if hs.len() + rec_len > MAX_HELLO_BYTES {
            return Flight::Garbage;
        }
        if rest.len() < RECORD_HEADER + rec_len {
            return Flight::NeedMore;
        }
        hs.extend_from_slice(&rest[RECORD_HEADER..RECORD_HEADER + rec_len]);
        pos += RECORD_HEADER + rec_len;
    }
}

/// The parsed ClientHello fields the REALITY authentication needs.
struct ClientHello {
    /// Reassembled handshake message (4-byte header + body) — the AAD base;
    /// the session_id sits at bytes [39..71] (4-byte header + 2-byte
    /// legacy_version + 32-byte random + 1-byte length), the same offsets
    /// the client's boring patch zeroes in its AAD.
    msg: Vec<u8>,
    random: [u8; 32],
    /// legacy session_id when it is exactly 32 bytes (the REALITY wire
    /// size; anything else cannot authenticate — tls.go:239-247).
    session_id: Option<[u8; 32]>,
    server_name: Option<String>,
    /// supported_versions offers TLS 1.3 (tls.go:211).
    tls13: bool,
    /// x25519 key share (tls.go:215-228): the x25519 entry, else the tail
    /// 32 bytes of an X25519MLKEM768 entry.
    peer_pub: Option<[u8; 32]>,
    /// Offered cipher suites (wire ids) — the borrowed ServerHello suite
    /// must be one the client actually offered.
    cipher_suites: Vec<u16>,
    /// Offered key-share groups — the borrowed ServerHello group must be
    /// one the client actually offered.
    groups: Vec<u16>,
}

fn parse_client_hello(prefix: &[u8]) -> Option<ClientHello> {
    let msg = match walk_hello_flight(prefix) {
        Flight::Complete(msg) if msg.len() >= 39 && msg[0] == 0x01 => msg,
        _ => return None,
    };
    let random: [u8; 32] = msg[6..38].try_into().ok()?;
    let sid_len = msg[38] as usize;
    let session_id = if sid_len == 32 && msg.len() >= 71 {
        Some(msg[39..71].try_into().ok()?)
    } else {
        None
    };

    // Extensions: cipher_suites (2B len) + compression (1B len) then the
    // extension block.
    let mut p = 39 + sid_len;
    let mut server_name = None;
    let mut tls13 = false;
    let mut peer_pub = None;
    let mut cipher_suites = Vec::new();
    let mut groups = Vec::new();
    if p + 2 <= msg.len() {
        let ciphers = u16::from_be_bytes([msg[p], msg[p + 1]]) as usize;
        let mut q = p + 2;
        let ciphers_end = (q + ciphers).min(msg.len());
        while q + 2 <= ciphers_end {
            cipher_suites.push(u16::from_be_bytes([msg[q], msg[q + 1]]));
            q += 2;
        }
        p += 2 + ciphers;
        if p < msg.len() {
            let comp = msg[p] as usize;
            p += 1 + comp;
            if p + 2 <= msg.len() {
                let ext_total =
                    u16::from_be_bytes([msg[p], msg[p + 1]]) as usize;
                p += 2;
                let end = (p + ext_total).min(msg.len());
                while p + 4 <= end {
                    let etype =
                        u16::from_be_bytes([msg[p], msg[p + 1]]);
                    let elen =
                        u16::from_be_bytes([msg[p + 2], msg[p + 3]]) as usize;
                    let (ds, de) = (p + 4, (p + 4 + elen).min(end));
                    match etype {
                        0 => server_name = parse_sni(&msg[ds..de]),
                        43 => tls13 = has_tls13(&msg[ds..de]),
                        51 => {
                            peer_pub = pick_key_share(&msg[ds..de]);
                            // Collect every offered group. The client's
                            // key_share carries a 2-byte list length, then
                            // entries of group(2B) + key_len(2B) + key.
                            let mut q = ds + 2;
                            while q + 4 <= de {
                                groups.push(u16::from_be_bytes([
                                    msg[q],
                                    msg[q + 1],
                                ]));
                                let klen = u16::from_be_bytes([
                                    msg[q + 2],
                                    msg[q + 3],
                                ]) as usize;
                                q += 4 + klen;
                            }
                        },
                        _ => {},
                    }
                    p = p + 4 + elen;
                }
            }
        }
    }
    Some(ClientHello {
        msg,
        random,
        session_id,
        server_name,
        tls13,
        peer_pub,
        cipher_suites,
        groups,
    })
}

/// SNI extension (type 0) hostname: `[2B list_len] { [1B type][2B len][host] }`.
fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = 2 + list_len.min(data.len() - 2);
    let mut p = 2;
    while p + 3 <= end {
        let name_type = data[p];
        let name_len = u16::from_be_bytes([data[p + 1], data[p + 2]]) as usize;
        p += 3;
        if p + name_len > end {
            return None;
        }
        if name_type == 0 {
            return std::str::from_utf8(&data[p..p + name_len])
                .ok()
                .map(str::to_string);
        }
        p += name_len;
    }
    None
}

/// supported_versions extension (type 43) in a ClientHello:
/// `[1B list_len] { 2B versions }` — true when TLS 1.3 is offered.
fn has_tls13(data: &[u8]) -> bool {
    let Some(&list_len) = data.first() else {
        return false;
    };
    let end = (1 + list_len as usize).min(data.len());
    (1..end.saturating_sub(1)).step_by(2).any(|p| {
        data[p] == 0x03 && data[p + 1] == 0x04
    })
}

/// key_share extension (type 51): `[2B list_len] { [2B group][2B len][key] }`.
/// xray prefers the x25519 share and falls back to the x25519 component of
/// an X25519MLKEM768 hybrid (tls.go:215-228).
fn pick_key_share(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = 2 + list_len.min(data.len() - 2);
    let mut x25519 = None;
    let mut mlkem = None;
    let mut p = 2;
    while p + 4 <= end {
        let group = u16::from_be_bytes([data[p], data[p + 1]]);
        let klen = u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        let (ks, ke) = (p + 4, (p + 4 + klen).min(end));
        let key = data.get(ks..ke).unwrap_or(&[]);
        if group == GROUP_X25519 && key.len() == 32 && x25519.is_none() {
            x25519 = Some(key.try_into().expect("32-byte share"));
        } else if group == GROUP_X25519MLKEM768
            && key.len() == MLKEM768_ENCAP_SIZE + 32
            && mlkem.is_none()
        {
            mlkem = Some(key[MLKEM768_ENCAP_SIZE..].try_into().expect("32B tail"));
        }
        p += 4 + klen;
    }
    x25519.or(mlkem)
}

// ---------------------------------------------------------------------------
// One-time certificate
// ---------------------------------------------------------------------------

/// The global one-time Ed25519 certificate template (reality/
/// handshake_server_tls13.go:73-81): a self-signed certificate whose DER
/// ends with the 64-byte signature value; every connection re-signs it with
/// `HMAC-SHA512(AuthKey, ed25519 pub)`.
#[derive(Debug)]
struct CertTemplate {
    der: Vec<u8>,
    ed_pub: [u8; 32],
    pkey: PKey<Private>,
}

impl CertTemplate {
    fn new() -> Result<Self, String> {
        let mut seed = [0u8; 32];
        rand_bytes(&mut seed)
            .map_err(|e| format!("reality: rand_bytes: {e}"))?;
        // boring has no Ed25519 keygen constructor; create the key from a
        // raw seed via FFI (the reality-session-id spike's approach).
        let pkey = unsafe {
            let ptr = boring_sys::EVP_PKEY_new_raw_private_key(
                boring_sys::EVP_PKEY_ED25519 as std::os::raw::c_int,
                std::ptr::null_mut(),
                seed.as_ptr(),
                seed.len(),
            );
            if ptr.is_null() {
                return Err("reality: EVP_PKEY_new_raw_private_key failed".into());
            }
            PKey::from_ptr(ptr)
        };
        let mut pub_buf = [0u8; 64];
        let ed_pub: [u8; 32] = pkey
            .raw_public_key(&mut pub_buf)
            .map_err(|e| format!("reality: ed25519 public key: {e}"))?
            .try_into()
            .map_err(|_| "reality: ed25519 public key not 32 bytes".to_string())?;

        let mut builder =
            X509Builder::new().map_err(|e| format!("reality: x509: {e}"))?;
        builder
            .set_version(2)
            .map_err(|e| format!("reality: x509 version: {e}"))?;
        let serial = BigNum::from_u32(1)
            .map_err(|e| format!("reality: serial: {e}"))?;
        let serial =
            Asn1Integer::from_bn(&serial).map_err(|e| format!("reality: serial: {e}"))?;
        builder
            .set_serial_number(&serial)
            .map_err(|e| format!("reality: x509 serial: {e}"))?;
        let mut name = X509NameBuilder::new()
            .map_err(|e| format!("reality: x509 name: {e}"))?;
        name.append_entry_by_nid(Nid::COMMONNAME, "anywhere-reality")
            .map_err(|e| format!("reality: x509 name: {e}"))?;
        let name = name.build();
        builder
            .set_issuer_name(&name)
            .map_err(|e| format!("reality: x509 issuer: {e}"))?;
        builder
            .set_subject_name(&name)
            .map_err(|e| format!("reality: x509 subject: {e}"))?;
        builder
            .set_pubkey(&pkey)
            .map_err(|e| format!("reality: x509 pubkey: {e}"))?;
        // Validity is not checked by any REALITY party (xray's Go template
        // even uses zero times); keep it wide anyway.
        builder
            .set_not_before(&Asn1Time::from_unix(0).expect("unix 0"))
            .map_err(|e| format!("reality: x509 not_before: {e}"))?;
        builder
            .set_not_after(&Asn1Time::from_unix(4_102_444_800).expect("2100"))
            .map_err(|e| format!("reality: x509 not_after: {e}"))?;
        let cert = builder.build();
        // Ed25519 signs with a NULL digest and boring exposes no null
        // MessageDigest for X509Builder::sign — X509_sign with a NULL md is
        // what Ed25519 requires (ASN1_item_sign → EVP_DigestSignInit).
        let rc = unsafe {
            boring_sys::X509_sign(cert.as_ptr(), pkey.as_ptr(), std::ptr::null())
        };
        if rc <= 0 {
            return Err("reality: X509_sign failed".into());
        }
        let der = cert.to_der().map_err(|e| format!("reality: x509 der: {e}"))?;
        // The per-connection rewrite targets the trailing 64-byte signature
        // value; pin that layout once at startup.
        let parsed = X509::from_der(&der)
            .map_err(|e| format!("reality: template parse: {e}"))?;
        if der.len() < 64 || parsed.signature().as_slice() != &der[der.len() - 64..]
        {
            return Err("reality: template signature is not the trailing \
                        64 bytes"
                .into());
        }
        Ok(Self { der, ed_pub, pkey })
    }

    /// The per-connection certificate: the template DER with its trailing
    /// 64-byte signature replaced by `HMAC-SHA512(AuthKey, ed25519 pub)`
    /// (handshake_server_tls13.go:145-152: `h.Sum(cert[:len(cert)-64])`).
    fn derive(&self, auth_key: &[u8; 32]) -> Result<X509, String> {
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(auth_key)
            .map_err(|e| format!("reality: hmac key: {e}"))?;
        mac.update(&self.ed_pub);
        let sig = mac.finalize().into_bytes();
        let mut der = self.der.clone();
        let tail = der.len() - 64;
        der[tail..].copy_from_slice(&sig);
        X509::from_der(&der)
            .map_err(|e| format!("reality: derived cert parse: {e}"))
    }
}

// ---------------------------------------------------------------------------
// RealityServer
// ---------------------------------------------------------------------------

/// The ClientHello facts the ServerHello borrow needs (offered cipher
/// suites and key-share groups).
#[derive(Debug, Clone)]
pub struct BorrowContext {
    pub cipher_suites: Vec<u16>,
    pub groups: Vec<u16>,
}

/// The destination site's ServerHello parameters worth borrowing
/// (see [`RealityServer::borrow_server_hello`]).
#[derive(Debug, Clone, Copy)]
pub struct BorrowedServerHello {
    pub cipher_id: u16,
    pub group_id: u16,
}

/// Outcome of the pre-handshake ClientHello peek.
pub enum RealityPeek {
    /// The ClientHello authenticated: `auth_key` drives the one-time
    /// certificate, `prefix` holds the consumed bytes to replay into
    /// `SSL_accept`, and `borrow_ctx` carries the ClientHello facts the
    /// ServerHello borrow validates against.
    Authenticated {
        auth_key: [u8; 32],
        prefix: Vec<u8>,
        borrow_ctx: BorrowContext,
    },
    /// Not a REALITY client: replay `prefix` into `dest` and splice.
    Fallback { prefix: Vec<u8> },
}

/// Server-side REALITY endpoint for one vless inbound.
#[derive(Debug)]
pub struct RealityServer {
    /// Camouflage site for unauthenticated connections (xray dest).
    dest: String,
    /// Accepted SNIs (xray serverNames; exact match, tls.go:211).
    server_names: Vec<String>,
    private_key: [u8; 32],
    /// Accepted session_id short_ids, zero-padded to the wire size
    /// (xray ShortIds, config.go:54-57).
    short_ids: Vec<[u8; 8]>,
    /// Max |now − session_id timestamp|; None = unchecked (xray
    /// MaxTimeDiff == 0, tls.go:259).
    max_time_diff: Option<Duration>,
    /// Configured client version floor (`min_client_ver`); None = no
    /// limit. anywhere deliberately defaults to None: xray's default floor
    /// [26, 3, 27] would reject sing-box clients, which report their own
    /// version {1, 8, 1} (reality_client.go:184-190) — plan doc §1.1.
    min_client_ver: Option<[u8; 3]>,
    max_client_ver: Option<[u8; 3]>,
    /// TLS 1.3-only accept context; the certificate is per-connection.
    ssl_ctx: boring::ssl::SslContext,
    cert: CertTemplate,
}

impl RealityServer {
    /// Build from the `[inbounds.reality]` config section.
    pub fn from_config(cfg: &RealityInboundConfig) -> Result<Self, String> {
        let dest = cfg.dest.trim().to_string();
        if dest.is_empty() {
            return Err("reality: dest is required".into());
        }
        if cfg.server_names.is_empty() {
            return Err("reality: server_names is required (xray rejects \
                        empty serverNames)"
                .into());
        }
        let private_key = decode_b32(&cfg.private_key)?;
        let mut short_ids = Vec::with_capacity(cfg.short_ids.len());
        for sid in &cfg.short_ids {
            let decoded = decode_hex(sid)?;
            if decoded.len() > 8 {
                return Err(format!(
                    "reality: short_id '{sid}' too long ({} bytes, max 8)",
                    decoded.len()
                ));
            }
            let mut padded = [0u8; 8];
            padded[..decoded.len()].copy_from_slice(&decoded);
            short_ids.push(padded);
        }
        if short_ids.is_empty() {
            // sing-box allows an empty ShortID list and then accepts only the
            // all-zero id — the same id clients with an unset short_id send.
            // (xray instead rejects the config.) Follow sing-box: default [0].
            log::info!(
                "reality: no short_ids configured; accepting the all-zero \
                 short_id only"
            );
            short_ids.push([0u8; 8]);
        }
        let max_time_diff = if cfg.max_time_diff_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(cfg.max_time_diff_ms))
        };
        let min_client_ver = cfg
            .min_client_ver
            .as_deref()
            .map(|v| parse_ver(v, "min_client_ver"))
            .transpose()?;
        let max_client_ver = cfg
            .max_client_ver
            .as_deref()
            .map(|v| parse_ver(v, "max_client_ver"))
            .transpose()?;

        let mut builder = SslContextBuilder::new(SslMethod::tls())
            .map_err(|e| format!("reality: ssl ctx: {e}"))?;
        // REALITY is TLS 1.3 only (anywhere client reality.rs §S2.7; xray
        // checks hs.c.vers == VersionTLS13, tls.go:211).
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("reality: min proto: {e}"))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("reality: max proto: {e}"))?;
        // xray disables session tickets (reality config.go NextProtos nil +
        // SessionTicketsDisabled): no post-handshake NST is sent.
        builder.set_options(SslOptions::NO_TICKET);

        Ok(Self {
            dest,
            server_names: cfg.server_names.clone(),
            private_key,
            short_ids,
            max_time_diff,
            min_client_ver,
            max_client_ver,
            ssl_ctx: builder.build(),
            cert: CertTemplate::new()?,
        })
    }

    /// The fallback destination (for diagnostics).
    pub fn dest(&self) -> &str {
        &self.dest
    }

    /// Peek the ClientHello flight off the fresh connection, authenticate
    /// it, and report either the REALITY acceptance (with the replay
    /// prefix) or the transparent-fallback outcome. `Err` means the
    /// transport died before anything was sent — there is nothing worth
    /// splicing to dest.
    pub async fn authenticate(
        &self, tcp: &mut tokio::net::TcpStream,
    ) -> io::Result<RealityPeek> {
        let prefix = read_client_hello_prefix(tcp).await?;
        if prefix.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "reality: connection closed before ClientHello",
            ));
        }
        let Some(hello) = parse_client_hello(&prefix) else {
            log::debug!("reality: not a TLS ClientHello; falling back");
            return Ok(RealityPeek::Fallback { prefix });
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        match self.authenticate_hello_at(&hello, now_ms) {
            Ok(auth_key) => {
                let borrow_ctx = BorrowContext {
                    cipher_suites: hello.cipher_suites.clone(),
                    groups: hello.groups.clone(),
                };
                Ok(RealityPeek::Authenticated {
                    auth_key,
                    prefix,
                    borrow_ctx,
                })
            },
            Err(reason) => {
                log::debug!("reality: unauthenticated ({reason}); falling back");
                Ok(RealityPeek::Fallback { prefix })
            },
        }
    }

    /// The session_id authentication (tls.go:207-262). Order matters for
    /// behavior parity: TLS 1.3 + SNI are checked before any crypto; the
    /// decrypted plaintext then passes the version range, time window and
    /// short_id set.
    fn authenticate_hello_at(
        &self, hello: &ClientHello, now_ms: i64,
    ) -> Result<[u8; 32], String> {
        if !hello.tls13 {
            return Err("client does not offer TLS 1.3".into());
        }
        let sni = hello.server_name.as_deref().unwrap_or("");
        if !self.server_names.iter().any(|n| n == sni) {
            return Err(format!("server name mismatch: {sni:?}"));
        }
        let Some(peer_pub) = hello.peer_pub else {
            return Err("no x25519 key share".into());
        };
        let Some(session_id) = hello.session_id else {
            return Err("session_id is not the 32-byte REALITY size".into());
        };

        // AuthKey = HKDF-SHA256(X25519(serverPrivateKey, clientShare),
        //                        salt = ClientRandom[:20], "REALITY")
        // (tls.go:230-235).
        let secret = XStaticSecret::from(self.private_key);
        let shared = secret.diffie_hellman(&XPublicKey::from(peer_pub));
        if !shared.was_contributory() {
            // curve25519.X25519 fails on the all-zero output (tls.go:230).
            return Err("low-order client key share".into());
        }
        let auth_key = auth_key(shared.as_bytes(), &hello.random);

        // AES-256-GCM open of the session_id: nonce = ClientRandom[20:],
        // AAD = the ClientHello with its session_id bytes zeroed
        // (tls.go:241-247).
        let mut aad = hello.msg.clone();
        aad[39..71].fill(0);
        let cipher = Aes256Gcm::new_from_slice(&auth_key)
            .map_err(|e| format!("aead key: {e}"))?;
        let nonce: &Nonce<_> = (&hello.random[20..32])
            .try_into()
            .expect("GCM nonce is 12 bytes");
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &session_id,
                    aad: &aad,
                },
            )
            .map_err(|_| "session_id decryption failed".to_string())?;
        if plaintext.len() != 16 {
            return Err(format!(
                "session_id plaintext len {} != 16",
                plaintext.len()
            ));
        }
        let client_ver: [u8; 3] =
            [plaintext[0], plaintext[1], plaintext[2]];
        let timestamp =
            u32::from_be_bytes(plaintext[4..8].try_into().expect("4 bytes"));
        let short_id: [u8; 8] =
            plaintext[8..16].try_into().expect("8 bytes");

        // tls.go:257-262. The floor applies only when explicitly
        // configured (default: no limit, plan doc §1.1).
        let ver = ver_value(&client_ver);
        if let Some(min) = &self.min_client_ver
            && ver < ver_value(min)
        {
            return Err(format!(
                "client version {client_ver:?} below {:#x}",
                ver_value(min)
            ));
        }
        if let Some(max) = &self.max_client_ver
            && ver > ver_value(max)
        {
            return Err(format!("client version {client_ver:?} above max"));
        }
        if let Some(window) = &self.max_time_diff {
            let diff = (now_ms - i64::from(timestamp) * 1000).abs();
            if diff > window.as_millis() as i64 {
                return Err(format!(
                    "session_id timestamp off by {diff} ms"
                ));
            }
        }
        if !self.short_ids.contains(&short_id) {
            return Err(format!("unknown short_id {short_id:02x?}"));
        }
        Ok(auth_key)
    }

    /// A fresh server SSL from the TLS 1.3-only accept context. When
    /// `borrowed` is set (the destination site answered the mirrored
    /// ClientHello with a usable TLS 1.3 ServerHello), the SSL is pinned to
    /// the destination's key-share group and cipher suite — the boring-side
    /// half of the xtls/reality ServerHello borrow. Opt-in per connection:
    /// `None` (or any non-REALITY use of the context) keeps boring's own
    /// selection.
    pub(crate) fn new_ssl(
        &self, borrowed: Option<&BorrowedServerHello>,
    ) -> io::Result<Ssl> {
        let ssl = Ssl::new(&self.ssl_ctx).map_err(io::Error::other)?;
        if let Some(b) = borrowed {
            // SAFETY: the pointer is a live SSL from this crate's boring
            // build; the FFI only sets two opt-in override fields read by
            // the ServerHello construction (reality-server-sh-borrow.patch).
            unsafe {
                boring_sys::SSL_set_reality_server_hello_borrow(
                    ssl.as_ptr(),
                    b.cipher_id,
                    b.group_id,
                );
            }
            LAST_APPLIED_BORROW.store(b.cipher_id, Ordering::Relaxed);
        }
        // Mirror the xtls/reality fork (handshake_server_tls13.go assigns
        // hs.sigAlg = Ed25519 without consulting the client): sign the
        // one-time certificate's CertificateVerify with the certificate's
        // own key regardless of the client's advertised signature_algorithms.
        // utls/xray REALITY clients (chrome fingerprints) never advertise
        // ed25519, but they do verify the Ed25519 signature — a stock boring
        // server would abort every authenticated handshake with
        // NO_COMMON_SIGNATURE_ALGORITHMS. The anywhere client explicitly
        // prefers Ed25519 (reality.rs REALITY_VERIFY_ALG_PREFS), so both
        // clients end up with the same signature algorithm.
        unsafe {
            boring_sys::SSL_set_reality_server_ignore_sigalgs(ssl.as_ptr());
        }
        Ok(ssl)
    }

    /// Inject the one-time certificate for `auth_key` into a not-yet-
    /// accepted SSL. boring has no null MessageDigest-free way to do this at
    /// context level per connection, so the certificate rides on the
    /// `SslRef` (`SSL_use_certificate`/`SSL_use_PrivateKey`) — the boring
    /// equivalent of the fork overwriting `signedCert` per handshake.
    pub(crate) fn inject_cert(
        &self, ssl: &mut SslRef, auth_key: &[u8; 32],
    ) -> io::Result<()> {
        let cert = self.cert.derive(auth_key).map_err(io::Error::other)?;
        ssl.set_certificate(&cert).map_err(io::Error::other)?;
        ssl.set_private_key(&self.cert.pkey)
            .map_err(io::Error::other)?;
        Ok(())
    }

    /// ServerHello 借用尝试（xtls/reality 的"借用目标站点握手"）。
    ///
    /// 认证成功后调用：把镜像的 ClientHello 回放给真实站点，读取其
    /// ServerHello 并校验（TLS 1.3 + x25519/MLKEM768 key share + 套件在
    /// 客户端提供列表内）。返回 [`Some`] 时调用方通过
    /// [`RealityServer::new_ssl`] 把 group/套件注入本连接的握手——可见
    /// 握手参数与真实站点一致；返回 [`None`]（目标不可达/行为异常/超时）
    /// 时退回本地握手（既有行为），服务不中断。
    pub async fn borrow_server_hello(
        &self, prefix: &[u8], ctx: &BorrowContext,
    ) -> Option<BorrowedServerHello> {
        let mut dest = match tokio::time::timeout(
            DEST_CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(&self.dest),
        )
        .await
        {
            Ok(Ok(d)) => d,
            _ => {
                log::debug!(
                    "reality borrow: dest {} dial failed/timed out",
                    self.dest
                );
                return None;
            },
        };
        if tokio::time::timeout(HELLO_TIMEOUT, dest.write_all(prefix))
            .await
            .ok()?
            .is_err()
        {
            log::debug!("reality borrow: dest {} write failed", self.dest);
            return None;
        }
        let sh = match tokio::time::timeout(
            BORROW_SH_TIMEOUT,
            read_target_server_hello(&mut dest),
        )
        .await
        {
            Ok(Ok(Some(sh))) => sh,
            Ok(Ok(None)) => {
                log::debug!(
                    "reality borrow: dest {} ServerHello not borrowable",
                    self.dest
                );
                return None;
            },
            Ok(Err(e)) => {
                log::debug!(
                    "reality borrow: dest {} ServerHello read failed: {e:?}",
                    self.dest
                );
                return None;
            },
            Err(_) => {
                log::debug!(
                    "reality borrow: dest {} ServerHello read timed out",
                    self.dest
                );
                return None;
            },
        };
        // 校验：套件必须是本 boring 支持的 TLS 1.3 套件且客户端有提供；
        // key-share 组必须客户端有提供。
        if !BORING_TLS13_SUITES.contains(&sh.cipher_id)
            || !ctx.cipher_suites.contains(&sh.cipher_id)
        {
            log::debug!(
                "reality borrow: borrowed suite {:#06x} not usable",
                sh.cipher_id
            );
            return None;
        }
        if !ctx.groups.contains(&sh.group_id) {
            log::debug!(
                "reality borrow: borrowed group {:#06x} not offered",
                sh.group_id
            );
            return None;
        }
        log::debug!(
            "reality borrow: borrowing dest {} ServerHello \
             (suite {:#06x}, group {:#06x})",
            self.dest,
            sh.cipher_id,
            sh.group_id
        );
        Some(sh)
    }

    /// Transparent fallback (tls.go:271-286, :430-447): replay the peeked
    /// bytes to `dest` and splice both directions. Client FIN half-closes
    /// dest (CloseWrite); errors break the respective direction. The task
    /// lives as long as the relayed connection, exactly like xray's copy
    /// loops.
    pub async fn splice_fallback(
        &self, client: tokio::net::TcpStream, prefix: Vec<u8>,
    ) {
        let mut dest = match tokio::time::timeout(
            DEST_CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(&self.dest),
        )
        .await
        {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => {
                log::debug!(
                    "reality fallback: dest {} dial failed: {e}",
                    self.dest
                );
                return;
            },
            Err(_) => {
                log::debug!(
                    "reality fallback: dest {} dial timed out after \
                     {DEST_CONNECT_TIMEOUT:?}",
                    self.dest
                );
                return;
            },
        };
        if !prefix.is_empty()
            && tokio::time::timeout(HELLO_TIMEOUT, dest.write_all(&prefix))
                .await
                .is_err()
        {
            return;
        }
        let (mut client_r, mut client_w) = client.into_split();
        let (mut dest_r, mut dest_w) = dest.into_split();

        let up = async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match client_r.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        // FIN (or error): CloseWrite toward dest.
                        let _ = dest_w.shutdown().await;
                        break;
                    },
                    Ok(n) => {
                        if dest_w.write_all(&buf[..n]).await.is_err() {
                            let _ = dest_w.shutdown().await;
                            break;
                        }
                    },
                }
            }
        };
        let down = async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match dest_r.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        let _ = client_w.shutdown().await;
                        break;
                    },
                    Ok(n) => {
                        if client_w.write_all(&buf[..n]).await.is_err() {
                            let _ = client_w.shutdown().await;
                            break;
                        }
                    },
                }
            }
        };
        tokio::join!(up, down);
    }
}

/// Read the ClientHello flight: consume TCP bytes until the first handshake
/// message is whole (reassembly across records), the budget runs out, the
/// peer closes, or the timeout fires. Partial bytes are returned either way
/// so the fallback can forward them (xray's MirrorConn forwards every byte
/// regardless of the handshake outcome).
async fn read_client_hello_prefix(
    tcp: &mut tokio::net::TcpStream,
) -> io::Result<Vec<u8>> {
    let mut prefix = Vec::with_capacity(1024);
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::sleep(HELLO_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        match walk_hello_flight(&prefix) {
            Flight::NeedMore => {},
            _ => return Ok(prefix),
        }
        tokio::select! {
            _ = &mut deadline => return Ok(prefix),
            read = tcp.read(&mut buf) => match read {
                Ok(0) => return Ok(prefix),
                Ok(n) => prefix.extend_from_slice(&buf[..n]),
                Err(e) => {
                    if prefix.is_empty() {
                        return Err(e);
                    }
                    return Ok(prefix);
                },
            },
        }
    }
}

/// Read one TLS record off `dest` and parse it as the destination site's
/// ServerHello. Returns `Ok(None)` when the record is not a borrowable
/// TLS 1.3 ServerHello (wrong shape, no TLS 1.3, unusable key share).
async fn read_target_server_hello(
    dest: &mut tokio::net::TcpStream,
) -> io::Result<Option<BorrowedServerHello>> {
    let mut header = [0u8; 5];
    dest.read_exact(&mut header).await?;
    if header[0] != 0x16 || header[1] != 0x03 || header[2] != 0x03 {
        // 常见情形：目标是 TLS alert（type 0x15，体 2 字节）——把描述读出
        // 来便于诊断（如 handshake_failure）。
        if header[0] == 0x15 {
            let alen = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut alert = vec![0u8; alen.min(2)];
            let _ = dest.read_exact(&mut alert).await;
            log::debug!(
                "reality borrow: dest answered with a TLS alert \
                 (level={:#04x} desc={:#04x})",
                alert.first().copied().unwrap_or(0),
                alert.get(1).copied().unwrap_or(0)
            );
        } else {
            log::debug!(
                "reality borrow: first record is not a handshake record \
                 ({:02x?})",
                header
            );
        }
        return Ok(None);
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if !(39..=16_384).contains(&len) {
        return Ok(None);
    }
    let mut body = vec![0u8; len];
    dest.read_exact(&mut body).await?;
    if len == 2 {
        log::debug!(
            "reality borrow: dest sent an alert: level={:#04x} desc={:#04x}",
            body[0],
            body[1]
        );
    }
    // 握手消息：type(1) + length(3) + 载荷(legacy_version 2B + random 32B
    // + session_id + cipher_suite + compression + extensions)。
    if body[0] != 0x02 || body[4] != 0x03 || body[5] != 0x03 {
        log::debug!(
            "reality borrow: first handshake message is not a ServerHello \
             (type {:#04x}, ver {:02x?})",
            body[0],
            &body[4..6]
        );
        return Ok(None);
    }
    let sid_len = body[38] as usize;
    let mut p = 39 + sid_len;
    if p + 5 > body.len() {
        return Ok(None);
    }
    let cipher_id = u16::from_be_bytes([body[p], body[p + 1]]);
    p += 2;
    if body[p] != 0 {
        return Ok(None); // compression must be null in TLS 1.3
    }
    p += 1;
    if p + 2 > body.len() {
        return Ok(None);
    }
    let ext_total = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let end = (p + ext_total).min(body.len());
    let (mut tls13, mut group_id) = (false, None);
    while p + 4 <= end {
        let etype = u16::from_be_bytes([body[p], body[p + 1]]);
        let elen = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        let (ds, de) = (p + 4, (p + 4 + elen).min(end));
        log::debug!(
            "reality borrow: target SH ext type={etype} len={elen}"
        );
        match etype {
            // supported_versions：ServerHello 携带单个 selected_version
            //（2 字节，RFC 8446 §4.1.3，与 ClientHello 的列表格式不同）。
            43 if ds + 2 <= de => {
                if body[ds] == 0x03 && body[ds + 1] == 0x04 {
                    tls13 = true;
                }
            },
            // key_share: the server's entry is group(2) + key_len(2) + key.
            51 if ds + 4 <= de => {
                let group = u16::from_be_bytes([body[ds], body[ds + 1]]);
                let klen =
                    u16::from_be_bytes([body[ds + 2], body[ds + 3]]) as usize;
                let usable = (group == GROUP_X25519_WIRE && klen == 32)
                    || (group == GROUP_X25519MLKEM768_WIRE && klen == 1120);
                if usable {
                    group_id = Some(group);
                }
            },
            _ => {},
        }
        p = p + 4 + elen;
    }
    log::debug!(
        "reality borrow: target ServerHello parsed: tls13={tls13} \
         group={group_id:?} cipher={cipher_id:#06x} len={}",
        body.len()
    );
    if !tls13 {
        return Ok(None);
    }
    Ok(group_id.map(|group_id| BorrowedServerHello { cipher_id, group_id }))
}

// ---------------------------------------------------------------------------
// Config decoding (mirrors xray infra/conf/transport_security.go)
// ---------------------------------------------------------------------------

fn decode_b32(s: &str) -> Result<[u8; 32], String> {
    use base64::engine::general_purpose;
    let s = s.trim();
    // xray prints URL-safe base64 without padding; accept the standard
    // alphabet and both padding conventions too (same as the client side).
    let bytes = general_purpose::STANDARD
        .decode(s)
        .or_else(|_| general_purpose::URL_SAFE.decode(s))
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(s))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(s))
        .map_err(|_| "reality: private_key is not valid base64".to_string())?;
    if bytes.len() != 32 {
        return Err(format!(
            "reality: private_key must decode to 32 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes.try_into().expect("32-byte array"))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(format!("reality: short_id '{s}' must be even-length hex"));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("reality: invalid hex in '{s}'"))
        })
        .collect()
}

/// "x.y.z" → [x, y, z] (xray parses up to three <256 components; missing
/// ones are zero).
fn parse_ver(s: &str, field: &str) -> Result<[u8; 3], String> {
    let mut out = [0u8; 3];
    for (i, part) in s.trim().split('.').enumerate() {
        if i == 3 {
            return Err(format!("reality: invalid {field}: {s}"));
        }
        out[i] = part
            .parse::<u8>()
            .map_err(|_| format!("reality: {field} component '{part}' must \
                                  be 0..=255"))?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Replay stream for the blocking accept
// ---------------------------------------------------------------------------

/// A blocking stream that replays the peeked ClientHello bytes before
/// delegating to the socket — lets boring's `SSL_accept` see exactly the
/// bytes that were consumed for the pre-handshake authentication.
pub(crate) struct PrefixStream {
    inner: std::net::TcpStream,
    prefix: Vec<u8>,
    pos: usize,
}

impl PrefixStream {
    pub(crate) fn new(prefix: Vec<u8>, inner: std::net::TcpStream) -> Self {
        Self {
            inner,
            prefix,
            pos: 0,
        }
    }
}

impl io::Read for PrefixStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

impl io::Write for PrefixStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl PrefixStream {
    /// Half/full close for the graceful-shutdown paths.
    pub(crate) fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown(Shutdown::Both)
    }
}

impl crate::inbound::vless::VlessIo for PrefixStream {
    fn set_read_timeout(&mut self, timeout: Duration) {
        // Inherent TcpStream method (Option-taking) — the local VlessIo one
        // has a different signature and cannot shadow the inherent call on
        // the inner stream.
        let _ = self.inner.set_read_timeout(Some(timeout));
    }

    fn close(&mut self) {
        let _ = self.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_PRIV: [u8; 32] = [42u8; 32];
    const TLS1_2_VERSION_BYTES: [u8; 2] = [0x03, 0x03];
    const CLIENT_PRIV: [u8; 32] = [7u8; 32];
    const NOW: u32 = 1_700_000_000;
    const SNI: &str = "www.example.com";

    fn b64(bytes: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD;
        STANDARD.encode(bytes)
    }

    fn server_config(private_key: &[u8; 32]) -> RealityInboundConfig {
        RealityInboundConfig {
            dest: "127.0.0.1:1".into(),
            server_names: vec![SNI.into()],
            private_key: b64(private_key),
            short_ids: vec!["".into(), "0123abcd".into()],
            max_time_diff_ms: 60_000,
            min_client_ver: None,
            max_client_ver: None,
        }
    }

    fn test_server() -> RealityServer {
        RealityServer::from_config(&server_config(&SERVER_PRIV)).unwrap()
    }

    fn server_pub() -> [u8; 32] {
        public_key_from_private(&SERVER_PRIV)
    }

    /// The 16-byte session_id plaintext (xray reality.go:141-148; the
    /// client-side layout is locked by transport/reality.rs's
    /// session_id_plaintext_layout_matches_xray).
    fn session_id_plaintext(
        client_ver: [u8; 3], timestamp: u32, short_id: &[u8; 8],
    ) -> [u8; 16] {
        let mut pt = [0u8; 16];
        pt[0..3].copy_from_slice(&client_ver);
        pt[3] = 0;
        pt[4..8].copy_from_slice(&timestamp.to_be_bytes());
        pt[8..16].copy_from_slice(short_id);
        pt
    }

    /// Client-side session_id sealing, mirroring xray reality.go:140-151 and
    /// the boring patch that implements it: AES-256-GCM-Seal of the 16-byte
    /// plaintext under the client-derived AuthKey, nonce = ClientRandom[20:],
    /// AAD = the final ClientHello with its session_id bytes zeroed. The
    /// hello is built twice: with a placeholder session_id (for the AAD —
    /// the zeroed session_id region of the finished hello) and then with the
    /// ciphertext in place.
    fn seal_hello(
        server_pub: &[u8; 32], timestamp: u32, short_id: &[u8; 8],
        client_ver: [u8; 3], sni: Option<&str>, tls13: bool,
        shares: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let random: [u8; 32] = std::array::from_fn(|i| i as u8);
        let client_secret = XStaticSecret::from(CLIENT_PRIV);
        let shared =
            client_secret.diffie_hellman(&XPublicKey::from(*server_pub));
        let client_auth_key = auth_key(shared.as_bytes(), &random);
        let plaintext = session_id_plaintext(client_ver, timestamp, short_id);
        // The AAD is the finished hello's message with the session_id
        // region zeroed — a placeholder-built message with a zero sid is
        // byte-identical to that.
        let placeholder =
            client_hello_msg(&random, &[0u8; 32], sni, tls13, shares);
        let session_id =
            seal_session_id(&client_auth_key, &random, &placeholder, &plaintext);
        wrap_record(&client_hello_msg(&random, &session_id, sni, tls13, shares))
    }

    /// Client-side session_id sealing, mirroring xray reality.go:140-151 /
    /// the boring patch: AES-256-GCM-Seal under the client-derived AuthKey,
    /// nonce = ClientRandom[20:], AAD = the ClientHello with its session_id
    /// bytes zeroed (offsets [39..71] of the handshake message).
    fn seal_session_id(
        auth_key: &[u8; 32], random: &[u8; 32], msg: &[u8], plaintext: &[u8; 16],
    ) -> [u8; 32] {
        let mut aad = msg.to_vec();
        aad[39..71].fill(0);
        let cipher = Aes256Gcm::new_from_slice(auth_key).unwrap();
        let nonce: &Nonce<_> = (&random[20..32])
            .try_into()
            .expect("GCM nonce is 12 bytes");
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .unwrap();
        ct.try_into().unwrap()
    }

    /// Hand-build the ClientHello handshake MESSAGE (4-byte header + body)
    /// — the AAD base, byte-identical to the server's reassembled `msg`.
    fn client_hello_msg(
        random: &[u8; 32], session_id: &[u8; 32], sni: Option<&str>,
        tls13: bool, shares: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(sni) = sni {
            let mut name = vec![0u8]; // host name type
            name.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            name.extend_from_slice(sni.as_bytes());
            let mut list = (name.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&name);
            exts.extend_from_slice(&0x0000u16.to_be_bytes());
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }
        if tls13 {
            exts.extend_from_slice(&43u16.to_be_bytes());
            // 1-byte list length + one 2-byte version.
            exts.extend_from_slice(&3u16.to_be_bytes());
            exts.push(2);
            exts.extend_from_slice(&0x0304u16.to_be_bytes());
        }
        if !shares.is_empty() {
            let mut entries = Vec::new();
            for (group, key) in shares {
                entries.extend_from_slice(&group.to_be_bytes());
                entries.extend_from_slice(&(key.len() as u16).to_be_bytes());
                entries.extend_from_slice(key);
            }
            exts.extend_from_slice(&51u16.to_be_bytes());
            // Extension data = [2B client_shares list length][entries].
            exts.extend_from_slice(&((entries.len() + 2) as u16).to_be_bytes());
            exts.extend_from_slice(&(entries.len() as u16).to_be_bytes());
            exts.extend_from_slice(&entries);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(random);
        body.push(32);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut msg = vec![0x01u8];
        msg.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        msg.extend_from_slice(&body);
        msg
    }

    /// Wrap a handshake message in a TLS handshake record.
    fn wrap_record(msg: &[u8]) -> Vec<u8> {
        let mut rec = vec![0x16u8, 0x03, 0x01];
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(msg);
        rec
    }

    fn x25519_share() -> (u16, Vec<u8>) {
        (
            GROUP_X25519,
            XPublicKey::from(&XStaticSecret::from(CLIENT_PRIV))
                .to_bytes()
                .to_vec(),
        )
    }

    /// A valid REALITY ClientHello from the anywhere client's perspective.
    fn good_hello(timestamp: u32, short_id: &[u8; 8]) -> Vec<u8> {
        seal_hello(&server_pub(), timestamp, short_id, [26, 3, 27], Some(SNI), true, &[x25519_share()])
    }

    fn parse(bytes: &[u8]) -> ClientHello {
        parse_client_hello(bytes).expect("parseable ClientHello")
    }

    // -- flight reassembly --------------------------------------------------

    /// The peek loop must not stop early: every strict prefix reports
    /// NeedMore until the full record has arrived.
    #[test]
    fn flight_needs_full_record() {
        let hello = good_hello(NOW, &[0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]);
        for i in 1..hello.len() {
            assert!(
                matches!(walk_hello_flight(&hello[..i]), Flight::NeedMore),
                "prefix of {i} bytes reported complete"
            );
        }
        assert!(matches!(walk_hello_flight(&hello), Flight::Complete(_)));
    }

    /// Non-TLS garbage is Garbage (stop reading, splice to dest).
    #[test]
    fn flight_garbage() {
        assert!(matches!(
            walk_hello_flight(b"GET / HTTP/1.1\r\n\r\n"),
            Flight::Garbage
        ));
        // A change-cipher-spec record first: not a ClientHello flight.
        let ccs = [0x14u8, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert!(matches!(walk_hello_flight(&ccs), Flight::Garbage));
    }

    /// A ClientHello split across two TLS records reassembles into the same
    /// handshake message (plan doc §6.6) — the AAD depends on it.
    #[test]
    fn flight_reassembles_across_records() {
        let hello = good_hello(NOW, &[0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]);
        let full = parse(&hello);
        let msg = full.msg.clone();
        assert!(msg.starts_with(&[0x01]));
        // The sealed session_id rides at record(5) + msg[39..71].
        assert_eq!(&hello[5 + 39..5 + 71], full.session_id.as_ref().unwrap());

        // Re-emit the handshake message as two records split mid-body.
        let split = 40;
        let mut two_records = Vec::new();
        for (part, ver) in [(&msg[..split], 0x0301u16), (&msg[split..], 0x0303u16)]
        {
            two_records.push(0x16);
            two_records.extend_from_slice(&ver.to_be_bytes());
            two_records.extend_from_slice(&(part.len() as u16).to_be_bytes());
            two_records.extend_from_slice(part);
        }
        let parsed = parse(&two_records);
        assert_eq!(parsed.msg, msg);
        assert_eq!(parsed.session_id, full.session_id);
        assert_eq!(parsed.server_name, full.server_name);
        assert_eq!(parsed.peer_pub, full.peer_pub);
    }

    // -- authentication -----------------------------------------------------

    /// Cross-verification with the anywhere client's derivation: the server
    /// opens a session_id sealed with the client-computed AuthKey and the
    /// two derivations agree.
    #[test]
    fn authenticates_client_session_id() {
        let server = test_server();
        let hello = parse(&good_hello(NOW, &[0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]));
        let server_auth_key = server
            .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
            .unwrap();
        // The client's own derivation for the same flight.
        let random: [u8; 32] = std::array::from_fn(|i| i as u8);
        let client_shared = XStaticSecret::from(CLIENT_PRIV)
            .diffie_hellman(&XPublicKey::from(server_pub()));
        assert_eq!(
            server_auth_key,
            auth_key(client_shared.as_bytes(), &random)
        );
    }

    /// boring/Chrome clients offer an MLKEM768 share alongside x25519; xray
    /// prefers the plain x25519 entry (tls.go:215-228) — so does the server.
    #[test]
    fn prefers_x25519_over_mlkem_share() {
        let server = test_server();
        let client_pub = XPublicKey::from(&XStaticSecret::from(CLIENT_PRIV))
            .to_bytes();
        // The hybrid share is mlkem_ct(1184) || x25519(32); the x25519
        // component is the same key the plain share carries.
        let mut mlkem = vec![0u8; MLKEM768_ENCAP_SIZE];
        mlkem.extend_from_slice(&client_pub);
        let hello = parse(&seal_hello(
            &server_pub(),
            NOW,
            &[0u8; 8],
            [26, 3, 27],
            Some(SNI),
            true,
            &[
                (GROUP_X25519MLKEM768, mlkem),
                (GROUP_X25519, client_pub.to_vec()),
            ],
        ));
        server
            .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
            .unwrap();
    }

    /// 缺省 short_ids（空列表）= 只接受全零 short_id（sing-box 行为）：
    /// 全零客户端通过，非零 short_id 仍被拒绝。
    #[test]
    fn short_ids_default_accepts_zero_only() {
        let mut cfg = server_config(&SERVER_PRIV);
        cfg.short_ids = vec![];
        let server = RealityServer::from_config(&cfg).unwrap();

        // 全零 short_id（客户端未配置 short_id 时发送的值）→ 通过。
        let hello = parse(&good_hello(NOW, &[0u8; 8]));
        server
            .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
            .unwrap();

        // 非零 short_id 不在（空的显式）列表里 → 拒绝。
        let hello = parse(&good_hello(NOW, &[0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]));
        let err = server
            .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
            .unwrap_err();
        assert!(err.contains("short_id"), "{err}");
    }

    /// fallback dest 连不上（拒连）时快速返回，不挂起拼接。
    #[tokio::test]
    async fn splice_fallback_returns_on_dial_failure() {
        // 占住一个端口再释放：连接它的行为是确定性的拒连。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = test_server();
        let dest_addr = server.dest().to_string();
        // 用拒连端口作为 dest。
        let mut cfg = server_config(&SERVER_PRIV);
        cfg.dest = addr.to_string();
        drop(dest_addr);
        let server = RealityServer::from_config(&cfg).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let client_addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move {
            tokio::net::TcpStream::connect(client_addr).await.unwrap()
        });
        let (client, _) = listener.accept().await.unwrap();
        let _ = connect.await.unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.splice_fallback(client, b"GET / HTTP/1.1\r\n\r\n".to_vec()),
        )
        .await
        .expect("splice_fallback must return promptly on dial failure");
    }

    #[test]
    fn rejects_stale_timestamp() {
        let server = test_server();
        let hello = parse(&good_hello(NOW, &[0u8; 8]));
        // +61s is beyond the 60s window; exactly +60s still passes.
        let err = server
            .authenticate_hello_at(&hello, i64::from(NOW + 61) * 1000)
            .unwrap_err();
        assert!(err.contains("timestamp"), "{err}");
        server
            .authenticate_hello_at(&hello, i64::from(NOW + 60) * 1000)
            .unwrap();
        // Future timestamps within the window pass too (|now − ts|).
        server
            .authenticate_hello_at(&hello, i64::from(NOW - 60) * 1000)
            .unwrap();
    }

    #[test]
    fn rejects_unknown_short_id() {
        let server = test_server();
        let hello = parse(&good_hello(
            NOW,
            &[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0],
        ));
        let err = server
            .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
            .unwrap_err();
        assert!(err.contains("short_id"), "{err}");
    }

    /// The empty short_id entry ("") is the all-zero id (xray zero-pads each
    /// entry into the 8-byte wire size) — clients with an empty short_id.
    #[test]
    fn accepts_zero_short_id() {
        let server = test_server();
        let hello = parse(&good_hello(NOW, &[0u8; 8]));
        server
            .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
            .unwrap();
    }

    #[test]
    fn rejects_wrong_sni() {
        let server = test_server();
        for sni in [None, Some("other.example.com")] {
            let hello = parse(&seal_hello(
                &server_pub(),
                NOW,
                &[0u8; 8],
                [26, 3, 27],
                sni,
                true,
                &[x25519_share()],
            ));
            let err = server
                .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
                .unwrap_err();
            assert!(err.contains("server name"), "{err}");
        }
    }

    #[test]
    fn rejects_non_tls13_and_missing_share() {
        let server = test_server();
        // No supported_versions extension → not TLS 1.3 (tls.go:211).
        let hello = parse(&seal_hello(
            &server_pub(),
            NOW,
            &[0u8; 8],
            [26, 3, 27],
            Some(SNI),
            false,
            &[x25519_share()],
        ));
        let err = server
            .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
            .unwrap_err();
        assert!(err.contains("TLS 1.3"), "{err}");
        // TLS 1.3 but no key share → no AuthKey to derive.
        let hello = parse(&seal_hello(
            &server_pub(),
            NOW,
            &[0u8; 8],
            [26, 3, 27],
            Some(SNI),
            true,
            &[],
        ));
        let err = server
            .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
            .unwrap_err();
        assert!(err.contains("key share"), "{err}");
    }

    /// A server keyed differently cannot open the session_id (AEAD tag).
    #[test]
    fn rejects_wrong_server_key() {
        let server =
            RealityServer::from_config(&server_config(&[43u8; 32])).unwrap();
        let hello = parse(&good_hello(NOW, &[0u8; 8]));
        let err = server
            .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
            .unwrap_err();
        assert!(err.contains("decryption"), "{err}");
    }

    /// Version range (tls.go:257-259): the anywhere default has NO floor —
    /// xray's default [26, 3, 27] would reject sing-box clients (plan doc
    /// §1.1) — while an explicit `min_client_ver` is enforced, and an
    /// explicit ceiling applies on top.
    #[test]
    fn client_version_range() {
        // Default: everything passes, from the xray-default floor up and
        // sing-box's self-reported {1, 8, 1} down to all-zero.
        let server = test_server();
        for ver in [[0u8, 0, 0], [1, 8, 1], [26, 3, 27], [30, 0, 0]] {
            let hello = parse(&seal_hello(
                &server_pub(),
                NOW,
                &[0u8; 8],
                ver,
                Some(SNI),
                true,
                &[x25519_share()],
            ));
            server
                .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
                .unwrap_or_else(|e| panic!("default floor: ver {ver:?}: {e}"));
        }
        // An explicit floor refuses anything below it and accepts exactly
        // the floor (xray semantics when minClientVer is configured).
        let mut cfg = server_config(&SERVER_PRIV);
        cfg.min_client_ver = Some("26.3.27".into());
        let server = RealityServer::from_config(&cfg).unwrap();
        for (ver, ok) in [([26u8, 3, 27], true), ([25u8, 9, 9], false)] {
            let hello = parse(&seal_hello(
                &server_pub(),
                NOW,
                &[0u8; 8],
                ver,
                Some(SNI),
                true,
                &[x25519_share()],
            ));
            assert_eq!(
                server
                    .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
                    .is_ok(),
                ok,
                "explicit floor: ver {ver:?}"
            );
        }
        // Explicit ceiling refuses anything above it.
        let mut cfg = server_config(&SERVER_PRIV);
        cfg.max_client_ver = Some("26.3.26".into());
        let server = RealityServer::from_config(&cfg).unwrap();
        let hello = parse(&good_hello(NOW, &[0u8; 8]));
        assert!(
            server
                .authenticate_hello_at(&hello, i64::from(NOW) * 1000)
                .is_err()
        );
    }

    // -- certificate ----------------------------------------------------------

    /// The per-connection certificate must satisfy the client's §S1.3
    /// check (reality.rs verify_reality_cert / xray reality.go:76-115):
    /// Ed25519 leaf, signature == HMAC-SHA512(AuthKey, leaf pubkey), and
    /// the HMAC must differ per AuthKey.
    #[test]
    fn derived_cert_matches_client_check() {
        let server = test_server();
        let auth_key = [9u8; 32];
        let cert = server.cert.derive(&auth_key).unwrap();

        let mut raw_buf = [0u8; 64];
        let raw = cert
            .public_key()
            .unwrap()
            .raw_public_key(&mut raw_buf)
            .unwrap();
        assert_eq!(raw.len(), 32, "leaf must be an Ed25519 key");
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&auth_key)
            .unwrap();
        mac.update(raw);
        assert_eq!(
            cert.signature().as_slice(),
            mac.finalize().into_bytes().as_slice(),
        );

        // Different AuthKey → different signature over the same template.
        let other = server.cert.derive(&[10u8; 32]).unwrap();
        assert_ne!(cert.signature().as_slice(), other.signature().as_slice());
        // Same AuthKey → deterministic (client and server derive the same
        // AuthKey independently, reality.rs:144-197).
        assert_eq!(
            cert.signature().as_slice(),
            server
                .cert
                .derive(&[9u8; 32])
                .unwrap()
                .signature()
                .as_slice()
        );
        // The template's own key must not leak: the template signature is
        // not the HMAC of any test AuthKey.
        assert_ne!(
            server.cert.der,
            cert.to_der().unwrap(),
            "per-connection cert must differ from the template"
        );
    }

    // -- config parsing ---------------------------------------------------

    #[test]
    fn config_rejects_invalid_input() {
        let mut cfg = server_config(&SERVER_PRIV);
        cfg.private_key = "no base64!!".into();
        assert!(RealityServer::from_config(&cfg)
            .unwrap_err()
            .contains("base64"));

        let mut cfg = server_config(&SERVER_PRIV);
        cfg.private_key = b64(&[1u8; 16]);
        assert!(RealityServer::from_config(&cfg)
            .unwrap_err()
            .contains("32 bytes"));

        let mut cfg = server_config(&SERVER_PRIV);
        cfg.server_names.clear();
        assert!(RealityServer::from_config(&cfg)
            .unwrap_err()
            .contains("server_names"));

        // 空 short_ids 现在是合法的（缺省 = 只接受全零 short_id，
        // 与 sing-box 一致；行为覆盖见 short_ids_default_accepts_zero_only）。

        let mut cfg = server_config(&SERVER_PRIV);
        cfg.short_ids = vec!["00112233445566778899".into()];
        assert!(RealityServer::from_config(&cfg)
            .unwrap_err()
            .contains("too long"));

        let mut cfg = server_config(&SERVER_PRIV);
        cfg.short_ids = vec!["0g".into()];
        assert!(RealityServer::from_config(&cfg)
            .unwrap_err()
            .contains("hex"));

        let mut cfg = server_config(&SERVER_PRIV);
        cfg.min_client_ver = Some("1.2.3.4".into());
        assert!(RealityServer::from_config(&cfg)
            .unwrap_err()
            .contains("min_client_ver"));

        let mut cfg = server_config(&SERVER_PRIV);
        cfg.dest = "  ".into();
        assert!(RealityServer::from_config(&cfg)
            .unwrap_err()
            .contains("dest"));
    }

    /// xray's version semantics: missing components are zero, at most
    /// three, each < 256.
    #[test]
    fn parse_ver_semantics() {
        assert_eq!(parse_ver("26", "v").unwrap(), [26, 0, 0]);
        assert_eq!(parse_ver("26.3", "v").unwrap(), [26, 3, 0]);
        assert_eq!(parse_ver("26.3.27", "v").unwrap(), [26, 3, 27]);
        assert!(parse_ver("26.3.27.1", "v").is_err());
        assert!(parse_ver("26.300", "v").is_err());
    }

    // -- socket-level peek --------------------------------------------------

    /// Peek over a real socket pair: the anywhere-style client bytes
    /// authenticate; garbage falls back with the exact consumed prefix.
    #[tokio::test(flavor = "multi_thread")]
    async fn peek_authenticates_over_socket() {
        let server = std::sync::Arc::new(test_server());
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_peek = server.clone();
        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            server_peek.authenticate(&mut sock).await
        });

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        // authenticate() stamps the real clock, so seal with a current
        // timestamp (inside the 60s window).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let hello = good_hello(now, &[0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]);
        use tokio::io::AsyncWriteExt;
        client.write_all(&hello).await.unwrap();
        match server_task.await.unwrap().unwrap() {
            RealityPeek::Authenticated { auth_key, prefix, .. } => {
                assert_eq!(prefix, hello);
                // The server's AuthKey opens what the client sealed.
                let mut mac =
                    <Hmac<Sha512> as KeyInit>::new_from_slice(&auth_key)
                        .unwrap();
                mac.update(&server.cert.ed_pub);
                let expected = mac.finalize().into_bytes();
                let cert = server.cert.derive(&auth_key).unwrap();
                assert_eq!(cert.signature().as_slice(), expected.as_slice());
            },
            RealityPeek::Fallback { .. } => panic!("expected Authenticated"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peek_falls_back_on_garbage() {
        let server = std::sync::Arc::new(test_server());
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_peek = server.clone();
        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            server_peek.authenticate(&mut sock).await
        });

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let probe = b"GET / HTTP/1.1\r\nHost: probe\r\n\r\n";
        use tokio::io::AsyncWriteExt;
        client.write_all(probe).await.unwrap();
        match server_task.await.unwrap().unwrap() {
            RealityPeek::Fallback { prefix } => {
                assert_eq!(prefix, probe.to_vec());
            },
            RealityPeek::Authenticated { .. } => {
                panic!("garbage must not authenticate")
            },
        }
    }

    // -- ServerHello borrow (xtls/reality 目标站点借用) ----------------------

    /// 构造一个可借用的目标站点 ServerHello 记录（TLS 1.3 + x25519 share +
    /// 指定套件）。
    fn fake_target_sh(cipher_id: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&TLS1_2_VERSION_BYTES);
        payload.extend_from_slice(&[0xA5u8; 32]); // random
        payload.push(32); // session_id echo length (REALITY size)
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&cipher_id.to_be_bytes());
        payload.push(0); // compression
        // extensions: key_share(x25519) + supported_versions(1.3)
        let mut ext = Vec::new();
        ext.extend_from_slice(&51u16.to_be_bytes()); // key_share
        let ks_data_len = 4u16 + 32u16; // group(2) + klen(2) + key
        ext.extend_from_slice(&ks_data_len.to_be_bytes());
        ext.extend_from_slice(&GROUP_X25519_WIRE.to_be_bytes());
        ext.extend_from_slice(&32u16.to_be_bytes());
        ext.extend_from_slice(&[9u8; 32]);
        ext.extend_from_slice(&43u16.to_be_bytes());
        // ServerHello 的 selected_version = 2 字节，无列表长度。
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&[0x03, 0x04]);
        payload.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        payload.extend_from_slice(&ext);

        // 握手消息 = type(1) + length(3) + payload。
        let mut hs = Vec::new();
        hs.push(0x02);
        let plen = payload.len();
        hs.extend_from_slice(&[
            (plen >> 16) as u8,
            (plen >> 8) as u8,
            plen as u8,
        ]);
        hs.extend_from_slice(&payload);

        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// 派生 dest：接受连接、读取（丢弃）客户端字节、回写伪造的目标
    /// ServerHello 记录。
    async fn spawn_fake_dest(cipher_id: u16) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let sh = fake_target_sh(cipher_id);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let sh = sh.clone();
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf)
                        .await;
                    let _ = sock.write_all(&sh).await;
                    // 保持半开片刻，等待服务端读取 SH。
                    tokio::time::sleep(Duration::from_millis(500)).await;
                });
            }
        });
        port
    }

    /// read_target_server_hello 解析伪造的目标 ServerHello 并提取套件/组。
    #[tokio::test]
    async fn borrow_parses_target_server_hello() {
        let port = spawn_fake_dest(0x1302).await;
        let mut dest = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        use tokio::io::AsyncWriteExt;
        dest.write_all(b"client-hello-bytes").await.unwrap();
        let sh = read_target_server_hello(&mut dest)
            .await
            .unwrap()
            .expect("borrowable ServerHello");
        assert_eq!(sh.cipher_id, 0x1302);
        assert_eq!(sh.group_id, GROUP_X25519_WIRE);
    }

    /// 非借用形态：目标回了 TLS 1.2 记录 → None（降级到本地握手）。
    #[tokio::test]
    async fn borrow_rejects_non_tls13_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                // TLS 1.2 风格的 ServerHello（legacy_version 0x0303 但
                // supported_versions 不含 1.3）。
                let mut hs = Vec::new();
                hs.push(0x02);
                hs.extend_from_slice(&TLS1_2_VERSION_BYTES);
                hs.extend_from_slice(&[0xA5u8; 32]);
                hs.push(0);
                hs.extend_from_slice(&0x1302u16.to_be_bytes());
                hs.push(0);
                hs.extend_from_slice(&0u16.to_be_bytes());
                let mut rec = vec![0x16, 0x03, 0x03];
                rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
                rec.extend_from_slice(&hs);
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let _ = sock.write_all(&rec).await;
                });
            }
        });
        let mut dest = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        assert!(read_target_server_hello(&mut dest).await.unwrap().is_none());
    }

    /// borrow_server_hello 编排：dial → 回放 → 读取 → 校验（marker 套件）。
    #[tokio::test]
    async fn borrow_server_hello_end_to_end() {
        let marker = 0x1302;
        let port = spawn_fake_dest(marker).await;
        let mut cfg = server_config(&SERVER_PRIV);
        cfg.dest = format!("127.0.0.1:{port}");
        let server = RealityServer::from_config(&cfg).unwrap();

        let ctx = BorrowContext {
            // 客户端必须提供 marker 套件与 x25519 组。
            cipher_suites: vec![0x1301, marker],
            groups: vec![GROUP_X25519_WIRE],
        };
        let prefix = good_hello(NOW, &[0u8; 8]);
        let borrowed = server
            .borrow_server_hello(&prefix, &ctx)
            .await
            .expect("borrow must succeed against the fake dest");
        assert_eq!(borrowed.cipher_id, marker);
        assert_eq!(borrowed.group_id, GROUP_X25519_WIRE);

        // 不在客户端提供列表内的套件不可借用。
        let ctx = BorrowContext {
            cipher_suites: vec![0x1301],
            groups: vec![GROUP_X25519_WIRE],
        };
        assert!(server.borrow_server_hello(&prefix, &ctx).await.is_none());
    }
}
