//! Spike: REALITY ClientHello injection feasibility (M1 step 0).
//!
//! REALITY carries client auth (X25519 proof / short-id / timestamp) inside
//! the ClientHello's legacy session_id, and derives an AuthKey from the
//! client's own X25519 key share. boring has no public API for either, so
//! this spike validates the boring-sys patch route
//! (`third_party/boring-sys/patches/reality-session-id.patch`):
//!
//! * `inlib`      — patched boring, session_id override set via the new
//!                  `SSL_set_client_session_id_override` FFI **before**
//!                  `SSL_connect`. Expect: wire session_id == MARKER, TLS 1.3
//!                  handshake completes, application data round-trips.
//!                  Only possible if the patch injects the session_id *before
//!                  transcript hashing* (see `posthoc` for the counter-proof).
//! * `inlib-noop` — patched boring, override NOT set (control). Expect:
//!                  random session_id != MARKER, handshake completes.
//! * `posthoc`    — stock behavior; the first client flight is rewritten at
//!                  the Rust stream layer *after* boring hashed the transcript.
//!                  Expect: handshake FAILS (transcript mismatch) — empirically
//!                  ruling out the "no-patch, rewrite on the wire" route.
//! * `authkey`    — full REALITY AuthKey derivation: the client's certificate
//!                  verification callback calls `SSL_client_key_share_x25519`
//!                  (the patch's second API) with the server's REALITY public
//!                  key, then HKDF-SHA256(salt=random[:20], info="REALITY").
//!                  The server computes the same from the X25519 key share it
//!                  parses out of the wire ClientHello. Expect: both sides
//!                  derive identical 32-byte AuthKeys over a completed TLS 1.3
//!                  handshake.
//! * `reality-handshake` — the complete REALITY authentication flow (M1
//!                  shape): the client asks boring (via the patch's new
//!                  `SSL_set_reality_client_hello_params`) to derive its
//!                  ClientHello session_id in-library — plaintext
//!                  `ver[3] || 0x00 || BE32(unix ts) || short_id[8]`,
//!                  AES-256-GCM-sealed under the AuthKey, AAD = full
//!                  ClientHello with session_id zeroed. The server (a
//!                  stand-in for xtls/reality) opens that session_id from the
//!                  wire, validates the plaintext structure, mints a
//!                  "REALITY-style" certificate (Ed25519 SPKI whose signature
//!                  value is HMAC-SHA512(AuthKey, ed25519_pub)), and finishes
//!                  TLS 1.3. The client's certificate callback re-derives the
//!                  AuthKey and verifies that HMAC — the handshake can only
//!                  complete when every step matches.
//!
//! The server thread peeks the raw ClientHello record off the socket first
//! (to capture the wire session_id / random / key share), then completes the
//! TLS 1.3 handshake on top of the same bytes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::exit;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use boring::pkey::PKey;
use boring::rand::rand_bytes;
use boring::ssl::{
    Ssl, SslAlert, SslContext, SslContextBuilder, SslMethod, SslSignatureAlgorithm,
    SslStream, SslVerifyError, SslVerifyMode, SslVersion,
};
use boring::x509::X509;
use foreign_types::ForeignTypeRef; // SslRef::as_ptr
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

/// The REALITY short_id this spike uses (8 bytes, as if hex "0a0b0c0d0e0f1011").
const SPIKE_SHORT_ID: [u8; 8] = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11];

/// Core version triple carried in the REALITY session_id plaintext, parsed
/// from the crate version (same rule anywhere will use: CARGO_PKG_VERSION).
fn version3() -> [u8; 3] {
    let mut out = [0u8; 3];
    for (i, part) in env!("CARGO_PKG_VERSION").split('.').take(3).enumerate() {
        out[i] = part.parse::<u8>().unwrap_or(0);
    }
    out
}

/// 32-byte marker: "REALITY-SPIKE" prefix + 0xA5 fill.
fn marker() -> [u8; 32] {
    let mut m = [0xA5u8; 32];
    m[..13].copy_from_slice(b"REALITY-SPIKE");
    m
}

/// REALITY AuthKey = HKDF-SHA256(ikm = x25519 share secret,
///                               salt = client_random[:20],
///                               info = "REALITY").
fn reality_authkey(shared: &[u8; 32], client_random: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared);
    let mut out = [0u8; 32];
    hk.expand(b"REALITY", &mut out).unwrap();
    out
}

// ---------------------------------------------------------------------------
// reality-handshake mode helpers
// ---------------------------------------------------------------------------

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p);
    }
    der_tlv(0x30, &content)
}

/// Build a minimal X.509 certificate (DER) carrying `ed25519_pub` in its
/// SubjectPublicKeyInfo and `sig` (64 bytes) as the signature value. In the
/// REALITY flow `sig` is HMAC-SHA512(AuthKey, ed25519_pub): not a valid
/// Ed25519 signature, but the declared algorithm (id-Ed25519) and length both
/// match, which is exactly the trick xtls/reality's custom verification path
/// relies on (client: `HMAC-SHA512(AuthKey, certpub) == cert.Signature`).
fn build_reality_cert(ed25519_pub: &[u8], sig: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier for Ed25519: SEQUENCE { OID 1.3.101.112 }.
    let alg: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    // Name: CN=reality-spike.
    let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03]; // OID 2.5.4.3 (CN)
    let cn_value = der_tlv(0x0c, b"reality-spike"); // UTF8String
    let atv = der_seq(&[cn_oid, &cn_value]);
    let rdn = der_tlv(0x31, &atv); // SET
    let name = der_seq(&[&rdn]);
    // Validity (fixed window; nothing on this path checks it).
    let validity = der_seq(&[
        &der_tlv(0x17, b"260101000000Z"),
        &der_tlv(0x17, b"360101000000Z"),
    ]);
    // SubjectPublicKeyInfo: BIT STRING with 0 unused bits + raw 32B key.
    let mut bits = vec![0u8];
    bits.extend_from_slice(ed25519_pub);
    let spki = der_seq(&[alg, &der_tlv(0x03, &bits)]);
    // TBSCertificate.
    let tbs = der_seq(&[
        &der_tlv(0xa0, &[0x02, 0x01, 0x02]), // [0] EXPLICIT version v3
        &der_tlv(0x02, &[0x01]),             // serialNumber = 1
        alg,
        &name,
        &validity,
        &name,
        &spki,
    ]);
    let mut sig_bits = vec![0u8];
    sig_bits.extend_from_slice(sig);
    der_seq(&[&tbs, alg, &der_tlv(0x03, &sig_bits)])
}

/// The client side of the REALITY certificate check (runs inside the
/// certificate verification callback): derive the AuthKey from this
/// connection's own key share + ClientRandom, then compare
/// HMAC-SHA512(AuthKey, leaf-cert Ed25519 public key) with the certificate's
/// signature value. Returns the derived AuthKey on success.
fn reality_verify_cert(
    ssl_ref: &mut boring::ssl::SslRef, reality_pub: &[u8; 32],
) -> Result<Vec<u8>, SslVerifyError> {
    let fail = || SslVerifyError::Invalid(SslAlert::HANDSHAKE_FAILURE);
    let ptr = ssl_ref.as_ptr() as *mut boring_sys::SSL;
    unsafe {
        let mut random = [0u8; 32];
        boring_sys::SSL_get_client_random(ptr, random.as_mut_ptr(), 32);
        let mut shared = [0u8; 32];
        if boring_sys::SSL_client_key_share_x25519(
            ptr,
            reality_pub.as_ptr(),
            shared.as_mut_ptr(),
        ) != 1
        {
            return Err(fail());
        }
        let authkey = reality_authkey(&shared, &random);

        let cert = ssl_ref
            .peer_certificate()
            .ok_or_else(fail)?;
        let pkey = cert.public_key().map_err(|_| fail())?;
        let mut raw = [0u8; 64];
        let raw = pkey.raw_public_key(&mut raw).map_err(|_| fail())?;
        if raw.len() != 32 {
            return Err(fail()); // REALITY expects an Ed25519 leaf key
        }
        let sig = cert.signature().as_slice();
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&authkey).map_err(|_| fail())?;
        mac.update(raw);
        let expected = mac.finalize().into_bytes();
        if expected.as_slice() != sig {
            return Err(fail());
        }
        Ok(authkey.to_vec())
    }
}

/// Client ctx for `reality-handshake` mode: REALITY parameters are set on the
/// SSL (see main), the certificate callback implements §S1.3's HMAC check.
fn reality_client_ctx(
    reality_pub: [u8; 32], slot: Arc<Mutex<Option<Vec<u8>>>>,
) -> SslContext {
    let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
    b.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    // boring's default client sigalgs do not include ed25519; the REALITY
    // server presents an Ed25519 leaf certificate whose CertificateVerify is
    // signed with it, so the client must offer ed25519 or the handshake dies
    // with NO_COMMON_SIGNATURE_ALGORITHMS.
    b.set_verify_algorithm_prefs(&[
        SslSignatureAlgorithm::ED25519,
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA256,
    ])
    .unwrap();
    b.set_verify(SslVerifyMode::PEER);
    b.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl_ref| {
        match reality_verify_cert(ssl_ref, &reality_pub) {
            Ok(authkey) => {
                *slot.lock().unwrap() = Some(authkey);
                Ok(())
            },
            Err(e) => {
                eprintln!("[reality] certificate HMAC check failed");
                Err(e)
            },
        }
    });
    b.build()
}

/// Server side of the REALITY authentication (stand-in for xtls/reality
/// tls.go:195-300): derive the AuthKey from the wire ClientHello, open the
/// encrypted session_id, validate its plaintext structure, then mint a
/// REALITY-style certificate for this connection. Returns the AuthKey (to be
/// compared with the client's), the certificate and its Ed25519 private key.
fn reality_server_auth(
    prefix: &[u8], secret: &XStaticSecret,
) -> Result<(Vec<u8>, X509, PKey<boring::pkey::Private>), String> {
    // prefix = record header (5) + ClientHello handshake message.
    let body = prefix
        .get(5..)
        .ok_or_else(|| "short ClientHello record".to_string())?;
    if body.len() < 71 || body[0] != 0x01 {
        return Err("not a ClientHello handshake message".into());
    }
    let sid_len = body[38] as usize;
    if sid_len != 32 {
        return Err(format!("session_id len {sid_len} != 32"));
    }
    let random: [u8; 32] = body[6..38].try_into().unwrap();
    let (_, client_pub) =
        parse_ch_random_and_x25519_pub(prefix).ok_or("no x25519 key share")?;
    let shared = secret.diffie_hellman(&XPublicKey::from(client_pub));
    let authkey = reality_authkey(shared.as_bytes(), &random);

    // AAD = the received ClientHello with the session_id field zeroed
    // (sessionId aliases raw[39..] inside the received bytes, exactly like
    // xtls/reality zeroes it before Open).
    let mut aad = body.to_vec();
    aad[39..71].fill(0);

    let cipher = Aes256Gcm::new_from_slice(&authkey)
        .map_err(|e| format!("aead key: {e}"))?;
    let pt = cipher
        .decrypt(
            (&random[20..32]).into(),
            Payload { msg: &body[39..71], aad: &aad },
        )
        .map_err(|_| "AES-256-GCM open of session_id failed".to_string())?;
    if pt.len() != 16 {
        return Err(format!("session_id plaintext len {}", pt.len()));
    }
    if pt[3] != 0 {
        return Err("session_id reserved byte [3] not zero".into());
    }
    if pt[8..16] != SPIKE_SHORT_ID {
        return Err(format!(
            "session_id short_id {:02x?} != expected {:02x?}",
            &pt[8..16],
            SPIKE_SHORT_ID
        ));
    }
    let ts = u32::from_be_bytes([pt[4], pt[5], pt[6], pt[7]]);
    eprintln!(
        "[reality] session_id open ok: ver={:?} ts={ts} short_id={:02x?}",
        &pt[..3],
        &pt[8..16]
    );

    // Mint the REALITY-style certificate for this connection. boring has no
    // generate_ed25519 constructor, so build the key via raw-byte FFI.
    let mut seed = [0u8; 32];
    rand_bytes(&mut seed).unwrap();
    let ed = unsafe {
        let ptr = boring_sys::EVP_PKEY_new_raw_private_key(
            boring_sys::EVP_PKEY_ED25519 as std::os::raw::c_int,
            std::ptr::null_mut(),
            seed.as_ptr(),
            seed.len(),
        );
        if ptr.is_null() {
            return Err("EVP_PKEY_new_raw_private_key failed".into());
        }
        use foreign_types::ForeignType;
        PKey::from_ptr(ptr)
    };
    let mut pubbuf = [0u8; 64];
    let raw_pub = ed.raw_public_key(&mut pubbuf).map_err(|e| e.to_string())?;
    if raw_pub.len() != 32 {
        return Err(format!("ed25519 pub len {}", raw_pub.len()));
    }
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&authkey)
        .map_err(|e| e.to_string())?;
    mac.update(raw_pub);
    let sig = mac.finalize().into_bytes();
    let der = build_reality_cert(raw_pub, &sig);
    let cert = X509::from_der(&der).map_err(|e| format!("parse own cert: {e}"))?;
    Ok((authkey.to_vec(), cert, ed))
}

/// Outcome reported by the server thread.
struct ServerOutcome {
    /// session_id captured from the raw ClientHello record (None if absent).
    wire_session_id: Option<Vec<u8>>,
    /// AuthKey the server derived from the wire ClientHello (authkey mode).
    authkey_server: Option<Vec<u8>>,
    /// Did the server-side TLS handshake complete?
    handshake_ok: bool,
    /// Did the app-data round-trip (client "ping" -> server "pong") complete?
    app_data_ok: bool,
    error: Option<String>,
}

/// Read/Write passthrough that replays `prefix` (the pre-read ClientHello
/// record) before delegating to the inner socket.
struct PrefixedStream {
    inner: TcpStream,
    prefix: Vec<u8>,
    pos: usize,
}

impl Read for PrefixedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

impl Write for PrefixedStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Parse the ClientHello record for (client_random, x25519 key-share pub).
/// Layout: record(5) + hs header(4) + version(2) + random(32) + sid_len(1)
/// + sid + cipher_len(2) + ciphers + comp_len(1) + comp + ext_len(2) + exts;
/// key_share (type 51) entries are {group(2), key_len(2), key}.
fn parse_ch_random_and_x25519_pub(prefix: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if prefix.len() < 44 + 32 + 2 + 1 {
        return None;
    }
    let random: [u8; 32] = prefix[11..43].try_into().ok()?;
    let sid_len = prefix[43] as usize;
    let mut c = 44 + sid_len;
    let cipher_len = u16::from_be_bytes([prefix[c], prefix[c + 1]]) as usize;
    c += 2 + cipher_len;
    let comp_len = prefix[c] as usize;
    c += 1 + comp_len;
    if c + 2 > prefix.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([prefix[c], prefix[c + 1]]) as usize;
    c += 2;
    let end = (c + ext_total).min(prefix.len());
    while c + 4 <= end {
        let etype = u16::from_be_bytes([prefix[c], prefix[c + 1]]);
        let elen = u16::from_be_bytes([prefix[c + 2], prefix[c + 3]]) as usize;
        let dstart = c + 4;
        let dend = (dstart + elen).min(end);
        if etype == 51 {
            let mut d = dstart + 2; // skip client_shares length
            while d + 4 <= dend {
                let group = u16::from_be_bytes([prefix[d], prefix[d + 1]]);
                let klen = u16::from_be_bytes([prefix[d + 2], prefix[d + 3]]) as usize;
                if group == 29 && klen == 32 && d + 4 + 32 <= dend {
                    let mut pubb = [0u8; 32];
                    pubb.copy_from_slice(&prefix[d + 4..d + 4 + 32]);
                    return Some((random, pubb));
                }
                d += 4 + klen;
            }
        }
        c = dstart + elen;
    }
    None
}

/// Read/Write passthrough that rewrites the ClientHello session_id **on the
/// wire only** (first flight). boring has already hashed the original bytes
/// into its transcript by the time this `write` runs, which is exactly why
/// this route must fail.
struct PostTranscriptRewriter {
    inner: TcpStream,
    marker: [u8; 32],
    done: bool,
}

impl PostTranscriptRewriter {
    fn rewrite_first_flight(&self, buf: &[u8]) -> Option<Vec<u8>> {
        // ClientHello: record header (5) + handshake header (4) +
        // legacy_version (2) + random (32) = 43; then 1-byte session_id_len.
        if buf.len() < 44 + self.marker.len() || buf[0] != 0x16 || buf[5] != 0x01 {
            return None;
        }
        let sid_len = buf[43] as usize;
        if sid_len != self.marker.len() {
            return None; // not the TLS 1.3 compat 32-byte session_id
        }
        let mut out = buf.to_vec();
        out[44..44 + sid_len].copy_from_slice(&self.marker);
        Some(out)
    }
}

impl Read for PostTranscriptRewriter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for PostTranscriptRewriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let to_send: Vec<u8> = match (self.done, self.rewrite_first_flight(buf)) {
            (false, Some(patched)) => {
                eprintln!("[posthoc] rewrote session_id on first flight (post-transcript)");
                self.done = true;
                patched
            }
            _ => {
                self.done = true;
                buf.to_vec()
            }
        };
        let mut written = 0;
        while written < to_send.len() {
            written += self.inner.write(&to_send[written..])?;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn server_ctx() -> SslContext {
    let cert = X509::from_pem(
        &std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/cert.pem")).unwrap(),
    )
    .unwrap();
    let pkey = boring::pkey::PKey::private_key_from_pem(
        &std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/key.pem")).unwrap(),
    )
    .unwrap();
    let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
    b.set_certificate(&cert).unwrap();
    b.set_private_key(&pkey).unwrap();
    b.build()
}

fn client_ctx() -> SslContext {
    let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::NONE); // self-signed spike server
    b.build()
}

/// Client ctx for `authkey` mode: the custom verification callback derives
/// the REALITY AuthKey from this connection's X25519 key share while the
/// handshake is in flight, then accepts the (self-signed) cert.
fn authkey_client_ctx(
    server_reality_pub: [u8; 32], slot: Arc<Mutex<Option<Vec<u8>>>>,
) -> SslContext {
    let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::PEER);
    b.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl_ref| {
        let ptr = ssl_ref.as_ptr() as *mut boring_sys::SSL;
        let mut random = [0u8; 32];
        unsafe {
            boring_sys::SSL_get_client_random(ptr, random.as_mut_ptr(), 32);
        }
        let mut shared = [0u8; 32];
        let ok = unsafe {
            boring_sys::SSL_client_key_share_x25519(
                ptr,
                server_reality_pub.as_ptr(),
                shared.as_mut_ptr(),
            )
        };
        if ok == 1 {
            let ak = reality_authkey(&shared, &random);
            *slot.lock().unwrap() = Some(ak.to_vec());
        } else {
            eprintln!("[authkey] SSL_client_key_share_x25519 failed, code = {ok}");
        }
        Ok(()) // accept the self-signed spike cert
    });
    b.build()
}

fn report(
    tx: &mpsc::Sender<ServerOutcome>, wire_session_id: Option<Vec<u8>>, authkey_server: Option<Vec<u8>>,
    handshake_ok: bool, app_data_ok: bool, error: Option<String>,
) {
    let _ = tx.send(ServerOutcome { wire_session_id, authkey_server, handshake_ok, app_data_ok, error });
}

/// Server: peek the raw ClientHello record, then finish TLS 1.3 on top of it.
fn run_server(
    listener: TcpListener, tx: mpsc::Sender<ServerOutcome>, mode: String,
    reality_secret: Option<XStaticSecret>,
) {
    let (sock, _) = match listener.accept() {
        Ok(x) => x,
        Err(e) => {
            report(&tx, None, None, false, false, Some(format!("accept: {e}")));
            return;
        }
    };

    // Read exactly the first TLS record (the ClientHello), then replay it to
    // TLS below, so the handshake continues over the same bytes.
    let mut sock2 = sock;
    let prefixed = (|| -> std::io::Result<PrefixedStream> {
        let mut header = [0u8; 5];
        sock2.read_exact(&mut header)?;
        if header[0] != 0x16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected handshake record, got {:#x}", header[0]),
            ));
        }
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; len];
        sock2.read_exact(&mut body)?;
        if body.len() < 39 || body.len() < 39 + body[38] as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "short ClientHello",
            ));
        }
        let mut prefix = header.to_vec();
        prefix.extend_from_slice(&body);
        Ok(PrefixedStream { inner: sock2, prefix, pos: 0 })
    })();

    let mut prefixed = match prefixed {
        Ok(p) => p,
        Err(e) => {
            report(&tx, None, None, false, false, Some(format!("peek ClientHello: {e}")));
            return;
        }
    };

    // Extract the wire session_id from the prefix we already hold.
    let wire_session_id = {
        let sid_len = prefixed.prefix[5 + 4 + 2 + 32] as usize;
        if sid_len > 0 {
            Some(
                prefixed.prefix
                    [5 + 4 + 2 + 33..5 + 4 + 2 + 33 + sid_len]
                    .to_vec(),
            )
        } else {
            None
        }
    };

    // authkey mode: derive the server-side REALITY AuthKey from the wire.
    let mut authkey_server = None;
    if mode == "authkey" {
        let secret = reality_secret.as_ref().expect("authkey mode needs reality secret");
        if let Some((random, client_pub)) = parse_ch_random_and_x25519_pub(&prefixed.prefix) {
            let shared = secret.diffie_hellman(&XPublicKey::from(client_pub));
            let ak = reality_authkey(shared.as_bytes(), &random);
            authkey_server = Some(ak.to_vec());
        } else {
            eprintln!("[authkey] failed to parse random/x25519 pub from ClientHello");
        }
    }

    // reality-handshake mode: full REALITY server-side auth — open the
    // session_id from the wire, validate it, mint a REALITY-style cert.
    let mut reality_pair: Option<(X509, PKey<boring::pkey::Private>)> = None;
    if mode == "reality-handshake" {
        let secret = reality_secret
            .as_ref()
            .expect("reality-handshake mode needs reality secret");
        match reality_server_auth(&prefixed.prefix, secret) {
            Ok((authkey, cert, pkey)) => {
                authkey_server = Some(authkey);
                reality_pair = Some((cert, pkey));
            },
            Err(e) => {
                report(&tx, wire_session_id, None, false, false, Some(e));
                return;
            },
        }
    }

    let sctx = match &reality_pair {
        Some((cert, pkey)) => {
            let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
            b.set_certificate(cert).unwrap();
            b.set_private_key(pkey).unwrap();
            b.build()
        },
        None => server_ctx(),
    };
    let ssl = match Ssl::new(&sctx) {
        Ok(s) => s,
        Err(e) => {
            report(&tx, wire_session_id, authkey_server, false, false, Some(format!("Ssl::new: {e}")));
            return;
        }
    };
    let mut stream = match SslStream::new(ssl, &mut prefixed) {
        Ok(s) => s,
        Err(e) => {
            report(&tx, wire_session_id, authkey_server, false, false, Some(format!("SslStream::new: {e}")));
            return;
        }
    };

    if let Err(e) = stream.accept() {
        report(&tx, wire_session_id, authkey_server, false, false, Some(format!("accept: {e}")));
        return;
    }

    // App data round-trip: read "ping", reply "pong".
    let mut buf = [0u8; 4];
    let app_data_ok = match stream.read_exact(&mut buf) {
        Ok(_) if &buf == b"ping" => stream.write_all(b"pong").is_ok(),
        _ => false,
    };
    drop(stream);

    report(&tx, wire_session_id, authkey_server, true, app_data_ok, None);
}

enum ClientWrap {
    Plain(TcpStream),
    Posthoc(PostTranscriptRewriter),
}

impl Read for ClientWrap {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ClientWrap::Plain(s) => s.read(buf),
            ClientWrap::Posthoc(s) => s.read(buf),
        }
    }
}

impl Write for ClientWrap {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ClientWrap::Plain(s) => s.write(buf),
            ClientWrap::Posthoc(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ClientWrap::Plain(s) => s.flush(),
            ClientWrap::Posthoc(s) => s.flush(),
        }
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "inlib".into());
    let marker = marker();

    // authkey / reality-handshake modes: server-side REALITY keypair.
    let reality_secret = if mode == "authkey" || mode == "reality-handshake" {
        let mut sk = [0u8; 32];
        rand_bytes(&mut sk).unwrap();
        Some(XStaticSecret::from(sk))
    } else {
        None
    };
    let reality_pub_bytes: Option<[u8; 32]> = reality_secret.as_ref().map(|s| {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(XPublicKey::from(s).as_bytes());
        pk
    });

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel::<ServerOutcome>();
    let mode_srv = mode.clone();
    thread::spawn(move || run_server(listener, tx, mode_srv, reality_secret));

    // Client
    let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let wrap = if mode == "posthoc" {
        ClientWrap::Posthoc(PostTranscriptRewriter { inner: sock, marker, done: false })
    } else {
        ClientWrap::Plain(sock)
    };

    let authkey_slot = Arc::new(Mutex::new(None::<Vec<u8>>));
    let ssl = if mode == "authkey" {
        let ctx = authkey_client_ctx(reality_pub_bytes.unwrap(), authkey_slot.clone());
        let mut ssl = Ssl::new(&ctx).unwrap();
        ssl.set_hostname("spike.local").unwrap();
        ssl
    } else if mode == "reality-handshake" {
        let ctx = reality_client_ctx(reality_pub_bytes.unwrap(), authkey_slot.clone());
        let mut ssl = Ssl::new(&ctx).unwrap();
        ssl.set_hostname("spike.local").unwrap();
        // The patch's parameter API: session_id is derived inside boring from
        // this connection's ClientRandom + key share at hello-build time.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let ver = version3();
        let rc = unsafe {
            boring_sys::SSL_set_reality_client_hello_params(
                ssl.as_ptr(),
                reality_pub_bytes.unwrap().as_ptr(),
                SPIKE_SHORT_ID.as_ptr(),
                ts,
                ver.as_ptr(),
            )
        };
        assert_eq!(rc, 1, "SSL_set_reality_client_hello_params failed");
        ssl
    } else {
        let mut ssl = Ssl::new(&client_ctx()).unwrap();
        ssl.set_hostname("spike.local").unwrap();
        if mode == "inlib" {
            // The patch's new FFI. boring-sys is the vendored, patched copy.
            unsafe {
                boring_sys::SSL_set_client_session_id_override(
                    ssl.as_ptr(),
                    marker.as_ptr(),
                    marker.len(),
                );
            }
        }
        ssl
    };

    let mut stream = SslStream::new(ssl, wrap).unwrap();
    let connect_result = stream.connect();
    let client_ok = connect_result.is_ok();
    if let Err(e) = &connect_result {
        eprintln!("[client] connect failed: {e}");
    }

    // App data round-trip BEFORE waiting on the server report — the server
    // only reports after the round-trip, so doing it the other way around
    // deadlocks.
    let mut app_data_ok = false;
    if client_ok {
        assert_eq!(
            stream.ssl().version2(),
            Some(SslVersion::TLS1_3),
            "expected TLS 1.3"
        );
        stream.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        app_data_ok = &buf == b"pong";
        println!("tls version     : TLS1.3, app-data round-trip: {app_data_ok}");
    }

    let outcome = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("server thread did not report");

    // Report
    let wire = outcome.wire_session_id.clone().unwrap_or_default();
    let wire_hex: String = wire.iter().map(|b| format!("{b:02x}")).collect();
    println!("mode            : {mode}");
    println!("wire session_id : {wire_hex}");
    println!("== marker?      : {}", wire.as_slice() == marker.as_slice());
    println!("client handshake: {client_ok}");
    println!("server handshake: {}", outcome.handshake_ok);
    if let Some(e) = &outcome.error {
        println!("server error    : {e}");
    }
    if mode == "authkey" || mode == "reality-handshake" {
        let client_ak = authkey_slot.lock().unwrap().clone();
        match (client_ak, outcome.authkey_server.clone()) {
            (Some(c), Some(s)) => {
                println!("authkey client  : {}", c.iter().map(|b| format!("{b:02x}")).collect::<String>());
                println!("authkey server  : {}", s.iter().map(|b| format!("{b:02x}")).collect::<String>());
                let equal = c == s;
                println!("authkeys equal? : {equal}");
            }
            _ => println!("authkey         : derivation failed on some side"),
        }
    }

    match mode.as_str() {
        "inlib" => {
            assert!(wire.as_slice() == marker.as_slice(), "inlib: wire session_id != marker");
            assert!(client_ok && outcome.handshake_ok, "inlib: handshake must complete");
            assert!(app_data_ok, "inlib: app data must round-trip");
            println!("RESULT: PASS (override on wire, TLS 1.3 handshake verifiable end-to-end)");
        }
        "inlib-noop" => {
            assert!(
                wire.as_slice() != marker.as_slice(),
                "inlib-noop: session_id unexpectedly == marker"
            );
            assert!(
                client_ok && outcome.handshake_ok && app_data_ok,
                "inlib-noop: baseline handshake broken"
            );
            println!("RESULT: PASS (control: random session_id, handshake fine)");
        }
        "posthoc" => {
            assert!(
                !client_ok || !outcome.handshake_ok,
                "posthoc: handshake unexpectedly completed — post-transcript rewrite must fail"
            );
            println!("RESULT: PASS (control: post-transcript rewrite breaks the handshake)");
        }
        "authkey" => {
            let client_ak = authkey_slot.lock().unwrap().clone();
            assert!(
                client_ok && outcome.handshake_ok && app_data_ok,
                "authkey: handshake must complete"
            );
            assert!(
                client_ak.is_some() && outcome.authkey_server.is_some(),
                "authkey: derivation failed on some side"
            );
            assert_eq!(
                client_ak.unwrap(),
                outcome.authkey_server.unwrap(),
                "authkey: client/server AuthKey mismatch"
            );
            println!("RESULT: PASS (REALITY AuthKey derived identically from the live key share)");
        }
        "reality-handshake" => {
            let client_ak = authkey_slot.lock().unwrap().clone();
            // The in-lib derivation must have produced a session_id the
            // server could open; server error would have been reported otherwise.
            assert!(
                outcome.error.is_none(),
                "reality-handshake: server rejected the ClientHello: {:?}",
                outcome.error
            );
            let sid = outcome.wire_session_id.clone().unwrap_or_default();
            assert_eq!(sid.len(), 32, "reality-handshake: no 32-byte wire session_id");
            assert_ne!(
                sid.as_slice(),
                marker.as_slice(),
                "reality-handshake: session_id unexpectedly the fixed marker"
            );
            assert!(
                client_ok && outcome.handshake_ok && app_data_ok,
                "reality-handshake: handshake must complete (client_ok={client_ok}, server_ok={})",
                outcome.handshake_ok
            );
            assert!(
                client_ak.is_some() && outcome.authkey_server.is_some(),
                "reality-handshake: AuthKey derivation failed on some side"
            );
            assert_eq!(
                client_ak.unwrap(),
                outcome.authkey_server.unwrap(),
                "reality-handshake: client/server AuthKey mismatch"
            );
            println!(
                "RESULT: PASS (in-lib REALITY session_id derived, opened by the server, \
                 certificate HMAC verified, TLS 1.3 + app data round-trip)"
            );
        }
        other => {
            eprintln!("unknown mode: {other}");
            exit(2);
        }
    }
}
