// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! TLS session resumption cache (BoringSSL, client side).
//!
//! Every client TLS dial used to build a fresh `SslConnector`/`SslContext`
//! (`create_tls_stream` / `create_tls_stream_async`), so the session each
//! server hands out — Cloudflare's edge sends session tickets right after
//! the handshake — was dropped immediately. Every mless pool build and slot
//! reconnect therefore paid a full handshake: cert chain download + verify
//! plus the post-quantum keyshare flight, the bulk of the observed 2–3 s on
//! high-RTT paths.
//!
//! This module keeps a small per-endpoint ring of `SslSession`s. Each dial
//! first offers the newest cached ticket via `SSL_set_session` (PSK
//! resumption; tickets are self-contained, so this works across the per-dial
//! `SSL_CTX`s), then replenishes the ring with its own negotiated session.
//! A resumed handshake sends no certificate chain and no MLKEM keyshare —
//! the ClientHello shrinks from ~1.8 KB to a few hundred bytes, which also
//! reduces the number of fragmented ClientHello segments.
//!
//! TLS 1.3 tickets arrive as post-handshake messages and are processed while
//! reading. Callers that read right after the handshake (the WS upgrade's
//! 101 response) re-capture via [`store`] at that point — for Cloudflare
//! that capture is the one that matters. [`is_resumable`] gates every store,
//! so a ticket-less TLS 1.3 handshake session never poisons the ring.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use boring::ssl::SslRef;
use boring::ssl::SslSession;
use boring::ssl::SslSessionRef;
use foreign_types::ForeignTypeRef;

/// Sessions kept per endpoint key. TLS 1.3 tickets are single-use on many
/// servers (Cloudflare rotates them per connection), so parallel pool dials
/// each need their own; a successful handshake always replenishes the ring.
const MAX_SESSIONS_PER_KEY: usize = 4;

/// Endpoint key → session ring. `SslSession` is `Send + Sync` (immutable
/// after creation, ref-counted), so sharing behind a mutex is sound.
static SESSIONS: LazyLock<Mutex<HashMap<String, Vec<Arc<SslSession>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Cache key for a client dial: same SNI + fingerprint + verify mode share
/// tickets (one server's tickets are useless to another endpoint, and the
/// fingerprint/verify shaping must stay per-config).
pub(crate) fn cache_key(sni: &str, fp: bool, insecure: bool) -> String {
    format!("{sni}|{fp}|{insecure}")
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether the session can actually resume: has a usable ticket/ID, and is
/// not past its server-issued lifetime. `SSL_SESSION_is_resumable` is not
/// surfaced by the `boring` crate, so call the FFI directly (same pattern
/// as `fingerprint.rs`).
fn is_resumable(session: &SslSessionRef, now: u64) -> bool {
    let resumable =
        unsafe { boring_sys::SSL_SESSION_is_resumable(session.as_ptr()) };
    if resumable == 0 {
        return false;
    }
    // Belt and braces: BoringSSL's check covers expiry, but the accessors
    // are cheap and keep the ring clean of near-expired tickets.
    session.time() + u64::from(session.timeout()) > now
}

/// Offer the newest cached session for resumption before the handshake.
///
/// Pop semantics: the session is removed from the ring, so concurrent dials
/// never `SSL_set_session` the same instance — each successful handshake
/// stores its own fresh ticket right back.
pub(crate) fn try_resume(ssl: &mut SslRef, key: &str) {
    let Some(session) = pop(key) else {
        return;
    };
    // SAFETY: BoringSSL's SSL_set_session does not take ownership and the
    // session is immutable after creation; it up-refs internally. `pop`
    // removed the instance from the cache, so no other dial can pass the
    // same `SslSession` concurrently.
    if unsafe { ssl.set_session(&session) }.is_err() {
        log::debug!("tlsresume: set_session rejected for {key}");
    }
}

/// Pop the newest still-resumable session for `key`, dropping expired ones.
fn pop(key: &str) -> Option<Arc<SslSession>> {
    let now = now_epoch();
    let mut sessions = SESSIONS.lock().ok()?;
    let ring = sessions.get_mut(key)?;
    while let Some(session) = ring.pop() {
        if is_resumable(&session, now) {
            return Some(session);
        }
    }
    sessions.remove(key);
    None
}

/// Store the connection's negotiated session for the next dial. No-op for
/// sessions that cannot resume (e.g. a TLS 1.3 handshake session captured
/// before any ticket arrived).
pub(crate) fn store(key: &str, session: &SslSessionRef) {
    let now = now_epoch();
    if !is_resumable(session, now) {
        return;
    }
    let owned = Arc::new(session.to_owned());
    let Ok(mut sessions) = SESSIONS.lock() else {
        return;
    };
    let ring = sessions.entry(key.to_string()).or_default();
    ring.push(owned);
    if ring.len() > MAX_SESSIONS_PER_KEY {
        ring.remove(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::ssl::SslAcceptor;
    use boring::ssl::SslConnector;
    use boring::ssl::SslMethod;
    use boring::ssl::SslVerifyMode;
    use std::io::Read;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::OnceLock;

    /// The repo's loopback server certificate (CN=localhost, see
    /// config/mless-server.toml) — BoringSSL's acceptor ships no default
    /// certificate, and generating one per test would be pure overhead.
    fn server_cert() -> &'static boring::x509::X509 {
        static CERT: OnceLock<boring::x509::X509> = OnceLock::new();
        CERT.get_or_init(|| {
            boring::x509::X509::from_pem(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/config/cert.pem"
            )))
            .unwrap()
        })
    }

    fn server_key() -> &'static boring::pkey::PKey<boring::pkey::Private> {
        static KEY: OnceLock<boring::pkey::PKey<boring::pkey::Private>> =
            OnceLock::new();
        KEY.get_or_init(|| {
            boring::pkey::PKey::private_key_from_pem(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/config/key.pem"
            )))
            .unwrap()
        })
    }

    /// A real loopback handshake returning the client-side session. The
    /// post-handshake `ok` bytes are read before capturing, so — matching
    /// the production capture order — NewSessionTickets are already
    /// processed and the session is resumable regardless of the
    /// negotiated version.
    fn loopback_session() -> Arc<SslSession> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (cert, key) = (server_cert().clone(), server_key().clone());
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut builder =
                SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            builder.set_certificate(&cert).unwrap();
            builder.set_private_key(&key).unwrap();
            let mut tls = builder.build().accept(stream).unwrap();
            tls.write_all(b"ok").unwrap();
            tls.shutdown().unwrap();
        });

        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        // Self-signed loopback cert — skip verification (mirrors the
        // insecure=true mless configs).
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();
        let tcp = std::net::TcpStream::connect(addr).unwrap();
        let mut tls = connector.connect("localhost", tcp).unwrap();
        let session = tls.ssl().session().unwrap().to_owned();
        let mut buf = [0u8; 2];
        tls.read_exact(&mut buf).unwrap();
        handle.join().unwrap();
        Arc::new(session)
    }

    #[test]
    fn stores_and_pops_resumable_session() {
        let key = cache_key("resume-test.invalid", false, true);
        let session = loopback_session();
        assert!(
            is_resumable(&session, now_epoch()),
            "TLS 1.2 loopback session must be resumable"
        );

        store(&key, &session);
        let popped = pop(&key).expect("stored session must pop");
        assert!(pop(&key).is_none(), "ring must be empty after pop");
        assert_eq!(popped.id(), session.id());
        assert_eq!(popped.to_der().unwrap(), session.to_der().unwrap());
    }

    #[test]
    fn ring_is_bounded_and_fifo() {
        let key = cache_key("ring-test.invalid", false, true);
        for _ in 0..(MAX_SESSIONS_PER_KEY + 2) {
            let session = loopback_session();
            store(&key, &session);
        }
        let mut sessions = SESSIONS.lock().unwrap();
        let ring = sessions.get(&key).unwrap();
        assert_eq!(ring.len(), MAX_SESSIONS_PER_KEY);
        sessions.remove(&key);
    }

    #[test]
    fn session_past_its_lifetime_is_not_resumable() {
        let session = loopback_session();
        // Pretend "now" is far past time + timeout: the expiry gate must
        // reject the session so a stale ticket never reaches the handshake
        // (the server would just answer with a full handshake anyway, but
        // keeping the ring clean avoids eating one dial per stale entry).
        let now = session.time() + u64::from(session.timeout()) + 60;
        assert!(!is_resumable(&session, now));
    }

    /// The whole point: dial 1 pays the full handshake and stores its
    /// ticket; dial 2 offers it via `try_resume` and BoringSSL must report
    /// `SSL_session_reused` — one flight, no certificate, no keyshare.
    #[test]
    fn second_dial_resumes_from_cached_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (cert, key) = (server_cert().clone(), server_key().clone());
        let handle = std::thread::spawn(move || {
            // One acceptor for both connections: TLS 1.2 ticket encryption
            // keys live in the SSL_CTX, so a fresh acceptor per connection
            // could not decrypt dial 1's ticket and would answer full.
            let mut builder =
                SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            builder.set_certificate(&cert).unwrap();
            builder.set_private_key(&key).unwrap();
            let acceptor = builder.build();
            for i in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let mut tls = acceptor.accept(stream).unwrap();
                if i == 1 {
                    assert!(
                        tls.ssl().session_reused(),
                        "server side must see the resumed session"
                    );
                }
                tls.write_all(b"ok").unwrap();
                tls.shutdown().unwrap();
            }
        });

        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();
        let key = cache_key("localhost", false, true);

        let tcp = std::net::TcpStream::connect(addr).unwrap();
        let mut tls = connector.connect("localhost", tcp).unwrap();
        assert!(!tls.ssl().session_reused(), "dial 1 is a full handshake");
        // Read the post-handshake bytes BEFORE capturing: this is the same
        // ordering as build_ws_async's post-101 capture, and for TLS 1.3 it
        // is when NewSessionTicket records get processed.
        let mut buf = [0u8; 2];
        tls.read_exact(&mut buf).unwrap();
        let session = tls.ssl().session().unwrap().to_owned();
        store(&key, &session);
        tls.shutdown().unwrap();

        let tcp = std::net::TcpStream::connect(addr).unwrap();
        let mut config = connector.configure().unwrap();
        try_resume(&mut config, &key);
        let mut tls = config.connect("localhost", tcp).unwrap();
        assert!(
            tls.ssl().session_reused(),
            "dial 2 must resume from the cached ticket"
        );
        let mut buf = [0u8; 2];
        tls.read_exact(&mut buf).unwrap();
        handle.join().unwrap();
    }
}
