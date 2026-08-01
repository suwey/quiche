//! H2 client: TLS + HTTP/2 connection management.
//!
//! Creates a pooled H2 connection to a target server using:
//! 1. `connect_tcp_bypass` (SO_MARK / VpnService.protect) for TUN bypass
//! 2. `tokio-rustls` with ALPN "h2" for TLS
//! 3. `hyper::client::conn::http2::handshake` for H2
//!
//! The returned `SendRequest` handle is `Clone` — clones share a single
//! underlying TCP+TLS+H2 connection and multiplex as independent streams.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use super::config::HttpVersionPref;
use http_body::{Body, Frame};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::mpsc;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A request body backed by a tokio mpsc channel.
///
/// The caller holds the `Sender` and writes data frames; hyper reads
/// from the `Receiver` side via `Body::poll_frame`. Dropping the
/// `Sender` signals end-of-body to the H2 layer.
pub struct ChannelBody {
    rx: mpsc::Receiver<Result<Frame<Bytes>, io::Error>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        // ChannelBody is Unpin (mpsc::Receiver is Unpin)
        let this = self.get_mut();
        this.rx.poll_recv(cx)
    }
}

/// The streaming request body type used by all XHTTP requests.
pub type ReqBody = ChannelBody;

/// H2 send-request handle - cloned per-stream from a shared connection.
pub type H2SendRequest = http2::SendRequest<ReqBody>;

// ---------------------------------------------------------------------------
// TLS configuration
// ---------------------------------------------------------------------------

/// Build a rustls `ClientConfig` with the given ALPN protocols.
fn build_tls_config(insecure: bool, alpn: Vec<Vec<u8>>) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = if insecure {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    config.alpn_protocols = alpn;
    Arc::new(config)
}

/// A `ServerCertVerifier` that accepts any certificate (insecure mode).
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ---------------------------------------------------------------------------
// H2Client
// ---------------------------------------------------------------------------

pub async fn connect(
    addr: std::net::SocketAddr,
    host: &str,
    insecure: bool,
    http_version: HttpVersionPref,
) -> io::Result<H2SendRequest> {
    // 1. TCP connect (bypasses TUN via SO_MARK / VpnService.protect)
    let tcp = crate::outbound::common::connect_tcp_bypass(addr).await?;
    let _ = tcp.set_nodelay(true);

    // 2. Determine ALPN based on http_version
    // Auto/Http3 resolve to H2. H1 uses http/1.1 ALPN.
    let (alpn, expect_h2) = match http_version {
        HttpVersionPref::Http1 => (vec![b"http/1.1".to_vec()], false),
        _ => (vec![b"h2".to_vec()], true),
    };

    // 3. TLS handshake with ALPN
    let tls_config = build_tls_config(insecure, alpn);
    let connector = TlsConnector::from(tls_config);
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

    // Verify ALPN negotiation
    let (_, session) = tls.get_ref();
    let negotiated = session.alpn_protocol();
    if expect_h2 && !matches!(negotiated, Some(b"h2")) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "server did not negotiate h2 via ALPN",
        ));
    }
    if !expect_h2 && !matches!(negotiated, Some(b"http/1.1")) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "server did not negotiate http/1.1 via ALPN",
        ));
    }

    if !expect_h2 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HTTP/1.1 not yet implemented (use http_version = \"auto\" or \"http2\")",
        ));
    }

    // 3. H2 handshake
    let io = TokioIo::new(tls);
    let exec = TokioExecutor::new();
    let (send_req, conn) = http2::handshake(exec, io)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

    // Drive the connection in background
    let host_owned = host.to_string();
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            log::debug!("xhttp: H2 connection to {host_owned} closed: {e}");
        }
    });

    Ok(send_req)
}

/// Create a streaming request body backed by a tokio mpsc channel.
///
/// Returns `(sender, body)` where:
/// - `sender`: write data frames to this; drop it to signal end-of-body
/// - `body`: pass to `Request::builder().body(body)`
pub fn make_stream_body(
    buffer: usize,
) -> (
    mpsc::Sender<Result<Frame<Bytes>, io::Error>>,
    ReqBody,
) {
    let (tx, rx) = mpsc::channel(buffer);
    (tx, ChannelBody { rx })
}

/// Create an empty body (for GET requests in stream-up mode, M6).
pub fn empty_body() -> ReqBody {
    let (_tx, body) = make_stream_body(1);
    // Drop tx immediately -> empty stream -> end-of-body
    body
}
