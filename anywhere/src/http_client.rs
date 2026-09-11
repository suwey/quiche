//! Simple HTTP/1.1 GET client using existing hyper + tokio-rustls deps.
//!
//! No reqwest - reuses the same primitives as `rules::geo::http_get_bypass`.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

/// Response from [`http_get_with_headers`].
///
/// `content_type` and `subscription_userinfo` are extracted from the response
/// headers. `subscription-userinfo` carries airport traffic/expiry info
/// (`upload=...; download=...; total=...; expire=...`).
///
/// `relay_signature` carries the OpenRung broker's
/// `X-OpenRung-Relays-Signature` header (`ed25519;<key_id>;<base64 sig>`,
/// detached signature over the exact body bytes) when present.
pub struct HttpResponse {
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub subscription_userinfo: Option<String>,
    pub relay_signature: Option<String>,
}

/// HTTP/1.1 GET request. Supports both `http://` (plain TCP) and `https://`
/// (TLS) URLs. Returns the raw response body on HTTP 2xx, or an error string
/// otherwise.
pub async fn http_get(url: &str, user_agent: &str) -> Result<Vec<u8>, String> {
    Ok(http_get_with_headers(url, user_agent).await?.body)
}

/// Like [`http_get`] but also returns selected response headers
/// (`content-type`, `subscription-userinfo`).
pub async fn http_get_with_headers(
    url: &str, user_agent: &str,
) -> Result<HttpResponse, String> {
    http_get_with_headers_inner(url, user_agent, None).await
}

/// Like [`http_get_with_headers`] but offers ECH on the TLS handshake using
/// `ech_config` (an ECHConfigList, outer u16 length included). The handshake
/// runs on the boring backend — the rustls connector used otherwise has no
/// ECH support. If the server rejects the offer the connection fails closed
/// (no plaintext-SNI fallback); callers treat that like any front failure.
pub async fn http_get_with_headers_ech(
    url: &str, user_agent: &str, ech_config: &[u8],
) -> Result<HttpResponse, String> {
    http_get_with_headers_inner(url, user_agent, Some(ech_config)).await
}

async fn http_get_with_headers_inner(
    url: &str, user_agent: &str, ech_config: Option<&[u8]>,
) -> Result<HttpResponse, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let query = parsed.query().map(|q| format!("?{q}")).unwrap_or_default();
    let path_query = format!("{path}{query}");

    // Resolve DNS via system resolver (subscription import happens before
    // the engine starts, so no fake-ip hijack concern).
    let addr_str = format!("{host}:{port}");
    let addr = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("no addresses for {host}"))?;

    // Build the HTTP/1.1 request (shared for both HTTP and HTTPS).
    // TCP connect happens per-branch: the ECH path redials on retry.
    let build_req = || {
        Request::builder()
            .method("GET")
            .uri(&path_query)
            .header("Host", host)
            .header("User-Agent", user_agent)
            .header("Connection", "close")
            .body(Empty::<Bytes>::new())
            .map_err(|e| format!("build request: {e}"))
    };

    match parsed.scheme() {
        "https" => {
            // ECH offer → boring backend (the only TLS client here with ECH
            // support). The offer encrypts the real SNI under the config's
            // neutral public_name; a server rejection fails closed (never a
            // plaintext fallback) and gets one automatic retry with the
            // server's fresh retry configs before giving up.
            if let Some(ech) = ech_config {
                return fetch_https_with_ech(&addr, host, &build_req, ech).await;
            }
            let tcp = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| format!("TCP connect {addr}: {e}"))?;
            let _ = tcp.set_nodelay(true);

            // TLS handshake with ALPN "http/1.1".
            let provider = tokio_rustls::rustls::crypto::ring::default_provider();
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut tls_config =
                ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .map_err(|e| format!("TLS config: {e}"))?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let connector = TlsConnector::from(Arc::new(tls_config));

            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| format!("invalid server name '{host}': {e}"))?;
            let tls = tokio::time::timeout(
                Duration::from_secs(15),
                connector.connect(server_name, tcp),
            )
            .await
            .map_err(|_| format!("TLS handshake timeout ({host})"))?
            .map_err(|e| format!("TLS handshake {host}: {e}"))?;

            let io = tls;
            do_hyper_get(io, build_req).await
        },
        "http" => {
            let tcp = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| format!("TCP connect {addr}: {e}"))?;
            let _ = tcp.set_nodelay(true);
            do_hyper_get(tcp, build_req).await
        },
        other => Err(format!("unsupported scheme: {other}")),
    }
}

/// ECH-specific dial failure: a rejection may carry the server's fresh
/// retry configs (authenticated via the public_name certificate check).
struct EchDialError {
    message: String,
    retry_configs: Option<Vec<u8>>,
}

fn plain_dial_error(message: String) -> EchDialError {
    EchDialError { message, retry_configs: None }
}

/// One TLS dial + handshake attempt with an ECH offer on the boring backend.
async fn ech_tls_dial(
    addr: &std::net::SocketAddr, host: &str, config_list: &[u8],
) -> Result<tokio_boring::SslStream<tokio::net::TcpStream>, EchDialError> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| plain_dial_error(format!("TCP connect {addr}: {e}")))?;
    let _ = tcp.set_nodelay(true);
    let mut builder = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())
        .map_err(|e| plain_dial_error(format!("TLS config: {e:?}")))?;
    builder
        .set_default_verify_paths()
        .map_err(|e| plain_dial_error(format!("TLS roots: {e:?}")))?;
    builder
        .set_alpn_protos(b"\x08http/1.1")
        .map_err(|e| plain_dial_error(format!("ALPN: {e:?}")))?;
    let connector = builder.build();
    let mut config = connector
        .configure()
        .map_err(|e| plain_dial_error(format!("TLS configure: {e:?}")))?;
    config
        .set_ech_config_list(config_list)
        .map_err(|e| plain_dial_error(format!("ECH offer: {e:?}")))?;
    let handshake = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_boring::connect(config, host, tcp),
    )
    .await
    .map_err(|_| plain_dial_error(format!("TLS handshake timeout ({host})")))?;
    match handshake {
        Ok(tls) => Ok(tls),
        Err(handshake_err) => {
            // ECH rejection surfaces as a mid-handshake failure carrying the
            // server's retry configs. The rejected handshake already
            // authenticated the edge against the config's public_name
            // (boring verifies the certificate before aborting), so those
            // configs are genuine and worth one retry.
            let retry_configs = handshake_err
                .ssl()
                .and_then(|ssl| ssl.get_ech_retry_configs())
                .map(|b| b.to_vec());
            Err(EchDialError {
                message: format!(
                    "TLS handshake {host}: ECH rejected{}",
                    if retry_configs.is_some() { " (fresh retry configs provided)" } else { "" },
                ),
                retry_configs,
            })
        },
    }
}

/// HTTPS GET with ECH: offer the config; on ECH rejection retry once with
/// the server's fresh retry configs. A successful retried handshake
/// promotes the fresh config for subsequent fetches.
async fn fetch_https_with_ech(
    addr: &std::net::SocketAddr, host: &str,
    build_req: &impl Fn() -> Result<Request<Empty<Bytes>>, String>,
    config_list: &[u8],
) -> Result<HttpResponse, String> {
    let mut current = config_list.to_vec();
    for attempt in 0..2 {
        match ech_tls_dial(addr, host, &current).await {
            Ok(tls) => {
                if !tls.ssl().ech_accepted() {
                    return Err(format!(
                        "ECH rejected by {host} (handshake fell back to outer \
                         parameters)"
                    ));
                }
                if attempt > 0 {
                    crate::ech::promote_cloudflare_config(&current);
                }
                return do_hyper_get(tls, build_req).await;
            },
            Err(EchDialError { message: _, retry_configs: Some(retry) })
            if attempt == 0 => {
                eprintln!(
                    "ECH: offer rejected, retrying with server's fresh retry \
                     configs ({} bytes)",
                    retry.len()
                );
                current = retry;
                continue;
            },
            Err(EchDialError { message, .. }) => return Err(message),
        }
    }
    Err(format!("ECH retry exhausted ({host})"))
}

async fn do_hyper_get<S>(
    io: S, build_req: impl FnOnce() -> Result<Request<Empty<Bytes>>, String>,
) -> Result<HttpResponse, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("hyper handshake: {e}"))?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = build_req()?;
    let resp =
        tokio::time::timeout(Duration::from_secs(30), sender.send_request(req))
            .await
            .map_err(|_| "HTTP response timeout".to_string())?
            .map_err(|e| format!("send request: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }

    // Capture headers before `into_body` consumes the response.
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let subscription_userinfo = resp
        .headers()
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // HeaderMap::get is case-insensitive, matching Go's relaySignatureHeaderValue.
    let relay_signature = resp
        .headers()
        .get("x-openrung-relays-signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read body: {e}"))?;
    Ok(HttpResponse {
        body: body.to_bytes().to_vec(),
        content_type,
        subscription_userinfo,
        relay_signature,
    })
}
