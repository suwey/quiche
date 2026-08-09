//! Simple HTTP/1.1 GET client using existing hyper + tokio-rustls deps.
//!
//! No reqwest - reuses the same primitives as `rules::geo::http_get_bypass`.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

/// Response from [`http_get_with_headers`].
///
/// `content_type` and `subscription_userinfo` are extracted from the response
/// headers. `subscription-userinfo` carries airport traffic/expiry info
/// (`upload=...; download=...; total=...; expire=...`).
pub struct HttpResponse {
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub subscription_userinfo: Option<String>,
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
    url: &str,
    user_agent: &str,
) -> Result<HttpResponse, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = if parsed.path().is_empty() { "/" } else { parsed.path() };
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

    // TCP connect
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("TCP connect {addr}: {e}"))?;
    let _ = tcp.set_nodelay(true);

    // Build the HTTP/1.1 request (shared for both HTTP and HTTPS).
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
            // TLS handshake with ALPN "http/1.1".
            let provider = tokio_rustls::rustls::crypto::ring::default_provider();
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut tls_config = ClientConfig::builder_with_provider(Arc::new(provider))
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
        }
        "http" => {
            do_hyper_get(tcp, build_req).await
        }
        other => Err(format!("unsupported scheme: {other}")),
    }
}

async fn do_hyper_get<S>(
    io: S,
    build_req: impl FnOnce() -> Result<Request<Empty<Bytes>>, String>,
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
    let resp = tokio::time::timeout(Duration::from_secs(30), sender.send_request(req))
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

    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read body: {e}"))?;
    Ok(HttpResponse {
        body: body.to_bytes().to_vec(),
        content_type,
        subscription_userinfo,
    })
}
