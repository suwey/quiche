use boring::ssl::Ssl;
use boring::ssl::SslContextBuilder;
use boring::ssl::SslMethod;
use boring::ssl::SslSignatureAlgorithm;
use boring::ssl::SslStream;
use boring::ssl::SslVerifyMode;
use std::io;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Bypass helpers — SO_MARK on Linux so outbound sockets avoid the TUN route
// ---------------------------------------------------------------------------

/// Connect a TCP socket, applying SO_MARK on Linux so it bypasses TUN routing.
/// The address MUST be a resolved `SocketAddr` (IP:port), not a domain.

pub async fn connect_tcp_bypass(
    addr: std::net::SocketAddr,
) -> io::Result<TcpStream> {
    #[cfg(target_os = "linux")]
    {
        use crate::inbound::tun::BYPASS_FWMARK;
        use socket2::Domain;
        use socket2::Protocol;
        use socket2::Socket;
        use socket2::Type;

        const TCP_CONNECT_TIMEOUT: std::time::Duration =
            std::time::Duration::from_secs(3);

        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let fwmark = BYPASS_FWMARK;

        tokio::task::spawn_blocking(move || {
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_mark(fwmark)?;
            socket.connect_timeout(&addr.into(), TCP_CONNECT_TIMEOUT)?;
            let std_stream: std::net::TcpStream = socket.into();
            TcpStream::from_std(std_stream)
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    }
    #[cfg(not(target_os = "linux"))]
    {
        TcpStream::connect(addr).await
    }
}

/// Bind a UDP socket, applying SO_MARK on Linux so it bypasses TUN routing.
pub async fn bind_udp_bypass(
    bind_addr: std::net::SocketAddr,
) -> io::Result<UdpSocket> {
    #[cfg(target_os = "linux")]
    {
        use crate::inbound::tun::BYPASS_FWMARK;
        use socket2::Domain;
        use socket2::Protocol;
        use socket2::Socket;
        use socket2::Type;

        let domain = if bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let fwmark = BYPASS_FWMARK;

        tokio::task::spawn_blocking(move || {
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_reuse_address(true)?;
            socket.set_mark(fwmark)?;
            socket.bind(&bind_addr.into())?;
            let std_socket: std::net::UdpSocket = socket.into();
            std_socket.set_nonblocking(true)?;
            UdpSocket::from_std(std_socket)
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    }
    #[cfg(not(target_os = "linux"))]
    {
        UdpSocket::bind(bind_addr).await
    }
}

/// Synchronous connect — for use inside `spawn_blocking`.
/// On Linux, applies SO_MARK before connect so the socket bypasses TUN routing.
/// The address MUST be a resolved `SocketAddr` (IP:port), not a domain.
pub fn connect_tcp_bypass_sync(
    addr: std::net::SocketAddr,
) -> io::Result<std::net::TcpStream> {
    #[cfg(target_os = "linux")]
    {
        use crate::inbound::tun::BYPASS_FWMARK;
        use socket2::Domain;
        use socket2::Protocol;
        use socket2::Socket;
        use socket2::Type;

        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_mark(BYPASS_FWMARK)?;
        socket.connect(&addr.into())?;
        Ok(socket.into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::net::TcpStream::connect(addr)
    }
}

// ---------------------------------------------------------------------------
// Brotli certificate decompressor (Chrome fingerprint — adds TLS extension 27)

/// Apply Chrome-like TLS fingerprint settings to an [`SslContextBuilder`].
///
/// Configures curves, signature algorithms, and verify algorithm prefs
/// to mimic Chrome's ClientHello.
pub fn apply_fingerprint_to_ctx(builder: &mut SslContextBuilder) {
    builder
        .set_curves_list("X25519MLKEM768:X25519:P-256:P-384")
        .expect("failed to set curves");
    builder
        .set_sigalgs_list(
            "ecdsa_secp256r1_sha256:\
             rsa_pss_rsae_sha256:\
             rsa_pkcs1_sha256:\
             ecdsa_secp384r1_sha384:\
             rsa_pss_rsae_sha384:\
             rsa_pkcs1_sha384:\
             rsa_pss_rsae_sha512:\
             rsa_pkcs1_sha512",
        )
        .expect("failed to set sigalgs");
    builder
        .set_verify_algorithm_prefs(&[
            SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
            SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
            SslSignatureAlgorithm::RSA_PKCS1_SHA256,
            SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
            SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
            SslSignatureAlgorithm::RSA_PKCS1_SHA384,
            SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
            SslSignatureAlgorithm::RSA_PKCS1_SHA512,
            SslSignatureAlgorithm::RSA_PKCS1_SHA1,
        ])
        .expect("failed to set verify algorithm prefs");
    // Certificate compression is intentionally omitted here — the current
    // BrotliCertDecompressor stub advertises brotli support but can't actually
    // decompress, causing CERT_DECOMPRESSION_FAILED with Cloudflare servers.
    // Omission slightly changes the JA3 fingerprint, but beats hard failures.
}

/// Extract SNI from config, defaulting to the hostname portion of `server`.
/// Returns an error if `server` is an IP address and `sni` was not explicitly
/// configured. Shared by anytls, vless, and any future outbound needing TLS
/// SNI.
pub fn resolve_sni(
    cfg: &crate::config::OutboundConfig,
) -> Result<String, String> {
    let server = cfg.server.as_deref().ok_or("missing server field")?;
    let host = server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server);
    match &cfg.sni {
        Some(s) => Ok(s.clone()),
        None =>
            if host.parse::<std::net::IpAddr>().is_ok() {
                Err(format!(
                    "server '{server}' is an IP but sni is not configured"
                ))
            } else {
                Ok(host.to_string())
            },
    }
}

/// Build a TLS connection: SSL context → fingerprint → verify → SNI →
/// connect. Shared by anytls, vless, and any future outbound that needs TLS.
pub fn create_tls_stream(
    tcp: std::net::TcpStream, sni: &str, fp: bool, insecure: bool,
) -> io::Result<SslStream<std::net::TcpStream>> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if fp {
        apply_fingerprint_to_ctx(&mut builder);
    }
    if insecure {
        builder.set_verify(SslVerifyMode::NONE);
    }
    let ctx = builder.build();
    let mut ssl =
        Ssl::new(&ctx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if !sni.is_empty() {
        ssl.set_hostname(sni)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }
    let mut stream = SslStream::new(ssl, tcp)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    stream
        .connect()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(stream)
}

/// Resolve a `server` string (IP:port or domain:port) to a `SocketAddr`.
///
/// For domains, retries DNS resolution up to 5 times with 500ms gaps.
/// This is called at registration time (before TUN comes up) to avoid
/// loopback DNS queries through the proxy later. Both anytls and vless
/// use this.
pub fn resolve_addr(server: &str) -> Result<std::net::SocketAddr, String> {
    // Try IP:port first — no DNS needed.
    if let Ok(addr) = server.parse() {
        return Ok(addr);
    }

    // Domain:port — retry DNS before TUN is up.
    let mut last_err = String::new();
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        match std::net::ToSocketAddrs::to_socket_addrs(server) {
            Ok(mut addrs) =>
                if let Some(addr) = addrs.next() {
                    return Ok(addr);
                },
            Err(e) => last_err = format!("{e}"),
        }
    }
    Err(format!(
        "failed to resolve server '{server}' after 5 attempts: {last_err}"
    ))
}
