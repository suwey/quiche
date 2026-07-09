use boring::ssl::Ssl;
use boring::ssl::SslContextBuilder;
use boring::ssl::SslMethod;
use boring::ssl::SslSignatureAlgorithm;
use boring::ssl::SslStream;
use boring::ssl::SslVerifyMode;
use std::io;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;

/// Default error message returned by [`OutboundClient::dial_udp`] when
/// the outbound does not support UDP at all.
pub const ERR_UDP_NOT_SUPPORTED: &str = "UDP not supported by this outbound";

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
            std::time::Duration::from_secs(5);

        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let fwmark = BYPASS_FWMARK;

        tokio::task::spawn_blocking(move || {
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_mark(fwmark)?;
            // Disable Nagle for low-latency protocols (DoH, proxy handshakes).
            socket.set_nodelay(true)?;
            socket.connect_timeout(&addr.into(), TCP_CONNECT_TIMEOUT)?;
            let std_stream: std::net::TcpStream = socket.into();
            TcpStream::from_std(std_stream)
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    }
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        use crate::inbound::tun::platform::android::get_protector;

        // IMPORTANT: VpnService.protect() MUST be called BEFORE connect(),
        // otherwise the SYN packet is already routed into the TUN.
        // tokio::TcpStream::connect() creates the socket and connects in
        // one step, leaving no window to protect the fd.  We must manually
        // create the socket, protect it, then connect.
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };

        let protector = get_protector();

        tokio::task::spawn_blocking(move || {
            let socket = socket2::Socket::new(
                domain,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            let fd = socket.as_raw_fd();
            let protected = protector.protect(fd);
            if !protected {
                log::warn!("VpnService.protect() failed for TCP fd={fd} addr={addr}");
            } else {
                log::debug!("protect(fd={fd}) ok, connecting to {addr}");
            }
            socket.set_nodelay(true)?;
            socket.set_nonblocking(true)?;

            // Non-blocking connect returns EINPROGRESS immediately.
            // We need to poll for writability, then check SO_ERROR.
            match socket.connect(&addr.into()) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {
                    // Wait for the socket to become writable (connect completes).
                    // Use poll() with a timeout.
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd, 1, 10_000) };
                    if ret < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if ret == 0 {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "connect poll timeout"));
                    }
                    // Check SO_ERROR to see if connect succeeded.
                    let mut err: i32 = 0;
                    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
                    let ret = unsafe {
                        libc::getsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_ERROR,
                            &mut err as *mut _ as *mut _,
                            &mut len,
                        )
                    };
                    if ret < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if err != 0 {
                        return Err(io::Error::from_raw_os_error(err));
                    }
                }
                Err(e) => return Err(e),
            }

            let std_stream: std::net::TcpStream = socket.into();
            Ok(TcpStream::from_std(std_stream))
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
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
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        use crate::inbound::tun::platform::android::get_protector;

        let socket = UdpSocket::bind(bind_addr).await?;
        let protector = get_protector();
        let fd = socket.as_raw_fd();
        if !protector.protect(fd) {
            log::warn!("VpnService.protect() failed for UDP fd={}", fd);
        }
        Ok(socket)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
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
        socket.set_nodelay(true)?;
        socket.connect(&addr.into())?;
        Ok(socket.into())
    }
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        use crate::inbound::tun::platform::android::get_protector;

        // protect() MUST be called BEFORE connect().
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(
            domain,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        let fd = socket.as_raw_fd();
        let protector = get_protector();
        if !protector.protect(fd) {
            log::warn!("VpnService.protect() failed for sync TCP fd={fd}");
        }
        socket.set_nodelay(true)?;
        socket.connect(&addr.into())?;
        Ok(socket.into())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
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
