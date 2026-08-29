use boring::ssl::Ssl;
use boring::ssl::SslContextBuilder;
use boring::ssl::SslMethod;
use boring::ssl::SslSignatureAlgorithm;
use boring::ssl::SslStream;
use boring::ssl::SslVerifyMode;
use std::io;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;

use crate::tlsfragment::{FragmentConfig, FragmentTcpStream};

/// Default error message returned by [`OutboundClient::dial_udp`] when
/// the outbound does not support UDP at all.
pub const ERR_UDP_NOT_SUPPORTED: &str = "UDP not supported by this outbound";

// ---------------------------------------------------------------------------
// Bypass helpers — SO_MARK on Linux, VpnService.protect on Android,
// IP_BOUND_IF on macOS, so outbound sockets avoid the TUN route.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct MacosPhysicalIface {
    name: String,
    index: u32,
    ipv4: Option<std::net::Ipv4Addr>,
}

#[cfg(target_os = "macos")]
static MACOS_PHYSICAL_IFACE_CACHE: std::sync::OnceLock<
    std::sync::RwLock<Option<MacosPhysicalIface>>,
> = std::sync::OnceLock::new();

/// On macOS, load the current default physical interface (en0/en1/…) and
/// its IPv4 address. The cache is refreshed explicitly when the TUN route
/// watcher detects a wake or network change.
#[cfg(target_os = "macos")]
fn load_macos_physical_iface() -> Option<MacosPhysicalIface> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut iface = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            let name = rest.trim();
            if !name.is_empty() && !name.starts_with("utun") {
                iface = Some(name.to_string());
            }
            break;
        }
    }

    let name = iface?;
    let c_iface = std::ffi::CString::new(name.as_str()).ok()?;
    let index = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    if index == 0 {
        return None;
    }

    let output = std::process::Command::new("ifconfig")
        .arg(&name)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ipv4 = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(ip_str) = rest.split_whitespace().next() {
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    ipv4 = Some(ip);
                }
            }
            break;
        }
    }

    Some(MacosPhysicalIface { name, index, ipv4 })
}

/// Replace the cached macOS physical interface after a wake or network change.
#[cfg(target_os = "macos")]
pub fn refresh_macos_physical_iface_cache() {
    let cache = MACOS_PHYSICAL_IFACE_CACHE
        .get_or_init(|| std::sync::RwLock::new(load_macos_physical_iface()));
    if let Ok(mut cached) = cache.write() {
        *cached = load_macos_physical_iface();
    }
}

#[cfg(target_os = "macos")]
fn cached_macos_physical_iface() -> Option<MacosPhysicalIface> {
    let cache = MACOS_PHYSICAL_IFACE_CACHE
        .get_or_init(|| std::sync::RwLock::new(load_macos_physical_iface()));
    if let Ok(cached) = cache.read() {
        if cached.as_ref().is_some_and(|iface| iface.ipv4.is_some()) {
            return cached.clone();
        }
    }

    refresh_macos_physical_iface_cache();
    cache.read().ok().and_then(|cached| cached.clone())
}

/// Cached interface index for IP_BOUND_IF.
#[cfg(target_os = "macos")]
fn physical_iface_index() -> Option<u32> {
    cached_macos_physical_iface().map(|iface| iface.index)
}

/// On macOS, get the IPv4 address of the physical interface (e.g. en0).
/// Used as the bind source address for outbound sockets so traffic
/// bypasses TUN split routes.
#[cfg(target_os = "macos")]
fn physical_iface_ipv4() -> Option<std::net::Ipv4Addr> {
    cached_macos_physical_iface().and_then(|iface| iface.ipv4)
}

/// Cached index of the physical (default-route) interface on Windows.
///
/// Queries the IP forwarding table for the original 0.0.0.0/0 default route
/// (dwForwardMask == 0). The TUN's split routes (0.0.0.0/1, 128.0.0.0/1)
/// carry a /1 mask (0x80000000), so they are excluded - we get the physical
/// interface even after TUN routes are installed.
#[cfg(target_os = "windows")]
fn physical_iface_index() -> Option<u32> {
    use std::sync::LazyLock;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetIpForwardTable, MIB_IPFORWARDTABLE,
    };

    static CACHED: LazyLock<Option<u32>> = LazyLock::new(|| unsafe {
        let mut size: u32 = 0;
        GetIpForwardTable(std::ptr::null_mut(), &mut size, 0);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let table = buf.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;
        if GetIpForwardTable(table, &mut size, 0) != 0 {
            return None;
        }
        let table = &*table;
        let entries = std::slice::from_raw_parts(
            table.table.as_ptr(),
            table.dwNumEntries as usize,
        );
        entries
            .iter()
            .find(|e| e.dwForwardDest == 0 && e.dwForwardMask == 0)
            .map(|e| e.dwForwardIfIndex)
    });
    *CACHED
}

/// On Windows, set IP_UNICAST_IF (IPv4) / IPV6_UNICAST_IF (IPv6) on a raw
/// socket so its traffic egresses via the physical interface, bypassing the
/// TUN split routes. Best-effort: logs on failure, never returns an error.
#[cfg(target_os = "windows")]
fn set_unicast_if_raw(raw: libc::SOCKET, ipv4: bool) {
    let Some(idx) = physical_iface_index() else {
        return;
    };
    let idx = idx as u32;
    // IP_UNICAST_IF / IPV6_UNICAST_IF expect the interface index in NETWORK
    // byte order (per MSDN). Passing host order on little-endian Windows
    // makes the kernel read a garbled index and fail with WSAEINVAL.
    let idx_be: u32 = idx.to_be();
    let ret = unsafe {
        if ipv4 {
            const IPPROTO_IP: libc::c_int = 0;
            const IP_UNICAST_IF: libc::c_int = 31;
            libc::setsockopt(
                raw,
                IPPROTO_IP,
                IP_UNICAST_IF,
                &idx_be as *const _ as *const libc::c_char,
                std::mem::size_of::<u32>() as libc::c_int,
            )
        } else {
            const IPPROTO_IPV6: libc::c_int = 41;
            const IPV6_UNICAST_IF: libc::c_int = 31;
            libc::setsockopt(
                raw,
                IPPROTO_IPV6,
                IPV6_UNICAST_IF,
                &idx_be as *const _ as *const libc::c_char,
                std::mem::size_of::<u32>() as libc::c_int,
            )
        }
    };
    if ret != 0 {
        log::warn!("Windows: IP_UNICAST_IF failed (idx={idx})");
    } else {
        log::debug!("Windows: IP_UNICAST_IF set ok (idx={idx})");
    }
}

/// On macOS, bind a socket to the physical interface using IP_BOUND_IF
/// so its traffic bypasses the TUN device.
///
/// Note: IP_BOUND_IF alone is NOT sufficient when TUN split routes
/// (0.0.0.0/1 + 128.0.0.0/1) are installed. The caller should also
/// bind() the socket to the physical interface's source IP address
/// before connect().
#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn bind_to_physical_iface(fd: std::os::fd::RawFd) -> io::Result<()> {
    let iface = cached_macos_physical_iface().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "no physical interface")
    })?;
    let idx = iface.index;
    // IP_BOUND_IF = 25 (IP level) on macOS. See <netinet/in.h>.
    const IP_BOUND_IF: libc::c_int = 25;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_BOUND_IF,
            &idx as *const _ as *const _,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    log::trace!("macOS: IP_BOUND_IF fd={fd} -> {} (idx={idx})", iface.name);
    Ok(())
}

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
            socket.set_tcp_nodelay(true)?;
            // Enable TCP keepalive to detect half-open connections.
            socket.set_keepalive(true)?;
            socket.set_tcp_keepalive(
                &socket2::TcpKeepalive::new()
                    .with_time(std::time::Duration::from_secs(60))
                    .with_interval(std::time::Duration::from_secs(15))
                    .with_retries(3),
            )?;
            socket.connect_timeout(&addr.into(), TCP_CONNECT_TIMEOUT)?;
            let std_stream: std::net::TcpStream = socket.into();
            TcpStream::from_std(std_stream)
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    }
    #[cfg(target_os = "android")]
    {
        use crate::inbound::tun::platform::android::get_protector;
        use std::os::fd::AsRawFd;

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
                log::warn!(
                    "VpnService.protect() failed for TCP fd={fd} addr={addr}"
                );
            } else {
                log::debug!("protect(fd={fd}) ok, connecting to {addr}");
            }
            socket.set_tcp_nodelay(true)?;
            // Enable TCP keepalive to detect half-open connections.
            socket.set_keepalive(true)?;
            socket.set_tcp_keepalive(
                &socket2::TcpKeepalive::new()
                    .with_time(std::time::Duration::from_secs(60))
                    .with_interval(std::time::Duration::from_secs(15))
                    .with_retries(3),
            )?;
            socket.set_nonblocking(true)?;

            // Non-blocking connect returns EINPROGRESS immediately.
            // We need to poll for writability, then check SO_ERROR.
            match socket.connect(&addr.into()) {
                Ok(()) => {},
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
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "connect poll timeout",
                        ));
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
                },
                Err(e) => return Err(e),
            }

            let std_stream: std::net::TcpStream = socket.into();
            Ok(TcpStream::from_std(std_stream))
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??
    }
    #[cfg(target_os = "macos")]
    {
        connect_tcp_bypass_macos(addr, true).await
    }
    #[cfg(target_os = "windows")]
    {
        use socket2::Domain;
        use socket2::Protocol;
        use socket2::Socket;
        use socket2::Type;
        use std::os::windows::io::AsRawSocket;

        // Windows: bind the socket to the physical interface via IP_UNICAST_IF
        // so outbound traffic bypasses the TUN split routes.
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_tcp_nodelay(true)?;
        socket.set_keepalive(true)?;
        socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(60))
                .with_interval(std::time::Duration::from_secs(15))
                .with_retries(3),
        )?;

        let ipv4 = addr.is_ipv4();
        set_unicast_if_raw(socket.as_raw_socket() as libc::SOCKET, ipv4);

        // Blocking connect on a cloned handle; the original retains the
        // IP_UNICAST_IF setting (duplicated sockets share the same state).
        let socket_clone = socket.try_clone()?;
        let connect_result = tokio::task::spawn_blocking(move || {
            socket_clone.connect(&addr.into())
        })
        .await;
        match connect_result {
            Ok(Ok(())) => {},
            Ok(Err(e)) => {
                log::warn!("Windows TCP bypass: connect to {addr} failed: {e}");
                return Err(e);
            },
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        }

        socket.set_nonblocking(true)?;
        let std_stream: std::net::TcpStream = socket.into();
        Ok(TcpStream::from_std(std_stream)?)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        let stream = TcpStream::connect(addr).await?;
        let sock_ref = socket2::SockRef::from(&stream);
        let _ = sock_ref.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(60))
                .with_interval(std::time::Duration::from_secs(15))
                .with_retries(3),
        );
        Ok(stream)
    }
}

#[cfg(target_os = "macos")]
async fn connect_tcp_bypass_macos(
    addr: std::net::SocketAddr, bind_interface: bool,
) -> io::Result<TcpStream> {
    use socket2::Domain;
    use socket2::Protocol;
    use socket2::Socket;
    use socket2::Type;
    use std::os::fd::AsRawFd;

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_tcp_nodelay(true)?;
    socket.set_keepalive(true)?;
    socket.set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(60))
            .with_interval(std::time::Duration::from_secs(15))
            .with_retries(3),
    )?;

    if addr.is_ipv4() {
        if let Some(src_ip) = physical_iface_ipv4() {
            socket.bind(&std::net::SocketAddr::from((src_ip, 0)).into())?;
        }
    }

    if bind_interface {
        let fd = socket.as_raw_fd();
        if let Some(idx) = physical_iface_index() {
            let ret = if addr.is_ipv4() {
                const IP_BOUND_IF: libc::c_int = 25;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        IP_BOUND_IF,
                        &idx as *const _ as *const _,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    )
                }
            } else {
                const IPV6_BOUND_IF: libc::c_int = 125;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IPV6,
                        IPV6_BOUND_IF,
                        &idx as *const _ as *const _,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    )
                }
            };
            if ret != 0 {
                log::warn!(
                    "macOS TCP bypass: IP_BOUND_IF failed: {}",
                    io::Error::last_os_error()
                );
            }
        }
    }

    let socket_clone = socket.try_clone()?;
    let connect_result =
        tokio::task::spawn_blocking(move || socket_clone.connect(&addr.into()))
            .await;
    match connect_result {
        Ok(Ok(())) => {},
        Ok(Err(e)) => {
            log::warn!("macOS TCP bypass: connect to {addr} failed: {e}");
            if e.kind() == io::ErrorKind::NetworkUnreachable {
                let destination = addr.ip();
                let _ = tokio::task::spawn_blocking(move || {
                    crate::inbound::tun::platform::macos::log_network_diagnostics(
                        destination,
                    )
                })
                .await;
            }
            return Err(e);
        },
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    }

    socket.set_nonblocking(true)?;
    let std_stream: std::net::TcpStream = socket.into();
    Ok(TcpStream::from_std(std_stream)?)
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
        use crate::inbound::tun::platform::android::get_protector;
        use std::os::fd::AsRawFd;

        let socket = UdpSocket::bind(bind_addr).await?;
        let protector = get_protector();
        let fd = socket.as_raw_fd();
        if !protector.protect(fd) {
            log::warn!("VpnService.protect() failed for UDP fd={}", fd);
        }
        Ok(socket)
    }
    #[cfg(target_os = "macos")]
    {
        bind_udp_bypass_macos(bind_addr, true).await
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        // Bind the UDP socket, then pin it to the physical interface so
        // responses route back via the physical NIC (bypassing TUN).
        let ipv4 = bind_addr.is_ipv4();
        let socket = UdpSocket::bind(bind_addr).await?;
        set_unicast_if_raw(socket.as_raw_socket() as libc::SOCKET, ipv4);
        Ok(socket)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        UdpSocket::bind(bind_addr).await
    }
}

pub async fn bind_udp_bypass_fallback(
    bind_addr: std::net::SocketAddr,
) -> io::Result<UdpSocket> {
    #[cfg(target_os = "macos")]
    {
        bind_udp_bypass_macos(bind_addr, true).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        bind_udp_bypass(bind_addr).await
    }
}

#[cfg(target_os = "macos")]
async fn bind_udp_bypass_macos(
    bind_addr: std::net::SocketAddr, bind_interface: bool,
) -> io::Result<UdpSocket> {
    use std::os::fd::AsRawFd;

    let effective_bind = if bind_addr.ip().is_unspecified() {
        if let Some(src_ip) = physical_iface_ipv4() {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(src_ip),
                bind_addr.port(),
            )
        } else {
            bind_addr
        }
    } else {
        bind_addr
    };
    let socket = UdpSocket::bind(effective_bind).await?;

    if bind_interface {
        let fd = socket.as_raw_fd();
        if let Some(idx) = physical_iface_index() {
            const IP_BOUND_IF: libc::c_int = 25;
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    IP_BOUND_IF,
                    &idx as *const _ as *const _,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                log::warn!(
                    "macOS UDP bypass: IP_BOUND_IF failed: {}",
                    io::Error::last_os_error()
                );
            }
        }
    }
    Ok(socket)
}

// Synchronous connect — for use inside `spawn_blocking`.
// Bound the blocking connect so a stuck dial (e.g. unreachable proxy server)
// can't wedge the tokio blocking pool — and therefore Ctrl+C shutdown — for
// the OS-level connect timeout (which can be many seconds to minutes).
const SYNC_CONNECT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);
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
        socket.set_tcp_nodelay(true)?;
        socket.set_keepalive(true)?;
        socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(60))
                .with_interval(std::time::Duration::from_secs(15))
                .with_retries(3),
        )?;
        socket.connect_timeout(&addr.into(), SYNC_CONNECT_TIMEOUT)?;
        Ok(socket.into())
    }
    #[cfg(target_os = "android")]
    {
        use crate::inbound::tun::platform::android::get_protector;
        use std::os::fd::AsRawFd;

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
        socket.set_keepalive(true)?;
        socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(60))
                .with_interval(std::time::Duration::from_secs(15))
                .with_retries(3),
        )?;
        socket.connect_timeout(&addr.into(), SYNC_CONNECT_TIMEOUT)?;
        Ok(socket.into())
    }
    #[cfg(target_os = "macos")]
    {
        use socket2::Domain;
        use socket2::Protocol;
        use socket2::Socket;
        use socket2::Type;
        use std::os::fd::AsRawFd;

        // Same as async: IP_BOUND_IF to physical interface.
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_tcp_nodelay(true)?;
        socket.set_keepalive(true)?;
        socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(60))
                .with_interval(std::time::Duration::from_secs(15))
                .with_retries(3),
        )?;

        let fd = socket.as_raw_fd();
        if let Some(idx) = physical_iface_index() {
            if addr.is_ipv4() {
                const IP_BOUND_IF: libc::c_int = 25;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        IP_BOUND_IF,
                        &idx as *const _ as *const _,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    )
                };
            } else {
                const IPV6_BOUND_IF: libc::c_int = 125;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IPV6,
                        IPV6_BOUND_IF,
                        &idx as *const _ as *const _,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    )
                };
            }
        }

        socket.connect_timeout(&addr.into(), SYNC_CONNECT_TIMEOUT)?;
        Ok(socket.into())
    }
    #[cfg(target_os = "windows")]
    {
        use socket2::Domain;
        use socket2::Protocol;
        use socket2::Socket;
        use socket2::Type;
        use std::os::windows::io::AsRawSocket;

        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_tcp_nodelay(true)?;
        socket.set_keepalive(true)?;
        socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(60))
                .with_interval(std::time::Duration::from_secs(15))
                .with_retries(3),
        )?;

        set_unicast_if_raw(
            socket.as_raw_socket() as libc::SOCKET,
            addr.is_ipv4(),
        );

        socket.connect_timeout(&addr.into(), SYNC_CONNECT_TIMEOUT)?;
        Ok(socket.into())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        let stream =
            std::net::TcpStream::connect_timeout(addr, SYNC_CONNECT_TIMEOUT)?;
        let sock_ref = socket2::SockRef::from(&stream);
        let _ = sock_ref.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(60))
                .with_interval(std::time::Duration::from_secs(15))
                .with_retries(3),
        );
        Ok(stream)
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
        None => {
            if host.parse::<std::net::IpAddr>().is_ok() {
                Err(format!(
                    "server '{server}' is an IP but sni is not configured"
                ))
            } else {
                Ok(host.to_string())
            }
        },
    }
}

/// The unified TLS stream type returned by [`create_tls_stream`].
///
/// When TLS fragment is enabled, the underlying TCP stream is wrapped in
/// [`FragmentTcpStream`] which splits the first ClientHello write across
/// multiple TCP segments.  When disabled, the wrapper still exists but
/// passes all writes through unchanged.
pub type TlsStream = SslStream<FragmentTcpStream<std::net::TcpStream>>;

/// Build a TLS connection: SSL context → fingerprint → verify → SNI →
/// connect. Shared by anytls, vless, and any future outbound that needs TLS.
///
/// If `fragment` is Some, the underlying TCP stream is wrapped with
/// `FragmentTcpStream` before TLS handshake, causing the ClientHello to be
/// split across multiple TCP segments to evade DPI SNI matching.
pub fn create_tls_stream(
    tcp: std::net::TcpStream, sni: &str, fp: bool, insecure: bool,
    fragment: Option<&FragmentConfig>,
) -> io::Result<TlsStream> {
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
    // Always wrap with FragmentTcpStream.  When fragment is None,
    // fragment_enabled is false and all writes pass through unchanged.
    #[cfg(unix)]
    let frag_stream = FragmentTcpStream::new(tcp, fragment.cloned());
    #[cfg(not(unix))]
    let frag_stream = FragmentTcpStream::new_no_ack(tcp, fragment.cloned());
    let mut stream = SslStream::new(ssl, frag_stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    stream
        .connect()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(stream)
}

/// The async TLS stream type returned by [`create_tls_stream_async`].
///
/// Uses `tokio_boring::SslStream` wrapped around `AsyncFragmentStream`
/// for TLS fragment support, implementing `AsyncRead + AsyncWrite`.
pub type AsyncTlsStream = tokio_boring::SslStream<
    crate::obfuscation::fragment::AsyncFragmentStream<tokio::net::TcpStream>,
>;

/// Build an async TLS connection using `tokio_boring`.
///
/// This mirrors [`create_tls_stream`] but returns a `tokio_boring::SslStream`
/// that implements `tokio::io::AsyncRead + AsyncWrite`, enabling fully async
/// WebSocket I/O. TLS fragment splitting is supported via `AsyncFragmentStream`.
pub async fn create_tls_stream_async(
    tcp: tokio::net::TcpStream, sni: &str, fp: bool, insecure: bool,
    fragment: Option<&FragmentConfig>,
) -> io::Result<AsyncTlsStream> {
    use crate::obfuscation::fragment::AsyncFragmentStream;
    use boring::ssl::SslConnector;
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if fp {
        apply_fingerprint_to_ctx(&mut builder);
    }
    if insecure {
        builder.set_verify(SslVerifyMode::NONE);
    }
    let connector = builder.build();
    let config = connector
        .configure()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let frag_stream = AsyncFragmentStream::new(tcp, fragment);
    tokio_boring::connect(config, sni, frag_stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
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
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    return Ok(addr);
                }
            },
            Err(e) => last_err = format!("{e}"),
        }
    }
    Err(format!(
        "failed to resolve server '{server}' after 5 attempts: {last_err}"
    ))
}
