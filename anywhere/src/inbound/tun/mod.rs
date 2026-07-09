//! TUN inbound: transparent proxy via userspace NAT.
//!
//! Creates a TUN device, captures all traffic via a default route, and
//! proxies TCP/UDP through the anywhere outbound pipeline.

mod handler;
mod nat;
pub mod packet;
pub(crate) mod platform;
pub mod reverse_dns;

pub use handler::TunWriter;

#[cfg(target_os = "linux")]
pub use platform::linux::cleanup_stale_routing;

#[cfg(target_os = "android")]
pub use platform::android::create_tun_from_fd;

use std::collections::HashMap;
use std::net::IpAddr;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
#[cfg(target_os = "linux")]
pub use platform::linux::BYPASS_FWMARK;
#[cfg(target_os = "linux")]
pub use platform::linux::TunRouteManager;
#[cfg(target_os = "android")]
pub use platform::android::AndroidTunManager;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::config::InboundConfig;
use crate::dns::DnsHijack;
use crate::inbound::Address;
use crate::inbound::Destination;
use crate::inbound::Inbound;
use crate::inbound::InboundConn;
use crate::inbound::tun::nat::TCPNat;
use crate::inbound::tun::reverse_dns::ReverseDnsCache;
use crate::relay::StreamRelay;

#[cfg(target_os = "android")]
use std::os::fd::RawFd;

const TUN_TCP_NAT_TIMEOUT: Duration = Duration::from_secs(120);
const TUN_TCP_NAT_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const TUN_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(900);

type TcpCancelRegistry = Arc<Mutex<HashMap<u16, CancellationToken>>>;

/// Configuration for the TUN inbound.
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub addr: IpAddr,
    pub mask_len: u8,
    pub mtu: u16,
    pub name: String,
    /// Automatically manage routing and iptables. True for router environments.
    /// Set to false on desktop Linux (only the TUN device is created).
    pub auto_hijack: bool,
    /// Automatically manage policy routing rules (`ip rule`/`ip route`).
    /// When false, only the TUN device is created; no routing rules are
    /// installed. Cleanup of stale rules from previous runs still happens
    /// at startup. Default: true.
    pub auto_route: bool,
    /// WAN interfaces to monitor for `from <wan_ip> lookup main` bypass rules.
    pub monitor_wan_ifaces: Vec<String>,
    /// LAN interfaces to install `from <ip>` / `to <subnet>` bypass rules for.
    pub bypass_lan_ifaces: Vec<String>,
    /// When true, DNS queries from local processes (127.0.0.1) skip rule
    /// matching and go directly to the direct upstream. Only effective when
    /// auto_hijack is true.
    pub local_direct: bool,
}

impl TunConfig {
    /// Parse from an InboundConfig.
    pub fn from_inbound_config(cfg: &InboundConfig) -> Result<Self, String> {
        let addr_cidr = cfg.addr.as_deref().unwrap_or("10.0.0.1/24");
        let (addr_s, prefix_s) = addr_cidr.split_once('/').ok_or_else(|| {
            "invalid addr: expected CIDR like 10.0.0.1/24".to_string()
        })?;
        let addr = addr_s
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid addr: {e}"))?;
        let mask_len = prefix_s
            .parse::<u8>()
            .map_err(|e| format!("invalid addr prefix: {e}"))?;
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if mask_len > max_prefix {
            return Err(format!("invalid addr prefix: {mask_len}"));
        }
        let auto_route = cfg.auto_route;

        let mtu = cfg.mtu.unwrap_or(1500);

        let name = cfg.name.clone().unwrap_or_else(|| "tun0".to_string());
        let auto_hijack = cfg.auto_hijack;
        let monitor_wan_ifaces =
            cfg.monitor_wan_ifaces.clone().unwrap_or_default();
        let bypass_lan_ifaces = cfg.bypass_lan_ifaces.clone().unwrap_or_default();
        let local_direct = cfg.local_direct;

        Ok(Self {
            addr,
            mask_len,
            mtu,
            name,
            auto_hijack,
            auto_route,
            monitor_wan_ifaces,
            bypass_lan_ifaces,
            local_direct,
        })
    }
}

/// TUN inbound: captures all machine traffic via a virtual network interface.
pub struct TunInbound {
    conn_rx: mpsc::Receiver<InboundConn>,
    _shutdown_tx: oneshot::Sender<()>,
}

/// RAII guard that deletes the TUN interface on drop.
///
/// Must be held on the caller's stack (not inside a spawned task) so Drop
/// is guaranteed to run when main() returns.
pub struct TunGuard {
    #[cfg(target_os = "linux")]
    _inner: Option<Arc<std::sync::Mutex<TunRouteManager>>>,
    #[cfg(target_os = "android")]
    _inner: Option<AndroidTunManager>,
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    _inner: (),
}

impl TunGuard {
    /// Return a clone of the inner TUN route manager, if available.
    #[cfg(target_os = "linux")]
    pub fn tun_mgr(&self) -> Option<Arc<std::sync::Mutex<TunRouteManager>>> {
        self._inner.clone()
    }
}

impl Drop for TunGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(mgr) = self._inner.take() {
            if let Ok(mut mgr) = mgr.lock() {
                mgr.cleanup_routing();

                let output = std::process::Command::new("ip")
                    .args(["link", "delete", &mgr.iface_name])
                    .output();
                match output {
                    Ok(out) if out.status.success() => {
                        log::info!("TUN interface {} deleted", mgr.iface_name);
                    },
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        log::warn!(
                            "Failed to delete TUN interface {}: {}",
                            mgr.iface_name,
                            stderr.trim()
                        );
                    },
                    Err(e) => {
                        log::warn!("Failed to run ip link delete: {e}");
                    },
                }
            }
        }

        #[cfg(target_os = "android")]
        if let Some(_mgr) = self._inner.take() {
            // AndroidTunManager::drop handles logging.
            // VpnService is responsible for closing the TUN fd and
            // tearing down the interface.
        }
    }
}

#[async_trait]
impl Inbound for TunInbound {
    async fn accept(&mut self) -> Option<InboundConn> {
        self.conn_rx.recv().await
    }
}

impl TunInbound {
    /// Create TUN device, set up routing, and return (inbound, guard).
    ///
    /// The caller MUST keep `guard` alive for the lifetime of the inbound.
    /// When `guard` is dropped, the TUN interface is deleted and routes
    /// are cleaned up.
    ///
    /// The `dns_hijack_builder` receives a `TunWriter` and the
    /// TUN-owned `ReverseDnsCache` so the DNS hijack can populate
    /// IP→domain mappings.
    ///
    /// On Android, `tun_fd` must be `Some(fd)` — the fd comes from
    /// VpnService.establish() via JNI. On Linux, `tun_fd` is ignored
    /// (the TUN device is created internally via rtnetlink).
    #[allow(unused_variables)]
    pub async fn new(
        config: &TunConfig,
        dns_hijack_builder: Option<
            Box<
                dyn FnOnce(handler::TunWriter, Arc<ReverseDnsCache>) -> DnsHijack
                    + Send,
            >,
        >,
        #[cfg(target_os = "android")] tun_fd: Option<RawFd>,
    ) -> Result<(Self, TunGuard), Box<dyn std::error::Error>> {
        let addr = config.addr;
        let mask_len = config.mask_len;
        let mtu = config.mtu;
        let name = &config.name;

        // 1. Create TUN device.
        #[cfg(target_os = "linux")]
        let device = {
            let mut tun_config = tun::Configuration::default();
            tun_config
                .address(addr)
                .netmask(mask_to_ipv4_addr(mask_len))
                .mtu(mtu)
                .tun_name(name.as_str())
                .up();
            let device = tun::create_as_async(&tun_config)?;
            Arc::new(device)
        };

        #[cfg(target_os = "android")]
        let device = {
            let fd = tun_fd.ok_or("tun_fd is required on Android")?;
            let device = platform::android::create_tun_from_fd(fd)?;
            Arc::new(device)
        };

        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            return Err("TUN is only supported on Linux and Android".into());
            // Compile-time: device is unbound here, but we return above.
            #[allow(unreachable_code)]
            let device: Arc<tun::AsyncDevice> = unreachable!();
            let _ = device;
        }

        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let device: Arc<tun::AsyncDevice> = unreachable!();

        log::info!("TUN device {name} created at {addr}");

        // 2. Bind TCP listener on the TUN address.
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(addr, 0)).await?;
        let listener_port = listener.local_addr()?.port();
        // 3. Initialize NAT table.
        let nat = Arc::new(Mutex::new(TCPNat::new(TUN_TCP_NAT_TIMEOUT)));

        // Create the reverse DNS cache (TUN-owned lifecycle).
        let reverse_dns = Arc::new(ReverseDnsCache::new(
            std::num::NonZeroUsize::new(4096).unwrap(),
        ));

        // Create DNS hijack handle early — it's needed inside the guard block
        // for the loopback listener on routers.
        let dns_hijack = dns_hijack_builder.map(|b| {
            Arc::new(b(
                handler::TunWriter::new(device.clone()),
                reverse_dns.clone(),
            ))
        });

        // Pass reverse_dns to the handler so it can look up IP→domain.
        let reverse_dns_for_handler = reverse_dns.clone();
        // 4. Set up routing via rtnetlink (Linux only).
        #[cfg(target_os = "linux")]
        let guard = {
            let (rt_conn, handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(rt_conn);

            use futures_util::TryStreamExt;
            let mut links =
                handle.link().get().match_name(name.to_string()).execute();
            let link_index = if let Some(link) = links.try_next().await? {
                link.header.index
            } else {
                return Err(format!("TUN interface '{name}' not found").into());
            };

            let monitor_wan_ifaces = config.monitor_wan_ifaces.clone();
            let bypass_lan_ifaces = config.bypass_lan_ifaces.clone();

            let mut mgr = platform::linux::TunRouteManager::new(
                handle,
                link_index,
                addr,
                name.clone(),
                config.auto_hijack,
                monitor_wan_ifaces,
                bypass_lan_ifaces,
            );

            if let Err(e) = mgr.setup_interface().await {
                log::warn!(
                    "Failed to setup TUN interface (may already be configured): {e}"
                );
            }

            if config.auto_route {
                if let Err(e) = mgr.setup_routing(config.auto_hijack) {
                    log::warn!("Failed to set up routing: {e}");
                }
            }

            // Start DNS loopback listener only when auto-hijack installs
            // iptables REDIRECT 53 → 1053. TUN-internal UDP/53 packets are
            // handled directly in run_tun_handler() and do not need this
            // listener.
            if config.auto_hijack {
                if let Some(ref hijack) = dns_hijack {
                    hijack.start_hijack_listener();
                }
            }
            let mgr = Arc::new(std::sync::Mutex::new(mgr));
            TunGuard { _inner: Some(mgr) }
        };

        // Android: no routing setup needed (VpnService handles it).
        #[cfg(target_os = "android")]
        let guard = TunGuard {
            _inner: Some(AndroidTunManager::new()),
        };

        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let guard = TunGuard { _inner: () };

        // 5. Create channels.
        let (conn_tx, conn_rx) = mpsc::channel::<InboundConn>(1024);
        let (_shutdown_tx, _shutdown_rx) = oneshot::channel::<()>();

        // 6. Spawn the TUN I/O handler.
        let tun_clone = device.clone();
        let nat_clone = nat.clone();
        let conn_tx_handler = conn_tx.clone();
        let dns_hijack_clone = dns_hijack.clone();
        tokio::spawn(async move {
            handler::run_tun_handler(
                tun_clone,
                addr,
                nat_clone,
                listener_port,
                conn_tx_handler,
                dns_hijack,
                Some(reverse_dns_for_handler),
            )
            .await;
        });

        // 7. Spawn the accept loop.
        let cancel_registry: TcpCancelRegistry =
            Arc::new(Mutex::new(HashMap::new()));
        let nat_accept = nat.clone();
        let cancel_accept = cancel_registry.clone();
        let conn_tx_accept = conn_tx.clone();
        let reverse_dns_accept = reverse_dns.clone();
        tokio::spawn(async move {
            accept_loop(
                listener,
                nat_accept,
                cancel_accept,
                conn_tx_accept,
                Some(reverse_dns_accept),
                dns_hijack_clone,
            )
            .await;
        });

        let nat_cleanup = nat.clone();
        let cancel_cleanup = cancel_registry.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TUN_TCP_NAT_CLEANUP_INTERVAL).await;
                let expired = {
                    let mut guard = nat_cleanup.lock().await;
                    guard.cleanup_expired()
                };

                if expired.is_empty() {
                    continue;
                }

                let mut cancels = cancel_cleanup.lock().await;
                for port in expired {
                    if let Some(token) = cancels.remove(&port) {
                        token.cancel();
                    }
                }
            }
        });

        Ok((
            Self {
                conn_rx,
                _shutdown_tx,
            },
            guard,
        ))
    }
}

/// Accept TCP connections from the NAT listener and forward them as
/// InboundConns.
async fn accept_loop(
    listener: tokio::net::TcpListener, nat: Arc<Mutex<TCPNat>>,
    cancel_registry: TcpCancelRegistry, conn_tx: mpsc::Sender<InboundConn>,
    reverse_dns: Option<Arc<ReverseDnsCache>>,
    dns_hijack: Option<Arc<DnsHijack>>,
) {
    let mut backoff = Duration::from_millis(100);
    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(accepted) => {
                backoff = Duration::from_millis(100);
                accepted
            },
            Err(e) => {
                let is_fd_exhausted = e.raw_os_error() == Some(24) /* EMFILE */
                    || e.raw_os_error() == Some(23) /* ENFILE */;
                if is_fd_exhausted {
                    log::error!(
                        "TUN listener accept error: too many open files ({e}), retrying in {backoff:?}..."
                    );
                } else {
                    log::error!(
                        "TUN listener accept error: {e}, retrying in {backoff:?}..."
                    );
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            },
        };

        let nat_port = remote.port();
        let session = {
            let guard = nat.lock().await;
            guard.lookup_back(nat_port).cloned()
        };

        match session {
            Some(session) => {
                let address = match (session.target_addr.ip(), &reverse_dns) {
                    (std::net::IpAddr::V4(v4), Some(rev)) => {
                        match rev.lookup_ipv4(v4).await {
                            Some(domain) => {
                                log::debug!(
                                    "TUN restore domain: {}:{} -> {}:{}",
                                    v4,
                                    session.target_addr.port(),
                                    domain,
                                    session.target_addr.port(),
                                );
                                Address::Domain(domain)
                            },
                            None => {
                                let is_fakeip = match &dns_hijack {
                                    Some(hj) => hj.fakeip_contains(v4),
                                    None => false,
                                };
                                if is_fakeip {
                                    log::warn!(
                                        "TUN fake-ip missing reverse mapping: {}:{}",
                                        v4,
                                        session.target_addr.port(),
                                    );
                                }
                                ip_to_addr(session.target_addr.ip())
                            },
                        }
                    },
                    (std::net::IpAddr::V6(v6), Some(rev)) => {
                        match rev.lookup_ipv6(v6).await {
                            Some(domain) => Address::Domain(domain),
                            None => ip_to_addr(session.target_addr.ip()),
                        }
                    },
                    _ => ip_to_addr(session.target_addr.ip()),
                };
                let cancel = CancellationToken::new();
                cancel_registry
                    .lock()
                    .await
                    .insert(nat_port, cancel.clone());

                let conn = InboundConn::Tcp {
                    destination: Destination::with_resolved(
                        address,
                        session.target_addr.port(),
                        session.target_addr.ip(),
                    ),
                    stream: Box::new(TunTcpRelay::new(
                        stream,
                        nat.clone(),
                        cancel_registry.clone(),
                        cancel,
                        nat_port,
                        TUN_TCP_IDLE_TIMEOUT,
                    )),
                    source: session.client_addr,
                    type_: "tun".into(),
                };
                if conn_tx.try_send(conn).is_err() {
                    let mut guard = nat.lock().await;
                    guard.remove(nat_port);
                    continue;
                }
            },
            None => {
                drop(stream);
            },
        }
    }
}

struct TunTcpRelay {
    stream: TcpStream,
    nat: Arc<Mutex<TCPNat>>,
    cancel_registry: TcpCancelRegistry,
    cancel: CancellationToken,
    nat_port: u16,
    last_activity: tokio::time::Instant,
    idle_timeout: Duration,
}

impl TunTcpRelay {
    fn new(
        stream: TcpStream, nat: Arc<Mutex<TCPNat>>,
        cancel_registry: TcpCancelRegistry, cancel: CancellationToken,
        nat_port: u16, idle_timeout: Duration,
    ) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            stream,
            nat,
            cancel_registry,
            cancel,
            nat_port,
            last_activity: now,
            idle_timeout,
        }
    }

    fn expired(&self) -> bool {
        tokio::time::Instant::now().duration_since(self.last_activity) >=
            self.idle_timeout
    }

    async fn touch_or_close(&mut self) -> std::io::Result<bool> {
        if self.expired() {
            self.close_nat().await;
            return Ok(false);
        }

        let mut guard = self.nat.lock().await;
        if guard.touch_by_port(self.nat_port) {
            self.last_activity = tokio::time::Instant::now();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn close_nat(&mut self) {
        self.cancel.cancel();
        let mut guard = self.nat.lock().await;
        guard.remove(self.nat_port);
        drop(guard);
        self.cancel_registry.lock().await.remove(&self.nat_port);
    }
}

#[async_trait]
impl StreamRelay for TunTcpRelay {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cancel.is_cancelled() || !self.touch_or_close().await? {
            return Ok(0);
        }

        let n = tokio::select! {
            _ = self.cancel.cancelled() => return Ok(0),
            result = self.stream.read(buf) => result?,
        };

        if n == 0 {
            self.close_nat().await;
            return Ok(0);
        }

        if !self.touch_or_close().await? {
            return Ok(0);
        }

        Ok(n)
    }

    async fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if self.cancel.is_cancelled() || !self.touch_or_close().await? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "stale TUN TCP NAT session",
            ));
        }

        tokio::select! {
            _ = self.cancel.cancelled() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "cancelled TUN TCP NAT session",
                ));
            },
            result = self.stream.write_all(buf) => result?,
        }

        if !self.touch_or_close().await? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "stale TUN TCP NAT session",
            ));
        }

        Ok(())
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        self.close_nat().await;
        self.stream.shutdown().await
    }
}

fn ip_to_addr(ip: std::net::IpAddr) -> Address {
    match ip {
        std::net::IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
        std::net::IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
    }
}

/// Convert a prefix length to an IPv4 netmask.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(dead_code)]
fn mask_to_ipv4_addr(len: u8) -> Ipv4Addr {
    let bits = if len >= 32 {
        !0u32
    } else {
        !0u32 << (32 - len)
    };
    Ipv4Addr::from(bits.to_be_bytes())
}
