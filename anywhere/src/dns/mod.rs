//! DNS hijack module.
//!
//! Intercepts UDP/53 at the TUN inbound, parses the query domain, runs it
//! through the rule engine, and forwards to either the `direct` upstream
//! (default 223.5.5.5) or the `remote` upstream (default 8.8.8.8). AAAA
//! queries are short-circuited to an empty NOERROR response (no IPv6
//! support end-to-end yet). Responses are cached in a small LRU keyed by
//! `{domain}/{qtype}`.
//!
//! Sub-modules:
//! - [`wire`] — DNS wire-format parsing/building (pure functions).
//! - [`upstream`] — `Upstream` enum and config-string parsing.
//! - [`doh`] — DNS-over-HTTPS (RFC 8484) client.

pub mod doh;
pub mod upstream;
pub mod wire;

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use lru::LruCache;
use serde::Deserialize;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::inbound::Network;
use crate::inbound::tun::TunWriter;
use crate::inbound::tun::packet;
use crate::inbound::tun::reverse_dns::ReverseDnsCache;
use crate::inbound::tun::reverse_dns::parse_a_records;
use crate::outbound::OutboundClient;
use crate::outbound::common::bind_udp_bypass;
use crate::rules::Rules;

use doh::DohClient;
use upstream::{Upstream, parse_upstream, parse_upstreams_ordered};
use wire::{
    apply_txn_id, build_empty_response, build_fake_a_response, build_refused_response,
    parse_dns_query, txn_id,
};

const CACHE_CAPACITY: usize = 1024;
const CACHE_TTL: Duration = Duration::from_secs(300);
/// Cap concurrent in-flight DNS resolutions. Each one holds an outbound
/// UDP socket until the response arrives; without a cap, a burst of
/// reverse lookups can exhaust the process fd budget.
const MAX_INFLIGHT: usize = 128;
/// Per-query upstream timeout. Misbehaving upstreams shouldn't pin fds.
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
/// Port for the DNS loopback listener. iptables REDIRECT forwards 53 → this
/// so dnsmasq (which may also serve DHCP) is never touched.
pub const DNS_REDIRECT_PORT: u16 = 1053;

/// `[dns]` config section.
///
/// `direct` and `remote` are each a list of upstreams. Each entry is either
/// an IP address (plain UDP/53) or a complete `https://` URL (DNS-over-HTTPS,
/// RFC 8484). For backward compatibility a single bare string is also
/// accepted and is treated as a one-element list.
///
/// At runtime DoH upstreams are tried first (in declared order) and plain
/// UDP upstreams last, so configured DoH always wins when it is reachable.
/// DoH is currently supported for the `direct` group only; any DoH entry in
/// `remote` is ignored with a warning.
///
/// ```toml
/// [dns]
/// direct = ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query", "223.5.5.5"]
/// remote = ["8.8.8.8", "1.1.1.1"]
/// fakeip = "198.18.0.0/15"
/// ```
///
/// DoH upstreams (entries starting with `https://`) and plain UDP upstreams
/// (bare IPs) are automatically separated from the `direct` list.  DoH is
/// used as the primary resolver with random selection; plain UDP serves as
/// DoH bootstrap and fallback.  If no plain UDP upstream is configured,
/// `223.5.5.5` is injected automatically.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_direct", deserialize_with = "de_upstream_list")]
    pub direct: Vec<String>,
    #[serde(default = "default_remote", deserialize_with = "de_upstream_list")]
    pub remote: Vec<String>,
    /// Fake-IP CIDR, e.g. "198.18.0.0/15". Enabled by default for TUN so
    /// domain information survives IP-only TUN packets.
    #[serde(default = "default_fakeip")]
    pub fakeip: Option<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            direct: default_direct(),
            remote: default_remote(),
            fakeip: default_fakeip(),
        }
    }
}

fn default_direct() -> Vec<String> {
    vec![
        // "https://doh.pub/dns-query".to_string(),
        // "https://dns.alidns.com/dns-query".to_string(),
        // "https://doh.360.cn/dns-query".to_string(),
        "223.5.5.5".to_string(),
        "114.114.114.114".to_string(),
    ]
}
fn default_remote() -> Vec<String> {
    vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
}
fn default_fakeip() -> Option<String> {
    Some("198.18.0.0/15".to_string())
}

/// Deserialize an upstream list while accepting a single bare string as a
/// one-element list (backward compatibility).
fn de_upstream_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StrOrList {
        Single(String),
        Multi(Vec<String>),
    }
    Ok(match StrOrList::deserialize(deserializer)? {
        StrOrList::Single(s) => vec![s],
        StrOrList::Multi(v) => v,
    })
}

/// Pick a random index in `[0, len)` using the current nanosecond count
/// as a cheap entropy source.  Good enough for load-balancing DNS upstreams
/// without pulling in a `rand` dependency.
fn nanos_random(len: usize) -> usize {
    if len <= 1 {
        return 0;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as usize % len)
        .unwrap_or(0)
}

#[derive(Clone)]
struct FakeIpPool {
    base: u32,
    size: u32,
    next: Arc<std::sync::atomic::AtomicU32>,
    /// Domain → allocated IP mapping, so repeated queries for the same
    /// domain return the same FakeIP instead of burning a new address.
    domain_map: Arc<tokio::sync::Mutex<lru::LruCache<String, std::net::Ipv4Addr>>>,
}

impl FakeIpPool {
    /// Returns true if `ip` falls within this FakeIP pool's CIDR range.
    fn contains(&self, ip: std::net::Ipv4Addr) -> bool {
        let v = u32::from(ip);
        v >= self.base && v < self.base + self.size
    }
}

impl FakeIpPool {
    fn parse(cidr: &str) -> Result<Self, String> {
        let (ip, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| format!("invalid fakeip CIDR '{cidr}'"))?;
        let ip: std::net::Ipv4Addr = ip
            .parse()
            .map_err(|e| format!("invalid fakeip address: {e}"))?;
        let prefix: u32 = prefix
            .parse()
            .map_err(|e| format!("invalid fakeip prefix: {e}"))?;
        if prefix > 32 {
            return Err("invalid fakeip prefix".to_string());
        }
        let size = 1u32.checked_shl(32 - prefix).unwrap_or(0);
        if size <= 2 {
            return Err("fakeip range too small".to_string());
        }
        Ok(Self {
            base: u32::from(ip),
            size,
            next: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            domain_map: Arc::new(tokio::sync::Mutex::new(
                lru::LruCache::new(
                    std::num::NonZeroUsize::new(4096).unwrap(),
                ),
            )),
        })
    }

    /// Allocate a FakeIP for `domain`. If the domain already has a
    /// FakeIP allocated, return the existing one (deduplication).
    async fn allocate(&self, domain: &str) -> std::net::Ipv4Addr {
        // Check existing mapping first.
        if let Some(ip) = self.domain_map.lock().await.get(domain).copied() {
            return ip;
        }
        // Allocate a new IP.
        let n = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let host = 1 + (n % (self.size - 2));
        let ip = std::net::Ipv4Addr::from(self.base + host);
        self.domain_map.lock().await.put(domain.to_string(), ip);
        ip
    }
}

/// Per-DNS-resolution context: which outbound to dispatch through, and the
/// ordered list of upstreams to try (DoH first, then plain UDP).
struct Plan {
    outbound_tag: String,
    upstreams: Vec<Upstream>,
}

/// DNS hijack handler. One instance per TUN inbound, shared by reference.
pub struct DnsHijack {
    remote_upstreams: Vec<Upstream>,
    /// DoH upstreams from the `direct` group. Randomly selected per query;
    /// on failure the resolver falls back to plain UDP.
    direct_doh_upstreams: Vec<Upstream>,
    /// Plain UDP upstreams from the `direct` group (e.g. 223.5.5.5).
    /// Used as bootstrap for DoH and as fallback when DoH fails.
    direct_plain: Vec<Upstream>,
    doh: DohClient,
    fakeip: Option<FakeIpPool>,
    /// When true, DNS queries from 127.0.0.1 skip rule matching and go
    /// directly to the direct upstream.
    local_direct: bool,
    cache: Mutex<LruCache<String, (Instant, Vec<u8>)>>,
    reverse_cache: Arc<ReverseDnsCache>,
    rules: Arc<Rules>,
    registry: Arc<HashMap<String, Arc<dyn OutboundClient>>>,
    writer: TunWriter,
    inflight: Arc<Semaphore>,
    /// Pool of connected UDP sockets for direct DNS queries. Each socket is
    /// `connect()`-ed to the upstream, so the kernel filters responses by
    /// source address — no cross-talk. A pool avoids serializing all direct
    /// DNS lookups behind a single socket.
    socket_pool: Mutex<Vec<UdpSocket>>,
    /// Maximum number of sockets to retain in the pool. Excess sockets are
    /// dropped (and their fds released) after use instead of being returned.
    socket_pool_cap: usize,
}

impl DnsHijack {
    /// Returns true if `ip` is a FakeIP address (i.e. falls within the
    /// configured fakeip CIDR range).
    pub fn fakeip_contains(&self, ip: std::net::Ipv4Addr) -> bool {
        self.fakeip.as_ref().is_some_and(|p| p.contains(ip))
    }

    pub fn new(
        config: &DnsConfig, local_direct: bool, rules: Arc<Rules>,
        registry: Arc<HashMap<String, Arc<dyn OutboundClient>>>,
        writer: TunWriter, reverse_cache: Arc<ReverseDnsCache>,
    ) -> Result<Self, String> {
        let mut direct_upstreams = parse_upstreams_ordered(&config.direct)?;

        // DoH needs a plain UDP bootstrap resolver (to resolve the DoH server
        // hostname itself without recursing into DoH). If the direct group
        // has no plain IP upstream, inject the default (223.5.5.5) so the
        // bootstrap path always works. The injected upstream also serves as
        // the plain UDP fallback when DoH fails or is disabled.
        if !direct_upstreams.iter().any(|u| matches!(u, Upstream::Plain(_))) {
            log::info!(
                "DNS: no plain IP upstream in `direct`, injecting 223.5.5.5 \
                 as DoH bootstrap + fallback"
            );
            direct_upstreams.push(parse_upstream("223.5.5.5")?);
        }

        // remote group: DoH over the proxy outbound is not supported, but
        // we reuse the `direct` DoH upstreams to resolve remote domains via
        // encrypted DoH (bypassing TUN) before falling back to proxy UDP.
        // Drop any DoH entries explicitly configured in `remote` — they
        // would need proxy-outbound DoH transport which doesn't exist yet.
        let mut remote_upstreams = parse_upstreams_ordered(&config.remote)?;
        let remote_doh_count = remote_upstreams.iter().filter(|u| u.is_doh()).count();
        if remote_doh_count > 0 {
            log::info!(
                "DNS: {remote_doh_count} DoH upstream(s) in `remote` ignored \
                 (DoH over proxy outbound not supported); remote domains will\
                 \n be resolved via direct DoH + proxy UDP fallback"
            );
            remote_upstreams.retain(|u| !u.is_doh());
        }
        if remote_upstreams.is_empty() {
            log::info!(
                "DNS: `remote` has no plain upstream; remote domains will be\
                 \n resolved via direct DoH + proxy UDP fallback (default 8.8.8.8)"
            );
            remote_upstreams.push(parse_upstream("8.8.8.8")?);
        }

        // Split direct upstreams into DoH and plain UDP groups.
        // DoH is used as the primary resolver (randomly selected per query);
        // plain UDP serves as DoH bootstrap and fallback. If the user didn't
        // configure any plain UDP upstream, 223.5.5.5 was already injected
        // above.
        let direct_doh_upstreams: Vec<Upstream> = direct_upstreams
            .iter()
            .filter(|u| u.is_doh())
            .cloned()
            .collect();
        let direct_plain: Vec<Upstream> = direct_upstreams
            .iter()
            .filter_map(|u| match u {
                Upstream::Plain(d) => Some(Upstream::Plain(d.clone())),
                _ => None,
            })
            .collect();
        if direct_doh_upstreams.is_empty() {
            log::info!("DNS: no DoH upstream in `direct`, using plain UDP only");
        } else {
            log::info!(
                "DNS: {} DoH upstream(s) + {} plain UDP fallback(s)",
                direct_doh_upstreams.len(),
                direct_plain.len()
            );
        }

        // Bootstrap upstreams for DoH = plain UDP entries from the direct group.
        let bootstrap: Vec<Destination> = direct_plain
            .iter()
            .filter_map(|u| match u {
                Upstream::Plain(d) => Some(d.clone()),
                _ => None,
            })
            .collect();
        let doh = DohClient::new(bootstrap);

        let fakeip = match &config.fakeip {
            Some(cidr) => Some(FakeIpPool::parse(cidr)?),
            None => None,
        };
        Ok(Self {
            remote_upstreams,
            direct_doh_upstreams,
            direct_plain,
            doh,
            fakeip,
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(CACHE_CAPACITY).unwrap(),
            )),
            reverse_cache,
            rules,
            registry,
            writer,
            local_direct,
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            socket_pool: Mutex::new(Vec::new()),
            socket_pool_cap: 8,
        })
    }

    /// Try to handle a UDP/53 datagram from the TUN handler. Returns true if
    /// it was hijacked (response written back to TUN) and the caller should
    /// skip the normal UDP relay path.
    pub async fn handle_query(
        self: Arc<Self>, query: &[u8], src_ip: IpAddr, src_port: u16,
        dst_ip: IpAddr, _dst_port: u16,
    ) -> bool {
        match self.resolve_query(query, src_ip).await {
            Some(response) => {
                log::info!(
                    "DNS handle_query: resolved {} bytes, sending via TUN to {src_ip}:{src_port}",
                    response.len()
                );
                let _ = self
                    .send_response(&response, dst_ip, src_ip, src_port)
                    .await;
                true
            },
            None => {
                log::warn!("DNS handle_query: resolution failed, sending REFUSED");
                if let Some(resp) = build_refused_response(query) {
                    let _ =
                        self.send_response(&resp, dst_ip, src_ip, src_port).await;
                }
                true
            },
        }
    }

    /// Resolve a DNS query and return the raw response bytes, or `None` if
    /// the query could not be resolved. `None` is also returned when the
    /// matched outbound is missing — the caller should send a REFUSED response.
    async fn resolve_query(
        &self, query: &[u8], src_ip: IpAddr,
    ) -> Option<Vec<u8>> {
        let q = parse_dns_query(query)?;

        log::info!(
            "DNS resolve: name={} qtype={} src={}",
            q.name, q.qtype, src_ip
        );

        // AAAA -> empty answer (no v6 end-to-end yet).
        if q.qtype == 28 {
            log::info!("DNS resolve: {} type AAAA -> empty (no v6)", q.name);
            return build_empty_response(query);
        }

        let cache_key_base = format!("{}/{}", q.name, q.qtype);

        // Local-direct mode: queries from the router itself (127.0.0.1)
        // skip rule matching and go directly to the direct upstream.
        // This avoids slow proxy DNS for the device's own queries and
        // prevents the proxy from being blocked waiting on its own DNS.
        if self.local_direct && src_ip.is_loopback() {
            let plan = self.plan_for("direct".to_string());
            return self.resolve_with_fallback(query, &plan, None).await;
        }
        // Match rule on (domain, udp, port 53) to pick outbound + upstream.
        let dest = Destination::new(Address::Domain(q.name.clone()), 53);
        let rule_match = self.rules.match_conn(&dest, Network::Udp, None);
        let plan = match rule_match {
            Some(m) => self.plan_for(m.outbound_tag),
            None => self.plan_for("direct".to_string()),
        };

        let cache_key = format!("{}/{}", cache_key_base, plan.outbound_tag);
        {
            let mut guard = self.cache.lock().await;
            if let Some((_, cached)) = guard
                .get(&cache_key)
                .cloned()
                .filter(|(ts, _)| ts.elapsed() < CACHE_TTL)
            {
                drop(guard);
                for (ip, _domain) in parse_a_records(&cached) {
                    self.reverse_cache
                        .insert(IpAddr::V4(ip), q.name.clone())
                        .await;
                }
                return Some(apply_txn_id(&cached, txn_id(query)));
            }
        }

        if q.qtype == 1
            && plan.outbound_tag != "direct"
            && let Some(fakeip) = &self.fakeip
        {
            let ip = fakeip.allocate(&q.name).await;
            self.reverse_cache
                .insert(IpAddr::V4(ip), q.name.clone())
                .await;
            if let Some(resp) = build_fake_a_response(query, ip) {
                self.cache
                    .lock()
                    .await
                    .put(cache_key, (Instant::now(), resp.clone()));
                log::debug!(
                    "DNS: {} (type {}) → fake-ip {} via {}",
                    q.name,
                    q.qtype,
                    ip,
                    plan.outbound_tag
                );
                return Some(resp);
            }
        }

        let client = self.registry.get(&plan.outbound_tag);
        let client = match client {
            Some(c) => c.clone(),
            None => {
                log::warn!("DNS hijack: outbound '{}' not found", plan.outbound_tag);
                return None; // caller sends REFUSED
            }
        };

        // Acquire a slot before opening an outbound socket.
        let _permit = self.inflight.clone().acquire_owned().await.ok()?;

        let response = self
            .resolve_with_fallback(query, &plan, Some(&client))
            .await;
        let response = match response {
            Some(r) => r,
            None => return None,
        };

        self.cache
            .lock()
            .await
            .put(cache_key, (Instant::now(), response.clone()));

        // Populate reverse cache so TUN handler can resolve IP → domain.
        for (ip, _domain) in parse_a_records(&response) {
            self.reverse_cache
                .insert(IpAddr::V4(ip), q.name.clone())
                .await;
        }

        Some(response)
    }

    /// Resolve a DNS query through a pooled direct UDP socket.
    ///
    /// Pops a socket from the pool (or creates one on miss), sends the query,
    /// reads the response, and returns the socket to the pool. Each socket is
    /// `connect()`-ed to the upstream so the kernel filters responses by source
    /// address — no cross-talk between concurrent queries.
    async fn resolve_direct_udp(
        &self, query: &[u8], upstream: &Destination,
    ) -> Option<Vec<u8>> {
        let addr: std::net::SocketAddr = upstream.to_string().parse().ok()?;
        log::info!("resolve_direct_udp: upstream={addr}");
        let sock = {
            let mut pool = self.socket_pool.lock().await;
            pool.pop()
        };
        let sock = match sock {
            Some(s) => {
                log::info!("resolve_direct_udp: reused pooled socket");
                s
            },
            None => {
                let s = match bind_udp_bypass("0.0.0.0:0".parse().unwrap()).await {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("resolve_direct_udp: bind failed: {e}");
                        return None;
                    }
                };
                match s.connect(addr).await {
                    Ok(()) => {},
                    Err(e) => {
                        log::warn!("resolve_direct_udp: connect to {addr} failed: {e}");
                        return None;
                    }
                }
                log::info!("resolve_direct_udp: socket connected to {addr}");
                s
            },
        };

        match sock.send(query).await {
            Ok(_) => {},
            Err(e) => {
                log::warn!("resolve_direct_udp: send to {addr} failed: {e}");
                return None;
            }
        }
        log::info!("resolve_direct_udp: sent {len} bytes to {addr}", len = query.len());
        let mut buf = vec![0u8; 4096];
        let result = match timeout(QUERY_TIMEOUT, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                log::info!("resolve_direct_udp: got {n} bytes from {addr}");
                Some(buf[..n].to_vec())
            }
            Ok(Err(e)) => {
                log::warn!("resolve_direct_udp: recv error from {addr}: {e}");
                None
            }
            Err(_) => {
                log::warn!("resolve_direct_udp: timeout waiting for {addr}");
                None
            }
        };

        // Return socket to the pool for reuse (if pool not full).
        let mut pool = self.socket_pool.lock().await;
        if pool.len() < self.socket_pool_cap {
            pool.push(sock);
        }
        // Excess sockets are dropped here, releasing their fd.
        result
    }

    /// Resolve a DNS query through an outbound client (remote proxy).
    async fn resolve_via_outbound(
        &self, query: &[u8], upstream: &Destination,
        client: &Arc<dyn OutboundClient>,
    ) -> Option<Vec<u8>> {
        let dial_res = {
            match timeout(QUERY_TIMEOUT, client.dial_udp(upstream)).await {
                Ok(r) => r.map_err(|e| e.to_string()),
                Err(_) => Err("dial timeout".to_string()),
            }
        };
        let mut relay = match dial_res {
            Ok(r) => r,
            Err(e) => {
                log::warn!("DNS hijack: dial_udp via remote failed: {e}");
                return None;
            },
        };

        if relay.write_packet(query, upstream).await.is_err() {
            log::warn!("DNS hijack: write failed");
            return None;
        }
        let mut buf = vec![0u8; 4096];
        let (n, _from) =
            match timeout(QUERY_TIMEOUT, relay.read_packet(&mut buf)).await {
                Ok(Ok(x)) => x,
                Ok(Err(e)) => {
                    log::warn!("DNS hijack: read failed: {e}");
                    return None;
                },
                Err(_) => {
                    log::warn!("DNS hijack: upstream timeout");
                    return None;
                },
            };
        Some(buf[..n].to_vec())
    }

    /// Spawn a UDP listener that answers DNS queries.
    ///
    /// Listens on port 1053 (not 53) — iptables REDIRECT forwards port 53
    /// traffic here, avoiding conflicts with dnsmasq (which may also serve
    /// DHCP).
    pub fn start_hijack_listener(self: &Arc<Self>) {
        let this = self.clone();

        // IPv4 listener.
        let this4 = this.clone();
        tokio::spawn(async move {
            // On macOS, bind to 127.0.0.1 (not 0.0.0.0) so:
            // 1) The listener receives pf `rdr`-redirected DNS (-> 127.0.0.1:1053)
            // 2) Response source IP is 127.0.0.1, matching the rdr state for
            //    reverse NAT. Binding 0.0.0.0 causes the kernel to pick the
            //    destination IP as source (e.g. 10.0.0.1), breaking rdr state.
            // On Linux/Android, bind to 0.0.0.0 with SO_MARK / VpnService
            // protect so response traffic bypasses TUN.
            #[cfg(target_os = "macos")]
            let addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                DNS_REDIRECT_PORT,
            );
            #[cfg(not(target_os = "macos"))]
            let addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                DNS_REDIRECT_PORT,
            );
            Self::run_listener(this4, addr).await;
        });

        // IPv6 listener (macOS only - pf `rdr inet6` redirects to ::1:1053).
        // Without this, IPv6 DNS queries are redirected to ::1:1053 where
        // nobody listens, causing DNS failure for systems using IPv6 DNS.
        #[cfg(target_os = "macos")]
        {
            let this6 = this.clone();
            tokio::spawn(async move {
                let addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                    DNS_REDIRECT_PORT,
                );
                Self::run_listener(this6, addr).await;
            });
        }
    }

    /// Run a DNS loopback listener on the given address.
    async fn run_listener(this: Arc<Self>, addr: std::net::SocketAddr) {
        let socket = match {
            #[cfg(target_os = "macos")]
            { UdpSocket::bind(addr).await }
            #[cfg(not(target_os = "macos"))]
            { bind_udp_bypass(addr).await }
        } {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log::error!("DNS loopback listener: bind {addr} failed: {e}");
                return;
            },
        };

        log::info!("DNS loopback listener on {addr}");
        let mut buf = vec![0u8; 512];
        loop {
            let (n, src) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    log::warn!("DNS loopback recv: {e}");
                    break;
                },
            };
            let query = buf[..n].to_vec();
            log::info!("DNS listener: received {n} bytes from {src}");
            let this = this.clone();
            let sock = socket.clone();
            tokio::spawn(async move {
                let response = this
                    .resolve_query(&query, src.ip())
                    .await
                    .or_else(|| build_refused_response(&query));
                if let Some(r) = response {
                    log::info!("DNS listener: sending {} bytes to {src}", r.len());
                    let _ = sock.send_to(&r, src).await;
                } else {
                    log::warn!("DNS listener: no response for {src}");
                }
            });
        }
    }

    fn plan_for(&self, tag: String) -> Plan {
        let upstreams = if tag == "direct" {
            // Direct resolution uses direct_doh_upstreams + direct_plain
            // directly in resolve_with_fallback; plan.upstreams is unused.
            Vec::new()
        } else {
            self.remote_upstreams.clone()
        };
        Plan {
            outbound_tag: tag,
            upstreams,
        }
    }

    /// Try DoH (randomly selected) first for direct domains, then fall back
    /// to a random plain UDP upstream.
    ///
    /// For `direct`: random DoH → random plain UDP (e.g. 223.5.5.5).
    /// For `remote`: random proxy UDP relay (e.g. 8.8.8.8, 1.1.1.1).
    ///
    /// Proxy domains never use direct DoH — the result may be polluted or
    /// the DoH server may be unreachable from the direct path.  This keeps
    /// DNS resolution consistent with the fake-ip outbound path.
    ///
    /// `client` is `Some` for non-direct outbounds (used for the UDP relay);
    /// `None` for the direct/local-direct path.
    async fn resolve_with_fallback(
        &self, query: &[u8], plan: &Plan,
        client: Option<&Arc<dyn OutboundClient>>,
    ) -> Option<Vec<u8>> {
        let qinfo = parse_dns_query(query).map(|q| (q.name, q.qtype)).unwrap_or_default();
        let qname = qinfo.0.as_str();
        let qtype = qinfo.1;
        let is_direct = plan.outbound_tag == "direct";

        // --- DoH phase: direct domains only ---
        if is_direct && !self.direct_doh_upstreams.is_empty() {
            let idx = nanos_random(self.direct_doh_upstreams.len());
            let up = &self.direct_doh_upstreams[idx];
            let host = match up { Upstream::Doh { host, .. } => host.as_str(), _ => "" };
            if let Some(resp) = self.doh.resolve(query, up).await {
                log::info!("DNS: {qname} (type {qtype}) -> DoH({host}) OK");
                return Some(resp);
            }
            // DoH failed - fall through to plain UDP fallback.
        }
        // --- Plain UDP fallback phase ---
        if is_direct {
            if !self.direct_plain.is_empty() {
                let idx = nanos_random(self.direct_plain.len());
                if let Upstream::Plain(dest) = &self.direct_plain[idx] {
                    let d = dest.to_string();
                    if let Some(resp) = self.resolve_direct_udp(query, dest).await {
                        log::info!("DNS: {qname} (type {qtype}) -> UDP({d}) OK");
                        return Some(resp);
                    }
                }
            }
        } else {
            // Remote: random proxy UDP relay.
            let plain: Vec<_> = plan.upstreams.iter().filter_map(|u| match u {
                Upstream::Plain(d) => Some(d),
                _ => None,
            }).collect();
            if !plain.is_empty() && client.is_some() {
                let idx = nanos_random(plain.len());
                let dest = plain[idx];
                let d = dest.to_string();
                let tag = plan.outbound_tag.clone();
                if let Some(c) = client {
                    if let Some(resp) = self.resolve_via_outbound(query, dest, c).await {
                        log::info!("DNS: {qname} (type {qtype}) -> via {tag}({d}) OK");
                        return Some(resp);
                    }
                }
            }
        }
        log::warn!("DNS: {qname} (type {qtype}) -> ALL METHODS FAILED");
        None
    }

    async fn send_response(
        &self,
        payload: &[u8],
        src_ip: IpAddr, // = original DNS server (kernel sees this as the source)
        dst_ip: IpAddr, // = original client
        dst_port: u16,
    ) -> std::io::Result<()> {
        let raw = match (src_ip, dst_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) =>
                packet::build_udp_response_ipv4(s, 53, d, dst_port, payload),
            (IpAddr::V6(s), IpAddr::V6(d)) =>
                packet::build_udp_response_ipv6(s, 53, d, dst_port, payload),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "mismatched IP versions",
                ));
            },
        };
        log::info!(
            "DNS send_response: {} bytes, src={}:53 dst={}:{} via TUN writer",
            raw.len(), src_ip, dst_ip, dst_port
        );
        self.writer.write(&raw).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_config_deserialize_single_string() {
        let toml = r#"
            direct = "8.8.8.8"
            remote = "1.1.1.1"
        "#;
        let cfg: DnsConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.direct, vec!["8.8.8.8"]);
        assert_eq!(cfg.remote, vec!["1.1.1.1"]);
    }

    #[test]
    fn dns_config_deserialize_arrays() {
        let toml = r#"
            direct = ["https://dns.alidns.com/dns-query", "223.5.5.5"]
            remote = ["8.8.8.8", "1.1.1.1"]
            fakeip = "198.18.0.0/15"
        "#;
        let cfg: DnsConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.direct.len(), 2);
        assert_eq!(cfg.remote.len(), 2);
        assert_eq!(cfg.fakeip, Some("198.18.0.0/15".to_string()));
    }

    #[test]
    fn dns_config_deserialize_default() {
        let toml = "";
        let cfg: DnsConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.direct,
            vec![
                // "https://doh.pub/dns-query",
                // "https://dns.alidns.com/dns-query",
                // "https://doh.360.cn/dns-query",
                "223.5.5.5",
                "114.114.114.114",
            ]
        );
        assert_eq!(cfg.remote, vec!["8.8.8.8", "1.1.1.1"]);
        assert_eq!(cfg.fakeip, Some("198.18.0.0/15".to_string()));
    }
}
