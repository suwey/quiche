//! DNS hijack module.
//!
//! Intercepts UDP/53 at the TUN inbound, parses the query domain, runs it
//! through the rule engine, and forwards to either the `direct` upstream
//! (default 223.5.5.5) or the `remote` upstream (default 8.8.8.8). On
//! non-direct plans, fake-ip mode answers A with a v4 fake from the
//! configured CIDR and AAAA with a v6 fake from the pool set by
//! `fakeip_inet6_range` (default `fdfe:dcba:9876::/64`) — both addresses
//! restore the same domain in the TUN handler. Direct plans (and
//! fakeip-filtered domains) resolve for real through the normal upstream
//! chain, with upstream AAAA records passed through untouched. Responses are
//! cached in a small LRU keyed by `{domain}/{qtype}`.
//!
//! Sub-modules:
//! - [`wire`] — DNS wire-format parsing/building (pure functions).
//! - [`upstream`] — `Upstream` enum and config-string parsing.
//! - [`doh`] — DNS-over-HTTPS (RFC 8484) client.

pub mod doh;
pub mod fakeip_filter;
pub mod https_record;
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
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::inbound::Network;
use crate::inbound::tun::TunWriter;
use crate::inbound::tun::packet;
use crate::inbound::tun::reverse_dns::ReverseDnsCache;
use crate::inbound::tun::reverse_dns::parse_a_records;
use crate::inbound::tun::reverse_dns::parse_aaaa_records;
use crate::outbound::OutboundClient;
use crate::outbound::common::bind_udp_bypass;
use crate::outbound::common::bind_udp_bypass_fallback;
use crate::rules::Rules;

use doh::DohClient;
use upstream::{Upstream, parse_upstream, parse_upstreams_ordered};
use wire::{
    apply_txn_id, build_a_response, build_aaaa_response, build_empty_response,
    build_refused_response, parse_dns_query, txn_id,
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
/// # fakeip_inet6_range = "fdfe:dcba:9876::/64"
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
    /// Fake-IP v4 CIDR, e.g. "198.18.0.0/15". Enabled by default for TUN so
    /// domain information survives IP-only TUN packets. A queries answer
    /// with a v4 fake from this range and AAAA queries with a v6 fake from
    /// the pool set by `fakeip_inet6_range`; both restore the same
    /// domain in the TUN handler.
    /// Set to `false` to disable FakeIP and use real DNS resolution
    /// (redir-host mode: real IP returned, IP→domain mapping still
    /// maintained via reverse cache for rule matching).
    #[serde(default = "default_fakeip", deserialize_with = "de_fakeip")]
    pub fakeip: Option<String>,

    /// Fake-IP v6 pool CIDR for AAAA answers, e.g. "fdfe:dcba:9876::/64".
    /// Default is that same ULA /64 (sing-box's `inet6_range` convention,
    /// kept identical for easier debugging against other fake-ip
    /// implementations). Prefixes from /1 to /126 are accepted; host parts
    /// start at 2 because `::1` within the pool is commonly the TUN's own
    /// v6 address (`tun.addr6 = ...::1`) and must never be handed out.
    /// Only read when `fakeip` is enabled.
    #[serde(default = "default_fakeip_inet6_range")]
    pub fakeip_inet6_range: Option<String>,

    /// FakeIP filter - domains in this list use real DNS instead of FakeIP.
    /// Supports exact domains (`dns.msftnsci.com`) and wildcards
    /// (`+.msftnsci.com` or `*.local`). If empty or omitted, a built-in
    /// default list (Windows connectivity checks) is used.
    #[serde(default)]
    pub fakeip_filter: Option<Vec<String>>,

    /// Static hosts table consulted before rules, cache and upstreams alike.
    /// Keys are domains (case-insensitive, trailing dot tolerated), values
    /// are IPv4 or IPv6 addresses: v4 values answer A queries, v6 values
    /// answer AAAA queries, and a hit on the other family answers empty
    /// NOERROR — that is what keeps the `0.0.0.0` / `::` block semantics
    /// effective on both query types (an upstream lookup would leak a real
    /// address of the other family).
    /// Example: `hosts = { "nas.lan" = "192.168.50.10", "ads.x.com" =
    /// "0.0.0.0", "v6.nas.lan" = "fd00::10" }`
    #[serde(default)]
    pub hosts: Option<HashMap<String, String>>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            direct: default_direct(),
            remote: default_remote(),
            fakeip: default_fakeip(),
            fakeip_inet6_range: default_fakeip_inet6_range(),
            fakeip_filter: None,
            hosts: None,
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
/// Default fake-ip v6 pool: a fixed ULA /64 (sing-box's `inet6_range`
/// default, kept identical for easier debugging against other fake-ip
/// implementations).
pub(crate) const DEFAULT_FAKEIP_V6_RANGE: &str = "fdfe:dcba:9876::/64";

fn default_fakeip_inet6_range() -> Option<String> {
    Some(DEFAULT_FAKEIP_V6_RANGE.to_string())
}

/// Deserialize fakeip field: accept a CIDR string (enabled), `false`
/// (disabled → redir-host mode), or omit for the default CIDR.
fn de_fakeip<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FakeipValue {
        Bool(bool),
        Str(String),
    }
    match FakeipValue::deserialize(deserializer)? {
        FakeipValue::Bool(false) => Ok(None),
        FakeipValue::Bool(true) => Ok(default_fakeip()),
        FakeipValue::Str(s) => Ok(Some(s)),
    }
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

/// Zero out everything past the first `prefix` bits of `ip`. The fake-ip v6
/// pool compares addresses prefix-masked so any configured CIDR
/// (`fakeip_inet6_range`) works, not just the default /64.
fn masked_v6(ip: std::net::Ipv6Addr, prefix: u8) -> std::net::Ipv6Addr {
    let mut o = ip.octets();
    for (i, b) in o.iter_mut().enumerate() {
        let bit_start = (i as u16) * 8;
        if bit_start >= prefix as u16 {
            *b = 0;
        } else if bit_start + 8 > prefix as u16 {
            let keep = prefix as u16 - bit_start; // 1..7
            *b &= !((0xffu16 >> keep) as u8);
        }
    }
    std::net::Ipv6Addr::from(o)
}

/// One domain's fake-ip addresses: A queries answer `v4`, AAAA queries
/// answer `v6`, and the TUN handler restores both to the same domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeIpPair {
    v4: std::net::Ipv4Addr,
    v6: std::net::Ipv6Addr,
}

#[derive(Clone)]
struct FakeIpPool {
    base: u32,
    size: u32,
    /// v6 pool network address, masked to `v6_prefix` (parsed from
    /// `fakeip_inet6_range`, default `fdfe:dcba:9876::/64`).
    v6_net: std::net::Ipv6Addr,
    v6_prefix: u8,
    /// Size of the v6 host space when it fits in the u64 counter
    /// (prefix > 64); `None` means prefix <= 64 and the counter wraps
    /// naturally at 2^64 like the v4 pool does.
    v6_host_space: Option<u64>,
    next: Arc<std::sync::atomic::AtomicU32>,
    /// Host-part counter for the v6 pool (host bits are the low 64).
    v6_next: Arc<std::sync::atomic::AtomicU64>,
    /// Domain → allocated address pair, so repeated queries for the same
    /// domain return the same FakeIPs instead of burning new addresses.
    domain_map: Arc<tokio::sync::Mutex<lru::LruCache<String, FakeIpPair>>>,
}

/// Parse the fake-ip v6 pool CIDR. Returns the network address masked to the
/// prefix, the prefix, and the bounded host-space size (`None` when the host
/// space is ≥ 2^64, i.e. prefix <= 64). Prefixes above /126 are rejected:
/// host parts start at 2 (skipping `::1`, commonly the TUN's own alias), so
/// at least 4 host addresses must exist.
fn parse_v6_pool(cidr: &str) -> Result<(std::net::Ipv6Addr, u8, Option<u64>), String> {
    let (ip_s, prefix_s) = cidr
        .split_once('/')
        .ok_or_else(|| format!("invalid fakeip_inet6_range CIDR '{cidr}'"))?;
    let ip: std::net::Ipv6Addr = ip_s
        .trim()
        .parse()
        .map_err(|e| format!("invalid fakeip_inet6_range address: {e}"))?;
    let prefix: u8 = prefix_s
        .trim()
        .parse()
        .map_err(|e| format!("invalid fakeip_inet6_range prefix: {e}"))?;
    if prefix > 126 {
        return Err(
            "fakeip_inet6_range too small (need at least 4 host addresses)"
                .to_string(),
        );
    }
    let host_bits = 128u16 - u16::from(prefix);
    let host_space =
        if host_bits >= 64 { None } else { Some(1u64 << host_bits) };
    Ok((masked_v6(ip, prefix), prefix, host_space))
}

impl FakeIpPool {
    fn parse(v4_cidr: &str, v6_cidr: &str) -> Result<Self, String> {
        let (ip, prefix) = v4_cidr
            .split_once('/')
            .ok_or_else(|| format!("invalid fakeip CIDR '{v4_cidr}'"))?;
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
        let (v6_net, v6_prefix, v6_host_space) = parse_v6_pool(v6_cidr)?;
        Ok(Self {
            base: u32::from(ip),
            size,
            v6_net,
            v6_prefix,
            v6_host_space,
            next: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            v6_next: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            domain_map: Arc::new(tokio::sync::Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(4096).unwrap(),
            ))),
        })
    }

    /// True when `ip` falls within this pool's v4 CIDR range.
    fn contains_v4(&self, ip: std::net::Ipv4Addr) -> bool {
        let v = u32::from(ip);
        v >= self.base && v < self.base + self.size
    }

    /// True when `ip` falls within the configured v6 pool (prefix-masked
    /// comparison against the pool network).
    fn contains_v6(&self, ip: std::net::Ipv6Addr) -> bool {
        masked_v6(ip, self.v6_prefix).octets() == self.v6_net.octets()
    }

    /// Allocate the fake-ip pair for `domain`. If the domain already has a
    /// pair allocated, return the existing one (deduplication), so the A and
    /// AAAA answers for a domain always point at the same name in the TUN
    /// restore path.
    ///
    /// v6 host parts start at 2: the first address of the pool is commonly
    /// used as the TUN interface's own v6 address (`tun.addr6 = ...::1`), and
    /// a fake-ip equal to the TUN address would be dropped by the handler's
    /// re-injection guard instead of being proxied.
    async fn allocate(&self, domain: &str) -> FakeIpPair {
        // Check existing mapping first.
        if let Some(pair) = self.domain_map.lock().await.get(domain).copied() {
            return pair;
        }
        // Allocate new addresses (both families together — AAAA often
        // arrives first under Happy Eyeballs, and the unused v4 half is
        // harmless).
        let n = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let host = 1 + (n % (self.size - 2));
        let v4 = std::net::Ipv4Addr::from(self.base + host);
        let n6 =
            self.v6_next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let host6 = match self.v6_host_space {
            // Bounded host space (prefix > 64): wrap inside it, still
            // starting at 2 so the pool's ::1 stays reserved for the TUN.
            Some(space) => 2 + (n6 % (space - 2)),
            // Prefix <= 64: the counter itself is the host part and wraps
            // naturally at 2^64.
            None => 2u64.wrapping_add(n6),
        };
        let mut octets = self.v6_net.octets();
        octets[8..].copy_from_slice(&host6.to_be_bytes());
        let v6 = std::net::Ipv6Addr::from(octets);
        let pair = FakeIpPair { v4, v6 };
        self.domain_map.lock().await.put(domain.to_string(), pair);
        pair
    }
}

/// Per-DNS-resolution context: which outbound to dispatch through, and the
/// ordered list of upstreams to try (DoH first, then plain UDP).
struct Plan {
    outbound_tag: String,
    upstreams: Vec<Upstream>,
}

/// The response for a reject-tagged plan: NOERROR with zero answers, or
/// `None` when the tag isn't a reject tag and resolution should continue.
///
/// `reject` is a pseudo-tag with no registered outbound, so the registry
/// lookup in `resolve_query` can never serve it; answering REFUSED instead
/// makes resolvers retry the same query.
fn reject_plan_response(outbound_tag: &str, query: &[u8]) -> Option<Vec<u8>> {
    crate::runner::is_reject_tag(outbound_tag)
        .then(|| build_empty_response(query))
        .flatten()
}

/// What the static hosts table answers for a query.
#[derive(Debug, PartialEq, Eq)]
enum HostsAnswer {
    /// Answer A with the configured v4 value (`0.0.0.0` included — an
    /// unroutable answer is the block semantics).
    V4(std::net::Ipv4Addr),
    /// Answer AAAA with the configured v6 value (`::` included — same
    /// unroutable block semantics as `0.0.0.0` on the v4 side).
    V6(std::net::Ipv6Addr),
    /// The name has a hosts entry but it is pinned to the other address
    /// family: answer NOERROR with zero answers instead of resolving
    /// upstream — an upstream lookup would hand back a real address of
    /// the other family and bypass a `0.0.0.0`/`::` block entry.
    Empty,
}

/// Family-aware static hosts lookup: a v4 value answers A, a v6 value
/// answers AAAA, and a hit on the opposite family is answered empty
/// ([`HostsAnswer::Empty`]). Case-insensitive; trailing dots in the query
/// name (`"example.com."`) are tolerated. `None` when the name is not in
/// the table or the qtype is neither A nor AAAA (other qtypes fall through
/// to normal resolution).
fn hosts_lookup(
    hosts: Option<&HashMap<String, std::net::IpAddr>>, name: &str,
    qtype: u16,
) -> Option<HostsAnswer> {
    let hosts = hosts?;
    let key = name.trim_end_matches('.').to_ascii_lowercase();
    let ip = hosts.get(&key)?;
    match (qtype, ip) {
        (1, std::net::IpAddr::V4(v4)) => Some(HostsAnswer::V4(*v4)),
        (28, std::net::IpAddr::V6(v6)) => Some(HostsAnswer::V6(*v6)),
        // Hit on the other family: the entry is the complete answer set
        // for the name, so never fall through to upstream.
        (1, std::net::IpAddr::V6(_)) | (28, std::net::IpAddr::V4(_)) => {
            Some(HostsAnswer::Empty)
        },
        _ => None,
    }
}

/// Normalize a configured hosts table: lowercase keys, parse values to IPs.
/// Both families are kept — v4 values answer A, v6 values answer AAAA
/// (`0.0.0.0`/`::` keep their unroutable block semantics). Invalid values
/// are skipped with a warning; an all-invalid table yields an empty map.
fn parse_hosts_table(
    map: &HashMap<String, String>,
) -> HashMap<String, std::net::IpAddr> {
    let mut out: HashMap<String, std::net::IpAddr> = HashMap::new();
    for (name, value) in map {
        let key = name.trim().trim_end_matches('.').to_ascii_lowercase();
        match value.trim().parse::<std::net::IpAddr>() {
            Ok(ip) => {
                out.insert(key, ip);
            },
            Err(_) => {
                log::warn!("DNS hosts: {key} → {value} ignored (invalid IP)");
            },
        }
    }
    out
}

/// True for an HTTPS/SVCB (type 65) query on a proxy plan: the record only
/// exists upstream, and proxy outbounds refuse UDP relay (`dial_udp` →
/// ERR_UDP_NOT_SUPPORTED), so the attempt can never succeed and answering
/// REFUSED only makes resolvers retry. Direct plans do get the record, over
/// DoH.
fn proxy_plan_cannot_answer_svcb(qtype: u16, outbound_tag: &str) -> bool {
    qtype == 65 && outbound_tag != "direct"
}

/// qtypes that get a fake-ip answer on a non-direct plan: A (1) answers
/// with a v4 fake from the configured CIDR, AAAA (28) with a v6 fake from
/// the fixed ULA pool — the two addresses restore the same domain in the
/// TUN handler, so Happy Eyeballs can pick either family and the connection
/// still reaches the proxy. Every other qtype falls through to the normal
/// upstream chain.
fn fakeip_answerable_qtype(qtype: u16) -> bool {
    qtype == 1 || qtype == 28
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
    /// FakeIP domain filter - matched domains use real DNS instead of FakeIP.
    fakeip_filter: Option<crate::dns::fakeip_filter::FakeIPFilter>,
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
    /// Cancellation token shared with the TUN inbound. When cancelled, the
    /// loopback listener and all in-flight query tasks exit promptly so the
    /// `Arc<AsyncDevice>` (held via `writer`) is released before the next
    /// `run()` iteration recreates the TUN device.
    pub(crate) shutdown: CancellationToken,
    /// Static hosts table (normalized lowercase keys → parsed IP). `None`
    /// when unset or every entry was invalid. Consulted before rules, cache
    /// and upstreams.
    hosts: Option<HashMap<String, std::net::IpAddr>>,
}

impl DnsHijack {
    /// Returns true if `ip` is a FakeIP address: within the configured v4
    /// CIDR, or within the configured v6 pool
    /// (`fakeip_inet6_range`, default `fdfe:dcba:9876::/64`).
    pub fn fakeip_contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                self.fakeip.as_ref().is_some_and(|p| p.contains_v4(v4))
            },
            IpAddr::V6(v6) => {
                self.fakeip.as_ref().is_some_and(|p| p.contains_v6(v6))
            },
        }
    }

    pub fn new(
        config: &DnsConfig, local_direct: bool, rules: Arc<Rules>,
        registry: Arc<HashMap<String, Arc<dyn OutboundClient>>>,
        writer: TunWriter, reverse_cache: Arc<ReverseDnsCache>,
        shutdown: CancellationToken,
    ) -> Result<Self, String> {
        // Bootstrap rule shared with the ECH config lookup
        // (dns::https_record::with_plain_bootstrap): DoH needs a plain UDP
        // resolver for its own hostname, and the same address doubles as the
        // plain fallback when DoH fails or is disabled.
        let direct_upstreams = crate::dns::https_record::with_plain_bootstrap(
            parse_upstreams_ordered(&config.direct)?,
        );

        // remote group: resolution happens EXCLUSIVELY at the proxy server
        // side — queries ride the tunnel and are forwarded as plain UDP to
        // the upstream (8.8.8.8 etc.). The tunnel TLS already encrypts the
        // query path, so DoH/DoT on this hop would protect nothing; DoH
        // entries configured in `remote` are dropped.
        let mut remote_upstreams = parse_upstreams_ordered(&config.remote)?;
        let remote_doh_count =
            remote_upstreams.iter().filter(|u| u.is_doh()).count();
        if remote_doh_count > 0 {
            log::info!(
                "DNS: {remote_doh_count} DoH upstream(s) in `remote` ignored \
                 — remote domains resolve at the proxy side via tunnel UDP"
            );
            remote_upstreams.retain(|u| !u.is_doh());
        }
        if remote_upstreams.is_empty() {
            log::info!(
                "DNS: `remote` has no plain upstream; remote domains will be\
                 \n resolved at the proxy side via tunnel UDP (default 8.8.8.8)"
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
            Some(cidr) => {
                let v6_range = config
                    .fakeip_inet6_range
                    .as_deref()
                    .unwrap_or(DEFAULT_FAKEIP_V6_RANGE);
                Some(FakeIpPool::parse(cidr, v6_range)?)
            },
            None => None,
        };

        let fakeip_filter = match config
            .fakeip_filter
            .as_deref()
            .filter(|l| !l.is_empty())
        {
            Some(list) => {
                Some(crate::dns::fakeip_filter::FakeIPFilter::from_list(list))
            },
            None => {
                Some(crate::dns::fakeip_filter::FakeIPFilter::default_filter())
            },
        };

        // Static hosts table: normalize keys to lowercase (DNS names are
        // case-insensitive) and parse values to IPs. Both families are
        // kept (v4 answers A, v6 answers AAAA); invalid values are skipped
        // with a warning.
        let hosts = config
            .hosts
            .as_ref()
            .map(parse_hosts_table)
            .filter(|h| !h.is_empty());

        Ok(Self {
            remote_upstreams,
            direct_doh_upstreams,
            direct_plain,
            doh,
            fakeip,
            fakeip_filter,
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
            shutdown,
            hosts,
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
                log::debug!(
                    "DNS handle_query: resolved {} bytes, sending via TUN to {src_ip}:{src_port}",
                    response.len()
                );
                let _ = self
                    .send_response(&response, dst_ip, src_ip, src_port)
                    .await;
                true
            },
            None => {
                log::warn!(
                    "DNS handle_query: resolution failed, sending REFUSED"
                );
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

        log::debug!(
            "DNS resolve: name={} qtype={} src={}",
            q.name,
            q.qtype,
            src_ip
        );

        // Static hosts table wins over fake-ip mode, local-direct mode,
        // rules, cache and upstreams alike (its whole point is to override
        // resolution). A v4 value answers A, a v6 value answers AAAA, and
        // a hit on the other family answers empty so a `0.0.0.0`/`::`
        // block entry can't leak a real address from upstream.
        match hosts_lookup(self.hosts.as_ref(), &q.name, q.qtype) {
            Some(HostsAnswer::V4(ip)) => {
                self.reverse_cache
                    .insert(IpAddr::V4(ip), q.name.clone())
                    .await;
                log::debug!("DNS: {} (type {}) → hosts {}", q.name, q.qtype, ip);
                return build_a_response(query, ip);
            },
            Some(HostsAnswer::V6(ip)) => {
                // Insert into the reverse cache so v6 TUN packets restore
                // the domain (the map is IpAddr-keyed on both families).
                self.reverse_cache
                    .insert(IpAddr::V6(ip), q.name.clone())
                    .await;
                log::debug!("DNS: {} (type {}) → hosts {}", q.name, q.qtype, ip);
                return build_aaaa_response(query, ip);
            },
            Some(HostsAnswer::Empty) => {
                log::debug!(
                    "DNS: {} (type {}) → hosts {}-only, empty answer",
                    q.name,
                    q.qtype,
                    if q.qtype == 1 { "v6" } else { "v4" }
                );
                return build_empty_response(query);
            },
            None => {},
        }

        // AAAA handling follows the plan: on non-direct plans the fake-ip
        // branch below answers AAAA with a v6 fake (dual-family fake pool);
        // on direct plans and with fake-ip off the query falls through to
        // the normal upstream chain and AAAA records pass through untouched
        // (only `apply_txn_id` rewrites bytes, record-type agnostic).

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
                self.populate_reverse_cache(&cached, &q.name).await;
                return Some(apply_txn_id(&cached, txn_id(query)));
            }
        }

        if let Some(resp) = reject_plan_response(&plan.outbound_tag, query) {
            self.cache
                .lock()
                .await
                .put(cache_key, (Instant::now(), resp.clone()));
            log::debug!("DNS: {} (type {}) → reject", q.name, q.qtype);
            return Some(resp);
        }

        if proxy_plan_cannot_answer_svcb(q.qtype, &plan.outbound_tag)
            && let Some(resp) = build_empty_response(query)
        {
            self.cache
                .lock()
                .await
                .put(cache_key, (Instant::now(), resp.clone()));
            log::debug!(
                "DNS: {} (type 65) → empty (no proxy SVCB)",
                q.name
            );
            return Some(resp);
        }

        if fakeip_answerable_qtype(q.qtype)
            && plan.outbound_tag != "direct"
            && let Some(fakeip) = &self.fakeip
            && !self
                .fakeip_filter
                .as_ref()
                .is_some_and(|f| f.should_skip(&q.name))
        {
            let pair = fakeip.allocate(&q.name).await;
            if let Some(resp) = match q.qtype {
                1 => build_a_response(query, pair.v4),
                _ => build_aaaa_response(query, pair.v6),
            } {
                self.populate_reverse_cache(&resp, &q.name).await;
                self.cache
                    .lock()
                    .await
                    .put(cache_key, (Instant::now(), resp.clone()));
                log::debug!(
                    "DNS: {} (type {}) → fake-ip {}/{} via {}",
                    q.name,
                    q.qtype,
                    pair.v4,
                    pair.v6,
                    plan.outbound_tag
                );
                return Some(resp);
            }
        }

        let client = self.registry.get(&plan.outbound_tag);
        let client = match client {
            Some(c) => c.clone(),
            None => {
                log::warn!(
                    "DNS hijack: outbound '{}' not found",
                    plan.outbound_tag
                );
                return None; // caller sends REFUSED
            },
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
        self.populate_reverse_cache(&response, &q.name).await;

        Some(response)
    }

    /// Populate the reverse cache (IP → domain) from a DNS response's A and
    /// AAAA answers so the TUN handler can restore domains from bare-IP
    /// packets on both families.
    async fn populate_reverse_cache(&self, response: &[u8], domain: &str) {
        for (ip, _record_domain) in parse_a_records(response) {
            self.reverse_cache
                .insert(IpAddr::V4(ip), domain.to_string())
                .await;
        }
        for (ip, _record_domain) in parse_aaaa_records(response) {
            self.reverse_cache
                .insert(IpAddr::V6(ip), domain.to_string())
                .await;
        }
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
        log::debug!("resolve_direct_udp: upstream={addr}");
        let (result, timed_out) =
            self.resolve_direct_udp_attempt(query, addr, true).await;
        if !timed_out {
            return result;
        }

        #[cfg(target_os = "macos")]
        crate::outbound::common::refresh_macos_physical_iface_cache();
        #[cfg(target_os = "macos")]
        crate::inbound::tun::platform::macos::log_network_diagnostics(addr.ip());
        log::info!("resolve_direct_udp: retrying {addr} with a fresh socket");
        let (retry, _) =
            self.resolve_direct_udp_attempt(query, addr, false).await;
        retry
    }

    async fn resolve_direct_udp_attempt(
        &self, query: &[u8], addr: std::net::SocketAddr, use_pool: bool,
    ) -> (Option<Vec<u8>>, bool) {
        let sock = {
            if use_pool {
                let mut pool = self.socket_pool.lock().await;
                pool.pop()
            } else {
                None
            }
        };
        let sock = match sock {
            Some(s) => {
                log::debug!("resolve_direct_udp: reused pooled socket");
                s
            },
            None => {
                let s = match bind_udp_bypass("0.0.0.0:0".parse().unwrap()).await
                {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("resolve_direct_udp: bind failed: {e}");
                        return (None, false);
                    },
                };
                match s.connect(addr).await {
                    Ok(()) => {},
                    Err(e) => {
                        log::warn!(
                            "resolve_direct_udp: connect to {addr} failed: {e}"
                        );
                        return (None, false);
                    },
                }
                log::debug!("resolve_direct_udp: socket connected to {addr}");
                s
            },
        };

        let mut sock = sock;
        match sock.send(query).await {
            Ok(_) => {},
            Err(e) => {
                log::warn!("resolve_direct_udp: send to {addr} failed: {e}");
                self.socket_pool.lock().await.clear();
                #[cfg(target_os = "macos")]
                crate::outbound::common::refresh_macos_physical_iface_cache();
                #[cfg(target_os = "macos")]
                {
                    let destination = addr.ip();
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::inbound::tun::platform::macos::log_network_diagnostics(
                            destination,
                        )
                    })
                    .await;
                }
                sock = {
                    let fresh_socket = match bind_udp_bypass_fallback(
                        "0.0.0.0:0".parse().unwrap(),
                    )
                    .await
                    {
                        Ok(socket) => socket,
                        Err(e) => {
                            log::warn!("resolve_direct_udp: bind failed: {e}");
                            return (None, false);
                        },
                    };
                    match fresh_socket.connect(addr).await {
                        Ok(()) => fresh_socket,
                        Err(e) => {
                            log::warn!(
                                "resolve_direct_udp: connect to {addr} failed: {e}"
                            );
                            return (None, false);
                        },
                    }
                };
                match sock.send(query).await {
                    Ok(_) => {},
                    Err(e) => {
                        log::warn!(
                            "resolve_direct_udp: retry send to {addr} failed: {e}"
                        );
                        return (None, false);
                    },
                }
            },
        }
        log::debug!(
            "resolve_direct_udp: sent {len} bytes to {addr}",
            len = query.len()
        );
        let mut buf = vec![0u8; 4096];
        let mut timed_out = false;
        let result = match timeout(QUERY_TIMEOUT, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                log::debug!("resolve_direct_udp: got {n} bytes from {addr}");
                Some(buf[..n].to_vec())
            },
            Ok(Err(e)) => {
                log::warn!("resolve_direct_udp: recv error from {addr}: {e}");
                None
            },
            Err(_) => {
                log::warn!("resolve_direct_udp: timeout waiting for {addr}");
                timed_out = true;
                None
            },
        };

        if result.is_some() {
            let mut pool = self.socket_pool.lock().await;
            if pool.len() < self.socket_pool_cap {
                pool.push(sock);
            }
        } else {
            self.socket_pool.lock().await.clear();
            #[cfg(target_os = "macos")]
            crate::outbound::common::refresh_macos_physical_iface_cache();
        }
        (result, timed_out)
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
    pub fn start_hijack_listener(self: &Arc<Self>) -> Vec<JoinHandle<()>> {
        let this = self.clone();
        let mut handles = Vec::new();

        // IPv4 listener.
        let this4 = this.clone();
        handles.push(tokio::spawn(async move {
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
        }));

        // Linux: the box's own queries land on 127.0.0.1. The OUTPUT REDIRECT
        // rewrites the destination to 127.0.0.1:1053 (measured: even when the
        // nameserver routes out of another interface), so the reply only
        // matches that conntrack entry, and is only reverse-NAT'ed back to the
        // nameserver the application actually asked, when it is sent from a
        // socket bound to 127.0.0.1. From the wildcard socket the kernel picks
        // the client's own address as source and the resolver drops it. The
        // wildcard socket above still serves PREROUTING-redirected queries
        // from LAN clients, whose redirect target is the interface address.
        #[cfg(target_os = "linux")]
        {
            let this_lo = this.clone();
            handles.push(tokio::spawn(async move {
                let addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    DNS_REDIRECT_PORT,
                );
                Self::run_listener(this_lo, addr).await;
            }));
            // v6 mirror: the ip6tables OUTPUT REDIRECT (only installed for
            // dual-stack tunnels) rewrites local v6 DNS to ::1:1053.
            let this_lo6 = this.clone();
            handles.push(tokio::spawn(async move {
                let addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                    DNS_REDIRECT_PORT,
                );
                Self::run_listener(this_lo6, addr).await;
            }));
        }

        // IPv6 listener (macOS only - pf `rdr inet6` redirects to ::1:1053).
        // Without this, IPv6 DNS queries are redirected to ::1:1053 where
        // nobody listens, causing DNS failure for systems using IPv6 DNS.
        #[cfg(target_os = "macos")]
        {
            let this6 = this.clone();
            handles.push(tokio::spawn(async move {
                let addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                    DNS_REDIRECT_PORT,
                );
                Self::run_listener(this6, addr).await;
            }));
        }
        handles
    }

    /// Run a DNS loopback listener on the given address.
    async fn run_listener(this: Arc<Self>, addr: std::net::SocketAddr) {
        let socket = match {
            #[cfg(target_os = "macos")]
            {
                UdpSocket::bind(addr).await
            }
            #[cfg(not(target_os = "macos"))]
            {
                bind_udp_bypass(addr).await
            }
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
            let (n, src) = tokio::select! {
                _ = this.shutdown.cancelled() => break,
                res = socket.recv_from(&mut buf) => match res {
                    Ok(x) => x,
                    Err(e) => {
                        log::warn!("DNS loopback recv: {e}");
                        break;
                    },
                },
            };
            let query = buf[..n].to_vec();
            log::debug!("DNS listener: received {n} bytes from {src}");
            let this = this.clone();
            let sock = socket.clone();
            tokio::spawn(async move {
                // Exit promptly on shutdown so the `Arc<DnsHijack>` (and the
                // `TunWriter` -> `Arc<AsyncDevice>` it owns) is released.
                tokio::select! {
                    _ = this.shutdown.cancelled() => {},
                    _ = async {
                        let response = this
                            .resolve_query(&query, src.ip())
                            .await
                            .or_else(|| build_refused_response(&query));
                        if let Some(r) = response {
                            log::debug!("DNS listener: sending {} bytes to {src}", r.len());
                            let _ = sock.send_to(&r, src).await;
                        } else {
                            log::warn!("DNS listener: no response for {src}");
                        }
                    } => {},
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
        let qinfo = parse_dns_query(query)
            .map(|q| (q.name, q.qtype))
            .unwrap_or_default();
        let qname = qinfo.0.as_str();
        let qtype = qinfo.1;
        let is_direct = plan.outbound_tag == "direct";

        // --- DoH phase: direct domains only ---
        if is_direct && !self.direct_doh_upstreams.is_empty() {
            let idx = nanos_random(self.direct_doh_upstreams.len());
            let up = &self.direct_doh_upstreams[idx];
            let host = match up {
                Upstream::Doh { host, .. } => host.as_str(),
                _ => "",
            };
            if let Some(resp) = self.doh.resolve(query, up).await {
                log::debug!("DNS: {qname} (type {qtype}) -> DoH({host}) OK");
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
                    if let Some(resp) = self.resolve_direct_udp(query, dest).await
                    {
                        log::debug!("DNS: {qname} (type {qtype}) -> UDP({d}) OK");
                        return Some(resp);
                    }
                }
            }
        } else {
            // Remote: random proxy UDP relay.
            let plain: Vec<_> = plan
                .upstreams
                .iter()
                .filter_map(|u| match u {
                    Upstream::Plain(d) => Some(d),
                    _ => None,
                })
                .collect();
            if !plain.is_empty() && client.is_some() {
                let idx = nanos_random(plain.len());
                let dest = plain[idx];
                let d = dest.to_string();
                let tag = plan.outbound_tag.clone();
                if let Some(c) = client
                    && let Some(resp) =
                        self.resolve_via_outbound(query, dest, c).await
                    {
                        log::debug!(
                            "DNS: {qname} (type {qtype}) -> via {tag}({d}) OK"
                        );
                        return Some(resp);
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
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                packet::build_udp_response_ipv4(s, 53, d, dst_port, payload)
            },
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                packet::build_udp_response_ipv6(s, 53, d, dst_port, payload)
            },
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "mismatched IP versions",
                ));
            },
        };
        log::debug!(
            "DNS send_response: {} bytes, src={}:53 dst={}:{} via TUN writer",
            raw.len(),
            src_ip,
            dst_ip,
            dst_port
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
    fn hosts_table_parses_and_looks_up_case_insensitively() {
        let toml = r#"
            direct = ["223.5.5.5"]
            remote = ["8.8.8.8"]
            hosts = { "nas.lan" = "192.168.50.10", "ads.x.com" = "0.0.0.0", "v6.x.com" = "::1", "bad.x.com" = "not-an-ip" }
        "#;
        let cfg: DnsConfig = toml::from_str(toml).unwrap();
        let hosts = cfg.hosts.expect("hosts table must parse");

        // Normalization: lowercase keys, parsed IPs (both families kept),
        // invalid values dropped.
        let parsed = parse_hosts_table(&hosts);
        assert_eq!(parsed.len(), 3, "invalid entries must be dropped");

        // Exact hit, case-insensitive, trailing dot tolerated.
        assert_eq!(
            hosts_lookup(Some(&parsed), "NAS.LAN", 1),
            Some(HostsAnswer::V4(std::net::Ipv4Addr::new(192, 168, 50, 10)))
        );
        assert_eq!(
            hosts_lookup(Some(&parsed), "ads.x.com.", 1),
            Some(HostsAnswer::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)))
        );
        assert!(hosts_lookup(Some(&parsed), "other.lan", 1).is_none());
        assert!(hosts_lookup(None, "nas.lan", 1).is_none());
    }

    #[test]
    fn hosts_lookup_serves_both_families() {
        let mut table = HashMap::new();
        for (name, value) in [
            ("v4.lan", "192.168.50.10"),
            ("v6.lan", "fd00:1986::10"),
            ("block4.lan", "0.0.0.0"),
            ("block6.lan", "::"),
        ] {
            table.insert(name.to_string(), value.parse::<IpAddr>().unwrap());
        }

        // v4 value answers A, v6 value answers AAAA; `0.0.0.0`/`::` keep
        // their unroutable block semantics on their own family.
        assert_eq!(
            hosts_lookup(Some(&table), "v4.lan", 1),
            Some(HostsAnswer::V4(std::net::Ipv4Addr::new(192, 168, 50, 10)))
        );
        assert_eq!(
            hosts_lookup(Some(&table), "v6.lan", 28),
            Some(HostsAnswer::V6(
                "fd00:1986::10".parse::<std::net::Ipv6Addr>().unwrap()
            ))
        );
        assert_eq!(
            hosts_lookup(Some(&table), "block4.lan", 1),
            Some(HostsAnswer::V4(std::net::Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            hosts_lookup(Some(&table), "block6.lan", 28),
            Some(HostsAnswer::V6(std::net::Ipv6Addr::UNSPECIFIED))
        );

        // A hit on the other family answers empty instead of resolving
        // upstream — otherwise a block entry would leak a real address of
        // the other family.
        assert_eq!(
            hosts_lookup(Some(&table), "v4.lan", 28),
            Some(HostsAnswer::Empty)
        );
        assert_eq!(
            hosts_lookup(Some(&table), "v6.lan", 1),
            Some(HostsAnswer::Empty)
        );

        // Non-address qtypes never get a hosts answer.
        assert!(hosts_lookup(Some(&table), "v4.lan", 65).is_none());
    }

    #[test]
    fn fakeip_answers_only_address_family_qtypes() {
        // Non-direct plans answer A with a v4 fake and AAAA with a v6 fake;
        // every other qtype (SVCB, TXT, …) keeps its upstream path.
        assert!(fakeip_answerable_qtype(1));
        assert!(fakeip_answerable_qtype(28));
        for qtype in [0u16, 2, 5, 12, 16, 65] {
            assert!(
                !fakeip_answerable_qtype(qtype),
                "qtype={qtype} must not be fake-answered"
            );
        }
    }

    #[tokio::test]
    async fn fakeip_pool_allocates_stable_dual_family_pairs() {
        let pool =
            FakeIpPool::parse("198.18.0.0/15", DEFAULT_FAKEIP_V6_RANGE).unwrap();

        let first = pool.allocate("example.com").await;
        let again = pool.allocate("example.com").await;
        assert_eq!(first, again, "same domain must dedup to the same pair");

        let other = pool.allocate("other.com").await;
        assert_ne!(first.v4, other.v4);
        assert_ne!(first.v6, other.v6);

        // First allocations: the v4 counter starts at 1 so host = base + 2
        // (198.18.0.2 — base+1 was the historic first skip), and the v6 host
        // parts start at 2 (::1 is commonly the TUN's own alias in the same
        // /64 and must never be handed out).
        assert_eq!(first.v4, std::net::Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(
            first.v6,
            "fdfe:dcba:9876::2".parse::<std::net::Ipv6Addr>().unwrap()
        );

        // Both allocated addresses are recognized as fake-ips.
        assert!(pool.contains_v4(first.v4));
        assert!(pool.contains_v4(other.v4));
        assert!(pool.contains_v6(first.v6));
        assert!(pool.contains_v6(other.v6));

        // Foreign addresses are not fake-ips: a random v4 outside the CIDR
        // and a global v6 outside the ULA /64 (plus the pool's own net and
        // the ::1 edge case).
        assert!(!pool.contains_v4(std::net::Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!pool.contains_v4(std::net::Ipv4Addr::new(198, 20, 0, 1)));
        assert!(!pool.contains_v6("2001:4860:4860::8888".parse().unwrap()));
        assert!(!pool.contains_v6(std::net::Ipv6Addr::UNSPECIFIED));
        assert_ne!(first.v6, std::net::Ipv6Addr::LOCALHOST);
    }

    #[tokio::test]
    async fn fakeip_pool_wraps_within_range_when_exhausted() {
        // A tiny pool forces the modulo wrap so every allocated v4 stays in
        // range and every v6 stays inside the /64.
        let pool =
            FakeIpPool::parse("198.18.0.0/30", DEFAULT_FAKEIP_V6_RANGE).unwrap();
        let mut v6_seen = std::collections::HashSet::new();
        for i in 0..100u64 {
            let pair = pool.allocate(&format!("d{i}.test")).await;
            assert!(pool.contains_v4(pair.v4));
            assert!(pool.contains_v6(pair.v6));
            assert!(v6_seen.insert(pair.v6), "v6 counter must not repeat early");
        }
    }

    #[test]
    fn fakeip_inet6_range_config_defaults_and_parses() {
        // Default: the fixed ULA /64, present even when the key is omitted.
        let cfg: DnsConfig = toml::from_str("fakeip = \"198.18.0.0/15\"").unwrap();
        assert_eq!(
            cfg.fakeip_inet6_range.as_deref(),
            Some(DEFAULT_FAKEIP_V6_RANGE)
        );

        // Custom range overrides it; a /64-less value is rejected at parse.
        let cfg: DnsConfig = toml::from_str(
            "fakeip = \"198.18.0.0/15\"\nfakeip_inet6_range = \"fd00:1986::/48\"",
        )
        .unwrap();
        assert_eq!(
            cfg.fakeip_inet6_range.as_deref(),
            Some("fd00:1986::/48")
        );
    }

    #[tokio::test]
    async fn fakeip_pool_uses_configured_v6_range() {
        let pool = FakeIpPool::parse("198.18.0.0/15", "fd00:1986::/64").unwrap();

        let pair = pool.allocate("example.com").await;
        assert_eq!(
            pair.v6,
            "fd00:1986::2".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert!(pool.contains_v6(pair.v6));
        assert!(pool.contains_v6("fd00:1986::dead".parse().unwrap()));

        // Everything outside the configured /64 is not a fake-ip — including
        // the previous hardcoded ULA pool and the global range.
        assert!(!pool.contains_v6("fdfe:dcba:9876::2".parse().unwrap()));
        assert!(!pool.contains_v6("2001:4860:4860::8888".parse().unwrap()));
    }

    #[tokio::test]
    async fn fakeip_pool_v6_narrow_prefix_stays_in_range() {
        // A /112 has a 16-bit host space: allocations must wrap within it
        // and the prefix-masked contains() must match every allocated host.
        let pool = FakeIpPool::parse("198.18.0.0/15", "fd00:1986::/112").unwrap();
        for i in 0..1000u64 {
            let pair = pool.allocate(&format!("d{i}.test")).await;
            assert!(pool.contains_v6(pair.v6));
            let host = u64::from_be_bytes(pair.v6.octets()[8..16].try_into().unwrap());
            assert!(host >= 2 && host < 0x10000, "host {host} outside /112");
        }
    }

    #[tokio::test]
    async fn fakeip_pool_v6_accepts_unmasked_network_address() {
        // Configuring the pool with a host address inside the /64 (e.g. the
        // same ::1 the TUN uses) must behave as the masked network.
        let pool =
            FakeIpPool::parse("198.18.0.0/15", "fdfe:dcba:9876::1/64").unwrap();
        let pair = pool.allocate("example.com").await;
        assert_eq!(
            pair.v6,
            "fdfe:dcba:9876::2".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert!(pool.contains_v6("fdfe:dcba:9876::ffff".parse().unwrap()));
        assert!(!pool.contains_v6("fdfe:dcba:9877::1".parse().unwrap()));
    }

    #[test]
    fn fakeip_pool_v6_rejects_prefixes_without_host_space() {
        // /127 and /128 cannot skip the reserved ::1 host part.
        assert!(FakeIpPool::parse("198.18.0.0/15", "fd00::/127").is_err());
        assert!(FakeIpPool::parse("198.18.0.0/15", "fd00::1/128").is_err());
        // Missing CIDR suffix and garbage are rejected too.
        assert!(FakeIpPool::parse("198.18.0.0/15", "fd00::").is_err());
        assert!(FakeIpPool::parse("198.18.0.0/15", "nonsense/64").is_err());
    }

    #[test]
    fn hosts_answer_wire_format_resolves_query_name() {
        let query = wire::build_dns_query("nas.lan", 1);
        let resp = build_a_response(&query, std::net::Ipv4Addr::new(192, 168, 50, 10))
            .expect("A response must build");
        let ips: Vec<std::net::Ipv4Addr> =
            parse_a_records(&resp).into_iter().map(|(ip, _)| ip).collect();
        assert_eq!(ips, vec![std::net::Ipv4Addr::new(192, 168, 50, 10)]);
    }

    #[test]
    fn hosts_aaaa_answer_wire_format_resolves_query_name() {
        let query = wire::build_dns_query("v6.lan", 28);
        let ip = std::net::Ipv6Addr::new(0xfd00, 0x1986, 0, 0, 0, 0, 0, 10);
        let resp =
            build_aaaa_response(&query, ip).expect("AAAA response must build");

        // Question section echoed (txn id and question bytes); the single
        // answer carries TYPE=28, RDLENGTH=16 and the configured address.
        assert_eq!(&resp[..2], &query[..2]);
        assert_eq!(&resp[12..query.len()], &query[12..]);
        let answer = &resp[query.len()..];
        assert_eq!(
            &answer[..2], &[0xC0, 0x0C],
            "answer name must be a pointer"
        );
        assert_eq!(&answer[2..4], &[0x00, 0x1C], "TYPE must be AAAA (28)");
        assert_eq!(&answer[10..12], &[0x00, 0x10], "RDLENGTH must be 16");
        assert_eq!(&answer[12..28], &ip.octets());
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
    fn dns_config_fakeip_disabled() {
        let toml = r#"
            fakeip = false
        "#;
        let cfg: DnsConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.fakeip, None);
    }

    #[test]
    fn dns_config_fakeip_enabled_shorthand() {
        let toml = r#"
            fakeip = true
        "#;
        let cfg: DnsConfig = toml::from_str(toml).unwrap();
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

    #[test]
    fn reject_plan_answers_noerror_with_zero_answers() {
        let query = wire::build_dns_query("ads.example.com", 1);

        let resp = reject_plan_response("reject", &query).expect("reject must be answered");
        assert_eq!(resp[2] & 0x80, 0x80, "QR must be set");
        assert_eq!(resp[3] & 0x0f, 0, "RCODE must be NOERROR");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "ANCOUNT must be 0");

        // Any other tag goes through the normal resolution path.
        for tag in ["direct", "remote", "reject "] {
            assert!(reject_plan_response(tag, &query).is_none());
        }
    }

    #[test]
    fn proxy_plan_svcb_queries_are_answered_empty() {
        assert!(proxy_plan_cannot_answer_svcb(65, "remote"));
        // Only the literal "direct" tag is exempt, so a near-miss tag is
        // still a proxy plan — same exact compare as the fake-ip branch.
        assert!(proxy_plan_cannot_answer_svcb(65, "direct "));
        assert!(proxy_plan_cannot_answer_svcb(65, "direct-auto"));

        // Direct plans resolve type 65 over DoH, and every other qtype keeps
        // its existing path.
        for (qtype, tag) in [
            (65u16, "direct"),
            (1, "remote"),
            (28, "remote"),
            (64, "remote"),
            (66, "remote"),
        ] {
            assert!(
                !proxy_plan_cannot_answer_svcb(qtype, tag),
                "qtype={qtype} tag={tag:?}"
            );
        }
    }
}
