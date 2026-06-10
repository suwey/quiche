//! DNS hijack module.
//!
//! Intercepts UDP/53 at the TUN inbound, parses the query domain, runs it
//! through the rule engine, and forwards to either the `direct` upstream
//! (default 223.5.5.5) or the `remote` upstream (default 8.8.8.8). AAAA
//! queries are short-circuited to an empty NOERROR response (no IPv6
//! support end-to-end yet). Responses are cached in a small LRU keyed by
//! `{domain}/{qtype}`.

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

const CACHE_CAPACITY: usize = 1024;
const CACHE_TTL: Duration = Duration::from_secs(300);
/// Cap concurrent in-flight DNS resolutions. Each one holds an outbound
/// UDP socket until the response arrives; without a cap, a burst of
/// reverse lookups can exhaust the process fd budget.
const MAX_INFLIGHT: usize = 32;
/// Per-query upstream timeout. Misbehaving upstreams shouldn't pin fds.
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
/// Port for the DNS loopback listener. iptables REDIRECT forwards 53 → this
/// so dnsmasq (which may also serve DHCP) is never touched.
pub const DNS_REDIRECT_PORT: u16 = 1053;
/// `[dns]` config section.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_direct")]
    pub direct: String,
    #[serde(default = "default_remote")]
    pub remote: String,
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

fn default_direct() -> String {
    "223.5.5.5".to_string()
}
fn default_remote() -> String {
    "8.8.8.8".to_string()
}
fn default_fakeip() -> Option<String> {
    Some("198.18.0.0/15".to_string())
}

#[derive(Clone)]
struct FakeIpPool {
    base: u32,
    size: u32,
    next: Arc<std::sync::atomic::AtomicU32>,
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
        })
    }

    fn next_ip(&self) -> std::net::Ipv4Addr {
        let n = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let host = 1 + (n % (self.size - 2));
        std::net::Ipv4Addr::from(self.base + host)
    }
}

/// Per-DNS-resolution context: which outbound to dispatch through, which
/// upstream DNS to send the query to.
struct Plan {
    outbound_tag: String,
    upstream: Destination,
}

/// DNS hijack handler. One instance per TUN inbound, shared by reference.
pub struct DnsHijack {
    direct_upstream: Destination,
    remote_upstream: Destination,
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
}

impl DnsHijack {
    pub fn new(
        config: &DnsConfig, local_direct: bool, rules: Arc<Rules>,
        registry: Arc<HashMap<String, Arc<dyn OutboundClient>>>,
        writer: TunWriter, reverse_cache: Arc<ReverseDnsCache>,
    ) -> Result<Self, String> {
        let direct_upstream = parse_upstream(&config.direct)?;
        let remote_upstream = parse_upstream(&config.remote)?;
        let fakeip = match &config.fakeip {
            Some(cidr) => Some(FakeIpPool::parse(cidr)?),
            None => None,
        };
        Ok(Self {
            direct_upstream,
            remote_upstream,
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
                let _ = self
                    .send_response(&response, dst_ip, src_ip, src_port)
                    .await;
                true
            },
            None => {
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
        let Some(q) = parse_dns_query(query) else {
            return None;
        };

        // AAAA → empty answer (no v6 end-to-end yet).
        if q.qtype == 28 {
            return build_empty_response(query);
        }

        let cache_key_base = format!("{}/{}", q.name, q.qtype);

        // Local-direct mode: queries from the router itself (127.0.0.1)
        // skip rule matching and go directly to the direct upstream.
        // This avoids slow proxy DNS for the device's own queries and
        // prevents the proxy from being blocked waiting on its own DNS.
        if self.local_direct && src_ip.is_loopback() {
            let plan = self.plan_for("direct".to_string());
            return self.resolve_direct(query, &plan.upstream).await;
        }
        // Match rule on (domain, udp, port 53) to pick outbound + upstream.
        let dest = Destination::new(Address::Domain(q.name.clone()), 53);
        let rule_match = self.rules.match_conn(&dest, Network::Udp);
        let plan = match rule_match {
            Some(m) => self.plan_for(m.outbound_tag),
            None => self.plan_for("direct".to_string()),
        };

        let cache_key = format!("{}/{}", cache_key_base, plan.outbound_tag);
        {
            let mut guard = self.cache.lock().await;
            if let Some((ts, cached)) = guard.get(&cache_key).cloned() {
                if ts.elapsed() < CACHE_TTL {
                    drop(guard);
                    for (ip, _domain) in parse_a_records(&cached) {
                        self.reverse_cache
                            .insert(IpAddr::V4(ip), q.name.clone())
                            .await;
                    }
                    return Some(apply_txn_id(&cached, txn_id(query)));
                }
            }
        }

        if q.qtype == 1 && plan.outbound_tag != "direct" {
            if let Some(fakeip) = &self.fakeip {
                let ip = fakeip.next_ip();
                self.reverse_cache
                    .insert(IpAddr::V4(ip), q.name.clone())
                    .await;
                if let Some(resp) = build_fake_a_response(query, ip) {
                    self.cache
                        .lock()
                        .await
                        .put(cache_key, (Instant::now(), resp.clone()));
                    log::info!(
                        "DNS fake-ip: {} → {} via {}",
                        q.name,
                        ip,
                        plan.outbound_tag
                    );
                    return Some(resp);
                }
            }
        }

        let Some(client) = self.registry.get(&plan.outbound_tag) else {
            log::warn!("DNS hijack: outbound '{}' not found", plan.outbound_tag);
            return None; // caller sends REFUSED
        };

        // Acquire a slot before opening an outbound socket.
        let _permit = self.inflight.clone().acquire_owned().await.ok()?;

        log::info!(
            "DNS hijack: {} → {} via {}",
            q.name,
            plan.upstream,
            plan.outbound_tag
        );

        let response = if plan.outbound_tag == "direct" {
            self.resolve_direct(query, &plan.upstream).await
        } else {
            self.resolve_via_outbound(query, &plan.upstream, &client)
                .await
        };
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
    async fn resolve_direct(
        &self, query: &[u8], upstream: &Destination,
    ) -> Option<Vec<u8>> {
        let addr: std::net::SocketAddr = upstream.to_string().parse().ok()?;
        let sock = {
            let mut pool = self.socket_pool.lock().await;
            pool.pop()
        };
        let sock = match sock {
            Some(s) => s,
            None => {
                let s =
                    bind_udp_bypass("0.0.0.0:0".parse().unwrap()).await.ok()?;
                s.connect(addr).await.ok()?;
                s
            },
        };

        sock.send(query).await.ok()?;
        let mut buf = vec![0u8; 4096];
        let result = match timeout(QUERY_TIMEOUT, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => Some(buf[..n].to_vec()),
            _ => None,
        };

        // Return socket to the pool for reuse.
        self.socket_pool.lock().await.push(sock);
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
        tokio::spawn(async move {
            let addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                DNS_REDIRECT_PORT,
            );
            let socket = match bind_udp_bypass(addr).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    log::error!(
                        "DNS loopback listener: bind 0.0.0.0:{} failed: {e}",
                        DNS_REDIRECT_PORT
                    );
                    crate::graceful_shutdown();
                    return;
                },
            };

            log::info!("DNS loopback listener on 0.0.0.0:{}", DNS_REDIRECT_PORT);
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
                let this = this.clone();
                let sock = socket.clone();
                tokio::spawn(async move {
                    let response = this
                        .resolve_query(&query, src.ip())
                        .await
                        .or_else(|| build_refused_response(&query));
                    if let Some(r) = response {
                        let _ = sock.send_to(&r, src).await;
                    }
                });
            }
        });
    }

    fn plan_for(&self, tag: String) -> Plan {
        let upstream = if tag == "direct" {
            self.direct_upstream.clone()
        } else {
            self.remote_upstream.clone()
        };
        Plan {
            outbound_tag: tag,
            upstream,
        }
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
        self.writer.write(&raw).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DNS wire-format helpers
// ---------------------------------------------------------------------------
fn build_fake_a_response(
    query: &[u8], ip: std::net::Ipv4Addr,
) -> Option<Vec<u8>> {
    let q_end = dns_question_end(query)?;
    let mut r = Vec::with_capacity(q_end + 16);
    r.extend_from_slice(&query[..2]);
    r.extend_from_slice(&[0x81, 0x80]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x00]);
    r.extend_from_slice(&[0x00, 0x00]);
    r.extend_from_slice(&query[12..q_end]);
    r.extend_from_slice(&[0xC0, 0x0C]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&60u32.to_be_bytes());
    r.extend_from_slice(&[0x00, 0x04]);
    r.extend_from_slice(&ip.octets());
    Some(r)
}

fn dns_question_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 12 {
        return None;
    }
    let mut pos = 12usize;
    loop {
        let len = *buf.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 || pos + len > buf.len() {
            return None;
        }
        pos += len;
    }
    if pos + 4 > buf.len() {
        return None;
    }
    Some(pos + 4)
}

struct DnsQuestion {
    name: String,
    qtype: u16,
}

fn txn_id(query: &[u8]) -> u16 {
    if query.len() < 2 {
        return 0;
    }
    u16::from_be_bytes([query[0], query[1]])
}

fn apply_txn_id(response: &[u8], id: u16) -> Vec<u8> {
    let mut v = response.to_vec();
    if v.len() >= 2 {
        let b = id.to_be_bytes();
        v[0] = b[0];
        v[1] = b[1];
    }
    v
}

/// Parse the first question from a DNS query. Returns None on malformed input.
fn parse_dns_query(buf: &[u8]) -> Option<DnsQuestion> {
    if buf.len() < 12 {
        return None;
    }
    // QR bit (high bit of byte 2) must be 0 for a query.
    if buf[2] & 0x80 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Compression pointers (top two bits set) shouldn't appear in
        // the question section of a normal query — reject.
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[pos..pos + len]).to_string());
        pos += len;
    }
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    Some(DnsQuestion {
        name: labels.join("."),
        qtype,
    })
}

/// Build an empty DNS response (NOERROR, 0 answers) from a query. Used to
/// short-circuit AAAA queries.
fn build_empty_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut v = query.to_vec();
    // Set QR=1, RA=1; clear AA, TC, RCODE.
    v[2] = (v[2] & 0x78) | 0x80; // keep OPCODE bits 3-6, set QR
    v[3] = 0x80; // RA=1, RCODE=0
    // ANCOUNT, NSCOUNT, ARCOUNT all zero.
    v[6] = 0;
    v[7] = 0;
    v[8] = 0;
    v[9] = 0;
    v[10] = 0;
    v[11] = 0;
    // Trim anything past the question section.
    let mut pos = 12usize;
    loop {
        if pos >= v.len() {
            return None;
        }
        let len = v[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1 + len;
        if pos > v.len() {
            return None;
        }
    }
    if pos + 4 > v.len() {
        return None;
    }
    v.truncate(pos + 4); // include QTYPE + QCLASS
    Some(v)
}

/// Build a REFUSED (RCODE=5) response from a query. Used when the matched
/// outbound doesn't exist, so the client gets an immediate error instead of
/// timing out.
fn build_refused_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut v = query.to_vec();
    v[2] = (v[2] & 0x78) | 0x80; // QR=1, keep OPCODE
    v[3] = 0x85; // AA=0, TC=0, RD=copy, RA=1, RCODE=5 (REFUSED)
    v[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT, NSCOUNT, ARCOUNT = 0
    let mut pos = 12usize;
    loop {
        if pos >= v.len() {
            return None;
        }
        let len = v[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1 + len;
        if pos > v.len() {
            return None;
        }
    }
    if pos + 4 > v.len() {
        return None;
    }
    v.truncate(pos + 4);
    Some(v)
}

fn parse_upstream(s: &str) -> Result<Destination, String> {
    // Accept "ip" or "ip:port"; default port 53.
    let (host, port) = if let Some((h, p)) = s.rsplit_once(':') {
        // Watch for IPv6 literal like "::1" — if `h` parses as a v6 it's the
        // address itself with no explicit port.
        if h.parse::<std::net::Ipv6Addr>().is_ok() && p.parse::<u16>().is_err() {
            (s, 53u16)
        } else if let Ok(port) = p.parse::<u16>() {
            (h, port)
        } else {
            (s, 53u16)
        }
    } else {
        (s, 53u16)
    };
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(Destination::new(Address::Ipv4(v4.octets()), port));
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return Ok(Destination::new(Address::Ipv6(v6.octets()), port));
    }
    Err(format!("dns upstream must be an IP literal, got '{s}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v[0] = 0xAB;
        v[1] = 0xCD; // txn id
        v[2] = 0x01;
        v[3] = 0x00; // standard query, RD=1
        v[4] = 0x00;
        v[5] = 0x01; // QDCOUNT = 1
        for label in name.split('.') {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0); // root label
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&[0u8, 1u8]); // QCLASS = IN
        v
    }

    #[test]
    fn parse_a_query() {
        let q = make_query("www.google.com", 1);
        let parsed = parse_dns_query(&q).unwrap();
        assert_eq!(parsed.name, "www.google.com");
        assert_eq!(parsed.qtype, 1);
    }

    #[test]
    fn parse_aaaa_query() {
        let q = make_query("example.org", 28);
        let parsed = parse_dns_query(&q).unwrap();
        assert_eq!(parsed.name, "example.org");
        assert_eq!(parsed.qtype, 28);
    }

    #[test]
    fn parse_rejects_response_packet() {
        let mut q = make_query("a.b", 1);
        q[2] |= 0x80; // set QR=1 → not a query
        assert!(parse_dns_query(&q).is_none());
    }

    #[test]
    fn parse_rejects_truncated() {
        let q = make_query("a.b", 1);
        assert!(parse_dns_query(&q[..10]).is_none());
    }

    #[test]
    fn empty_response_round_trips() {
        let q = make_query("foo.example", 28);
        let r = build_empty_response(&q).unwrap();
        // Same txn id, QR=1, ANCOUNT=0.
        assert_eq!(&r[..2], &[0xAB, 0xCD]);
        assert!(r[2] & 0x80 != 0);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0);
        // Question section preserved.
        let parsed = parse_dns_query(&q).unwrap();
        assert_eq!(parsed.name, "foo.example");
    }

    #[test]
    fn apply_txn_id_overwrites() {
        let cached = vec![0u8, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let restored = apply_txn_id(&cached, 0x1234);
        assert_eq!(&restored[..2], &[0x12, 0x34]);
    }

    #[test]
    fn parse_upstream_default_port() {
        let d = parse_upstream("8.8.8.8").unwrap();
        assert_eq!(d.port, 53);
        assert_eq!(d.address, Address::Ipv4([8, 8, 8, 8]));
    }

    #[test]
    fn parse_upstream_explicit_port() {
        let d = parse_upstream("1.1.1.1:5353").unwrap();
        assert_eq!(d.port, 5353);
    }

    #[test]
    fn parse_upstream_rejects_domain() {
        assert!(parse_upstream("dns.example").is_err());
    }
}
