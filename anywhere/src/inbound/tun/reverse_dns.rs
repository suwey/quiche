//! Reverse DNS cache — maps resolved IP addresses back to domain names.
//!
//! Populated by the DNS hijack after each successful resolution (fake-ip
//! allocation, hosts table, upstream A/AAAA answers) and consulted by the
//! TUN handler so that routing rules (geo-site, domain-matching) see the
//! original domain instead of a bare IP. Both address families share the
//! same LRU — keys are full `IpAddr`s, so a v4 and a v6 fake-ip for the
//! same domain coexist without colliding.
//! Owned by the TUN inbound — the cache lifecycle is tied to the TUN device.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::num::NonZeroUsize;

use lru::LruCache;
use tokio::sync::Mutex;

/// A cache that maps resolved IP addresses back to their domain names.
pub struct ReverseDnsCache {
    inner: Mutex<LruCache<IpAddr, String>>,
}

impl ReverseDnsCache {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
        }
    }

    /// Look up a domain name by IPv4 address.
    pub async fn lookup_ipv4(&self, ip: Ipv4Addr) -> Option<String> {
        self.inner.lock().await.get(&IpAddr::V4(ip)).cloned()
    }

    /// Look up a domain name by IPv6 address.
    pub async fn lookup_ipv6(&self, ip: Ipv6Addr) -> Option<String> {
        self.inner.lock().await.get(&IpAddr::V6(ip)).cloned()
    }

    /// Insert an IP → domain mapping (for use by the DNS hijack).
    pub async fn insert(&self, ip: IpAddr, domain: String) {
        self.inner.lock().await.put(ip, domain);
    }
}

/// Extract all IPv4 A-record answers from a DNS response and return
/// `(ip, domain_name)` pairs.
pub fn parse_a_records(response: &[u8]) -> Vec<(Ipv4Addr, String)> {
    parse_answer_rdata(response, 1, 4)
        .into_iter()
        .map(|(rdata, domain)| {
            (
                Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
                domain,
            )
        })
        .collect()
}

/// Extract all IPv6 AAAA-record answers from a DNS response and return
/// `(ip, domain_name)` pairs. Same walk as [`parse_a_records`]; lets the
/// reverse cache cover AAAA answers (fake-ip v6, hosts v6, upstream
/// passthrough) so v6 TUN packets restore domains like v4 ones.
pub fn parse_aaaa_records(response: &[u8]) -> Vec<(Ipv6Addr, String)> {
    parse_answer_rdata(response, 28, 16)
        .into_iter()
        .map(|(rdata, domain)| {
            let mut groups = [0u16; 8];
            for (i, group) in groups.iter_mut().enumerate() {
                *group = u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]]);
            }
            (Ipv6Addr::new(
                groups[0],
                groups[1],
                groups[2],
                groups[3],
                groups[4],
                groups[5],
                groups[6],
                groups[7],
            ), domain)
        })
        .collect()
}

/// Walk a DNS response and collect `(RDATA, domain)` pairs for every answer
/// record whose TYPE is `rtype_want` and RDLENGTH is `rdata_len`.
fn parse_answer_rdata(
    response: &[u8], rtype_want: u16, rdata_len: usize,
) -> Vec<(Vec<u8>, String)> {
    if response.len() < 12 {
        return vec![];
    }
    // Must be a response (QR=1).
    if response[2] & 0x80 == 0 {
        return vec![];
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]);
    if ancount == 0 {
        return vec![];
    }

    // Parse the question section to get the domain name.
    let mut pos = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= response.len() {
            return vec![];
        }
        let len = response[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Handle compression pointers in the question (unlikely but spec-valid).
        if len & 0xC0 == 0xC0 {
            // Compression pointer: 2 bytes consumed, question ends here.
            pos += 2;
            break;
        }
        pos += 1;
        if pos + len > response.len() {
            return vec![];
        }
        labels
            .push(String::from_utf8_lossy(&response[pos..pos + len]).to_string());
        pos += len;
    }
    let domain = labels.join(".");
    if domain.is_empty() {
        return vec![];
    }

    // Skip QTYPE + QCLASS (4 bytes).
    pos += 4;
    if pos > response.len() {
        return vec![];
    }

    let mut results = Vec::new();
    for _ in 0..ancount {
        if pos >= response.len() {
            break;
        }

        // Parse the NAME field (may be a pointer).
        let name_len = if response[pos] & 0xC0 == 0xC0 {
            2 // compression pointer
        } else {
            let mut p = pos;
            loop {
                if p >= response.len() {
                    return results;
                }
                let l = response[p] as usize;
                if l == 0 {
                    p += 1;
                    break;
                }
                if l & 0xC0 != 0 {
                    p += 2;
                    break;
                }
                p += 1 + l;
                if p > response.len() {
                    return results;
                }
            }
            p - pos
        };
        pos += name_len;
        if pos + 10 > response.len() {
            break;
        }

        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let _rclass = u16::from_be_bytes([response[pos + 2], response[pos + 3]]);
        let _ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlength =
            u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > response.len() {
            break;
        }

        if rtype == rtype_want && rdlength == rdata_len {
            results.push((response[pos..pos + rdlength].to_vec(), domain.clone()));
        }
        pos += rdlength;
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fake-ip style response built with the DNS wire builder; the answer
    // section shape is identical for hosts-table answers.
    fn aaaa_response(domain: &str, ip: Ipv6Addr) -> Vec<u8> {
        let query = crate::dns::wire::build_dns_query(domain, 28);
        crate::dns::wire::build_aaaa_response(&query, ip)
            .expect("AAAA response must build")
    }

    fn a_response(domain: &str, ip: Ipv4Addr) -> Vec<u8> {
        let query = crate::dns::wire::build_dns_query(domain, 1);
        crate::dns::wire::build_a_response(&query, ip)
            .expect("A response must build")
    }

    #[test]
    fn parse_aaaa_records_extracts_v6_answers() {
        let ip =
            std::net::Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 0x42);
        let resp = aaaa_response("example.org", ip);
        let records = parse_aaaa_records(&resp);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, ip);
        assert_eq!(records[0].1, "example.org");
    }

    #[test]
    fn parse_a_records_still_works_after_refactor() {
        let ip = Ipv4Addr::new(198, 18, 0, 7);
        let resp = a_response("example.org", ip);
        let records = parse_a_records(&resp);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, ip);
        assert_eq!(records[0].1, "example.org");
        // An AAAA response contains no A records and vice versa.
        let v6 =
            std::net::Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 0x42);
        assert!(parse_a_records(&aaaa_response("x.org", v6)).is_empty());
        assert!(parse_aaaa_records(&a_response("x.org", ip)).is_empty());
    }

    #[tokio::test]
    async fn reverse_cache_serves_both_families() {
        let cache = ReverseDnsCache::new(NonZeroUsize::new(16).unwrap());
        let v4 = Ipv4Addr::new(198, 18, 0, 1);
        let v6 =
            std::net::Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 2);

        cache.insert(IpAddr::V4(v4), "dual.example".into()).await;
        cache.insert(IpAddr::V6(v6), "dual.example".into()).await;

        assert_eq!(
            cache.lookup_ipv4(v4).await.as_deref(),
            Some("dual.example")
        );
        assert_eq!(
            cache.lookup_ipv6(v6).await.as_deref(),
            Some("dual.example")
        );
        // A v4 lookup must not collide with the same 32 bits inside a v6 key
        // (the old u32-keyed map could not express v6 at all).
        assert_eq!(cache.lookup_ipv6(Ipv6Addr::LOCALHOST).await, None);
    }
}
