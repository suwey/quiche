//! Reverse DNS cache — maps resolved IP addresses back to domain names.
//!
//! Populated by the DNS hijack after each successful resolution and consulted
//! by the TUN handler so that routing rules (geo-site, domain-matching) see
//! the original domain instead of a bare IP.
//! Owned by the TUN inbound — the cache lifecycle is tied to the TUN device.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::num::NonZeroUsize;

use lru::LruCache;
use tokio::sync::Mutex;

/// A cache that maps resolved IP addresses back to their domain names.
pub struct ReverseDnsCache {
    inner: Mutex<LruCache<u32, String>>,
}

impl ReverseDnsCache {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
        }
    }

    /// Look up a domain name by IPv4 address.
    pub async fn lookup_ipv4(&self, ip: Ipv4Addr) -> Option<String> {
        let key = u32::from(ip);
        self.inner.lock().await.get(&key).cloned()
    }

    /// Look up a domain name by IPv6 address.
    pub async fn lookup_ipv6(&self, _ip: Ipv6Addr) -> Option<String> {
        // TODO: IPv6 reverse lookup support when needed
        None
    }

    /// Insert an IP → domain mapping (for use by the DNS hijack).
    pub async fn insert(&self, ip: IpAddr, domain: String) {
        match ip {
            IpAddr::V4(v4) => {
                let key = u32::from(v4);
                self.inner.lock().await.put(key, domain);
            },
            IpAddr::V6(_) => {
                // IPv6 reverse lookup not yet needed
            },
        }
    }
}

/// Extract all IPv4 A-record answers from a DNS response and return
/// `(ip, domain_name)` pairs.
pub fn parse_a_records(response: &[u8]) -> Vec<(Ipv4Addr, String)> {
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

        if rtype == 1 && rdlength == 4 {
            // A record
            let ip = Ipv4Addr::new(
                response[pos],
                response[pos + 1],
                response[pos + 2],
                response[pos + 3],
            );
            results.push((ip, domain.clone()));
        }
        pos += rdlength;
    }
    results
}
