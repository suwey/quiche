//! Geo rule-set support — SRS binary parsing, DomainMatcher (trie), GeoMatcher,
//! download/cache/refresh.
//!
//! See docs/superpowers/specs/2026-05-28-geo-rules-module-design.md

use std::net::IpAddr;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::inbound::Network;

// ---------------------------------------------------------------------------
// DomainMatcher — succinct trie over reversed domain names
// ---------------------------------------------------------------------------

/// A succinct-domain-trie matcher extracted from an SRS rule-set file.
///
/// Holds the compressed trie (leaves, label_bitmap, labels) from a sing-box
/// `domain.Matcher` binary.  Matching is O(domain_length) — NOT O(rule_count).
#[derive(Clone)]
pub struct DomainMatcher {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    ranks: Vec<i32>,
    selects: Vec<i32>,
}

impl DomainMatcher {
    pub(crate) fn new(
        leaves: Vec<u64>, label_bitmap: Vec<u64>, labels: Vec<u8>,
    ) -> Self {
        let ranks = rank64_slice(&label_bitmap);
        let selects = select32_slice(&label_bitmap);
        Self {
            leaves,
            label_bitmap,
            labels,
            ranks,
            selects,
        }
    }

    /// Walk the trie with the reversed host.
    /// Returns `true` when the host (or a suffix of it) matches.
    pub fn matches(&self, host: &str) -> bool {
        let key: Vec<u8> = host.bytes().rev().collect();
        self.has(&key)
    }

    /// Core trie walk — mirrors sing-box `domain.Matcher.has()`.
    fn has(&self, key: &[u8]) -> bool {
        let mut node_id = 0usize;
        let mut bm_idx = 0usize;

        for &current_char in key {
            loop {
                if get_bit(&self.label_bitmap, bm_idx) != 0 {
                    return false;
                }
                let label_idx = bm_idx - node_id;
                if label_idx >= self.labels.len() {
                    return false;
                }
                let next_label = self.labels[label_idx];

                // '\r' (prefixLabel) → matches any subdomain of this prefix
                if next_label == b'\r' {
                    return true;
                }
                // '\n' (rootLabel) → matches the domain itself AND all subdomains
                if next_label == b'\n' {
                    let next_node =
                        count_zeros(&self.label_bitmap, &self.ranks, bm_idx + 1);
                    let has_next = get_bit(&self.leaves, next_node) != 0;
                    if current_char == b'.' && has_next {
                        return true;
                    }
                }
                if next_label == current_char {
                    break;
                }
                bm_idx += 1;
            }

            // Advance to the child node
            node_id = count_zeros(&self.label_bitmap, &self.ranks, bm_idx + 1);
            let prev_one = if node_id == 0 {
                !0usize
            } else {
                select_ith_one(
                    &self.label_bitmap,
                    &self.ranks,
                    &self.selects,
                    node_id - 1,
                )
            };
            bm_idx = prev_one.wrapping_add(1);
        }

        // Exact match: current node is a leaf
        if get_bit(&self.leaves, node_id) != 0 {
            return true;
        }

        // Not a leaf — check if any remaining child is a suffix marker
        loop {
            if get_bit(&self.label_bitmap, bm_idx) != 0 {
                return false;
            }
            let label_idx = bm_idx - node_id;
            if label_idx >= self.labels.len() {
                return false;
            }
            let next_label = self.labels[label_idx];
            if next_label == b'\r' || next_label == b'\n' {
                return true;
            }
            bm_idx += 1;
        }
    }

    /// Extract all keys, split into (exact_domains, domain_suffixes).
    pub fn dump(&self) -> (Vec<String>, Vec<String>) {
        let mut keys = Vec::new();
        let mut current_key: Vec<u8> = Vec::new();
        extract_keys(
            &self.leaves,
            &self.label_bitmap,
            &self.labels,
            &self.ranks,
            &self.selects,
            0,
            0,
            &mut current_key,
            &mut keys,
        );

        let mut domains = Vec::new();
        let mut suffixes = Vec::new();
        for key in &keys {
            if key.is_empty() {
                continue;
            }
            let reversed: Vec<u8> = key.bytes().rev().collect();
            if reversed.is_empty() {
                continue;
            }
            match reversed[0] {
                b'\r' | b'\n' => {
                    if reversed.len() > 1 {
                        suffixes.push(
                            std::str::from_utf8(&reversed[1..])
                                .unwrap_or("")
                                .to_string(),
                        );
                    }
                },
                _ => {
                    domains.push(
                        std::str::from_utf8(&reversed).unwrap_or("").to_string(),
                    );
                },
            }
        }
        (domains, suffixes)
    }
}

// ---------------------------------------------------------------------------
// GeoMatcher
// ---------------------------------------------------------------------------

/// A compact matcher for a sing-box rule-set file.
///
/// Holds domain trie(s), keyword, and/or IP range matchers parsed from an
/// `.srs` file without expanding into individual rules.
#[derive(Clone)]
pub struct GeoMatcher {
    pub source: String,
    inner: GeoMatcherInner,
}

#[derive(Clone)]
enum GeoMatcherInner {
    Domain(Vec<DomainMatcher>, Option<Vec<String>>),
    IP(Vec<IpRange>),
    Mixed(Vec<DomainMatcher>, Option<Vec<String>>, Vec<IpRange>),
}

impl GeoMatcher {
    pub fn matches(&self, dest: &Destination, _network: Network) -> bool {
        match &self.inner {
            GeoMatcherInner::Domain(matchers, kw) => {
                self.match_domain(dest, matchers, kw.as_deref())
            },
            GeoMatcherInner::IP(ranges) => self.match_ip(dest, ranges),
            GeoMatcherInner::Mixed(matchers, kw, ranges) => {
                self.match_domain(dest, matchers, kw.as_deref())
                    || self.match_ip(dest, ranges)
            },
        }
    }

    fn match_domain(
        &self, dest: &Destination, matchers: &[DomainMatcher],
        kw: Option<&[String]>,
    ) -> bool {
        if let Address::Domain(ref host) = dest.address {
            if matchers.iter().any(|m| m.matches(host)) {
                return true;
            }
            if let Some(kw_list) = kw {
                if kw_list.iter().any(|k| host.contains(k.as_str())) {
                    return true;
                }
            }
        }
        false
    }

    fn match_ip(&self, dest: &Destination, ranges: &[IpRange]) -> bool {
        let ip = match dest.address {
            Address::Ipv4(o) => IpAddr::V4(std::net::Ipv4Addr::from(o)),
            Address::Ipv6(o) => IpAddr::V6(std::net::Ipv6Addr::from(o)),
            Address::Domain(ref host) => match host.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => return false,
            },
        };
        ranges.iter().any(|r| r.contains(&ip))
    }
}

#[derive(Clone)]
pub struct IpRange {
    pub from: u128,
    pub to: u128,
}

impl IpRange {
    fn contains(&self, ip: &IpAddr) -> bool {
        let val = match ip {
            IpAddr::V4(v4) => u128::from(u32::from(*v4)),
            IpAddr::V6(v6) => u128::from(*v6),
        };
        val >= self.from && val <= self.to
    }
}

// ---------------------------------------------------------------------------
// SRS binary parser — produces compact trie-based SrsRuleSet
// ---------------------------------------------------------------------------

/// Parsed rule-set data in compact form.
///
/// Domain rules are kept as compressed tries (`DomainMatcher`) rather than
/// expanded into flat string lists.
pub struct SrsRuleSet {
    pub domain_matchers: Vec<DomainMatcher>,
    pub keywords: Vec<String>,
    pub ip_ranges: Vec<IpRange>,
}

impl SrsRuleSet {
    /// Expand into flat lists (expensive — for display / debugging only).
    pub fn dump(&self) -> ParsedRuleSet {
        let mut domains = Vec::new();
        let mut suffixes = Vec::new();
        for dm in &self.domain_matchers {
            let (d, s) = dm.dump();
            domains.extend(d);
            suffixes.extend(s);
        }
        ParsedRuleSet {
            domains,
            domain_suffixes: suffixes,
            keywords: self.keywords.clone(),
            ip_ranges: self.ip_ranges.clone(),
        }
    }
}

/// Flat rule-set data for display (produced by [`SrsRuleSet::dump`]).
pub struct ParsedRuleSet {
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub keywords: Vec<String>,
    pub ip_ranges: Vec<IpRange>,
}

const RULE_ITEM_DOMAIN: u8 = 2;
const RULE_ITEM_DOMAIN_KEYWORD: u8 = 3;
const RULE_ITEM_DOMAIN_REGEX: u8 = 4;
const RULE_ITEM_IP_CIDR: u8 = 6;
const RULE_ITEM_FINAL: u8 = 0xFF;

/// Parse SRS v2 binary data into a compact [`SrsRuleSet`].
pub fn read_srs_bytes(data: &[u8]) -> Option<SrsRuleSet> {
    if data.len() < 4 || &data[0..3] != b"SRS" {
        return None;
    }
    let version = data[3];
    if version > 2 {
        return None;
    }

    use std::io::Read;
    let mut decoder = flate2::read::ZlibDecoder::new(&data[4..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).ok()?;

    let mut pos = 0usize;
    let rule_count = read_uvarint(&decompressed, &mut pos)?;

    let mut domain_matchers: Vec<DomainMatcher> = Vec::new();
    let mut all_keywords: Vec<String> = Vec::new();
    let mut all_ip_ranges: Vec<IpRange> = Vec::new();

    for _ in 0..rule_count {
        let rule_type = read_u8(&decompressed, &mut pos)?;
        if rule_type != 0 {
            loop {
                let item_type = read_u8(&decompressed, &mut pos)?;
                if item_type == RULE_ITEM_FINAL {
                    let _invert = read_u8(&decompressed, &mut pos)?;
                    break;
                }
                skip_item(&decompressed, &mut pos, item_type);
            }
            continue;
        }

        loop {
            let item_type = read_u8(&decompressed, &mut pos)?;
            if item_type == RULE_ITEM_FINAL {
                let _invert = read_u8(&decompressed, &mut pos)?;
                break;
            }
            match item_type {
                RULE_ITEM_DOMAIN => {
                    if let Some(dm) = read_domain_item(&decompressed, &mut pos) {
                        domain_matchers.push(dm);
                    }
                },
                RULE_ITEM_DOMAIN_KEYWORD => {
                    let keywords = read_string_list(&decompressed, &mut pos)?;
                    all_keywords.extend(keywords);
                },
                RULE_ITEM_DOMAIN_REGEX => {
                    let _regexes = read_string_list(&decompressed, &mut pos)?;
                },
                RULE_ITEM_IP_CIDR => {
                    let ranges = read_ip_cidr_item(&decompressed, &mut pos)?;
                    all_ip_ranges.extend(ranges);
                },
                _ => {
                    skip_item(&decompressed, &mut pos, item_type);
                },
            }
        }
    }

    Some(SrsRuleSet {
        domain_matchers,
        keywords: all_keywords,
        ip_ranges: all_ip_ranges,
    })
}

/// Convert a parsed [`SrsRuleSet`] into a [`GeoMatcher`].
pub fn parsed_to_geomatcher(
    parsed: SrsRuleSet, source: &str,
) -> Option<GeoMatcher> {
    let has_domain = !parsed.domain_matchers.is_empty();
    let kw = if parsed.keywords.is_empty() {
        None
    } else {
        Some(parsed.keywords)
    };
    let ip = if parsed.ip_ranges.is_empty() {
        None
    } else {
        Some(parsed.ip_ranges)
    };

    let inner = match (has_domain, kw, ip) {
        (true, kw, Some(ip)) => {
            GeoMatcherInner::Mixed(parsed.domain_matchers, kw, ip)
        },
        (true, kw, None) => GeoMatcherInner::Domain(parsed.domain_matchers, kw),
        (false, None, Some(ip)) => GeoMatcherInner::IP(ip),
        (false, Some(kw), None) => GeoMatcherInner::Domain(vec![], Some(kw)),
        (false, Some(kw), Some(ip)) => {
            GeoMatcherInner::Mixed(vec![], Some(kw), ip)
        },
        (false, None, None) => return None,
    };

    Some(GeoMatcher {
        source: source.to_string(),
        inner,
    })
}

// ---------------------------------------------------------------------------
// SRS binary reader helpers
// ---------------------------------------------------------------------------

fn read_uvarint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut val = 0u64;
    let mut shift = 0;
    loop {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        val |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(val);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

fn read_u8(buf: &[u8], pos: &mut usize) -> Option<u8> {
    let val = *buf.get(*pos)?;
    *pos += 1;
    Some(val)
}

fn read_exact<'a>(
    buf: &'a [u8], pos: &mut usize, len: usize,
) -> Option<&'a [u8]> {
    if *pos + len > buf.len() {
        return None;
    }
    let slice = &buf[*pos..*pos + len];
    *pos += len;
    Some(slice)
}

fn skip_item(buf: &[u8], pos: &mut usize, item_type: u8) {
    let _ = (|| -> Option<()> {
        match item_type {
            RULE_ITEM_DOMAIN => {
                let _version = read_u8(buf, pos)?;
                let leaves_len = read_uvarint(buf, pos)? as usize;
                read_exact(buf, pos, leaves_len * 8)?;
                let bitmap_len = read_uvarint(buf, pos)? as usize;
                read_exact(buf, pos, bitmap_len * 8)?;
                let labels_len = read_uvarint(buf, pos)? as usize;
                read_exact(buf, pos, labels_len)?;
                Some(())
            },
            RULE_ITEM_DOMAIN_KEYWORD | RULE_ITEM_DOMAIN_REGEX => {
                let count = read_uvarint(buf, pos)?;
                for _ in 0..count {
                    let len = read_uvarint(buf, pos)? as usize;
                    read_exact(buf, pos, len)?;
                }
                Some(())
            },
            RULE_ITEM_IP_CIDR => {
                let _version = read_u8(buf, pos)?;
                let range_bytes = read_exact(buf, pos, 8)?;
                let range_count =
                    u64::from_be_bytes(range_bytes.try_into().unwrap());
                for _ in 0..range_count {
                    let from_len = read_uvarint(buf, pos)? as usize;
                    read_exact(buf, pos, from_len)?;
                    let to_len = read_uvarint(buf, pos)? as usize;
                    read_exact(buf, pos, to_len)?;
                }
                Some(())
            },
            _ => None,
        }
    })();
}

fn read_string_list(buf: &[u8], pos: &mut usize) -> Option<Vec<String>> {
    let count = read_uvarint(buf, pos)? as usize;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_uvarint(buf, pos)? as usize;
        let bytes = read_exact(buf, pos, len)?;
        list.push(String::from_utf8_lossy(bytes).to_string());
    }
    Some(list)
}

fn read_ip_cidr_item(buf: &[u8], pos: &mut usize) -> Option<Vec<IpRange>> {
    let _version = read_u8(buf, pos)?;
    let range_bytes = read_exact(buf, pos, 8)?;
    let range_count = u64::from_be_bytes(range_bytes.try_into().unwrap());

    let mut ranges = Vec::with_capacity(range_count as usize);
    for _ in 0..range_count {
        let from_len = read_uvarint(buf, pos)? as usize;
        let from_bytes = read_exact(buf, pos, from_len)?;
        let to_len = read_uvarint(buf, pos)? as usize;
        let to_bytes = read_exact(buf, pos, to_len)?;
        ranges.push(IpRange {
            from: ip_bytes_to_u128(from_bytes),
            to: ip_bytes_to_u128(to_bytes),
        });
    }
    Some(ranges)
}

fn ip_bytes_to_u128(bytes: &[u8]) -> u128 {
    if bytes.len() == 4 {
        let mut arr = [0u8; 16];
        arr[12..16].copy_from_slice(bytes);
        u128::from_be_bytes(arr)
    } else if bytes.len() == 16 {
        <[u8; 16]>::try_from(bytes)
            .map(u128::from_be_bytes)
            .unwrap_or(0)
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Succinct set parsing — produces DomainMatcher directly
// ---------------------------------------------------------------------------

fn read_domain_item(buf: &[u8], pos: &mut usize) -> Option<DomainMatcher> {
    let _version = read_u8(buf, pos)?;

    let leaves_len = read_uvarint(buf, pos)? as usize;
    let leaves_bytes = read_exact(buf, pos, leaves_len * 8)?;
    let mut leaves = Vec::with_capacity(leaves_len);
    for i in 0..leaves_len {
        let arr: &[u8; 8] = leaves_bytes[i * 8..(i + 1) * 8].try_into().ok()?;
        leaves.push(u64::from_be_bytes(*arr));
    }

    let bitmap_len = read_uvarint(buf, pos)? as usize;
    let bitmap_bytes = read_exact(buf, pos, bitmap_len * 8)?;
    let mut label_bitmap = Vec::with_capacity(bitmap_len);
    for i in 0..bitmap_len {
        let arr: &[u8; 8] = bitmap_bytes[i * 8..(i + 1) * 8].try_into().ok()?;
        label_bitmap.push(u64::from_be_bytes(*arr));
    }

    let labels_len = read_uvarint(buf, pos)? as usize;
    let labels = read_exact(buf, pos, labels_len)?.to_vec();

    Some(DomainMatcher::new(leaves, label_bitmap, labels))
}

// ---------------------------------------------------------------------------
// Trie traversal for dump()
// ---------------------------------------------------------------------------

fn extract_keys(
    leaves: &[u64], label_bitmap: &[u64], labels: &[u8], ranks: &[i32],
    selects: &[i32], node_id: usize, bm_idx: usize, current_key: &mut Vec<u8>,
    keys: &mut Vec<String>,
) {
    if node_id >> 6 < leaves.len() && get_bit(leaves, node_id) != 0 {
        keys.push(String::from_utf8_lossy(current_key).to_string());
    }

    let mut bm_idx = bm_idx;
    loop {
        if bm_idx >> 6 >= label_bitmap.len() {
            return;
        }
        if get_bit(label_bitmap, bm_idx) != 0 {
            return;
        }
        let label_idx = bm_idx - node_id;
        if label_idx >= labels.len() {
            return;
        }
        let next_label = labels[label_idx];
        current_key.push(next_label);
        let next_node = count_zeros(label_bitmap, ranks, bm_idx + 1);
        let prev_one = if next_node == 0 {
            !0usize
        } else {
            select_ith_one(label_bitmap, ranks, selects, next_node - 1)
        };
        extract_keys(
            leaves,
            label_bitmap,
            labels,
            ranks,
            selects,
            next_node,
            prev_one.wrapping_add(1),
            current_key,
            keys,
        );
        current_key.pop();
        bm_idx += 1;
    }
}

// ---------------------------------------------------------------------------
// Rank / select helpers
// ---------------------------------------------------------------------------

fn get_bit(bm: &[u64], i: usize) -> u64 {
    if i >> 6 >= bm.len() {
        0
    } else {
        bm[i >> 6] & (1 << (i & 63))
    }
}

fn count_zeros(bm: &[u64], ranks: &[i32], i: usize) -> usize {
    let ones = rank64(bm, ranks, i as i32);
    i - (ones as usize)
}

fn rank64(bm: &[u64], ranks: &[i32], i: i32) -> i32 {
    let word_idx = (i >> 6) as usize;
    if word_idx >= ranks.len() {
        return ranks.last().copied().unwrap_or(0);
    }
    let bit_idx = (i & 63) as u32;
    let w = bm[word_idx];
    let mask = if bit_idx == 0 {
        0u64
    } else {
        (1u64 << bit_idx) - 1
    };
    ranks[word_idx] + (w & mask).count_ones() as i32
}

fn select_ith_one(bm: &[u64], ranks: &[i32], selects: &[i32], i: usize) -> usize {
    if i >> 5 >= selects.len() {
        return bm.len() << 6;
    }
    let mut word_idx = (selects[i >> 5] >> 6) as usize;
    while word_idx + 1 < ranks.len() && (ranks[word_idx + 1] as i32) <= i as i32 {
        word_idx += 1;
    }
    let mut w = bm[word_idx];
    let base = word_idx << 6;
    let find_ith = i as i32 - ranks[word_idx];
    let mut remaining = find_ith;
    let mut offset: i32 = 0;

    let ones32 = (w as u32).count_ones() as i32;
    if ones32 <= remaining {
        remaining -= ones32;
        w >>= 32;
        offset += 32;
    }
    let ones16 = (w as u16).count_ones() as i32;
    if ones16 <= remaining {
        remaining -= ones16;
        w >>= 16;
        offset += 16;
    }
    let ones8 = (w as u8).count_ones() as i32;
    if ones8 <= remaining {
        remaining -= ones8;
        w >>= 8;
        offset += 8;
    }

    let mut pos = 0i32;
    let mut mask = 1u64;
    for _ in 0..remaining {
        while w & mask == 0 {
            mask <<= 1;
            pos += 1;
        }
        mask <<= 1;
        pos += 1;
    }
    while w & mask == 0 {
        mask <<= 1;
        pos += 1;
    }

    (base as i32 + offset + pos) as usize
}

fn rank64_slice(bm: &[u64]) -> Vec<i32> {
    let mut ranks = Vec::with_capacity(bm.len() + 1);
    let mut n = 0i32;
    for &w in bm {
        ranks.push(n);
        n += w.count_ones() as i32;
    }
    ranks.push(n);
    ranks
}

fn select32_slice(bm: &[u64]) -> Vec<i32> {
    let mut selects = Vec::new();
    let mut ith = -1i32;
    for i in 0..bm.len() << 6 {
        if get_bit(bm, i) != 0 {
            ith += 1;
            if ith & 31 == 0 {
                selects.push(i as i32);
            }
        }
    }
    selects
}

// ---------------------------------------------------------------------------
// Helper functions for GeoRuleSet
// ---------------------------------------------------------------------------

/// Extract source name from URL path, e.g.
/// ".../geosite/geolocation-!cn.srs" -> "geosite:geolocation-!cn"
pub(super) fn extract_source_name(url: &str) -> String {
    let path = url.split('?').next().unwrap_or(url);
    let path = path.split('#').next().unwrap_or(path);
    let path_std = path.replace('\\', "/");
    let segments: Vec<&str> = path_std.split('/').collect();

    let filename = segments.last().unwrap_or(&"unknown");
    let stem = if let Some(dot) = filename.rfind('.') {
        &filename[..dot]
    } else {
        filename
    };

    if segments.len() >= 2 {
        let parent = segments[segments.len() - 2];
        format!("{parent}:{stem}")
    } else {
        stem.to_string()
    }
}

/// Parse duration strings like "3d", "24h", "30m".
pub(super) fn parse_duration_str(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();
    if let Some(d) = s.strip_suffix('d') {
        d.parse::<u64>()
            .ok()
            .map(|n| std::time::Duration::from_secs(n * 86400))
    } else if let Some(h) = s.strip_suffix('h') {
        h.parse::<u64>()
            .ok()
            .map(|n| std::time::Duration::from_secs(n * 3600))
    } else if let Some(m) = s.strip_suffix('m') {
        m.parse::<u64>()
            .ok()
            .map(|n| std::time::Duration::from_secs(n * 60))
    } else if s.is_empty() {
        None
    } else {
        Some(std::time::Duration::from_secs(3 * 86400))
    }
}

// ---------------------------------------------------------------------------
// GeoRuleSet — download, cache, refresh
// ---------------------------------------------------------------------------

/// A managed geo rule-set: downloads, caches, and periodically refreshes an SRS
/// file.
pub struct GeoRuleSet {
    url: String,
    source_name: String,
    update_interval: std::time::Duration,
    cache_path: std::path::PathBuf,
    matcher: tokio::sync::RwLock<Option<GeoMatcher>>,
    /// True when the cache was stale (or absent) at construction and should be
    /// refreshed ASAP in the background - without blocking startup.
    needs_refresh: bool,
    /// Plain-IP DNS upstreams (e.g. `223.5.5.5:53`) used to resolve geo-rule
    /// download hosts via a bypass socket, so the refresh works even after
    /// the TUN / fake-ip DNS hijack is active.
    dns_plain: Vec<std::net::SocketAddr>,
}

impl GeoRuleSet {
    /// Create a new GeoRuleSet.
    ///
    /// Cache-first (stale-while-revalidate): if a cached file exists it is
    /// loaded immediately so engine startup is not blocked on network I/O.
    /// A stale cache (older than `update_interval`) is marked for a background
    /// refresh via [`start_background_update`]. Only when there is no cache at
    /// all does this block on a download (first run; on Android the Kotlin
    /// prefetch usually populates the cache before the engine starts).
    pub async fn new(
        url: &str, update_interval_str: Option<&str>,
        cache_dir: &std::path::Path, dns_plain: Vec<std::net::SocketAddr>,
    ) -> Self {
        let source_name = extract_source_name(url);
        let update_interval = update_interval_str
            .and_then(parse_duration_str)
            .unwrap_or_else(|| std::time::Duration::from_secs(3 * 86400));

        let cache_filename: String = url
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let cache_filename = if cache_filename.len() > 200 {
            format!("{}.srs", &cache_filename[..196])
        } else {
            format!("{cache_filename}.srs")
        };
        let cache_path = cache_dir.join("rule_set").join(&cache_filename);

        // Cache-first: load immediately for fast startup. The blocking download
        // that used to happen here would fail on Android anyway (TUN/DNS not
        // ready during engine init) and burn ~30s of DNS timeouts before
        // falling back to this same cache.
        let (matcher, needs_refresh) = if cache_path.exists() {
            let age = std::time::SystemTime::now()
                .duration_since(
                    cache_path
                        .metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                )
                .unwrap_or(std::time::Duration::ZERO);
            let stale = age >= update_interval;
            if stale {
                log::info!(
                    "Using cached geo rule set (stale, age={}s; will refresh in background): {url}",
                    age.as_secs(),
                );
            } else {
                log::info!(
                    "Using cached geo rule set (age={}s): {url}",
                    age.as_secs(),
                );
            }
            (Self::load_cache(&cache_path, &source_name).await, stale)
        } else {
            // No cache - must download now (first run only).
            if let Some(dir) = cache_path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            match Self::fetch_and_cache(
                url,
                &cache_path,
                &source_name,
                &dns_plain,
            )
            .await
            {
                Ok(m) => (Some(m), false),
                Err(e) => {
                    log::warn!(
                        "Download failed for {url}: {e}; no cache available"
                    );
                    (None, true)
                },
            }
        };

        Self {
            url: url.to_string(),
            source_name,
            update_interval,
            cache_path,
            matcher: tokio::sync::RwLock::new(matcher),
            needs_refresh,
            dns_plain,
        }
    }

    /// Download, parse, and write to cache. Returns the GeoMatcher on success.
    ///
    /// Uses `connect_tcp_bypass` + `tokio-rustls` TLS so that on Android the
    /// underlying socket is protected via `VpnService.protect()`, bypassing
    /// the TUN interface.  This avoids the startup deadlock where geo-rule
    /// downloads would be routed into the TUN before the rules engine is
    /// ready.
    async fn fetch_and_cache(
        url: &str, cache_path: &std::path::Path, source_name: &str,
        dns_plain: &[std::net::SocketAddr],
    ) -> Result<GeoMatcher, String> {
        let data = Self::http_get_bypass(url, dns_plain)
            .await
            .map_err(|e| format!("HTTP GET {url}: {e}"))?;

        let parsed = read_srs_bytes(&data)
            .ok_or_else(|| "Failed to parse SRS file".to_string())?;
        let matcher = parsed_to_geomatcher(parsed, source_name)
            .ok_or_else(|| "Parsed SRS produced empty matcher".to_string())?;

        let _ = tokio::fs::write(cache_path, &data).await;
        log::info!("Updated geo rule set: {source_name}");
        Ok(matcher)
    }

    /// HTTP/1.1 GET over a protect-ed (bypass) TCP + TLS connection.
    ///
    /// This replaces `reqwest` for geo-rule downloads so that the socket is
    /// properly protected on Android (via `VpnService.protect`) and marked
    /// with `SO_MARK` on Linux, consistent with all other outbound
    /// connections.
    async fn http_get_bypass(
        url: &str, dns_plain: &[std::net::SocketAddr],
    ) -> Result<Vec<u8>, String> {
        use std::sync::Arc;
        use std::time::Duration;

        use http_body_util::{BodyExt, Empty};
        use hyper::Request;
        use hyper::body::Bytes;
        use hyper_util::rt::TokioIo;
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::ClientConfig;
        use tokio_rustls::rustls::pki_types::ServerName;

        // Parse URL.
        let parsed =
            url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "URL has no host".to_string())?;
        let port = parsed.port_or_known_default().unwrap_or(443);
        let path = if parsed.path().is_empty() {
            "/"
        } else {
            parsed.path()
        };
        let query = parsed.query().map(|q| format!("?{q}")).unwrap_or_default();
        let path_query = format!("{path}{query}");

        // Resolve host to an IP. On Android the system resolver is hijacked
        // by the engine's fake-ip DNS (query source is the TUN address, not
        // loopback, so local_direct doesn't apply) and returns a non-routable
        // 198.18.x.x. Try a direct UDP query to a configured plain upstream
        // over a bypass (protected) socket first; fall back to the system
        // resolver if that fails or returns a fake-ip (e.g. pf rdr on macOS
        // still redirected the bypass query to the hijack). On desktop (no
        // TUN) the system resolver is fine either way.
        let ip = if !dns_plain.is_empty() {
            Self::resolve_bypass(host, dns_plain).await
        } else {
            None
        };
        let ip = match ip {
            Some(ip) => ip,
            None => tokio::net::lookup_host(format!("{host}:{port}"))
                .await
                .ok()
                .and_then(|mut it| it.next())
                .map(|sa| sa.ip())
                .ok_or_else(|| format!("DNS resolution failed for {host}"))?,
        };
        let addr = std::net::SocketAddr::new(ip, port);

        // TCP connect with bypass (protect on Android / SO_MARK on Linux).
        let tcp = crate::outbound::common::connect_tcp_bypass(addr)
            .await
            .map_err(|e| format!("TCP connect {addr}: {e}"))?;
        let _ = tcp.set_nodelay(true);

        // TLS handshake with ALPN "http/1.1".
        let provider = tokio_rustls::rustls::crypto::ring::default_provider();
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls_config =
            ClientConfig::builder_with_provider(Arc::new(provider))
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

        // HTTP/1.1 GET via hyper.
        let io = TokioIo::new(tls);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("hyper handshake: {e}"))?;

        // Drive the connection in the background.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method("GET")
            .uri(&path_query)
            .header("Host", host)
            .header("User-Agent", "anywhere/geo-rules")
            .header("Connection", "close")
            .body(Empty::<Bytes>::new())
            .map_err(|e| format!("build request: {e}"))?;

        let resp = tokio::time::timeout(
            Duration::from_secs(30),
            sender.send_request(req),
        )
        .await
        .map_err(|_| "HTTP response timeout".to_string())?
        .map_err(|e| format!("send request: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }

        // Collect body.
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("read body: {e}"))?;
        Ok(body.to_bytes().to_vec())
    }

    /// True if `ip` is in the default fake-ip range 198.18.0.0/15 (what the
    /// engine's fake-ip DNS hands out for proxied domains).
    fn is_fakeip(ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 198 && (18..=19).contains(&o[1])
            },
            _ => false,
        }
    }

    /// Resolve `host` to an IP via a direct UDP DNS query to one of
    /// `dns_plain`, over a bypass (TUN-protected) socket. Returns the first
    /// A record found; tries each upstream in order.
    async fn resolve_bypass(
        host: &str, dns_plain: &[std::net::SocketAddr],
    ) -> Option<std::net::IpAddr> {
        use crate::dns::wire::{build_a_query, first_a_record};
        use crate::outbound::common::bind_udp_bypass;
        use tokio::time::timeout;

        let query = build_a_query(host);
        for up in dns_plain {
            let sock = match bind_udp_bypass("0.0.0.0:0".parse().unwrap()).await {
                Ok(s) => s,
                Err(_) => continue,
            };
            if sock.connect(*up).await.is_err() {
                continue;
            }
            if sock.send(&query).await.is_err() {
                continue;
            }
            let mut buf = vec![0u8; 512];
            if let Ok(Ok(n)) =
                timeout(std::time::Duration::from_secs(3), sock.recv(&mut buf))
                    .await
            {
                if let Some(ip) = first_a_record(&buf[..n]) {
                    // Reject fake-ip (198.18.0.0/15): the bypass query didn't
                    // escape the engine's DNS hijack (e.g. pf rdr on macOS
                    // still redirected it). Fall through so the caller retries
                    // via the system resolver.
                    if !Self::is_fakeip(&ip) {
                        log::debug!("geo DNS bypass: {host} -> {ip} via {up}");
                        return Some(ip);
                    }
                    log::warn!(
                        "geo DNS bypass: {host} -> fake-ip {ip} via {up} \
                         (bypass leaked to hijack)"
                    );
                }
            }
        }
        None
    }

    async fn load_cache(
        cache_path: &std::path::Path, source_name: &str,
    ) -> Option<GeoMatcher> {
        let data = tokio::fs::read(cache_path).await.ok()?;
        let parsed = read_srs_bytes(&data)?;
        let matcher = parsed_to_geomatcher(parsed, source_name)?;
        log::info!("Loaded cached geo rule set: {source_name}");
        Some(matcher)
    }

    /// Get a clone of the current matcher for matching.
    pub async fn matcher(&self) -> Option<GeoMatcher> {
        self.matcher.read().await.clone()
    }

    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    /// Start background refresh loop.
    ///
    /// If the cache was stale at construction, refresh immediately first (by
    /// then the TUN/DNS is up so the download can actually succeed), then
    /// loop on `update_interval`.
    pub fn start_background_update(self: std::sync::Arc<Self>) {
        let interval = self.update_interval;
        let this = self.clone();
        tokio::spawn(async move {
            if this.needs_refresh {
                Self::refresh_once(&this).await;
            }
            loop {
                tokio::time::sleep(interval).await;
                Self::refresh_once(&this).await;
            }
        });
    }

    /// Download, parse, write to cache, and swap in the new matcher.
    async fn refresh_once(this: &std::sync::Arc<Self>) {
        match Self::fetch_and_cache(
            &this.url,
            &this.cache_path,
            &this.source_name,
            &this.dns_plain,
        )
        .await
        {
            Ok(matcher) => {
                *this.matcher.write().await = Some(matcher);
                log::info!("Refreshed geo rule set: {}", this.source_name);
            },
            Err(e) => {
                log::warn!(
                    "Failed to refresh geo rule set {}: {e}",
                    this.source_name
                );
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_range_v4() {
        let range = IpRange {
            from: 0x0100_0000u128,
            to: 0x0100_00ffu128,
        };
        assert!(range.contains(&IpAddr::V4(std::net::Ipv4Addr::new(1, 0, 0, 1))));
        assert!(
            !range.contains(&IpAddr::V4(std::net::Ipv4Addr::new(2, 0, 0, 1)))
        );
    }

    #[test]
    fn test_uvarint() {
        let buf = [0x01];
        let mut pos = 0;
        assert_eq!(read_uvarint(&buf, &mut pos), Some(1));
        assert_eq!(pos, 1);

        let buf = [0x80, 0x01];
        let mut pos = 0;
        assert_eq!(read_uvarint(&buf, &mut pos), Some(128));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_ip_bytes_to_u128() {
        let v4 = [10, 0, 0, 1];
        let val = ip_bytes_to_u128(&v4);
        assert_eq!(val, u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1)) as u128);

        let v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let val = ip_bytes_to_u128(&v6);
        assert_eq!(
            val,
            u128::from(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn test_read_string_list() {
        let buf = [
            0x02, 0x05, b'h', b'e', b'l', b'l', b'o', 0x05, b'w', b'o', b'r',
            b'l', b'd',
        ];
        let mut pos = 0;
        let list = read_string_list(&buf, &mut pos).unwrap();
        assert_eq!(list, vec!["hello", "world"]);
    }

    #[test]
    fn test_extract_source_name() {
        assert_eq!(
            extract_source_name(
                "https://example.com/geosite/geolocation-!cn.srs"
            ),
            "geosite:geolocation-!cn"
        );
        assert_eq!(
            extract_source_name("https://example.com/geoip/cn.srs"),
            "geoip:cn"
        );
        assert_eq!(
            extract_source_name(
                "https://example.com/path/geosite/ads.srs?token=abc"
            ),
            "geosite:ads"
        );
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(
            parse_duration_str("3d"),
            Some(std::time::Duration::from_secs(3 * 86400))
        );
        assert_eq!(
            parse_duration_str("24h"),
            Some(std::time::Duration::from_secs(24 * 3600))
        );
        assert_eq!(
            parse_duration_str("30m"),
            Some(std::time::Duration::from_secs(30 * 60))
        );
        assert_eq!(parse_duration_str(""), None);
        assert_eq!(
            parse_duration_str("abc"),
            Some(std::time::Duration::from_secs(3 * 86400))
        );
    }
}
