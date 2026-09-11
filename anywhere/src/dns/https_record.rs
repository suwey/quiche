// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! DNS HTTPS resource record (type 65, RFC 9460) — echconfig extraction.
//!
//! HTTPS records are how browsers bootstrap ECH: the record's `echconfig`
//! SvcParam (key 5) carries the server's ECHConfigList. anywhere uses the
//! same bootstrap for `ech = true` outbounds, resolved through the configured
//! DNS upstreams (DoH first, plain UDP fallback).

use crate::dns::doh::DohClient;
use crate::dns::upstream::{parse_upstreams_ordered, Upstream};
use crate::dns::wire::build_dns_query;
use std::time::Duration;

const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Plain UDP resolver used as the DoH bootstrap (to resolve the DoH server
/// hostname itself) and as the last-resort fallback. Shared with the TUN
/// DNS hijack, which injects the same address for the same purpose.
pub const BOOTSTRAP_PLAIN_UPSTREAM: &str = "223.5.5.5";

/// Privacy-first DoH bootstrap list for the ECH config lookup. These are
/// queried (encrypted) before any configured plaintext upstream, so the
/// interest in a host's ECH config leaks to nobody. Chinese-network-friendly
/// endpoints, mirroring the defaults commented in `DnsConfig::default_direct`.
pub const ECH_BOOTSTRAP_DOH_UPSTREAMS: &[&str] = &[
    "https://doh.pub/dns-query",
    "https://dns.alidns.com/dns-query",
    "https://doh.360.cn/dns-query",
];

/// Shared bootstrap rule (also used by the TUN DNS hijack): when an upstream
/// list carries no plain IP resolver, append the default bootstrap so DoH
/// hostnames can be resolved and DoH failures have a UDP fallback.
pub fn with_plain_bootstrap(mut upstreams: Vec<Upstream>) -> Vec<Upstream> {
    if !upstreams.iter().any(|u| matches!(u, Upstream::Plain(_))) {
        if let Ok(u) = crate::dns::upstream::parse_upstream(BOOTSTRAP_PLAIN_UPSTREAM)
        {
            upstreams.push(u);
        }
    }
    upstreams
}

/// Upstream candidate order for the ECH config lookup:
/// 1. the embedded DoH bootstrap trio (encrypted — the interest in a host's
///    ECH config leaks to nobody),
/// 2. the `[dns].direct` list as configured (user-configured servers, or the
///    plaintext defaults), with the plain bootstrap injected for DoH hostname
///    resolution and last-resort fallback.
pub fn ech_candidate_upstreams(dns_direct: &[String]) -> Vec<Upstream> {
    let mut candidates = Vec::new();
    for s in ECH_BOOTSTRAP_DOH_UPSTREAMS {
        if let Ok(u) = crate::dns::upstream::parse_upstream(s) {
            candidates.push(u);
        }
    }
    let direct = with_plain_bootstrap(
        parse_upstreams_ordered(dns_direct).unwrap_or_default(),
    );
    candidates.extend(direct);
    candidates
}

/// Query `host`'s HTTPS record for an echconfig via the configured upstreams
/// (DoH first, then plain UDP), returning the raw ECHConfigList bytes
/// (including its outer u16 length — ready for `SSL_set1_ech_config_list`).
pub async fn resolve_echconfig(host: &str, dns_direct: &[String]) -> Option<Vec<u8>> {
    let query = build_dns_query(host, 65);
    let candidates = ech_candidate_upstreams(dns_direct);
    // Bootstrap resolvers for the DoH hosts themselves (the plain candidates;
    // priority-independent — this is plumbing, not order).
    let bootstrap: Vec<crate::inbound::Destination> = candidates
        .iter()
        .filter_map(|u| match u {
            Upstream::Plain(dest) => Some(dest.clone()),
            _ => None,
        })
        .collect();
    let client = DohClient::new(bootstrap);

    for up in &candidates {
        match up {
            Upstream::Doh { .. } => {
                if let Some(resp) = client.resolve(&query, up).await {
                    if let Some(config) = parse_https_echconfig(&resp) {
                        return Some(config);
                    }
                }
            },
            Upstream::Plain(_) => {
                // Plaintext fallback: the type-65 query is visible to the
                // resolver path, but it reveals only that `host` was resolved
                // — which the A query for the same connection reveals anyway.
                if let Some(resp) = udp_dns_query(&query, up).await {
                    if let Some(config) = parse_https_echconfig(&resp) {
                        return Some(config);
                    }
                }
            },
        }
    }
    None
}

fn destination_socket_addr(dest: &crate::inbound::Destination) -> Option<std::net::SocketAddr> {
    use crate::inbound::Address;
    let ip = match &dest.address {
        Address::Ipv4(o) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(*o)),
        Address::Ipv6(o) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(*o)),
        Address::Domain(_) => return None,
    };
    Some(std::net::SocketAddr::new(ip, dest.port as u16))
}

/// One plain-UDP DNS exchange with a short timeout.
async fn udp_dns_query(query: &[u8], up: &Upstream) -> Option<Vec<u8>> {
    let dest = match up {
        Upstream::Plain(dest) => dest,
        _ => return None,
    };
    let addr = match destination_socket_addr(dest) {
        Some(addr) => addr,
        None => {
            let host = match &dest.address {
                crate::inbound::Address::Domain(d) => d.clone(),
                _ => return None,
            };
            tokio::net::lookup_host((host.as_str(), dest.port as u16))
                .await
                .ok()?
                .next()?
        },
    };

    // bind_udp_bypass: in TUN mode a plain socket would be routed into the
    // tunnel (loop). Bypass keeps the bootstrap query on the physical path.
    let socket =
        crate::outbound::common::bind_udp_bypass("0.0.0.0:0".parse().ok()?)
            .await
            .ok()?;
    socket.connect(addr).await.ok()?;
    socket.send(query).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(DNS_QUERY_TIMEOUT, socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Parse a raw DNS response and extract the ECHConfigList from the first
/// HTTPS (type 65) answer record carrying an `echconfig` SvcParam (key 5).
/// The returned bytes are the SvcParam value verbatim — the ECHConfigList
/// including its outer u16 length — ready for `SSL_set1_ech_config_list`.
pub fn parse_https_echconfig(resp: &[u8]) -> Option<Vec<u8>> {
    if resp.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut pos = 12usize;

    // Skip question section (name + qtype + qclass).
    for _ in 0..qdcount {
        pos = skip_dns_name(resp, pos)?;
        pos = pos.checked_add(4)?;
    }

    // Answer records.
    for _ in 0..ancount {
        pos = skip_dns_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start.checked_add(rdlength)?;
        if rdata_end > resp.len() {
            return None;
        }
        if rtype == 65 {
            if let Some(config) = https_rdata_ech_config(&resp[rdata_start..rdata_end]) {
                return Some(config);
            }
        }
        pos = rdata_end;
    }
    None
}

/// Extract the `echconfig` SvcParam (key 5) from HTTPS record rdata:
/// `priority(2) target-name svcparams{ key(2) len(2) value }`.
fn https_rdata_ech_config(rdata: &[u8]) -> Option<Vec<u8>> {
    if rdata.len() < 2 {
        return None;
    }
    let mut pos = 2usize; // skip priority
    pos = skip_dns_name(rdata, pos)?;
    while pos + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        let value_start = pos + 4;
        let value_end = value_start.checked_add(len)?;
        if value_end > rdata.len() {
            return None;
        }
        if key == 5 && len > 0 {
            return Some(rdata[value_start..value_end].to_vec());
        }
        pos = value_end;
    }
    None
}

/// Skip a (possibly compressed) DNS name starting at `pos`, returning the
/// offset just past it in the original stream. Compression pointers must jump
/// strictly backward; a loop guard caps the chain.
fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    let start = pos;
    let mut cursor = pos;
    let mut jumps = 0usize;
    loop {
        let len = *buf.get(cursor)? as usize;
        match len & 0xC0 {
            0xC0 => {
                if cursor + 1 >= buf.len() {
                    return None;
                }
                jumps += 1;
                if jumps > 32 {
                    return None; // pointer loop guard
                }
                let target =
                    (((len & 0x3F) as usize) << 8) | buf[cursor + 1] as usize;
                if target >= cursor {
                    return None; // pointers must point strictly backward
                }
                if cursor == start {
                    pos = start + 2; // top-level pointer: the name occupies 2 bytes here
                }
                cursor = target;
            },
            0x40 | 0x80 => return None, // reserved
            _ => {
                if len == 0 {
                    // after a jump, every subsequent byte lives before `start`,
                    // so the name's extent in the original stream stays `pos`
                    return Some(if cursor >= start { cursor + 1 } else { pos });
                }
                cursor += 1 + len;
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS response with one HTTPS record carrying an
    /// echconfig SvcParam (no compression).
    fn build_https_response(ech_value: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&[0x00, 0x01]); // txn id
        r.extend_from_slice(&[0x81, 0x80]); // flags: response, RD, RA
        r.extend_from_slice(&[0x00, 0x01]); // qdcount
        r.extend_from_slice(&[0x00, 0x01]); // ancount
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ns/ar
        // question: node.example.com IN HTTPS
        for label in ["node", "example", "com"] {
            r.push(label.len() as u8);
            r.extend_from_slice(label.as_bytes());
        }
        r.push(0);
        r.extend_from_slice(&65u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        // answer: same name (uncompressed), type 65, class IN, ttl, rdlen
        for label in ["node", "example", "com"] {
            r.push(label.len() as u8);
            r.extend_from_slice(label.as_bytes());
        }
        r.push(0);
        r.extend_from_slice(&65u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 60]); // ttl
        let rdlen_pos = r.len();
        // rdata: priority(2) target(root) svcparams
        let mut rdata = vec![0x00, 0x01]; // priority
        rdata.push(0); // target = root
        rdata.extend_from_slice(&5u16.to_be_bytes()); // key = echconfig
        rdata.extend_from_slice(&(ech_value.len() as u16).to_be_bytes());
        rdata.extend_from_slice(ech_value);
        r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(&rdata);
        assert_eq!(r.len(), rdlen_pos + 2 + rdata.len());
        r
    }

    #[test]
    fn ech_candidates_privacy_first_then_configured() {
        // default [dns].direct (223/114): DoH trio leads, plaintext follows,
        // and the plain bootstrap is present for DoH hostname resolution.
        let candidates = ech_candidate_upstreams(&[
            "223.5.5.5".to_string(),
            "114.114.114.114".to_string(),
        ]);
        let is_doh = |u: &Upstream| matches!(u, Upstream::Doh { .. });
        assert_eq!(candidates.len(), 5);
        assert!(candidates.iter().take(3).all(is_doh));
        assert!(candidates.iter().skip(3).all(|u| !is_doh(u)));
    }

    #[test]
    fn with_plain_bootstrap_injects_only_when_missing() {
        let doh_only =
            vec![crate::dns::upstream::parse_upstream("https://doh.pub/dns-query")
                .unwrap()];
        let with = with_plain_bootstrap(doh_only);
        assert_eq!(with.len(), 2);
        assert!(matches!(with[1], Upstream::Plain(_)));

        // a list that already carries a plain upstream is untouched
        let mixed = vec![
            crate::dns::upstream::parse_upstream("https://doh.pub/dns-query")
                .unwrap(),
            crate::dns::upstream::parse_upstream("114.114.114.114").unwrap(),
        ];
        let mixed_len = mixed.len();
        assert_eq!(with_plain_bootstrap(mixed).len(), mixed_len);
    }

    #[test]
    fn parse_https_echconfig_roundtrip() {
        // openrung's embedded bootstrap list doubles as a realistic value
        let ech_value = crate::ech::OPENRUNG_CLOUDFLARE_ECH_CONFIG_LIST.to_vec();
        let resp = build_https_response(&ech_value);
        assert_eq!(parse_https_echconfig(&resp), Some(ech_value));
    }

    #[test]
    fn parse_https_echconfig_absent_param() {
        // HTTPS record without an echconfig SvcParam → None
        let mut r = Vec::new();
        r.extend_from_slice(&[0x00, 0x01, 0x81, 0x80]);
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        for label in ["node", "example", "com"] {
            r.push(label.len() as u8);
            r.extend_from_slice(label.as_bytes());
        }
        r.push(0);
        r.extend_from_slice(&65u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        for label in ["node", "example", "com"] {
            r.push(label.len() as u8);
            r.extend_from_slice(label.as_bytes());
        }
        r.push(0);
        r.extend_from_slice(&65u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 60]);
        let mut rdata = vec![0x00, 0x01, 0x00]; // priority + root target
        rdata.extend_from_slice(&1u16.to_be_bytes()); // key = alpn (1)
        rdata.extend_from_slice(&2u16.to_be_bytes());
        rdata.extend_from_slice(b"h3");
        r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(&rdata);
        assert_eq!(parse_https_echconfig(&r), None);
    }

    #[test]
    fn parse_handles_compressed_names() {
        // answer name is a compression pointer back to the question name
        let mut r = Vec::new();
        r.extend_from_slice(&[0x00, 0x01, 0x81, 0x80]);
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        let question_name_pos = r.len();
        for label in ["node", "example", "com"] {
            r.push(label.len() as u8);
            r.extend_from_slice(label.as_bytes());
        }
        r.push(0);
        r.extend_from_slice(&65u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        // answer: pointer to question name
        r.push(0xC0);
        r.push(question_name_pos as u8);
        r.extend_from_slice(&65u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 60]);
        let ech_value = vec![0x00, 0x10];
        let mut rdata = vec![0x00, 0x01, 0x00];
        rdata.extend_from_slice(&5u16.to_be_bytes());
        rdata.extend_from_slice(&(ech_value.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&ech_value);
        r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(&rdata);
        assert_eq!(parse_https_echconfig(&r), Some(ech_value));
    }

    #[test]
    fn parse_rejects_pointer_loops() {
        // an answer name with a self-referential pointer must not hang
        let mut r = vec![0x00, 0x01, 0x81, 0x80];
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        let pos = r.len();
        r.push(0xC0);
        r.push(pos as u8); // points at itself
        r.extend_from_slice(&65u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 0]); // rdlength 0
        assert_eq!(parse_https_echconfig(&r), None);
    }
}
