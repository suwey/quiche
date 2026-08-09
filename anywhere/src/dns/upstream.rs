//! DNS upstream configuration parsing.
//!
//! Each upstream entry is either a plain UDP/53 server (IP literal) or a
//! DNS-over-HTTPS (RFC 8484) endpoint. This module handles parsing raw
//! config strings into the [`Upstream`] enum and ordering them so DoH
//! entries take priority over plain UDP.

use crate::inbound::Address;
use crate::inbound::Destination;

/// A resolved DNS upstream.
#[derive(Clone, Debug)]
pub enum Upstream {
    /// Plain UDP DNS at an IP:port (default port 53).
    Plain(Destination),
    /// DNS-over-HTTPS endpoint parsed from a `https://host[:port][/path]` URL.
    /// `path` defaults to `/dns-query` when omitted. `host` is a domain (or
    /// IP literal) used for SNI and the HTTP `:authority`.
    Doh {
        host: String,
        path: String,
        port: u16,
    },
}

impl Upstream {
    pub fn is_doh(&self) -> bool {
        matches!(self, Upstream::Doh { .. })
    }
}

/// Parse one upstream entry.
///
/// - `https://host[:port][/path]` → [`Upstream::Doh`] (path defaults to
///   `/dns-query`).
/// - `ip` / `ip:port` (v4 or v6) → [`Upstream::Plain`], default port 53.
///
/// Other schemes (`tls://`, `quic://`, etc.) are rejected here with a
/// clear message so the user knows exactly what's wrong instead of
/// getting a generic "not an IP literal" error downstream.
pub fn parse_upstream(s: &str) -> Result<Upstream, String> {
    let s = s.trim();

    if let Some(rest) = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")) {
        return parse_doh_url(rest).map(|(host, path, port)| Upstream::Doh { host, path, port });
    }

    // Reject known-but-unsupported schemes early with a helpful message.
    if let Some(scheme) = s
        .split("://")
        .next()
        .filter(|_| s.contains("://"))
    {
        return Err(format!(
            "dns upstream '{s}': scheme '{scheme}://' is not supported. \
             Use DoH (https://host/dns-query) or a plain IP address instead"
        ));
    }

    // Plain UDP/53. Accept "ip" or "ip:port"; default port 53.
    //
    // IPv6 literals are ambiguous with `host:port` splitting because they
    // contain colons. Strategy:
    //   1. If the entire string parses as an IPv6 address, it's a bare
    //      address with default port 53.
    //   2. Otherwise, if it starts with '[' it's `[ipv6]:port` (bracketed).
    //   3. Otherwise, try `host:port` split on the last ':' — but only
    //      accept it if `host` is a valid IPv4 or IPv6 address (handles
    //      `8.8.8.8:53` and `::1:53` is NOT valid since `::1` already
    //      consumed the colon). For IPv6 with explicit port, require
    //      brackets.
    //   4. Fall back to treating the whole string as a hostname (which will
    //      fail the IP-literal check below).
    let (host, port) = if s.parse::<std::net::Ipv6Addr>().is_ok() {
        // Bare IPv6 literal (e.g. "::1", "2001:db8::1").
        (s, 53u16)
    } else if let Some(rest) = s.strip_prefix('[') {
        // Bracketed IPv6: [::1] or [::1]:53
        if let Some(close) = rest.find(']') {
            let host = &rest[..close];
            let tail = &rest[close + 1..];
            let port = tail
                .strip_prefix(':')
                .map(|p| p.parse::<u16>().map_err(|e| format!("invalid port: {e}")))
                .transpose()?
                .unwrap_or(53);
            (host, port)
        } else {
            (s, 53u16) // malformed bracket — let IP parse fail below
        }
    } else if let Some((h, p)) = s.rsplit_once(':') {
        // `host:port` — only accept if host is IPv4 (IPv6 requires brackets).
        if let Ok(port) = p.parse::<u16>() {
            (h, port)
        } else {
            (s, 53u16)
        }
    } else {
        (s, 53u16)
    };
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(Upstream::Plain(Destination::new(
            Address::Ipv4(v4.octets()),
            port,
        )));
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return Ok(Upstream::Plain(Destination::new(
            Address::Ipv6(v6.octets()),
            port,
        )));
    }
    Err(format!(
        "dns upstream '{s}': not a valid IP address or https:// URL. \
         Use DoH (e.g. https://dns.alidns.com/dns-query) or a plain IP (e.g. 223.5.5.5)"
    ))
}

/// Parse the host/path/port of a DoH URL (the `scheme://` prefix is already
/// stripped). Returns `(host, path, port)`. Path defaults to `/dns-query`;
/// port defaults to 443.
fn parse_doh_url(rest: &str) -> Result<(String, String, u16), String> {
    // Split authority from path at the first '/'.
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/dns-query"),
    };
    let path = if path == "/" { "/dns-query".to_string() } else { path.to_string() };

    // Authority is host[:port]. IPv6 literals are bracketed, e.g. [::1]:443.
    let (host, port) = if let Some(authority) = authority.strip_prefix('[') {
        let close = authority
            .find(']')
            .ok_or_else(|| format!("missing ']' in IPv6 DoH host '{rest}'"))?;
        let host = &authority[..close];
        let tail = &authority[close + 1..];
        let port = tail
            .strip_prefix(':')
            .map(|p| p.parse::<u16>().map_err(|e| format!("invalid DoH port: {e}")))
            .transpose()?
            .unwrap_or(443);
        (host.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|e| format!("invalid DoH port: {e}"))?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), 443u16)
    };

    if host.is_empty() {
        return Err(format!("DoH URL missing host: '{rest}'"));
    }
    Ok((host, path, port))
}

/// Parse a list of raw upstream strings into [`Upstream`]s, ordered so that
/// DoH entries come first (in declared order) followed by plain entries (in
/// declared order). This makes configured DoH the preferred path while plain
/// UDP remains as fallback.
pub fn parse_upstreams_ordered(raw: &[String]) -> Result<Vec<Upstream>, String> {
    let mut doh = Vec::new();
    let mut plain = Vec::new();
    for s in raw {
        match parse_upstream(s)? {
            u @ Upstream::Doh { .. } => doh.push(u),
            u @ Upstream::Plain(_) => plain.push(u),
        }
    }
    doh.extend(plain);
    Ok(doh)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_upstream_plain_ip() {
        match parse_upstream("8.8.8.8").unwrap() {
            Upstream::Plain(dest) => {
                assert_eq!(dest.port, 53);
                assert_eq!(dest.address, Address::Ipv4([8, 8, 8, 8]));
            }
            Upstream::Doh { .. } => panic!("expected Plain"),
        }
    }

    #[test]
    fn parse_upstream_plain_ip_port() {
        match parse_upstream("1.1.1.1:5353").unwrap() {
            Upstream::Plain(dest) => {
                assert_eq!(dest.port, 5353);
            }
            Upstream::Doh { .. } => panic!("expected Plain"),
        }
    }

    #[test]
    fn parse_upstream_plain_ipv6_bare() {
        let up = parse_upstream("::1").unwrap();
        match up {
            Upstream::Plain(dest) => {
                assert_eq!(dest.port, 53);
                assert_eq!(dest.address, Address::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
            }
            Upstream::Doh { .. } => panic!("expected Plain"),
        }
    }

    #[test]
    fn parse_upstream_plain_ipv6_full() {
        let up = parse_upstream("2001:db8::1").unwrap();
        match up {
            Upstream::Plain(dest) => {
                assert_eq!(dest.port, 53);
                assert_eq!(dest.address, Address::Ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]));
            }
            Upstream::Doh { .. } => panic!("expected Plain"),
        }
    }

    #[test]
    fn parse_upstream_plain_ipv6_bracketed_with_port() {
        let up = parse_upstream("[::1]:5353").unwrap();
        match up {
            Upstream::Plain(dest) => {
                assert_eq!(dest.port, 5353);
                assert_eq!(dest.address, Address::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
            }
            Upstream::Doh { .. } => panic!("expected Plain"),
        }
    }

    #[test]
    fn parse_upstream_plain_ipv6_bracketed_no_port() {
        let up = parse_upstream("[::1]").unwrap();
        match up {
            Upstream::Plain(dest) => {
                assert_eq!(dest.port, 53);
                assert_eq!(dest.address, Address::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
            }
            Upstream::Doh { .. } => panic!("expected Plain"),
        }
    }

    #[test]
    fn parse_upstream_doh_url() {
        match parse_upstream("https://dns.google/dns-query").unwrap() {
            Upstream::Doh { host, path, port } => {
                assert_eq!(host, "dns.google");
                assert_eq!(path, "/dns-query");
                assert_eq!(port, 443);
            }
            Upstream::Plain(_) => panic!("expected Doh"),
        }
    }

    #[test]
    fn parse_upstream_doh_url_default_path() {
        match parse_upstream("https://dns.alidns.com").unwrap() {
            Upstream::Doh { host, path, port } => {
                assert_eq!(host, "dns.alidns.com");
                assert_eq!(path, "/dns-query");
                assert_eq!(port, 443);
            }
            Upstream::Plain(_) => panic!("expected Doh"),
        }
    }

    #[test]
    fn parse_upstream_doh_url_custom_port() {
        match parse_upstream("https://dns.example:8443/custom").unwrap() {
            Upstream::Doh { host, path, port } => {
                assert_eq!(host, "dns.example");
                assert_eq!(path, "/custom");
                assert_eq!(port, 8443);
            }
            Upstream::Plain(_) => panic!("expected Doh"),
        }
    }

    #[test]
    fn parse_upstream_doh_url_root_slash_becomes_dns_query() {
        match parse_upstream("https://dns.google/").unwrap() {
            Upstream::Doh { ref path, .. } => {
                assert_eq!(path, "/dns-query");
            }
            Upstream::Plain(_) => panic!("expected Doh"),
        }
    }

    #[test]
    fn parse_upstream_rejects_domain() {
        assert!(parse_upstream("dns.example").is_err());
    }

    #[test]
    fn parse_upstream_rejects_tls_scheme() {
        let err = parse_upstream("tls://dot.pub:853").unwrap_err();
        assert!(err.contains("not supported"), "got: {err}");
    }

    #[test]
    fn parse_upstream_rejects_quic_scheme() {
        let err = parse_upstream("quic://dns.adguard.com").unwrap_err();
        assert!(err.contains("not supported"), "got: {err}");
    }

    #[test]
    fn parse_upstream_rejects_tls_scheme_domain() {
        let err = parse_upstream("tls://dns.alidns.com:853").unwrap_err();
        assert!(err.contains("not supported"), "got: {err}");
    }

    #[test]
    fn parse_upstream_rejects_hostname_port() {
        // "dot.pub:853" — looks like host:port but host is not an IP
        let err = parse_upstream("dot.pub:853").unwrap_err();
        assert!(err.contains("not a valid IP"), "got: {err}");
    }

    #[test]
    fn parse_upstream_rejects_bare_hostname() {
        let err = parse_upstream("dns.google").unwrap_err();
        assert!(err.contains("not a valid IP"), "got: {err}");
    }

    #[test]
    fn parse_upstreams_ordered_doh_first() {
        let ups = parse_upstreams_ordered(&[
            "223.5.5.5".to_string(),
            "https://dns.google/dns-query".to_string(),
            "1.1.1.1".to_string(),
        ])
        .unwrap();
        assert!(ups[0].is_doh());
        assert!(!ups[1].is_doh());
        assert!(!ups[2].is_doh());
        match &ups[0] {
            Upstream::Doh { host, .. } => assert_eq!(host, "dns.google"),
            _ => panic!("expected Doh"),
        }
    }

    #[test]
    fn parse_upstreams_ordered_all_plain() {
        let ups = parse_upstreams_ordered(&[
            "8.8.8.8".to_string(),
            "1.1.1.1".to_string(),
        ])
        .unwrap();
        assert_eq!(ups.len(), 2);
        assert!(!ups[0].is_doh());
        assert!(!ups[1].is_doh());
    }
}
