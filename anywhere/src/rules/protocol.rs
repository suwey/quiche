//! Protocol matching — unifies port-based shorthand and sniff-based detection.
//!
//! The `protocol` field in rule config can be:
//! - A name like `"bittorrent"` → port-based match + sniff-based match
//! - An inline port spec like `"both:443"` or `"tcp:80,443"` → port-based only
//! - A sniff-only spec like `"sniff:ssh"` → sniff-based only
//! - A plain name like `"ssh"` → sniff-based only (no known port mapping)
//!
//! When a rule has protocol matches, **any** match condition hitting is enough
//! for that dimension to pass (OR semantics within the protocol dimension).

use crate::inbound::Network;

/// Information from traffic sniffing, passed into rule matching.
#[derive(Debug, Clone, Default)]
pub struct SniffInfo {
    /// Sniffed domain (TLS SNI / HTTP Host / QUIC SNI / DNS query name).
    pub domain: Option<String>,
    /// Sniffed protocol name: "tls", "http", "quic", "dns", "bittorrent",
    /// "ssh", "rdp", "stun", "dtls", "ntp".
    pub protocol: Option<String>,
    /// Sniffed client fingerprint (e.g. "chromium", "firefox", "safari").
    pub client: Option<String>,
}

impl SniffInfo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_sniff_result(domain: Option<String>, protocol: &str) -> Self {
        Self {
            domain,
            protocol: Some(protocol.to_string()),
            client: None,
        }
    }
}

/// A single protocol match condition.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolMatch {
    /// Match by network type + port range (the classic shorthand).
    PortRange { network: Network, range: (u16, u16) },
    /// Match by sniffed protocol name.
    Sniffed(String),
}

/// Parsed protocol field from config — a list of OR conditions.
pub fn parse_protocol(s: &str) -> Vec<ProtocolMatch> {
    // Try inline port syntax first: "tcp:80", "both:443", "udp:53,80"
    if let Some(result) = parse_inline(s) {
        return result;
    }

    // "sniff:name" → sniff-only match
    if let Some(name) = s.strip_prefix("sniff:") {
        return vec![ProtocolMatch::Sniffed(name.to_string())];
    }

    // Known protocol names → port mapping + sniff match
    let mut result = Vec::new();
    for &(name, net, lo, hi) in PROTOCOL_PORTS {
        if name == s {
            result.push(ProtocolMatch::PortRange {
                network: net,
                range: (lo, hi),
            });
        }
    }
    // Always add sniff match for known protocol names so that
    // e.g. BT on port 443 is still detected.
    if KNOWN_PROTOCOLS.contains(&s) {
        result.push(ProtocolMatch::Sniffed(s.to_string()));
    }

    if result.is_empty() {
        log::warn!("Unknown protocol '{s}', skipping rule");
    }

    result
}

/// Known protocol names that can be sniffed.
pub const KNOWN_PROTOCOLS: &[&str] = &[
    "tls",
    "http",
    "quic",
    "dns",
    "bittorrent",
    "ssh",
    "rdp",
    "stun",
    "dtls",
    "ntp",
];

/// Built-in protocol → port mappings.
const PROTOCOL_PORTS: &[(&str, Network, u16, u16)] = &[
    // BitTorrent
    ("bittorrent", Network::Tcp, 6881, 6889),
    ("bittorrent", Network::Udp, 6881, 6881),
    // STUN / TURN
    ("stun", Network::Udp, 3478, 3479),
    ("stun", Network::Tcp, 3478, 3479),
    // SSH
    ("ssh", Network::Tcp, 22, 22),
    // RDP
    ("rdp", Network::Tcp, 3389, 3389),
    ("rdp", Network::Udp, 3389, 3389),
    // NTP
    ("ntp", Network::Udp, 123, 123),
    // DTLS
    ("dtls", Network::Udp, 443, 443),
    // QUIC (for port-based fallback, though sniffing is primary)
    ("quic", Network::Udp, 443, 443),
    // DNS
    ("dns", Network::Udp, 53, 53),
    ("dns", Network::Tcp, 53, 53),
];

/// Check if a protocol string would produce any match conditions.
pub fn is_valid_protocol(s: &str) -> bool {
    if s.contains(':') {
        return parse_inline(s).map(|v| !v.is_empty()).unwrap_or(false);
    }
    KNOWN_PROTOCOLS.contains(&s)
}

// ---------------------------------------------------------------------------
// Inline parsing (ported from the old parse_protocol_inline)
// ---------------------------------------------------------------------------

/// Parse inline protocol+port syntax like `"both:443"`, `"tcp:80,1132"`,
/// or `"udp:53"`.
///
/// - One value after the colon = single port
/// - Two comma-separated values = inclusive range `lo,hi`
///
/// Returns `Some(vec![])` for invalid inline syntax (already warned).
/// Returns `None` when there's no `:` separator (caller tries name lookup).
fn parse_inline(s: &str) -> Option<Vec<ProtocolMatch>> {
    let (proto, ports_str) = s.split_once(':')?;

    // "sniff:xxx" is handled by caller, not here.
    if proto == "sniff" {
        return None;
    }

    let nets: &[Network] = match proto.to_ascii_lowercase().as_str() {
        "tcp" => &[Network::Tcp],
        "udp" => &[Network::Udp],
        "both" => &[Network::Tcp, Network::Udp],
        _ => {
            log::warn!(
                "Unknown protocol '{proto}' in '{s}', expected tcp/udp/both"
            );
            return Some(vec![]);
        },
    };

    let ports: Vec<&str> = ports_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if ports.is_empty() {
        log::warn!("No valid ports in protocol '{s}'");
        return Some(vec![]);
    }

    if ports.len() > 2 {
        log::warn!(
            "Too many ports in protocol '{s}', expected 1 or 2 (use '-' for range)"
        );
        return Some(vec![]);
    }

    let p1: u16 = match ports[0].parse() {
        Ok(p) => p,
        Err(_) => {
            log::warn!("Invalid port '{}' in protocol '{}'", ports[0], s);
            return Some(vec![]);
        },
    };

    let range = if ports.len() == 2 {
        let p2: u16 = match ports[1].parse() {
            Ok(p) => p,
            Err(_) => {
                log::warn!("Invalid port '{}' in protocol '{}'", ports[1], s);
                return Some(vec![]);
            },
        };
        if p1 <= p2 { (p1, p2) } else { (p2, p1) }
    } else {
        (p1, p1)
    };

    let mut result = Vec::new();
    for &net in nets {
        result.push(ProtocolMatch::PortRange {
            network: net,
            range,
        });
    }

    Some(result)
}

/// Check if any protocol match condition is satisfied.
pub fn protocol_matches(
    matches: &[ProtocolMatch], network: Network, port: u16,
    sniff: Option<&SniffInfo>,
) -> bool {
    matches.iter().any(|m| match m {
        ProtocolMatch::PortRange { network: mn, range } => {
            *mn == network && port >= range.0 && port <= range.1
        },
        ProtocolMatch::Sniffed(name) => {
            sniff.and_then(|s| s.protocol.as_deref()) == Some(name.as_str())
        },
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_both_single_port() {
        let result = parse_protocol("both:443");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&ProtocolMatch::PortRange {
            network: Network::Tcp,
            range: (443, 443)
        }));
        assert!(result.contains(&ProtocolMatch::PortRange {
            network: Network::Udp,
            range: (443, 443)
        }));
    }

    #[test]
    fn inline_tcp_port_range() {
        let result = parse_protocol("tcp:80,443");
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ProtocolMatch::PortRange {
                network: Network::Tcp,
                range: (80, 443)
            }
        );
    }

    #[test]
    fn inline_udp_single_port() {
        let result = parse_protocol("udp:53");
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ProtocolMatch::PortRange {
                network: Network::Udp,
                range: (53, 53)
            }
        );
    }

    #[test]
    fn sniff_prefix() {
        let result = parse_protocol("sniff:ssh");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ProtocolMatch::Sniffed("ssh".into()));
    }

    #[test]
    fn known_name_bittorrent() {
        let result = parse_protocol("bittorrent");
        // port ranges + sniff match
        assert!(result.len() >= 3); // 2 port ranges + 1 sniff
        assert!(result.iter().any(|m| matches!(
            m,
            ProtocolMatch::Sniffed(n) if n == "bittorrent"
        )));
    }

    #[test]
    fn known_name_ssh() {
        // SSH has port 22 + sniff match
        let result = parse_protocol("ssh");
        assert!(result.len() >= 1);
        assert!(result.iter().any(|m| matches!(
            m,
            ProtocolMatch::Sniffed(n) if n == "ssh"
        )));
    }

    #[test]
    fn unknown_name_returns_empty() {
        let result = parse_protocol("foobar");
        assert!(result.is_empty());
    }

    #[test]
    fn inline_reversed_range() {
        let result = parse_protocol("tcp:443,80");
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ProtocolMatch::PortRange {
                network: Network::Tcp,
                range: (80, 443)
            }
        );
    }

    #[test]
    fn inline_invalid_port() {
        let result = parse_protocol("tcp:abc");
        assert!(result.is_empty());
    }

    #[test]
    fn inline_too_many_ports() {
        let result = parse_protocol("tcp:80,443,8080");
        assert!(result.is_empty());
    }

    // --- protocol_matches tests ---

    #[test]
    fn matches_port_range() {
        let matches = parse_protocol("tcp:80,443");
        assert!(protocol_matches(&matches, Network::Tcp, 80, None));
        assert!(protocol_matches(&matches, Network::Tcp, 443, None));
        assert!(!protocol_matches(&matches, Network::Tcp, 8080, None));
        assert!(!protocol_matches(&matches, Network::Udp, 80, None));
    }

    #[test]
    fn matches_sniffed() {
        let matches = parse_protocol("sniff:ssh");
        let sniff = SniffInfo {
            protocol: Some("ssh".into()),
            ..Default::default()
        };
        assert!(protocol_matches(&matches, Network::Tcp, 22, Some(&sniff)));
        assert!(!protocol_matches(&matches, Network::Tcp, 22, None));
    }

    #[test]
    fn matches_bittorrent_port_or_sniff() {
        let matches = parse_protocol("bittorrent");
        // Port match
        assert!(protocol_matches(&matches, Network::Tcp, 6881, None));
        // Sniff match (BT on port 443)
        let sniff = SniffInfo {
            protocol: Some("bittorrent".into()),
            ..Default::default()
        };
        assert!(protocol_matches(&matches, Network::Tcp, 443, Some(&sniff)));
        // No match
        assert!(!protocol_matches(&matches, Network::Tcp, 443, None));
    }
}
