use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

use crate::config::OutboundConfig;
use crate::config::RuleConfig;
use crate::inbound::Address;
use crate::inbound::Destination;
use crate::inbound::Network;
use crate::rules::geo::GeoMatcher;
use crate::rules::geo::GeoRuleSet;

pub mod geo;
pub use geo::DomainMatcher;
pub use geo::IpRange;
pub use geo::ParsedRuleSet;
pub use geo::SrsRuleSet;
const PAYLOAD_DISPLAY_ITEMS: usize = 4;

pub use geo::read_srs_bytes;

/// Protocol shortcuts — expand to known port/network combos.
fn protocol_rules() -> Vec<(&'static str, Network, u16, u16)> {
    vec![
        ("bittorrent", Network::Tcp, 6881, 6889),
        ("bittorrent", Network::Udp, 6881, 6881),
        ("stun", Network::Udp, 3478, 3479),
        ("stun", Network::Tcp, 3478, 3479),
    ]
}

/// A single routing rule.
#[derive(Clone)]
pub struct Rule {
    pub type_: String,
    pub domain: Option<Vec<String>>,
    pub domain_suffix: Option<Vec<String>>,
    pub domain_keyword: Option<Vec<String>>,
    pub ip_cidr: Option<Vec<String>>,
    pub port: Option<u16>,
    pub port_range: Option<(u16, u16)>,
    pub network: Option<Network>,
    pub outbound_tag: String,
    pub geo_matcher: Option<Arc<GeoMatcher>>,
}

/// Result of a rule match: the outbound tag and a human-readable description.
#[derive(Debug, PartialEq)]
pub struct RuleMatch {
    pub outbound_tag: String,
    pub description: String,
}

/// Rule type_ values for built-in rules.
pub const TYPE_BUILTIN: &str = "builtin";

/// Mode constants (must match MODE_LIST order in ui/mod.rs).
pub const MODE_RULE: u8 = 0;
pub const MODE_DIRECT: u8 = 1;
pub const MODE_GLOBAL: u8 = 2;

/// Ordered set of [`Rule`]s evaluated in sequence.
///
/// Rule layout at runtime:
///   [0] builtin private CIDRs (always direct)
///   [1..] user-configured rules
pub struct Rules {
    rules: Vec<Rule>,
    mode: AtomicU8,
    /// Outbound tag for unmatched traffic in GLOBAL / RULE modes.
    /// Computed from the last user rule at construction time.
    global_outbound: String,
}

impl Rule {
    /// Human-readable payload string for this rule's matching conditions.
    pub fn payload(&self) -> String {
        if let Some(ref geo) = self.geo_matcher {
            return geo.source.clone();
        }

        let mut parts = Vec::new();

        if let Some(ref domain) = self.domain {
            parts.push(format!(
                "domain={}",
                display_rule_list(domain, PAYLOAD_DISPLAY_ITEMS)
            ));
        }
        if let Some(ref suffix) = self.domain_suffix {
            parts.push(format!(
                "domain_suffix={}",
                display_rule_list(suffix, PAYLOAD_DISPLAY_ITEMS)
            ));
        }
        if let Some(ref keyword) = self.domain_keyword {
            parts.push(format!(
                "domain_keyword={}",
                display_rule_list(keyword, PAYLOAD_DISPLAY_ITEMS)
            ));
        }
        if let Some(ref cidrs) = self.ip_cidr {
            parts.push(format!(
                "ip_cidr={}",
                display_rule_list(cidrs, PAYLOAD_DISPLAY_ITEMS)
            ));
        }
        if let Some(port) = self.port {
            parts.push(format!("port={port}"));
        }
        if let Some((lo, hi)) = self.port_range {
            parts.push(format!("port_range={lo}-{hi}"));
        }
        if let Some(ref net) = self.network {
            parts.push(format!("network={net}"));
        }

        if parts.is_empty() {
            "match-all".to_string()
        } else {
            parts.join(" ")
        }
    }
}

fn display_rule_list(values: &[String], max_items: usize) -> String {
    if values.len() <= max_items {
        return values.join(",");
    }

    let hidden = values.len() - max_items;
    format!("{},…(+{hidden})", values[..max_items].join(","))
}

impl Rules {
    /// Returns the built-in rule for private/internal network ranges that
    /// should always be routed directly. It is prepended before
    /// user-configured rules so private traffic is never accidentally
    /// routed through a proxy.
    fn builtin_private_rules() -> Vec<Rule> {
        vec![Rule {
            type_: TYPE_BUILTIN.into(),
            domain: None,
            domain_suffix: None,
            domain_keyword: None,
            ip_cidr: Some(vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "127.0.0.0/8".into(),
                "169.254.0.0/16".into(),
                "::1/128".into(),
                "fc00::/7".into(),
                "fe80::/10".into(),
            ]),
            port: None,
            port_range: None,
            network: None,
            outbound_tag: "direct".into(),
            geo_matcher: None,
        }]
    }

    /// Builds [`Rules`] from the TOML-derived [`RuleConfig`] slice.
    ///
    /// Built-in private-network CIDR rules are automatically prepended so that
    /// internal traffic is never accidentally routed through a proxy.
    ///
    /// Additionally, for every outbound whose `server` is a domain name
    /// (not an IP), a `domain=... outbound=direct` rule is prepended so that
    /// traffic to the proxy server itself is never proxied (avoiding loops).
    ///
    /// Geo rules (with `geo_url`) are downloaded/loaded
    /// and expanded inline. Background refresh is started for each.
    pub async fn from_config(
        configs: &[RuleConfig], outbounds: &[OutboundConfig], cache_dir: &Path,
    ) -> Result<Self, String> {
        let mut rules = Self::builtin_private_rules();

        // Auto-generate domain=direct rules for proxy server domains.
        // This prevents traffic to the proxy server itself from being
        // proxied (avoiding connection loops).
        let mut seen_servers = HashSet::new();
        for ob in outbounds {
            let Some(server) = &ob.server else { continue };

            // Strip port to get the bare host.
            let host = server.split(':').next().unwrap_or(server);

            // Dedup: skip server already processed (same domain or bare IP).
            if !seen_servers.insert(host.to_string()) {
                continue;
            }

            // Try parsing as IP first.
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                // CIDR for the single IP (e.g. "1.2.3.4/32" or "::1/128").
                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                let cidr = format!("{ip}/{prefix}");
                log::info!("Auto-rule: ip_cidr={cidr} → direct (proxy server)");
                rules.push(Rule {
                    type_: TYPE_BUILTIN.into(),
                    domain: None,
                    domain_suffix: None,
                    domain_keyword: None,
                    ip_cidr: Some(vec![cidr]),
                    port: None,
                    port_range: None,
                    network: None,
                    outbound_tag: "direct".into(),
                    geo_matcher: None,
                });
                continue;
            }

            // Domain name — add domain=direct rule.
            if host.contains('.') && !host.contains(':') {
                log::info!("Auto-rule: domain={host} → direct (proxy server)");
                rules.push(Rule {
                    type_: TYPE_BUILTIN.into(),
                    domain: Some(vec![host.to_string()]),
                    domain_suffix: None,
                    domain_keyword: None,
                    ip_cidr: None,
                    port: None,
                    port_range: None,
                    network: None,
                    outbound_tag: "direct".into(),
                    geo_matcher: None,
                });
            }
        }
        let mut geo_sets: Vec<Arc<GeoRuleSet>> = Vec::new();

        for config in configs {
            if let Some(url) = &config.geo_url {
                log::info!("Loading geo rule set: {url}");
                let geo_set = GeoRuleSet::new(
                    url,
                    config.update_interval.as_deref(),
                    cache_dir,
                )
                .await;
                let source_name = geo_set.source_name().to_string();
                let matcher = geo_set.matcher().await;
                match matcher {
                    Some(gm) => {
                        rules.push(Rule {
                            type_: config.type_.clone(),
                            domain: None,
                            domain_suffix: None,
                            domain_keyword: None,
                            ip_cidr: None,
                            port: config.port,
                            port_range: config
                                .port_range
                                .as_deref()
                                .and_then(parse_port_range),
                            network: config
                                .network
                                .as_deref()
                                .and_then(parse_network),
                            outbound_tag: config.outbound.clone(),
                            geo_matcher: Some(Arc::new(gm)),
                        });
                        log::info!("Loaded geo rule set: {source_name}");
                        geo_sets.push(Arc::new(geo_set));
                    },
                    None => {
                        return Err(format!(
                            "Failed to load geo rule set {url}: download failed and no cached file"
                        ));
                    },
                }
            } else {
                if let Some(ref proto) = config.protocol {
                    if let Some(parsed) = parse_protocol_inline(proto) {
                        for (net, range) in parsed {
                            rules.push(Rule {
                                type_: config.type_.clone(),
                                domain: config.domain.clone(),
                                domain_suffix: config.domain_suffix.clone(),
                                domain_keyword: config.domain_keyword.clone(),
                                ip_cidr: config.ip_cidr.clone(),
                                port: None,
                                port_range: Some(range),
                                network: Some(net),
                                outbound_tag: config.outbound.clone(),
                                geo_matcher: None,
                            });
                        }
                    } else {
                        // Legacy protocol name lookup (e.g. "bittorrent").
                        let mut matched = false;
                        for &(p, net, lo, hi) in &protocol_rules() {
                            if p != proto {
                                continue;
                            }
                            matched = true;
                            rules.push(Rule {
                                type_: config.type_.clone(),
                                domain: config.domain.clone(),
                                domain_suffix: config.domain_suffix.clone(),
                                domain_keyword: config.domain_keyword.clone(),
                                ip_cidr: config.ip_cidr.clone(),
                                port: config.port,
                                port_range: Some((lo, hi)),
                                network: Some(net),
                                outbound_tag: config.outbound.clone(),
                                geo_matcher: None,
                            });
                        }
                        if !matched {
                            log::warn!(
                                "Unknown protocol shorthand '{proto}', skipping rule"
                            );
                        }
                    }
                } else {
                    rules.push(Rule {
                        type_: config.type_.clone(),
                        domain: config.domain.clone(),
                        domain_suffix: config.domain_suffix.clone(),
                        domain_keyword: config.domain_keyword.clone(),
                        ip_cidr: config.ip_cidr.clone(),
                        port: config.port,
                        port_range: config
                            .port_range
                            .as_deref()
                            .and_then(parse_port_range),
                        network: config
                            .network
                            .as_deref()
                            .and_then(parse_network),
                        outbound_tag: config.outbound.clone(),
                        geo_matcher: None,
                    });
                }
            }
        }

        // The "global outbound" is the tag of the last user-configured rule,
        // used as the catch-all fallback in GLOBAL and RULE modes.
        let global_outbound = rules
            .iter()
            .rev()
            .find(|r| r.type_ != TYPE_BUILTIN)
            .map(|r| r.outbound_tag.clone())
            .unwrap_or_else(|| "direct".into());

        let rules_obj = Self {
            rules,
            mode: AtomicU8::new(MODE_RULE),
            global_outbound,
        };

        // Start background refresh for geo rule sets
        for gs in geo_sets {
            gs.start_background_update();
        }

        Ok(rules_obj)
    }

    /// Return a clone of all rules (for UI / API use).
    pub fn list(&self) -> Vec<Rule> {
        self.rules.clone()
    }

    /// Returns the global outbound tag (catch-all for GLOBAL mode).
    pub fn global_outbound(&self) -> &str {
        &self.global_outbound
    }

    /// Returns the current mode.
    pub fn current_mode(&self) -> u8 {
        self.mode.load(Ordering::Relaxed)
    }

    /// Switch mode. In DIRECT mode unmatched traffic routes to "direct".
    /// In GLOBAL and RULE modes unmatched traffic routes to the last user rule.
    ///
    /// Returns `true` if the mode changed.
    pub fn set_mode(&self, mode: u8) -> bool {
        let old = self.mode.swap(mode, Ordering::Relaxed);
        old != mode
    }

    /// Evaluates rules in order against a `(destination, network)` tuple.
    ///
    /// Behavior depends on the current mode:
    /// - DIRECT:   all traffic goes to "direct" (no rule matching)
    /// - GLOBAL:   only builtin rules are matched; unmatched →
    ///   `global_outbound`
    /// - RULE:     all rules are matched
    pub fn match_conn(
        &self, dest: &Destination, network: Network,
    ) -> Option<RuleMatch> {
        if self.rules.is_empty() {
            return None;
        }

        let mode = self.mode.load(Ordering::Relaxed);

        match mode {
            MODE_DIRECT => {
                return Some(RuleMatch {
                    outbound_tag: "direct".into(),
                    description: "direct mode => route(direct)".into(),
                });
            },
            MODE_GLOBAL => {
                // Only match builtin rules (e.g. private CIDRs).
                for rule in &self.rules {
                    if rule.type_ == TYPE_BUILTIN {
                        if Self::matches(dest, network, rule) {
                            return Some(Self::rule_match(
                                rule.outbound_tag.clone(),
                                rule,
                            ));
                        }
                    }
                }
                return Some(RuleMatch {
                    outbound_tag: self.global_outbound.clone(),
                    description: format!(
                        "global mode => route({})",
                        self.global_outbound
                    ),
                });
            },
            _ => {
                // MODE_RULE: match all rules
                for rule in &self.rules {
                    if Self::matches(dest, network, rule) {
                        return Some(Self::rule_match(
                            rule.outbound_tag.clone(),
                            rule,
                        ));
                    }
                }
                None
            },
        }
    }

    /// Build a RuleMatch from a matching rule.
    fn rule_match(outbound_tag: String, rule: &Rule) -> RuleMatch {
        let cond = rule.payload();

        RuleMatch {
            outbound_tag,
            description: format!("{cond} => route({})", rule.outbound_tag),
        }
    }

    /// Returns `true` when `dest`/`network` match all configured matchers on
    /// `rule`. A matcher that is `None` is ignored. A rule with no matchers
    /// always matches (catch-all).
    fn matches(dest: &Destination, network: Network, rule: &Rule) -> bool {
        if let Some(rule_net) = rule.network {
            if rule_net != network {
                return false;
            }
        }

        if let Some(rule_port) = rule.port {
            if rule_port != dest.port {
                return false;
            }
        }

        if let Some((min, max)) = rule.port_range {
            if dest.port < min || dest.port > max {
                return false;
            }
        }

        // If this is a geo rule, delegate to GeoMatcher
        if let Some(ref geo) = rule.geo_matcher {
            return geo.matches(dest, network);
        }

        let host_matchers_present = rule.domain.is_some() ||
            rule.domain_suffix.is_some() ||
            rule.domain_keyword.is_some() ||
            rule.ip_cidr.is_some();

        if host_matchers_present && !Self::host_matches(&dest.address, rule) {
            return false;
        }

        true
    }

    fn host_matches(address: &Address, rule: &Rule) -> bool {
        match address {
            Address::Domain(host) => {
                if let Some(ref domains) = rule.domain {
                    if domains.iter().any(|d| host == d) {
                        return true;
                    }
                }
                if let Some(ref suffixes) = rule.domain_suffix {
                    if suffixes.iter().any(|s| {
                        let sfx = s.strip_prefix('.').unwrap_or(s);
                        host == sfx || host.ends_with(&format!(".{sfx}"))
                    }) {
                        return true;
                    }
                }
                if let Some(ref keywords) = rule.domain_keyword {
                    if keywords.iter().any(|k| host.contains(k.as_str())) {
                        return true;
                    }
                }
                // If the domain string looks like an IP address, also check
                // ip_cidr rules (handles SOCKS5 clients that send IP literals
                // as ATYP 0x03 domain).
                if let Some(ref cidrs) = rule.ip_cidr {
                    if let Ok(ip) = host.parse::<IpAddr>() {
                        if cidrs.iter().any(|cidr| {
                            Self::cidr_matches(ip, cidr).unwrap_or(false)
                        }) {
                            return true;
                        }
                    }
                }
                false
            },
            Address::Ipv4(o) => {
                if let Some(ref cidrs) = rule.ip_cidr {
                    let ip = IpAddr::V4(std::net::Ipv4Addr::from(*o));
                    return cidrs.iter().any(|cidr| {
                        Self::cidr_matches(ip, cidr).unwrap_or(false)
                    });
                }
                false
            },
            Address::Ipv6(o) => {
                if let Some(ref cidrs) = rule.ip_cidr {
                    let ip = IpAddr::V6(std::net::Ipv6Addr::from(*o));
                    return cidrs.iter().any(|cidr| {
                        Self::cidr_matches(ip, cidr).unwrap_or(false)
                    });
                }
                false
            },
        }
    }

    /// Checks whether `ip` falls within the CIDR range described by `cidr`.
    ///
    /// Returns [`None`] when the CIDR string is malformed.
    fn cidr_matches(ip: IpAddr, cidr: &str) -> Option<bool> {
        let (ip_str, prefix_str) = cidr.split_once('/')?;
        let prefix: u8 = prefix_str.parse().ok()?;
        let network_ip: IpAddr = ip_str.parse().ok()?;

        match (ip, network_ip) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_u32 = u32::from(ip);
                let net_u32 = u32::from(net);
                let mask = v4_prefix_mask(prefix);
                Some((ip_u32 & mask) == (net_u32 & mask))
            },
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let ip_u128 = u128::from(ip);
                let net_u128 = u128::from(net);
                let mask = v6_prefix_mask(prefix);
                Some((ip_u128 & mask) == (net_u128 & mask))
            },
            _ => Some(false),
        }
    }
}

fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.split_once('-')?;
    let lo: u16 = a.trim().parse().ok()?;
    let hi: u16 = b.trim().parse().ok()?;
    if lo <= hi {
        Some((lo, hi))
    } else {
        Some((hi, lo))
    }
}

fn parse_network(s: &str) -> Option<Network> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Some(Network::Tcp),
        "udp" => Some(Network::Udp),
        _ => None,
    }
}

/// Parse inline protocol+port syntax like `"both:443"`, `"tcp:80,1132"`, or
/// `"udp:53"`.
///
/// One value after the colon = single port. Two comma-separated values =
/// inclusive range `lo,hi`. Three or more values → invalid (warn and skip).
///
/// Return value semantics:
/// - `Some(vec![...])` — valid inline format, use these entries
/// - `Some(vec![])` — inline format detected but invalid (already warned), skip
/// - `None` — no `:` separator, caller should try legacy name lookup
fn parse_protocol_inline(s: &str) -> Option<Vec<(Network, (u16, u16))>> {
    let (proto, ports_str) = s.split_once(':')?;

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
            log::warn!("Invalid port '{}' in protocol '{s}'", ports[0]);
            return Some(vec![]);
        },
    };

    let range = if ports.len() == 2 {
        let p2: u16 = match ports[1].parse() {
            Ok(p) => p,
            Err(_) => {
                log::warn!("Invalid port '{}' in protocol '{s}'", ports[1]);
                return Some(vec![]);
            },
        };
        if p1 <= p2 { (p1, p2) } else { (p2, p1) }
    } else {
        (p1, p1)
    };

    let mut result = Vec::new();
    for &net in nets {
        result.push((net, range));
    }

    Some(result)
}

/// Builds a bitmask with the top `prefix` bits set for an IPv4 address.
fn v4_prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        !0u32
    } else {
        !0u32 << (32 - prefix)
    }
}

/// Builds a bitmask with the top `prefix` bits set for an IPv6 address.
fn v6_prefix_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else if prefix >= 128 {
        !0u128
    } else {
        !0u128 << (128 - prefix)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuleConfig;

    /// Sync helper so existing tests don't need async infrastructure.
    impl Rules {
        fn from_config_sync(configs: &[RuleConfig]) -> Self {
            let mut rules = Self::builtin_private_rules();
            rules.extend(configs.iter().map(|c| Rule {
                type_: c.type_.clone(),
                domain: c.domain.clone(),
                domain_suffix: c.domain_suffix.clone(),
                domain_keyword: c.domain_keyword.clone(),
                ip_cidr: c.ip_cidr.clone(),
                port: c.port,
                port_range: c.port_range.as_deref().and_then(parse_port_range),
                network: c.network.as_deref().and_then(parse_network),
                outbound_tag: c.outbound.clone(),
                geo_matcher: None,
            }));
            let global_outbound = rules
                .iter()
                .rev()
                .find(|r| r.type_ != TYPE_BUILTIN)
                .map(|r| r.outbound_tag.clone())
                .unwrap_or_else(|| "direct".into());
            Self {
                rules,
                mode: AtomicU8::new(MODE_RULE),
                global_outbound,
            }
        }
    }

    fn rc() -> RuleConfig {
        RuleConfig {
            type_: "default".into(),
            domain: None,
            domain_suffix: None,
            domain_keyword: None,
            ip_cidr: None::<Vec<String>>,
            port: None,
            port_range: None,
            network: None,
            protocol: None,
            outbound: "direct".into(),
            geo_url: None,
            update_interval: None,
        }
    }

    fn dest(s: &str) -> Destination {
        s.parse().unwrap()
    }

    #[test]
    fn domain_exact_match() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            domain: Some(vec!["example.com".into()]),
            ..rc()
        }]);

        assert_eq!(
            rules
                .match_conn(&dest("example.com:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("direct")
        );
        // No catch-all rule — unmatched returns None.
        assert!(
            rules
                .match_conn(&dest("other.com:80"), Network::Tcp)
                .is_none()
        );
    }

    #[test]
    fn domain_suffix_match() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            domain_suffix: Some(vec!["example.com".into()]),
            outbound: "proxy".into(),
            ..rc()
        }]);

        assert_eq!(
            rules
                .match_conn(&dest("example.com:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("proxy")
        );
        assert_eq!(
            rules
                .match_conn(&dest("sub.example.com:80"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("proxy")
        );
    }

    #[test]
    fn domain_keyword_match() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            domain_keyword: Some(vec!["google".into()]),
            outbound: "block".into(),
            ..rc()
        }]);

        assert_eq!(
            rules
                .match_conn(&dest("google.com:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("block")
        );
        assert_eq!(
            rules
                .match_conn(&dest("www.googleapis.com:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("block")
        );
    }

    #[test]
    fn domain_payload_truncates_long_lists() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            domain: Some(vec![
                "a.example".into(),
                "b.example".into(),
                "c.example".into(),
                "d.example".into(),
                "e.example".into(),
                "f.example".into(),
            ]),
            outbound: "proxy".into(),
            ..rc()
        }]);

        assert_eq!(
            rules
                .match_conn(&dest("a.example:443"), Network::Tcp)
                .map(|m| m.description),
            Some(
                "domain=a.example,b.example,c.example,d.example,…(+2) => \
                 route(proxy)"
                    .into(),
            )
        );
    }

    #[test]
    fn domain_payload_keeps_short_lists_complete() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            domain_suffix: Some(vec![
                "a.example".into(),
                "b.example".into(),
                "c.example".into(),
                "d.example".into(),
            ]),
            outbound: "proxy".into(),
            ..rc()
        }]);

        assert_eq!(
            rules
                .match_conn(&dest("www.a.example:443"), Network::Tcp)
                .map(|m| m.description),
            Some(
                "domain_suffix=a.example,b.example,c.example,d.example => \
                 route(proxy)"
                    .into(),
            )
        );
    }

    #[test]
    fn ipv4_cidr_match() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            ip_cidr: Some(vec!["198.51.100.0/24".into()]),
            outbound: "proxy".into(),
            ..rc()
        }]);

        assert_eq!(
            rules
                .match_conn(&dest("198.51.100.1:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("proxy")
        );
    }

    #[test]
    fn ipv4_cidr_match_via_domain_literal() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            ip_cidr: Some(vec!["192.168.0.0/16".into()]),
            outbound: "direct".into(),
            ..rc()
        }]);

        let dest = Destination::new(Address::Domain("192.168.1.100".into()), 443);
        assert_eq!(
            rules
                .match_conn(&dest, Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("direct")
        );

        // Non-matching IP should fall through to catch-all.
        let dest = Destination::new(Address::Domain("10.0.0.1".into()), 443);
        assert_eq!(
            rules
                .match_conn(&dest, Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("direct")
        );
    }

    #[test]
    fn ipv6_cidr_match() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            ip_cidr: Some(vec!["2001:db8::/32".into()]),
            outbound: "v6".into(),
            ..rc()
        }]);

        assert_eq!(
            rules
                .match_conn(&dest("[2001:db8::1]:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("v6")
        );
    }

    #[test]
    fn first_match_wins() {
        let rules = Rules::from_config_sync(&[
            RuleConfig {
                domain: Some(vec!["example.com".into()]),
                outbound: "direct".into(),
                ..rc()
            },
            RuleConfig {
                domain_suffix: Some(vec!["example.com".into()]),
                outbound: "proxy".into(),
                ..rc()
            },
        ]);

        assert_eq!(
            rules
                .match_conn(&dest("example.com:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("direct")
        );
    }

    #[test]
    fn empty_config_returns_none_for_public_ip() {
        let rules = Rules::from_config_sync(&[]);
        // 1.1.1.1 is not a private CIDR, so built-in rules don't match.
        let m = rules.match_conn(&dest("1.1.1.1:443"), Network::Tcp);
        assert!(m.is_none());
    }

    // -- mode switching -------------------------------------------------------

    #[test]
    fn mode_direct_catchall() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            domain: Some(vec!["example.com".into()]),
            outbound: "proxy".into(),
            ..rc()
        }]);
        rules.set_mode(MODE_DIRECT);

        // Everything routes to direct in DIRECT mode.
        assert_eq!(
            rules
                .match_conn(&dest("192.168.1.1:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("direct")
        );
        assert_eq!(
            rules
                .match_conn(&dest("example.com:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("direct")
        );
        assert_eq!(
            rules
                .match_conn(&dest("1.1.1.1:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("direct")
        );
    }

    #[test]
    fn mode_global_only_matches_builtin() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            domain: Some(vec!["example.com".into()]),
            outbound: "proxy".into(),
            ..rc()
        }]);
        rules.set_mode(MODE_GLOBAL);

        // Builtin private CIDRs still route to direct.
        assert_eq!(
            rules
                .match_conn(&dest("192.168.1.1:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("direct")
        );
        // example.com doesn't match builtin, falls through to global_outbound.
        assert_eq!(
            rules
                .match_conn(&dest("example.com:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("proxy")
        );
        // Unmatched traffic catches to global_outbound (= last user rule).
        assert_eq!(
            rules
                .match_conn(&dest("1.1.1.1:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("proxy")
        );
    }

    #[test]
    fn mode_rule_matches_all_rules() {
        let rules = Rules::from_config_sync(&[RuleConfig {
            domain: Some(vec!["example.com".into()]),
            outbound: "proxy".into(),
            ..rc()
        }]);
        // Default is MODE_RULE — user rules work normally.
        assert_eq!(
            rules
                .match_conn(&dest("example.com:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("proxy")
        );
        // Unmatched traffic returns None in MODE_RULE (no catch-all).
        assert!(
            rules
                .match_conn(&dest("1.1.1.1:443"), Network::Tcp)
                .is_none()
        );
    }

    // -- network / port matching --------------------------------------------

    #[test]
    fn network_filter_udp_only() {
        let rules = Rules::from_config_sync(&[
            RuleConfig {
                network: Some("udp".into()),
                outbound: "udp-out".into(),
                ..rc()
            },
            RuleConfig {
                outbound: "default".into(),
                ..rc()
            },
        ]);

        assert_eq!(
            rules
                .match_conn(&dest("1.1.1.1:53"), Network::Udp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("udp-out")
        );
        assert_eq!(
            rules
                .match_conn(&dest("1.1.1.1:53"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("default")
        );
    }

    #[test]
    fn port_exact_filter() {
        let rules = Rules::from_config_sync(&[
            RuleConfig {
                port: Some(443),
                outbound: "https".into(),
                ..rc()
            },
            RuleConfig {
                outbound: "default".into(),
                ..rc()
            },
        ]);

        assert_eq!(
            rules
                .match_conn(&dest("example.com:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("https")
        );
        assert_eq!(
            rules
                .match_conn(&dest("example.com:80"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("default")
        );
    }

    #[test]
    fn port_range_filter() {
        let rules = Rules::from_config_sync(&[
            RuleConfig {
                port_range: Some("8000-9000".into()),
                outbound: "range".into(),
                ..rc()
            },
            RuleConfig {
                outbound: "default".into(),
                ..rc()
            },
        ]);

        assert_eq!(
            rules
                .match_conn(&dest("example.com:8500"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("range")
        );
        assert_eq!(
            rules
                .match_conn(&dest("example.com:9001"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("default")
        );
    }

    // -- parse_protocol_inline ------------------------------------------------

    #[test]
    fn inline_both_single_port() {
        let result = parse_protocol_inline("both:443").unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&(Network::Tcp, (443, 443))));
        assert!(result.contains(&(Network::Udp, (443, 443))));
    }

    #[test]
    fn inline_tcp_port_range() {
        let result = parse_protocol_inline("tcp:80,1132").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], (Network::Tcp, (80, 1132)));
    }

    #[test]
    fn inline_udp_single_port() {
        let result = parse_protocol_inline("udp:53").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], (Network::Udp, (53, 53)));
    }

    #[test]
    fn inline_unknown_protocol_returns_empty() {
        let result = parse_protocol_inline("foo:443");
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn inline_no_colon_falls_back() {
        let result = parse_protocol_inline("bittorrent");
        assert!(result.is_none());
    }

    #[test]
    fn inline_invalid_port_returns_empty() {
        let result = parse_protocol_inline("tcp:abc");
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn inline_empty_ports_returns_empty() {
        let result = parse_protocol_inline("both:");
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn inline_too_many_ports_returns_empty() {
        let result = parse_protocol_inline("tcp:80,443,8080");
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn inline_reversed_range_swapped() {
        let result = parse_protocol_inline("tcp:1132,80").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], (Network::Tcp, (80, 1132)));
    }

    // -- protocol inline via config -------------------------------------------

    fn from_config_sync_protocol(configs: &[RuleConfig]) -> Rules {
        let mut rules = Rules::builtin_private_rules();
        for config in configs {
            if let Some(ref proto) = config.protocol {
                if let Some(parsed) = parse_protocol_inline(proto) {
                    for (net, range) in parsed {
                        rules.push(Rule {
                            type_: config.type_.clone(),
                            domain: config.domain.clone(),
                            domain_suffix: config.domain_suffix.clone(),
                            domain_keyword: config.domain_keyword.clone(),
                            ip_cidr: config.ip_cidr.clone(),
                            port: None,
                            port_range: Some(range),
                            network: Some(net),
                            outbound_tag: config.outbound.clone(),
                            geo_matcher: None,
                        });
                    }
                } else {
                    for &(p, net, lo, hi) in &protocol_rules() {
                        if p != proto {
                            continue;
                        }
                        rules.push(Rule {
                            type_: config.type_.clone(),
                            domain: config.domain.clone(),
                            domain_suffix: config.domain_suffix.clone(),
                            domain_keyword: config.domain_keyword.clone(),
                            ip_cidr: config.ip_cidr.clone(),
                            port: config.port,
                            port_range: Some((lo, hi)),
                            network: Some(net),
                            outbound_tag: config.outbound.clone(),
                            geo_matcher: None,
                        });
                    }
                }
            } else {
                rules.push(Rule {
                    type_: config.type_.clone(),
                    domain: config.domain.clone(),
                    domain_suffix: config.domain_suffix.clone(),
                    domain_keyword: config.domain_keyword.clone(),
                    ip_cidr: config.ip_cidr.clone(),
                    port: config.port,
                    port_range: config
                        .port_range
                        .as_deref()
                        .and_then(parse_port_range),
                    network: config.network.as_deref().and_then(parse_network),
                    outbound_tag: config.outbound.clone(),
                    geo_matcher: None,
                });
            }
        }
        let global_outbound = rules
            .iter()
            .rev()
            .find(|r| r.type_ != TYPE_BUILTIN)
            .map(|r| r.outbound_tag.clone())
            .unwrap_or_else(|| "direct".into());
        Rules {
            rules,
            mode: AtomicU8::new(MODE_RULE),
            global_outbound,
        }
    }

    #[test]
    fn protocol_inline_tcp_range_matches_config() {
        let rules = from_config_sync_protocol(&[RuleConfig {
            protocol: Some("tcp:80,443".into()),
            outbound: "web".into(),
            ..rc()
        }]);

        assert_eq!(
            rules
                .match_conn(&dest("example.com:80"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("web")
        );
        assert_eq!(
            rules
                .match_conn(&dest("example.com:443"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("web")
        );
        assert!(
            rules
                .match_conn(&dest("example.com:80"), Network::Udp)
                .is_none()
        );
        // 8080 is outside 80-443 range
        assert!(
            rules
                .match_conn(&dest("example.com:8080"), Network::Tcp)
                .is_none()
        );
    }

    #[test]
    fn protocol_inline_both_matches_any_protocol() {
        let rules = from_config_sync_protocol(&[RuleConfig {
            protocol: Some("both:1232".into()),
            outbound: "svc".into(),
            ..rc()
        }]);

        assert_eq!(
            rules
                .match_conn(&dest("example.com:1232"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("svc")
        );
        assert_eq!(
            rules
                .match_conn(&dest("example.com:1232"), Network::Udp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("svc")
        );
    }

    #[test]
    fn protocol_inline_and_legacy_name_both_work() {
        let rules = from_config_sync_protocol(&[RuleConfig {
            protocol: Some("bittorrent".into()),
            outbound: "p2p".into(),
            ..rc()
        }]);

        assert_eq!(
            rules
                .match_conn(&dest("example.com:6881"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("p2p")
        );
        assert_eq!(
            rules
                .match_conn(&dest("example.com:6889"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("p2p")
        );
    }

    #[test]
    fn combined_network_and_port() {
        let rules = Rules::from_config_sync(&[
            RuleConfig {
                network: Some("udp".into()),
                port: Some(53),
                outbound: "dns".into(),
                ..rc()
            },
            RuleConfig {
                outbound: "default".into(),
                ..rc()
            },
        ]);

        assert_eq!(
            rules
                .match_conn(&dest("8.8.8.8:53"), Network::Udp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("dns")
        );
        // TCP/53 should NOT match the dns rule.
        assert_eq!(
            rules
                .match_conn(&dest("8.8.8.8:53"), Network::Tcp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("default")
        );
        // UDP/443 should NOT match the dns rule either.
        assert_eq!(
            rules
                .match_conn(&dest("8.8.8.8:443"), Network::Udp)
                .map(|m| m.outbound_tag)
                .as_deref(),
            Some("default")
        );
    }
}
