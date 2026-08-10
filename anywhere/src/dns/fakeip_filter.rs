// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! FakeIP filter - controls which domains get a FakeIP vs real DNS resolution.
//!
//! In blacklist mode (default), domains in the filter list use real DNS;
//! everything else gets a FakeIP. This is essential for domains that must
//! receive a real IP to function correctly (Windows connectivity checks,
//! LAN discovery, NTP, etc.).

/// Domains that should always use real DNS (Windows network connectivity
/// checks). These return FakeIP-unfriendly results that break OS-level
/// network status detection.
const DEFAULT_FILTER: &[&str] = &[
    "dns.msftnsci.com",
    "www.msftnsci.com",
    "www.msftconnecttest.com",
];

/// A single domain pattern for the filter.
///
/// Supports two forms:
/// - Exact: `dns.msftnsci.com` matches only that domain.
/// - Suffix: `+.msftnsci.com` or `*.msftnsci.com` matches the domain and
///   all subdomains (e.g. `msftnsci.com`, `a.b.msftnsci.com`).
#[derive(Debug, Clone)]
struct DomainPattern {
    /// Lowercase domain without any wildcard prefix.
    domain: String,
    /// If true, matches the domain and all subdomains.
    suffix: bool,
}

impl DomainPattern {
    fn parse(pattern: &str) -> Self {
        let (suffix, rest) = pattern
            .strip_prefix("+.")
            .or_else(|| pattern.strip_prefix("*."))
            .map_or((false, pattern), |r| (true, r));

        Self {
            domain: rest.to_lowercase(),
            suffix,
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        if self.suffix {
            domain == self.domain
                || domain.ends_with(&format!(".{}", self.domain))
        } else {
            domain == self.domain
        }
    }
}

/// FakeIP domain filter. In blacklist mode, matched domains skip FakeIP
/// and resolve via real DNS.
#[derive(Debug, Clone)]
pub struct FakeIPFilter {
    patterns: Vec<DomainPattern>,
}

impl FakeIPFilter {
    /// Build a filter from user-provided patterns. If the list is empty,
    /// the built-in default filter is used.
    pub fn from_list(patterns: &[String]) -> Self {
        let patterns: Vec<DomainPattern> = if patterns.is_empty() {
            DEFAULT_FILTER
                .iter()
                .map(|p| DomainPattern::parse(p))
                .collect()
        } else {
            patterns.iter().map(|p| DomainPattern::parse(p)).collect()
        };
        Self { patterns }
    }

    /// Build the default filter (Windows connectivity check domains).
    pub fn default_filter() -> Self {
        Self::from_list(&[])
    }

    /// Returns true if `domain` should skip FakeIP and use real DNS.
    pub fn should_skip(&self, domain: &str) -> bool {
        self.patterns.iter().any(|p| p.matches(domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let p = DomainPattern::parse("dns.msftnsci.com");
        assert!(p.matches("dns.msftnsci.com"));
        assert!(!p.matches("www.msftnsci.com"));
        assert!(!p.matches("sub.dns.msftnsci.com"));
    }

    #[test]
    fn suffix_match_plus() {
        let p = DomainPattern::parse("+.msftnsci.com");
        assert!(p.matches("msftnsci.com"));
        assert!(p.matches("dns.msftnsci.com"));
        assert!(p.matches("a.b.msftnsci.com"));
        assert!(!p.matches("msftnsci.com.evil.com"));
    }

    #[test]
    fn suffix_match_star() {
        let p = DomainPattern::parse("*.local");
        assert!(p.matches("local"));
        assert!(p.matches("host.local"));
        assert!(!p.matches("notlocal"));
    }

    #[test]
    fn case_insensitive() {
        let p = DomainPattern::parse("+.MSFTNSCI.COM");
        assert!(p.matches("DNS.Msftnsci.COM"));
    }

    #[test]
    fn default_filter_skips_windows_domains() {
        let f = FakeIPFilter::default_filter();
        assert!(f.should_skip("dns.msftnsci.com"));
        assert!(f.should_skip("www.msftconnecttest.com"));
        assert!(!f.should_skip("google.com"));
    }

    #[test]
    fn custom_filter() {
        let f = FakeIPFilter::from_list(&[
            "+.lan".to_string(),
            "+.local".to_string(),
            "time.windows.com".to_string(),
        ]);
        assert!(f.should_skip("myhost.lan"));
        assert!(f.should_skip("ntp.local"));
        assert!(f.should_skip("time.windows.com"));
        assert!(!f.should_skip("google.com"));
    }

    #[test]
    fn empty_list_uses_default() {
        let f = FakeIPFilter::from_list(&[]);
        assert!(f.should_skip("www.msftnsci.com"));
    }
}
