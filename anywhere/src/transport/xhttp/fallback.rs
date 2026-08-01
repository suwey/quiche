//! HTTP version fallback state machine (H3 -> H2).
//!
//! When H3 (QUIC) connection fails (e.g., UDP blocked by firewall),
//! the fallback state machine tracks the failure and provides H2 as
//! the fallback version.
//!
//! ## Fallback order
//!
//! - `Http3` -> H3 -> H2 (when H3 client is implemented)
//! - `Auto` -> H2 (no fallback needed)
//! - `Http2` -> H2 (no fallback)
//! - `Http1` -> H1 (no fallback, via ALPN negotiation)
//!
//! H2/H1 selection is handled by TLS ALPN negotiation, not by this
//! state machine. This module is only for H3->H2 transport fallback.

use super::config::HttpVersionPref;

/// Tracks HTTP version fallback state for H3 -> H2.
#[derive(Debug, Clone)]
pub struct FallbackState {
    /// Whether H3 has been tried and failed.
    h3_failed: bool,
    /// The version to try next.
    current: HttpVersionPref,
}

impl FallbackState {
    /// Create a new fallback state starting from the preferred version.
    pub fn new(pref: HttpVersionPref) -> Self {
        let current = match pref {
            HttpVersionPref::Auto => HttpVersionPref::Http2,
            HttpVersionPref::Http3 => HttpVersionPref::Http3,
            HttpVersionPref::Http2 => HttpVersionPref::Http2,
            HttpVersionPref::Http1 => HttpVersionPref::Http1,
        };
        Self {
            h3_failed: false,
            current,
        }
    }

    /// The HTTP version to try on the next connection attempt.
    pub fn current(&self) -> HttpVersionPref {
        self.current
    }

    /// Record that the current version failed and advance to the next.
    ///
    /// Returns `true` if there is a version to fall back to, `false` if
    /// all versions have been exhausted.
    pub fn record_failure(&mut self) -> bool {
        match self.current {
            HttpVersionPref::Http3 => {
                self.h3_failed = true;
                self.current = HttpVersionPref::Http2;
                true
            }
            _ => false,
        }
    }

    /// Whether any fallback has occurred.
    pub fn has_fallen_back(&self) -> bool {
        self.h3_failed
    }
}

impl Default for FallbackState {
    fn default() -> Self {
        Self::new(HttpVersionPref::Auto)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_starts_with_h2() {
        let fs = FallbackState::new(HttpVersionPref::Auto);
        assert_eq!(fs.current(), HttpVersionPref::Http2);
        assert!(!fs.has_fallen_back());
    }

    #[test]
    fn http2_no_fallback() {
        let mut fs = FallbackState::new(HttpVersionPref::Http2);
        assert_eq!(fs.current(), HttpVersionPref::Http2);
        assert!(!fs.record_failure());
        assert_eq!(fs.current(), HttpVersionPref::Http2);
    }

    #[test]
    fn http3_falls_back_to_h2() {
        let mut fs = FallbackState::new(HttpVersionPref::Http3);
        assert_eq!(fs.current(), HttpVersionPref::Http3);
        assert!(fs.record_failure());
        assert_eq!(fs.current(), HttpVersionPref::Http2);
        assert!(fs.has_fallen_back());
        // No further fallback from H2
        assert!(!fs.record_failure());
    }

    #[test]
    fn http1_no_fallback() {
        let mut fs = FallbackState::new(HttpVersionPref::Http1);
        assert_eq!(fs.current(), HttpVersionPref::Http1);
        assert!(!fs.record_failure());
    }

    #[test]
    fn default_is_auto() {
        let fs = FallbackState::default();
        assert_eq!(fs.current(), HttpVersionPref::Http2);
    }
}
