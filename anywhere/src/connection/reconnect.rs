//! Generic reconnection policy for long-lived sessions.
//!
//! [`ReconnectPolicy`] encapsulates the timing decision: when should a
//! long-lived connection be re-established? The answer is either
//! "the peer closed it" (EOF, detected by the caller) or "it has been
//! open longer than `max_age`" (timeout, checked by this policy).
//!
//! The actual reconnection action is protocol-specific and stays in the
//! caller: XHTTP re-issues an HTTP GET with the same session_id,
//! WebSocket would re-open the WS upgrade, AnyTLS would re-authenticate.

use std::time::{Duration, Instant};

/// Timing policy for session-continuity reconnection.
///
/// Tracks when the current connection was established and whether it
/// has exceeded the configured maximum age.
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Max age of the current connection before forced reconnect.
    /// `None` = no age limit (reconnect only on EOF).
    pub max_age: Option<Duration>,
    /// When the current connection was established.
    connected_at: Instant,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            max_age: None,
            connected_at: Instant::now(),
        }
    }
}

impl ReconnectPolicy {
    /// Create a policy with the given max age.
    pub fn new(max_age: Option<Duration>) -> Self {
        Self {
            max_age,
            connected_at: Instant::now(),
        }
    }

    /// Record that a new connection was established.
    /// Call this after every successful (re)connect.
    pub fn reset(&mut self) {
        self.connected_at = Instant::now();
    }

    /// Whether the current connection has exceeded `max_age`.
    /// Always `false` when `max_age` is `None`.
    pub fn should_reconnect(&self) -> bool {
        self.max_age
            .map(|max| self.connected_at.elapsed() >= max)
            .unwrap_or(false)
    }

    /// How long the current connection has been open.
    pub fn elapsed(&self) -> Duration {
        self.connected_at.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_max_age_never_reconnects() {
        let policy = ReconnectPolicy::new(None);
        assert!(!policy.should_reconnect());
    }

    #[test]
    fn max_age_zero_triggers_immediately() {
        let policy = ReconnectPolicy::new(Some(Duration::ZERO));
        assert!(policy.should_reconnect());
    }

    #[test]
    fn reset_restarts_timer() {
        let mut policy = ReconnectPolicy::new(Some(Duration::from_millis(1)));
        assert!(!policy.should_reconnect());
        std::thread::sleep(Duration::from_millis(2));
        assert!(policy.should_reconnect());
        policy.reset();
        assert!(!policy.should_reconnect());
    }

    #[test]
    fn default_is_no_reconnect() {
        let policy = ReconnectPolicy::default();
        assert!(policy.max_age.is_none());
        assert!(!policy.should_reconnect());
    }
}
