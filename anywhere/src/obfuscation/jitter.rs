//! Timing and size jitter primitives for traffic shaping.
//!
//! - `TimingJitter`: compensating delay between operations
//! - `SizeJitter`: random chunk sizes for splitting payloads
//! - `ConnBehaviorJitter`: randomized connection lifecycle parameters
//! - `ConnLifecycle`: runtime state derived from `ConnBehaviorJitter`

use std::time::{Duration, Instant};

use super::range::Range;

// ---------------------------------------------------------------------------
// TimingJitter — compensating delay
// ---------------------------------------------------------------------------

/// Timing jitter: enforces a random interval between successive operations.
///
/// `wait()` sleeps for the remaining time since the last `wait()` call,
/// implementing a compensating delay (similar to Xray's `scMinPostsIntervalMs`).
/// If the elapsed time already exceeds the target interval, no sleep occurs.
pub struct TimingJitter {
    interval: Range,
    last_op: Instant,
}

impl TimingJitter {
    /// Create with a millisecond interval range.
    pub fn new(interval_ms: Range) -> Self {
        Self {
            interval: interval_ms,
            last_op: Instant::now(),
        }
    }

    /// Sleep until the random interval has elapsed since the last `wait()`.
    pub async fn wait(&mut self) {
        let target = self.interval.rand_duration();
        let elapsed = self.last_op.elapsed();
        if elapsed < target {
            tokio::time::sleep(target - elapsed).await;
        }
        self.last_op = Instant::now();
    }

    /// Reset the timer (e.g., after a long idle period).
    pub fn reset(&mut self) {
        self.last_op = Instant::now();
    }

    /// Get the configured interval range.
    pub fn interval(&self) -> &Range {
        &self.interval
    }
}

// ---------------------------------------------------------------------------
// SizeJitter — random chunk sizes
// ---------------------------------------------------------------------------

/// Size jitter: produces random size values within a range.
///
/// Used to determine how much data to send in each chunk (similar to
/// Xray's `scMaxEachPostBytes`).
pub struct SizeJitter {
    range: Range,
}

impl SizeJitter {
    /// Create with a byte-size range.
    pub fn new(range: Range) -> Self {
        Self { range }
    }

    /// Return a random chunk size, clamped to `max`.
    pub fn next_size(&self, max: usize) -> usize {
        let v = self.range.rand_usize();
        if v == 0 { 0 } else { v.min(max) }
    }

    /// Return a random chunk size without clamping.
    pub fn next_raw(&self) -> usize {
        self.range.rand_usize()
    }

    /// Get the configured size range.
    pub fn range(&self) -> &Range {
        &self.range
    }
}

// ---------------------------------------------------------------------------
// ConnBehaviorJitter — connection lifecycle randomization
// ---------------------------------------------------------------------------

/// Connection behavior jitter: rolls random lifecycle parameters.
///
/// Mirrors Xray's xmux configuration but with randomized ranges instead
/// of fixed values. Each field is optional — `None` means "use the
/// transport's default".
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ConnBehaviorJitter {
    pub max_connections: Option<Range>,
    pub max_concurrency: Option<Range>,
    pub c_max_reuse_times: Option<Range>,
    pub h_max_request_times: Option<Range>,
    pub h_max_reusable_secs: Option<Range>,
    pub h_keep_alive_period: Option<Range>,
}

/// Runtime lifecycle state derived from a `ConnBehaviorJitter` roll.
#[derive(Debug, Clone)]
pub struct ConnLifecycle {
    pub max_connections: Option<u32>,
    pub max_concurrency: Option<u32>,
    pub left_reuses: Option<u32>,
    pub left_requests: Option<u32>,
    pub reusable_until: Option<Instant>,
    pub keep_alive_period: Option<Duration>,
}

impl ConnBehaviorJitter {
    /// Roll a new `ConnLifecycle` with randomized values.
    pub fn roll(&self) -> ConnLifecycle {
        ConnLifecycle {
            max_connections: self.max_connections.as_ref().map(|r| r.rand_u32()),
            max_concurrency: self.max_concurrency.as_ref().map(|r| r.rand_u32()),
            left_reuses: self.c_max_reuse_times.as_ref().map(|r| r.rand_u32()),
            left_requests: self.h_max_request_times.as_ref().map(|r| r.rand_u32()),
            reusable_until: self
                .h_max_reusable_secs
                .as_ref()
                .map(|r| Instant::now() + Duration::from_secs(r.rand_u64())),
            keep_alive_period: self
                .h_keep_alive_period
                .as_ref()
                .map(|r| r.rand_duration()),
        }
    }
}

impl ConnLifecycle {
    /// Whether this connection can still be reused.
    pub fn is_reusable(&self) -> bool {
        if let Some(left) = self.left_reuses
            && left == 0
        {
            return false;
        }
        if let Some(left) = self.left_requests
            && left == 0
        {
            return false;
        }
        if let Some(until) = self.reusable_until
            && Instant::now() >= until
        {
            return false;
        }
        true
    }

    /// Decrement reuse/request counters after one use.
    pub fn record_use(&mut self) {
        if let Some(ref mut left) = self.left_reuses {
            *left = left.saturating_sub(1);
        }
        if let Some(ref mut left) = self.left_requests {
            *left = left.saturating_sub(1);
        }
    }

    /// Whether a keep-alive ping should be sent now.
    pub fn needs_keep_alive(&self, last_activity: Instant) -> bool {
        match self.keep_alive_period {
            Some(period) => last_activity.elapsed() >= period,
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timing_jitter_sleeps() {
        let mut tj = TimingJitter::new(Range::new(50, 50));
        let start = Instant::now();
        tj.wait().await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(40), "wait took {:?}", elapsed);
    }

    #[tokio::test]
    async fn timing_jitter_skips_when_already_elapsed() {
        let mut tj = TimingJitter::new(Range::new(10, 10));
        tokio::time::sleep(Duration::from_millis(20)).await; // already past interval
        let start = Instant::now();
        tj.wait().await;
        let elapsed = start.elapsed();
        // Should return almost immediately since 10ms already elapsed.
        assert!(elapsed < Duration::from_millis(10), "should not sleep, took {:?}", elapsed);
    }

    #[tokio::test]
    async fn timing_jitter_reset() {
        let mut tj = TimingJitter::new(Range::new(100, 100));
        tj.wait().await;
        tj.reset();
        let start = Instant::now();
        tj.wait().await;
        // After reset, should sleep the full 100ms.
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(90), "after reset took {:?}", elapsed);
    }

    #[test]
    fn size_jitter_clamped() {
        let sj = SizeJitter::new(Range::new(1000, 2000));
        let s = sj.next_size(500);
        assert!(s <= 500, "size {} exceeds max 500", s);
    }

    #[test]
    fn size_jitter_unclamped() {
        let sj = SizeJitter::new(Range::new(100, 200));
        let s = sj.next_raw();
        assert!(s >= 100 && s <= 200);
    }

    #[test]
    fn size_jitter_zero() {
        let sj = SizeJitter::new(Range::constant(0));
        assert_eq!(sj.next_size(1000), 0);
        assert_eq!(sj.next_raw(), 0);
    }

    #[test]
    fn conn_behavior_roll_with_values() {
        let cb = ConnBehaviorJitter {
            max_connections: Some(Range::new(1, 5)),
            max_concurrency: Some(Range::new(2, 10)),
            c_max_reuse_times: Some(Range::new(3, 8)),
            h_max_request_times: Some(Range::new(10, 100)),
            h_max_reusable_secs: Some(Range::new(30, 300)),
            h_keep_alive_period: Some(Range::new(15, 60)),
        };
        let lc = cb.roll();
        assert!(lc.max_connections.unwrap() >= 1 && lc.max_connections.unwrap() <= 5);
        assert!(lc.max_concurrency.unwrap() >= 2 && lc.max_concurrency.unwrap() <= 10);
        assert!(lc.left_reuses.unwrap() >= 3 && lc.left_reuses.unwrap() <= 8);
        assert!(lc.left_requests.unwrap() >= 10 && lc.left_requests.unwrap() <= 100);
        assert!(lc.reusable_until.is_some());
        assert!(lc.keep_alive_period.is_some());
        assert!(lc.is_reusable());
    }

    #[test]
    fn conn_behavior_roll_empty() {
        let cb = ConnBehaviorJitter::default();
        let lc = cb.roll();
        assert!(lc.max_connections.is_none());
        assert!(lc.is_reusable()); // nothing limits reuse
    }

    #[test]
    fn conn_lifecycle_reuse_depleted() {
        let mut lc = ConnLifecycle {
            max_connections: None,
            max_concurrency: None,
            left_reuses: Some(1),
            left_requests: Some(10),
            reusable_until: None,
            keep_alive_period: None,
        };
        assert!(lc.is_reusable());
        lc.record_use();
        assert!(!lc.is_reusable(), "should not be reusable after depleting left_reuses");
    }

    #[test]
    fn conn_lifecycle_request_depleted() {
        let mut lc = ConnLifecycle {
            max_connections: None,
            max_concurrency: None,
            left_reuses: Some(5),
            left_requests: Some(1),
            reusable_until: None,
            keep_alive_period: None,
        };
        lc.record_use();
        assert!(!lc.is_reusable(), "should not be reusable after depleting left_requests");
    }

    #[test]
    fn conn_lifecycle_expired() {
        let lc = ConnLifecycle {
            max_connections: None,
            max_concurrency: None,
            left_reuses: Some(10),
            left_requests: Some(10),
            reusable_until: Some(Instant::now() - Duration::from_secs(1)),
            keep_alive_period: None,
        };
        assert!(!lc.is_reusable(), "expired connection should not be reusable");
    }

    #[test]
    fn conn_lifecycle_keep_alive() {
        let lc = ConnLifecycle {
            max_connections: None,
            max_concurrency: None,
            left_reuses: None,
            left_requests: None,
            reusable_until: None,
            keep_alive_period: Some(Duration::from_millis(50)),
        };
        // Just created — last_activity is now, so no keep-alive needed yet.
        let recent = Instant::now();
        assert!(!lc.needs_keep_alive(recent));

        // After 60ms, keep-alive should be needed.
        let old = Instant::now() - Duration::from_millis(60);
        assert!(lc.needs_keep_alive(old));
    }

    #[test]
    fn conn_lifecycle_record_use_saturating() {
        let mut lc = ConnLifecycle {
            max_connections: None,
            max_concurrency: None,
            left_reuses: Some(0),
            left_requests: Some(0),
            reusable_until: None,
            keep_alive_period: None,
        };
        lc.record_use(); // should not underflow
        assert_eq!(lc.left_reuses, Some(0));
        assert_eq!(lc.left_requests, Some(0));
    }
}
