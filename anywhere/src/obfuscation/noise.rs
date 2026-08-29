//! UDP noise injection - sends dummy packets to mask real traffic patterns.
//!
//! Mirrors Xray's `finalmask noise` concept: periodically inject random
//! UDP packets with configurable size, content, and timing.
//!
//! NOTE: Designed but not currently wired into any outbound path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use super::range::Range;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for a single noise stream.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NoiseItem {
    /// Random packet size range (bytes).
    pub rand_size: Range,
    /// Per-byte content range `[min_byte, max_byte]`.
    #[serde(default = "default_byte_range")]
    pub rand_range: [u8; 2],
    /// Inter-packet delay range (milliseconds).
    pub delay: Range,
}

fn default_byte_range() -> [u8; 2] {
    [0, 255]
}

/// Overall noise injection configuration.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct NoiseConfig {
    /// Injection reset interval (seconds). After this duration, a new
    /// noise burst is triggered.
    pub reset_interval: Range,
    /// Noise items to send in each burst.
    #[serde(default)]
    pub items: Vec<NoiseItem>,
}

// ---------------------------------------------------------------------------
// NoiseInjector — stateful noise packet generator
// ---------------------------------------------------------------------------

/// Stateful noise injector that tracks per-destination timing.
pub struct NoiseInjector {
    config: NoiseConfig,
    last_inject: HashMap<SocketAddr, Instant>,
}

impl NoiseInjector {
    /// Create a new injector from configuration.
    pub fn new(config: NoiseConfig) -> Self {
        Self {
            config,
            last_inject: HashMap::new(),
        }
    }

    /// Create an empty injector (no noise).
    pub fn empty() -> Self {
        Self::new(NoiseConfig::default())
    }

    /// Check if a noise burst should be sent to `dest` now.
    ///
    /// Returns `Some(Vec<NoisePacket>)` if enough time has elapsed since
    /// the last injection for this destination, or `None` otherwise.
    pub fn should_inject(
        &mut self, dest: SocketAddr,
    ) -> Option<Vec<NoisePacket>> {
        if self.config.items.is_empty() {
            return None;
        }

        let now = Instant::now();
        let interval_secs = self.config.reset_interval.rand_u64();
        let interval = std::time::Duration::from_secs(interval_secs);

        let should = match self.last_inject.get(&dest) {
            Some(last) => now.duration_since(*last) >= interval,
            None => true,
        };

        if !should {
            return None;
        }

        self.last_inject.insert(dest, now);
        Some(self.generate_burst())
    }

    /// Generate a burst of noise packets.
    fn generate_burst(&self) -> Vec<NoisePacket> {
        self.config
            .items
            .iter()
            .map(|item| {
                let size = item.rand_size.rand_usize();
                let delay = item.delay.rand_duration();
                let data = self.generate_noise_data(size, &item.rand_range);
                NoisePacket { data, delay }
            })
            .collect()
    }

    /// Generate random noise bytes.
    fn generate_noise_data(&self, size: usize, byte_range: &[u8; 2]) -> Vec<u8> {
        let lo = byte_range[0] as i64;
        let hi = byte_range[1] as i64;
        (0..size)
            .map(|_| super::range::rand_range(lo, hi) as u8)
            .collect()
    }

    /// Number of configured noise items.
    pub fn item_count(&self) -> usize {
        self.config.items.len()
    }

    /// Whether noise injection is enabled.
    pub fn is_enabled(&self) -> bool {
        !self.config.items.is_empty()
    }
}

/// A single generated noise packet with its associated delay.
#[derive(Debug, Clone)]
pub struct NoisePacket {
    /// Random payload bytes.
    pub data: Vec<u8>,
    /// Delay before sending this packet (after the previous one).
    pub delay: std::time::Duration,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn make_config() -> NoiseConfig {
        NoiseConfig {
            reset_interval: Range::constant(0), // inject every check
            items: vec![NoiseItem {
                rand_size: Range::new(64, 128),
                rand_range: [0, 255],
                delay: Range::new(10, 50),
            }],
        }
    }

    #[test]
    fn inject_on_first_check() {
        let mut inj = NoiseInjector::new(make_config());
        let dest: SocketAddr =
            SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443).into();
        let packets = inj
            .should_inject(dest)
            .expect("should inject on first check");
        assert_eq!(packets.len(), 1);
        let p = &packets[0];
        assert!(p.data.len() >= 64 && p.data.len() <= 128);
        assert!(p.delay.as_millis() >= 10 && p.delay.as_millis() <= 50);
    }

    #[test]
    fn no_inject_when_empty() {
        let mut inj = NoiseInjector::empty();
        let dest: SocketAddr =
            SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443).into();
        assert!(inj.should_inject(dest).is_none());
        assert!(!inj.is_enabled());
    }

    #[test]
    fn inject_resets_after_interval() {
        let mut inj = NoiseInjector::new(make_config());
        let dest: SocketAddr =
            SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443).into();

        // First check: injects.
        let p1 = inj.should_inject(dest);
        assert!(p1.is_some());

        // Second check: interval is 0 seconds, so should inject again.
        let p2 = inj.should_inject(dest);
        assert!(p2.is_some());
    }

    #[test]
    fn multiple_items() {
        let config = NoiseConfig {
            reset_interval: Range::constant(0),
            items: vec![
                NoiseItem {
                    rand_size: Range::constant(32),
                    rand_range: [0x41, 0x41], // all 'A'
                    delay: Range::constant(5),
                },
                NoiseItem {
                    rand_size: Range::constant(64),
                    rand_range: [0x42, 0x42], // all 'B'
                    delay: Range::constant(10),
                },
            ],
        };
        let mut inj = NoiseInjector::new(config);
        let dest: SocketAddr =
            SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443).into();
        let packets = inj.should_inject(dest).expect("should inject");
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].data.len(), 32);
        assert!(packets[0].data.iter().all(|&b| b == 0x41));
        assert_eq!(packets[1].data.len(), 64);
        assert!(packets[1].data.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn per_destination_tracking() {
        let mut inj = NoiseInjector::new(make_config());
        let dest1: SocketAddr =
            SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443).into();
        let dest2: SocketAddr =
            SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 443).into();

        // Both should inject independently on first check.
        assert!(inj.should_inject(dest1).is_some());
        assert!(inj.should_inject(dest2).is_some());
    }

    #[test]
    fn noise_data_byte_range() {
        let config = NoiseConfig {
            reset_interval: Range::constant(0),
            items: vec![NoiseItem {
                rand_size: Range::constant(100),
                rand_range: [10, 20],
                delay: Range::constant(0),
            }],
        };
        let inj = NoiseInjector::new(config);
        let data = inj.generate_noise_data(100, &[10, 20]);
        assert_eq!(data.len(), 100);
        assert!(data.iter().all(|&b| b >= 10 && b <= 20));
    }
}
