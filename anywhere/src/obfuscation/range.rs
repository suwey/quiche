//! Range and SegmentRange — interval random primitives for obfuscation.
//!
//! Uses a thread-local LCG PRNG (same algorithm as `protocol::anytls::LcgGen`)
//! to avoid pulling in the `rand` crate. Seeded from system nanos on first use.

use std::cell::RefCell;

// ---------------------------------------------------------------------------
// LCG PRNG (same constants as protocol/anytls.rs LcgGen)
// ---------------------------------------------------------------------------

thread_local! {
    static LCG: RefCell<u64> = RefCell::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1),
    );
}

fn lcg_next() -> u64 {
    LCG.with(|cell| {
        let mut state = cell.borrow_mut();
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state
    })
}

/// Random integer in [min, max] (inclusive).
pub(crate) fn rand_range(min: i64, max: i64) -> i64 {
    if min >= max {
        return min;
    }
    // Use upper 32 bits of LCG output for better quality
    // (lower bits of LCG have shorter periods)
    let raw = lcg_next();
    min + ((raw >> 32) % (max - min + 1) as u64) as i64
}

// ---------------------------------------------------------------------------
// Range — single interval [from, to]
// ---------------------------------------------------------------------------

/// A single inclusive interval `[from, to]`.
///
/// `rand()` returns a random value within the interval on each call.
/// When `from == to` the value is deterministic (acts as a constant).
#[derive(Debug, Clone, Default, serde::Deserialize, PartialEq, Eq)]
pub struct Range {
    pub from: i64,
    pub to: i64,
}

impl Range {
    /// Create a fixed (zero-width) range that always returns `val`.
    pub fn constant(val: i64) -> Self {
        Self { from: val, to: val }
    }

    /// Create an interval `[from, to]`.
    pub fn new(from: i64, to: i64) -> Self {
        Self { from, to }
    }

    /// Return a random value in `[from, to]`.
    pub fn rand(&self) -> i64 {
        rand_range(self.from, self.to)
    }

    /// Return a random value as `u64`.
    pub fn rand_u64(&self) -> u64 {
        self.rand() as u64
    }

    /// Return a random value as `usize`.
    pub fn rand_usize(&self) -> usize {
        self.rand() as usize
    }

    /// Return a random value as `u32`.
    pub fn rand_u32(&self) -> u32 {
        self.rand() as u32
    }

    /// Return a random duration (interpreting the range as milliseconds).
    pub fn rand_duration(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.rand_u64())
    }
}

// ---------------------------------------------------------------------------
// SegmentRange — per-segment intervals
// ---------------------------------------------------------------------------

/// Per-segment interval configuration.
///
/// `mins` and `maxs` are parallel arrays: segment `i` uses
/// `[mins[i], maxs[i]]`. If the index exceeds the array length,
/// the last element is reused (or 0 if empty).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct SegmentRange {
    pub mins: Vec<i64>,
    pub maxs: Vec<i64>,
}

impl SegmentRange {
    /// Create an empty `SegmentRange` (all segments return 0).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from parallel arrays.
    pub fn from_arrays(mins: Vec<i64>, maxs: Vec<i64>) -> Self {
        Self { mins, maxs }
    }

    /// Create from a list of (min, max) tuples.
    pub fn from_pairs(pairs: &[(i64, i64)]) -> Self {
        let mins = pairs.iter().map(|(a, _)| *a).collect();
        let maxs = pairs.iter().map(|(_, b)| *b).collect();
        Self { mins, maxs }
    }

    /// Return a random value for segment `seg_idx`.
    ///
    /// If `seg_idx` exceeds the array length, the last element is reused.
    /// If both arrays are empty, returns 0.
    pub fn rand_for_segment(&self, seg_idx: usize) -> i64 {
        if self.mins.is_empty() || self.maxs.is_empty() {
            return 0;
        }
        let idx = seg_idx.min(self.mins.len() - 1).min(self.maxs.len() - 1);
        rand_range(self.mins[idx], self.maxs[idx])
    }

    /// Number of configured segments.
    pub fn len(&self) -> usize {
        self.mins.len().min(self.maxs.len())
    }

    /// Whether any segments are configured.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PartialEq for SegmentRange {
    fn eq(&self, other: &Self) -> bool {
        self.mins == other.mins && self.maxs == other.maxs
    }
}

impl Eq for SegmentRange {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_constant() {
        let r = Range::constant(42);
        for _ in 0..100 {
            assert_eq!(r.rand(), 42);
        }
    }

    #[test]
    fn range_interval_in_bounds() {
        let r = Range::new(10, 20);
        for _ in 0..1000 {
            let v = r.rand();
            assert!(v >= 10 && v <= 20, "value {} out of [10, 20]", v);
        }
    }

    #[test]
    fn range_default_is_zero() {
        let r = Range::default();
        assert_eq!(r.rand(), 0);
    }

    #[test]
    fn range_rand_duration() {
        let r = Range::new(100, 200);
        let d = r.rand_duration();
        let ms = d.as_millis();
        assert!(ms >= 100 && ms <= 200);
    }

    #[test]
    fn segment_range_empty_returns_zero() {
        let sr = SegmentRange::new();
        assert_eq!(sr.rand_for_segment(0), 0);
        assert_eq!(sr.rand_for_segment(10), 0);
    }

    #[test]
    fn segment_range_in_bounds() {
        let sr = SegmentRange::from_pairs(&[(10, 20), (100, 200), (1, 5)]);
        for i in 0..10 {
            let v = sr.rand_for_segment(i);
            // Segments beyond len-1 reuse last entry [1, 5]
            let expected_idx = i.min(2);
            let (lo, hi) = match expected_idx {
                0 => (10, 20),
                1 => (100, 200),
                _ => (1, 5),
            };
            assert!(v >= lo && v <= hi, "seg {} got {} not in [{}, {}]", i, v, lo, hi);
        }
    }

    #[test]
    fn segment_range_from_arrays() {
        let sr = SegmentRange::from_arrays(vec![5, 10], vec![15, 20]);
        assert_eq!(sr.len(), 2);
        assert!(!sr.is_empty());
    }

    #[test]
    fn range_equality() {
        assert_eq!(Range::new(1, 10), Range::new(1, 10));
        assert_ne!(Range::new(1, 10), Range::new(1, 11));
    }

    #[test]
    fn segment_range_equality() {
        let a = SegmentRange::from_pairs(&[(1, 2), (3, 4)]);
        let b = SegmentRange::from_pairs(&[(1, 2), (3, 4)]);
        assert_eq!(a, b);
        let c = SegmentRange::from_pairs(&[(1, 2), (3, 5)]);
        assert_ne!(a, c);
    }

    #[test]
    fn range_single_value() {
        // from == to acts as constant
        let r = Range::new(7, 7);
        assert_eq!(r.rand(), 7);
    }

    #[test]
    fn lcgproduces_different_values() {
        // Two consecutive calls should (almost certainly) differ.
        let a = lcg_next();
        let b = lcg_next();
        assert_ne!(a, b, "LCG produced same value twice");
    }
}
