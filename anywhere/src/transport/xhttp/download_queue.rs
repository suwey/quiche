//! Download queue: reorders out-of-sequence download packets.
//!
//! For stream-one and stream-up: downlink is a single GET long response,
//! data arrives in order, queue is pass-through.
//!
//! For packet-up (future: multiple GET responses): packets may arrive
//! out of order, queue buffers and returns data in seq order.
// TODO: M5 server-side — download queue is not yet used by the server.

use std::collections::BTreeMap;

/// Reorders download packets by sequence number.
///
/// When data arrives in order (no seq), pass through directly.
/// When data arrives out of order (with seq), buffer and return
/// in ascending seq order.
#[derive(Debug, Default)]
pub struct DownloadQueue {
    /// Next expected seq number (0 = start).
    next_seq: u64,
    /// Buffered out-of-order chunks keyed by seq.
    buffer: BTreeMap<u64, Vec<u8>>,
    /// Whether seq-based reordering is active.
    use_seq: bool,
}

impl DownloadQueue {
    /// Create a new download queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a download queue with seq-based reordering enabled.
    pub fn with_seq() -> Self {
        Self {
            next_seq: 0,
            buffer: BTreeMap::new(),
            use_seq: true,
        }
    }

    /// Push ordered data (no seq). Returns data immediately.
    ///
    /// Use this for stream-one / stream-up where data is already in order.
    pub fn push_ordered(&mut self, data: Vec<u8>) -> Vec<u8> {
        data
    }

    /// Push data with a sequence number.
    ///
    /// Returns all data that can be delivered in order (may be empty
    /// if the expected seq hasn't arrived yet).
    pub fn push_seq(&mut self, seq: u64, data: Vec<u8>) -> Vec<Vec<u8>> {
        if !self.use_seq {
            return vec![data];
        }

        // Buffer the data
        self.buffer.insert(seq, data);

        // Deliver all consecutive chunks starting from next_seq
        let mut output = Vec::new();
        while let Some(data) = self.buffer.remove(&self.next_seq) {
            output.push(data);
            self.next_seq += 1;
        }

        output
    }

    /// Whether there are buffered (undeliverable) chunks.
    pub fn has_buffered(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Number of buffered chunks.
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    /// Next expected seq number.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_passthrough() {
        let mut q = DownloadQueue::new();
        let data = q.push_ordered(b"hello".to_vec());
        assert_eq!(data, b"hello");
    }

    #[test]
    fn seq_in_order() {
        let mut q = DownloadQueue::with_seq();
        let out = q.push_seq(0, b"a".to_vec());
        assert_eq!(out, vec![b"a".to_vec()]);

        let out = q.push_seq(1, b"b".to_vec());
        assert_eq!(out, vec![b"b".to_vec()]);
    }

    #[test]
    fn seq_out_of_order() {
        let mut q = DownloadQueue::with_seq();

        // seq=1 arrives first -> buffered
        let out = q.push_seq(1, b"b".to_vec());
        assert!(out.is_empty());
        assert!(q.has_buffered());

        // seq=0 arrives -> deliver 0 and 1
        let out = q.push_seq(0, b"a".to_vec());
        assert_eq!(out, vec![b"a".to_vec(), b"b".to_vec()]);
        assert!(!q.has_buffered());
    }

    #[test]
    fn seq_gap_then_fill() {
        let mut q = DownloadQueue::with_seq();

        // seq=2 arrives -> buffered
        q.push_seq(2, b"c".to_vec());
        assert_eq!(q.buffered_count(), 1);

        // seq=0 arrives -> deliver 0
        let out = q.push_seq(0, b"a".to_vec());
        assert_eq!(out, vec![b"a".to_vec()]);
        assert_eq!(q.next_seq(), 1);

        // seq=1 arrives -> deliver 1 and 2
        let out = q.push_seq(1, b"b".to_vec());
        assert_eq!(out, vec![b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(q.next_seq(), 3);
    }

    #[test]
    fn seq_duplicate_ignored() {
        let mut q = DownloadQueue::with_seq();
        q.push_seq(0, b"a".to_vec());
        // Duplicate seq=0 -> overwrites buffer, but next_seq already advanced
        let out = q.push_seq(0, b"x".to_vec());
        assert!(out.is_empty()); // next_seq=1, seq=0 is stale
    }

    #[test]
    fn seq_large_gap() {
        let mut q = DownloadQueue::with_seq();
        q.push_seq(5, b"f".to_vec());
        q.push_seq(3, b"d".to_vec());
        q.push_seq(4, b"e".to_vec());

        assert_eq!(q.buffered_count(), 3);
        assert!(!q.has_buffered() == false);

        // seq=0 arrives -> deliver 0
        let out = q.push_seq(0, b"a".to_vec());
        assert_eq!(out, vec![b"a".to_vec()]);

        // seq=1 arrives -> deliver 1
        let out = q.push_seq(1, b"b".to_vec());
        assert_eq!(out, vec![b"b".to_vec()]);

        // seq=2 arrives -> deliver 2,3,4,5
        let out = q.push_seq(2, b"c".to_vec());
        assert_eq!(
            out,
            vec![b"c".to_vec(), b"d".to_vec(), b"e".to_vec(), b"f".to_vec()]
        );
        assert!(!q.has_buffered());
    }
}
