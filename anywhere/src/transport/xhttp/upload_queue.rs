//! Upload queue for packet-up mode: buffers data and splits into
//! fixed-size chunks, each sent as a separate POST with an incrementing
//! sequence number.
//!
//! Mirrors Xray's `splithttp` upload packet behavior:
//! - Data accumulates in a buffer
//! - When the buffer reaches `chunk_size`, a chunk is emitted with the
//!   current `seq` value
//! - On flush, any remaining buffered data is emitted as the final chunk
//! - The server reassembles chunks by `seq` order

// ---------------------------------------------------------------------------
// UploadQueue
// ---------------------------------------------------------------------------

/// Buffers data and splits it into chunks for packet-up mode.
///
/// Each chunk is tagged with a sequence number. The caller sends each
/// chunk as a separate HTTP POST with `?seq=N` in the URL.
#[derive(Debug)]
pub struct UploadQueue {
    chunk_size: usize,
    buffer: Vec<u8>,
    next_seq: u64,
    /// Maximum bytes to buffer before forcing a flush (backpressure).
    max_buffered: usize,
}

impl UploadQueue {
    /// Create a new upload queue with the given chunk size.
    ///
    /// Default `max_buffered` is 16 MB (matches Xray's `scMaxBufferedPosts`).
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size,
            buffer: Vec::new(),
            next_seq: 0,
            max_buffered: 16 * 1024 * 1024,
        }
    }

    /// Push data into the buffer. Returns chunks that are ready to send.
    ///
    /// Each returned chunk is `(seq, data)`. The caller should send each
    /// as a separate POST request with `?seq=<seq>`.
    pub fn push(&mut self, data: &[u8]) -> Vec<(u64, Vec<u8>)> {
        self.buffer.extend_from_slice(data);

        let mut chunks = Vec::new();
        while self.buffer.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buffer.drain(..self.chunk_size).collect();
            chunks.push((self.next_seq, chunk));
            self.next_seq += 1;
        }

        chunks
    }

    /// Flush remaining buffer. Returns the last chunk if any.
    ///
    /// Should be called on shutdown to ensure all buffered data is sent.
    pub fn flush(&mut self) -> Option<(u64, Vec<u8>)> {
        if self.buffer.is_empty() {
            return None;
        }
        let chunk = std::mem::take(&mut self.buffer);
        let seq = self.next_seq;
        self.next_seq += 1;
        Some((seq, chunk))
    }

    /// Current buffered bytes (not yet sent).
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the buffer exceeds the max (backpressure signal).
    pub fn is_overflow(&self) -> bool {
        self.buffer.len() > self.max_buffered
    }

    /// Next sequence number that will be assigned.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

impl Default for UploadQueue {
    fn default() -> Self {
        // Default chunk size: 16 KB (matches Xray's `scMaxEachPostBytes` default)
        Self::new(16 * 1024)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_flush_returns_none() {
        let mut q = UploadQueue::new(1024);
        assert!(q.flush().is_none());
    }

    #[test]
    fn push_below_chunk_size_no_chunks() {
        let mut q = UploadQueue::new(1024);
        let chunks = q.push(b"hello");
        assert!(chunks.is_empty());
        assert_eq!(q.buffered_len(), 5);
    }

    #[test]
    fn push_exact_chunk_size() {
        let mut q = UploadQueue::new(4);
        let chunks = q.push(b"abcd");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, 0); // seq = 0
        assert_eq!(chunks[0].1, b"abcd");
        assert_eq!(q.buffered_len(), 0);
    }

    #[test]
    fn push_multiple_chunks() {
        let mut q = UploadQueue::new(4);
        let chunks = q.push(b"abcdefgh"); // 8 bytes, chunk_size=4 -> 2 chunks
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[0].1, b"abcd");
        assert_eq!(chunks[1].0, 1);
        assert_eq!(chunks[1].1, b"efgh");
    }

    #[test]
    fn push_partial_chunk_remains_in_buffer() {
        let mut q = UploadQueue::new(4);
        let chunks = q.push(b"abcde"); // 5 bytes, chunk_size=4 -> 1 chunk + 1 byte
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].1, b"abcd");
        assert_eq!(q.buffered_len(), 1);
    }

    #[test]
    fn flush_remaining() {
        let mut q = UploadQueue::new(4);
        q.push(b"abcde"); // 1 chunk + 1 byte remaining
        let flushed = q.flush();
        assert!(flushed.is_some());
        let (seq, data) = flushed.unwrap();
        assert_eq!(seq, 1);
        assert_eq!(data, b"e");
    }

    #[test]
    fn seq_increments_across_pushes() {
        let mut q = UploadQueue::new(2);
        let c1 = q.push(b"ab"); // seq 0
        let c2 = q.push(b"cd"); // seq 1
        let c3 = q.push(b"ef"); // seq 2
        assert_eq!(c1[0].0, 0);
        assert_eq!(c2[0].0, 1);
        assert_eq!(c3[0].0, 2);
    }

    #[test]
    fn seq_continues_after_flush() {
        let mut q = UploadQueue::new(4);
        q.push(b"abcde"); // chunk seq=0, buffer="e"
        let f = q.flush().unwrap(); // seq=1
        assert_eq!(f.0, 1);
        assert_eq!(q.next_seq(), 2);
    }

    #[test]
    fn overflow_detection() {
        let mut q = UploadQueue::new(1024);
        q.max_buffered = 10;
        q.push(b"hello world"); // 11 bytes > 10
        assert!(q.is_overflow());
    }

    #[test]
    fn default_chunk_size() {
        let q = UploadQueue::default();
        let mut q2 = q;
        let data = vec![0u8; 16 * 1024];
        let chunks = q2.push(&data);
        assert_eq!(chunks.len(), 1);
    }
}
