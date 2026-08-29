//! Generic sequence-numbered chunking and reordering primitives.
//!
//! - [`SeqChunker`]: splits a byte stream into fixed-size chunks, each
//!   tagged with an incrementing sequence number.
//! - [`SeqReorderBuffer`]: buffers out-of-order chunks and delivers them
//!   in ascending sequence order.
//!
//! These are transport-agnostic: XHTTP packet-up uses them for POST/GET
//! chunking, and any multiplexed transport (WebSocket, QUIC datagrams)
//! can reuse them for seq-based framing.

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// SeqChunker
// ---------------------------------------------------------------------------

/// Splits a byte stream into fixed-size chunks with sequence numbers.
///
/// Data accumulates in an internal buffer; when the buffer reaches
/// `chunk_size`, a chunk is emitted with the current `seq` value.
/// On flush, any remaining buffered data is emitted as the final chunk.
///
/// Enforces backpressure via `max_buffered`: when exceeded, `push()`
/// returns `Err(WouldBlock)`.
#[derive(Debug)]
pub struct SeqChunker {
    chunk_size: usize,
    buffer: Vec<u8>,
    next_seq: u64,
    max_buffered: usize,
}

impl SeqChunker {
    /// Create a new chunker with the given chunk size and max buffered bytes.
    pub fn new(chunk_size: usize, max_buffered: usize) -> Self {
        Self {
            chunk_size,
            buffer: Vec::new(),
            next_seq: 0,
            max_buffered,
        }
    }

    /// Push data into the buffer. Returns chunks that are ready to send.
    ///
    /// Each returned chunk is `(seq, data)`.
    /// Returns `Err(WouldBlock)` when the internal buffer exceeds
    /// `max_buffered`, signalling backpressure to the caller.
    pub fn push(&mut self, data: &[u8]) -> std::io::Result<Vec<(u64, Vec<u8>)>> {
        self.buffer.extend_from_slice(data);

        if self.is_overflow() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "seq chunker buffer overflow: too many buffered bytes",
            ));
        }

        let mut chunks = Vec::new();
        while self.buffer.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buffer.drain(..self.chunk_size).collect();
            chunks.push((self.next_seq, chunk));
            self.next_seq += 1;
        }

        Ok(chunks)
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

    /// Current buffered bytes (not yet emitted).
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

impl Default for SeqChunker {
    fn default() -> Self {
        // Default chunk size: 16 KB, default max_buffered: 16 MB
        Self::new(16 * 1024, 16 * 1024 * 1024)
    }
}

// ---------------------------------------------------------------------------
// SeqReorderBuffer
// ---------------------------------------------------------------------------

/// Buffers out-of-order chunks and delivers them in ascending seq order.
///
/// When data arrives in order (no seq), pass through directly.
/// When data arrives out of order (with seq), buffer and return
/// consecutive runs starting from the next expected seq.
#[derive(Debug, Default)]
pub struct SeqReorderBuffer {
    next_seq: u64,
    buffer: BTreeMap<u64, Vec<u8>>,
    use_seq: bool,
}

impl SeqReorderBuffer {
    /// Create a new reorder buffer (passthrough mode, no seq tracking).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a reorder buffer with seq-based reordering enabled.
    pub fn with_seq() -> Self {
        Self {
            next_seq: 0,
            buffer: BTreeMap::new(),
            use_seq: true,
        }
    }

    /// Push ordered data (no seq). Returns data immediately.
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

        self.buffer.insert(seq, data);

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

    // --- SeqChunker ---

    #[test]
    fn chunker_empty_flush_returns_none() {
        let mut q = SeqChunker::new(1024, 16 * 1024 * 1024);
        assert!(q.flush().is_none());
    }

    #[test]
    fn chunker_push_below_chunk_size_no_chunks() {
        let mut q = SeqChunker::new(1024, 16 * 1024 * 1024);
        let chunks = q.push(b"hello").unwrap();
        assert!(chunks.is_empty());
        assert_eq!(q.buffered_len(), 5);
    }

    #[test]
    fn chunker_push_exact_chunk_size() {
        let mut q = SeqChunker::new(4, 16 * 1024 * 1024);
        let chunks = q.push(b"abcd").unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[0].1, b"abcd");
        assert_eq!(q.buffered_len(), 0);
    }

    #[test]
    fn chunker_push_multiple_chunks() {
        let mut q = SeqChunker::new(4, 16 * 1024 * 1024);
        let chunks = q.push(b"abcdefgh").unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[0].1, b"abcd");
        assert_eq!(chunks[1].0, 1);
        assert_eq!(chunks[1].1, b"efgh");
    }

    #[test]
    fn chunker_push_partial_chunk_remains_in_buffer() {
        let mut q = SeqChunker::new(4, 16 * 1024 * 1024);
        let chunks = q.push(b"abcde").unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].1, b"abcd");
        assert_eq!(q.buffered_len(), 1);
    }

    #[test]
    fn chunker_flush_remaining() {
        let mut q = SeqChunker::new(4, 16 * 1024 * 1024);
        q.push(b"abcde").unwrap();
        let flushed = q.flush();
        assert!(flushed.is_some());
        let (seq, data) = flushed.unwrap();
        assert_eq!(seq, 1);
        assert_eq!(data, b"e");
    }

    #[test]
    fn chunker_seq_increments_across_pushes() {
        let mut q = SeqChunker::new(2, 16 * 1024 * 1024);
        let c1 = q.push(b"ab").unwrap();
        let c2 = q.push(b"cd").unwrap();
        let c3 = q.push(b"ef").unwrap();
        assert_eq!(c1[0].0, 0);
        assert_eq!(c2[0].0, 1);
        assert_eq!(c3[0].0, 2);
    }

    #[test]
    fn chunker_seq_continues_after_flush() {
        let mut q = SeqChunker::new(4, 16 * 1024 * 1024);
        q.push(b"abcde").unwrap();
        let f = q.flush().unwrap();
        assert_eq!(f.0, 1);
        assert_eq!(q.next_seq(), 2);
    }

    #[test]
    fn chunker_default_chunk_size() {
        let mut q = SeqChunker::default();
        let data = vec![0u8; 16 * 1024];
        let chunks = q.push(&data).unwrap();
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn chunker_push_returns_wouldblock_on_overflow() {
        let mut q = SeqChunker::new(1024, 10);
        assert!(q.push(b"hi").is_ok());
        let result = q.push(b"hello world this is too much");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }

    // --- SeqReorderBuffer ---

    #[test]
    fn reorder_ordered_passthrough() {
        let mut q = SeqReorderBuffer::new();
        let data = q.push_ordered(b"hello".to_vec());
        assert_eq!(data, b"hello");
    }

    #[test]
    fn reorder_seq_in_order() {
        let mut q = SeqReorderBuffer::with_seq();
        let out = q.push_seq(0, b"a".to_vec());
        assert_eq!(out, vec![b"a".to_vec()]);

        let out = q.push_seq(1, b"b".to_vec());
        assert_eq!(out, vec![b"b".to_vec()]);
    }

    #[test]
    fn reorder_seq_out_of_order() {
        let mut q = SeqReorderBuffer::with_seq();

        let out = q.push_seq(1, b"b".to_vec());
        assert!(out.is_empty());
        assert!(q.has_buffered());

        let out = q.push_seq(0, b"a".to_vec());
        assert_eq!(out, vec![b"a".to_vec(), b"b".to_vec()]);
        assert!(!q.has_buffered());
    }

    #[test]
    fn reorder_seq_gap_then_fill() {
        let mut q = SeqReorderBuffer::with_seq();

        q.push_seq(2, b"c".to_vec());
        assert_eq!(q.buffered_count(), 1);

        let out = q.push_seq(0, b"a".to_vec());
        assert_eq!(out, vec![b"a".to_vec()]);
        assert_eq!(q.next_seq(), 1);

        let out = q.push_seq(1, b"b".to_vec());
        assert_eq!(out, vec![b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(q.next_seq(), 3);
    }

    #[test]
    fn reorder_seq_duplicate_ignored() {
        let mut q = SeqReorderBuffer::with_seq();
        q.push_seq(0, b"a".to_vec());
        let out = q.push_seq(0, b"x".to_vec());
        assert!(out.is_empty());
    }

    #[test]
    fn reorder_seq_large_gap() {
        let mut q = SeqReorderBuffer::with_seq();
        q.push_seq(5, b"f".to_vec());
        q.push_seq(3, b"d".to_vec());
        q.push_seq(4, b"e".to_vec());

        assert_eq!(q.buffered_count(), 3);

        let out = q.push_seq(0, b"a".to_vec());
        assert_eq!(out, vec![b"a".to_vec()]);

        let out = q.push_seq(1, b"b".to_vec());
        assert_eq!(out, vec![b"b".to_vec()]);

        let out = q.push_seq(2, b"c".to_vec());
        assert_eq!(
            out,
            vec![b"c".to_vec(), b"d".to_vec(), b"e".to_vec(), b"f".to_vec()]
        );
        assert!(!q.has_buffered());
    }
}
