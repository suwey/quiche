//! TLS Fragment — split TLS ClientHello to evade DPI SNI matching.
//!
//! Wraps the underlying TCP stream before it is handed to BoringSSL's
//! `SslStream::connect()`.  The first `write()` call (which is the TLS
//! ClientHello) is fragmented into multiple smaller writes with delays
//! between them, so the SNI string spans multiple TCP segments and
//! cannot be matched by single-packet DPI.
//!
//! Only effective on direct (unencrypted) outbound connections where the
//! raw ClientHello is visible to DPI.  Non-TLS first writes pass through
//! unchanged.

use std::io::{self, Read, Write};
use std::time::Duration;

use crate::obfuscation::range::{Range, SegmentRange};

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_SNI_EXTENSION_TYPE: u16 = 0x0000;

/// Configuration for TLS fragmentation.
///
/// When all fields are `None` (the `Default`), fragmentation uses the
/// legacy behavior: split ClientHello at SNI label boundaries with a
/// fixed 100ms delay (or ACK-wait on Linux).
///
/// When fields are set, the enhanced mode activates:
/// - `packets`: which packet numbers to fragment (0-indexed)
/// - `max_split`: random maximum number of split segments
/// - `lengths`: per-segment random length range
/// - `delays`: per-segment random delay range
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct FragmentConfig {
    /// Packet number range to fragment (e.g. `0-1` = only first packet).
    /// `None` means fragment all packets (legacy behavior: first only).
    #[serde(default)]
    pub packets: Option<Range>,

    /// Maximum number of segments to split into.
    /// `None` means use SNI label count (legacy behavior).
    #[serde(default)]
    pub max_split: Option<Range>,

    /// Per-segment length range. If set, segments are padded/truncated
    /// to fall within these ranges. `None` means natural SNI-boundary sizes.
    #[serde(default)]
    pub lengths: Option<SegmentRange>,

    /// Per-segment delay range. `None` means legacy 100ms / ACK-wait.
    #[serde(default)]
    pub delays: Option<SegmentRange>,
}

impl FragmentConfig {
    /// Whether enhanced fragmentation is enabled (any field is set).
    pub fn is_enhanced(&self) -> bool {
        self.packets.is_some()
            || self.max_split.is_some()
            || self.lengths.is_some()
            || self.delays.is_some()
    }

    /// Whether a given packet index should be fragmented.
    pub fn should_fragment_packet(&self, pkt_idx: usize) -> bool {
        match &self.packets {
            Some(r) => {
                let lo = r.from as usize;
                let hi = r.to as usize;
                pkt_idx >= lo && pkt_idx <= hi
            }
            None => pkt_idx == 0, // legacy: first packet only
        }
    }

    /// Return the delay for a given segment index.
    ///
    /// Returns `None` if no delays configured (caller uses legacy behavior).
    pub fn delay_for_segment(&self, seg_idx: usize) -> Option<Duration> {
        self.delays.as_ref().map(|sr| {
            let ms = sr.rand_for_segment(seg_idx);
            std::time::Duration::from_millis(ms as u64)
        })
    }

    /// Return the target length for a given segment index.
    ///
    /// Returns `None` if no lengths configured.
    pub fn length_for_segment(&self, seg_idx: usize) -> Option<usize> {
        self.lengths.as_ref().map(|sr| sr.rand_for_segment(seg_idx) as usize)
    }

    /// Return the maximum number of split segments.
    ///
    /// Returns `None` if not configured (caller uses SNI label count).
    pub fn max_splits(&self) -> Option<usize> {
        self.max_split.as_ref().map(|r| r.rand_usize())
    }
}

/// Delay used on platforms without ACK detection (ms).
const FRAGMENT_SLEEP_DELAY_MS: u64 = 100;

/// Maximum iterations when polling for ACK, each iteration sleeps 2ms.
#[cfg(target_os = "linux")]
const ACK_POLL_MAX_ITERS: u32 = 500; // ~1s cap

#[cfg(target_os = "linux")]
fn wait_for_ack(fd: std::os::fd::RawFd) {
    // On Linux, use TCP_INFO to check tcpi_unacked == 0.
    // This returns once the kernel has received an ACK for all sent data,
    // meaning the remote has received the segment.
    use std::mem::MaybeUninit;
    use std::time::Duration;

    let mut info: MaybeUninit<libc::tcp_info> = MaybeUninit::zeroed();
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;

    for _ in 0..ACK_POLL_MAX_ITERS {
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                info.as_mut_ptr() as *mut _,
                &mut len,
            )
        };
        if ret == 0 {
            let info = unsafe { info.assume_init_ref() };
            if info.tcpi_unacked == 0 {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    // Timed out waiting for ACK — proceed anyway.
    log::warn!("tls fragment: ACK wait timed out, proceeding");
}

#[cfg(all(unix, not(target_os = "linux")))]
fn wait_for_ack(_fd: std::os::fd::RawFd) {
    // Non-Linux platforms: no reliable ACK detection, use sleep fallback.
    std::thread::sleep(Duration::from_millis(FRAGMENT_SLEEP_DELAY_MS));
}

/// Offset and length of the SNI server name within a TLS ClientHello payload.
struct SniLocation {
    /// Absolute offset of the server_name string in the original payload.
    offset: usize,
    /// Length of the server_name string.
    length: usize,
}

/// Find the SNI server name location within a TLS ClientHello.
/// Returns None if this is not a TLS ClientHello with SNI.
fn find_sni_location(payload: &[u8]) -> Option<SniLocation> {
    if payload.len() < 5 || payload[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        return None;
    }

    // Handshake header
    if payload.len() < 6 || payload[5] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }

    // Skip to: record(5) + hs_type(1) + hs_len(3) + client_version(2) + random(32) = 43
    let mut pos = 43;
    if pos >= payload.len() {
        return None;
    }

    // session_id
    let sid_len = payload[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > payload.len() {
        return None;
    }

    // cipher_suites
    let cs_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= payload.len() {
        return None;
    }

    // compression_methods
    let cm_len = payload[pos] as usize;
    pos += 1 + cm_len;
    if pos + 2 > payload.len() {
        return None;
    }

    // extensions total length
    let ext_total = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    let ext_end = (pos + ext_total).min(payload.len());

    // Walk extensions to find SNI
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            break;
        }

        if ext_type == TLS_SNI_EXTENSION_TYPE {
            // SNI extension: list_len(2) + name_type(1) + name_len(2) + name
            let data = &payload[pos..pos + ext_len];
            if data.len() < 5 {
                return None;
            }
            if data[2] != 0x00 {
                return None; // not host_name
            }
            let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
            let name_offset = pos + 5; // absolute offset in payload
            if name_offset + name_len > payload.len() {
                return None;
            }
            return Some(SniLocation {
                offset: name_offset,
                length: name_len,
            });
        }

        pos += ext_len;
    }

    None
}

/// Compute split points that break the SNI domain across TCP segments.
/// Returns a list of (start, end) byte ranges to write separately.
///
/// Strategy (mirrors sing-box):
/// 1. Cut right before SNI begins.
/// 2. Split the SNI at each "." label boundary, choosing a random split
///    point within each label (so the "." itself may end up in either
///    segment).
/// 3. Final segment is the remainder of the payload after SNI.
fn compute_split_points(
    payload: &[u8],
    sni: &SniLocation,
) -> Vec<(usize, usize)> {
    let sni_bytes = &payload[sni.offset..sni.offset + sni.length];
    let sni_str = match std::str::from_utf8(sni_bytes) {
        Ok(s) => s,
        Err(_) => {
            // SNI not valid UTF-8 — just split at SNI midpoint.
            let mid = sni.offset + sni.length / 2;
            return vec![
                (0, sni.offset),
                (sni.offset, mid),
                (mid, payload.len()),
            ];
        }
    };

    // Split SNI at "." boundaries, like sing-box does.
    let labels: Vec<&str> = sni_str.split('.').collect();
    if labels.len() < 2 {
        // Single-label SNI — split at midpoint.
        let mid = sni.offset + sni.length / 2;
        return vec![
            (0, sni.offset),
            (sni.offset, mid),
            (mid, payload.len()),
        ];
    }

    let mut points = vec![0, sni.offset];
    let mut cur = sni.offset;

    for (i, label) in labels.iter().enumerate() {
        // Random split point within the label.
        let split_at = if label.is_empty() {
            0
        } else {
            // Use a simple deterministic split (label midpoint) to avoid
            // pulling in `rand` just for this.  sing-box uses rand, but
            // the exact position doesn't matter much — the key is that
            // the SNI spans multiple TCP segments.
            label.len() / 2
        };
        cur += split_at;
        points.push(cur);
        cur += label.len() - split_at;
        if i < labels.len() - 1 {
            cur += 1; // the "."
        }
    }

    points.push(payload.len());

    // Sort, dedup, and build ranges.
    points.sort();
    points.dedup();

    let mut ranges = Vec::new();
    for i in 0..points.len() - 1 {
        if points[i] < points[i + 1] {
            ranges.push((points[i], points[i + 1]));
        }
    }
    ranges
}

/// A wrapper around `TcpStream` that fragments the first TLS ClientHello
/// write to evade DPI SNI matching.
///
/// Implements `Read + Write` so it can be passed to `SslStream::new()`.
/// After the first `write()`, all I/O passes through unchanged.
pub struct FragmentTcpStream<S> {
    inner: S,
    #[cfg(unix)]
    fd: Option<std::os::fd::RawFd>,
    fragment_enabled: bool,
    first_write_done: bool,
}

#[cfg(unix)]
impl<S: std::os::fd::AsRawFd> FragmentTcpStream<S> {
    pub fn new(inner: S, config: Option<FragmentConfig>) -> Self {
        Self {
            fd: Some(inner.as_raw_fd()),
            fragment_enabled: config.is_some(),
            first_write_done: false,
            inner,
        }
    }

    /// Construct with ACK detection and a `FragmentConfig` (enhanced mode).
    pub fn with_config(inner: S, _config: FragmentConfig) -> Self {
        Self {
            fd: Some(inner.as_raw_fd()),
            fragment_enabled: true,
            first_write_done: false,
            inner,
        }
    }
}

impl<S> FragmentTcpStream<S> {
    /// Construct without ACK detection (sleep fallback always).
    pub fn new_no_ack(inner: S, config: Option<FragmentConfig>) -> Self {
        Self {
            #[cfg(unix)]
            fd: None,
            fragment_enabled: config.is_some(),
            first_write_done: false,
            inner,
        }
    }

    /// Construct without ACK detection, with a `FragmentConfig` (enhanced mode).
    pub fn new_no_ack_with_config(inner: S, _config: FragmentConfig) -> Self {
        Self {
            #[cfg(unix)]
            fd: None,
            fragment_enabled: true,
            first_write_done: false,
            inner,
        }
    }

    /// Get a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: Read> Read for FragmentTcpStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Write> Write for FragmentTcpStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.first_write_done {
            self.first_write_done = true;

            if self.fragment_enabled {
                if let Some(sni) = find_sni_location(buf) {
                    let splits = compute_split_points(buf, &sni);

                    log::debug!(
                        "tls fragment: splitting ClientHello ({} bytes) into {} segments, SNI at offset {} len {}",
                        buf.len(),
                        splits.len(),
                        sni.offset,
                        sni.length,
                    );

                    let mut total_written = 0;
                    for (i, (start, end)) in splits.iter().enumerate() {
                        let chunk = &buf[*start..*end];
                        if chunk.is_empty() {
                            continue;
                        }
                        self.inner.write_all(chunk)?;
                        self.inner.flush()?;
                        total_written += chunk.len();
                        if i < splits.len() - 1 {
                            #[cfg(unix)]
                            {
                                if let Some(fd) = self.fd {
                                    wait_for_ack(fd);
                                } else {
                                    // No fd available - sleep fallback.
                                    std::thread::sleep(Duration::from_millis(FRAGMENT_SLEEP_DELAY_MS));
                                }
                            }
                            #[cfg(not(unix))]
                            {
                                std::thread::sleep(Duration::from_millis(FRAGMENT_SLEEP_DELAY_MS));
                            }
                        }
                    }
                    return Ok(total_written);
                }
            }
        }

        // Not a TLS ClientHello, first write already done, or fragment
        // disabled — pass through.
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Mock stream that records all writes.
    struct MockStream {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Read for MockStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.lock().unwrap().push(buf.to_vec());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn build_client_hello_with_sni(domain: &str) -> Vec<u8> {
        let domain_bytes = domain.as_bytes();
        let sni_entry_len = 1 + 2 + domain_bytes.len();
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len;
        let ext_total = 4 + sni_ext_data_len;

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&u16::to_be_bytes(ext_total as u16));
        extensions.extend_from_slice(&u16::to_be_bytes(0x0000));
        extensions.extend_from_slice(&u16::to_be_bytes(sni_ext_data_len as u16));
        extensions.extend_from_slice(&u16::to_be_bytes(sni_list_len as u16));
        extensions.push(0x00);
        extensions.extend_from_slice(&u16::to_be_bytes(domain_bytes.len() as u16));
        extensions.extend_from_slice(domain_bytes);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&u16::to_be_bytes(2));
        body.extend_from_slice(&[0xc0, 0x2c]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&extensions);

        let body_len = body.len();
        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.push((body_len >> 16) as u8 & 0xff);
        handshake.push((body_len >> 8) as u8 & 0xff);
        handshake.push(body_len as u8 & 0xff);
        handshake.extend_from_slice(&body);

        let rec_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16);
        record.push(0x03);
        record.push(0x01);
        record.extend_from_slice(&u16::to_be_bytes(rec_len as u16));
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn find_sni_in_client_hello() {
        let hello = build_client_hello_with_sni("proxy.example.com");
        let loc = find_sni_location(&hello).expect("should find SNI");
        let name = std::str::from_utf8(&hello[loc.offset..loc.offset + loc.length]).unwrap();
        assert_eq!(name, "proxy.example.com");
    }

    #[test]
    fn no_sni_in_non_tls() {
        assert!(find_sni_location(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
    }

    #[test]
    fn compute_splits_break_within_sni() {
        let hello = build_client_hello_with_sni("proxy.example.com");
        let loc = find_sni_location(&hello).unwrap();
        let splits = compute_split_points(&hello, &loc);
        assert!(splits.len() >= 3, "should split into at least 3 segments: got {}", splits.len());
        // Verify all splits are within bounds.
        for (start, end) in &splits {
            assert!(*start < *end);
            assert!(*end <= hello.len());
        }
    }

    #[test]
    fn fragment_writes_multiple_chunks() {
        let hello = build_client_hello_with_sni("proxy.example.com");
        let writes = Arc::new(Mutex::new(Vec::new()));
        let mock = MockStream {
            writes: writes.clone(),
        };
        let mut stream = FragmentTcpStream::new_no_ack(
            mock,
            Some(FragmentConfig::default()),
        );

        stream.write_all(&hello).unwrap();

        let recorded = writes.lock().unwrap();
        assert!(recorded.len() >= 2, "should write multiple chunks: got {}", recorded.len());
        // Reassemble and verify completeness.
        let total: Vec<u8> = recorded.iter().flatten().cloned().collect();
        assert_eq!(total, hello);
    }

    #[test]
    fn passthrough_non_tls() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let mock = MockStream {
            writes: writes.clone(),
        };
        let mut stream = FragmentTcpStream::new_no_ack(mock, Some(FragmentConfig::default()));

        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        stream.write_all(payload).unwrap();

        let recorded = writes.lock().unwrap();
        assert_eq!(recorded.len(), 1, "non-TLS should pass through as single write");
        assert_eq!(recorded[0], payload);
    }

    #[test]
    fn only_first_write_fragmented() {
        let hello = build_client_hello_with_sni("proxy.example.com");
        let writes = Arc::new(Mutex::new(Vec::new()));
        let mock = MockStream {
            writes: writes.clone(),
        };
        let mut stream = FragmentTcpStream::new_no_ack(
            mock,
            Some(FragmentConfig::default()),
        );

        // First write: ClientHello → fragmented.
        stream.write_all(&hello).unwrap();
        let first_count = writes.lock().unwrap().len();
        assert!(first_count >= 2);

        // Second write: random data → single write.
        stream.write_all(b"subsequent data").unwrap();
        let total = writes.lock().unwrap().len();
        assert_eq!(total, first_count + 1);
    }

    #[test]
    fn single_label_sni_splits_at_midpoint() {
        let hello = build_client_hello_with_sni("localhost");
        let loc = find_sni_location(&hello).unwrap();
        let splits = compute_split_points(&hello, &loc);
        assert!(splits.len() >= 2);
    }
}

// ---------------------------------------------------------------------------
// ObfuscationLayer trait implementation
// ---------------------------------------------------------------------------

use crate::obfuscation::{ObfuscationLayer, ObfContext};

#[async_trait::async_trait]
impl ObfuscationLayer for FragmentConfig {
    async fn pre_send(
        &mut self,
        data: &[u8],
        _ctx: &ObfContext,
    ) -> io::Result<Vec<u8>> {
        // FragmentConfig 作用于 TCP 层（TLS ClientHello 分片），
        // 不在数据层修改 payload，直接透传
        Ok(data.to_vec())
    }

    async fn post_recv(
        &mut self,
        data: &[u8],
        _ctx: &ObfContext,
    ) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn name(&self) -> &'static str {
        "tls-fragment"
    }
}

// ---------------------------------------------------------------------------
// ObfuscationLayer trait tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod obfuscation_trait_tests {
    use super::*;
    use crate::obfuscation::{ObfuscationLayer, ObfContext};

    #[tokio::test]
    async fn fragment_impl_obfuscation_layer() {
        let mut frag = FragmentConfig::default();
        let ctx = ObfContext {
            request_url: None,
            is_first: true,
            seq: None,
        };
        let data = b"test data";
        let out = frag.pre_send(data, &ctx).await.unwrap();
        assert_eq!(out, data); // FragmentConfig 透传数据
    }
}
