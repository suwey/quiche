//! XTLS Vision data plane (M2) — padding-phase state machines.
//!
//! Byte-exact port of Xray-core's Vision implementation in
//! `proxy/proxy.go`: `VisionWriter` (:289-404), `VisionReader` (:174-285),
//! `XtlsPadding` (:496-532), `XtlsUnpadding` (:535-616), `XtlsFilterTls`
//! (:619-670), `IsCompleteRecord` (:407-458) and `ReshapeMultiBuffer`
//! (:460-493). Wire-format evidence lives in
//! `docs/vless-reality-wire-notes.md` §S2; every branch below cites the
//! Xray line it mirrors.
//!
//! # Framing (proxy.go:496-532)
//!
//! The first frame of each direction is prefixed with the 16-byte user UUID
//! (`writeOnceUserUUID`, :519-522, written exactly once). Every frame is
//! `command(1) + content_len(2 BE) + padding_len(2 BE) + content + padding`
//! with zero-filled padding. `command` is 0x00 Continue, 0x01 End, 0x02
//! Direct (:56-58). Padding length (:502-517): when `longPadding` (the
//! stream is TLS and `contentLen < 900`) `paddingLen = rand[0,500) + 900 -
//! contentLen`, so content+padding lands in [900, 1400); otherwise
//! `rand[0,256)`; always capped at `2048 - 21 - contentLen` (21 = UUID +
//! frame header). Randomness comes from the system CSPRNG
//! (`obfuscation::range::rand_range`, rejection-sampled getrandom) — never
//! an LCG.
//!
//! # The four independent state lines
//!
//! Xray keeps four per-direction lines (In/Out × read/write) plus one
//! shared TLS-detection block per connection (TrafficState, :104-114). A
//! client needs two of them: an uplink [`VisionWriter`] (Outbound write
//! line) and a downlink [`VisionReader`] (Outbound read line), sharing one
//! [`VisionFilterState`]. The shared state is guarded by a mutex because
//! the two relay halves run in separate tasks (Xray shares the struct
//! across goroutines the same way).
//!
//! # Direct phase semantics and the raw-socket handoff (§S2.6)
//!
//! Seeing the first complete inner-TLS AppData record, the writer sends the
//! frame carrying End (Direct when EnableXtls) through the outer TLS/REALITY
//! stream and stops padding; with Direct, every subsequent write must go to
//! the raw TCP socket instead of the SSL stream (Xray `UnwrapRawConn`,
//! :343-347 / :280-283). Likewise the reader that decodes a Direct frame
//! stops unpadding and the transport must splice the raw socket from then
//! on. On the read side this raises the "buffer drainage" question: raw TCP
//! bytes coalesced after the last REALITY record could sit inside the TLS
//! library's buffers and be lost at the switch. **For boring this cannot
//! happen — the switch-point buffers are provably empty:**
//!
//! 1. `tls_read_buffer_extend_to` (`ssl/ssl_buffer.cc:145-167`) reads from
//!    the BIO in a `while (buf->size() < len)` loop requesting exactly
//!    `len - buf->size()` bytes, where `len` is the current record's
//!    `5 + ciphertext_len` (`tls_record.cc:217/:246` report the partial
//!    record's exact total). A BIO read can only return *at most* the
//!    requested length (tokio-boring's `AsyncStreamBridge::read` maps
//!    `BIO_read` onto `poll_read`, which never fills beyond the caller's
//!    buffer), so `read_buffer` never contains bytes past the record being
//!    fetched — no TCP coalescing ever leaks into it.
//! 2. After a record is fully consumed, `SSL_read`
//!    (`ssl/ssl_lib.cc:1031-1044`) drops it: when the returned plaintext
//!    span `pending_app_data` is drained it calls
//!    `read_buffer.DiscardConsumed()`, and `SSLBuffer::DiscardConsumed`
//!    (`ssl_buffer.cc:118-122`) `Clear()`s an empty buffer.
//! 3. The relay's reader always calls `SSL_read` with a 16384-byte buffer,
//!    the TLS plaintext maximum, so each record is returned in one call and
//!    `pending_app_data` is always empty between calls
//!    (`ssl_read_impl` only fetches new records while `pending_app_data`
//!    is empty, `ssl_lib.cc:967`).
//! 4. Nothing between boring and the socket buffers reads:
//!    `AsyncFragmentStream::poll_read` (`obfuscation/fragment.rs`) and
//!    `AsyncStreamBridge::read` are pure pass-through.
//!
//! Therefore, when a decrypted chunk containing the Direct command has been
//! delivered, every byte the server sent after the final REALITY record is
//! still in the kernel receive buffer, and reading the raw socket from that
//! point yields the lossless continuation. (Xray needs reflection to drain
//! uTLS's `input`/`rawInput` because Go's TLS over-reads via bufio —
//! outbound.go:286-289 — boring's exact-length record reads remove the
//! problem at the source.) `SSL_write` is symmetric: the write buffer is
//! flushed to the BIO in full before `SSL_write` returns success
//! (`tls_write_buffer_flush`, `ssl_buffer.cc:260-273` loops until
//! `buf->empty()`), so the Direct frame itself is entirely on the wire
//! before the next write goes raw.
//!
//! The raw socket handle is obtained with `TcpStream::try_clone` before the
//! relay splits the SSL stream (the fd is duplicated; dropping the SSL
//! halves later does not close the socket). Vision state machines freeze
//! after the handoff: both directions become pure byte splices.

use std::sync::{Arc, Mutex};

use crate::obfuscation::range::rand_range;

// ---------------------------------------------------------------------------
// Protocol constants — proxy.go:37-59
// ---------------------------------------------------------------------------

pub(crate) const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub(crate) const COMMAND_PADDING_END: u8 = 0x01;
pub(crate) const COMMAND_PADDING_DIRECT: u8 = 0x02;

const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// Xray `buf.Size` (common/buf/buffer.go): outer buffer unit and the frame
/// total-size bound.
const BUF_SIZE: i64 = 2048;
/// Per-frame overhead bound: 16-byte UUID prefix + 5-byte frame header
/// (proxy.go:515 `buf.Size - 21 - contentLen`).
const FRAME_OVERHEAD: i64 = 21;

/// Default testseed (proxy.go:308 `{900, 500, 900, 256}`): long-padding
/// threshold, long-padding random range, long-padding base, short-padding
/// range.
const TESTSEED_LONG_THRESHOLD: i64 = 900;
const TESTSEED_LONG_RAND: i64 = 500;
const TESTSEED_LONG_BASE: i64 = 900;
const TESTSEED_SHORT_RAND: i64 = 256;

/// TLS 1.3 cipher suites that enable Direct (proxy.go:43-49 dictionary,
/// :650-655: in the table and not `TLS_AES_128_CCM_8_SHA256`, i.e.
/// 0x1305 is excluded).
fn is_tls13_cipher(cipher: u16) -> bool {
    matches!(cipher, 0x1301..=0x1304)
}

/// IsCompleteRecord — complete-TLS-AppData-record check over one write
/// (proxy.go:407-458). Every byte must belong to a whole `17 03 03`
/// record; an empty input is vacuously complete (:454 quirk).
fn is_complete_record(b: &[u8]) -> bool {
    let mut header_len = 5usize;
    let mut record_len = 0usize;
    let total = b.len();
    let mut i = 0usize;
    while i < total {
        if header_len > 0 {
            let data = b[i];
            i += 1;
            match header_len {
                5 => {
                    if data != 0x17 {
                        return false;
                    }
                },
                4 | 3 => {
                    if data != 0x03 {
                        return false;
                    }
                },
                2 => record_len = (data as usize) << 8,
                1 => record_len |= data as usize,
                _ => unreachable!("header_len is 1..=5"),
            }
            header_len -= 1;
        } else if record_len > 0 {
            let remaining = total - i;
            if remaining < record_len {
                return false;
            }
            i += record_len;
            record_len = 0;
            header_len = 5;
        } else {
            return false;
        }
    }
    header_len == 5 && record_len == 0
}

/// ReshapeMultiBuffer equivalent (proxy.go:460-493): split the write into
/// Xray-sized 2048-byte buffer units, then split any unit ≥ `2048-21` at
/// the last `17 03 03` boundary — or the midpoint when the boundary falls
/// outside `[21, 2048-21]` — so a padded frame never exceeds the buffer
/// size. Returns borrowed pieces of `chunk`.
fn reshape_pieces(chunk: &[u8]) -> Vec<&[u8]> {
    let mut pieces: Vec<&[u8]> = Vec::new();
    for unit in chunk.chunks(BUF_SIZE as usize) {
        if unit.len() as i64 >= BUF_SIZE - FRAME_OVERHEAD {
            let mut index = unit
                .windows(3)
                .rposition(|w| w == TLS_APPLICATION_DATA_START)
                .map_or(-1i64, |i| i as i64);
            if index < FRAME_OVERHEAD || index > BUF_SIZE - FRAME_OVERHEAD {
                index = BUF_SIZE / 2;
            }
            pieces.push(&unit[..index as usize]);
            pieces.push(&unit[index as usize..]);
        } else {
            pieces.push(unit);
        }
    }
    pieces
}

// ---------------------------------------------------------------------------
// Shared TLS-detection state — TrafficState filter half (proxy.go:104-114)
// ---------------------------------------------------------------------------

/// Shared inner-TLS detection state of one VLESS connection: the filter
/// fields of Xray's `TrafficState`, mutated by [`VisionFilterState::filter_tls`]
/// from both the uplink writer (sees the inner ClientHello) and the downlink
/// reader (sees the inner ServerHello).
pub(crate) struct VisionFilterState {
    number_of_packets_to_filter: i32,
    enable_xtls: bool,
    is_tls12_or_above: bool,
    is_tls: bool,
    cipher: u16,
    remaining_server_hello: i32,
}

impl VisionFilterState {
    pub(crate) fn new() -> Self {
        Self {
            // NewTrafficState: NumberOfPacketToFilter = 8,
            // RemainingServerHello = -1 (proxy.go:142-150).
            number_of_packets_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }

    /// XtlsFilterTls (proxy.go:619-670). Called with the plain (uplink) or
    /// unpadded (downlink) chunk; `NumberOfPacketToFilter` decrements once
    /// per 2048-byte buffer unit, mirroring Xray's per-MultiBuffer-entry
    /// loop. Conclusive results stop the filter (`:657/:661`).
    pub(crate) fn filter_tls(&mut self, chunk: &[u8]) {
        for unit in chunk.chunks(BUF_SIZE as usize) {
            self.number_of_packets_to_filter -= 1;
            if unit.len() >= 6 {
                if unit[..3] == TLS_SERVER_HANDSHAKE_START
                    && unit[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
                {
                    // :627-630 — record length + 5.
                    self.remaining_server_hello =
                        ((unit[3] as i32) << 8 | unit[4] as i32) + 5;
                    self.is_tls12_or_above = true;
                    self.is_tls = true;
                    if unit.len() >= 79 && self.remaining_server_hello >= 79 {
                        // :632-634 — cipher suite at 43 + sessionIdLen + 1.
                        let sid_len = unit[43] as usize;
                        self.cipher = ((unit[43 + sid_len + 1] as u16) << 8)
                            | unit[43 + sid_len + 2] as u16;
                    } else {
                        log::debug!(
                            "vision: XtlsFilterTls short server hello, tls 1.2 or older? len={} remaining={}",
                            unit.len(),
                            self.remaining_server_hello,
                        );
                    }
                } else if unit[..2] == TLS_CLIENT_HANDSHAKE_START
                    && unit[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
                {
                    // :638-640.
                    self.is_tls = true;
                    log::debug!("vision: XtlsFilterTls found tls client hello!");
                }
            }
            if self.remaining_server_hello > 0 {
                let end =
                    (self.remaining_server_hello as usize).min(unit.len());
                self.remaining_server_hello -= unit.len() as i32;
                if unit[..end]
                    .windows(6)
                    .any(|w| w == TLS13_SUPPORTED_VERSIONS)
                {
                    // :649-655 — supported_versions + TLS 1.3 cipher (and
                    // not CCM_8) enables Direct.
                    if is_tls13_cipher(self.cipher) {
                        self.enable_xtls = true;
                    }
                    log::debug!(
                        "vision: XtlsFilterTls found tls 1.3! cipher={:#06x} enable_xtls={}",
                        self.cipher,
                        self.enable_xtls,
                    );
                    self.number_of_packets_to_filter = 0;
                    return;
                } else if self.remaining_server_hello <= 0 {
                    log::debug!("vision: XtlsFilterTls found tls 1.2!");
                    self.number_of_packets_to_filter = 0;
                    return;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Uplink writer — Outbound write state line (proxy.go:289-404)
// ---------------------------------------------------------------------------

/// Vision uplink writer (client → server, padding phase). Frames every
/// write until the first complete inner AppData record is seen (End, or
/// Direct when the shared state detected TLS 1.3) or the filter quota runs
/// out on a non-TLS/TLS 1.2 stream (End). Afterwards it is the identity.
pub(crate) struct VisionWriter {
    uuid: [u8; 16],
    /// `writeOnceUserUUID != nil` (proxy.go:298) — the next frame carries
    /// the UUID prefix.
    uuid_pending: bool,
    /// `Outbound.IsPadding` (:139).
    is_padding: bool,
    /// `Outbound.UplinkWriterDirectCopy` (:139).
    switch_to_direct: bool,
    state: Arc<Mutex<VisionFilterState>>,
}

impl VisionWriter {
    pub(crate) fn new(uuid: [u8; 16], state: Arc<Mutex<VisionFilterState>>) -> Self {
        Self {
            uuid,
            uuid_pending: true,
            is_padding: true,
            switch_to_direct: false,
            state,
        }
    }

    /// Frame one uplink chunk. Returns the bytes to push through the outer
    /// TLS/REALITY stream (identity once padding ended; empty input →
    /// empty output). After the returned bytes have been written, call
    /// [`Self::take_direct_switch`]: when it returns true the frame just
    /// written carried Direct and the transport must send everything
    /// further on the raw socket.
    pub(crate) fn write_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        // Clone the Arc so the guard does not borrow `self`.
        let state_arc = self.state.clone();
        let mut state = state_arc.lock().unwrap();
        // FilterTls runs on every write while the quota remains,
        // regardless of the padding state (:352-354).
        if state.number_of_packets_to_filter > 0 {
            state.filter_tls(chunk);
        }
        if !self.is_padding {
            return chunk.to_vec();
        }
        if chunk.is_empty() {
            return Vec::new();
        }

        let is_complete = is_complete_record(chunk);
        let pieces = reshape_pieces(chunk);
        let mut out = Vec::with_capacity(chunk.len() + 64);
        // `longPadding := w.trafficState.IsTLS` (:362).
        let mut long_padding = state.is_tls;
        let mut i = 0;
        while i < pieces.len() {
            let piece = pieces[i];
            let is_last = i + 1 == pieces.len();
            if state.is_tls
                && piece.len() >= 6
                && piece.starts_with(&TLS_APPLICATION_DATA_START)
                && is_complete
            {
                // :364-378 — first complete AppData record ends padding.
                if state.enable_xtls {
                    self.switch_to_direct = true;
                }
                let command = if is_last {
                    if state.enable_xtls {
                        COMMAND_PADDING_DIRECT
                    } else {
                        COMMAND_PADDING_END
                    }
                } else {
                    COMMAND_PADDING_CONTINUE
                };
                log::debug!(
                    "vision: uplink inner AppData record ({}B), command={command}",
                    piece.len(),
                );
                // Branch 1 passes longPadding=true literally (:375).
                self.frame_into(&mut out, piece, command, true, &state);
                self.is_padding = false;
                long_padding = false;
                i += 1;
                continue;
            } else if !state.is_tls12_or_above
                && state.number_of_packets_to_filter <= 1
            {
                // :379-382 — non-TLS/TLS 1.2: finish one packet early with
                // End; the remaining pieces stay unframed (Xray breaks and
                // the tail of the MultiBuffer is written as-is). Never
                // Direct.
                log::debug!("vision: uplink filter quota exhausted, sending End");
                self.frame_into(
                    &mut out,
                    piece,
                    COMMAND_PADDING_END,
                    long_padding,
                    &state,
                );
                self.is_padding = false;
                for rest in &pieces[i + 1..] {
                    out.extend_from_slice(rest);
                }
                break;
            }
            // :384-391 — plain Continue frame; when padding already ended
            // earlier in this write the final piece carries End/Direct.
            let command = if is_last && !self.is_padding {
                if state.enable_xtls {
                    COMMAND_PADDING_DIRECT
                } else {
                    COMMAND_PADDING_END
                }
            } else {
                COMMAND_PADDING_CONTINUE
            };
            self.frame_into(&mut out, piece, command, long_padding, &state);
            i += 1;
        }
        out
    }

    /// Xray's `[nil]` pure-padding frame (proxy.go:357-358,
    /// outbound.go:343-348): no content, long padding, Continue command —
    /// sent when no first packet arrived within 500 ms to hide the VLESS
    /// header's length signature.
    pub(crate) fn write_pad_only(&mut self) -> Vec<u8> {
        let state_arc = self.state.clone();
        let state = state_arc.lock().unwrap();
        let mut out = Vec::new();
        self.frame_into(
            &mut out,
            &[],
            COMMAND_PADDING_CONTINUE,
            true,
            &state,
        );
        log::debug!("vision: uplink sent pure-padding frame to camouflage header");
        out
    }

    /// One-shot: consume the Direct-switch signal (the previous
    /// [`Self::write_chunk`] emitted the Direct frame).
    pub(crate) fn take_direct_switch(&mut self) -> bool {
        std::mem::take(&mut self.switch_to_direct)
    }

    /// XtlsPadding (proxy.go:496-532): optional UUID prefix + 5-byte frame
    /// header + content + zero padding.
    fn frame_into(
        &mut self, out: &mut Vec<u8>, content: &[u8], command: u8,
        long_padding: bool, _state: &VisionFilterState,
    ) {
        let content_len = content.len() as i64;
        let mut padding_len = if content_len < TESTSEED_LONG_THRESHOLD
            && long_padding
        {
            // rand[0,500) + 900 - contentLen → content+padding ∈ [900,1400).
            rand_range(0, TESTSEED_LONG_RAND - 1) + TESTSEED_LONG_BASE
                - content_len
        } else {
            rand_range(0, TESTSEED_SHORT_RAND - 1)
        };
        let cap = BUF_SIZE - FRAME_OVERHEAD - content_len;
        if padding_len > cap {
            padding_len = cap;
        }
        if self.uuid_pending {
            out.extend_from_slice(&self.uuid);
            self.uuid_pending = false;
        }
        out.push(command);
        out.extend_from_slice(&(content_len as u16).to_be_bytes());
        out.extend_from_slice(&(padding_len as u16).to_be_bytes());
        out.extend_from_slice(content);
        // buf.Extend zero-fills (common/buf/buffer.go:148-156).
        out.extend(std::iter::repeat(0u8).take(padding_len as usize));
    }
}

// ---------------------------------------------------------------------------
// Downlink reader — Outbound read state line (proxy.go:174-285, 535-616)
// ---------------------------------------------------------------------------

/// Vision downlink reader (server → client, padding phase). Unpads frames
/// until End (keep reading the outer TLS stream) or Direct (the transport
/// must hand over the raw socket, §S2.6).
pub(crate) struct VisionReader {
    uuid: [u8; 16],
    /// `Outbound.WithinPaddingBuffers` (:132).
    within_padding_buffers: bool,
    /// `Outbound.DownlinkReaderDirectCopy` (:132).
    switch_to_direct: bool,
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: i32,
    state: Arc<Mutex<VisionFilterState>>,
}

impl VisionReader {
    pub(crate) fn new(uuid: [u8; 16], state: Arc<Mutex<VisionFilterState>>) -> Self {
        Self {
            uuid,
            within_padding_buffers: true,
            switch_to_direct: false,
            // XtlsUnpadding initial state (-1, -1, -1), CurrentCommand = 0
            // (proxy.go:161-170).
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            state,
        }
    }

    /// Unpad one downlink chunk. Returns the content to forward to the
    /// application (may be empty for pure-padding frames). After the
    /// returned content has been delivered, call
    /// [`Self::take_direct_switch`]: when it returns true a Direct frame
    /// was decoded and the transport must splice the raw socket from the
    /// next read on (see the module docs for the buffer-drainage proof).
    pub(crate) fn read_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        // :228-233 — already direct-copying: raw passthrough.
        if self.switch_to_direct {
            return chunk.to_vec();
        }
        let state_arc = self.state.clone();
        let mut state = state_arc.lock().unwrap();
        // :235-254 — unpadding gate.
        let out = if self.within_padding_buffers
            || state.number_of_packets_to_filter > 0
        {
            let out = self.xtls_unpadding(chunk);
            if self.remaining_content > 0
                || self.remaining_padding > 0
                || self.current_command == 0
            {
                self.within_padding_buffers = true;
            } else if self.current_command == 1 {
                log::debug!("vision: downlink padding End — keep outer stream");
                self.within_padding_buffers = false;
                } else if self.current_command == 2 {
                    log::debug!(
                        "vision: downlink Direct — raw-socket handoff requested",
                    );
                    self.within_padding_buffers = false;
                    self.switch_to_direct = true;
                } else {
                log::debug!(
                    "vision: XtlsRead unknown command {}",
                    self.current_command
                );
            }
            out
        } else {
            chunk.to_vec()
        };
        // :255-257 — FilterTls runs on the *unpadded* buffers.
        if state.number_of_packets_to_filter > 0 {
            state.filter_tls(&out);
        }
        out
    }

    /// One-shot: consume the Direct-switch signal.
    pub(crate) fn take_direct_switch(&mut self) -> bool {
        std::mem::take(&mut self.switch_to_direct)
    }

    /// XtlsUnpadding (proxy.go:535-616) over one chunk; the parse state
    /// spans chunks. Bytes after an End/Direct frame inside the same chunk
    /// are passed through raw (:606-608).
    fn xtls_unpadding(&mut self, b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        if self.remaining_command == -1
            && self.remaining_content == -1
            && self.remaining_padding == -1
        {
            // :551-557 — enter framing mode only on a UUID-prefixed frame
            // header (≥ 21 bytes); otherwise the chunk is plain content.
            if b.len() >= 21 && b[..16] == self.uuid {
                pos = 16;
                self.remaining_command = 5;
            } else {
                return b.to_vec();
            }
        }
        while pos < b.len() {
            if self.remaining_command > 0 {
                let data = b[pos];
                pos += 1;
                match self.remaining_command {
                    5 => self.current_command = data as i32,
                    4 => self.remaining_content = (data as i32) << 8,
                    3 => self.remaining_content |= data as i32,
                    2 => self.remaining_padding = (data as i32) << 8,
                    1 => self.remaining_padding |= data as i32,
                    _ => unreachable!("remaining_command is 1..=5 here"),
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let len =
                    (self.remaining_content as usize).min(b.len() - pos);
                out.extend_from_slice(&b[pos..pos + len]);
                pos += len;
                self.remaining_content -= len as i32;
            } else {
                // remaining_padding > 0 — skip the zero padding.
                let len =
                    (self.remaining_padding as usize).min(b.len() - pos);
                pos += len;
                self.remaining_padding -= len as i32;
            }
            if self.remaining_command <= 0
                && self.remaining_content <= 0
                && self.remaining_padding <= 0
            {
                // This frame is done (:599-610).
                if self.current_command == 0 {
                    self.remaining_command = 5;
                } else {
                    self.remaining_command = -1;
                    self.remaining_content = -1;
                    self.remaining_padding = -1;
                    if pos < b.len() {
                        out.extend_from_slice(&b[pos..]);
                    }
                    break;
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c,
        0xda, 0x48, 0xb3, 0x08, 0x11,
    ];
    const OTHER_UUID: [u8; 16] = [0xEE; 16];

    fn pair() -> (VisionWriter, VisionReader, Arc<Mutex<VisionFilterState>>) {
        let state = Arc::new(Mutex::new(VisionFilterState::new()));
        let writer = VisionWriter::new(UUID, state.clone());
        let reader = VisionReader::new(UUID, state.clone());
        (writer, reader, state)
    }

    /// Build a Vision frame the way a peer would send it.
    fn frame_with_uuid(
        uuid: &[u8; 16], command: u8, content: &[u8], padding: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(uuid);
        out.push(command);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(padding as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.extend(std::iter::repeat(0u8).take(padding));
        out
    }

    /// Frame without the UUID prefix — only each direction's first frame
    /// carries it (writeOnceUserUUID is written once, proxy.go:519-522).
    fn frame_bytes(command: u8, content: &[u8], padding: usize) -> Vec<u8> {
        frame_with_uuid(&[0u8; 16], command, content, padding)[16..].to_vec()
    }

    /// Split `data` into pieces of the given sizes (last piece takes the
    /// remainder).
    fn split(data: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0;
        for s in sizes {
            if pos >= data.len() {
                break;
            }
            let end = (pos + *s).min(data.len());
            out.push(data[pos..end].to_vec());
            pos = end;
        }
        if pos < data.len() {
            out.push(data[pos..].to_vec());
        }
        out
    }

    /// Parsed frame view for assertions (after the optional UUID prefix).
    struct FrameView {
        command: u8,
        content_len: usize,
        padding_len: usize,
    }

    /// Parse the frame header starting at `offset`; returns the view and
    /// the total frame size (header + content + padding).
    fn parse_frame_at(buf: &[u8], offset: usize) -> (FrameView, usize) {
        assert!(buf.len() >= offset + 5, "frame header truncated");
        let command = buf[offset];
        let content_len =
            u16::from_be_bytes([buf[offset + 1], buf[offset + 2]]) as usize;
        let padding_len =
            u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        (
            FrameView {
                command,
                content_len,
                padding_len,
            },
            5 + content_len + padding_len,
        )
    }

    fn client_hello_record() -> Vec<u8> {
        // Minimal but structurally valid: 16 03 01 <len> 01 <hs len> ...
        let mut hs = vec![0x01u8, 0x00, 0x00, 0x80];
        hs.extend_from_slice(&[0x03, 0x03]); // legacy version
        hs.extend_from_slice(&[0x5A; 32]); // random
        hs.push(32); // session id len
        hs.extend_from_slice(&[0x5B; 32]);
        hs.extend_from_slice(&[0x13, 0x01]); // cipher suite
        hs.extend_from_slice(&[0x01, 0x00]); // compression
        let mut rec = vec![0x16u8, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn server_hello_record(cipher: u16, with_tls13_ext: bool) -> Vec<u8> {
        // Handshake body: version(2) random(32) sid_len(1) sid(32)
        // cipher(2) comp_len(1) comp(1) ext_total(2) extensions.
        let mut exts = Vec::new();
        if with_tls13_ext {
            exts.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        } else {
            exts.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // dummy ext
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAA; 32]);
        body.push(32);
        body.extend_from_slice(&[0xBB; 32]);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![0x02u8];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16u8, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// ServerHello spanning more than one 2048-byte buffer unit: a large
    /// dummy extension first, the supported_versions extension last.
    fn long_server_hello_record(cipher: u16) -> Vec<u8> {
        let mut exts = vec![0x00u8, 0x00];
        exts.extend_from_slice(&2400u16.to_be_bytes());
        exts.extend_from_slice(&[0x11; 2400]);
        exts.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAA; 32]);
        body.push(32);
        body.extend_from_slice(&[0xBB; 32]);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![0x02u8];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16u8, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn app_data_record(payload: &[u8]) -> Vec<u8> {
        let mut rec = vec![0x17u8, 0x03, 0x03];
        rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        rec.extend_from_slice(payload);
        rec
    }

    // -- IsCompleteRecord --------------------------------------------------

    #[test]
    fn complete_record_detection() {
        assert!(is_complete_record(&[])); // Xray :454 quirk: vacuously true
        let rec = app_data_record(&[7u8; 100]);
        assert!(is_complete_record(&rec));
        // Two concatenated complete records.
        let two = [rec.as_slice(), app_data_record(&[1, 2, 3]).as_slice()]
            .concat();
        assert!(is_complete_record(&two));
        // Truncated body.
        assert!(!is_complete_record(&rec[..rec.len() - 1]));
        // Truncated header.
        assert!(!is_complete_record(&rec[..4]));
        // Header only (recordLen > 0, no body).
        assert!(!is_complete_record(&rec[..5]));
        // Handshake record is not AppData.
        assert!(!is_complete_record(&client_hello_record()));
        // Empty AppData record: headerLen == 0 at the end → false (Xray
        // requires headerLen == 5 at exit).
        assert!(!is_complete_record(&[0x17, 0x03, 0x03, 0x00, 0x00]));
    }

    // -- FilterTls ----------------------------------------------------------

    #[test]
    fn filter_tls_detects_client_hello_uplink() {
        let mut st = VisionFilterState::new();
        st.filter_tls(&client_hello_record());
        assert!(st.is_tls);
        assert!(!st.is_tls12_or_above);
        assert!(!st.enable_xtls);
        assert_eq!(st.number_of_packets_to_filter, 7);
        // Non-TLS traffic leaves the flags alone (still decrements).
        st.filter_tls(&[b'x'; 100]);
        assert!(st.is_tls);
        assert_eq!(st.number_of_packets_to_filter, 6);
    }

    #[test]
    fn filter_tls_server_hello_with_supported_versions_enables_xtls() {
        for cipher in [0x1301u16, 0x1302, 0x1303, 0x1304] {
            let mut st = VisionFilterState::new();
            st.filter_tls(&server_hello_record(cipher, true));
            assert!(st.is_tls);
            assert!(st.is_tls12_or_above);
            assert!(st.enable_xtls, "cipher {cipher:#06x}");
            assert_eq!(st.cipher, cipher);
            assert_eq!(st.number_of_packets_to_filter, 0); // conclusive
        }
    }

    #[test]
    fn filter_tls_ccm8_and_tls12_do_not_enable_xtls() {
        // CCM_8 (0x1305) is in the TLS 1.3 table but excluded (:653).
        let mut st = VisionFilterState::new();
        st.filter_tls(&server_hello_record(0x1305, true));
        assert!(!st.enable_xtls);
        // TLS 1.2 cipher without the supported_versions extension.
        let mut st = VisionFilterState::new();
        st.filter_tls(&server_hello_record(0xc02c, false));
        assert!(st.is_tls12_or_above);
        assert!(!st.enable_xtls);
        // Old TLS 1.2 cipher WITH the extension bytes present (still
        // rejected by the cipher table).
        let mut st = VisionFilterState::new();
        st.filter_tls(&server_hello_record(0xc02c, true));
        assert!(!st.enable_xtls);
    }

    #[test]
    fn filter_tls_server_hello_spanning_units() {
        // ServerHello larger than one 2048-byte unit: detected from the
        // first unit (starts with 16 03 03, cipher extracted), conclusive
        // only when the supported_versions bytes arrive with the second.
        let sh = long_server_hello_record(0x1302);
        assert!(sh.len() > 2048);
        let mut st = VisionFilterState::new();
        st.filter_tls(&sh[..2048]);
        assert!(st.is_tls12_or_above);
        assert_eq!(st.cipher, 0x1302);
        assert!(!st.enable_xtls); // inconclusive yet
        assert!(st.remaining_server_hello > 0);
        st.filter_tls(&sh[2048..]);
        assert!(st.enable_xtls);
        assert_eq!(st.number_of_packets_to_filter, 0);
    }

    // -- Padding regions ----------------------------------------------------

    #[test]
    fn short_padding_in_range_for_plain_traffic() {
        let (mut w, _r, _s) = pair();
        // Keep under the 8-packet filter quota: the 7th write would fire
        // the quota-End path (branch 2) — covered by its own test below.
        for i in 0..5 {
            let out = w.write_chunk(&[b'a' + i as u8; 100]);
            // Only the very first frame of the direction carries the UUID.
            if i == 0 {
                assert_eq!(out[..16], UUID, "first frame carries the UUID");
            } else {
                assert_ne!(out[..16], UUID, "UUID prefix is written once");
            }
            let (f, _total) = parse_frame_at(&out, if i == 0 { 16 } else { 0 });
            assert_eq!(f.command, COMMAND_PADDING_CONTINUE);
            assert_eq!(f.content_len, 100);
            assert!(f.padding_len < 256, "short padding {}", f.padding_len);
        }
    }

    #[test]
    fn long_padding_total_in_900_1400_when_tls() {
        let (mut w, _r, _s) = pair();
        // Uplink ClientHello switches the writer into TLS mode; the filter
        // runs before framing (:352-356), so the hello frame is long-padded.
        let framed = w.write_chunk(&client_hello_record());
        let (f, total) = parse_frame_at(&framed, 16);
        assert_eq!(f.command, COMMAND_PADDING_CONTINUE);
        let content_plus_padding = total - 5;
        assert!(
            (900..1400).contains(&content_plus_padding),
            "hello content+padding = {content_plus_padding}",
        );
        for _ in 0..5 {
            // A partial AppData record (claims 1024, delivers 102 bytes):
            // is_complete=false → plain Continue with long padding.
            let mut partial = vec![0x17u8, 0x03, 0x03, 0x04, 0x00];
            partial.extend_from_slice(&[0u8; 102]);
            let out = w.write_chunk(&partial);
            let (f, total) = parse_frame_at(&out, 0); // UUID already spent
            assert_eq!(f.command, COMMAND_PADDING_CONTINUE);
            let content_plus_padding = total - 5;
            assert!(
                (900..1400).contains(&content_plus_padding),
                "content+padding = {content_plus_padding}",
            );
            assert_eq!(f.content_len, partial.len());
        }
    }

    #[test]
    fn pad_only_frame_has_long_padding_and_uuid() {
        let (mut w, _r, _s) = pair();
        let out = w.write_pad_only();
        assert_eq!(out[..16], UUID);
        let (f, total) = parse_frame_at(&out, 16);
        assert_eq!(f.command, COMMAND_PADDING_CONTINUE);
        assert_eq!(f.content_len, 0);
        // 21 + padding ≤ 2048 → padding ≤ 2027; long padding [900, 1400).
        assert!((900..1400).contains(&f.padding_len));
        assert_eq!(total, 5 + f.padding_len);
        // UUID consumed exactly once.
        let out2 = w.write_pad_only();
        assert_ne!(out2[..16], UUID);
    }

    // -- Round trips --------------------------------------------------------

    #[test]
    fn round_trip_plain_payloads() {
        let (mut w, mut r, _s) = pair();
        let payload: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let framed = w.write_chunk(&payload);
        assert!(!framed.is_empty());
        let content = r.read_chunk(&framed);
        assert_eq!(content, payload);
    }

    #[test]
    fn round_trip_across_chunk_boundaries() {
        let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
        // Writer receives the payload in pieces; reader receives the
        // concatenated framing in different pieces.
        for wsizes in [
            vec![1],
            vec![7],
            vec![21],
            vec![100, 37],
            vec![2048],
            vec![1000, 1000, 1000],
        ] {
            let (mut w, _r, _s) = pair();
            let mut framed = Vec::new();
            for piece in split(&payload, &wsizes) {
                framed.extend_from_slice(&w.write_chunk(&piece));
            }
            // The first reader piece must be ≥ 21 bytes: the UUID gate
            // (XtlsUnpadding initial check, proxy.go:552) needs the whole
            // UUID+header in one chunk, exactly like an SSL record read.
            for rsizes in [vec![21], vec![40], vec![999], vec![2048]] {
                let mut r = VisionReader::new(
                    UUID,
                    Arc::new(Mutex::new(VisionFilterState::new())),
                );
                let mut content = Vec::new();
                for piece in split(&framed, &rsizes) {
                    content.extend_from_slice(&r.read_chunk(&piece));
                }
                assert_eq!(content, payload, "w={wsizes:?} r={rsizes:?}");
            }
        }
    }

    #[test]
    fn reader_passes_through_without_uuid_match() {
        let mut r = VisionReader::new(
            OTHER_UUID,
            Arc::new(Mutex::new(VisionFilterState::new())),
        );
        let frame = frame_with_uuid(&UUID, COMMAND_PADDING_CONTINUE, b"hi", 5);
        assert_eq!(r.read_chunk(&frame), frame);
        // Short chunks (< 21 bytes) also pass through untouched.
        assert_eq!(r.read_chunk(b"short"), b"short");
    }

    // -- State machine matrix ------------------------------------------------

    #[test]
    fn matrix_tls13_uplink_direct_and_downlink_direct() {
        let (mut w, mut r, state) = pair();

        // 1. Uplink ClientHello (framed, Continue, long-padded? no: ≥ 900).
        let f1 = w.write_chunk(&client_hello_record());
        let (f, _t) = parse_frame_at(&f1, 16);
        assert_eq!(f.command, COMMAND_PADDING_CONTINUE);
        assert!(!w.take_direct_switch());

        // 2. Downlink ServerHello (TLS 1.3) → EnableXtls.
        let sh = server_hello_record(0x1301, true);
        let sf = frame_with_uuid(&UUID, COMMAND_PADDING_CONTINUE, &sh, 42);
        assert_eq!(r.read_chunk(&sf), sh);
        assert!(state.lock().unwrap().enable_xtls);
        assert!(!r.take_direct_switch());

        // 3. First complete AppData record uplink → Direct frame + switch.
        let ad = app_data_record(&[0xAB; 120]);
        let f2 = w.write_chunk(&ad);
        let (f, _t) = parse_frame_at(&f2, 0); // UUID spent on frame 1
        assert_eq!(f.command, COMMAND_PADDING_DIRECT);
        assert_eq!(&f2[5..5 + f.content_len], &ad[..]); // content intact
        assert!(w.take_direct_switch());
        // Further writes are the identity (transport writes them raw).
        assert_eq!(w.write_chunk(b"raw-uplink"), b"raw-uplink");

        // 4. Downlink Direct frame (no UUID — spent on frame 1) → content
        // + switch + raw passthrough.
        let df = frame_bytes(COMMAND_PADDING_DIRECT, &ad, 0);
        assert_eq!(r.read_chunk(&df), ad);
        assert!(r.take_direct_switch());
        assert_eq!(r.read_chunk(b"raw-downlink"), b"raw-downlink");
    }

    #[test]
    fn matrix_tls12_end_without_direct() {
        let (mut w, mut r, state) = pair();

        let f1 = w.write_chunk(&client_hello_record());
        assert_eq!(parse_frame_at(&f1, 16).0.command, COMMAND_PADDING_CONTINUE);

        // ServerHello without supported_versions → TLS 1.2.
        let sh = server_hello_record(0xc02c, false);
        let sf = frame_with_uuid(&UUID, COMMAND_PADDING_CONTINUE, &sh, 13);
        assert_eq!(r.read_chunk(&sf), sh);
        assert!(state.lock().unwrap().is_tls12_or_above);
        assert!(!state.lock().unwrap().enable_xtls);

        // First complete AppData record → End (no Direct, no switch).
        let ad = app_data_record(&[0xCD; 64]);
        let f2 = w.write_chunk(&ad);
        let (f, _t) = parse_frame_at(&f2, 0);
        assert_eq!(f.command, COMMAND_PADDING_END);
        assert!(!w.take_direct_switch());
        // Identity afterwards — still inside the outer TLS stream.
        assert_eq!(w.write_chunk(b"tls12-raw"), b"tls12-raw");

        // Downlink End frame (no UUID — spent on frame 1) → no switch;
        // afterwards passthrough.
        let ef = frame_bytes(COMMAND_PADDING_END, b"tail", 0);
        assert_eq!(r.read_chunk(&ef), b"tail");
        assert!(!r.take_direct_switch());
        assert_eq!(r.read_chunk(b"still-outer"), b"still-outer");
    }

    #[test]
    fn matrix_plain_traffic_ends_via_quota_never_direct() {
        let (mut w, mut r, _state) = pair();
        // No ClientHello/ServerHello: IsTLS stays false, short padding.
        for i in 0..6 {
            let out = w.write_chunk(&[b'x'; 2048]);
            // 2048 ≥ 2027 → reshaped into two ≤ 1024 pieces at the midpoint.
            let (f1, t1) = parse_frame_at(&out, if i == 0 { 16 } else { 0 });
            assert_eq!(f1.command, COMMAND_PADDING_CONTINUE);
            let (f2, _t2) = parse_frame_at(&out, if i == 0 { 16 + t1 } else { t1 });
            assert_eq!(f2.command, COMMAND_PADDING_CONTINUE);
            assert!(!w.take_direct_switch());
        }
        // 7th unit: quota reaches 1 → the first piece gets the End frame
        // and the second reshaped piece follows unframed (Xray breaks out
        // of the loop, :379-382, leaving the tail of the write raw).
        let out = w.write_chunk(&[b'x'; 2048]);
        let (f1, t1) = parse_frame_at(&out, 0);
        assert_eq!(f1.command, COMMAND_PADDING_END);
        assert_eq!(f1.content_len, 1024);
        assert_eq!(out.len(), t1 + 1024);
        assert!(out[t1..].iter().all(|&b| b == b'x'));
        assert!(!w.take_direct_switch());
        // Post-End writes are identity.
        assert_eq!(w.write_chunk(b"plaintext"), b"plaintext");

        // Reader side: chunks pass through (UUID mismatch → passthrough).
        let down = frame_with_uuid(&UUID, COMMAND_PADDING_END, b"srv", 0);
        assert_eq!(r.read_chunk(&down), b"srv");
        assert!(!r.take_direct_switch());
        assert_eq!(r.read_chunk(b"http/1.1 200 ok"), b"http/1.1 200 ok");
    }

    #[test]
    fn matrix_tls13_first_write_is_complete_appdata_is_impossible_for_hello() {
        // Sanity: a ClientHello write never triggers the AppData branch.
        let (mut w, _r, _s) = pair();
        let f = w.write_chunk(&client_hello_record());
        let (fr, _t) = parse_frame_at(&f, 16);
        assert_eq!(fr.command, COMMAND_PADDING_CONTINUE);
        assert!(!w.take_direct_switch());
    }

    #[test]
    fn empty_write_chunk_is_noop() {
        let (mut w, _r, _s) = pair();
        assert!(w.write_chunk(&[]).is_empty());
    }

    #[test]
    fn zero_length_padding_frame_round_trips() {
        // content=0 padding=0 → exactly 21/5-byte frames, including the
        // 16-byte-UUID minimum check.
        let (mut w, mut r, _s) = pair();
        let out = w.write_chunk(&[]);
        assert!(out.is_empty()); // empty chunks are never framed
        let out = w.write_pad_only(); // pure padding still carries the UUID
        let content = r.read_chunk(&out);
        assert!(content.is_empty());
    }

    #[test]
    fn reshape_splits_large_units_at_record_boundary_or_midpoint() {
        // A unit ≥ 2027 with an AppData start in [21, 2027] splits there.
        let mut chunk = vec![b'z'; 2048];
        chunk[1500..1503].copy_from_slice(&TLS_APPLICATION_DATA_START);
        let pieces = reshape_pieces(&chunk);
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].len(), 1500);
        assert_eq!(pieces[1].len(), 548);
        // No boundary found → midpoint split.
        let chunk = vec![b'z'; 2048];
        let pieces = reshape_pieces(&chunk);
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].len(), 1024);
        // Boundary too close to the end (> 2027) → midpoint.
        let mut chunk = vec![b'z'; 2048];
        chunk[2030..2033].copy_from_slice(&TLS_APPLICATION_DATA_START);
        let pieces = reshape_pieces(&chunk);
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].len(), 1024);
    }
}
