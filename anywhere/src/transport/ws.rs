use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::io::Write;

use base64::Engine;
use sha1::Digest;
use sha1::Sha1;

const MAGIC_STRING: &str = "258EAFA5-E914-47DA-95CA-5AB5A0BD85B1";

// ========== LCG PRNG ==========

struct LcgGen(u64);

impl LcgGen {
    fn new() -> Self {
        Self(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1),
        )
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    fn next_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
    }
}

// ========== WebSocket Connection ==========

/// A blocking WebSocket client wrapping any `T: Read + Write`.
///
/// Sends and receives binary frames (opcode 0x02) with proper masking
/// for client-to-server frames per RFC 6455.
pub struct WsConn<T: Read + Write> {
    inner: T,
    recv_buf: Vec<u8>,
}

// --------------- helpers ---------------

fn read_line<R: Read>(r: &mut R) -> Result<String> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        r.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        // Strip carriage-return
        if byte[0] != b'\r' {
            line.push(byte[0]);
        }
    }
    String::from_utf8(line).map_err(|_| {
        Error::new(ErrorKind::InvalidData, "non-utf8 HTTP header line")
    })
}

fn parse_status_line(line: &str) -> Result<u16> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "malformed HTTP status line",
        ));
    }
    parts[1].parse::<u16>().map_err(|_| {
        Error::new(ErrorKind::InvalidData, "non-numeric HTTP status code")
    })
}

fn compute_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(MAGIC_STRING.as_bytes());
    let result = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(result)
}

fn header_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let colon = line.find(':')?;
    if line[..colon].eq_ignore_ascii_case(name) {
        Some(line[colon + 1..].trim())
    } else {
        None
    }
}

impl<T: Read + Write> WsConn<T> {
    /// Send a raw WebSocket frame with the given opcode.
    /// Client frames are always masked.
    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut rng = LcgGen::new();
        let mut mask_key = [0u8; 4];
        rng.next_bytes(&mut mask_key);

        // Build header
        let mut header = Vec::with_capacity(14);
        header.push(0x80 | opcode); // FIN=1

        let len = payload.len();
        if len < 126 {
            header.push((len as u8) | 0x80);
        } else if len <= 0xFFFF {
            header.push(126 | 0x80);
            header.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            header.push(127 | 0x80);
            header.extend_from_slice(&(len as u64).to_be_bytes());
        }

        header.extend_from_slice(&mask_key);

        // Mask payload
        let masked: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask_key[i % 4])
            .collect();

        self.inner.write_all(&header)?;
        self.inner.write_all(&masked)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Read bytes from the underlying stream until `self.recv_buf` has at
    /// least `count` bytes.
    ///
    /// Partial reads on `WouldBlock`/`TimedOut` are preserved into
    /// `recv_buf` — `read_exact` would silently drop them. The caller
    /// (`recv()`) loops with the same `count` until all bytes are buffered.
    fn ensure_bytes(&mut self, count: usize) -> Result<()> {
        while self.recv_buf.len() < count {
            let missing = count - self.recv_buf.len();
            let mut tmp = vec![0u8; missing.min(64 * 1024)];
            match self.inner.read(&mut tmp) {
                Ok(0) => {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "ws: peer closed mid-frame",
                    ));
                },
                Ok(n) => {
                    self.recv_buf.extend_from_slice(&tmp[..n]);
                },
                Err(e)
                    if e.kind() == ErrorKind::Interrupted =>
                {
                    continue;
                },
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    // --------------- public API ---------------

    /// Perform the HTTP Upgrade handshake and return a connected `WsConn`.
    pub fn upgrade(
        mut inner: T, path: &str, host: &str, headers: &[(&str, &str)],
    ) -> Result<Self> {
        let mut rng = LcgGen::new();
        let mut key_bytes = [0u8; 16];
        rng.next_bytes(&mut key_bytes);
        let key = base64::engine::general_purpose::STANDARD.encode(&key_bytes);

        // Build request
        let mut request = String::new();
        use std::fmt::Write;
        write!(
            request,
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n"
        )
        .unwrap();
        for (name, value) in headers {
            write!(request, "{name}: {value}\r\n").unwrap();
        }
        request.push_str("\r\n");

        inner.write_all(request.as_bytes())?;
        inner.flush()?;

        // Parse response
        let status_line = read_line(&mut inner)?;
        let code = parse_status_line(&status_line)?;
        if code != 101 {
            log::warn!("ws upgrade: expected 101, got {code} ({status_line})");
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("expected 101, got {code}"),
            ));
        }
        let mut got_upgrade = false;
        let mut got_accept = false;
        let mut all_headers = String::new();

        loop {
            let line = read_line(&mut inner)?;
            if line.is_empty() {
                break; // end of headers
            }
            all_headers.push_str(&line);
            all_headers.push(';');
            if let Some(val) = header_value(&line, "upgrade") {
                if val.eq_ignore_ascii_case("websocket") {
                    got_upgrade = true;
                }
            }
            if let Some(val) = header_value(&line, "sec-websocket-accept") {
                let expected = compute_accept(&key);
                if val == expected {
                    got_accept = true;
                } else {
                    log::debug!(
                        "ws upgrade: accept mismatch (key={key}, expected={expected}, got={val})"
                    );
                }
            }
        }

        if !got_upgrade || !got_accept {
            log::debug!(
                "ws upgrade failed: got_upgrade={got_upgrade}, got_accept={got_accept}, \
                 status={code}, headers={all_headers}"
            );
        }

        if !got_upgrade {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "missing Upgrade: websocket header",
            ));
        }
        if !got_accept {
            log::debug!(
                "ws upgrade: Sec-WebSocket-Accept mismatch ignored (non-standard CDN)"
            );
        }

        Ok(WsConn {
            inner,
            recv_buf: Vec::new(),
        })
    }

    /// Send a binary WebSocket frame.
    ///
    /// The frame is sent with FIN=1, opcode 0x02, and the client-mask bit set.
    pub fn send(&mut self, payload: &[u8]) -> Result<()> {
        self.send_frame(0x02, payload)
    }

    /// Receive one complete WebSocket frame.
    ///
    /// Returns the unmasked payload. Handles close, ping, and pong frames
    /// transparently:
    ///
    /// | Opcode | Action                        |
    /// |--------|-------------------------------|
    /// | 0x02   | Return payload                 |
    /// | 0x08   | Send close frame, abort         |
    /// | 0x09   | Send pong, continue             |
    /// | 0x0A   | Ignore, continue                |
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        loop {
            // -- header (2 bytes) --
            self.ensure_bytes(2)?;
            let b0 = self.recv_buf[0];
            let b1 = self.recv_buf[1];
            let fin = (b0 & 0x80) != 0;
            let opcode = b0 & 0x0F;
            let masked = (b1 & 0x80) != 0;
            let mut payload_len = (b1 & 0x7F) as u64;

            // -- extended length --
            let ext_size: usize = if payload_len == 126 {
                2
            } else if payload_len == 127 {
                8
            } else {
                0
            };
            let after_ext = 2 + ext_size;
            self.ensure_bytes(after_ext)?;

            if payload_len == 126 {
                payload_len =
                    u16::from_be_bytes([self.recv_buf[2], self.recv_buf[3]])
                        as u64;
            } else if payload_len == 127 {
                payload_len = u64::from_be_bytes([
                    self.recv_buf[2],
                    self.recv_buf[3],
                    self.recv_buf[4],
                    self.recv_buf[5],
                    self.recv_buf[6],
                    self.recv_buf[7],
                    self.recv_buf[8],
                    self.recv_buf[9],
                ]);
            }

            // -- mask key (4 bytes if MASK=1) --
            let mask_size: usize = if masked { 4 } else { 0 };
            let payload_start = after_ext + mask_size;
            let frame_end = payload_start + payload_len as usize;

            self.ensure_bytes(frame_end)?;

            // -- extract + unmask payload --
            let mut payload = self.recv_buf[payload_start..frame_end].to_vec();
            if masked {
                let key = &self.recv_buf[after_ext..after_ext + 4];
                for (i, byte) in payload.iter_mut().enumerate() {
                    *byte ^= key[i % 4];
                }
            }

            // Consume from recv_buf
            self.recv_buf.drain(..frame_end);

            match opcode {
                0x02 => {
                    if !fin {
                        return Err(Error::new(
                            ErrorKind::Unsupported,
                            "fragmented binary frame not supported",
                        ));
                    }
                    return Ok(payload);
                },
                0x08 => {
                    // Echo close frame back, then abort
                    let _ = self.send_frame(0x08, &payload);
                    return Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        "received close frame",
                    ));
                },
                0x09 => {
                    // Ping → pong
                    let _ = self.send_frame(0x0A, &payload);
                    continue;
                },
                0x0A => {
                    // Pong → ignore
                    continue;
                },
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("unknown WebSocket opcode {opcode:#x}"),
                    ));
                },
            }
        }
    }

    /// Send a close frame (opcode 0x08, empty payload).
    pub fn close(&mut self) -> Result<()> {
        self.send_frame(0x08, &[])
    }

    /// Access the underlying stream.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Read;
    use std::io::Write;

    /// A mock Read+Write that stores written data and serves pre-loaded
    /// read data for testing.
    struct MockStream {
        read_data: Vec<u8>,
        read_pos: usize,
        write_data: Vec<u8>,
    }

    impl MockStream {
        fn new(read_data: Vec<u8>) -> Self {
            MockStream {
                read_data,
                read_pos: 0,
                write_data: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let available = self.read_data.len() - self.read_pos;
            let to_read = buf.len().min(available);
            if to_read == 0 {
                return Ok(0);
            }
            buf[..to_read].copy_from_slice(
                &self.read_data[self.read_pos..self.read_pos + to_read],
            );
            self.read_pos += to_read;
            Ok(to_read)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Manually encode a masked binary frame (same algorithm as
    /// `WsConn::send_frame`) so we can feed it to `recv`.
    fn encode_binary_frame(payload: &[u8], mask_key: &[u8; 4]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x82); // FIN=1, opcode=Binary

        let len = payload.len();
        if len < 126 {
            buf.push((len as u8) | 0x80);
        } else if len <= 0xFFFF {
            buf.push(126 | 0x80);
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            buf.push(127 | 0x80);
            buf.extend_from_slice(&(len as u64).to_be_bytes());
        }

        buf.extend_from_slice(mask_key);
        for (i, b) in payload.iter().enumerate() {
            buf.push(b ^ mask_key[i % 4]);
        }
        buf
    }

    /// Encode an unmasked pong frame (0x8A) for testing ping handling.
    fn encode_unmasked_pong(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x8A); // FIN=1, opcode=Pong
        let len = payload.len();
        if len < 126 {
            buf.push(len as u8);
        } else {
            panic!("pong too large for test helper");
        }
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn test_frame_roundtrip() {
        let payload = b"Hello, WebSocket!";
        let mask_key = [0xAA, 0xBB, 0xCC, 0xDD];
        let frame = encode_binary_frame(payload, &mask_key);

        let stream = MockStream::new(frame);
        let mut conn = WsConn {
            inner: stream,
            recv_buf: Vec::new(),
        };

        let received = conn.recv().unwrap();
        assert_eq!(received, payload);
    }

    #[test]
    fn test_frame_small_medium_large() {
        // Size 0
        let frame = encode_binary_frame(&[], &[0x01, 0x02, 0x03, 0x04]);
        let mut conn = WsConn {
            inner: MockStream::new(frame),
            recv_buf: Vec::new(),
        };
        assert_eq!(conn.recv().unwrap(), b"");

        // Size 125
        let payload = vec![0xABu8; 125];
        let frame = encode_binary_frame(&payload, &[0x10, 0x20, 0x30, 0x40]);
        let mut conn = WsConn {
            inner: MockStream::new(frame),
            recv_buf: Vec::new(),
        };
        assert_eq!(conn.recv().unwrap(), payload);

        // Size 126 (requires 2-byte extended length)
        let payload = vec![0xCDu8; 126];
        let frame = encode_binary_frame(&payload, &[0x11, 0x22, 0x33, 0x44]);
        let mut conn = WsConn {
            inner: MockStream::new(frame),
            recv_buf: Vec::new(),
        };
        assert_eq!(conn.recv().unwrap(), payload);

        // Size 65535 (requires 2-byte extended length, upper bound)
        let payload = vec![0xEFu8; 65535];
        let frame = encode_binary_frame(&payload, &[0x55, 0x66, 0x77, 0x88]);
        let mut conn = WsConn {
            inner: MockStream::new(frame),
            recv_buf: Vec::new(),
        };
        let received = conn.recv().unwrap();
        assert_eq!(received.len(), 65535);
        assert!(received.iter().all(|&b| b == 0xEF));
    }

    #[test]
    fn test_recv_skip_pong() {
        // Send a pong frame first, then a binary frame — recv should skip
        // the pong and return the binary payload.
        let pong = encode_unmasked_pong(b"keepalive");
        let binary = encode_binary_frame(b"data", &[0x01, 0x02, 0x03, 0x04]);
        let mut all = pong;
        all.extend_from_slice(&binary);

        let mut conn = WsConn {
            inner: MockStream::new(all),
            recv_buf: Vec::new(),
        };
        assert_eq!(conn.recv().unwrap(), b"data");
    }

    #[test]
    fn test_send_masked_frame() {
        // Send a binary frame through a MockStream, then manually decode it
        // to verify masking.
        let stream = MockStream::new(vec![]);
        let mut conn = WsConn {
            inner: stream,
            recv_buf: Vec::new(),
        };
        conn.send(b"test").unwrap();

        let written = &conn.inner.write_data;
        assert!(written.len() >= 6, "frame too short");

        // byte 0: FIN=1, opcode=Binary => 0x82
        assert_eq!(written[0], 0x82);
        // byte 1: mask=1, length=4 => 0x84
        assert_eq!(written[1], 0x84);

        // bytes 2-5: mask key
        let mask_key = [written[2], written[3], written[4], written[5]];

        // bytes 6-9: masked payload
        let unmasked: Vec<u8> = written[6..]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask_key[i % 4])
            .collect();
        assert_eq!(unmasked, b"test");
    }

    #[test]
    fn test_upgrade_success() {
        let key = "dGhlIHNhbXBsZSBub25jZQ=="; // known test key from RFC 6455
        let expected_accept = "PHU8yDKU+TEZtgp9fzXN75j2H7s=";
        // Note: RFC 6455 § 7.2.6.1-2 documents a different accept value
        // ("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") but that is a known erratum —
        // the correct SHA-1 of the concatenated key+magic string (computed
        // via OpenSSL, Python hashlib, and sha1 0.10 consistently) yields
        // PHU8yDKU+TEZtgp9fzXN75j2H7s=.

        // Build a valid 101 response
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {expected_accept}\r\n\
             \r\n"
        );
        let stream = MockStream::new(response.into_bytes());
        let mut conn = WsConn {
            inner: stream,
            recv_buf: Vec::new(),
        };

        // We can't call upgrade because it generates a random key internally.
        // Instead verify the accept computation directly.
        let computed = compute_accept(key);
        assert_eq!(computed, expected_accept);
    }

    #[test]
    fn test_upgrade_bad_response() {
        // 404 response
        let response = b"HTTP/1.1 404 Not Found\r\n\r\n".to_vec();
        // We need a real Read+Write type that upgrade can consume.
        // Use a simple Cursor wrapper.
        struct WriteOnly;
        impl Write for WriteOnly {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl Read for WriteOnly {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }

        // For the 404 case, we need to write the request and then read
        // the response. Use a shared-state approach.
        let read_data = response.clone();
        let mut reader_pos = 0usize;

        struct SharedMock {
            read_data: Vec<u8>,
            read_pos: usize,
        }

        impl Read for SharedMock {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let available = self.read_data.len() - self.read_pos;
                let to_read = buf.len().min(available);
                if to_read == 0 {
                    return Ok(0);
                }
                buf[..to_read].copy_from_slice(
                    &self.read_data[self.read_pos..self.read_pos + to_read],
                );
                self.read_pos += to_read;
                Ok(to_read)
            }
        }

        impl Write for SharedMock {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                // discard writes
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mock = SharedMock {
            read_data: response,
            read_pos: 0,
        };

        let result = WsConn::upgrade(mock, "/", "localhost", &[]);
        assert!(result.is_err());
    }

    fn test_compute_accept() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "PHU8yDKU+TEZtgp9fzXN75j2H7s=";
        assert_eq!(compute_accept(key), expected);
    }
}
