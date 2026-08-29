// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! SS2022 (AEAD-2022) UDP packet relay.
//!
//! Implements [`SsUdpRelay`] for the Shadowsocks 2022 UDP protocol with
//! session management and replay protection (sliding window). Single-PSK
//! only — no EIH (Extended Identity Header) for UDP.
//!
//! ## Wire format
//!
//! **AES methods** (`2022-blake3-aes-128/256-gcm`):
//! ```text
//! [header: 16B]  sessionId(8 BE) || packetId(8 BE)  →  AES-ECB encrypt
//! [body]         AEAD-seal(nonce=header[4..16],
//!                type(1) || timestamp(8 BE) || paddingLen(2 BE)
//!                || padding || SocksAddr || payload)
//! ```
//! The session AEAD key is `SessionKey(psk, sessionId_bytes)`.
//!
//! **ChaCha20 method** (`2022-blake3-chacha20-poly1305`):
//! ```text
//! [nonce: 24B]   random
//! [body]         XChaCha20Poly1305-seal(nonce, psk,
//!                sessionId(8) || packetId(8) || type(1) || timestamp(8 BE)
//!                || paddingLen(2 BE) || padding || SocksAddr || payload)
//! ```
//! The PSK is used directly (no session key derivation).
//!
//! Server → client responses carry `type = 1` (Server) and include a
//! `clientSessionId` field that must match our own `sessionId`.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Nonce};
use tokio::net::UdpSocket;

use crate::inbound::Destination;
use crate::relay::PacketRelay;

use super::cipher::*;
use super::socks::{deserialize_socks_addr, serialize_socks_addr};

// ─── SlidingWindow ───────────────────────────────────────────────────────────

/// 64-bit sliding-window replay filter.
///
/// Tracks the highest packet ID seen and a bitmask of the last 64 IDs.
/// Bit position is the *distance* from `highest` (not `id % 64`) so that
/// the window shifts correctly as `highest` advances.
struct SlidingWindow {
    highest: u64,
    bitmap: u64,
}

impl SlidingWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
        }
    }

    /// Returns `true` if `id` has not been seen (acceptable).
    fn check(&self, id: u64) -> bool {
        if id > self.highest {
            return true; // ahead of window
        }
        if self.highest - id > 63 {
            return false; // too old (behind window)
        }
        let bit = 1u64 << (self.highest - id);
        self.bitmap & bit == 0
    }

    /// Marks `id` as seen. Call [`check`](Self::check) first to verify
    /// the ID is acceptable.
    fn add(&mut self, id: u64) {
        if id > self.highest {
            let shift = id - self.highest;
            if shift >= 64 {
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift;
            }
            self.highest = id;
        }
        if self.highest - id < 64 {
            let bit = 1u64 << (self.highest - id);
            self.bitmap |= bit;
        }
    }
}

// ─── SsUdpRelay ──────────────────────────────────────────────────────────────

/// SS2022 UDP relay implementing [`PacketRelay`].
///
/// Manages a client UDP session: encrypts outgoing datagrams with the
/// session AEAD (AES) or XChaCha20-Poly1305 (chacha), and decrypts
/// incoming server responses with replay protection.
pub struct SsUdpRelay {
    socket: UdpSocket,
    method: CipherMethod,
    /// Client session ID (random, generated at construction).
    session_id: u64,
    /// Outgoing packet counter (starts at 0, increments per send).
    packet_id: u64,
    /// Pre-computed session AEAD for the client (Some for AES, None for chacha).
    session_aead: Option<SsAead>,
    /// Remote (server) session ID, learned from the first response.
    remote_session_id: u64,
    /// AEAD for decrypting server responses (created on new remote session).
    remote_cipher: Option<SsAead>,
    /// Replay-protection window for incoming packets.
    window: SlidingWindow,
}

impl SsUdpRelay {
    /// Create a new UDP relay over `socket` using `method`.
    ///
    /// Generates a random `session_id` and, for AES methods, pre-computes
    /// the session AEAD from `SessionKey(psk, sessionId_bytes)`.
    pub fn new(socket: UdpSocket, method: CipherMethod) -> Self {
        let mut id_bytes = [0u8; 8];
        getrandom::fill(&mut id_bytes).expect("getrandom: system CSPRNG failed");
        let session_id = u64::from_be_bytes(id_bytes);

        let session_aead = if method.is_aes() {
            let sk = method.session_key(&id_bytes);
            Some(method.create_aead(&sk))
        } else {
            None
        };

        Self {
            socket,
            method,
            session_id,
            packet_id: 0,
            session_aead,
            remote_session_id: 0,
            remote_cipher: None,
            window: SlidingWindow::new(),
        }
    }

    /// Compute SS2022 UDP padding length.
    ///
    /// Padding is only applied to DNS (port 53) packets shorter than
    /// `MAX_PADDING_LENGTH`. The length is random in `1..=(max - len)`.
    fn compute_padding_len(payload_len: usize, port: u16) -> usize {
        if port == 53 && payload_len < MAX_PADDING_LENGTH {
            let mut rand_bytes = [0u8; 2];
            getrandom::fill(&mut rand_bytes)
                .expect("getrandom: system CSPRNG failed");
            let r = u16::from_be_bytes(rand_bytes) as usize;
            r % (MAX_PADDING_LENGTH - payload_len) + 1
        } else {
            0
        }
    }

    /// Current Unix timestamp in seconds.
    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs()
    }

    // ── Encrypt (client → server) ───────────────────────────────────────────

    /// Build an encrypted AES UDP packet (client → server).
    fn encrypt_packet_aes(&self, payload: &[u8], dest: &Destination) -> Vec<u8> {
        // 1. Packet header: sessionId(8 BE) || packetId(8 BE)
        let mut hdr = [0u8; 16];
        hdr[0..8].copy_from_slice(&self.session_id.to_be_bytes());
        hdr[8..16].copy_from_slice(&self.packet_id.to_be_bytes());

        // 2. Padding
        let padding_len = Self::compute_padding_len(payload.len(), dest.port);
        let padding = vec![0u8; padding_len];

        // 3. Body plaintext: type || timestamp || paddingLen || padding || SocksAddr || payload
        let addr = serialize_socks_addr(dest);
        let mut body = Vec::with_capacity(
            1 + 8 + 2 + padding_len + addr.len() + payload.len(),
        );
        body.push(HEADER_TYPE_CLIENT);
        body.extend_from_slice(&Self::now_secs().to_be_bytes());
        body.extend_from_slice(&(padding_len as u16).to_be_bytes());
        body.extend_from_slice(&padding);
        body.extend_from_slice(&addr);
        body.extend_from_slice(payload);

        // 4-5. AEAD seal with nonce = header[4..16]
        let nonce = &hdr[4..16];
        let enc_body = self
            .session_aead
            .as_ref()
            .expect("session_aead must be Some for AES")
            .seal(nonce, &body);

        // 6. ECB-encrypt the packet header
        let ecb = self.method.udp_block_encryptor();
        ecb.encrypt_block(&mut hdr);

        // 7. Assemble: ECB(header) || AEAD(body)
        let mut packet = Vec::with_capacity(16 + enc_body.len());
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&enc_body);
        packet
    }

    /// Build an encrypted ChaCha20 UDP packet (client → server).
    fn encrypt_packet_chacha(
        &self, payload: &[u8], dest: &Destination,
    ) -> Vec<u8> {
        // 1. Random 24-byte nonce
        let mut nonce = [0u8; PACKET_NONCE_SIZE];
        getrandom::fill(&mut nonce).expect("getrandom: system CSPRNG failed");

        // 2. Padding
        let padding_len = Self::compute_padding_len(payload.len(), dest.port);
        let padding = vec![0u8; padding_len];

        // 3. Plaintext: sessionId || packetId || type || timestamp || paddingLen || padding || SocksAddr || payload
        let addr = serialize_socks_addr(dest);
        let mut plain = Vec::with_capacity(
            8 + 8 + 1 + 8 + 2 + padding_len + addr.len() + payload.len(),
        );
        plain.extend_from_slice(&self.session_id.to_be_bytes());
        plain.extend_from_slice(&self.packet_id.to_be_bytes());
        plain.push(HEADER_TYPE_CLIENT);
        plain.extend_from_slice(&Self::now_secs().to_be_bytes());
        plain.extend_from_slice(&(padding_len as u16).to_be_bytes());
        plain.extend_from_slice(&padding);
        plain.extend_from_slice(&addr);
        plain.extend_from_slice(payload);

        // 4-5. XChaCha20-Poly1305 encrypt with PSK
        let cipher = XChaCha20Poly1305::new_from_slice(self.method.last_psk())
            .expect("invalid PSK length for XChaCha20Poly1305");
        let n: Nonce<XChaCha20Poly1305> =
            nonce.try_into().expect("nonce must be 24 bytes");
        let enc = cipher
            .encrypt(&n, plain.as_ref())
            .expect("XChaCha20Poly1305 encryption failed");

        // 6. Assemble: nonce || ciphertext
        let mut packet = Vec::with_capacity(PACKET_NONCE_SIZE + enc.len());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&enc);
        packet
    }

    // ── Decrypt (server → client) ───────────────────────────────────────────

    /// Decrypt and parse an AES server response packet.
    fn decrypt_packet_aes(
        &mut self, packet: &[u8],
    ) -> io::Result<(Vec<u8>, Destination)> {
        // 1-2. Minimum size: 16 (ECB header) + 16 (AEAD tag)
        if packet.len() < 16 + OVERHEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too short",
            ));
        }

        // 3. ECB-decrypt the 16-byte header
        let mut hdr = [0u8; 16];
        hdr.copy_from_slice(&packet[..16]);
        let ecb = self.method.udp_block_decryptor();
        ecb.decrypt_block(&mut hdr);

        // 4. Parse sessionId, packetId
        let session_id = u64::from_be_bytes(hdr[0..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(hdr[8..16].try_into().unwrap());

        // 5. New remote session → derive AEAD, reset window
        if session_id != self.remote_session_id || self.remote_cipher.is_none() {
            self.remote_session_id = session_id;
            let sk = self.method.session_key(&hdr[0..8]);
            self.remote_cipher = Some(self.method.create_aead(&sk));
            self.window = SlidingWindow::new();
        }

        // 6. Replay check
        if !self.window.check(packet_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "replay detected",
            ));
        }

        // 7-8. AEAD decrypt body with nonce = header[4..16]
        let nonce = &hdr[4..16];
        let remote_cipher = self
            .remote_cipher
            .as_ref()
            .expect("remote_cipher must be set");
        let plain = remote_cipher.open(nonce, &packet[16..]).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("decrypt: {e}"))
        })?;

        // 9. Parse plaintext body
        let (payload, dest) = self.parse_server_body(&plain)?;

        // 10. Mark packet as seen
        self.window.add(packet_id);

        Ok((payload.to_vec(), dest))
    }

    /// Decrypt and parse a ChaCha20 server response packet.
    fn decrypt_packet_chacha(
        &mut self, packet: &[u8],
    ) -> io::Result<(Vec<u8>, Destination)> {
        // 1-2. Minimum size: 24 (nonce) + 16 (AEAD tag)
        if packet.len() < PACKET_NONCE_SIZE + OVERHEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too short",
            ));
        }

        // 3-5. XChaCha20-Poly1305 decrypt with PSK
        let nonce = &packet[..PACKET_NONCE_SIZE];
        let cipher = XChaCha20Poly1305::new_from_slice(self.method.last_psk())
            .expect("invalid PSK length for XChaCha20Poly1305");
        let n: Nonce<XChaCha20Poly1305> =
            nonce.try_into().expect("nonce must be 24 bytes");
        let plain =
            cipher
                .decrypt(&n, &packet[PACKET_NONCE_SIZE..])
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("decrypt: {e}"),
                    )
                })?;

        // 6. Parse sessionId, packetId from decrypted plaintext
        if plain.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decrypted packet too short",
            ));
        }
        let _session_id = u64::from_be_bytes(plain[0..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(plain[8..16].try_into().unwrap());

        // 7. Replay check
        if !self.window.check(packet_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "replay detected",
            ));
        }

        // 8. Parse the rest of the body (type onwards)
        let (payload, dest) = self.parse_server_body(&plain[16..])?;

        // 9. Mark packet as seen
        self.window.add(packet_id);

        Ok((payload.to_vec(), dest))
    }

    /// Parse the common server-response body that follows the per-method
    /// header/session fields.
    ///
    /// Layout: `type(1) || timestamp(8 BE) || clientSessionId(8 BE) ||
    /// paddingLen(2 BE) || padding || SocksAddr || payload`
    fn parse_server_body<'a>(
        &self, body: &'a [u8],
    ) -> io::Result<(&'a [u8], Destination)> {
        // Minimum: type(1) + timestamp(8) + clientSessionId(8) + paddingLen(2) = 19
        if body.len() < 19 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet body too short",
            ));
        }

        // Header type
        let header_type = body[0];
        if header_type != HEADER_TYPE_SERVER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bad header type: expected {HEADER_TYPE_SERVER}, got {header_type}"
                ),
            ));
        }

        // Timestamp (±30s)
        let timestamp = i64::from_be_bytes(body[1..9].try_into().unwrap());
        let now = Self::now_secs() as i64;
        let diff = (now - timestamp).abs();
        if diff > TIMESTAMP_TOLERANCE_SECS as i64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad timestamp: diff {diff}s"),
            ));
        }

        // Client session ID (must match ours)
        let client_session_id =
            u64::from_be_bytes(body[9..17].try_into().unwrap());
        if client_session_id != self.session_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad client session id",
            ));
        }

        // Padding
        let padding_len = u16::from_be_bytes([body[17], body[18]]) as usize;
        let offset = 19 + padding_len;
        if offset > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "padding length exceeds body",
            ));
        }

        // SocksAddr
        let (dest, addr_len) =
            deserialize_socks_addr(&body[offset..]).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("socks addr: {e}"),
                )
            })?;
        let offset = offset + addr_len;

        // Remaining bytes are the payload
        Ok((&body[offset..], dest))
    }
}

// ─── PacketRelay impl ────────────────────────────────────────────────────────

#[async_trait]
impl PacketRelay for SsUdpRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        let n = match self.socket.recv(buf).await {
            Ok(n) => n,
            Err(e) => {
                log::debug!("ss: udp recv failed: {e}");
                return Err(e);
            },
        };
        let (payload, dest) = if self.method.is_aes() {
            self.decrypt_packet_aes(&buf[..n])
        } else {
            self.decrypt_packet_chacha(&buf[..n])
        }?;

        let len = payload.len();
        if len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload too large for buffer",
            ));
        }
        buf[..len].copy_from_slice(&payload);
        Ok((len, dest))
    }

    async fn write_packet(
        &mut self, buf: &[u8], dest: &Destination,
    ) -> io::Result<()> {
        let packet = if self.method.is_aes() {
            self.encrypt_packet_aes(buf, dest)
        } else {
            self.encrypt_packet_chacha(buf, dest)
        };
        log::debug!("ss: udp send {} bytes to {}", packet.len(), dest);
        if let Err(e) = self.socket.send(&packet).await {
            log::debug!("ss: udp send failed: {e}");
            return Err(e);
        }
        self.packet_id += 1;
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        // UdpSocket closes on drop — nothing to do.
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::{Address, Destination};
    use base64::Engine;

    /// Generate a test PSK of `len` zero bytes, base64-encoded.
    fn make_psk(len: usize) -> String {
        base64::engine::general_purpose::STANDARD.encode(vec![0u8; len])
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // ── SlidingWindow ───────────────────────────────────────────────────────

    #[test]
    fn test_window_fresh_accepts_all() {
        let sw = SlidingWindow::new();
        assert!(sw.check(0));
        assert!(sw.check(1));
        assert!(sw.check(42));
        assert!(sw.check(u64::MAX));
    }

    #[test]
    fn test_window_rejects_replay() {
        let mut sw = SlidingWindow::new();
        sw.add(0);
        assert!(!sw.check(0)); // replay
        assert!(sw.check(1)); // new

        sw.add(1);
        assert!(!sw.check(0)); // seen, within window
        assert!(!sw.check(1)); // replay
        assert!(sw.check(2)); // new
    }

    #[test]
    fn test_window_out_of_order() {
        let mut sw = SlidingWindow::new();
        sw.add(5);
        assert!(!sw.check(5)); // replay
        assert!(sw.check(3)); // not seen, within window
        sw.add(3);
        assert!(!sw.check(3)); // now replay
        assert!(sw.check(4)); // still not seen
    }

    #[test]
    fn test_window_too_old_rejected() {
        let mut sw = SlidingWindow::new();
        sw.add(0);
        sw.add(100);
        // 0 is 100 behind highest — outside the 64-entry window
        assert!(!sw.check(0));
        assert!(!sw.check(100)); // replay
        assert!(sw.check(50)); // within window, not seen
        assert!(sw.check(99)); // within window, not seen
    }

    #[test]
    fn test_window_slides_correctly() {
        let mut sw = SlidingWindow::new();
        for i in 0..50 {
            sw.add(i);
        }
        for i in 0..50 {
            assert!(!sw.check(i), "id {i} should be replayed");
        }
        assert!(sw.check(50));
        sw.add(50);
        // 0 is 50 behind highest (50) — still within window, was seen
        assert!(!sw.check(0));
        // 63 is 13 ahead — new
        assert!(sw.check(63));
    }

    #[test]
    fn test_window_duplicate_add_idempotent() {
        let mut sw = SlidingWindow::new();
        sw.add(10);
        sw.add(10); // adding again should be harmless
        assert!(!sw.check(10));
        assert!(sw.check(11));
    }

    // ── Test helpers: build server response packets ─────────────────────────

    /// Build an AES server→client response packet.
    fn build_server_aes(
        method: &CipherMethod, server_session_id: u64, server_packet_id: u64,
        client_session_id: u64, dest: &Destination, payload: &[u8],
        timestamp: Option<u64>, padding_len: u16,
    ) -> Vec<u8> {
        let mut hdr = [0u8; 16];
        hdr[0..8].copy_from_slice(&server_session_id.to_be_bytes());
        hdr[8..16].copy_from_slice(&server_packet_id.to_be_bytes());

        let sk = method.session_key(&hdr[0..8]);
        let aead = method.create_aead(&sk);

        let addr = serialize_socks_addr(dest);
        let ts = timestamp.unwrap_or_else(now_secs);
        let mut body = Vec::new();
        body.push(HEADER_TYPE_SERVER);
        body.extend_from_slice(&ts.to_be_bytes());
        body.extend_from_slice(&client_session_id.to_be_bytes());
        body.extend_from_slice(&padding_len.to_be_bytes());
        body.extend_from_slice(&vec![0u8; padding_len as usize]);
        body.extend_from_slice(&addr);
        body.extend_from_slice(payload);

        let nonce = &hdr[4..16];
        let enc_body = aead.seal(nonce, &body);

        let ecb = method.udp_block_encryptor();
        ecb.encrypt_block(&mut hdr);

        let mut packet = Vec::with_capacity(16 + enc_body.len());
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&enc_body);
        packet
    }

    /// Build a ChaCha20 server→client response packet.
    fn build_server_chacha(
        method: &CipherMethod, server_session_id: u64, server_packet_id: u64,
        client_session_id: u64, dest: &Destination, payload: &[u8],
        timestamp: Option<u64>, padding_len: u16,
    ) -> Vec<u8> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(method.last_psk()).unwrap();

        let mut nonce = [0u8; PACKET_NONCE_SIZE];
        getrandom::fill(&mut nonce).unwrap();

        let addr = serialize_socks_addr(dest);
        let ts = timestamp.unwrap_or_else(now_secs);
        let mut plain = Vec::new();
        plain.extend_from_slice(&server_session_id.to_be_bytes());
        plain.extend_from_slice(&server_packet_id.to_be_bytes());
        plain.push(HEADER_TYPE_SERVER);
        plain.extend_from_slice(&ts.to_be_bytes());
        plain.extend_from_slice(&client_session_id.to_be_bytes());
        plain.extend_from_slice(&padding_len.to_be_bytes());
        plain.extend_from_slice(&vec![0u8; padding_len as usize]);
        plain.extend_from_slice(&addr);
        plain.extend_from_slice(payload);

        let n: Nonce<XChaCha20Poly1305> =
            nonce.try_into().expect("nonce must be 24 bytes");
        let enc = cipher.encrypt(&n, plain.as_ref()).unwrap();

        let mut packet = Vec::with_capacity(PACKET_NONCE_SIZE + enc.len());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&enc);
        packet
    }

    // ── AES encrypt/decrypt round-trip ──────────────────────────────────────

    #[tokio::test]
    async fn test_aes256_decrypt_round_trip() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &make_psk(32)).unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let client_session_id = relay.session_id;
        let dest = Destination::new(Address::Ipv4([8, 8, 8, 8]), 53);
        let payload = b"hello aes-256 udp";

        let packet = build_server_aes(
            &method,
            99_999,
            0,
            client_session_id,
            &dest,
            payload,
            None,
            0,
        );

        let (decrypted, parsed_dest) = relay.decrypt_packet_aes(&packet).unwrap();
        assert_eq!(decrypted, payload);
        assert_eq!(parsed_dest, dest);
    }

    #[tokio::test]
    async fn test_aes128_decrypt_round_trip() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-aes-128-gcm", &make_psk(16)).unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let client_session_id = relay.session_id;
        let dest = Destination::new(Address::Ipv6([0; 16]), 443);
        let payload = b"hello aes-128 udp";

        let packet = build_server_aes(
            &method,
            55_555,
            0,
            client_session_id,
            &dest,
            payload,
            None,
            0,
        );

        let (decrypted, parsed_dest) = relay.decrypt_packet_aes(&packet).unwrap();
        assert_eq!(decrypted, payload);
        assert_eq!(parsed_dest, dest);
    }

    #[tokio::test]
    async fn test_aes_encrypt_round_trip() {
        // Verify the client's encrypt path by parsing the produced packet.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &make_psk(32)).unwrap();
        let relay = SsUdpRelay::new(socket, method.clone());

        let expected_session_id = relay.session_id;
        let dest = Destination::new(Address::Ipv4([1, 1, 1, 1]), 80);
        let payload = b"client encrypt test";

        let packet = relay.encrypt_packet_aes(payload, &dest);

        // ECB-decrypt the header
        let mut hdr = [0u8; 16];
        hdr.copy_from_slice(&packet[..16]);
        method.udp_block_decryptor().decrypt_block(&mut hdr);

        let session_id = u64::from_be_bytes(hdr[0..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
        assert_eq!(session_id, expected_session_id);
        assert_eq!(packet_id, 0);

        // AEAD-decrypt the body
        let sk = method.session_key(&hdr[0..8]);
        let aead = method.create_aead(&sk);
        let plain = aead.open(&hdr[4..16], &packet[16..]).unwrap();

        // Parse: type || timestamp || paddingLen || padding || SocksAddr || payload
        assert_eq!(plain[0], HEADER_TYPE_CLIENT);
        let padding_len = u16::from_be_bytes([plain[9], plain[10]]) as usize;
        let offset = 11 + padding_len;
        let (parsed_dest, addr_len) =
            deserialize_socks_addr(&plain[offset..]).unwrap();
        let parsed_payload = &plain[offset + addr_len..];

        assert_eq!(parsed_dest, dest);
        assert_eq!(parsed_payload, payload);
    }

    #[tokio::test]
    async fn test_aes_with_padding() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &make_psk(32)).unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let client_session_id = relay.session_id;
        let dest = Destination::new(Address::Ipv4([8, 8, 8, 8]), 53);
        let payload = b"pad";

        let packet = build_server_aes(
            &method,
            7777,
            0,
            client_session_id,
            &dest,
            payload,
            None,
            200,
        );

        let (decrypted, parsed_dest) = relay.decrypt_packet_aes(&packet).unwrap();
        assert_eq!(decrypted, payload);
        assert_eq!(parsed_dest, dest);
    }

    // ── ChaCha20 encrypt/decrypt round-trip ─────────────────────────────────

    #[tokio::test]
    async fn test_chacha_decrypt_round_trip() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-chacha20-poly1305", &make_psk(32))
                .unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let client_session_id = relay.session_id;
        let dest =
            Destination::new(Address::Domain("example.com".to_string()), 443);
        let payload = b"hello chacha udp";

        let packet = build_server_chacha(
            &method,
            88_888,
            0,
            client_session_id,
            &dest,
            payload,
            None,
            0,
        );

        let (decrypted, parsed_dest) =
            relay.decrypt_packet_chacha(&packet).unwrap();
        assert_eq!(decrypted, payload);
        assert_eq!(parsed_dest, dest);
    }

    #[tokio::test]
    async fn test_chacha_encrypt_round_trip() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-chacha20-poly1305", &make_psk(32))
                .unwrap();
        let relay = SsUdpRelay::new(socket, method.clone());

        let expected_session_id = relay.session_id;
        let dest = Destination::new(Address::Ipv4([9, 9, 9, 9]), 80);
        let payload = b"chacha encrypt test";

        let packet = relay.encrypt_packet_chacha(payload, &dest);

        // XChaCha20-Poly1305 decrypt with PSK
        let cipher =
            XChaCha20Poly1305::new_from_slice(method.last_psk()).unwrap();
        let n: Nonce<XChaCha20Poly1305> = packet[..PACKET_NONCE_SIZE]
            .try_into()
            .expect("nonce must be 24 bytes");
        let plain = cipher.decrypt(&n, &packet[PACKET_NONCE_SIZE..]).unwrap();

        // Parse: sessionId || packetId || type || timestamp || paddingLen || padding || SocksAddr || payload
        let session_id = u64::from_be_bytes(plain[0..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(plain[8..16].try_into().unwrap());
        assert_eq!(session_id, expected_session_id);
        assert_eq!(packet_id, 0);
        assert_eq!(plain[16], HEADER_TYPE_CLIENT);

        let padding_len = u16::from_be_bytes([plain[25], plain[26]]) as usize;
        let offset = 27 + padding_len;
        let (parsed_dest, addr_len) =
            deserialize_socks_addr(&plain[offset..]).unwrap();
        let parsed_payload = &plain[offset + addr_len..];

        assert_eq!(parsed_dest, dest);
        assert_eq!(parsed_payload, payload);
    }

    // ── Timestamp validation ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_timestamp_validation_aes() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &make_psk(32)).unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let client_session_id = relay.session_id;
        let dest = Destination::new(Address::Ipv4([1, 2, 3, 4]), 80);
        let payload = b"bad ts";

        // 120s in the past — exceeds 30s tolerance
        let old_ts = now_secs().saturating_sub(120);
        let packet = build_server_aes(
            &method,
            42,
            0,
            client_session_id,
            &dest,
            payload,
            Some(old_ts),
            0,
        );

        let err = relay.decrypt_packet_aes(&packet).unwrap_err();
        assert!(
            err.to_string().contains("timestamp"),
            "expected timestamp error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_timestamp_validation_chacha() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-chacha20-poly1305", &make_psk(32))
                .unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let client_session_id = relay.session_id;
        let dest = Destination::new(Address::Ipv4([1, 2, 3, 4]), 80);
        let payload = b"bad ts";

        let old_ts = now_secs().saturating_sub(120);
        let packet = build_server_chacha(
            &method,
            42,
            0,
            client_session_id,
            &dest,
            payload,
            Some(old_ts),
            0,
        );

        let err = relay.decrypt_packet_chacha(&packet).unwrap_err();
        assert!(
            err.to_string().contains("timestamp"),
            "expected timestamp error, got: {err}"
        );
    }

    // ── Client session ID validation ────────────────────────────────────────

    #[tokio::test]
    async fn test_client_session_id_validation_aes() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &make_psk(32)).unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let dest = Destination::new(Address::Ipv4([5, 6, 7, 8]), 443);
        let payload = b"wrong sid";

        // Wrong clientSessionId
        let wrong_id = relay.session_id.wrapping_add(1);
        let packet =
            build_server_aes(&method, 66, 0, wrong_id, &dest, payload, None, 0);

        let err = relay.decrypt_packet_aes(&packet).unwrap_err();
        assert!(
            err.to_string().contains("session id"),
            "expected session id error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_client_session_id_validation_chacha() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-chacha20-poly1305", &make_psk(32))
                .unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let dest = Destination::new(Address::Ipv4([5, 6, 7, 8]), 443);
        let payload = b"wrong sid";

        let wrong_id = relay.session_id.wrapping_add(1);
        let packet = build_server_chacha(
            &method, 66, 0, wrong_id, &dest, payload, None, 0,
        );

        let err = relay.decrypt_packet_chacha(&packet).unwrap_err();
        assert!(
            err.to_string().contains("session id"),
            "expected session id error, got: {err}"
        );
    }

    // ── Replay detection ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_replay_detection_aes() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &make_psk(32)).unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let client_session_id = relay.session_id;
        let dest = Destination::new(Address::Ipv4([9, 9, 9, 9]), 53);
        let payload = b"replay me";

        let packet = build_server_aes(
            &method,
            44,
            0,
            client_session_id,
            &dest,
            payload,
            None,
            0,
        );

        // First reception: OK
        assert!(relay.decrypt_packet_aes(&packet).is_ok());

        // Second reception: replay
        let err = relay.decrypt_packet_aes(&packet).unwrap_err();
        assert!(
            err.to_string().contains("replay"),
            "expected replay error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_replay_detection_chacha() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-chacha20-poly1305", &make_psk(32))
                .unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let client_session_id = relay.session_id;
        let dest = Destination::new(Address::Ipv4([9, 9, 9, 9]), 53);
        let payload = b"replay me";

        let packet = build_server_chacha(
            &method,
            44,
            0,
            client_session_id,
            &dest,
            payload,
            None,
            0,
        );

        // First reception: OK
        assert!(relay.decrypt_packet_chacha(&packet).is_ok());

        // Second reception: replay
        let err = relay.decrypt_packet_chacha(&packet).unwrap_err();
        assert!(
            err.to_string().contains("replay"),
            "expected replay error, got: {err}"
        );
    }

    // ── Bad header type ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_bad_header_type() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &make_psk(32)).unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let client_session_id = relay.session_id;
        let dest = Destination::new(Address::Ipv4([1, 1, 1, 1]), 80);
        let payload = b"bad type";

        // Build a packet with type = 0 (Client) instead of 1 (Server)
        let mut hdr = [0u8; 16];
        hdr[0..8].copy_from_slice(&33u64.to_be_bytes());
        hdr[8..16].copy_from_slice(&0u64.to_be_bytes());
        let sk = method.session_key(&hdr[0..8]);
        let aead = method.create_aead(&sk);
        let addr = serialize_socks_addr(&dest);
        let mut body = Vec::new();
        body.push(HEADER_TYPE_CLIENT); // wrong type for a server response
        body.extend_from_slice(&now_secs().to_be_bytes());
        body.extend_from_slice(&client_session_id.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&addr);
        body.extend_from_slice(payload);
        let enc_body = aead.seal(&hdr[4..16], &body);
        method.udp_block_encryptor().encrypt_block(&mut hdr);
        let mut packet = Vec::new();
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&enc_body);

        let err = relay.decrypt_packet_aes(&packet).unwrap_err();
        assert!(
            err.to_string().contains("header type"),
            "expected header type error, got: {err}"
        );
    }

    // ── Domain address round-trip ───────────────────────────────────────────

    #[tokio::test]
    async fn test_domain_address_round_trip() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &make_psk(32)).unwrap();
        let mut relay = SsUdpRelay::new(socket, method.clone());

        let client_session_id = relay.session_id;
        let dest =
            Destination::new(Address::Domain("dns.google".to_string()), 53);
        let payload = b"domain test";

        let packet = build_server_aes(
            &method,
            222,
            0,
            client_session_id,
            &dest,
            payload,
            None,
            0,
        );

        let (decrypted, parsed_dest) = relay.decrypt_packet_aes(&packet).unwrap();
        assert_eq!(decrypted, payload);
        assert_eq!(parsed_dest, dest);
    }
}
