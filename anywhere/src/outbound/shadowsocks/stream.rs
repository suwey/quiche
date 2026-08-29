// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Shadowsocks 2022 (AEAD-2022) TCP stream with delayed handshake.
//!
//! Implements [`SsTcpStream`], an [`StreamRelay`] that speaks the SS2022 TCP
//! protocol as a client. The design mirrors `sing-shadowsocks2`:
//!
//! - **Delayed handshake** (`DialEarlyConn`): the stream is returned before any
//!   bytes hit the wire. The first non-empty [`StreamRelay::write`] bundles the
//!   data as *early data* inside the request variable-header chunk; the first
//!   [`StreamRelay::read`] reads the server's response header. Either may happen
//!   first — if `read` is called before `write`, an empty request is sent so the
//!   response salt can be validated.
//! - **shadowio chunk framing**: after the handshake, payload is framed as
//!   `2-byte-BE-length || payload`, each encrypted separately. Every chunk
//!   consumes two nonces (length block, then payload block).
//!
//! The relay loop drives this via `tokio::select!`, so `read` and `write` are
//! never invoked concurrently — no internal locking is required.
//!
//! Protocol references:
//! - `shadowaead_2022/method.go` (`writeRequest`, `readResponse`)
//! - `internal/shadowio/reader.go`, `internal/shadowio/writer.go`

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(test)]
use tokio::net::TcpStream;

use super::cipher::{
    CipherMethod, HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER, MAX_PACKET_SIZE,
    MAX_PADDING_LENGTH, OVERHEAD, REQUEST_HEADER_FIXED_CHUNK_LENGTH, SsAead,
    TIMESTAMP_TOLERANCE_SECS, increase_nonce,
};
use super::socks::{serialize_socks_addr, socks_addr_len};
use crate::inbound::Destination;
use crate::relay::StreamRelay;

/// Capacity of the request buffer, mirroring sing's `buf.BufferSize` (standard
/// build). It bounds how much *early data* fits inside the variable-header
/// chunk of the handshake write; anything beyond `max_payload_len` is sent as
/// ordinary shadowio data chunks. The exact value only affects the early-data
/// split — the server reads whatever length the fixed header declares.
const REQUEST_BUFFER_SIZE: usize = 32 * 1024;

/// Fill `buf` with cryptographically secure random bytes from the OS CSPRNG.
///
/// `getrandom::fill` never fails on supported platforms; panicking is the only
/// safe response if it does (matches the rest of the codebase).
fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("getrandom: system CSPRNG failed");
}

/// SS2022 client TCP stream with lazy handshake and shadowio chunk framing.
pub struct SsTcpStream<S: AsyncRead + AsyncWrite + Unpin + Send> {
    conn: S,
    method: CipherMethod,
    dest: Destination,
    /// Salt of the client's request; set by the write handshake and validated
    /// against the server's response salt by the read handshake.
    request_salt: Option<Vec<u8>>,
    // ── write state ──
    write_aead: Option<SsAead>,
    write_nonce: [u8; 12],
    write_handshaked: bool,
    // ── read state ──
    read_aead: Option<SsAead>,
    read_nonce: [u8; 12],
    read_handshaked: bool,
    /// Decrypted-but-unconsumed payload from the most recent chunk read.
    read_buf: Vec<u8>,
    /// Read cursor into `read_buf`.
    read_buf_pos: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SsTcpStream<S> {
    /// Create a new SS2022 client stream over an established connection.
    ///
    /// No data is sent; the handshake is deferred to the first `read`/`write`.
    pub fn new(conn: S, method: CipherMethod, dest: Destination) -> Self {
        Self {
            conn,
            method,
            dest,
            request_salt: None,
            write_aead: None,
            write_nonce: [0u8; 12],
            write_handshaked: false,
            read_aead: None,
            read_nonce: [0u8; 12],
            read_handshaked: false,
            read_buf: Vec::new(),
            read_buf_pos: 0,
        }
    }

    /// Perform the client -> server request handshake, optionally bundling
    /// `payload` as early data.
    ///
    /// Wire layout: `salt || EIH || enc(fixed header) || enc(variable header)`
    /// followed by any overflow of `payload` as shadowio data chunks.
    ///
    /// Nonce sequence consumed: `0` (fixed header), `1` (variable header),
    /// leaving `write_nonce` at `[2, 0, …]` for the first data chunk.
    async fn do_handshake_write(&mut self, payload: &[u8]) -> io::Result<()> {
        let ksl = self.method.key_salt_length();
        let addr_len = socks_addr_len(&self.dest);

        // 1. Random salt + session key + AEAD + EIH.
        let mut salt = vec![0u8; ksl];
        fill_random(&mut salt);
        let session_key = self.method.session_key(&salt);
        let aead = self.method.create_aead(&session_key);
        let eih = self.method.generate_eih(&salt);

        // 2. Timestamp + padding length + early-data bounds.
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            .as_secs();
        let padding_len: usize = if payload.len() < MAX_PADDING_LENGTH {
            let mut rb = [0u8; 2];
            fill_random(&mut rb);
            (u16::from_be_bytes(rb) % MAX_PADDING_LENGTH as u16) as usize + 1
        } else {
            0
        };

        // `max_payload_len` mirrors sing's
        // `requestBuffer.FreeLen() - (variableLengthHeaderLen + Overhead)`,
        // i.e. the remaining request-buffer space after the salt, EIH, fixed
        // header ciphertext, and the variable header (sans payload) + its tag.
        let var_header_len_no_payload = addr_len + 2 + padding_len;
        let used_before_var =
            ksl + eih.len() + REQUEST_HEADER_FIXED_CHUNK_LENGTH + OVERHEAD;
        let free = REQUEST_BUFFER_SIZE.saturating_sub(used_before_var);
        let max_payload_len =
            free.saturating_sub(var_header_len_no_payload + OVERHEAD);
        let early_payload_len = payload.len().min(max_payload_len);
        let var_header_len = var_header_len_no_payload + early_payload_len;

        // 3. Fixed header plaintext: type || timestamp(u64 BE) || varHeaderLen(u16 BE).
        let mut fixed_header =
            Vec::with_capacity(REQUEST_HEADER_FIXED_CHUNK_LENGTH);
        fixed_header.push(HEADER_TYPE_CLIENT);
        fixed_header.extend_from_slice(&timestamp.to_be_bytes());
        fixed_header.extend_from_slice(&(var_header_len as u16).to_be_bytes());

        // 4. Encrypt fixed header with nonce 0 -> nonce becomes [1, 0, …].
        let enc_fixed = aead.seal(&self.write_nonce, &fixed_header);
        increase_nonce(&mut self.write_nonce);

        // 5. Variable header plaintext: socksaddr || paddingLen(u16 BE) || padding || earlyPayload.
        let socks_addr = serialize_socks_addr(&self.dest);
        let mut var_header = Vec::with_capacity(var_header_len);
        var_header.extend_from_slice(&socks_addr);
        var_header.extend_from_slice(&(padding_len as u16).to_be_bytes());
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            fill_random(&mut padding);
            var_header.extend_from_slice(&padding);
        }
        var_header.extend_from_slice(&payload[..early_payload_len]);

        // 6. Encrypt variable header with nonce 1 -> nonce becomes [2, 0, …].
        let enc_var = aead.seal(&self.write_nonce, &var_header);
        increase_nonce(&mut self.write_nonce);

        // 7. Write salt || EIH || enc(fixed) || enc(var) in a single send.
        let mut out =
            Vec::with_capacity(ksl + eih.len() + enc_fixed.len() + enc_var.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&eih);
        out.extend_from_slice(&enc_fixed);
        out.extend_from_slice(&enc_var);
        self.conn.write_all(&out).await?;

        log::trace!(
            "ss: handshake write: addr={} ({} bytes), padding_len={}, early_payload_len={}, var_header_len={}",
            String::from_utf8_lossy(&socks_addr),
            socks_addr.len(),
            padding_len,
            early_payload_len,
            var_header_len
        );

        // 8. Commit write state; `write_nonce` is already [2, 0, …].
        self.request_salt = Some(salt);
        self.write_aead = Some(aead);
        self.write_handshaked = true;
        log::trace!(
            "ss: handshake write ok (salt={}B eih={}B early={}B)",
            ksl,
            eih.len(),
            early_payload_len
        );

        // 9. Any payload that did not fit as early data -> data chunks.
        if early_payload_len < payload.len() {
            self.write_data_chunks(&payload[early_payload_len..])
                .await?;
        }
        Ok(())
    }

    /// Perform the server -> client response handshake.
    ///
    /// Reads the response salt, derives the read session key, reads and
    /// validates the fixed response header (type, timestamp, request-salt echo,
    /// padding length) and discards the padding. Leaves `read_nonce` at
    /// `[2, 0, …]` for the first data chunk.
    async fn do_handshake_read(&mut self) -> io::Result<()> {
        // If the request has not been sent yet (read-before-write), send an
        // empty request so the response salt can be validated.
        if self.request_salt.is_none() {
            self.do_handshake_write(&[]).await?;
        }

        let ksl = self.method.key_salt_length();

        // 1. Response salt -> read session key + AEAD.
        let mut salt = vec![0u8; ksl];
        self.conn.read_exact(&mut salt).await?;
        let session_key = self.method.session_key(&salt);
        let aead = self.method.create_aead(&session_key);

        // 2. Fixed response header (nonce 0): type || timestamp || requestSalt || maxPaddingLen.
        let mut enc_hdr =
            vec![0u8; REQUEST_HEADER_FIXED_CHUNK_LENGTH + ksl + OVERHEAD];
        self.conn.read_exact(&mut enc_hdr).await?;
        let hdr = aead
            .open(&self.read_nonce, &enc_hdr)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        increase_nonce(&mut self.read_nonce); // -> [1, 0, …]

        if hdr[0] != HEADER_TYPE_SERVER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bad response header type: expected {HEADER_TYPE_SERVER}, got {}",
                    hdr[0]
                ),
            ));
        }
        let epoch = u64::from_be_bytes(hdr[1..9].try_into().unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            .as_secs() as i64;
        let diff = (now - epoch as i64).abs();
        if diff > TIMESTAMP_TOLERANCE_SECS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bad timestamp: diff {diff}s exceeds {TIMESTAMP_TOLERANCE_SECS}s"
                ),
            ));
        }
        {
            let req_salt = self
                .request_salt
                .as_ref()
                .expect("request_salt set by write handshake");
            let response_salt = &hdr[9..9 + ksl];
            if response_salt != req_salt.as_slice() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad response salt: does not match request salt",
                ));
            }
        }
        let data_length =
            u16::from_be_bytes([hdr[9 + ksl], hdr[9 + ksl + 1]]) as usize;
        log::trace!(
            "ss: handshake read: type={}, timestamp_diff={}s, data_length={}",
            hdr[0],
            diff,
            data_length
        );

        // 3. First data chunk (nonce 1) — read and buffer for the caller.
        //    In SS2022, the server's first encrypted block after the header is
        //    actual payload (e.g. TLS ServerHello), NOT padding to discard.
        if data_length > 0 {
            let mut enc_data = vec![0u8; data_length + OVERHEAD];
            self.conn.read_exact(&mut enc_data).await?;
            let payload = aead
                .open(&self.read_nonce, &enc_data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            increase_nonce(&mut self.read_nonce); // -> [2, 0, …]
            self.read_buf = payload;
            self.read_buf_pos = 0;
        } else {
            increase_nonce(&mut self.read_nonce); // -> [2, 0, …]
        }

        // 4. Commit read state.
        self.read_aead = Some(aead);
        self.read_handshaked = true;
        log::trace!("ss: handshake read ok");
        Ok(())
    }

    /// Write `buf` as shadowio data chunks. Each chunk consumes two nonces
    /// (length block, then payload block). `buf` must be non-empty and the
    /// write handshake must already be complete.
    async fn write_data_chunks(&mut self, buf: &[u8]) -> io::Result<()> {
        log::trace!("ss: write_data_chunks {} bytes", buf.len());
        let mut start = 0;
        while start < buf.len() {
            let end = (start + MAX_PACKET_SIZE).min(buf.len());
            let chunk = &buf[start..end];
            let len_bytes = (chunk.len() as u16).to_be_bytes();

            let enc_len = self
                .write_aead
                .as_ref()
                .expect("write_aead set after handshake")
                .seal(&self.write_nonce, &len_bytes);
            increase_nonce(&mut self.write_nonce);

            let enc_payload = self
                .write_aead
                .as_ref()
                .expect("write_aead set after handshake")
                .seal(&self.write_nonce, chunk);
            increase_nonce(&mut self.write_nonce);

            self.conn.write_all(&enc_len).await?;
            self.conn.write_all(&enc_payload).await?;
            start = end;
        }
        Ok(())
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> StreamRelay for SsTcpStream<S> {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        log::trace!(
            "ss: read called, buf_len={}, read_handshaked={}",
            buf.len(),
            self.read_handshaked
        );
        if !self.read_handshaked {
            if let Err(e) = self.do_handshake_read().await {
                log::error!("ss: handshake read failed: {e}");
                return Err(e);
            }
        }

        // Serve any leftover payload from the previous chunk first.
        if self.read_buf_pos < self.read_buf.len() {
            let avail = self.read_buf.len() - self.read_buf_pos;
            let n = avail.min(buf.len());
            buf[..n].copy_from_slice(
                &self.read_buf[self.read_buf_pos..self.read_buf_pos + n],
            );
            self.read_buf_pos += n;
            if self.read_buf_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_buf_pos = 0;
            }
            return Ok(n);
        }

        // Read one chunk: encrypted length (2 + tag), then encrypted payload.
        let mut enc_len_buf = [0u8; 2 + OVERHEAD];
        match self.conn.read_exact(&mut enc_len_buf).await {
            Ok(_) => {
                log::trace!(
                    "ss: read enc_len_buf ok, {} bytes",
                    enc_len_buf.len()
                );
            },
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                log::trace!("ss: read enc_len_buf EOF");
                return Ok(0);
            },
            Err(e) => {
                log::error!("ss: chunk read_exact(len) failed: {e}");
                return Err(e);
            },
        }
        let len_plain = self
            .read_aead
            .as_ref()
            .expect("read_aead set after handshake")
            .open(&self.read_nonce, &enc_len_buf)
            .map_err(|e| {
                log::error!("ss: chunk decrypt(len) failed: {e}");
                io::Error::new(io::ErrorKind::InvalidData, e)
            })?;
        increase_nonce(&mut self.read_nonce);

        let len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        if len == 0 {
            return Ok(0);
        }

        let mut enc_payload_buf = vec![0u8; len + OVERHEAD];
        match self.conn.read_exact(&mut enc_payload_buf).await {
            Ok(_) => {},
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
            Err(e) => {
                log::error!("ss: chunk read_exact(payload) failed: {e}");
                return Err(e);
            },
        }
        let payload = self
            .read_aead
            .as_ref()
            .expect("read_aead set after handshake")
            .open(&self.read_nonce, &enc_payload_buf)
            .map_err(|e| {
                log::error!("ss: chunk decrypt(payload) failed: {e}");
                io::Error::new(io::ErrorKind::InvalidData, e)
            })?;
        increase_nonce(&mut self.read_nonce);
        log::trace!(
            "ss: read chunk: {} bytes, first 8 bytes: {:02x?}",
            payload.len(),
            &payload[..payload.len().min(8)]
        );

        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        if n < payload.len() {
            // Caller's buffer was smaller than the chunk; buffer the rest.
            self.read_buf = payload;
            self.read_buf_pos = n;
        } else {
            self.read_buf.clear();
            self.read_buf_pos = 0;
        }
        Ok(n)
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        log::trace!(
            "ss: write called with {} bytes, handshaked={}",
            buf.len(),
            self.write_handshaked
        );
        if !self.write_handshaked {
            if let Err(e) = self.do_handshake_write(buf).await {
                log::error!("ss: handshake write failed: {e}");
                return Err(e);
            }
            return Ok(());
        }
        if let Err(e) = self.write_data_chunks(buf).await {
            log::error!("ss: data write failed: {e}");
            return Err(e);
        }
        log::trace!("ss: write_data_chunks done, {} bytes", buf.len());
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.conn.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::Address;
    use crate::outbound::shadowsocks::socks::deserialize_socks_addr;
    use base64::Engine;
    use tokio::net::TcpListener;

    // ── helpers ────────────────────────────────────────────────────────────

    fn make_method(name: &str) -> CipherMethod {
        let ksl = match name {
            "2022-blake3-aes-128-gcm" => 16,
            _ => 32,
        };
        let psk = vec![0x42u8; ksl];
        let password = base64::engine::general_purpose::STANDARD.encode(&psk);
        CipherMethod::new(name, &password).unwrap()
    }

    fn test_dest() -> Destination {
        Destination::new(Address::Domain("example.com".to_string()), 443)
    }

    /// Create a connected loopback TCP pair `(client, server)`.
    async fn make_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect =
            tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let client = connect.await.unwrap();
        (client, server)
    }

    /// Server-side: read the request header (salt, EIH, fixed header, variable
    /// header). Returns `(request_salt, dest, early_data, aead, next_nonce)`.
    async fn server_read_request_header(
        conn: &mut TcpStream, method: &CipherMethod,
    ) -> (Vec<u8>, Destination, Vec<u8>, SsAead, [u8; 12]) {
        let ksl = method.key_salt_length();
        let mut salt = vec![0u8; ksl];
        conn.read_exact(&mut salt).await.unwrap();

        let eih_len = method.generate_eih(&salt).len();
        let mut eih = vec![0u8; eih_len];
        if eih_len > 0 {
            conn.read_exact(&mut eih).await.unwrap();
        }

        let sk = method.session_key(&salt);
        let aead = method.create_aead(&sk);

        let mut enc_fixed =
            vec![0u8; REQUEST_HEADER_FIXED_CHUNK_LENGTH + OVERHEAD];
        conn.read_exact(&mut enc_fixed).await.unwrap();
        let fixed = aead.open(&[0u8; 12], &enc_fixed).unwrap();
        assert_eq!(fixed[0], HEADER_TYPE_CLIENT);
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;

        let mut nonce = [0u8; 12];
        increase_nonce(&mut nonce); // [1, 0, …]
        let mut enc_var = vec![0u8; var_len + OVERHEAD];
        conn.read_exact(&mut enc_var).await.unwrap();
        let var = aead.open(&nonce, &enc_var).unwrap();
        increase_nonce(&mut nonce); // [2, 0, …]

        let (dest, consumed) = deserialize_socks_addr(&var).unwrap();
        let padding_len =
            u16::from_be_bytes([var[consumed], var[consumed + 1]]) as usize;
        let early_start = consumed + 2 + padding_len;
        let early_data = var[early_start..].to_vec();
        (salt, dest, early_data, aead, nonce)
    }

    /// Server-side: read data chunks until EOF. `nonce` continues from the
    /// request header (i.e. starts at `[2, 0, …]`).
    async fn server_read_chunks(
        conn: &mut TcpStream, aead: &SsAead, nonce: &mut [u8; 12],
    ) -> Vec<u8> {
        let mut all = Vec::new();
        loop {
            let mut enc_len = [0u8; 2 + OVERHEAD];
            if conn.read_exact(&mut enc_len).await.is_err() {
                break; // EOF
            }
            let len_plain = aead.open(nonce, &enc_len).unwrap();
            increase_nonce(nonce);
            let len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
            if len == 0 {
                break;
            }
            let mut enc_payload = vec![0u8; len + OVERHEAD];
            conn.read_exact(&mut enc_payload).await.unwrap();
            let payload = aead.open(nonce, &enc_payload).unwrap();
            increase_nonce(nonce);
            all.extend_from_slice(&payload);
        }
        all
    }

    /// Server-side: write the response (salt, fixed header, padding) then `data`
    /// as shadowio chunks. The response salt must echo the client's request salt.
    async fn server_write_response(
        conn: &mut TcpStream, method: &CipherMethod, request_salt: &[u8],
        data: &[u8],
    ) {
        let ksl = method.key_salt_length();
        let mut salt = vec![0u8; ksl];
        fill_random(&mut salt);
        let sk = method.session_key(&salt);
        let aead = method.create_aead(&sk);
        let mut nonce = [0u8; 12];

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // In SS2022, the server's first encrypted block after the header IS
        // the payload (e.g. TLS ServerHello). The LENGTH field in the header
        // is the payload length, NOT padding length.
        //
        // Layout: salt || enc(type + timestamp + request_salt + length) || enc(data[..MAX_PACKET_SIZE])
        //         || [enc(len2) || enc(data2)] *  (subsequent chunks if any)
        let first_chunk_end = data.len().min(MAX_PACKET_SIZE);
        let first_len = first_chunk_end as u16;

        let mut fixed = Vec::with_capacity(1 + 8 + ksl + 2);
        fixed.push(HEADER_TYPE_SERVER);
        fixed.extend_from_slice(&ts.to_be_bytes());
        fixed.extend_from_slice(request_salt);
        fixed.extend_from_slice(&first_len.to_be_bytes());
        let enc_fixed = aead.seal(&nonce, &fixed);
        increase_nonce(&mut nonce); // [1, 0, …]

        let mut out = Vec::new();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&enc_fixed);

        if first_chunk_end > 0 {
            let enc_data = aead.seal(&nonce, &data[..first_chunk_end]);
            increase_nonce(&mut nonce); // [2, 0, …]
            out.extend_from_slice(&enc_data);
        } else {
            // No first chunk; nonce still increments because the header
            // declared length=0 conceptually consumes nonce 1.
            increase_nonce(&mut nonce);
        }

        conn.write_all(&out).await.unwrap();

        // Subsequent chunks (if data exceeded MAX_PACKET_SIZE).
        let mut start = first_chunk_end;
        while start < data.len() {
            let end = (start + MAX_PACKET_SIZE).min(data.len());
            let chunk = &data[start..end];
            let len_bytes = (chunk.len() as u16).to_be_bytes();
            let enc_len = aead.seal(&nonce, &len_bytes);
            increase_nonce(&mut nonce);
            let enc_payload = aead.seal(&nonce, chunk);
            increase_nonce(&mut nonce);
            conn.write_all(&enc_len).await.unwrap();
            conn.write_all(&enc_payload).await.unwrap();
            start = end;
        }
    }

    // ── nonce sequence ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_write_nonce_sequence() {
        let (client_conn, mut peer) = make_pair().await;
        let mut s = SsTcpStream::new(
            client_conn,
            make_method("2022-blake3-aes-128-gcm"),
            test_dest(),
        );

        // Drain the peer so the client's writes never block on a full buffer.
        let drain = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match peer.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {},
                }
            }
        });

        // First write: handshake with small early data (fits, no chunks).
        // Nonces 0 (fixed header) + 1 (variable header) consumed -> [2, 0, …].
        s.write(b"hello").await.unwrap();
        assert!(s.write_handshaked);
        assert_eq!(s.write_nonce, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // 16384 bytes -> 2 chunks (16383 + 1); 2 nonces each -> +4.
        s.write(&vec![0xABu8; 16384]).await.unwrap();
        assert_eq!(s.write_nonce, [6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // 100 bytes -> 1 chunk -> +2.
        s.write(&vec![0xCDu8; 100]).await.unwrap();
        assert_eq!(s.write_nonce, [8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Closing the client lets the drain task observe EOF and exit.
        drop(s);
        drain.await.unwrap();
    }

    // ── handshake state machine (read before write) ────────────────────────

    #[tokio::test]
    async fn test_handshake_state_machine_read_first() {
        let (client_conn, mut server_conn) = make_pair().await;
        let method = make_method("2022-blake3-aes-128-gcm");

        // Fresh stream: nothing handshaked yet.
        let mut s = SsTcpStream::new(client_conn, method.clone(), test_dest());
        assert!(!s.write_handshaked);
        assert!(!s.read_handshaked);
        assert!(s.request_salt.is_none());

        // The server reads the (empty-early-data) request then replies with no
        // data, so the client's read() hits EOF right after the handshake.
        let server_task = tokio::spawn(async move {
            let (salt, _dest, early, _aead, _nonce) =
                server_read_request_header(&mut server_conn, &method).await;
            assert!(early.is_empty(), "no early data expected for read-first");
            // Response with no payload, then close.
            server_write_response(&mut server_conn, &method, &salt, b"").await;
            server_conn.shutdown().await.unwrap();
        });

        // read() before any write: triggers an empty write handshake, then the
        // read handshake. No data chunk arrives -> Ok(0).
        let mut buf = vec![0u8; 64];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        // Both handshakes are now complete.
        assert!(s.write_handshaked);
        assert!(s.read_handshaked);
        assert!(s.request_salt.is_some());
        // Empty early-data write handshake: nonces 0 + 1 -> [2, 0, …].
        assert_eq!(s.write_nonce, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // Read handshake: nonce 0 (fixed header) + 1 (first data chunk, length=0) -> [2, 0, …].
        assert_eq!(s.read_nonce, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        server_task.await.unwrap();
    }

    // ── full round-trip across all three methods ────────────────────────────

    async fn roundtrip_one(method_name: &str) {
        let (client_conn, mut server_conn) = make_pair().await;
        let method = make_method(method_name);
        let dest = test_dest();

        let payload1 = b"hello world".to_vec();
        let payload2 = vec![0x42u8; 20000]; // 2 chunks
        let mut expected: Vec<u8> = payload1.clone();
        expected.extend_from_slice(&payload2);

        let client_method = method.clone();
        let client_dest = dest.clone();
        let client_task = tokio::spawn(async move {
            let mut s = SsTcpStream::new(client_conn, client_method, client_dest);
            s.write(&payload1).await.unwrap();
            s.write(&payload2).await.unwrap();
            s.shutdown().await.unwrap();
            let mut received = Vec::new();
            let mut buf = vec![0u8; 1024];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            received
        });

        // Server: read request, verify, reply.
        let (salt, parsed_dest, early, aead, mut nonce) =
            server_read_request_header(&mut server_conn, &method).await;
        assert_eq!(parsed_dest, dest, "{method_name}: dest mismatch");
        let chunks =
            server_read_chunks(&mut server_conn, &aead, &mut nonce).await;
        let mut all = early;
        all.extend_from_slice(&chunks);
        assert_eq!(all, expected, "{method_name}: request payload mismatch");

        let response: &[u8] = b"response data from server";
        server_write_response(&mut server_conn, &method, &salt, response).await;
        server_conn.shutdown().await.unwrap();

        let received = client_task.await.unwrap();
        assert_eq!(received, response, "{method_name}: response mismatch");
    }

    #[tokio::test]
    async fn test_roundtrip_aes128() {
        roundtrip_one("2022-blake3-aes-128-gcm").await;
    }

    #[tokio::test]
    async fn test_roundtrip_aes256() {
        roundtrip_one("2022-blake3-aes-256-gcm").await;
    }

    #[tokio::test]
    async fn test_roundtrip_chacha20() {
        roundtrip_one("2022-blake3-chacha20-poly1305").await;
    }

    // ── early-data split ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_early_data_split() {
        let (client_conn, mut server_conn) = make_pair().await;
        let method = make_method("2022-blake3-aes-128-gcm");
        let dest = test_dest();
        // Larger than max_payload_len (~32 KiB) so the first write must split
        // into early data + data chunks.
        let payload = vec![0x77u8; 40000];

        let client_method = method.clone();
        let client_dest = dest.clone();
        let payload_clone = payload.clone();
        let client_task = tokio::spawn(async move {
            let mut s = SsTcpStream::new(client_conn, client_method, client_dest);
            s.write(&payload_clone).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let (_salt, parsed_dest, early, aead, mut nonce) =
            server_read_request_header(&mut server_conn, &method).await;
        assert_eq!(parsed_dest, dest);
        // The split must have occurred: some early data, some chunk data.
        assert!(!early.is_empty(), "early data should be non-empty");
        assert!(
            early.len() < payload.len(),
            "early data ({}) should be smaller than payload ({}) — split did not occur",
            early.len(),
            payload.len()
        );
        let chunks =
            server_read_chunks(&mut server_conn, &aead, &mut nonce).await;
        assert!(!chunks.is_empty(), "chunk data should be non-empty");
        let mut all = early;
        all.extend_from_slice(&chunks);
        assert_eq!(all.len(), payload.len());
        assert_eq!(all, payload);

        client_task.await.unwrap();
    }

    // ── small-buffer chunk reassembly ──────────────────────────────────────

    #[tokio::test]
    async fn test_read_reassembles_oversized_chunk() {
        let (client_conn, mut server_conn) = make_pair().await;
        let method = make_method("2022-blake3-aes-256-gcm");

        // Server sends a response with one 5000-byte chunk; client reads with a
        // 1024-byte buffer, forcing multiple read() calls to drain one chunk.
        let chunk_data = vec![0x5Au8; 5000];

        let client_method = method.clone();
        let client_dest = test_dest();
        let chunk_for_server = chunk_data.clone();
        let client_task = tokio::spawn(async move {
            let mut s = SsTcpStream::new(client_conn, client_method, client_dest);
            // Send a tiny request so the server can reply.
            s.write(b"hi").await.unwrap();
            s.shutdown().await.unwrap();
            let mut received = Vec::new();
            let mut buf = vec![0u8; 1024];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            received
        });

        let (salt, _dest, _early, _aead, _nonce) =
            server_read_request_header(&mut server_conn, &method).await;
        server_write_response(
            &mut server_conn,
            &method,
            &salt,
            &chunk_for_server,
        )
        .await;
        server_conn.shutdown().await.unwrap();

        let received = client_task.await.unwrap();
        assert_eq!(received, chunk_data);
    }
}
