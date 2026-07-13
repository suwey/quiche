//! Traffic sniffing — extract domain from TLS ClientHello / HTTP Host.
//!
//! Pure functions: input is the first N bytes of a TCP stream, output is
//! an optional domain string. No I/O, no state.
//!
//! Used by the TUN inbound path to recover the domain that was lost when
//! the kernel handed us a raw IP packet (SOCKS5/QUIC inbounds already have
//! the domain from their handshake).

/// Maximum bytes to read from the stream for sniffing.
pub const SNIFF_BUF_SIZE: usize = 4096;

/// Result of a successful sniff.
#[derive(Debug, Clone)]
pub struct SniffResult {
    /// Sniffed domain (TLS SNI / HTTP Host / QUIC SNI / DNS query name).
    /// `None` for protocol-only identification (e.g. SSH, BitTorrent).
    pub domain: Option<String>,
    pub protocol: &'static str,
}

/// Sniff a payload for domain and/or protocol information.
///
/// Tries domain-extracting protocols first (TLS, HTTP, QUIC, DNS),
/// then protocol-only identifiers (BitTorrent, SSH, RDP, STUN, DTLS, NTP).
/// Quick check: does this payload look like something we can sniff?
/// Used to short-circuit sniff reads for non-standard protocols (e.g.
/// WeChat MMTLS) to avoid adding latency.
pub fn looks_sniffable(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    // TLS: starts with 0x16 (handshake) + version 0x03xx
    if payload.len() >= 2 && payload[0] == 0x16 && payload[1] == 0x03 {
        return true;
    }
    // HTTP: starts with a known HTTP method
    let http_methods = [
        b"GET ", b"POST", b"CONN", b"HEAD", b"PUT ", b"DELE", b"OPTI", b"PATC",
    ];
    if payload.len() >= 4 && http_methods.iter().any(|m| payload[..4] == **m) {
        return true;
    }
    // QUIC: first byte has QUIC bit pattern (0xXX & 0x80 == 0x80, long header)
    // QUIC long header: bit 7 set, bits 6-4 = 1 (Long), next 3 bytes = version
    if payload.len() >= 5 && (payload[0] & 0xc0) == 0xc0 {
        return true;
    }
    // DTLS: starts with 0x16 + version 0xfeXX (DTLS 1.2 = 0xfefd)
    if payload.len() >= 2 && payload[0] == 0x16 && payload[1] == 0xfe {
        return true;
    }
    // SSH: starts with "SSH-"
    if payload.len() >= 4 && &payload[..4] == b"SSH-" {
        return true;
    }
    // BT: starts with 0x13 + "BitTorrent protocol"
    if payload.len() >= 1 && payload[0] == 0x13 && payload.len() >= 20
        && &payload[1..20] == b"BitTorrent protoco" {
        return true;
    }
    // RDP: X.224 Connection Request — starts with TPKT header 0x03 0x00
    if payload.len() >= 2 && payload[0] == 0x03 && payload[1] == 0x00 {
        return true;
    }
    // STUN: first two bytes have magic cookie 0x2112 in bytes 4-7
    if payload.len() >= 8 {
        let cookie = &payload[4..8];
        if cookie == [0x21, 0x12, 0xa4, 0x42] {
            return true;
        }
    }
    // NTP: 48 bytes, first byte has LI(2) + VN(3) + Mode(3) in high nibble
    if payload.len() >= 1 && (payload[0] & 0xc7) != 0 && payload.len() <= 48 {
        // Heuristic — many protocols could match, but combined with
        // other checks this is good enough. Skip if not clearly NTP.
    }
    // DNS: query/response with reasonable length
    if payload.len() >= 12 {
        // DNS header: ID(2) + flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
        // QDCOUNT should be >= 1 for a query
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount >= 1 && qdcount <= 10 {
            return true;
        }
    }
    false
}

pub fn sniff(payload: &[u8]) -> Option<SniffResult> {
    sniff_tls(payload)
        .or_else(|| sniff_http(payload))
        .or_else(|| sniff_quic(payload))
        .or_else(|| sniff_dns(payload))
        .or_else(|| sniff_bittorrent(payload))
        .or_else(|| sniff_ssh(payload))
        .or_else(|| sniff_rdp(payload))
        .or_else(|| sniff_stun(payload))
        .or_else(|| sniff_dtls(payload))
        .or_else(|| sniff_ntp(payload))
}

/// Server-first protocols: the server sends data before the client,
/// so sniffing the client's first packet is useless.
/// Ports: SMTP(25/465/587), IMAP(143/993), POP3(110/995), FTP(21), SSH(22)
pub fn is_server_first(port: u16) -> bool {
    matches!(port, 25 | 465 | 587 | 143 | 993 | 110 | 995 | 21 | 22)
}

// ---------------------------------------------------------------------------
// TLS SNI
// ---------------------------------------------------------------------------

/// Extract SNI from a TLS ClientHello record.
///
/// TLS record format:
///   [0]  content type      (0x16 = Handshake)
///   [1]  version major     (0x03)
///   [2]  version minor
///   [3..5] length (u16 BE)
///   [5]  handshake type    (0x01 = ClientHello)
///   [6..9] length (3 bytes BE)
///   [9..11] client version (0x03 0xxx)
///   [11..43] random (32 bytes)
///   [43] session_id length → skip that many
///   then: cipher_suites (2-byte length prefix) → skip
///   then: compression_methods (1-byte length prefix) → skip
///   then: extensions (2-byte total length prefix) → parse
pub fn sniff_tls(payload: &[u8]) -> Option<SniffResult> {
    if payload.len() < 5 {
        return None;
    }

    // TLS record header
    if payload[0] != 0x16 {
        return None;
    }
    if payload[1] != 0x03 {
        return None;
    }
    let _record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;

    // Need at least the handshake header
    if payload.len() < 6 {
        return None;
    }
    if payload[5] != 0x01 {
        // Not ClientHello
        return None;
    }

    // [5]     handshake type (0x01 = ClientHello)
    // [6..9]  handshake length (3 bytes BE)
    // [9..11] client version (2 bytes)
    // [11..43] random (32 bytes)
    let mut pos = 9;  // start after record header(5) + handshake type(1) + length(3)
    pos += 2;         // skip client version
    pos += 32;        // skip random
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

    let ext_end = pos + ext_total;
    let ext_end = ext_end.min(payload.len());

    // Walk extensions
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            break;
        }

        if ext_type == 0x0000 {
            // SNI extension
            // [0..2] server_name_list_length (u16 BE)
            // then entries: [0..1] name_type (0 = host_name)
            //               [1..3] name_length (u16 BE)
            //               [3..]  name
            return parse_sni_extension(&payload[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<SniffResult> {
    if data.len() < 5 {
        return None;
    }
    // list length (ignored, there's typically one entry)
    let mut pos = 2;

    // name_type
    if pos >= data.len() {
        return None;
    }
    if data[pos] != 0x00 {
        // not host_name
        return None;
    }
    pos += 1;

    // name_length
    if pos + 2 > data.len() {
        return None;
    }
    let name_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if pos + name_len > data.len() {
        return None;
    }

    let name = std::str::from_utf8(&data[pos..pos + name_len]).ok()?;
    if name.is_empty() {
        return None;
    }

    Some(SniffResult {
        domain: Some(name.to_string()),
        protocol: "tls",
    })
}

// ---------------------------------------------------------------------------
// HTTP Host
// ---------------------------------------------------------------------------

/// Extract Host from an HTTP request line.
///
/// Looks for "GET "/"POST " etc. prefix, then scans for "Host: " header.
pub fn sniff_http(payload: &[u8]) -> Option<SniffResult> {
    if payload.len() < 16 {
        return None;
    }

    // Quick check: does it look like an HTTP request?
    let methods: &[&[u8]] = &[
        b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
    ];
    let is_http = methods
        .iter()
        .any(|m| payload.starts_with(m));
    if !is_http {
        return None;
    }

    // Find "Host: " header (case-insensitive)
    let text = std::str::from_utf8(payload).ok()?;
    let host = find_host_header(text)?;
    let host = host.trim();

    if host.is_empty() {
        return None;
    }

    // Strip port from host if present (e.g. "example.com:443" → "example.com")
    let domain = host.split(':').next().unwrap_or(host).to_string();

    if domain.is_empty() {
        return None;
    }

    Some(SniffResult {
        domain: Some(domain),
        protocol: "http",
    })
}

/// Find the Host header value in an HTTP request text.
/// Returns the raw host string (may include port).
fn find_host_header(text: &str) -> Option<String> {
    // Search line by line for "Host:" prefix (case-insensitive).
    // The request line comes first, then headers separated by \r\n.
    for line in text.split("\r\n") {
        if line.eq_ignore_ascii_case("host:") || line.to_ascii_lowercase().starts_with("host:") {
            // Everything after "Host:" is the value.
            let colon = line.find(':')?;
            let value = line[colon + 1..].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// QUIC SNI
// ---------------------------------------------------------------------------

/// QUIC v1 Initial Salt (RFC 9001).
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC v2 Initial Salt (RFC 9369).
const QUIC_V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
    0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Extract SNI from a QUIC Initial packet.
///
/// QUIC Initial packets carry a TLS ClientHello inside a CRYPTO frame.
/// The payload is encrypted with keys derived from the DCID and a fixed salt.
pub fn sniff_quic(payload: &[u8]) -> Option<SniffResult> {
    let dcid = parse_quic_long_header(payload)?;
    let plaintext = decrypt_quic_initial(payload, &dcid)?;
    extract_sni_from_quic_payload(&plaintext)
}

/// Parse the QUIC long header and return the DCID.
/// Returns None if this is not a QUIC Initial packet.
fn parse_quic_long_header(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 6 {
        return None;
    }

    // First byte: high bit must be 1 (long header)
    if payload[0] & 0x80 == 0 {
        return None;
    }

    // Version (4 bytes, BE)
    let version = u32::from_be_bytes([
        payload[1], payload[2], payload[3], payload[4],
    ]);

    // QUIC v1 = 0x00000001, v2 = 0x6b3343cf
    // Negotiation (0x00000000) and unknown versions are skipped.
    if version != 0x00000001 && version != 0x6b3343cf {
        return None;
    }

    // DCID
    let dcid_len = payload[5] as usize;
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    if payload.len() < 6 + dcid_len {
        return None;
    }
    let dcid = payload[6..6 + dcid_len].to_vec();

    // Verify this is an Initial packet (type bits in byte 0)
    // For QUIC v1: (byte0 & 0x30) == 0x00 means Initial
    // For QUIC v2: (byte0 & 0x30) == 0x01 means Initial
    let is_initial = if version == 0x00000001 {
        (payload[0] & 0x30) == 0x00
    } else {
        (payload[0] & 0x30) == 0x10
    };
    if !is_initial {
        return None;
    }

    Some(dcid)
}

/// Decrypt a QUIC Initial packet payload.
/// Returns the plaintext frames.
fn decrypt_quic_initial(payload: &[u8], dcid: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::{Aes128Gcm, KeyInit, aead::Aead};
    use hkdf::Hkdf;
    use sha2::Sha256;

    let salt = if u32::from_be_bytes([
        payload[1], payload[2], payload[3], payload[4],
    ]) == 0x00000001
    {
        &QUIC_V1_INITIAL_SALT[..]
    } else {
        &QUIC_V2_INITIAL_SALT[..]
    };

    // initial_secret = HKDF-Extract(initial_salt, client_dcid)
    let initial_secret = Hkdf::<Sha256>::new(Some(salt), dcid);

    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    let client_secret = hkdf_expand_label(&initial_secret, b"client in", &[], 32)?;

    // key = HKDF-Expand-Label(client_secret, "quic key", "", 16)
    let key = hkdf_expand_label(&Hkdf::<Sha256>::from_prk(&client_secret).ok()?, b"quic key", &[], 16)?;
    // iv = HKDF-Expand-Label(client_secret, "quic iv", "", 12)
    let iv = hkdf_expand_label(&Hkdf::<Sha256>::from_prk(&client_secret).ok()?, b"quic iv", &[], 12)?;
    // hp = HKDF-Expand-Label(client_secret, "quic hp", "", 16)
    let hp = hkdf_expand_label(&Hkdf::<Sha256>::from_prk(&client_secret).ok()?, b"quic hp", &[], 16)?;

    // Parse past DCID to find SCID, token, and ciphertext
    let dcid_len = payload[5] as usize;
    let mut pos = 6 + dcid_len;

    // SCID
    if pos >= payload.len() { return None; }
    let scid_len = payload[pos] as usize;
    pos += 1 + scid_len;
    if pos >= payload.len() { return None; }

    // Token length (varint)
    let (token_len, token_bytes) = read_varint(&payload[pos..])?;
    pos += token_bytes + token_len;
    if pos >= payload.len() { return None; }

    // Payload length (varint) — length of the encrypted payload
    let (payload_len, payload_bytes) = read_varint(&payload[pos..])?;
    pos += payload_bytes;

    if pos + payload_len > payload.len() {
        return None;
    }

    let ciphertext = &payload[pos..pos + payload_len];

    // Remove header protection (first 4 bytes of packet header are unprotected)
    // The protected header starts at byte 1 (after the first byte)
    // and covers the packet number region.
    // For simplicity, assume 4-byte packet number (common for Initial).
    if ciphertext.len() < 4 + 16 {
        return None;
    }

    // Compute header protection mask
    let hp_mask = compute_hp_mask(&hp, &ciphertext[..16])?;

    // The packet number is at the end of the header, before the ciphertext.
    // Actually, in QUIC the packet number is part of the header but is
    // protected. The first byte's low 2 bits encode pn_len-1.
    // We need to unprotect the packet number first.
    //
    // The protected region starts right after the first byte's type bits.
    // In our parsed position, `pos` points to the start of the encrypted
    // ciphertext which includes the encrypted packet number.
    //
    // Let's unprotect: the last 4 bytes of the header (packet number)
    // are XORed with hp_mask[0..pn_len].
    //
    // Actually, the packet number is the first 1-4 bytes of the ciphertext,
    // and it's protected by XOR with hp_mask.
    //
    // Determine pn_len from the (unprotected) first byte's low 2 bits,
    // after XOR with hp_mask[0].
    let mut first_byte = payload[0];
    first_byte ^= hp_mask[0] & 0x0f; // unprotect low 4 bits
    let pn_len = (first_byte & 0x03) as usize + 1;

    // Unprotect packet number bytes
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[i] = ciphertext[i] ^ hp_mask[1 + i];
    }

    // Reconstruct full packet number (assume 4 bytes, pad with zeros for truncated)
    let packet_number = {
        let mut val: u32 = 0;
        for i in 0..pn_len {
            val = (val << 8) | pn_bytes[i] as u32;
        }
        val
    };

    // The actual encrypted payload starts after the packet number
    let enc_start = pn_len;
    if ciphertext.len() < enc_start + 16 {
        return None;
    }
    let enc_data = &ciphertext[enc_start..];

    // Construct nonce: iv XOR packet_number (left-padded to 12 bytes)
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);
    let pn_bytes_be = packet_number.to_be_bytes();
    for i in 0..4 {
        nonce[12 - 4 + i] ^= pn_bytes_be[i];
    }

    // Associated data = the entire packet from byte 0 to the start of ciphertext[enc_start]
    // i.e. header up to and including the (now unprotected) packet number
    let header_end = pos + enc_start;
    let aad = &payload[..header_end];
    // We need to modify the first byte and pn bytes in a copy for proper AAD
    let mut aad_copy = aad.to_vec();
    aad_copy[0] = first_byte; // unprotected first byte
    for i in 0..pn_len {
        aad_copy[pos + i] = pn_bytes[i]; // unprotected pn bytes
    }

    let cipher = Aes128Gcm::new_from_slice(&key).ok()?;
    let nonce: &aes_gcm::Nonce<_> = (&nonce).try_into().ok()?;
    let plaintext = cipher.decrypt(
        nonce,
        aes_gcm::aead::Payload { msg: enc_data, aad: &aad_copy },
    ).ok()?;

    Some(plaintext)
}

/// HKDF-Expand-Label as defined in RFC 8446 §7.1.
fn hkdf_expand_label(
    secret: &hkdf::Hkdf<sha2::Sha256>,
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Option<Vec<u8>> {
    // HkdfLabel struct:
    //   uint16 length = length;
    //   opaque label<7..255> = "tls13 " + label;
    //   opaque context<0..255> = context;
    let full_label = [b"tls13 ", label].concat();

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut okm = vec![0u8; length];
    secret.expand(&info, &mut okm).ok()?;
    Some(okm)
}

/// Read a QUIC variable-length integer (RFC 9000 §16).
/// Returns (value, bytes_consumed).
fn read_varint(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() { return None; }
    let prefix = (data[0] & 0xc0) >> 6;
    let len = 1usize << prefix;
    if data.len() < len { return None; }
    let mut val: usize = (data[0] & 0x3f) as usize;
    for i in 1..len {
        val = (val << 8) | data[i] as usize;
    }
    Some((val, len))
}

/// Compute QUIC header protection mask using AES-ECB.
fn compute_hp_mask(hp: &[u8], sample: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(hp).ok()?;
    let mut block = [0u8; 16];
    block.copy_from_slice(&sample[..16]);
    cipher.encrypt_block(&mut block.into());
    Some(block.to_vec())
}

/// Extract SNI from decrypted QUIC payload (CRYPTO frames).
fn extract_sni_from_quic_payload(plaintext: &[u8]) -> Option<SniffResult> {
    let mut pos = 0;
    while pos < plaintext.len() {
        if pos + 1 > plaintext.len() { break; }
        let frame_type = plaintext[pos];

        if frame_type == 0x06 {
            // CRYPTO frame
            pos += 1;
            let (_offset, off_bytes) = read_varint(&plaintext[pos..])?;
            pos += off_bytes;
            let (length, len_bytes) = read_varint(&plaintext[pos..])?;
            pos += len_bytes;

            if pos + length > plaintext.len() { break; }

            // The CRYPTO frame data is a TLS handshake message.
            // It should be a ClientHello (type 0x01).
            let tls_data = &plaintext[pos..pos + length];
            if tls_data.len() > 4 && tls_data[0] == 0x01 {
                // Skip handshake header (type + 3-byte length) and parse as TLS
                // Build a fake TLS record: type(1) + version(2) + length(2) + handshake
                let mut fake_record = Vec::with_capacity(5 + tls_data.len());
                fake_record.push(0x16); // Handshake
                fake_record.push(0x03); fake_record.push(0x01); // TLS 1.0 version (arbitrary)
                fake_record.extend_from_slice(&(tls_data.len() as u16).to_be_bytes());
                fake_record.extend_from_slice(tls_data);
                if let Some(result) = sniff_tls(&fake_record) {
                    return Some(SniffResult {
                        domain: result.domain,
                        protocol: "quic",
                    });
                }
            }
            pos += length;
        } else if frame_type == 0x00 {
            // PADDING frame
            pos += 1;
        } else if frame_type == 0x01 {
            // PING frame
            pos += 1;
        } else {
            // Unknown frame type — bail out.
            break;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// DNS query name
// ---------------------------------------------------------------------------

/// Extract the query name from a DNS query packet.
///
/// DNS query format (RFC 1035):
///   [0..2]  Transaction ID
///   [2..4]  Flags (QR=0 for query)
///   [4..6]  QDCOUNT (number of questions)
///   [6..8]  ANCOUNT
///   [8..10] NSCOUNT
///   [10..12] ARCOUNT
///   then QDCOSTION sections: qname + qtype(2) + qclass(2)
pub fn sniff_dns(payload: &[u8]) -> Option<SniffResult> {
    if payload.len() < 12 {
        return None;
    }

    // Check if this is a DNS query (QR bit = 0)
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        // This is a response, not a query
        return None;
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if qdcount == 0 {
        return None;
    }

    // Parse the first question
    let mut pos = 12;
    let name = parse_dns_name(payload, &mut pos)?;

    if name.is_empty() {
        return None;
    }

    Some(SniffResult {
        domain: Some(name),
        protocol: "dns",
    })
}

/// Parse a DNS name (uncompressed, no pointers — queries don't use compression).
fn parse_dns_name(data: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels = Vec::new();

    loop {
        if *pos >= data.len() {
            return None;
        }
        let len = data[*pos];
        if len == 0 {
            *pos += 1;
            break;
        }
        // Labels are 1-63 bytes, top 2 bits clear (no compression pointers)
        if len & 0xc0 != 0 {
            return None;
        }
        let len = len as usize;
        *pos += 1;
        if *pos + len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[*pos..*pos + len]).ok()?;
        labels.push(label);
        *pos += len;
    }

    Some(labels.join("."))
}

// ---------------------------------------------------------------------------
// Protocol-only sniffers (no domain extraction)
// ---------------------------------------------------------------------------

/// BitTorrent: BT handshake starts with `\x13BitTorrent protocol`.
/// Also detect DHT (BEP-5) and uTP (BEP-20) patterns.
pub fn sniff_bittorrent(payload: &[u8]) -> Option<SniffResult> {
    // BT handshake: pstrlen(1) + pstr("BitTorrent protocol") + reserved(8) + info_hash(20) + peer_id(20)
    if payload.len() >= 20 && payload.starts_with(b"\x13BitTorrent protocol") {
        return Some(SniffResult { domain: None, protocol: "bittorrent" });
    }
    // uTP (BEP-20): UDP, type in first byte, connection_id in bytes 8-16
    // uTP header: type(1) + version(1) + extension(1) + connection_id(4) + ...
    // type values: 0=ST_DATA, 1=ST_FINAL, 2=ST_STATE, 3=ST_RESET, 4=ST_SYN
    // version = 1
    if payload.len() >= 20 {
        let utp_type = payload[0] & 0x0f;
        let utp_version = (payload[0] >> 4) & 0x0f;
        if utp_version == 1 && utp_type <= 4 && payload.len() >= 20 {
            // Additional check: uTP connections have a recognizable pattern
            return Some(SniffResult { domain: None, protocol: "bittorrent" });
        }
    }
    None
}

/// SSH: handshake starts with `SSH-`.
pub fn sniff_ssh(payload: &[u8]) -> Option<SniffResult> {
    if payload.len() >= 4 && payload.starts_with(b"SSH-") {
        return Some(SniffResult { domain: None, protocol: "ssh" });
    }
    None
}

/// RDP: X.224 Connection Request.
/// Starts with TPKT header (version=3, reserved=0) followed by X.224 CR.
pub fn sniff_rdp(payload: &[u8]) -> Option<SniffResult> {
    // TPKT header: version(1)=3, reserved(1)=0, length(2, BE)
    if payload.len() >= 4 && payload[0] == 3 && payload[1] == 0 {
        // X.224 Connection Request: length indicator + type=0xe0 (CR)
        if payload.len() >= 7 && payload[4] >= 2 && payload[5] == 0xe0 {
            return Some(SniffResult { domain: None, protocol: "rdp" });
        }
    }
    None
}

/// STUN: magic cookie 0x2112A442 at bytes 4-8.
/// STUN message header: type(2) + length(2) + cookie(4) + transaction_id(12)
pub fn sniff_stun(payload: &[u8]) -> Option<SniffResult> {
    if payload.len() >= 8 {
        let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        if cookie == 0x2112a442 {
            return Some(SniffResult { domain: None, protocol: "stun" });
        }
    }
    None
}

/// DTLS: ContentType=22 (Handshake) + version=0xfefd (DTLS 1.0) or 0xfefe (DTLS 1.2).
/// DTLS record header: type(1) + version(2) + epoch(2) + seq(6) + length(2)
pub fn sniff_dtls(payload: &[u8]) -> Option<SniffResult> {
    if payload.len() >= 3 && payload[0] == 22 {
        let version = u16::from_be_bytes([payload[1], payload[2]]);
        if version == 0xfefd || version == 0xfefe {
            return Some(SniffResult { domain: None, protocol: "dtls" });
        }
    }
    None
}

/// NTP: version(2 bits) + mode(3 bits) in first byte.
/// NTP version 3 or 4, mode 3 (client) or 4 (server).
pub fn sniff_ntp(payload: &[u8]) -> Option<SniffResult> {
    if payload.len() >= 48 {
        let version = (payload[0] >> 3) & 0x07;
        let mode = payload[0] & 0x07;
        if (version == 3 || version == 4) && (mode == 3 || mode == 4) {
            return Some(SniffResult { domain: None, protocol: "ntp" });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- TLS SNI tests ---

    #[test]
    fn tls_not_handshake() {
        assert!(sniff_tls(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn tls_too_short() {
        assert!(sniff_tls(&[0x16, 0x03]).is_none());
    }

    #[test]
    fn tls_parses_sni() {
        // Build a minimal ClientHello with SNI extension.
        let hello = build_client_hello_with_sni("example.com");
        let result = sniff_tls(&hello).expect("should parse SNI");
        assert_eq!(result.domain.as_deref(), Some("example.com"));
        assert_eq!(result.protocol, "tls");
    }

    #[test]
    fn tls_parses_long_domain() {
        let domain = "a".repeat(200) + ".example.com";
        let hello = build_client_hello_with_sni(&domain);
        let result = sniff_tls(&hello).expect("should parse SNI");
        assert_eq!(result.domain.as_deref(), Some(domain.as_str()));
    }

    #[test]
    fn tls_no_sni_extension() {
        let hello = build_client_hello_no_sni();
        assert!(sniff_tls(&hello).is_none());
    }

    #[test]
    fn tls_not_client_hello() {
        // ServerHello (type 0x02)
        let mut hello = build_client_hello_with_sni("example.com");
        hello[5] = 0x02; // Change handshake type to ServerHello
        assert!(sniff_tls(&hello).is_none());
    }

    // --- HTTP Host tests ---

    #[test]
    fn http_get_host() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = sniff_http(payload).expect("should find host");
        assert_eq!(result.domain.as_deref(), Some("example.com"));
        assert_eq!(result.protocol, "http");
    }

    #[test]
    fn http_post_host_with_port() {
        let payload = b"POST /api HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n";
        let result = sniff_http(payload).expect("should find host");
        assert_eq!(result.domain.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn http_host_case_insensitive() {
        let payload = b"GET / HTTP/1.1\r\nHOST: Example.COM\r\n\r\n";
        let result = sniff_http(payload).expect("should find host");
        assert_eq!(result.domain.as_deref(), Some("Example.COM"));
    }

    #[test]
    fn http_no_host() {
        let payload = b"GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert!(sniff_http(payload).is_none());
    }

    #[test]
    fn http_not_http() {
        assert!(sniff_http(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00").is_none());
    }

    #[test]
    fn http_connect_host() {
        let payload = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let result = sniff_http(payload).expect("should find host");
        assert_eq!(result.domain.as_deref(), Some("example.com"));
    }

    // --- combined sniff tests ---

    #[test]
    fn sniff_falls_through_to_http() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = sniff(payload).expect("should sniff");
        assert_eq!(result.protocol, "http");
        assert_eq!(result.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn sniff_tls_priority() {
        let hello = build_client_hello_with_sni("tls.example.com");
        let result = sniff(&hello).expect("should sniff");
        assert_eq!(result.protocol, "tls");
        assert_eq!(result.domain.as_deref(), Some("tls.example.com"));
    }

    #[test]
    fn sniff_unknown_returns_none() {
        let payload = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
        assert!(sniff(payload).is_none());
    }

    // --- DNS tests ---

    #[test]
    fn dns_query_example_com() {
        // Minimal DNS query for example.com, type A, class IN
        let pkt = build_dns_query("example.com");
        let result = sniff_dns(&pkt).expect("should sniff DNS");
        assert_eq!(result.protocol, "dns");
        assert_eq!(result.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn dns_query_multi_label() {
        let pkt = build_dns_query("api.github.com");
        let result = sniff_dns(&pkt).expect("should sniff DNS");
        assert_eq!(result.domain.as_deref(), Some("api.github.com"));
    }

    #[test]
    fn dns_response_not_sniffed() {
        let mut pkt = build_dns_query("example.com");
        // Set QR bit to 1 (response)
        pkt[2] |= 0x80;
        assert!(sniff_dns(&pkt).is_none());
    }

    #[test]
    fn dns_too_short() {
        assert!(sniff_dns(&[0x00; 5]).is_none());
    }

    #[test]
    fn dns_zero_qdcount() {
        let pkt = [
            0x12, 0x34, // Transaction ID
            0x00, 0x00, // Flags: query
            0x00, 0x00, // QDCOUNT = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR count
        ];
        assert!(sniff_dns(&pkt).is_none());
    }

    // --- QUIC tests ---

    #[test]
    fn quic_short_packet_returns_none() {
        assert!(sniff_quic(&[0x00; 5]).is_none());
    }

    #[test]
    fn quic_not_long_header() {
        // Short header: high bit = 0
        let pkt = [0x40, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert!(sniff_quic(&pkt).is_none());
    }

    #[test]
    fn quic_unknown_version_returns_none() {
        // Long header, version 0x00000000 (negotiation)
        let pkt = [0xc0, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert!(sniff_quic(&pkt).is_none());
    }

    // --- protocol-only sniffer tests ---

    #[test]
    fn bittorrent_handshake() {
        let pkt = b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00";
        let result = sniff_bittorrent(pkt).expect("should detect BT");
        assert_eq!(result.protocol, "bittorrent");
        assert!(result.domain.is_none());
    }

    #[test]
    fn ssh_handshake() {
        let pkt = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n";
        let result = sniff_ssh(pkt).expect("should detect SSH");
        assert_eq!(result.protocol, "ssh");
        assert!(result.domain.is_none());
    }

    #[test]
    fn rdp_connection_request() {
        // TPKT header + X.224 CR
        let pkt = [
            0x03, 0x00, 0x00, 0x13, // TPKT: version=3, reserved=0, length=19
            0x0e,                   // X.224 length indicator
            0xe0,                   // X.224 type = Connection Request
            0x00, 0x00,             // dst-ref
            0x00, 0x00,             // src-ref
            0x00,                   // class-options
        ];
        let result = sniff_rdp(&pkt).expect("should detect RDP");
        assert_eq!(result.protocol, "rdp");
        assert!(result.domain.is_none());
    }

    #[test]
    fn stun_binding_request() {
        // STUN Binding Request: type=0x0001, length=0, cookie=0x2112A442
        let pkt = [
            0x00, 0x01,             // type = Binding Request
            0x00, 0x00,             // length = 0
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // txn id
        ];
        let result = sniff_stun(&pkt).expect("should detect STUN");
        assert_eq!(result.protocol, "stun");
        assert!(result.domain.is_none());
    }

    #[test]
    fn dtls_handshake() {
        // DTLS 1.2 handshake: type=22, version=0xfefd
        let pkt = [
            0x16,                   // type = Handshake
            0xfe, 0xfd,             // version = DTLS 1.0
            0x00, 0x00,             // epoch
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00,             // length
        ];
        let result = sniff_dtls(&pkt).expect("should detect DTLS");
        assert_eq!(result.protocol, "dtls");
        assert!(result.domain.is_none());
    }

    #[test]
    fn ntp_client_request() {
        // NTP v4 client: version=4, mode=3 (client)
        // first byte: 00_100_011 = 0x23
        let mut pkt = [0u8; 48];
        pkt[0] = 0x23; // version=4, mode=3
        let result = sniff_ntp(&pkt).expect("should detect NTP");
        assert_eq!(result.protocol, "ntp");
        assert!(result.domain.is_none());
    }

    #[test]
    fn server_first_ports() {
        assert!(is_server_first(25));   // SMTP
        assert!(is_server_first(465));  // SMTPS
        assert!(is_server_first(587));  // SMTP submission
        assert!(is_server_first(143));  // IMAP
        assert!(is_server_first(993));  // IMAPS
        assert!(is_server_first(110));  // POP3
        assert!(is_server_first(995));  // POP3S
        assert!(is_server_first(21));   // FTP
        assert!(is_server_first(22));   // SSH
        assert!(!is_server_first(443));
        assert!(!is_server_first(80));
    }

    // --- helpers ---

    /// Build a minimal TLS ClientHello record with the given SNI.
    fn build_client_hello_with_sni(domain: &str) -> Vec<u8> {
        let domain_bytes = domain.as_bytes();

        // SNI extension data: list_length(2) + name_type(1) + name_length(2) + name
        let sni_entry_len = 1 + 2 + domain_bytes.len();
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len; // list_length field + entry

        // One extension: type(2) + length(2) + data(sni_ext_data_len)
        let ext_total = 4 + sni_ext_data_len;

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&u16::to_be_bytes(ext_total as u16)); // extensions total length
        extensions.extend_from_slice(&u16::to_be_bytes(0x0000)); // SNI type
        extensions.extend_from_slice(&u16::to_be_bytes(sni_ext_data_len as u16)); // SNI data length
        extensions.extend_from_slice(&u16::to_be_bytes(sni_list_len as u16)); // server_name_list length
        extensions.push(0x00); // name_type = host_name
        extensions.extend_from_slice(&u16::to_be_bytes(domain_bytes.len() as u16)); // name length
        extensions.extend_from_slice(domain_bytes); // name

        // Build ClientHello body (after handshake header)
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id length = 0
        body.extend_from_slice(&u16::to_be_bytes(2)); // cipher_suites length
        body.extend_from_slice(&[0xc0, 0x2c]); // one cipher suite
        body.push(0x01); // compression_methods length
        body.push(0x00); // null compression
        body.extend_from_slice(&extensions);

        // Handshake header: type(1) + length(3)
        let body_len = body.len();
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.push((body_len >> 16) as u8 & 0xff);
        handshake.push((body_len >> 8) as u8 & 0xff);
        handshake.push(body_len as u8 & 0xff);
        handshake.extend_from_slice(&body);

        // TLS record header
        let rec_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.push(0x03); // version major
        record.push(0x01); // version minor
        record.extend_from_slice(&u16::to_be_bytes(rec_len as u16));
        record.extend_from_slice(&handshake);

        record
    }

    /// Build a ClientHello with extensions but no SNI.
    fn build_client_hello_no_sni() -> Vec<u8> {
        // Build an extension that's not SNI (e.g. supported_versions)
        let ext_data = vec![0x04, 0x00]; // one version entry
        let ext_total = 4 + ext_data.len();

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&u16::to_be_bytes(ext_total as u16)); // total length
        extensions.extend_from_slice(&u16::to_be_bytes(0x002b)); // supported_versions type
        extensions.extend_from_slice(&u16::to_be_bytes(ext_data.len() as u16));
        extensions.extend_from_slice(&ext_data);

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

    /// Build a minimal DNS query for the given domain name.
    fn build_dns_query(domain: &str) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&[0x12, 0x34]); // Transaction ID
        pkt.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, RD=1
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR

        // Question section: encode domain as DNS labels
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // Root label (terminator)

        // QTYPE = A (1), QCLASS = IN (1)
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x01]);

        pkt
    }
}
