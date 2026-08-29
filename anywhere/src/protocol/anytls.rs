// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Shared AnyTLS protocol primitives used by both inbound and outbound.
//!
//! Contains command constants, frame encoding/decoding, SOCKS address helpers,
//! padding scheme management, settings serialization, and hash utilities.
//! UoT (UDP-over-TCP) lives in [`crate::protocol::uot`] and is re-exported.

use std::collections::HashMap;
use std::io;
use std::io::Read;

use boring::hash::MessageDigest;
use boring::hash::hash;
use bytes::BufMut;

// ========== Protocol Constants ==========

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;

pub const PROTOCOL_VERSION: u32 = 2;
pub const FRAME_HEADER_SIZE: usize = 7;

/// Human-readable name for a command byte (for logging).
pub fn cmd_name(cmd: u8) -> &'static str {
    match cmd {
        CMD_WASTE => "WASTE",
        CMD_SYN => "SYN",
        CMD_PSH => "PSH",
        CMD_FIN => "FIN",
        CMD_SETTINGS => "SETTINGS",
        CMD_ALERT => "ALERT",
        CMD_UPDATE_PADDING_SCHEME => "UPDATE_PADDING_SCHEME",
        CMD_SYNACK => "SYNACK",
        CMD_HEART_REQUEST => "HEART_REQUEST",
        CMD_HEART_RESPONSE => "HEART_RESPONSE",
        CMD_SERVER_SETTINGS => "SERVER_SETTINGS",
        _ => "UNKNOWN",
    }
}

// ========== Frame encoding/decoding ==========

/// Encode one anytls frame:
/// `[cmd:u8][stream_id:u32-be][data_len:u16-be][data]`.
pub fn encode_frame(cmd: u8, stream_id: u32, data: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload too large",
        ));
    }
    let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
    buf.push(cmd);
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    Ok(buf)
}

/// Read one complete frame from a blocking `Read` stream.
/// Returns `(cmd, stream_id, data)`.
pub fn read_frame_blocking<R: Read>(
    stream: &mut R,
) -> io::Result<(u8, u32, Vec<u8>)> {
    let mut hdr = [0u8; FRAME_HEADER_SIZE];
    stream.read_exact(&mut hdr)?;
    let command = hdr[0];
    let stream_id = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
    let data_len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
    let mut data = vec![0u8; data_len];
    if data_len > 0 {
        stream.read_exact(&mut data)?;
    }
    Ok((command, stream_id, data))
}

// ========== SOCKS address helpers ==========

/// Encode a `host:port` target into SOCKS5 address bytes (ATYP 0x01/0x03/0x04).
pub fn encode_target(target: &str) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let (host, port_str) = if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "unclosed bracket")
        })?;
        (host, rest.strip_prefix(':').unwrap_or(""))
    } else {
        let Some((h, p)) = target.rsplit_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("no port: {target}"),
            ));
        };
        (h, p)
    };
    let port: u16 = port_str.parse().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid port")
    })?;
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        buf.put_u8(0x01);
        buf.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        buf.put_u8(0x04);
        buf.extend_from_slice(&ip.octets());
    } else {
        if host.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "domain too long",
            ));
        }
        buf.put_u8(0x03);
        buf.put_u8(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
    }
    buf.put_u16(port);
    Ok(buf)
}

/// Decode SOCKS5 address bytes into a `host:port` string.
pub fn decode_socks_addr(data: &[u8]) -> io::Result<String> {
    if data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty socks addr",
        ));
    }
    let atyp = data[0];
    let (host, port_offset) = match atyp {
        0x01 => {
            if data.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short ipv4 addr",
                ));
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            (ip.to_string(), 5)
        },
        0x04 => {
            if data.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short ipv6 addr",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            (format!("[{ip}]"), 17)
        },
        0x03 => {
            if data.len() < 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short domain addr",
                ));
            }
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short domain addr data",
                ));
            }
            let domain = String::from_utf8_lossy(&data[2..2 + len]).to_string();
            (domain, 2 + len)
        },
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown atyp: {other}"),
            ));
        },
    };
    let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
    Ok(format!("{host}:{port}"))
}

/// Compute the byte length of a SOCKS5 address at the start of `data`.
/// Returns 0 if the data is incomplete.
pub fn target_addr_len(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    match data[0] {
        0x01 => 7,
        0x04 => 19,
        0x03 => {
            if data.len() < 2 {
                return 0;
            }
            2 + data[1] as usize + 2
        },
        _ => 0,
    }
}

// ========== LCG PRNG ==========

/// Simple LCG pseudo-random number generator (no external `rand` dependency).
pub struct LcgGen(u64);

impl LcgGen {
    pub fn new() -> Self {
        Self(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1),
        )
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    pub fn range(&mut self, min: i64, max: i64) -> i64 {
        min + (self.next() % (max - min + 1) as u64) as i64
    }

    /// Fill `buf` with pseudo-random bytes.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next() as u8;
        }
    }
}

// ========== Padding ==========

pub const CHECK_MARK: i32 = -1;

pub const DEFAULT_PADDING_SCHEME: &str = r#"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000"#;

/// Padding scheme parser and random-size generator.
#[derive(Clone)]
pub struct PaddingFactory {
    scheme: HashMap<String, String>,
    stop: u32,
}

impl PaddingFactory {
    /// Parse a padding scheme from raw text bytes.
    pub fn new(raw: &[u8]) -> io::Result<Self> {
        let mut scheme = HashMap::new();
        for line in std::str::from_utf8(raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .lines()
        {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            scheme.insert(k.trim().to_string(), v.trim().to_string());
        }
        let stop =
            scheme
                .get("stop")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing stop")
                })?;
        Ok(Self { scheme, stop })
    }

    /// Build a `PaddingFactory` from the built-in default scheme.
    pub fn default_factory() -> Self {
        Self::new(DEFAULT_PADDING_SCHEME.as_bytes()).expect("default")
    }

    /// Generate random segment sizes for packet index `pkt`.
    /// Returns an empty vec if no rule exists for `pkt`.
    /// `CHECK_MARK` (-1) indicates a checkpoint.
    pub fn generate_sizes(&self, pkt: u32) -> Vec<i32> {
        let mut sizes = Vec::new();
        let Some(spec) = self.scheme.get(&pkt.to_string()) else {
            return sizes;
        };
        let mut rng = LcgGen::new();
        for part in spec.split(',') {
            let part = part.trim();
            if part == "c" {
                sizes.push(CHECK_MARK);
                continue;
            }
            let Some((a, b)) = part.split_once('-') else {
                continue;
            };
            let min: i64 = a.trim().parse().unwrap_or(0);
            let max: i64 = b.trim().parse().unwrap_or(0);
            if min <= 0 || max <= 0 {
                continue;
            }
            let (mn, mx) = (min.min(max), min.max(max));
            sizes.push(if mn == mx {
                mn as i32
            } else {
                rng.range(mn, mx) as i32
            });
        }
        sizes
    }

    /// Packet index above which no padding is applied.
    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// Compute the MD5 hex digest of the raw scheme text.
    pub fn md5_hex(raw: &[u8]) -> String {
        hash(MessageDigest::md5(), raw)
            .map(|h| h.as_ref().iter().map(|b| format!("{b:02x}")).collect())
            .unwrap_or_default()
    }

    /// Format a `PaddingFactory` back into its canonical text representation.
    pub fn format_scheme_text(&self) -> String {
        let mut s = format!("stop={}\n", self.stop);
        let mut indices: Vec<String> = self.scheme.keys().cloned().collect();
        indices.sort_by(|a, b| {
            let ai: usize = a.parse().unwrap_or(usize::MAX);
            let bi: usize = b.parse().unwrap_or(usize::MAX);
            ai.cmp(&bi)
        });
        for key in &indices {
            if key == "stop" {
                continue;
            }
            s.push_str(&format!("{key}={}\n", self.scheme[key]));
        }
        s.trim().to_string()
    }

    /// Return the raw scheme entries (excluding "stop").
    pub fn scheme(&self) -> &HashMap<String, String> {
        &self.scheme
    }
}

// ========== Settings ==========

/// Parse a settings payload (key=value lines separated by '\n').
pub fn parse_settings(data: &[u8]) -> io::Result<HashMap<String, String>> {
    let s = std::str::from_utf8(data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut map = HashMap::new();
    for line in s.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(map)
}

/// Build the client settings body sent in `CMD_SETTINGS`.
pub fn build_client_settings_body(padding_md5: &str) -> String {
    format!(
        "v={}\nclient=anywhere/0.1.0\npadding-md5={}",
        PROTOCOL_VERSION, padding_md5
    )
}

/// Build the server settings body sent in `CMD_SERVER_SETTINGS`.
pub fn build_server_settings_body() -> String {
    format!("v={}", PROTOCOL_VERSION)
}

// ========== Hash ==========

/// SHA-256 hash of `data`, returned as a 32-byte array.
pub fn sha256(data: &[u8]) -> io::Result<[u8; 32]> {
    let digest = hash(MessageDigest::sha256(), data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

// ========== Control / Write message types ==========

/// Control frame sent from a stream to the session IO thread.
pub enum ControlFrame {
    Fin(u32),
}

/// Messages sent to the session write task.
pub enum WriteMsg {
    /// (cmd, stream_id, data) — a single frame to write.
    Frame(u8, u32, Vec<u8>),
    /// Raw pre-encoded frame bytes.
    RawFrame(Vec<u8>),
}

// UoT (UDP-over-TCP) protocol moved to [`crate::protocol::uot`].
// Re-exported here so existing `protocol::anytls` callers (inbound/outbound
// anytls) keep resolving without import churn. New callers (e.g.
// shadowsocks UoT) should use `crate::protocol::uot` directly.
pub use crate::protocol::uot::{
    SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, UOT_ATYP_DOMAIN,
    UOT_ATYP_IPV4, UOT_ATYP_IPV6, UOT_MAGIC_ADDRESS, uot_encode_associate_packet,
    uot_magic_address_with_port, uot_try_parse_associate_packet,
};
