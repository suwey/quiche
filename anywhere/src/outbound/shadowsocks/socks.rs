// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! SOCKS5 address serialization for the Shadowsocks 2022 protocol.
//!
//! Mirrors sing's `M.SocksaddrSerializer.WriteAddrPort` / `ReadAddrPort`.
//! Address types:
//! - `0x01` IPv4: `01` + 4 bytes IP + 2 bytes port (BE)
//! - `0x03` Domain: `03` + 1 byte length + domain + 2 bytes port (BE)
//! - `0x04` IPv6: `04` + 16 bytes IP + 2 bytes port (BE)
//!
//! The domain form is always sent to the remote SS server for DNS resolution;
//! `dest.resolved_ip` is intentionally ignored on serialize.

use crate::inbound::{Address, Destination};

/// Serialize a [`Destination`] to SOCKS5 address bytes (ATYP + addr + port).
///
/// Uses `dest.address` as-is; `dest.resolved_ip` is never consulted.
/// Panics if a domain name exceeds 255 bytes (it cannot fit the length byte).
pub fn serialize_socks_addr(dest: &Destination) -> Vec<u8> {
    let mut buf = Vec::with_capacity(socks_addr_len(dest));
    match &dest.address {
        Address::Ipv4(ip) => {
            buf.push(0x01);
            buf.extend_from_slice(ip);
        },
        Address::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.len() > u8::MAX as usize {
                panic!(
                    "socks addr: domain length {} exceeds maximum {} bytes",
                    bytes.len(),
                    u8::MAX
                );
            }
            buf.push(0x03);
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        },
        Address::Ipv6(ip) => {
            buf.push(0x04);
            buf.extend_from_slice(ip);
        },
    }
    buf.extend_from_slice(&dest.port.to_be_bytes());
    buf
}

/// Deserialize a SOCKS5 address from `buf`.
///
/// Returns the parsed [`Destination`] (with `resolved_ip = None`) and the
/// total number of bytes consumed.
pub fn deserialize_socks_addr(
    buf: &[u8],
) -> Result<(Destination, usize), String> {
    if buf.is_empty() {
        return Err("socks addr: buffer too short for ATYP".to_string());
    }
    let atyp = buf[0];
    match atyp {
        0x01 => {
            // IPv4: ATYP + 4 IP + 2 port = 7
            if buf.len() < 7 {
                return Err("socks addr: truncated IPv4 address".to_string());
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[1..5]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((Destination::new(Address::Ipv4(ip), port), 7))
        },
        0x03 => {
            // Domain: ATYP + 1 length + N + 2 port
            if buf.len() < 2 {
                return Err("socks addr: truncated domain length".to_string());
            }
            let len = buf[1] as usize;
            let total = 1 + 1 + len + 2;
            if buf.len() < total {
                return Err("socks addr: truncated domain address".to_string());
            }
            let domain = std::str::from_utf8(&buf[2..2 + len])
                .map_err(|e| format!("socks addr: invalid domain UTF-8: {}", e))?
                .to_string();
            let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);
            Ok((Destination::new(Address::Domain(domain), port), total))
        },
        0x04 => {
            // IPv6: ATYP + 16 IP + 2 port = 19
            if buf.len() < 19 {
                return Err("socks addr: truncated IPv6 address".to_string());
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((Destination::new(Address::Ipv6(ip), port), 19))
        },
        other => Err(format!("socks addr: unknown ATYP 0x{:02x}", other)),
    }
}

/// Number of bytes [`serialize_socks_addr`] will produce for `dest`.
pub fn socks_addr_len(dest: &Destination) -> usize {
    match &dest.address {
        Address::Ipv4(_) => 1 + 4 + 2,
        Address::Domain(d) => 1 + 1 + d.len() + 2,
        Address::Ipv6(_) => 1 + 16 + 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- exact byte output --------------------------------------------------

    #[test]
    fn test_serialize_ipv4_exact() {
        let dest = Destination::new(Address::Ipv4([192, 168, 1, 1]), 443);
        assert_eq!(
            serialize_socks_addr(&dest),
            vec![0x01, 192, 168, 1, 1, 0x01, 0xBB]
        );
    }

    #[test]
    fn test_serialize_domain_exact() {
        let dest =
            Destination::new(Address::Domain("example.com".to_string()), 443);
        let mut expected = vec![0x03, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&[0x01, 0xBB]);
        assert_eq!(serialize_socks_addr(&dest), expected);
    }

    #[test]
    fn test_serialize_ipv6_exact() {
        let ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let dest = Destination::new(Address::Ipv6(ip), 443);
        let mut expected = vec![0x04];
        expected.extend_from_slice(&ip);
        expected.extend_from_slice(&[0x01, 0xBB]);
        assert_eq!(serialize_socks_addr(&dest), expected);
    }

    #[test]
    fn test_serialize_port_boundaries() {
        let zero = Destination::new(Address::Ipv4([0, 0, 0, 0]), 0);
        assert_eq!(
            serialize_socks_addr(&zero),
            vec![0x01, 0, 0, 0, 0, 0x00, 0x00]
        );

        let max = Destination::new(Address::Ipv4([255, 255, 255, 255]), 65535);
        assert_eq!(
            serialize_socks_addr(&max),
            vec![0x01, 255, 255, 255, 255, 0xFF, 0xFF]
        );
    }

    // -- round-trip ----------------------------------------------------------

    #[test]
    fn test_roundtrip_ipv4() {
        let dest = Destination::new(Address::Ipv4([10, 0, 0, 1]), 8080);
        let bytes = serialize_socks_addr(&dest);
        let (parsed, n) = deserialize_socks_addr(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(parsed.address, dest.address);
        assert_eq!(parsed.port, dest.port);
        assert!(parsed.resolved_ip.is_none());
    }

    #[test]
    fn test_roundtrip_domain() {
        let dest = Destination::new(
            Address::Domain("sub.example.org".to_string()),
            8443,
        );
        let bytes = serialize_socks_addr(&dest);
        let (parsed, n) = deserialize_socks_addr(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(parsed.address, dest.address);
        assert_eq!(parsed.port, dest.port);
        assert!(parsed.resolved_ip.is_none());
    }

    #[test]
    fn test_roundtrip_ipv6() {
        let ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let dest = Destination::new(Address::Ipv6(ip), 443);
        let bytes = serialize_socks_addr(&dest);
        let (parsed, n) = deserialize_socks_addr(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(parsed.address, dest.address);
        assert_eq!(parsed.port, dest.port);
        assert!(parsed.resolved_ip.is_none());
    }

    #[test]
    fn test_roundtrip_preserves_resolved_ip_none() {
        // resolved_ip must always be None after deserialization even if the
        // input Destination carried one (serialize ignores it).
        let mut dest = Destination::new(Address::Ipv4([8, 8, 8, 8]), 53);
        dest.resolved_ip =
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)));
        let bytes = serialize_socks_addr(&dest);
        let (parsed, _) = deserialize_socks_addr(&bytes).unwrap();
        assert!(parsed.resolved_ip.is_none());
    }

    // -- deserialize edge cases ---------------------------------------------

    #[test]
    fn test_deserialize_truncated() {
        // empty
        assert!(deserialize_socks_addr(&[]).is_err());
        // IPv4 truncated
        assert!(deserialize_socks_addr(&[0x01, 192, 168]).is_err());
        assert!(deserialize_socks_addr(&[0x01]).is_err());
        // domain: length byte present but body + port missing
        assert!(deserialize_socks_addr(&[0x03]).is_err());
        assert!(
            deserialize_socks_addr(&[0x03, 11, b'h', b'e', b'l', b'l', b'o'])
                .is_err()
        );
        // domain: body complete but port missing
        assert!(
            deserialize_socks_addr(&[0x03, 5, b'h', b'e', b'l', b'l', b'o'])
                .is_err()
        );
        // IPv6 truncated
        assert!(deserialize_socks_addr(&[0x04, 0, 0, 0]).is_err());
        // unknown ATYP
        assert!(deserialize_socks_addr(&[0x00, 0, 0]).is_err());
        assert!(deserialize_socks_addr(&[0x05, 0, 0]).is_err());
    }

    #[test]
    fn test_deserialize_consumes_only_needed_bytes() {
        let dest = Destination::new(Address::Ipv4([1, 2, 3, 4]), 53);
        let bytes = serialize_socks_addr(&dest);
        let mut extended = bytes.clone();
        extended.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        let (parsed, n) = deserialize_socks_addr(&extended).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(parsed.address, dest.address);
        assert_eq!(parsed.port, dest.port);
    }

    #[test]
    fn test_deserialize_unknown_atyp_message() {
        let err = deserialize_socks_addr(&[0x02]).unwrap_err();
        assert!(err.contains("ATYP"), "unexpected error: {}", err);
    }

    #[test]
    fn test_deserialize_invalid_utf8_domain() {
        // ATYP=domain, len=2, two invalid UTF-8 continuation bytes, port=0
        let buf = vec![0x03, 2, 0xFF, 0xFE, 0x00, 0x00];
        assert!(deserialize_socks_addr(&buf).is_err());
    }

    // -- socks_addr_len ------------------------------------------------------

    #[test]
    fn test_socks_addr_len() {
        assert_eq!(
            socks_addr_len(&Destination::new(Address::Ipv4([1, 2, 3, 4]), 80)),
            7
        );
        assert_eq!(
            socks_addr_len(&Destination::new(
                Address::Domain("a.com".to_string()),
                80
            )),
            1 + 1 + 5 + 2,
        );
        assert_eq!(
            socks_addr_len(&Destination::new(Address::Ipv6([0u8; 16]), 80)),
            19
        );
    }

    #[test]
    fn test_socks_addr_len_matches_serialize() {
        for dest in [
            Destination::new(Address::Ipv4([172, 16, 0, 1]), 22),
            Destination::new(Address::Domain("x.y.z".to_string()), 1234),
            Destination::new(Address::Ipv6([0xAB; 16]), 9999),
        ] {
            assert_eq!(socks_addr_len(&dest), serialize_socks_addr(&dest).len());
        }
    }

    // -- domain length overflow ---------------------------------------------

    #[test]
    #[should_panic(expected = "domain length")]
    fn test_serialize_domain_too_long() {
        let long = "a".repeat(256);
        let dest = Destination::new(Address::Domain(long), 80);
        let _ = serialize_socks_addr(&dest);
    }
}
