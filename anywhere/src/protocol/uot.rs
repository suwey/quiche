// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! UDP-over-TCP (UoT) protocol - shared between outbounds.
//!
//! UoT tunnels UDP datagrams over a TCP byte stream by dialing the stream to
//! a magic FQDN (`sp.v2.udp-over-tcp.arpa`, sing `common/uot` v2) that the
//! server recognizes, then framing each datagram with a length prefix.
//!
//! This is NOT part of the Shadowsocks 2022 spec; it is a sing-box/mihomo
//! extension. It lets a TCP-only server (no UDP relay) carry UDP traffic
//! (DNS, QUIC, ...). Both anytls and shadowsocks outbounds use it via the
//! generic [`UotPacketRelay`].
//!
//! Frame formats (all big-endian), per sing `common/uot/protocol.go`:
//!
//! - Request (sent once at stream open) - uses SOCKS5 ATYP:
//!   `[isConnect:u8][ATYP:u8][addr...][port:u16]`
//!
//! - Associate datagram (repeating) - uses UoT ATYP:
//!   `[ATYP:u8][addr...][port:u16][len:u16][data...]`
//!
//! Important: the Request frame uses sing's `SocksaddrSerializer` (SOCKS5
//! ATYP - 0x01=v4 / 0x03=fqdn / 0x04=v6), while the associate datagrams use
//! `AddrParser` (UoT ATYP - 0x00=v4 / 0x01=v6 / 0x02=fqdn).

use std::io;

use async_trait::async_trait;
use bytes::BufMut;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;

// ========== Constants ==========

/// UoT v2 magic FQDN used to negotiate a UDP-over-TCP stream.
pub const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";

// UoT ATYP (used in associate datagrams).
pub const UOT_ATYP_IPV4: u8 = 0x00;
pub const UOT_ATYP_IPV6: u8 = 0x01;
pub const UOT_ATYP_DOMAIN: u8 = 0x02;

// SOCKS5 ATYP (used in the UoT request header).
pub const SOCKS_ATYP_IPV4: u8 = 0x01;
pub const SOCKS_ATYP_DOMAIN: u8 = 0x03;
pub const SOCKS_ATYP_IPV6: u8 = 0x04;

/// Magic address with a placeholder port; the server only inspects the FQDN.
pub fn uot_magic_address_with_port() -> String {
    format!("{UOT_MAGIC_ADDRESS}:443")
}

// ========== Associate datagram (UoT ATYP) ==========

/// Write `dest` using UoT ATYP (for associate datagrams).
fn write_uot_addr(buf: &mut Vec<u8>, dest: &Destination) -> io::Result<()> {
    match &dest.address {
        Address::Ipv4(o) => {
            buf.put_u8(UOT_ATYP_IPV4);
            buf.extend_from_slice(o);
        },
        Address::Ipv6(o) => {
            buf.put_u8(UOT_ATYP_IPV6);
            buf.extend_from_slice(o);
        },
        Address::Domain(d) => {
            if d.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "uot domain too long",
                ));
            }
            buf.put_u8(UOT_ATYP_DOMAIN);
            buf.put_u8(d.len() as u8);
            buf.extend_from_slice(d.as_bytes());
        },
    }
    buf.put_u16(dest.port);
    Ok(())
}

/// On-the-wire length of `dest`'s UoT addr+port encoding.
fn uot_addr_len(dest: &Destination) -> usize {
    let addr = match &dest.address {
        Address::Ipv4(_) => 1 + 4,
        Address::Ipv6(_) => 1 + 16,
        Address::Domain(d) => 1 + 1 + d.len(),
    };
    addr + 2
}

/// Encode one associate-mode UoT datagram. Uses UoT ATYP.
pub fn uot_encode_associate_packet(
    dest: &Destination, data: &[u8],
) -> io::Result<Vec<u8>> {
    if data.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "uot datagram too large",
        ));
    }
    let mut buf = Vec::with_capacity(uot_addr_len(dest) + 2 + data.len());
    write_uot_addr(&mut buf, dest)?;
    buf.put_u16(data.len() as u16);
    buf.extend_from_slice(data);
    Ok(buf)
}

/// Attempt to parse one associate-mode UoT datagram from `buf`.
///
/// Returns:
/// - `Ok(Some((dest, data_range, consumed)))` on a complete frame
/// - `Ok(None)` if more bytes are needed
/// - `Err(...)` on protocol violation
pub fn uot_try_parse_associate_packet(
    buf: &[u8],
) -> io::Result<Option<(Destination, std::ops::Range<usize>, usize)>> {
    if buf.is_empty() {
        return Ok(None);
    }
    let atyp = buf[0];
    let (address, addr_end) = match atyp {
        UOT_ATYP_IPV4 => {
            if buf.len() < 1 + 4 {
                return Ok(None);
            }
            let mut o = [0u8; 4];
            o.copy_from_slice(&buf[1..5]);
            (Address::Ipv4(o), 5)
        },
        UOT_ATYP_IPV6 => {
            if buf.len() < 1 + 16 {
                return Ok(None);
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[1..17]);
            (Address::Ipv6(o), 17)
        },
        UOT_ATYP_DOMAIN => {
            if buf.len() < 2 {
                return Ok(None);
            }
            let dlen = buf[1] as usize;
            let end = 2 + dlen;
            if buf.len() < end {
                return Ok(None);
            }
            let s = std::str::from_utf8(&buf[2..end]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "uot bad domain utf8")
            })?;
            (Address::Domain(s.to_string()), end)
        },
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("uot associate bad ATYP {atyp:#04x}"),
            ));
        },
    };

    let port_end = addr_end + 2;
    if buf.len() < port_end + 2 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([buf[addr_end], buf[addr_end + 1]]);

    let len_end = port_end + 2;
    let dlen = u16::from_be_bytes([buf[port_end], buf[port_end + 1]]) as usize;

    let data_end = len_end + dlen;
    if buf.len() < data_end {
        return Ok(None);
    }

    Ok(Some((
        Destination::new(address, port),
        len_end..data_end,
        data_end,
    )))
}

// ========== Request frame (SOCKS5 ATYP) ==========

/// Write `dest` using SOCKS5 ATYP (for the Request header only).
fn write_socks_addr(buf: &mut Vec<u8>, dest: &Destination) -> io::Result<()> {
    match &dest.address {
        Address::Ipv4(o) => {
            buf.put_u8(SOCKS_ATYP_IPV4);
            buf.extend_from_slice(o);
        },
        Address::Ipv6(o) => {
            buf.put_u8(SOCKS_ATYP_IPV6);
            buf.extend_from_slice(o);
        },
        Address::Domain(d) => {
            if d.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "uot domain too long",
                ));
            }
            buf.put_u8(SOCKS_ATYP_DOMAIN);
            buf.put_u8(d.len() as u8);
            buf.extend_from_slice(d.as_bytes());
        },
    }
    buf.put_u16(dest.port);
    Ok(())
}

fn socks_addr_len(dest: &Destination) -> usize {
    let addr = match &dest.address {
        Address::Ipv4(_) => 1 + 4,
        Address::Ipv6(_) => 1 + 16,
        Address::Domain(d) => 1 + 1 + d.len(),
    };
    addr + 2
}

/// Encode the request frame sent once at stream open. Uses SOCKS5 ATYP
/// (1/3/4) per sing `protocol.go::WriteRequest` - NOT UoT ATYP.
pub fn encode_request(
    is_connect: bool, dest: &Destination,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1 + socks_addr_len(dest));
    buf.put_u8(if is_connect { 1 } else { 0 });
    write_socks_addr(&mut buf, dest)?;
    Ok(buf)
}

// ========== UotPacketRelay ==========

/// `PacketRelay` over a byte stream (`StreamRelay`) running UoT v2 in
/// associate mode.
///
/// Generic over the underlying stream so it can wrap anytls multiplexed
/// streams, shadowsocks TCP streams, or any other `StreamRelay`.
pub struct UotPacketRelay<S: StreamRelay> {
    stream: S,
    /// Bytes received from `stream` but not yet consumed into a full frame.
    read_buf: Vec<u8>,
}

impl<S: StreamRelay> UotPacketRelay<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buf: Vec::with_capacity(2048),
        }
    }
}

#[async_trait]
impl<S: StreamRelay> PacketRelay for UotPacketRelay<S> {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        let mut scratch = [0u8; 4096];

        loop {
            // Try to parse a frame from the buffer first.
            if let Some((dest, data_range, consumed)) =
                uot_try_parse_associate_packet(&self.read_buf)?
            {
                let data = &self.read_buf[data_range];
                if buf.len() < data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "uot read buffer too small",
                    ));
                }
                let n = data.len();
                buf[..n].copy_from_slice(data);
                self.read_buf.drain(..consumed);
                return Ok((n, dest));
            }

            // Need more bytes from the underlying stream.
            let n = self.stream.read(&mut scratch).await?;
            if n == 0 {
                return Ok((0, Destination::new(Address::Ipv4([0; 4]), 0)));
            }
            self.read_buf.extend_from_slice(&scratch[..n]);
        }
    }

    async fn write_packet(
        &mut self, buf: &[u8], dest: &Destination,
    ) -> io::Result<()> {
        let frame = uot_encode_associate_packet(dest, buf)?;
        self.stream.write(&frame).await?;
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        let _ = self.stream.shutdown().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(host: &str, port: u16) -> Destination {
        let address = if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            Address::Ipv4(ip.octets())
        } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            Address::Ipv6(ip.octets())
        } else {
            Address::Domain(host.to_string())
        };
        Destination::new(address, port)
    }

    #[test]
    fn encode_request_ipv4() {
        // SOCKS5 ATYP: v4 = 0x01.
        let req = encode_request(false, &d("8.8.8.8", 53)).unwrap();
        assert_eq!(req, vec![0x00, 0x01, 8, 8, 8, 8, 0x00, 53]);
    }

    #[test]
    fn encode_request_domain() {
        // SOCKS5 ATYP: fqdn = 0x03.
        let req = encode_request(false, &d("example.com", 443)).unwrap();
        let expected: Vec<u8> =
            [&[0x00, 0x03, 11u8][..], b"example.com", &[0x01, 0xbb][..]].concat();
        assert_eq!(req, expected);
    }

    #[test]
    fn round_trip_associate_ipv4() {
        let dest = d("1.1.1.1", 53);
        let payload = b"hello dns";
        let frame = uot_encode_associate_packet(&dest, payload).unwrap();

        let (parsed_dest, range, consumed) =
            uot_try_parse_associate_packet(&frame).unwrap().unwrap();
        assert_eq!(parsed_dest, dest);
        assert_eq!(&frame[range], payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn round_trip_associate_ipv6() {
        let dest = d("2001:db8::1", 443);
        let payload = b"x";
        let frame = uot_encode_associate_packet(&dest, payload).unwrap();

        let (parsed_dest, range, consumed) =
            uot_try_parse_associate_packet(&frame).unwrap().unwrap();
        assert_eq!(parsed_dest, dest);
        assert_eq!(&frame[range], payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn round_trip_associate_domain() {
        let dest = d("example.com", 53);
        let payload = b"abc";
        let frame = uot_encode_associate_packet(&dest, payload).unwrap();

        let (parsed_dest, range, consumed) =
            uot_try_parse_associate_packet(&frame).unwrap().unwrap();
        assert_eq!(parsed_dest, dest);
        assert_eq!(&frame[range], payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn parser_needs_more_bytes() {
        let dest = d("1.1.1.1", 53);
        let frame = uot_encode_associate_packet(&dest, b"hello").unwrap();
        // Feed truncated input one byte at a time; should keep returning None
        // until the whole frame arrives.
        for i in 0..frame.len() {
            assert!(uot_try_parse_associate_packet(&frame[..i]).unwrap().is_none());
        }
        assert!(uot_try_parse_associate_packet(&frame).unwrap().is_some());
    }

    #[test]
    fn parser_rejects_bad_atyp() {
        let bad = vec![0x99u8, 0, 0, 0, 0];
        assert!(uot_try_parse_associate_packet(&bad).is_err());
    }

    #[test]
    fn domain_too_long_rejected() {
        let long = "a".repeat(256);
        let dest = d(&long, 80);
        assert!(encode_request(false, &dest).is_err());
    }
}
