//! UDP-over-TCP (UoT) protocol — used by AnyTLS to tunnel UDP datagrams over
//! a single anytls stream.
//!
//! Protocol v2 (`sp.v2.udp-over-tcp.arpa`), associate mode.
//!
//! Frame formats (all big-endian):
//!
//! - Request (sent once at stream open) — uses SOCKS5 ATYP:
//!   `[isConnect:u8][ATYP:u8][addr...][port:u16]`
//!
//! - Associate datagram (repeating) — uses UoT ATYP:
//!   `[ATYP:u8][addr...][port:u16][len:u16][data...]`
//!
//! Important: the Request frame uses sing's `SocksaddrSerializer` (SOCKS5
//! ATYP — 0x01=v4 / 0x03=fqdn / 0x04=v6), while the associate datagrams use
//! `AddrParser` (UoT ATYP — 0x00=v4 / 0x01=v6 / 0x02=fqdn). See
//! `sing/common/uot/{protocol.go,conn.go}` for the source of this asymmetry.

use std::io;

use async_trait::async_trait;
use bytes::BufMut;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::outbound::anytls::StreamHandle;
use crate::relay::PacketRelay;

pub const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";

// UoT ATYP (used in associate datagrams).
const UOT_ATYP_IPV4: u8 = 0x00;
const UOT_ATYP_IPV6: u8 = 0x01;
const UOT_ATYP_DOMAIN: u8 = 0x02;

// SOCKS5 ATYP (used in the request header).
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

/// Magic address with a placeholder port; the server only inspects the FQDN.
pub fn magic_address_with_port() -> String {
    format!("{UOT_MAGIC_ADDRESS}:443")
}

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

fn socks_addr_len(dest: &Destination) -> usize {
    let addr = match &dest.address {
        Address::Ipv4(_) => 1 + 4,
        Address::Ipv6(_) => 1 + 16,
        Address::Domain(d) => 1 + 1 + d.len(),
    };
    addr + 2
}

/// Returns the on-the-wire length of `dest`'s UoT addr+port encoding.
fn uot_addr_len(dest: &Destination) -> usize {
    let addr = match &dest.address {
        Address::Ipv4(_) => 1 + 4,
        Address::Ipv6(_) => 1 + 16,
        Address::Domain(d) => 1 + 1 + d.len(),
    };
    addr + 2
}

/// Encode the request frame sent once at stream open. Uses SOCKS5 ATYP
/// (1/3/4) per sing `protocol.go::WriteRequest` — NOT UoT ATYP. Mixing the
/// two makes the server reject with "unknown address family".
pub fn encode_request(
    is_connect: bool, dest: &Destination,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1 + socks_addr_len(dest));
    buf.put_u8(if is_connect { 1 } else { 0 });
    write_socks_addr(&mut buf, dest)?;
    Ok(buf)
}

/// Encode one associate-mode datagram. Uses UoT ATYP.
pub fn encode_associate_packet(
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

/// Attempt to parse one associate-mode datagram from `buf` starting at offset
/// 0. Uses UoT ATYP.
///
/// Returns:
/// - `Ok(Some((dest, data_range, consumed)))` on a complete frame
/// - `Ok(None)` if more bytes are needed
/// - `Err(...)` on protocol violation
fn try_parse_associate_packet(
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
                format!("uot bad ATYP {atyp:#04x}"),
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

// ---------------------------------------------------------------------------
// UotPacketRelay
// ---------------------------------------------------------------------------

/// `PacketRelay` over a single anytls multiplexed stream running UoT v2 in
/// associate mode.
pub struct UotPacketRelay {
    stream: StreamHandle,
    /// Bytes received from `stream` but not yet consumed into a full frame.
    read_buf: Vec<u8>,
}

impl UotPacketRelay {
    pub(super) fn new(stream: StreamHandle) -> Self {
        Self {
            stream,
            read_buf: Vec::with_capacity(2048),
        }
    }
}

#[async_trait]
impl PacketRelay for UotPacketRelay {
    async fn read_packet(
        &mut self, buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        let mut scratch = [0u8; 4096];

        loop {
            // Try to parse a frame from the buffer first.
            if let Some((dest, data_range, consumed)) =
                try_parse_associate_packet(&self.read_buf)?
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
        let frame = encode_associate_packet(dest, buf)?;
        self.stream.write(&frame)?;
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.stream.close().await;
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
        let frame = encode_associate_packet(&dest, payload).unwrap();

        let (parsed_dest, range, consumed) =
            try_parse_associate_packet(&frame).unwrap().unwrap();
        assert_eq!(parsed_dest, dest);
        assert_eq!(&frame[range], payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn round_trip_associate_ipv6() {
        let dest = d("2001:db8::1", 443);
        let payload = b"x";
        let frame = encode_associate_packet(&dest, payload).unwrap();

        let (parsed_dest, range, consumed) =
            try_parse_associate_packet(&frame).unwrap().unwrap();
        assert_eq!(parsed_dest, dest);
        assert_eq!(&frame[range], payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn round_trip_associate_domain() {
        let dest = d("example.com", 53);
        let payload = b"abc";
        let frame = encode_associate_packet(&dest, payload).unwrap();

        let (parsed_dest, range, consumed) =
            try_parse_associate_packet(&frame).unwrap().unwrap();
        assert_eq!(parsed_dest, dest);
        assert_eq!(&frame[range], payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn parser_needs_more_bytes() {
        let dest = d("1.1.1.1", 53);
        let frame = encode_associate_packet(&dest, b"hello").unwrap();
        // Feed truncated input one byte at a time; should keep returning None
        // until the whole frame arrives.
        for i in 0..frame.len() {
            assert!(try_parse_associate_packet(&frame[..i]).unwrap().is_none());
        }
        assert!(try_parse_associate_packet(&frame).unwrap().is_some());
    }

    #[test]
    fn parser_rejects_bad_atyp() {
        let bad = vec![0x99u8, 0, 0, 0, 0];
        assert!(try_parse_associate_packet(&bad).is_err());
    }

    #[test]
    fn domain_too_long_rejected() {
        let long = "a".repeat(256);
        let dest = d(&long, 80);
        assert!(encode_request(false, &dest).is_err());
    }
}
