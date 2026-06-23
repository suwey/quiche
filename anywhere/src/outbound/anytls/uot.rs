//! UDP-over-TCP (UoT) protocol — outbound-specific helpers and relay.
//!
//! Shared UoT constants, ATYP values, and associate-packet encoding/parsing
//! live in [`crate::protocol::anytls`].  This module adds the outbound-only
//! request encoder (SOCKS5 ATYP) and the [`UotPacketRelay`] wrapper.

use std::io;

use async_trait::async_trait;
use bytes::BufMut;

use crate::inbound::Address;
use crate::inbound::Destination;
use crate::outbound::anytls::StreamHandle;
use crate::protocol::anytls as proto;
use crate::relay::PacketRelay;

// Re-export the magic address helper for convenience.
pub use proto::uot_magic_address_with_port as magic_address_with_port;

// SOCKS5 ATYP (used in the request header only).
const SOCKS_ATYP_IPV4: u8 = proto::SOCKS_ATYP_IPV4;
const SOCKS_ATYP_DOMAIN: u8 = proto::SOCKS_ATYP_DOMAIN;
const SOCKS_ATYP_IPV6: u8 = proto::SOCKS_ATYP_IPV6;

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
/// (1/3/4) per sing `protocol.go::WriteRequest` — NOT UoT ATYP.
pub fn encode_request(
    is_connect: bool, dest: &Destination,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1 + socks_addr_len(dest));
    buf.put_u8(if is_connect { 1 } else { 0 });
    write_socks_addr(&mut buf, dest)?;
    Ok(buf)
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
                proto::uot_try_parse_associate_packet(&self.read_buf)?
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
        let frame = proto::uot_encode_associate_packet(dest, buf)?;
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
        let frame = proto::uot_encode_associate_packet(&dest, payload).unwrap();

        let (parsed_dest, range, consumed) =
            proto::uot_try_parse_associate_packet(&frame)
                .unwrap()
                .unwrap();
        assert_eq!(parsed_dest, dest);
        assert_eq!(&frame[range], payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn round_trip_associate_ipv6() {
        let dest = d("2001:db8::1", 443);
        let payload = b"x";
        let frame = proto::uot_encode_associate_packet(&dest, payload).unwrap();

        let (parsed_dest, range, consumed) =
            proto::uot_try_parse_associate_packet(&frame)
                .unwrap()
                .unwrap();
        assert_eq!(parsed_dest, dest);
        assert_eq!(&frame[range], payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn round_trip_associate_domain() {
        let dest = d("example.com", 53);
        let payload = b"abc";
        let frame = proto::uot_encode_associate_packet(&dest, payload).unwrap();

        let (parsed_dest, range, consumed) =
            proto::uot_try_parse_associate_packet(&frame)
                .unwrap()
                .unwrap();
        assert_eq!(parsed_dest, dest);
        assert_eq!(&frame[range], payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn parser_needs_more_bytes() {
        let dest = d("1.1.1.1", 53);
        let frame = proto::uot_encode_associate_packet(&dest, b"hello").unwrap();
        // Feed truncated input one byte at a time; should keep returning None
        // until the whole frame arrives.
        for i in 0..frame.len() {
            assert!(
                proto::uot_try_parse_associate_packet(&frame[..i])
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            proto::uot_try_parse_associate_packet(&frame)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn parser_rejects_bad_atyp() {
        let bad = vec![0x99u8, 0, 0, 0, 0];
        assert!(proto::uot_try_parse_associate_packet(&bad).is_err());
    }

    #[test]
    fn domain_too_long_rejected() {
        let long = "a".repeat(256);
        let dest = d(&long, 80);
        assert!(encode_request(false, &dest).is_err());
    }
}
