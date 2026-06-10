use std::io::Read;
use std::io::Write;
use std::io::{
    self,
};

use crate::inbound::Address;
use crate::inbound::Destination;

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum VlessCommand {
    Tcp = 0x01,
    Udp = 0x02,
}

impl TryFrom<u8> for VlessCommand {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            _ => Err(()),
        }
    }
}

/// Encodes a VLESS request header into `writer`.
pub fn encode_request<W: Write>(
    writer: &mut W, uuid: &[u8; 16], flow: Option<&str>, command: VlessCommand,
    dest: &Destination,
) -> io::Result<()> {
    // version
    writer.write_all(&[0x00])?;

    // UUID (16 raw bytes)
    writer.write_all(uuid)?;

    // addons
    match flow {
        Some(f) if !f.is_empty() => {
            let flow_bytes = f.as_bytes();
            let addons_len: u8 = 2u8
                .checked_add(flow_bytes.len() as u8)
                .expect("flow too long");
            writer.write_all(&[addons_len])?;
            // 0x0A = protobuf field 1, wire type 2 (length-delimited)
            writer.write_all(&[0x0A])?;
            writer.write_all(&[flow_bytes.len() as u8])?;
            writer.write_all(flow_bytes)?;
        },
        _ => {
            writer.write_all(&[0x00])?;
        },
    }

    // command
    writer.write_all(&[command as u8])?;

    // port (big-endian u16) first, then address (vmess addr format)
    writer.write_all(&dest.port.to_be_bytes())?;

    match &dest.address {
        Address::Ipv4(o) => {
            writer.write_all(&[0x01])?;
            writer.write_all(o)?;
        },
        Address::Domain(d) => {
            writer.write_all(&[0x02])?;
            let len: u8 = d.len() as u8;
            writer.write_all(&[len])?;
            writer.write_all(d.as_bytes())?;
        },
        Address::Ipv6(o) => {
            writer.write_all(&[0x03])?;
            writer.write_all(o)?;
        },
    }

    Ok(())
}

/// Reads the 1-byte VLESS response header.
///
/// Returns `Ok(())` when the byte is `0x00` (success).
/// Returns `Err` with `InvalidData` containing the unexpected byte otherwise.
pub fn decode_response<R: Read>(reader: &mut R) -> io::Result<()> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    if buf[0] == 0x00 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected response byte: {}", buf[0]),
        ))
    }
}

/// Convenience wrapper that encodes a VLESS request header into a `Vec<u8>`.
pub fn encode_request_bytes(
    uuid: &[u8; 16], flow: Option<&str>, command: VlessCommand,
    dest: &Destination,
) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_request(&mut buf, uuid, flow, command, dest)
        .expect("Vec writer is infallible");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_tcp_ipv4() {
        let uuid = [0u8; 16];
        let dest = Destination::new(Address::Ipv4([10, 0, 0, 1]), 443);
        let bytes = encode_request_bytes(&uuid, None, VlessCommand::Tcp, &dest);

        // version
        assert_eq!(bytes[0], 0x00);
        // uuid
        assert_eq!(&bytes[1..17], &[0u8; 16]);
        // addons_length = 0
        assert_eq!(bytes[17], 0x00);
        // command = TCP
        assert_eq!(bytes[18], 0x01);
        // port (big-endian) before address
        assert_eq!(&bytes[19..21], &443u16.to_be_bytes());
        // addr type = IPv4
        assert_eq!(bytes[21], 0x01);
        // addr bytes
        assert_eq!(&bytes[22..26], &[10, 0, 0, 1]);
    }

    #[test]
    fn test_encode_udp_domain() {
        let uuid = [0xabu8; 16];
        let dest = Destination::new(Address::Domain("example.com".into()), 53);

        let bytes = encode_request_bytes(&uuid, None, VlessCommand::Udp, &dest);

        // version
        assert_eq!(bytes[0], 0x00);
        // uuid
        assert_eq!(&bytes[1..17], &[0xabu8; 16]);
        // addons_length = 0
        // command = UDP
        assert_eq!(bytes[18], 0x02);
        // port (big-endian) before address
        assert_eq!(&bytes[19..21], &53u16.to_be_bytes());
        // addr type = Domain
        assert_eq!(bytes[21], 0x02);
        // domain length
        assert_eq!(bytes[22], 11);
        // domain bytes
        assert_eq!(&bytes[23..34], b"example.com");
    }

    #[test]
    fn test_encode_ipv6() {
        let uuid = [0u8; 16];
        let dest = Destination::new(
            Address::Ipv6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ]),
            8080,
        );

        let bytes = encode_request_bytes(&uuid, None, VlessCommand::Tcp, &dest);

        // version
        assert_eq!(bytes[0], 0x00);
        // addons_length = 0
        assert_eq!(bytes[17], 0x00);
        // command
        assert_eq!(bytes[18], 0x01);
        // port before address
        assert_eq!(&bytes[19..21], &8080u16.to_be_bytes());
        // addr type = IPv6
        assert_eq!(bytes[21], 0x03);
        // addr: 2001:db8::1
        assert_eq!(
            &bytes[22..38],
            &[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ][..]
        );
    }

    #[test]

    fn test_encode_with_flow() {
        let uuid = [0u8; 16];
        let dest = Destination::new(Address::Ipv4([192, 168, 1, 1]), 443);
        let flow = "xtls-rprx-vision";

        let bytes =
            encode_request_bytes(&uuid, Some(flow), VlessCommand::Tcp, &dest);

        // version
        assert_eq!(bytes[0], 0x00);
        // uuid
        assert_eq!(&bytes[1..17], &[0u8; 16]);
        // addons_length = 2 + flow.len() = 2 + 16 = 18
        assert_eq!(bytes[17], 18, "addons_length mismatch");
        // protobuf tag=1, wire_type=2
        assert_eq!(bytes[18], 0x0A);
        // flow byte length
        assert_eq!(bytes[19], 16);
        // flow bytes
        assert_eq!(&bytes[20..36], flow.as_bytes());
        // command
        assert_eq!(bytes[36], 0x01);
        // port before address
        assert_eq!(&bytes[37..39], &443u16.to_be_bytes());
        // addr type = IPv4
        assert_eq!(bytes[39], 0x01);
        // addr bytes
        assert_eq!(&bytes[40..44], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_encode_with_flow_empty_string() {
        let uuid = [0u8; 16];
        let dest = Destination::new(Address::Domain("test.local".into()), 80);

        // empty flow string should be treated like None
        let bytes =
            encode_request_bytes(&uuid, Some(""), VlessCommand::Tcp, &dest);

        assert_eq!(bytes[17], 0x00, "empty flow should set addons_length=0");
    }

    #[test]
    fn test_decode_success() {
        let mut buf: &[u8] = &[0x00];
        let result = decode_response(&mut buf);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_failure() {
        let mut buf: &[u8] = &[0x01];
        let result = decode_response(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let uuid = [0x42u8; 16];
        let dest = Destination::new(Address::Ipv4([172, 16, 0, 1]), 1234);

        // encode must not panic
        let bytes = encode_request_bytes(
            &uuid,
            Some("xtls-rprx-vision"),
            VlessCommand::Udp,
            &dest,
        );
        assert!(!bytes.is_empty());

        // decode a valid response
        let mut resp: &[u8] = &[0x00];
        assert!(decode_response(&mut resp).is_ok());
    }
}
