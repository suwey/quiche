// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

use crate::inbound::Address;
use crate::inbound::Destination;

/// Build VLESS request header for TCP (cmd=1) or UDP (cmd=2).
///
/// Format: version(1B=0) + UUID(16B) + addon_len(1B=0) + cmd(1B) +
///         port(2B BE) + addr_type(1B) + address(variable)
///
/// Address types:
/// - 1 = IPv4 (4 bytes)
/// - 2 = Domain (1-byte length + N bytes UTF-8)
/// - 3 = IPv6 (16 bytes)
pub fn build_vless_header(
    uuid: &[u8; 16], dest: &Destination, is_udp: bool,
) -> Vec<u8> {
    let cmd: u8 = if is_udp { 0x02 } else { 0x01 };
    let mut buf =
        Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + max_addr_len(&dest.address));

    // version
    buf.push(0x00);
    // UUID
    buf.extend_from_slice(uuid);
    // addon length (no addons)
    buf.push(0x00);
    // command
    buf.push(cmd);
    // port (big-endian)
    buf.extend_from_slice(&dest.port.to_be_bytes());

    match &dest.address {
        Address::Ipv4(o) => {
            buf.push(0x01);
            buf.extend_from_slice(o);
        },
        Address::Domain(d) => {
            buf.push(0x02);
            buf.push(d.len() as u8);
            buf.extend_from_slice(d.as_bytes());
        },
        Address::Ipv6(o) => {
            buf.push(0x03);
            buf.extend_from_slice(o);
        },
    }

    buf
}

/// Upper bound on address bytes for pre-allocation.
fn max_addr_len(addr: &Address) -> usize {
    match addr {
        Address::Ipv4(_) => 4,
        Address::Domain(d) => 1 + d.len(),
        Address::Ipv6(_) => 16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_ipv4() {
        let uuid = [0x01u8; 16];
        let dest = Destination::new(Address::Ipv4([192, 168, 1, 1]), 443);
        let hdr = build_vless_header(&uuid, &dest, false);

        // version
        assert_eq!(hdr[0], 0x00);
        // uuid
        assert_eq!(&hdr[1..17], &uuid);
        // addon_len
        assert_eq!(hdr[17], 0x00);
        // cmd = TCP
        assert_eq!(hdr[18], 0x01);
        // port = 443 (0x01BB)
        assert_eq!(hdr[19], 0x01);
        assert_eq!(hdr[20], 0xBB);
        // addr_type = IPv4
        assert_eq!(hdr[21], 0x01);
        // address
        assert_eq!(&hdr[22..26], &[192, 168, 1, 1]);
        assert_eq!(hdr.len(), 26);
    }

    #[test]
    fn test_udp_ipv4() {
        let uuid = [0x02u8; 16];
        let dest = Destination::new(Address::Ipv4([10, 0, 0, 1]), 53);
        let hdr = build_vless_header(&uuid, &dest, true);

        assert_eq!(hdr[0], 0x00);
        assert_eq!(&hdr[1..17], &uuid);
        assert_eq!(hdr[17], 0x00);
        // cmd = UDP
        assert_eq!(hdr[18], 0x02);
        // port = 53
        assert_eq!(hdr[19], 0x00);
        assert_eq!(hdr[20], 0x35);
        // addr_type = IPv4
        assert_eq!(hdr[21], 0x01);
        assert_eq!(&hdr[22..26], &[10, 0, 0, 1]);
        assert_eq!(hdr.len(), 26);
    }

    #[test]
    fn test_tcp_domain() {
        let uuid = [0x03u8; 16];
        let dest = Destination::new(Address::Domain("example.com".into()), 80);
        let hdr = build_vless_header(&uuid, &dest, false);

        assert_eq!(hdr[0], 0x00);
        assert_eq!(&hdr[1..17], &uuid);
        assert_eq!(hdr[17], 0x00);
        assert_eq!(hdr[18], 0x01);
        // port = 80
        assert_eq!(hdr[19], 0x00);
        assert_eq!(hdr[20], 0x50);
        // addr_type = Domain
        assert_eq!(hdr[21], 0x02);
        // domain length
        assert_eq!(hdr[22], 11);
        // domain
        assert_eq!(&hdr[23..34], b"example.com");
        assert_eq!(hdr.len(), 34);
    }

    #[test]
    fn test_tcp_ipv6() {
        let uuid = [0x04u8; 16];
        let addr = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let dest = Destination::new(Address::Ipv6(addr), 443);
        let hdr = build_vless_header(&uuid, &dest, false);

        assert_eq!(hdr[0], 0x00);
        assert_eq!(&hdr[1..17], &uuid);
        assert_eq!(hdr[17], 0x00);
        assert_eq!(hdr[18], 0x01);
        // port = 443
        assert_eq!(hdr[19], 0x01);
        assert_eq!(hdr[20], 0xBB);
        // addr_type = IPv6
        assert_eq!(hdr[21], 0x03);
        // address
        assert_eq!(&hdr[22..38], &addr);
        assert_eq!(hdr.len(), 38);
    }

    #[test]
    fn test_tcp_vs_udp_cmd_byte() {
        let uuid = [0x00u8; 16];
        let dest = Destination::new(Address::Ipv4([1, 2, 3, 4]), 1234);

        let tcp_hdr = build_vless_header(&uuid, &dest, false);
        let udp_hdr = build_vless_header(&uuid, &dest, true);

        // Everything before cmd byte should be identical
        assert_eq!(&tcp_hdr[..18], &udp_hdr[..18]);
        // Everything after cmd byte should be identical
        assert_eq!(&tcp_hdr[19..], &udp_hdr[19..]);
        // Only cmd byte differs
        assert_eq!(tcp_hdr[18], 0x01);
        assert_eq!(udp_hdr[18], 0x02);
    }
}
