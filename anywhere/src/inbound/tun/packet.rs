//! Raw IP/TCP/UDP packet parsing and in-place header rewriting.
//!
//! All functions operate on raw byte buffers as read from / written to the TUN
//! device. etherparse is used for safe header field extraction; in-place
//! modification is done via direct byte manipulation at known offsets.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use etherparse::Ipv4Header;
use etherparse::Ipv6Header;
use etherparse::TcpHeader;
use etherparse::UdpHeader;

/// Classified IP packet type with extracted metadata.
#[derive(Debug)]
pub enum IpPacket {
    Tcp(IpPacketMeta),
    Udp(IpPacketMeta),
    Other,
}

/// Extracted addressing information from an IP packet.
#[derive(Debug, Clone)]
pub struct IpPacketMeta {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// Offset where the TCP/UDP header starts (after IP header).
    pub l4_offset: usize,
    /// Total packet length (IP header + L4 header + payload).
    pub total_len: usize,
}

/// Parse and classify a raw IP packet from TUN.
pub fn classify(buf: &[u8]) -> Option<IpPacket> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] >> 4 {
        4 => classify_ipv4(buf),
        6 => classify_ipv6(buf),
        _ => None,
    }
}

fn classify_ipv4(buf: &[u8]) -> Option<IpPacket> {
    let ip_hdr = Ipv4Header::from_slice(buf).ok()?.0;
    let l4_offset = ip_hdr.header_len() as usize;
    let total_len = ip_hdr.total_len as usize;

    let src_ip = IpAddr::V4(ip_hdr.source.into());
    let dst_ip = IpAddr::V4(ip_hdr.destination.into());

    match ip_hdr.protocol.0 {
        6 /* TCP */ => {
            let tcp = TcpHeader::from_slice(&buf[l4_offset..]).ok()?.0;
            Some(IpPacket::Tcp(IpPacketMeta {
                src_ip,
                dst_ip,
                src_port: tcp.source_port,
                dst_port: tcp.destination_port,
                l4_offset,
                total_len,
            }))
        }
        17 /* UDP */ => {
            let udp = UdpHeader::from_slice(&buf[l4_offset..]).ok()?.0;
            Some(IpPacket::Udp(IpPacketMeta {
                src_ip,
                dst_ip,
                src_port: udp.source_port,
                dst_port: udp.destination_port,
                l4_offset,
                total_len,
            }))
        }
        _ => Some(IpPacket::Other),
    }
}

fn classify_ipv6(buf: &[u8]) -> Option<IpPacket> {
    let ip_hdr = Ipv6Header::from_slice(buf).ok()?.0;
    let l4_offset = 40; // IPv6 fixed header is 40 bytes
    let total_len = (ip_hdr.payload_length as usize) + 40;

    let src_ip = IpAddr::V6(ip_hdr.source.into());
    let dst_ip = IpAddr::V6(ip_hdr.destination.into());

    match ip_hdr.next_header.0 {
        6 /* TCP */ => {
            let tcp = TcpHeader::from_slice(&buf[l4_offset..]).ok()?.0;
            Some(IpPacket::Tcp(IpPacketMeta {
                src_ip,
                dst_ip,
                src_port: tcp.source_port,
                dst_port: tcp.destination_port,
                l4_offset,
                total_len,
            }))
        }
        17 /* UDP */ => {
            let udp = UdpHeader::from_slice(&buf[l4_offset..]).ok()?.0;
            Some(IpPacket::Udp(IpPacketMeta {
                src_ip,
                dst_ip,
                src_port: udp.source_port,
                dst_port: udp.destination_port,
                l4_offset,
                total_len,
            }))
        }
        _ => Some(IpPacket::Other),
    }
}

/// Check whether the TCP flags indicate a SYN (not SYN-ACK).
pub fn is_syn_only(meta: &IpPacketMeta, buf: &[u8]) -> bool {
    let flags = buf[meta.l4_offset + 13];
    (flags & 0x02) != 0 && (flags & 0x10) == 0 // SYN set, ACK not set
}

/// Rewrite source and destination IP:port of a TCP packet in-place.
///
/// Updates IP addresses at bytes 12-19 (IPv4) and TCP ports at l4_offset,
/// then recalculates both checksums.
pub fn rewrite_tcp_ipv4(
    buf: &mut [u8], meta: &IpPacketMeta, new_src_ip: Ipv4Addr, new_src_port: u16,
    new_dst_ip: Ipv4Addr, new_dst_port: u16,
) {
    // Rewrite IP addresses (bytes 12-19 in IPv4 header).
    buf[12..16].copy_from_slice(&new_src_ip.octets());
    buf[16..20].copy_from_slice(&new_dst_ip.octets());

    // Rewrite TCP ports.
    let off = meta.l4_offset;
    buf[off..off + 2].copy_from_slice(&new_src_port.to_be_bytes());
    buf[off + 2..off + 4].copy_from_slice(&new_dst_port.to_be_bytes());

    // Zero out checksums before recomputing.
    buf[10..12].copy_from_slice(&[0, 0]); // IP checksum
    buf[off + 16..off + 18].copy_from_slice(&[0, 0]); // TCP checksum

    // Compute IP header checksum.
    let ip_csum = internet_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // Compute TCP checksum with IPv4 pseudo-header.
    let tcp_len = meta.total_len - meta.l4_offset;
    let tcp_csum = tcp_checksum_ipv4(
        &new_src_ip.octets(),
        &new_dst_ip.octets(),
        &buf[off..off + tcp_len],
    );
    buf[off + 16..off + 18].copy_from_slice(&tcp_csum.to_be_bytes());
}

/// Rewrite source and destination IP:port of a TCP packet in-place (IPv6).
pub fn rewrite_tcp_ipv6(
    buf: &mut [u8], meta: &IpPacketMeta, new_src_ip: Ipv6Addr, new_src_port: u16,
    new_dst_ip: Ipv6Addr, new_dst_port: u16,
) {
    // Rewrite IP addresses (bytes 8-39 in IPv6 header).
    buf[8..24].copy_from_slice(&new_src_ip.octets());
    buf[24..40].copy_from_slice(&new_dst_ip.octets());

    let off = meta.l4_offset;
    buf[off..off + 2].copy_from_slice(&new_src_port.to_be_bytes());
    buf[off + 2..off + 4].copy_from_slice(&new_dst_port.to_be_bytes());

    // Zero TCP checksum.
    buf[off + 16..off + 18].copy_from_slice(&[0, 0]);

    // IPv6 has no header checksum. Only TCP checksum needed.
    let tcp_len = meta.total_len - meta.l4_offset;
    let tcp_csum = tcp_checksum_ipv6(
        &new_src_ip.octets(),
        &new_dst_ip.octets(),
        &buf[off..off + tcp_len],
    );
    buf[off + 16..off + 18].copy_from_slice(&tcp_csum.to_be_bytes());
}

/// Build a raw IPv4 + UDP packet for sending a response back through TUN.
pub fn build_udp_response_ipv4(
    src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut buf = vec![0u8; total_len];

    // IPv4 header (20 bytes).
    buf[0] = 0x45; // Version=4, IHL=5
    buf[1] = 0; // DSCP + ECN
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..8].copy_from_slice(&[0, 0, 0x40, 0]); // ID=0, flags=0x40 (DF), frag_offset=0
    buf[8] = 64; // TTL
    buf[9] = 17; // UDP protocol
    buf[10..12].copy_from_slice(&[0, 0]); // checksum (zeroed)
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    // UDP header (8 bytes).
    let udp_off = 20;
    buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[udp_off + 4..udp_off + 6]
        .copy_from_slice(&(udp_len as u16).to_be_bytes());
    buf[udp_off + 6..udp_off + 8].copy_from_slice(&[0, 0]); // checksum (zero, optional for IPv4)

    // Payload.
    buf[udp_off + 8..].copy_from_slice(payload);

    // IP checksum.
    let ip_csum = internet_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    buf
}

/// Build a raw IPv6 + UDP packet for sending a response back through TUN.
pub fn build_udp_response_ipv6(
    src_ip: Ipv6Addr, src_port: u16, dst_ip: Ipv6Addr, dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 40 + udp_len;
    let mut buf = vec![0u8; total_len];

    // IPv6 header (40 bytes).
    buf[0..4].copy_from_slice(&[0x60, 0, 0, 0]); // Version=6, traffic class, flow label
    buf[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes()); // payload length
    buf[6..8].copy_from_slice(&[17, 64]); // next header=UDP, hop limit=64
    buf[8..24].copy_from_slice(&src_ip.octets());
    buf[24..40].copy_from_slice(&dst_ip.octets());

    // UDP header (8 bytes).
    let udp_off = 40;
    buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[udp_off + 4..udp_off + 6]
        .copy_from_slice(&(udp_len as u16).to_be_bytes());
    buf[udp_off + 6..udp_off + 8].copy_from_slice(&[0, 0]);

    // Payload.
    buf[udp_off + 8..].copy_from_slice(payload);

    // IPv6 has no header checksum. Compute UDP checksum with pseudo-header.
    let udp_csum =
        udp_checksum_ipv6(&src_ip.octets(), &dst_ip.octets(), &buf[udp_off..]);
    buf[udp_off + 6..udp_off + 8].copy_from_slice(&udp_csum.to_be_bytes());

    buf
}

/// Build an ICMPv4 destination-unreachable (port unreachable) packet to send
/// back through TUN, telling the client a UDP flow was rejected.
///
/// `orig_src`/`orig_dst` are the original UDP endpoints (client -> server).
/// The ICMP is sourced from `orig_dst` (the "server" that refused the port)
/// and addressed to `orig_src` (the client), embedding the original IP+UDP
/// header so the client stack can match it to the flow and fall back to TCP.
pub fn build_icmp_port_unreachable_ipv4(
    orig_src_ip: Ipv4Addr, orig_src_port: u16, orig_dst_ip: Ipv4Addr,
    orig_dst_port: u16,
) -> Vec<u8> {
    // outer IPv4(20) + ICMP(8) + embedded IPv4(20) + embedded UDP(8) = 56
    let mut buf = vec![0u8; 56];

    // Outer IPv4 header.
    buf[0] = 0x45;
    buf[2..4].copy_from_slice(&56u16.to_be_bytes());
    buf[8] = 64; // TTL
    buf[9] = 1; // protocol = ICMP
    buf[12..16].copy_from_slice(&orig_dst_ip.octets()); // src = server
    buf[16..20].copy_from_slice(&orig_src_ip.octets()); // dst = client

    // ICMP header: type=3 (dest unreachable), code=3 (port unreachable).
    let icmp_off = 20;
    buf[icmp_off] = 3;
    buf[icmp_off + 1] = 3;

    // Embedded original IPv4 header.
    let emb_off = icmp_off + 8; // 28
    buf[emb_off] = 0x45;
    buf[emb_off + 2..emb_off + 4].copy_from_slice(&28u16.to_be_bytes());
    buf[emb_off + 8] = 64;
    buf[emb_off + 9] = 17; // protocol = UDP
    buf[emb_off + 12..emb_off + 16].copy_from_slice(&orig_src_ip.octets());
    buf[emb_off + 16..emb_off + 20].copy_from_slice(&orig_dst_ip.octets());

    // Embedded original UDP header.
    let eudp_off = emb_off + 20; // 48
    buf[eudp_off..eudp_off + 2].copy_from_slice(&orig_src_port.to_be_bytes());
    buf[eudp_off + 2..eudp_off + 4].copy_from_slice(&orig_dst_port.to_be_bytes());
    buf[eudp_off + 4..eudp_off + 6].copy_from_slice(&8u16.to_be_bytes());

    // Checksums.
    let emb_csum = internet_checksum(&buf[emb_off..emb_off + 20]);
    buf[emb_off + 10..emb_off + 12].copy_from_slice(&emb_csum.to_be_bytes());
    let icmp_csum = internet_checksum(&buf[icmp_off..]);
    buf[icmp_off + 2..icmp_off + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    let ip_csum = internet_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    buf
}

/// Build an ICMPv6 destination-unreachable (port unreachable) packet.
/// See [`build_icmp_port_unreachable_ipv4`] for semantics.
pub fn build_icmp_port_unreachable_ipv6(
    orig_src_ip: Ipv6Addr, orig_src_port: u16, orig_dst_ip: Ipv6Addr,
    orig_dst_port: u16,
) -> Vec<u8> {
    // outer IPv6(40) + ICMPv6(8) + embedded IPv6(40) + embedded UDP(8) = 96
    let icmpv6_len: u32 = 8 + 40 + 8; // 56
    let mut buf = vec![0u8; 40 + icmpv6_len as usize];

    // Outer IPv6 header.
    buf[0..4].copy_from_slice(&[0x60, 0, 0, 0]);
    buf[4..6].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
    buf[6] = 58; // next header = ICMPv6
    buf[7] = 64; // hop limit
    buf[8..24].copy_from_slice(&orig_dst_ip.octets()); // src = server
    buf[24..40].copy_from_slice(&orig_src_ip.octets()); // dst = client

    // ICMPv6 header: type=1 (dest unreachable), code=4 (port unreachable).
    let icmp_off = 40;
    buf[icmp_off] = 1;
    buf[icmp_off + 1] = 4;

    // Embedded original IPv6 header.
    let emb_off = icmp_off + 8; // 48
    buf[emb_off..emb_off + 4].copy_from_slice(&[0x60, 0, 0, 0]);
    buf[emb_off + 4..emb_off + 6].copy_from_slice(&8u16.to_be_bytes()); // payload len (UDP only)
    buf[emb_off + 6] = 17; // next header = UDP
    buf[emb_off + 7] = 64;
    buf[emb_off + 8..emb_off + 24].copy_from_slice(&orig_src_ip.octets());
    buf[emb_off + 24..emb_off + 40].copy_from_slice(&orig_dst_ip.octets());

    // Embedded original UDP header.
    let eudp_off = emb_off + 40; // 88
    buf[eudp_off..eudp_off + 2].copy_from_slice(&orig_src_port.to_be_bytes());
    buf[eudp_off + 2..eudp_off + 4].copy_from_slice(&orig_dst_port.to_be_bytes());
    buf[eudp_off + 4..eudp_off + 6].copy_from_slice(&8u16.to_be_bytes());

    // ICMPv6 checksum = pseudo-header + ICMPv6 message.
    let mut acc = CsumAccum::new();
    acc.feed(&orig_dst_ip.octets()); // src of outer = server
    acc.feed(&orig_src_ip.octets()); // dst of outer = client
    acc.feed(&icmpv6_len.to_be_bytes());
    acc.feed(&[0, 0, 0, 58]); // zero + next header = ICMPv6
    acc.feed(&buf[icmp_off..]);
    let icmp_csum = acc.finalize();
    buf[icmp_off + 2..icmp_off + 4].copy_from_slice(&icmp_csum.to_be_bytes());

    buf
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

/// Internet checksum (RFC 1071) over the given bytes.
/// The checksum field itself (if present) must already be zeroed.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }
    // Fold 32-bit → 16-bit one's complement
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Streaming checksum accumulator — avoids allocating a Vec to concatenate
/// a pseudo-header with payload. Call `feed()` for each slice in order,
/// then `finalize()` to get the result.
struct CsumAccum {
    sum: u32,
    odd: bool,
    pending: u8,
}

impl CsumAccum {
    fn new() -> Self {
        Self {
            sum: 0,
            odd: false,
            pending: 0,
        }
    }

    fn feed(&mut self, data: &[u8]) {
        if self.odd {
            // Prepend the pending byte from the previous feed.
            let word = u16::from_be_bytes([self.pending, data[0]]);
            self.sum = self.sum.wrapping_add(word as u32);
            for chunk in data[1..].chunks(2) {
                let word = if chunk.len() == 2 {
                    u16::from_be_bytes([chunk[0], chunk[1]])
                } else {
                    self.odd = true;
                    self.pending = chunk[0];
                    continue;
                };
                self.sum = self.sum.wrapping_add(word as u32);
            }
            self.odd = false;
        } else {
            for chunk in data.chunks(2) {
                let word = if chunk.len() == 2 {
                    u16::from_be_bytes([chunk[0], chunk[1]])
                } else {
                    self.odd = true;
                    self.pending = chunk[0];
                    continue;
                };
                self.sum = self.sum.wrapping_add(word as u32);
            }
        }
    }

    fn finalize(self) -> u16 {
        let mut sum = self.sum;
        if self.odd {
            let word = u16::from_be_bytes([self.pending, 0]);
            sum = sum.wrapping_add(word as u32);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// TCP checksum with IPv4 pseudo-header (RFC 793) — no heap allocation.
fn tcp_checksum_ipv4(
    src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8],
) -> u16 {
    let tcp_len = tcp_segment.len();
    let mut acc = CsumAccum::new();
    acc.feed(src_ip);
    acc.feed(dst_ip);
    acc.feed(&[0, 6]); // zero pad + protocol = TCP
    acc.feed(&(tcp_len as u16).to_be_bytes());
    acc.feed(tcp_segment);
    acc.finalize()
}

/// TCP checksum with IPv6 pseudo-header (RFC 2460) — no heap allocation.
fn tcp_checksum_ipv6(
    src_ip: &[u8; 16], dst_ip: &[u8; 16], tcp_segment: &[u8],
) -> u16 {
    let tcp_len = tcp_segment.len();
    let mut acc = CsumAccum::new();
    acc.feed(src_ip);
    acc.feed(dst_ip);
    acc.feed(&(tcp_len as u32).to_be_bytes());
    acc.feed(&[0, 0, 0, 6]); // protocol = TCP
    acc.feed(tcp_segment);
    acc.finalize()
}

/// UDP checksum with IPv6 pseudo-header (RFC 2460) — no heap allocation.
fn udp_checksum_ipv6(
    src_ip: &[u8; 16], dst_ip: &[u8; 16], udp_datagram: &[u8],
) -> u16 {
    let udp_len = udp_datagram.len();
    let mut acc = CsumAccum::new();
    acc.feed(src_ip);
    acc.feed(dst_ip);
    acc.feed(&(udp_len as u32).to_be_bytes());
    acc.feed(&[0, 0, 0, 17]); // protocol = UDP
    acc.feed(udp_datagram);
    acc.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internet_checksum() {
        // Known good: a zeroed 20-byte IPv4 header should produce 0xFFFF
        let data = [0u8; 20];
        assert_eq!(internet_checksum(&data), 0xFFFF);
    }

    #[test]
    fn test_classify_ipv4_tcp() {
        // Build a minimal valid IPv4 + TCP packet
        let mut pkt = vec![0u8; 54]; // 20 IP + 20 TCP + 14 padding
        pkt[0] = 0x45; // v4, IHL=5
        pkt[2..4].copy_from_slice(&(54u16).to_be_bytes()); // total length
        pkt[8] = 64; // TTL
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]); // src = 192.168.1.1
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst = 10.0.0.1
        pkt[20..22].copy_from_slice(&(12345u16).to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&(80u16).to_be_bytes()); // dst port
        pkt[32] = 0x50; // data_offset=5 (20 bytes), no reserved bits
        pkt[33] = 0x02; // SYN flag

        let result = classify(&pkt);
        assert!(result.is_some());
        match result.unwrap() {
            IpPacket::Tcp(meta) => {
                assert_eq!(
                    meta.src_ip,
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
                );
                assert_eq!(meta.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                assert_eq!(meta.src_port, 12345);
                assert_eq!(meta.dst_port, 80);
                assert!(is_syn_only(&meta, &pkt));
            },
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn test_icmp_port_unreachable_ipv4() {
        let app = Ipv4Addr::new(192, 168, 1, 100);
        let srv = Ipv4Addr::new(142, 250, 10, 46);
        let pkt = build_icmp_port_unreachable_ipv4(app, 54321, srv, 443);

        // Layout: outer IPv4(20) + ICMP(8) + embedded IPv4(20) + embedded UDP(8).
        assert_eq!(pkt.len(), 56);

        // Outer IP: src = server (reporting unreachable), dst = client, proto = ICMP.
        assert_eq!(&pkt[12..16], &srv.octets());
        assert_eq!(&pkt[16..20], &app.octets());
        assert_eq!(pkt[9], 1);

        // ICMP type=3 (dest unreachable), code=3 (port unreachable).
        assert_eq!(pkt[20], 3);
        assert_eq!(pkt[21], 3);

        // ICMP checksum is valid (recompute with field zeroed -> matches stored).
        let mut icmp = pkt[20..].to_vec();
        icmp[2..4].copy_from_slice(&[0, 0]);
        assert_eq!(
            internet_checksum(&icmp),
            u16::from_be_bytes([pkt[22], pkt[23]])
        );

        // Outer IP header checksum is valid.
        let mut ip = pkt[..20].to_vec();
        ip[10..12].copy_from_slice(&[0, 0]);
        assert_eq!(
            internet_checksum(&ip),
            u16::from_be_bytes([pkt[10], pkt[11]])
        );

        // Embedded original: src = client, dst = server, proto = UDP, ports.
        let emb = 28;
        assert_eq!(&pkt[emb + 12..emb + 16], &app.octets());
        assert_eq!(&pkt[emb + 16..emb + 20], &srv.octets());
        assert_eq!(pkt[emb + 9], 17);
        let eudp = emb + 20;
        assert_eq!(u16::from_be_bytes([pkt[eudp], pkt[eudp + 1]]), 54321);
        assert_eq!(u16::from_be_bytes([pkt[eudp + 2], pkt[eudp + 3]]), 443);
    }

    #[test]
    fn test_icmp_port_unreachable_ipv6() {
        let app = Ipv6Addr::LOCALHOST;
        let srv = "2001:4860:4860::8888".parse().unwrap();
        let pkt = build_icmp_port_unreachable_ipv6(app, 54321, srv, 443);

        // Layout: outer IPv6(40) + ICMPv6(8) + embedded IPv6(40) + embedded UDP(8).
        assert_eq!(pkt.len(), 96);
        // ICMPv6 type=1 (dest unreachable), code=4 (port unreachable).
        assert_eq!(pkt[40], 1);
        assert_eq!(pkt[41], 4);
        // Outer IPv6 src = server, dst = client.
        assert_eq!(&pkt[8..24], &srv.octets());
        assert_eq!(&pkt[24..40], &app.octets());
        // Embedded UDP ports.
        let eudp = 48 + 40;
        assert_eq!(u16::from_be_bytes([pkt[eudp], pkt[eudp + 1]]), 54321);
        assert_eq!(u16::from_be_bytes([pkt[eudp + 2], pkt[eudp + 3]]), 443);
    }
}
