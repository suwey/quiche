//! DNS wire-format helpers.
//!
//! Pure functions for parsing and building DNS messages: query parsing,
//! fake-IP A responses, empty NOERROR responses, REFUSED responses, and
//! transaction-ID patching. No state, no I/O.

/// Parsed question from a DNS query.
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
}

/// Build a fake A-record response that answers `query` with `ip`.
pub fn build_fake_a_response(
    query: &[u8], ip: std::net::Ipv4Addr,
) -> Option<Vec<u8>> {
    let q_end = dns_question_end(query)?;
    let mut r = Vec::with_capacity(q_end + 16);
    r.extend_from_slice(&query[..2]);
    r.extend_from_slice(&[0x81, 0x80]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x00]);
    r.extend_from_slice(&[0x00, 0x00]);
    r.extend_from_slice(&query[12..q_end]);
    r.extend_from_slice(&[0xC0, 0x0C]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&60u32.to_be_bytes());
    r.extend_from_slice(&[0x00, 0x04]);
    r.extend_from_slice(&ip.octets());
    Some(r)
}

/// Return the byte offset just past the question section (offset 12 + name +
/// QTYPE + QCLASS). Used to know where the question ends for response
/// construction.
fn dns_question_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 12 {
        return None;
    }
    let mut pos = 12usize;
    loop {
        let len = *buf.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 || pos + len > buf.len() {
            return None;
        }
        pos += len;
    }
    if pos + 4 > buf.len() {
        return None;
    }
    Some(pos + 4)
}

/// Extract the transaction ID from a DNS message.
pub fn txn_id(query: &[u8]) -> u16 {
    if query.len() < 2 {
        return 0;
    }
    u16::from_be_bytes([query[0], query[1]])
}

/// Overwrite the transaction ID of a (possibly cached) response to match
/// the caller's query ID.
pub fn apply_txn_id(response: &[u8], id: u16) -> Vec<u8> {
    let mut v = response.to_vec();
    if v.len() >= 2 {
        let b = id.to_be_bytes();
        v[0] = b[0];
        v[1] = b[1];
    }
    v
}

/// Parse the first question from a DNS query. Returns `None` on malformed
/// input or if the message is a response (QR bit set).
pub fn parse_dns_query(buf: &[u8]) -> Option<DnsQuestion> {
    if buf.len() < 12 {
        return None;
    }
    // QR bit (high bit of byte 2) must be 0 for a query.
    if buf[2] & 0x80 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Compression pointers (top two bits set) shouldn't appear in
        // the question section of a normal query — reject.
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[pos..pos + len]).to_string());
        pos += len;
    }
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    Some(DnsQuestion {
        name: labels.join("."),
        qtype,
    })
}

/// Build an empty DNS response (NOERROR, 0 answers) from a query. Used to
/// short-circuit AAAA queries.
pub fn build_empty_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut v = query.to_vec();
    // Set QR=1, RA=1; clear AA, TC, RCODE.
    v[2] = (v[2] & 0x78) | 0x80; // keep OPCODE bits 3-6, set QR
    v[3] = 0x80; // RA=1, RCODE=0
    // ANCOUNT, NSCOUNT, ARCOUNT all zero.
    v[6] = 0;
    v[7] = 0;
    v[8] = 0;
    v[9] = 0;
    v[10] = 0;
    v[11] = 0;
    // Trim anything past the question section.
    let mut pos = 12usize;
    loop {
        if pos >= v.len() {
            return None;
        }
        let len = v[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1 + len;
        if pos > v.len() {
            return None;
        }
    }
    if pos + 4 > v.len() {
        return None;
    }
    v.truncate(pos + 4); // include QTYPE + QCLASS
    Some(v)
}

/// Build a REFUSED (RCODE=5) response from a query. Used when the matched
/// outbound doesn't exist, so the client gets an immediate error instead of
/// timing out.
pub fn build_refused_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut v = query.to_vec();
    v[2] = (v[2] & 0x78) | 0x80; // QR=1, keep OPCODE
    v[3] = 0x85; // AA=0, TC=0, RD=copy, RA=1, RCODE=5 (REFUSED)
    v[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT, NSCOUNT, ARCOUNT = 0
    let mut pos = 12usize;
    loop {
        if pos >= v.len() {
            return None;
        }
        let len = v[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1 + len;
        if pos > v.len() {
            return None;
        }
    }
    if pos + 4 > v.len() {
        return None;
    }
    v.truncate(pos + 4);
    Some(v)
}

/// Build a minimal A-record DNS query (txn id 0, RD=1) for `name`. Used for
/// bootstrap resolution of DoH hostnames via plain UDP.
pub fn build_a_query(name: &str) -> Vec<u8> {
    let mut v = vec![0u8; 12];
    v[2] = 0x01; v[3] = 0x00; // RD=1
    v[4] = 0x00; v[5] = 0x01; // QDCOUNT = 1
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0); // root label
    v.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    v.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    v
}

/// Extract the first A record IP from a raw DNS response.
pub fn first_a_record(resp: &[u8]) -> Option<std::net::IpAddr> {
    crate::inbound::tun::reverse_dns::parse_a_records(resp)
        .into_iter()
        .next()
        .map(|(ip, _)| std::net::IpAddr::V4(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v[0] = 0xAB;
        v[1] = 0xCD; // txn id
        v[2] = 0x01;
        v[3] = 0x00; // standard query, RD=1
        v[4] = 0x00;
        v[5] = 0x01; // QDCOUNT = 1
        for label in name.split('.') {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0); // root label
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&[0u8, 1u8]); // QCLASS = IN
        v
    }

    #[test]
    fn parse_a_query() {
        let q = make_query("www.google.com", 1);
        let parsed = parse_dns_query(&q).unwrap();
        assert_eq!(parsed.name, "www.google.com");
        assert_eq!(parsed.qtype, 1);
    }

    #[test]
    fn parse_aaaa_query() {
        let q = make_query("example.org", 28);
        let parsed = parse_dns_query(&q).unwrap();
        assert_eq!(parsed.name, "example.org");
        assert_eq!(parsed.qtype, 28);
    }

    #[test]
    fn parse_rejects_response_packet() {
        let mut q = make_query("a.b", 1);
        q[2] |= 0x80; // set QR=1 → not a query
        assert!(parse_dns_query(&q).is_none());
    }

    #[test]
    fn parse_rejects_truncated() {
        let q = make_query("a.b", 1);
        assert!(parse_dns_query(&q[..10]).is_none());
    }

    #[test]
    fn empty_response_round_trips() {
        let q = make_query("foo.example", 28);
        let r = build_empty_response(&q).unwrap();
        assert_eq!(&r[..2], &[0xAB, 0xCD]);
        assert!(r[2] & 0x80 != 0);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0);
        let parsed = parse_dns_query(&q).unwrap();
        assert_eq!(parsed.name, "foo.example");
    }

    #[test]
    fn apply_txn_id_overwrites() {
        let cached = vec![0u8, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let restored = apply_txn_id(&cached, 0x1234);
        assert_eq!(&restored[..2], &[0x12, 0x34]);
    }
}
