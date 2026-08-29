// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Mless frame encoding: QUIC-style varints and stream frames.

use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;

pub const FLAG_FIRST: u8 = 0x80;
pub const FLAG_CLOSE: u8 = 0x40;
pub const FLAG_DATA: u8 = 0x00;

/// Decode a QUIC-style variable-length integer starting at `offset`.
///
/// Top two bits encode the width:
/// - `00` → 1 byte,  value range 0..63
/// - `01` → 2 bytes, value range 0..16383
/// - `10` → 4 bytes, value range 0..1073741823
/// - `11` → 8 bytes, value range 0..2^62-1
pub fn decode_varint(data: &[u8], offset: usize) -> Result<(u64, usize)> {
    let b = *data.get(offset).ok_or_else(|| {
        Error::new(ErrorKind::UnexpectedEof, "varint: unexpected end of data")
    })?;
    let tag = b >> 6;
    match tag {
        0 => Ok((u64::from(b & 0x3f), 1)),
        1 => {
            if offset + 1 >= data.len() {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "varint: unexpected end of data",
                ));
            }
            let value = (u64::from(b & 0x3f) << 8) | u64::from(data[offset + 1]);
            Ok((value, 2))
        },
        2 => {
            if offset + 3 >= data.len() {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "varint: unexpected end of data",
                ));
            }
            let value = (u64::from(b & 0x3f) << 24)
                | (u64::from(data[offset + 1]) << 16)
                | (u64::from(data[offset + 2]) << 8)
                | u64::from(data[offset + 3]);
            Ok((value, 4))
        },
        3 => {
            if offset + 7 >= data.len() {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "varint: unexpected end of data",
                ));
            }
            let value = (u64::from(b & 0x3f) << 56)
                | (u64::from(data[offset + 1]) << 48)
                | (u64::from(data[offset + 2]) << 40)
                | (u64::from(data[offset + 3]) << 32)
                | (u64::from(data[offset + 4]) << 24)
                | (u64::from(data[offset + 5]) << 16)
                | (u64::from(data[offset + 6]) << 8)
                | u64::from(data[offset + 7]);
            Ok((value, 8))
        },
        _ => Err(Error::new(
            ErrorKind::InvalidData,
            "varint: reserved top-two bits",
        )),
    }
}

/// Encode a `u64` as a QUIC-style variable-length integer.
pub fn encode_varint(value: u64) -> Vec<u8> {
    if value <= 63 {
        vec![value as u8]
    } else if value <= 16383 {
        let high = (value >> 8) as u8 | 0x40;
        let low = (value & 0xff) as u8;
        vec![high, low]
    } else if value <= 1_073_741_823 {
        let b0 = (value >> 24) as u8 | 0x80;
        let b1 = (value >> 16) as u8;
        let b2 = (value >> 8) as u8;
        let b3 = value as u8;
        vec![b0, b1, b2, b3]
    } else {
        let b0 = (value >> 56) as u8 | 0xc0;
        let b1 = (value >> 48) as u8;
        let b2 = (value >> 40) as u8;
        let b3 = (value >> 32) as u8;
        let b4 = (value >> 24) as u8;
        let b5 = (value >> 16) as u8;
        let b6 = (value >> 8) as u8;
        let b7 = value as u8;
        vec![b0, b1, b2, b3, b4, b5, b6, b7]
    }
}

/// Encode a Mless frame: varint(stream_id) + flags + varint(payload_len) +
/// payload.
///
/// The payload length field allows multiple frames to be concatenated
/// in a single WebSocket message (the server's Grain sender batches
/// frames for efficiency).
pub fn encode_frame(stream_id: u64, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = encode_varint(stream_id);
    buf.push(flags);
    buf.extend_from_slice(&encode_varint(payload.len() as u64));
    buf.extend_from_slice(payload);
    buf
}

/// Parse one Mless frame from a buffer.
///
/// Returns `(stream_id, flags, payload_slice, bytes_consumed)` on success,
/// or `None` if the buffer is too short or contains an invalid varint.
///
/// The payload length field allows correct parsing of concatenated
/// frames within a single WebSocket message.
pub fn decode_frame(data: &[u8]) -> Option<(u64, u8, &[u8], usize)> {
    let (stream_id, sid_len) = decode_varint(data, 0).ok()?;
    let flags = *data.get(sid_len)?;
    let len_start = sid_len + 1;
    let (payload_len, len_field_size) = decode_varint(data, len_start).ok()?;
    let payload_start = len_start + len_field_size;
    let payload_end = payload_start.checked_add(payload_len as usize)?;
    let payload = data.get(payload_start..payload_end)?;
    Some((stream_id, flags, payload, payload_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for &v in &[0u64, 63, 64, 16383, 16384, 1_073_741_823] {
            let enc = encode_varint(v);
            let (dec, consumed) = decode_varint(&enc, 0).unwrap();
            assert_eq!(dec, v, "value {v}");
            assert_eq!(consumed, enc.len(), "value {v}");
        }
    }

    #[test]
    fn varint_large() {
        let v = (1u64 << 62) - 1;
        let enc = encode_varint(v);
        let (dec, consumed) = decode_varint(&enc, 0).unwrap();
        assert_eq!(dec, v);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn varint_truncated() {
        assert!(decode_varint(&[0x80], 0).is_err());
        assert!(decode_varint(&[0x40], 1).is_err());
    }

    #[test]
    fn frame_with_payload() {
        let payload = b"hello";
        let frame = encode_frame(42, FLAG_DATA, payload);
        let (sid, flags, data, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(sid, 42);
        assert_eq!(flags, FLAG_DATA);
        assert_eq!(data, payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn frame_empty_payload() {
        let frame = encode_frame(7, FLAG_FIRST, b"");
        let (sid, flags, data, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(sid, 7);
        assert_eq!(flags, FLAG_FIRST);
        assert!(data.is_empty());
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn frame_close() {
        let frame = encode_frame(1, FLAG_CLOSE, b"bye");
        let (sid, flags, data, _) = decode_frame(&frame).unwrap();
        assert_eq!(sid, 1);
        assert_eq!(flags, FLAG_CLOSE);
        assert_eq!(data, b"bye");
    }

    #[test]
    fn concatenated_frames() {
        let f1 = encode_frame(0, FLAG_DATA, b"a");
        let f2 = encode_frame(1, FLAG_FIRST, b"bc");
        let f3 = encode_frame(2, FLAG_CLOSE, b"");

        let mut buf = Vec::new();
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&f2);
        buf.extend_from_slice(&f3);

        // With the payload length field, decode_frame can parse
        // concatenated frames correctly.
        let (sid1, fl1, pl1, c1) = decode_frame(&buf).unwrap();
        assert_eq!(sid1, 0);
        assert_eq!(fl1, FLAG_DATA);
        assert_eq!(pl1, b"a");
        assert_eq!(c1, f1.len());

        let (sid2, fl2, pl2, c2) = decode_frame(&buf[c1..]).unwrap();
        assert_eq!(sid2, 1);
        assert_eq!(fl2, FLAG_FIRST);
        assert_eq!(pl2, b"bc");
        assert_eq!(c2, f2.len());

        let (sid3, fl3, pl3, c3) = decode_frame(&buf[c1 + c2..]).unwrap();
        assert_eq!(sid3, 2);
        assert_eq!(fl3, FLAG_CLOSE);
        assert!(pl3.is_empty());
        assert_eq!(c3, f3.len());

        // Total consumed should equal the full buffer.
        assert_eq!(c1 + c2 + c3, buf.len());
    }

    #[test]
    fn decode_frame_truncated() {
        // Only stream_id varint, no flags byte
        let buf = encode_varint(5);
        assert!(decode_frame(&buf).is_none());
    }
}
