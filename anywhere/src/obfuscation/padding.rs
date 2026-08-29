//! XPadding — HTTP header/query/cookie padding to evade size-based traffic analysis.
//!
//! Mirrors Xray's `splithttp/xpadding.go` implementation:
//!
//! - **repeat-x**: `"X".repeat(length)` — 'X' and 'Z' have 8-bit HPACK codes,
//!   so HPACK compression preserves the exact length on the wire.
//! - **tokenish**: random base62 string adjusted so that HPACK Huffman-encoded
//!   length falls within `[target-2, target+2]` bytes.
//!
//! Padding can be placed in:
//! - URL query parameter (default: `x_padding`)
//! - HTTP header (configurable name)
//! - Cookie (configurable name)
//! - Query embedded in a header value (e.g., `Referer: https://host/path?x_padding=...`)
//!
//! Default mode (obfs_mode=false): padding goes into `Referer` header URL query.
//! Custom mode (obfs_mode=true): configurable placement.

use crate::obfuscation::range::Range;

// ---------------------------------------------------------------------------
// HPACK Huffman encoding length table (RFC 7541, Appendix B)
// ---------------------------------------------------------------------------

/// Bits per character in the HPACK Huffman table.
///
/// Indexed by byte value 0–255. Derived from RFC 7541 Appendix B.
/// Used to compute the Huffman-encoded length of a string (as it would
/// appear after HPACK compression in HTTP/2 or QPACK compression in HTTP/3).
const HPACK_HUFFMAN_BITS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, // 0-15
    28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, // 16-31
    6, 10, 10, 12, 13, 6, 15, 13, 10, 10, 8, 11, 8, 6, 6,
    6, // 32-47  (space, !, ", #, $, %, &, ', (, ), *, +, ,, -, ., /)
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 5, 8, 7, 8,
    6, // 48-63  (0-9, :, ;, <, =, >, ?, @)
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // 64-79  (A-O)
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 12, 10, 12, 12,
    13, // 80-95  (P-Z, [, \, ], ^, _)
    12, 10, 13, 12, 12, 12, 12, 12, 12, 11, 12, 12, 12, 12, 12,
    12, // 96-111 (`a-o)
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, // 112-127 (p-z, {, |, }, ~, DEL)
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, // 128-143
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, // 144-159
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, // 160-175
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, // 176-191
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, // 192-207
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, // 208-223
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, // 224-239
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, // 240-255
];

/// Compute the HPACK Huffman-encoded length (in bytes) of a string.
///
/// This matches `hpack.HuffmanEncodeLength()` in Go's `golang.org/x/net/http2/hpack`.
/// The encoded length is `ceil(total_bits / 8)`, with padding bits at the end.
pub fn hpack_huffman_encoded_len(s: &str) -> usize {
    let mut bits: usize = 0;
    for &b in s.as_bytes() {
        bits += HPACK_HUFFMAN_BITS[b as usize] as usize;
    }
    (bits).div_ceil(8)
}

// ---------------------------------------------------------------------------
// Padding method
// ---------------------------------------------------------------------------

/// Padding generation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaddingMethod {
    /// `"X".repeat(length)` — 'X' has an 8-bit HPACK code, so the
    /// compressed length equals the plain length.
    #[default]
    RepeatX,
    /// Random base62 string adjusted so HPACK-encoded length ≈ target.
    Tokenish,
}

/// Where to place the padding value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XPaddingPlacement {
    /// URL query parameter.
    #[default]
    Query,
    /// Standalone HTTP header.
    Header,
    /// Cookie value.
    Cookie,
    /// URL query embedded in a header value (e.g., `Referer: https://host/path?key=value`).
    QueryInHeader,
}

// ---------------------------------------------------------------------------
// XPaddingConfig
// ---------------------------------------------------------------------------

/// Configuration for XPadding generation and placement.
///
/// ## Default mode (`obfs_mode = false`)
///
/// Padding is placed in the `Referer` header as a URL query parameter
/// with key `x_padding`. This matches Xray's default behavior.
///
/// ## Custom mode (`obfs_mode = true`)
///
/// Padding placement is configured via `placement`, `key`, and `header`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct XPaddingConfig {
    /// Padding length range (default: 100–1000).
    #[serde(default = "default_bytes_range")]
    pub bytes: Range,

    /// Padding generation method (default: `repeat-x`).
    #[serde(default)]
    pub method: PaddingMethod,

    /// If false, padding goes into `Referer` header URL query (`?x_padding=...`).
    /// If true, uses `placement` / `key` / `header` for custom placement.
    #[serde(default)]
    pub obfs_mode: bool,

    /// Padding placement (only used when `obfs_mode = true`).
    #[serde(default)]
    pub placement: XPaddingPlacement,

    /// Padding key name (query param name or cookie name).
    #[serde(default = "default_padding_key")]
    pub key: String,

    /// Header name (for `Header` and `QueryInHeader` placements).
    #[serde(default = "default_padding_header")]
    pub header: String,
}

fn default_bytes_range() -> Range {
    Range::new(100, 1000)
}

fn default_padding_key() -> String {
    "x_padding".to_string()
}

fn default_padding_header() -> String {
    "X-Padding".to_string()
}

impl Default for XPaddingConfig {
    fn default() -> Self {
        Self {
            bytes: default_bytes_range(),
            method: PaddingMethod::default(),
            obfs_mode: false,
            placement: XPaddingPlacement::default(),
            key: default_padding_key(),
            header: default_padding_header(),
        }
    }
}

// ---------------------------------------------------------------------------
// Padding generation
// ---------------------------------------------------------------------------

/// Huffman-encoded bytes per base62 character (approximate).
const AVG_HUFFMAN_BYTES_PER_CHAR_BASE62: f64 = 0.8;

/// Maximum adjustment iterations for tokenish padding.
const MAX_TOKENISH_ITERS: usize = 150;

/// Validation tolerance: HPACK-encoded length must be within ±2 bytes of target.
pub const VALIDATION_TOLERANCE: usize = 2;

const CHARSET_BASE62: &[u8] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Generate a random base62 string of length `n` using the thread-local LCG.
fn rand_base62(n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    // Batch-generate random bytes in one syscall, then map to base62
    // with rejection sampling to avoid modulo bias.
    let m = CHARSET_BASE62.len(); // 62
    let limit = 256 - (256 % m); // 248: bytes < 248 map uniformly
    let mut result = Vec::with_capacity(n);
    // Oversize buffer: ~1.03x rejection rate for 62, so n*2 is plenty
    let mut buf = vec![0u8; n * 2];
    crate::obfuscation::range::fill_random(&mut buf);

    for &b in &buf {
        if result.len() == n {
            break;
        }
        if b < limit as u8 {
            result.push(CHARSET_BASE62[(b as usize) % m]);
        }
    }

    // Extremely unlikely: if rejection rate exhausted the buffer,
    // fall back to per-byte generation.
    while result.len() < n {
        let mut b = [0u8; 1];
        crate::obfuscation::range::fill_random(&mut b);
        if b[0] < limit as u8 {
            result.push(CHARSET_BASE62[(b[0] as usize) % m]);
        }
    }

    result.into_iter().map(|b| b as char).collect()
}

/// Generate tokenish padding: a random base62 string whose HPACK
/// Huffman-encoded length falls within `[target-2, target+2]`.
///
/// Algorithm (adapted from Xray's `GenerateTokenishPaddingBase62`):
/// 1. Estimate plaintext length: `ceil(target / 0.8)`
/// 2. Generate random base62 string of that length
/// 3. Iteratively adjust:
///    - If too short (diff < 0): append 'X'/'Z' (8-bit HPACK code = 1 byte each)
///    - If too long (diff > 0): remove characters from the end
///    - For large diffs, batch-adjust to speed convergence
/// 4. Stop when HPACK-encoded length is within tolerance
/// 5. Give up after `MAX_TOKENISH_ITERS` iterations
pub fn generate_tokenish_padding(target_huffman_bytes: usize) -> String {
    if target_huffman_bytes == 0 {
        return String::new();
    }

    let n = (target_huffman_bytes as f64 / AVG_HUFFMAN_BYTES_PER_CHAR_BASE62)
        .ceil() as usize;
    let n = n.max(1);

    let mut s = rand_base62(n);
    let mut adjust_char = b'X';

    for _ in 0..MAX_TOKENISH_ITERS {
        let current_len = hpack_huffman_encoded_len(&s);

        if current_len
            >= target_huffman_bytes.saturating_sub(VALIDATION_TOLERANCE)
            && current_len <= target_huffman_bytes + VALIDATION_TOLERANCE
        {
            return s;
        }

        let diff = current_len as isize - target_huffman_bytes as isize;

        if diff < 0 {
            // Too short — need ~|diff| more bytes.
            // Append 'X'/'Z' (each = 8 bits = 1 byte in HPACK).
            let need = (-diff) as usize;
            // Batch append for large diffs, then fine-tune
            let batch = need.min(20);
            for _ in 0..batch {
                s.push(adjust_char as char);
                adjust_char = if adjust_char == b'X' { b'Z' } else { b'X' };
            }
        } else {
            // Too long — need to remove chars.
            // Each base62 char averages 0.8 bytes, so remove ~diff/0.8 chars.
            let need =
                (diff as f64 / AVG_HUFFMAN_BYTES_PER_CHAR_BASE62).ceil() as usize;
            let remove = need.min(s.len() - 1).max(1);
            let new_len = s.len() - remove;
            s.truncate(new_len);
        }
    }

    s
}

/// Generate padding using the configured method.
///
/// Returns an empty string if `length <= 0`.
pub fn generate_padding(method: PaddingMethod, length: usize) -> String {
    if length == 0 {
        return String::new();
    }

    match method {
        PaddingMethod::RepeatX => "X".repeat(length),
        PaddingMethod::Tokenish => {
            let padding = generate_tokenish_padding(length);
            if padding.is_empty() {
                "X".repeat(length)
            } else {
                padding
            }
        },
    }
}

impl XPaddingConfig {
    /// Generate a padding value using this config's method and a random
    /// length drawn from the `bytes` range.
    pub fn generate(&self) -> String {
        let length = self.bytes.rand_usize();
        generate_padding(self.method, length)
    }

    /// Generate padding with a specific length (overrides `bytes` range).
    pub fn generate_with_length(&self, length: usize) -> String {
        generate_padding(self.method, length)
    }

    /// Validate a received padding value.
    ///
    /// For `repeat-x`: checks plaintext length is within `[from, to]`.
    /// For `tokenish`: checks HPACK-encoded length is within `[from-2, to+2]`.
    pub fn is_valid(&self, padding: &str) -> bool {
        if padding.is_empty() {
            return false;
        }

        let from = self.bytes.from as usize;
        let to = self.bytes.to as usize;
        if to == 0 {
            return false;
        }

        match self.method {
            PaddingMethod::RepeatX => {
                let n = padding.len();
                n >= from && n <= to
            },
            PaddingMethod::Tokenish => {
                let n = hpack_huffman_encoded_len(padding);
                let lo = from.saturating_sub(VALIDATION_TOLERANCE);
                let hi = to + VALIDATION_TOLERANCE;
                n >= lo && n <= hi
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Placement constants
// ---------------------------------------------------------------------------

/// Default padding key name (used in Referer URL query).
pub const DEFAULT_PADDING_KEY: &str = "x_padding";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- HPACK Huffman tests ---

    #[test]
    fn huffman_len_empty_string() {
        assert_eq!(hpack_huffman_encoded_len(""), 0);
    }

    #[test]
    fn huffman_len_single_char() {
        // 'X' = 8 bits → 1 byte
        assert_eq!(hpack_huffman_encoded_len("X"), 1);
        // 'Z' = 8 bits → 1 byte
        assert_eq!(hpack_huffman_encoded_len("Z"), 1);
        // '0' = 5 bits → 1 byte
        assert_eq!(hpack_huffman_encoded_len("0"), 1);
        // 'a' = 12 bits → 2 bytes
        assert_eq!(hpack_huffman_encoded_len("a"), 2);
    }

    #[test]
    fn huffman_len_repeat_x_preserves_length() {
        // "X" has 8-bit HPACK code, so N X's = N bytes (no compression)
        for n in [1, 10, 100, 1000] {
            let s = "X".repeat(n);
            assert_eq!(
                hpack_huffman_encoded_len(&s),
                n,
                "repeat-x length {} should encode to {} bytes",
                n,
                n
            );
        }
    }

    #[test]
    fn huffman_len_base62_shorter_than_plain() {
        // base62 characters have 5–12 bit codes, so encoded should be
        // shorter than plain bytes for typical strings
        let s = "ABCDEFGHIJ1234567890";
        let plain = s.len();
        let encoded = hpack_huffman_encoded_len(s);
        assert!(
            encoded <= plain,
            "encoded {} should be <= plain {}",
            encoded,
            plain
        );
    }

    // --- repeat-x padding tests ---

    #[test]
    fn repeat_x_padding() {
        let p = generate_padding(PaddingMethod::RepeatX, 100);
        assert_eq!(p.len(), 100);
        assert!(p.chars().all(|c| c == 'X'));
    }

    #[test]
    fn repeat_x_zero_length() {
        assert_eq!(generate_padding(PaddingMethod::RepeatX, 0), "");
    }

    // --- tokenish padding tests ---

    #[test]
    fn tokenish_padding_within_tolerance() {
        for target in [50, 100, 200, 500, 1000] {
            let p = generate_tokenish_padding(target);
            let encoded = hpack_huffman_encoded_len(&p);
            assert!(
                encoded >= target.saturating_sub(VALIDATION_TOLERANCE)
                    && encoded <= target + VALIDATION_TOLERANCE,
                "target {}: encoded {} not within [{}, {}]",
                target,
                encoded,
                target.saturating_sub(VALIDATION_TOLERANCE),
                target + VALIDATION_TOLERANCE
            );
        }
    }

    #[test]
    fn tokenish_padding_nonempty() {
        let p = generate_tokenish_padding(100);
        assert!(!p.is_empty());
    }

    #[test]
    fn tokenish_padding_base62_chars() {
        let p = generate_tokenish_padding(200);
        assert!(
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == 'X' || c == 'Z'),
            "tokenish padding should be base62 + adjustment chars: got {:?}",
            p
        );
    }

    #[test]
    fn tokenish_zero_target() {
        assert_eq!(generate_tokenish_padding(0), "");
    }

    // --- XPaddingConfig tests ---

    #[test]
    fn config_default_generate() {
        let cfg = XPaddingConfig::default();
        let p = cfg.generate();
        assert!(!p.is_empty());
        // Default method is repeat-x, so length should be in [100, 1000]
        assert!(p.len() >= 100 && p.len() <= 1000);
        assert!(p.chars().all(|c| c == 'X'));
    }

    #[test]
    fn config_tokenish_generate() {
        let cfg = XPaddingConfig {
            method: PaddingMethod::Tokenish,
            ..Default::default()
        };
        let p = cfg.generate();
        assert!(!p.is_empty());
        // HPACK-encoded length should be within [100-2, 1000+2]
        let encoded = hpack_huffman_encoded_len(&p);
        assert!(encoded >= 98 && encoded <= 1002);
    }

    #[test]
    fn config_is_valid_repeat_x() {
        let cfg = XPaddingConfig::default();
        assert!(cfg.is_valid(&"X".repeat(100)));
        assert!(cfg.is_valid(&"X".repeat(500)));
        assert!(cfg.is_valid(&"X".repeat(1000)));
        assert!(!cfg.is_valid(&"X".repeat(99)));
        assert!(!cfg.is_valid(&"X".repeat(1001)));
        assert!(!cfg.is_valid(""));
    }

    #[test]
    fn config_is_valid_tokenish() {
        let cfg = XPaddingConfig {
            method: PaddingMethod::Tokenish,
            ..Default::default()
        };
        // Generate a valid tokenish padding and verify
        let p = generate_tokenish_padding(500);
        assert!(
            cfg.is_valid(&p),
            "generated tokenish padding should be valid"
        );

        // A very short string should fail (encoded length too small)
        assert!(!cfg.is_valid("X"));
    }

    #[test]
    fn config_generate_with_length() {
        let cfg = XPaddingConfig::default();
        let p = cfg.generate_with_length(42);
        assert_eq!(p.len(), 42);
        assert!(p.chars().all(|c| c == 'X'));
    }

    // --- Placement tests ---

    #[test]
    fn default_config_values() {
        let cfg = XPaddingConfig::default();
        assert_eq!(cfg.bytes, Range::new(100, 1000));
        assert_eq!(cfg.method, PaddingMethod::RepeatX);
        assert!(!cfg.obfs_mode);
        assert_eq!(cfg.placement, XPaddingPlacement::Query);
        assert_eq!(cfg.key, "x_padding");
        assert_eq!(cfg.header, "X-Padding");
    }

    #[test]
    fn default_padding_key_constant() {
        assert_eq!(DEFAULT_PADDING_KEY, "x_padding");
    }

    // --- Consistency with Xray ---

    #[test]
    fn x_and_z_both_8_bit_hpack() {
        // Xray relies on X and Z both having 8-bit HPACK codes
        assert_eq!(HPACK_HUFFMAN_BITS[b'X' as usize], 8);
        assert_eq!(HPACK_HUFFMAN_BITS[b'Z' as usize], 8);
    }

    #[test]
    fn tokenish_matches_xray_algorithm() {
        // Verify the algorithm produces results consistent with Xray's approach:
        // 1. Start with ceil(target / 0.8) random base62 chars
        // 2. Adjust until HPACK encoded length ∈ [target-2, target+2]
        let target = 300;
        let p = generate_tokenish_padding(target);
        let encoded = hpack_huffman_encoded_len(&p);
        let diff = (encoded as isize - target as isize).abs();
        assert!(
            diff <= VALIDATION_TOLERANCE as isize,
            "diff {} exceeds tolerance {}",
            diff,
            VALIDATION_TOLERANCE
        );
    }
}
