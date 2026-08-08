// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! SS2022 (AEAD-2022) cipher primitives.
//!
//! Implements key derivation, AEAD encryption/decryption, and EIH
//! (Extended Identity Header) generation for the three SS2022 methods:
//! - `2022-blake3-aes-128-gcm`
//! - `2022-blake3-aes-256-gcm`
//! - `2022-blake3-chacha20-poly1305`
//!
//! Protocol details follow `sing-shadowsocks2` (`shadowaead_2022/method.go`
//! and `shadowaead_2022/protocol.go`).

// ─── Constants ──────────────────────────────────────────────────────────────

/// AEAD authentication tag length (GCM / Poly1305).
pub const OVERHEAD: usize = 16;

/// TCP AEAD nonce length (GCM / ChaCha20-Poly1305).
pub const NONCE_SIZE: usize = 12;

/// Maximum TCP frame payload (`16 * 1024 - 1`).
pub const MAX_PACKET_SIZE: usize = 16383;

/// SS2022 padding upper bound.
pub const MAX_PADDING_LENGTH: usize = 900;

/// Fixed header chunk: `1(type) + 8(timestamp) + 2(var header len)`.
pub const REQUEST_HEADER_FIXED_CHUNK_LENGTH: usize = 11;

/// Request header type (client → server).
pub const HEADER_TYPE_CLIENT: u8 = 0;

/// Response header type (server → client).
pub const HEADER_TYPE_SERVER: u8 = 1;

/// UDP XChaCha20-Poly1305 nonce length (chacha method only).
pub const PACKET_NONCE_SIZE: usize = 24;

/// Timestamp tolerance in seconds.
pub const TIMESTAMP_TOLERANCE_SECS: i64 = 30;

// ─── CipherMethod ───────────────────────────────────────────────────────────

/// Parsed SS2022 cipher method with PSK(s) and pre-computed identity hashes.
#[derive(Clone, Debug)]
pub enum CipherMethod {
    Aes128Gcm {
        psk_list: Vec<[u8; 16]>,
        /// `(N-1) * 16` bytes: `blake3_512(psk_i)[:16]` for i = 1 to N-1.
        psk_hash: Vec<u8>,
    },
    Aes256Gcm {
        psk_list: Vec<[u8; 32]>,
        psk_hash: Vec<u8>,
    },
    ChaCha20Poly1305 {
        psk: [u8; 32],
    },
}

impl CipherMethod {
    /// Parse a method name + base64-encoded PSK password into a `CipherMethod`.
    ///
    /// `password` is base64-encoded PSK. For multi-user (AES only):
    /// `"psk1:psk2:..."` (colon-separated base64). The last PSK is the
    /// server key used for session key derivation.
    pub fn new(method: &str, password: &str) -> Result<Self, String> {
        use base64::Engine;

        if password.is_empty() {
            return Err("missing password".to_string());
        }

        // 1. Base64-decode each colon-separated PSK.
        let key_strs: Vec<&str> = password.split(':').collect();
        let mut psk_list: Vec<Vec<u8>> = Vec::with_capacity(key_strs.len());
        for ks in &key_strs {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(ks)
                .map_err(|e| format!("decode key: {e}"))?;
            psk_list.push(decoded);
        }

        // 2. Determine method + keySaltLength.
        let (key_salt_length, is_chacha): (usize, bool) = match method {
            "2022-blake3-aes-128-gcm" => (16, false),
            "2022-blake3-aes-256-gcm" => (32, false),
            "2022-blake3-chacha20-poly1305" => (32, true),
            _ => return Err(format!("unknown method: {method}")),
        };

        // 3. ChaCha20Poly1305 does not support EIH / multi-PSK.
        if is_chacha && psk_list.len() > 1 {
            return Err(
                "Shadowsocks 2022 EIH support only available in AES ciphers".to_string(),
            );
        }

        // 4. Validate each PSK length.
        for key in &psk_list {
            if key.len() != key_salt_length {
                return Err(format!(
                    "bad key length, required {key_salt_length}, got {}",
                    key.len()
                ));
            }
        }

        // 5. Build the enum variant.
        if is_chacha {
            // Single PSK, 32 bytes.
            let mut psk = [0u8; 32];
            psk.copy_from_slice(&psk_list[0]);
            Ok(CipherMethod::ChaCha20Poly1305 { psk })
        } else {
            // AES method — may have multiple PSKs.
            if key_salt_length == 16 {
                let mut fixed_psks: Vec<[u8; 16]> =
                    Vec::with_capacity(psk_list.len());
                for key in &psk_list {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(key);
                    fixed_psks.push(arr);
                }
                let psk_hash = compute_psk_hash(&psk_list);
                Ok(CipherMethod::Aes128Gcm {
                    psk_list: fixed_psks,
                    psk_hash,
                })
            } else {
                let mut fixed_psks: Vec<[u8; 32]> =
                    Vec::with_capacity(psk_list.len());
                for key in &psk_list {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(key);
                    fixed_psks.push(arr);
                }
                let psk_hash = compute_psk_hash(&psk_list);
                Ok(CipherMethod::Aes256Gcm {
                    psk_list: fixed_psks,
                    psk_hash,
                })
            }
        }
    }

    /// Key/salt length for this method (16 for aes-128, 32 for aes-256/chacha).
    pub fn key_salt_length(&self) -> usize {
        match self {
            CipherMethod::Aes128Gcm { .. } => 16,
            CipherMethod::Aes256Gcm { .. } => 32,
            CipherMethod::ChaCha20Poly1305 { .. } => 32,
        }
    }

    /// Method name string.
    pub fn method_name(&self) -> &'static str {
        match self {
            CipherMethod::Aes128Gcm { .. } => "2022-blake3-aes-128-gcm",
            CipherMethod::Aes256Gcm { .. } => "2022-blake3-aes-256-gcm",
            CipherMethod::ChaCha20Poly1305 { .. } => "2022-blake3-chacha20-poly1305",
        }
    }

    /// Derive a per-connection session key from the last PSK and a random salt.
    ///
    /// `session_key = blake3_derive_key("shadowsocks 2022 session subkey",
    /// psk_last || salt)` truncated to `key_salt_length`.
    pub fn session_key(&self, salt: &[u8]) -> Vec<u8> {
        let psk = self.last_psk();
        let mut key_material = Vec::with_capacity(psk.len() + salt.len());
        key_material.extend_from_slice(psk);
        key_material.extend_from_slice(salt);
        let derived = blake3::derive_key("shadowsocks 2022 session subkey", &key_material);
        derived[..self.key_salt_length()].to_vec()
    }

    /// Create an AEAD cipher from a session key.
    pub fn create_aead(&self, session_key: &[u8]) -> SsAead {
        match self {
            CipherMethod::Aes128Gcm { .. } => {
                use aes_gcm::aead::KeyInit;
                SsAead::Aes128(
                    aes_gcm::Aes128Gcm::new_from_slice(session_key)
                        .expect("invalid session key length for Aes128Gcm"),
                )
            }
            CipherMethod::Aes256Gcm { .. } => {
                use aes_gcm::aead::KeyInit;
                SsAead::Aes256(
                    aes_gcm::Aes256Gcm::new_from_slice(session_key)
                        .expect("invalid session key length for Aes256Gcm"),
                )
            }
            CipherMethod::ChaCha20Poly1305 { .. } => {
                use chacha20poly1305::aead::KeyInit;
                SsAead::ChaCha20(
                    chacha20poly1305::ChaCha20Poly1305::new_from_slice(session_key)
                        .expect("invalid session key length for ChaCha20Poly1305"),
                )
            }
        }
    }

    /// Generate Extended Identity Headers (EIH) for multi-user AES.
    ///
    /// For each PSK index `i` from `0` to `N-2`:
    /// 1. `identity_subkey = blake3_derive_key("shadowsocks 2022 identity
    ///    subkey", psk_i || salt)` truncated to `key_salt_length`.
    /// 2. `eih_block = AES-ECB-encrypt(identity_subkey, psk_hash[i])`.
    ///
    /// Returns an empty `Vec` for single-PSK or ChaCha20Poly1305.
    pub fn generate_eih(&self, salt: &[u8]) -> Vec<u8> {
        let ksl = self.key_salt_length();
        let (psk_refs, psk_hash): (Vec<&[u8]>, &[u8]) = match self {
            CipherMethod::Aes128Gcm { psk_list, psk_hash } => {
                (psk_list.iter().map(|p| p.as_slice()).collect(), psk_hash.as_slice())
            }
            CipherMethod::Aes256Gcm { psk_list, psk_hash } => {
                (psk_list.iter().map(|p| p.as_slice()).collect(), psk_hash.as_slice())
            }
            CipherMethod::ChaCha20Poly1305 { .. } => return Vec::new(),
        };

        if psk_refs.len() < 2 {
            return Vec::new();
        }

        let mut result = Vec::with_capacity((psk_refs.len() - 1) * 16);
        for i in 0..psk_refs.len() - 1 {
            let psk = psk_refs[i];
            let mut key_material = Vec::with_capacity(ksl * 2);
            key_material.extend_from_slice(psk);
            key_material.extend_from_slice(salt);
            let identity_subkey =
                blake3::derive_key("shadowsocks 2022 identity subkey", &key_material);
            let identity_subkey = &identity_subkey[..ksl];

            let psk_hash_block = &psk_hash[i * 16..(i + 1) * 16];
            let ecb = AesEcb::new(identity_subkey);
            let mut block = [0u8; 16];
            block.copy_from_slice(psk_hash_block);
            ecb.encrypt_block(&mut block);
            result.extend_from_slice(&block);
        }
        result
    }

    /// `true` if this is an AES method (supports EIH).
    pub fn is_aes(&self) -> bool {
        matches!(
            self,
            CipherMethod::Aes128Gcm { .. } | CipherMethod::Aes256Gcm { .. }
        )
    }

    /// Last PSK in the list (used for session key derivation).
    pub fn last_psk(&self) -> &[u8] {
        match self {
            CipherMethod::Aes128Gcm { psk_list, .. } => {
                psk_list.last().expect("psk_list must not be empty")
            }
            CipherMethod::Aes256Gcm { psk_list, .. } => {
                psk_list.last().expect("psk_list must not be empty")
            }
            CipherMethod::ChaCha20Poly1305 { psk } => psk,
        }
    }

    /// AES-ECB block cipher for UDP header encryption (key = `psk_list[0]`).
    pub fn udp_block_encryptor(&self) -> AesEcb {
        match self {
            CipherMethod::Aes128Gcm { psk_list, .. } => AesEcb::new(&psk_list[0]),
            CipherMethod::Aes256Gcm { psk_list, .. } => AesEcb::new(&psk_list[0]),
            CipherMethod::ChaCha20Poly1305 { .. } => {
                panic!("udp_block_encryptor not available for ChaCha20Poly1305")
            }
        }
    }

    /// AES-ECB block cipher for UDP header decryption (key = `psk_list[last]`).
    pub fn udp_block_decryptor(&self) -> AesEcb {
        match self {
            CipherMethod::Aes128Gcm { psk_list, .. } => {
                AesEcb::new(psk_list.last().expect("psk_list must not be empty"))
            }
            CipherMethod::Aes256Gcm { psk_list, .. } => {
                AesEcb::new(psk_list.last().expect("psk_list must not be empty"))
            }
            CipherMethod::ChaCha20Poly1305 { .. } => {
                panic!("udp_block_decryptor not available for ChaCha20Poly1305")
            }
        }
    }
}

/// Compute `psk_hash`: for each PSK from index 1 to N-1, take
/// `blake3::hash(psk).as_bytes()[..16]` and concatenate.
///
/// This matches `blake3.Sum512(psk)[:16]` in Go (first 16 bytes of the
/// BLAKE3 XOF output are identical regardless of requested length).
fn compute_psk_hash(psk_list: &[Vec<u8>]) -> Vec<u8> {
    if psk_list.len() < 2 {
        return Vec::new();
    }
    let mut hash = Vec::with_capacity((psk_list.len() - 1) * 16);
    for i in 1..psk_list.len() {
        let h = blake3::hash(&psk_list[i]);
        hash.extend_from_slice(&h.as_bytes()[..16]);
    }
    hash
}

// ─── SsAead ─────────────────────────────────────────────────────────────────

/// AEAD cipher wrapper for the three SS2022 methods.
pub enum SsAead {
    Aes128(aes_gcm::Aes128Gcm),
    Aes256(aes_gcm::Aes256Gcm),
    ChaCha20(chacha20poly1305::ChaCha20Poly1305),
}

impl SsAead {
    /// Encrypt `plaintext` with the given 12-byte nonce. Returns
    /// ciphertext + 16-byte tag.
    pub fn seal(&self, nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match self {
            SsAead::Aes128(c) => {
                use aes_gcm::aead::Aead;
                let n: [u8; 12] = nonce
                    .try_into()
                    .expect("nonce must be 12 bytes");
                c.encrypt((&n).into(), plaintext)
                    .expect("AEAD encryption failed")
            }
            SsAead::Aes256(c) => {
                use aes_gcm::aead::Aead;
                let n: [u8; 12] = nonce
                    .try_into()
                    .expect("nonce must be 12 bytes");
                c.encrypt((&n).into(), plaintext)
                    .expect("AEAD encryption failed")
            }
            SsAead::ChaCha20(c) => {
                use chacha20poly1305::aead::Aead;
                let n: chacha20poly1305::aead::Nonce<chacha20poly1305::ChaCha20Poly1305> =
                    nonce.try_into().expect("nonce must be 12 bytes");
                c.encrypt(&n, plaintext)
                    .expect("AEAD encryption failed")
            }
        }
    }

    /// Decrypt `ciphertext` (including 16-byte tag) with the given nonce.
    pub fn open(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            SsAead::Aes128(c) => {
                use aes_gcm::aead::Aead;
                let n: [u8; 12] = nonce
                    .try_into()
                    .expect("nonce must be 12 bytes");
                c.decrypt((&n).into(), ciphertext)
                    .map_err(|e| format!("AEAD decryption failed: {e}"))
            }
            SsAead::Aes256(c) => {
                use aes_gcm::aead::Aead;
                let n: [u8; 12] = nonce
                    .try_into()
                    .expect("nonce must be 12 bytes");
                c.decrypt((&n).into(), ciphertext)
                    .map_err(|e| format!("AEAD decryption failed: {e}"))
            }
            SsAead::ChaCha20(c) => {
                use chacha20poly1305::aead::Aead;
                let n: chacha20poly1305::aead::Nonce<chacha20poly1305::ChaCha20Poly1305> =
                    nonce.try_into().expect("nonce must be 12 bytes");
                c.decrypt(&n, ciphertext)
                    .map_err(|e| format!("AEAD decryption failed: {e}"))
            }
        }
    }
}

// ─── AesEcb ─────────────────────────────────────────────────────────────────

/// AES-ECB block cipher (single block, no padding). Used for UDP header
/// encryption/decryption and EIH block encryption.
pub struct AesEcb {
    inner: AesEcbInner,
}

enum AesEcbInner {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}

impl AesEcb {
    /// Create from a 16-byte (AES-128) or 32-byte (AES-256) key.
    pub fn new(key: &[u8]) -> Self {
        use aes::cipher::KeyInit;
        match key.len() {
            16 => AesEcb {
                inner: AesEcbInner::Aes128(
                    aes::Aes128::new_from_slice(key)
                        .expect("invalid AES-128 key"),
                ),
            },
            32 => AesEcb {
                inner: AesEcbInner::Aes256(
                    aes::Aes256::new_from_slice(key)
                        .expect("invalid AES-256 key"),
                ),
            },
            _ => panic!("invalid AES key length: {}", key.len()),
        }
    }

    /// Encrypt a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockCipherEncrypt;
        match &self.inner {
            AesEcbInner::Aes128(c) => c.encrypt_block(block.into()),
            AesEcbInner::Aes256(c) => c.encrypt_block(block.into()),
        }
    }

    /// Decrypt a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockCipherDecrypt;
        match &self.inner {
            AesEcbInner::Aes128(c) => c.decrypt_block(block.into()),
            AesEcbInner::Aes256(c) => c.decrypt_block(block.into()),
        }
    }
}

// ─── Nonce ──────────────────────────────────────────────────────────────────

/// Increment a nonce as a little-endian counter. Byte 0 is the least
/// significant; carries propagate to higher bytes. Matches Go `increaseNonce`.
pub fn increase_nonce(nonce: &mut [u8]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            return;
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine;

    fn b64_encode(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    // ── PSK parsing ─────────────────────────────────────────────────────────

    #[test]
    fn test_psk_parsing_single_aes128() {
        let psk = [0x42u8; 16];
        let password = b64_encode(&psk);
        let method =
            CipherMethod::new("2022-blake3-aes-128-gcm", &password).unwrap();
        assert_eq!(method.key_salt_length(), 16);
        assert_eq!(method.method_name(), "2022-blake3-aes-128-gcm");
        assert!(method.is_aes());
        assert_eq!(method.last_psk(), &psk);
    }

    #[test]
    fn test_psk_parsing_single_aes256() {
        let psk = [0x99u8; 32];
        let password = b64_encode(&psk);
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &password).unwrap();
        assert_eq!(method.key_salt_length(), 32);
        assert_eq!(method.method_name(), "2022-blake3-aes-256-gcm");
        assert!(method.is_aes());
        assert_eq!(method.last_psk(), &psk);
    }

    #[test]
    fn test_psk_parsing_single_chacha() {
        let psk = [0xABu8; 32];
        let password = b64_encode(&psk);
        let method = CipherMethod::new(
            "2022-blake3-chacha20-poly1305",
            &password,
        )
        .unwrap();
        assert_eq!(method.key_salt_length(), 32);
        assert_eq!(
            method.method_name(),
            "2022-blake3-chacha20-poly1305"
        );
        assert!(!method.is_aes());
        assert_eq!(method.last_psk(), &psk);
    }

    #[test]
    fn test_psk_parsing_multi_aes128() {
        let psk0 = [0x01u8; 16];
        let psk1 = [0x02u8; 16];
        let psk2 = [0x03u8; 16];
        let password = format!(
            "{}:{}:{}",
            b64_encode(&psk0),
            b64_encode(&psk1),
            b64_encode(&psk2)
        );
        let method =
            CipherMethod::new("2022-blake3-aes-128-gcm", &password).unwrap();
        assert_eq!(method.last_psk(), &psk2);
        // EIH should be available (2 blocks for 3 PSKs).
        let salt = [0u8; 16];
        let eih = method.generate_eih(&salt);
        assert_eq!(eih.len(), 2 * 16);
    }

    #[test]
    fn test_psk_parsing_multi_aes256() {
        let psk0 = [0x10u8; 32];
        let psk1 = [0x20u8; 32];
        let password =
            format!("{}:{}", b64_encode(&psk0), b64_encode(&psk1));
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &password).unwrap();
        assert_eq!(method.last_psk(), &psk1);
    }

    #[test]
    fn test_psk_parsing_chacha_rejects_multi() {
        let psk0 = [0x01u8; 32];
        let psk1 = [0x02u8; 32];
        let password =
            format!("{}:{}", b64_encode(&psk0), b64_encode(&psk1));
        let result = CipherMethod::new(
            "2022-blake3-chacha20-poly1305",
            &password,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("EIH"));
    }

    #[test]
    fn test_psk_parsing_bad_key_length() {
        let psk = [0u8; 10]; // wrong length
        let password = b64_encode(&psk);
        let result =
            CipherMethod::new("2022-blake3-aes-128-gcm", &password);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bad key length"));
    }

    #[test]
    fn test_psk_parsing_invalid_base64() {
        let result = CipherMethod::new(
            "2022-blake3-aes-128-gcm",
            "!!!not-base64!!!",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_psk_parsing_unknown_method() {
        let psk = [0u8; 16];
        let password = b64_encode(&psk);
        let result = CipherMethod::new("aes-256-cfb", &password);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown method"));
    }

    #[test]
    fn test_psk_parsing_empty_password() {
        let result =
            CipherMethod::new("2022-blake3-aes-128-gcm", "");
        assert!(result.is_err());
    }

    // ── Session key derivation ──────────────────────────────────────────────

    #[test]
    fn test_session_key_derivation() {
        let psk = [0x42u8; 16];
        let method = CipherMethod::new(
            "2022-blake3-aes-128-gcm",
            &b64_encode(&psk),
        )
        .unwrap();
        let salt = [0xAAu8; 16];

        // Manually compute expected session key.
        let mut key_material = Vec::new();
        key_material.extend_from_slice(&psk);
        key_material.extend_from_slice(&salt);
        let expected =
            blake3::derive_key("shadowsocks 2022 session subkey", &key_material);
        let expected = &expected[..16];

        let session_key = method.session_key(&salt);
        assert_eq!(session_key.len(), 16);
        assert_eq!(session_key.as_slice(), expected);
    }

    #[test]
    fn test_session_key_derivation_aes256() {
        let psk = [0x77u8; 32];
        let method = CipherMethod::new(
            "2022-blake3-aes-256-gcm",
            &b64_encode(&psk),
        )
        .unwrap();
        let salt = [0xBBu8; 32];

        let mut key_material = Vec::new();
        key_material.extend_from_slice(&psk);
        key_material.extend_from_slice(&salt);
        let expected =
            blake3::derive_key("shadowsocks 2022 session subkey", &key_material);

        let session_key = method.session_key(&salt);
        assert_eq!(session_key.len(), 32);
        assert_eq!(session_key.as_slice(), &expected[..]);
    }

    #[test]
    fn test_session_key_uses_last_psk() {
        // Multi-PSK: session key should use the last PSK.
        let psk0 = [0x01u8; 16];
        let psk1 = [0x02u8; 16];
        let password =
            format!("{}:{}", b64_encode(&psk0), b64_encode(&psk1));
        let method =
            CipherMethod::new("2022-blake3-aes-128-gcm", &password).unwrap();
        let salt = [0u8; 16];

        let mut key_material = Vec::new();
        key_material.extend_from_slice(&psk1);
        key_material.extend_from_slice(&salt);
        let expected =
            blake3::derive_key("shadowsocks 2022 session subkey", &key_material);

        let session_key = method.session_key(&salt);
        assert_eq!(session_key.as_slice(), &expected[..16]);
    }

    // ── SsAead seal/open round-trip ─────────────────────────────────────────

    #[test]
    fn test_aead_round_trip_aes128() {
        let psk = [0x42u8; 16];
        let method = CipherMethod::new(
            "2022-blake3-aes-128-gcm",
            &b64_encode(&psk),
        )
        .unwrap();
        let salt = [0u8; 16];
        let session_key = method.session_key(&salt);
        let aead = method.create_aead(&session_key);

        let nonce = [0u8; 12];
        let plaintext = b"hello ss2022";
        let ciphertext = aead.seal(&nonce, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + OVERHEAD);

        let decrypted = aead.open(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_round_trip_aes256() {
        let psk = [0x99u8; 32];
        let method = CipherMethod::new(
            "2022-blake3-aes-256-gcm",
            &b64_encode(&psk),
        )
        .unwrap();
        let salt = [0xFFu8; 32];
        let session_key = method.session_key(&salt);
        let aead = method.create_aead(&session_key);

        let nonce = [1u8; 12];
        let plaintext = b"aes-256-gcm test payload";
        let ciphertext = aead.seal(&nonce, plaintext);
        let decrypted = aead.open(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_round_trip_chacha20() {
        let psk = [0xABu8; 32];
        let method = CipherMethod::new(
            "2022-blake3-chacha20-poly1305",
            &b64_encode(&psk),
        )
        .unwrap();
        let salt = [0xCDu8; 32];
        let session_key = method.session_key(&salt);
        let aead = method.create_aead(&session_key);

        let nonce = [2u8; 12];
        let plaintext = b"chacha20poly1305 test";
        let ciphertext = aead.seal(&nonce, plaintext);
        let decrypted = aead.open(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_open_wrong_nonce_fails() {
        let psk = [0x42u8; 16];
        let method = CipherMethod::new(
            "2022-blake3-aes-128-gcm",
            &b64_encode(&psk),
        )
        .unwrap();
        let salt = [0u8; 16];
        let session_key = method.session_key(&salt);
        let aead = method.create_aead(&session_key);

        let nonce = [0u8; 12];
        let wrong_nonce = [1u8; 12];
        let plaintext = b"test";
        let ciphertext = aead.seal(&nonce, plaintext);
        assert!(aead.open(&wrong_nonce, &ciphertext).is_err());
    }

    #[test]
    fn test_aead_open_tampered_ciphertext_fails() {
        let psk = [0x42u8; 16];
        let method = CipherMethod::new(
            "2022-blake3-aes-128-gcm",
            &b64_encode(&psk),
        )
        .unwrap();
        let salt = [0u8; 16];
        let session_key = method.session_key(&salt);
        let aead = method.create_aead(&session_key);

        let nonce = [0u8; 12];
        let plaintext = b"test";
        let mut ciphertext = aead.seal(&nonce, plaintext);
        // Flip a bit in the ciphertext.
        ciphertext[0] ^= 0xFF;
        assert!(aead.open(&nonce, &ciphertext).is_err());
    }

    // ── EIH generation ──────────────────────────────────────────────────────

    #[test]
    fn test_eih_single_psk_empty() {
        let psk = [0x42u8; 16];
        let method = CipherMethod::new(
            "2022-blake3-aes-128-gcm",
            &b64_encode(&psk),
        )
        .unwrap();
        let salt = [0u8; 16];
        let eih = method.generate_eih(&salt);
        assert!(eih.is_empty());
    }

    #[test]
    fn test_eih_chacha_empty() {
        let psk = [0xABu8; 32];
        let method = CipherMethod::new(
            "2022-blake3-chacha20-poly1305",
            &b64_encode(&psk),
        )
        .unwrap();
        let salt = [0u8; 32];
        let eih = method.generate_eih(&salt);
        assert!(eih.is_empty());
    }

    #[test]
    fn test_eih_multi_psk_aes128() {
        let psk0 = [0x01u8; 16];
        let psk1 = [0x02u8; 16];
        let psk2 = [0x03u8; 16];
        let password = format!(
            "{}:{}:{}",
            b64_encode(&psk0),
            b64_encode(&psk1),
            b64_encode(&psk2)
        );
        let method =
            CipherMethod::new("2022-blake3-aes-128-gcm", &password).unwrap();
        let salt = [0xAAu8; 16];
        let eih = method.generate_eih(&salt);

        // (N-1) * 16 = 2 * 16 = 32 bytes.
        assert_eq!(eih.len(), 32);

        // Independently verify each EIH block.
        let psks = [psk0, psk1, psk2];
        for i in 0..2 {
            // identity_subkey = DeriveKey(psk_i || salt)
            let mut key_material = Vec::new();
            key_material.extend_from_slice(&psks[i]);
            key_material.extend_from_slice(&salt);
            let identity_subkey = blake3::derive_key(
                "shadowsocks 2022 identity subkey",
                &key_material,
            );

            // psk_hash block i = blake3::hash(psk_{i+1})[:16]
            let psk_hash = blake3::hash(&psks[i + 1]);
            let psk_hash_block = &psk_hash.as_bytes()[..16];

            let ecb = AesEcb::new(&identity_subkey[..16]);
            let mut expected = [0u8; 16];
            expected.copy_from_slice(psk_hash_block);
            ecb.encrypt_block(&mut expected);

            assert_eq!(
                &eih[i * 16..(i + 1) * 16],
                &expected,
                "EIH block {i} mismatch"
            );
        }
    }

    #[test]
    fn test_eih_multi_psk_aes256() {
        let psk0 = [0x10u8; 32];
        let psk1 = [0x20u8; 32];
        let password =
            format!("{}:{}", b64_encode(&psk0), b64_encode(&psk1));
        let method =
            CipherMethod::new("2022-blake3-aes-256-gcm", &password).unwrap();
        let salt = [0xBBu8; 32];
        let eih = method.generate_eih(&salt);

        // (N-1) * 16 = 1 * 16 = 16 bytes.
        assert_eq!(eih.len(), 16);

        // Verify block 0.
        let mut key_material = Vec::new();
        key_material.extend_from_slice(&psk0);
        key_material.extend_from_slice(&salt);
        let identity_subkey =
            blake3::derive_key("shadowsocks 2022 identity subkey", &key_material);
        let psk_hash = blake3::hash(&psk1);
        let psk_hash_block = &psk_hash.as_bytes()[..16];

        let ecb = AesEcb::new(&identity_subkey[..32]);
        let mut expected = [0u8; 16];
        expected.copy_from_slice(psk_hash_block);
        ecb.encrypt_block(&mut expected);

        assert_eq!(&eih[..16], &expected);
    }

    // ── increase_nonce ──────────────────────────────────────────────────────

    #[test]
    fn test_increase_nonce_simple() {
        let mut nonce = [0u8; 12];
        increase_nonce(&mut nonce);
        assert_eq!(nonce[0], 1);
        assert_eq!(nonce[1..], [0u8; 11]);
    }

    #[test]
    fn test_increase_nonce_carry() {
        let mut nonce = [0u8; 12];
        nonce[0] = 0xFF;
        increase_nonce(&mut nonce);
        assert_eq!(nonce[0], 0);
        assert_eq!(nonce[1], 1);
        assert_eq!(nonce[2..], [0u8; 10]);
    }

    #[test]
    fn test_increase_nonce_multi_carry() {
        let mut nonce = [0u8; 12];
        nonce[0] = 0xFF;
        nonce[1] = 0xFF;
        increase_nonce(&mut nonce);
        assert_eq!(nonce[0], 0);
        assert_eq!(nonce[1], 0);
        assert_eq!(nonce[2], 1);
    }

    #[test]
    fn test_increase_nonce_full_wrap() {
        let mut nonce = [0xFFu8; 12];
        increase_nonce(&mut nonce);
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn test_increase_nonce_sequential() {
        let mut nonce = [0u8; 12];
        for i in 1..=300u16 {
            increase_nonce(&mut nonce);
            // Verify little-endian encoding of i.
            assert_eq!(nonce[0], (i & 0xFF) as u8);
            assert_eq!(nonce[1], (i >> 8) as u8);
        }
    }

    // ── AesEcb round-trip ───────────────────────────────────────────────────

    #[test]
    fn test_aes_ecb_round_trip_128() {
        let key = [0x42u8; 16];
        let ecb = AesEcb::new(&key);
        let original = [0xABu8; 16];
        let mut block = original;
        ecb.encrypt_block(&mut block);
        assert_ne!(block, original, "encryption should change the block");
        ecb.decrypt_block(&mut block);
        assert_eq!(block, original, "decryption should restore the block");
    }

    #[test]
    fn test_aes_ecb_round_trip_256() {
        let key = [0x99u8; 32];
        let ecb = AesEcb::new(&key);
        let original = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let mut block = original;
        ecb.encrypt_block(&mut block);
        assert_ne!(block, original);
        ecb.decrypt_block(&mut block);
        assert_eq!(block, original);
    }

    #[test]
    #[should_panic(expected = "invalid AES key length")]
    fn test_aes_ecb_invalid_key_length() {
        let _ = AesEcb::new(&[0u8; 10]);
    }

    // ── UDP block encryptor/decryptor ───────────────────────────────────────

    #[test]
    fn test_udp_block_encryptor_decryptor_single_psk() {
        let psk = [0x42u8; 16];
        let method = CipherMethod::new(
            "2022-blake3-aes-128-gcm",
            &b64_encode(&psk),
        )
        .unwrap();

        // Single PSK: encryptor and decryptor use the same key.
        let enc = method.udp_block_encryptor();
        let dec = method.udp_block_decryptor();
        let original = [0x55u8; 16];
        let mut block = original;
        enc.encrypt_block(&mut block);
        dec.decrypt_block(&mut block);
        assert_eq!(block, original);
    }

    #[test]
    fn test_udp_block_encryptor_decryptor_multi_psk() {
        let psk0 = [0x01u8; 16];
        let psk1 = [0x02u8; 16];
        let password =
            format!("{}:{}", b64_encode(&psk0), b64_encode(&psk1));
        let method =
            CipherMethod::new("2022-blake3-aes-128-gcm", &password).unwrap();

        // Multi-PSK: encryptor uses psk_list[0], decryptor uses psk_list[last].
        // They use DIFFERENT keys, so cross-round-trip is impossible.
        // Verify each round-trips independently.
        let enc = method.udp_block_encryptor();
        let dec = method.udp_block_decryptor();
        let original = [0x77u8; 16];

        // Encryptor round-trip (same key = psk0)
        let mut block = original;
        enc.encrypt_block(&mut block);
        assert_ne!(block, original, "encryption should change the block");
        enc.decrypt_block(&mut block);
        assert_eq!(block, original, "encryptor round-trip should restore");

        // Decryptor round-trip (same key = psk1)
        let mut block2 = original;
        dec.encrypt_block(&mut block2);
        assert_ne!(block2, original);
        dec.decrypt_block(&mut block2);
        assert_eq!(block2, original, "decryptor round-trip should restore");

        // Different keys produce different ciphertext
        let mut b_enc = original;
        enc.encrypt_block(&mut b_enc);
        let mut b_dec = original;
        dec.encrypt_block(&mut b_dec);
        assert_ne!(b_enc, b_dec, "different keys should produce different ciphertext");
    }

    // ── Constants sanity ────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(OVERHEAD, 16);
        assert_eq!(NONCE_SIZE, 12);
        assert_eq!(MAX_PACKET_SIZE, 16383);
        assert_eq!(MAX_PADDING_LENGTH, 900);
        assert_eq!(REQUEST_HEADER_FIXED_CHUNK_LENGTH, 11);
        assert_eq!(HEADER_TYPE_CLIENT, 0);
        assert_eq!(HEADER_TYPE_SERVER, 1);
        assert_eq!(PACKET_NONCE_SIZE, 24);
        assert_eq!(TIMESTAMP_TOLERANCE_SECS, 30);
    }
}
