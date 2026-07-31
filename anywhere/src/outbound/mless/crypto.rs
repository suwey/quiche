// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Per-frame XOR obfuscation using SHA-256 in CTR-like mode.
//!
//! Each frame is encrypted by XORing with a keystream derived from
//! `SHA-256(key || counter_LE64)`. The 32-byte hash is cyclically
//! repeated to cover the entire payload (`i % 32`), matching the
//! Workers implementation.

use sha2::Digest;
use sha2::Sha256;

/// Per-connection obfuscation state with independent send/recv counters.
pub struct Obfuscation {
    key: [u8; 32],
    send_counter: u64,
    recv_counter: u64,
}

impl Obfuscation {
    /// Derive a 32-byte key from a UUID string.
    ///
    /// Key = SHA-256(uuid_string_with_dashes || "anywhere-obfuscation-v1")
    /// The server (Workers) uses the UUID string (e.g.
    /// "00000000-0000-4000-8000-000000000000"), NOT the raw 16 bytes.
    pub fn new(uuid_str: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(uuid_str.as_bytes());
        hasher.update(b"anywhere-obfuscation-v1");
        let key: [u8; 32] = hasher.finalize().into();

        Self {
            key,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// Expose the derived key for debug logging.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Encrypt `payload`, returning the ciphertext.
    ///
    /// Uses `SHA-256(key || counter_LE64)` cyclically (i % 32).
    /// Increments `send_counter` by one.
    pub fn encrypt(&mut self, payload: &[u8]) -> Vec<u8> {
        let ct = xor_keystream(&self.key, self.send_counter, payload);
        self.send_counter = self.send_counter.wrapping_add(1);
        ct
    }

    /// Decrypt `payload`, returning the plaintext.
    ///
    /// Uses `SHA-256(key || counter_LE64)` cyclically (i % 32).
    /// Increments `recv_counter` by one.
    pub fn decrypt(&mut self, payload: &[u8]) -> Vec<u8> {
        let pt = xor_keystream(&self.key, self.recv_counter, payload);
        self.recv_counter = self.recv_counter.wrapping_add(1);
        pt
    }
}

/// Generate keystream and XOR with `data`.
///
/// Keystream is `SHA-256(key || counter_LE64)` repeated cyclically:
/// `out[i] = data[i] ^ hash[i % 32]`. This matches the Workers
/// implementation which reuses the 32-byte hash for the entire payload.
fn xor_keystream(key: &[u8; 32], counter: u64, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    if data.is_empty() {
        return out;
    }
    let counter_bytes = counter.to_le_bytes();
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(counter_bytes);
    let hash: [u8; 32] = hasher.finalize().into();
    for (i, out_byte) in out.iter_mut().enumerate() {
        *out_byte ^= hash[i % 32];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encrypt then decrypt returns the original payload.
    #[test]
    fn encrypt_then_decrypt() {
        let mut obf = Obfuscation::new("00000000-0000-4000-8000-000000000000");

        let payload = b"Hello, Mless!";
        let ct = obf.encrypt(payload);
        assert_ne!(ct, payload, "ciphertext should differ from plaintext");

        let pt = obf.decrypt(&ct);
        assert_eq!(
            pt, payload,
            "decrypt(encrypt(payload)) should return payload"
        );
    }

    /// Send and recv counters advance independently.
    #[test]
    fn independent_counters() {
        let mut obf = Obfuscation::new("00000000-0000-4000-8000-000000000000");

        let payload = b"test data";
        let ct1 = obf.encrypt(payload);
        let ct2 = obf.encrypt(payload);
        assert_ne!(
            ct1, ct2,
            "different send counters should produce different ciphertext"
        );

        // Decrypt in correct order to match send counters.
        let pt1 = obf.decrypt(&ct1);
        let pt2 = obf.decrypt(&ct2);
        assert_eq!(pt1, payload);
        assert_eq!(pt2, payload);
    }

    /// Different counters produce different ciphertext for same plaintext.
    #[test]
    fn different_counters_different_ct() {
        let mut obf_a = Obfuscation::new("00000000-0000-4000-8000-000000000000");
        let mut obf_b = Obfuscation::new("00000000-0000-4000-8000-000000000000");

        let payload = b"same plaintext";
        let ct_a = obf_a.encrypt(payload);
        let ct_b = obf_b.encrypt(payload);

        // Both start at counter 0, so ciphertexts should be identical.
        assert_eq!(ct_a, ct_b, "same counter should produce same ciphertext");

        let ct_c = obf_b.encrypt(payload);
        assert_ne!(
            ct_a, ct_c,
            "different counter should produce different ciphertext"
        );
    }

    /// Empty payload round-trips correctly.
    #[test]
    fn empty_payload() {
        let mut obf = Obfuscation::new("00000000-0000-4000-8000-000000000000");

        let ct = obf.encrypt(b"");
        assert!(ct.is_empty());

        let pt = obf.decrypt(&ct);
        assert!(pt.is_empty());
    }

    /// Payload longer than one keystream block (32 bytes).
    #[test]
    fn long_payload() {
        let mut obf = Obfuscation::new("00000000-0000-4000-8000-000000000000");

        let payload = b"this is a long payload that spans multiple keystream blocks for testing";
        assert!(payload.len() > 32);

        let ct = obf.encrypt(payload);
        assert_eq!(ct.len(), payload.len());

        let pt = obf.decrypt(&ct);
        assert_eq!(pt, payload);
    }

    /// Deterministic: same key + counter produces same keystream.
    #[test]
    fn deterministic_keystream() {
        let mut obf = Obfuscation::new("00000000-0000-4000-8000-000000000000");

        let payload = b"deterministic test";
        let ct1 = obf.encrypt(payload);
        let ct2 = obf.encrypt(payload);
        assert_ne!(ct1, ct2);

        // A fresh instance with the same uuid produces the same first ciphertext.
        let mut obf2 = Obfuscation::new("00000000-0000-4000-8000-000000000000");
        let ct2_first = obf2.encrypt(payload);
        assert_eq!(ct1, ct2_first);
    }
}

// ---------------------------------------------------------------------------
// CryptoLayer trait implementation
// ---------------------------------------------------------------------------

use crate::crypto::CryptoLayer;

#[async_trait::async_trait]
impl CryptoLayer for Obfuscation {
    async fn encrypt(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        Ok(Obfuscation::encrypt(self, plaintext))
    }

    async fn decrypt(&mut self, ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
        Ok(Obfuscation::decrypt(self, ciphertext))
    }

    fn reset(&mut self) {
        self.send_counter = 0;
        self.recv_counter = 0;
    }
}

// ---------------------------------------------------------------------------
// CryptoLayer trait tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod crypto_trait_tests {
    use super::*;
    use crate::crypto::CryptoLayer;

    #[tokio::test]
    async fn obfuscation_impl_cryptolayer() {
        let obf: &mut dyn CryptoLayer = &mut Obfuscation::new("00000000-0000-4000-8000-000000000000");
        let payload = b"test CryptoLayer trait";

        let ct = obf.encrypt(payload).await.unwrap();
        assert_ne!(ct, payload);

        let pt = obf.decrypt(&ct).await.unwrap();
        assert_eq!(pt, payload);
    }

    #[tokio::test]
    async fn obfuscation_reset() {
        let mut obf = Obfuscation::new("00000000-0000-4000-8000-000000000000");
        let payload = b"reset test";

        // 先加密两次（counter 递增，密文不同）
        let ct1 = CryptoLayer::encrypt(&mut obf, payload).await.unwrap();
        obf.reset();
        let ct2 = CryptoLayer::encrypt(&mut obf, payload).await.unwrap();

        // reset 后 counter 回到 0，应该产生相同的密文
        assert_eq!(ct1, ct2);
    }
}
