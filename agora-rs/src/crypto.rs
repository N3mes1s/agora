//! Agora cryptographic core.
//!
//! Security properties:
//! - AES-256-GCM authenticated encryption (confidentiality + integrity)
//! - HKDF-SHA256 key derivation from shared secrets
//! - Per-message random 96-bit nonces
//! - Forward secrecy via hash ratchet
//! - Zero-knowledge room membership proof (HMAC challenge-response)

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, NONCE_LEN};
use ring::hkdf::{self, Salt, HKDF_SHA256};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

/// Errors from crypto operations.
#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKey,
    RngFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed (wrong key or tampered)"),
            Self::InvalidKey => write!(f, "invalid key material"),
            Self::RngFailed => write!(f, "random number generation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

// ── Key Derivation ──────────────────────────────────────────────

/// Derive a 256-bit room key from a shared secret using HKDF-SHA256.
///
/// The room_id is used as salt so the same secret produces different
/// keys for different rooms, preventing cross-room key reuse.
pub fn derive_room_key(shared_secret: &str, room_id: &str) -> [u8; 32] {
    let salt = Salt::new(HKDF_SHA256, room_id.as_bytes());
    let prk = salt.extract(shared_secret.as_bytes());
    let info = [b"agora-room-key-v1".as_slice()];
    let okm = prk.expand(&info, HkdfLen(32)).expect("HKDF expand failed");
    let mut key = [0u8; 32];
    okm.fill(&mut key).expect("HKDF fill failed");
    key
}

/// Derive separate encryption and MAC keys from the room key.
pub fn derive_message_keys(room_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let enc_key = hkdf_derive(room_key, b"agora-enc-v1");
    let mac_key = hkdf_derive(room_key, b"agora-mac-v1");
    (enc_key, mac_key)
}

/// Single HKDF derivation helper.
fn hkdf_derive(ikm: &[u8], info_label: &[u8]) -> [u8; 32] {
    let salt = Salt::new(HKDF_SHA256, &[]);
    let prk = salt.extract(ikm);
    let info = [info_label];
    let okm = prk.expand(&info, HkdfLen(32)).expect("HKDF expand failed");
    let mut out = [0u8; 32];
    okm.fill(&mut out).expect("HKDF fill failed");
    out
}

/// Advance key one step forward using hash ratchet for forward secrecy.
pub fn ratchet_key(current: &[u8; 32]) -> [u8; 32] {
    hkdf_derive(current, b"agora-ratchet-v1")
}

// ── Authenticated Encryption ────────────────────────────────────

/// Encrypt with AES-256-GCM.
///
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes).map_err(|_| CryptoError::RngFailed)?;

    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| CryptoError::InvalidKey)?;
    let sealing_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Prepend nonce
    let mut result = Vec::with_capacity(NONCE_LEN + in_out.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&in_out);
    Ok(result)
}

/// Decrypt AES-256-GCM.
///
/// Input: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn decrypt(blob: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN + aead::AES_256_GCM.tag_len() {
        return Err(CryptoError::DecryptionFailed);
    }

    let (nonce_bytes, ciphertext_with_tag) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| CryptoError::DecryptionFailed)?;

    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| CryptoError::InvalidKey)?;
    let opening_key = LessSafeKey::new(unbound);

    let mut in_out = ciphertext_with_tag.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}

// ── Zero-Knowledge Membership Proof ─────────────────────────────

/// Create a ZKP commitment. Returns (nonce, commitment).
pub fn zkp_create_commitment(room_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce).map_err(|_| CryptoError::RngFailed)?;

    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, room_key);
    let tag = hmac::sign(&hmac_key, &nonce);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(tag.as_ref());

    Ok((nonce, commitment))
}

/// Create a random challenge.
pub fn zkp_create_challenge() -> Result<[u8; 32], CryptoError> {
    let rng = SystemRandom::new();
    let mut challenge = [0u8; 32];
    rng.fill(&mut challenge).map_err(|_| CryptoError::RngFailed)?;
    Ok(challenge)
}

/// Respond to a ZKP challenge.
pub fn zkp_respond(room_key: &[u8; 32], nonce: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, room_key);
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(nonce);
    data.extend_from_slice(challenge);
    let tag = hmac::sign(&hmac_key, &data);
    let mut response = [0u8; 32];
    response.copy_from_slice(tag.as_ref());
    response
}

/// Verify a ZKP response.
pub fn zkp_verify(
    room_key: &[u8; 32],
    nonce: &[u8; 32],
    challenge: &[u8; 32],
    response: &[u8; 32],
) -> bool {
    // Use HMAC verification for constant-time comparison
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, room_key);
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(nonce);
    data.extend_from_slice(challenge);
    hmac::verify(&hmac_key, &data, response).is_ok()
}

// ── Utilities ───────────────────────────────────────────────────

/// Generate a random room ID.
pub fn generate_room_id() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes).expect("RNG failed");
    format!("ag-{}", hex::encode(bytes))
}

/// Generate a 256-bit shared secret as hex.
pub fn generate_secret() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("RNG failed");
    hex::encode(bytes)
}

/// Human-readable key fingerprint for out-of-band verification.
pub fn fingerprint(key: &[u8; 32]) -> String {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, key);
    let hex_str = hex::encode(&hash.as_ref()[..16]);
    hex_str
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

// ── HKDF length helper ──────────────────────────────────────────

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_room_key_deterministic() {
        let k1 = derive_room_key("secret", "room-a");
        let k2 = derive_room_key("secret", "room-a");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_room_key_different_rooms() {
        let k1 = derive_room_key("secret", "room-a");
        let k2 = derive_room_key("secret", "room-b");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_room_key_different_secrets() {
        let k1 = derive_room_key("secret1", "room");
        let k2 = derive_room_key("secret2", "room");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_message_keys_separate() {
        let room_key = derive_room_key("secret", "room");
        let (enc, mac) = derive_message_keys(&room_key);
        assert_ne!(enc, mac);
    }

    #[test]
    fn test_ratchet_advances() {
        let key = derive_room_key("s", "r");
        let next = ratchet_key(&key);
        assert_ne!(key, next);
    }

    #[test]
    fn test_ratchet_chain_unique() {
        let mut key = derive_room_key("s", "r");
        let mut seen = vec![key];
        for _ in 0..10 {
            key = ratchet_key(&key);
            assert!(!seen.contains(&key));
            seen.push(key);
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = derive_room_key("secret", "room");
        let (enc_key, _) = derive_message_keys(&key);
        let plaintext = b"Hello, world!";
        let blob = encrypt(plaintext, &enc_key, b"room").unwrap();
        let result = decrypt(&blob, &enc_key, b"room").unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let k1 = derive_room_key("s1", "r");
        let k2 = derive_room_key("s2", "r");
        let (ek1, _) = derive_message_keys(&k1);
        let (ek2, _) = derive_message_keys(&k2);
        let blob = encrypt(b"test", &ek1, b"").unwrap();
        assert!(decrypt(&blob, &ek2, b"").is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = derive_room_key("s", "r");
        let (ek, _) = derive_message_keys(&key);
        let mut blob = encrypt(b"test", &ek, b"").unwrap();
        blob[20] ^= 0xFF;
        assert!(decrypt(&blob, &ek, b"").is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = derive_room_key("s", "r");
        let (ek, _) = derive_message_keys(&key);
        let blob = encrypt(b"test", &ek, b"room-a").unwrap();
        assert!(decrypt(&blob, &ek, b"room-b").is_err());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = derive_room_key("s", "r");
        let (ek, _) = derive_message_keys(&key);
        let b1 = encrypt(b"test", &ek, b"").unwrap();
        let b2 = encrypt(b"test", &ek, b"").unwrap();
        assert_ne!(&b1[..12], &b2[..12]);
    }

    #[test]
    fn test_zkp_valid_proof() {
        let key = derive_room_key("s", "r");
        let (nonce, _commitment) = zkp_create_commitment(&key).unwrap();
        let challenge = zkp_create_challenge().unwrap();
        let response = zkp_respond(&key, &nonce, &challenge);
        assert!(zkp_verify(&key, &nonce, &challenge, &response));
    }

    #[test]
    fn test_zkp_wrong_key_fails() {
        let k1 = derive_room_key("s1", "r");
        let k2 = derive_room_key("s2", "r");
        let (nonce, _) = zkp_create_commitment(&k1).unwrap();
        let challenge = zkp_create_challenge().unwrap();
        let response = zkp_respond(&k1, &nonce, &challenge);
        assert!(!zkp_verify(&k2, &nonce, &challenge, &response));
    }

    #[test]
    fn test_room_id_format() {
        let id = generate_room_id();
        assert!(id.starts_with("ag-"));
        assert_eq!(id.len(), 19);
    }

    #[test]
    fn test_secret_length() {
        let s = generate_secret();
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn test_fingerprint_format() {
        let key = derive_room_key("s", "r");
        let fp = fingerprint(&key);
        let parts: Vec<&str> = fp.split(' ').collect();
        assert_eq!(parts.len(), 8);
        assert!(parts.iter().all(|p| p.len() == 4));
    }
}
