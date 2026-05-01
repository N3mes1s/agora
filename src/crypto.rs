//! Agora cryptographic core.
//!
//! Security properties:
//! - AES-256-GCM authenticated encryption (confidentiality + integrity)
//! - HKDF-SHA256 key derivation from shared secrets
//! - Per-message random 96-bit nonces
//! - Room-specific symmetric keys derived from the shared secret
//! - Zero-knowledge room membership proof (HMAC challenge-response)

use ring::aead::{self, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf::{self, HKDF_SHA256, Salt};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

/// Errors from crypto operations.
#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKey,
    RngFailed,
    SignatureFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed (wrong key or tampered)"),
            Self::InvalidKey => write!(f, "invalid key material"),
            Self::RngFailed => write!(f, "random number generation failed"),
            Self::SignatureFailed => write!(f, "signature operation failed"),
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

// ── Per-Sender Ratchet ─────────────────────────────────────────
//
// Provides no-backward-derivation: once a chain key is advanced,
// previous message keys cannot be derived from the new state.
// Does NOT provide full forward secrecy against room-secret
// compromise (the initial chain is deterministic from room_key +
// sender_id). See PR #12 for the design rationale.

/// Initialize a per-sender chain key from the room key and sender ID.
///
/// Each sender gets a unique starting chain key so multi-sender
/// rooms don't collide or need synchronized counters.
#[cfg_attr(not(test), allow(dead_code))]
pub fn init_sender_chain(room_key: &[u8; 32], sender_id: &str) -> [u8; 32] {
    let salt = Salt::new(HKDF_SHA256, sender_id.as_bytes());
    let prk = salt.extract(room_key);
    let info = [b"agora-ratchet-v1".as_slice()];
    let okm = prk.expand(&info, HkdfLen(32)).expect("HKDF expand failed");
    let mut key = [0u8; 32];
    okm.fill(&mut key).expect("HKDF fill failed");
    key
}

/// Advance the chain key by one step. The old key should be deleted.
#[cfg_attr(not(test), allow(dead_code))]
pub fn advance_chain(chain_key: &[u8; 32]) -> [u8; 32] {
    hkdf_derive(chain_key, b"agora-chain-advance")
}

/// Derive a message encryption key from the current chain key.
/// This key is used for AES-256-GCM for a single message.
#[cfg_attr(not(test), allow(dead_code))]
pub fn derive_msg_key(chain_key: &[u8; 32]) -> [u8; 32] {
    hkdf_derive(chain_key, b"agora-msg-key")
}

// ── Authenticated Encryption ────────────────────────────────────

/// Encrypt with AES-256-GCM.
///
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| CryptoError::RngFailed)?;

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
    let nonce =
        Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| CryptoError::DecryptionFailed)?;

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
    rng.fill(&mut challenge)
        .map_err(|_| CryptoError::RngFailed)?;
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

// ── Message Signing ─────────────────────────────────────────────

pub fn generate_signing_keypair_pkcs8() -> Result<Vec<u8>, CryptoError> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| CryptoError::SignatureFailed)?;
    Ok(pkcs8.as_ref().to_vec())
}

/// Generate an Ed25519 PKCS8 keypair deterministically from a 32-byte seed.
///
/// Uses ring's `Ed25519KeyPair::from_seed_unchecked` to derive the keypair from the
/// raw seed bytes, extracts the public key, then constructs a full RFC 5958 / RFC 8410
/// PKCS8v1 document (version=1, with public key) that ring's `from_pkcs8` accepts.
///
/// Wire format (83 bytes):
///   SEQUENCE(81) {
///     INTEGER(1)                         -- version 1
///     SEQUENCE { OID 1.3.101.112 }       -- Ed25519
///     OCTET STRING { OCTET STRING { seed } }  -- 32-byte seed
///     [1] IMPLICIT BIT STRING { pubkey } -- 33 bytes: 0x00 + 32 pubkey bytes
///   }
pub fn generate_signing_keypair_from_seed(seed: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    // Derive the keypair from the seed to get the matching public key.
    let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| CryptoError::InvalidKey)?;
    let pubkey = pair.public_key().as_ref();

    // Construct PKCS8 v1 (RFC 5958 + RFC 8410) with both seed and public key.
    // This is the format ring generates and accepts via from_pkcs8.
    #[rustfmt::skip]
    let mut pkcs8: Vec<u8> = vec![
        0x30, 0x51,                                     // SEQUENCE, length 81
        0x02, 0x01, 0x01,                               // INTEGER 1 (version)
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,      // SEQUENCE { OID 1.3.101.112 }
        0x04, 0x22, 0x04, 0x20,                         // OCTET STRING(34) { OCTET STRING(32) }
    ];
    pkcs8.extend_from_slice(seed); // 32-byte private key seed
    pkcs8.extend_from_slice(&[0x81, 0x21, 0x00]); // [1] IMPLICIT BIT STRING(33), no unused bits
    pkcs8.extend_from_slice(pubkey); // 32-byte compressed Edwards point

    // Validate round-trip before returning.
    Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| CryptoError::InvalidKey)?;
    Ok(pkcs8)
}

pub fn signing_public_key(pkcs8: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| CryptoError::InvalidKey)?;
    Ok(pair.public_key().as_ref().to_vec())
}

pub fn sign_message(pkcs8: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| CryptoError::InvalidKey)?;
    Ok(pair.sign(message).as_ref().to_vec())
}

pub fn verify_message_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let verifier = UnparsedPublicKey::new(&ED25519, public_key);
    verifier.verify(message, signature).is_ok()
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
    fn test_init_sender_chain_deterministic() {
        let rk = derive_room_key("s", "r");
        let c1 = init_sender_chain(&rk, "alice");
        let c2 = init_sender_chain(&rk, "alice");
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_init_sender_chain_different_senders() {
        let rk = derive_room_key("s", "r");
        let c1 = init_sender_chain(&rk, "alice");
        let c2 = init_sender_chain(&rk, "bob");
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_advance_chain_unique() {
        let rk = derive_room_key("s", "r");
        let mut ck = init_sender_chain(&rk, "alice");
        let mut seen = vec![ck];
        for _ in 0..10 {
            ck = advance_chain(&ck);
            assert!(!seen.contains(&ck));
            seen.push(ck);
        }
    }

    #[test]
    fn test_msg_key_differs_from_chain_key() {
        let rk = derive_room_key("s", "r");
        let ck = init_sender_chain(&rk, "alice");
        let mk = derive_msg_key(&ck);
        assert_ne!(ck, mk);
    }

    #[test]
    fn test_msg_key_changes_after_advance() {
        let rk = derive_room_key("s", "r");
        let ck0 = init_sender_chain(&rk, "alice");
        let mk0 = derive_msg_key(&ck0);
        let ck1 = advance_chain(&ck0);
        let mk1 = derive_msg_key(&ck1);
        assert_ne!(mk0, mk1);
    }

    #[test]
    fn test_encrypt_with_msg_key() {
        let rk = derive_room_key("s", "r");
        let ck = init_sender_chain(&rk, "alice");
        let mk = derive_msg_key(&ck);
        let blob = encrypt(b"hello ratchet", &mk, b"room").unwrap();
        let pt = decrypt(&blob, &mk, b"room").unwrap();
        assert_eq!(pt, b"hello ratchet");
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
    fn test_sign_and_verify_roundtrip() {
        let pkcs8 = generate_signing_keypair_pkcs8().unwrap();
        let public_key = signing_public_key(&pkcs8).unwrap();
        let msg = b"agora signed payload";
        let sig = sign_message(&pkcs8, msg).unwrap();
        assert!(verify_message_signature(&public_key, msg, &sig));
    }

    #[test]
    fn test_wrong_signing_key_fails_verification() {
        let pkcs8_a = generate_signing_keypair_pkcs8().unwrap();
        let pkcs8_b = generate_signing_keypair_pkcs8().unwrap();
        let public_key_b = signing_public_key(&pkcs8_b).unwrap();
        let msg = b"agora signed payload";
        let sig_a = sign_message(&pkcs8_a, msg).unwrap();
        assert!(!verify_message_signature(&public_key_b, msg, &sig_a));
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

    #[test]
    fn seed_keypair_is_deterministic() {
        let seed = [0x42u8; 32];
        let pkcs8_a = generate_signing_keypair_from_seed(&seed).unwrap();
        let pkcs8_b = generate_signing_keypair_from_seed(&seed).unwrap();
        assert_eq!(pkcs8_a, pkcs8_b, "same seed must produce same PKCS8");
    }

    #[test]
    fn seed_keypair_different_seeds_differ() {
        let seed_a = [0x01u8; 32];
        let seed_b = [0x02u8; 32];
        let pkcs8_a = generate_signing_keypair_from_seed(&seed_a).unwrap();
        let pkcs8_b = generate_signing_keypair_from_seed(&seed_b).unwrap();
        assert_ne!(
            pkcs8_a, pkcs8_b,
            "different seeds must produce different keypairs"
        );
    }

    #[test]
    fn seed_keypair_produces_valid_signing_key() {
        let seed = [0xabu8; 32];
        let pkcs8 = generate_signing_keypair_from_seed(&seed).unwrap();
        let pubkey = signing_public_key(&pkcs8).unwrap();
        let msg = b"test message for signing";
        let sig = sign_message(&pkcs8, msg).unwrap();
        assert!(
            verify_message_signature(&pubkey, msg, &sig),
            "seed-derived key must sign/verify"
        );
    }

    #[test]
    fn seed_keypair_differs_from_random_keypair() {
        let seed = [0x55u8; 32];
        let seed_pkcs8 = generate_signing_keypair_from_seed(&seed).unwrap();
        let random_pkcs8 = generate_signing_keypair_pkcs8().unwrap();
        assert_ne!(
            seed_pkcs8, random_pkcs8,
            "seed-derived must differ from random"
        );
    }
}
