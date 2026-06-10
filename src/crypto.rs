use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::VaultError;

const ARGON2_MEMORY_KIB: u32 = 64 * 1024; // 64 MB — limits GPU parallelism to ~375 guesses on a 24 GB card
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// 256-bit master key. ZeroizeOnDrop overwrites the 32 bytes before the
/// allocator reclaims them, defeating forensic memory dumps.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

/// A single vault entry. ZeroizeOnDrop scrubs the String heap buffers on drop.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Credential {
    pub label: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub notes: String,
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives a MasterKey using Argon2id (RFC 9106).
/// Argon2id = Argon2i (cache-timing resistant) + Argon2d (GPU/ASIC resistant).
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<MasterKey, VaultError> {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(KEY_LEN))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; KEY_LEN];
    argon2.hash_password_into(password, salt, &mut key_bytes)?;
    Ok(MasterKey(key_bytes))
}

/// Encrypts plaintext with ChaCha20-Poly1305 and returns `nonce (12) || ciphertext+tag`.
/// ChaCha20 is constant-time in pure software — no AES-NI hardware required.
/// A fresh random nonce is generated per call; never reuse a (key, nonce) pair.
pub fn encrypt(key: &MasterKey, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| VaultError::Encryption)?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypts a blob from `encrypt`. Poly1305 authenticates before returning any
/// plaintext — a single flipped bit causes a clean error, not garbled output.
/// Returns Zeroizing<Vec<u8>> so the plaintext heap buffer is wiped on drop.
pub fn decrypt(key: &MasterKey, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if blob.len() < NONCE_LEN {
        return Err(VaultError::MalformedBlob);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| VaultError::Decryption)?;
    Ok(Zeroizing::new(plaintext))
}

pub fn seal_credentials(key: &MasterKey, creds: &[Credential]) -> Result<Vec<u8>, VaultError> {
    let json = Zeroizing::new(serde_json::to_vec(creds)?);
    encrypt(key, &json)
}

pub fn open_credentials(key: &MasterKey, blob: &[u8]) -> Result<Vec<Credential>, VaultError> {
    let plaintext = decrypt(key, blob)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let salt = generate_salt();
        let key = derive_key(b"test-password", &salt).unwrap();
        let blob = encrypt(&key, b"hello zerovault").unwrap();
        assert_eq!(&*decrypt(&key, &blob).unwrap(), b"hello zerovault");
    }

    #[test]
    fn wrong_key_fails() {
        let salt = generate_salt();
        let key_a = derive_key(b"correct", &salt).unwrap();
        let key_b = derive_key(b"wrong", &salt).unwrap();
        let blob = encrypt(&key_a, b"secret").unwrap();
        assert!(matches!(decrypt(&key_b, &blob), Err(VaultError::Decryption)));
    }

    #[test]
    fn bitflip_fails() {
        let salt = generate_salt();
        let key = derive_key(b"password", &salt).unwrap();
        let mut blob = encrypt(&key, b"data").unwrap();
        blob[NONCE_LEN + 1] ^= 0xFF;
        assert!(matches!(decrypt(&key, &blob), Err(VaultError::Decryption)));
    }

    #[test]
    fn credential_roundtrip() {
        let salt = generate_salt();
        let key = derive_key(b"vault-password", &salt).unwrap();
        let creds = vec![Credential {
            label: "GitHub".into(),
            username: "alice".into(),
            password: "tok_abc123".into(),
            notes: String::new(),
        }];
        let blob = seal_credentials(&key, &creds).unwrap();
        let out = open_credentials(&key, &blob).unwrap();
        assert_eq!(out[0].password, "tok_abc123");
    }
}
