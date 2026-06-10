use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{self, Credential, MasterKey, SALT_LEN};
use crate::error::VaultError;

// On-disk format: [ salt (16) ][ nonce (12) ][ ciphertext + Poly1305 tag (N+16) ]
// The salt is not secret — it only needs to be unique per vault.
// The nonce is embedded inside the blob returned by crypto::seal_credentials.

pub struct Vault {
    path: PathBuf,
    salt: [u8; SALT_LEN],
    key: MasterKey, // ZeroizeOnDrop: wiped when Vault is dropped
    pub credentials: Vec<Credential>,
}

impl Vault {
    /// Creates a new empty vault file. Returns an error if the file already exists.
    pub fn init(path: &Path, password: &[u8]) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::VaultAlreadyExists);
        }
        let salt = crypto::generate_salt();
        let key = crypto::derive_key(password, &salt)?;
        let vault = Vault {
            path: path.to_path_buf(),
            salt,
            key,
            credentials: Vec::new(),
        };
        vault.save()?;
        Ok(vault)
    }

    /// Reads and decrypts an existing vault file.
    pub fn open(path: &Path, password: &[u8]) -> Result<Self, VaultError> {
        let bytes = fs::read(path)?;
        if bytes.len() < SALT_LEN {
            return Err(VaultError::MalformedBlob);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[..SALT_LEN]);
        let key = crypto::derive_key(password, &salt)?;
        let credentials = crypto::open_credentials(&key, &bytes[SALT_LEN..])?;
        Ok(Vault { path: path.to_path_buf(), salt, key, credentials })
    }

    /// Re-encrypts all credentials and writes the vault file.
    /// Writes to a .tmp file first, then renames — avoids corrupting the vault
    /// if the process is killed mid-write.
    pub fn save(&self) -> Result<(), VaultError> {
        let blob = crypto::seal_credentials(&self.key, &self.credentials)?;
        let mut out = Vec::with_capacity(SALT_LEN + blob.len());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&blob);
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, &out)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}
