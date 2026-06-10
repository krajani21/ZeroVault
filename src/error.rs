use std::fmt;

#[derive(Debug)]
pub enum VaultError {
    KeyDerivation(argon2::Error),
    Encryption,
    // Intentionally doesn't distinguish "wrong password" from "corrupt file" —
    // separating the two would create an authentication oracle.
    Decryption,
    MalformedBlob,
    VaultAlreadyExists,
    Io(std::io::Error),
    Serialization(serde_json::Error),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::KeyDerivation(e) => write!(f, "Key derivation failed: {e}"),
            VaultError::Encryption => write!(f, "Encryption failed"),
            VaultError::Decryption => write!(f, "Wrong master password or vault is corrupt"),
            VaultError::MalformedBlob => write!(f, "Vault data is malformed"),
            VaultError::VaultAlreadyExists => write!(f, "A vault already exists at that path"),
            VaultError::Io(e) => write!(f, "I/O error: {e}"),
            VaultError::Serialization(e) => write!(f, "Serialisation error: {e}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<argon2::Error> for VaultError {
    fn from(e: argon2::Error) -> Self { VaultError::KeyDerivation(e) }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self { VaultError::Io(e) }
}

impl From<serde_json::Error> for VaultError {
    fn from(e: serde_json::Error) -> Self { VaultError::Serialization(e) }
}
