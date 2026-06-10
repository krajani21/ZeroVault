# ZeroVault

A lightweight, offline command-line password manager engineered around the principle that **the host machine should never be trusted with plaintext secrets**. Every byte of sensitive data is encrypted with authenticated encryption before touching disk, and every plaintext key or password is erased from RAM as soon as it is no longer needed.

> Built from scratch in Rust as a security engineering project — no vendor lock-in, no cloud sync, no attack surface beyond what is necessary.

---

## Security Architecture

The threat model assumes an attacker can read the vault file at any time (e.g. via backups, disk imaging, or a stolen laptop). The design choices below ensure that reading the file without the master password yields nothing useful.

### 1. Memory Safety — `zeroize`

Rust's ownership model prevents use-after-free and buffer overflows at compile time. On top of that, every struct that holds a plaintext key or password derives [`ZeroizeOnDrop`](https://docs.rs/zeroize), which overwrites the backing memory with zeros the instant the value goes out of scope — before the allocator can reclaim it. This defeats forensic memory dumps and cold-boot attacks.

```
MasterKey([u8; 32]) ──► ZeroizeOnDrop ──► heap memory wiped on drop
PlaintextCredential { password: String } ──► same guarantee
```

### 2. Key Derivation — Argon2id

The master key is **never stored**. It is re-derived from the master password on every unlock using **Argon2id** (RFC 9106), the winner of the 2015 Password Hashing Competition.

| Parameter | Value | Rationale |
|---|---|---|
| Algorithm | Argon2id | Combines Argon2i (side-channel hardness) and Argon2d (GPU/ASIC hardness) |
| Memory cost | 64 MB | Makes parallel brute-force on GPUs extremely expensive |
| Time cost | 3 iterations | Adds sequential work on top of memory hardness |
| Salt | 16 bytes, random | Prevents rainbow-table and cross-user attacks |
| Output | 32 bytes | Exact key size for AES-256 / ChaCha20 |

A random salt is generated at vault creation time and stored unencrypted alongside the ciphertext — it is not a secret.

### 3. Authenticated Encryption — ChaCha20-Poly1305

The vault payload is encrypted with **ChaCha20-Poly1305** (RFC 8439), a modern AEAD (Authenticated Encryption with Associated Data) cipher.

- **ChaCha20** is a stream cipher that is provably constant-time in pure software — no secret-dependent branches, no AES-NI hardware dependency.
- **Poly1305** is a one-time MAC that authenticates the ciphertext. Any single-bit modification to the file causes decryption to fail with an explicit authentication error before any plaintext is returned.
- A fresh **12-byte random nonce** is generated per encryption, making ciphertext non-deterministic even for identical inputs.

The on-disk vault format is intentionally minimal:

```
[ 16 bytes: Argon2id salt ][ 12 bytes: ChaCha20 nonce ][ N bytes: ciphertext + 16-byte Poly1305 tag ]
```

---

## Project Structure

```
zerovault/
├── Cargo.toml          # Dependencies and crate metadata
└── src/
    ├── main.rs         # CLI entry point (clap argument parser)
    ├── crypto.rs       # Cryptographic engine: KDF, encrypt, decrypt
    └── error.rs        # Unified error type across all modules
```

Future phases will add:

```
    ├── vault.rs        # Vault file: serialise/deserialise the on-disk format
    └── store.rs        # Credential CRUD: add, list, get, delete
```

---

## Building

```bash
# Requires Rust stable (1.70+)
git clone https://github.com/<you>/zerovault
cd zerovault
cargo build --release
./target/release/zerovault --help
```

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| 0 | ✅ Done | Repository setup, README, security architecture |
| 1 | ✅ Done | Cryptographic engine (`crypto.rs`): KDF + AEAD roundtrip |
| 2 | 🔲 Next | Vault file I/O: `init`, `unlock`, `save` |
| 3 | 🔲 Planned | Credential CRUD: `add`, `list`, `get`, `delete` |
| 4 | 🔲 Planned | Clipboard integration and TTY-only password prompts |
| 5 | 🔲 Planned | Export / import; TOTP seed storage |

---

## License

MIT — see [LICENSE](LICENSE).
