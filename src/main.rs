mod crypto;
mod error;

use crypto::{derive_key, generate_salt, open_credentials, seal_credentials, Credential};
use zeroize::Zeroizing;

fn main() {
    // Phase 1: prove the full crypto pipeline compiles and produces a correct roundtrip.
    // Password input and file I/O are Phase 2+.
    let master_password = Zeroizing::new(b"correct horse battery staple".to_vec());

    let salt = generate_salt();
    let key = derive_key(&master_password, &salt).expect("key derivation failed");

    let creds = vec![
        Credential {
            label: "GitHub".into(),
            username: "alice".into(),
            password: "ghp_abc123".into(),
            notes: String::new(),
        },
        Credential {
            label: "Email".into(),
            username: "alice@example.com".into(),
            password: "hunter2".into(),
            notes: "recovery codes in safe".into(),
        },
    ];

    let blob = seal_credentials(&key, &creds).expect("encryption failed");
    println!("Sealed vault: {} bytes", blob.len());

    let recovered = open_credentials(&key, &blob).expect("decryption failed");
    for c in &recovered {
        println!("[{}] {} / {}", c.label, c.username, c.password);
    }

    // key, creds, recovered, and master_password are all zeroized on drop here.
}
