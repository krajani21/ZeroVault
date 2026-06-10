mod crypto;
mod error;
mod vault;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vault::Vault;
use crypto::Credential;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "zerovault", about = "Offline CLI password manager")]
struct Cli {
    /// Path to the vault file
    #[arg(short, long, default_value = "vault.zv")]
    vault: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault
    Init,
    /// Add a new credential entry
    Add {
        #[arg(short, long)]
        label: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long, default_value = "")]
        notes: String,
    },
    /// List all stored labels
    List,
    /// Show credentials for a label
    Get { label: String },
    /// Delete a credential by label
    Delete { label: String },
}

fn prompt(msg: &str) -> Zeroizing<String> {
    Zeroizing::new(rpassword::prompt_password(msg).expect("failed to read input"))
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), error::VaultError> {
    match cli.command {
        Command::Init => {
            let pw = prompt("New master password: ");
            let confirm = prompt("Confirm master password: ");
            if *pw != *confirm {
                eprintln!("Passwords do not match.");
                std::process::exit(1);
            }
            Vault::init(&cli.vault, pw.as_bytes())?;
            println!("Vault created: {}", cli.vault.display());
        }

        Command::Add { label, username, notes } => {
            let pw = prompt("Master password: ");
            let cred_pw = prompt(&format!("Password for [{label}]: "));
            let mut vault = Vault::open(&cli.vault, pw.as_bytes())?;
            vault.credentials.push(Credential {
                label,
                username,
                password: cred_pw.as_str().to_owned(),
                notes,
            });
            vault.save()?;
            println!("Credential added.");
        }

        Command::List => {
            let pw = prompt("Master password: ");
            let vault = Vault::open(&cli.vault, pw.as_bytes())?;
            if vault.credentials.is_empty() {
                println!("No credentials stored.");
            } else {
                for (i, c) in vault.credentials.iter().enumerate() {
                    println!("[{}] {}", i + 1, c.label);
                }
            }
        }

        Command::Get { label } => {
            let pw = prompt("Master password: ");
            let vault = Vault::open(&cli.vault, pw.as_bytes())?;
            match vault.credentials.iter().find(|c| c.label.eq_ignore_ascii_case(&label)) {
                Some(c) => {
                    println!("Label:    {}", c.label);
                    println!("Username: {}", c.username);
                    println!("Password: {}", c.password);
                    if !c.notes.is_empty() {
                        println!("Notes:    {}", c.notes);
                    }
                }
                None => println!("No credential found for '{label}'."),
            }
        }

        Command::Delete { label } => {
            let pw = prompt("Master password: ");
            let mut vault = Vault::open(&cli.vault, pw.as_bytes())?;
            let before = vault.credentials.len();
            vault.credentials.retain(|c| !c.label.eq_ignore_ascii_case(&label));
            if vault.credentials.len() == before {
                println!("No credential found for '{label}'.");
            } else {
                vault.save()?;
                println!("Deleted '{label}'.");
            }
        }
    }
    Ok(())
}
