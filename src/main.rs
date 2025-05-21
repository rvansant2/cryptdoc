use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::KeyInit;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use clap::{Parser, Subcommand};
use rand::RngCore;
use anyhow::{Result, anyhow};
use std::fs;
use rpassword::prompt_password;
use serde::{Serialize, Deserialize};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long)]
        file: String,
    },
    Decrypt {
        #[arg(short, long)]
        file: String,
    },
}

#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    version: String,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    hmac: Vec<u8>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt { file } => {
            let password = prompt_for_password()?;
            encrypt_file(file, &password)
        }
        Commands::Decrypt { file } => {
            let password = prompt_for_password()?;
            decrypt_file(file, &password)
        }
    }
}

fn prompt_for_password() -> Result<String> {
    let password = match std::env::var("CRYPTDOC_PASSWORD") {
        Ok(p) => p,
        Err(_) => prompt_password("Enter password: ")?,
    };
    Ok(password)
}

fn encrypt_file(file_path: &str, password: &str) -> Result<()> {
    let plaintext = fs::read(file_path)?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(&key.into());
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| anyhow!("Encryption failed"))?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key)?;
    mac.update(&ciphertext);
    let hmac = mac.finalize().into_bytes().to_vec();

    let encrypted = EncryptedFile {
        version: "1.0".into(),
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
        hmac,
    };

    let json = serde_json::to_vec_pretty(&encrypted)?;
    let out_path = format!("{file_path}.enc");
    fs::write(&out_path, json)?;
    println!("✅ Encrypted to {out_path}");
    Ok(())
}

fn decrypt_file(file_path: &str, password: &str) -> Result<()> {
    let data = fs::read(file_path)?;

    if data.starts_with(b"{") {
        // JSON format
        let encrypted: EncryptedFile = serde_json::from_slice(&data)
            .map_err(|e| anyhow!("Failed to parse encrypted file as JSON: {e}"))?;

        if encrypted.version != "1.0" {
            return Err(anyhow!("Unsupported file version"));
        }

        let key = derive_key(password, &encrypted.salt)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key)?;
        mac.update(&encrypted.ciphertext);
        mac.verify_slice(&encrypted.hmac)
            .map_err(|_| anyhow!("HMAC verification failed"))?;

        let cipher = Aes256Gcm::new(&key.into());
        let plaintext = cipher.decrypt(Nonce::from_slice(&encrypted.nonce), encrypted.ciphertext.as_ref())
            .map_err(|_| anyhow!("Decryption failed"))?;

        let out_path = format!("{file_path}.dec");
        fs::write(&out_path, plaintext)?;
        println!("✅ Decrypted to {out_path} (JSON format)");
    } else {
        // 🧾 Legacy raw format
        if data.len() < SALT_LEN + NONCE_LEN {
            return Err(anyhow!("Encrypted file is too short"));
        }

        let salt = &data[..SALT_LEN];
        let nonce = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
        let ciphertext = &data[SALT_LEN + NONCE_LEN..];

        let key = derive_key(password, salt)?;
        let cipher = Aes256Gcm::new(&key.into());
        let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow!("Decryption failed"))?;

        let out_path = format!("{file_path}.dec");
        fs::write(&out_path, plaintext)?;
        println!("✅ Decrypted to {out_path} (raw legacy format)");
    }

    Ok(())
}


fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    Ok(key)
}
