# cryptdoc

A fast, secure, local-first file encryption CLI written in Rust, using AES-256-GCM authenticated encryption with HMAC-SHA256 for tamper detection and PBKDF2-based password-derived keys.

---

## Required
rustc ^v1.87.0

## Features

- 🔒 AES-256-GCM encryption (authenticated)
- 🧂 PBKDF2 key derivation with SHA-256 and salt
- 🔐 HMAC-SHA256 message authentication to detect tampering
- 🗂️ JSON metadata with versioning
- ✅ Dual format support: JSON + raw legacy format
- 🔐 Secure password prompt with [rpassword](https://docs.rs/rpassword)
- 🧪 Integration test support with `CRYPTDOC_PASSWORD` env var
- 🧹 Clean and minimal CLI, no third-party services or cloud dependencies


## Usage

```bash
# Run tests
cargo test

# Quick execution
cargo run -- encrypt --file secrets.txt
cargo run -- decrypt --file secrets.txt.enc

# Build 
cargo build --release

# Build execution
# encrypt file
./target/release/cryptdoc encrypt --file myfile.txt
# decrypt file
./target/release/cryptdoc decrypt --file myfile.txt.enc



