use std::fs::{self, File};
use std::io::Write;
use std::process::Command;

#[test]
fn encrypt_decrypt_roundtrip() {
    let input_file = "test_data.txt";
    let password = "test-password";

    // Create a file
    let mut f = File::create(input_file).expect("Failed to create input file");
    writeln!(f, "Top secret!").expect("Failed to write input");

    // Encrypt
    let status = Command::new("cargo")
        .args(["run", "--", "encrypt", "--file", input_file])
        .env("CRYPTDOC_PASSWORD", password)
        .status()
        .expect("Failed to run encryption");

    assert!(status.success());

    let enc_file = format!("{input_file}.enc");
    assert!(fs::metadata(&enc_file).is_ok());

    // Decrypt
    let status = Command::new("cargo")
        .args(["run", "--", "decrypt", "--file", &enc_file])
        .env("CRYPTDOC_PASSWORD", password)
        .status()
        .expect("Failed to run decryption");

    assert!(status.success());

    let dec_file = format!("{enc_file}.dec");
    let decrypted = fs::read_to_string(&dec_file).expect("Failed to read decrypted file");

    assert_eq!(decrypted.trim(), "Top secret!");

    // Cleanup
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(&enc_file);
    let _ = fs::remove_file(&dec_file);
}
