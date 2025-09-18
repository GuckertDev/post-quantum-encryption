use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::io::Write;
use tempfile::{tempdir, NamedTempFile};
// Removed direct imports of internal modules as integration tests
// should focus on the public interface (the binary).
use anyhow::Result;
use std::process::{Command, Stdio};

const EXT: &str = "mlkem";

// --- CLI Integration Tests ---

#[test]
fn test_cli_help() -> Result<()> {
    let mut cmd = Command::cargo_bin("pqe")?;
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Encrypts a file or folder"));
    Ok(())
}

#[test]
fn test_cli_version() -> Result<()> {
    let mut cmd = Command::cargo_bin("pqe")?;
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
    Ok(())
}


#[test]
fn test_cli_file_not_found() -> Result<()> {
    let mut cmd = Command::cargo_bin("pqe")?;
    cmd.args(&["encrypt", "-f", "nonexistent-file-12345.txt", "-m", "copy"]);
    cmd.assert()
        .failure()
        // Check for the context-aware error message from file_ops.rs
        .stderr(predicate::str::contains("Failed to read file: nonexistent-file-12345.txt"));
    Ok(())
}

#[test]
fn test_cli_encrypt_decrypt_cycle_replace() -> Result<()> {
    let mut temp_file = NamedTempFile::new()?;
    let content = "This is a test file for pqe.";
    writeln!(temp_file, "{}", content)?;
    let file_path = temp_file.path().to_path_buf();

    // Encrypt (Replace)
    Command::cargo_bin("pqe")?
        .args(&["encrypt", "-f", file_path.to_str().unwrap(), "-m", "replace"])
        .assert()
        .success();

    let encrypted_path = file_path.with_extension(EXT);
    assert!(encrypted_path.exists());
    assert!(!file_path.exists()); // Original should be gone

    // Decrypt (Replace)
    Command::cargo_bin("pqe")?
        .args(&["decrypt", "-f", encrypted_path.to_str().unwrap(), "-m", "replace"])
        .assert()
        .success();

    assert!(file_path.exists()); // Original name restored (based on metadata)
    assert!(!encrypted_path.exists()); // Encrypted file gone

    let decrypted_content = fs::read_to_string(file_path)?;
    assert_eq!(decrypted_content.trim(), content);

    Ok(())
}

#[test]
fn test_cli_encrypt_decrypt_cycle_copy() -> Result<()> {
    let mut temp_file = NamedTempFile::new()?;
    let content = "Copy mode test.";
    writeln!(temp_file, "{}", content)?;
    let file_path = temp_file.path().to_path_buf();

    // Encrypt (Copy)
    Command::cargo_bin("pqe")?
        .args(&["encrypt", "-f", file_path.to_str().unwrap(), "-m", "copy"])
        .assert()
        .success();

    let encrypted_path = file_path.with_extension(EXT);
    assert!(encrypted_path.exists());
    assert!(file_path.exists()); // Original should remain

    // Decrypt (Copy)
    Command::cargo_bin("pqe")?
        .args(&["decrypt", "-f", encrypted_path.to_str().unwrap(), "-m", "copy"])
        .assert()
        .success();

    // Decryption in copy mode defaults to the original filename path (overwriting the original temp file).
    let decrypted_content = fs::read_to_string(&file_path)?;
    assert_eq!(decrypted_content.trim(), content);

    // Cleanup
    fs::remove_file(encrypted_path)?;

    Ok(())
}


// This test requires interactive input (TTY) simulation for the passphrase prompt.
// It is excluded from coverage runs (tarpaulin_include) which run in non-interactive environments.
#[test]
#[cfg(not(tarpaulin_include))]
fn test_cli_encrypt_decrypt_passphrase() -> Result<()> {
    let mut temp_file = NamedTempFile::new()?;
    writeln!(temp_file, "password protected")?;
    let file_path = temp_file.path().to_path_buf();
    let passphrase = "testpassword123";

    // Encrypt with passphrase
    // We spawn the process and pipe input to simulate user typing the passphrase.
    let mut encrypt_child = Command::cargo_bin("pqe")?
        .args(&["encrypt", "-f", file_path.to_str().unwrap(), "-m", "copy", "--passphrase"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    if let Some(mut stdin) = encrypt_child.stdin.take() {
        // rpassword expects a newline after the password input
        stdin.write_all(passphrase.as_bytes())?;
        stdin.write_all(b"\n")?;
    }
    let encrypt_output = encrypt_child.wait_with_output()?;
    assert!(encrypt_output.status.success(), "Encryption failed: {:?}", String::from_utf8_lossy(&encrypt_output.stderr));


    let encrypted_path = file_path.with_extension(EXT);
    assert!(encrypted_path.exists());

    // Decrypt with correct passphrase
    let mut decrypt_child = Command::cargo_bin("pqe")?
        .args(&["decrypt", "-f", encrypted_path.to_str().unwrap(), "-m", "copy", "--passphrase"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    if let Some(mut stdin) = decrypt_child.stdin.take() {
        stdin.write_all(passphrase.as_bytes())?;
        stdin.write_all(b"\n")?;
    }
    let decrypt_output = decrypt_child.wait_with_output()?;
    assert!(decrypt_output.status.success(), "Decryption failed: {:?}", String::from_utf8_lossy(&decrypt_output.stderr));

    // Verify content (decryption defaults to original filename path)
    let decrypted_content = fs::read_to_string(&file_path)?;
    assert_eq!(decrypted_content.trim(), "password protected");

    // Test Decrypt with WRONG passphrase
    let mut decrypt_fail_child = Command::cargo_bin("pqe")?
        .args(&["decrypt", "-f", encrypted_path.to_str().unwrap(), "-m", "copy", "--passphrase"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    if let Some(mut stdin) = decrypt_fail_child.stdin.take() {
        stdin.write_all(b"wrongpassword\n")?;
    }
    let decrypt_fail_output = decrypt_fail_child.wait_with_output()?;
    assert!(!decrypt_fail_output.status.success());
    // Check for the specific error message from crypto.rs
    assert!(String::from_utf8_lossy(&decrypt_fail_output.stderr).contains("Decryption failed (invalid authentication tag)"));


    Ok(())
}

// --- Folder Tests (Recursion and Modes) ---

#[test]
fn test_cli_folder_encryption_copy_recursive() -> Result<()> {
    let temp_dir = tempdir()?;
    let base_path = temp_dir.path();

    fs::write(base_path.join("file1.txt"), b"File 1")?;
    fs::create_dir(base_path.join("subdir"))?;
    fs::write(base_path.join("subdir/file2.txt"), b"File 2")?;

    // Encrypt (Copy, Recursive)
    Command::cargo_bin("pqe")?
        .args(&["encrypt", "-d", base_path.to_str().unwrap(), "-m", "copy", "--recursive"])
        .assert()
        .success();

    let encrypted_folder_name = format!("{}_encrypted", base_path.file_name().unwrap().to_str().unwrap());
    let encrypted_folder_path = base_path.with_file_name(&encrypted_folder_name);

    assert!(encrypted_folder_path.join("file1.txt.mlkem").exists());
    assert!(encrypted_folder_path.join("subdir/file2.txt.mlkem").exists());
    // Originals remain
    assert!(base_path.join("file1.txt").exists());

    Ok(())
}

#[test]
fn test_cli_folder_recursion_disabled() -> Result<()> {
    let temp_dir = tempdir()?;
    let base_path = temp_dir.path();

    fs::write(base_path.join("root.txt"), b"Root")?;
    fs::create_dir(base_path.join("sub"))?;
    fs::write(base_path.join("sub/nested.txt"), b"Nested")?;

    // Encrypt (Copy, Non-Recursive - default if flag is absent)
    Command::cargo_bin("pqe")?
        .args(&["encrypt", "-d", base_path.to_str().unwrap(), "-m", "copy"]) // --recursive is absent
        .assert()
        .success();

    let encrypted_folder_name = format!("{}_encrypted", base_path.file_name().unwrap().to_str().unwrap());
    let encrypted_folder_path = base_path.with_file_name(&encrypted_folder_name);

    assert!(encrypted_folder_path.join("root.txt.mlkem").exists());
    // Nested file/folder should NOT exist in the output
    assert!(!encrypted_folder_path.join("sub").exists());
    assert!(!encrypted_folder_path.join("sub/nested.txt.mlkem").exists());

    Ok(())
}


#[test]
fn test_cli_folder_replace_recursive() -> Result<()> {
    let temp_dir = tempdir()?;
    let base_path = temp_dir.path();

    fs::write(base_path.join("r1.txt"), b"R1")?;
    fs::create_dir(base_path.join("sub"))?;
    fs::write(base_path.join("sub/r2.txt"), b"R2")?;

    // Encrypt (Replace, Recursive)
    Command::cargo_bin("pqe")?
        .args(&["encrypt", "-d", base_path.to_str().unwrap(), "-m", "replace", "-r"])
        .assert()
        .success();

    // Check originals are gone and encrypted exist in place
    assert!(!base_path.join("r1.txt").exists());
    assert!(!base_path.join("sub/r2.txt").exists());
    assert!(base_path.join("r1.txt.mlkem").exists());
    assert!(base_path.join("sub/r2.txt.mlkem").exists());

    // Decrypt (Replace, Recursive)
    Command::cargo_bin("pqe")?
        .args(&["decrypt", "-d", base_path.to_str().unwrap(), "-m", "replace", "-r"])
        .assert()
        .success();

     // Check encrypted are gone and originals restored
    assert!(base_path.join("r1.txt").exists());
    assert!(base_path.join("sub/r2.txt").exists());
    assert!(!base_path.join("r1.txt.mlkem").exists());
    assert!(!base_path.join("sub/r2.txt.mlkem").exists());

    assert_eq!(fs::read(base_path.join("r1.txt"))?, b"R1");
    assert_eq!(fs::read(base_path.join("sub/r2.txt"))?, b"R2");

    Ok(())
}


// --- Argument Parsing Tests ---

#[test]
fn test_cli_conflicting_args() -> Result<()> {
    Command::cargo_bin("pqe")?
        .args(&["encrypt", "-f", "file.txt", "-d", "folder/", "-m", "copy"])
        .assert()
        .failure()
        // Clap handles this conflict detection
        .stderr(predicate::str::contains("the argument '--file <FILE>' cannot be used with '--folder <FOLDER>'"));
    Ok(())
}

// These tests verify the validation logic in main.rs
// We exclude them from coverage because we exclude main.rs from coverage analysis.
#[test]
#[cfg(not(tarpaulin_include))]
fn test_cli_encrypt_missing_args() -> Result<()> {
    Command::cargo_bin("pqe")?
        .args(&["encrypt", "-m", "copy"])
        .assert()
        .failure()
        // Our custom validation in main.rs handles this
        .stderr(predicate::str::contains("At least one of --file or --folder must be provided for encryption."));
    Ok(())
}

#[test]
#[cfg(not(tarpaulin_include))]
fn test_cli_decrypt_missing_args() -> Result<()> {
    Command::cargo_bin("pqe")?
        .args(&["decrypt", "-m", "copy"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("At least one of --file or --folder must be provided for decryption."));
    Ok(())
}

#[test]
fn test_cli_decrypt_corrupted_file() -> Result<()> {
    let mut temp_file = NamedTempFile::new()?;
    // Write content that is clearly not the expected serialized format
    writeln!(temp_file, "This is just plain text, not an encrypted file.")?;
    let file_path = temp_file.path().to_path_buf();

    Command::cargo_bin("pqe")?
        .args(&["decrypt", "-f", file_path.to_str().unwrap(), "-m", "copy"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to deserialize encrypted data"));

    Ok(())
}