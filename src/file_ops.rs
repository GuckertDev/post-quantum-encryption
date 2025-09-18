use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::fs;
use std::thread;
// use std::time::Duration; // Removed unused import
use colored::Colorize;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use crate::crypto::{encrypt_symmetric, decrypt_symmetric};
use crate::models::EncryptedData;
use crate::cli::Mode;
use std::io::{self, Write, BufRead, Stdin, Stdout, BufReader, BufWriter};
use oqs::kem::{Algorithm, Kem};
use serde_bytes::ByteBuf;
use walkdir::WalkDir;
use rand::RngCore;
use dialoguer::{theme::ColorfulTheme, Select, Input, Confirm, Password};
use console::{style, Style};

pub const ENCRYPTION_EXTENSION: &str = "mlkem";

pub fn process_file_encrypt<R: BufRead, W: Write>(
    path: &Path,
    mode: &Mode,
    extension: &str,
    passphrase: Option<&str>,
    output_path: Option<&Path>,
    quiet: bool,
    _reader: &mut R, // Kept for signature consistency
    writer: &mut W, // Use injected writer for output
) -> Result<()> {
    // Read file content first to ensure readability before starting crypto operations
    let file_content = fs::read(path).context(format!("Failed to read file: {}", path.display()))?;

    let mut salt = None;
    // Clone passphrase if needed to manage ownership
    let passphrase_owned = if passphrase.is_some() {
        let mut s = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut s);
        salt = Some(s.clone());
        passphrase.map(|s| s.to_string())
    } else {
        None
    };

    // KEM Operations (Kyber1024)
    let alg = Algorithm::Kyber1024;
    let kem = Kem::new(alg)?;
    let (public_key, private_key) = kem.keypair()?;
    let (ciphertext, shared_secret) = kem.encapsulate(&public_key)?;

    // Symmetric Encryption
    let (sym_ct, nonce, generated_salt) = encrypt_symmetric(&file_content, &shared_secret, passphrase_owned.as_deref())?;

    // Determine final salt
    let final_salt = generated_salt.or(salt);

    let private_key_bytes = private_key.into_vec();
    let file_name = path.file_name().and_then(|s| s.to_str()).context("Invalid file name")?;

    // Serialize data
    let serialized_data = bincode::serialize(&EncryptedData {
        alg_id: alg.to_string(),
        public_key_bytes: ByteBuf::from(public_key.into_vec()),
        ciphertext_bytes: ByteBuf::from(ciphertext.into_vec()),
        encrypted_content: sym_ct,
        original_path: file_name.to_string(),
        nonce: ByteBuf::from(nonce),
        salt: final_salt,
        private_key_bytes: ByteBuf::from(private_key_bytes),
    })?;

    // Determine output path
    let output_file_path = match output_path {
        Some(path) => path.to_path_buf(),
        None => {
            let new_file_name = format!("{}.{}", file_name, extension);
            path.with_file_name(new_file_name)
        }
    };

    // Ensure output directory exists
    if let Some(parent) = output_file_path.parent() {
        if !parent.exists() && parent != Path::new("") {
             fs::create_dir_all(parent).context(format!("Failed to create directory: {}", parent.display()))?;
        }
    }

    // Write encrypted file
    fs::write(&output_file_path, serialized_data)
        .context(format!("Failed to write encrypted file: {}", output_file_path.display()))?;

    // Handle Replace mode: only remove if successful, mode is Replace, AND no explicit output path was given
    if matches!(*mode, Mode::Replace) && output_path.is_none() {
        fs::remove_file(path).context(format!("Failed to remove original file: {}", path.display()))?;
    }

    // Output success message using injected writer
    if !quiet {
        writeln!(writer, "\n{}\n", "Success!".green())?;
        let output_display = output_file_path.display().to_string();
        let (base_path, _) = output_display
            .rsplit_once(&format!(".{}", extension))
            .unwrap_or((&output_display, ""));

        writeln!(
            writer,
            "{} {} {}{}",
            "File Encrypted".truecolor(128, 128, 128),
            "➜".green(),
            base_path.truecolor(128, 128, 128),
            format!(".{}", extension).truecolor(249, 216, 73)
        )?;
        writeln!(writer)?;
    }

    Ok(())
}

pub fn process_file_decrypt<R: BufRead, W: Write>(
    path: &Path,
    mode: &Mode,
    _extension: &str,
    passphrase: Option<&str>,
    output_path: Option<&Path>,
    quiet: bool,
    _reader: &mut R,
    writer: &mut W, // Use injected writer for output
) -> Result<()> {
    // Clone passphrase if needed
    let passphrase_owned = passphrase.map(|s| s.to_string());

    // Read and Deserialize
    let file_data = fs::read(path).context(format!("Failed to read file: {}", path.display()))?;
    let enc_data: EncryptedData = bincode::deserialize(&file_data)
        .context("Failed to deserialize encrypted data. File may be corrupt or not an encrypted file.")?;

    // Initialize KEM
    let alg: Algorithm = enc_data.alg_id.parse().map_err(|_| anyhow!("Invalid algorithm ID: {}", enc_data.alg_id))?;
    let kem = Kem::new(alg)?;

    // Reconstruct keys and ciphertext
    let private_key = kem.secret_key_from_bytes(enc_data.private_key_bytes.as_ref())
        .ok_or_else(|| anyhow!("Failed to reconstruct private key"))?;
    let ciphertext = kem.ciphertext_from_bytes(&enc_data.ciphertext_bytes)
        .ok_or_else(|| anyhow!("Failed to reconstruct ciphertext"))?;

    // Decapsulate
    let shared_secret = kem.decapsulate(&private_key, ciphertext)?;

    // Symmetric Decryption
    let decrypted_content = decrypt_symmetric(
        &enc_data.encrypted_content,
        &shared_secret,
        &enc_data.nonce,
        passphrase_owned.as_deref(),
        enc_data.salt.as_deref(),
    )?;

    // Determine output path
    let output_file_path = match output_path {
        Some(p) => p.to_path_buf(),
        None => {
            let original_path = Path::new(&enc_data.original_path);
            let parent_dir = path.parent().unwrap_or(Path::new("."));

            // In both Copy and Replace modes (when output_path is None), the decrypted file
            // is placed next to the encrypted file using the original name.
            let file_name = original_path.file_name().context("Invalid original file name in metadata")?;
            parent_dir.join(file_name)
        }
    };

     // Ensure output directory exists
     if let Some(parent) = output_file_path.parent() {
        if !parent.exists() && parent != Path::new("") {
             fs::create_dir_all(parent).context(format!("Failed to create directory: {}", parent.display()))?;
        }
    }

    // Write decrypted file
    fs::write(&output_file_path, decrypted_content)
        .with_context(|| format!("Failed to write decrypted file: {}", output_file_path.display()))?;

    // Handle Replace mode
    if matches!(*mode, Mode::Replace) && output_path.is_none() {
        fs::remove_file(path).context(format!("Failed to remove encrypted file: {}", path.display()))?;
    }

    // Output success message using injected writer
    if !quiet {
        writeln!(writer, "\n{}\n", "Success!".green())?;
        writeln!(
            writer,
            "{} {} {}",
            "File Decrypted".truecolor(128, 128, 128),
            "➜".green(),
            output_file_path.display().to_string().truecolor(128, 128, 128)
        )?;
        writeln!(writer)?;
    }

    Ok(())
}

// Helper to determine if a file should be processed
fn should_process(path: &Path, is_encrypt: bool, encryption_extension: &str) -> bool {
    let ext = path.extension().and_then(|s| s.to_str());
    if is_encrypt {
        // Encrypt files that do NOT have the encryption extension
        ext != Some(encryption_extension)
    } else {
        // Decrypt files that DO have the encryption extension
        ext == Some(encryption_extension)
    }
}

/// Processes (encrypts or decrypts) files in a folder, optionally recursively.
pub fn process_folder(folder: &Path, is_encrypt: bool, mode: &Mode, extension: &str, passphrase: Option<&str>, recursive: bool) -> Result<()> {
    if !folder.is_dir() {
        return Err(anyhow!("Provided path is not a directory: {}", folder.display()));
    }

    // 1. Configure directory traversal based on the recursive flag
    let walk_dir = WalkDir::new(folder);
    let walk_dir = if recursive {
        walk_dir
    } else {
        walk_dir.max_depth(1)
    };

    // 2. Collect all relevant files
    let entries: Vec<_> = walk_dir
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter(|e| should_process(e.path(), is_encrypt, extension))
        .collect();

    if entries.is_empty() {
        return Err(anyhow!("No matching files found to process in folder: {}", folder.display()));
    }

    // 3. Determine the output folder structure (only relevant for Mode::Copy)
    let output_folder = if matches!(*mode, Mode::Copy) {
        let mut new_path = folder.to_path_buf();
        let base_name = folder.file_name().and_then(|s| s.to_str()).context("Invalid folder name")?;
        let new_name = if is_encrypt {
            format!("{}_encrypted", base_name)
        } else {
            // Heuristic for decryption folder name
            if base_name.ends_with("_encrypted") {
                 base_name.replace("_encrypted", "_decrypted")
            } else {
                format!("{}_decrypted", base_name)
            }
        };
        new_path.set_file_name(new_name);

        // Create the root output directory
        fs::create_dir_all(&new_path).context(format!("Failed to create output folder: {}", new_path.display()))?;
        new_path
    } else {
        // Mode::Replace operates in place
        folder.to_path_buf()
    };

    // 4. Process files in parallel
    let results: Vec<Result<()>> = entries
        .par_iter()
        .map(|entry| -> Result<()> {
            let entry_path = entry.path();
            // Calculate the relative path to maintain directory structure (only needed for Mode::Copy)
            let relative_path = entry_path.strip_prefix(folder).unwrap();

            // Use dummy reader/writer for parallel execution. Crucial for thread safety.
            let mut reader = io::empty();
            let mut writer = io::sink();

            if is_encrypt {
                // Determine the explicit output path if Mode::Copy
                let explicit_output = if matches!(*mode, Mode::Copy) {
                    let file_name = relative_path.file_name().context("Invalid file name during encryption")?;
                    let new_file_name = format!("{}.{}", file_name.to_str().unwrap(), extension);
                    let output_path = output_folder.join(relative_path).with_file_name(new_file_name);

                     // Ensure subdirectory exists
                    if let Some(parent) = output_path.parent() {
                        // create_dir_all is generally safe to call concurrently
                        fs::create_dir_all(parent)?;
                    }
                    Some(output_path)
                } else {
                    // Mode::Replace: Let process_file_encrypt handle pathing and deletion
                    None
                };

                let result = process_file_encrypt(entry_path, mode, extension, passphrase, explicit_output.as_deref(), true, &mut reader, &mut writer);
                result

            } else {
                // Decryption Logic

                // Determine the explicit output path if Mode::Copy
                let explicit_output = if matches!(*mode, Mode::Copy) {
                    // Inefficiency: We must read the file header here to determine the original path
                    // and construct the output path in the target directory structure.
                    let file_data = fs::read(entry_path)?;
                    let enc_data: EncryptedData = bincode::deserialize(&file_data)
                         .context(format!("Failed to read metadata from {}", entry_path.display()))?;

                    let original_file_name = PathBuf::from(&enc_data.original_path);
                    let relative_dir = relative_path.parent().unwrap_or(Path::new(""));
                    let output_path = output_folder.join(relative_dir).join(original_file_name);

                    // Ensure subdirectory exists
                    if let Some(parent) = output_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    Some(output_path)
                 } else {
                    // Mode::Replace: Let process_file_decrypt handle pathing and deletion
                    None
                 };

                // process_file_decrypt will read the file again (if Mode::Copy) or for the first time (if Mode::Replace)
                let result = process_file_decrypt(entry_path, mode, extension, passphrase, explicit_output.as_deref(), true, &mut reader, &mut writer);
                result
            }
        })
        .collect();

    // 5. Check results and aggregate errors
    let mut errors = Vec::new();
    for result in results {
        if let Err(e) = result {
            // Log the error immediately (using eprintln! as a placeholder for proper logging)
            // We use eprintln! here because the main success message is printed to stdout below.
            eprintln!("{} {:?}", "Error processing file:".red(), e);
            errors.push(e);
        }
    }

    if !errors.is_empty() {
        return Err(anyhow!("{} files failed to process.", errors.len()));
    }

    // 6. Display success message (printed to stdout)
    let action_str = if is_encrypt { "Encrypted" } else { "Decrypted" };
    println!("\n{}\n", "Success!".green());
    println!(
        "{} {} {} {}",
        "Folder".truecolor(128, 128, 128),
        action_str.truecolor(128, 128, 128),
        "➜".green(),
        // Display the actual folder processed (output_folder for Copy, original folder for Replace)
        (if matches!(*mode, Mode::Copy) { &output_folder } else { folder }).display().to_string().truecolor(128, 128, 128)
    );
    println!();

    Ok(())
}

/// Interactive command-line interface menu.
// Excluded from coverage analysis as it requires TTY interaction.
// Replaced old attribute #[cfg_attr(tarpaulin, tarpaulin::skip)]
#[cfg(not(tarpaulin_include))]
pub fn interactive_menu(_reader: Option<Stdin>, _writer: Option<Stdout>) -> Result<()> {
    // Dummy reader for passing to process functions
    let mut dummy_reader = BufReader::new(io::empty());
    // Use stdout writer so the success messages from process_file_* (which use the injected writer) are displayed
    let mut stdout_writer = BufWriter::new(io::stdout());

    // Configure the dialoguer theme
    let theme = ColorfulTheme {
        prompt_prefix: style("".to_string()),
        active_item_prefix: style("❯ ".to_string()).cyan(),
        inactive_item_prefix: style(" ".to_string()),
        success_prefix: style("".to_string()),
        prompt_style: Style::new().for_stderr().color256(244),
        values_style: Style::new().for_stderr().white(),
        ..ColorfulTheme::default()
    };

    // Initialize Rayon thread pool optimized for CLI responsiveness
    let num_threads = thread::available_parallelism().map_or(2, |p| p.get().saturating_sub(1)).max(1);
    // Initialize global thread pool if not already initialized
    let _ = ThreadPoolBuilder::new().num_threads(num_threads).build_global();

    println!(
        "\n{}{}{}\n",
        "Welcome to ".truecolor(128, 128, 128),
        "Post-Quantum Encryption".truecolor(249, 216, 73).bold(),
        "".normal()
    );

    loop {
        let main_selection = Select::with_theme(&theme)
            .with_prompt("Select Operation") // Added prompt text
            .items(&["Encrypt File", "Decrypt File", "Encrypt Folder", "Decrypt Folder", "Exit"])
            .default(0)
            .interact()?;

        println!();

        let mut passphrase: Option<String> = None;
        // Prompt for passphrase if an operation (not Exit) is selected
        if main_selection < 4 {
            if Confirm::with_theme(&theme).with_prompt("Use Passphrase?").interact()? {
                println!();
                passphrase = Some(Password::with_theme(&theme)
                    .with_prompt("Enter Passphrase")
                    .with_confirmation("Confirm Passphrase", "Passphrases do not match")
                    .interact()?);
                println!();
            } else {
                println!();
            }
        }

        let mode_items = &["Overwrite Original (Replace)", "Make Copy"]; // Clarified mode names
        match main_selection {
            0 | 1 => { // File Operations
                let action_str = if main_selection == 0 { "Encrypt" } else { "Decrypt" };
                let raw_path_str: String = Input::with_theme(&theme)
                    .with_prompt(format!("Enter File Path to {}", action_str))
                    .interact_text()?;
                // Handle paths dragged into the terminal (often quoted)
                let path_str = raw_path_str.trim_matches(|c| c == '\'' || c == '"');
                let path = PathBuf::from(path_str);

                if !path.is_file() {
                    println!("\n{}", format!("Error: Not a valid file path: {}", path.display()).red());
                    continue;
                }
                println!();

                let mode_selection = Select::with_theme(&theme).with_prompt("Select Mode").items(mode_items).default(1).interact()?;
                let mode = if mode_selection == 0 { Mode::Replace } else { Mode::Copy };

                let result = if main_selection == 0 {
                    process_file_encrypt(&path, &mode, ENCRYPTION_EXTENSION, passphrase.as_deref(), None, false, &mut dummy_reader, &mut stdout_writer)
                } else {
                    process_file_decrypt(&path, &mode, ENCRYPTION_EXTENSION, passphrase.as_deref(), None, false, &mut dummy_reader, &mut stdout_writer)
                };

                if let Err(e) = result {
                     // Use println! here as we are in the main interactive loop context
                     println!("\n{}: {}\n", "Operation Failed".red(), e);
                }

            },
            2 | 3 => { // Folder Operations
                let action_str = if main_selection == 2 { "Encrypt" } else { "Decrypt" };
                let raw_path_str: String = Input::with_theme(&theme)
                    .with_prompt(format!("Enter Folder Path to {}", action_str))
                    .interact_text()?;
                let path_str = raw_path_str.trim_matches(|c| c == '\'' || c == '"');
                let path = PathBuf::from(path_str);

                if !path.is_dir() {
                    println!("\n{}", format!("Error: Not a valid folder path: {}", path.display()).red());
                    continue;
                }
                println!();

                let mode_selection = Select::with_theme(&theme).with_prompt("Select Mode").items(mode_items).default(1).interact()?;
                let mode = if mode_selection == 0 { Mode::Replace } else { Mode::Copy };

                println!();
                let recursive = Confirm::with_theme(&theme)
                    .with_prompt("Recurse into subdirectories?")
                    .default(true)
                    .interact()?;
                println!();

                let result = if main_selection == 2 {
                    process_folder(&path, true, &mode, ENCRYPTION_EXTENSION, passphrase.as_deref(), recursive)
                } else {
                    process_folder(&path, false, &mode, ENCRYPTION_EXTENSION, passphrase.as_deref(), recursive)
                };

                if let Err(e) = result {
                     println!("\n{}: {}\n", "Operation Failed".red(), e);
                }
            },
            4 => { // Exit
                print_exit_message();
                break;
            }
            _ => unreachable!(),
        }

        // Ask to perform another operation
        let perform_another = Confirm::with_theme(&theme)
            .with_prompt("Perform another operation?")
            .default(true)
            .interact()?;
        println!();

        if !perform_another {
            print_exit_message();
            break;
        }
    }
    Ok(())
}

#[cfg(not(tarpaulin_include))]
fn print_exit_message() {
    println!(
        "\n{}{}{}\n",
        "Thank you for using ".truecolor(128, 128, 128),
        "Post-Quantum Encryption".truecolor(249, 216, 73).bold(),
        "".normal()
    );
}


// ================================================
// Module-level Unit Tests
// ================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, NamedTempFile};
    use std::io::{Cursor, Write as IoWrite};
    use crate::models::EncryptedData;
    use std::fs;
    use oqs::kem::{Kem, Algorithm};
    use serde_bytes::ByteBuf;

    // Helper to create a dummy file with content
    fn create_test_file(content: &str) -> (NamedTempFile, PathBuf) {
        let mut file = NamedTempFile::new().unwrap();
        // Write content (we don't use writeln! here to control exact bytes, avoiding OS-specific line endings)
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        let path = file.path().to_path_buf();
        (file, path)
    }

    // --- process_file_encrypt/decrypt Tests ---

    #[test]
    fn test_process_file_encrypt_copy_mode() {
        let (_file, path) = create_test_file("test content");
        let mut reader = Cursor::new("");
        let mut writer = Vec::new();
        let mode = Mode::Copy;
        let extension = "testenc";

        process_file_encrypt(&path, &mode, extension, None, None, true, &mut reader, &mut writer).unwrap();

        let encrypted_path = path.with_extension(extension);
        assert!(encrypted_path.exists());
        assert!(path.exists()); // Original should still exist in Copy mode
    }

    #[test]
    fn test_process_file_encrypt_replace_mode() {
        let (_file, path) = create_test_file("test content replace");
        let mut reader = Cursor::new("");
        let mut writer = Vec::new();
        let mode = Mode::Replace;

        process_file_encrypt(&path, &mode, ENCRYPTION_EXTENSION, None, None, true, &mut reader, &mut writer).unwrap();

        let encrypted_path = path.with_extension(ENCRYPTION_EXTENSION);
        assert!(encrypted_path.exists());
        assert!(!path.exists()); // Original should be removed in Replace mode
    }

    #[test]
    fn test_process_file_encrypt_decrypt_cycle() {
        let content = "roundtrip test";
        let (_file, path) = create_test_file(content);
        let mut reader = Cursor::new("");
        let mut writer = Vec::new();

        // Encrypt
        process_file_encrypt(&path, &Mode::Copy, ENCRYPTION_EXTENSION, None, None, true, &mut reader, &mut writer).unwrap();
        let encrypted_path = path.with_extension(ENCRYPTION_EXTENSION);

        // Decrypt to a specific path
        let decrypted_path = path.with_extension("decrypted");
        process_file_decrypt(&encrypted_path, &Mode::Copy, ENCRYPTION_EXTENSION, None, Some(&decrypted_path), true, &mut reader, &mut writer).unwrap();

        let decrypted_content = fs::read_to_string(decrypted_path).unwrap();
        assert_eq!(decrypted_content, content);
    }

    #[test]
    fn test_process_file_encrypt_output_path() {
        let (_file, path) = create_test_file("output path test");
        let temp_dir = tempdir().unwrap();
        // Test creating nested output directories
        let output_path = temp_dir.path().join("nested/dir/specific_output.enc");

        let mut reader = Cursor::new("");
        let mut writer = Vec::new();

        // Even in Replace mode, if an output path is specified, the original remains.
        process_file_encrypt(&path, &Mode::Replace, ENCRYPTION_EXTENSION, None, Some(&output_path), true, &mut reader, &mut writer).unwrap();

        assert!(output_path.exists());
        assert!(path.exists()); // Original remains because output_path was specified
        let default_output_path = path.with_extension(ENCRYPTION_EXTENSION);
        assert!(!default_output_path.exists());
    }

     #[test]
    fn test_process_file_encrypt_non_existent_file() {
        let path = PathBuf::from("non_existent_file_12345.txt");
        let mut reader = Cursor::new("");
        let mut writer = Vec::new();

        let result = process_file_encrypt(&path, &Mode::Copy, ENCRYPTION_EXTENSION, None, None, true, &mut reader, &mut writer);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }

    #[test]
    fn test_process_file_decrypt_corrupt_file() {
        let (_file, path) = create_test_file("this is not serialized data");
        let mut reader = Cursor::new("");
        let mut writer = Vec::new();

        let result = process_file_decrypt(&path, &Mode::Copy, ENCRYPTION_EXTENSION, None, None, true, &mut reader, &mut writer);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to deserialize encrypted data"));
    }

    #[test]
    fn test_process_file_encrypt_passphrase_salt_generation() {
        let (_file, path) = create_test_file("passphrase test");
        let mut reader = Cursor::new("");
        let mut writer = Vec::new();
        let passphrase = "mypassword";

        process_file_encrypt(&path, &Mode::Copy, ENCRYPTION_EXTENSION, Some(passphrase), None, true, &mut reader, &mut writer).unwrap();

        let encrypted_path = path.with_extension(ENCRYPTION_EXTENSION);
        let data = fs::read(encrypted_path).unwrap();
        let enc_data: EncryptedData = bincode::deserialize(&data).unwrap();

        assert!(enc_data.salt.is_some());
        assert_eq!(enc_data.salt.unwrap().len(), 16);
    }

    #[test]
    fn test_process_file_non_quiet_output() {
        let (_file, path) = create_test_file("output test");
        let mut reader = Cursor::new("");
        let mut writer = Vec::new();

        // Encrypt (Non-Quiet) - Test Writer Injection
        process_file_encrypt(&path, &Mode::Copy, ENCRYPTION_EXTENSION, None, None, false, &mut reader, &mut writer).unwrap();

        let output_enc = String::from_utf8(writer.clone()).unwrap();
        assert!(output_enc.contains("Success!"));
        assert!(output_enc.contains("File Encrypted"));

        // Decrypt (Non-Quiet) - Test Writer Injection
        let encrypted_path = path.with_extension(ENCRYPTION_EXTENSION);
        writer.clear();
        process_file_decrypt(&encrypted_path, &Mode::Copy, ENCRYPTION_EXTENSION, None, None, false, &mut reader, &mut writer).unwrap();

        let output_dec = String::from_utf8(writer).unwrap();
        assert!(output_dec.contains("Success!"));
        assert!(output_dec.contains("File Decrypted"));
    }

    // --- Folder Processing Tests ---

    #[test]
    fn test_process_folder_not_a_directory() {
        let (_file, path) = create_test_file("I am a file");
        let result = process_folder(&path, true, &Mode::Copy, ENCRYPTION_EXTENSION, None, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Provided path is not a directory"));
    }

    #[test]
    fn test_process_folder_empty() {
        let temp_dir = tempdir().unwrap();
        let result = process_folder(temp_dir.path(), true, &Mode::Copy, ENCRYPTION_EXTENSION, None, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No matching files found"));
    }

    #[test]
    fn test_process_folder_no_matching_files() {
        let temp_dir = tempdir().unwrap();
        // Create an already encrypted file
        fs::write(temp_dir.path().join("file1.mlkem"), b"data").unwrap();

        // Try to encrypt (should find nothing)
        let result_enc = process_folder(temp_dir.path(), true, &Mode::Copy, ENCRYPTION_EXTENSION, None, true);
        assert!(result_enc.is_err());

        // Try to decrypt a folder with only a plain text file
        let temp_dir_dec = tempdir().unwrap();
        fs::write(temp_dir_dec.path().join("file1.txt"), b"data").unwrap();
        let result_dec = process_folder(temp_dir_dec.path(), false, &Mode::Copy, ENCRYPTION_EXTENSION, None, true);
        assert!(result_dec.is_err());
    }

    #[test]
    fn test_process_folder_recursion_control() {
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path();
        fs::write(base_path.join("file1.txt"), b"content1").unwrap();
        fs::create_dir(base_path.join("subdir")).unwrap();
        fs::write(base_path.join("subdir/file2.dat"), b"content2").unwrap();

        // 1. Non-Recursive (recursive=false)
        process_folder(base_path, true, &Mode::Copy, "enc", None, false).unwrap();

        let base_name = base_path.file_name().unwrap().to_str().unwrap();
        let encrypted_folder_nr_name = format!("{}_encrypted", base_name);
        let encrypted_folder_nr = base_path.with_file_name(&encrypted_folder_nr_name);

        assert!(encrypted_folder_nr.join("file1.txt.enc").exists());
        // Subdirectory content/structure should NOT be present
        assert!(!encrypted_folder_nr.join("subdir/file2.dat.enc").exists());
        assert!(!encrypted_folder_nr.join("subdir").exists());

        // Clean up
        fs::remove_dir_all(&encrypted_folder_nr).unwrap();

        // 2. Recursive (recursive=true)
        process_folder(base_path, true, &Mode::Copy, "enc", None, true).unwrap();
        let encrypted_folder_r = base_path.with_file_name(encrypted_folder_nr_name); // Same name as before

        assert!(encrypted_folder_r.join("file1.txt.enc").exists());
        // Subdirectory content SHOULD be present
        assert!(encrypted_folder_r.join("subdir/file2.dat.enc").exists());
    }

    // Comprehensive test covering folder cycle (Encrypt/Decrypt) in Replace mode, recursively.
    #[test]
    fn test_process_folder_cycle_replace_recursive() {
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path();
        let original_content1 = b"replace_cycle1";
        let original_content2 = b"replace_cycle2_sub";

        fs::write(base_path.join("data.bin"), original_content1).unwrap();
        fs::create_dir(base_path.join("subdir")).unwrap();
        fs::write(base_path.join("subdir/data2.txt"), original_content2).unwrap();

        // Encrypt (Replace, Recursive)
        process_folder(base_path, true, &Mode::Replace, ENCRYPTION_EXTENSION, None, true).unwrap();

        assert!(base_path.join("data.bin.mlkem").exists());
        assert!(base_path.join("subdir/data2.txt.mlkem").exists());
        assert!(!base_path.join("data.bin").exists());
        assert!(!base_path.join("subdir/data2.txt").exists());

        // Decrypt (Replace, Recursive)
        process_folder(base_path, false, &Mode::Replace, ENCRYPTION_EXTENSION, None, true).unwrap();

        assert!(!base_path.join("data.bin.mlkem").exists());
        assert!(!base_path.join("subdir/data2.txt.mlkem").exists());
        assert!(base_path.join("data.bin").exists());
        assert!(base_path.join("subdir/data2.txt").exists());

        let final_content1 = fs::read(base_path.join("data.bin")).unwrap();
        let final_content2 = fs::read(base_path.join("subdir/data2.txt")).unwrap();
        assert_eq!(final_content1, original_content1);
        assert_eq!(final_content2, original_content2);
    }

     #[test]
    fn test_process_folder_error_aggregation() {
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path();
        // Create a valid file to encrypt
        fs::write(base_path.join("valid.txt"), b"content").unwrap();

        // Create a directory where a file is expected (to cause an I/O error on read)
        // This simulates a permission error or similar I/O issue on some OSes.
        fs::create_dir(base_path.join("invalid_is_dir.txt")).unwrap();

        // Run processing (Encryption)
        let result = process_folder(base_path, true, &Mode::Copy, ENCRYPTION_EXTENSION, None, true);

        // It should fail overall
        assert!(result.is_err());
        // The error message should indicate that 1 file failed (the invalid one)
        assert!(result.unwrap_err().to_string().contains("1 files failed to process."));

        // The valid file should still have been processed
        let base_name = base_path.file_name().unwrap().to_str().unwrap();
        let encrypted_folder = base_path.with_file_name(format!("{}_encrypted", base_name));
        assert!(encrypted_folder.join("valid.txt.mlkem").exists());
    }

    #[test]
    fn test_should_process() {
        let file_txt = PathBuf::from("file.txt");
        let file_mlkem = PathBuf::from("file.mlkem");

        // Encrypting: Should process .txt, not .mlkem
        assert!(should_process(&file_txt, true, ENCRYPTION_EXTENSION));
        assert!(!should_process(&file_mlkem, true, ENCRYPTION_EXTENSION));

        // Decrypting: Should process .mlkem, not .txt
        assert!(!should_process(&file_txt, false, ENCRYPTION_EXTENSION));
        assert!(should_process(&file_mlkem, false, ENCRYPTION_EXTENSION));

        // Custom extension
        assert!(should_process(&file_txt, true, "pqc"));
        assert!(!should_process(&PathBuf::from("file.pqc"), true, "pqc"));
    }

    // Helper to generate EncryptedData structure for testing decryption failures
    fn generate_test_encrypted_data() -> EncryptedData {
        let alg = Algorithm::Kyber1024;
        let kem = Kem::new(alg).unwrap();
        let (pk, sk) = kem.keypair().unwrap();
        let (ct, _) = kem.encapsulate(&pk).unwrap();

        EncryptedData {
            alg_id: alg.to_string(),
            public_key_bytes: ByteBuf::from(pk.into_vec()),
            ciphertext_bytes: ByteBuf::from(ct.into_vec()),
            encrypted_content: vec![1, 2, 3], // Dummy content
            original_path: "test.txt".to_string(),
            nonce: ByteBuf::from(vec![0; 12]),
            salt: None,
            private_key_bytes: ByteBuf::from(sk.into_vec()),
        }
    }

    #[test]
    fn test_decrypt_corrupted_metadata() {
        let base_data = generate_test_encrypted_data();
        let mut reader = std::io::Cursor::new("");
        let mut writer = std::io::sink();

        // Helper closure to serialize, write to temp file, and attempt decryption
        let try_decrypt = |data: &EncryptedData| -> Result<()> {
            let serialized = bincode::serialize(data)?;
            let temp_file = NamedTempFile::new().unwrap();
            fs::write(temp_file.path(), serialized)?;
            process_file_decrypt(temp_file.path(), &Mode::Copy, "mlkem", None, None, true, &mut reader, &mut writer)
        };

        // 1. Invalid Algorithm ID
        let mut data_invalid_alg = base_data.clone();
        data_invalid_alg.alg_id = "NonExistentKEM".to_string();
        let result_alg = try_decrypt(&data_invalid_alg);
        assert!(result_alg.is_err());
        assert!(result_alg.unwrap_err().to_string().contains("Invalid algorithm ID"));

        // 2. Failed private key reconstruction (incorrect length)
        let mut data_short_sk = base_data.clone();
        data_short_sk.private_key_bytes.pop();
        let result_short_sk = try_decrypt(&data_short_sk);
        assert!(result_short_sk.is_err());
        assert!(result_short_sk.unwrap_err().to_string().contains("Failed to reconstruct private key"));

        // 3. Failed ciphertext reconstruction (incorrect length)
        let mut data_short_ct = base_data.clone();
        data_short_ct.ciphertext_bytes.pop();
        let result_short_ct = try_decrypt(&data_short_ct);
        assert!(result_short_ct.is_err());
        assert!(result_short_ct.unwrap_err().to_string().contains("Failed to reconstruct ciphertext"));
    }
}