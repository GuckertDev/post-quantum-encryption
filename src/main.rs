use anyhow::Result;
use clap::Parser;
use std::io::{self, BufReader, BufWriter, Write};

mod cli;
mod crypto;
mod file_ops;
mod models;

// We exclude the main function from coverage analysis as it primarily handles CLI orchestration
// and user input (like TTY interaction for passphrases), which are better tested via integration tests.
#[cfg(not(tarpaulin_include))]
fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    // Handle interactive mode or default if no command provided
    if cli.interactive || cli.command.is_none() {
        return file_ops::interactive_menu(None, None);
    }

    if let Some(command) = cli.command {
        match command {
            cli::Commands::Encrypt { file, folder, mode, extension, passphrase, recursive } => {
                if file.is_none() && folder.is_none() {
                    anyhow::bail!("At least one of --file or --folder must be provided for encryption.");
                }

                let mut reader = BufReader::new(io::stdin());
                let mut writer = BufWriter::new(io::stdout());

                // Handle passphrase input securely
                let passphrase_str = if passphrase {
                    print!("Enter passphrase: ");
                    io::stdout().flush()?;
                    Some(rpassword::read_password()?)
                } else {
                    None
                };

                if let Some(file_path) = file {
                    file_ops::process_file_encrypt(&file_path, &mode, &extension, passphrase_str.as_deref(), None, false, &mut reader, &mut writer)?;
                }
                if let Some(folder_path) = folder {
                    // Pass the recursive flag
                    file_ops::process_folder(&folder_path, true, &mode, &extension, passphrase_str.as_deref(), recursive)?;
                }
            }
            cli::Commands::Decrypt { file, folder, mode, extension, passphrase, recursive } => {
                if file.is_none() && folder.is_none() {
                    anyhow::bail!("At least one of --file or --folder must be provided for decryption.");
                }

                let mut reader = BufReader::new(io::stdin());
                let mut writer = BufWriter::new(io::stdout());

                // Handle passphrase input securely
                let passphrase_str = if passphrase {
                    print!("Enter passphrase: ");
                    io::stdout().flush()?;
                    Some(rpassword::read_password()?)
                } else {
                    None
                };

                if let Some(file_path) = file {
                    file_ops::process_file_decrypt(&file_path, &mode, &extension, passphrase_str.as_deref(), None, false, &mut reader, &mut writer)?;
                }
                if let Some(folder_path) = folder {
                    // Pass the recursive flag
                    file_ops::process_folder(&folder_path, false, &mode, &extension, passphrase_str.as_deref(), recursive)?;
                }
            }
        }
    }

    Ok(())
}

// Placeholder main for coverage runs
#[cfg(tarpaulin_include)]
fn main() {}