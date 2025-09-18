use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Optional: Use the interactive menu
    #[arg(short, long)]
    pub interactive: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypts a file or folder
    Encrypt {
        /// The file to encrypt
        #[arg(short, long, value_name = "FILE", conflicts_with = "folder")]
        file: Option<PathBuf>,

        /// The folder to encrypt
        #[arg(short = 'd', long, value_name = "FOLDER")]
        folder: Option<PathBuf>,

        /// The encryption mode
        #[arg(short, long, value_enum)]
        mode: Mode,
        
        /// The extension for the encrypted file
        #[arg(short, long, default_value = "mlkem")]
        extension: String,

        /// Use a passphrase for symmetric encryption
        #[arg(short, long)]
        passphrase: bool,

        /// Recurse into subdirectories
        #[arg(short, long)]
        recursive: bool,
    },
    /// Decrypts a file or folder
    Decrypt {
        /// The file to decrypt
        #[arg(short, long, value_name = "FILE", conflicts_with = "folder")]
        file: Option<PathBuf>,

        /// The folder to decrypt
        #[arg(short = 'd', long, value_name = "FOLDER")]
        folder: Option<PathBuf>,
        
        /// The decryption mode
        #[arg(short, long, value_enum)]
        mode: Mode,

        /// The extension for the decrypted file
        #[arg(short, long, default_value = "mlkem")]
        extension: String,

        /// Use a passphrase for symmetric decryption
        #[arg(short, long)]
        passphrase: bool,

        /// Recurse into subdirectories
        #[arg(short, long)]
        recursive: bool,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Mode {
    /// Overwrite the original file(s)
    Replace,
    /// Create a new file(s)
    Copy,
}