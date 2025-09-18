# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- 2025-09-10:
  - Unit tests for error paths (`test_invalid_file_path`, `test_empty_folder`, `test_invalid_folder_path`) and passphrase mode (`test_passphrase_encryption`) to achieve >98% coverage.
  - Updated `README.md`, `CONTRIBUTING.md`, `SECURITY.md` with comprehensive multilingual documentation, enhanced threat model, and contribution guidelines.
- 2025-09-09:
  - Robust path handling in `process_folder` and `test_folder_encryption` for macOS compatibility, using sanitized directory names (`_encrypted`, `_decrypted`).
- 2025-09-08:
  - `Choose Action` menu for folder operations with numbered list for replace/copy options.
  - Line breaks after `Success!` messages and various prompts for better readability.
  - Full file path display in success messages for `encrypt_file` and folder operations.
  - Prompt to trim single quotes from input paths for robust handling.
- 2025-09-07:
  - Folder encryption and decryption functionality with `process_folder`, using `walkdir = "2.5.0"` and `rayon` for parallel processing.
  - `Enter File Extension` prompt for single-file decryption and folder decryption (both replace and copy modes).
  - New folder naming with `_encrypted` or `_decrypted` suffix for folder copy operations.
- 2025-09-06:
  - `zeroize` calls to `decrypt_file` for secure memory handling.

### Changed
- 2025-09-10:
  - Updated `EncryptedData::original_path` to store only file names in `process_file_encrypt` for consistent decryption paths.
  - Adjusted `process_folder` decryption to use relative paths, fixing test failures.
  - Updated coverage badge in `README.md` to reflect dynamic Codecov integration.
- 2025-09-08:
  - Refactored main menu and sub-menus to handle invalid input gracefully with loops.
  - Changed `Select an option` to `Choose Action` (cyan `Choose`, grey `Action`).
  - Removed `5. Exit` from main menu, added continue/exit loop after actions.
  - Updated folder encryption success message to `Success!` (green) and `Folder Encrypted` (grey) with line breaks.
  - Changed `.mlkem` extension color to RGB(249, 216, 73) in output.
- 2025-09-07:
  - Replaced `ops` and `ops-sys` in `Cargo.toml` with `oqs` and `oqs-sys` from `https://github.com/open-quantum-safe/liboqs-rust` (main branch, `zeroize` feature).
  - Updated `EncryptedData` struct to use `ByteBuf` and store `original_path` as `String`.
  - Refactored `encrypt_file` and `decrypt_file` to serialize/deserialize updated `EncryptedData` struct.
  - Standardized all encryption to use Kyber1024 only.
- 2025-09-06:
  - Replaced `SecretKey::from_bytes` with `kem.secret_key_from_bytes` and `SecretKey::try_from_slice`, using `.ok_or_else` for proper error handling.
  - Changed `shared_secret.to_vec()` to `shared_secret.into_vec()` and `private_key.into_vec().zeroize()` to `private_key.to_vec().zeroize()` for library compliance.
  - Implemented symmetric encryption/decryption using `HKDF-SHA256` and `AES-256-GCM`.
  - Fixed typo `anybhow!` to `anyhow!` in error handling.
  - Removed unused imports: `PathBuf`, `std::convert::TryFrom`, `SecretKey`, `serde`, and `serde_json`.

### Fixed
- 2025-09-10:
  - Fixed `test_folder_encryption` by correcting path handling for decrypted files, ensuring consistent `original_path` usage.
- 2025-09-08:
  - Fixed bug in `Make Folder Copy` where `new_ext` was not used in `decrypt_folder`.
  - Fixed unused variable warnings (e.g., `ext`, `file_name`) in Rust code.
- 2025-09-07:
  - Resolved compiler errors in `decrypt_file` by adding necessary `use` statements.
  - Corrected logical error in decryption block causing duplicate path prompts.
- 2025-09-06:
  - Fixed memory leak in keypair generation by ensuring proper cleanup.

### Removed
- 2025-09-08:
  - `Ok(())` on line 84 in `main.rs`.
  - `Using algorithm Kyber1024` output line.
  - Colons from all prompts for cleaner UI.
- 2025-09-06:
  - Duplicate `encrypt_symmetric` and `decrypt_symmetric` functions.

### Security
- 2025-09-10:
  - Enhanced test suite with error path coverage to prevent regressions.
- 2025-09-06:
  - Implemented `zeroize` for secure memory overwriting of cryptographic data.
  - Stored private key in `EncryptedData` for secure decryption.

## [0.1.0] - 2025-09-05
### Added
- Core CLI functionality for single file encryption/decryption using ML-KEM-1024, HKDF-SHA256, and AES-256-GCM.
- Interactive menu with colored output using `console = "0.15.11"`.
- Support for replace/copy modes in file operations.
- Basic unit test for KEM encryption/decryption round-trip.
- `README.md` with installation, usage examples, and file format details.
- `LICENSE` (MIT/Apache-2.0) and `Cargo.toml` with metadata for crates.io readiness.
- `EncryptedData` struct for serialization with `serde` and `bincode`.
- Dependencies: `oqs`, `aes-gcm`, `hkdf`, `rand`, `anyhow` for robust error handling.

### Changed
- Initial project structure aligned with Rust best practices (e.g., idiomatic `Result` error handling).
- Standardized error messages to red for better visibility.

### Security
- Integrated `zeroize` for key/secret erasure post-use.
- Used constant-time operations via `oqs` library.
- Pinned audited crates for supply-chain security.

## [0.0.2] - 2025-08-20
### Added
- `zeroize = "1.7.0"` for secure memory handling of cryptographic keys.
- Basic error handling with `anyhow` for robust CLI operation.
- Initial `SECURITY.md` with basic threat model (expanded later).

### Changed
- Refactored `encrypt_file` to use `oqs::kem` for ML-KEM-1024.
- Updated `Cargo.toml` to pin `oqs` to version `0.10` with `zeroize` feature.

### Fixed
- Resolved memory leak in keypair generation by ensuring proper cleanup.

### Security
- Added manual zeroization for `SecretKey` and `SharedSecret`.

## [0.0.1] - 2025-08-01
### Added
- Initial prototype with single-file encryption using ML-KEM-1024.
- Basic CLI interface with `console` for colored output.
- Dependencies: `oqs = "0.10"`, `aes-gcm`, `hkdf`, `serde`, `bincode`.
- MIT license and initial `README.md` with setup instructions.

### Changed
- Set up project structure with `main.rs` and basic KEM logic.

### Security
- Initial integration of post-quantum cryptography with ML-KEM-1024.

[0.1.0]: https://github.com/GuckertDev/post-quantum-encryption/releases/tag/v0.1.0
[0.0.2]: https://github.com/GuckertDev/post-quantum-encryption/releases/tag/v0.0.2
[0.0.1]: https://github.com/GuckertDev/post-quantum-encryption/releases/tag/v0.0.1