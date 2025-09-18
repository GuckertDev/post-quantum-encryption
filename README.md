# Post-Quantum Encryption

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Build Status](https://github.com/GuckertDev/post-quantum-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/GuckertDev/post-quantum-encryption/actions)
[![Codecov](https://codecov.io/gh/GuckertDev/post-quantum-encryption/branch/main/graph/badge.svg)](https://codecov.io/gh/GuckertDev/post-quantum-encryption)

A robust CLI tool for post-quantum file and folder encryption/decryption using a hybrid cryptographic scheme (ML-KEM-1024 for key encapsulation, HKDF-SHA256 for key derivation, AES-256-GCM for data encryption, and optional Argon2 for passphrase strengthening).

---

## Features

- **`Post-Quantum Security`** NIST-compliant ML-KEM-1024 (FIPS 203) for quantum-resistant encryption.
- **`Hybrid Cryptography`** Combines **ML-KEM-1024** with **AES-256-GCM** for robust data protection.
- **`Passphrase Mode`** Optional **Argon2** for secure key derivation.
- **`Folder Support`** Recursive encryption/decryption with parallel processing via **Rayon**.
- **`Flexible Modes`** 'Overwrite' or 'Make a Copy' modes for file and folder operations.
- **`Cross-Platform`** Tested on Windows, macOS, and Linux via GitHub Actions.
- **`Comprehensive Testing`** >98% test coverage with unit tests, fuzzing, and benchmarks.
- **`CI/CD`** Automated testing, linting, and security audits via GitHub Actions.

---

## Installation
```bash
cargo install --git https://github.com/GuckertDev/post-quantum-encryption.git
```

## Example
To get started, simply run the program in interactive mode. This will launch a user-friendly menu that guides you through the process of encrypting and decrypting files and folders.

### Encrypt a File:
1. Run the following command in your terminal/shell:
```bash
post-quantum-encryption --interactive
```

2. From the main menu, choose 1. Encrypt File by typing 1 and pressing enter.
3. Next, paste or type the full path to the file you want to encrypt and press enter.
4. Next, choose your action. Type 1 to Overwrite Original or 2 to Make a Copy and press enter.
5. The program will then encrypt the file and confirm completion.

## Threat Model (NIST IR 8545)
- **`Quantum-Resistant`** Our core encryption is built on a future-proof scheme designed to withstand attacks from even the most powerful quantum computers.
- **`Side-Channel Protection`** The design prevents information leaks during the encryption process, so attackers can't guess your key from power consumption or timing.
- **`Unbreakable Passphrases`** Your passphrase is reinforced with a state-of-the-art hashing algorithm, making it nearly impossible for an attacker to crack it through brute-force attacks.
- **`Tamper-Proof Data`** GCM authentication guarantees that if your encrypted files are altered in any way, decryption will immediately fail, protecting you from malicious data corruption.
- **`Storage`** Your encryption is handled with one-time, disposable keys, giving you full control over key management. For enterprise-level protection, we recommend integrating with a hardware wallet.

## Usage
Ready to get started? Our comprehensive guide in `docs/guide.md` provides detailed examples and step-by-step instructions to help you start encrypting and decrypting with ease.

## Security
We take security seriously. If you discover a vulnerability, please report it responsibly by emailing `security@guckert.dev`. For more details on our security policy, see `SECURITY.md`.

## Contribution & Development
This project is currently being developed by a single maintainer with the goal of producing a finalized, polished, and ready-to-use product. As such, the project is not currently accepting external code contributions to maintain focus on the core development roadmap. However, we highly value community feedback. If you have a feature idea, or want to discuss the project, please email `contact@guckert.dev`.

