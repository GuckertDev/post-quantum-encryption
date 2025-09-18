# Security Policy

## Supported Versions
| Version | Supported          |
|---------|--------------------|
| 0.2.1   | ✅                 |
| < 0.2.0 | ❌                 |

## Reporting a Vulnerability
If you discover a security vulnerability, please report it responsibly:
1. **Contact**: Email `security@guckert.dev` with:
   - Detailed description of the vulnerability.
   - Steps to reproduce (if applicable).
   - Potential impact and severity.
   - Your contact details (optional, for follow-up).
2. **Response Timeline**:
   - Acknowledgment: Within 48 hours.
   - Initial assessment: Within 7 days.
   - Fix or mitigation: Within 30 days for critical issues, per OpenSSF guidelines.
3. **Disclosure**: We follow coordinated disclosure. You’ll be credited (if desired) in `CHANGELOG.md` once resolved.
4. **Avoid**: Do not post vulnerabilities publicly in issues, discussions, or social media (e.g., X) to prevent exploitation.

## Threat Model (NIST IR 8545)
### Introduction
This threat model outlines assets, threats, and mitigations for the Post-Quantum Encryption CLI tool, which uses a hybrid cryptographic scheme (ML-KEM-1024, HKDF-SHA256, AES-256-GCM, optional Argon2).  
- **Assets**: User files, encryption keys, derived secrets, passphrases.  
- **Adversaries**: Quantum-capable nation-states, insiders, malware.  
- **Model**: Assumes Dolev-Yao network model and potential side-channel attacks.

### Key Threats and Mitigations
1. **Quantum Attacks**:
   - **Threat**: Shor's algorithm breaks classical public-key cryptography; Grover's algorithm reduces symmetric key strength.
   - **Mitigation**: ML-KEM-1024 (NIST FIPS 203) for quantum-resistant key encapsulation. AES-256-GCM and HKDF-SHA256 for symmetric encryption, robust against Grover’s algorithm.
2. **Side-Channel Attacks**:
   - **Threat**: Timing or power analysis leaks keys or secrets.
   - **Mitigation**: Constant-time operations via `subtle` and `oqs`. Memory zeroization with `zeroize` crate. Regular audits with `cargo crev`.
3. **Key Derivation/Management Issues**:
   - **Threat**: Weak entropy, key reuse, or exposure.
   - **Mitigation**: CSPRNG via `rand` for key generation. HKDF-SHA256 with random salts. Optional Argon2 for passphrase strengthening in `--passphrase` mode. Ephemeral keys used by default.
4. **Data Integrity/Confidentiality Breaches**:
   - **Threat**: Tampering, decryption failures, or corrupt files.
   - **Mitigation**: AES-GCM provides authenticated encryption, ensuring decryption fails on tampered data. Robust error handling with `anyhow` for invalid inputs or corrupt files.
5. **Usability-Related Risks**:
   - **Threat**: User errors (e.g., weak passphrases, incorrect flags).
   - **Mitigation**: CLI input validation, clear error messages, and comprehensive documentation (`docs/guide.md`). Planned: `rpassword` for secure passphrase input, `indicatif` for progress feedback.
6. **Supply Chain/Dependency Attacks**:
   - **Threat**: Malicious or vulnerable dependencies.
   - **Mitigation**: Regular `cargo audit` checks in CI. Pinned crate versions in `Cargo.toml`. Dependabot alerts via GitHub Security tab.

### Residual Risks
- **Harvest-Now-Decrypt-Later**: Mitigated by ML-KEM-1024’s forward secrecy.
- **Physical Access**: Users must implement OS-level protections (e.g., disk encryption).
- **Passphrase Input**: Current `std::io` input is unmasked; `rpassword` integration planned.
- **Metadata Integrity**: No HMAC on `EncryptedData` yet; planned for future releases.

### Recommendations
- Conduct quarterly threat model reviews using STRIDE methodology.
- Integrate OpenSSF Scorecard for third-party security validation.
- Plan external audits (e.g., Trail of Bits) post-v1.0.
- Enhance with `rpassword` and HMAC for improved security.

## Dependency Management
- **Audits**: `cargo-audit` runs in CI to detect vulnerable dependencies.
- **Pinning**: Crate versions are pinned in `Cargo.toml` for reproducibility.
- **Monitoring**: GitHub Dependabot alerts for known issues. Prompt updates for security fixes, maintaining compatibility.

## Security Audits
- **Tools**: Integrated `cargo-audit` and `clippy` in CI. Fuzz testing with `cargo-fuzz` for `decrypt_symmetric`.
- **Scorecard**: Targeting OpenSSF Scorecard A-grade (planned integration).
- **External Audits**: Planned post-v1.0 with professional security firms.
- **Guidelines**: Follows [ANSSI Rust secure coding guidelines](https://www.anssi.fr/en/secure-development-rust).

## Verification
- Run dependency audit: `cargo audit`.
- Run fuzz tests: `cargo +nightly fuzz run decrypt -- -runs=10000`.
- Check coverage: `cargo tarpaulin --out Html` (target >98%).
- Review [CHANGELOG.md](CHANGELOG.md) for security fixes.

We appreciate your help in keeping Post-Quantum Encryption secure and production-ready!