# Compliance of U.S. government's highest security standards for Cryptographic Technologies

**Purpose**: To ensure all cryptographic technologies, proccesses and associated software libraries and functionality used in the `Post-Quantum Encryption software` is compliant, secure and safely capable of handling data of classified information up to `Top Secret/SCI`, under NSA guidelines or `sensitive unclassified data`, under `FISMA/FedRAMP` and compliance and exemplary software execution of high US government security standards `FIPS 140-3 Security Level 3`, using software-only implementations to ensure accessibility on standard hardware, while all other security controls, processes, and non-cryptographic components and tooling adhere to `FIPS 140-3 Security Level 4` equivelencies as regulated by the `United States National Institute of Standards and Technology` (`NIST`) and the `United States National Security Agency` (`NSA`) regulations.

**Scope**: This directive applies to all software dependencies listed in the provided dependency list, with all cryptographic libraries required to be `U.S. FIPS 140-3 Security Level 3 compliant` and all non-cryptographic libraries, packages, system configurations, and all other operational software controls compliant with `U.S. Security Level 4` equivalence standards, all implemented in software without requiring specialized hardware (e.g., HSMs or cryptographic accelerators).

**Effective Date**: September 17, 2025, 14:09 EDT

**Directive**: All cryptographic technologies, proccesses, functions and packages must comply with `NIST’s Cryptographic Module Validation Program (CMVP)` under `FIPS 140-3` at `U.S. Security Level 3` using software-only implementations to ensure robust protection and accessibility on standard hardware (e.g., commodity CPUs). All other security controls, including non-cryptographic libraries, system configurations, authentication mechanisms, and operational environments, must be compliant to `FIPS 140-3 Security Level 4 equivenlance standards` (e.g., tamper-evident measures, strict role-based access, hardened software environments) or agency-specific maximums, and align with `NSA’s Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)` for classified data. All components must be executable by anyone who downloads the software on standard hardware without specialized hardware dependencies.

---

## Requirements and Implementation Guidelines

### 1. Governing Standards
All cryptographic and non-cryptographic components must adhere to the following official U.S. documents to ensure interoperability, security assurance, and quantum resistance:

- **FIPS 140-3**: Security Requirements for Cryptographic Modules (NIST). Cryptographic modules must be validated at Security Level 3, requiring `software-based protection`, `role-based authentication`, and `secure operational environments`. Non-cryptographic controls (e.g., authentication, system hardening) must meet Security Level 4 equivalence via software configurations.
- **NIST SP 800-175B Revision 1**: Guideline for Using Cryptographic Standards. Specifies approved algorithms (e.g., AES-256, SHA-384, ECDSA, ML-KEM, ML-DSA).
- **NSA CNSA 2.0**: Commercial National Security Algorithm Suite mandates algorithms for classified data (e.g., AES-256, SHA-384, post-quantum ML-KEM) for NSS.
- **NIST SP 800-53 Revision 5**: Security and Privacy Controls. Requires `FIPS-validated cryptography at Security Level 3` for `SC-13 controls` and Level 4-equivalent software controls for other High Impact requirements (e.g., AC-2, IA-2).
- **FIPS 186-5**: Digital Signature Standard. Specifies approved signature algorithms (e.g., ECDSA, EdDSA, ML-DSA).
- **CMVP Validated Modules List**: Cryptographic modules must be validated at Security Level 3 or higher in `NIST’s CMVP database`.
- **CNSSI 4009** (if applicable): Agency-specific guidance for NSS, emphasizing maximum software-based security controls.

**Action**: Verify cryptographic modules against the [CMVP database](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules) for Security Level 3 validation. Ensure non-cryptographic controls meet Level 4 equivalence via software configurations (e.g., hardened OS, MFA). Confirm CNSA 2.0 compliance for NSS via [NSA guidance](https://www.nsa.gov).

### 2. Dependencies Requiring Replacement (Cryptographic, FIPS 140-3 Security Level 3, Software-Only)
The following cryptographic libraries **do not** meet FIPS 140-3 Security Level 3 or CNSA 2.0 requirements and must be replaced with software-only, FIPS-validated alternatives. Implementation steps use `aws-lc-rs` (FIPS 140-3 Level 1 validated, Certificate #4631, configurable for Level 3) or `openssl`, both running on standard hardware.

| Technology | Reason for Replacement | Replacement | Implementation Steps |
|-----------|-----------------------|-------------|----------------------|
| **oqs & oqs-sys** | Open Quantum Safe libraries are experimental and not FIPS 140-3 validated at Security Level 3. NIST-standardized PQC algorithms (e.g., ML-KEM, ML-DSA) require Level 3-validated software implementations. | **AWS-LC via aws-lc-rs** (FIPS 140-3 validated, supports ML-KEM, ML-DSA). | 1. Replace `oqs` and `oqs-sys` with `aws-lc-rs` (version 0.22 or later) in `Cargo.toml`. 2. Update code to use `aws_lc_rs::kem` for PQC algorithms. 3. Configure for FIPS mode (`AWS_LC_FIPS=1`) and Level 3 compliance (e.g., role-based authentication, secure OS). 4. Verify validation status on NIST CMVP. |
| **aes-gcm** | RustCrypto’s `aes-gcm` is not FIPS 140-3 validated at Security Level 3. AES-GCM must use a Level 3-validated software module. | **AWS-LC via aws-lc-rs** (FIPS 140-3 validated AES-GCM). | 1. Replace `aes-gcm` with `aws-lc-rs` in `Cargo.toml`. 2. Refactor code to use `aws_lc_rs::aead` for AES-GCM. 3. Enable FIPS mode and configure for Level 3 (e.g., secure OS environment). 4. Test with NIST’s ACVP. |
| **hkdf** | RustCrypto’s `hkdf` is not FIPS 140-3 validated at Security Level 3. HMAC-based KDFs must be validated at Level 3. | **AWS-LC via aws-lc-rs** (FIPS 140-3 validated HKDF). | 1. Replace `hkdf` with `aws-lc-rs`. 2. Use `aws_lc_rs::hkdf` for key derivation. 3. Configure for FIPS Level 3 mode. 4. Validate output against NIST SP 800-56C. |
| **sha2** | RustCrypto’s `sha2` is not FIPS 140-3 validated at Security Level 3. SHA-2 requires a Level 3-validated software module. | **AWS-LC via aws-lc-rs** (FIPS 140-3 validated SHA-256, SHA-384, SHA-512). | 1. Replace `sha2` with `aws-lc-rs`. 2. Update to `aws_lc_rs::digest` for SHA-2. 3. Enable FIPS Level 3 mode. 4. Verify with NIST’s CAVP test vectors. |
| **rand** | `rand` is not a FIPS 140-3 validated RNG at Security Level 3. NIST SP 800-90A-compliant DRBGs are required in Level 3 software modules. | **AWS-LC via aws-lc-rs** (FIPS 140-3 validated CTR_DRBG or HMAC_DRBG) or **getrandom** (in FIPS mode). | 1. Replace `rand` with `aws-lc-rs` or `getrandom`. 2. Use `aws_lc_rs::rand` or `getrandom` for NIST SP 800-90A DRBG. 3. Configure for Level 3 mode (secure OS). 4. Test with NIST SP 800-90A test suites. |
| **argon2** | Argon2 is not FIPS-approved. NIST recommends PBKDF2 in a Level 3-validated software module for password hashing. | **AWS-LC via aws-lc-rs or OpenSSL** (FIPS-validated PBKDF2). | 1. Replace `argon2` with `aws-lc-rs` or `openssl` crate. 2. Implement PBKDF2 using `aws_lc_rs::pbkdf2` or `openssl::pkcs5`. 3. Configure for Level 3 mode. 4. Validate per NIST SP 800-132. |

### 3. Dependencies Not Requiring Replacement (Non-Cryptographic, Security Level 4 Equivalence, Software-Only)
The following libraries are non-cryptographic or do not perform cryptographic functions. They must meet security standards equivalent to `U.S. FIPS 140-3 Security Level 4` using `software-only configurations` (e.g., tamper-evident logging, strict role-based access, hardened OS) to ensure maximum security without hardware dependencies:

- **clap, anyhow, bincode, serde, serde_bytes, walkdir, colored, indicatif, rayon, toml, dirs, dialoguer, console, rpassword**: No cryptographic functions, implemented as software-only Rust crates. Secure to Level 4 equivalence via:
  - **Vulnerability Management**: Use `cargo-audit` to ensure no critical CVEs. Update or remove vulnerable versions.
  - **Secure Configuration**: Implement `tamper-evident logging` (e.g., via  `rpassword` for secure input) and `role-based authentication` (e.g., software-based MFA per `NIST SP 800-63-3`).
  - **Hardened Environment**: Deploy on a `Level 4-equivalent software environment` (e.g., SELinux with strict policies, Windows with Secure Boot and BitLocker).
- **zeroize, subtle**: Software-based security utilities (memory zeroing, constant-time ops) used in cryptographic contexts. Acceptable when paired with Level 3-validated cryptographic modules and configured for Level 4-equivalent security:
  - **Integration**: Ensure `zeroize` and `subtle` are used with FIPS-validated modules (e.g., aws-lc-rs) and `do not bypass FIPS mode`.
  - **Environment**: Enforce Level 4-equivalent controls (e.g., memory protection, tamper-evident auditing) via software (`NIST SP 800-53 SC-28`).
- **criterion, arbitrary, libfuzzer-sys, tempfile, proptest, assert_cmd, predicates**: Development/testing tools, not used in production. Ensure exclusion from production builds via `Cargo.toml` `[dev-dependencies]`.

**Action**: Conduct a security assessment of non-cryptographic libraries using `cargo-audit` and `NSA’s software supply chain guidance` (`EO 14028`). Configure systems to meet Level 4-equivalent software controls (e.g., tamper-evident logs, MFA, hardened OS). Document compliance with NIST SP 800-53 (e.g., AC-2, AU-2, SC-28).

### 4. Implementation Guidelines
- **Cryptographic Modules (Level 3, Software-Only)**: Configure cryptographic modules (e.g., aws-lc-rs) for FIPS 140-3 Security Level 3 using software-only implementations. Set `AWS_LC_FIPS=1` for aws-lc-rs and ensure Level 3 compliance (e.g., role-based authentication, secure OS). Verify execution on standard hardware (e.g., x86/ARM CPUs).
- **Non-Cryptographic Components (Level 4 Equivalence, Software-Only)**: Implement maximum security controls via software:
  - **Authentication**: Use software-based MFA (e.g., TOTP via software tokens per NIST SP 800-63-3) or integrate with OS-level authentication (e.g., Kerberos, LDAP).
  - **System Hardening**: Deploy on hardened software environments (e.g., SELinux with mandatory access control, Windows with Secure Boot and BitLocker).
  - **Auditing**: Enable tamper-evident logging via software (e.g., Linux auditd, Windows Event Logging) per NIST SP 800-53 AU-2, AU-9.
- **Validation Verification**: Confirm cryptographic modules are listed in NIST’s [CMVP database](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules) at Security Level 3 or higher. Verify non-cryptographic controls meet Level 4 equivalence via agency audits.
- **CNSA 2.0 Compliance**: Use `CNSA 2.0-approved algorithms` (e.g., AES-256, SHA-384, ML-KEM) for classified systems, implemented via software libraries (e.g., aws-lc-rs). Consult [NSA guidance](https://www.nsa.gov).
- **Testing and Validation**: Use `NIST’s ACVP and CAVP for cryptographic modules`, ensuring compliance with `NIST SP 800-90A` (`RNG`), `SP 800-56C` (`KDF`), and `SP 800-132` (`PBKDF2`). Test non-cryptographic components against `DISA STIGs` or `NIST SP 800-53` controls using software tools.
- **Documentation**: Maintain records of module validations, configurations, and test results per NIST SP 800-53 (`AU-3`, `CM-3`). Document Level 4-equivalent software controls. S`ubmit to Authorizing Official` (`AO`) for `ATO` under `FISMA`.
- **Quantum Resistance**: Prioritize `CNSA 2.0-compliant post-quantum algorithms` (e.g., ML-KEM, ML-DSA) via software libraries, per `NSM-8` and `NSM-10`. Monitor NIST PQC updates.
- **Accessibility**: Ensure all components (e.g., aws-lc-rs, openssl, hardened OS) are software-only, open-source, and executable on standard hardware (e.g., commodity CPUs) without HSMs or cryptographic accelerators.

### 5. Monitoring and Updates
- **Regular Audits**: Check [NIST CSRC](https://csrc.nist.gov) and [NSA websites](https://www.nsa.gov) quarterly for updates to `U.S. FIPS 140-3 Security Level 3 validations`, `CNSA 2.0`, and `PQC standards`. Audit non-cryptographic software controls for Level 4 equivalence.
- **Agency Coordination**: Consult agency-specific policies (e.g., CNSSI 4009 for DoD) for additional software-based requirements. Engage with the agency’s Information System Security Officer (ISSO) for approval.
- **Supply Chain Security**: `Follow NSA’s software supply chain security guidance` (`EO 14028`) to vet open-source dependencies (e.g., aws-lc-rs) for provenance and integrity using software tools.

---

**Enforcement**: Non-compliance `risks system decertification` under `FISMA` or `NSA` regulations. All replacements and configurations must be completed, tested, and documented by December 16, 2025 (90 days from issuance). Report progress to `security@guckert.dev` and submit `compliance evidence` to the `AO`.

**Resources**:
- [NIST CSRC](https://csrc.nist.gov)
- [NSA CNSA 2.0](https://www.nsa.gov)
- [AWS-LC GitHub](https://github.com/aws/aws-lc)
- [aws-lc-rs GitHub](https://github.com/aws/aws-lc-rs)
- [CMVP Database](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)

**Point of Contact**: Email `security@guckert.dev` for implementation support and questions.

---

This directive ensures cryptographic dependencies meet `U.S. FIPS 140-3 Security Level 3` for accessibility on standard hardware, while non-cryptographic components and security controls are `U.S. FIPS 140-3 Security Level 4` compliant, all using `software-only` implementations, enabling compliance with `FISMA`, `FedRAMP`, and `NSA` requirements for `protecting sensitive and classified data` while maintaining wide-spread, download-and-work accesibility for average consumers without the need of specialized hardware requirments. The end goal is bringing a level of cryptographic security quality and software excellence, normally reserved only for high-level government and military applications and personell, as global tool available and accessible for everyone.

