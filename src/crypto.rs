use anyhow::{anyhow, Result};
use oqs::kem::SharedSecret;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;
use argon2::Argon2;
use zeroize::Zeroize;

// Use a constant for the HKDF info parameter for consistency and domain separation
const HKDF_INFO: &[u8] = b"post-quantum-encryption-aes-key-v1";

pub fn derive_seed(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut seed = [0u8; 32];
    // We expect here as Argon2 with default parameters and correct output length shouldn't fail.
    argon2.hash_password_into(passphrase, salt, &mut seed).expect("Argon2 key derivation failed");
    seed
}

pub fn encrypt_symmetric(data: &[u8], key: &SharedSecret, passphrase: Option<&str>) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
    let mut derived_salt = None;
    let raw_key = if let Some(pass) = passphrase {
        let mut s = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut s);
        derived_salt = Some(s.clone());
        let seed = derive_seed(pass.as_bytes(), &s);
        let mut effective_key = key.as_ref().to_vec();
        effective_key.extend_from_slice(&seed[..]);
        effective_key
    } else {
        key.as_ref().to_vec()
    };

    let hkdf = Hkdf::<Sha256>::new(None, &raw_key);
    let mut aes_key = [0u8; 32];
    // Use distinct info parameter for domain separation
    hkdf.expand(HKDF_INFO, &mut aes_key)
        .map_err(|e| anyhow!("HKDF key derivation failed: {}", e))?;

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| anyhow!("Failed to initialize AES-GCM: {}", e))?;

    // Zeroize the derived AES key from memory after initialization
    aes_key.zeroize();

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    Ok((ciphertext, nonce_bytes.to_vec(), derived_salt))
}

pub fn decrypt_symmetric(data: &[u8], key: &SharedSecret, nonce_slice: &[u8], passphrase: Option<&str>, salt: Option<&[u8]>) -> Result<Vec<u8>> {
    let raw_key = if let Some(pass) = passphrase {
        let s = salt.ok_or_else(|| anyhow!("Salt required for passphrase mode but not provided"))?;
        let seed = derive_seed(pass.as_bytes(), s);
        let mut effective_key = key.as_ref().to_vec();
        effective_key.extend_from_slice(&seed[..]);
        effective_key
    } else {
        key.as_ref().to_vec()
    };

    let hkdf = Hkdf::<Sha256>::new(None, &raw_key);
    let mut aes_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut aes_key)
        .map_err(|e| anyhow!("HKDF key derivation failed: {}", e))?;

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| anyhow!("Failed to initialize AES-GCM: {}", e))?;

    aes_key.zeroize();

    if nonce_slice.len() != 12 {
        return Err(anyhow!("Invalid nonce length: expected 12 bytes, got {}", nonce_slice.len()));
    }
    let nonce = Nonce::from_slice(nonce_slice);

    let plaintext = cipher.decrypt(nonce, data)
        // This error occurs if the authentication tag is invalid (e.g., wrong key, corrupted data, or wrong nonce)
        .map_err(|e| anyhow!("Decryption failed (invalid authentication tag): {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oqs::kem::{Algorithm, Kem};

    // Helper to generate a shared secret for testing
    fn get_test_shared_secret() -> SharedSecret {
        let alg = Algorithm::Kyber1024;
        let kem = Kem::new(alg).unwrap();
        let (pk, _) = kem.keypair().unwrap();
        let (_, ss) = kem.encapsulate(&pk).unwrap();
        ss
    }

    #[test]
    fn test_derive_seed_determinism() {
        let passphrase = b"test_password";
        let salt = b"random_salt_1234";
        let seed1 = derive_seed(passphrase, salt);
        let seed2 = derive_seed(passphrase, salt);
        assert_eq!(seed1, seed2); // Deterministic derivation

        let different_salt = b"other_salt_5678";
        let seed3 = derive_seed(passphrase, different_salt);
        assert_ne!(seed1, seed3); // Different salt yields different seed

        let different_passphrase = b"another_password";
        let seed4 = derive_seed(different_passphrase, salt);
        assert_ne!(seed1, seed4); // Different passphrase yields different seed

        assert_eq!(seed1.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_symmetric_no_passphrase() -> Result<()> {
        let shared_secret = get_test_shared_secret();
        let data = b"Hello, Post-Quantum World!";

        // Encrypt
        let (ciphertext, nonce, salt) = encrypt_symmetric(data, &shared_secret, None)?;
        assert!(salt.is_none());
        assert_ne!(&ciphertext, data);
        assert_eq!(nonce.len(), 12);

        // Decrypt
        let plaintext = decrypt_symmetric(&ciphertext, &shared_secret, &nonce, None, None)?;
        assert_eq!(plaintext, data);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_symmetric_with_passphrase() -> Result<()> {
        let shared_secret = get_test_shared_secret();
        let data = b"Sensitive data protected by KEM and Passphrase.";
        let passphrase = "strong_password_!@#";

        // Encrypt
        let (ciphertext, nonce, salt) = encrypt_symmetric(data, &shared_secret, Some(passphrase))?;
        assert!(salt.is_some());
        assert_eq!(salt.as_ref().unwrap().len(), 16);

        // Decrypt
        let plaintext = decrypt_symmetric(&ciphertext, &shared_secret, &nonce, Some(passphrase), salt.as_deref())?;
        assert_eq!(plaintext, data);

        Ok(())
    }

    #[test]
    fn test_decrypt_symmetric_wrong_passphrase() {
        let shared_secret = get_test_shared_secret();
        let data = b"Data";
        let correct_pass = "correct";
        let wrong_pass = "wrong";

        let (ciphertext, nonce, salt) = encrypt_symmetric(data, &shared_secret, Some(correct_pass)).unwrap();

        let result = decrypt_symmetric(&ciphertext, &shared_secret, &nonce, Some(wrong_pass), salt.as_deref());
        assert!(result.is_err());
        // The error should indicate decryption failure (invalid tag) because the derived key is wrong
        assert!(result.unwrap_err().to_string().contains("Decryption failed (invalid authentication tag)"));
    }

    #[test]
    fn test_decrypt_symmetric_missing_salt() {
        let shared_secret = get_test_shared_secret();
        let data = b"Data";
        let passphrase = "password123";

        // Encrypt with passphrase (generates salt internally)
        let (ciphertext, nonce, _) = encrypt_symmetric(data, &shared_secret, Some(passphrase)).unwrap();

        // Attempt to decrypt with passphrase but provide None for salt
        let result = decrypt_symmetric(&ciphertext, &shared_secret, &nonce, Some(passphrase), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Salt required for passphrase mode but not provided"));
    }

    #[test]
    fn test_decrypt_symmetric_invalid_nonce_length() {
        let shared_secret = get_test_shared_secret();
        let ciphertext = vec![1, 2, 3, 4];
        let invalid_nonce = vec![1, 2, 3]; // Too short

        let result = decrypt_symmetric(&ciphertext, &shared_secret, &invalid_nonce, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid nonce length: expected 12 bytes, got 3"));
    }

    #[test]
    fn test_decrypt_symmetric_corrupted_data() {
        let shared_secret = get_test_shared_secret();
        let data = b"Original data";

        let (mut ciphertext, nonce, _) = encrypt_symmetric(data, &shared_secret, None).unwrap();

        // Corrupt the ciphertext
        let corrupt_index = ciphertext.len() / 2;
        ciphertext[corrupt_index] = ciphertext[corrupt_index].wrapping_add(1);

        let result = decrypt_symmetric(&ciphertext, &shared_secret, &nonce, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Decryption failed (invalid authentication tag)"));
    }

    #[test]
    fn test_decrypt_symmetric_wrong_kem_key() {
        let shared_secret1 = get_test_shared_secret();
        let shared_secret2 = get_test_shared_secret(); // Different key
        assert_ne!(shared_secret1.as_ref(), shared_secret2.as_ref());

        let data = b"Data";

        let (ciphertext, nonce, _) = encrypt_symmetric(data, &shared_secret1, None).unwrap();

        // Attempt to decrypt with the wrong KEM shared secret
        let result = decrypt_symmetric(&ciphertext, &shared_secret2, &nonce, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Decryption failed (invalid authentication tag)"));
    }
}