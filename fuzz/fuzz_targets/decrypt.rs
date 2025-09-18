use libfuzzer_sys::fuzz_target;
use post_quantum_encryption::{decrypt_symmetric, Kem, Algorithm, SharedSecret};
use aes_gcm::Nonce;

fuzz_target!(|data: &[u8]| {
    let kem = match Kem::new(Algorithm::Kyber1024) {
        Ok(kem) => kem,
        Err(_) => return,
    };
    let (pk, sk) = match kem.keypair() {
        Ok(kp) => kp,
        Err(_) => return,
    };
    let (ct, ss) = match kem.encapsulate(&pk) {
        Ok(enc) => enc,
        Err(_) => return,
    };
    let nonce = vec![0u8; 12];
    let _ = decrypt_symmetric(data, &ss, &nonce, None, None);
});