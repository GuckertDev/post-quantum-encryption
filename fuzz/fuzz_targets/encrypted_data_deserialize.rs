#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use post_quantum_encryption::EncryptedData; // From lib
use bincode;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<EncryptedData>(data);
});
