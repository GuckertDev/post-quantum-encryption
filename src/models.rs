use serde::{Serialize, Deserialize};
use serde_bytes::ByteBuf;

// Added Clone derive for easier testing manipulation (e.g., testing corrupted data scenarios)
#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedData {
    pub alg_id: String,
    pub public_key_bytes: ByteBuf,
    pub ciphertext_bytes: ByteBuf,
    pub encrypted_content: Vec<u8>,
    pub original_path: String,
    pub nonce: ByteBuf,
    pub salt: Option<Vec<u8>>, // For passphrase mode
    pub private_key_bytes: ByteBuf,
}