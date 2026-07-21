//! AES-256-GCM decryption for Chrome's encrypted data.
//!
//! Chrome encodes encrypted values as:
//!   v10: "v10" + 12-byte nonce + ciphertext+tag
//!   v20: "v20" + 12-byte nonce + ciphertext+tag
//!
//! Both use the same layout; the prefix indicates which key to use.
//! v20 data requires the App-Bound key.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const PREFIX_LEN: usize = 3; // "v10" or "v20"

/// Decrypt a Chrome-encrypted value (v10 or v20 format) with the given key.
pub fn decrypt_value(encrypted: &[u8], key: &[u8; 32]) -> Result<String, String> {
    if encrypted.len() < PREFIX_LEN + NONCE_LEN + TAG_LEN {
        return Err(format!(
            "value too short: {} bytes",
            encrypted.len()
        ));
    }

    let prefix = &encrypted[..PREFIX_LEN];
    if prefix != b"v10" && prefix != b"v20" {
        // Might be plaintext (old Chrome versions stored plaintext).
        return String::from_utf8(encrypted.to_vec())
            .map_err(|_| "not v10/v20 and not valid UTF-8".into());
    }

    let nonce_bytes = &encrypted[PREFIX_LEN..PREFIX_LEN + NONCE_LEN];
    let ciphertext = &encrypted[PREFIX_LEN + NONCE_LEN..];

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES-GCM decrypt: {e}"))?;

    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 decode: {e}"))
}

/// Return a HEX representation for bytes that cannot be decrypted as UTF-8.
pub fn hex_fallback(data: &[u8]) -> String {
    format!("[HEX:{}]", data.iter().map(|b| format!("{b:02x}")).collect::<String>())
}
