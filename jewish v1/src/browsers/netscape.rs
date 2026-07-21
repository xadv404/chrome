//! Netscape HTTP Cookie File format (curl / browser import compatible).
//! https://curl.se/docs/http-cookies.html

pub const HEADER: &str = "\
# Netscape HTTP Cookie File
# https://curl.se/docs/http-cookies.html
# This file was generated automatically.

";

/// Format one cookie line for a Netscape cookies.txt file.
pub fn format_line(
    host: &str,
    path: &str,
    secure: bool,
    expiry: i64,
    name: &str,
    value: &str,
    httponly: bool,
) -> String {
    let include_subdomains = if host.starts_with('.') { "TRUE" } else { "FALSE" };
    let secure_flag = if secure { "TRUE" } else { "FALSE" };
    let host_field = if httponly {
        format!("#HttpOnly_{host}")
    } else {
        host.to_string()
    };
    format!(
        "{host_field}\t{include_subdomains}\t{path}\t{secure_flag}\t{expiry}\t{name}\t{value}\n"
    )
}

pub fn build_file(body: &str) -> Option<String> {
    if body.is_empty() {
        None
    } else {
        Some(format!("{HEADER}{body}"))
    }
}
