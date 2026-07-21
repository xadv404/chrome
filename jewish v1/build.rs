use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = env::var("OUT_DIR")
        .map(PathBuf::from)
        .expect("OUT_DIR not set")
        .join("payload.dll");

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
        let size = fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
        if size == 0 {
            continue;
        }
        fs::copy(&src, &out).expect("copy payload.dll into OUT_DIR");
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
