use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        env::var("CHROME_PAYLOAD_DLL")
            .ok()
            .map(PathBuf::from),
        Some(manifest_dir.join("target/release/chrome_payload.dll")),
        Some(manifest_dir.join("../target/release/chrome_payload.dll")),
    ];

    let out = PathBuf::from(env!("OUT_DIR")).join("payload.dll");
    let mut copied = false;

    for src in candidates.into_iter().flatten() {
        if src.exists() {
            fs::copy(&src, &out).expect("copy payload.dll into OUT_DIR");
            println!("cargo:rerun-if-changed={}", src.display());
            copied = true;
            break;
        }
    }

    if !copied {
        fs::write(&out, b"").ok();
        println!("cargo:warning=chrome_payload.dll not found — build payload first: cargo build -p chrome-payload --release");
    }
}
