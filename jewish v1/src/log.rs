use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Mutex,
};

use chrono::Utc;

static LOG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

pub fn log_path() -> PathBuf {
    if let Ok(guard) = LOG_PATH.lock() {
        if let Some(ref p) = *guard {
            return p.clone();
        }
    }
    std::env::temp_dir().join("jewish_debug.log")
}

pub fn init() {
    let path = log_path();
    if let Ok(mut guard) = LOG_PATH.lock() {
        *guard = Some(path.clone());
    }
    let header = format!(
        "=== jewish debug log {} ===\r\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    let _ = fs::write(&path, header);
    log(&format!("log file: {}", path.display()));
}

pub fn log(msg: &str) {
    let line = format!("[{}] {}\r\n", Utc::now().format("%H:%M:%S"), msg);
    let path = log_path();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(line.as_bytes());
    }
}
