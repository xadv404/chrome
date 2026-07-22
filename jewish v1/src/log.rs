#[cfg(debug_assertions)]
use std::{
    env, fs,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::Mutex,
};

#[cfg(debug_assertions)]
use chrono::Utc;

#[cfg(debug_assertions)]
static LOG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

#[cfg(debug_assertions)]
fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(local) = env::var("LOCALAPPDATA") {
        paths.push(PathBuf::from(local).join("app").join("trace.log"));
    }

    paths.push(env::temp_dir().join("trace.log"));

    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("trace.log"));
        }
    }

    paths
}

#[cfg(debug_assertions)]
fn pick_writable_path() -> PathBuf {
    for path in candidate_paths() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .is_ok()
        {
            return path;
        }
    }
    env::temp_dir().join("trace.log")
}

#[cfg(debug_assertions)]
pub fn log_path() -> PathBuf {
    if let Ok(guard) = LOG_PATH.lock() {
        if let Some(ref p) = *guard {
            return p.clone();
        }
    }
    pick_writable_path()
}

#[cfg(debug_assertions)]
pub fn init() {
    init_debug();
}

#[cfg(debug_assertions)]
fn init_debug() {
    let path = pick_writable_path();
    if let Ok(mut guard) = LOG_PATH.lock() {
        *guard = Some(path.clone());
    }

    let header = format!(
        "=== trace {} ===\r\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    let _ = fs::write(&path, header);
    log(&format!("log file: {}", path.display()));
}

#[cfg(debug_assertions)]
pub fn log(msg: &str) {
    log_debug(msg);
}

/// Debug-only log; format args are not evaluated in release (stealth).
#[macro_export]
macro_rules! logf {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            $crate::log::log(&format!($($arg)*));
        }
    }};
}

/// Debug-only log for static messages.
#[macro_export]
macro_rules! logs {
    ($msg:expr) => {{
        #[cfg(debug_assertions)]
        {
            $crate::log::log($msg);
        }
    }};
}

#[cfg(debug_assertions)]
fn log_debug(msg: &str) {
    let line = format!("[{}] {}\r\n", Utc::now().format("%H:%M:%S"), msg);
    let path = log_path();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
}
