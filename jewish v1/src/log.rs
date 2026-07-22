use std::{
    env, fs,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::Mutex,
};

use chrono::Utc;

static LOG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(local) = env::var("LOCALAPPDATA") {
        paths.push(PathBuf::from(local).join("jewish").join("jewish_debug.log"));
    }

    paths.push(env::temp_dir().join("jewish_debug.log"));

    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("jewish_debug.log"));
            paths.push(dir.join("release").join("jewish_debug.log"));
        }
    }

    paths
}

fn pick_writable_path() -> PathBuf {
    for path in candidate_paths() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(mut file) => {
                let _ = file.flush();
                return path;
            }
            Err(_) => continue,
        }
    }
    env::temp_dir().join("jewish_debug.log")
}

fn write_marker(path: &PathBuf) {
    let markers: Vec<PathBuf> = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.to_path_buf()))
        .into_iter()
        .chain(
            env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|d| d.join("release")))
                .into_iter(),
        )
        .collect();

    let body = format!(
        "jewish debug log\r\npath: {}\r\n",
        path.display()
    );

    for dir in markers {
        let marker = dir.join("jewish_log_here.txt");
        let _ = fs::write(&marker, &body);
    }
}

pub fn log_path() -> PathBuf {
    if let Ok(guard) = LOG_PATH.lock() {
        if let Some(ref p) = *guard {
            return p.clone();
        }
    }
    pick_writable_path()
}

pub fn init() {
    let path = pick_writable_path();
    if let Ok(mut guard) = LOG_PATH.lock() {
        *guard = Some(path.clone());
    }

    let header = format!(
        "=== jewish debug log {} ===\r\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    let _ = fs::write(&path, header);
    write_marker(&path);
    log(&format!("log file: {}", path.display()));
}

pub fn log(msg: &str) {
    let line = format!("[{}] {}\r\n", Utc::now().format("%H:%M:%S"), msg);
    let path = log_path();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
}
