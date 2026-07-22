// Logging disabled for stealth
pub fn init() {}
pub fn log(_msg: &str) {}
pub fn log_path() -> std::path::PathBuf {
    std::env::temp_dir()
}
