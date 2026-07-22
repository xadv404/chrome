//! Minimal PE parser for reflective injection.

use crate::hash::{export_rva_by_hash, H_BOOTSTRAP};

pub struct PeImage {
    pub size_of_image: usize,
    pub bootstrap_rva: u32,
}

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
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
    _data_directory: [ImageDataDirectory; 16],
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
    pointer_to_raw_data: u32,
    _pointer_to_relocations: u32,
    _pointer_to_linenumbers: u32,
    _number_of_relocations: u16,
    _number_of_linenumbers: u16,
    characteristics: u32,
}

pub fn parse_pe(data: &[u8]) -> Option<PeImage> {
    if data.len() < std::mem::size_of::<ImageDosHeader>() {
        return None;
    }
    let dos = unsafe { &*(data.as_ptr() as *const ImageDosHeader) };
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let nt_off = dos.e_lfanew as usize;
    if data.len() < nt_off + 4 + std::mem::size_of::<ImageFileHeader>() {
        return None;
    }
    let sig = u32::from_le_bytes([
        data[nt_off],
        data[nt_off + 1],
        data[nt_off + 2],
        data[nt_off + 3],
    ]);
    if sig != IMAGE_NT_SIGNATURE {
        return None;
    }

    let opt_off = nt_off + 4 + std::mem::size_of::<ImageFileHeader>();
    if data.len() < opt_off + std::mem::size_of::<ImageOptionalHeader64>() {
        return None;
    }
    let opt = unsafe { &*(data.as_ptr().add(opt_off) as *const ImageOptionalHeader64) };
    if opt.magic != 0x20B {
        return None;
    }

    let bootstrap_rva = unsafe { export_rva_by_hash(data, H_BOOTSTRAP)? };

    Some(PeImage {
        size_of_image: opt.size_of_image as usize,
        bootstrap_rva,
    })
}

pub fn build_mapped_image(pe: &[u8], size_of_image: usize) -> Option<Vec<u8>> {
    let dos = unsafe { &*(pe.as_ptr() as *const ImageDosHeader) };
    let nt_off = dos.e_lfanew as usize;
    let fh = unsafe { &*(pe.as_ptr().add(nt_off + 4) as *const ImageFileHeader) };
    let opt_off = nt_off + 4 + std::mem::size_of::<ImageFileHeader>();
    let opt = unsafe { &*(pe.as_ptr().add(opt_off) as *const ImageOptionalHeader64) };

    let mut image = vec![0u8; size_of_image];
    let headers_size = opt.size_of_headers.min(size_of_image as u32) as usize;
    image[..headers_size].copy_from_slice(&pe[..headers_size.min(pe.len())]);

    let section_off = opt_off + fh.size_of_optional_header as usize;
    for i in 0..fh.number_of_sections as usize {
        let sh_off = section_off + i * std::mem::size_of::<ImageSectionHeader>();
        if sh_off + std::mem::size_of::<ImageSectionHeader>() > pe.len() {
            break;
        }
        let sh = unsafe { &*(pe.as_ptr().add(sh_off) as *const ImageSectionHeader) };
        if sh.size_of_raw_data == 0 {
            continue;
        }
        let dst = sh.virtual_address as usize;
        let src = sh.pointer_to_raw_data as usize;
        let len = sh.size_of_raw_data as usize;
        if dst + len > image.len() || src + len > pe.len() {
            continue;
        }
        image[dst..dst + len].copy_from_slice(&pe[src..src + len]);
    }
    Some(image)
}

pub fn section_protection(characteristics: u32) -> u32 {
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

pub fn section_regions(pe: &[u8]) -> Option<Vec<(u32, u32, u32)>> {
    let dos = unsafe { &*(pe.as_ptr() as *const ImageDosHeader) };
    let nt_off = dos.e_lfanew as usize;
    let fh = unsafe { &*(pe.as_ptr().add(nt_off + 4) as *const ImageFileHeader) };
    let opt_off = nt_off + 4 + std::mem::size_of::<ImageFileHeader>();
    let section_off = opt_off + fh.size_of_optional_header as usize;
    let mut out = Vec::new();
    for i in 0..fh.number_of_sections as usize {
        let sh_off = section_off + i * std::mem::size_of::<ImageSectionHeader>();
        if sh_off + std::mem::size_of::<ImageSectionHeader>() > pe.len() {
            break;
        }
        let sh = unsafe { &*(pe.as_ptr().add(sh_off) as *const ImageSectionHeader) };
        let size = sh.virtual_size.max(sh.size_of_raw_data);
        if size == 0 {
            continue;
        }
        out.push((sh.virtual_address, size, section_protection(sh.characteristics)));
    }
    Some(out)
}
