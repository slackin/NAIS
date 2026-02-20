use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

// Get system username as default nickname
fn get_system_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "nais".to_string())
}

// Generate fallback nicknames
pub fn generate_fallback_nicknames(base: &str) -> Vec<String> {
    vec![
        format!("{}_", base),
        format!("{}`", base),
    ]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub server: String,
    pub nickname: String,
    pub channel: String,
    #[serde(default = "default_use_tls")]
    pub use_tls: bool,
    #[serde(default = "default_auto_connect")]
    pub auto_connect: bool,
    #[serde(default = "default_enable_logging")]
    pub enable_logging: bool,
    #[serde(default = "default_scrollback_limit")]
    pub scrollback_limit: usize,
    #[serde(default = "default_log_buffer_size")]
    pub log_buffer_size: usize,
    #[serde(default = "default_hide_host")]
    pub hide_host: bool,
}

fn default_use_tls() -> bool {
    true
}

fn default_auto_connect() -> bool {
    true
}

fn default_enable_logging() -> bool {
    true
}

fn default_scrollback_limit() -> usize {
    1000
}

fn default_log_buffer_size() -> usize {
    1000
}

fn default_hide_host() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileStore {
    pub profiles: Vec<Profile>,
    pub last_used: Option<String>,
    #[serde(default)]
    pub default_nickname: Option<String>,
    #[serde(default)]
    pub show_timestamps: bool,
    #[serde(default)]
    pub show_advanced: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self::with_nickname(get_system_username())
    }
}

impl Profile {
    pub fn with_nickname(nickname: String) -> Self {
        let server = "irc.libera.chat".to_string();
        let channel = "#general".to_string();
        let name = profile_name(&server, &nickname, &channel);
        Self {
            name,
            server,
            nickname,
            channel,
            use_tls: true,
            auto_connect: true,
            enable_logging: true,
            scrollback_limit: 1000,
            log_buffer_size: 1000,
            hide_host: true,
        }
    }

    /// Pre-configured support profile for QuakeNet #nais channel
    pub fn support() -> Self {
        let nickname = get_system_username();
        Self {
            name: "support".to_string(),
            server: "irc.quakenet.org".to_string(),
            nickname,
            channel: "#nais".to_string(),
            use_tls: false, // QuakeNet doesn't support TLS on standard ports
            auto_connect: true,
            enable_logging: true,
            scrollback_limit: 1000,
            log_buffer_size: 1000,
            hide_host: true,
        }
    }
}

impl Default for ProfileStore {
    fn default() -> Self {
        let support_profile = Profile::support();
        Self {
            profiles: vec![support_profile.clone()],
            last_used: Some(support_profile.name.clone()),
            default_nickname: None,
            show_timestamps: false,
            show_advanced: false,
        }
    }
}

fn profile_path() -> Option<PathBuf> {
    let base = dirs::config_dir()?;
    Some(base.join("nais-client").join("profile.json"))
}

pub fn profile_name(server: &str, nickname: &str, channel: &str) -> String {
    format!("{server} | {nickname} | {channel}")
}

pub fn load_store() -> ProfileStore {
    let Some(path) = profile_path() else {
        return ProfileStore::default();
    };
    let Ok(data) = fs::read_to_string(path) else {
        return ProfileStore::default();
    };

    if let Ok(store) = serde_json::from_str::<ProfileStore>(&data) {
        return ensure_store(store);
    }
    if let Ok(legacy) = serde_json::from_str::<Profile>(&data) {
        let mut store = ProfileStore::default();
        let profile = Profile {
            name: profile_name(&legacy.server, &legacy.nickname, &legacy.channel),
            server: legacy.server,
            nickname: legacy.nickname,
            channel: legacy.channel,
            use_tls: legacy.use_tls,
            auto_connect: legacy.auto_connect,
            enable_logging: legacy.enable_logging,
            scrollback_limit: legacy.scrollback_limit,
            log_buffer_size: legacy.log_buffer_size,
            hide_host: legacy.hide_host,
        };
        store.profiles = vec![profile.clone()];
        store.last_used = Some(profile.name.clone());
        return store;
    }

    ProfileStore::default()
}

pub fn save_store(store: &ProfileStore) -> Result<(), String> {
    let path = profile_path().ok_or("No config directory")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let data = serde_json::to_string_pretty(store).map_err(|err| err.to_string())?;
    fs::write(path, data).map_err(|err| err.to_string())
}

pub fn select_profile(store: &ProfileStore) -> Profile {
    if let Some(name) = store.last_used.as_ref() {
        if let Some(profile) = store.profiles.iter().find(|profile| &profile.name == name) {
            return profile.clone();
        }
    }
    store.profiles.first().cloned().unwrap_or_default()
}

#[allow(dead_code)]
pub fn upsert_profile(store: &mut ProfileStore, profile: Profile) {
    if let Some(existing) = store
        .profiles
        .iter_mut()
        .find(|item| item.name == profile.name)
    {
        *existing = profile.clone();
    } else {
        store.profiles.push(profile.clone());
    }
    store.last_used = Some(profile.name);
}

#[allow(dead_code)]
pub fn remove_profile(store: &mut ProfileStore, name: &str) {
    store.profiles.retain(|profile| profile.name != name);
    if store.profiles.is_empty() {
        let profile = Profile::default();
        store.profiles.push(profile.clone());
        store.last_used = Some(profile.name);
        return;
    }
    if store.last_used.as_deref() == Some(name) {
        store.last_used = Some(store.profiles[0].name.clone());
    }
}

fn ensure_store(mut store: ProfileStore) -> ProfileStore {
    if store.profiles.is_empty() {
        let profile = Profile::default();
        store.profiles.push(profile.clone());
        store.last_used = Some(profile.name.clone());
    }
    store
}
