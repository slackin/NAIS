use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub server: String,
    pub nickname: String,
    pub channel: String,
    #[serde(default = "default_use_tls")]
    pub use_tls: bool,
}

fn default_use_tls() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileStore {
    pub profiles: Vec<Profile>,
    pub last_used: Option<String>,
}

impl Default for Profile {
    fn default() -> Self {
        let server = "irc.libera.chat".to_string();
        let nickname = "nais".to_string();
        let channel = "#general".to_string();
        let name = profile_name(&server, &nickname, &channel);
        Self {
            name,
            server,
            nickname,
            channel,
            use_tls: true,
        }
    }
}

impl Default for ProfileStore {
    fn default() -> Self {
        let profile = Profile::default();
        Self {
            profiles: vec![profile.clone()],
            last_used: Some(profile.name.clone()),
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
