//! Server configuration.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    #[serde(default)]
    #[allow(dead_code)]
    pub tls: Option<TlsSection>,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub opers: Vec<OperConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerSection {
    /// Server name (used in message prefixes)
    pub name: String,
    /// Bind address for plaintext connections
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Bind address for TLS connections
    #[allow(dead_code)]
    pub tls_bind: Option<String>,
    /// Server description
    #[serde(default = "default_description")]
    pub description: String,
    /// Network name
    #[serde(default = "default_network")]
    pub network: String,
    /// MOTD lines
    #[serde(default)]
    pub motd: Vec<String>,
    /// Server password (optional, for PASS command)
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TlsSection {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsSection {
    /// Maximum clients
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,
    /// Maximum channels per user
    #[serde(default = "default_max_channels_per_user")]
    pub max_channels_per_user: usize,
    /// Maximum houses per user (ownership)
    #[serde(default = "default_max_houses_per_user")]
    pub max_houses_per_user: usize,
    /// Maximum rooms per house
    #[serde(default = "default_max_rooms_per_house")]
    pub max_rooms_per_house: usize,
    /// Maximum roles per house
    #[serde(default = "default_max_roles_per_house")]
    pub max_roles_per_house: usize,
    /// Ping timeout in seconds
    #[serde(default = "default_ping_timeout")]
    pub ping_timeout: u64,
    /// Registration timeout in seconds
    #[serde(default = "default_reg_timeout")]
    pub registration_timeout: u64,
    /// Maximum scrollback lines kept per channel when logging is enabled
    #[serde(default = "default_max_scrollback")]
    pub max_scrollback: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperConfig {
    pub name: String,
    /// Argon2 hashed password
    pub password_hash: String,
    /// Host mask required
    pub host: Option<String>,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_clients: default_max_clients(),
            max_channels_per_user: default_max_channels_per_user(),
            max_houses_per_user: default_max_houses_per_user(),
            max_rooms_per_house: default_max_rooms_per_house(),
            max_roles_per_house: default_max_roles_per_house(),
            ping_timeout: default_ping_timeout(),
            registration_timeout: default_reg_timeout(),
            max_scrollback: default_max_scrollback(),
        }
    }
}

fn default_bind() -> String { "0.0.0.0:6667".to_string() }
fn default_description() -> String { "NAIS IRC Server".to_string() }
fn default_network() -> String { "NAIS".to_string() }
fn default_max_clients() -> usize { 10000 }
fn default_max_channels_per_user() -> usize { 100 }
fn default_max_houses_per_user() -> usize { 10 }
fn default_max_rooms_per_house() -> usize { 200 }
fn default_max_roles_per_house() -> usize { 50 }
fn default_ping_timeout() -> u64 { 180 }
fn default_reg_timeout() -> u64 { 30 }
fn default_max_scrollback() -> usize { 500 }

impl ServerConfig {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: ServerConfig = toml::from_str(&content)?;
        Ok(config)
    }
}
