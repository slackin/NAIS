#![allow(dead_code)]

mod console;
mod irc_client;
mod nais_channel;
mod nais_secure_channel;
mod nsc_channel;
mod nsc_crypto;
mod nsc_irc;
mod nsc_manager;
mod nsc_mls;
#[allow(dead_code)]
mod nsc_nat;
#[allow(dead_code)]
mod nsc_router;
#[allow(dead_code)]
mod nsc_transport;
mod profile;
mod ui;
mod voice_chat;

use clap::Parser;
use std::path::PathBuf;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Convey IRC Client
#[derive(Parser, Debug)]
#[command(name = "convey", about = "Convey IRC Client")]
struct Cli {
    /// Launch in console/terminal mode instead of the GUI
    #[arg(long, short = 'c')]
    console: bool,
}

/// Returns the path to the version marker file inside the config directory.
fn version_marker_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("nais-client").join(".version"))
}

/// Remove all config and cache directories, returning the application to a
/// fresh-install state.  After clearing, the version marker is re-written so
/// the next launch does not trigger another migration.
pub fn reset_all_data() {
    log::info!("Resetting all configs and cache to initial state");

    let mut dirs_to_clear: Vec<PathBuf> = Vec::new();

    if let Some(config_base) = dirs::config_dir() {
        dirs_to_clear.push(config_base.join("nais-client")); // profile.json, logs/
        dirs_to_clear.push(config_base.join("nais"));         // nsc_data.json
    }
    if let Some(cache_base) = dirs::cache_dir() {
        dirs_to_clear.push(cache_base.join("nais-client"));   // cached data
    }

    for dir in &dirs_to_clear {
        if dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(dir) {
                log::warn!("Failed to remove {}: {}", dir.display(), e);
            } else {
                log::info!("Removed {}", dir.display());
            }
        }
    }

    // Re-write the version marker so version-migration doesn't re-trigger
    if let Some(marker_path) = version_marker_path() {
        if let Some(parent) = marker_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        if let Err(e) = std::fs::write(&marker_path, APP_VERSION) {
            log::warn!("Failed to write version marker: {}", e);
        }
    }
}

/// Check if this is the first launch of a new version.
/// If so, clear all previous config and cache directories so the new version
/// starts from a clean slate, then write the current version marker.
fn check_version_migration() {
    let Some(marker_path) = version_marker_path() else {
        log::warn!("Could not determine config directory; skipping version migration");
        return;
    };

    // Read stored version (if any)
    let stored_version = std::fs::read_to_string(&marker_path).ok();
    let stored_version = stored_version.as_deref().map(|s| s.trim());

    if stored_version == Some(APP_VERSION) {
        // Same version — nothing to do
        return;
    }

    log::info!(
        "Version change detected ({} -> {}). Clearing previous configs and cache.",
        stored_version.unwrap_or("<none>"),
        APP_VERSION
    );

    reset_all_data();
}

fn main() {
    let cli = Cli::parse();

    // Install ring crypto provider for rustls (required before any TLS connections)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize logging - use RUST_LOG env var to control level
    // e.g., RUST_LOG=debug or RUST_LOG=nais_client=debug
    // In console mode, default to warnings-only to avoid cluttering the TUI
    let default_filter = if cli.console { "warn" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp_millis()
        .init();

    // Clear old configs/cache when version changes
    check_version_migration();

    if cli.console {
        log::info!("NAIS IRC Client starting (console mode)...");
        console::run();
    } else {
        log::info!("NAIS IRC Client starting...");
        ui::run();
    }
}
