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

/// Convey IRC Client
#[derive(Parser, Debug)]
#[command(name = "convey", about = "Convey IRC Client")]
struct Cli {
    /// Launch in console/terminal mode instead of the GUI
    #[arg(long, short = 'c')]
    console: bool,
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
    
    if cli.console {
        log::info!("NAIS IRC Client starting (console mode)...");
        console::run();
    } else {
        log::info!("NAIS IRC Client starting...");
        ui::run();
    }
}
