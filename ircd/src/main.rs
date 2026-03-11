//! NAIS IRC Server (nais-ircd)
//!
//! A from-scratch IRC daemon with:
//! - Full RFC 2812 protocol support
//! - Discord-style permissions with role-based access control
//! - Houses/Rooms system (guilds with grouped channels)
//! - IRCv3 capability negotiation
//! - Extensible for NAIS secure channel overlay
//!
//! Usage:
//!   nais-ircd --config ircd.toml
//!   nais-ircd  (uses default settings)

#![allow(dead_code)] // Many permission constants and helper methods are for public API use

use clap::Parser;
use std::sync::Arc;

mod commands;
mod config;
mod connection;
mod houses;
mod permissions;
mod protocol;
mod server;
mod state;

#[derive(Parser)]
#[command(name = "nais-ircd", about = "NAIS IRC Server with houses & advanced permissions")]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "ircd.toml")]
    config: String,

    /// Override bind address
    #[arg(short, long)]
    bind: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    // Load config
    let config = match config::ServerConfig::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Could not load config from '{}': {}. Using defaults.", args.config, e);
            default_config()
        }
    };

    let bind_addr = args.bind.unwrap_or_else(|| config.server.bind.clone());

    log::info!("===========================================");
    log::info!("  NAIS IRC Server v0.1.0");
    log::info!("  Network: {}", config.server.network);
    log::info!("  Server:  {}", config.server.name);
    log::info!("  Bind:    {}", bind_addr);
    log::info!("  Max clients: {}", config.limits.max_clients);
    log::info!("===========================================");

    let server_state = Arc::new(state::ServerState::new(config));

    // Start background tasks
    let ping_state = Arc::clone(&server_state);
    tokio::spawn(async move {
        server::run_ping_loop(ping_state).await;
    });

    // Start stats reporting
    let stats_state = Arc::clone(&server_state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            log::info!("Stats: {} clients, {} channels, {} houses",
                stats_state.client_count(),
                stats_state.channel_count(),
                stats_state.house_count());
        }
    });

    // Run the TCP listener
    if let Err(e) = server::run_listener(server_state, &bind_addr).await {
        log::error!("Server error: {}", e);
        std::process::exit(1);
    }
}

fn default_config() -> config::ServerConfig {
    config::ServerConfig {
        server: config::ServerSection {
            name: "irc.nais.local".to_string(),
            bind: "0.0.0.0:6667".to_string(),
            tls_bind: None,
            description: "NAIS IRC Server".to_string(),
            network: "NAIS".to_string(),
            motd: vec![
                "Welcome to the NAIS IRC Network!".to_string(),
                "".to_string(),
                "This server supports Houses — use /HOUSE HELP for info.".to_string(),
                "Standard IRC commands work as expected.".to_string(),
            ],
            password: None,
        },
        tls: None,
        limits: config::LimitsSection::default(),
        opers: vec![],
    }
}
