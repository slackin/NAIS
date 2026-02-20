mod irc_client;
mod nais_channel;
mod profile;
mod ui;
mod voice_chat;

fn main() {
    // Initialize logging - use RUST_LOG env var to control level
    // e.g., RUST_LOG=debug or RUST_LOG=nais_client=debug
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();
    
    log::info!("NAIS IRC Client starting...");
    ui::run();
}
