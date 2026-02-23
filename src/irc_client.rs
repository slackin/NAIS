//! Core IRC state, events, and the network loop.

use async_channel::{Receiver, Sender};
use futures::StreamExt;
use irc::client::prelude::{Client, Command as IrcCommand, Config, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use lazy_static::lazy_static;

// Reconnection delay settings to prevent rapid cycling and IRC bans
const RECONNECT_BASE_DELAY_SECS: u64 = 30;      // Initial delay between reconnection attempts
const RECONNECT_MAX_DELAY_SECS: u64 = 300;      // Maximum delay (5 minutes)
const RECONNECT_BACKOFF_MULTIPLIER: f64 = 1.5;  // Each failure multiplies delay by this

/// Global reconnection state tracker - persists across core instances
#[derive(Debug)]
struct ReconnectState {
    last_attempt: Option<Instant>,
    consecutive_failures: u32,
}

lazy_static! {
    static ref RECONNECT_TRACKER: Arc<Mutex<HashMap<String, ReconnectState>>> = 
        Arc::new(Mutex::new(HashMap::new()));
}

/// Get the required delay before connecting to this server, returns None if no delay needed
pub fn get_reconnect_delay(server: &str) -> Option<Duration> {
    let tracker = RECONNECT_TRACKER.lock().ok()?;
    let state = tracker.get(server)?;
    let last_attempt = state.last_attempt?;
    let elapsed = last_attempt.elapsed();
    let required_delay = calculate_reconnect_delay(state.consecutive_failures);
    
    if elapsed < required_delay {
        Some(required_delay - elapsed)
    } else {
        None
    }
}

/// Record a connection attempt for a server
pub fn record_connection_attempt(server: &str) {
    if let Ok(mut tracker) = RECONNECT_TRACKER.lock() {
        let state = tracker.entry(server.to_string()).or_insert(ReconnectState {
            last_attempt: None,
            consecutive_failures: 0,
        });
        state.last_attempt = Some(Instant::now());
    }
}

/// Record a connection failure for a server (increases backoff)
pub fn record_connection_failure(server: &str) {
    if let Ok(mut tracker) = RECONNECT_TRACKER.lock() {
        let state = tracker.entry(server.to_string()).or_insert(ReconnectState {
            last_attempt: None,
            consecutive_failures: 0,
        });
        state.consecutive_failures += 1;
        log::info!("[IRC] Connection failure #{} for {}, next delay: {}s", 
            state.consecutive_failures, server, 
            calculate_reconnect_delay(state.consecutive_failures).as_secs());
    }
}

/// Record a successful connection (resets backoff)
pub fn record_connection_success(server: &str) {
    if let Ok(mut tracker) = RECONNECT_TRACKER.lock() {
        if let Some(state) = tracker.get_mut(server) {
            state.consecutive_failures = 0;
        }
    }
}

/// Reset reconnection state for a server (e.g., user-initiated disconnect)
pub fn reset_reconnect_state(server: &str) {
    if let Ok(mut tracker) = RECONNECT_TRACKER.lock() {
        tracker.remove(server);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
}

use std::sync::atomic::{AtomicU64, Ordering};

// Global message ID counter for unique keys
static MESSAGE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_message_id() -> u64 {
    MESSAGE_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Unique message ID for efficient UI rendering (not persisted)
    #[serde(skip, default = "next_message_id")]
    pub id: u64,
    pub channel: String,
    pub user: String,
    pub text: String,
    pub is_system: bool,
    pub is_action: bool,
    #[serde(default = "default_timestamp")]
    pub timestamp: i64,
}

fn default_timestamp() -> i64 {
    chrono::Utc::now().timestamp()
}

#[derive(Clone, Debug)]
pub struct ServerState {
    pub status: ConnectionStatus,
    pub server: String,
    pub nickname: String,
    pub current_channel: String,
    pub channels: Vec<String>,
    pub users_by_channel: HashMap<String, Vec<String>>,
    pub messages: Vec<ChatMessage>,
    #[allow(dead_code)]
    pub auto_reconnect: bool,
    #[allow(dead_code)]
    pub last_connect: Option<ConnectInfo>,
    pub connection_log: Vec<String>,
    pub cached_channel_list: Vec<(String, u32, String)>,
    pub topics_by_channel: HashMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub active_profile: String,
    pub servers: HashMap<String, ServerState>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ConnectInfo {
    pub server: String,
    pub nickname: String,
    pub channel: String,
    pub use_tls: bool,
}

#[derive(Clone, Debug)]
pub enum IrcEvent {
    Connected { server: String },
    Disconnected,
    Joined { channel: String },
    Parted { channel: String },
    /// Another user joined a channel
    UserJoined { channel: String, user: String },
    /// Another user parted a channel
    UserParted { channel: String, user: String },
    /// A user quit IRC (affects all channels)
    UserQuit { user: String },
    Users { channel: String, users: Vec<String> },
    Message { channel: String, user: String, text: String },
    Action { channel: String, user: String, text: String },
    System { channel: String, text: String },
    Topic { channel: String, topic: String },
    ChannelListItem { channel: String, user_count: u32, topic: String },
    ChannelListEnd,
    /// Nick changed (own or fallback from registration)
    NickChanged { new_nick: String },
    /// Voice chat CTCP message received
    VoiceCtcp { from: String, command: String, args: Vec<String> },
    /// WHOIS response data
    WhoisUser { nick: String, user: String, host: String, realname: String },
    WhoisServer { nick: String, server: String, server_info: String },
    WhoisChannels { nick: String, channels: String },
    WhoisIdle { nick: String, idle_secs: String },
    WhoisEnd { nick: String },
    /// CTCP response received (from a NOTICE with CTCP content)
    CtcpResponse { from: String, command: String, response: String },
    /// NAIS channel CTCP message received
    NaisCtcp { from: String, command: String, args: Vec<String> },
    /// IRC INVITE received - someone invited us to a channel
    Invited { from: String, channel: String },
}

#[derive(Clone, Debug)]
pub enum IrcCommandEvent {
    Connect {
        server: String,
        nickname: String,
        channel: String,
        use_tls: bool,
        hide_host: bool,
    },
    Join {
        channel: String,
    },
    Send {
        channel: String,
        text: String,
    },
    Nick {
        nickname: String,
    },
    Part {
        channel: String,
        reason: Option<String>,
    },
    Whois {
        nickname: String,
    },
    Who {
        target: String,
    },
    Topic {
        channel: String,
        topic: Option<String>,
    },
    List,
    Msg {
        target: String,
        text: String,
    },
    Notice {
        target: String,
        text: String,
    },
    Kick {
        channel: String,
        user: String,
        reason: Option<String>,
    },
    Mode {
        target: String,
        modes: String,
        args: Option<String>,
    },
    Invite {
        nickname: String,
        channel: String,
    },
    Away {
        message: Option<String>,
    },
    /// Send a CTCP message to a user (for voice chat negotiation)
    Ctcp {
        target: String,
        message: String,
    },
    /// Quit IRC with an optional message
    Quit {
        message: Option<String>,
    },
    /// Send a raw IRC command
    Raw {
        command: String,
    },
    #[allow(dead_code)]
    Disconnect,
}

#[derive(Clone)]
pub struct CoreHandle {
    pub cmd_tx: Sender<IrcCommandEvent>,
    pub evt_rx: Receiver<IrcEvent>,
}

// Message logging functions
fn logs_dir() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|base| base.join("nais-client").join("logs"))
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '#' => '_',
            _ => c,
        })
        .collect()
}

fn log_path(server: &str, channel: &str) -> Option<std::path::PathBuf> {
    logs_dir().map(|dir| {
        let server_safe = sanitize_filename(server);
        let channel_safe = sanitize_filename(channel);
        dir.join(format!("{}_{}.json", server_safe, channel_safe))
    })
}

pub fn save_messages(server: &str, channel: &str, messages: &[ChatMessage], buffer_size: usize) -> Result<(), String> {
    let path = log_path(server, channel).ok_or("No logs directory")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    
    // Keep only the last N messages to avoid files getting too large
    let messages_to_save: Vec<_> = messages.iter()
        .filter(|m| m.channel == channel)
        .rev()
        .take(buffer_size)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .cloned()
        .collect();
    
    let data = serde_json::to_string_pretty(&messages_to_save).map_err(|e| e.to_string())?;
    std::fs::write(path, data).map_err(|e| e.to_string())
}

pub fn load_messages(server: &str, channel: &str) -> Vec<ChatMessage> {
    let Some(path) = log_path(server, channel) else {
        return Vec::new();
    };
    
    let Ok(data) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    
    serde_json::from_str::<Vec<ChatMessage>>(&data).unwrap_or_default()
}

pub fn default_server_state(server: String, nickname: String, channel: String) -> ServerState {
    let channel = channel.trim().to_string();
    let current_channel = if channel.is_empty() { String::new() } else { channel };
    
    // Don't pre-populate channels or users - they'll be added when actually joined
    ServerState {
        status: ConnectionStatus::Disconnected,
        server,
        nickname,
        current_channel,
        channels: Vec::new(),
        users_by_channel: HashMap::new(),
        messages: Vec::new(),
        auto_reconnect: true,
        last_connect: None,
        connection_log: Vec::new(),
        cached_channel_list: Vec::new(),
        topics_by_channel: HashMap::new(),
    }
}
pub fn apply_event(state: &mut AppState, profile: &str, event: IrcEvent, enable_logging: bool, scrollback_limit: usize, log_buffer_size: usize) {
    if let Some(server_state) = state.servers.get_mut(profile) {
        apply_event_to_server(server_state, event, enable_logging, scrollback_limit, log_buffer_size);
    }
}

pub fn apply_event_to_server(state: &mut ServerState, event: IrcEvent, enable_logging: bool, scrollback_limit: usize, log_buffer_size: usize) {
    match event {
        IrcEvent::Connected { server } => {
            state.status = ConnectionStatus::Connected;
            state.server = server.clone();
            let log_msg = format!("[Connected] Successfully connected to {}", server);
            state.connection_log.push(log_msg);
            if !state.current_channel.is_empty() {
                state.messages.push(ChatMessage {
                    id: next_message_id(),
                    channel: state.current_channel.clone(),
                    user: "system".to_string(),
                    text: "Connected.".to_string(),
                    is_system: true,
                    is_action: false,
                    timestamp: chrono::Utc::now().timestamp(),
                });
            }
        }
        IrcEvent::Disconnected => {
            state.status = ConnectionStatus::Disconnected;
            let log_msg = format!("[Disconnected] Connection to {} closed", state.server);
            state.connection_log.push(log_msg);
            if !state.current_channel.is_empty() {
                state.messages.push(ChatMessage {
                    id: next_message_id(),
                    channel: state.current_channel.clone(),
                    user: "system".to_string(),
                    text: "Disconnected.".to_string(),
                    is_system: true,
                    is_action: false,
                    timestamp: chrono::Utc::now().timestamp(),
                });
            }
        }
        IrcEvent::Joined { channel } => {
            if !state.channels.contains(&channel) {
                state.channels.push(channel.clone());
            }
            state.current_channel = channel.clone();
            state
                .users_by_channel
                .entry(channel.clone())
                .or_insert_with(Vec::new);
            
            // Load historical messages for this channel
            let historical = load_messages(&state.server, &channel);
            if !historical.is_empty() {
                // Add historical messages to the state, but only if they're not already there
                let existing_timestamps: std::collections::HashSet<_> = state.messages.iter()
                    .filter(|m| m.channel == channel)
                    .map(|m| m.timestamp)
                    .collect();
                
                for msg in historical {
                    if !existing_timestamps.contains(&msg.timestamp) {
                        state.messages.push(msg);
                    }
                }
                
                // Sort messages by timestamp to maintain order
                state.messages.sort_by_key(|m| m.timestamp);
            }
            
            state.messages.push(ChatMessage {
                id: next_message_id(),
                channel: channel.clone(),
                user: "system".to_string(),
                text: "Joined channel.".to_string(),
                is_system: true,
                is_action: false,
                timestamp: chrono::Utc::now().timestamp(),
            });
        }
        IrcEvent::Parted { channel } => {
            state.channels.retain(|name| name != &channel);
            state.users_by_channel.remove(&channel);
            if state.current_channel == channel {
                state.current_channel = state
                    .channels
                    .first()
                    .cloned()
                    .unwrap_or_default();
            }
            state.messages.push(ChatMessage {
                id: next_message_id(),
                channel,
                user: "system".to_string(),
                text: "Left channel.".to_string(),
                is_system: true,
                is_action: false,
                timestamp: chrono::Utc::now().timestamp(),
            });
        }
        IrcEvent::Users { channel, users } => {
            // Append users from this NAMES reply to the existing list
            let user_list = state.users_by_channel.entry(channel).or_insert_with(Vec::new);
            for user in users {
                if !user_list.contains(&user) {
                    user_list.push(user);
                }
            }
        }
        IrcEvent::UserJoined { channel, user } => {
            // Add the user to the channel's user list (no message, that comes via System event)
            let user_list = state.users_by_channel.entry(channel).or_insert_with(Vec::new);
            if !user_list.contains(&user) {
                user_list.push(user);
            }
        }
        IrcEvent::UserParted { channel, user } => {
            // Remove the user from the channel's user list (no message, that comes via System event)
            if let Some(user_list) = state.users_by_channel.get_mut(&channel) {
                user_list.retain(|u| u != &user && u.trim_start_matches(|c| c == '@' || c == '+' || c == '%' || c == '!' || c == '~') != user);
            }
        }
        IrcEvent::UserQuit { user } => {
            // Remove the user from all channels (no message, that comes via System event)
            for user_list in state.users_by_channel.values_mut() {
                user_list.retain(|u| u != &user && u.trim_start_matches(|c| c == '@' || c == '+' || c == '%' || c == '!' || c == '~') != user);
            }
        }
        IrcEvent::Message { channel, user, text } => {
            // If this is a private message (channel doesn't start with #/&/+/!), auto-add to channel list
            if !channel.starts_with('#') && !channel.starts_with('&') && !channel.starts_with('+') && !channel.starts_with('!') {
                if !state.channels.contains(&channel) {
                    state.channels.push(channel.clone());
                }
            }
            state.messages.push(ChatMessage {
                id: next_message_id(),
                channel,
                user,
                text,
                is_system: false,
                is_action: false,
                timestamp: chrono::Utc::now().timestamp(),
            });
        }
        IrcEvent::Action { channel, user, text } => {
            // If this is a private message action (channel doesn't start with #/&/+/!), auto-add to channel list
            if !channel.starts_with('#') && !channel.starts_with('&') && !channel.starts_with('+') && !channel.starts_with('!') {
                if !state.channels.contains(&channel) {
                    state.channels.push(channel.clone());
                }
            }
            state.messages.push(ChatMessage {
                id: next_message_id(),
                channel,
                user,
                text,
                is_system: false,
                is_action: true,
                timestamp: chrono::Utc::now().timestamp(),
            });
        }
        IrcEvent::System { channel, text } => {
            // Log connection-related and IRC protocol messages to connection log
            // All messages with these prefixes go to the server log
            let is_connection_message = text.starts_with("[IRC]") ||
                text.starts_with("[CONN]") ||
                text.starts_with("[DNS]") ||
                text.starts_with("[TCP]") ||
                text.starts_with("[TLS]") ||
                text.starts_with("[ERROR]") ||
                text.starts_with("[SERVER ERROR]") ||
                text.starts_with("═══") ||
                text.starts_with("[RPL_") ||
                text.starts_with("[ERR_") ||
                text.contains("error") || 
                text.contains("Error") || 
                text.contains("Connection") ||
                text.contains("Stream");
            
            if is_connection_message {
                state.connection_log.push(text.clone());
            }
            
            // Only add to channel messages if it's NOT a connection/protocol message
            // These belong in the Server Log, not in channel views
            if !is_connection_message {
                state.messages.push(ChatMessage {
                    id: next_message_id(),
                    channel,
                    user: "system".to_string(),
                    text,
                    is_system: true,
                    is_action: false,
                    timestamp: chrono::Utc::now().timestamp(),
                });
            }
        }
        IrcEvent::Topic { channel, topic } => {
            state.topics_by_channel.insert(channel, topic);
        }
        IrcEvent::ChannelListItem { .. } | IrcEvent::ChannelListEnd => {
            // These events are handled in the UI event loop, not here
        }
        IrcEvent::VoiceCtcp { .. } => {
            // Voice CTCP events are handled in the UI event loop, not here
        }
        IrcEvent::WhoisUser { .. } | IrcEvent::WhoisServer { .. } | IrcEvent::WhoisChannels { .. } | IrcEvent::WhoisIdle { .. } | IrcEvent::WhoisEnd { .. } => {
            // WHOIS events are handled in the UI event loop for popup display
        }
        IrcEvent::CtcpResponse { .. } => {
            // CTCP response events are handled in the UI event loop for popup display
        }
        IrcEvent::NickChanged { new_nick } => {
            // Update the nickname in state when it changes (e.g., from rollover during registration)
            state.nickname = new_nick;
        }
        IrcEvent::NaisCtcp { .. } => {
            // NAIS CTCP events are handled in the UI event loop
        }
        IrcEvent::Invited { .. } => {
            // Invite events are handled in the UI event loop for popup display
        }
    }
    
    // Apply scrollback limit - keep only the most recent messages in memory
    if state.messages.len() > scrollback_limit {
        // Group by channel and keep last N per channel
        let mut messages_by_channel: std::collections::HashMap<String, Vec<ChatMessage>> = std::collections::HashMap::new();
        for msg in state.messages.drain(..) {
            messages_by_channel.entry(msg.channel.clone()).or_insert_with(Vec::new).push(msg);
        }
        
        for (_, msgs) in messages_by_channel.iter_mut() {
            msgs.sort_by_key(|m| m.timestamp);
            if msgs.len() > scrollback_limit {
                msgs.drain(0..msgs.len() - scrollback_limit);
            }
        }
        
        // Flatten back to single vec
        state.messages = messages_by_channel.into_iter()
            .flat_map(|(_, msgs)| msgs)
            .collect();
        state.messages.sort_by_key(|m| m.timestamp);
    }
    
    // Save messages to disk for persistence (if logging is enabled)
    if enable_logging {
        let channels_to_save: std::collections::HashSet<String> = state.messages.iter()
            .filter(|m| m.channel.starts_with('#'))
            .map(|m| m.channel.clone())
            .collect();
        
        for channel in channels_to_save {
            let _ = save_messages(&state.server, &channel, &state.messages, log_buffer_size);
        }
    }
}

pub fn start_core() -> CoreHandle {
    let (cmd_tx, cmd_rx) = async_channel::unbounded();
    let (evt_tx, evt_rx) = async_channel::unbounded();

    std::thread::spawn(move || {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async move {
            let _ = core_loop(cmd_rx, evt_tx).await;
        });
    });

    CoreHandle { cmd_tx, evt_rx }
}

async fn core_loop(cmd_rx: Receiver<IrcCommandEvent>, evt_tx: Sender<IrcEvent>) -> Result<(), Box<dyn Error>> {
    let command_rx = cmd_rx;
    
    loop {
        let Some(command) = command_rx.recv().await.ok() else {
            break;
        };
        match command {
            IrcCommandEvent::Connect {
                server,
                nickname,
                channel,
                use_tls,
                hide_host,
            } => {
                // Check global reconnection tracker for required delay
                if let Some(wait_time) = get_reconnect_delay(&server) {
                    let _ = evt_tx
                        .send(IrcEvent::System {
                            channel: channel.clone(),
                            text: format!("Waiting {:.0} seconds before reconnecting to avoid rate limiting...", wait_time.as_secs_f64()),
                        })
                        .await;
                    tokio::time::sleep(wait_time).await;
                }
                
                // Record this connection attempt
                record_connection_attempt(&server);
                
                if let Err(error) = handle_connection(
                    &server,
                    &nickname,
                    &channel,
                    use_tls,
                    hide_host,
                    &command_rx,
                    &evt_tx,
                )
                .await
                {
                    // Record the failure (increases backoff for next attempt)
                    record_connection_failure(&server);
                    let _ = evt_tx
                        .send(IrcEvent::System {
                            channel: channel.clone(),
                            text: format!("Connection error: {error}"),
                        })
                        .await;
                    let _ = evt_tx.send(IrcEvent::Disconnected).await;
                } else {
                    // Connection ended (user disconnected or server closed after being connected)
                    // Success is recorded in handle_connection when we get Connected event
                }
            }
            IrcCommandEvent::Disconnect => {
                let _ = evt_tx.send(IrcEvent::Disconnected).await;
            }
            _ => {
                let _ = evt_tx
                    .send(IrcEvent::System {
                        channel: "#general".to_string(),
                        text: "Connect first.".to_string(),
                    })
                    .await;
            }
        }
    }
    Ok(())
}

/// Calculate reconnection delay with exponential backoff
fn calculate_reconnect_delay(consecutive_failures: u32) -> Duration {
    if consecutive_failures == 0 {
        return Duration::from_secs(RECONNECT_BASE_DELAY_SECS);
    }
    
    let multiplier = RECONNECT_BACKOFF_MULTIPLIER.powi(consecutive_failures as i32);
    let delay_secs = (RECONNECT_BASE_DELAY_SECS as f64 * multiplier).min(RECONNECT_MAX_DELAY_SECS as f64);
    Duration::from_secs(delay_secs as u64)
}

/// Check if a message is a CTCP message (starts and ends with \x01)
fn is_ctcp_message(text: &str) -> bool {
    text.len() >= 2 && text.starts_with('\x01') && text.ends_with('\x01')
}

/// Parse CTCP message and return (command, args)
fn parse_ctcp(text: &str) -> Option<(String, String)> {
    if !is_ctcp_message(text) {
        return None;
    }
    
    // Remove leading and trailing \x01
    let content = &text[1..text.len()-1];
    
    // Split into command and args
    if let Some(space_pos) = content.find(' ') {
        let command = content[..space_pos].to_string();
        let args = content[space_pos+1..].to_string();
        Some((command, args))
    } else {
        Some((content.to_string(), String::new()))
    }
}

/// Create a CTCP response message
fn create_ctcp_response(command: &str, response: &str) -> String {
    format!("\x01{} {}\x01", command, response)
}

/// Handle CTCP query and return response if needed
fn handle_ctcp_query(command: &str, args: &str) -> Option<String> {
    match command {
        "VERSION" => {
            Some(create_ctcp_response("VERSION", "NAIS-client v0.1.0 (Rust)"))
        }
        "CLIENTINFO" => {
            Some(create_ctcp_response("CLIENTINFO", "ACTION VERSION CLIENTINFO TIME PING FINGER SOURCE USERINFO VOICE_CALL VOICE_ACCEPT VOICE_REJECT VOICE_CANCEL NAIS_PROBE NAIS_INFO NAIS_JOIN NAIS_ACCEPT NAIS_CONNECT NAIS_LEAVE"))
        }
        "TIME" => {
            let now = chrono::Local::now();
            Some(create_ctcp_response("TIME", &now.to_rfc2822()))
        }
        "PING" => {
            Some(create_ctcp_response("PING", args))
        }
        "FINGER" => {
            // Return user information (in a real client, this might include idle time)
            Some(create_ctcp_response("FINGER", "NAIS-client user"))
        }
        "SOURCE" => {
            Some(create_ctcp_response("SOURCE", "https://github.com/nais-client"))
        }
        "USERINFO" => {
            Some(create_ctcp_response("USERINFO", "NAIS IRC Client"))
        }
        // Voice CTCP commands are handled separately - return None to let them be forwarded to voice system
        "VOICE_CALL" | "VOICE_ACCEPT" | "VOICE_REJECT" | "VOICE_CANCEL" => None,
        // NAIS channel CTCP commands are handled separately
        "NAIS_PROBE" | "NAIS_INFO" | "NAIS_JOIN" | "NAIS_ACCEPT" | "NAIS_CONNECT" | "NAIS_LEAVE" => None,
        _ => None,
    }
}

/// Check if a CTCP command is voice-related
fn is_voice_ctcp(command: &str) -> bool {
    matches!(command, "VOICE_CALL" | "VOICE_ACCEPT" | "VOICE_REJECT" | "VOICE_CANCEL")
}

/// Check if a CTCP command is NAIS channel-related (NSC = Nais Secure Channels)
fn is_nais_ctcp(command: &str) -> bool {
    command.starts_with("NSC_") || matches!(command, "NAIS_PROBE" | "NAIS_INFO" | "NAIS_JOIN" | "NAIS_ACCEPT" | "NAIS_CONNECT" | "NAIS_LEAVE" | "NAIS_CHANNEL_INVITE" | "NAIS_MSG")
}

async fn handle_connection(
    server: &str,
    nickname: &str,
    channel: &str,
    use_tls: bool,
    hide_host: bool,
    cmd_rx: &Receiver<IrcCommandEvent>,
    evt_tx: &Sender<IrcEvent>,
) -> Result<(), Box<dyn Error>> {
    let mut self_nick = nickname.to_string();
    let default_channel = channel.to_string();
    let fallback_nicks = crate::profile::generate_fallback_nicknames(nickname);
    let mut nick_attempt = 0;
    let mut hide_host_sent = !hide_host; // Mark as "sent" if disabled to skip sending
    
    // Determine port and log connection type
    let port = if use_tls { 6697 } else { 6667 };
    let connection_type = if use_tls { "TLS/SSL encrypted" } else { "plaintext (no encryption)" };
    
    // Log connection attempt with detailed info
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("═══ Connection to {} ═══", server),
        })
        .await;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[CONN] Target: {}:{}", server, port),
        })
        .await;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[CONN] Security: {}", connection_type),
        })
        .await;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[CONN] Nickname: {} (with {} fallbacks)", nickname, fallback_nicks.len()),
        })
        .await;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[CONN] Hide hostname: {}", if hide_host { "yes" } else { "no" }),
        })
        .await;
    
    // DNS resolution logging
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[DNS] Resolving {}...", server),
        })
        .await;
    
    // Try to resolve DNS to show the user what's happening
    let dns_start = Instant::now();
    match tokio::net::lookup_host(format!("{}:{}", server, port)).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            let dns_time = dns_start.elapsed();
            let _ = evt_tx
                .send(IrcEvent::System {
                    channel: channel.to_string(),
                    text: format!("[DNS] Resolved to {} address(es) in {:?}", addrs.len(), dns_time),
                })
                .await;
            for (i, addr) in addrs.iter().take(3).enumerate() {
                let _ = evt_tx
                    .send(IrcEvent::System {
                        channel: channel.to_string(),
                        text: format!("[DNS]   #{}: {}", i + 1, addr),
                    })
                    .await;
            }
            if addrs.len() > 3 {
                let _ = evt_tx
                    .send(IrcEvent::System {
                        channel: channel.to_string(),
                        text: format!("[DNS]   ... and {} more", addrs.len() - 3),
                    })
                    .await;
            }
        }
        Err(e) => {
            let _ = evt_tx
                .send(IrcEvent::System {
                    channel: channel.to_string(),
                    text: format!("[DNS] Resolution failed: {}", e),
                })
                .await;
            // Continue anyway - the IRC library will try to connect
        }
    }
    
    let mut config = Config::default();
    config.server = Some(server.to_string());
    config.nickname = Some(nickname.to_string());
    config.alt_nicks = fallback_nicks.clone(); // Use library's built-in nick rollover
    config.port = Some(port);
    config.use_tls = Some(use_tls);
    // Accept expired/invalid certificates (some IRC servers have expired certs)
    config.dangerously_accept_invalid_certs = Some(true);
    // Set very long PING timeouts (in seconds) instead of None
    config.ping_time = Some(300); // Send PING every 5 minutes
    config.ping_timeout = Some(600); // Timeout after 10 minutes
    // Set a real name to avoid potential issues
    config.realname = Some(nickname.to_string());
    config.username = Some(nickname.to_string());
    // Disable ghost checking
    config.should_ghost = false;

    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[TCP] Connecting to {}:{}...", server, port),
        })
        .await;

    let connect_start = Instant::now();
    let client_result = Client::from_config(config).await;
    let connect_time = connect_start.elapsed();
    
    let mut client = match client_result {
        Ok(c) => {
            let _ = evt_tx
                .send(IrcEvent::System {
                    channel: channel.to_string(),
                    text: format!("[TCP] Connected in {:?}", connect_time),
                })
                .await;
            if use_tls {
                let _ = evt_tx
                    .send(IrcEvent::System {
                        channel: channel.to_string(),
                        text: "[TLS] Secure connection established".to_string(),
                    })
                    .await;
            }
            c
        }
        Err(e) => {
            let _ = evt_tx
                .send(IrcEvent::System {
                    channel: channel.to_string(),
                    text: format!("[TCP] Connection FAILED after {:?}: {}", connect_time, e),
                })
                .await;
            
            // Log the full error chain for debugging
            let mut error_chain = format!("{}", e);
            let mut source = e.source();
            while let Some(s) = source {
                error_chain.push_str(&format!(" -> {}", s));
                source = s.source();
            }
            let _ = evt_tx
                .send(IrcEvent::System {
                    channel: channel.to_string(),
                    text: format!("[DEBUG] Error chain: {}", error_chain),
                })
                .await;
            
            // Provide more helpful error messages
            let error_str = error_chain;
            if error_str.contains("certificate") || error_str.contains("tls") || error_str.contains("ssl") {
                let _ = evt_tx
                    .send(IrcEvent::System {
                        channel: channel.to_string(),
                        text: "[TLS] Certificate/TLS error - the server may not support TLS on this port".to_string(),
                    })
                    .await;
                let _ = evt_tx
                    .send(IrcEvent::System {
                        channel: channel.to_string(),
                        text: "[TLS] Try: 1) Disable TLS in profile settings, or 2) Use port 6667".to_string(),
                    })
                    .await;
            } else if error_str.contains("refused") {
                let _ = evt_tx
                    .send(IrcEvent::System {
                        channel: channel.to_string(),
                        text: format!("[TCP] Connection refused - server may be down or port {} blocked", port),
                    })
                    .await;
            } else if error_str.contains("timeout") || error_str.contains("timed out") {
                let _ = evt_tx
                    .send(IrcEvent::System {
                        channel: channel.to_string(),
                        text: "[TCP] Connection timed out - server unreachable or firewall blocking".to_string(),
                    })
                    .await;
            } else if error_str.contains("reset") {
                let _ = evt_tx
                    .send(IrcEvent::System {
                        channel: channel.to_string(),
                        text: "[TCP] Connection reset by server - may be banned or rate-limited".to_string(),
                    })
                    .await;
            }
            
            return Err(Box::new(e));
        }
    };
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: "[IRC] Getting message stream...".to_string(),
        })
        .await;
    
    let mut stream = client.stream()?;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[IRC] Sending registration: NICK {} / USER {}", nickname, nickname),
        })
        .await;
    
    client.identify()?;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: "[IRC] Waiting for server response...".to_string(),
        })
        .await;

    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 10;
    let mut auto_joined = false;
    let mut connected_emitted = false;

    loop {
        tokio::select! {
            command = cmd_rx.recv() => {
                let Some(command) = command.ok() else { break; };
                match command {
                    IrcCommandEvent::Join { channel } => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: JOIN {}", channel),
                            })
                            .await;
                        let _ = client.send_join(&channel);
                    }
                    IrcCommandEvent::Send { channel, text } => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: channel.clone(),
                                text: format!("[IRC] Sent: PRIVMSG {} :{}", channel, text),
                            })
                            .await;
                        let _ = client.send_privmsg(&channel, &text);
                    }
                    IrcCommandEvent::Nick { nickname } => {
                        let nick_copy = nickname.clone();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: NICK {}", nickname),
                            })
                            .await;
                        let _ = client.send(IrcCommand::NICK(nickname));
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: channel.to_string(),
                                text: format!("Nickname set to {nick_copy}."),
                            })
                            .await;
                    }
                    IrcCommandEvent::Part { channel, reason } => {
                        let reason_str = reason.as_ref().map(|r| format!(" :{}", r)).unwrap_or_default();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: channel.clone(),
                                text: format!("[IRC] Sent: PART {}{}", channel, reason_str),
                            })
                            .await;
                        let _ = client.send(IrcCommand::PART(channel, reason));
                    }
                    IrcCommandEvent::Whois { nickname } => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: WHOIS {}", nickname),
                            })
                            .await;
                        let _ = client.send(IrcCommand::WHOIS(None, nickname));
                    }
                    IrcCommandEvent::Who { target } => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: WHO {}", target),
                            })
                            .await;
                        let _ = client.send(IrcCommand::WHO(Some(target), None));
                    }
                    IrcCommandEvent::Topic { channel, topic } => {
                        let topic_str = topic.as_ref().map(|t| format!(" :{}", t)).unwrap_or_default();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: channel.clone(),
                                text: format!("[IRC] Sent: TOPIC {}{}", channel, topic_str),
                            })
                            .await;
                        let _ = client.send(IrcCommand::TOPIC(channel, topic));
                    }
                    IrcCommandEvent::List => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: "[IRC] Sent: LIST".to_string(),
                            })
                            .await;
                        let _ = client.send(IrcCommand::LIST(None, None));
                    }
                    IrcCommandEvent::Msg { target, text } => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: PRIVMSG {} :{}", target, text),
                            })
                            .await;
                        let _ = client.send_privmsg(&target, &text);
                        // Echo the message back to the user in a PM "channel"
                        let _ = evt_tx
                            .send(IrcEvent::Message {
                                channel: target.clone(),
                                user: self_nick.to_string(),
                                text,
                            })
                            .await;
                    }
                    IrcCommandEvent::Notice { target, text } => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: NOTICE {} :{}", target, text),
                            })
                            .await;
                        let _ = client.send(IrcCommand::NOTICE(target, text));
                    }
                    IrcCommandEvent::Kick { channel, user, reason } => {
                        let reason_str = reason.as_ref().map(|r| format!(" :{}", r)).unwrap_or_default();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: channel.clone(),
                                text: format!("[IRC] Sent: KICK {} {}{}", channel, user, reason_str),
                            })
                            .await;
                        let _ = client.send(IrcCommand::KICK(channel, user, reason));
                    }
                    IrcCommandEvent::Mode { target, modes, args } => {
                        let mode_str = if let Some(ref a) = args {
                            format!("{} {}", modes, a)
                        } else {
                            modes.clone()
                        };
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: MODE {} {}", target, mode_str),
                            })
                            .await;
                        // MODE command needs to be sent as a raw command
                        let mode_str = if let Some(ref a) = args {
                            format!("MODE {} {} {}", target, modes, a)
                        } else {
                            format!("MODE {} {}", target, modes)
                        };
                        let _ = client.send(IrcCommand::Raw(mode_str, vec![]));
                    }
                    IrcCommandEvent::Invite { nickname, channel } => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: INVITE {} {}", nickname, channel),
                            })
                            .await;
                        let _ = client.send(IrcCommand::INVITE(nickname, channel));
                    }
                    IrcCommandEvent::Away { message } => {
                        if let Some(ref msg) = message {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("[IRC] Sent: AWAY :{}", msg),
                                })
                                .await;
                            let _ = client.send(IrcCommand::AWAY(Some(msg.clone())));
                        } else {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: "[IRC] Sent: AWAY".to_string(),
                                })
                                .await;
                            let _ = client.send(IrcCommand::AWAY(None));
                        }
                    }
                    IrcCommandEvent::Ctcp { target, message } => {
                        // Send CTCP message via PRIVMSG (CTCP is wrapped in \x01)
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[CTCP] Sent to {}: {}", target, message.replace('\x01', "")),
                            })
                            .await;
                        let _ = client.send_privmsg(&target, &message);
                    }
                    IrcCommandEvent::Quit { message } => {
                        let quit_msg = message.as_ref().map(|m| m.as_str()).unwrap_or("NAIS-client");
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: QUIT :{}", quit_msg),
                            })
                            .await;
                        let _ = client.send_quit(quit_msg);
                        // User-initiated quit - reset reconnection backoff
                        reset_reconnect_state(server);
                        let _ = evt_tx.send(IrcEvent::Disconnected).await;
                        break;
                    }
                    IrcCommandEvent::Raw { command } => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent RAW: {}", command),
                            })
                            .await;
                        let _ = client.send(IrcCommand::Raw(command, vec![]));
                    }
                    IrcCommandEvent::Disconnect => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: QUIT :NAIS-client"),
                            })
                            .await;
                        let _ = client.send_quit("NAIS-client");
                        // User-initiated disconnect - reset reconnection backoff
                        reset_reconnect_state(server);
                        let _ = evt_tx.send(IrcEvent::Disconnected).await;
                        break;
                    }
                    IrcCommandEvent::Connect { .. } => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: channel.to_string(),
                                text: "Already connected.".to_string(),
                            })
                            .await;
                    }
                }
            }
            message = stream.next() => {
                let Some(message) = message else {
                    let _ = evt_tx.send(IrcEvent::Disconnected).await;
                    break;
                };
                let message = match message {
                    Ok(message) => {
                        consecutive_errors = 0; // Reset error count on success
                        message
                    }
                    Err(error) => {
                        let error_str = error.to_string();
                        
                        // Connection reset is fatal - don't retry
                        if error_str.contains("connection reset") || error_str.contains("broken pipe") {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: channel.to_string(),
                                    text: format!("Connection error: {error}"),
                                })
                                .await;
                            let _ = evt_tx.send(IrcEvent::Disconnected).await;
                            break;
                        }
                        
                        consecutive_errors += 1;
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: channel.to_string(),
                                text: format!("Stream error: {error}"),
                            })
                            .await;
                        
                        if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: channel.to_string(),
                                    text: format!("Too many consecutive errors ({}), disconnecting", consecutive_errors),
                                })
                                .await;
                            let _ = evt_tx.send(IrcEvent::Disconnected).await;
                            break;
                        }
                        
                        // Add a small delay to prevent tight error loop
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                
                // Log raw message received
                let _ = evt_tx
                    .send(IrcEvent::System {
                        channel: default_channel.clone(),
                        text: format!("[IRC] Recv: {}", message),
                    })
                    .await;
                
                // Handle PING/PONG immediately
                if let IrcCommand::PING(ref server, ref server2) = message.command {
                    let pong_target = server2.as_ref().unwrap_or(server);
                    let _ = client.send(IrcCommand::PONG(pong_target.clone(), None));
                    let _ = evt_tx
                        .send(IrcEvent::System {
                            channel: default_channel.clone(),
                            text: format!("[IRC] Sent: PONG {}", pong_target),
                        })
                        .await;
                    continue;
                }
                
                match message.command {
                    IrcCommand::PRIVMSG(ref target, ref body) => {
                        let user = message.source_nickname().unwrap_or("unknown").to_string();
                        
                        // Log raw PRIVMSG for debugging
                        log::debug!("[IRC PRIVMSG] From {} to {}: {} chars", user, target, body.len());
                        
                        // Check if this is a CTCP message
                        if let Some((command, args)) = parse_ctcp(body) {
                            log::info!("[IRC CTCP] Parsed CTCP: cmd={}, args_len={}, from={}", command, args.len(), user);
                            if command == "ACTION" {
                                // This is a /me action
                                // For private messages, use sender's nick as channel
                                let channel = if !target.starts_with('#') && !target.starts_with('&') && !target.starts_with('+') && !target.starts_with('!') {
                                    user.clone()
                                } else {
                                    target.to_string()
                                };
                                let _ = evt_tx
                                    .send(IrcEvent::Action {
                                        channel,
                                        user,
                                        text: args,
                                    })
                                    .await;
                            } else if is_voice_ctcp(&command) {
                                // Voice CTCP command - forward to voice system
                                let args_vec: Vec<String> = args.split_whitespace()
                                    .map(|s| s.to_string())
                                    .collect();
                                
                                let _ = evt_tx
                                    .send(IrcEvent::System {
                                        channel: default_channel.clone(),
                                        text: format!("[Voice] {} from {}", command, user),
                                    })
                                    .await;
                                
                                let _ = evt_tx
                                    .send(IrcEvent::VoiceCtcp {
                                        from: user,
                                        command,
                                        args: args_vec,
                                    })
                                    .await;
                            } else if is_nais_ctcp(&command) {
                                // NAIS channel CTCP command - forward to NAIS system
                                let args_vec: Vec<String> = args.split_whitespace()
                                    .map(|s| s.to_string())
                                    .collect();
                                
                                log::info!("[IRC NAIS CTCP] Received {} from {} with {} args", command, user, args_vec.len());
                                
                                let _ = evt_tx
                                    .send(IrcEvent::System {
                                        channel: default_channel.clone(),
                                        text: format!("[NAIS] {} from {}", command, user),
                                    })
                                    .await;
                                
                                let _ = evt_tx
                                    .send(IrcEvent::NaisCtcp {
                                        from: user,
                                        command,
                                        args: args_vec,
                                    })
                                    .await;
                            } else {
                                // This is a CTCP query - send response
                                if let Some(response) = handle_ctcp_query(&command, &args) {
                                    // Send CTCP response via NOTICE to the user
                                    let _ = client.send(IrcCommand::NOTICE(user.clone(), response));
                                    let _ = evt_tx
                                        .send(IrcEvent::System {
                                            channel: default_channel.clone(),
                                            text: format!("[CTCP] {} query from {}, responded", command, user),
                                        })
                                        .await;
                                } else {
                                    // Unknown CTCP command
                                    let _ = evt_tx
                                        .send(IrcEvent::System {
                                            channel: default_channel.clone(),
                                            text: format!("[CTCP] Unknown {} query from {}", command, user),
                                        })
                                        .await;
                                }
                            }
                        } else {
                            // Regular message - not CTCP
                            // Log if it starts with \x01 but wasn't parsed (malformed CTCP?)
                            if body.starts_with('\x01') {
                                log::warn!("[IRC] Message starts with CTCP marker but wasn't parsed: len={}, starts={}, ends={}", 
                                    body.len(), body.starts_with('\x01'), body.ends_with('\x01'));
                            }
                            
                            // For private messages (target is our nick), use sender's nick as channel
                            let channel = if !target.starts_with('#') && !target.starts_with('&') && !target.starts_with('+') && !target.starts_with('!') {
                                // This is a private message to us, use sender's nick as channel
                                user.clone()
                            } else {
                                target.to_string()
                            };
                            let _ = evt_tx
                                .send(IrcEvent::Message {
                                    channel,
                                    user,
                                    text: body.to_string(),
                                })
                                .await;
                        }
                    }
                    IrcCommand::NOTICE(ref target, ref body) => {
                        let user = message.source_nickname().unwrap_or("unknown").to_string();
                        
                        // Check if this is a CTCP response
                        if let Some((command, response)) = parse_ctcp(body) {
                            // Check if this is a NAIS CTCP response
                            if is_nais_ctcp(&command) {
                                let args_vec: Vec<String> = response.split_whitespace()
                                    .map(|s| s.to_string())
                                    .collect();
                                
                                let _ = evt_tx
                                    .send(IrcEvent::System {
                                        channel: target.to_string(),
                                        text: format!("[NAIS] {} response from {}", command, user),
                                    })
                                    .await;
                                
                                let _ = evt_tx
                                    .send(IrcEvent::NaisCtcp {
                                        from: user,
                                        command,
                                        args: args_vec,
                                    })
                                    .await;
                            } else {
                                // This is a CTCP response - emit special event for popup
                                // Note: UI layer handles showing system message to avoid showing during invite probes
                                let _ = evt_tx
                                    .send(IrcEvent::CtcpResponse {
                                        from: user.clone(),
                                        command: command.clone(),
                                        response: response.clone(),
                                    })
                                    .await;
                            }
                        } else {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: target.to_string(),
                                    text: body.to_string(),
                                })
                                .await;
                        }
                    }
                    IrcCommand::JOIN(ref channel, ..) => {
                        let user = message.source_nickname().unwrap_or("unknown");
                        if user == self_nick {
                            let _ = evt_tx
                                .send(IrcEvent::Joined {
                                    channel: channel.to_string(),
                                })
                                .await;
                        } else {
                            // Update user list
                            let _ = evt_tx
                                .send(IrcEvent::UserJoined {
                                    channel: channel.to_string(),
                                    user: user.to_string(),
                                })
                                .await;
                            // Show join message
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: channel.to_string(),
                                    text: format!("{user} joined."),
                                })
                                .await;
                        }
                    }
                    IrcCommand::PART(ref channel, ref reason) => {
                        let user = message.source_nickname().unwrap_or("unknown");
                        let note = reason.clone().unwrap_or_default();
                        if user == self_nick {
                            let _ = evt_tx
                                .send(IrcEvent::Parted {
                                    channel: channel.to_string(),
                                })
                                .await;
                        } else {
                            // Update user list
                            let _ = evt_tx
                                .send(IrcEvent::UserParted {
                                    channel: channel.to_string(),
                                    user: user.to_string(),
                                })
                                .await;
                            // Show part message
                            let detail = if note.is_empty() {
                                format!("{user} left.")
                            } else {
                                format!("{user} left: {note}")
                            };
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: channel.to_string(),
                                    text: detail,
                                })
                                .await;
                        }
                    }
                    IrcCommand::QUIT(ref reason) => {
                        let user = message.source_nickname().unwrap_or("unknown");
                        // Update user list (removes from all channels)
                        let _ = evt_tx
                            .send(IrcEvent::UserQuit {
                                user: user.to_string(),
                            })
                            .await;
                        // Show quit message
                        let note = reason.clone().unwrap_or_default();
                        let detail = if note.is_empty() {
                            format!("{user} quit.")
                        } else {
                            format!("{user} quit: {note}")
                        };
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: detail,
                            })
                            .await;
                    }
                    IrcCommand::KICK(ref channel, ref kicked_user, ref reason) => {
                        let user = message.source_nickname().unwrap_or("unknown");
                        let reason_text = reason.clone().unwrap_or_default();
                        let detail = if reason_text.is_empty() {
                            format!("{kicked_user} was kicked by {user}")
                        } else {
                            format!("{kicked_user} was kicked by {user}: {reason_text}")
                        };
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: channel.clone(),
                                text: detail,
                            })
                            .await;
                        // Update user list
                        if kicked_user.as_str() == self_nick {
                            // We were kicked - part the channel
                            let _ = evt_tx
                                .send(IrcEvent::Parted {
                                    channel: channel.clone(),
                                })
                                .await;
                        } else {
                            // Someone else was kicked - remove them from user list (no extra message needed)
                            let _ = evt_tx
                                .send(IrcEvent::UserParted {
                                    channel: channel.clone(),
                                    user: kicked_user.clone(),
                                })
                                .await;
                        }
                    }
                    IrcCommand::INVITE(ref invited_user, ref channel) => {
                        let user = message.source_nickname().unwrap_or("unknown");
                        if invited_user.as_str() == self_nick {
                            // We are being invited - emit Invited event for popup handling
                            let _ = evt_tx
                                .send(IrcEvent::Invited {
                                    from: user.to_string(),
                                    channel: channel.clone(),
                                })
                                .await;
                        } else {
                            // Someone else was invited - show as system message
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("{user} invited {invited_user} to {channel}"),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_UMODEIS, _) => {
                        // User mode response (221) - we're fully connected, trigger auto-join
                        // Sync our nick with what the library actually registered
                        let actual_nick = client.current_nickname().to_string();
                        if actual_nick != self_nick {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("[IRC] Registered with nickname '{}' (was '{}')", actual_nick, self_nick),
                                })
                                .await;
                            self_nick = actual_nick.clone();
                            let _ = evt_tx
                                .send(IrcEvent::NickChanged {
                                    new_nick: actual_nick,
                                })
                                .await;
                        }
                        if !auto_joined && !default_channel.is_empty() {
                            // Send MODE +x to hide host if enabled and not yet sent
                            if !hide_host_sent {
                                hide_host_sent = true;
                                let _ = evt_tx
                                    .send(IrcEvent::System {
                                        channel: default_channel.clone(),
                                        text: format!("[IRC] Sent: MODE {} +x", self_nick),
                                    })
                                    .await;
                                let mode_str = format!("MODE {} +x", self_nick);
                                let _ = client.send(IrcCommand::Raw(mode_str, vec![]));
                            }
                            auto_joined = true;
                            // Join all comma-separated channels
                            for channel in default_channel.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                                let _ = evt_tx
                                    .send(IrcEvent::System {
                                        channel: channel.to_string(),
                                        text: format!("[IRC] Sent: JOIN {}", channel),
                                    })
                                    .await;
                                let _ = client.send_join(channel);
                            }
                        }
                    }
                    IrcCommand::Response(Response::RPL_ENDOFMOTD, _) => {
                        if !connected_emitted {
                            evt_tx
                                .send(IrcEvent::Connected {
                                    server: server.to_string(),
                                })
                                .await?;
                            // Successfully connected - reset the reconnection backoff
                            record_connection_success(server);
                            connected_emitted = true;
                        }

                        // End of MOTD - now we can join the channel
                        // Sync our nick with what the library actually registered
                        let actual_nick = client.current_nickname().to_string();
                        if actual_nick != self_nick {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("[IRC] Registered with nickname '{}' (was '{}')", actual_nick, self_nick),
                                })
                                .await;
                            self_nick = actual_nick.clone();
                            let _ = evt_tx
                                .send(IrcEvent::NickChanged {
                                    new_nick: actual_nick,
                                })
                                .await;
                        }
                        if !auto_joined && !default_channel.is_empty() {
                            // Send MODE +x to hide host if enabled and not yet sent
                            if !hide_host_sent {
                                hide_host_sent = true;
                                let _ = evt_tx
                                    .send(IrcEvent::System {
                                        channel: default_channel.clone(),
                                        text: format!("[IRC] Sent: MODE {} +x", self_nick),
                                    })
                                    .await;
                                let mode_str = format!("MODE {} +x", self_nick);
                                let _ = client.send(IrcCommand::Raw(mode_str, vec![]));
                            }
                            auto_joined = true;
                            // Join all comma-separated channels
                            for channel in default_channel.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                                let _ = evt_tx
                                    .send(IrcEvent::System {
                                        channel: channel.to_string(),
                                        text: format!("[IRC] Sent: JOIN {}", channel),
                                    })
                                    .await;
                                let _ = client.send_join(channel);
                            }
                        }
                    }
                    IrcCommand::Response(Response::ERR_NOMOTD, _) => {
                        // Some servers skip MOTD and send ERR_NOMOTD instead.
                        if !connected_emitted {
                            evt_tx
                                .send(IrcEvent::Connected {
                                    server: server.to_string(),
                                })
                                .await?;
                            // Successfully connected - reset the reconnection backoff
                            record_connection_success(server);
                            connected_emitted = true;
                        }
                    }
                    IrcCommand::Response(Response::RPL_NAMREPLY, ref args) => {
                        if args.len() >= 4 {
                            let channel = args[2].clone();
                            // Keep prefixes: @ for op, + for voice
                            let names = args[3]
                                .split_whitespace()
                                .map(|name| name.to_string())
                                .collect::<Vec<_>>();
                            let _ = evt_tx
                                .send(IrcEvent::Users { channel, users: names })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_WHOISUSER, ref args) => {
                        if args.len() >= 5 {
                            let nick = args[1].clone();
                            let user = args[2].clone();
                            let host = args[3].clone();
                            let real = args[4].clone();
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("WHOIS {nick}: {user}@{host} ({real})"),
                                })
                                .await;
                            let _ = evt_tx
                                .send(IrcEvent::WhoisUser {
                                    nick: nick.clone(),
                                    user,
                                    host,
                                    realname: real,
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_WHOISSERVER, ref args) => {
                        if args.len() >= 4 {
                            let nick = args[1].clone();
                            let server = args[2].clone();
                            let info = args[3].clone();
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("WHOIS {nick}: server {server} ({info})"),
                                })
                                .await;
                            let _ = evt_tx
                                .send(IrcEvent::WhoisServer {
                                    nick: nick.clone(),
                                    server,
                                    server_info: info,
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_WHOISCHANNELS, ref args) => {
                        if args.len() >= 3 {
                            let nick = args[1].clone();
                            let channels = args[2].clone();
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("WHOIS {nick}: channels {channels}"),
                                })
                                .await;
                            let _ = evt_tx
                                .send(IrcEvent::WhoisChannels {
                                    nick: nick.clone(),
                                    channels,
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_WHOISIDLE, ref args) => {
                        if args.len() >= 3 {
                            let nick = args[1].clone();
                            let idle = args[2].clone();
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("WHOIS {nick}: idle {idle}s"),
                                })
                                .await;
                            let _ = evt_tx
                                .send(IrcEvent::WhoisIdle {
                                    nick: nick.clone(),
                                    idle_secs: idle,
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_ENDOFWHOIS, ref args) => {
                        if args.len() >= 2 {
                            let nick = args[1].clone();
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("WHOIS {nick}: end"),
                                })
                                .await;
                            let _ = evt_tx
                                .send(IrcEvent::WhoisEnd {
                                    nick: nick.clone(),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_WHOREPLY, ref args) => {
                        if args.len() >= 7 {
                            let channel = args[1].clone();
                            let user = args[2].clone();
                            let host = args[3].clone();
                            let nick = args[5].clone();
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("WHO {channel}: {nick} {user}@{host}"),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_ENDOFWHO, ref args) => {
                        if args.len() >= 2 {
                            let target = args[1].clone();
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("WHO {target}: end"),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_AWAY, ref args) => {
                        // 301: <nick> :<away message>
                        if args.len() >= 3 {
                            let nick = args[1].clone();
                            let away_msg = args[2].clone();
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("{nick} is away: {away_msg}"),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_UNAWAY, ref args) => {
                        // 305: :You are no longer marked as being away
                        if args.len() >= 2 {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: args[1].clone(),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_NOWAWAY, ref args) => {
                        // 306: :You have been marked as being away
                        if args.len() >= 2 {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: args[1].clone(),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_INVITING, ref args) => {
                        // 341: <nick> <channel>
                        if args.len() >= 3 {
                            let nick = args[1].clone();
                            let channel = args[2].clone();
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("Invited {nick} to {channel}"),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_CHANNELMODEIS, ref args) => {
                        // 324: <channel> <mode> <mode params>
                        if args.len() >= 3 {
                            let channel = args[1].clone();
                            let modes = args[2].clone();
                            let mode_args = if args.len() > 3 {
                                format!(" {}", args[3..].join(" "))
                            } else {
                                String::new()
                            };
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: channel.clone(),
                                    text: format!("Channel modes: {modes}{mode_args}"),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_TOPIC, ref args) => {
                        // 332: <channel> :<topic>
                        if args.len() >= 3 {
                            let channel = args[1].clone();
                            let topic = args[2].clone();
                            let _ = evt_tx
                                .send(IrcEvent::Topic {
                                    channel,
                                    topic,
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_NOTOPIC, ref args) => {
                        // 331: <channel> :No topic is set
                        if args.len() >= 2 {
                            let channel = args[1].clone();
                            let _ = evt_tx
                                .send(IrcEvent::Topic {
                                    channel,
                                    topic: String::new(),
                                })
                                .await;
                        }
                    }
                    IrcCommand::TOPIC(ref channel, ref new_topic) => {
                        // Someone changed the topic
                        if let Some(topic) = new_topic {
                            let user = message.source_nickname().unwrap_or("unknown");
                            let _ = evt_tx
                                .send(IrcEvent::Topic {
                                    channel: channel.clone(),
                                    topic: topic.clone(),
                                })
                                .await;
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: channel.clone(),
                                    text: format!("{user} changed the topic to: {topic}"),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_LIST, ref args) => {
                        // RPL_LIST: <channel> <# visible> :<topic>
                        if args.len() >= 3 {
                            let channel = args[1].clone();
                            let user_count = args[2].parse::<u32>().unwrap_or(0);
                            let topic = if args.len() >= 4 {
                                args[3].clone()
                            } else {
                                String::new()
                            };
                            let _ = evt_tx
                                .send(IrcEvent::ChannelListItem {
                                    channel,
                                    user_count,
                                    topic,
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::RPL_LISTEND, _) => {
                        let _ = evt_tx.send(IrcEvent::ChannelListEnd).await;
                    }
                    IrcCommand::Response(Response::RPL_WELCOME, ref args) => {
                        // 001 - Welcome message, registration successful
                        let welcome_msg = args.get(1).cloned().unwrap_or_default();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] ✓ Registration successful: {}", welcome_msg),
                            })
                            .await;
                    }
                    IrcCommand::Response(Response::RPL_YOURHOST, ref args) => {
                        // 002 - Your host is...
                        let host_msg = args.get(1).cloned().unwrap_or_default();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Server: {}", host_msg),
                            })
                            .await;
                    }
                    IrcCommand::Response(Response::RPL_CREATED, ref args) => {
                        // 003 - Server created...
                        let created_msg = args.get(1).cloned().unwrap_or_default();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] {}", created_msg),
                            })
                            .await;
                    }
                    IrcCommand::Response(Response::RPL_MYINFO, ref args) => {
                        // 004 - Server info
                        if args.len() > 2 {
                            let server_name = args.get(1).cloned().unwrap_or_default();
                            let server_ver = args.get(2).cloned().unwrap_or_default();
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("[IRC] Software: {} {}", server_name, server_ver),
                                })
                                .await;
                        }
                    }
                    IrcCommand::Response(Response::ERR_BADCHANNELKEY, ref args) => {
                        // 475 - Bad channel key (password required)
                        let channel_name = args.get(1).cloned().unwrap_or_default();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[ERROR] Cannot join {}: Channel requires a password", channel_name),
                            })
                            .await;
                    }
                    IrcCommand::Response(Response::ERR_NOSUCHCHANNEL, ref args) => {
                        // 403 - No such channel
                        let channel_name = args.get(1).cloned().unwrap_or_default();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[ERROR] No such channel: {}", channel_name),
                            })
                            .await;
                    }
                    IrcCommand::Response(Response::ERR_NOTREGISTERED, _) => {
                        // 451 - Not registered yet
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: "[ERROR] Server says: Not registered yet. Waiting...".to_string(),
                            })
                            .await;
                    }
                    IrcCommand::Response(Response::ERR_INVITEONLYCHAN, ref args) => {
                        // 473 - Invite only channel
                        let channel_name = args.get(1).cloned().unwrap_or_default();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[ERROR] Cannot join {}: Channel is invite-only", channel_name),
                            })
                            .await;
                    }
                    IrcCommand::Response(Response::ERR_CHANNELISFULL, ref args) => {
                        // 471 - Channel is full
                        let channel_name = args.get(1).cloned().unwrap_or_default();
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[ERROR] Cannot join {}: Channel is full", channel_name),
                            })
                            .await;
                    }
                    IrcCommand::Response(Response::ERR_NICKNAMEINUSE, ref args) => {
                        // Nickname is already in use - library handles rollover via alt_nicks
                        // Just inform the user about the rollover
                        let rejected_nick = if args.len() >= 2 { &args[1] } else { &self_nick };
                        nick_attempt += 1;
                        
                        if nick_attempt <= fallback_nicks.len() {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("[IRC] Nickname '{}' is in use, trying fallback...", rejected_nick),
                                })
                                .await;
                        } else {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("[IRC] All nicknames in use. You may need to manually change your nickname with /nick."),
                                })
                                .await;
                        }
                    }
                    IrcCommand::ERROR(ref msg) => {
                        // Server ERROR message
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[SERVER ERROR] {}", msg),
                            })
                            .await;
                    }
                    IrcCommand::Response(ref resp, ref args) => {
                        // Catch-all for other numeric responses - shows all server messages
                        let code = format!("{:?}", resp);
                        let msg = args.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
                        if !msg.is_empty() {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("[{}] {}", code, msg),
                                })
                                .await;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
