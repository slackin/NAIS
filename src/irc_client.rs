//! Core IRC state, events, and the network loop.

use async_channel::{Receiver, Sender};
use futures::StreamExt;
use irc::client::prelude::{Client, Command as IrcCommand, Config, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use tokio02::runtime::Runtime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
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
    pub auto_reconnect: bool,
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
    Users { channel: String, users: Vec<String> },
    Message { channel: String, user: String, text: String },
    Action { channel: String, user: String, text: String },
    System { channel: String, text: String },
    Topic { channel: String, topic: String },
    ChannelListItem { channel: String, user_count: u32, topic: String },
    ChannelListEnd,
}

#[derive(Clone, Debug)]
pub enum IrcCommandEvent {
    Connect {
        server: String,
        nickname: String,
        channel: String,
        use_tls: bool,
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
        IrcEvent::Message { channel, user, text } => {
            state.messages.push(ChatMessage {
                channel,
                user,
                text,
                is_system: false,
                is_action: false,
                timestamp: chrono::Utc::now().timestamp(),
            });
        }
        IrcEvent::Action { channel, user, text } => {
            state.messages.push(ChatMessage {
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
            if text.contains("error") || text.contains("Error") || 
               text.contains("Connection") || text.contains("TLS") || 
               text.contains("Stream") || text.starts_with("[IRC]") {
                state.connection_log.push(text.clone());
            }
            
            // Only add to channel messages if it's NOT an IRC protocol message
            if !text.starts_with("[IRC]") {
                state.messages.push(ChatMessage {
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
        let mut runtime = Runtime::new().expect("tokio runtime");
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
            } => {
                if let Err(error) = handle_connection(
                    &server,
                    &nickname,
                    &channel,
                    use_tls,
                    &command_rx,
                    &evt_tx,
                )
                .await
                {
                    let _ = evt_tx
                        .send(IrcEvent::System {
                            channel: channel.clone(),
                            text: format!("Connection error: {error}"),
                        })
                        .await;
                    let _ = evt_tx.send(IrcEvent::Disconnected).await;
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
            Some(create_ctcp_response("CLIENTINFO", "ACTION VERSION CLIENTINFO TIME PING"))
        }
        "TIME" => {
            let now = chrono::Local::now();
            Some(create_ctcp_response("TIME", &now.to_rfc2822()))
        }
        "PING" => {
            Some(create_ctcp_response("PING", args))
        }
        _ => None,
    }
}

async fn handle_connection(
    server: &str,
    nickname: &str,
    channel: &str,
    use_tls: bool,
    cmd_rx: &Receiver<IrcCommandEvent>,
    evt_tx: &Sender<IrcEvent>,
) -> Result<(), Box<dyn Error>> {
    let mut self_nick = nickname.to_string();
    let default_channel = channel.to_string();
    let fallback_nicks = crate::profile::generate_fallback_nicknames(nickname);
    let mut nick_attempt = 0;
    
    // Determine port and log connection type
    let port = if use_tls { 6697 } else { 6667 };
    let connection_type = if use_tls { "with TLS" } else { "without TLS (plaintext)" };
    
    // Log connection attempt
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[IRC] Configuring connection to {}:{} {}", server, port, connection_type),
        })
        .await;
    
    let mut config = Config::default();
    config.server = Some(server.to_string());
    config.nickname = Some(nickname.to_string());
    config.port = Some(port);
    config.use_tls = Some(use_tls);
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
            text: format!("[IRC] Attempting {} connection to {}:{}...", if use_tls { "TLS" } else { "plaintext" }, server, port),
        })
        .await;

    let mut client = Client::from_config(config).await?;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[IRC] {} connection established, getting message stream", if use_tls { "TCP/TLS" } else { "TCP" }),
        })
        .await;
    
    let mut stream = client.stream()?;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[IRC] Sending identification"),
        })
        .await;
    
    client.identify()?;

    evt_tx
        .send(IrcEvent::Connected {
            server: server.to_string(),
        })
        .await?;

    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 10;
    let mut auto_joined = false;

    loop {
        tokio02::select! {
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
                    IrcCommandEvent::Disconnect => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: format!("[IRC] Sent: QUIT :NAIS-client"),
                            })
                            .await;
                        let _ = client.send_quit("NAIS-client");
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
                        tokio02::time::delay_for(Duration::from_millis(100)).await;
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
                        
                        // Check if this is a CTCP message
                        if let Some((command, args)) = parse_ctcp(body) {
                            if command == "ACTION" {
                                // This is a /me action
                                let _ = evt_tx
                                    .send(IrcEvent::Action {
                                        channel: target.to_string(),
                                        user,
                                        text: args,
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
                            // Regular message
                            let _ = evt_tx
                                .send(IrcEvent::Message {
                                    channel: target.to_string(),
                                    user,
                                    text: body.to_string(),
                                })
                                .await;
                        }
                    }
                    IrcCommand::NOTICE(ref target, ref body) => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: target.to_string(),
                                text: body.to_string(),
                            })
                            .await;
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
                        // If we were kicked, part the channel
                        if kicked_user.as_str() == self_nick {
                            let _ = evt_tx
                                .send(IrcEvent::Parted {
                                    channel: channel.clone(),
                                })
                                .await;
                        }
                    }
                    IrcCommand::INVITE(ref invited_user, ref channel) => {
                        let user = message.source_nickname().unwrap_or("unknown");
                        let detail = if invited_user.as_str() == self_nick {
                            format!("{user} invited you to {channel}")
                        } else {
                            format!("{user} invited {invited_user} to {channel}")
                        };
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: default_channel.clone(),
                                text: detail,
                            })
                            .await;
                    }
                    IrcCommand::Response(Response::RPL_UMODEIS, _) => {
                        // User mode response (221) - we're fully connected, trigger auto-join
                        if !auto_joined && !default_channel.is_empty() {
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
                        // End of MOTD - now we can join the channel
                        if !auto_joined && !default_channel.is_empty() {
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
                    IrcCommand::Response(Response::ERR_NICKNAMEINUSE, ref args) => {
                        // Nickname is already in use, try a fallback
                        if nick_attempt < fallback_nicks.len() {
                            let new_nick = fallback_nicks[nick_attempt].clone();
                            nick_attempt += 1;
                            
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("[IRC] Nickname '{}' is in use, trying '{}'...", self_nick, new_nick),
                                })
                                .await;
                            
                            self_nick = new_nick.clone();
                            let _ = client.send(IrcCommand::NICK(new_nick));
                        } else {
                            let _ = evt_tx
                                .send(IrcEvent::System {
                                    channel: default_channel.clone(),
                                    text: format!("[IRC] All nicknames in use. You may need to manually change your nickname with /nick."),
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
