//! Core IRC state, events, and the network loop.

use async_channel::{Receiver, Sender};
use futures::StreamExt;
use irc::client::prelude::{Client, Command as IrcCommand, Config, Response};
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

#[derive(Clone, Debug)]
pub struct ChatMessage {
    pub channel: String,
    pub user: String,
    pub text: String,
    pub is_system: bool,
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
}

#[derive(Clone, Debug)]
pub enum IrcEvent {
    Connected { server: String },
    Disconnected,
    Joined { channel: String },
    Parted { channel: String },
    Users { channel: String, users: Vec<String> },
    Message { channel: String, user: String, text: String },
    System { channel: String, text: String },
}

#[derive(Clone, Debug)]
pub enum IrcCommandEvent {
    Connect {
        server: String,
        nickname: String,
        channel: String,
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
    Disconnect,
}

#[derive(Clone)]
pub struct CoreHandle {
    pub cmd_tx: Sender<IrcCommandEvent>,
    pub evt_rx: Receiver<IrcEvent>,
}

pub fn default_server_state(server: String, nickname: String, channel: String) -> ServerState {
    let mut users_by_channel = HashMap::new();
    let channel = channel.trim().to_string();
    let current_channel = if channel.is_empty() { String::new() } else { channel };
    if !current_channel.is_empty() {
        users_by_channel.insert(
            current_channel.clone(),
            vec!["aiden".to_string(), "nova".to_string(), "you".to_string()],
        );
    }
    let channels = if current_channel.is_empty() {
        Vec::new()
    } else {
        vec![current_channel.clone()]
    };
    let mut messages = Vec::new();
    if !current_channel.is_empty() {
        messages.push(ChatMessage {
            channel: current_channel.clone(),
            user: "system".to_string(),
            text: "Welcome to NAIS-client.".to_string(),
            is_system: true,
        });
    }
    ServerState {
        status: ConnectionStatus::Disconnected,
        server,
        nickname,
        current_channel,
        channels,
        users_by_channel,
        messages,
        auto_reconnect: true,
        last_connect: None,
        connection_log: Vec::new(),
    }
}
pub fn apply_event(state: &mut AppState, profile: &str, event: IrcEvent) {
    if let Some(server_state) = state.servers.get_mut(profile) {
        apply_event_to_server(server_state, event);
    }
}

pub fn apply_event_to_server(state: &mut ServerState, event: IrcEvent) {
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
            state.messages.push(ChatMessage {
                channel,
                user: "system".to_string(),
                text: "Joined channel.".to_string(),
                is_system: true,
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
            });
        }
        IrcEvent::Users { channel, users } => {
            state.users_by_channel.insert(channel, users);
        }
        IrcEvent::Message { channel, user, text } => {
            state.messages.push(ChatMessage {
                channel,
                user,
                text,
                is_system: false,
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
                });
            }
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
            } => {
                if let Err(error) = handle_connection(
                    &server,
                    &nickname,
                    &channel,
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

async fn handle_connection(
    server: &str,
    nickname: &str,
    channel: &str,
    cmd_rx: &Receiver<IrcCommandEvent>,
    evt_tx: &Sender<IrcEvent>,
) -> Result<(), Box<dyn Error>> {
    let self_nick = nickname.to_string();
    let default_channel = channel.to_string();
    
    // Log connection attempt
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[IRC] Configuring connection to {}:6697 with TLS", server),
        })
        .await;
    
    let mut config = Config::default();
    config.server = Some(server.to_string());
    config.nickname = Some(nickname.to_string());
    config.port = Some(6697);
    config.use_tls = Some(true);

    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[IRC] Attempting TLS connection to {}:6697...", server),
        })
        .await;

    let mut client = Client::from_config(config).await?;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[IRC] TCP/TLS connection established, sending identification"),
        })
        .await;
    
    client.identify()?;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[IRC] Sent: NICK {}", nickname),
        })
        .await;
    
    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[IRC] Sent: USER {} 0 * :{}", nickname, nickname),
        })
        .await;
    
    let mut stream = client.stream()?;

    evt_tx
        .send(IrcEvent::Connected {
            server: server.to_string(),
        })
        .await?;

    let _ = evt_tx
        .send(IrcEvent::System {
            channel: channel.to_string(),
            text: format!("[IRC] Sent: JOIN {}", channel),
        })
        .await;

    client.send_join(channel)?;

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
                    Ok(message) => message,
                    Err(error) => {
                        let _ = evt_tx
                            .send(IrcEvent::System {
                                channel: channel.to_string(),
                                text: format!("Stream error: {error}"),
                            })
                            .await;
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
                
                match message.command {
                    IrcCommand::PRIVMSG(ref target, ref body) => {
                        let user = message.source_nickname().unwrap_or("unknown").to_string();
                        let _ = evt_tx
                            .send(IrcEvent::Message {
                                channel: target.to_string(),
                                user,
                                text: body.to_string(),
                            })
                            .await;
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
                    IrcCommand::Response(Response::RPL_NAMREPLY, ref args) => {
                        if args.len() >= 4 {
                            let channel = args[2].clone();
                            let names = args[3]
                                .split_whitespace()
                                .map(|name| name.trim_start_matches(['@', '+']).to_string())
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
                    _ => {}
                }
            }
        }
        tokio02::time::delay_for(Duration::from_millis(10)).await;
    }

    Ok(())
}
