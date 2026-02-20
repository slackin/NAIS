//! NAIS Secure Channel Module
//! 
//! Implements peer-to-peer encrypted channels that use IRC as a discovery mechanism.
//! 
//! ## How it works:
//! 1. A client creates a "discovery" channel on IRC with a special topic format: `NAIS:v1:<channel_id>:<creator_fingerprint>`
//! 2. The IRC channel is set to moderated (+m) so no one can speak in it - it's only for discovery
//! 3. When other NAIS clients join and see the NAIS topic identifier, they:
//!    a. Probe existing users via CTCP to discover NAIS-capable clients
//!    b. Exchange connection info and encryption keys
//!    c. Establish direct P2P connections for actual communication
//! 4. All chat messages are sent encrypted directly between clients, not through IRC
//! 
//! This provides:
//! - End-to-end encryption (IRC server never sees message content)
//! - Decentralized routing (no central server for messages)
//! - IRC-based discovery (leverages existing IRC infrastructure)

#![allow(dead_code)]

use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use async_channel::{Receiver, Sender};
use serde::{Serialize, Deserialize};

// ============================================================================
// Constants
// ============================================================================

/// NAIS protocol version identifier
pub const NAIS_PROTOCOL_VERSION: &str = "v1";

/// Topic prefix that identifies a NAIS discovery channel
pub const NAIS_TOPIC_PREFIX: &str = "NAIS:";

/// CTCP command to probe if a user is a NAIS client
pub const CTCP_NAIS_PROBE: &str = "NAIS_PROBE";

/// CTCP response confirming NAIS capability with client info
pub const CTCP_NAIS_INFO: &str = "NAIS_INFO";

/// CTCP command to request joining a NAIS channel
pub const CTCP_NAIS_JOIN: &str = "NAIS_JOIN";

/// CTCP command to accept a join request with connection info
pub const CTCP_NAIS_ACCEPT: &str = "NAIS_ACCEPT";

/// CTCP command to send P2P connection details
pub const CTCP_NAIS_CONNECT: &str = "NAIS_CONNECT";

/// CTCP command to announce leaving a NAIS channel
pub const CTCP_NAIS_LEAVE: &str = "NAIS_LEAVE";

/// CTCP command to announce a message (used for message routing info)
pub const CTCP_NAIS_MSG: &str = "NAIS_MSG";

/// CTCP command to invite a user to a channel (with full server info for cross-network invites)
/// Format: NAIS_CHANNEL_INVITE <channel> <server> <type:nais|irc>
pub const CTCP_NAIS_CHANNEL_INVITE: &str = "NAIS_CHANNEL_INVITE";

/// Default port range for P2P listeners
pub const DEFAULT_PORT_RANGE_START: u16 = 45000;
pub const DEFAULT_PORT_RANGE_END: u16 = 45100;

/// Maximum number of peers in a channel
pub const MAX_PEERS: usize = 50;

// ============================================================================
// Types
// ============================================================================

/// State of a NAIS channel
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NaisChannelState {
    /// Channel is being created (setting up IRC channel)
    Creating,
    /// Channel is active and operational
    Active,
    /// Discovery phase - probing users
    Discovering,
    /// Connecting to peers
    Connecting,
    /// Channel is closed/left
    Closed,
}

/// A peer in the NAIS channel
#[derive(Clone, Debug)]
pub struct NaisPeer {
    /// IRC nickname of the peer
    pub nickname: String,
    /// Peer's public key fingerprint (for encryption)
    pub fingerprint: String,
    /// Peer's IP address for P2P connection
    pub ip: String,
    /// Peer's listening port for P2P connection
    pub port: u16,
    /// When the peer joined
    pub joined_at: Instant,
    /// Whether we have an active P2P connection to this peer
    pub connected: bool,
    /// Last time we received data from this peer
    pub last_seen: Instant,
}

/// NAIS Channel information
#[derive(Clone, Debug)]
pub struct NaisChannel {
    /// Unique channel ID (random hex string)
    pub channel_id: String,
    /// The IRC channel name used for discovery (e.g., "#nais-abc123")
    pub irc_channel: String,
    /// Display name for the channel
    pub name: Option<String>,
    /// Our own nickname in this channel
    pub our_nickname: String,
    /// Our public key fingerprint
    pub our_fingerprint: String,
    /// Our listening IP (external)
    pub our_ip: String,
    /// Our listening port
    pub our_port: u16,
    /// Whether we are the channel creator/host
    pub is_host: bool,
    /// List of peers in this channel
    pub peers: HashMap<String, NaisPeer>,
    /// Channel state
    pub state: NaisChannelState,
    /// When the channel was created/joined
    pub created_at: Instant,
    /// Pending probes (users we've sent NAIS_PROBE to)
    pub pending_probes: Vec<String>,
    /// Messages in this channel (encrypted locally)
    pub messages: Vec<NaisMessage>,
}

/// A message in a NAIS channel
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NaisMessage {
    /// Unique message ID
    pub id: String,
    /// Channel ID
    pub channel_id: String,
    /// Sender's nickname
    pub sender: String,
    /// Message content (plaintext, encryption handled at transport)
    pub content: String,
    /// Timestamp
    pub timestamp: i64,
    /// Whether this is a system message
    pub is_system: bool,
}

/// Events emitted by the NAIS channel system
#[derive(Clone, Debug)]
pub enum NaisEvent {
    /// Channel was created successfully
    ChannelCreated { channel: NaisChannel },
    /// Joined an existing NAIS channel
    ChannelJoined { channel_id: String, irc_channel: String },
    /// Left a channel
    ChannelLeft { channel_id: String },
    /// Channel was closed
    ChannelClosed { channel_id: String, reason: String },
    /// A peer joined the channel
    PeerJoined { channel_id: String, peer: NaisPeer },
    /// A peer left the channel
    PeerLeft { channel_id: String, nickname: String },
    /// Connected to a peer
    PeerConnected { channel_id: String, nickname: String },
    /// Disconnected from a peer
    PeerDisconnected { channel_id: String, nickname: String },
    /// Received a message
    MessageReceived { channel_id: String, message: NaisMessage },
    /// Message sent successfully
    MessageSent { channel_id: String, message_id: String },
    /// Discovery found NAIS users
    DiscoveryResult { channel_id: String, users: Vec<String> },
    /// State changed
    StateChanged { channel_id: String, state: NaisChannelState },
    /// Error occurred
    Error { channel_id: Option<String>, message: String },
    /// Received a probe request
    ProbeReceived { from: String, irc_channel: String },
    /// Need to send IRC command
    SendIrcCommand { command: NaisIrcCommand },
}

/// Commands to send to IRC from NAIS system
#[derive(Clone, Debug)]
pub enum NaisIrcCommand {
    /// Join an IRC channel
    Join { channel: String },
    /// Set channel topic
    Topic { channel: String, topic: String },
    /// Set channel modes
    Mode { channel: String, modes: String },
    /// Send CTCP message
    Ctcp { target: String, message: String },
    /// Send CTCP response (via NOTICE)  
    CtcpResponse { target: String, message: String },
    /// Leave IRC channel
    Part { channel: String, reason: Option<String> },
}

/// Commands for the NAIS channel system
#[derive(Clone, Debug)]
pub enum NaisCommand {
    /// Create a new NAIS channel
    Create { name: Option<String> },
    /// Join an existing NAIS channel (after detecting it)
    Join { irc_channel: String },
    /// Leave a NAIS channel
    Leave { channel_id: String },
    /// Send a message to a channel
    SendMessage { channel_id: String, content: String },
    /// Respond to a probe
    RespondToProbe { from: String, irc_channel: String },
    /// Process discovered users in IRC channel
    ProcessUsers { irc_channel: String, users: Vec<String> },
    /// Handle incoming CTCP
    HandleCtcp { from: String, command: String, args: Vec<String> },
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a unique channel ID
pub fn generate_channel_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}{:x}", (timestamp & 0xFFFFFFFF) as u32, count)
}

/// Generate a fingerprint (simplified - in production use actual crypto)
pub fn generate_fingerprint() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:016x}", timestamp)
}

/// Generate a unique message ID
pub fn generate_message_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("msg{:x}{:x}", timestamp as u64, count)
}

/// Check if a topic indicates a NAIS channel
pub fn is_nais_topic(topic: &str) -> bool {
    topic.starts_with(NAIS_TOPIC_PREFIX)
}

/// Parse NAIS topic to extract channel info
/// Format: NAIS:v1:<channel_id>:<creator_fingerprint>
pub fn parse_nais_topic(topic: &str) -> Option<(String, String, String)> {
    if !topic.starts_with(NAIS_TOPIC_PREFIX) {
        return None;
    }
    
    let parts: Vec<&str> = topic.split(':').collect();
    if parts.len() >= 4 && parts[1] == NAIS_PROTOCOL_VERSION {
        Some((
            parts[1].to_string(), // version
            parts[2].to_string(), // channel_id
            parts[3].to_string(), // fingerprint
        ))
    } else {
        None
    }
}

/// Create NAIS topic string
pub fn create_nais_topic(channel_id: &str, fingerprint: &str) -> String {
    format!("{}{}:{}:{}", NAIS_TOPIC_PREFIX, NAIS_PROTOCOL_VERSION, channel_id, fingerprint)
}

/// Create IRC channel name for NAIS channel
pub fn create_nais_irc_channel(channel_id: &str) -> String {
    format!("#nais-{}", &channel_id[..8.min(channel_id.len())])
}

// ============================================================================
// CTCP Message Creation
// ============================================================================

/// Create CTCP probe message
/// Sent to users in a NAIS IRC channel to check if they're NAIS clients
pub fn create_probe_ctcp(irc_channel: &str) -> String {
    format!("\x01{} {}\x01", CTCP_NAIS_PROBE, irc_channel)
}

/// Create CTCP info response message
/// Response to a probe with our NAIS info
pub fn create_info_ctcp(channel_id: &str, fingerprint: &str, ip: &str, port: u16) -> String {
    format!("\x01{} {} {} {} {}\x01", CTCP_NAIS_INFO, channel_id, fingerprint, ip, port)
}

/// Create CTCP join request message
/// Request to join a NAIS channel
pub fn create_join_ctcp(channel_id: &str, fingerprint: &str, ip: &str, port: u16) -> String {
    format!("\x01{} {} {} {} {}\x01", CTCP_NAIS_JOIN, channel_id, fingerprint, ip, port)
}

/// Create CTCP accept message
/// Accept a peer into the channel
pub fn create_accept_ctcp(channel_id: &str, fingerprint: &str, ip: &str, port: u16) -> String {
    format!("\x01{} {} {} {} {}\x01", CTCP_NAIS_ACCEPT, channel_id, fingerprint, ip, port)
}

/// Create CTCP connect message
/// Send P2P connection details
pub fn create_connect_ctcp(channel_id: &str, ip: &str, port: u16) -> String {
    format!("\x01{} {} {} {}\x01", CTCP_NAIS_CONNECT, channel_id, ip, port)
}

/// Create CTCP leave message
pub fn create_leave_ctcp(channel_id: &str) -> String {
    format!("\x01{} {}\x01", CTCP_NAIS_LEAVE, channel_id)
}

// ============================================================================
// CTCP Parsing
// ============================================================================

/// Check if a CTCP command is NAIS-related
pub fn is_nais_ctcp(command: &str) -> bool {
    matches!(command, 
        CTCP_NAIS_PROBE | CTCP_NAIS_INFO | CTCP_NAIS_JOIN | 
        CTCP_NAIS_ACCEPT | CTCP_NAIS_CONNECT | CTCP_NAIS_LEAVE | CTCP_NAIS_MSG |
        CTCP_NAIS_CHANNEL_INVITE
    )
}

/// Parse CTCP args into a vector
pub fn parse_ctcp_args(args: &str) -> Vec<String> {
    args.split_whitespace().map(|s| s.to_string()).collect()
}

// ============================================================================
// NAIS Channel Manager
// ============================================================================

/// Manages NAIS channels and P2P connections
pub struct NaisChannelManager {
    /// Our current nickname
    pub our_nickname: String,
    /// Our fingerprint
    pub our_fingerprint: String,
    /// Our external IP (for P2P)
    pub our_ip: String,
    /// Our listening port
    pub our_port: u16,
    /// Active NAIS channels (by channel_id)
    pub channels: HashMap<String, NaisChannel>,
    /// IRC channel to NAIS channel_id mapping
    pub irc_to_nais: HashMap<String, String>,
    /// Event sender
    event_tx: Sender<NaisEvent>,
    /// Command receiver
    cmd_rx: Receiver<NaisCommand>,
    /// TCP Listener for P2P connections
    listener: Option<TcpListener>,
    /// Active P2P connections
    connections: HashMap<String, TcpStream>,
}

impl NaisChannelManager {
    /// Create a new NAIS channel manager
    pub fn new(
        our_nickname: String,
        event_tx: Sender<NaisEvent>,
        cmd_rx: Receiver<NaisCommand>,
    ) -> Self {
        Self {
            our_nickname,
            our_fingerprint: generate_fingerprint(),
            our_ip: String::new(),
            our_port: 0,
            channels: HashMap::new(),
            irc_to_nais: HashMap::new(),
            event_tx,
            cmd_rx,
            listener: None,
            connections: HashMap::new(),
        }
    }
    
    /// Create a new NAIS channel
    pub async fn create_channel(&mut self, name: Option<String>) -> Result<NaisChannel, String> {
        let channel_id = generate_channel_id();
        let irc_channel = create_nais_irc_channel(&channel_id);
        let topic = create_nais_topic(&channel_id, &self.our_fingerprint);
        
        let channel = NaisChannel {
            channel_id: channel_id.clone(),
            irc_channel: irc_channel.clone(),
            name,
            our_nickname: self.our_nickname.clone(),
            our_fingerprint: self.our_fingerprint.clone(),
            our_ip: self.our_ip.clone(),
            our_port: self.our_port,
            is_host: true,
            peers: HashMap::new(),
            state: NaisChannelState::Creating,
            created_at: Instant::now(),
            pending_probes: Vec::new(),
            messages: Vec::new(),
        };
        
        // Send IRC commands to create the channel
        let _ = self.event_tx.send(NaisEvent::SendIrcCommand {
            command: NaisIrcCommand::Join { channel: irc_channel.clone() },
        }).await;
        
        // Set topic with NAIS identifier
        let _ = self.event_tx.send(NaisEvent::SendIrcCommand {
            command: NaisIrcCommand::Topic { 
                channel: irc_channel.clone(), 
                topic,
            },
        }).await;
        
        // Set channel to moderated (+m) so only we (as op) could speak
        // But we don't want anyone to speak - this is only for discovery
        let _ = self.event_tx.send(NaisEvent::SendIrcCommand {
            command: NaisIrcCommand::Mode { 
                channel: irc_channel.clone(), 
                modes: "+mnt".to_string(), // moderated, no external messages, topic lock
            },
        }).await;
        
        self.channels.insert(channel_id.clone(), channel.clone());
        self.irc_to_nais.insert(irc_channel, channel_id);
        
        Ok(channel)
    }
    
    /// Join an existing NAIS channel (detected via topic)
    pub async fn join_channel(&mut self, irc_channel: &str) -> Result<(), String> {
        // Join the IRC channel first to discover peers
        let _ = self.event_tx.send(NaisEvent::SendIrcCommand {
            command: NaisIrcCommand::Join { channel: irc_channel.to_string() },
        }).await;
        
        Ok(())
    }
    
    /// Process IRC channel topic to potentially initialize NAIS channel
    pub async fn process_topic(&mut self, irc_channel: &str, topic: &str) -> Option<String> {
        if let Some((version, channel_id, creator_fingerprint)) = parse_nais_topic(topic) {
            if version != NAIS_PROTOCOL_VERSION {
                return None;
            }
            
            // Check if we already have this channel
            if self.channels.contains_key(&channel_id) {
                return Some(channel_id);
            }
            
            // Create a new channel entry for this NAIS channel we're joining
            let channel = NaisChannel {
                channel_id: channel_id.clone(),
                irc_channel: irc_channel.to_string(),
                name: None,
                our_nickname: self.our_nickname.clone(),
                our_fingerprint: self.our_fingerprint.clone(),
                our_ip: self.our_ip.clone(),
                our_port: self.our_port,
                is_host: creator_fingerprint == self.our_fingerprint,
                peers: HashMap::new(),
                state: NaisChannelState::Discovering,
                created_at: Instant::now(),
                pending_probes: Vec::new(),
                messages: Vec::new(),
            };
            
            self.channels.insert(channel_id.clone(), channel);
            self.irc_to_nais.insert(irc_channel.to_string(), channel_id.clone());
            
            let _ = self.event_tx.send(NaisEvent::ChannelJoined {
                channel_id: channel_id.clone(),
                irc_channel: irc_channel.to_string(),
            }).await;
            
            Some(channel_id)
        } else {
            None
        }
    }
    
    /// Process users in IRC channel and probe for NAIS clients
    pub async fn probe_users(&mut self, irc_channel: &str, users: &[String]) {
        let Some(channel_id) = self.irc_to_nais.get(irc_channel).cloned() else {
            return;
        };
        
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return;
        };
        
        // Probe each user (except ourselves)
        for user in users {
            // Strip mode prefixes (@, +, etc.)
            let clean_user = user.trim_start_matches(|c| c == '@' || c == '+' || c == '%' || c == '!' || c == '~');
            
            if clean_user == self.our_nickname {
                continue;
            }
            
            // Don't probe users we've already probed
            if channel.pending_probes.contains(&clean_user.to_string()) {
                continue;
            }
            
            // Don't probe users we already have as peers
            if channel.peers.contains_key(clean_user) {
                continue;
            }
            
            channel.pending_probes.push(clean_user.to_string());
            
            // Send probe CTCP
            let probe_msg = create_probe_ctcp(irc_channel);
            let _ = self.event_tx.send(NaisEvent::SendIrcCommand {
                command: NaisIrcCommand::Ctcp {
                    target: clean_user.to_string(),
                    message: probe_msg,
                },
            }).await;
        }
    }
    
    /// Handle incoming NAIS CTCP command
    pub async fn handle_ctcp(&mut self, from: &str, command: &str, args: &[String]) {
        match command {
            CTCP_NAIS_PROBE => {
                // Someone is probing us - respond with our info if we're in that channel
                if let Some(irc_channel) = args.first() {
                    if let Some(channel_id) = self.irc_to_nais.get(irc_channel).cloned() {
                        if self.channels.contains_key(&channel_id) {
                            // Respond with our NAIS info
                            let info_msg = create_info_ctcp(
                                &channel_id,
                                &self.our_fingerprint,
                                &self.our_ip,
                                self.our_port,
                            );
                            let _ = self.event_tx.send(NaisEvent::SendIrcCommand {
                                command: NaisIrcCommand::CtcpResponse {
                                    target: from.to_string(),
                                    message: info_msg,
                                },
                            }).await;
                        }
                    }
                }
            }
            CTCP_NAIS_INFO => {
                // Received info response - add peer
                if args.len() >= 4 {
                    let channel_id = &args[0];
                    let fingerprint = &args[1];
                    let ip = &args[2];
                    let port: u16 = args[3].parse().unwrap_or(0);
                    
                    if let Some(channel) = self.channels.get_mut(channel_id) {
                        // Remove from pending probes
                        channel.pending_probes.retain(|u| u != from);
                        
                        // Add as peer
                        let peer = NaisPeer {
                            nickname: from.to_string(),
                            fingerprint: fingerprint.clone(),
                            ip: ip.clone(),
                            port,
                            joined_at: Instant::now(),
                            connected: false,
                            last_seen: Instant::now(),
                        };
                        
                        channel.peers.insert(from.to_string(), peer.clone());
                        
                        let _ = self.event_tx.send(NaisEvent::PeerJoined {
                            channel_id: channel_id.clone(),
                            peer,
                        }).await;
                        
                        // If we have at least one peer, channel is now active
                        if channel.state == NaisChannelState::Discovering && !channel.peers.is_empty() {
                            channel.state = NaisChannelState::Active;
                            let _ = self.event_tx.send(NaisEvent::StateChanged {
                                channel_id: channel_id.clone(),
                                state: NaisChannelState::Active,
                            }).await;
                        }
                    }
                }
            }
            CTCP_NAIS_JOIN => {
                // Someone wants to join our channel
                if args.len() >= 4 {
                    let channel_id = &args[0];
                    let fingerprint = &args[1];
                    let ip = &args[2];
                    let port: u16 = args[3].parse().unwrap_or(0);
                    
                    if let Some(channel) = self.channels.get_mut(channel_id) {
                        // Add as peer
                        let peer = NaisPeer {
                            nickname: from.to_string(),
                            fingerprint: fingerprint.clone(),
                            ip: ip.clone(),
                            port,
                            joined_at: Instant::now(),
                            connected: false,
                            last_seen: Instant::now(),
                        };
                        
                        channel.peers.insert(from.to_string(), peer.clone());
                        
                        // Send accept response
                        let accept_msg = create_accept_ctcp(
                            channel_id,
                            &self.our_fingerprint,
                            &self.our_ip,
                            self.our_port,
                        );
                        let _ = self.event_tx.send(NaisEvent::SendIrcCommand {
                            command: NaisIrcCommand::CtcpResponse {
                                target: from.to_string(),
                                message: accept_msg,
                            },
                        }).await;
                        
                        let _ = self.event_tx.send(NaisEvent::PeerJoined {
                            channel_id: channel_id.clone(),
                            peer,
                        }).await;
                    }
                }
            }
            CTCP_NAIS_ACCEPT => {
                // Our join request was accepted
                if args.len() >= 4 {
                    let channel_id = &args[0];
                    let fingerprint = &args[1];
                    let ip = &args[2];
                    let port: u16 = args[3].parse().unwrap_or(0);
                    
                    if let Some(channel) = self.channels.get_mut(channel_id) {
                        let peer = NaisPeer {
                            nickname: from.to_string(),
                            fingerprint: fingerprint.clone(),
                            ip: ip.clone(),
                            port,
                            joined_at: Instant::now(),
                            connected: false,
                            last_seen: Instant::now(),
                        };
                        
                        channel.peers.insert(from.to_string(), peer.clone());
                        channel.state = NaisChannelState::Active;
                        
                        let _ = self.event_tx.send(NaisEvent::PeerJoined {
                            channel_id: channel_id.clone(),
                            peer,
                        }).await;
                        
                        let _ = self.event_tx.send(NaisEvent::StateChanged {
                            channel_id: channel_id.clone(),
                            state: NaisChannelState::Active,
                        }).await;
                    }
                }
            }
            CTCP_NAIS_LEAVE => {
                // Peer is leaving
                if let Some(channel_id) = args.first() {
                    if let Some(channel) = self.channels.get_mut(channel_id) {
                        channel.peers.remove(from);
                        let _ = self.event_tx.send(NaisEvent::PeerLeft {
                            channel_id: channel_id.clone(),
                            nickname: from.to_string(),
                        }).await;
                    }
                }
            }
            _ => {}
        }
    }
    
    /// Leave a NAIS channel
    pub async fn leave_channel(&mut self, channel_id: &str) {
        if let Some(channel) = self.channels.remove(channel_id) {
            // Notify peers we're leaving
            for (nickname, _peer) in &channel.peers {
                let leave_msg = create_leave_ctcp(channel_id);
                let _ = self.event_tx.send(NaisEvent::SendIrcCommand {
                    command: NaisIrcCommand::Ctcp {
                        target: nickname.clone(),
                        message: leave_msg,
                    },
                }).await;
            }
            
            // Leave the IRC channel
            let _ = self.event_tx.send(NaisEvent::SendIrcCommand {
                command: NaisIrcCommand::Part {
                    channel: channel.irc_channel.clone(),
                    reason: Some("Leaving NAIS channel".to_string()),
                },
            }).await;
            
            self.irc_to_nais.remove(&channel.irc_channel);
            
            let _ = self.event_tx.send(NaisEvent::ChannelLeft {
                channel_id: channel_id.to_string(),
            }).await;
        }
    }
    
    /// Send a message to a NAIS channel
    pub async fn send_message(&mut self, channel_id: &str, content: &str) -> Result<String, String> {
        let Some(channel) = self.channels.get_mut(channel_id) else {
            return Err("Channel not found".to_string());
        };
        
        let message = NaisMessage {
            id: generate_message_id(),
            channel_id: channel_id.to_string(),
            sender: self.our_nickname.clone(),
            content: content.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            is_system: false,
        };
        
        // Add to our local messages
        channel.messages.push(message.clone());
        
        // In a full implementation, this would:
        // 1. Encrypt the message with each peer's public key
        // 2. Send via P2P connection to each peer
        // For now, we'll use a simplified approach
        
        // Notify UI that message was sent
        let _ = self.event_tx.send(NaisEvent::MessageSent {
            channel_id: channel_id.to_string(),
            message_id: message.id.clone(),
        }).await;
        
        Ok(message.id)
    }
    
    /// Add a system message to a channel
    pub async fn add_system_message(&mut self, channel_id: &str, content: &str) {
        let Some(channel) = self.channels.get_mut(channel_id) else {
            return;
        };
        
        let message = NaisMessage {
            id: generate_message_id(),
            channel_id: channel_id.to_string(),
            sender: "system".to_string(),
            content: content.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            is_system: true,
        };
        
        channel.messages.push(message.clone());
        
        let _ = self.event_tx.send(NaisEvent::MessageReceived {
            channel_id: channel_id.to_string(),
            message,
        }).await;
    }
    
    /// Get channel by ID
    pub fn get_channel(&self, channel_id: &str) -> Option<&NaisChannel> {
        self.channels.get(channel_id)
    }
    
    /// Get channel by IRC channel name
    pub fn get_channel_by_irc(&self, irc_channel: &str) -> Option<&NaisChannel> {
        self.irc_to_nais.get(irc_channel)
            .and_then(|id| self.channels.get(id))
    }
    
    /// Check if an IRC channel is a NAIS channel
    pub fn is_nais_channel(&self, irc_channel: &str) -> bool {
        self.irc_to_nais.contains_key(irc_channel)
    }
    
    /// Set our external IP
    pub fn set_our_ip(&mut self, ip: String) {
        self.our_ip = ip;
    }
    
    /// Set our listening port
    pub fn set_our_port(&mut self, port: u16) {
        self.our_port = port;
    }
    
    /// Update our nickname
    pub fn set_our_nickname(&mut self, nickname: String) {
        self.our_nickname = nickname;
    }
}

// ============================================================================
// P2P Message Protocol
// ============================================================================

/// P2P message types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2PMessageType {
    /// Chat message
    Chat { content: String },
    /// Ping for keepalive
    Ping { timestamp: i64 },
    /// Pong response
    Pong { timestamp: i64 },
    /// Peer list update
    PeerList { peers: Vec<(String, String, u16)> }, // (nickname, ip, port)
    /// Goodbye - disconnecting
    Goodbye,
}

/// P2P message envelope
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2PMessage {
    /// Message type
    pub msg_type: P2PMessageType,
    /// Sender's nickname
    pub sender: String,
    /// Channel ID
    pub channel_id: String,
    /// Timestamp
    pub timestamp: i64,
    /// Message sequence number
    pub sequence: u64,
}

impl P2PMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }
}

// ============================================================================
// Encryption helpers (placeholder - would use real crypto in production)
// ============================================================================

/// Simple XOR encryption for demonstration (NOT SECURE - use real crypto!)
pub fn simple_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

/// Simple XOR decryption
pub fn simple_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    simple_encrypt(data, key) // XOR is symmetric
}

// ============================================================================
// Utility functions for UI integration
// ============================================================================

/// Check if a string looks like a NAIS IRC channel name
pub fn looks_like_nais_channel(name: &str) -> bool {
    name.starts_with("#nais-")
}

/// Format peer count for display
pub fn format_peer_count(count: usize) -> String {
    match count {
        0 => "No peers".to_string(),
        1 => "1 peer".to_string(),
        n => format!("{} peers", n),
    }
}

/// Get channel state as string
pub fn state_to_string(state: &NaisChannelState) -> &'static str {
    match state {
        NaisChannelState::Creating => "Creating",
        NaisChannelState::Active => "Active",
        NaisChannelState::Discovering => "Discovering",
        NaisChannelState::Connecting => "Connecting",
        NaisChannelState::Closed => "Closed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nais_topic_parsing() {
        let topic = "NAIS:v1:abc123def:fingerprint456";
        let parsed = parse_nais_topic(topic);
        assert!(parsed.is_some());
        let (version, channel_id, fingerprint) = parsed.unwrap();
        assert_eq!(version, "v1");
        assert_eq!(channel_id, "abc123def");
        assert_eq!(fingerprint, "fingerprint456");
    }
    
    #[test]
    fn test_is_nais_topic() {
        assert!(is_nais_topic("NAIS:v1:abc:def"));
        assert!(!is_nais_topic("Regular channel topic"));
        assert!(!is_nais_topic(""));
    }
    
    #[test]
    fn test_create_nais_topic() {
        let topic = create_nais_topic("abc123", "fp456");
        assert_eq!(topic, "NAIS:v1:abc123:fp456");
    }
    
    #[test]
    fn test_irc_channel_name() {
        let name = create_nais_irc_channel("abc123def456");
        assert_eq!(name, "#nais-abc123de");
    }
}
