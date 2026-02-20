//! Peer-to-peer voice chat module with CTCP negotiation and socket-based audio streaming.
#![allow(dead_code)]

use async_channel::{Receiver, Sender};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use std::time::Duration;

// Re-export opus codec types
pub use opus::{Encoder as OpusEncoder, Decoder as OpusDecoder, Channels, Application};

/// Network statistics for voice chat
#[derive(Clone, Debug, Default)]
pub struct VoiceNetworkStats {
    /// Total bytes transmitted
    pub bytes_tx: u64,
    /// Total bytes received
    pub bytes_rx: u64,
    /// Packets transmitted
    pub packets_tx: u64,
    /// Packets received
    pub packets_rx: u64,
    /// Packets lost (detected via sequence gaps)
    pub packets_lost: u64,
    /// Current bitrate in bits per second (transmit)
    pub bitrate_tx: u32,
    /// Current bitrate in bits per second (receive)
    pub bitrate_rx: u32,
    /// Round-trip time in milliseconds (if measured)
    pub rtt_ms: Option<u32>,
    /// Jitter in milliseconds
    pub jitter_ms: u32,
    /// Last sequence number received
    pub last_seq_rx: u32,
    /// Last sequence number sent
    pub last_seq_tx: u32,
    /// Timestamp of last stats update
    #[allow(dead_code)]
    last_update: Option<std::time::Instant>,
    /// Timestamp for TX bitrate
    last_tx_update: Option<std::time::Instant>,
    /// Timestamp for RX bitrate
    last_rx_update: Option<std::time::Instant>,
}

impl VoiceNetworkStats {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Record a packet being transmitted
    pub fn record_tx(&mut self, bytes: usize, seq: u32) {
        self.bytes_tx += bytes as u64;
        self.packets_tx += 1;
        self.last_seq_tx = seq;
        self.update_bitrate_tx(bytes);
    }
    
    /// Record a packet being received
    pub fn record_rx(&mut self, bytes: usize, seq: u32) {
        self.bytes_rx += bytes as u64;
        self.packets_rx += 1;
        
        // Check for packet loss (gaps in sequence numbers)
        if self.last_seq_rx > 0 && seq > self.last_seq_rx + 1 {
            self.packets_lost += (seq - self.last_seq_rx - 1) as u64;
        }
        self.last_seq_rx = seq;
        self.update_bitrate_rx(bytes);
    }
    
    fn update_bitrate_tx(&mut self, bytes: usize) {
        let now = std::time::Instant::now();
        if let Some(last) = self.last_tx_update {
            let elapsed = now.duration_since(last).as_secs_f32();
            if elapsed > 0.0 {
                // Exponential moving average
                let instant_bitrate = (bytes as f32 * 8.0 / elapsed) as u32;
                self.bitrate_tx = ((self.bitrate_tx as f32 * 0.9) + (instant_bitrate as f32 * 0.1)) as u32;
            }
        }
        self.last_tx_update = Some(now);
    }
    
    fn update_bitrate_rx(&mut self, bytes: usize) {
        let now = std::time::Instant::now();
        if let Some(last) = self.last_rx_update {
            let elapsed = now.duration_since(last).as_secs_f32();
            if elapsed > 0.0 {
                let instant_bitrate = (bytes as f32 * 8.0 / elapsed) as u32;
                self.bitrate_rx = ((self.bitrate_rx as f32 * 0.9) + (instant_bitrate as f32 * 0.1)) as u32;
            }
        }
        self.last_rx_update = Some(now);
    }
    
    /// Format bytes as human-readable string
    pub fn format_bytes(bytes: u64) -> String {
        if bytes >= 1_000_000 {
            format!("{:.1} MB", bytes as f64 / 1_000_000.0)
        } else if bytes >= 1_000 {
            format!("{:.1} KB", bytes as f64 / 1_000.0)
        } else {
            format!("{} B", bytes)
        }
    }
    
    /// Format bitrate as human-readable string
    pub fn format_bitrate(bps: u32) -> String {
        if bps >= 1_000_000 {
            format!("{:.1} Mbps", bps as f64 / 1_000_000.0)
        } else if bps >= 1_000 {
            format!("{:.1} kbps", bps as f64 / 1_000.0)
        } else {
            format!("{} bps", bps)
        }
    }
    
    /// Get packet loss percentage
    pub fn packet_loss_percent(&self) -> f32 {
        if self.packets_rx + self.packets_lost == 0 {
            0.0
        } else {
            (self.packets_lost as f32 / (self.packets_rx + self.packets_lost) as f32) * 100.0
        }
    }
}

/// Voice chat connection state
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceState {
    /// No active voice call
    Idle,
    /// Waiting for peer to accept our call request
    Outgoing { peer: String },
    /// Incoming call waiting for user decision
    Incoming { peer: String, ip: String, port: u16 },
    /// Call is being connected
    Connecting { peer: String },
    /// Voice call is active
    Active { peer: String },
    /// Call ended
    Ended,
}

/// Voice chat protocol commands (sent over TCP control channel)
#[derive(Clone, Debug)]
pub enum VoiceCommand {
    /// Initiate a voice call
    CallRequest { session_id: String },
    /// Accept a voice call
    CallAccept { session_id: String },
    /// Reject a voice call
    CallReject { reason: String },
    /// End the current call
    Hangup,
    /// Ping for keepalive
    Ping,
    /// Pong response
    Pong,
    /// Audio data frame
    AudioFrame { sequence: u32, data: Vec<u8> },
    /// Mute status changed
    MuteStatus { muted: bool },
}

/// Events emitted by the voice chat system
#[derive(Clone, Debug)]
pub enum VoiceEvent {
    /// Incoming call request via CTCP
    IncomingCall { from: String, ip: String, port: u16, session_id: String },
    /// Call was accepted by peer
    CallAccepted { peer: String },
    /// Call was rejected by peer
    CallRejected { peer: String, reason: String },
    /// Call connected and audio streaming
    CallConnected { peer: String },
    /// Call ended
    CallEnded { peer: String, reason: String },
    /// Error occurred
    Error { message: String },
    /// State changed
    StateChanged { state: VoiceState },
    /// Audio level for visualization
    AudioLevel { is_local: bool, level: f32 },
    /// Peer mute status changed
    PeerMuteChanged { muted: bool },
    /// Network stats update
    NetworkStats { stats: VoiceNetworkStats },
    /// Output audio level (what we're receiving and playing)
    OutputLevel { level: f32 },
}

/// CTCP commands for voice chat negotiation
pub const CTCP_VOICE_CALL: &str = "VOICE_CALL";
pub const CTCP_VOICE_ACCEPT: &str = "VOICE_ACCEPT";
pub const CTCP_VOICE_REJECT: &str = "VOICE_REJECT";
pub const CTCP_VOICE_CANCEL: &str = "VOICE_CANCEL";

/// Voice chat configuration
#[derive(Clone, Debug)]
pub struct VoiceConfig {
    /// Local port for incoming connections (0 = auto-assign)
    pub listen_port: u16,
    /// Opus encoder bitrate
    pub bitrate: i32,
    /// Audio sample rate
    pub sample_rate: u32,
    /// Audio frame size in samples
    pub frame_size: usize,
    /// Number of audio channels
    pub channels: u16,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        Self {
            listen_port: 0,
            bitrate: 24000,
            sample_rate: 48000,
            frame_size: 960, // 20ms at 48kHz
            channels: 1,
        }
    }
}

/// Voice chat session state
pub struct VoiceSession {
    pub session_id: String,
    pub peer: String,
    pub state: VoiceState,
    pub local_muted: bool,
    pub peer_muted: bool,
    control_stream: Option<TcpStream>,
    audio_sequence: u32,
}

impl VoiceSession {
    pub fn new(session_id: String, peer: String) -> Self {
        Self {
            session_id,
            peer,
            state: VoiceState::Idle,
            local_muted: false,
            peer_muted: false,
            control_stream: None,
            audio_sequence: 0,
        }
    }
}

/// Active voice chat sessions manager
pub struct VoiceChatManager {
    pub config: VoiceConfig,
    pub state: VoiceState,
    current_session: Option<VoiceSession>,
    listener_addr: Option<SocketAddr>,
    event_tx: Option<Sender<VoiceEvent>>,
    local_muted: bool,
    audio_active: Arc<Mutex<bool>>,
}

impl VoiceChatManager {
    pub fn new(config: VoiceConfig) -> Self {
        Self {
            config,
            state: VoiceState::Idle,
            current_session: None,
            listener_addr: None,
            event_tx: None,
            local_muted: false,
            audio_active: Arc::new(Mutex::new(false)),
        }
    }

    /// Generate a unique session ID
    pub fn generate_session_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("VC{:x}", timestamp)
    }

    /// Get current voice state
    pub fn get_state(&self) -> VoiceState {
        self.state.clone()
    }

    /// Check if voice chat is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, VoiceState::Active { .. })
    }

    /// Check if there's an incoming call
    pub fn has_incoming_call(&self) -> bool {
        matches!(self.state, VoiceState::Incoming { .. })
    }

    /// Check if there's an outgoing call
    pub fn has_outgoing_call(&self) -> bool {
        matches!(self.state, VoiceState::Outgoing { .. })
    }

    /// Get peer nickname if in a call
    pub fn get_peer(&self) -> Option<String> {
        match &self.state {
            VoiceState::Active { peer } |
            VoiceState::Incoming { peer, .. } |
            VoiceState::Outgoing { peer } |
            VoiceState::Connecting { peer } => Some(peer.clone()),
            _ => None,
        }
    }

    /// Set local mute state
    pub fn set_muted(&mut self, muted: bool) {
        self.local_muted = muted;
    }

    /// Get local mute state
    pub fn is_muted(&self) -> bool {
        self.local_muted
    }
}

/// Create CTCP message for voice call request
/// Returns: (CTCP command string, IP, port) to be sent via IRC PRIVMSG
pub fn create_voice_call_ctcp(ip: &str, port: u16, session_id: &str) -> String {
    format!("\x01{} {} {} {}\x01", CTCP_VOICE_CALL, ip, port, session_id)
}

/// Create CTCP message for accepting a voice call
pub fn create_voice_accept_ctcp(ip: &str, port: u16, session_id: &str) -> String {
    format!("\x01{} {} {} {}\x01", CTCP_VOICE_ACCEPT, ip, port, session_id)
}

/// Create CTCP message for rejecting a voice call
pub fn create_voice_reject_ctcp(session_id: &str, reason: &str) -> String {
    format!("\x01{} {} {}\x01", CTCP_VOICE_REJECT, session_id, reason)
}

/// Create CTCP message for canceling a voice call
pub fn create_voice_cancel_ctcp(session_id: &str) -> String {
    format!("\x01{} {}\x01", CTCP_VOICE_CANCEL, session_id)
}

/// Parse CTCP voice message
/// Returns: (command, args) if valid voice CTCP
pub fn parse_voice_ctcp(text: &str) -> Option<(String, Vec<String>)> {
    if !text.starts_with('\x01') || !text.ends_with('\x01') {
        return None;
    }
    
    let content = &text[1..text.len()-1];
    let parts: Vec<&str> = content.splitn(2, ' ').collect();
    
    let command = parts[0].to_string();
    if !command.starts_with("VOICE_") {
        return None;
    }
    
    let args = if parts.len() > 1 {
        parts[1].split_whitespace().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    };
    
    Some((command, args))
}

/// Voice protocol message serialization
impl VoiceCommand {
    /// Serialize command to bytes for network transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VoiceCommand::CallRequest { session_id } => {
                let mut buf = vec![0x01]; // Command type
                buf.extend_from_slice(session_id.as_bytes());
                buf
            }
            VoiceCommand::CallAccept { session_id } => {
                let mut buf = vec![0x02];
                buf.extend_from_slice(session_id.as_bytes());
                buf
            }
            VoiceCommand::CallReject { reason } => {
                let mut buf = vec![0x03];
                buf.extend_from_slice(reason.as_bytes());
                buf
            }
            VoiceCommand::Hangup => vec![0x04],
            VoiceCommand::Ping => vec![0x05],
            VoiceCommand::Pong => vec![0x06],
            VoiceCommand::AudioFrame { sequence, data } => {
                let mut buf = vec![0x10]; // Audio frame type
                buf.extend_from_slice(&sequence.to_be_bytes());
                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(data);
                buf
            }
            VoiceCommand::MuteStatus { muted } => {
                vec![0x07, if *muted { 1 } else { 0 }]
            }
        }
    }

    /// Deserialize command from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        
        match data[0] {
            0x01 => {
                let session_id = String::from_utf8_lossy(&data[1..]).to_string();
                Some(VoiceCommand::CallRequest { session_id })
            }
            0x02 => {
                let session_id = String::from_utf8_lossy(&data[1..]).to_string();
                Some(VoiceCommand::CallAccept { session_id })
            }
            0x03 => {
                let reason = String::from_utf8_lossy(&data[1..]).to_string();
                Some(VoiceCommand::CallReject { reason })
            }
            0x04 => Some(VoiceCommand::Hangup),
            0x05 => Some(VoiceCommand::Ping),
            0x06 => Some(VoiceCommand::Pong),
            0x07 if data.len() >= 2 => {
                Some(VoiceCommand::MuteStatus { muted: data[1] != 0 })
            }
            0x10 if data.len() >= 7 => {
                let sequence = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let len = u16::from_be_bytes([data[5], data[6]]) as usize;
                if data.len() >= 7 + len {
                    let audio_data = data[7..7+len].to_vec();
                    Some(VoiceCommand::AudioFrame { sequence, data: audio_data })
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Voice chat handle for UI interaction
#[derive(Clone)]
pub struct VoiceChatHandle {
    pub cmd_tx: Sender<VoiceChatCommand>,
    pub evt_rx: Receiver<VoiceEvent>,
}

/// Commands that can be sent to the voice chat system
#[derive(Clone, Debug)]
pub enum VoiceChatCommand {
    /// Start a voice call with a user
    Call { nickname: String },
    /// Accept an incoming call
    Accept,
    /// Reject an incoming call
    Reject { reason: String },
    /// Hang up current call
    Hangup,
    /// Cancel outgoing call
    Cancel,
    /// Toggle mute
    ToggleMute,
    /// Set mute state
    SetMute { muted: bool },
    /// Shutdown voice chat system
    Shutdown,
}

/// Voice chat core that manages the P2P connection
pub struct VoiceChatCore {
    config: VoiceConfig,
    state: Arc<Mutex<VoiceState>>,
    cmd_rx: Receiver<VoiceChatCommand>,
    evt_tx: Sender<VoiceEvent>,
    // IRC integration: send CTCP messages through this
    irc_ctcp_tx: Option<Sender<(String, String)>>, // (target, ctcp_message)
    current_session_id: Arc<Mutex<Option<String>>>,
    pending_calls: Arc<Mutex<HashMap<String, PendingCall>>>,
    local_muted: Arc<Mutex<bool>>,
    audio_running: Arc<Mutex<bool>>,
}

/// Pending call information
#[derive(Clone, Debug)]
pub struct PendingCall {
    pub session_id: String,
    pub peer: String,
    pub peer_ip: String,
    pub peer_port: u16,
    pub is_incoming: bool,
}

impl VoiceChatCore {
    pub fn new(
        config: VoiceConfig,
        cmd_rx: Receiver<VoiceChatCommand>,
        evt_tx: Sender<VoiceEvent>,
    ) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(VoiceState::Idle)),
            cmd_rx,
            evt_tx,
            irc_ctcp_tx: None,
            current_session_id: Arc::new(Mutex::new(None)),
            pending_calls: Arc::new(Mutex::new(HashMap::new())),
            local_muted: Arc::new(Mutex::new(false)),
            audio_running: Arc::new(Mutex::new(false)),
        }
    }

    /// Set IRC CTCP sender for sending voice CTCP messages
    pub fn set_irc_ctcp_sender(&mut self, tx: Sender<(String, String)>) {
        self.irc_ctcp_tx = Some(tx);
    }

    /// Handle incoming CTCP voice message from IRC
    pub async fn handle_ctcp_message(&self, from: &str, command: &str, args: &[String]) {
        match command {
            CTCP_VOICE_CALL => {
                // Format: VOICE_CALL <ip> <port> <session_id>
                if args.len() >= 3 {
                    let ip = args[0].clone();
                    let port = args[1].parse::<u16>().unwrap_or(0);
                    let session_id = args[2].clone();
                    
                    if port > 0 {
                        // Store pending call
                        let call = PendingCall {
                            session_id: session_id.clone(),
                            peer: from.to_string(),
                            peer_ip: ip.clone(),
                            peer_port: port,
                            is_incoming: true,
                        };
                        
                        if let Ok(mut pending) = self.pending_calls.lock() {
                            pending.insert(session_id.clone(), call);
                        }
                        
                        // Update state
                        if let Ok(mut state) = self.state.lock() {
                            *state = VoiceState::Incoming {
                                peer: from.to_string(),
                                ip: ip.clone(),
                                port,
                            };
                        }
                        
                        // Notify UI
                        let _ = self.evt_tx.send(VoiceEvent::IncomingCall {
                            from: from.to_string(),
                            ip,
                            port,
                            session_id,
                        }).await;
                    }
                }
            }
            CTCP_VOICE_ACCEPT => {
                // Format: VOICE_ACCEPT <ip> <port> <session_id>
                if args.len() >= 3 {
                    let _ip = args[0].clone();
                    let _port = args[1].parse::<u16>().unwrap_or(0);
                    let session_id = args[2].clone();
                    
                    // Check if this is a response to our call
                    if let Ok(current_id) = self.current_session_id.lock() {
                        if current_id.as_ref() == Some(&session_id) {
                            // Our call was accepted, connect to peer
                            let _ = self.evt_tx.send(VoiceEvent::CallAccepted {
                                peer: from.to_string(),
                            }).await;
                            
                            // Update state to connecting then active
                            if let Ok(mut state) = self.state.lock() {
                                *state = VoiceState::Active {
                                    peer: from.to_string(),
                                };
                            }
                            
                            let _ = self.evt_tx.send(VoiceEvent::CallConnected {
                                peer: from.to_string(),
                            }).await;
                        }
                    }
                }
            }
            CTCP_VOICE_REJECT => {
                // Format: VOICE_REJECT <session_id> <reason>
                if !args.is_empty() {
                    let _session_id = args[0].clone();
                    let reason = if args.len() > 1 {
                        args[1..].join(" ")
                    } else {
                        "Rejected".to_string()
                    };
                    
                    // Clear call state
                    if let Ok(mut state) = self.state.lock() {
                        *state = VoiceState::Idle;
                    }
                    
                    let _ = self.evt_tx.send(VoiceEvent::CallRejected {
                        peer: from.to_string(),
                        reason,
                    }).await;
                }
            }
            CTCP_VOICE_CANCEL => {
                // Format: VOICE_CANCEL <session_id>
                if !args.is_empty() {
                    let session_id = args[0].clone();
                    
                    // Remove from pending
                    if let Ok(mut pending) = self.pending_calls.lock() {
                        pending.remove(&session_id);
                    }
                    
                    // Clear state if this was an incoming call
                    if let Ok(mut state) = self.state.lock() {
                        if matches!(*state, VoiceState::Incoming { .. }) {
                            *state = VoiceState::Idle;
                        }
                    }
                    
                    let _ = self.evt_tx.send(VoiceEvent::CallEnded {
                        peer: from.to_string(),
                        reason: "Call cancelled".to_string(),
                    }).await;
                }
            }
            _ => {}
        }
    }
}

/// Start the voice chat system and return a handle for interaction
pub fn start_voice_chat(config: VoiceConfig) -> VoiceChatHandle {
    let (cmd_tx, cmd_rx) = async_channel::unbounded();
    let (evt_tx, evt_rx) = async_channel::unbounded();
    
    // Spawn voice chat task
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime for voice chat");
        runtime.block_on(async move {
            let core = VoiceChatCore::new(config, cmd_rx, evt_tx.clone());
            let _ = voice_chat_loop(core).await;
        });
    });
    
    VoiceChatHandle { cmd_tx, evt_rx }
}

/// Initiate an outgoing voice connection to a peer
/// Returns a channel receiver for VoiceEvents
pub fn connect_voice_call(
    peer_ip: &str, 
    peer_port: u16, 
    config: VoiceConfig,
    muted: Arc<Mutex<bool>>,
) -> Option<async_channel::Receiver<VoiceEvent>> {
    let peer_addr = format!("{}:{}", peer_ip, peer_port);
    let (evt_tx, evt_rx) = async_channel::unbounded();
    
    let peer_addr_clone = peer_addr.clone();
    let config_clone = config.clone();
    let evt_tx_clone = evt_tx.clone();
    let muted_clone = muted.clone();
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("voice connect runtime");
        rt.block_on(async move {
            log::info!("Initiating voice connection to {}", peer_addr_clone);
            
            match TcpStream::connect(&peer_addr_clone).await {
                Ok(stream) => {
                    log::info!("Voice connection established to {}", peer_addr_clone);
                    let addr = stream.peer_addr().unwrap_or_else(|_| {
                        peer_addr_clone.parse().unwrap()
                    });
                    let _ = handle_voice_connection(
                        stream,
                        addr,
                        evt_tx_clone,
                        Arc::new(Mutex::new(VoiceState::Active { peer: "remote".to_string() })),
                        muted_clone,
                        config_clone,
                    ).await;
                }
                Err(e) => {
                    log::error!("Failed to connect voice to {}: {}", peer_addr_clone, e);
                    let _ = evt_tx_clone.send(VoiceEvent::Error {
                        message: format!("Connection failed: {}", e),
                    }).await;
                }
            }
        });
    });
    
    Some(evt_rx)
}

/// Start listening for incoming voice connections (used when initiating a call)
/// Returns (listener port, event receiver)
pub fn start_voice_listener(
    config: VoiceConfig,
    muted: Arc<Mutex<bool>>,
) -> Option<(u16, async_channel::Receiver<VoiceEvent>)> {
    let (evt_tx, evt_rx) = async_channel::unbounded();
    
    let config_clone = config.clone();
    let evt_tx_clone = evt_tx.clone();
    let muted_clone = muted.clone();
    
    // Create a channel to receive the bound port
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("voice listener runtime");
        rt.block_on(async move {
            // Bind to any available port
            match TcpListener::bind("0.0.0.0:0").await {
                Ok(listener) => {
                    let local_addr = listener.local_addr().unwrap();
                    let port = local_addr.port();
                    log::info!("Voice listener started on port {}", port);
                    
                    // Send the port back
                    let _ = port_tx.send(port);
                    
                    // Wait for one incoming connection
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            log::info!("Voice connection from {}", addr);
                            let _ = handle_voice_connection(
                                stream,
                                addr,
                                evt_tx_clone,
                                Arc::new(Mutex::new(VoiceState::Active { peer: addr.to_string() })),
                                muted_clone,
                                config_clone,
                            ).await;
                        }
                        Err(e) => {
                            log::error!("Voice accept error: {}", e);
                            let _ = evt_tx_clone.send(VoiceEvent::Error {
                                message: format!("Accept failed: {}", e),
                            }).await;
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to bind voice listener: {}", e);
                    let _ = port_tx.send(0);
                }
            }
        });
    });
    
    // Wait for the port
    match port_rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(port) if port > 0 => Some((port, evt_rx)),
        _ => None,
    }
}

/// Main voice chat event loop
async fn voice_chat_loop(core: VoiceChatCore) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Start TCP listener for incoming voice connections
    let listener = TcpListener::bind(format!("0.0.0.0:{}", core.config.listen_port)).await?;
    let local_addr = listener.local_addr()?;
    
    log::info!("Voice chat listening on {}", local_addr);
    
    loop {
        tokio::select! {
            // Handle incoming commands
            cmd = core.cmd_rx.recv() => {
                let Some(cmd) = cmd.ok() else { break; };
                match cmd {
                    VoiceChatCommand::Shutdown => {
                        break;
                    }
                    VoiceChatCommand::ToggleMute => {
                        if let Ok(mut muted) = core.local_muted.lock() {
                            *muted = !*muted;
                        }
                    }
                    VoiceChatCommand::SetMute { muted } => {
                        if let Ok(mut m) = core.local_muted.lock() {
                            *m = muted;
                        }
                    }
                    VoiceChatCommand::Hangup | VoiceChatCommand::Cancel => {
                        // End any active call
                        if let Ok(mut state) = core.state.lock() {
                            let peer = match &*state {
                                VoiceState::Active { peer } |
                                VoiceState::Outgoing { peer } |
                                VoiceState::Connecting { peer } => Some(peer.clone()),
                                _ => None,
                            };
                            
                            *state = VoiceState::Idle;
                            
                            if let Some(peer) = peer {
                                let _ = core.evt_tx.send(VoiceEvent::CallEnded {
                                    peer,
                                    reason: "Call ended".to_string(),
                                }).await;
                            }
                        }
                    }
                    VoiceChatCommand::Reject { reason } => {
                        if let Ok(mut state) = core.state.lock() {
                            if let VoiceState::Incoming { peer, .. } = &*state {
                                let _ = core.evt_tx.send(VoiceEvent::CallEnded {
                                    peer: peer.clone(),
                                    reason: reason.clone(),
                                }).await;
                            }
                            *state = VoiceState::Idle;
                        }
                    }
                    VoiceChatCommand::Accept => {
                        // Accept incoming call and start audio
                        if let Ok(mut state) = core.state.lock() {
                            if let VoiceState::Incoming { peer, .. } = state.clone() {
                                *state = VoiceState::Active { peer: peer.clone() };
                                let _ = core.evt_tx.send(VoiceEvent::CallConnected {
                                    peer,
                                }).await;
                            }
                        }
                    }
                    VoiceChatCommand::Call { nickname } => {
                        // Initiate outgoing call
                        if let Ok(mut state) = core.state.lock() {
                            if *state == VoiceState::Idle {
                                *state = VoiceState::Outgoing { peer: nickname.clone() };
                                let _ = core.evt_tx.send(VoiceEvent::StateChanged {
                                    state: VoiceState::Outgoing { peer: nickname },
                                }).await;
                            }
                        }
                    }
                }
            }
            
            // Handle incoming TCP connections
            accept_result = listener.accept() => {
                if let Ok((stream, addr)) = accept_result {
                    log::info!("Voice connection from {}", addr);
                    // Handle the connection in a separate thread with its own runtime
                    // This is needed because the audio stream (cpal) isn't Send
                    let evt_tx = core.evt_tx.clone();
                    let state = core.state.clone();
                    let muted = core.local_muted.clone();
                    let config = core.config.clone();
                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().expect("voice connection runtime");
                        rt.block_on(async move {
                            let _ = handle_voice_connection(stream, addr, evt_tx, state, muted, config).await;
                        });
                    });
                }
            }
        }
    }
    
    Ok(())
}

/// Handle an established voice connection
async fn handle_voice_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    evt_tx: Sender<VoiceEvent>,
    _state: Arc<Mutex<VoiceState>>,
    muted: Arc<Mutex<bool>>,
    config: VoiceConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = [0u8; 4096];
    
    // Create audio stream
    let mut audio_stream = VoiceAudioStream::new(&config);
    
    // Start audio capture and playback
    let frame_rx = audio_stream.start(
        &config,
        None, // Default input device
        None, // Default output device
        evt_tx.clone(),
        muted.clone(),
    );
    
    if frame_rx.is_none() {
        log::error!("Failed to start audio stream");
        let _ = evt_tx.send(VoiceEvent::Error {
            message: "Failed to start audio".to_string(),
        }).await;
        return Ok(());
    }
    
    let frame_rx = frame_rx.unwrap();
    let mut stats_timer = tokio::time::interval(std::time::Duration::from_secs(1));
    
    log::info!("Voice audio stream started for connection from {}", addr);
    
    loop {
        tokio::select! {
            // Send encoded audio frames
            frame = frame_rx.recv() => {
                if let Ok((seq, data)) = frame {
                    let cmd = VoiceCommand::AudioFrame { sequence: seq, data };
                    if let Err(e) = stream.write_all(&cmd.to_bytes()).await {
                        log::error!("Failed to send audio frame: {}", e);
                        break;
                    }
                }
            }
            
            // Receive data from peer
            result = stream.read(&mut buf) => {
                let n = match result {
                    Ok(n) => n,
                    Err(e) => {
                        log::error!("Read error: {}", e);
                        break;
                    }
                };
                
                if n == 0 {
                    // Connection closed
                    log::info!("Voice connection closed by peer");
                    break;
                }
                
                if let Some(cmd) = VoiceCommand::from_bytes(&buf[..n]) {
                    match cmd {
                        VoiceCommand::AudioFrame { sequence, data } => {
                            // Decode and play audio
                            audio_stream.receive_frame(sequence, &data);
                        }
                        VoiceCommand::Hangup => {
                            let _ = evt_tx.send(VoiceEvent::CallEnded {
                                peer: addr.to_string(),
                                reason: "Peer hung up".to_string(),
                            }).await;
                            break;
                        }
                        VoiceCommand::Ping => {
                            let _ = stream.write_all(&VoiceCommand::Pong.to_bytes()).await;
                        }
                        VoiceCommand::MuteStatus { muted } => {
                            let _ = evt_tx.send(VoiceEvent::PeerMuteChanged { muted }).await;
                        }
                        _ => {}
                    }
                }
            }
            
            // Periodic stats update
            _ = stats_timer.tick() => {
                let stats = audio_stream.get_stats();
                let _ = evt_tx.send(VoiceEvent::NetworkStats { stats: stats.clone() }).await;
                
                // Also send input level
                let input_level = audio_stream.get_input_level();
                let _ = evt_tx.send(VoiceEvent::AudioLevel { is_local: true, level: input_level }).await;
                
                // And output level
                let output_level = audio_stream.get_output_level();
                let _ = evt_tx.send(VoiceEvent::OutputLevel { level: output_level }).await;
            }
        }
    }
    
    // Cleanup
    audio_stream.stop();
    log::info!("Voice connection ended");
    
    Ok(())
}

/// Audio capture and encoding task
pub struct AudioCapture {
    pub sample_rate: u32,
    pub channels: u16,
    pub frame_size: usize,
}

impl AudioCapture {
    pub fn new(config: &VoiceConfig) -> Self {
        Self {
            sample_rate: config.sample_rate,
            channels: config.channels,
            frame_size: config.frame_size,
        }
    }
    
    /// Initialize Opus encoder
    pub fn create_encoder(&self) -> Result<OpusEncoder, opus::Error> {
        let channels = if self.channels == 1 {
            Channels::Mono
        } else {
            Channels::Stereo
        };
        
        OpusEncoder::new(self.sample_rate, channels, Application::Voip)
    }
    
    /// Initialize Opus decoder
    pub fn create_decoder(&self) -> Result<OpusDecoder, opus::Error> {
        let channels = if self.channels == 1 {
            Channels::Mono
        } else {
            Channels::Stereo
        };
        
        OpusDecoder::new(self.sample_rate, channels)
    }
}

/// Audio playback system using ring buffer for received audio
pub struct AudioPlayback {
    /// Ring buffer for audio samples
    buffer: Arc<Mutex<std::collections::VecDeque<f32>>>,
    /// Stop flag
    stop_flag: Arc<Mutex<bool>>,
    /// Output level for monitoring
    output_level: Arc<Mutex<f32>>,
    /// Output stream handle (kept alive)
    _stream: Option<cpal::Stream>,
}

impl AudioPlayback {
    /// Start audio playback on the specified device (or default)
    pub fn start(device_name: Option<&str>, sample_rate: u32, channels: u16) -> Option<Self> {
        use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
        
        let host = cpal::default_host();
        let device = if let Some(name) = device_name {
            host.output_devices().ok()?.find(|d| d.name().ok().as_deref() == Some(name))?
        } else {
            host.default_output_device()?
        };
        
        // Create buffer with some capacity (100ms at given sample rate)
        let buffer_capacity = (sample_rate as usize * channels as usize) / 10;
        let buffer = Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(buffer_capacity)));
        let stop_flag = Arc::new(Mutex::new(false));
        let output_level = Arc::new(Mutex::new(0.0f32));
        
        let buffer_clone = buffer.clone();
        let stop_clone = stop_flag.clone();
        let level_clone = output_level.clone();
        
        let config = cpal::StreamConfig {
            channels,
            sample_rate: cpal::SampleRate(sample_rate),
            buffer_size: cpal::BufferSize::Default,
        };
        
        let stream = device.build_output_stream(
            &config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                if *stop_clone.lock().unwrap() {
                    data.fill(0.0);
                    return;
                }
                
                let mut buf = buffer_clone.lock().unwrap();
                let mut sum_sq = 0.0f32;
                
                for sample in data.iter_mut() {
                    if let Some(s) = buf.pop_front() {
                        *sample = s;
                        sum_sq += s * s;
                    } else {
                        *sample = 0.0; // Silence if buffer underrun
                    }
                }
                
                // Update output level
                if !data.is_empty() {
                    let rms = (sum_sq / data.len() as f32).sqrt();
                    *level_clone.lock().unwrap() = (rms * 10.0).min(1.0);
                }
            },
            |err| {
                log::error!("Audio output stream error: {}", err);
            },
            None,
        ).ok()?;
        
        stream.play().ok()?;
        
        Some(Self {
            buffer,
            stop_flag,
            output_level,
            _stream: Some(stream),
        })
    }
    
    /// Push decoded audio samples to the playback buffer
    pub fn push_samples(&self, samples: &[f32]) {
        if *self.stop_flag.lock().unwrap() {
            return;
        }
        
        let mut buf = self.buffer.lock().unwrap();
        // Limit buffer size to prevent unbounded growth (500ms max)
        let max_size = 48000 / 2; // 500ms at 48kHz mono
        if buf.len() + samples.len() > max_size {
            // Drop oldest samples if we're getting behind
            let to_drop = buf.len() + samples.len() - max_size;
            for _ in 0..to_drop.min(buf.len()) {
                buf.pop_front();
            }
        }
        buf.extend(samples.iter().copied());
    }
    
    /// Get current output level (0.0 to 1.0)  
    pub fn get_level(&self) -> f32 {
        *self.output_level.lock().unwrap()
    }
    
    /// Stop playback
    pub fn stop(&self) {
        *self.stop_flag.lock().unwrap() = true;
    }
}

impl Drop for AudioPlayback {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Full duplex audio stream for voice chat
pub struct VoiceAudioStream {
    /// Audio capture from microphone
    capture_stream: Option<cpal::Stream>,
    /// Audio playback
    playback: Option<AudioPlayback>,
    /// Opus encoder for sending
    encoder: Option<OpusEncoder>,
    /// Opus decoder for receiving
    decoder: Option<OpusDecoder>,
    /// Frame size in samples
    frame_size: usize,
    /// Stop flag
    stop_flag: Arc<Mutex<bool>>,
    /// Mute flag (don't send audio when muted)
    muted: Arc<Mutex<bool>>,
    /// Network stats
    stats: Arc<Mutex<VoiceNetworkStats>>,
    /// Event sender for level updates
    evt_tx: Option<Sender<VoiceEvent>>,
    /// Channel for sending encoded frames out
    frame_tx: Option<async_channel::Sender<(u32, Vec<u8>)>>,
    /// Sequence number for outgoing frames
    sequence: Arc<Mutex<u32>>,
    /// Buffer for accumulating input samples before encoding
    input_buffer: Arc<Mutex<Vec<f32>>>,
    /// Input level
    input_level: Arc<Mutex<f32>>,
}

impl VoiceAudioStream {
    /// Create a new voice audio stream
    pub fn new(config: &VoiceConfig) -> Self {
        Self {
            capture_stream: None,
            playback: None,
            encoder: None,
            decoder: None,
            frame_size: config.frame_size,
            stop_flag: Arc::new(Mutex::new(false)),
            muted: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(VoiceNetworkStats::new())),
            evt_tx: None,
            frame_tx: None,
            sequence: Arc::new(Mutex::new(0)),
            input_buffer: Arc::new(Mutex::new(Vec::with_capacity(config.frame_size * 2))),
            input_level: Arc::new(Mutex::new(0.0)),
        }
    }
    
    /// Start the audio stream
    pub fn start(
        &mut self,
        config: &VoiceConfig,
        input_device: Option<&str>,
        output_device: Option<&str>,
        evt_tx: Sender<VoiceEvent>,
        muted: Arc<Mutex<bool>>,
    ) -> Option<async_channel::Receiver<(u32, Vec<u8>)>> {
        use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
        
        // Create encoder and decoder
        let capture = AudioCapture::new(config);
        let encoder = capture.create_encoder().ok()?;
        let decoder = capture.create_decoder().ok()?;
        
        self.encoder = Some(encoder);
        self.decoder = Some(decoder);
        self.evt_tx = Some(evt_tx.clone());
        self.muted = muted;
        
        // Start playback
        self.playback = AudioPlayback::start(output_device, config.sample_rate, config.channels);
        
        // Create channel for encoded frames
        let (frame_tx, frame_rx) = async_channel::bounded(100);
        self.frame_tx = Some(frame_tx.clone());
        
        // Start capture
        let host = cpal::default_host();
        let input_dev = if let Some(name) = input_device {
            host.input_devices().ok()?.find(|d| d.name().ok().as_deref() == Some(name))?
        } else {
            host.default_input_device()?
        };
        
        let input_config = cpal::StreamConfig {
            channels: config.channels,
            sample_rate: cpal::SampleRate(config.sample_rate),
            buffer_size: cpal::BufferSize::Default,
        };
        
        let stop_clone = self.stop_flag.clone();
        let muted_clone = self.muted.clone();
        let _input_buffer = self.input_buffer.clone();
        let frame_size = config.frame_size;
        let sequence = self.sequence.clone();
        let input_level = self.input_level.clone();
        let _evt_tx_clone = evt_tx.clone();
        
        // We need to encode in a separate task since we can't do async in the audio callback
        let encode_buffer = Arc::new(Mutex::new(Vec::<f32>::new()));
        let encode_buffer_clone = encode_buffer.clone();
        
        let capture_stream = input_dev.build_input_stream(
            &input_config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                if *stop_clone.lock().unwrap() {
                    return;
                }
                
                // Calculate input level
                let rms = calculate_audio_level(data);
                *input_level.lock().unwrap() = (rms * 10.0).min(1.0);
                
                // Add to encode buffer if not muted
                if !*muted_clone.lock().unwrap() {
                    let mut buf = encode_buffer_clone.lock().unwrap();
                    buf.extend_from_slice(data);
                }
            },
            |err| {
                log::error!("Audio capture error: {}", err);
            },
            None,
        ).ok()?;
        
        capture_stream.play().ok()?;
        self.capture_stream = Some(capture_stream);
        
        // Spawn encoding task
        let stop_clone2 = self.stop_flag.clone();
        let stats_clone = self.stats.clone();
        
        std::thread::spawn(move || {
            let mut encoder = AudioCapture::new(&VoiceConfig::default()).create_encoder().unwrap();
            let mut opus_output = vec![0u8; 4000]; // Max opus frame size
            
            loop {
                if *stop_clone2.lock().unwrap() {
                    break;
                }
                
                // Check if we have enough samples to encode
                let samples_to_encode: Option<Vec<f32>> = {
                    let mut buf = encode_buffer.lock().unwrap();
                    if buf.len() >= frame_size {
                        Some(buf.drain(0..frame_size).collect())
                    } else {
                        None
                    }
                };
                
                if let Some(samples) = samples_to_encode {
                    // Encode the frame
                    match encoder.encode_float(&samples, &mut opus_output) {
                        Ok(len) => {
                            let encoded = opus_output[..len].to_vec();
                            let seq = {
                                let mut s = sequence.lock().unwrap();
                                let curr = *s;
                                *s = s.wrapping_add(1);
                                curr
                            };
                            
                            // Update stats
                            {
                                let mut stats = stats_clone.lock().unwrap();
                                stats.record_tx(encoded.len(), seq);
                            }
                            
                            // Send to frame channel
                            let _ = frame_tx.try_send((seq, encoded));
                        }
                        Err(e) => {
                            log::error!("Opus encode error: {}", e);
                        }
                    }
                } else {
                    // Sleep a bit if no data to encode
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        });
        
        Some(frame_rx)
    }
    
    /// Decode and play received audio frame
    pub fn receive_frame(&mut self, sequence: u32, data: &[u8]) {
        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.record_rx(data.len(), sequence);
        }
        
        // Decode
        if let Some(ref mut decoder) = self.decoder {
            let mut pcm = vec![0.0f32; self.frame_size];
            match decoder.decode_float(data, &mut pcm, false) {
                Ok(samples) => {
                    let pcm = &pcm[..samples];
                    
                    // Send to playback
                    if let Some(ref playback) = self.playback {
                        playback.push_samples(pcm);
                        
                        // Send output level event
                        if let Some(ref evt_tx) = self.evt_tx {
                            let level = playback.get_level();
                            let _ = evt_tx.try_send(VoiceEvent::OutputLevel { level });
                        }
                    }
                }
                Err(e) => {
                    log::error!("Opus decode error: {}", e);
                }
            }
        }
    }
    
    /// Get current network stats
    pub fn get_stats(&self) -> VoiceNetworkStats {
        self.stats.lock().unwrap().clone()
    }
    
    /// Get input level
    pub fn get_input_level(&self) -> f32 {
        *self.input_level.lock().unwrap()
    }
    
    /// Get output level
    pub fn get_output_level(&self) -> f32 {
        self.playback.as_ref().map(|p| p.get_level()).unwrap_or(0.0)
    }
    
    /// Stop the audio stream
    pub fn stop(&mut self) {
        *self.stop_flag.lock().unwrap() = true;
        if let Some(ref playback) = self.playback {
            playback.stop();
        }
    }
}

impl Drop for VoiceAudioStream {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Calculate RMS audio level from samples
pub fn calculate_audio_level(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    
    let sum: f32 = samples.iter().map(|s| s * s).sum();
    (sum / samples.len() as f32).sqrt()
}

/// Audio input device info
#[derive(Clone, Debug)]
pub struct AudioInputDevice {
    pub name: String,
    pub is_default: bool,
}

/// Audio output device info
#[derive(Clone, Debug)]
pub struct AudioOutputDevice {
    pub name: String,
    pub is_default: bool,
}

/// Get list of available audio input devices
pub fn list_audio_input_devices() -> Vec<AudioInputDevice> {
    use cpal::traits::{HostTrait, DeviceTrait};
    
    let mut devices = Vec::new();
    
    let host = cpal::default_host();
    let default_device_name = host.default_input_device()
        .and_then(|d| d.name().ok());
    
    if let Ok(input_devices) = host.input_devices() {
        for device in input_devices {
            if let Ok(name) = device.name() {
                let is_default = default_device_name.as_ref() == Some(&name);
                devices.push(AudioInputDevice { name, is_default });
            }
        }
    }
    
    devices
}

/// Get list of available audio output devices
pub fn list_audio_output_devices() -> Vec<AudioOutputDevice> {
    use cpal::traits::{HostTrait, DeviceTrait};
    
    let mut devices = Vec::new();
    
    let host = cpal::default_host();
    let default_device_name = host.default_output_device()
        .and_then(|d| d.name().ok());
    
    if let Ok(output_devices) = host.output_devices() {
        for device in output_devices {
            if let Ok(name) = device.name() {
                let is_default = default_device_name.as_ref() == Some(&name);
                devices.push(AudioOutputDevice { name, is_default });
            }
        }
    }
    
    devices
}

/// Get audio output device by name
pub fn get_audio_output_device(name: &str) -> Option<cpal::Device> {
    use cpal::traits::{HostTrait, DeviceTrait};
    
    let host = cpal::default_host();
    if let Ok(devices) = host.output_devices() {
        for device in devices {
            if let Ok(device_name) = device.name() {
                if device_name == name {
                    return Some(device);
                }
            }
        }
    }
    None
}

/// Get the default audio output device
pub fn get_default_output_device() -> Option<cpal::Device> {
    use cpal::traits::HostTrait;
    cpal::default_host().default_output_device()
}

/// Get audio input device by name
pub fn get_audio_input_device(name: &str) -> Option<cpal::Device> {
    use cpal::traits::{HostTrait, DeviceTrait};
    
    let host = cpal::default_host();
    if let Ok(devices) = host.input_devices() {
        for device in devices {
            if let Ok(device_name) = device.name() {
                if device_name == name {
                    return Some(device);
                }
            }
        }
    }
    None
}

/// Get the default audio input device
pub fn get_default_input_device() -> Option<cpal::Device> {
    use cpal::traits::HostTrait;
    cpal::default_host().default_input_device()
}

/// Audio level monitor handle
pub struct AudioLevelMonitor {
    stop_flag: Arc<Mutex<bool>>,
    level: Arc<Mutex<f32>>,
    _stream: Option<cpal::Stream>,
}

impl AudioLevelMonitor {
    /// Start monitoring audio input levels from the specified device (or default if None)
    pub fn start(device_name: Option<&str>) -> Option<Self> {
        use cpal::traits::{DeviceTrait, StreamTrait};
        
        let device = if let Some(name) = device_name {
            get_audio_input_device(name)?
        } else {
            get_default_input_device()?
        };
        
        let config = device.default_input_config().ok()?;
        let level = Arc::new(Mutex::new(0.0f32));
        let stop_flag = Arc::new(Mutex::new(false));
        
        let level_clone = level.clone();
        let stop_clone = stop_flag.clone();
        
        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => {
                device.build_input_stream(
                    &config.into(),
                    move |data: &[f32], _: &cpal::InputCallbackInfo| {
                        if *stop_clone.lock().unwrap() {
                            return;
                        }
                        let rms = calculate_audio_level(data);
                        // Convert to dB-like scale (0.0 to 1.0)
                        let level_db = (rms * 10.0).min(1.0);
                        *level_clone.lock().unwrap() = level_db;
                    },
                    |err| {
                        log::error!("Audio input stream error: {}", err);
                    },
                    None,
                ).ok()?
            }
            cpal::SampleFormat::I16 => {
                let level_clone = level.clone();
                let stop_clone = stop_flag.clone();
                device.build_input_stream(
                    &config.into(),
                    move |data: &[i16], _: &cpal::InputCallbackInfo| {
                        if *stop_clone.lock().unwrap() {
                            return;
                        }
                        // Convert i16 to f32
                        let samples: Vec<f32> = data.iter().map(|&s| s as f32 / 32768.0).collect();
                        let rms = calculate_audio_level(&samples);
                        let level_db = (rms * 10.0).min(1.0);
                        *level_clone.lock().unwrap() = level_db;
                    },
                    |err| {
                        log::error!("Audio input stream error: {}", err);
                    },
                    None,
                ).ok()?
            }
            cpal::SampleFormat::U16 => {
                let level_clone = level.clone();
                let stop_clone = stop_flag.clone();
                device.build_input_stream(
                    &config.into(),
                    move |data: &[u16], _: &cpal::InputCallbackInfo| {
                        if *stop_clone.lock().unwrap() {
                            return;
                        }
                        // Convert u16 to f32
                        let samples: Vec<f32> = data.iter().map(|&s| (s as f32 - 32768.0) / 32768.0).collect();
                        let rms = calculate_audio_level(&samples);
                        let level_db = (rms * 10.0).min(1.0);
                        *level_clone.lock().unwrap() = level_db;
                    },
                    |err| {
                        log::error!("Audio input stream error: {}", err);
                    },
                    None,
                ).ok()?
            }
            _ => return None,
        };
        
        stream.play().ok()?;
        
        Some(Self {
            stop_flag,
            level,
            _stream: Some(stream),
        })
    }
    
    /// Get the current audio level (0.0 to 1.0)
    pub fn get_level(&self) -> f32 {
        *self.level.lock().unwrap()
    }
    
    /// Stop monitoring
    pub fn stop(&self) {
        *self.stop_flag.lock().unwrap() = true;
    }
}

impl Drop for AudioLevelMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Audio output level monitor (monitors what's being played to a device)
/// This uses a loopback/monitor stream when available, or tracks sent audio levels
pub struct AudioOutputLevelMonitor {
    stop_flag: Arc<Mutex<bool>>,
    level: Arc<Mutex<f32>>,
}

impl AudioOutputLevelMonitor {
    /// Create a new output level monitor
    pub fn new() -> Self {
        Self {
            stop_flag: Arc::new(Mutex::new(false)),
            level: Arc::new(Mutex::new(0.0f32)),
        }
    }
    
    /// Update the output level from audio being sent/played
    pub fn update_level(&self, samples: &[f32]) {
        if *self.stop_flag.lock().unwrap() {
            return;
        }
        let rms = calculate_audio_level(samples);
        let level_db = (rms * 10.0).min(1.0);
        *self.level.lock().unwrap() = level_db;
    }
    
    /// Get the current output level (0.0 to 1.0)
    pub fn get_level(&self) -> f32 {
        *self.level.lock().unwrap()
    }
    
    /// Stop monitoring
    pub fn stop(&self) {
        *self.stop_flag.lock().unwrap() = true;
        *self.level.lock().unwrap() = 0.0;
    }
}

impl Drop for AudioOutputLevelMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Default for AudioOutputLevelMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Get local IP address that should be reachable by peers
pub fn get_local_ip() -> Option<String> {
    use std::net::UdpSocket;
    
    // Connect to a public IP to determine local interface
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let local_addr = socket.local_addr().ok()?;
    Some(local_addr.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_voice_command_serialization() {
        let cmd = VoiceCommand::Ping;
        let bytes = cmd.to_bytes();
        let decoded = VoiceCommand::from_bytes(&bytes);
        assert!(matches!(decoded, Some(VoiceCommand::Ping)));
        
        let cmd = VoiceCommand::AudioFrame {
            sequence: 42,
            data: vec![1, 2, 3, 4],
        };
        let bytes = cmd.to_bytes();
        let decoded = VoiceCommand::from_bytes(&bytes);
        assert!(matches!(decoded, Some(VoiceCommand::AudioFrame { sequence: 42, .. })));
    }
    
    #[test]
    fn test_ctcp_parsing() {
        let ctcp = create_voice_call_ctcp("192.168.1.100", 5000, "VC123");
        assert!(ctcp.starts_with('\x01'));
        assert!(ctcp.ends_with('\x01'));
        
        let parsed = parse_voice_ctcp(&ctcp);
        assert!(parsed.is_some());
        let (cmd, args) = parsed.unwrap();
        assert_eq!(cmd, CTCP_VOICE_CALL);
        assert_eq!(args[0], "192.168.1.100");
        assert_eq!(args[1], "5000");
        assert_eq!(args[2], "VC123");
    }
    
    #[test]
    fn test_session_id_generation() {
        let id1 = VoiceChatManager::generate_session_id();
        let id2 = VoiceChatManager::generate_session_id();
        assert!(id1.starts_with("VC"));
        assert_ne!(id1, id2);
    }
}
