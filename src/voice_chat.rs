//! Peer-to-peer voice chat module with CTCP negotiation and socket-based audio streaming.

use async_channel::{Receiver, Sender};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio02::net::{TcpListener, TcpStream};
use tokio02::prelude::*;
#[allow(unused_imports)]
use std::time::Duration;

// Re-export opus codec types
pub use opus::{Encoder as OpusEncoder, Decoder as OpusDecoder, Channels, Application};

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
                    let ip = args[0].clone();
                    let port = args[1].parse::<u16>().unwrap_or(0);
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
                    let session_id = args[0].clone();
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
        let mut runtime = tokio02::runtime::Runtime::new().expect("tokio runtime for voice chat");
        runtime.block_on(async move {
            let core = VoiceChatCore::new(config, cmd_rx, evt_tx.clone());
            let _ = voice_chat_loop(core).await;
        });
    });
    
    VoiceChatHandle { cmd_tx, evt_rx }
}

/// Main voice chat event loop
async fn voice_chat_loop(core: VoiceChatCore) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Start TCP listener for incoming voice connections
    let mut listener = TcpListener::bind(format!("0.0.0.0:{}", core.config.listen_port)).await?;
    let local_addr = listener.local_addr()?;
    
    log::info!("Voice chat listening on {}", local_addr);
    
    loop {
        tokio02::select! {
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
                    // Handle the connection in a spawned task
                    let evt_tx = core.evt_tx.clone();
                    let state = core.state.clone();
                    let muted = core.local_muted.clone();
                    let config = core.config.clone();
                    tokio02::spawn(async move {
                        let _ = handle_voice_connection(stream, addr, evt_tx, state, muted, config).await;
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
    _muted: Arc<Mutex<bool>>,
    _config: VoiceConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = [0u8; 4096];
    
    loop {
        tokio02::select! {
            result = stream.read(&mut buf) => {
                let n = result?;
                if n == 0 {
                    // Connection closed
                    break;
                }
                
                if let Some(cmd) = VoiceCommand::from_bytes(&buf[..n]) {
                    match cmd {
                        VoiceCommand::AudioFrame { sequence: _, data: _ } => {
                            // Decode and play audio
                            // Audio playback is handled by the audio system
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
        }
    }
    
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

/// Calculate RMS audio level from samples
pub fn calculate_audio_level(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    
    let sum: f32 = samples.iter().map(|s| s * s).sum();
    (sum / samples.len() as f32).sqrt()
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
