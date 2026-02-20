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

// Noise filtering imports
use biquad::{Biquad, Coefficients, DirectForm1, ToHertz, Type as FilterType, Q_BUTTERWORTH_F32};

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
    /// Hosting a voice channel, waiting for users to join
    Hosting,
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

// Voice channel CTCP commands
pub const CTCP_VOICE_CHANNEL_INVITE: &str = "VOICE_CHANNEL_INVITE";
pub const CTCP_VOICE_CHANNEL_JOIN: &str = "VOICE_CHANNEL_JOIN";
pub const CTCP_VOICE_CHANNEL_LEAVE: &str = "VOICE_CHANNEL_LEAVE";

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
    /// Noise filtering configuration
    pub noise_filter: NoiseFilterConfig,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        Self {
            listen_port: 0,
            bitrate: 24000,
            sample_rate: 48000,
            frame_size: 960, // 20ms at 48kHz
            channels: 1,
            noise_filter: NoiseFilterConfig::default(),
        }
    }
}

// ============================================================================
// Noise Filtering
// ============================================================================

/// Configuration for noise filtering options
#[derive(Clone, Debug)]
pub struct NoiseFilterConfig {
    /// Enable AI-powered noise suppression (nnnoiseless/RNNoise)
    pub noise_suppression_enabled: bool,
    /// Noise suppression strength (0.0 = off, 1.0 = full suppression)
    pub noise_suppression_strength: f32,
    /// Enable noise gate (mutes audio below threshold)
    pub noise_gate_enabled: bool,
    /// Noise gate threshold (0.0-1.0, audio below this is muted)
    pub noise_gate_threshold: f32,
    /// Noise gate attack time in ms (how fast gate opens)
    pub noise_gate_attack_ms: f32,
    /// Noise gate release time in ms (how fast gate closes)
    pub noise_gate_release_ms: f32,
    /// Enable high-pass filter (removes low frequency rumble)
    pub highpass_enabled: bool,
    /// High-pass filter cutoff frequency in Hz
    pub highpass_cutoff_hz: f32,
}

impl Default for NoiseFilterConfig {
    fn default() -> Self {
        Self {
            noise_suppression_enabled: true,
            noise_suppression_strength: 1.0,
            noise_gate_enabled: true,
            noise_gate_threshold: 0.01, // -40dB roughly
            noise_gate_attack_ms: 5.0,
            noise_gate_release_ms: 50.0,
            highpass_enabled: true,
            highpass_cutoff_hz: 80.0, // Remove rumble below 80Hz
        }
    }
}

/// Real-time audio noise filter processor
pub struct NoiseFilter {
    config: NoiseFilterConfig,
    sample_rate: u32,
    /// RNNoise denoiser state
    denoiser: Option<Box<nnnoiseless::DenoiseState<'static>>>,
    /// High-pass filter state
    highpass: Option<DirectForm1<f32>>,
    /// Noise gate state
    gate_envelope: f32,
    /// Buffer for RNNoise (requires 480-sample frames at 48kHz)
    rnnoise_buffer: Vec<f32>,
    /// Output buffer for processed audio
    output_buffer: Vec<f32>,
}

impl NoiseFilter {
    /// Create a new noise filter with the given configuration
    pub fn new(config: NoiseFilterConfig, sample_rate: u32) -> Self {
        // Initialize RNNoise denoiser if enabled
        let denoiser = if config.noise_suppression_enabled {
            Some(nnnoiseless::DenoiseState::new())
        } else {
            None
        };
        
        // Initialize high-pass filter if enabled
        let highpass: Option<DirectForm1<f32>> = if config.highpass_enabled {
            let coeffs = Coefficients::<f32>::from_params(
                FilterType::HighPass,
                sample_rate.hz(),
                config.highpass_cutoff_hz.hz(),
                Q_BUTTERWORTH_F32,
            ).ok();
            coeffs.map(DirectForm1::<f32>::new)
        } else {
            None
        };
        
        Self {
            config,
            sample_rate,
            denoiser,
            highpass,
            gate_envelope: 0.0,
            rnnoise_buffer: Vec::with_capacity(480),
            output_buffer: Vec::new(),
        }
    }
    
    /// Update the filter configuration at runtime
    pub fn update_config(&mut self, config: NoiseFilterConfig) {
        // Reinitialize denoiser if suppression was toggled
        if config.noise_suppression_enabled != self.config.noise_suppression_enabled {
            self.denoiser = if config.noise_suppression_enabled {
                Some(nnnoiseless::DenoiseState::new())
            } else {
                None
            };
        }
        
        // Reinitialize high-pass if settings changed
        if config.highpass_enabled != self.config.highpass_enabled 
            || config.highpass_cutoff_hz != self.config.highpass_cutoff_hz 
        {
            self.highpass = if config.highpass_enabled {
                let coeffs = Coefficients::<f32>::from_params(
                    FilterType::HighPass,
                    self.sample_rate.hz(),
                    config.highpass_cutoff_hz.hz(),
                    Q_BUTTERWORTH_F32,
                ).ok();
                coeffs.map(DirectForm1::<f32>::new)
            } else {
                None
            };
        }
        
        self.config = config;
    }
    
    /// Process audio samples through all enabled filters
    /// Returns filtered audio samples
    pub fn process(&mut self, input: &[f32]) -> Vec<f32> {
        if input.is_empty() {
            return Vec::new();
        }
        
        let mut samples = input.to_vec();
        
        // Step 1: High-pass filter (remove low frequency rumble)
        if let Some(ref mut hp) = self.highpass {
            for sample in samples.iter_mut() {
                *sample = hp.run(*sample);
            }
        }
        
        // Step 2: RNNoise noise suppression
        if self.config.noise_suppression_enabled {
            samples = self.apply_rnnoise(&samples);
        }
        
        // Step 3: Noise gate
        if self.config.noise_gate_enabled {
            self.apply_noise_gate(&mut samples);
        }
        
        samples
    }
    
    /// Apply RNNoise noise suppression
    /// RNNoise requires 480-sample frames at 48kHz (10ms)
    fn apply_rnnoise(&mut self, input: &[f32]) -> Vec<f32> {
        const RNNOISE_FRAME_SIZE: usize = 480;
        
        let denoiser = match &mut self.denoiser {
            Some(d) => d,
            None => return input.to_vec(),
        };
        
        // Add input to buffer
        self.rnnoise_buffer.extend_from_slice(input);
        self.output_buffer.clear();
        
        // Process complete frames
        while self.rnnoise_buffer.len() >= RNNOISE_FRAME_SIZE {
            let frame: Vec<f32> = self.rnnoise_buffer.drain(0..RNNOISE_FRAME_SIZE).collect();
            let mut output_frame = vec![0.0f32; RNNOISE_FRAME_SIZE];
            
            // RNNoise works with values in range [-32768, 32767]
            let input_scaled: Vec<f32> = frame.iter().map(|s| s * 32767.0).collect();
            
            let _vad_prob = denoiser.process_frame(&mut output_frame, &input_scaled);
            
            // Scale back to [-1, 1] and apply suppression strength
            let strength = self.config.noise_suppression_strength;
            for (i, sample) in output_frame.iter_mut().enumerate() {
                let denoised = *sample / 32767.0;
                let original = frame[i];
                // Blend between original and denoised based on strength
                *sample = original * (1.0 - strength) + denoised * strength;
            }
            
            self.output_buffer.extend_from_slice(&output_frame);
        }
        
        // Return processed audio (may be less than input if buffering)
        std::mem::take(&mut self.output_buffer)
    }
    
    /// Apply noise gate to samples in-place
    fn apply_noise_gate(&mut self, samples: &mut [f32]) {
        let threshold = self.config.noise_gate_threshold;
        let attack_coeff = (-1.0 / (self.sample_rate as f32 * self.config.noise_gate_attack_ms / 1000.0)).exp();
        let release_coeff = (-1.0 / (self.sample_rate as f32 * self.config.noise_gate_release_ms / 1000.0)).exp();
        
        for sample in samples.iter_mut() {
            let input_level = sample.abs();
            
            // Update envelope follower
            if input_level > self.gate_envelope {
                // Attack: envelope rises quickly
                self.gate_envelope = attack_coeff * self.gate_envelope + (1.0 - attack_coeff) * input_level;
            } else {
                // Release: envelope falls slowly
                self.gate_envelope = release_coeff * self.gate_envelope + (1.0 - release_coeff) * input_level;
            }
            
            // Apply gate: if envelope is below threshold, attenuate
            if self.gate_envelope < threshold {
                // Soft knee - gradually reduce gain as we approach threshold
                let gain = (self.gate_envelope / threshold).powi(2);
                *sample *= gain;
            }
        }
    }
    
    /// Get current configuration
    pub fn config(&self) -> &NoiseFilterConfig {
        &self.config
    }
    
    /// Check if any filtering is enabled
    pub fn is_active(&self) -> bool {
        self.config.noise_suppression_enabled 
            || self.config.noise_gate_enabled 
            || self.config.highpass_enabled
    }
}

// ============================================================================
// Voice Channel Types (Multi-party voice chat)
// ============================================================================

/// State of a voice channel
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceChannelState {
    /// Channel is active and accepting connections
    Active,
    /// Channel is being created
    Creating,
    /// Channel has ended
    Closed,
}

/// A participant in a voice channel
#[derive(Clone, Debug)]
pub struct VoiceChannelParticipant {
    /// Nickname of the participant
    pub nickname: String,
    /// IP address of the participant
    pub ip: String,
    /// Port the participant is listening on
    pub port: u16,
    /// Whether the participant is muted
    pub muted: bool,
    /// Whether this is the channel host
    pub is_host: bool,
    /// When the participant joined
    pub joined_at: std::time::Instant,
}

/// Voice channel information
#[derive(Clone, Debug)]
pub struct VoiceChannel {
    /// Unique channel ID (e.g., "VCHAN1a2b3c4d")
    pub channel_id: String,
    /// Channel name (optional, for display)
    pub name: Option<String>,
    /// Host's nickname (the channel creator)
    pub host: String,
    /// Host's IP address
    pub host_ip: String,
    /// Host's listening port
    pub host_port: u16,
    /// List of participants (including host)
    pub participants: Vec<VoiceChannelParticipant>,
    /// Channel state
    pub state: VoiceChannelState,
    /// When the channel was created
    pub created_at: std::time::Instant,
    /// Maximum number of participants (0 = unlimited)
    pub max_participants: usize,
}

impl VoiceChannel {
    /// Create a new voice channel
    pub fn new(host: String, host_ip: String, host_port: u16) -> Self {
        let channel_id = generate_channel_id();
        let host_participant = VoiceChannelParticipant {
            nickname: host.clone(),
            ip: host_ip.clone(),
            port: host_port,
            muted: false,
            is_host: true,
            joined_at: std::time::Instant::now(),
        };
        
        Self {
            channel_id,
            name: None,
            host,
            host_ip,
            host_port,
            participants: vec![host_participant],
            state: VoiceChannelState::Active,
            created_at: std::time::Instant::now(),
            max_participants: 8, // Default max participants
        }
    }
    
    /// Create a voice channel with a custom name
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }
    
    /// Add a participant to the channel
    pub fn add_participant(&mut self, nickname: String, ip: String, port: u16) -> bool {
        // Check if at max capacity
        if self.max_participants > 0 && self.participants.len() >= self.max_participants {
            return false;
        }
        
        // Check if already in channel
        if self.participants.iter().any(|p| p.nickname == nickname) {
            return false;
        }
        
        self.participants.push(VoiceChannelParticipant {
            nickname,
            ip,
            port,
            muted: false,
            is_host: false,
            joined_at: std::time::Instant::now(),
        });
        true
    }
    
    /// Remove a participant from the channel
    pub fn remove_participant(&mut self, nickname: &str) -> bool {
        let initial_len = self.participants.len();
        self.participants.retain(|p| p.nickname != nickname);
        self.participants.len() < initial_len
    }
    
    /// Get a participant by nickname
    pub fn get_participant(&self, nickname: &str) -> Option<&VoiceChannelParticipant> {
        self.participants.iter().find(|p| p.nickname == nickname)
    }
    
    /// Get participant count
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }
    
    /// Check if the channel is full
    pub fn is_full(&self) -> bool {
        self.max_participants > 0 && self.participants.len() >= self.max_participants
    }
    
    /// Get display name for the channel
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("{}'s Voice Channel", self.host))
    }
}

/// Generate a unique channel ID
pub fn generate_channel_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("VCHAN{:x}{:x}", timestamp, count)
}

/// Events specific to voice channels
#[derive(Clone, Debug)]
pub enum VoiceChannelEvent {
    /// Voice channel was created
    Created { channel: VoiceChannel },
    /// Received an invitation to join a voice channel
    Invited { from: String, channel_id: String, channel_name: Option<String>, host_ip: String, host_port: u16 },
    /// A participant joined the channel
    ParticipantJoined { channel_id: String, nickname: String },
    /// A participant left the channel
    ParticipantLeft { channel_id: String, nickname: String },
    /// Channel was closed
    Closed { channel_id: String, reason: String },
    /// Error occurred
    Error { channel_id: String, message: String },
}

/// Commands for voice channel management
#[derive(Clone, Debug)]
pub enum VoiceChannelCommand {
    /// Create a new voice channel
    Create { name: Option<String> },
    /// Invite a user to the channel
    Invite { nickname: String },
    /// Join a channel (when accepting an invite)
    Join { channel_id: String, host_ip: String, host_port: u16 },
    /// Leave the current channel
    Leave,
    /// Close the channel (host only)
    Close,
    /// Kick a participant (host only)
    Kick { nickname: String },
}

// ============================================================================
// Voice Channel CTCP Message Functions
// ============================================================================

/// Create CTCP message for inviting someone to a voice channel
/// Format: VOICE_CHANNEL_INVITE <channel_id> <host_ip> <host_port> [channel_name]
pub fn create_voice_channel_invite_ctcp(channel_id: &str, host_ip: &str, host_port: u16, channel_name: Option<&str>) -> String {
    if let Some(name) = channel_name {
        format!("\x01{} {} {} {} {}\x01", CTCP_VOICE_CHANNEL_INVITE, channel_id, host_ip, host_port, name)
    } else {
        format!("\x01{} {} {} {}\x01", CTCP_VOICE_CHANNEL_INVITE, channel_id, host_ip, host_port)
    }
}

/// Create CTCP message for joining a voice channel
/// Format: VOICE_CHANNEL_JOIN <channel_id> <joiner_ip> <joiner_port>
pub fn create_voice_channel_join_ctcp(channel_id: &str, joiner_ip: &str, joiner_port: u16) -> String {
    format!("\x01{} {} {} {}\x01", CTCP_VOICE_CHANNEL_JOIN, channel_id, joiner_ip, joiner_port)
}

/// Create CTCP message for leaving a voice channel
/// Format: VOICE_CHANNEL_LEAVE <channel_id>
pub fn create_voice_channel_leave_ctcp(channel_id: &str) -> String {
    format!("\x01{} {}\x01", CTCP_VOICE_CHANNEL_LEAVE, channel_id)
}

/// Parse voice channel CTCP message
/// Returns: (command, args) if valid voice channel CTCP
pub fn parse_voice_channel_ctcp(text: &str) -> Option<(String, Vec<String>)> {
    if !text.starts_with('\x01') || !text.ends_with('\x01') {
        return None;
    }
    
    let content = &text[1..text.len()-1];
    let parts: Vec<&str> = content.splitn(2, ' ').collect();
    
    let command = parts[0].to_string();
    if !command.starts_with("VOICE_CHANNEL_") {
        return None;
    }
    
    let args = if parts.len() > 1 {
        parts[1].split_whitespace().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    };
    
    Some((command, args))
}

// ============================================================================
// Voice Channel Manager
// ============================================================================

/// Manages voice channels (hosting and participating)
pub struct VoiceChannelManager {
    /// Currently hosted channel (if we're the host)
    pub hosted_channel: Option<VoiceChannel>,
    /// Currently joined channel (if we're a participant)
    pub joined_channel: Option<VoiceChannel>,
    /// Configuration
    pub config: VoiceConfig,
    /// Local listener address (when hosting)
    listener_addr: Option<SocketAddr>,
    /// Event sender
    event_tx: Option<Sender<VoiceChannelEvent>>,
    /// Connections to participants (when hosting)
    participant_streams: Arc<Mutex<HashMap<String, TcpStream>>>,
    /// Connection to host (when joining)
    host_stream: Option<TcpStream>,
    /// Local muted state
    pub local_muted: bool,
    /// Stop flag
    stop_flag: Arc<Mutex<bool>>,
}

impl VoiceChannelManager {
    pub fn new(config: VoiceConfig) -> Self {
        Self {
            hosted_channel: None,
            joined_channel: None,
            config,
            listener_addr: None,
            event_tx: None,
            participant_streams: Arc::new(Mutex::new(HashMap::new())),
            host_stream: None,
            local_muted: false,
            stop_flag: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Check if we're currently in a voice channel
    pub fn is_in_channel(&self) -> bool {
        self.hosted_channel.is_some() || self.joined_channel.is_some()
    }
    
    /// Check if we're the host of a channel
    pub fn is_host(&self) -> bool {
        self.hosted_channel.is_some()
    }
    
    /// Get the current channel (hosted or joined)
    pub fn current_channel(&self) -> Option<&VoiceChannel> {
        self.hosted_channel.as_ref().or(self.joined_channel.as_ref())
    }
    
    /// Get participants in the current channel
    pub fn get_participants(&self) -> Vec<VoiceChannelParticipant> {
        self.current_channel()
            .map(|c| c.participants.clone())
            .unwrap_or_default()
    }
}

/// Handle for interacting with voice channels from UI
#[derive(Clone)]
pub struct VoiceChannelHandle {
    pub cmd_tx: Sender<VoiceChannelCommand>,
    pub evt_rx: Receiver<VoiceChannelEvent>,
}

/// Start a voice channel as host
/// Returns (channel, external port, event receiver, stop flag)
pub fn create_voice_channel(
    host_nickname: &str,
    config: VoiceConfig,
    channel_name: Option<&str>,
    muted: Arc<Mutex<bool>>,
) -> Option<(VoiceChannel, u16, Receiver<VoiceChannelEvent>, Arc<Mutex<bool>>)> {
    let (evt_tx, evt_rx) = async_channel::unbounded();
    let stop_flag = Arc::new(Mutex::new(false));
    
    // Create a channel to receive the bound port and external address info
    // Returns (external_ip, external_port, local_port)
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<(String, u16, u16)>();
    
    let host_nick = host_nickname.to_string();
    let config_clone = config.clone();
    let evt_tx_clone = evt_tx.clone();
    let stop_flag_clone = stop_flag.clone();
    let muted_clone = muted.clone();
    let channel_name_owned = channel_name.map(|s| s.to_string());
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("voice channel runtime");
        rt.block_on(async move {
            // Bind to any available port
            match TcpListener::bind("0.0.0.0:0").await {
                Ok(listener) => {
                    let local_addr = listener.local_addr().unwrap();
                    let local_port = local_addr.port();
                    log::info!("Voice channel listener started on local port {}", local_port);
                    
                    // Set up UPnP and get external address
                    let (external_ip, external_port, _upnp_mapping) = setup_voice_address(local_port);
                    log::info!("Voice channel address: {}:{} (local port {})", 
                        external_ip, external_port, local_port);
                    
                    // Send the address info back
                    let _ = addr_tx.send((external_ip.clone(), external_port, local_port));
                    
                    // Run the channel host loop
                    let _ = run_voice_channel_host(
                        listener,
                        host_nick,
                        external_ip,
                        external_port,
                        config_clone,
                        evt_tx_clone,
                        stop_flag_clone,
                        muted_clone,
                        channel_name_owned,
                    ).await;
                }
                Err(e) => {
                    log::error!("Failed to bind voice channel listener: {}", e);
                    let _ = addr_tx.send(("".to_string(), 0, 0));
                }
            }
        });
    });
    
    // Wait for the address info
    match addr_rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok((external_ip, external_port, _local_port)) if external_port > 0 => {
            let mut channel = VoiceChannel::new(host_nickname.to_string(), external_ip, external_port);
            if let Some(name) = channel_name {
                channel.name = Some(name.to_string());
            }
            Some((channel, external_port, evt_rx, stop_flag))
        }
        _ => None,
    }
}

/// Join an existing voice channel
/// Returns (event receiver, stop flag)
pub fn join_voice_channel(
    channel_id: &str,
    host_ip: &str,
    host_port: u16,
    our_nickname: &str,
    config: VoiceConfig,
    muted: Arc<Mutex<bool>>,
) -> Option<(Receiver<VoiceChannelEvent>, Arc<Mutex<bool>>)> {
    let (evt_tx, evt_rx) = async_channel::unbounded();
    let stop_flag = Arc::new(Mutex::new(false));
    
    let channel_id = channel_id.to_string();
    let host_addr = format!("{}:{}", host_ip, host_port);
    let our_nick = our_nickname.to_string();
    let config_clone = config.clone();
    let evt_tx_clone = evt_tx.clone();
    let stop_flag_clone = stop_flag.clone();
    let muted_clone = muted.clone();
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("voice channel join runtime");
        rt.block_on(async move {
            log::info!("Joining voice channel {} at {}", channel_id, host_addr);
            
            match TcpStream::connect(&host_addr).await {
                Ok(stream) => {
                    log::info!("Connected to voice channel host");
                    let _ = run_voice_channel_participant(
                        stream,
                        channel_id,
                        our_nick,
                        config_clone,
                        evt_tx_clone,
                        stop_flag_clone,
                        muted_clone,
                    ).await;
                }
                Err(e) => {
                    log::error!("Failed to connect to voice channel: {}", e);
                    let _ = evt_tx_clone.send(VoiceChannelEvent::Error {
                        channel_id,
                        message: format!("Connection failed: {}", e),
                    }).await;
                }
            }
        });
    });
    
    Some((evt_rx, stop_flag))
}

/// Run the voice channel host loop - accepts connections and mixes audio
async fn run_voice_channel_host(
    listener: TcpListener,
    host_nick: String,
    host_ip: String,
    host_port: u16,
    config: VoiceConfig,
    evt_tx: Sender<VoiceChannelEvent>,
    stop_flag: Arc<Mutex<bool>>,
    muted: Arc<Mutex<bool>>,
    channel_name: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel_id = generate_channel_id();
    let mut channel = VoiceChannel::new(host_nick.clone(), host_ip.clone(), host_port);
    if let Some(name) = &channel_name {
        channel.name = Some(name.clone());
    }
    channel.channel_id = channel_id.clone();
    
    // Send channel created event
    let _ = evt_tx.send(VoiceChannelEvent::Created { channel: channel.clone() }).await;
    
    // Track participant connections
    let participants: Arc<Mutex<HashMap<String, ParticipantConnection>>> = Arc::new(Mutex::new(HashMap::new()));
    
    // Channel for receiving audio from participants
    let (audio_tx, audio_rx) = async_channel::bounded::<(String, u32, Vec<u8>)>(100);
    
    // Start our own audio capture
    let mut audio_stream = VoiceAudioStream::new(&config);
    let dummy_voice_evt_tx: Sender<VoiceEvent> = {
        let (tx, _rx) = async_channel::unbounded();
        tx
    };
    
    let frame_rx = audio_stream.start(
        &config,
        None,
        None,
        dummy_voice_evt_tx,
        muted.clone(),
    );
    
    // Spawn audio mixing task
    let participants_clone = participants.clone();
    let stop_flag_clone = stop_flag.clone();
    let config_clone = config.clone();
    
    tokio::spawn(async move {
        let mut mixer = AudioMixer::new(&config_clone);
        let mut mix_interval = tokio::time::interval(std::time::Duration::from_millis(20));
        
        loop {
            if *stop_flag_clone.lock().unwrap() {
                break;
            }
            
            tokio::select! {
                _ = mix_interval.tick() => {
                    // Collect and mix audio from all participants
                    let pconns = participants_clone.lock().unwrap();
                    for (_nick, conn) in pconns.iter() {
                        // Get pending audio from this participant
                        if let Some(audio) = conn.pending_audio.lock().unwrap().take() {
                            mixer.add_audio(&audio);
                        }
                    }
                    
                    // Get mixed audio and broadcast
                    if let Some(mixed) = mixer.get_mixed() {
                        for (nick, conn) in pconns.iter() {
                            if let Some(ref tx) = conn.audio_out_tx {
                                let _ = tx.try_send(mixed.clone());
                            }
                            let _ = nick; // Silence unused warning
                        }
                    }
                }
                
                // Receive audio from participants
                audio = audio_rx.recv() => {
                    if let Ok((from_nick, _seq, data)) = audio {
                        if let Ok(mut pconns) = participants_clone.lock() {
                            if let Some(conn) = pconns.get_mut(&from_nick) {
                                *conn.pending_audio.lock().unwrap() = Some(data);
                            }
                        }
                    }
                }
            }
        }
    });
    
    // Accept loop
    loop {
        if *stop_flag.lock().unwrap() {
            break;
        }
        
        tokio::select! {
            accept_result = listener.accept() => {
                if let Ok((stream, addr)) = accept_result {
                    log::info!("New participant connected from {}", addr);
                    
                    // Create participant connection
                    let (out_tx, out_rx) = async_channel::bounded::<Vec<u8>>(100);
                    let participant_name = format!("participant_{}", addr.port());
                    
                    let conn = ParticipantConnection {
                        stream: None, // Will be set after we identify the participant
                        audio_out_tx: Some(out_tx),
                        pending_audio: Arc::new(Mutex::new(None)),
                    };
                    
                    participants.lock().unwrap().insert(participant_name.clone(), conn);
                    
                    // Handle this participant in a separate task
                    let audio_tx_clone = audio_tx.clone();
                    let evt_tx_clone = evt_tx.clone();
                    let channel_id_clone = channel_id.clone();
                    let stop_flag_clone = stop_flag.clone();
                    let config_clone = config.clone();
                    let muted_clone = muted.clone();
                    
                    tokio::spawn(async move {
                        let _ = handle_channel_participant(
                            stream,
                            participant_name,
                            audio_tx_clone,
                            out_rx,
                            evt_tx_clone,
                            channel_id_clone,
                            stop_flag_clone,
                            config_clone,
                            muted_clone,
                        ).await;
                    });
                }
            }
            
            // Send our own audio frames
            frame = async {
                if let Some(ref rx) = frame_rx {
                    rx.recv().await.ok()
                } else {
                    None
                }
            } => {
                if let Some((_seq, data)) = frame {
                    // Broadcast to all participants
                    let pconns = participants.lock().unwrap();
                    for (_nick, conn) in pconns.iter() {
                        if let Some(ref tx) = conn.audio_out_tx {
                            let _ = tx.try_send(data.clone());
                        }
                    }
                }
            }
        }
    }
    
    // Cleanup
    audio_stream.stop();
    let _ = evt_tx.send(VoiceChannelEvent::Closed {
        channel_id,
        reason: "Host ended channel".to_string(),
    }).await;
    
    Ok(())
}

/// Participant connection state
struct ParticipantConnection {
    #[allow(dead_code)]
    stream: Option<TcpStream>,
    audio_out_tx: Option<Sender<Vec<u8>>>,
    pending_audio: Arc<Mutex<Option<Vec<u8>>>>,
}

/// Handle a single participant connection (runs on the host)
async fn handle_channel_participant(
    mut stream: TcpStream,
    participant_name: String,
    audio_tx: Sender<(String, u32, Vec<u8>)>,
    audio_out_rx: Receiver<Vec<u8>>,
    evt_tx: Sender<VoiceChannelEvent>,
    channel_id: String,
    stop_flag: Arc<Mutex<bool>>,
    _config: VoiceConfig,
    _muted: Arc<Mutex<bool>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut read_buf = [0u8; 8192];
    let mut pending_data: Vec<u8> = Vec::with_capacity(16384);
    
    let _ = evt_tx.send(VoiceChannelEvent::ParticipantJoined {
        channel_id: channel_id.clone(),
        nickname: participant_name.clone(),
    }).await;
    
    loop {
        if *stop_flag.lock().unwrap() {
            break;
        }
        
        tokio::select! {
            // Send audio out to this participant
            audio_out = audio_out_rx.recv() => {
                if let Ok(data) = audio_out {
                    // Send as audio frame
                    let cmd = VoiceCommand::AudioFrame { sequence: 0, data };
                    if let Err(e) = stream.write_all(&cmd.to_bytes()).await {
                        log::error!("Failed to send audio to {}: {}", participant_name, e);
                        break;
                    }
                }
            }
            
            // Receive audio from this participant
            result = stream.read(&mut read_buf) => {
                let n = match result {
                    Ok(n) => n,
                    Err(e) => {
                        log::error!("Read error from {}: {}", participant_name, e);
                        break;
                    }
                };
                
                if n == 0 {
                    log::info!("Participant {} disconnected", participant_name);
                    break;
                }
                
                pending_data.extend_from_slice(&read_buf[..n]);
                
                // Process messages
                loop {
                    match parse_voice_command_from_buffer(&pending_data) {
                        Some((cmd, consumed)) => {
                            pending_data.drain(..consumed);
                            
                            match cmd {
                                VoiceCommand::AudioFrame { sequence, data } => {
                                    let _ = audio_tx.try_send((participant_name.clone(), sequence, data));
                                }
                                VoiceCommand::Hangup => {
                                    break;
                                }
                                _ => {}
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    }
    
    let _ = evt_tx.send(VoiceChannelEvent::ParticipantLeft {
        channel_id,
        nickname: participant_name,
    }).await;
    
    Ok(())
}

/// Run as a participant in a voice channel
async fn run_voice_channel_participant(
    mut stream: TcpStream,
    channel_id: String,
    our_nick: String,
    config: VoiceConfig,
    evt_tx: Sender<VoiceChannelEvent>,
    stop_flag: Arc<Mutex<bool>>,
    muted: Arc<Mutex<bool>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut read_buf = [0u8; 8192];
    let mut pending_data: Vec<u8> = Vec::with_capacity(16384);
    
    // Start audio
    let mut audio_stream = VoiceAudioStream::new(&config);
    let dummy_evt_tx: Sender<VoiceEvent> = {
        let (tx, _rx) = async_channel::unbounded();
        tx
    };
    
    let frame_rx = audio_stream.start(
        &config,
        None,
        None,
        dummy_evt_tx,
        muted.clone(),
    );
    
    if frame_rx.is_none() {
        let _ = evt_tx.send(VoiceChannelEvent::Error {
            channel_id: channel_id.clone(),
            message: "Failed to start audio".to_string(),
        }).await;
        return Ok(());
    }
    
    let frame_rx = frame_rx.unwrap();
    
    log::info!("Participant {} joined channel {}", our_nick, channel_id);
    
    loop {
        if *stop_flag.lock().unwrap() {
            // Send hangup to host
            let _ = stream.write_all(&VoiceCommand::Hangup.to_bytes()).await;
            break;
        }
        
        tokio::select! {
            // Send our audio frames to host
            frame = frame_rx.recv() => {
                if let Ok((seq, data)) = frame {
                    let cmd = VoiceCommand::AudioFrame { sequence: seq, data };
                    if let Err(e) = stream.write_all(&cmd.to_bytes()).await {
                        log::error!("Failed to send audio to host: {}", e);
                        break;
                    }
                }
            }
            
            // Receive mixed audio from host
            result = stream.read(&mut read_buf) => {
                let n = match result {
                    Ok(n) => n,
                    Err(e) => {
                        log::error!("Read error from host: {}", e);
                        break;
                    }
                };
                
                if n == 0 {
                    log::info!("Host closed connection");
                    break;
                }
                
                pending_data.extend_from_slice(&read_buf[..n]);
                
                loop {
                    match parse_voice_command_from_buffer(&pending_data) {
                        Some((cmd, consumed)) => {
                            pending_data.drain(..consumed);
                            
                            match cmd {
                                VoiceCommand::AudioFrame { sequence, data } => {
                                    audio_stream.receive_frame(sequence, &data);
                                }
                                VoiceCommand::Hangup => {
                                    let _ = evt_tx.send(VoiceChannelEvent::Closed {
                                        channel_id: channel_id.clone(),
                                        reason: "Host ended channel".to_string(),
                                    }).await;
                                    break;
                                }
                                _ => {}
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    }
    
    audio_stream.stop();
    let _ = evt_tx.send(VoiceChannelEvent::Closed {
        channel_id,
        reason: "Left channel".to_string(),
    }).await;
    
    Ok(())
}

/// Simple audio mixer for combining multiple audio streams
struct AudioMixer {
    frame_size: usize,
    accumulated: Vec<f32>,
    source_count: usize,
}

impl AudioMixer {
    fn new(config: &VoiceConfig) -> Self {
        Self {
            frame_size: config.frame_size,
            accumulated: vec![0.0; config.frame_size],
            source_count: 0,
        }
    }
    
    /// Add audio data to the mix (already encoded, needs decoding first)
    fn add_audio(&mut self, _encoded_data: &[u8]) {
        // In a full implementation, we'd decode and mix
        // For now, this is a placeholder
        self.source_count += 1;
    }
    
    /// Get the mixed audio and reset
    fn get_mixed(&mut self) -> Option<Vec<u8>> {
        if self.source_count == 0 {
            return None;
        }
        
        // In a full implementation, we'd encode the mixed audio
        // For now, return None to indicate no mixing happened
        self.source_count = 0;
        self.accumulated.fill(0.0);
        None
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
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("VC{:x}{:x}", timestamp, count)
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
/// Returns (event receiver, stop flag)
/// Set the stop flag to true to terminate the voice connection
pub fn connect_voice_call(
    peer_ip: &str, 
    peer_port: u16, 
    config: VoiceConfig,
    muted: Arc<Mutex<bool>>,
) -> Option<(async_channel::Receiver<VoiceEvent>, Arc<Mutex<bool>>)> {
    let peer_addr = format!("{}:{}", peer_ip, peer_port);
    let (evt_tx, evt_rx) = async_channel::unbounded();
    let stop_flag = Arc::new(Mutex::new(false));
    
    let peer_addr_clone = peer_addr.clone();
    let config_clone = config.clone();
    let evt_tx_clone = evt_tx.clone();
    let muted_clone = muted.clone();
    let stop_flag_clone = stop_flag.clone();
    
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
                        stop_flag_clone,
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
    
    Some((evt_rx, stop_flag))
}

/// Start listening for incoming voice connections (used when initiating a call)
/// Returns (external_ip, external_port, event receiver, stop flag)
/// Set the stop flag to true to terminate the voice connection
pub fn start_voice_listener(
    config: VoiceConfig,
    muted: Arc<Mutex<bool>>,
) -> Option<(String, u16, async_channel::Receiver<VoiceEvent>, Arc<Mutex<bool>>)> {
    let (evt_tx, evt_rx) = async_channel::unbounded();
    let stop_flag = Arc::new(Mutex::new(false));
    
    let config_clone = config.clone();
    let evt_tx_clone = evt_tx.clone();
    let muted_clone = muted.clone();
    let stop_flag_clone = stop_flag.clone();
    
    // Create a channel to receive the bound address info
    // Returns (external_ip, external_port, local_port)
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<(String, u16, u16)>();
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("voice listener runtime");
        rt.block_on(async move {
            // Bind to any available port
            match TcpListener::bind("0.0.0.0:0").await {
                Ok(listener) => {
                    let local_addr = listener.local_addr().unwrap();
                    let local_port = local_addr.port();
                    log::info!("Voice listener started on local port {}", local_port);
                    
                    // Set up UPnP and get external address
                    let (external_ip, external_port, _upnp_mapping) = setup_voice_address(local_port);
                    log::info!("Voice listener address: {}:{} (local port {})", 
                        external_ip, external_port, local_port);
                    
                    // Send the address info back
                    let _ = addr_tx.send((external_ip, external_port, local_port));
                    
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
                                stop_flag_clone,
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
                    let _ = addr_tx.send(("".to_string(), 0, 0));
                }
            }
        });
    });
    
    // Wait for the address info (allow more time for UPnP setup)
    match addr_rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok((external_ip, external_port, _local_port)) if external_port > 0 => {
            Some((external_ip, external_port, evt_rx, stop_flag))
        }
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
                    // Create a stop flag for this connection (no external control for now)
                    let stop_flag = Arc::new(Mutex::new(false));
                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().expect("voice connection runtime");
                        rt.block_on(async move {
                            let _ = handle_voice_connection(stream, addr, evt_tx, state, muted, config, stop_flag).await;
                        });
                    });
                }
            }
        }
    }
    
    Ok(())
}

/// Parse a single VoiceCommand from a buffer, returning (command, bytes_consumed)
/// Returns None if buffer doesn't contain a complete message
fn parse_voice_command_from_buffer(data: &[u8]) -> Option<(VoiceCommand, usize)> {
    if data.is_empty() {
        return None;
    }
    
    match data[0] {
        0x01 | 0x02 | 0x03 => {
            // Variable length text commands - need a length prefix or delimiter
            // For now, these are rarely used during active calls, skip
            None
        }
        0x04 => Some((VoiceCommand::Hangup, 1)),
        0x05 => Some((VoiceCommand::Ping, 1)),
        0x06 => Some((VoiceCommand::Pong, 1)),
        0x07 if data.len() >= 2 => {
            Some((VoiceCommand::MuteStatus { muted: data[1] != 0 }, 2))
        }
        0x10 if data.len() >= 7 => {
            let sequence = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            let len = u16::from_be_bytes([data[5], data[6]]) as usize;
            let total_len = 7 + len;
            if data.len() >= total_len {
                let audio_data = data[7..total_len].to_vec();
                Some((VoiceCommand::AudioFrame { sequence, data: audio_data }, total_len))
            } else {
                // Not enough data yet - need more bytes
                None
            }
        }
        _ => {
            // Unknown command, skip one byte
            log::warn!("Unknown voice command byte: 0x{:02x}", data[0]);
            Some((VoiceCommand::Ping, 1)) // Dummy to consume the byte
        }
    }
}

/// Handle an established voice connection
async fn handle_voice_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    evt_tx: Sender<VoiceEvent>,
    _state: Arc<Mutex<VoiceState>>,
    muted: Arc<Mutex<bool>>,
    config: VoiceConfig,
    stop_flag: Arc<Mutex<bool>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut read_buf = [0u8; 8192];
    // Accumulation buffer for TCP stream reassembly
    let mut pending_data: Vec<u8> = Vec::with_capacity(16384);
    
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
    
    // Check interval for stop flag
    let mut stop_check_timer = tokio::time::interval(std::time::Duration::from_millis(100));
    
    loop {
        // Check stop flag
        if let Ok(stopped) = stop_flag.lock() {
            if *stopped {
                log::info!("Voice connection stopped by user");
                // Send hangup to peer before closing
                let _ = stream.write_all(&VoiceCommand::Hangup.to_bytes()).await;
                break;
            }
        }
        
        tokio::select! {
            // Check stop flag periodically
            _ = stop_check_timer.tick() => {
                // Just to trigger the stop check at top of loop
                continue;
            }
            
            // Send encoded audio frames
            frame = frame_rx.recv() => {
                if let Ok((seq, data)) = frame {
                    let cmd = VoiceCommand::AudioFrame { sequence: seq, data };
                    let bytes = cmd.to_bytes();
                    if let Err(e) = stream.write_all(&bytes).await {
                        log::error!("Failed to send audio frame: {}", e);
                        break;
                    }
                }
            }
            
            // Receive data from peer - use buffered reading with message framing
            result = stream.read(&mut read_buf) => {
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
                
                // Append new data to pending buffer
                pending_data.extend_from_slice(&read_buf[..n]);
                
                // Process all complete messages in the buffer
                let mut should_break = false;
                loop {
                    match parse_voice_command_from_buffer(&pending_data) {
                        Some((cmd, consumed)) => {
                            // Remove consumed bytes from buffer
                            pending_data.drain(..consumed);
                            
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
                                    should_break = true;
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
                        None => {
                            // Need more data - wait for next read
                            break;
                        }
                    }
                }
                
                if should_break {
                    break;
                }
                
                // Safety: prevent unbounded buffer growth from malformed data
                if pending_data.len() > 65536 {
                    log::error!("Voice protocol buffer overflow, resetting");
                    pending_data.clear();
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

/// Audio playback system using ring buffer for received audio with jitter buffering
pub struct AudioPlayback {
    /// Ring buffer for audio samples
    buffer: Arc<Mutex<std::collections::VecDeque<f32>>>,
    /// Stop flag
    stop_flag: Arc<Mutex<bool>>,
    /// Output level for monitoring
    output_level: Arc<Mutex<f32>>,
    /// Jitter buffer priming flag - wait until we have enough data before playing
    primed: Arc<Mutex<bool>>,
    /// Target jitter buffer size in samples (80ms at 48kHz = 3840 samples)
    jitter_target: usize,
    /// Output stream handle (kept alive)
    _stream: Option<cpal::Stream>,
}

impl AudioPlayback {
    /// Start audio playback on the specified device (or default)
    pub fn start(device_name: Option<&str>, sample_rate: u32, channels: u16) -> Option<Self> {
        use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
        
        let host = cpal::default_host();
        log::info!("Audio playback: Using host {:?}", host.id());
        
        let device = if let Some(name) = device_name {
            log::info!("Audio playback: Looking for device '{}'", name);
            host.output_devices().ok()?.find(|d| d.name().ok().as_deref() == Some(name))?
        } else {
            log::info!("Audio playback: Using default output device");
            host.default_output_device()?
        };
        
        log::info!("Audio playback: Selected device '{}'", device.name().unwrap_or_default());
        
        // Log supported configs
        if let Ok(supported) = device.supported_output_configs() {
            for cfg in supported {
                log::debug!("  Supported config: {:?}", cfg);
            }
        }
        
        // Jitter buffer: target 80ms of buffered audio before starting playback
        // This helps smooth out network jitter and prevents choppy audio
        let jitter_target = (sample_rate as usize * channels as usize * 80) / 1000; // 80ms
        
        // Create buffer with larger capacity (300ms for jitter absorption)
        let buffer_capacity = (sample_rate as usize * channels as usize * 300) / 1000;
        let buffer = Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(buffer_capacity)));
        let stop_flag = Arc::new(Mutex::new(false));
        let output_level = Arc::new(Mutex::new(0.0f32));
        let primed = Arc::new(Mutex::new(false)); // Start unprimed - wait for jitter buffer to fill
        
        let buffer_clone = buffer.clone();
        let stop_clone = stop_flag.clone();
        let level_clone = output_level.clone();
        let primed_clone = primed.clone();
        let jitter_target_clone = jitter_target;
        
        // On Windows, we may need stereo output even if input is mono
        // Windows audio devices often don't support mono output
        let output_channels = if cfg!(windows) && channels == 1 { 2 } else { channels };
        let is_mono_to_stereo = output_channels != channels;
        
        let config = cpal::StreamConfig {
            channels: output_channels,
            sample_rate: cpal::SampleRate(sample_rate),
            buffer_size: cpal::BufferSize::Default,
        };
        
        log::info!("Audio playback: Attempting config: {} Hz, {} channels (mono_to_stereo: {}, jitter_target: {} samples)", 
            sample_rate, output_channels, is_mono_to_stereo, jitter_target);
        
        let stream_result = device.build_output_stream(
            &config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                if *stop_clone.lock().unwrap() {
                    data.fill(0.0);
                    return;
                }
                
                let mut buf = buffer_clone.lock().unwrap();
                let mut is_primed = primed_clone.lock().unwrap();
                let mut sum_sq = 0.0f32;
                
                // Jitter buffer logic: wait until we have enough data before playing
                if !*is_primed {
                    if buf.len() >= jitter_target_clone {
                        *is_primed = true;
                        log::info!("Audio playback: Jitter buffer primed with {} samples", buf.len());
                    } else {
                        // Still buffering - output silence
                        data.fill(0.0);
                        return;
                    }
                }
                
                // Check for buffer underrun - if we run dry, re-prime
                if buf.is_empty() {
                    *is_primed = false;
                    log::debug!("Audio playback: Buffer underrun, re-priming jitter buffer");
                    data.fill(0.0);
                    return;
                }
                
                if is_mono_to_stereo {
                    // Duplicate mono samples to stereo
                    for chunk in data.chunks_mut(2) {
                        if let Some(s) = buf.pop_front() {
                            chunk[0] = s;  // Left
                            if chunk.len() > 1 {
                                chunk[1] = s;  // Right
                            }
                            sum_sq += s * s;
                        } else {
                            chunk.fill(0.0); // Silence if buffer underrun
                        }
                    }
                } else {
                    for sample in data.iter_mut() {
                        if let Some(s) = buf.pop_front() {
                            *sample = s;
                            sum_sq += s * s;
                        } else {
                            *sample = 0.0; // Silence if buffer underrun
                        }
                    }
                }
                
                // Update output level
                let sample_count = if is_mono_to_stereo { data.len() / 2 } else { data.len() };
                if sample_count > 0 {
                    let rms = (sum_sq / sample_count as f32).sqrt();
                    *level_clone.lock().unwrap() = (rms * 10.0).min(1.0);
                }
            },
            |err| {
                log::error!("Audio output stream error: {}", err);
            },
            None,
        );
        
        let stream = match stream_result {
            Ok(s) => s,
            Err(e) => {
                log::error!("Audio playback: Failed to build output stream: {}", e);
                // Try with device's default config
                log::info!("Audio playback: Attempting device default config...");
                if let Ok(default_config) = device.default_output_config() {
                    log::info!("Audio playback: Device default: {:?}", default_config);
                }
                return None;
            }
        };
        
        if let Err(e) = stream.play() {
            log::error!("Audio playback: Failed to start stream: {}", e);
            return None;
        }
        
        log::info!("Audio playback: Stream started successfully");
        
        Some(Self {
            buffer,
            stop_flag,
            output_level,
            primed,
            jitter_target,
            _stream: Some(stream),
        })
    }
    
    /// Push decoded audio samples to the playback buffer
    pub fn push_samples(&self, samples: &[f32]) {
        if *self.stop_flag.lock().unwrap() {
            return;
        }
        
        let mut buf = self.buffer.lock().unwrap();
        // Limit buffer size to prevent unbounded growth (500ms max at 48kHz mono)
        let max_size = 48000 / 2;
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
        log::info!("VoiceAudioStream: Starting playback with sample_rate={}, channels={}", config.sample_rate, config.channels);
        self.playback = AudioPlayback::start(output_device, config.sample_rate, config.channels);
        if self.playback.is_none() {
            log::error!("VoiceAudioStream: Failed to start audio playback!");
        } else {
            log::info!("VoiceAudioStream: Audio playback started successfully");
        }
        
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
        let config_clone = config.clone(); // Use actual config, not default
        
        std::thread::spawn(move || {
            let mut encoder = AudioCapture::new(&config_clone).create_encoder().unwrap();
            let mut opus_output = vec![0u8; 4000]; // Max opus frame size
            
            // Initialize noise filter
            let mut noise_filter = NoiseFilter::new(
                config_clone.noise_filter.clone(),
                config_clone.sample_rate,
            );
            
            // Target frame interval based on frame size and sample rate
            // frame_size / sample_rate = time per frame
            // e.g., 960 samples / 48000 Hz = 20ms per frame
            let frame_duration_ms = (frame_size as u64 * 1000) / config_clone.sample_rate as u64;
            let frame_interval = std::time::Duration::from_millis(frame_duration_ms.max(1));
            
            // Buffer for filtered samples (noise filter may output different amounts than input)
            let mut filtered_buffer: Vec<f32> = Vec::new();
            
            loop {
                if *stop_clone2.lock().unwrap() {
                    break;
                }
                
                // Check if we have enough samples to encode
                let has_samples = {
                    let mut buf = encode_buffer.lock().unwrap();
                    if buf.len() >= frame_size {
                        let raw_samples: Vec<f32> = buf.drain(0..frame_size).collect();
                        // Process through noise filter and add to filtered buffer
                        let filtered = noise_filter.process(&raw_samples);
                        filtered_buffer.extend(filtered);
                        true
                    } else {
                        false
                    }
                };
                
                // Encode complete frames from filtered buffer
                while filtered_buffer.len() >= frame_size {
                    let samples: Vec<f32> = filtered_buffer.drain(0..frame_size).collect();
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
                }
                
                // No samples available - sleep to avoid busy-waiting
                if !has_samples {
                    // Sleep for half the frame interval (e.g., 10ms for 20ms frames)
                    // This balances responsiveness with CPU efficiency
                    std::thread::sleep(frame_interval / 2);
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
        
        // Log every 50th frame to avoid spam
        if sequence % 50 == 0 {
            log::debug!("receive_frame: seq={}, data_len={}, has_decoder={}, has_playback={}",
                sequence, data.len(), self.decoder.is_some(), self.playback.is_some());
        }
        
        // Decode
        if let Some(ref mut decoder) = self.decoder {
            let mut pcm = vec![0.0f32; self.frame_size];
            match decoder.decode_float(data, &mut pcm, false) {
                Ok(samples) => {
                    let pcm = &pcm[..samples];
                    
                    // Log first decode success and periodically
                    if sequence % 50 == 0 {
                        let max_sample = pcm.iter().fold(0.0f32, |a, &b| a.max(b.abs()));
                        log::debug!("Decoded {} samples, max_amplitude={:.4}", samples, max_sample);
                    }
                    
                    // Send to playback
                    if let Some(ref playback) = self.playback {
                        playback.push_samples(pcm);
                        
                        // Send output level event
                        if let Some(ref evt_tx) = self.evt_tx {
                            let level = playback.get_level();
                            let _ = evt_tx.try_send(VoiceEvent::OutputLevel { level });
                        }
                    } else if sequence % 50 == 0 {
                        log::warn!("receive_frame: No playback available to push samples!");
                    }
                }
                Err(e) => {
                    log::error!("Opus decode error: {}", e);
                }
            }
        } else {
            if sequence % 50 == 0 {
                log::warn!("receive_frame: No decoder available!");
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

// ============================================================================
// NAT Traversal - External IP and UPnP
// ============================================================================

/// Get the external (public) IP address using various public services
pub async fn get_external_ip() -> Option<String> {
    // Try multiple services for reliability
    let services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://api.seeip.org",
    ];
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    
    for service in services {
        match client.get(service).send().await {
            Ok(resp) => {
                if let Ok(ip) = resp.text().await {
                    let ip = ip.trim().to_string();
                    // Validate it looks like an IP address
                    if ip.parse::<std::net::IpAddr>().is_ok() {
                        log::info!("Got external IP from {}: {}", service, ip);
                        return Some(ip);
                    }
                }
            }
            Err(e) => {
                log::debug!("Failed to get external IP from {}: {}", service, e);
            }
        }
    }
    
    log::warn!("Failed to get external IP from any service, falling back to local IP");
    None
}

/// Get external IP synchronously (blocking)
pub fn get_external_ip_sync() -> Option<String> {
    // Try to create a runtime for async operation
    match tokio::runtime::Handle::try_current() {
        Ok(_handle) => {
            // We're in an async context, spawn blocking
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().ok()?;
                rt.block_on(get_external_ip())
            }).join().ok()?
        }
        Err(_) => {
            // Not in async context, create runtime
            let rt = tokio::runtime::Runtime::new().ok()?;
            rt.block_on(get_external_ip())
        }
    }
}

/// Represents an active UPnP port mapping
#[derive(Clone, Debug)]
pub struct UPnPMapping {
    /// External port that was mapped
    pub external_port: u16,
    /// Local port it maps to
    pub local_port: u16,
    /// Protocol (TCP or UDP)
    pub protocol: igd_next::PortMappingProtocol,
    /// External IP address
    pub external_ip: String,
    /// Description of the mapping
    pub description: String,
}

impl UPnPMapping {
    /// Remove this port mapping from the gateway
    pub fn remove(&self) -> Result<(), String> {
        use igd_next::SearchOptions;
        
        let options = SearchOptions::default();
        let gateway = igd_next::search_gateway(options)
            .map_err(|e| format!("Failed to find gateway: {}", e))?;
        
        gateway.remove_port(self.protocol, self.external_port)
            .map_err(|e| format!("Failed to remove port mapping: {}", e))?;
        
        log::info!("Removed UPnP port mapping: {} -> {}", self.external_port, self.local_port);
        Ok(())
    }
}

impl Drop for UPnPMapping {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            log::warn!("Failed to clean up UPnP mapping on drop: {}", e);
        }
    }
}

/// Set up a UPnP port mapping for voice chat
/// Returns the mapping info on success, or uses local IP as fallback
pub fn setup_upnp_mapping(local_port: u16, description: &str) -> Result<UPnPMapping, String> {
    use igd_next::{SearchOptions, PortMappingProtocol};
    use std::net::SocketAddrV4;
    
    log::info!("Setting up UPnP port mapping for port {}", local_port);
    
    let options = SearchOptions {
        timeout: Some(std::time::Duration::from_secs(5)),
        ..Default::default()
    };
    
    let gateway = igd_next::search_gateway(options)
        .map_err(|e| format!("Failed to find UPnP gateway: {}", e))?;
    
    log::info!("Found UPnP gateway: {:?}", gateway);
    
    // Get our local IP to this gateway
    let local_ip = get_local_ip()
        .ok_or_else(|| "Failed to get local IP".to_string())?;
    
    let local_addr_v4: SocketAddrV4 = format!("{}:{}", local_ip, local_port)
        .parse()
        .map_err(|e| format!("Invalid local address: {}", e))?;
    let local_addr: std::net::SocketAddr = local_addr_v4.into();
    
    // Get external IP from gateway
    let external_ip = gateway.get_external_ip()
        .map_err(|e| format!("Failed to get external IP from gateway: {}", e))?;
    
    log::info!("External IP from gateway: {}", external_ip);
    
    // Try to use the same port externally if possible
    let mut external_port = local_port;
    let mut attempts = 0;
    
    loop {
        // Lease duration of 3 hours (in seconds)
        let lease_duration = 3 * 60 * 60;
        
        match gateway.add_port(
            PortMappingProtocol::TCP,
            external_port,
            local_addr,
            lease_duration,
            description,
        ) {
            Ok(()) => {
                log::info!("Successfully created UPnP mapping: external {}:{} -> local {}:{}", 
                    external_ip, external_port, local_ip, local_port);
                
                return Ok(UPnPMapping {
                    external_port,
                    local_port,
                    protocol: PortMappingProtocol::TCP,
                    external_ip: external_ip.to_string(),
                    description: description.to_string(),
                });
            }
            Err(igd_next::AddPortError::PortInUse) => {
                // Try a different port
                attempts += 1;
                if attempts >= 10 {
                    return Err("Failed to find available port after 10 attempts".to_string());
                }
                external_port = external_port.saturating_add(1);
                if external_port < 1024 {
                    external_port = 49152; // Jump to dynamic port range
                }
                log::debug!("Port {} in use, trying {}", external_port - 1, external_port);
            }
            Err(e) => {
                return Err(format!("Failed to add port mapping: {}", e));
            }
        }
    }
}

/// Try to set up UPnP, falling back to local IP if it fails
/// Returns (ip, port, optional_upnp_mapping)
pub fn setup_voice_address(local_port: u16) -> (String, u16, Option<UPnPMapping>) {
    // First try UPnP
    match setup_upnp_mapping(local_port, "NAIS Voice Chat") {
        Ok(mapping) => {
            let ip = mapping.external_ip.clone();
            let port = mapping.external_port;
            log::info!("Using UPnP: {}:{}", ip, port);
            (ip, port, Some(mapping))
        }
        Err(e) => {
            log::warn!("UPnP setup failed: {}, trying external IP service", e);
            
            // Try to get external IP from service
            if let Some(external_ip) = get_external_ip_sync() {
                log::info!("Using external IP (no UPnP): {}:{}", external_ip, local_port);
                log::warn!("Note: You may need to manually forward port {} to this machine", local_port);
                (external_ip, local_port, None)
            } else {
                // Final fallback: local IP
                let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
                log::warn!("Using local IP (NAT may block connections): {}:{}", local_ip, local_port);
                (local_ip, local_port, None)
            }
        }
    }
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
    
    #[test]
    fn test_channel_id_generation() {
        let id1 = generate_channel_id();
        let id2 = generate_channel_id();
        assert!(id1.starts_with("VCHAN"));
        assert_ne!(id1, id2);
    }
    
    #[test]
    fn test_voice_channel_creation() {
        let channel = VoiceChannel::new(
            "TestHost".to_string(),
            "192.168.1.1".to_string(),
            5000,
        );
        
        assert!(channel.channel_id.starts_with("VCHAN"));
        assert_eq!(channel.host, "TestHost");
        assert_eq!(channel.host_ip, "192.168.1.1");
        assert_eq!(channel.host_port, 5000);
        assert_eq!(channel.participants.len(), 1);
        assert!(channel.participants[0].is_host);
        assert_eq!(channel.state, VoiceChannelState::Active);
    }
    
    #[test]
    fn test_voice_channel_add_participant() {
        let mut channel = VoiceChannel::new(
            "TestHost".to_string(),
            "192.168.1.1".to_string(),
            5000,
        );
        
        assert!(channel.add_participant("User1".to_string(), "192.168.1.2".to_string(), 5001));
        assert_eq!(channel.participants.len(), 2);
        
        // Can't add duplicate
        assert!(!channel.add_participant("User1".to_string(), "192.168.1.2".to_string(), 5001));
        assert_eq!(channel.participants.len(), 2);
        
        // Add another
        assert!(channel.add_participant("User2".to_string(), "192.168.1.3".to_string(), 5002));
        assert_eq!(channel.participants.len(), 3);
    }
    
    #[test]
    fn test_voice_channel_remove_participant() {
        let mut channel = VoiceChannel::new(
            "TestHost".to_string(),
            "192.168.1.1".to_string(),
            5000,
        );
        channel.add_participant("User1".to_string(), "192.168.1.2".to_string(), 5001);
        channel.add_participant("User2".to_string(), "192.168.1.3".to_string(), 5002);
        
        assert_eq!(channel.participants.len(), 3);
        assert!(channel.remove_participant("User1"));
        assert_eq!(channel.participants.len(), 2);
        
        // Can't remove non-existent
        assert!(!channel.remove_participant("User1"));
        assert_eq!(channel.participants.len(), 2);
    }
    
    #[test]
    fn test_voice_channel_max_participants() {
        let mut channel = VoiceChannel::new(
            "TestHost".to_string(),
            "192.168.1.1".to_string(),
            5000,
        );
        channel.max_participants = 3;
        
        assert!(channel.add_participant("User1".to_string(), "192.168.1.2".to_string(), 5001));
        assert!(channel.add_participant("User2".to_string(), "192.168.1.3".to_string(), 5002));
        assert!(channel.is_full());
        
        // Can't add when full
        assert!(!channel.add_participant("User3".to_string(), "192.168.1.4".to_string(), 5003));
    }
    
    #[test]
    fn test_voice_channel_invite_ctcp() {
        let ctcp = create_voice_channel_invite_ctcp("VCHAN123", "192.168.1.100", 5000, Some("Test Channel"));
        assert!(ctcp.starts_with('\x01'));
        assert!(ctcp.ends_with('\x01'));
        assert!(ctcp.contains("VOICE_CHANNEL_INVITE"));
        assert!(ctcp.contains("VCHAN123"));
        assert!(ctcp.contains("192.168.1.100"));
        assert!(ctcp.contains("5000"));
        assert!(ctcp.contains("Test Channel"));
        
        let parsed = parse_voice_channel_ctcp(&ctcp);
        assert!(parsed.is_some());
        let (cmd, args) = parsed.unwrap();
        assert_eq!(cmd, CTCP_VOICE_CHANNEL_INVITE);
        assert_eq!(args[0], "VCHAN123");
        assert_eq!(args[1], "192.168.1.100");
        assert_eq!(args[2], "5000");
    }
    
    #[test]
    fn test_voice_channel_join_ctcp() {
        let ctcp = create_voice_channel_join_ctcp("VCHAN123", "192.168.1.50", 6000);
        
        let parsed = parse_voice_channel_ctcp(&ctcp);
        assert!(parsed.is_some());
        let (cmd, args) = parsed.unwrap();
        assert_eq!(cmd, CTCP_VOICE_CHANNEL_JOIN);
        assert_eq!(args[0], "VCHAN123");
        assert_eq!(args[1], "192.168.1.50");
        assert_eq!(args[2], "6000");
    }
    
    #[test]
    fn test_voice_channel_leave_ctcp() {
        let ctcp = create_voice_channel_leave_ctcp("VCHAN123");
        
        let parsed = parse_voice_channel_ctcp(&ctcp);
        assert!(parsed.is_some());
        let (cmd, args) = parsed.unwrap();
        assert_eq!(cmd, CTCP_VOICE_CHANNEL_LEAVE);
        assert_eq!(args[0], "VCHAN123");
    }
    
    #[test]
    fn test_voice_channel_display_name() {
        let channel = VoiceChannel::new(
            "TestHost".to_string(),
            "192.168.1.1".to_string(),
            5000,
        );
        assert_eq!(channel.display_name(), "TestHost's Voice Channel");
        
        let channel_with_name = channel.with_name("Game Night Chat");
        assert_eq!(channel_with_name.display_name(), "Game Night Chat");
    }
}
