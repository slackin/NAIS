//! NAIS Secure Channel Services (SCS)
//!
//! A standalone bot that acts as a persistent host for NAIS Secure Channels.
//! Provides 24/7 availability for channels, key distribution, and message
//! store-and-forward services.
//!
//! Features:
//! - Long-term channel hosting with persistent identity
//! - Message store-and-forward for offline members
//! - Key distribution for new channel members
//! - IRC presence for peer discovery
//! - QUIC transport for secure P2P communication

use bytes::Bytes;
use clap::Parser;
use dashmap::DashMap;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use futures::StreamExt;
use hkdf::Hkdf;
use irc::client::prelude::*;
use quinn::{Connection, Endpoint, ServerConfig};
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// =============================================================================
// Constants
// =============================================================================

/// Protocol version
const PROTOCOL_VERSION: u8 = 0x02;

/// Maximum message size (64KB)
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// How long to keep stored messages
const DEFAULT_MESSAGE_TTL: Duration = Duration::from_secs(7 * 24 * 3600); // 7 days

/// Maximum stored messages per channel
const MAX_STORED_PER_CHANNEL: usize = 10000;

/// Peer timeout
const PEER_TIMEOUT: Duration = Duration::from_secs(120);

/// Statistics reporting interval
const STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Heartbeat interval
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Scs version
const SCS_VERSION: &str = "0.1.0";

// =============================================================================
// Protocol Types
// =============================================================================

/// Message types (matching nsc_transport.rs)
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessageType {
    // Channel Messages
    ChannelMessage = 0x01,
    ChannelAction = 0x02,
    ChannelMetadata = 0x03,

    // Membership
    MemberJoin = 0x10,
    MemberLeave = 0x11,
    MemberUpdate = 0x12,

    // Key Exchange
    KeyPackage = 0x20,
    Welcome = 0x21,
    Commit = 0x22,

    // Control
    Ack = 0x30,
    Heartbeat = 0x31,
    RoutingUpdate = 0x32,

    // NAT Traversal
    IceCandidate = 0x40,
    IceOffer = 0x41,
    IceAnswer = 0x42,

    // Relay
    RelayRequest = 0x50,
    RelayData = 0x51,

    // Scs specific
    ScsInfo = 0x60,
    ScsRegister = 0x61,
    ScsQuery = 0x62,
}

impl MessageType {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::ChannelMessage),
            0x02 => Some(Self::ChannelAction),
            0x03 => Some(Self::ChannelMetadata),
            0x10 => Some(Self::MemberJoin),
            0x11 => Some(Self::MemberLeave),
            0x12 => Some(Self::MemberUpdate),
            0x20 => Some(Self::KeyPackage),
            0x21 => Some(Self::Welcome),
            0x22 => Some(Self::Commit),
            0x30 => Some(Self::Ack),
            0x31 => Some(Self::Heartbeat),
            0x32 => Some(Self::RoutingUpdate),
            0x40 => Some(Self::IceCandidate),
            0x41 => Some(Self::IceOffer),
            0x42 => Some(Self::IceAnswer),
            0x50 => Some(Self::RelayRequest),
            0x51 => Some(Self::RelayData),
            0x60 => Some(Self::ScsInfo),
            0x61 => Some(Self::ScsRegister),
            0x62 => Some(Self::ScsQuery),
            _ => None,
        }
    }
}

/// Peer ID (32-byte hash of public key)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PeerId(pub [u8; 32]);

impl PeerId {
    fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }

    fn from_public_key(public_key: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        Self(id)
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short())
    }
}

/// Channel ID
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ChannelId(pub [u8; 32]);

impl ChannelId {
    fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }

    /// Generate IRC channel name for discovery
    fn to_irc_channel(&self) -> String {
        format!("#nais-{}", &self.to_hex()[..8])
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.short())
    }
}

/// NSC message envelope
struct NscEnvelope {
    version: u8,
    message_type: MessageType,
    flags: u16,
    sender_id: [u8; 32],
    channel_id: [u8; 32],
    sequence_number: u64,
    timestamp: u64,
    payload: Bytes,
    signature: [u8; 64],
}

impl NscEnvelope {
    fn from_bytes(data: Bytes) -> Option<Self> {
        if data.len() < 153 {
            return None;
        }

        let version = data[0];
        if version != PROTOCOL_VERSION {
            log::warn!("Unknown protocol version: {}", version);
        }

        let message_type = MessageType::from_u8(data[1])?;
        let flags = u16::from_be_bytes([data[2], data[3]]);

        let mut sender_id = [0u8; 32];
        sender_id.copy_from_slice(&data[4..36]);

        let mut channel_id = [0u8; 32];
        channel_id.copy_from_slice(&data[36..68]);

        let sequence_number = u64::from_be_bytes([
            data[68], data[69], data[70], data[71], data[72], data[73], data[74], data[75],
        ]);

        let timestamp = u64::from_be_bytes([
            data[76], data[77], data[78], data[79], data[80], data[81], data[82], data[83],
        ]);

        let payload_len = u32::from_be_bytes([data[84], data[85], data[86], data[87]]) as usize;

        if data.len() < 88 + payload_len + 64 {
            return None;
        }

        let payload = data.slice(88..88 + payload_len);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[88 + payload_len..88 + payload_len + 64]);

        Some(Self {
            version,
            message_type,
            flags,
            sender_id,
            channel_id,
            sequence_number,
            timestamp,
            payload,
            signature,
        })
    }

    fn to_bytes(&self) -> Bytes {
        let mut buf = Vec::with_capacity(152 + self.payload.len());

        buf.push(self.version);
        buf.push(self.message_type as u8);
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.sender_id);
        buf.extend_from_slice(&self.channel_id);
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&self.signature);

        Bytes::from(buf)
    }

    fn sign(&mut self, signing_key: &SigningKey) {
        let data = self.to_signing_data();
        let sig = signing_key.sign(&data);
        self.signature = sig.to_bytes();
    }

    fn to_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.version);
        data.push(self.message_type as u8);
        data.extend_from_slice(&self.flags.to_be_bytes());
        data.extend_from_slice(&self.sender_id);
        data.extend_from_slice(&self.channel_id);
        data.extend_from_slice(&self.sequence_number.to_be_bytes());
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        data.extend_from_slice(&self.payload);
        data
    }
}

// =============================================================================
// Configuration
// =============================================================================

/// Main configuration structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScsConfig {
    /// Bot nickname
    #[serde(default = "default_nickname")]
    pub nickname: String,

    /// Display name
    #[serde(default = "default_display_name")]
    pub display_name: String,

    /// Bind address for QUIC server
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Relay hub address for NAT traversal fallback
    #[serde(default)]
    pub relay_hub: Option<String>,

    /// IRC configuration
    #[serde(default)]
    pub irc: IrcConfig,

    /// Storage configuration
    #[serde(default)]
    pub storage: StorageConfig,

    /// Hosted channels
    #[serde(default)]
    pub channels: Vec<HostedChannelConfig>,
}

fn default_nickname() -> String {
    "SCS".into()
}

fn default_display_name() -> String {
    "NAIS Secure Channel Services".into()
}

fn default_bind_address() -> String {
    "0.0.0.0:4434".into()
}

impl Default for ScsConfig {
    fn default() -> Self {
        Self {
            nickname: default_nickname(),
            display_name: default_display_name(),
            bind_address: default_bind_address(),
            relay_hub: None,
            irc: IrcConfig::default(),
            storage: StorageConfig::default(),
            channels: Vec::new(),
        }
    }
}

/// IRC connection configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IrcConfig {
    /// IRC server address
    #[serde(default = "default_irc_server")]
    pub server: String,

    /// IRC server port
    #[serde(default = "default_irc_port")]
    pub port: u16,

    /// Use TLS
    #[serde(default = "default_use_tls")]
    pub use_tls: bool,

    /// IRC nickname
    #[serde(default = "default_irc_nick")]
    pub nick: String,

    /// Alternative nicknames to try if primary is taken
    #[serde(default = "default_alt_nicks")]
    pub alt_nicks: Vec<String>,

    /// IRC channels to join (for presence)
    #[serde(default)]
    pub channels: Vec<String>,
}

fn default_irc_server() -> String {
    "irc.pugbot.net".into()
}

fn default_irc_port() -> u16 {
    6697
}

fn default_use_tls() -> bool {
    true
}

fn default_irc_nick() -> String {
    "Convey-SCS".into()
}

fn default_alt_nicks() -> Vec<String> {
    vec![
        "NAIS-CS".into(),
        "NAIS-Services".into(),
        "NAIS-CS2".into(),
        "ConveySCS".into(),
    ]
}

impl Default for IrcConfig {
    fn default() -> Self {
        Self {
            server: default_irc_server(),
            port: default_irc_port(),
            use_tls: default_use_tls(),
            nick: default_irc_nick(),
            alt_nicks: default_alt_nicks(),
            channels: vec!["#nais-scs".into()],
        }
    }
}

/// Storage configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Data directory
    #[serde(default = "default_data_dir")]
    pub data_dir: String,

    /// Message TTL in days
    #[serde(default = "default_message_ttl_days")]
    pub message_ttl_days: u32,

    /// Maximum messages per channel
    #[serde(default = "default_max_messages")]
    pub max_messages_per_channel: usize,
}

fn default_data_dir() -> String {
    "~/.nais-scs".into()
}

fn default_message_ttl_days() -> u32 {
    7
}

fn default_max_messages() -> usize {
    10000
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            message_ttl_days: default_message_ttl_days(),
            max_messages_per_channel: default_max_messages(),
        }
    }
}

/// Hosted channel configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostedChannelConfig {
    /// Channel name
    pub name: String,

    /// Channel topic
    #[serde(default)]
    pub topic: String,

    /// Auto-register if not exists
    #[serde(default)]
    pub auto_register: bool,

    /// Channel ID (hex) - if empty, will be generated
    #[serde(default)]
    pub channel_id: Option<String>,
}

// =============================================================================
// Identity Management
// =============================================================================

/// SCS's cryptographic identity
#[derive(Clone)]
struct ScsIdentity {
    /// Ed25519 signing key
    signing_key: SigningKey,
    /// Verifying key (public)
    verifying_key: VerifyingKey,
    /// Peer ID (hash of public key)
    peer_id: PeerId,
    /// Display name
    display_name: String,
}

impl ScsIdentity {
    /// Create new identity
    fn new(display_name: String) -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let public_bytes = verifying_key.to_bytes();
        let peer_id = PeerId::from_public_key(&public_bytes);

        Self {
            signing_key,
            verifying_key,
            peer_id,
            display_name,
        }
    }

    /// Load from stored data
    fn from_stored(stored: &StoredIdentity) -> Option<Self> {
        let key_bytes = hex::decode(&stored.private_key).ok()?;
        if key_bytes.len() != 32 {
            return None;
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);

        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();
        let public_bytes = verifying_key.to_bytes();
        let peer_id = PeerId::from_public_key(&public_bytes);

        Some(Self {
            signing_key,
            verifying_key,
            peer_id,
            display_name: stored.display_name.clone(),
        })
    }

    /// Convert to stored format
    fn to_stored(&self) -> StoredIdentity {
        StoredIdentity {
            private_key: hex::encode(self.signing_key.to_bytes()),
            public_key: hex::encode(self.verifying_key.to_bytes()),
            display_name: self.display_name.clone(),
            peer_id: self.peer_id.to_hex(),
            created_at: now_millis(),
        }
    }

    /// Get public key bytes
    fn public_key(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Sign data
    fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }
}

/// Stored identity format
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredIdentity {
    private_key: String,
    public_key: String,
    display_name: String,
    peer_id: String,
    created_at: u64,
}

// =============================================================================
// Channel State
// =============================================================================

/// Epoch secrets for a channel (simplified MLS-lite)
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EpochSecrets {
    /// Current epoch number
    epoch: u64,
    /// Application secret for message encryption
    application_secret: [u8; 32],
    /// Confirmation key for membership changes
    confirmation_key: [u8; 32],
    /// Membership key
    membership_key: [u8; 32],
    /// When this epoch started
    epoch_start: u64,
}

impl EpochSecrets {
    /// Create new epoch secrets
    fn new(epoch: u64) -> Self {
        let mut rng = rand::thread_rng();
        let mut application_secret = [0u8; 32];
        let mut confirmation_key = [0u8; 32];
        let mut membership_key = [0u8; 32];

        rng.fill_bytes(&mut application_secret);
        rng.fill_bytes(&mut confirmation_key);
        rng.fill_bytes(&mut membership_key);

        Self {
            epoch,
            application_secret,
            confirmation_key,
            membership_key,
            epoch_start: now_millis(),
        }
    }

    /// Derive message key for a specific sequence
    fn derive_message_key(&self, sequence: u64) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.application_secret);
        let info = format!("message-key-{}", sequence);
        let mut key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut key).unwrap();
        key
    }

    /// Advance to next epoch
    fn advance(&self) -> Self {
        let hk = Hkdf::<Sha256>::new(None, &self.application_secret);

        let mut new_app_secret = [0u8; 32];
        let mut new_conf_key = [0u8; 32];
        let mut new_member_key = [0u8; 32];

        hk.expand(b"next-application-secret", &mut new_app_secret)
            .unwrap();
        hk.expand(b"next-confirmation-key", &mut new_conf_key)
            .unwrap();
        hk.expand(b"next-membership-key", &mut new_member_key)
            .unwrap();

        Self {
            epoch: self.epoch + 1,
            application_secret: new_app_secret,
            confirmation_key: new_conf_key,
            membership_key: new_member_key,
            epoch_start: now_millis(),
        }
    }
}

/// Channel member information
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChannelMember {
    /// Member's peer ID
    peer_id: String,
    /// Display name
    display_name: String,
    /// Public key (hex)
    public_key: String,
    /// Role (owner, admin, member)
    role: String,
    /// When joined
    joined_at: u64,
    /// Last seen
    last_seen: u64,
    /// Is online
    online: bool,
}

/// Channel metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChannelMetadata {
    /// Channel ID (hex)
    channel_id: String,
    /// Channel name
    name: String,
    /// Topic
    topic: String,
    /// Creator peer ID (hex)
    creator: String,
    /// Created timestamp
    created_at: u64,
    /// Current version
    version: u64,
    /// Admin peer IDs
    admins: Vec<String>,
    /// IRC channel for discovery
    irc_channel: String,
}

/// Hosted channel state
struct HostedChannel {
    /// Channel ID
    channel_id: ChannelId,
    /// Channel metadata
    metadata: ChannelMetadata,
    /// Current epoch secrets
    epoch_secrets: EpochSecrets,
    /// Channel members
    members: HashMap<String, ChannelMember>,
    /// Message sequence counter
    message_sequence: u64,
    /// Stored messages for offline delivery
    stored_messages: VecDeque<StoredMessage>,
    /// Message TTL
    message_ttl: Duration,
    /// Maximum stored messages
    max_messages: usize,
}

impl HostedChannel {
    fn new(channel_id: ChannelId, metadata: ChannelMetadata,  config: &StorageConfig) -> Self {
        Self {
            channel_id,
            metadata,
            epoch_secrets: EpochSecrets::new(1),
            members: HashMap::new(),
            message_sequence: 0,
            stored_messages: VecDeque::new(),
            message_ttl: Duration::from_secs(config.message_ttl_days as u64 * 24 * 3600),
            max_messages: config.max_messages_per_channel,
        }
    }

    /// Add a member
    fn add_member(&mut self, member: ChannelMember) {
        self.members.insert(member.peer_id.clone(), member);
    }

    /// Remove a member
    fn remove_member(&mut self, peer_id: &str) {
        self.members.remove(peer_id);
    }

    /// Store a message for offline delivery
    fn store_message(&mut self, msg: StoredMessage) {
        while self.stored_messages.len() >= self.max_messages {
            self.stored_messages.pop_front();
        }
        self.stored_messages.push_back(msg);
    }

    /// Get messages for a peer that joined after a certain sequence
    fn get_messages_after(&self, since_sequence: u64) -> Vec<&StoredMessage> {
        self.stored_messages
            .iter()
            .filter(|m| m.sequence > since_sequence)
            .collect()
    }

    /// Clean expired messages
    fn cleanup_messages(&mut self) {
        let now = Instant::now();
        self.stored_messages.retain(|m| !m.is_expired(now));
    }

    /// Advance epoch (key rotation)
    fn advance_epoch(&mut self) {
        self.epoch_secrets = self.epoch_secrets.advance();
        log::info!(
            "Channel {} advanced to epoch {}",
            self.channel_id,
            self.epoch_secrets.epoch
        );
    }

    /// Convert to stored format
    fn to_stored(&self) -> StoredChannel {
        StoredChannel {
            channel_id: self.channel_id.to_hex(),
            metadata: self.metadata.clone(),
            epoch_secrets: self.epoch_secrets.clone(),
            members: self.members.values().cloned().collect(),
            message_sequence: self.message_sequence,
        }
    }

    /// Load from stored format
    fn from_stored(stored: StoredChannel, config: &StorageConfig) -> Option<Self> {
        let channel_id_bytes = hex::decode(&stored.channel_id).ok()?;
        if channel_id_bytes.len() != 32 {
            return None;
        }
        let mut channel_id = [0u8; 32];
        channel_id.copy_from_slice(&channel_id_bytes);

        let mut members = HashMap::new();
        for member in stored.members {
            members.insert(member.peer_id.clone(), member);
        }

        Some(Self {
            channel_id: ChannelId(channel_id),
            metadata: stored.metadata,
            epoch_secrets: stored.epoch_secrets,
            members,
            message_sequence: stored.message_sequence,
            stored_messages: VecDeque::new(),
            message_ttl: Duration::from_secs(config.message_ttl_days as u64 * 24 * 3600),
            max_messages: config.max_messages_per_channel,
        })
    }
}

/// Stored message
#[derive(Clone, Debug)]
struct StoredMessage {
    /// Sender peer ID
    sender: PeerId,
    /// Message sequence number
    sequence: u64,
    /// Timestamp
    timestamp: u64,
    /// Encrypted payload
    encrypted_payload: Vec<u8>,
    /// When stored (for TTL)
    stored_at: Instant,
    /// Expiry time
    expires_at: Instant,
}

impl StoredMessage {
    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Stored channel format for persistence
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredChannel {
    channel_id: String,
    metadata: ChannelMetadata,
    epoch_secrets: EpochSecrets,
    members: Vec<ChannelMember>,
    message_sequence: u64,
}

// =============================================================================
// Connected Peer State
// =============================================================================

/// A peer connected via QUIC
struct ConnectedPeer {
    /// Peer ID
    peer_id: PeerId,
    /// QUIC connection
    connection: Connection,
    /// Remote address
    remote_addr: SocketAddr,
    /// Channels this peer is subscribed to
    channels: Vec<ChannelId>,
    /// Connected at
    connected_at: Instant,
    /// Last activity
    last_activity: Instant,
    /// Messages sent
    messages_sent: u64,
}

// =============================================================================
// Scs Storage
// =============================================================================

/// Persistent storage for SCS
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ScsStorage {
    /// Our identity
    identity: Option<StoredIdentity>,
    /// Hosted channels
    channels: Vec<StoredChannel>,
}

impl ScsStorage {
    fn load(data_dir: &PathBuf) -> Self {
        let path = data_dir.join("scs.json");
        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(storage) => return storage,
                    Err(e) => log::warn!("Failed to parse storage: {}", e),
                },
                Err(e) => log::warn!("Failed to read storage: {}", e),
            }
        }
        Self::default()
    }

    fn save(&self, data_dir: &PathBuf) -> Result<(), String> {
        fs::create_dir_all(data_dir).map_err(|e| format!("Failed to create data dir: {}", e))?;

        let path = data_dir.join("scs.json");
        let content =
            serde_json::to_string_pretty(self).map_err(|e| format!("Failed to serialize: {}", e))?;
        fs::write(&path, content).map_err(|e| format!("Failed to write storage: {}", e))?;
        Ok(())
    }
}

// =============================================================================
// Scs Bot
// =============================================================================

/// Statistics
#[derive(Default)]
struct ScsStats {
    /// Total connections received
    total_connections: u64,
    /// Currently connected peers
    active_peers: u64,
    /// Total messages relayed
    messages_relayed: u64,
    /// Messages stored
    messages_stored: u64,
    /// Total hosted channels
    hosted_channels: u64,
    /// Uptime start
    started_at: u64,
}

/// The Scs bot
struct Scs {
    /// Configuration
    config: ScsConfig,
    /// Our identity
    identity: ScsIdentity,
    /// Data directory
    data_dir: PathBuf,
    /// Connected peers
    peers: DashMap<PeerId, ConnectedPeer>,
    /// Peers by address
    addr_to_peer: DashMap<SocketAddr, PeerId>,
    /// Hosted channels
    channels: RwLock<HashMap<ChannelId, HostedChannel>>,
    /// Channel ID to IRC channel mapping
    irc_channels: RwLock<HashMap<String, ChannelId>>,
    /// Statistics
    stats: RwLock<ScsStats>,
    /// IRC client sender (for sending messages)
    irc_sender: RwLock<Option<irc::client::Sender>>,
}

impl Scs {
    /// Create new Scs instance
    async fn new(config: ScsConfig) -> Arc<Self> {
        // Resolve data directory
        let data_dir = if config.storage.data_dir.starts_with("~") {
            dirs::home_dir()
                .unwrap_or_default()
                .join(&config.storage.data_dir[2..])
        } else {
            PathBuf::from(&config.storage.data_dir)
        };

        // Load or create identity
        let storage = ScsStorage::load(&data_dir);
        let identity = if let Some(stored) = &storage.identity {
            ScsIdentity::from_stored(stored)
                .unwrap_or_else(|| ScsIdentity::new(config.display_name.clone()))
        } else {
            ScsIdentity::new(config.display_name.clone())
        };

        log::info!("Scs identity: {}", identity.peer_id);

        // Load channels
        let mut channels_map = HashMap::new();
        let mut irc_channels_map = HashMap::new();

        for stored in storage.channels {
            if let Some(channel) = HostedChannel::from_stored(stored, &config.storage) {
                let irc_channel = channel.channel_id.to_irc_channel();
                irc_channels_map.insert(irc_channel, channel.channel_id);
                log::info!("Loaded hosted channel: {}", channel.channel_id);
                channels_map.insert(channel.channel_id, channel);
            }
        }

        // Create configured channels that don't exist
        for ch_config in &config.channels {
            if ch_config.auto_register {
                // Check if already exists by name
                let exists = channels_map
                    .values()
                    .any(|c| c.metadata.name == ch_config.name);

                if !exists {
                    // Create new channel
                    let channel_id = if let Some(id_hex) = &ch_config.channel_id {
                        if let Ok(bytes) = hex::decode(id_hex) {
                            if bytes.len() == 32 {
                                let mut id = [0u8; 32];
                                id.copy_from_slice(&bytes);
                                ChannelId(id)
                            } else {
                                generate_channel_id(&ch_config.name, &identity.peer_id)
                            }
                        } else {
                            generate_channel_id(&ch_config.name, &identity.peer_id)
                        }
                    } else {
                        generate_channel_id(&ch_config.name, &identity.peer_id)
                    };

                    let metadata = ChannelMetadata {
                        channel_id: channel_id.to_hex(),
                        name: ch_config.name.clone(),
                        topic: ch_config.topic.clone(),
                        creator: identity.peer_id.to_hex(),
                        created_at: now_millis(),
                        version: 1,
                        admins: vec![identity.peer_id.to_hex()],
                        irc_channel: channel_id.to_irc_channel(),
                    };

                    let channel = HostedChannel::new(channel_id, metadata, &config.storage);
                    let irc_channel = channel_id.to_irc_channel();

                    log::info!(
                        "Created new channel: {} ({})",
                        ch_config.name,
                        channel_id
                    );

                    irc_channels_map.insert(irc_channel, channel_id);
                    channels_map.insert(channel_id, channel);
                }
            }
        }

        let bot = Arc::new(Self {
            config,
            identity,
            data_dir,
            peers: DashMap::new(),
            addr_to_peer: DashMap::new(),
            channels: RwLock::new(channels_map),
            irc_channels: RwLock::new(irc_channels_map),
            stats: RwLock::new(ScsStats {
                started_at: now_millis(),
                ..Default::default()
            }),
            irc_sender: RwLock::new(None),
        });

        // Save initial state
        if let Err(e) = bot.save_state().await {
            log::warn!("Failed to save initial state: {}", e);
        }

        // Update stats
        bot.stats.write().await.hosted_channels = bot.channels.read().await.len() as u64;

        bot
    }

    /// Save current state to disk
    async fn save_state(&self) -> Result<(), String> {
        let channels: Vec<StoredChannel> = self
            .channels
            .read()
            .await
            .values()
            .map(|c| c.to_stored())
            .collect();

        let storage = ScsStorage {
            identity: Some(self.identity.to_stored()),
            channels,
        };

        storage.save(&self.data_dir)
    }

    /// Register a peer connection
    async fn register_peer(
        &self,
        peer_id: PeerId,
        connection: Connection,
        channels: Vec<ChannelId>,
    ) {
        let remote_addr = connection.remote_address();
        let now = Instant::now();

        // Remove old registration
        if let Some((_, old)) = self.peers.remove(&peer_id) {
            old.connection.close(0u32.into(), b"re-registering");
            self.addr_to_peer.remove(&old.remote_addr);
        }

        let peer = ConnectedPeer {
            peer_id,
            connection,
            remote_addr,
            channels,
            connected_at: now,
            last_activity: now,
            messages_sent: 0,
        };

        self.peers.insert(peer_id, peer);
        self.addr_to_peer.insert(remote_addr, peer_id);

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_connections += 1;
            stats.active_peers = self.peers.len() as u64;
        }

        log::info!("Peer {} connected from {}", peer_id, remote_addr);

        // Send any stored messages for channels this peer subscribes to
        self.deliver_stored_messages(peer_id).await;
    }

    /// Unregister a peer
    async fn unregister_peer(&self, remote_addr: SocketAddr) {
        if let Some((_, peer_id)) = self.addr_to_peer.remove(&remote_addr) {
            if let Some((_, peer)) = self.peers.remove(&peer_id) {
                log::info!(
                    "Peer {} disconnected (sent {} messages)",
                    peer_id,
                    peer.messages_sent
                );
            }
        }

        // Update stats
        self.stats.write().await.active_peers = self.peers.len() as u64;
    }

    /// Deliver stored messages to a peer
    async fn deliver_stored_messages(&self, peer_id: PeerId) {
        let peer_channels: Vec<ChannelId> = self
            .peers
            .get(&peer_id)
            .map(|p| p.channels.clone())
            .unwrap_or_default();

        if peer_channels.is_empty() {
            return;
        }

        // Get messages from subscribed channels
        let channels = self.channels.read().await;
        for channel_id in peer_channels {
            if let Some(channel) = channels.get(&channel_id) {
                // In a real implementation, we'd track each peer's last received sequence
                // For now, send all recent messages
                let messages = channel.get_messages_after(0);
                if !messages.is_empty() {
                    log::info!(
                        "Delivering {} stored messages to {} for channel {}",
                        messages.len(),
                        peer_id,
                        channel_id
                    );
                    // Would send messages here via the peer's connection
                }
            }
        }
    }

    /// Handle a message from a peer
    async fn handle_message(&self, from: PeerId, envelope: NscEnvelope) {
        let channel_id = ChannelId(envelope.channel_id);

        // Update peer activity
        if let Some(mut peer) = self.peers.get_mut(&from) {
            peer.last_activity = Instant::now();
        }

        match envelope.message_type {
            MessageType::ChannelMessage | MessageType::ChannelAction => {
                // Store and relay the message
                self.handle_channel_message(from, channel_id, envelope).await;
            }
            MessageType::MemberJoin => {
                self.handle_member_join(from, channel_id, envelope).await;
            }
            MessageType::MemberLeave => {
                self.handle_member_leave(from, channel_id).await;
            }
            MessageType::KeyPackage => {
                // Handle key package (for new member setup)
                self.handle_key_package(from, channel_id, envelope).await;
            }
            MessageType::ChannelMetadata => {
                self.handle_metadata_update(from, channel_id, envelope).await;
            }
            MessageType::ScsQuery => {
                self.handle_query(from, envelope).await;
            }
            MessageType::Heartbeat => {
                // Already updated activity above
            }
            _ => {
                log::debug!("Ignoring message type {:?} from {}", envelope.message_type, from);
            }
        }
    }

    /// Handle channel message (store and relay)
    async fn handle_channel_message(&self, from: PeerId, channel_id: ChannelId, envelope: NscEnvelope) {
        let mut channels = self.channels.write().await;
        
        if let Some(channel) = channels.get_mut(&channel_id) {
            // Increment sequence
            channel.message_sequence += 1;
            let sequence = channel.message_sequence;

            // Store message
            let stored_msg = StoredMessage {
                sender: from,
                sequence,
                timestamp: envelope.timestamp,
                encrypted_payload: envelope.payload.to_vec(),
                stored_at: Instant::now(),
                expires_at: Instant::now() + channel.message_ttl,
            };
            channel.store_message(stored_msg);

            // Update stats
            self.stats.write().await.messages_stored += 1;

            // Relay to other connected members
            let members: Vec<String> = channel.members.keys().cloned().collect();
            drop(channels); // Release lock before sending

            for member_id in members {
                if let Ok(bytes) = hex::decode(&member_id) {
                    if bytes.len() == 32 {
                        let mut peer_id_bytes = [0u8; 32];
                        peer_id_bytes.copy_from_slice(&bytes);
                        let peer_id = PeerId(peer_id_bytes);

                        // Don't send back to sender
                        if peer_id != from {
                            if let Some(peer) = self.peers.get(&peer_id) {
                                if let Err(e) = self.send_to_peer(&peer.connection, &envelope).await {
                                    log::warn!("Failed to relay to {}: {}", peer_id, e);
                                } else {
                                    self.stats.write().await.messages_relayed += 1;
                                }
                            }
                        }
                    }
                }
            }

            log::debug!(
                "Relayed message from {} in channel {} (seq {})",
                from,
                channel_id,
                sequence
            );
        } else {
            log::warn!("Message for unknown channel {} from {}", channel_id, from);
        }
    }

    /// Handle member join
    async fn handle_member_join(&self, from: PeerId, channel_id: ChannelId, envelope: NscEnvelope) {
        let mut channels = self.channels.write().await;

        if let Some(channel) = channels.get_mut(&channel_id) {
            // Parse member info from payload
            if let Ok(member_info) = serde_json::from_slice::<ChannelMember>(&envelope.payload) {
                channel.add_member(member_info.clone());
                log::info!(
                    "Member {} joined channel {} (invited by {})",
                    member_info.display_name,
                    channel_id,
                    from
                );

                // Save state
                drop(channels);
                if let Err(e) = self.save_state().await {
                    log::warn!("Failed to save state after member join: {}", e);
                }

                // Send welcome with epoch secrets
                // In real implementation, would encrypt epoch secrets for the new member
            }
        }
    }

    /// Handle member leave
    async fn handle_member_leave(&self, from: PeerId, channel_id: ChannelId) {
        let mut channels = self.channels.write().await;

        if let Some(channel) = channels.get_mut(&channel_id) {
            channel.remove_member(&from.to_hex());
            log::info!("Member {} left channel {}", from, channel_id);

            // Advance epoch for forward secrecy
            channel.advance_epoch();

            // Save state
            drop(channels);
            if let Err(e) = self.save_state().await {
                log::warn!("Failed to save state after member leave: {}", e);
            }
        }
    }

    /// Handle key package
    async fn handle_key_package(&self, from: PeerId, channel_id: ChannelId, envelope: NscEnvelope) {
        let channels = self.channels.read().await;

        if let Some(channel) = channels.get(&channel_id) {
            // Store key package for the member
            log::debug!(
                "Received key package from {} for channel {}",
                from,
                channel_id
            );

            // In real implementation, would store and distribute key packages
            // to facilitate new member key exchange
            let _ = (channel, envelope);
        }
    }

    /// Handle metadata update
    async fn handle_metadata_update(&self, from: PeerId, channel_id: ChannelId, envelope: NscEnvelope) {
        let mut channels = self.channels.write().await;

        if let Some(channel) = channels.get_mut(&channel_id) {
            // Verify sender is authorized
            if !channel.metadata.admins.contains(&from.to_hex()) && channel.metadata.creator != from.to_hex() {
                log::warn!("Unauthorized metadata update from {} for {}", from, channel_id);
                return;
            }

            // Parse and apply update
            if let Ok(new_metadata) = serde_json::from_slice::<ChannelMetadata>(&envelope.payload) {
                if new_metadata.version > channel.metadata.version {
                    channel.metadata = new_metadata;
                    log::info!("Updated metadata for channel {} (v{})", channel_id, channel.metadata.version);

                    // Save state
                    drop(channels);
                    if let Err(e) = self.save_state().await {
                        log::warn!("Failed to save state after metadata update: {}", e);
                    }
                }
            }
        }
    }

    /// Handle query from peer
    async fn handle_query(&self, from: PeerId, envelope: NscEnvelope) {
        // Parse query
        if let Ok(query) = String::from_utf8(envelope.payload.to_vec()) {
            log::debug!("Query from {}: {}", from, query);

            match query.as_str() {
                "INFO" => {
                    // Send bot info
                    self.send_info_response(from).await;
                }
                "CHANNELS" => {
                    // Send list of hosted channels
                    self.send_channels_response(from).await;
                }
                _ if query.starts_with("JOIN ") => {
                    // Join request for a channel
                    let channel_id_hex = &query[5..];
                    self.handle_join_request(from, channel_id_hex).await;
                }
                _ => {
                    log::debug!("Unknown query: {}", query);
                }
            }
        }
    }

    /// Send info response
    async fn send_info_response(&self, to: PeerId) {
        let info = serde_json::json!({
            "version": SCS_VERSION,
            "peer_id": self.identity.peer_id.to_hex(),
            "display_name": self.identity.display_name,
            "channels": self.channels.read().await.len(),
            "uptime": now_millis() - self.stats.read().await.started_at,
        });

        if let Some(peer) = self.peers.get(&to) {
            let mut envelope = NscEnvelope {
                version: PROTOCOL_VERSION,
                message_type: MessageType::ScsInfo,
                flags: 0,
                sender_id: self.identity.public_key(),
                channel_id: [0u8; 32],
                sequence_number: 0,
                timestamp: now_millis(),
                payload: Bytes::from(info.to_string()),
                signature: [0u8; 64],
            };
            envelope.sign(&self.identity.signing_key);

            if let Err(e) = self.send_to_peer(&peer.connection, &envelope).await {
                log::warn!("Failed to send info to {}: {}", to, e);
            }
        }
    }

    /// Send channels list response
    async fn send_channels_response(&self, to: PeerId) {
        let channels: Vec<serde_json::Value> = self
            .channels
            .read()
            .await
            .values()
            .map(|c| {
                serde_json::json!({
                    "channel_id": c.channel_id.to_hex(),
                    "name": c.metadata.name,
                    "topic": c.metadata.topic,
                    "members": c.members.len(),
                    "irc_channel": c.metadata.irc_channel,
                })
            })
            .collect();

        if let Some(peer) = self.peers.get(&to) {
            let mut envelope = NscEnvelope {
                version: PROTOCOL_VERSION,
                message_type: MessageType::ScsInfo,
                flags: 0,
                sender_id: self.identity.public_key(),
                channel_id: [0u8; 32],
                sequence_number: 0,
                timestamp: now_millis(),
                payload: Bytes::from(serde_json::to_string(&channels).unwrap()),
                signature: [0u8; 64],
            };
            envelope.sign(&self.identity.signing_key);

            if let Err(e) = self.send_to_peer(&peer.connection, &envelope).await {
                log::warn!("Failed to send channels to {}: {}", to, e);
            }
        }
    }

    /// Handle join request
    async fn handle_join_request(&self, from: PeerId, channel_id_hex: &str) {
        let channels = self.channels.read().await;

        if let Ok(bytes) = hex::decode(channel_id_hex) {
            if bytes.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                let channel_id = ChannelId(id);

                if let Some(channel) = channels.get(&channel_id) {
                    // Send welcome with epoch secrets
                    log::info!("Processing join request from {} for {}", from, channel_id);

                    // In real implementation:
                    // 1. Verify peer identity
                    // 2. Encrypt epoch secrets for peer
                    // 3. Send Welcome message
                    // 4. Add to members
                    let _ = channel;
                }
            }
        }
    }

    /// Send envelope to peer
    async fn send_to_peer(&self, conn: &Connection, envelope: &NscEnvelope) -> Result<(), String> {
        let mut send = conn
            .open_uni()
            .await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        let data = envelope.to_bytes();
        send.write_all(&(data.len() as u32).to_be_bytes())
            .await
            .map_err(|e| format!("Failed to write length: {}", e))?;
        send.write_all(&data)
            .await
            .map_err(|e| format!("Failed to write data: {}", e))?;
        send.finish()
            .map_err(|e| format!("Failed to finish stream: {}", e))?;

        Ok(())
    }

    /// Handle incoming connections
    async fn handle_connection(self: Arc<Self>, connection: Connection) {
        let remote_addr = connection.remote_address();
        log::debug!("New connection from {}", remote_addr);

        loop {
            match connection.accept_uni().await {
                Ok(mut recv) => {
                    // Read length prefix
                    let mut len_buf = [0u8; 4];
                    if recv.read_exact(&mut len_buf).await.is_err() {
                        continue;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len > MAX_MESSAGE_SIZE {
                        log::warn!("Message too large from {}: {} bytes", remote_addr, len);
                        continue;
                    }

                    // Read message
                    let mut buf = vec![0u8; len];
                    if recv.read_exact(&mut buf).await.is_err() {
                        continue;
                    }

                    // Parse envelope
                    let envelope = match NscEnvelope::from_bytes(Bytes::from(buf)) {
                        Some(env) => env,
                        None => {
                            log::warn!("Invalid envelope from {}", remote_addr);
                            continue;
                        }
                    };

                    let sender_id = PeerId(envelope.sender_id);

                    // Handle registration
                    if envelope.message_type == MessageType::RelayRequest {
                        // Parse channel subscriptions from payload
                        let channels = parse_channel_subscriptions(&envelope.payload);
                        self.register_peer(sender_id, connection.clone(), channels)
                            .await;
                        continue;
                    }

                    // Handle other messages
                    self.handle_message(sender_id, envelope).await;
                }
                Err(e) => {
                    log::debug!("Connection closed from {}: {}", remote_addr, e);
                    break;
                }
            }
        }

        // Cleanup on disconnect
        self.unregister_peer(remote_addr).await;
    }

    /// Periodic cleanup task
    async fn cleanup_task(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            // Clean expired messages
            {
                let mut channels = self.channels.write().await;
                for channel in channels.values_mut() {
                    channel.cleanup_messages();
                }
            }

            // Check for stale peers
            let now = Instant::now();
            let stale: Vec<SocketAddr> = self
                .peers
                .iter()
                .filter(|p| now.duration_since(p.last_activity) > PEER_TIMEOUT)
                .map(|p| p.remote_addr)
                .collect();

            for addr in stale {
                log::info!("Removing stale peer at {}", addr);
                self.unregister_peer(addr).await;
            }

            // Save state periodically
            if let Err(e) = self.save_state().await {
                log::warn!("Failed to save state: {}", e);
            }
        }
    }

    /// Statistics reporting task
    async fn stats_task(self: Arc<Self>) {
        let mut interval = tokio::time::interval(STATS_INTERVAL);

        loop {
            interval.tick().await;

            let stats = self.stats.read().await;
            let channels = self.channels.read().await;

            let total_members: usize = channels.values().map(|c| c.members.len()).sum();
            let total_stored: usize = channels.values().map(|c| c.stored_messages.len()).sum();

            log::info!(
                "Scs Stats: {} channels, {} members, {} peers, {} relayed, {} stored ({} pending)",
                channels.len(),
                total_members,
                stats.active_peers,
                stats.messages_relayed,
                stats.messages_stored,
                total_stored
            );
        }
    }

    /// IRC client task for peer discovery
    async fn irc_task(self: Arc<Self>) {
        loop {
            if let Err(e) = self.run_irc().await {
                log::warn!("IRC connection error: {}", e);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }

    /// Run IRC client
    async fn run_irc(&self) -> Result<(), String> {
        let irc_config = Config {
            nickname: Some(self.config.irc.nick.clone()),
            alt_nicks: self.config.irc.alt_nicks.clone(),
            server: Some(self.config.irc.server.clone()),
            port: Some(self.config.irc.port),
            use_tls: Some(self.config.irc.use_tls),
            channels: self.config.irc.channels.clone(),
            ..Config::default()
        };

        let mut client = Client::from_config(irc_config)
            .await
            .map_err(|e| format!("IRC client error: {}", e))?;

        client
            .identify()
            .map_err(|e| format!("IRC identify error: {}", e))?;

        // Store sender for outgoing messages
        *self.irc_sender.write().await = Some(client.sender());

        // NOTE: NAIS channel JOINs are deferred to handle_irc_message()
        // when we receive RPL_ENDOFMOTD/ERR_NOMOTD, because the server
        // ignores JOIN commands sent before registration completes.

        log::info!("IRC connected to {}", self.config.irc.server);

        let mut stream = client.stream().map_err(|e| format!("IRC stream error: {}", e))?;

        while let Some(message) = stream.next().await.transpose().map_err(|e| e.to_string())? {
            self.handle_irc_message(&message).await;
        }

        log::warn!("IRC stream ended");
        *self.irc_sender.write().await = None;

        Ok(())
    }

    /// Handle IRC message
    async fn handle_irc_message(&self, message: &Message) {
        match &message.command {
            Command::PRIVMSG(target, text) => {
                let source = message.source_nickname().unwrap_or("unknown");

                // Check for CTCP
                if text.starts_with('\x01') && text.ends_with('\x01') {
                    let ctcp = &text[1..text.len() - 1];
                    self.handle_ctcp(source, target, ctcp).await;
                    return;
                }

                // Check for direct commands (when messaged directly)
                if target == &self.config.irc.nick {
                    self.handle_irc_command(source, text).await;
                }
            }
            Command::JOIN(channel, _, _) => {
                let nick = message.source_nickname().unwrap_or("unknown");
                if nick != self.config.irc.nick {
                    // Someone joined a channel we're in
                    self.handle_irc_join(nick, channel).await;
                }
            }
            Command::PART(channel, _) => {
                let nick = message.source_nickname().unwrap_or("unknown");
                if nick != self.config.irc.nick {
                    self.handle_irc_part(nick, channel).await;
                }
            }
            // Join NAIS secure channel IRC rooms once registration is complete
            Command::Response(resp, _) => {
                use irc::client::prelude::Response;
                if *resp == Response::RPL_ENDOFMOTD || *resp == Response::ERR_NOMOTD {
                    log::info!("IRC registration complete, joining NAIS channel rooms");
                    self.join_nais_irc_channels().await;
                }
            }
            _ => {}
        }
    }

    /// Handle CTCP message
    async fn handle_ctcp(&self, source: &str, _target: &str, ctcp: &str) {
        let parts: Vec<&str> = ctcp.splitn(2, ' ').collect();
        let command = parts[0];
        let args = parts.get(1).copied().unwrap_or("");

        match command {
            "VERSION" => {
                // Respond with version
                if let Some(sender) = self.irc_sender.read().await.as_ref() {
                    let response = format!(
                        "\x01VERSION NAIS SCS {} - Secure Channel Services\x01",
                        SCS_VERSION
                    );
                    let _ = sender.send_notice(source, &response);
                }
            }
            "NAIS" => {
                // NAIS-specific CTCP
                self.handle_nais_ctcp(source, args).await;
            }
            "PING" => {
                if let Some(sender) = self.irc_sender.read().await.as_ref() {
                    let response = format!("\x01PING {}\x01", args);
                    let _ = sender.send_notice(source, &response);
                }
            }
            "NAIS_QUERY_CHANNELS" => {
                // Respond to channel query with all hosted channels
                log::info!("Received NAIS_QUERY_CHANNELS from {}", source);
                
                let channels = self.channels.read().await;
                let mut channel_entries: Vec<String> = Vec::new();
                
                for channel in channels.values() {
                    // Format: channel_name|server|type
                    let irc_channel = if channel.metadata.irc_channel.is_empty() {
                        &channel.metadata.name
                    } else {
                        &channel.metadata.irc_channel
                    };
                    channel_entries.push(format!("{}|{}|nais", irc_channel, self.config.irc.server));
                }
                drop(channels);
                
                if let Some(sender) = self.irc_sender.read().await.as_ref() {
                    let channel_list = channel_entries.join(",");
                    let response = format!("\x01NAIS_QUERY_CHANNELS_RESPONSE ACCEPT {}\x01", channel_list);
                    let _ = sender.send_notice(source, &response);
                    log::info!("Sent NAIS_QUERY_CHANNELS_RESPONSE to {} with {} channels", source, channel_entries.len());
                }
            }
            "NSC_PROBE" => {
                // Respond to NSC probe with our probe response (capabilities + peer ID)
                log::info!("Received NSC_PROBE from {}", source);
                let response = self.create_nsc_probe_response_ctcp();
                if let Some(sender) = self.irc_sender.read().await.as_ref() {
                    let _ = sender.send(Command::PRIVMSG(source.to_string(), response));
                    log::info!("Sent NSC_PROBE_RESPONSE to {}", source);
                }
            }
            "NSC_PROBE_RESPONSE" => {
                // A peer responded to our probe - they are NSC-capable
                log::info!("Received NSC_PROBE_RESPONSE from {}: {}", source, &args[..args.len().min(40)]);
            }
            _ => {}
        }
    }

    /// Handle NAIS CTCP
    async fn handle_nais_ctcp(&self, source: &str, args: &str) {
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        let subcommand = parts[0];
        let subargs = parts.get(1).copied().unwrap_or("");

        let sender_guard = self.irc_sender.read().await;
        let Some(sender) = sender_guard.as_ref() else {
            return;
        };

        match subcommand {
            "INFO" => {
                // Send Scs info
                let info = format!(
                    "\x01NAIS INFO {} {} {} {}\x01",
                    self.identity.peer_id.to_hex(),
                    hex::encode(self.identity.public_key()),
                    self.config.bind_address,
                    self.channels.read().await.len()
                );
                let _ = sender.send_notice(source, &info);
            }
            "CHANNELS" => {
                // List hosted channels
                let channels = self.channels.read().await;
                for channel in channels.values() {
                    let info = format!(
                        "\x01NAIS CHANNEL {} {} {}\x01",
                        channel.channel_id.to_hex(),
                        channel.metadata.name,
                        channel.metadata.irc_channel
                    );
                    let _ = sender.send_notice(source, &info);
                }
            }
            "PREKEY" => {
                // Generate and send a prekey bundle for key exchange
                // In real implementation, would create proper X3DH prekey bundle
                let prekey = format!(
                    "\x01NAIS PREKEY {} {} {}\x01",
                    self.identity.peer_id.to_hex(),
                    hex::encode(self.identity.public_key()),
                    self.config.bind_address
                );
                let _ = sender.send_notice(source, &prekey);
            }
            "JOIN" => {
                // Request to join a hosted channel
                if !subargs.is_empty() {
                    log::info!("Join request from {} for channel {}", source, subargs);
                    // Would process join request here
                }
            }
            _ => {
                log::debug!("Unknown NAIS CTCP from {}: {} {}", source, subcommand, subargs);
            }
        }
    }

    /// Handle IRC command (direct message)
    async fn handle_irc_command(&self, source: &str, text: &str) {
        let parts: Vec<&str> = text.splitn(2, ' ').collect();
        let command = parts[0].to_uppercase();
        let args = parts.get(1).copied().unwrap_or("");

        let sender_guard = self.irc_sender.read().await;
        let Some(sender) = sender_guard.as_ref() else {
            return;
        };

        match command.as_str() {
            "HELP" => {
                let _ = sender.send_privmsg(source, "NAIS Secure Channel Services (SCS)");
                let _ = sender.send_privmsg(source, "Commands: HELP, INFO, CHANNELS, REGISTER <name>");
            }
            "INFO" => {
                let stats = self.stats.read().await;
                let uptime = (now_millis() - stats.started_at) / 1000;
                let _ = sender.send_privmsg(
                    source,
                    &format!(
                        "Scs v{} | Peer: {} | Uptime: {}s | Channels: {} | Peers: {}",
                        SCS_VERSION,
                        self.identity.peer_id.short(),
                        uptime,
                        stats.hosted_channels,
                        stats.active_peers
                    ),
                );
            }
            "CHANNELS" => {
                let channels = self.channels.read().await;
                for channel in channels.values() {
                    let _ = sender.send_privmsg(
                        source,
                        &format!(
                            "{} - {} ({} members) IRC: {}",
                            channel.metadata.name,
                            channel.metadata.topic,
                            channel.members.len(),
                            channel.metadata.irc_channel
                        ),
                    );
                }
                if channels.is_empty() {
                    let _ = sender.send_privmsg(source, "No channels currently hosted.");
                }
            }
            "REGISTER" => {
                if !args.is_empty() {
                    log::info!("Channel registration request from {}: {}", source, args);
                    let _ = sender.send_privmsg(
                        source,
                        &format!("Registration request for '{}' received. Contact admin for approval.", args),
                    );
                } else {
                    let _ = sender.send_privmsg(source, "Usage: REGISTER <channel_name>");
                }
            }
            _ => {
                let _ = sender.send_privmsg(source, "Unknown command. Type HELP for available commands.");
            }
        }
    }

    /// Join IRC channels for all hosted NAIS secure channels
    async fn join_nais_irc_channels(&self) {
        let channels = self.channels.read().await;
        let sender_guard = self.irc_sender.read().await;
        let Some(sender) = sender_guard.as_ref() else {
            log::warn!("No IRC sender available when trying to join NAIS channels");
            return;
        };
        for channel in channels.values() {
            let irc_chan = channel.channel_id.to_irc_channel();
            if !self.config.irc.channels.contains(&irc_chan) {
                log::info!("Joining NAIS IRC channel: {}", irc_chan);
                if let Err(e) = sender.send_join(&irc_chan) {
                    log::warn!("Failed to join {}: {}", irc_chan, e);
                } else {
                    // Set the NAIS topic so clients can auto-discover this as a secure channel
                    // Format: NAIS:v1:<channel_id>:<creator_fingerprint>
                    let nais_topic = format!(
                        "NAIS:v1:{}:{}",
                        channel.channel_id.to_hex(),
                        self.identity.peer_id.to_hex()
                    );
                    if let Err(e) = sender.send(Command::TOPIC(irc_chan.clone(), Some(nais_topic.clone()))) {
                        log::warn!("Failed to set NAIS topic on {}: {}", irc_chan, e);
                    } else {
                        log::info!("Set NAIS topic on {}: {}", irc_chan, nais_topic);
                    }
                }
            }
        }
    }

    /// Handle IRC join (peer discovery)
    async fn handle_irc_join(&self, nick: &str, channel: &str) {
        // Check if this is a NAIS discovery channel
        let irc_channels = self.irc_channels.read().await;
        if let Some(channel_id) = irc_channels.get(channel) {
            log::info!("User {} joined NAIS channel {} ({}), sending NSC probe", nick, channel, channel_id);
            drop(irc_channels);

            // Send NSC_PROBE to the joining user to discover if they're an NSC-capable client
            // This triggers the secure channel handshake on their end
            let probe = self.create_nsc_probe_ctcp();
            if let Some(sender) = self.irc_sender.read().await.as_ref() {
                let _ = sender.send(Command::PRIVMSG(nick.to_string(), probe));
                log::info!("Sent NSC_PROBE to {} in channel {}", nick, channel);
            }
        }
    }

    /// Create an NSC_PROBE CTCP message
    fn create_nsc_probe_ctcp(&self) -> String {
        // ProbeMessage format matching the client's nsc_irc::ProbeMessage
        let probe = serde_json::json!({
            "version": 2,
            "peer_id": self.identity.peer_id.to_hex(),
            "nat_type": null,
            "features": ["ice", "e2e", "mls", "scs"]
        });
        let json = serde_json::to_string(&probe).unwrap_or_default();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &json);
        format!("\x01NSC_PROBE {}\x01", encoded)
    }

    /// Create an NSC_PROBE_RESPONSE CTCP message
    fn create_nsc_probe_response_ctcp(&self) -> String {
        let probe = serde_json::json!({
            "version": 2,
            "peer_id": self.identity.peer_id.to_hex(),
            "nat_type": null,
            "features": ["ice", "e2e", "mls", "scs"]
        });
        let json = serde_json::to_string(&probe).unwrap_or_default();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &json);
        format!("\x01NSC_PROBE_RESPONSE {}\x01", encoded)
    }

    /// Handle IRC part
    async fn handle_irc_part(&self, nick: &str, channel: &str) {
        let irc_channels = self.irc_channels.read().await;
        if let Some(_channel_id) = irc_channels.get(channel) {
            log::debug!("User {} left NAIS channel {}", nick, channel);
        }
    }
}

// =============================================================================
// Utilities
// =============================================================================

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn generate_channel_id(name: &str, creator: &PeerId) -> ChannelId {
    let mut hasher = Sha256::new();
    hasher.update(&creator.0);
    hasher.update(name.as_bytes());
    hasher.update(&now_millis().to_be_bytes());
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    ChannelId(id)
}

fn parse_channel_subscriptions(payload: &Bytes) -> Vec<ChannelId> {
    if payload.len() < 4 {
        return Vec::new();
    }

    let count = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let mut channels = Vec::with_capacity(count);

    for i in 0..count {
        let start = 4 + i * 32;
        if start + 32 <= payload.len() {
            let mut id = [0u8; 32];
            id.copy_from_slice(&payload[start..start + 32]);
            channels.push(ChannelId(id));
        }
    }

    channels
}

// =============================================================================
// TLS Configuration
// =============================================================================

fn generate_self_signed_cert(
) -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>), String> {
    let cert = rcgen::generate_simple_self_signed(vec!["scs.local".into(), "localhost".into()])
        .map_err(|e| format!("Failed to generate cert: {}", e))?;

    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());

    Ok((vec![cert_der], key))
}

fn create_server_config() -> Result<ServerConfig, String> {
    let (certs, key) = generate_self_signed_cert()?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .map_err(|e| format!("TLS config error: {}", e))?;

    server_crypto.alpn_protocols = vec![b"nais-secure-channel/2".to_vec()];

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| format!("QUIC config error: {}", e))?,
    ));

    Ok(server_config)
}

// =============================================================================
// CLI
// =============================================================================

#[derive(Parser, Debug)]
#[command(name = "nais-scs")]
#[command(about = "NAIS Secure Channel Services (SCS) - Long-term host for secure channels")]
#[command(version = SCS_VERSION)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Address to bind QUIC server to
    #[arg(short, long)]
    bind: Option<String>,

    /// Relay hub address for NAT traversal fallback
    #[arg(short, long)]
    relay_hub: Option<String>,

    /// Log level (debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install ring crypto provider for rustls (required for musl builds)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = Args::parse();

    // Initialize logging
    env_logger::Builder::new()
        .filter_level(match args.log_level.as_str() {
            "debug" => log::LevelFilter::Debug,
            "info" => log::LevelFilter::Info,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            _ => log::LevelFilter::Info,
        })
        .format_timestamp_millis()
        .init();

    log::info!("NAIS SCS v{} starting", SCS_VERSION);

    // Load configuration
    let mut config = if let Some(config_path) = &args.config {
        let content = fs::read_to_string(config_path)?;
        toml::from_str(&content)?
    } else {
        // Try default locations
        let default_paths = [
            PathBuf::from("scs.toml"),
            dirs::config_dir()
                .unwrap_or_default()
                .join("nais-scs/config.toml"),
        ];

        let mut loaded: Option<ScsConfig> = None;
        for path in &default_paths {
            if path.exists() {
                let content = fs::read_to_string(path)?;
                loaded = Some(toml::from_str(&content)?);
                log::info!("Loaded config from {:?}", path);
                break;
            }
        }
        loaded.unwrap_or_default()
    };

    // Override with CLI args
    if let Some(bind) = args.bind {
        config.bind_address = bind;
    }
    if let Some(hub) = args.relay_hub {
        config.relay_hub = Some(hub);
    }

    let bind_addr: SocketAddr = config.bind_address.parse()?;

    // Create Scs instance
    let scs = Scs::new(config).await;

    log::info!("Scs peer ID: {}", scs.identity.peer_id);
    log::info!("Hosting {} channels", scs.channels.read().await.len());

    // Create QUIC server
    let server_config = create_server_config()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;

    log::info!("QUIC server listening on {}", bind_addr);

    // Start background tasks
    tokio::spawn(scs.clone().cleanup_task());
    tokio::spawn(scs.clone().stats_task());
    tokio::spawn(scs.clone().irc_task());

    // Handle shutdown signal
    let scs_shutdown = scs.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        log::info!("Shutdown signal received, saving state...");
        if let Err(e) = scs_shutdown.save_state().await {
            log::error!("Failed to save state on shutdown: {}", e);
        }
        std::process::exit(0);
    });

    // Accept connections
    while let Some(incoming) = endpoint.accept().await {
        let scs = scs.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    scs.handle_connection(connection).await;
                }
                Err(e) => {
                    log::warn!("Connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}
