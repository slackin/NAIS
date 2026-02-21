//! Nais Secure Channels - Implementation Skeleton
//!
//! This module provides the type definitions and trait interfaces for the
//! NSC architecture. Implementation details are documented in
//! docs/NAIS_SECURE_CHANNELS_ARCHITECTURE.md

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::future::Future;
use std::pin::Pin;

// =============================================================================
// Core Types
// =============================================================================

/// 32-byte cryptographic identity
pub type IdentityKey = [u8; 32];
pub type Fingerprint = [u8; 32];
pub type ChannelId = [u8; 32];
pub type DeviceId = [u8; 16];
pub type Secret = [u8; 32];
pub type Signature = [u8; 64];
pub type Nonce = [u8; 24];

/// Peer identifier (hash of identity key)
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PeerId(pub Fingerprint);

/// Hub identifier
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct HubId(pub Fingerprint);

// =============================================================================
// Protocol Messages
// =============================================================================

/// Wire protocol message types
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
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
}

/// NSC message envelope
#[derive(Clone, Debug)]
pub struct NscEnvelope {
    pub version: u8,
    pub message_type: MessageType,
    pub flags: u16,
    pub sender_id: Fingerprint,
    pub channel_id: ChannelId,
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub payload: Vec<u8>,
    pub signature: Signature,
}

impl NscEnvelope {
    pub const HEADER_SIZE: usize = 1 + 1 + 2 + 32 + 32 + 8 + 8 + 4 + 64; // 152 bytes

    pub fn new(
        message_type: MessageType,
        sender_id: Fingerprint,
        channel_id: ChannelId,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: 0x02,
            message_type,
            flags: 0,
            sender_id,
            channel_id,
            sequence,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            payload,
            signature: [0u8; 64], // To be filled by signing
        }
    }

    /// Serialize for signing/transmission
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.payload.len());
        buf.push(self.version);
        buf.push(self.message_type as u8);
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.sender_id);
        buf.extend_from_slice(&self.channel_id);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < Self::HEADER_SIZE {
            return Err(ParseError::TooShort);
        }

        let version = data[0];
        if version != 0x02 {
            return Err(ParseError::UnsupportedVersion);
        }

        let message_type = match data[1] {
            0x01 => MessageType::ChannelMessage,
            0x02 => MessageType::ChannelAction,
            0x03 => MessageType::ChannelMetadata,
            0x10 => MessageType::MemberJoin,
            0x11 => MessageType::MemberLeave,
            0x12 => MessageType::MemberUpdate,
            0x20 => MessageType::KeyPackage,
            0x21 => MessageType::Welcome,
            0x22 => MessageType::Commit,
            0x30 => MessageType::Ack,
            0x31 => MessageType::Heartbeat,
            0x32 => MessageType::RoutingUpdate,
            0x40 => MessageType::IceCandidate,
            0x41 => MessageType::IceOffer,
            0x42 => MessageType::IceAnswer,
            0x50 => MessageType::RelayRequest,
            0x51 => MessageType::RelayData,
            _ => return Err(ParseError::UnknownMessageType),
        };

        let flags = u16::from_be_bytes([data[2], data[3]]);
        let mut sender_id = [0u8; 32];
        sender_id.copy_from_slice(&data[4..36]);
        let mut channel_id = [0u8; 32];
        channel_id.copy_from_slice(&data[36..68]);
        let sequence = u64::from_be_bytes(data[68..76].try_into().unwrap());
        let timestamp_ms = u64::from_be_bytes(data[76..84].try_into().unwrap());
        let payload_len = u32::from_be_bytes(data[84..88].try_into().unwrap()) as usize;

        if data.len() < 88 + payload_len + 64 {
            return Err(ParseError::TooShort);
        }

        let payload = data[88..88 + payload_len].to_vec();
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[88 + payload_len..88 + payload_len + 64]);

        Ok(Self {
            version,
            message_type,
            flags,
            sender_id,
            channel_id,
            sequence,
            timestamp_ms,
            payload,
            signature,
        })
    }
}

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    UnsupportedVersion,
    UnknownMessageType,
    InvalidSignature,
}

// =============================================================================
// Identity System
// =============================================================================

/// Long-term identity with device support
#[derive(Clone, Debug)]
pub struct NaisIdentity {
    /// Ed25519 identity key pair
    pub identity_key: IdentityKey,
    pub identity_public: IdentityKey,

    /// Human-readable display name
    pub display_name: String,

    /// Device identifier
    pub device_id: DeviceId,

    /// Creation timestamp
    pub created_at: u64,

    /// Associated devices (for master identity)
    pub devices: Vec<DeviceCertificate>,
}

#[derive(Clone, Debug)]
pub struct DeviceCertificate {
    pub device_id: DeviceId,
    pub device_name: String,
    pub device_public_key: IdentityKey,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Signature, // Signed by master identity
}

/// Trust level for a peer identity
#[derive(Clone, Debug)]
pub enum TrustLevel {
    /// Unknown identity
    Unknown,

    /// Trust on first use
    Tofu {
        first_seen: u64,
        pinned_key: IdentityKey,
    },

    /// Verified out-of-band
    Verified {
        verified_at: u64,
        method: VerificationMethod,
    },

    /// Web of trust
    WebOfTrust {
        trust_paths: Vec<TrustPath>,
        trust_score: f32,
    },

    /// Compromised/revoked
    Compromised { reported_at: u64 },
}

#[derive(Clone, Debug)]
pub enum VerificationMethod {
    SafetyNumber(String),
    QrCode,
    Sas(Vec<String>),
    Attestation { attester: IdentityKey },
}

#[derive(Clone, Debug)]
pub struct TrustPath {
    pub signers: Vec<IdentityKey>,
    pub established: u64,
}

/// Revocation record
#[derive(Clone, Debug)]
pub struct Revocation {
    pub revoked_key: IdentityKey,
    pub reason: RevocationReason,
    pub revoked_at: u64,
    pub signature: Signature,
    pub successor: Option<IdentityKey>,
}

#[derive(Clone, Debug)]
pub enum RevocationReason {
    Compromised,
    Rotation,
    DeviceLost,
    UserRequested,
    Expired,
}

// =============================================================================
// Key Management
// =============================================================================

/// X3DH pre-key bundle for initial key exchange
#[derive(Clone, Debug)]
pub struct X3dhPreKeyBundle {
    pub identity_key: IdentityKey,
    pub signed_pre_key: IdentityKey,
    pub signed_pre_key_signature: Signature,
    pub one_time_pre_keys: Vec<IdentityKey>,
}

/// MLS group state for a channel
#[derive(Clone, Debug)]
pub struct MlsGroupState {
    pub group_id: ChannelId,
    pub epoch: u64,
    pub members: Vec<MlsMember>,
    pub epoch_secrets: EpochSecrets,
}

#[derive(Clone, Debug)]
pub struct MlsMember {
    pub identity: IdentityKey,
    pub leaf_index: u32,
    pub credential: Vec<u8>,
}

#[derive(Clone)]
pub struct EpochSecrets {
    pub joiner_secret: Secret,
    pub epoch_secret: Secret,
    pub sender_data_secret: Secret,
    pub encryption_secret: Secret,
    pub authentication_secret: Secret,
    pub exporter_secret: Secret,
    pub resumption_secret: Secret,
}

impl std::fmt::Debug for EpochSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochSecrets")
            .field("joiner_secret", &"[REDACTED]")
            .field("epoch_secret", &"[REDACTED]")
            .finish()
    }
}

/// Key rotation policy
#[derive(Clone, Debug)]
pub struct KeyRotationPolicy {
    pub messages_threshold: u32,
    pub time_threshold: Duration,
    pub rotate_on_leave: bool,
    pub rotate_on_join: bool,
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        Self {
            messages_threshold: 1000,
            time_threshold: Duration::from_secs(7 * 24 * 3600),
            rotate_on_leave: true,
            rotate_on_join: false,
        }
    }
}

// =============================================================================
// Channel Metadata
// =============================================================================

/// Signed channel metadata
#[derive(Clone, Debug)]
pub struct ChannelMetadata {
    pub channel_id: ChannelId,
    pub name: String,
    pub topic: String,
    pub avatar_hash: Option<[u8; 32]>,
    pub created_at: u64,
    pub version: u64,
    pub creator: IdentityKey,
    pub admins: Vec<IdentityKey>,
    pub settings: ChannelSettings,
    pub signature: Signature,
    pub previous_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct ChannelSettings {
    pub discoverable: bool,
    pub invite_only: bool,
    pub max_members: u32,
    pub retention_days: u32,
}

impl Default for ChannelSettings {
    fn default() -> Self {
        Self {
            discoverable: true,
            invite_only: false,
            max_members: 0, // unlimited
            retention_days: 30,
        }
    }
}

// =============================================================================
// NAT Traversal
// =============================================================================

/// NAT type classification
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatType {
    None,
    FullCone,
    AddressRestricted,
    PortRestricted,
    Symmetric,
    Unknown,
}

/// ICE candidate types
#[derive(Clone, Debug)]
pub enum IceCandidate {
    Host {
        addr: SocketAddr,
        interface: String,
    },
    ServerReflexive {
        addr: SocketAddr,
        base: SocketAddr,
        stun_server: String,
    },
    PeerReflexive {
        addr: SocketAddr,
        base: SocketAddr,
    },
    Relay {
        addr: SocketAddr,
        turn_server: String,
    },
}

impl IceCandidate {
    /// Priority for candidate selection (RFC 5245)
    pub fn priority(&self) -> u32 {
        match self {
            IceCandidate::Host { .. } => 126 << 24,
            IceCandidate::PeerReflexive { .. } => 110 << 24,
            IceCandidate::ServerReflexive { .. } => 100 << 24,
            IceCandidate::Relay { .. } => 0,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        match self {
            IceCandidate::Host { addr, .. } => *addr,
            IceCandidate::ServerReflexive { addr, .. } => *addr,
            IceCandidate::PeerReflexive { addr, .. } => *addr,
            IceCandidate::Relay { addr, .. } => *addr,
        }
    }
}

/// ICE agent state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceState {
    New,
    Gathering,
    Complete,
    Connected,
    Failed,
    Closed,
}

/// ICE agent for NAT traversal
pub struct IceAgent {
    pub state: IceState,
    pub local_candidates: Vec<IceCandidate>,
    pub remote_candidates: Vec<IceCandidate>,
    pub stun_servers: Vec<String>,
    pub turn_servers: Vec<TurnServer>,
    pub nat_type: Option<NatType>,
}

#[derive(Clone, Debug)]
pub struct TurnServer {
    pub url: String,
    pub username: String,
    pub credential: String,
}

// =============================================================================
// Network Topology
// =============================================================================

/// Federation hub definition
#[derive(Clone, Debug)]
pub struct FederationHub {
    pub hub_id: HubId,
    pub identity: IdentityKey,
    pub addresses: Vec<SocketAddr>,
    pub region: String,
    pub capabilities: HubCapabilities,
    pub load_factor: f32,
}

#[derive(Clone, Debug)]
pub struct HubCapabilities {
    pub relay: bool,
    pub turn: bool,
    pub store_forward: bool,
    pub max_relay_size: usize,
}

/// Connection path types
#[derive(Clone, Debug)]
pub enum PathType {
    Direct,
    HubRelay { hub_id: HubId },
    PeerRelay { relay_peer: PeerId },
    MultiPath { paths: Vec<PathType> },
}

/// Routing table entry
#[derive(Clone, Debug)]
pub struct RoutingEntry {
    pub peer_id: PeerId,
    pub path_type: PathType,
    pub latency_ms: u32,
    pub reliability: f32,
    pub last_success: Instant,
}

// =============================================================================
// Connection Security Status (for UX)
// =============================================================================

/// Security status for UI display
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionSecurityStatus {
    DirectVerified,
    DirectTofu,
    RelayVerified,
    RelayTofu,
    Unverified,
    Degraded,
    Disconnected,
}

impl ConnectionSecurityStatus {
    pub fn icon(&self) -> &'static str {
        match self {
            Self::DirectVerified => "🔒✓",
            Self::DirectTofu => "🔒",
            Self::RelayVerified => "🔗✓",
            Self::RelayTofu => "🔗",
            Self::Unverified => "⚠️",
            Self::Degraded => "🔓",
            Self::Disconnected => "❌",
        }
    }

    pub fn tooltip(&self) -> &'static str {
        match self {
            Self::DirectVerified => "Direct connection, identity verified",
            Self::DirectTofu => "Direct connection, identity pinned (TOFU)",
            Self::RelayVerified => "Relayed connection, identity verified",
            Self::RelayTofu => "Relayed connection, identity pinned",
            Self::Unverified => "Identity not verified",
            Self::Degraded => "Encryption degraded",
            Self::Disconnected => "Not connected",
        }
    }

    /// Determine status from connection and trust info
    pub fn from_state(connected: bool, direct: bool, trust: &TrustLevel) -> Self {
        if !connected {
            return Self::Disconnected;
        }

        match trust {
            TrustLevel::Verified { .. } => {
                if direct {
                    Self::DirectVerified
                } else {
                    Self::RelayVerified
                }
            }
            TrustLevel::Tofu { .. } | TrustLevel::WebOfTrust { .. } => {
                if direct {
                    Self::DirectTofu
                } else {
                    Self::RelayTofu
                }
            }
            TrustLevel::Unknown => Self::Unverified,
            TrustLevel::Compromised { .. } => Self::Degraded,
        }
    }
}

// =============================================================================
// Channel State
// =============================================================================

/// NAIS Secure Channel state
#[derive(Clone, Debug)]
pub struct NaisSecureChannel {
    pub channel_id: ChannelId,
    pub metadata: ChannelMetadata,
    pub state: ChannelState,
    pub our_identity: IdentityKey,
    pub mls_state: Option<MlsGroupState>,
    pub members: HashMap<PeerId, MemberInfo>,
    pub routing_table: HashMap<PeerId, RoutingEntry>,
    pub message_queue: Vec<QueuedMessage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelState {
    Creating,
    Discovering,
    Connecting,
    Active,
    Degraded,
    Closed,
}

#[derive(Clone, Debug)]
pub struct MemberInfo {
    pub peer_id: PeerId,
    pub identity: IdentityKey,
    pub display_name: String,
    pub trust_level: TrustLevel,
    pub security_status: ConnectionSecurityStatus,
    pub last_seen: Instant,
}

#[derive(Clone, Debug)]
pub struct QueuedMessage {
    pub envelope: NscEnvelope,
    pub recipient: PeerId,
    pub queued_at: Instant,
    pub attempts: u32,
}

// =============================================================================
// Events and Commands
// =============================================================================

/// Events emitted by the secure channel system
#[derive(Clone, Debug)]
pub enum NscEvent {
    // Channel events
    ChannelCreated {
        channel_id: ChannelId,
    },
    ChannelJoined {
        channel_id: ChannelId,
    },
    ChannelLeft {
        channel_id: ChannelId,
    },
    MetadataUpdated {
        channel_id: ChannelId,
        metadata: ChannelMetadata,
    },

    // Member events
    MemberJoined {
        channel_id: ChannelId,
        member: MemberInfo,
    },
    MemberLeft {
        channel_id: ChannelId,
        peer_id: PeerId,
    },
    MemberStatusChanged {
        channel_id: ChannelId,
        peer_id: PeerId,
        status: ConnectionSecurityStatus,
    },

    // Message events
    MessageReceived {
        channel_id: ChannelId,
        sender: PeerId,
        content: Vec<u8>,
        timestamp: u64,
    },
    MessageDelivered {
        channel_id: ChannelId,
        message_id: u64,
    },
    MessageFailed {
        channel_id: ChannelId,
        message_id: u64,
        reason: String,
    },

    // Security events
    KeyRotated {
        channel_id: ChannelId,
        epoch: u64,
    },
    IdentityChanged {
        peer_id: PeerId,
        old_key: IdentityKey,
        new_key: IdentityKey,
    },
    TrustLevelChanged {
        peer_id: PeerId,
        trust_level: TrustLevel,
    },

    // Connection events
    ConnectionEstablished {
        peer_id: PeerId,
        path_type: PathType,
    },
    ConnectionLost {
        peer_id: PeerId,
    },

    // Errors
    Error {
        channel_id: Option<ChannelId>,
        message: String,
    },
}

/// Commands to the secure channel system
#[derive(Clone, Debug)]
pub enum NscCommand {
    // Channel commands
    CreateChannel {
        name: String,
        settings: ChannelSettings,
    },
    JoinChannel {
        channel_id: ChannelId,
    },
    LeaveChannel {
        channel_id: ChannelId,
    },
    UpdateMetadata {
        channel_id: ChannelId,
        name: Option<String>,
        topic: Option<String>,
    },

    // Message commands
    SendMessage {
        channel_id: ChannelId,
        content: Vec<u8>,
    },

    // Member commands
    InviteMember {
        channel_id: ChannelId,
        identity: IdentityKey,
    },
    KickMember {
        channel_id: ChannelId,
        peer_id: PeerId,
    },

    // Identity commands
    VerifyIdentity {
        peer_id: PeerId,
        method: VerificationMethod,
    },
    RevokeDevice {
        device_id: DeviceId,
        reason: RevocationReason,
    },

    // Key management
    RotateKeys {
        channel_id: ChannelId,
    },
}

// =============================================================================
// Configuration
// =============================================================================

/// NSC configuration
#[derive(Clone, Debug)]
pub struct NscConfig {
    /// Protocol version
    pub version: u8,

    /// STUN servers for NAT traversal
    pub stun_servers: Vec<String>,

    /// TURN servers for relay fallback
    pub turn_servers: Vec<TurnServer>,

    /// Federation hubs
    pub federation_hubs: Vec<String>,

    /// Key rotation policy
    pub key_rotation: KeyRotationPolicy,

    /// Heartbeat interval
    pub heartbeat_interval: Duration,

    /// Peer timeout
    pub peer_timeout: Duration,

    /// Message queue size
    pub message_queue_size: usize,

    /// Max message size
    pub max_message_size: usize,

    /// Enable IPv6 preference
    pub prefer_ipv6: bool,

    /// Enable UPnP optimization
    pub enable_upnp: bool,
}

impl Default for NscConfig {
    fn default() -> Self {
        Self {
            version: 0x02,
            stun_servers: vec![
                "stun:stun.l.google.com:19302".into(),
                "stun:stun1.l.google.com:19302".into(),
            ],
            turn_servers: vec![],
            federation_hubs: vec![],
            key_rotation: KeyRotationPolicy::default(),
            heartbeat_interval: Duration::from_secs(30),
            peer_timeout: Duration::from_secs(120),
            message_queue_size: 1000,
            max_message_size: 64 * 1024,
            prefer_ipv6: true,
            enable_upnp: true,
        }
    }
}

// =============================================================================
// Manager Traits (for dependency injection / testing)
// =============================================================================

/// Boxed future type for async trait methods
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Identity management interface
pub trait IdentityManager: Send + Sync {
    /// Get our current identity
    fn our_identity(&self) -> &NaisIdentity;

    /// Get trust level for a peer
    fn trust_level(&self, peer: &PeerId) -> TrustLevel;

    /// Verify a peer's identity
    fn verify_identity<'a>(
        &'a mut self,
        peer: &'a PeerId,
        method: VerificationMethod,
    ) -> BoxFuture<'a, Result<(), String>>;

    /// Generate pre-key bundle for X3DH
    fn generate_prekey_bundle(&self) -> X3dhPreKeyBundle;

    /// Perform X3DH key exchange
    fn x3dh_initiate<'a>(
        &'a self,
        their_bundle: &'a X3dhPreKeyBundle,
    ) -> BoxFuture<'a, Result<(Secret, IdentityKey), String>>;
}

/// Transport management interface
pub trait TransportManager: Send + Sync {
    /// Establish connection to peer
    fn connect<'a>(&'a mut self, peer: &'a PeerId) -> BoxFuture<'a, Result<PathType, String>>;

    /// Send message to peer
    fn send<'a>(
        &'a self,
        peer: &'a PeerId,
        message: &'a NscEnvelope,
    ) -> BoxFuture<'a, Result<(), String>>;

    /// Get current connection status
    fn connection_status(&self, peer: &PeerId) -> Option<ConnectionSecurityStatus>;

    /// Get NAT type
    fn nat_type(&self) -> NatType;
}

/// Key management interface
pub trait KeyManager: Send + Sync {
    /// Initialize MLS group for channel
    fn init_group<'a>(
        &'a mut self,
        channel_id: &'a ChannelId,
    ) -> BoxFuture<'a, Result<MlsGroupState, String>>;

    /// Add member to group (returns Welcome message)
    fn add_member<'a>(
        &'a mut self,
        channel_id: &'a ChannelId,
        member: &'a IdentityKey,
    ) -> BoxFuture<'a, Result<Vec<u8>, String>>;

    /// Remove member from group (returns Commit message)
    fn remove_member<'a>(
        &'a mut self,
        channel_id: &'a ChannelId,
        member: &'a IdentityKey,
    ) -> BoxFuture<'a, Result<Vec<u8>, String>>;

    /// Encrypt message for group
    fn encrypt(&self, channel_id: &ChannelId, plaintext: &[u8]) -> Result<Vec<u8>, String>;

    /// Decrypt message from group
    fn decrypt(
        &self,
        channel_id: &ChannelId,
        sender: &IdentityKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String>;

    /// Rotate keys
    fn rotate_keys<'a>(
        &'a mut self,
        channel_id: &'a ChannelId,
    ) -> BoxFuture<'a, Result<Vec<u8>, String>>;

    /// Get current epoch
    fn current_epoch(&self, channel_id: &ChannelId) -> Option<u64>;
}

// =============================================================================
// CTCP Extension Constants
// =============================================================================

pub mod ctcp {
    /// NAIS protocol hello/capability announcement
    pub const HELLO: &str = "NAIS_HELLO";

    /// ICE offer for P2P connection
    pub const ICE_OFFER: &str = "NAIS_ICE_OFFER";

    /// ICE answer
    pub const ICE_ANSWER: &str = "NAIS_ICE_ANSWER";

    /// ICE candidate
    pub const ICE_CANDIDATE: &str = "NAIS_ICE_CANDIDATE";

    /// Request relay through hub
    pub const RELAY_REQUEST: &str = "NAIS_RELAY_REQUEST";

    /// Hub availability announcement
    pub const HUB_ANNOUNCE: &str = "NAIS_HUB_ANNOUNCE";

    /// Request MLS KeyPackage for joining
    pub const KEYPACKAGE_REQUEST: &str = "NAIS_KEYPACKAGE_REQUEST";

    /// Provide KeyPackage (may be multi-part)
    pub const KEYPACKAGE: &str = "NAIS_KEYPACKAGE";

    /// Channel metadata sync request
    pub const METADATA_SYNC: &str = "NAIS_METADATA_SYNC";

    /// Channel metadata response
    pub const METADATA: &str = "NAIS_METADATA";
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_serialize_parse() {
        let original = NscEnvelope::new(
            MessageType::ChannelMessage,
            [1u8; 32],
            [2u8; 32],
            42,
            b"Hello, World!".to_vec(),
        );

        let serialized = original.serialize();
        let parsed = NscEnvelope::parse(&serialized).unwrap();

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.message_type, original.message_type);
        assert_eq!(parsed.sender_id, original.sender_id);
        assert_eq!(parsed.channel_id, original.channel_id);
        assert_eq!(parsed.sequence, original.sequence);
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn test_ice_candidate_priority() {
        let host = IceCandidate::Host {
            addr: "192.168.1.1:5000".parse().unwrap(),
            interface: "eth0".into(),
        };
        let srflx = IceCandidate::ServerReflexive {
            addr: "1.2.3.4:5000".parse().unwrap(),
            base: "192.168.1.1:5000".parse().unwrap(),
            stun_server: "stun.example.com".into(),
        };
        let relay = IceCandidate::Relay {
            addr: "5.6.7.8:5000".parse().unwrap(),
            turn_server: "turn.example.com".into(),
        };

        assert!(host.priority() > srflx.priority());
        assert!(srflx.priority() > relay.priority());
    }

    #[test]
    fn test_connection_security_status() {
        let trust_verified = TrustLevel::Verified {
            verified_at: 0,
            method: VerificationMethod::QrCode,
        };
        let trust_tofu = TrustLevel::Tofu {
            first_seen: 0,
            pinned_key: [0u8; 32],
        };

        assert_eq!(
            ConnectionSecurityStatus::from_state(true, true, &trust_verified),
            ConnectionSecurityStatus::DirectVerified
        );
        assert_eq!(
            ConnectionSecurityStatus::from_state(true, false, &trust_verified),
            ConnectionSecurityStatus::RelayVerified
        );
        assert_eq!(
            ConnectionSecurityStatus::from_state(true, true, &trust_tofu),
            ConnectionSecurityStatus::DirectTofu
        );
        assert_eq!(
            ConnectionSecurityStatus::from_state(false, true, &trust_verified),
            ConnectionSecurityStatus::Disconnected
        );
    }
}
