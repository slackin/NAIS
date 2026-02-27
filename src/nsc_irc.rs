//! Nais Secure Channels - IRC Integration Layer
//!
//! Implements IRC-based signaling for secure channel discovery:
//! - CTCP-based ICE candidate exchange
//! - Presence tracking via IRC
//! - Secure channel invitations via IRC
//! - Bridge between IRC and secure transport
//!
//! # Key Principle
//! IRC is used ONLY for discovery and signaling. No encrypted payloads
//! ever traverse IRC - all message content flows through direct P2P
//! or encrypted relay connections.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

use crate::nsc_channel::{ChannelId, ChannelMetadata};
use crate::nsc_nat::{CandidateType, IceCandidate, IceCredentials, NatType};
use crate::nsc_transport::PeerId;

// =============================================================================
// Error Types
// =============================================================================

#[derive(Debug, Error)]
pub enum IrcIntegrationError {
    #[error("Not connected to IRC")]
    NotConnected,

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Invalid CTCP message: {0}")]
    InvalidCtcp(String),

    #[error("Signaling timeout")]
    Timeout,

    #[error("Invite expired")]
    InviteExpired,

    #[error("Already connected to peer")]
    AlreadyConnected,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type IrcResult<T> = Result<T, IrcIntegrationError>;

// =============================================================================
// Constants
// =============================================================================

/// CTCP command prefix for NSC
pub const NSC_CTCP_PREFIX: &str = "NSC";

/// ICE offer timeout
pub const ICE_OFFER_TIMEOUT: Duration = Duration::from_secs(30);

/// Presence heartbeat interval
pub const PRESENCE_HEARTBEAT: Duration = Duration::from_secs(60);

/// Presence timeout (consider offline if no heartbeat)
pub const PRESENCE_TIMEOUT: Duration = Duration::from_secs(180);

/// Maximum CTCP message length (IRC limit is typically ~400-500 chars)
pub const MAX_CTCP_LENGTH: usize = 380; // Safe limit after nick!user@host PRIVMSG target : prefix

// =============================================================================
// CTCP Message Types
// =============================================================================

/// NSC CTCP command types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NscCtcpCommand {
    /// Probe for NSC capability
    Probe,
    /// Respond to probe with capabilities
    ProbeResponse,
    /// ICE offer with candidates
    IceOffer,
    /// ICE answer with candidates
    IceAnswer,
    /// Additional ICE candidate
    IceCandidate,
    /// Channel invite
    Invite,
    /// Accept channel invite
    InviteAccept,
    /// Decline channel invite
    InviteDecline,
    /// Presence heartbeat
    Presence,
    /// Key package announcement
    KeyPackage,
    /// Identity announcement
    Identity,
    /// Request channel metadata sync
    MetadataSync,
    /// Channel metadata response
    Metadata,
    /// Acknowledgment message
    Ack,
}

impl NscCtcpCommand {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Probe => "NSC_PROBE",
            Self::ProbeResponse => "NSC_PROBE_RESPONSE",
            Self::IceOffer => "NSC_ICE_OFFER",
            Self::IceAnswer => "NSC_ICE_ANSWER",
            Self::IceCandidate => "NSC_ICE_CANDIDATE",
            Self::Invite => "NSC_INVITE",
            Self::InviteAccept => "NSC_INVITE_ACCEPT",
            Self::InviteDecline => "NSC_INVITE_DECLINE",
            Self::Presence => "NSC_PRESENCE",
            Self::KeyPackage => "NSC_KEYPACKAGE",
            Self::Identity => "NSC_IDENTITY",
            Self::MetadataSync => "NSC_METADATA_SYNC",
            Self::Metadata => "NSC_METADATA",
            Self::Ack => "NSC_ACK",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "NSC_PROBE" => Some(Self::Probe),
            "NSC_PROBE_RESPONSE" => Some(Self::ProbeResponse),
            "NSC_ICE_OFFER" => Some(Self::IceOffer),
            "NSC_ICE_ANSWER" => Some(Self::IceAnswer),
            "NSC_ICE_CANDIDATE" => Some(Self::IceCandidate),
            "NSC_INVITE" => Some(Self::Invite),
            "NSC_INVITE_ACCEPT" => Some(Self::InviteAccept),
            "NSC_INVITE_DECLINE" => Some(Self::InviteDecline),
            "NSC_PRESENCE" => Some(Self::Presence),
            "NSC_KEYPACKAGE" => Some(Self::KeyPackage),
            "NSC_IDENTITY" => Some(Self::Identity),
            "NSC_METADATA_SYNC" => Some(Self::MetadataSync),
            "NSC_METADATA" => Some(Self::Metadata),
            "NSC_ACK" => Some(Self::Ack),
            _ => None,
        }
    }
}

// =============================================================================
// Signaling Messages (CTCP Payloads)
// =============================================================================

/// Probe request/response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeMessage {
    /// Protocol version
    pub version: u8,
    /// Our peer ID (hex)
    pub peer_id: String,
    /// NAT type if known
    pub nat_type: Option<String>,
    /// Supported features
    pub features: Vec<String>,
    /// Display name / username of the peer (if set)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl ProbeMessage {
    pub fn new(peer_id: &PeerId, nat_type: Option<NatType>) -> Self {
        Self {
            version: 2,
            peer_id: peer_id.to_hex(),
            nat_type: nat_type.map(|n| format!("{:?}", n)),
            features: vec![
                "ice".to_string(),
                "e2e".to_string(),
                "mls".to_string(),
            ],
            display_name: None,
        }
    }

    /// Create a probe message with a display name
    pub fn with_display_name(peer_id: &PeerId, nat_type: Option<NatType>, display_name: Option<String>) -> Self {
        let mut msg = Self::new(peer_id, nat_type);
        msg.display_name = display_name;
        msg
    }
}

/// ICE offer/answer message - uses short field names to fit in IRC CTCP limit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IceMessage {
    /// Session ID for this exchange (8 chars for compactness)
    #[serde(rename = "s")]
    pub session_id: String,
    /// Our peer ID (truncated to 16 hex chars - enough for uniqueness)
    #[serde(rename = "p")]
    pub peer_id: String,
    /// Target channel ID (truncated to 16 hex chars)
    #[serde(rename = "c", skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    /// ICE credentials
    #[serde(rename = "u")]
    pub ufrag: String,
    #[serde(rename = "w")]
    pub pwd: String,
    /// ICE candidates (compact format: "t:ip:port" or "t:ip:port/rip:rport")
    #[serde(rename = "i")]
    pub candidates: Vec<String>,
    /// NAT type
    #[serde(rename = "n", skip_serializing_if = "Option::is_none")]
    pub nat_type: Option<String>,
    /// QUIC transport port (the actual port to connect to after ICE completes)
    #[serde(rename = "q", skip_serializing_if = "Option::is_none")]
    pub transport_port: Option<u16>,
    /// Timestamp (seconds, not millis to save space)
    #[serde(rename = "t")]
    pub timestamp: u64,
}

impl IceMessage {
    pub fn new(
        session_id: String,
        peer_id: &PeerId,
        channel_id: Option<&ChannelId>,
        credentials: &IceCredentials,
        candidates: &[IceCandidate],
        transport_port: Option<u16>,
    ) -> Self {
        Self {
            // Truncate session_id to 8 chars for compactness
            session_id: session_id.chars().take(8).collect(),
            // Truncate peer_id to first 16 hex chars (64 bits - enough for uniqueness)
            peer_id: peer_id.to_hex().chars().take(16).collect(),
            // Truncate channel_id to first 16 hex chars
            channel_id: channel_id.map(|c| c.to_hex().chars().take(16).collect()),
            ufrag: credentials.ufrag.clone(),
            pwd: credentials.pwd.clone(),
            // Use compact candidate format
            candidates: candidates.iter().map(|c| Self::candidate_to_compact(c)).collect(),
            nat_type: None,
            transport_port,
            // Use seconds instead of millis
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Generate unique session ID (8 chars for compactness)
    pub fn generate_session_id() -> String {
        use rand::distributions::Alphanumeric;
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect()
    }
    
    /// Convert candidate to compact format: "t:ip:port" or "t:ip:port/rip:rport"
    /// t = h (host), u (upnp/port-mapped), s (srflx), p (prflx), r (relay)
    fn candidate_to_compact(candidate: &IceCandidate) -> String {
        let typ = match candidate.candidate_type {
            CandidateType::Host => 'h',
            CandidateType::PortMapped => 'u', // UPnP port-mapped
            CandidateType::ServerReflexive => 's',
            CandidateType::PeerReflexive => 'p',
            CandidateType::Relay => 'r',
        };
        
        let base = format!("{}:{}:{}", typ, candidate.address.ip(), candidate.address.port());
        
        if let Some(ref raddr) = candidate.related_address {
            format!("{}/{}:{}", base, raddr.ip(), raddr.port())
        } else {
            base
        }
    }
    
    /// Parse compact candidate format back to full candidate
    pub fn compact_to_candidate(compact: &str) -> Option<IceCandidate> {
        use std::net::SocketAddr;
        
        // Format: "t:ip:port" or "t:ip:port/rip:rport"
        let (main, related) = if let Some(pos) = compact.find('/') {
            (&compact[..pos], Some(&compact[pos+1..]))
        } else {
            (compact, None)
        };
        
        let parts: Vec<&str> = main.split(':').collect();
        if parts.len() < 3 {
            return None;
        }
        
        let candidate_type = match parts[0] {
            "h" => CandidateType::Host,
            "u" => CandidateType::PortMapped, // UPnP port-mapped
            "s" => CandidateType::ServerReflexive,
            "p" => CandidateType::PeerReflexive,
            "r" => CandidateType::Relay,
            _ => return None,
        };
        
        // Handle IPv6 addresses which contain colons
        let (ip_str, port_str) = if parts.len() > 3 {
            // IPv6: t:ip:ip:ip:ip:ip:ip:port -> join all but first and last
            let port = parts.last()?;
            let ip = parts[1..parts.len()-1].join(":");
            (ip, port.to_string())
        } else {
            (parts[1].to_string(), parts[2].to_string())
        };
        
        let ip: std::net::IpAddr = ip_str.parse().ok()?;
        let port: u16 = port_str.parse().ok()?;
        let address = SocketAddr::new(ip, port);
        
        let related_address = if let Some(r) = related {
            let rparts: Vec<&str> = r.split(':').collect();
            if rparts.len() >= 2 {
                let (rip_str, rport_str) = if rparts.len() > 2 {
                    let rport = rparts.last()?;
                    let rip = rparts[..rparts.len()-1].join(":");
                    (rip, rport.to_string())
                } else {
                    (rparts[0].to_string(), rparts[1].to_string())
                };
                let rip: std::net::IpAddr = rip_str.parse().ok()?;
                let rport: u16 = rport_str.parse().ok()?;
                Some(SocketAddr::new(rip, rport))
            } else {
                None
            }
        } else {
            None
        };
        
        // Calculate priority like the original implementation
        let type_pref: u32 = match candidate_type {
            CandidateType::PortMapped => 126, // Same as host - direct connectivity
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        };
        let local_pref: u32 = if address.is_ipv6() { 65535 } else { 65534 };
        let priority = (type_pref << 24) + (local_pref << 8) + 255;
        
        // Build foundation string before moving candidate_type
        let foundation = format!("{:?}_{}", candidate_type, address.ip());
        
        Some(IceCandidate {
            candidate_type,
            protocol: "udp".to_string(),
            address,
            base_address: related_address.or(Some(address)),
            priority,
            foundation,
            component: 1,
            related_address,
        })
    }
    
    /// Expand compact candidates to full IceCandidate objects
    pub fn expand_candidates(&self) -> Vec<IceCandidate> {
        self.candidates
            .iter()
            .filter_map(|c| Self::compact_to_candidate(c))
            .collect()
    }
}

/// Channel invite message - uses short field names to fit in IRC CTCP limit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteMessage {
    /// Invite ID
    #[serde(rename = "i")]
    pub invite_id: String,
    /// Channel ID (hex)
    #[serde(rename = "c")]
    pub channel_id: String,
    /// Channel name (plaintext for display)
    #[serde(rename = "n")]
    pub channel_name: String,
    /// Inviter peer ID
    #[serde(rename = "r")]
    pub inviter: String,
    /// Invitee peer ID (for verification)
    #[serde(rename = "e")]
    pub invitee: String,
    /// Channel member count
    #[serde(rename = "m")]
    pub member_count: u32,
    /// Expiry timestamp
    #[serde(rename = "x")]
    pub expires_at: u64,
    /// Signature over invite
    #[serde(rename = "s")]
    pub signature: String,
    /// IRC network this channel belongs to (profile name)
    #[serde(rename = "w", default)]
    pub network: String,
}

impl InviteMessage {
    pub fn new(
        channel_id: &ChannelId,
        channel_name: &str,
        inviter: &PeerId,
        invitee: &PeerId,
        member_count: u32,
        network: &str,
    ) -> Self {
        let invite_id: String = {
            use rand::distributions::Alphanumeric;
            use rand::Rng;
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(12) // Shorter invite ID
                .map(char::from)
                .collect()
        };

        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + 3600; // 1 hour expiry

        // Use truncated hex strings (16 chars = 8 bytes) for peer IDs to fit in IRC CTCP limit
        // Still unique enough for correlation within IRC context
        // BUT: channel_id must be full 64 chars for proper channel identification and leave operations
        let channel_hex = channel_id.to_hex();
        let inviter_hex = inviter.to_hex();
        let invitee_hex = invitee.to_hex();
        
        Self {
            invite_id,
            channel_id: channel_hex, // Full channel ID - essential for channel operations
            channel_name: channel_name.chars().take(32).collect(), // Limit name length
            inviter: inviter_hex.chars().take(16).collect(),
            invitee: invitee_hex.chars().take(16).collect(),
            member_count,
            expires_at,
            signature: String::new(), // Signed after creation
            network: network.to_string(),
        }
    }

    /// Check if invite is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }
}

/// Presence heartbeat message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceMessage {
    /// Our peer ID
    pub peer_id: String,
    /// Channels we're in (hashed for privacy)
    pub channel_hashes: Vec<String>,
    /// Online status
    pub status: String,
    /// NAT type (for connection hints)
    pub nat_type: Option<String>,
    /// Timestamp
    pub timestamp: u64,
}

impl PresenceMessage {
    pub fn new(peer_id: &PeerId, channels: &[ChannelId], status: &str) -> Self {
        // Hash channel IDs for privacy
        let channel_hashes = channels
            .iter()
            .map(|c| {
                let mut hasher = Sha256::new();
                hasher.update(c.0);
                hex::encode(&hasher.finalize()[..8])
            })
            .collect();

        Self {
            peer_id: peer_id.to_hex(),
            channel_hashes,
            status: status.to_string(),
            nat_type: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }
}

/// Identity announcement (public key fingerprint)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityMessage {
    /// Peer ID
    pub peer_id: String,
    /// Identity public key (hex)
    pub identity_key: String,
    /// Key fingerprint
    pub fingerprint: String,
    /// Display name
    pub display_name: String,
    /// Signed pre-key (hex)
    pub signed_prekey: Option<String>,
    /// Timestamp
    pub timestamp: u64,
    /// Signature over identity data
    pub signature: String,
}

/// Request for channel metadata synchronization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetadataSyncRequest {
    /// Channel ID (hex)
    pub channel_id: String,
    /// Our current metadata version (0 if we have none)
    pub current_version: u64,
    /// Requester's peer ID
    pub requester: String,
    /// Timestamp
    pub timestamp: u64,
}

impl MetadataSyncRequest {
    pub fn new(channel_id: &ChannelId, current_version: u64, requester: &PeerId) -> Self {
        Self {
            channel_id: channel_id.to_hex(),
            current_version,
            requester: requester.to_hex(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }
}

/// Channel metadata response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetadataResponse {
    /// Channel ID (hex)
    pub channel_id: String,
    /// Channel name
    pub name: String,
    /// Channel topic
    pub topic: String,
    /// Metadata version
    pub version: u64,
    /// Creator's peer ID
    pub creator: String,
    /// Admin peer IDs
    pub admins: Vec<String>,
    /// Member count
    pub member_count: u32,
    /// Whether discoverable
    pub discoverable: bool,
    /// Whether invite-only
    pub invite_only: bool,
    /// Previous hash (for chain validation)
    pub previous_hash: Option<String>,
    /// Signature over metadata
    pub signature: String,
    /// Timestamp
    pub timestamp: u64,
}

impl MetadataResponse {
    pub fn from_metadata(metadata: &ChannelMetadata, member_count: u32) -> Self {
        Self {
            channel_id: metadata.channel_id.to_hex(),
            name: metadata.name.clone(),
            topic: metadata.topic.clone(),
            version: metadata.version,
            creator: hex::encode(metadata.creator.0),
            admins: metadata.admins.iter().map(|a| hex::encode(a.0)).collect(),
            member_count,
            discoverable: metadata.settings.discoverable,
            invite_only: metadata.settings.invite_only,
            previous_hash: metadata.previous_hash.map(|h| hex::encode(h)),
            signature: hex::encode(metadata.signature),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }
}

/// Acknowledgment message for reliable delivery
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AckMessage {
    /// Message ID being acknowledged
    pub message_id: String,
    /// Channel ID (hex)
    pub channel_id: String,
    /// Sequence number being acknowledged
    pub sequence: u64,
    /// Acknowledger's peer ID
    pub from: String,
    /// Timestamp
    pub timestamp: u64,
}

impl AckMessage {
    pub fn new(message_id: &str, channel_id: &ChannelId, sequence: u64, from: &PeerId) -> Self {
        Self {
            message_id: message_id.to_string(),
            channel_id: channel_id.to_hex(),
            sequence,
            from: from.to_hex(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }
}

// =============================================================================
// CTCP Message Encoding/Decoding
// =============================================================================

/// Encode a signaling message for CTCP transport
pub fn encode_ctcp(command: NscCtcpCommand, payload: &impl Serialize) -> IrcResult<String> {
    let json = serde_json::to_string(payload)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;

    // Base64 encode to handle special characters
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &json);

    let ctcp = format!("\x01{} {}\x01", command.as_str(), encoded);

    if ctcp.len() > MAX_CTCP_LENGTH {
        log::warn!("CTCP message too long: {} bytes (max {}), command: {}", ctcp.len(), MAX_CTCP_LENGTH, command.as_str());
        return Err(IrcIntegrationError::InvalidCtcp(format!("Message too long: {} bytes (max {})", ctcp.len(), MAX_CTCP_LENGTH)));
    }

    Ok(ctcp)
}

/// Decode a CTCP signaling message
pub fn decode_ctcp<T: for<'de> Deserialize<'de>>(ctcp: &str) -> IrcResult<(NscCtcpCommand, T)> {
    // Remove CTCP markers
    if !ctcp.starts_with('\x01') || !ctcp.ends_with('\x01') {
        return Err(IrcIntegrationError::InvalidCtcp("Not a CTCP message".into()));
    }

    let content = &ctcp[1..ctcp.len() - 1];

    // Split command and payload
    let (command_str, encoded) = content
        .split_once(' ')
        .ok_or_else(|| IrcIntegrationError::InvalidCtcp("Missing payload".into()))?;

    let command = NscCtcpCommand::from_str(command_str)
        .ok_or_else(|| IrcIntegrationError::InvalidCtcp(format!("Unknown command: {}", command_str)))?;

    // Base64 decode
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;

    let payload: T = serde_json::from_slice(&json)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;

    Ok((command, payload))
}

/// Parse a raw CTCP string into command and args
pub fn parse_raw_ctcp(ctcp: &str) -> Option<(String, String)> {
    if !ctcp.starts_with('\x01') || !ctcp.ends_with('\x01') {
        return None;
    }

    let content = &ctcp[1..ctcp.len() - 1];
    if let Some(space_pos) = content.find(' ') {
        Some((
            content[..space_pos].to_string(),
            content[space_pos + 1..].to_string(),
        ))
    } else {
        Some((content.to_string(), String::new()))
    }
}

// =============================================================================
// Peer Presence Tracking
// =============================================================================

/// Tracked peer presence info
#[derive(Clone, Debug)]
pub struct PeerPresence {
    /// Peer's IRC nickname
    pub nick: String,
    /// Peer ID (if known)
    pub peer_id: Option<PeerId>,
    /// NSC capability confirmed
    pub nsc_capable: bool,
    /// NAT type (if known)
    pub nat_type: Option<NatType>,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Channel hashes they announced
    pub channel_hashes: Vec<String>,
    /// Identity fingerprint (if announced)
    pub fingerprint: Option<String>,
    /// Online status
    pub status: PresenceStatus,
    /// Display name / username reported by the peer
    pub display_name: Option<String>,
}

/// Peer online status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceStatus {
    /// Online and available
    Online,
    /// Away
    Away,
    /// Do not disturb
    DoNotDisturb,
    /// Offline (not seen recently)
    Offline,
    /// Unknown status
    Unknown,
}

impl Default for PeerPresence {
    fn default() -> Self {
        Self {
            nick: String::new(),
            peer_id: None,
            nsc_capable: false,
            nat_type: None,
            last_seen: Instant::now(),
            channel_hashes: Vec::new(),
            fingerprint: None,
            status: PresenceStatus::Unknown,
            display_name: None,
        }
    }
}

/// Presence tracker for IRC users
pub struct PresenceTracker {
    /// Tracked peers by IRC nick
    peers: HashMap<String, PeerPresence>,
    /// Map peer ID to IRC nick
    peer_id_to_nick: HashMap<PeerId, String>,
    /// Presence timeout
    timeout: Duration,
}

impl PresenceTracker {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            peer_id_to_nick: HashMap::new(),
            timeout: PRESENCE_TIMEOUT,
        }
    }

    /// Update presence from probe response
    pub fn update_from_probe(&mut self, nick: &str, probe: &ProbeMessage) {
        let peer_id = hex_to_peer_id(&probe.peer_id);
        
        let presence = self.peers.entry(nick.to_string()).or_insert_with(|| {
            PeerPresence {
                nick: nick.to_string(),
                ..Default::default()
            }
        });

        presence.nsc_capable = true;
        presence.peer_id = peer_id;
        presence.last_seen = Instant::now();
        presence.status = PresenceStatus::Online;

        if let Some(nat_str) = &probe.nat_type {
            presence.nat_type = parse_nat_type(nat_str);
        }

        // Update display name if provided in probe
        if let Some(ref name) = probe.display_name {
            presence.display_name = Some(name.clone());
        }

        // Update reverse lookup
        if let Some(pid) = peer_id {
            self.peer_id_to_nick.insert(pid, nick.to_string());
        }
    }

    /// Update presence from heartbeat
    pub fn update_from_presence(&mut self, nick: &str, msg: &PresenceMessage) {
        let peer_id = hex_to_peer_id(&msg.peer_id);

        let presence = self.peers.entry(nick.to_string()).or_insert_with(|| {
            PeerPresence {
                nick: nick.to_string(),
                ..Default::default()
            }
        });

        presence.peer_id = peer_id;
        presence.nsc_capable = true;
        presence.channel_hashes = msg.channel_hashes.clone();
        presence.last_seen = Instant::now();
        presence.status = match msg.status.as_str() {
            "online" => PresenceStatus::Online,
            "away" => PresenceStatus::Away,
            "dnd" => PresenceStatus::DoNotDisturb,
            _ => PresenceStatus::Online,
        };

        if let Some(nat_str) = &msg.nat_type {
            presence.nat_type = parse_nat_type(nat_str);
        }

        if let Some(pid) = peer_id {
            self.peer_id_to_nick.insert(pid, nick.to_string());
        }
    }

    /// Update presence from identity announcement
    pub fn update_from_identity(&mut self, nick: &str, msg: &IdentityMessage) {
        let peer_id = hex_to_peer_id(&msg.peer_id);

        let presence = self.peers.entry(nick.to_string()).or_insert_with(|| {
            PeerPresence {
                nick: nick.to_string(),
                ..Default::default()
            }
        });

        presence.peer_id = peer_id;
        presence.fingerprint = Some(msg.fingerprint.clone());
        presence.last_seen = Instant::now();

        if let Some(pid) = peer_id {
            self.peer_id_to_nick.insert(pid, nick.to_string());
        }
    }

    /// Mark peer as offline (e.g., on QUIT)
    pub fn mark_offline(&mut self, nick: &str) {
        if let Some(presence) = self.peers.get_mut(nick) {
            presence.status = PresenceStatus::Offline;
        }
    }

    /// Remove peer (on PART/QUIT)
    pub fn remove(&mut self, nick: &str) {
        if let Some(presence) = self.peers.remove(nick) {
            if let Some(peer_id) = presence.peer_id {
                self.peer_id_to_nick.remove(&peer_id);
            }
        }
    }

    /// Get presence by nick
    pub fn get_by_nick(&self, nick: &str) -> Option<&PeerPresence> {
        self.peers.get(nick)
    }

    /// Get presence by peer ID
    pub fn get_by_peer_id(&self, peer_id: &PeerId) -> Option<&PeerPresence> {
        self.peer_id_to_nick
            .get(peer_id)
            .and_then(|nick| self.peers.get(nick))
    }

    /// Get IRC nick for peer ID
    pub fn nick_for_peer(&self, peer_id: &PeerId) -> Option<&str> {
        self.peer_id_to_nick.get(peer_id).map(|s| s.as_str())
    }

    /// Get all NSC-capable peers
    pub fn nsc_peers(&self) -> impl Iterator<Item = &PeerPresence> {
        self.peers.values().filter(|p| p.nsc_capable)
    }

    /// Get all online peers
    pub fn online_peers(&self) -> impl Iterator<Item = &PeerPresence> {
        self.peers
            .values()
            .filter(|p| p.status == PresenceStatus::Online || p.status == PresenceStatus::Away)
    }

    /// Clean up stale entries
    pub fn cleanup_stale(&mut self) {
        let now = Instant::now();
        let stale_nicks: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, p)| now.duration_since(p.last_seen) > self.timeout)
            .map(|(n, _)| n.clone())
            .collect();

        for nick in stale_nicks {
            self.remove(&nick);
        }
    }
}

impl Default for PresenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// ICE Signaling State Machine
// =============================================================================

/// State of an ICE signaling exchange
#[derive(Clone, Debug)]
pub enum IceSignalingState {
    /// No signaling in progress
    Idle,
    /// Sent offer, waiting for answer
    OfferSent {
        session_id: String,
        target_nick: String,
        sent_at: Instant,
    },
    /// Received offer, need to send answer
    OfferReceived {
        session_id: String,
        from_nick: String,
        offer: IceMessage,
    },
    /// Answer sent, waiting for connection
    AnswerSent {
        session_id: String,
        target_nick: String,
    },
    /// Exchange complete
    Complete {
        session_id: String,
        peer_nick: String,
    },
    /// Exchange failed
    Failed {
        reason: String,
    },
}

/// Manages ICE signaling via IRC CTCP
pub struct IceSignalingManager {
    /// Current signaling state per peer
    states: HashMap<String, IceSignalingState>,
    /// Pending offers we sent
    pending_offers: HashMap<String, IceMessage>,
    /// Received answers
    received_answers: HashMap<String, IceMessage>,
    /// Handler for completed exchanges
    completion_tx: Option<mpsc::Sender<(String, IceMessage, IceMessage)>>,
}

impl IceSignalingManager {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            pending_offers: HashMap::new(),
            received_answers: HashMap::new(),
            completion_tx: None,
        }
    }

    /// Set completion handler
    pub fn set_completion_handler(&mut self, tx: mpsc::Sender<(String, IceMessage, IceMessage)>) {
        self.completion_tx = Some(tx);
    }

    /// Start ICE exchange with peer
    pub fn start_exchange(
        &mut self,
        target_nick: &str,
        offer: IceMessage,
    ) -> IrcResult<String> {
        // Check if already in progress
        if let Some(state) = self.states.get(target_nick) {
            if !matches!(state, IceSignalingState::Idle | IceSignalingState::Failed { .. }) {
                return Err(IrcIntegrationError::AlreadyConnected);
            }
        }

        let session_id = offer.session_id.clone();

        self.states.insert(
            target_nick.to_string(),
            IceSignalingState::OfferSent {
                session_id: session_id.clone(),
                target_nick: target_nick.to_string(),
                sent_at: Instant::now(),
            },
        );

        self.pending_offers.insert(session_id.clone(), offer);

        Ok(session_id)
    }

    /// Handle received ICE offer
    pub fn receive_offer(&mut self, from_nick: &str, offer: IceMessage) {
        self.states.insert(
            from_nick.to_string(),
            IceSignalingState::OfferReceived {
                session_id: offer.session_id.clone(),
                from_nick: from_nick.to_string(),
                offer,
            },
        );
    }

    /// Mark answer as sent
    pub fn mark_answer_sent(&mut self, target_nick: &str, session_id: &str) {
        self.states.insert(
            target_nick.to_string(),
            IceSignalingState::AnswerSent {
                session_id: session_id.to_string(),
                target_nick: target_nick.to_string(),
            },
        );
    }

    /// Handle received ICE answer
    pub async fn receive_answer(&mut self, from_nick: &str, answer: IceMessage) {
        // Find matching offer
        if let Some(offer) = self.pending_offers.remove(&answer.session_id) {
            self.states.insert(
                from_nick.to_string(),
                IceSignalingState::Complete {
                    session_id: answer.session_id.clone(),
                    peer_nick: from_nick.to_string(),
                },
            );

            // Notify completion handler
            if let Some(ref tx) = self.completion_tx {
                let _ = tx.send((from_nick.to_string(), offer, answer)).await;
            }
        }
    }

    /// Handle additional ICE candidate
    pub fn add_candidate(&mut self, from_nick: &str, candidate: &str) {
        // In a full implementation, this would add the candidate to the
        // ongoing ICE exchange. For now, we log it.
        log::debug!("Received ICE candidate from {}: {}", from_nick, candidate);
    }

    /// Get current state for peer
    pub fn get_state(&self, nick: &str) -> Option<&IceSignalingState> {
        self.states.get(nick)
    }

    /// Check for timed out offers
    pub fn check_timeouts(&mut self) -> Vec<String> {
        let now = Instant::now();
        let mut timed_out = Vec::new();

        for (nick, state) in &self.states {
            if let IceSignalingState::OfferSent { sent_at, .. } = state {
                if now.duration_since(*sent_at) > ICE_OFFER_TIMEOUT {
                    timed_out.push(nick.clone());
                }
            }
        }

        for nick in &timed_out {
            self.states.insert(
                nick.clone(),
                IceSignalingState::Failed {
                    reason: "Timeout".to_string(),
                },
            );
        }

        timed_out
    }

    /// Reset state for peer
    pub fn reset(&mut self, nick: &str) {
        self.states.remove(nick);
    }
}

impl Default for IceSignalingManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Invite Manager
// =============================================================================

/// Manages channel invites via IRC
pub struct InviteManager {
    /// Sent invites (invite_id -> invite)
    sent_invites: HashMap<String, InviteMessage>,
    /// Received invites (invite_id -> (from_nick, invite))
    received_invites: HashMap<String, (String, InviteMessage)>,
    /// Handler for accepted invites
    accept_tx: Option<mpsc::Sender<(String, InviteMessage)>>,
}

impl InviteManager {
    pub fn new() -> Self {
        Self {
            sent_invites: HashMap::new(),
            received_invites: HashMap::new(),
            accept_tx: None,
        }
    }

    /// Set accept handler
    pub fn set_accept_handler(&mut self, tx: mpsc::Sender<(String, InviteMessage)>) {
        self.accept_tx = Some(tx);
    }

    /// Create and track an invite
    pub fn create_invite(
        &mut self,
        channel_id: &ChannelId,
        channel_name: &str,
        inviter: &PeerId,
        invitee: &PeerId,
        member_count: u32,
        network: &str,
    ) -> InviteMessage {
        let invite = InviteMessage::new(channel_id, channel_name, inviter, invitee, member_count, network);
        self.sent_invites.insert(invite.invite_id.clone(), invite.clone());
        invite
    }

    /// Handle received invite
    pub fn receive_invite(&mut self, from_nick: &str, invite: InviteMessage) {
        if !invite.is_expired() {
            self.received_invites
                .insert(invite.invite_id.clone(), (from_nick.to_string(), invite));
        }
    }

    /// Handle invite acceptance
    pub async fn handle_accept(&mut self, from_nick: &str, invite_id: &str) {
        if let Some(invite) = self.sent_invites.remove(invite_id) {
            if let Some(ref tx) = self.accept_tx {
                let _ = tx.send((from_nick.to_string(), invite)).await;
            }
        }
    }

    /// Handle invite decline
    pub fn handle_decline(&mut self, invite_id: &str) {
        self.sent_invites.remove(invite_id);
    }

    /// Get pending received invites
    pub fn pending_invites(&self) -> Vec<&InviteMessage> {
        self.received_invites
            .values()
            .filter(|(_, i)| !i.is_expired())
            .map(|(_, i)| i)
            .collect()
    }

    /// Accept a received invite
    pub fn accept(&mut self, invite_id: &str) -> Option<InviteMessage> {
        self.received_invites.remove(invite_id).map(|(_, i)| i)
    }

    /// Decline a received invite
    pub fn decline(&mut self, invite_id: &str) {
        self.received_invites.remove(invite_id);
    }

    /// Clean up expired invites
    pub fn cleanup_expired(&mut self) {
        self.sent_invites.retain(|_, i| !i.is_expired());
        self.received_invites.retain(|_, (_, i)| !i.is_expired());
    }
}

impl Default for InviteManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// IRC Integration Bridge
// =============================================================================

/// Events from IRC signaling to secure channel layer
#[derive(Clone, Debug)]
pub enum IrcSignalingEvent {
    /// Peer probed and responded with capabilities
    PeerDiscovered {
        nick: String,
        peer_id: PeerId,
        nat_type: Option<NatType>,
    },
    /// ICE exchange completed
    IceExchangeComplete {
        nick: String,
        local_offer: IceMessage,
        remote_answer: IceMessage,
    },
    /// Invite received
    InviteReceived {
        from_nick: String,
        invite: InviteMessage,
    },
    /// Invite accepted
    InviteAccepted {
        nick: String,
        invite: InviteMessage,
    },
    /// Peer came online
    PeerOnline {
        nick: String,
        peer_id: Option<PeerId>,
    },
    /// Peer went offline
    PeerOffline {
        nick: String,
        peer_id: Option<PeerId>,
    },
    /// Metadata sync request received
    MetadataSyncRequested {
        from_nick: String,
        channel_id: String,
        current_version: u64,
    },
    /// Metadata response received
    MetadataReceived {
        from_nick: String,
        channel_id: String,
        version: u64,
        name: String,
        topic: String,
    },
    /// Acknowledgment received
    AckReceived {
        from_nick: String,
        message_id: String,
        timestamp: u64,
    },
}

/// Commands to send via IRC signaling
#[derive(Clone, Debug)]
pub enum IrcSignalingCommand {
    /// Send probe to discover NSC peers
    Probe { target: String },
    /// Send ICE offer
    SendIceOffer { target: String, offer: IceMessage },
    /// Send ICE answer
    SendIceAnswer { target: String, answer: IceMessage },
    /// Send channel invite
    SendInvite { target: String, invite: InviteMessage },
    /// Accept invite
    AcceptInvite { target: String, invite_id: String },
    /// Decline invite
    DeclineInvite { target: String, invite_id: String },
    /// Broadcast presence
    BroadcastPresence { presence: PresenceMessage },
    /// Announce identity
    AnnounceIdentity { identity: IdentityMessage },
}

/// Bridge between IRC layer and secure channel layer
pub struct IrcIntegrationBridge {
    /// Presence tracker
    pub presence: Arc<RwLock<PresenceTracker>>,
    /// ICE signaling manager
    pub ice_signaling: Arc<RwLock<IceSignalingManager>>,
    /// Invite manager
    pub invites: Arc<RwLock<InviteManager>>,
    /// Event sender (to secure channel layer)
    event_tx: mpsc::Sender<IrcSignalingEvent>,
    /// Command receiver (from secure channel layer)
    command_rx: Arc<RwLock<mpsc::Receiver<IrcSignalingCommand>>>,
    /// Our peer ID
    local_peer_id: PeerId,
}

impl IrcIntegrationBridge {
    /// Create new integration bridge
    pub fn new(
        local_peer_id: PeerId,
    ) -> (Self, mpsc::Receiver<IrcSignalingEvent>, mpsc::Sender<IrcSignalingCommand>) {
        let (event_tx, event_rx) = mpsc::channel(100);
        let (command_tx, command_rx) = mpsc::channel(100);

        let bridge = Self {
            presence: Arc::new(RwLock::new(PresenceTracker::new())),
            ice_signaling: Arc::new(RwLock::new(IceSignalingManager::new())),
            invites: Arc::new(RwLock::new(InviteManager::new())),
            event_tx,
            command_rx: Arc::new(RwLock::new(command_rx)),
            local_peer_id,
        };

        (bridge, event_rx, command_tx)
    }

    /// Handle incoming CTCP message from IRC
    pub async fn handle_ctcp(&self, from_nick: &str, command: &str, args: &str) -> IrcResult<Option<String>> {
        let Some(cmd) = NscCtcpCommand::from_str(command) else {
            return Ok(None); // Not an NSC command
        };

        match cmd {
            NscCtcpCommand::Probe => {
                // Respond with our capabilities
                let response = ProbeMessage::new(&self.local_peer_id, None);
                let ctcp = encode_ctcp(NscCtcpCommand::ProbeResponse, &response)?;
                Ok(Some(ctcp))
            }

            NscCtcpCommand::ProbeResponse => {
                // Parse probe response
                if let Ok(probe) = decode_probe_response(args) {
                    self.presence.write().await.update_from_probe(from_nick, &probe);

                    if let Some(peer_id) = hex_to_peer_id(&probe.peer_id) {
                        let _ = self.event_tx.send(IrcSignalingEvent::PeerDiscovered {
                            nick: from_nick.to_string(),
                            peer_id,
                            nat_type: probe.nat_type.as_ref().and_then(|s| parse_nat_type(s)),
                        }).await;
                    }
                }
                Ok(None)
            }

            NscCtcpCommand::IceOffer => {
                if let Ok(offer) = decode_ice_message(args) {
                    self.ice_signaling.write().await.receive_offer(from_nick, offer);
                }
                Ok(None)
            }

            NscCtcpCommand::IceAnswer => {
                if let Ok(answer) = decode_ice_message(args) {
                    self.ice_signaling.write().await.receive_answer(from_nick, answer).await;
                }
                Ok(None)
            }

            NscCtcpCommand::IceCandidate => {
                self.ice_signaling.write().await.add_candidate(from_nick, args);
                Ok(None)
            }

            NscCtcpCommand::Invite => {
                if let Ok(invite) = decode_invite_message(args) {
                    self.invites.write().await.receive_invite(from_nick, invite.clone());
                    let _ = self.event_tx.send(IrcSignalingEvent::InviteReceived {
                        from_nick: from_nick.to_string(),
                        invite,
                    }).await;
                }
                Ok(None)
            }

            NscCtcpCommand::InviteAccept => {
                // Parse invite_id from args
                if let Ok(invite_id) = String::from_utf8(
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args)
                        .unwrap_or_default(),
                ) {
                    self.invites.write().await.handle_accept(from_nick, &invite_id).await;
                }
                Ok(None)
            }

            NscCtcpCommand::InviteDecline => {
                if let Ok(invite_id) = String::from_utf8(
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args)
                        .unwrap_or_default(),
                ) {
                    self.invites.write().await.handle_decline(&invite_id);
                }
                Ok(None)
            }

            NscCtcpCommand::Presence => {
                if let Ok(presence) = decode_presence_message(args) {
                    self.presence.write().await.update_from_presence(from_nick, &presence);
                }
                Ok(None)
            }

            NscCtcpCommand::Identity => {
                if let Ok(identity) = decode_identity_message(args) {
                    self.presence.write().await.update_from_identity(from_nick, &identity);
                }
                Ok(None)
            }

            NscCtcpCommand::KeyPackage => {
                // Key package handling would go here
                Ok(None)
            }

            NscCtcpCommand::MetadataSync => {
                // Metadata sync request - respond with channel metadata if we have it
                if let Ok(sync_req) = decode_metadata_sync_request(args) {
                    let _ = self.event_tx.send(IrcSignalingEvent::MetadataSyncRequested {
                        from_nick: from_nick.to_string(),
                        channel_id: sync_req.channel_id,
                        current_version: sync_req.current_version,
                    }).await;
                }
                Ok(None)
            }

            NscCtcpCommand::Metadata => {
                // Metadata response received
                if let Ok(metadata) = decode_metadata_response(args) {
                    let _ = self.event_tx.send(IrcSignalingEvent::MetadataReceived {
                        from_nick: from_nick.to_string(),
                        channel_id: metadata.channel_id,
                        version: metadata.version,
                        name: metadata.name,
                        topic: metadata.topic,
                    }).await;
                }
                Ok(None)
            }

            NscCtcpCommand::Ack => {
                // Acknowledgment message received
                if let Ok(ack) = decode_ack_message(args) {
                    let _ = self.event_tx.send(IrcSignalingEvent::AckReceived {
                        from_nick: from_nick.to_string(),
                        message_id: ack.message_id,
                        timestamp: ack.timestamp,
                    }).await;
                }
                Ok(None)
            }
        }
    }

    /// Handle IRC user joining
    pub async fn handle_user_join(&self, nick: &str) {
        // Add to presence tracker
        let mut presence = self.presence.write().await;
        presence.peers.entry(nick.to_string()).or_insert_with(|| {
            PeerPresence {
                nick: nick.to_string(),
                ..Default::default()
            }
        });
    }

    /// Handle IRC user parting/quitting
    pub async fn handle_user_leave(&self, nick: &str) {
        let presence = self.presence.read().await;
        let peer_id = presence.get_by_nick(nick).and_then(|p| p.peer_id);
        drop(presence);

        self.presence.write().await.mark_offline(nick);

        let _ = self.event_tx.send(IrcSignalingEvent::PeerOffline {
            nick: nick.to_string(),
            peer_id,
        }).await;
    }

    /// Build CTCP message for a command
    pub fn build_ctcp(&self, command: &IrcSignalingCommand) -> IrcResult<(String, String)> {
        match command {
            IrcSignalingCommand::Probe { target } => {
                let probe = ProbeMessage::new(&self.local_peer_id, None);
                let ctcp = encode_ctcp(NscCtcpCommand::Probe, &probe)?;
                Ok((target.clone(), ctcp))
            }

            IrcSignalingCommand::SendIceOffer { target, offer } => {
                let ctcp = encode_ctcp(NscCtcpCommand::IceOffer, offer)?;
                Ok((target.clone(), ctcp))
            }

            IrcSignalingCommand::SendIceAnswer { target, answer } => {
                let ctcp = encode_ctcp(NscCtcpCommand::IceAnswer, answer)?;
                Ok((target.clone(), ctcp))
            }

            IrcSignalingCommand::SendInvite { target, invite } => {
                let ctcp = encode_ctcp(NscCtcpCommand::Invite, invite)?;
                Ok((target.clone(), ctcp))
            }

            IrcSignalingCommand::AcceptInvite { target, invite_id } => {
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    invite_id,
                );
                let ctcp = format!("\x01{} {}\x01", NscCtcpCommand::InviteAccept.as_str(), encoded);
                Ok((target.clone(), ctcp))
            }

            IrcSignalingCommand::DeclineInvite { target, invite_id } => {
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    invite_id,
                );
                let ctcp = format!("\x01{} {}\x01", NscCtcpCommand::InviteDecline.as_str(), encoded);
                Ok((target.clone(), ctcp))
            }

            IrcSignalingCommand::BroadcastPresence { presence } => {
                // Presence is broadcast to a channel, not a specific user
                let ctcp = encode_ctcp(NscCtcpCommand::Presence, presence)?;
                Ok(("*".to_string(), ctcp))
            }

            IrcSignalingCommand::AnnounceIdentity { identity } => {
                let ctcp = encode_ctcp(NscCtcpCommand::Identity, identity)?;
                Ok(("*".to_string(), ctcp))
            }
        }
    }

    /// Get online NSC-capable peers
    pub async fn get_nsc_peers(&self) -> Vec<PeerPresence> {
        self.presence
            .read()
            .await
            .nsc_peers()
            .cloned()
            .collect()
    }

    /// Get pending invites
    pub async fn get_pending_invites(&self) -> Vec<InviteMessage> {
        self.invites
            .read()
            .await
            .pending_invites()
            .into_iter()
            .cloned()
            .collect()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert hex string to PeerId
fn hex_to_peer_id(hex: &str) -> Option<PeerId> {
    let bytes = hex::decode(hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(PeerId(arr))
}

/// Parse NAT type from string
fn parse_nat_type(s: &str) -> Option<NatType> {
    match s {
        "None" => Some(NatType::None),
        "FullCone" => Some(NatType::FullCone),
        "AddressRestricted" => Some(NatType::AddressRestricted),
        "PortRestricted" => Some(NatType::PortRestricted),
        "Symmetric" => Some(NatType::Symmetric),
        _ => Some(NatType::Unknown),
    }
}

/// Decode probe response
fn decode_probe_response(args: &str) -> IrcResult<ProbeMessage> {
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;
    serde_json::from_slice(&json)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))
}

/// Decode ICE message
fn decode_ice_message(args: &str) -> IrcResult<IceMessage> {
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;
    serde_json::from_slice(&json)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))
}

/// Decode invite message
fn decode_invite_message(args: &str) -> IrcResult<InviteMessage> {
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;
    serde_json::from_slice(&json)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))
}

/// Decode presence message
fn decode_presence_message(args: &str) -> IrcResult<PresenceMessage> {
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;
    serde_json::from_slice(&json)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))
}

/// Decode identity message
fn decode_identity_message(args: &str) -> IrcResult<IdentityMessage> {
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;
    serde_json::from_slice(&json)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))
}

/// Decode metadata sync request
fn decode_metadata_sync_request(args: &str) -> IrcResult<MetadataSyncRequest> {
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;
    serde_json::from_slice(&json)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))
}

/// Decode metadata response
fn decode_metadata_response(args: &str) -> IrcResult<MetadataResponse> {
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;
    serde_json::from_slice(&json)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))
}

/// Decode ack message
fn decode_ack_message(args: &str) -> IrcResult<AckMessage> {
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))?;
    serde_json::from_slice(&json)
        .map_err(|e| IrcIntegrationError::SerializationError(e.to_string()))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nsc_ctcp_command_roundtrip() {
        let commands = vec![
            NscCtcpCommand::Probe,
            NscCtcpCommand::ProbeResponse,
            NscCtcpCommand::IceOffer,
            NscCtcpCommand::IceAnswer,
            NscCtcpCommand::Invite,
        ];

        for cmd in commands {
            let s = cmd.as_str();
            let parsed = NscCtcpCommand::from_str(s);
            assert_eq!(parsed, Some(cmd));
        }
    }

    #[test]
    fn test_probe_message_encoding() {
        let peer_id = PeerId([1u8; 32]);
        let probe = ProbeMessage::new(&peer_id, Some(NatType::FullCone));

        let ctcp = encode_ctcp(NscCtcpCommand::Probe, &probe).unwrap();
        assert!(ctcp.starts_with('\x01'));
        assert!(ctcp.ends_with('\x01'));
        assert!(ctcp.contains("NSC_PROBE"));
    }

    #[test]
    fn test_ice_message_session_id() {
        let id1 = IceMessage::generate_session_id();
        let id2 = IceMessage::generate_session_id();
        assert_eq!(id1.len(), 8);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_invite_expiry() {
        let channel_id = ChannelId([1u8; 32]);
        let inviter = PeerId([2u8; 32]);
        let invitee = PeerId([3u8; 32]);

        let invite = InviteMessage::new(&channel_id, "Test", &inviter, &invitee, 10, "testnet");
        assert!(!invite.is_expired());

        // Manually set expired
        let mut expired = invite.clone();
        expired.expires_at = 0;
        assert!(expired.is_expired());
    }

    #[test]
    fn test_presence_tracker() {
        let mut tracker = PresenceTracker::new();

        let peer_id = PeerId([1u8; 32]);
        let probe = ProbeMessage::new(&peer_id, None);

        tracker.update_from_probe("testuser", &probe);

        assert!(tracker.get_by_nick("testuser").is_some());
        assert!(tracker.get_by_nick("testuser").unwrap().nsc_capable);

        let nsc_peers: Vec<_> = tracker.nsc_peers().collect();
        assert_eq!(nsc_peers.len(), 1);
    }

    #[test]
    fn test_presence_message() {
        let peer_id = PeerId([1u8; 32]);
        let channels = vec![ChannelId([2u8; 32]), ChannelId([3u8; 32])];

        let msg = PresenceMessage::new(&peer_id, &channels, "online");
        assert_eq!(msg.channel_hashes.len(), 2);
        assert_eq!(msg.status, "online");
    }

    #[test]
    fn test_ice_signaling_state() {
        let mut manager = IceSignalingManager::new();

        let peer_id = PeerId([1u8; 32]);
        let credentials = IceCredentials::generate();
        let offer = IceMessage::new(
            IceMessage::generate_session_id(),
            &peer_id,
            None,
            &credentials,
            &[],
            None, // No transport port in test
        );

        let session_id = manager.start_exchange("testuser", offer).unwrap();
        assert!(!session_id.is_empty());

        let state = manager.get_state("testuser").unwrap();
        assert!(matches!(state, IceSignalingState::OfferSent { .. }));
    }

    #[test]
    fn test_invite_manager() {
        let mut manager = InviteManager::new();

        let channel_id = ChannelId([1u8; 32]);
        let inviter = PeerId([2u8; 32]);
        let invitee = PeerId([3u8; 32]);

        let invite = manager.create_invite(&channel_id, "Test", &inviter, &invitee, 5, "testnet");
        assert!(!invite.invite_id.is_empty());

        // Simulate receiving an invite
        let received = InviteMessage::new(&channel_id, "Other", &inviter, &invitee, 10, "testnet");
        manager.receive_invite("sender", received);

        let pending = manager.pending_invites();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_hex_to_peer_id() {
        let peer_id = PeerId([1u8; 32]);
        let hex = peer_id.to_hex();
        let parsed = hex_to_peer_id(&hex).unwrap();
        assert_eq!(parsed.0, peer_id.0);

        // Invalid hex
        assert!(hex_to_peer_id("invalid").is_none());
        assert!(hex_to_peer_id("0102").is_none()); // Too short
    }

    #[test]
    fn test_parse_nat_type() {
        assert_eq!(parse_nat_type("FullCone"), Some(NatType::FullCone));
        assert_eq!(parse_nat_type("Symmetric"), Some(NatType::Symmetric));
        assert_eq!(parse_nat_type("unknown"), Some(NatType::Unknown));
    }

    #[tokio::test]
    async fn test_irc_bridge_creation() {
        let peer_id = PeerId([1u8; 32]);
        let (bridge, _event_rx, _command_tx) = IrcIntegrationBridge::new(peer_id);

        let peers = bridge.get_nsc_peers().await;
        assert!(peers.is_empty());

        let invites = bridge.get_pending_invites().await;
        assert!(invites.is_empty());
    }

    #[test]
    fn test_parse_raw_ctcp() {
        let ctcp = "\x01NSC_PROBE data\x01";
        let (cmd, args) = parse_raw_ctcp(ctcp).unwrap();
        assert_eq!(cmd, "NSC_PROBE");
        assert_eq!(args, "data");

        // No args
        let ctcp2 = "\x01VERSION\x01";
        let (cmd2, args2) = parse_raw_ctcp(ctcp2).unwrap();
        assert_eq!(cmd2, "VERSION");
        assert_eq!(args2, "");

        // Not CTCP
        assert!(parse_raw_ctcp("not ctcp").is_none());
    }
}
