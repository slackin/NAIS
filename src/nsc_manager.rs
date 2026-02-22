//! Nais Secure Channels - Application Manager
//!
//! High-level manager that integrates identity, channels, storage, and P2P transport for the UI.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};

use crate::nsc_channel::{ChannelId, ChannelManager};
use crate::nsc_crypto::{IdentityKeyPair, PeerSessionManager, PreKeyBundle, X3dhHeader, MessageHeader, TrustManager, TrustCheckResult, TrustVerificationMethod, KeyStorage};
use crate::nsc_irc::{IceMessage, NscCtcpCommand, encode_ctcp};
use crate::nsc_nat::{IceAgent, IceCandidate, IceCredentials};
use crate::nsc_transport::{
    MessageType, NscEnvelope, PeerId, QuicConfig, QuicTransport, TransportResult, RelayClient,
};

// =============================================================================
// Storage Types
// =============================================================================

/// Stored identity data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredIdentity {
    /// Identity private key (hex encoded)
    pub private_key: String,
    /// Display name
    pub display_name: String,
    /// Created timestamp
    pub created_at: u64,
}

/// Device information for multi-device support
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Unique device ID (derived from device key)
    pub device_id: String,
    /// Device name (e.g., "iPhone", "Desktop")
    pub name: String,
    /// Device signing public key (hex)
    pub public_key: String,
    /// When this device was linked
    pub linked_at: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Is this the primary device?
    pub is_primary: bool,
}

/// Linking request for adding new devices
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceLinkRequest {
    /// Short linking code (6 chars)
    pub link_code: String,
    /// Public key of device requesting link
    pub device_public_key: String,
    /// Device name
    pub device_name: String,
    /// Expiry timestamp
    pub expires_at: u64,
}

/// Linking response with account secrets
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceLinkResponse {
    /// Encrypted identity key (using DH shared secret)
    pub encrypted_identity: String,
    /// Encrypted epoch secrets for all channels
    pub encrypted_channel_secrets: Vec<EncryptedChannelSecrets>,
    /// Device info for the primary device
    pub primary_device: DeviceInfo,
}

/// Encrypted channel secrets for transfer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedChannelSecrets {
    /// Channel ID (hex)
    pub channel_id: String,
    /// Channel name
    pub channel_name: String,
    /// Encrypted epoch secrets (using DH shared secret)
    pub encrypted_secrets: String,
}

/// Stored channel data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredChannel {
    /// Channel ID (hex encoded)
    pub channel_id: String,
    /// Channel name
    pub name: String,
    /// Channel topic
    pub topic: String,
    /// Created timestamp
    pub created_at: u64,
    /// Member count
    pub member_count: u32,
    /// Are we the owner?
    pub is_owner: bool,
    /// IRC channel name for peer discovery
    #[serde(default)]
    pub irc_channel: String,
}

/// Stored message data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    /// Timestamp (Unix seconds)
    pub timestamp: u64,
    /// Sender fingerprint (short form)
    pub sender: String,
    /// Message text
    pub text: String,
    /// Is this from us?
    pub is_own: bool,
}

/// Full NSC storage
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NscStorage {
    /// Our identity
    pub identity: Option<StoredIdentity>,
    /// Our channels
    pub channels: Vec<StoredChannel>,
    /// Messages by channel ID
    #[serde(default)]
    pub messages: HashMap<String, Vec<StoredMessage>>,
    /// Linked devices
    #[serde(default)]
    pub devices: Vec<DeviceInfo>,
    /// This device's ID
    #[serde(default)]
    pub this_device_id: Option<String>,
    /// Encrypted peer session data (hex encoded)
    #[serde(default)]
    pub encrypted_sessions: Option<String>,
    /// Encrypted trust records (hex encoded)  
    #[serde(default)]
    pub encrypted_trust: Option<String>,
    /// PreKeyBundles from peers (fingerprint -> base64 encoded bundle)
    #[serde(default)]
    pub peer_prekey_bundles: HashMap<String, String>,
    /// IRC channel mapping for peer discovery
    #[serde(default)]
    pub irc_channel_mapping: IrcChannelMapping,
}

// =============================================================================
// IRC Channel Mapping
// =============================================================================

/// Mapping between NAIS channel IDs and IRC discovery channels
/// This mapping allows peers to discover each other via IRC channels
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IrcChannelMapping {
    /// NAIS channel ID (hex) -> IRC channel name
    nais_to_irc: HashMap<String, String>,
    /// IRC channel name -> NAIS channel ID (hex)
    irc_to_nais: HashMap<String, String>,
}

impl IrcChannelMapping {
    /// Generate opaque IRC channel name for a NAIS channel ID
    /// Format: #nais-<first 8 chars of channel_id>
    pub fn generate_irc_channel(channel_id: &str) -> String {
        let short_id = if channel_id.len() >= 8 {
            &channel_id[..8]
        } else {
            channel_id
        };
        format!("#nais-{}", short_id.to_lowercase())
    }
    
    /// Register a mapping between NAIS channel and IRC channel
    pub fn register(&mut self, nais_channel_id: String, irc_channel: String) {
        self.irc_to_nais.insert(irc_channel.clone(), nais_channel_id.clone());
        self.nais_to_irc.insert(nais_channel_id, irc_channel);
    }
    
    /// Get IRC channel for a NAIS channel ID
    pub fn get_irc_channel(&self, nais_channel_id: &str) -> Option<&String> {
        self.nais_to_irc.get(nais_channel_id)
    }
    
    /// Get NAIS channel ID for an IRC channel
    pub fn get_nais_channel(&self, irc_channel: &str) -> Option<&String> {
        self.irc_to_nais.get(irc_channel)
    }
    
    /// Remove a mapping by NAIS channel ID
    pub fn remove_by_nais(&mut self, nais_channel_id: &str) {
        if let Some(irc_channel) = self.nais_to_irc.remove(nais_channel_id) {
            self.irc_to_nais.remove(&irc_channel);
        }
    }
    
    /// Get all mappings
    pub fn all_mappings(&self) -> impl Iterator<Item = (&String, &String)> {
        self.nais_to_irc.iter()
    }
}

// =============================================================================
// Channel Info (for UI display)
// =============================================================================

/// Channel information for UI display
#[derive(Clone, Debug)]
pub struct ChannelInfo {
    pub channel_id: String,
    pub name: String,
    pub topic: String,
    pub member_count: u32,
    pub is_owner: bool,
    pub created_at: u64,
    /// IRC channel name for peer discovery (e.g., #nais-a1b2c3d4)
    pub irc_channel: String,
}

// =============================================================================
// Message Types (for UI)
// =============================================================================

/// A message in a secure channel
#[derive(Clone, Debug)]
pub struct NscMessage {
    /// Timestamp (Unix seconds)
    pub timestamp: u64,
    /// Sender fingerprint (short form)
    pub sender: String,
    /// Message text
    pub text: String,
    /// Is this from us?
    pub is_own: bool,
}

/// Events from the transport layer for the UI
#[derive(Clone, Debug)]
pub enum NscEvent {
    /// A message was received
    MessageReceived {
        channel_id: String,
        message: NscMessage,
    },
    /// A message was delivered (ACK received)
    MessageDelivered {
        channel_id: String,
        message_id: u64,
    },
    /// A peer connected
    PeerConnected {
        peer_id: String,
    },
    /// A peer disconnected
    PeerDisconnected {
        peer_id: String,
    },
    /// Connection error
    Error {
        message: String,
    },
    /// Received an invite from someone
    InviteReceived {
        from_nick: String,
        channel_name: String,
        invite_id: String,
    },
    /// Discovered an NSC-capable peer
    PeerDiscovered {
        nick: String,
        irc_channel: String,
    },
    /// A member joined a channel
    MemberJoined {
        channel_id: String,
        peer_id: String,
    },
    /// A member left a channel
    MemberLeft {
        channel_id: String,
        peer_id: String,
    },
    /// Channel metadata was updated
    MetadataUpdated {
        channel_id: String,
    },
}

// =============================================================================
// Peer Info (for connection management)
// =============================================================================

/// Information about a known peer in a channel
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer ID (hex)
    pub peer_id: String,
    /// Last known address
    pub address: Option<String>,
    /// Display name (if known)
    pub display_name: Option<String>,
    /// Last seen timestamp
    pub last_seen: u64,
}

// =============================================================================
// NSC Pending Invite (for UI display)
// =============================================================================

/// A pending invite that the user received
#[derive(Clone, Debug)]
pub struct PendingInvite {
    pub invite_id: String,
    pub from_nick: String,
    pub from_fingerprint: String,
    pub channel_name: String,
    pub channel_id: String,
    pub member_count: u32,
    pub received_at: u64,
    pub expires_at: u64,
}

/// A known NSC-capable peer from IRC
#[derive(Clone, Debug)]  
pub struct NscPeer {
    pub nick: String,
    pub fingerprint: String,
    pub peer_id: String,
    pub nat_type: Option<String>,
    pub last_seen: u64,
}

/// A pending message awaiting delivery acknowledgment
#[derive(Clone, Debug)]
pub struct PendingMessage {
    /// Channel ID (hex encoded)
    pub channel_id: String,
    /// Sequence number for this message
    pub sequence_number: u64,
    /// The serialized envelope to retry
    pub envelope_bytes: Vec<u8>,
    /// When the message was first sent
    pub sent_at: u64,
    /// Number of retry attempts made
    pub retry_count: u32,
    /// Next retry time (Unix timestamp)
    pub next_retry_at: u64,
    /// Target peer IDs we're trying to reach
    pub target_peers: Vec<PeerId>,
}

impl PendingMessage {
    /// Calculate next retry time with exponential backoff
    pub fn calculate_next_retry(&mut self) {
        // Exponential backoff: 2, 4, 8, 16, 32, 60 seconds max
        let delay_secs = std::cmp::min(2u64.pow(self.retry_count + 1), 60);
        self.next_retry_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() + delay_secs;
        self.retry_count += 1;
    }
    
    /// Check if message has exceeded maximum retries (10 attempts)
    pub fn is_expired(&self) -> bool {
        self.retry_count >= 10
    }
}

/// A member of an NSC channel (for UI display)
#[derive(Clone, Debug)]
pub struct NscChannelMember {
    /// Peer ID (hex encoded)
    pub peer_id: String,
    /// Display name (short fingerprint if unknown)
    pub display_name: String,
    /// Is this us (the local user)?
    pub is_self: bool,
    /// Is this the channel owner?
    pub is_owner: bool,
    /// When they joined (unix timestamp)
    pub joined_at: u64,
}

// =============================================================================
// NSC Manager
// =============================================================================

/// High-level manager for Nais Secure Channels
pub struct NscManager {
    /// Our identity key pair
    identity: Arc<IdentityKeyPair>,
    /// Our peer ID
    peer_id: PeerId,
    /// Channel manager
    channel_manager: ChannelManager,
    /// Cached channel info for UI
    channel_info: Arc<RwLock<HashMap<String, ChannelInfo>>>,
    /// QUIC transport (lazy initialized)
    transport: Arc<RwLock<Option<Arc<QuicTransport>>>>,
    /// Peer connections by peer ID
    peer_addresses: Arc<RwLock<HashMap<String, SocketAddr>>>,
    /// Message sequence numbers per channel
    sequence_numbers: Arc<RwLock<HashMap<String, u64>>>,
    /// Event sender for UI
    event_tx: Option<mpsc::Sender<NscEvent>>,
    /// Pending invites received from others (invite_id -> invite)
    pending_invites: Arc<RwLock<HashMap<String, PendingInvite>>>,
    /// Sent invites to others (invite_id -> sent invite info)
    sent_invites: Arc<RwLock<HashMap<String, SentInvite>>>,
    /// Known NSC-capable peers from IRC (nick -> peer info)
    known_peers: Arc<RwLock<HashMap<String, NscPeer>>>,
    /// IRC channel -> list of NSC peers in that channel
    peers_by_irc_channel: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Pending ICE sessions: session_id -> (target_nick, IceAgent, channel_id)
    pending_ice_sessions: Arc<RwLock<HashMap<String, PendingIceSession>>>,
    /// Relay client for fallback connectivity (symmetric NAT)
    relay_client: Arc<RelayClient>,
    /// This device's info
    this_device: Arc<RwLock<DeviceInfo>>,
    /// Linked devices
    linked_devices: Arc<RwLock<Vec<DeviceInfo>>>,
    /// Pending device link requests (link_code -> request)
    pending_link_requests: Arc<RwLock<HashMap<String, DeviceLinkRequest>>>,
    /// Peer session manager for Double Ratchet sessions
    peer_sessions: Arc<RwLock<PeerSessionManager>>,
    /// Cached PreKeyBundles from peers (fingerprint_hex -> bundle)
    peer_prekey_bundles: Arc<RwLock<HashMap<String, PreKeyBundle>>>,
    /// Trust manager for peer verification
    trust_manager: Arc<RwLock<TrustManager>>,
    /// Pending messages awaiting delivery acknowledgment (channel_id+seq -> pending)
    retry_queue: Arc<RwLock<HashMap<String, PendingMessage>>>,
    /// IRC channel mapping for peer discovery
    irc_channel_mapping: Arc<RwLock<IrcChannelMapping>>,
    /// Channel members for UI display (channel_id -> members)
    channel_members: Arc<RwLock<HashMap<String, Vec<NscChannelMember>>>>,
}

/// Pending ICE session info
#[derive(Clone)]
pub struct PendingIceSession {
    pub session_id: String,
    pub target_nick: String,
    pub channel_id: Option<String>,
    pub our_candidates: Vec<String>,
    pub our_ufrag: String,
    pub our_pwd: String,
    pub remote_candidates: Vec<String>,
    pub remote_ufrag: Option<String>,
    pub remote_pwd: Option<String>,
    pub created_at: u64,
    /// True if we initiated the ICE exchange
    pub is_initiator: bool,
}

/// Sent invite info (for tracking invites we sent to others)
#[derive(Clone, Debug)]
pub struct SentInvite {
    pub invite_id: String,
    pub target_nick: String,
    pub channel_id: String,
    pub created_at: u64,
}

impl NscManager {
    /// Create or load NSC manager
    pub fn new() -> Self {
        let storage = load_nsc_storage();
        
        // Load or generate identity
        let identity = if let Some(stored) = &storage.identity {
            // Load existing identity
            if let Ok(bytes) = hex::decode(&stored.private_key) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Arc::new(IdentityKeyPair::from_bytes(&arr))
                } else {
                    Arc::new(IdentityKeyPair::generate())
                }
            } else {
                Arc::new(IdentityKeyPair::generate())
            }
        } else {
            // Generate new identity
            Arc::new(IdentityKeyPair::generate())
        };
        
        // Derive peer ID from identity public key
        let peer_id = PeerId(identity.public_key().to_bytes());
        
        // Create channel manager
        let channel_manager = ChannelManager::new(identity.clone(), peer_id);
        
        // Load channel info and IRC channel mappings
        let mut channel_info = HashMap::new();
        let mut irc_channel_mapping = storage.irc_channel_mapping.clone();
        
        for ch in &storage.channels {
            // Generate IRC channel if not stored (migration for older storage)
            let irc_channel = if ch.irc_channel.is_empty() {
                let generated = IrcChannelMapping::generate_irc_channel(&ch.channel_id);
                // Register the generated mapping
                irc_channel_mapping.register(ch.channel_id.clone(), generated.clone());
                generated
            } else {
                ch.irc_channel.clone()
            };
            
            channel_info.insert(ch.channel_id.clone(), ChannelInfo {
                channel_id: ch.channel_id.clone(),
                name: ch.name.clone(),
                topic: ch.topic.clone(),
                member_count: ch.member_count,
                is_owner: ch.is_owner,
                created_at: ch.created_at,
                irc_channel,
            });
        }
        
        // Create or load device info for this device
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let device_id = storage.this_device_id.clone().unwrap_or_else(|| {
            // Generate device ID from peer ID + random component
            let mut device_bytes = [0u8; 16];
            device_bytes[..8].copy_from_slice(&peer_id.0[..8]);
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut device_bytes[8..]);
            hex::encode(device_bytes)
        });
        
        let this_device = DeviceInfo {
            device_id: device_id.clone(),
            name: Self::get_device_name(),
            public_key: hex::encode(peer_id.0),
            linked_at: now,
            last_seen: now,
            is_primary: storage.devices.is_empty(), // Primary if no other devices
        };
        
        // Create key storage for encrypted data (derive from identity)
        let storage_password = hex::encode(&identity.to_bytes()[..16]);
        let key_storage = KeyStorage::new(&storage_password).ok();
        
        // Try to load peer sessions from storage, or create new
        let peer_sessions = if let (Some(ref ks), Some(ref enc_sessions)) = (&key_storage, &storage.encrypted_sessions) {
            if let Ok(encrypted_bytes) = hex::decode(enc_sessions) {
                match ks.load_sessions(&encrypted_bytes) {
                    Ok(loaded) => {
                        log::info!("Loaded {} peer sessions from storage", loaded.session_count());
                        loaded
                    }
                    Err(e) => {
                        log::warn!("Failed to load sessions: {:?}, creating new", e);
                        PeerSessionManager::new(IdentityKeyPair::from_bytes(&identity.to_bytes()))
                    }
                }
            } else {
                PeerSessionManager::new(IdentityKeyPair::from_bytes(&identity.to_bytes()))
            }
        } else {
            PeerSessionManager::new(IdentityKeyPair::from_bytes(&identity.to_bytes()))
        };
        
        // Try to load trust records from storage, or create new
        let trust_manager = if let (Some(ref ks), Some(ref enc_trust)) = (&key_storage, &storage.encrypted_trust) {
            if let Ok(encrypted_bytes) = hex::decode(enc_trust) {
                match ks.load_trust(&encrypted_bytes) {
                    Ok(loaded) => {
                        log::info!("Loaded {} trust records from storage", loaded.all_records().len());
                        loaded
                    }
                    Err(e) => {
                        log::warn!("Failed to load trust records: {:?}, creating new", e);
                        TrustManager::new()
                    }
                }
            } else {
                TrustManager::new()
            }
        } else {
            TrustManager::new()
        };
        
        // Load peer PreKeyBundles from storage
        let mut peer_prekey_bundles = HashMap::new();
        for (fingerprint, encoded) in &storage.peer_prekey_bundles {
            if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded) {
                if let Ok(bundle) = PeerSessionManager::deserialize_prekey_bundle(&bytes) {
                    peer_prekey_bundles.insert(fingerprint.clone(), bundle);
                }
            }
        }
        log::info!("Loaded {} peer PreKeyBundles from storage", peer_prekey_bundles.len());
        
        // Initialize channel members - add ourselves to each channel we own
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let our_peer_id_hex = hex::encode(peer_id.0);
        let our_display_name = format!("{}...", &our_peer_id_hex[..8]);
        let mut channel_members = HashMap::new();
        for ch in &storage.channels {
            let self_member = NscChannelMember {
                peer_id: our_peer_id_hex.clone(),
                display_name: our_display_name.clone(),
                is_self: true,
                is_owner: ch.is_owner,
                joined_at: ch.created_at,
            };
            channel_members.insert(ch.channel_id.clone(), vec![self_member]);
        }
        
        let manager = Self {
            identity: identity.clone(),
            peer_id,
            channel_manager,
            channel_info: Arc::new(RwLock::new(channel_info)),
            transport: Arc::new(RwLock::new(None)),
            peer_addresses: Arc::new(RwLock::new(HashMap::new())),
            sequence_numbers: Arc::new(RwLock::new(HashMap::new())),
            event_tx: None,
            pending_invites: Arc::new(RwLock::new(HashMap::new())),
            sent_invites: Arc::new(RwLock::new(HashMap::new())),
            known_peers: Arc::new(RwLock::new(HashMap::new())),
            peers_by_irc_channel: Arc::new(RwLock::new(HashMap::new())),
            pending_ice_sessions: Arc::new(RwLock::new(HashMap::new())),
            relay_client: Arc::new(RelayClient::new(peer_id, identity)),
            this_device: Arc::new(RwLock::new(this_device)),
            linked_devices: Arc::new(RwLock::new(storage.devices.clone())),
            pending_link_requests: Arc::new(RwLock::new(HashMap::new())),
            peer_sessions: Arc::new(RwLock::new(peer_sessions)),
            peer_prekey_bundles: Arc::new(RwLock::new(peer_prekey_bundles)),
            trust_manager: Arc::new(RwLock::new(trust_manager)),
            retry_queue: Arc::new(RwLock::new(HashMap::new())),
            irc_channel_mapping: Arc::new(RwLock::new(irc_channel_mapping)),
            channel_members: Arc::new(RwLock::new(channel_members)),
        };
        
        // Save identity if newly generated
        if storage.identity.is_none() {
            manager.save_storage();
        }
        
        manager
    }
    
    /// Set the event sender for UI notifications
    pub fn set_event_sender(&mut self, tx: mpsc::Sender<NscEvent>) {
        self.event_tx = Some(tx);
    }
    
    /// Initialize the transport layer (must be called before sending/receiving)
    pub async fn init_transport(&self) -> Result<u16, String> {
        let mut transport_lock = self.transport.write().await;
        if transport_lock.is_some() {
            // Already initialized - return current port
            if let Some(ref t) = *transport_lock {
                return t.local_addr()
                    .map(|a| a.port())
                    .map_err(|e| format!("Failed to get port: {}", e));
            }
        }
        
        // Create new transport
        let config = QuicConfig::default();
        let transport = QuicTransport::new(config).await
            .map_err(|e| format!("Failed to create transport: {}", e))?;
        
        let port = transport.local_addr()
            .map(|a| a.port())
            .map_err(|e| format!("Failed to get port: {}", e))?;
        
        *transport_lock = Some(Arc::new(transport));
        
        log::info!("NSC transport initialized on port {}", port);
        
        Ok(port)
    }
    
    /// Get our local listening port (if transport is running)
    pub async fn local_port(&self) -> Option<u16> {
        let transport = self.transport.read().await;
        transport.as_ref()?.local_addr().ok().map(|a| a.port())
    }
    
    /// Get our identity fingerprint (for display)
    pub fn fingerprint(&self) -> String {
        self.identity.public_key().fingerprint_hex()
    }
    
    /// Create a new secure channel
    pub async fn create_channel(&self, name: String) -> Result<ChannelInfo, String> {
        let channel_id = self.channel_manager.create_channel(name.clone())
            .await
            .map_err(|e| format!("Failed to create channel: {:?}", e))?;
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let channel_id_hex = channel_id.to_hex();
        
        // Generate IRC channel name for peer discovery
        let irc_channel = IrcChannelMapping::generate_irc_channel(&channel_id_hex);
        
        // Register the mapping
        self.irc_channel_mapping.write().await.register(
            channel_id_hex.clone(),
            irc_channel.clone(),
        );
        
        let info = ChannelInfo {
            channel_id: channel_id_hex.clone(),
            name,
            topic: String::new(),
            member_count: 1,
            is_owner: true,
            created_at: now,
            irc_channel,
        };
        
        // Add ourselves as a member
        let our_peer_id = hex::encode(self.peer_id.0);
        let our_display_name = format!("{}...", &our_peer_id[..8]);
        let self_member = NscChannelMember {
            peer_id: our_peer_id,
            display_name: our_display_name,
            is_self: true,
            is_owner: true,
            joined_at: now,
        };
        self.channel_members.write().await.insert(channel_id_hex.clone(), vec![self_member]);
        
        // Cache the info
        self.channel_info.write().await.insert(info.channel_id.clone(), info.clone());
        
        // Save to storage
        self.save_storage_async().await;
        
        log::info!("Created secure channel '{}' with IRC discovery channel: {}", 
            info.name, info.irc_channel);
        
        Ok(info)
    }
    
    /// Leave a channel
    pub async fn leave_channel(&self, channel_id: &str) -> Result<(), String> {
        // Parse channel ID
        let bytes = hex::decode(channel_id)
            .map_err(|_| "Invalid channel ID")?;
        if bytes.len() != 32 {
            return Err("Invalid channel ID length".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let cid = ChannelId(arr);
        
        // Try to leave from ChannelManager, but don't fail if not found
        // (channel may only exist in storage/cache from a previous session)
        if let Err(e) = self.channel_manager.leave_channel(&cid).await {
            log::debug!("Channel not in ChannelManager (this is OK for stored channels): {:?}", e);
        }
        
        // Remove from cache
        self.channel_info.write().await.remove(channel_id);
        
        // Remove IRC channel mapping
        self.irc_channel_mapping.write().await.remove_by_nais(channel_id);
        
        // Save to storage
        self.save_storage_async().await;
        
        Ok(())
    }
    
    /// Get all channels
    pub async fn list_channels(&self) -> Vec<ChannelInfo> {
        self.channel_info.read().await.values().cloned().collect()
    }
    
    /// Get channel by ID
    pub async fn get_channel(&self, channel_id: &str) -> Option<ChannelInfo> {
        self.channel_info.read().await.get(channel_id).cloned()
    }
    
    /// Get channel by IRC channel name
    pub async fn get_channel_by_irc(&self, irc_channel: &str) -> Option<ChannelInfo> {
        let mapping = self.irc_channel_mapping.read().await;
        if let Some(channel_id) = mapping.get_nais_channel(irc_channel) {
            self.channel_info.read().await.get(channel_id).cloned()
        } else {
            None
        }
    }
    
    /// Get members of a channel for UI display
    pub async fn get_channel_members(&self, channel_id: &str) -> Vec<NscChannelMember> {
        self.channel_members.read().await
            .get(channel_id)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Add a member to a channel (internal use)
    pub async fn add_channel_member(&self, channel_id: &str, peer_id_hex: &str, is_owner: bool) {
        let mut members = self.channel_members.write().await;
        let channel_members = members.entry(channel_id.to_string()).or_insert_with(Vec::new);
        
        // Check if already a member
        if channel_members.iter().any(|m| m.peer_id == peer_id_hex) {
            return;
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let our_peer_id = hex::encode(self.peer_id.0);
        let display_name = format!("{}...", &peer_id_hex[..8.min(peer_id_hex.len())]);
        
        let member = NscChannelMember {
            peer_id: peer_id_hex.to_string(),
            display_name,
            is_self: peer_id_hex == our_peer_id,
            is_owner,
            joined_at: now,
        };
        
        channel_members.push(member);
        
        // Update member count in channel info
        let mut info = self.channel_info.write().await;
        if let Some(channel) = info.get_mut(channel_id) {
            channel.member_count = channel_members.len() as u32;
        }
    }
    
    /// Remove a member from a channel (internal use)
    pub async fn remove_channel_member(&self, channel_id: &str, peer_id_hex: &str) {
        let mut members = self.channel_members.write().await;
        if let Some(channel_members) = members.get_mut(channel_id) {
            channel_members.retain(|m| m.peer_id != peer_id_hex);
            
            // Update member count in channel info
            let mut info = self.channel_info.write().await;
            if let Some(channel) = info.get_mut(channel_id) {
                channel.member_count = channel_members.len() as u32;
            }
        }
    }
    
    /// Get the IRC channel mapping
    pub async fn get_irc_channel_mapping(&self) -> IrcChannelMapping {
        self.irc_channel_mapping.read().await.clone()
    }
    
    /// Save storage to disk (async version)
    async fn save_storage_async(&self) {
        let channels: Vec<StoredChannel> = self.channel_info.read().await.values().map(|info| StoredChannel {
            channel_id: info.channel_id.clone(),
            name: info.name.clone(),
            topic: info.topic.clone(),
            created_at: info.created_at,
            member_count: info.member_count,
            is_owner: info.is_owner,
            irc_channel: info.irc_channel.clone(),
        }).collect();
        
        let this_device = self.this_device.read().await;
        let linked_devices = self.linked_devices.read().await;
        let irc_channel_mapping = self.irc_channel_mapping.read().await.clone();
        
        // Encrypt sessions and trust records
        let storage_password = hex::encode(&self.identity.to_bytes()[..16]);
        let (encrypted_sessions, encrypted_trust) = match KeyStorage::new(&storage_password) {
            Ok(ks) => {
                let sessions = self.peer_sessions.read().await;
                let trust = self.trust_manager.read().await;
                
                let enc_sessions = ks.save_sessions(&sessions)
                    .map(|b| hex::encode(b))
                    .ok();
                let enc_trust = ks.save_trust(&trust)
                    .map(|b| hex::encode(b))
                    .ok();
                
                (enc_sessions, enc_trust)
            }
            Err(_) => (None, None),
        };
        
        // Serialize PreKeyBundles
        let bundles = self.peer_prekey_bundles.read().await;
        let peer_prekey_bundles: HashMap<String, String> = bundles.iter()
            .map(|(fingerprint, bundle)| {
                // Serialize the bundle
                let mut bundle_bytes = Vec::with_capacity(256);
                bundle_bytes.extend_from_slice(&bundle.identity_key.to_bytes());
                bundle_bytes.extend_from_slice(bundle.identity_dh_key.as_bytes());
                bundle_bytes.extend_from_slice(bundle.signed_prekey.as_bytes());
                bundle_bytes.extend_from_slice(&bundle.signed_prekey_signature);
                let otpk_count = bundle.one_time_prekeys.len().min(u16::MAX as usize) as u16;
                bundle_bytes.extend_from_slice(&otpk_count.to_be_bytes());
                for otpk in bundle.one_time_prekeys.iter().take(otpk_count as usize) {
                    bundle_bytes.extend_from_slice(otpk.as_bytes());
                }
                let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bundle_bytes);
                (fingerprint.clone(), encoded)
            })
            .collect();
        
        let storage = NscStorage {
            identity: Some(StoredIdentity {
                private_key: hex::encode(self.identity.to_bytes()),
                display_name: "Me".to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            }),
            channels,
            messages: HashMap::new(),
            devices: linked_devices.clone(),
            this_device_id: Some(this_device.device_id.clone()),
            encrypted_sessions,
            encrypted_trust,
            peer_prekey_bundles,
            irc_channel_mapping,
        };
        
        if let Err(e) = save_nsc_storage(&storage) {
            log::error!("Failed to save NSC storage: {}", e);
        } else {
            log::debug!("Saved NSC storage with {} channels", storage.channels.len());
        }
    }
    
    /// Save storage to disk (sync version for initialization)
    fn save_storage(&self) {
        // For initial save, channel_info is empty so we don't need async
        let storage = NscStorage {
            identity: Some(StoredIdentity {
                private_key: hex::encode(self.identity.to_bytes()),
                display_name: "Me".to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            }),
            channels: Vec::new(),
            messages: HashMap::new(),
            devices: Vec::new(),
            this_device_id: None, // Will be set on first async save
            encrypted_sessions: None,
            encrypted_trust: None,
            peer_prekey_bundles: HashMap::new(),
            irc_channel_mapping: IrcChannelMapping::default(),
        };
        
        let _ = save_nsc_storage(&storage);
    }
    
    // =========================================================================
    // P2P Transport Methods
    // =========================================================================
    
    /// Connect to a peer by address
    pub async fn connect_to_peer(&self, peer_id_hex: &str, addr: SocketAddr) -> Result<(), String> {
        // Parse peer ID
        let bytes = hex::decode(peer_id_hex)
            .map_err(|_| "Invalid peer ID")?;
        if bytes.len() != 32 {
            return Err("Invalid peer ID length".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let peer_id = PeerId(arr);
        
        // Ensure transport is initialized
        let transport_lock = self.transport.read().await;
        let transport = transport_lock.as_ref()
            .ok_or("Transport not initialized - call init_transport() first")?;
        
        // Connect
        transport.connect(peer_id, addr).await
            .map_err(|e| format!("Connection failed: {}", e))?;
        
        // Store peer address for future use
        self.peer_addresses.write().await.insert(peer_id_hex.to_string(), addr);
        
        log::info!("Connected to peer {} at {}", peer_id_hex, addr);
        
        // Notify UI
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(NscEvent::PeerConnected { 
                peer_id: peer_id_hex.to_string() 
            }).await;
        }
        
        Ok(())
    }
    
    /// Connect to a peer via relay hub (fallback for symmetric NAT)
    pub async fn connect_via_relay(&self, peer_id_hex: &str, channel_id: Option<&str>) -> Result<(), String> {
        use crate::nsc_transport::RelayState;
        
        // Ensure relay is connected
        if self.relay_client.state().await != RelayState::Connected {
            // Register our channels with relay
            let channel_ids: Vec<[u8; 32]> = {
                let info = self.channel_info.read().await;
                info.keys()
                    .filter_map(|id| {
                        let bytes = hex::decode(id).ok()?;
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            Some(arr)
                        } else {
                            None
                        }
                    })
                    .collect()
            };
            self.relay_client.register_channels(channel_ids).await;
            
            // Connect to relay hub
            self.relay_client.connect_any().await
                .map_err(|e| format!("Failed to connect to relay: {}", e))?;
        }
        
        log::info!("Connected to peer {} via relay", peer_id_hex);
        
        // Notify UI
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(NscEvent::PeerConnected { 
                peer_id: peer_id_hex.to_string() 
            }).await;
        }
        
        // If this was an invite, send Welcome with epoch secrets via relay
        if let Some(ch_id) = channel_id {
            if let Err(e) = self.send_welcome_via_relay(peer_id_hex, ch_id).await {
                log::error!("Failed to send epoch secrets via relay: {}", e);
            }
        }
        
        Ok(())
    }
    
    /// Send Welcome message with epoch secrets via relay
    pub async fn send_welcome_via_relay(&self, peer_id_hex: &str, channel_id: &str) -> Result<(), String> {
        use crate::nsc_channel::ChannelId;
        
        // Parse channel ID
        let bytes = hex::decode(channel_id).map_err(|_| "Invalid channel ID")?;
        if bytes.len() != 32 {
            return Err("Invalid channel ID length".to_string());
        }
        let mut channel_arr = [0u8; 32];
        channel_arr.copy_from_slice(&bytes);
        let channel_id_typed = ChannelId(channel_arr);
        
        // Get epoch secrets for this channel
        let epoch_secrets = self.channel_manager.get_epoch_secrets(&channel_id_typed).await
            .ok_or("No epoch secrets for this channel")?;
        
        // Serialize epoch secrets
        let secrets_json = serde_json::to_vec(&epoch_secrets)
            .map_err(|e| format!("Failed to serialize epoch secrets: {}", e))?;
        
        // Create Welcome envelope
        let seq = {
            let mut seqs = self.sequence_numbers.write().await;
            let seq = seqs.entry(channel_id.to_string()).or_insert(0);
            *seq += 1;
            *seq
        };
        
        let payload = Bytes::from(secrets_json);
        let mut envelope = NscEnvelope::new(
            MessageType::Welcome,
            self.peer_id.0,
            channel_arr,
            seq,
            payload,
        );
        envelope.sign(&self.identity);
        
        // Parse peer ID
        let peer_bytes = hex::decode(peer_id_hex).map_err(|_| "Invalid peer ID")?;
        if peer_bytes.len() != 32 {
            return Err("Invalid peer ID length".to_string());
        }
        let mut peer_arr = [0u8; 32];
        peer_arr.copy_from_slice(&peer_bytes);
        let peer_id = PeerId(peer_arr);
        
        // Send via relay
        self.relay_client.send_to_peer(&peer_id, &envelope).await
            .map_err(|e| format!("Failed to send Welcome via relay: {}", e))?;
        
        log::info!("Sent Welcome with epoch secrets via relay to peer {} for channel {}", peer_id_hex, channel_id);
        Ok(())
    }
    
    /// Check if relay is connected
    pub async fn is_relay_connected(&self) -> bool {
        self.relay_client.is_connected().await
    }
    
    /// Get relay address if connected
    pub async fn relay_address(&self) -> Option<String> {
        self.relay_client.relay_address().await
    }
    
    /// Get our peer ID as hex string
    pub fn peer_id_hex(&self) -> String {
        hex::encode(self.peer_id.0)
    }
    
    /// Get our peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    
    /// Send a message to a channel
    /// Returns the message with timestamp for UI display
    pub async fn send_message(&self, channel_id: &str, text: String) -> Result<NscMessage, String> {
        // Create the message
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let sender_short = self.fingerprint();
        let sender_short = if sender_short.len() > 8 { 
            sender_short[..8].to_string() 
        } else { 
            sender_short 
        };
        
        // Parse channel ID
        let channel_bytes = hex::decode(channel_id)
            .map_err(|_| "Invalid channel ID")?;
        if channel_bytes.len() != 32 {
            return Err("Invalid channel ID length".to_string());
        }
        let mut channel_arr = [0u8; 32];
        channel_arr.copy_from_slice(&channel_bytes);
        let channel_id_typed = ChannelId::from_bytes(channel_arr);
        
        // Get next sequence number for this channel
        let seq = {
            let mut seqs = self.sequence_numbers.write().await;
            let seq = seqs.entry(channel_id.to_string()).or_insert(0);
            *seq += 1;
            *seq
        };
        
        // Encrypt the message using channel's group key
        let encrypted_payload = self.channel_manager
            .encrypt_for_channel(&channel_id_typed, text.as_bytes())
            .await
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Create envelope with encrypted payload
        let payload = Bytes::from(encrypted_payload);
        let mut envelope = NscEnvelope::new(
            MessageType::ChannelMessage,
            self.peer_id.0,
            channel_arr,
            seq,
            payload,
        );
        envelope.sign(&self.identity);
        
        // Serialize envelope for retry queue (convert Bytes to Vec<u8>)
        let envelope_bytes = envelope.to_bytes().to_vec();
        
        // Try to send to all connected peers
        let mut target_peers: Vec<PeerId> = Vec::new();
        let transport_lock = self.transport.read().await;
        if let Some(ref transport) = *transport_lock {
            let connected_peers = transport.connected_peers().await;
            
            for peer_id in &connected_peers {
                target_peers.push(peer_id.clone());
                if let Err(e) = transport.send(peer_id, &envelope).await {
                    log::warn!("Failed to send to peer {}: {}", hex::encode(peer_id.0), e);
                } else {
                    log::debug!("Sent encrypted message to peer {}", hex::encode(peer_id.0));
                }
            }
        }
        
        // Add to retry queue if we have target peers
        if !target_peers.is_empty() {
            let pending_key = format!("{}:{}", channel_id, seq);
            let pending = PendingMessage {
                channel_id: channel_id.to_string(),
                sequence_number: seq,
                envelope_bytes,
                sent_at: timestamp,
                retry_count: 0,
                next_retry_at: timestamp + 2, // First retry in 2 seconds
                target_peers,
            };
            self.retry_queue.write().await.insert(pending_key, pending);
            log::debug!("Added message to retry queue: {}:{}", channel_id, seq);
        }
        // Note: If no peers connected, message is created but only stored locally
        // This is fine - the UI will display it, and when peers connect they can sync
        
        let message = NscMessage {
            timestamp,
            sender: sender_short.clone(),
            text: text.clone(),
            is_own: true,
        };
        
        // Persist sent message to storage
        let stored = StoredMessage {
            timestamp,
            sender: sender_short,
            text,
            is_own: true,
        };
        if let Err(e) = save_message(channel_id, &stored) {
            log::warn!("Failed to persist sent message: {}", e);
        }
        
        Ok(message)
    }
    
    /// Add a peer address for a channel (for direct connection)
    pub async fn add_peer_address(&self, peer_id: &str, addr: SocketAddr) {
        self.peer_addresses.write().await.insert(peer_id.to_string(), addr);
    }
    
    /// Send a heartbeat to all connected peers
    pub async fn send_heartbeat(&self) -> Result<(), String> {
        let transport_lock = self.transport.read().await;
        let transport = transport_lock.as_ref()
            .ok_or("Transport not initialized")?;
        
        let seq = {
            let mut seqs = self.sequence_numbers.write().await;
            let seq = seqs.entry("__heartbeat__".to_string()).or_insert(0);
            *seq += 1;
            *seq
        };
        
        let mut envelope = NscEnvelope::new(
            MessageType::Heartbeat,
            self.peer_id.0,
            [0u8; 32], // No channel for heartbeat
            seq,
            Bytes::new(),
        );
        envelope.sign(&self.identity);
        
        let peers = transport.connected_peers().await;
        for peer_id in &peers {
            if let Err(e) = transport.send(peer_id, &envelope).await {
                log::warn!("Failed to send heartbeat to {}: {}", peer_id, e);
            }
        }
        
        log::debug!("Sent heartbeat to {} peers", peers.len());
        Ok(())
    }
    
    /// Send an acknowledgment for a received message
    pub async fn send_ack(&self, peer_id_hex: &str, channel_id: &str, sequence: u64) -> Result<(), String> {
        let transport_lock = self.transport.read().await;
        let transport = transport_lock.as_ref()
            .ok_or("Transport not initialized")?;
        
        // Parse peer ID
        let peer_bytes = hex::decode(peer_id_hex).map_err(|_| "Invalid peer ID")?;
        if peer_bytes.len() != 32 {
            return Err("Invalid peer ID length".to_string());
        }
        let mut peer_arr = [0u8; 32];
        peer_arr.copy_from_slice(&peer_bytes);
        let peer_id = PeerId(peer_arr);
        
        // Parse channel ID
        let channel_bytes = hex::decode(channel_id).map_err(|_| "Invalid channel ID")?;
        if channel_bytes.len() != 32 {
            return Err("Invalid channel ID length".to_string());
        }
        let mut channel_arr = [0u8; 32];
        channel_arr.copy_from_slice(&channel_bytes);
        
        let mut envelope = NscEnvelope::new(
            MessageType::Ack,
            self.peer_id.0,
            channel_arr,
            sequence,
            Bytes::new(),
        );
        envelope.sign(&self.identity);
        
        transport.send(&peer_id, &envelope).await
            .map_err(|e| format!("Failed to send ACK: {}", e))?;
        
        log::debug!("Sent ACK to {} for channel {} seq {}", peer_id_hex, channel_id, sequence);
        Ok(())
    }
    
    /// Start a background heartbeat loop
    pub fn start_heartbeat_loop(&self, interval_secs: u64) -> tokio::task::JoinHandle<()> {
        let transport = self.transport.clone();
        let identity = self.identity.clone();
        let peer_id = self.peer_id;
        let sequence_numbers = self.sequence_numbers.clone();
        
        tokio::spawn(async move {
            let interval = tokio::time::Duration::from_secs(interval_secs);
            let mut ticker = tokio::time::interval(interval);
            
            loop {
                ticker.tick().await;
                
                let transport_lock = transport.read().await;
                if let Some(ref transport) = *transport_lock {
                    let seq = {
                        let mut seqs = sequence_numbers.write().await;
                        let seq = seqs.entry("__heartbeat__".to_string()).or_insert(0);
                        *seq += 1;
                        *seq
                    };
                    
                    let mut envelope = NscEnvelope::new(
                        MessageType::Heartbeat,
                        peer_id.0,
                        [0u8; 32],
                        seq,
                        Bytes::new(),
                    );
                    envelope.sign(&identity);
                    
                    let peers = transport.connected_peers().await;
                    for peer in &peers {
                        let _ = transport.send(peer, &envelope).await;
                    }
                    
                    if !peers.is_empty() {
                        log::debug!("Heartbeat sent to {} peers", peers.len());
                    }
                }
                drop(transport_lock);
            }
        })
    }
    
    /// Send Welcome message with epoch secrets to a new channel member
    pub async fn send_welcome_epoch_secrets(&self, peer_id_hex: &str, channel_id: &str) -> Result<(), String> {
        use crate::nsc_channel::ChannelId;
        
        // Parse channel ID
        let bytes = hex::decode(channel_id).map_err(|_| "Invalid channel ID")?;
        if bytes.len() != 32 {
            return Err("Invalid channel ID length".to_string());
        }
        let mut channel_arr = [0u8; 32];
        channel_arr.copy_from_slice(&bytes);
        let channel_id_typed = ChannelId(channel_arr);
        
        // Get epoch secrets for this channel
        let epoch_secrets = self.channel_manager.get_epoch_secrets(&channel_id_typed).await
            .ok_or("No epoch secrets for this channel")?;
        
        // Serialize epoch secrets
        let secrets_json = serde_json::to_vec(&epoch_secrets)
            .map_err(|e| format!("Failed to serialize epoch secrets: {}", e))?;
        
        // Create Welcome envelope
        let seq = {
            let mut seqs = self.sequence_numbers.write().await;
            let seq = seqs.entry(channel_id.to_string()).or_insert(0);
            *seq += 1;
            *seq
        };
        
        let payload = Bytes::from(secrets_json);
        let mut envelope = NscEnvelope::new(
            MessageType::Welcome,
            self.peer_id.0,
            channel_arr,
            seq,
            payload,
        );
        envelope.sign(&self.identity);
        
        // Parse peer ID
        let peer_bytes = hex::decode(peer_id_hex).map_err(|_| "Invalid peer ID")?;
        if peer_bytes.len() != 32 {
            return Err("Invalid peer ID length".to_string());
        }
        let mut peer_arr = [0u8; 32];
        peer_arr.copy_from_slice(&peer_bytes);
        let peer_id = PeerId(peer_arr);
        
        // Send to peer
        let transport_lock = self.transport.read().await;
        let transport = transport_lock.as_ref()
            .ok_or("Transport not initialized")?;
        
        transport.send(&peer_id, &envelope).await
            .map_err(|e| format!("Failed to send Welcome: {}", e))?;
        
        log::info!("Sent Welcome with epoch secrets to peer {} for channel {}", peer_id_hex, channel_id);
        Ok(())
    }
    
    /// Advance epoch for a channel and broadcast Commit to all members
    pub async fn advance_channel_epoch(&self, channel_id: &str) -> Result<u64, String> {
        use crate::nsc_channel::ChannelId;
        
        // Parse channel ID
        let bytes = hex::decode(channel_id).map_err(|_| "Invalid channel ID")?;
        if bytes.len() != 32 {
            return Err("Invalid channel ID length".to_string());
        }
        let mut channel_arr = [0u8; 32];
        channel_arr.copy_from_slice(&bytes);
        let channel_id_typed = ChannelId(channel_arr);
        
        // Advance epoch
        let new_secrets = self.channel_manager.advance_epoch(&channel_id_typed).await
            .map_err(|e| format!("Failed to advance epoch: {:?}", e))?;
        
        let new_epoch = new_secrets.epoch;
        
        // Broadcast Commit to all connected peers
        self.broadcast_commit(channel_id, &new_secrets).await?;
        
        // Save updated state
        self.save_storage_async().await;
        
        Ok(new_epoch)
    }
    
    /// Broadcast Commit (new epoch secrets) to all channel members
    async fn broadcast_commit(&self, channel_id: &str, new_secrets: &crate::nsc_channel::EpochSecrets) -> Result<(), String> {
        let bytes = hex::decode(channel_id).map_err(|_| "Invalid channel ID")?;
        if bytes.len() != 32 {
            return Err("Invalid channel ID length".to_string());
        }
        let mut channel_arr = [0u8; 32];
        channel_arr.copy_from_slice(&bytes);
        
        // Serialize epoch secrets
        let secrets_json = serde_json::to_vec(new_secrets)
            .map_err(|e| format!("Failed to serialize epoch secrets: {}", e))?;
        
        // Create Commit envelope
        let seq = {
            let mut seqs = self.sequence_numbers.write().await;
            let seq = seqs.entry(channel_id.to_string()).or_insert(0);
            *seq += 1;
            *seq
        };
        
        let payload = Bytes::from(secrets_json);
        let mut envelope = NscEnvelope::new(
            MessageType::Commit,
            self.peer_id.0,
            channel_arr,
            seq,
            payload,
        );
        envelope.sign(&self.identity);
        
        // Send to all connected peers
        let transport_lock = self.transport.read().await;
        if let Some(ref transport) = *transport_lock {
            let peers = transport.connected_peers().await;
            for peer_id in &peers {
                if let Err(e) = transport.send(peer_id, &envelope).await {
                    log::warn!("Failed to send Commit to {}: {}", hex::encode(peer_id.0), e);
                }
            }
            log::info!("Broadcast Commit for epoch {} to {} peers", new_secrets.epoch, peers.len());
        }
        
        Ok(())
    }
    
    /// Start background task to check for needed key rotations
    pub async fn start_key_rotation_check(&self) {
        let manager = get_nsc_manager();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                let mgr = manager.read().await;
                let channels_needing_rotation = mgr.channel_manager.check_rotation_needed().await;
                
                for channel_id in channels_needing_rotation {
                    let channel_hex = channel_id.to_hex();
                    log::info!("Channel {} needs key rotation", channel_hex);
                    
                    if let Err(e) = mgr.advance_channel_epoch(&channel_hex).await {
                        log::error!("Failed to advance epoch for {}: {}", channel_hex, e);
                    }
                }
            }
        });
    }
    
    /// Start background task to retry unacknowledged messages
    pub async fn start_retry_loop(&self) {
        let manager = get_nsc_manager();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
            
            loop {
                interval.tick().await;
                
                let mgr = manager.read().await;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                // Get messages that need retry
                let mut to_retry: Vec<String> = Vec::new();
                let mut to_remove: Vec<String> = Vec::new();
                
                {
                    let queue = mgr.retry_queue.read().await;
                    for (key, pending) in queue.iter() {
                        if pending.is_expired() {
                            to_remove.push(key.clone());
                            log::warn!("Message {} expired after {} retries", key, pending.retry_count);
                        } else if now >= pending.next_retry_at {
                            to_retry.push(key.clone());
                        }
                    }
                }
                
                // Remove expired messages
                if !to_remove.is_empty() {
                    let mut queue = mgr.retry_queue.write().await;
                    for key in to_remove {
                        queue.remove(&key);
                    }
                }
                
                // Retry pending messages
                for key in to_retry {
                    let mut queue = mgr.retry_queue.write().await;
                    if let Some(pending) = queue.get_mut(&key) {
                        // Try to resend
                        let transport_lock = mgr.transport.read().await;
                        if let Some(ref transport) = *transport_lock {
                            // Parse envelope from bytes
                            let envelope_bytes = Bytes::from(pending.envelope_bytes.clone());
                            if let Ok(envelope) = NscEnvelope::from_bytes(envelope_bytes) {
                                let mut sent_count = 0;
                                for peer_id in &pending.target_peers {
                                    if let Err(e) = transport.send(peer_id, &envelope).await {
                                        log::debug!("Retry failed for peer {}: {}", hex::encode(peer_id.0), e);
                                    } else {
                                        sent_count += 1;
                                    }
                                }
                                
                                if sent_count > 0 {
                                    log::debug!("Retried message {} (attempt {}), sent to {} peers", 
                                        key, pending.retry_count + 1, sent_count);
                                }
                            }
                            
                            // Update retry timing
                            pending.calculate_next_retry();
                        }
                    }
                }
            }
        });
    }
    
    /// Process retry queue once (for manual triggering or testing)
    pub async fn process_retry_queue(&self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut retried_count = 0;
        let mut to_remove: Vec<String> = Vec::new();
        
        // Get messages that need processing
        {
            let queue = self.retry_queue.read().await;
            for (key, pending) in queue.iter() {
                if pending.is_expired() {
                    to_remove.push(key.clone());
                }
            }
        }
        
        // Remove expired
        {
            let mut queue = self.retry_queue.write().await;
            for key in &to_remove {
                queue.remove(key);
            }
        }
        
        // Get pending messages to retry
        let pending_keys: Vec<String> = {
            let queue = self.retry_queue.read().await;
            queue.iter()
                .filter(|(_, p)| now >= p.next_retry_at)
                .map(|(k, _)| k.clone())
                .collect()
        };
        
        for key in pending_keys {
            let mut queue = self.retry_queue.write().await;
            if let Some(pending) = queue.get_mut(&key) {
                let transport_lock = self.transport.read().await;
                if let Some(ref transport) = *transport_lock {
                    let envelope_bytes = Bytes::from(pending.envelope_bytes.clone());
                    if let Ok(envelope) = NscEnvelope::from_bytes(envelope_bytes) {
                        for peer_id in &pending.target_peers {
                            let _ = transport.send(peer_id, &envelope).await;
                        }
                        pending.calculate_next_retry();
                        retried_count += 1;
                    }
                }
            }
        }
        
        retried_count
    }
    
    /// Get pending message count in retry queue
    pub async fn pending_message_count(&self) -> usize {
        self.retry_queue.read().await.len()
    }
    
    /// Get known peer addresses
    pub async fn get_peer_addresses(&self) -> HashMap<String, SocketAddr> {
        self.peer_addresses.read().await.clone()
    }
    
    /// Check if transport is running
    pub async fn is_transport_running(&self) -> bool {
        self.transport.read().await.is_some()
    }
    
    /// Get connected peer count
    pub async fn connected_peer_count(&self) -> usize {
        let transport_lock = self.transport.read().await;
        if let Some(ref transport) = *transport_lock {
            transport.connected_peers().await.len()
        } else {
            0
        }
    }
    
    /// Start listening for incoming messages
    /// Returns a receiver that yields received messages with their channel IDs
    pub async fn start_listener(&self) -> Result<mpsc::Receiver<(String, NscMessage)>, String> {
        // Ensure transport is initialized
        if !self.is_transport_running().await {
            self.init_transport().await?;
        }
        
        let (tx, rx) = mpsc::channel(100);
        
        // Get transport reference
        let transport = {
            let transport_lock = self.transport.read().await;
            transport_lock.as_ref().cloned()
        };
        
        let Some(transport) = transport else {
            return Err("Transport not available".to_string());
        };
        
        let our_peer_id = self.peer_id_hex();
        let fingerprint = self.fingerprint();
        let fingerprint_short = if fingerprint.len() > 8 { 
            fingerprint[..8].to_string() 
        } else { 
            fingerprint 
        };
        
        // Spawn background task to accept connections and read messages
        tokio::spawn(async move {
            log::info!("NSC listener started, waiting for connections...");
            
            loop {
                // Accept incoming connection
                match transport.accept().await {
                    Ok((connection, addr)) => {
                        log::info!("Accepted connection from {}", addr);
                        
                        let tx_clone = tx.clone();
                        let our_peer_id = our_peer_id.clone();
                        
                        // Spawn task to handle this connection
                        tokio::spawn(async move {
                            // Read messages from this connection
                            loop {
                                match connection.accept_uni().await {
                                    Ok(mut recv_stream) => {
                                        match crate::nsc_transport::QuicTransport::receive_from_stream(&mut recv_stream).await {
                                            Ok(envelope) => {
                                                let sender_hex = hex::encode(&envelope.sender_id);
                                                let channel_hex = hex::encode(&envelope.channel_id);
                                                
                                                // Decrypt message using channel's group key
                                                let channel_id = ChannelId::from_bytes(envelope.channel_id);
                                                
                                                let text = {
                                                    let manager = get_nsc_manager();
                                                    let mgr = manager.read().await;
                                                    match mgr.channel_manager.decrypt_for_channel(&channel_id, &envelope.payload).await {
                                                        Ok(plaintext) => String::from_utf8_lossy(&plaintext).to_string(),
                                                        Err(e) => {
                                                            log::warn!("Decryption failed for channel {}: {}", channel_hex, e);
                                                            // Fall back to raw data (for backwards compat)
                                                            String::from_utf8_lossy(&envelope.payload).to_string()
                                                        }
                                                    }
                                                };
                                                
                                                let timestamp = envelope.timestamp / 1000; // Convert ms to seconds
                                                let sender_short = if sender_hex.len() >= 16 {
                                                    sender_hex[..16].to_string()
                                                } else {
                                                    sender_hex.clone()
                                                };
                                                
                                                let is_own = sender_hex == our_peer_id;
                                                
                                                let msg = NscMessage {
                                                    timestamp,
                                                    sender: sender_short.clone(),
                                                    text: text.clone(),
                                                    is_own,
                                                };
                                                
                                                // Persist message to storage
                                                let stored = StoredMessage {
                                                    timestamp,
                                                    sender: sender_short,
                                                    text,
                                                    is_own,
                                                };
                                                if let Err(e) = save_message(&channel_hex, &stored) {
                                                    log::warn!("Failed to persist message: {}", e);
                                                }
                                                
                                                if tx_clone.send((channel_hex, msg)).await.is_err() {
                                                    log::warn!("Message receiver dropped");
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                log::warn!("Failed to receive message: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::debug!("Connection stream ended: {}", e);
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        log::warn!("Accept failed: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
        
        Ok(rx)
    }
    
    // =========================================================================
    // IRC Discovery/Signaling Integration
    // =========================================================================
    
    /// Handle an incoming NSC CTCP command from IRC
    /// Returns an optional CTCP response to send back
    pub async fn handle_nsc_ctcp(&self, from_nick: &str, irc_channel: &str, command: &str, args: &str) -> Option<String> {
        use crate::nsc_irc::{NscCtcpCommand, ProbeMessage, encode_ctcp, InviteMessage};
        
        log::info!("[NSC_MANAGER] handle_nsc_ctcp: cmd={}, from={}, args_len={}", command, from_nick, args.len());
        
        let cmd = NscCtcpCommand::from_str(command)?;
        log::info!("[NSC_MANAGER] Parsed command: {:?}", cmd);
        
        match cmd {
            NscCtcpCommand::Probe => {
                // Respond with our capabilities
                let response = ProbeMessage::new(&self.peer_id, None);
                match encode_ctcp(NscCtcpCommand::ProbeResponse, &response) {
                    Ok(ctcp) => Some(ctcp),
                    Err(e) => {
                        log::warn!("Failed to encode probe response: {}", e);
                        None
                    }
                }
            }
            NscCtcpCommand::ProbeResponse => {
                // Parse probe response and track the peer
                if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args) {
                    if let Ok(probe) = serde_json::from_slice::<ProbeMessage>(&decoded) {
                        let peer_id_hex = probe.peer_id.clone();
                        let peer = NscPeer {
                            nick: from_nick.to_string(),
                            fingerprint: probe.peer_id.clone(),
                            peer_id: probe.peer_id,
                            nat_type: probe.nat_type,
                            last_seen: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        };
                        
                        // Add to known peers
                        self.known_peers.write().await.insert(from_nick.to_string(), peer);
                        
                        // Add to IRC channel list
                        let mut by_channel = self.peers_by_irc_channel.write().await;
                        let peers = by_channel.entry(irc_channel.to_string()).or_insert_with(Vec::new);
                        if !peers.contains(&from_nick.to_string()) {
                            peers.push(from_nick.to_string());
                        }
                        drop(by_channel);
                        
                        log::info!("Discovered NSC peer: {} (peer_id: {}...) in IRC channel {}", 
                            from_nick, &peer_id_hex[..8.min(peer_id_hex.len())], irc_channel);
                        
                        // Check if this IRC channel maps to an NSC secure channel
                        // If so, add this peer to the channel members list
                        let mapping = self.irc_channel_mapping.read().await;
                        if let Some(nais_channel_id) = mapping.get_nais_channel(irc_channel) {
                            let channel_id = nais_channel_id.clone();
                            drop(mapping);
                            
                            log::info!("IRC channel {} maps to NSC channel {}, adding peer {} as member", 
                                irc_channel, channel_id, from_nick);
                            
                            // Add peer to NSC channel members (not owner since they're joining)
                            self.add_channel_member(&channel_id, &peer_id_hex, false).await;
                            
                            // Send MemberJoined event to UI
                            if let Some(ref tx) = self.event_tx {
                                let _ = tx.send(NscEvent::MemberJoined {
                                    channel_id: channel_id.clone(),
                                    peer_id: peer_id_hex.clone(),
                                }).await;
                            }
                        }
                    }
                }
                None
            }
            NscCtcpCommand::Invite => {
                log::info!("[NSC_MANAGER] Processing INVITE from {}, args: {}", from_nick, &args[..args.len().min(50)]);
                // Parse invite
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args) {
                    Ok(decoded) => {
                        log::info!("[NSC_MANAGER] Base64 decoded {} bytes", decoded.len());
                        match serde_json::from_slice::<InviteMessage>(&decoded) {
                            Ok(invite) => {
                                log::info!("[NSC_MANAGER] Parsed invite: channel={}, from={}", invite.channel_name, from_nick);
                                let pending = PendingInvite {
                                    invite_id: invite.invite_id.clone(),
                                    from_nick: from_nick.to_string(),
                                    from_fingerprint: invite.inviter.clone(),
                                    channel_name: invite.channel_name.clone(),
                                    channel_id: invite.channel_id.clone(),
                                    member_count: invite.member_count,
                                    received_at: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                    expires_at: invite.expires_at,
                                };
                                
                                // Add to pending invites
                                self.pending_invites.write().await.insert(invite.invite_id.clone(), pending);
                                log::info!("[NSC_MANAGER] Added to pending_invites, id={}", invite.invite_id);
                                
                                log::info!("Received invite to '{}' from {}", invite.channel_name, from_nick);
                                
                                // Notify UI of new invite
                                if let Some(ref tx) = self.event_tx {
                                    log::info!("[NSC_MANAGER] Sending InviteReceived event to UI");
                                    let _ = tx.send(NscEvent::InviteReceived {
                                        from_nick: from_nick.to_string(),
                                        channel_name: invite.channel_name,
                                        invite_id: invite.invite_id,
                                    }).await;
                                } else {
                                    log::warn!("[NSC_MANAGER] No event_tx to send InviteReceived!");
                                }
                            }
                            Err(e) => {
                                log::error!("[NSC_MANAGER] Failed to parse invite JSON: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("[NSC_MANAGER] Failed to base64 decode args: {}", e);
                    }
                }
                None
            }
            NscCtcpCommand::InviteAccept => {
                // Someone accepted our invite - start ICE exchange
                log::info!("Invite accepted by {}", from_nick);
                
                // Decode invite_id from args and look up which channel this was for
                let channel_id: Option<String> = if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args) {
                    let invite_id = String::from_utf8_lossy(&decoded).to_string();
                    if let Some(sent) = self.sent_invites.read().await.get(&invite_id) {
                        log::info!("Found sent invite {} for channel {}", invite_id, sent.channel_id);
                        Some(sent.channel_id.clone())
                    } else {
                        log::warn!("No record of sent invite {}", invite_id);
                        None
                    }
                } else {
                    log::warn!("Failed to decode invite_id from INVITE_ACCEPT");
                    None
                };
                
                // Create ICE offer with channel context
                match self.create_ice_offer(from_nick, channel_id.as_deref()).await {
                    Ok(offer_ctcp) => {
                        log::info!("Created ICE offer for {}", from_nick);
                        Some(offer_ctcp)
                    }
                    Err(e) => {
                        log::error!("Failed to create ICE offer: {}", e);
                        None
                    }
                }
            }
            NscCtcpCommand::InviteDecline => {
                log::info!("Invite declined by {}", from_nick);
                None
            }
            NscCtcpCommand::IceOffer => {
                // Received ICE offer - respond with ICE answer
                log::info!("Received ICE offer from {}", from_nick);
                
                if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args) {
                    if let Ok(offer) = serde_json::from_slice::<IceMessage>(&decoded) {
                        match self.create_ice_answer(from_nick, &offer).await {
                            Ok(answer_ctcp) => {
                                log::info!("Created ICE answer for {}", from_nick);
                                return Some(answer_ctcp);
                            }
                            Err(e) => {
                                log::error!("Failed to create ICE answer: {}", e);
                            }
                        }
                    }
                }
                None
            }
            NscCtcpCommand::IceAnswer => {
                // Received ICE answer - complete ICE exchange
                log::info!("Received ICE answer from {}", from_nick);
                
                if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args) {
                    if let Ok(answer) = serde_json::from_slice::<IceMessage>(&decoded) {
                        if let Err(e) = self.complete_ice_exchange(from_nick, &answer).await {
                            log::error!("Failed to complete ICE exchange: {}", e);
                        }
                    }
                }
                None
            }
            NscCtcpCommand::IceCandidate => {
                // Received trickle ICE candidate - add to pending candidates
                log::debug!("Received ICE candidate from {}", from_nick);
                // ICE candidates are already handled during ICE exchange
                // via IceOffer/IceAnswer, but trickle ICE would go here
                None
            }
            NscCtcpCommand::KeyPackage => {
                // Received a PreKeyBundle from a peer
                log::info!("Received KeyPackage from {}", from_nick);
                
                if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args) {
                    match PeerSessionManager::deserialize_prekey_bundle(&decoded) {
                        Ok(bundle) => {
                            // Store the peer's PreKeyBundle
                            let fingerprint_hex = bundle.identity_key.fingerprint_hex();
                            self.peer_prekey_bundles.write().await.insert(fingerprint_hex.clone(), bundle);
                            
                            // Update known peer info if we have it
                            if let Some(peer) = self.known_peers.write().await.get_mut(from_nick) {
                                peer.fingerprint = fingerprint_hex;
                            }
                            
                            log::info!("Stored PreKeyBundle from {} (fingerprint: {})", from_nick, 
                                hex::encode(&decoded[..8.min(decoded.len())]));
                        }
                        Err(e) => {
                            log::error!("Failed to parse KeyPackage from {}: {:?}", from_nick, e);
                        }
                    }
                }
                None
            }
            NscCtcpCommand::Presence => {
                // Update peer last-seen timestamp
                if let Some(peer) = self.known_peers.write().await.get_mut(from_nick) {
                    peer.last_seen = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                }
                None
            }
            NscCtcpCommand::Identity => {
                // Peer is announcing/updating their identity
                log::info!("Received Identity from {}", from_nick);
                // Identity is typically sent along with KeyPackage, nothing extra to do here
                None
            }
            NscCtcpCommand::MetadataSync => {
                // Peer is requesting channel metadata
                use crate::nsc_irc::{MetadataSyncRequest, MetadataResponse};
                
                log::info!("Received MetadataSync request from {}", from_nick);
                
                if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args) {
                    if let Ok(request) = serde_json::from_slice::<MetadataSyncRequest>(&decoded) {
                        // Look up the channel
                        if let Ok(channel_bytes) = hex::decode(&request.channel_id) {
                            if channel_bytes.len() == 32 {
                                let mut channel_arr = [0u8; 32];
                                channel_arr.copy_from_slice(&channel_bytes);
                                let channel_id = ChannelId(channel_arr);
                                
                                // Get channel info and build response
                                if let Some(info) = self.channel_info.read().await.get(&request.channel_id) {
                                    // Only respond if we have a newer version
                                    if info.created_at > 0 {
                                        let response = MetadataResponse {
                                            channel_id: request.channel_id.clone(),
                                            name: info.name.clone(),
                                            topic: info.topic.clone(),
                                            version: 1, // TODO: Track actual version
                                            creator: self.peer_id_hex(),
                                            admins: vec![self.peer_id_hex()],
                                            member_count: info.member_count,
                                            discoverable: false,
                                            invite_only: true,
                                            previous_hash: None,
                                            signature: String::new(),
                                            timestamp: SystemTime::now()
                                                .duration_since(UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_millis() as u64,
                                        };
                                        
                                        match encode_ctcp(NscCtcpCommand::Metadata, &response) {
                                            Ok(ctcp) => return Some(ctcp),
                                            Err(e) => log::error!("Failed to encode metadata response: {}", e),
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                None
            }
            NscCtcpCommand::Metadata => {
                // Received channel metadata from a peer
                use crate::nsc_irc::MetadataResponse;
                
                log::info!("Received Metadata from {}", from_nick);
                
                if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args) {
                    if let Ok(metadata) = serde_json::from_slice::<MetadataResponse>(&decoded) {
                        // Update our channel info if this is newer
                        let mut channel_info = self.channel_info.write().await;
                        
                        if let Some(info) = channel_info.get_mut(&metadata.channel_id) {
                            // Update if newer version
                            info.name = metadata.name;
                            info.topic = metadata.topic;
                            info.member_count = metadata.member_count;
                            log::info!("Updated channel {} metadata from {}", metadata.channel_id, from_nick);
                        } else {
                            // New channel we didn't know about - generate IRC channel
                            let irc_channel = IrcChannelMapping::generate_irc_channel(&metadata.channel_id);
                            channel_info.insert(metadata.channel_id.clone(), ChannelInfo {
                                channel_id: metadata.channel_id,
                                name: metadata.name,
                                topic: metadata.topic,
                                member_count: metadata.member_count,
                                is_owner: false,
                                created_at: metadata.timestamp / 1000,
                                irc_channel,
                            });
                        }
                    }
                }
                None
            }
            NscCtcpCommand::Ack => {
                // Message delivery acknowledgment
                use crate::nsc_irc::AckMessage;
                
                if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, args) {
                    if let Ok(ack) = serde_json::from_slice::<AckMessage>(&decoded) {
                        log::debug!("Received ACK for message {} seq {} from {}", 
                            ack.message_id, ack.sequence, from_nick);
                        // Could be used to track delivery status, update UI, etc.
                    }
                }
                None
            }
        }
    }
    
    /// Create a probe CTCP message to discover NSC peers
    pub fn create_probe_ctcp(&self) -> String {
        use crate::nsc_irc::{NscCtcpCommand, ProbeMessage, encode_ctcp};
        
        let probe = ProbeMessage::new(&self.peer_id, None);
        match encode_ctcp(NscCtcpCommand::Probe, &probe) {
            Ok(ctcp) => ctcp,
            Err(_) => String::new(),
        }
    }
    
    /// Create a KeyPackage CTCP message to share our PreKeyBundle
    pub async fn create_keypackage_ctcp(&self) -> Result<String, String> {
        let sessions = self.peer_sessions.read().await;
        let bundle_bytes = sessions.serialize_prekey_bundle()
            .map_err(|e| format!("Failed to serialize PreKeyBundle: {:?}", e))?;
        
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bundle_bytes);
        Ok(format!("\x01NSC_KEYPACKAGE {}\x01", encoded))
    }
    
    /// Initiate a Double Ratchet session with a peer
    /// Returns the X3DH header to include with first message
    pub async fn initiate_peer_session(&self, peer_fingerprint_hex: &str) -> Result<Vec<u8>, String> {
        // Get peer's PreKeyBundle
        let bundle = self.peer_prekey_bundles.read().await
            .get(peer_fingerprint_hex)
            .cloned()
            .ok_or("No PreKeyBundle for peer - request KeyPackage first")?;
        
        // Parse fingerprint to bytes
        let fingerprint_bytes = hex::decode(peer_fingerprint_hex)
            .map_err(|_| "Invalid fingerprint hex")?;
        if fingerprint_bytes.len() != 32 {
            return Err("Invalid fingerprint length".to_string());
        }
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&fingerprint_bytes);
        
        // Initiate session
        let mut sessions = self.peer_sessions.write().await;
        let header = sessions.initiate_session(fingerprint, &bundle)
            .map_err(|e| format!("Failed to initiate session: {:?}", e))?;
        
        // Serialize header for transmission
        let mut header_bytes = Vec::with_capacity(160);
        header_bytes.extend_from_slice(&header.identity_key.to_bytes());
        header_bytes.extend_from_slice(header.identity_dh_key.as_bytes());
        header_bytes.extend_from_slice(header.ephemeral_key.as_bytes());
        if let Some(ref opk) = header.one_time_prekey {
            header_bytes.push(1);
            header_bytes.extend_from_slice(opk.as_bytes());
        } else {
            header_bytes.push(0);
        }
        
        log::info!("Initiated Double Ratchet session with peer {}", peer_fingerprint_hex);
        Ok(header_bytes)
    }
    
    /// Receive and process an X3DH header to establish session
    pub async fn receive_peer_session(&self, peer_fingerprint_hex: &str, header_bytes: &[u8]) -> Result<(), String> {
        use crate::nsc_crypto::IdentityPublicKey;
        use x25519_dalek::PublicKey as X25519PublicKey;
        
        // Parse header
        if header_bytes.len() < 97 { // 32 + 32 + 32 + 1
            return Err("X3DH header too short".to_string());
        }
        
        let identity_key = IdentityPublicKey::from_bytes(&header_bytes[0..32])
            .map_err(|e| format!("Invalid identity key: {:?}", e))?;
        
        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(&header_bytes[32..64]);
        let identity_dh_key = X25519PublicKey::from(dh_bytes);
        
        let mut eph_bytes = [0u8; 32];
        eph_bytes.copy_from_slice(&header_bytes[64..96]);
        let ephemeral_key = X25519PublicKey::from(eph_bytes);
        
        let one_time_prekey = if header_bytes[96] == 1 && header_bytes.len() >= 129 {
            let mut opk_bytes = [0u8; 32];
            opk_bytes.copy_from_slice(&header_bytes[97..129]);
            Some(X25519PublicKey::from(opk_bytes))
        } else {
            None
        };
        
        let header = X3dhHeader {
            identity_key,
            identity_dh_key,
            ephemeral_key,
            one_time_prekey,
        };
        
        // Parse fingerprint
        let fingerprint_bytes = hex::decode(peer_fingerprint_hex)
            .map_err(|_| "Invalid fingerprint hex")?;
        if fingerprint_bytes.len() != 32 {
            return Err("Invalid fingerprint length".to_string());
        }
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&fingerprint_bytes);
        
        // Receive session
        let mut sessions = self.peer_sessions.write().await;
        sessions.receive_session(fingerprint, &header)
            .map_err(|e| format!("Failed to receive session: {:?}", e))?;
        
        log::info!("Established Double Ratchet session with peer {}", peer_fingerprint_hex);
        Ok(())
    }
    
    /// Encrypt a message for a specific peer using Double Ratchet
    pub async fn encrypt_for_peer(&self, peer_fingerprint_hex: &str, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let fingerprint_bytes = hex::decode(peer_fingerprint_hex)
            .map_err(|_| "Invalid fingerprint hex")?;
        if fingerprint_bytes.len() != 32 {
            return Err("Invalid fingerprint length".to_string());
        }
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&fingerprint_bytes);
        
        let mut sessions = self.peer_sessions.write().await;
        let (header, ciphertext) = sessions.encrypt_for_peer(&fingerprint, plaintext)
            .map_err(|e| format!("Encryption failed: {:?}", e))?;
        
        // Serialize header
        let header_bytes = header.to_bytes();
        
        Ok((header_bytes, ciphertext))
    }
    
    /// Decrypt a message from a specific peer using Double Ratchet
    pub async fn decrypt_from_peer(&self, peer_fingerprint_hex: &str, header_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let fingerprint_bytes = hex::decode(peer_fingerprint_hex)
            .map_err(|_| "Invalid fingerprint hex")?;
        if fingerprint_bytes.len() != 32 {
            return Err("Invalid fingerprint length".to_string());
        }
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&fingerprint_bytes);
        
        let header = MessageHeader::from_bytes(header_bytes)
            .map_err(|e| format!("Invalid message header: {:?}", e))?;
        
        let mut sessions = self.peer_sessions.write().await;
        sessions.decrypt_from_peer(&fingerprint, &header, ciphertext)
            .map_err(|e| format!("Decryption failed: {:?}", e))
    }
    
    /// Check if we have an active session with a peer
    pub async fn has_peer_session(&self, peer_fingerprint_hex: &str) -> bool {
        let fingerprint_bytes = match hex::decode(peer_fingerprint_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if fingerprint_bytes.len() != 32 {
            return false;
        }
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&fingerprint_bytes);
        
        self.peer_sessions.read().await.has_session(&fingerprint)
    }
    
    /// Get the number of active peer sessions
    pub async fn peer_session_count(&self) -> usize {
        self.peer_sessions.read().await.session_count()
    }
    
    /// Get the number of available one-time prekeys
    pub async fn available_prekeys(&self) -> usize {
        self.peer_sessions.read().await.available_prekeys()
    }
    
    /// Replenish one-time prekeys if running low
    pub async fn replenish_prekeys(&self, count: usize) {
        self.peer_sessions.write().await.replenish_prekeys(count);
    }
    
    // =========================================================================
    // Trust Verification Methods
    // =========================================================================
    
    /// Check and record trust for a peer's identity key
    pub async fn check_peer_trust(&self, identity_key_bytes: &[u8]) -> Result<TrustCheckResult, String> {
        use crate::nsc_crypto::IdentityPublicKey;
        
        let identity_key = IdentityPublicKey::from_bytes(identity_key_bytes)
            .map_err(|e| format!("Invalid identity key: {:?}", e))?;
        
        let result = self.trust_manager.write().await.check_key(&identity_key);
        
        match &result {
            TrustCheckResult::NewPeer => {
                log::info!("New peer recorded with TOFU: {}", identity_key.fingerprint_hex());
            }
            TrustCheckResult::Trusted => {
                log::debug!("Trusted peer connected: {}", identity_key.fingerprint_hex());
            }
            TrustCheckResult::KeyChanged { .. } => {
                log::warn!("⚠️ Peer key changed: {} - possible security issue!", identity_key.fingerprint_hex());
            }
            TrustCheckResult::Compromised(reason) => {
                log::error!("⛔ Compromised peer attempted connection: {} - {}", identity_key.fingerprint_hex(), reason);
            }
            _ => {}
        }
        
        Ok(result)
    }
    
    /// Verify a peer's identity (mark as verified)
    pub async fn verify_peer(&self, fingerprint: &str, method: TrustVerificationMethod) -> Result<(), String> {
        self.trust_manager.write().await.verify_peer(fingerprint, method)
    }
    
    /// Mark a peer as compromised
    pub async fn mark_peer_compromised(&self, fingerprint: &str, reason: &str) {
        self.trust_manager.write().await.mark_compromised(fingerprint, reason);
        log::warn!("Marked peer {} as compromised: {}", fingerprint, reason);
    }
    
    /// Accept a key change after user confirmation
    pub async fn accept_key_change(&self, fingerprint: &str) -> Result<(), String> {
        self.trust_manager.write().await.accept_key_change(fingerprint)
    }
    
    /// Get trust description for UI display
    pub async fn get_trust_description(&self, fingerprint: &str) -> String {
        self.trust_manager.read().await.get_trust_description(fingerprint)
    }
    
    /// Generate safety numbers for out-of-band verification
    pub async fn generate_safety_numbers(&self, their_fingerprint: &str) -> Result<String, String> {
        let their_bytes = hex::decode(their_fingerprint)
            .map_err(|_| "Invalid fingerprint hex")?;
        if their_bytes.len() != 32 {
            return Err("Invalid fingerprint length".to_string());
        }
        let mut their_fp = [0u8; 32];
        their_fp.copy_from_slice(&their_bytes);
        
        let our_fp = self.identity.fingerprint();
        
        Ok(TrustManager::generate_safety_number(&our_fp, &their_fp))
    }
    
    /// Create an invite CTCP message for a user
    pub async fn create_invite_ctcp(&self, target_nick: &str, channel_id: &str) -> Result<String, String> {
        use crate::nsc_irc::{encode_ctcp, NscCtcpCommand, InviteMessage};
        use crate::nsc_channel::ChannelId;
        
        // Get channel info
        let channel_info = self.channel_info.read().await;
        let info = channel_info.get(channel_id)
            .ok_or("Channel not found")?;
        
        // Parse channel ID
        let bytes = hex::decode(channel_id).map_err(|_| "Invalid channel ID")?;
        if bytes.len() != 32 {
            return Err("Invalid channel ID length".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let cid = ChannelId(arr);
        
        // Get target peer ID (use empty for now, will be filled when they respond)
        let target_peer_id = PeerId([0u8; 32]);
        
        let invite = InviteMessage::new(
            &cid,
            &info.name,
            &self.peer_id,
            &target_peer_id,
            info.member_count,
        );
        
        // Track this sent invite so we know which channel it was for when accepted
        let sent_invite = SentInvite {
            invite_id: invite.invite_id.clone(),
            target_nick: target_nick.to_string(),
            channel_id: channel_id.to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        self.sent_invites.write().await.insert(invite.invite_id.clone(), sent_invite);
        log::info!("Stored sent invite {} for channel {} to {}", invite.invite_id, channel_id, target_nick);
        
        encode_ctcp(NscCtcpCommand::Invite, &invite)
            .map_err(|e| format!("Failed to encode invite: {}", e))
    }
    
    /// Get list of pending invites
    pub async fn get_pending_invites(&self) -> Vec<PendingInvite> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.pending_invites.read().await
            .values()
            .filter(|inv| inv.expires_at > now)
            .cloned()
            .collect()
    }
    
    /// Accept a pending invite
    /// Returns: (target_nick, ctcp_response, irc_channel)
    pub async fn accept_invite(&self, invite_id: &str) -> Result<(String, String, String), String> {
        let invite = self.pending_invites.write().await.remove(invite_id)
            .ok_or("Invite not found or expired")?;
        
        // Create accept CTCP message
        let accept_msg = format!("\x01NSC_INVITE_ACCEPT {}\x01", 
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, invite_id));
        
        // Add to our channels
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let irc_channel = IrcChannelMapping::generate_irc_channel(&invite.channel_id);
        
        let info = ChannelInfo {
            channel_id: invite.channel_id.clone(),
            name: invite.channel_name.clone(),
            topic: String::new(),
            member_count: invite.member_count + 1,
            is_owner: false,
            created_at: now,
            irc_channel: irc_channel.clone(),
        };
        
        // Initialize members list with ourselves  
        let our_peer_id = hex::encode(self.peer_id.0);
        let our_display_name = format!("{}...", &our_peer_id[..8]);
        let self_member = NscChannelMember {
            peer_id: our_peer_id,
            display_name: our_display_name,
            is_self: true,
            is_owner: false,
            joined_at: now,
        };
        self.channel_members.write().await.insert(invite.channel_id.clone(), vec![self_member]);
        
        self.channel_info.write().await.insert(invite.channel_id.clone(), info);
        self.save_storage_async().await;
        
        log::info!("Accepted invite for channel '{}', IRC discovery channel: {}", 
            invite.channel_name, irc_channel);
        
        Ok((invite.from_nick, accept_msg, irc_channel))
    }
    
    /// Decline a pending invite
    pub async fn decline_invite(&self, invite_id: &str) -> Result<(String, String), String> {
        let invite = self.pending_invites.write().await.remove(invite_id)
            .ok_or("Invite not found or expired")?;
        
        let decline_msg = format!("\x01NSC_INVITE_DECLINE {}\x01",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, invite_id));
        
        Ok((invite.from_nick, decline_msg))
    }
    
    /// Get NSC-capable peers in an IRC channel
    pub async fn get_nsc_peers_in_channel(&self, irc_channel: &str) -> Vec<NscPeer> {
        let by_channel = self.peers_by_irc_channel.read().await;
        let known = self.known_peers.read().await;
        
        by_channel.get(irc_channel)
            .map(|nicks| {
                nicks.iter()
                    .filter_map(|nick| known.get(nick).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Check if a user in IRC channel is NSC-capable
    pub async fn is_nsc_capable(&self, nick: &str) -> bool {
        self.known_peers.read().await.contains_key(nick)
    }
    
    // =========================================================================
    // ICE Exchange Methods
    // =========================================================================
    
    /// Create an ICE offer to send to a peer
    /// Returns the CTCP message to send
    pub async fn create_ice_offer(&self, target_nick: &str, channel_id: Option<&str>) -> Result<String, String> {
        // Create ICE agent and gather candidates
        let ice_agent = IceAgent::new(true); // We're controlling (initiator)
        
        let candidates = ice_agent.gather_candidates().await
            .map_err(|e| format!("Failed to gather ICE candidates: {}", e))?;
        
        let credentials = ice_agent.local_credentials();
        let session_id = IceMessage::generate_session_id();
        
        // Convert channel_id if provided
        let cid = if let Some(id) = channel_id {
            let bytes = hex::decode(id).map_err(|_| "Invalid channel ID")?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(ChannelId(arr))
            } else {
                None
            }
        } else {
            None
        };
        
        // Create ICE message
        let ice_msg = IceMessage::new(
            session_id.clone(),
            &self.peer_id,
            cid.as_ref(),
            credentials,
            &candidates,
        );
        
        // Store pending session
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let session = PendingIceSession {
            session_id: session_id.clone(),
            target_nick: target_nick.to_string(),
            channel_id: channel_id.map(|s| s.to_string()),
            our_candidates: candidates.iter().map(|c| c.to_sdp()).collect(),
            our_ufrag: credentials.ufrag.clone(),
            our_pwd: credentials.pwd.clone(),
            remote_candidates: Vec::new(),
            remote_ufrag: None,
            remote_pwd: None,
            created_at: now,
            is_initiator: true,
        };
        
        self.pending_ice_sessions.write().await.insert(session_id.clone(), session);
        
        // Encode as CTCP
        encode_ctcp(NscCtcpCommand::IceOffer, &ice_msg)
            .map_err(|e| format!("Failed to encode ICE offer: {}", e))
    }
    
    /// Create an ICE answer in response to an offer
    /// Returns the CTCP message to send
    pub async fn create_ice_answer(&self, from_nick: &str, offer: &IceMessage) -> Result<String, String> {
        // Create ICE agent (not controlling - we're responding)
        let ice_agent = IceAgent::new(false);
        
        // Set remote credentials from offer
        let remote_creds = IceCredentials {
            ufrag: offer.ufrag.clone(),
            pwd: offer.pwd.clone(),
        };
        ice_agent.set_remote_credentials(remote_creds).await;
        
        // Add remote candidates from offer
        for candidate_sdp in &offer.candidates {
            if let Some(candidate) = IceCandidate::from_sdp(candidate_sdp) {
                ice_agent.add_remote_candidate(candidate).await;
            }
        }
        
        // Gather our candidates
        let candidates = ice_agent.gather_candidates().await
            .map_err(|e| format!("Failed to gather ICE candidates: {}", e))?;
        
        let credentials = ice_agent.local_credentials();
        
        // Create answer with same session ID as offer
        let ice_answer = IceMessage::new(
            offer.session_id.clone(),
            &self.peer_id,
            None, // Channel ID from offer
            credentials,
            &candidates,
        );
        
        // Store pending session for connection establishment
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let session = PendingIceSession {
            session_id: offer.session_id.clone(),
            target_nick: from_nick.to_string(),
            channel_id: offer.channel_id.clone(),
            our_candidates: candidates.iter().map(|c| c.to_sdp()).collect(),
            our_ufrag: credentials.ufrag.clone(),
            our_pwd: credentials.pwd.clone(),
            remote_candidates: offer.candidates.clone(),
            remote_ufrag: Some(offer.ufrag.clone()),
            remote_pwd: Some(offer.pwd.clone()),
            created_at: now,
            is_initiator: false,
        };
        
        self.pending_ice_sessions.write().await.insert(offer.session_id.clone(), session);
        
        // Try to establish connection in background
        let peer_id = offer.peer_id.clone();
        let target = from_nick.to_string();
        
        tokio::spawn(async move {
            // Give a moment for answer to be sent
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            
            // Try connectivity check
            if let Err(e) = ice_agent.check_connectivity().await {
                log::warn!("ICE connectivity check failed for {}: {}", target, e);
                return;
            }
            
            log::info!("ICE connectivity verified with {}", target);
            
            // Get selected candidate pair
            let Some(selected) = ice_agent.selected_pair().await else {
                log::warn!("No selected ICE pair for {}", target);
                return;
            };
            
            let addr = selected.remote.address;
            log::info!("Selected ICE candidate: {} for peer {}", addr, target);
            
            // Establish QUIC connection using the discovered address
            let manager = get_nsc_manager();
            let mgr = manager.read().await;
            if let Err(e) = mgr.connect_to_peer(&peer_id, addr).await {
                log::error!("Failed to establish QUIC connection with {}: {}", target, e);
            } else {
                log::info!("QUIC connection established with {} at {}", target, addr);
            }
        });
        
        // Encode answer as CTCP
        encode_ctcp(NscCtcpCommand::IceAnswer, &ice_answer)
            .map_err(|e| format!("Failed to encode ICE answer: {}", e))
    }
    
    /// Complete ICE exchange after receiving an answer
    pub async fn complete_ice_exchange(&self, from_nick: &str, answer: &IceMessage) -> Result<(), String> {
        // Get pending session
        let session = {
            let sessions = self.pending_ice_sessions.read().await;
            sessions.get(&answer.session_id).cloned()
                .ok_or("No pending ICE session found")?
        };
        
        if session.target_nick != from_nick {
            return Err("ICE answer from unexpected peer".to_string());
        }
        
        if !session.is_initiator {
            return Err("Received answer but we are not initiator".to_string());
        }
        
        // Create ICE agent with our credentials
        let ice_agent = IceAgent::new(true); // We're controlling
        
        // Set remote credentials from answer
        let remote_creds = IceCredentials {
            ufrag: answer.ufrag.clone(),
            pwd: answer.pwd.clone(),
        };
        ice_agent.set_remote_credentials(remote_creds).await;
        
        // Gather our candidates (we already have them but need to set up the agent)
        let _our_candidates = ice_agent.gather_candidates().await
            .map_err(|e| format!("Failed to gather ICE candidates: {}", e))?;
        
        // Add remote candidates from answer
        for candidate_sdp in &answer.candidates {
            if let Some(candidate) = IceCandidate::from_sdp(candidate_sdp) {
                ice_agent.add_remote_candidate(candidate).await;
            }
        }
        
        // Try connectivity check
        let peer_id = answer.peer_id.clone();
        let target_nick = from_nick.to_string();
        let channel_id = session.channel_id.clone();
        
        tokio::spawn(async move {
            match ice_agent.check_connectivity().await {
                Ok(_) => {
                    log::info!("ICE connectivity verified with {}", target_nick);
                    
                    // Get selected candidate pair
                    let Some(selected) = ice_agent.selected_pair().await else {
                        log::warn!("No selected ICE pair for {}", target_nick);
                        return;
                    };
                    
                    let addr = selected.remote.address;
                    log::info!("Selected ICE candidate: {} for peer {}", addr, target_nick);
                    
                    // Establish QUIC connection using the discovered address
                    let manager = get_nsc_manager();
                    let mgr = manager.read().await;
                    if let Err(e) = mgr.connect_to_peer(&peer_id, addr).await {
                        log::error!("Failed to establish QUIC connection with {}: {}", target_nick, e);
                        // Try relay fallback
                        if let Err(relay_err) = mgr.connect_via_relay(&peer_id, channel_id.as_deref()).await {
                            log::error!("Relay fallback also failed: {}", relay_err);
                        }
                    } else {
                        log::info!("QUIC connection established with {} at {}", target_nick, addr);
                        
                        // If this was an invite acceptance, send Welcome with epoch secrets
                        if let Some(ref ch_id) = channel_id {
                            if let Err(e) = mgr.send_welcome_epoch_secrets(&peer_id, ch_id).await {
                                log::error!("Failed to send epoch secrets to {}: {}", target_nick, e);
                            } else {
                                log::info!("Sent epoch secrets to {} for channel {}", target_nick, ch_id);
                                
                                // Add the invitee as a member to our channel members list
                                mgr.add_channel_member(ch_id, &peer_id, false).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    log::error!("ICE connectivity check failed: {}, trying relay fallback", e);
                    // Try relay fallback when ICE fails
                    let manager = get_nsc_manager();
                    let mgr = manager.read().await;
                    if let Err(relay_err) = mgr.connect_via_relay(&peer_id, channel_id.as_deref()).await {
                        log::error!("Relay fallback also failed: {}", relay_err);
                    }
                }
            }
        });
        
        // Remove pending session
        self.pending_ice_sessions.write().await.remove(&answer.session_id);
        
        Ok(())
    }
    
    /// Get a pending ICE session by session ID
    pub async fn get_ice_session(&self, session_id: &str) -> Option<PendingIceSession> {
        self.pending_ice_sessions.read().await.get(session_id).cloned()
    }
    
    /// Clean up expired ICE sessions (older than 60 seconds)
    pub async fn cleanup_stale_ice_sessions(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut sessions = self.pending_ice_sessions.write().await;
        sessions.retain(|_, session| now - session.created_at < 60);
    }
    
    /// Get connected peers with their nicknames (if known)
    pub async fn get_connected_peers(&self) -> Vec<(String, Option<String>)> {
        let addresses = self.peer_addresses.read().await;
        let known = self.known_peers.read().await;
        
        addresses.keys().map(|peer_id| {
            // Try to find nickname for this peer
            let nick = known.values()
                .find(|p| p.peer_id == *peer_id)
                .map(|p| p.nick.clone());
            (peer_id.clone(), nick)
        }).collect()
    }
    
    /// Start the inbound message handler - accepts connections and routes messages to UI
    pub async fn start_inbound_handler(&self) -> Result<(), String> {
        // Ensure transport is initialized
        if !self.is_transport_running().await {
            self.init_transport().await?;
        }
        
        let transport = {
            let lock = self.transport.read().await;
            lock.clone().ok_or("Transport not initialized")?
        };
        
        let event_tx = self.event_tx.clone();
        let our_peer_id = self.peer_id_hex();
        let _peer_addresses = self.peer_addresses.clone();
        
        tokio::spawn(async move {
            log::info!("Starting inbound message handler");
            loop {
                // Accept incoming connections
                match transport.accept().await {
                    Ok((connection, addr)) => {
                        log::info!("Accepted connection from {}", addr);
                        
                        let event_tx = event_tx.clone();
                        let our_peer_id = our_peer_id.clone();
                        
                        // Spawn handler for this connection
                        tokio::spawn(async move {
                            loop {
                                // Accept incoming uni streams
                                match connection.accept_uni().await {
                                    Ok(mut recv_stream) => {
                                        // Read message from stream
                                        match QuicTransport::receive_from_stream(&mut recv_stream).await {
                                            Ok(envelope) => {
                                                log::debug!("Received message: type={:?}", envelope.message_type);
                                                
                                                // Handle based on message type
                                                match envelope.message_type {
                                                    MessageType::ChannelMessage | MessageType::ChannelAction => {
                                                        let sender_hex = hex::encode(envelope.sender_id);
                                                        let channel_hex = hex::encode(&envelope.channel_id);
                                                        
                                                        // Decrypt using channel's group key
                                                        let channel_id = ChannelId::from_bytes(envelope.channel_id);
                                                        
                                                        let text = {
                                                            let manager = get_nsc_manager();
                                                            let mgr = manager.read().await;
                                                            match mgr.channel_manager.decrypt_for_channel(&channel_id, &envelope.payload).await {
                                                                Ok(plaintext) => String::from_utf8_lossy(&plaintext).to_string(),
                                                                Err(e) => {
                                                                    log::warn!("Decryption failed for channel {}: {}", channel_hex, e);
                                                                    // Fall back to raw data (for backwards compat or unencrypted messages)
                                                                    String::from_utf8_lossy(&envelope.payload).to_string()
                                                                }
                                                            }
                                                        };
                                                        
                                                        let msg = NscMessage {
                                                            timestamp: envelope.timestamp,
                                                            sender: sender_hex[..16].to_string(),
                                                            text,
                                                            is_own: sender_hex == our_peer_id,
                                                        };
                                                        
                                                        if let Some(ref tx) = event_tx {
                                                            let _ = tx.send(NscEvent::MessageReceived { 
                                                                channel_id: channel_hex,
                                                                message: msg,
                                                            }).await;
                                                        }
                                                    }
                                                    MessageType::Welcome => {
                                                        // Received epoch secrets for a channel
                                                        let channel_hex = hex::encode(&envelope.channel_id);
                                                        let sender_hex = hex::encode(envelope.sender_id);
                                                        log::info!("Received Welcome message with epoch secrets for channel {} from {}", 
                                                            channel_hex, sender_hex);
                                                        
                                                        // Parse epoch secrets from payload
                                                        use crate::nsc_channel::EpochSecrets;
                                                        match serde_json::from_slice::<EpochSecrets>(&envelope.payload) {
                                                            Ok(secrets) => {
                                                                let channel_id = ChannelId::from_bytes(envelope.channel_id);
                                                                let manager = get_nsc_manager();
                                                                let mgr = manager.read().await;
                                                                
                                                                // Get channel name from channel_info
                                                                let name = {
                                                                    let info = mgr.channel_info.read().await;
                                                                    info.get(&channel_hex)
                                                                        .map(|i| i.name.clone())
                                                                        .unwrap_or_else(|| "Unknown".to_string())
                                                                };
                                                                
                                                                // Store the epoch secrets
                                                                match mgr.channel_manager
                                                                    .join_channel_with_secrets(&channel_id, name, secrets)
                                                                    .await 
                                                                {
                                                                    Ok(_) => {
                                                                        log::info!("Successfully stored epoch secrets for channel {}", channel_hex);
                                                                        
                                                                        // Add the sender (inviter) as a member - they're the channel owner
                                                                        mgr.add_channel_member(&channel_hex, &sender_hex, true).await;
                                                                        
                                                                        // Also add ourselves as a member
                                                                        let our_peer_id = hex::encode(mgr.peer_id.0);
                                                                        mgr.add_channel_member(&channel_hex, &our_peer_id, false).await;
                                                                    }
                                                                    Err(e) => {
                                                                        log::error!("Failed to store epoch secrets: {:?}", e);
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                log::error!("Failed to parse epoch secrets from Welcome: {}", e);
                                                            }
                                                        }
                                                    }
                                                    MessageType::Ack => {
                                                        // Delivery acknowledgment received
                                                        let sender_hex = hex::encode(envelope.sender_id);
                                                        let channel_hex = hex::encode(&envelope.channel_id);
                                                        log::debug!("Received ACK from {} for channel {} seq {}", 
                                                            sender_hex, channel_hex, envelope.sequence_number);
                                                        
                                                        // Remove from retry queue - message was delivered
                                                        let pending_key = format!("{}:{}", channel_hex, envelope.sequence_number);
                                                        {
                                                            let manager = get_nsc_manager();
                                                            let mgr = manager.read().await;
                                                            let mut queue = mgr.retry_queue.write().await;
                                                            if queue.remove(&pending_key).is_some() {
                                                                log::debug!("Removed {} from retry queue after ACK", pending_key);
                                                            }
                                                        }
                                                        
                                                        // Notify UI of delivery confirmation
                                                        if let Some(ref tx) = event_tx {
                                                            let _ = tx.send(NscEvent::MessageDelivered { 
                                                                channel_id: channel_hex,
                                                                message_id: envelope.sequence_number,
                                                            }).await;
                                                        }
                                                    }
                                                    MessageType::Heartbeat => {
                                                        // Keep-alive heartbeat - update peer last seen
                                                        let sender_hex = hex::encode(envelope.sender_id);
                                                        log::debug!("Received Heartbeat from {}", sender_hex);
                                                        
                                                        // Update peer last seen timestamp
                                                        let manager = get_nsc_manager();
                                                        let mgr = manager.read().await;
                                                        
                                                        // Find peer by ID and update last_seen
                                                        let mut peers = mgr.known_peers.write().await;
                                                        for peer in peers.values_mut() {
                                                            if peer.peer_id == sender_hex {
                                                                peer.last_seen = SystemTime::now()
                                                                    .duration_since(UNIX_EPOCH)
                                                                    .unwrap_or_default()
                                                                    .as_secs();
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    MessageType::RoutingUpdate => {
                                                        // Peer is sharing routing information
                                                        let sender_hex = hex::encode(envelope.sender_id);
                                                        log::debug!("Received RoutingUpdate from {}", sender_hex);
                                                        
                                                        // Parse routing info from payload
                                                        // Format: list of (peer_id, address) tuples
                                                        if let Ok(routes) = serde_json::from_slice::<Vec<(String, String)>>(&envelope.payload) {
                                                            let manager = get_nsc_manager();
                                                            let mgr = manager.read().await;
                                                            let mut addresses = mgr.peer_addresses.write().await;
                                                            let route_count = routes.len();
                                                            
                                                            for (peer_id, addr_str) in routes {
                                                                if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                                                                    addresses.insert(peer_id, addr);
                                                                }
                                                            }
                                                            log::debug!("Updated {} routing entries from {}", route_count, sender_hex);
                                                        }
                                                    }
                                                    MessageType::MemberJoin => {
                                                        let sender_hex = hex::encode(envelope.sender_id);
                                                        let channel_hex = hex::encode(&envelope.channel_id);
                                                        log::info!("Received MemberJoin from {} for channel {}", sender_hex, channel_hex);
                                                        
                                                        // Add member to channel_members map
                                                        {
                                                            let manager = get_nsc_manager();
                                                            let mgr = manager.read().await;
                                                            mgr.add_channel_member(&channel_hex, &sender_hex, false).await;
                                                        }
                                                        
                                                        if let Some(ref tx) = event_tx {
                                                            let _ = tx.send(NscEvent::MemberJoined { 
                                                                channel_id: channel_hex,
                                                                peer_id: sender_hex,
                                                            }).await;
                                                        }
                                                    }
                                                    MessageType::MemberLeave => {
                                                        let sender_hex = hex::encode(envelope.sender_id);
                                                        let channel_hex = hex::encode(&envelope.channel_id);
                                                        log::info!("Received MemberLeave from {} for channel {}", sender_hex, channel_hex);
                                                        
                                                        // Remove member from channel_members map
                                                        {
                                                            let manager = get_nsc_manager();
                                                            let mgr = manager.read().await;
                                                            mgr.remove_channel_member(&channel_hex, &sender_hex).await;
                                                        }
                                                        
                                                        if let Some(ref tx) = event_tx {
                                                            let _ = tx.send(NscEvent::MemberLeft { 
                                                                channel_id: channel_hex,
                                                                peer_id: sender_hex,
                                                            }).await;
                                                        }
                                                    }
                                                    MessageType::ChannelMetadata => {
                                                        let channel_hex = hex::encode(&envelope.channel_id);
                                                        log::info!("Received ChannelMetadata update for {}", channel_hex);
                                                        
                                                        // Parse and update channel metadata
                                                        if let Ok(metadata) = serde_json::from_slice::<crate::nsc_irc::MetadataResponse>(&envelope.payload) {
                                                            let manager = get_nsc_manager();
                                                            let mgr = manager.read().await;
                                                            let mut info = mgr.channel_info.write().await;
                                                            
                                                            if let Some(channel) = info.get_mut(&channel_hex) {
                                                                channel.name = metadata.name;
                                                                channel.topic = metadata.topic;
                                                                channel.member_count = metadata.member_count;
                                                            }
                                                        }
                                                    }
                                                    MessageType::Commit => {
                                                        // Epoch advancement / key rotation from another member
                                                        let channel_hex = hex::encode(&envelope.channel_id);
                                                        let sender_hex = hex::encode(envelope.sender_id);
                                                        log::info!("Received Commit (epoch rotation) for channel {} from {}", 
                                                            channel_hex, sender_hex);
                                                        
                                                        use crate::nsc_channel::EpochSecrets;
                                                        match serde_json::from_slice::<EpochSecrets>(&envelope.payload) {
                                                            Ok(new_secrets) => {
                                                                let channel_id = ChannelId::from_bytes(envelope.channel_id);
                                                                let manager = get_nsc_manager();
                                                                let mgr = manager.read().await;
                                                                
                                                                match mgr.channel_manager.process_commit(&channel_id, new_secrets).await {
                                                                    Ok(_) => {
                                                                        log::info!("Applied Commit - epoch rotated for channel {}", channel_hex);
                                                                        
                                                                        // Notify UI about epoch change
                                                                        if let Some(ref tx) = event_tx {
                                                                            let _ = tx.send(NscEvent::MetadataUpdated { 
                                                                                channel_id: channel_hex,
                                                                            }).await;
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        log::error!("Failed to process Commit: {:?}", e);
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                log::error!("Failed to parse Commit epoch secrets: {}", e);
                                                            }
                                                        }
                                                    }
                                                    MessageType::KeyPackage => {
                                                        // Peer sharing their KeyPackage (prekey bundle)
                                                        let sender_hex = hex::encode(envelope.sender_id);
                                                        log::info!("Received KeyPackage from {}", sender_hex);
                                                        
                                                        match PeerSessionManager::deserialize_prekey_bundle(&envelope.payload) {
                                                            Ok(bundle) => {
                                                                let manager = get_nsc_manager();
                                                                let mgr = manager.read().await;
                                                                let fingerprint = bundle.identity_key.fingerprint_hex();
                                                                mgr.peer_prekey_bundles.write().await.insert(fingerprint.clone(), bundle);
                                                                log::info!("Stored KeyPackage from {} (fingerprint: {})", sender_hex, fingerprint);
                                                            }
                                                            Err(e) => {
                                                                log::error!("Failed to parse KeyPackage: {:?}", e);
                                                            }
                                                        }
                                                    }
                                                    MessageType::MemberUpdate => {
                                                        // Member key update (e.g., device rotation)
                                                        let sender_hex = hex::encode(envelope.sender_id);
                                                        let channel_hex = hex::encode(&envelope.channel_id);
                                                        log::info!("Received MemberUpdate from {} for channel {}", sender_hex, channel_hex);
                                                    }
                                                    _ => {
                                                        log::debug!("Unhandled message type {:?}", envelope.message_type);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                log::warn!("Failed to receive message: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::debug!("Connection closed or error: {}", e);
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Accept failed: {}", e);
                        // Small delay before retrying
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    // =========================================================================
    // Multi-Device Support Methods
    // =========================================================================
    
    /// Get this device's name (platform-specific)
    fn get_device_name() -> String {
        #[cfg(target_os = "android")]
        return "Android".to_string();
        
        #[cfg(target_os = "ios")]
        return "iPhone".to_string();
        
        #[cfg(target_os = "macos")]
        return "Mac".to_string();  
        
        #[cfg(target_os = "windows")]
        return "Windows".to_string();
        
        #[cfg(target_os = "linux")]
        return "Linux".to_string();
        
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos", target_os = "windows", target_os = "linux")))]
        return "Unknown Device".to_string();
    }
    
    /// Get info about this device
    pub async fn this_device(&self) -> DeviceInfo {
        self.this_device.read().await.clone()
    }
    
    /// Get all linked devices
    pub async fn linked_devices(&self) -> Vec<DeviceInfo> {
        self.linked_devices.read().await.clone()
    }
    
    /// Check if this is the primary device
    pub async fn is_primary_device(&self) -> bool {
        self.this_device.read().await.is_primary
    }
    
    /// Generate a linking code for adding a new device
    /// Returns (link_code, expires_at)
    pub async fn generate_link_code(&self) -> Result<(String, u64), String> {
        use rand::Rng;
        
        // Generate 6-character alphanumeric code (easy to type)
        let code: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(6)
            .map(char::from)
            .map(|c| c.to_ascii_uppercase())
            .collect();
        
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() + 300; // 5 minute expiry
        
        // Store as pending request
        let request = DeviceLinkRequest {
            link_code: code.clone(),
            device_public_key: String::new(), // Will be filled when device connects
            device_name: String::new(),
            expires_at,
        };
        
        self.pending_link_requests.write().await.insert(code.clone(), request);
        
        log::info!("Generated device link code: {} (expires in 5 minutes)", code);
        Ok((code, expires_at))
    }
    
    /// Request to link this device to an existing account using a link code
    /// This is called by the NEW device
    pub async fn request_device_link(&self, link_code: &str, primary_peer_id: &str) -> Result<String, String> {
        use crate::nsc_transport::MessageType;
        
        // Create device link request message
        let request = DeviceLinkRequest {
            link_code: link_code.to_uppercase(),
            device_public_key: hex::encode(self.peer_id.0),
            device_name: Self::get_device_name(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() + 60,
        };
        
        let request_json = serde_json::to_vec(&request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;
        
        // Create envelope to send to primary device
        let envelope = NscEnvelope::new(
            MessageType::MemberJoin, // Reuse for device link request
            self.peer_id.0,
            [0u8; 32], // No specific channel
            0,
            Bytes::from(request_json),
        );
        
        // If we have direct connection, send directly; otherwise use relay
        let peer_bytes = hex::decode(primary_peer_id).map_err(|_| "Invalid peer ID")?;
        if peer_bytes.len() != 32 {
            return Err("Invalid peer ID length".to_string());
        }
        let mut peer_arr = [0u8; 32];
        peer_arr.copy_from_slice(&peer_bytes);
        let target_peer = PeerId(peer_arr);
        
        // Try relay since we might not have direct connection yet
        if self.relay_client.is_connected().await {
            self.relay_client.send_to_peer(&target_peer, &envelope).await
                .map_err(|e| format!("Failed to send link request: {}", e))?;
        } else {
            return Err("Not connected to relay - connect first".to_string());
        }
        
        log::info!("Sent device link request with code: {}", link_code);
        Ok("Link request sent - waiting for approval".to_string())
    }
    
    /// Process incoming device link request (on PRIMARY device)
    pub async fn process_link_request(&self, request: DeviceLinkRequest) -> Result<DeviceLinkResponse, String> {
        // Verify the link code exists and hasn't expired
        let pending = self.pending_link_requests.read().await;
        let stored_request = pending.get(&request.link_code)
            .ok_or("Invalid or expired link code")?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if stored_request.expires_at < now {
            return Err("Link code expired".to_string());
        }
        drop(pending);
        
        // Compute shared secret using ECDH for encrypting the response
        // For simplicity, we'll use the requesting device's public key with our identity
        let new_device_pubkey_bytes = hex::decode(&request.device_public_key)
            .map_err(|_| "Invalid device public key")?;
        
        // Derive a shared encryption key (simplified - in production use proper X3DH)
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.identity.to_bytes());
        hasher.update(&new_device_pubkey_bytes);
        let shared_key: [u8; 32] = hasher.finalize().into();
        
        // Encrypt identity key for the new device
        let identity_bytes = self.identity.to_bytes();
        let encrypted_identity = Self::encrypt_with_key(&shared_key, &identity_bytes)?;
        
        // Encrypt epoch secrets for each channel
        let mut encrypted_channel_secrets = Vec::new();
        let channel_info = self.channel_info.read().await;
        
        for (channel_id, info) in channel_info.iter() {
            // Get channel ID as bytes
            if let Ok(ch_bytes) = hex::decode(channel_id) {
                if ch_bytes.len() == 32 {
                    let mut ch_arr = [0u8; 32];
                    ch_arr.copy_from_slice(&ch_bytes);
                    let cid = crate::nsc_channel::ChannelId(ch_arr);
                    
                    if let Some(secrets) = self.channel_manager.get_epoch_secrets(&cid).await {
                        let secrets_json = serde_json::to_vec(&secrets)
                            .map_err(|e| format!("Failed to serialize secrets: {}", e))?;
                        let encrypted = Self::encrypt_with_key(&shared_key, &secrets_json)?;
                        
                        encrypted_channel_secrets.push(EncryptedChannelSecrets {
                            channel_id: channel_id.clone(),
                            channel_name: info.name.clone(),
                            encrypted_secrets: base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &encrypted
                            ),
                        });
                    }
                }
            }
        }
        
        // Create response
        let response = DeviceLinkResponse {
            encrypted_identity: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &encrypted_identity
            ),
            encrypted_channel_secrets,
            primary_device: self.this_device.read().await.clone(),
        };
        
        // Add new device to linked devices
        let new_device = DeviceInfo {
            device_id: hex::encode(&new_device_pubkey_bytes[..16]),
            name: request.device_name.clone(),
            public_key: request.device_public_key.clone(),
            linked_at: now,
            last_seen: now,
            is_primary: false,
        };
        self.linked_devices.write().await.push(new_device);
        
        // Remove used link code
        self.pending_link_requests.write().await.remove(&request.link_code);
        
        // Save updated device list
        self.save_storage_async().await;
        
        log::info!("Device linked successfully: {}", request.device_name);
        Ok(response)
    }
    
    /// Process device link response (on NEW device)
    pub async fn process_link_response(&self, response: DeviceLinkResponse, primary_peer_pubkey: &str) -> Result<(), String> {
        // Derive the same shared key
        let primary_pubkey_bytes = hex::decode(primary_peer_pubkey)
            .map_err(|_| "Invalid primary device public key")?;
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&primary_pubkey_bytes);
        hasher.update(&self.peer_id.0);
        let shared_key: [u8; 32] = hasher.finalize().into();
        
        // Decrypt identity key
        let encrypted_identity = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &response.encrypted_identity
        ).map_err(|e| format!("Failed to decode identity: {}", e))?;
        
        let identity_bytes = Self::decrypt_with_key(&shared_key, &encrypted_identity)?;
        if identity_bytes.len() != 32 {
            return Err("Invalid identity key length".to_string());
        }
        
        // Note: In a real implementation, we would replace our identity with the shared one
        // For now, just log that we received it
        log::info!("Received shared identity from primary device");
        
        // Decrypt and store epoch secrets for each channel
        for ch_secrets in &response.encrypted_channel_secrets {
            let encrypted = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &ch_secrets.encrypted_secrets
            ).map_err(|e| format!("Failed to decode channel secrets: {}", e))?;
            
            let secrets_json = Self::decrypt_with_key(&shared_key, &encrypted)?;
            let epoch_secrets: crate::nsc_channel::EpochSecrets = serde_json::from_slice(&secrets_json)
                .map_err(|e| format!("Failed to parse epoch secrets: {}", e))?;
            
            // Store channel with secrets
            let ch_bytes = hex::decode(&ch_secrets.channel_id)
                .map_err(|_| "Invalid channel ID")?;
            if ch_bytes.len() == 32 {
                let mut ch_arr = [0u8; 32];
                ch_arr.copy_from_slice(&ch_bytes);
                let cid = crate::nsc_channel::ChannelId(ch_arr);
                
                self.channel_manager.join_channel_with_secrets(
                    &cid,
                    ch_secrets.channel_name.clone(),
                    epoch_secrets
                ).await.map_err(|e| format!("Failed to store channel: {:?}", e))?;
                
                // Add to channel_info
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                self.channel_info.write().await.insert(ch_secrets.channel_id.clone(), ChannelInfo {
                    channel_id: ch_secrets.channel_id.clone(),
                    name: ch_secrets.channel_name.clone(),
                    topic: String::new(),
                    member_count: 1,
                    is_owner: false,
                    created_at: now,
                    irc_channel: IrcChannelMapping::generate_irc_channel(&ch_secrets.channel_id),
                });
            }
        }
        
        // Add primary device to our linked devices list
        self.linked_devices.write().await.push(response.primary_device);
        
        // Mark ourselves as non-primary
        self.this_device.write().await.is_primary = false;
        
        // Save everything
        self.save_storage_async().await;
        
        log::info!("Successfully linked to primary device - {} channels synced", 
            response.encrypted_channel_secrets.len());
        Ok(())
    }
    
    /// Simple symmetric encryption helper (ChaCha20-Poly1305)
    fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadCore, aead::Aead};
        use rand::rngs::OsRng;
        
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
    
    /// Simple symmetric decryption helper
    fn decrypt_with_key(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead, Nonce};
        
        if ciphertext.len() < 12 {
            return Err("Ciphertext too short".to_string());
        }
        
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        
        cipher.decrypt(nonce, &ciphertext[12..])
            .map_err(|e| format!("Decryption failed: {}", e))
    }
    
    /// Update this device's last seen timestamp
    pub async fn update_device_last_seen(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.this_device.write().await.last_seen = now;
    }
    
    /// Remove a linked device
    pub async fn remove_device(&self, device_id: &str) -> Result<(), String> {
        let mut devices = self.linked_devices.write().await;
        let initial_len = devices.len();
        devices.retain(|d| d.device_id != device_id);
        
        if devices.len() == initial_len {
            return Err("Device not found".to_string());
        }
        
        drop(devices);
        self.save_storage_async().await;
        
        log::info!("Removed device: {}", device_id);
        Ok(())
    }
    
    /// Get device count (including this device)
    pub async fn device_count(&self) -> usize {
        1 + self.linked_devices.read().await.len()
    }
}

impl Default for NscManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Storage Functions
// =============================================================================

/// Get the NSC storage file path
fn nsc_storage_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("nais").join("nsc_data.json"))
}

/// Load NSC storage from disk
pub fn load_nsc_storage() -> NscStorage {
    let Some(path) = nsc_storage_path() else {
        return NscStorage::default();
    };
    
    let Ok(data) = fs::read_to_string(path) else {
        return NscStorage::default();
    };
    
    serde_json::from_str(&data).unwrap_or_default()
}

/// Save NSC storage to disk
pub fn save_nsc_storage(storage: &NscStorage) -> Result<(), String> {
    let path = nsc_storage_path().ok_or("No config directory")?;
    
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    
    let data = serde_json::to_string_pretty(storage).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())
}

/// Save a single message to storage
pub fn save_message(channel_id: &str, msg: &StoredMessage) -> Result<(), String> {
    let mut storage = load_nsc_storage();
    
    let channel_msgs = storage.messages.entry(channel_id.to_string()).or_insert_with(Vec::new);
    
    // Avoid duplicates by timestamp+sender+text
    let exists = channel_msgs.iter().any(|m| 
        m.timestamp == msg.timestamp && m.sender == msg.sender && m.text == msg.text
    );
    
    if !exists {
        channel_msgs.push(msg.clone());
        // Keep only last 1000 messages per channel
        if channel_msgs.len() > 1000 {
            channel_msgs.drain(0..channel_msgs.len() - 1000);
        }
        save_nsc_storage(&storage)?;
    }
    
    Ok(())
}

/// Load messages for a channel
pub fn load_messages(channel_id: &str) -> Vec<StoredMessage> {
    let storage = load_nsc_storage();
    storage.messages.get(channel_id).cloned().unwrap_or_default()
}

// =============================================================================
// Global Instance
// =============================================================================

use std::sync::OnceLock;

static NSC_MANAGER: OnceLock<Arc<tokio::sync::RwLock<NscManager>>> = OnceLock::new();

/// Get or initialize the global NSC manager
pub fn get_nsc_manager() -> Arc<tokio::sync::RwLock<NscManager>> {
    NSC_MANAGER.get_or_init(|| {
        Arc::new(tokio::sync::RwLock::new(NscManager::new()))
    }).clone()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_storage_serialization() {
        let storage = NscStorage {
            identity: Some(StoredIdentity {
                private_key: "0".repeat(64),
                display_name: "Test".to_string(),
                created_at: 1234567890,
            }),
            channels: vec![
                StoredChannel {
                    channel_id: "a".repeat(64),
                    name: "Test Channel".to_string(),
                    topic: "Test topic".to_string(),
                    created_at: 1234567890,
                    member_count: 5,
                    is_owner: true,
                },
            ],
            messages: HashMap::new(),
            devices: Vec::new(),
            this_device_id: None,
            encrypted_sessions: None,
            encrypted_trust: None,
            peer_prekey_bundles: HashMap::new(),
        };
        
        let json = serde_json::to_string(&storage).unwrap();
        let loaded: NscStorage = serde_json::from_str(&json).unwrap();
        
        assert!(loaded.identity.is_some());
        assert_eq!(loaded.channels.len(), 1);
        assert_eq!(loaded.channels[0].name, "Test Channel");
    }
    
    #[tokio::test]
    async fn test_manager_creation() {
        let manager = NscManager::new();
        
        // Should have a peer ID
        assert_ne!(manager.peer_id().0, [0u8; 32]);
        
        // Fingerprint should be hex
        let fp = manager.fingerprint();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
    
    #[tokio::test]
    async fn test_create_channel() {
        let manager = NscManager::new();
        
        let info = manager.create_channel("Test Channel".to_string()).await.unwrap();
        
        assert_eq!(info.name, "Test Channel");
        assert!(info.is_owner);
        assert_eq!(info.member_count, 1);
        assert_eq!(info.channel_id.len(), 64);
        
        // Should be in list
        let channels = manager.list_channels().await;
        assert!(!channels.is_empty());
    }
}
