//! Nais Secure Channels - Channel Management
//!
//! Implements secure channel state management:
//! - Channel creation and lifecycle
//! - Membership management (join/leave/update)
//! - Message ordering and deduplication
//! - Signed metadata with version chain
//! - Offline message queue
//! - Group key management (MLS-lite)

use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

use crate::nsc_crypto::{IdentityKeyPair, PreKeyBundle};
use crate::nsc_transport::{MessageType, NscEnvelope, PeerId};

// =============================================================================
// Error Types
// =============================================================================

#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("Channel not found: {0}")]
    NotFound(String),

    #[error("Not a member of channel")]
    NotMember,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid metadata: {0}")]
    InvalidMetadata(String),

    #[error("Stale version: expected > {expected}, got {got}")]
    StaleVersion { expected: u64, got: u64 },

    #[error("Broken metadata chain")]
    BrokenChain,

    #[error("Member already exists: {0}")]
    MemberExists(String),

    #[error("Member not found: {0}")]
    MemberNotFound(String),

    #[error("Duplicate message: {0}")]
    DuplicateMessage(String),

    #[error("Message too old")]
    MessageTooOld,

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Transport error: {0}")]
    TransportError(String),
}

pub type ChannelResult<T> = Result<T, ChannelError>;

// =============================================================================
// Constants
// =============================================================================

/// Maximum message age to accept (5 minutes)
pub const MAX_MESSAGE_AGE: Duration = Duration::from_secs(300);

/// Deduplication window size
pub const DEDUP_WINDOW_SIZE: usize = 10000;

/// Maximum queued messages per peer
pub const MAX_QUEUED_MESSAGES: usize = 1000;

/// Maximum channel members (0 = unlimited)
pub const DEFAULT_MAX_MEMBERS: u32 = 500;

/// Key rotation threshold (messages)
pub const KEY_ROTATION_MESSAGE_THRESHOLD: u32 = 100;

/// Key rotation threshold (time)
pub const KEY_ROTATION_TIME_THRESHOLD: Duration = Duration::from_secs(3600); // 1 hour

/// Switch to sender keys threshold (member count)
pub const SENDER_KEYS_THRESHOLD: usize = 100;

/// Maximum sender key chain length before refresh
pub const MAX_SENDER_KEY_CHAIN: u32 = 1000;

// =============================================================================
// Channel Identity
// =============================================================================

/// Unique channel identifier (32 bytes)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChannelId(pub [u8; 32]);

impl ChannelId {
    /// Create from creation block hash
    pub fn from_creation(creator: &PeerId, name: &str, created_at: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(creator.0);
        hasher.update(name.as_bytes());
        hasher.update(&created_at.to_be_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        Self(id)
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short form for display
    pub fn short(&self) -> String {
        self.to_hex()[..8].to_string()
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.short())
    }
}

// =============================================================================
// Channel Settings
// =============================================================================

/// Message retention policy
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetentionPolicy {
    /// Keep messages forever
    Forever,
    /// Keep for specified duration
    Duration(Duration),
    /// Keep last N messages
    Count(usize),
    /// Delete immediately after delivery
    Ephemeral,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self::Forever
    }
}

/// Channel settings
#[derive(Clone, Debug)]
pub struct ChannelSettings {
    /// Is channel publicly discoverable
    pub discoverable: bool,
    /// Require admin approval to join
    pub invite_only: bool,
    /// Maximum members (0 = unlimited)
    pub max_members: u32,
    /// Message retention policy
    pub retention: RetentionPolicy,
    /// Allow regular members to invite
    pub members_can_invite: bool,
    /// Require read receipts
    pub require_read_receipts: bool,
}

impl Default for ChannelSettings {
    fn default() -> Self {
        Self {
            discoverable: false,
            invite_only: true,
            max_members: DEFAULT_MAX_MEMBERS,
            retention: RetentionPolicy::default(),
            members_can_invite: true,
            require_read_receipts: false,
        }
    }
}

// =============================================================================
// Channel Metadata
// =============================================================================

/// Signed channel metadata with version chain
#[derive(Clone, Debug)]
pub struct ChannelMetadata {
    /// Channel identifier
    pub channel_id: ChannelId,
    /// Human-readable channel name
    pub name: String,
    /// Channel topic/description
    pub topic: String,
    /// Channel avatar hash
    pub avatar: Option<[u8; 32]>,
    /// Creation timestamp
    pub created_at: u64,
    /// Current metadata version (monotonic)
    pub version: u64,
    /// Channel creator's peer ID
    pub creator: PeerId,
    /// List of admin peer IDs
    pub admins: Vec<PeerId>,
    /// Channel settings
    pub settings: ChannelSettings,
    /// Signature by authorized updater
    pub signature: [u8; 64],
    /// Previous metadata hash (chain)
    pub previous_hash: Option<[u8; 32]>,
}

impl ChannelMetadata {
    /// Create new channel metadata
    pub fn new(name: String, creator: PeerId) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let channel_id = ChannelId::from_creation(&creator, &name, created_at);

        Self {
            channel_id,
            name,
            topic: String::new(),
            avatar: None,
            created_at,
            version: 1,
            creator,
            admins: vec![creator],
            settings: ChannelSettings::default(),
            signature: [0u8; 64],
            previous_hash: None,
        }
    }

    /// Compute hash of this metadata
    pub fn hash(&self) -> [u8; 32] {
        let data = self.to_signing_data();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Get data to sign
    fn to_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.channel_id.0);
        data.extend_from_slice(self.name.as_bytes());
        data.extend_from_slice(self.topic.as_bytes());
        if let Some(avatar) = &self.avatar {
            data.extend_from_slice(avatar);
        }
        data.extend_from_slice(&self.created_at.to_be_bytes());
        data.extend_from_slice(&self.version.to_be_bytes());
        data.extend_from_slice(&self.creator.0);
        for admin in &self.admins {
            data.extend_from_slice(&admin.0);
        }
        // Settings serialization
        data.push(self.settings.discoverable as u8);
        data.push(self.settings.invite_only as u8);
        data.extend_from_slice(&self.settings.max_members.to_be_bytes());
        if let Some(prev) = &self.previous_hash {
            data.extend_from_slice(prev);
        }
        data
    }

    /// Sign metadata with identity key
    pub fn sign(&mut self, identity: &IdentityKeyPair) {
        let data = self.to_signing_data();
        self.signature = identity.sign(&data);
    }

    /// Verify signature
    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        use ed25519_dalek::{Signature, VerifyingKey};

        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };

        let signature = Signature::from_bytes(&self.signature);
        let data = self.to_signing_data();
        verifying_key.verify_strict(&data, &signature).is_ok()
    }

    /// Check if peer is authorized to update metadata
    pub fn can_update(&self, peer: &PeerId) -> bool {
        *peer == self.creator || self.admins.contains(peer)
    }

    /// Verify an update is valid
    pub fn verify_update(&self, new: &ChannelMetadata) -> ChannelResult<()> {
        // Check version is incrementing
        if new.version <= self.version {
            return Err(ChannelError::StaleVersion {
                expected: self.version,
                got: new.version,
            });
        }

        // Check previous hash chain
        if new.previous_hash != Some(self.hash()) {
            return Err(ChannelError::BrokenChain);
        }

        // Channel ID must match
        if new.channel_id != self.channel_id {
            return Err(ChannelError::InvalidMetadata("channel_id mismatch".into()));
        }

        Ok(())
    }

    /// Create updated metadata
    pub fn update(&self) -> ChannelMetadataBuilder {
        ChannelMetadataBuilder {
            base: self.clone(),
            new_name: None,
            new_topic: None,
            new_avatar: None,
            new_settings: None,
            add_admins: Vec::new(),
            remove_admins: Vec::new(),
        }
    }
}

/// Builder for metadata updates
pub struct ChannelMetadataBuilder {
    base: ChannelMetadata,
    new_name: Option<String>,
    new_topic: Option<String>,
    new_avatar: Option<Option<[u8; 32]>>,
    new_settings: Option<ChannelSettings>,
    add_admins: Vec<PeerId>,
    remove_admins: Vec<PeerId>,
}

impl ChannelMetadataBuilder {
    pub fn name(mut self, name: String) -> Self {
        self.new_name = Some(name);
        self
    }

    pub fn topic(mut self, topic: String) -> Self {
        self.new_topic = Some(topic);
        self
    }

    pub fn avatar(mut self, avatar: Option<[u8; 32]>) -> Self {
        self.new_avatar = Some(avatar);
        self
    }

    pub fn settings(mut self, settings: ChannelSettings) -> Self {
        self.new_settings = Some(settings);
        self
    }

    pub fn add_admin(mut self, admin: PeerId) -> Self {
        self.add_admins.push(admin);
        self
    }

    pub fn remove_admin(mut self, admin: PeerId) -> Self {
        self.remove_admins.push(admin);
        self
    }

    pub fn build(self, identity: &IdentityKeyPair) -> ChannelMetadata {
        // Compute hash before consuming any fields
        let previous_hash = Some(self.base.hash());
        
        let mut metadata = ChannelMetadata {
            channel_id: self.base.channel_id,
            name: self.new_name.unwrap_or(self.base.name),
            topic: self.new_topic.unwrap_or(self.base.topic),
            avatar: self.new_avatar.unwrap_or(self.base.avatar),
            created_at: self.base.created_at,
            version: self.base.version + 1,
            creator: self.base.creator,
            admins: self.base.admins.clone(),
            settings: self.new_settings.unwrap_or(self.base.settings),
            signature: [0u8; 64],
            previous_hash,
        };

        // Update admins
        for admin in self.add_admins {
            if !metadata.admins.contains(&admin) {
                metadata.admins.push(admin);
            }
        }
        for admin in &self.remove_admins {
            metadata.admins.retain(|a| a != admin);
        }

        // Ensure creator is always admin
        if !metadata.admins.contains(&metadata.creator) {
            metadata.admins.push(metadata.creator);
        }

        metadata.sign(identity);
        metadata
    }
}

// =============================================================================
// Membership
// =============================================================================

/// Member role in channel
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberRole {
    /// Channel creator (cannot be removed)
    Owner,
    /// Can manage channel settings and members
    Admin,
    /// Regular member
    Member,
}

/// Channel member information
#[derive(Clone, Debug)]
pub struct ChannelMember {
    /// Member's peer ID
    pub peer_id: PeerId,
    /// Display name
    pub display_name: String,
    /// Role in channel
    pub role: MemberRole,
    /// When member joined
    pub joined_at: u64,
    /// Member's identity public key
    pub identity_key: [u8; 32],
    /// Pre-key bundle for this member (for new sessions)
    pub prekey_bundle: Option<PreKeyBundle>,
    /// Last message received from this member
    pub last_message_at: Option<u64>,
    /// Online status
    pub online: bool,
}

impl ChannelMember {
    pub fn new(peer_id: PeerId, display_name: String, identity_key: [u8; 32]) -> Self {
        let joined_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            peer_id,
            display_name,
            role: MemberRole::Member,
            joined_at,
            identity_key,
            prekey_bundle: None,
            last_message_at: None,
            online: true,
        }
    }

    pub fn with_role(mut self, role: MemberRole) -> Self {
        self.role = role;
        self
    }

    pub fn with_prekey_bundle(mut self, bundle: PreKeyBundle) -> Self {
        self.prekey_bundle = Some(bundle);
        self
    }
}

/// Membership change event
#[derive(Clone, Debug)]
pub enum MembershipEvent {
    /// Member joined the channel
    Joined {
        member: ChannelMember,
        invited_by: Option<PeerId>,
    },
    /// Member left the channel
    Left {
        peer_id: PeerId,
        reason: LeaveReason,
    },
    /// Member's role changed
    RoleChanged {
        peer_id: PeerId,
        old_role: MemberRole,
        new_role: MemberRole,
        changed_by: PeerId,
    },
    /// Member's key updated
    KeyUpdated {
        peer_id: PeerId,
        new_key: [u8; 32],
    },
}

/// Reason for leaving channel
#[derive(Clone, Debug)]
pub enum LeaveReason {
    /// Voluntary leave
    Voluntary,
    /// Kicked by admin
    Kicked { by: PeerId },
    /// Banned
    Banned { by: PeerId, reason: String },
    /// Key compromise
    KeyCompromise,
}

// =============================================================================
// Message Ordering
// =============================================================================

/// Message identifier for deduplication
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MessageId {
    /// Sender peer ID
    pub sender: PeerId,
    /// Sequence number
    pub sequence: u64,
}

impl MessageId {
    pub fn new(sender: PeerId, sequence: u64) -> Self {
        Self { sender, sequence }
    }

    pub fn from_envelope(envelope: &NscEnvelope) -> Self {
        Self {
            sender: PeerId(envelope.sender_id),
            sequence: envelope.sequence_number,
        }
    }
}

/// Per-sender sequence tracker
#[derive(Clone, Debug)]
pub struct SequenceTracker {
    /// Last seen sequence number per sender
    last_seen: HashMap<PeerId, u64>,
    /// Recent message IDs for deduplication
    recent_ids: VecDeque<MessageId>,
    /// Maximum size of dedup window
    max_size: usize,
}

impl SequenceTracker {
    pub fn new(max_size: usize) -> Self {
        Self {
            last_seen: HashMap::new(),
            recent_ids: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    /// Check if message was already seen
    pub fn is_duplicate(&self, id: &MessageId) -> bool {
        self.recent_ids.contains(id)
    }

    /// Record a message as seen
    pub fn record(&mut self, id: MessageId) {
        // Update last seen for sender
        self.last_seen
            .entry(id.sender)
            .and_modify(|seq| {
                if id.sequence > *seq {
                    *seq = id.sequence;
                }
            })
            .or_insert(id.sequence);

        // Add to dedup window
        if self.recent_ids.len() >= self.max_size {
            self.recent_ids.pop_front();
        }
        self.recent_ids.push_back(id);
    }

    /// Get last seen sequence for sender
    pub fn last_sequence(&self, sender: &PeerId) -> Option<u64> {
        self.last_seen.get(sender).copied()
    }

    /// Check if message is out of order
    pub fn is_out_of_order(&self, id: &MessageId) -> bool {
        if let Some(last) = self.last_seen.get(&id.sender) {
            // Allow some slack for reordering
            id.sequence < last.saturating_sub(100)
        } else {
            false
        }
    }
}

// =============================================================================
// Message Queue
// =============================================================================

/// Queued message for offline peer
#[derive(Clone, Debug)]
pub struct QueuedMessage {
    /// Target peer
    pub recipient: PeerId,
    /// The message envelope
    pub envelope: NscEnvelope,
    /// When message was queued
    pub queued_at: Instant,
    /// Number of delivery attempts
    pub attempts: u32,
    /// Last attempt time
    pub last_attempt: Option<Instant>,
}

impl QueuedMessage {
    pub fn new(recipient: PeerId, envelope: NscEnvelope) -> Self {
        Self {
            recipient,
            envelope,
            queued_at: Instant::now(),
            attempts: 0,
            last_attempt: None,
        }
    }

    /// Check if message has expired
    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.queued_at.elapsed() > max_age
    }

    /// Mark an attempt
    pub fn mark_attempt(&mut self) {
        self.attempts += 1;
        self.last_attempt = Some(Instant::now());
    }
}

/// Offline message queue per channel
pub struct MessageQueue {
    /// Queued messages by recipient
    queues: HashMap<PeerId, VecDeque<QueuedMessage>>,
    /// Maximum messages per peer
    max_per_peer: usize,
    /// Maximum age before expiry
    max_age: Duration,
}

impl MessageQueue {
    pub fn new() -> Self {
        Self {
            queues: HashMap::new(),
            max_per_peer: MAX_QUEUED_MESSAGES,
            max_age: Duration::from_secs(86400), // 24 hours
        }
    }

    /// Queue a message for offline peer
    pub fn enqueue(&mut self, recipient: PeerId, envelope: NscEnvelope) -> bool {
        let queue = self.queues.entry(recipient).or_insert_with(VecDeque::new);

        // Check capacity
        if queue.len() >= self.max_per_peer {
            // Remove oldest message
            queue.pop_front();
        }

        queue.push_back(QueuedMessage::new(recipient, envelope));
        true
    }

    /// Get queued messages for a peer
    pub fn get_queued(&mut self, recipient: &PeerId) -> Vec<QueuedMessage> {
        self.queues
            .remove(recipient)
            .map(|q| q.into_iter().filter(|m| !m.is_expired(self.max_age)).collect())
            .unwrap_or_default()
    }

    /// Get number of queued messages
    pub fn queue_size(&self, recipient: &PeerId) -> usize {
        self.queues.get(recipient).map(|q| q.len()).unwrap_or(0)
    }

    /// Clear expired messages
    pub fn clear_expired(&mut self) {
        for queue in self.queues.values_mut() {
            queue.retain(|m| !m.is_expired(self.max_age));
        }
        // Remove empty queues
        self.queues.retain(|_, q| !q.is_empty());
    }

    /// Total queued messages
    pub fn total_queued(&self) -> usize {
        self.queues.values().map(|q| q.len()).sum()
    }
}

impl Default for MessageQueue {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Group Key Management (MLS-lite)
// =============================================================================

/// Group epoch secrets (simplified MLS)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EpochSecrets {
    /// Current epoch number
    pub epoch: u64,
    /// Epoch secret (32 bytes)
    pub epoch_secret: [u8; 32],
    /// Sender data secret
    pub sender_data_secret: [u8; 32],
    /// Encryption key
    pub encryption_key: [u8; 32],
    /// When this epoch started
    pub started_at: u64,
    /// Messages encrypted in this epoch
    pub message_count: u32,
}

impl EpochSecrets {
    /// Create initial epoch secrets from shared secret
    pub fn initial(shared_secret: &[u8; 32]) -> Self {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);

        let mut epoch_secret = [0u8; 32];
        let mut sender_data_secret = [0u8; 32];
        let mut encryption_key = [0u8; 32];

        hkdf.expand(b"NSC_EpochSecret", &mut epoch_secret).unwrap();
        hkdf.expand(b"NSC_SenderData", &mut sender_data_secret)
            .unwrap();
        hkdf.expand(b"NSC_EncryptionKey", &mut encryption_key)
            .unwrap();

        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            epoch: 0,
            epoch_secret,
            sender_data_secret,
            encryption_key,
            started_at,
            message_count: 0,
        }
    }

    /// Advance to next epoch
    pub fn advance(&self) -> Self {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, &self.epoch_secret);

        let mut new_epoch_secret = [0u8; 32];
        let mut sender_data_secret = [0u8; 32];
        let mut encryption_key = [0u8; 32];

        let epoch_bytes = (self.epoch + 1).to_be_bytes();
        hkdf.expand(&epoch_bytes, &mut new_epoch_secret).unwrap();
        hkdf.expand(b"NSC_SenderData", &mut sender_data_secret)
            .unwrap();
        hkdf.expand(b"NSC_EncryptionKey", &mut encryption_key)
            .unwrap();

        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            epoch: self.epoch + 1,
            epoch_secret: new_epoch_secret,
            sender_data_secret,
            encryption_key,
            started_at,
            message_count: 0,
        }
    }

    /// Check if epoch should rotate
    pub fn should_rotate(&self) -> bool {
        let time_exceeded = {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            now - self.started_at > KEY_ROTATION_TIME_THRESHOLD.as_millis() as u64
        };

        self.message_count > KEY_ROTATION_MESSAGE_THRESHOLD || time_exceeded
    }
    
    /// Encrypt a message using channel group key
    /// Returns nonce || ciphertext
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        
        // Generate random nonce (12 bytes for ChaCha20-Poly1305)
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt a message using channel group key
    /// Input format: nonce (12 bytes) || ciphertext
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted.len() < 12 {
            return Err("Encrypted data too short".to_string());
        }
        
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];
        
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed (authentication error): {}", e))
    }
}

// =============================================================================
// Sender Keys (for large groups > 100 members)
// =============================================================================

/// Sender key for large group messaging
/// Each sender maintains their own chain key that others use to derive message keys
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SenderKey {
    /// Sender's peer ID
    pub sender_id: PeerId,
    /// Current chain key
    pub chain_key: [u8; 32],
    /// Current iteration (message index)
    pub iteration: u32,
    /// Sender's signing public key (for verification)
    pub signing_key: [u8; 32],
    /// Distribution ID (changes when sender key is rotated)
    pub distribution_id: u32,
}

impl SenderKey {
    /// Create a new sender key for ourselves
    pub fn generate(sender_id: PeerId, signing_key: [u8; 32]) -> Self {
        let mut chain_key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut chain_key);
        
        Self {
            sender_id,
            chain_key,
            iteration: 0,
            signing_key,
            distribution_id: 0,
        }
    }
    
    /// Derive message key and advance chain
    pub fn derive_message_key(&mut self) -> MessageKey {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        let hkdf = Hkdf::<Sha256>::new(None, &self.chain_key);
        
        // Derive message key
        let mut message_key = [0u8; 32];
        let info = format!("SenderKey_Msg_{}", self.iteration);
        hkdf.expand(info.as_bytes(), &mut message_key).unwrap();
        
        // Advance chain key
        let mut new_chain_key = [0u8; 32];
        let chain_info = format!("SenderKey_Chain_{}", self.iteration);
        hkdf.expand(chain_info.as_bytes(), &mut new_chain_key).unwrap();
        self.chain_key = new_chain_key;
        
        self.iteration += 1;
        
        MessageKey {
            key: message_key,
            iteration: self.iteration - 1,
        }
    }
    
    /// Derive message key at specific iteration (for decryption)
    /// Returns None if iteration is in the past
    pub fn derive_at_iteration(&self, target_iteration: u32) -> Option<MessageKey> {
        if target_iteration < self.iteration {
            return None; // Cannot derive past keys
        }
        
        // Clone and advance to target
        let mut temp = self.clone();
        while temp.iteration < target_iteration {
            let _ = temp.derive_message_key();
        }
        
        if temp.iteration == target_iteration {
            Some(temp.derive_message_key())
        } else {
            None
        }
    }
    
    /// Check if sender key should be rotated
    pub fn should_rotate(&self) -> bool {
        self.iteration >= MAX_SENDER_KEY_CHAIN
    }
    
    /// Rotate sender key (creates a new chain)
    pub fn rotate(&mut self) {
        let mut new_chain_key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut new_chain_key);
        
        self.chain_key = new_chain_key;
        self.iteration = 0;
        self.distribution_id += 1;
    }
    
    /// Serialize for distribution to other members
    pub fn to_distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            sender_id: self.sender_id,
            chain_key: self.chain_key,
            iteration: self.iteration,
            signing_key: self.signing_key,
            distribution_id: self.distribution_id,
        }
    }
}

/// Message key derived from sender key
#[derive(Clone)]
pub struct MessageKey {
    pub key: [u8; 32],
    pub iteration: u32,
}

impl MessageKey {
    /// Encrypt message with this key
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        let mut result = Vec::with_capacity(4 + 12 + ciphertext.len());
        result.extend_from_slice(&self.iteration.to_be_bytes());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt message with this key
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted.len() < 16 {
            return Err("Encrypted data too short".to_string());
        }
        
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        
        // Skip iteration (4 bytes) - already extracted by caller
        let nonce = Nonce::from_slice(&encrypted[4..16]);
        let ciphertext = &encrypted[16..];
        
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))
    }
}

/// Sender key distribution message (sent to new members or when rotating)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SenderKeyDistribution {
    pub sender_id: PeerId,
    pub chain_key: [u8; 32],
    pub iteration: u32,
    pub signing_key: [u8; 32],
    pub distribution_id: u32,
}

impl SenderKeyDistribution {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(104);
        bytes.extend_from_slice(&self.sender_id.0);
        bytes.extend_from_slice(&self.chain_key);
        bytes.extend_from_slice(&self.iteration.to_be_bytes());
        bytes.extend_from_slice(&self.signing_key);
        bytes.extend_from_slice(&self.distribution_id.to_be_bytes());
        bytes
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 104 {
            return None;
        }
        
        let mut sender_id = [0u8; 32];
        sender_id.copy_from_slice(&bytes[0..32]);
        
        let mut chain_key = [0u8; 32];
        chain_key.copy_from_slice(&bytes[32..64]);
        
        let mut iteration_bytes = [0u8; 4];
        iteration_bytes.copy_from_slice(&bytes[64..68]);
        let iteration = u32::from_be_bytes(iteration_bytes);
        
        let mut signing_key = [0u8; 32];
        signing_key.copy_from_slice(&bytes[68..100]);
        
        let mut distribution_id_bytes = [0u8; 4];
        distribution_id_bytes.copy_from_slice(&bytes[100..104]);
        let distribution_id = u32::from_be_bytes(distribution_id_bytes);
        
        Some(Self {
            sender_id: PeerId(sender_id),
            chain_key,
            iteration,
            signing_key,
            distribution_id,
        })
    }
    
    /// Convert to a SenderKey for storing
    pub fn to_sender_key(&self) -> SenderKey {
        SenderKey {
            sender_id: self.sender_id,
            chain_key: self.chain_key,
            iteration: self.iteration,
            signing_key: self.signing_key,
            distribution_id: self.distribution_id,
        }
    }
}

/// Manages sender keys for a large group channel
pub struct SenderKeyStore {
    /// Our own sender key
    our_key: SenderKey,
    /// Sender keys from other members (peer_id -> sender_key)
    peer_keys: HashMap<PeerId, SenderKey>,
    /// Cached message keys for out-of-order decryption (sender_id || iteration -> key)
    cached_keys: HashMap<(PeerId, u32), MessageKey>,
    /// Maximum cached keys per sender
    max_cache_per_sender: usize,
}

impl SenderKeyStore {
    /// Create a new sender key store
    pub fn new(our_peer_id: PeerId, signing_key: [u8; 32]) -> Self {
        Self {
            our_key: SenderKey::generate(our_peer_id, signing_key),
            peer_keys: HashMap::new(),
            cached_keys: HashMap::new(),
            max_cache_per_sender: 100,
        }
    }
    
    /// Get our sender key distribution (for sending to others)
    pub fn our_distribution(&self) -> SenderKeyDistribution {
        self.our_key.to_distribution()
    }
    
    /// Encrypt a message using our sender key
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mk = self.our_key.derive_message_key();
        mk.encrypt(plaintext)
    }
    
    /// Decrypt a message from a peer
    pub fn decrypt(&mut self, sender_id: &PeerId, encrypted: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted.len() < 4 {
            return Err("Encrypted data too short".to_string());
        }
        
        // Extract iteration
        let mut iteration_bytes = [0u8; 4];
        iteration_bytes.copy_from_slice(&encrypted[0..4]);
        let iteration = u32::from_be_bytes(iteration_bytes);
        
        // Check cache first
        if let Some(mk) = self.cached_keys.get(&(*sender_id, iteration)) {
            return mk.decrypt(encrypted);
        }
        
        // Get peer's sender key
        let peer_key = self.peer_keys.get_mut(sender_id)
            .ok_or_else(|| format!("No sender key for peer {}", sender_id.short()))?;
        
        // Derive key at iteration
        if iteration < peer_key.iteration {
            return Err(format!("Message key already consumed (iteration {})", iteration));
        }
        
        // Advance and cache keys up to target
        while peer_key.iteration <= iteration {
            let mk = peer_key.derive_message_key();
            // Cache for potential out-of-order messages
            self.cached_keys.insert((*sender_id, mk.iteration), mk);
        }
        
        // Get the key we need
        let mk = self.cached_keys.get(&(*sender_id, iteration))
            .ok_or_else(|| "Failed to derive message key".to_string())?;
        
        let result = mk.decrypt(encrypted);
        
        // Remove used key
        self.cached_keys.remove(&(*sender_id, iteration));
        
        // Prune old cached keys for this sender
        self.prune_cached_keys(sender_id);
        
        result
    }
    
    /// Add or update a peer's sender key
    pub fn add_peer_key(&mut self, distribution: SenderKeyDistribution) {
        // Check if this is a newer distribution
        if let Some(existing) = self.peer_keys.get(&distribution.sender_id) {
            if distribution.distribution_id <= existing.distribution_id 
               && distribution.iteration <= existing.iteration {
                return; // Already have newer or same key
            }
        }
        
        // Clear cached keys for this sender if distribution changed
        if let Some(existing) = self.peer_keys.get(&distribution.sender_id) {
            if distribution.distribution_id != existing.distribution_id {
                self.cached_keys.retain(|(peer, _), _| *peer != distribution.sender_id);
            }
        }
        
        self.peer_keys.insert(distribution.sender_id, distribution.to_sender_key());
    }
    
    /// Check if we should rotate our sender key
    pub fn should_rotate(&self) -> bool {
        self.our_key.should_rotate()
    }
    
    /// Rotate our sender key
    pub fn rotate(&mut self) -> SenderKeyDistribution {
        self.our_key.rotate();
        self.our_key.to_distribution()
    }
    
    /// Prune old cached keys for a sender
    fn prune_cached_keys(&mut self, sender_id: &PeerId) {
        let keys_for_sender: Vec<_> = self.cached_keys.keys()
            .filter(|(peer, _)| peer == sender_id)
            .copied()
            .collect();
        
        if keys_for_sender.len() > self.max_cache_per_sender {
            // Remove oldest keys
            let mut sorted_keys = keys_for_sender;
            sorted_keys.sort_by_key(|(_, iter)| *iter);
            
            let to_remove = sorted_keys.len() - self.max_cache_per_sender;
            for key in sorted_keys.into_iter().take(to_remove) {
                self.cached_keys.remove(&key);
            }
        }
    }
    
    /// Get all peer IDs with sender keys
    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.peer_keys.keys().copied().collect()
    }
    
    /// Remove a peer's sender key
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peer_keys.remove(peer_id);
        self.cached_keys.retain(|(peer, _), _| peer != peer_id);
    }
}

// =============================================================================
// Channel State
// =============================================================================

/// Complete channel state
pub struct NaisSecureChannel {
    /// Channel metadata
    pub metadata: ChannelMetadata,
    /// Channel members
    members: HashMap<PeerId, ChannelMember>,
    /// Our peer ID
    local_peer_id: PeerId,
    /// Our identity key
    identity: Arc<IdentityKeyPair>,
    /// Current epoch secrets
    epoch_secrets: EpochSecrets,
    /// Message sequence tracker
    sequence_tracker: SequenceTracker,
    /// Our next sequence number
    next_sequence: u64,
    /// Offline message queue
    message_queue: MessageQueue,
    /// Membership event handlers
    membership_handlers: Vec<mpsc::Sender<MembershipEvent>>,
    /// Pending invites (peer -> inviter)
    pending_invites: HashMap<PeerId, PeerId>,
}

impl NaisSecureChannel {
    /// Create a new channel
    pub fn create(
        name: String,
        identity: Arc<IdentityKeyPair>,
        local_peer_id: PeerId,
    ) -> Self {
        let mut metadata = ChannelMetadata::new(name, local_peer_id);
        metadata.sign(&identity);

        // Generate initial epoch secrets
        let mut secret_bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let epoch_secrets = EpochSecrets::initial(&secret_bytes);

        let mut channel = Self {
            metadata,
            members: HashMap::new(),
            local_peer_id,
            identity,
            epoch_secrets,
            sequence_tracker: SequenceTracker::new(DEDUP_WINDOW_SIZE),
            next_sequence: 0,
            message_queue: MessageQueue::new(),
            membership_handlers: Vec::new(),
            pending_invites: HashMap::new(),
        };

        // Add ourselves as owner
        let local_identity_key = channel.identity.public_key().to_bytes();
        let mut local_member =
            ChannelMember::new(local_peer_id, "Me".to_string(), local_identity_key);
        local_member.role = MemberRole::Owner;
        channel.members.insert(local_peer_id, local_member);

        channel
    }

    /// Join an existing channel
    pub fn join(
        metadata: ChannelMetadata,
        epoch_secrets: EpochSecrets,
        identity: Arc<IdentityKeyPair>,
        local_peer_id: PeerId,
    ) -> Self {
        Self {
            metadata,
            members: HashMap::new(),
            local_peer_id,
            identity,
            epoch_secrets,
            sequence_tracker: SequenceTracker::new(DEDUP_WINDOW_SIZE),
            next_sequence: 0,
            message_queue: MessageQueue::new(),
            membership_handlers: Vec::new(),
            pending_invites: HashMap::new(),
        }
    }

    /// Get channel ID
    pub fn channel_id(&self) -> ChannelId {
        self.metadata.channel_id
    }

    /// Get channel name
    pub fn name(&self) -> &str {
        &self.metadata.name
    }

    /// Get channel topic
    pub fn topic(&self) -> &str {
        &self.metadata.topic
    }

    /// Check if we're a member
    pub fn is_member(&self) -> bool {
        self.members.contains_key(&self.local_peer_id)
    }

    /// Check if we're an admin
    pub fn is_admin(&self) -> bool {
        self.members
            .get(&self.local_peer_id)
            .map(|m| matches!(m.role, MemberRole::Owner | MemberRole::Admin))
            .unwrap_or(false)
    }

    /// Get member count
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Get list of members
    pub fn members(&self) -> impl Iterator<Item = &ChannelMember> {
        self.members.values()
    }

    /// Get specific member
    pub fn get_member(&self, peer_id: &PeerId) -> Option<&ChannelMember> {
        self.members.get(peer_id)
    }

    /// Add a member to the channel
    pub async fn add_member(&mut self, member: ChannelMember) -> ChannelResult<()> {
        // Check if already a member
        if self.members.contains_key(&member.peer_id) {
            return Err(ChannelError::MemberExists(member.peer_id.to_hex()));
        }

        // Check member limit
        if self.metadata.settings.max_members > 0
            && self.members.len() >= self.metadata.settings.max_members as usize
        {
            return Err(ChannelError::Unauthorized("Channel is full".into()));
        }

        let peer_id = member.peer_id;
        let invited_by = self.pending_invites.remove(&peer_id);

        self.members.insert(peer_id, member.clone());

        // Advance epoch on member join
        self.epoch_secrets = self.epoch_secrets.advance();

        // Notify handlers
        let event = MembershipEvent::Joined {
            member,
            invited_by,
        };
        self.notify_membership_event(event).await;

        Ok(())
    }

    /// Remove a member from the channel
    pub async fn remove_member(&mut self, peer_id: &PeerId, reason: LeaveReason) -> ChannelResult<()> {
        // Check if member exists
        if !self.members.contains_key(peer_id) {
            return Err(ChannelError::MemberNotFound(peer_id.to_hex()));
        }

        // Cannot remove owner
        if let Some(member) = self.members.get(peer_id) {
            if member.role == MemberRole::Owner {
                return Err(ChannelError::Unauthorized("Cannot remove channel owner".into()));
            }
        }

        self.members.remove(peer_id);

        // Advance epoch on member leave (forward secrecy)
        self.epoch_secrets = self.epoch_secrets.advance();

        // Notify handlers
        let event = MembershipEvent::Left {
            peer_id: *peer_id,
            reason,
        };
        self.notify_membership_event(event).await;

        Ok(())
    }

    /// Update member role
    pub async fn update_member_role(
        &mut self,
        peer_id: &PeerId,
        new_role: MemberRole,
    ) -> ChannelResult<()> {
        // Check authorization
        if !self.is_admin() {
            return Err(ChannelError::Unauthorized("Must be admin".into()));
        }

        let member = self
            .members
            .get_mut(peer_id)
            .ok_or_else(|| ChannelError::MemberNotFound(peer_id.to_hex()))?;

        // Cannot change owner's role
        if member.role == MemberRole::Owner {
            return Err(ChannelError::Unauthorized("Cannot change owner's role".into()));
        }

        let old_role = member.role;
        member.role = new_role;

        // Notify handlers
        let event = MembershipEvent::RoleChanged {
            peer_id: *peer_id,
            old_role,
            new_role,
            changed_by: self.local_peer_id,
        };
        self.notify_membership_event(event).await;

        Ok(())
    }

    /// Create an invite for a peer
    pub fn create_invite(&mut self, invitee: PeerId) -> ChannelResult<ChannelInvite> {
        // Check authorization
        if !self.is_admin() && !self.metadata.settings.members_can_invite {
            return Err(ChannelError::Unauthorized("Not authorized to invite".into()));
        }

        // Record pending invite
        self.pending_invites.insert(invitee, self.local_peer_id);

        Ok(ChannelInvite {
            channel_id: self.metadata.channel_id,
            channel_name: self.metadata.name.clone(),
            inviter: self.local_peer_id,
            invitee,
            metadata: self.metadata.clone(),
            epoch_secrets_encrypted: Vec::new(), // Would be encrypted to invitee's key
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        })
    }

    /// Update channel metadata
    pub fn update_metadata(&mut self, new_metadata: ChannelMetadata) -> ChannelResult<()> {
        // Verify update
        self.metadata.verify_update(&new_metadata)?;

        // Verify signature
        // Note: In production, verify against the signer's public key
        
        self.metadata = new_metadata;
        Ok(())
    }

    /// Process incoming message
    pub fn process_message(&mut self, envelope: &NscEnvelope) -> ChannelResult<Bytes> {
        let msg_id = MessageId::from_envelope(envelope);

        // Check for duplicate
        if self.sequence_tracker.is_duplicate(&msg_id) {
            return Err(ChannelError::DuplicateMessage(format!(
                "{}:{}",
                msg_id.sender.short(),
                msg_id.sequence
            )));
        }

        // Check message age
        if envelope.age_ms() > MAX_MESSAGE_AGE.as_millis() as u64 {
            return Err(ChannelError::MessageTooOld);
        }

        // Check sender is member
        let sender_id = PeerId(envelope.sender_id);
        if !self.members.contains_key(&sender_id) {
            return Err(ChannelError::NotMember);
        }

        // Record message
        self.sequence_tracker.record(msg_id);

        // Update member's last message time
        if let Some(member) = self.members.get_mut(&sender_id) {
            member.last_message_at = Some(envelope.timestamp);
        }

        // Decrypt payload (simplified - in production use session keys)
        // Here we just return the payload as-is since encryption is handled at session level
        Ok(envelope.payload.clone())
    }

    /// Create outgoing message envelope
    pub fn create_envelope(
        &mut self,
        message_type: MessageType,
        payload: Bytes,
    ) -> NscEnvelope {
        let sequence = self.next_sequence;
        self.next_sequence += 1;

        // Track epoch message count
        self.epoch_secrets.message_count += 1;

        // Check if epoch rotation needed
        if self.epoch_secrets.should_rotate() {
            self.epoch_secrets = self.epoch_secrets.advance();
        }

        let mut envelope = NscEnvelope::new(
            message_type,
            self.local_peer_id.0,
            self.metadata.channel_id.0,
            sequence,
            payload,
        );

        envelope.sign(&self.identity);
        envelope
    }

    /// Queue message for offline peer
    pub fn queue_message(&mut self, recipient: PeerId, envelope: NscEnvelope) {
        self.message_queue.enqueue(recipient, envelope);
    }

    /// Get queued messages for peer that came online
    pub fn drain_queued(&mut self, peer_id: &PeerId) -> Vec<QueuedMessage> {
        self.message_queue.get_queued(peer_id)
    }

    /// Register membership event handler
    pub fn on_membership_event(&mut self, handler: mpsc::Sender<MembershipEvent>) {
        self.membership_handlers.push(handler);
    }

    /// Notify membership event handlers
    async fn notify_membership_event(&self, event: MembershipEvent) {
        for handler in &self.membership_handlers {
            let _ = handler.send(event.clone()).await;
        }
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        self.epoch_secrets.epoch
    }

    /// Force epoch rotation
    pub fn rotate_epoch(&mut self) {
        self.epoch_secrets = self.epoch_secrets.advance();
    }

    /// Get online members
    pub fn online_members(&self) -> Vec<&ChannelMember> {
        self.members.values().filter(|m| m.online).collect()
    }

    /// Update member online status
    pub fn set_member_online(&mut self, peer_id: &PeerId, online: bool) {
        if let Some(member) = self.members.get_mut(peer_id) {
            member.online = online;
        }
    }
}

// =============================================================================
// Channel Invite
// =============================================================================

/// Invitation to join a channel
#[derive(Clone, Debug)]
pub struct ChannelInvite {
    /// Channel ID
    pub channel_id: ChannelId,
    /// Channel name
    pub channel_name: String,
    /// Who sent the invite
    pub inviter: PeerId,
    /// Who is being invited
    pub invitee: PeerId,
    /// Current channel metadata
    pub metadata: ChannelMetadata,
    /// Encrypted epoch secrets for invitee
    pub epoch_secrets_encrypted: Vec<u8>,
    /// When invite was created
    pub created_at: u64,
}

// =============================================================================
// Channel Manager
// =============================================================================

/// Manages multiple channels
pub struct ChannelManager {
    /// Active channels
    channels: Arc<RwLock<HashMap<ChannelId, NaisSecureChannel>>>,
    /// Our identity
    identity: Arc<IdentityKeyPair>,
    /// Our peer ID
    local_peer_id: PeerId,
    /// Pending invites
    pending_invites: Arc<RwLock<HashMap<ChannelId, ChannelInvite>>>,
}

impl ChannelManager {
    /// Create new channel manager
    pub fn new(identity: Arc<IdentityKeyPair>, local_peer_id: PeerId) -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            identity,
            local_peer_id,
            pending_invites: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create new channel manager with pre-initialized channels
    pub fn new_with_channels(
        identity: Arc<IdentityKeyPair>,
        local_peer_id: PeerId,
        channels: HashMap<ChannelId, NaisSecureChannel>,
    ) -> Self {
        Self {
            channels: Arc::new(RwLock::new(channels)),
            identity,
            local_peer_id,
            pending_invites: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new channel
    pub async fn create_channel(&self, name: String) -> ChannelResult<ChannelId> {
        let channel = NaisSecureChannel::create(name, self.identity.clone(), self.local_peer_id);
        let channel_id = channel.channel_id();

        self.channels.write().await.insert(channel_id, channel);
        Ok(channel_id)
    }

    /// Get channel by ID
    pub async fn get_channel(&self, channel_id: &ChannelId) -> Option<ChannelId> {
        if self.channels.read().await.contains_key(channel_id) {
            Some(*channel_id)
        } else {
            None
        }
    }

    /// List all channels
    pub async fn list_channels(&self) -> Vec<ChannelId> {
        self.channels.read().await.keys().copied().collect()
    }

    /// Leave a channel
    pub async fn leave_channel(&self, channel_id: &ChannelId) -> ChannelResult<()> {
        self.channels
            .write()
            .await
            .remove(channel_id)
            .ok_or_else(|| ChannelError::NotFound(channel_id.to_hex()))?;
        Ok(())
    }

    /// Process incoming invite
    pub async fn process_invite(&self, invite: ChannelInvite) {
        self.pending_invites
            .write()
            .await
            .insert(invite.channel_id, invite);
    }

    /// Accept an invite
    pub async fn accept_invite(&self, channel_id: &ChannelId) -> ChannelResult<()> {
        let invite = self
            .pending_invites
            .write()
            .await
            .remove(channel_id)
            .ok_or_else(|| ChannelError::NotFound(channel_id.to_hex()))?;

        // In production, decrypt epoch secrets from invite
        let mut secret_bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let epoch_secrets = EpochSecrets::initial(&secret_bytes);

        let channel = NaisSecureChannel::join(
            invite.metadata,
            epoch_secrets,
            self.identity.clone(),
            self.local_peer_id,
        );

        self.channels.write().await.insert(*channel_id, channel);
        Ok(())
    }

    /// Decline an invite
    pub async fn decline_invite(&self, channel_id: &ChannelId) {
        self.pending_invites.write().await.remove(channel_id);
    }

    /// Get pending invites
    pub async fn pending_invites(&self) -> Vec<ChannelInvite> {
        self.pending_invites.read().await.values().cloned().collect()
    }
    
    /// Encrypt a message for a specific channel
    pub async fn encrypt_for_channel(&self, channel_id: &ChannelId, plaintext: &[u8]) -> ChannelResult<Vec<u8>> {
        let channels = self.channels.read().await;
        let channel = channels.get(channel_id)
            .ok_or_else(|| ChannelError::NotFound(channel_id.to_hex()))?;
        
        // Log key fingerprint for debugging
        let key_fp = hex::encode(&channel.epoch_secrets.encryption_key[..4]);
        log::debug!(
            "[ENCRYPT_DEBUG] Encrypting for channel {}: epoch={}, key_fp={}, pt_len={}",
            &channel_id.to_hex()[..8],
            channel.epoch_secrets.epoch,
            key_fp,
            plaintext.len()
        );
        
        channel.epoch_secrets.encrypt(plaintext)
            .map_err(|e| ChannelError::InvalidMetadata(e))
    }
    
    /// Decrypt a message for a specific channel
    pub async fn decrypt_for_channel(&self, channel_id: &ChannelId, ciphertext: &[u8]) -> ChannelResult<Vec<u8>> {
        let channels = self.channels.read().await;
        let channel = channels.get(channel_id)
            .ok_or_else(|| ChannelError::NotFound(channel_id.to_hex()))?;
        
        // Log key fingerprint on decrypt attempt for debugging key mismatch issues
        let key_fp = hex::encode(&channel.epoch_secrets.encryption_key[..4]);
        
        match channel.epoch_secrets.decrypt(ciphertext) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => {
                log::warn!(
                    "[DECRYPT_DEBUG] Failed to decrypt for channel {}: epoch={}, key_fp={}, ct_len={}",
                    &channel_id.to_hex()[..8],
                    channel.epoch_secrets.epoch,
                    key_fp,
                    ciphertext.len()
                );
                Err(ChannelError::InvalidMetadata(e))
            }
        }
    }
    
    /// Get epoch secrets for a channel (to share with new members)
    pub async fn get_epoch_secrets(&self, channel_id: &ChannelId) -> Option<EpochSecrets> {
        let channels = self.channels.read().await;
        channels.get(channel_id).map(|c| c.epoch_secrets.clone())
    }
    
    /// Join a channel with provided epoch secrets (used when receiving Welcome message)
    pub async fn join_channel_with_secrets(
        &self,
        channel_id: &ChannelId,
        name: String,
        epoch_secrets: EpochSecrets,
    ) -> ChannelResult<()> {
        let new_key_fp = hex::encode(&epoch_secrets.encryption_key[..4]);
        
        // Check if we already have this channel
        if self.channels.read().await.contains_key(channel_id) {
            // Update existing channel's epoch secrets
            let mut channels = self.channels.write().await;
            if let Some(channel) = channels.get_mut(channel_id) {
                let old_key_fp = hex::encode(&channel.epoch_secrets.encryption_key[..4]);
                log::info!(
                    "[JOIN_SECRETS] Updating existing channel {}: old_epoch={} old_key_fp={} -> new_epoch={} new_key_fp={}",
                    &channel_id.to_hex()[..8],
                    channel.epoch_secrets.epoch,
                    old_key_fp,
                    epoch_secrets.epoch,
                    new_key_fp
                );
                channel.epoch_secrets = epoch_secrets;
            }
            return Ok(());
        }
        
        log::info!(
            "[JOIN_SECRETS] Creating new channel {}: epoch={} key_fp={}",
            &channel_id.to_hex()[..8],
            epoch_secrets.epoch,
            new_key_fp
        );
        
        // Create channel metadata
        let metadata = ChannelMetadata {
            channel_id: *channel_id,
            name,
            topic: String::new(),
            avatar: None,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            version: 1,
            creator: self.local_peer_id, // We're joining, not creating, but need a value
            admins: vec![],
            settings: ChannelSettings::default(),
            signature: [0u8; 64],
            previous_hash: None,
        };
        
        // Create the channel with the provided secrets
        let channel = NaisSecureChannel::join(
            metadata,
            epoch_secrets,
            self.identity.clone(),
            self.local_peer_id,
        );
        
        self.channels.write().await.insert(*channel_id, channel);
        Ok(())
    }
    
    /// Advance epoch for a channel (key rotation)
    /// Returns the new epoch secrets to send as a Commit message
    pub async fn advance_epoch(&self, channel_id: &ChannelId) -> ChannelResult<EpochSecrets> {
        let mut channels = self.channels.write().await;
        let channel = channels.get_mut(channel_id)
            .ok_or_else(|| ChannelError::NotFound(channel_id.to_hex()))?;
        
        // Advance to new epoch
        let new_secrets = channel.epoch_secrets.advance();
        channel.epoch_secrets = new_secrets.clone();
        
        log::info!("Advanced channel {} to epoch {}", channel_id.to_hex(), new_secrets.epoch);
        Ok(new_secrets)
    }
    
    /// Process a Commit message (epoch advancement from another member)
    pub async fn process_commit(&self, channel_id: &ChannelId, new_epoch_secrets: EpochSecrets) -> ChannelResult<()> {
        let mut channels = self.channels.write().await;
        let channel = channels.get_mut(channel_id)
            .ok_or_else(|| ChannelError::NotFound(channel_id.to_hex()))?;
        
        // Only accept if epoch is newer
        if new_epoch_secrets.epoch <= channel.epoch_secrets.epoch {
            log::warn!("Received stale Commit: got epoch {}, have epoch {}", 
                new_epoch_secrets.epoch, channel.epoch_secrets.epoch);
            return Err(ChannelError::StaleVersion { 
                expected: channel.epoch_secrets.epoch + 1, 
                got: new_epoch_secrets.epoch 
            });
        }
        
        channel.epoch_secrets = new_epoch_secrets;
        log::info!("Applied Commit, now at epoch {}", channel.epoch_secrets.epoch);
        Ok(())
    }
    
    /// Check if any channel needs key rotation
    pub async fn check_rotation_needed(&self) -> Vec<ChannelId> {
        let channels = self.channels.read().await;
        channels.iter()
            .filter(|(_, ch)| ch.epoch_secrets.should_rotate())
            .map(|(id, _)| *id)
            .collect()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identity() -> (Arc<IdentityKeyPair>, PeerId) {
        let identity = Arc::new(IdentityKeyPair::generate());
        let peer_id = PeerId::from_public_key(&identity.public_key().to_bytes());
        (identity, peer_id)
    }

    #[test]
    fn test_channel_id_creation() {
        let peer_id = PeerId([1u8; 32]);
        let id1 = ChannelId::from_creation(&peer_id, "test", 12345);
        let id2 = ChannelId::from_creation(&peer_id, "test", 12345);
        let id3 = ChannelId::from_creation(&peer_id, "test2", 12345);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_metadata_signing() {
        let (identity, peer_id) = create_test_identity();
        let mut metadata = ChannelMetadata::new("Test Channel".into(), peer_id);
        metadata.sign(&identity);

        assert!(metadata.verify(&identity.public_key().to_bytes()));

        // Tamper and verify fails
        metadata.name = "Tampered".into();
        assert!(!metadata.verify(&identity.public_key().to_bytes()));
    }

    #[test]
    fn test_metadata_chain() {
        let (identity, peer_id) = create_test_identity();
        let mut metadata = ChannelMetadata::new("Test".into(), peer_id);
        metadata.sign(&identity);

        let updated = metadata.update().topic("New topic".into()).build(&identity);

        assert_eq!(updated.version, 2);
        assert_eq!(updated.previous_hash, Some(metadata.hash()));
        assert!(metadata.verify_update(&updated).is_ok());
    }

    #[test]
    fn test_sequence_tracker() {
        let mut tracker = SequenceTracker::new(100);
        let sender = PeerId([1u8; 32]);

        let msg1 = MessageId::new(sender, 1);
        let msg2 = MessageId::new(sender, 2);

        assert!(!tracker.is_duplicate(&msg1));
        tracker.record(msg1);
        assert!(tracker.is_duplicate(&msg1));

        assert_eq!(tracker.last_sequence(&sender), Some(1));

        tracker.record(msg2);
        assert_eq!(tracker.last_sequence(&sender), Some(2));
    }

    #[test]
    fn test_message_queue() {
        let mut queue = MessageQueue::new();
        let peer = PeerId([1u8; 32]);

        let envelope = NscEnvelope::new(
            MessageType::ChannelMessage,
            [0u8; 32],
            [0u8; 32],
            1,
            Bytes::from("test"),
        );

        assert!(queue.enqueue(peer, envelope.clone()));
        assert_eq!(queue.queue_size(&peer), 1);

        let messages = queue.get_queued(&peer);
        assert_eq!(messages.len(), 1);
        assert_eq!(queue.queue_size(&peer), 0);
    }

    #[test]
    fn test_epoch_secrets() {
        let secret = [42u8; 32];
        let epoch0 = EpochSecrets::initial(&secret);

        assert_eq!(epoch0.epoch, 0);
        assert_eq!(epoch0.message_count, 0);

        let epoch1 = epoch0.advance();
        assert_eq!(epoch1.epoch, 1);

        // Secrets should be different
        assert_ne!(epoch0.epoch_secret, epoch1.epoch_secret);
        assert_ne!(epoch0.encryption_key, epoch1.encryption_key);
    }

    #[test]
    fn test_channel_creation() {
        let (identity, peer_id) = create_test_identity();
        let channel =
            NaisSecureChannel::create("Test Channel".into(), identity, peer_id);

        assert_eq!(channel.name(), "Test Channel");
        assert!(channel.is_member());
        assert!(channel.is_admin());
        assert_eq!(channel.member_count(), 1);
    }

    #[tokio::test]
    async fn test_membership() {
        let (identity1, peer_id1) = create_test_identity();
        let (identity2, peer_id2) = create_test_identity();

        let mut channel =
            NaisSecureChannel::create("Test".into(), identity1.clone(), peer_id1);

        // Add member
        let member = ChannelMember::new(
            peer_id2,
            "User2".into(),
            identity2.public_key().to_bytes(),
        );
        channel.add_member(member).await.unwrap();

        assert_eq!(channel.member_count(), 2);
        assert!(channel.get_member(&peer_id2).is_some());

        // Remove member
        channel
            .remove_member(&peer_id2, LeaveReason::Voluntary)
            .await
            .unwrap();
        assert_eq!(channel.member_count(), 1);
    }

    #[tokio::test]
    async fn test_channel_manager() {
        let (identity, peer_id) = create_test_identity();
        let manager = ChannelManager::new(identity, peer_id);

        let channel_id = manager.create_channel("Test".into()).await.unwrap();
        assert!(manager.get_channel(&channel_id).await.is_some());

        let channels = manager.list_channels().await;
        assert_eq!(channels.len(), 1);

        manager.leave_channel(&channel_id).await.unwrap();
        assert!(manager.get_channel(&channel_id).await.is_none());
    }

    #[test]
    fn test_retention_policy_default() {
        let policy = RetentionPolicy::default();
        assert!(matches!(policy, RetentionPolicy::Forever));
    }

    #[test]
    fn test_channel_settings_default() {
        let settings = ChannelSettings::default();
        assert!(!settings.discoverable);
        assert!(settings.invite_only);
        assert!(settings.members_can_invite);
    }
    
    #[test]
    fn test_epoch_secrets_encryption() {
        // Create epoch secrets from a test shared secret
        let mut shared_secret = [0u8; 32];
        for (i, b) in shared_secret.iter_mut().enumerate() {
            *b = i as u8;
        }
        let epoch = EpochSecrets::initial(&shared_secret);
        
        // Test encryption and decryption
        let plaintext = b"Hello, secure channel!";
        let encrypted = epoch.encrypt(plaintext).expect("encryption should work");
        
        // Encrypted should be longer (nonce + ciphertext + auth tag)
        assert!(encrypted.len() > plaintext.len());
        // Should have 12-byte nonce prefix
        assert!(encrypted.len() >= 12);
        
        // Decrypt
        let decrypted = epoch.decrypt(&encrypted).expect("decryption should work");
        assert_eq!(decrypted, plaintext);
        
        // Wrong key should fail
        let other_secret = [99u8; 32];
        let other_epoch = EpochSecrets::initial(&other_secret);
        assert!(other_epoch.decrypt(&encrypted).is_err());
    }
    
    #[test]
    fn test_epoch_secrets_key_rotation() {
        let shared_secret = [42u8; 32];
        let epoch0 = EpochSecrets::initial(&shared_secret);
        assert_eq!(epoch0.epoch, 0);
        
        let epoch1 = epoch0.advance();
        assert_eq!(epoch1.epoch, 1);
        
        // Different epochs should have different encryption keys
        assert_ne!(epoch0.encryption_key, epoch1.encryption_key);
        
        // Message encrypted with epoch0 should not decrypt with epoch1
        let plaintext = b"Secret message";
        let encrypted = epoch0.encrypt(plaintext).unwrap();
        assert!(epoch1.decrypt(&encrypted).is_err());
    }
}
