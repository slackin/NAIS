//! Nais Secure Channels - Message Router
//!
//! Implements intelligent message routing for P2P and relay delivery:
//! - Direct peer connections with connection pooling
//! - Hub relay for peers behind symmetric NAT
//! - Peer relay for mesh networking
//! - Routing table with path selection and latency tracking
//! - Partial connectivity handling with fallback
//! - Redundant delivery for reliability
//! - Routing announcements for topology discovery

use bytes::Bytes;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

use crate::nsc_crypto::{IdentityKeyPair, IdentityPublicKey};
use crate::nsc_nat::NatType;
use crate::nsc_transport::{
    FederationHub, MessageType, NscEnvelope, PeerId, TransportError,
};

// =============================================================================
// Error Types
// =============================================================================

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("No route to peer: {0}")]
    NoRoute(String),

    #[error("All paths failed for peer: {0}")]
    AllPathsFailed(String),

    #[error("Delivery timeout")]
    Timeout,

    #[error("Transport error: {0}")]
    TransportError(#[from] TransportError),

    #[error("Message queued for offline peer")]
    Queued,

    #[error("Peer unreachable: {0}")]
    PeerUnreachable(String),

    #[error("Hub relay failed: {0}")]
    HubRelayFailed(String),

    #[error("Rate limited")]
    RateLimited,
}

pub type RouterResult<T> = Result<T, RouterError>;

// =============================================================================
// Constants
// =============================================================================

/// Maximum routing table entries
pub const MAX_ROUTING_ENTRIES: usize = 10000;

/// Routing entry expiration time
pub const ROUTING_ENTRY_TTL: Duration = Duration::from_secs(300);

/// Maximum message queue per peer
pub const MAX_QUEUED_PER_PEER: usize = 100;

/// Default redundancy factor
pub const DEFAULT_REDUNDANCY: u8 = 2;

/// Routing announcement interval
pub const ROUTING_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(60);

/// Primary path timeout before trying backup
pub const PRIMARY_PATH_TIMEOUT: Duration = Duration::from_secs(5);

/// Deduplication window
pub const DEDUP_WINDOW: Duration = Duration::from_secs(60);

/// Maximum dedup entries
pub const MAX_DEDUP_ENTRIES: usize = 10000;

// =============================================================================
// Hub Identifier
// =============================================================================

/// Unique identifier for federation hubs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HubId(pub [u8; 32]);

impl HubId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_address(address: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"HUB_ID");
        hasher.update(address.as_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        Self(id)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

// =============================================================================
// Path Types
// =============================================================================

/// Type of path to a peer
#[derive(Clone, Debug, PartialEq)]
pub enum PathType {
    /// Direct P2P connection
    Direct,
    /// Via federation hub
    HubRelay { hub_id: HubId },
    /// Via another peer (mesh relay)
    PeerRelay { relay_peer: PeerId },
    /// Multiple paths available
    MultiPath { paths: Vec<PathType> },
}

impl PathType {
    /// Get priority (lower is better)
    pub fn priority(&self) -> u8 {
        match self {
            PathType::Direct => 0,
            PathType::PeerRelay { .. } => 1,
            PathType::HubRelay { .. } => 2,
            PathType::MultiPath { .. } => 0, // Best available
        }
    }
}

/// Next hop for routing
#[derive(Clone, Debug, PartialEq)]
pub struct NextHop {
    /// Peer to send to (either destination or relay)
    pub peer_id: PeerId,
    /// If this is a relay hop
    pub is_relay: bool,
    /// Final destination (for relay)
    pub final_destination: Option<PeerId>,
    /// Hub to use (for hub relay)
    pub hub_id: Option<HubId>,
}

// =============================================================================
// Routing Table Entry
// =============================================================================

/// Entry in the routing table
#[derive(Clone, Debug, PartialEq)]
pub struct RoutingEntry {
    /// Destination peer
    pub peer_id: PeerId,
    /// Best path type
    pub path_type: PathType,
    /// Latency estimate (milliseconds)
    pub latency_ms: u32,
    /// Reliability score (0.0 - 1.0)
    pub reliability: f32,
    /// Last successful delivery
    pub last_success: Option<Instant>,
    /// Last failure
    pub last_failure: Option<Instant>,
    /// Consecutive successes
    pub success_count: u32,
    /// Consecutive failures
    pub failure_count: u32,
    /// Next hops for this destination
    pub next_hops: Vec<NextHop>,
    /// When this entry was created
    pub created_at: Instant,
    /// When this entry was last updated
    pub updated_at: Instant,
    /// Direct socket address (if known)
    pub direct_addr: Option<SocketAddr>,
}

impl RoutingEntry {
    /// Create a new direct routing entry
    pub fn direct(peer_id: PeerId, addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            path_type: PathType::Direct,
            latency_ms: 0,
            reliability: 1.0,
            last_success: None,
            last_failure: None,
            success_count: 0,
            failure_count: 0,
            next_hops: vec![NextHop {
                peer_id,
                is_relay: false,
                final_destination: None,
                hub_id: None,
            }],
            created_at: now,
            updated_at: now,
            direct_addr: Some(addr),
        }
    }

    /// Create a hub relay entry
    pub fn hub_relay(peer_id: PeerId, hub_id: HubId) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            path_type: PathType::HubRelay {
                hub_id: hub_id.clone(),
            },
            latency_ms: 100, // Default estimate
            reliability: 0.9,
            last_success: None,
            last_failure: None,
            success_count: 0,
            failure_count: 0,
            next_hops: vec![NextHop {
                peer_id,
                is_relay: true,
                final_destination: Some(peer_id),
                hub_id: Some(hub_id),
            }],
            created_at: now,
            updated_at: now,
            direct_addr: None,
        }
    }

    /// Create a peer relay entry
    pub fn peer_relay(peer_id: PeerId, relay_peer: PeerId) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            path_type: PathType::PeerRelay { relay_peer },
            latency_ms: 50, // Default estimate
            reliability: 0.8,
            last_success: None,
            last_failure: None,
            success_count: 0,
            failure_count: 0,
            next_hops: vec![NextHop {
                peer_id: relay_peer,
                is_relay: true,
                final_destination: Some(peer_id),
                hub_id: None,
            }],
            created_at: now,
            updated_at: now,
            direct_addr: None,
        }
    }

    /// Update entry on successful delivery
    pub fn record_success(&mut self, latency_ms: u32) {
        self.last_success = Some(Instant::now());
        self.success_count += 1;
        self.failure_count = 0;
        self.updated_at = Instant::now();

        // Exponential moving average for latency
        self.latency_ms = ((self.latency_ms as f32 * 0.7) + (latency_ms as f32 * 0.3)) as u32;

        // Update reliability
        self.reliability = self.reliability * 0.95 + 0.05;
        self.reliability = self.reliability.min(1.0);
    }

    /// Update entry on failed delivery
    pub fn record_failure(&mut self) {
        self.last_failure = Some(Instant::now());
        self.failure_count += 1;
        self.success_count = 0;
        self.updated_at = Instant::now();

        // Decay reliability
        self.reliability = self.reliability * 0.8;
        self.reliability = self.reliability.max(0.0);
    }

    /// Check if entry is stale
    pub fn is_stale(&self) -> bool {
        self.updated_at.elapsed() > ROUTING_ENTRY_TTL
    }

    /// Calculate route score (lower is better)
    pub fn score(&self) -> u32 {
        let latency_score = self.latency_ms;
        let reliability_score = ((1.0 - self.reliability) * 100.0) as u32;
        let path_score = self.path_type.priority() as u32 * 50;
        latency_score + reliability_score + path_score
    }
}

// =============================================================================
// Routing Table
// =============================================================================

/// Routing table for all known peers
pub struct RoutingTable {
    /// Entries by peer ID
    entries: HashMap<PeerId, RoutingEntry>,
    /// Peers by hub (for hub announcements)
    peers_by_hub: HashMap<HubId, HashSet<PeerId>>,
    /// Our local peer ID
    local_peer_id: PeerId,
}

impl RoutingTable {
    /// Create new routing table
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            entries: HashMap::new(),
            peers_by_hub: HashMap::new(),
            local_peer_id,
        }
    }

    /// Add or update a routing entry
    pub fn upsert(&mut self, entry: RoutingEntry) {
        // Track hub membership
        if let PathType::HubRelay { hub_id } = &entry.path_type {
            self.peers_by_hub
                .entry(*hub_id)
                .or_default()
                .insert(entry.peer_id);
        }

        // Don't add route to ourselves
        if entry.peer_id == self.local_peer_id {
            return;
        }

        // Update or insert
        if let Some(existing) = self.entries.get_mut(&entry.peer_id) {
            // Keep the better route
            if entry.score() < existing.score() {
                *existing = entry;
            } else {
                existing.updated_at = Instant::now();
            }
        } else {
            // Check size limit
            if self.entries.len() >= MAX_ROUTING_ENTRIES {
                self.evict_oldest();
            }
            self.entries.insert(entry.peer_id, entry);
        }
    }

    /// Get route for a peer
    pub fn get(&self, peer_id: &PeerId) -> Option<&RoutingEntry> {
        self.entries.get(peer_id)
    }

    /// Get mutable route for a peer
    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut RoutingEntry> {
        self.entries.get_mut(peer_id)
    }

    /// Remove a peer from the routing table
    pub fn remove(&mut self, peer_id: &PeerId) {
        if let Some(entry) = self.entries.remove(peer_id) {
            if let PathType::HubRelay { hub_id } = &entry.path_type {
                if let Some(peers) = self.peers_by_hub.get_mut(hub_id) {
                    peers.remove(peer_id);
                }
            }
        }
    }

    /// Get all direct peers
    pub fn direct_peers(&self) -> Vec<PeerId> {
        self.entries
            .iter()
            .filter(|(_, e)| matches!(e.path_type, PathType::Direct))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get all peers reachable via hub
    pub fn hub_peers(&self, hub_id: &HubId) -> Vec<PeerId> {
        self.peers_by_hub
            .get(hub_id)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get best route to peer
    pub fn best_route(&self, peer_id: &PeerId) -> Option<&RoutingEntry> {
        self.entries.get(peer_id)
    }

    /// Get all routes (for redundant delivery)
    pub fn all_routes(&self, peer_id: &PeerId) -> Vec<&RoutingEntry> {
        // In a real implementation, we'd track multiple routes per peer
        self.entries.get(peer_id).into_iter().collect()
    }

    /// Clean up stale entries
    pub fn cleanup_stale(&mut self) {
        let stale: Vec<PeerId> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_stale())
            .map(|(id, _)| *id)
            .collect();

        for id in stale {
            self.remove(&id);
        }
    }

    /// Evict oldest entry
    fn evict_oldest(&mut self) {
        if let Some((oldest_id, _)) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.updated_at)
            .map(|(id, e)| (*id, e.updated_at))
        {
            self.remove(&oldest_id);
        }
    }

    /// Get entry count
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// =============================================================================
// Queued Message
// =============================================================================

/// A message queued for later delivery
#[derive(Clone)]
pub struct QueuedMessage {
    /// Target peer
    pub target: PeerId,
    /// Message envelope
    pub envelope: NscEnvelope,
    /// When queued
    pub queued_at: Instant,
    /// Delivery attempts
    pub attempts: u32,
    /// Maximum attempts
    pub max_attempts: u32,
    /// Priority (higher = more important)
    pub priority: u8,
}

impl QueuedMessage {
    pub fn new(target: PeerId, envelope: NscEnvelope) -> Self {
        Self {
            target,
            envelope,
            queued_at: Instant::now(),
            attempts: 0,
            max_attempts: 5,
            priority: 0,
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.queued_at.elapsed() > max_age
    }

    pub fn should_retry(&self) -> bool {
        self.attempts < self.max_attempts
    }
}

// =============================================================================
// Partial Connectivity Manager
// =============================================================================

/// Manages connectivity state and message queuing for offline peers
pub struct PartialConnectivityManager {
    /// Peers we can reach directly
    reachable: HashSet<PeerId>,
    /// Peers we can only reach via relay
    relay_only: HashSet<PeerId>,
    /// Peers currently unreachable
    unreachable: HashSet<PeerId>,
    /// Message queue for unreachable peers
    pending_messages: HashMap<PeerId, VecDeque<QueuedMessage>>,
    /// Maximum queue size per peer
    max_queue_per_peer: usize,
}

impl PartialConnectivityManager {
    /// Create new manager
    pub fn new() -> Self {
        Self {
            reachable: HashSet::new(),
            relay_only: HashSet::new(),
            unreachable: HashSet::new(),
            pending_messages: HashMap::new(),
            max_queue_per_peer: MAX_QUEUED_PER_PEER,
        }
    }

    /// Mark peer as directly reachable
    pub fn mark_reachable(&mut self, peer_id: PeerId) {
        self.reachable.insert(peer_id);
        self.relay_only.remove(&peer_id);
        self.unreachable.remove(&peer_id);
    }

    /// Mark peer as relay-only
    pub fn mark_relay_only(&mut self, peer_id: PeerId) {
        self.relay_only.insert(peer_id);
        self.reachable.remove(&peer_id);
        self.unreachable.remove(&peer_id);
    }

    /// Mark peer as unreachable
    pub fn mark_unreachable(&mut self, peer_id: PeerId) {
        self.unreachable.insert(peer_id);
        self.reachable.remove(&peer_id);
        self.relay_only.remove(&peer_id);
    }

    /// Check if peer is reachable (directly or via relay)
    pub fn is_reachable(&self, peer_id: &PeerId) -> bool {
        self.reachable.contains(peer_id) || self.relay_only.contains(peer_id)
    }

    /// Check if peer is directly reachable
    pub fn is_direct(&self, peer_id: &PeerId) -> bool {
        self.reachable.contains(peer_id)
    }

    /// Check if peer is relay-only
    pub fn is_relay_only(&self, peer_id: &PeerId) -> bool {
        self.relay_only.contains(peer_id)
    }

    /// Check if peer is unreachable
    pub fn is_unreachable(&self, peer_id: &PeerId) -> bool {
        self.unreachable.contains(peer_id)
    }

    /// Queue a message for an unreachable peer
    pub fn queue_message(&mut self, peer_id: PeerId, envelope: NscEnvelope) {
        let queue = self
            .pending_messages
            .entry(peer_id)
            .or_insert_with(VecDeque::new);

        // Enforce queue size limit
        while queue.len() >= self.max_queue_per_peer {
            queue.pop_front();
        }

        queue.push_back(QueuedMessage::new(peer_id, envelope));
    }

    /// Get queued messages for a peer (when they become reachable)
    pub fn take_queued(&mut self, peer_id: &PeerId) -> Vec<QueuedMessage> {
        self.pending_messages
            .remove(peer_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    /// Check if there are queued messages
    pub fn has_queued(&self, peer_id: &PeerId) -> bool {
        self.pending_messages
            .get(peer_id)
            .map(|q| !q.is_empty())
            .unwrap_or(false)
    }

    /// Clear expired messages
    pub fn clear_expired(&mut self, max_age: Duration) {
        for queue in self.pending_messages.values_mut() {
            queue.retain(|msg| !msg.is_expired(max_age));
        }
        // Remove empty queues
        self.pending_messages.retain(|_, q| !q.is_empty());
    }

    /// Get total queued message count
    pub fn total_queued(&self) -> usize {
        self.pending_messages.values().map(|q| q.len()).sum()
    }
}

impl Default for PartialConnectivityManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Delivery Result
// =============================================================================

/// Result of message delivery attempt
#[derive(Clone, Debug)]
pub enum DeliveryResult {
    /// Delivered successfully
    Delivered {
        /// Path used
        path: PathType,
        /// Latency in milliseconds
        latency_ms: u32,
    },
    /// Queued for later delivery
    Queued,
    /// Delivery failed
    Failed {
        /// Error reason
        reason: String,
    },
    /// Partially delivered (some paths succeeded)
    Partial {
        /// Successful paths
        successes: Vec<PathType>,
        /// Failed paths  
        failures: Vec<(PathType, String)>,
    },
}

// =============================================================================
// Redundant Delivery
// =============================================================================

/// Configuration for redundant delivery
pub struct RedundantDeliveryConfig {
    /// Number of redundant paths to use
    pub redundancy_factor: u8,
    /// Timeout for primary path before using backup
    pub primary_timeout: Duration,
    /// Maximum total wait time
    pub max_wait: Duration,
}

impl Default for RedundantDeliveryConfig {
    fn default() -> Self {
        Self {
            redundancy_factor: DEFAULT_REDUNDANCY,
            primary_timeout: PRIMARY_PATH_TIMEOUT,
            max_wait: Duration::from_secs(30),
        }
    }
}

/// Manages redundant delivery across multiple paths
pub struct RedundantDelivery {
    config: RedundantDeliveryConfig,
}

impl RedundantDelivery {
    pub fn new(config: RedundantDeliveryConfig) -> Self {
        Self { config }
    }

    /// Select diverse paths for redundant delivery
    pub fn select_diverse_paths<'a>(
        &self,
        routes: &'a [&RoutingEntry],
        count: u8,
    ) -> Vec<&'a RoutingEntry> {
        if routes.is_empty() {
            return Vec::new();
        }

        let mut selected = Vec::new();
        let mut used_types = HashSet::new();

        // First, get one of each path type
        for route in routes {
            let type_key = match &route.path_type {
                PathType::Direct => "direct",
                PathType::HubRelay { .. } => "hub",
                PathType::PeerRelay { .. } => "peer",
                PathType::MultiPath { .. } => "multi",
            };

            if !used_types.contains(type_key) && selected.len() < count as usize {
                selected.push(*route);
                used_types.insert(type_key);
            }
        }

        // Fill remaining slots with best scoring routes
        let remaining = count as usize - selected.len();
        if remaining > 0 {
            let mut sorted: Vec<_> = routes
                .iter()
                .filter(|r| !selected.contains(r))
                .collect();
            sorted.sort_by_key(|r| r.score());
            
            for route in sorted.into_iter().take(remaining) {
                selected.push(route);
            }
        }

        selected
    }
}

impl Default for RedundantDelivery {
    fn default() -> Self {
        Self::new(RedundantDeliveryConfig::default())
    }
}

// =============================================================================
// Message Deduplication
// =============================================================================

/// Message identifier for deduplication
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MessageId {
    /// Sender peer ID
    pub sender: PeerId,
    /// Channel ID
    pub channel_id: [u8; 32],
    /// Sequence number
    pub sequence: u64,
}

impl MessageId {
    pub fn from_envelope(envelope: &NscEnvelope) -> Self {
        Self {
            sender: PeerId(envelope.sender_id),
            channel_id: envelope.channel_id,
            sequence: envelope.sequence_number,
        }
    }
}

/// Deduplication cache
pub struct DeduplicationCache {
    /// Seen message IDs with timestamp
    seen: HashMap<MessageId, Instant>,
    /// Maximum entries
    max_entries: usize,
    /// Entry TTL
    ttl: Duration,
}

impl DeduplicationCache {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            max_entries: MAX_DEDUP_ENTRIES,
            ttl: DEDUP_WINDOW,
        }
    }

    /// Check if message was already seen
    pub fn is_duplicate(&self, id: &MessageId) -> bool {
        if let Some(seen_at) = self.seen.get(id) {
            seen_at.elapsed() < self.ttl
        } else {
            false
        }
    }

    /// Mark message as seen
    pub fn mark_seen(&mut self, id: MessageId) {
        // Cleanup if at capacity
        if self.seen.len() >= self.max_entries {
            self.cleanup();
        }
        self.seen.insert(id, Instant::now());
    }

    /// Remove expired entries
    pub fn cleanup(&mut self) {
        self.seen.retain(|_, seen_at| seen_at.elapsed() < self.ttl);
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for DeduplicationCache {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Routing Announcement
// =============================================================================

/// Announcement of routing capabilities
#[derive(Clone, Debug)]
pub struct RoutingAnnouncement {
    /// Our peer ID
    pub peer_id: PeerId,
    /// Our identity public key
    pub identity_key: [u8; 32],
    /// Direct peers we can reach
    pub direct_peers: Vec<PeerId>,
    /// Hub connections we have
    pub hub_connections: Vec<HubId>,
    /// Our NAT type
    pub nat_type: NatType,
    /// IPv6 availability
    pub ipv6_available: bool,
    /// Timestamp
    pub timestamp: u64,
    /// Signature
    pub signature: [u8; 64],
}

impl RoutingAnnouncement {
    /// Create a new announcement
    pub fn new(
        identity: &IdentityKeyPair,
        direct_peers: Vec<PeerId>,
        hub_connections: Vec<HubId>,
        nat_type: NatType,
        ipv6_available: bool,
    ) -> Self {
        let peer_id = PeerId::from_public_key(&identity.public_key().to_bytes());
        let identity_key = identity.public_key().to_bytes();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut announcement = Self {
            peer_id,
            identity_key,
            direct_peers,
            hub_connections,
            nat_type,
            ipv6_available,
            timestamp,
            signature: [0u8; 64],
        };

        announcement.sign(identity);
        announcement
    }

    /// Sign the announcement
    fn sign(&mut self, identity: &IdentityKeyPair) {
        let data = self.to_signing_data();
        self.signature = identity.sign(&data);
    }

    /// Get data for signing
    fn to_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(256);
        data.extend_from_slice(b"ROUTING_ANNOUNCEMENT_v1");
        data.extend_from_slice(&self.peer_id.0);
        data.extend_from_slice(&self.identity_key);
        data.extend_from_slice(&(self.direct_peers.len() as u32).to_be_bytes());
        for peer in &self.direct_peers {
            data.extend_from_slice(&peer.0);
        }
        data.extend_from_slice(&(self.hub_connections.len() as u32).to_be_bytes());
        for hub in &self.hub_connections {
            data.extend_from_slice(&hub.0);
        }
        data.push(self.nat_type as u8);
        data.push(if self.ipv6_available { 1 } else { 0 });
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data
    }

    /// Verify the announcement signature
    pub fn verify(&self) -> bool {
        if let Ok(public_key) = IdentityPublicKey::from_bytes(&self.identity_key) {
            let data = self.to_signing_data();
            public_key.verify(&data, &self.signature).is_ok()
        } else {
            false
        }
    }

    /// Check if announcement is fresh
    pub fn is_fresh(&self, max_age_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.timestamp) < max_age_secs
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(&self.peer_id.0);
        bytes.extend_from_slice(&self.identity_key);
        bytes.extend_from_slice(&(self.direct_peers.len() as u16).to_be_bytes());
        for peer in &self.direct_peers {
            bytes.extend_from_slice(&peer.0);
        }
        bytes.extend_from_slice(&(self.hub_connections.len() as u16).to_be_bytes());
        for hub in &self.hub_connections {
            bytes.extend_from_slice(&hub.0);
        }
        bytes.push(self.nat_type as u8);
        bytes.push(if self.ipv6_available { 1 } else { 0 });
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 104 {
            return None;
        }

        let mut offset = 0;

        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let direct_count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        if bytes.len() < offset + direct_count * 32 {
            return None;
        }

        let mut direct_peers = Vec::with_capacity(direct_count);
        for _ in 0..direct_count {
            let mut peer = [0u8; 32];
            peer.copy_from_slice(&bytes[offset..offset + 32]);
            direct_peers.push(PeerId(peer));
            offset += 32;
        }

        if bytes.len() < offset + 2 {
            return None;
        }

        let hub_count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        if bytes.len() < offset + hub_count * 32 + 10 + 64 {
            return None;
        }

        let mut hub_connections = Vec::with_capacity(hub_count);
        for _ in 0..hub_count {
            let mut hub = [0u8; 32];
            hub.copy_from_slice(&bytes[offset..offset + 32]);
            hub_connections.push(HubId(hub));
            offset += 32;
        }

        let nat_type = match bytes[offset] {
            0 => NatType::None,
            1 => NatType::FullCone,
            2 => NatType::AddressRestricted,
            3 => NatType::PortRestricted,
            4 => NatType::Symmetric,
            _ => NatType::Unknown,
        };
        offset += 1;

        let ipv6_available = bytes[offset] != 0;
        offset += 1;

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&bytes[offset..offset + 8]);
        let timestamp = u64::from_be_bytes(ts_bytes);
        offset += 8;

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[offset..offset + 64]);

        Some(Self {
            peer_id: PeerId(peer_id),
            identity_key,
            direct_peers,
            hub_connections,
            nat_type,
            ipv6_available,
            timestamp,
            signature,
        })
    }
}

// =============================================================================
// Message Router
// =============================================================================

/// Hub connection for routing
#[derive(Clone)]
pub struct HubConnection {
    pub hub_id: HubId,
    pub hub: FederationHub,
    pub connected: bool,
    pub last_ping: Option<Instant>,
}

/// The main message router
pub struct MessageRouter {
    /// Our local peer ID
    local_peer_id: PeerId,
    /// Our identity
    identity: IdentityKeyPair,
    /// Routing table
    routing_table: Arc<RwLock<RoutingTable>>,
    /// Partial connectivity manager
    connectivity: Arc<RwLock<PartialConnectivityManager>>,
    /// Hub connections
    hub_connections: Arc<RwLock<HashMap<HubId, HubConnection>>>,
    /// Deduplication cache
    dedup_cache: Arc<RwLock<DeduplicationCache>>,
    /// Redundant delivery config
    redundant_delivery: RedundantDelivery,
    /// Message send channel (to transport)
    send_tx: mpsc::Sender<(PeerId, NscEnvelope)>,
    /// Our NAT type
    nat_type: Arc<RwLock<NatType>>,
    /// Last routing announcement time
    last_announcement: Arc<RwLock<Option<Instant>>>,
}

impl MessageRouter {
    /// Create a new message router
    pub fn new(
        identity: IdentityKeyPair,
        send_tx: mpsc::Sender<(PeerId, NscEnvelope)>,
    ) -> Self {
        let local_peer_id = PeerId::from_public_key(&identity.public_key().to_bytes());

        Self {
            local_peer_id,
            identity,
            routing_table: Arc::new(RwLock::new(RoutingTable::new(local_peer_id))),
            connectivity: Arc::new(RwLock::new(PartialConnectivityManager::new())),
            hub_connections: Arc::new(RwLock::new(HashMap::new())),
            dedup_cache: Arc::new(RwLock::new(DeduplicationCache::new())),
            redundant_delivery: RedundantDelivery::default(),
            send_tx,
            nat_type: Arc::new(RwLock::new(NatType::Unknown)),
            last_announcement: Arc::new(RwLock::new(None)),
        }
    }

    /// Get our peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Add a direct peer route
    pub async fn add_direct_peer(&self, peer_id: PeerId, addr: SocketAddr) {
        let entry = RoutingEntry::direct(peer_id, addr);
        self.routing_table.write().await.upsert(entry);
        self.connectivity.write().await.mark_reachable(peer_id);
    }

    /// Add a hub relay route
    pub async fn add_hub_route(&self, peer_id: PeerId, hub_id: HubId) {
        let entry = RoutingEntry::hub_relay(peer_id, hub_id);
        self.routing_table.write().await.upsert(entry);
        self.connectivity.write().await.mark_relay_only(peer_id);
    }

    /// Add a peer relay route
    pub async fn add_peer_relay(&self, peer_id: PeerId, relay_peer: PeerId) {
        let entry = RoutingEntry::peer_relay(peer_id, relay_peer);
        self.routing_table.write().await.upsert(entry);
        self.connectivity.write().await.mark_relay_only(peer_id);
    }

    /// Remove a peer from routing
    pub async fn remove_peer(&self, peer_id: &PeerId) {
        self.routing_table.write().await.remove(peer_id);
        self.connectivity.write().await.mark_unreachable(*peer_id);
    }

    /// Route a message to a single peer
    pub async fn route_to_peer(
        &self,
        envelope: NscEnvelope,
        target: PeerId,
    ) -> RouterResult<DeliveryResult> {
        // Check deduplication (for received messages we're re-routing)
        let msg_id = MessageId::from_envelope(&envelope);
        if self.dedup_cache.read().await.is_duplicate(&msg_id) {
            return Ok(DeliveryResult::Delivered {
                path: PathType::Direct,
                latency_ms: 0,
            });
        }

        // Get connectivity state
        let connectivity = self.connectivity.read().await;

        // Try direct delivery first
        if connectivity.is_direct(&target) {
            drop(connectivity);
            return self.try_direct_delivery(envelope, target).await;
        }

        // Try relay delivery
        if connectivity.is_relay_only(&target) {
            drop(connectivity);
            return self.try_relay_delivery(envelope, target).await;
        }

        drop(connectivity);

        // Peer is unreachable - queue the message
        self.connectivity
            .write()
            .await
            .queue_message(target, envelope);
        Ok(DeliveryResult::Queued)
    }

    /// Route a message to multiple peers (channel broadcast)
    pub async fn route_to_channel(
        &self,
        envelope: NscEnvelope,
        members: &[PeerId],
    ) -> RouterResult<Vec<(PeerId, DeliveryResult)>> {
        let mut results = Vec::with_capacity(members.len());

        // Group members by delivery method
        let (direct, relay, unreachable) = self.categorize_peers(members).await;

        // Send to direct peers
        for peer in direct {
            let result = self
                .try_direct_delivery(envelope.clone(), peer)
                .await
                .unwrap_or(DeliveryResult::Failed {
                    reason: "Send failed".into(),
                });
            results.push((peer, result));
        }

        // Send via relay for relay-only peers
        for peer in relay {
            let result = self
                .try_relay_delivery(envelope.clone(), peer)
                .await
                .unwrap_or(DeliveryResult::Failed {
                    reason: "Relay failed".into(),
                });
            results.push((peer, result));
        }

        // Queue for unreachable peers
        for peer in unreachable {
            self.connectivity
                .write()
                .await
                .queue_message(peer, envelope.clone());
            results.push((peer, DeliveryResult::Queued));
        }

        Ok(results)
    }

    /// Route with redundant delivery
    pub async fn route_redundant(
        &self,
        envelope: NscEnvelope,
        target: PeerId,
    ) -> RouterResult<DeliveryResult> {
        // Collect routes and clone them to release the lock quickly
        let routes: Vec<RoutingEntry> = {
            let rt = self.routing_table.read().await;
            rt.all_routes(&target).into_iter().cloned().collect()
        };

        if routes.is_empty() {
            // Queue for offline delivery
            self.connectivity
                .write()
                .await
                .queue_message(target, envelope);
            return Ok(DeliveryResult::Queued);
        }

        // Select diverse paths
        let route_refs: Vec<&RoutingEntry> = routes.iter().collect();
        let selected = self.redundant_delivery.select_diverse_paths(
            &route_refs,
            self.redundant_delivery.config.redundancy_factor,
        );

        let mut successes = Vec::new();
        let mut failures = Vec::new();

        // Try each path
        for route in selected {
            let envelope_clone = envelope.clone();
            let result = match &route.path_type {
                PathType::Direct => self.try_direct_delivery(envelope_clone, target).await,
                PathType::HubRelay { .. } => self.try_relay_delivery(envelope_clone, target).await,
                PathType::PeerRelay { relay_peer } => {
                    self.send_via_peer(*relay_peer, target, envelope_clone)
                        .await
                }
                PathType::MultiPath { .. } => continue,
            };

            match result {
                Ok(DeliveryResult::Delivered { path, .. }) => {
                    successes.push(path);
                }
                Ok(DeliveryResult::Failed { reason }) => {
                    failures.push((route.path_type.clone(), reason));
                }
                Err(e) => {
                    failures.push((route.path_type.clone(), e.to_string()));
                }
                _ => {}
            }
        }

        if !successes.is_empty() {
            Ok(DeliveryResult::Partial {
                successes,
                failures,
            })
        } else if failures.is_empty() {
            Ok(DeliveryResult::Queued)
        } else {
            Ok(DeliveryResult::Failed {
                reason: format!("All {} paths failed", failures.len()),
            })
        }
    }

    /// Process received routing announcement
    pub async fn process_announcement(&self, announcement: RoutingAnnouncement) {
        // Verify announcement
        if !announcement.verify() {
            log::warn!(
                "Invalid routing announcement from {}",
                announcement.peer_id.short()
            );
            return;
        }

        // Check freshness
        if !announcement.is_fresh(300) {
            log::debug!(
                "Stale routing announcement from {}",
                announcement.peer_id.short()
            );
            return;
        }

        // Update routing table based on announced direct peers
        // These peers can potentially relay messages through the announcer
        for direct_peer in &announcement.direct_peers {
            // We can potentially reach direct_peer via announcement.peer_id
            let entry = RoutingEntry::peer_relay(*direct_peer, announcement.peer_id);
            self.routing_table.write().await.upsert(entry);
        }

        // Track hub memberships
        for hub_id in &announcement.hub_connections {
            // The announcer can be reached via this hub
            let entry = RoutingEntry::hub_relay(announcement.peer_id, *hub_id);
            self.routing_table.write().await.upsert(entry);
        }
    }

    /// Create a routing announcement
    pub async fn create_announcement(&self) -> RoutingAnnouncement {
        let direct_peers = self.routing_table.read().await.direct_peers();
        let hub_connections: Vec<HubId> = self
            .hub_connections
            .read()
            .await
            .keys()
            .copied()
            .collect();
        let nat_type = *self.nat_type.read().await;

        RoutingAnnouncement::new(
            &self.identity,
            direct_peers,
            hub_connections,
            nat_type,
            false, // TODO: detect IPv6 availability
        )
    }

    /// Handle peer coming online
    pub async fn on_peer_connected(&self, peer_id: PeerId, addr: SocketAddr) {
        // Update routing
        self.add_direct_peer(peer_id, addr).await;

        // Deliver queued messages
        let queued = self.connectivity.write().await.take_queued(&peer_id);
        for msg in queued {
            let _ = self.try_direct_delivery(msg.envelope, peer_id).await;
        }
    }

    /// Handle peer going offline
    pub async fn on_peer_disconnected(&self, peer_id: PeerId) {
        self.connectivity.write().await.mark_unreachable(peer_id);
    }

    /// Set NAT type
    pub async fn set_nat_type(&self, nat_type: NatType) {
        *self.nat_type.write().await = nat_type;
    }

    /// Get routing table stats
    pub async fn stats(&self) -> RouterStats {
        let rt = self.routing_table.read().await;
        let connectivity = self.connectivity.read().await;

        RouterStats {
            total_routes: rt.len(),
            direct_peers: rt.direct_peers().len(),
            queued_messages: connectivity.total_queued(),
            dedup_cache_size: self.dedup_cache.read().await.len(),
        }
    }

    /// Cleanup stale entries
    pub async fn cleanup(&self) {
        self.routing_table.write().await.cleanup_stale();
        self.connectivity
            .write()
            .await
            .clear_expired(Duration::from_secs(3600));
        self.dedup_cache.write().await.cleanup();
    }

    // Internal helpers

    async fn categorize_peers(&self, peers: &[PeerId]) -> (Vec<PeerId>, Vec<PeerId>, Vec<PeerId>) {
        let connectivity = self.connectivity.read().await;
        let mut direct = Vec::new();
        let mut relay = Vec::new();
        let mut unreachable = Vec::new();

        for peer in peers {
            if *peer == self.local_peer_id {
                continue;
            }

            if connectivity.is_direct(peer) {
                direct.push(*peer);
            } else if connectivity.is_relay_only(peer) {
                relay.push(*peer);
            } else {
                unreachable.push(*peer);
            }
        }

        (direct, relay, unreachable)
    }

    async fn try_direct_delivery(
        &self,
        envelope: NscEnvelope,
        target: PeerId,
    ) -> RouterResult<DeliveryResult> {
        let start = Instant::now();

        self.send_tx
            .send((target, envelope))
            .await
            .map_err(|_| RouterError::TransportError(TransportError::SendFailed("Queue full".into())))?;

        // Record success
        if let Some(entry) = self.routing_table.write().await.get_mut(&target) {
            entry.record_success(start.elapsed().as_millis() as u32);
        }

        Ok(DeliveryResult::Delivered {
            path: PathType::Direct,
            latency_ms: start.elapsed().as_millis() as u32,
        })
    }

    async fn try_relay_delivery(
        &self,
        envelope: NscEnvelope,
        target: PeerId,
    ) -> RouterResult<DeliveryResult> {
        // Find best relay route
        let route = self
            .routing_table
            .read()
            .await
            .best_route(&target)
            .cloned();

        let route = route.ok_or_else(|| RouterError::NoRoute(target.short()))?;

        let start = Instant::now();

        match &route.path_type {
            PathType::HubRelay { hub_id } => {
                // Send via hub
                self.send_via_hub(*hub_id, target, envelope).await?;
            }
            PathType::PeerRelay { relay_peer } => {
                // Send via peer
                self.send_via_peer(*relay_peer, target, envelope).await?;
            }
            _ => {
                return Err(RouterError::NoRoute(target.short()));
            }
        }

        // Record success
        if let Some(entry) = self.routing_table.write().await.get_mut(&target) {
            entry.record_success(start.elapsed().as_millis() as u32);
        }

        Ok(DeliveryResult::Delivered {
            path: route.path_type,
            latency_ms: start.elapsed().as_millis() as u32,
        })
    }

    async fn send_via_hub(
        &self,
        hub_id: HubId,
        target: PeerId,
        envelope: NscEnvelope,
    ) -> RouterResult<DeliveryResult> {
        // Wrap envelope for relay
        let relay_envelope = self.wrap_for_relay(target, envelope);

        let hub_conn = self.hub_connections.read().await.get(&hub_id).cloned();

        if hub_conn.is_none() || !hub_conn.as_ref().unwrap().connected {
            return Err(RouterError::HubRelayFailed("Hub not connected".into()));
        }

        // Send to hub (hub will forward to target based on registration)
        let hub_peer_id = PeerId(hub_id.0); // Use hub ID as peer ID for addressing
        
        self.send_tx
            .send((hub_peer_id, relay_envelope))
            .await
            .map_err(|_| RouterError::HubRelayFailed("Send failed".into()))?;

        Ok(DeliveryResult::Delivered {
            path: PathType::HubRelay { hub_id },
            latency_ms: 0, // Will be updated on ack
        })
    }

    async fn send_via_peer(
        &self,
        relay_peer: PeerId,
        target: PeerId,
        envelope: NscEnvelope,
    ) -> RouterResult<DeliveryResult> {
        // Wrap envelope for relay
        let relay_envelope = self.wrap_for_relay(target, envelope);

        self.send_tx
            .send((relay_peer, relay_envelope))
            .await
            .map_err(|_| RouterError::TransportError(TransportError::SendFailed("Queue full".into())))?;

        Ok(DeliveryResult::Delivered {
            path: PathType::PeerRelay { relay_peer },
            latency_ms: 0,
        })
    }

    fn wrap_for_relay(&self, target: PeerId, inner: NscEnvelope) -> NscEnvelope {
        // Create relay wrapper envelope
        let mut payload = Vec::with_capacity(32 + inner.to_bytes().len());
        payload.extend_from_slice(&target.0);
        payload.extend_from_slice(&inner.to_bytes());

        let mut relay_envelope = NscEnvelope::new(
            MessageType::RelayData,
            self.local_peer_id.0,
            [0u8; 32], // Channel ID not used for relay
            0,
            Bytes::from(payload),
        );

        relay_envelope.sign(&self.identity);
        relay_envelope
    }
}

/// Router statistics
#[derive(Clone, Debug, Default)]
pub struct RouterStats {
    pub total_routes: usize,
    pub direct_peers: usize,
    pub queued_messages: usize,
    pub dedup_cache_size: usize,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hub_id() {
        let hub_id = HubId::from_address("relay.nais.chat:4433");
        assert_eq!(hub_id.to_hex().len(), 64);
        assert_eq!(hub_id.short().len(), 8);
    }

    #[test]
    fn test_path_priority() {
        assert!(PathType::Direct.priority() < PathType::PeerRelay { relay_peer: PeerId([0u8; 32]) }.priority());
        assert!(PathType::PeerRelay { relay_peer: PeerId([0u8; 32]) }.priority() < PathType::HubRelay { hub_id: HubId([0u8; 32]) }.priority());
    }

    #[test]
    fn test_routing_entry_score() {
        let peer = PeerId([1u8; 32]);
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        let direct = RoutingEntry::direct(peer, addr);
        let hub = RoutingEntry::hub_relay(peer, HubId([0u8; 32]));

        // Direct should have better (lower) score
        assert!(direct.score() < hub.score());
    }

    #[test]
    fn test_routing_entry_success_failure() {
        let peer = PeerId([1u8; 32]);
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        let mut entry = RoutingEntry::direct(peer, addr);
        assert_eq!(entry.success_count, 0);
        assert_eq!(entry.failure_count, 0);

        entry.record_success(50);
        assert_eq!(entry.success_count, 1);
        assert_eq!(entry.failure_count, 0);
        assert!(entry.reliability > 0.0);

        entry.record_failure();
        assert_eq!(entry.success_count, 0);
        assert_eq!(entry.failure_count, 1);
    }

    #[test]
    fn test_routing_table() {
        let local = PeerId([0u8; 32]);
        let mut table = RoutingTable::new(local);

        let peer = PeerId([1u8; 32]);
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        table.upsert(RoutingEntry::direct(peer, addr));
        assert_eq!(table.len(), 1);
        assert!(table.get(&peer).is_some());

        let direct_peers = table.direct_peers();
        assert_eq!(direct_peers.len(), 1);
        assert!(direct_peers.contains(&peer));
    }

    #[test]
    fn test_partial_connectivity() {
        let mut mgr = PartialConnectivityManager::new();
        let peer = PeerId([1u8; 32]);

        assert!(!mgr.is_reachable(&peer));

        mgr.mark_reachable(peer);
        assert!(mgr.is_reachable(&peer));
        assert!(mgr.is_direct(&peer));

        mgr.mark_relay_only(peer);
        assert!(mgr.is_reachable(&peer));
        assert!(!mgr.is_direct(&peer));
        assert!(mgr.is_relay_only(&peer));

        mgr.mark_unreachable(peer);
        assert!(!mgr.is_reachable(&peer));
        assert!(mgr.is_unreachable(&peer));
    }

    #[test]
    fn test_dedup_cache() {
        let mut cache = DeduplicationCache::new();
        let msg_id = MessageId {
            sender: PeerId([1u8; 32]),
            channel_id: [2u8; 32],
            sequence: 42,
        };

        assert!(!cache.is_duplicate(&msg_id));

        cache.mark_seen(msg_id);
        assert!(cache.is_duplicate(&msg_id));
    }

    #[test]
    fn test_routing_announcement_serialization() {
        let identity = crate::nsc_crypto::IdentityKeyPair::generate();
        let announcement = RoutingAnnouncement::new(
            &identity,
            vec![PeerId([1u8; 32]), PeerId([2u8; 32])],
            vec![HubId([3u8; 32])],
            NatType::FullCone,
            true,
        );

        let bytes = announcement.to_bytes();
        let parsed = RoutingAnnouncement::from_bytes(&bytes).unwrap();

        assert_eq!(announcement.peer_id.0, parsed.peer_id.0);
        assert_eq!(announcement.direct_peers.len(), parsed.direct_peers.len());
        assert_eq!(announcement.hub_connections.len(), parsed.hub_connections.len());
        assert_eq!(announcement.nat_type, parsed.nat_type);
        assert_eq!(announcement.ipv6_available, parsed.ipv6_available);
    }

    #[test]
    fn test_routing_announcement_verification() {
        let identity = crate::nsc_crypto::IdentityKeyPair::generate();
        let announcement = RoutingAnnouncement::new(
            &identity,
            vec![],
            vec![],
            NatType::Unknown,
            false,
        );

        assert!(announcement.verify());
        assert!(announcement.is_fresh(300));
    }

    #[test]
    fn test_redundant_delivery_path_selection() {
        let rd = RedundantDelivery::default();
        let peer = PeerId([1u8; 32]);
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        let routes = vec![
            RoutingEntry::direct(peer, addr),
            RoutingEntry::hub_relay(peer, HubId([0u8; 32])),
            RoutingEntry::peer_relay(peer, PeerId([2u8; 32])),
        ];

        let refs: Vec<_> = routes.iter().collect();
        let selected = rd.select_diverse_paths(&refs, 2);

        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_queued_message() {
        let msg = QueuedMessage::new(
            PeerId([1u8; 32]),
            NscEnvelope::new(
                MessageType::ChannelMessage,
                [0u8; 32],
                [0u8; 32],
                1,
                Bytes::from("test"),
            ),
        );

        assert!(!msg.is_expired(Duration::from_secs(60)));
        assert!(msg.should_retry());
    }
}
