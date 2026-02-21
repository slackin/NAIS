//! NAIS Secure Channels Relay Hub
//!
//! A federation hub that relays encrypted messages between NSC peers.
//! Used as a fallback when direct P2P connections fail (e.g., symmetric NAT).
//!
//! Features:
//! - QUIC transport with TLS 1.3
//! - Peer registration by PeerId and channels
//! - Message forwarding to connected peers
//! - Store-and-forward for offline peers (TTL-limited)
//!
//! Usage:
//!   relay-hub --bind 0.0.0.0:4433

use bytes::Bytes;
use clap::Parser;
use dashmap::DashMap;
use quinn::{Connection, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// =============================================================================
// Constants
// =============================================================================

/// Maximum message size (64KB)
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// How long to keep stored messages for offline peers
const STORE_FORWARD_TTL: Duration = Duration::from_secs(7 * 24 * 3600); // 7 days

/// Maximum stored messages per peer
const MAX_STORED_PER_PEER: usize = 1000;

/// Peer timeout (consider offline after this)
const PEER_TIMEOUT: Duration = Duration::from_secs(120);

/// Statistics reporting interval
const STATS_INTERVAL: Duration = Duration::from_secs(60);

// =============================================================================
// Protocol Types (mirrored from nsc_transport.rs)
// =============================================================================

/// Protocol version
const PROTOCOL_VERSION: u8 = 0x02;

/// Message types
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
            _ => None,
        }
    }
}

/// Peer ID (32-byte hash of public key)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PeerId(pub [u8; 32]);

impl PeerId {
    #[allow(dead_code)]
    fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    
    fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short())
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
            data[68], data[69], data[70], data[71],
            data[72], data[73], data[74], data[75],
        ]);
        
        let timestamp = u64::from_be_bytes([
            data[76], data[77], data[78], data[79],
            data[80], data[81], data[82], data[83],
        ]);
        
        let payload_len = u32::from_be_bytes([
            data[84], data[85], data[86], data[87],
        ]) as usize;
        
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
}

/// Relay register message
struct RelayRegister {
    peer_id: PeerId,
    channels: Vec<[u8; 32]>,
}

impl RelayRegister {
    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 36 {
            return None;
        }
        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(&data[..32]);
        let channel_count = u32::from_be_bytes([data[32], data[33], data[34], data[35]]) as usize;
        if data.len() < 36 + channel_count * 32 {
            return None;
        }
        let mut channels = Vec::with_capacity(channel_count);
        for i in 0..channel_count {
            let start = 36 + i * 32;
            let mut ch = [0u8; 32];
            ch.copy_from_slice(&data[start..start + 32]);
            channels.push(ch);
        }
        Some(Self { peer_id: PeerId(peer_id), channels })
    }
}

/// Relay forward message
struct RelayForward {
    target_peer_id: PeerId,
    envelope: Vec<u8>,
}

impl RelayForward {
    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 36 {
            return None;
        }
        let mut target = [0u8; 32];
        target.copy_from_slice(&data[..32]);
        let envelope_len = u32::from_be_bytes([data[32], data[33], data[34], data[35]]) as usize;
        if data.len() < 36 + envelope_len {
            return None;
        }
        let envelope = data[36..36 + envelope_len].to_vec();
        Some(Self { target_peer_id: PeerId(target), envelope })
    }
    
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36 + self.envelope.len());
        buf.extend_from_slice(&self.target_peer_id.0);
        buf.extend_from_slice(&(self.envelope.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.envelope);
        buf
    }
}

// =============================================================================
// Relay Hub State
// =============================================================================

/// A connected peer
struct ConnectedPeer {
    /// Peer ID
    #[allow(dead_code)]
    peer_id: PeerId,
    /// QUIC connection
    connection: Connection,
    /// Remote address
    remote_addr: SocketAddr,
    /// Channels this peer is interested in
    channels: Vec<[u8; 32]>,
    /// When the peer connected
    #[allow(dead_code)]
    connected_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Messages relayed through this peer
    messages_relayed: u64,
}

/// A stored message for offline delivery
struct StoredMessage {
    /// Target peer
    #[allow(dead_code)]
    target: PeerId,
    /// Channel ID
    channel_id: [u8; 32],
    /// Raw envelope bytes
    envelope_data: Vec<u8>,
    /// When stored
    #[allow(dead_code)]
    stored_at: Instant,
    /// Expiry time
    expires_at: Instant,
}

impl StoredMessage {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Hub statistics
#[derive(Default)]
struct HubStats {
    /// Total connections received
    total_connections: u64,
    /// Currently connected peers
    active_peers: u64,
    /// Total messages relayed
    messages_relayed: u64,
    /// Messages stored for offline delivery
    messages_stored: u64,
    /// Messages delivered from store
    messages_delivered: u64,
    /// Failed deliveries
    delivery_failures: u64,
}

/// The relay hub
struct RelayHub {
    /// Connected peers by peer ID
    peers: DashMap<PeerId, ConnectedPeer>,
    /// Peers by connection (for cleanup)
    conn_to_peer: DashMap<SocketAddr, PeerId>,
    /// Channel subscriptions: channel_id -> set of peer IDs
    channel_subs: DashMap<[u8; 32], Vec<PeerId>>,
    /// Stored messages for offline peers
    stored_messages: RwLock<HashMap<PeerId, VecDeque<StoredMessage>>>,
    /// Hub statistics
    stats: RwLock<HubStats>,
}

impl RelayHub {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            peers: DashMap::new(),
            conn_to_peer: DashMap::new(),
            channel_subs: DashMap::new(),
            stored_messages: RwLock::new(HashMap::new()),
            stats: RwLock::new(HubStats::default()),
        })
    }
    
    /// Register a peer
    async fn register_peer(&self, peer_id: PeerId, connection: Connection, channels: Vec<[u8; 32]>) {
        let remote_addr = connection.remote_address();
        let now = Instant::now();
        
        // Remove old registration if exists
        if let Some((_, old)) = self.peers.remove(&peer_id) {
            old.connection.close(0u32.into(), b"re-registering");
            self.conn_to_peer.remove(&old.remote_addr);
            // Remove from old channel subscriptions
            for ch in &old.channels {
                if let Some(mut subs) = self.channel_subs.get_mut(ch) {
                    subs.retain(|p| *p != peer_id);
                }
            }
        }
        
        // Add to channel subscriptions
        for ch in &channels {
            self.channel_subs
                .entry(*ch)
                .or_insert_with(Vec::new)
                .push(peer_id);
        }
        
        // Store peer
        let peer = ConnectedPeer {
            peer_id,
            connection,
            remote_addr,
            channels,
            connected_at: now,
            last_activity: now,
            messages_relayed: 0,
        };
        self.peers.insert(peer_id, peer);
        self.conn_to_peer.insert(remote_addr, peer_id);
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_connections += 1;
            stats.active_peers = self.peers.len() as u64;
        }
        
        // Deliver any stored messages
        self.deliver_stored_messages(peer_id).await;
        
        log::info!("Peer {} registered from {}", peer_id, remote_addr);
    }
    
    /// Unregister a peer (on disconnect)
    async fn unregister_peer(&self, remote_addr: SocketAddr) {
        if let Some((_, peer_id)) = self.conn_to_peer.remove(&remote_addr) {
            if let Some((_, peer)) = self.peers.remove(&peer_id) {
                // Remove from channel subscriptions
                for ch in &peer.channels {
                    if let Some(mut subs) = self.channel_subs.get_mut(ch) {
                        subs.retain(|p| *p != peer_id);
                    }
                }
                
                log::info!("Peer {} disconnected (relayed {} messages)", 
                    peer_id, peer.messages_relayed);
            }
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.active_peers = self.peers.len() as u64;
        }
    }
    
    /// Forward a message to a target peer
    async fn forward_message(&self, from: PeerId, target: PeerId, envelope_data: Vec<u8>, channel_id: [u8; 32]) -> bool {
        // Update sender's last activity
        if let Some(mut peer) = self.peers.get_mut(&from) {
            peer.last_activity = Instant::now();
        }
        
        // Try to find target peer
        if let Some(mut target_peer) = self.peers.get_mut(&target) {
            // Create relay forward wrapper
            let forward = RelayForward {
                target_peer_id: target,
                envelope: envelope_data.clone(),
            };
            
            // Wrap in NscEnvelope
            let relay_envelope = NscEnvelope {
                version: PROTOCOL_VERSION,
                message_type: MessageType::RelayData,
                flags: 0,
                sender_id: from.0,
                channel_id,
                sequence_number: 0,
                timestamp: now_millis(),
                payload: Bytes::from(forward.encode()),
                signature: [0u8; 64], // Hub doesn't sign forwards
            };
            
            // Send to target
            match self.send_to_peer(&target_peer.connection, &relay_envelope).await {
                Ok(_) => {
                    target_peer.messages_relayed += 1;
                    target_peer.last_activity = Instant::now();
                    
                    // Update stats
                    self.stats.write().await.messages_relayed += 1;
                    
                    log::debug!("Forwarded message from {} to {}", from, target);
                    return true;
                }
                Err(e) => {
                    log::warn!("Failed to forward to {}: {}", target, e);
                    self.stats.write().await.delivery_failures += 1;
                }
            }
        }
        
        // Target not connected - store for later
        self.store_message(target, channel_id, envelope_data).await;
        false
    }
    
    /// Store a message for offline delivery
    async fn store_message(&self, target: PeerId, channel_id: [u8; 32], envelope_data: Vec<u8>) {
        let now = Instant::now();
        let msg = StoredMessage {
            target,
            channel_id,
            envelope_data,
            stored_at: now,
            expires_at: now + STORE_FORWARD_TTL,
        };
        
        let mut stored = self.stored_messages.write().await;
        let queue = stored.entry(target).or_insert_with(VecDeque::new);
        
        // Enforce max stored messages
        while queue.len() >= MAX_STORED_PER_PEER {
            queue.pop_front();
        }
        
        queue.push_back(msg);
        self.stats.write().await.messages_stored += 1;
        
        log::debug!("Stored message for offline peer {} ({} queued)", target, queue.len());
    }
    
    /// Deliver stored messages to a newly connected peer
    async fn deliver_stored_messages(&self, peer_id: PeerId) {
        let messages: Vec<StoredMessage> = {
            let mut stored = self.stored_messages.write().await;
            if let Some(queue) = stored.get_mut(&peer_id) {
                let msgs: Vec<_> = queue.drain(..).filter(|m| !m.is_expired()).collect();
                msgs
            } else {
                Vec::new()
            }
        };
        
        if messages.is_empty() {
            return;
        }
        
        log::info!("Delivering {} stored messages to {}", messages.len(), peer_id);
        
        if let Some(peer) = self.peers.get(&peer_id) {
            for msg in messages {
                let forward = RelayForward {
                    target_peer_id: peer_id,
                    envelope: msg.envelope_data,
                };
                
                let relay_envelope = NscEnvelope {
                    version: PROTOCOL_VERSION,
                    message_type: MessageType::RelayData,
                    flags: 0,
                    sender_id: [0u8; 32], // From store
                    channel_id: msg.channel_id,
                    sequence_number: 0,
                    timestamp: now_millis(),
                    payload: Bytes::from(forward.encode()),
                    signature: [0u8; 64],
                };
                
                if self.send_to_peer(&peer.connection, &relay_envelope).await.is_ok() {
                    self.stats.write().await.messages_delivered += 1;
                }
            }
        }
    }
    
    /// Send an envelope to a peer connection
    async fn send_to_peer(&self, conn: &Connection, envelope: &NscEnvelope) -> Result<(), String> {
        let mut send = conn.open_uni().await
            .map_err(|e| format!("Failed to open stream: {}", e))?;
        
        let data = envelope.to_bytes();
        send.write_all(&(data.len() as u32).to_be_bytes()).await
            .map_err(|e| format!("Failed to write length: {}", e))?;
        send.write_all(&data).await
            .map_err(|e| format!("Failed to write data: {}", e))?;
        send.finish()
            .map_err(|e| format!("Failed to finish stream: {}", e))?;
        
        Ok(())
    }
    
    /// Handle incoming messages from a peer
    async fn handle_peer(self: Arc<Self>, connection: Connection) {
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
                    
                    match envelope.message_type {
                        MessageType::RelayRequest => {
                            // Peer registration
                            if let Some(register) = RelayRegister::decode(&envelope.payload) {
                                self.register_peer(
                                    register.peer_id,
                                    connection.clone(),
                                    register.channels,
                                ).await;
                            }
                        }
                        MessageType::RelayData => {
                            // Forward to target peer
                            if let Some(forward) = RelayForward::decode(&envelope.payload) {
                                self.forward_message(
                                    sender_id,
                                    forward.target_peer_id,
                                    forward.envelope,
                                    envelope.channel_id,
                                ).await;
                            }
                        }
                        MessageType::Heartbeat => {
                            // Update peer activity
                            if let Some(mut peer) = self.peers.get_mut(&sender_id) {
                                peer.last_activity = Instant::now();
                            }
                        }
                        _ => {
                            log::debug!("Ignoring message type {:?} from {}", 
                                envelope.message_type, remote_addr);
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Connection closed from {}: {}", remote_addr, e);
                    break;
                }
            }
        }
        
        // Clean up on disconnect
        self.unregister_peer(remote_addr).await;
    }
    
    /// Periodic cleanup of expired messages and stale peers
    async fn cleanup_task(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            // Clean expired stored messages
            {
                let mut stored = self.stored_messages.write().await;
                for queue in stored.values_mut() {
                    queue.retain(|m| !m.is_expired());
                }
                stored.retain(|_, q| !q.is_empty());
            }
            
            // Check for stale peers
            let now = Instant::now();
            let stale: Vec<SocketAddr> = self.peers.iter()
                .filter(|p| now.duration_since(p.last_activity) > PEER_TIMEOUT)
                .map(|p| p.remote_addr)
                .collect();
            
            for addr in stale {
                log::info!("Removing stale peer at {}", addr);
                self.unregister_peer(addr).await;
            }
        }
    }
    
    /// Print statistics periodically
    async fn stats_task(self: Arc<Self>) {
        let mut interval = tokio::time::interval(STATS_INTERVAL);
        
        loop {
            interval.tick().await;
            
            let stats = self.stats.read().await;
            let stored_count: usize = self.stored_messages.read().await
                .values().map(|q| q.len()).sum();
            
            log::info!(
                "Hub Stats: {} active peers, {} total connections, {} relayed, {} stored ({} pending)",
                stats.active_peers,
                stats.total_connections,
                stats.messages_relayed,
                stats.messages_stored,
                stored_count
            );
        }
    }
}

// =============================================================================
// TLS Configuration
// =============================================================================

/// Generate self-signed certificate for the relay hub
fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>), String> {
    let cert = rcgen::generate_simple_self_signed(vec!["pugbot.net".into(), "localhost".into()])
        .map_err(|e| format!("Failed to generate cert: {}", e))?;
    
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    
    Ok((vec![cert_der], key))
}

/// Create QUIC server config
fn create_server_config() -> Result<ServerConfig, String> {
    let (certs, key) = generate_self_signed_cert()?;
    
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .map_err(|e| format!("TLS config error: {}", e))?;
    
    server_crypto.alpn_protocols = vec![b"nsc-relay".to_vec()];
    
    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| format!("QUIC config error: {}", e))?
    ));
    
    Ok(server_config)
}

// =============================================================================
// CLI
// =============================================================================

#[derive(Parser, Debug)]
#[command(name = "relay-hub")]
#[command(about = "NAIS Secure Channels Relay Hub")]
struct Args {
    /// Address to bind to
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    bind: SocketAddr,
    
    /// Log level (debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
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

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    
    log::info!("NAIS Relay Hub starting on {}", args.bind);
    
    // Create server config
    let server_config = create_server_config()?;
    
    // Create QUIC endpoint
    let endpoint = Endpoint::server(server_config, args.bind)?;
    
    log::info!("Relay hub listening on {}", args.bind);
    
    // Create hub state
    let hub = RelayHub::new();
    
    // Start background tasks
    tokio::spawn(hub.clone().cleanup_task());
    tokio::spawn(hub.clone().stats_task());
    
    // Accept connections
    while let Some(incoming) = endpoint.accept().await {
        let hub = hub.clone();
        
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    hub.handle_peer(connection).await;
                }
                Err(e) => {
                    log::warn!("Connection failed: {}", e);
                }
            }
        });
    }
    
    Ok(())
}
