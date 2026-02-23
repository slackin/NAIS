//! Nais Secure Channels - Transport Layer
//!
//! Implements QUIC-based transport for P2P messaging:
//! - Wire protocol (NSC envelope format)
//! - QUIC transport with TLS 1.3
//! - Connection pool management
//! - Message routing and delivery
//! - Integration with NAT traversal

use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, ServerConfig, TransportConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

use crate::nsc_crypto::IdentityKeyPair;
use crate::nsc_nat::{ConnectionManager, IceCandidate, IceCredentials, NatType};

// =============================================================================
// Error Types
// =============================================================================

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Timeout")]
    Timeout,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Quinn error: {0}")]
    QuinnError(String),
}

pub type TransportResult<T> = Result<T, TransportError>;

// =============================================================================
// Constants
// =============================================================================

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 0x02;

/// Maximum message size (1 MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Header size (fixed portion)
pub const HEADER_SIZE: usize = 152;

/// Connection timeout
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Keepalive interval
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// ALPN protocol identifier
pub const ALPN_PROTOCOL: &[u8] = b"nais-secure-channel/2";

// =============================================================================
// Wire Protocol - Message Types
// =============================================================================

/// Message type identifiers
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
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
    KeyRevocation = 0x23,
    SenderKeyDistribution = 0x24,

    // Control
    Ack = 0x30,
    Heartbeat = 0x31,
    RoutingUpdate = 0x32,

    // NAT Traversal
    IceCandidateMsg = 0x40,
    IceOffer = 0x41,
    IceAnswer = 0x42,

    // Relay
    RelayRequest = 0x50,
    RelayData = 0x51,
    RelayRegister = 0x52,
    RelayUnregister = 0x53,

    // Store-and-Forward
    StoreRequest = 0x60,
    StoredMessage = 0x61,
    StoredMessageAck = 0x62,
    FetchStoredMessages = 0x63,

    // Federation
    HubAnnounce = 0x70,
    HubQuery = 0x71,
    HubRoute = 0x72,
}

impl MessageType {
    pub fn from_u8(val: u8) -> Option<Self> {
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
            0x23 => Some(Self::KeyRevocation),
            0x24 => Some(Self::SenderKeyDistribution),
            0x30 => Some(Self::Ack),
            0x31 => Some(Self::Heartbeat),
            0x32 => Some(Self::RoutingUpdate),
            0x40 => Some(Self::IceCandidateMsg),
            0x41 => Some(Self::IceOffer),
            0x42 => Some(Self::IceAnswer),
            0x50 => Some(Self::RelayRequest),
            0x51 => Some(Self::RelayData),
            0x52 => Some(Self::RelayRegister),
            0x53 => Some(Self::RelayUnregister),
            0x60 => Some(Self::StoreRequest),
            0x61 => Some(Self::StoredMessage),
            0x62 => Some(Self::StoredMessageAck),
            0x63 => Some(Self::FetchStoredMessages),
            0x70 => Some(Self::HubAnnounce),
            0x71 => Some(Self::HubQuery),
            0x72 => Some(Self::HubRoute),
            _ => None,
        }
    }
}

/// Message flags
#[derive(Clone, Copy, Debug, Default)]
pub struct MessageFlags {
    /// Message is being relayed through a hub
    pub relayed: bool,
    /// High priority message
    pub priority: bool,
    /// Delivery acknowledgment requested
    pub ack_requested: bool,
    /// Message is encrypted with group key
    pub group_encrypted: bool,
}

impl MessageFlags {
    pub fn to_u16(&self) -> u16 {
        let mut flags = 0u16;
        if self.relayed {
            flags |= 0x0001;
        }
        if self.priority {
            flags |= 0x0002;
        }
        if self.ack_requested {
            flags |= 0x0004;
        }
        if self.group_encrypted {
            flags |= 0x0008;
        }
        flags
    }

    pub fn from_u16(val: u16) -> Self {
        Self {
            relayed: (val & 0x0001) != 0,
            priority: (val & 0x0002) != 0,
            ack_requested: (val & 0x0004) != 0,
            group_encrypted: (val & 0x0008) != 0,
        }
    }
}

// =============================================================================
// Wire Protocol - Message Envelope
// =============================================================================

/// NSC Message Envelope
///
/// Wire format:
/// - Version:         1 byte
/// - Message Type:    1 byte
/// - Flags:           2 bytes
/// - Sender ID:       32 bytes (identity public key hash)
/// - Channel ID:      32 bytes (SHA-256 of channel creation)
/// - Sequence Number: 8 bytes
/// - Timestamp:       8 bytes (Unix ms)
/// - Payload Length:  4 bytes
/// - Payload:         variable
/// - Signature:       64 bytes (Ed25519)
#[derive(Clone, Debug)]
pub struct NscEnvelope {
    pub version: u8,
    pub message_type: MessageType,
    pub flags: MessageFlags,
    pub sender_id: [u8; 32],
    pub channel_id: [u8; 32],
    pub sequence_number: u64,
    pub timestamp: u64,
    pub payload: Bytes,
    pub signature: [u8; 64],
}

impl NscEnvelope {
    /// Create a new envelope
    pub fn new(
        message_type: MessageType,
        sender_id: [u8; 32],
        channel_id: [u8; 32],
        sequence_number: u64,
        payload: Bytes,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            version: PROTOCOL_VERSION,
            message_type,
            flags: MessageFlags::default(),
            sender_id,
            channel_id,
            sequence_number,
            timestamp,
            payload,
            signature: [0u8; 64],
        }
    }

    /// Sign the envelope with identity key
    pub fn sign(&mut self, identity: &IdentityKeyPair) {
        let data = self.to_signing_data();
        self.signature = identity.sign(&data);
    }

    /// Verify envelope signature
    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        use ed25519_dalek::{Signature, VerifyingKey};

        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };

        let signature = Signature::from_bytes(&self.signature);

        let data = self.to_signing_data();
        verifying_key.verify_strict(&data, &signature).is_ok()
    }

    /// Get data to be signed (everything except signature)
    fn to_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(HEADER_SIZE - 64 + self.payload.len());
        data.push(self.version);
        data.push(self.message_type as u8);
        data.extend_from_slice(&self.flags.to_u16().to_be_bytes());
        data.extend_from_slice(&self.sender_id);
        data.extend_from_slice(&self.channel_id);
        data.extend_from_slice(&self.sequence_number.to_be_bytes());
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        data.extend_from_slice(&self.payload);
        data
    }

    /// Serialize envelope to bytes
    pub fn to_bytes(&self) -> Bytes {
        let total_size = HEADER_SIZE + self.payload.len();
        let mut buf = BytesMut::with_capacity(total_size);

        buf.put_u8(self.version);
        buf.put_u8(self.message_type as u8);
        buf.put_u16(self.flags.to_u16());
        buf.put_slice(&self.sender_id);
        buf.put_slice(&self.channel_id);
        buf.put_u64(self.sequence_number);
        buf.put_u64(self.timestamp);
        buf.put_u32(self.payload.len() as u32);
        buf.put_slice(&self.payload);
        buf.put_slice(&self.signature);

        buf.freeze()
    }

    /// Parse envelope from bytes
    pub fn from_bytes(mut data: Bytes) -> TransportResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(TransportError::InvalidMessage("Message too short".into()));
        }

        let version = data.get_u8();
        if version != PROTOCOL_VERSION {
            return Err(TransportError::InvalidMessage(format!(
                "Unsupported version: {}",
                version
            )));
        }

        let message_type_byte = data.get_u8();
        let message_type = MessageType::from_u8(message_type_byte)
            .ok_or_else(|| TransportError::InvalidMessage("Unknown message type".into()))?;

        let flags = MessageFlags::from_u16(data.get_u16());

        let mut sender_id = [0u8; 32];
        data.copy_to_slice(&mut sender_id);

        let mut channel_id = [0u8; 32];
        data.copy_to_slice(&mut channel_id);

        let sequence_number = data.get_u64();
        let timestamp = data.get_u64();
        let payload_length = data.get_u32() as usize;

        if payload_length > MAX_MESSAGE_SIZE {
            return Err(TransportError::InvalidMessage("Payload too large".into()));
        }

        if data.remaining() < payload_length + 64 {
            return Err(TransportError::InvalidMessage("Incomplete message".into()));
        }

        let payload = data.copy_to_bytes(payload_length);

        let mut signature = [0u8; 64];
        data.copy_to_slice(&mut signature);

        Ok(Self {
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

    /// Get message age in milliseconds
    pub fn age_ms(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now.saturating_sub(self.timestamp)
    }
}

// =============================================================================
// Peer Identity
// =============================================================================

/// Peer identifier (32-byte hash of identity public key)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Create from identity public key
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(public_key);
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

    /// Short form for display (first 8 chars)
    pub fn short(&self) -> String {
        self.to_hex()[..8].to_string()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short())
    }
}

// =============================================================================
// Connection State
// =============================================================================

/// State of a peer connection
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Establishing connection
    Connecting,
    /// Connected and ready
    Connected,
    /// Connection failed
    Failed,
}

/// Information about a connected peer
#[derive(Clone, Debug)]
pub struct PeerConnection {
    /// Peer identifier
    pub peer_id: PeerId,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Connection state
    pub state: ConnectionState,
    /// Connection established time
    pub connected_at: Option<Instant>,
    /// Last activity time
    pub last_activity: Instant,
    /// NAT type of peer (if known)
    pub nat_type: Option<NatType>,
    /// Is this a relayed connection?
    pub relayed: bool,
    /// Round-trip time estimate
    pub rtt: Option<Duration>,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
}

impl PeerConnection {
    pub fn new(peer_id: PeerId, remote_addr: SocketAddr) -> Self {
        Self {
            peer_id,
            remote_addr,
            state: ConnectionState::Connecting,
            connected_at: None,
            last_activity: Instant::now(),
            nat_type: None,
            relayed: false,
            rtt: None,
            messages_sent: 0,
            messages_received: 0,
        }
    }

    pub fn mark_connected(&mut self) {
        self.state = ConnectionState::Connected;
        self.connected_at = Some(Instant::now());
        self.last_activity = Instant::now();
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

// =============================================================================
// QUIC Transport
// =============================================================================

/// QUIC transport configuration
#[derive(Clone, Debug)]
pub struct QuicConfig {
    /// Bind address for the endpoint
    pub bind_addr: SocketAddr,
    /// Maximum idle timeout
    pub idle_timeout: Duration,
    /// Keep-alive interval
    pub keep_alive: Duration,
    /// Maximum concurrent bi-directional streams
    pub max_bi_streams: u32,
    /// Maximum concurrent uni-directional streams
    pub max_uni_streams: u32,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            idle_timeout: Duration::from_secs(60),
            keep_alive: Duration::from_secs(30),
            max_bi_streams: 100,
            max_uni_streams: 100,
        }
    }
}

/// QUIC transport manager
pub struct QuicTransport {
    /// QUIC endpoint
    endpoint: Endpoint,
    /// Active connections by peer ID
    connections: Arc<RwLock<HashMap<PeerId, Connection>>>,
    /// Peer connection info
    peers: Arc<RwLock<HashMap<PeerId, PeerConnection>>>,
    /// Server certificate (for TLS)
    certificate: CertificateDer<'static>,
    /// Server private key
    private_key: PrivateKeyDer<'static>,
}

impl QuicTransport {
    /// Create new QUIC transport
    pub async fn new(config: QuicConfig) -> TransportResult<Self> {
        // Generate self-signed certificate for TLS
        let (certificate, private_key) = Self::generate_certificate()?;

        // Create server config
        let server_config = Self::create_server_config(certificate.clone(), private_key.clone_key())?;

        // Create endpoint with server config
        let endpoint = Endpoint::server(server_config, config.bind_addr)
            .map_err(|e| TransportError::QuinnError(e.to_string()))?;

        log::info!("QUIC transport listening on {}", endpoint.local_addr()?);

        Ok(Self {
            endpoint,
            connections: Arc::new(RwLock::new(HashMap::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            certificate,
            private_key,
        })
    }

    /// Generate self-signed certificate
    fn generate_certificate() -> TransportResult<(CertificateDer<'static>, PrivateKeyDer<'static>)>
    {
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .map_err(|e| TransportError::TlsError(e.to_string()))?;
        
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| TransportError::TlsError(e.to_string()))?;
        
        let cert = cert_params
            .self_signed(&key_pair)
            .map_err(|e| TransportError::TlsError(e.to_string()))?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        Ok((cert_der, key_der))
    }

    /// Create server TLS config
    fn create_server_config(
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> TransportResult<ServerConfig> {
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| TransportError::TlsError(e.to_string()))?;

        crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

        let mut transport_config = TransportConfig::default();
        transport_config.keep_alive_interval(Some(KEEPALIVE_INTERVAL));
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(60).try_into().unwrap(),
        ));

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .map_err(|e| TransportError::TlsError(e.to_string()))?,
        ));
        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }

    /// Create client TLS config
    fn create_client_config() -> TransportResult<ClientConfig> {
        // For P2P, we use a custom certificate verifier that accepts all certs
        // Security comes from the application-layer identity verification
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| TransportError::TlsError(e.to_string()))?,
        ));

        let mut transport_config = TransportConfig::default();
        transport_config.keep_alive_interval(Some(KEEPALIVE_INTERVAL));

        client_config.transport_config(Arc::new(transport_config));

        Ok(client_config)
    }

    /// Connect to a peer
    pub async fn connect(&self, peer_id: PeerId, addr: SocketAddr) -> TransportResult<()> {
        // Check if already connected
        if self.connections.read().await.contains_key(&peer_id) {
            return Ok(());
        }

        // Create client config
        let client_config = Self::create_client_config()?;

        // Connect
        let connecting = self
            .endpoint
            .connect_with(client_config, addr, "localhost")
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let connection = tokio::time::timeout(CONNECTION_TIMEOUT, connecting)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Store connection
        self.connections.write().await.insert(peer_id, connection);

        // Create peer info
        let mut peer_conn = PeerConnection::new(peer_id, addr);
        peer_conn.mark_connected();
        self.peers.write().await.insert(peer_id, peer_conn);

        log::info!("Connected to peer {} at {}", peer_id, addr);

        Ok(())
    }

    /// Accept incoming connections
    pub async fn accept(&self) -> TransportResult<(Connection, SocketAddr)> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(TransportError::ConnectionClosed)?;

        let connection = incoming
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let addr = connection.remote_address();
        Ok((connection, addr))
    }

    /// Send message to peer
    pub async fn send(&self, peer_id: &PeerId, envelope: &NscEnvelope) -> TransportResult<()> {
        let connections = self.connections.read().await;
        let connection = connections
            .get(peer_id)
            .ok_or_else(|| TransportError::PeerNotFound(peer_id.to_hex()))?;

        // Open a uni-directional stream for the message
        let mut send_stream = connection
            .open_uni()
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        // Write message
        let data = envelope.to_bytes();
        send_stream
            .write_all(&data)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        send_stream
            .finish()
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        // Update peer stats
        drop(connections);
        if let Some(peer) = self.peers.write().await.get_mut(peer_id) {
            peer.messages_sent += 1;
            peer.update_activity();
        }

        Ok(())
    }

    /// Receive message from a stream
    pub async fn receive_from_stream(recv: &mut RecvStream) -> TransportResult<NscEnvelope> {
        // Read header first to get payload length
        let mut header = vec![0u8; HEADER_SIZE - 64]; // Without signature
        recv.read_exact(&mut header)
            .await
            .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;

        // Get payload length from header
        let payload_len = u32::from_be_bytes([header[76], header[77], header[78], header[79]]) as usize;

        if payload_len > MAX_MESSAGE_SIZE {
            return Err(TransportError::InvalidMessage("Payload too large".into()));
        }

        // Read payload and signature
        let mut payload_and_sig = vec![0u8; payload_len + 64];
        recv.read_exact(&mut payload_and_sig)
            .await
            .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;

        // Combine into full message
        let mut full_message = BytesMut::with_capacity(header.len() + payload_and_sig.len());
        full_message.extend_from_slice(&header);
        full_message.extend_from_slice(&payload_and_sig);

        NscEnvelope::from_bytes(full_message.freeze())
    }

    /// Disconnect from peer
    pub async fn disconnect(&self, peer_id: &PeerId) {
        if let Some(connection) = self.connections.write().await.remove(peer_id) {
            connection.close(0u8.into(), b"disconnect");
        }
        if let Some(peer) = self.peers.write().await.get_mut(peer_id) {
            peer.state = ConnectionState::Disconnected;
        }
    }

    /// Get local address
    pub fn local_addr(&self) -> TransportResult<SocketAddr> {
        self.endpoint.local_addr().map_err(TransportError::IoError)
    }

    /// Get peer connection info
    pub async fn get_peer(&self, peer_id: &PeerId) -> Option<PeerConnection> {
        self.peers.read().await.get(peer_id).cloned()
    }

    /// Register an incoming connection (used when accepting connections)
    /// This allows bidirectional communication with peers who connected to us
    pub async fn register_connection(&self, peer_id: PeerId, connection: Connection, addr: SocketAddr) {
        // Check if already registered
        if self.connections.read().await.contains_key(&peer_id) {
            log::debug!("Peer {} already registered, skipping", peer_id);
            return;
        }

        // Store connection
        self.connections.write().await.insert(peer_id, connection);

        // Create peer info
        let mut peer_conn = PeerConnection::new(peer_id, addr);
        peer_conn.mark_connected();
        self.peers.write().await.insert(peer_id, peer_conn);

        log::info!("Registered incoming connection from peer {} at {}", peer_id, addr);
    }

    /// Get all connected peers
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.peers
            .read()
            .await
            .iter()
            .filter(|(_, p)| p.state == ConnectionState::Connected)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Close the transport
    pub fn close(&self) {
        self.endpoint.close(0u8.into(), b"shutdown");
    }
}

/// Custom certificate verifier that skips verification
/// Security is provided by application-layer identity verification
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Skip certificate verification - we verify identity at application layer
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// =============================================================================
// Transport Manager
// =============================================================================

/// Manages transport connections with NAT traversal
pub struct TransportManager {
    /// QUIC transport
    quic: Arc<QuicTransport>,
    /// NAT connection manager per peer
    nat_managers: Arc<RwLock<HashMap<PeerId, ConnectionManager>>>,
    /// Message sender channel
    outgoing_tx: mpsc::Sender<(PeerId, NscEnvelope)>,
    /// Message receiver channel
    outgoing_rx: Arc<RwLock<mpsc::Receiver<(PeerId, NscEnvelope)>>>,
    /// Our identity
    identity: Arc<IdentityKeyPair>,
    /// Our peer ID
    local_peer_id: PeerId,
}

impl TransportManager {
    /// Create new transport manager
    pub async fn new(identity: IdentityKeyPair) -> TransportResult<Self> {
        let quic = QuicTransport::new(QuicConfig::default()).await?;
        let (outgoing_tx, outgoing_rx) = mpsc::channel(1000);

        let public_key = identity.public_key();
        let local_peer_id = PeerId::from_public_key(&public_key.to_bytes());

        Ok(Self {
            quic: Arc::new(quic),
            nat_managers: Arc::new(RwLock::new(HashMap::new())),
            outgoing_tx,
            outgoing_rx: Arc::new(RwLock::new(outgoing_rx)),
            identity: Arc::new(identity),
            local_peer_id,
        })
    }

    /// Get our local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Get local address
    pub fn local_addr(&self) -> TransportResult<SocketAddr> {
        self.quic.local_addr()
    }

    /// Initiate connection to a peer using NAT traversal
    pub async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        remote_credentials: IceCredentials,
        remote_candidates: Vec<IceCandidate>,
    ) -> TransportResult<()> {
        // Create NAT connection manager
        let mut nat_manager = ConnectionManager::new(true);
        nat_manager.set_remote_credentials(remote_credentials).await;

        for candidate in remote_candidates {
            nat_manager.add_remote_candidate(candidate).await;
        }

        // Gather our candidates
        let _our_candidates = nat_manager
            .gather_candidates()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Attempt connection
        let conn_info = nat_manager
            .connect()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Now establish QUIC over the NAT-traversed connection
        self.quic
            .connect(peer_id, conn_info.remote_address)
            .await?;

        // Store NAT manager
        self.nat_managers.write().await.insert(peer_id, nat_manager);

        Ok(())
    }

    /// Get ICE credentials for signaling to a peer
    pub async fn get_ice_offer(&self, peer_id: PeerId) -> TransportResult<(IceCredentials, Vec<IceCandidate>)> {
        let mut nat_manager = ConnectionManager::new(true);
        let candidates = nat_manager
            .gather_candidates()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let credentials = nat_manager.local_credentials().clone();

        self.nat_managers.write().await.insert(peer_id, nat_manager);

        Ok((credentials, candidates))
    }

    /// Send a message to a peer
    pub async fn send(&self, peer_id: PeerId, message_type: MessageType, payload: Bytes) -> TransportResult<()> {
        let mut envelope = NscEnvelope::new(
            message_type,
            self.local_peer_id.0,
            [0u8; 32], // Channel ID would be set by caller
            0,         // Sequence number would be managed by channel
            payload,
        );

        envelope.sign(&self.identity);

        self.quic.send(&peer_id, &envelope).await
    }

    /// Queue a message for sending
    pub async fn queue_send(&self, peer_id: PeerId, envelope: NscEnvelope) -> TransportResult<()> {
        self.outgoing_tx
            .send((peer_id, envelope))
            .await
            .map_err(|_| TransportError::SendFailed("Queue full".into()))
    }

    /// Get connected peers
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.quic.connected_peers().await
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: &PeerId) {
        self.quic.disconnect(peer_id).await;
        self.nat_managers.write().await.remove(peer_id);
    }

    /// Close the transport
    pub fn close(&self) {
        self.quic.close();
    }
}

// =============================================================================
// Message Router
// =============================================================================

/// Routes messages between transport and application layer
pub struct MessageRouter {
    /// Transport manager
    transport: Arc<TransportManager>,
    /// Handlers for different message types
    handlers: Arc<RwLock<HashMap<MessageType, mpsc::Sender<NscEnvelope>>>>,
    /// Default handler for unrouted messages
    default_handler: Option<mpsc::Sender<NscEnvelope>>,
}

impl MessageRouter {
    /// Create new message router
    pub fn new(transport: Arc<TransportManager>) -> Self {
        Self {
            transport,
            handlers: Arc::new(RwLock::new(HashMap::new())),
            default_handler: None,
        }
    }

    /// Register a handler for a message type
    pub async fn register_handler(&self, message_type: MessageType, handler: mpsc::Sender<NscEnvelope>) {
        self.handlers.write().await.insert(message_type, handler);
    }

    /// Route an incoming message to the appropriate handler
    pub async fn route(&self, envelope: NscEnvelope) -> TransportResult<()> {
        let handlers = self.handlers.read().await;

        if let Some(handler) = handlers.get(&envelope.message_type) {
            handler
                .send(envelope)
                .await
                .map_err(|_| TransportError::SendFailed("Handler channel closed".into()))?;
        } else if let Some(ref default) = self.default_handler {
            default
                .send(envelope)
                .await
                .map_err(|_| TransportError::SendFailed("Default handler closed".into()))?;
        } else {
            log::warn!(
                "No handler for message type {:?}",
                envelope.message_type
            );
        }

        Ok(())
    }
}

// =============================================================================
// Relay Client - Fallback for Symmetric NAT
// =============================================================================

/// Default relay hub addresses
/// Local hub (127.0.0.1:4433) is tried first for development/testing.
/// Run `cargo run -p nais-relay-hub` to start a local relay.
pub const DEFAULT_RELAY_HUBS: &[&str] = &[
    "127.0.0.1:4433",       // Local test relay (run relay-hub first)
    "pugbot.net:4433",      // Primary relay hub
];

/// Relay message for registering with hub
#[derive(Clone, Debug)]
pub struct RelayRegister {
    /// Our peer ID
    pub peer_id: PeerId,
    /// Channels we're interested in
    pub channels: Vec<[u8; 32]>,
}

impl RelayRegister {
    pub fn new(peer_id: PeerId, channels: Vec<[u8; 32]>) -> Self {
        Self { peer_id, channels }
    }
    
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 4 + self.channels.len() * 32);
        buf.extend_from_slice(&self.peer_id.0);
        buf.extend_from_slice(&(self.channels.len() as u32).to_be_bytes());
        for ch in &self.channels {
            buf.extend_from_slice(ch);
        }
        buf
    }
    
    pub fn decode(data: &[u8]) -> Option<Self> {
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

/// Relay wrapper for forwarding messages through hub
#[derive(Clone, Debug)]
pub struct RelayForward {
    /// Target peer ID
    pub target_peer_id: PeerId,
    /// Inner envelope (encrypted)
    pub envelope: Vec<u8>,
}

impl RelayForward {
    pub fn new(target: PeerId, envelope: Vec<u8>) -> Self {
        Self { target_peer_id: target, envelope }
    }
    
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 4 + self.envelope.len());
        buf.extend_from_slice(&self.target_peer_id.0);
        buf.extend_from_slice(&(self.envelope.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.envelope);
        buf
    }
    
    pub fn decode(data: &[u8]) -> Option<Self> {
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
}

/// Relay client state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayState {
    /// Not connected to any relay
    Disconnected,
    /// Connecting to relay hub
    Connecting,
    /// Connected and registered
    Connected,
    /// Connection error
    Error,
}

// =============================================================================
// Federation Hub Discovery
// =============================================================================

/// Capabilities advertised by a federation hub
#[derive(Clone, Debug, Default)]
pub struct HubCapabilities {
    /// Can relay encrypted messages
    pub relay: bool,
    /// Provides TURN server for NAT traversal
    pub turn: bool,
    /// Stores messages for offline peers
    pub store_forward: bool,
    /// Maximum relay message size (bytes)
    pub max_relay_size: usize,
    /// Rate limit (messages per minute)
    pub rate_limit_per_min: u32,
}

/// Health status of a federation hub
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HubHealth {
    /// Hub is healthy and responding
    Healthy,
    /// Hub is degraded (high latency or errors)
    Degraded,
    /// Hub is unreachable
    Unreachable,
    /// Hub status unknown (not yet checked)
    Unknown,
}

/// A federation hub for relay connectivity
#[derive(Clone, Debug)]
pub struct FederationHub {
    /// Hub address (host:port)
    pub address: String,
    /// Hub identity public key (if known)
    pub public_key: Option<[u8; 32]>,
    /// Geographic region for latency optimization
    pub region: String,
    /// Hub capabilities
    pub capabilities: HubCapabilities,
    /// Current health status
    pub health: HubHealth,
    /// Last successful ping latency (ms)
    pub latency_ms: Option<u32>,
    /// Load factor (0.0 = idle, 1.0 = fully loaded)
    pub load_factor: f32,
    /// Last health check timestamp
    pub last_check: u64,
    /// Consecutive failure count
    pub failure_count: u32,
}

impl FederationHub {
    /// Create a new hub entry with default values
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_string(),
            public_key: None,
            region: "unknown".to_string(),
            capabilities: HubCapabilities::default(),
            health: HubHealth::Unknown,
            latency_ms: None,
            load_factor: 0.0,
            last_check: 0,
            failure_count: 0,
        }
    }
    
    /// Check if hub should be retried based on failure count
    pub fn should_retry(&self) -> bool {
        // Exponential backoff: wait 2^failures seconds between retries, max 300s
        if self.failure_count == 0 {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let backoff_secs = std::cmp::min(2u64.pow(self.failure_count), 300);
        now >= self.last_check + backoff_secs
    }
    
    /// Record a successful connection
    pub fn record_success(&mut self, latency_ms: u32) {
        self.health = HubHealth::Healthy;
        self.latency_ms = Some(latency_ms);
        self.failure_count = 0;
        self.last_check = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
    
    /// Record a failed connection attempt
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_check = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.health = if self.failure_count >= 5 {
            HubHealth::Unreachable
        } else {
            HubHealth::Degraded
        };
    }
}

/// Registry of known federation hubs
pub struct HubRegistry {
    /// Known hubs by address
    hubs: RwLock<HashMap<String, FederationHub>>,
    /// Currently connected hub address
    connected_hub: RwLock<Option<String>>,
}

impl HubRegistry {
    /// Create a new hub registry with default hubs
    pub fn new() -> Self {
        let mut hubs = HashMap::new();
        
        // Add default hubs
        for addr in DEFAULT_RELAY_HUBS {
            let mut hub = FederationHub::new(addr);
            hub.capabilities = HubCapabilities {
                relay: true,
                turn: true,
                store_forward: true,
                max_relay_size: 64 * 1024, // 64KB
                rate_limit_per_min: 100,
            };
            hubs.insert(addr.to_string(), hub);
        }
        
        Self {
            hubs: RwLock::new(hubs),
            connected_hub: RwLock::new(None),
        }
    }
    
    /// Add a hub to the registry
    pub async fn add_hub(&self, hub: FederationHub) {
        self.hubs.write().await.insert(hub.address.clone(), hub);
    }
    
    /// Remove a hub from the registry
    pub async fn remove_hub(&self, address: &str) {
        self.hubs.write().await.remove(address);
    }
    
    /// Get all known hubs
    pub async fn all_hubs(&self) -> Vec<FederationHub> {
        self.hubs.read().await.values().cloned().collect()
    }
    
    /// Get healthy hubs sorted by latency
    pub async fn healthy_hubs(&self) -> Vec<FederationHub> {
        let hubs = self.hubs.read().await;
        let mut healthy: Vec<_> = hubs.values()
            .filter(|h| h.health == HubHealth::Healthy || h.health == HubHealth::Unknown)
            .filter(|h| h.should_retry())
            .cloned()
            .collect();
        
        // Sort by latency (unknown latency goes last)
        healthy.sort_by(|a, b| {
            match (a.latency_ms, b.latency_ms) {
                (Some(la), Some(lb)) => la.cmp(&lb),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });
        
        healthy
    }
    
    /// Select the best hub for connection
    pub async fn select_best_hub(&self) -> Option<FederationHub> {
        let healthy = self.healthy_hubs().await;
        healthy.into_iter().next()
    }
    
    /// Record successful connection to a hub
    pub async fn record_connection_success(&self, address: &str, latency_ms: u32) {
        let mut hubs = self.hubs.write().await;
        if let Some(hub) = hubs.get_mut(address) {
            hub.record_success(latency_ms);
        }
        drop(hubs);
        *self.connected_hub.write().await = Some(address.to_string());
    }
    
    /// Record failed connection to a hub
    pub async fn record_connection_failure(&self, address: &str) {
        let mut hubs = self.hubs.write().await;
        if let Some(hub) = hubs.get_mut(address) {
            hub.record_failure();
        }
    }
    
    /// Get currently connected hub
    pub async fn connected_hub(&self) -> Option<String> {
        self.connected_hub.read().await.clone()
    }
    
    /// Clear connected hub
    pub async fn clear_connected(&self) {
        *self.connected_hub.write().await = None;
    }
    
    /// Discover hubs from DNS TXT records
    /// Format: _nsc-hub.<domain> TXT "addr=host:port,region=us-west,relay=1,turn=1"
    pub async fn discover_from_dns(&self, domain: &str) -> Vec<FederationHub> {
        let record_name = format!("_nsc-hub.{}", domain);
        log::debug!("Looking up DNS TXT record: {}", record_name);
        
        // Use tokio's DNS resolver
        let addrs = match tokio::net::lookup_host(&record_name).await {
            Ok(addrs) => addrs.collect::<Vec<_>>(),
            Err(e) => {
                log::debug!("DNS hub discovery failed for {}: {}", domain, e);
                return Vec::new();
            }
        };
        
        let mut discovered = Vec::new();
        for addr in addrs {
            let hub = FederationHub::new(&addr.to_string());
            discovered.push(hub);
        }
        discovered
    }
    
    /// Check health of all hubs
    pub async fn check_all_health(&self) {
        let addresses: Vec<String> = {
            self.hubs.read().await.keys().cloned().collect()
        };
        
        for address in addresses {
            let should_check = {
                let hubs = self.hubs.read().await;
                if let Some(hub) = hubs.get(&address) {
                    hub.should_retry()
                } else {
                    false
                }
            };
            
            if should_check {
                // Simple TCP connect check as health probe
                let start = Instant::now();
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::TcpStream::connect(&address)
                ).await {
                    Ok(Ok(_)) => {
                        let latency = start.elapsed().as_millis() as u32;
                        self.record_connection_success(&address, latency).await;
                        log::debug!("Hub {} healthy, latency {}ms", address, latency);
                    }
                    _ => {
                        self.record_connection_failure(&address).await;
                        log::debug!("Hub {} health check failed", address);
                    }
                }
            }
        }
    }
}

impl Default for HubRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Weak reference to relay client state for background tasks
struct RelayClientWeak {
    peer_id: PeerId,
    state: Arc<RwLock<RelayState>>,
    relay_addr: Arc<RwLock<Option<String>>>,
}

/// Relay client for fallback connectivity
pub struct RelayClient {
    /// Our peer ID
    peer_id: PeerId,
    /// Identity for TLS
    identity: Arc<IdentityKeyPair>,
    /// Current state
    state: Arc<RwLock<RelayState>>,
    /// QUIC endpoint (client mode)
    endpoint: Arc<RwLock<Option<Endpoint>>>,
    /// Current relay connection
    connection: Arc<RwLock<Option<Connection>>>,
    /// Relay hub address we're connected to
    relay_addr: Arc<RwLock<Option<String>>>,
    /// Channels we're interested in
    channels: Arc<RwLock<Vec<[u8; 32]>>>,
    /// Handler for incoming relayed messages
    message_handler: Arc<RwLock<Option<mpsc::Sender<(PeerId, NscEnvelope)>>>>,
    /// Hub registry for discovery and failover
    hub_registry: Arc<HubRegistry>,
}

impl RelayClient {
    /// Create new relay client
    pub fn new(peer_id: PeerId, identity: Arc<IdentityKeyPair>) -> Self {
        Self {
            peer_id,
            identity,
            state: Arc::new(RwLock::new(RelayState::Disconnected)),
            endpoint: Arc::new(RwLock::new(None)),
            connection: Arc::new(RwLock::new(None)),
            relay_addr: Arc::new(RwLock::new(None)),
            channels: Arc::new(RwLock::new(Vec::new())),
            message_handler: Arc::new(RwLock::new(None)),
            hub_registry: Arc::new(HubRegistry::new()),
        }
    }
    
    /// Set message handler for incoming relayed messages
    pub async fn set_message_handler(&self, handler: mpsc::Sender<(PeerId, NscEnvelope)>) {
        *self.message_handler.write().await = Some(handler);
    }
    
    /// Register channels we want to receive messages for
    pub async fn register_channels(&self, channels: Vec<[u8; 32]>) {
        *self.channels.write().await = channels;
    }
    
    /// Connect to a relay hub
    pub async fn connect(&self, relay_addr: &str) -> TransportResult<()> {
        *self.state.write().await = RelayState::Connecting;
        
        // Create QUIC client config with self-signed cert (relay validates our identity later)
        let client_config = self.create_client_config()
            .map_err(|e| TransportError::TlsError(e))?;
        
        // Create endpoint
        let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| TransportError::QuinnError(e.to_string()))?;
        
        // Resolve relay address
        let addr: SocketAddr = tokio::net::lookup_host(relay_addr)
            .await
            .map_err(|e| TransportError::ConnectionFailed(format!("DNS lookup failed: {}", e)))?
            .next()
            .ok_or_else(|| TransportError::ConnectionFailed("No addresses found".into()))?;
        
        // Extract hostname for SNI (strip port)
        let sni_host = relay_addr.split(':').next().unwrap_or("pugbot.net");
        
        // Connect with timeout
        let connecting = endpoint.connect_with(client_config, addr, sni_host)
            .map_err(|e| TransportError::QuinnError(e.to_string()))?;
        
        let connection = tokio::time::timeout(CONNECTION_TIMEOUT, connecting)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        
        // Register with the relay
        let channels = self.channels.read().await.clone();
        self.send_register(&connection, &channels).await?;
        
        // Store connection state
        *self.endpoint.write().await = Some(endpoint);
        *self.connection.write().await = Some(connection.clone());
        *self.relay_addr.write().await = Some(relay_addr.to_string());
        *self.state.write().await = RelayState::Connected;
        
        // Start listening for incoming messages
        self.start_listener(connection).await;
        
        log::info!("Connected to relay hub: {}", relay_addr);
        Ok(())
    }
    
    /// Try to connect to any available relay hub using the registry
    pub async fn connect_any(&self) -> TransportResult<()> {
        // First try hubs from registry sorted by health/latency
        let healthy_hubs = self.hub_registry.healthy_hubs().await;
        
        for hub in healthy_hubs {
            log::info!("Trying relay hub: {} (latency: {:?}ms)", hub.address, hub.latency_ms);
            let start = Instant::now();
            match self.connect(&hub.address).await {
                Ok(_) => {
                    let latency = start.elapsed().as_millis() as u32;
                    self.hub_registry.record_connection_success(&hub.address, latency).await;
                    return Ok(());
                }
                Err(e) => {
                    self.hub_registry.record_connection_failure(&hub.address).await;
                    log::warn!("Failed to connect to relay {}: {}", hub.address, e);
                    continue;
                }
            }
        }
        
        // Fallback to static list if registry hubs failed
        for hub in DEFAULT_RELAY_HUBS {
            // Skip if already tried from registry
            if self.hub_registry.all_hubs().await.iter().any(|h| h.address == *hub) {
                continue;
            }
            
            log::info!("Trying fallback relay hub: {}", hub);
            match self.connect(hub).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    log::warn!("Failed to connect to relay {}: {}", hub, e);
                    continue;
                }
            }
        }
        
        Err(TransportError::ConnectionFailed("All relay hubs failed".into()))
    }
    
    /// Attempt failover to another hub when current connection fails
    pub async fn failover(&self) -> TransportResult<()> {
        // Get current hub address
        let current = self.relay_addr.read().await.clone();
        
        // Mark current hub as failed if we have one
        if let Some(addr) = &current {
            self.hub_registry.record_connection_failure(addr).await;
            log::info!("Hub {} failed, attempting failover", addr);
        }
        
        // Disconnect from failed hub
        self.disconnect().await;
        self.hub_registry.clear_connected().await;
        
        // Try to connect to another hub
        self.connect_any().await
    }
    
    /// Get the hub registry for external access
    pub fn hub_registry(&self) -> Arc<HubRegistry> {
        Arc::clone(&self.hub_registry)
    }
    
    /// Start background health check task
    pub async fn start_health_monitor(&self) {
        let registry = Arc::clone(&self.hub_registry);
        let relay_client = RelayClientWeak {
            peer_id: self.peer_id,
            state: Arc::clone(&self.state),
            relay_addr: Arc::clone(&self.relay_addr),
        };
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // Check health of all known hubs
                registry.check_all_health().await;
                
                // Check if we need to failover
                let state = *relay_client.state.read().await;
                if state == RelayState::Error {
                    log::info!("Relay in error state, will try reconnect on next message");
                }
            }
        });
    }
    
    /// Disconnect from relay
    pub async fn disconnect(&self) {
        if let Some(conn) = self.connection.write().await.take() {
            conn.close(0u32.into(), b"bye");
        }
        *self.state.write().await = RelayState::Disconnected;
        *self.relay_addr.write().await = None;
    }
    
    /// Send a message through the relay to a peer
    pub async fn send_to_peer(&self, target: &PeerId, envelope: &NscEnvelope) -> TransportResult<()> {
        let conn = self.connection.read().await.clone()
            .ok_or_else(|| TransportError::ConnectionFailed("Not connected to relay".into()))?;
        
        // Serialize the envelope
        let envelope_bytes = envelope.to_bytes().to_vec();
        
        // Wrap in RelayForward
        let forward = RelayForward::new(*target, envelope_bytes);
        
        // Create RelayData message
        let relay_envelope = NscEnvelope::new(
            MessageType::RelayData,
            self.peer_id.0,
            [0u8; 32], // No specific channel for relay control
            0,
            Bytes::from(forward.encode()),
        );
        
        // Send through relay
        let mut send = conn.open_uni().await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        
        let data = relay_envelope.to_bytes();
        send.write_all(&(data.len() as u32).to_be_bytes()).await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        send.write_all(&data).await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        send.finish()
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// Get current state
    pub async fn state(&self) -> RelayState {
        *self.state.read().await
    }
    
    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == RelayState::Connected
    }
    
    /// Get connected relay address
    pub async fn relay_address(&self) -> Option<String> {
        self.relay_addr.read().await.clone()
    }
    
    // Internal: Create QUIC client config
    fn create_client_config(&self) -> Result<ClientConfig, String> {
        // For relay connection, we accept any server cert (relay validates us via message signing)
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        
        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| format!("Crypto config error: {}", e))?
        ));
        
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(KEEPALIVE_INTERVAL));
        config.transport_config(Arc::new(transport));
        
        Ok(config)
    }
    
    // Internal: Send register message to relay
    async fn send_register(&self, conn: &Connection, channels: &[[u8; 32]]) -> TransportResult<()> {
        let register = RelayRegister::new(self.peer_id, channels.to_vec());
        
        let envelope = NscEnvelope::new(
            MessageType::RelayRequest,
            self.peer_id.0,
            [0u8; 32],
            0,
            Bytes::from(register.encode()),
        );
        
        let mut send = conn.open_uni().await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        
        let data = envelope.to_bytes();
        send.write_all(&(data.len() as u32).to_be_bytes()).await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        send.write_all(&data).await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        send.finish()
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        
        Ok(())
    }
    
    // Internal: Start listening for incoming relayed messages
    async fn start_listener(&self, connection: Connection) {
        let handler = self.message_handler.clone();
        let state = self.state.clone();
        
        tokio::spawn(async move {
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
                            continue;
                        }
                        
                        // Read message
                        let mut buf = vec![0u8; len];
                        if recv.read_exact(&mut buf).await.is_err() {
                            continue;
                        }
                        
                        // Parse envelope
                        let envelope = match NscEnvelope::from_bytes(Bytes::from(buf)) {
                            Ok(env) => env,
                            Err(_) => continue,
                        };
                        
                        // Handle RelayData messages
                        if envelope.message_type == MessageType::RelayData {
                            if let Some(forward) = RelayForward::decode(&envelope.payload) {
                                // Parse the inner envelope
                                if let Ok(inner) = NscEnvelope::from_bytes(Bytes::from(forward.envelope)) {
                                    let sender = PeerId(envelope.sender_id);
                                    if let Some(ref h) = *handler.read().await {
                                        let _ = h.send((sender, inner)).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Relay connection error: {}", e);
                        *state.write().await = RelayState::Disconnected;
                        break;
                    }
                }
            }
        });
    }
}

// =============================================================================
// Store-and-Forward System
// =============================================================================

/// A message stored for offline delivery
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StoredMessage {
    /// Unique message identifier
    pub message_id: [u8; 32],
    /// Target peer ID who should receive this
    pub target_peer: PeerId,
    /// Channel ID the message belongs to
    pub channel_id: [u8; 32],
    /// The encrypted envelope bytes
    pub envelope_data: Vec<u8>,
    /// When the message was stored
    pub stored_at: u64,
    /// Message expiry time
    pub expires_at: u64,
    /// Number of delivery attempts
    pub delivery_attempts: u32,
    /// Priority (higher = more urgent)
    pub priority: u8,
}

impl StoredMessage {
    /// Create a new stored message
    pub fn new(target: PeerId, channel_id: [u8; 32], envelope: &NscEnvelope, ttl_secs: u64) -> Self {
        use sha2::{Sha256, Digest};
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Generate message ID from content hash
        let mut hasher = Sha256::new();
        hasher.update(&envelope.sender_id);
        hasher.update(&envelope.channel_id);
        hasher.update(&envelope.sequence_number.to_be_bytes());
        hasher.update(&envelope.timestamp.to_be_bytes());
        let hash = hasher.finalize();
        let mut message_id = [0u8; 32];
        message_id.copy_from_slice(&hash);
        
        Self {
            message_id,
            target_peer: target,
            channel_id,
            envelope_data: envelope.to_bytes().to_vec(),
            stored_at: now,
            expires_at: now + ttl_secs,
            delivery_attempts: 0,
            priority: 0,
        }
    }
    
    /// Check if message has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at
    }
    
    /// Serialize for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128 + self.envelope_data.len());
        bytes.extend_from_slice(&self.message_id);
        bytes.extend_from_slice(&self.target_peer.0);
        bytes.extend_from_slice(&self.channel_id);
        bytes.extend_from_slice(&self.stored_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.delivery_attempts.to_be_bytes());
        bytes.push(self.priority);
        bytes.extend_from_slice(&(self.envelope_data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.envelope_data);
        bytes
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 117 {
            return None;
        }
        
        let mut message_id = [0u8; 32];
        message_id.copy_from_slice(&bytes[0..32]);
        
        let mut target_peer = [0u8; 32];
        target_peer.copy_from_slice(&bytes[32..64]);
        
        let mut channel_id = [0u8; 32];
        channel_id.copy_from_slice(&bytes[64..96]);
        
        let stored_at = u64::from_be_bytes([
            bytes[96], bytes[97], bytes[98], bytes[99],
            bytes[100], bytes[101], bytes[102], bytes[103],
        ]);
        
        let expires_at = u64::from_be_bytes([
            bytes[104], bytes[105], bytes[106], bytes[107],
            bytes[108], bytes[109], bytes[110], bytes[111],
        ]);
        
        let delivery_attempts = u32::from_be_bytes([
            bytes[112], bytes[113], bytes[114], bytes[115],
        ]);
        
        let priority = bytes[116];
        
        let envelope_len = u32::from_be_bytes([
            bytes[117], bytes[118], bytes[119], bytes[120],
        ]) as usize;
        
        if bytes.len() < 121 + envelope_len {
            return None;
        }
        
        let envelope_data = bytes[121..121 + envelope_len].to_vec();
        
        Some(Self {
            message_id,
            target_peer: PeerId(target_peer),
            channel_id,
            stored_at,
            expires_at,
            delivery_attempts,
            priority,
            envelope_data,
        })
    }
}

/// Store-and-forward request to hub
#[derive(Clone, Debug)]
pub struct StoreForwardRequest {
    /// Messages to store for offline delivery
    pub messages: Vec<StoredMessage>,
}

impl StoreForwardRequest {
    /// Create a new store request
    pub fn new(messages: Vec<StoredMessage>) -> Self {
        Self { messages }
    }
    
    /// Encode for transmission
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.messages.len() as u32).to_be_bytes());
        for msg in &self.messages {
            let msg_bytes = msg.to_bytes();
            bytes.extend_from_slice(&(msg_bytes.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&msg_bytes);
        }
        bytes
    }
    
    /// Decode from bytes
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        
        let count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if count > 1000 {
            return None; // Sanity check
        }
        
        let mut messages = Vec::with_capacity(count);
        let mut offset = 4;
        
        for _ in 0..count {
            if offset + 4 > bytes.len() {
                return None;
            }
            
            let msg_len = u32::from_be_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            ]) as usize;
            offset += 4;
            
            if offset + msg_len > bytes.len() {
                return None;
            }
            
            if let Some(msg) = StoredMessage::from_bytes(&bytes[offset..offset + msg_len]) {
                messages.push(msg);
            }
            offset += msg_len;
        }
        
        Some(Self { messages })
    }
}

/// Request to fetch stored messages from hub
#[derive(Clone, Debug)]
pub struct FetchStoredRequest {
    /// Our peer ID
    pub peer_id: PeerId,
    /// Channel IDs we're interested in
    pub channel_ids: Vec<[u8; 32]>,
    /// Fetch messages since this timestamp
    pub since: u64,
    /// Maximum number of messages to fetch
    pub limit: u32,
}

impl FetchStoredRequest {
    /// Encode for transmission
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(44 + self.channel_ids.len() * 32);
        bytes.extend_from_slice(&self.peer_id.0);
        bytes.extend_from_slice(&self.since.to_be_bytes());
        bytes.extend_from_slice(&self.limit.to_be_bytes());
        bytes.extend_from_slice(&(self.channel_ids.len() as u32).to_be_bytes());
        for id in &self.channel_ids {
            bytes.extend_from_slice(id);
        }
        bytes
    }
    
    /// Decode from bytes
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 48 {
            return None;
        }
        
        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(&bytes[0..32]);
        
        let since = u64::from_be_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35],
            bytes[36], bytes[37], bytes[38], bytes[39],
        ]);
        
        let limit = u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        
        let channel_count = u32::from_be_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]) as usize;
        
        if bytes.len() < 48 + channel_count * 32 {
            return None;
        }
        
        let mut channel_ids = Vec::with_capacity(channel_count);
        for i in 0..channel_count {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes[48 + i * 32..48 + (i + 1) * 32]);
            channel_ids.push(id);
        }
        
        Some(Self {
            peer_id: PeerId(peer_id),
            channel_ids,
            since,
            limit,
        })
    }
}

/// Local store-forward manager for client-side queuing
pub struct StoreForwardManager {
    /// Messages queued for offline peers (target_peer -> messages)
    queued_messages: RwLock<HashMap<PeerId, Vec<StoredMessage>>>,
    /// Maximum messages per peer
    max_per_peer: usize,
    /// Default message TTL (7 days)
    default_ttl: u64,
    /// Message delivery callback
    on_delivery: RwLock<Option<mpsc::Sender<StoredMessage>>>,
}

impl StoreForwardManager {
    /// Create a new store-forward manager
    pub fn new() -> Self {
        Self {
            queued_messages: RwLock::new(HashMap::new()),
            max_per_peer: 1000,
            default_ttl: 7 * 24 * 3600, // 7 days
            on_delivery: RwLock::new(None),
        }
    }
    
    /// Queue a message for an offline peer
    pub async fn queue_message(&self, target: PeerId, channel_id: [u8; 32], envelope: &NscEnvelope) {
        let msg = StoredMessage::new(target, channel_id, envelope, self.default_ttl);
        
        let mut queued = self.queued_messages.write().await;
        let queue = queued.entry(target).or_insert_with(Vec::new);
        
        // Check limit
        if queue.len() >= self.max_per_peer {
            // Remove oldest message
            queue.remove(0);
        }
        
        queue.push(msg);
    }
    
    /// Get queued messages for a peer (and clear them)
    pub async fn take_queued(&self, target: &PeerId) -> Vec<StoredMessage> {
        self.queued_messages.write().await.remove(target).unwrap_or_default()
    }
    
    /// Get all queued messages for upload to hub
    pub async fn take_all_queued(&self) -> Vec<StoredMessage> {
        let mut all = Vec::new();
        let mut queued = self.queued_messages.write().await;
        for (_, messages) in queued.drain() {
            all.extend(messages);
        }
        all
    }
    
    /// Process received stored messages
    pub async fn process_received(&self, messages: Vec<StoredMessage>) {
        if let Some(ref callback) = *self.on_delivery.read().await {
            for msg in messages {
                if !msg.is_expired() {
                    let _ = callback.send(msg).await;
                }
            }
        }
    }
    
    /// Clear expired messages
    pub async fn clear_expired(&self) {
        let mut queued = self.queued_messages.write().await;
        for queue in queued.values_mut() {
            queue.retain(|msg| !msg.is_expired());
        }
        // Remove empty queues
        queued.retain(|_, q| !q.is_empty());
    }
    
    /// Set delivery callback
    pub async fn set_delivery_callback(&self, callback: mpsc::Sender<StoredMessage>) {
        *self.on_delivery.write().await = Some(callback);
    }
    
    /// Get total queued message count
    pub async fn queued_count(&self) -> usize {
        self.queued_messages.read().await.values().map(|q| q.len()).sum()
    }
    
    /// Get queued message count for a specific peer
    pub async fn queued_for_peer(&self, peer: &PeerId) -> usize {
        self.queued_messages.read().await.get(peer).map(|q| q.len()).unwrap_or(0)
    }
}

impl Default for StoreForwardManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_roundtrip() {
        for i in 0..=255u8 {
            if let Some(mt) = MessageType::from_u8(i) {
                assert_eq!(mt as u8, i);
            }
        }
    }

    #[test]
    fn test_message_flags() {
        let flags = MessageFlags {
            relayed: true,
            priority: false,
            ack_requested: true,
            group_encrypted: false,
        };

        let encoded = flags.to_u16();
        let decoded = MessageFlags::from_u16(encoded);

        assert_eq!(flags.relayed, decoded.relayed);
        assert_eq!(flags.priority, decoded.priority);
        assert_eq!(flags.ack_requested, decoded.ack_requested);
        assert_eq!(flags.group_encrypted, decoded.group_encrypted);
    }

    #[test]
    fn test_envelope_serialization() {
        let envelope = NscEnvelope::new(
            MessageType::ChannelMessage,
            [1u8; 32],
            [2u8; 32],
            42,
            Bytes::from("Hello, NSC!"),
        );

        let bytes = envelope.to_bytes();
        let parsed = NscEnvelope::from_bytes(bytes).unwrap();

        assert_eq!(parsed.version, PROTOCOL_VERSION);
        assert_eq!(parsed.message_type, MessageType::ChannelMessage);
        assert_eq!(parsed.sender_id, [1u8; 32]);
        assert_eq!(parsed.channel_id, [2u8; 32]);
        assert_eq!(parsed.sequence_number, 42);
        assert_eq!(parsed.payload.as_ref(), b"Hello, NSC!");
    }

    #[test]
    fn test_envelope_signing() {
        let identity = IdentityKeyPair::generate();
        let public_key = identity.public_key();

        let mut envelope = NscEnvelope::new(
            MessageType::ChannelMessage,
            [0u8; 32],
            [0u8; 32],
            1,
            Bytes::from("Test message"),
        );

        envelope.sign(&identity);

        assert!(envelope.verify(&public_key.to_bytes()));

        // Tamper with message
        let mut tampered = envelope.clone();
        tampered.payload = Bytes::from("Tampered!");
        assert!(!tampered.verify(&public_key.to_bytes()));
    }

    #[test]
    fn test_peer_id() {
        let key = [1u8; 32];
        let peer_id = PeerId::from_public_key(&key);

        assert_eq!(peer_id.to_hex().len(), 64);
        assert_eq!(peer_id.short().len(), 8);
    }

    #[test]
    fn test_peer_connection_stale() {
        let mut conn = PeerConnection::new(PeerId([0u8; 32]), "127.0.0.1:1234".parse().unwrap());

        assert!(!conn.is_stale(Duration::from_secs(1)));

        // Simulate time passing by updating last_activity to past
        conn.last_activity = Instant::now() - Duration::from_secs(10);

        assert!(conn.is_stale(Duration::from_secs(5)));
    }

    #[test]
    fn test_header_size() {
        // Verify header size calculation:
        // 1 (version) + 1 (type) + 2 (flags) + 32 (sender) + 32 (channel) +
        // 8 (seq) + 8 (timestamp) + 4 (payload_len) + 64 (signature) = 152
        assert_eq!(HEADER_SIZE, 152);
    }

    #[test]
    fn test_envelope_too_short() {
        let short_data = Bytes::from(vec![0u8; 50]);
        let result = NscEnvelope::from_bytes(short_data);
        assert!(matches!(result, Err(TransportError::InvalidMessage(_))));
    }

    #[test]
    fn test_envelope_wrong_version() {
        let mut data = vec![0u8; HEADER_SIZE + 64];
        data[0] = 0xFF; // Wrong version
        let result = NscEnvelope::from_bytes(Bytes::from(data));
        assert!(matches!(result, Err(TransportError::InvalidMessage(_))));
    }
}
