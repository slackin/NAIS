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
            0x30 => Some(Self::Ack),
            0x31 => Some(Self::Heartbeat),
            0x32 => Some(Self::RoutingUpdate),
            0x40 => Some(Self::IceCandidateMsg),
            0x41 => Some(Self::IceOffer),
            0x42 => Some(Self::IceAnswer),
            0x50 => Some(Self::RelayRequest),
            0x51 => Some(Self::RelayData),
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
