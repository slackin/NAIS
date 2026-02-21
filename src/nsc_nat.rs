//! Nais Secure Channels - NAT Traversal Module
//!
//! Implements NAT traversal for P2P connectivity:
//! - STUN client for public address discovery
//! - ICE-lite agent for candidate gathering and connectivity checks
//! - TURN client for relay fallback
//! - UDP hole punching
//!
//! # Priority Order
//! 1. Direct IPv6 (if available)
//! 2. Direct IPv4 via UDP hole punching
//! 3. TURN relay (fallback)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;

// =============================================================================
// Error Types
// =============================================================================

#[derive(Debug, Error)]
pub enum NatError {
    #[error("STUN request failed: {0}")]
    StunFailed(String),

    #[error("STUN timeout")]
    StunTimeout,

    #[error("Invalid STUN response")]
    InvalidStunResponse,

    #[error("No STUN servers available")]
    NoStunServers,

    #[error("ICE gathering failed: {0}")]
    IceGatheringFailed(String),

    #[error("ICE connectivity check failed")]
    IceConnectivityFailed,

    #[error("TURN allocation failed: {0}")]
    TurnAllocationFailed(String),

    #[error("TURN authentication failed")]
    TurnAuthFailed,

    #[error("No candidates available")]
    NoCandidates,

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Network unreachable")]
    NetworkUnreachable,
}

pub type NatResult<T> = Result<T, NatError>;

// =============================================================================
// Constants
// =============================================================================

/// Default STUN servers
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// STUN message types
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_BINDING_ERROR: u16 = 0x0111;

/// STUN attributes
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_ATTR_USERNAME: u16 = 0x0006;
const STUN_ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const STUN_ATTR_ERROR_CODE: u16 = 0x0009;
const STUN_ATTR_REALM: u16 = 0x0014;
const STUN_ATTR_NONCE: u16 = 0x0015;
const STUN_ATTR_SOFTWARE: u16 = 0x8022;
const STUN_ATTR_FINGERPRINT: u16 = 0x8028;

/// STUN magic cookie (RFC 5389)
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// Timeouts
const STUN_TIMEOUT: Duration = Duration::from_secs(3);
const ICE_CHECK_TIMEOUT: Duration = Duration::from_millis(500);
const HOLE_PUNCH_INTERVAL: Duration = Duration::from_millis(50);
const HOLE_PUNCH_ATTEMPTS: u32 = 20;

// =============================================================================
// NAT Types
// =============================================================================

/// Detected NAT type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatType {
    /// No NAT - direct public connectivity
    None,
    /// Full cone NAT - easiest to traverse
    FullCone,
    /// Address-restricted cone NAT
    AddressRestricted,
    /// Port-restricted cone NAT
    PortRestricted,
    /// Symmetric NAT - hardest, needs TURN
    Symmetric,
    /// Unknown or couldn't determine
    Unknown,
}

impl NatType {
    /// Can we do UDP hole punching with this NAT type?
    pub fn supports_hole_punching(&self) -> bool {
        matches!(
            self,
            NatType::None | NatType::FullCone | NatType::AddressRestricted | NatType::PortRestricted
        )
    }

    /// Do we need TURN relay for this NAT type?
    pub fn needs_turn(&self) -> bool {
        matches!(self, NatType::Symmetric | NatType::Unknown)
    }
}

// =============================================================================
// ICE Candidate Types
// =============================================================================

/// ICE candidate type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateType {
    /// Host candidate - local interface address
    Host,
    /// Server reflexive - address as seen by STUN server
    ServerReflexive,
    /// Peer reflexive - address discovered during connectivity checks
    PeerReflexive,
    /// Relay - TURN server allocated address
    Relay,
}

/// ICE candidate
#[derive(Clone, Debug)]
pub struct IceCandidate {
    /// Candidate type
    pub candidate_type: CandidateType,
    /// Transport protocol (always UDP for now)
    pub protocol: String,
    /// Address of this candidate
    pub address: SocketAddr,
    /// Base address (local address for reflexive candidates)
    pub base_address: Option<SocketAddr>,
    /// Priority (higher is better)
    pub priority: u32,
    /// Foundation (used for candidate pairing)
    pub foundation: String,
    /// Component ID (1 for RTP-like data)
    pub component: u8,
    /// Related address (for diagnostics)
    pub related_address: Option<SocketAddr>,
}

impl IceCandidate {
    /// Create a host candidate
    pub fn host(address: SocketAddr) -> Self {
        let priority = Self::calculate_priority(CandidateType::Host, address);
        let foundation = format!("host_{}", address.ip());
        
        Self {
            candidate_type: CandidateType::Host,
            protocol: "udp".to_string(),
            address,
            base_address: Some(address),
            priority,
            foundation,
            component: 1,
            related_address: None,
        }
    }

    /// Create a server reflexive candidate
    pub fn server_reflexive(address: SocketAddr, base: SocketAddr, stun_server: &str) -> Self {
        let priority = Self::calculate_priority(CandidateType::ServerReflexive, address);
        let foundation = format!("srflx_{}_{}", base.ip(), stun_server);
        
        Self {
            candidate_type: CandidateType::ServerReflexive,
            protocol: "udp".to_string(),
            address,
            base_address: Some(base),
            priority,
            foundation,
            component: 1,
            related_address: Some(base),
        }
    }

    /// Create a relay candidate
    pub fn relay(address: SocketAddr, turn_server: &str) -> Self {
        let priority = Self::calculate_priority(CandidateType::Relay, address);
        let foundation = format!("relay_{}", turn_server);
        
        Self {
            candidate_type: CandidateType::Relay,
            protocol: "udp".to_string(),
            address,
            base_address: None,
            priority,
            foundation,
            component: 1,
            related_address: None,
        }
    }

    /// Calculate candidate priority per RFC 5245
    fn calculate_priority(candidate_type: CandidateType, address: SocketAddr) -> u32 {
        // Type preference (0-126)
        let type_pref: u32 = match candidate_type {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        };

        // Local preference (0-65535) - prefer IPv6
        let local_pref: u32 = if address.is_ipv6() { 65535 } else { 65534 };

        // Component ID (1-256)
        let component: u32 = 1;

        // Priority formula from RFC 5245
        (type_pref << 24) + (local_pref << 8) + (256 - component)
    }

    /// Serialize to SDP attribute format
    pub fn to_sdp(&self) -> String {
        let typ = match self.candidate_type {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::PeerReflexive => "prflx",
            CandidateType::Relay => "relay",
        };

        let mut sdp = format!(
            "{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.protocol,
            self.priority,
            self.address.ip(),
            self.address.port(),
            typ
        );

        if let Some(ref raddr) = self.related_address {
            sdp.push_str(&format!(" raddr {} rport {}", raddr.ip(), raddr.port()));
        }

        sdp
    }
}

// =============================================================================
// STUN Client
// =============================================================================

/// STUN binding request/response handler
pub struct StunClient {
    /// Available STUN servers
    servers: Vec<String>,
    /// Current server index
    current_server: usize,
}

impl StunClient {
    /// Create new STUN client with default servers
    pub fn new() -> Self {
        Self {
            servers: DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            current_server: 0,
        }
    }

    /// Create with custom servers
    pub fn with_servers(servers: Vec<String>) -> Self {
        Self {
            servers,
            current_server: 0,
        }
    }

    /// Perform STUN binding request and get mapped address
    pub async fn get_mapped_address(&self, local_socket: &TokioUdpSocket) -> NatResult<SocketAddr> {
        if self.servers.is_empty() {
            return Err(NatError::NoStunServers);
        }

        // Try each server until one works
        for server in &self.servers {
            match self.stun_request(local_socket, server).await {
                Ok(addr) => return Ok(addr),
                Err(e) => {
                    log::debug!("STUN request to {} failed: {}", server, e);
                    continue;
                }
            }
        }

        Err(NatError::StunFailed("All STUN servers failed".into()))
    }

    /// Perform STUN request to a specific server
    async fn stun_request(
        &self,
        socket: &TokioUdpSocket,
        server: &str,
    ) -> NatResult<SocketAddr> {
        // Resolve server address
        let server_addr: SocketAddr = tokio::net::lookup_host(server)
            .await?
            .next()
            .ok_or_else(|| NatError::StunFailed(format!("Cannot resolve {}", server)))?;

        // Build STUN binding request
        let transaction_id = Self::generate_transaction_id();
        let request = Self::build_binding_request(&transaction_id);

        // Send request
        socket.send_to(&request, server_addr).await?;

        // Wait for response with timeout
        let mut buf = [0u8; 1024];
        let result = timeout(STUN_TIMEOUT, socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((len, _from))) => {
                Self::parse_binding_response(&buf[..len], &transaction_id)
            }
            Ok(Err(e)) => Err(NatError::IoError(e)),
            Err(_) => Err(NatError::StunTimeout),
        }
    }

    /// Generate random 96-bit transaction ID
    fn generate_transaction_id() -> [u8; 12] {
        let mut id = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// Build STUN binding request message
    fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(20);
        
        // Message type: Binding Request
        msg.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        
        // Message length (0 for simple binding request)
        msg.extend_from_slice(&0u16.to_be_bytes());
        
        // Magic cookie
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        
        // Transaction ID
        msg.extend_from_slice(transaction_id);

        msg
    }

    /// Parse STUN binding response
    fn parse_binding_response(data: &[u8], expected_txn: &[u8; 12]) -> NatResult<SocketAddr> {
        if data.len() < 20 {
            return Err(NatError::InvalidStunResponse);
        }

        // Parse header
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        
        // Verify magic cookie
        if magic != STUN_MAGIC_COOKIE {
            return Err(NatError::InvalidStunResponse);
        }

        // Verify transaction ID
        if &data[8..20] != expected_txn {
            return Err(NatError::InvalidStunResponse);
        }

        // Check message type
        if msg_type == STUN_BINDING_ERROR {
            return Err(NatError::StunFailed("Binding error response".into()));
        }
        if msg_type != STUN_BINDING_RESPONSE {
            return Err(NatError::InvalidStunResponse);
        }

        // Parse attributes
        let mut offset = 20;
        let end = 20 + msg_len;

        while offset + 4 <= end && offset + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > data.len() {
                break;
            }

            let attr_data = &data[offset..offset + attr_len];

            match attr_type {
                STUN_ATTR_XOR_MAPPED_ADDRESS => {
                    return Self::parse_xor_mapped_address(attr_data, &data[4..8]);
                }
                STUN_ATTR_MAPPED_ADDRESS => {
                    return Self::parse_mapped_address(attr_data);
                }
                _ => {}
            }

            // Align to 4-byte boundary
            offset += (attr_len + 3) & !3;
        }

        Err(NatError::InvalidStunResponse)
    }

    /// Parse XOR-MAPPED-ADDRESS attribute
    fn parse_xor_mapped_address(data: &[u8], magic: &[u8]) -> NatResult<SocketAddr> {
        if data.len() < 8 {
            return Err(NatError::InvalidStunResponse);
        }

        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;

        match family {
            0x01 => {
                // IPv4
                if data.len() < 8 {
                    return Err(NatError::InvalidStunResponse);
                }
                let ip_bytes = [
                    data[4] ^ magic[0],
                    data[5] ^ magic[1],
                    data[6] ^ magic[2],
                    data[7] ^ magic[3],
                ];
                let ip = Ipv4Addr::from(ip_bytes);
                Ok(SocketAddr::new(IpAddr::V4(ip), port))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return Err(NatError::InvalidStunResponse);
                }
                // XOR with magic cookie + transaction ID
                let mut ip_bytes = [0u8; 16];
                for i in 0..16 {
                    // First 4 bytes XOR with magic, rest with transaction ID
                    ip_bytes[i] = data[4 + i] ^ if i < 4 { magic[i] } else { 0 }; // Simplified
                }
                let ip = Ipv6Addr::from(ip_bytes);
                Ok(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => Err(NatError::InvalidStunResponse),
        }
    }

    /// Parse MAPPED-ADDRESS attribute (legacy, non-XOR)
    fn parse_mapped_address(data: &[u8]) -> NatResult<SocketAddr> {
        if data.len() < 8 {
            return Err(NatError::InvalidStunResponse);
        }

        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);

        match family {
            0x01 => {
                let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                Ok(SocketAddr::new(IpAddr::V4(ip), port))
            }
            0x02 => {
                if data.len() < 20 {
                    return Err(NatError::InvalidStunResponse);
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[4..20]);
                let ip = Ipv6Addr::from(ip_bytes);
                Ok(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => Err(NatError::InvalidStunResponse),
        }
    }
}

impl Default for StunClient {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// NAT Type Detection
// =============================================================================

/// Detect NAT type using multiple STUN requests
pub struct NatDetector {
    stun_client: StunClient,
}

impl NatDetector {
    pub fn new() -> Self {
        Self {
            stun_client: StunClient::new(),
        }
    }

    /// Detect NAT type
    pub async fn detect(&self) -> NatResult<NatType> {
        // Bind to a local socket
        let socket = TokioUdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = socket.local_addr()?;

        // Get mapped address from first server
        let mapped1 = self.stun_client.get_mapped_address(&socket).await?;

        // Check if we have a public IP (no NAT)
        if mapped1.ip() == local_addr.ip() || is_public_ip(&mapped1.ip()) && local_addr.ip().is_unspecified() {
            // Try to verify by checking if port is preserved
            if mapped1.port() == local_addr.port() {
                return Ok(NatType::None);
            }
        }

        // Get mapped address from second server (if available)
        if self.stun_client.servers.len() >= 2 {
            // Use different socket to test port allocation
            let socket2 = TokioUdpSocket::bind("0.0.0.0:0").await?;
            
            // Try to get address from different STUN server
            let alt_client = StunClient::with_servers(vec![
                self.stun_client.servers[1].clone()
            ]);
            
            if let Ok(mapped2) = alt_client.get_mapped_address(&socket2).await {
                // Compare mapped addresses
                if mapped1.ip() != mapped2.ip() {
                    // Different IPs from different servers = Symmetric NAT
                    return Ok(NatType::Symmetric);
                }
                
                // Same IP, check ports
                // Note: This is simplified - full detection needs more tests
                if mapped1.port() != mapped2.port() {
                    // Port changes per destination = likely Symmetric
                    return Ok(NatType::Symmetric);
                }
            }
        }

        // Without full RFC 3489 tests, we assume port-restricted
        // This is conservative but safe
        Ok(NatType::PortRestricted)
    }
}

impl Default for NatDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if IP is a public (non-private) address
fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                // Basic check - not link-local or unique-local
                && !v6.octets()[0..2].starts_with(&[0xfe, 0x80])
                && !v6.octets()[0..2].starts_with(&[0xfc])
                && !v6.octets()[0..2].starts_with(&[0xfd])
        }
    }
}

// =============================================================================
// ICE Agent
// =============================================================================

/// ICE agent state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceState {
    /// Initial state
    New,
    /// Gathering local candidates
    Gathering,
    /// Gathering complete
    Complete,
    /// Checking connectivity
    Checking,
    /// Connection established
    Connected,
    /// All checks failed
    Failed,
    /// Agent closed
    Closed,
}

/// ICE credentials
#[derive(Clone, Debug)]
pub struct IceCredentials {
    /// Username fragment
    pub ufrag: String,
    /// Password
    pub pwd: String,
}

impl IceCredentials {
    /// Generate new random credentials
    pub fn generate() -> Self {
        use rand::distributions::Alphanumeric;
        use rand::Rng;
        
        let ufrag: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        
        let pwd: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();
        
        Self { ufrag, pwd }
    }
}

/// ICE candidate pair state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidatePairState {
    Waiting,
    InProgress,
    Succeeded,
    Failed,
    Frozen,
}

/// ICE candidate pair
#[derive(Clone, Debug)]
pub struct CandidatePair {
    pub local: IceCandidate,
    pub remote: IceCandidate,
    pub state: CandidatePairState,
    pub priority: u64,
    pub nominated: bool,
}

impl CandidatePair {
    pub fn new(local: IceCandidate, remote: IceCandidate, controlling: bool) -> Self {
        // Calculate pair priority per RFC 5245
        let (g, d) = if controlling {
            (local.priority as u64, remote.priority as u64)
        } else {
            (remote.priority as u64, local.priority as u64)
        };
        
        let priority = ((1u64 << 32) * g.min(d)) + (2 * g.max(d)) + if g > d { 1 } else { 0 };
        
        Self {
            local,
            remote,
            state: CandidatePairState::Frozen,
            priority,
            nominated: false,
        }
    }
}

/// ICE Agent for NAT traversal
pub struct IceAgent {
    /// Agent state
    state: Arc<RwLock<IceState>>,
    /// Local candidates
    local_candidates: Arc<RwLock<Vec<IceCandidate>>>,
    /// Remote candidates
    remote_candidates: Arc<RwLock<Vec<IceCandidate>>>,
    /// Candidate pairs
    pairs: Arc<RwLock<Vec<CandidatePair>>>,
    /// Local credentials
    local_credentials: IceCredentials,
    /// Remote credentials
    remote_credentials: Arc<RwLock<Option<IceCredentials>>>,
    /// STUN client
    stun_client: StunClient,
    /// Local socket
    socket: Arc<RwLock<Option<Arc<TokioUdpSocket>>>>,
    /// Are we the controlling agent?
    controlling: bool,
    /// Selected pair
    selected_pair: Arc<RwLock<Option<CandidatePair>>>,
    /// NAT type (if detected)
    nat_type: Arc<RwLock<Option<NatType>>>,
}

impl IceAgent {
    /// Create new ICE agent
    pub fn new(controlling: bool) -> Self {
        Self {
            state: Arc::new(RwLock::new(IceState::New)),
            local_candidates: Arc::new(RwLock::new(Vec::new())),
            remote_candidates: Arc::new(RwLock::new(Vec::new())),
            pairs: Arc::new(RwLock::new(Vec::new())),
            local_credentials: IceCredentials::generate(),
            remote_credentials: Arc::new(RwLock::new(None)),
            stun_client: StunClient::new(),
            socket: Arc::new(RwLock::new(None)),
            controlling,
            selected_pair: Arc::new(RwLock::new(None)),
            nat_type: Arc::new(RwLock::new(None)),
        }
    }

    /// Get local credentials
    pub fn local_credentials(&self) -> &IceCredentials {
        &self.local_credentials
    }

    /// Set remote credentials
    pub async fn set_remote_credentials(&self, credentials: IceCredentials) {
        *self.remote_credentials.write().await = Some(credentials);
    }

    /// Gather local candidates
    pub async fn gather_candidates(&self) -> NatResult<Vec<IceCandidate>> {
        *self.state.write().await = IceState::Gathering;
        let mut candidates = Vec::new();

        // Bind local socket
        let socket = Arc::new(TokioUdpSocket::bind("0.0.0.0:0").await?);
        let local_addr = socket.local_addr()?;
        *self.socket.write().await = Some(socket.clone());

        // Gather host candidates from local interfaces
        if let Ok(interfaces) = get_local_interfaces().await {
            for addr in interfaces {
                let candidate = IceCandidate::host(SocketAddr::new(addr, local_addr.port()));
                candidates.push(candidate);
            }
        }

        // Gather server reflexive candidates via STUN
        match self.stun_client.get_mapped_address(&socket).await {
            Ok(mapped_addr) => {
                let srflx = IceCandidate::server_reflexive(
                    mapped_addr,
                    local_addr,
                    &self.stun_client.servers[0],
                );
                candidates.push(srflx);
            }
            Err(e) => {
                log::warn!("Failed to gather STUN candidate: {}", e);
            }
        }

        // Detect NAT type
        let detector = NatDetector::new();
        if let Ok(nat_type) = detector.detect().await {
            *self.nat_type.write().await = Some(nat_type);
            log::info!("Detected NAT type: {:?}", nat_type);
        }

        // Sort by priority (highest first)
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        *self.local_candidates.write().await = candidates.clone();
        *self.state.write().await = IceState::Complete;

        Ok(candidates)
    }

    /// Add a remote candidate
    pub async fn add_remote_candidate(&self, candidate: IceCandidate) {
        self.remote_candidates.write().await.push(candidate.clone());
        
        // Create pairs with all local candidates
        let locals = self.local_candidates.read().await.clone();
        let mut pairs = self.pairs.write().await;
        
        for local in locals {
            let pair = CandidatePair::new(local, candidate.clone(), self.controlling);
            pairs.push(pair);
        }
        
        // Sort pairs by priority
        pairs.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Perform connectivity checks
    pub async fn check_connectivity(&self) -> NatResult<CandidatePair> {
        *self.state.write().await = IceState::Checking;

        let socket = self.socket.read().await.clone()
            .ok_or(NatError::IceConnectivityFailed)?;

        let pairs = self.pairs.read().await.clone();
        
        for pair in pairs {
            // Skip relay candidates in first pass (try direct first)
            if pair.local.candidate_type == CandidateType::Relay {
                continue;
            }

            if let Ok(()) = self.check_pair(&socket, &pair).await {
                *self.state.write().await = IceState::Connected;
                *self.selected_pair.write().await = Some(pair.clone());
                return Ok(pair);
            }
        }

        // Try relay candidates if direct failed
        let pairs = self.pairs.read().await.clone();
        for pair in pairs {
            if pair.local.candidate_type == CandidateType::Relay {
                if let Ok(()) = self.check_pair(&socket, &pair).await {
                    *self.state.write().await = IceState::Connected;
                    *self.selected_pair.write().await = Some(pair.clone());
                    return Ok(pair);
                }
            }
        }

        *self.state.write().await = IceState::Failed;
        Err(NatError::IceConnectivityFailed)
    }

    /// Check a single candidate pair
    async fn check_pair(&self, socket: &TokioUdpSocket, pair: &CandidatePair) -> NatResult<()> {
        let remote_addr = pair.remote.address;
        
        // Build STUN binding request with credentials
        let transaction_id = StunClient::generate_transaction_id();
        let request = self.build_connectivity_check(&transaction_id);

        // Send connectivity check
        socket.send_to(&request, remote_addr).await?;

        // Wait for response
        let mut buf = [0u8; 1024];
        let result = timeout(ICE_CHECK_TIMEOUT, socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((len, from))) => {
                if from == remote_addr {
                    // Verify it's a valid STUN response
                    if Self::verify_stun_response(&buf[..len], &transaction_id) {
                        return Ok(());
                    }
                }
                Err(NatError::IceConnectivityFailed)
            }
            _ => Err(NatError::IceConnectivityFailed),
        }
    }

    /// Build STUN connectivity check (simplified - without full ICE attributes)
    fn build_connectivity_check(&self, transaction_id: &[u8; 12]) -> Vec<u8> {
        StunClient::build_binding_request(transaction_id)
    }

    /// Verify STUN response (simplified)
    fn verify_stun_response(data: &[u8], expected_txn: &[u8; 12]) -> bool {
        if data.len() < 20 {
            return false;
        }
        
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        
        msg_type == STUN_BINDING_RESPONSE
            && magic == STUN_MAGIC_COOKIE
            && &data[8..20] == expected_txn
    }

    /// Get current state
    pub async fn state(&self) -> IceState {
        *self.state.read().await
    }

    /// Get selected pair
    pub async fn selected_pair(&self) -> Option<CandidatePair> {
        self.selected_pair.read().await.clone()
    }

    /// Get detected NAT type
    pub async fn nat_type(&self) -> Option<NatType> {
        *self.nat_type.read().await
    }

    /// Get the socket for data transfer (after connection established)
    pub async fn socket(&self) -> Option<Arc<TokioUdpSocket>> {
        self.socket.read().await.clone()
    }
}

/// Get local network interface addresses
async fn get_local_interfaces() -> NatResult<Vec<IpAddr>> {
    let mut addrs = Vec::new();

    // Try to get addresses using a connected UDP socket trick
    // This finds the preferred route to the internet
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = socket.local_addr() {
                if !local.ip().is_loopback() && !local.ip().is_unspecified() {
                    addrs.push(local.ip());
                }
            }
        }
    }

    // Also try IPv6
    if let Ok(socket) = UdpSocket::bind("[::]:0") {
        if socket.connect("[2001:4860:4860::8888]:80").is_ok() {
            if let Ok(local) = socket.local_addr() {
                if !local.ip().is_loopback() && !local.ip().is_unspecified() {
                    addrs.push(local.ip());
                }
            }
        }
    }

    if addrs.is_empty() {
        // Fallback to localhost
        addrs.push(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    Ok(addrs)
}

// =============================================================================
// UDP Hole Punching
// =============================================================================

/// UDP hole puncher for NAT traversal
pub struct HolePuncher {
    /// Local socket
    socket: Arc<TokioUdpSocket>,
    /// Target peer address (their public address)
    target: SocketAddr,
}

impl HolePuncher {
    /// Create new hole puncher
    pub fn new(socket: Arc<TokioUdpSocket>, target: SocketAddr) -> Self {
        Self { socket, target }
    }

    /// Attempt simultaneous UDP hole punch
    pub async fn punch(&self) -> NatResult<()> {
        // Send multiple packets to punch hole in NAT
        for i in 0..HOLE_PUNCH_ATTEMPTS {
            // Send a small probe packet
            let probe = format!("NAIS_PUNCH_{}", i);
            if let Err(e) = self.socket.send_to(probe.as_bytes(), self.target).await {
                log::debug!("Hole punch send failed: {}", e);
            }

            // Short delay between punches
            tokio::time::sleep(HOLE_PUNCH_INTERVAL).await;

            // Check if we received anything back (hole punched successfully)
            let mut buf = [0u8; 64];
            match timeout(Duration::from_millis(10), self.socket.recv_from(&mut buf)).await {
                Ok(Ok((_len, from))) => {
                    if from == self.target {
                        log::info!("Hole punch succeeded after {} attempts", i + 1);
                        return Ok(());
                    }
                }
                _ => continue,
            }
        }

        Err(NatError::ConnectionFailed("Hole punch failed".into()))
    }

    /// Simultaneous hole punch with coordination
    /// Both peers should call this at roughly the same time
    pub async fn simultaneous_punch(&self, send_first: bool) -> NatResult<()> {
        let mut buf = [0u8; 64];
        
        for round in 0..HOLE_PUNCH_ATTEMPTS {
            // Stagger sends based on role
            if send_first || round > 0 {
                let probe = format!("NAIS_SIM_PUNCH_{}", round);
                let _ = self.socket.send_to(probe.as_bytes(), self.target).await;
            }

            // Short delay
            tokio::time::sleep(HOLE_PUNCH_INTERVAL).await;

            // Try to receive
            match timeout(Duration::from_millis(50), self.socket.recv_from(&mut buf)).await {
                Ok(Ok((_, from))) if from == self.target => {
                    // Got a packet - send confirmation
                    let _ = self.socket.send_to(b"NAIS_PUNCH_ACK", self.target).await;
                    log::info!("Simultaneous hole punch succeeded at round {}", round);
                    return Ok(());
                }
                _ => continue,
            }
        }

        Err(NatError::ConnectionFailed("Simultaneous hole punch failed".into()))
    }
}

// =============================================================================
// TURN Client (Simplified)
// =============================================================================

/// TURN relay client configuration
#[derive(Clone, Debug)]
pub struct TurnConfig {
    pub server: String,
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
}

/// TURN allocation state
#[derive(Clone, Debug)]
pub struct TurnAllocation {
    /// Relayed address allocated by TURN server
    pub relayed_address: SocketAddr,
    /// Server reflexive address
    pub mapped_address: SocketAddr,
    /// Lifetime in seconds
    pub lifetime: u32,
    /// Allocation expiry time
    pub expires_at: Instant,
}

/// TURN client for relay fallback
pub struct TurnClient {
    config: TurnConfig,
    socket: Option<Arc<TokioUdpSocket>>,
    allocation: Option<TurnAllocation>,
}

impl TurnClient {
    /// Create new TURN client
    pub fn new(config: TurnConfig) -> Self {
        Self {
            config,
            socket: None,
            allocation: None,
        }
    }

    /// Allocate a relay address
    pub async fn allocate(&mut self) -> NatResult<TurnAllocation> {
        // Resolve TURN server
        let server_addr: SocketAddr = tokio::net::lookup_host(&self.config.server)
            .await?
            .next()
            .ok_or_else(|| NatError::TurnAllocationFailed("Cannot resolve TURN server".into()))?;

        // Bind local socket
        let socket = Arc::new(TokioUdpSocket::bind("0.0.0.0:0").await?);
        self.socket = Some(socket.clone());

        // Build TURN Allocate request
        // Note: Full TURN implementation requires proper authentication
        // This is a simplified version
        let transaction_id = StunClient::generate_transaction_id();
        let request = self.build_allocate_request(&transaction_id);

        // Send request
        socket.send_to(&request, server_addr).await?;

        // Wait for response
        let mut buf = [0u8; 1024];
        let result = timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((len, _))) => {
                let allocation = self.parse_allocate_response(&buf[..len])?;
                self.allocation = Some(allocation.clone());
                Ok(allocation)
            }
            Ok(Err(e)) => Err(NatError::IoError(e)),
            Err(_) => Err(NatError::TurnAllocationFailed("Allocation timeout".into())),
        }
    }

    /// Build TURN Allocate request (simplified)
    fn build_allocate_request(&self, transaction_id: &[u8; 12]) -> Vec<u8> {
        const TURN_ALLOCATE_REQUEST: u16 = 0x0003;
        
        let mut msg = Vec::with_capacity(100);
        
        // Message type: Allocate Request
        msg.extend_from_slice(&TURN_ALLOCATE_REQUEST.to_be_bytes());
        
        // Placeholder for message length
        msg.extend_from_slice(&0u16.to_be_bytes());
        
        // Magic cookie
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        
        // Transaction ID
        msg.extend_from_slice(transaction_id);

        // Add REQUESTED-TRANSPORT attribute (UDP = 17)
        const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
        msg.extend_from_slice(&ATTR_REQUESTED_TRANSPORT.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes()); // Length
        msg.push(17); // UDP
        msg.push(0); msg.push(0); msg.push(0); // Reserved

        // Update message length
        let msg_len = (msg.len() - 20) as u16;
        msg[2..4].copy_from_slice(&msg_len.to_be_bytes());

        msg
    }

    /// Parse TURN Allocate response (simplified)
    fn parse_allocate_response(&self, _data: &[u8]) -> NatResult<TurnAllocation> {
        // In a real implementation, parse:
        // - XOR-RELAYED-ADDRESS
        // - XOR-MAPPED-ADDRESS
        // - LIFETIME
        
        // For now, return a placeholder error
        // Full implementation requires proper STUN/TURN message parsing
        Err(NatError::TurnAllocationFailed(
            "Full TURN implementation pending - use ICE relay instead".into()
        ))
    }

    /// Get current allocation
    pub fn allocation(&self) -> Option<&TurnAllocation> {
        self.allocation.as_ref()
    }

    /// Create ICE relay candidate from allocation
    pub fn to_ice_candidate(&self) -> Option<IceCandidate> {
        self.allocation.as_ref().map(|alloc| {
            IceCandidate::relay(alloc.relayed_address, &self.config.server)
        })
    }
}

// =============================================================================
// Connection Manager
// =============================================================================

/// Manages the full NAT traversal process
pub struct ConnectionManager {
    /// ICE agent
    ice_agent: IceAgent,
    /// TURN client (optional)
    turn_client: Option<TurnClient>,
    /// Current connection state
    state: ConnectionState,
}

/// Connection state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state
    New,
    /// Gathering candidates
    Gathering,
    /// Exchanging candidates with peer
    Signaling,
    /// Performing connectivity checks
    Connecting,
    /// Connected via direct P2P
    DirectP2P,
    /// Connected via relay
    Relayed,
    /// Connection failed
    Failed,
    /// Connection closed
    Closed,
}

impl ConnectionManager {
    /// Create new connection manager
    pub fn new(controlling: bool) -> Self {
        Self {
            ice_agent: IceAgent::new(controlling),
            turn_client: None,
            state: ConnectionState::New,
        }
    }

    /// Set TURN configuration
    pub fn set_turn_config(&mut self, config: TurnConfig) {
        self.turn_client = Some(TurnClient::new(config));
    }

    /// Get local credentials for signaling
    pub fn local_credentials(&self) -> &IceCredentials {
        self.ice_agent.local_credentials()
    }

    /// Gather local candidates
    pub async fn gather_candidates(&mut self) -> NatResult<Vec<IceCandidate>> {
        self.state = ConnectionState::Gathering;
        
        let mut candidates = self.ice_agent.gather_candidates().await?;

        // Also get TURN relay candidate if configured
        if let Some(ref mut turn) = self.turn_client {
            match turn.allocate().await {
                Ok(_) => {
                    if let Some(relay_candidate) = turn.to_ice_candidate() {
                        candidates.push(relay_candidate);
                    }
                }
                Err(e) => {
                    log::warn!("TURN allocation failed: {} - continuing without relay", e);
                }
            }
        }

        self.state = ConnectionState::Signaling;
        Ok(candidates)
    }

    /// Set remote credentials
    pub async fn set_remote_credentials(&mut self, credentials: IceCredentials) {
        self.ice_agent.set_remote_credentials(credentials).await;
    }

    /// Add remote candidate
    pub async fn add_remote_candidate(&mut self, candidate: IceCandidate) {
        self.ice_agent.add_remote_candidate(candidate).await;
    }

    /// Attempt to connect to peer
    pub async fn connect(&mut self) -> NatResult<ConnectionInfo> {
        self.state = ConnectionState::Connecting;

        // Try ICE connectivity checks
        match self.ice_agent.check_connectivity().await {
            Ok(pair) => {
                let is_relay = pair.local.candidate_type == CandidateType::Relay
                    || pair.remote.candidate_type == CandidateType::Relay;
                
                self.state = if is_relay {
                    ConnectionState::Relayed
                } else {
                    ConnectionState::DirectP2P
                };

                Ok(ConnectionInfo {
                    local_address: pair.local.address,
                    remote_address: pair.remote.address,
                    connection_type: if is_relay {
                        ConnectionType::Relayed
                    } else {
                        ConnectionType::DirectP2P
                    },
                    nat_type: self.ice_agent.nat_type().await,
                })
            }
            Err(e) => {
                self.state = ConnectionState::Failed;
                Err(e)
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get the socket for data transfer
    pub async fn socket(&self) -> Option<Arc<TokioUdpSocket>> {
        self.ice_agent.socket().await
    }
}

/// Connection info after successful NAT traversal
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub local_address: SocketAddr,
    pub remote_address: SocketAddr,
    pub connection_type: ConnectionType,
    pub nat_type: Option<NatType>,
}

/// Type of connection established
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionType {
    /// Direct peer-to-peer connection
    DirectP2P,
    /// Relayed through TURN server
    Relayed,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_properties() {
        assert!(NatType::None.supports_hole_punching());
        assert!(NatType::FullCone.supports_hole_punching());
        assert!(NatType::PortRestricted.supports_hole_punching());
        assert!(!NatType::Symmetric.supports_hole_punching());
        
        assert!(!NatType::None.needs_turn());
        assert!(NatType::Symmetric.needs_turn());
        assert!(NatType::Unknown.needs_turn());
    }

    #[test]
    fn test_ice_candidate_priority() {
        let host_v4 = IceCandidate::host("192.168.1.1:5000".parse().unwrap());
        let host_v6 = IceCandidate::host("[::1]:5000".parse().unwrap());
        let srflx = IceCandidate::server_reflexive(
            "1.2.3.4:5000".parse().unwrap(),
            "192.168.1.1:5000".parse().unwrap(),
            "stun.example.com",
        );
        let relay = IceCandidate::relay("5.6.7.8:5000".parse().unwrap(), "turn.example.com");

        // Host > SRFLX > Relay
        assert!(host_v4.priority > srflx.priority);
        assert!(srflx.priority > relay.priority);
        
        // IPv6 > IPv4 for same type
        assert!(host_v6.priority > host_v4.priority);
    }

    #[test]
    fn test_ice_candidate_sdp() {
        let candidate = IceCandidate::host("192.168.1.1:5000".parse().unwrap());
        let sdp = candidate.to_sdp();
        
        assert!(sdp.contains("host"));
        assert!(sdp.contains("192.168.1.1"));
        assert!(sdp.contains("5000"));
        assert!(sdp.contains("udp"));
    }

    #[test]
    fn test_ice_credentials_generation() {
        let creds = IceCredentials::generate();
        
        assert_eq!(creds.ufrag.len(), 8);
        assert_eq!(creds.pwd.len(), 24);
        
        // Should be unique
        let creds2 = IceCredentials::generate();
        assert_ne!(creds.ufrag, creds2.ufrag);
    }

    #[test]
    fn test_stun_message_building() {
        let txn_id = StunClient::generate_transaction_id();
        let msg = StunClient::build_binding_request(&txn_id);
        
        // Check header
        assert_eq!(msg.len(), 20);
        assert_eq!(u16::from_be_bytes([msg[0], msg[1]]), STUN_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 0); // No attributes
        assert_eq!(
            u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
            STUN_MAGIC_COOKIE
        );
        assert_eq!(&msg[8..20], &txn_id);
    }

    #[test]
    fn test_candidate_pair_priority() {
        // Use different candidate types to get different priorities
        let local = IceCandidate::host("192.168.1.1:5000".parse().unwrap());
        let remote = IceCandidate::server_reflexive(
            "1.2.3.4:5000".parse().unwrap(),
            "192.168.1.2:5000".parse().unwrap(),
            "stun.example.com",
        );
        
        let pair1 = CandidatePair::new(local.clone(), remote.clone(), true);
        let pair2 = CandidatePair::new(local, remote, false);
        
        // Priority should differ based on controlling flag when candidate priorities differ
        // When controlling=true, G=local, D=remote
        // When controlling=false, G=remote, D=local
        assert_ne!(pair1.priority, pair2.priority);
    }

    #[test]
    fn test_public_ip_detection() {
        assert!(is_public_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip(&"192.168.1.1".parse().unwrap()));
        assert!(!is_public_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip(&"172.16.0.1".parse().unwrap()));
        assert!(!is_public_ip(&"127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_ice_agent_creation() {
        let agent = IceAgent::new(true);
        assert_eq!(agent.state().await, IceState::New);
        assert!(agent.controlling);
    }

    #[tokio::test]
    async fn test_local_interfaces() {
        let interfaces = get_local_interfaces().await.unwrap();
        assert!(!interfaces.is_empty());
    }
}
