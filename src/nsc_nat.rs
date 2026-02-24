//! Nais Secure Channels - NAT Traversal Module
//!
//! Implements NAT traversal for P2P connectivity:
//! - UPnP port mapping (highest priority - direct connectivity)
//! - STUN client for public address discovery
//! - ICE-lite agent for candidate gathering and connectivity checks
//! - TURN client for relay fallback
//! - UDP hole punching
//!
//! # Priority Order
//! 1. UPnP port-mapped address (most reliable for direct P2P)
//! 2. Direct IPv6 (if available)
//! 3. Direct IPv4 via UDP hole punching (STUN-discovered)
//! 4. TURN relay (fallback - rarely needed with UPnP)

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;
use igd_next::{SearchOptions, PortMappingProtocol};

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

    #[error("UPnP failed: {0}")]
    UPnPFailed(String),
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
/// Timeout for bidirectional ICE check - give more time for both directions
const ICE_BIDIR_CHECK_TIMEOUT: Duration = Duration::from_millis(1500);
const HOLE_PUNCH_INTERVAL: Duration = Duration::from_millis(50);
const HOLE_PUNCH_ATTEMPTS: u32 = 20;

/// UPnP lease duration (3 hours)
const UPNP_LEASE_DURATION: u32 = 3 * 60 * 60;

// =============================================================================
// UPnP Port Mapping
// =============================================================================

/// Represents an active UPnP port mapping for NAT traversal
#[derive(Clone, Debug)]
pub struct UPnPMapping {
    /// External port that was mapped
    pub external_port: u16,
    /// Local port it maps to
    pub local_port: u16,
    /// Protocol (UDP for QUIC)
    pub protocol: PortMappingProtocol,
    /// External IP address
    pub external_ip: IpAddr,
    /// Description of the mapping
    pub description: String,
}

impl UPnPMapping {
    /// Remove this port mapping from the gateway
    pub fn remove(&self) -> Result<(), String> {
        let options = SearchOptions::default();
        let gateway = igd_next::search_gateway(options)
            .map_err(|e| format!("Failed to find gateway: {}", e))?;
        
        gateway.remove_port(self.protocol, self.external_port)
            .map_err(|e| format!("Failed to remove port mapping: {}", e))?;
        
        log::info!("Removed UPnP port mapping: external {} -> local {}", self.external_port, self.local_port);
        Ok(())
    }
}

impl Drop for UPnPMapping {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            log::debug!("Failed to clean up UPnP mapping on drop: {}", e);
        }
    }
}

/// UPnP port mapper for creating port forwards on the router
pub struct UPnPPortMapper;

impl UPnPPortMapper {
    /// Attempt to create a UPnP port mapping for P2P connectivity
    /// Returns the mapping info on success
    pub fn create_mapping(local_port: u16, description: &str) -> NatResult<UPnPMapping> {
        log::info!("Attempting UPnP port mapping for local port {}...", local_port);
        
        let options = SearchOptions {
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        };
        
        let gateway = igd_next::search_gateway(options)
            .map_err(|e| NatError::UPnPFailed(format!("No UPnP gateway found: {}", e)))?;
        
        log::info!("Found UPnP gateway at: {}", gateway);
        
        // Get our local IP
        let local_ip = get_local_ip_sync()
            .ok_or_else(|| NatError::UPnPFailed("Failed to get local IP".into()))?;
        
        let local_addr_str = format!("{}:{}", local_ip, local_port);
        let local_addr_v4: SocketAddrV4 = local_addr_str.parse()
            .map_err(|e| NatError::UPnPFailed(format!("Invalid local address: {}", e)))?;
        let local_addr: SocketAddr = local_addr_v4.into();
        
        // Get external IP from gateway
        let external_ip = gateway.get_external_ip()
            .map_err(|e| NatError::UPnPFailed(format!("Failed to get external IP: {}", e)))?;
        
        // Check for CGNAT (carrier-grade NAT) - UPnP won't help here
        // Also extract the IPv4 address for the mapping
        let external_ip_v4 = match external_ip {
            IpAddr::V4(ipv4) => {
                // Check for CGNAT/private IP
                if ipv4.is_private() || ipv4.is_loopback() 
                    || (ipv4.octets()[0] == 100 && ipv4.octets()[1] >= 64 && ipv4.octets()[1] <= 127) {
                    log::warn!("CGNAT detected - router external IP {} is not public", ipv4);
                    log::warn!("UPnP cannot bypass CGNAT, will need relay fallback");
                    return Err(NatError::UPnPFailed("CGNAT detected - external IP is not public".into()));
                }
                ipv4
            }
            IpAddr::V6(_) => {
                // IPv6 doesn't typically use UPnP for NAT traversal
                return Err(NatError::UPnPFailed("IPv6 gateway - UPnP not needed".into()));
            }
        };
        
        log::info!("Router external IP: {} (public)", external_ip_v4);
        
        // Try to map the same port, or find an available one
        let mut external_port = local_port;
        let mut attempts = 0;
        
        loop {
            match gateway.add_port(
                PortMappingProtocol::UDP,
                external_port,
                local_addr,
                UPNP_LEASE_DURATION,
                description,
            ) {
                Ok(()) => {
                    log::info!("=== UPnP MAPPING CREATED ===");
                    log::info!("  External: {}:{} (UDP)", external_ip_v4, external_port);
                    log::info!("  Internal: {} (UDP)", local_addr);
                    log::info!("  Direct P2P connections now possible!");
                    
                    return Ok(UPnPMapping {
                        external_port,
                        local_port,
                        protocol: PortMappingProtocol::UDP,
                        external_ip: IpAddr::V4(external_ip_v4),
                        description: description.to_string(),
                    });
                }
                Err(igd_next::AddPortError::PortInUse) => {
                    attempts += 1;
                    if attempts >= 10 {
                        return Err(NatError::UPnPFailed("No available ports after 10 attempts".into()));
                    }
                    external_port = external_port.saturating_add(1);
                    if external_port < 1024 {
                        external_port = 49152; // Jump to dynamic port range
                    }
                    log::debug!("Port {} in use, trying {}", external_port - 1, external_port);
                }
                Err(e) => {
                    return Err(NatError::UPnPFailed(format!("Failed to add port mapping: {}", e)));
                }
            }
        }
    }
    
    /// Check if UPnP is available on this network
    pub fn is_available() -> bool {
        let options = SearchOptions {
            timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        igd_next::search_gateway(options).is_ok()
    }
}

/// Get local IP address (sync version)
fn get_local_ip_sync() -> Option<String> {
    // Try to connect to a public IP to determine our local interface
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let local_addr = socket.local_addr().ok()?;
    Some(local_addr.ip().to_string())
}

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
    /// UPnP port-mapped - external address with UPnP port forward (highest priority)
    PortMapped,
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

    /// Create a UPnP port-mapped candidate (highest priority - direct connectivity)
    pub fn port_mapped(external_address: SocketAddr, local_address: SocketAddr) -> Self {
        let priority = Self::calculate_priority(CandidateType::PortMapped, external_address);
        let foundation = format!("upnp_{}", external_address.ip());
        
        Self {
            candidate_type: CandidateType::PortMapped,
            protocol: "udp".to_string(),
            address: external_address,
            base_address: Some(local_address),
            priority,
            foundation,
            component: 1,
            related_address: Some(local_address),
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
        // Type preference (0-126) - higher is better
        // Host candidates get highest priority so LAN peers try local IPs first
        let type_pref: u32 = match candidate_type {
            CandidateType::Host => 126,         // Local IPs - best for LAN-to-LAN
            CandidateType::PortMapped => 120,   // UPnP external address - good for WAN
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
            CandidateType::PortMapped => "upnp", // UPnP port-mapped addresses
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
    
    /// Parse from SDP attribute format
    pub fn from_sdp(sdp: &str) -> Option<Self> {
        let parts: Vec<&str> = sdp.split_whitespace().collect();
        if parts.len() < 8 {
            return None;
        }
        
        // Parse foundation, component, protocol, priority, ip, port, typ, type
        let foundation = parts[0].to_string();
        let component: u8 = parts[1].parse().ok()?;
        let protocol = parts[2].to_string();
        let priority: u32 = parts[3].parse().ok()?;
        let ip: std::net::IpAddr = parts[4].parse().ok()?;
        let port: u16 = parts[5].parse().ok()?;
        // parts[6] should be "typ"
        let candidate_type = match parts[7] {
            "host" => CandidateType::Host,
            "upnp" => CandidateType::PortMapped,
            "srflx" => CandidateType::ServerReflexive,
            "prflx" => CandidateType::PeerReflexive,
            "relay" => CandidateType::Relay,
            _ => return None,
        };
        
        let address = SocketAddr::new(ip, port);
        
        // Parse optional related address
        let mut related_address = None;
        for i in 0..parts.len() {
            if parts[i] == "raddr" && i + 3 < parts.len() && parts[i + 2] == "rport" {
                if let (Ok(rip), Ok(rport)) = (parts[i + 1].parse::<std::net::IpAddr>(), parts[i + 3].parse::<u16>()) {
                    related_address = Some(SocketAddr::new(rip, rport));
                }
            }
        }
        
        Some(Self {
            candidate_type,
            protocol,
            address,
            base_address: related_address.or(Some(address)),
            priority,
            foundation,
            component,
            related_address,
        })
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
    /// Active UPnP mapping (kept alive to prevent drop from removing it)
    upnp_mapping: Arc<RwLock<Option<UPnPMapping>>>,
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
            upnp_mapping: Arc::new(RwLock::new(None)),
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

        // === PRIORITY 1: Try UPnP port mapping first ===
        // This provides the most reliable direct connectivity
        log::info!("Attempting UPnP port mapping for direct P2P...");
        match UPnPPortMapper::create_mapping(local_addr.port(), "NAIS Secure Channel") {
            Ok(mapping) => {
                let external_addr = SocketAddr::new(mapping.external_ip, mapping.external_port);
                let upnp_candidate = IceCandidate::port_mapped(external_addr, local_addr);
                log::info!("UPnP SUCCESS: {} -> {}", external_addr, local_addr);
                candidates.push(upnp_candidate);
                // Store the mapping to keep it alive - the Drop impl will remove it when IceAgent is dropped
                *self.upnp_mapping.write().await = Some(mapping);
                log::info!("[ICE] UPnP mapping stored to prevent premature cleanup");
            }
            Err(e) => {
                log::info!("UPnP unavailable ({}), falling back to STUN/hole-punching", e);
            }
        }

        // === PRIORITY 2: Gather host candidates from local interfaces ===
        if let Ok(interfaces) = get_local_interfaces().await {
            log::info!("[ICE] Found {} local network interfaces", interfaces.len());
            for addr in interfaces {
                log::info!("[ICE] Adding host candidate: {}:{}", addr, local_addr.port());
                let candidate = IceCandidate::host(SocketAddr::new(addr, local_addr.port()));
                candidates.push(candidate);
            }
        } else {
            log::warn!("[ICE] Failed to get local network interfaces");
        }

        // === PRIORITY 3: Gather server reflexive candidates via STUN ===
        // Only needed if UPnP failed - STUN helps with hole-punching
        if !candidates.iter().any(|c| c.candidate_type == CandidateType::PortMapped) {
            match self.stun_client.get_mapped_address(&socket).await {
                Ok(mapped_addr) => {
                    let srflx = IceCandidate::server_reflexive(
                        mapped_addr,
                        local_addr,
                        &self.stun_client.servers[0],
                    );
                    candidates.push(srflx);
                    log::info!("STUN reflexive address: {}", mapped_addr);
                }
                Err(e) => {
                    log::warn!("Failed to gather STUN candidate: {}", e);
                }
            }
        }

        // Detect NAT type (useful for diagnostics)
        let detector = NatDetector::new();
        if let Ok(nat_type) = detector.detect().await {
            *self.nat_type.write().await = Some(nat_type);
            log::info!("Detected NAT type: {:?}", nat_type);
            
            // Log warning if we're in a difficult NAT situation without UPnP
            if nat_type.needs_turn() && !candidates.iter().any(|c| c.candidate_type == CandidateType::PortMapped) {
                log::warn!("Symmetric NAT detected and UPnP unavailable - relay may be needed");
            }
        }

        // Sort by priority (highest first - UPnP candidates will be at top)
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        log::info!("[ICE] Gathered {} local candidates:", candidates.len());
        for (i, c) in candidates.iter().enumerate() {
            log::info!("[ICE]   {}: {} (type={:?}, priority={})", i, c.address, c.candidate_type, c.priority);
        }

        *self.local_candidates.write().await = candidates.clone();
        *self.state.write().await = IceState::Complete;

        Ok(candidates)
    }

    /// Add a remote candidate
    pub async fn add_remote_candidate(&self, candidate: IceCandidate) {
        log::info!("[ICE] Adding remote candidate: {} (type={:?})", candidate.address, candidate.candidate_type);
        self.remote_candidates.write().await.push(candidate.clone());
        
        // Create pairs with all local candidates
        let locals = self.local_candidates.read().await.clone();
        let mut pairs = self.pairs.write().await;
        
        for local in locals {
            log::debug!("[ICE] Creating pair: local={} ({:?}) <-> remote={} ({:?})", 
                local.address, local.candidate_type, candidate.address, candidate.candidate_type);
            let pair = CandidatePair::new(local, candidate.clone(), self.controlling);
            pairs.push(pair);
        }
        
        // Sort pairs by priority
        pairs.sort_by(|a, b| b.priority.cmp(&a.priority));
        log::info!("[ICE] Total candidate pairs: {}", pairs.len());
    }

    /// Perform connectivity checks
    pub async fn check_connectivity(&self) -> NatResult<CandidatePair> {
        *self.state.write().await = IceState::Checking;

        let socket = self.socket.read().await.clone()
            .ok_or(NatError::IceConnectivityFailed)?;

        let pairs = self.pairs.read().await.clone();
        let local_candidates = self.local_candidates.read().await.clone();
        
        log::info!("[ICE] Starting connectivity checks on {} pairs", pairs.len());
        
        // Log all pairs
        for (i, pair) in pairs.iter().enumerate() {
            log::info!("[ICE] Pair {}: local={} ({:?}) -> remote={} ({:?}) priority={}", 
                i, pair.local.address, pair.local.candidate_type, 
                pair.remote.address, pair.remote.candidate_type, pair.priority);
        }
        
        // No separate listener task - check_pair handles both requests and responses
        // to avoid race conditions on the shared socket
        
        for pair in pairs.iter() {
            // Skip relay candidates in first pass (try direct first)
            if pair.local.candidate_type == CandidateType::Relay {
                continue;
            }

            log::info!("[ICE] Checking pair: {} -> {}", pair.local.address, pair.remote.address);
            if let Ok(()) = self.check_pair(&socket, &pair).await {
                // Determine the effective local address for this pair
                // If our local candidate is a Host with private IP but remote is public,
                // the remote actually sees us via our ServerReflexive address
                let effective_pair = self.get_effective_pair(pair, &local_candidates);
                
                *self.state.write().await = IceState::Connected;
                *self.selected_pair.write().await = Some(effective_pair.clone());
                log::info!("[ICE] SUCCESS! Selected pair: {} ({:?}) -> {} ({:?})", 
                    effective_pair.local.address, effective_pair.local.candidate_type,
                    effective_pair.remote.address, effective_pair.remote.candidate_type);
                return Ok(effective_pair);
            } else {
                log::debug!("[ICE] Pair failed: {} -> {}", pair.local.address, pair.remote.address);
            }
        }

        // Try relay candidates if direct failed
        let pairs = self.pairs.read().await.clone();
        for pair in pairs {
            if pair.local.candidate_type == CandidateType::Relay {
                if let Ok(()) = self.check_pair(&socket, &pair).await {
                    *self.state.write().await = IceState::Connected;
                    *self.selected_pair.write().await = Some(pair.clone());
                    log::info!("[ICE] SUCCESS via relay! Selected pair: {} -> {}", pair.local.address, pair.remote.address);
                    return Ok(pair);
                }
            }
        }

        log::error!("[ICE] All connectivity checks failed!");
        *self.state.write().await = IceState::Failed;
        Err(NatError::IceConnectivityFailed)
    }
    
    /// Get the effective pair with corrected local address.
    /// When a Host candidate with private IP successfully connects to a public remote,
    /// the remote actually sees us via our ServerReflexive address. This function
    /// returns a pair with the correct externally-visible local address.
    fn get_effective_pair(&self, pair: &CandidatePair, local_candidates: &[IceCandidate]) -> CandidatePair {
        let local = &pair.local;
        let remote = &pair.remote;
        
        // Check if we need to adjust: local is Host with private IP, remote is public
        let local_is_private = !is_public_ip(&local.address.ip());
        let remote_is_public = is_public_ip(&remote.address.ip());
        
        if local.candidate_type == CandidateType::Host && local_is_private && remote_is_public {
            // Find a ServerReflexive candidate that has this Host as its base
            let srflx_candidate = local_candidates.iter().find(|c| {
                c.candidate_type == CandidateType::ServerReflexive 
                    && c.base_address == Some(local.address)
            });
            
            if let Some(srflx) = srflx_candidate {
                log::info!("[ICE] Upgrading local address from {} (Host/private) to {} (ServerReflexive/public) for external peer",
                    local.address, srflx.address);
                
                // Create new pair with ServerReflexive local, using controlling flag for priority calculation
                return CandidatePair::new(srflx.clone(), remote.clone(), self.controlling);
            } else {
                log::warn!("[ICE] Local {} is private but no matching ServerReflexive candidate found - remote may have trouble reaching us", 
                    local.address);
            }
        }
        
        // No adjustment needed
        pair.clone()
    }

    /// Check a single candidate pair with BIDIRECTIONAL verification
    /// Requires BOTH:
    /// 1. We can send to remote AND receive their response (outbound works)
    /// 2. Remote can send to us - evidenced by receiving a STUN request from them (inbound works)
    /// 
    /// This ensures the selected pair will work in both directions, not just outbound.
    async fn check_pair(&self, socket: &TokioUdpSocket, pair: &CandidatePair) -> NatResult<()> {
        let remote_addr = pair.remote.address;
        
        // Build STUN binding request with credentials
        let transaction_id = StunClient::generate_transaction_id();
        let request = self.build_connectivity_check(&transaction_id);

        // Send connectivity check
        socket.send_to(&request, remote_addr).await?;

        // Track bidirectional connectivity
        let mut got_response = false;  // We received a response to our request (outbound OK)
        let mut got_request = false;   // We received a request from peer (inbound OK)
        
        // Loop receiving until we have bidirectional confirmation or timeout
        // Use longer timeout for bidirectional check
        let deadline = tokio::time::Instant::now() + ICE_BIDIR_CHECK_TIMEOUT;
        let mut buf = [0u8; 1024];
        
        // Also send our request multiple times to ensure it gets through
        let mut next_retry = tokio::time::Instant::now() + Duration::from_millis(200);
        
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                if got_response && !got_request {
                    log::warn!("[ICE] Pair {} -> {}: Outbound OK but no inbound request received (one-way only)", 
                        pair.local.address, pair.remote.address);
                } else if !got_response && got_request {
                    log::warn!("[ICE] Pair {} -> {}: Inbound OK but no response to our request (one-way only)", 
                        pair.local.address, pair.remote.address);
                }
                return Err(NatError::IceConnectivityFailed);
            }
            
            // Retry sending our request periodically
            if tokio::time::Instant::now() >= next_retry {
                let _ = socket.send_to(&request, remote_addr).await;
                next_retry = tokio::time::Instant::now() + Duration::from_millis(200);
            }
            
            let result = timeout(remaining.min(Duration::from_millis(100)), socket.recv_from(&mut buf)).await;
            
            match result {
                Ok(Ok((len, from))) => {
                    if len >= 20 {
                        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
                        
                        if msg_type == STUN_BINDING_REQUEST {
                            // Received a STUN request from peer - this proves they can reach us!
                            log::debug!("[ICE] Received STUN request from {} (proves inbound connectivity)", from);
                            let mut txn_id = [0u8; 12];
                            txn_id.copy_from_slice(&buf[8..20]);
                            let response = Self::build_binding_response_static(&txn_id, from);
                            let _ = socket.send_to(&response, from).await;
                            
                            // Mark inbound connectivity as confirmed
                            // Accept requests from any address (NAT may translate remote's address)
                            got_request = true;
                            
                            if got_response && got_request {
                                log::debug!("[ICE] Bidirectional connectivity confirmed for {} -> {}", 
                                    pair.local.address, pair.remote.address);
                                return Ok(());
                            }
                            continue;
                        } else if msg_type == STUN_BINDING_RESPONSE {
                            // Check if this is the response we're waiting for
                            if Self::verify_stun_response(&buf[..len], &transaction_id) {
                                log::debug!("[ICE] Received valid STUN response from {} (proves outbound connectivity)", from);
                                got_response = true;
                                
                                if got_response && got_request {
                                    log::debug!("[ICE] Bidirectional connectivity confirmed for {} -> {}", 
                                        pair.local.address, pair.remote.address);
                                    return Ok(());
                                }
                            }
                            continue;
                        }
                    }
                    continue;
                }
                Ok(Err(_)) => return Err(NatError::IceConnectivityFailed),
                Err(_) => continue, // Timeout on this recv, but continue loop
            }
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
    
    /// Build a STUN binding response (static version for use in async blocks)
    fn build_binding_response_static(transaction_id: &[u8; 12], mapped_addr: std::net::SocketAddr) -> Vec<u8> {
        let mut msg = Vec::with_capacity(32);
        
        // Message Type: Binding Response
        msg.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        
        // Message Length (placeholder, will update)
        msg.extend_from_slice(&0u16.to_be_bytes());
        
        // Magic Cookie
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        
        // Transaction ID
        msg.extend_from_slice(transaction_id);
        
        // XOR-MAPPED-ADDRESS attribute
        let xor_port = mapped_addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        
        // Attribute type: XOR-MAPPED-ADDRESS (0x0020)
        msg.extend_from_slice(&0x0020u16.to_be_bytes());
        
        match mapped_addr {
            std::net::SocketAddr::V4(addr) => {
                // Attribute length (8 bytes for IPv4)
                msg.extend_from_slice(&8u16.to_be_bytes());
                // Reserved
                msg.push(0);
                // Family (IPv4 = 0x01)
                msg.push(0x01);
                // XOR'd port
                msg.extend_from_slice(&xor_port.to_be_bytes());
                // XOR'd address
                let ip_bytes = addr.ip().octets();
                let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    msg.push(ip_bytes[i] ^ magic_bytes[i]);
                }
            }
            std::net::SocketAddr::V6(addr) => {
                // Attribute length (20 bytes for IPv6)
                msg.extend_from_slice(&20u16.to_be_bytes());
                // Reserved
                msg.push(0);
                // Family (IPv6 = 0x02)
                msg.push(0x02);
                // XOR'd port
                msg.extend_from_slice(&xor_port.to_be_bytes());
                // XOR'd address (XOR with magic cookie + transaction id)
                let ip_bytes = addr.ip().octets();
                let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    msg.push(ip_bytes[i] ^ magic_bytes[i]);
                }
                for i in 4..16 {
                    msg.push(ip_bytes[i] ^ transaction_id[i - 4]);
                }
            }
        }
        
        // Update message length
        let attr_len = (msg.len() - 20) as u16;
        msg[2..4].copy_from_slice(&attr_len.to_be_bytes());
        
        msg
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

/// TURN authentication state (for long-term credential mechanism)
#[derive(Clone)]
struct TurnAuthState {
    /// Server realm
    realm: String,
    /// Server nonce (changes on each auth challenge)
    nonce: String,
    /// Computed key = MD5(username:realm:password)
    key: [u8; 16],
}

impl TurnAuthState {
    fn new(username: &str, password: &str, realm: &str, nonce: &str) -> Self {
        let digest = md5::compute(format!("{}:{}:{}", username, realm, password).as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest.0);
        Self {
            realm: realm.to_string(),
            nonce: nonce.to_string(),
            key,
        }
    }
    
    /// Calculate MESSAGE-INTEGRITY HMAC-SHA1 over the message
    fn message_integrity(&self, message: &[u8]) -> [u8; 20] {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;
        
        let mut mac = HmacSha1::new_from_slice(&self.key)
            .expect("HMAC can take any key size");
        mac.update(message);
        let result = mac.finalize();
        let mut output = [0u8; 20];
        output.copy_from_slice(&result.into_bytes());
        output
    }
}

/// TURN client for relay fallback
pub struct TurnClient {
    config: TurnConfig,
    socket: Option<Arc<TokioUdpSocket>>,
    allocation: Option<TurnAllocation>,
    auth_state: Option<TurnAuthState>,
    /// Channel bindings (peer address -> channel number)
    channel_bindings: HashMap<SocketAddr, u16>,
    /// Next channel number to use (0x4000-0x7FFF per RFC 5766)
    next_channel: u16,
}

impl TurnClient {
    /// Create new TURN client
    pub fn new(config: TurnConfig) -> Self {
        Self {
            config,
            socket: None,
            allocation: None,
            auth_state: None,
            channel_bindings: HashMap::new(),
            next_channel: 0x4000,
        }
    }

    /// Allocate a relay address with authentication
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

    /// Parse TURN Allocate response
    fn parse_allocate_response(&self, data: &[u8]) -> NatResult<TurnAllocation> {
        // STUN/TURN message minimum size: 20 bytes header
        if data.len() < 20 {
            return Err(NatError::TurnAllocationFailed("Response too short".into()));
        }
        
        // Check message type
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        const TURN_ALLOCATE_SUCCESS: u16 = 0x0103;
        const TURN_ALLOCATE_ERROR: u16 = 0x0113;
        
        if msg_type == TURN_ALLOCATE_ERROR {
            // Parse error code if available
            return Err(NatError::TurnAllocationFailed("TURN allocation rejected by server".into()));
        }
        
        if msg_type != TURN_ALLOCATE_SUCCESS {
            return Err(NatError::TurnAllocationFailed(
                format!("Unexpected response type: 0x{:04x}", msg_type)
            ));
        }
        
        // Verify magic cookie
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic != STUN_MAGIC_COOKIE {
            return Err(NatError::TurnAllocationFailed("Invalid magic cookie".into()));
        }
        
        // Parse message length
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 20 + msg_len {
            return Err(NatError::TurnAllocationFailed("Truncated response".into()));
        }
        
        // Parse attributes
        let mut relayed_address: Option<SocketAddr> = None;
        let mut mapped_address: Option<SocketAddr> = None;
        let mut lifetime: u32 = 600; // Default 10 minutes
        
        const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
        const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
        const ATTR_LIFETIME: u16 = 0x000D;
        
        let mut offset = 20; // Start after header
        while offset + 4 <= 20 + msg_len {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            
            if offset + attr_len > data.len() {
                break; // Malformed attribute
            }
            
            match attr_type {
                ATTR_XOR_RELAYED_ADDRESS => {
                    relayed_address = self.parse_xor_address(&data[offset..offset + attr_len], &data[4..8]);
                }
                ATTR_XOR_MAPPED_ADDRESS => {
                    mapped_address = self.parse_xor_address(&data[offset..offset + attr_len], &data[4..8]);
                }
                ATTR_LIFETIME => {
                    if attr_len >= 4 {
                        lifetime = u32::from_be_bytes([
                            data[offset], data[offset + 1], 
                            data[offset + 2], data[offset + 3]
                        ]);
                    }
                }
                _ => {} // Ignore unknown attributes
            }
            
            // Pad to 4-byte boundary
            offset += (attr_len + 3) & !3;
        }
        
        let relayed = relayed_address.ok_or_else(|| 
            NatError::TurnAllocationFailed("Missing XOR-RELAYED-ADDRESS".into())
        )?;
        
        let mapped = mapped_address.unwrap_or(relayed);
        
        Ok(TurnAllocation {
            relayed_address: relayed,
            mapped_address: mapped,
            lifetime,
            expires_at: Instant::now() + Duration::from_secs(lifetime as u64),
        })
    }
    
    /// Parse XOR-MAPPED-ADDRESS or XOR-RELAYED-ADDRESS attribute
    fn parse_xor_address(&self, attr_data: &[u8], magic_cookie: &[u8]) -> Option<SocketAddr> {
        if attr_data.len() < 8 {
            return None;
        }
        
        // First byte is reserved (0x00)
        let family = attr_data[1];
        let xor_port = u16::from_be_bytes([attr_data[2], attr_data[3]]);
        
        // XOR with magic cookie high bits
        let port = xor_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        
        match family {
            0x01 => {
                // IPv4
                if attr_data.len() < 8 {
                    return None;
                }
                let xor_ip = [attr_data[4], attr_data[5], attr_data[6], attr_data[7]];
                let ip = [
                    xor_ip[0] ^ magic_cookie[0],
                    xor_ip[1] ^ magic_cookie[1],
                    xor_ip[2] ^ magic_cookie[2],
                    xor_ip[3] ^ magic_cookie[3],
                ];
                Some(SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)),
                    port,
                ))
            }
            0x02 => {
                // IPv6
                if attr_data.len() < 20 {
                    return None;
                }
                // XOR with magic cookie + transaction ID
                // For simplicity, just handle basic case
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&attr_data[4..20]);
                // XOR first 4 bytes with magic cookie
                for i in 0..4 {
                    ip_bytes[i] ^= magic_cookie[i];
                }
                // Note: Should XOR remaining 12 bytes with transaction ID
                Some(SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes)),
                    port,
                ))
            }
            _ => None,
        }
    }
    
    /// Refresh TURN allocation before it expires
    pub async fn refresh(&mut self) -> NatResult<()> {
        let socket = self.socket.as_ref()
            .ok_or_else(|| NatError::TurnAllocationFailed("No active allocation".into()))?;
        
        let server_addr: SocketAddr = tokio::net::lookup_host(&self.config.server)
            .await?
            .next()
            .ok_or_else(|| NatError::TurnAllocationFailed("Cannot resolve TURN server".into()))?;
        
        let transaction_id = StunClient::generate_transaction_id();
        let request = self.build_refresh_request(&transaction_id);
        
        socket.send_to(&request, server_addr).await?;
        
        let mut buf = [0u8; 512];
        let result = timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await;
        
        match result {
            Ok(Ok((len, _))) => {
                // Check for success response
                if len >= 20 {
                    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
                    if msg_type == 0x0104 {
                        // Refresh success - update expiry
                        if let Some(ref mut alloc) = self.allocation {
                            alloc.expires_at = Instant::now() + Duration::from_secs(alloc.lifetime as u64);
                        }
                        return Ok(());
                    }
                }
                Err(NatError::TurnAllocationFailed("Refresh failed".into()))
            }
            Ok(Err(e)) => Err(NatError::IoError(e)),
            Err(_) => Err(NatError::TurnAllocationFailed("Refresh timeout".into())),
        }
    }
    
    /// Build TURN Refresh request
    fn build_refresh_request(&self, transaction_id: &[u8; 12]) -> Vec<u8> {
        const TURN_REFRESH_REQUEST: u16 = 0x0004;
        
        let mut msg = Vec::with_capacity(40);
        
        // Message type: Refresh Request
        msg.extend_from_slice(&TURN_REFRESH_REQUEST.to_be_bytes());
        
        // Placeholder for message length  
        msg.extend_from_slice(&0u16.to_be_bytes());
        
        // Magic cookie
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        
        // Transaction ID
        msg.extend_from_slice(transaction_id);
        
        // Update message length (no additional attributes)
        let msg_len = (msg.len() - 20) as u16;
        msg[2..4].copy_from_slice(&msg_len.to_be_bytes());
        
        msg
    }
    
    /// Send data through TURN relay
    pub async fn send_via_relay(&self, peer_addr: SocketAddr, data: &[u8]) -> NatResult<()> {
        let socket = self.socket.as_ref()
            .ok_or_else(|| NatError::TurnAllocationFailed("No active allocation".into()))?;
        
        let allocation = self.allocation.as_ref()
            .ok_or_else(|| NatError::TurnAllocationFailed("No active allocation".into()))?;
        
        // Check if allocation is still valid
        if Instant::now() > allocation.expires_at {
            return Err(NatError::TurnAllocationFailed("Allocation expired".into()));
        }
        
        let server_addr: SocketAddr = tokio::net::lookup_host(&self.config.server)
            .await?
            .next()
            .ok_or_else(|| NatError::TurnAllocationFailed("Cannot resolve TURN server".into()))?;
        
        // Build Send Indication with XOR-PEER-ADDRESS and DATA
        let transaction_id = StunClient::generate_transaction_id();
        let message = self.build_send_indication(&transaction_id, peer_addr, data);
        
        socket.send_to(&message, server_addr).await?;
        
        Ok(())
    }
    
    /// Build TURN Send Indication
    fn build_send_indication(&self, transaction_id: &[u8; 12], peer_addr: SocketAddr, data: &[u8]) -> Vec<u8> {
        const TURN_SEND_INDICATION: u16 = 0x0016;
        const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
        const ATTR_DATA: u16 = 0x0013;
        
        let mut msg = Vec::with_capacity(48 + data.len());
        
        // Message type: Send Indication
        msg.extend_from_slice(&TURN_SEND_INDICATION.to_be_bytes());
        
        // Placeholder for message length
        msg.extend_from_slice(&0u16.to_be_bytes());
        
        // Magic cookie
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        
        // Transaction ID
        msg.extend_from_slice(transaction_id);
        
        // XOR-PEER-ADDRESS attribute
        msg.extend_from_slice(&ATTR_XOR_PEER_ADDRESS.to_be_bytes());
        match peer_addr {
            SocketAddr::V4(addr) => {
                msg.extend_from_slice(&8u16.to_be_bytes()); // Length
                msg.push(0x00); // Reserved
                msg.push(0x01); // IPv4
                let port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                msg.extend_from_slice(&port.to_be_bytes());
                let ip = addr.ip().octets();
                let magic = STUN_MAGIC_COOKIE.to_be_bytes();
                msg.push(ip[0] ^ magic[0]);
                msg.push(ip[1] ^ magic[1]);
                msg.push(ip[2] ^ magic[2]);
                msg.push(ip[3] ^ magic[3]);
            }
            SocketAddr::V6(addr) => {
                msg.extend_from_slice(&20u16.to_be_bytes()); // Length
                msg.push(0x00); // Reserved
                msg.push(0x02); // IPv6
                let port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                msg.extend_from_slice(&port.to_be_bytes());
                let ip = addr.ip().octets();
                let magic = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    msg.push(ip[i] ^ magic[i]);
                }
                for i in 4..16 {
                    msg.push(ip[i]); // Should XOR with transaction ID
                }
            }
        }
        
        // DATA attribute
        msg.extend_from_slice(&ATTR_DATA.to_be_bytes());
        msg.extend_from_slice(&(data.len() as u16).to_be_bytes());
        msg.extend_from_slice(data);
        // Pad to 4-byte boundary
        while msg.len() % 4 != 0 {
            msg.push(0);
        }
        
        // Update message length
        let msg_len = (msg.len() - 20) as u16;
        msg[2..4].copy_from_slice(&msg_len.to_be_bytes());
        
        msg
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
    
    /// Create a channel binding for more efficient relay (RFC 5766 Section 11)
    /// Channel numbers 0x4000-0x7FFF are used for ChannelData messages
    pub async fn create_channel_binding(&mut self, peer_addr: SocketAddr) -> NatResult<u16> {
        // Check if we already have a binding
        if let Some(&channel) = self.channel_bindings.get(&peer_addr) {
            return Ok(channel);
        }
        
        let socket = self.socket.as_ref()
            .ok_or_else(|| NatError::TurnAllocationFailed("No active allocation".into()))?;
        
        let server_addr: SocketAddr = tokio::net::lookup_host(&self.config.server)
            .await?
            .next()
            .ok_or_else(|| NatError::TurnAllocationFailed("Cannot resolve TURN server".into()))?;
        
        let channel_number = self.next_channel;
        if channel_number > 0x7FFE {
            return Err(NatError::TurnAllocationFailed("No more channel numbers available".into()));
        }
        
        let transaction_id = StunClient::generate_transaction_id();
        let request = self.build_channel_bind_request(&transaction_id, channel_number, peer_addr);
        
        socket.send_to(&request, server_addr).await?;
        
        let mut buf = [0u8; 512];
        let result = timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await;
        
        match result {
            Ok(Ok((len, _))) => {
                // Check for success response (0x0109)
                if len >= 20 {
                    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
                    if msg_type == 0x0109 {
                        self.channel_bindings.insert(peer_addr, channel_number);
                        self.next_channel += 1;
                        return Ok(channel_number);
                    }
                }
                Err(NatError::TurnAllocationFailed("Channel binding failed".into()))
            }
            Ok(Err(e)) => Err(NatError::IoError(e)),
            Err(_) => Err(NatError::TurnAllocationFailed("Channel binding timeout".into())),
        }
    }
    
    /// Build ChannelBind request
    fn build_channel_bind_request(&self, transaction_id: &[u8; 12], channel: u16, peer_addr: SocketAddr) -> Vec<u8> {
        const TURN_CHANNEL_BIND_REQUEST: u16 = 0x0009;
        const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
        const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
        
        let mut msg = Vec::with_capacity(60);
        
        // Message type
        msg.extend_from_slice(&TURN_CHANNEL_BIND_REQUEST.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes()); // Length placeholder
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(transaction_id);
        
        // CHANNEL-NUMBER attribute
        msg.extend_from_slice(&ATTR_CHANNEL_NUMBER.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&channel.to_be_bytes());
        msg.push(0); msg.push(0); // RFFU (Reserved For Future Use)
        
        // XOR-PEER-ADDRESS attribute
        msg.extend_from_slice(&ATTR_XOR_PEER_ADDRESS.to_be_bytes());
        match peer_addr {
            SocketAddr::V4(addr) => {
                msg.extend_from_slice(&8u16.to_be_bytes());
                msg.push(0x00);
                msg.push(0x01);
                let port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                msg.extend_from_slice(&port.to_be_bytes());
                let ip = addr.ip().octets();
                let magic = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    msg.push(ip[i] ^ magic[i]);
                }
            }
            SocketAddr::V6(addr) => {
                msg.extend_from_slice(&20u16.to_be_bytes());
                msg.push(0x00);
                msg.push(0x02);
                let port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                msg.extend_from_slice(&port.to_be_bytes());
                let ip = addr.ip().octets();
                let magic = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    msg.push(ip[i] ^ magic[i]);
                }
                for i in 4..16 {
                    msg.push(ip[i]);
                }
            }
        }
        
        // Update message length
        let msg_len = (msg.len() - 20) as u16;
        msg[2..4].copy_from_slice(&msg_len.to_be_bytes());
        
        msg
    }
    
    /// Send data using channel binding (more efficient than Send Indication)
    pub async fn send_via_channel(&self, peer_addr: SocketAddr, data: &[u8]) -> NatResult<()> {
        let socket = self.socket.as_ref()
            .ok_or_else(|| NatError::TurnAllocationFailed("No active allocation".into()))?;
        
        let channel = self.channel_bindings.get(&peer_addr)
            .ok_or_else(|| NatError::TurnAllocationFailed("No channel binding for peer".into()))?;
        
        let server_addr: SocketAddr = tokio::net::lookup_host(&self.config.server)
            .await?
            .next()
            .ok_or_else(|| NatError::TurnAllocationFailed("Cannot resolve TURN server".into()))?;
        
        // ChannelData format: channel (2 bytes) || length (2 bytes) || data
        let mut message = Vec::with_capacity(4 + data.len());
        message.extend_from_slice(&channel.to_be_bytes());
        message.extend_from_slice(&(data.len() as u16).to_be_bytes());
        message.extend_from_slice(data);
        // Pad to 4-byte boundary
        while message.len() % 4 != 0 {
            message.push(0);
        }
        
        socket.send_to(&message, server_addr).await?;
        Ok(())
    }
    
    /// Receive data from relay (handles both Data Indication and ChannelData)
    pub async fn receive(&self, buf: &mut [u8]) -> NatResult<(usize, SocketAddr)> {
        let socket = self.socket.as_ref()
            .ok_or_else(|| NatError::TurnAllocationFailed("No active allocation".into()))?;
        
        loop {
            let (len, _from) = socket.recv_from(buf).await?;
            if len < 4 {
                continue;
            }
            
            // Check if it's a ChannelData message (first two bytes 0x4000-0x7FFF)
            let first_two = u16::from_be_bytes([buf[0], buf[1]]);
            if first_two >= 0x4000 && first_two <= 0x7FFF {
                // ChannelData
                let channel = first_two;
                let data_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                
                // Find peer address from channel binding
                let peer_addr = self.channel_bindings.iter()
                    .find(|(_, &ch)| ch == channel)
                    .map(|(addr, _)| *addr)
                    .ok_or_else(|| NatError::TurnAllocationFailed("Unknown channel".into()))?;
                
                // Move data to start of buffer
                if data_len <= len - 4 {
                    buf.copy_within(4..4 + data_len, 0);
                    return Ok((data_len, peer_addr));
                }
            } else if first_two == 0x0017 {
                // Data Indication (0x0017)
                // Parse to get XOR-PEER-ADDRESS and DATA attributes
                if let Some((peer_addr, data)) = self.parse_data_indication(&buf[..len]) {
                    let data_len = data.len().min(buf.len());
                    buf[..data_len].copy_from_slice(&data[..data_len]);
                    return Ok((data_len, peer_addr));
                }
            }
            // Otherwise continue receiving
        }
    }
    
    /// Parse Data Indication to extract peer address and data
    fn parse_data_indication(&self, data: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
        if data.len() < 20 {
            return None;
        }
        
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 20 + msg_len {
            return None;
        }
        
        let mut peer_addr: Option<SocketAddr> = None;
        let mut payload: Option<Vec<u8>> = None;
        
        const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
        const ATTR_DATA: u16 = 0x0013;
        
        let mut offset = 20;
        while offset + 4 <= 20 + msg_len {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            
            if offset + attr_len > data.len() {
                break;
            }
            
            match attr_type {
                ATTR_XOR_PEER_ADDRESS => {
                    peer_addr = self.parse_xor_address(&data[offset..offset + attr_len], &data[4..8]);
                }
                ATTR_DATA => {
                    payload = Some(data[offset..offset + attr_len].to_vec());
                }
                _ => {}
            }
            
            offset += (attr_len + 3) & !3;
        }
        
        peer_addr.zip(payload)
    }
    
    /// Get channel binding for a peer
    pub fn get_channel(&self, peer_addr: &SocketAddr) -> Option<u16> {
        self.channel_bindings.get(peer_addr).copied()
    }
    
    /// Check if allocation needs refresh
    pub fn needs_refresh(&self) -> bool {
        self.allocation.as_ref()
            .map(|a| Instant::now() + Duration::from_secs(60) > a.expires_at)
            .unwrap_or(false)
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
        
        // Test roundtrip parsing
        let parsed = IceCandidate::from_sdp(&sdp).unwrap();
        assert_eq!(parsed.address, candidate.address);
        assert_eq!(parsed.candidate_type, candidate.candidate_type);
        assert_eq!(parsed.priority, candidate.priority);
        
        // Test server reflexive with related address
        let srflx = IceCandidate::server_reflexive(
            "1.2.3.4:5000".parse().unwrap(),
            "192.168.1.1:5000".parse().unwrap(),
            "stun.example.com",
        );
        let srflx_sdp = srflx.to_sdp();
        let parsed_srflx = IceCandidate::from_sdp(&srflx_sdp).unwrap();
        assert_eq!(parsed_srflx.address, srflx.address);
        assert_eq!(parsed_srflx.candidate_type, CandidateType::ServerReflexive);
        assert_eq!(parsed_srflx.related_address, srflx.related_address);
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
