# Nais Secure Channels Architecture

**Version:** 2.0  
**Status:** Design Specification  
**Date:** February 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Protocol Stack Design](#3-protocol-stack-design)
4. [Network Topology](#4-network-topology)
5. [NAT Traversal Strategy](#5-nat-traversal-strategy)
6. [Key Management Design](#6-key-management-design)
7. [Identity System](#7-identity-system)
8. [Routing Algorithm](#8-routing-algorithm)
9. [Channel Metadata](#9-channel-metadata)
10. [UX Integration](#10-ux-integration)
11. [Threat Model](#11-threat-model)
12. [Failure Scenarios](#12-failure-scenarios)
13. [Tradeoff Analysis](#13-tradeoff-analysis)
14. [Scalability Considerations](#14-scalability-considerations)

---

## 1. Executive Summary

Nais Secure Channels (NSC) is an end-to-end encrypted overlay messaging system that operates alongside IRC infrastructure. IRC is used exclusively for peer discovery and presence signaling—**no encrypted payloads traverse IRC servers**. All message content flows through direct P2P connections or encrypted relay through untrusted federation hubs.

### Core Principles

1. **Zero Trust Transport**: All hubs and relays are untrusted; they see only ciphertext
2. **IRC as Discovery Only**: IRC provides the social graph and presence; never carries payload
3. **Forward Secrecy**: Compromise of long-term keys doesn't expose past messages
4. **Graceful Degradation**: System remains functional with partial connectivity
5. **User Sovereignty**: Channel creators maintain authority over channel metadata

---

## 2. Architecture Overview

### 2.1 System Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Application Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   Chat UI   │  │  Metadata   │  │   Status    │  │   Voice     │ │
│  │   Display   │  │   Display   │  │  Indicators │  │   Chat      │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│                         Channel Management                          │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │  NaisChannel  │  Membership  │  Metadata Sync  │  Message Queue ││
│  └─────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│                         Security Layer                              │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────────┐│
│  │  MLS Group    │  │  X3DH Key     │  │  Double Ratchet          ││
│  │  Protocol     │  │  Exchange     │  │  (per-peer)              ││
│  └───────────────┘  └───────────────┘  └───────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│                         Transport Layer                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────────┐│
│  │  QUIC/UDP     │  │  WebRTC       │  │  Relay Transport         ││
│  │  Direct P2P   │  │  DataChannel  │  │  (Hub Encrypted)         ││
│  └───────────────┘  └───────────────┘  └───────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│                         NAT Traversal                               │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────────┐│
│  │  ICE Agent    │  │  STUN Client  │  │  TURN Fallback           ││
│  └───────────────┘  └───────────────┘  └───────────────────────────┘│
├─────────────────────────────────────────────────────────────────────┤
│                         Discovery Layer (IRC)                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  CTCP Signaling  │  Presence  │  Channel Join/Part  │  WHOIS  │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| `NaisSecureChannel` | Channel state, membership, message ordering |
| `IdentityManager` | Long-term keys, device management, revocation |
| `KeyManager` | Session keys, ratcheting, group key derivation |
| `TransportManager` | Connection establishment, NAT traversal |
| `RelayClient` | Hub communication, encrypted relay |
| `MetadataStore` | Signed channel metadata, sync protocol |
| `IrcDiscovery` | IRC-based peer discovery and presence |

---

## 3. Protocol Stack Design

### 3.1 Wire Protocol

All P2P messages follow this envelope format:

```
┌────────────────────────────────────────────────────────────────┐
│                    NSC Message Envelope                        │
├────────────────────────────────────────────────────────────────┤
│ Version          │ 1 byte  │ Protocol version (0x02)          │
│ Message Type     │ 1 byte  │ See message types below          │
│ Flags            │ 2 bytes │ Relay, Priority, Ack-Request     │
│ Sender ID        │ 32 bytes│ Sender's identity public key hash│
│ Channel ID       │ 32 bytes│ SHA-256 of channel creation block│
│ Sequence Number  │ 8 bytes │ Per-sender monotonic sequence    │
│ Timestamp        │ 8 bytes │ Unix timestamp (milliseconds)    │
│ Payload Length   │ 4 bytes │ Length of encrypted payload      │
│ Encrypted Payload│ variable│ MLS/Double-Ratchet ciphertext    │
│ Signature        │ 64 bytes│ Ed25519 over entire message      │
└────────────────────────────────────────────────────────────────┘
```

### 3.2 Message Types

```rust
pub enum MessageType {
    // Channel Messages
    ChannelMessage      = 0x01,  // Regular chat message
    ChannelAction       = 0x02,  // /me action
    ChannelMetadata     = 0x03,  // Signed metadata update
    
    // Membership
    MemberJoin          = 0x10,  // MLS Welcome message
    MemberLeave         = 0x11,  // MLS Remove
    MemberUpdate        = 0x12,  // Key update
    
    // Key Exchange
    KeyPackage          = 0x20,  // MLS KeyPackage
    Welcome             = 0x21,  // MLS Welcome
    Commit              = 0x22,  // MLS Commit
    
    // Control
    Ack                 = 0x30,  // Delivery acknowledgment
    Heartbeat           = 0x31,  // Keep-alive
    RoutingUpdate       = 0x32,  // Peer connectivity info
    
    // NAT Traversal (via IRC signaling)
    IceCandidate        = 0x40,  // ICE candidate exchange
    IceOffer            = 0x41,  // Connection offer
    IceAnswer           = 0x42,  // Connection answer
    
    // Relay
    RelayRequest        = 0x50,  // Request relay through hub
    RelayData           = 0x51,  // Relayed encrypted data
}
```

### 3.3 Encryption Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Message Flow                              │
│                                                              │
│  Plaintext Message                                           │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  MLS Group Encryption (or Sender Keys for large groups) ││
│  │  - Group secret derived via MLS tree                    ││
│  │  - Forward secrecy via epoch advancement               ││
│  └─────────────────────────────────────────────────────────┘│
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  Per-Peer Double Ratchet (for 1:1 within group)        ││
│  │  - Optional additional PFS layer                        ││
│  │  - Used for key distribution messages                   ││
│  └─────────────────────────────────────────────────────────┘│
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  QUIC TLS 1.3 (transport encryption)                   ││
│  │  - Provides replay protection at transport             ││
│  │  - Not trusted for E2E security                        ││
│  └─────────────────────────────────────────────────────────┘│
│       │                                                      │
│       ▼                                                      │
│  Network (P2P or Relay)                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Network Topology

### 4.1 Federated Star with Mesh Fallback

```
                    ┌─────────────┐
                    │  Hub A      │
                    │ (Europe)    │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐       ┌─────▼─────┐      ┌────▼────┐
   │ Peer 1  │◄─────►│  Peer 2   │◄────►│ Peer 3  │
   │ (NAT)   │       │ (Public)  │      │ (NAT)   │
   └────┬────┘       └─────┬─────┘      └────┬────┘
        │                  │                  │
        │            ┌─────▼─────┐            │
        └───────────►│  Hub B    │◄───────────┘
                     │ (US East) │
                     └───────────┘

  ─────► Direct P2P connection
  ─ ─ ─► Relay through hub (encrypted)
```

### 4.2 Hub Role Definition

```rust
pub struct FederationHub {
    /// Hub's public identity key
    pub identity: PublicKey,
    
    /// Supported protocols (QUIC, WebSocket, etc.)
    pub protocols: Vec<Protocol>,
    
    /// Geographic region for latency optimization
    pub region: String,
    
    /// Hub capabilities
    pub capabilities: HubCapabilities,
    
    /// Current load (for load balancing)
    pub load_factor: f32,
}

pub struct HubCapabilities {
    /// Can relay encrypted messages
    pub relay: bool,
    
    /// Provides TURN server
    pub turn: bool,
    
    /// Stores encrypted messages for offline peers
    pub store_forward: bool,
    
    /// Maximum message size for relay
    pub max_relay_size: usize,
    
    /// Rate limits
    pub rate_limit: RateLimit,
}
```

### 4.3 Connection Priority

1. **Direct P2P (IPv6)**: Preferred when both peers have IPv6
2. **Direct P2P (IPv4)**: Via NAT traversal if possible
3. **Relay via nearest hub**: When direct connection fails
4. **Multi-hop relay**: Through peer with better connectivity

### 4.4 Topology State Machine

```
                         ┌─────────────────┐
                         │   DISCOVERING   │
                         │ (IRC presence)  │
                         └────────┬────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
       ┌──────────────┐  ┌───────────────┐  ┌───────────────┐
       │DIRECT_ATTEMPT│  │ HUB_CONNECT   │  │ PEER_RELAY    │
       │ (ICE/STUN)   │  │ (QUIC to hub) │  │ (via peer)    │
       └──────┬───────┘  └───────┬───────┘  └───────┬───────┘
              │                  │                  │
              ▼                  ▼                  ▼
       ┌──────────────┐  ┌───────────────┐  ┌───────────────┐
       │ DIRECT_P2P   │  │ HUB_RELAY     │  │ MESH_RELAY    │
       │ (preferred)  │  │ (fallback)    │  │ (degraded)    │
       └──────────────┘  └───────────────┘  └───────────────┘
```

---

## 5. NAT Traversal Strategy

### 5.1 ICE Implementation

```rust
pub struct IceAgent {
    /// Local candidates gathered
    candidates: Vec<IceCandidate>,
    
    /// STUN servers (ordered by preference)
    stun_servers: Vec<StunServer>,
    
    /// TURN servers (fallback)
    turn_servers: Vec<TurnServer>,
    
    /// UPnP mappings (optional optimization)
    upnp_mappings: Vec<UpnpMapping>,
    
    /// Agent state
    state: IceState,
}

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
```

### 5.2 NAT Type Detection

```rust
pub enum NatType {
    /// No NAT, direct connectivity
    None,
    
    /// Full-cone NAT (easiest to traverse)
    FullCone,
    
    /// Address-restricted cone NAT
    AddressRestricted,
    
    /// Port-restricted cone NAT
    PortRestricted,
    
    /// Symmetric NAT (hardest, requires TURN)
    Symmetric,
    
    /// Unknown/blocked
    Unknown,
}

impl IceAgent {
    /// Detect NAT type using STUN binding requests
    pub async fn detect_nat_type(&mut self) -> NatType {
        // 1. Send STUN binding to server A
        // 2. Compare response address to local address
        // 3. Send STUN binding to server A from different port
        // 4. Send STUN binding to server B
        // 5. Classify based on response patterns
    }
}
```

### 5.3 Traversal Strategy by NAT Type

| Peer A NAT | Peer B NAT | Strategy |
|------------|------------|----------|
| None | Any | Direct to A's public address |
| Full Cone | Full Cone | UDP hole punching |
| Port Restricted | Full Cone | Simultaneous UDP hole punch |
| Symmetric | Full Cone | Hole punch + port prediction |
| Symmetric | Symmetric | TURN relay required |
| Any | Unknown | Try direct, fallback to hub relay |

### 5.4 IPv6 Preference

```rust
impl TransportManager {
    pub async fn establish_connection(&self, peer: &PeerId) -> Connection {
        // 1. Check for IPv6 addresses
        if let Some(v6_addr) = peer.ipv6_address() {
            if let Ok(conn) = self.try_direct_ipv6(v6_addr).await {
                return conn;
            }
        }
        
        // 2. Try IPv4 with NAT traversal
        if let Ok(conn) = self.try_ice_connection(peer).await {
            return conn;
        }
        
        // 3. Fall back to hub relay
        self.establish_relay(peer).await
    }
}
```

### 5.5 UDP Hole Punching Protocol

```
      Peer A                    IRC Server                    Peer B
         │                          │                            │
         │  CTCP NAIS_ICE_OFFER    │                            │
         │────────────────────────►│                            │
         │                          │  CTCP NAIS_ICE_OFFER      │
         │                          │───────────────────────────►│
         │                          │                            │
         │                          │  CTCP NAIS_ICE_ANSWER     │
         │                          │◄───────────────────────────│
         │  CTCP NAIS_ICE_ANSWER   │                            │
         │◄────────────────────────│                            │
         │                          │                            │
         │                          │                            │
         │◄═══════════════════════UDP Hole Punch════════════════►│
         │                          │                            │
         │◄══════════════════════QUIC Connection═════════════════►│
```

---

## 6. Key Management Design

### 6.1 Key Hierarchy

```
                    ┌─────────────────────────────────┐
                    │      Identity Key (IK)          │
                    │   Ed25519 (long-term, device)   │
                    └────────────────┬────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
    ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
    │ Pre-Key Bundle  │   │ Signing Key     │   │ Encryption Key  │
    │ (X3DH)          │   │ (Metadata)      │   │ (Device Backup) │
    └────────┬────────┘   └─────────────────┘   └─────────────────┘
             │
    ┌────────┴────────┐
    │                 │
    ▼                 ▼
┌────────────┐  ┌────────────┐
│ Signed     │  │ One-Time   │
│ Pre-Key    │  │ Pre-Keys   │
│ (rotating) │  │ (ephemeral)│
└────────────┘  └────────────┘
```

### 6.2 MLS Group State

```rust
pub struct MlsGroupState {
    /// Group identifier (derived from creation)
    pub group_id: GroupId,
    
    /// Current epoch number
    pub epoch: u64,
    
    /// Tree structure for key derivation
    pub ratchet_tree: RatchetTree,
    
    /// Group secrets for this epoch
    pub epoch_secrets: EpochSecrets,
    
    /// Pending commits awaiting confirmation
    pub pending_commits: Vec<PendingCommit>,
    
    /// Members and their key packages
    pub members: HashMap<LeafIndex, Member>,
}

pub struct EpochSecrets {
    /// Joiner secret for adding members
    pub joiner_secret: Secret,
    
    /// Epoch secret for message encryption
    pub epoch_secret: Secret,
    
    /// Sender data secret
    pub sender_data_secret: Secret,
    
    /// Encryption key schedule
    pub encryption_secret: Secret,
    
    /// Authentication secret
    pub authentication_secret: Secret,
    
    /// Exporter secret (for external use)
    pub exporter_secret: Secret,
    
    /// Resumption secret (for rejoining)
    pub resumption_secret: Secret,
}
```

### 6.3 Key Rotation Strategy

```rust
pub struct KeyRotationPolicy {
    /// Rotate after N messages sent
    pub messages_threshold: u32,
    
    /// Rotate after time duration
    pub time_threshold: Duration,
    
    /// Force rotation on member leave
    pub rotate_on_leave: bool,
    
    /// Force rotation on member join
    pub rotate_on_join: bool,
    
    /// Emergency rotation trigger
    pub compromise_rotation: bool,
}

impl MlsGroupState {
    pub fn should_rotate(&self, policy: &KeyRotationPolicy) -> bool {
        let messages_exceeded = self.messages_since_rotation > policy.messages_threshold;
        let time_exceeded = self.time_since_rotation() > policy.time_threshold;
        messages_exceeded || time_exceeded
    }
    
    pub async fn rotate_keys(&mut self) -> Result<Commit, Error> {
        // 1. Generate new epoch secrets
        // 2. Update ratchet tree
        // 3. Create MLS Commit message
        // 4. Broadcast to all members
        // 5. Wait for acknowledgments
        // 6. Apply update
    }
}
```

### 6.4 Forward Secrecy Guarantees

| Event | Action | Forward Secrecy |
|-------|--------|-----------------|
| Regular message | Double ratchet step | Per-message |
| Member join | MLS epoch advance | From join point |
| Member leave | Full tree update | Post-leave |
| Key compromise detected | Emergency rotation | From rotation |
| Time threshold | Proactive rotation | Bounded window |

### 6.5 X3DH Key Exchange (for new peer sessions)

```rust
pub struct X3dhPreKeyBundle {
    /// Identity key
    pub identity_key: PublicKey,
    
    /// Signed pre-key (rotated weekly)
    pub signed_pre_key: PublicKey,
    pub signed_pre_key_signature: Signature,
    
    /// One-time pre-keys (consumed on use)
    pub one_time_pre_keys: Vec<PublicKey>,
}

impl X3dhSession {
    /// Initiator creates session with recipient's bundle
    pub fn initiate(
        our_identity: &IdentityKeyPair,
        their_bundle: &X3dhPreKeyBundle,
    ) -> (SharedSecret, EphemeralPublic) {
        // DH1 = DH(IK_A, SPK_B)
        // DH2 = DH(EK_A, IK_B)
        // DH3 = DH(EK_A, SPK_B)
        // DH4 = DH(EK_A, OPK_B) [if available]
        // SK = KDF(DH1 || DH2 || DH3 [|| DH4])
    }
}
```

---

## 7. Identity System

### 7.1 Identity Structure

```rust
pub struct NaisIdentity {
    /// Long-term identity key pair
    pub identity_key: IdentityKeyPair,
    
    /// Human-readable display name
    pub display_name: String,
    
    /// Identity fingerprint (SHA-256 of public key)
    pub fingerprint: Fingerprint,
    
    /// Device identifier (unique per device)
    pub device_id: DeviceId,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Identity certificate (self-signed or CA-signed)
    pub certificate: IdentityCertificate,
    
    /// Revocation status
    pub revocation: Option<Revocation>,
}

pub struct IdentityCertificate {
    /// Certificate version
    pub version: u8,
    
    /// Subject identity key
    pub subject: PublicKey,
    
    /// Issuer (self or parent identity)
    pub issuer: PublicKey,
    
    /// Valid from timestamp
    pub valid_from: u64,
    
    /// Valid until timestamp
    pub valid_until: u64,
    
    /// Certificate extensions
    pub extensions: CertificateExtensions,
    
    /// Signature over certificate data
    pub signature: Signature,
}
```

### 7.2 Multi-Device Model

```
                    ┌─────────────────────────────────┐
                    │       User Master Identity      │
                    │    (stored encrypted, backed    │
                    │     up to recovery method)      │
                    └────────────────┬────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │        Device Sub-Keys          │
                    │   (derived, can be revoked      │
                    │    individually)                │
                    └────────────────┬────────────────┘
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         │                           │                           │
         ▼                           ▼                           ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ Desktop Device  │       │ Mobile Device   │       │ Web Device      │
│ Device Key A    │       │ Device Key B    │       │ Device Key C    │
└─────────────────┘       └─────────────────┘       └─────────────────┘
```

### 7.3 Device Authorization Flow

```rust
pub enum DeviceAuthMethod {
    /// Scan QR code from existing device
    QrCode {
        challenge: [u8; 32],
        device_info: DeviceInfo,
    },
    
    /// Enter code displayed on existing device
    NumericCode {
        code: String,
        expires: u64,
    },
    
    /// Use recovery phrase
    RecoveryPhrase {
        phrase_hash: [u8; 32],
    },
}

impl IdentityManager {
    pub async fn authorize_new_device(
        &self,
        method: DeviceAuthMethod,
        new_device_key: &PublicKey,
    ) -> Result<DeviceCertificate, Error> {
        // 1. Verify authorization method
        // 2. Create device certificate signed by master
        // 3. Distribute to existing sessions
        // 4. Store device mapping
    }
}
```

### 7.4 Trust Verification

```rust
pub enum TrustLevel {
    /// Unknown identity, not verified
    Unknown,
    
    /// Trust on first use (key pinned)
    Tofu {
        first_seen: u64,
        pin_hash: [u8; 32],
    },
    
    /// Verified out-of-band (e.g., in person)
    Verified {
        verified_at: u64,
        method: VerificationMethod,
    },
    
    /// Web of trust verification
    WebOfTrust {
        trust_paths: Vec<TrustPath>,
        trust_score: f32,
    },
    
    /// Key has been marked compromised
    Compromised {
        reported_at: u64,
        evidence: Option<String>,
    },
}

pub struct TrustPath {
    /// Chain of signatures leading to peer
    pub signers: Vec<PublicKey>,
    
    /// Trust level assigned by each signer
    pub levels: Vec<u8>,
    
    /// When this path was established
    pub established: u64,
}
```

### 7.5 Verification Methods

```rust
pub enum VerificationMethod {
    /// Safety number comparison (like Signal)
    SafetyNumber {
        /// 60-digit number displayed to both parties
        number: String,
    },
    
    /// QR code scan in person
    QrCode {
        /// Contains identity key fingerprint
        payload: Vec<u8>,
    },
    
    /// Signed attestation from trusted third party
    Attestation {
        attester: PublicKey,
        signature: Signature,
    },
    
    /// Short authentication string (SAS)
    Sas {
        emoji_sequence: Vec<String>,
    },
}
```

### 7.6 Revocation

```rust
pub struct Revocation {
    /// Revoked identity key
    pub revoked_key: PublicKey,
    
    /// Revocation reason
    pub reason: RevocationReason,
    
    /// Timestamp
    pub revoked_at: u64,
    
    /// Signature by revoking authority
    pub signature: Signature,
    
    /// Successor key (if rotating, not compromised)
    pub successor: Option<PublicKey>,
}

pub enum RevocationReason {
    /// Key was compromised
    Compromised,
    
    /// Key is being rotated (not compromised)
    Rotation,
    
    /// Device lost or stolen
    DeviceLost,
    
    /// User requested revocation
    UserRequested,
    
    /// Key expired
    Expired,
}
```

---

## 8. Routing Algorithm

### 8.1 Group Messaging Model

```rust
pub struct MessageRouter {
    /// Local peer connections (direct P2P)
    direct_peers: HashMap<PeerId, Connection>,
    
    /// Peers reachable via relay
    relay_peers: HashMap<PeerId, RelayPath>,
    
    /// Known hub connections
    hub_connections: Vec<HubConnection>,
    
    /// Routing table with connectivity info
    routing_table: RoutingTable,
}

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
    pub last_success: Instant,
    
    /// Next hops for this destination
    pub next_hops: Vec<NextHop>,
}

pub enum PathType {
    /// Direct P2P connection
    Direct,
    
    /// Via federation hub
    HubRelay { hub_id: HubId },
    
    /// Via another peer
    PeerRelay { relay_peer: PeerId },
    
    /// Multiple paths available
    MultiPath { paths: Vec<PathType> },
}
```

### 8.2 Message Propagation Algorithm

```rust
impl MessageRouter {
    /// Route a channel message to all members
    pub async fn route_channel_message(
        &self,
        message: &EncryptedMessage,
        channel: &NaisChannel,
    ) -> RoutingResult {
        let mut results = Vec::new();
        
        // Group peers by best delivery method
        let direct_peers = self.get_direct_peers(channel);
        let relay_peers = self.get_relay_peers(channel);
        let hub_peers = self.get_hub_routed_peers(channel);
        
        // 1. Send to direct peers in parallel
        for peer in direct_peers {
            results.push(self.send_direct(peer, message).await);
        }
        
        // 2. Send via hub relay (single send, hub fans out)
        if !hub_peers.is_empty() {
            let hub = self.select_best_hub(&hub_peers);
            results.push(self.send_via_hub(hub, &hub_peers, message).await);
        }
        
        // 3. Send via peer relay for remaining
        for (peer, relay) in relay_peers {
            results.push(self.send_via_peer(relay, peer, message).await);
        }
        
        self.compile_results(results)
    }
}
```

### 8.3 Partial Connectivity Handling

```rust
pub struct PartialConnectivityManager {
    /// Peers we can reach directly
    reachable: HashSet<PeerId>,
    
    /// Peers we can only reach via relay
    relay_only: HashSet<PeerId>,
    
    /// Peers currently unreachable
    unreachable: HashSet<PeerId>,
    
    /// Message queue for unreachable peers
    pending_messages: HashMap<PeerId, Vec<QueuedMessage>>,
}

impl PartialConnectivityManager {
    /// Handle message delivery with partial connectivity
    pub async fn deliver_with_fallback(
        &mut self,
        message: Message,
        recipient: PeerId,
    ) -> DeliveryResult {
        // 1. Try direct delivery
        if self.reachable.contains(&recipient) {
            if let Ok(result) = self.try_direct(&recipient, &message).await {
                return result;
            }
            // Connection failed, update state
            self.reachable.remove(&recipient);
            self.relay_only.insert(recipient.clone());
        }
        
        // 2. Try relay delivery
        if self.relay_only.contains(&recipient) {
            if let Ok(result) = self.try_relay(&recipient, &message).await {
                return result;
            }
            // Relay failed
            self.relay_only.remove(&recipient);
            self.unreachable.insert(recipient.clone());
        }
        
        // 3. Queue for later delivery
        self.queue_message(recipient, message);
        DeliveryResult::Queued
    }
    
    /// Attempt redelivery when peer becomes reachable
    pub async fn on_peer_connected(&mut self, peer: &PeerId) {
        if let Some(messages) = self.pending_messages.remove(peer) {
            for msg in messages {
                self.deliver_with_fallback(msg.message, peer.clone()).await;
            }
        }
    }
}
```

### 8.4 Avoiding Single Points of Failure

```rust
pub struct RedundantDelivery {
    /// Number of redundant paths to use
    redundancy_factor: u8,
    
    /// Timeout for primary path before using backup
    primary_timeout: Duration,
    
    /// Deduplication window
    dedup_window: Duration,
}

impl RedundantDelivery {
    pub async fn deliver_redundant(
        &self,
        router: &MessageRouter,
        message: &Message,
        recipient: &PeerId,
    ) -> DeliveryResult {
        let paths = router.get_paths(recipient);
        let paths = self.select_diverse_paths(paths, self.redundancy_factor);
        
        // Send via multiple paths simultaneously
        let mut handles = Vec::new();
        for path in paths {
            let handle = tokio::spawn(async move {
                router.send_via_path(path, message).await
            });
            handles.push(handle);
        }
        
        // Wait for first success or all failures
        // Recipient deduplicates by message ID
        self.wait_for_delivery(handles).await
    }
}
```

### 8.5 Routing Announcements

```rust
/// Periodically broadcast connectivity information
pub struct RoutingAnnouncement {
    /// Our peer ID
    pub peer_id: PeerId,
    
    /// Direct peers we can reach
    pub direct_peers: Vec<PeerId>,
    
    /// Our hub connections
    pub hub_connections: Vec<HubId>,
    
    /// NAT type (for connectivity hints)
    pub nat_type: NatType,
    
    /// IPv6 available
    pub ipv6_available: bool,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Signature
    pub signature: Signature,
}
```

---

## 9. Channel Metadata

### 9.1 Signed Metadata Structure

```rust
pub struct ChannelMetadata {
    /// Channel identifier
    pub channel_id: ChannelId,
    
    /// Human-readable channel name
    pub name: String,
    
    /// Channel topic/description
    pub topic: String,
    
    /// Channel avatar (IPFS/content-addressed hash)
    pub avatar: Option<ContentHash>,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Current metadata version (monotonic)
    pub version: u64,
    
    /// Channel creator's identity
    pub creator: PublicKey,
    
    /// List of admins who can update metadata
    pub admins: Vec<PublicKey>,
    
    /// Channel settings
    pub settings: ChannelSettings,
    
    /// Signature by authorized updater
    pub signature: Signature,
    
    /// Previous metadata hash (chain)
    pub previous_hash: Option<[u8; 32]>,
}

pub struct ChannelSettings {
    /// Is channel publicly discoverable
    pub discoverable: bool,
    
    /// Require admin approval to join
    pub invite_only: bool,
    
    /// Maximum members (0 = unlimited)
    pub max_members: u32,
    
    /// Message retention policy
    pub retention: RetentionPolicy,
    
    /// Allowed message types
    pub allowed_types: Vec<MessageType>,
}
```

### 9.2 Metadata Authority

```rust
impl ChannelMetadata {
    /// Verify metadata update is authorized
    pub fn verify_update(&self, new: &ChannelMetadata) -> Result<(), Error> {
        // 1. Check version is incrementing
        if new.version <= self.version {
            return Err(Error::StaleVersion);
        }
        
        // 2. Check previous hash chain
        if new.previous_hash != Some(self.hash()) {
            return Err(Error::BrokenChain);
        }
        
        // 3. Verify signer is creator or admin
        let signer = new.signature.recover_signer(&new.signing_data())?;
        if signer != self.creator && !self.admins.contains(&signer) {
            return Err(Error::Unauthorized);
        }
        
        // 4. Verify signature
        new.signature.verify(&new.signing_data(), &signer)?;
        
        Ok(())
    }
}
```

### 9.3 P2P Metadata Sync

```rust
pub struct MetadataSyncProtocol {
    /// Local metadata store
    store: MetadataStore,
    
    /// Pending metadata updates
    pending: Vec<ChannelMetadata>,
}

impl MetadataSyncProtocol {
    /// Request metadata from peer
    pub async fn sync_with_peer(&self, peer: &PeerId) -> Result<(), Error> {
        // 1. Send our metadata version
        let request = MetadataSyncRequest {
            channel_id: self.channel_id,
            our_version: self.store.current_version(),
        };
        
        // 2. Peer responds with their version or full metadata
        let response = peer.send_request(request).await?;
        
        match response {
            MetadataSyncResponse::UpToDate => Ok(()),
            MetadataSyncResponse::Update(metadata) => {
                // Verify and apply update
                self.verify_and_apply(metadata)
            }
            MetadataSyncResponse::NeedSync => {
                // We have newer version, send to peer
                self.send_metadata_to_peer(peer).await
            }
        }
    }
}
```

### 9.4 IRC Channel Mapping (Internal Only)

```rust
/// Mapping between NAIS channels and IRC discovery channels
/// This mapping is NEVER exposed to UI
pub struct IrcChannelMapping {
    /// NAIS channel ID -> IRC channel name
    nais_to_irc: HashMap<ChannelId, String>,
    
    /// IRC channel name -> NAIS channel ID  
    irc_to_nais: HashMap<String, ChannelId>,
}

impl IrcChannelMapping {
    /// Generate opaque IRC channel name for NAIS channel
    pub fn irc_channel_for(&self, channel_id: &ChannelId) -> String {
        // IRC channel is hash-derived, not human-readable
        // Format: #nais-<first 8 chars of channel_id hash>
        let hash = sha256(channel_id);
        format!("#nais-{}", hex::encode(&hash[..4]))
    }
}
```

---

## 10. UX Integration

### 10.1 Connection Status Icons

```rust
pub enum ConnectionSecurityStatus {
    /// Direct P2P, verified identity
    DirectVerified,
    
    /// Direct P2P, TOFU identity
    DirectTofu,
    
    /// Via relay, verified identity
    RelayVerified,
    
    /// Via relay, TOFU identity
    RelayTofu,
    
    /// Identity not verified
    Unverified,
    
    /// Degraded encryption (e.g., key rotation pending)
    Degraded,
    
    /// Connection lost
    Disconnected,
}

impl ConnectionSecurityStatus {
    pub fn icon(&self) -> &'static str {
        match self {
            Self::DirectVerified => "🔒✓",   // Lock with checkmark
            Self::DirectTofu => "🔒",         // Lock
            Self::RelayVerified => "🔗✓",     // Chain with checkmark
            Self::RelayTofu => "🔗",          // Chain
            Self::Unverified => "⚠️",         // Warning
            Self::Degraded => "🔓",           // Open lock
            Self::Disconnected => "❌",        // X
        }
    }
    
    pub fn tooltip(&self) -> &'static str {
        match self {
            Self::DirectVerified => "Direct connection, identity verified",
            Self::DirectTofu => "Direct connection, identity pinned (TOFU)",
            Self::RelayVerified => "Relayed connection, identity verified",
            Self::RelayTofu => "Relayed connection, identity pinned",
            Self::Unverified => "Identity not verified - verify out-of-band",
            Self::Degraded => "Encryption degraded - key rotation in progress",
            Self::Disconnected => "Not connected",
        }
    }
}
```

### 10.2 UI Components

```rust
/// User list item with security indicators
pub struct UserListEntry {
    /// Display name from signed identity
    pub display_name: String,
    
    /// Security status
    pub security: ConnectionSecurityStatus,
    
    /// Connection quality (for optional display)
    pub latency_ms: Option<u32>,
    
    /// Voice chat status
    pub voice_status: VoiceStatus,
}

/// Channel display with overlay metadata
pub struct ChannelDisplay {
    /// Channel name from signed metadata
    pub name: String,
    
    /// Channel topic from signed metadata
    pub topic: String,
    
    /// Never expose IRC channel name
    // pub irc_channel: HIDDEN
    
    /// Member count
    pub member_count: u32,
    
    /// Channel security status
    pub security: ChannelSecurityStatus,
}
```

### 10.3 Message Display

```rust
pub struct MessageDisplay {
    /// Sender display name (from verified identity)
    pub sender: String,
    
    /// Decrypted message content
    pub content: String,
    
    /// Local timestamp (received)
    pub timestamp: DateTime,
    
    /// Security indicator for this specific message
    pub security: MessageSecurityStatus,
    
    /// Delivery status
    pub delivery: DeliveryStatus,
}

pub enum MessageSecurityStatus {
    /// Message verified and decrypted successfully
    Verified,
    
    /// Decrypted but sender key changed since verification
    KeyChanged,
    
    /// Could not verify sender
    Unverified,
    
    /// Decryption failed (corrupted or tampered)
    Failed,
}
```

### 10.4 Security Alerts

```rust
pub enum SecurityAlert {
    /// Peer's identity key changed
    KeyChanged {
        peer: String,
        old_fingerprint: String,
        new_fingerprint: String,
    },
    
    /// New device added to peer's identity
    NewDevice {
        peer: String,
        device_name: String,
    },
    
    /// Peer's key was revoked
    KeyRevoked {
        peer: String,
        reason: RevocationReason,
    },
    
    /// Channel admin changed
    AdminChanged {
        channel: String,
        new_admin: String,
    },
    
    /// Encryption degraded temporarily
    EncryptionDegraded {
        reason: String,
        expected_resolution: Duration,
    },
}
```

---

## 11. Threat Model

### 11.1 Adversary Classes

| Adversary | Capabilities | Mitigations |
|-----------|-------------|-------------|
| **Passive Network** | Observe traffic patterns, timing | Traffic padding, cover traffic |
| **Active Network** | Block, delay, replay messages | Authenticated encryption, sequence numbers |
| **Compromised Hub** | See all relayed traffic, metadata | E2E encryption, hub sees only ciphertext |
| **Compromised Peer** | Access group secrets, impersonate | Key rotation, membership auditing |
| **Compromised IRC** | User presence, discovery patterns | Minimal IRC use, encrypted signaling |
| **Device Theft** | Access local keys, history | Device encryption, remote revocation |
| **Targeted Attack** | Active MITM, social engineering | Identity verification, certificate pinning |

### 11.2 Security Properties

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Confidentiality** | Only members read messages | MLS group encryption |
| **Integrity** | Tampering detected | AEAD + signatures |
| **Authenticity** | Sender verification | Identity signatures |
| **Forward Secrecy** | Past messages protected | Ratcheting keys |
| **Post-Compromise** | Future messages protected | Key rotation, MLS updates |
| **Replay Protection** | Each message delivered once | Sequence numbers, nonce tracking |
| **Membership Privacy** | Non-members don't see membership | Encrypted membership list |
| **Metadata Privacy** | Channel names/topics encrypted | Signed encrypted metadata |

### 11.3 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                         TRUSTED                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Local Device                                               ││
│  │  - Decrypted messages                                       ││
│  │  - Private keys                                             ││
│  │  - Identity secrets                                         ││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│                     PARTIALLY TRUSTED                           │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Verified Peers                                             ││
│  │  - Can send messages to group                               ││
│  │  - Part of key derivation                                   ││
│  │  - Identity verified out-of-band                            ││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│                        UNTRUSTED                                │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │  IRC Server   │  │  Federation   │  │  Network      │       │
│  │  - Presence   │  │    Hubs       │  │  - Routing    │       │
│  │  - Discovery  │  │  - Relay      │  │  - Delivery   │       │
│  │  - No content │  │  - Ciphertext │  │  - Timing     │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

### 11.4 Attack Scenarios and Mitigations

#### 11.4.1 MITM During Key Exchange
```
Attacker intercepts X3DH key exchange via IRC

Mitigation:
1. Out-of-band verification (safety numbers, QR codes)
2. Trust-on-first-use with key pinning
3. Web of trust propagation
4. Certificate transparency for long-term keys
```

#### 11.4.2 Compromised Federation Hub
```
Hub operator attempts to decrypt relayed traffic

Mitigation:
1. E2E encryption - hub never sees plaintext
2. Multiple hub paths - no single point of interception
3. Padding to hide message sizes
4. Decoy traffic to hide patterns
```

#### 11.4.3 Denial of Service via IRC
```
IRC server blocks NAIS discovery channels

Mitigation:
1. Multiple IRC networks for redundancy
2. Direct IP exchange via out-of-band means
3. Federation hub provides alternative discovery
4. Cached peer addresses for existing channels
```

#### 11.4.4 Membership Enumeration
```
Observer attempts to learn channel membership

Mitigation:
1. IRC channel shows only IRC usernames
2. NAIS identity not correlated to IRC nick
3. Encrypted membership list in metadata
4. Phantom members to obscure true count
```

---

## 12. Failure Scenarios

### 12.1 Failure Modes

| Failure | Impact | Recovery |
|---------|--------|----------|
| IRC disconnection | No new peer discovery | Use cached peers, hub discovery |
| Hub unavailable | NAT-restricted peers isolated | Peer-to-peer relay, return when available |
| Peer offline | Messages not delivered | Queue + store-forward via hub |
| Key mismatch | Peer communication fails | Request key update, re-verify |
| Network partition | Channel splits | Merge when reconnected |
| Clock skew | Message ordering issues | Use logical clocks, tolerate drift |

### 12.2 Graceful Degradation Paths

```rust
pub struct DegradationManager {
    /// Current operational mode
    mode: OperationalMode,
    
    /// Fallback strategies by priority
    fallbacks: Vec<FallbackStrategy>,
}

pub enum OperationalMode {
    /// Full functionality
    Normal,
    
    /// IRC unavailable, using cached state
    OfflineDiscovery,
    
    /// All hubs unavailable
    DirectMeshOnly,
    
    /// Severe connectivity issues
    StoreAndForward,
    
    /// Complete isolation
    LocalQueueOnly,
}

impl DegradationManager {
    pub fn handle_failure(&mut self, failure: FailureType) -> Action {
        match failure {
            FailureType::IrcDisconnect => {
                self.mode = OperationalMode::OfflineDiscovery;
                // Continue with known peers
                Action::UseCachedDiscovery
            }
            FailureType::AllHubsDown => {
                self.mode = OperationalMode::DirectMeshOnly;
                // Attempt direct connections only
                Action::DisableRelayRouting
            }
            FailureType::NoConnectivity => {
                self.mode = OperationalMode::LocalQueueOnly;
                // Queue messages locally
                Action::EnableOfflineQueue
            }
        }
    }
}
```

### 12.3 Partition Healing

```rust
impl NaisChannel {
    /// Handle network partition healing
    pub async fn heal_partition(&mut self, reconnected_peers: Vec<PeerId>) {
        // 1. Exchange message histories
        let our_history = self.get_message_ids_since(self.last_sync);
        
        for peer in reconnected_peers {
            let their_history = peer.request_message_ids().await;
            
            // 2. Request missing messages
            let missing = their_history.difference(&our_history);
            for msg_id in missing {
                if let Ok(msg) = peer.request_message(msg_id).await {
                    self.replay_message(msg);
                }
            }
            
            // 3. Send our missing messages
            let they_missing = our_history.difference(&their_history);
            for msg_id in they_missing {
                peer.send_message(self.get_message(msg_id)).await;
            }
        }
        
        // 4. Reconcile membership changes
        self.reconcile_membership().await;
        
        // 5. Update MLS epoch if needed
        self.sync_mls_state().await;
    }
}
```

---

## 13. Tradeoff Analysis

### 13.1 Security vs. Usability

| Decision | Security Impact | Usability Impact | Choice |
|----------|-----------------|------------------|--------|
| Mandatory verification | High - prevents MITM | Low - extra steps | Optional but encouraged |
| Key rotation frequency | High with frequent | Low with frequent | Adaptive based on activity |
| Device authorization | High - limits attack surface | Medium - multi-step | Streamlined with QR |
| Metadata encryption | High - protects channel info | Low - slight overhead | Always encrypted |
| Forward secrecy | High - protects history | Medium - key management | Always enabled |

### 13.2 Performance vs. Security

| Decision | Performance Impact | Security Impact | Choice |
|----------|-------------------|-----------------|--------|
| MLS tree operations | O(log n) per message | Full PFS | Accept for groups < 1000 |
| Message padding | Bandwidth overhead | Traffic analysis resistance | Optional, recommended |
| Redundant delivery | 2-3x bandwidth | Reliability | Configurable per channel |
| Signature verification | CPU overhead | Authentication | Always verify |
| Double encryption | 2x crypto ops | Defense in depth | Use for sensitive channels |

### 13.3 Centralization vs. Resilience

| Aspect | Centralized | Decentralized | Our Approach |
|--------|-------------|---------------|--------------|
| Discovery | Single IRC network | No discovery | Multiple IRC + hub fallback |
| Relay | Central TURN | No relay | Federated hubs |
| Key distribution | Key server | In-band only | In-band with hub assist |
| Metadata | Central storage | Peer-to-peer | P2P with hub cache |

### 13.4 Latency vs. Security

```
Message Latency Breakdown:
┌────────────────────────────────────────────────────────────────┐
│ Direct P2P (best case):                                        │
│   Encryption: 1-2ms                                            │
│   Network RTT: 10-50ms                                         │
│   Decryption: 1-2ms                                            │
│   Total: ~15-55ms                                              │
├────────────────────────────────────────────────────────────────┤
│ Hub Relay (typical):                                           │
│   Encryption: 1-2ms                                            │
│   To Hub: 20-100ms                                             │
│   Hub Processing: 1-5ms                                        │
│   From Hub: 20-100ms                                           │
│   Decryption: 1-2ms                                            │
│   Total: ~45-210ms                                             │
├────────────────────────────────────────────────────────────────┤
│ Peer Relay (fallback):                                         │
│   Encryption: 1-2ms                                            │
│   To Relay Peer: 30-150ms                                      │
│   Relay Processing: 1-5ms                                      │
│   To Destination: 30-150ms                                     │
│   Decryption: 1-2ms                                            │
│   Total: ~65-310ms                                             │
└────────────────────────────────────────────────────────────────┘
```

---

## 14. Scalability Considerations

### 14.1 Group Size Scaling

| Members | MLS Tree Depth | Message Overhead | Strategy |
|---------|----------------|------------------|----------|
| 1-10 | 4 | 2-4 KB | Full MLS |
| 10-100 | 7 | 4-8 KB | Full MLS |
| 100-1000 | 10 | 8-16 KB | Sender Keys |
| 1000+ | N/A | Variable | Fanout via subgroups |

### 14.2 Sender Keys Optimization (Large Groups)

```rust
/// For groups > 100 members, use Sender Keys instead of full MLS
pub struct SenderKeyDistribution {
    /// Sender's current chain key
    chain_key: [u8; 32],
    
    /// Current message key index
    iteration: u32,
    
    /// Sender's signing key for this distribution
    signing_key: PublicKey,
}

impl SenderKeyDistribution {
    /// Derive next message key (forward secrecy within session)
    pub fn derive_next_key(&mut self) -> MessageKey {
        let message_key = hkdf_expand(&self.chain_key, b"MessageKey", self.iteration);
        self.chain_key = hkdf_expand(&self.chain_key, b"ChainKey", self.iteration);
        self.iteration += 1;
        message_key
    }
}
```

### 14.3 Hub Load Distribution

```rust
pub struct LoadBalancer {
    /// Known hubs with their load factors
    hubs: Vec<(HubId, f32)>,
    
    /// Current routing assignments
    assignments: HashMap<ChannelId, Vec<HubId>>,
}

impl LoadBalancer {
    /// Assign hubs for a channel based on member locations
    pub fn assign_hubs_for_channel(&mut self, channel: &ChannelId, members: &[PeerInfo]) {
        // 1. Group members by region
        let regions = self.group_by_region(members);
        
        // 2. Select lowest-load hub in each region
        let mut assigned = Vec::new();
        for region in regions {
            if let Some(hub) = self.select_hub_in_region(&region) {
                assigned.push(hub);
            }
        }
        
        // 3. Ensure at least 2 hubs for redundancy
        while assigned.len() < 2 {
            if let Some(hub) = self.select_global_lowest_load(&assigned) {
                assigned.push(hub);
            } else {
                break;
            }
        }
        
        self.assignments.insert(channel.clone(), assigned);
    }
}
```

### 14.4 Message Fanout Optimization

```rust
pub struct FanoutOptimizer {
    /// Threshold for using hierarchical fanout
    direct_fanout_limit: usize,
}

impl FanoutOptimizer {
    pub fn plan_fanout(&self, recipients: &[PeerId], topology: &RoutingTable) -> FanoutPlan {
        if recipients.len() <= self.direct_fanout_limit {
            // Direct fanout to all
            return FanoutPlan::Direct(recipients.to_vec());
        }
        
        // Hierarchical fanout through well-connected peers
        let mut plan = FanoutPlan::Hierarchical {
            tiers: Vec::new(),
        };
        
        // Tier 1: Direct connections
        let (direct, remaining) = self.partition_direct(recipients, topology);
        plan.add_tier(FanoutTier::Direct(direct));
        
        // Tier 2: Via hubs
        let (hub_routed, remaining) = self.partition_hub(remaining, topology);
        plan.add_tier(FanoutTier::Hub(hub_routed));
        
        // Tier 3: Via well-connected peers
        let (peer_relayed, remaining) = self.partition_peer_relay(remaining, topology);
        plan.add_tier(FanoutTier::PeerRelay(peer_relayed));
        
        // Remaining: Store-and-forward
        if !remaining.is_empty() {
            plan.add_tier(FanoutTier::StoreForward(remaining));
        }
        
        plan
    }
}
```

### 14.5 Bandwidth Estimation

```
Per-message overhead:
- Envelope header: 153 bytes
- MLS ciphertext overhead: ~50-100 bytes
- QUIC framing: ~20 bytes
- Typical total: ~220 bytes + plaintext

Estimated bandwidth per user per channel:
- Idle (heartbeat): ~5 KB/hour
- Light activity (10 msg/hr): ~25 KB/hour
- Active (100 msg/hr): ~200 KB/hour
- Heavy (1000 msg/hr): ~2 MB/hour

Hub relay bandwidth:
- Per relayed message: ~300 bytes
- 100-member channel, 100 msg/hr: ~3 MB/hour in, ~3 MB/hour out
- 1000-member channel, 100 msg/hr: ~30 MB/hour
```

---

## Appendix A: Constants and Configuration

```rust
pub mod config {
    use std::time::Duration;
    
    /// Protocol version
    pub const PROTOCOL_VERSION: u8 = 0x02;
    
    /// Maximum channel members (MLS limit)
    pub const MAX_CHANNEL_MEMBERS: usize = 10_000;
    
    /// Switch to sender keys threshold
    pub const SENDER_KEYS_THRESHOLD: usize = 100;
    
    /// Key rotation interval
    pub const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(7 * 24 * 3600);
    
    /// Key rotation message threshold
    pub const KEY_ROTATION_MESSAGES: u32 = 1000;
    
    /// Heartbeat interval
    pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
    
    /// Peer timeout
    pub const PEER_TIMEOUT: Duration = Duration::from_secs(120);
    
    /// Hub reconnect interval
    pub const HUB_RECONNECT_INTERVAL: Duration = Duration::from_secs(30);
    
    /// Message queue max size per peer
    pub const MESSAGE_QUEUE_MAX: usize = 1000;
    
    /// Message retention (offline delivery)
    pub const MESSAGE_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
    
    /// Maximum message size
    pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;
    
    /// STUN servers (default)
    pub const DEFAULT_STUN_SERVERS: &[&str] = &[
        "stun:stun.l.google.com:19302",
        "stun:stun1.l.google.com:19302",
    ];
    
    /// Federation hubs (default)
    pub const DEFAULT_HUBS: &[&str] = &[
        "hub.nais.example.com:4433",
    ];
}
```

---

## Appendix B: CTCP Protocol Extension

```rust
/// Extended CTCP commands for NSC signaling (via IRC)
pub mod ctcp {
    /// Announce NSC capability and request peer's KeyPackage
    /// Format: NAIS_HELLO <version> <identity_fingerprint> <key_package_hash>
    pub const HELLO: &str = "NAIS_HELLO";
    
    /// Send ICE offer for connection establishment
    /// Format: NAIS_ICE_OFFER <channel_id> <sdp_fingerprint> <ufrag> <pwd>
    pub const ICE_OFFER: &str = "NAIS_ICE_OFFER";
    
    /// Send ICE answer
    /// Format: NAIS_ICE_ANSWER <channel_id> <sdp_fingerprint> <ufrag> <pwd>
    pub const ICE_ANSWER: &str = "NAIS_ICE_ANSWER";
    
    /// Send ICE candidate
    /// Format: NAIS_ICE_CANDIDATE <channel_id> <candidate_string>
    pub const ICE_CANDIDATE: &str = "NAIS_ICE_CANDIDATE";
    
    /// Request connection via relay (when direct fails)
    /// Format: NAIS_RELAY_REQUEST <channel_id> <hub_id>
    pub const RELAY_REQUEST: &str = "NAIS_RELAY_REQUEST";
    
    /// Announce hub availability
    /// Format: NAIS_HUB_ANNOUNCE <hub_address> <hub_id> <signature>
    pub const HUB_ANNOUNCE: &str = "NAIS_HUB_ANNOUNCE";
    
    /// Request key package for group join
    /// Format: NAIS_KEYPACKAGE_REQUEST <channel_id>
    pub const KEYPACKAGE_REQUEST: &str = "NAIS_KEYPACKAGE_REQUEST";
    
    /// Provide key package (response, may be large - split if needed)
    /// Format: NAIS_KEYPACKAGE <channel_id> <part> <total_parts> <base64_data>
    pub const KEYPACKAGE: &str = "NAIS_KEYPACKAGE";
}
```

---

## Appendix C: Security Audit Checklist

- [ ] All messages encrypted with AEAD (AES-256-GCM or ChaCha20-Poly1305)
- [ ] All messages signed with Ed25519
- [ ] Key derivation uses HKDF-SHA256
- [ ] X3DH implemented per Signal specification
- [ ] MLS implementation follows RFC 9420
- [ ] Double Ratchet per Signal specification
- [ ] No plaintext ever transmitted over network
- [ ] No plaintext ever transmitted via IRC
- [ ] Identity keys stored encrypted at rest
- [ ] Session keys zeroized after use
- [ ] Constant-time comparison for MAC verification
- [ ] Replay protection via sequence numbers
- [ ] Message timestamps validated within tolerance
- [ ] Certificate chain validation implemented
- [ ] Revocation checking implemented
- [ ] UI never displays IRC channel names
- [ ] Security indicators accurately reflect state
- [ ] Key change warnings displayed prominently

---

*Document Version: 2.0*  
*Last Updated: February 2026*
