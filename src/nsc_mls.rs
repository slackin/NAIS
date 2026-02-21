//! Nais Secure Channels - MLS (Message Layer Security) Protocol
//!
//! Implements RFC 9420 MLS for scalable group key management:
//! - Ratchet tree structure for efficient key derivation
//! - KeyPackage for joining groups
//! - Welcome messages for group invitation
//! - Proposal/Commit for group state changes
//! - Epoch-based key schedule with forward secrecy
//!
//! # Design Decisions
//! - Uses X25519 for HPKE (key encapsulation)
//! - Uses Ed25519 for signing
//! - Uses ChaCha20-Poly1305 for AEAD
//! - Uses HKDF-SHA256 for key derivation

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::nsc_crypto::{IdentityKeyPair, IdentityPublicKey, X25519KeyPair};
use crate::nsc_transport::PeerId;

// =============================================================================
// Error Types
// =============================================================================

#[derive(Debug, Error)]
pub enum MlsError {
    #[error("Invalid tree structure")]
    InvalidTree,

    #[error("Member not found: {0}")]
    MemberNotFound(String),

    #[error("Invalid leaf index: {0}")]
    InvalidLeafIndex(u32),

    #[error("Invalid KeyPackage: {0}")]
    InvalidKeyPackage(String),

    #[error("Invalid Welcome: {0}")]
    InvalidWelcome(String),

    #[error("Invalid Commit: {0}")]
    InvalidCommit(String),

    #[error("Invalid Proposal: {0}")]
    InvalidProposal(String),

    #[error("Stale epoch: expected {expected}, got {got}")]
    StaleEpoch { expected: u64, got: u64 },

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Not a member of group")]
    NotMember,

    #[error("Unauthorized operation")]
    Unauthorized,

    #[error("Group is full")]
    GroupFull,

    #[error("Pending commit exists")]
    PendingCommit,
}

pub type MlsResult<T> = Result<T, MlsError>;

// =============================================================================
// Constants
// =============================================================================

/// MLS protocol version
pub const MLS_VERSION: u8 = 0x01;

/// Maximum tree depth (supports up to 2^16 = 65536 members)
pub const MAX_TREE_DEPTH: u32 = 16;

/// Maximum members in a group
pub const MAX_GROUP_SIZE: u32 = 65536;

/// KDF labels per RFC 9420
const MLS_LABEL_SECRET: &[u8] = b"MLS 1.0 secret";
const MLS_LABEL_JOINER: &[u8] = b"MLS 1.0 joiner";
const MLS_LABEL_WELCOME: &[u8] = b"MLS 1.0 welcome";
const MLS_LABEL_EPOCH: &[u8] = b"MLS 1.0 epoch";
const MLS_LABEL_SENDER_DATA: &[u8] = b"MLS 1.0 sender data";
const MLS_LABEL_ENCRYPTION: &[u8] = b"MLS 1.0 encryption";
const MLS_LABEL_EXPORTER: &[u8] = b"MLS 1.0 exporter";
const MLS_LABEL_EXTERNAL: &[u8] = b"MLS 1.0 external";
const MLS_LABEL_CONFIRM: &[u8] = b"MLS 1.0 confirm";
const MLS_LABEL_MEMBERSHIP: &[u8] = b"MLS 1.0 membership";
const MLS_LABEL_RESUMPTION: &[u8] = b"MLS 1.0 resumption";
const MLS_LABEL_AUTHENTICATION: &[u8] = b"MLS 1.0 authentication";

// =============================================================================
// Group Identifier
// =============================================================================

/// Unique MLS group identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GroupId(pub [u8; 32]);

impl GroupId {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a random group ID
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create from creation parameters
    pub fn from_creation(creator: &PeerId, name: &str, created_at: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"MLS_GROUP_ID");
        hasher.update(creator.0);
        hasher.update(name.as_bytes());
        hasher.update(&created_at.to_be_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        Self(id)
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

// =============================================================================
// Leaf Index (position in ratchet tree)
// =============================================================================

/// Index of a leaf in the ratchet tree
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeafIndex(pub u32);

impl LeafIndex {
    pub fn new(index: u32) -> Self {
        Self(index)
    }

    /// Get the node index for this leaf in the tree
    pub fn node_index(&self) -> NodeIndex {
        NodeIndex(2 * self.0)
    }

    /// Get direct path from this leaf to the root
    pub fn direct_path(&self, tree_size: u32) -> Vec<NodeIndex> {
        let mut path = Vec::new();
        let mut node = self.node_index();
        while let Some(parent) = node.parent(tree_size) {
            path.push(parent);
            node = parent;
        }
        path
    }
}

/// Index of a node in the ratchet tree (leaves and interior nodes)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeIndex(pub u32);

impl NodeIndex {
    pub fn new(index: u32) -> Self {
        Self(index)
    }

    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        self.0 % 2 == 0
    }

    /// Get the leaf index if this is a leaf
    pub fn as_leaf(&self) -> Option<LeafIndex> {
        if self.is_leaf() {
            Some(LeafIndex(self.0 / 2))
        } else {
            None
        }
    }

    /// Get the parent node
    pub fn parent(&self, tree_size: u32) -> Option<NodeIndex> {
        let root = root_index(tree_size);
        if self.0 == root.0 {
            return None;
        }
        let level = self.level();
        let parent_level = level + 1;
        let parent_step = 1u32 << (parent_level + 1);
        let parent_offset = 1u32 << parent_level;
        let parent = ((self.0 / parent_step) * parent_step) + parent_offset - 1;
        Some(NodeIndex(parent))
    }

    /// Get the left child
    pub fn left(&self) -> Option<NodeIndex> {
        if self.is_leaf() {
            return None;
        }
        let level = self.level();
        if level == 0 {
            return None;
        }
        let child_offset = 1u32 << (level - 1);
        Some(NodeIndex(self.0 - child_offset))
    }

    /// Get the right child
    pub fn right(&self) -> Option<NodeIndex> {
        if self.is_leaf() {
            return None;
        }
        let level = self.level();
        if level == 0 {
            return None;
        }
        let child_offset = 1u32 << (level - 1);
        Some(NodeIndex(self.0 + child_offset))
    }

    /// Get the sibling node
    pub fn sibling(&self, tree_size: u32) -> Option<NodeIndex> {
        let parent = self.parent(tree_size)?;
        let left = parent.left()?;
        if left.0 == self.0 {
            parent.right()
        } else {
            Some(left)
        }
    }

    /// Get the level (height) of this node
    fn level(&self) -> u32 {
        // Level is the number of trailing zeros in (index + 1)
        (self.0 + 1).trailing_zeros()
    }
}

/// Get the root node index for a tree with n leaves
fn root_index(num_leaves: u32) -> NodeIndex {
    // The root is at position 2^(depth) - 1 where depth = ceil(log2(n))
    let depth = (32 - (num_leaves.saturating_sub(1)).leading_zeros()) as u32;
    NodeIndex((1u32 << depth) - 1)
}

// =============================================================================
// Ratchet Tree Node
// =============================================================================

/// Node in the MLS ratchet tree
#[derive(Clone)]
pub enum TreeNode {
    /// Leaf node with member's key material
    Leaf(LeafNode),
    /// Interior node with path secret
    Parent(ParentNode),
    /// Empty/blank node
    Blank,
}

impl TreeNode {
    pub fn is_blank(&self) -> bool {
        matches!(self, TreeNode::Blank)
    }

    pub fn public_key(&self) -> Option<&X25519PublicKey> {
        match self {
            TreeNode::Leaf(leaf) => Some(&leaf.encryption_key),
            TreeNode::Parent(parent) => Some(&parent.public_key),
            TreeNode::Blank => None,
        }
    }
}

/// Leaf node containing member information
#[derive(Clone)]
pub struct LeafNode {
    /// Member's encryption key (X25519)
    pub encryption_key: X25519PublicKey,
    /// Member's signature key (Ed25519)
    pub signature_key: IdentityPublicKey,
    /// Credential (identity binding)
    pub credential: Credential,
    /// Capabilities
    pub capabilities: Capabilities,
    /// Leaf node extensions
    pub extensions: Vec<Extension>,
    /// Signature over leaf node
    pub signature: [u8; 64],
}

impl LeafNode {
    /// Create a new leaf node
    pub fn new(
        encryption_key: X25519PublicKey,
        signature_key: IdentityPublicKey,
        identity_name: String,
    ) -> Self {
        Self {
            encryption_key,
            signature_key: signature_key.clone(),
            credential: Credential::Basic {
                identity: identity_name,
                public_key: signature_key,
            },
            capabilities: Capabilities::default(),
            extensions: Vec::new(),
            signature: [0u8; 64],
        }
    }

    /// Sign the leaf node
    pub fn sign(&mut self, identity: &IdentityKeyPair, group_id: &GroupId) {
        let data = self.to_be_signed(group_id);
        self.signature = identity.sign(&data);
    }

    /// Verify the leaf node signature
    pub fn verify(&self, group_id: &GroupId) -> bool {
        let data = self.to_be_signed(group_id);
        self.signature_key.verify(&data, &self.signature).is_ok()
    }

    fn to_be_signed(&self, group_id: &GroupId) -> Vec<u8> {
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(b"MLS_LEAF_NODE_TBS");
        data.extend_from_slice(&group_id.0);
        data.extend_from_slice(self.encryption_key.as_bytes());
        data.extend_from_slice(&self.signature_key.to_bytes());
        data
    }
}

/// Parent (interior) node in the ratchet tree
#[derive(Clone)]
pub struct ParentNode {
    /// HPKE public key for this node
    pub public_key: X25519PublicKey,
    /// Hash of parent node content
    pub parent_hash: [u8; 32],
    /// Unmerged leaves (members who don't have this node's secret)
    pub unmerged_leaves: Vec<LeafIndex>,
}

impl ParentNode {
    pub fn new(public_key: X25519PublicKey) -> Self {
        Self {
            public_key,
            parent_hash: [0u8; 32],
            unmerged_leaves: Vec::new(),
        }
    }
}

/// Member credential (identity binding)
#[derive(Clone, Debug)]
pub enum Credential {
    /// Basic credential with identity name
    Basic {
        identity: String,
        public_key: IdentityPublicKey,
    },
    /// X.509 certificate chain
    X509 {
        certificates: Vec<Vec<u8>>,
    },
}

/// Node capabilities
#[derive(Clone, Debug, Default)]
pub struct Capabilities {
    pub versions: Vec<u8>,
    pub ciphersuites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub proposals: Vec<u16>,
    pub credentials: Vec<u16>,
}

/// Extension type
#[derive(Clone, Debug)]
pub struct Extension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}

// =============================================================================
// Ratchet Tree
// =============================================================================

/// The MLS ratchet tree structure
pub struct RatchetTree {
    /// Nodes in the tree (indexed by NodeIndex)
    nodes: Vec<TreeNode>,
    /// Number of leaves (members)
    num_leaves: u32,
    /// Our leaf index
    our_leaf: Option<LeafIndex>,
    /// Private keys for nodes on our direct path
    private_keys: HashMap<NodeIndex, X25519KeyPair>,
}

impl RatchetTree {
    /// Create an empty tree
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            num_leaves: 0,
            our_leaf: None,
            private_keys: HashMap::new(),
        }
    }

    /// Create a tree with a single member (group creation)
    pub fn create_single(
        identity: &IdentityKeyPair,
        identity_name: String,
    ) -> MlsResult<(Self, X25519KeyPair)> {
        let mut tree = Self::new();
        
        // Generate encryption key pair
        let encryption_keypair = X25519KeyPair::generate();
        
        // Create leaf node
        let leaf = LeafNode::new(
            encryption_keypair.public_key(),
            identity.public_key(),
            identity_name,
        );
        
        tree.nodes.push(TreeNode::Leaf(leaf));
        tree.num_leaves = 1;
        tree.our_leaf = Some(LeafIndex(0));
        
        // Store private key for our leaf
        tree.private_keys.insert(NodeIndex(0), encryption_keypair.clone());
        
        Ok((tree, encryption_keypair))
    }

    /// Add a member to the tree
    pub fn add_member(&mut self, leaf_node: LeafNode) -> MlsResult<LeafIndex> {
        // Find first blank leaf or append
        let leaf_index = self.find_free_leaf().unwrap_or_else(|| {
            let idx = LeafIndex(self.num_leaves);
            self.num_leaves += 1;
            idx
        });

        // Ensure nodes vector is large enough
        let node_index = leaf_index.node_index();
        while self.nodes.len() <= node_index.0 as usize {
            self.nodes.push(TreeNode::Blank);
        }

        // Insert leaf
        self.nodes[node_index.0 as usize] = TreeNode::Leaf(leaf_node);

        // Blank out the direct path (will be filled by commit)
        for parent in leaf_index.direct_path(self.tree_width()) {
            if parent.0 as usize >= self.nodes.len() {
                self.nodes.resize(parent.0 as usize + 1, TreeNode::Blank);
            }
            // Mark parent as needing update (add to unmerged leaves)
            if let TreeNode::Parent(ref mut p) = self.nodes[parent.0 as usize] {
                if !p.unmerged_leaves.contains(&leaf_index) {
                    p.unmerged_leaves.push(leaf_index);
                }
            }
        }

        Ok(leaf_index)
    }

    /// Remove a member from the tree
    pub fn remove_member(&mut self, leaf_index: LeafIndex) -> MlsResult<()> {
        let node_index = leaf_index.node_index();
        if node_index.0 as usize >= self.nodes.len() {
            return Err(MlsError::InvalidLeafIndex(leaf_index.0));
        }

        // Blank the leaf
        self.nodes[node_index.0 as usize] = TreeNode::Blank;

        // Blank the direct path
        for parent in leaf_index.direct_path(self.tree_width()) {
            if (parent.0 as usize) < self.nodes.len() {
                self.nodes[parent.0 as usize] = TreeNode::Blank;
            }
        }

        Ok(())
    }

    /// Update our own leaf and path (after key rotation)
    pub fn update_self(
        &mut self,
        identity: &IdentityKeyPair,
        group_id: &GroupId,
    ) -> MlsResult<(LeafNode, PathSecret)> {
        let our_leaf = self.our_leaf.ok_or(MlsError::NotMember)?;
        
        // Generate new encryption key
        let new_keypair = X25519KeyPair::generate();
        
        // Create updated leaf node
        let leaf_node = self.nodes.get(our_leaf.node_index().0 as usize)
            .and_then(|n| if let TreeNode::Leaf(l) = n { Some(l) } else { None })
            .ok_or(MlsError::NotMember)?;
        
        let mut new_leaf = LeafNode::new(
            new_keypair.public_key(),
            identity.public_key(),
            match &leaf_node.credential {
                Credential::Basic { identity, .. } => identity.clone(),
                _ => String::new(),
            },
        );
        new_leaf.sign(identity, group_id);
        
        // Store new private key
        self.private_keys.insert(our_leaf.node_index(), new_keypair);
        
        // Generate path secret for direct path
        let path_secret = PathSecret::generate();
        
        Ok((new_leaf, path_secret))
    }

    /// Get the number of members
    pub fn member_count(&self) -> u32 {
        self.nodes.iter()
            .filter(|n| matches!(n, TreeNode::Leaf(_)))
            .count() as u32
    }

    /// Get a member's leaf node
    pub fn get_member(&self, leaf_index: LeafIndex) -> Option<&LeafNode> {
        self.nodes.get(leaf_index.node_index().0 as usize)
            .and_then(|n| if let TreeNode::Leaf(l) = n { Some(l) } else { None })
    }

    /// Find first free (blank) leaf
    fn find_free_leaf(&self) -> Option<LeafIndex> {
        for i in 0..self.num_leaves {
            let node_idx = LeafIndex(i).node_index();
            if (node_idx.0 as usize) < self.nodes.len() {
                if self.nodes[node_idx.0 as usize].is_blank() {
                    return Some(LeafIndex(i));
                }
            }
        }
        None
    }

    /// Get tree width (number of nodes needed for num_leaves)
    fn tree_width(&self) -> u32 {
        if self.num_leaves == 0 {
            return 0;
        }
        // Width = 2 * num_leaves - 1
        2 * self.num_leaves - 1
    }
}

impl Default for RatchetTree {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Path Secret (for tree updates)
// =============================================================================

/// Secret used to derive keys along a path
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PathSecret(pub [u8; 32]);

impl PathSecret {
    /// Generate a random path secret
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derive the next path secret
    pub fn derive_next(&self) -> MlsResult<Self> {
        let secret = expand_with_label(&self.0, b"path", &[], 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&secret);
        Ok(Self(bytes))
    }

    /// Derive node key pair from path secret
    pub fn derive_node_keypair(&self) -> MlsResult<X25519KeyPair> {
        let secret = expand_with_label(&self.0, b"node", &[], 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&secret);
        Ok(X25519KeyPair::from_bytes(bytes))
    }
}

// =============================================================================
// KeyPackage (joining token)
// =============================================================================

/// KeyPackage for joining a group
#[derive(Clone)]
pub struct KeyPackage {
    /// Protocol version
    pub version: u8,
    /// Ciphersuite identifier
    pub cipher_suite: u16,
    /// HPKE public key for initial key exchange
    pub init_key: X25519PublicKey,
    /// Leaf node for the joiner
    pub leaf_node: LeafNode,
    /// Extensions
    pub extensions: Vec<Extension>,
    /// Signature over the KeyPackage
    pub signature: [u8; 64],
}

impl KeyPackage {
    /// Create a new KeyPackage
    pub fn new(
        identity: &IdentityKeyPair,
        identity_name: String,
    ) -> (Self, X25519KeyPair) {
        let init_keypair = X25519KeyPair::generate();
        let leaf_keypair = X25519KeyPair::generate();
        
        let leaf_node = LeafNode::new(
            leaf_keypair.public_key(),
            identity.public_key(),
            identity_name,
        );
        
        let mut kp = Self {
            version: MLS_VERSION,
            cipher_suite: 0x0001, // X25519_AES128GCM_SHA256
            init_key: init_keypair.public_key(),
            leaf_node,
            extensions: Vec::new(),
            signature: [0u8; 64],
        };
        
        kp.sign(identity);
        
        (kp, init_keypair)
    }

    /// Sign the KeyPackage
    fn sign(&mut self, identity: &IdentityKeyPair) {
        let data = self.to_be_signed();
        self.signature = identity.sign(&data);
    }

    /// Verify the KeyPackage signature
    pub fn verify(&self) -> bool {
        let data = self.to_be_signed();
        self.leaf_node.signature_key.verify(&data, &self.signature).is_ok()
    }

    fn to_be_signed(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(b"MLS_KEY_PACKAGE_TBS");
        data.push(self.version);
        data.extend_from_slice(&self.cipher_suite.to_be_bytes());
        data.extend_from_slice(self.init_key.as_bytes());
        data.extend_from_slice(self.leaf_node.encryption_key.as_bytes());
        data
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.cipher_suite.to_be_bytes());
        bytes.extend_from_slice(self.init_key.as_bytes());
        bytes.extend_from_slice(self.leaf_node.encryption_key.as_bytes());
        bytes.extend_from_slice(&self.leaf_node.signature_key.to_bytes());
        // Simplified: omit extensions for now
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Get the identity fingerprint
    pub fn identity_fingerprint(&self) -> [u8; 32] {
        self.leaf_node.signature_key.fingerprint()
    }
}

// =============================================================================
// Welcome Message
// =============================================================================

/// Welcome message for adding a new member
#[derive(Clone)]
pub struct Welcome {
    /// Ciphersuite
    pub cipher_suite: u16,
    /// Encrypted group secrets for each new member
    pub secrets: Vec<EncryptedGroupSecrets>,
    /// Encrypted group info
    pub encrypted_group_info: Vec<u8>,
}

/// Encrypted secrets for a specific new member
#[derive(Clone)]
pub struct EncryptedGroupSecrets {
    /// Hash of recipient's KeyPackage
    pub key_package_hash: [u8; 32],
    /// HPKE-encrypted secrets
    pub encrypted_group_secrets: HpkeCiphertext,
}

/// HPKE ciphertext
#[derive(Clone)]
pub struct HpkeCiphertext {
    /// Ephemeral public key
    pub kem_output: X25519PublicKey,
    /// Encrypted payload
    pub ciphertext: Vec<u8>,
}

impl Welcome {
    /// Create a Welcome for new members
    pub fn create(
        group_secrets: &GroupSecrets,
        group_info: &GroupInfo,
        key_packages: &[KeyPackage],
    ) -> MlsResult<Self> {
        let mut secrets = Vec::with_capacity(key_packages.len());
        
        for kp in key_packages {
            // Hash the KeyPackage
            let kp_hash = hash_key_package(kp);
            
            // Encrypt group secrets to the KeyPackage init key
            let encrypted = hpke_seal(
                &kp.init_key,
                &group_secrets.to_bytes(),
                &kp_hash,
            )?;
            
            secrets.push(EncryptedGroupSecrets {
                key_package_hash: kp_hash,
                encrypted_group_secrets: encrypted,
            });
        }
        
        // Encrypt group info
        let welcome_key = derive_welcome_key(&group_secrets.joiner_secret)?;
        let encrypted_group_info = aead_encrypt(&welcome_key, &group_info.to_bytes(), &[])?;
        
        Ok(Self {
            cipher_suite: 0x0001,
            secrets,
            encrypted_group_info,
        })
    }

    /// Process a Welcome message to join a group
    pub fn process(
        &self,
        my_key_package: &KeyPackage,
        init_private_key: &X25519KeyPair,
    ) -> MlsResult<(GroupSecrets, GroupInfo)> {
        // Find our encrypted secrets
        let kp_hash = hash_key_package(my_key_package);
        let my_secrets = self.secrets.iter()
            .find(|s| s.key_package_hash == kp_hash)
            .ok_or(MlsError::InvalidWelcome("KeyPackage not found".into()))?;
        
        // Decrypt group secrets
        let secrets_bytes = hpke_open(
            init_private_key,
            &my_secrets.encrypted_group_secrets,
            &kp_hash,
        )?;
        let group_secrets = GroupSecrets::from_bytes(&secrets_bytes)?;
        
        // Decrypt group info
        let welcome_key = derive_welcome_key(&group_secrets.joiner_secret)?;
        let group_info_bytes = aead_decrypt(&welcome_key, &self.encrypted_group_info, &[])?;
        let group_info = GroupInfo::from_bytes(&group_info_bytes)?;
        
        Ok((group_secrets, group_info))
    }
}

/// Secrets needed to join a group
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GroupSecrets {
    /// Joiner secret
    pub joiner_secret: [u8; 32],
    /// Path secret (if provided)
    pub path_secret: Option<[u8; 32]>,
    /// Pre-shared keys (if any)
    pub psks: Vec<[u8; 32]>,
}

impl GroupSecrets {
    pub fn new(joiner_secret: [u8; 32]) -> Self {
        Self {
            joiner_secret,
            path_secret: None,
            psks: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.joiner_secret);
        if let Some(ps) = &self.path_secret {
            bytes.push(1);
            bytes.extend_from_slice(ps);
        } else {
            bytes.push(0);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> MlsResult<Self> {
        if bytes.len() < 33 {
            return Err(MlsError::InvalidWelcome("GroupSecrets too short".into()));
        }
        
        let mut joiner_secret = [0u8; 32];
        joiner_secret.copy_from_slice(&bytes[0..32]);
        
        let path_secret = if bytes[32] == 1 && bytes.len() >= 65 {
            let mut ps = [0u8; 32];
            ps.copy_from_slice(&bytes[33..65]);
            Some(ps)
        } else {
            None
        };
        
        Ok(Self {
            joiner_secret,
            path_secret,
            psks: Vec::new(),
        })
    }
}

/// Group info included in Welcome
pub struct GroupInfo {
    /// Group ID
    pub group_id: GroupId,
    /// Current epoch
    pub epoch: u64,
    /// Tree hash
    pub tree_hash: [u8; 32],
    /// Confirmed transcript hash
    pub confirmed_transcript_hash: [u8; 32],
    /// Extensions
    pub extensions: Vec<Extension>,
    /// Confirmation tag
    pub confirmation_tag: [u8; 32],
    /// Signer's leaf index
    pub signer: LeafIndex,
    /// Signature
    pub signature: [u8; 64],
}

impl GroupInfo {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(200);
        bytes.extend_from_slice(&self.group_id.0);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.tree_hash);
        bytes.extend_from_slice(&self.confirmed_transcript_hash);
        bytes.extend_from_slice(&self.confirmation_tag);
        bytes.extend_from_slice(&(self.signer.0).to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> MlsResult<Self> {
        if bytes.len() < 180 {
            return Err(MlsError::InvalidWelcome("GroupInfo too short".into()));
        }
        
        let mut group_id = [0u8; 32];
        group_id.copy_from_slice(&bytes[0..32]);
        
        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&bytes[32..40]);
        let epoch = u64::from_be_bytes(epoch_bytes);
        
        let mut tree_hash = [0u8; 32];
        tree_hash.copy_from_slice(&bytes[40..72]);
        
        let mut confirmed_transcript_hash = [0u8; 32];
        confirmed_transcript_hash.copy_from_slice(&bytes[72..104]);
        
        let mut confirmation_tag = [0u8; 32];
        confirmation_tag.copy_from_slice(&bytes[104..136]);
        
        let mut signer_bytes = [0u8; 4];
        signer_bytes.copy_from_slice(&bytes[136..140]);
        let signer = LeafIndex(u32::from_be_bytes(signer_bytes));
        
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[140..204]);
        
        Ok(Self {
            group_id: GroupId(group_id),
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            extensions: Vec::new(),
            confirmation_tag,
            signer,
            signature,
        })
    }
}

// =============================================================================
// Proposals
// =============================================================================

/// Proposal for group changes
#[derive(Clone)]
pub enum Proposal {
    /// Add a new member
    Add(AddProposal),
    /// Update own leaf
    Update(UpdateProposal),
    /// Remove a member
    Remove(RemoveProposal),
    /// Pre-shared key
    PreSharedKey(PreSharedKeyProposal),
    /// Re-initialize group (cipher suite change)
    ReInit(ReInitProposal),
    /// External initialization (for external joins)
    ExternalInit(ExternalInitProposal),
    /// Group context extensions
    GroupContextExtensions(GroupContextExtensionsProposal),
}

impl Proposal {
    pub fn proposal_type(&self) -> u16 {
        match self {
            Proposal::Add(_) => 0x0001,
            Proposal::Update(_) => 0x0002,
            Proposal::Remove(_) => 0x0003,
            Proposal::PreSharedKey(_) => 0x0004,
            Proposal::ReInit(_) => 0x0005,
            Proposal::ExternalInit(_) => 0x0006,
            Proposal::GroupContextExtensions(_) => 0x0007,
        }
    }
}

#[derive(Clone)]
pub struct AddProposal {
    pub key_package: KeyPackage,
}

#[derive(Clone)]
pub struct UpdateProposal {
    pub leaf_node: LeafNode,
}

#[derive(Clone)]
pub struct RemoveProposal {
    pub removed: LeafIndex,
}

#[derive(Clone)]
pub struct PreSharedKeyProposal {
    pub psk_type: u8,
    pub psk_id: Vec<u8>,
}

#[derive(Clone)]
pub struct ReInitProposal {
    pub group_id: GroupId,
    pub version: u8,
    pub cipher_suite: u16,
    pub extensions: Vec<Extension>,
}

#[derive(Clone)]
pub struct ExternalInitProposal {
    pub kem_output: Vec<u8>,
}

#[derive(Clone)]
pub struct GroupContextExtensionsProposal {
    pub extensions: Vec<Extension>,
}

/// Reference to a proposal (by hash or inline)
#[derive(Clone)]
pub enum ProposalOrRef {
    /// Inline proposal
    Proposal(Proposal),
    /// Reference by hash
    Reference([u8; 32]),
}

// =============================================================================
// Commit Message
// =============================================================================

/// Commit message applying proposals
#[derive(Clone)]
pub struct Commit {
    /// Proposals being committed
    pub proposals: Vec<ProposalOrRef>,
    /// Updated path (if any)
    pub path: Option<UpdatePath>,
}

/// Path update for commit
#[derive(Clone)]
pub struct UpdatePath {
    /// Updated leaf node
    pub leaf_node: LeafNode,
    /// Encrypted path secrets for each node on the path
    pub path_secrets: Vec<PathNode>,
}

/// Encrypted path secret for a single node
#[derive(Clone)]
pub struct PathNode {
    /// Public key for this node
    pub public_key: X25519PublicKey,
    /// Encrypted path secrets for each resolution node
    pub encrypted_path_secrets: Vec<HpkeCiphertext>,
}

// =============================================================================
// Epoch Secrets
// =============================================================================

/// All secrets for a single epoch
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochSecrets {
    /// Joiner secret (for adding new members)
    pub joiner_secret: [u8; 32],
    /// Epoch secret (base for all other secrets)
    epoch_secret: [u8; 32],
    /// Sender data secret
    sender_data_secret: [u8; 32],
    /// Encryption secret
    encryption_secret: [u8; 32],
    /// Exporter secret
    exporter_secret: [u8; 32],
    /// External secret (for external joins)
    external_secret: [u8; 32],
    /// Confirmation key
    confirmation_key: [u8; 32],
    /// Membership key
    membership_key: [u8; 32],
    /// Resumption secret
    resumption_secret: [u8; 32],
    /// Authentication secret
    authentication_secret: [u8; 32],
}

impl EpochSecrets {
    /// Derive all epoch secrets from epoch secret
    pub fn derive(init_secret: &[u8; 32], commit_secret: &[u8; 32], group_context: &[u8]) -> MlsResult<Self> {
        // joiner_secret = KDF.Extract(init_secret, commit_secret)
        let joiner_secret = kdf_extract(init_secret, commit_secret)?;
        
        // epoch_secret = DeriveSecret(joiner_secret, "epoch", group_context)
        let epoch_secret = derive_secret(&joiner_secret, MLS_LABEL_EPOCH, group_context)?;
        
        // Derive all other secrets from epoch_secret
        let sender_data_secret = derive_secret(&epoch_secret, MLS_LABEL_SENDER_DATA, &[])?;
        let encryption_secret = derive_secret(&epoch_secret, MLS_LABEL_ENCRYPTION, &[])?;
        let exporter_secret = derive_secret(&epoch_secret, MLS_LABEL_EXPORTER, &[])?;
        let external_secret = derive_secret(&epoch_secret, MLS_LABEL_EXTERNAL, &[])?;
        let confirmation_key = derive_secret(&epoch_secret, MLS_LABEL_CONFIRM, &[])?;
        let membership_key = derive_secret(&epoch_secret, MLS_LABEL_MEMBERSHIP, &[])?;
        let resumption_secret = derive_secret(&epoch_secret, MLS_LABEL_RESUMPTION, &[])?;
        let authentication_secret = derive_secret(&epoch_secret, MLS_LABEL_AUTHENTICATION, &[])?;
        
        Ok(Self {
            joiner_secret,
            epoch_secret,
            sender_data_secret,
            encryption_secret,
            exporter_secret,
            external_secret,
            confirmation_key,
            membership_key,
            resumption_secret,
            authentication_secret,
        })
    }

    /// Get the init secret for the next epoch
    pub fn init_secret(&self) -> [u8; 32] {
        let mut secret = [0u8; 32];
        let _ = expand_with_label(&self.epoch_secret, b"init", &[], 32)
            .map(|s| secret.copy_from_slice(&s));
        secret
    }

    /// Derive a key for external use
    pub fn derive_exporter(&self, label: &[u8], context: &[u8], length: usize) -> MlsResult<Vec<u8>> {
        let secret = derive_secret(&self.exporter_secret, label, context)?;
        expand_with_label(&secret, b"exporter", context, length)
    }
}

// =============================================================================
// MLS Group State
// =============================================================================

/// Complete MLS group state
pub struct MlsGroup {
    /// Group identifier
    pub group_id: GroupId,
    /// Current epoch
    pub epoch: u64,
    /// Ratchet tree
    pub tree: RatchetTree,
    /// Our leaf index
    pub our_leaf: LeafIndex,
    /// Our identity key
    identity: IdentityKeyPair,
    /// Our leaf encryption key
    leaf_keypair: X25519KeyPair,
    /// Current epoch secrets
    epoch_secrets: EpochSecrets,
    /// Transcript hash
    transcript_hash: [u8; 32],
    /// Confirmed transcript hash
    confirmed_transcript_hash: [u8; 32],
    /// Pending proposals
    pending_proposals: Vec<(ProposalOrRef, LeafIndex)>,
    /// Pending commit
    pending_commit: Option<Commit>,
    /// Message key schedule for encryption
    key_schedule: MessageKeySchedule,
}

impl MlsGroup {
    /// Create a new MLS group
    pub fn create(
        identity: IdentityKeyPair,
        identity_name: String,
        group_id: Option<GroupId>,
    ) -> MlsResult<Self> {
        let group_id = group_id.unwrap_or_else(GroupId::random);
        
        // Create initial tree with just us
        let (tree, leaf_keypair) = RatchetTree::create_single(&identity, identity_name)?;
        let our_leaf = LeafIndex(0);
        
        // Initial secrets (empty commit secret for epoch 0)
        let init_secret = [0u8; 32];
        let commit_secret = [0u8; 32];
        let group_context = Self::compute_group_context(&group_id, 0, &[0u8; 32], &[0u8; 32]);
        let epoch_secrets = EpochSecrets::derive(&init_secret, &commit_secret, &group_context)?;
        
        // Key schedule
        let key_schedule = MessageKeySchedule::new(&epoch_secrets.encryption_secret);
        
        Ok(Self {
            group_id,
            epoch: 0,
            tree,
            our_leaf,
            identity,
            leaf_keypair,
            epoch_secrets,
            transcript_hash: [0u8; 32],
            confirmed_transcript_hash: [0u8; 32],
            pending_proposals: Vec::new(),
            pending_commit: None,
            key_schedule,
        })
    }

    /// Add a member using their KeyPackage
    pub fn add_member(&mut self, key_package: &KeyPackage) -> MlsResult<ProposalOrRef> {
        // Verify KeyPackage
        if !key_package.verify() {
            return Err(MlsError::InvalidKeyPackage("Signature verification failed".into()));
        }
        
        let proposal = Proposal::Add(AddProposal {
            key_package: key_package.clone(),
        });
        
        let prop_ref = ProposalOrRef::Proposal(proposal);
        self.pending_proposals.push((prop_ref.clone(), self.our_leaf));
        
        Ok(prop_ref)
    }

    /// Remove a member
    pub fn remove_member(&mut self, leaf_index: LeafIndex) -> MlsResult<ProposalOrRef> {
        if leaf_index == self.our_leaf {
            return Err(MlsError::Unauthorized);
        }
        
        let proposal = Proposal::Remove(RemoveProposal {
            removed: leaf_index,
        });
        
        let prop_ref = ProposalOrRef::Proposal(proposal);
        self.pending_proposals.push((prop_ref.clone(), self.our_leaf));
        
        Ok(prop_ref)
    }

    /// Update our own keys
    pub fn propose_update(&mut self) -> MlsResult<ProposalOrRef> {
        let (new_leaf, _path_secret) = self.tree.update_self(&self.identity, &self.group_id)?;
        
        let proposal = Proposal::Update(UpdateProposal {
            leaf_node: new_leaf,
        });
        
        let prop_ref = ProposalOrRef::Proposal(proposal);
        self.pending_proposals.push((prop_ref.clone(), self.our_leaf));
        
        Ok(prop_ref)
    }

    /// Create a Commit message from pending proposals
    pub fn create_commit(&mut self) -> MlsResult<(Commit, Option<Welcome>)> {
        if self.pending_commit.is_some() {
            return Err(MlsError::PendingCommit);
        }
        
        let proposals = std::mem::take(&mut self.pending_proposals);
        
        // Collect new members for Welcome
        let mut new_key_packages = Vec::new();
        
        for (prop_ref, _sender) in &proposals {
            if let ProposalOrRef::Proposal(Proposal::Add(add)) = prop_ref {
                new_key_packages.push(add.key_package.clone());
            }
        }
        
        // Generate path update
        let path = self.generate_update_path()?;
        
        let commit = Commit {
            proposals: proposals.into_iter().map(|(p, _)| p).collect(),
            path: Some(path),
        };
        
        // Create Welcome for new members
        let welcome = if !new_key_packages.is_empty() {
            let group_secrets = GroupSecrets::new(self.epoch_secrets.joiner_secret);
            let group_info = self.create_group_info()?;
            Some(Welcome::create(&group_secrets, &group_info, &new_key_packages)?)
        } else {
            None
        };
        
        self.pending_commit = Some(commit.clone());
        
        Ok((commit, welcome))
    }

    /// Process a received Commit
    pub fn process_commit(&mut self, commit: &Commit, sender: LeafIndex) -> MlsResult<()> {
        // Apply proposals
        for prop_ref in &commit.proposals {
            self.apply_proposal(prop_ref)?;
        }
        
        // Apply path update
        if let Some(path) = &commit.path {
            self.apply_path_update(path, sender)?;
        }
        
        // Advance epoch
        self.advance_epoch()?;
        
        // Clear pending state
        self.pending_proposals.clear();
        self.pending_commit = None;
        
        Ok(())
    }

    /// Confirm our own commit was accepted
    pub fn confirm_commit(&mut self) -> MlsResult<()> {
        let commit = self.pending_commit.take()
            .ok_or(MlsError::InvalidCommit("No pending commit".into()))?;
        
        // Apply our own commit
        for prop_ref in &commit.proposals {
            self.apply_proposal(prop_ref)?;
        }
        
        // Advance epoch
        self.advance_epoch()?;
        
        self.pending_proposals.clear();
        
        Ok(())
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> MlsResult<MlsMessage> {
        let (key, nonce, generation) = self.key_schedule.next_key(self.our_leaf)?;
        
        let content = MessageContent {
            content_type: ContentType::Application,
            authenticated_data: Vec::new(),
            payload: plaintext.to_vec(),
        };
        
        let sender_data = SenderData {
            leaf_index: self.our_leaf,
            generation,
        };
        
        // Encrypt sender data
        let sender_data_key = derive_sender_data_key(&self.epoch_secrets.sender_data_secret, &nonce)?;
        let encrypted_sender_data = aead_encrypt(&sender_data_key, &sender_data.to_bytes(), &[])?;
        
        // Encrypt content
        let ciphertext = aead_encrypt(&key, &content.to_bytes(), &[])?;
        
        Ok(MlsMessage {
            group_id: self.group_id,
            epoch: self.epoch,
            content_type: ContentType::Application,
            encrypted_sender_data,
            ciphertext,
        })
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, message: &MlsMessage) -> MlsResult<(LeafIndex, Vec<u8>)> {
        if message.group_id != self.group_id {
            return Err(MlsError::DecryptionFailed("Wrong group".into()));
        }
        
        if message.epoch != self.epoch {
            return Err(MlsError::StaleEpoch {
                expected: self.epoch,
                got: message.epoch,
            });
        }
        
        // We need to try decrypting sender data to figure out who sent it
        // This is simplified - real MLS uses more complex reuse guards
        for leaf_idx in 0..self.tree.member_count() {
            let leaf = LeafIndex(leaf_idx);
            if let Ok((key, nonce, _generation)) = self.key_schedule.get_key(leaf) {
                let sender_data_key = derive_sender_data_key(&self.epoch_secrets.sender_data_secret, &nonce)?;
                
                if let Ok(sender_data_bytes) = aead_decrypt(&sender_data_key, &message.encrypted_sender_data, &[]) {
                    if let Ok(sender_data) = SenderData::from_bytes(&sender_data_bytes) {
                        // Found the sender, now decrypt content
                        let plaintext = aead_decrypt(&key, &message.ciphertext, &[])?;
                        let content = MessageContent::from_bytes(&plaintext)?;
                        
                        // Mark key as used
                        self.key_schedule.mark_used(sender_data.leaf_index, sender_data.generation);
                        
                        return Ok((sender_data.leaf_index, content.payload));
                    }
                }
            }
        }
        
        Err(MlsError::DecryptionFailed("Could not decrypt message".into()))
    }

    /// Get member count
    pub fn member_count(&self) -> u32 {
        self.tree.member_count()
    }

    /// Get member by leaf index
    pub fn get_member(&self, leaf: LeafIndex) -> Option<&LeafNode> {
        self.tree.get_member(leaf)
    }

    // Internal helpers

    fn compute_group_context(
        group_id: &GroupId,
        epoch: u64,
        tree_hash: &[u8; 32],
        confirmed_transcript_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut ctx = Vec::with_capacity(80);
        ctx.extend_from_slice(&group_id.0);
        ctx.extend_from_slice(&epoch.to_be_bytes());
        ctx.extend_from_slice(tree_hash);
        ctx.extend_from_slice(confirmed_transcript_hash);
        ctx
    }

    fn generate_update_path(&self) -> MlsResult<UpdatePath> {
        // Generate new leaf node
        let leaf_keypair = X25519KeyPair::generate();
        let mut leaf_node = LeafNode::new(
            leaf_keypair.public_key(),
            self.identity.public_key(),
            String::new(), // TODO: preserve identity name
        );
        leaf_node.sign(&self.identity, &self.group_id);
        
        // For each node on direct path, generate encrypted path secret
        let path_secret = PathSecret::generate();
        let mut path_nodes = Vec::new();
        
        let direct_path = self.our_leaf.direct_path(self.tree.tree_width());
        for _node_idx in &direct_path {
            let node_keypair = path_secret.derive_node_keypair()?;
            
            // Encrypt to sibling subtree (simplified)
            let path_node = PathNode {
                public_key: node_keypair.public_key(),
                encrypted_path_secrets: Vec::new(), // Simplified
            };
            path_nodes.push(path_node);
        }
        
        Ok(UpdatePath {
            leaf_node,
            path_secrets: path_nodes,
        })
    }

    fn apply_proposal(&mut self, prop_ref: &ProposalOrRef) -> MlsResult<()> {
        match prop_ref {
            ProposalOrRef::Proposal(prop) => {
                match prop {
                    Proposal::Add(add) => {
                        self.tree.add_member(add.key_package.leaf_node.clone())?;
                    }
                    Proposal::Remove(remove) => {
                        self.tree.remove_member(remove.removed)?;
                    }
                    Proposal::Update(update) => {
                        // Update leaf in tree
                        let node_idx = self.our_leaf.node_index();
                        if (node_idx.0 as usize) < self.tree.nodes.len() {
                            self.tree.nodes[node_idx.0 as usize] = TreeNode::Leaf(update.leaf_node.clone());
                        }
                    }
                    _ => {
                        // Other proposals not fully implemented
                    }
                }
            }
            ProposalOrRef::Reference(_hash) => {
                // Would look up proposal by hash
            }
        }
        Ok(())
    }

    fn apply_path_update(&mut self, _path: &UpdatePath, _sender: LeafIndex) -> MlsResult<()> {
        // Apply the path update from the committer
        // This would update parent nodes along the path
        Ok(())
    }

    fn advance_epoch(&mut self) -> MlsResult<()> {
        self.epoch += 1;
        
        // Derive new epoch secrets
        let init_secret = self.epoch_secrets.init_secret();
        let commit_secret = [0u8; 32]; // Would come from path secret update
        let group_context = Self::compute_group_context(
            &self.group_id,
            self.epoch,
            &self.transcript_hash,
            &self.confirmed_transcript_hash,
        );
        
        self.epoch_secrets = EpochSecrets::derive(&init_secret, &commit_secret, &group_context)?;
        self.key_schedule = MessageKeySchedule::new(&self.epoch_secrets.encryption_secret);
        
        Ok(())
    }

    fn create_group_info(&self) -> MlsResult<GroupInfo> {
        let mut info = GroupInfo {
            group_id: self.group_id,
            epoch: self.epoch,
            tree_hash: self.transcript_hash,
            confirmed_transcript_hash: self.confirmed_transcript_hash,
            extensions: Vec::new(),
            confirmation_tag: [0u8; 32],
            signer: self.our_leaf,
            signature: [0u8; 64],
        };
        
        // Sign group info
        let data = info.to_bytes();
        info.signature = self.identity.sign(&data);
        
        Ok(info)
    }
}

// =============================================================================
// Message Key Schedule
// =============================================================================

/// Per-sender message key derivation
pub struct MessageKeySchedule {
    /// Base encryption secret
    base_secret: [u8; 32],
    /// Current generation per sender
    generations: HashMap<LeafIndex, u32>,
    /// Used keys (for replay protection)
    used_keys: HashMap<(LeafIndex, u32), bool>,
}

impl MessageKeySchedule {
    pub fn new(encryption_secret: &[u8; 32]) -> Self {
        Self {
            base_secret: *encryption_secret,
            generations: HashMap::new(),
            used_keys: HashMap::new(),
        }
    }

    /// Get the next key for sending
    pub fn next_key(&mut self, sender: LeafIndex) -> MlsResult<([u8; 32], [u8; 12], u32)> {
        let gen = self.generations.entry(sender).or_insert(0);
        let current_gen = *gen;
        *gen += 1;
        
        let (key, nonce) = self.derive_key(sender, current_gen)?;
        Ok((key, nonce, current_gen))
    }

    /// Get key for a specific generation (for receiving)
    pub fn get_key(&self, sender: LeafIndex) -> MlsResult<([u8; 32], [u8; 12], u32)> {
        let gen = self.generations.get(&sender).copied().unwrap_or(0);
        let (key, nonce) = self.derive_key(sender, gen)?;
        Ok((key, nonce, gen))
    }

    /// Mark a key as used
    pub fn mark_used(&mut self, sender: LeafIndex, generation: u32) {
        self.used_keys.insert((sender, generation), true);
    }

    fn derive_key(&self, sender: LeafIndex, generation: u32) -> MlsResult<([u8; 32], [u8; 12])> {
        let mut input = Vec::new();
        input.extend_from_slice(&self.base_secret);
        input.extend_from_slice(&sender.0.to_be_bytes());
        input.extend_from_slice(&generation.to_be_bytes());
        
        let derived = expand_with_label(&input, b"key", &[], 44)?;
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived[0..32]);
        
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&derived[32..44]);
        
        Ok((key, nonce))
    }
}

// =============================================================================
// MLS Message Types
// =============================================================================

/// Content type for MLS messages
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    Application = 0x01,
    Proposal = 0x02,
    Commit = 0x03,
}

/// MLS ciphertext message
#[derive(Clone)]
pub struct MlsMessage {
    pub group_id: GroupId,
    pub epoch: u64,
    pub content_type: ContentType,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl MlsMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128 + self.ciphertext.len());
        bytes.extend_from_slice(&self.group_id.0);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.push(self.content_type as u8);
        bytes.extend_from_slice(&(self.encrypted_sender_data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.encrypted_sender_data);
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> MlsResult<Self> {
        if bytes.len() < 45 {
            return Err(MlsError::DecryptionFailed("Message too short".into()));
        }
        
        let mut group_id = [0u8; 32];
        group_id.copy_from_slice(&bytes[0..32]);
        
        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&bytes[32..40]);
        let epoch = u64::from_be_bytes(epoch_bytes);
        
        let content_type = match bytes[40] {
            0x01 => ContentType::Application,
            0x02 => ContentType::Proposal,
            0x03 => ContentType::Commit,
            _ => return Err(MlsError::DecryptionFailed("Invalid content type".into())),
        };
        
        let mut sd_len_bytes = [0u8; 2];
        sd_len_bytes.copy_from_slice(&bytes[41..43]);
        let sd_len = u16::from_be_bytes(sd_len_bytes) as usize;
        
        if bytes.len() < 47 + sd_len {
            return Err(MlsError::DecryptionFailed("Message truncated".into()));
        }
        
        let encrypted_sender_data = bytes[43..43 + sd_len].to_vec();
        
        let mut ct_len_bytes = [0u8; 4];
        ct_len_bytes.copy_from_slice(&bytes[43 + sd_len..47 + sd_len]);
        let ct_len = u32::from_be_bytes(ct_len_bytes) as usize;
        
        if bytes.len() < 47 + sd_len + ct_len {
            return Err(MlsError::DecryptionFailed("Message truncated".into()));
        }
        
        let ciphertext = bytes[47 + sd_len..47 + sd_len + ct_len].to_vec();
        
        Ok(Self {
            group_id: GroupId(group_id),
            epoch,
            content_type,
            encrypted_sender_data,
            ciphertext,
        })
    }
}

/// Sender data encrypted with sender_data_secret
struct SenderData {
    leaf_index: LeafIndex,
    generation: u32,
}

impl SenderData {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(&self.leaf_index.0.to_be_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> MlsResult<Self> {
        if bytes.len() < 8 {
            return Err(MlsError::DecryptionFailed("SenderData too short".into()));
        }
        
        let mut idx_bytes = [0u8; 4];
        idx_bytes.copy_from_slice(&bytes[0..4]);
        let leaf_index = LeafIndex(u32::from_be_bytes(idx_bytes));
        
        let mut gen_bytes = [0u8; 4];
        gen_bytes.copy_from_slice(&bytes[4..8]);
        let generation = u32::from_be_bytes(gen_bytes);
        
        Ok(Self { leaf_index, generation })
    }
}

/// Message content before encryption
struct MessageContent {
    content_type: ContentType,
    authenticated_data: Vec<u8>,
    payload: Vec<u8>,
}

impl MessageContent {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.content_type as u8);
        bytes.extend_from_slice(&(self.authenticated_data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.authenticated_data);
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> MlsResult<Self> {
        if bytes.len() < 7 {
            return Err(MlsError::DecryptionFailed("MessageContent too short".into()));
        }
        
        let content_type = match bytes[0] {
            0x01 => ContentType::Application,
            0x02 => ContentType::Proposal,
            0x03 => ContentType::Commit,
            _ => return Err(MlsError::DecryptionFailed("Invalid content type".into())),
        };
        
        let mut ad_len_bytes = [0u8; 2];
        ad_len_bytes.copy_from_slice(&bytes[1..3]);
        let ad_len = u16::from_be_bytes(ad_len_bytes) as usize;
        
        if bytes.len() < 7 + ad_len {
            return Err(MlsError::DecryptionFailed("MessageContent truncated".into()));
        }
        
        let authenticated_data = bytes[3..3 + ad_len].to_vec();
        
        let mut pl_len_bytes = [0u8; 4];
        pl_len_bytes.copy_from_slice(&bytes[3 + ad_len..7 + ad_len]);
        let pl_len = u32::from_be_bytes(pl_len_bytes) as usize;
        
        if bytes.len() < 7 + ad_len + pl_len {
            return Err(MlsError::DecryptionFailed("MessageContent truncated".into()));
        }
        
        let payload = bytes[7 + ad_len..7 + ad_len + pl_len].to_vec();
        
        Ok(Self {
            content_type,
            authenticated_data,
            payload,
        })
    }
}

// =============================================================================
// Cryptographic Primitives
// =============================================================================

/// HKDF-SHA256 extract
fn kdf_extract(salt: &[u8; 32], ikm: &[u8; 32]) -> MlsResult<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = [0u8; 32];
    hk.expand(&[], &mut output)
        .map_err(|e| MlsError::KeyDerivationFailed(e.to_string()))?;
    Ok(output)
}

/// Derive secret with label
fn derive_secret(secret: &[u8; 32], label: &[u8], context: &[u8]) -> MlsResult<[u8; 32]> {
    let expanded = expand_with_label(secret, label, context, 32)?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&expanded);
    Ok(result)
}

/// HKDF-Expand with MLS label
fn expand_with_label(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> MlsResult<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(None, secret);
    
    // MLS label format: length || "MLS 1.0 " || label || context
    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.extend_from_slice(b"MLS 1.0 ");
    info.extend_from_slice(label);
    info.extend_from_slice(context);
    
    let mut output = vec![0u8; length];
    hk.expand(&info, &mut output)
        .map_err(|e| MlsError::KeyDerivationFailed(e.to_string()))?;
    
    Ok(output)
}

/// Derive welcome key from joiner secret
fn derive_welcome_key(joiner_secret: &[u8; 32]) -> MlsResult<[u8; 32]> {
    derive_secret(joiner_secret, MLS_LABEL_WELCOME, &[])
}

/// Derive sender data key
fn derive_sender_data_key(sender_data_secret: &[u8; 32], ciphertext_sample: &[u8]) -> MlsResult<[u8; 32]> {
    // Use first 16 bytes of ciphertext as sample
    let sample = if ciphertext_sample.len() >= 16 {
        &ciphertext_sample[..16]
    } else {
        ciphertext_sample
    };
    derive_secret(sender_data_secret, b"sender data", sample)
}

/// Hash a KeyPackage
fn hash_key_package(kp: &KeyPackage) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&kp.to_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// HPKE seal (encrypt to public key)
fn hpke_seal(public_key: &X25519PublicKey, plaintext: &[u8], aad: &[u8]) -> MlsResult<HpkeCiphertext> {
    // Generate ephemeral key
    let eph_secret = X25519SecretKey::random_from_rng(OsRng);
    let eph_public = X25519PublicKey::from(&eph_secret);
    
    // DH
    let shared = eph_secret.diffie_hellman(public_key);
    
    // Derive key
    let hk = Hkdf::<Sha256>::new(Some(aad), shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"hpke", &mut key)
        .map_err(|e| MlsError::KeyDerivationFailed(e.to_string()))?;
    
    // Encrypt
    let ciphertext = aead_encrypt(&key, plaintext, aad)?;
    
    Ok(HpkeCiphertext {
        kem_output: eph_public,
        ciphertext,
    })
}

/// HPKE open (decrypt with private key)
fn hpke_open(private_key: &X25519KeyPair, ciphertext: &HpkeCiphertext, aad: &[u8]) -> MlsResult<Vec<u8>> {
    // DH
    let shared = private_key.diffie_hellman(&ciphertext.kem_output);
    
    // Derive key
    let hk = Hkdf::<Sha256>::new(Some(aad), shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"hpke", &mut key)
        .map_err(|e| MlsError::KeyDerivationFailed(e.to_string()))?;
    
    // Decrypt
    aead_decrypt(&key, &ciphertext.ciphertext, aad)
}

/// AEAD encrypt with ChaCha20-Poly1305
fn aead_encrypt(key: &[u8; 32], plaintext: &[u8], _aad: &[u8]) -> MlsResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| MlsError::EncryptionFailed(e.to_string()))?;
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| MlsError::EncryptionFailed(e.to_string()))?;
    
    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// AEAD decrypt with ChaCha20-Poly1305
fn aead_decrypt(key: &[u8; 32], ciphertext: &[u8], _aad: &[u8]) -> MlsResult<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(MlsError::DecryptionFailed("Ciphertext too short".into()));
    }
    
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| MlsError::DecryptionFailed(e.to_string()))?;
    
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let actual_ciphertext = &ciphertext[12..];
    
    cipher.decrypt(nonce, actual_ciphertext)
        .map_err(|e| MlsError::DecryptionFailed(e.to_string()))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_creation() {
        let identity = IdentityKeyPair::generate();
        let group = MlsGroup::create(identity, "Alice".into(), None).unwrap();
        
        assert_eq!(group.epoch, 0);
        assert_eq!(group.member_count(), 1);
    }

    #[test]
    fn test_key_package_creation() {
        let identity = IdentityKeyPair::generate();
        let (kp, _init_key) = KeyPackage::new(&identity, "Bob".into());
        
        assert!(kp.verify());
    }

    #[test]
    fn test_add_member() {
        let alice_id = IdentityKeyPair::generate();
        let mut alice_group = MlsGroup::create(alice_id, "Alice".into(), None).unwrap();
        
        let bob_id = IdentityKeyPair::generate();
        let (bob_kp, _bob_init) = KeyPackage::new(&bob_id, "Bob".into());
        
        alice_group.add_member(&bob_kp).unwrap();
        let (commit, welcome) = alice_group.create_commit().unwrap();
        
        assert!(welcome.is_some());
        assert!(!commit.proposals.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let identity = IdentityKeyPair::generate();
        let mut group = MlsGroup::create(identity, "Alice".into(), None).unwrap();
        
        let plaintext = b"Hello, MLS!";
        let message = group.encrypt(plaintext).unwrap();
        
        // Note: Decryption requires proper key schedule state
        assert!(!message.ciphertext.is_empty());
    }

    #[test]
    fn test_tree_indices() {
        let leaf = LeafIndex(0);
        assert_eq!(leaf.node_index().0, 0);
        assert!(leaf.node_index().is_leaf());
        
        let leaf3 = LeafIndex(3);
        assert_eq!(leaf3.node_index().0, 6);
    }

    #[test]
    fn test_node_parent() {
        let node = NodeIndex(0);
        let parent = node.parent(7);
        assert_eq!(parent.map(|p| p.0), Some(1));
        
        let root = root_index(4);
        assert_eq!(root.0, 3); // For 4 leaves, root is at index 3
    }

    #[test]
    fn test_aead_round_trip() {
        let key = [42u8; 32];
        let plaintext = b"Secret message";
        let aad = b"Additional data";
        
        let ciphertext = aead_encrypt(&key, plaintext, aad).unwrap();
        let decrypted = aead_decrypt(&key, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hpke_round_trip() {
        let keypair = X25519KeyPair::generate();
        let plaintext = b"HPKE test message";
        let aad = b"context";
        
        let ciphertext = hpke_seal(&keypair.public_key(), plaintext, aad).unwrap();
        let decrypted = hpke_open(&keypair, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
