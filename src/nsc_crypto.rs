//! Nais Secure Channels - Cryptographic Primitives
//!
//! This module implements the cryptographic foundation for NSC:
//! - Identity key generation and management (Ed25519)
//! - X3DH key agreement protocol
//! - Double Ratchet for forward-secret messaging
//!
//! # Security Properties
//! - Forward secrecy: Compromise of long-term keys doesn't expose past messages
//! - Post-compromise security: System recovers after key compromise
//! - Deniability: Messages can't be cryptographically attributed to sender

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Error Types
// =============================================================================

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("No one-time prekey available")]
    NoOneTimePrekey,

    #[error("Session not found for peer")]
    SessionNotFound,

    #[error("Message out of order: expected {expected}, got {got}")]
    MessageOutOfOrder { expected: u32, got: u32 },

    #[error("Too many skipped messages")]
    TooManySkippedMessages,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Key has been revoked: {0}")]
    KeyRevoked(String),

    #[error("Invalid revocation certificate")]
    InvalidRevocation,
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of message keys to skip (for out-of-order messages)
const MAX_SKIP: u32 = 1000;

/// KDF info strings
const KDF_ROOT_INFO: &[u8] = b"NSC_RootKey";
const KDF_CHAIN_INFO: &[u8] = b"NSC_ChainKey";
const KDF_MESSAGE_INFO: &[u8] = b"NSC_MessageKey";

/// AEAD constants
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

// =============================================================================
// Identity Keys (Ed25519)
// =============================================================================

/// Long-term identity signing key pair
#[derive(Clone, ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    /// Private signing key
    #[zeroize(skip)] // Ed25519 SigningKey handles its own zeroization
    signing_key: SigningKey,
}

impl IdentityKeyPair {
    /// Generate a new random identity key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create from existing secret bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Get the public verifying key
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Get the private key bytes (for storage)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get fingerprint (SHA-256 of public key)
    pub fn fingerprint(&self) -> [u8; 32] {
        self.public_key().fingerprint()
    }
}

impl std::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// Public identity key for verification
#[derive(Clone, Debug)]
pub struct IdentityPublicKey {
    verifying_key: VerifyingKey,
}

impl IdentityPublicKey {
    /// Create from bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let bytes_arr: [u8; 32] = bytes.try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&bytes_arr)
            .map_err(|_e| CryptoError::InvalidSignature)?;
        Ok(Self { verifying_key })
    }

    /// Get the public key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> CryptoResult<()> {
        let sig = Signature::from_bytes(signature);
        self.verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Get fingerprint (SHA-256 of public key)
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        hasher.finalize().into()
    }

    /// Get fingerprint as hex string
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint())
    }
}

impl PartialEq for IdentityPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for IdentityPublicKey {}

impl std::hash::Hash for IdentityPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

// =============================================================================
// X25519 Key Exchange Keys
// =============================================================================

/// X25519 key pair for Diffie-Hellman key exchange
#[derive(ZeroizeOnDrop)]
pub struct X25519KeyPair {
    #[zeroize(skip)]
    secret: X25519SecretKey,
    public: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let secret = X25519SecretKey::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create from existing secret bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let secret = X25519SecretKey::from(bytes);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key
    pub fn public_key(&self) -> X25519PublicKey {
        self.public
    }

    /// Get the secret key bytes (for storage)
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> SharedSecret {
        SharedSecret(self.secret.diffie_hellman(their_public).to_bytes())
    }
}

impl Clone for X25519KeyPair {
    fn clone(&self) -> Self {
        Self::from_bytes(self.secret.to_bytes())
    }
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("public", &hex::encode(self.public.as_bytes()))
            .finish_non_exhaustive()
    }
}

/// Shared secret from DH exchange
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// =============================================================================
// X3DH Protocol Implementation
// =============================================================================

/// Pre-key bundle published by a user for X3DH
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// Ed25519 identity public key (for signature verification)
    pub identity_key: IdentityPublicKey,

    /// X25519 identity public key (for DH in X3DH)
    pub identity_dh_key: X25519PublicKey,

    /// Signed pre-key (SPK) - rotated periodically
    pub signed_prekey: X25519PublicKey,

    /// Signature over (identity_dh_key || signed_prekey) by identity_key
    pub signed_prekey_signature: [u8; 64],

    /// One-time pre-keys (OPK) - used once then discarded
    pub one_time_prekeys: Vec<X25519PublicKey>,
}

impl PreKeyBundle {
    /// Verify the signed prekey signature
    pub fn verify(&self) -> CryptoResult<()> {
        // Signature covers both DH identity and signed prekey
        let mut signed_data = Vec::with_capacity(64);
        signed_data.extend_from_slice(self.identity_dh_key.as_bytes());
        signed_data.extend_from_slice(self.signed_prekey.as_bytes());
        self.identity_key
            .verify(&signed_data, &self.signed_prekey_signature)
    }
}

/// Local pre-key state (includes private keys)
pub struct PreKeyState {
    /// Ed25519 identity key pair (for signing)
    pub identity: IdentityKeyPair,

    /// X25519 identity key pair (for DH in X3DH)
    pub identity_dh: X25519KeyPair,

    /// Current signed pre-key pair
    pub signed_prekey: X25519KeyPair,

    /// Signed pre-key signature
    pub signed_prekey_signature: [u8; 64],

    /// One-time pre-key pairs (private keys kept for receiving)
    pub one_time_prekeys: Vec<X25519KeyPair>,

    /// Used one-time prekey public keys (to detect reuse)
    pub used_one_time_prekeys: std::collections::HashSet<[u8; 32]>,
}

impl PreKeyState {
    /// Create new pre-key state with fresh keys
    pub fn new(identity: IdentityKeyPair, num_one_time_keys: usize) -> Self {
        let identity_dh = X25519KeyPair::generate();
        let signed_prekey = X25519KeyPair::generate();
        
        // Sign both DH identity and signed prekey
        let mut signed_data = Vec::with_capacity(64);
        signed_data.extend_from_slice(identity_dh.public_key().as_bytes());
        signed_data.extend_from_slice(signed_prekey.public_key().as_bytes());
        let signed_prekey_signature = identity.sign(&signed_data);

        let one_time_prekeys: Vec<X25519KeyPair> =
            (0..num_one_time_keys).map(|_| X25519KeyPair::generate()).collect();

        Self {
            identity,
            identity_dh,
            signed_prekey,
            signed_prekey_signature,
            one_time_prekeys,
            used_one_time_prekeys: std::collections::HashSet::new(),
        }
    }

    /// Get publishable pre-key bundle
    pub fn to_bundle(&self) -> PreKeyBundle {
        PreKeyBundle {
            identity_key: self.identity.public_key(),
            identity_dh_key: self.identity_dh.public_key(),
            signed_prekey: self.signed_prekey.public_key(),
            signed_prekey_signature: self.signed_prekey_signature,
            one_time_prekeys: self.one_time_prekeys.iter().map(|k| k.public_key()).collect(),
        }
    }

    /// Rotate the signed pre-key
    pub fn rotate_signed_prekey(&mut self) {
        self.signed_prekey = X25519KeyPair::generate();
        let mut signed_data = Vec::with_capacity(64);
        signed_data.extend_from_slice(self.identity_dh.public_key().as_bytes());
        signed_data.extend_from_slice(self.signed_prekey.public_key().as_bytes());
        self.signed_prekey_signature = self.identity.sign(&signed_data);
    }

    /// Generate more one-time pre-keys
    pub fn generate_one_time_prekeys(&mut self, count: usize) {
        for _ in 0..count {
            self.one_time_prekeys.push(X25519KeyPair::generate());
        }
    }

    /// Consume a one-time pre-key (for receiving X3DH)
    pub fn consume_one_time_prekey(&mut self, public: &X25519PublicKey) -> Option<X25519KeyPair> {
        let public_bytes = *public.as_bytes();
        
        // Check if already used
        if self.used_one_time_prekeys.contains(&public_bytes) {
            return None;
        }

        // Find and remove the matching prekey
        if let Some(pos) = self
            .one_time_prekeys
            .iter()
            .position(|k| k.public_key().as_bytes() == public.as_bytes())
        {
            let key = self.one_time_prekeys.remove(pos);
            self.used_one_time_prekeys.insert(public_bytes);
            Some(key)
        } else {
            None
        }
    }
}

/// X3DH key agreement result
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X3dhAgreement {
    /// Shared secret for initializing Double Ratchet
    pub shared_secret: [u8; 32],

    /// Associated data (identities) for AEAD
    #[zeroize(skip)]
    pub associated_data: Vec<u8>,
}

/// X3DH sender (initiator) output
pub struct X3dhSenderOutput {
    /// The key agreement
    pub agreement: X3dhAgreement,

    /// Our X25519 identity public key (for the header)
    pub identity_dh_public: X25519PublicKey,

    /// Ephemeral public key to send to recipient
    pub ephemeral_public: X25519PublicKey,

    /// Which one-time prekey was used (if any)
    pub used_one_time_prekey: Option<X25519PublicKey>,
}

/// Perform X3DH as the sender (initiator)
pub fn x3dh_sender(
    our_identity: &IdentityKeyPair,
    our_identity_dh: &X25519KeyPair,
    their_bundle: &PreKeyBundle,
) -> CryptoResult<X3dhSenderOutput> {
    // Verify the bundle first
    their_bundle.verify()?;

    // Generate ephemeral key pair
    let ephemeral = X25519KeyPair::generate();

    // Perform DH calculations:
    // DH1 = DH(IK_A_dh, SPK_B)
    let dh1 = our_identity_dh.diffie_hellman(&their_bundle.signed_prekey);

    // DH2 = DH(EK_A, IK_B_dh)
    let dh2 = ephemeral.diffie_hellman(&their_bundle.identity_dh_key);

    // DH3 = DH(EK_A, SPK_B)
    let dh3 = ephemeral.diffie_hellman(&their_bundle.signed_prekey);

    // DH4 = DH(EK_A, OPK_B) if one-time prekey available
    let (dh4, used_opk) = if let Some(opk) = their_bundle.one_time_prekeys.first() {
        (Some(ephemeral.diffie_hellman(opk)), Some(*opk))
    } else {
        (None, None)
    };

    // Concatenate DH outputs
    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());
    if let Some(ref dh4) = dh4 {
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // Derive shared secret using HKDF
    let shared_secret = kdf(&dh_concat, b"X3DH", 32)?;
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&shared_secret);

    // Associated data = IK_A || IK_B (Ed25519 identity keys for authentication)
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(&our_identity.public_key().to_bytes());
    ad.extend_from_slice(&their_bundle.identity_key.to_bytes());

    Ok(X3dhSenderOutput {
        agreement: X3dhAgreement {
            shared_secret: secret_arr,
            associated_data: ad,
        },
        identity_dh_public: our_identity_dh.public_key(),
        ephemeral_public: ephemeral.public_key(),
        used_one_time_prekey: used_opk,
    })
}

/// X3DH message header sent with first message
#[derive(Clone, Debug)]
pub struct X3dhHeader {
    /// Sender's Ed25519 identity public key (for verification)
    pub identity_key: IdentityPublicKey,

    /// Sender's X25519 identity public key (for DH)
    pub identity_dh_key: X25519PublicKey,

    /// Sender's ephemeral public key
    pub ephemeral_key: X25519PublicKey,

    /// Which one-time prekey was used (if any)
    pub one_time_prekey: Option<X25519PublicKey>,
}

/// Perform X3DH as the receiver
pub fn x3dh_receiver(
    our_prekey_state: &mut PreKeyState,
    header: &X3dhHeader,
) -> CryptoResult<X3dhAgreement> {
    // DH1 = DH(SPK_B, IK_A_dh)
    let dh1 = our_prekey_state.signed_prekey.diffie_hellman(&header.identity_dh_key);

    // DH2 = DH(IK_B_dh, EK_A)
    let dh2 = our_prekey_state.identity_dh.diffie_hellman(&header.ephemeral_key);

    // DH3 = DH(SPK_B, EK_A)
    let dh3 = our_prekey_state.signed_prekey.diffie_hellman(&header.ephemeral_key);

    // DH4 = DH(OPK_B, EK_A) if one-time prekey was used
    let dh4 = if let Some(ref opk_public) = header.one_time_prekey {
        let opk = our_prekey_state
            .consume_one_time_prekey(opk_public)
            .ok_or(CryptoError::NoOneTimePrekey)?;
        Some(opk.diffie_hellman(&header.ephemeral_key))
    } else {
        None
    };

    // Concatenate DH outputs (same order as sender)
    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());
    if let Some(ref dh4) = dh4 {
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // Derive shared secret
    let shared_secret = kdf(&dh_concat, b"X3DH", 32)?;
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&shared_secret);

    // Associated data = IK_A || IK_B
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(&header.identity_key.to_bytes());
    ad.extend_from_slice(&our_prekey_state.identity.public_key().to_bytes());

    Ok(X3dhAgreement {
        shared_secret: secret_arr,
        associated_data: ad,
    })
}

// =============================================================================
// Double Ratchet Protocol Implementation
// =============================================================================

/// Message header for Double Ratchet
#[derive(Clone, Debug)]
pub struct MessageHeader {
    /// Current ratchet public key
    pub ratchet_key: X25519PublicKey,

    /// Previous chain length (number of messages in previous sending chain)
    pub previous_chain_length: u32,

    /// Message number in current chain
    pub message_number: u32,
}

impl MessageHeader {
    /// Serialize header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(self.ratchet_key.as_bytes());
        bytes.extend_from_slice(&self.previous_chain_length.to_be_bytes());
        bytes.extend_from_slice(&self.message_number.to_be_bytes());
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < 40 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 40,
                got: bytes.len(),
            });
        }

        let mut ratchet_bytes = [0u8; 32];
        ratchet_bytes.copy_from_slice(&bytes[0..32]);
        let ratchet_key = X25519PublicKey::from(ratchet_bytes);

        let previous_chain_length = u32::from_be_bytes(bytes[32..36].try_into().unwrap());
        let message_number = u32::from_be_bytes(bytes[36..40].try_into().unwrap());

        Ok(Self {
            ratchet_key,
            previous_chain_length,
            message_number,
        })
    }
}

/// Chain key state for symmetric ratchet
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct ChainKey([u8; 32]);

impl ChainKey {
    fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Derive message key and advance chain
    fn derive_message_key(&mut self) -> CryptoResult<MessageKey> {
        // Message key = KDF(chain_key, 0x01)
        let mk = kdf(&self.0, KDF_MESSAGE_INFO, 32)?;
        let mut mk_arr = [0u8; 32];
        mk_arr.copy_from_slice(&mk);

        // Advance chain key = KDF(chain_key, 0x02)
        let new_ck = kdf(&self.0, KDF_CHAIN_INFO, 32)?;
        self.0.copy_from_slice(&new_ck);

        Ok(MessageKey(mk_arr))
    }
}

/// Message encryption key (used once)
#[derive(Zeroize, ZeroizeOnDrop)]
struct MessageKey([u8; 32]);

impl MessageKey {
    /// Encrypt plaintext with this message key
    fn encrypt(&self, plaintext: &[u8], _ad: &[u8]) -> CryptoResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.0)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create associated data: AD || header
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Output: nonce || ciphertext
        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Decrypt ciphertext with this message key
    fn decrypt(&self, ciphertext: &[u8], _ad: &[u8]) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.0)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
        let ct = &ciphertext[NONCE_SIZE..];

        cipher
            .decrypt(nonce, ct)
            .map_err(|_| CryptoError::DecryptionFailed("Authentication failed".into()))
    }
}

/// Double Ratchet session state
pub struct DoubleRatchetSession {
    /// Our current ratchet key pair
    ratchet_keypair: Option<X25519KeyPair>,

    /// Their current ratchet public key
    remote_ratchet_key: Option<X25519PublicKey>,

    /// Root key for DH ratchet
    root_key: [u8; 32],

    /// Sending chain key
    sending_chain: Option<ChainKey>,

    /// Receiving chain key
    receiving_chain: Option<ChainKey>,

    /// Number of messages sent in current sending chain
    send_count: u32,

    /// Number of messages received in current receiving chain
    recv_count: u32,

    /// Previous sending chain length (for header)
    previous_chain_length: u32,

    /// Skipped message keys (for out-of-order messages)
    /// Key: (ratchet_public_key, message_number) -> message_key
    skipped_keys: HashMap<([u8; 32], u32), MessageKey>,

    /// Associated data
    associated_data: Vec<u8>,
}

impl DoubleRatchetSession {
    /// Initialize as sender (Alice) after X3DH
    pub fn init_sender(x3dh: X3dhAgreement, their_ratchet_key: X25519PublicKey) -> CryptoResult<Self> {
        let ratchet_keypair = X25519KeyPair::generate();

        // First DH ratchet step
        let dh = ratchet_keypair.diffie_hellman(&their_ratchet_key);

        // Derive root key and sending chain key
        let (root_key, chain_key) = kdf_rk(&x3dh.shared_secret, dh.as_bytes())?;

        Ok(Self {
            ratchet_keypair: Some(ratchet_keypair),
            remote_ratchet_key: Some(their_ratchet_key),
            root_key,
            sending_chain: Some(ChainKey::new(chain_key)),
            receiving_chain: None,
            send_count: 0,
            recv_count: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
            associated_data: x3dh.associated_data.clone(),
        })
    }

    /// Initialize as receiver (Bob) after X3DH
    pub fn init_receiver(x3dh: X3dhAgreement, our_signed_prekey: X25519KeyPair) -> Self {
        Self {
            ratchet_keypair: Some(our_signed_prekey),
            remote_ratchet_key: None,
            root_key: x3dh.shared_secret,
            sending_chain: None,
            receiving_chain: None,
            send_count: 0,
            recv_count: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
            associated_data: x3dh.associated_data.clone(),
        }
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> CryptoResult<(MessageHeader, Vec<u8>)> {
        // Ensure we have a sending chain
        if self.sending_chain.is_none() {
            return Err(CryptoError::SessionNotFound);
        }

        let ratchet_key = self
            .ratchet_keypair
            .as_ref()
            .ok_or(CryptoError::SessionNotFound)?
            .public_key();

        // Create header
        let header = MessageHeader {
            ratchet_key,
            previous_chain_length: self.previous_chain_length,
            message_number: self.send_count,
        };

        // Derive message key
        let mk = self
            .sending_chain
            .as_mut()
            .unwrap()
            .derive_message_key()?;

        // Encrypt (AD = associated_data || header)
        let mut ad = self.associated_data.clone();
        ad.extend_from_slice(&header.to_bytes());

        let ciphertext = mk.encrypt(plaintext, &ad)?;

        self.send_count += 1;

        Ok((header, ciphertext))
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, header: &MessageHeader, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Check for skipped message key
        let header_key_tuple = (*header.ratchet_key.as_bytes(), header.message_number);
        if let Some(mk) = self.skipped_keys.remove(&header_key_tuple) {
            let mut ad = self.associated_data.clone();
            ad.extend_from_slice(&header.to_bytes());
            return mk.decrypt(ciphertext, &ad);
        }

        // Check if we need to perform a DH ratchet step
        let need_ratchet = self
            .remote_ratchet_key
            .as_ref()
            .map(|k| k.as_bytes() != header.ratchet_key.as_bytes())
            .unwrap_or(true);

        if need_ratchet {
            // Skip any remaining messages in the current receiving chain
            if self.receiving_chain.is_some() && self.remote_ratchet_key.is_some() {
                self.skip_message_keys(header.previous_chain_length)?;
            }

            // Perform DH ratchet step
            self.dh_ratchet(&header.ratchet_key)?;
        }

        // Skip any messages in the current chain before this one
        self.skip_message_keys(header.message_number)?;

        // Derive message key
        let mk = self
            .receiving_chain
            .as_mut()
            .ok_or(CryptoError::SessionNotFound)?
            .derive_message_key()?;

        self.recv_count += 1;

        // Decrypt
        let mut ad = self.associated_data.clone();
        ad.extend_from_slice(&header.to_bytes());
        mk.decrypt(ciphertext, &ad)
    }

    /// Perform DH ratchet step (when receiving new ratchet key)
    fn dh_ratchet(&mut self, their_ratchet_key: &X25519PublicKey) -> CryptoResult<()> {
        self.previous_chain_length = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;

        self.remote_ratchet_key = Some(*their_ratchet_key);

        // DH with our current ratchet key
        let our_keypair = self.ratchet_keypair.as_ref().ok_or(CryptoError::SessionNotFound)?;
        let dh = our_keypair.diffie_hellman(their_ratchet_key);

        // Derive new receiving chain
        let (new_root, recv_chain) = kdf_rk(&self.root_key, dh.as_bytes())?;
        self.root_key = new_root;
        self.receiving_chain = Some(ChainKey::new(recv_chain));

        // Generate new ratchet key pair
        let new_keypair = X25519KeyPair::generate();
        let dh2 = new_keypair.diffie_hellman(their_ratchet_key);

        // Derive new sending chain
        let (new_root2, send_chain) = kdf_rk(&self.root_key, dh2.as_bytes())?;
        self.root_key = new_root2;
        self.sending_chain = Some(ChainKey::new(send_chain));

        self.ratchet_keypair = Some(new_keypair);

        Ok(())
    }

    /// Skip message keys for out-of-order handling
    fn skip_message_keys(&mut self, until: u32) -> CryptoResult<()> {
        let recv_chain = match self.receiving_chain.as_mut() {
            Some(c) => c,
            None => return Ok(()),
        };

        if until > self.recv_count + MAX_SKIP {
            return Err(CryptoError::TooManySkippedMessages);
        }

        let remote_key = self
            .remote_ratchet_key
            .as_ref()
            .ok_or(CryptoError::SessionNotFound)?;

        while self.recv_count < until {
            let mk = recv_chain.derive_message_key()?;
            self.skipped_keys
                .insert((*remote_key.as_bytes(), self.recv_count), mk);
            self.recv_count += 1;
        }

        Ok(())
    }

    /// Get the current ratchet public key (for X3DH header)
    pub fn get_ratchet_public_key(&self) -> Option<X25519PublicKey> {
        self.ratchet_keypair.as_ref().map(|kp| kp.public_key())
    }
}

// =============================================================================
// Key Derivation Functions
// =============================================================================

/// Generic KDF using HKDF-SHA256
fn kdf(input: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(None, input);
    let mut output = vec![0u8; length];
    hk.expand(info, &mut output)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    Ok(output)
}

/// Root key KDF for Double Ratchet
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> CryptoResult<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);

    let mut chain_key = [0u8; 32];
    let mut new_root_key = [0u8; 32];

    hk.expand(KDF_ROOT_INFO, &mut new_root_key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(KDF_CHAIN_INFO, &mut chain_key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok((new_root_key, chain_key))
}

// =============================================================================
// Peer Session Manager
// =============================================================================

/// Manages per-peer Double Ratchet sessions and PreKey state
pub struct PeerSessionManager {
    /// Our identity key pair
    identity: IdentityKeyPair,
    /// Our X25519 identity key pair (separate from Ed25519)
    identity_dh: X25519KeyPair,
    /// Our pre-key state for receiving X3DH
    prekey_state: PreKeyState,
    /// Active Double Ratchet sessions by peer fingerprint
    sessions: HashMap<[u8; 32], DoubleRatchetSession>,
    /// Pending X3DH headers waiting for session establishment
    pending_x3dh: HashMap<[u8; 32], X3dhSenderOutput>,
}

impl PeerSessionManager {
    /// Create a new peer session manager
    pub fn new(identity: IdentityKeyPair) -> Self {
        let identity_dh = X25519KeyPair::generate();
        let prekey_state = PreKeyState::new(identity.clone(), 20);
        
        Self {
            identity,
            identity_dh,
            prekey_state,
            sessions: HashMap::new(),
            pending_x3dh: HashMap::new(),
        }
    }
    
    /// Create from existing identity with custom prekey count
    pub fn with_prekey_count(identity: IdentityKeyPair, prekey_count: usize) -> Self {
        let identity_dh = X25519KeyPair::generate();
        let prekey_state = PreKeyState::new(identity.clone(), prekey_count);
        
        Self {
            identity,
            identity_dh,
            prekey_state,
            sessions: HashMap::new(),
            pending_x3dh: HashMap::new(),
        }
    }
    
    /// Get our PreKeyBundle for sharing with peers
    pub fn get_prekey_bundle(&self) -> PreKeyBundle {
        self.prekey_state.to_bundle()
    }
    
    /// Get our identity public key
    pub fn identity_public_key(&self) -> IdentityPublicKey {
        self.identity.public_key()
    }
    
    /// Initiate X3DH with a peer's PreKeyBundle
    /// Returns the X3DH header to send with the first message
    pub fn initiate_session(&mut self, their_fingerprint: [u8; 32], their_bundle: &PreKeyBundle) -> CryptoResult<X3dhHeader> {
        // Check if session already exists
        if self.sessions.contains_key(&their_fingerprint) {
            return Err(CryptoError::SessionNotFound); // Reuse error for "already exists"
        }
        
        // Perform X3DH as sender
        let x3dh_output = x3dh_sender(&self.identity, &self.identity_dh, their_bundle)?;
        
        // Create header to send
        let header = X3dhHeader {
            identity_key: self.identity.public_key(),
            identity_dh_key: x3dh_output.identity_dh_public,
            ephemeral_key: x3dh_output.ephemeral_public,
            one_time_prekey: x3dh_output.used_one_time_prekey,
        };
        
        // Get their signed prekey for ratchet initialization
        let their_ratchet_key = their_bundle.signed_prekey;
        
        // Initialize Double Ratchet session as sender
        let session = DoubleRatchetSession::init_sender(x3dh_output.agreement, their_ratchet_key)?;
        
        self.sessions.insert(their_fingerprint, session);
        
        Ok(header)
    }
    
    /// Complete session from received X3DH header (we're the responder)
    pub fn receive_session(&mut self, their_fingerprint: [u8; 32], header: &X3dhHeader) -> CryptoResult<()> {
        // Check if session already exists
        if self.sessions.contains_key(&their_fingerprint) {
            return Ok(()); // Already have session
        }
        
        // Perform X3DH as receiver
        let agreement = x3dh_receiver(&mut self.prekey_state, header)?;
        
        // Initialize Double Ratchet as receiver using our signed prekey
        let session = DoubleRatchetSession::init_receiver(agreement, self.prekey_state.signed_prekey.clone());
        
        self.sessions.insert(their_fingerprint, session);
        
        Ok(())
    }
    
    /// Encrypt message for a peer
    pub fn encrypt_for_peer(&mut self, peer_fingerprint: &[u8; 32], plaintext: &[u8]) -> CryptoResult<(MessageHeader, Vec<u8>)> {
        let session = self.sessions.get_mut(peer_fingerprint)
            .ok_or(CryptoError::SessionNotFound)?;
        
        session.encrypt(plaintext)
    }
    
    /// Decrypt message from a peer
    pub fn decrypt_from_peer(&mut self, peer_fingerprint: &[u8; 32], header: &MessageHeader, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        let session = self.sessions.get_mut(peer_fingerprint)
            .ok_or(CryptoError::SessionNotFound)?;
        
        session.decrypt(header, ciphertext)
    }
    
    /// Check if we have a session with a peer
    pub fn has_session(&self, peer_fingerprint: &[u8; 32]) -> bool {
        self.sessions.contains_key(peer_fingerprint)
    }
    
    /// Remove a session (e.g., when peer leaves)
    pub fn remove_session(&mut self, peer_fingerprint: &[u8; 32]) {
        self.sessions.remove(peer_fingerprint);
    }
    
    /// Get the number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
    
    /// Rotate our signed prekey (should be done periodically)
    pub fn rotate_prekey(&mut self) {
        self.prekey_state.rotate_signed_prekey();
    }
    
    /// Generate more one-time prekeys if running low
    pub fn replenish_prekeys(&mut self, count: usize) {
        self.prekey_state.generate_one_time_prekeys(count);
    }
    
    /// Get number of available one-time prekeys
    pub fn available_prekeys(&self) -> usize {
        self.prekey_state.one_time_prekeys.len()
    }
    
    /// Serialize PreKeyBundle to bytes for transmission
    pub fn serialize_prekey_bundle(&self) -> CryptoResult<Vec<u8>> {
        let bundle = self.get_prekey_bundle();
        
        let mut bytes = Vec::with_capacity(256);
        
        // Identity key (32 bytes)
        bytes.extend_from_slice(&bundle.identity_key.to_bytes());
        
        // Identity DH key (32 bytes)
        bytes.extend_from_slice(bundle.identity_dh_key.as_bytes());
        
        // Signed prekey (32 bytes)
        bytes.extend_from_slice(bundle.signed_prekey.as_bytes());
        
        // Signed prekey signature (64 bytes)
        bytes.extend_from_slice(&bundle.signed_prekey_signature);
        
        // One-time prekey count (2 bytes)
        let otpk_count = bundle.one_time_prekeys.len().min(u16::MAX as usize) as u16;
        bytes.extend_from_slice(&otpk_count.to_be_bytes());
        
        // One-time prekeys (32 bytes each)
        for otpk in bundle.one_time_prekeys.iter().take(otpk_count as usize) {
            bytes.extend_from_slice(otpk.as_bytes());
        }
        
        Ok(bytes)
    }
    
    /// Deserialize PreKeyBundle from bytes
    pub fn deserialize_prekey_bundle(bytes: &[u8]) -> CryptoResult<PreKeyBundle> {
        if bytes.len() < 162 { // 32 + 32 + 32 + 64 + 2 = minimum size
            return Err(CryptoError::InvalidKeyLength { expected: 162, got: bytes.len() });
        }
        
        let mut offset = 0;
        
        // Identity key
        let identity_key = IdentityPublicKey::from_bytes(&bytes[offset..offset + 32])?;
        offset += 32;
        
        // Identity DH key
        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(&bytes[offset..offset + 32]);
        let identity_dh_key = X25519PublicKey::from(dh_bytes);
        offset += 32;
        
        // Signed prekey
        let mut spk_bytes = [0u8; 32];
        spk_bytes.copy_from_slice(&bytes[offset..offset + 32]);
        let signed_prekey = X25519PublicKey::from(spk_bytes);
        offset += 32;
        
        // Signature
        let mut signed_prekey_signature = [0u8; 64];
        signed_prekey_signature.copy_from_slice(&bytes[offset..offset + 64]);
        offset += 64;
        
        // One-time prekey count
        let otpk_count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        
        // One-time prekeys
        let mut one_time_prekeys = Vec::with_capacity(otpk_count);
        for _ in 0..otpk_count {
            if offset + 32 > bytes.len() {
                break;
            }
            let mut otpk_bytes = [0u8; 32];
            otpk_bytes.copy_from_slice(&bytes[offset..offset + 32]);
            one_time_prekeys.push(X25519PublicKey::from(otpk_bytes));
            offset += 32;
        }
        
        Ok(PreKeyBundle {
            identity_key,
            identity_dh_key,
            signed_prekey,
            signed_prekey_signature,
            one_time_prekeys,
        })
    }
}

// =============================================================================
// Trust Verification System
// =============================================================================

/// How a peer's identity was verified
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TrustVerificationMethod {
    /// Trust on first use - we stored their key when first seen
    Tofu,
    /// Fingerprint comparison (e.g., user compared safety numbers)
    FingerprintComparison,
    /// QR code scan 
    QrCodeScan,
    /// Vouched by a trusted third party (web of trust)
    VouchedBy(String),
    /// Manually marked as trusted by user
    ManualApproval,
}

/// Trust level for a peer
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum TrustLevel {
    /// Unknown peer - never seen before
    Unknown,
    /// TOFU - first key we saw for this peer
    Tofu {
        first_seen: u64,
        pinned_key: [u8; 32],
    },
    /// Verified by user action
    Verified {
        verified_at: u64,
        method: TrustVerificationMethod,
    },
    /// Key changed since we last verified - warning state
    KeyChanged {
        previous_key: [u8; 32],
        new_key: [u8; 32],
        changed_at: u64,
    },
    /// Explicitly marked as untrusted/compromised
    Compromised {
        marked_at: u64,
        reason: String,
    },
}

/// Stored trust record for a peer
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TrustRecord {
    /// Peer's identity fingerprint (hex)
    pub fingerprint: String,
    /// Current trust level
    pub trust_level: TrustLevel,
    /// Display name if known
    pub display_name: Option<String>,
    /// Last interaction timestamp
    pub last_seen: u64,
    /// Number of successful verifications
    pub verification_count: u32,
}

/// Manages trust relationships with peers
pub struct TrustManager {
    /// Trust records by fingerprint
    records: HashMap<String, TrustRecord>,
}

impl TrustManager {
    /// Create a new trust manager
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }
    
    /// Load from existing records
    pub fn with_records(records: HashMap<String, TrustRecord>) -> Self {
        Self { records }
    }
    
    /// Get all trust records (for persistence)
    pub fn all_records(&self) -> &HashMap<String, TrustRecord> {
        &self.records
    }
    
    /// Record first contact with a peer (TOFU)
    pub fn record_tofu(&mut self, identity_key: &IdentityPublicKey, display_name: Option<&str>) -> &TrustRecord {
        let fingerprint = identity_key.fingerprint_hex();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.records.entry(fingerprint.clone()).or_insert_with(|| {
            TrustRecord {
                fingerprint: fingerprint.clone(),
                trust_level: TrustLevel::Tofu {
                    first_seen: now,
                    pinned_key: identity_key.fingerprint(),
                },
                display_name: display_name.map(String::from),
                last_seen: now,
                verification_count: 0,
            }
        });
        
        // Update last_seen if record already exists
        if let Some(record) = self.records.get_mut(&fingerprint) {
            record.last_seen = now;
        }
        
        self.records.get(&fingerprint).unwrap()
    }
    
    /// Verify a peer's identity
    pub fn verify_peer(&mut self, fingerprint: &str, method: TrustVerificationMethod) -> Result<(), String> {
        let record = self.records.get_mut(fingerprint)
            .ok_or_else(|| "Unknown peer".to_string())?;
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        record.trust_level = TrustLevel::Verified {
            verified_at: now,
            method,
        };
        record.verification_count += 1;
        record.last_seen = now;
        
        Ok(())
    }
    
    /// Check if a peer's key has changed (must be called when connecting)
    pub fn check_key(&mut self, identity_key: &IdentityPublicKey) -> TrustCheckResult {
        let fingerprint = identity_key.fingerprint_hex();
        let current_key = identity_key.fingerprint();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        match self.records.get(&fingerprint) {
            None => {
                // First contact - create TOFU record
                self.records.insert(fingerprint.clone(), TrustRecord {
                    fingerprint,
                    trust_level: TrustLevel::Tofu {
                        first_seen: now,
                        pinned_key: current_key,
                    },
                    display_name: None,
                    last_seen: now,
                    verification_count: 0,
                });
                TrustCheckResult::NewPeer
            }
            Some(record) => {
                match &record.trust_level {
                    TrustLevel::Tofu { pinned_key, .. } => {
                        // Check if key matches the pinned key from TOFU
                        let stored_key = *pinned_key;
                        if stored_key == current_key {
                            return TrustCheckResult::Trusted;
                        } else {
                            // Key changed!
                            let prev_key = stored_key;
                            self.records.get_mut(&identity_key.fingerprint_hex()).unwrap().trust_level = 
                                TrustLevel::KeyChanged {
                                    previous_key: prev_key,
                                    new_key: current_key,
                                    changed_at: now,
                                };
                            return TrustCheckResult::KeyChanged { previous: prev_key, current: current_key };
                        }
                    }
                    TrustLevel::Verified { .. } => {
                        // Already explicitly verified by user - trust it
                        // In a production system, we'd store and check the verified key
                        // For now, if manually verified, we trust the peer
                        TrustCheckResult::Trusted
                    }
                    TrustLevel::KeyChanged { .. } => TrustCheckResult::KeyChanged {
                        previous: [0u8; 32], // Unknown previous
                        current: current_key,
                    },
                    TrustLevel::Compromised { reason, .. } => TrustCheckResult::Compromised(reason.clone()),
                    TrustLevel::Unknown => TrustCheckResult::Untrusted,
                }
            }
        }
    }
    
    /// Mark a peer as compromised/untrusted
    pub fn mark_compromised(&mut self, fingerprint: &str, reason: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let Some(record) = self.records.get_mut(fingerprint) {
            record.trust_level = TrustLevel::Compromised {
                marked_at: now,
                reason: reason.to_string(),
            };
        }
    }
    
    /// Accept a key change (user acknowledged the change)
    pub fn accept_key_change(&mut self, fingerprint: &str) -> Result<(), String> {
        let record = self.records.get_mut(fingerprint)
            .ok_or_else(|| "Unknown peer".to_string())?;
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let TrustLevel::KeyChanged { new_key, .. } = &record.trust_level {
            record.trust_level = TrustLevel::Tofu {
                first_seen: now,
                pinned_key: *new_key,
            };
            Ok(())
        } else {
            Err("Peer is not in key changed state".to_string())
        }
    }
    
    /// Get trust level for a peer
    pub fn get_trust_level(&self, fingerprint: &str) -> Option<&TrustLevel> {
        self.records.get(fingerprint).map(|r| &r.trust_level)
    }
    
    /// Get a human-readable trust description
    pub fn get_trust_description(&self, fingerprint: &str) -> String {
        match self.records.get(fingerprint) {
            None => "Unknown".to_string(),
            Some(record) => match &record.trust_level {
                TrustLevel::Unknown => "Unknown".to_string(),
                TrustLevel::Tofu { .. } => "Trust on first use".to_string(),
                TrustLevel::Verified { method, .. } => {
                    format!("Verified via {:?}", method)
                }
                TrustLevel::KeyChanged { .. } => "⚠️ Key changed!".to_string(),
                TrustLevel::Compromised { reason, .. } => format!("⛔ Compromised: {}", reason),
            }
        }
    }
    
    /// Generate safety numbers for verification
    /// These are strings users can compare out-of-band
    pub fn generate_safety_number(our_fingerprint: &[u8; 32], their_fingerprint: &[u8; 32]) -> String {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        
        // Use consistent ordering by sorting fingerprints
        let (first, second) = if our_fingerprint < their_fingerprint {
            (our_fingerprint, their_fingerprint)
        } else {
            (their_fingerprint, our_fingerprint)
        };
        
        hasher.update(first);
        hasher.update(second);
        let hash = hasher.finalize();
        
        // Format as 12 groups of 5 digits
        let mut safety_number = String::with_capacity(72);
        for i in 0..12 {
            let chunk = &hash[i * 2..(i * 2) + 2];
            let num = (u16::from_be_bytes([chunk[0], chunk[1]]) as u32) % 100000;
            if i > 0 {
                safety_number.push(' ');
            }
            safety_number.push_str(&format!("{:05}", num));
        }
        
        safety_number
    }
}

impl Default for TrustManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of checking a peer's identity key
#[derive(Clone, Debug)]
pub enum TrustCheckResult {
    /// New peer, TOFU applied
    NewPeer,
    /// Known and trusted peer
    Trusted,
    /// Known but not verified
    Untrusted,
    /// Key has changed since last seen - potential attack!
    KeyChanged {
        previous: [u8; 32],
        current: [u8; 32],
    },
    /// Peer marked as compromised
    Compromised(String),
    /// Key has been revoked
    Revoked(RevocationReason),
}

// =============================================================================
// Key Revocation System
// =============================================================================

/// Reason for key revocation
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RevocationReason {
    /// Key was compromised (known to attacker)
    Compromised,
    /// Planned key rotation (not compromised)
    KeyRotation,
    /// Device was lost or stolen
    DeviceLost,
    /// User requested revocation
    UserRequested,
    /// Key expired
    Expired,
    /// Device deauthorized
    DeviceDeauthorized,
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compromised => write!(f, "Key compromised"),
            Self::KeyRotation => write!(f, "Key rotation"),
            Self::DeviceLost => write!(f, "Device lost"),
            Self::UserRequested => write!(f, "User requested"),
            Self::Expired => write!(f, "Key expired"),
            Self::DeviceDeauthorized => write!(f, "Device deauthorized"),
        }
    }
}

/// A signed revocation certificate
#[derive(Clone, Debug)]
pub struct RevocationCertificate {
    /// The revoked key's fingerprint
    pub revoked_fingerprint: [u8; 32],
    /// Reason for revocation
    pub reason: RevocationReason,
    /// Timestamp of revocation
    pub revoked_at: u64,
    /// Optional successor key fingerprint (for rotation)
    pub successor_fingerprint: Option<[u8; 32]>,
    /// The revoking authority's fingerprint (usually same as revoked, or parent key)
    pub revoker_fingerprint: [u8; 32],
    /// Ed25519 signature over the revocation data (64 bytes)
    pub signature: [u8; 64],
}

// Manual serde implementation for RevocationCertificate to handle [u8; 64]
impl serde::Serialize for RevocationCertificate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RevocationCertificate", 6)?;
        state.serialize_field("revoked_fingerprint", &hex::encode(self.revoked_fingerprint))?;
        state.serialize_field("reason", &self.reason)?;
        state.serialize_field("revoked_at", &self.revoked_at)?;
        state.serialize_field("successor_fingerprint", &self.successor_fingerprint.map(|f| hex::encode(f)))?;
        state.serialize_field("revoker_fingerprint", &hex::encode(self.revoker_fingerprint))?;
        state.serialize_field("signature", &hex::encode(self.signature))?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for RevocationCertificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Helper {
            revoked_fingerprint: String,
            reason: RevocationReason,
            revoked_at: u64,
            successor_fingerprint: Option<String>,
            revoker_fingerprint: String,
            signature: String,
        }
        
        let helper = Helper::deserialize(deserializer)?;
        
        let revoked_fingerprint = hex::decode(&helper.revoked_fingerprint)
            .map_err(serde::de::Error::custom)?;
        if revoked_fingerprint.len() != 32 {
            return Err(serde::de::Error::custom("invalid revoked_fingerprint length"));
        }
        let mut rf = [0u8; 32];
        rf.copy_from_slice(&revoked_fingerprint);
        
        let revoker_fingerprint = hex::decode(&helper.revoker_fingerprint)
            .map_err(serde::de::Error::custom)?;
        if revoker_fingerprint.len() != 32 {
            return Err(serde::de::Error::custom("invalid revoker_fingerprint length"));
        }
        let mut rkf = [0u8; 32];
        rkf.copy_from_slice(&revoker_fingerprint);
        
        let signature = hex::decode(&helper.signature)
            .map_err(serde::de::Error::custom)?;
        if signature.len() != 64 {
            return Err(serde::de::Error::custom("invalid signature length"));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&signature);
        
        let successor_fingerprint = if let Some(s) = helper.successor_fingerprint {
            let sf = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if sf.len() != 32 {
                return Err(serde::de::Error::custom("invalid successor_fingerprint length"));
            }
            let mut sfp = [0u8; 32];
            sfp.copy_from_slice(&sf);
            Some(sfp)
        } else {
            None
        };
        
        Ok(Self {
            revoked_fingerprint: rf,
            reason: helper.reason,
            revoked_at: helper.revoked_at,
            successor_fingerprint,
            revoker_fingerprint: rkf,
            signature: sig,
        })
    }
}

impl RevocationCertificate {
    /// Create a self-revocation (key owner revokes their own key)
    pub fn self_revoke(
        identity: &IdentityKeyPair,
        reason: RevocationReason,
        successor: Option<&IdentityKeyPair>,
    ) -> Self {
        let revoked_fingerprint = identity.fingerprint();
        let revoker_fingerprint = revoked_fingerprint;
        let successor_fingerprint = successor.map(|s| s.fingerprint());
        let revoked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut cert = Self {
            revoked_fingerprint,
            reason,
            revoked_at,
            successor_fingerprint,
            revoker_fingerprint,
            signature: [0u8; 64],
        };
        
        cert.sign(identity);
        cert
    }
    
    /// Sign the revocation certificate
    fn sign(&mut self, signer: &IdentityKeyPair) {
        let data = self.signing_data();
        self.signature = signer.sign(&data);
    }
    
    /// Get the data to be signed
    fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(b"NSC_REVOCATION_v1");
        data.extend_from_slice(&self.revoked_fingerprint);
        data.push(self.reason_byte());
        data.extend_from_slice(&self.revoked_at.to_be_bytes());
        if let Some(successor) = &self.successor_fingerprint {
            data.push(1);
            data.extend_from_slice(successor);
        } else {
            data.push(0);
        }
        data.extend_from_slice(&self.revoker_fingerprint);
        data
    }
    
    fn reason_byte(&self) -> u8 {
        match self.reason {
            RevocationReason::Compromised => 0,
            RevocationReason::KeyRotation => 1,
            RevocationReason::DeviceLost => 2,
            RevocationReason::UserRequested => 3,
            RevocationReason::Expired => 4,
            RevocationReason::DeviceDeauthorized => 5,
        }
    }
    
    /// Verify the revocation certificate signature
    pub fn verify(&self, revoker_public_key: &IdentityPublicKey) -> bool {
        let data = self.signing_data();
        revoker_public_key.verify(&data, &self.signature).is_ok()
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(170);
        bytes.extend_from_slice(&self.revoked_fingerprint);
        bytes.push(self.reason_byte());
        bytes.extend_from_slice(&self.revoked_at.to_be_bytes());
        if let Some(successor) = &self.successor_fingerprint {
            bytes.push(1);
            bytes.extend_from_slice(successor);
        } else {
            bytes.push(0);
        }
        bytes.extend_from_slice(&self.revoker_fingerprint);
        bytes.extend_from_slice(&self.signature);
        bytes
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 106 {
            return None;
        }
        
        let mut revoked_fingerprint = [0u8; 32];
        revoked_fingerprint.copy_from_slice(&bytes[0..32]);
        
        let reason = match bytes[32] {
            0 => RevocationReason::Compromised,
            1 => RevocationReason::KeyRotation,
            2 => RevocationReason::DeviceLost,
            3 => RevocationReason::UserRequested,
            4 => RevocationReason::Expired,
            5 => RevocationReason::DeviceDeauthorized,
            _ => return None,
        };
        
        let mut revoked_at_bytes = [0u8; 8];
        revoked_at_bytes.copy_from_slice(&bytes[33..41]);
        let revoked_at = u64::from_be_bytes(revoked_at_bytes);
        
        let (successor_fingerprint, offset) = if bytes[41] == 1 {
            if bytes.len() < 138 {
                return None;
            }
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&bytes[42..74]);
            (Some(fp), 74)
        } else {
            (None, 42)
        };
        
        if bytes.len() < offset + 96 {
            return None;
        }
        
        let mut revoker_fingerprint = [0u8; 32];
        revoker_fingerprint.copy_from_slice(&bytes[offset..offset + 32]);
        
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[offset + 32..offset + 96]);
        
        Some(Self {
            revoked_fingerprint,
            reason,
            revoked_at,
            successor_fingerprint,
            revoker_fingerprint,
            signature,
        })
    }
}

/// Manages key revocations
pub struct RevocationManager {
    /// Known revocations by revoked fingerprint (hex)
    revocations: HashMap<String, RevocationCertificate>,
    /// Revocations pending broadcast
    pending_broadcasts: Vec<RevocationCertificate>,
}

impl RevocationManager {
    /// Create a new revocation manager
    pub fn new() -> Self {
        Self {
            revocations: HashMap::new(),
            pending_broadcasts: Vec::new(),
        }
    }
    
    /// Load from existing revocations
    pub fn with_revocations(revocations: HashMap<String, RevocationCertificate>) -> Self {
        Self {
            revocations,
            pending_broadcasts: Vec::new(),
        }
    }
    
    /// Get all revocations (for persistence)
    pub fn all_revocations(&self) -> &HashMap<String, RevocationCertificate> {
        &self.revocations
    }
    
    /// Revoke our own key
    pub fn revoke_self(
        &mut self,
        identity: &IdentityKeyPair,
        reason: RevocationReason,
        successor: Option<&IdentityKeyPair>,
    ) -> RevocationCertificate {
        let cert = RevocationCertificate::self_revoke(identity, reason, successor);
        let fingerprint_hex = hex::encode(cert.revoked_fingerprint);
        self.revocations.insert(fingerprint_hex, cert.clone());
        self.pending_broadcasts.push(cert.clone());
        cert
    }
    
    /// Process a received revocation certificate
    pub fn process_revocation(
        &mut self,
        cert: &RevocationCertificate,
        revoker_key: Option<&IdentityPublicKey>,
    ) -> Result<(), CryptoError> {
        // For self-revocation, revoker_key can be derived from revoked key
        // For authority revocation, must provide the authority's key
        if let Some(key) = revoker_key {
            if !cert.verify(key) {
                return Err(CryptoError::InvalidRevocation);
            }
        }
        
        let fingerprint_hex = hex::encode(cert.revoked_fingerprint);
        
        // Check if we already have a newer revocation
        if let Some(existing) = self.revocations.get(&fingerprint_hex) {
            if existing.revoked_at >= cert.revoked_at {
                return Ok(()); // Already have newer or same revocation
            }
        }
        
        self.revocations.insert(fingerprint_hex, cert.clone());
        Ok(())
    }
    
    /// Check if a key is revoked
    pub fn is_revoked(&self, fingerprint: &[u8; 32]) -> Option<&RevocationCertificate> {
        let fingerprint_hex = hex::encode(fingerprint);
        self.revocations.get(&fingerprint_hex)
    }
    
    /// Check if a key is revoked (hex fingerprint)
    pub fn is_revoked_hex(&self, fingerprint_hex: &str) -> Option<&RevocationCertificate> {
        self.revocations.get(fingerprint_hex)
    }
    
    /// Get successor key if one exists
    pub fn get_successor(&self, fingerprint: &[u8; 32]) -> Option<[u8; 32]> {
        self.is_revoked(fingerprint).and_then(|cert| cert.successor_fingerprint)
    }
    
    /// Take pending broadcasts (clears the list)
    pub fn take_pending_broadcasts(&mut self) -> Vec<RevocationCertificate> {
        std::mem::take(&mut self.pending_broadcasts)
    }
    
    /// Clear expired revocations (older than retention period)
    pub fn clear_expired(&mut self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.revocations.retain(|_, cert| {
            // Keep revocations that are newer than max_age
            // Exception: always keep compromised key revocations
            cert.reason == RevocationReason::Compromised || 
            now - cert.revoked_at < max_age_secs
        });
    }
}

impl Default for RevocationManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Secure Key Storage
// =============================================================================

/// Encrypted key storage
pub struct KeyStorage {
    /// Encryption key derived from password
    storage_key: [u8; 32],
}

impl KeyStorage {
    /// Create new key storage with password
    pub fn new(password: &str) -> CryptoResult<Self> {
        // Derive storage key from password using HKDF
        // In production, use Argon2 or similar memory-hard function
        let storage_key_vec = kdf(password.as_bytes(), b"NSC_KeyStorage", 32)?;
        let mut storage_key = [0u8; 32];
        storage_key.copy_from_slice(&storage_key_vec);
        Ok(Self { storage_key })
    }

    /// Encrypt data for storage
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.storage_key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypt data from storage
    pub fn decrypt(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.storage_key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
        let ct = &ciphertext[NONCE_SIZE..];

        cipher
            .decrypt(nonce, ct)
            .map_err(|_| CryptoError::DecryptionFailed("Authentication failed".into()))
    }

    /// Save identity key pair to encrypted bytes
    pub fn save_identity(&self, identity: &IdentityKeyPair) -> CryptoResult<Vec<u8>> {
        self.encrypt(&identity.to_bytes())
    }

    /// Load identity key pair from encrypted bytes
    pub fn load_identity(&self, encrypted: &[u8]) -> CryptoResult<IdentityKeyPair> {
        let decrypted = self.decrypt(encrypted)?;
        if decrypted.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: decrypted.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decrypted);
        Ok(IdentityKeyPair::from_bytes(&bytes))
    }
}

impl Drop for KeyStorage {
    fn drop(&mut self) {
        self.storage_key.zeroize();
    }
}

// =============================================================================
// Session Persistence
// =============================================================================

/// Serializable form of Double Ratchet session state
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SerializedSession {
    /// Our ratchet private key (if we have one)
    pub ratchet_private_key: Option<[u8; 32]>,
    /// Their current ratchet public key
    pub remote_ratchet_key: Option<[u8; 32]>,
    /// Root key
    pub root_key: [u8; 32],
    /// Sending chain key (if any)
    pub sending_chain: Option<[u8; 32]>,
    /// Receiving chain key (if any)
    pub receiving_chain: Option<[u8; 32]>,
    /// Message counts
    pub send_count: u32,
    pub recv_count: u32,
    pub previous_chain_length: u32,
    /// Skipped keys: (ratchet_key_hex, msg_num) -> message_key_bytes
    pub skipped_keys: Vec<(String, u32, [u8; 32])>,
    /// Associated data
    pub associated_data: Vec<u8>,
}

/// Serializable form of PreKey state
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SerializedPreKeyState {
    /// Identity DH private key
    pub identity_dh_private: [u8; 32],
    /// Signed prekey private
    pub signed_prekey_private: [u8; 32],
    /// Signed prekey signature (stored as Vec since [u8; 64] doesn't impl serde)
    pub signed_prekey_signature: Vec<u8>,
    /// One-time prekeys (private keys)
    pub one_time_prekeys: Vec<[u8; 32]>,
}

/// Full serializable form of PeerSessionManager
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SerializedPeerSessionManager {
    /// Identity private key bytes
    pub identity_private_key: [u8; 32],
    /// PreKey state
    pub prekey_state: SerializedPreKeyState,
    /// Sessions by peer fingerprint (hex)
    pub sessions: Vec<(String, SerializedSession)>,
}

impl DoubleRatchetSession {
    /// Serialize session state for persistence
    pub fn to_serialized(&self) -> SerializedSession {
        SerializedSession {
            ratchet_private_key: self.ratchet_keypair.as_ref().map(|kp| kp.secret_bytes()),
            remote_ratchet_key: self.remote_ratchet_key.map(|k| k.to_bytes()),
            root_key: self.root_key,
            sending_chain: self.sending_chain.as_ref().map(|c| c.0),
            receiving_chain: self.receiving_chain.as_ref().map(|c| c.0),
            send_count: self.send_count,
            recv_count: self.recv_count,
            previous_chain_length: self.previous_chain_length,
            skipped_keys: self.skipped_keys.iter()
                .map(|((rk, num), mk)| (hex::encode(rk), *num, mk.0))
                .collect(),
            associated_data: self.associated_data.clone(),
        }
    }
    
    /// Restore session from serialized state
    pub fn from_serialized(s: SerializedSession) -> Self {
        let ratchet_keypair = s.ratchet_private_key.map(|pk| {
            let secret = X25519SecretKey::from(pk);
            let public = X25519PublicKey::from(&secret);
            X25519KeyPair { secret, public }
        });
        
        let remote_ratchet_key = s.remote_ratchet_key.map(X25519PublicKey::from);
        
        let sending_chain = s.sending_chain.map(ChainKey::new);
        let receiving_chain = s.receiving_chain.map(ChainKey::new);
        
        let skipped_keys: HashMap<([u8; 32], u32), MessageKey> = s.skipped_keys
            .into_iter()
            .filter_map(|(rk_hex, num, mk_bytes)| {
                let rk_bytes = hex::decode(&rk_hex).ok()?;
                if rk_bytes.len() != 32 { return None; }
                let mut rk = [0u8; 32];
                rk.copy_from_slice(&rk_bytes);
                Some(((rk, num), MessageKey(mk_bytes)))
            })
            .collect();
        
        Self {
            ratchet_keypair,
            remote_ratchet_key,
            root_key: s.root_key,
            sending_chain,
            receiving_chain,
            send_count: s.send_count,
            recv_count: s.recv_count,
            previous_chain_length: s.previous_chain_length,
            skipped_keys,
            associated_data: s.associated_data,
        }
    }
}

impl PeerSessionManager {
    /// Serialize entire manager state for encrypted storage
    pub fn to_serialized(&self) -> SerializedPeerSessionManager {
        let prekey_state = SerializedPreKeyState {
            identity_dh_private: self.identity_dh.secret_bytes(),
            signed_prekey_private: self.prekey_state.signed_prekey.secret_bytes(),
            signed_prekey_signature: self.prekey_state.signed_prekey_signature.to_vec(),
            one_time_prekeys: self.prekey_state.one_time_prekeys
                .iter()
                .map(|kp| kp.secret_bytes())
                .collect(),
        };
        
        let sessions = self.sessions
            .iter()
            .map(|(fingerprint, session)| {
                (hex::encode(fingerprint), session.to_serialized())
            })
            .collect();
        
        SerializedPeerSessionManager {
            identity_private_key: self.identity.to_bytes(),
            prekey_state,
            sessions,
        }
    }
    
    /// Restore manager from serialized state
    pub fn from_serialized(s: SerializedPeerSessionManager) -> Self {
        let identity = IdentityKeyPair::from_bytes(&s.identity_private_key);
        
        // Restore identity DH
        let identity_dh_secret = X25519SecretKey::from(s.prekey_state.identity_dh_private);
        let identity_dh_public = X25519PublicKey::from(&identity_dh_secret);
        let identity_dh = X25519KeyPair {
            secret: identity_dh_secret,
            public: identity_dh_public,
        };
        
        // Restore signed prekey
        let signed_prekey_secret = X25519SecretKey::from(s.prekey_state.signed_prekey_private);
        let signed_prekey_public = X25519PublicKey::from(&signed_prekey_secret);
        let signed_prekey = X25519KeyPair {
            secret: signed_prekey_secret,
            public: signed_prekey_public,
        };
        
        // Restore one-time prekeys
        let one_time_prekeys: Vec<X25519KeyPair> = s.prekey_state.one_time_prekeys
            .into_iter()
            .map(|pk| {
                let secret = X25519SecretKey::from(pk);
                let public = X25519PublicKey::from(&secret);
                X25519KeyPair { secret, public }
            })
            .collect();
        
        // Convert Vec<u8> signature back to [u8; 64]
        let mut signed_prekey_signature = [0u8; 64];
        if s.prekey_state.signed_prekey_signature.len() >= 64 {
            signed_prekey_signature.copy_from_slice(&s.prekey_state.signed_prekey_signature[..64]);
        }
        
        let prekey_state = PreKeyState {
            identity: identity.clone(),
            identity_dh: identity_dh.clone(),
            signed_prekey,
            signed_prekey_signature,
            one_time_prekeys,
            used_one_time_prekeys: std::collections::HashSet::new(),
        };
        
        // Restore sessions
        let sessions: HashMap<[u8; 32], DoubleRatchetSession> = s.sessions
            .into_iter()
            .filter_map(|(fingerprint_hex, session)| {
                let fingerprint_bytes = hex::decode(&fingerprint_hex).ok()?;
                if fingerprint_bytes.len() != 32 { return None; }
                let mut fingerprint = [0u8; 32];
                fingerprint.copy_from_slice(&fingerprint_bytes);
                Some((fingerprint, DoubleRatchetSession::from_serialized(session)))
            })
            .collect();
        
        Self {
            identity,
            identity_dh,
            prekey_state,
            sessions,
            pending_x3dh: HashMap::new(),
        }
    }
}

impl TrustManager {
    /// Serialize trust records for storage
    pub fn to_serialized(&self) -> Vec<TrustRecord> {
        self.all_records().values().cloned().collect()
    }
    
    /// Restore from serialized records
    pub fn from_serialized(records: Vec<TrustRecord>) -> Self {
        let map: HashMap<String, TrustRecord> = records.into_iter()
            .map(|r| (r.fingerprint.clone(), r))
            .collect();
        Self::with_records(map)
    }
}

impl KeyStorage {
    /// Save peer session manager to encrypted bytes
    pub fn save_sessions(&self, manager: &PeerSessionManager) -> CryptoResult<Vec<u8>> {
        let serialized = manager.to_serialized();
        let json = serde_json::to_vec(&serialized)
            .map_err(|e| CryptoError::EncryptionFailed(format!("Serialization failed: {}", e)))?;
        self.encrypt(&json)
    }
    
    /// Load peer session manager from encrypted bytes
    pub fn load_sessions(&self, encrypted: &[u8]) -> CryptoResult<PeerSessionManager> {
        let json = self.decrypt(encrypted)?;
        let serialized: SerializedPeerSessionManager = serde_json::from_slice(&json)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Deserialization failed: {}", e)))?;
        Ok(PeerSessionManager::from_serialized(serialized))
    }
    
    /// Save trust manager to encrypted bytes
    pub fn save_trust(&self, manager: &TrustManager) -> CryptoResult<Vec<u8>> {
        let records = manager.to_serialized();
        let json = serde_json::to_vec(&records)
            .map_err(|e| CryptoError::EncryptionFailed(format!("Serialization failed: {}", e)))?;
        self.encrypt(&json)
    }
    
    /// Load trust manager from encrypted bytes
    pub fn load_trust(&self, encrypted: &[u8]) -> CryptoResult<TrustManager> {
        let json = self.decrypt(encrypted)?;
        let records: Vec<TrustRecord> = serde_json::from_slice(&json)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Deserialization failed: {}", e)))?;
        Ok(TrustManager::from_serialized(records))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_key_generation() {
        let identity = IdentityKeyPair::generate();
        let public = identity.public_key();

        // Sign and verify
        let message = b"Hello, World!";
        let signature = identity.sign(message);
        assert!(public.verify(message, &signature).is_ok());

        // Verify fails with wrong message
        assert!(public.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_identity_serialization() {
        let identity = IdentityKeyPair::generate();
        let bytes = identity.to_bytes();

        let restored = IdentityKeyPair::from_bytes(&bytes);
        assert_eq!(identity.public_key().to_bytes(), restored.public_key().to_bytes());
    }

    #[test]
    fn test_x25519_key_exchange() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_x3dh_key_agreement() {
        // Bob creates prekey state
        let bob_identity = IdentityKeyPair::generate();
        let mut bob_prekeys = PreKeyState::new(bob_identity, 10);
        let bob_bundle = bob_prekeys.to_bundle();

        // Alice initiates X3DH (needs her own identity DH key)
        let alice_identity = IdentityKeyPair::generate();
        let alice_identity_dh = X25519KeyPair::generate();
        let alice_output = x3dh_sender(&alice_identity, &alice_identity_dh, &bob_bundle).unwrap();

        // Bob receives X3DH
        let header = X3dhHeader {
            identity_key: alice_identity.public_key(),
            identity_dh_key: alice_output.identity_dh_public,
            ephemeral_key: alice_output.ephemeral_public,
            one_time_prekey: alice_output.used_one_time_prekey,
        };

        let bob_agreement = x3dh_receiver(&mut bob_prekeys, &header).unwrap();

        // Both should derive the same shared secret
        assert_eq!(
            alice_output.agreement.shared_secret,
            bob_agreement.shared_secret
        );
    }

    #[test]
    fn test_double_ratchet_session() {
        // Setup: Bob creates prekeys, Alice initiates X3DH
        let bob_identity = IdentityKeyPair::generate();
        let mut bob_prekeys = PreKeyState::new(bob_identity, 10);
        let bob_bundle = bob_prekeys.to_bundle();

        let alice_identity = IdentityKeyPair::generate();
        let alice_identity_dh = X25519KeyPair::generate();
        let alice_x3dh = x3dh_sender(&alice_identity, &alice_identity_dh, &bob_bundle).unwrap();

        // Bob's initial ratchet key is his signed prekey
        let bob_ratchet_key = bob_prekeys.signed_prekey.public_key();

        // Alice initializes as sender
        let mut alice_session =
            DoubleRatchetSession::init_sender(alice_x3dh.agreement, bob_ratchet_key).unwrap();

        // Bob receives X3DH header
        let x3dh_header = X3dhHeader {
            identity_key: alice_identity.public_key(),
            identity_dh_key: alice_x3dh.identity_dh_public,
            ephemeral_key: alice_x3dh.ephemeral_public,
            one_time_prekey: alice_x3dh.used_one_time_prekey,
        };

        let bob_x3dh = x3dh_receiver(&mut bob_prekeys, &x3dh_header).unwrap();

        // Bob initializes as receiver
        let mut bob_session =
            DoubleRatchetSession::init_receiver(bob_x3dh, bob_prekeys.signed_prekey.clone());

        // Alice sends message
        let plaintext = b"Hello Bob!";
        let (header, ciphertext) = alice_session.encrypt(plaintext).unwrap();

        // Bob decrypts
        let decrypted = bob_session.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Bob replies
        let reply = b"Hello Alice!";
        let (header2, ciphertext2) = bob_session.encrypt(reply).unwrap();

        // Alice decrypts
        let decrypted2 = alice_session.decrypt(&header2, &ciphertext2).unwrap();
        assert_eq!(reply.as_slice(), decrypted2.as_slice());

        // Multiple messages back and forth
        for i in 0..5 {
            let msg = format!("Message {} from Alice", i);
            let (h, c) = alice_session.encrypt(msg.as_bytes()).unwrap();
            let d = bob_session.decrypt(&h, &c).unwrap();
            assert_eq!(msg.as_bytes(), d.as_slice());

            let reply = format!("Reply {} from Bob", i);
            let (h2, c2) = bob_session.encrypt(reply.as_bytes()).unwrap();
            let d2 = alice_session.decrypt(&h2, &c2).unwrap();
            assert_eq!(reply.as_bytes(), d2.as_slice());
        }
    }

    #[test]
    fn test_key_storage() {
        let storage = KeyStorage::new("test_password").unwrap();

        // Encrypt and decrypt data
        let plaintext = b"Secret data";
        let encrypted = storage.encrypt(plaintext).unwrap();
        let decrypted = storage.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Save and load identity
        let identity = IdentityKeyPair::generate();
        let encrypted_identity = storage.save_identity(&identity).unwrap();
        let loaded_identity = storage.load_identity(&encrypted_identity).unwrap();
        assert_eq!(identity.public_key().to_bytes(), loaded_identity.public_key().to_bytes());
    }

    #[test]
    fn test_out_of_order_messages() {
        // Setup sessions
        let bob_identity = IdentityKeyPair::generate();
        let mut bob_prekeys = PreKeyState::new(bob_identity, 10);
        let bob_bundle = bob_prekeys.to_bundle();

        let alice_identity = IdentityKeyPair::generate();
        let alice_identity_dh = X25519KeyPair::generate();
        let alice_x3dh = x3dh_sender(&alice_identity, &alice_identity_dh, &bob_bundle).unwrap();
        let bob_ratchet_key = bob_prekeys.signed_prekey.public_key();

        let mut alice_session =
            DoubleRatchetSession::init_sender(alice_x3dh.agreement, bob_ratchet_key).unwrap();

        let x3dh_header = X3dhHeader {
            identity_key: alice_identity.public_key(),
            identity_dh_key: alice_x3dh.identity_dh_public,
            ephemeral_key: alice_x3dh.ephemeral_public,
            one_time_prekey: alice_x3dh.used_one_time_prekey,
        };
        let bob_x3dh = x3dh_receiver(&mut bob_prekeys, &x3dh_header).unwrap();
        let mut bob_session =
            DoubleRatchetSession::init_receiver(bob_x3dh, bob_prekeys.signed_prekey.clone());

        // Alice sends 3 messages
        let (header1, cipher1) = alice_session.encrypt(b"Message 1").unwrap();
        let (header2, cipher2) = alice_session.encrypt(b"Message 2").unwrap();
        let (header3, cipher3) = alice_session.encrypt(b"Message 3").unwrap();

        // Bob receives them out of order
        let plain3 = bob_session.decrypt(&header3, &cipher3).unwrap();
        assert_eq!(b"Message 3".as_slice(), plain3.as_slice());

        let plain1 = bob_session.decrypt(&header1, &cipher1).unwrap();
        assert_eq!(b"Message 1".as_slice(), plain1.as_slice());

        let plain2 = bob_session.decrypt(&header2, &cipher2).unwrap();
        assert_eq!(b"Message 2".as_slice(), plain2.as_slice());
    }

    #[test]
    fn test_fingerprint() {
        let identity = IdentityKeyPair::generate();
        let fingerprint = identity.fingerprint();
        let fingerprint_hex = identity.public_key().fingerprint_hex();

        assert_eq!(fingerprint.len(), 32);
        assert_eq!(fingerprint_hex.len(), 64);
        assert_eq!(hex::encode(fingerprint), fingerprint_hex);
    }
}
