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
