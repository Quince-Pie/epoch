//! Concrete Binary Wire & Persistent State Struct Definitions (RFC 8949 Deterministic CBOR).
//!
//! Matches Section 7.3 of `DESIGN.md` verbatim across all 4 planes.

use crate::cbor::{
    serde_byte_vec, serde_bytes12, serde_bytes32, serde_chunk_vec, serde_sig64, serde_vec_bytes32,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type Blake3Hash = [u8; 32];
pub type Sha256Hash = [u8; 32];
pub type Ed25519Pub = [u8; 32];
pub type Ed25519Sig = [u8; 64];

/// Plane 1: Cryptographically Signed Canonical Execution Plan (`plan.cbor`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExecutionPlan {
    pub version: u16,
    pub cluster_id: String,
    pub tx_epoch: u64,
    #[serde(with = "serde_bytes32")]
    pub flake_lock_blake3: Blake3Hash,
    pub waves: Vec<WaveSpec>,
    pub nodes: Vec<NodePlanEntry>,
    #[serde(with = "serde_bytes32")]
    pub coordinator_pub: Ed25519Pub,
    /// Ed25519 signature over BLAKE3(RFC8949_deterministic_cbor(version..coordinator_pub))
    #[serde(with = "serde_sig64")]
    pub coordinator_sig: Ed25519Sig,
}

/// Unsigned payload of `SignedExecutionPlan` used for deterministic CBOR signing & verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsignedExecutionPlan<'a> {
    pub version: u16,
    pub cluster_id: &'a str,
    pub tx_epoch: u64,
    #[serde(with = "serde_bytes32")]
    pub flake_lock_blake3: Blake3Hash,
    pub waves: &'a [WaveSpec],
    pub nodes: &'a [NodePlanEntry],
    #[serde(with = "serde_bytes32")]
    pub coordinator_pub: Ed25519Pub,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveSpec {
    pub wave_id: String,
    pub depends_on: Vec<String>,
    pub node_ids: Vec<String>,
    pub max_unavailable: u16,
    pub lease_ttl_ms: u32,
    pub reboot_lease_ttl_ms: u32,
    pub probes: HealthOracleSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePlanEntry {
    pub node_id: String,
    pub system_arch: String,
    pub rack_id: String,
    pub zone_id: String,
    pub quic_endpoint: String,
    #[serde(with = "serde_bytes32")]
    pub node_pub: Ed25519Pub,
    pub toplevel_path: String,
    pub kernel_path: String,
    pub initrd_path: String,
    #[serde(with = "serde_bytes32")]
    pub secrets_envelope_hash: Blake3Hash,
    #[serde(with = "serde_bytes32")]
    pub closure_manifests_merkle_root: Blake3Hash,
    pub p2p_parent_node_id: Option<String>,
    pub p2p_children_node_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HealthOracleSpec {
    pub required_systemd_units: Vec<String>,
    pub tcp_endpoints: Vec<String>,
    pub http_checks: Vec<(String, u16)>,
    pub peer_mesh_quorum: u16,
    pub forbid_kmsg_patterns: Vec<String>,
}

/// Quorum group policy for static quorum safety verification in Plane 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumGroupSpec {
    pub quorum_id: String,
    pub members: Vec<String>,
    pub max_unavailable: u16,
}

/// Plane 2: Store-Hash-Normalized FastCDC Sub-Package Manifest
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NarChunkManifest {
    pub store_path: String,
    #[serde(with = "serde_bytes32")]
    pub nar_sha256: Sha256Hash,
    pub nar_size: u64,
    /// Sorted 32-char nix-base32 store hashes r_0..r_{m-1} mapped to \x00EPOCH_REF_<hex_u16(idx)>________________
    #[serde(with = "serde_vec_bytes32")]
    pub reference_hashes: Vec<[u8; 32]>,
    pub references_full: Vec<String>,
    pub deriver: Option<String>,
    pub store_sig: String,
    pub chunks: Vec<ChunkDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkDescriptor {
    #[serde(with = "serde_bytes32")]
    pub norm_blake3: Blake3Hash,
    pub raw_len: u32,
    pub zstd_len: u32,
}

/// Plane 3: Hardware-Bound In-Store Ciphertext Envelope (`epoch-secrets.cbor`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEnvelopeBundle {
    pub version: u16,
    pub node_id: String,
    pub archetype_toplevel: String,
    #[serde(with = "serde_byte_vec")]
    pub age_x25519_wrapped_dek: Vec<u8>,
    pub tpm2_sealed_dek: Option<Tpm2SealedBlob>,
    #[serde(with = "serde_bytes12")]
    pub aead_nonce: [u8; 12],
    /// ChaCha20-Poly1305(DEK, nonce, AAD = BLAKE3("epoch-secret-v1" || node_id || archetype_toplevel), cbor(Vec<SecretEntry>))
    #[serde(with = "serde_byte_vec")]
    pub aead_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tpm2SealedBlob {
    pub pcr_mask: u32,
    #[serde(with = "serde_sig64::option")]
    pub policy_authorize_sig: Option<Ed25519Sig>,
    #[serde(with = "serde_byte_vec")]
    pub tpm2b_private: Vec<u8>,
    #[serde(with = "serde_byte_vec")]
    pub tpm2b_public: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretEntry {
    pub name: String,
    pub owner_user: String,
    pub owner_group: String,
    pub mode: u32,
    #[serde(with = "serde_byte_vec")]
    pub plaintext: Vec<u8>,
}

/// Plane 4: Target Crash-Safe Persistent State (`/var/lib/epoch/state.cbor`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentPhase {
    Idle,
    Staged,
    Prepared,
    Activating,
    Probing,
    BarrierWait,
    Committed,
    RolledBack,
}

impl AgentPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            AgentPhase::Idle => "IDLE",
            AgentPhase::Staged => "STAGED",
            AgentPhase::Prepared => "PREPARED",
            AgentPhase::Activating => "ACTIVATING",
            AgentPhase::Probing => "PROBING",
            AgentPhase::BarrierWait => "BARRIER_WAIT",
            AgentPhase::Committed => "COMMITTED",
            AgentPhase::RolledBack => "ROLLED_BACK",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentAgentState {
    pub highest_tx_epoch: u64,
    pub phase: AgentPhase,
    pub active_wave_id: Option<String>,
    pub prev_toplevel: String,
    pub prev_secret_epoch: u64,
    pub staged_toplevel: Option<String>,
    pub lease_deadline_boottime_ns: u64,
    pub reboot_deadline_wall_utc_s: u64,
    #[serde(with = "serde_bytes32")]
    pub state_blake3_mac: Blake3Hash,
}

/// Plane 4: Wire Protocol Messages over QUIC/mTLS (`ALPN = "epoch-p2p/1"`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpochWireMsg {
    StageManifest {
        tx_epoch: u64,
        plan: SignedExecutionPlan,
        manifests: Vec<NarChunkManifest>,
    },
    StageAck {
        tx_epoch: u64,
        node_id: String,
        ok: bool,
        error: Option<String>,
    },
    FetchChunksReq {
        tx_epoch: u64,
        #[serde(with = "serde_vec_bytes32")]
        missing_norm_blake3: Vec<Blake3Hash>,
    },
    FetchChunksResp {
        #[serde(with = "serde_chunk_vec")]
        chunks: Vec<(Blake3Hash, Vec<u8>)>,
    },
    PrepareWave {
        tx_epoch: u64,
        wave_id: String,
    },
    PrepareAck {
        tx_epoch: u64,
        wave_id: String,
        node_id: String,
        ok: bool,
        error: Option<String>,
    },
    ActivateWave {
        tx_epoch: u64,
        wave_id: String,
        lease_ttl_ms: u32,
        #[serde(with = "serde_sig64")]
        coord_sig: Ed25519Sig,
    },
    LeaseKeepalive {
        tx_epoch: u64,
        wave_id: String,
        extend_ttl_ms: u32,
        #[serde(with = "serde_sig64")]
        coord_sig: Ed25519Sig,
    },
    HealthAttestation {
        tx_epoch: u64,
        wave_id: String,
        node_id: String,
        healthy: bool,
        diagnostic: String,
        #[serde(with = "serde_sig64")]
        node_sig: Ed25519Sig,
    },
    PeerWitnessRelay {
        attestation: Box<EpochWireMsg>,
        relayed_coord_msg: Option<Box<EpochWireMsg>>,
        relay_node_id: String,
        #[serde(with = "serde_sig64")]
        relay_sig: Ed25519Sig,
    },
    CommitWave {
        tx_epoch: u64,
        wave_id: String,
        #[serde(with = "serde_vec_bytes32")]
        attestation_hashes: Vec<Blake3Hash>,
        #[serde(with = "serde_sig64")]
        coord_sig: Ed25519Sig,
    },
    AbortWave {
        tx_epoch: u64,
        wave_id: String,
        reason: String,
        #[serde(with = "serde_sig64")]
        coord_sig: Ed25519Sig,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EpochError {
    #[error(
        "Stale tx_epoch fenced: message epoch {msg_epoch} < highest persisted epoch {highest_epoch}"
    )]
    StaleEpochFenced { msg_epoch: u64, highest_epoch: u64 },

    #[error("Cryptographic verification failed: {0}")]
    CryptoVerificationFailed(String),

    #[error(
        "Store quota exceeded on /nix/store: available {available_bytes} B ({available_inodes} inodes), required {required_bytes} B ({required_inodes} inodes)"
    )]
    StoreQuotaExceeded {
        available_bytes: u64,
        required_bytes: u64,
        available_inodes: u64,
        required_inodes: u64,
    },

    #[error("Disk I/O ENOSPC during staging: {0}")]
    IoEnospc(String),

    #[error("Chunk BLAKE3 digest mismatch on chunk {chunk_idx}: expected {expected}, got {actual}")]
    ChunkBlake3Mismatch {
        chunk_idx: usize,
        expected: String,
        actual: String,
    },

    #[error("NAR SHA-256 or store signature mismatch for {store_path}: {reason}")]
    NarIntegrityMismatch { store_path: String, reason: String },

    #[error("Invalid state machine transition from {from:?} on event {event}")]
    InvalidTransition {
        from: AgentPhase,
        event: &'static str,
    },

    #[error("Secret unseal failed for node {node_id}: {reason}")]
    SecretUnsealFailed { node_id: String, reason: String },

    #[error("Plan validation error: {0}")]
    PlanValidation(String),

    #[error("CBOR codec error: {0}")]
    Cbor(String),

    #[error("I/O error: {0}")]
    Io(String),
}

impl From<crate::cbor::CborError> for EpochError {
    fn from(e: crate::cbor::CborError) -> Self {
        EpochError::Cbor(e.to_string())
    }
}

impl From<std::io::Error> for EpochError {
    fn from(e: std::io::Error) -> Self {
        if e.raw_os_error() == Some(libc::ENOSPC) {
            EpochError::IoEnospc(e.to_string())
        } else {
            EpochError::Io(e.to_string())
        }
    }
}
