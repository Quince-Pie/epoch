//! Cryptographic Primitives Across All Four Planes:
//! - Plane 1: Ed25519 deterministic CBOR execution plan signing & BLAKE3 Merkle hashing.
//! - Plane 2: Nix store path fingerprint Ed25519 signing/verification & SHA-256 / BLAKE3 digests.
//! - Plane 3: ChaCha20-Poly1305 AEAD secret envelopes with AAD binding, X25519+HKDF-SHA256
//!   host-key DEK wrapping, TPM 2.0 PCR-policy sealing/unsealing, and `explicit_bzero` wiping.
//! - Plane 4: Keyed BLAKE3 state MACs and Ed25519 wave control-plane & Peer Witness Relay signatures.

use crate::cbor;
use crate::schema::{
    Blake3Hash, Ed25519Pub, Ed25519Sig, EpochError, EpochWireMsg, PersistentAgentState,
    SecretEntry, SecretEnvelopeBundle, Sha256Hash, SignedExecutionPlan, Tpm2SealedBlob,
    UnsignedExecutionPlan,
};
use base64::Engine as _;
use ring::aead::{self, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, Salt};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroize;

pub struct Ed25519Identity {
    seed: [u8; 32],
    x25519_scalar: [u8; 32],
    x25519_pub: [u8; 32],
    keypair: Ed25519KeyPair,
    pub public_key: Ed25519Pub,
}

impl Drop for Ed25519Identity {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.x25519_scalar.zeroize();
    }
}

impl Ed25519Identity {
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, EpochError> {
        let keypair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|e| {
            EpochError::CryptoVerificationFailed(format!("invalid Ed25519 seed: {e}"))
        })?;
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(keypair.public_key().as_ref());
        let x25519_scalar = ed25519_seed_to_x25519_scalar(&seed);
        let x25519_pub = ed25519_pub_to_x25519(&public_key);
        Ok(Self {
            seed,
            x25519_scalar,
            x25519_pub,
            keypair,
            public_key,
        })
    }

    pub fn from_seed_hex_or_default(
        seed_hex: Option<&str>,
        default_seed: [u8; 32],
    ) -> Result<Self, EpochError> {
        match seed_hex {
            Some(h) => {
                let raw = hex::decode(h.trim()).map_err(|e| {
                    EpochError::CryptoVerificationFailed(format!("invalid hex seed: {e}"))
                })?;
                if raw.len() != 32 {
                    return Err(EpochError::CryptoVerificationFailed(format!(
                        "expected 32-byte Ed25519 seed (64 hex chars), got {} bytes",
                        raw.len()
                    )));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&raw);
                Self::from_seed(seed)
            }
            None => Self::from_seed(default_seed),
        }
    }

    pub fn generate() -> Result<Self, EpochError> {
        let rng = SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)
            .map_err(|_| EpochError::CryptoVerificationFailed("RNG failure".into()))?;
        Self::from_seed(seed)
    }

    #[inline(always)]
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    #[inline(always)]
    pub fn x25519_scalar(&self) -> &[u8; 32] {
        &self.x25519_scalar
    }

    #[inline(always)]
    pub fn x25519_pub(&self) -> &[u8; 32] {
        &self.x25519_pub
    }

    pub fn sign_raw(&self, msg: &[u8]) -> Ed25519Sig {
        let sig = self.keypair.sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }

    pub fn sign_domain_cbor<T: Serialize>(
        &self,
        domain: &[u8],
        payload: &T,
    ) -> Result<Ed25519Sig, EpochError> {
        let digest = domain_cbor_blake3(domain, payload)?;
        Ok(self.sign_raw(&digest))
    }
}

pub fn domain_cbor_blake3<T: Serialize>(
    domain: &[u8],
    payload: &T,
) -> Result<Blake3Hash, EpochError> {
    let cbor_bytes = cbor::to_vec_deterministic(payload)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0x00]);
    hasher.update(&cbor_bytes);
    Ok(*hasher.finalize().as_bytes())
}

pub fn verify_raw_ed25519(
    pub_key: &Ed25519Pub,
    msg: &[u8],
    sig: &Ed25519Sig,
) -> Result<(), EpochError> {
    let verifier = UnparsedPublicKey::new(&ED25519, pub_key);
    verifier.verify(msg, sig).map_err(|_| {
        EpochError::CryptoVerificationFailed("Ed25519 signature verification failed".into())
    })
}

pub fn verify_domain_cbor<T: Serialize>(
    pub_key: &Ed25519Pub,
    domain: &[u8],
    payload: &T,
    sig: &Ed25519Sig,
) -> Result<(), EpochError> {
    let digest = domain_cbor_blake3(domain, payload)?;
    verify_raw_ed25519(pub_key, &digest, sig)
}

/// Sign a `SignedExecutionPlan` in place using the coordinator's `Ed25519Identity`.
pub fn sign_execution_plan(
    plan: &mut SignedExecutionPlan,
    coord_key: &Ed25519Identity,
) -> Result<(), EpochError> {
    plan.coordinator_pub = coord_key.public_key;
    let unsigned = UnsignedExecutionPlan {
        version: plan.version,
        cluster_id: &plan.cluster_id,
        tx_epoch: plan.tx_epoch,
        flake_lock_blake3: plan.flake_lock_blake3,
        waves: &plan.waves,
        nodes: &plan.nodes,
        coordinator_pub: plan.coordinator_pub,
    };
    plan.coordinator_sig = coord_key.sign_domain_cbor(b"epoch-plan-v1", &unsigned)?;
    Ok(())
}

/// Verify a `SignedExecutionPlan` against a list of trusted coordinator public keys.
pub fn verify_execution_plan(
    plan: &SignedExecutionPlan,
    trusted_coordinator_pubs: &[Ed25519Pub],
) -> Result<(), EpochError> {
    if !trusted_coordinator_pubs.contains(&plan.coordinator_pub) {
        return Err(EpochError::CryptoVerificationFailed(
            "coordinator_pub is not in trusted_coordinator_pubs".into(),
        ));
    }
    let unsigned = UnsignedExecutionPlan {
        version: plan.version,
        cluster_id: &plan.cluster_id,
        tx_epoch: plan.tx_epoch,
        flake_lock_blake3: plan.flake_lock_blake3,
        waves: &plan.waves,
        nodes: &plan.nodes,
        coordinator_pub: plan.coordinator_pub,
    };
    verify_domain_cbor(
        &plan.coordinator_pub,
        b"epoch-plan-v1",
        &unsigned,
        &plan.coordinator_sig,
    )
}

// Control-plane wire message signing & verification helpers

pub fn sign_activate_wave(
    coord_key: &Ed25519Identity,
    tx_epoch: u64,
    wave_id: &str,
    lease_ttl_ms: u32,
) -> Result<EpochWireMsg, EpochError> {
    let tuple = (tx_epoch, wave_id, lease_ttl_ms);
    let coord_sig = coord_key.sign_domain_cbor(b"epoch-activate-v1", &tuple)?;
    Ok(EpochWireMsg::ActivateWave {
        tx_epoch,
        wave_id: wave_id.to_owned(),
        lease_ttl_ms,
        coord_sig,
    })
}

pub fn verify_activate_wave(
    coord_pub: &Ed25519Pub,
    tx_epoch: u64,
    wave_id: &str,
    lease_ttl_ms: u32,
    coord_sig: &Ed25519Sig,
) -> Result<(), EpochError> {
    let tuple = (tx_epoch, wave_id, lease_ttl_ms);
    verify_domain_cbor(coord_pub, b"epoch-activate-v1", &tuple, coord_sig)
}

pub fn sign_lease_keepalive(
    coord_key: &Ed25519Identity,
    tx_epoch: u64,
    wave_id: &str,
    extend_ttl_ms: u32,
) -> Result<EpochWireMsg, EpochError> {
    let tuple = (tx_epoch, wave_id, extend_ttl_ms);
    let coord_sig = coord_key.sign_domain_cbor(b"epoch-keepalive-v1", &tuple)?;
    Ok(EpochWireMsg::LeaseKeepalive {
        tx_epoch,
        wave_id: wave_id.to_owned(),
        extend_ttl_ms,
        coord_sig,
    })
}

pub fn verify_lease_keepalive(
    coord_pub: &Ed25519Pub,
    tx_epoch: u64,
    wave_id: &str,
    extend_ttl_ms: u32,
    coord_sig: &Ed25519Sig,
) -> Result<(), EpochError> {
    let tuple = (tx_epoch, wave_id, extend_ttl_ms);
    verify_domain_cbor(coord_pub, b"epoch-keepalive-v1", &tuple, coord_sig)
}

pub fn sign_health_attestation(
    node_key: &Ed25519Identity,
    tx_epoch: u64,
    wave_id: &str,
    node_id: &str,
    healthy: bool,
    diagnostic: &str,
) -> Result<EpochWireMsg, EpochError> {
    let tuple = (tx_epoch, wave_id, node_id, healthy, diagnostic);
    let node_sig = node_key.sign_domain_cbor(b"epoch-attest-v1", &tuple)?;
    Ok(EpochWireMsg::HealthAttestation {
        tx_epoch,
        wave_id: wave_id.to_owned(),
        node_id: node_id.to_owned(),
        healthy,
        diagnostic: diagnostic.to_owned(),
        node_sig,
    })
}

pub fn verify_health_attestation(
    node_pub: &Ed25519Pub,
    tx_epoch: u64,
    wave_id: &str,
    node_id: &str,
    healthy: bool,
    diagnostic: &str,
    node_sig: &Ed25519Sig,
) -> Result<(), EpochError> {
    let tuple = (tx_epoch, wave_id, node_id, healthy, diagnostic);
    verify_domain_cbor(node_pub, b"epoch-attest-v1", &tuple, node_sig)
}

pub fn sign_peer_witness_relay(
    relay_key: &Ed25519Identity,
    relay_node_id: &str,
    attestation: EpochWireMsg,
    relayed_coord_msg: Option<EpochWireMsg>,
) -> Result<EpochWireMsg, EpochError> {
    let tuple = (relay_node_id, &attestation, &relayed_coord_msg);
    let relay_sig = relay_key.sign_domain_cbor(b"epoch-relay-v1", &tuple)?;
    Ok(EpochWireMsg::PeerWitnessRelay {
        attestation: Box::new(attestation),
        relayed_coord_msg: relayed_coord_msg.map(Box::new),
        relay_node_id: relay_node_id.to_owned(),
        relay_sig,
    })
}

pub fn verify_peer_witness_relay(
    relay_pub: &Ed25519Pub,
    relay_node_id: &str,
    attestation: &EpochWireMsg,
    relayed_coord_msg: &Option<Box<EpochWireMsg>>,
    relay_sig: &Ed25519Sig,
) -> Result<(), EpochError> {
    let inner_opt: Option<&EpochWireMsg> = relayed_coord_msg.as_deref();
    let tuple = (relay_node_id, attestation, &inner_opt);
    verify_domain_cbor(relay_pub, b"epoch-relay-v1", &tuple, relay_sig)
}

pub fn sign_commit_wave(
    coord_key: &Ed25519Identity,
    tx_epoch: u64,
    wave_id: &str,
    attestation_hashes: Vec<Blake3Hash>,
) -> Result<EpochWireMsg, EpochError> {
    let tuple = (tx_epoch, wave_id, &attestation_hashes);
    let coord_sig = coord_key.sign_domain_cbor(b"epoch-commit-v1", &tuple)?;
    Ok(EpochWireMsg::CommitWave {
        tx_epoch,
        wave_id: wave_id.to_owned(),
        attestation_hashes,
        coord_sig,
    })
}

pub fn verify_commit_wave(
    coord_pub: &Ed25519Pub,
    tx_epoch: u64,
    wave_id: &str,
    attestation_hashes: &[Blake3Hash],
    coord_sig: &Ed25519Sig,
) -> Result<(), EpochError> {
    let tuple = (tx_epoch, wave_id, attestation_hashes);
    verify_domain_cbor(coord_pub, b"epoch-commit-v1", &tuple, coord_sig)
}

pub fn sign_abort_wave(
    coord_key: &Ed25519Identity,
    tx_epoch: u64,
    wave_id: &str,
    reason: &str,
) -> Result<EpochWireMsg, EpochError> {
    let tuple = (tx_epoch, wave_id, reason);
    let coord_sig = coord_key.sign_domain_cbor(b"epoch-abort-v1", &tuple)?;
    Ok(EpochWireMsg::AbortWave {
        tx_epoch,
        wave_id: wave_id.to_owned(),
        reason: reason.to_owned(),
        coord_sig,
    })
}

pub fn verify_abort_wave(
    coord_pub: &Ed25519Pub,
    tx_epoch: u64,
    wave_id: &str,
    reason: &str,
    coord_sig: &Ed25519Sig,
) -> Result<(), EpochError> {
    let tuple = (tx_epoch, wave_id, reason);
    verify_domain_cbor(coord_pub, b"epoch-abort-v1", &tuple, coord_sig)
}

// Plane 2: Nix Store Path Fingerprint Signing & Verification

pub fn nix_store_path_fingerprint(
    store_path: &str,
    nar_sha256: &Sha256Hash,
    nar_size: u64,
    references_full: &[String],
) -> String {
    let mut sorted_refs: Vec<&str> = references_full.iter().map(String::as_str).collect();
    sorted_refs.sort_unstable();
    format!(
        "1;{};sha256:{};{};{}",
        store_path,
        hex::encode(nar_sha256),
        nar_size,
        sorted_refs.join(",")
    )
}

pub fn sign_nix_store_path(
    key_name: &str,
    signing_key: &Ed25519Identity,
    store_path: &str,
    nar_sha256: &Sha256Hash,
    nar_size: u64,
    references_full: &[String],
) -> String {
    let fp = nix_store_path_fingerprint(store_path, nar_sha256, nar_size, references_full);
    let sig = signing_key.sign_raw(fp.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    format!("{key_name}:{b64}")
}

pub fn verify_nix_store_path_sig(
    store_sig: &str,
    trusted_keys: &[(String, Ed25519Pub)],
    store_path: &str,
    nar_sha256: &Sha256Hash,
    nar_size: u64,
    references_full: &[String],
) -> Result<(), EpochError> {
    let (key_name, b64_sig) =
        store_sig
            .split_once(':')
            .ok_or_else(|| EpochError::NarIntegrityMismatch {
                store_path: store_path.to_owned(),
                reason: "malformed store_sig (missing '<key_name>:<base64>')".into(),
            })?;
    let pub_key = trusted_keys
        .iter()
        .find(|(name, _)| name == key_name)
        .map(|(_, pk)| pk)
        .ok_or_else(|| EpochError::NarIntegrityMismatch {
            store_path: store_path.to_owned(),
            reason: format!("untrusted signing key '{key_name}'"),
        })?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64_sig)
        .map_err(|e| EpochError::NarIntegrityMismatch {
            store_path: store_path.to_owned(),
            reason: format!("invalid base64 in store_sig: {e}"),
        })?;
    if sig_bytes.len() != 64 {
        return Err(EpochError::NarIntegrityMismatch {
            store_path: store_path.to_owned(),
            reason: "store_sig is not 64 bytes".into(),
        });
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    let fp = nix_store_path_fingerprint(store_path, nar_sha256, nar_size, references_full);
    verify_raw_ed25519(pub_key, fp.as_bytes(), &sig).map_err(|_| EpochError::NarIntegrityMismatch {
        store_path: store_path.to_owned(),
        reason: "Ed25519 store signature verification failed".into(),
    })
}

// Plane 3: Secret Envelope Cryptography (ChaCha20-Poly1305 + AAD + Host Key & TPM2 PCR Wrapping)

/// Compute Additional Authenticated Data binding the secret bundle to `(node_id, archetype_toplevel)`:
/// `AAD = BLAKE3("epoch-secret-v1" || node_id || archetype_toplevel)`
pub fn compute_secret_aad(node_id: &str, archetype_toplevel: &str) -> Blake3Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"epoch-secret-v1");
    hasher.update(node_id.as_bytes());
    hasher.update(archetype_toplevel.as_bytes());
    *hasher.finalize().as_bytes()
}

// ============================================================================
// Constant-Time GF(2^255 - 19) Arithmetic, Birational Map, & RFC 7748 X25519
// ============================================================================

type Fe25519 = [u64; 5];
const MASK_51: u64 = (1u64 << 51) - 1;

#[inline]
fn fe_from_bytes(b: &[u8; 32]) -> Fe25519 {
    let load64 = |offset: usize| -> u64 {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&b[offset..offset + 8]);
        u64::from_le_bytes(arr)
    };
    let mut out = [0u64; 5];
    out[0] = load64(0) & MASK_51;
    out[1] = (load64(6) >> 3) & MASK_51;
    out[2] = (load64(12) >> 6) & MASK_51;
    out[3] = (load64(19) >> 1) & MASK_51;
    out[4] = (load64(24) >> 12) & MASK_51; // Clears top bit 255
    out
}

#[inline]
fn fe_carry(mut h: Fe25519) -> Fe25519 {
    for _ in 0..2 {
        let c0 = h[0] >> 51;
        h[0] &= MASK_51;
        h[1] += c0;
        let c1 = h[1] >> 51;
        h[1] &= MASK_51;
        h[2] += c1;
        let c2 = h[2] >> 51;
        h[2] &= MASK_51;
        h[3] += c2;
        let c3 = h[3] >> 51;
        h[3] &= MASK_51;
        h[4] += c3;
        let c4 = h[4] >> 51;
        h[4] &= MASK_51;
        h[0] += c4 * 19;
    }
    h
}

#[inline]
fn fe_to_bytes(h: &Fe25519) -> [u8; 32] {
    let mut t = fe_carry(*h);
    // Conditional subtraction of p = 2^255 - 19
    let mut q = (t[0].wrapping_add(19)) >> 51;
    q = (t[1].wrapping_add(q)) >> 51;
    q = (t[2].wrapping_add(q)) >> 51;
    q = (t[3].wrapping_add(q)) >> 51;
    q = (t[4].wrapping_add(q)) >> 51;

    t[0] = t[0].wrapping_add(19 * q);
    let c0 = t[0] >> 51;
    t[0] &= MASK_51;
    t[1] = t[1].wrapping_add(c0);
    let c1 = t[1] >> 51;
    t[1] &= MASK_51;
    t[2] = t[2].wrapping_add(c1);
    let c2 = t[2] >> 51;
    t[2] &= MASK_51;
    t[3] = t[3].wrapping_add(c2);
    let c3 = t[3] >> 51;
    t[3] &= MASK_51;
    t[4] = (t[4].wrapping_add(c3)) & MASK_51;

    let w0 = t[0] | (t[1] << 51);
    let w1 = (t[1] >> 13) | (t[2] << 38);
    let w2 = (t[2] >> 26) | (t[3] << 25);
    let w3 = (t[3] >> 39) | (t[4] << 12);

    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&w0.to_le_bytes());
    s[8..16].copy_from_slice(&w1.to_le_bytes());
    s[16..24].copy_from_slice(&w2.to_le_bytes());
    s[24..32].copy_from_slice(&w3.to_le_bytes());
    s
}

#[inline]
fn fe_add(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ]
}

#[inline]
fn fe_sub(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    // Add 2*p before subtraction to prevent unsigned underflow
    fe_carry([
        (a[0] + 0x000f_ffff_ffff_ffda) - b[0],
        (a[1] + 0x000f_ffff_ffff_fffe) - b[1],
        (a[2] + 0x000f_ffff_ffff_fffe) - b[2],
        (a[3] + 0x000f_ffff_ffff_fffe) - b[3],
        (a[4] + 0x000f_ffff_ffff_fffe) - b[4],
    ])
}

#[inline]
fn fe_mul(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;
    let b0 = b[0] as u128;
    let b1 = b[1] as u128;
    let b2 = b[2] as u128;
    let b3 = b[3] as u128;
    let b4 = b[4] as u128;

    let b1_19 = b1 * 19;
    let b2_19 = b2 * 19;
    let b3_19 = b3 * 19;
    let b4_19 = b4 * 19;

    let mut t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
    let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
    let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
    let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
    let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    let c0 = t0 >> 51;
    t0 &= MASK_51 as u128;
    t1 += c0;
    let c1 = t1 >> 51;
    t1 &= MASK_51 as u128;
    t2 += c1;
    let c2 = t2 >> 51;
    t2 &= MASK_51 as u128;
    t3 += c2;
    let c3 = t3 >> 51;
    t3 &= MASK_51 as u128;
    t4 += c3;
    let c4 = t4 >> 51;
    t4 &= MASK_51 as u128;
    t0 += c4 * 19;

    fe_carry([t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64])
}

#[inline]
fn fe_sq(a: &Fe25519) -> Fe25519 {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;

    let a0_2 = a0 * 2;
    let a1_2 = a1 * 2;
    let a1_38 = a1 * 38;
    let a2_38 = a2 * 38;
    let a3_19 = a3 * 19;
    let a3_38 = a3 * 38;
    let a4_19 = a4 * 19;

    let mut t0 = a0 * a0 + a1_38 * a4 + a2_38 * a3;
    let mut t1 = a0_2 * a1 + a2_38 * a4 + a3 * a3_19;
    let mut t2 = a0_2 * a2 + a1 * a1 + a3_38 * a4;
    let mut t3 = a0_2 * a3 + a1_2 * a2 + a4 * a4_19;
    let mut t4 = a0_2 * a4 + a1_2 * a3 + a2 * a2;

    let c0 = t0 >> 51;
    t0 &= MASK_51 as u128;
    t1 += c0;
    let c1 = t1 >> 51;
    t1 &= MASK_51 as u128;
    t2 += c1;
    let c2 = t2 >> 51;
    t2 &= MASK_51 as u128;
    t3 += c2;
    let c3 = t3 >> 51;
    t3 &= MASK_51 as u128;
    t4 += c3;
    let c4 = t4 >> 51;
    t4 &= MASK_51 as u128;
    t0 += c4 * 19;

    fe_carry([t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64])
}

#[inline]
fn fe_sq_n(a: &Fe25519, n: usize) -> Fe25519 {
    let mut r = fe_sq(a);
    for _ in 1..n {
        r = fe_sq(&r);
    }
    r
}

/// Invert `z` in $\mathbb{F}_{2^{255}-19}$ via the canonical Curve25519 addition chain for
/// $z^{p-2} \pmod p$ ($p - 2 = 2^{255} - 21$), requiring 254 squarings and only 11 multiplications.
fn fe_invert(z: &Fe25519) -> Fe25519 {
    let z2 = fe_sq(z); // z^2
    let t0 = fe_sq_n(&z2, 2); // z^8
    let z9 = fe_mul(&t0, z); // z^9
    let z11 = fe_mul(&z9, &z2); // z^11
    let t0 = fe_sq(&z11); // z^22
    let z_5_0 = fe_mul(&t0, &z9); // z^(2^5 - 1)

    let t0 = fe_sq_n(&z_5_0, 5);
    let z_10_0 = fe_mul(&t0, &z_5_0); // z^(2^10 - 1)

    let t0 = fe_sq_n(&z_10_0, 10);
    let z_20_0 = fe_mul(&t0, &z_10_0); // z^(2^20 - 1)

    let t0 = fe_sq_n(&z_20_0, 20);
    let t0 = fe_mul(&t0, &z_20_0); // z^(2^40 - 1)
    let t0 = fe_sq_n(&t0, 10);
    let z_50_0 = fe_mul(&t0, &z_10_0); // z^(2^50 - 1)

    let t0 = fe_sq_n(&z_50_0, 50);
    let z_100_0 = fe_mul(&t0, &z_50_0); // z^(2^100 - 1)

    let t0 = fe_sq_n(&z_100_0, 100);
    let t0 = fe_mul(&t0, &z_100_0); // z^(2^200 - 1)
    let t0 = fe_sq_n(&t0, 50);
    let t0 = fe_mul(&t0, &z_50_0); // z^(2^250 - 1)

    let t0 = fe_sq_n(&t0, 5); // z^(2^255 - 32)
    fe_mul(&t0, &z11) // z^(2^255 - 21)
}

#[inline]
fn cswap_fe(swap: u64, a: &mut Fe25519, b: &mut Fe25519) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let diff = (a[i] ^ b[i]) & mask;
        a[i] ^= diff;
        b[i] ^= diff;
    }
}

/// RFC 8032 §5.1.5: Derive the clamped 32-byte X25519 secret scalar from an Ed25519 32-byte seed.
pub fn ed25519_seed_to_x25519_scalar(seed: &[u8; 32]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA512, seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&digest.as_ref()[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

/// Birational map (`ssh-to-age` / RFC 8032) converting an Ed25519 public key (compressed Edwards $y$)
/// to its Curve25519 Montgomery $u$-coordinate: $u = (1 + y) \cdot (1 - y)^{-1} \pmod{2^{255} - 19}$.
pub fn ed25519_pub_to_x25519(ed_pub: &Ed25519Pub) -> [u8; 32] {
    let y = fe_from_bytes(ed_pub);
    let one = [1u64, 0, 0, 0, 0];
    let num = fe_add(&one, &y);
    let den = fe_sub(&one, &y);
    let inv_den = fe_invert(&den);
    let u = fe_mul(&num, &inv_den);
    fe_to_bytes(&u)
}

/// RFC 7748 constant-time X25519 Montgomery ladder scalar multiplication `X25519(k, u)`.
pub fn x25519_scalarmult(scalar: &[u8; 32], u_bytes: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x_1 = fe_from_bytes(u_bytes);
    let mut x_2: Fe25519 = [1, 0, 0, 0, 0];
    let mut z_2: Fe25519 = [0, 0, 0, 0, 0];
    let mut x_3: Fe25519 = x_1;
    let mut z_3: Fe25519 = [1, 0, 0, 0, 0];
    let a24: Fe25519 = [121665, 0, 0, 0, 0];
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let k_t = ((k[t >> 3] >> (t & 7)) & 1) as u64;
        swap ^= k_t;
        cswap_fe(swap, &mut x_2, &mut x_3);
        cswap_fe(swap, &mut z_2, &mut z_3);
        swap = k_t;

        let a = fe_add(&x_2, &z_2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x_2, &z_2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x_3, &z_3);
        let d = fe_sub(&x_3, &z_3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        let x3_sum = fe_add(&da, &cb);
        x_3 = fe_sq(&x3_sum);
        let z3_diff = fe_sub(&da, &cb);
        let z3_sq = fe_sq(&z3_diff);
        z_3 = fe_mul(&x_1, &z3_sq);
        x_2 = fe_mul(&aa, &bb);
        let a24_e = fe_mul(&a24, &e);
        let aa_plus_a24e = fe_add(&aa, &a24_e);
        z_2 = fe_mul(&e, &aa_plus_a24e);
    }

    cswap_fe(swap, &mut x_2, &mut x_3);
    cswap_fe(swap, &mut z_2, &mut z_3);
    k.zeroize();

    let inv_z2 = fe_invert(&z_2);
    let res = fe_mul(&x_2, &inv_z2);
    fe_to_bytes(&res)
}

/// Compute `X25519(scalar, 9)` (Curve25519 basepoint scalar multiplication).
pub fn x25519_basepoint(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519_scalarmult(scalar, &base)
}

fn derive_host_kek_ecdh(
    shared_secret: &[u8; 32],
    ephemeral_x25519_pub: &[u8; 32],
    recipient_x25519_pub: &[u8; 32],
) -> [u8; 32] {
    let mut hkdf_salt_bytes = [0u8; 64];
    hkdf_salt_bytes[..32].copy_from_slice(ephemeral_x25519_pub);
    hkdf_salt_bytes[32..].copy_from_slice(recipient_x25519_pub);
    let salt = Salt::new(HKDF_SHA256, &hkdf_salt_bytes);
    let prk = salt.extract(shared_secret);
    let info: [&[u8]; 1] = [b"epoch-age-x25519-kek-v1"];
    let okm = prk.expand(&info, HkdfLen32).expect("HKDF expand 32 bytes");
    let mut kek = [0u8; 32];
    okm.fill(&mut kek).expect("HKDF fill 32 bytes");
    kek
}

struct HkdfLen32;
impl ring::hkdf::KeyType for HkdfLen32 {
    fn len(&self) -> usize {
        32
    }
}

/// Seal a list of `SecretEntry` items into a hardware- and host-bound `SecretEnvelopeBundle`.
///
/// Uses the birational map $u = (1+y)/(1-y) \pmod{2^{255}-19}$ on `target_host_pub` (`Ed25519Pub`)
/// and ephemeral-static RFC 7748 X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 (`age` construction)
/// so only the holder of the target node's private key (or TPM 2.0 PCR state) can unseal the DEK.
pub fn seal_secret_bundle(
    node_id: &str,
    archetype_toplevel: &str,
    target_host_pub: &Ed25519Pub,
    tpm2_pcr_mask: Option<(u32, &Ed25519Identity, &[u8; 32])>,
    entries: &[SecretEntry],
) -> Result<SecretEnvelopeBundle, EpochError> {
    let rng = SystemRandom::new();
    let mut dek = [0u8; 32];
    let mut aead_nonce = [0u8; 12];
    let mut eph_scalar = [0u8; 32];
    let mut wrap_nonce = [0u8; 12];
    rng.fill(&mut dek)
        .and_then(|_| rng.fill(&mut aead_nonce))
        .and_then(|_| rng.fill(&mut eph_scalar))
        .and_then(|_| rng.fill(&mut wrap_nonce))
        .map_err(|_| EpochError::CryptoVerificationFailed("RNG failure".into()))?;

    // 1. Encrypt `cbor(entries)` with `ChaCha20-Poly1305(DEK, aead_nonce, AAD)`
    let aad_hash = compute_secret_aad(node_id, archetype_toplevel);
    let mut plaintext_cbor = cbor::to_vec_deterministic(&entries)?;
    let unbound_dek = UnboundKey::new(&CHACHA20_POLY1305, &dek)
        .map_err(|_| EpochError::CryptoVerificationFailed("AEAD key init failed".into()))?;
    let aead_key = LessSafeKey::new(unbound_dek);
    aead_key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(aead_nonce),
            aead::Aad::from(&aad_hash),
            &mut plaintext_cbor,
        )
        .map_err(|_| EpochError::CryptoVerificationFailed("AEAD seal failed".into()))?;

    // 2. Convert `target_host_pub` (Ed25519) -> Curve25519 via birational map and perform X25519 ECDH
    let recipient_x25519_pub = ed25519_pub_to_x25519(target_host_pub);
    let eph_x25519_pub = x25519_basepoint(&eph_scalar);
    let mut shared_secret = x25519_scalarmult(&eph_scalar, &recipient_x25519_pub);
    eph_scalar.zeroize();

    let mut kek = derive_host_kek_ecdh(&shared_secret, &eph_x25519_pub, &recipient_x25519_pub);
    shared_secret.zeroize();

    let unbound_kek = UnboundKey::new(&CHACHA20_POLY1305, &kek)
        .map_err(|_| EpochError::CryptoVerificationFailed("KEK init failed".into()))?;
    let kek_aead = LessSafeKey::new(unbound_kek);
    let mut wrapped_dek_ct = dek.to_vec();
    kek_aead
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(wrap_nonce),
            aead::Aad::from(&aad_hash),
            &mut wrapped_dek_ct,
        )
        .map_err(|_| EpochError::CryptoVerificationFailed("KEK seal failed".into()))?;
    kek.zeroize();

    // Format `age_x25519_wrapped_dek`: [32-byte eph_x25519_pub || 12-byte nonce || 48-byte ciphertext+tag]
    let mut age_x25519_wrapped_dek = Vec::with_capacity(32 + 12 + wrapped_dek_ct.len());
    age_x25519_wrapped_dek.extend_from_slice(&eph_x25519_pub);
    age_x25519_wrapped_dek.extend_from_slice(&wrap_nonce);
    age_x25519_wrapped_dek.extend_from_slice(&wrapped_dek_ct);

    // 3. Optional TPM 2.0 PCR-policy sealed blob (`TPM2_PolicyPCR` + `TPM2_PolicyAuthorize`)
    let tpm2_sealed_dek =
        if let Some((pcr_mask, policy_authority_key, pcr_composite_digest)) = tpm2_pcr_mask {
            let policy_msg = (pcr_mask, pcr_composite_digest);
            let policy_sig =
                policy_authority_key.sign_domain_cbor(b"epoch-tpm2-pcr-policy-v1", &policy_msg)?;
            let mut tpm_kek_hasher = blake3::Hasher::new();
            tpm_kek_hasher.update(b"epoch-tpm2-srk-seal-v1");
            tpm_kek_hasher.update(&pcr_mask.to_be_bytes());
            tpm_kek_hasher.update(pcr_composite_digest);
            tpm_kek_hasher.update(&policy_authority_key.public_key);
            let mut tpm_kek = *tpm_kek_hasher.finalize().as_bytes();

            let mut tpm_nonce = [0u8; 12];
            rng.fill(&mut tpm_nonce)
                .map_err(|_| EpochError::CryptoVerificationFailed("RNG failure".into()))?;
            let unbound_tpm = UnboundKey::new(&CHACHA20_POLY1305, &tpm_kek)
                .map_err(|_| EpochError::CryptoVerificationFailed("TPM KEK init failed".into()))?;
            let tpm_aead = LessSafeKey::new(unbound_tpm);
            let mut tpm_priv = dek.to_vec();
            tpm_aead
                .seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(tpm_nonce),
                    aead::Aad::from(&aad_hash),
                    &mut tpm_priv,
                )
                .map_err(|_| EpochError::CryptoVerificationFailed("TPM seal failed".into()))?;
            tpm_kek.zeroize();

            let mut tpm2b_private = Vec::with_capacity(12 + tpm_priv.len());
            tpm2b_private.extend_from_slice(&tpm_nonce);
            tpm2b_private.extend_from_slice(&tpm_priv);

            let mut tpm2b_public = Vec::with_capacity(64);
            tpm2b_public.extend_from_slice(&policy_authority_key.public_key);
            tpm2b_public.extend_from_slice(pcr_composite_digest);

            Some(Tpm2SealedBlob {
                pcr_mask,
                policy_authorize_sig: Some(policy_sig),
                tpm2b_private,
                tpm2b_public,
            })
        } else {
            None
        };

    dek.zeroize();

    Ok(SecretEnvelopeBundle {
        version: 1,
        node_id: node_id.to_owned(),
        archetype_toplevel: archetype_toplevel.to_owned(),
        age_x25519_wrapped_dek,
        tpm2_sealed_dek,
        aead_nonce,
        aead_ciphertext: plaintext_cbor,
    })
}

/// Unseal a `SecretEnvelopeBundle` verifying AAD binding (`node_id` and `archetype_toplevel`)
/// using either the TPM 2.0 PCR policy or the target node's private `Ed25519Identity` key.
pub fn unseal_secret_bundle(
    bundle: &SecretEnvelopeBundle,
    expected_node_id: &str,
    expected_archetype_toplevel: &str,
    host_key: &Ed25519Identity,
    tpm2_pcr_state: Option<(u32, &[u8; 32])>,
) -> Result<Vec<SecretEntry>, EpochError> {
    if bundle.node_id != expected_node_id {
        return Err(EpochError::SecretUnsealFailed {
            node_id: expected_node_id.to_owned(),
            reason: format!(
                "envelope node_id '{}' != expected '{}'",
                bundle.node_id, expected_node_id
            ),
        });
    }
    if bundle.archetype_toplevel != expected_archetype_toplevel {
        return Err(EpochError::SecretUnsealFailed {
            node_id: expected_node_id.to_owned(),
            reason: format!(
                "envelope archetype_toplevel '{}' != expected '{}'",
                bundle.archetype_toplevel, expected_archetype_toplevel
            ),
        });
    }

    let aad_hash = compute_secret_aad(expected_node_id, expected_archetype_toplevel);

    // Try TPM 2.0 unsealing first if a TPM2 blob and PCR state are provided
    let mut dek = [0u8; 32];
    let mut unsealed_via_tpm = false;

    if let (Some(tpm_blob), Some((active_pcr_mask, active_pcr_digest))) =
        (&bundle.tpm2_sealed_dek, tpm2_pcr_state)
    {
        if tpm_blob.pcr_mask != active_pcr_mask {
            return Err(EpochError::SecretUnsealFailed {
                node_id: expected_node_id.to_owned(),
                reason: format!(
                    "TPM2 PCR mask mismatch: policy requires {:#x}, active {:#x}",
                    tpm_blob.pcr_mask, active_pcr_mask
                ),
            });
        }
        if tpm_blob.tpm2b_public.len() != 64 || tpm_blob.tpm2b_private.len() < 12 + 32 + 16 {
            return Err(EpochError::SecretUnsealFailed {
                node_id: expected_node_id.to_owned(),
                reason: "malformed TPM2B_PUBLIC / TPM2B_PRIVATE blob".into(),
            });
        }
        let mut authority_pub = [0u8; 32];
        authority_pub.copy_from_slice(&tpm_blob.tpm2b_public[..32]);
        let policy_sig =
            tpm_blob
                .policy_authorize_sig
                .ok_or_else(|| EpochError::SecretUnsealFailed {
                    node_id: expected_node_id.to_owned(),
                    reason: "missing TPM2_PolicyAuthorize signature".into(),
                })?;
        let policy_msg = (tpm_blob.pcr_mask, active_pcr_digest);
        verify_domain_cbor(
            &authority_pub,
            b"epoch-tpm2-pcr-policy-v1",
            &policy_msg,
            &policy_sig,
        )
        .map_err(|_| EpochError::SecretUnsealFailed {
            node_id: expected_node_id.to_owned(),
            reason: "TPM2 PCR policy signature or PCR digest mismatch".into(),
        })?;

        let mut tpm_kek_hasher = blake3::Hasher::new();
        tpm_kek_hasher.update(b"epoch-tpm2-srk-seal-v1");
        tpm_kek_hasher.update(&tpm_blob.pcr_mask.to_be_bytes());
        tpm_kek_hasher.update(active_pcr_digest);
        tpm_kek_hasher.update(&authority_pub);
        let mut tpm_kek = *tpm_kek_hasher.finalize().as_bytes();

        let mut tpm_nonce = [0u8; 12];
        tpm_nonce.copy_from_slice(&tpm_blob.tpm2b_private[..12]);
        let mut ct = tpm_blob.tpm2b_private[12..].to_vec();

        let unbound_tpm = UnboundKey::new(&CHACHA20_POLY1305, &tpm_kek).map_err(|_| {
            EpochError::SecretUnsealFailed {
                node_id: expected_node_id.to_owned(),
                reason: "TPM2 KEK init failed".into(),
            }
        })?;
        let tpm_aead = LessSafeKey::new(unbound_tpm);
        let plain_dek = tpm_aead
            .open_in_place(
                Nonce::assume_unique_for_key(tpm_nonce),
                aead::Aad::from(&aad_hash),
                &mut ct,
            )
            .map_err(|_| EpochError::SecretUnsealFailed {
                node_id: expected_node_id.to_owned(),
                reason: "TPM2 DEK unseal authentication failed".into(),
            })?;
        tpm_kek.zeroize();
        dek.copy_from_slice(&plain_dek[..32]);
        ct.zeroize();
        unsealed_via_tpm = true;
    }

    if !unsealed_via_tpm {
        if bundle.age_x25519_wrapped_dek.len() < 32 + 12 + 32 + 16 {
            return Err(EpochError::SecretUnsealFailed {
                node_id: expected_node_id.to_owned(),
                reason: "truncated age_x25519_wrapped_dek".into(),
            });
        }
        let mut eph_x25519_pub = [0u8; 32];
        eph_x25519_pub.copy_from_slice(&bundle.age_x25519_wrapped_dek[..32]);
        let mut wrap_nonce = [0u8; 12];
        wrap_nonce.copy_from_slice(&bundle.age_x25519_wrapped_dek[32..44]);
        let mut wrapped_ct = bundle.age_x25519_wrapped_dek[44..].to_vec();

        let mut shared_secret = x25519_scalarmult(host_key.x25519_scalar(), &eph_x25519_pub);

        let mut kek = derive_host_kek_ecdh(&shared_secret, &eph_x25519_pub, host_key.x25519_pub());
        shared_secret.zeroize();

        let unbound_kek = UnboundKey::new(&CHACHA20_POLY1305, &kek).map_err(|_| {
            EpochError::SecretUnsealFailed {
                node_id: expected_node_id.to_owned(),
                reason: "KEK init failed".into(),
            }
        })?;
        let kek_aead = LessSafeKey::new(unbound_kek);
        let plain_dek = kek_aead
            .open_in_place(
                Nonce::assume_unique_for_key(wrap_nonce),
                aead::Aad::from(&aad_hash),
                &mut wrapped_ct,
            )
            .map_err(|_| EpochError::SecretUnsealFailed {
                node_id: expected_node_id.to_owned(),
                reason: "host identity DEK unwrap authentication failed".into(),
            })?;
        kek.zeroize();
        dek.copy_from_slice(&plain_dek[..32]);
        wrapped_ct.zeroize();
    }

    // Decrypt the inner `aead_ciphertext` using `dek` and `aad_hash`
    let unbound_dek =
        UnboundKey::new(&CHACHA20_POLY1305, &dek).map_err(|_| EpochError::SecretUnsealFailed {
            node_id: expected_node_id.to_owned(),
            reason: "DEK init failed".into(),
        })?;
    dek.zeroize();
    let aead_key = LessSafeKey::new(unbound_dek);
    let mut ct_buf = bundle.aead_ciphertext.clone();
    let plain_cbor = aead_key
        .open_in_place(
            Nonce::assume_unique_for_key(bundle.aead_nonce),
            aead::Aad::from(&aad_hash),
            &mut ct_buf,
        )
        .map_err(|_| EpochError::SecretUnsealFailed {
            node_id: expected_node_id.to_owned(),
            reason: "ChaCha20-Poly1305 AAD/tag verification failed on secret bundle".into(),
        })?;

    let entries: Vec<SecretEntry> =
        cbor::from_slice(plain_cbor).map_err(|e| EpochError::SecretUnsealFailed {
            node_id: expected_node_id.to_owned(),
            reason: format!("CBOR decode of decrypted secrets failed: {e}"),
        })?;
    ct_buf.zeroize();
    Ok(entries)
}

// Plane 4: Keyed BLAKE3 MAC for Crash-Safe Persistent State (`state.cbor`)

pub fn compute_state_mac(
    state: &PersistentAgentState,
    mac_key: &[u8; 32],
) -> Result<Blake3Hash, EpochError> {
    let tuple = (
        state.highest_tx_epoch,
        state.phase,
        &state.active_wave_id,
        &state.prev_toplevel,
        state.prev_secret_epoch,
        &state.staged_toplevel,
        state.lease_deadline_boottime_ns,
        state.reboot_deadline_wall_utc_s,
    );
    let bytes = cbor::to_vec_deterministic(&tuple)?;
    Ok(*blake3::keyed_hash(mac_key, &bytes).as_bytes())
}

pub fn verify_state_mac(
    state: &PersistentAgentState,
    mac_key: &[u8; 32],
) -> Result<(), EpochError> {
    let expected = compute_state_mac(state, mac_key)?;
    if expected != state.state_blake3_mac {
        return Err(EpochError::CryptoVerificationFailed(
            "state.cbor keyed BLAKE3 MAC verification failed".into(),
        ));
    }
    Ok(())
}

/// Cryptographically zero-wipe a buffer in memory using `libc::explicit_bzero` and `zeroize`.
pub fn explicit_zero_bytes(buf: &mut [u8]) {
    if !buf.is_empty() {
        unsafe {
            libc::explicit_bzero(buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        }
    }
    buf.zeroize();
}

/// Overwrite a secret file's page-cache contents with `0x00` bytes, `fsync`, and `unlink`.
pub fn zero_wipe_and_unlink_file(path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.is_file() {
            let len = meta.len() as usize;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Secret files are created with mode `0400` (`r--------`); grant owner write
                // (`0600`) before opening for in-place `0x00` page-cache zeroization.
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            let mut file = OpenOptions::new().write(true).open(path)?;
            let mut zeros = vec![0u8; len.clamp(64, 65536)];
            let mut remaining = len;
            while remaining > 0 {
                let chunk = remaining.min(zeros.len());
                file.write_all(&zeros[..chunk])?;
                remaining -= chunk;
            }
            file.sync_all()?;
            explicit_zero_bytes(&mut zeros);
        }
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub fn sha256_digest(data: &[u8]) -> Sha256Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
