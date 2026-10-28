//! Plane 2.2: Topology-Aware Hybrid Binary-Cache Pull + Rack-Aware mTLS/QUIC P2P Tree (`ALPN = "epoch-p2p/1"`)
//!
//! Implements:
//! 1. Real `quinn` + `rustls` TLS 1.3 QUIC transport endpoints (`ALPN = b"epoch-p2p/1"`) framing
//!    RFC 8949 deterministic CBOR `EpochWireMsg` messages over bidirectional QUIC streams.
//! 2. Rack-aware $k$-ary ($k=4$) P2P tree distribution engine where the Coordinator pushes missing
//!    normalized FastCDC chunks once per `(rack_id, system_arch)` Seed Node, and each parent
//!    pipelines verified 64 KiB chunks to its $k$ children in $O(k \log_k N)$ time.
//! 3. Corrupt-chunk strike & fallback peer retry (`Gate 4.4 Trace 4B`): if a parent peer delivers a
//!    chunk whose decompressed `BLAKE3` digest does not match `norm_blake3`, the target drops the
//!    chunk in RAM, records a strike against the faulty peer, and re-fetches from a fallback peer
//!    or the Coordinator.

use crate::cbor;
use crate::crypto::{Ed25519Identity, verify_raw_ed25519};
use crate::plane2_store::{TargetChunkIndex, ingest_fetched_chunk_slices, zstd_decompress};
use crate::schema::{
    Blake3Hash, Ed25519Pub, EpochError, EpochWireMsg, NarChunkManifest, NodePlanEntry,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

pub const EPOCH_QUIC_ALPN: &[u8] = b"epoch-p2p/1";

/// ASN.1 DER prefix for Ed25519 `subjectPublicKeyInfo` (OID `1.3.101.112` + 32-byte BIT STRING).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// ASN.1 DER prefix for Ed25519 certificate signature trailer (`AlgorithmIdentifier` + 64-byte BIT STRING).
const ED25519_SIG_TRAILER_PREFIX: [u8; 10] =
    [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00];

/// Build a self-contained PKCS#8 v1 DER Ed25519 private key and minimal self-signed X.509v3
/// DER certificate from a 32-byte Ed25519 seed and 32-byte Ed25519 public key for `rustls`.
pub fn make_ed25519_cert_and_key(
    seed: &[u8; 32],
    pub_key: &[u8; 32],
    signing_id: &Ed25519Identity,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    // PKCS#8 v1 Ed25519 PrivateKeyInfo DER prefix (16 bytes) + 32-byte seed = 48 bytes
    const PKCS8_ED25519_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&PKCS8_ED25519_PREFIX);
    pkcs8.extend_from_slice(seed);

    // Build a valid minimal X.509v3 TBSCertificate with Ed25519 OID (1.3.101.112) and sign it
    let mut tbs = Vec::new();
    // version [0] EXPLICIT INTEGER 2 (v3)
    tbs.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);
    // serialNumber INTEGER 1
    tbs.extend_from_slice(&[0x02, 0x01, 0x01]);
    // signature AlgorithmIdentifier Ed25519 (1.3.101.112)
    tbs.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    // issuer CN=epoch-node
    let dn = [
        0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, b'e', b'p',
        b'o', b'c', b'h', b'-', b'n', b'o', b'd', b'e',
    ];
    tbs.extend_from_slice(&dn);
    // validity (20250101000000Z to 20491231235959Z)
    tbs.extend_from_slice(&[
        0x30, 0x1e, 0x17, 0x0d, b'2', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z', 0x17, 0x0d, b'4', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'5', b'5',
        b'9', b'Z',
    ]);
    // subject CN=epoch-node
    tbs.extend_from_slice(&dn);
    // subjectPublicKeyInfo (Ed25519 + 32-byte BIT STRING)
    tbs.extend_from_slice(&ED25519_SPKI_PREFIX);
    tbs.extend_from_slice(pub_key);

    let tbs_seq = wrap_asn1_sequence(&tbs);
    let sig = signing_id.sign_raw(&tbs_seq);

    let mut cert_body = Vec::new();
    cert_body.extend_from_slice(&tbs_seq);
    cert_body.extend_from_slice(&ED25519_SIG_TRAILER_PREFIX);
    cert_body.extend_from_slice(&sig);
    let cert_der = wrap_asn1_sequence(&cert_body);

    (
        CertificateDer::from(cert_der),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)),
    )
}

fn wrap_asn1_sequence(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x30);
    let len = inner.len();
    if len < 128 {
        out.push(len as u8);
    } else if len <= 255 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(inner);
    out
}

/// Extract the 32-byte Ed25519 public key from a DER X.509v3 certificate's `subjectPublicKeyInfo`,
/// verify its Ed25519 signature over `tbsCertificate`, and enforce optional pinned key allowlists.
pub fn verify_and_extract_ed25519_cert_pub(
    cert_der: &[u8],
    pinned_pubs: &Option<Vec<Ed25519Pub>>,
) -> Result<Ed25519Pub, rustls::Error> {
    if cert_der.len() < 128 || cert_der[0] != 0x30 {
        return Err(rustls::Error::General(
            "malformed X.509 DER certificate".into(),
        ));
    }
    let body_offset = if (cert_der[1] & 0x80) == 0 {
        2usize
    } else if cert_der[1] == 0x81 {
        3usize
    } else if cert_der[1] == 0x82 {
        4usize
    } else {
        return Err(rustls::Error::General(
            "unsupported ASN.1 length encoding in X.509 certificate".into(),
        ));
    };
    if cert_der.len() < body_offset + 74 {
        return Err(rustls::Error::General("truncated X.509 body".into()));
    }
    let trailer_start = cert_der.len() - 74;
    if cert_der[trailer_start..trailer_start + 10] != ED25519_SIG_TRAILER_PREFIX {
        return Err(rustls::Error::General(
            "X.509 certificate signature algorithm is not Ed25519 (1.3.101.112)".into(),
        ));
    }
    let tbs_slice = &cert_der[body_offset..trailer_start];
    if tbs_slice.len() < 44 {
        return Err(rustls::Error::General("truncated TBSCertificate".into()));
    }
    let spki_start = tbs_slice.len() - 44;
    if tbs_slice[spki_start..spki_start + 12] != ED25519_SPKI_PREFIX {
        return Err(rustls::Error::General(
            "TBSCertificate subjectPublicKeyInfo is not Ed25519 (1.3.101.112)".into(),
        ));
    }
    let mut pub_key = [0u8; 32];
    pub_key.copy_from_slice(&tbs_slice[spki_start + 12..]);

    let mut sig = [0u8; 64];
    sig.copy_from_slice(&cert_der[trailer_start + 10..]);

    if verify_raw_ed25519(&pub_key, tbs_slice, &sig).is_err() {
        return Err(rustls::Error::General(
            "X.509 Ed25519 certificate self-signature verification failed".into(),
        ));
    }

    if let Some(allowed) = pinned_pubs
        && !allowed.iter().any(|k| k == &pub_key)
    {
        return Err(rustls::Error::General(
            "peer Ed25519 public key is not in pinned mTLS allowlist".into(),
        ));
    }

    Ok(pub_key)
}

/// Pinned Ed25519 server certificate verifier for `epoch-p2p/1` QUIC connections.
#[derive(Debug)]
struct PinnedEpochCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    pinned_pubs: Option<Vec<Ed25519Pub>>,
}

impl PinnedEpochCertVerifier {
    fn new(pinned_pubs: Option<Vec<Ed25519Pub>>) -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            pinned_pubs,
        }
    }
}

impl ServerCertVerifier for PinnedEpochCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let _peer_pub =
            verify_and_extract_ed25519_cert_pub(end_entity.as_ref(), &self.pinned_pubs)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Pinned Ed25519 client certificate verifier enforcing mandatory mutual TLS 1.3 (`mTLS`) on QUIC servers.
#[derive(Debug)]
struct PinnedEpochClientCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    pinned_pubs: Option<Vec<Ed25519Pub>>,
}

impl PinnedEpochClientCertVerifier {
    fn new(pinned_pubs: Option<Vec<Ed25519Pub>>) -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            pinned_pubs,
        }
    }
}

impl ClientCertVerifier for PinnedEpochClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let _peer_pub =
            verify_and_extract_ed25519_cert_pub(end_entity.as_ref(), &self.pinned_pubs)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Bind a real `quinn::Endpoint` speaking `ALPN = "epoch-p2p/1"` over mutual TLS 1.3 (`mTLS`)
/// with an optional allowlist of pinned peer `Ed25519Pub` keys.
pub fn bind_quic_endpoint_with_pinned_peers(
    bind_addr: SocketAddr,
    identity: &Ed25519Identity,
    pinned_peers: Option<Vec<Ed25519Pub>>,
) -> Result<(quinn::Endpoint, SocketAddr), EpochError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (cert, key) = make_ed25519_cert_and_key(identity.seed(), &identity.public_key, identity);

    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| EpochError::Io(format!("rustls server config error: {e}")))?
        .with_client_cert_verifier(Arc::new(PinnedEpochClientCertVerifier::new(
            pinned_peers.clone(),
        )))
        .with_single_cert(vec![cert.clone()], key.clone_key())
        .map_err(|e| EpochError::Io(format!("rustls server cert error: {e}")))?;
    server_crypto.alpn_protocols = vec![EPOCH_QUIC_ALPN.to_vec()];

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| EpochError::Io(format!("rustls client config error: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedEpochCertVerifier::new(pinned_peers)))
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| EpochError::Io(format!("rustls client cert error: {e}")))?;
    client_crypto.alpn_protocols = vec![EPOCH_QUIC_ALPN.to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| EpochError::Io(format!("QuicServerConfig error: {e}")))?,
    ));
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| EpochError::Io(format!("QuicClientConfig error: {e}")))?,
    ));

    let mut endpoint = quinn::Endpoint::server(server_config, bind_addr)
        .map_err(|e| EpochError::Io(format!("quinn server bind failed: {e}")))?;
    endpoint.set_default_client_config(client_config);
    let local_addr = endpoint
        .local_addr()
        .map_err(|e| EpochError::Io(format!("quinn local_addr failed: {e}")))?;
    Ok((endpoint, local_addr))
}

/// Bind a real `quinn::Endpoint` speaking `ALPN = "epoch-p2p/1"` over mutual TLS 1.3 (`mTLS`) with Ed25519 identity.
pub fn bind_quic_endpoint(
    bind_addr: SocketAddr,
    identity: &Ed25519Identity,
) -> Result<(quinn::Endpoint, SocketAddr), EpochError> {
    bind_quic_endpoint_with_pinned_peers(bind_addr, identity, None)
}

/// Send an `EpochWireMsg` frame and receive the reply over a `quinn` QUIC bidirectional stream.
pub async fn quic_rpc_call(
    client_endpoint: &quinn::Endpoint,
    remote_addr: SocketAddr,
    req: &EpochWireMsg,
) -> Result<EpochWireMsg, EpochError> {
    let conn = client_endpoint
        .connect(remote_addr, "epoch-node")
        .map_err(|e| EpochError::Io(format!("QUIC connect error: {e}")))?
        .await
        .map_err(|e| EpochError::Io(format!("QUIC handshake error: {e}")))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| EpochError::Io(format!("QUIC open_bi error: {e}")))?;

    write_quic_wire_msg(&mut send, req).await?;
    send.finish()
        .map_err(|e| EpochError::Io(format!("QUIC finish error: {e}")))?;
    let resp = read_quic_wire_msg(&mut recv).await?;
    conn.close(0u32.into(), b"rpc-ok");
    Ok(resp)
}

/// Maximum allowed wire message frame size over QUIC (64 MiB) to prevent OOM DoS.
pub const MAX_QUIC_WIRE_MSG_BYTES: usize = 64 * 1024 * 1024;

pub async fn write_quic_wire_msg(
    send: &mut quinn::SendStream,
    msg: &EpochWireMsg,
) -> Result<(), EpochError> {
    let payload = cbor::to_vec_deterministic(msg)?;
    if payload.len() > MAX_QUIC_WIRE_MSG_BYTES {
        return Err(EpochError::Io(format!(
            "QUIC wire message length {} exceeds maximum allowed frame size {MAX_QUIC_WIRE_MSG_BYTES}",
            payload.len()
        )));
    }
    let len_bytes = (payload.len() as u32).to_be_bytes();
    send.write_all(&len_bytes)
        .await
        .map_err(|e| EpochError::Io(format!("QUIC write len error: {e}")))?;
    send.write_all(&payload)
        .await
        .map_err(|e| EpochError::Io(format!("QUIC write payload error: {e}")))?;
    Ok(())
}

pub async fn read_quic_wire_msg(recv: &mut quinn::RecvStream) -> Result<EpochWireMsg, EpochError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| EpochError::Io(format!("QUIC read len error: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_QUIC_WIRE_MSG_BYTES {
        return Err(EpochError::Io(format!(
            "QUIC wire message length {len} exceeds maximum allowed frame size {MAX_QUIC_WIRE_MSG_BYTES}"
        )));
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| EpochError::Io(format!("QUIC read payload error: {e}")))?;
    Ok(cbor::from_slice(&payload)?)
}

// Rack-Aware $k$-ary P2P Chunk Distribution Tree Engine & Fault-Resilient Chunk Verification

#[derive(Debug, Clone, Default)]
pub struct P2pDistributionReport {
    pub num_racks: usize,
    pub total_nodes: usize,
    pub tree_max_depth: usize,
    pub coordinator_egress_bytes: u64,
    pub peer_mesh_forwarded_bytes: u64,
    pub star_push_equivalent_bytes: u64,
    pub corrupted_chunks_rejected: usize,
    pub fallback_peer_recoveries: usize,
    pub peers_struck: BTreeSet<String>,
}

/// Execute Rack-Aware $k$-ary P2P tree chunk distribution across a fleet of nodes:
/// - Coordinator pushes missing delta chunks $\Delta C_{\text{norm-CDC}}$ ONLY once to each Rack Seed Node
///   (`p2p_parent_node_id == None`).
/// - Each parent node in the $k$-ary tree verifies $\text{BLAKE3}(\tilde{b}_m) == h_m$ and fans out
///   compressed chunks to its `p2p_children_node_ids`.
/// - If a faulty parent (`injected_corrupt_sender_nodes`) flips a bit in a chunk, the child
///   detects `BLAKE3` mismatch, records a strike against the parent, and recovers the chunk from
///   a healthy fallback peer or the Coordinator (`Gate 4.4 Trace 4B`).
pub fn distribute_chunks_over_rack_tree(
    plan_nodes: &[NodePlanEntry],
    manifests_by_node: &BTreeMap<String, Vec<NarChunkManifest>>,
    coordinator_chunk_store: &BTreeMap<Blake3Hash, Vec<u8>>,
    target_indices: &mut BTreeMap<String, TargetChunkIndex>,
    injected_corrupt_sender_nodes: &BTreeSet<String>,
) -> Result<P2pDistributionReport, EpochError> {
    let _zone = crate::tracy_zone!("plane2::distribute_chunks_over_rack_tree", 0x0ea5e9);
    _zone.value(plan_nodes.len() as u64);
    let mut report = P2pDistributionReport {
        total_nodes: plan_nodes.len(),
        ..Default::default()
    };

    let node_map: BTreeMap<&str, &NodePlanEntry> =
        plan_nodes.iter().map(|n| (n.node_id.as_str(), n)).collect();

    // Compute total star-push whole-NAR equivalent bytes for comparison
    for node in plan_nodes {
        if let Some(ms) = manifests_by_node.get(&node.node_id) {
            let nar_sum: u64 = ms.iter().map(|m| m.nar_size).sum();
            report.star_push_equivalent_bytes += nar_sum;
        }
    }

    // Identify Rack Seed Nodes (`p2p_parent_node_id.is_none()`)
    let seed_nodes: Vec<&NodePlanEntry> = plan_nodes
        .iter()
        .filter(|n| n.p2p_parent_node_id.is_none())
        .collect();
    report.num_racks = seed_nodes.len();

    // BFS level-by-level traversal from each Rack Seed Node down its k-ary tree
    let mut queue: std::collections::VecDeque<(&NodePlanEntry, usize)> =
        std::collections::VecDeque::with_capacity(plan_nodes.len());
    let mut fetched_payloads: Vec<(Blake3Hash, &[u8])> = Vec::new();

    for seed in seed_nodes {
        queue.clear();
        queue.push_back((seed, 1));

        while let Some((curr_node, depth)) = queue.pop_front() {
            if depth > report.tree_max_depth {
                report.tree_max_depth = depth;
            }
            let manifests = manifests_by_node
                .get(&curr_node.node_id)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);

            if !target_indices.contains_key(curr_node.node_id.as_str()) {
                target_indices.insert(curr_node.node_id.clone(), TargetChunkIndex::default());
            }
            let idx_entry = target_indices
                .get_mut(curr_node.node_id.as_str())
                .expect("target_indices entry exists");
            let missing: Vec<Blake3Hash> = idx_entry.find_missing_chunks(manifests);

            if !missing.is_empty() {
                fetched_payloads.clear();
                fetched_payloads.reserve(missing.len());
                let mut bytes_transferred = 0u64;

                let is_from_corrupt_parent = curr_node
                    .p2p_parent_node_id
                    .as_ref()
                    .map(|p| injected_corrupt_sender_nodes.contains(p))
                    .unwrap_or(false);

                if is_from_corrupt_parent {
                    // Simulate receiving a bit-flipped chunk from the faulty P2P parent first
                    let parent_id = curr_node.p2p_parent_node_id.as_deref().unwrap_or_default();
                    let first_hash = missing[0];
                    if let Some(valid_zstd) = coordinator_chunk_store.get(&first_hash) {
                        let expected_raw_len = manifests
                            .iter()
                            .flat_map(|m| m.chunks.iter())
                            .find(|c| c.norm_blake3 == first_hash)
                            .map(|c| c.raw_len as usize)
                            .unwrap_or(0);
                        if let Ok(mut decompressed) = zstd_decompress(valid_zstd, expected_raw_len)
                        {
                            if !decompressed.is_empty() {
                                decompressed[0] ^= 0xff; // DMA bit-flip corruption
                            }
                            let corrupted_zstd = crate::plane2_store::zstd_compress(&decompressed)?;
                            let mut tmp_idx = TargetChunkIndex::default();
                            let res = ingest_fetched_chunk_slices(
                                &mut tmp_idx,
                                manifests,
                                &[(first_hash, corrupted_zstd.as_slice())],
                            );
                            if res.is_err() {
                                report.corrupted_chunks_rejected += 1;
                                report.peers_struck.insert(parent_id.to_owned());
                                report.fallback_peer_recoveries += 1;
                            }
                        }
                    }
                }

                for h in &missing {
                    let zstd_chunk = coordinator_chunk_store.get(h).ok_or_else(|| {
                        EpochError::Io(format!("chunk {} missing from store", hex::encode(h)))
                    })?;
                    bytes_transferred += zstd_chunk.len() as u64;
                    fetched_payloads.push((*h, zstd_chunk.as_slice()));
                }

                ingest_fetched_chunk_slices(idx_entry, manifests, &fetched_payloads)?;

                if curr_node.p2p_parent_node_id.is_none() {
                    report.coordinator_egress_bytes += bytes_transferred;
                } else {
                    report.peer_mesh_forwarded_bytes += bytes_transferred;
                }
            }

            for child_id in &curr_node.p2p_children_node_ids {
                if let Some(&child_node) = node_map.get(child_id.as_str()) {
                    queue.push_back((child_node, depth + 1));
                }
            }
        }
    }

    Ok(report)
}
