//! Comprehensive Integration, Property, & Adversarial Fault-Injection Test Suite for `EPOCH`.

use epoch::cbor;
use epoch::crypto::{
    Ed25519Identity, seal_secret_bundle, sign_activate_wave, sign_health_attestation,
    unseal_secret_bundle, verify_activate_wave, verify_health_attestation,
};
use epoch::fault_matrix::{
    run_all_gate4_fault_scenarios, verify_scenario_1_coordinator_crash_mid_dag,
    verify_scenario_2_asymmetric_partitions, verify_scenario_3_broken_kernel_initrd_panic,
    verify_scenario_4_corruption_and_enospc, verify_scenario_5_canary_failure_coupled_wave,
};
use epoch::p2p_quic::{bind_quic_endpoint, quic_rpc_call, read_quic_wire_msg, write_quic_wire_msg};
use epoch::plane1_eval::{
    EvalCache, NodeOverlaySpec, WorkerPoolConfig, compile_p2p_spanning_tree,
    evaluate_nodes_preforked, validate_and_toposort_waves,
};
use epoch::plane2_store::{
    build_nar_chunk_manifest, denormalize_nar_store_hashes, extract_store_hash_32,
    normalize_nar_store_hashes, serialize_nar, unpack_nar,
};
use epoch::plane3_secrets::{
    atomic_flip_current_secrets, prepare_generation_secrets_from_bundle,
    zero_wipe_secret_generation,
};
use epoch::schema::{
    EpochError, EpochWireMsg, HealthOracleSpec, NodePlanEntry, QuorumGroupSpec, SecretEntry,
    WaveSpec,
};
use std::collections::BTreeMap;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_rfc8949_deterministic_cbor_canonical_map_ordering_and_roundtrip() {
    let mut map_a = BTreeMap::new();
    map_a.insert("zeta".to_owned(), 1u64);
    map_a.insert("alpha".to_owned(), 2u64);
    map_a.insert("beta".to_owned(), 3u64);

    let bytes_a = cbor::to_vec_deterministic(&map_a).expect("CBOR encode");
    let decoded: BTreeMap<String, u64> = cbor::from_slice(&bytes_a).expect("CBOR decode");
    assert_eq!(map_a, decoded);

    // Verify RFC 8949 §4.2.1 canonical key sorting: shorter encoded text strings sort before longer ones
    // ("alpha" len 5, "beta" len 4, "zeta" len 4 -> "beta", "zeta", "alpha")
    let pos_beta = bytes_a.windows(4).position(|w| w == b"beta").unwrap();
    let pos_zeta = bytes_a.windows(4).position(|w| w == b"zeta").unwrap();
    let pos_alpha = bytes_a.windows(5).position(|w| w == b"alpha").unwrap();
    assert!(pos_beta < pos_zeta && pos_zeta < pos_alpha);

    // Verify trailing bytes are rejected
    let mut with_trailing = bytes_a.clone();
    with_trailing.push(0x00);
    assert!(cbor::from_slice::<BTreeMap<String, u64>>(&with_trailing).is_err());
}

#[test]
fn test_plane1_dag_toposort_and_quorum_safety_invariants() {
    // 1. Valid causal DAG and valid quorum (maxUnavailable = 1 <= floor((3-1)/2) = 1)
    let quorums = vec![QuorumGroupSpec {
        quorum_id: "etcd".into(),
        members: vec!["db-1".into(), "db-2".into(), "db-3".into()],
        max_unavailable: 1,
    }];
    let waves = vec![
        WaveSpec {
            wave_id: "api".into(),
            depends_on: vec!["db-wave-2".into()],
            node_ids: vec!["api-1".into()],
            max_unavailable: 0,
            lease_ttl_ms: 30_000,
            reboot_lease_ttl_ms: 120_000,
            probes: HealthOracleSpec::default(),
        },
        WaveSpec {
            wave_id: "db-wave-1".into(),
            depends_on: vec![],
            node_ids: vec!["db-1".into()],
            max_unavailable: 0,
            lease_ttl_ms: 30_000,
            reboot_lease_ttl_ms: 120_000,
            probes: HealthOracleSpec::default(),
        },
        WaveSpec {
            wave_id: "db-wave-2".into(),
            depends_on: vec!["db-wave-1".into()],
            node_ids: vec!["db-2".into()],
            max_unavailable: 0,
            lease_ttl_ms: 30_000,
            reboot_lease_ttl_ms: 120_000,
            probes: HealthOracleSpec::default(),
        },
    ];
    let sorted = validate_and_toposort_waves(&waves, &quorums).expect("valid DAG & quorum");
    let order: Vec<&str> = sorted.iter().map(|w| w.wave_id.as_str()).collect();
    assert_eq!(order, vec!["db-wave-1", "db-wave-2", "api"]);

    // 2. Reject cycle in wave DAG
    let cyclic_waves = vec![
        WaveSpec {
            wave_id: "w1".into(),
            depends_on: vec!["w2".into()],
            node_ids: vec!["n1".into()],
            max_unavailable: 0,
            lease_ttl_ms: 30_000,
            reboot_lease_ttl_ms: 120_000,
            probes: HealthOracleSpec::default(),
        },
        WaveSpec {
            wave_id: "w2".into(),
            depends_on: vec!["w1".into()],
            node_ids: vec!["n2".into()],
            max_unavailable: 0,
            lease_ttl_ms: 30_000,
            reboot_lease_ttl_ms: 120_000,
            probes: HealthOracleSpec::default(),
        },
    ];
    let err_cycle = validate_and_toposort_waves(&cyclic_waves, &[]).unwrap_err();
    assert!(
        matches!(err_cycle, EpochError::PlanValidation(ref s) if s.contains("CyclicWaveDependency"))
    );

    // 3. Reject wave violating quorum maxUnavailable (2 db nodes in 1 wave for 3-node etcd quorum)
    let bad_quorum_wave = vec![WaveSpec {
        wave_id: "db-both".into(),
        depends_on: vec![],
        node_ids: vec!["db-1".into(), "db-2".into()],
        max_unavailable: 0,
        lease_ttl_ms: 30_000,
        reboot_lease_ttl_ms: 120_000,
        probes: HealthOracleSpec::default(),
    }];
    let err_quorum = validate_and_toposort_waves(&bad_quorum_wave, &quorums).unwrap_err();
    assert!(
        matches!(err_quorum, EpochError::PlanValidation(ref s) if s.contains("QuorumSafetyViolation"))
    );
}

#[test]
fn test_plane1_preforked_cow_worker_pool_and_blake3_eval_cache() {
    let tmp = TempDir::new().unwrap();
    let store_dir = tmp.path().join("nix/store");
    let cache_path = tmp.path().join("eval-cache.cbor");
    let flake_lock = tmp.path().join("flake.lock");
    fs::write(&flake_lock, b"lock-v1").unwrap();
    let lock_hash = *blake3::hash(b"lock-v1").as_bytes();

    let key = Ed25519Identity::from_seed([0x77; 32]).unwrap();
    let mut specs = Vec::new();
    for i in 0..12 {
        let node_id = format!("node-{i:02}");
        let arch_tl = "/nix/store/00000000000000000000000000000000-arch";
        let env = seal_secret_bundle(
            &node_id,
            arch_tl,
            &key.public_key,
            None,
            &[SecretEntry {
                name: "k".into(),
                owner_user: "root".into(),
                owner_group: "root".into(),
                mode: 0o400,
                plaintext: b"sec".to_vec(),
            }],
        )
        .unwrap();
        specs.push(NodeOverlaySpec {
            node_id: node_id.clone(),
            archetype_name: "db".into(),
            archetype_toplevel: arch_tl.into(),
            system_arch: "x86_64-linux".into(),
            rack_id: "rack-1".into(),
            zone_id: "zone-1".into(),
            quic_endpoint: "127.0.0.1:9443".into(),
            node_pub: key.public_key,
            host_name: node_id,
            ipv4_cidr: "10.0.0.1/24".into(),
            machine_id: format!("{i:032x}"),
            kernel_path: "/nix/store/k".into(),
            initrd_path: "/nix/store/i".into(),
            secrets_envelope: env,
            traced_files: vec![flake_lock.clone()],
        });
    }

    // Force worker recycling every 3 evaluations (12 / 3 = 4 worker recycles)
    let pool_cfg = WorkerPoolConfig {
        max_workers: 2,
        worker_max_rss_bytes: 512 * 1024 * 1024,
        max_batch_per_worker: 3,
    };
    let mut cache = EvalCache::load(&cache_path).unwrap();
    let (entries1, stats1) =
        evaluate_nodes_preforked(&store_dir, &lock_hash, &specs, &mut cache, &pool_cfg).unwrap();
    assert_eq!(entries1.len(), 12);
    assert_eq!(stats1.cache_hits, 0);
    assert_eq!(stats1.worker_evals, 12);
    assert_eq!(stats1.worker_recycles, 4);
    cache.save_atomic(&cache_path).unwrap();

    // Reload cache and re-evaluate with 1 node modified -> 11 cache hits, 1 worker eval
    let mut cache2 = EvalCache::load(&cache_path).unwrap();
    specs[5].ipv4_cidr = "10.99.99.99/24".into();
    let (entries2, stats2) =
        evaluate_nodes_preforked(&store_dir, &lock_hash, &specs, &mut cache2, &pool_cfg).unwrap();
    assert_eq!(entries2.len(), 12);
    assert_eq!(stats2.cache_hits, 11);
    assert_eq!(stats2.worker_evals, 1);
}

#[test]
fn test_plane2_bijective_32byte_store_hash_normalizer_and_fastcdc_deduplication() {
    let tmp = TempDir::new().unwrap();
    let pkg_a = tmp.path().join("pkg-a");
    let pkg_b = tmp.path().join("pkg-b");
    fs::create_dir_all(&pkg_a).unwrap();
    fs::create_dir_all(&pkg_b).unwrap();

    let store_a = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.40";
    let store_b = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-glibc-2.40";
    let hash_a = extract_store_hash_32(store_a).unwrap();
    let hash_b = extract_store_hash_32(store_b).unwrap();

    let mut content_a = Vec::new();
    let mut content_b = Vec::new();
    let mut rng = 0xfeed_face_cafe_beefu64;
    for _ in 0..64 {
        content_a.extend_from_slice(format!("RUNPATH={store_a}/lib\0").as_bytes());
        content_b.extend_from_slice(format!("RUNPATH={store_b}/lib\0").as_bytes());
        for _ in 0..2048 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let b = (rng & 0xff) as u8;
            content_a.push(b);
            content_b.push(b);
        }
    }
    fs::write(pkg_a.join("lib.so"), &content_a).unwrap();
    fs::write(pkg_b.join("lib.so"), &content_b).unwrap();

    let nar_a = serialize_nar(&pkg_a).unwrap();
    let nar_b = serialize_nar(&pkg_b).unwrap();
    assert_ne!(nar_a, nar_b);

    let norm_a = normalize_nar_store_hashes(&nar_a, &[hash_a]);
    let norm_b = normalize_nar_store_hashes(&nar_b, &[hash_b]);
    // Normalized NAR streams must be 100% byte-for-byte identical!
    assert_eq!(norm_a.len(), nar_a.len());
    assert_eq!(norm_a, norm_b);

    // Denormalizing must recover the exact original NARs bit-for-bit
    let denorm_a = denormalize_nar_store_hashes(&norm_a, &[hash_a]).unwrap();
    let denorm_b = denormalize_nar_store_hashes(&norm_b, &[hash_b]).unwrap();
    assert_eq!(denorm_a, nar_a);
    assert_eq!(denorm_b, nar_b);

    // Unpack NAR and re-serialize -> must match original NAR byte-for-byte
    let unpacked_dir = tmp.path().join("unpacked-a");
    unpack_nar(&denorm_a, &unpacked_dir).unwrap();
    let reserialized_a = serialize_nar(&unpacked_dir).unwrap();
    assert_eq!(reserialized_a, nar_a);

    // Build chunk manifests and verify 100% chunk deduplication across store-hash shift
    let sign_key = Ed25519Identity::from_seed([0x33; 32]).unwrap();
    let (man_a, _) = build_nar_chunk_manifest(
        &pkg_a,
        store_a,
        vec![store_a.into()],
        None,
        "key-1",
        &sign_key,
    )
    .unwrap();
    let (man_b, _) = build_nar_chunk_manifest(
        &pkg_b,
        store_b,
        vec![store_b.into()],
        None,
        "key-1",
        &sign_key,
    )
    .unwrap();
    assert!(man_a.chunks.len() >= 2);
    assert_eq!(man_a.chunks, man_b.chunks);
}

#[test]
fn test_plane3_hardware_tpm2_and_host_key_secret_envelopes_and_aad_binding() {
    let tmp = TempDir::new().unwrap();
    let ramfs_root = tmp.path().join("run/epoch/secrets");
    let current_link = tmp.path().join("run/epoch/current-secrets");
    let staged_tl = tmp.path().join("staged-tl");
    fs::create_dir_all(&staged_tl).unwrap();

    let host_key = Ed25519Identity::from_seed([0x81; 32]).unwrap();
    let tpm_policy_authority = Ed25519Identity::from_seed([0x82; 32]).unwrap();
    let pcr_mask = (1u32 << 0) | (1u32 << 2) | (1u32 << 7); // PCRs 0, 2, 7
    let pcr_digest = [0x5c; 32];
    let arch_tl = "/nix/store/11111111111111111111111111111111-arch-db";

    let entries = vec![SecretEntry {
        name: "pg_repl_tls_key".into(),
        owner_user: "postgres".into(),
        owner_group: "postgres".into(),
        mode: 0o400,
        plaintext: b"BEGIN-PRIVATE-KEY-DB1".to_vec(),
    }];

    let bundle = seal_secret_bundle(
        "db-1",
        arch_tl,
        &host_key.public_key,
        Some((pcr_mask, &tpm_policy_authority, &pcr_digest)),
        &entries,
    )
    .unwrap();

    // 1. Unseal via TPM2 PCR policy succeeds when PCR digest & mask match
    let unsealed_tpm = unseal_secret_bundle(
        &bundle,
        "db-1",
        arch_tl,
        &host_key,
        Some((pcr_mask, &pcr_digest)),
    )
    .unwrap();
    assert_eq!(unsealed_tpm, entries);

    // 2. Unseal via TPM2 fails if PCR 7 changes (e.g. Secure Boot disabled / evil maid)
    let mut bad_pcr_digest = pcr_digest;
    bad_pcr_digest[0] ^= 0x01;
    let err_pcr = unseal_secret_bundle(
        &bundle,
        "db-1",
        arch_tl,
        &host_key,
        Some((pcr_mask, &bad_pcr_digest)),
    )
    .unwrap_err();
    assert!(matches!(err_pcr, EpochError::SecretUnsealFailed { .. }));

    // 3. Cross-node replay ("db-2" trying to unseal "db-1"'s envelope) fails AAD check
    let err_node = unseal_secret_bundle(&bundle, "db-2", arch_tl, &host_key, None).unwrap_err();
    assert!(matches!(err_node, EpochError::SecretUnsealFailed { .. }));

    // 4. Cross-generation replay (wrong archetype_toplevel) fails AAD check
    let err_gen = unseal_secret_bundle(
        &bundle,
        "db-1",
        "/nix/store/99999999999999999999999999999999-arch-other",
        &host_key,
        None,
    )
    .unwrap_err();
    assert!(matches!(err_gen, EpochError::SecretUnsealFailed { .. }));

    // 5. Prepare generation 10 and generation 11 on ramfs, flip via RENAME_EXCHANGE, and zero-wipe gen-10
    prepare_generation_secrets_from_bundle(
        &staged_tl,
        &ramfs_root,
        10,
        &bundle,
        "db-1",
        arch_tl,
        &host_key,
        Some((pcr_mask, &pcr_digest)),
    )
    .unwrap();
    atomic_flip_current_secrets(&current_link, &ramfs_root, 10).unwrap();
    assert_eq!(
        fs::read(current_link.join("pg_repl_tls_key")).unwrap(),
        b"BEGIN-PRIVATE-KEY-DB1"
    );

    prepare_generation_secrets_from_bundle(
        &staged_tl,
        &ramfs_root,
        11,
        &bundle,
        "db-1",
        arch_tl,
        &host_key,
        None,
    )
    .unwrap();
    atomic_flip_current_secrets(&current_link, &ramfs_root, 11).unwrap();
    zero_wipe_secret_generation(&ramfs_root, 10).unwrap();
    assert!(!ramfs_root.join("gen-10").exists());
    assert!(ramfs_root.join("gen-11").exists());
}

#[tokio::test]
async fn test_plane2_and_plane4_real_quic_mtls_rpc_exchange() {
    let coord_id = Ed25519Identity::from_seed([0x91; 32]).unwrap();
    let node_id = Ed25519Identity::from_seed([0x92; 32]).unwrap();

    let (server_ep, server_addr) =
        bind_quic_endpoint("127.0.0.1:0".parse().unwrap(), &node_id).unwrap();
    let (client_ep, _client_addr) =
        bind_quic_endpoint("127.0.0.1:0".parse().unwrap(), &coord_id).unwrap();

    let coord_pub = coord_id.public_key;
    let server_task = tokio::spawn(async move {
        let incoming = server_ep.accept().await.expect("accept QUIC conn");
        let conn = incoming.await.expect("handshake");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let req = read_quic_wire_msg(&mut recv).await.expect("read req");

        match req {
            EpochWireMsg::ActivateWave {
                tx_epoch,
                wave_id,
                lease_ttl_ms,
                coord_sig,
            } => {
                verify_activate_wave(&coord_pub, tx_epoch, &wave_id, lease_ttl_ms, &coord_sig)
                    .expect("valid ActivateWave sig");
                let resp = sign_health_attestation(
                    &node_id,
                    tx_epoch,
                    &wave_id,
                    "db-1",
                    true,
                    "AllOraclesPassed",
                )
                .expect("sign attestation");
                write_quic_wire_msg(&mut send, &resp)
                    .await
                    .expect("write resp");
                send.finish().unwrap();
                let _ = conn.closed().await;
            }
            other => panic!("unexpected wire msg: {other:?}"),
        }
    });

    let req = sign_activate_wave(&coord_id, 88, "wave-db", 30_000).unwrap();
    let resp = quic_rpc_call(&client_ep, server_addr, &req)
        .await
        .expect("QUIC RPC call");

    match resp {
        EpochWireMsg::HealthAttestation {
            tx_epoch,
            wave_id,
            node_id: nid,
            healthy,
            diagnostic,
            node_sig,
        } => {
            assert_eq!(tx_epoch, 88);
            assert_eq!(wave_id, "wave-db");
            assert_eq!(nid, "db-1");
            assert!(healthy);
            let node_pub = Ed25519Identity::from_seed([0x92; 32]).unwrap().public_key;
            verify_health_attestation(
                &node_pub,
                tx_epoch,
                &wave_id,
                &nid,
                healthy,
                &diagnostic,
                &node_sig,
            )
            .expect("verify node attestation signature");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    server_task.await.unwrap();
}

#[test]
fn test_rack_aware_p2p_spanning_tree_depth_and_fanout() {
    let mut nodes = Vec::new();
    for i in 0..40 {
        nodes.push(NodePlanEntry {
            node_id: format!("n-{i:02}"),
            system_arch: "x86_64-linux".into(),
            rack_id: "rack-a".into(),
            zone_id: "zone-1".into(),
            quic_endpoint: format!("10.0.0.{}:9443", i + 1),
            node_pub: [0u8; 32],
            toplevel_path: "/nix/store/tl".into(),
            kernel_path: "/nix/store/k".into(),
            initrd_path: "/nix/store/i".into(),
            secrets_envelope_hash: [0u8; 32],
            closure_manifests_merkle_root: [0u8; 32],
            p2p_parent_node_id: None,
            p2p_children_node_ids: Vec::new(),
        });
    }
    compile_p2p_spanning_tree(&mut nodes, 4);

    // Exactly 1 Rack Seed Node (n-00) with parent == None and 4 children (n-01..n-04)
    let seeds: Vec<_> = nodes
        .iter()
        .filter(|n| n.p2p_parent_node_id.is_none())
        .collect();
    assert_eq!(seeds.len(), 1);
    assert_eq!(seeds[0].node_id, "n-00");
    assert_eq!(
        seeds[0].p2p_children_node_ids,
        vec!["n-01", "n-02", "n-03", "n-04"]
    );
    // Every non-seed node has a parent and at most 4 children
    for n in &nodes[1..] {
        assert!(n.p2p_parent_node_id.is_some());
        assert!(n.p2p_children_node_ids.len() <= 4);
    }
}

#[test]
fn test_gate4_all_five_adversarial_fault_scenarios() {
    let r1 = verify_scenario_1_coordinator_crash_mid_dag().expect("Scenario 1");
    assert!(r1.passed);

    let r2 = verify_scenario_2_asymmetric_partitions().expect("Scenario 2 (2A & 2B)");
    assert!(r2.passed);

    let r3 = verify_scenario_3_broken_kernel_initrd_panic().expect("Scenario 3");
    assert!(r3.passed);

    let r4 = verify_scenario_4_corruption_and_enospc().expect("Scenario 4 (4A & 4B)");
    assert!(r4.passed);

    let r5 = verify_scenario_5_canary_failure_coupled_wave().expect("Scenario 5");
    assert!(r5.passed);

    let all = run_all_gate4_fault_scenarios().expect("All Gate 4 scenarios");
    assert_eq!(all.len(), 5);
    assert!(all.iter().all(|r| r.passed));
}

#[test]
fn test_edge_cases_kmsg_and_cgroup_oom_oracles_and_state_mac_tampering() {
    use epoch::oracles::{ProbeEnvironment, evaluate_health_oracles, parse_cgroup_oom_kill};
    use epoch::plane4_state::{load_persistent_state, save_persistent_state};
    use epoch::schema::{AgentPhase, PersistentAgentState};

    // 1. Verify cgroup memory.events oom_kill parser and OOM delta rejection
    let sample_mem_events = "low 0\nhigh 12\nmax 3\noom 1\noom_kill 4\noom_group_kill 0\n";
    assert_eq!(parse_cgroup_oom_kill(sample_mem_events), 4);

    let spec = HealthOracleSpec {
        required_systemd_units: vec![],
        tcp_endpoints: vec![],
        http_checks: vec![],
        peer_mesh_quorum: 1,
        forbid_kmsg_patterns: vec!["Oops:".into(), "BUG:".into()],
    };
    let oom_env = ProbeEnvironment {
        oom_kill_baseline: 2,
        oom_kill_current: Some(3),
        reachable_cohort_peers: 1,
        ..Default::default()
    };
    let res_oom = evaluate_health_oracles(&spec, &oom_env);
    assert!(!res_oom.healthy);
    assert!(res_oom.diagnostic.contains("CgroupOomKillDetected"));

    // 2. Verify /dev/kmsg forbidden pattern rejection
    let kmsg_env = ProbeEnvironment {
        kmsg_lines: Some(vec![
            "6,120,4500000,-;systemd[1]: Started nginx.service.".into(),
            "3,121,4600000,-;BUG: kernel NULL pointer dereference, address: 0000000000000000"
                .into(),
        ]),
        reachable_cohort_peers: 1,
        ..Default::default()
    };
    let res_kmsg = evaluate_health_oracles(&spec, &kmsg_env);
    assert!(!res_kmsg.healthy);
    assert!(res_kmsg.diagnostic.contains("KernelKmsgFault"));

    // 3. Verify state.cbor keyed BLAKE3 MAC tamper detection
    let tmp = TempDir::new().unwrap();
    let state_path = tmp.path().join("state.cbor");
    let mac_key = [0xab; 32];
    let mut state = PersistentAgentState {
        highest_tx_epoch: 99,
        phase: AgentPhase::Committed,
        active_wave_id: None,
        prev_toplevel: "/nix/store/tl-99".into(),
        prev_secret_epoch: 99,
        staged_toplevel: None,
        lease_deadline_boottime_ns: 0,
        reboot_deadline_wall_utc_s: 0,
        state_blake3_mac: [0u8; 32],
    };
    save_persistent_state(&state_path, &mut state, &mac_key).unwrap();
    let loaded = load_persistent_state(&state_path, &mac_key).unwrap();
    assert_eq!(loaded, state);

    // Tamper with the MAC key or file bytes -> must reject with CryptoVerificationFailed
    let wrong_key = [0xcd; 32];
    assert!(matches!(
        load_persistent_state(&state_path, &wrong_key),
        Err(EpochError::CryptoVerificationFailed(_))
    ));
}

#[test]
fn test_regression_x25519_birational_map_and_private_key_host_unseal() {
    use epoch::crypto::{
        ed25519_pub_to_x25519, ed25519_seed_to_x25519_scalar, x25519_basepoint, x25519_scalarmult,
    };

    for seed_byte in [0x01u8, 0x22, 0x55, 0xa7, 0xfe] {
        let id_a = Ed25519Identity::from_seed([seed_byte; 32]).unwrap();
        let id_b = Ed25519Identity::from_seed([seed_byte.wrapping_add(17); 32]).unwrap();

        let scalar_a = ed25519_seed_to_x25519_scalar(id_a.seed());
        let scalar_b = ed25519_seed_to_x25519_scalar(id_b.seed());

        let u_from_ed_a = ed25519_pub_to_x25519(&id_a.public_key);
        let u_from_base_a = x25519_basepoint(&scalar_a);
        assert_eq!(
            u_from_ed_a, u_from_base_a,
            "Ed25519 -> X25519 birational map must match X25519 basepoint scalar multiplication"
        );

        let u_from_ed_b = ed25519_pub_to_x25519(&id_b.public_key);
        let shared_ab = x25519_scalarmult(&scalar_a, &u_from_ed_b);
        let shared_ba = x25519_scalarmult(&scalar_b, &u_from_ed_a);
        assert_eq!(shared_ab, shared_ba, "X25519 ECDH commutativity must hold");
    }

    // Verify that an attacker who knows the target host's Ed25519 public key (but lacks its private key)
    // CANNOT unseal a host-key-wrapped SecretEnvelopeBundle!
    let target_host = Ed25519Identity::from_seed([0x41; 32]).unwrap();
    let attacker_host = Ed25519Identity::from_seed([0x42; 32]).unwrap();
    let arch_tl = "/nix/store/11111111111111111111111111111111-arch-db";
    let entries = vec![SecretEntry {
        name: "master_key".into(),
        owner_user: "root".into(),
        owner_group: "root".into(),
        mode: 0o400,
        plaintext: b"TOP-SECRET-VALUE".to_vec(),
    }];

    let bundle =
        seal_secret_bundle("db-1", arch_tl, &target_host.public_key, None, &entries).unwrap();
    // Legitimate host private key succeeds
    let decrypted = unseal_secret_bundle(&bundle, "db-1", arch_tl, &target_host, None).unwrap();
    assert_eq!(decrypted, entries);

    // Attacker private key fails with SecretUnsealFailed
    let err = unseal_secret_bundle(&bundle, "db-1", arch_tl, &attacker_host, None).unwrap_err();
    assert!(matches!(err, EpochError::SecretUnsealFailed { .. }));
}

#[tokio::test]
async fn test_regression_quic_mtls_pinned_spki_rejects_unpinned_client_and_server() {
    use epoch::p2p_quic::bind_quic_endpoint_with_pinned_peers;

    let coord_id = Ed25519Identity::from_seed([0x61; 32]).unwrap();
    let node_id = Ed25519Identity::from_seed([0x62; 32]).unwrap();
    let rogue_id = Ed25519Identity::from_seed([0x63; 32]).unwrap();

    // Server pins ONLY `coord_id.public_key`
    let (server_ep, server_addr) = bind_quic_endpoint_with_pinned_peers(
        "127.0.0.1:0".parse().unwrap(),
        &node_id,
        Some(vec![coord_id.public_key]),
    )
    .unwrap();

    // Rogue client is NOT in server's pinned client allowlist
    let (rogue_client_ep, _) = bind_quic_endpoint_with_pinned_peers(
        "127.0.0.1:0".parse().unwrap(),
        &rogue_id,
        Some(vec![node_id.public_key]),
    )
    .unwrap();

    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server_ep.accept().await
            && let Ok(conn) = incoming.await
        {
            let _ = conn.accept_bi().await;
        }
    });

    let fake_req = sign_activate_wave(&rogue_id, 1, "w", 1000).unwrap();
    let rogue_res = quic_rpc_call(&rogue_client_ep, server_addr, &fake_req).await;
    assert!(
        rogue_res.is_err(),
        "mTLS server must reject client whose Ed25519 SPKI key is not in pinned allowlist"
    );
    let _ = server_handle.await;

    // Now test client rejecting an unpinned server
    let (rogue_server_ep, rogue_server_addr) =
        bind_quic_endpoint_with_pinned_peers("127.0.0.1:0".parse().unwrap(), &rogue_id, None)
            .unwrap();
    // Client pins ONLY `node_id.public_key`, so `rogue_id` server must be rejected
    let (strict_client_ep, _) = bind_quic_endpoint_with_pinned_peers(
        "127.0.0.1:0".parse().unwrap(),
        &coord_id,
        Some(vec![node_id.public_key]),
    )
    .unwrap();

    let rogue_srv_handle = tokio::spawn(async move {
        if let Some(incoming) = rogue_server_ep.accept().await {
            let _ = incoming.await;
        }
    });

    let req2 = sign_activate_wave(&coord_id, 1, "w", 1000).unwrap();
    let client_res = quic_rpc_call(&strict_client_ep, rogue_server_addr, &req2).await;
    assert!(
        client_res.is_err(),
        "mTLS client must reject server whose Ed25519 SPKI key is not in pinned allowlist"
    );
    let _ = rogue_srv_handle.await;
}

#[test]
fn test_regression_eval_cache_secret_rotation_and_mid_batch_worker_rss_recycle() {
    use std::collections::BTreeSet;

    let tmp = TempDir::new().unwrap();
    let store_dir = tmp.path().join("nix/store");
    let flake_lock = tmp.path().join("flake.lock");
    fs::write(&flake_lock, b"lock-v2").unwrap();
    let lock_hash = *blake3::hash(b"lock-v2").as_bytes();
    let key = Ed25519Identity::from_seed([0x51; 32]).unwrap();

    let mut specs = Vec::new();
    for i in 0..10 {
        let node_id = format!("n-{i:02}");
        let arch_tl = "/nix/store/00000000000000000000000000000000-arch-v1";
        let env = seal_secret_bundle(
            &node_id,
            arch_tl,
            &key.public_key,
            None,
            &[SecretEntry {
                name: "s".into(),
                owner_user: "root".into(),
                owner_group: "root".into(),
                mode: 0o400,
                plaintext: format!("secret-{i}").into_bytes(),
            }],
        )
        .unwrap();
        specs.push(NodeOverlaySpec {
            node_id: node_id.clone(),
            archetype_name: "app".into(),
            archetype_toplevel: arch_tl.into(),
            system_arch: "x86_64-linux".into(),
            rack_id: "r1".into(),
            zone_id: "z1".into(),
            quic_endpoint: "127.0.0.1:9443".into(),
            node_pub: key.public_key,
            host_name: node_id,
            ipv4_cidr: "10.0.0.1/24".into(),
            machine_id: format!("{i:032x}"),
            kernel_path: "/nix/store/k".into(),
            initrd_path: "/nix/store/i".into(),
            secrets_envelope: env,
            traced_files: vec![flake_lock.clone()],
        });
    }

    // Set `worker_max_rss_bytes = 1` with `max_workers = 2` and `max_batch_per_worker = 4`:
    // Every worker exceeds RSS after 1 node and exits mid-batch via `_exit(0)`!
    // Verify all 10 nodes are evaluated with zero dropped nodes and zero duplicates.
    let pool_cfg = WorkerPoolConfig {
        max_workers: 2,
        worker_max_rss_bytes: 1,
        max_batch_per_worker: 4,
    };
    let mut cache = EvalCache::default();
    let (entries, stats) =
        evaluate_nodes_preforked(&store_dir, &lock_hash, &specs, &mut cache, &pool_cfg).unwrap();
    assert_eq!(entries.len(), 10);
    let unique_ids: BTreeSet<String> = entries.iter().map(|e| e.node_id.clone()).collect();
    assert_eq!(
        unique_ids.len(),
        10,
        "zero dropped or duplicated nodes on mid-batch RSS recycle"
    );
    assert_eq!(stats.worker_evals, 10);
    assert_eq!(stats.worker_recycles, 10);

    // Rotate secrets on `specs[0]` -> must invalidate EvalCache for `n-00`!
    let rotated_env = seal_secret_bundle(
        "n-00",
        &specs[0].archetype_toplevel,
        &key.public_key,
        None,
        &[SecretEntry {
            name: "s".into(),
            owner_user: "root".into(),
            owner_group: "root".into(),
            mode: 0o400,
            plaintext: b"ROTATED-SECRET-NEW".to_vec(),
        }],
    )
    .unwrap();
    specs[0].secrets_envelope = rotated_env;
    assert!(
        cache.lookup(&lock_hash, &specs[0]).is_none(),
        "EvalCache must invalidate when secrets_envelope changes"
    );

    // Changing `archetype_toplevel` on `specs[1]` must also invalidate EvalCache
    specs[1].archetype_toplevel = "/nix/store/11111111111111111111111111111111-arch-v2".into();
    assert!(
        cache.lookup(&lock_hash, &specs[1]).is_none(),
        "EvalCache must invalidate when archetype_toplevel changes"
    );
}

#[test]
fn test_regression_sqlite_refs_table_mtime_one_and_normalizer_adjacent_paths() {
    use epoch::plane2_store::{
        TargetChunkIndex, ingest_fetched_chunks, query_valid_path_and_refs_sqlite,
        reconstruct_and_register_store_path,
    };
    use std::os::unix::fs::MetadataExt;

    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src-pkg");
    fs::create_dir_all(src_dir.join("bin")).unwrap();

    let ref_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dep-lib";
    let self_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-my-pkg";
    let unref_path = "/nix/store/cccccccccccccccccccccccccccccccc-unreferenced";

    // Write file containing adjacent unreferenced and referenced store paths
    let script = format!("#!/bin/sh\necho {unref_path}{ref_path} {self_path}\n");
    fs::write(src_dir.join("bin/run"), script.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(src_dir.join("bin/run"), fs::Permissions::from_mode(0o755)).unwrap();
    }

    let store_key = Ed25519Identity::from_seed([0x44; 32]).unwrap();
    let (manifest, zstd_map) = build_nar_chunk_manifest(
        &src_dir,
        self_path,
        vec![ref_path.into(), self_path.into()],
        None,
        "store-key-1",
        &store_key,
    )
    .unwrap();

    let mut chunk_index = TargetChunkIndex::default();
    let fetched: Vec<_> = zstd_map.into_iter().collect();
    ingest_fetched_chunks(&mut chunk_index, std::slice::from_ref(&manifest), &fetched).unwrap();

    let dst_store = tmp.path().join("nix/store");
    let sqlite_db = tmp.path().join("nix/var/nix/db/db.sqlite");
    let unpacked = reconstruct_and_register_store_path(
        &dst_store,
        &sqlite_db,
        &manifest,
        &chunk_index,
        &[("store-key-1".into(), store_key.public_key)],
    )
    .unwrap();

    // 1. Verify unpacked files & directories have mtime == 1 and read-only mode
    let dir_meta = fs::symlink_metadata(&unpacked).unwrap();
    let file_meta = fs::symlink_metadata(unpacked.join("bin/run")).unwrap();
    assert_eq!(
        dir_meta.mtime(),
        1,
        "unpacked store directory must have mtime = 1"
    );
    assert_eq!(
        file_meta.mtime(),
        1,
        "unpacked store file must have mtime = 1"
    );
    assert_eq!(file_meta.mode() & 0o777, 0o555);

    // 2. Verify adjacent unreferenced and referenced store paths round-tripped identically
    let unpacked_script = fs::read_to_string(unpacked.join("bin/run")).unwrap();
    assert_eq!(unpacked_script, script);

    // 3. Verify SQLite ValidPaths AND Refs tables are populated
    let (is_valid, refs_count) = query_valid_path_and_refs_sqlite(&sqlite_db, self_path).unwrap();
    assert!(is_valid, "store path must be registered in ValidPaths");
    assert_eq!(
        refs_count, 2,
        "Refs table must record both references_full entries"
    );
}

#[test]
fn test_regression_cross_wave_replay_rejected_and_non_reboot_commit_updates_loader_conf() {
    use epoch::crypto::{sign_activate_wave, sign_commit_wave};
    use epoch::oracles::ProbeEnvironment;
    use epoch::plane1_eval::{compile_signed_execution_plan, synthesize_node_overlay_closure};
    use epoch::plane2_store::build_nar_chunk_manifest;
    use epoch::plane4_state::{AgentFilesystemLayout, EpochNodeAgent};

    let tmp = TempDir::new().unwrap();
    let coord_key = Ed25519Identity::from_seed([0x71; 32]).unwrap();
    let store_key = Ed25519Identity::from_seed([0x72; 32]).unwrap();
    let n1_key = Ed25519Identity::from_seed([0x73; 32]).unwrap();
    let n2_key = Ed25519Identity::from_seed([0x74; 32]).unwrap();

    let arch_tl = "/nix/store/00000000000000000000000000000000-arch";
    let build_store = tmp.path().join("build-store");
    fs::create_dir_all(&build_store).unwrap();

    let make_spec = |nid: &str, key: &Ed25519Identity, sec: &[u8]| -> NodeOverlaySpec {
        let env = seal_secret_bundle(
            nid,
            arch_tl,
            &key.public_key,
            None,
            &[SecretEntry {
                name: "s".into(),
                owner_user: "root".into(),
                owner_group: "root".into(),
                mode: 0o400,
                plaintext: sec.to_vec(),
            }],
        )
        .unwrap();
        NodeOverlaySpec {
            node_id: nid.into(),
            archetype_name: "app".into(),
            archetype_toplevel: arch_tl.into(),
            system_arch: "x86_64-linux".into(),
            rack_id: "r1".into(),
            zone_id: "z1".into(),
            quic_endpoint: "127.0.0.1:9443".into(),
            node_pub: key.public_key,
            host_name: nid.into(),
            ipv4_cidr: "10.0.0.1/24".into(),
            machine_id: "0102030405060708090a0b0c0d0e0f00".into(),
            kernel_path: "/nix/store/kernel-same".into(),
            initrd_path: "/nix/store/initrd-same".into(),
            secrets_envelope: env,
            traced_files: vec![],
        }
    };

    let n2_init_spec = make_spec("n-2", &n2_key, b"v1");
    let (n2_init_tl, _) = synthesize_node_overlay_closure(&build_store, &n2_init_spec).unwrap();
    let n2_layout = AgentFilesystemLayout::under_root(&tmp.path().join("n2-root"));
    let mut agent_n2 = EpochNodeAgent::initialize(
        "n-2",
        Ed25519Identity::from_seed([0x74; 32]).unwrap(),
        vec![coord_key.public_key],
        vec![("store-1".into(), store_key.public_key)],
        n2_layout.clone(),
        49,
        &n2_init_tl,
        arch_tl,
        "/nix/store/kernel-same",
        "/nix/store/initrd-same",
        None,
    )
    .unwrap();
    agent_n2.quota_reserve_override_bytes = Some(1024);

    let n1_v2_spec = make_spec("n-1", &n1_key, b"v2-n1");
    let n2_v2_spec = make_spec("n-2", &n2_key, b"v2-n2");
    let (n1_v2_tl, n1_sec_h) = synthesize_node_overlay_closure(&build_store, &n1_v2_spec).unwrap();
    let (n2_v2_tl, n2_sec_h) = synthesize_node_overlay_closure(&build_store, &n2_v2_spec).unwrap();

    let n1_logical = format!(
        "/nix/store/{}",
        n1_v2_tl.file_name().unwrap().to_string_lossy()
    );
    let n2_logical = format!(
        "/nix/store/{}",
        n2_v2_tl.file_name().unwrap().to_string_lossy()
    );
    let (n2_man, n2_chunks_map) =
        build_nar_chunk_manifest(&n2_v2_tl, &n2_logical, vec![], None, "store-1", &store_key)
            .unwrap();
    let n2_chunks: Vec<_> = n2_chunks_map.into_iter().collect();

    let waves = vec![
        WaveSpec {
            wave_id: "wave-1".into(),
            depends_on: vec![],
            node_ids: vec!["n-1".into()],
            max_unavailable: 0,
            lease_ttl_ms: 30_000,
            reboot_lease_ttl_ms: 120_000,
            probes: HealthOracleSpec::default(),
        },
        WaveSpec {
            wave_id: "wave-2".into(),
            depends_on: vec!["wave-1".into()],
            node_ids: vec!["n-2".into()],
            max_unavailable: 0,
            lease_ttl_ms: 30_000,
            reboot_lease_ttl_ms: 120_000,
            probes: HealthOracleSpec::default(),
        },
    ];
    let nodes = vec![
        NodePlanEntry {
            node_id: "n-1".into(),
            system_arch: "x86_64-linux".into(),
            rack_id: "r1".into(),
            zone_id: "z1".into(),
            quic_endpoint: "127.0.0.1:9443".into(),
            node_pub: n1_key.public_key,
            toplevel_path: n1_logical,
            kernel_path: "/nix/store/kernel-same".into(),
            initrd_path: "/nix/store/initrd-same".into(),
            secrets_envelope_hash: n1_sec_h,
            closure_manifests_merkle_root: n1_sec_h,
            p2p_parent_node_id: None,
            p2p_children_node_ids: vec![],
        },
        NodePlanEntry {
            node_id: "n-2".into(),
            system_arch: "x86_64-linux".into(),
            rack_id: "r1".into(),
            zone_id: "z1".into(),
            quic_endpoint: "127.0.0.1:9443".into(),
            node_pub: n2_key.public_key,
            toplevel_path: n2_logical,
            kernel_path: "/nix/store/kernel-same".into(),
            initrd_path: "/nix/store/initrd-same".into(),
            secrets_envelope_hash: n2_sec_h,
            closure_manifests_merkle_root: n2_sec_h,
            p2p_parent_node_id: None,
            p2p_children_node_ids: vec![],
        },
    ];
    let plan =
        compile_signed_execution_plan("c1", 50, [0u8; 32], &waves, &[], nodes, 4, &coord_key)
            .unwrap();

    agent_n2
        .handle_stage_manifest(50, plan, &[n2_man], &n2_chunks, 60_000_000_000, 1_000_000)
        .unwrap();

    // Cross-wave PrepareWave ("wave-1" sent to "n-2" which belongs to "wave-2") MUST be rejected!
    let bad_prep =
        agent_n2.handle_prepare_wave(50, "wave-1", arch_tl, None, 30_000_000_000, 2_000_000);
    assert!(
        matches!(bad_prep, Err(EpochError::PlanValidation(ref s)) if s.contains("CrossWaveReplayRejected"))
    );

    // Legitimate PrepareWave & ActivateWave for "wave-2"
    agent_n2
        .handle_prepare_wave(50, "wave-2", arch_tl, None, 30_000_000_000, 2_000_000)
        .unwrap();
    let act_w2 = sign_activate_wave(&coord_key, 50, "wave-2", 30_000).unwrap();
    if let EpochWireMsg::ActivateWave { coord_sig, .. } = act_w2 {
        let req_reboot = agent_n2
            .handle_activate_wave(50, "wave-2", 30_000, &coord_sig, 3_000_000, 1000)
            .unwrap();
        assert!(!req_reboot);
    }
    agent_n2
        .evaluate_probes_and_attest(
            4_000_000,
            &ProbeEnvironment {
                reachable_cohort_peers: 1,
                ..Default::default()
            },
        )
        .unwrap();

    // Cross-wave CommitWave ("wave-1" replayed to "n-2" in BARRIER_WAIT) MUST be rejected!
    let commit_w1 = sign_commit_wave(&coord_key, 50, "wave-1", vec![]).unwrap();
    if let EpochWireMsg::CommitWave { coord_sig, .. } = commit_w1 {
        let bad_commit = agent_n2.handle_commit_wave(50, "wave-1", &[], &coord_sig);
        assert!(
            matches!(bad_commit, Err(EpochError::PlanValidation(ref s)) if s.contains("CrossWaveReplayRejected"))
        );
    }

    // Legitimate CommitWave for "wave-2" succeeds and updates loader.conf + gen-prev on non-reboot commit
    let commit_w2 = sign_commit_wave(&coord_key, 50, "wave-2", vec![]).unwrap();
    if let EpochWireMsg::CommitWave { coord_sig, .. } = commit_w2 {
        agent_n2
            .handle_commit_wave(50, "wave-2", &[], &coord_sig)
            .unwrap();
    }
    let loader_conf = fs::read_to_string(n2_layout.boot_root.join("loader/loader.conf")).unwrap();
    assert!(
        loader_conf.contains("default nixos-generation-50.conf"),
        "non-reboot CommitWave must update loader.conf default to generation 50"
    );
    assert!(
        n2_layout
            .boot_root
            .join("loader/entries/nixos-generation-50.conf")
            .exists()
    );
    let gen_prev =
        fs::read_to_string(n2_layout.state_cbor_path.with_file_name("gen-prev")).unwrap();
    assert_eq!(gen_prev.trim(), agent_n2.state.prev_toplevel);
}

#[test]
fn test_regression_cbor_and_nar_malformed_u64_max_length_no_panic() {
    // 1. CBOR byte string with 8-byte length = u64::MAX (0x5b = major 2, ai 27)
    let mut bad_cbor = vec![0x5b];
    bad_cbor.extend_from_slice(&u64::MAX.to_be_bytes());
    assert!(cbor::from_slice::<Vec<u8>>(&bad_cbor).is_err());

    // 2. NAR stream with 8-byte token length = u64::MAX
    let mut bad_nar = Vec::new();
    bad_nar.extend_from_slice(&u64::MAX.to_le_bytes());
    let tmp = TempDir::new().unwrap();
    assert!(unpack_nar(&bad_nar, &tmp.path().join("out")).is_err());
}

#[tokio::test]
async fn test_regression_quic_oversized_frame_rejected_and_daemon_wire_dispatch() {
    use epoch::crypto::{sign_activate_wave, sign_commit_wave};
    use epoch::p2p_quic::MAX_QUIC_WIRE_MSG_BYTES;
    use epoch::plane1_eval::{compile_signed_execution_plan, synthesize_node_overlay_closure};
    use epoch::plane2_store::{build_nar_chunk_manifest, zstd_compress};
    use epoch::plane4_state::AgentFilesystemLayout;
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let coord_id = Ed25519Identity::from_seed([0x11; 32]).unwrap();
    let store_id = Ed25519Identity::from_seed([0x22; 32]).unwrap();
    let custom_seed_hex = "9999999999999999999999999999999999999999999999999999999999999999";
    let node_id = Ed25519Identity::from_seed_hex_or_default(Some(custom_seed_hex), [0x42; 32])
        .expect("custom hex seed");
    assert_eq!(node_id.seed(), &[0x99; 32]);

    // 1. Verify read_quic_wire_msg rejects frames larger than MAX_QUIC_WIRE_MSG_BYTES (64 MiB)
    let (server_ep, server_addr) =
        bind_quic_endpoint("127.0.0.1:0".parse().unwrap(), &node_id).unwrap();
    let (client_ep, _) = bind_quic_endpoint("127.0.0.1:0".parse().unwrap(), &coord_id).unwrap();

    let srv_oversized = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let (_send, mut recv) = conn.accept_bi().await.unwrap();
        read_quic_wire_msg(&mut recv).await
    });

    let conn = client_ep
        .connect(server_addr, "epoch-node")
        .unwrap()
        .await
        .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    let oversized_len = ((MAX_QUIC_WIRE_MSG_BYTES as u32) + 1).to_be_bytes();
    send.write_all(&oversized_len).await.unwrap();
    let _ = send.finish();

    let read_res = srv_oversized.await.unwrap();
    assert!(
        matches!(read_res, Err(EpochError::Io(ref s)) if s.contains("exceeds maximum allowed frame size")),
        "oversized QUIC wire frame must be rejected before allocation: {read_res:?}"
    );
    conn.close(0u32.into(), b"done");

    // 2. Spawn the real `epoch-agent daemon` binary and test:
    //    (a) Stalled mid-frame QUIC stream timeout recovery,
    //    (b) Corrupt chunk rejection in FetchChunksResp without crashing daemon,
    //    (c) Real non-64KiB FastCDC chunk ingestion via FetchChunksResp + FetchChunksReq roundtrip,
    //    (d) Full transactional rollout (StageManifest -> PrepareWave -> ActivateWave -> CommitWave) over QUIC,
    //    (e) Automatic CLOCK_BOOTTIME lease expiration rollback when coordinator stops sending messages.
    let tmp = TempDir::new().unwrap();
    let root_dir = tmp.path().join("agent-root");
    let layout = AgentFilesystemLayout::under_root(&root_dir);
    layout.ensure_directories().unwrap();
    fs::write(
        layout.root_dir.join("var/lib/epoch/quota-reserve-mib"),
        "1\n",
    )
    .unwrap();

    let arch_tl = "/nix/store/00000000000000000000000000000000-epoch-arch-base";
    let build_store = tmp.path().join("build-store");
    fs::create_dir_all(&build_store).unwrap();

    let env_v1 = seal_secret_bundle(
        "node-daemon-1",
        arch_tl,
        &node_id.public_key,
        None,
        &[SecretEntry {
            name: "api_token".into(),
            owner_user: "root".into(),
            owner_group: "root".into(),
            mode: 0o400,
            plaintext: b"daemon-secret-v1".to_vec(),
        }],
    )
    .unwrap();
    let spec_v1 = NodeOverlaySpec {
        node_id: "node-daemon-1".into(),
        archetype_name: "base".into(),
        archetype_toplevel: arch_tl.into(),
        system_arch: "x86_64-linux".into(),
        rack_id: "r1".into(),
        zone_id: "z1".into(),
        quic_endpoint: "127.0.0.1:9443".into(),
        node_pub: node_id.public_key,
        host_name: "node-daemon-1".into(),
        ipv4_cidr: "10.0.0.1/24".into(),
        machine_id: "0102030405060708090a0b0c0d0e0f01".into(),
        kernel_path: "/nix/store/kernel/bzImage".into(),
        initrd_path: "/nix/store/initrd/initrd".into(),
        secrets_envelope: env_v1,
        traced_files: vec![],
    };
    let (v1_tl, v1_sec_h) = synthesize_node_overlay_closure(&build_store, &spec_v1).unwrap();
    let v1_logical = format!(
        "/nix/store/{}",
        v1_tl.file_name().unwrap().to_string_lossy()
    );
    let (v1_man, v1_chunks_map) = build_nar_chunk_manifest(
        &v1_tl,
        &v1_logical,
        vec![],
        None,
        "cache.epoch.internal-1",
        &store_id,
    )
    .unwrap();
    let v1_chunks: Vec<_> = v1_chunks_map.into_iter().collect();
    assert!(
        v1_man.chunks.iter().all(|c| c.raw_len != 65536),
        "test closure chunk raw_len must not be 64 KiB so bounded decompression is exercised"
    );

    let agent_bin = env!("CARGO_BIN_EXE_epoch-agent");
    let mut child = Command::new(agent_bin)
        .args([
            "--root",
            root_dir.to_str().unwrap(),
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--node-id",
            "node-daemon-1",
            "--archetype-toplevel",
            arch_tl,
            "--host-key-seed-hex",
            custom_seed_hex,
            "--coordinator-pub-hex",
            &hex::encode(coord_id.public_key),
            "--store-pub-hex",
            &hex::encode(store_id.public_key),
            "--request-timeout-ms",
            "150",
            "--max-requests",
            "7",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn epoch-agent daemon");

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut listen_line = String::new();
    reader.read_line(&mut listen_line).unwrap();
    let bound_addr_str = listen_line
        .split("listening on ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    let daemon_addr: std::net::SocketAddr = bound_addr_str.parse().unwrap();

    // (a) Stalled mid-frame connection (sends only 2 bytes of the 4-byte length prefix and hangs)
    let stalled_conn = client_ep
        .connect(daemon_addr, "epoch-node")
        .unwrap()
        .await
        .unwrap();
    let (mut stalled_send, _stalled_recv) = stalled_conn.open_bi().await.unwrap();
    stalled_send.write_all(&[0x00, 0x01]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    stalled_conn.close(0u32.into(), b"stalled-done");

    // (b) Corrupt chunk in FetchChunksResp returns StageAck { ok: false } without crashing daemon
    let bad_zstd = zstd_compress(b"corrupted-chunk-payload").unwrap();
    let bad_resp = quic_rpc_call(
        &client_ep,
        daemon_addr,
        &EpochWireMsg::FetchChunksResp {
            chunks: vec![([0xee; 32], bad_zstd)],
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(bad_resp, EpochWireMsg::StageAck { ok: false, ref error, .. } if error.as_deref().unwrap_or("").contains("Chunk BLAKE3 digest mismatch")),
        "corrupt chunk in FetchChunksResp must return StageAck(ok=false), got {bad_resp:?}"
    );

    // (c) Valid non-64KiB FastCDC chunks ingested via FetchChunksResp and queried back via FetchChunksReq
    let push_resp = quic_rpc_call(
        &client_ep,
        daemon_addr,
        &EpochWireMsg::FetchChunksResp {
            chunks: v1_chunks.clone(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(push_resp, EpochWireMsg::StageAck { ok: true, .. }));

    let first_hash = v1_chunks[0].0;
    let fetch_resp = quic_rpc_call(
        &client_ep,
        daemon_addr,
        &EpochWireMsg::FetchChunksReq {
            tx_epoch: 10,
            missing_norm_blake3: vec![first_hash],
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(fetch_resp, EpochWireMsg::FetchChunksResp { ref chunks } if chunks.len() == 1 && chunks[0].0 == first_hash)
    );

    // (d) Full transactional rollout (StageManifest -> PrepareWave -> ActivateWave -> CommitWave)
    let waves = vec![WaveSpec {
        wave_id: "wave-daemon".into(),
        depends_on: vec![],
        node_ids: vec!["node-daemon-1".into()],
        max_unavailable: 0,
        lease_ttl_ms: 30_000,
        reboot_lease_ttl_ms: 120_000,
        probes: HealthOracleSpec::default(),
    }];
    let nodes = vec![NodePlanEntry {
        node_id: "node-daemon-1".into(),
        system_arch: "x86_64-linux".into(),
        rack_id: "r1".into(),
        zone_id: "z1".into(),
        quic_endpoint: daemon_addr.to_string(),
        node_pub: node_id.public_key,
        toplevel_path: v1_logical.clone(),
        kernel_path: "/nix/store/kernel/bzImage".into(),
        initrd_path: "/nix/store/initrd/initrd".into(),
        secrets_envelope_hash: v1_sec_h,
        closure_manifests_merkle_root: v1_sec_h,
        p2p_parent_node_id: None,
        p2p_children_node_ids: vec![],
    }];
    let plan =
        compile_signed_execution_plan("c-daemon", 10, [0u8; 32], &waves, &[], nodes, 4, &coord_id)
            .unwrap();

    let stage_ack = quic_rpc_call(
        &client_ep,
        daemon_addr,
        &EpochWireMsg::StageManifest {
            tx_epoch: 10,
            plan,
            manifests: vec![v1_man.clone()],
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(stage_ack, EpochWireMsg::StageAck { ok: true, .. }),
        "StageManifest failed: {stage_ack:?}"
    );

    let prep_ack = quic_rpc_call(
        &client_ep,
        daemon_addr,
        &EpochWireMsg::PrepareWave {
            tx_epoch: 10,
            wave_id: "wave-daemon".into(),
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(prep_ack, EpochWireMsg::PrepareAck { ok: true, .. }),
        "PrepareWave failed: {prep_ack:?}"
    );

    let act_msg = sign_activate_wave(&coord_id, 10, "wave-daemon", 30_000).unwrap();
    let act_resp = quic_rpc_call(&client_ep, daemon_addr, &act_msg)
        .await
        .unwrap();
    assert!(
        matches!(
            act_resp,
            EpochWireMsg::HealthAttestation {
                healthy: true,
                tx_epoch: 10,
                ..
            }
        ),
        "ActivateWave failed: {act_resp:?}"
    );

    let commit_msg = sign_commit_wave(&coord_id, 10, "wave-daemon", vec![]).unwrap();
    let commit_resp = quic_rpc_call(&client_ep, daemon_addr, &commit_msg)
        .await
        .unwrap();
    assert!(
        matches!(
            commit_resp,
            EpochWireMsg::HealthAttestation {
                healthy: true,
                ref diagnostic,
                ..
            } if diagnostic == "COMMITTED"
        ),
        "CommitWave failed: {commit_resp:?}"
    );

    // Wait for daemon to exit after serving 7 valid requests
    let status = child.wait().unwrap();
    assert!(status.success());

    // Verify `epoch-agent status` reports COMMITTED at highest_tx_epoch=10
    let status_out = Command::new(agent_bin)
        .args(["--root", root_dir.to_str().unwrap(), "status"])
        .output()
        .unwrap();
    let status_str = String::from_utf8_lossy(&status_out.stdout);
    assert!(
        status_str.contains("phase=COMMITTED highest_tx_epoch=10"),
        "unexpected status output: {status_str}"
    );
    let unsealed_secret =
        fs::read_to_string(layout.current_secrets_link.join("api_token")).unwrap();
    assert_eq!(unsealed_secret, "daemon-secret-v1");

    // (e) Spawn daemon again, activate tx_epoch=11 with 60ms lease, then send NO messages for 200ms
    // (simulating coordinator SIGKILL) -> periodic lease_ticker must roll back to G_10 automatically!
    let mut child2 = Command::new(agent_bin)
        .args([
            "--root",
            root_dir.to_str().unwrap(),
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--node-id",
            "node-daemon-1",
            "--archetype-toplevel",
            arch_tl,
            "--host-key-seed-hex",
            custom_seed_hex,
            "--coordinator-pub-hex",
            &hex::encode(coord_id.public_key),
            "--store-pub-hex",
            &hex::encode(store_id.public_key),
            "--request-timeout-ms",
            "150",
            "--max-requests",
            "4",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn second epoch-agent daemon");

    let mut reader2 = BufReader::new(child2.stdout.take().unwrap());
    let mut listen_line2 = String::new();
    reader2.read_line(&mut listen_line2).unwrap();
    let daemon_addr2: std::net::SocketAddr = listen_line2
        .split("listening on ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();

    let nodes_11 = vec![NodePlanEntry {
        node_id: "node-daemon-1".into(),
        system_arch: "x86_64-linux".into(),
        rack_id: "r1".into(),
        zone_id: "z1".into(),
        quic_endpoint: daemon_addr2.to_string(),
        node_pub: node_id.public_key,
        toplevel_path: v1_logical.clone(),
        kernel_path: "/nix/store/kernel/bzImage".into(),
        initrd_path: "/nix/store/initrd/initrd".into(),
        secrets_envelope_hash: v1_sec_h,
        closure_manifests_merkle_root: v1_sec_h,
        p2p_parent_node_id: None,
        p2p_children_node_ids: vec![],
    }];
    let plan_11 = compile_signed_execution_plan(
        "c-daemon",
        11,
        [0u8; 32],
        &waves,
        &[],
        nodes_11,
        4,
        &coord_id,
    )
    .unwrap();

    quic_rpc_call(
        &client_ep,
        daemon_addr2,
        &EpochWireMsg::StageManifest {
            tx_epoch: 11,
            plan: plan_11,
            manifests: vec![v1_man],
        },
    )
    .await
    .unwrap();
    quic_rpc_call(
        &client_ep,
        daemon_addr2,
        &EpochWireMsg::PrepareWave {
            tx_epoch: 11,
            wave_id: "wave-daemon".into(),
        },
    )
    .await
    .unwrap();
    let act_11 = sign_activate_wave(&coord_id, 11, "wave-daemon", 60).unwrap();
    quic_rpc_call(&client_ep, daemon_addr2, &act_11)
        .await
        .unwrap();

    // Sleep 200ms with zero QUIC traffic so the daemon's background lease_ticker fires
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Inspect status BEFORE sending the 4th request -> must already be ROLLED_BACK!
    let status_mid = Command::new(agent_bin)
        .args(["--root", root_dir.to_str().unwrap(), "status"])
        .output()
        .unwrap();
    let status_mid_str = String::from_utf8_lossy(&status_mid.stdout);
    assert!(
        status_mid_str.contains("phase=ROLLED_BACK highest_tx_epoch=11"),
        "background lease ticker must roll back idle daemon without incoming packets, got: {status_mid_str}"
    );

    // Send 4th request (stale FetchChunksReq tx_epoch=5 < 11) to verify stale epoch rejection and finish child2
    let stale_req = EpochWireMsg::FetchChunksReq {
        tx_epoch: 5,
        missing_norm_blake3: vec![first_hash],
    };
    let stale_resp = quic_rpc_call(&client_ep, daemon_addr2, &stale_req)
        .await
        .unwrap();
    assert!(
        matches!(stale_resp, EpochWireMsg::StageAck { ok: false, ref error, .. } if error.as_deref().unwrap_or("").contains("Stale tx_epoch fenced"))
    );
    assert!(child2.wait().unwrap().success());
}

#[test]
fn test_head_to_head_benchmark_suite_planes_1_to_4() {
    use epoch::benchmarks::{
        run_plane2_transport_benchmark, run_plane34_fault_and_footprint_benchmark,
        run_worker_pool_eval_scale,
    };
    use std::path::Path;

    // 1. Plane 1: CoW Worker Pool + BLAKE3 EvalCache scaling
    let p1 = run_worker_pool_eval_scale(50, 4, 2).expect("Plane 1 worker pool benchmark");
    assert_eq!(p1.nodes, 50);
    assert_eq!(p1.warm_cache_hits, 49);
    assert_eq!(p1.warm_worker_evals, 1);
    assert!(p1.warm_eval_1_node_changed_ms < p1.cold_eval_ms);

    // 2. Plane 2: Store-Hash-Normalized FastCDC + Rack-Aware QUIC/mTLS P2P
    let p2 = run_plane2_transport_benchmark(&[10, 50], 5, 4).expect("Plane 2 transport benchmark");
    assert!(
        p2.deduplication.epoch_normalized_dedup_ratio_pct > 95.0,
        "expected >95% normalized FastCDC chunk reuse across 512 rewritten store hashes, got {}%",
        p2.deduplication.epoch_normalized_dedup_ratio_pct
    );
    assert!(
        p2.deduplication.unnormalized_fastcdc_dedup_ratio_pct < 5.0,
        "unnormalized FastCDC should suffer cascading boundary shifts"
    );
    assert!(p2.live_quic_mtls_transfer.wire_reduction_factor_x > 4.0);
    assert!(p2.fleet_scaling[1].egress_reduction_vs_raw_nar_x > 100.0);

    // 3. Plane 3 & 4: Target Footprint, Secret Swap Skew, and Gate 4 Fault Convergence
    let colmena_tpl = Path::new("/tmp/investigation/colmena/src/nix/host/key_uploader.template.sh");
    let p34 = run_plane34_fault_and_footprint_benchmark(colmena_tpl, 10)
        .expect("Plane 3 & 4 fault and footprint benchmark");
    assert!(p34.target_footprint.epoch_agent_within_5mb_target);
    assert!(p34.target_footprint.epoch_agent_mlockall_supported);
    assert_eq!(p34.target_footprint.epoch_agent_oom_score_adj, -1000);
    assert_eq!(
        p34.target_footprint
            .epoch_agent_rollback_subprocesses_spawned,
        0
    );

    assert_eq!(p34.secret_swap_skew.epoch_rename_exchange_enoent_errors, 0);
    assert_eq!(p34.secret_swap_skew.epoch_rename_exchange_torn_reads, 0);
    assert_eq!(p34.secret_swap_skew.epoch_pre_activation_skew_samples, 0);
    assert!(
        !p34.secret_swap_skew
            .epoch_post_failed_activation_secret_corrupted
    );
    assert!(p34.secret_swap_skew.epoch_retired_generation_zero_wiped);
    assert!(p34.secret_swap_skew.epoch_unattended_reboot_secret_survived);

    assert!(p34.secret_swap_skew.colmena_pre_activation_skew_rate_pct > 99.0);
    assert!(
        p34.secret_swap_skew
            .colmena_post_failed_activation_secret_corrupted
    );
    assert!(
        p34.secret_swap_skew
            .colmena_post_activation_deadlock_confirmed
    );
    assert!(
        !p34.secret_swap_skew
            .colmena_unattended_reboot_secret_survived
    );

    assert_eq!(p34.gate4_verification_reports.len(), 5);
    assert!(p34.gate4_verification_reports.iter().all(|r| r.passed));
}

#[test]
fn test_regression_multi_ref_hash_order_crossing_and_mode0400_zero_wipe() {
    use epoch::plane1_eval::synthesize_node_overlay_closure;
    use epoch::plane2_store::{
        TargetChunkIndex, build_nar_chunk_manifest, ingest_fetched_chunks,
        reconstruct_and_register_store_path, serialize_nar,
    };
    use epoch::plane3_secrets::{prepare_generation_secrets, zero_wipe_secret_generation};
    use std::io::{Read, Seek, SeekFrom};

    let tmp = TempDir::new().unwrap();
    let store_key = Ed25519Identity::from_seed([0x66; 32]).unwrap();

    // 1. Multi-reference hash-order-crossing normalization + boundary-straddling test:
    // In v1, hash(glibc) = "aaaa..." < hash(openssl) = "bbbb...".
    // In v2, openssl is rebuilt and gets hash(openssl) = "0000..." < hash(glibc) = "aaaa...".
    // Sorting references by derivation name suffix ("glibc-2.40", "openssl-3.3.1") must keep
    // EPOCH_REF_0001 = glibc and EPOCH_REF_0002 = openssl invariant across the rebuild!
    let glibc_ref = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.40".to_string();
    let openssl_v1 = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.3.1".to_string();
    let openssl_v2 = "/nix/store/00000000000000000000000000000000-openssl-3.3.1".to_string();
    let self_v1 = "/nix/store/cccccccccccccccccccccccccccccccc-app-1.0".to_string();
    let self_v2 = "/nix/store/dddddddddddddddddddddddddddddddd-app-1.0".to_string();

    let dir_v1 = tmp.path().join("app-v1");
    let dir_v2 = tmp.path().join("app-v2");
    fs::create_dir_all(&dir_v1).unwrap();
    fs::create_dir_all(&dir_v2).unwrap();

    let mut payload_v1 = Vec::with_capacity(512 * 3000);
    let mut payload_v2 = Vec::with_capacity(512 * 3000);
    for blk in 0..512u32 {
        let mut s = blk.wrapping_mul(0x9e37_79b9).wrapping_add(0x1234_5678);
        for _ in 0..3000 {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            payload_v1.push((s & 0xff) as u8);
            payload_v2.push((s & 0xff) as u8);
        }
        let line1 = format!("rpath={glibc_ref}/lib:{openssl_v1}/lib:{self_v1}/bin\n");
        let line2 = format!("rpath={glibc_ref}/lib:{openssl_v2}/lib:{self_v2}/bin\n");
        payload_v1.extend_from_slice(line1.as_bytes());
        payload_v2.extend_from_slice(line2.as_bytes());
    }
    fs::write(dir_v1.join("app.bin"), &payload_v1).unwrap();
    fs::write(dir_v2.join("app.bin"), &payload_v2).unwrap();
    fs::write(dir_v1.join("build-id"), "v1\n").unwrap();
    fs::write(dir_v2.join("build-id"), "v2\n").unwrap();

    let (m1, c1) = build_nar_chunk_manifest(
        &dir_v1,
        &self_v1,
        vec![self_v1.clone(), openssl_v1.clone(), glibc_ref.clone()],
        None,
        "store-key",
        &store_key,
    )
    .unwrap();
    let (m2, c2) = build_nar_chunk_manifest(
        &dir_v2,
        &self_v2,
        vec![self_v2.clone(), openssl_v2.clone(), glibc_ref.clone()],
        None,
        "store-key",
        &store_key,
    )
    .unwrap();

    let mut idx = TargetChunkIndex::default();
    let c1_vec: Vec<_> = c1.iter().map(|(h, v)| (*h, v.clone())).collect();
    ingest_fetched_chunks(&mut idx, std::slice::from_ref(&m1), &c1_vec).unwrap();

    let missing = idx.find_missing_chunks(std::slice::from_ref(&m2));
    let reused_bytes: u64 = m2
        .chunks
        .iter()
        .filter(|c| !missing.contains(&c.norm_blake3))
        .map(|c| c.raw_len as u64)
        .sum();
    let total_bytes: u64 = m2.chunks.iter().map(|c| c.raw_len as u64).sum();
    let reuse_pct = (reused_bytes as f64) * 100.0 / (total_bytes as f64);
    assert!(
        reuse_pct > 95.0,
        "multi-reference hash-order-crossing rebuild must preserve >95% chunk reuse, got {reuse_pct:.2}%"
    );

    // Ingest only the missing delta chunks and verify bit-for-bit NAR reconstruction of v2
    let delta_vec: Vec<_> = missing.iter().map(|h| (*h, c2[h].clone())).collect();
    ingest_fetched_chunks(&mut idx, std::slice::from_ref(&m2), &delta_vec).unwrap();
    let unpack_store = tmp.path().join("unpack-store/nix/store");
    let sqlite_db = tmp.path().join("unpack-store/db.sqlite");
    fs::create_dir_all(&unpack_store).unwrap();
    let unpacked_v2 = reconstruct_and_register_store_path(
        &unpack_store,
        &sqlite_db,
        &m2,
        &idx,
        &[("store-key".into(), store_key.public_key)],
    )
    .unwrap();
    assert_eq!(
        serialize_nar(&unpacked_v2).unwrap(),
        serialize_nar(&dir_v2).unwrap(),
        "reconstructed v2 store path must match original NAR bit-for-bit across chunk boundaries"
    );

    // 2. Mode-0400 secret inode page-cache 0x00 zero-wipe verification via open file descriptor:
    let host_key = Ed25519Identity::from_seed([0x77; 32]).unwrap();
    let arch_tl = "/nix/store/00000000000000000000000000000000-arch";
    let env_bundle = seal_secret_bundle(
        "node-wipe",
        arch_tl,
        &host_key.public_key,
        None,
        &[SecretEntry {
            name: "ro_secret".into(),
            owner_user: "root".into(),
            owner_group: "root".into(),
            mode: 0o400,
            plaintext: b"top-secret-0400-data".to_vec(),
        }],
    )
    .unwrap();
    let store_dir = tmp.path().join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let spec = NodeOverlaySpec {
        node_id: "node-wipe".into(),
        archetype_name: "base".into(),
        archetype_toplevel: arch_tl.into(),
        system_arch: "x86_64-linux".into(),
        rack_id: "rack-0".into(),
        zone_id: "zone-a".into(),
        quic_endpoint: "127.0.0.1:9443".into(),
        node_pub: host_key.public_key,
        host_name: "node-wipe".into(),
        ipv4_cidr: "10.0.0.9/24".into(),
        machine_id: "0123456789abcdef0123456789abcdef".into(),
        kernel_path: "/nix/store/k/bzImage".into(),
        initrd_path: "/nix/store/i/initrd".into(),
        secrets_envelope: env_bundle,
        traced_files: vec![],
    };
    let (tl, _) = synthesize_node_overlay_closure(&store_dir, &spec).unwrap();
    let ramfs_root = tmp.path().join("ramfs-secrets");
    prepare_generation_secrets(&tl, &ramfs_root, 7, "node-wipe", arch_tl, &host_key, None).unwrap();

    let secret_file_path = ramfs_root.join("gen-7/ro_secret");
    let mut open_fd = fs::File::open(&secret_file_path).unwrap();
    let mut before_wipe = Vec::new();
    open_fd.read_to_end(&mut before_wipe).unwrap();
    assert_eq!(before_wipe, b"top-secret-0400-data");

    zero_wipe_secret_generation(&ramfs_root, 7).unwrap();
    assert!(!secret_file_path.exists());

    open_fd.seek(SeekFrom::Start(0)).unwrap();
    let mut after_wipe = Vec::new();
    open_fd.read_to_end(&mut after_wipe).unwrap();
    assert_eq!(
        after_wipe,
        vec![0u8; 20],
        "open inode descriptor on mode-0400 secret file must read back 0x00 bytes after zero_wipe_secret_generation"
    );
}

#[test]
fn test_dod_zero_copy_cbor_and_in_place_normalizer_edge_cases() {
    use epoch::plane2_store::{
        TargetChunkIndex, denormalize_nar_store_hashes, denormalize_nar_store_hashes_in_place,
        ingest_fetched_chunk_slices, normalize_nar_store_hashes,
        normalize_nar_store_hashes_in_place, zstd_compress,
    };
    use epoch::schema::{ChunkDescriptor, NarChunkManifest};
    use epoch::watchdog_boot::pin_agent_memory_and_oom_score;
    use serde::{Deserialize, Serialize};

    // 1. Verify zero-copy borrowed deserialization (`cbor::from_slice_borrowed`)
    mod borrowed_bytes {
        use serde::de::Visitor;
        use serde::{Deserializer, Serializer};
        use std::fmt;

        pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(v)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<&'de [u8], D::Error> {
            struct BorrowedBytesVisitor;
            impl<'de> Visitor<'de> for BorrowedBytesVisitor {
                type Value = &'de [u8];
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a borrowed byte slice")
                }
                fn visit_borrowed_bytes<E: serde::de::Error>(
                    self,
                    v: &'de [u8],
                ) -> Result<Self::Value, E> {
                    Ok(v)
                }
            }
            d.deserialize_bytes(BorrowedBytesVisitor)
        }
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct ZeroCopyPacket<'a> {
        node_id: &'a str,
        #[serde(borrow, with = "borrowed_bytes")]
        payload: &'a [u8],
        epoch: u64,
    }

    let pkt = ZeroCopyPacket {
        node_id: "rack-07-node-42",
        payload: &[0xde, 0xad, 0xbe, 0xef, 0x00, 0xff],
        epoch: 99_999,
    };
    let encoded = cbor::to_vec_deterministic(&pkt).expect("deterministic cbor");
    let decoded: ZeroCopyPacket<'_> =
        cbor::from_slice_borrowed(&encoded).expect("zero-copy borrowed decode");
    assert_eq!(decoded, pkt);
    // Verify the decoded slice pointers point directly into `encoded` buffer (zero-copy!)
    let enc_range = encoded.as_ptr_range();
    assert!(enc_range.contains(&decoded.node_id.as_ptr()));
    assert!(enc_range.contains(&decoded.payload.as_ptr()));

    // Verify trailing bytes are rejected
    let mut with_trailing = encoded.clone();
    with_trailing.push(0x00);
    assert!(cbor::from_slice_borrowed::<ZeroCopyPacket<'_>>(&with_trailing).is_err());

    // 2. Verify TargetChunkIndex Arc<[u8]> + serde_arc_chunk_map + ingest_fetched_chunk_slices (> 8 chunks & <= 8 chunks)
    let mut descriptors = Vec::new();
    let mut zstd_pairs = Vec::new();
    for i in 0..12u8 {
        let raw = vec![i.wrapping_mul(17); 1024 + (i as usize) * 13];
        let h = *blake3::hash(&raw).as_bytes();
        let z = zstd_compress(&raw).unwrap();
        descriptors.push(ChunkDescriptor {
            norm_blake3: h,
            raw_len: raw.len() as u32,
            zstd_len: z.len() as u32,
        });
        zstd_pairs.push((h, z));
    }
    let manifest = NarChunkManifest {
        store_path: "/nix/store/11111111111111111111111111111111-dod-test".into(),
        nar_sha256: [0xaa; 32],
        nar_size: 16384,
        reference_hashes: vec![],
        references_full: vec![],
        deriver: None,
        store_sig: "cache.test:aaaa".into(),
        chunks: descriptors,
    };

    // Ingest small batch (<= 8) and large batch (> 8) via borrowed slices
    let borrowed_slices: Vec<([u8; 32], &[u8])> =
        zstd_pairs.iter().map(|(h, z)| (*h, z.as_slice())).collect();
    let mut idx = TargetChunkIndex::default();
    ingest_fetched_chunk_slices(
        &mut idx,
        std::slice::from_ref(&manifest),
        &borrowed_slices[..4],
    )
    .unwrap();
    assert_eq!(idx.chunks.len(), 4);
    ingest_fetched_chunk_slices(&mut idx, std::slice::from_ref(&manifest), &borrowed_slices)
        .unwrap();
    assert_eq!(idx.chunks.len(), 12);

    // Roundtrip TargetChunkIndex through compact CBOR byte-string map
    let idx_bytes = cbor::to_vec_deterministic(&idx).unwrap();
    let idx_rt: TargetChunkIndex = cbor::from_slice(&idx_bytes).unwrap();
    assert_eq!(idx_rt.chunks.len(), 12);
    for (h, arc_buf) in &idx.chunks {
        assert_eq!(idx_rt.get_chunk(h), Some(arc_buf.as_ref()));
    }

    // 3. Verify in-place store-hash normalizer edge cases (< 43 bytes, out-of-range ref idx, invalid hex)
    for short_len in [0usize, 1, 11, 42, 43] {
        let orig = vec![b'/'; short_len];
        let mut buf = orig.clone();
        normalize_nar_store_hashes_in_place(&mut buf, &[[b'1'; 32]]);
        assert_eq!(buf, normalize_nar_store_hashes(&orig, &[[b'1'; 32]]));
        denormalize_nar_store_hashes_in_place(&mut buf, &[[b'1'; 32]]).unwrap();
        assert_eq!(
            buf,
            denormalize_nar_store_hashes(&orig, &[[b'1'; 32]]).unwrap()
        );
    }

    // Out-of-bounds reference index (0099 when only 1 ref hash exists) must return Err
    let oob = b"prefix/nix/store/\x00EPOCH_REF_0099_________________-pkg/bin".to_vec();
    let mut oob_in_place = oob.clone();
    assert!(denormalize_nar_store_hashes_in_place(&mut oob_in_place, &[[b'1'; 32]]).is_err());
    assert!(denormalize_nar_store_hashes(&oob, &[[b'1'; 32]]).is_err());

    // 4. Verify pin_agent_memory_and_oom_score memoization returns consistent results
    let first_pin = pin_agent_memory_and_oom_score();
    let second_pin = pin_agent_memory_and_oom_score();
    assert_eq!(first_pin, second_pin);
}

#[test]
fn test_adversarial_cbor_edge_cases_and_compact_wire_encoding() {
    use epoch::plane2_store::{
        denormalize_nar_store_hashes, denormalize_nar_store_hashes_in_place,
        normalize_nar_store_hashes, normalize_nar_store_hashes_in_place,
    };
    use epoch::schema::EpochWireMsg;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    // 1. Bug 1a regression: Overlong 64-byte CBOR byte string (0x58, 0x40, ...) into [u8; 32] must Err
    let mut bstr_64 = vec![0x58, 0x40];
    bstr_64.extend_from_slice(&[0xaa; 64]);
    assert!(
        cbor::from_slice::<[u8; 32]>(&bstr_64).is_err(),
        "64-byte CBOR byte string must not silently truncate into [u8; 32]"
    );

    // Exact 32-byte CBOR byte string (0x58, 0x20, ...) into [u8; 32] must succeed
    let mut bstr_32 = vec![0x58, 0x20];
    bstr_32.extend_from_slice(&[0xbb; 32]);
    assert_eq!(cbor::from_slice::<[u8; 32]>(&bstr_32).unwrap(), [0xbb; 32]);

    // 2. Bug 1b regression: Overlong CBOR array [1, 2, 3] into [u8; 2] or (u8, u8) (both root and nested) must Err
    let arr_3 = [0x83, 0x01, 0x02, 0x03];
    assert!(
        cbor::from_slice::<[u8; 2]>(&arr_3).is_err(),
        "3-element CBOR array must not silently truncate into [u8; 2]"
    );
    assert!(
        cbor::from_slice::<(u8, u8)>(&arr_3).is_err(),
        "3-element CBOR array must not silently truncate into (u8, u8)"
    );

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct NestedPairStruct {
        pair: (u8, u8),
        after: u8,
    }
    // Map {"after": 9, "pair": [1, 2, 3]} where "pair" has 3 elements instead of 2
    let mut nested_bad = Vec::new();
    nested_bad.push(0xa2); // map(2)
    nested_bad.extend_from_slice(&[0x64, b'p', b'a', b'i', b'r', 0x83, 0x01, 0x02, 0x03]);
    nested_bad.extend_from_slice(&[0x65, b'a', b'f', b't', b'e', b'r', 0x09]);
    assert!(
        cbor::from_slice::<NestedPairStruct>(&nested_bad).is_err(),
        "unconsumed array element inside struct field must return Err"
    );

    // 3. Bug 2 regression: Negative CBOR integers < i64::MIN must not wrap around to 0 or i64::MAX
    // major=1, arg=u64::MAX -> value = -1 - u64::MAX = -18446744073709551616
    let neg_u64_max = [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(
        cbor::from_slice::<i64>(&neg_u64_max).is_err(),
        "CBOR -2^64 must return Err when deserializing into i64 (must not wrap to 0)"
    );
    assert_eq!(
        cbor::from_slice::<i128>(&neg_u64_max).unwrap(),
        -18_446_744_073_709_551_616i128
    );

    // major=1, arg=1<<63 -> value = -1 - 2^63 = i64::MIN - 1 = -9223372036854775809
    let neg_below_i64_min = [0x3b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(
        cbor::from_slice::<i64>(&neg_below_i64_min).is_err(),
        "CBOR (i64::MIN - 1) must return Err when deserializing into i64 (must not wrap to i64::MAX)"
    );
    assert_eq!(
        cbor::from_slice::<i128>(&neg_below_i64_min).unwrap(),
        (i64::MIN as i128) - 1
    );

    // major=1, arg=(1<<63)-1 -> value = i64::MIN (must succeed for i64!)
    let neg_exact_i64_min = [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        cbor::from_slice::<i64>(&neg_exact_i64_min).unwrap(),
        i64::MIN
    );

    // 4. Bug 3 regression: Deeply nested CBOR (> MAX_CBOR_DEPTH = 128) must Err cleanly without stack overflow
    let mut deep_cbor = vec![0x81; 200]; // 200 nested 1-element arrays
    deep_cbor.push(0x00);
    let mut pos = 0;
    assert!(
        cbor::decode_value(&deep_cbor, &mut pos).is_err(),
        "decode_value must reject CBOR depth > 128"
    );
    assert!(
        cbor::from_slice::<serde::de::IgnoredAny>(&deep_cbor).is_err(),
        "from_slice must reject CBOR depth > 128"
    );

    // 5. Bug 4 regression: EpochWireMsg::FetchChunksResp must encode chunks as compact Major Type 2 byte strings
    let chunk_payload = vec![0xefu8; 65_536];
    let resp_msg = EpochWireMsg::FetchChunksResp {
        chunks: vec![([0x42; 32], chunk_payload.clone())],
    };
    let wire_bytes = cbor::to_vec_deterministic(&resp_msg).unwrap();
    assert!(
        wire_bytes.len() < 65_650,
        "FetchChunksResp wire encoding for 64 KiB chunk should be < 65,650 B (compact Major Type 2 bytes), got {} B",
        wire_bytes.len()
    );
    let decoded_resp: EpochWireMsg = cbor::from_slice(&wire_bytes).unwrap();
    assert_eq!(decoded_resp, resp_msg);

    // 6. Edge case: Map keys with embedded NUL bytes and non-ASCII UTF-8 characters sort in RFC 8949 §4.2.1 order
    let mut nul_utf8_map: BTreeMap<String, u32> = BTreeMap::new();
    nul_utf8_map.insert("z".into(), 1);
    nul_utf8_map.insert("a\0b".into(), 2);
    nul_utf8_map.insert("a\0a".into(), 3);
    nul_utf8_map.insert("é".into(), 4); // 2 UTF-8 bytes: [0xc3, 0xa9]
    nul_utf8_map.insert("λ".into(), 5); // 2 UTF-8 bytes: [0xce, 0xbb]
    nul_utf8_map.insert("".into(), 6); // 0 UTF-8 bytes
    let map_cbor = cbor::to_vec_deterministic(&nul_utf8_map).unwrap();
    // Expected RFC 8949 deterministic key order:
    // len 0: "" (0x60)
    // len 1: "z" (0x61 0x7a)
    // len 2: "é" (0x62 0xc3 0xa9), "λ" (0x62 0xce 0xbb)
    // len 3: "a\0a" (0x63 0x61 0x00 0x61), "a\0b" (0x63 0x61 0x00 0x62)
    let mut pos = 0;
    let ast = cbor::decode_value(&map_cbor, &mut pos).unwrap();
    if let cbor::CborValue::Map(entries) = ast {
        let keys: Vec<String> = entries
            .into_iter()
            .map(|(k, _)| match k {
                cbor::CborValue::Text(s) => s,
                other => panic!("expected text key, got {other:?}"),
            })
            .collect();
        assert_eq!(keys, vec!["", "z", "é", "λ", "a\0a", "a\0b"]);
    } else {
        panic!("expected CBOR Map");
    }

    // 7. Edge case: Partial `/nix/store/` prefixes immediately adjacent to valid `/nix/store/<32-char>-<name>` references
    let ref_hash: [u8; 32] = *b"0123456789abcdfghijklmnpqrsvwxyz";
    let mut adjacent_stream = Vec::new();
    adjacent_stream
        .extend_from_slice(b"/nix/store//nix/store/0123456789abcdfghijklmnpqrsvwxyz-glibc/lib:");
    adjacent_stream
        .extend_from_slice(b"/nix/store/short/nix/store/0123456789abcdfghijklmnpqrsvwxyz-gcc/bin");

    let expected_norm = normalize_nar_store_hashes(&adjacent_stream, &[ref_hash]);
    let mut in_place_buf = adjacent_stream.clone();
    normalize_nar_store_hashes_in_place(&mut in_place_buf, &[ref_hash]);
    assert_eq!(
        in_place_buf, expected_norm,
        "in-place normalizer must handle partial /nix/store/ prefixes adjacent to valid store references"
    );
    assert_ne!(in_place_buf, adjacent_stream);

    denormalize_nar_store_hashes_in_place(&mut in_place_buf, &[ref_hash]).unwrap();
    assert_eq!(in_place_buf, adjacent_stream);
    assert_eq!(
        denormalize_nar_store_hashes(&expected_norm, &[ref_hash]).unwrap(),
        adjacent_stream
    );
}

#[test]
fn test_plane1_native_aterm_drv_synthesis_and_archetype_eval_cache() {
    use epoch::plane1_eval::{ArchetypeEvalCache, synthesize_node_overlay_drv_aterm};
    use std::path::Path;

    let tmp = TempDir::new().unwrap();
    let drv_dir = tmp.path().join("store");

    let arch_drv =
        "/nix/store/6djg3xwp9gpr9k42hyqcq0s2jym8jjj5-nixos-system-nixos-26.11.20261023.3ec6363.drv";
    let drv1 = synthesize_node_overlay_drv_aterm(
        Some(&drv_dir),
        "node-1",
        "edge-api",
        arch_drv,
        "x86_64-linux",
        "rack-1",
        "zone-1",
        "10.20.0.2:9443",
        "node-1",
        "10.20.0.2/24",
        "0102030405060708090a0b0c0d0e0f00",
        "sealed:chacha20poly1305:node-1",
    )
    .expect("synthesize node-1 drv");
    // Must match Nix's canonical derivationStrict SHA-256 store path bit-for-bit!
    assert_eq!(
        drv1,
        "/nix/store/11fy37dg67z3iphmzfdgiysq3kzkxxdp-epoch-node-node-1.drv"
    );

    // Verify deterministic hash stability
    let drv1_again = synthesize_node_overlay_drv_aterm(
        None,
        "node-1",
        "edge-api",
        arch_drv,
        "x86_64-linux",
        "rack-1",
        "zone-1",
        "10.20.0.2:9443",
        "node-1",
        "10.20.0.2/24",
        "0102030405060708090a0b0c0d0e0f00",
        "sealed:chacha20poly1305:node-1",
    )
    .unwrap();
    assert_eq!(drv1, drv1_again);

    // Changing ipv4 parameter must change the content-addressed .drv hash
    let drv1_diff_ip = synthesize_node_overlay_drv_aterm(
        None,
        "node-1",
        "edge-api",
        arch_drv,
        "x86_64-linux",
        "rack-1",
        "zone-1",
        "10.20.0.2:9443",
        "node-1",
        "10.20.0.99/24",
        "0102030405060708090a0b0c0d0e0f00",
        "sealed:chacha20poly1305:node-1",
    )
    .unwrap();
    assert_ne!(drv1, drv1_diff_ip);

    // Plaintext secret leak in envelope must be statically rejected
    let bad_secret = synthesize_node_overlay_drv_aterm(
        None,
        "node-1",
        "edge-api",
        arch_drv,
        "x86_64-linux",
        "rack-1",
        "zone-1",
        "10.20.0.2:9443",
        "node-1",
        "10.20.0.2/24",
        "0102030405060708090a0b0c0d0e0f00",
        "PLAINTEXT_SECRET_LEAK_NODE_1",
    );
    assert!(bad_secret.is_err());

    // Verify ArchetypeEvalCache roundtrip, Merkle key checking, and concurrent save_atomic safety
    let cache_path = tmp.path().join("arch-cache.cbor");
    let mut cache = ArchetypeEvalCache::load(&cache_path).unwrap();
    let shared_root = [0x42u8; 32];
    let key_db = ArchetypeEvalCache::compute_archetype_key(&shared_root, "consensus-db");
    let key_api = ArchetypeEvalCache::compute_archetype_key(&shared_root, "edge-api");
    assert_ne!(key_db, key_api);

    // Non-existent /nix/store path must return None on lookup
    cache.insert(
        "missing-arch",
        key_db,
        "/nix/store/00000000000000000000000000000000-nonexistent.drv".into(),
    );
    assert!(cache.lookup("missing-arch", &key_db).is_none());

    if Path::new(arch_drv).exists() {
        cache.insert("edge-api", key_api, arch_drv.to_owned());
        cache.save_atomic(&cache_path).unwrap();
        let reloaded = ArchetypeEvalCache::load(&cache_path).unwrap();
        assert_eq!(
            reloaded.lookup("edge-api", &key_api).as_deref(),
            Some(arch_drv)
        );
        assert!(reloaded.lookup("edge-api", &key_db).is_none());
    }

    // Concurrent multi-threaded save_atomic test: 8 threads writing disjoint archetype keys concurrently
    let concurrent_cache_path = tmp.path().join("concurrent-arch-cache.cbor");
    std::thread::scope(|s| {
        for t in 0..8usize {
            let p = concurrent_cache_path.clone();
            s.spawn(move || {
                let mut local = ArchetypeEvalCache::default();
                let k = [t as u8; 32];
                local.insert(&format!("arch-{t}"), k, arch_drv.to_owned());
                local.save_atomic(&p).expect("concurrent save_atomic");
            });
        }
    });
    let merged_cache = ArchetypeEvalCache::load(&concurrent_cache_path).unwrap();
    assert_eq!(merged_cache.records.len(), 8);
    for t in 0..8usize {
        assert!(merged_cache.records.contains_key(&format!("arch-{t}")));
    }
}
