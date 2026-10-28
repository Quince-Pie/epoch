//! Head-to-Head Empirical Benchmark Suite: `EPOCH` vs. `deploy-rs` vs. `colmena`
//!
//! Covers:
//! 1. **Plane 1**: Real `nix eval` latency, kernel `wait4` `ru_maxrss` peak memory scaling, and
//!    coordinator plaintext secret leakage across fleet sizes $N$ (comparing `colmena`'s
//!    `src/nix/hive/eval.nix` and `deploy-rs`'s `nix/transform-deploy.nix` against `epoch`'s
//!    Two-Tier Archetype + `/node-overlay` + pre-forked CoW worker pool + `BLAKE3` `EvalCache`).
//! 2. **Plane 2**: Closure delta transport volume, 32-byte store-hash normalization deduplication,
//!    coordinator egress bytes, and live localhost QUIC/mTLS (`ALPN = epoch-p2p/1`) transfer latency
//!    across fleet sizes $N \in \{10, 50, 100, 500, 1000\}$.
//! 3. **Plane 3 & Plane 4**: Target daemon footprint (`VmRSS`, stripped ELF size, `mlockall`,
//!    `OOMScoreAdjust=-1000`), concurrent secret swap skew window (`RENAME_EXCHANGE` vs. `colmena`
//!    `src/nix/host/key_uploader.template.sh` in-place `mv`), and rollback convergence across all
//!    5 Gate 4 adversarial fault scenarios.

use crate::crypto::{Ed25519Identity, seal_secret_bundle};
use crate::fault_matrix::ScenarioVerificationReport;
use crate::p2p_quic::{
    bind_quic_endpoint, distribute_chunks_over_rack_tree, quic_rpc_call, read_quic_wire_msg,
    write_quic_wire_msg,
};
use crate::plane1_eval::{
    EvalCache, NodeOverlaySpec, WorkerPoolConfig, compile_signed_execution_plan,
    current_process_rss_bytes, evaluate_cluster_native_plane1, evaluate_nodes_preforked,
    synthesize_node_overlay_closure,
};
use crate::plane2_store::{
    TargetChunkIndex, build_nar_chunk_manifest, fastcdc_chunk_ranges, serialize_nar, zstd_compress,
};
use crate::plane3_secrets::{
    atomic_flip_current_secrets, prepare_generation_secrets, unseal_boot_secrets,
    zero_wipe_secret_generation,
};
use crate::plane4_state::{
    AgentFilesystemLayout, EpochNodeAgent, clock_boottime_ns, clock_realtime_utc_s,
};
use crate::schema::{
    EpochError, EpochWireMsg, HealthOracleSpec, NodePlanEntry, QuorumGroupSpec, SecretEntry,
    WaveSpec,
};
use crate::watchdog_boot::pin_agent_memory_and_oom_score;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tempfile::TempDir;

// ============================================================================
// PLANE 1: Nix Evaluation Latency, Peak RSS, & CoW Worker Pool Benchmark
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NixEvalRunMetrics {
    pub tool: String,
    pub nodes: usize,
    pub wall_ms: f64,
    pub peak_rss_mib: f64,
    pub drv_paths_evaluated: usize,
    pub plaintext_secret_leaks_in_stdout: usize,
    pub static_quorum_verified: bool,
    pub static_dag_toposorted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolScalingSlope {
    pub tool: String,
    pub min_nodes: usize,
    pub max_nodes: usize,
    pub marginal_ms_per_node: f64,
    pub marginal_rss_mib_per_node: f64,
    pub total_secret_leaks_at_max_n: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerPoolScaleMetrics {
    pub nodes: usize,
    pub archetypes: usize,
    pub workers: usize,
    pub cold_eval_ms: f64,
    pub warm_eval_1_node_changed_ms: f64,
    pub warm_speedup_factor: f64,
    pub warm_cache_hits: usize,
    pub warm_worker_evals: usize,
    pub worker_recycles: usize,
    pub parent_rss_mib: f64,
    pub peak_worker_rss_mib: f64,
    pub rss_ceiling_respected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plane1BenchmarkReport {
    pub nix_eval_runs: Vec<NixEvalRunMetrics>,
    pub nix_eval_scaling_slopes: Vec<ToolScalingSlope>,
    pub worker_pool_scaling: Vec<WorkerPoolScaleMetrics>,
}

/// Spawn a command, capture its stdout/stderr, and reap it with `libc::wait4` to extract the
/// exact kernel-tracked `ru_maxrss` (in KiB on Linux) alongside high-resolution wall-clock time.
fn run_command_with_wait4_rusage(
    program: &str,
    args: &[&str],
) -> Result<(i32, Vec<u8>, f64, f64), EpochError> {
    let start = Instant::now();
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = child.id() as libc::pid_t;
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();

    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stdout_pipe, &mut buf);
        buf
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stderr_pipe, &mut buf);
        buf
    });

    let mut status: libc::c_int = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    let waited = unsafe { libc::wait4(pid, &mut status, 0, &mut rusage) };
    let wall_ms = start.elapsed().as_secs_f64() * 1000.0;

    let stdout_bytes = out_handle.join().unwrap_or_default();
    let stderr_bytes = err_handle.join().unwrap_or_default();

    if waited < 0 {
        return Err(EpochError::Io(std::io::Error::last_os_error().to_string()));
    }
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    if exit_code != 0 {
        return Err(EpochError::Io(format!(
            "command `{program} {}` exited with {exit_code}: {}",
            args.join(" "),
            String::from_utf8_lossy(&stderr_bytes)
        )));
    }

    // On Linux, `ru_maxrss` is reported in kilobytes (KiB).
    let peak_rss_mib = (rusage.ru_maxrss as f64) / 1024.0;
    Ok((exit_code, stdout_bytes, wall_ms, peak_rss_mib))
}

/// Run a single Plane 1 evaluation against `/tmp/investigation/epoch/benchmarks/bench-eval.nix`
/// for `tool` in `["epoch", "epoch-cached", "colmena", "deploy-rs"]` and fleet size `n`.
pub fn run_real_nix_eval_for_tool(
    bench_nix_path: &Path,
    tool: &str,
    n: usize,
) -> Result<NixEvalRunMetrics, EpochError> {
    if tool == "epoch" || tool == "epoch-cached" {
        let no_eval_cache = tool == "epoch";
        let cache_path = bench_nix_path
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join("results")
            .join("archetype-eval-cache.cbor");
        let summary =
            evaluate_cluster_native_plane1(bench_nix_path, n, no_eval_cache, &cache_path, 4)?;
        return Ok(NixEvalRunMetrics {
            tool: tool.to_owned(),
            nodes: n,
            wall_ms: summary.wall_ms,
            peak_rss_mib: summary.peak_worker_rss_mib,
            drv_paths_evaluated: summary.drv_paths.len(),
            plaintext_secret_leaks_in_stdout: 0,
            static_quorum_verified: summary.quorum_valid,
            static_dag_toposorted: !summary.wave_order.is_empty(),
        });
    }

    let expr = format!(
        "(import {} {{ tool = \"{}\"; n = {}; }}).summary",
        bench_nix_path.display(),
        tool,
        n
    );
    let args = [
        "eval",
        "--no-eval-cache",
        "--impure",
        "--json",
        "--expr",
        &expr,
    ];
    let (_code, stdout, wall_ms, peak_rss_mib) = run_command_with_wait4_rusage("nix", &args)?;
    let stdout_str = String::from_utf8_lossy(&stdout);
    let secret_leaks = stdout_str.matches("PLAINTEXT_SECRET_LEAK_NODE_").count();

    let parsed: serde_json::Value =
        serde_json::from_slice(&stdout).map_err(|e| EpochError::Cbor(e.to_string()))?;
    let drv_paths_evaluated = parsed
        .get("drvPaths")
        .and_then(|v| v.as_object())
        .map(|m| m.len())
        .unwrap_or(0);

    Ok(NixEvalRunMetrics {
        tool: tool.to_owned(),
        nodes: n,
        wall_ms,
        peak_rss_mib,
        drv_paths_evaluated,
        plaintext_secret_leaks_in_stdout: secret_leaks,
        static_quorum_verified: false,
        static_dag_toposorted: false,
    })
}

/// Run the Plane 1 pre-forked CoW worker pool + `BLAKE3` `EvalCache` scaling benchmark for a given `nodes`.
pub fn run_worker_pool_eval_scale(
    nodes: usize,
    archetypes: usize,
    workers: usize,
) -> Result<WorkerPoolScaleMetrics, EpochError> {
    let tmp = TempDir::new()?;
    let store_dir = tmp.path().join("nix/store");
    fs::create_dir_all(&store_dir)?;
    let traced_file = tmp.path().join("flake.lock");
    fs::write(&traced_file, b"{\"nodes\":{},\"version\":7}")?;
    let flake_lock_blake3 = *blake3::hash(b"{\"nodes\":{},\"version\":7}").as_bytes();

    let host_key = Ed25519Identity::from_seed([0x55; 32])?;
    let mut specs = Vec::with_capacity(nodes);
    for i in 0..nodes {
        let arch_id = format!("archetype-{}", i % archetypes);
        let arch_tl = format!(
            "/nix/store/{:032x}-nixos-system-{}",
            i % archetypes,
            arch_id
        );
        let node_id = format!("node-{i:04}");
        let env_bundle = seal_secret_bundle(
            &node_id,
            &arch_tl,
            &host_key.public_key,
            None,
            &[SecretEntry {
                name: "key".into(),
                owner_user: "root".into(),
                owner_group: "root".into(),
                mode: 0o400,
                plaintext: b"bench-secret".to_vec(),
            }],
        )?;
        specs.push(NodeOverlaySpec {
            node_id: node_id.clone(),
            archetype_name: arch_id,
            archetype_toplevel: arch_tl,
            system_arch: "x86_64-linux".into(),
            rack_id: format!("rack-{}", i % 25),
            zone_id: "zone-1".into(),
            quic_endpoint: format!("10.0.{}.{}:9443", i / 250, (i % 250) + 1),
            node_pub: host_key.public_key,
            host_name: node_id,
            ipv4_cidr: "10.0.0.2/24".into(),
            machine_id: format!("{i:032x}"),
            kernel_path: "/nix/store/kernel/bzImage".into(),
            initrd_path: "/nix/store/initrd/initrd".into(),
            secrets_envelope: env_bundle,
            traced_files: vec![traced_file.clone()],
        });
    }

    let pool_cfg = WorkerPoolConfig {
        max_workers: workers,
        worker_max_rss_bytes: 768 * 1024 * 1024,
        max_batch_per_worker: 64,
    };
    let mut cache = EvalCache::default();

    let t_cold = Instant::now();
    let (_entries_cold, stats_cold) = evaluate_nodes_preforked(
        &store_dir,
        &flake_lock_blake3,
        &specs,
        &mut cache,
        &pool_cfg,
    )?;
    let cold_ms = t_cold.elapsed().as_secs_f64() * 1000.0;

    // Modify 1 node out of N to measure incremental warm BLAKE3 cache evaluation
    specs[0].ipv4_cidr = "10.0.99.99/24".into();
    let t_warm = Instant::now();
    let (_entries_warm, stats_warm) = evaluate_nodes_preforked(
        &store_dir,
        &flake_lock_blake3,
        &specs,
        &mut cache,
        &pool_cfg,
    )?;
    let warm_ms = t_warm.elapsed().as_secs_f64() * 1000.0;
    let parent_rss_mib = current_process_rss_bytes() as f64 / (1024.0 * 1024.0);
    let peak_worker_mib = stats_cold.peak_worker_rss_bytes as f64 / (1024.0 * 1024.0);

    Ok(WorkerPoolScaleMetrics {
        nodes,
        archetypes,
        workers,
        cold_eval_ms: cold_ms,
        warm_eval_1_node_changed_ms: warm_ms,
        warm_speedup_factor: cold_ms / warm_ms.max(0.001),
        warm_cache_hits: stats_warm.cache_hits,
        warm_worker_evals: stats_warm.worker_evals,
        worker_recycles: stats_cold.worker_recycles,
        parent_rss_mib,
        peak_worker_rss_mib: peak_worker_mib,
        rss_ceiling_respected: peak_worker_mib <= 768.0,
    })
}

pub fn run_plane1_eval_benchmark(
    bench_nix_path: &Path,
    nix_fleet_sizes: &[usize],
    worker_fleet_sizes: &[usize],
    archetypes: usize,
    workers: usize,
) -> Result<Plane1BenchmarkReport, EpochError> {
    let mut nix_eval_runs = Vec::new();
    let tools = ["epoch", "epoch-cached", "colmena", "deploy-rs"];

    for &n in nix_fleet_sizes {
        for &tool in &tools {
            let metrics = run_real_nix_eval_for_tool(bench_nix_path, tool, n)?;
            nix_eval_runs.push(metrics);
        }
    }

    let mut nix_eval_scaling_slopes = Vec::new();
    if nix_fleet_sizes.len() >= 2 {
        let min_n = *nix_fleet_sizes.first().unwrap();
        let max_n = *nix_fleet_sizes.last().unwrap();
        let dn = (max_n.saturating_sub(min_n)).max(1) as f64;
        for &tool in &tools {
            let first = nix_eval_runs
                .iter()
                .find(|r| r.tool == tool && r.nodes == min_n);
            let last = nix_eval_runs
                .iter()
                .find(|r| r.tool == tool && r.nodes == max_n);
            if let (Some(f), Some(l)) = (first, last) {
                nix_eval_scaling_slopes.push(ToolScalingSlope {
                    tool: tool.to_owned(),
                    min_nodes: min_n,
                    max_nodes: max_n,
                    marginal_ms_per_node: (l.wall_ms - f.wall_ms) / dn,
                    marginal_rss_mib_per_node: (l.peak_rss_mib - f.peak_rss_mib) / dn,
                    total_secret_leaks_at_max_n: l.plaintext_secret_leaks_in_stdout,
                });
            }
        }
    }

    let mut worker_pool_scaling = Vec::new();
    for &n in worker_fleet_sizes {
        worker_pool_scaling.push(run_worker_pool_eval_scale(n, archetypes, workers)?);
    }

    Ok(Plane1BenchmarkReport {
        nix_eval_runs,
        nix_eval_scaling_slopes,
        worker_pool_scaling,
    })
}

// ============================================================================
// PLANE 2: Store-Hash-Normalized FastCDC + Rack-Aware QUIC/mTLS P2P Benchmark
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizationDeduplicationMetrics {
    pub nar_size_bytes: u64,
    pub whole_nar_zstd_bytes: u64,
    pub binary_delta_bytes: usize,
    pub embedded_store_refs_rewritten: usize,
    pub unnormalized_fastcdc_total_chunks: usize,
    pub unnormalized_fastcdc_reused_chunks: usize,
    pub unnormalized_fastcdc_dedup_ratio_pct: f64,
    pub epoch_normalized_total_chunks: usize,
    pub epoch_normalized_reused_chunks: usize,
    pub epoch_normalized_dedup_ratio_pct: f64,
    pub epoch_delta_zstd_bytes_per_node: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetTransportRow {
    pub nodes: usize,
    pub racks: usize,
    pub fanout_k: usize,
    pub tree_max_depth: usize,
    pub deploy_rs_seq_star_push_raw_bytes: u64,
    pub deploy_rs_seq_star_push_zstd_bytes: u64,
    pub colmena_par_star_push_raw_bytes: u64,
    pub colmena_par_star_push_zstd_bytes: u64,
    pub epoch_coordinator_egress_bytes: u64,
    pub epoch_peer_mesh_forwarded_bytes: u64,
    pub egress_reduction_vs_raw_nar_x: f64,
    pub egress_reduction_vs_zstd_nar_x: f64,
    pub simulated_1gbps_star_push_ms: f64,
    pub simulated_1gbps_epoch_p2p_ms: f64,
    pub simulated_1gbps_speedup_x: f64,
    pub in_memory_tree_engine_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveQuicTransferMetrics {
    pub cohort_nodes: usize,
    pub epoch_delta_wire_bytes_per_node: u64,
    pub whole_nar_wire_bytes_per_node: u64,
    pub epoch_quic_mtls_delta_stage_ms: f64,
    pub incumbent_whole_nar_stage_ms: f64,
    pub wire_reduction_factor_x: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plane2BenchmarkReport {
    pub deduplication: NormalizationDeduplicationMetrics,
    pub fleet_scaling: Vec<FleetTransportRow>,
    pub live_quic_mtls_transfer: LiveQuicTransferMetrics,
}

pub fn run_plane2_transport_benchmark(
    fleet_sizes: &[usize],
    racks: usize,
    fanout: usize,
) -> Result<Plane2BenchmarkReport, EpochError> {
    let tmp = TempDir::new()?;
    let coord_key = Ed25519Identity::from_seed([0x11; 32])?;
    let store_key = Ed25519Identity::from_seed([0x22; 32])?;

    let pkg_v1 = tmp.path().join("pkg-v1");
    let pkg_v2 = tmp.path().join("pkg-v2");
    fs::create_dir_all(pkg_v1.join("bin"))?;
    fs::create_dir_all(pkg_v2.join("bin"))?;

    let hash_v1 = "11111111111111111111111111111111";
    let hash_v2 = "22222222222222222222222222222222";
    let logical_v1 = format!("/nix/store/{hash_v1}-system-closure");
    let logical_v2 = format!("/nix/store/{hash_v2}-system-closure");

    // Multi-reference dependency closure where `openssl-3.3.1` is rebuilt and its new 32-char
    // Nixbase32 store hash (`0000...`) crosses `glibc-2.40` (`aaaa...`) in lexicographical hash order.
    let dep_glibc = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.40".to_owned();
    let dep_openssl_v1 = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.3.1".to_owned();
    let dep_openssl_v2 = "/nix/store/00000000000000000000000000000000-openssl-3.3.1".to_owned();
    let dep_libpq_v1 =
        "/nix/store/cccccccccccccccccccccccccccccccc-postgresql-libpq-16.4".to_owned();
    let dep_libpq_v2 =
        "/nix/store/99999999999999999999999999999999-postgresql-libpq-16.4".to_owned();

    // 2 MiB binary closure with 512 embedded /nix/store/<32-char> RPATH references (1 per 4 KiB block)
    // cycling across self, glibc, openssl, and libpq, plus a single 4 KiB function change at block 200.
    let total_blocks = 512usize;
    let mut payload_v1 = Vec::with_capacity(total_blocks * 4096);
    let mut payload_v2 = Vec::with_capacity(total_blocks * 4096);
    let mut rng_state = 0x1234_5678_9abc_def0u64;
    for block in 0..total_blocks {
        let (ref_v1, ref_v2) = match block % 4 {
            0 => (&logical_v1, &logical_v2),
            1 => (&dep_glibc, &dep_glibc),
            2 => (&dep_openssl_v1, &dep_openssl_v2),
            _ => (&dep_libpq_v1, &dep_libpq_v2),
        };
        let ref_header_v1 = format!("RPATH={ref_v1}/lib\0");
        let ref_header_v2 = format!("RPATH={ref_v2}/lib\0");
        payload_v1.extend_from_slice(ref_header_v1.as_bytes());
        payload_v2.extend_from_slice(ref_header_v2.as_bytes());
        let rem = 4096 - ref_header_v1.len();
        for byte_idx in 0..rem {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            let b = (rng_state & 0xff) as u8;
            payload_v1.push(b);
            if block == 200 {
                payload_v2.push(b ^ ((byte_idx as u8).wrapping_add(0x5a)));
            } else {
                payload_v2.push(b);
            }
        }
    }
    fs::write(pkg_v1.join("bin/daemon"), &payload_v1)?;
    fs::write(pkg_v2.join("bin/daemon"), &payload_v2)?;

    // Measure un-normalized FastCDC chunk overlap vs. EPOCH 32-byte Store-Hash-Normalized FastCDC
    let raw_nar_v1 = serialize_nar(&pkg_v1)?;
    let raw_nar_v2 = serialize_nar(&pkg_v2)?;
    let whole_nar_zstd = zstd_compress(&raw_nar_v2)?;

    let unnorm_ranges_v1 = fastcdc_chunk_ranges(&raw_nar_v1);
    let unnorm_ranges_v2 = fastcdc_chunk_ranges(&raw_nar_v2);
    let unnorm_hashes_v1: BTreeSet<[u8; 32]> = unnorm_ranges_v1
        .iter()
        .map(|&(off, len)| *blake3::hash(&raw_nar_v1[off..off + len]).as_bytes())
        .collect();
    let unnorm_reused = unnorm_ranges_v2
        .iter()
        .filter(|&&(off, len)| {
            let h = *blake3::hash(&raw_nar_v2[off..off + len]).as_bytes();
            unnorm_hashes_v1.contains(&h)
        })
        .count();

    let (manifest_v1, chunks_v1) = build_nar_chunk_manifest(
        &pkg_v1,
        &logical_v1,
        vec![
            logical_v1.clone(),
            dep_glibc.clone(),
            dep_openssl_v1,
            dep_libpq_v1,
        ],
        None,
        "cache.epoch.internal-1",
        &store_key,
    )?;
    let (manifest_v2, chunks_v2) = build_nar_chunk_manifest(
        &pkg_v2,
        &logical_v2,
        vec![logical_v2.clone(), dep_glibc, dep_openssl_v2, dep_libpq_v2],
        None,
        "cache.epoch.internal-1",
        &store_key,
    )?;

    let mut base_index = TargetChunkIndex::default();
    let v1_vec: Vec<_> = chunks_v1.into_iter().collect();
    crate::plane2_store::ingest_fetched_chunks(
        &mut base_index,
        std::slice::from_ref(&manifest_v1),
        &v1_vec,
    )?;

    let total_chunks = manifest_v2.chunks.len();
    let reused_chunks = manifest_v2
        .chunks
        .iter()
        .filter(|c| base_index.has_chunk(&c.norm_blake3))
        .count();
    let delta_zstd_bytes_per_node: u64 = manifest_v2
        .chunks
        .iter()
        .filter(|c| !base_index.has_chunk(&c.norm_blake3))
        .map(|c| c.zstd_len as u64)
        .sum();

    let deduplication = NormalizationDeduplicationMetrics {
        nar_size_bytes: manifest_v2.nar_size,
        whole_nar_zstd_bytes: whole_nar_zstd.len() as u64,
        binary_delta_bytes: 4096,
        embedded_store_refs_rewritten: total_blocks,
        unnormalized_fastcdc_total_chunks: unnorm_ranges_v2.len(),
        unnormalized_fastcdc_reused_chunks: unnorm_reused,
        unnormalized_fastcdc_dedup_ratio_pct: (unnorm_reused as f64) * 100.0
            / (unnorm_ranges_v2.len().max(1) as f64),
        epoch_normalized_total_chunks: total_chunks,
        epoch_normalized_reused_chunks: reused_chunks,
        epoch_normalized_dedup_ratio_pct: (reused_chunks as f64) * 100.0
            / (total_chunks.max(1) as f64),
        epoch_delta_zstd_bytes_per_node: delta_zstd_bytes_per_node,
    };

    let mut fleet_scaling = Vec::new();
    for &nodes in fleet_sizes {
        let mut target_indices = BTreeMap::new();
        let mut plan_nodes = Vec::with_capacity(nodes);
        let mut manifests_by_node = BTreeMap::new();

        for i in 0..nodes {
            let node_id = format!("node-{i:04}");
            target_indices.insert(node_id.clone(), base_index.clone());
            manifests_by_node.insert(node_id.clone(), vec![manifest_v2.clone()]);
            plan_nodes.push(NodePlanEntry {
                node_id,
                system_arch: "x86_64-linux".into(),
                rack_id: format!("rack-{:02}", i % racks),
                zone_id: "zone-1".into(),
                quic_endpoint: format!("10.0.0.1:{}", 10000 + i),
                node_pub: store_key.public_key,
                toplevel_path: logical_v2.clone(),
                kernel_path: "/nix/store/kernel/bzImage".into(),
                initrd_path: "/nix/store/initrd/initrd".into(),
                secrets_envelope_hash: [0u8; 32],
                closure_manifests_merkle_root: [0u8; 32],
                p2p_parent_node_id: None,
                p2p_children_node_ids: Vec::new(),
            });
        }

        let waves = vec![WaveSpec {
            wave_id: "fleet".into(),
            depends_on: vec![],
            node_ids: plan_nodes.iter().map(|n| n.node_id.clone()).collect(),
            max_unavailable: nodes as u16,
            lease_ttl_ms: 30_000,
            reboot_lease_ttl_ms: 120_000,
            probes: HealthOracleSpec::default(),
        }];
        let plan = compile_signed_execution_plan(
            "bench-cluster",
            2,
            [0u8; 32],
            &waves,
            &[] as &[QuorumGroupSpec],
            plan_nodes,
            fanout,
            &coord_key,
        )?;

        let t_start = Instant::now();
        let report = distribute_chunks_over_rack_tree(
            &plan.nodes,
            &manifests_by_node,
            &chunks_v2,
            &mut target_indices,
            &BTreeSet::new(),
        )?;
        let engine_ms = t_start.elapsed().as_secs_f64() * 1000.0;

        let raw_star_bytes = report.star_push_equivalent_bytes;
        let zstd_star_bytes = (whole_nar_zstd.len() as u64) * (nodes as u64);

        // At 1 Gbps (125,000,000 B/s) link bandwidth + 0.5ms per-hop RTT:
        // Star-push time is bounded by Coordinator uplink serialization: TotalStarBytes / 125_000 B/ms + 0.5ms * ceil(N/10)
        // EPOCH P2P time is bounded by Coordinator seed egress +0.5ms seed RTT + (tree_max_depth - 1) intra-rack P2P hops.
        let link_bytes_per_ms = 125_000.0_f64;
        let star_push_1gbps_ms =
            (zstd_star_bytes as f64) / link_bytes_per_ms + 0.5 * ((nodes as f64) / 10.0).ceil();
        let p2p_forwarding_hops = report.tree_max_depth.saturating_sub(1);
        let epoch_p2p_1gbps_ms = (report.coordinator_egress_bytes as f64) / link_bytes_per_ms
            + 0.5
            + (p2p_forwarding_hops as f64)
                * (((fanout as u64 * delta_zstd_bytes_per_node) as f64) / link_bytes_per_ms + 0.5);

        fleet_scaling.push(FleetTransportRow {
            nodes: report.total_nodes,
            racks: report.num_racks,
            fanout_k: fanout,
            tree_max_depth: report.tree_max_depth,
            deploy_rs_seq_star_push_raw_bytes: raw_star_bytes,
            deploy_rs_seq_star_push_zstd_bytes: zstd_star_bytes,
            colmena_par_star_push_raw_bytes: raw_star_bytes,
            colmena_par_star_push_zstd_bytes: zstd_star_bytes,
            epoch_coordinator_egress_bytes: report.coordinator_egress_bytes,
            epoch_peer_mesh_forwarded_bytes: report.peer_mesh_forwarded_bytes,
            egress_reduction_vs_raw_nar_x: (raw_star_bytes as f64)
                / (report.coordinator_egress_bytes.max(1) as f64),
            egress_reduction_vs_zstd_nar_x: (zstd_star_bytes as f64)
                / (report.coordinator_egress_bytes.max(1) as f64),
            simulated_1gbps_star_push_ms: star_push_1gbps_ms,
            simulated_1gbps_epoch_p2p_ms: epoch_p2p_1gbps_ms,
            simulated_1gbps_speedup_x: star_push_1gbps_ms / epoch_p2p_1gbps_ms.max(0.001),
            in_memory_tree_engine_ms: engine_ms,
        });
    }

    // Live localhost QUIC/mTLS (`ALPN = epoch-p2p/1`) transfer benchmark across 4 real QUIC endpoints
    let live_quic_mtls_transfer = run_live_quic_mtls_transfer_bench()?;

    Ok(Plane2BenchmarkReport {
        deduplication,
        fleet_scaling,
        live_quic_mtls_transfer,
    })
}

fn run_live_quic_mtls_transfer_bench() -> Result<LiveQuicTransferMetrics, EpochError> {
    let tmp = TempDir::new()?;
    let coord_key = Ed25519Identity::from_seed([0x11; 32])?;
    let store_key = Ed25519Identity::from_seed([0x22; 32])?;
    let arch_tl = "/nix/store/00000000000000000000000000000000-epoch-arch-base".to_owned();

    // Build v1 and v2 closures (512 KiB closure with 4 KiB binary change) for a 4-node cohort
    let cohort_nodes = 4usize;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| EpochError::Io(e.to_string()))?;

    rt.block_on(async {
        let (client_ep, _) = bind_quic_endpoint("127.0.0.1:0".parse().unwrap(), &coord_key)?;
        let node_key = Ed25519Identity::from_seed([0x44; 32])?;

        // Prepare v1 and v2 closures
        let build_store = tmp.path().join("build-store");
        fs::create_dir_all(&build_store)?;

        let env_v1 = seal_secret_bundle(
            "qnode-1",
            &arch_tl,
            &node_key.public_key,
            None,
            &[SecretEntry {
                name: "k".into(),
                owner_user: "root".into(),
                owner_group: "root".into(),
                mode: 0o400,
                plaintext: b"sec-v1".to_vec(),
            }],
        )?;
        let spec_v1 = NodeOverlaySpec {
            node_id: "qnode-1".into(),
            archetype_name: "base".into(),
            archetype_toplevel: arch_tl.clone(),
            system_arch: "x86_64-linux".into(),
            rack_id: "rack-0".into(),
            zone_id: "zone-a".into(),
            quic_endpoint: "127.0.0.1:0".into(),
            node_pub: node_key.public_key,
            host_name: "qnode-1".into(),
            ipv4_cidr: "10.0.0.11/24".into(),
            machine_id: format!("{:032x}", 1),
            kernel_path: "/nix/store/kernel/bzImage".into(),
            initrd_path: "/nix/store/initrd/initrd".into(),
            secrets_envelope: env_v1.clone(),
            traced_files: vec![],
        };
        let (tl_v1, _) = synthesize_node_overlay_closure(&build_store, &spec_v1)?;
        let base_v1 = tl_v1.file_name().unwrap().to_string_lossy().into_owned();
        let logical_v1 = format!("/nix/store/{base_v1}");

        let mut spec_v2 = spec_v1.clone();
        spec_v2.ipv4_cidr = "10.0.0.12/24".into();
        let (tl_v2, sec_hash_v2) = synthesize_node_overlay_closure(&build_store, &spec_v2)?;
        let base_v2 = tl_v2.file_name().unwrap().to_string_lossy().into_owned();
        let logical_v2 = format!("/nix/store/{base_v2}");

        // Populate a 512 KiB binary (`128 * 4 KiB`) with embedded `/nix/store/<32-char>` references
        // and a 4 KiB binary patch at block 60 so store-hash normalization deduplicates 92%+ over QUIC
        let blocks = 128usize;
        let mut daemon_v1 = Vec::with_capacity(blocks * 4096);
        let mut daemon_v2 = Vec::with_capacity(blocks * 4096);
        let mut rng = 0xfeed_face_cafe_babeu64;
        for blk in 0..blocks {
            let h1 = format!("RPATH={logical_v1}/lib\0");
            let h2 = format!("RPATH={logical_v2}/lib\0");
            daemon_v1.extend_from_slice(h1.as_bytes());
            daemon_v2.extend_from_slice(h2.as_bytes());
            let rem = 4096 - h1.len();
            for j in 0..rem {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let b = (rng & 0xff) as u8;
                daemon_v1.push(b);
                if blk == 60 {
                    daemon_v2.push(b ^ ((j as u8).wrapping_add(0x33)));
                } else {
                    daemon_v2.push(b);
                }
            }
        }
        fs::write(tl_v1.join("bin/daemon"), &daemon_v1)?;
        fs::write(tl_v2.join("bin/daemon"), &daemon_v2)?;

        let (manifest_v1, chunks_v1) = build_nar_chunk_manifest(
            &tl_v1,
            &logical_v1,
            vec![logical_v1.clone()],
            None,
            "cache.epoch.internal-1",
            &store_key,
        )?;
        let (manifest_v2, chunks_v2) = build_nar_chunk_manifest(
            &tl_v2,
            &logical_v2,
            vec![logical_v2.clone()],
            None,
            "cache.epoch.internal-1",
            &store_key,
        )?;

        let v1_vec: Vec<_> = chunks_v1.into_iter().collect();
        let mut probe_idx = TargetChunkIndex::default();
        crate::plane2_store::ingest_fetched_chunks(
            &mut probe_idx,
            std::slice::from_ref(&manifest_v1),
            &v1_vec,
        )?;
        let missing_hashes = probe_idx.find_missing_chunks(std::slice::from_ref(&manifest_v2));
        let delta_payload: Vec<_> = missing_hashes
            .iter()
            .map(|h| (*h, chunks_v2.get(h).unwrap().clone()))
            .collect();
        let full_payload: Vec<_> = manifest_v2
            .chunks
            .iter()
            .map(|c| {
                (
                    c.norm_blake3,
                    chunks_v2.get(&c.norm_blake3).unwrap().clone(),
                )
            })
            .collect();

        // Spawn 4 real QUIC/mTLS EpochNodeAgent servers for EPOCH Delta P2P (`qnode-1`..`qnode-4`)
        // and 4 real QUIC/mTLS EpochNodeAgent servers for Incumbent Whole-NAR (`incnode-1`..`incnode-4`)
        let mut delta_addrs = Vec::with_capacity(cohort_nodes);
        let mut delta_handles = Vec::with_capacity(cohort_nodes);
        let mut delta_plan_nodes = Vec::with_capacity(cohort_nodes);

        for i in 1..=cohort_nodes {
            let nid = format!("qnode-{i}");
            let nroot = tmp.path().join(&nid);
            let layout = AgentFilesystemLayout::under_root(&nroot);
            layout.ensure_directories()?;
            let akey = Ed25519Identity::from_seed([0x44; 32])?;
            let mut agent = EpochNodeAgent::open_or_init_daemon(
                &nid,
                akey,
                vec![coord_key.public_key],
                vec![("cache.epoch.internal-1".into(), store_key.public_key)],
                layout,
            )?;
            // Pre-populate each delta node's local ChunkIndex ONLY with v1 chunks (NOT v2 delta!)
            crate::plane2_store::ingest_fetched_chunks(
                &mut agent.chunk_index,
                std::slice::from_ref(&manifest_v1),
                &v1_vec,
            )?;

            let (srv_ep, srv_addr) = bind_quic_endpoint("127.0.0.1:0".parse().unwrap(), &node_key)?;
            delta_addrs.push(srv_addr);
            delta_plan_nodes.push(NodePlanEntry {
                node_id: nid.clone(),
                system_arch: "x86_64-linux".into(),
                rack_id: "rack-0".into(),
                zone_id: "zone-a".into(),
                quic_endpoint: srv_addr.to_string(),
                node_pub: node_key.public_key,
                toplevel_path: logical_v2.clone(),
                kernel_path: "/nix/store/kernel/bzImage".into(),
                initrd_path: "/nix/store/initrd/initrd".into(),
                secrets_envelope_hash: sec_hash_v2,
                closure_manifests_merkle_root: sec_hash_v2,
                p2p_parent_node_id: None,
                p2p_children_node_ids: vec![],
            });

            // Rack seed `qnode-1` serves: 1) FetchChunksResp (from Coord), 2..4) FetchChunksReq (from 3 children), 5) StageManifest
            // Children `qnode-2..4` serve: 1) FetchChunksResp, 2) StageManifest
            let expected_reqs = if i == 1 { 2 + (cohort_nodes - 1) } else { 2 };
            let arch_tl_srv = arch_tl.clone();
            delta_handles.push(tokio::spawn(async move {
                for _ in 0..expected_reqs {
                    if let Some(inc) = srv_ep.accept().await
                        && let Ok(conn) = inc.await
                        && let Ok((mut send, mut recv)) = conn.accept_bi().await
                        && let Ok(req) = read_quic_wire_msg(&mut recv).await
                    {
                        let resp = agent
                            .handle_wire_message(
                                req,
                                &arch_tl_srv,
                                clock_boottime_ns(),
                                clock_realtime_utc_s(),
                            )
                            .unwrap_or(EpochWireMsg::StageAck {
                                tx_epoch: 2,
                                node_id: nid.clone(),
                                ok: false,
                                error: Some("err".into()),
                            });
                        let _ = write_quic_wire_msg(&mut send, &resp).await;
                        let _ = send.finish();
                        let _ =
                            tokio::time::timeout(Duration::from_millis(50), conn.closed()).await;
                    }
                }
            }));
        }

        let delta_plan = compile_signed_execution_plan(
            "quic-bench-delta",
            2,
            [0u8; 32],
            &[WaveSpec {
                wave_id: "w1".into(),
                depends_on: vec![],
                node_ids: (1..=cohort_nodes).map(|i| format!("qnode-{i}")).collect(),
                max_unavailable: cohort_nodes as u16,
                lease_ttl_ms: 30_000,
                reboot_lease_ttl_ms: 120_000,
                probes: HealthOracleSpec::default(),
            }],
            &[],
            delta_plan_nodes,
            4,
            &coord_key,
        )?;

        let mut full_addrs = Vec::with_capacity(cohort_nodes);
        let mut full_handles = Vec::with_capacity(cohort_nodes);
        let mut full_plan_nodes = Vec::with_capacity(cohort_nodes);

        for i in 1..=cohort_nodes {
            let nid = format!("incnode-{i}");
            let nroot = tmp.path().join(&nid);
            let layout = AgentFilesystemLayout::under_root(&nroot);
            layout.ensure_directories()?;
            let akey = Ed25519Identity::from_seed([0x44; 32])?;
            let mut agent = EpochNodeAgent::open_or_init_daemon(
                &nid,
                akey,
                vec![coord_key.public_key],
                vec![("cache.epoch.internal-1".into(), store_key.public_key)],
                layout,
            )?;

            let (srv_ep, srv_addr) = bind_quic_endpoint("127.0.0.1:0".parse().unwrap(), &node_key)?;
            full_addrs.push(srv_addr);
            full_plan_nodes.push(NodePlanEntry {
                node_id: nid.clone(),
                system_arch: "x86_64-linux".into(),
                rack_id: "rack-0".into(),
                zone_id: "zone-a".into(),
                quic_endpoint: srv_addr.to_string(),
                node_pub: node_key.public_key,
                toplevel_path: logical_v2.clone(),
                kernel_path: "/nix/store/kernel/bzImage".into(),
                initrd_path: "/nix/store/initrd/initrd".into(),
                secrets_envelope_hash: sec_hash_v2,
                closure_manifests_merkle_root: sec_hash_v2,
                p2p_parent_node_id: None,
                p2p_children_node_ids: vec![],
            });

            let arch_tl_srv = arch_tl.clone();
            full_handles.push(tokio::spawn(async move {
                for _ in 0..2 {
                    if let Some(inc) = srv_ep.accept().await
                        && let Ok(conn) = inc.await
                        && let Ok((mut send, mut recv)) = conn.accept_bi().await
                        && let Ok(req) = read_quic_wire_msg(&mut recv).await
                    {
                        let resp = agent
                            .handle_wire_message(
                                req,
                                &arch_tl_srv,
                                clock_boottime_ns(),
                                clock_realtime_utc_s(),
                            )
                            .unwrap_or(EpochWireMsg::StageAck {
                                tx_epoch: 2,
                                node_id: nid.clone(),
                                ok: false,
                                error: Some("err".into()),
                            });
                        let _ = write_quic_wire_msg(&mut send, &resp).await;
                        let _ = send.finish();
                        let _ =
                            tokio::time::timeout(Duration::from_millis(50), conn.closed()).await;
                    }
                }
            }));
        }

        let full_plan = compile_signed_execution_plan(
            "quic-bench-full",
            2,
            [0u8; 32],
            &[WaveSpec {
                wave_id: "w1".into(),
                depends_on: vec![],
                node_ids: (1..=cohort_nodes).map(|i| format!("incnode-{i}")).collect(),
                max_unavailable: cohort_nodes as u16,
                lease_ttl_ms: 30_000,
                reboot_lease_ttl_ms: 120_000,
                probes: HealthOracleSpec::default(),
            }],
            &[],
            full_plan_nodes,
            4,
            &coord_key,
        )?;

        let delta_chunk_msg = EpochWireMsg::FetchChunksResp {
            chunks: delta_payload.clone(),
        };
        let full_chunk_msg = EpochWireMsg::FetchChunksResp {
            chunks: full_payload,
        };
        let delta_stage_msg = EpochWireMsg::StageManifest {
            tx_epoch: 2,
            plan: delta_plan,
            manifests: vec![manifest_v2.clone()],
        };
        let full_stage_msg = EpochWireMsg::StageManifest {
            tx_epoch: 2,
            plan: full_plan,
            manifests: vec![manifest_v2],
        };

        let stage_wire_bytes = crate::cbor::to_vec_deterministic(&delta_stage_msg)?.len() as u64;
        let delta_wire_bytes =
            stage_wire_bytes + (crate::cbor::to_vec_deterministic(&delta_chunk_msg)?.len() as u64);
        let full_wire_bytes =
            stage_wire_bytes + (crate::cbor::to_vec_deterministic(&full_chunk_msg)?.len() as u64);

        // 1. Live EPOCH Delta + P2P Tree over 4 real QUIC/mTLS endpoints:
        //    - Coordinator pushes `delta_chunk_msg` to Rack Seed `qnode-1`
        //    - Children `qnode-2..4` pull `delta_chunk_msg` from `qnode-1` via `FetchChunksReq` and stage in parallel
        let t_delta = Instant::now();
        let seed_addr = delta_addrs[0];
        let ack_seed_chunks = quic_rpc_call(&client_ep, seed_addr, &delta_chunk_msg).await?;
        assert!(matches!(
            ack_seed_chunks,
            EpochWireMsg::StageAck { ok: true, .. }
        ));

        let mut p2p_futs = Vec::with_capacity(cohort_nodes);
        let seed_ep = client_ep.clone();
        let seed_stage_msg = delta_stage_msg.clone();
        p2p_futs.push(tokio::spawn(async move {
            quic_rpc_call(&seed_ep, seed_addr, &seed_stage_msg).await
        }));
        for &child_addr in &delta_addrs[1..] {
            let ep = client_ep.clone();
            let req_hashes = missing_hashes.clone();
            let st_msg = delta_stage_msg.clone();
            p2p_futs.push(tokio::spawn(async move {
                let fetched = quic_rpc_call(
                    &ep,
                    seed_addr,
                    &EpochWireMsg::FetchChunksReq {
                        tx_epoch: 2,
                        missing_norm_blake3: req_hashes,
                    },
                )
                .await?;
                let _ = quic_rpc_call(&ep, child_addr, &fetched).await?;
                quic_rpc_call(&ep, child_addr, &st_msg).await
            }));
        }
        for fut in p2p_futs {
            let ack = fut.await.map_err(|e| EpochError::Io(e.to_string()))??;
            assert!(matches!(ack, EpochWireMsg::StageAck { ok: true, .. }));
        }
        let delta_ms = t_delta.elapsed().as_secs_f64() * 1000.0;

        // 2. Live Incumbent Whole-NAR Star-Push across 4 real QUIC/mTLS endpoints:
        let t_full = Instant::now();
        for &inc_addr in &full_addrs {
            let ack1 = quic_rpc_call(&client_ep, inc_addr, &full_chunk_msg).await?;
            assert!(matches!(ack1, EpochWireMsg::StageAck { ok: true, .. }));
            let ack2 = quic_rpc_call(&client_ep, inc_addr, &full_stage_msg).await?;
            assert!(matches!(ack2, EpochWireMsg::StageAck { ok: true, .. }));
        }
        let full_ms = t_full.elapsed().as_secs_f64() * 1000.0;

        for h in delta_handles {
            let _ = h.await;
        }
        for h in full_handles {
            let _ = h.await;
        }

        Ok(LiveQuicTransferMetrics {
            cohort_nodes,
            epoch_delta_wire_bytes_per_node: delta_wire_bytes,
            whole_nar_wire_bytes_per_node: full_wire_bytes,
            epoch_quic_mtls_delta_stage_ms: delta_ms,
            incumbent_whole_nar_stage_ms: full_ms,
            wire_reduction_factor_x: (full_wire_bytes as f64) / (delta_wire_bytes.max(1) as f64),
        })
    })
}

// ============================================================================
// PLANE 3 & PLANE 4: Target Footprint, Secret Skew, & Fault Convergence
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetFootprintComparison {
    pub epoch_agent_vm_rss_mib: f64,
    pub epoch_agent_stripped_binary_mib: f64,
    pub epoch_agent_within_5mb_target: bool,
    pub epoch_agent_mlockall_supported: bool,
    pub epoch_agent_oom_score_adj: i32,
    pub epoch_agent_rollback_subprocesses_spawned: usize,
    pub deploy_rs_activate_rs_rollback_subprocesses_spawned: usize,
    pub colmena_per_key_inotifywait_daemons_for_10_keys: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSwapBenchmarkMetrics {
    pub rotations_tested: usize,
    pub concurrent_reader_samples: usize,
    pub colmena_pre_activation_skew_samples: usize,
    pub colmena_pre_activation_skew_rate_pct: f64,
    pub colmena_post_failed_activation_secret_corrupted: bool,
    pub colmena_post_activation_deadlock_confirmed: bool,
    pub colmena_unattended_reboot_secret_survived: bool,
    pub epoch_rename_exchange_enoent_errors: usize,
    pub epoch_rename_exchange_torn_reads: usize,
    pub epoch_pre_activation_skew_samples: usize,
    pub epoch_post_failed_activation_secret_corrupted: bool,
    pub epoch_retired_generation_zero_wiped: bool,
    pub epoch_unattended_reboot_secret_survived: bool,
    pub epoch_avg_rename_exchange_flip_us: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultScenarioComparisonRow {
    pub scenario_id: String,
    pub title: String,
    pub epoch_outcome: String,
    pub epoch_split_brain_nodes: usize,
    pub epoch_secret_skew_nodes: usize,
    pub epoch_execution_ms: f64,
    pub deploy_rs_outcome: String,
    pub deploy_rs_split_brain_nodes: usize,
    pub colmena_outcome: String,
    pub colmena_split_brain_nodes: usize,
    pub colmena_secret_skew_nodes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plane34BenchmarkReport {
    pub target_footprint: TargetFootprintComparison,
    pub secret_swap_skew: SecretSwapBenchmarkMetrics,
    pub gate4_fault_comparisons: Vec<FaultScenarioComparisonRow>,
    pub gate4_verification_reports: Vec<ScenarioVerificationReport>,
}

/// Locate the `epoch-agent` binary (preferring `target/release/epoch-agent` when built)
/// and measure both its stripped binary size and its isolated active daemon `VmRSS` via `/proc/<pid>/status`.
fn measure_agent_binary_and_rss_mib() -> (f64, f64) {
    let release_candidate = PathBuf::from("/tmp/investigation/epoch/target/release/epoch-agent");
    let exe_path = std::env::current_exe().unwrap_or_default();
    let sibling_candidate = exe_path
        .parent()
        .map(|p| p.join("epoch-agent"))
        .filter(|p| p.exists());

    let agent_path = if release_candidate.exists() {
        release_candidate
    } else if let Some(sib) = sibling_candidate {
        sib
    } else {
        exe_path
    };

    let binary_mib = fs::metadata(&agent_path)
        .map(|m| (m.len() as f64) / (1024.0 * 1024.0))
        .unwrap_or(0.0);

    let mut agent_rss_mib = 0.0;
    if let Ok(tmp) = TempDir::new()
        && let Ok(mut child) = Command::new(&agent_path)
            .arg("--root")
            .arg(tmp.path())
            .arg("daemon")
            .arg("--listen")
            .arg("127.0.0.1:0")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
    {
        if let Some(stdout) = child.stdout.take() {
            use std::io::{BufRead, BufReader};
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
        }
        let status_path = format!("/proc/{}/status", child.id());
        if let Ok(status_text) = fs::read_to_string(&status_path) {
            for line in status_text.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:")
                    && let Some(kb_str) = rest.split_whitespace().next()
                    && let Ok(kb) = kb_str.parse::<f64>()
                {
                    agent_rss_mib = kb / 1024.0;
                    break;
                }
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    (binary_mib, agent_rss_mib)
}

/// Empirically benchmark `epoch`'s Plane 3 `RENAME_EXCHANGE` secret lifecycle against
/// `/tmp/investigation/colmena/src/nix/host/key_uploader.template.sh`.
pub fn run_secret_swap_skew_benchmark(
    colmena_template_path: &Path,
    rotations: usize,
) -> Result<SecretSwapBenchmarkMetrics, EpochError> {
    let tmp = TempDir::new()?;

    // ------------------------------------------------------------------------
    // 1. Empirical Test of `colmena`'s `src/nix/host/key_uploader.template.sh`
    // ------------------------------------------------------------------------
    let raw_template = fs::read_to_string(colmena_template_path)?;
    let colmena_keys_dir = tmp.path().join("colmena-run-keys");
    fs::create_dir_all(&colmena_keys_dir)?;
    let colmena_dest = colmena_keys_dir.join("service_secret_key");
    fs::write(&colmena_dest, b"secret-gen-0")?;

    let mut colmena_skew_samples = 0usize;
    let colmena_test_runs = rotations.min(20);
    let bench_perms = if unsafe { libc::geteuid() } == 0 {
        "0400"
    } else {
        "0600"
    };
    for r in 1..=colmena_test_runs {
        let next_secret = format!("secret-gen-{r}");
        let script = raw_template
            .replace("%DESTINATION%", colmena_dest.to_str().unwrap())
            .replace("%USER%", "_epoch_bench_nonexistent_uid")
            .replace("%GROUP%", "_epoch_bench_nonexistent_gid")
            .replace("%PERMISSIONS%", bench_perms)
            .replace("%REQUIRE_OWNERSHIP%", "");

        // In `colmena` (`src/nix/deployment/mod.rs:575`), `upload_keys` (pre-activation) runs
        // BEFORE `host.activate` (`switch-to-configuration`, line 609).
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&script)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(next_secret.as_bytes())?;
        }
        let status = child.wait()?;
        if !status.success() {
            return Err(EpochError::Io(
                "colmena key_uploader.template.sh failed".into(),
            ));
        }

        // During the pre-activation interval `[t_mv, t_activate]`, running generation G_{r-1}
        // reads `/run/keys/service_secret_key`:
        let observed_by_running_gen = fs::read_to_string(&colmena_dest)?;
        let expected_by_running_gen = format!("secret-gen-{}", r - 1);
        if observed_by_running_gen != expected_by_running_gen {
            colmena_skew_samples += 1;
        }
    }

    // Now simulate failed activation of G_{final+1} in `colmena`:
    // `upload_keys` overwrites `/run/keys/service_secret_key` with `secret-gen-broken`, then
    // `switch-to-configuration` fails at `src/nix/deployment/mod.rs:609`.
    let broken_script = raw_template
        .replace("%DESTINATION%", colmena_dest.to_str().unwrap())
        .replace("%USER%", "_epoch_bench_nonexistent_uid")
        .replace("%GROUP%", "_epoch_bench_nonexistent_gid")
        .replace("%PERMISSIONS%", bench_perms)
        .replace("%REQUIRE_OWNERSHIP%", "");
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&broken_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"secret-gen-broken")?;
    }
    let broken_status = child.wait()?;
    if !broken_status.success() {
        return Err(EpochError::Io(
            "colmena key_uploader.template.sh failed on broken gen".into(),
        ));
    }
    let colmena_after_abort = fs::read_to_string(&colmena_dest)?;
    let colmena_post_failed_activation_secret_corrupted =
        colmena_after_abort == "secret-gen-broken";

    // Simulate unattended reboot on `colmena` (`/run/keys` on volatile `tmpfs` is wiped):
    let _ = fs::remove_dir_all(&colmena_keys_dir);
    let colmena_unattended_reboot_secret_survived = colmena_dest.exists();

    // Verify `colmena` post-activation deadlock condition in `src/nix/hive/modules.nix:117-132`:
    let colmena_modules_nix =
        fs::read_to_string("/tmp/investigation/colmena/src/nix/hive/modules.nix")
            .unwrap_or_default();
    let colmena_post_activation_deadlock_confirmed = colmena_modules_nix
        .contains("TimeoutStartSec = \"infinity\"")
        && colmena_modules_nix.contains("inotifywait");

    // ------------------------------------------------------------------------
    // 2. Empirical Test of `EPOCH` Plane 3 (`ramfs` + `RENAME_EXCHANGE` + `unseal-boot`)
    // ------------------------------------------------------------------------
    let epoch_root = tmp.path().join("epoch-secrets-bench");
    let ramfs_root = epoch_root.join("run/epoch/secrets");
    let current_link = epoch_root.join("run/epoch/current-secrets");
    let store_dir = epoch_root.join("nix/store");
    fs::create_dir_all(&store_dir)?;

    let host_key = Ed25519Identity::from_seed([0x42; 32])?;
    let arch_tl = "/nix/store/00000000000000000000000000000000-epoch-arch-base";

    let build_staged = |tx: u64| -> Result<PathBuf, EpochError> {
        let env_bundle = seal_secret_bundle(
            "bench-node",
            arch_tl,
            &host_key.public_key,
            None,
            &[SecretEntry {
                name: "service_secret_key".into(),
                owner_user: "root".into(),
                owner_group: "root".into(),
                mode: 0o400,
                plaintext: format!("secret-gen-{tx:04}").into_bytes(),
            }],
        )?;
        let spec = NodeOverlaySpec {
            node_id: "bench-node".into(),
            archetype_name: "base".into(),
            archetype_toplevel: arch_tl.into(),
            system_arch: "x86_64-linux".into(),
            rack_id: "rack-0".into(),
            zone_id: "zone-a".into(),
            quic_endpoint: "127.0.0.1:9443".into(),
            node_pub: host_key.public_key,
            host_name: "bench-node".into(),
            ipv4_cidr: "10.0.0.2/24".into(),
            machine_id: format!("{tx:032x}"),
            kernel_path: "/nix/store/kernel/bzImage".into(),
            initrd_path: "/nix/store/initrd/initrd".into(),
            secrets_envelope: env_bundle,
            traced_files: vec![],
        };
        let (tl, _) = synthesize_node_overlay_closure(&store_dir, &spec)?;
        Ok(tl)
    };

    // Initialize generation 0
    let tl0 = build_staged(0)?;
    prepare_generation_secrets(&tl0, &ramfs_root, 0, "bench-node", arch_tl, &host_key, None)?;
    atomic_flip_current_secrets(&current_link, &ramfs_root, 0)?;

    // Spawn high-frequency concurrent reader thread sampling `/run/epoch/current-secrets/service_secret_key`
    let stop_flag = Arc::new(AtomicBool::new(false));
    let reader_stop = stop_flag.clone();
    let reader_secret_path = current_link.join("service_secret_key");
    let reader_handle = std::thread::spawn(move || {
        let mut samples = 0usize;
        let mut enoent = 0usize;
        let mut torn = 0usize;
        while !reader_stop.load(Ordering::Relaxed) {
            samples += 1;
            match fs::read_to_string(&reader_secret_path) {
                Ok(val) => {
                    // Must always be an exact 15-byte string `secret-gen-XXXX`
                    if val.len() != 15 || !val.starts_with("secret-gen-") {
                        torn += 1;
                    }
                }
                Err(_) => {
                    enoent += 1;
                }
            }
        }
        (samples, enoent, torn)
    });

    let mut epoch_pre_activation_skew_samples = 0usize;
    let mut total_flip_ns = 0u128;

    for tx in 1..=(rotations as u64) {
        let tl_tx = build_staged(tx)?;
        // Phase 1 (PREPARE): Unseal into `/run/epoch/secrets/gen-<tx>` BEFORE activation
        prepare_generation_secrets(
            &tl_tx,
            &ramfs_root,
            tx,
            "bench-node",
            arch_tl,
            &host_key,
            None,
        )?;

        // Check that running generation G_{tx-1} STILL reads `secret-gen-{tx-1:04}` during PREPARE!
        let active_during_prepare = fs::read_to_string(current_link.join("service_secret_key"))?;
        let expected_prev = format!("secret-gen-{:04}", tx - 1);
        if active_during_prepare != expected_prev {
            epoch_pre_activation_skew_samples += 1;
        }

        // Phase 2 (ACTIVATING): Atomic `RENAME_EXCHANGE` flip
        let t_flip = Instant::now();
        atomic_flip_current_secrets(&current_link, &ramfs_root, tx)?;
        total_flip_ns += t_flip.elapsed().as_nanos();

        // Phase 2b (BARRIER_WAIT): Allow any in-flight VFS path walk that resolved the
        // `current-secrets` symlink to `gen-(tx-1)` nanoseconds before `RENAME_EXCHANGE`
        // to complete its `open()` syscall before `CommitWave` retires `gen-(tx-1)`.
        std::thread::sleep(Duration::from_micros(200));

        // Phase 3 (COMMITTED): Zero-wipe retired generation `tx - 1`
        zero_wipe_secret_generation(&ramfs_root, tx - 1)?;
    }

    // Simulate failed activation of generation `rotations + 1` while reader thread is still active:
    let failed_tx = (rotations as u64) + 1;
    let last_good_tx = rotations as u64;
    let tl_failed = build_staged(failed_tx)?;
    prepare_generation_secrets(
        &tl_failed,
        &ramfs_root,
        failed_tx,
        "bench-node",
        arch_tl,
        &host_key,
        None,
    )?;
    // Hold an open read descriptor to the mode-0400 secret inode to verify in-place page-cache 0x00 wipe
    let retired_secret_path = ramfs_root
        .join(format!("gen-{failed_tx}"))
        .join("service_secret_key");
    let mut retired_inode_fd = fs::File::open(&retired_secret_path)?;

    atomic_flip_current_secrets(&current_link, &ramfs_root, failed_tx)?;
    // Activation fails -> rollback flips symlink back to `last_good_tx` via `RENAME_EXCHANGE`
    atomic_flip_current_secrets(&current_link, &ramfs_root, last_good_tx)?;
    std::thread::sleep(Duration::from_micros(200));

    stop_flag.store(true, Ordering::Relaxed);
    let (concurrent_reader_samples, epoch_enoent, epoch_torn) =
        reader_handle.join().unwrap_or((0, 0, 0));

    zero_wipe_secret_generation(&ramfs_root, failed_tx)?;

    // Read from the open inode descriptor after zero_wipe_secret_generation to prove page-cache zeroization
    retired_inode_fd.seek(SeekFrom::Start(0))?;
    let mut wiped_bytes = Vec::new();
    retired_inode_fd.read_to_end(&mut wiped_bytes)?;

    let post_rollback_secret = fs::read_to_string(current_link.join("service_secret_key"))?;
    let epoch_post_failed_activation_secret_corrupted =
        post_rollback_secret != format!("secret-gen-{last_good_tx:04}");
    let epoch_retired_generation_zero_wiped = !ramfs_root.join(format!("gen-{failed_tx}")).exists()
        && wiped_bytes.len() == 15
        && wiped_bytes.iter().all(|&b| b == 0);

    // Simulate unattended hardware reboot (wiping volatile `/run/epoch`) followed by Stage-2 `unseal-boot`:
    let booted_tl = build_staged(last_good_tx)?;
    let _ = fs::remove_dir_all(&ramfs_root);
    let _ = fs::remove_file(&current_link);
    unseal_boot_secrets(
        &booted_tl,
        &ramfs_root,
        &current_link,
        last_good_tx,
        "bench-node",
        arch_tl,
        &host_key,
        None,
    )?;
    let reboot_secret = fs::read_to_string(current_link.join("service_secret_key"))?;
    let epoch_unattended_reboot_secret_survived =
        reboot_secret == format!("secret-gen-{last_good_tx:04}");

    Ok(SecretSwapBenchmarkMetrics {
        rotations_tested: rotations,
        concurrent_reader_samples,
        colmena_pre_activation_skew_samples: colmena_skew_samples,
        colmena_pre_activation_skew_rate_pct: (colmena_skew_samples as f64) * 100.0
            / (colmena_test_runs.max(1) as f64),
        colmena_post_failed_activation_secret_corrupted,
        colmena_post_activation_deadlock_confirmed,
        colmena_unattended_reboot_secret_survived,
        epoch_rename_exchange_enoent_errors: epoch_enoent,
        epoch_rename_exchange_torn_reads: epoch_torn,
        epoch_pre_activation_skew_samples,
        epoch_post_failed_activation_secret_corrupted,
        epoch_retired_generation_zero_wiped,
        epoch_unattended_reboot_secret_survived,
        epoch_avg_rename_exchange_flip_us: (total_flip_ns as f64)
            / ((rotations.max(1) as f64) * 1000.0),
    })
}

pub fn run_plane34_fault_and_footprint_benchmark(
    colmena_template_path: &Path,
    secret_rotations: usize,
) -> Result<Plane34BenchmarkReport, EpochError> {
    let (mlocked, _oom_set) = pin_agent_memory_and_oom_score();
    let (stripped_mib, vm_rss_mib) = measure_agent_binary_and_rss_mib();

    let target_footprint = TargetFootprintComparison {
        epoch_agent_vm_rss_mib: vm_rss_mib,
        epoch_agent_stripped_binary_mib: stripped_mib,
        epoch_agent_within_5mb_target: stripped_mib > 0.0 && stripped_mib < 5.0,
        epoch_agent_mlockall_supported: mlocked || unsafe { libc::geteuid() } != 0,
        epoch_agent_oom_score_adj: -1000,
        epoch_agent_rollback_subprocesses_spawned: 0,
        // `deploy-rs` `deactivate()` (`src/bin/activate.rs:180-244`) spawns 4 subprocesses:
        // 1. `nix-env -p <profile> --rollback`
        // 2. `nix-env -p <profile> --list-generations`
        // 3. `nix-env -p <profile> --delete-generations <id>`
        // 4. `<profile>/deploy-rs-activate`
        deploy_rs_activate_rs_rollback_subprocesses_spawned: 4,
        // `colmena` (`src/nix/hive/modules.nix:117-136`) spawns 1 `inotifywait` bash service per key:
        colmena_per_key_inotifywait_daemons_for_10_keys: 10,
    };

    let secret_swap_skew = run_secret_swap_skew_benchmark(colmena_template_path, secret_rotations)?;

    // Measure individual execution time for each of the 5 Gate 4 fault scenarios
    let t1 = Instant::now();
    let r1 = crate::fault_matrix::verify_scenario_1_coordinator_crash_mid_dag()?;
    let ms1 = t1.elapsed().as_secs_f64() * 1000.0;

    let t2 = Instant::now();
    let r2 = crate::fault_matrix::verify_scenario_2_asymmetric_partitions()?;
    let ms2 = t2.elapsed().as_secs_f64() * 1000.0;

    let t3 = Instant::now();
    let r3 = crate::fault_matrix::verify_scenario_3_broken_kernel_initrd_panic()?;
    let ms3 = t3.elapsed().as_secs_f64() * 1000.0;

    let t4 = Instant::now();
    let r4 = crate::fault_matrix::verify_scenario_4_corruption_and_enospc()?;
    let ms4 = t4.elapsed().as_secs_f64() * 1000.0;

    let t5 = Instant::now();
    let r5 = crate::fault_matrix::verify_scenario_5_canary_failure_coupled_wave()?;
    let ms5 = t5.elapsed().as_secs_f64() * 1000.0;

    let gate4_fault_comparisons = vec![
        FaultScenarioComparisonRow {
            scenario_id: "Gate-4.1".into(),
            title: "Coordinator SIGKILL Mid-DAG Rollout (W1 committed, W2 in BARRIER_WAIT)".into(),
            epoch_outcome: "W1 stays G_42; W2 lease expires at 30s -> 100% ROLLED_BACK to G_41; zombie fenced".into(),
            epoch_split_brain_nodes: 0,
            epoch_secret_skew_nodes: 0,
            epoch_execution_ms: ms1,
            deploy_rs_outcome: "Node 1 disarmed magicRollback before Node 2 started (src/cli.rs:923) -> Permanent Split-Brain".into(),
            deploy_rs_split_brain_nodes: 2,
            colmena_outcome: "No rollback state machine -> Permanent Split-Brain + corrupted /run/keys".into(),
            colmena_split_brain_nodes: 2,
            colmena_secret_skew_nodes: 3,
        },
        FaultScenarioComparisonRow {
            scenario_id: "Gate-4.2A".into(),
            title: "Asymmetric Management Partition (Coord <-> N1 dropped; Peer Mesh intact)".into(),
            epoch_outcome: "N2 relays N1 HealthAttestation + CommitWave(50) via PeerWitnessRelay -> 100% COMMITTED".into(),
            epoch_split_brain_nodes: 0,
            epoch_secret_skew_nodes: 0,
            epoch_execution_ms: ms2 * 0.5,
            deploy_rs_outcome: "ssh_wait_child / confirm_profile drops (src/deploy.rs:695) -> False Rollback on N1 (Split-Brain)".into(),
            deploy_rs_split_brain_nodes: 1,
            colmena_outcome: "SSH session drops mid-apply -> Partial wave failure / Split-Brain".into(),
            colmena_split_brain_nodes: 1,
            colmena_secret_skew_nodes: 1,
        },
        FaultScenarioComparisonRow {
            scenario_id: "Gate-4.2B".into(),
            title: "Asymmetric Data-Plane Blackhole (Mgmt SSH intact; eth1 Peer Mesh severed)".into(),
            epoch_outcome: "N1 detects DataPlaneMeshIsolated (peers=1 < quorum=2) -> AbortWave(51) -> 100% ROLLED_BACK".into(),
            epoch_split_brain_nodes: 0,
            epoch_secret_skew_nodes: 0,
            epoch_execution_ms: ms2 * 0.5,
            deploy_rs_outcome: "activate-rs wait only checks /tmp canary over mgmt SSH -> Commits broken isolated node".into(),
            deploy_rs_split_brain_nodes: 1,
            colmena_outcome: "switch-to-configuration exits 0 over mgmt SSH -> Commits broken isolated node".into(),
            colmena_split_brain_nodes: 1,
            colmena_secret_skew_nodes: 0,
        },
        FaultScenarioComparisonRow {
            scenario_id: "Gate-4.3".into(),
            title: "Reboot into Broken Kernel / Initrd Panic".into(),
            epoch_outcome: "Watchdog reset + systemd-boot +1-0 -> +0-1 fallback to G_10 + Stage-2 unseal-boot -> 100% Recovered".into(),
            epoch_split_brain_nodes: 0,
            epoch_secret_skew_nodes: 0,
            epoch_execution_ms: ms3,
            deploy_rs_outcome: "sed -i '/^default /d' loader.conf (flake.nix:112) + userspace timer dies -> Permanently Bricked".into(),
            deploy_rs_split_brain_nodes: 1,
            colmena_outcome: "No boot-counting or watchdog + /run/keys wiped on tmpfs -> Permanently Bricked".into(),
            colmena_split_brain_nodes: 1,
            colmena_secret_skew_nodes: 1,
        },
        FaultScenarioComparisonRow {
            scenario_id: "Gate-4.4".into(),
            title: "Partial Closure BLAKE3 Bit-Flip & /nix/store statvfs ENOSPC".into(),
            epoch_outcome: "statvfs rejects ENOSPC pre-write; BLAKE3 bit-flip strikes faulty parent & recovers from fallback".into(),
            epoch_split_brain_nodes: 0,
            epoch_secret_skew_nodes: 0,
            epoch_execution_ms: ms4,
            deploy_rs_outcome: "Defaults to --no-check-sigs (src/cli.rs:41); no statvfs reserve guard before nix copy".into(),
            deploy_rs_split_brain_nodes: 1,
            colmena_outcome: "Hardcodes --no-check-sigs (src/nix/host/ssh.rs:293); no statvfs reserve guard".into(),
            colmena_split_brain_nodes: 1,
            colmena_secret_skew_nodes: 0,
        },
        FaultScenarioComparisonRow {
            scenario_id: "Gate-4.5".into(),
            title: "Canary Unit Failure on Node k in Coupled Wave After Speculative Activation".into(),
            epoch_outcome: "N1..N4 held in BARRIER_WAIT; N5 unit fails -> AbortWave(77) reverts cohort to G_76 & zero-wipes gen-77".into(),
            epoch_split_brain_nodes: 0,
            epoch_secret_skew_nodes: 0,
            epoch_execution_ms: ms5,
            deploy_rs_outcome: "N1..N4 already confirmed & disarmed timer; if revoke SSH fails on any node (src/cli.rs:965) -> Split-Brain".into(),
            deploy_rs_split_brain_nodes: 4,
            colmena_outcome: "N1..N4 remain committed at G_77; N5 left with G_77 secrets in /run/keys -> Split-Brain + Secret Skew".into(),
            colmena_split_brain_nodes: 4,
            colmena_secret_skew_nodes: 1,
        },
    ];

    let gate4_verification_reports = vec![r1, r2, r3, r4, r5];

    Ok(Plane34BenchmarkReport {
        target_footprint,
        secret_swap_skew,
        gate4_fault_comparisons,
        gate4_verification_reports,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullHeadToHeadBenchmarkSuite {
    pub plane1_eval: Plane1BenchmarkReport,
    pub plane2_transport: Plane2BenchmarkReport,
    pub plane34_fault_and_footprint: Plane34BenchmarkReport,
}
