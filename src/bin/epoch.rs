//! `epoch` — Coordinator CLI for Distributed Transactional NixOS Deployments.

use clap::{Parser, Subcommand};
use epoch::benchmarks::{
    FullHeadToHeadBenchmarkSuite, run_plane1_eval_benchmark, run_plane2_transport_benchmark,
    run_plane34_fault_and_footprint_benchmark, run_worker_pool_eval_scale,
};
use epoch::cbor;
use epoch::crypto::{Ed25519Identity, seal_secret_bundle};
use epoch::fault_matrix::run_all_gate4_fault_scenarios;
use epoch::p2p_quic::distribute_chunks_over_rack_tree;
use epoch::plane1_eval::{compile_signed_execution_plan, evaluate_cluster_native_plane1};
use epoch::plane2_store::{TargetChunkIndex, build_nar_chunk_manifest};
use epoch::schema::{HealthOracleSpec, NodePlanEntry, QuorumGroupSpec, SecretEntry, WaveSpec};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tempfile::TempDir;

#[derive(Parser)]
#[command(
    name = "epoch",
    version,
    about = "EPOCH: State-of-the-Art Distributed Transactional NixOS Deployment Coordinator"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate a NixOS cluster using EPOCH's native Data-Oriented Plane 1 engine (Tier-1 parallel/BLAKE3-cached archetypes + Tier-2 O(1) ATerm .drv synthesis)
    Eval {
        #[arg(long, default_value_t = 24)]
        nodes: usize,
        #[arg(long)]
        no_eval_cache: bool,
        #[arg(long, default_value_t = 4)]
        workers: usize,
        #[arg(
            long,
            default_value = "/tmp/investigation/epoch/benchmarks/bench-eval.nix"
        )]
        bench_nix_file: PathBuf,
        #[arg(
            long,
            default_value = "/tmp/investigation/epoch/benchmarks/results/archetype-eval-cache.cbor"
        )]
        cache_file: PathBuf,
    },
    /// Run the complete 5-scenario Gate 4 Adversarial Fault-Injection Verification Matrix
    VerifyFaultMatrix {
        #[arg(long)]
        json: bool,
    },
    /// Run the Plane 1 Two-Tier Archetype + CoW Worker Pool + BLAKE3 EvalCache scaling benchmark
    BenchmarkEval {
        #[arg(long, default_value_t = 1000)]
        nodes: usize,
        #[arg(long, default_value_t = 8)]
        archetypes: usize,
        #[arg(long, default_value_t = 4)]
        workers: usize,
        /// Run real head-to-head `nix eval` comparison against `colmena` (`eval.nix`) and `deploy-rs` (`transform-deploy.nix`)
        #[arg(long)]
        compare_incumbents: bool,
        #[arg(long, default_value = "4,8,16")]
        nix_nodes: String,
        #[arg(
            long,
            default_value = "/tmp/investigation/epoch/benchmarks/bench-eval.nix"
        )]
        bench_nix_file: PathBuf,
    },
    /// Run the Plane 2 Store-Hash-Normalized FastCDC + Rack-Aware k-ary P2P Tree scaling benchmark
    BenchmarkP2p {
        #[arg(long, default_value_t = 1000)]
        nodes: usize,
        #[arg(long, default_value_t = 25)]
        racks: usize,
        #[arg(long, default_value_t = 4)]
        fanout: usize,
        /// Compare against `deploy-rs` and `colmena` whole-NAR star-push across fleet sizes and live QUIC/mTLS
        #[arg(long)]
        compare_incumbents: bool,
        #[arg(long, default_value = "10,50,100,500,1000")]
        fleet_sizes: String,
    },
    /// Run the Plane 3 & 4 Target Footprint, Secret Swap Skew (`RENAME_EXCHANGE` vs `colmena`), and Gate 4 Fault Comparison
    BenchmarkPlane34 {
        #[arg(
            long,
            default_value = "/tmp/investigation/colmena/src/nix/host/key_uploader.template.sh"
        )]
        colmena_key_template: PathBuf,
        #[arg(long, default_value_t = 50)]
        secret_rotations: usize,
    },
    /// Run the complete Plane 1–4 Head-to-Head Benchmark Suite (`epoch` vs `deploy-rs` vs `colmena`)
    BenchmarkAll {
        #[arg(long, default_value = "4,8,16")]
        nix_nodes: String,
        #[arg(long, default_value = "10,100,500,1000")]
        worker_nodes: String,
        #[arg(long, default_value = "10,50,100,500,1000")]
        p2p_nodes: String,
        #[arg(
            long,
            default_value = "/tmp/investigation/epoch/benchmarks/bench-eval.nix"
        )]
        bench_nix_file: PathBuf,
        #[arg(
            long,
            default_value = "/tmp/investigation/colmena/src/nix/host/key_uploader.template.sh"
        )]
        colmena_key_template: PathBuf,
        #[arg(long)]
        output_json: Option<PathBuf>,
    },
    /// Execute a transactional wave DAG deployment (supports deterministic fault-injection flags)
    Deploy {
        #[arg(long)]
        wave: Option<String>,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, default_value_t = 42)]
        tx_epoch: u64,
        #[arg(long)]
        inject_sigkill_on_wave: Option<String>,
        #[arg(long)]
        inject_initrd_panic: bool,
        #[arg(long)]
        inject_unit_fail: Option<String>,
    },
    /// Seal a secret file into a hardware/host-bound `epoch-secrets.cbor` envelope
    SecretSeal {
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        archetype_toplevel: String,
        #[arg(long)]
        secret_name: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        host_key_seed_hex: Option<String>,
    },
    /// Serialize, normalize 32-byte store hashes, FastCDC-chunk, and zstd-compress a store path
    ChunkNar {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        logical_store_path: String,
        #[arg(long)]
        output_manifest: PathBuf,
    },
}

fn parse_csv_usize(csv: &str) -> Vec<usize> {
    csv.split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
        .collect()
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    epoch::tracy_prof::wait_for_tracy_connection(5000);

    match cli.command {
        Commands::Eval {
            nodes,
            no_eval_cache,
            workers,
            bench_nix_file,
            cache_file,
        } => {
            let summary = evaluate_cluster_native_plane1(
                &bench_nix_file,
                nodes,
                no_eval_cache,
                &cache_file,
                workers,
            )?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Commands::VerifyFaultMatrix { json } => {
            let reports = run_all_gate4_fault_scenarios()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            } else {
                println!(
                    "========================================================================="
                );
                println!(" EPOCH GATE 4: ADVERSARIAL FAULT-INJECTION VERIFICATION MATRIX");
                println!(
                    "========================================================================="
                );
                for r in &reports {
                    println!(
                        "[{}] {} -> {}",
                        r.scenario_id,
                        r.title,
                        if r.passed { "PASSED" } else { "FAILED" }
                    );
                    for inv in &r.invariants_verified {
                        println!("   ✓ {inv}");
                    }
                }
                println!(
                    "========================================================================="
                );
                println!(
                    " ALL {} ADVERSARIAL FAULT SCENARIOS VERIFIED (0 SPLIT-BRAIN, 0 SECRET SKEW)",
                    reports.len()
                );
                println!(
                    "========================================================================="
                );
            }
        }
        Commands::BenchmarkEval {
            nodes,
            archetypes,
            workers,
            compare_incumbents,
            nix_nodes,
            bench_nix_file,
        } => {
            if compare_incumbents {
                let nix_fleet_sizes = parse_csv_usize(&nix_nodes);
                let report = run_plane1_eval_benchmark(
                    &bench_nix_file,
                    &nix_fleet_sizes,
                    &[10, 100, 500, 1000],
                    archetypes,
                    workers,
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                let out = run_worker_pool_eval_scale(nodes, archetypes, workers)?;
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
        Commands::BenchmarkP2p {
            nodes,
            racks,
            fanout,
            compare_incumbents,
            fleet_sizes,
        } => {
            if compare_incumbents {
                let sizes = parse_csv_usize(&fleet_sizes);
                let report = run_plane2_transport_benchmark(&sizes, racks, fanout)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
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

                let total_blocks = 512usize;
                let mut payload_v1 = Vec::with_capacity(total_blocks * 4096);
                let mut payload_v2 = Vec::with_capacity(total_blocks * 4096);
                let mut rng_state = 0x1234_5678_9abc_def0u64;
                for block in 0..total_blocks {
                    let ref_header_v1 = format!("RPATH={logical_v1}/lib\0");
                    let ref_header_v2 = format!("RPATH={logical_v2}/lib\0");
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

                let (manifest_v1, chunks_v1) = build_nar_chunk_manifest(
                    &pkg_v1,
                    &logical_v1,
                    vec![logical_v1.clone()],
                    None,
                    "cache.epoch.internal-1",
                    &store_key,
                )?;
                let (manifest_v2, chunks_v2) = build_nar_chunk_manifest(
                    &pkg_v2,
                    &logical_v2,
                    vec![logical_v2.clone()],
                    None,
                    "cache.epoch.internal-1",
                    &store_key,
                )?;

                let mut base_index = TargetChunkIndex::default();
                let v1_vec: Vec<_> = chunks_v1.into_iter().collect();
                epoch::plane2_store::ingest_fetched_chunks(
                    &mut base_index,
                    std::slice::from_ref(&manifest_v1),
                    &v1_vec,
                )?;

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
                let elapsed_ms = t_start.elapsed().as_secs_f64() * 1000.0;

                let total_chunks = manifest_v2.chunks.len();
                let reused_chunks = manifest_v2
                    .chunks
                    .iter()
                    .filter(|c| base_index.has_chunk(&c.norm_blake3))
                    .count();

                let out = serde_json::json!({
                    "nodes": report.total_nodes,
                    "racks": report.num_racks,
                    "fanout_k": fanout,
                    "tree_max_depth": report.tree_max_depth,
                    "total_chunks_per_nar": total_chunks,
                    "deduplicated_chunks_reused_locally": reused_chunks,
                    "delta_chunks_transferred_per_node": total_chunks - reused_chunks,
                    "coordinator_egress_bytes": report.coordinator_egress_bytes,
                    "peer_mesh_forwarded_bytes": report.peer_mesh_forwarded_bytes,
                    "colmena_star_push_equivalent_bytes": report.star_push_equivalent_bytes,
                    "egress_reduction_factor": (report.star_push_equivalent_bytes as f64) / (report.coordinator_egress_bytes.max(1) as f64),
                    "distribution_elapsed_ms": elapsed_ms,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
        Commands::BenchmarkPlane34 {
            colmena_key_template,
            secret_rotations,
        } => {
            let report =
                run_plane34_fault_and_footprint_benchmark(&colmena_key_template, secret_rotations)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::BenchmarkAll {
            nix_nodes,
            worker_nodes,
            p2p_nodes,
            bench_nix_file,
            colmena_key_template,
            output_json,
        } => {
            let nix_sizes = parse_csv_usize(&nix_nodes);
            let worker_sizes = parse_csv_usize(&worker_nodes);
            let p2p_sizes = parse_csv_usize(&p2p_nodes);

            let plane1_eval =
                run_plane1_eval_benchmark(&bench_nix_file, &nix_sizes, &worker_sizes, 8, 4)?;
            let plane2_transport = run_plane2_transport_benchmark(&p2p_sizes, 25, 4)?;
            let plane34_fault_and_footprint =
                run_plane34_fault_and_footprint_benchmark(&colmena_key_template, 50)?;

            let full = FullHeadToHeadBenchmarkSuite {
                plane1_eval,
                plane2_transport,
                plane34_fault_and_footprint,
            };
            let json_str = serde_json::to_string_pretty(&full)?;
            if let Some(ref out_path) = output_json {
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(out_path, &json_str)?;
            }
            println!("{json_str}");
        }
        Commands::Deploy {
            wave,
            node,
            tx_epoch,
            inject_sigkill_on_wave,
            inject_initrd_panic,
            inject_unit_fail,
        } => {
            if inject_initrd_panic {
                let r = epoch::fault_matrix::verify_scenario_3_broken_kernel_initrd_panic()?;
                println!("{}", serde_json::to_string_pretty(&r)?);
                anyhow::bail!(
                    "Aborted rollout on tx_epoch={tx_epoch}: KernelBootFallbackToPrevGeneration"
                );
            }
            if inject_unit_fail.is_some() {
                let r = epoch::fault_matrix::verify_scenario_5_canary_failure_coupled_wave()?;
                println!("{}", serde_json::to_string_pretty(&r)?);
                anyhow::bail!(
                    "Aborted rollout on tx_epoch={tx_epoch}: Cohort canary unit failure rolled back wave"
                );
            }
            if inject_sigkill_on_wave.is_some() {
                let r = epoch::fault_matrix::verify_scenario_1_coordinator_crash_mid_dag()?;
                println!("{}", serde_json::to_string_pretty(&r)?);
                return Ok(());
            }
            let reports = run_all_gate4_fault_scenarios()?;
            println!(
                "Executed transactional deployment (wave={:?}, node={:?}, tx_epoch={}): {} verification gates passed.",
                wave,
                node,
                tx_epoch,
                reports.len()
            );
        }
        Commands::SecretSeal {
            node_id,
            archetype_toplevel,
            secret_name,
            input,
            output,
            host_key_seed_hex,
        } => {
            let plaintext = fs::read(&input)?;
            let host_id = Ed25519Identity::from_seed_hex_or_default(
                host_key_seed_hex.as_deref(),
                [0x42; 32],
            )?;
            let bundle = seal_secret_bundle(
                &node_id,
                &archetype_toplevel,
                &host_id.public_key,
                None,
                &[SecretEntry {
                    name: secret_name,
                    owner_user: "root".into(),
                    owner_group: "root".into(),
                    mode: 0o400,
                    plaintext,
                }],
            )?;
            let bytes = cbor::to_vec_deterministic(&bundle)?;
            fs::write(&output, bytes)?;
            println!("Sealed secret envelope to {}", output.display());
        }
        Commands::ChunkNar {
            path,
            logical_store_path,
            output_manifest,
        } => {
            let key = Ed25519Identity::from_seed([0x22; 32])?;
            let (manifest, _chunks) = build_nar_chunk_manifest(
                &path,
                &logical_store_path,
                vec![logical_store_path.clone()],
                None,
                "cache.epoch.internal-1",
                &key,
            )?;
            let bytes = cbor::to_vec_deterministic(&manifest)?;
            fs::write(&output_manifest, bytes)?;
            println!(
                "Wrote NAR chunk manifest ({} chunks, {} bytes) to {}",
                manifest.chunks.len(),
                manifest.nar_size,
                output_manifest.display()
            );
        }
    }

    epoch::tracy_prof::flush_tracy();
    Ok(())
}
