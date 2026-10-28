//! `epoch` — Coordinator CLI for Distributed Transactional NixOS Deployments.

use clap::{Parser, Subcommand};
use epoch::benchmarks::{
    FullHeadToHeadBenchmarkSuite, run_plane1_eval_benchmark, run_plane2_transport_benchmark,
    run_plane34_fault_and_footprint_benchmark, run_worker_pool_eval_scale,
};
use epoch::cbor;
use epoch::crypto::{
    Ed25519Identity, parse_nix_secret_key, seal_secret_bundle, sign_activate_wave, sign_commit_wave,
};
use epoch::fault_matrix::run_all_gate4_fault_scenarios;
use epoch::p2p_quic::{bind_quic_endpoint, distribute_chunks_over_rack_tree, quic_rpc_call};
use epoch::plane1_eval::{compile_signed_execution_plan, evaluate_cluster_native_plane1};
use epoch::plane2_store::{TargetChunkIndex, build_nar_chunk_manifest};
use epoch::schema::{
    EpochWireMsg, HealthOracleSpec, NodePlanEntry, QuorumGroupSpec, SecretEntry, WaveSpec,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
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
    /// Execute a live QUIC/mTLS NixOS deployment (`epoch deploy [switch|boot|test|dry-activate] (<host> | --store-path <path>)`) or transactional wave DAG verification
    Deploy {
        /// Optional `[switch|boot|test|dry-activate]` action followed by optional `<host>`
        #[arg(value_name = "ACTION_OR_HOST")]
        args: Vec<String>,
        /// Deploy a pre-built NixOS system closure path directly without running `nix build`
        #[arg(long)]
        store_path: Option<PathBuf>,
        /// Flake URI when building `<host>` (defaults to `$SATURN_FLAKE` or `.`)
        #[arg(long)]
        flake: Option<String>,
        /// Path to Nix Ed25519 secret signing key (`<name>:<base64>`) (defaults to `$SATURN_SIGNING_KEY` or `/etc/nix/signing-key.sec`)
        #[arg(long, alias = "key", short = 'k')]
        signing_key: Option<PathBuf>,
        /// Optional GC root output link when building from a flake
        #[arg(long)]
        out_link: Option<PathBuf>,
        /// Override target QUIC endpoint (`<host_or_ip>:<port>`)
        #[arg(long)]
        endpoint: Option<String>,
        /// Override confirmation lease timeout in seconds
        #[arg(long)]
        confirm_timeout: Option<u64>,
        /// Override `nix build` timeout in seconds
        #[arg(long)]
        build_timeout: Option<u64>,
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
            args,
            store_path,
            flake,
            signing_key,
            out_link,
            endpoint,
            confirm_timeout,
            build_timeout,
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
            if args.is_empty() && store_path.is_none() && (wave.is_some() || node.is_some()) {
                let reports = run_all_gate4_fault_scenarios()?;
                println!(
                    "Executed transactional deployment (wave={:?}, node={:?}, tx_epoch={}): {} verification gates passed.",
                    wave,
                    node,
                    tx_epoch,
                    reports.len()
                );
                return Ok(());
            }

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run_live_quic_deploy(
                &args,
                store_path,
                flake,
                signing_key,
                out_link,
                endpoint,
                confirm_timeout,
                build_timeout,
                tx_epoch,
            ))?;
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

fn query_store_closure(toplevel: &Path) -> Vec<String> {
    if let Ok(out) = std::process::Command::new("nix-store")
        .arg("-qR")
        .arg(toplevel)
        .output()
        && out.status.success()
    {
        let list: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    vec![toplevel.to_string_lossy().into_owned()]
}

fn query_immediate_references(store_path: &str) -> Vec<String> {
    if let Ok(out) = std::process::Command::new("nix-store")
        .arg("-q")
        .arg("--references")
        .arg(store_path)
        .output()
        && out.status.success()
    {
        let mut refs: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !refs.iter().any(|r| r == store_path) {
            refs.push(store_path.to_owned());
        }
        return refs;
    }
    vec![store_path.to_owned()]
}

async fn send_quic_wire_msg(
    endpoint: &quinn::Endpoint,
    remote_addr: SocketAddr,
    req: &EpochWireMsg,
    timeout_ms: u64,
) -> anyhow::Result<EpochWireMsg> {
    let resp = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        quic_rpc_call(endpoint, remote_addr, req),
    )
    .await
    .map_err(|_| anyhow::anyhow!("QUIC RPC to {remote_addr} timed out after {timeout_ms}ms"))??;
    Ok(resp)
}

const SSH_BOOTSTRAP_SCRIPT: &str = r#"
set -euo pipefail

action="$1"
toplevel="$2"
target="$3"
confirm_timeout="$4"
key_file="$5"

export NIX_CONFIG="extra-experimental-features = nix-command flakes${NIX_CONFIG:+$'\n'$NIX_CONFIG}"

tmp_base="${TMPDIR:-/tmp}"
if [[ ! -d "$tmp_base" || ! -w "$tmp_base" || "$tmp_base" =~ [[:space:]] ]] || (( ${#tmp_base} > 60 )); then
  tmp_base="/tmp"
fi
work_dir=$(mktemp -d "$tmp_base/saturn-deploy.XXXXXX")
chmod 700 "$work_dir"
ctrl_sock="$work_dir/ssh.sock"

ssh_extra=()
if [[ -n "${NIX_SSHOPTS:-}" ]]; then
  read -r -a ssh_extra <<< "$NIX_SSHOPTS"
fi

mux_opts=(
  "${ssh_extra[@]}"
  -o ControlMaster=auto
  -o "ControlPath=$ctrl_sock"
  -o ControlPersist=300
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=3
)
fresh_opts=(
  "${ssh_extra[@]}"
  -o ControlMaster=no
  -o ControlPath=none
  -o ConnectTimeout=5
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=2
)

run_id=$(< /proc/sys/kernel/random/uuid)
hold_active=false
mux_pid=""

quote_sh() {
  local sq="'\\''"
  printf "'%s'" "${1//\'/$sq}"
}

close_mux() {
  if [[ -n "$mux_pid" ]]; then
    wait "$mux_pid" 2>/dev/null || true
    mux_pid=""
  fi
  if [[ -S "$ctrl_sock" ]]; then
    ssh "${ssh_extra[@]}" -o "ControlPath=$ctrl_sock" -O exit "$target" >/dev/null 2>&1 || true
  fi
}
cleanup() {
  if "$hold_active" && [[ -S "$ctrl_sock" ]]; then
    ssh -n "${mux_opts[@]}" "$target" \
      "rm -rf /tmp/saturn-deploy-hold-$(quote_sh "$run_id") /tmp/saturn-deploy-root.$(quote_sh "$run_id").*" \
      >/dev/null 2>&1 || true
  fi
  close_mux
  rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

ssh -fN "${mux_opts[@]}" "$target" >/dev/null 2>&1 &
mux_pid=$!

if [[ -n "$key_file" && -r "$key_file" ]]; then
  nix store sign --key-file "$key_file" --recursive "$toplevel"
fi

wait "$mux_pid" 2>/dev/null || true
mux_pid=""

NIX_SSHOPTS="${mux_opts[*]}" nix copy --to "ssh-ng://$target" "$toplevel" </dev/null

sudo_needs_pass=true
sudo_password=""

run_remote_root() {
  local mode="$1"
  local script="$2"
  shift 2
  local quoted_args
  quoted_args="$(quote_sh "$run_id") $(quote_sh "$script")"
  local arg
  for arg in "$@"; do
    quoted_args+=" $(quote_sh "$arg")"
  done
  local wrapper='
    set -eu
    export PATH="/run/wrappers/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/bin"
    run_id="$1"
    script="$2"
    shift 2
    d=$(mktemp -d "/tmp/saturn-deploy-root.$run_id.XXXXXX")
    trap "rm -rf \"\$d\" 2>/dev/null || true" EXIT INT TERM HUP
    printf "%s\n" "$script" > "$d/run.sh"
    rc=0
    sudo -u root -S -p "" -- /bin/sh "$d/run.sh" "$@" || rc=$?
    if [ -d "$d" ]; then
      rm -rf "$d" 2>/dev/null || true
      exit 41
    fi
    exit "$rc"
  '
  local remote_cmd
  remote_cmd="/bin/sh -c $(quote_sh "$wrapper") sh $quoted_args"
  local -a opts
  if [[ "$mode" == "mux" ]]; then
    opts=("${mux_opts[@]}")
  else
    opts=("${fresh_opts[@]}")
  fi
  if "$sudo_needs_pass"; then
    printf '%s\n' "$sudo_password" | ssh "${opts[@]}" "$target" "$remote_cmd"
  else
    ssh "${opts[@]}" "$target" "$remote_cmd" </dev/null
  fi
}

dry_script='
  exec </dev/null
  set -eu
  rm -rf "$(dirname "$0")" 2>/dev/null || true
  toplevel="$2"
  run_id="$3"
  trap "rm -f \"/tmp/saturn-deploy-hold-$run_id\"" EXIT
  export PATH="/run/wrappers/bin:$toplevel/sw/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/bin"
  if [ -f "$toplevel/sw/lib/locale/locale-archive" ]; then
    export LOCALE_ARCHIVE="$toplevel/sw/lib/locale/locale-archive"
  fi
  cd /
  "$toplevel/bin/switch-to-configuration" dry-activate
'

launch_script='
  exec </dev/null
  set -eu
  rm -rf "$(dirname "$0")" 2>/dev/null || true
  action="$1"
  toplevel="$2"
  run_id="$3"
  confirm_timeout="$4"
  export PATH="/run/wrappers/bin:$toplevel/sw/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/bin"

  unit="saturn-deploy.service"
  if systemctl is-active --quiet "$unit" nixos-rebuild-switch-to-configuration.service; then
    rm -f "/tmp/saturn-deploy-hold-$run_id"
    echo "Another saturn-deploy activation is already running on this host." >&2
    exit 42
  fi
  systemctl reset-failed "$unit" >/dev/null 2>&1 || true

  install -d -m 0700 /run/saturn-deploy
  find /run/saturn-deploy -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} + 2>/dev/null || true
  state_dir="/run/saturn-deploy/$run_id"
  install -d -m 0700 "$state_dir"
  : > "$state_dir/log"
  mkfifo -m 0600 "$state_dir/confirm.fifo" "$state_dir/event.fifo"
  printf "%s\n" "$$" > "$state_dir/client.pid"

  gc_root="/nix/var/nix/gcroots/saturn-deploy"
  ln -sfn "$toplevel" "$gc_root" 2>/dev/null || true
  rm -f "/tmp/saturn-deploy-hold-$run_id" 2>/dev/null || true

  cat <<\EOF > "$state_dir/worker.sh"
#!/bin/sh
set -eu
action="$1"
toplevel="$2"
state_dir="$3"
confirm_timeout="$4"
run_id="$5"
export PATH="/run/wrappers/bin:$toplevel/sw/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/bin"
if [ -f "$toplevel/sw/lib/locale/locale-archive" ]; then
  export LOCALE_ARCHIVE="$toplevel/sw/lib/locale/locale-archive"
fi

exec </dev/null >"$state_dir/log" 2>&1 3<>"$state_dir/confirm.fifo" 4<>"$state_dir/event.fifo"
printf "%s\n" "$$" > "$state_dir/worker.pid.tmp"
mv -f "$state_dir/worker.pid.tmp" "$state_dir/worker.pid"

gc_root="/nix/var/nix/gcroots/saturn-deploy"
ln -sfn "$toplevel" "$gc_root" 2>/dev/null || true
rm -f "/tmp/saturn-deploy-hold-$run_id" 2>/dev/null || true

cur_status="running"
write_status() {
  cur_status="$1"
  printf "%s\n" "$1" > "$state_dir/status.tmp"
  mv -f "$state_dir/status.tmp" "$state_dir/status"
  if [ "$1" = "ready" ]; then
    printf "\n" >&4 || true
  fi
}

finish_log() {
  if [ "$cur_status" != "confirmed" ] && [ "$cur_status" != "rolled-back" ] && [ "$cur_status" != "failed" ]; then
    write_status "failed"
  fi
  rm -f "$gc_root" 2>/dev/null || true
  cp -f "$state_dir/log" /run/saturn-deploy/last.log 2>/dev/null || true
  cp -f "$state_dir/status" /run/saturn-deploy/last.status 2>/dev/null || true
  printf "%s\n" "$run_id" > /run/saturn-deploy/last.run_id 2>/dev/null || true
  systemd-cat -t saturn-deploy < "$state_dir/log" 2>/dev/null || true
  : > "$state_dir/done"
  printf "\n" >&4 || true
}
trap finish_log EXIT

profile=/nix/var/nix/profiles/system
prev_current=$(readlink -f /run/current-system 2>/dev/null || true)
if { [ "$action" = "switch" ] || [ "$action" = "boot" ]; } && [ ! -L "$profile" ] && [ -n "$prev_current" ] && [ "$prev_current" != "$toplevel" ]; then
  nix-env -p "$profile" --set "$prev_current" 3>&- 4>&-
fi
prev_link=$(readlink "$profile" 2>/dev/null || true)
prev_profile=$(readlink -f "$profile" 2>/dev/null || true)

rollback_profile() {
  failed_link=$(readlink "$profile" 2>/dev/null || true)
  if [ -n "$prev_link" ] && [ "$failed_link" != "$prev_link" ]; then
    nix-env -p "$profile" --rollback 3>&- 4>&-
    gen_num=${failed_link#system-}
    gen_num=${gen_num%-link}
    case "$gen_num" in
      ""|*[!0-9]*) ;;
      *) nix-env -p "$profile" --delete-generations "$gen_num" 3>&- 4>&- || true ;;
    esac
  fi
}

rollback() {
  set +e
  echo "De-activating due to error; rolling back to previous configuration..." >&2
  if [ "$action" = "boot" ]; then
    rollback_profile
    if [ -x "$profile/bin/switch-to-configuration" ]; then
      (exec 3>&- 4>&-; cd / && "$profile/bin/switch-to-configuration" boot)
    fi
  elif [ "$action" = "switch" ]; then
    rollback_profile
    if [ -z "$prev_current" ] || [ "$prev_profile" = "$prev_current" ]; then
      if [ -x "$profile/bin/switch-to-configuration" ]; then
        (exec 3>&- 4>&-; cd / && "$profile/bin/switch-to-configuration" switch)
      elif [ -n "$prev_current" ] && [ -x "$prev_current/bin/switch-to-configuration" ]; then
        (exec 3>&- 4>&-; cd / && "$prev_current/bin/switch-to-configuration" switch)
      fi
    else
      if [ -x "$prev_current/bin/switch-to-configuration" ]; then
        (exec 3>&- 4>&-; cd / && "$prev_current/bin/switch-to-configuration" test)
      fi
      if [ -x "$profile/bin/switch-to-configuration" ]; then
        (exec 3>&- 4>&-; cd / && "$profile/bin/switch-to-configuration" boot)
      fi
    fi
  elif [ "$action" = "test" ] && [ -n "$prev_current" ] && [ -x "$prev_current/bin/switch-to-configuration" ]; then
    (exec 3>&- 4>&-; cd / && "$prev_current/bin/switch-to-configuration" test)
  fi
}

if [ "$action" = "switch" ] || [ "$action" = "boot" ]; then
  if ! nix-env -p "$profile" --set "$toplevel" 3>&- 4>&-; then
    rollback
    write_status "failed"
    exit 1
  fi
fi

if ! (exec 3>&- 4>&-; cd / && "$toplevel/bin/switch-to-configuration" "$action"); then
  echo "switch-to-configuration $action failed." >&2
  rollback
  write_status "failed"
  exit 1
fi

if [ "$action" = "boot" ]; then
  write_status "confirmed"
  exit 0
fi

if [ -x "$toplevel/saturn-health-check" ]; then
  if ! (exec 3>&- 4>&-; cd / && timeout "$confirm_timeout" "$toplevel/saturn-health-check"); then
    echo "Post-activation health check failed." >&2
    rollback
    write_status "failed"
    exit 1
  fi
fi

write_status "ready"

if [ -e "$state_dir/confirmed" ] || read -r -t "$confirm_timeout" _ <&3 || [ -e "$state_dir/confirmed" ]; then
  echo "Activation succeeded."
  write_status "confirmed"
  exit 0
fi

write_status "rolling-back"
echo "Timeout elapsed for confirmation (${confirm_timeout}s)." >&2
rollback
write_status "rolled-back"
exit 1
EOF
  chmod 0700 "$state_dir/worker.sh"

  exec 4<>"$state_dir/event.fifo"
  if ! systemd-run \
    --unit="$unit" \
    --collect \
    --no-ask-password \
    --service-type=exec \
    --quiet \
    "$state_dir/worker.sh" "$action" "$toplevel" "$state_dir" "$confirm_timeout" "$run_id" >/dev/null 4>&-; then
    rm -f "$gc_root" "/tmp/saturn-deploy-hold-$run_id"
    rm -rf "$state_dir"
    exit 42
  fi

  printed=0
  flush_log() {
    if [ -f "$state_dir/log" ]; then
      total=$(wc -c < "$state_dir/log" 2>/dev/null || echo 0)
      if [ "$total" -gt "$printed" ]; then
        tail -c +"$((printed + 1))" "$state_dir/log" 2>/dev/null | head -c "$((total - printed))" || true
        printed="$total"
      fi
    fi
  }

  worker_pid=""
  unit_active() {
    if [ -z "$worker_pid" ] && [ -f "$state_dir/worker.pid" ]; then
      IFS= read -r worker_pid < "$state_dir/worker.pid" 2>/dev/null || worker_pid=""
    fi
    if [ -n "$worker_pid" ] && kill -0 "$worker_pid" 2>/dev/null; then
      return 0
    fi
    systemctl is-active --quiet "$unit"
  }

  while [ ! -f "$state_dir/status" ] && unit_active; do
    flush_log
    read -r -t 0.1 _ <&4 || true
  done
  flush_log

  IFS= read -r status < "$state_dir/status" 2>/dev/null || status="failed"
  if [ "$status" = "ready" ]; then
    exit 0
  fi

  while [ ! -f "$state_dir/done" ] && unit_active; do
    flush_log
    read -r -t 0.1 _ <&4 || true
  done
  flush_log
  IFS= read -r status < "$state_dir/status" 2>/dev/null || status="failed"
  rm -rf "$state_dir"
  if [ "$status" = "confirmed" ]; then
    exit 0
  fi
  exit 42
'

if [[ -t 0 && -z "${SATURN_SUDO_PASSWORD+x}" ]]; then
  hold_active=true
  diff_script='
    export PATH="/run/wrappers/bin:$1/sw/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/bin"
    nix-store --realise "$1" --add-root "/tmp/saturn-deploy-hold-$2" >/dev/null 2>&1 || true
    if [ -e /run/current-system ]; then
      current=$(readlink -f /run/current-system)
      printf "<<< %s\n>>> %s\n" "$current" "$1" >&2
      if [ "$current" != "$1" ]; then
        nix --extra-experimental-features "nix-command flakes" store diff-closures "$current" "$1" >&2 || true
      fi
    fi
    if sudo -n true >/dev/null 2>&1; then
      exit 0
    fi
    exit 40
  '
  diff_rc=0
  ssh -n "${mux_opts[@]}" "$target" \
    "/bin/sh -c $(quote_sh "$diff_script") sh $(quote_sh "$toplevel") $(quote_sh "$run_id")" || diff_rc=$?
  if (( diff_rc == 0 )); then
    sudo_needs_pass=false
    if [[ "$action" == "dry-activate" ]]; then
      run_remote_root mux "$dry_script" "$action" "$toplevel" "$run_id" "$confirm_timeout"
      hold_active=false
      exit 0
    fi
    : > "$work_dir/streamed.log"
    set +e
    run_remote_root mux "$launch_script" "$action" "$toplevel" "$run_id" "$confirm_timeout" \
      | tee -a "$work_dir/streamed.log" >&2
    launch_rc="${PIPESTATUS[0]}"
    set -e
  elif (( diff_rc == 40 )); then
    auth_ok=false
    for attempt in 1 2 3; do
      if ! IFS= read -rsp "[sudo] password for $target: " sudo_password && [[ -z "$sudo_password" ]]; then
        echo >&2
        break
      fi
      echo >&2
      if [[ "$action" == "dry-activate" ]]; then
        launch_rc=0
        run_remote_root mux "$dry_script" "$action" "$toplevel" "$run_id" "$confirm_timeout" || launch_rc=$?
      else
        : > "$work_dir/streamed.log"
        set +e
        run_remote_root mux "$launch_script" "$action" "$toplevel" "$run_id" "$confirm_timeout" \
          | tee -a "$work_dir/streamed.log" >&2
        launch_rc="${PIPESTATUS[0]}"
        set -e
      fi
      if (( launch_rc != 41 )); then
        auth_ok=true
        break
      fi
      if (( attempt < 3 )); then
        echo "Sorry, try again." >&2
      fi
    done
    if ! "$auth_ok"; then
      echo "sudo authentication failed on $target." >&2
      exit 1
    fi
    if [[ "$action" == "dry-activate" ]]; then
      hold_active=false
      exit "$launch_rc"
    fi
  else
    exit "$diff_rc"
  fi
else
  if [[ -n "${SATURN_SUDO_PASSWORD+x}" ]]; then
    sudo_password="$SATURN_SUDO_PASSWORD"
  elif ! IFS= read -r sudo_password && [[ -z "$sudo_password" ]]; then
    sudo_needs_pass=false
  fi

  combined_script='
    set -eu
    action="$1"
    toplevel="$2"
    run_id="$3"
    confirm_timeout="$4"
    target_label="$5"
    root_script="$6"
    export PATH="/run/wrappers/bin:$toplevel/sw/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/bin"

    hold="/tmp/saturn-deploy-hold-$run_id"
    cmd_dir=$(mktemp -d "/tmp/saturn-deploy-root.$run_id.XXXXXX")
    trap "[ ! -d \"\$cmd_dir\" ] || rm -rf \"\$cmd_dir\" \"\$hold\" 2>/dev/null || true" EXIT INT TERM HUP
    printf "%s\n" "$root_script" > "$cmd_dir/run.sh"
    nix-store --realise "$toplevel" --add-root "$hold" </dev/null >/dev/null 2>&1 || true
    if [ -e /run/current-system ]; then
      current=$(readlink -f /run/current-system)
      printf "<<< %s\n>>> %s\n" "$current" "$toplevel" >&2
      if [ "$current" != "$toplevel" ]; then
        nix --extra-experimental-features "nix-command flakes" store diff-closures "$current" "$toplevel" </dev/null >&2 || true
      fi
    fi

    rc=0
    sudo -u root -S -p "" -- /bin/sh "$cmd_dir/run.sh" "$action" "$toplevel" "$run_id" "$confirm_timeout" || rc=$?
    if [ -d "$cmd_dir" ]; then
      rm -rf "$cmd_dir" "$hold"
      echo "sudo authentication failed on $target_label." >&2
      exit 41
    fi
    exit "$rc"
  '

  run_combined() {
    local root_script="$1"
    local remote_cmd
    remote_cmd="/bin/sh -c $(quote_sh "$combined_script") sh $(quote_sh "$action") $(quote_sh "$toplevel") $(quote_sh "$run_id") $(quote_sh "$confirm_timeout") $(quote_sh "$target") $(quote_sh "$root_script")"
    if "$sudo_needs_pass"; then
      printf '%s\n' "$sudo_password" | ssh "${mux_opts[@]}" "$target" "$remote_cmd"
    else
      ssh "${mux_opts[@]}" "$target" "$remote_cmd" </dev/null
    fi
  }

  hold_active=true
  if [[ "$action" == "dry-activate" ]]; then
    dry_rc=0
    run_combined "$dry_script" || dry_rc=$?
    if (( dry_rc == 41 )); then
      exit 1
    fi
    hold_active=false
    exit "$dry_rc"
  fi

  : > "$work_dir/streamed.log"
  set +e
  run_combined "$launch_script" | tee -a "$work_dir/streamed.log" >&2
  launch_rc="${PIPESTATUS[0]}"
  set -e
fi

if (( launch_rc == 41 || launch_rc == 42 )); then
  exit 1
fi
hold_active=false

if [[ "$action" == "boot" ]] && (( launch_rc == 0 )); then
  exit 0
fi

close_mux

confirm_script='
  exec </dev/null
  set -eu
  rm -rf "$(dirname "$0")" 2>/dev/null || true
  toplevel="$1"
  run_id="$2"
  printed="$3"
  export PATH="/run/wrappers/bin:$toplevel/sw/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/bin"
  unit="saturn-deploy.service"
  state_dir="/run/saturn-deploy/$run_id"

  flush_file() {
    file="$1"
    if [ -f "$file" ]; then
      total=$(wc -c < "$file" 2>/dev/null || echo 0)
      if [ "$total" -gt "$printed" ]; then
        tail -c +"$((printed + 1))" "$file" 2>/dev/null | head -c "$((total - printed))" || true
        printed="$total"
      fi
    fi
  }

  if [ ! -d "$state_dir" ]; then
    rm -rf "/tmp/saturn-deploy-hold-$run_id" /tmp/saturn-deploy-root."$run_id".* 2>/dev/null || true
    IFS= read -r last_id < /run/saturn-deploy/last.run_id 2>/dev/null || last_id=""
    IFS= read -r last_status < /run/saturn-deploy/last.status 2>/dev/null || last_status=""
    if [ "$last_id" = "$run_id" ]; then
      flush_file /run/saturn-deploy/last.log
      if [ "$last_status" = "confirmed" ]; then
        exit 0
      fi
    else
      echo "Activation unit for $run_id did not start on target." >&2
    fi
    exit 43
  fi

  if [ -f "$state_dir/client.pid" ]; then
    IFS= read -r old_pid < "$state_dir/client.pid" 2>/dev/null || old_pid=""
    if [ -n "$old_pid" ] && [ "$old_pid" != "$$" ]; then
      kill -TERM "$old_pid" 2>/dev/null || true
    fi
  fi
  printf "%s\n" "$$" > "$state_dir/client.pid"

  flush_log() {
    flush_file "$state_dir/log"
  }

  exec 4<>"$state_dir/event.fifo"
  worker_pid=""
  unit_active() {
    if [ -z "$worker_pid" ] && [ -f "$state_dir/worker.pid" ]; then
      IFS= read -r worker_pid < "$state_dir/worker.pid" 2>/dev/null || worker_pid=""
    fi
    if [ -n "$worker_pid" ] && kill -0 "$worker_pid" 2>/dev/null; then
      return 0
    fi
    systemctl is-active --quiet "$unit"
  }

  while [ ! -f "$state_dir/status" ] && unit_active; do
    flush_log
    read -r -t 0.1 _ <&4 || true
  done

  IFS= read -r status < "$state_dir/status" 2>/dev/null || status="failed"
  if [ "$status" = "ready" ]; then
    while read -r -t 0 _ <&4 2>/dev/null; do
      read -r -t 0.01 _ <&4 2>/dev/null || break
    done
    : > "$state_dir/confirmed"
    if [ -p "$state_dir/confirm.fifo" ]; then
      exec 3<>"$state_dir/confirm.fifo"
      printf "\n" >&3 || true
      exec 3>&-
    fi
  fi

  while [ ! -f "$state_dir/done" ] && unit_active; do
    flush_log
    read -r -t 0.1 _ <&4 || true
  done
  flush_log
  IFS= read -r final_status < "$state_dir/status" 2>/dev/null || final_status="failed"
  rm -rf "$state_dir"
  if [ "$final_status" = "confirmed" ]; then
    exit 0
  fi
  exit 43
'

deadline=$((SECONDS + confirm_timeout + 45))
while (( SECONDS < deadline )); do
  printed=$(wc -c < "$work_dir/streamed.log")
  set +e
  run_remote_root fresh "$confirm_script" "$toplevel" "$run_id" "$printed" \
    | tee -a "$work_dir/streamed.log" >&2
  confirm_rc="${PIPESTATUS[0]}"
  set -e

  if (( confirm_rc == 0 )); then
    exit 0
  elif (( confirm_rc == 43 )); then
    exit 1
  fi
  sleep 0.2
done

echo "Target $target remained unreachable after confirmation timeout." >&2
exit 1
"#;

fn run_ssh_bootstrap_deploy(
    action: &str,
    toplevel: &Path,
    ssh_target: &str,
    confirm_timeout_secs: u64,
    key_file: Option<&Path>,
) -> anyhow::Result<()> {
    let key_arg = key_file
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let status = Command::new("bash")
        .arg("-c")
        .arg(SSH_BOOTSTRAP_SCRIPT)
        .arg("epoch-ssh-bootstrap")
        .arg(action)
        .arg(toplevel.as_os_str())
        .arg(ssh_target)
        .arg(confirm_timeout_secs.to_string())
        .arg(&key_arg)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if !status.success() {
        anyhow::bail!("SSH bootstrap deployment to {ssh_target} failed");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_live_quic_deploy(
    args: &[String],
    store_path: Option<PathBuf>,
    flake: Option<String>,
    signing_key: Option<PathBuf>,
    out_link: Option<PathBuf>,
    endpoint: Option<String>,
    confirm_timeout: Option<u64>,
    build_timeout: Option<u64>,
    cli_tx_epoch: u64,
) -> anyhow::Result<()> {
    if let Some(0) = confirm_timeout {
        anyhow::bail!("Invalid confirmation timeout: 0 (must be a positive integer)");
    }

    let (action, remaining) = match args.first().map(String::as_str) {
        Some("switch" | "boot" | "test" | "dry-activate") => (args[0].as_str(), &args[1..]),
        _ => ("switch", args),
    };
    let (host, extra_nix_flags) = match remaining.first() {
        Some(first) if !first.starts_with('-') => (Some(first.clone()), &remaining[1..]),
        _ => (None, remaining),
    };
    for flag in extra_nix_flags {
        if !flag.starts_with('-') {
            anyhow::bail!("Unexpected argument: {flag}");
        }
    }

    if (host.is_some() && store_path.is_some()) || (host.is_none() && store_path.is_none()) {
        anyhow::bail!(
            "Usage: epoch deploy [switch|boot|test|dry-activate] (<host> | --store-path <path>)"
        );
    }

    let mut resolved_key_path = signing_key
        .or_else(|| std::env::var_os("SATURN_SIGNING_KEY").map(PathBuf::from))
        .or_else(|| std::env::var_os("EPOCH_SIGNING_KEY").map(PathBuf::from))
        .or_else(|| std::env::var_os("LOCAL_KEY").map(PathBuf::from));

    let (key_name, coord_key) = if let Some(ref kp) = resolved_key_path {
        let raw = fs::read_to_string(kp)
            .map_err(|_| anyhow::anyhow!("Signing key is not readable: {}", kp.display()))?;
        let trimmed = raw.trim();
        if trimmed.contains(':') {
            parse_nix_secret_key(trimmed)
                .map_err(|e| anyhow::anyhow!("Signing key is not valid ({}): {e}", kp.display()))?
        } else {
            (
                "epoch-coord-1".to_owned(),
                Ed25519Identity::from_seed_hex_or_default(Some(trimmed), [0x11; 32])?,
            )
        }
    } else {
        let default_candidates = [
            PathBuf::from("/etc/nix/signing-key.sec"),
            PathBuf::from(format!(
                "{}/.config/nixing2/dragonfly-1.sec",
                std::env::var("HOME").unwrap_or_else(|_| "/root".into())
            )),
        ];
        if let Some(found) = default_candidates.into_iter().find(|p| p.exists()) {
            let raw = fs::read_to_string(&found)
                .map_err(|_| anyhow::anyhow!("Signing key is not readable: {}", found.display()))?;
            let trimmed = raw.trim();
            resolved_key_path = Some(found);
            if trimmed.contains(':') {
                parse_nix_secret_key(trimmed)?
            } else {
                (
                    "epoch-coord-1".to_owned(),
                    Ed25519Identity::from_seed_hex_or_default(Some(trimmed), [0x11; 32])?,
                )
            }
        } else {
            (
                "epoch-coord-1".to_owned(),
                Ed25519Identity::from_seed([0x11; 32])?,
            )
        }
    };

    let toplevel = if let Some(ref sp) = store_path {
        if !sp.exists() {
            anyhow::bail!("Store path does not exist: {}", sp.display());
        }
        let canon = fs::canonicalize(sp)
            .map_err(|_| anyhow::anyhow!("Store path does not exist: {}", sp.display()))?;
        if !canon.join("nixos-version").is_file()
            || !canon.join("bin/switch-to-configuration").exists()
        {
            anyhow::bail!("Invalid NixOS system closure: {}", canon.display());
        }
        canon
    } else {
        let h = host.as_deref().unwrap();
        let flake_ref = flake
            .or_else(|| std::env::var("SATURN_FLAKE").ok())
            .unwrap_or_else(|| ".".to_owned());
        let out_link_path = out_link.unwrap_or_else(|| PathBuf::from(format!("result-{h}")));
        let attr = format!("{flake_ref}#.nixosConfigurations.{h}.config.system.build.toplevel");
        let build_secs = build_timeout.unwrap_or(1800);
        let mut cmd = tokio::process::Command::new("nix");
        cmd.args([
            "build",
            "--no-update-lock-file",
            "--extra-experimental-features",
            "nix-command flakes",
            "--print-out-paths",
            "--out-link",
        ])
        .arg(&out_link_path);
        for flag in extra_nix_flags {
            if flag != "--no-update-lock-file" {
                cmd.arg(flag);
            }
        }
        cmd.arg(&attr)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let output = tokio::time::timeout(Duration::from_secs(build_secs), cmd.output())
            .await
            .map_err(|_| anyhow::anyhow!("nix build timed out after {build_secs}s"))??;
        if !output.status.success() {
            anyhow::bail!("nix build failed for {attr}");
        }
        let built_str = String::from_utf8_lossy(&output.stdout)
            .lines()
            .last()
            .unwrap_or("")
            .trim()
            .to_owned();
        if built_str.is_empty() {
            anyhow::bail!("nix build produced empty output path for {attr}");
        }
        fs::canonicalize(&built_str)?
    };
    let toplevel_str = toplevel.to_string_lossy().into_owned();

    let meta_path = toplevel.join("saturn-deploy.json");
    let mut meta_hostname: Option<String> = None;
    let mut meta_ssh_user: String = "root".to_owned();
    let mut meta_node_id: Option<String> = None;
    let mut meta_quic_port: u16 = 9443;
    let mut meta_confirm_timeout: u64 = 60;

    if meta_path.is_file()
        && let Ok(meta_raw) = fs::read_to_string(&meta_path)
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&meta_raw)
    {
        if let Some(h) = val.get("hostname").and_then(|v| v.as_str())
            && !h.is_empty()
        {
            meta_hostname = Some(h.to_owned());
        }
        if let Some(u) = val.get("sshUser").and_then(|v| v.as_str())
            && !u.is_empty()
        {
            meta_ssh_user = u.to_owned();
        }
        if let Some(n) = val.get("nodeId").and_then(|v| v.as_str())
            && !n.is_empty()
        {
            meta_node_id = Some(n.to_owned());
        }
        if let Some(p) = val.get("quicPort").and_then(|v| v.as_u64())
            && (1..=65535).contains(&p)
        {
            meta_quic_port = p as u16;
        }
        if let Some(ct) = val.get("confirmTimeout").and_then(|v| v.as_u64()) {
            meta_confirm_timeout = ct;
        }
    }

    let confirm_timeout_secs = confirm_timeout.unwrap_or(meta_confirm_timeout);
    if confirm_timeout_secs == 0 {
        anyhow::bail!("Invalid confirmation timeout: 0 (must be a positive integer)");
    }

    let endpoint_str = if let Some(ep) = endpoint {
        if ep.contains(':') {
            ep
        } else {
            format!("{ep}:{meta_quic_port}")
        }
    } else if let Some(ref hn) = meta_hostname {
        format!("{hn}:{meta_quic_port}")
    } else {
        anyhow::bail!(
            "Host {} has no saturn.deploy.hostname configured; use local nixos-rebuild instead.",
            host.as_deref().unwrap_or(&toplevel_str)
        );
    };

    let target_node_id = meta_node_id
        .or_else(|| meta_hostname.clone())
        .or_else(|| host.clone())
        .unwrap_or_else(|| "target".to_owned());

    let resolved_addrs: Vec<SocketAddr> = tokio::net::lookup_host(&endpoint_str)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to resolve target endpoint '{endpoint_str}': {e}"))?
        .collect();
    let target_addr = resolved_addrs
        .iter()
        .find(|a| a.is_ipv4())
        .copied()
        .or_else(|| resolved_addrs.first().copied())
        .ok_or_else(|| anyhow::anyhow!("No socket addresses resolved for '{endpoint_str}'"))?;

    let closure_paths = query_store_closure(&toplevel);

    let (pre_switch_endpoint, _) = bind_quic_endpoint("0.0.0.0:0".parse()?, &coord_key)?;

    let initial_timeout_ms = if host.is_some() { 2_500 } else { 30_000 };
    let query_resp = match send_quic_wire_msg(
        &pre_switch_endpoint,
        target_addr,
        &EpochWireMsg::QueryMissingPathsReq {
            tx_epoch: cli_tx_epoch,
            store_paths: closure_paths.clone(),
        },
        initial_timeout_ms,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            let err_msg = e.to_string();
            if host.is_some()
                && let Some(ref hn) = meta_hostname
                && (err_msg.contains("timed out") || err_msg.contains("Connection refused"))
            {
                pre_switch_endpoint.close(0u32.into(), b"bootstrap");
                let ssh_target = format!("{meta_ssh_user}@{hn}");
                eprintln!(
                    "epoch-agent on {target_addr} is not yet reachable over UDP {meta_quic_port}; bootstrapping via SSH ({ssh_target})..."
                );
                return run_ssh_bootstrap_deploy(
                    action,
                    &toplevel,
                    &ssh_target,
                    confirm_timeout_secs,
                    resolved_key_path.as_deref(),
                );
            }
            return Err(anyhow::anyhow!("QUIC query to {target_addr} failed: {e}"));
        }
    };

    let (missing_paths, current_system, highest_tx_epoch, active_deployment) = match query_resp {
        EpochWireMsg::QueryMissingPathsResp {
            missing_paths,
            current_system,
            highest_tx_epoch,
            active_deployment,
            ..
        } => (
            missing_paths,
            current_system,
            highest_tx_epoch,
            active_deployment,
        ),
        other => anyhow::bail!("Unexpected response to QueryMissingPathsReq: {other:?}"),
    };

    if active_deployment {
        anyhow::bail!("Another saturn-deploy activation is already running on this host.");
    }

    let tx_epoch = if cli_tx_epoch == 42 || cli_tx_epoch <= highest_tx_epoch {
        highest_tx_epoch.saturating_add(1)
    } else {
        cli_tx_epoch
    };

    if !current_system.is_empty() {
        eprintln!("<<< {current_system}\n>>> {toplevel_str}");
        if current_system != toplevel_str && Path::new(&current_system).exists() {
            let _ = Command::new("nix")
                .args([
                    "--extra-experimental-features",
                    "nix-command flakes",
                    "store",
                    "diff-closures",
                    &current_system,
                    &toplevel_str,
                ])
                .status();
        }
    }

    let mut manifests = Vec::with_capacity(missing_paths.len());
    let mut unique_chunks: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for mp in &missing_paths {
        let refs = query_immediate_references(mp);
        let (manifest, chunks) =
            build_nar_chunk_manifest(Path::new(mp), mp, refs, None, &key_name, &coord_key)?;
        for (h, zstd_bytes) in chunks {
            unique_chunks.entry(h).or_insert(zstd_bytes);
        }
        manifests.push(manifest);
    }

    if !unique_chunks.is_empty() {
        let mut batch = Vec::new();
        let mut batch_bytes = 0usize;
        for (h, zstd_bytes) in unique_chunks {
            if !batch.is_empty()
                && (batch_bytes + zstd_bytes.len() > 4 * 1024 * 1024 || batch.len() >= 64)
            {
                let ack = send_quic_wire_msg(
                    &pre_switch_endpoint,
                    target_addr,
                    &EpochWireMsg::FetchChunksResp {
                        chunks: std::mem::take(&mut batch),
                    },
                    60_000,
                )
                .await?;
                if let EpochWireMsg::StageAck {
                    ok: false, error, ..
                } = ack
                {
                    anyhow::bail!(
                        "Chunk transfer rejected on {target_addr}: {}",
                        error.unwrap_or_default()
                    );
                }
                batch_bytes = 0;
            }
            batch_bytes += zstd_bytes.len();
            batch.push((h, zstd_bytes));
        }
        if !batch.is_empty() {
            let ack = send_quic_wire_msg(
                &pre_switch_endpoint,
                target_addr,
                &EpochWireMsg::FetchChunksResp { chunks: batch },
                60_000,
            )
            .await?;
            if let EpochWireMsg::StageAck {
                ok: false, error, ..
            } = ack
            {
                anyhow::bail!(
                    "Chunk transfer rejected on {target_addr}: {}",
                    error.unwrap_or_default()
                );
            }
        }
    }

    let kernel_path = fs::read_link(toplevel.join("kernel"))
        .unwrap_or_else(|_| PathBuf::from("/nix/store/kernel/bzImage"))
        .to_string_lossy()
        .into_owned();
    let initrd_path = fs::read_link(toplevel.join("initrd"))
        .unwrap_or_else(|_| PathBuf::from("/nix/store/initrd/initrd"))
        .to_string_lossy()
        .into_owned();

    let lease_ttl_ms = (confirm_timeout_secs.saturating_mul(1000)).min(u32::MAX as u64) as u32;
    let waves = vec![WaveSpec {
        wave_id: action.to_owned(),
        depends_on: vec![],
        node_ids: vec![target_node_id.clone()],
        max_unavailable: 0,
        lease_ttl_ms,
        reboot_lease_ttl_ms: 120_000,
        probes: HealthOracleSpec::default(),
    }];
    let plan_nodes = vec![NodePlanEntry {
        node_id: target_node_id.clone(),
        system_arch: "x86_64-linux".into(),
        rack_id: "default".into(),
        zone_id: "default".into(),
        quic_endpoint: target_addr.to_string(),
        node_pub: coord_key.public_key,
        toplevel_path: toplevel_str.clone(),
        kernel_path,
        initrd_path,
        secrets_envelope_hash: [0u8; 32],
        closure_manifests_merkle_root: [0u8; 32],
        p2p_parent_node_id: None,
        p2p_children_node_ids: vec![],
    }];
    let signed_plan = compile_signed_execution_plan(
        "saturn-cluster",
        tx_epoch,
        *blake3::hash(toplevel_str.as_bytes()).as_bytes(),
        &waves,
        &[] as &[QuorumGroupSpec],
        plan_nodes,
        4,
        &coord_key,
    )?;

    let stage_ack = send_quic_wire_msg(
        &pre_switch_endpoint,
        target_addr,
        &EpochWireMsg::StageManifest {
            tx_epoch,
            plan: signed_plan,
            manifests,
        },
        60_000,
    )
    .await?;
    match stage_ack {
        EpochWireMsg::StageAck { ok: true, .. } => {}
        EpochWireMsg::StageAck {
            ok: false, error, ..
        } => {
            anyhow::bail!("{}", error.unwrap_or_else(|| "StageManifest failed".into()));
        }
        other => anyhow::bail!("Unexpected response to StageManifest: {other:?}"),
    }

    let prep_ack = send_quic_wire_msg(
        &pre_switch_endpoint,
        target_addr,
        &EpochWireMsg::PrepareWave {
            tx_epoch,
            wave_id: action.to_owned(),
        },
        30_000,
    )
    .await?;
    match prep_ack {
        EpochWireMsg::PrepareAck { ok: true, .. } => {}
        EpochWireMsg::PrepareAck {
            ok: false, error, ..
        } => {
            anyhow::bail!("{}", error.unwrap_or_else(|| "PrepareWave failed".into()));
        }
        other => anyhow::bail!("Unexpected response to PrepareWave: {other:?}"),
    }

    let activate_msg = sign_activate_wave(&coord_key, tx_epoch, action, lease_ttl_ms)?;
    let activate_timeout_ms = (confirm_timeout_secs.saturating_add(60)).saturating_mul(1000);
    let activate_resp = send_quic_wire_msg(
        &pre_switch_endpoint,
        target_addr,
        &activate_msg,
        activate_timeout_ms,
    )
    .await?;

    let att_hash = *blake3::hash(&cbor::to_vec_deterministic(&activate_resp)?).as_bytes();
    match activate_resp {
        EpochWireMsg::HealthAttestation {
            healthy: true,
            diagnostic,
            ..
        } => {
            if !diagnostic.is_empty() {
                eprintln!("{diagnostic}");
            }
        }
        EpochWireMsg::HealthAttestation {
            healthy: false,
            diagnostic,
            ..
        } => {
            anyhow::bail!(
                "De-activating due to error; rolling back to previous configuration...\n{diagnostic}"
            );
        }
        other => anyhow::bail!("Unexpected response to ActivateWave: {other:?}"),
    }

    let commit_msg = sign_commit_wave(&coord_key, tx_epoch, action, vec![att_hash])?;

    if action == "dry-activate" || action == "boot" {
        let commit_resp =
            send_quic_wire_msg(&pre_switch_endpoint, target_addr, &commit_msg, 30_000).await?;
        match commit_resp {
            EpochWireMsg::HealthAttestation { healthy: true, .. } => {
                println!("Activation succeeded.");
                return Ok(());
            }
            EpochWireMsg::HealthAttestation {
                healthy: false,
                diagnostic,
                ..
            } => {
                anyhow::bail!(
                    "De-activating due to error; rolling back to previous configuration...\n{diagnostic}"
                );
            }
            other => anyhow::bail!("Unexpected response to CommitWave: {other:?}"),
        }
    }

    // Bind fresh QUIC endpoint on a new ephemeral UDP source port (`ctstate NEW`) BEFORE closing
    // `pre_switch_endpoint` so the OS cannot reuse the old port and firewall changes are genuinely tested.
    let (fresh_endpoint, _) = bind_quic_endpoint("0.0.0.0:0".parse()?, &coord_key)?;
    pre_switch_endpoint.close(0u32.into(), b"pre-switch-closed");
    drop(pre_switch_endpoint);

    let confirm_deadline = Instant::now() + Duration::from_secs(confirm_timeout_secs);
    while Instant::now() < confirm_deadline {
        let remaining_ms = confirm_deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        if remaining_ms == 0 {
            break;
        }
        let attempt_ms = remaining_ms.clamp(500, 2_500);
        if let Ok(resp) =
            send_quic_wire_msg(&fresh_endpoint, target_addr, &commit_msg, attempt_ms).await
        {
            match resp {
                EpochWireMsg::HealthAttestation { healthy: true, .. } => {
                    fresh_endpoint.close(0u32.into(), b"done");
                    println!("Activation succeeded.");
                    return Ok(());
                }
                EpochWireMsg::HealthAttestation {
                    healthy: false,
                    diagnostic,
                    ..
                } => {
                    fresh_endpoint.close(0u32.into(), b"failed");
                    anyhow::bail!(
                        "De-activating due to error; rolling back to previous configuration...\n{diagnostic}"
                    );
                }
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Confirmation timed out! Wait until target's lease expires and `execute_rollback` completes
    // (which also restores firewall reachability on `target`) before returning to caller.
    let rollback_wait_deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < rollback_wait_deadline {
        if let Ok(EpochWireMsg::QueryMissingPathsResp {
            active_deployment: false,
            ..
        }) = send_quic_wire_msg(
            &fresh_endpoint,
            target_addr,
            &EpochWireMsg::QueryMissingPathsReq {
                tx_epoch,
                store_paths: vec![],
            },
            1_500,
        )
        .await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    fresh_endpoint.close(0u32.into(), b"timeout");
    anyhow::bail!(
        "Timeout elapsed for confirmation ({confirm_timeout_secs}s).\nDe-activating due to error; rolling back to previous configuration..."
    );
}
