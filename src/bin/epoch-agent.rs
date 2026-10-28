//! `epoch-agent` — Target Host Daemon & Early-Boot Secret/Rollback Agent.

use clap::{Parser, Subcommand};
use epoch::cbor;
use epoch::crypto::{Ed25519Identity, parse_nix_public_key};
use epoch::p2p_quic::{
    bind_quic_endpoint_with_pinned_peers, read_quic_wire_msg, write_quic_wire_msg,
};
use epoch::plane3_secrets::{
    atomic_flip_current_secrets, prepare_empty_generation_secrets, unseal_boot_secrets,
};
use epoch::plane4_state::{
    AgentFilesystemLayout, EpochNodeAgent, clock_boottime_ns, clock_realtime_utc_s,
};
use epoch::schema::{Ed25519Pub, PersistentAgentState};
use epoch::watchdog_boot::pin_agent_memory_and_oom_score;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "epoch-agent",
    version,
    about = "EPOCH Target Host Transactional Activation, Ramfs Secret, & Watchdog Agent"
)]
struct Cli {
    #[arg(long, default_value = "/")]
    root: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print current persistent agent phase, highest_tx_epoch, and secret symlink status
    Status,
    /// Stage-2 early-boot coordinator-free secret unsealing from /run/booted-system
    UnsealBoot {
        #[arg(long, default_value = "/run/booted-system")]
        system_root: PathBuf,
        #[arg(long, default_value = "/run/epoch/secrets")]
        ramfs_root: PathBuf,
        #[arg(long, default_value = "/run/epoch/current-secrets")]
        current_secrets_link: PathBuf,
        #[arg(long, default_value = "local-node")]
        node_id: String,
        #[arg(
            long,
            default_value = "/nix/store/00000000000000000000000000000000-epoch-arch-base"
        )]
        archetype_toplevel: String,
        #[arg(long, default_value_t = 0)]
        boot_epoch: u64,
        #[arg(long)]
        host_key_seed_hex: Option<String>,
    },
    /// Override the statvfs free-space reserve in MiB for deterministic ENOSPC fault testing
    DebugSetQuotaReserveMib { mib: u64 },
    /// Pin process memory (`mlockall`, `OOMScoreAdjust=-1000`) and run the target QUIC mTLS agent
    Daemon {
        #[arg(long, default_value = "127.0.0.1:9443")]
        listen: String,
        #[arg(long, default_value = "local-node")]
        node_id: String,
        #[arg(
            long,
            default_value = "/nix/store/00000000000000000000000000000000-epoch-arch-base"
        )]
        archetype_toplevel: String,
        #[arg(long)]
        host_key_seed_hex: Option<String>,
        #[arg(long)]
        coordinator_pub_hex: Option<String>,
        #[arg(long)]
        store_pub_hex: Option<String>,
        #[arg(long, default_value = "cache.epoch.internal-1")]
        store_key_name: String,
        /// Trusted Nix Ed25519 public key (`<name>:<base64>`) for mTLS, plan signing, and store path verification
        #[arg(long = "trusted-public-key")]
        trusted_public_keys: Vec<String>,
        #[arg(long)]
        once: bool,
        #[arg(long)]
        max_requests: Option<usize>,
        #[arg(long, default_value_t = 60000)]
        request_timeout_ms: u64,
    },
}

fn parse_pub_hex(h: &str) -> anyhow::Result<Ed25519Pub> {
    let raw = hex::decode(h.trim())?;
    anyhow::ensure!(
        raw.len() == 32,
        "expected 32-byte Ed25519 public key (64 hex chars), got {} bytes",
        raw.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let layout = AgentFilesystemLayout::under_root(&cli.root);

    match cli.command {
        Commands::Status => {
            if layout.state_cbor_path.exists() {
                let bytes = fs::read(&layout.state_cbor_path)?;
                let st: PersistentAgentState = cbor::from_slice(&bytes)?;
                println!(
                    "phase={} highest_tx_epoch={} prev_toplevel={} prev_secret_epoch={}",
                    st.phase.as_str(),
                    st.highest_tx_epoch,
                    st.prev_toplevel,
                    st.prev_secret_epoch
                );
            } else {
                println!("phase=IDLE highest_tx_epoch=0");
            }
        }
        Commands::UnsealBoot {
            system_root,
            ramfs_root,
            current_secrets_link,
            node_id,
            archetype_toplevel,
            boot_epoch,
            host_key_seed_hex,
        } => {
            let envelope_path = system_root.join("node-overlay").join("epoch-secrets.cbor");
            let gen_dir = if envelope_path.exists() {
                let host_id = Ed25519Identity::from_seed_hex_or_default(
                    host_key_seed_hex.as_deref(),
                    [0x42; 32],
                )?;
                unseal_boot_secrets(
                    &system_root,
                    &ramfs_root,
                    &current_secrets_link,
                    boot_epoch,
                    &node_id,
                    &archetype_toplevel,
                    &host_id,
                    None,
                )?
            } else {
                let dir = prepare_empty_generation_secrets(&ramfs_root, boot_epoch)?;
                atomic_flip_current_secrets(&current_secrets_link, &ramfs_root, boot_epoch)?;
                dir
            };
            println!("Unsealed early-boot secrets into {}", gen_dir.display());
        }
        Commands::DebugSetQuotaReserveMib { mib } => {
            layout.ensure_directories()?;
            let reserve_file = layout.root_dir.join("var/lib/epoch/quota-reserve-mib");
            fs::write(&reserve_file, format!("{mib}\n"))?;
            println!("Set statvfs quota reserve override to {mib} MiB");
        }
        Commands::Daemon {
            listen,
            node_id,
            archetype_toplevel,
            host_key_seed_hex,
            coordinator_pub_hex,
            store_pub_hex,
            store_key_name,
            trusted_public_keys,
            once,
            max_requests,
            request_timeout_ms,
        } => {
            let (mlocked, oom_set) = pin_agent_memory_and_oom_score();
            let host_id = Ed25519Identity::from_seed_hex_or_default(
                host_key_seed_hex.as_deref(),
                [0x42; 32],
            )?;
            let agent_key = Ed25519Identity::from_seed_hex_or_default(
                host_key_seed_hex.as_deref(),
                [0x42; 32],
            )?;
            let mut coord_pubs = Vec::new();
            let mut store_keys = Vec::new();
            for raw_tk in &trusted_public_keys {
                for token in raw_tk.split_whitespace() {
                    let (k_name, k_pub) = parse_nix_public_key(token)?;
                    if !coord_pubs.contains(&k_pub) {
                        coord_pubs.push(k_pub);
                    }
                    store_keys.push((k_name, k_pub));
                }
            }
            if let Some(ref h) = coordinator_pub_hex {
                let pk = parse_pub_hex(h)?;
                if !coord_pubs.contains(&pk) {
                    coord_pubs.push(pk);
                }
            }
            if let Some(ref h) = store_pub_hex {
                let pk = parse_pub_hex(h)?;
                store_keys.push((store_key_name.clone(), pk));
            }
            let pinned_peers = if !coord_pubs.is_empty() {
                Some(coord_pubs.clone())
            } else {
                None
            };
            if coord_pubs.is_empty() {
                coord_pubs.push(Ed25519Identity::from_seed([0x11; 32])?.public_key);
            }
            if store_keys.is_empty() {
                store_keys.push((
                    store_key_name,
                    Ed25519Identity::from_seed([0x22; 32])?.public_key,
                ));
            }
            let mut agent = EpochNodeAgent::open_or_init_daemon(
                &node_id, agent_key, coord_pubs, store_keys, layout,
            )?;
            let listen_addr: SocketAddr = listen.parse()?;
            let target_reqs = if once { Some(1) } else { max_requests };
            let req_timeout = std::time::Duration::from_millis(request_timeout_ms.max(50));

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                let (endpoint, bound_addr) =
                    bind_quic_endpoint_with_pinned_peers(listen_addr, &host_id, pinned_peers)?;
                println!(
                    "epoch-agent listening on {} (mlockall={}, oom_score_adj={})",
                    bound_addr, mlocked, oom_set
                );
                let _ = std::io::stdout().flush();

                if target_reqs == Some(0) {
                    return Ok::<(), anyhow::Error>(());
                }

                let mut served = 0usize;
                let mut lease_ticker =
                    tokio::time::interval(std::time::Duration::from_millis(25));
                lease_ticker
                    .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    tokio::select! {
                        _ = lease_ticker.tick() => {
                            let _ = agent.check_lease_expiration(clock_boottime_ns());
                        }
                        incoming_opt = endpoint.accept() => {
                            let Some(incoming) = incoming_opt else {
                                break;
                            };
                            if let Ok(Ok(conn)) = tokio::time::timeout(req_timeout, incoming).await
                                && let Ok(Ok((mut send, mut recv))) =
                                    tokio::time::timeout(req_timeout, conn.accept_bi()).await
                                && let Ok(Ok(req)) =
                                    tokio::time::timeout(req_timeout, read_quic_wire_msg(&mut recv)).await
                            {
                                if let Ok(resp) = agent.handle_wire_message(
                                    req,
                                    &archetype_toplevel,
                                    clock_boottime_ns(),
                                    clock_realtime_utc_s(),
                                ) {
                                    let _ = tokio::time::timeout(
                                        req_timeout,
                                        write_quic_wire_msg(&mut send, &resp),
                                    )
                                    .await;
                                    let _ = send.finish();
                                    let _ = tokio::time::timeout(
                                        std::time::Duration::from_millis(200),
                                        conn.closed(),
                                    )
                                    .await;
                                }
                                served += 1;
                                if let Some(limit) = target_reqs
                                    && served >= limit
                                {
                                    break;
                                }
                            }
                        }
                    }
                }
                Ok(())
            })?;
        }
    }

    Ok(())
}
