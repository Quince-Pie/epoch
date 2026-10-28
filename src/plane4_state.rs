//! Plane 4: Distributed Transactional Activation, Consensus Leases, & Rollback Plane
//!
//! Implements:
//! 1. Monotonic `tx_epoch` fencing and crash-safe `/var/lib/epoch/state.cbor` persistence with keyed BLAKE3 MAC.
//! 2. Monotonic `CLOCK_BOOTTIME` lease timers immune to NTP wall-clock jumps.
//! 3. Two-phase speculative activation (`IDLE -> STAGED -> PREPARED -> ACTIVATING -> PROBING -> BARRIER_WAIT -> COMMITTED / ROLLED_BACK`).
//! 4. Peer Witness Lease Relay (`PeerWitnessRelay`) wrapping/verification for asymmetric partition survival.
//! 5. Layer-3 post-reboot `state.cbor` reconciliation after hardware watchdog + `systemd-boot` `+1-0.conf` recovery.

use crate::cbor;
use crate::crypto::{
    Ed25519Identity, compute_state_mac, sign_health_attestation, sign_peer_witness_relay,
    verify_abort_wave, verify_activate_wave, verify_commit_wave, verify_execution_plan,
    verify_health_attestation, verify_lease_keepalive, verify_peer_witness_relay,
};
use crate::oracles::{ProbeEnvironment, evaluate_health_oracles};
use crate::plane2_store::{
    TargetChunkIndex, check_store_quota, create_staging_gcroot, flush_sqlite_conn_cache,
    ingest_fetched_chunks, query_missing_store_paths, reconstruct_and_register_store_path,
    remove_staging_gcroot, set_nix_store_writable,
};
use crate::plane3_secrets::{
    atomic_flip_current_secrets, prepare_empty_generation_secrets, prepare_generation_secrets,
    unseal_boot_secrets, zero_wipe_secret_generation,
};
use crate::schema::{
    AgentPhase, Blake3Hash, Ed25519Pub, Ed25519Sig, EpochError, EpochWireMsg, NarChunkManifest,
    PersistentAgentState, SignedExecutionPlan,
};
use crate::watchdog_boot::{
    HardwareWatchdog, arm_systemd_boot_single_trial, cleanup_failed_systemd_boot_trials,
    init_systemd_boot_layout, pin_agent_memory_and_oom_score,
    promote_or_write_systemd_boot_permanent,
};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Read the Linux kernel's monotonic `CLOCK_BOOTTIME` in nanoseconds (ticks across suspend).
pub fn clock_boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if rc == 0 {
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    } else {
        0
    }
}

/// Read current UTC wall-clock time in seconds.
pub fn clock_realtime_utc_s() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc == 0 && ts.tv_sec >= 0 {
        ts.tv_sec as u64
    } else {
        0
    }
}

/// Complete filesystem layout for a target node (`/` in production or an isolated root in tests/VMs).
#[derive(Debug, Clone)]
pub struct AgentFilesystemLayout {
    pub root_dir: PathBuf,
    pub store_dir: PathBuf,
    pub sqlite_db_path: PathBuf,
    pub gcroots_staging_dir: PathBuf,
    pub profiles_dir: PathBuf,
    pub system_profile_link: PathBuf,
    pub run_current_system_link: PathBuf,
    pub run_booted_system_link: PathBuf,
    pub ramfs_secrets_root: PathBuf,
    pub current_secrets_link: PathBuf,
    pub state_cbor_path: PathBuf,
    pub chunk_index_path: PathBuf,
    pub boot_root: PathBuf,
    pub efivars_dir: PathBuf,
    pub watchdog_path: PathBuf,
}

impl AgentFilesystemLayout {
    pub fn under_root(root: &Path) -> Self {
        Self {
            root_dir: root.to_path_buf(),
            store_dir: root.join("nix/store"),
            sqlite_db_path: root.join("nix/var/nix/db/db.sqlite"),
            gcroots_staging_dir: root.join("nix/var/nix/gcroots/epoch/staging"),
            profiles_dir: root.join("nix/var/nix/profiles"),
            system_profile_link: root.join("nix/var/nix/profiles/system"),
            run_current_system_link: root.join("run/current-system"),
            run_booted_system_link: root.join("run/booted-system"),
            ramfs_secrets_root: root.join("run/epoch/secrets"),
            current_secrets_link: root.join("run/epoch/current-secrets"),
            state_cbor_path: root.join("var/lib/epoch/state.cbor"),
            chunk_index_path: root.join("var/cache/epoch/chunk-index.bin"),
            boot_root: root.join("boot"),
            efivars_dir: root.join("sys/firmware/efi/efivars"),
            watchdog_path: root.join("dev/watchdog"),
        }
    }

    pub fn ensure_directories(&self) -> Result<(), EpochError> {
        for dir in [
            &self.store_dir,
            &self.gcroots_staging_dir,
            &self.profiles_dir,
            &self.ramfs_secrets_root,
            &self.boot_root,
        ] {
            if !dir.exists() {
                fs::create_dir_all(dir)?;
            }
        }
        let _ = fs::create_dir_all(&self.efivars_dir);
        if let Some(p) = self.sqlite_db_path.parent() {
            fs::create_dir_all(p)?;
        }
        if let Some(p) = self.state_cbor_path.parent() {
            fs::create_dir_all(p)?;
        }
        if let Some(p) = self.chunk_index_path.parent() {
            fs::create_dir_all(p)?;
        }
        if let Some(p) = self.run_current_system_link.parent() {
            fs::create_dir_all(p)?;
        }
        if let Some(p) = self.watchdog_path.parent() {
            fs::create_dir_all(p)?;
        }
        Ok(())
    }
}

/// Atomically persist `PersistentAgentState` to `/var/lib/epoch/state.cbor` with `fdatasync` + directory `fsync`.
pub fn save_persistent_state(
    path: &Path,
    state: &mut PersistentAgentState,
    mac_key: &[u8; 32],
) -> Result<(), EpochError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    state.state_blake3_mac = compute_state_mac(state, mac_key)?;
    let bytes = cbor::to_vec_deterministic(state)?;
    let tmp_path = path.with_extension("cbor.tmp");
    {
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
        f.write_all(&bytes)?;
        f.sync_data()?;
    }
    fs::rename(&tmp_path, path)?;
    let gen_prev_path = path.with_file_name("gen-prev");
    let expected_prev = format!("{}\n", state.prev_toplevel);
    if fs::read_to_string(&gen_prev_path).ok().as_deref() != Some(expected_prev.as_str()) {
        let _ = fs::write(&gen_prev_path, expected_prev);
    }
    if let Some(parent) = path.parent()
        && let Ok(dir_f) = File::open(parent)
    {
        let _ = dir_f.sync_all();
    }
    Ok(())
}

/// Load and verify `PersistentAgentState` from `/var/lib/epoch/state.cbor`.
pub fn load_persistent_state(
    path: &Path,
    mac_key: &[u8; 32],
) -> Result<PersistentAgentState, EpochError> {
    let bytes = fs::read(path)?;
    let state: PersistentAgentState = cbor::from_slice(&bytes)?;
    crate::crypto::verify_state_mac(&state, mac_key)?;
    Ok(state)
}

/// Target `epoch-agent` state machine instance.
pub struct EpochNodeAgent {
    pub node_id: String,
    pub node_key: Ed25519Identity,
    pub state_mac_key: [u8; 32],
    pub trusted_coordinator_pubs: Vec<Ed25519Pub>,
    pub trusted_store_keys: Vec<(String, Ed25519Pub)>,
    pub layout: AgentFilesystemLayout,
    pub state: PersistentAgentState,
    pub chunk_index: TargetChunkIndex,
    pub active_plan: Option<SignedExecutionPlan>,
    pub staged_kernel_path: Option<String>,
    pub staged_initrd_path: Option<String>,
    pub active_kernel_path: String,
    pub active_initrd_path: String,
    pub watchdog: Option<HardwareWatchdog>,
    pub quota_reserve_override_bytes: Option<u64>,
    pub last_activation_log: String,
    pub active_lease_ns: u64,
}

impl EpochNodeAgent {
    /// Initialize a target node agent with a known-good initial generation $G_{\text{init}}$.
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        node_id: &str,
        node_key: Ed25519Identity,
        trusted_coordinator_pubs: Vec<Ed25519Pub>,
        trusted_store_keys: Vec<(String, Ed25519Pub)>,
        layout: AgentFilesystemLayout,
        init_epoch: u64,
        init_toplevel: &Path,
        init_archetype_toplevel: &str,
        init_kernel_path: &str,
        init_initrd_path: &str,
        tpm2_pcr_state: Option<(u32, &[u8; 32])>,
    ) -> Result<Self, EpochError> {
        layout.ensure_directories()?;
        let mut mac_hasher = blake3::Hasher::new();
        mac_hasher.update(b"epoch-state-mac-key-v1");
        mac_hasher.update(node_key.seed());
        let state_mac_key = *mac_hasher.finalize().as_bytes();

        // Set up initial generation profile and symlinks
        let gen_link = layout
            .profiles_dir
            .join(format!("system-{init_epoch}-link"));
        replace_symlink(&gen_link, init_toplevel)?;
        replace_symlink(&layout.system_profile_link, &gen_link)?;
        replace_symlink(&layout.run_current_system_link, init_toplevel)?;
        replace_symlink(&layout.run_booted_system_link, init_toplevel)?;

        // Initialize systemd-boot layout for known-good generation
        init_systemd_boot_layout(
            &layout.boot_root,
            init_epoch,
            &init_toplevel.to_string_lossy(),
            init_kernel_path,
            init_initrd_path,
        )?;

        // Unseal initial generation secrets onto ramfs
        unseal_boot_secrets(
            init_toplevel,
            &layout.ramfs_secrets_root,
            &layout.current_secrets_link,
            init_epoch,
            node_id,
            init_archetype_toplevel,
            &node_key,
            tpm2_pcr_state,
        )?;

        let mut state = PersistentAgentState {
            highest_tx_epoch: init_epoch,
            phase: AgentPhase::Idle,
            active_wave_id: None,
            prev_toplevel: init_toplevel.to_string_lossy().into_owned(),
            prev_secret_epoch: init_epoch,
            staged_toplevel: None,
            lease_deadline_boottime_ns: 0,
            reboot_deadline_wall_utc_s: 0,
            state_blake3_mac: [0u8; 32],
        };
        save_persistent_state(&layout.state_cbor_path, &mut state, &state_mac_key)?;

        let chunk_index = TargetChunkIndex::load(&layout.chunk_index_path).unwrap_or_default();

        Ok(Self {
            node_id: node_id.to_owned(),
            node_key,
            state_mac_key,
            trusted_coordinator_pubs,
            trusted_store_keys,
            layout,
            state,
            chunk_index,
            active_plan: None,
            staged_kernel_path: None,
            staged_initrd_path: None,
            active_kernel_path: init_kernel_path.to_owned(),
            active_initrd_path: init_initrd_path.to_owned(),
            watchdog: None,
            quota_reserve_override_bytes: None,
            last_activation_log: String::new(),
            active_lease_ns: 30_000_000_000,
        })
    }

    /// Open an existing `EpochNodeAgent` from `layout` if `/var/lib/epoch/state.cbor` exists,
    /// or initialize a fresh daemon state under `layout`.
    pub fn open_or_init_daemon(
        node_id: &str,
        node_key: Ed25519Identity,
        trusted_coordinator_pubs: Vec<Ed25519Pub>,
        trusted_store_keys: Vec<(String, Ed25519Pub)>,
        layout: AgentFilesystemLayout,
    ) -> Result<Self, EpochError> {
        layout.ensure_directories()?;
        let mut mac_hasher = blake3::Hasher::new();
        mac_hasher.update(b"epoch-state-mac-key-v1");
        mac_hasher.update(node_key.seed());
        let state_mac_key = *mac_hasher.finalize().as_bytes();

        let state = if layout.state_cbor_path.exists() {
            load_persistent_state(&layout.state_cbor_path, &state_mac_key)?
        } else {
            let prev_tl = fs::read_link(&layout.run_current_system_link)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| {
                    "/nix/store/00000000000000000000000000000000-epoch-init".into()
                });
            let mut st = PersistentAgentState {
                highest_tx_epoch: 0,
                phase: AgentPhase::Idle,
                active_wave_id: None,
                prev_toplevel: prev_tl,
                prev_secret_epoch: 0,
                staged_toplevel: None,
                lease_deadline_boottime_ns: 0,
                reboot_deadline_wall_utc_s: 0,
                state_blake3_mac: [0u8; 32],
            };
            save_persistent_state(&layout.state_cbor_path, &mut st, &state_mac_key)?;
            st
        };

        if !layout
            .ramfs_secrets_root
            .join(format!("gen-{}", state.prev_secret_epoch))
            .exists()
        {
            let _ = prepare_empty_generation_secrets(
                &layout.ramfs_secrets_root,
                state.prev_secret_epoch,
            );
            let _ = atomic_flip_current_secrets(
                &layout.current_secrets_link,
                &layout.ramfs_secrets_root,
                state.prev_secret_epoch,
            );
        }

        let mut active_kernel_path = "/nix/store/kernel/bzImage".to_owned();
        let mut active_initrd_path = "/nix/store/initrd/initrd".to_owned();
        let loader_conf_path = layout.boot_root.join("loader/loader.conf");
        if let Ok(loader_conf) = fs::read_to_string(&loader_conf_path) {
            if let Some(default_entry) = loader_conf
                .lines()
                .find_map(|l| l.strip_prefix("default ").map(|s| s.trim().to_owned()))
                && let Ok(entry_content) =
                    fs::read_to_string(layout.boot_root.join("loader/entries").join(default_entry))
            {
                for line in entry_content.lines() {
                    if let Some(k) = line.strip_prefix("linux ") {
                        active_kernel_path = k.trim().to_owned();
                    } else if let Some(i) = line.strip_prefix("initrd ") {
                        active_initrd_path = i.trim().to_owned();
                    }
                }
            }
        } else {
            let _ = init_systemd_boot_layout(
                &layout.boot_root,
                state.prev_secret_epoch,
                &state.prev_toplevel,
                &active_kernel_path,
                &active_initrd_path,
            );
        }

        let mut active_plan = None;
        let mut staged_kernel_path = None;
        let mut staged_initrd_path = None;
        let active_plan_path = layout.state_cbor_path.with_file_name("active-plan.cbor");
        if let Ok(plan_bytes) = fs::read(&active_plan_path)
            && let Ok(plan) = cbor::from_slice::<SignedExecutionPlan>(&plan_bytes)
            && verify_execution_plan(&plan, &trusted_coordinator_pubs).is_ok()
            && plan.tx_epoch == state.highest_tx_epoch
        {
            if let Some(np) = plan.nodes.iter().find(|n| n.node_id == node_id) {
                staged_kernel_path = Some(np.kernel_path.clone());
                staged_initrd_path = Some(np.initrd_path.clone());
            }
            active_plan = Some(plan);
        }

        let chunk_index = TargetChunkIndex::load(&layout.chunk_index_path).unwrap_or_default();

        Ok(Self {
            node_id: node_id.to_owned(),
            node_key,
            state_mac_key,
            trusted_coordinator_pubs,
            trusted_store_keys,
            layout,
            state,
            chunk_index,
            active_plan,
            staged_kernel_path,
            staged_initrd_path,
            active_kernel_path,
            active_initrd_path,
            watchdog: None,
            quota_reserve_override_bytes: None,
            last_activation_log: String::new(),
            active_lease_ns: 30_000_000_000,
        })
    }

    /// Strictly enforce monotonic `tx_epoch` fencing (`DESIGN.md` §5.4.1).
    pub fn check_epoch_fencing(
        &self,
        msg_epoch: u64,
        allow_equal_active: bool,
    ) -> Result<(), EpochError> {
        if msg_epoch < self.state.highest_tx_epoch {
            return Err(EpochError::StaleEpochFenced {
                msg_epoch,
                highest_epoch: self.state.highest_tx_epoch,
            });
        }
        if !allow_equal_active && msg_epoch == self.state.highest_tx_epoch {
            return Err(EpochError::StaleEpochFenced {
                msg_epoch,
                highest_epoch: self.state.highest_tx_epoch,
            });
        }
        if msg_epoch == self.state.highest_tx_epoch
            && matches!(
                self.state.phase,
                AgentPhase::RolledBack | AgentPhase::Committed
            )
        {
            return Err(EpochError::StaleEpochFenced {
                msg_epoch,
                highest_epoch: self.state.highest_tx_epoch,
            });
        }
        Ok(())
    }

    /// Step 1 (`IDLE | COMMITTED | ROLLED_BACK -> STAGED`):
    /// Verify `plan.cbor`, enforce `tx_epoch` fencing, verify `statvfs` quota, ingest/verify chunks,
    /// unpack NARs, register in SQLite `db.sqlite`, and create isolated staging GC root.
    pub fn handle_stage_manifest(
        &mut self,
        tx_epoch: u64,
        plan: SignedExecutionPlan,
        manifests: &[NarChunkManifest],
        fetched_chunks: &[(Blake3Hash, Vec<u8>)],
        inactivity_ttl_ns: u64,
        now_boottime_ns: u64,
    ) -> Result<PathBuf, EpochError> {
        let _zone = crate::tracy_zone!("plane4::handle_stage_manifest", 0xec4899);
        verify_execution_plan(&plan, &self.trusted_coordinator_pubs)?;
        if plan.tx_epoch != tx_epoch {
            return Err(EpochError::CryptoVerificationFailed(
                "StageManifest tx_epoch != SignedExecutionPlan.tx_epoch".into(),
            ));
        }
        // A new StageManifest must strictly advance highest_tx_epoch
        self.check_epoch_fencing(tx_epoch, false)?;

        if self.layout.root_dir == Path::new("/") {
            if matches!(
                self.state.phase,
                AgentPhase::Activating | AgentPhase::Probing | AgentPhase::BarrierWait
            ) && now_boottime_ns < self.state.lease_deadline_boottime_ns
            {
                return Err(EpochError::Io(
                    "Another epoch activation is already running on this host.".into(),
                ));
            }
            if let Ok(st) = Command::new("/run/current-system/sw/bin/systemctl")
                .args([
                    "is-active",
                    "--quiet",
                    "epoch-activate.service",
                    "saturn-deploy.service",
                    "nixos-rebuild-switch-to-configuration.service",
                ])
                .status()
                && st.success()
            {
                return Err(EpochError::Io(
                    "Another epoch activation is already running on this host.".into(),
                ));
            }
        }

        let node_plan = plan
            .nodes
            .iter()
            .find(|n| n.node_id == self.node_id)
            .ok_or_else(|| {
                EpochError::PlanValidation(format!(
                    "node '{}' not present in SignedExecutionPlan",
                    self.node_id
                ))
            })?;

        // Check `statvfs` free space & inode quotas before writing a single byte
        let missing_refs: Vec<&NarChunkManifest> = manifests.iter().collect();
        let file_reserve_override = self.layout.root_dir.join("var/lib/epoch/quota-reserve-mib");
        let effective_reserve = self.quota_reserve_override_bytes.or_else(|| {
            fs::read_to_string(&file_reserve_override)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|mib| mib.saturating_mul(1024 * 1024))
        });
        check_store_quota(&self.layout.store_dir, &missing_refs, effective_reserve)?;

        // Ingest and BLAKE3-verify fetched chunks
        ingest_fetched_chunks(&mut self.chunk_index, manifests, fetched_chunks)?;
        if !fetched_chunks.is_empty() || !self.layout.chunk_index_path.exists() {
            self.chunk_index
                .save_atomic(&self.layout.chunk_index_path)?;
        }

        // Reconstruct and register every store path in the closure
        let mut staged_toplevel_disk: Option<PathBuf> = None;
        for m in manifests {
            let unpacked = match reconstruct_and_register_store_path(
                &self.layout.store_dir,
                &self.layout.sqlite_db_path,
                m,
                &self.chunk_index,
                &self.trusted_store_keys,
            ) {
                Ok(u) => u,
                Err(e) => {
                    set_nix_store_writable(&self.layout.store_dir, false);
                    return Err(e);
                }
            };
            if m.store_path == node_plan.toplevel_path
                || unpacked.file_name() == Path::new(&node_plan.toplevel_path).file_name()
            {
                staged_toplevel_disk = Some(unpacked);
            }
        }
        if !manifests.is_empty() {
            flush_sqlite_conn_cache(&self.layout.sqlite_db_path);
            set_nix_store_writable(&self.layout.store_dir, false);
        }

        if matches!(
            self.state.phase,
            AgentPhase::Idle | AgentPhase::Committed | AgentPhase::RolledBack
        ) && let Ok(curr_link) = fs::read_link(&self.layout.run_current_system_link)
        {
            let resolved = fs::canonicalize(&curr_link).unwrap_or(curr_link);
            self.state.prev_toplevel = resolved.to_string_lossy().into_owned();
        }

        let staged_path = staged_toplevel_disk.unwrap_or_else(|| {
            let basename = Path::new(&node_plan.toplevel_path)
                .file_name()
                .unwrap_or_default();
            self.layout.store_dir.join(basename)
        });
        let staged_kernel_path = node_plan.kernel_path.clone();
        let staged_initrd_path = node_plan.initrd_path.clone();

        // Create isolated staging GC root without touching /nix/var/nix/profiles/system or /run/current-system
        let gcroot =
            create_staging_gcroot(&self.layout.gcroots_staging_dir, tx_epoch, &staged_path)?;

        self.state.highest_tx_epoch = tx_epoch;
        self.state.phase = AgentPhase::Staged;
        self.state.staged_toplevel = Some(staged_path.to_string_lossy().into_owned());
        self.state.lease_deadline_boottime_ns = now_boottime_ns.saturating_add(inactivity_ttl_ns);
        save_persistent_state(
            &self.layout.state_cbor_path,
            &mut self.state,
            &self.state_mac_key,
        )?;

        self.staged_kernel_path = Some(staged_kernel_path);
        self.staged_initrd_path = Some(staged_initrd_path);
        if let Ok(plan_bytes) = cbor::to_vec_deterministic(&plan) {
            let active_plan_path = self
                .layout
                .state_cbor_path
                .with_file_name("active-plan.cbor");
            let _ = fs::write(active_plan_path, plan_bytes);
        }
        self.active_plan = Some(plan);
        self.last_activation_log.clear();

        Ok(gcroot)
    }

    /// Verify that `wave_id` matches the node's assigned wave in `active_plan` and `self.state.active_wave_id`.
    fn check_wave_binding(
        &self,
        wave_id: &str,
        require_active_match: bool,
    ) -> Result<(), EpochError> {
        if let Some(ref plan) = self.active_plan {
            let wave_contains_node = plan
                .waves
                .iter()
                .find(|w| w.wave_id == wave_id)
                .map(|w| w.node_ids.iter().any(|n| n == &self.node_id))
                .unwrap_or(false);
            if !wave_contains_node {
                return Err(EpochError::PlanValidation(format!(
                    "CrossWaveReplayRejected: node '{}' is not a member of wave '{}' in SignedExecutionPlan",
                    self.node_id, wave_id
                )));
            }
        }
        if require_active_match && self.state.active_wave_id.as_deref() != Some(wave_id) {
            return Err(EpochError::PlanValidation(format!(
                "CrossWaveReplayRejected: active_wave_id {:?} != message wave_id '{}'",
                self.state.active_wave_id, wave_id
            )));
        }
        Ok(())
    }

    /// Step 2 (`STAGED -> PREPARED`):
    /// Unseal `$staged_toplevel/node-overlay/epoch-secrets.cbor` into `/run/epoch/secrets/gen-<tx_epoch>`
    /// on unswappable `ramfs` without flipping `/run/epoch/current-secrets`.
    pub fn handle_prepare_wave(
        &mut self,
        tx_epoch: u64,
        wave_id: &str,
        expected_archetype_toplevel: &str,
        tpm2_pcr_state: Option<(u32, &[u8; 32])>,
        prepare_ttl_ns: u64,
        now_boottime_ns: u64,
    ) -> Result<PathBuf, EpochError> {
        self.check_epoch_fencing(tx_epoch, true)?;
        if self.state.phase != AgentPhase::Staged {
            return Err(EpochError::InvalidTransition {
                from: self.state.phase,
                event: "PrepareWave",
            });
        }
        self.check_wave_binding(wave_id, false)?;

        let staged_tl = self
            .state
            .staged_toplevel
            .clone()
            .ok_or_else(|| EpochError::Io("missing staged_toplevel in Staged phase".into()))?;

        let envelope_path = Path::new(&staged_tl)
            .join("node-overlay")
            .join("epoch-secrets.cbor");
        let allow_empty_secrets = self
            .active_plan
            .as_ref()
            .and_then(|p| p.nodes.iter().find(|n| n.node_id == self.node_id))
            .map(|n| n.secrets_envelope_hash == [0u8; 32])
            .unwrap_or(false);

        let gen_dir = if !envelope_path.exists() && allow_empty_secrets {
            prepare_empty_generation_secrets(&self.layout.ramfs_secrets_root, tx_epoch)?
        } else {
            prepare_generation_secrets(
                Path::new(&staged_tl),
                &self.layout.ramfs_secrets_root,
                tx_epoch,
                &self.node_id,
                expected_archetype_toplevel,
                &self.node_key,
                tpm2_pcr_state,
            )?
        };

        self.state.phase = AgentPhase::Prepared;
        self.state.active_wave_id = Some(wave_id.to_owned());
        self.state.lease_deadline_boottime_ns = now_boottime_ns.saturating_add(prepare_ttl_ns);
        save_persistent_state(
            &self.layout.state_cbor_path,
            &mut self.state,
            &self.state_mac_key,
        )?;

        Ok(gen_dir)
    }

    fn seed_initial_system_profile_if_missing(
        &self,
        prev_toplevel: &Path,
        staged_toplevel: &Path,
    ) -> Result<(), EpochError> {
        if self.layout.root_dir != Path::new("/") {
            return Ok(());
        }
        if fs::symlink_metadata(&self.layout.system_profile_link).is_ok() {
            return Ok(());
        }
        if !prev_toplevel.exists() {
            return Ok(());
        }
        let prev_canon =
            fs::canonicalize(prev_toplevel).unwrap_or_else(|_| prev_toplevel.to_path_buf());
        let staged_canon =
            fs::canonicalize(staged_toplevel).unwrap_or_else(|_| staged_toplevel.to_path_buf());
        if prev_canon != staged_canon && highest_system_profile_gen(&self.layout.profiles_dir) == 0
        {
            let gen1_link = self.layout.profiles_dir.join("system-1-link");
            replace_symlink(&gen1_link, &prev_canon)?;
            atomic_replace_or_exchange_symlink(
                &self.layout.system_profile_link,
                Path::new("system-1-link"),
            )?;
        }
        Ok(())
    }

    fn advance_live_system_profile(&self, target_toplevel: &Path) -> Result<(), EpochError> {
        let target_canon =
            fs::canonicalize(target_toplevel).unwrap_or_else(|_| target_toplevel.to_path_buf());
        if let Ok(curr_canon) = fs::canonicalize(&self.layout.system_profile_link)
            && curr_canon == target_canon
        {
            return Ok(());
        }
        let next_gen = highest_system_profile_gen(&self.layout.profiles_dir).saturating_add(1);
        let link_name = format!("system-{next_gen}-link");
        let new_gen_link = self.layout.profiles_dir.join(&link_name);
        replace_symlink(&new_gen_link, &target_canon)?;
        atomic_replace_or_exchange_symlink(
            &self.layout.system_profile_link,
            Path::new(&link_name),
        )?;
        Ok(())
    }

    /// Step 3 (`PREPARED -> ACTIVATING -> PROBING`):
    /// Verify `coord_sig`, arm `/dev/watchdog` and `CLOCK_BOOTTIME` lease, stage `+1-0.conf` boot entry
    /// if kernel/initrd changed, atomically exchange `/run/epoch/current-secrets` via `RENAME_EXCHANGE`,
    /// and execute `$staged_toplevel/bin/switch-to-configuration`.
    pub fn handle_activate_wave(
        &mut self,
        tx_epoch: u64,
        wave_id: &str,
        lease_ttl_ms: u32,
        coord_sig: &Ed25519Sig,
        now_boottime_ns: u64,
        now_wall_utc_s: u64,
    ) -> Result<bool, EpochError> {
        let _zone = crate::tracy_zone!("plane4::handle_activate_wave", 0xdb2777);
        self.check_epoch_fencing(tx_epoch, true)?;
        if self.state.phase != AgentPhase::Prepared {
            return Err(EpochError::InvalidTransition {
                from: self.state.phase,
                event: "ActivateWave",
            });
        }
        self.check_wave_binding(wave_id, true)?;

        let plan = self
            .active_plan
            .as_ref()
            .ok_or_else(|| EpochError::Io("no active plan loaded".into()))?;
        verify_activate_wave(
            &plan.coordinator_pub,
            tx_epoch,
            wave_id,
            lease_ttl_ms,
            coord_sig,
        )?;

        let staged_tl = self
            .state
            .staged_toplevel
            .clone()
            .ok_or_else(|| EpochError::Io("missing staged_toplevel".into()))?;

        // Layer 1: Pin memory (`mlockall`), set `oom_score_adj = -1000`, and arm `/dev/watchdog` (`60s`)
        let _ = pin_agent_memory_and_oom_score();
        self.watchdog = Some(HardwareWatchdog::arm(&self.layout.watchdog_path, 60));

        // Arm monotonic `CLOCK_BOOTTIME` lease deadline and persist `Activating` BEFORE mutating live state
        let lease_ns = (lease_ttl_ms as u64).saturating_mul(1_000_000);
        self.active_lease_ns = lease_ns;
        self.last_activation_log.clear();
        self.state.phase = AgentPhase::Activating;
        self.state.active_wave_id = Some(wave_id.to_owned());
        self.state.lease_deadline_boottime_ns = now_boottime_ns.saturating_add(lease_ns);
        self.state.reboot_deadline_wall_utc_s = now_wall_utc_s.saturating_add(120);
        save_persistent_state(
            &self.layout.state_cbor_path,
            &mut self.state,
            &self.state_mac_key,
        )?;

        // Check if kernel or initrd changed (requires Layer 2 systemd-boot +1-0.conf trial reboot)
        let new_kernel = self
            .staged_kernel_path
            .clone()
            .unwrap_or_else(|| self.active_kernel_path.clone());
        let new_initrd = self
            .staged_initrd_path
            .clone()
            .unwrap_or_else(|| self.active_initrd_path.clone());
        let requires_reboot =
            new_kernel != self.active_kernel_path || new_initrd != self.active_initrd_path;

        if requires_reboot && self.layout.root_dir != Path::new("/") {
            arm_systemd_boot_single_trial(
                &self.layout.boot_root,
                &self.layout.efivars_dir,
                tx_epoch,
                &staged_tl,
                &new_kernel,
                &new_initrd,
            )?;
        }

        // Plane 3 Phase 2: Zero-window atomic symlink exchange on `/run/epoch/current-secrets`
        if let Err(e) = atomic_flip_current_secrets(
            &self.layout.current_secrets_link,
            &self.layout.ramfs_secrets_root,
            tx_epoch,
        ) {
            self.execute_rollback(tx_epoch, "SecretFlipFailed")?;
            return Err(e);
        }

        let stage_gcroot = self
            .layout
            .gcroots_staging_dir
            .join(format!("tx-{tx_epoch}"));
        let prev_tl_path = Path::new(&self.state.prev_toplevel).to_path_buf();
        let staged_tl_path = Path::new(&staged_tl);

        let switch_action = match wave_id {
            "dry-activate" => "dry-activate",
            "boot" => {
                self.seed_initial_system_profile_if_missing(&prev_tl_path, staged_tl_path)?;
                if self.layout.root_dir == Path::new("/") {
                    self.advance_live_system_profile(staged_tl_path)?;
                }
                "boot"
            }
            "switch" => {
                self.seed_initial_system_profile_if_missing(&prev_tl_path, staged_tl_path)?;
                "test"
            }
            _ => "test",
        };

        let switch_bin = staged_tl_path.join("bin").join("switch-to-configuration");
        if switch_bin.exists() {
            let (ok, out_log) =
                run_switch_to_configuration(staged_tl_path, switch_action, Some(&stage_gcroot))?;
            if !out_log.is_empty() {
                self.last_activation_log = out_log;
            }
            if !ok {
                let diag = if self.last_activation_log.is_empty() {
                    format!("switch-to-configuration {switch_action} returned non-zero")
                } else {
                    format!(
                        "switch-to-configuration {switch_action} returned non-zero:\n{}",
                        self.last_activation_log
                    )
                };
                self.execute_rollback(tx_epoch, "SwitchToConfigurationTestFailed")?;
                return Err(EpochError::Io(diag));
            }
        }
        if wave_id != "boot" && wave_id != "dry-activate" {
            replace_symlink(&self.layout.run_current_system_link, staged_tl_path)?;
        }

        self.state.phase = AgentPhase::Probing;
        save_persistent_state(
            &self.layout.state_cbor_path,
            &mut self.state,
            &self.state_mac_key,
        )?;

        Ok(requires_reboot)
    }

    /// Step 4 (`PROBING -> BARRIER_WAIT | ROLLED_BACK`):
    /// Evaluate all 3 Multi-Signal Health Oracles and optional `$staged_toplevel/saturn-health-check`.
    /// If healthy, enter `BARRIER_WAIT` under active lease;
    /// if unhealthy or lease expired, immediately roll back and return a signed negative `HealthAttestation`.
    pub fn evaluate_probes_and_attest(
        &mut self,
        now_boottime_ns: u64,
        probe_env: &ProbeEnvironment,
    ) -> Result<EpochWireMsg, EpochError> {
        let tx_epoch = self.state.highest_tx_epoch;
        let wave_id = self
            .state
            .active_wave_id
            .clone()
            .unwrap_or_else(|| "default".into());

        if now_boottime_ns >= self.state.lease_deadline_boottime_ns {
            self.execute_rollback(tx_epoch, "LeaseExpiredDuringProbing")?;
            return sign_health_attestation(
                &self.node_key,
                tx_epoch,
                &wave_id,
                &self.node_id,
                false,
                "LeaseExpiredDuringProbing",
            );
        }

        if let Some(ref mut wd) = self.watchdog {
            wd.ping_keepalive();
        }

        let probes_spec = self
            .active_plan
            .as_ref()
            .and_then(|p| p.waves.iter().find(|w| w.wave_id == wave_id))
            .map(|w| w.probes.clone())
            .unwrap_or_default();

        let oracle_res = evaluate_health_oracles(&probes_spec, probe_env);
        if !oracle_res.healthy {
            self.execute_rollback(tx_epoch, &oracle_res.diagnostic)?;
            return sign_health_attestation(
                &self.node_key,
                tx_epoch,
                &wave_id,
                &self.node_id,
                false,
                &oracle_res.diagnostic,
            );
        }

        if wave_id != "dry-activate"
            && wave_id != "boot"
            && let Some(ref staged_tl) = self.state.staged_toplevel.clone()
            && Path::new(staged_tl).join("saturn-health-check").exists()
        {
            let remaining_ns = self
                .state
                .lease_deadline_boottime_ns
                .saturating_sub(clock_boottime_ns())
                .max(1_000_000_000);
            let hc_timeout_ns = self.active_lease_ns.min(remaining_ns).max(1_000_000_000);
            let (hc_ok, hc_log) = run_saturn_health_check(Path::new(staged_tl), hc_timeout_ns)?;
            if !hc_log.is_empty() {
                if !self.last_activation_log.is_empty() {
                    self.last_activation_log.push('\n');
                }
                self.last_activation_log.push_str(&hc_log);
            }
            if !hc_ok {
                let reason = if self.last_activation_log.is_empty() {
                    "SaturnHealthCheckFailed".to_owned()
                } else {
                    format!("SaturnHealthCheckFailed:\n{}", self.last_activation_log)
                };
                self.execute_rollback(tx_epoch, &reason)?;
                return sign_health_attestation(
                    &self.node_key,
                    tx_epoch,
                    &wave_id,
                    &self.node_id,
                    false,
                    &reason,
                );
            }
            // Refresh lease deadline after health check so coordinator has full lease window to confirm
            self.state.lease_deadline_boottime_ns =
                clock_boottime_ns().saturating_add(self.active_lease_ns);
        }

        self.state.phase = AgentPhase::BarrierWait;
        save_persistent_state(
            &self.layout.state_cbor_path,
            &mut self.state,
            &self.state_mac_key,
        )?;
        let diag = if self.last_activation_log.is_empty() {
            oracle_res.diagnostic
        } else {
            format!("{}\n{}", oracle_res.diagnostic, self.last_activation_log)
        };
        sign_health_attestation(
            &self.node_key,
            tx_epoch,
            &wave_id,
            &self.node_id,
            true,
            &diag,
        )
    }

    /// Check monotonic `CLOCK_BOOTTIME` lease expiration across `PREPARED`, `ACTIVATING`, `PROBING`, and `BARRIER_WAIT`.
    /// Returns `Ok(true)` if the lease expired and triggered automatic fail-closed rollback to $G_t$.
    pub fn check_lease_expiration(&mut self, now_boottime_ns: u64) -> Result<bool, EpochError> {
        if matches!(
            self.state.phase,
            AgentPhase::Prepared
                | AgentPhase::Activating
                | AgentPhase::Probing
                | AgentPhase::BarrierWait
        ) && now_boottime_ns >= self.state.lease_deadline_boottime_ns
        {
            let tx = self.state.highest_tx_epoch;
            self.execute_rollback(tx, "ClockBoottimeLeaseExpired")?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Extend the active `BARRIER_WAIT` lease upon verifying a coordinator-signed `LeaseKeepalive`
    /// (received either directly from Coordinator or via `PeerWitnessRelay`).
    pub fn handle_lease_keepalive(
        &mut self,
        tx_epoch: u64,
        wave_id: &str,
        extend_ttl_ms: u32,
        coord_sig: &Ed25519Sig,
        now_boottime_ns: u64,
    ) -> Result<(), EpochError> {
        self.check_epoch_fencing(tx_epoch, true)?;
        self.check_wave_binding(wave_id, true)?;
        let plan = self
            .active_plan
            .as_ref()
            .ok_or_else(|| EpochError::Io("no active plan loaded".into()))?;
        verify_lease_keepalive(
            &plan.coordinator_pub,
            tx_epoch,
            wave_id,
            extend_ttl_ms,
            coord_sig,
        )?;
        let ext_ns = (extend_ttl_ms as u64).saturating_mul(1_000_000);
        self.state.lease_deadline_boottime_ns = now_boottime_ns.saturating_add(ext_ns);
        if let Some(ref mut wd) = self.watchdog {
            wd.ping_keepalive();
        }
        save_persistent_state(
            &self.layout.state_cbor_path,
            &mut self.state,
            &self.state_mac_key,
        )?;
        Ok(())
    }

    /// Wrap a cohort peer's `HealthAttestation` (and optional coordinator `LeaseKeepalive`/`CommitWave`)
    /// into a signed `PeerWitnessRelay` message.
    pub fn create_peer_witness_relay(
        &self,
        peer_attestation: EpochWireMsg,
        relayed_coord_msg: Option<EpochWireMsg>,
    ) -> Result<EpochWireMsg, EpochError> {
        // Verify the peer's attestation signature against the pinned `plan.cbor` node keys first
        if let EpochWireMsg::HealthAttestation {
            tx_epoch,
            ref wave_id,
            ref node_id,
            healthy,
            ref diagnostic,
            ref node_sig,
        } = peer_attestation
        {
            let plan = self
                .active_plan
                .as_ref()
                .ok_or_else(|| EpochError::Io("no active plan loaded".into()))?;
            let peer_pub = plan
                .nodes
                .iter()
                .find(|n| &n.node_id == node_id)
                .map(|n| &n.node_pub)
                .ok_or_else(|| {
                    EpochError::CryptoVerificationFailed(format!("unknown peer node {node_id}"))
                })?;
            verify_health_attestation(
                peer_pub, tx_epoch, wave_id, node_id, healthy, diagnostic, node_sig,
            )?;
        }
        sign_peer_witness_relay(
            &self.node_key,
            &self.node_id,
            peer_attestation,
            relayed_coord_msg,
        )
    }

    /// Handle a peer-relayed message (`PeerWitnessRelay`) or direct peer failure gossip.
    /// - If a cohort peer gossips a validly signed `HealthAttestation { healthy: false }`,
    ///   immediately abort `BARRIER_WAIT -> ROLLED_BACK`!
    /// - If a cohort peer relays a coordinator-signed `CommitWave` or `LeaseKeepalive`,
    ///   verify the coordinator's `Ed25519` signature and execute it!
    pub fn handle_peer_witness_relay(
        &mut self,
        relay_msg: &EpochWireMsg,
        now_boottime_ns: u64,
    ) -> Result<(), EpochError> {
        if let EpochWireMsg::PeerWitnessRelay {
            attestation,
            relayed_coord_msg,
            relay_node_id,
            relay_sig,
        } = relay_msg
        {
            let rollback_action = {
                let plan = self
                    .active_plan
                    .as_ref()
                    .ok_or_else(|| EpochError::Io("no active plan loaded".into()))?;

                let relay_pub = plan
                    .nodes
                    .iter()
                    .find(|n| &n.node_id == relay_node_id)
                    .map(|n| &n.node_pub)
                    .ok_or_else(|| {
                        EpochError::CryptoVerificationFailed(format!(
                            "unknown relay peer {relay_node_id}"
                        ))
                    })?;
                verify_peer_witness_relay(
                    relay_pub,
                    relay_node_id,
                    attestation,
                    relayed_coord_msg,
                    relay_sig,
                )?;

                if let EpochWireMsg::HealthAttestation {
                    tx_epoch,
                    ref wave_id,
                    ref node_id,
                    healthy,
                    ref diagnostic,
                    ref node_sig,
                } = **attestation
                {
                    let origin_pub = plan
                        .nodes
                        .iter()
                        .find(|n| &n.node_id == node_id)
                        .map(|n| &n.node_pub)
                        .ok_or_else(|| {
                            EpochError::CryptoVerificationFailed(format!(
                                "unknown attestation origin {node_id}"
                            ))
                        })?;
                    verify_health_attestation(
                        origin_pub, tx_epoch, wave_id, node_id, healthy, diagnostic, node_sig,
                    )?;
                    if !healthy
                        && self.state.highest_tx_epoch == tx_epoch
                        && self.state.active_wave_id.as_deref() == Some(wave_id.as_str())
                    {
                        Some((tx_epoch, format!("CohortPeerFailed:{node_id}:{diagnostic}")))
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some((tx_epoch, reason)) = rollback_action {
                self.execute_rollback(tx_epoch, &reason)?;
                return Ok(());
            }

            if let Some(coord_msg) = relayed_coord_msg {
                match &**coord_msg {
                    EpochWireMsg::LeaseKeepalive {
                        tx_epoch,
                        wave_id,
                        extend_ttl_ms,
                        coord_sig,
                    } => {
                        self.handle_lease_keepalive(
                            *tx_epoch,
                            wave_id,
                            *extend_ttl_ms,
                            coord_sig,
                            now_boottime_ns,
                        )?;
                    }
                    EpochWireMsg::CommitWave {
                        tx_epoch,
                        wave_id,
                        attestation_hashes,
                        coord_sig,
                    } => {
                        self.handle_commit_wave(*tx_epoch, wave_id, attestation_hashes, coord_sig)?;
                    }
                    EpochWireMsg::AbortWave {
                        tx_epoch,
                        wave_id,
                        reason,
                        coord_sig,
                    } => {
                        self.handle_abort_wave(*tx_epoch, wave_id, reason, coord_sig)?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Step 5 (`BARRIER_WAIT -> COMMITTED`):
    /// Verify `CommitWave(tx_epoch, coord_sig)`, atomically update `/nix/var/nix/profiles/system`,
    /// promote `systemd-boot` trial entry to permanent default, zero-wipe retired secret generation
    /// `/run/epoch/secrets/gen-<prev_secret_epoch>`, remove staging GC root, and disarm `/dev/watchdog`.
    pub fn handle_commit_wave(
        &mut self,
        tx_epoch: u64,
        wave_id: &str,
        attestation_hashes: &[Blake3Hash],
        coord_sig: &Ed25519Sig,
    ) -> Result<(), EpochError> {
        let _zone = crate::tracy_zone!("plane4::handle_commit_wave", 0xbe185d);
        self.check_epoch_fencing(tx_epoch, true)?;
        if self.state.phase != AgentPhase::BarrierWait {
            return Err(EpochError::InvalidTransition {
                from: self.state.phase,
                event: "CommitWave",
            });
        }
        self.check_wave_binding(wave_id, true)?;
        let plan = self
            .active_plan
            .as_ref()
            .ok_or_else(|| EpochError::Io("no active plan loaded".into()))?;
        verify_commit_wave(
            &plan.coordinator_pub,
            tx_epoch,
            wave_id,
            attestation_hashes,
            coord_sig,
        )?;

        let staged_tl = self
            .state
            .staged_toplevel
            .clone()
            .ok_or_else(|| EpochError::Io("missing staged_toplevel on commit".into()))?;
        let staged_tl_path = Path::new(&staged_tl);

        match wave_id {
            "test" | "dry-activate" => {
                // `test` and `dry-activate` never update `/nix/var/nix/profiles/system`
            }
            "boot" => {
                if self.layout.root_dir == Path::new("/") {
                    self.advance_live_system_profile(staged_tl_path)?;
                } else {
                    let new_gen_link = self
                        .layout
                        .profiles_dir
                        .join(format!("system-{tx_epoch}-link"));
                    replace_symlink(&new_gen_link, staged_tl_path)?;
                    atomic_replace_or_exchange_symlink(
                        &self.layout.system_profile_link,
                        &new_gen_link,
                    )?;
                }
            }
            _ => {
                if self.layout.root_dir == Path::new("/") {
                    self.advance_live_system_profile(staged_tl_path)?;
                } else {
                    let new_gen_link = self
                        .layout
                        .profiles_dir
                        .join(format!("system-{tx_epoch}-link"));
                    replace_symlink(&new_gen_link, staged_tl_path)?;
                    atomic_replace_or_exchange_symlink(
                        &self.layout.system_profile_link,
                        &new_gen_link,
                    )?;
                }
                replace_symlink(&self.layout.run_current_system_link, staged_tl_path)?;

                let switch_bin = staged_tl_path.join("bin").join("switch-to-configuration");
                if switch_bin.exists() {
                    let (ok, out_log) =
                        run_switch_to_configuration(staged_tl_path, "switch", None)?;
                    if !out_log.is_empty() {
                        if !self.last_activation_log.is_empty() {
                            self.last_activation_log.push('\n');
                        }
                        self.last_activation_log.push_str(&out_log);
                    }
                    if !ok {
                        self.execute_rollback(tx_epoch, "SwitchToConfigurationSwitchFailed")?;
                        return Err(EpochError::Io(format!(
                            "switch-to-configuration switch failed:\n{}",
                            self.last_activation_log
                        )));
                    }
                }
            }
        }

        // 2. Promote `systemd-boot` trial entry (`+0-1.conf` / `+1-0.conf`) or write permanent `.conf` and update `loader.conf`
        if self.layout.root_dir != Path::new("/") {
            let commit_kernel = self
                .staged_kernel_path
                .clone()
                .unwrap_or_else(|| self.active_kernel_path.clone());
            let commit_initrd = self
                .staged_initrd_path
                .clone()
                .unwrap_or_else(|| self.active_initrd_path.clone());
            promote_or_write_systemd_boot_permanent(
                &self.layout.boot_root,
                tx_epoch,
                &staged_tl,
                &commit_kernel,
                &commit_initrd,
            )?;
        }

        // 3. Cryptographically zero-wipe retired secret generation `gen-<prev_secret_epoch>`
        let prev_sec_epoch = self.state.prev_secret_epoch;
        if prev_sec_epoch != tx_epoch {
            zero_wipe_secret_generation(&self.layout.ramfs_secrets_root, prev_sec_epoch)?;
        }

        // 4. Remove temporary staging GC root (closure is now anchored by `/nix/var/nix/profiles/system`)
        remove_staging_gcroot(&self.layout.gcroots_staging_dir, tx_epoch);

        // 5. Disarm hardware watchdog and persist `Committed`
        if let Some(ref mut wd) = self.watchdog {
            wd.disarm();
        }
        self.watchdog = None;

        if let Some(k) = self.staged_kernel_path.take() {
            self.active_kernel_path = k;
        }
        if let Some(initrd) = self.staged_initrd_path.take() {
            self.active_initrd_path = initrd;
        }

        self.state.phase = AgentPhase::Committed;
        if wave_id != "boot" && wave_id != "dry-activate" {
            self.state.prev_toplevel = staged_tl;
        }
        self.state.prev_secret_epoch = tx_epoch;
        self.state.staged_toplevel = None;
        self.state.lease_deadline_boottime_ns = 0;
        self.state.reboot_deadline_wall_utc_s = 0;
        save_persistent_state(
            &self.layout.state_cbor_path,
            &mut self.state,
            &self.state_mac_key,
        )?;

        Ok(())
    }

    /// Handle coordinator-signed `AbortWave(tx_epoch, wave_id, reason, coord_sig)`.
    pub fn handle_abort_wave(
        &mut self,
        tx_epoch: u64,
        wave_id: &str,
        reason: &str,
        coord_sig: &Ed25519Sig,
    ) -> Result<(), EpochError> {
        self.check_epoch_fencing(tx_epoch, true)?;
        self.check_wave_binding(wave_id, true)?;
        let plan = self
            .active_plan
            .as_ref()
            .ok_or_else(|| EpochError::Io("no active plan loaded".into()))?;
        verify_abort_wave(&plan.coordinator_pub, tx_epoch, wave_id, reason, coord_sig)?;
        self.execute_rollback(tx_epoch, reason)
    }

    /// Deterministically revert both system closure and `/run/epoch/current-secrets` symlink to $G_t$,
    /// zero-wipe (`explicit_bzero`) `/run/epoch/secrets/gen-<tx_epoch>`, clean up staging GC roots
    /// and trial boot entries, disarm `/dev/watchdog`, and persist `RolledBack(tx_epoch)`.
    pub fn execute_rollback(&mut self, tx_epoch: u64, reason: &str) -> Result<(), EpochError> {
        let _zone = crate::tracy_zone!("plane4::execute_rollback", 0x9d174d);
        let prev_sec_epoch = self.state.prev_secret_epoch;
        let prev_tl = self.state.prev_toplevel.clone();

        // 1. Atomically swap `/run/epoch/current-secrets` back to `gen-<prev_secret_epoch>` via RENAME_EXCHANGE
        if self
            .layout
            .ramfs_secrets_root
            .join(format!("gen-{prev_sec_epoch}"))
            .exists()
        {
            atomic_flip_current_secrets(
                &self.layout.current_secrets_link,
                &self.layout.ramfs_secrets_root,
                prev_sec_epoch,
            )?;
        }

        // 2. Restore `/run/current-system -> prev_toplevel` and run `$prev_toplevel/bin/switch-to-configuration test`
        let prev_tl_path = Path::new(&prev_tl);
        if prev_tl_path.exists() {
            let switch_bin = prev_tl_path.join("bin").join("switch-to-configuration");
            if switch_bin.exists() {
                let _ = run_switch_to_configuration(prev_tl_path, "test", None);
            }
            let _ = replace_symlink(&self.layout.run_current_system_link, prev_tl_path);
        }

        // 3. Cryptographically zero-wipe (`explicit_bzero`) retired trial secret generation `gen-<tx_epoch>`
        if tx_epoch != prev_sec_epoch {
            zero_wipe_secret_generation(&self.layout.ramfs_secrets_root, tx_epoch)?;
        }

        // 4. Remove staging GC root and any `+1-0.conf` / `+0-1.conf` trial boot entries
        remove_staging_gcroot(&self.layout.gcroots_staging_dir, tx_epoch);
        if self.layout.root_dir != Path::new("/") {
            let _ = cleanup_failed_systemd_boot_trials(
                &self.layout.boot_root,
                &self.layout.efivars_dir,
            );
        }

        // 5. Disarm `/dev/watchdog` and persist `RolledBack`
        if let Some(ref mut wd) = self.watchdog {
            wd.disarm();
        }
        self.watchdog = None;

        if !reason.is_empty() {
            if !self.last_activation_log.is_empty() {
                self.last_activation_log.push('\n');
            }
            self.last_activation_log
                .push_str(&format!("RolledBack: {reason}"));
        }

        self.state.highest_tx_epoch = self.state.highest_tx_epoch.max(tx_epoch);
        self.state.phase = AgentPhase::RolledBack;
        self.state.staged_toplevel = None;
        self.state.lease_deadline_boottime_ns = 0;
        self.state.reboot_deadline_wall_utc_s = 0;
        save_persistent_state(
            &self.layout.state_cbor_path,
            &mut self.state,
            &self.state_mac_key,
        )?;

        Ok(())
    }

    /// Layer 3 Post-Reboot `state.cbor` Reconciliation (`DESIGN.md` §5.4.4 Layer 3):
    /// Called when `epoch-agent` starts after a reboot (e.g. after a kernel panic / initrd hang
    /// triggered a hardware watchdog reset and `systemd-boot` fell back from `+0-1.conf` to `G_t`).
    pub fn reconcile_post_reboot(
        &mut self,
        booted_toplevel: &Path,
        prev_archetype_toplevel: &str,
        tpm2_pcr_state: Option<(u32, &[u8; 32])>,
        now_wall_utc_s: u64,
    ) -> Result<Option<EpochWireMsg>, EpochError> {
        replace_symlink(&self.layout.run_booted_system_link, booted_toplevel)?;

        // Stage 2 early-boot unseal of booted generation's secrets
        let booted_str = booted_toplevel.to_string_lossy().into_owned();
        if booted_str == self.state.prev_toplevel {
            unseal_boot_secrets(
                booted_toplevel,
                &self.layout.ramfs_secrets_root,
                &self.layout.current_secrets_link,
                self.state.prev_secret_epoch,
                &self.node_id,
                prev_archetype_toplevel,
                &self.node_key,
                tpm2_pcr_state,
            )?;
        }

        if matches!(
            self.state.phase,
            AgentPhase::Activating | AgentPhase::Probing | AgentPhase::BarrierWait
        ) {
            let tx_epoch = self.state.highest_tx_epoch;
            let wave_id = self
                .state
                .active_wave_id
                .clone()
                .unwrap_or_else(|| "default".into());
            let fell_back_to_prev = booted_str == self.state.prev_toplevel;
            let deadline_expired = self.state.reboot_deadline_wall_utc_s > 0
                && now_wall_utc_s > self.state.reboot_deadline_wall_utc_s;

            if fell_back_to_prev || deadline_expired {
                self.execute_rollback(tx_epoch, "KernelBootFallbackToPrevGeneration")?;
                let att = sign_health_attestation(
                    &self.node_key,
                    tx_epoch,
                    &wave_id,
                    &self.node_id,
                    false,
                    "KernelBootFallbackToPrevGeneration",
                )?;
                return Ok(Some(att));
            }
        }
        Ok(None)
    }

    /// Dispatch an incoming `EpochWireMsg` received over an `epoch-p2p/1` QUIC mTLS stream
    /// and produce the corresponding wire response message.
    pub fn handle_wire_message(
        &mut self,
        msg: EpochWireMsg,
        expected_archetype_toplevel: &str,
        now_boottime_ns: u64,
        now_wall_utc_s: u64,
    ) -> Result<EpochWireMsg, EpochError> {
        let _ = self.check_lease_expiration(now_boottime_ns);
        match msg {
            EpochWireMsg::QueryMissingPathsReq {
                tx_epoch,
                store_paths,
            } => {
                let systemd_unit_active = self.layout.root_dir == Path::new("/")
                    && Command::new("/run/current-system/sw/bin/systemctl")
                        .args([
                            "is-active",
                            "--quiet",
                            "epoch-activate.service",
                            "saturn-deploy.service",
                            "nixos-rebuild-switch-to-configuration.service",
                        ])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                let active_deployment = systemd_unit_active
                    || (matches!(
                        self.state.phase,
                        AgentPhase::Activating | AgentPhase::Probing | AgentPhase::BarrierWait
                    ) && now_boottime_ns < self.state.lease_deadline_boottime_ns);
                let current_system = fs::read_link(&self.layout.run_current_system_link)
                    .ok()
                    .and_then(|p| fs::canonicalize(&p).ok().or(Some(p)))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| self.state.prev_toplevel.clone());
                let missing_paths = query_missing_store_paths(
                    &self.layout.store_dir,
                    &self.layout.sqlite_db_path,
                    &store_paths,
                )?;
                Ok(EpochWireMsg::QueryMissingPathsResp {
                    tx_epoch,
                    missing_paths,
                    current_system,
                    highest_tx_epoch: self.state.highest_tx_epoch,
                    active_deployment,
                })
            }
            EpochWireMsg::StageManifest {
                tx_epoch,
                plan,
                manifests,
            } => match self.handle_stage_manifest(
                tx_epoch,
                plan,
                &manifests,
                &[],
                60_000_000_000,
                now_boottime_ns,
            ) {
                Ok(_) => Ok(EpochWireMsg::StageAck {
                    tx_epoch,
                    node_id: self.node_id.clone(),
                    ok: true,
                    error: None,
                }),
                Err(e) => Ok(EpochWireMsg::StageAck {
                    tx_epoch,
                    node_id: self.node_id.clone(),
                    ok: false,
                    error: Some(e.to_string()),
                }),
            },
            EpochWireMsg::FetchChunksReq {
                tx_epoch,
                missing_norm_blake3,
            } => {
                if tx_epoch < self.state.highest_tx_epoch {
                    let err = EpochError::StaleEpochFenced {
                        msg_epoch: tx_epoch,
                        highest_epoch: self.state.highest_tx_epoch,
                    };
                    return Ok(EpochWireMsg::StageAck {
                        tx_epoch,
                        node_id: self.node_id.clone(),
                        ok: false,
                        error: Some(err.to_string()),
                    });
                }
                let mut chunks = Vec::with_capacity(missing_norm_blake3.len());
                for h in missing_norm_blake3 {
                    if let Some(raw) = self.chunk_index.get_chunk(&h) {
                        let zstd_bytes = crate::plane2_store::zstd_compress(raw)?;
                        chunks.push((h, zstd_bytes));
                    }
                }
                Ok(EpochWireMsg::FetchChunksResp { chunks })
            }
            EpochWireMsg::FetchChunksResp { chunks } => {
                for (idx, (h, zstd_bytes)) in chunks.into_iter().enumerate() {
                    let raw = match crate::plane2_store::zstd_decompress_bounded(
                        &zstd_bytes,
                        crate::plane2_store::FASTCDC_MAX_SIZE,
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            return Ok(EpochWireMsg::StageAck {
                                tx_epoch: self.state.highest_tx_epoch,
                                node_id: self.node_id.clone(),
                                ok: false,
                                error: Some(e.to_string()),
                            });
                        }
                    };
                    let actual = *blake3::hash(&raw).as_bytes();
                    if actual != h {
                        let err = EpochError::ChunkBlake3Mismatch {
                            chunk_idx: idx,
                            expected: hex::encode(h),
                            actual: hex::encode(actual),
                        };
                        return Ok(EpochWireMsg::StageAck {
                            tx_epoch: self.state.highest_tx_epoch,
                            node_id: self.node_id.clone(),
                            ok: false,
                            error: Some(err.to_string()),
                        });
                    }
                    self.chunk_index.insert_verified_chunk(h, raw);
                }
                if let Err(e) = self.chunk_index.save_atomic(&self.layout.chunk_index_path) {
                    return Ok(EpochWireMsg::StageAck {
                        tx_epoch: self.state.highest_tx_epoch,
                        node_id: self.node_id.clone(),
                        ok: false,
                        error: Some(e.to_string()),
                    });
                }
                Ok(EpochWireMsg::StageAck {
                    tx_epoch: self.state.highest_tx_epoch,
                    node_id: self.node_id.clone(),
                    ok: true,
                    error: None,
                })
            }
            EpochWireMsg::PrepareWave { tx_epoch, wave_id } => match self.handle_prepare_wave(
                tx_epoch,
                &wave_id,
                expected_archetype_toplevel,
                None,
                30_000_000_000,
                now_boottime_ns,
            ) {
                Ok(_) => Ok(EpochWireMsg::PrepareAck {
                    tx_epoch,
                    wave_id,
                    node_id: self.node_id.clone(),
                    ok: true,
                    error: None,
                }),
                Err(e) => Ok(EpochWireMsg::PrepareAck {
                    tx_epoch,
                    wave_id,
                    node_id: self.node_id.clone(),
                    ok: false,
                    error: Some(e.to_string()),
                }),
            },
            EpochWireMsg::ActivateWave {
                tx_epoch,
                wave_id,
                lease_ttl_ms,
                coord_sig,
            } => match self.handle_activate_wave(
                tx_epoch,
                &wave_id,
                lease_ttl_ms,
                &coord_sig,
                now_boottime_ns,
                now_wall_utc_s,
            ) {
                Ok(_) => self.evaluate_probes_and_attest(
                    now_boottime_ns,
                    &ProbeEnvironment {
                        reachable_cohort_peers: 1,
                        ..Default::default()
                    },
                ),
                Err(e) => sign_health_attestation(
                    &self.node_key,
                    tx_epoch,
                    &wave_id,
                    &self.node_id,
                    false,
                    &e.to_string(),
                ),
            },
            EpochWireMsg::LeaseKeepalive {
                tx_epoch,
                wave_id,
                extend_ttl_ms,
                coord_sig,
            } => match self.handle_lease_keepalive(
                tx_epoch,
                &wave_id,
                extend_ttl_ms,
                &coord_sig,
                now_boottime_ns,
            ) {
                Ok(()) => sign_health_attestation(
                    &self.node_key,
                    tx_epoch,
                    &wave_id,
                    &self.node_id,
                    true,
                    "LeaseExtended",
                ),
                Err(e) => sign_health_attestation(
                    &self.node_key,
                    tx_epoch,
                    &wave_id,
                    &self.node_id,
                    false,
                    &e.to_string(),
                ),
            },
            EpochWireMsg::PeerWitnessRelay { .. } => {
                match self.handle_peer_witness_relay(&msg, now_boottime_ns) {
                    Ok(()) => {
                        let wave = self
                            .state
                            .active_wave_id
                            .clone()
                            .unwrap_or_else(|| "default".into());
                        sign_health_attestation(
                            &self.node_key,
                            self.state.highest_tx_epoch,
                            &wave,
                            &self.node_id,
                            self.state.phase != AgentPhase::RolledBack,
                            self.state.phase.as_str(),
                        )
                    }
                    Err(e) => {
                        let wave = self
                            .state
                            .active_wave_id
                            .clone()
                            .unwrap_or_else(|| "default".into());
                        sign_health_attestation(
                            &self.node_key,
                            self.state.highest_tx_epoch,
                            &wave,
                            &self.node_id,
                            false,
                            &e.to_string(),
                        )
                    }
                }
            }
            EpochWireMsg::CommitWave {
                tx_epoch,
                wave_id,
                attestation_hashes,
                coord_sig,
            } => match self.handle_commit_wave(tx_epoch, &wave_id, &attestation_hashes, &coord_sig)
            {
                Ok(()) => {
                    let diag = if self.last_activation_log.is_empty() {
                        "COMMITTED".to_owned()
                    } else {
                        format!("COMMITTED\n{}", self.last_activation_log)
                    };
                    sign_health_attestation(
                        &self.node_key,
                        tx_epoch,
                        &wave_id,
                        &self.node_id,
                        true,
                        &diag,
                    )
                }
                Err(e) => {
                    let diag = if self.last_activation_log.is_empty() {
                        e.to_string()
                    } else {
                        format!("{e}\n{}", self.last_activation_log)
                    };
                    sign_health_attestation(
                        &self.node_key,
                        tx_epoch,
                        &wave_id,
                        &self.node_id,
                        false,
                        &diag,
                    )
                }
            },
            EpochWireMsg::AbortWave {
                tx_epoch,
                wave_id,
                reason,
                coord_sig,
            } => match self.handle_abort_wave(tx_epoch, &wave_id, &reason, &coord_sig) {
                Ok(()) => sign_health_attestation(
                    &self.node_key,
                    tx_epoch,
                    &wave_id,
                    &self.node_id,
                    false,
                    &format!("RolledBack:{reason}"),
                ),
                Err(e) => sign_health_attestation(
                    &self.node_key,
                    tx_epoch,
                    &wave_id,
                    &self.node_id,
                    false,
                    &e.to_string(),
                ),
            },
            _ => {
                let wave = self
                    .state
                    .active_wave_id
                    .clone()
                    .unwrap_or_else(|| "default".into());
                let diag = if self.state.phase == AgentPhase::RolledBack
                    && !self.last_activation_log.is_empty()
                {
                    format!("ROLLED_BACK\n{}", self.last_activation_log)
                } else {
                    self.state.phase.as_str().to_owned()
                };
                sign_health_attestation(
                    &self.node_key,
                    self.state.highest_tx_epoch,
                    &wave,
                    &self.node_id,
                    self.state.phase != AgentPhase::RolledBack,
                    &diag,
                )
            }
        }
    }
}

fn highest_system_profile_gen(profiles_dir: &Path) -> u64 {
    let mut highest = 0u64;
    if let Ok(entries) = fs::read_dir(profiles_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if let Some(mid) = s
                .strip_prefix("system-")
                .and_then(|r| r.strip_suffix("-link"))
                && let Ok(n) = mid.parse::<u64>()
                && n > highest
            {
                highest = n;
            }
        }
    }
    highest
}

fn build_activation_path_env(toplevel: &Path) -> String {
    format!(
        "/run/wrappers/bin:{}/sw/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/bin:/usr/bin",
        toplevel.display()
    )
}

fn run_switch_to_configuration(
    toplevel: &Path,
    action: &str,
    stage_gcroot: Option<&Path>,
) -> Result<(bool, String), EpochError> {
    let switch_bin = toplevel.join("bin").join("switch-to-configuration");
    let mut cmd = Command::new(&switch_bin);
    cmd.arg(action);
    cmd.env("PATH", build_activation_path_env(toplevel));
    let locale_archive = toplevel.join("sw/lib/locale/locale-archive");
    if locale_archive.exists() {
        cmd.env("LOCALE_ARCHIVE", &locale_archive);
    }
    if let Some(gc) = stage_gcroot {
        cmd.env("EPOCH_STAGE_ROOT", gc);
    }
    if Path::new("/").exists() {
        cmd.current_dir("/");
    }
    let output = cmd
        .output()
        .map_err(|e| EpochError::Io(format!("failed to spawn {}: {e}", switch_bin.display())))?;
    let mut combined = String::new();
    let stdout_s = String::from_utf8_lossy(&output.stdout);
    let stderr_s = String::from_utf8_lossy(&output.stderr);
    if !stdout_s.trim().is_empty() {
        combined.push_str(stdout_s.trim());
    }
    if !stderr_s.trim().is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(stderr_s.trim());
    }
    Ok((output.status.success(), combined))
}

fn run_saturn_health_check(toplevel: &Path, timeout_ns: u64) -> Result<(bool, String), EpochError> {
    use std::os::unix::process::CommandExt as _;
    let hc_path = toplevel.join("saturn-health-check");
    if !hc_path.exists() {
        return Ok((true, String::new()));
    }
    let mut cmd = Command::new(&hc_path);
    cmd.env("PATH", build_activation_path_env(toplevel));
    let locale_archive = toplevel.join("sw/lib/locale/locale-archive");
    if locale_archive.exists() {
        cmd.env("LOCALE_ARCHIVE", &locale_archive);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.process_group(0);

    let mut child = cmd
        .spawn()
        .map_err(|e| EpochError::Io(format!("failed to spawn {}: {e}", hc_path.display())))?;
    let deadline_ns = clock_boottime_ns().saturating_add(timeout_ns);

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|e| EpochError::Io(e.to_string()))?;
                let mut combined = String::new();
                let stdout_s = String::from_utf8_lossy(&output.stdout);
                let stderr_s = String::from_utf8_lossy(&output.stderr);
                if !stdout_s.trim().is_empty() {
                    combined.push_str(stdout_s.trim());
                }
                if !stderr_s.trim().is_empty() {
                    if !combined.is_empty() {
                        combined.push('\n');
                    }
                    combined.push_str(stderr_s.trim());
                }
                return Ok((output.status.success(), combined));
            }
            Ok(None) => {
                if clock_boottime_ns() >= deadline_ns {
                    let pid = child.id() as i32;
                    if pid > 0 {
                        unsafe {
                            let _ = libc::kill(-pid, libc::SIGKILL);
                        }
                    }
                    let _ = child.kill();
                    let output = child.wait_with_output().ok();
                    let mut combined = String::new();
                    if let Some(out) = output {
                        let stdout_s = String::from_utf8_lossy(&out.stdout);
                        let stderr_s = String::from_utf8_lossy(&out.stderr);
                        if !stdout_s.trim().is_empty() {
                            combined.push_str(stdout_s.trim());
                        }
                        if !stderr_s.trim().is_empty() {
                            if !combined.is_empty() {
                                combined.push('\n');
                            }
                            combined.push_str(stderr_s.trim());
                        }
                    }
                    if !combined.is_empty() {
                        combined.push('\n');
                    }
                    combined.push_str("saturn-health-check timed out");
                    return Ok((false, combined));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => return Err(EpochError::Io(e.to_string())),
        }
    }
}

pub fn replace_symlink(link_path: &Path, target: &Path) -> Result<(), EpochError> {
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = link_path.with_extension(" symlink_tmp");
    if fs::symlink_metadata(&tmp).is_ok() {
        let _ = fs::remove_file(&tmp);
    }
    symlink(target, &tmp)?;
    fs::rename(&tmp, link_path)?;
    Ok(())
}

pub fn atomic_replace_or_exchange_symlink(
    link_path: &Path,
    new_target: &Path,
) -> Result<(), EpochError> {
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let next_link = link_path.with_extension("next");
    if fs::symlink_metadata(&next_link).is_ok() {
        let _ = fs::remove_file(&next_link);
    }
    symlink(new_target, &next_link)?;

    if fs::symlink_metadata(link_path).is_ok() {
        let next_c = CString::new(next_link.as_os_str().as_bytes())
            .map_err(|e| EpochError::Io(e.to_string()))?;
        let curr_c = CString::new(link_path.as_os_str().as_bytes())
            .map_err(|e| EpochError::Io(e.to_string()))?;
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                next_c.as_ptr(),
                libc::AT_FDCWD,
                curr_c.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        if rc == 0 {
            let _ = fs::remove_file(&next_link);
            return Ok(());
        }
    }
    fs::rename(&next_link, link_path)?;
    Ok(())
}
