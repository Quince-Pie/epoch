//! Plane 4.4: 3-Layer Kernel & Reboot Safety
//!
//! Implements:
//! 1. **Layer 1 (Hardware Watchdog & Anti-OOM Pinning)**:
//!    - `mlockall(MCL_CURRENT | MCL_FUTURE)` + `/proc/self/oom_score_adj = -1000`.
//!    - `/dev/watchdog` `WDIOC_SETTIMEOUT` (`60s`), `WDIOC_KEEPALIVE`, and magic `'V'` disarm.
//! 2. **Layer 2 (`systemd-boot` Single-Trial Boot Counting `+1-0.conf`)**:
//!    - Leaves `/boot/loader/loader.conf` `default nixos-generation-<prev>.conf` untouched during trial boot.
//!    - Creates `/boot/loader/entries/nixos-generation-<tx>+1-0.conf` and sets EFI `LoaderEntryOneShot`.
//!    - On boot, `systemd-boot` decrements `+1-0.conf -> +0-1.conf`; if the new kernel/initrd panics and
//!      watchdog resets the host, the next boot skips `+0-1.conf` and boots known-good `default`.
//!    - Upon `CommitWave`, promotes `+0-1.conf -> .conf` and updates `loader.conf` default.

use crate::schema::EpochError;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

// Linux watchdog ioctl constants (<linux/watchdog.h>)
const WDIOC_KEEPALIVE: libc::c_ulong = 0x8004_5705;
const WDIOC_SETTIMEOUT: libc::c_ulong = 0xc004_5706;

/// Lock all current and future process pages in RAM (`mlockall`) and set `oom_score_adj = -1000`
/// so `epoch-agent` cannot be killed by the Linux OOM killer or swapped out during rollback.
/// Because `MCL_FUTURE` automatically locks all subsequent pages mapped by the process,
/// we execute the kernel VMA walk once per process and cache the result.
pub fn pin_agent_memory_and_oom_score() -> (bool, bool) {
    static PIN_STATE: std::sync::OnceLock<(bool, bool)> = std::sync::OnceLock::new();
    *PIN_STATE.get_or_init(|| {
        let mlocked = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 };
        let oom_adjusted = fs::write("/proc/self/oom_score_adj", b"-1000\n").is_ok();
        (mlocked, oom_adjusted)
    })
}

/// Layer 1: Hardware `/dev/watchdog` controller.
#[derive(Debug)]
pub struct HardwareWatchdog {
    file: Option<File>,
    pub timeout_secs: i32,
    pub armed: bool,
    pub keepalive_count: u64,
}

impl HardwareWatchdog {
    pub fn arm(watchdog_path: &Path, timeout_secs: i32) -> Self {
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(watchdog_path)
            .ok();
        if let Some(ref f) = file {
            let mut t = timeout_secs as libc::c_int;
            unsafe {
                let _ = libc::ioctl(f.as_raw_fd(), WDIOC_SETTIMEOUT, &mut t);
            }
        }
        Self {
            file,
            timeout_secs,
            armed: true,
            keepalive_count: 0,
        }
    }

    pub fn ping_keepalive(&mut self) -> bool {
        if !self.armed {
            return false;
        }
        self.keepalive_count += 1;
        if let Some(ref mut f) = self.file {
            unsafe {
                let mut dummy: libc::c_int = 0;
                let _ = libc::ioctl(f.as_raw_fd(), WDIOC_KEEPALIVE, &mut dummy);
            }
        }
        true
    }

    /// Disarm the hardware watchdog using the standard Linux magic close character `'V'`.
    pub fn disarm(&mut self) {
        if self.armed {
            if let Some(mut f) = self.file.take() {
                let _ = f.write_all(b"V");
                let _ = f.flush();
            }
            self.armed = false;
        }
    }
}

impl Drop for HardwareWatchdog {
    fn drop(&mut self) {
        self.disarm();
    }
}

/// Layer 2: Initialize `/boot/loader/loader.conf` and known-good default entry for generation `gen_id`.
pub fn init_systemd_boot_layout(
    boot_root: &Path,
    gen_id: u64,
    toplevel_path: &str,
    kernel_path: &str,
    initrd_path: &str,
) -> Result<(), EpochError> {
    let entries_dir = boot_root.join("loader").join("entries");
    fs::create_dir_all(&entries_dir)?;

    let loader_conf = boot_root.join("loader").join("loader.conf");
    let default_entry = format!("nixos-generation-{gen_id}.conf");
    fs::write(
        &loader_conf,
        format!("timeout 3\ndefault {default_entry}\n"),
    )?;

    let entry_path = entries_dir.join(&default_entry);
    let content = format!(
        "title NixOS Generation {gen_id}\nlinux {kernel_path}\ninitrd {initrd_path}\noptions init={toplevel_path}/init\n"
    );
    fs::write(entry_path, content)?;
    Ok(())
}

/// Layer 2: Stage a single-trial `systemd-boot` entry (`nixos-generation-<tx_epoch>+1-0.conf`)
/// and set the `LoaderEntryOneShot` EFI variable WITHOUT modifying `loader.conf` default.
pub fn arm_systemd_boot_single_trial(
    boot_root: &Path,
    efivars_dir: &Path,
    tx_epoch: u64,
    staged_toplevel: &str,
    kernel_path: &str,
    initrd_path: &str,
) -> Result<PathBuf, EpochError> {
    let entries_dir = boot_root.join("loader").join("entries");
    fs::create_dir_all(&entries_dir)?;
    let _ = fs::create_dir_all(efivars_dir);

    let trial_name = format!("nixos-generation-{tx_epoch}+1-0.conf");
    let trial_path = entries_dir.join(&trial_name);
    let content = format!(
        "title NixOS Trial Generation {tx_epoch}\nlinux {kernel_path}\ninitrd {initrd_path}\noptions init={staged_toplevel}/init\n"
    );
    {
        let mut f = File::create(&trial_path)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }

    if efivars_dir.exists() {
        let oneshot_var =
            efivars_dir.join("LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f");
        if let Ok(mut f) = File::create(&oneshot_var) {
            let _ = f.write_all(format!("{trial_name}\0").as_bytes());
            let _ = f.sync_all();
        }
    }

    Ok(trial_path)
}

/// Simulate UEFI `systemd-boot` boot entry selection & boot-counter decrement across a reboot.
/// Returns `(selected_entry_filename, booted_toplevel_path, booted_kernel_path)`.
pub fn simulate_systemd_boot_select(
    boot_root: &Path,
    efivars_dir: &Path,
) -> Result<(String, String, String), EpochError> {
    let entries_dir = boot_root.join("loader").join("entries");
    let oneshot_var = efivars_dir.join("LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f");

    // 1. Check if a `+1-0.conf` single-trial entry exists (either via LoaderEntryOneShot or entries scan)
    if let Ok(entries) = fs::read_dir(&entries_dir) {
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();

        for name in names {
            if let Some(prefix) = name.strip_suffix("+1-0.conf") {
                // Decrement +1-0.conf -> +0-1.conf BEFORE jumping to kernel (exact systemd-boot behavior)
                let old_path = entries_dir.join(&name);
                let exhausted_name = format!("{prefix}+0-1.conf");
                let new_path = entries_dir.join(&exhausted_name);
                let content = fs::read_to_string(&old_path)?;
                fs::rename(&old_path, &new_path)?;
                let _ = fs::remove_file(&oneshot_var);
                let (toplevel, kernel) = parse_boot_entry_paths(&content);
                return Ok((exhausted_name, toplevel, kernel));
            }
        }
    }

    // 2. Otherwise (or if only `+0-1.conf` with 0 tries left exists), boot `default` from `loader.conf`!
    let loader_conf = fs::read_to_string(boot_root.join("loader").join("loader.conf"))?;
    let default_name = loader_conf
        .lines()
        .find_map(|l| l.strip_prefix("default ").map(|s| s.trim().to_owned()))
        .ok_or_else(|| EpochError::Io("missing default in loader.conf".into()))?;

    let default_content = fs::read_to_string(entries_dir.join(&default_name))?;
    let (toplevel, kernel) = parse_boot_entry_paths(&default_content);
    Ok((default_name, toplevel, kernel))
}

fn parse_boot_entry_paths(content: &str) -> (String, String) {
    let mut toplevel = String::new();
    let mut kernel = String::new();
    for line in content.lines() {
        if let Some(k) = line.strip_prefix("linux ") {
            kernel = k.trim().to_owned();
        } else if let Some(opts) = line.strip_prefix("options ") {
            for tok in opts.split_whitespace() {
                if let Some(init_path) = tok.strip_prefix("init=")
                    && let Some(tl) = init_path.strip_suffix("/init")
                {
                    toplevel = tl.to_owned();
                }
            }
        }
    }
    (toplevel, kernel)
}

/// Promote a succeeded trial boot entry (`+0-1.conf` or `+1-0.conf`) to permanent `.conf`
/// or write a fresh permanent `.conf` for non-reboot deployments, and update `/boot/loader/loader.conf`
/// `default` upon `CommitWave`.
pub fn promote_or_write_systemd_boot_permanent(
    boot_root: &Path,
    tx_epoch: u64,
    staged_toplevel: &str,
    kernel_path: &str,
    initrd_path: &str,
) -> Result<(), EpochError> {
    let entries_dir = boot_root.join("loader").join("entries");
    fs::create_dir_all(&entries_dir)?;
    let perm_name = format!("nixos-generation-{tx_epoch}.conf");
    let perm_path = entries_dir.join(&perm_name);

    for suffix in ["+0-1.conf", "+1-0.conf"] {
        let candidate = entries_dir.join(format!("nixos-generation-{tx_epoch}{suffix}"));
        if candidate.exists() {
            fs::rename(&candidate, &perm_path)?;
        }
    }

    if !perm_path.exists() {
        let content = format!(
            "title NixOS Generation {tx_epoch}\nlinux {kernel_path}\ninitrd {initrd_path}\noptions init={staged_toplevel}/init\n"
        );
        let mut f = File::create(&perm_path)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }

    let loader_conf = boot_root.join("loader").join("loader.conf");
    let mut f = File::create(&loader_conf)?;
    f.write_all(format!("timeout 3\ndefault {perm_name}\n").as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Promote a succeeded trial boot entry (`+0-1.conf` or `+1-0.conf`) to permanent `.conf`
/// and update `/boot/loader/loader.conf` `default` upon `CommitWave`.
pub fn promote_systemd_boot_trial_to_permanent(
    boot_root: &Path,
    tx_epoch: u64,
) -> Result<(), EpochError> {
    let entries_dir = boot_root.join("loader").join("entries");
    if !entries_dir.exists() {
        return Ok(());
    }
    let perm_name = format!("nixos-generation-{tx_epoch}.conf");
    let perm_path = entries_dir.join(&perm_name);

    for suffix in ["+0-1.conf", "+1-0.conf"] {
        let candidate = entries_dir.join(format!("nixos-generation-{tx_epoch}{suffix}"));
        if candidate.exists() {
            fs::rename(&candidate, &perm_path)?;
        }
    }

    if perm_path.exists() {
        let loader_conf = boot_root.join("loader").join("loader.conf");
        fs::write(&loader_conf, format!("timeout 3\ndefault {perm_name}\n"))?;
    }
    Ok(())
}

/// Remove any exhausted/aborted trial boot entries (`nixos-generation-*+*.conf`) on rollback.
pub fn cleanup_failed_systemd_boot_trials(
    boot_root: &Path,
    efivars_dir: &Path,
) -> Result<usize, EpochError> {
    let mut removed = 0usize;
    let entries_dir = boot_root.join("loader").join("entries");
    if let Ok(entries) = fs::read_dir(&entries_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains('+') && name.ends_with(".conf") {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
    }
    let oneshot_var = efivars_dir.join("LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f");
    if oneshot_var.exists() {
        let _ = fs::remove_file(oneshot_var);
    }
    Ok(removed)
}
