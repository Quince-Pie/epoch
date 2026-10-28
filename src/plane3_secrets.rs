//! Plane 3: Zero-Trust Ephemeral Secret & Hardware Identity Plane
//!
//! Implements:
//! 1. Unswappable kernel `ramfs` mount (`/run/epoch/secrets`, `MS_NOSUID | MS_NODEV | MS_NOEXEC`, mode `0700`).
//! 2. `PREPARE`-phase unsealing of `/node-overlay/epoch-secrets.cbor` into `/run/epoch/secrets/gen-<tx_epoch>`
//!    with `/etc/passwd` & `/etc/group` UID/GID resolution and `ChaCha20-Poly1305` AAD verification.
//! 3. Zero-window atomic symlink exchange on `/run/epoch/current-secrets` via `syscall(SYS_renameat2, ..., RENAME_EXCHANGE)`.
//! 4. Cryptographic zeroization (`explicit_bzero` + `0x00` page-cache overwrite + `unlink` + `rmdir`) of retired
//!    secret generations on `COMMITTED` or `ROLLED_BACK`.
//! 5. 100% coordinator-free Stage-2 early-boot unsealing (`unseal-boot`) from `/run/booted-system`.

use crate::cbor;
use crate::crypto::{Ed25519Identity, unseal_secret_bundle, zero_wipe_and_unlink_file};
use crate::schema::{EpochError, SecretEntry, SecretEnvelopeBundle};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

/// Ensure `/run/epoch/secrets` is mounted as an unswappable kernel `ramfs` (`0700`).
/// Returns `Ok(true)` if kernel `mount("ramfs")` succeeded, or `Ok(false)` if running
/// unprivileged (where the directory is still created with mode `0700`).
pub fn ensure_ramfs_secrets_mount(ramfs_root: &Path) -> Result<bool, EpochError> {
    fs::create_dir_all(ramfs_root)?;
    fs::set_permissions(ramfs_root, fs::Permissions::from_mode(0o700))?;

    let mut mounted_ramfs = false;
    if unsafe { libc::geteuid() } == 0 {
        let src = CString::new("epoch-secrets").unwrap();
        let target = CString::new(ramfs_root.as_os_str().as_bytes())
            .map_err(|e| EpochError::Io(e.to_string()))?;
        let fstype = CString::new("ramfs").unwrap();
        let flags = (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong;
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                flags,
                std::ptr::null(),
            )
        };
        if rc == 0 {
            mounted_ramfs = true;
            let _ = fs::set_permissions(ramfs_root, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(mounted_ramfs)
}

/// Resolve username/groupname from `<staged_toplevel>/etc/passwd` and `<staged_toplevel>/etc/group`
/// if present.
pub fn resolve_uid_gid_from_toplevel(
    staged_toplevel: &Path,
    user: &str,
    group: &str,
) -> (Option<u32>, Option<u32>) {
    let passwd_path = staged_toplevel.join("etc/passwd");
    let group_path = staged_toplevel.join("etc/group");

    let uid = fs::read_to_string(passwd_path).ok().and_then(|content| {
        for line in content.lines() {
            let mut parts = line.split(':');
            let name = parts.next()?;
            let _pw = parts.next()?;
            let uid_str = parts.next()?;
            if name == user {
                return uid_str.parse::<u32>().ok();
            }
        }
        None
    });

    let gid = fs::read_to_string(group_path).ok().and_then(|content| {
        for line in content.lines() {
            let mut parts = line.split(':');
            let name = parts.next()?;
            let _pw = parts.next()?;
            let gid_str = parts.next()?;
            if name == group {
                return gid_str.parse::<u32>().ok();
            }
        }
        None
    });

    (uid, gid)
}

/// Phase 1 (`PREPARE`): Unseal `$staged_toplevel/node-overlay/epoch-secrets.cbor` into
/// `<ramfs_root>/gen-<tx_epoch>` (`0700`) without mutating `/run/epoch/current-secrets`.
pub fn prepare_generation_secrets(
    staged_toplevel: &Path,
    ramfs_root: &Path,
    tx_epoch: u64,
    expected_node_id: &str,
    expected_archetype_toplevel: &str,
    host_key: &Ed25519Identity,
    tpm2_pcr_state: Option<(u32, &[u8; 32])>,
) -> Result<PathBuf, EpochError> {
    ensure_ramfs_secrets_mount(ramfs_root)?;

    let envelope_path = staged_toplevel
        .join("node-overlay")
        .join("epoch-secrets.cbor");
    let envelope_bytes = fs::read(&envelope_path).map_err(|e| EpochError::SecretUnsealFailed {
        node_id: expected_node_id.to_owned(),
        reason: format!("failed to read {}: {e}", envelope_path.display()),
    })?;
    let bundle: SecretEnvelopeBundle =
        cbor::from_slice(&envelope_bytes).map_err(|e| EpochError::SecretUnsealFailed {
            node_id: expected_node_id.to_owned(),
            reason: format!("invalid CBOR in epoch-secrets.cbor: {e}"),
        })?;

    prepare_generation_secrets_from_bundle(
        staged_toplevel,
        ramfs_root,
        tx_epoch,
        &bundle,
        expected_node_id,
        expected_archetype_toplevel,
        host_key,
        tpm2_pcr_state,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_generation_secrets_from_bundle(
    staged_toplevel: &Path,
    ramfs_root: &Path,
    tx_epoch: u64,
    bundle: &SecretEnvelopeBundle,
    expected_node_id: &str,
    expected_archetype_toplevel: &str,
    host_key: &Ed25519Identity,
    tpm2_pcr_state: Option<(u32, &[u8; 32])>,
) -> Result<PathBuf, EpochError> {
    let _zone = crate::tracy_zone!("plane3::prepare_generation_secrets", 0xa855f7);
    ensure_ramfs_secrets_mount(ramfs_root)?;

    let entries: Vec<SecretEntry> = unseal_secret_bundle(
        bundle,
        expected_node_id,
        expected_archetype_toplevel,
        host_key,
        tpm2_pcr_state,
    )?;

    let gen_dir = ramfs_root.join(format!("gen-{tx_epoch}"));
    if gen_dir.exists() {
        zero_wipe_secret_generation(ramfs_root, tx_epoch)?;
    }
    fs::create_dir_all(&gen_dir)?;
    fs::set_permissions(&gen_dir, fs::Permissions::from_mode(0o700))?;

    for entry in &entries {
        if entry.name.is_empty()
            || entry.name.contains('/')
            || entry.name == "."
            || entry.name == ".."
        {
            return Err(EpochError::SecretUnsealFailed {
                node_id: expected_node_id.to_owned(),
                reason: format!("unsafe secret filename '{}'", entry.name),
            });
        }
        let secret_path = gen_dir.join(&entry.name);
        {
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&secret_path)?;
            f.write_all(&entry.plaintext)?;
            f.set_permissions(fs::Permissions::from_mode(entry.mode & 0o777))?;
            f.sync_all()?;
        }
        if unsafe { libc::geteuid() } == 0 {
            let (uid_opt, gid_opt) = resolve_uid_gid_from_toplevel(
                staged_toplevel,
                &entry.owner_user,
                &entry.owner_group,
            );
            if (uid_opt.is_some() || gid_opt.is_some())
                && let Ok(c_path) = CString::new(secret_path.as_os_str().as_bytes())
            {
                unsafe {
                    libc::chown(
                        c_path.as_ptr(),
                        uid_opt.unwrap_or(u32::MAX),
                        gid_opt.unwrap_or(u32::MAX),
                    );
                }
            }
        }
    }

    // Sync the generation directory
    if let Ok(dir_file) = fs::File::open(&gen_dir) {
        let _ = dir_file.sync_all();
    }

    Ok(gen_dir)
}

/// Prepare an empty `<ramfs_root>/gen-<tx_epoch>` (`0700`) directory when a node's signed plan
/// declares no secret envelope (`secrets_envelope_hash == [0u8; 32]`).
pub fn prepare_empty_generation_secrets(
    ramfs_root: &Path,
    tx_epoch: u64,
) -> Result<PathBuf, EpochError> {
    ensure_ramfs_secrets_mount(ramfs_root)?;
    let gen_dir = ramfs_root.join(format!("gen-{tx_epoch}"));
    if gen_dir.exists() {
        zero_wipe_secret_generation(ramfs_root, tx_epoch)?;
    }
    fs::create_dir_all(&gen_dir)?;
    fs::set_permissions(&gen_dir, fs::Permissions::from_mode(0o700))?;
    if let Ok(dir_file) = fs::File::open(&gen_dir) {
        let _ = dir_file.sync_all();
    }
    Ok(gen_dir)
}

/// Phase 2 (`ACTIVATING`): Atomically flip `<current_secrets_link>` to point to
/// `<ramfs_root>/gen-<target_epoch>` using Linux `syscall(SYS_renameat2, ..., RENAME_EXCHANGE)`.
///
/// Guarantees a 0-microsecond window where `<current_secrets_link>` is missing (`ENOENT`).
pub fn atomic_flip_current_secrets(
    current_secrets_link: &Path,
    ramfs_root: &Path,
    target_epoch: u64,
) -> Result<PathBuf, EpochError> {
    let _zone = crate::tracy_zone!("plane3::atomic_flip_current_secrets", 0x9333ea);
    let target_gen_dir = ramfs_root.join(format!("gen-{target_epoch}"));
    if !target_gen_dir.exists() {
        return Err(EpochError::SecretUnsealFailed {
            node_id: "local".into(),
            reason: format!(
                "target secret generation directory {} does not exist",
                target_gen_dir.display()
            ),
        });
    }

    if let Some(parent) = current_secrets_link.parent() {
        fs::create_dir_all(parent)?;
    }

    let next_link = current_secrets_link.with_extension("next");
    if fs::symlink_metadata(&next_link).is_ok() {
        let _ = fs::remove_file(&next_link);
    }
    symlink(&target_gen_dir, &next_link)?;

    if fs::symlink_metadata(current_secrets_link).is_ok() {
        let next_c = CString::new(next_link.as_os_str().as_bytes())
            .map_err(|e| EpochError::Io(e.to_string()))?;
        let curr_c = CString::new(current_secrets_link.as_os_str().as_bytes())
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
            // `next_link` now holds the old symlink after atomic exchange; remove it cleanly.
            let _ = fs::remove_file(&next_link);
        } else {
            // Fallback to atomic POSIX `rename()` if the underlying filesystem doesn't support RENAME_EXCHANGE
            fs::rename(&next_link, current_secrets_link)?;
        }
    } else {
        // First activation: atomic POSIX rename into place
        fs::rename(&next_link, current_secrets_link)?;
    }

    Ok(target_gen_dir)
}

/// Phase 3 (`COMMITTED` or `ROLLED_BACK`): Cryptographically zero-wipe (`explicit_bzero` + `0x00` write)
/// and unlink all files in `<ramfs_root>/gen-<retired_epoch>`, then remove the directory.
pub fn zero_wipe_secret_generation(
    ramfs_root: &Path,
    retired_epoch: u64,
) -> Result<(), EpochError> {
    let gen_dir = ramfs_root.join(format!("gen-{retired_epoch}"));
    if !gen_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&gen_dir)? {
        let entry = entry?;
        zero_wipe_and_unlink_file(&entry.path())?;
    }
    fs::remove_dir(&gen_dir)?;
    Ok(())
}

/// Plane 3.3: 100% Coordinator-Free Early-Boot (`initrd` & Stage 2) Unsealing (`epoch-agent unseal-boot`).
/// Reads `<booted_system_root>/node-overlay/epoch-secrets.cbor`, unseals via local TPM2 / host key
/// into `<ramfs_root>/gen-<boot_epoch>`, and atomically points `<current_secrets_link>` to it.
#[allow(clippy::too_many_arguments)]
pub fn unseal_boot_secrets(
    booted_system_root: &Path,
    ramfs_root: &Path,
    current_secrets_link: &Path,
    boot_epoch: u64,
    expected_node_id: &str,
    expected_archetype_toplevel: &str,
    host_key: &Ed25519Identity,
    tpm2_pcr_state: Option<(u32, &[u8; 32])>,
) -> Result<PathBuf, EpochError> {
    let gen_dir = prepare_generation_secrets(
        booted_system_root,
        ramfs_root,
        boot_epoch,
        expected_node_id,
        expected_archetype_toplevel,
        host_key,
        tpm2_pcr_state,
    )?;
    atomic_flip_current_secrets(current_secrets_link, ramfs_root, boot_epoch)?;
    Ok(gen_dir)
}
