//! Plane 2: Closure Distribution & Store Transport Plane
//!
//! Implements:
//! 1. Canonical Nix Archive (`nix-archive-1`) serializer and atomic read-only unpacker.
//! 2. Bijective length-preserving 32-byte store-hash normalizer (`\x00EPOCH_REF_<hex_u16>_________________`).
//! 3. Gear-based Normalized FastCDC chunker ($c_{\min}=16\text{ KiB}, c_{\text{avg}}=64\text{ KiB}, c_{\max}=256\text{ KiB}$)
//!    + `libzstd` (`zstd -3`) compression FFI.
//! 4. Target-local `ChunkIndex` for zero-network reconstruction of deduplicated chunks.
//! 5. `libc::statvfs` byte & inode quota guard, `libsqlite3` `/nix/var/nix/db/db.sqlite` registration,
//!    and isolated `/nix/var/nix/gcroots/epoch/staging/tx-<tx_epoch>` GC root management.

use crate::cbor;
use crate::crypto::{
    Ed25519Identity, sha256_digest, sign_nix_store_path, verify_nix_store_path_sig,
};
use crate::schema::{Blake3Hash, ChunkDescriptor, Ed25519Pub, EpochError, NarChunkManifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const FASTCDC_MIN_SIZE: usize = 16 * 1024;
pub const FASTCDC_AVG_SIZE: usize = 64 * 1024;
pub const FASTCDC_MAX_SIZE: usize = 256 * 1024;

// Direct FFI to libzstd (`-lzstd`) and libsqlite3 (`-lsqlite3`)
unsafe extern "C" {
    fn ZSTD_compressBound(srcSize: usize) -> usize;
    fn ZSTD_compress(
        dst: *mut libc::c_void,
        dstCapacity: usize,
        src: *const libc::c_void,
        srcSize: usize,
        compressionLevel: libc::c_int,
    ) -> usize;
    fn ZSTD_decompress(
        dst: *mut libc::c_void,
        dstCapacity: usize,
        src: *const libc::c_void,
        compressedSize: usize,
    ) -> usize;
    fn ZSTD_isError(code: usize) -> libc::c_uint;

    fn sqlite3_open(filename: *const libc::c_char, ppDb: *mut *mut libc::c_void) -> libc::c_int;
    fn sqlite3_exec(
        db: *mut libc::c_void,
        sql: *const libc::c_char,
        callback: Option<
            unsafe extern "C" fn(
                *mut libc::c_void,
                libc::c_int,
                *mut *mut libc::c_char,
                *mut *mut libc::c_char,
            ) -> libc::c_int,
        >,
        arg: *mut libc::c_void,
        errmsg: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sqlite3_free(ptr: *mut libc::c_void);
    fn sqlite3_close(db: *mut libc::c_void) -> libc::c_int;
}

/// Compress bytes with `libzstd` at level 3 (`zstd -3`).
pub fn zstd_compress(raw: &[u8]) -> Result<Vec<u8>, EpochError> {
    unsafe {
        let cap = ZSTD_compressBound(raw.len());
        let mut out = Vec::with_capacity(cap);
        let written = ZSTD_compress(
            out.as_mut_ptr() as *mut libc::c_void,
            cap,
            raw.as_ptr() as *const libc::c_void,
            raw.len(),
            3,
        );
        if ZSTD_isError(written) != 0 || written > cap {
            return Err(EpochError::Io("ZSTD_compress failed".into()));
        }
        out.set_len(written);
        Ok(out)
    }
}

/// Decompress `zstd` frame into exact `expected_raw_len` bytes without redundant zero-initialization.
pub fn zstd_decompress(compressed: &[u8], expected_raw_len: usize) -> Result<Vec<u8>, EpochError> {
    unsafe {
        let mut out = Vec::with_capacity(expected_raw_len);
        let decoded = ZSTD_decompress(
            out.as_mut_ptr() as *mut libc::c_void,
            expected_raw_len,
            compressed.as_ptr() as *const libc::c_void,
            compressed.len(),
        );
        if ZSTD_isError(decoded) != 0 || decoded != expected_raw_len {
            return Err(EpochError::Io(format!(
                "ZSTD_decompress failed or length mismatch (got {decoded}, expected {expected_raw_len})"
            )));
        }
        out.set_len(decoded);
        Ok(out)
    }
}

/// Decompress a `zstd` frame up to `max_raw_len` bytes, returning the exact decompressed slice.
pub fn zstd_decompress_bounded(
    compressed: &[u8],
    max_raw_len: usize,
) -> Result<Vec<u8>, EpochError> {
    unsafe {
        let mut out = Vec::with_capacity(max_raw_len);
        let decoded = ZSTD_decompress(
            out.as_mut_ptr() as *mut libc::c_void,
            max_raw_len,
            compressed.as_ptr() as *const libc::c_void,
            compressed.len(),
        );
        if ZSTD_isError(decoded) != 0 || decoded > max_raw_len {
            return Err(EpochError::Io(format!(
                "ZSTD_decompress failed (code={decoded}, max_raw_len={max_raw_len})"
            )));
        }
        out.set_len(decoded);
        Ok(out)
    }
}

// Canonical Nix Archive (`nix-archive-1`) Serializer and Unpacker

fn write_nar_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u64;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
    let pad = (8 - (data.len() % 8)) % 8;
    if pad > 0 {
        buf.extend_from_slice(&[0u8; 8][..pad]);
    }
}

fn serialize_nar_node(path: &Path, buf: &mut Vec<u8>) -> Result<(), EpochError> {
    let meta = fs::symlink_metadata(path)?;
    let ft = meta.file_type();

    write_nar_bytes(buf, b"(");
    write_nar_bytes(buf, b"type");

    if ft.is_symlink() {
        write_nar_bytes(buf, b"symlink");
        write_nar_bytes(buf, b"target");
        let target = fs::read_link(path)?;
        write_nar_bytes(buf, target.as_os_str().as_bytes());
        write_nar_bytes(buf, b")");
    } else if ft.is_file() {
        write_nar_bytes(buf, b"regular");
        if (meta.permissions().mode() & 0o111) != 0 {
            write_nar_bytes(buf, b"executable");
            write_nar_bytes(buf, b"");
        }
        write_nar_bytes(buf, b"contents");
        let expected_len = meta.len() as usize;
        buf.reserve(8 + expected_len + 16);
        let len_pos = buf.len();
        buf.extend_from_slice(&0u64.to_le_bytes());
        let start_pos = buf.len();
        let mut f = fs::File::open(path)?;
        std::io::Read::read_to_end(&mut f, buf)?;
        let actual_len = buf.len() - start_pos;
        buf[len_pos..len_pos + 8].copy_from_slice(&(actual_len as u64).to_le_bytes());
        let pad = (8 - (actual_len % 8)) % 8;
        if pad > 0 {
            buf.extend_from_slice(&[0u8; 8][..pad]);
        }
        write_nar_bytes(buf, b")");
    } else if ft.is_dir() {
        write_nar_bytes(buf, b"directory");
        let mut entries: Vec<(Vec<u8>, PathBuf)> = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            entries.push((entry.file_name().as_bytes().to_vec(), entry.path()));
        }
        // NAR specification requires strictly sorted directory entry names
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name_bytes, child_path) in entries {
            write_nar_bytes(buf, b"entry");
            write_nar_bytes(buf, b"(");
            write_nar_bytes(buf, b"name");
            write_nar_bytes(buf, &name_bytes);
            write_nar_bytes(buf, b"node");
            serialize_nar_node(&child_path, buf)?;
            write_nar_bytes(buf, b")");
        }
        write_nar_bytes(buf, b")");
    } else {
        return Err(EpochError::Io(format!(
            "unsupported file type in NAR serialization: {}",
            path.display()
        )));
    }
    Ok(())
}

/// Serialize a filesystem path into a canonical `nix-archive-1` byte stream.
pub fn serialize_nar(path: &Path) -> Result<Vec<u8>, EpochError> {
    let _zone = crate::tracy_zone!("plane2::serialize_nar", 0x10b981);
    let mut buf = Vec::with_capacity(4096);
    write_nar_bytes(&mut buf, b"nix-archive-1");
    serialize_nar_node(path, &mut buf)?;
    _zone.value(buf.len() as u64);
    Ok(buf)
}

fn read_nar_token<'a>(nar: &'a [u8], pos: &mut usize) -> Result<&'a [u8], EpochError> {
    if nar.len().saturating_sub(*pos) < 8 {
        return Err(EpochError::Io(
            "unexpected EOF reading NAR token length".into(),
        ));
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&nar[*pos..*pos + 8]);
    let raw_len = u64::from_le_bytes(len_bytes);
    let len = usize::try_from(raw_len)
        .map_err(|_| EpochError::Io("NAR token length overflows usize".into()))?;
    *pos += 8;
    if nar.len().saturating_sub(*pos) < len {
        return Err(EpochError::Io(
            "unexpected EOF reading NAR token payload".into(),
        ));
    }
    let slice = &nar[*pos..*pos + len];
    let pad = (8 - (len % 8)) % 8;
    let total_advance = len
        .checked_add(pad)
        .ok_or_else(|| EpochError::Io("NAR token length + padding overflow".into()))?;
    if nar.len().saturating_sub(*pos) < total_advance {
        return Err(EpochError::Io("unexpected EOF in NAR token padding".into()));
    }
    for &b in &nar[*pos + len..*pos + total_advance] {
        if b != 0 {
            return Err(EpochError::Io("non-zero padding byte in NAR stream".into()));
        }
    }
    *pos += total_advance;
    Ok(slice)
}

fn expect_nar_token(nar: &[u8], pos: &mut usize, expected: &[u8]) -> Result<(), EpochError> {
    let tok = read_nar_token(nar, pos)?;
    if tok != expected {
        return Err(EpochError::Io(format!(
            "expected NAR token {:?}, got {:?}",
            String::from_utf8_lossy(expected),
            String::from_utf8_lossy(tok)
        )));
    }
    Ok(())
}

const STORE_TIMESPEC_ONE: [libc::timespec; 2] = [
    libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    },
    libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    },
];

/// Normalize a store object's `atime` and `mtime` to `1` (`1970-01-01T00:00:01Z`) without following symlinks.
fn set_store_mtime_one(path: &Path) -> Result<(), EpochError> {
    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|e| EpochError::Io(e.to_string()))?;
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            STORE_TIMESPEC_ONE.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(EpochError::Io(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

/// Normalize an open file descriptor's `atime` and `mtime` to `1` without path lookup or CString allocation.
#[inline]
fn set_fd_mtime_one(fd: libc::c_int) -> Result<(), EpochError> {
    let rc = unsafe { libc::futimens(fd, STORE_TIMESPEC_ONE.as_ptr()) };
    if rc != 0 {
        return Err(EpochError::Io(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

fn unpack_nar_node(nar: &[u8], pos: &mut usize, dst: &Path) -> Result<(), EpochError> {
    expect_nar_token(nar, pos, b"(")?;
    expect_nar_token(nar, pos, b"type")?;
    let node_type = read_nar_token(nar, pos)?;

    match node_type {
        b"regular" => {
            let next = read_nar_token(nar, pos)?;
            let (executable, contents) = if next == b"executable" {
                expect_nar_token(nar, pos, b"")?;
                expect_nar_token(nar, pos, b"contents")?;
                (true, read_nar_token(nar, pos)?)
            } else if next == b"contents" {
                (false, read_nar_token(nar, pos)?)
            } else {
                return Err(EpochError::Io(
                    "unexpected token in NAR regular file".into(),
                ));
            };
            expect_nar_token(nar, pos, b")")?;
            let mut file = fs::File::create(dst)?;
            file.write_all(contents)?;
            let mode = if executable { 0o555 } else { 0o444 };
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            set_fd_mtime_one(std::os::unix::io::AsRawFd::as_raw_fd(&file))?;
            file.sync_all()?;
        }
        b"symlink" => {
            expect_nar_token(nar, pos, b"target")?;
            let target_bytes = read_nar_token(nar, pos)?;
            expect_nar_token(nar, pos, b")")?;
            let target_os = std::ffi::OsStr::from_bytes(target_bytes);
            symlink(target_os, dst)?;
            set_store_mtime_one(dst)?;
        }
        b"directory" => {
            fs::create_dir_all(dst)?;
            loop {
                let tok = read_nar_token(nar, pos)?;
                if tok == b")" {
                    break;
                }
                if tok != b"entry" {
                    return Err(EpochError::Io(
                        "expected 'entry' or ')' in NAR directory".into(),
                    ));
                }
                expect_nar_token(nar, pos, b"(")?;
                expect_nar_token(nar, pos, b"name")?;
                let name_bytes = read_nar_token(nar, pos)?;
                if name_bytes.is_empty()
                    || name_bytes == b"."
                    || name_bytes == b".."
                    || name_bytes.contains(&b'/')
                    || name_bytes.contains(&0)
                {
                    return Err(EpochError::Io("unsafe NAR directory entry name".into()));
                }
                let name_os = std::ffi::OsStr::from_bytes(name_bytes);
                expect_nar_token(nar, pos, b"node")?;
                unpack_nar_node(nar, pos, &dst.join(name_os))?;
                expect_nar_token(nar, pos, b")")?;
            }
            fs::set_permissions(dst, fs::Permissions::from_mode(0o555))?;
            set_store_mtime_one(dst)?;
        }
        other => {
            return Err(EpochError::Io(format!(
                "unknown NAR node type {:?}",
                String::from_utf8_lossy(other)
            )));
        }
    }
    Ok(())
}

/// Unpack a canonical `nix-archive-1` stream into `dst`.
pub fn unpack_nar(nar: &[u8], dst: &Path) -> Result<(), EpochError> {
    let _zone = crate::tracy_zone!("plane2::unpack_nar", 0x059669);
    _zone.value(nar.len() as u64);
    let mut pos = 0;
    expect_nar_token(nar, &mut pos, b"nix-archive-1")?;
    unpack_nar_node(nar, &mut pos, dst)?;
    if pos != nar.len() {
        return Err(EpochError::Io("trailing bytes after NAR stream".into()));
    }
    Ok(())
}

// Plane 2.1: Bijective 32-Byte Store-Hash Normalizer (LUT + In-Place Zero-Copy)

const TOKEN_PREFIX: &[u8; 11] = b"\x00EPOCH_REF_";
const TOKEN_SUFFIX: &[u8; 17] = b"_________________";

const fn build_nix_base32_lut() -> [bool; 256] {
    let mut lut = [false; 256];
    let mut b = 0usize;
    while b < 256 {
        let c = b as u8;
        lut[b] = (c >= b'0' && c <= b'9')
            || (c >= b'a' && c <= b'd')
            || (c >= b'f' && c <= b'n')
            || (c >= b'p' && c <= b's')
            || (c >= b'v' && c <= b'z');
        b += 1;
    }
    lut
}

const fn build_hex_nibble_lut() -> [u8; 256] {
    let mut lut = [0xffu8; 256];
    let mut b = 0usize;
    while b < 256 {
        let c = b as u8;
        if c >= b'0' && c <= b'9' {
            lut[b] = c - b'0';
        } else if c >= b'A' && c <= b'F' {
            lut[b] = c - b'A' + 10;
        } else if c >= b'a' && c <= b'f' {
            lut[b] = c - b'a' + 10;
        }
        b += 1;
    }
    lut
}

const NIX_BASE32_LUT: [bool; 256] = build_nix_base32_lut();
const HEX_NIBBLE_LUT: [u8; 256] = build_hex_nibble_lut();

#[inline(always)]
pub const fn is_nix_base32_char(b: u8) -> bool {
    NIX_BASE32_LUT[b as usize]
}

/// Construct the exact 32-byte canonical reference token:
/// `\x00EPOCH_REF_<hex_u16(idx)>_________________` (11 + 4 + 17 = 32 bytes) on the stack with zero heap allocations.
#[inline(always)]
pub const fn make_ref_token(idx: u16) -> [u8; 32] {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut tok = *b"\x00EPOCH_REF_0000_________________";
    tok[11] = HEX_UPPER[((idx >> 12) & 0x0f) as usize];
    tok[12] = HEX_UPPER[((idx >> 8) & 0x0f) as usize];
    tok[13] = HEX_UPPER[((idx >> 4) & 0x0f) as usize];
    tok[14] = HEX_UPPER[(idx & 0x0f) as usize];
    tok
}

/// Parse `\x00EPOCH_REF_<hex_u16(idx)>_________________` back into `Some(idx)` using a 256-byte nibble LUT.
#[inline(always)]
pub fn parse_ref_token(candidate: &[u8; 32]) -> Option<u16> {
    if &candidate[..11] != TOKEN_PREFIX || &candidate[15..32] != TOKEN_SUFFIX {
        return None;
    }
    let n0 = HEX_NIBBLE_LUT[candidate[11] as usize];
    let n1 = HEX_NIBBLE_LUT[candidate[12] as usize];
    let n2 = HEX_NIBBLE_LUT[candidate[13] as usize];
    let n3 = HEX_NIBBLE_LUT[candidate[14] as usize];
    if (n0 | n1 | n2 | n3) & 0xf0 != 0 {
        return None;
    }
    Some(((n0 as u16) << 12) | ((n1 as u16) << 8) | ((n2 as u16) << 4) | (n3 as u16))
}

/// In-place bijective 32-byte store-hash normalization over `buf`.
/// Scans for `/` using vectorized byte search before checking `nix/store/` and `NIX_BASE32_LUT`.
pub fn normalize_nar_store_hashes_in_place(buf: &mut [u8], reference_hashes: &[[u8; 32]]) {
    let _zone = crate::tracy_zone!("plane2::normalize_nar_store_hashes", 0x34d399);
    _zone.value(buf.len() as u64);
    if buf.len() < 43 || reference_hashes.is_empty() {
        return;
    }
    let limit = buf.len() - 43;
    let mut i = 0;
    while i <= limit {
        let Some(rel) = buf[i..=limit].iter().position(|&b| b == b'/') else {
            break;
        };
        i += rel;
        if &buf[i + 1..i + 11] == b"nix/store/" {
            let hash_slice = &buf[i + 11..i + 43];
            if hash_slice.iter().all(|&b| NIX_BASE32_LUT[b as usize]) {
                let candidate: &[u8; 32] = hash_slice.try_into().unwrap();
                if let Some(idx) = reference_hashes.iter().position(|r| r == candidate)
                    && idx <= u16::MAX as usize
                {
                    let tok = make_ref_token(idx as u16);
                    buf[i + 11..i + 43].copy_from_slice(&tok);
                    i += 43;
                    continue;
                }
            }
        }
        i += 1;
    }
}

/// Scan `nar` for `/nix/store/<32-char-nix-base32>` matching any entry in `reference_hashes`
/// and replace the 32-byte hash in-place with `make_ref_token(idx)`.
/// Preserves exact byte length and offsets across the entire NAR.
pub fn normalize_nar_store_hashes(nar: &[u8], reference_hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut out = nar.to_vec();
    normalize_nar_store_hashes_in_place(&mut out, reference_hashes);
    out
}

/// In-place inverse bijective substitution: restores `/nix/store/\x00EPOCH_REF_<idx>_________________`
/// back to `/nix/store/<reference_hashes[idx]>` without allocating a second NAR buffer.
pub fn denormalize_nar_store_hashes_in_place(
    buf: &mut [u8],
    reference_hashes: &[[u8; 32]],
) -> Result<(), EpochError> {
    let _zone = crate::tracy_zone!("plane2::denormalize_nar_store_hashes", 0x10b981);
    _zone.value(buf.len() as u64);
    if buf.len() < 43 || reference_hashes.is_empty() {
        return Ok(());
    }
    let limit = buf.len() - 43;
    let mut i = 0;
    while i <= limit {
        let Some(rel) = buf[i..=limit].iter().position(|&b| b == b'/') else {
            break;
        };
        i += rel;
        if &buf[i + 1..i + 11] == b"nix/store/" && buf[i + 11] == 0 {
            let candidate: &[u8; 32] = buf[i + 11..i + 43].try_into().unwrap();
            if let Some(idx) = parse_ref_token(candidate) {
                let idx_usize = idx as usize;
                let orig_hash = reference_hashes.get(idx_usize).ok_or_else(|| {
                    EpochError::Io(format!(
                        "EPOCH_REF token index {idx_usize} out of bounds (len {})",
                        reference_hashes.len()
                    ))
                })?;
                buf[i + 11..i + 43].copy_from_slice(orig_hash);
                i += 43;
                continue;
            }
        }
        i += 1;
    }
    Ok(())
}

/// Inverse bijective substitution: restores `/nix/store/\x00EPOCH_REF_<idx>_________________`
/// back to `/nix/store/<reference_hashes[idx]>`.
pub fn denormalize_nar_store_hashes(
    norm_nar: &[u8],
    reference_hashes: &[[u8; 32]],
) -> Result<Vec<u8>, EpochError> {
    let mut out = norm_nar.to_vec();
    denormalize_nar_store_hashes_in_place(&mut out, reference_hashes)?;
    Ok(out)
}

// Plane 2.1: Gear-Based Normalized FastCDC Segmentation

const fn generate_gear_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut i = 0;
    let mut state = 0x853c_49e6_748f_ea9bu64;
    while i < 256 {
        // SplitMix64 deterministic PRNG for the 256-entry 64-bit Gear table
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        table[i] = z ^ (z >> 31);
        i += 1;
    }
    table
}

const GEAR_TABLE: [u64; 256] = generate_gear_table();
// Two-level normalized FastCDC masks around 64 KiB (2^16):
// Small region [16 KiB, 64 KiB) uses 17-bit mask; large region [64 KiB, 256 KiB) uses 15-bit mask.
const FASTCDC_MASK_S: u64 = 0x0003_d930_0353_0000;
const FASTCDC_MASK_L: u64 = 0x0000_d900_0353_0000;

/// Segment `data` into content-defined chunks using Gear-hash Normalized FastCDC
/// ($c_{\min} = 16\text{ KiB}, c_{\text{avg}} = 64\text{ KiB}, c_{\max} = 256\text{ KiB}$).
/// Returns `(offset, len)` slices covering `data`.
pub fn fastcdc_chunk_ranges(data: &[u8]) -> Vec<(usize, usize)> {
    let _zone = crate::tracy_zone!("plane2::fastcdc_chunk_ranges", 0x6ee7b7);
    _zone.value(data.len() as u64);
    let total = data.len();
    let mut ranges = Vec::with_capacity(total / FASTCDC_AVG_SIZE + 2);
    let mut offset = 0;

    while offset < total {
        let remaining = total - offset;
        if remaining <= FASTCDC_MIN_SIZE {
            ranges.push((offset, remaining));
            break;
        }

        let max_len = remaining.min(FASTCDC_MAX_SIZE);
        let normal_end = remaining.min(FASTCDC_AVG_SIZE);
        let window = &data[offset..offset + max_len];
        let mut fp = 0u64;
        let mut cut = max_len;
        let mut found = false;

        for (rel_idx, &b) in window[FASTCDC_MIN_SIZE..normal_end].iter().enumerate() {
            fp = (fp << 1).wrapping_add(GEAR_TABLE[b as usize]);
            if (fp & FASTCDC_MASK_S) == 0 {
                cut = FASTCDC_MIN_SIZE + rel_idx;
                found = true;
                break;
            }
        }

        if !found {
            for (rel_idx, &b) in window[normal_end..max_len].iter().enumerate() {
                fp = (fp << 1).wrapping_add(GEAR_TABLE[b as usize]);
                if (fp & FASTCDC_MASK_L) == 0 {
                    cut = normal_end + rel_idx;
                    break;
                }
            }
        }

        ranges.push((offset, cut));
        offset += cut;
    }

    ranges
}

/// Extract the 32-byte Nix-base32 hash from a `/nix/store/<32-char>-<name>` path string.
pub fn extract_store_hash_32(store_path: &str) -> Option<[u8; 32]> {
    let rest = store_path.strip_prefix("/nix/store/")?;
    if rest.len() < 33 || rest.as_bytes()[32] != b'-' {
        return None;
    }
    let hash_bytes = &rest.as_bytes()[..32];
    if !hash_bytes.iter().all(|&b| is_nix_base32_char(b)) {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(hash_bytes);
    Some(out)
}

/// Extract the canonical derivation name suffix `<name>` after `/nix/store/<32-char>-`.
pub fn extract_store_name_suffix(store_path: &str) -> Option<&str> {
    let rest = store_path.strip_prefix("/nix/store/")?;
    if rest.len() < 33 || rest.as_bytes()[32] != b'-' {
        return None;
    }
    let hash_bytes = &rest.as_bytes()[..32];
    if !hash_bytes.iter().all(|&b| is_nix_base32_char(b)) {
        return None;
    }
    Some(&rest[33..])
}

/// Build a `NarChunkManifest` and map of `norm_blake3 -> zstd_compressed_chunk` for a store path on disk.
pub fn build_nar_chunk_manifest(
    disk_path: &Path,
    logical_store_path: &str,
    references_full: Vec<String>,
    deriver: Option<String>,
    signing_key_name: &str,
    signing_key: &Ed25519Identity,
) -> Result<(NarChunkManifest, BTreeMap<Blake3Hash, Vec<u8>>), EpochError> {
    let _zone = crate::tracy_zone!("plane2::build_nar_chunk_manifest", 0x059669);
    let raw_nar = serialize_nar(disk_path)?;
    let nar_size = raw_nar.len() as u64;
    let nar_sha256 = sha256_digest(&raw_nar);

    let mut ref_hashes = Vec::with_capacity(references_full.len() + 1);
    if let Some(self_h) = extract_store_hash_32(logical_store_path) {
        ref_hashes.push(self_h);
    }
    // Sort non-self references by canonical derivation name suffix `<name>` (with 32-byte hash
    // as tie-breaker) rather than by pseudorandom 32-char store hash so rebuilt dependencies
    // keep invariant `EPOCH_REF_<idx>` slot indices across rebuilds.
    let mut other_refs: Vec<(&str, [u8; 32])> = references_full
        .iter()
        .filter(|r| r.as_str() != logical_store_path)
        .filter_map(|r| {
            let h = extract_store_hash_32(r)?;
            let name = extract_store_name_suffix(r).unwrap_or("");
            Some((name, h))
        })
        .collect();
    other_refs.sort_unstable_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(&b.1)));
    for (_name, h) in other_refs {
        if !ref_hashes.contains(&h) {
            ref_hashes.push(h);
        }
    }

    // Normalize in-place on the owned NAR buffer to avoid allocating a second 2 MiB Vec<u8>
    let mut norm_nar = raw_nar;
    normalize_nar_store_hashes_in_place(&mut norm_nar, &ref_hashes);
    let ranges = fastcdc_chunk_ranges(&norm_nar);

    let mut chunks = Vec::with_capacity(ranges.len());
    let mut compressed_map = BTreeMap::new();

    for (off, len) in ranges {
        let norm_slice = &norm_nar[off..off + len];
        let norm_blake3 = *blake3::hash(norm_slice).as_bytes();
        let zstd_bytes = zstd_compress(norm_slice)?;
        chunks.push(ChunkDescriptor {
            norm_blake3,
            raw_len: len as u32,
            zstd_len: zstd_bytes.len() as u32,
        });
        compressed_map.insert(norm_blake3, zstd_bytes);
    }

    let store_sig = sign_nix_store_path(
        signing_key_name,
        signing_key,
        logical_store_path,
        &nar_sha256,
        nar_size,
        &references_full,
    );

    Ok((
        NarChunkManifest {
            store_path: logical_store_path.to_owned(),
            nar_sha256,
            nar_size,
            reference_hashes: ref_hashes,
            references_full,
            deriver,
            store_sig,
            chunks,
        },
        compressed_map,
    ))
}

// Target-Local Chunk Index (`/var/cache/epoch/chunk-index.bin`)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedChunkEntry {
    pub norm_blake3: Blake3Hash,
    pub raw_normalized_bytes: Vec<u8>,
}

/// Target-local chunk store backed by reference-counted `Arc<[u8]>` slices and serialized via
/// compact CBOR major type 2 byte strings (`serde_arc_chunk_map`), enabling $O(1)$ zero-copy
/// sharing of verified chunks across simulated and in-process nodes.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TargetChunkIndex {
    #[serde(with = "crate::cbor::serde_arc_chunk_map")]
    pub chunks: BTreeMap<Blake3Hash, Arc<[u8]>>,
}

impl TargetChunkIndex {
    pub fn load(path: &Path) -> Result<Self, EpochError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)?;
        Ok(cbor::from_slice(&bytes)?)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), EpochError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("bin.tmp");
        let bytes = cbor::to_vec_deterministic(self)?;
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    #[inline(always)]
    pub fn has_chunk(&self, hash: &Blake3Hash) -> bool {
        self.chunks.contains_key(hash)
    }

    #[inline(always)]
    pub fn get_chunk(&self, hash: &Blake3Hash) -> Option<&[u8]> {
        self.chunks.get(hash).map(|v| v.as_ref())
    }

    #[inline(always)]
    pub fn get_arc_chunk(&self, hash: &Blake3Hash) -> Option<Arc<[u8]>> {
        self.chunks.get(hash).cloned()
    }

    #[inline]
    pub fn insert_verified_chunk(&mut self, hash: Blake3Hash, norm_raw: Vec<u8>) {
        self.chunks
            .insert(hash, Arc::from(norm_raw.into_boxed_slice()));
    }

    #[inline]
    pub fn insert_verified_arc_chunk(&mut self, hash: Blake3Hash, norm_raw: Arc<[u8]>) {
        self.chunks.insert(hash, norm_raw);
    }

    /// Return all missing `norm_blake3` chunk digests required by `manifests`.
    pub fn find_missing_chunks(&self, manifests: &[NarChunkManifest]) -> Vec<Blake3Hash> {
        let mut missing = Vec::new();
        for m in manifests {
            for c in &m.chunks {
                if !self.has_chunk(&c.norm_blake3) && !missing.contains(&c.norm_blake3) {
                    missing.push(c.norm_blake3);
                }
            }
        }
        missing
    }
}

// Plane 2.3: Strict Store Staging Invariant (`statvfs` Pre-Check, Atomic Reconstruction, SQLite, GC Root)

/// Verify `/nix/store` free byte and inode quotas using `libc::statvfs` before staging.
/// Formula (`DESIGN.md` §5.2.3):
/// - `f_bavail * f_frsize >= sum(NarSize) + max(reserve_override_bytes.unwrap_or(512 MiB), 0.05 * f_blocks * f_frsize)`
/// - `f_favail >= 2 * missing_paths_count + 4096`
pub fn check_store_quota(
    store_dir: &Path,
    missing_manifests: &[&NarChunkManifest],
    reserve_override_bytes: Option<u64>,
) -> Result<(), EpochError> {
    if !store_dir.exists() {
        fs::create_dir_all(store_dir)?;
    }
    let c_path = CString::new(store_dir.as_os_str().as_bytes())
        .map_err(|e| EpochError::Io(e.to_string()))?;

    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) };
    if rc != 0 {
        return Err(EpochError::Io(std::io::Error::last_os_error().to_string()));
    }

    let frsize = if vfs.f_frsize > 0 {
        vfs.f_frsize as u64
    } else {
        vfs.f_bsize as u64
    };
    let available_bytes = (vfs.f_bavail as u64).saturating_mul(frsize);
    let total_bytes = (vfs.f_blocks as u64).saturating_mul(frsize);
    let five_pct = total_bytes / 20;
    let base_reserve = reserve_override_bytes.unwrap_or(512 * 1024 * 1024);
    let reserve_bytes = if reserve_override_bytes.is_some() {
        base_reserve
    } else {
        base_reserve.max(five_pct)
    };

    let sum_nar_size: u64 = missing_manifests.iter().map(|m| m.nar_size).sum();
    let required_bytes = sum_nar_size.saturating_add(reserve_bytes);

    let available_inodes = vfs.f_favail as u64;
    let required_inodes = (2 * missing_manifests.len() as u64) + 4096;

    // Note: some filesystems (e.g. tmpfs/btrfs without fixed inode table) report f_favail == 0
    // when f_files == 0; only enforce inode limit when f_files > 0.
    let inode_violation = vfs.f_files > 0 && available_inodes < required_inodes;

    if available_bytes < required_bytes || inode_violation {
        return Err(EpochError::StoreQuotaExceeded {
            available_bytes,
            required_bytes,
            available_inodes,
            required_inodes,
        });
    }
    Ok(())
}

#[inline]
fn lookup_expected_chunk_len(
    manifests: &[NarChunkManifest],
    expected_hash: &Blake3Hash,
) -> Option<usize> {
    for m in manifests {
        for c in &m.chunks {
            if &c.norm_blake3 == expected_hash {
                return Some(c.raw_len as usize);
            }
        }
    }
    None
}

/// Decompress, verify `BLAKE3` digests, and ingest borrowed compressed chunk slices into `TargetChunkIndex`.
pub fn ingest_fetched_chunk_slices(
    index: &mut TargetChunkIndex,
    manifests: &[NarChunkManifest],
    fetched_zstd_chunks: &[(Blake3Hash, &[u8])],
) -> Result<(), EpochError> {
    let _zone = crate::tracy_zone!("plane2::ingest_fetched_chunks", 0x10b981);
    _zone.value(fetched_zstd_chunks.len() as u64);
    if fetched_zstd_chunks.is_empty() {
        return Ok(());
    }

    // For small delta batches (<= 8 chunks), scan manifests directly on the stack instead of
    // heap-allocating a BTreeMap of all chunks in the closure.
    if fetched_zstd_chunks.len() <= 8 {
        for (idx, &(ref expected_hash, zstd_bytes)) in fetched_zstd_chunks.iter().enumerate() {
            let raw_len = lookup_expected_chunk_len(manifests, expected_hash).ok_or_else(|| {
                EpochError::Io(format!(
                    "received unrequested chunk {}",
                    hex::encode(expected_hash)
                ))
            })?;
            let norm_raw = zstd_decompress(zstd_bytes, raw_len)?;
            let actual_hash = *blake3::hash(&norm_raw).as_bytes();
            if actual_hash != *expected_hash {
                return Err(EpochError::ChunkBlake3Mismatch {
                    chunk_idx: idx,
                    expected: hex::encode(expected_hash),
                    actual: hex::encode(actual_hash),
                });
            }
            index.insert_verified_chunk(*expected_hash, norm_raw);
        }
        return Ok(());
    }

    let mut expected_lengths: BTreeMap<Blake3Hash, usize> = BTreeMap::new();
    for m in manifests {
        for c in &m.chunks {
            expected_lengths.insert(c.norm_blake3, c.raw_len as usize);
        }
    }

    for (idx, &(ref expected_hash, zstd_bytes)) in fetched_zstd_chunks.iter().enumerate() {
        let raw_len = *expected_lengths.get(expected_hash).ok_or_else(|| {
            EpochError::Io(format!(
                "received unrequested chunk {}",
                hex::encode(expected_hash)
            ))
        })?;
        let norm_raw = zstd_decompress(zstd_bytes, raw_len)?;
        let actual_hash = *blake3::hash(&norm_raw).as_bytes();
        if actual_hash != *expected_hash {
            return Err(EpochError::ChunkBlake3Mismatch {
                chunk_idx: idx,
                expected: hex::encode(expected_hash),
                actual: hex::encode(actual_hash),
            });
        }
        index.insert_verified_chunk(*expected_hash, norm_raw);
    }
    Ok(())
}

/// Decompress, verify `BLAKE3` digests, and ingest fetched compressed chunks into `TargetChunkIndex`.
pub fn ingest_fetched_chunks(
    index: &mut TargetChunkIndex,
    manifests: &[NarChunkManifest],
    fetched_zstd_chunks: &[(Blake3Hash, Vec<u8>)],
) -> Result<(), EpochError> {
    let _zone = crate::tracy_zone!("plane2::ingest_fetched_chunks", 0x10b981);
    _zone.value(fetched_zstd_chunks.len() as u64);
    if fetched_zstd_chunks.is_empty() {
        return Ok(());
    }

    if fetched_zstd_chunks.len() <= 8 {
        for (idx, (expected_hash, zstd_bytes)) in fetched_zstd_chunks.iter().enumerate() {
            let raw_len = lookup_expected_chunk_len(manifests, expected_hash).ok_or_else(|| {
                EpochError::Io(format!(
                    "received unrequested chunk {}",
                    hex::encode(expected_hash)
                ))
            })?;
            let norm_raw = zstd_decompress(zstd_bytes, raw_len)?;
            let actual_hash = *blake3::hash(&norm_raw).as_bytes();
            if actual_hash != *expected_hash {
                return Err(EpochError::ChunkBlake3Mismatch {
                    chunk_idx: idx,
                    expected: hex::encode(expected_hash),
                    actual: hex::encode(actual_hash),
                });
            }
            index.insert_verified_chunk(*expected_hash, norm_raw);
        }
        return Ok(());
    }

    let mut expected_lengths: BTreeMap<Blake3Hash, usize> = BTreeMap::new();
    for m in manifests {
        for c in &m.chunks {
            expected_lengths.insert(c.norm_blake3, c.raw_len as usize);
        }
    }

    for (idx, (expected_hash, zstd_bytes)) in fetched_zstd_chunks.iter().enumerate() {
        let raw_len = *expected_lengths.get(expected_hash).ok_or_else(|| {
            EpochError::Io(format!(
                "received unrequested chunk {}",
                hex::encode(expected_hash)
            ))
        })?;
        let norm_raw = zstd_decompress(zstd_bytes, raw_len)?;
        let actual_hash = *blake3::hash(&norm_raw).as_bytes();
        if actual_hash != *expected_hash {
            return Err(EpochError::ChunkBlake3Mismatch {
                chunk_idx: idx,
                expected: hex::encode(expected_hash),
                actual: hex::encode(actual_hash),
            });
        }
        index.insert_verified_chunk(*expected_hash, norm_raw);
    }
    Ok(())
}

/// Reconstruct a store path from `TargetChunkIndex`, denormalize 32-byte store-hash tokens in-place,
/// verify full-NAR `SHA-256 == manifest.nar_sha256` and `manifest.store_sig`, unpack into
/// `.epoch-tmp-<tx>`, atomically rename into `store_root`, and register in SQLite `db.sqlite`.
pub fn reconstruct_and_register_store_path(
    store_root: &Path,
    sqlite_db_path: &Path,
    manifest: &NarChunkManifest,
    index: &TargetChunkIndex,
    trusted_store_keys: &[(String, Ed25519Pub)],
) -> Result<PathBuf, EpochError> {
    let _zone = crate::tracy_zone!("plane2::reconstruct_and_register_store_path", 0x047857);
    _zone.value(manifest.nar_size);
    // 1. Verify store_sig against trusted keys before writing to disk
    verify_nix_store_path_sig(
        &manifest.store_sig,
        trusted_store_keys,
        &manifest.store_path,
        &manifest.nar_sha256,
        manifest.nar_size,
        &manifest.references_full,
    )?;

    // 2. Concatenate verified normalized chunks
    let mut nar_buf = Vec::with_capacity(manifest.nar_size as usize);
    for (chunk_idx, desc) in manifest.chunks.iter().enumerate() {
        let chunk_bytes = index.get_chunk(&desc.norm_blake3).ok_or_else(|| {
            EpochError::Io(format!(
                "missing chunk {} ({}) during reconstruction of {}",
                chunk_idx,
                hex::encode(desc.norm_blake3),
                manifest.store_path
            ))
        })?;
        let actual_b3 = *blake3::hash(chunk_bytes).as_bytes();
        if actual_b3 != desc.norm_blake3 {
            return Err(EpochError::ChunkBlake3Mismatch {
                chunk_idx,
                expected: hex::encode(desc.norm_blake3),
                actual: hex::encode(actual_b3),
            });
        }
        nar_buf.extend_from_slice(chunk_bytes);
    }

    // 3. Apply inverse 32-byte store-hash substitution IN-PLACE (zero second 2 MiB buffer allocation)
    denormalize_nar_store_hashes_in_place(&mut nar_buf, &manifest.reference_hashes)?;
    let raw_nar = nar_buf;
    if raw_nar.len() as u64 != manifest.nar_size {
        return Err(EpochError::NarIntegrityMismatch {
            store_path: manifest.store_path.clone(),
            reason: format!(
                "NAR size mismatch: reconstructed {} != manifest {}",
                raw_nar.len(),
                manifest.nar_size
            ),
        });
    }
    let actual_sha256 = sha256_digest(&raw_nar);
    if actual_sha256 != manifest.nar_sha256 {
        return Err(EpochError::NarIntegrityMismatch {
            store_path: manifest.store_path.clone(),
            reason: format!(
                "NAR SHA-256 mismatch: reconstructed {} != manifest {}",
                hex::encode(actual_sha256),
                hex::encode(manifest.nar_sha256)
            ),
        });
    }

    // 4. Unpack into `.epoch-tmp-<hash>` inside `store_root` and atomically rename to target
    set_nix_store_writable(store_root, true);
    if !store_root.exists() {
        fs::create_dir_all(store_root)?;
    }
    let store_basename = Path::new(&manifest.store_path)
        .file_name()
        .ok_or_else(|| EpochError::Io(format!("invalid store_path {}", manifest.store_path)))?;
    let final_path = store_root.join(store_basename);
    let tmp_name = format!(
        ".epoch-tmp-{}-{}",
        store_basename.to_string_lossy(),
        unsafe { libc::getpid() }
    );
    let tmp_path = store_root.join(tmp_name);

    if tmp_path.exists() {
        force_remove_tree(&tmp_path)?;
    }

    if let Err(e) = unpack_nar(&raw_nar, &tmp_path) {
        let _ = force_remove_tree(&tmp_path);
        return Err(e);
    }

    if final_path.exists() {
        force_remove_tree(&final_path)?;
    }
    fs::rename(&tmp_path, &final_path)?;

    // 5. Register path in `/nix/var/nix/db/db.sqlite` (`ValidPaths` and `Refs` tables)
    register_valid_path_sqlite(sqlite_db_path, manifest)?;

    Ok(final_path)
}

/// Remount `/nix/store` read-write (`writable = true`) or read-only (`writable = false`)
/// when running as root on a live NixOS system with `nix.readOnlyStore = true`.
pub fn set_nix_store_writable(store_root: &Path, writable: bool) {
    if store_root == Path::new("/nix/store") {
        let flags = if writable {
            libc::MS_REMOUNT | libc::MS_BIND
        } else {
            libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY
        };
        unsafe {
            let _ = libc::mount(
                std::ptr::null(),
                c"/nix/store".as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            );
        }
    }
}

/// Remove a read-only store directory tree by temporarily restoring `u+w` on directories.
pub fn force_remove_tree(path: &Path) -> Result<(), EpochError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_dir() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    force_remove_tree(&entry.path())?;
                }
            }
            fs::remove_dir(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

struct CachedSqliteDb {
    path: PathBuf,
    dev: u64,
    ino: u64,
    db: *mut libc::c_void,
}

unsafe impl Send for CachedSqliteDb {}

impl Drop for CachedSqliteDb {
    fn drop(&mut self) {
        if !self.db.is_null() {
            unsafe {
                sqlite3_close(self.db);
            }
            self.db = std::ptr::null_mut();
        }
    }
}

static SQLITE_CONN_CACHE: std::sync::Mutex<Vec<CachedSqliteDb>> = std::sync::Mutex::new(Vec::new());

fn with_sqlite_conn<F, R>(sqlite_db_path: &Path, f: F) -> Result<R, EpochError>
where
    F: FnOnce(*mut libc::c_void) -> Result<R, EpochError>,
{
    use std::os::unix::fs::MetadataExt as _;

    if let Some(parent) = sqlite_db_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut cache = SQLITE_CONN_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Ok(meta) = fs::metadata(sqlite_db_path) {
        let dev = meta.dev();
        let ino = meta.ino();
        if let Some(pos) = cache
            .iter()
            .position(|entry| entry.path == sqlite_db_path && entry.dev == dev && entry.ino == ino)
        {
            let entry = cache.remove(pos);
            let db_ptr = entry.db;
            cache.push(entry);
            return f(db_ptr);
        }
    }

    cache.retain(|entry| entry.path != sqlite_db_path);
    if cache.len() >= 16 {
        cache.remove(0);
    }

    let c_db_path = CString::new(sqlite_db_path.as_os_str().as_bytes())
        .map_err(|e| EpochError::Io(e.to_string()))?;

    let mut db: *mut libc::c_void = std::ptr::null_mut();
    unsafe {
        let rc = sqlite3_open(c_db_path.as_ptr(), &mut db);
        if rc != 0 || db.is_null() {
            if !db.is_null() {
                sqlite3_close(db);
            }
            return Err(EpochError::Io("sqlite3_open failed on db.sqlite".into()));
        }

        let init_sql = "PRAGMA journal_mode = WAL; \
                        PRAGMA synchronous = NORMAL; \
                        CREATE TABLE IF NOT EXISTS ValidPaths (\
                            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, \
                            path TEXT UNIQUE NOT NULL, \
                            hash TEXT NOT NULL, \
                            registrationTime INTEGER NOT NULL, \
                            deriver TEXT, \
                            narSize INTEGER, \
                            ultimate INTEGER, \
                            sigs TEXT, \
                            ca TEXT\
                        ); \
                        CREATE TABLE IF NOT EXISTS Refs (\
                            referrer INTEGER NOT NULL, \
                            reference INTEGER NOT NULL, \
                            PRIMARY KEY (referrer, reference)\
                        );";
        if let Err(e) = exec_sql(db, init_sql) {
            sqlite3_close(db);
            return Err(e);
        }
    }

    let (dev, ino) = fs::metadata(sqlite_db_path)
        .map(|m| (m.dev(), m.ino()))
        .unwrap_or((0, 0));
    cache.push(CachedSqliteDb {
        path: sqlite_db_path.to_path_buf(),
        dev,
        ino,
        db,
    });
    f(db)
}

/// Register a validated store path in Nix's SQLite database (`ValidPaths` & `Refs` tables) via `libsqlite3`.
/// Batches `ValidPaths` upsert and `Refs` insertion into a single atomic WAL transaction on an
/// inode-verified cached SQLite connection to preserve crash durability without per-path connection/WAL teardown.
pub fn register_valid_path_sqlite(
    sqlite_db_path: &Path,
    manifest: &NarChunkManifest,
) -> Result<(), EpochError> {
    use std::fmt::Write as _;
    let _zone = crate::tracy_zone!("plane2::register_valid_path_sqlite", 0x065f46);

    let escaped_path = manifest.store_path.replace('\'', "''");
    let hash_hex = hex::encode(manifest.nar_sha256);
    let escaped_sig = manifest.store_sig.replace('\'', "''");

    let mut batch_sql = String::with_capacity(512 + manifest.references_full.len() * 256);
    batch_sql.push_str("BEGIN IMMEDIATE TRANSACTION; ");

    let _ = write!(
        batch_sql,
        "INSERT INTO ValidPaths (path, hash, registrationTime, deriver, narSize, ultimate, sigs) \
         VALUES ('{escaped_path}', 'sha256:{hash_hex}', 1, "
    );
    if let Some(ref d) = manifest.deriver {
        let _ = write!(batch_sql, "'{}'", d.replace('\'', "''"));
    } else {
        batch_sql.push_str("NULL");
    }
    let _ = write!(
        batch_sql,
        ", {}, 0, '{escaped_sig}') \
         ON CONFLICT(path) DO UPDATE SET \
           hash = excluded.hash, \
           registrationTime = excluded.registrationTime, \
           deriver = excluded.deriver, \
           narSize = excluded.narSize, \
           ultimate = excluded.ultimate, \
           sigs = excluded.sigs; \
         DELETE FROM Refs WHERE referrer = (SELECT id FROM ValidPaths WHERE path = '{escaped_path}'); ",
        manifest.nar_size
    );

    for r in &manifest.references_full {
        let escaped_ref = r.replace('\'', "''");
        let _ = write!(
            batch_sql,
            "INSERT OR IGNORE INTO ValidPaths (path, hash, registrationTime, ultimate) \
             VALUES ('{escaped_ref}', 'sha256:0000000000000000000000000000000000000000000000000000000000000000', 1, 0); \
             INSERT OR IGNORE INTO Refs (referrer, reference) \
             SELECT v1.id, v2.id FROM ValidPaths v1, ValidPaths v2 \
             WHERE v1.path = '{escaped_path}' AND v2.path = '{escaped_ref}'; "
        );
    }
    batch_sql.push_str("COMMIT;");

    with_sqlite_conn(sqlite_db_path, |db| unsafe { exec_sql(db, &batch_sql) })
}

/// Query `/nix/var/nix/db/db.sqlite` to check if `store_path` is registered in `ValidPaths`
/// and return `(is_registered, refs_count)` from `Refs`.
pub fn query_valid_path_and_refs_sqlite(
    sqlite_db_path: &Path,
    store_path: &str,
) -> Result<(bool, usize), EpochError> {
    if !sqlite_db_path.exists() {
        return Ok((false, 0));
    }

    unsafe extern "C" fn count_cb(
        arg: *mut libc::c_void,
        argc: libc::c_int,
        argv: *mut *mut libc::c_char,
        _col_names: *mut *mut libc::c_char,
    ) -> libc::c_int {
        if argc >= 1 && !argv.is_null() {
            let val_ptr = unsafe { *argv };
            if !val_ptr.is_null() {
                let s = unsafe { std::ffi::CStr::from_ptr(val_ptr) }.to_string_lossy();
                if let Ok(n) = s.parse::<usize>() {
                    unsafe { *(arg as *mut usize) = n };
                }
            }
        }
        0
    }

    with_sqlite_conn(sqlite_db_path, |db| unsafe {
        let escaped_path = store_path.replace('\'', "''");
        let vp_sql = CString::new(format!(
            "SELECT COUNT(*) FROM ValidPaths WHERE path = '{escaped_path}';"
        ))
        .map_err(|e| EpochError::Io(e.to_string()))?;
        let mut vp_count = 0usize;
        let mut errmsg: *mut libc::c_char = std::ptr::null_mut();
        let rc1 = sqlite3_exec(
            db,
            vp_sql.as_ptr(),
            Some(count_cb),
            (&mut vp_count as *mut usize) as *mut libc::c_void,
            &mut errmsg,
        );
        if !errmsg.is_null() {
            sqlite3_free(errmsg as *mut libc::c_void);
        }

        let refs_sql = CString::new(format!(
            "SELECT COUNT(*) FROM Refs WHERE referrer = (SELECT id FROM ValidPaths WHERE path = '{escaped_path}');"
        ))
        .map_err(|e| EpochError::Io(e.to_string()))?;
        let mut refs_count = 0usize;
        let mut errmsg2: *mut libc::c_char = std::ptr::null_mut();
        let rc2 = sqlite3_exec(
            db,
            refs_sql.as_ptr(),
            Some(count_cb),
            (&mut refs_count as *mut usize) as *mut libc::c_void,
            &mut errmsg2,
        );
        if !errmsg2.is_null() {
            sqlite3_free(errmsg2 as *mut libc::c_void);
        }

        if rc1 != 0 || rc2 != 0 {
            return Err(EpochError::Io("sqlite3 query failed".into()));
        }
        Ok((vp_count > 0, refs_count))
    })
}

/// Checkpoint the SQLite WAL file and close the cached handle for `sqlite_db_path` so external
/// `nix-store` / `switch-to-configuration` processes observe newly registered paths immediately.
pub fn flush_sqlite_conn_cache(sqlite_db_path: &Path) {
    let mut cache = SQLITE_CONN_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for entry in cache.iter() {
        if entry.path == sqlite_db_path && !entry.db.is_null() {
            unsafe {
                let _ = exec_sql(entry.db, "PRAGMA wal_checkpoint(TRUNCATE);");
            }
        }
    }
    cache.retain(|entry| entry.path != sqlite_db_path);
}

/// Return all store paths from `store_paths` that are either missing on disk in `store_dir`
/// or not registered with a real SHA-256 hash in `ValidPaths` (`sqlite_db_path`).
pub fn query_missing_store_paths(
    store_dir: &Path,
    sqlite_db_path: &Path,
    store_paths: &[String],
) -> Result<Vec<String>, EpochError> {
    if store_paths.is_empty() {
        return Ok(Vec::new());
    }
    if !sqlite_db_path.exists() {
        return Ok(store_paths.to_vec());
    }

    unsafe extern "C" fn collect_path_cb(
        arg: *mut libc::c_void,
        argc: libc::c_int,
        argv: *mut *mut libc::c_char,
        _col_names: *mut *mut libc::c_char,
    ) -> libc::c_int {
        if argc >= 1 && !argv.is_null() {
            let val_ptr = unsafe { *argv };
            if !val_ptr.is_null() {
                let s = unsafe { std::ffi::CStr::from_ptr(val_ptr) }
                    .to_string_lossy()
                    .into_owned();
                let set = unsafe { &mut *(arg as *mut std::collections::BTreeSet<String>) };
                set.insert(s);
            }
        }
        0
    }

    let mut valid_in_db = std::collections::BTreeSet::new();
    with_sqlite_conn(sqlite_db_path, |db| unsafe {
        for chunk in store_paths.chunks(500) {
            let mut sql = String::from(
                "SELECT path FROM ValidPaths WHERE hash != 'sha256:0000000000000000000000000000000000000000000000000000000000000000' AND path IN (",
            );
            for (idx, p) in chunk.iter().enumerate() {
                if idx > 0 {
                    sql.push(',');
                }
                sql.push('\'');
                sql.push_str(&p.replace('\'', "''"));
                sql.push('\'');
            }
            sql.push_str(");");
            let c_sql = CString::new(sql).map_err(|e| EpochError::Io(e.to_string()))?;
            let mut errmsg: *mut libc::c_char = std::ptr::null_mut();
            let rc = sqlite3_exec(
                db,
                c_sql.as_ptr(),
                Some(collect_path_cb),
                (&mut valid_in_db as *mut std::collections::BTreeSet<String>) as *mut libc::c_void,
                &mut errmsg,
            );
            if !errmsg.is_null() {
                sqlite3_free(errmsg as *mut libc::c_void);
            }
            if rc != 0 {
                return Err(EpochError::Io(
                    "sqlite3 ValidPaths batch query failed".into(),
                ));
            }
        }
        Ok(())
    })?;

    let mut missing = Vec::new();
    for p in store_paths {
        let on_disk = Path::new(p)
            .file_name()
            .map(|base| store_dir.join(base).exists())
            .unwrap_or(false);
        if !on_disk || !valid_in_db.contains(p) {
            missing.push(p.clone());
        }
    }
    Ok(missing)
}

unsafe fn exec_sql(db: *mut libc::c_void, sql: &str) -> Result<(), EpochError> {
    let c_sql = CString::new(sql).map_err(|e| EpochError::Io(e.to_string()))?;
    let mut errmsg: *mut libc::c_char = std::ptr::null_mut();
    let rc = unsafe { sqlite3_exec(db, c_sql.as_ptr(), None, std::ptr::null_mut(), &mut errmsg) };
    if rc != 0 {
        let msg = if !errmsg.is_null() {
            let s = unsafe { std::ffi::CStr::from_ptr(errmsg) }
                .to_string_lossy()
                .into_owned();
            unsafe { sqlite3_free(errmsg as *mut libc::c_void) };
            s
        } else {
            format!("sqlite3_exec failed with code {rc}")
        };
        return Err(EpochError::Io(msg));
    }
    Ok(())
}

/// Create the isolated staging GC root symlink:
/// `<gcroots_staging_dir>/tx-<tx_epoch> -> <staged_toplevel_path>`
/// without mutating `/nix/var/nix/profiles/system`, `/run/current-system`, or `/boot`.
pub fn create_staging_gcroot(
    gcroots_staging_dir: &Path,
    tx_epoch: u64,
    staged_toplevel_path: &Path,
) -> Result<PathBuf, EpochError> {
    fs::create_dir_all(gcroots_staging_dir)?;
    let link_path = gcroots_staging_dir.join(format!("tx-{tx_epoch}"));
    let tmp_link = gcroots_staging_dir.join(format!(".tx-{tx_epoch}.tmp"));
    if tmp_link.exists() || fs::symlink_metadata(&tmp_link).is_ok() {
        let _ = fs::remove_file(&tmp_link);
    }
    symlink(staged_toplevel_path, &tmp_link)?;
    fs::rename(&tmp_link, &link_path)?;
    Ok(link_path)
}

/// Remove the staging GC root symlink `<gcroots_staging_dir>/tx-<tx_epoch>` upon rollback or cleanup.
pub fn remove_staging_gcroot(gcroots_staging_dir: &Path, tx_epoch: u64) {
    let link_path = gcroots_staging_dir.join(format!("tx-{tx_epoch}"));
    let _ = fs::remove_file(link_path);
}
