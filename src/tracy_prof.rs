//! Zero-cost Rust FFI bindings and instrumentation macros for `tracy-flake` (`libTracyClient.so` v0.14.1).
//!
//! When compiled with `--features tracy`, zones, plots, and frame marks are emitted directly to
//! `libTracyClient.so` (`TracyC.h` ABI) for live or headless capture via `tracy-capture` and
//! `tracy-csvexport`. When the `tracy` feature is disabled (the default release build for
//! `epoch-agent`), all instrumentation macros compile down to zero-instruction inline no-ops.

use std::sync::atomic::{AtomicBool, Ordering};

/// Set to `true` inside forked child worker processes after `libc::fork() == 0` so child processes
/// do not emit into the parent process's `libTracyClient.so` ringbuffer before `_exit(0)`.
static IN_FORKED_CHILD: AtomicBool = AtomicBool::new(false);

/// Marks the current process as a forked child worker.
#[inline(always)]
pub fn mark_forked_child() {
    IN_FORKED_CHILD.store(true, Ordering::Relaxed);
}

/// Returns `true` if the current process is a forked child worker.
#[inline(always)]
pub fn is_forked_child() -> bool {
    IN_FORKED_CHILD.load(Ordering::Relaxed)
}

/// Static source location descriptor matching `struct ___tracy_source_location_data` in `<tracy/TracyC.h>`.
#[repr(C)]
pub struct TracySourceLocationData {
    pub name: *const libc::c_char,
    pub function: *const libc::c_char,
    pub file: *const libc::c_char,
    pub line: u32,
    pub color: u32,
}

// SAFETY: `TracySourceLocationData` is only ever constructed from `'static` NUL-terminated string
// literals and read immutably by `libTracyClient.so`.
unsafe impl Sync for TracySourceLocationData {}

/// C ABI zone context matching `struct ___tracy_c_zone_context` in `<tracy/TracyC.h>`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TracyCZoneContext {
    pub id: u32,
    pub active: i32,
}

#[cfg(feature = "tracy")]
unsafe extern "C" {
    fn ___tracy_emit_zone_begin(
        srcloc: *const TracySourceLocationData,
        active: i32,
    ) -> TracyCZoneContext;
    fn ___tracy_emit_zone_end(ctx: TracyCZoneContext);
    fn ___tracy_emit_zone_value(ctx: TracyCZoneContext, value: u64);
    fn ___tracy_emit_frame_mark(name: *const libc::c_char);
    fn ___tracy_emit_plot(name: *const libc::c_char, val: f64);
    fn ___tracy_connected() -> i32;
}

/// RAII guard for a Tracy instrumentation zone.
pub struct ZoneGuard {
    #[cfg(feature = "tracy")]
    ctx: TracyCZoneContext,
    #[cfg(feature = "tracy")]
    enabled: bool,
}

impl ZoneGuard {
    #[cfg(feature = "tracy")]
    #[inline(always)]
    pub fn enter(srcloc: &'static TracySourceLocationData) -> Self {
        if is_forked_child() {
            return Self {
                ctx: TracyCZoneContext { id: 0, active: 0 },
                enabled: false,
            };
        }
        // SAFETY: `srcloc` is a `'static` reference to valid NUL-terminated strings.
        let ctx = unsafe { ___tracy_emit_zone_begin(srcloc as *const TracySourceLocationData, 1) };
        Self { ctx, enabled: true }
    }

    #[cfg(not(feature = "tracy"))]
    #[inline(always)]
    pub fn enter(_srcloc: &'static TracySourceLocationData) -> Self {
        Self {}
    }

    /// Attaches an integer metric (e.g., byte count, node count, chunk count) to the active zone.
    #[inline(always)]
    pub fn value(&self, val: u64) {
        #[cfg(feature = "tracy")]
        if self.enabled {
            // SAFETY: `self.ctx` was returned by `___tracy_emit_zone_begin` on the current thread.
            unsafe {
                ___tracy_emit_zone_value(self.ctx, val);
            }
        }
        #[cfg(not(feature = "tracy"))]
        let _ = val;
    }
}

#[cfg(feature = "tracy")]
impl Drop for ZoneGuard {
    #[inline(always)]
    fn drop(&mut self) {
        if self.enabled {
            // SAFETY: `self.ctx` was opened on this thread by `___tracy_emit_zone_begin`.
            unsafe {
                ___tracy_emit_zone_end(self.ctx);
            }
        }
    }
}

/// Emits a frame mark to Tracy when the `tracy` feature is active.
#[inline(always)]
pub fn emit_frame_mark(name_cstr: &'static [u8]) {
    #[cfg(feature = "tracy")]
    if !is_forked_child() {
        let ptr = if name_cstr.is_empty() {
            std::ptr::null()
        } else {
            name_cstr.as_ptr().cast::<libc::c_char>()
        };
        unsafe {
            ___tracy_emit_frame_mark(ptr);
        }
    }
    #[cfg(not(feature = "tracy"))]
    let _ = name_cstr;
}

/// Emits a floating-point plot sample to Tracy when the `tracy` feature is active.
#[inline(always)]
pub fn emit_plot(name_cstr: &'static [u8], val: f64) {
    #[cfg(feature = "tracy")]
    if !is_forked_child() && !name_cstr.is_empty() {
        unsafe {
            ___tracy_emit_plot(name_cstr.as_ptr().cast::<libc::c_char>(), val);
        }
    }
    #[cfg(not(feature = "tracy"))]
    {
        let _ = (name_cstr, val);
    }
}

/// When `EPOCH_TRACY_WAIT=1` is set and the binary is compiled with `--features tracy`, waits up
/// to `timeout_ms` for `tracy-capture` to connect before starting benchmark workloads.
pub fn wait_for_tracy_connection(timeout_ms: u64) {
    #[cfg(feature = "tracy")]
    {
        if std::env::var_os("EPOCH_TRACY_WAIT").is_some() {
            let start = std::time::Instant::now();
            while unsafe { ___tracy_connected() } == 0 {
                if start.elapsed().as_millis() as u64 >= timeout_ms {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // Allow handshake negotiation to settle
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    #[cfg(not(feature = "tracy"))]
    let _ = timeout_ms;
}

/// Flushes pending Tracy client telemetry before process termination when `EPOCH_TRACY_WAIT=1` is set.
pub fn flush_tracy() {
    #[cfg(feature = "tracy")]
    {
        if std::env::var_os("EPOCH_TRACY_WAIT").is_some() {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
}

/// Opens a scoped Tracy zone bound to `_tracy_guard` (or returns a `ZoneGuard` expression).
#[macro_export]
macro_rules! tracy_zone {
    ($name:literal) => {{ $crate::tracy_zone!($name, 0x38bdf8u32) }};
    ($name:literal, $color:expr) => {{
        static SRCLOC: $crate::tracy_prof::TracySourceLocationData =
            $crate::tracy_prof::TracySourceLocationData {
                name: concat!($name, "\0").as_ptr().cast::<libc::c_char>(),
                function: concat!(module_path!(), "\0")
                    .as_ptr()
                    .cast::<libc::c_char>(),
                file: concat!(file!(), "\0").as_ptr().cast::<libc::c_char>(),
                line: line!(),
                color: $color,
            };
        $crate::tracy_prof::ZoneGuard::enter(&SRCLOC)
    }};
}

/// Emits a Tracy frame boundary.
#[macro_export]
macro_rules! tracy_frame {
    () => {
        $crate::tracy_prof::emit_frame_mark(b"")
    };
    ($name:literal) => {
        $crate::tracy_prof::emit_frame_mark(concat!($name, "\0").as_bytes())
    };
}

/// Emits a numeric sample to a named Tracy plot series.
#[macro_export]
macro_rules! tracy_plot {
    ($name:literal, $val:expr) => {
        $crate::tracy_prof::emit_plot(concat!($name, "\0").as_bytes(), ($val) as f64)
    };
}
