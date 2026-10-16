//! Test-only allocator-injection harness for the SSL adversarial tests
//! (`stage/p25/adv-tests`, §16 negative controls / §18 verification schedule).
//!
//! It installs the crate's allocator seam (`CRYPTO_set_mem_functions`) with counting, recording
//! hooks and, on request, refuses one allocation at a chosen authority coordinate, so a test can
//! drive the `SSL_SESSION` ticket writers and the member-buffer handles through their
//! allocation-refusal path and observe the exact allocator-event sequence.
//!
//! Installing an allocator is a **process-global** act, so each probe test that uses this module is
//! gated on `OPENSSL_RS_ADV_PROBE=1` and is meant to run alone in its process (an exact test filter
//! with `--test-threads=1`), exactly like `runtime/sparse_array_probe.rs`. In the ordinary
//! `cargo test --lib` suite the gate is unset, the test returns immediately, and the shared
//! allocator is never replaced. This module is never linked into a release build: it is declared
//! `#[cfg(test)]` in `ssl/mod.rs`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::runtime::mem::{CRYPTO_set_mem_functions, CRYPTO_zalloc};
use crate::ssl::ssl_lib::Ssl;

extern "C" {
    fn malloc(n: usize) -> *mut c_void;
    fn realloc(p: *mut c_void, n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
}

/// One allocator event observed by the installed hook.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Ev {
    /// A `CRYPTO_*` allocation request of `n` bytes. `site` is true when the request came from an
    /// authority coordinate of `(NULL, 0)` — the site every ticket writer allocates its replacement
    /// ticket at — and `refused` is true when this hook answered NULL instead of allocating.
    Malloc { n: usize, site: bool, refused: bool },
    /// A `CRYPTO_free` release of `p` (0 for the NULL no-op).
    Free { p: usize },
}

/// The instrument's whole state, behind one lock so `hook_malloc` and `hook_free` cannot take two
/// mutexes in opposite orders and deadlock.
struct State {
    log: Vec<Ev>,
    /// Pointers released and not since reallocated. A `free` of a pointer already here is a double
    /// release (the defect class the tests target).
    freed: Vec<usize>,
    double_free: bool,
}

static STATE: Mutex<State> = Mutex::new(State {
    log: Vec::new(),
    freed: Vec::new(),
    double_free: false,
});

/// One-shot refusal: set by [`arm`], consumed by the first matching request in `hook_malloc`.
static ARMED: AtomicBool = AtomicBool::new(false);
static ARMED_SIZE: AtomicUsize = AtomicUsize::new(0);
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Run `f` with the instrument's state locked (poison recovered: a panic already failed the run).
fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut g = STATE.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut g)
}

/// The recording `CRYPTO_malloc` shim. Refuses a request when armed for exactly that size at the
/// `(NULL, 0)` site; forwards every other request to the C allocator and records it.
unsafe extern "C" fn hook_malloc(n: usize, file: *const c_char, line: c_int) -> *mut c_void {
    let site = file.is_null() && line == 0;
    if ARMED.load(Ordering::SeqCst) && site && n == ARMED_SIZE.load(Ordering::SeqCst) {
        // One-shot: disarm and answer NULL, exactly as a refused allocator call.
        ARMED.store(false, Ordering::SeqCst);
        with_state(|s| {
            s.log.push(Ev::Malloc {
                n,
                site,
                refused: true,
            })
        });
        return ptr::null_mut();
    }
    // SAFETY: `malloc` has no preconditions and answers NULL or a block of at least `n` bytes.
    let p = unsafe { malloc(n) };
    let key = p as usize;
    with_state(|s| {
        s.log.push(Ev::Malloc {
            n,
            site,
            refused: false,
        });
        if !p.is_null() {
            if let Some(i) = s.freed.iter().position(|&x| x == key) {
                s.freed.swap_remove(i);
            }
        }
    });
    p
}

/// The recording `CRYPTO_realloc` shim.
unsafe extern "C" fn hook_realloc(
    p: *mut c_void,
    n: usize,
    _file: *const c_char,
    _line: c_int,
) -> *mut c_void {
    // SAFETY: `p` is NULL or a block from `hook_malloc`, and `realloc`'s contract is this hook's.
    let q = unsafe { realloc(p, n) };
    with_state(|s| {
        for cand in [p as usize, q as usize] {
            if cand != 0 {
                if let Some(i) = s.freed.iter().position(|&x| x == cand) {
                    s.freed.swap_remove(i);
                }
            }
        }
    });
    q
}

/// The recording `CRYPTO_free` shim. Flags a double release and refuses to forward it, so the run
/// continues and the test's own assertion (not glibc's abort) reports the defect.
unsafe extern "C" fn hook_free(p: *mut c_void, _file: *const c_char, _line: c_int) {
    if p.is_null() {
        with_state(|s| s.log.push(Ev::Free { p: 0 }));
        return;
    }
    let key = p as usize;
    let already = with_state(|s| {
        s.log.push(Ev::Free { p: key });
        if s.freed.contains(&key) {
            s.double_free = true;
            true
        } else {
            s.freed.push(key);
            false
        }
    });
    if !already {
        // SAFETY: `p` is a block `hook_malloc` returned and has not been released yet.
        unsafe { free(p) };
    }
}

/// True when the probe gate is set; the caller reports a skip otherwise.
pub(crate) fn probe_enabled() -> bool {
    std::env::var("OPENSSL_RS_ADV_PROBE").as_deref() == Ok("1")
}

/// Install the recording allocator. Answers false when the seam refuses the installation (some
/// allocation already ran in this process), i.e. the test is not running alone; the caller skips.
pub(crate) fn install() -> bool {
    if INSTALLED.load(Ordering::SeqCst) {
        return true;
    }
    // SAFETY: the three hooks satisfy the allocator contract and are valid for the lifetime of the
    // process; the caller runs this probe alone, so replacing the allocator perturbs no other test.
    let rc =
        unsafe { CRYPTO_set_mem_functions(Some(hook_malloc), Some(hook_realloc), Some(hook_free)) };
    if rc == 1 {
        INSTALLED.store(true, Ordering::SeqCst);
    }
    rc == 1
}

/// Arm a one-shot refusal for the next request of exactly `size` bytes at the `(NULL, 0)` site.
pub(crate) fn arm(size: usize) {
    ARMED_SIZE.store(size, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
}

/// Disarm a refusal that was not consumed.
pub(crate) fn disarm() {
    ARMED.store(false, Ordering::SeqCst);
}

/// Clear the event log, the freed-pointer set and the double-release flag.
pub(crate) fn reset() {
    with_state(|s| {
        s.log.clear();
        s.freed.clear();
        s.double_free = false;
    });
}

/// A snapshot of the event log so far.
pub(crate) fn events() -> Vec<Ev> {
    with_state(|s| s.log.clone())
}

/// Whether a double release has been observed since the last [`reset`].
pub(crate) fn double_free() -> bool {
    with_state(|s| s.double_free)
}

/// A zeroed `Ssl` block allocated through the installed seam, the way `SSL_new` allocates it, so
/// the refusal tests can drive a ticket writer with only the few fields its failure path reads set.
///
/// # Safety
/// The returned pointer is NULL or a live zeroed `Ssl` block owned by the caller, whose single
/// release is `CRYPTO_free(ptr, NULL, 0)`.
pub(crate) unsafe fn zeroed_ssl() -> *mut Ssl {
    // `CRYPTO_zalloc` is a safe function: a zeroed block of `Ssl`'s size is what `SSL_new`
    // allocates; every field of `Ssl` has an all-zero valid value, and the caller sets the fields
    // the writer reads before it is used.
    CRYPTO_zalloc(core::mem::size_of::<Ssl>(), ptr::null(), 0).cast::<Ssl>()
}
