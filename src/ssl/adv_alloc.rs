//! Test-only allocator-injection harness for the SSL adversarial tests
//! (`stage/p25/adv-tests`, §16 negative controls / §18 verification schedule).
//!
//! It installs the crate's allocator seam (`CRYPTO_set_mem_functions`) with counting, recording
//! hooks and, on request, refuses one allocation at a chosen authority coordinate, so a test can
//! drive the `SSL_SESSION` ticket writers and the member-buffer handles through their
//! allocation-refusal path and observe the exact allocator-event sequence.
//!
//! Installing an allocator is a **process-global** act, so each probe test that uses this module is
//! `#[ignore]`d: the ordinary `cargo test --lib` suite reports it as **ignored** (never as a false
//! pass), and it executes only under `OPENSSL_RS_ADV_PROBE=1` with `--ignored`. Each probe then runs
//! alone in its own process (`--exact --test-threads=1`), because the allocator hook persists for
//! the life of the process. `scripts/adv-probe.sh` is the one-process-per-probe runner.
//!
//! The probes are **self-verifying and hard-failing** (§16): [`require_installed`] panics when the
//! gate is set but the seam refuses the hook, and [`assert_instrument_live`] proves the recording
//! hook actually observes allocations before a probe trusts its transcript. A dead detector cannot
//! report a green run.
//!
//! This module is never linked into a release build: it is declared `#[cfg(test)]` in `ssl/mod.rs`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_set_mem_functions, CRYPTO_zalloc};
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
    /// A `CRYPTO_realloc` request of `n` bytes. `refused` is true when the hook answered NULL
    /// instead of forwarding, leaving the old block (if any) untouched and owned by the caller.
    Realloc { n: usize, refused: bool },
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
    /// The member `(ptr, len)` pair an armed reentrant realloc hook observed *during* the call, if
    /// any. `None` means the reenter observer did not fire.
    reenter_obs: Option<(usize, usize)>,
}

static STATE: Mutex<State> = Mutex::new(State {
    log: Vec::new(),
    freed: Vec::new(),
    double_free: false,
    reenter_obs: None,
});

/// One-shot refusal: set by [`arm`], consumed by the first matching request in `hook_malloc`.
static ARMED: AtomicBool = AtomicBool::new(false);
static ARMED_SIZE: AtomicUsize = AtomicUsize::new(0);
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// One-shot realloc interception: refuse (or merely observe) the next `CRYPTO_realloc` of
/// `REALLOC_SIZE` bytes. A refused request answers NULL without forwarding, so the incumbent block
/// is kept exactly as `realloc`'s failure contract requires.
static REALLOC_ARMED: AtomicBool = AtomicBool::new(false);
static REALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);
static REALLOC_REFUSE: AtomicBool = AtomicBool::new(false);

/// Reentrancy observation: when armed, the intercepted realloc hook reads the member pair whose
/// field addresses the test supplied, *before* forwarding to the real allocator. This models an
/// allocator/callback that reenters and inspects the caller's state mid-call.
static REENTER_ARMED: AtomicBool = AtomicBool::new(false);
static REENTER_PTR: AtomicUsize = AtomicUsize::new(0);
static REENTER_LEN: AtomicUsize = AtomicUsize::new(0);

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

/// The recording `CRYPTO_realloc` shim. An armed request of the chosen size is recorded and
/// either refused (NULL, incumbent kept) or forwarded after the optional reentrancy observation.
unsafe extern "C" fn hook_realloc(
    p: *mut c_void,
    n: usize,
    _file: *const c_char,
    _line: c_int,
) -> *mut c_void {
    let intercept =
        REALLOC_ARMED.load(Ordering::SeqCst) && n == REALLOC_SIZE.load(Ordering::SeqCst);
    if intercept {
        // One-shot, exactly like the malloc refusal.
        REALLOC_ARMED.store(false, Ordering::SeqCst);
        let refuse = REALLOC_REFUSE.load(Ordering::SeqCst);
        if REENTER_ARMED.load(Ordering::SeqCst) {
            REENTER_ARMED.store(false, Ordering::SeqCst);
            let pp = REENTER_PTR.load(Ordering::SeqCst) as *const *mut u8;
            let pl = REENTER_LEN.load(Ordering::SeqCst) as *const usize;
            if !pp.is_null() && !pl.is_null() {
                // SAFETY: the test armed these as the addresses of the live member pair it is
                // watching; both are readable for the duration of this call. Reading the pair
                // here (before forwarding) is the reentrancy probe: the caller's state must not
                // be partially published at the allocator boundary.
                let observed = unsafe { (*pp as usize, *pl) };
                with_state(|s| s.reenter_obs = Some(observed));
            }
        }
        with_state(|s| s.log.push(Ev::Realloc { n, refused: refuse }));
        if refuse {
            // The allocator failure contract: answer NULL and do **not** touch the incumbent, so
            // the caller still owns (and must still release) it.
            return ptr::null_mut();
        }
    }
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
/// allocation already ran in this process), i.e. the test is not running alone. Callers must not
/// skip on false: [`require_installed`] turns it into a hard failure.
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

/// Hard-fail unless the gate is set and the recording allocator installed.
///
/// Unlike the old probe bodies this never returns success on a failed installation: a broken or
/// unavailable detector must fail the run, not silently pass. Call it at the top of every probe
/// test (after taking [`crate::test_support::lock_global_state`]).
///
/// The gate check is retained even though the probes are `#[ignore]`d, so an accidental
/// `--ignored` run without `OPENSSL_RS_ADV_PROBE=1` fails loudly instead of exercising nothing.
pub(crate) fn require_installed() {
    assert!(
        probe_enabled(),
        "OPENSSL_RS_ADV_PROBE=1 is required; run scripts/adv-probe.sh (or pass --ignored with the \
         gate set)"
    );
    assert!(
        install(),
        "the recording allocator hook did not install (the seam refused it); run this probe alone \
         in its own process with --exact --test-threads=1"
    );
}

/// Self-verify the instrument (§16): prove the installed hooks actually observe this process's
/// allocations. A probe that cannot see a known `CRYPTO_malloc`/`CRYPTO_free` pair must not trust
/// its own transcript, so this panics rather than returning.
pub(crate) fn assert_instrument_live() {
    reset();
    let p = CRYPTO_malloc(8, ptr::null(), 0);
    assert!(
        !p.is_null(),
        "probe self-check: a fresh 8-byte allocation failed"
    );
    // SAFETY: `p` is the fresh block the previous line returned and has not been released.
    unsafe { CRYPTO_free(p, ptr::null(), 0) };
    let ev = events();
    assert!(
        ev.iter().any(|e| matches!(e, Ev::Malloc { .. })),
        "the recording malloc hook is not live: no Malloc event observed"
    );
    assert!(
        ev.iter().any(|e| matches!(e, Ev::Free { .. })),
        "the recording free hook is not live: no Free event observed"
    );
    reset();
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

/// Arm a one-shot interception of the next `CRYPTO_realloc` of exactly `size` bytes.
///
/// `refuse == true` answers NULL (the incumbent is kept untouched); `refuse == false` records the
/// event and forwards. Either way the interception is consumed by the first matching request.
pub(crate) fn arm_realloc(size: usize, refuse: bool) {
    REALLOC_SIZE.store(size, Ordering::SeqCst);
    REALLOC_REFUSE.store(refuse, Ordering::SeqCst);
    REALLOC_ARMED.store(true, Ordering::SeqCst);
}

/// Disarm a realloc interception that was not consumed.
pub(crate) fn disarm_realloc() {
    REALLOC_ARMED.store(false, Ordering::SeqCst);
}

/// Arm the reentrancy observer for the next intercepted realloc. `ptr_field`/`len_field` are the
/// addresses of the member pair the observer reads during the call.
pub(crate) fn arm_reenter(ptr_field: *mut *mut u8, len_field: *mut usize) {
    REENTER_PTR.store(ptr_field as usize, Ordering::SeqCst);
    REENTER_LEN.store(len_field as usize, Ordering::SeqCst);
    REENTER_ARMED.store(true, Ordering::SeqCst);
}

/// The member pair the reentrancy observer captured during the last intercepted realloc.
pub(crate) fn reenter_observed() -> Option<(usize, usize)> {
    with_state(|s| s.reenter_obs)
}

/// Clear the event log, the freed-pointer set, the double-release flag, the reentrancy
/// observation and any un-consumed arming.
pub(crate) fn reset() {
    REALLOC_ARMED.store(false, Ordering::SeqCst);
    REENTER_ARMED.store(false, Ordering::SeqCst);
    with_state(|s| {
        s.log.clear();
        s.freed.clear();
        s.double_free = false;
        s.reenter_obs = None;
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
