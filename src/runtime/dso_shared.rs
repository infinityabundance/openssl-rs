//! Cross-DSO shared runtime state — the link-shape repair `RT-CROSS-DSO-STATE` measures.
//!
//! The admitted authority ships one `libcrypto.so.3` and a `libssl.so.3` that imports its
//! `ERR_*` and `conf_ssl_*` owners through `DT_NEEDED`, so both DSOs observe **one** error
//! queue and **one** `ssl_conf` store. The Phase-2 distribution shell links the crate archive
//! `--whole-archive` into both DSOs, so each carries its own copy of those globals: an error
//! raised through libssl lands in libssl's queue, unreadable through libcrypto's exported
//! `ERR_peek_error`, and a `system_default` set `CONF_modules_load_file` stores through
//! libcrypto is invisible to libssl's `SSL_CTX_config`. That is the divergence 17.3 measured.
//!
//! This module restores the authority's binding **without** un-whole-archiving the crate: the
//! runtime resolves libcrypto's *exported* owners of the shared state at first use and routes
//! through them. libssl's own copies are hidden from the dynamic symbol table by its version
//! script (`local: *`), so `dlsym(RTLD_DEFAULT, ...)` finds libcrypto's definition from either
//! DSO — in libcrypto that is the local definition, in libssl it is the imported one, which is
//! exactly the authority's own binding. A static link has no such symbol and falls back to the
//! local implementation, where there is only one copy anyway.
//!
//! The state itself, its layout and every operation on it are unchanged: this is a
//! resolution-path repair, not a behavioural one. No symbol is added to either ABI — the
//! accessors reused here (`ERR_get_state`, `conf_ssl_name_find`, `conf_ssl_get`,
//! `conf_ssl_get_cmd`) are the authority's own libcrypto exports.
//!
//! The shared error ring owns heap buffers, so the same boundary applies to the allocator:
//! each DSO links its own copy of the `CRYPTO_*` function table, while a slot written through
//! one copy may be released by the other (the ring itself is shared). `crypto_malloc`,
//! `crypto_realloc` and `crypto_free` therefore route through libcrypto's exported entry
//! points, which are the table an application's `CRYPTO_set_mem_functions` hook modifies.
//! Without that, a hook-installed allocator allocated an `err_file` string in one DSO and
//! `ERR_clear_error` released it through the other, an invalid free.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use crate::runtime::conf::conf_ssl::SslConfCmd;
use crate::runtime::conf::init_settings::OpenSslInitSettings;
use crate::runtime::err::ErrState;

extern "C" {
    /// `void *dlsym(void *handle, const char *symbol)`, with `RTLD_DEFAULT` (a null handle)
    /// selecting the search of the global scope.
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// `RTLD_DEFAULT` — the null handle that makes `dlsym` walk the global symbol scope.
const RTLD_DEFAULT: *mut c_void = ptr::null_mut();

/// The resolution state of one cached symbol.
const UNRESOLVED: u8 = 0;
/// A thread is inside `dlsym` for this symbol; another lookup would be re-entrant.
const RESOLVING: u8 = 1;
/// The symbol resolved to `value`.
const PRESENT: u8 = 2;
/// The symbol is absent from the global scope; the local implementation is the only one.
const ABSENT: u8 = 3;

/// A lazily resolved `dlsym(RTLD_DEFAULT, name)` result.
///
/// The cache exists so the lookup runs once. `RESOLVING` is a re-entrancy guard: `dlsym` is
/// allowed to run code (an IFUNC resolver, for instance), and that code must not recurse into
/// an unbounded lookup. A caller that arrives while another is resolving sees the guard and
/// falls back to the local implementation. That is memory-safe in every link shape (a static
/// link has one copy; in a DSO the local copy is this object's own live implementation). The
/// residual is functional, not unsound: a first call that races a resolution may reach this
/// DSO's own `ERR_STATE`/`ssl_conf` store instead of libcrypto's. The lookup is performed
/// once, so only that first-call window is affected.
struct LazySymbol {
    state: AtomicU8,
    value: AtomicPtr<c_void>,
}

impl LazySymbol {
    const fn new() -> Self {
        LazySymbol {
            state: AtomicU8::new(UNRESOLVED),
            value: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// The address of `name` in the global scope, or null when it is absent (or is being
    /// resolved by a re-entrant caller).
    fn resolve(&self, name: &core::ffi::CStr) -> *mut c_void {
        loop {
            match self.state.load(Ordering::Acquire) {
                PRESENT => return self.value.load(Ordering::Acquire),
                ABSENT => return ptr::null_mut(),
                UNRESOLVED => {
                    if self
                        .state
                        .compare_exchange(
                            UNRESOLVED,
                            RESOLVING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        // SAFETY: `name` is a NUL-terminated static string.
                        let p = unsafe { dlsym(RTLD_DEFAULT, name.as_ptr()) };
                        if p.is_null() {
                            self.state.store(ABSENT, Ordering::Release);
                        } else {
                            self.value.store(p, Ordering::Release);
                            self.state.store(PRESENT, Ordering::Release);
                        }
                        return p;
                    }
                }
                _ => return ptr::null_mut(),
            }
        }
    }
}

/// `ERR_STATE *(*)(void)` — the signature of the authority's `ERR_get_state`.
type ErrGetStateFn = extern "C" fn() -> *mut ErrState;
/// `int (*)(const char *, size_t *)` — `conf_ssl_name_find`.
type NameFindFn = unsafe extern "C" fn(*const c_char, *mut usize) -> c_int;
/// `const SSL_CONF_CMD *(*)(size_t, const char **, size_t *)` — `conf_ssl_get`.
type GetFn = unsafe extern "C" fn(usize, *mut *const c_char, *mut usize) -> *const SslConfCmd;
/// `void (*)(const SSL_CONF_CMD *, size_t, char **, char **)` — `conf_ssl_get_cmd`.
type GetCmdFn = unsafe extern "C" fn(*const SslConfCmd, usize, *mut *mut c_char, *mut *mut c_char);
/// `int (*)(uint64_t, const OPENSSL_INIT_SETTINGS *)` — `OPENSSL_init_crypto`.
type InitCryptoFn = extern "C" fn(u64, *const OpenSslInitSettings) -> c_int;

/// `void *(*)(size_t, const char *, int)` — the authority's `CRYPTO_malloc`.
type MallocFn = unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void;
/// `void *(*)(void *, size_t, const char *, int)` — the authority's `CRYPTO_realloc`.
type ReallocFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void;
/// `void (*)(void *, const char *, int)` — the authority's `CRYPTO_free`.
type FreeFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int);

static ERR_GET_STATE: LazySymbol = LazySymbol::new();
static CONF_SSL_NAME_FIND: LazySymbol = LazySymbol::new();
static CONF_SSL_GET: LazySymbol = LazySymbol::new();
static CONF_SSL_GET_CMD: LazySymbol = LazySymbol::new();
static OPENSSL_INIT_CRYPTO: LazySymbol = LazySymbol::new();
static CRYPTO_MALLOC_SYM: LazySymbol = LazySymbol::new();
static CRYPTO_REALLOC_SYM: LazySymbol = LazySymbol::new();
static CRYPTO_FREE_SYM: LazySymbol = LazySymbol::new();

/// The process's shared `ERR_STATE` for this thread.
///
/// Resolves libcrypto's exported `ERR_get_state` so both DSOs reach **one** per-thread queue;
/// when there is no such symbol (a static link) it calls the local accessor instead.
pub(crate) fn err_state_ptr() -> *mut ErrState {
    let p = ERR_GET_STATE.resolve(c"ERR_get_state");
    if p.is_null() {
        crate::runtime::err::ERR_get_state()
    } else {
        // SAFETY: the symbol is the authority's `ERR_get_state`, whose prototype produced a
        // `*mut c_void` through `dlsym`; reinterpreting it as its own function pointer is the
        // only reading of that answer.
        let f: ErrGetStateFn = unsafe { core::mem::transmute(p) };
        f()
    }
}

/// `int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)`, routed through
/// libcrypto's exported owner so an SSL string-table load reaches the copy `ERR_reason_error_string`
/// reads through libcrypto. `SSL_CTX_new_ex` (`ssl_lib.c:4005`) is the caller.
pub(crate) fn openssl_init_crypto(opts: u64) -> c_int {
    let p = OPENSSL_INIT_CRYPTO.resolve(c"OPENSSL_init_crypto");
    if p.is_null() {
        crate::runtime::init::OPENSSL_init_crypto(opts, ptr::null())
    } else {
        // SAFETY: the symbol is the authority's `OPENSSL_init_crypto`; the settings pointer is a
        // NULL this function accepts.
        let f: InitCryptoFn = unsafe { core::mem::transmute(p) };
        f(opts, ptr::null())
    }
}

/// `int conf_ssl_name_find(const char *name, size_t *idx)`, shared across DSOs.
///
/// # Safety
/// Exactly the resolved function's contract: `name` is NULL or NUL-terminated and `idx` is
/// writable when a match is possible.
pub(crate) unsafe fn conf_ssl_name_find(name: *const c_char, idx: *mut usize) -> c_int {
    let p = CONF_SSL_NAME_FIND.resolve(c"conf_ssl_name_find");
    if p.is_null() {
        // SAFETY: forwarded per the caller's contract.
        unsafe { crate::runtime::conf::conf_ssl::conf_ssl_name_find(name, idx) }
    } else {
        // SAFETY: the symbol is the authority's `conf_ssl_name_find`.
        let f: NameFindFn = unsafe { core::mem::transmute(p) };
        // SAFETY: forwarded per the caller's contract.
        unsafe { f(name, idx) }
    }
}

/// `const SSL_CONF_CMD *conf_ssl_get(size_t idx, const char **name, size_t *cnt)`, shared.
///
/// # Safety
/// Exactly the resolved function's contract: `idx` is in range for the live store, and both
/// out-parameters are writable.
pub(crate) unsafe fn conf_ssl_get(
    idx: usize,
    name: *mut *const c_char,
    cnt: *mut usize,
) -> *const SslConfCmd {
    let p = CONF_SSL_GET.resolve(c"conf_ssl_get");
    if p.is_null() {
        // SAFETY: forwarded per the caller's contract.
        unsafe { crate::runtime::conf::conf_ssl::conf_ssl_get(idx, name, cnt) }
    } else {
        // SAFETY: the symbol is the authority's `conf_ssl_get`.
        let f: GetFn = unsafe { core::mem::transmute(p) };
        // SAFETY: forwarded per the caller's contract.
        unsafe { f(idx, name, cnt) }
    }
}

/// `void conf_ssl_get_cmd(const SSL_CONF_CMD *cmd, size_t idx, char **cmdstr, char **arg)`, shared.
///
/// # Safety
/// Exactly the resolved function's contract: `cmd` points at a set whose count exceeds `idx`,
/// and both out-parameters are writable.
pub(crate) unsafe fn conf_ssl_get_cmd(
    cmd: *const SslConfCmd,
    idx: usize,
    cmdstr: *mut *mut c_char,
    arg: *mut *mut c_char,
) {
    let p = CONF_SSL_GET_CMD.resolve(c"conf_ssl_get_cmd");
    if p.is_null() {
        // SAFETY: forwarded per the caller's contract.
        unsafe { crate::runtime::conf::conf_ssl::conf_ssl_get_cmd(cmd, idx, cmdstr, arg) }
    } else {
        // SAFETY: the symbol is the authority's `conf_ssl_get_cmd`.
        let f: GetCmdFn = unsafe { core::mem::transmute(p) };
        // SAFETY: forwarded per the caller's contract.
        unsafe { f(cmd, idx, cmdstr, arg) }
    }
}

// ---------------------------------------------------------------------------
// The process-global allocator seam
// ---------------------------------------------------------------------------

//
// The error ring outlives a single DSO's code path: a slot buffer can be written by libssl
// and released by libcrypto's `ERR_clear_error` (or the reverse). Allocating through *this*
// DSO's private `CRYPTO_malloc` and releasing through the other copy is only sound while both
// copies are the default libc pair; an application that installs `CRYPTO_set_mem_functions`
// gives libcrypto a different allocator, and the cross-copy release becomes an invalid free.
// These three wrappers make both halves name libcrypto's exported entry points, which is
// exactly the table `CRYPTO_set_mem_functions` writes. In libcrypto the lookup finds the local
// definition, so the wrapper is a pass-through there; a static link has no such symbol and
// falls back to the local implementation, where there is one copy and no boundary.

/// `CRYPTO_malloc`, routed through the process-global copy when the symbol exists.
///
/// # Safety
/// `file` is NULL or a NUL-terminated C string valid for the call.
pub(crate) unsafe fn crypto_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void {
    note_malloc();
    #[cfg(test)]
    {
        seam_probe::note_in_borrow();
        if seam_probe::take_failure() {
            return ptr::null_mut();
        }
    }
    let p = CRYPTO_MALLOC_SYM.resolve(c"CRYPTO_malloc");
    if p.is_null() {
        // SAFETY: forwarded per the caller's contract.
        unsafe { crate::runtime::mem::CRYPTO_malloc(num, file, line) }
    } else {
        // SAFETY: the symbol is the authority's `CRYPTO_malloc`, whose prototype produced this
        // `*mut c_void` through `dlsym`; the reinterpretation is the only reading of that answer.
        let f: MallocFn = unsafe { core::mem::transmute(p) };
        // SAFETY: forwarded per the caller's contract.
        unsafe { f(num, file, line) }
    }
}

/// `CRYPTO_realloc`, routed through the process-global copy when the symbol exists.
///
/// # Safety
/// `addr` is NULL or a live block from the same seam, and `file` is NULL or NUL-terminated.
pub(crate) unsafe fn crypto_realloc(
    addr: *mut c_void,
    num: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    #[cfg(test)]
    seam_probe::note_in_borrow();
    let p = CRYPTO_REALLOC_SYM.resolve(c"CRYPTO_realloc");
    if p.is_null() {
        // SAFETY: forwarded per the caller's contract.
        unsafe { crate::runtime::mem::CRYPTO_realloc(addr, num, file, line) }
    } else {
        // SAFETY: the symbol is the authority's `CRYPTO_realloc`; as `crypto_malloc`.
        let f: ReallocFn = unsafe { core::mem::transmute(p) };
        // SAFETY: forwarded per the caller's contract.
        unsafe { f(addr, num, file, line) }
    }
}

/// `CRYPTO_free`, routed through the process-global copy when the symbol exists.
///
/// # Safety
/// `ptr` is NULL or a live block from the same seam; `file` is NULL or NUL-terminated.
pub(crate) unsafe fn crypto_free(ptr: *mut c_void, file: *const c_char, line: c_int) {
    note_free(ptr);
    #[cfg(test)]
    seam_probe::note_in_borrow();
    let p = CRYPTO_FREE_SYM.resolve(c"CRYPTO_free");
    if p.is_null() {
        // SAFETY: forwarded per the caller's contract.
        unsafe { crate::runtime::mem::CRYPTO_free(ptr, file, line) }
    } else {
        // SAFETY: the symbol is the authority's `CRYPTO_free`; as `crypto_malloc`.
        let f: FreeFn = unsafe { core::mem::transmute(p) };
        // SAFETY: forwarded per the caller's contract.
        unsafe { f(ptr, file, line) }
    }
}

// Test-only observation of the seam the error ring uses, for the regression test that the
// slot buffers are allocated **and** released through these wrappers (the property that made
// an installed allocator invalid-free before). Thread-local so concurrent tests cannot
// perturb each other.
#[cfg(test)]
fn note_malloc() {
    seam_probe::malloc();
}

/// Test-only: arm `n` refusals of the process-global allocator. The next `crypto_malloc` calls
/// answer NULL without raising, which lets a test drive the ERR failure path deterministically.
#[cfg(test)]
pub(crate) fn arm_malloc_failure(n: usize) {
    seam_probe::arm_failure(n);
}

/// Test-only: consume the number of seam calls made while this DSO held the `&mut ErrState`.
#[cfg(test)]
pub(crate) fn take_in_borrow_probe() -> usize {
    seam_probe::take_in_borrow()
}
#[cfg(not(test))]
fn note_malloc() {}

#[cfg(test)]
fn note_free(ptr: *mut c_void) {
    seam_probe::free(ptr);
}
#[cfg(not(test))]
fn note_free(_ptr: *mut c_void) {}

/// Test-only: record the release of one specific block, by address identity.
///
/// Used by the thread-exit regression test for the error ring: the buffer's address is
/// read from the live `ERR_STATE` inside the thread, and the test then asserts that this
/// exact block was handed to `CRYPTO_free`. Recording one address (rather than counting
/// releases) keeps the observation immune to unrelated allocations, including those made
/// concurrently by other tests.
#[cfg(test)]
pub(crate) fn arm_free_observation(addr: usize) {
    seam_probe::arm_free_observation(addr);
}

/// Test-only: report whether the armed address has been released since it was armed, and
/// disarm. A missing observation is a failure, never an inferred pass.
#[cfg(test)]
pub(crate) fn take_free_observation() -> bool {
    seam_probe::take_free_observation()
}

/// Test-only: consume and return `(mallocs, frees)` observed on the process-global seam by
/// this thread since the previous call.
#[cfg(test)]
pub(crate) fn take_seam_probe() -> (usize, usize) {
    seam_probe::take()
}

// Kept last: it is a test module, and the lint forbids ordinary items after one.
#[cfg(test)]
mod seam_probe {
    use core::cell::Cell;
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    thread_local! {
        static MALLOCS: Cell<usize> = const { Cell::new(0) };
        static FREES: Cell<usize> = const { Cell::new(0) };
        static FAIL_MALLOCS: Cell<usize> = const { Cell::new(0) };
        static IN_BORROW: Cell<usize> = const { Cell::new(0) };
    }

    /// The one block whose release a probe is observing, or 0 when disarmed.
    static OBSERVED_ADDR: AtomicUsize = AtomicUsize::new(0);
    /// Whether `OBSERVED_ADDR` has been seen in a release since it was armed.
    static OBSERVED_SEEN: AtomicBool = AtomicBool::new(false);

    pub(super) fn arm_failure(n: usize) {
        let _ = FAIL_MALLOCS.try_with(|c| c.set(n));
    }

    /// Consume one armed refusal, answering true when this allocation must fail.
    pub(super) fn take_failure() -> bool {
        FAIL_MALLOCS
            .try_with(|c| {
                let n = c.get();
                if n == 0 {
                    false
                } else {
                    c.set(n - 1);
                    true
                }
            })
            .unwrap_or(false)
    }

    /// Record a seam call made while this DSO holds the `&mut ErrState`.
    pub(super) fn note_in_borrow() {
        if crate::runtime::err::state_borrowed() {
            let _ = IN_BORROW.try_with(|c| c.set(c.get() + 1));
        }
    }

    pub(super) fn take_in_borrow() -> usize {
        IN_BORROW.try_with(|c| c.replace(0)).unwrap_or(0)
    }

    pub(super) fn malloc() {
        let _ = MALLOCS.try_with(|n| n.set(n.get() + 1));
    }

    pub(super) fn free(ptr: *mut c_void) {
        let addr = ptr as usize;
        // Identity, not a count: a concurrent test's unrelated release cannot satisfy this.
        if addr != 0
            && OBSERVED_ADDR.load(Ordering::SeqCst) == addr
            && !OBSERVED_SEEN.swap(true, Ordering::SeqCst)
        {
            OBSERVED_ADDR.store(0, Ordering::SeqCst);
        }
        let _ = FREES.try_with(|n| n.set(n.get() + 1));
    }

    pub(super) fn arm_free_observation(addr: usize) {
        OBSERVED_SEEN.store(false, Ordering::SeqCst);
        OBSERVED_ADDR.store(addr, Ordering::SeqCst);
    }

    pub(super) fn take_free_observation() -> bool {
        let seen = OBSERVED_SEEN.swap(false, Ordering::SeqCst);
        OBSERVED_ADDR.store(0, Ordering::SeqCst);
        seen
    }

    pub(super) fn take() -> (usize, usize) {
        MALLOCS
            .try_with(|m| {
                FREES
                    .try_with(|f| (m.replace(0), f.replace(0)))
                    .unwrap_or((0, 0))
            })
            .unwrap_or((0, 0))
    }
}
