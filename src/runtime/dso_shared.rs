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
/// falls back to the local implementation, which is safe because a static link has one copy.
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

static ERR_GET_STATE: LazySymbol = LazySymbol::new();
static CONF_SSL_NAME_FIND: LazySymbol = LazySymbol::new();
static CONF_SSL_GET: LazySymbol = LazySymbol::new();
static CONF_SSL_GET_CMD: LazySymbol = LazySymbol::new();
static OPENSSL_INIT_CRYPTO: LazySymbol = LazySymbol::new();

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
