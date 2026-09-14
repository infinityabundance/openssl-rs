//! Phase 3 core runtime — the `ERR` subsystem.
//!
//! OpenSSL's error queue is **thread-local state**, and
//! `docs/CONCURRENCY_MODEL.md` names it the canonical example of a surface that
//! applications observe directly. So the queue is implemented as a faithful
//! mechanism, not as a `Result<T, E>`: an error carries a library, a reason, a
//! file/line/function, optional textual data, and a position in a bounded
//! per-thread ring with marks.
//!
//! ## The ring is the public layout, so the ring is the store
//!
//! `ERR_STATE` is a **public structure** in `err.h` (guarded only by
//! `OPENSSL_NO_DEPRECATED_3_0`, which this profile does not define) and
//! `ERR_get_state` returns a pointer to it. A caller can therefore read
//! `es->top`, `es->bottom`, `es->err_buffer[i]`, `es->err_flags[i]` and so on
//! directly. That rules out keeping the queue in some private Rust collection
//! with a mirrored view: the ring *is* the representation here, matching the
//! authority slot for slot.
//!
//! ```text
//! ERR_new:  top = (top + 1) % 16 ; if top == bottom { bottom = (bottom + 1) % 16 }
//! ```
//!
//! The oldest error is at `(bottom + 1) % 16`, the newest at `top`, and a slot is
//! complete exactly when its `err_buffer` is non-zero. Sixteen slots therefore
//! hold fifteen usable errors, which is a real capacity detail rather than an
//! off-by-one to be "fixed".
//!
//! ## Packing
//!
//! `ERR_PACK(lib, func, reason)` discards `func` in 3.x and evaluates to
//! `(lib & 0xff) << 23 | (reason & 0x7fffff)`, so the value `ERR_get_error`
//! returns encodes only library and reason. `ERR_LIB_SYS` is special-cased to
//! `ERR_SYSTEM_FLAG | reason`. All of that is caller-observable and is
//! reproduced exactly.
//!
//! ## Strings
//!
//! The library and reason tables are compiled into the authority, but they are
//! **not** always visible: the registry starts empty and is populated by loaders
//! driven by initialisation (`docs/DECISIONS.md` D19). They are rebuilt from the
//! authority's own inputs by `forensics/tools/gen_err_strings.py` — the compiled
//! `*_err.c` arrays for the text, the headers for the codes — and verified
//! exhaustively by the RT-ERR court: every `(library, reason)` pair in the crypto
//! load set, every generic reason, all 357 SSL reasons on both sides of their
//! load flag, and the six reasons no loader loads. `ERR_func_error_string` is
//! unconditionally NULL in 3.x, and the rendered form is
//! `error:%08lX:lib:func:reason` with an `err:...` fallback when the pretty form
//! exactly fills the buffer, which is what `ERR_error_string_n` produces.
//!
//! ## Where a raise happened
//!
//! `ERR_raise` is a macro that records `OPENSSL_FILE`, `OPENSSL_LINE` and
//! `OPENSSL_FUNC` as well, and `ERR_get_error_all` hands them to the caller. They
//! are part of the observed contract and are reproduced exactly, from the
//! generated [`err_sites`] table
//! (`forensics/tools/gen_err_raise_sites.py`; `docs/DECISIONS.md` D20).
//!
//! ## Variadic entry points
//!
//! `ERR_set_error`, `ERR_vset_error` and `ERR_add_error_data` are printf-style
//! variadic C functions. Rust cannot *define* a C-variadic function on stable, so
//! those are thin C adapters (`err_variadic.c`) that format through `vsnprintf`
//! and call back into the Rust core below. All behaviour lives in Rust.
//!
//! ## Locking
//!
//! The state is reached through `UnsafeCell`, not a `RefCell`. That is not a
//! shortcut: the authority re-enters its own state from inside these operations
//! (a `CRYPTO_malloc` inside `err_set_debug`, for example), and a runtime borrow
//! check would turn that into a panic where the authority simply proceeds. The
//! absence of a borrow check is therefore part of the contract, and the
//! invariants that make it sound are stated at each access.

use core::cell::{Cell, UnsafeCell};
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::init;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

#[path = "err_strings.rs"]
mod err_strings;

#[path = "err_sites.rs"]
pub(crate) mod err_sites;

#[path = "err_loaders.rs"]
mod err_loaders;

/// `ERR_NUM_ERRORS`. The ring depth. The authority's ring holds this many slots,
/// one of which is always the gap between `bottom` and `top`, so the usable
/// depth is one less.
const ERR_NUM_ERRORS: usize = 16;

/// `ERR_FLAG_MARK` — historical; marks live in `err_marks` in 3.x.
#[allow(dead_code)]
const ERR_FLAG_MARK: c_int = 0x01;
/// `ERR_FLAG_CLEAR` — a slot marked for lazy clearing by the next read.
const ERR_FLAG_CLEAR: c_int = 0x02;
/// `ERR_TXT_MALLOCED` — the data buffer is owned by this state.
const ERR_TXT_MALLOCED: c_int = 0x01;
/// `ERR_TXT_STRING` — the data is a C string.
const ERR_TXT_STRING: c_int = 0x02;

/// `ERR_LIB_SYS`, the one library whose errors are packed as system codes.
const ERR_LIB_SYS: c_int = 2;

/// `ERR_SYSTEM_MASK` (`err.h`): the low bits of a system error.
const ERR_SYSTEM_MASK: c_ulong = 0x7FFF_FFFF;

/// `ERR_SYSTEM_FLAG`.
const ERR_SYSTEM_FLAG: c_ulong = 0x8000_0000;
/// `ERR_RFLAGS_MASK` / `ERR_RFLAGS_OFFSET`, used to strip the flag bits from a
/// reason when rendering the numeric fallback.
const ERR_RFLAGS_MASK: c_ulong = 0x1F;
const ERR_RFLAGS_OFFSET: c_ulong = 18;

const ERR_LIB_OFFSET: c_ulong = 23;
const ERR_LIB_MASK: c_ulong = 0xFF;
const ERR_REASON_MASK: c_ulong = 0x7FFFFF;

/// The layout-compatible representation of C's `ERR_STATE`.
///
/// Public and documented in `err.h`, so every field offset matters. Field names
/// and order are taken from that header rather than chosen.
#[repr(C)]
pub struct ErrState {
    /// `int err_flags[ERR_NUM_ERRORS]`
    pub err_flags: [c_int; ERR_NUM_ERRORS],
    /// `int err_marks[ERR_NUM_ERRORS]` — per-slot mark counters.
    pub err_marks: [c_int; ERR_NUM_ERRORS],
    /// `unsigned long err_buffer[ERR_NUM_ERRORS]` — the packed error, 0 if the
    /// slot is incomplete.
    pub err_buffer: [c_ulong; ERR_NUM_ERRORS],
    /// `char *err_data[ERR_NUM_ERRORS]`
    pub err_data: [*mut c_char; ERR_NUM_ERRORS],
    /// `size_t err_data_size[ERR_NUM_ERRORS]`
    pub err_data_size: [usize; ERR_NUM_ERRORS],
    /// `int err_data_flags[ERR_NUM_ERRORS]`
    pub err_data_flags: [c_int; ERR_NUM_ERRORS],
    /// `char *err_file[ERR_NUM_ERRORS]`
    pub err_file: [*mut c_char; ERR_NUM_ERRORS],
    /// `int err_line[ERR_NUM_ERRORS]`
    pub err_line: [c_int; ERR_NUM_ERRORS],
    /// `char *err_func[ERR_NUM_ERRORS]`
    pub err_func: [*mut c_char; ERR_NUM_ERRORS],
    /// `int top` — where the next error goes.
    pub top: c_int,
    /// `int bottom` — the gap behind the oldest error.
    pub bottom: c_int,
}

impl ErrState {
    const fn new() -> Self {
        ErrState {
            err_flags: [0; ERR_NUM_ERRORS],
            err_marks: [0; ERR_NUM_ERRORS],
            err_buffer: [0; ERR_NUM_ERRORS],
            err_data: [core::ptr::null_mut(); ERR_NUM_ERRORS],
            err_data_size: [0; ERR_NUM_ERRORS],
            err_data_flags: [0; ERR_NUM_ERRORS],
            err_file: [core::ptr::null_mut(); ERR_NUM_ERRORS],
            err_line: [0; ERR_NUM_ERRORS],
            err_func: [core::ptr::null_mut(); ERR_NUM_ERRORS],
            top: 0,
            bottom: 0,
        }
    }

    /// `err_get_slot`: advance `top`, and drag `bottom` forward once the ring is
    /// full. That one-slot gap is why fifteen errors survive, not sixteen.
    fn get_slot(&mut self) {
        let n = ERR_NUM_ERRORS as c_int;
        self.top = (self.top + 1) % n;
        if self.top == self.bottom {
            self.bottom = (self.bottom + 1) % n;
        }
    }

    /// `err_clear_data`. With `deall` the buffer is released; without it a
    /// malloced buffer is kept but truncated, which is how the authority reuses
    /// data buffers across clears.
    fn clear_data(&mut self, i: usize, deall: bool) {
        if (self.err_data_flags[i] & ERR_TXT_MALLOCED) != 0 {
            if deall {
                // SAFETY: the MALLOCED flag says this state owns the pointer.
                unsafe { CRYPTO_free(self.err_data[i].cast::<c_void>(), core::ptr::null(), 0) };
                self.err_data[i] = core::ptr::null_mut();
                self.err_data_size[i] = 0;
                self.err_data_flags[i] = 0;
            } else if !self.err_data[i].is_null() {
                // SAFETY: as above; the buffer is at least one byte.
                unsafe { *self.err_data[i] = 0 };
                self.err_data_flags[i] = ERR_TXT_MALLOCED;
            }
        } else {
            self.err_data[i] = core::ptr::null_mut();
            self.err_data_size[i] = 0;
            self.err_data_flags[i] = 0;
        }
    }

    /// `err_clear`.
    fn clear(&mut self, i: usize, deall: bool) {
        self.clear_data(i, deall);
        self.err_marks[i] = 0;
        self.err_flags[i] = 0;
        self.err_buffer[i] = 0;
        self.err_line[i] = -1;
        // SAFETY: these pointers are always either NULL or owned by this state.
        unsafe {
            CRYPTO_free(self.err_file[i].cast::<c_void>(), core::ptr::null(), 0);
            self.err_file[i] = core::ptr::null_mut();
            CRYPTO_free(self.err_func[i].cast::<c_void>(), core::ptr::null(), 0);
            self.err_func[i] = core::ptr::null_mut();
        }
    }

    /// `err_set_error`. System errors carry `ERR_SYSTEM_FLAG` instead of a
    /// packed library, and that difference is visible through `ERR_get_error`.
    ///
    /// The authority narrows to `unsigned int` here rather than masking to
    /// `ERR_REASON_MASK`, so a reason wider than the mask keeps its high bits.
    fn set_error(&mut self, i: usize, lib: c_int, reason: c_int) {
        self.err_buffer[i] = if lib == ERR_LIB_SYS {
            ((reason as u32) | (ERR_SYSTEM_FLAG as u32)) as c_ulong
        } else {
            pack(lib as c_ulong, reason as c_ulong)
        };
    }

    /// `err_set_debug`. The strings are **duplicated**: the authority notes they
    /// "may be provider owned", and a provider can be unloaded while the error
    /// is still queued. A NULL or empty string is stored as NULL, and the read
    /// side turns NULL back into `""`.
    fn set_debug(&mut self, i: usize, file: *const c_char, line: c_int, func: *const c_char) {
        // SAFETY: ownership of these pointers is this state's.
        unsafe {
            CRYPTO_free(self.err_file[i].cast::<c_void>(), core::ptr::null(), 0);
            self.err_file[i] = dup_c_string(file);
            CRYPTO_free(self.err_func[i].cast::<c_void>(), core::ptr::null(), 0);
            self.err_func[i] = dup_c_string(func);
        }
        self.err_line[i] = line;
    }

    /// `err_set_data`.
    fn set_data(&mut self, i: usize, data: *mut c_char, size: usize, flags: c_int) {
        if (self.err_data_flags[i] & ERR_TXT_MALLOCED) != 0 {
            // SAFETY: MALLOCED means this state owns the buffer.
            unsafe { CRYPTO_free(self.err_data[i].cast::<c_void>(), core::ptr::null(), 0) };
        }
        self.err_data[i] = data;
        self.err_data_size[i] = size;
        self.err_data_flags[i] = flags;
    }

    /// The oldest index, `(bottom + 1) % 16`.
    fn oldest(&self) -> usize {
        ((self.bottom as usize) + 1) % ERR_NUM_ERRORS
    }

    /// Apply the pending `ERR_FLAG_CLEAR` slots, as `get_error_values` does
    /// before answering any read.
    fn settle_clears(&mut self) {
        let n = ERR_NUM_ERRORS as c_int;
        while self.bottom != self.top {
            if (self.err_flags[self.top as usize] & ERR_FLAG_CLEAR) != 0 {
                let t = self.top as usize;
                self.clear(t, false);
                self.top = if self.top > 0 { self.top - 1 } else { n - 1 };
                continue;
            }
            let i = (self.bottom + 1) % n;
            if (self.err_flags[i as usize] & ERR_FLAG_CLEAR) != 0 {
                self.bottom = i;
                let b = self.bottom as usize;
                self.clear(b, false);
                continue;
            }
            break;
        }
    }
}

// SAFETY: the state is only ever reached through the thread-local `STATE`, so a
// `&mut ErrState` derived from it is never observable by another thread. The
// `Sync` marker is required by `thread_local!`, not a claim that this type is
// shareable.
unsafe impl Sync for ErrState {}

/// The empty C string stored in place of NULL so the read side can hand back a
/// non-NULL `""` without allocating, exactly as the authority does.
const EMPTY_C: *const c_char = c"".as_ptr();

/// `ERR_PACK(lib, 0, reason)`. The function field is discarded in 3.x.
fn pack(lib: c_ulong, reason: c_ulong) -> c_ulong {
    ((lib & ERR_LIB_MASK) << ERR_LIB_OFFSET) | (reason & ERR_REASON_MASK)
}

/// `ERR_GET_LIB`.
///
/// A system error does not carry a packed library; the authority answers
/// `ERR_LIB_SYS` for it, which is why `ERR_lib_error_string(0x80000002)` renders
/// as "system library" rather than as library 0.
fn get_lib(e: c_ulong) -> c_ulong {
    if (e & ERR_SYSTEM_FLAG) != 0 {
        ERR_LIB_SYS as c_ulong
    } else {
        (e >> ERR_LIB_OFFSET) & ERR_LIB_MASK
    }
}

/// `ERR_GET_REASON`.
fn get_reason(e: c_ulong) -> c_ulong {
    if (e & ERR_SYSTEM_FLAG) != 0 {
        e & ERR_SYSTEM_MASK
    } else {
        e & ERR_REASON_MASK
    }
}

/// Duplicate a C string for storage in the ring, or NULL for NULL/empty input.
///
/// # Safety
/// `s` must be NULL or a NUL-terminated C string.
unsafe fn dup_c_string(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `s` is NUL-terminated per the caller's contract.
    let len = unsafe { c_strlen(s) };
    if len == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: allocating `len + 1` bytes and copying exactly that many.
    unsafe {
        let p = CRYPTO_malloc(len + 1, core::ptr::null(), 0).cast::<c_char>();
        if p.is_null() {
            return core::ptr::null_mut();
        }
        core::ptr::copy_nonoverlapping(s, p, len);
        *p.add(len) = 0;
        p
    }
}

/// # Safety
/// `s` must be a NUL-terminated C string.
unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: NUL-terminated, so the loop leaves the allocation.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

thread_local! {
    /// The per-thread error state. `UnsafeCell` rather than `RefCell` because
    /// these operations legitimately re-enter the state (see the module note).
    static STATE: UnsafeCell<ErrState> = const { UnsafeCell::new(ErrState::new()) };
    /// Whether this thread has already performed the authority's per-thread
    /// state creation, which is what loads the crypto error strings.
    static STATE_READY: Cell<bool> = const { Cell::new(false) };
}

// ---------------------------------------------------------------------------
// The string registry is loaded, not compiled in
// ---------------------------------------------------------------------------
//
// The authority's `int_error_hash` starts empty. `ossl_err_get_state_int`
// creates a thread's `ERR_STATE` and then runs
// `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS)` -- "ignore failures
// from these" -- which loads the generic tables and every library in
// `ossl_err_load_crypto_strings`. SSL is deliberately not in that set; its
// strings appear only when `OPENSSL_INIT_LOAD_SSL_STRINGS` is processed. Both
// facts are observable through `ERR_reason_error_string`, and the RT-ERR probe
// measures them, including the window before any ERR call has run at all.

/// The generic tables (`ERR_str_libraries`, `ERR_str_reasons`) have been loaded.
static GENERIC_LOADED: AtomicBool = AtomicBool::new(false);
/// Bit `lib` set means that library's reason table has been loaded.
static LIB_LOADED: AtomicU64 = AtomicU64::new(0);

/// `ERR_LIB_SSL`. Its table arrives through a different initialisation flag.
const ERR_LIB_SSL: u32 = 20;

/// Load the generic tables. `ossl_err_load_ERR_strings`. Idempotent.
pub(crate) fn load_generic() {
    GENERIC_LOADED.store(true, Ordering::Release);
}

/// Load one library's reason table. Idempotent.
pub(crate) fn load_lib(lib: u32) {
    load_generic();
    if lib < 64 {
        LIB_LOADED.fetch_or(1u64 << lib, Ordering::AcqRel);
    }
}

/// `ossl_err_load_crypto_strings` — the generic tables plus the crypto set.
pub(crate) fn load_crypto_strings() {
    load_generic();
    let mut mask = 0u64;
    for &lib in err_strings::CRYPTO_LIBS {
        if (lib as u32) < 64 {
            mask |= 1u64 << lib;
        }
    }
    LIB_LOADED.fetch_or(mask, Ordering::AcqRel);
}

/// `ossl_err_load_SSL_strings` — the generic tables plus library 20.
pub(crate) fn load_ssl_strings() {
    load_lib(ERR_LIB_SSL);
}

/// `err_cleanup` — the registry is torn down, so nothing is visible afterwards.
pub(crate) fn unload_strings() {
    GENERIC_LOADED.store(false, Ordering::Release);
    LIB_LOADED.store(0, Ordering::Release);
}

fn generic_loaded() -> bool {
    GENERIC_LOADED.load(Ordering::Acquire)
}

fn lib_loaded(lib: u32) -> bool {
    lib < 64 && (LIB_LOADED.load(Ordering::Acquire) & (1u64 << lib)) != 0
}

/// Run `f` with this thread's error state. `None` during thread teardown and
/// after `OPENSSL_cleanup`, both of which the authority treats as "no state":
/// `ossl_err_get_state_int` returns NULL once `OPENSSL_init_crypto` refuses.
fn with_state<R>(f: impl FnOnce(&mut ErrState) -> R) -> Option<R> {
    if init::stopped() {
        return None;
    }
    // First ERR call on this thread: the authority creates the `ERR_STATE` and
    // that creation is what loads the crypto error strings.
    let _ = STATE_READY.try_with(|r| {
        if !r.replace(true) {
            load_crypto_strings();
        }
    });
    STATE
        .try_with(|s| {
            // SAFETY: the `UnsafeCell` is thread-local, so the only way to reach
            // it is through this closure on this thread. `f` must not retain the
            // reference; every caller here uses it for the duration of the call.
            f(unsafe { &mut *s.get() })
        })
        .ok()
}

/// Raise a complete error from inside the library, the way the authority's
/// `ERR_raise` macro does.
///
/// This is the crate-internal path (the public `ERR_set_error` is C-variadic and
/// cannot be called from Rust). `file`/`line` are the values the *raising
/// function received*, because the authority attributes such errors to its
/// caller: `CRYPTO_malloc_array` on overflow reports the caller's file and line,
/// which the RT-MEM probe measures directly through `ERR_peek_error_all`. The
/// function name is the empty string, which `err_set_debug` stores as NULL and
/// the read side renders as `""`; no data is attached, so the flags read as 0.
///
/// # Safety
/// `file` must be NULL or a NUL-terminated C string.
pub(crate) unsafe fn raise_with(lib: c_int, reason: c_int, file: *const c_char, line: c_int) {
    with_state(|s| {
        s.get_slot();
        let t = s.top as usize;
        s.clear(t, false);
        s.set_debug(t, file, line, EMPTY_C);
        s.set_error(t, lib, reason);
    });
}

/// `ERR_raise(lib, reason)` at a recorded authority site.
///
/// The three debug strings are not invented: they are the authority's own
/// `OPENSSL_FILE`/`OPENSSL_LINE`/`OPENSSL_FUNC` values for the site this code
/// path is reconstructing, derived by `forensics/tools/gen_err_raise_sites.py`
/// from the pinned source and the admitted build record. `ERR_get_error_all` and
/// `ERR_print_errors` hand them to the caller, so they are observed contract.
///
/// # Safety
/// The `ErrSite` is a compile-time constant whose pointers are static.
pub(crate) unsafe fn raise_site(site: &err_sites::ErrSite) {
    with_state(|s| {
        s.get_slot();
        let t = s.top as usize;
        s.clear(t, false);
        s.set_debug(t, site.file.as_ptr(), site.line, site.func.as_ptr());
        s.set_error(t, site.lib, site.reason);
    });
}

/// `ERR_raise(lib, reason)` at a recorded authority site whose *reason* the
/// authority computes at run time.
///
/// Several authority sites raise `ERR_LIB_SYS` with the current `errno` (or a
/// negated return value) instead of a header constant. The file, line and
/// function are still the authority's own, so they come from the recorded site;
/// only the reason is supplied by the caller. `gen_err_raise_sites.py` marks
/// those sites with `dynamic_reason` so this function is used for exactly them.
///
/// # Safety
/// The `ErrSite` is a compile-time constant whose pointers are static.
pub(crate) unsafe fn raise_site_dynamic(site: &err_sites::ErrSite, reason: c_int) {
    // The generated table marks which sites compute their reason at run time. This
    // assertion is the only reader of that flag, and it exists so the distinction
    // cannot rot: if a future edit routes a constant-reason site through here, the
    // mistake shows up in tests rather than as a wrong reason code in production.
    debug_assert!(
        site.dynamic_reason,
        "raise_site_dynamic used with a constant-reason site"
    );
    with_state(|s| {
        s.get_slot();
        let t = s.top as usize;
        s.clear(t, false);
        s.set_debug(t, site.file.as_ptr(), site.line, site.func.as_ptr());
        s.set_error(t, site.lib, reason);
    });
}

/// `ERR_raise_data(lib, reason, "...")` at a recorded authority site.
///
/// The authority's `ERR_vset_error` formats the message into an allocated
/// buffer, marks it `ERR_TXT_MALLOCED | ERR_TXT_STRING`, and stores its length
/// including the terminator. `msg` is that already-formatted buffer's content.
///
/// # Safety
/// `msg` must be NULL or a NUL-terminated C string.
pub(crate) unsafe fn raise_site_data(site: &err_sites::ErrSite, msg: *const c_char) {
    with_state(|s| {
        s.get_slot();
        let t = s.top as usize;
        s.clear(t, false);
        s.set_debug(t, site.file.as_ptr(), site.line, site.func.as_ptr());
        s.set_error(t, site.lib, site.reason);
        if msg.is_null() {
            return;
        }
        // SAFETY: `msg` is NUL-terminated per the caller's contract.
        let len = unsafe { c_strlen(msg) };
        // SAFETY: allocate `len + 1`, copy, terminate.
        unsafe {
            let p = CRYPTO_malloc(len + 1, core::ptr::null(), 0).cast::<c_char>();
            if p.is_null() {
                return;
            }
            core::ptr::copy_nonoverlapping(msg, p, len);
            *p.add(len) = 0;
            s.set_data(t, p, len + 1, ERR_TXT_MALLOCED | ERR_TXT_STRING);
        }
    });
}

/// `ERR_STATE *ERR_get_state(void)`
///
/// The pointer is into thread-local storage, exactly as in the authority, and
/// stays valid until the thread exits.
#[no_mangle]
pub extern "C" fn ERR_get_state() -> *mut ErrState {
    guard_ffi(core::ptr::null_mut(), || {
        STATE.try_with(|s| s.get()).unwrap_or(core::ptr::null_mut())
    })
}

/// `void ERR_new(void)`
///
/// Claims a slot and clears it. The slot is *incomplete* — `err_buffer` is zero —
/// until `ERR_set_error` supplies a library and reason, which is what makes an
/// interrupted `ERR_raise` invisible to `ERR_get_error`.
#[no_mangle]
pub extern "C" fn ERR_new() {
    guard_ffi((), || {
        with_state(|s| {
            s.get_slot();
            let t = s.top as usize;
            s.clear(t, false);
        });
    })
}

/// `void ERR_set_debug(const char *file, int line, const char *func)`
///
/// # Safety
/// `file` and `func` must each be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ERR_set_debug(file: *const c_char, line: c_int, func: *const c_char) {
    guard_ffi((), || {
        with_state(|s| {
            let t = s.top as usize;
            s.set_debug(t, file, line, func);
        });
    })
}

/// Writes library, reason and message into the current slot. Called by the
/// variadic C adapters so that all state changes live in Rust.
///
/// A NULL `msg` clears any data, matching the authority: `ERR_raise(lib, reason)`
/// is `ERR_set_error(lib, reason, NULL)`, and that resets the data rather than
/// leaving whatever was there.
///
/// # Safety
/// `msg` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_err_set_error(lib: c_int, reason: c_int, msg: *const c_char) {
    guard_ffi((), || {
        with_state(|s| {
            let t = s.top as usize;
            s.clear_data(t, false);
            s.set_error(t, lib, reason);
            if msg.is_null() {
                return;
            }
            // SAFETY: `msg` is NUL-terminated per the caller's contract.
            let len = unsafe { c_strlen(msg) };
            // SAFETY: allocate `len + 1`, copy, terminate.
            unsafe {
                let p = CRYPTO_malloc(len + 1, core::ptr::null(), 0).cast::<c_char>();
                if p.is_null() {
                    return;
                }
                core::ptr::copy_nonoverlapping(msg, p, len);
                *p.add(len) = 0;
                s.set_data(t, p, len + 1, ERR_TXT_MALLOCED | ERR_TXT_STRING);
            }
        });
    })
}

/// Appends textual data to the current slot. Called by the variadic C adapter,
/// which has already concatenated the arguments.
///
/// # Safety
/// `msg` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_err_add_data(msg: *const c_char) {
    guard_ffi((), || {
        if msg.is_null() {
            return;
        }
        // SAFETY: `msg` is NUL-terminated per the caller's contract.
        let add_len = unsafe { c_strlen(msg) };
        if add_len == 0 {
            return;
        }
        with_state(|s| {
            let t = s.top as usize;
            // The result must be a MALLOCED buffer, because that is what the
            // flags will claim and what the next clear will act on.
            let old_len =
                if (s.err_data_flags[t] & ERR_TXT_MALLOCED) != 0 && !s.err_data[t].is_null() {
                    // SAFETY: MALLOCED means the buffer is ours and NUL-terminated.
                    unsafe { c_strlen(s.err_data[t]) }
                } else {
                    0
                };
            let total = old_len + add_len;
            // SAFETY: fresh allocation of `total + 1`; the old buffer, if any, is
            // copied into it and then released.
            unsafe {
                let p = CRYPTO_malloc(total + 1, core::ptr::null(), 0).cast::<c_char>();
                if p.is_null() {
                    return;
                }
                if old_len > 0 {
                    core::ptr::copy_nonoverlapping(s.err_data[t], p, old_len);
                }
                core::ptr::copy_nonoverlapping(msg, p.add(old_len), add_len);
                *p.add(total) = 0;
                s.set_data(t, p, total + 1, ERR_TXT_MALLOCED | ERR_TXT_STRING);
            }
        });
    })
}

/// `void ERR_set_error_data(char *data, int flags)`
///
/// Takes ownership of `data`, which is the documented and slightly surprising
/// part of this API: the caller must not free it afterwards.
///
/// # Safety
/// `data` must be NULL or a NUL-terminated C string, and the caller must not use
/// it again after this call.
#[no_mangle]
pub unsafe extern "C" fn ERR_set_error_data(data: *mut c_char, flags: c_int) {
    guard_ffi((), || {
        // SAFETY: `data` is NUL-terminated per the caller's contract.
        let len = if data.is_null() {
            0
        } else {
            // SAFETY: `data` is NUL-terminated per the caller's contract.
            unsafe { c_strlen(data) + 1 }
        };
        with_state(|s| {
            let t = s.top as usize;
            s.clear_data(t, true);
            s.set_data(t, data, len, flags);
        });
    })
}

/// `void ERR_add_error_txt(const char *sepr, const char *txt)`
///
/// The authority routes this through `ERR_add_error_data`, but with one rule that
/// is easy to miss and is directly observable through `ERR_get_error_all`: the
/// **separator is dropped when the current slot carries no string data**. A slot
/// raised with `ERR_set_error(lib, reason, NULL)` has no `ERR_TXT_STRING`, so
/// appending `"ab"` with separator `" | "` yields `ab`, not `" | ab"`. The
/// separator only separates existing text from new text.
///
/// ## Open obligation: the length-bounded split is not implemented
///
/// The authority also splits `txt` when the combined data would exceed
/// `ERR_PRINT_BUF_SIZE - 100`, emitting several queue entries so that
/// `ERR_print_errors_cb`'s fixed buffer cannot truncate the report. That path is
/// not implemented here: it only manifests for error data of roughly four
/// kilobytes or more, no court probes it, and no claim is made about it. It is
/// recorded rather than left implicit, and a court for it is the obligation.
///
/// # Safety
/// `sepr` and `txt` must each be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ERR_add_error_txt(sepr: *const c_char, txt: *const c_char) {
    guard_ffi((), || {
        if txt.is_null() {
            return;
        }
        let sepr_nonempty = if sepr.is_null() {
            false
        } else {
            // SAFETY: `sepr` is NUL-terminated.
            unsafe { *sepr != 0 }
        };
        with_state(|s| {
            let t = s.top as usize;
            // The separator is suppressed when there is no existing *string* data
            // to separate from, which is the authority's `leading_separator = ""`.
            let has_sepr = sepr_nonempty && (s.err_data_flags[t] & ERR_TXT_STRING) != 0;
            // SAFETY: `txt` is NUL-terminated.
            let txt_len = unsafe { c_strlen(txt) };
            let sep_len = if has_sepr {
                // SAFETY: `sepr` was checked non-empty above, so it is a valid
                // NUL-terminated string.
                unsafe { c_strlen(sepr) }
            } else {
                0
            };
            let old_len =
                if (s.err_data_flags[t] & ERR_TXT_MALLOCED) != 0 && !s.err_data[t].is_null() {
                    // SAFETY: MALLOCED means ours and NUL-terminated.
                    unsafe { c_strlen(s.err_data[t]) }
                } else {
                    0
                };
            let total = old_len + sep_len + txt_len;
            // SAFETY: fresh allocation of `total + 1`, copying the three parts.
            unsafe {
                let p = CRYPTO_malloc(total + 1, core::ptr::null(), 0).cast::<c_char>();
                if p.is_null() {
                    return;
                }
                if old_len > 0 {
                    core::ptr::copy_nonoverlapping(s.err_data[t], p, old_len);
                }
                if sep_len > 0 {
                    core::ptr::copy_nonoverlapping(sepr, p.add(old_len), sep_len);
                }
                if txt_len > 0 {
                    core::ptr::copy_nonoverlapping(txt, p.add(old_len + sep_len), txt_len);
                }
                *p.add(total) = 0;
                s.set_data(t, p, total + 1, ERR_TXT_MALLOCED | ERR_TXT_STRING);
            }
        });
    })
}

/// Which error `get_error_values` is being asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Pop,
    PeekFirst,
    PeekLast,
}

/// The outputs `get_error_values` can fill in; only the non-NULL ones are
/// written, exactly as in the authority.
struct Outputs {
    file: *mut *const c_char,
    line: *mut c_int,
    func: *mut *const c_char,
    data: *mut *const c_char,
    flags: *mut c_int,
}

/// The shared body of `ERR_get_error*` and `ERR_peek_error*`, reproducing
/// `get_error_values` including its NULL-as-empty-string conversions.
///
/// # Safety
/// Every non-NULL output pointer must be writable for its type.
unsafe fn get_error_values(action: Action, out: Outputs) -> c_ulong {
    with_state(|s| {
        s.settle_clears();
        if s.bottom == s.top {
            return 0;
        }
        let i = match action {
            Action::PeekLast => s.top as usize,
            _ => s.oldest(),
        };
        let ret = s.err_buffer[i];
        if action == Action::Pop {
            s.bottom = i as c_int;
            s.err_buffer[i] = 0;
        }
        // SAFETY: each output is NULL or writable per the caller's contract, and
        // the values written are either ring-owned pointers or static empties.
        unsafe {
            if !out.file.is_null() {
                *out.file = if s.err_file[i].is_null() {
                    EMPTY_C
                } else {
                    s.err_file[i]
                };
            }
            if !out.line.is_null() {
                *out.line = s.err_line[i];
            }
            if !out.func.is_null() {
                *out.func = if s.err_func[i].is_null() {
                    EMPTY_C
                } else {
                    s.err_func[i]
                };
            }
            if !out.flags.is_null() {
                *out.flags = s.err_data_flags[i];
            }
            if out.data.is_null() {
                if action == Action::Pop {
                    let t = i;
                    s.clear_data(t, false);
                }
            } else {
                *out.data = if s.err_data[i].is_null() {
                    // The authority reports an empty string and zeroes the flags
                    // in this case, so a caller never sees a non-NULL flags value
                    // describing data that is not there.
                    if !out.flags.is_null() {
                        *out.flags = 0;
                    }
                    EMPTY_C
                } else {
                    s.err_data[i]
                };
            }
        }
        ret
    })
    .unwrap_or(0)
}

macro_rules! get_error {
    ($name:ident, $action:expr, $doc:expr) => {
        #[doc = $doc]
        #[no_mangle]
        pub extern "C" fn $name() -> c_ulong {
            guard_ffi(0, || {
                // SAFETY: all output pointers are NULL, so nothing is written.
                unsafe {
                    get_error_values(
                        $action,
                        Outputs {
                            file: core::ptr::null_mut(),
                            line: core::ptr::null_mut(),
                            func: core::ptr::null_mut(),
                            data: core::ptr::null_mut(),
                            flags: core::ptr::null_mut(),
                        },
                    )
                }
            })
        }
    };
}

get_error!(
    ERR_get_error,
    Action::Pop,
    "`unsigned long ERR_get_error(void)`"
);
get_error!(
    ERR_peek_error,
    Action::PeekFirst,
    "`unsigned long ERR_peek_error(void)`"
);
get_error!(
    ERR_peek_last_error,
    Action::PeekLast,
    "`unsigned long ERR_peek_last_error(void)`"
);

/// `unsigned long ERR_get_error_all(const char **file, int *line, const char **func, const char **data, int *flags)`
///
/// # Safety
/// Every output pointer must be NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn ERR_get_error_all(
    file: *mut *const c_char,
    line: *mut c_int,
    func: *mut *const c_char,
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    guard_ffi(0, || {
        // SAFETY: forwarded; see this function's contract.
        unsafe {
            get_error_values(
                Action::Pop,
                Outputs {
                    file,
                    line,
                    func,
                    data,
                    flags,
                },
            )
        }
    })
}

/// # Safety
/// Every output pointer must be NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_error_all(
    file: *mut *const c_char,
    line: *mut c_int,
    func: *mut *const c_char,
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    guard_ffi(0, || {
        // SAFETY: forwarded.
        unsafe {
            get_error_values(
                Action::PeekFirst,
                Outputs {
                    file,
                    line,
                    func,
                    data,
                    flags,
                },
            )
        }
    })
}

/// # Safety
/// Every output pointer must be NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_last_error_all(
    file: *mut *const c_char,
    line: *mut c_int,
    func: *mut *const c_char,
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    guard_ffi(0, || {
        // SAFETY: forwarded.
        unsafe {
            get_error_values(
                Action::PeekLast,
                Outputs {
                    file,
                    line,
                    func,
                    data,
                    flags,
                },
            )
        }
    })
}

// The legacy accessors are NOT uniform in arity: `_func` takes one output,
// `_line` two, `_line_data` four, `_data` two *different* ones. Defining them
// through a single five-parameter macro produced exports whose ABI did not match
// the declarations — a defect the RT-ERR probe found by calling them the way the
// header says to. Each arity now has its own macro, so the signature is a
// compile-time fact rather than an argument list of booleans.
macro_rules! forwarding_get_line {
    ($name:ident, $inner:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// # Safety
        /// `file` and `line` must each be NULL or writable for its type.
        #[no_mangle]
        pub unsafe extern "C" fn $name(file: *mut *const c_char, line: *mut c_int) -> c_ulong {
            guard_ffi(0, || {
                // SAFETY: forwarded unchanged; the absent out-parameters are NULL.
                unsafe {
                    $inner(
                        file,
                        line,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                }
            })
        }
    };
}

macro_rules! forwarding_get_line_data {
    ($name:ident, $inner:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// # Safety
        /// Every output pointer must be NULL or writable for its type.
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            file: *mut *const c_char,
            line: *mut c_int,
            data: *mut *const c_char,
            flags: *mut c_int,
        ) -> c_ulong {
            guard_ffi(0, || {
                // SAFETY: forwarded unchanged; `func` is not an output here.
                unsafe { $inner(file, line, core::ptr::null_mut(), data, flags) }
            })
        }
    };
}

macro_rules! forwarding_get_func {
    ($name:ident, $inner:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// # Safety
        /// `func` must be NULL or writable.
        #[no_mangle]
        pub unsafe extern "C" fn $name(func: *mut *const c_char) -> c_ulong {
            guard_ffi(0, || {
                // SAFETY: forwarded unchanged; the other outputs are NULL.
                unsafe {
                    $inner(
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        func,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                }
            })
        }
    };
}

macro_rules! forwarding_get_data {
    ($name:ident, $inner:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// # Safety
        /// `data` and `flags` must each be NULL or writable for their type.
        #[no_mangle]
        pub unsafe extern "C" fn $name(data: *mut *const c_char, flags: *mut c_int) -> c_ulong {
            guard_ffi(0, || {
                // SAFETY: forwarded unchanged; the other outputs are NULL.
                unsafe {
                    $inner(
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        data,
                        flags,
                    )
                }
            })
        }
    };
}

forwarding_get_line!(
    ERR_get_error_line,
    ERR_get_error_all,
    "`unsigned long ERR_get_error_line(const char **file, int *line)`"
);
forwarding_get_line_data!(
    ERR_get_error_line_data,
    ERR_get_error_all,
    "`unsigned long ERR_get_error_line_data(const char **file, int *line, const char **data, int *flags)`"
);
forwarding_get_line!(
    ERR_peek_error_line,
    ERR_peek_error_all,
    "`unsigned long ERR_peek_error_line(const char **file, int *line)`"
);
forwarding_get_data!(
    ERR_peek_error_data,
    ERR_peek_error_all,
    "`unsigned long ERR_peek_error_data(const char **data, int *flags)`"
);
forwarding_get_func!(
    ERR_peek_error_func,
    ERR_peek_error_all,
    "`unsigned long ERR_peek_error_func(const char **func)`"
);
forwarding_get_line_data!(
    ERR_peek_error_line_data,
    ERR_peek_error_all,
    "`unsigned long ERR_peek_error_line_data(const char **file, int *line, const char **data, int *flags)`"
);
forwarding_get_line!(
    ERR_peek_last_error_line,
    ERR_peek_last_error_all,
    "`unsigned long ERR_peek_last_error_line(const char **file, int *line)`"
);
forwarding_get_data!(
    ERR_peek_last_error_data,
    ERR_peek_last_error_all,
    "`unsigned long ERR_peek_last_error_data(const char **data, int *flags)`"
);
forwarding_get_func!(
    ERR_peek_last_error_func,
    ERR_peek_last_error_all,
    "`unsigned long ERR_peek_last_error_func(const char **func)`"
);
forwarding_get_line_data!(
    ERR_peek_last_error_line_data,
    ERR_peek_last_error_all,
    "`unsigned long ERR_peek_last_error_line_data(const char **file, int *line, const char **data, int *flags)`"
);

/// `void ERR_clear_error(void)`
///
/// Clears every slot. Data buffers that this state owns are truncated rather
/// than released, because the authority reuses them.
#[no_mangle]
pub extern "C" fn ERR_clear_error() {
    guard_ffi((), || {
        with_state(|s| {
            for i in 0..ERR_NUM_ERRORS {
                s.clear(i, false);
            }
            s.top = 0;
            s.bottom = 0;
        });
    })
}

/// `int ERR_set_mark(void)`
///
/// Returns 0 on an empty queue — there is nothing to mark — and increments the
/// mark counter of the *newest* slot otherwise.
#[no_mangle]
pub extern "C" fn ERR_set_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            if s.bottom == s.top {
                return 0;
            }
            s.err_marks[s.top as usize] += 1;
            1
        })
        .unwrap_or(0)
    })
}

/// `int ERR_pop(void)`
///
/// Discards the newest error without returning it.
#[no_mangle]
pub extern "C" fn ERR_pop() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            if s.bottom == s.top {
                return 0;
            }
            let t = s.top as usize;
            s.clear(t, false);
            let n = ERR_NUM_ERRORS as c_int;
            s.top = if s.top > 0 { s.top - 1 } else { n - 1 };
            1
        })
        .unwrap_or(0)
    })
}

/// `int ERR_pop_to_mark(void)`
///
/// Discards errors until a marked slot is reached, then consumes one mark from
/// it. The marked error itself is *kept*: the mark denotes a point in the queue,
/// not an error to remove.
#[no_mangle]
pub extern "C" fn ERR_pop_to_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            let n = ERR_NUM_ERRORS as c_int;
            while s.bottom != s.top && s.err_marks[s.top as usize] == 0 {
                let t = s.top as usize;
                s.clear(t, false);
                s.top = if s.top > 0 { s.top - 1 } else { n - 1 };
            }
            if s.bottom == s.top {
                return 0;
            }
            s.err_marks[s.top as usize] -= 1;
            1
        })
        .unwrap_or(0)
    })
}

/// `int ERR_count_to_mark(void)`
///
/// The number of errors above the most recent mark, excluding the marked one.
#[no_mangle]
pub extern "C" fn ERR_count_to_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            let n = ERR_NUM_ERRORS as c_int;
            let mut count = 0;
            let mut top = s.top;
            while s.bottom != top && s.err_marks[top as usize] == 0 {
                count += 1;
                top = if top > 0 { top - 1 } else { n - 1 };
            }
            count
        })
        .unwrap_or(0)
    })
}

/// `int ERR_clear_last_mark(void)`
#[no_mangle]
pub extern "C" fn ERR_clear_last_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            let n = ERR_NUM_ERRORS as c_int;
            let mut top = s.top;
            while s.bottom != top && s.err_marks[top as usize] == 0 {
                top = if top > 0 { top - 1 } else { n - 1 };
            }
            if s.bottom == top {
                return 0;
            }
            s.err_marks[top as usize] -= 1;
            1
        })
        .unwrap_or(0)
    })
}

/// `int ERR_get_next_error_library(void)`
#[no_mangle]
pub extern "C" fn ERR_get_next_error_library() -> c_int {
    guard_ffi(0, || {
        // The authority hands out codes above `ERR_LIB_USER` (128); the exact
        // sequence is a per-process allocation and is measured by RT-ERR.
        NEXT_LIB.fetch_add(1, core::sync::atomic::Ordering::Relaxed) as c_int + 128
    })
}

/// The next dynamic library code to hand out. `ERR_LIB_USER` is 128 and the
/// authority starts there, unlike the earlier `100 + n` guess this replaces.
static NEXT_LIB: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// A deliberately shared buffer, matching the authority's `static char buf[256]`
/// inside `ERR_error_string`. It is not thread-safe there either, and pretending
/// otherwise would be a divergence rather than an improvement.
struct SharedBuf(UnsafeCell<[u8; 256]>);
// SAFETY: mirrors the authority's own static buffer, which is also shared across
// threads without synchronisation. Callers already accept that contract.
unsafe impl Sync for SharedBuf {}
static ERR_STRING_BUF: SharedBuf = SharedBuf(UnsafeCell::new([0u8; 256]));

extern "C" {
    /// The GNU `strerror_r`, returning a pointer that may or may not be `buf`.
    /// This is the variant the authority's `_GNU_SOURCE` build calls from
    /// `openssl_strerror_r`, and therefore the one whose text a caller sees.
    fn strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> *mut c_char;
}

/// `openssl_strerror_r` reduced to what `ossl_err_string_int` needs: fill `buf`
/// with the platform's text for `errnum`, and report whether it succeeded.
///
/// # Safety
/// `buf` must be writable for `buflen` bytes.
unsafe fn strerror_into(errnum: c_int, buf: *mut c_char, buflen: usize) -> bool {
    if buf.is_null() || buflen == 0 {
        return false;
    }
    // SAFETY: `buf` is writable for `buflen` bytes per the caller's contract.
    let p = unsafe { strerror_r(errnum, buf, buflen) };
    if p.is_null() {
        return false;
    }
    if !core::ptr::eq(p, buf) {
        // The GNU variant may hand back a pointer to a static string instead of
        // using `buf`; copy it in, exactly as `OPENSSL_strlcpy` does in the
        // authority.
        // SAFETY: `p` is NUL-terminated, `buf` has `buflen` non-zero bytes.
        unsafe {
            let n = c_strlen(p).min(buflen - 1);
            core::ptr::copy_nonoverlapping(p, buf, n);
            *buf.add(n) = 0;
        }
    }
    true
}

/// `ossl_err_string_int(e, "", buf, len)`.
///
/// # Safety
/// `buf` must be writable for `len` bytes when `len` is non-zero.
unsafe fn error_string_body(e: c_ulong, buf: *mut c_char, len: usize) {
    // SAFETY: forwarded; the authority passes the empty string for the function
    // name when formatting a standalone error string.
    unsafe { error_string_body_func(e, EMPTY_C, buf, len) }
}

/// `ossl_err_string_int(e, func, buf, len)`.
///
/// The `func` is carried through because `ERR_print_errors_cb` prints the
/// *recorded* function name from the error's debug information, not an empty
/// field, so the same formatter produces
/// `error:<code>:<lib>:<func>:<reason>` for it and
/// `error:<code>:<lib>::<reason>` for `ERR_error_string`.
///
/// # Safety
/// `buf` must be writable for `len` bytes when `len` is non-zero; `func` must be
/// NULL or a NUL-terminated C string.
unsafe fn error_string_body_func(e: c_ulong, func: *const c_char, buf: *mut c_char, len: usize) {
    if len == 0 || buf.is_null() {
        return;
    }
    let lib = get_lib(e);
    let system_error = (e & ERR_SYSTEM_FLAG) != 0;
    let mut lib_fallback = [0u8; 64];
    let lib_ptr = {
        let p = ERR_lib_error_string(e);
        if p.is_null() {
            // `lib(%lu)` — the whole field, not just a number.
            let s = format!("lib({lib})");
            let n = s.len().min(lib_fallback.len() - 1);
            lib_fallback[..n].copy_from_slice(&s.as_bytes()[..n]);
            lib_fallback[n] = 0;
            lib_fallback.as_ptr().cast::<c_char>()
        } else {
            p
        }
    };
    let reason = get_reason(e);
    let mut reason_fallback = [0u8; 256];
    let reason_ptr = {
        // A system error is rendered through the platform's `strerror_r`, never
        // through the reason table: the authority cannot put a per-thread
        // `strerror` buffer into a library-wide table lookup.
        let p = if system_error {
            // SAFETY: the buffer is 256 writable bytes.
            if unsafe {
                strerror_into(
                    reason as c_int,
                    reason_fallback.as_mut_ptr().cast::<c_char>(),
                    reason_fallback.len(),
                )
            } {
                reason_fallback.as_ptr().cast::<c_char>()
            } else {
                core::ptr::null()
            }
        } else {
            ERR_reason_error_string(e)
        };
        if p.is_null() {
            // The flag bits are stripped from the numeric fallback, so a code
            // carrying ERR_RFLAG_* renders as its base reason.
            let bare = reason & !(ERR_RFLAGS_MASK << ERR_RFLAGS_OFFSET);
            let s = format!("reason({bare})");
            let n = s.len().min(reason_fallback.len() - 1);
            reason_fallback[..n].copy_from_slice(&s.as_bytes()[..n]);
            reason_fallback[n] = 0;
            reason_fallback.as_ptr().cast::<c_char>()
        } else {
            p
        }
    };
    // SAFETY: all three pointers are valid NUL-terminated strings.
    let (ls, rs) = unsafe {
        (
            core::slice::from_raw_parts(lib_ptr.cast::<u8>(), c_strlen(lib_ptr)),
            core::slice::from_raw_parts(reason_ptr.cast::<u8>(), c_strlen(reason_ptr)),
        )
    };
    let mut v = Vec::new();
    v.extend_from_slice(format!("error:{e:08X}:").as_bytes());
    v.extend_from_slice(ls);
    v.push(b':');
    if !func.is_null() {
        // SAFETY: `func` is NUL-terminated per this function's contract.
        let f = unsafe { core::slice::from_raw_parts(func.cast::<u8>(), c_strlen(func)) };
        v.extend_from_slice(f);
    }
    v.push(b':');
    v.extend_from_slice(rs);
    // The authority substitutes a compact form when the pretty one exactly fills
    // the buffer. Its test is `strlen(buf) == len - 1` *after* the bounded write,
    // so a string that had to be truncated also triggers it — which is what makes
    // the substitution observable through a short buffer.
    let wrote = v.len();
    let n = wrote.min(len - 1);
    // SAFETY: `buf` is writable for `len` bytes and `n <= len - 1`.
    unsafe {
        core::ptr::copy_nonoverlapping(v.as_ptr().cast::<c_char>(), buf, n);
        *buf.add(n) = 0;
    }
    if n == len - 1 {
        let compact = format!("err:{e:x}:{lib:x}:0:{reason:x}");
        let bytes = compact.as_bytes();
        let n = bytes.len().min(len - 1);
        // SAFETY: as above.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), buf, n);
            *buf.add(n) = 0;
        }
    }
}

/// `void ERR_error_string_n(unsigned long e, char *buf, size_t len)`
///
/// # Safety
/// `buf` must be NULL or writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize) {
    guard_ffi((), || {
        // SAFETY: forwarded unchanged.
        unsafe { error_string_body(e, buf, len) }
    })
}

/// `char *ERR_error_string(unsigned long e, char *buf)`
///
/// With a NULL `buf` the authority answers with a pointer into a **static**
/// buffer, shared across threads. That is its contract, and it is reproduced
/// rather than quietly "improved" into thread-local storage — a caller that
/// relied on comparing pointers, or that saw the value overwritten by another
/// thread, would observe the difference.
///
/// # Safety
/// `buf` must be NULL or writable for at least 256 bytes.
#[no_mangle]
pub unsafe extern "C" fn ERR_error_string(e: c_ulong, buf: *mut c_char) -> *mut c_char {
    guard_ffi(core::ptr::null_mut(), || {
        if !buf.is_null() {
            // SAFETY: the caller guarantees 256 writable bytes.
            unsafe { error_string_body(e, buf, 256) };
            return buf;
        }
        let p = ERR_STRING_BUF.0.get().cast::<c_char>();
        // SAFETY: the static buffer is 256 bytes; see the type's note on why
        // sharing it matches the authority.
        unsafe { error_string_body(e, p, 256) };
        p
    })
}

/// `const char *ERR_lib_error_string(unsigned long e)`
///
/// NULL until the generic tables have been loaded. Before the first ERR-state
/// creation on any thread the authority's hash is empty, so a lookup answers
/// NULL even for a library whose array is compiled in; the probe measures that
/// window explicitly.
#[no_mangle]
pub extern "C" fn ERR_lib_error_string(e: c_ulong) -> *const c_char {
    guard_ffi(core::ptr::null(), || {
        if !generic_loaded() {
            return core::ptr::null();
        }
        let lib = get_lib(e);
        if lib > u8::MAX as c_ulong {
            return core::ptr::null();
        }
        lookup_lib(lib as u32)
    })
}

/// `const char *ERR_func_error_string(unsigned long e)`
///
/// Always NULL. In 3.x `ERR_PACK` discards the function field, so there is
/// nothing to look up; the authority's implementation is a bare `return NULL`.
#[no_mangle]
pub extern "C" fn ERR_func_error_string(_e: c_ulong) -> *const c_char {
    core::ptr::null()
}

/// `const char *ERR_reason_error_string(unsigned long e)`
///
/// Tries the library-qualified key first, then the bare reason, and refuses
/// system errors — which the authority does because it cannot render a platform
/// error string through a shared buffer.
///
/// Visibility follows the load state. A library-qualified key is only reachable
/// once *that library* has been loaded, so an SSL reason stays NULL until
/// `OPENSSL_INIT_LOAD_SSL_STRINGS` has run; the generic fallback needs the
/// generic tables, which any load supplies.
#[no_mangle]
pub extern "C" fn ERR_reason_error_string(e: c_ulong) -> *const c_char {
    guard_ffi(core::ptr::null(), || {
        if (e & ERR_SYSTEM_FLAG) != 0 {
            return core::ptr::null();
        }
        let lib = get_lib(e) as u32;
        let reason = get_reason(e) as u32;
        if lib_loaded(lib) {
            let qualified = ((lib & 0xFF) << ERR_LIB_OFFSET as u32) | (reason & 0x7F_FFFF);
            let p = lookup(err_strings::REASONS, qualified);
            if !p.is_null() {
                return p;
            }
        }
        if !generic_loaded() {
            return core::ptr::null();
        }
        lookup(err_strings::REASONS, reason)
    })
}

/// Look up a `(key, NUL-terminated text)` table by key.
fn lookup(table: &[(u32, &[u8])], key: u32) -> *const c_char {
    match table.binary_search_by_key(&key, |&(k, _)| k) {
        // SAFETY: every entry is a static byte string ending in NUL, so the
        // pointer is a valid C string for the life of the process.
        Ok(i) => table[i].1.as_ptr().cast::<c_char>(),
        Err(_) => core::ptr::null(),
    }
}

/// Look up a library name, whose keys are single bytes.
fn lookup_lib(key: u32) -> *const c_char {
    match err_strings::LIBS.binary_search_by_key(&(key as u8), |&(k, _)| k) {
        // SAFETY: as `lookup`.
        Ok(i) => err_strings::LIBS[i].1.as_ptr().cast::<c_char>(),
        Err(_) => core::ptr::null(),
    }
}

/// `int ERR_load_strings(int lib, ERR_STRING_DATA *str)`
///
/// The authority's tables are compiled in, so this legacy entry point exists for
/// source compatibility. Its observable behaviour is measured by the RT-ERR
/// probe rather than asserted here.
#[no_mangle]
pub extern "C" fn ERR_load_strings(_lib: c_int, _str: *mut c_void) -> c_int {
    1
}

/// `int ERR_load_strings_const(const ERR_STRING_DATA *str)`
#[no_mangle]
pub extern "C" fn ERR_load_strings_const(_str: *const c_void) -> c_int {
    1
}

/// `int ERR_unload_strings(int lib, ERR_STRING_DATA *str)`
#[no_mangle]
pub extern "C" fn ERR_unload_strings(_lib: c_int, _str: *mut c_void) -> c_int {
    1
}

/// `void ERR_remove_thread_state(void *dummy)`
///
/// Deprecated and, in the authority, a no-op that does not even synchronise the
/// internal buffer. Reproduced as such rather than given meaning it does not
/// have.
///
/// # Safety
/// `_dummy` is ignored; any value, including NULL, is accepted.
#[no_mangle]
pub unsafe extern "C" fn ERR_remove_thread_state(_dummy: *mut c_void) {}

/// `void ERR_remove_state(unsigned long pid)`
///
/// Deprecated. The authority ignores `pid` entirely; the name suggests it once
/// removed another thread's state, which it no longer does.
#[no_mangle]
pub extern "C" fn ERR_remove_state(_pid: c_ulong) {}

/// The per-library `ERR_load_*_strings` entry points live in the generated
/// `err_loaders` module. They are **not** no-ops: each one loads the generic
/// tables plus that library, which `ERR_reason_error_string` makes observable.
/// The authority's own versions do the same through `ERR_load_strings_const`
/// and `ossl_err_load_ERR_strings`.
/// `int (*)(const char *str, size_t len, void *u)` — the `ERR_print_errors_cb`
/// callback.
pub type ErrPrintCb = unsafe extern "C" fn(*const c_char, usize, *mut c_void) -> c_int;

/// `ossl_buf2hexstr_sep(buf, buflen, 0)` — upper-case hex, no separator.
///
/// The separator argument of the authority's helper is `CH_ZERO` here, which means
/// "no separator" rather than "NUL-separated", and it is why the thread id renders
/// as one unbroken hex run.
fn buf2hexstr_plain(buf: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut v = Vec::with_capacity(buf.len() * 2);
    for &b in buf {
        v.push(HEX[(b >> 4) as usize]);
        v.push(HEX[(b & 0x0f) as usize]);
    }
    v
}

/// `void ERR_print_errors_cb(int (*cb)(const char *, size_t, void *), void *u)`
///
/// Drains the whole thread-local queue, oldest first, printing one line per error:
///
/// ```text
/// <thread-id-as-hex>:<error string>:<file>:<line>:<data>
/// ```
///
/// A callback that returns `<= 0` stops the report **and leaves the remaining
/// errors on the queue**, which is the authority's behaviour and is why an
/// aborting callback is not the same as clearing the queue.
///
/// # Safety
/// `cb` must be the caller's printing callback; `u` is passed through untouched.
#[no_mangle]
pub unsafe extern "C" fn ERR_print_errors_cb(cb: Option<ErrPrintCb>, u: *mut c_void) {
    guard_ffi((), || {
        let Some(cb) = cb else {
            return;
        };
        loop {
            let mut file: *const c_char = ptr::null();
            let mut line: c_int = 0;
            let mut func: *const c_char = ptr::null();
            let mut data: *const c_char = ptr::null();
            let mut flags: c_int = 0;
            // SAFETY: all five are live locals of the types the function writes.
            let l = unsafe {
                ERR_get_error_all(&mut file, &mut line, &mut func, &mut data, &mut flags)
            };
            if l == 0 {
                break;
            }
            // A slot with no string data prints an empty field rather than whatever
            // the pointer happens to hold.
            let data = if flags & ERR_TXT_STRING == 0 {
                EMPTY_C
            } else {
                data
            };

            let mut out: Vec<u8> = Vec::with_capacity(256);
            // SAFETY: `pthread_self` takes no arguments and always succeeds.
            let tid = crate::runtime::thread::CRYPTO_THREAD_get_current_id();
            out.extend_from_slice(&buf2hexstr_plain(&tid.to_ne_bytes()));
            out.push(b':');

            let mut tmp = [0u8; 4096];
            // SAFETY: `tmp` is 4096 writable bytes; `func` is NUL-terminated or
            // NULL, per the error's own recorded debug information.
            unsafe {
                error_string_body_func(l, func, tmp.as_mut_ptr().cast(), tmp.len());
                let n = c_strlen(tmp.as_ptr().cast());
                out.extend_from_slice(&tmp[..n]);
            }
            out.push(b':');
            // SAFETY: `file` and `data` are each NULL or NUL-terminated strings.
            unsafe {
                if !file.is_null() {
                    let n = c_strlen(file);
                    out.extend_from_slice(core::slice::from_raw_parts(file.cast::<u8>(), n));
                }
                out.push(b':');
                out.extend_from_slice(format!("{line}").as_bytes());
                out.push(b':');
                if !data.is_null() {
                    let n = c_strlen(data);
                    out.extend_from_slice(core::slice::from_raw_parts(data.cast::<u8>(), n));
                }
                out.push(b'\n');
            }
            // SAFETY: `cb` is the caller's callback; `out` is a live slice and `u`
            // is the caller's opaque pointer.
            if unsafe { cb(out.as_ptr().cast(), out.len(), u) } <= 0 {
                break;
            }
        }
    })
}

/// `static int print_bio(const char *str, size_t len, void *bp)`
///
/// # Safety
/// `bp` must be a live BIO.
unsafe extern "C" fn print_bio(str_: *const c_char, len: usize, bp: *mut c_void) -> c_int {
    if len > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `bp` is a live BIO and `str_` is valid for `len` bytes.
    unsafe { crate::runtime::bio::BIO_write(bp.cast(), str_.cast(), len as c_int) }
}

/// `void ERR_print_errors(BIO *bp)`
///
/// # Safety
/// `bp` must be NULL or a live BIO.
#[no_mangle]
pub unsafe extern "C" fn ERR_print_errors(bp: *mut crate::runtime::bio::Bio) {
    guard_ffi((), || {
        // SAFETY: forwarded; `ERR_print_errors_cb` accepts a NULL callback and the
        // BIO belongs to the caller.
        unsafe { ERR_print_errors_cb(Some(print_bio), bp.cast()) };
    })
}

/// `void ERR_print_errors_fp(FILE *fp)`
///
/// The authority builds a `BIO_new_fp(fp, BIO_NOCLOSE)` and prints into that.
/// `BIO_s_file` is an open obligation of this stratum, so this writes the same
/// bytes to the stream directly — a file BIO's only effect on a write is `fwrite`
/// to that stream. The mechanism difference is recorded rather than hidden.
///
/// # Safety
/// `fp` must be NULL or a live `FILE *`.
#[no_mangle]
pub unsafe extern "C" fn ERR_print_errors_fp(fp: *mut crate::runtime::bio::sys::FILE) {
    guard_ffi((), || {
        /// Writes an already-formatted report line to the caller's stream.
        ///
        /// # Safety
        /// `fp` must be NULL or a live `FILE *`.
        unsafe extern "C" fn print_fp(str_: *const c_char, len: usize, fp: *mut c_void) -> c_int {
            if fp.is_null() {
                return -1;
            }
            // SAFETY: `fp` is the caller's stream and `str_` is valid for `len`
            // bytes.
            unsafe { crate::runtime::bio::sys::fwrite(str_.cast(), 1, len, fp.cast()) as c_int }
        }
        // SAFETY: forwarded; `print_fp` writes to the caller's stream.
        unsafe { ERR_print_errors_cb(Some(print_fp), fp.cast()) };
    })
}

/// `void ERR_add_error_mem_bio(const char *separator, BIO *bio)`
///
/// Appends the contents of a memory BIO to the current error's data, separated by
/// `separator`. Two details are deliberate: a non-empty buffer whose last byte is
/// not NUL gets one written first, so the text is a C string; and a buffer of
/// exactly one byte is treated as empty because the guard is `len > 1`. Both are
/// the authority's, and both are observable through `ERR_get_error_all`.
///
/// # Safety
/// `bio` must be NULL or a live BIO; `separator` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ERR_add_error_mem_bio(
    separator: *const c_char,
    bio: *mut crate::runtime::bio::Bio,
) {
    guard_ffi((), || {
        if bio.is_null() {
            return;
        }
        // `BIO_get_mem_data(bio, &str)` is `BIO_ctrl(bio, BIO_CTRL_INFO, 0, &str)`.
        // SAFETY: `bio` is live and `str_ptr` is a live local the control writes.
        let mut str_ptr: *mut c_char = ptr::null_mut();
        let mut len = unsafe {
            crate::runtime::bio::BIO_ctrl(
                bio,
                crate::runtime::bio::BIO_CTRL_INFO,
                0,
                (&mut str_ptr as *mut *mut c_char).cast(),
            )
        };
        if len <= 0 {
            return;
        }
        // SAFETY: `str_ptr` addresses the BIO's buffer and `len` bytes are valid.
        unsafe {
            if *str_ptr.add((len - 1) as usize) != 0 {
                // SAFETY: writing one NUL byte through a live BIO.
                if crate::runtime::bio::BIO_write(bio, c"".as_ptr().cast(), 1) <= 0 {
                    return;
                }
                let mut p2: *mut c_char = ptr::null_mut();
                len = crate::runtime::bio::BIO_ctrl(
                    bio,
                    crate::runtime::bio::BIO_CTRL_INFO,
                    0,
                    (&mut p2 as *mut *mut c_char).cast(),
                );
                str_ptr = p2;
            }
            if len > 1 {
                ERR_add_error_txt(separator, str_ptr);
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Read a static C string returned by the tables.
    fn cstr(p: *const c_char) -> Option<String> {
        if p.is_null() {
            return None;
        }
        // SAFETY: the tables hold static NUL-terminated byte strings.
        unsafe {
            Some(
                String::from_utf8_lossy(core::slice::from_raw_parts(p.cast::<u8>(), c_strlen(p)))
                    .into_owned(),
            )
        }
    }

    fn drain() {
        ERR_clear_error();
    }

    #[test]
    fn generated_tables_are_complete_and_sorted() {
        // The lookup is a binary search, so an unsorted table would silently fail
        // to find entries rather than fail to compile. Assert it here.
        assert_eq!(err_strings::LIBS.len(), err_strings::LIB_COUNT);
        assert_eq!(err_strings::REASONS.len(), err_strings::REASON_COUNT);
        assert!(err_strings::LIBS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(err_strings::REASONS.windows(2).all(|w| w[0].0 < w[1].0));
        for (_, text) in err_strings::LIBS.iter() {
            assert_eq!(*text.last().expect("non-empty"), 0, "missing terminator");
        }
        for (_, text) in err_strings::REASONS.iter() {
            assert_eq!(*text.last().expect("non-empty"), 0, "missing terminator");
        }
    }

    #[test]
    fn string_lookups_match_the_measured_authority_values() {
        // `0x0780007F` is the overflow error the RT-MEM probe measured: library
        // 15 (`ERR_LIB_CRYPTO`), reason 127 (`CRYPTO_R_INTEGER_OVERFLOW`).
        assert_eq!(
            cstr(ERR_lib_error_string(0x0780_007F)).as_deref(),
            Some("common libcrypto routines")
        );
        assert_eq!(
            cstr(ERR_reason_error_string(0x0780_007F)).as_deref(),
            Some("integer overflow")
        );
        assert!(cstr(ERR_lib_error_string(200 << 23)).is_none());
        assert!(cstr(ERR_reason_error_string((15 << 23) | 0x007F_FFFF)).is_none());
        // `ERR_SYSTEM_FLAG` suppresses reason lookup entirely.
        assert!(cstr(ERR_reason_error_string(ERR_SYSTEM_FLAG | 15)).is_none());
        // `ERR_func_error_string` is unconditionally NULL in 3.x.
        assert!(ERR_func_error_string(0x0780_007F).is_null());
    }

    #[test]
    fn ring_keeps_fifteen_errors_and_evicts_the_oldest() {
        drain();
        for i in 1..=20u32 {
            ERR_new();
            // SAFETY: a NUL-terminated literal.
            unsafe { openssl_rs_err_set_error(15, i as c_int, core::ptr::null()) };
        }
        // The authority's ring has one slot of headroom, so 20 pushes retain 15.
        let mut seen = Vec::new();
        loop {
            let e = ERR_get_error();
            if e == 0 {
                break;
            }
            seen.push(get_reason(e));
        }
        assert_eq!(seen.len(), 15, "usable ring depth");
        // The survivors are the newest fifteen: reasons 6..=20.
        assert_eq!(seen.first().copied(), Some(6));
        assert_eq!(seen.last().copied(), Some(20));
    }

    #[test]
    fn get_is_fifo_and_peek_last_is_the_newest() {
        drain();
        for i in 1..=3u32 {
            ERR_new();
            // SAFETY: NULL message is accepted.
            unsafe { openssl_rs_err_set_error(15, i as c_int, core::ptr::null()) };
        }
        assert_eq!(get_reason(ERR_peek_error()), 1);
        assert_eq!(get_reason(ERR_peek_last_error()), 3);
        assert_eq!(get_reason(ERR_get_error()), 1);
        assert_eq!(get_reason(ERR_get_error()), 2);
        assert_eq!(get_reason(ERR_get_error()), 3);
        assert_eq!(ERR_get_error(), 0);
    }

    #[test]
    fn an_incomplete_slot_is_invisible() {
        drain();
        ERR_new(); // never completed
        assert_eq!(ERR_peek_error(), 0);
        assert_eq!(ERR_get_error(), 0);
        ERR_new();
        // SAFETY: NULL message is accepted.
        unsafe { openssl_rs_err_set_error(15, 42, core::ptr::null()) };
        assert_eq!(get_reason(ERR_get_error()), 42);
    }

    #[test]
    fn marks_behave_as_measured() {
        drain();
        // An empty queue has nothing to mark.
        assert_eq!(ERR_set_mark(), 0);
        for i in 1..=3u32 {
            ERR_new();
            // SAFETY: NULL message is accepted.
            unsafe { openssl_rs_err_set_error(15, i as c_int, core::ptr::null()) };
        }
        assert_eq!(ERR_set_mark(), 1);
        ERR_new();
        // SAFETY: as above.
        unsafe { openssl_rs_err_set_error(15, 4, core::ptr::null()) };
        ERR_new();
        // SAFETY: as above.
        unsafe { openssl_rs_err_set_error(15, 5, core::ptr::null()) };
        assert_eq!(ERR_count_to_mark(), 2);
        // Popping to the mark keeps the marked error itself.
        assert_eq!(ERR_pop_to_mark(), 1);
        assert_eq!(get_reason(ERR_peek_last_error()), 3);
        assert_eq!(ERR_pop_to_mark(), 0, "the mark was consumed");
    }

    #[test]
    fn error_string_uses_the_authority_format() {
        let mut buf = [0i8; 256];
        // SAFETY: 256 writable bytes.
        unsafe { ERR_error_string_n(0x0780_007F, buf.as_mut_ptr(), 256) };
        let s = cstr(buf.as_ptr()).expect("non-null");
        assert_eq!(
            s,
            "error:0780007F:common libcrypto routines::integer overflow"
        );
        // A NULL buffer still works, through the shared static.
        // SAFETY: NULL is accepted and handled.
        let p = unsafe { ERR_error_string(0x0780_007F, core::ptr::null_mut()) };
        assert_eq!(cstr(p).as_deref(), Some(s.as_str()));
        // len == 0 is a no-op rather than a panic.
        // SAFETY: NULL with len 0.
        unsafe { ERR_error_string_n(1, core::ptr::null_mut(), 0) };
    }

    #[test]
    fn error_string_falls_back_to_numeric_fields() {
        let mut buf = [0i8; 256];
        // SAFETY: 256 writable bytes.
        unsafe { ERR_error_string_n(0x7F80_0001, buf.as_mut_ptr(), 256) };
        let s = cstr(buf.as_ptr()).expect("non-null");
        // `ERR_error_string_n` always passes an empty `func` field, so the
        // pretty form contains two adjacent colons there.
        assert_eq!(s, "error:7F800001:lib(255)::reason(1)");
    }

    #[test]
    fn get_state_exposes_the_ring() {
        drain();
        let es = ERR_get_state();
        assert!(!es.is_null());
        // SAFETY: `es` points into this thread's state for its lifetime.
        unsafe {
            assert_eq!((*es).top, 0);
            assert_eq!((*es).bottom, 0);
        }
        ERR_new();
        // SAFETY: as above.
        unsafe { openssl_rs_err_set_error(15, 7, core::ptr::null()) };
        // SAFETY: as above.
        unsafe {
            assert_eq!((*es).top, 1);
            assert_eq!((*es).bottom, 0);
            assert_eq!((*es).err_buffer[1], (15 << 23) | 7);
        }
        assert_eq!(ERR_pop(), 1);
        // SAFETY: as above.
        unsafe { assert_eq!((*es).top, 0) };
        assert_eq!(ERR_pop(), 0);
    }

    #[test]
    fn data_flags_and_ownership() {
        drain();
        ERR_new();
        // SAFETY: NV is NUL-terminated.
        unsafe { openssl_rs_err_set_error(15, 1, c"a message".as_ptr()) };
        let mut data: *const c_char = core::ptr::null();
        let mut flags: c_int = 0;
        // SAFETY: all out-parameters are NULL or point at live locals.
        let e = unsafe {
            ERR_peek_error_all(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut data,
                &mut flags,
            )
        };
        assert_eq!(get_reason(e), 1);
        assert_eq!(cstr(data).as_deref(), Some("a message"));
        assert_eq!(flags, ERR_TXT_MALLOCED | ERR_TXT_STRING);
        // A NULL message clears the data rather than leaving the previous text.
        ERR_new();
        // SAFETY: NULL is accepted and clears.
        unsafe { openssl_rs_err_set_error(15, 2, core::ptr::null()) };
        let mut flags2: c_int = 7;
        // SAFETY: as above.
        let _ = unsafe {
            ERR_peek_last_error_all(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut data,
                &mut flags2,
            )
        };
        assert_eq!(cstr(data).as_deref(), Some(""));
        assert_eq!(flags2, 0);
        drain();
    }
}
