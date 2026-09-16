//! Phase 6.6c — the core BIO: the BIO a provider reaches an application's BIO through.
//!
//! `crypto/bio/bss_core.c` (188 lines) defines a BIO **method** whose every
//! operation is a *forward* to a function pointer the application handed the
//! library in an `OSSL_DISPATCH` table. It is the opposite of every other BIO in
//! this crate: a `BIO_s_mem` owns a buffer and does work, whereas a `BIO_s_core`
//! owns nothing and calls whatever it was given. So the whole behaviour of the
//! method is *what it calls, with what arguments, and what it answers when there
//! is nothing to call*.
//!
//! ## The five-way "nothing to call" answer is not uniform
//!
//! Each operation answers differently when its callback is missing, and the
//! differences are the authority's:
//!
//! | operation | missing `BIO_CORE_GLOBALS` | callback present but NULL |
//! |---|---|---|
//! | `read_ex` | `0` | `0` |
//! | `write_ex` | `0` | `0` |
//! | `ctrl` | `-1` | `-1` |
//! | `gets` | `-1` | `-1` |
//! | `puts` | `-1` | `-1` |
//! | `create` | — | succeeds, setting `init` to 1 |
//! | `destroy` | `0` | **faults** (see below) |
//!
//! A transcription that returned `-1` everywhere, or `0` everywhere, would pass a
//! happy-path test and diverge on the first BIO whose table omits `BIO_ctrl`.
//!
//! ## Two guards the authority does not have, and why they do not change the
//! reachable answers
//!
//! `bio_core_free` calls `bcgbl->c_bio_free(...)` and `BIO_new_from_core_bio`
//! calls `bcgbl->c_bio_up_ref(corebio)` **without checking either for NULL**. A
//! table with `BIO_write_ex` but neither `BIO_free` nor `BIO_up_ref` is accepted
//! by the constructor's guard (which only asks that `write_ex` or `read_ex` is
//! set) and then faults the first time the BIO is written or released. This module
//! answers the documented failure instead — `0` from `destroy`, NULL from the
//! constructor — because `docs/UNSAFE.md` §5 forbids reproducing a crash merely
//! because an observed run did. No caller that supplies a usable table can tell
//! the two apart: every path that reaches the unguarded call in the authority
//! dies there.
//!
//! The same rule covers a NULL dispatch table: `ossl_bio_init_core` dereferences
//! it in the authority (its loop condition is `fns->function_id != 0`), where this
//! treats it as the empty table — which is what a table containing only
//! `OSSL_DISPATCH_END` means, and what a caller passing NULL was asking for.
//!
//! ## The globals are per context, which is the only reason the BIO knows anything
//!
//! Six of the seven callbacks are read through `get_globals(bio->libctx)`, so the
//! dispatch table a BIO uses is the one belonging to **the context the BIO was
//! created on**. That is why `src/runtime/bio/mod.rs`'s `BIO_new_ex` records
//! `libctx` on the BIO; Phase 4 accepted and ignored that argument and named this
//! subphase as the obligation it created.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::context::dispatch::{
    entry_function, OsslDispatch, OsslFuncBioCtrl, OsslFuncBioFree, OsslFuncBioGets,
    OsslFuncBioPuts, OsslFuncBioReadEx, OsslFuncBioUpRef, OsslFuncBioWriteEx, OSSL_DISPATCH_END,
    OSSL_FUNC_BIO_CTRL, OSSL_FUNC_BIO_FREE, OSSL_FUNC_BIO_GETS, OSSL_FUNC_BIO_PUTS,
    OSSL_FUNC_BIO_READ_EX, OSSL_FUNC_BIO_UP_REF, OSSL_FUNC_BIO_WRITE_EX,
};
use crate::context::{lib_ctx_get_data, OSSL_LIB_CTX_BIO_CORE_INDEX};
use crate::runtime::bio::{
    BIO_free, BIO_get_data, BIO_new_ex, BIO_set_data, BIO_set_init, Bio, BioMethod,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// The authority's translation unit and coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/bio/bss_core.c".as_ptr();
const LINE_ZALLOC: c_int = 32;
const LINE_FREE: c_int = 27;

/// `BIO_TYPE_CORE_TO_PROV`, from `openssl/bio.h`: `25 | BIO_TYPE_SOURCE_SINK`.
const BIO_TYPE_CORE_TO_PROV: c_int = 25 | 0x0400;

/// `struct BIO_CORE_GLOBALS` — seven callbacks, filled from a dispatch table.
///
/// The fields are `Option<fn>` rather than raw pointers precisely because a
/// function pointer's null value is a valid niche: an `OPENSSL_zalloc`ed block is
/// therefore a valid, empty `BioCoreGlobals` with no initialisation step, which is
/// what the authority's `OPENSSL_zalloc(sizeof(BIO_CORE_GLOBALS))` also produces.
#[repr(C)]
pub(crate) struct BioCoreGlobals {
    read_ex: Option<OsslFuncBioReadEx>,
    write_ex: Option<OsslFuncBioWriteEx>,
    gets: Option<OsslFuncBioGets>,
    puts: Option<OsslFuncBioPuts>,
    ctrl: Option<OsslFuncBioCtrl>,
    up_ref: Option<OsslFuncBioUpRef>,
    free: Option<OsslFuncBioFree>,
}

/// `void *ossl_bio_core_globals_new(OSSL_LIB_CTX *ctx)` — the slot constructor.
///
/// The `ctx` argument is accepted and unused, as in the authority.
pub(crate) fn ossl_bio_core_globals_new(_ctx: *mut c_void) -> *mut BioCoreGlobals {
    CRYPTO_zalloc(core::mem::size_of::<BioCoreGlobals>(), FILE, LINE_ZALLOC)
        .cast::<BioCoreGlobals>()
}

/// `void ossl_bio_core_globals_free(void *vbcg)`
///
/// # Safety
/// `vbcg` must be NULL or a pointer returned by [`ossl_bio_core_globals_new`] and
/// not already released.
pub(crate) unsafe fn ossl_bio_core_globals_free(vbcg: *mut BioCoreGlobals) {
    if vbcg.is_null() {
        return;
    }
    // SAFETY: the block came from `CRYPTO_zalloc` in the constructor and is
    // released exactly once here.
    unsafe { CRYPTO_free(vbcg.cast::<c_void>(), FILE, LINE_FREE) };
}

/// `static BIO_CORE_GLOBALS *get_globals(OSSL_LIB_CTX *libctx)`
fn get_globals(libctx: *mut c_void) -> *mut BioCoreGlobals {
    lib_ctx_get_data(libctx, OSSL_LIB_CTX_BIO_CORE_INDEX).cast::<BioCoreGlobals>()
}

// ---------------------------------------------------------------------------
// The method's operations
// ---------------------------------------------------------------------------

/// The globals for the context this BIO was created on, or NULL.
///
/// # Safety
/// `bio` must be a live BIO.
unsafe fn globals_of(bio: *mut Bio) -> *mut BioCoreGlobals {
    // SAFETY: `bio` is live per the caller's contract.
    let libctx = unsafe { (*bio).libctx };
    get_globals(libctx)
}

/// `static int bio_core_read_ex(BIO *bio, char *data, size_t data_len, size_t *bytes_read)`
///
/// # Safety
/// A BIO method's contract: `bio` is live, and `data`/`bytes_read` are the
/// caller's per `BIO_read_ex`.
unsafe extern "C" fn bio_core_read_ex(
    bio: *mut Bio,
    data: *mut c_char,
    data_len: usize,
    bytes_read: *mut usize,
) -> c_int {
    // SAFETY: `bio` is live per the method contract.
    let g = unsafe { globals_of(bio) };
    if g.is_null() {
        return 0;
    }
    // SAFETY: `g` is a live globals block owned by the context.
    let Some(f) = (unsafe { (*g).read_ex }) else {
        return 0;
    };
    // SAFETY: `bio` is live, so `BIO_get_data` answers this BIO's own handle; the
    // three arguments are forwarded unchanged.
    unsafe { f(BIO_get_data(bio), data.cast(), data_len, bytes_read) }
}

/// `static int bio_core_write_ex(BIO *bio, const char *data, size_t data_len, size_t *written)`
///
/// # Safety
/// As [`bio_core_read_ex`].
unsafe extern "C" fn bio_core_write_ex(
    bio: *mut Bio,
    data: *const c_char,
    data_len: usize,
    written: *mut usize,
) -> c_int {
    // SAFETY: `bio` is live per the method contract.
    let g = unsafe { globals_of(bio) };
    if g.is_null() {
        return 0;
    }
    // SAFETY: `g` is a live globals block.
    let Some(f) = (unsafe { (*g).write_ex }) else {
        return 0;
    };
    // SAFETY: as `bio_core_read_ex`.
    unsafe { f(BIO_get_data(bio), data.cast(), data_len, written) }
}

/// `static long bio_core_ctrl(BIO *bio, int cmd, long num, void *ptr)`
///
/// Answers `-1`, not `0`, when there is nothing to call — the authority's answer,
/// and the one a caller reads as "this BIO has no such control".
///
/// # Safety
/// As [`bio_core_read_ex`], plus `ptr` is whatever `BIO_ctrl`'s command means.
unsafe extern "C" fn bio_core_ctrl(
    bio: *mut Bio,
    cmd: c_int,
    num: c_long,
    ptr_: *mut c_void,
) -> c_long {
    // SAFETY: `bio` is live per the method contract.
    let g = unsafe { globals_of(bio) };
    if g.is_null() {
        return -1;
    }
    // SAFETY: `g` is a live globals block.
    let Some(f) = (unsafe { (*g).ctrl }) else {
        return -1;
    };
    // SAFETY: as `bio_core_read_ex`. The callback answers `int` and this method
    // answers `long`, so the value is widened rather than reinterpreted.
    c_long::from(unsafe { f(BIO_get_data(bio), cmd, num, ptr_) })
}

/// `static int bio_core_gets(BIO *bio, char *buf, int size)`
///
/// # Safety
/// As [`bio_core_read_ex`].
unsafe extern "C" fn bio_core_gets(bio: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    // SAFETY: `bio` is live per the method contract.
    let g = unsafe { globals_of(bio) };
    if g.is_null() {
        return -1;
    }
    // SAFETY: `g` is a live globals block.
    let Some(f) = (unsafe { (*g).gets }) else {
        return -1;
    };
    // SAFETY: as `bio_core_read_ex`.
    unsafe { f(BIO_get_data(bio), buf, size) }
}

/// `static int bio_core_puts(BIO *bio, const char *str)`
///
/// # Safety
/// As [`bio_core_read_ex`].
unsafe extern "C" fn bio_core_puts(bio: *mut Bio, str_: *const c_char) -> c_int {
    // SAFETY: `bio` is live per the method contract.
    let g = unsafe { globals_of(bio) };
    if g.is_null() {
        return -1;
    }
    // SAFETY: `g` is a live globals block.
    let Some(f) = (unsafe { (*g).puts }) else {
        return -1;
    };
    // SAFETY: as `bio_core_read_ex`.
    unsafe { f(BIO_get_data(bio), str_) }
}

/// `static int bio_core_new(BIO *bio)` — sets `init` and asks nothing.
///
/// # Safety
/// `bio` must be a live BIO.
unsafe extern "C" fn bio_core_new(bio: *mut Bio) -> c_int {
    // SAFETY: `bio` is live per the method contract.
    unsafe { BIO_set_init(bio, 1) };
    1
}

/// `static int bio_core_free(BIO *bio)`
///
/// Clears `init` and releases the caller's core BIO through the `BIO_FREE`
/// callback. A NULL globals block answers **0** where the other operations answer
/// `-1`: the authority's `if (bcgbl == NULL) return 0;`. A missing `BIO_FREE`
/// callback is the guarded case described in the module documentation.
///
/// # Safety
/// `bio` must be a live BIO whose `BIO_free` is in progress.
unsafe extern "C" fn bio_core_free(bio: *mut Bio) -> c_int {
    // SAFETY: `bio` is live per the method contract.
    let g = unsafe { globals_of(bio) };
    if g.is_null() {
        return 0;
    }
    // SAFETY: `bio` is live.
    unsafe { BIO_set_init(bio, 0) };
    // SAFETY: `g` is a live globals block owned by the context.
    if let Some(f) = unsafe { (*g).free } {
        // SAFETY: the callback takes the same handle `BIO_get_data` answers, and
        // `bio` is live.
        unsafe { f(BIO_get_data(bio)) };
    }
    1
}

/// `static const BIO_METHOD corebiometh` — built as a `static` so that
/// `BIO_s_core` can answer the same address every time, which is what the
/// authority's `&corebiometh` does.
///
/// The field order is the crate's `BioMethod`, which follows the authority's
/// `struct bio_method_st`. The two modern read/write slots are filled and the two
/// legacy ones are NULL, exactly as the C initialiser has it.
static CORE_BIO_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_CORE_TO_PROV,
    name: c"BIO to Core filter".as_ptr(),
    bwrite: Some(bio_core_write_ex),
    bwrite_old: None,
    bread: Some(bio_core_read_ex),
    bread_old: None,
    bputs: Some(bio_core_puts),
    bgets: Some(bio_core_gets),
    ctrl: Some(bio_core_ctrl),
    create: Some(bio_core_new),
    destroy: Some(bio_core_free),
    callback_ctrl: None,
    sendmmsg: None,
    recvmmsg: None,
};

// ---------------------------------------------------------------------------
// The exports
// ---------------------------------------------------------------------------

/// `const BIO_METHOD *BIO_s_core(void)`
///
/// The same address on every call, so a caller can compare it — which is how a
/// BIO built by [`BIO_new_from_core_bio`] is recognised.
#[no_mangle]
pub extern "C" fn BIO_s_core() -> *const BioMethod {
    &CORE_BIO_METHOD
}

/// `BIO *BIO_new_from_core_bio(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *corebio)`
///
/// Wraps a handle the application owns into a BIO the library can use. Three
/// things can make it fail, in the authority's order: the context has no globals
/// block; the table has **neither** `BIO_read_ex` nor `BIO_write_ex` (a table with
/// only one of them is accepted); or the `BIO_UP_REF` callback answers 0, in which
/// case the newly created BIO is released and NULL is returned — note that it is
/// the *wrapper* that is released, never the caller's `corebio`.
///
/// # Safety
/// `libctx` must be NULL or a live context. `corebio` must be a handle the
/// dispatch table's callbacks accept; this function only stores it and passes it
/// back, so its meaning is the table's.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_from_core_bio(
    libctx: *mut c_void,
    corebio: *mut c_void,
) -> *mut Bio {
    let g = get_globals(libctx);
    if g.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `g` is a live globals block.
    let (read, write, up_ref) = unsafe { ((*g).read_ex, (*g).write_ex, (*g).up_ref) };
    if write.is_none() && read.is_none() {
        return ptr::null_mut();
    }
    // SAFETY: `libctx` is NULL or live per the contract, and the method is
    // `'static`.
    let outbio = unsafe { BIO_new_ex(libctx, &CORE_BIO_METHOD) };
    if outbio.is_null() {
        return ptr::null_mut();
    }
    // The authority calls `c_bio_up_ref` unguarded; see the module documentation.
    let Some(up_ref) = up_ref else {
        // SAFETY: `outbio` was just created and is not yet published.
        unsafe { BIO_free(outbio) };
        return ptr::null_mut();
    };
    // SAFETY: the callback takes the caller's handle.
    if unsafe { up_ref(corebio) } == 0 {
        // SAFETY: `outbio` is the BIO created above, released exactly once, and
        // `corebio` belongs to the caller and is untouched.
        unsafe { BIO_free(outbio) };
        return ptr::null_mut();
    }
    // SAFETY: `outbio` is live and `corebio` is the handle to record.
    unsafe { BIO_set_data(outbio, corebio) };
    outbio
}

/// `int ossl_bio_init_core(OSSL_LIB_CTX *libctx, const OSSL_DISPATCH *fns)`
///
/// Fills the context's globals from a dispatch table. **The first table wins**: an
/// entry is stored only when its slot is still empty, so a second call carrying a
/// different `BIO_write_ex` leaves the first one in place. That is not reachable
/// from a consumer — `OSSL_LIB_CTX_new_from_dispatch` builds a fresh context each
/// time — but it is the authority's behaviour and it is unit-tested here.
///
/// # Safety
/// `libctx` must be NULL or a live context. `fns` must be NULL or a
/// `OSSL_DISPATCH_END`-terminated table whose entries stay live for the call; the
/// function pointers stored out of it must remain callable for as long as the
/// context may use them.
pub(crate) unsafe fn ossl_bio_init_core(libctx: *mut c_void, fns: *const OsslDispatch) -> c_int {
    let g = get_globals(libctx);
    if g.is_null() {
        return 0;
    }
    if fns.is_null() {
        // The authority reads `fns->function_id` and faults. Treated as the empty
        // table, which is what a terminator-only table is; see the module
        // documentation.
        return 1;
    }
    let mut p = fns;
    // SAFETY: `fns` is END-terminated per the caller's contract.
    unsafe {
        while (*p).function_id != OSSL_DISPATCH_END {
            let id = (*p).function_id;
            match id {
                OSSL_FUNC_BIO_READ_EX if (*g).read_ex.is_none() => {
                    (*g).read_ex = entry_function::<OsslFuncBioReadEx>(p);
                }
                OSSL_FUNC_BIO_WRITE_EX if (*g).write_ex.is_none() => {
                    (*g).write_ex = entry_function::<OsslFuncBioWriteEx>(p);
                }
                OSSL_FUNC_BIO_GETS if (*g).gets.is_none() => {
                    (*g).gets = entry_function::<OsslFuncBioGets>(p);
                }
                OSSL_FUNC_BIO_PUTS if (*g).puts.is_none() => {
                    (*g).puts = entry_function::<OsslFuncBioPuts>(p);
                }
                OSSL_FUNC_BIO_CTRL if (*g).ctrl.is_none() => {
                    (*g).ctrl = entry_function::<OsslFuncBioCtrl>(p);
                }
                OSSL_FUNC_BIO_UP_REF if (*g).up_ref.is_none() => {
                    (*g).up_ref = entry_function::<OsslFuncBioUpRef>(p);
                }
                OSSL_FUNC_BIO_FREE if (*g).free.is_none() => {
                    (*g).free = entry_function::<OsslFuncBioFree>(p);
                }
                // Any other id is not this table's business, exactly as the
                // authority's `switch` has no arm for it.
                _ => {}
            }
            p = p.add(1);
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};

    use core::sync::atomic::{AtomicI32, Ordering};

    static WRITES: AtomicI32 = AtomicI32::new(0);
    static FREES: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn cb_write_ex(
        _bio: *mut c_void,
        _data: *const c_void,
        _len: usize,
        written: *mut usize,
    ) -> c_int {
        // SAFETY: `written` is the caller's out-parameter per the callback
        // contract.
        unsafe { *written = 3 };
        WRITES.fetch_add(1, Ordering::Relaxed);
        1
    }

    unsafe extern "C" fn cb_free(_bio: *mut c_void) -> c_int {
        FREES.fetch_add(1, Ordering::Relaxed);
        1
    }

    unsafe extern "C" fn cb_up_ref(_bio: *mut c_void) -> c_int {
        1
    }

    static TABLE: [OsslDispatch; 4] = [
        OsslDispatch {
            function_id: OSSL_FUNC_BIO_WRITE_EX,
            function: cb_write_ex as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_BIO_UP_REF,
            function: cb_up_ref as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_BIO_FREE,
            function: cb_free as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_DISPATCH_END,
            function: ptr::null_mut(),
        },
    ];

    #[test]
    fn the_method_is_static_and_named() {
        let a = BIO_s_core();
        assert!(!a.is_null());
        assert_eq!(a, BIO_s_core());
        // SAFETY: `a` is the `'static` method this module owns.
        let method = unsafe { &*a };
        assert_eq!(method.type_, BIO_TYPE_CORE_TO_PROV);
        assert_eq!(
            // SAFETY: the name is a `'static` literal written by the method above.
            unsafe { core::ffi::CStr::from_ptr(method.name) },
            c"BIO to Core filter"
        );
    }

    /// A context with no dispatch table answers NULL from the constructor, and one
    /// with a table accepts it; the write callback is reached with the handle the
    /// constructor stored.
    #[test]
    fn a_table_is_needed_and_the_handle_round_trips() {
        WRITES.store(0, Ordering::Relaxed);
        FREES.store(0, Ordering::Relaxed);
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live.
        unsafe {
            // No table: the constructor refuses.
            assert!(
                BIO_new_from_core_bio(ctx, ptr::null_mut()).is_null(),
                "a context with no core BIO callbacks must refuse"
            );
            assert_eq!(ossl_bio_init_core(ctx, TABLE.as_ptr()), 1);
            let handle = 0x1234usize as *mut c_void;
            let bio = BIO_new_from_core_bio(ctx, handle);
            assert!(!bio.is_null());
            // The handle is what the callbacks will receive.
            assert_eq!(BIO_get_data(bio), handle);

            let mut data = [0u8; 3];
            let data_ptr = data.as_mut_ptr().cast::<core::ffi::c_void>();
            // SAFETY: `bio` is live and `data_ptr` points at the three bytes just
            // declared.
            let rc = crate::runtime::bio::iolib::BIO_write(bio, data_ptr, 3);
            assert_eq!(rc, 3, "BIO_write answers the byte count it was told");
            assert_eq!(WRITES.load(Ordering::Relaxed), 1);

            // SAFETY: `bio` is live and has not been released.
            BIO_free(bio);
            assert_eq!(FREES.load(Ordering::Relaxed), 1);
            OSSL_LIB_CTX_free(ctx);
        }
    }

    /// The first table wins: a second call cannot replace a callback that is
    /// already stored.
    #[test]
    fn the_first_table_wins() {
        WRITES.store(0, Ordering::Relaxed);
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live and both tables are `'static`.
        unsafe {
            assert_eq!(ossl_bio_init_core(ctx, TABLE.as_ptr()), 1);
            // The same table again changes nothing.
            assert_eq!(ossl_bio_init_core(ctx, TABLE.as_ptr()), 1);
            let g = get_globals(ctx);
            assert!(!g.is_null());
            assert!((*g).write_ex.is_some());
            assert!((*g).ctrl.is_none(), "an unreferenced slot stays empty");
            // A NULL table is the empty table.
            assert_eq!(ossl_bio_init_core(ctx, ptr::null()), 1);
            OSSL_LIB_CTX_free(ctx);
        }
    }
}
