//! Phase 6.7a — the global-properties holder from `crypto/property/property.c`.
//!
//! This file is named for the object rather than for the authority's translation
//! unit, because `property.c` inside a `property` module is a name clippy refuses and
//! an allowance for that would be a suppression rather than a correction. Everything
//! below is `crypto/property/property.c`'s.
//!
//! `property.c` is the largest file in the subsystem (949 lines) and most of it is
//! the *method store*: the table of fetched algorithms, its lock discipline, the
//! `nid`-keyed flush and the fetch cache that a property query is applied to. All of
//! that is 6.7c, and 6.7c is 6.8's work, because `ossl_method_store_add` takes an
//! `OSSL_PROVIDER *` and there are no providers yet.
//!
//! Two hundred lines of that file are not the store, and one of them is a **slot**:
//!
//! ```c
//! typedef struct ossl_global_properties_st {
//!     OSSL_PROPERTY_LIST *list;
//! #ifndef FIPS_MODULE
//!     unsigned int no_mirrored : 1;
//! #endif
//! } OSSL_GLOBAL_PROPERTIES;
//! ```
//!
//! The per-context *global properties* — the defaults a query is mixed with before
//! it is applied — are slot 14. `context_init` allocates the holder and
//! `context_deinit_objs` releases it, so the slot exists for every context from the
//! moment it is created, exactly as slot 17 does.
//!
//! ## The holder is a zeroed block with one pointer, and that is the whole of it
//!
//! `ossl_ctx_global_properties_new` is `OPENSSL_zalloc(sizeof(OSSL_GLOBAL_PROPERTIES))`
//! and nothing else. **A zeroed block is a valid, empty holder**: `list` is NULL,
//! which `ossl_ctx_global_properties` hands back as `&globp->list`, and a NULL list
//! is "the context has no global properties yet" rather than "the slot is
//! uninitialised". That is why this slot can land before the grammar can parse a
//! list, and why landing it asserts nothing about property behaviour.
//!
//! `no_mirrored` is a bitfield in the authority's struct and is **not** reproduced
//! as a field here. Its reader is `ossl_property_set_mirrored_property`, which is
//! `provider.c`'s and part of 6.8; reproducing a bitfield that nothing in this
//! stratum reads or writes would be a placeholder, which `docs/PARITY_MODEL.md`
//! refuses. The layout differs by four bytes of trailing padding as a result, which
//! is recorded in 6.7a's residual rather than papered over.

use core::ffi::{c_char, c_int, c_void};

use crate::property::parse::ossl_property_free;
use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx};
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_LOAD_CONFIG};

/// The authority's translation unit.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/property/property.c".as_ptr();

/// `ossl_ctx_global_properties_free`'s `OPENSSL_free(globp)`.
const LINE_FREE_GLOBP: c_int = 120;
/// `ossl_ctx_global_properties_new`'s `OPENSSL_zalloc`.
const LINE_ZALLOC_GLOBP: c_int = 126;

/// `struct ossl_global_properties_st`.
///
/// **The `no_mirrored` bit landed in D142**, and until then this struct was the authority's minus
/// that field: 6.7a omitted it because nothing in that stratum read or wrote it and a bitfield
/// nothing touches would have been a placeholder. Now the two functions that read and write it are
/// here — `ossl_global_properties_no_mirrored` and `ossl_global_properties_stop_mirroring` — and
/// with them the layout matches the authority's exactly: a pointer and a one-bit field, which
/// both round to sixteen bytes.
///
/// The bit is stored as a `u32` with a mask rather than as a Rust `bool`, for the reason
/// `OsslProvider`'s flags are: the authority's field shares its storage unit with nothing else
/// here, but writing a `bool` into a C bitfield's slot would claim a one-byte field the layout
/// does not have.
#[repr(C)]
pub(crate) struct OsslGlobalProperties {
    list: *mut crate::property::list::OsslPropertyList,
    /// `unsigned int no_mirrored : 1;` — set once, never cleared.
    no_mirrored: u32,
}

/// A second name for [`FILE`] for the [`CtxDestroy`] implementation below, whose associated
/// `FILE` would otherwise shadow the module constant inside its own definition.
const CTX_FILE: *const c_char = FILE;

// SAFETY: (a) `destroy_body` releases the holder's one separately allocated member, `list`, by
// the authority's own `ossl_property_free`, and never the enclosing block, which `OwnedCtx`
// releases; `ossl_property_free` accepts NULL, so the empty holder is handled. (b) an all-zero
// block is a valid empty holder (`list` NULL, `no_mirrored` zero), which is the state the
// authority's `OPENSSL_zalloc` constructor leaves, and `destroy_body` is sound on it.
unsafe impl CtxDestroy for OsslGlobalProperties {
    const FILE: *const c_char = CTX_FILE;
    const LINE_ALLOC: c_int = LINE_ZALLOC_GLOBP;
    const LINE_FREE: c_int = LINE_FREE_GLOBP;

    /// `ossl_ctx_global_properties_free`'s body without the block release: release the current
    /// property list exactly once, through the authority's own releaser.
    unsafe fn destroy_body(ptr: *mut OsslGlobalProperties) {
        // SAFETY: `ptr` is a live holder per the owner's contract; `list` is NULL or one list this
        // crate owns, and `ossl_property_free` accepts NULL and releases it once.
        unsafe { ossl_property_free((*ptr).list) };
    }
}

/// `NO_MIRRORED`'s bit, so the field is written by name rather than by a bare `1`.
#[allow(dead_code)] // its two readers are the accessors below, which are not yet reached
const NO_MIRRORED: u32 = 1;

/// `void ossl_ctx_global_properties_free(void *vglobp)`
///
/// The list first, the block second, and nothing at all for NULL.
///
/// # Safety
/// `vglobp` must be NULL or a pointer returned by
/// [`ossl_ctx_global_properties_new`] and not already released.
pub(crate) unsafe fn ossl_ctx_global_properties_free(vglobp: *mut c_void) {
    // SAFETY: `vglobp` is NULL or a block a previous
    // `ossl_ctx_global_properties_new` handed out and `Drop` has not released; `from_raw`
    // reclaims it (NULL yields `None`), and its `Drop` runs the authority's list release first and
    // then the block release at `FILE`/`LINE_FREE_GLOBP`, exactly once.
    drop(unsafe {
        OwnedCtx::<OsslGlobalProperties>::from_raw(vglobp.cast::<OsslGlobalProperties>())
    });
}

/// `void *ossl_ctx_global_properties_new(OSSL_LIB_CTX *ctx)` — the slot 14 constructor.
///
/// One zeroed block. The `ctx` argument is accepted and unused, as in the authority.
pub(crate) fn ossl_ctx_global_properties_new(_ctx: *mut c_void) -> *mut c_void {
    // `OwnedCtx::zalloc` is the authority's `OPENSSL_zalloc(sizeof(OSSL_GLOBAL_PROPERTIES))` at
    // `property.c:126`; a zeroed block is the authority's constructed empty holder. The returned
    // raw pointer transfers ownership to the slot, whose release edge is
    // `ossl_ctx_global_properties_free`.
    OwnedCtx::<OsslGlobalProperties>::zalloc().map_or(core::ptr::null_mut(), |globp| {
        globp.into_raw().cast::<c_void>()
    })
}

/// `OSSL_PROPERTY_LIST **ossl_ctx_global_properties(OSSL_LIB_CTX *libctx, int loadconfig)`.
///
/// Answers a pointer to the **holder's `list` field**, not the holder: the caller owns the list it
/// finds there, and `add`'s property lookup is the only thing that reads through it. A NULL holder
/// answers NULL rather than pointing at anything, which is the distinction the caller tests.
///
/// `loadconfig` is what makes this more than a slot read: with it set, the configuration file is
/// loaded **first**, so a `providers` section can set properties before the first query is
/// answered. The `#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_AUTOLOAD_CONFIG)` guard is not
/// present on the admitted profile — neither name is defined — so the branch is live, and a
/// refused load is a NULL answer rather than a slot read that would have loaded nothing.
///
/// # Safety
/// `libctx` must be NULL or live.
#[allow(dead_code)] // // unreachable until the store's `_fetch` and 7.2's default-property paths
pub(crate) unsafe fn ossl_ctx_global_properties(
    libctx: *mut c_void,
    loadconfig: c_int,
) -> *mut *mut crate::property::list::OsslPropertyList {
    if loadconfig != 0 && OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, core::ptr::null()) == 0 {
        return core::ptr::null_mut();
    }
    // `lib_ctx_get_data` is a SAFE function in this crate (D113), so the slot read needs no block
    // even though this function is `unsafe`.
    let globp = crate::context::lib_ctx_get_data(
        libctx,
        crate::context::OSSL_LIB_CTX_GLOBAL_PROPERTIES_INDEX,
    )
    .cast::<OsslGlobalProperties>();
    if globp.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `globp` is the live slot object.
    unsafe { core::ptr::addr_of_mut!((*globp).list) }
}

/// `int ossl_global_properties_no_mirrored(OSSL_LIB_CTX *libctx)`.
///
/// The reader is `evp_fetch.c:471`'s, inside `evp_default_properties_is_fips_enabled`: a NULL
/// holder is **0** and not an error, so a context that was never given global properties answers
/// "mirroring is still on".
///
/// # Safety
/// `libctx` must be NULL or live.
#[allow(dead_code)] // // unreachable until 7.2's `evp_default_properties_is_fips_enabled`
pub(crate) unsafe fn ossl_global_properties_no_mirrored(libctx: *mut c_void) -> c_int {
    // `lib_ctx_get_data` is a SAFE function in this crate (D113), so the slot read needs no block
    // even though this function is `unsafe`.
    let globp = crate::context::lib_ctx_get_data(
        libctx,
        crate::context::OSSL_LIB_CTX_GLOBAL_PROPERTIES_INDEX,
    )
    .cast::<OsslGlobalProperties>();
    if globp.is_null() {
        return 0;
    }
    // SAFETY: `globp` is the live slot object.
    c_int::from(unsafe { (*globp).no_mirrored } & NO_MIRRORED != 0)
}

/// `void ossl_global_properties_stop_mirroring(OSSL_LIB_CTX *libctx)`.
///
/// A one-way flag — there is no function that clears it — and a NULL holder is *nothing to do*
/// rather than an error. Its only caller is `evp_fetch.c:478`, which sets it when the default
/// property query turns FIPS mode on, so that the context's global properties stop being mirrored
/// into the default context.
///
/// # Safety
/// `libctx` must be NULL or live.
#[allow(dead_code)] // // unreachable until 7.2 sets the flag from the FIPS default query
pub(crate) unsafe fn ossl_global_properties_stop_mirroring(libctx: *mut c_void) {
    // `lib_ctx_get_data` is a SAFE function in this crate (D113), so the slot read needs no block
    // even though this function is `unsafe`.
    let globp = crate::context::lib_ctx_get_data(
        libctx,
        crate::context::OSSL_LIB_CTX_GLOBAL_PROPERTIES_INDEX,
    )
    .cast::<OsslGlobalProperties>();
    if !globp.is_null() {
        // SAFETY: `globp` is the live slot object.
        unsafe { (*globp).no_mirrored |= NO_MIRRORED };
    }
}
