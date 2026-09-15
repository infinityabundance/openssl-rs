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
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// The authority's translation unit.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/property/property.c".as_ptr();

/// `ossl_ctx_global_properties_free`'s `OPENSSL_free(globp)`.
const LINE_FREE_GLOBP: c_int = 120;
/// `ossl_ctx_global_properties_new`'s `OPENSSL_zalloc`.
const LINE_ZALLOC_GLOBP: c_int = 126;

/// `struct ossl_global_properties_st`, minus the FIPS-blocked `no_mirrored` bit.
#[repr(C)]
pub(crate) struct OsslGlobalProperties {
    list: *mut crate::property::list::OsslPropertyList,
}

/// `void ossl_ctx_global_properties_free(void *vglobp)`
///
/// The list first, the block second, and nothing at all for NULL.
///
/// # Safety
/// `vglobp` must be NULL or a pointer returned by
/// [`ossl_ctx_global_properties_new`] and not already released.
pub(crate) unsafe fn ossl_ctx_global_properties_free(vglobp: *mut c_void) {
    if vglobp.is_null() {
        return;
    }
    let globp = vglobp.cast::<OsslGlobalProperties>();
    // SAFETY: `globp` is the live slot object. `list` is NULL today and a list this
    // crate allocated once 6.7b can make one; `ossl_property_free` accepts NULL.
    unsafe {
        let list = (*globp).list;
        ossl_property_free(list);
        CRYPTO_free(vglobp, FILE, LINE_FREE_GLOBP);
    }
}

/// `void *ossl_ctx_global_properties_new(OSSL_LIB_CTX *ctx)` — the slot 14 constructor.
///
/// One zeroed block. The `ctx` argument is accepted and unused, as in the authority.
pub(crate) fn ossl_ctx_global_properties_new(_ctx: *mut c_void) -> *mut c_void {
    CRYPTO_zalloc(
        core::mem::size_of::<OsslGlobalProperties>(),
        FILE,
        LINE_ZALLOC_GLOBP,
    )
}
