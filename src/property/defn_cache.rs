//! Phase 6.7a — `crypto/property/defn_cache.c`, the per-context definition cache.
//!
//! A *definition* is a property string as an algorithm declares it — `provider=default`,
//! `fips=yes` — and a *query* is one as a fetch writes it. Both are parsed into an
//! `OSSL_PROPERTY_LIST`, and both are cached by their original text so that the same
//! string is parsed once per context. This file is that cache: an lhash keyed by the
//! text, holding the parsed list.
//!
//! ## What 6.7a lands, and what it leaves
//!
//! The constructor and the releaser, because `context_init` builds slot 2 and
//! `context_deinit_objs` releases it, and a slot that cannot be released is not a
//! slot that has landed. `ossl_prop_defn_get` and `ossl_prop_defn_set` are 6.7b's:
//! `get` returns an `OSSL_PROPERTY_LIST`, which does not exist until the grammar
//! does, and `set` frees one through `ossl_property_free`, which is
//! `property_parse.c`'s.
//!
//! That split is why this module can compile at all today: an lhash of
//! `PROPERTY_DEFN_ELEM` needs only the element type and a comparator, so the cache's
//! container is complete while its contents are not. **The slot is therefore filled
//! and empty**, which is exactly what the authority's own constructor produces —
//! `lh_PROPERTY_DEFN_ELEM_new` on an empty table. Nothing is asserted about a list
//! that has never been stored, so nothing is claimed beyond the slot's existence.
//!
//! ## The element is self-referential, like the string table's
//!
//! ```c
//! typedef struct {
//!     const char *prop;
//!     OSSL_PROPERTY_LIST *defn;
//!     char body[1];
//! } PROPERTY_DEFN_ELEM;
//! ```
//!
//! and `ossl_prop_defn_set` does `p->prop = p->body; memcpy(p->body, prop, len + 1)`,
//! so the key lives inside the same block. `property_defn_free` releases the list and
//! then the block, in that order.
//!
//! The `defn` field is compared by nothing: `property_defn_hash` hashes `prop` and
//! `property_defn_cmp` compares `prop`. It is released, never read, until 6.7b.

use core::ffi::{c_char, c_int, c_void};

use crate::property::list::OsslPropertyList;
use crate::runtime::lhash::{
    OPENSSL_LH_doall, OPENSSL_LH_free, OPENSSL_LH_new, OPENSSL_LH_strhash, OpenSslLhash,
};
use crate::runtime::mem::CRYPTO_free;

extern "C" {
    /// `int strcmp(const char *, const char *)` — `property_defn_cmp`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
}

/// The authority's translation unit.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/property/defn_cache.c".as_ptr();

/// `property_defn_free`'s `OPENSSL_free(elem)`.
const LINE_FREE_ELEM: c_int = 48;

/// `struct PROPERTY_DEFN_ELEM`.
///
/// `defn` holds the parsed list once 6.7b can make one; this stratum can only ever
/// see it NULL, but the releaser handles a list because the field is what 6.7b will
/// fill and a releaser that ignored it would leak.
#[repr(C)]
struct PropertyDefnElem {
    prop: *const c_char,
    defn: *mut OsslPropertyList,
    body: [c_char; 1],
}

/// `static unsigned long property_defn_hash(const PROPERTY_DEFN_ELEM *a)`
///
/// # Safety
/// `a` must be a live element of the table this module builds.
unsafe extern "C" fn property_defn_hash(a: *const c_void) -> core::ffi::c_ulong {
    // SAFETY: the lhash only hands this function elements it stores.
    let prop = unsafe { (*a.cast::<PropertyDefnElem>()).prop };
    // SAFETY: `prop` is a NUL-terminated string.
    unsafe { OPENSSL_LH_strhash(prop) }
}

/// `static int property_defn_cmp(const PROPERTY_DEFN_ELEM *a, const PROPERTY_DEFN_ELEM *b)`
///
/// # Safety
/// Both arguments must be live elements, or a key built by a caller whose `prop` is
/// valid.
unsafe extern "C" fn property_defn_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: both are live per the contract.
    let (x, y) = unsafe {
        (
            (*a.cast::<PropertyDefnElem>()).prop,
            (*b.cast::<PropertyDefnElem>()).prop,
        )
    };
    // SAFETY: both are NUL-terminated.
    unsafe { strcmp(x, y) }
}

/// The lhash `doall` adapter: `lh_PROPERTY_DEFN_ELEM_doall(t, &property_defn_free)`.
///
/// The list is released first and the block second, in the authority's order. The
/// list is NULL for every element this stratum can currently create, and
/// `ossl_property_free` is `OPENSSL_free`, which accepts NULL.
///
/// # Safety
/// `elem` is one of the table's elements.
unsafe extern "C" fn property_defn_free_thunk(elem: *mut c_void) {
    // SAFETY: `elem` is a live element, so its `defn` pointer is NULL or a list this
    // crate allocated.
    unsafe {
        crate::property::parse::ossl_property_free((*elem.cast::<PropertyDefnElem>()).defn);
        CRYPTO_free(elem, FILE, LINE_FREE_ELEM);
    }
}

/// `void ossl_property_defns_free(void *vproperty_defns)`
///
/// # Safety
/// `vproperty_defns` must be NULL or a table returned by
/// [`ossl_property_defns_new`] and not already released.
pub(crate) unsafe fn ossl_property_defns_free(vproperty_defns: *mut c_void) {
    if vproperty_defns.is_null() {
        return;
    }
    let t = vproperty_defns.cast::<OpenSslLhash>();
    // SAFETY: `t` is a table built by `ossl_property_defns_new`, so every element is
    // a `PropertyDefnElem` this module created.
    unsafe {
        OPENSSL_LH_doall(t, Some(property_defn_free_thunk));
        OPENSSL_LH_free(t);
    }
}

/// `void *ossl_property_defns_new(OSSL_LIB_CTX *ctx)` — the slot 2 constructor.
///
/// One lhash, empty. The `ctx` argument is accepted and unused, as in the authority.
pub(crate) fn ossl_property_defns_new(_ctx: *mut c_void) -> *mut c_void {
    OPENSSL_LH_new(Some(property_defn_hash), Some(property_defn_cmp)).cast::<c_void>()
}
