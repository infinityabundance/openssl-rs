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
use crate::property::parse::ossl_property_free;
use crate::runtime::lhash::{
    OPENSSL_LH_delete, OPENSSL_LH_doall, OPENSSL_LH_error, OPENSSL_LH_free, OPENSSL_LH_insert,
    OPENSSL_LH_new, OPENSSL_LH_retrieve, OPENSSL_LH_strhash, OpenSslLhash,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

extern "C" {
    /// `int strcmp(const char *, const char *)` — `property_defn_cmp`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    /// `size_t strlen(const char *)` — `ossl_prop_defn_set`'s `len`.
    fn strlen(s: *const c_char) -> usize;
}

/// `ossl_prop_defn_set`'s `len = strlen(prop)`.
///
/// # Safety
/// `p` must be NUL-terminated.
unsafe fn c_strlen(p: *const c_char) -> usize {
    // SAFETY: the caller's contract.
    unsafe { strlen(p) }
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

/// An owned `PROPERTY_DEFN_ELEM` block from this unit's `CRYPTO_malloc`/`CRYPTO_free`
/// seam.
///
/// The block keeps the authority's exact size and its allocation `file`/`line`
/// (observable to a caller-installed `CRYPTO_set_mem_functions` hook), and its release
/// keeps the authority's own free coordinate; its *ownership* is this type. [`Self::new`]
/// allocates here, [`Self::adopt`] takes in an element the table hands back for release,
/// and `Drop` is the single plain release. The lhash owns an element it has accepted, so
/// [`Self::into_raw`] is the transfer at that ABI edge.
struct OwnedElem {
    ptr: *mut PropertyDefnElem,
    release_line: c_int,
}

impl OwnedElem {
    /// `CRYPTO_malloc(size, FILE, alloc_line)`, released at `release_line`, or `None` when
    /// the allocator answers NULL.
    fn new(size: usize, alloc_line: c_int, release_line: c_int) -> Option<OwnedElem> {
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc(size, FILE, alloc_line)
        }
        .cast::<PropertyDefnElem>();
        if raw.is_null() {
            None
        } else {
            Some(OwnedElem {
                ptr: raw,
                release_line,
            })
        }
    }

    /// Adopt an element block for release by `Drop`; NULL answers `None`.
    ///
    /// # Safety
    /// `ptr` is NULL or one of the table's elements: a block this module's allocator
    /// seam allocated in full, not a sub-range, and no other owner will release it;
    /// `release_line` is the authority's own free site.
    unsafe fn adopt(ptr: *mut PropertyDefnElem, release_line: c_int) -> Option<OwnedElem> {
        if ptr.is_null() {
            None
        } else {
            Some(OwnedElem { ptr, release_line })
        }
    }

    /// The block's address, for the raw calls that initialise or publish it.
    fn as_ptr(&self) -> *mut PropertyDefnElem {
        self.ptr
    }

    /// Give up ownership of the block to the lhash that accepted it.
    fn into_raw(self) -> *mut PropertyDefnElem {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedElem {
    /// The block's single release through the seam it was allocated on.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block this handle owns and has not released, and
        // `self.release_line` is the authority's own free site; `CRYPTO_free` accepts NULL.
        unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), FILE, self.release_line) };
    }
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
    // SAFETY: `elem` is one of the table's elements, allocated in full by
    // `ossl_prop_defn_set` through the crate's allocator seam and not released before;
    // the `doall` calls this once per element, so this frame becomes its only owner.
    let Some(elem) = (unsafe { OwnedElem::adopt(elem.cast::<PropertyDefnElem>(), LINE_FREE_ELEM) })
    else {
        return;
    };
    // SAFETY: `elem` is a live element, so its `defn` pointer is NULL or a list this
    // crate allocated. The owner's `Drop` then releases the block, after the list.
    unsafe { crate::property::parse::ossl_property_free((*elem.as_ptr()).defn) };
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

/// `OSSL_PROPERTY_LIST *ossl_prop_defn_get(OSSL_LIB_CTX *ctx, const char *prop)`
///
/// The cache lookup. Two things about it are worth naming:
///
///   * the two `ossl_assert`s are `(x) != 0` under `NDEBUG`, which the admitted
///     profile's `configdata.pm` defines — so a NULL table and an entry with a NULL
///     `defn` each **return NULL** rather than aborting. The opposite assumption turns
///     a NULL return into a process death.
///   * the context's lock is taken for the lookup, which is what makes the cache safe
///     against a concurrent `set` rather than merely convenient.
///
/// # Safety
/// `ctx` must be NULL or live, and `prop` NULL or NUL-terminated.
#[allow(dead_code)] // unreachable until 6.8's fetch calls it
pub(crate) unsafe fn ossl_prop_defn_get(
    ctx: *mut c_void,
    prop: *const c_char,
) -> *mut OsslPropertyList {
    // SAFETY: `ctx` is NULL or live, so this answers slot 2 or NULL.
    let t = crate::context::lib_ctx_get_data(ctx, crate::context::OSSL_LIB_CTX_PROPERTY_DEFN_INDEX)
        .cast::<OpenSslLhash>();
    if t.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `ctx` is NULL or live, so it has a lock.
    if crate::context::lib_ctx_read_lock(ctx) == 0 {
        return core::ptr::null_mut();
    }
    let elem = PropertyDefnElem {
        prop,
        defn: core::ptr::null_mut(),
        body: [0],
    };
    // SAFETY: `t` is a live table built by `ossl_property_defns_new`, and `elem` is a
    // valid key for its comparator, which reads `prop` only.
    let r = unsafe {
        OPENSSL_LH_retrieve(t, core::ptr::addr_of!(elem).cast::<c_void>())
            .cast::<PropertyDefnElem>()
    };
    // SAFETY: the lock was taken above.
    crate::context::lib_ctx_unlock(ctx);
    if r.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `r` is a live element.
    unsafe { (*r).defn }
}

/// `int ossl_prop_defn_set(OSSL_LIB_CTX *ctx, const char *prop,
/// OSSL_PROPERTY_LIST **pl)`
///
/// The cache store, and all three of its shapes:
///
///   * `prop == NULL` answers **1** without touching anything, so a caller may pass a
///     missing property string and get success;
///   * `pl == NULL` **deletes** the entry and answers 1;
///   * a `pl` whose property is already cached frees the caller's list and *overwrites
///     `*pl` with the cached one*, so the caller ends up sharing the cache's object —
///     which is why nothing may free a list it obtained this way twice;
///   * otherwise the text and the list are copied into one block and inserted.
///
/// The copy is one allocation and it is self-referential: `p->prop = p->body`, so the
/// key lives inside the same block as the entry's header and the releaser only frees
/// the block.
///
/// # Safety
/// `ctx` must be NULL or live; `prop` NULL or NUL-terminated; `pl` must be NULL or
/// point at a live `*mut OsslPropertyList` the caller owns.
#[allow(dead_code)] // unreachable until 6.8's fetch calls it
pub(crate) unsafe fn ossl_prop_defn_set(
    ctx: *mut c_void,
    prop: *const c_char,
    pl: *mut *mut OsslPropertyList,
) -> c_int {
    /// `ossl_prop_defn_set`'s `OPENSSL_malloc`.
    const LINE_MALLOC_ELEM: c_int = 120;
    /// `ossl_prop_defn_set`'s `OPENSSL_free(p)` on the unwind path.
    const LINE_FREE_ELEM: c_int = 132;

    // SAFETY: `ctx` is NULL or live, so this answers slot 2 or NULL.
    let t = crate::context::lib_ctx_get_data(ctx, crate::context::OSSL_LIB_CTX_PROPERTY_DEFN_INDEX)
        .cast::<OpenSslLhash>();
    if t.is_null() {
        return 0;
    }
    if prop.is_null() {
        return 1;
    }
    // SAFETY: `ctx` is NULL or live, so it has a lock.
    if crate::context::lib_ctx_write_lock(ctx) == 0 {
        return 0;
    }
    // Everything below runs under the write lock and leaves through `end`.
    let mut res: c_int = 1;
    let elem = PropertyDefnElem {
        prop,
        defn: core::ptr::null_mut(),
        body: [0],
    };
    let key = core::ptr::addr_of!(elem).cast::<c_void>();
    if pl.is_null() {
        // SAFETY: `t` is live and `key` is a valid key for its comparator. The
        // element the table returns is not freed here, which is the authority's
        // behaviour and the reason the cache is "not cleaned out except at shutdown".
        unsafe { OPENSSL_LH_delete(t, key) };
    } else {
        // SAFETY: `t` is live and `key` is a valid key.
        let p = unsafe { OPENSSL_LH_retrieve(t, key) }.cast::<PropertyDefnElem>();
        if !p.is_null() {
            // The caller's list is freed and replaced by the cached one, so both
            // sides now refer to the same object.
            // SAFETY: `*pl` is the caller's live list and `(*p).defn` is the cached
            // one, which outlives the call because the cache owns it.
            unsafe {
                ossl_property_free(*pl);
                *pl = (*p).defn;
            }
        } else {
            // SAFETY: `prop` is NUL-terminated per the contract.
            let len = unsafe { c_strlen(prop) };
            // `sizeof(*p) + len`, where `sizeof(*p)` places `body` at offset 16 on this
            // target: 8 for `prop`, 8 for `defn`, 1 for `body`, padded to 24. The sum is
            // checked so an impossible wrapped request never reaches the allocator; on
            // that path no block is allocated, which is the allocation-failure outcome.
            let block = core::mem::size_of::<PropertyDefnElem>()
                .checked_add(len)
                .and_then(|size| OwnedElem::new(size, LINE_MALLOC_ELEM, LINE_FREE_ELEM));
            if let Some(block) = block {
                let p = block.as_ptr();
                // SAFETY: `p` is `size_of + len` bytes, so writing `len + 1` bytes at
                // `body` (offset 16) stays inside it.
                unsafe {
                    (*p).prop = core::ptr::addr_of!((*p).body).cast::<c_char>();
                    (*p).defn = *pl;
                    core::ptr::copy_nonoverlapping(
                        prop,
                        core::ptr::addr_of_mut!((*p).body).cast::<c_char>(),
                        len + 1,
                    );
                }
                // SAFETY: `t` is live and `p` is a fresh element for it.
                let old =
                    unsafe { OPENSSL_LH_insert(t, p.cast::<c_void>()).cast::<PropertyDefnElem>() };
                // `!ossl_assert(old == NULL)` under `NDEBUG` is `old != NULL`, and the
                // retrieve above established that it cannot be — so this arm is the
                // authority's assertion, kept as a branch rather than removed.
                if old.is_null() {
                    // SAFETY: `t` is live.
                    if unsafe { OPENSSL_LH_error(t) } == 0 {
                        // No error: the element is in the table and the table owns it.
                        let _ = block.into_raw();
                        // SAFETY: the lock was taken above.
                        crate::context::lib_ctx_unlock(ctx);
                        return res;
                    }
                }
                // The unwind path, reached when the insertion failed or the assertion's
                // condition was false. The authority releases the block here whether or
                // not the table kept it, which is a double-free if it did; reproduced
                // structurally, and unreachable unless an allocation fails. The owner's
                // `Drop` is that release, at the authority's line 132.
            }
            res = 0;
        }
    }
    // SAFETY: the lock was taken above.
    crate::context::lib_ctx_unlock(ctx);
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};
    use crate::property::parse::{ossl_parse_property, ossl_property_free};

    /// A live context with the property engine pre-initialised.
    fn ctx() -> *mut c_void {
        let c = OSSL_LIB_CTX_new();
        assert!(!c.is_null());
        // SAFETY: `c` is live and its slot 3 was built by `context_init`.
        assert_eq!(unsafe { crate::property::ossl_property_parse_init(c) }, 1);
        c
    }

    #[test]
    fn the_cache_answers_null_for_an_unfilled_text() {
        let c = ctx();
        // SAFETY: `c` is live and the literal is NUL-terminated.
        unsafe {
            assert!(ossl_prop_defn_get(c, c"fips=yes".as_ptr()).is_null());
            OSSL_LIB_CTX_free(c);
        }
    }

    #[test]
    fn a_stored_list_is_shared_rather_than_copied_a_second_time() {
        let c = ctx();
        // SAFETY: `c` is live and every literal is NUL-terminated.
        unsafe {
            let first = ossl_parse_property(c, c"fips=yes".as_ptr());
            assert!(!first.is_null());
            let mut mine = first;
            // The store takes ownership of the *entry*; `mine` keeps its pointer.
            assert_eq!(ossl_prop_defn_set(c, c"fips=yes".as_ptr(), &mut mine), 1);

            let got = ossl_prop_defn_get(c, c"fips=yes".as_ptr());
            assert!(!got.is_null(), "the text now names a cached list");

            // A second store of the same text must free the caller's list and replace
            // it with the cached one — which is why nothing may free a list obtained
            // this way twice.
            let mut second = ossl_parse_property(c, c"fips=yes".as_ptr());
            assert!(!second.is_null());
            let second_before = second;
            assert_eq!(ossl_prop_defn_set(c, c"fips=yes".as_ptr(), &mut second), 1);
            assert_eq!(
                second, got,
                "the caller's list is replaced by the cached one"
            );
            assert_ne!(
                second, second_before,
                "and the caller's own list was released"
            );

            // Deleting with a NULL list leaves the text unnamed again.
            assert_eq!(
                ossl_prop_defn_set(c, c"fips=yes".as_ptr(), core::ptr::null_mut()),
                1
            );
            assert!(
                ossl_prop_defn_get(c, c"fips=yes".as_ptr()).is_null(),
                "a NULL list deletes the entry"
            );

            // A NULL text is a no-op that answers success, in both directions.
            assert!(ossl_prop_defn_get(c, core::ptr::null()).is_null());
            assert_eq!(
                ossl_prop_defn_set(c, core::ptr::null(), core::ptr::null_mut()),
                1
            );

            ossl_property_free(first);
            OSSL_LIB_CTX_free(c);
        }
    }

    #[test]
    fn the_cache_is_per_context() {
        let a = ctx();
        let b = ctx();
        // SAFETY: both contexts are live and the literal is NUL-terminated.
        unsafe {
            let mut mine = ossl_parse_property(a, c"fips=yes".as_ptr());
            assert_eq!(ossl_prop_defn_set(a, c"fips=yes".as_ptr(), &mut mine), 1);
            assert!(!ossl_prop_defn_get(a, c"fips=yes".as_ptr()).is_null());
            assert!(
                ossl_prop_defn_get(b, c"fips=yes".as_ptr()).is_null(),
                "a second context has its own cache"
            );
            // Free the entry through the context that owns it, by deleting it.
            assert_eq!(
                ossl_prop_defn_set(a, c"fips=yes".as_ptr(), core::ptr::null_mut()),
                1
            );
            OSSL_LIB_CTX_free(a);
            OSSL_LIB_CTX_free(b);
        }
    }
}
