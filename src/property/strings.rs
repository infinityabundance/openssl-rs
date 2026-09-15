//! Phase 6.7a — `crypto/property/property_string.c`, the property string table.
//!
//! Every property name and every property value that the property subsystem ever
//! sees is *interned* here: a string is turned into a small integer once, and every
//! later comparison is an integer compare. The table exists because property
//! matching happens per fetch per algorithm; without it a fetch would be a forest of
//! `strcmp`s.
//!
//! ## Two tables, two counters, and one ordering that is a contract
//!
//! Names and values live in **separate** namespaces, each with its own counter, so
//! the name `"fips"` and the value `"fips"` are different entries with their own
//! numbers that may happen to be equal. Indices are one-based: `new_property_string`
//! assigns `idx = ++*pidx`, and 0 means "no such name, or no such value" rather than
//! naming the first one.
//!
//! That makes the *insertion order* observable, because `ossl_property_parse_init`
//! asserts it at every context construction:
//!
//! ```c
//! if ((ossl_property_value(ctx, "yes", 1) != OSSL_PROPERTY_TRUE)
//!     || (ossl_property_value(ctx, "no", 1) != OSSL_PROPERTY_FALSE))
//!     goto err;
//! ```
//!
//! with `OSSL_PROPERTY_TRUE == 1` and `OSSL_PROPERTY_FALSE == 2`. Because the value
//! counter is separate, "yes" and "no" are the first two *values* even though six
//! names were interred first. Getting that wrong — sharing one counter, or
//! interning the names as values — fails the authority's own check at start up.
//!
//! ## The reverse lookup reads a stack, and that is why the stack exists
//!
//! `ossl_property_name_str(ctx, idx)` has to turn the number back into a string.
//! The authority's `OPENSSL_SMALL_FOOTPRINT` build walks the hash table to find the
//! entry with that index; the ordinary build — and the admitted profile's
//! `configdata.pm` does **not** define `OPENSSL_SMALL_FOOTPRINT`, which is measured
//! rather than assumed — keeps a `STACK_OF(OPENSSL_CSTRING)` in insertion order and
//! reads `sk_value(list, idx - 1)`. The stack is therefore not an optimisation but
//! the lookup itself, and it is also what makes index assignment and push order
//! one event: the string is pushed *before* the insert, and the push is undone if
//! the insert reports an error.
//!
//! The consequence of `idx - 1` is that index 0 asks for `sk_value(list, -1)`,
//! which is out of range; the authority's `sk_value` returns NULL for that and so
//! does this crate's, so "index 0 has no name" is the range check.
//!
//! ## The element is self-referential, and its layout is reproduced
//!
//! ```c
//! typedef struct {
//!     const char *s;
//!     OSSL_PROPERTY_IDX idx;
//!     char body[1];
//! } PROPERTY_STRING;
//! ```
//!
//! `s` points at the element's own `body`, so one `OPENSSL_malloc` holds the header
//! and the string and the releaser only has to free the block — `property_free` is a
//! bare `OPENSSL_free`. On x86-64 that is 8 + 4 + 1 padded to **16** bytes with
//! `body` at offset 12, and `new_property_string` allocates `sizeof(*ps) + l`, which
//! is `16 + l`. The layout is written out here rather than approximated, because a
//! Rust type with a trailing `[c_char; 1]` gives the same offsets and the same
//! `size_of`, and the arithmetic has to be the authority's for the string to land
//! where `s` says it does.

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;

use crate::context::{lib_ctx_get_data, OSSL_LIB_CTX_PROPERTY_STRING_INDEX};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::lhash::{
    OPENSSL_LH_doall, OPENSSL_LH_error, OPENSSL_LH_free, OPENSSL_LH_insert, OPENSSL_LH_new,
    OPENSSL_LH_retrieve, OPENSSL_LH_strhash, OpenSslLhash,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_pop, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};

extern "C" {
    /// `int strcmp(const char *, const char *)` — `property_cmp`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    /// `size_t strlen(const char *)` — `new_property_string`'s `l`.
    fn strlen(s: *const c_char) -> usize;
}

/// The authority's translation unit. `CRYPTO_malloc` records it, and the error
/// coordinates the raise sites below carry are generated from the same file.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/property/property_string.c".as_ptr();

/// `property_free`'s `OPENSSL_free(ps)`.
const LINE_FREE_PS: c_int = 62;
/// `ossl_property_string_data_free`'s `OPENSSL_free(propdata)`.
const LINE_FREE_DATA: c_int = 93;
/// `ossl_property_string_data_new`'s `OPENSSL_zalloc`.
const LINE_ZALLOC_DATA: c_int = 98;
/// `new_property_string`'s `OPENSSL_malloc`.
const LINE_MALLOC_PS: c_int = 129;
/// `new_property_string`'s `OPENSSL_free(ps)` on an index wrap.
const LINE_FREE_PS_WRAP: c_int = 136;

/// `struct PROPERTY_STRING`.
///
/// Only ever reached through a raw pointer: the element is allocated by
/// `OPENSSL_malloc` as a header plus a tail, and `s` points at its own tail. The
/// `body` field is a one-element array so that `size_of` and the field offset are
/// the authority's, not an approximation.
#[repr(C)]
struct PropertyString {
    s: *const c_char,
    idx: c_int,
    body: [c_char; 1],
}

/// `struct PROPERTY_STRING_DATA` — the slot's object.
///
/// The two `*list` stacks are present because the admitted profile does not define
/// `OPENSSL_SMALL_FOOTPRINT`; see the module documentation for why the reverse
/// lookup reads them.
#[repr(C)]
pub(crate) struct PropertyStringData {
    lock: *mut CryptoRwlock,
    prop_names: *mut OpenSslLhash,
    prop_values: *mut OpenSslLhash,
    prop_name_idx: c_int,
    prop_value_idx: c_int,
    prop_namelist: *mut OpenSslStack,
    prop_valuelist: *mut OpenSslStack,
}

/// `static unsigned long property_hash(const PROPERTY_STRING *a)`
///
/// # Safety
/// `a` must be a live `PropertyString`, as the lhash contract guarantees.
unsafe extern "C" fn property_hash(a: *const c_void) -> c_ulong {
    // SAFETY: the lhash only ever hands this function elements it stores, all of
    // which were built by `new_property_string`.
    let s = unsafe { (*a.cast::<PropertyString>()).s };
    // SAFETY: `s` is that element's own `body`, a NUL-terminated string.
    unsafe { OPENSSL_LH_strhash(s) }
}

/// `static int property_cmp(const PROPERTY_STRING *a, const PROPERTY_STRING *b)`
///
/// # Safety
/// Both arguments must be live `PropertyString`s, or — for the probe key the
/// callers build on the stack — a `PropertyString` whose `s` is valid.
unsafe extern "C" fn property_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: both are live per the contract.
    let (x, y) = unsafe {
        (
            (*a.cast::<PropertyString>()).s,
            (*b.cast::<PropertyString>()).s,
        )
    };
    // SAFETY: both are NUL-terminated.
    unsafe { strcmp(x, y) }
}

/// `static void property_free(PROPERTY_STRING *ps)` — `OPENSSL_free(ps)`, the whole
/// block, because `s` points inside it.
///
/// # Safety
/// `ps` must come from `new_property_string` and not have been released.
unsafe fn property_free(ps: *mut PropertyString) {
    // SAFETY: the caller's contract.
    unsafe { CRYPTO_free(ps.cast::<c_void>(), FILE, LINE_FREE_PS) };
}

/// The lhash `doall` adapter: `lh_PROPERTY_STRING_doall(t, &property_free)`.
///
/// # Safety
/// `p` is one of the table's elements.
unsafe extern "C" fn property_free_thunk(p: *mut c_void) {
    // SAFETY: as `property_free`.
    unsafe { property_free(p.cast::<PropertyString>()) };
}

/// `static void property_table_free(PROP_TABLE **pt)` — empty the table, release the
/// elements, release the table, and clear the caller's pointer.
///
/// # Safety
/// `pt` must be the address of a live `*mut OpenSslLhash` field.
unsafe fn property_table_free(pt: *mut *mut OpenSslLhash) {
    // SAFETY: `pt` is a live field address.
    let t = unsafe { *pt };
    if !t.is_null() {
        // SAFETY: `t` is a table built by `OPENSSL_LH_new` with this module's hash
        // and comparator, so every element is a `PropertyString`.
        unsafe {
            OPENSSL_LH_doall(t, Some(property_free_thunk));
            OPENSSL_LH_free(t);
            *pt = ptr::null_mut();
        }
    }
}

/// `void ossl_property_string_data_free(void *vpropdata)`
///
/// The order is the authority's: the lock first, then the two tables, then the two
/// lists.
///
/// # Safety
/// `vpropdata` must be NULL or a pointer returned by
/// [`ossl_property_string_data_new`] and not already released.
pub(crate) unsafe fn ossl_property_string_data_free(vpropdata: *mut c_void) {
    if vpropdata.is_null() {
        return;
    }
    let propdata = vpropdata.cast::<PropertyStringData>();
    // SAFETY: `propdata` is the live slot object. Every release below is of a field
    // this module created, once, and the two table pointers are cleared through
    // their own addresses.
    unsafe {
        CRYPTO_THREAD_lock_free((*propdata).lock);
        property_table_free(ptr::addr_of_mut!((*propdata).prop_names));
        property_table_free(ptr::addr_of_mut!((*propdata).prop_values));
        OPENSSL_sk_free((*propdata).prop_namelist);
        OPENSSL_sk_free((*propdata).prop_valuelist);
        (*propdata).prop_namelist = ptr::null_mut();
        (*propdata).prop_valuelist = ptr::null_mut();
        CRYPTO_free(vpropdata, FILE, LINE_FREE_DATA);
    }
}

/// `void *ossl_property_string_data_new(OSSL_LIB_CTX *ctx)` — the slot 3 constructor.
///
/// A zeroed datum, a lock, two tables and two lists; any of the five failing
/// releases the whole thing and answers NULL, which is the authority's condition:
/// it frees unless **all** five were created.
///
/// The `ctx` argument is accepted and unused, as in the authority.
pub(crate) fn ossl_property_string_data_new(_ctx: *mut c_void) -> *mut PropertyStringData {
    let propdata = CRYPTO_zalloc(
        core::mem::size_of::<PropertyStringData>(),
        FILE,
        LINE_ZALLOC_DATA,
    )
    .cast::<PropertyStringData>();
    if propdata.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `propdata` is a fresh, exclusively owned block of exactly this type.
    let complete = unsafe {
        (*propdata).lock = CRYPTO_THREAD_lock_new();
        (*propdata).prop_names = OPENSSL_LH_new(Some(property_hash), Some(property_cmp));
        (*propdata).prop_values = OPENSSL_LH_new(Some(property_hash), Some(property_cmp));
        (*propdata).prop_namelist = OPENSSL_sk_new_null();
        (*propdata).prop_valuelist = OPENSSL_sk_new_null();
        !(*propdata).lock.is_null()
            && !(*propdata).prop_namelist.is_null()
            && !(*propdata).prop_valuelist.is_null()
            && !(*propdata).prop_names.is_null()
            && !(*propdata).prop_values.is_null()
    };
    if !complete {
        // SAFETY: `propdata` was created above and is not published, so it is
        // released exactly once, here. Any of the five that was created is released
        // by the same function, and the ones that were not are NULL, which every
        // releaser accepts.
        unsafe { ossl_property_string_data_free(propdata.cast::<c_void>()) };
        return ptr::null_mut();
    }
    propdata
}

/// `static PROPERTY_STRING *new_property_string(const char *s, OSSL_PROPERTY_IDX *pidx)`
///
/// One block, the header and the string, with `s` pointing at the string. The index
/// is `++*pidx` — so the caller's counter names the next slot before this element is
/// published — and a wrap to zero is refused, because 0 is the "no entry" index.
///
/// # Safety
/// `s` must be a NUL-terminated string and `pidx` the address of the live counter in
/// the slot datum.
unsafe fn new_property_string(s: *const c_char, pidx: *mut c_int) -> *mut PropertyString {
    // SAFETY: `s` is NUL-terminated per the contract.
    let l = unsafe { strlen(s) };
    // The block is `size_of::<PropertyString>() + l`, which is where `body` lives;
    // `CRYPTO_malloc` is the authority's `OPENSSL_malloc`.
    let ps = CRYPTO_malloc(
        core::mem::size_of::<PropertyString>() + l,
        FILE,
        LINE_MALLOC_PS,
    )
    .cast::<PropertyString>();
    if !ps.is_null() {
        // SAFETY: `ps` is a fresh block of `size_of + l`, so `l + 1` bytes written
        // at `body` (offset 12) stay inside it, and `pidx` is the caller's live
        // counter.
        unsafe {
            ptr::copy_nonoverlapping(s, ptr::addr_of_mut!((*ps).body).cast::<c_char>(), l + 1);
            (*ps).s = ptr::addr_of!((*ps).body).cast::<c_char>();
            *pidx += 1;
            (*ps).idx = *pidx;
            if (*ps).idx == 0 {
                CRYPTO_free(ps.cast::<c_void>(), FILE, LINE_FREE_PS_WRAP);
                return ptr::null_mut();
            }
        }
    }
    ps
}

/// `static OSSL_PROPERTY_IDX ossl_property_string(OSSL_LIB_CTX *ctx, int name, int create, const char *s)`
///
/// The intern. A read-locked lookup, and — only when `create` is set and the lookup
/// missed — an unlock, a write lock, a second lookup and an allocation. The second
/// lookup is not redundant: the read lock had to be dropped, so another thread may
/// have interned the string in between, and taking the other thread's index is what
/// keeps the numbers stable.
///
/// The push happens before the insert, and an insert error undoes the push *and*
/// the counter, because the index was already handed out by `new_property_string`.
///
/// # Safety
/// `ctx` must be NULL or a live context, and `s` a NUL-terminated string that stays
/// live for the call.
unsafe fn ossl_property_string(
    ctx: *mut c_void,
    name: c_int,
    create: c_int,
    s: *const c_char,
) -> c_int {
    // The lookup key. `property_cmp` and `property_hash` only read `s`, and the
    // stored elements' own `s` points into their own blocks; `idx` and `body` are
    // never read from a key.
    let p = PropertyString {
        s,
        idx: 0,
        body: [0],
    };
    let propdata =
        lib_ctx_get_data(ctx, OSSL_LIB_CTX_PROPERTY_STRING_INDEX).cast::<PropertyStringData>();
    if propdata.is_null() {
        return 0;
    }
    // SAFETY: `propdata` is the live slot object. The three fields selected here are
    // plain pointers and an integer field's address; nothing is written yet.
    let (t, pidx, slist) = unsafe {
        if name != 0 {
            (
                (*propdata).prop_names,
                ptr::addr_of_mut!((*propdata).prop_name_idx),
                (*propdata).prop_namelist,
            )
        } else {
            (
                (*propdata).prop_values,
                ptr::addr_of_mut!((*propdata).prop_value_idx),
                (*propdata).prop_valuelist,
            )
        }
    };
    // SAFETY: `(*propdata).lock` was created by this module's constructor.
    if unsafe { CRYPTO_THREAD_read_lock((*propdata).lock) } == 0 {
        // SAFETY: the generated site is this file's, at the line the authority raises
        // from.
        unsafe { raise_site(&err_sites::PROPERTY_STRING_158) };
        return 0;
    }
    let key = ptr::addr_of!(p).cast::<c_void>();
    // SAFETY: `t` is a live table and `key` is a valid key for this module's
    // comparator.
    let mut ps = unsafe { OPENSSL_LH_retrieve(t, key) }.cast::<PropertyString>();
    if ps.is_null() && create != 0 {
        // SAFETY: the read lock is held by this thread.
        unsafe { CRYPTO_THREAD_unlock((*propdata).lock) };
        // SAFETY: as the read lock above.
        if unsafe { CRYPTO_THREAD_write_lock((*propdata).lock) } == 0 {
            // SAFETY: as the raise above.
            unsafe { raise_site(&err_sites::PROPERTY_STRING_165) };
            return 0;
        }
        // SAFETY: the table and the key are live under the write lock.
        ps = unsafe { OPENSSL_LH_retrieve(t, key) }.cast::<PropertyString>();
        if ps.is_null() {
            // SAFETY: `s` is NUL-terminated and `pidx` is the live counter.
            let ps_new = unsafe { new_property_string(s, pidx) };
            if !ps_new.is_null() {
                // SAFETY: `ps_new` is live and `slist` is this datum's own list.
                if unsafe { OPENSSL_sk_push(slist, (*ps_new).s.cast::<c_void>()) } <= 0 {
                    // SAFETY: `ps_new` was created above and is not published.
                    unsafe { property_free(ps_new) };
                    // SAFETY: this thread holds the write lock.
                    unsafe { CRYPTO_THREAD_unlock((*propdata).lock) };
                    return 0;
                }
                // SAFETY: `t` is live and `ps_new` is a fresh element for it. The
                // authority ignores the returned previous element, which its `assert`
                // says must be NULL and which `NDEBUG` leaves unimplemented.
                unsafe { OPENSSL_LH_insert(t, ps_new.cast::<c_void>()) };
                // SAFETY: `t` is live.
                if unsafe { OPENSSL_LH_error(t) } != 0 {
                    // SAFETY: the push above is undone with the matching pop, the
                    // element is released, the counter is decremented because
                    // `new_property_string` incremented it, and this thread holds the
                    // write lock.
                    unsafe {
                        OPENSSL_sk_pop(slist);
                        property_free(ps_new);
                        *pidx -= 1;
                        CRYPTO_THREAD_unlock((*propdata).lock);
                    }
                    return 0;
                }
                ps = ps_new;
            }
        }
    }
    // SAFETY: this thread holds a lock on `propdata`.
    unsafe { CRYPTO_THREAD_unlock((*propdata).lock) };
    if ps.is_null() {
        0
    } else {
        // SAFETY: `ps` is a live element of `t`.
        unsafe { (*ps).idx }
    }
}

/// `static const char *ossl_property_str(int name, OSSL_LIB_CTX *ctx, OSSL_PROPERTY_IDX idx)`
///
/// The reverse lookup, through the insertion-ordered stack: `sk_value(list, idx - 1)`.
/// An index of 0 reads `sk_value(list, -1)`, which is out of range and answers NULL
/// — that, and not a bounds test, is how "index 0 has no name" is expressed.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[allow(dead_code)] // unreachable until the strata that read a property back land (6.7b, 6.8)
unsafe fn ossl_property_str(name: c_int, ctx: *mut c_void, idx: c_int) -> *const c_char {
    let propdata =
        lib_ctx_get_data(ctx, OSSL_LIB_CTX_PROPERTY_STRING_INDEX).cast::<PropertyStringData>();
    if propdata.is_null() {
        return ptr::null();
    }
    // SAFETY: `propdata` is the live slot object and its lock was created by this
    // module's constructor.
    if unsafe { CRYPTO_THREAD_read_lock((*propdata).lock) } == 0 {
        // SAFETY: the generated site is this file's, at the line the authority raises
        // from.
        unsafe { raise_site(&err_sites::PROPERTY_STRING_228) };
        return ptr::null();
    }
    // SAFETY: `propdata` is live under the read lock; the list selected is one of the
    // two this module created and populated, and `idx - 1` is the authority's own
    // index arithmetic, whose out-of-range case `sk_value` answers NULL for.
    let r = unsafe {
        let list = if name != 0 {
            (*propdata).prop_namelist
        } else {
            (*propdata).prop_valuelist
        };
        OPENSSL_sk_value(list, idx - 1).cast::<c_char>()
    };
    // SAFETY: this thread holds a read lock on `propdata`.
    unsafe { CRYPTO_THREAD_unlock((*propdata).lock) };
    r
}

/// `OSSL_PROPERTY_IDX ossl_property_name(OSSL_LIB_CTX *ctx, const char *s, int create)`
///
/// # Safety
/// As [`ossl_property_string`].
pub(crate) unsafe fn ossl_property_name(
    ctx: *mut c_void,
    s: *const c_char,
    create: c_int,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { ossl_property_string(ctx, 1, create, s) }
}

/// `const char *ossl_property_name_str(OSSL_LIB_CTX *ctx, OSSL_PROPERTY_IDX idx)`
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[allow(dead_code)] // unreachable until the strata that read a property back land (6.7b, 6.8)
pub(crate) unsafe fn ossl_property_name_str(ctx: *mut c_void, idx: c_int) -> *const c_char {
    // SAFETY: forwarded.
    unsafe { ossl_property_str(1, ctx, idx) }
}

/// `OSSL_PROPERTY_IDX ossl_property_value(OSSL_LIB_CTX *ctx, const char *s, int create)`
///
/// # Safety
/// As [`ossl_property_string`].
pub(crate) unsafe fn ossl_property_value(
    ctx: *mut c_void,
    s: *const c_char,
    create: c_int,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { ossl_property_string(ctx, 0, create, s) }
}

/// `const char *ossl_property_value_str(OSSL_LIB_CTX *ctx, OSSL_PROPERTY_IDX idx)`
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[allow(dead_code)] // unreachable until the strata that read a property back land (6.7b, 6.8)
pub(crate) unsafe fn ossl_property_value_str(ctx: *mut c_void, idx: c_int) -> *const c_char {
    // SAFETY: forwarded.
    unsafe { ossl_property_str(0, ctx, idx) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};
    use crate::property::ossl_property_parse_init;

    /// A live context with slot 3 built and the authority's pre-initialisation done.
    ///
    /// The ordering contract below is **not observable through any export** — the
    /// property engine has none — so a unit test is the only place it can be
    /// asserted at all, and it is asserted against the ordering rather than against
    /// the numbers alone.
    fn prepared() -> *mut c_void {
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live, so `context_init` built slot 3.
        assert_eq!(unsafe { ossl_property_parse_init(ctx) }, 1);
        ctx
    }

    #[test]
    fn the_boolean_values_are_one_and_two_in_their_own_sequence() {
        let ctx = prepared();
        // SAFETY: `ctx` is live; the two literals are `'static`.
        unsafe {
            // The authority's own start-up assertion, made here as the assertion it
            // is: `yes` is `OSSL_PROPERTY_TRUE` (1) and `no` is
            // `OSSL_PROPERTY_FALSE` (2).
            assert_eq!(ossl_property_value(ctx, c"yes".as_ptr(), 1), 1);
            assert_eq!(ossl_property_value(ctx, c"no".as_ptr(), 1), 2);

            // The six predefined names occupy **their own** counter, so they are
            // 1..6 while the values are also 1..2. A shared counter would put `yes`
            // at 7 and `no` at 8, and every boolean property would answer wrongly.
            for (i, n) in [
                c"provider",
                c"version",
                c"fips",
                c"output",
                c"input",
                c"structure",
            ]
            .iter()
            .enumerate()
            {
                assert_eq!(ossl_property_name(ctx, n.as_ptr(), 1), i as c_int + 1);
            }

            // A value table and a name table are separate: `"fips"` is the name
            // with index 3 *and* may be interned as a value with a different one.
            assert_eq!(ossl_property_value(ctx, c"fips".as_ptr(), 1), 3);
            assert_eq!(ossl_property_name(ctx, c"fips".as_ptr(), 1), 3);

            OSSL_LIB_CTX_free(ctx);
        }
    }

    #[test]
    fn interning_twice_answers_the_same_index_and_zero_names_nothing() {
        let ctx = prepared();
        // SAFETY: `ctx` is live.
        unsafe {
            let first = ossl_property_name(ctx, c"custom".as_ptr(), 1);
            assert_eq!(first, 7, "after the six predefined names");
            assert_eq!(ossl_property_name(ctx, c"custom".as_ptr(), 1), first);
            // `create` is what makes a miss allocate: without it a new name is 0.
            assert_eq!(ossl_property_name(ctx, c"absent".as_ptr(), 0), 0);
            // The reverse lookup is `sk_value(list, idx - 1)`, so index 0 asks for
            // the -1st element and answers NULL rather than the first name.
            assert!(ossl_property_name_str(ctx, 0).is_null());
            assert!(ossl_property_value_str(ctx, 0).is_null());
            let s = ossl_property_name_str(ctx, first);
            assert!(!s.is_null());
            assert_eq!(core::ffi::CStr::from_ptr(s), c"custom");
            OSSL_LIB_CTX_free(ctx);
        }
    }

    #[test]
    fn each_context_has_its_own_tables_and_its_own_counters() {
        let a = prepared();
        let b = prepared();
        // SAFETY: both contexts are live.
        unsafe {
            assert_ne!(
                lib_ctx_get_data(a, OSSL_LIB_CTX_PROPERTY_STRING_INDEX),
                lib_ctx_get_data(b, OSSL_LIB_CTX_PROPERTY_STRING_INDEX)
            );
            assert_eq!(ossl_property_name(a, c"a-name".as_ptr(), 1), 7);
            assert_eq!(ossl_property_name(b, c"b-name".as_ptr(), 1), 7);
            assert_eq!(ossl_property_name(a, c"b-name".as_ptr(), 0), 0);
            OSSL_LIB_CTX_free(a);
            OSSL_LIB_CTX_free(b);
        }
    }
}
