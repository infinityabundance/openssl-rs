//! `crypto/x509/by_store.c` — the `X509_LOOKUP_store` method: a store URI's contents loaded into
//! the `X509_STORE`. **This slice lands the unit whole**: its one open export (`X509_LOOKUP_store`)
//! and the eight `static` callbacks and helpers it is built on.
//!
//! `crypto/x509/by_store.c` is 293 lines. Its closure is the landed `OSSL_STORE_*` surface
//! (`src/store/store_lib.rs`, Phase 10), [`X509_LOOKUP_get_store`](crate::x509::x509_lu::X509_LOOKUP_get_store)/
//! [`X509_LOOKUP_get_method_data`](crate::x509::x509_lu::X509_LOOKUP_get_method_data)/
//! [`X509_LOOKUP_set_method_data`](crate::x509::x509_lu::X509_LOOKUP_set_method_data),
//! [`X509_STORE_add_cert`](crate::x509::x509_lu::X509_STORE_add_cert)/
//! [`X509_STORE_add_crl`](crate::x509::x509_lu::X509_STORE_add_crl), the object cache readers and
//! the store's read lock — so nothing here waits on a later stratum.
//!
//! ## `X509_L_ADD_STORE` and `X509_L_LOAD_STORE`
//!
//! The `ctrl` door carries two commands (`include/openssl/x509_vfy.h:285-286`): `X509_L_ADD_STORE`
//! (3) records a URI to search later, and `X509_L_LOAD_STORE` (4) loads a URI's objects into the
//! callers' store immediately. A command the authority does not implement answers 0.
//!
//! ## The one substitution
//!
//! The method's `get_by_subject` is `by_store_subject`, and `by_store.c:269-273` records why
//! `get_by_issuer_serial`, `get_by_fingerprint` and `get_by_alias` are NULL: "there's simply not
//! enough support in the `X509_LOOKUP` or `X509_STORE` APIs". That comment is transcribed in place
//! rather than the three NULL slots being either filled or dropped.
//!
//! `crypto/x509/by_store.c` raises nothing, so it is deliberately **not** listed in
//! `gen_err_raise_sites.py`'s covered set and declares no raise coordinate. It does call
//! `ERR_set_mark`/`ERR_pop_to_mark` around the optional `OSSL_STORE_find` criterion, which is the
//! authority's own way of discarding a search failure.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_void, CStr};
use core::mem::size_of;
use core::ptr;

use crate::runtime::err::{ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::store::store_lib::{
    OSSL_STORE_INFO_free, OSSL_STORE_INFO_get0_CERT, OSSL_STORE_INFO_get0_CRL,
    OSSL_STORE_INFO_get0_NAME, OSSL_STORE_INFO_get_type, OSSL_STORE_SEARCH_by_name,
    OSSL_STORE_SEARCH_free, OSSL_STORE_close, OSSL_STORE_find, OSSL_STORE_load, OSSL_STORE_open_ex,
    OsslStoreSearch,
};
use crate::store::{OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_CRL, OSSL_STORE_INFO_NAME};
use crate::x509::x509_lu::{
    ossl_x509_store_read_lock, X509Lookup, X509LookupMethod, X509Object,
    X509_LOOKUP_get_method_data, X509_LOOKUP_get_store, X509_LOOKUP_set_method_data,
    X509_LOOKUP_TYPE, X509_LU_CRL, X509_LU_NONE, X509_LU_X509,
};
use crate::x509::x509_lu::{
    X509_OBJECT_retrieve_by_subject, X509_STORE_add_cert, X509_STORE_add_crl,
};
use crate::x509::x509_lu::{
    X509_OBJECT_set1_X509, X509_OBJECT_set1_X509_CRL, X509_STORE_get0_objects, X509_STORE_unlock,
};
use crate::x509::x_crl::{X509Crl, X509_CRL_free};
use crate::x509::x_name::X509Name;
use crate::x509::x_x509::{X509_free, X509};

/// `X509_L_ADD_STORE` — `include/openssl/x509_vfy.h:285`.
const X509_L_ADD_STORE: c_int = 3;
/// `X509_L_LOAD_STORE` — `include/openssl/x509_vfy.h:286`.
const X509_L_LOAD_STORE: c_int = 4;

/// The `OPENSSL_FILE` string for this unit's `OPENSSL_zalloc`/`OPENSSL_strdup`/`OPENSSL_free`
/// expansions.
const FILE: &CStr = c"crypto/x509/by_store.c";
/// `free_store`'s `OPENSSL_free(store->uri)` (`:115`).
const LINE_FREE_STORE_URI: c_int = 115;
/// `free_store`'s `OPENSSL_free(store->propq)` (`:116`).
const LINE_FREE_STORE_PROPQ: c_int = 116;
/// `free_store`'s `OPENSSL_free(store)` (`:117`).
const LINE_FREE_STORE: c_int = 117;
/// `by_store_ctrl_ex`'s `OPENSSL_zalloc(sizeof(*store))` (`:135`).
const LINE_ZALLOC_STORE: c_int = 135;
/// `by_store_ctrl_ex`'s `OPENSSL_strdup(argp)` (`:142`).
const LINE_STRDUP_URI: c_int = 142;
/// `by_store_ctrl_ex`'s `OPENSSL_strdup(propq)` (`:145`).
const LINE_STRDUP_PROPQ: c_int = 145;

/// `struct cached_store_st` (`CACHED_STORE`) — `crypto/x509/by_store.c:16-20`.
///
/// One store URI an `X509_L_ADD_STORE` command recorded, with the library context and property
/// query it was added under.
#[repr(C)]
struct CachedStore {
    /// `char *uri` — the URI, owned.
    uri: *mut c_char,
    /// `OSSL_LIB_CTX *libctx` — the library context, borrowed.
    libctx: *mut c_void,
    /// `char *propq` — the property query, owned when non-NULL.
    propq: *mut c_char,
}

// ---------------------------------------------------------------------------------------------
// The loader — `crypto/x509/by_store.c:24-125`
// ---------------------------------------------------------------------------------------------

/// `static int cache_objects(X509_LOOKUP *lctx, CACHED_STORE *store, const OSSL_STORE_SEARCH
/// *criterion, int depth)` — `crypto/x509/by_store.c:25-110`.
///
/// Opens the store URI, optionally narrows it with the criterion (a failure there is discarded,
/// because for an `OSSL_STORE` the criterion is only an optimisation), then loads every object.
/// A `NAME` entry is a sub-directory to recurse into while `depth` allows; a `CERT`/`CRL` entry is
/// added to the lookup's store. The answer is the last load's outcome.
///
/// # Safety
///
/// `lctx` must be a live `X509_LOOKUP` owning a live store; `store` a live `CACHED_STORE` whose
/// strings are borrowed for the call; `criterion` NULL or a live search. The lookup's store must be
/// live and unlocked.
unsafe fn cache_objects(
    lctx: *mut X509Lookup,
    store: *mut CachedStore,
    criterion: *const OsslStoreSearch,
    depth: c_int,
) -> c_int {
    let mut ok = 0;
    // SAFETY: `lctx` is live per the contract.
    let xstore = unsafe { X509_LOOKUP_get_store(lctx) };

    // SAFETY: `store` is live; the allocator's type parameters are those of the authority's cast.
    let ctx = unsafe {
        OSSL_STORE_open_ex(
            (*store).uri,
            (*store).libctx,
            (*store).propq,
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            None,
            ptr::null_mut(),
        )
    };
    if ctx.is_null() {
        return 0;
    }

    if !criterion.is_null() {
        // SAFETY: neither call takes arguments; they only move the error queue's marks.
        unsafe {
            ERR_set_mark();
            OSSL_STORE_find(ctx, criterion);
            ERR_pop_to_mark();
        }
    }

    loop {
        // SAFETY: `ctx` is live per the above.
        let info = unsafe { OSSL_STORE_load(ctx) };

        // NULL means error or "end of file". Either way, we break.
        if info.is_null() {
            break;
        }

        // SAFETY: `info` is live per the above.
        let infotype = unsafe { OSSL_STORE_INFO_get_type(info) };
        ok = 0;

        if infotype == OSSL_STORE_INFO_NAME {
            // An entry in the "directory" the current URI represents; dive into it if depth allows.
            if depth > 0 {
                // SAFETY: `info` is a `NAME`, so `get0_NAME` answers its own name, and `store` is
                // live; the substore borrows both for the recursive call.
                let substore = unsafe {
                    CachedStore {
                        uri: OSSL_STORE_INFO_get0_NAME(info).cast_mut(),
                        libctx: (*store).libctx,
                        propq: (*store).propq,
                    }
                };
                // SAFETY: `substore` is a live local for the call, as the authority's stack copy is.
                ok = unsafe {
                    cache_objects(lctx, (&raw const substore).cast_mut(), criterion, depth - 1)
                };
            }
        } else {
            // `X509_STORE_add_{cert|crl}` increments the object's refcount, so the borrowed
            // `get0_{cert,crl}` result is safe to hand it.
            match infotype {
                OSSL_STORE_INFO_CERT => {
                    // SAFETY: `info` is live and `xstore` is the lookup's own store.
                    ok = unsafe {
                        X509_STORE_add_cert(xstore, OSSL_STORE_INFO_get0_CERT(info).cast::<X509>())
                    }
                }
                OSSL_STORE_INFO_CRL => {
                    // SAFETY: as above, for the CRL arm.
                    ok = unsafe {
                        X509_STORE_add_crl(xstore, OSSL_STORE_INFO_get0_CRL(info).cast::<X509Crl>())
                    }
                }
                _ => {}
            }
        }

        // SAFETY: `info` is live and this frame owns it.
        unsafe { OSSL_STORE_INFO_free(info) };
        if ok == 0 {
            break;
        }
    }
    // SAFETY: `ctx` is this call's own live context.
    unsafe { OSSL_STORE_close(ctx) };

    ok
}

/// `static void free_store(CACHED_STORE *store)` — `crypto/x509/by_store.c:112-119`.
///
/// Releases a recorded store's owned strings and the record itself. A NULL `store` is a no-op.
///
/// # Safety
///
/// `store` must be NULL or a record this module allocated, not already freed.
unsafe fn free_store(store: *mut CachedStore) {
    if !store.is_null() {
        // SAFETY: `store` is live per the contract; its strings are its own.
        unsafe {
            CRYPTO_free(
                (*store).uri.cast::<c_void>(),
                FILE.as_ptr(),
                LINE_FREE_STORE_URI,
            );
            CRYPTO_free(
                (*store).propq.cast::<c_void>(),
                FILE.as_ptr(),
                LINE_FREE_STORE_PROPQ,
            );
            CRYPTO_free(store.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_STORE);
        }
    }
}

/// The `CACHED_STORE` destructor [`by_store_free`] passes to `OPENSSL_sk_pop_free`.
///
/// # Safety
///
/// `elem` must be NULL or a record this module allocated.
unsafe extern "C" fn free_store_thunk(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or a record per the contract; `free_store` accepts NULL.
    unsafe { free_store(elem.cast::<CachedStore>()) };
}

/// `static void by_store_free(X509_LOOKUP *ctx)` — `crypto/x509/by_store.c:121-125`.
///
/// The method's `free` hook: releases the lookup's `STACK_OF(CACHED_STORE)` and every record on it.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP` whose method data is NULL or this method's own record stack.
unsafe extern "C" fn by_store_free(ctx: *mut X509Lookup) {
    // SAFETY: `ctx` is live per the contract.
    let stores = unsafe { X509_LOOKUP_get_method_data(ctx) }.cast::<OpenSslStack>();
    // SAFETY: `stores` is NULL or this method's own stack; the thunk handles NULL elements.
    unsafe { OPENSSL_sk_pop_free(stores, Some(free_store_thunk)) };
}

/// `static int by_store_ctrl_ex(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **retp,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/x509/by_store.c:127-187`.
///
/// The method's `ctrl_ex` door. `X509_L_ADD_STORE` records `argp` as a store URI (opening it once
/// now so a bad URI is reported early); a NULL `argp` is a no-op that answers 1.
/// `X509_L_LOAD_STORE` loads `argp`'s objects into the lookup's store immediately. Any other
/// command answers 0.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`; `argp`/`propq` NULL or NUL-terminated; `libctx` NULL or
/// live; the lookup's store must be live and unlocked.
unsafe extern "C" fn by_store_ctrl_ex(
    ctx: *mut X509Lookup,
    cmd: c_int,
    argp: *const c_char,
    _argl: c_long,
    _retp: *mut *mut c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    match cmd {
        X509_L_ADD_STORE => {
            if !argp.is_null() {
                // SAFETY: `ctx` is live per the contract.
                let mut stores = unsafe { X509_LOOKUP_get_method_data(ctx) }.cast::<OpenSslStack>();
                // SAFETY: the allocator takes the file/line for its mdbg record only.
                let store =
                    CRYPTO_zalloc(size_of::<CachedStore>(), FILE.as_ptr(), LINE_ZALLOC_STORE)
                        .cast::<CachedStore>();

                if store.is_null() {
                    return 0;
                }

                // SAFETY: `argp` is NUL-terminated per the contract; `store` is this call's own.
                unsafe {
                    (*store).uri = CRYPTO_strdup(argp, FILE.as_ptr(), LINE_STRDUP_URI);
                    (*store).libctx = libctx;
                    if !propq.is_null() {
                        (*store).propq = CRYPTO_strdup(propq, FILE.as_ptr(), LINE_STRDUP_PROPQ);
                    }
                }
                // Open this now to check for errors, so they can be reported early.
                // SAFETY: `argp`/`propq`/`libctx` are the caller's; the allocator's type
                // parameters are those of the authority's cast.
                let sctx = unsafe {
                    OSSL_STORE_open_ex(
                        argp,
                        libctx,
                        propq,
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null(),
                        None,
                        ptr::null_mut(),
                    )
                };
                // SAFETY: `store` is this call's own record, so its fields are live.
                let missing = unsafe {
                    (*store).uri.is_null() || (!propq.is_null() && (*store).propq.is_null())
                };
                if sctx.is_null() || missing {
                    // SAFETY: `sctx` is NULL or this call's own context; `store` is its own record.
                    unsafe {
                        OSSL_STORE_close(sctx);
                        free_store(store);
                    }
                    return 0;
                }
                // SAFETY: `sctx` is this call's own live context.
                unsafe { OSSL_STORE_close(sctx) };

                if stores.is_null() {
                    stores = OPENSSL_sk_new_null();
                    if !stores.is_null() {
                        // SAFETY: `ctx` is live and `stores` is this lookup's new stack.
                        unsafe { X509_LOOKUP_set_method_data(ctx, stores.cast::<c_void>()) };
                    }
                }
                // SAFETY: `stores` is NULL or this lookup's own stack; `store` is the element.
                if stores.is_null() {
                    // SAFETY: `store` was not installed, so this call still owns it.
                    unsafe { free_store(store) };
                    return 0;
                }
                // SAFETY: `stores` is this lookup's own stack; `store` is the element to push.
                if unsafe { OPENSSL_sk_push(stores, store.cast::<c_void>()) } <= 0 {
                    // SAFETY: `store` was not installed, so this call still owns it.
                    unsafe { free_store(store) };
                    return 0;
                }
                return 1;
            }
            // NOP if no URI is given.
            1
        }
        X509_L_LOAD_STORE => {
            // This is a shortcut for quick loading of specific containers.
            let store = CachedStore {
                uri: argp.cast_mut(),
                libctx,
                propq: propq.cast_mut(),
            };
            // SAFETY: `store` is a live local for the call; `ctx` is live per the contract.
            unsafe { cache_objects(ctx, (&raw const store).cast_mut(), ptr::null(), 0) }
        }
        // Unsupported command.
        _ => 0,
    }
}

/// `static int by_store_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **retp)` —
/// `crypto/x509/by_store.c:189-193`.
///
/// [`by_store_ctrl_ex`] with a NULL library context and property query.
///
/// # Safety
///
/// As [`by_store_ctrl_ex`], without `libctx`/`propq`.
unsafe extern "C" fn by_store_ctrl(
    ctx: *mut X509Lookup,
    cmd: c_int,
    argp: *const c_char,
    argl: c_long,
    retp: *mut *mut c_char,
) -> c_int {
    // SAFETY: the contract is `by_store_ctrl_ex`'s with NULL libctx/propq.
    unsafe { by_store_ctrl_ex(ctx, cmd, argp, argl, retp, ptr::null_mut(), ptr::null()) }
}

/// `static int by_store(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const OSSL_STORE_SEARCH
/// *criterion, X509_OBJECT *ret)` — `crypto/x509/by_store.c:195-210`.
///
/// Tries each recorded store in turn with the criterion, stopping at the first that answers 1.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`; `criterion` NULL or a live search; `_ret` is unused by the
/// authority's own body (only `by_store_subject` reaches the loaded objects from the cache).
unsafe fn by_store(
    ctx: *mut X509Lookup,
    _type: X509_LOOKUP_TYPE,
    criterion: *const OsslStoreSearch,
    _ret: *mut X509Object,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let stores = unsafe { X509_LOOKUP_get_method_data(ctx) }.cast::<OpenSslStack>();
    let mut ok = 0;

    // SAFETY: `stores` is NULL or this lookup's own stack; `OPENSSL_sk_num` accepts NULL.
    for i in 0..unsafe { OPENSSL_sk_num(stores) } {
        // SAFETY: `stores` is live and `i` is in range.
        let store = unsafe { OPENSSL_sk_value(stores, i) }.cast::<CachedStore>();
        // SAFETY: `store` is a live record; `ret` is writable per the contract.
        ok = unsafe {
            cache_objects(ctx, store, criterion, 1 /* depth */)
        };

        if ok != 0 {
            break;
        }
    }
    ok
}

/// `static int by_store_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const X509_NAME *name,
/// X509_OBJECT *ret)` — `crypto/x509/by_store.c:212-267`.
///
/// The method's `get_by_subject` hook: loads the objects matching `name` through an
/// `OSSL_STORE_SEARCH_by_name` criterion, then pulls the match back out of the cache. The object
/// `set1_` incremented a reference that the caller's `X509_STORE_CTX_get_by_subject` will increment
/// again, so the cache's own reference is dropped here to keep the count exact.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`; `name` live; `ret` writable. The lookup's store must be live.
unsafe extern "C" fn by_store_subject(
    ctx: *mut X509Lookup,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
    ret: *mut X509Object,
) -> c_int {
    // SAFETY: `name` is live per the contract; the search borrows it for the call.
    let criterion = unsafe { OSSL_STORE_SEARCH_by_name(name.cast_mut().cast::<c_void>()) };
    // SAFETY: `criterion` is a live search; `ret` is writable per the contract.
    let mut ok = unsafe { by_store(ctx, type_, criterion, ret) };
    // SAFETY: `ctx` is live per the contract.
    let store_objects = unsafe { X509_STORE_get0_objects(X509_LOOKUP_get_store(ctx)) };
    let mut tmp: *mut X509Object = ptr::null_mut();

    // SAFETY: `criterion` is this call's own search.
    unsafe { OSSL_STORE_SEARCH_free(criterion) };

    if ok != 0 {
        // SAFETY: `ctx` is live per the contract.
        let store = unsafe { X509_LOOKUP_get_store(ctx) };

        // SAFETY: `store` is the lookup's own live store.
        if unsafe { ossl_x509_store_read_lock(store) } == 0 {
            return 0;
        }
        // SAFETY: `store_objects` is the store's own live cache; `name` is live.
        tmp = unsafe { X509_OBJECT_retrieve_by_subject(store_objects, type_, name) };
        // SAFETY: `store` is the store locked above.
        unsafe { X509_STORE_unlock(store) };
    }

    ok = 0;
    if !tmp.is_null() {
        match type_ {
            X509_LU_X509 => {
                // SAFETY: `ret` is writable and `tmp` names a live `X509`, as its tag says.
                ok = unsafe { X509_OBJECT_set1_X509(ret, (*tmp).data.x509) };
                if ok != 0 {
                    // SAFETY: `tmp`'s object carries the reference this call drops, as in the
                    // authority's own comment: the caller up-refs on return.
                    unsafe { X509_free((*tmp).data.x509) };
                }
            }
            X509_LU_CRL => {
                // SAFETY: `ret` is writable and `tmp` names a live `X509_CRL`, as its tag says.
                ok = unsafe { X509_OBJECT_set1_X509_CRL(ret, (*tmp).data.crl) };
                if ok != 0 {
                    // SAFETY: as the `X509_LU_X509` arm.
                    unsafe { X509_CRL_free((*tmp).data.crl) };
                }
            }
            X509_LU_NONE => {}
            _ => {}
        }
    }
    ok
}

// ---------------------------------------------------------------------------------------------
// The method table and its constructor — `crypto/x509/by_store.c:269-293`
// ---------------------------------------------------------------------------------------------

// We lack the implementations for `get_by_issuer_serial`, `get_by_fingerprint` and
// `get_by_alias`. There's simply not enough support in the `X509_LOOKUP` or `X509_STORE` APIs.

/// A `Sync` newtype over the method row, so it can be a `static`.
///
/// A `static` of raw pointers is not `Sync` (the same reason [`crate::x509::v3_lib`]'s method rows
/// claim it), so the table is wrapped.
#[repr(transparent)]
struct StoreLookupMethod(X509LookupMethod);

// SAFETY: the row is fully initialised at compile time and never written. Its pointer fields borrow
// the crate's own `static` string, function addresses and NULL; the authority's `x509_store_lookup`
// is exactly this -- an immutable table of immutable fields.
unsafe impl Sync for StoreLookupMethod {}

/// `static X509_LOOKUP_METHOD x509_store_lookup` — `crypto/x509/by_store.c:275-288`.
///
/// The method row [`X509_LOOKUP_store`] hands out. Its `new_item`, `init`, `shutdown`,
/// `get_by_issuer_serial`, `get_by_fingerprint`, `get_by_alias` and `get_by_subject_ex` slots are
/// NULL; `free`, `ctrl`, `get_by_subject` and `ctrl_ex` are this unit's callbacks.
static X509_STORE_LOOKUP: StoreLookupMethod = StoreLookupMethod(X509LookupMethod {
    name: c"Load certs from STORE URIs".as_ptr().cast_mut(),
    new_item: None,
    free: Some(by_store_free),
    init: None,
    shutdown: None,
    ctrl: Some(by_store_ctrl),
    get_by_subject: Some(by_store_subject),
    get_by_issuer_serial: None,
    get_by_fingerprint: None,
    get_by_alias: None,
    get_by_subject_ex: None,
    ctrl_ex: Some(by_store_ctrl_ex),
});

/// `X509_LOOKUP_METHOD *X509_LOOKUP_store(void)` — `crypto/x509/by_store.c:290-293`.
///
/// The STORE-URI lookup method. The answer is a `'static` row the caller must not free.
///
/// # Safety
///
/// The answer is a module-owned `static`; no argument is read.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_store() -> *mut X509LookupMethod {
    (&raw const X509_STORE_LOOKUP.0).cast_mut()
}
