//! Phase 7.1 — `crypto/property/property.c`'s remainder: the `OSSL_METHOD_STORE` itself.
//!
//! This is the file 6.7c named and Phase 6 closed without (`docs/PHASE-6-SUBPHASES.md` row 6.7c),
//! which is why fifteen names in `forensics/prerequisites.json` were retargeted to this stratum
//! by D141 rather than staying attributed to a sealed one. `src/property/globals.rs` holds the
//! other end of the same translation unit — the *global properties* holder that 6.7a landed — and
//! the three accessors 6.7a left (`ossl_ctx_global_properties` and the two mirroring flags) live
//! beside it, in that file, because they are the same object.
//!
//! ## What a method store is
//!
//! A table of *implementations* keyed by an internal id, plus a cache of *queries* against it:
//!
//! ```text
//! OSSL_METHOD_STORE
//!   algs   -> sparse array, indexed by nid
//!     ALGORITHM { nid, impls -> stack of IMPLEMENTATION, cache -> lhash of QUERY }
//!       IMPLEMENTATION { provider, properties, METHOD }
//!       QUERY          { provider, query text, METHOD }   -- a *result*, cached
//! METHOD { method, up_ref, free }
//! ```
//!
//! `METHOD` is why this file owns nothing of any algorithm: a method arrives as a `void *` with
//! its own reference-count and destructor callbacks, so the store holds implementations it cannot
//! interpret. The fetch path that *builds* them is `crypto/core_fetch.c`'s (7.1, transcribed in
//! `src/evp/method_store.rs`) and `crypto/evp/evp_fetch.c`'s (7.2), and the algorithms themselves
//! are Phases 8 to 13.
//!
//! ## The `nid` is not a `NID_*`, and the file says so twice on purpose
//!
//! The authority's own `ossl_method_store_add` doc comment carries the note — "The nid parameter
//! here is _not_ a nid in the sense of the NID_* macros. It is an internal unique identifier" —
//! and `evp_fetch.c`'s `evp_method_id` is what produces one, by packing a namemap number and an
//! operation id. A reader who assumes `NID_sha256` would conclude the sparse array is keyed by the
//! object database, and it is not: nothing in this crate's `OBJ_*` surface can reach this table.
//!
//! ## Two locks, and they are not the same lock
//!
//! `lock` protects `algs` against concurrent insertion and query; `biglock` **reserves the whole
//! store**, and it exists for the walk in `core_fetch.c` — `ossl_method_construct_reserve_store`
//! takes it around every map so that a fetch of a set of algorithms is consistent as a set. The
//! two are taken in that order and never the other way, and this file never takes `biglock`
//! itself: the only callers of `ossl_method_lock_store` are the four method-store *clients*
//! (`evp_fetch.c`, `decoder_meth.c`, `encoder_meth.c`, `store_meth.c`), each of which hands it to
//! `core_fetch.c` as its `mcm->lock_store`. That is why it lives here and not with them: three of
//! those four are Phases 10's, and the object is shared.
//!
//! ## What is not here yet
//!
//! The **query path**: `ossl_method_store_fetch` and the cache's `_cache_get`, `_cache_set` and
//! `_cache_flush_all`'s stochastic half, plus `ossl_method_store_do_all` and its three helpers.
//! They land next, with `RT-FETCH`, which is the observation that makes any of it evidence rather
//! than a transcription. What is here is the object and its lifetime, which is what the query path
//! is written *against*.
//!
//! SPDX-License-Identifier: Apache-2.0

// D143 lands the query path, so `_fetch`, `_cache_get`, `_cache_set` and `_do_all` are complete and
// the *store* is whole. What still has no caller in this crate is the store's surface as seen from
// outside it: `_add`, `_remove`, `_remove_all_provided`, `_fetch`, the cache pair and `_do_all` are
// called by `evp_fetch.c`'s methods, and `_lock_store`/`_unlock_store` by its `mcm` — which is 7.2.
// The module carries one allowance rather than nine per-item ones whose comments would each
// restate this paragraph, and what retires it is 7.2.
#![allow(dead_code)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::property::defn_cache::{ossl_prop_defn_get, ossl_prop_defn_set};
use crate::property::list::OsslPropertyList;
use crate::property::parse::{ossl_parse_property, ossl_property_free};
use crate::property::parse::{ossl_parse_query, ossl_property_match_count, ossl_property_merge};
use crate::property::query::ossl_property_has_optional;
use crate::provider::OsslProvider;
use crate::runtime::lhash::{
    OPENSSL_LH_delete, OPENSSL_LH_doall, OPENSSL_LH_doall_arg, OPENSSL_LH_error, OPENSSL_LH_flush,
    OPENSSL_LH_free, OPENSSL_LH_get_down_load, OPENSSL_LH_insert, OPENSSL_LH_new,
    OPENSSL_LH_num_items, OPENSSL_LH_retrieve, OPENSSL_LH_set_down_load, OPENSSL_LH_strhash,
    OpenSslLhash,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_zalloc};
use crate::runtime::rdtsc::OPENSSL_rdtsc;
use crate::runtime::sparse_array::{
    ossl_sa_doall, ossl_sa_doall_arg, ossl_sa_free, ossl_sa_get, ossl_sa_new, ossl_sa_num,
    ossl_sa_set, OpenSslSa, OsslUintMax,
};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_dup, OPENSSL_sk_free, OPENSSL_sk_new_null,
    OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/property/property.c".as_ptr();

/// `ossl_method_store_new`'s `OPENSSL_zalloc(sizeof(*res))` (line 247).
const LINE_ZALLOC_STORE: c_int = 247;
/// `ossl_method_store_add`'s `OPENSSL_malloc(sizeof(*impl))` (line 337).
const LINE_MALLOC_IMPL: c_int = 337;
/// `ossl_method_store_add`'s `OPENSSL_zalloc(sizeof(*alg))` (line 390).
const LINE_ZALLOC_ALG: c_int = 390;
/// `alg_cleanup`'s `OPENSSL_free(a)` (line 233).
const LINE_FREE_ALG: c_int = 233;
/// `impl_free`'s `OPENSSL_free(impl)` (line 207).
const LINE_FREE_IMPL: c_int = 207;
/// `impl_cache_free`'s `OPENSSL_free(elem)` (line 215).
const LINE_FREE_QUERY: c_int = 215;
/// `ossl_method_store_free`'s `OPENSSL_free(store)` (line 268).
const LINE_FREE_STORE: c_int = 268;
/// `ossl_method_store_cache_set`'s `OPENSSL_malloc` for the cache entry (line 922).
const LINE_MALLOC_QUERY: c_int = 922;
/// `alg_copy`'s `OPENSSL_memdup(alg, sizeof(ALGORITHM))` (line 563).
const LINE_MEMDUP_ALG: c_int = 563;

/// `int (*up_ref)(void *)` and `void (*free)(void *)` — the reference count and the destructor a
/// method carries, so the store can hold one without knowing what it is.
pub(crate) type MethodUpRefFn = unsafe extern "C" fn(*mut c_void) -> c_int;
/// `void (*free)(void *)`.
pub(crate) type MethodFreeFn = unsafe extern "C" fn(*mut c_void);

/// `typedef struct { void *method; int (*up_ref)(void *); void (*free)(void *); } METHOD`.
///
/// The authority's three fields, in its order. Neither function pointer is checked for NULL before
/// it is called, on either side: a caller that hands over a method without a destructor has
/// already broken the contract.
#[repr(C)]
pub(crate) struct Method {
    /// `void *method` — the object the store holds, opaque here.
    pub(crate) method: *mut c_void,
    /// `int (*up_ref)(void *)`.
    pub(crate) up_ref: MethodUpRefFn,
    /// `void (*free)(void *)`.
    pub(crate) free: MethodFreeFn,
}

/// `typedef struct { const OSSL_PROVIDER *provider; OSSL_PROPERTY_LIST *properties;
/// METHOD method; } IMPLEMENTATION`.
///
/// `properties` is the provider's *declared* properties — `provider=default`, `fips=yes` — parsed
/// into a list and kept for the query match, which is why the list is reached through
/// `ossl_prop_defn_set`'s per-context cache: the same text is parsed once per context however many
/// implementations declare it.
#[repr(C)]
pub(crate) struct Implementation {
    /// `const OSSL_PROVIDER *provider` — compared by identity, never dereferenced.
    pub(crate) provider: *const OsslProvider,
    /// `OSSL_PROPERTY_LIST *properties` — owned through the context's definition cache, so the
    /// same list may be pointed at by two implementations. It is released by the cache, not here.
    pub(crate) properties: *mut OsslPropertyList,
    /// `METHOD method`.
    pub(crate) method: Method,
}

/// `typedef struct { const OSSL_PROVIDER *provider; const char *query; METHOD method;
/// char body[1]; } QUERY`.
///
/// A cached **result**, not a cached implementation: the query text and the provider that answered
/// it, so a repeat of the same fetch returns the same method without walking the implementations
/// again. `body` is the flexible array member the query string is copied into, which is why
/// `query` points inside the same allocation and why freeing one is a single `OPENSSL_free`.
///
/// `#[repr(C)]` with a one-element array rather than a Rust slice: the allocation is sized by hand
/// in `ossl_method_store_cache_set` and the field is never indexed.
#[repr(C)]
pub(crate) struct Query {
    /// `const OSSL_PROVIDER *provider` — the provider that answered.
    pub(crate) provider: *const OsslProvider,
    /// `const char *query` — the query text, inside `body`.
    pub(crate) query: *const c_char,
    /// `METHOD method` — the cached result, holding its own reference.
    pub(crate) method: Method,
    /// `char body[1]` — the allocation's tail; the query string is copied here.
    pub(crate) body: [c_char; 1],
}

/// `typedef struct { int nid; STACK_OF(IMPLEMENTATION) *impls; LHASH_OF(QUERY) *cache; }
/// ALGORITHM`.
///
/// One entry per id that has ever been added. `impls` is the implementations; `cache` is the
/// query results *against* them, and it is flushed whenever an implementation is added or removed,
/// because a cached answer that predates a new implementation would starve it (the authority's own
/// comment at `ossl_method_store_add` says exactly that).
#[repr(C)]
pub(crate) struct Algorithm {
    /// `int nid` — the store's internal id, not a `NID_*`.
    pub(crate) nid: c_int,
    /// `STACK_OF(IMPLEMENTATION) *impls`.
    pub(crate) impls: *mut OpenSslStack,
    /// `LHASH_OF(QUERY) *cache`.
    pub(crate) cache: *mut OpenSslLhash,
}

/// `struct ossl_method_store_st` — `OSSL_METHOD_STORE`.
///
/// Public because it appears in this file's exported-signature functions and Rust requires the
/// type of an exported item's parameter to be at least as visible; the *fields* are `pub(crate)`
/// because the object is opaque everywhere outside this module, which is what
/// `include/internal/core.h`'s forward declaration means.
#[repr(C)]
pub struct OsslMethodStore {
    /// `OSSL_LIB_CTX *ctx` — the context whose property grammar and definition cache the
    /// implementations in this store are parsed and matched against.
    pub(crate) ctx: *mut c_void,
    /// `SPARSE_ARRAY_OF(ALGORITHM) *algs` — indexed by nid.
    pub(crate) algs: *mut OpenSslSa,
    /// `CRYPTO_RWLOCK *lock` — protects `algs`.
    pub(crate) lock: *mut CryptoRwlock,
    /// `CRYPTO_RWLOCK *biglock` — reserves the whole store for `core_fetch.c`'s walk.
    pub(crate) biglock: *mut CryptoRwlock,
    /// `size_t cache_nelem` — the query cache's total entry count, across every algorithm.
    pub(crate) cache_nelem: usize,
    /// `int cache_need_flush` — set when the count crosses the threshold.
    pub(crate) cache_need_flush: c_int,
}

/// `static int ossl_method_up_ref(METHOD *method)`.
///
/// # Safety
/// `method` must be a live `Method` whose `up_ref` is valid.
pub(crate) unsafe fn ossl_method_up_ref(method: *mut Method) -> c_int {
    // SAFETY: `method` is live per the contract, so both fields are the caller's.
    unsafe { ((*method).up_ref)((*method).method) }
}

/// `static void ossl_method_free(METHOD *method)`.
///
/// # Safety
/// `method` must be a live `Method` whose `free` is valid, and this must be the last reference.
pub(crate) unsafe fn ossl_method_free(method: *mut Method) {
    // SAFETY: `method` is live per the contract.
    unsafe { ((*method).free)((*method).method) };
}

/// `static __owur int ossl_property_read_lock(OSSL_METHOD_STORE *p)`.
///
/// A **NULL store is a refusal, not a crash** — `p != NULL ? ... : 0` — which is the shape that
/// makes the four delegating callers safe to call it with a slot that is not filled.
///
/// # Safety
/// `p` must be NULL or a live store.
unsafe fn ossl_property_read_lock(p: *mut OsslMethodStore) -> c_int {
    if p.is_null() {
        return 0;
    }
    // SAFETY: `p` is live, so `lock` is this object's own.
    unsafe { CRYPTO_THREAD_read_lock((*p).lock) }
}

/// `static __owur int ossl_property_write_lock(OSSL_METHOD_STORE *p)`.
///
/// # Safety
/// `p` must be NULL or a live store.
unsafe fn ossl_property_write_lock(p: *mut OsslMethodStore) -> c_int {
    if p.is_null() {
        return 0;
    }
    // SAFETY: `p` is live, so `lock` is this object's own.
    unsafe { CRYPTO_THREAD_write_lock((*p).lock) }
}

/// `static int ossl_property_unlock(OSSL_METHOD_STORE *p)`.
///
/// The authority spells the test `p != 0`, which is the same test as `p != NULL` for a pointer; it
/// is transcribed as a null test because that is what it means. The locked field is `lock` and
/// **not** `biglock`, which is the one thing about this trio that a reader could get wrong.
///
/// # Safety
/// `p` must be NULL or a live store whose `lock` this thread holds.
unsafe fn ossl_property_unlock(p: *mut OsslMethodStore) -> c_int {
    if p.is_null() {
        return 0;
    }
    // SAFETY: `p` is live, so `lock` is this object's own.
    unsafe { CRYPTO_THREAD_unlock((*p).lock) }
}

/// `static unsigned long query_hash(const QUERY *a)` — the query text's string hash.
///
/// # Safety
/// `a` must be a live `Query` whose `query` is NUL-terminated.
unsafe extern "C" fn query_hash(a: *const c_void) -> core::ffi::c_ulong {
    // SAFETY: the lhash only ever hands this function a `Query` this module built.
    let query = unsafe { (*a.cast::<Query>()).query };
    // SAFETY: `query` points into a `body` this module filled with a NUL-terminated copy.
    unsafe { OPENSSL_LH_strhash(query) }
}

/// `static int query_cmp(const QUERY *a, const QUERY *b)`.
///
/// The text first, and the provider **only if the texts are equal and both providers are set**.
/// The provider comparison is by address and it is *reversed* — `b->provider > a->provider` — which
/// makes the ordering the caller's input order rather than an accident of allocation: two queries
/// that differ only in provider must compare deterministically, and comparing `a` against `b` would
/// leave the hash table's bucket order dependent on which was inserted first.
///
/// # Safety
/// Both arguments must be live `Query` objects, or a key built by a caller whose `query` is valid.
unsafe extern "C" fn query_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: both arguments are live per the contract.
    let (x, y, xp, yp) = unsafe {
        let x = a.cast::<Query>();
        let y = b.cast::<Query>();
        ((*x).query, (*y).query, (*x).provider, (*y).provider)
    };
    // SAFETY: `x` and `y` are NUL-terminated per the contract. The call is wrapped because this is
    // an `unsafe fn` whose body would otherwise be an `unsafe_op_in_unsafe_fn` site; a *safe*
    // helper would need no block (D113), but `strcmp` is a C call and stays unsafe.
    let res = unsafe { c_strcmp(x, y) };
    if res == 0 && !xp.is_null() && !yp.is_null() {
        let (xpa, ypa) = (xp as usize, yp as usize);
        return if ypa > xpa {
            1
        } else if ypa < xpa {
            -1
        } else {
            0
        };
    }
    res
}

/// `strcmp`, behind a safe name.
///
/// # Safety
/// Both pointers must be NUL-terminated.
unsafe fn c_strcmp(a: *const c_char, b: *const c_char) -> c_int {
    extern "C" {
        fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    }
    // SAFETY: the caller's contract.
    unsafe { strcmp(a, b) }
}

/// `static void impl_free(IMPLEMENTATION *impl)`.
///
/// The method's reference is dropped **before** the block, in the authority's order, and a NULL
/// argument is a no-op.
///
/// # Safety
/// `implementation` must be NULL or a live `Implementation` this module allocated and not already
/// released.
unsafe fn impl_free(implementation: *mut Implementation) {
    if implementation.is_null() {
        return;
    }
    // SAFETY: `implementation` is live per the contract, so `method` is a field of this module's
    // own object.
    unsafe {
        ossl_method_free(ptr::addr_of_mut!((*implementation).method));
        CRYPTO_free(implementation.cast::<c_void>(), FILE, LINE_FREE_IMPL);
    }
}

/// `static void impl_cache_free(QUERY *elem)`.
///
/// The same shape for a cached query result.
///
/// # Safety
/// `elem` must be NULL or a live `Query` this module allocated and not already released.
unsafe fn impl_cache_free(elem: *mut Query) {
    if elem.is_null() {
        return;
    }
    // SAFETY: `elem` is live per the contract.
    unsafe {
        ossl_method_free(ptr::addr_of_mut!((*elem).method));
        CRYPTO_free(elem.cast::<c_void>(), FILE, LINE_FREE_QUERY);
    }
}

/// The `doall` thunk for `impl_cache_free`, which takes one argument.
///
/// # Safety
/// `elem` must be a live `Query` in the table being walked.
unsafe extern "C" fn impl_cache_free_thunk(elem: *mut c_void) {
    // SAFETY: the lhash only hands this function its own elements.
    unsafe { impl_cache_free(elem.cast::<Query>()) };
}

/// `static void impl_cache_flush_alg(ossl_uintmax_t idx, ALGORITHM *alg)`.
///
/// Every cached result for one algorithm, freed and then the table itself flushed. The two steps
/// are not redundant: `doall` frees the *elements*, `flush` resets the table's buckets to NULL.
/// Skipping the flush would leave the table holding pointers to freed blocks.
///
/// `idx` is accepted and unused, as in the authority, because this is also the `doall` leaf.
///
/// # Safety
/// `alg` must be NULL or a live `Algorithm` whose `cache` is a table this module built.
unsafe fn impl_cache_flush_alg(_idx: OsslUintMax, alg: *mut c_void) {
    if alg.is_null() {
        return;
    }
    // SAFETY: `alg` is live per the contract.
    let cache = unsafe { (*alg.cast::<Algorithm>()).cache };
    // SAFETY: `cache` is a table this module built, so every element is a `Query` it allocated.
    unsafe {
        OPENSSL_LH_doall(cache, Some(impl_cache_free_thunk));
        OPENSSL_LH_flush(cache);
    }
}

/// `static void alg_cleanup(ossl_uintmax_t idx, ALGORITHM *a, void *arg)`.
///
/// Four releases in the authority's order — the implementations, the cached queries, the cache
/// table, the block — and then the slot itself is cleared, **with the store's table rather than
/// with a local copy of the pointer**: a caller that passed NULL for `store` (`add`'s error path)
/// gets the releases without the clear, which is correct because the entry was never inserted.
///
/// # Safety
/// `a` must be NULL or a live `Algorithm`; `arg` must be NULL or a live `OsslMethodStore`.
unsafe fn alg_cleanup(_idx: OsslUintMax, a: *mut c_void, arg: *mut c_void) {
    let store = arg.cast::<OsslMethodStore>();
    let alg = a.cast::<Algorithm>();
    if !alg.is_null() {
        // SAFETY: `alg` is live per the contract, so `impls` and `cache` are this module's own.
        unsafe {
            OPENSSL_sk_pop_free((*alg).impls, Some(impl_free_thunk));
            OPENSSL_LH_doall((*alg).cache, Some(impl_cache_free_thunk));
            OPENSSL_LH_free((*alg).cache);
            CRYPTO_free(alg.cast::<c_void>(), FILE, LINE_FREE_ALG);
        }
    }
    if !store.is_null() {
        // SAFETY: `store` is live per the contract and `idx` is the slot this entry came from.
        unsafe { ossl_sa_set((*store).algs, _idx, ptr::null_mut()) };
    }
}

/// The `pop_free` thunk for `impl_free`, which takes one argument.
///
/// # Safety
/// `implementation` must be a live `Implementation` in the stack being released.
unsafe extern "C" fn impl_free_thunk(implementation: *mut c_void) {
    // SAFETY: the stack only hands this function its own elements.
    unsafe { impl_free(implementation.cast::<Implementation>()) };
}

/// `OSSL_METHOD_STORE *ossl_method_store_new(OSSL_LIB_CTX *ctx)`.
///
/// A zeroed block, the sparse array, and the two locks — and the dependency order is why the
/// failure path calls the **releaser** rather than unwinding by hand: `ossl_method_store_free`
/// accepts a partially built store, and `CRYPTO_THREAD_lock_free` and `ossl_sa_free` both accept
/// NULL, so a store that failed at the first allocation is released correctly by the same code
/// that releases a complete one.
///
/// # Safety
/// `ctx` must be NULL or a live `OSSL_LIB_CTX`.
pub(crate) unsafe fn ossl_method_store_new(ctx: *mut c_void) -> *mut OsslMethodStore {
    // SAFETY: `ctx` is stored, not read.
    let res = CRYPTO_zalloc(
        core::mem::size_of::<OsslMethodStore>(),
        FILE,
        LINE_ZALLOC_STORE,
    )
    .cast::<OsslMethodStore>();
    if res.is_null() {
        return res;
    }
    // SAFETY: `res` is a fresh zeroed block this call owns.
    unsafe {
        (*res).ctx = ctx;
        (*res).algs = ossl_sa_new();
        (*res).lock = CRYPTO_THREAD_lock_new();
        (*res).biglock = CRYPTO_THREAD_lock_new();
        if (*res).algs.is_null() || (*res).lock.is_null() || (*res).biglock.is_null() {
            ossl_method_store_free(res);
            return ptr::null_mut();
        }
    }
    res
}

/// `void ossl_method_store_free(OSSL_METHOD_STORE *store)`.
///
/// The array's entries are cleaned **through the array**, so each slot is cleared as its entry is
/// released; then the containers, then the locks, then the block. NULL is a no-op at every step,
/// which is what makes this usable as `_new`'s failure path.
///
/// # Safety
/// `store` must be NULL or a store returned by [`ossl_method_store_new`] and not already released.
pub(crate) unsafe fn ossl_method_store_free(store: *mut OsslMethodStore) {
    if store.is_null() {
        return;
    }
    // SAFETY: `store` is live per the contract; `algs` is NULL only on a failed construction, and
    // `ossl_sa_doall_arg` and `ossl_sa_free` both accept NULL.
    unsafe {
        if !(*store).algs.is_null() {
            ossl_sa_doall_arg((*store).algs, Some(alg_cleanup), store.cast::<c_void>());
        }
        ossl_sa_free((*store).algs);
        CRYPTO_THREAD_lock_free((*store).lock);
        CRYPTO_THREAD_lock_free((*store).biglock);
        CRYPTO_free(store.cast::<c_void>(), FILE, LINE_FREE_STORE);
    }
}

/// `int ossl_method_lock_store(OSSL_METHOD_STORE *store)` — the **reservation** lock, `biglock`.
///
/// A NULL store is a refusal, and that is what the four delegating callers rely on: their
/// `mcm->lock_store` is handed whatever slot they got, including none.
///
/// # Safety
/// `store` must be NULL or a live store.
pub(crate) unsafe fn ossl_method_lock_store(store: *mut OsslMethodStore) -> c_int {
    if store.is_null() {
        return 0;
    }
    // SAFETY: `store` is live, so `biglock` is this object's own.
    unsafe { CRYPTO_THREAD_write_lock((*store).biglock) }
}

/// `int ossl_method_unlock_store(OSSL_METHOD_STORE *store)` — release `biglock`.
///
/// # Safety
/// `store` must be NULL or a live store whose `biglock` this thread holds.
pub(crate) unsafe fn ossl_method_unlock_store(store: *mut OsslMethodStore) -> c_int {
    if store.is_null() {
        return 0;
    }
    // SAFETY: `store` is live, so `biglock` is this object's own.
    unsafe { CRYPTO_THREAD_unlock((*store).biglock) }
}

/// `static ALGORITHM *ossl_method_store_retrieve(OSSL_METHOD_STORE *store, int nid)`.
///
/// The sparse array's values are `void *`, so the cast is the only thing that makes the array
/// typed; there is no per-type array in this crate, unlike the authority's generated
/// `ossl_sa_ALGORITHM_*`.
///
/// # Safety
/// `store` must be a live store whose `algs` is live.
unsafe fn ossl_method_store_retrieve(store: *mut OsslMethodStore, nid: c_int) -> *mut Algorithm {
    // SAFETY: `store` is live per the contract.
    unsafe { ossl_sa_get((*store).algs, nid as OsslUintMax) }.cast::<Algorithm>()
}

/// `static int ossl_method_store_insert(OSSL_METHOD_STORE *store, ALGORITHM *alg)`.
///
/// # Safety
/// `store` must be a live store whose `algs` is live, and `alg` a live entry.
unsafe fn ossl_method_store_insert(store: *mut OsslMethodStore, alg: *mut Algorithm) -> c_int {
    // SAFETY: `store` and `alg` are live per the contract.
    unsafe {
        ossl_sa_set(
            (*store).algs,
            (*alg).nid as OsslUintMax,
            alg.cast::<c_void>(),
        )
    }
}

/// `static void ossl_method_cache_flush_alg(OSSL_METHOD_STORE *store, ALGORITHM *alg)`.
///
/// The count is decremented by the table's **own** count before the flush, not by a stored number:
/// the store's total is maintained incrementally, so subtracting the table's size at flush time is
/// what keeps it exact. The `impl_cache_flush_alg(0, alg)` call passes zero for the index because
/// that leaf does not use it — the authority's own comment for the index is that it is unused.
///
/// # Safety
/// `store` must be a live store and `alg` a live entry whose `cache` this module built.
unsafe fn ossl_method_cache_flush_alg(store: *mut OsslMethodStore, alg: *mut Algorithm) {
    // SAFETY: `alg` is live per the contract.
    let n = unsafe { OPENSSL_LH_num_items((*alg).cache) } as usize;
    // SAFETY: `store` is live per the contract.
    unsafe {
        (*store).cache_nelem -= n;
    }
    // SAFETY: `alg` is live.
    unsafe { impl_cache_flush_alg(0, alg.cast::<c_void>()) };
}

/// `static void ossl_method_cache_flush(OSSL_METHOD_STORE *store, int nid)`.
///
/// # Safety
/// `store` must be a live store.
unsafe fn ossl_method_cache_flush(store: *mut OsslMethodStore, nid: c_int) {
    // SAFETY: `store` is live per the contract.
    let alg = unsafe { ossl_method_store_retrieve(store, nid) };
    if !alg.is_null() {
        // SAFETY: `alg` is live and belongs to `store`.
        unsafe { ossl_method_cache_flush_alg(store, alg) };
    }
}

/// `int ossl_method_store_cache_flush_all(OSSL_METHOD_STORE *store)`.
///
/// Every algorithm's cached results, and the total set to zero rather than decremented: the whole
/// table is flushed, so the running count is replaced by its known value instead of being adjusted
/// entry by entry.
///
/// # Safety
/// `store` must be a live store.
pub(crate) unsafe fn ossl_method_store_cache_flush_all(store: *mut OsslMethodStore) -> c_int {
    // SAFETY: `store` is live per the contract; a NULL store is refused by the lock helper.
    unsafe {
        if ossl_property_write_lock(store) == 0 {
            return 0;
        }
        ossl_sa_doall((*store).algs, Some(impl_cache_flush_alg));
        (*store).cache_nelem = 0;
        ossl_property_unlock(store);
    }
    1
}

/// `int ossl_method_store_add(OSSL_METHOD_STORE *store, const OSSL_PROVIDER *prov, int nid,
/// const char *properties, void *method, int (*method_up_ref)(void *),
/// void (*method_destruct)(void *))`.
///
/// Three things are worth naming before the code:
///
///   * **the cache is flushed for this id before the new implementation is stored**, and the
///     authority's comment says why: a cached answer that predates the new method would keep
///     selecting the old one, because the query path trusts the cache. This is not an
///     optimisation — it is what makes re-adding a method observable.
///   * **the properties are parsed once per context, not once per implementation.** `defn_get`
///     first, `parse` and `defn_set` second, so two providers publishing the same property string
///     share one `OSSL_PROPERTY_LIST`, which is then *not* freed by `add`'s error path if the list
///     is already cached — hence the explicit `ossl_property_free` only on the freshly parsed one.
///   * **a duplicate implementation is not an error**, it is a no-op: the scan looks for an entry
///     with the same provider and the same property list, and `ret` stays 0. The authority's return
///     is 0 there, which a caller reads as "not added".
///
/// # Safety
/// `store` must be NULL or a live store; `prov` live; `properties` NULL or NUL-terminated; `method`
/// NULL or the method to hand over, valid for the two callbacks.
pub(crate) unsafe fn ossl_method_store_add(
    store: *mut OsslMethodStore,
    prov: *const OsslProvider,
    nid: c_int,
    properties: *const c_char,
    method: *mut c_void,
    method_up_ref: MethodUpRefFn,
    method_destruct: MethodFreeFn,
) -> c_int {
    if nid <= 0 || method.is_null() || store.is_null() {
        return 0;
    }
    // The authority's `properties == NULL` default is the **empty string**, not "no properties":
    // it is the text the definition cache is keyed by, and a NULL key has no hash.
    let properties = if properties.is_null() {
        c"".as_ptr()
    } else {
        properties
    };

    // `ossl_assert(prov != NULL)` under `NDEBUG` is `(x) != 0`, so this is a refusal and not an
    // abort. The provider is compared by identity everywhere below and never dereferenced.
    if prov.is_null() {
        return 0;
    }

    // SAFETY: `Implementation` is this module's own `#[repr(C)]` type.
    let impl_ = CRYPTO_zalloc(
        core::mem::size_of::<Implementation>(),
        FILE,
        LINE_MALLOC_IMPL,
    )
    .cast::<Implementation>();
    if impl_.is_null() {
        return 0;
    }
    // SAFETY: `impl_` is a fresh block this call owns.
    unsafe {
        (*impl_).method.method = method;
        (*impl_).method.up_ref = method_up_ref;
        (*impl_).method.free = method_destruct;
        // SAFETY: `impl_` is live, so the `Method` field is this module's own.
        if ossl_method_up_ref(ptr::addr_of_mut!((*impl_).method)) == 0 {
            CRYPTO_free(impl_.cast::<c_void>(), FILE, LINE_MALLOC_IMPL);
            return 0;
        }
        (*impl_).provider = prov;
    }

    // Everything from here to the two exits below runs under the store's write lock.
    // SAFETY: `store` is live per the contract.
    unsafe {
        if ossl_property_write_lock(store) == 0 {
            impl_free(impl_);
            return 0;
        }
        ossl_method_cache_flush(store, nid);
    }

    // SAFETY: `store` is live and `properties` is NUL-terminated, so the definition cache's
    // contract is this function's.
    unsafe {
        (*impl_).properties = ossl_prop_defn_get((*store).ctx, properties);
        if (*impl_).properties.is_null() {
            (*impl_).properties = ossl_parse_property((*store).ctx, properties);
            if (*impl_).properties.is_null() {
                ossl_property_unlock(store);
                alg_cleanup(0, ptr::null_mut(), ptr::null_mut());
                impl_free(impl_);
                return 0;
            }
            // `&impl->properties` is a pointer to the *field*, so a cache insertion that fails
            // leaves the field NULL after the local free -- the authority's own shape, and the
            // reason the free and the clear are both written.
            if ossl_prop_defn_set(
                (*store).ctx,
                properties,
                ptr::addr_of_mut!((*impl_).properties),
            ) == 0
            {
                ossl_property_free((*impl_).properties);
                (*impl_).properties = ptr::null_mut();
                ossl_property_unlock(store);
                alg_cleanup(0, ptr::null_mut(), ptr::null_mut());
                impl_free(impl_);
                return 0;
            }
        }
    }

    // SAFETY: `store` is live, so `algs` is this object's own array.
    let mut alg = unsafe { ossl_method_store_retrieve(store, nid) };
    if alg.is_null() {
        // `CRYPTO_zalloc` is a SAFE function in this crate (D113), so the allocation needs no
        // block even though this function is `unsafe`.
        alg = CRYPTO_zalloc(core::mem::size_of::<Algorithm>(), FILE, LINE_ZALLOC_ALG)
            .cast::<Algorithm>();
        if alg.is_null() {
            // SAFETY: `store` is locked by this thread.
            unsafe {
                ossl_property_unlock(store);
                alg_cleanup(0, ptr::null_mut(), ptr::null_mut());
                impl_free(impl_);
            }
            return 0;
        }
        // SAFETY: `alg` is a fresh block this call owns.
        unsafe {
            (*alg).impls = OPENSSL_sk_new_null();
            (*alg).cache = OPENSSL_LH_new(Some(query_hash), Some(query_cmp));
            (*alg).nid = nid;
            if (*alg).impls.is_null()
                || (*alg).cache.is_null()
                || ossl_method_store_insert(store, alg) == 0
            {
                ossl_property_unlock(store);
                alg_cleanup(0, ptr::null_mut(), ptr::null_mut());
                impl_free(impl_);
                return 0;
            }
        }
    }

    // The duplicate scan: same provider **and** same property list, which is pointer identity on a
    // list the definition cache hands out, so two identical property strings are one list.
    let mut i: c_int = 0;
    // SAFETY: `alg` is live and belongs to the store.
    unsafe {
        while i < OPENSSL_sk_num((*alg).impls) {
            let tmpimpl = OPENSSL_sk_value((*alg).impls, i).cast::<Implementation>();
            if (*tmpimpl).provider == (*impl_).provider
                && (*tmpimpl).properties == (*impl_).properties
            {
                break;
            }
            i += 1;
        }
    }

    // SAFETY: `alg` is live and `impl_` is this call's own object, now owned by the stack if the
    // push succeeds.
    let ret = unsafe {
        if i == OPENSSL_sk_num((*alg).impls) && OPENSSL_sk_push((*alg).impls, impl_.cast()) != 0 {
            1
        } else {
            0
        }
    };
    // SAFETY: `store` is locked by this thread.
    unsafe { ossl_property_unlock(store) };
    if ret == 0 {
        // SAFETY: the push did not take ownership, so this call still owns `impl_`.
        unsafe { impl_free(impl_) };
    }
    ret
}

/// `int ossl_method_store_remove(OSSL_METHOD_STORE *store, int nid, const void *method)`.
///
/// A **linear scan and a delete**, and the authority's comment says why it is not a sorted find:
/// these stacks are small, and sorting would surprise callers whose result orderings would change
/// even though no ordering is promised. The comparison is against `impl->method.method` — the
/// method object itself — and not against the `IMPLEMENTATION` wrapper, which is what a caller has.
///
/// # Safety
/// `store` must be NULL or a live store; `method` NULL or a pointer that was added to it.
pub(crate) unsafe fn ossl_method_store_remove(
    store: *mut OsslMethodStore,
    nid: c_int,
    method: *const c_void,
) -> c_int {
    if nid <= 0 || method.is_null() || store.is_null() {
        return 0;
    }
    // SAFETY: `store` is live per the contract.
    unsafe {
        if ossl_property_write_lock(store) == 0 {
            return 0;
        }
        ossl_method_cache_flush(store, nid);
        let alg = ossl_method_store_retrieve(store, nid);
        if alg.is_null() {
            ossl_property_unlock(store);
            return 0;
        }

        let mut i: c_int = 0;
        while i < OPENSSL_sk_num((*alg).impls) {
            let impl_ = OPENSSL_sk_value((*alg).impls, i).cast::<Implementation>();
            if ptr::eq((*impl_).method.method as *const c_void, method) {
                impl_free(impl_);
                OPENSSL_sk_delete((*alg).impls, i);
                ossl_property_unlock(store);
                return 1;
            }
            i += 1;
        }
        ossl_property_unlock(store);
    }
    0
}

/// `struct alg_cleanup_by_provider_data_st { OSSL_METHOD_STORE *store;
/// const OSSL_PROVIDER *prov; }`.
#[repr(C)]
struct AlgCleanupByProviderData {
    /// `OSSL_METHOD_STORE *store` — the store whose cache is flushed if anything was removed.
    store: *mut OsslMethodStore,
    /// `const OSSL_PROVIDER *prov` — compared by identity.
    prov: *const OsslProvider,
}

/// `static void alg_cleanup_by_provider(ossl_uintmax_t idx, ALGORITHM *alg, void *arg)`.
///
/// The stack is walked **backwards** and that is load-bearing: the loop deletes as it goes, and
/// forward iteration would skip the element shifted into the hole left by each removal. The
/// authority's own comment says so.
///
/// The cache is flushed only if something was removed, also deliberately: flushing when nothing
/// changed would throw away good answers for every provider.
///
/// # Safety
/// `alg` must be a live entry of the array being walked and `arg` a live
/// `AlgCleanupByProviderData`.
unsafe fn alg_cleanup_by_provider(_idx: OsslUintMax, alg: *mut c_void, arg: *mut c_void) {
    let data = arg.cast::<AlgCleanupByProviderData>();
    let alg = alg.cast::<Algorithm>();
    if alg.is_null() {
        return;
    }
    let mut count: c_int = 0;
    // SAFETY: `data` is live per the contract and `alg` is a live entry, so both fields of each
    // element are this module's own.
    unsafe {
        let mut i = OPENSSL_sk_num((*alg).impls);
        while i > 0 {
            i -= 1;
            let impl_ = OPENSSL_sk_value((*alg).impls, i).cast::<Implementation>();
            if (*impl_).provider == (*data).prov {
                OPENSSL_sk_delete((*alg).impls, i);
                count += 1;
                impl_free(impl_);
            }
        }
    }
    if count > 0 {
        // SAFETY: `data->store` is the store the walk came from and `alg` belongs to it.
        unsafe { ossl_method_cache_flush_alg((*data).store, alg) };
    }
}

/// `int ossl_method_store_remove_all_provided(OSSL_METHOD_STORE *store,
/// const OSSL_PROVIDER *prov)`.
///
/// **A NULL store answers 0, not 1**, and the distinction is the lock's: the authority's first
/// statement is `if (!ossl_property_write_lock(store)) return 0;`, and a NULL store cannot take a
/// lock, so it is refused before the provider is looked at. The `remove_all_provided` family's
/// *absent-slot* answer of 1 that `src/provider/stores.rs` documents belongs to the *bridges*
/// (`evp_method_store_remove_all_provided` and its three siblings), which test the slot themselves
/// and never reach here with NULL — a difference the first version of this file's test got wrong.
///
/// # Safety
/// `store` must be NULL or a live store; `prov` live.
pub(crate) unsafe fn ossl_method_store_remove_all_provided(
    store: *mut OsslMethodStore,
    prov: *const OsslProvider,
) -> c_int {
    // SAFETY: `store` is NULL or live per the contract.
    unsafe {
        if ossl_property_write_lock(store) == 0 {
            return 0;
        }
        let mut data = AlgCleanupByProviderData { store, prov };
        let p: *mut c_void = ptr::addr_of_mut!(data).cast::<c_void>();
        ossl_sa_doall_arg((*store).algs, Some(alg_cleanup_by_provider), p);
        ossl_property_unlock(store);
    }
    1
}

/// `#define IMPL_CACHE_FLUSH_THRESHOLD 500`.
///
/// The number of cached query results the whole store may hold before a `_cache_set` asks for a
/// flush. The authority's own comment calls it a threshold rather than a bound and says why the
/// strategy on the other side of it is stochastic.
const IMPL_CACHE_FLUSH_THRESHOLD: usize = 500;

/// `typedef struct { LHASH_OF(QUERY) *cache; size_t nelem; uint32_t seed;
/// unsigned char using_global_seed; } IMPL_CACHE_FLUSH`.
///
/// The state one stochastic flush carries: the table currently being walked (rewritten per
/// algorithm), how many entries were *kept*, the xorshift's current word, and whether the seed came
/// from the counter or from the process-global fallback.
#[repr(C)]
struct ImplCacheFlush {
    /// `LHASH_OF(QUERY) *cache` — the table being flushed, not the store's.
    cache: *mut OpenSslLhash,
    /// `size_t nelem` — entries the walk kept.
    nelem: usize,
    /// `uint32_t seed` — the xorshift's state, advanced in place.
    seed: u32,
    /// `unsigned char using_global_seed` — 1 when the counter answered 0.
    using_global_seed: core::ffi::c_uchar,
}

/// `static TSAN_QUALIFIER uint32_t global_seed = 1;`.
///
/// The fallback seed, advanced only when the timestamp counter is unavailable — and then advanced
/// by *adding* the word just generated, so two flush cycles a moment apart do not draw the same
/// sequence. `TSAN_QUALIFIER` and the `tsan_load`/`tsan_add` pair the authority wraps it in are
/// thread-sanitizer annotations; the atomic is the part that matters, and an `AtomicU32` with
/// `Relaxed` ordering reproduces the annotation's guarantee (a plain load and a plain add) without
/// claiming stronger ordering than the authority has.
static GLOBAL_SEED: AtomicU32 = AtomicU32::new(1);

/// `static void impl_cache_flush_cache(QUERY *c, IMPL_CACHE_FLUSH *state)`.
///
/// The 32-bit xorshift from Marsaglia's *Xorshift RNGs*, which the authority cites by DOI, and then
/// one bit decides: **odd frees, even keeps**. The free is a `delete` from the table rather than a
/// `doall`-style release, and that is safe because the table's down-load was set to 0 by the caller
/// — every element is in a bucket of its own, so a delete cannot shift another element out from
/// under the walk.
///
/// # Safety
/// `c` must be a live element of `(*state).cache`, and `state` a live `ImplCacheFlush`.
unsafe extern "C" fn impl_cache_flush_cache(c: *mut c_void, state: *mut c_void) {
    let state = state.cast::<ImplCacheFlush>();
    // SAFETY: `state` is live per the contract.
    let n = unsafe { (*state).seed };
    let n = n ^ (n << 13);
    let n = n ^ (n >> 17);
    let n = n ^ (n << 5);
    // SAFETY: `state` is live, so this writes the advanced word back on both branches -- which is
    // the point: the sequence advances once per element whether the element is kept or dropped.
    unsafe { (*state).seed = n };
    if (n & 1) != 0 {
        // SAFETY: `c` is a live element of the table and `state` is live.
        let removed = unsafe { OPENSSL_LH_delete((*state).cache, c) };
        // SAFETY: `removed` is the element just unlinked, so it is this walk's own.
        unsafe { impl_cache_free(removed.cast::<Query>()) };
    } else {
        // SAFETY: `state` is live.
        unsafe { (*state).nelem += 1 };
    }
}

/// `IMPLEMENT_LHASH_DOALL_ARG(QUERY, IMPL_CACHE_FLUSH)`, which is the `doall_arg` call with the
/// two-argument thunk: `lh_QUERY_doall_IMPL_CACHE_FLUSH`.
///
/// # Safety
/// `alg` must be a live `Algorithm` and `v` a live `ImplCacheFlush`.
unsafe fn impl_cache_flush_one_alg(_idx: OsslUintMax, alg: *mut c_void, v: *mut c_void) {
    let alg = alg.cast::<Algorithm>();
    let state = v.cast::<ImplCacheFlush>();
    // SAFETY: `alg` and `state` are live per the contract.
    let cache = unsafe { (*alg).cache };
    // SAFETY: `cache` is the table this module built.
    let orig = unsafe { OPENSSL_LH_get_down_load(cache) };
    // SAFETY: `state` is live.
    unsafe { (*state).cache = cache };
    // The down-load is **set to 0 for the walk and restored after**, and both halves matter: at 0
    // every element is in a bucket of its own, so a `delete` inside the walk cannot move an element
    // the walk has not reached; and restoring it is what keeps the table's later retrievals
    // O(1)-ish rather than a linear scan.
    // SAFETY: `cache` is live.
    unsafe { OPENSSL_LH_set_down_load(cache, 0) };
    // SAFETY: `cache` is live and every element it hands the thunk is a `Query` this module built;
    // `state` outlives the walk.
    unsafe {
        OPENSSL_LH_doall_arg(cache, Some(impl_cache_flush_cache), state.cast::<c_void>());
        OPENSSL_LH_set_down_load(cache, orig);
    }
}

/// `static void ossl_method_cache_flush_some(OSSL_METHOD_STORE *store)`.
///
/// The stochastic flush, and every part of it is deliberate:
///
///   * the seed comes from the **timestamp counter**, so two flushes do not drop the same entries;
///   * a counter that answers 0 falls back to `GLOBAL_SEED` and *adds* the word back, so the
///     fallback still advances;
///   * `cache_need_flush` is cleared **before** the walk rather than after, so a concurrent
///     `_cache_set` that races the flush leaves the flag set for the next one instead of losing it;
///   * `cache_nelem` is replaced by the number of entries the walk *kept*, which is exact because
///     every kept entry was counted and every dropped one was deleted from a table whose count is
///     therefore unchanged.
///
/// **Its outcome is not reproducible, on either side.** The authority's own answer depends on its
/// timestamp counter, so no court may assert which entries survive — `RT-FETCH` says so in its
/// header and observes the *threshold* behaviour instead.
///
/// # Safety
/// `store` must be a live store.
unsafe fn ossl_method_cache_flush_some(store: *mut OsslMethodStore) {
    let mut state = ImplCacheFlush {
        cache: core::ptr::null_mut(),
        nelem: 0,
        seed: OPENSSL_rdtsc(),
        using_global_seed: 0,
    };
    if state.seed == 0 {
        state.using_global_seed = 1;
        state.seed = GLOBAL_SEED.load(Ordering::Relaxed);
    }
    // SAFETY: `store` is live per the contract.
    unsafe {
        (*store).cache_need_flush = 0;
        ossl_sa_doall_arg(
            (*store).algs,
            Some(impl_cache_flush_one_alg),
            ptr::addr_of_mut!(state).cast::<c_void>(),
        );
        (*store).cache_nelem = state.nelem;
    }
    if state.using_global_seed != 0 {
        GLOBAL_SEED.fetch_add(state.seed, Ordering::Relaxed);
    }
}

/// `int ossl_method_store_cache_get(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov, int nid,
/// const char *prop_query, void **method)`.
///
/// A cached *lookup*: build a key of the query text and the provider, retrieve, and take a
/// reference. `method` is written only on success, which is why `res` is the return value and not
/// `*method`.
///
/// The three refusals are the authority's: a non-positive id, a NULL store, and a **NULL
/// `prop_query`** — a cache keyed by text cannot be asked with no text, and that is a refusal rather
/// than a miss, so a caller that passes NULL learns nothing from the zero it gets.
///
/// # Safety
/// `store` must be NULL or live; `prov` NULL or live; `prop_query` NULL or NUL-terminated;
/// `method` NULL or writable for a `*mut c_void`.
pub(crate) unsafe fn ossl_method_store_cache_get(
    store: *mut OsslMethodStore,
    prov: *mut OsslProvider,
    nid: c_int,
    prop_query: *const c_char,
    method: *mut *mut c_void,
) -> c_int {
    if nid <= 0 || store.is_null() || prop_query.is_null() {
        return 0;
    }
    let mut res: c_int = 0;
    // SAFETY: `store` is live per the contract.
    unsafe {
        if ossl_property_read_lock(store) == 0 {
            return 0;
        }
        let alg = ossl_method_store_retrieve(store, nid);
        if !alg.is_null() {
            // The key is a *stack* `Query` whose `body` is never used: the comparator reads `query`
            // and `provider` only, and the hash reads `query`. The authority builds it on the stack
            // for exactly that reason.
            let mut elem = Query {
                provider: prov,
                query: prop_query,
                method: Method {
                    method: ptr::null_mut(),
                    up_ref: unused_up_ref,
                    free: unused_free,
                },
                body: [0],
            };
            let r = OPENSSL_LH_retrieve((*alg).cache, ptr::addr_of_mut!(elem).cast::<c_void>())
                .cast::<Query>();
            if !r.is_null() && ossl_method_up_ref(ptr::addr_of_mut!((*r).method)) != 0 {
                *method = (*r).method.method;
                res = 1;
            }
        }
        ossl_property_unlock(store);
    }
    res
}

/// `int ossl_method_store_cache_set(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov, int nid,
/// const char *prop_query, void *method, int (*method_up_ref)(void *),
/// void (*method_destruct)(void *))`.
///
/// Three behaviours in one function, and the `method == NULL` arm is the one a reader is least
/// likely to expect: **it is a delete.** A caller that finds the provider gone invalidates its
/// entry by setting NULL, which is why the entry point has a destructor parameter it does not use
/// on that path.
///
/// The insert path allocates one block for the header *and* the query text, points `query` at the
/// text inside the same allocation, copies the text with its terminator, and then distinguishes
/// three outcomes from one `insert`:
///
///   * the insert **replaced** an entry — free the old one and return, without touching the count,
///     because the table's size did not change;
///   * the insert succeeded — bump the count, and cross the threshold into a flush request;
///   * the insert failed — drop the reference the new entry took and report 0, leaving nothing
///     behind.
///
/// The `ossl_assert(prov != NULL)` is `(x) != 0` under `NDEBUG`, so a NULL provider is a refusal.
///
/// # Safety
/// `store` must be NULL or live; `prov` live; `prop_query` NULL or NUL-terminated; `method` NULL or
/// the method to cache, valid for the two callbacks.
pub(crate) unsafe fn ossl_method_store_cache_set(
    store: *mut OsslMethodStore,
    prov: *mut OsslProvider,
    nid: c_int,
    prop_query: *const c_char,
    method: *mut c_void,
    method_up_ref: MethodUpRefFn,
    method_destruct: MethodFreeFn,
) -> c_int {
    if nid <= 0 || store.is_null() || prop_query.is_null() {
        return 0;
    }
    if prov.is_null() {
        return 0;
    }
    let mut res: c_int = 1;
    let mut p: *mut Query = ptr::null_mut();
    // SAFETY: `store` is live per the contract.
    unsafe {
        if ossl_property_write_lock(store) == 0 {
            return 0;
        }
        if (*store).cache_need_flush != 0 {
            ossl_method_cache_flush_some(store);
        }
        let alg = ossl_method_store_retrieve(store, nid);
        if alg.is_null() {
            res = 0;
            CRYPTO_free(p.cast::<c_void>(), FILE, LINE_FREE_QUERY);
            ossl_property_unlock(store);
            return res;
        }

        if method.is_null() {
            let mut elem = Query {
                provider: prov,
                query: prop_query,
                method: Method {
                    method: ptr::null_mut(),
                    up_ref: unused_up_ref,
                    free: unused_free,
                },
                body: [0],
            };
            let old = OPENSSL_LH_delete((*alg).cache, ptr::addr_of_mut!(elem).cast::<c_void>())
                .cast::<Query>();
            if !old.is_null() {
                impl_cache_free(old);
                (*store).cache_nelem -= 1;
            }
            ossl_property_unlock(store);
            return res;
        }

        // `sizeof(QUERY) + strlen(prop_query)`, which is exactly enough for a header whose `body`
        // already holds one `char` plus the text and its terminator.
        let len = c_strlen(prop_query);
        p = CRYPTO_malloc(core::mem::size_of::<Query>() + len, FILE, LINE_MALLOC_QUERY)
            .cast::<Query>();
        if !p.is_null() {
            (*p).query = ptr::addr_of!((*p).body).cast::<c_char>();
            (*p).provider = prov;
            (*p).method.method = method;
            (*p).method.up_ref = method_up_ref;
            (*p).method.free = method_destruct;
            if ossl_method_up_ref(ptr::addr_of_mut!((*p).method)) == 0 {
                res = 0;
                CRYPTO_free(p.cast::<c_void>(), FILE, LINE_MALLOC_QUERY);
                ossl_property_unlock(store);
                return res;
            }
            c_memcpy(
                (*p).query.cast_mut().cast::<c_void>(),
                prop_query.cast(),
                len + 1,
            );
            let old = OPENSSL_LH_insert((*alg).cache, p.cast::<c_void>()).cast::<Query>();
            if !old.is_null() {
                impl_cache_free(old);
                ossl_property_unlock(store);
                return res;
            }
            if OPENSSL_LH_error((*alg).cache) == 0 {
                (*store).cache_nelem += 1;
                if (*store).cache_nelem >= IMPL_CACHE_FLUSH_THRESHOLD {
                    (*store).cache_need_flush = 1;
                }
                ossl_property_unlock(store);
                return res;
            }
            // The insert failed: the table did not take the entry, so the reference it took is
            // dropped here -- and the block is released by the shared `err:` path below.
            ossl_method_free(ptr::addr_of_mut!((*p).method));
        }
        res = 0;
        CRYPTO_free(p.cast::<c_void>(), FILE, LINE_MALLOC_QUERY);
        ossl_property_unlock(store);
    }
    res
}

/// `int ossl_method_store_fetch(OSSL_METHOD_STORE *store, int nid, const char *prop_query,
/// const OSSL_PROVIDER **prov_rw, void **method)`.
///
/// The match itself. The shape a reader has to hold on to is that the *no-query* path and the
/// *query* path are separate loops, not one loop with a condition:
///
///   * with no query at all, the first implementation of the first matching provider wins — the
///     authority's comment says provider preference is expressed by the *order* of the
///     implementation stack, so scanning in order and stopping is the preference rule;
///   * with a query, every matching implementation is scored by `ossl_property_match_count` and the
///     best score wins. **If the query has no optional properties the loop stops at the first
///     match**, because a score that cannot be improved on need not be searched for; if it has any,
///     the whole stack is walked, because a later implementation may match more of them.
///
/// The query is the caller's **merged with the context's global properties**, and the merge is
/// allocated when both exist — which is why `p2`, and not `pq`, is what is freed at the end. When
/// the caller's query is NULL and the context has global properties, `pq` *points at the context's
/// list* and must not be freed; when both exist, `p2` is the new list and `pq` is an alias of it.
///
/// The default-context shortcut is the authority's: a fetch against the default context loads the
/// configuration file first, so a `providers` section has been honoured before a name is resolved.
///
/// # Safety
/// `method` must be non-NULL and writable for a `*mut c_void`; `prov_rw` NULL or pointing at a
/// NULL-or-live provider **and writable for one**; `prop_query` NULL or NUL-terminated; `store`
/// NULL or live.
pub(crate) unsafe fn ossl_method_store_fetch(
    store: *mut OsslMethodStore,
    nid: c_int,
    prop_query: *const c_char,
    prov_rw: *mut *const OsslProvider,
    method: *mut *mut c_void,
) -> c_int {
    if nid <= 0 || method.is_null() || store.is_null() {
        return 0;
    }
    let prov = if prov_rw.is_null() {
        ptr::null()
    } else {
        // SAFETY: non-NULL here, so it points at a provider, which this reads.
        unsafe { *prov_rw }
    };

    let mut ret: c_int = 0;
    let mut pq: *mut OsslPropertyList = ptr::null_mut();
    let mut p2: *mut OsslPropertyList = ptr::null_mut();
    let mut best_impl: *mut Implementation = ptr::null_mut();

    // SAFETY: `store` is live per the contract.
    unsafe {
        // `#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_AUTOLOAD_CONFIG)`: neither is defined on
        // the admitted profile, so the branch is live. A refused load is a refusal to fetch.
        if crate::context::lib_ctx_is_default_symbol((*store).ctx) != 0
            && crate::runtime::init::OPENSSL_init_crypto(
                crate::runtime::init::OPENSSL_INIT_LOAD_CONFIG,
                ptr::null(),
            ) == 0
        {
            return 0;
        }

        // A **read** lock: a fetch creates nothing.
        if ossl_property_read_lock(store) == 0 {
            return 0;
        }
        let alg = ossl_method_store_retrieve(store, nid);
        if alg.is_null() {
            ossl_property_unlock(store);
            return 0;
        }

        if !prop_query.is_null() {
            pq = ossl_parse_query((*store).ctx, prop_query, 0);
            p2 = pq;
        }

        // The context's own default properties are merged in, and the two cases are not the same:
        // with no caller query, `pq` becomes an **alias** of the context's list.
        let plp = crate::property::globals::ossl_ctx_global_properties((*store).ctx, 0);
        if !plp.is_null() && !(*plp).is_null() {
            if pq.is_null() {
                pq = *plp;
            } else {
                p2 = ossl_property_merge(pq, *plp);
                ossl_property_free(pq);
                if p2.is_null() {
                    // The authority's `goto fin` with `ret == 0` and `p2 == NULL`: the caller's own
                    // list has already been released, the merge produced nothing, and the free at
                    // the tail is `ossl_property_free(NULL)`. Nothing is left to point `pq` at, so
                    // it is not touched -- writing NULL there would be a line the authority does
                    // not have.
                    ossl_property_unlock(store);
                    return 0;
                }
                pq = p2;
            }
        }

        if pq.is_null() {
            let mut j: c_int = 0;
            while j < OPENSSL_sk_num((*alg).impls) {
                let implementation = OPENSSL_sk_value((*alg).impls, j).cast::<Implementation>();
                if !implementation.is_null()
                    && (prov.is_null() || (*implementation).provider == prov)
                {
                    best_impl = implementation;
                    ret = 1;
                    break;
                }
                j += 1;
            }
        } else {
            let optional = ossl_property_has_optional(pq);
            let mut best: c_int = -1;
            let mut j: c_int = 0;
            while j < OPENSSL_sk_num((*alg).impls) {
                let implementation = OPENSSL_sk_value((*alg).impls, j).cast::<Implementation>();
                if !implementation.is_null()
                    && (prov.is_null() || (*implementation).provider == prov)
                {
                    let score = ossl_property_match_count(pq, (*implementation).properties);
                    if score > best {
                        best_impl = implementation;
                        best = score;
                        ret = 1;
                        if optional == 0 {
                            break;
                        }
                    }
                }
                j += 1;
            }
        }

        if ret != 0 && ossl_method_up_ref(ptr::addr_of_mut!((*best_impl).method)) != 0 {
            *method = (*best_impl).method.method;
            if !prov_rw.is_null() {
                // The authority's `const OSSL_PROVIDER **prov_rw`: the *pointee* is a
                // `const OSSL_PROVIDER *` and the pointer itself is writable, which is why this
                // parameter is `*mut *const` rather than `*const *const`. The fetch reports
                // **which** provider the method came from, which is how a caller learns the answer
                // was not the one it asked for.
                *prov_rw = (*best_impl).provider;
            }
        } else {
            ret = 0;
        }

        ossl_property_unlock(store);
        ossl_property_free(p2);
    }
    ret
}

/// `static void alg_do_one(ALGORITHM *alg, IMPLEMENTATION *impl,
/// void (*fn)(int id, void *method, void *fnarg), void *fnarg)`.
///
/// # Safety
/// `alg` and `impl` live; `fn` valid for a method.
unsafe fn alg_do_one(
    alg: *const Algorithm,
    implementation: *const Implementation,
    fn_: Option<MethodDoAllFn>,
    fnarg: *mut c_void,
) {
    if let Some(f) = fn_ {
        // SAFETY: `alg` and `implementation` are live per the contract and `fnarg` is the caller's.
        unsafe { f((*alg).nid, (*implementation).method.method, fnarg) };
    }
}

/// `void (*fn)(int id, void *method, void *fnarg)` — the visitor `ossl_method_store_do_all` takes.
pub(crate) type MethodDoAllFn = unsafe extern "C" fn(c_int, *mut c_void, *mut c_void);

/// `static void alg_copy(ossl_uintmax_t idx, ALGORITHM *alg, void *arg)`.
///
/// The store is **copied under the lock and walked outside it**, which is the whole reason this
/// function exists: a visitor may call back into the store, and holding the read lock across a
/// visitor that takes the write lock would deadlock. The copy is *shallow in the author's intent and
/// accidentally deep in one field* — `OPENSSL_memdup` copies the `ALGORITHM` header, and then
/// `sk_IMPLEMENTATION_dup` copies the implementation **stack** — so the snapshot's stack is its own
/// while the implementations inside it are the store's, and `del_tmpalg` frees only the stack and
/// the copied header.
///
/// # Safety
/// `alg` must be a live entry of the array being walked and `arg` a live `OPENSSL_STACK`.
unsafe fn alg_copy(_idx: OsslUintMax, alg: *mut c_void, arg: *mut c_void) {
    let newalg = arg.cast::<OpenSslStack>();
    let alg = alg.cast::<Algorithm>();
    // `OPENSSL_memdup(str, s)` is a macro: `CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)`,
    // which is why the coordinates are this call site's.
    // SAFETY: `alg` is live per the contract, so this reads `sizeof(ALGORITHM)` bytes of it.
    let copy = unsafe {
        CRYPTO_memdup(
            alg.cast::<c_void>(),
            core::mem::size_of::<Algorithm>(),
            FILE,
            LINE_MEMDUP_ALG,
        )
        .cast::<Algorithm>()
    };
    if copy.is_null() {
        return;
    }
    // SAFETY: `copy` is a fresh block this call owns and `alg` is live per the contract.
    unsafe {
        (*copy).impls = OPENSSL_sk_dup((*alg).impls);
        OPENSSL_sk_push(newalg, copy.cast::<c_void>());
    }
}

/// `static void del_tmpalg(ALGORITHM *alg)`.
///
/// The copied header's releaser: the **stack container only**, not its elements — they belong to the
/// store and are still in it.
///
/// # Safety
/// `alg` must be a copied header produced by [`alg_copy`].
unsafe extern "C" fn del_tmpalg(alg: *mut c_void) {
    let alg = alg.cast::<Algorithm>();
    // SAFETY: `alg` is a copy this module made, so `impls` is the duplicate stack it created.
    unsafe {
        OPENSSL_sk_free((*alg).impls);
        CRYPTO_free(alg.cast::<c_void>(), FILE, LINE_FREE_ALG);
    }
}

/// `void ossl_method_store_do_all(OSSL_METHOD_STORE *store,
/// void (*fn)(int id, void *method, void *fnarg), void *fnarg)`.
///
/// A read lock, a snapshot, an unlock, then the walk. A NULL store is a no-op rather than a
/// refusal, because the entry point returns nothing: there is no answer to distinguish.
///
/// # Safety
/// `store` must be NULL or live; `fn` NULL or valid for every method the store holds.
pub(crate) unsafe fn ossl_method_store_do_all(
    store: *mut OsslMethodStore,
    fn_: Option<MethodDoAllFn>,
    fnarg: *mut c_void,
) {
    if store.is_null() {
        return;
    }
    // SAFETY: `store` is live per the contract.
    unsafe {
        if ossl_property_read_lock(store) == 0 {
            return;
        }
        let tmpalgs = OPENSSL_sk_new_reserve(None, ossl_sa_num((*store).algs) as c_int);
        if tmpalgs.is_null() {
            ossl_property_unlock(store);
            return;
        }
        ossl_sa_doall_arg((*store).algs, Some(alg_copy), tmpalgs.cast::<c_void>());
        ossl_property_unlock(store);
        let numalgs = OPENSSL_sk_num(tmpalgs);
        let mut i: c_int = 0;
        while i < numalgs {
            let alg = OPENSSL_sk_value(tmpalgs, i).cast::<Algorithm>();
            let numimps = OPENSSL_sk_num((*alg).impls);
            let mut j: c_int = 0;
            while j < numimps {
                let implementation = OPENSSL_sk_value((*alg).impls, j).cast::<Implementation>();
                alg_do_one(alg, implementation, fn_, fnarg);
                j += 1;
            }
            i += 1;
        }
        OPENSSL_sk_pop_free(tmpalgs, Some(del_tmpalg));
    }
}

/// `strlen`, behind a safe-to-call-from-`unsafe` name.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn c_strlen(s: *const c_char) -> usize {
    extern "C" {
        fn strlen(s: *const c_char) -> usize;
    }
    // SAFETY: the caller's contract.
    unsafe { strlen(s) }
}

/// `memcpy`, behind a safe-to-call-from-`unsafe` name.
///
/// # Safety
/// `dst` must be writable for `n` bytes and `src` readable for the same.
unsafe fn c_memcpy(dst: *mut c_void, src: *const c_void, n: usize) {
    extern "C" {
        fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    }
    // SAFETY: the caller's contract.
    unsafe {
        memcpy(dst, src, n);
    }
}

/// The two callbacks a **stack-built key** carries, which are never called.
///
/// `ossl_method_store_cache_get` and `_cache_set`'s delete arm each build a `Query` on the stack
/// whose `query` and `provider` are read by the hash and comparator and whose `method` is never
/// touched — the authority leaves those three fields indeterminate and the table never looks at
/// them, because a key is not stored. Rust cannot spell an indeterminate function pointer, so the
/// fields are initialised to functions that abort if they are ever reached, which turns "the table
/// never calls this" from a comment into a check.
unsafe extern "C" fn unused_up_ref(_method: *mut c_void) -> c_int {
    unreachable!("a stack-built QUERY key's `method.up_ref` was called")
}

/// See [`unused_up_ref`].
unsafe extern "C" fn unused_free(_method: *mut c_void) {
    unreachable!("a stack-built QUERY key's `method.free` was called")
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicI32, Ordering};

    /// The method object the tests store, and a marker the two callbacks check it against. A
    /// `static` so its address is stable and comparable.
    static METHOD: u8 = 0xA5;
    /// `[0]` up_ref calls, `[1]` free calls, `[2]` the last method pointer `up_ref` saw, `[3]` the
    /// same for `free`.
    static SAW: [AtomicI32; 4] = [
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
    ];

    /// `[4]`/`[5]`: `do_all`'s visitor counters -- the number of visits and the sum of the ids it
    /// was handed, so a visitor called with the wrong id is visible.
    static VISITS: AtomicI32 = AtomicI32::new(0);
    static NIDS: AtomicI32 = AtomicI32::new(0);

    /// `void (*fn)(int id, void *method, void *fnarg)`, for `do_all`'s test.
    unsafe extern "C" fn visit(id: c_int, _method: *mut c_void, _fnarg: *mut c_void) {
        VISITS.fetch_add(1, Ordering::SeqCst);
        NIDS.fetch_add(id, Ordering::SeqCst);
    }

    fn method_ptr() -> *mut c_void {
        ptr::addr_of!(METHOD) as *mut c_void
    }

    fn reset() {
        for s in &SAW {
            s.store(0, Ordering::SeqCst);
        }
    }

    unsafe extern "C" fn up_ref(m: *mut c_void) -> c_int {
        SAW[0].fetch_add(1, Ordering::SeqCst);
        SAW[2].store(m as usize as i32, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn free(m: *mut c_void) {
        SAW[1].fetch_add(1, Ordering::SeqCst);
        SAW[3].store(m as usize as i32, Ordering::SeqCst);
    }

    fn store() -> *mut OsslMethodStore {
        // SAFETY: a NULL context is accepted and stored, not read.
        let s = unsafe { ossl_method_store_new(ptr::null_mut()) };
        assert!(!s.is_null(), "the store was built");
        s
    }

    fn release(s: *mut OsslMethodStore) {
        // SAFETY: `s` came from `store()` and is released once.
        unsafe { ossl_method_store_free(s) };
    }

    /// `add` takes a reference and rejects the four arguments that cannot be used, and the
    /// reference count is the part a caller cannot see: a store that did not take one would let a
    /// caller free the method while the store still held it.
    #[test]
    fn add_takes_a_reference_and_refuses_the_unusable_arguments() {
        reset();
        let s = store();
        // SAFETY: `s` is live; the provider is a non-NULL marker this test only compares by
        // identity, and the method's two callbacks are this module's own.
        let prov = 0x1000usize as *const OsslProvider;
        // SAFETY: as above.
        let added = unsafe {
            ossl_method_store_add(
                s,
                prov,
                1,
                c"provider=default".as_ptr(),
                method_ptr(),
                up_ref,
                free,
            )
        };
        assert_eq!(added, 1);
        assert_eq!(SAW[0].load(Ordering::SeqCst), 1, "one reference taken");
        assert_eq!(SAW[2].load(Ordering::SeqCst), method_ptr() as usize as i32);

        // The four refusals, in the authority's order of tests.
        // SAFETY: every call passes an argument that makes it return before any use.
        unsafe {
            assert_eq!(
                ossl_method_store_add(s, prov, 0, ptr::null(), method_ptr(), up_ref, free),
                0,
                "nid <= 0"
            );
            assert_eq!(
                ossl_method_store_add(s, prov, 2, ptr::null(), ptr::null_mut(), up_ref, free),
                0,
                "method == NULL"
            );
            assert_eq!(
                ossl_method_store_add(
                    ptr::null_mut(),
                    prov,
                    3,
                    ptr::null(),
                    method_ptr(),
                    up_ref,
                    free
                ),
                0,
                "store == NULL"
            );
            assert_eq!(
                ossl_method_store_add(s, ptr::null(), 4, ptr::null(), method_ptr(), up_ref, free),
                0,
                "prov == NULL"
            );
        }
        assert_eq!(
            SAW[0].load(Ordering::SeqCst),
            1,
            "and no further references"
        );
        release(s);
    }

    /// A second add of the same provider and the same property text is a **no-op**, not a second
    /// implementation: the property *list* is shared through the definition cache, so the duplicate
    /// scan compares pointers and finds them equal.
    #[test]
    fn a_duplicate_implementation_is_not_added_twice() {
        reset();
        let s = store();
        let prov = 0x1000usize as *const OsslProvider;
        // SAFETY: `s` is live and the arguments are as above.
        unsafe {
            assert_eq!(
                ossl_method_store_add(
                    s,
                    prov,
                    7,
                    c"provider=default".as_ptr(),
                    method_ptr(),
                    up_ref,
                    free
                ),
                1
            );
            assert_eq!(
                ossl_method_store_add(
                    s,
                    prov,
                    7,
                    c"provider=default".as_ptr(),
                    method_ptr(),
                    up_ref,
                    free
                ),
                0,
                "the same provider and property list is already there"
            );
        }
        // Two references were taken and one implementation was released by the refused add.
        assert_eq!(SAW[0].load(Ordering::SeqCst), 2);
        assert_eq!(SAW[1].load(Ordering::SeqCst), 1);
        release(s);
    }

    /// `remove` finds the implementation **by the method object**, not by the wrapper, and answers
    /// 0 for one that is not there — which is what a caller that lost track of whether it added
    /// something depends on.
    #[test]
    fn remove_finds_the_method_and_answers_zero_for_one_that_is_absent() {
        reset();
        let s = store();
        let prov = 0x1000usize as *const OsslProvider;
        // SAFETY: `s` is live and the arguments are as above.
        unsafe {
            assert_eq!(
                ossl_method_store_add(s, prov, 9, c"".as_ptr(), method_ptr(), up_ref, free),
                1
            );
            // A different method object: the same nid, but not a method this store holds.
            let other = 0x2000usize as *const c_void;
            assert_eq!(ossl_method_store_remove(s, 9, other), 0, "not there");
            assert_eq!(SAW[1].load(Ordering::SeqCst), 0, "and nothing was released");
            assert_eq!(ossl_method_store_remove(s, 9, method_ptr()), 1);
            assert_eq!(SAW[1].load(Ordering::SeqCst), 1, "the store's reference");
            assert_eq!(
                ossl_method_store_remove(s, 9, method_ptr()),
                0,
                "removing it twice is not a success"
            );
        }
        release(s);
    }

    /// `remove_all_provided` releases every implementation of one provider, and a **NULL store is
    /// a refusal** — the lock cannot be taken, so the function answers 0 before it looks at the
    /// provider. That is `ossl_property_write_lock`'s contract showing through, and it is not the
    /// absent-*slot* answer of 1 that the provider bridges document: those test the slot first.
    #[test]
    fn remove_all_provided_releases_one_provider_and_refuses_a_null_store() {
        reset();
        let s = store();
        let mine = 0x1000usize as *const OsslProvider;
        let theirs = 0x2000usize as *const OsslProvider;
        // SAFETY: `s` is live; the two providers are markers compared by identity only.
        unsafe {
            assert_eq!(
                ossl_method_store_add(s, mine, 1, c"".as_ptr(), method_ptr(), up_ref, free),
                1
            );
            assert_eq!(
                ossl_method_store_add(s, theirs, 1, c"".as_ptr(), method_ptr(), up_ref, free),
                1
            );
            assert_eq!(ossl_method_store_remove_all_provided(s, mine), 1);
            assert_eq!(
                SAW[1].load(Ordering::SeqCst),
                1,
                "only the one provider's implementation was released"
            );
            assert_eq!(
                ossl_method_store_remove_all_provided(ptr::null_mut(), mine),
                0,
                "a NULL store cannot take the lock, so it is refused"
            );
        }
        release(s);
    }

    /// The store's own reference is dropped when it is freed, once per implementation, and a store
    /// that was never used releases cleanly.
    #[test]
    fn freeing_the_store_drops_every_reference_it_held() {
        reset();
        let s = store();
        let prov = 0x1000usize as *const OsslProvider;
        // SAFETY: `s` is live and the arguments are as above.
        unsafe {
            assert_eq!(
                ossl_method_store_add(s, prov, 3, c"".as_ptr(), method_ptr(), up_ref, free),
                1
            );
            assert_eq!(
                ossl_method_store_add(s, prov, 4, c"".as_ptr(), method_ptr(), up_ref, free),
                1
            );
        }
        release(s);
        assert_eq!(SAW[0].load(Ordering::SeqCst), 2, "two references");
        assert_eq!(SAW[1].load(Ordering::SeqCst), 2, "both dropped");
        assert_eq!(SAW[3].load(Ordering::SeqCst), method_ptr() as usize as i32);

        reset();
        release(store());
        assert_eq!(SAW[0].load(Ordering::SeqCst), 0);
        assert_eq!(SAW[1].load(Ordering::SeqCst), 0);
    }

    /// The two locks are **different locks**: taking the reservation and then releasing the array's
    /// lock would leave the reservation held, and the test pins that they are independent rather
    /// than the same object.
    #[test]
    fn the_two_locks_are_independent() {
        reset();
        let s = store();
        // SAFETY: `s` is live and both helpers accept it.
        unsafe {
            assert_eq!(ossl_method_lock_store(s), 1);
            // The array lock is a *different* lock, so this succeeds while the reservation is held.
            assert_eq!(ossl_property_write_lock(s), 1);
            assert_eq!(ossl_property_unlock(s), 1);
            assert_eq!(ossl_method_unlock_store(s), 1);
            // Both are released, so both can be taken again.
            assert_eq!(ossl_method_lock_store(s), 1);
            assert_eq!(ossl_method_unlock_store(s), 1);
            assert_eq!(
                ossl_method_lock_store(ptr::null_mut()),
                0,
                "NULL is a refusal"
            );
            assert_eq!(ossl_method_unlock_store(ptr::null_mut()), 0);
            assert_eq!(ossl_property_read_lock(ptr::null_mut()), 0);
            assert_eq!(ossl_property_write_lock(ptr::null_mut()), 0);
            assert_eq!(ossl_property_unlock(ptr::null_mut()), 0);
        }
        release(s);
    }

    /// The cache round-trips, and **a NULL method deletes**. The delete arm is the one a reader
    /// would not predict from the name, and it is what `evp_fetch.c` uses to invalidate an entry
    /// whose provider has gone: the entry point takes a destructor parameter it does not need on
    /// that path.
    #[test]
    fn the_cache_round_trips_a_result_and_a_null_method_deletes_it() {
        reset();
        let s = store();
        let prov = 0x1000usize as *mut OsslProvider;
        let mut got: *mut c_void = ptr::null_mut();
        // SAFETY: `s` is live; `prov` is a marker compared by identity; the query is a literal and
        // the out-parameter is this frame's own slot.
        unsafe {
            // A miss first: the table is empty.
            assert_eq!(
                ossl_method_store_cache_get(s, prov, 5, c"provider=default".as_ptr(), &mut got),
                0,
                "nothing is cached yet"
            );
            // A store the entry can be attached to: the cache is per-nid, so the nid must exist.
            assert_eq!(
                ossl_method_store_add(
                    s,
                    prov,
                    5,
                    c"provider=default".as_ptr(),
                    method_ptr(),
                    up_ref,
                    free
                ),
                1
            );
            reset();
            assert_eq!(
                ossl_method_store_cache_set(
                    s,
                    prov,
                    5,
                    c"provider=default".as_ptr(),
                    method_ptr(),
                    up_ref,
                    free
                ),
                1
            );
            assert_eq!(
                ossl_method_store_cache_get(s, prov, 5, c"provider=default".as_ptr(), &mut got),
                1
            );
            assert_eq!(got, method_ptr(), "the cached method came back");
            assert_eq!(
                SAW[0].load(Ordering::SeqCst),
                2,
                "set and get each took one"
            );

            // A NULL `method` is a delete, and the entry's reference is dropped with it.
            reset();
            assert_eq!(
                ossl_method_store_cache_set(
                    s,
                    prov,
                    5,
                    c"provider=default".as_ptr(),
                    ptr::null_mut(),
                    up_ref,
                    free
                ),
                1
            );
            assert_eq!(
                SAW[1].load(Ordering::SeqCst),
                1,
                "the entry's reference was dropped"
            );
            assert_eq!(
                ossl_method_store_cache_get(s, prov, 5, c"provider=default".as_ptr(), &mut got),
                0,
                "and the entry is gone"
            );
        }
        release(s);
    }

    /// With no query at all the **first** implementation wins, because the authority's provider
    /// preference is expressed by the order of the implementation stack rather than by a score.
    #[test]
    fn the_fetch_takes_the_first_implementation_when_there_is_no_query() {
        reset();
        let s = store();
        let first = 0x1000usize as *const OsslProvider;
        let second = 0x2000usize as *const OsslProvider;
        let mut got: *mut c_void = ptr::null_mut();
        let mut reported: *const OsslProvider = ptr::null();
        // SAFETY: `s` is live; the providers are markers compared by identity only.
        unsafe {
            assert_eq!(
                ossl_method_store_add(s, first, 3, c"".as_ptr(), method_ptr(), up_ref, free),
                1
            );
            assert_eq!(
                ossl_method_store_add(s, second, 3, c"".as_ptr(), method_ptr(), up_ref, free),
                1
            );
            assert_eq!(
                ossl_method_store_fetch(s, 3, ptr::null(), &mut reported, &mut got),
                1
            );
            assert_eq!(got, method_ptr());
            assert_eq!(
                reported, first,
                "the provider pushed first is the one reported"
            );

            // The provider filter is the caller's: asking for the second provider answers the
            // second, even though the first is earlier in the stack.
            let mut got2: *mut c_void = ptr::null_mut();
            let mut want = second;
            assert_eq!(
                ossl_method_store_fetch(s, 3, ptr::null(), &mut want, &mut got2),
                1
            );
            assert_eq!(got2, method_ptr());

            // An id nobody added is a refusal, and `*method` is left alone.
            let untouched = got2;
            assert_eq!(
                ossl_method_store_fetch(s, 99, ptr::null(), ptr::null_mut(), &mut got2),
                0
            );
            assert_eq!(got2, untouched, "a failed fetch writes nothing");
        }
        release(s);
    }

    /// With a query, the **best match** wins rather than the first, and the provider that answered
    /// is written back through the caller's out-parameter — which is how a caller learns the method
    /// it got was not the one it asked for.
    #[test]
    fn the_fetch_scores_against_a_query_and_reports_the_answering_provider() {
        reset();
        let s = store();
        let default_prov = 0x1000usize as *const OsslProvider;
        let other_prov = 0x2000usize as *const OsslProvider;
        let mut got: *mut c_void = ptr::null_mut();
        let mut reported: *const OsslProvider = ptr::null();
        // SAFETY: `s` is live; the providers are markers compared by identity only.
        unsafe {
            assert_eq!(
                ossl_method_store_add(
                    s,
                    default_prov,
                    8,
                    c"provider=default".as_ptr(),
                    method_ptr(),
                    up_ref,
                    free
                ),
                1
            );
            assert_eq!(
                ossl_method_store_add(
                    s,
                    other_prov,
                    8,
                    c"provider=other".as_ptr(),
                    method_ptr(),
                    up_ref,
                    free
                ),
                1
            );
            // A query that only the second implementation satisfies: the score picks it over the
            // implementation that is earlier in the stack.
            assert_eq!(
                ossl_method_store_fetch(s, 8, c"provider=other".as_ptr(), &mut reported, &mut got),
                1
            );
            assert_eq!(
                reported, other_prov,
                "the query decided the provider, not the stack order"
            );
            assert_eq!(got, method_ptr());

            // A query nobody satisfies is still a refusal rather than a partial match.
            let mut got3: *mut c_void = ptr::null_mut();
            assert_eq!(
                ossl_method_store_fetch(s, 8, c"fips=yes".as_ptr(), ptr::null_mut(), &mut got3),
                0,
                "no implementation declares fips=yes"
            );
        }
        release(s);
    }

    /// `do_all` visits every implementation of every id, and the visitor sees the id the store is
    /// keyed by. It is the only entry point here whose contract is a *count* of visits rather than
    /// an answer, which is what makes it the one that catches a snapshot built wrongly.
    #[test]
    fn do_all_visits_every_method_once() {
        reset();
        let s = store();
        let prov = 0x1000usize as *const OsslProvider;
        VISITS.store(0, Ordering::SeqCst);
        NIDS.store(0, Ordering::SeqCst);
        // SAFETY: `s` is live and the provider is a marker compared by identity only.
        unsafe {
            assert_eq!(
                ossl_method_store_add(s, prov, 1, c"".as_ptr(), method_ptr(), up_ref, free),
                1
            );
            assert_eq!(
                ossl_method_store_add(s, prov, 2, c"".as_ptr(), method_ptr(), up_ref, free),
                1
            );
            ossl_method_store_do_all(s, Some(visit), ptr::null_mut());
        }
        assert_eq!(VISITS.load(Ordering::SeqCst), 2, "two ids, one method each");
        assert_eq!(
            NIDS.load(Ordering::SeqCst),
            3,
            "the visitor saw nid 1 and nid 2"
        );
        release(s);
    }

    /// `cache_need_flush` is requested **at** the threshold, not above it, and a `_cache_set` that
    /// arrives with the flag set flushes before it inserts. The flush's *outcome* is seed-dependent
    /// on the authority as well, so this asserts the flag only — see the module's note on the
    /// stochastic flush and `RT-FETCH`'s header.
    #[test]
    fn the_threshold_requests_a_flush() {
        reset();
        let s = store();
        let prov = 0x1000usize as *mut OsslProvider;
        // SAFETY: `s` is live and the provider is a marker compared by identity only.
        unsafe {
            assert_eq!(
                ossl_method_store_add(
                    s,
                    prov.cast_const(),
                    6,
                    c"".as_ptr(),
                    method_ptr(),
                    up_ref,
                    free
                ),
                1
            );
            assert_eq!((*s).cache_need_flush, 0, "not yet");
            // `IMPL_CACHE_FLUSH_THRESHOLD` distinct query strings, which is what makes them
            // distinct entries rather than replacements.
            let mut buf = [0i8; 16];
            let alphabet = b"0123456789abcdef";
            for i in 0..IMPL_CACHE_FLUSH_THRESHOLD {
                buf[0] = b'q' as i8;
                buf[1] = b'=' as i8;
                buf[2] = alphabet[(i >> 4) & 0xf] as i8;
                buf[3] = alphabet[i & 0xf] as i8;
                buf[4] = alphabet[(i >> 8) & 0xf] as i8;
                buf[5] = 0;
                assert_eq!(
                    ossl_method_store_cache_set(
                        s,
                        prov,
                        6,
                        buf.as_ptr(),
                        method_ptr(),
                        up_ref,
                        free
                    ),
                    1
                );
            }
            assert_eq!((*s).cache_nelem, IMPL_CACHE_FLUSH_THRESHOLD);
            assert_eq!((*s).cache_need_flush, 1, "the threshold was crossed");
        }
        release(s);
    }
}
