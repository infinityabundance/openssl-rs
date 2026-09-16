//! Phase 7.1 — `crypto/core_fetch.c`: the walk that turns a provider's algorithms into methods.
//!
//! This is the upper half of 7.1 and the other deferral Phase 6 handed forward (D132, D134): its
//! only meaningful work is calling `ossl_algorithm_do_all`, which is `crypto/core_algorithm.c`'s
//! and landed in `src/evp/algorithm.rs`. What this file contributes on top of the walk is the
//! *policy* of when construction happens and where the result is put, and every one of its
//! functions is one of the six callbacks the walk takes.
//!
//! ## It is a callback host, and the shape follows from that
//!
//! `ossl_method_construct` fills a `construct_data_st` and hands six of its own static
//! functions to `ossl_algorithm_do_all`. So the five `ossl_method_construct_*` functions below
//! are not a call graph — they are entry points that the walk reaches in a fixed order, and the
//! order is what makes the policy legible:
//!
//! ```text
//! reserve_store   -> get the store, or a *temporary* one, and lock it
//! precondition    -> has this provider already been asked for this operation?
//! this            -> construct one method per algorithm and put it in the store
//! postcondition   -> mark the provider's operation bit, so it is not asked again
//! unreserve_store -> unlock
//! ```
//!
//! ## The bit is the whole optimisation, and it is inverted
//!
//! The precondition asks `ossl_provider_test_operation_bit` whether methods for this operation
//! have *already been constructed*, and the authority then **negates the answer**, because the
//! walk wants to know whether construction *should happen* and that is the opposite question:
//!
//! ```c
//! *result = !*result;
//! ```
//!
//! That negation is why `algorithm_do_map` treats `result = 0` as *skip this map and continue*
//! rather than as an error — the two facts together are the mechanism that stops a second fetch
//! of the same name from re-constructing every method of every provider. A transcription that
//! dropped the `!` would construct once and then never again, which fails in the direction that
//! looks like a performance problem and is actually a correctness one: a provider loaded later
//! would still be asked, but a provider whose bits were set but whose store had been cleared
//! would not be.
//!
//! **Temporary stores have no bits.** `is_temporary_method_store` is `no_store && !force_store`,
//! and both the pre- and the postcondition short-circuit on it — the pre because there is no
//! bit to test, the post because there is none to set. A temporary store is the caller's, and
//! its lifetime is the caller's problem; that is what `mcm->get_tmp_store` is for.
//!
//! ## Where the method is looked up is not where it was put
//!
//! `this` puts into the store **only when `no_store` is zero**:
//!
//! ```c
//! data->mcm->put(no_store ? data->store : NULL, method, ...);
//! ```
//!
//! — a temporary store receives the method, the global store receives it when the provider
//! asked for caching. Then `ossl_method_construct` looks first in the temporary store if there
//! is one, and only then in the global one with a **NULL** store argument, which is the `mcm`'s
//! way of naming "the global store" rather than passing it. Both lookups are the caller's
//! `mcm->get`, so no store type is visible here at all: `OSSL_METHOD_STORE` is opaque in this
//! file, and the four `void *store` callbacks are what keeps it that way.
//!
//! **That two-lookup policy is not unit-tested, and the reason is worth stating rather than
//! discovering.** The branch between the two lookups is chosen by `cbdata.store`, which the walk
//! fills — so reaching it needs a provider that can be queried, and a unit test that called
//! `ossl_algorithm_do_all` for real would sweep the default context, activate the three
//! predefined providers and read `openssl.cnf` as a side effect of a `cargo test`. The sibling
//! `algorithm.rs` draws the same line for the same reason. `RT-FETCH` is the observation: a
//! differential court calls this function with a real provider and sees both lookups.
//!
//! ## The reference count is dropped by us and not by the store
//!
//! `this` calls `mcm->destruct` on the method it just constructed, and the authority's comment
//! says why in the same breath as the `put`: *"it is expected that the put function increments
//! the refcnt of the passed method"*. So the sequence is construct (1) → put (+1 = 2) →
//! destruct (−1 = 1), and the store's reference is what survives. A transcription that skipped
//! the destruct would leak one reference per algorithm per fetch, which the memory courts would
//! only catch if something counted — and nothing does, because the store holds them forever.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::evp::algorithm::{
    ossl_algorithm_do_all, AlgorithmFn, AlgorithmPostFn, AlgorithmPreFn, AlgorithmReserveStoreFn,
    AlgorithmUnreserveStoreFn,
};
use crate::provider::activate::{
    ossl_provider_set_operation_bit, ossl_provider_test_operation_bit, OsslAlgorithm,
};
use crate::provider::OsslProvider;
use crate::runtime::err::{err_sites, raise_site};

/// `OSSL_METHOD_STORE` — `include/internal/core.h`: `typedef struct ossl_method_store_st
/// OSSL_METHOD_STORE;`. Opaque here, and **that is the design rather than an omission**: this
/// file never reads a store, it only hands one back to the caller's `mcm`, so the type that a
/// store *is* belongs to the file that implements it.
///
/// That file is **`crypto/property/property.c`** and not `crypto/evp/evp_fetch.c`, which is worth
/// stating because 7.1's own plan row said the opposite until D141: `evp_fetch.c` *calls*
/// `ossl_method_store_new` and the eleven other store functions, and `property.c` defines them —
/// alongside the three `ossl_ctx_global_properties`/`ossl_global_properties_*` that 6.7a left
/// behind. The store lands in the same subphase as this file, which is why the walk can be
/// written before it: nothing here dereferences a store.
pub enum OsslMethodStore {}

/// `void *(*get_tmp_store)(void *data)`.
pub(crate) type McmGetTmpStoreFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `int (*lock_store)(void *store, void *data)`.
pub(crate) type McmLockStoreFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
/// `int (*unlock_store)(void *store, void *data)`.
pub(crate) type McmUnlockStoreFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
/// `void *(*get)(void *store, const OSSL_PROVIDER **prov, void *data)`.
pub(crate) type McmGetFn =
    unsafe extern "C" fn(*mut c_void, *const *const OsslProvider, *mut c_void) -> *mut c_void;
/// `int (*put)(void *store, void *method, const OSSL_PROVIDER *prov, const char *name,
/// const char *propdef, void *data)`.
pub(crate) type McmPutFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_void,
    *const OsslProvider,
    *const c_char,
    *const c_char,
    *mut c_void,
) -> c_int;
/// `void *(*construct)(const OSSL_ALGORITHM *algodef, OSSL_PROVIDER *prov, void *data)`.
pub(crate) type McmConstructFn =
    unsafe extern "C" fn(*const OsslAlgorithm, *mut OsslProvider, *mut c_void) -> *mut c_void;
/// `void (*destruct)(void *method, void *data)`.
pub(crate) type McmDestructFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

/// `typedef struct ossl_method_construct_method_st { ... } OSSL_METHOD_CONSTRUCT_METHOD`.
///
/// Every entry is a function pointer and every store parameter is `void *`, so this file is a
/// policy layer over an interface rather than over an implementation. The order of the fields is
/// the authority's; nothing in this crate constructs one by position, so the order is
/// documentation rather than ABI — but it is kept, because the authority's own readers use it.
///
/// The *type* is `pub` for one reason and it is not a claim about the interface: it appears in
/// `ossl_method_construct`'s signature, that function is `pub` because it is exported, and Rust
/// requires the type of an exported item's parameter to be at least as visible. The authority
/// keeps `OSSL_METHOD_CONSTRUCT_METHOD` internal to `include/internal/core.h`, the fields here
/// are `pub(crate)` for that reason, and nothing outside this crate can name the type or reach
/// an entry point through it.
#[repr(C)]
pub struct OsslMethodConstructMethod {
    /// `void *(*get_tmp_store)(void *data)`.
    pub(crate) get_tmp_store: McmGetTmpStoreFn,
    /// `int (*lock_store)(void *store, void *data)`.
    pub(crate) lock_store: McmLockStoreFn,
    /// `int (*unlock_store)(void *store, void *data)`.
    pub(crate) unlock_store: McmUnlockStoreFn,
    /// `void *(*get)(void *store, const OSSL_PROVIDER **prov, void *data)`.
    pub(crate) get: McmGetFn,
    /// `int (*put)(void *store, void *method, const OSSL_PROVIDER *prov, const char *name,
    /// const char *propdef, void *data)`.
    pub(crate) put: McmPutFn,
    /// `void *(*construct)(const OSSL_ALGORITHM *algodef, OSSL_PROVIDER *prov, void *data)`.
    pub(crate) construct: McmConstructFn,
    /// `void (*destruct)(void *method, void *data)`.
    pub(crate) destruct: McmDestructFn,
}

/// `struct construct_data_st` — the walk's state for this file, filled by `ossl_method_construct`
/// and read by each of the five callbacks below.
///
/// **Two of its six fields are not assigned by the authority.** `ossl_method_construct` declares
/// `struct construct_data_st cbdata;` as a stack local and sets four of them — `store`,
/// `force_store`, `mcm` and `mcm_data` — so `libctx` and `operation_id` are indeterminate and
/// nothing in the file reads either: the walk takes the operation from its own argument and the
/// callbacks are never given the `libctx` at all. This transcription assigns both from
/// `ossl_method_construct`'s parameters, which is a divergence *in the crate's favour* — it makes
/// the struct fully determined — and it is invisible because no reader exists on either side. The
/// alternative, leaving them uninitialised, is the one thing this crate cannot transcribe: Rust
/// cannot spell an undetermined field, and inventing a read of it would be worse than a write.
#[repr(C)]
pub(crate) struct ConstructData {
    /// `OSSL_LIB_CTX *libctx` — written here, never written and never read by the authority.
    pub(crate) libctx: *mut c_void,
    /// `OSSL_METHOD_STORE *store` — NULL until `reserve_store` fills it, and the flag that says
    /// whether a temporary store was used: `ossl_method_construct`'s final lookups test it.
    pub(crate) store: *mut c_void,
    /// `int operation_id` — written here, never written and never read by the authority.
    pub(crate) operation_id: c_int,
    /// `int force_store` — makes `no_store` irrelevant, which is how a caller that must cache
    /// says so.
    pub(crate) force_store: c_int,
    /// `OSSL_METHOD_CONSTRUCT_METHOD *mcm` — the caller's interface, and the only way this file
    /// touches a store.
    pub(crate) mcm: *const OsslMethodConstructMethod,
    /// `void *mcm_data` — opaque, and handed back to every `mcm` entry point.
    pub(crate) mcm_data: *mut c_void,
}

/// `static int is_temporary_method_store(int no_store, void *cbdata)`.
///
/// `no_store && !force_store`, and it is the predicate the other four callbacks branch on. Named
/// as a function rather than open-coded because the two places that must agree about it are the
/// pre- and the postcondition, and a transcription that spelled it out in one of them and not
/// the other would set a bit on a store that has none.
///
/// # Safety
/// `cbdata` must be a live `ConstructData`.
unsafe fn is_temporary_method_store(no_store: c_int, cbdata: *mut c_void) -> bool {
    let data = cbdata.cast::<ConstructData>();
    // SAFETY: `cbdata` is a live `ConstructData` per the caller's contract.
    no_store != 0 && unsafe { (*data).force_store } == 0
}

/// `static int ossl_method_construct_reserve_store(int no_store, void *cbdata)`.
///
/// Three things in four lines, and the order matters. A temporary store is obtained **once** —
/// the `data->store == NULL` test guards the `mcm->get_tmp_store` call, and the walk calls this
/// function once per map, so without the guard a caller would be handed a fresh temporary store
/// per operation. Then the store is locked, whichever it is. And the answer is the lock's, not
/// the get's: a get that succeeded and a lock that failed is a refusal.
///
/// The frozen `mcm->get_tmp_store` call is dereferenced unconditionally, as the authority's is:
/// a NULL `mcm` is a caller error on both sides rather than a checked refusal here, and the
/// sibling `algorithm.rs` transcribes `algorithm_do_map`'s `reserve_store` call the same way.
///
/// # Safety
/// `cbdata` must be a live `ConstructData` whose `mcm` is live.
unsafe extern "C" fn ossl_method_construct_reserve_store(
    no_store: c_int,
    cbdata: *mut c_void,
) -> c_int {
    let data = cbdata.cast::<ConstructData>();
    // SAFETY: `cbdata` is a live `ConstructData` whose `mcm` and `mcm_data` are the caller's,
    // per the contract.
    unsafe {
        if is_temporary_method_store(no_store, cbdata) && (*data).store.is_null() {
            (*data).store = ((*(*data).mcm).get_tmp_store)((*data).mcm_data);
            if (*data).store.is_null() {
                return 0;
            }
        }
        ((*(*data).mcm).lock_store)((*data).store, (*data).mcm_data)
    }
}

/// `static int ossl_method_construct_unreserve_store(void *cbdata)`.
///
/// The unlock, with the store this file was given — which is NULL when no store was needed and
/// the `mcm`'s own no-op territory.
///
/// # Safety
/// `cbdata` must be a live `ConstructData` whose `mcm` is live.
unsafe extern "C" fn ossl_method_construct_unreserve_store(cbdata: *mut c_void) -> c_int {
    let data = cbdata.cast::<ConstructData>();
    // SAFETY: `cbdata` is live per the contract, so `mcm` and `mcm_data` are the caller's.
    unsafe { ((*(*data).mcm).unlock_store)((*data).store, (*data).mcm_data) }
}

/// `static int ossl_method_construct_precondition(OSSL_PROVIDER *provider, int operation_id,
/// int no_store, void *cbdata, int *result)`.
///
/// **The answer is inverted on purpose**, and that inversion is the mechanism described in the
/// module note: the bit says whether construction has *happened*, and the walk needs to know
/// whether it *should*.
///
/// The NULL check on `result` is `ossl_assert` plus an `ERR_raise`, which in this build is
/// **non-fatal** — so a NULL `result` raises and returns 0 rather than aborting, and 0 from a
/// precondition is the *error* case in `algorithm_do_map`, which quits the walk. The crate's
/// `ossl_assert` is `(x) != 0` under `NDEBUG` and each site reproduces it; this one is written
/// as the refusal because that is what the authority's `if` does.
///
/// # Safety
/// `provider` live, `cbdata` a live `ConstructData`, `result` NULL or writable for a `c_int`.
unsafe extern "C" fn ossl_method_construct_precondition(
    provider: *mut OsslProvider,
    operation_id: c_int,
    no_store: c_int,
    cbdata: *mut c_void,
    result: *mut c_int,
) -> c_int {
    if result.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::CORE_FETCH_65) };
        return 0;
    }
    // SAFETY: `result` is non-NULL and writable per the contract.
    unsafe { *result = 0 };

    // SAFETY: `cbdata` is live, so the predicate's contract is the caller's.
    if !unsafe { is_temporary_method_store(no_store, cbdata) } {
        // SAFETY: `provider` is live and `result` is this frame's own writable slot.
        if unsafe { ossl_provider_test_operation_bit(provider, operation_id as usize, result) } == 0
        {
            return 0;
        }
    }

    // SAFETY: `result` is non-NULL and writable per the contract; the value read is the one
    // just written above or by `ossl_provider_test_operation_bit`, which is the authority's
    // `!*result`.
    unsafe { *result = c_int::from(*result == 0) };
    1
}

/// `static int ossl_method_construct_postcondition(OSSL_PROVIDER *provider, int operation_id,
/// int no_store, void *cbdata, int *result)`.
///
/// Sets the bit the precondition tests, so the next fetch of the same operation skips this
/// provider entirely — and **the answer is the short-circuit's**: a temporary store answers 1
/// without touching the provider, because a store with no bits has nothing to mark and the walk
/// must still continue.
///
/// # Safety
/// `provider` live, `cbdata` a live `ConstructData`, `result` NULL or writable for a `c_int`.
unsafe extern "C" fn ossl_method_construct_postcondition(
    provider: *mut OsslProvider,
    operation_id: c_int,
    no_store: c_int,
    cbdata: *mut c_void,
    result: *mut c_int,
) -> c_int {
    if result.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::CORE_FETCH_92) };
        return 0;
    }
    // SAFETY: `result` is non-NULL and writable per the contract. The authority writes 1
    // before deciding, so a caller reading it after a failed `set_operation_bit` still sees a
    // success -- which is the shape of the code and not an oversight to tidy.
    unsafe { *result = 1 };

    // SAFETY: `cbdata` is live.
    if unsafe { is_temporary_method_store(no_store, cbdata) } {
        return 1;
    }
    // SAFETY: `provider` is live.
    unsafe { ossl_provider_set_operation_bit(provider, operation_id as usize) }
}

/// `static void ossl_method_construct_this(OSSL_PROVIDER *provider, const OSSL_ALGORITHM *algo,
/// int no_store, void *cbdata)`.
///
/// One algorithm: construct, put, and **drop the reference the construction left**. The authority
/// asserts the contract in a comment — the `put` function is expected to increment the refcount —
/// so the destruct here is the matching decrement and not an error path.
///
/// The one branch that is not a call is the `construct` refusal: a method that could not be built
/// is skipped silently, with no error and no put, because a provider may legitimately publish an
/// algorithm this build cannot instantiate and that is not a failure of the walk.
///
/// # Safety
/// `provider` live, `algo` a live `OSSL_ALGORITHM`, `cbdata` a live `ConstructData` whose `mcm`
/// is live.
unsafe extern "C" fn ossl_method_construct_this(
    provider: *mut OsslProvider,
    algo: *const OsslAlgorithm,
    no_store: c_int,
    cbdata: *mut c_void,
) {
    let data = cbdata.cast::<ConstructData>();
    // SAFETY: `cbdata` is live per the contract, so `mcm`, `mcm_data` and `store` are the
    // caller's, and `algo` is live; `mcm->construct` is dereferenced unconditionally because the
    // authority's is.
    let method = unsafe { ((*(*data).mcm).construct)(algo, provider, (*data).mcm_data) };
    if method.is_null() {
        return;
    }

    // SAFETY: as above, with `method` the object just constructed and the two string fields the
    // algorithm's own, which outlive the call.
    unsafe {
        ((*(*data).mcm).put)(
            if no_store != 0 {
                (*data).store
            } else {
                ptr::null_mut()
            },
            method,
            provider,
            (*algo).algorithm_names,
            (*algo).property_definition,
            (*data).mcm_data,
        );
        // The matching decrement for the reference `construct` took. See the module note: the
        // store's reference is what survives, and skipping this leaks one per algorithm.
        ((*(*data).mcm).destruct)(method, (*data).mcm_data);
    }
}

/// `void *ossl_method_construct(OSSL_LIB_CTX *libctx, int operation_id,
/// OSSL_PROVIDER **provider_rw, int force_store, OSSL_METHOD_CONSTRUCT_METHOD *mcm,
/// void *mcm_data)`.
///
/// Walk, then look in the temporary store, then in the global one. The authority's own comment
/// explains why the *lookup* does not happen first: a query with optional properties can be
/// matched better by a provider loaded since, so the walk runs and the pre/postcondition pair is
/// what keeps it cheap.
///
/// `provider_rw` is both an input and an output: a caller may name the provider to walk, and the
/// successful `mcm->get` writes back **which** provider the method came from. That is why the
/// store lookups take `(const OSSL_PROVIDER **)` rather than a provider value — and why the
/// pointer is passed through rather than copied out here.
///
/// # Safety
/// `libctx` NULL or live; `provider_rw` NULL or pointing at a NULL-or-live provider; `mcm` live
/// with every entry point valid; `mcm_data` opaque to this file.
///
/// `pub(crate)` and not `#[no_mangle]`, for `ossl_algorithm_do_all`'s reason: the authority's name
/// is a global C symbol, libcrypto's version script hides it from the DSO, and its only caller is
/// `crypto/evp/evp_fetch.c`'s `inner_evp_generic_fetch`, which is **7.2's** and is not written
/// yet. Until it is, nothing in this crate calls this function, which is why it carries a
/// dead-code allowance rather than an export.
#[allow(dead_code)] // unreachable until 7.2's `inner_evp_generic_fetch` calls it
pub(crate) unsafe extern "C" fn ossl_method_construct(
    libctx: *mut c_void,
    operation_id: c_int,
    provider_rw: *mut *mut OsslProvider,
    force_store: c_int,
    mcm: *const OsslMethodConstructMethod,
    mcm_data: *mut c_void,
) -> *mut c_void {
    // SAFETY: `provider_rw` is NULL or points at a provider per the contract.
    let provider = if provider_rw.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: non-NULL here, so it points at a provider, which this reads.
        unsafe { *provider_rw }
    };

    let mut cbdata = ConstructData {
        libctx,
        store: ptr::null_mut(),
        operation_id,
        force_store,
        mcm,
        mcm_data,
    };
    let cbptr: *mut c_void = ptr::addr_of_mut!(cbdata).cast::<c_void>();

    // SAFETY: every argument is passed through to `ossl_algorithm_do_all`, whose contract is
    // this function's; the five callbacks are this module's own and each documents what it
    // needs, which is a live `ConstructData` -- `cbptr` is exactly that.
    unsafe {
        ossl_algorithm_do_all(
            libctx,
            operation_id,
            provider,
            Some(ossl_method_construct_precondition as AlgorithmPreFn),
            ossl_method_construct_reserve_store as AlgorithmReserveStoreFn,
            ossl_method_construct_this as AlgorithmFn,
            ossl_method_construct_unreserve_store as AlgorithmUnreserveStoreFn,
            Some(ossl_method_construct_postcondition as AlgorithmPostFn),
            cbptr,
        );
    }

    // The temporary store first, if the walk made one. `provider_rw` is written through by the
    // get, which is how a caller learns which provider the method came from.
    let mut method: *mut c_void = ptr::null_mut();
    if !cbdata.store.is_null() {
        // SAFETY: `cbdata.store` is the store the caller's own `get_tmp_store` produced, so it is
        // the caller's own to read, and `provider_rw` is the pointer this function was given.
        method = unsafe {
            ((*mcm).get)(
                cbdata.store,
                provider_rw.cast::<*const OsslProvider>(),
                mcm_data,
            )
        };
    }

    if method.is_null() {
        // NULL is how the `mcm` names "the global store": no store object is passed at all.
        // SAFETY: as above, with a NULL store, which is the interface's own spelling and not a
        // missing argument.
        method = unsafe {
            ((*mcm).get)(
                ptr::null_mut(),
                provider_rw.cast::<*const OsslProvider>(),
                mcm_data,
            )
        };
    }

    method
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::err::ERR_peek_last_error_all;
    use core::ffi::CStr;
    use core::sync::atomic::{AtomicI32, Ordering};

    /// The observation record a test's `mcm` writes into. One static set, because these are C
    /// callbacks and cannot capture.
    static SAW: [AtomicI32; 10] = [
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
    ];
    const GET_TMP: usize = 0;
    const LOCK: usize = 1;
    const UNLOCK: usize = 2;
    const GET: usize = 3;
    const PUT_STORE: usize = 4;
    const PUT_NULL: usize = 5;
    const CONSTRUCT: usize = 6;
    const DESTRUCT: usize = 7;
    /// The `store` argument the last `put` saw, so the `no_store ? store : NULL` choice is
    /// observable rather than inferred from which counter moved.
    static LAST_PUT_STORE: AtomicI32 = AtomicI32::new(-1);
    /// A distinguished non-NULL address standing in for a temporary store and a method.
    static TMP_STORE: AtomicI32 = AtomicI32::new(0);
    static METHOD: AtomicI32 = AtomicI32::new(0);

    fn reset() {
        for s in &SAW {
            s.store(0, Ordering::SeqCst);
        }
        LAST_PUT_STORE.store(-1, Ordering::SeqCst);
    }

    fn store_ptr() -> *mut c_void {
        TMP_STORE.load(Ordering::SeqCst) as *mut c_void
    }

    fn method_ptr() -> *mut c_void {
        METHOD.load(Ordering::SeqCst) as *mut c_void
    }

    unsafe extern "C" fn get_tmp_store(_data: *mut c_void) -> *mut c_void {
        SAW[GET_TMP].fetch_add(1, Ordering::SeqCst);
        store_ptr()
    }

    unsafe extern "C" fn lock_store(store: *mut c_void, _data: *mut c_void) -> c_int {
        SAW[LOCK].fetch_add(1, Ordering::SeqCst);
        LAST_PUT_STORE.store(store as usize as i32, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn unlock_store(_store: *mut c_void, _data: *mut c_void) -> c_int {
        SAW[UNLOCK].fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn get(
        store: *mut c_void,
        _prov: *const *const OsslProvider,
        _data: *mut c_void,
    ) -> *mut c_void {
        SAW[GET].fetch_add(1, Ordering::SeqCst);
        // A method answers from the temporary store only; the global store answers NULL, which
        // is what the "try the global store second" branch is observable through.
        if store.is_null() {
            ptr::null_mut()
        } else {
            method_ptr()
        }
    }

    unsafe extern "C" fn put(
        store: *mut c_void,
        _method: *mut c_void,
        _prov: *const OsslProvider,
        _name: *const c_char,
        _propdef: *const c_char,
        _data: *mut c_void,
    ) -> c_int {
        if store.is_null() {
            SAW[PUT_NULL].fetch_add(1, Ordering::SeqCst);
        } else {
            SAW[PUT_STORE].fetch_add(1, Ordering::SeqCst);
        }
        1
    }

    unsafe extern "C" fn construct(
        _algo: *const OsslAlgorithm,
        _prov: *mut OsslProvider,
        _data: *mut c_void,
    ) -> *mut c_void {
        SAW[CONSTRUCT].fetch_add(1, Ordering::SeqCst);
        method_ptr()
    }

    unsafe extern "C" fn destruct(_method: *mut c_void, _data: *mut c_void) {
        SAW[DESTRUCT].fetch_add(1, Ordering::SeqCst);
    }

    fn mcm() -> OsslMethodConstructMethod {
        OsslMethodConstructMethod {
            get_tmp_store,
            lock_store,
            unlock_store,
            get,
            put,
            construct,
            destruct,
        }
    }

    /// `is_temporary_method_store` is `no_store && !force_store`, and both halves are needed:
    /// `force_store` alone turns a temporary request into a permanent one, which is how a caller
    /// that must cache says so.
    #[test]
    fn temporary_is_no_store_and_not_force_store() {
        let mut plain = ConstructData {
            libctx: ptr::null_mut(),
            store: ptr::null_mut(),
            operation_id: 0,
            force_store: 0,
            mcm: ptr::null(),
            mcm_data: ptr::null_mut(),
        };
        let p: *mut c_void = ptr::addr_of_mut!(plain).cast::<c_void>();
        // SAFETY: `p` is this frame's own live `ConstructData`, which is the predicate's
        // whole contract.
        let no_store = unsafe { is_temporary_method_store(1, p) };
        // SAFETY: as above.
        let not_no_store = unsafe { is_temporary_method_store(0, p) };
        assert!(no_store, "no_store and no force");
        assert!(!not_no_store, "not no_store");

        let mut forced = ConstructData {
            libctx: ptr::null_mut(),
            store: ptr::null_mut(),
            operation_id: 0,
            force_store: 1,
            mcm: ptr::null(),
            mcm_data: ptr::null_mut(),
        };
        let pf: *mut c_void = ptr::addr_of_mut!(forced).cast::<c_void>();
        // SAFETY: as above.
        let forced_answers = unsafe { is_temporary_method_store(1, pf) };
        assert!(!forced_answers, "force_store wins");
    }

    /// The temporary store is obtained **once**, however many maps the walk visits. Without the
    /// `store == NULL` guard a caller would be handed a fresh store per operation, and the
    /// methods constructed for the first operation would be invisible to the second.
    #[test]
    fn the_temporary_store_is_obtained_once() {
        reset();
        TMP_STORE.store(0x1000, Ordering::SeqCst);
        let m = mcm();
        let mut data = ConstructData {
            libctx: ptr::null_mut(),
            store: ptr::null_mut(),
            operation_id: 0,
            force_store: 0,
            mcm: ptr::addr_of!(m),
            mcm_data: ptr::null_mut(),
        };
        let p: *mut c_void = ptr::addr_of_mut!(data).cast::<c_void>();
        for _ in 0..3 {
            // SAFETY: `p` is this frame's own live `ConstructData` whose `mcm` is `m`'s.
            let got = unsafe { ossl_method_construct_reserve_store(1, p) };
            assert_eq!(got, 1);
        }
        assert_eq!(SAW[GET_TMP].load(Ordering::SeqCst), 1, "obtained once");
        assert_eq!(SAW[LOCK].load(Ordering::SeqCst), 3, "locked every time");
        assert_eq!(data.store, store_ptr());
    }

    /// A permanent store is never asked for a temporary one, and the store argument stays NULL
    /// so that `lock_store`/`unlock_store` see the "global store" spelling rather than a store
    /// object they were not given.
    #[test]
    fn a_permanent_store_is_not_obtained_and_is_passed_as_null() {
        reset();
        TMP_STORE.store(0x1000, Ordering::SeqCst);
        let m = mcm();
        let mut data = ConstructData {
            libctx: ptr::null_mut(),
            store: ptr::null_mut(),
            operation_id: 0,
            force_store: 0,
            mcm: ptr::addr_of!(m),
            mcm_data: ptr::null_mut(),
        };
        let p: *mut c_void = ptr::addr_of_mut!(data).cast::<c_void>();
        // SAFETY: `p` is this frame's own live `ConstructData` whose `mcm` is `m`'s.
        let reserved = unsafe { ossl_method_construct_reserve_store(0, p) };
        assert_eq!(reserved, 1);
        assert_eq!(SAW[GET_TMP].load(Ordering::SeqCst), 0);
        assert_eq!(data.store, ptr::null_mut());
        // SAFETY: as above.
        let released = unsafe { ossl_method_construct_unreserve_store(p) };
        assert_eq!(released, 1);
        assert_eq!(SAW[UNLOCK].load(Ordering::SeqCst), 1);
    }

    /// `this` puts into the store **only when `no_store` is set**, and drops the reference the
    /// construction took either way. Both halves are asserted, because the reference count is
    /// what leaks if only one of them is written.
    #[test]
    fn this_puts_only_into_a_temporary_store_and_always_destructs() {
        reset();
        TMP_STORE.store(0x1000, Ordering::SeqCst);
        METHOD.store(0x2000, Ordering::SeqCst);
        let algo = OsslAlgorithm {
            algorithm_names: c"SHA256".as_ptr(),
            property_definition: c"provider=default".as_ptr(),
            implementation: ptr::null(),
            algorithm_description: ptr::null(),
        };
        let m = mcm();

        // `no_store` set: the method goes to the store the caller was given.
        let mut temporary = ConstructData {
            libctx: ptr::null_mut(),
            store: store_ptr(),
            operation_id: 0,
            force_store: 0,
            mcm: ptr::addr_of!(m),
            mcm_data: ptr::null_mut(),
        };
        let pt: *mut c_void = ptr::addr_of_mut!(temporary).cast::<c_void>();
        // SAFETY: `pt` is this frame's own live `ConstructData` whose `mcm` is `m`'s, and
        // `algo` is this frame's own live `OSSL_ALGORITHM`.
        unsafe { ossl_method_construct_this(ptr::null_mut(), &algo, 1, pt) };
        assert_eq!(
            SAW[PUT_STORE].load(Ordering::SeqCst),
            1,
            "temporary: with the store"
        );
        assert_eq!(SAW[PUT_NULL].load(Ordering::SeqCst), 0);
        assert_eq!(
            SAW[DESTRUCT].load(Ordering::SeqCst),
            1,
            "the reference construct took is dropped in this arm too"
        );

        // `no_store` clear: the put is handed a NULL store, which is the interface's name for
        // "the global one" rather than a missing argument.
        reset();
        let mut permanent = ConstructData {
            libctx: ptr::null_mut(),
            store: store_ptr(),
            operation_id: 0,
            force_store: 0,
            mcm: ptr::addr_of!(m),
            mcm_data: ptr::null_mut(),
        };
        let pp: *mut c_void = ptr::addr_of_mut!(permanent).cast::<c_void>();
        // SAFETY: as above.
        unsafe { ossl_method_construct_this(ptr::null_mut(), &algo, 0, pp) };
        assert_eq!(
            SAW[PUT_NULL].load(Ordering::SeqCst),
            1,
            "permanent: NULL store"
        );
        assert_eq!(SAW[PUT_STORE].load(Ordering::SeqCst), 0);
        assert_eq!(
            SAW[DESTRUCT].load(Ordering::SeqCst),
            1,
            "the reference construct took is dropped, or one leaks per algorithm"
        );
    }

    /// A construction that refuses is **skipped silently**: no put, no destruct, no error. A
    /// provider may publish an algorithm this build cannot instantiate, and that is not a
    /// failure of the walk.
    #[test]
    fn a_refused_construction_is_skipped_without_putting_or_destructing() {
        reset();
        TMP_STORE.store(0x1000, Ordering::SeqCst);
        METHOD.store(0, Ordering::SeqCst); // construct answers NULL
        let algo = OsslAlgorithm {
            algorithm_names: c"SHA256".as_ptr(),
            property_definition: ptr::null(),
            implementation: ptr::null(),
            algorithm_description: ptr::null(),
        };
        let m = mcm();
        let mut data = ConstructData {
            libctx: ptr::null_mut(),
            store: store_ptr(),
            operation_id: 0,
            force_store: 0,
            mcm: ptr::addr_of!(m),
            mcm_data: ptr::null_mut(),
        };
        let p: *mut c_void = ptr::addr_of_mut!(data).cast::<c_void>();
        // SAFETY: `p` is this frame's own live `ConstructData` whose `mcm` is `m`'s, and
        // `algo` is this frame's own live `OSSL_ALGORITHM`.
        unsafe { ossl_method_construct_this(ptr::null_mut(), &algo, 1, p) };
        assert_eq!(SAW[CONSTRUCT].load(Ordering::SeqCst), 1, "it was asked");
        assert_eq!(SAW[PUT_STORE].load(Ordering::SeqCst), 0, "and not stored");
        assert_eq!(
            SAW[DESTRUCT].load(Ordering::SeqCst),
            0,
            "and nothing to release"
        );
        METHOD.store(0x2000, Ordering::SeqCst);
    }

    /// The coordinate of the **last** error raised, against a recorded site: the three strings a
    /// caller reads back through `ERR_get_error_all`. A test that asserted only the returned
    /// code would pass on a transcription that raised from the wrong file, which is exactly the
    /// mistake D98's family is about.
    ///
    /// The *last* rather than the first, because a test that raises twice in a row would
    /// otherwise compare the second site against the first error still sitting in the queue.
    fn assert_coordinate(site: &err_sites::ErrSite) {
        let mut file: *const c_char = ptr::null();
        let mut line: c_int = 0;
        let mut func: *const c_char = ptr::null();
        let mut data: *const c_char = ptr::null();
        let mut flags: c_int = 0;
        // SAFETY: every output pointer is this frame's own storage, writable for its type; a
        // NULL for any of them is also accepted, which is what `data` relies on here.
        let code = unsafe {
            ERR_peek_last_error_all(&mut file, &mut line, &mut func, &mut data, &mut flags)
        };
        assert_ne!(code, 0, "an error was raised");
        // SAFETY: the call above wrote a NUL-terminated string the error state still owns.
        assert_eq!(unsafe { CStr::from_ptr(file) }, site.file, "file");
        assert_eq!(line, site.line, "line");
        // SAFETY: as above.
        assert_eq!(unsafe { CStr::from_ptr(func) }, site.func, "function");
    }

    /// **A NULL `result` refuses at the authority's own coordinate.** This is the arm where
    /// `ossl_assert` and the `ERR_raise` disagree about severity: the assertion is
    /// `(x) != 0` under `NDEBUG` and therefore does nothing, so the raise is the whole of what
    /// a caller sees — and the coordinate is the observable, not the refusal.
    #[test]
    fn a_null_result_is_refused_at_the_authority_coordinate() {
        reset();
        let mut data = ConstructData {
            libctx: ptr::null_mut(),
            store: ptr::null_mut(),
            operation_id: 0,
            force_store: 0,
            mcm: ptr::null(),
            mcm_data: ptr::null_mut(),
        };
        let p: *mut c_void = ptr::addr_of_mut!(data).cast::<c_void>();

        // The provider is NULL on purpose: a NULL `result` is returned from *before* the
        // provider is touched, which is what makes this arm reachable without one.
        // SAFETY: `p` is this frame's own live `ConstructData`; the provider is NULL and is
        // never reached on this arm, and the `result` output is NULL, which the callee allows.
        let refused = unsafe {
            ossl_method_construct_precondition(ptr::null_mut(), 0, 0, p, ptr::null_mut())
        };
        assert_eq!(refused, 0);
        assert_coordinate(&err_sites::CORE_FETCH_65);

        // SAFETY: as above, with the postcondition's own coordinate.
        let refused_post = unsafe {
            ossl_method_construct_postcondition(ptr::null_mut(), 0, 0, p, ptr::null_mut())
        };
        assert_eq!(refused_post, 0);
        assert_coordinate(&err_sites::CORE_FETCH_92);
    }

    /// **The precondition's answer is inverted, and a temporary store skips the provider.**
    /// `*result` goes in as 1 — "methods have already been constructed" — and comes out as 1 —
    /// "construction should happen", because the two are opposite questions. And with a
    /// temporary store the provider's operation bit is not consulted at all, which is the only
    /// reason this function is callable with a NULL provider.
    #[test]
    fn a_temporary_store_inverts_the_answer_without_asking_the_provider() {
        reset();
        let mut data = ConstructData {
            libctx: ptr::null_mut(),
            store: ptr::null_mut(),
            operation_id: 0,
            force_store: 0,
            mcm: ptr::null(),
            mcm_data: ptr::null_mut(),
        };
        let p: *mut c_void = ptr::addr_of_mut!(data).cast::<c_void>();
        let mut result: c_int = 1;
        // `no_store` set and `force_store` clear: a temporary store, so the provider is not
        // consulted and a NULL one is therefore safe to pass.
        // SAFETY: `p` is this frame's own live `ConstructData`, `result` is this frame's own
        // writable slot, and a NULL provider is unreachable on the temporary-store arm.
        let asked =
            unsafe { ossl_method_construct_precondition(ptr::null_mut(), 0, 1, p, &mut result) };
        assert_eq!(asked, 1);
        assert_eq!(result, 1, "*result was set to 0 and then inverted");

        // The postcondition answers 1 for a temporary store and writes 1 into `*result`, again
        // without touching a provider -- a store with no bits has nothing to mark.
        let mut post_result: c_int = 0;
        // SAFETY: as above, with the postcondition's own output slot.
        let marked = unsafe {
            ossl_method_construct_postcondition(ptr::null_mut(), 0, 1, p, &mut post_result)
        };
        assert_eq!(marked, 1);
        assert_eq!(post_result, 1);
    }
}
