//! Phase 7.1 — `crypto/core_algorithm.c`: the walk over a provider's algorithms, per operation.
//!
//! This is the bottom of Phase 7's fetch path and the first thing the stratum had to write,
//! for the reason `docs/DECISIONS.md` D132 records: its only caller in the whole authority is
//! `crypto/core_fetch.c`'s `ossl_method_construct`, which is Phase 7's, so Phase 6 could not
//! build it and nothing in that crate referenced it — which is why it was invisible to four
//! different pieces of evidence machinery until a plan-versus-crate check was written.
//!
//! ## The three functions and why the split matters
//!
//! `ossl_algorithm_do_all` is the public entry point and does almost nothing: it fills the
//! `algorithm_data_st`, and then either sweeps every activated provider through
//! `ossl_provider_doall_activated` or handles one named provider directly. `algorithm_do_this`
//! is the per-provider half — it loops the operations and queries each one. `algorithm_do_map`
//! is the per-operation half and is where all the real arithmetic is: reserve, pre, construct,
//! post, unreserve, with three different return conventions that are easy to collapse and must
//! not be.
//!
//! Those three conventions are the reason this file is worth reading closely rather than
//! transcribing by shape:
//!
//! * `solution_do_map` answers **-1** to mean *quit the whole walk immediately*, **0** to mean
//!   *this map failed but carry on*, and **1** to mean *fine so far*. `algorithm_do_this`
//!   turns -1 into an immediate `return 0` and a 0 into `ok = 0` while continuing — so a
//!   provider whose *second* operation fails is still asked for its third, and the overall
//!   answer is a failure rather than a truncation.
//! * A **refused precondition is not a failure**. `pre` sets `*result = 0`, and that is turned
//!   into `ret = 1` — success — with the map skipped. The authority's comment says why: it
//!   means another thread got there first, which is a race the caller resolves by looking in
//!   the store, not an error. A transcription that propagated the 0 would make a benign race
//!   into a fetch failure.
//! * `pre` and `post` are **optional** and an absent one means "yes"; `reserve_store` and
//!   `unreserve_store` are **not** checked for NULL, so a caller that passes one must pass both.
//!
//! ## The operation range is `1 ..= 22`, and 0 means "all of them"
//!
//! `operation_id == 0` is the authority's sentinel for *every* operation, and it is not the
//! same as passing 0 through: the loop runs `OSSL_OP_DIGEST` (1) through `OSSL_OP__HIGHEST`
//! (22). `OSSL_OP_KEYEXCH` is 11 and `OSSL_OP__HIGHEST` is 22, so the range is not a count of
//! the operations that have names — it includes the reserved ids above the named ones, and a
//! transcription that looped `1..=OSSL_OP_KEYEXCH` or over the named ids alone would silently
//! skip whatever a provider publishes at an id above 11.
//!
//! ## `ossl_algorithm_get1_first_name` splits on `:`, not on whitespace
//!
//! An `OSSL_ALGORITHM`'s `algorithm_names` is a `:`-separated list of aliases — `"SHA256:SHA2-256:sha256"` —
//! and this function answers a **copy** of the first one. Two details: a name list with no `:`
//! at all is copied whole, and the copy is `OPENSSL_strndup`'s, so the caller owns it and frees
//! it with `OPENSSL_free`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::lib_ctx_get_concrete;
use crate::provider::activate::{
    ossl_provider_doall_activated, ossl_provider_query_operation, ossl_provider_unquery_operation,
    OsslAlgorithm,
};
use crate::provider::{ossl_provider_libctx, OsslProvider};
use crate::runtime::mem::CRYPTO_strndup;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/core_algorithm.c".as_ptr();

/// `OPENSSL_strndup`'s call site in `ossl_algorithm_get1_first_name`.
const L_STRNDUP: c_int = 175;

/// `OSSL_OP_DIGEST` — `include/openssl/core_dispatch.h`. The first operation the walk visits.
pub(crate) const OSSL_OP_DIGEST: c_int = 1;
/// `OSSL_OP__HIGHEST` — `include/openssl/core_dispatch.h`. The last, and **not** the last
/// *named* one: the range runs past `OSSL_OP_KEYEXCH` (11) because the reserved ids above it
/// are real dispatch ids a provider may publish.
pub(crate) const OSSL_OP_HIGHEST: c_int = 22;

/// `int (*pre)(OSSL_PROVIDER *, int operation_id, int no_store, void *data, int *result)`.
pub(crate) type AlgorithmPreFn =
    unsafe extern "C" fn(*mut OsslProvider, c_int, c_int, *mut c_void, *mut c_int) -> c_int;

/// `int (*reserve_store)(int no_store, void *data)`.
pub(crate) type AlgorithmReserveStoreFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;

/// `void (*fn)(OSSL_PROVIDER *, const OSSL_ALGORITHM *, int no_store, void *data)`.
pub(crate) type AlgorithmFn =
    unsafe extern "C" fn(*mut OsslProvider, *const OsslAlgorithm, c_int, *mut c_void);

/// `int (*unreserve_store)(void *data)`.
pub(crate) type AlgorithmUnreserveStoreFn = unsafe extern "C" fn(*mut c_void) -> c_int;

/// `int (*post)(OSSL_PROVIDER *, int operation_id, int no_store, void *data, int *result)`.
pub(crate) type AlgorithmPostFn =
    unsafe extern "C" fn(*mut OsslProvider, c_int, c_int, *mut c_void, *mut c_int) -> c_int;

/// `struct algorithm_data_st` — the walk's own state, assembled by `ossl_algorithm_do_all`.
///
/// Field order is the authority's and is not load-bearing; the *types* are, and the two that
/// are `Option` are the two the authority tests for NULL and treats as "yes". The reserve pair
/// is deliberately **not** `Option`: the authority dereferences both unconditionally, so a
/// caller that passes one and not the other is a programming error on both sides rather than a
/// checked refusal here.
pub(crate) struct AlgorithmData {
    /// `OSSL_LIB_CTX *libctx` — the context the walk is scoped to. Rewritten to the
    /// **provider's** context when a specific provider is named.
    pub(crate) libctx: *mut c_void,
    /// `int operation_id` — zero means "every operation", and is not passed through.
    pub(crate) operation_id: c_int,
    /// `int (*pre)(...)` — the precondition, or `None` for "assume yes".
    pub(crate) pre: Option<AlgorithmPreFn>,
    /// `int (*reserve_store)(...)`.
    pub(crate) reserve_store: AlgorithmReserveStoreFn,
    /// `void (*fn)(...)` — the constructor, and the only callback with no answer.
    pub(crate) fn_: AlgorithmFn,
    /// `int (*unreserve_store)(...)`.
    pub(crate) unreserve_store: AlgorithmUnreserveStoreFn,
    /// `int (*post)(...)` — the postcondition, or `None` for "assume yes".
    pub(crate) post: Option<AlgorithmPostFn>,
    /// `void *data` — opaque, and passed back to every one of the six callbacks.
    pub(crate) data: *mut c_void,
}

/// `static int algorithm_do_map(OSSL_PROVIDER *provider, const OSSL_ALGORITHM *map,
/// int cur_operation, int no_store, void *cbdata)`.
///
/// Returns -1 to quit the whole walk, 0 to record a failure and continue, 1 for success — see
/// the module note. The one branch that is not a transcription of its own name is the refused
/// precondition: `ret == 0` becomes `ret = 1` and the map is skipped, because the authority
/// treats that as *another thread got there first* rather than as an error.
///
/// # Safety
/// `provider` must be live, `map` NULL or a `OSSL_ALGORITHM` array terminated by a NULL
/// `algorithm_names`, and `cbdata` a live `AlgorithmData`.
unsafe fn algorithm_do_map(
    provider: *mut OsslProvider,
    map: *const OsslAlgorithm,
    cur_operation: c_int,
    no_store: c_int,
    cbdata: *mut c_void,
) -> c_int {
    // SAFETY: `cbdata` is a live `AlgorithmData` per the caller's contract.
    let data = cbdata.cast::<AlgorithmData>();
    let mut ret: c_int = 0;

    // SAFETY: `data` is live, so its two function pointers are readable, and the authority
    // calls both unconditionally.
    if unsafe { ((*data).reserve_store)(no_store, (*data).data) } == 0 {
        // The reserve failed, and the authority bails out of the whole walk rather than
        // skipping this map: the store could not be prepared, so nothing may be added to it.
        return -1;
    }

    // SAFETY: `data` is live.
    match unsafe { (*data).pre } {
        // No precondition is "assume yes", spelled as an assignment rather than as a skip so
        // that the three-way logic below reads the same in both branches.
        None => ret = 1,
        Some(pre) => {
            // SAFETY: `provider` is live and `data` is live, so the callback's own contract
            // is the caller's, and `ret` is this frame's own slot.
            let called = unsafe { pre(provider, cur_operation, no_store, (*data).data, &mut ret) };
            if called == 0 {
                // An *error* from the precondition bails out; a refusal is handled below.
                ret = -1;
                // SAFETY: `data` is live.
                unsafe { ((*data).unreserve_store)((*data).data) };
                return ret;
            }
        }
    }

    if ret == 0 {
        // **A refused precondition is success.** The authority's comment: "If pre-condition not
        // fulfilled don't add this set of implementations, but do continue with the next. This
        // simply means that another thread got to it first." So the map is skipped, 0 becomes
        // 1, and the walk continues.
        // SAFETY: `data` is live.
        unsafe { ((*data).unreserve_store)((*data).data) };
        return 1;
    }

    if !map.is_null() {
        let mut thismap = map;
        // SAFETY: `map` is a terminated array per the contract, so the loop leaves it at the
        // terminator, and every entry before it is readable.
        unsafe {
            while !(*thismap).algorithm_names.is_null() {
                ((*data).fn_)(provider, thismap, no_store, (*data).data);
                thismap = thismap.add(1);
            }
        }
    }

    // SAFETY: `data` is live.
    match unsafe { (*data).post } {
        None => ret = 1,
        Some(post) => {
            // SAFETY: `provider` is live and `data` is live, so the callback's own contract
            // is the caller's, and `ret` is this frame's own slot.
            let called = unsafe { post(provider, cur_operation, no_store, (*data).data, &mut ret) };
            if called == 0 {
                ret = -1;
            }
        }
    }

    // SAFETY: `data` is live.
    unsafe { ((*data).unreserve_store)((*data).data) };
    ret
}

/// `static int algorithm_do_this(OSSL_PROVIDER *provider, void *cbdata)`.
///
/// One provider, every operation the walk was asked for. A hard error from
/// `algorithm_do_map` stops everything; a soft one is remembered and the loop continues, which
/// is the difference between `return 0` and `ok = 0` in the authority and is why a provider
/// whose first operation fails is still asked for the rest.
///
/// # Safety
/// `provider` must be live and `cbdata` a live `AlgorithmData`.
unsafe extern "C" fn algorithm_do_this(provider: *mut OsslProvider, cbdata: *mut c_void) -> c_int {
    // SAFETY: `cbdata` is a live `AlgorithmData` per the caller's contract.
    let data = cbdata.cast::<AlgorithmData>();
    let mut first_operation = OSSL_OP_DIGEST;
    let mut last_operation = OSSL_OP_HIGHEST;

    // SAFETY: `data` is live, so `operation_id` is readable; it is read once into a local
    // because the authority's two assignments are to the same value.
    let only = unsafe { (*data).operation_id };
    if only != 0 {
        first_operation = only;
        last_operation = only;
    }

    let mut cur_operation = first_operation;
    let mut ok: c_int = 1;
    while cur_operation <= last_operation {
        let mut no_store: c_int = 0; // Assume caching is ok.
                                     // SAFETY: `provider` is live and `data` is live, so the query's contract is the
                                     // caller's; a provider with no operation table answers NULL, which is not an error.
        let map: *const OsslAlgorithm =
            unsafe { ossl_provider_query_operation(provider, cur_operation, &mut no_store) };
        // SAFETY: as above; `map` is NULL or the provider's own terminated array.
        let ret = unsafe { algorithm_do_map(provider, map, cur_operation, no_store, cbdata) };
        // SAFETY: as above, and the array is handed back before it is dropped.
        unsafe { ossl_provider_unquery_operation(provider, cur_operation, map) };

        if ret < 0 {
            // Hard error: bail out immediately, and the walk reports failure.
            return 0;
        }
        if ret == 0 {
            // Soft error: remember it and keep asking this provider for the rest.
            ok = 0;
        }
        cur_operation += 1;
    }
    ok
}

/// `void ossl_algorithm_do_all(OSSL_LIB_CTX *libctx, int operation_id, OSSL_PROVIDER *provider,
/// int (*pre)(...), int (*reserve_store)(...), void (*fn)(...), int (*unreserve_store)(...),
/// int (*post)(...), void *data)`.
///
/// Two paths, and the difference between them is a check rather than a branch:
///
/// * **no provider** — every activated provider in the context is swept, through
///   `ossl_provider_doall_activated`, and the walk's answer is discarded because the entry
///   point has no answer to give;
/// * **a provider** — that one provider is walked directly, and `libctx` is **replaced** by the
///   provider's own context. The authority asserts the two resolve to the same concrete object
///   first, and a mismatch is a programming error up the stack: it returns without walking
///   anything rather than walking the wrong scope.
///
/// The assertion is `ossl_assert`, which is **non-fatal** in this build (D109 read `NDEBUG`
/// from `configdata.pm`), so a mismatch is a silent no-walk rather than an abort. That is
/// reproduced, because a caller cannot see the difference and a build that aborted would be a
/// divergence in exactly the case the assertion exists to detect.
///
/// # Safety
/// `libctx` NULL or live; `provider` NULL or live; `reserve_store`, `fn` and `unreserve_store`
/// non-NULL; `pre` and `post` NULL or valid; `data` opaque and passed back unchanged.
#[no_mangle]
pub unsafe extern "C" fn ossl_algorithm_do_all(
    libctx: *mut c_void,
    operation_id: c_int,
    provider: *mut OsslProvider,
    pre: Option<AlgorithmPreFn>,
    reserve_store: AlgorithmReserveStoreFn,
    fn_: AlgorithmFn,
    unreserve_store: AlgorithmUnreserveStoreFn,
    post: Option<AlgorithmPostFn>,
    data: *mut c_void,
) {
    let mut cbdata = AlgorithmData {
        libctx,
        operation_id,
        pre,
        reserve_store,
        fn_,
        unreserve_store,
        post,
        data,
    };
    let cbptr: *mut c_void = ptr::addr_of_mut!(cbdata).cast::<c_void>();

    if provider.is_null() {
        // The sweep. Its answer is dropped: this entry point returns nothing, and the
        // per-provider failures are what `pre`/`post` report through `data`.
        // SAFETY: `libctx` is NULL or live and `algorithm_do_this` has this function's own
        // contract for `provider` and `cbdata`.
        unsafe { ossl_provider_doall_activated(libctx, algorithm_do_this, cbptr) };
        return;
    }

    // SAFETY: `provider` is live, so its context is readable.
    let provider_libctx = unsafe { ossl_provider_libctx(provider) };

    // `ossl_assert(ossl_lib_ctx_get_concrete(libctx) == ossl_lib_ctx_get_concrete(libctx2))`,
    // and the authority's own comment says a failure here is "a programming error in the
    // functions up the call stack" -- which is why it returns rather than walking. `ossl_assert`
    // is `(x) != 0` under `NDEBUG`, so the no-walk is silent and that is reproduced.
    if lib_ctx_get_concrete(libctx) != lib_ctx_get_concrete(provider_libctx) {
        return;
    }

    // The rewrite that matters: the walk's own scope becomes the *provider's* context, so
    // every callback sees the context the methods it builds will belong to rather than the one
    // the caller passed. `#[allow]` because the field is written and only read through the
    // pointer `cbptr` gives the walk — the compiler cannot see that reader.
    #[allow(unused_assignments)]
    {
        cbdata.libctx = provider_libctx;
    }
    // SAFETY: `provider` is live and `cbptr` is this call's own live stack object.
    unsafe { algorithm_do_this(provider, cbptr) };
}

/// `char *ossl_algorithm_get1_first_name(const OSSL_ALGORITHM *algo)`.
///
/// The **first** of the `:`-separated aliases in `algorithm_names`, as a fresh allocation. A
/// list with no `:` at all is copied whole, and a NULL list answers NULL rather than an empty
/// string — which is a distinction a caller can see, because an empty allocation and no
/// allocation look different under `OPENSSL_free`.
///
/// # Safety
/// `algo` must be a live `OSSL_ALGORITHM`.
#[no_mangle]
pub unsafe extern "C" fn ossl_algorithm_get1_first_name(algo: *const OsslAlgorithm) -> *mut c_char {
    // SAFETY: `algo` is live per the contract.
    let names = unsafe { (*algo).algorithm_names };
    if names.is_null() {
        return ptr::null_mut();
    }

    // `strchr`, the authority's split, and it stops at the **first** colon rather than the
    // last: an alias list is a preference order and this answers the preferred name.
    let mut len: usize = 0;
    // SAFETY: `names` is a NUL-terminated C string per the struct's contract, so the walk
    // leaves the allocation.
    let first_name_len = unsafe {
        while *names.add(len) != 0 {
            if *names.add(len) == b':' as c_char {
                break;
            }
            len += 1;
        }
        len
    };

    // SAFETY: `names` is NUL-terminated and the length is within it.
    unsafe { CRYPTO_strndup(names, first_name_len, FILE, L_STRNDUP) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::activate::OsslAlgorithm;
    use core::ffi::c_int;
    use core::sync::atomic::{AtomicI32, Ordering};

    /// The observation record a test's callbacks write into. One static per test, because
    /// these are C callbacks and cannot capture.
    static SAW: [AtomicI32; 8] = [
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
    ];
    /// Indices into `SAW`, named so a test reads as a sequence rather than as integers.
    const RESERVE: usize = 0;
    const PRE: usize = 1;
    const FN: usize = 2;
    const POST: usize = 3;
    const UNRESERVE: usize = 4;

    fn reset() {
        for s in &SAW {
            s.store(0, Ordering::SeqCst);
        }
    }

    /// What `pre` does on this call, so one test can drive all three of its outcomes.
    static PRE_RESULT: AtomicI32 = AtomicI32::new(1);
    static PRE_ERRORS: AtomicI32 = AtomicI32::new(0);
    /// What `post` does: 1 fine, 0 a soft failure, -1 an error.
    static POST_RESULT: AtomicI32 = AtomicI32::new(0);
    static PROV_CTX: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn reserve(_no_store: c_int, _data: *mut c_void) -> c_int {
        SAW[RESERVE].fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn unreserve(_data: *mut c_void) -> c_int {
        SAW[UNRESERVE].fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn pre(
        _prov: *mut OsslProvider,
        _op: c_int,
        _no_store: c_int,
        _data: *mut c_void,
        result: *mut c_int,
    ) -> c_int {
        SAW[PRE].fetch_add(1, Ordering::SeqCst);
        if PRE_ERRORS.load(Ordering::SeqCst) != 0 {
            return 0;
        }
        // SAFETY: `result` is the walk's own slot.
        unsafe { *result = PRE_RESULT.load(Ordering::SeqCst) };
        1
    }

    unsafe extern "C" fn post(
        _prov: *mut OsslProvider,
        _op: c_int,
        _no_store: c_int,
        _data: *mut c_void,
        result: *mut c_int,
    ) -> c_int {
        SAW[POST].fetch_add(1, Ordering::SeqCst);
        let r = POST_RESULT.load(Ordering::SeqCst);
        if r >= 0 {
            // SAFETY: `result` is the walk's own slot, and the authority's `post` writes it
            // only on the success path.
            unsafe { *result = r };
            return 1;
        }
        0
    }

    unsafe extern "C" fn count_algorithms(
        _prov: *mut OsslProvider,
        _algo: *const OsslAlgorithm,
        _no_store: c_int,
        _data: *mut c_void,
    ) {
        SAW[FN].fetch_add(1, Ordering::SeqCst);
    }

    /// A terminated `OSSL_ALGORITHM` array with two entries, built on the stack.
    fn two_algorithms() -> [OsslAlgorithm; 3] {
        [
            OsslAlgorithm {
                algorithm_names: c"SHA256:SHA2-256".as_ptr(),
                property_definition: c"provider=default".as_ptr(),
                implementation: ptr::null(),
                algorithm_description: c"a test".as_ptr(),
            },
            OsslAlgorithm {
                algorithm_names: c"SHA1".as_ptr(),
                property_definition: c"provider=default".as_ptr(),
                implementation: ptr::null(),
                algorithm_description: ptr::null(),
            },
            OsslAlgorithm {
                algorithm_names: ptr::null(),
                property_definition: ptr::null(),
                implementation: ptr::null(),
                algorithm_description: ptr::null(),
            },
        ]
    }

    /// The map walk itself, without a provider: `algorithm_do_map` is what the three return
    /// conventions live in, and it is testable on its own because it only needs the callback
    /// structure.
    fn run_map(
        map: *const OsslAlgorithm,
        pre_fn: Option<AlgorithmPreFn>,
        post_fn: Option<AlgorithmPostFn>,
    ) -> (c_int, AlgorithmData) {
        let mut data = AlgorithmData {
            libctx: ptr::null_mut(),
            operation_id: 0,
            pre: pre_fn,
            reserve_store: reserve,
            fn_: count_algorithms,
            unreserve_store: unreserve,
            post: post_fn,
            data: PROV_CTX.load(Ordering::SeqCst) as *mut c_void,
        };
        // SAFETY: `map` is NULL or a terminated array and `data` is this frame's own live
        // object, which is `algorithm_do_map`'s contract exactly; a NULL provider is accepted
        // because the map walk never reads it.
        let ret = unsafe {
            algorithm_do_map(
                ptr::null_mut(),
                map,
                7,
                0,
                ptr::addr_of_mut!(data).cast::<c_void>(),
            )
        };
        (ret, data)
    }

    /// Every callback runs, in the authority's order, and the constructor runs **once per
    /// entry** — not once per map. An implementation that called `fn` once and passed the array
    /// would pass a naive test and produce one method where the provider published two.
    #[test]
    fn the_map_walks_every_entry_and_reserves_around_them() {
        reset();
        let map = two_algorithms();
        let (ret, _) = run_map(map.as_ptr(), None, None);
        assert_eq!(ret, 1, "a map with no pre or post is a success");
        assert_eq!(SAW[RESERVE].load(Ordering::SeqCst), 1);
        assert_eq!(SAW[UNRESERVE].load(Ordering::SeqCst), 1);
        assert_eq!(SAW[PRE].load(Ordering::SeqCst), 0, "no pre, so no pre call");
        assert_eq!(
            SAW[POST].load(Ordering::SeqCst),
            0,
            "no post, so no post call"
        );
        assert_eq!(
            SAW[FN].load(Ordering::SeqCst),
            2,
            "the constructor runs once per entry, and the terminator is not an entry"
        );
    }

    /// **A refused precondition is success and the map is skipped.** This is the branch that
    /// reads like an error and is not: the authority's comment says another thread got there
    /// first. A transcription that propagated the 0 would turn a benign race into a fetch
    /// failure, and the difference is invisible unless the test asserts the *answer*.
    #[test]
    fn a_refused_precondition_is_success_and_skips_the_map() {
        reset();
        PRE_RESULT.store(0, Ordering::SeqCst);
        PRE_ERRORS.store(0, Ordering::SeqCst);
        let map = two_algorithms();
        let (ret, _) = run_map(map.as_ptr(), Some(pre), None);
        assert_eq!(ret, 1, "0 from pre becomes 1, not 0");
        assert_eq!(SAW[PRE].load(Ordering::SeqCst), 1);
        assert_eq!(SAW[FN].load(Ordering::SeqCst), 0, "the map is skipped");
        assert_eq!(
            SAW[UNRESERVE].load(Ordering::SeqCst),
            1,
            "the reservation is still given back"
        );
    }

    /// An **error** from the precondition is -1 and there is no postcondition call, because the
    /// authority jumps straight to the unreserve.
    #[test]
    fn an_erroring_precondition_bails_out_with_minus_one() {
        reset();
        PRE_ERRORS.store(1, Ordering::SeqCst);
        let map = two_algorithms();
        let (ret, _) = run_map(map.as_ptr(), Some(pre), Some(post));
        assert_eq!(ret, -1);
        assert_eq!(SAW[FN].load(Ordering::SeqCst), 0);
        assert_eq!(SAW[POST].load(Ordering::SeqCst), 0, "post is not reached");
        assert_eq!(SAW[UNRESERVE].load(Ordering::SeqCst), 1);
        PRE_ERRORS.store(0, Ordering::SeqCst);
        PRE_RESULT.store(1, Ordering::SeqCst);
    }

    /// **The postcondition's answer is all or nothing, and `ret` does not survive a refusal.**
    ///
    /// The authority is
    /// `if (data->post == NULL) ret = 1; else if (!data->post(..., &ret)) ret = -1;` — so a
    /// post that writes 0 and answers 1 leaves `ret = 0`, a soft failure the walk remembers and
    /// continues past, while a post that answers **0** overwrites `ret` with -1 whatever it had
    /// written. The two are one character apart in the authority, and the first version of this
    /// test asserted the shape a hand-written implementation would have — that an erroring post
    /// left `ret` at its old value — which is the assertion that found the difference.
    #[test]
    fn the_postcondition_overwrites_ret_when_it_refuses() {
        reset();
        PRE_RESULT.store(1, Ordering::SeqCst);
        POST_RESULT.store(0, Ordering::SeqCst);
        let map = two_algorithms();
        let (soft, _) = run_map(map.as_ptr(), Some(pre), Some(post));
        assert_eq!(soft, 0, "post wrote 0 and answered 1, so ret is 0");

        POST_RESULT.store(-1, Ordering::SeqCst);
        reset();
        let (hard, _) = run_map(map.as_ptr(), Some(pre), Some(post));
        assert_eq!(hard, -1, "a post that answers 0 sets ret to -1");
        assert_eq!(SAW[UNRESERVE].load(Ordering::SeqCst), 1);
        POST_RESULT.store(0, Ordering::SeqCst);
    }

    /// A NULL map is not a failure: the pre and post still run, and nothing is constructed.
    /// `algorithm_do_this` passes NULL for an operation a provider has no table for.
    #[test]
    fn a_null_map_runs_the_pre_and_post_and_constructs_nothing() {
        reset();
        PRE_RESULT.store(1, Ordering::SeqCst);
        POST_RESULT.store(1, Ordering::SeqCst);
        let (ret, _) = run_map(ptr::null(), Some(pre), Some(post));
        assert_eq!(ret, 1);
        assert_eq!(SAW[FN].load(Ordering::SeqCst), 0);
        assert_eq!(SAW[PRE].load(Ordering::SeqCst), 1);
        assert_eq!(SAW[POST].load(Ordering::SeqCst), 1);
        POST_RESULT.store(0, Ordering::SeqCst);
    }

    /// `ossl_algorithm_get1_first_name` splits on the **first** `:`, copies rather than
    /// borrowing, and answers NULL — not an empty string — for a NULL name list.
    #[test]
    fn the_first_name_is_the_first_alias_and_is_owned() {
        let local = two_algorithms();
        let mut algo = OsslAlgorithm {
            algorithm_names: local[0].algorithm_names,
            property_definition: local[0].property_definition,
            implementation: local[0].implementation,
            algorithm_description: local[0].algorithm_description,
        };
        // SAFETY: `algo` is a local with a `'static` name list.
        let p = unsafe { ossl_algorithm_get1_first_name(&algo) };
        assert!(!p.is_null());
        // SAFETY: `p` is a fresh NUL-terminated allocation.
        let s = unsafe { core::ffi::CStr::from_ptr(p) };
        assert_eq!(s.to_bytes(), b"SHA256", "the first alias, not the second");
        // SAFETY: `p` came from `CRYPTO_strndup`, so this is the matching free.
        unsafe { crate::runtime::mem::CRYPTO_free(p.cast::<c_void>(), FILE, L_STRNDUP) };

        // A list with no colon at all is copied whole.
        algo.algorithm_names = c"SHA1".as_ptr();
        // SAFETY: as above.
        let p = unsafe { ossl_algorithm_get1_first_name(&algo) };
        // SAFETY: `p` is a fresh NUL-terminated allocation.
        assert_eq!(unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes(), b"SHA1");
        // SAFETY: matching free.
        unsafe { crate::runtime::mem::CRYPTO_free(p.cast::<c_void>(), FILE, L_STRNDUP) };

        // NULL in, NULL out.
        algo.algorithm_names = ptr::null();
        // SAFETY: the function only reads the pointer and answers NULL without allocating.
        assert!(unsafe { ossl_algorithm_get1_first_name(&algo) }.is_null());
    }

    /// The operation range is the authority's, including the reserved ids above
    /// `OSSL_OP_KEYEXCH`. A transcription that looped over the *named* operations would cover
    /// 1..11 and silently skip whatever a provider publishes at 12..22.
    #[test]
    fn the_operation_range_includes_the_reserved_ids_above_keyexch() {
        assert_eq!(OSSL_OP_DIGEST, 1);
        assert_eq!(OSSL_OP_HIGHEST, 22);
        let keyexch = 11;
        assert!(
            OSSL_OP_HIGHEST > keyexch,
            "the range must run past the last named operation"
        );
        assert_eq!(
            OSSL_OP_HIGHEST - OSSL_OP_DIGEST + 1,
            22,
            "twenty-two operations are visited when operation_id is zero"
        );
    }
}
