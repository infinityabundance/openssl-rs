//! Phase 7.4 — `crypto/evp/keymgmt_lib.c` whole.
//!
//! The eighteen internal functions that make a provider-side `EVP_PKEY` *portable*: they export key
//! data from the provider that owns it and import it into another provider that needs it, caching the
//! result so the round trip happens once per (key, provider, selection). The unit exports nothing —
//! `keymgmt_lib.c` has no `libcrypto-contamination` entry and no symbol in `libcrypto.ld` — so it is
//! invisible to every export-based atlas and is reached only through `p_lib.c` and `pmeth_lib.c`.
//!
//! ## The operation cache, and why it is not an optimisation
//!
//! `struct evp_pkey_st` carries `dirty_cnt`, `dirty_cnt_copy` and an `operation_cache` stack of
//! `OP_CACHE_ELEM`. The comment the authority writes over the pair says the cache exists "so we don't
//! need to redo the export/import every time we perform the same operation in that same provider",
//! which reads like a performance note and is not one: **two `EVP_KEYMGMT`s are the same origin in two
//! different ways**, and the cache is keyed on the second. The identity test is
//!
//! ```text
//! keymgmt1 == keymgmt2
//!   || (keymgmt1->name_id == keymgmt2->name_id && keymgmt1->prov == keymgmt2->prov)
//! ```
//!
//! and the second clause is what survives a flushed fetch cache, where the same provider's key
//! manager is a *new object* with the same name identity. A transcription that compared pointers
//! would re-export on every fetch-cache flush and, worse, would report "not the same type" for a key
//! compared against itself. `evp_keymgmt_util_find_operation_cache` and the origin test at the top of
//! `evp_keymgmt_util_export_to_provider` therefore use the same two-clause test, and they have to
//! agree or the cache is never found.
//!
//! ## Two locks, two directions
//!
//! `export_to_provider` takes the **read** lock to look for a cached entry and the **write** lock to
//! install one, and it releases the read lock *before* the export/import round trip — because the
//! export callback re-enters provider code and the authority does not hold `pk->lock` across a call
//! into another provider. The write-lock path then re-checks the cache, "to make sure some other
//! thread didn't get there first", and abandons its own work if it did. That re-check is not a
//! formality: it is the only thing that stops two threads each installing a different keydata object
//! for the same (key, provider, selection) triple, one of which would then leak.
//!
//! ## What is deliberately absent
//!
//! `evp_keymgmt_util_match` and `evp_keymgmt_util_copy` both have a **legacy arm** in the authority —
//! `evp_keymgmt_util_match` compares against a legacy `pk->pkey.ptr` through `evp_pkey_cmp_any`, and
//! `copy` handles a legacy source through the ameth's `copy`. Both are Phase 8's under D163/D165, and
//! neither is reachable here: a legacy origin cannot be constructed in this crate until
//! `pkey_set_type`'s legacy arm lands, so `pkey->keymgmt == NULL` with `pkey->type != EVP_PKEY_NONE`
//! is a state no caller can reach. Each site is marked where it would have to be filled.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::evp::keymgmt::{
    evp_keymgmt_dup, evp_keymgmt_export, evp_keymgmt_freedata, evp_keymgmt_gen,
    evp_keymgmt_get_params, evp_keymgmt_has, evp_keymgmt_import, evp_keymgmt_match,
    evp_keymgmt_newdata, EVP_KEYMGMT_free, EVP_KEYMGMT_get0_name, EVP_KEYMGMT_is_a,
    EVP_KEYMGMT_up_ref, EvpKeyMgmt,
};
use crate::evp::pkey::{evp_pkey_set_type_by_keymgmt, EvpPkey};
use crate::params::OsslParam;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::runtime::str::OPENSSL_strlcpy;
use crate::runtime::thread::{
    CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock,
};

/// The authority's translation unit, so a failing allocation or free records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/keymgmt_lib.c".as_ptr();
#[allow(dead_code)] // read by `evp_keymgmt_util_cache_keydata`, whose first live caller is 7.4b
/// `evp_keymgmt_util_cache_keydata`'s `OPENSSL_malloc(sizeof(*p))` (line 268).
const LINE_MALLOC_CACHE_ELEM: c_int = 268;
/// `op_cache_free`'s `OPENSSL_free(e)` (line 219).
const LINE_FREE_CACHE_ELEM: c_int = 219;
#[allow(dead_code)] // read by `evp_keymgmt_util_cache_keydata`, whose first live caller is 7.4b
/// `evp_keymgmt_util_cache_keydata`'s free after a failed `up_ref` (line 276).
const LINE_FREE_CACHE_ELEM_FAILED_UPREF: c_int = 276;
#[allow(dead_code)] // read by `evp_keymgmt_util_cache_keydata`, whose first live caller is 7.4b
/// `evp_keymgmt_util_cache_keydata`'s free after a failed push (line 282).
const LINE_FREE_CACHE_ELEM_FAILED_PUSH: c_int = 282;

/// `OSSL_PKEY_PARAM_BITS` — `include/openssl/core_names.h`.
const OSSL_PKEY_PARAM_BITS: *const c_char = c"bits".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_BITS`.
const OSSL_PKEY_PARAM_SECURITY_BITS: *const c_char = c"security-bits".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_CATEGORY` — spelled `OSSL_ALG_PARAM_SECURITY_CATEGORY`.
const OSSL_PKEY_PARAM_SECURITY_CATEGORY: *const c_char = c"security-category".as_ptr();
/// `OSSL_PKEY_PARAM_MAX_SIZE`.
const OSSL_PKEY_PARAM_MAX_SIZE: *const c_char = c"max-size".as_ptr();
#[allow(dead_code)] // read by `evp_keymgmt_util_get_deflt_digest_name`
/// `OSSL_PKEY_PARAM_DEFAULT_DIGEST`.
const OSSL_PKEY_PARAM_DEFAULT_DIGEST: *const c_char = c"default-digest".as_ptr();
#[allow(dead_code)] // read by `evp_keymgmt_util_get_deflt_digest_name`
/// `OSSL_PKEY_PARAM_MANDATORY_DIGEST`.
const OSSL_PKEY_PARAM_MANDATORY_DIGEST: *const c_char = c"mandatory-digest".as_ptr();

#[allow(non_upper_case_globals, dead_code)]
// read by `evp_keymgmt_util_get_deflt_digest_name`; the name mirrors the authority's `SN_undef` macro, which is why it is not upper case
/// `SN_undef` — `include/openssl/obj_mac.h`'s `#define SN_undef "UNDEF"`.
const SN_undef: *const c_char = c"UNDEF".as_ptr();

#[allow(dead_code)] // the two buffers of `evp_keymgmt_util_get_deflt_digest_name`
/// The size of the two digest-name buffers `evp_keymgmt_util_get_deflt_digest_name` fills, which are
/// the authority's `char mddefault[100]` and `char mdmandatory[100]`.
const DIGEST_NAME_BUFFER: usize = 100;

/// One entry of the authority's `OP_CACHE_ELEM` stack.
///
/// The struct is **not** opaque to the authority — `DEFINE_STACK_OF(OP_CACHE_ELEM)` generates
/// accessors over it — and it is not opaque here either, because `evp_keymgmt_util_export_to_provider`
/// reads `op->keymgmt` / `op->keydata` and `evp_keymgmt_util_match` reads the selection.
#[repr(C)]
pub(crate) struct OpCacheElem {
    /// `EVP_KEYMGMT *keymgmt` — the destination method, holding a reference.
    pub(crate) keymgmt: *mut EvpKeyMgmt,
    /// `void *keydata` — the key data this provider created by importing the origin's export.
    pub(crate) keydata: *mut c_void,
    /// `int selection` — what was imported into `keydata`.
    pub(crate) selection: c_int,
}

/// `struct evp_keymgmt_util_try_import_data_st` — the callback's argument.
///
/// `keydata` is `NULL` on entry when the destination has nothing yet, and the callback allocates on
/// demand; `keymgmt` and `selection` are inputs.
#[repr(C)]
pub(crate) struct TryImportData {
    /// `EVP_KEYMGMT *keymgmt`.
    pub(crate) keymgmt: *mut EvpKeyMgmt,
    /// `void *keydata`.
    pub(crate) keydata: *mut c_void,
    /// `int selection`.
    pub(crate) selection: c_int,
}

/// `static int match_type(const EVP_KEYMGMT *keymgmt1, const EVP_KEYMGMT *keymgmt2)`.
///
/// Whether two methods name the same key type, judged by asking the *first* for the second's name.
/// The authority's comment says it "assumes that the caller has made all the necessary NULL checks",
/// and that assumption is load-bearing: `EVP_KEYMGMT_get0_name` on a NULL method faults.
///
/// # Safety
/// Both arguments must be live `EvpKeyMgmt`s.
unsafe fn match_type(keymgmt1: *const EvpKeyMgmt, keymgmt2: *const EvpKeyMgmt) -> c_int {
    // SAFETY: both arguments are live per the contract.
    let name2 = unsafe { EVP_KEYMGMT_get0_name(keymgmt2) };
    // SAFETY: as above; a NULL method's name is not this function's contract.
    unsafe { EVP_KEYMGMT_is_a(keymgmt1, name2) }
}

/// `int evp_keymgmt_util_try_import(const OSSL_PARAM params[], void *arg)`.
///
/// The **callback** `evp_keymgmt_util_export` is handed, so the destination's key data is created
/// *during* the source's export rather than after it: the source calls back once with the parameters it
/// can provide, and this imports them. Three details are contract rather than plumbing:
///
///   * the key data is created **just in time**, on the first invocation, and `delete_on_error` records
///     whether *this* call created it — so a later failure frees what this call allocated and a failure
///     after an earlier successful invocation does not,
///   * `params[0].key == NULL` is an **empty** parameter array, which is not an error: the comment says
///     "It's fine if there was no data to transfer, we just end up with an empty destination key",
///   * a NULL key data allocation raises `ERR_R_EVP_LIB` at the site the authority raises it.
///
/// # Safety
/// `params` must be a terminated parameter array and `arg` a live `TryImportData`.
pub(crate) unsafe extern "C" fn evp_keymgmt_util_try_import(
    params: *const OsslParam,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: `arg` is a live `TryImportData` per the contract.
    let data = arg.cast::<TryImportData>();
    let mut delete_on_error = 0;

    // SAFETY: `data` is live.
    let (keymgmt, mut keydata) = unsafe { ((*data).keymgmt, (*data).keydata) };
    if keydata.is_null() {
        // SAFETY: `keymgmt` is live per the contract.
        keydata = unsafe { evp_keymgmt_newdata(keymgmt) };
        if keydata.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::KEYMGMT_LIB_37) };
            return 0;
        }
        delete_on_error = 1;
    }

    // SAFETY: `params` is a terminated array per the contract.
    let first_key = unsafe { (*params).key };
    if first_key.is_null() {
        // SAFETY: `data` is live and `keydata` is this call's own object.
        unsafe { (*data).keydata = keydata };
        return 1;
    }

    // SAFETY: `keymgmt` is live, `keydata` is live, and `params` is terminated.
    if unsafe { evp_keymgmt_import(keymgmt, keydata, (*data).selection, params) } != 0 {
        // SAFETY: `data` is live.
        unsafe { (*data).keydata = keydata };
        return 1;
    }
    if delete_on_error != 0 {
        // SAFETY: `keymgmt` is live and `keydata` was allocated for it.
        unsafe { evp_keymgmt_freedata(keymgmt, keydata) };
        // SAFETY: `data` is live.
        unsafe { (*data).keydata = ptr::null_mut() };
    }
    0
}

#[allow(dead_code)]
// its three callers here are `fromdata`, `gen` and `make_pkey`, and all three wait on a later subphase; the first live one is 7.4a-iii
/// `int evp_keymgmt_util_assign_pkey(EVP_PKEY *pkey, EVP_KEYMGMT *keymgmt, void *keydata)`.
///
/// Forcibly re-types `pkey` onto `keymgmt` and gives it `keydata`. The word *forcibly* is the
/// authority's own comment about the difference between this and `evp_keymgmt_util_copy`: this one
/// does not care what `pkey` was before, and `copy` does.
///
/// The four-way refusal is one `||` with one error, so a caller cannot tell which clause failed.
///
/// # Safety
/// `pkey` and `keymgmt` NULL or live; `keydata` NULL or live for `keymgmt`.
pub(crate) unsafe fn evp_keymgmt_util_assign_pkey(
    pkey: *mut EvpPkey,
    keymgmt: *mut EvpKeyMgmt,
    keydata: *mut c_void,
) -> c_int {
    if pkey.is_null()
        || keymgmt.is_null()
        || keydata.is_null()
        // SAFETY: `pkey` is live and `keymgmt` is live.
        || unsafe { evp_pkey_set_type_by_keymgmt(pkey, keymgmt) } == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEYMGMT_LIB_65) };
        return 0;
    }
    // SAFETY: `pkey` is live.
    unsafe { (*pkey).keydata = keydata };
    // SAFETY: `pkey` is live.
    unsafe { evp_keymgmt_util_cache_keyinfo(pkey) };
    1
}

#[allow(dead_code)]
// first live caller is the `EVP_PKEY` construction path in 7.4a-iii; `evp_keymgmt_util_assign_pkey` is the other
/// `EVP_PKEY *evp_keymgmt_util_make_pkey(EVP_KEYMGMT *keymgmt, void *keydata)`.
///
/// A fresh `EVP_PKEY` assigned onto `keymgmt`, or NULL with **no error raised of its own** — the
/// failure modes are `EVP_PKEY_new`'s and `assign_pkey`'s, and the authority adds none. The `||`
/// short-circuits, so a NULL `keymgmt` never calls `EVP_PKEY_new`.
///
/// # Safety
/// `keymgmt` NULL or live; `keydata` NULL or live for `keymgmt`.
pub(crate) unsafe fn evp_keymgmt_util_make_pkey(
    keymgmt: *mut EvpKeyMgmt,
    keydata: *mut c_void,
) -> *mut EvpPkey {
    if keymgmt.is_null() || keydata.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let pkey = unsafe { crate::evp::pkey::EVP_PKEY_new() };
    if pkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pkey` is this call's own object and the other two are live.
    if unsafe { evp_keymgmt_util_assign_pkey(pkey, keymgmt, keydata) } == 0 {
        // SAFETY: `pkey` is this call's own object, and it takes a reference count of one.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        return ptr::null_mut();
    }
    pkey
}

/// `int evp_keymgmt_util_export(const EVP_PKEY *pk, int selection, OSSL_CALLBACK *export_cb,
/// void *export_cbarg)`.
///
/// Two NULL guards, then a delegation to the origin's own exporter. It reads `pk->keymgmt` and
/// `pk->keydata` with no test on either, so a **typed but unassigned** provider key — `keymgmt`
/// non-NULL, `keydata` NULL — reaches `evp_keymgmt_export` with a NULL keydata, which the provider
/// sees. `evp_pkey_export_to_provider` guards that case before calling here; nothing else does.
///
/// # Safety
/// `pk` NULL or live; `export_cb` NULL or a valid callback.
pub(crate) unsafe fn evp_keymgmt_util_export(
    pk: *const EvpPkey,
    selection: c_int,
    export_cb: Option<unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int>,
    export_cbarg: *mut c_void,
) -> c_int {
    if pk.is_null() || export_cb.is_none() {
        return 0;
    }
    // SAFETY: `pk` is live per the contract.
    let (keymgmt, keydata) = unsafe { ((*pk).keymgmt, (*pk).keydata) };
    // SAFETY: `keymgmt` is live and `export_cb` is valid.
    unsafe { evp_keymgmt_export(keymgmt, keydata, selection, export_cb, export_cbarg) }
}

#[allow(dead_code)]
// first live caller is 7.4b's method classes -- reaching a foreign provider is what an `EVP_SIGNATURE`/`EVP_KEYEXCH` operation does -- and `evp_keymgmt_util_match` here
/// `void *evp_keymgmt_util_export_to_provider(EVP_PKEY *pk, EVP_KEYMGMT *keymgmt, int selection)`.
///
/// The round trip, and the unit's centre. Exported key data lives in the provider that created it, and
/// an operation that needs it in another provider goes through here: the origin exports, the
/// destination imports, and the result is cached on the key.
///
/// Six exits, and each is a different answer a caller can distinguish only by the return value:
///
///   1. no destination method, or an **unassigned** key → NULL, no error;
///   2. **same origin** — pointer identity, or the same name id *and* provider → the key's own
///      keydata, which is why a key handed to its own provider costs nothing;
///   3. a cached entry for this destination and selection, when the dirty counter has not moved →
///      the cached keydata;
///   4. the origin publishes no `export` → NULL;
///   5. the two methods do not name the same type, which the authority tests with **`ossl_assert`**
///      and therefore only in a debug build → NULL. In the released authority the assertion is the
///      identity function and the round trip proceeds; the crate follows the released build, which is
///      the profile the authority was built with, and calls `match_type` regardless so that the two
///      sides agree on the *result* rather than on the check;
///   6. a failed export/import round trip → NULL with the destination's own error on the queue.
///
/// The write-lock re-check is the seventh path and returns the *other* thread's keydata, freeing its
/// own. It is the only exit that returns a pointer this call did not produce.
///
/// # Safety
/// `pk` NULL or live; `keymgmt` NULL or live.
pub(crate) unsafe fn evp_keymgmt_util_export_to_provider(
    pk: *mut EvpPkey,
    keymgmt: *mut EvpKeyMgmt,
    selection: c_int,
) -> *mut c_void {
    // SAFETY: `pk` is live or NULL per the contract; the authority dereferences it below without a
    // NULL test, and every caller has already checked.
    let (pk_keymgmt, pk_keydata) = unsafe { ((*pk).keymgmt, (*pk).keydata) };
    let mut import_data = TryImportData {
        keymgmt,
        keydata: ptr::null_mut(),
        selection,
    };
    let mut op: *mut OpCacheElem;

    if keymgmt.is_null() {
        return ptr::null_mut();
    }

    if pk_keydata.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: both methods are live.
    let same_origin = unsafe {
        (*pk_keymgmt).name_id == (*keymgmt).name_id && (*pk_keymgmt).prov == (*keymgmt).prov
    };
    if pk_keymgmt == keymgmt || same_origin {
        return pk_keydata;
    }

    // SAFETY: `pk` is live.
    let lock = unsafe { (*pk).lock };
    // SAFETY: `lock` is the key's own lock, live for as long as the key is.
    if unsafe { CRYPTO_THREAD_read_lock(lock) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `pk` is live.
    let dirty = unsafe { ((*pk).dirty_cnt, (*pk).dirty_cnt_copy) };
    if dirty.0 == dirty.1 {
        // SAFETY: `pk` is live and the read lock is held, which is what the lookup requires.
        op = unsafe { evp_keymgmt_util_find_operation_cache(pk, keymgmt, selection) };
        if !op.is_null() {
            // SAFETY: `op` is non-NULL.
            if !unsafe { (*op).keymgmt }.is_null() {
                // SAFETY: `op` is non-NULL and cached under the lock.
                let ret = unsafe { (*op).keydata };
                // SAFETY: the read lock is held.
                unsafe { CRYPTO_THREAD_unlock(lock) };
                return ret;
            }
        }
    }
    // SAFETY: the read lock is held.
    unsafe { CRYPTO_THREAD_unlock(lock) };

    // SAFETY: `pk_keymgmt` is live — the key is assigned, so it has a method.
    if unsafe { (*pk_keymgmt).export }.is_none() {
        return ptr::null_mut();
    }

    // SAFETY: both methods name their types; `match_type`'s own contract is that both are live.
    if unsafe { match_type(pk_keymgmt, keymgmt) } == 0 {
        return ptr::null_mut();
    }

    import_data.keydata = ptr::null_mut();
    import_data.keymgmt = keymgmt;
    import_data.selection = selection;

    // SAFETY: `pk` is live and the callback is this file's own `try_import`.
    if unsafe {
        evp_keymgmt_util_export(
            pk,
            selection,
            Some(evp_keymgmt_util_try_import),
            ptr::addr_of_mut!(import_data).cast::<c_void>(),
        )
    } == 0
    {
        return ptr::null_mut();
    }

    // SAFETY: the write lock is this key's lock.
    if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
        // SAFETY: `keymgmt` is live and `import_data.keydata` was created for it.
        unsafe { evp_keymgmt_freedata(keymgmt, import_data.keydata) };
        return ptr::null_mut();
    }
    // SAFETY: `pk` is live and the write lock is held, which is what the lookup requires.
    op = unsafe { evp_keymgmt_util_find_operation_cache(pk, keymgmt, selection) };
    if !op.is_null() {
        // SAFETY: `op` is non-NULL.
        if !unsafe { (*op).keydata }.is_null() {
            // SAFETY: `op` is non-NULL and cached under the lock.
            let ret = unsafe { (*op).keydata };
            // SAFETY: the write lock is held.
            unsafe { CRYPTO_THREAD_unlock(lock) };
            // SAFETY: `keymgmt` is live and this call's own keydata is not in the cache.
            unsafe { evp_keymgmt_freedata(keymgmt, import_data.keydata) };
            return ret;
        }
    }

    // SAFETY: `pk` is live.
    let dirty_now = unsafe { ((*pk).dirty_cnt, (*pk).dirty_cnt_copy) };
    if dirty_now.0 != dirty_now.1 {
        // SAFETY: `pk` is live and the write lock is held.
        unsafe { evp_keymgmt_util_clear_operation_cache(pk) };
    }

    // SAFETY: `pk` is live, `keymgmt` is live, and the write lock is held.
    if unsafe { evp_keymgmt_util_cache_keydata(pk, keymgmt, import_data.keydata, selection) } == 0 {
        // SAFETY: the write lock is held.
        unsafe { CRYPTO_THREAD_unlock(lock) };
        // SAFETY: `keymgmt` is live and the data was not cached.
        unsafe { evp_keymgmt_freedata(keymgmt, import_data.keydata) };
        return ptr::null_mut();
    }

    // SAFETY: `pk` is live.
    unsafe { (*pk).dirty_cnt_copy = (*pk).dirty_cnt };

    // SAFETY: the write lock is held.
    unsafe { CRYPTO_THREAD_unlock(lock) };

    import_data.keydata
}

/// `static void op_cache_free(OP_CACHE_ELEM *e)` — one element's destructor.
///
/// # Safety
/// `e` must be an element this file allocated and not yet freed.
unsafe extern "C" fn op_cache_free(e: *mut c_void) {
    // SAFETY: `e` is an element of the cache per the contract.
    let elem = e.cast::<OpCacheElem>();
    // SAFETY: `elem` is live.
    let (keymgmt, keydata) = unsafe { ((*elem).keymgmt, (*elem).keydata) };
    // SAFETY: `keymgmt` is live and holds the reference taken by `cache_keydata`.
    unsafe { evp_keymgmt_freedata(keymgmt, keydata) };
    // SAFETY: `keymgmt` is live and the cache holds one reference to it.
    unsafe { EVP_KEYMGMT_free(keymgmt) };
    // SAFETY: `elem` was allocated with `CRYPTO_malloc`.
    unsafe { CRYPTO_free(e, FILE, LINE_FREE_CACHE_ELEM) };
}

/// `int evp_keymgmt_util_clear_operation_cache(EVP_PKEY *pk)`.
///
/// Always answers 1, including for a NULL key — the guard is on the whole body, so a NULL key is a
/// no-op rather than an error, and the "can this fail" answer is a constant.
///
/// # Safety
/// `pk` NULL or live.
pub(crate) unsafe fn evp_keymgmt_util_clear_operation_cache(pk: *mut EvpPkey) -> c_int {
    if !pk.is_null() {
        // SAFETY: `pk` is live.
        let cache = unsafe { (*pk).operation_cache };
        // SAFETY: `cache` is a stack of `OpCacheElem` this file built, or NULL.
        unsafe { OPENSSL_sk_pop_free(cache, Some(op_cache_free)) };
        // SAFETY: `pk` is live.
        unsafe { (*pk).operation_cache = ptr::null_mut() };
    }
    1
}

#[allow(dead_code)] // called by `evp_keymgmt_util_export_to_provider`, which 7.4b is the first to reach
/// `OP_CACHE_ELEM *evp_keymgmt_util_find_operation_cache(EVP_PKEY *pk, EVP_KEYMGMT *keymgmt,
/// int selection)`.
///
/// A **linear scan**, and the authority says why: "A comparison and
/// `sk_P_CACHE_ELEM_find()` are avoided to not cause problems when we've only a read lock." The
/// sorted-stack lookup would need the comparison function to be set, which mutates the stack.
///
/// The match is two clauses, and the second is the one that matters: the selection must be a
/// **subset** of the entry's (`(p->selection & selection) == selection`), so an entry that imported
/// *more* satisfies a request for less, and one that imported less does not satisfy a request for
/// more. Together with the origin test this is the whole cache contract.
///
/// # Safety
/// `pk` must be live and its lock held; `keymgmt` must be live.
pub(crate) unsafe fn evp_keymgmt_util_find_operation_cache(
    pk: *mut EvpPkey,
    keymgmt: *mut EvpKeyMgmt,
    selection: c_int,
) -> *mut OpCacheElem {
    // SAFETY: `pk` is live.
    let cache = unsafe { (*pk).operation_cache };
    // SAFETY: `cache` is a stack of `OpCacheElem` or NULL.
    let end = unsafe { OPENSSL_sk_num(cache) };

    for i in 0..end {
        // SAFETY: `cache` is a stack of `OpCacheElem` and `i` is in range.
        let p = unsafe { OPENSSL_sk_value(cache, i) }.cast::<OpCacheElem>();
        // SAFETY: `p` is a live element.
        let matches = unsafe {
            ((*p).selection & selection) == selection
                && (keymgmt == (*p).keymgmt
                    || ((*keymgmt).name_id == (*(*p).keymgmt).name_id
                        && (*keymgmt).prov == (*(*p).keymgmt).prov))
        };
        if matches {
            return p;
        }
    }
    ptr::null_mut()
}

#[allow(dead_code)] // called by `evp_keymgmt_util_export_to_provider`, which 7.4b is the first to reach
/// `int evp_keymgmt_util_cache_keydata(EVP_PKEY *pk, EVP_KEYMGMT *keymgmt, void *keydata,
/// int selection)`.
///
/// Installs an entry, taking it only when `keydata` is non-NULL — so caching "nothing" is a success
/// that stores nothing, which is what makes the NULL return of a failed round trip distinguishable
/// from a cache miss by the caller rather than by this function.
///
/// Four failure exits, and the last two matter: a failed `up_ref` frees the element, and a failed
/// push gives *back* the reference the `up_ref` took. A transcription that dropped either would leak
/// a method reference per failure.
///
/// # Safety
/// `pk` must be live and its write lock held; `keymgmt` must be live.
pub(crate) unsafe fn evp_keymgmt_util_cache_keydata(
    pk: *mut EvpPkey,
    keymgmt: *mut EvpKeyMgmt,
    keydata: *mut c_void,
    selection: c_int,
) -> c_int {
    if !keydata.is_null() {
        // SAFETY: `pk` is live.
        if unsafe { (*pk).operation_cache }.is_null() {
            /* `OPENSSL_sk_new_null` is a safe entry point: it validates nothing and answers NULL
             * only when the allocation fails. */
            let stack = OPENSSL_sk_new_null();
            if stack.is_null() {
                return 0;
            }
            // SAFETY: `pk` is live.
            unsafe { (*pk).operation_cache = stack };
        }

        // SAFETY: this allocates a fresh object and reads nothing.
        let p = CRYPTO_malloc(
            core::mem::size_of::<OpCacheElem>(),
            FILE,
            LINE_MALLOC_CACHE_ELEM,
        )
        .cast::<OpCacheElem>();
        if p.is_null() {
            return 0;
        }
        // SAFETY: `p` is this call's own allocation.
        unsafe {
            (*p).keydata = keydata;
            (*p).keymgmt = keymgmt;
            (*p).selection = selection;
        }

        // SAFETY: `keymgmt` is live.
        if unsafe { EVP_KEYMGMT_up_ref(keymgmt) } == 0 {
            // SAFETY: `p` is this call's own allocation.
            unsafe { CRYPTO_free(p.cast(), FILE, LINE_FREE_CACHE_ELEM_FAILED_UPREF) };
            return 0;
        }

        // SAFETY: `pk` is live and its cache stack was created above or already existed.
        if unsafe { OPENSSL_sk_push((*pk).operation_cache, p.cast::<c_void>()) } == 0 {
            // SAFETY: `keymgmt` is live and the push did not take the entry's reference.
            unsafe { EVP_KEYMGMT_free(keymgmt) };
            // SAFETY: `p` is this call's own allocation.
            unsafe { CRYPTO_free(p.cast(), FILE, LINE_FREE_CACHE_ELEM_FAILED_PUSH) };
            return 0;
        }
    }
    1
}

/// `void evp_keymgmt_util_cache_keyinfo(EVP_PKEY *pk)`.
///
/// Asks the origin for four of the properties every `EVP_PKEY_get_*` accessor answers from, and stores
/// them in `pk->cache`. The four are constructed with **different initial values** and that is
/// contract, not tidiness: `security_category` starts at **-1** and the other three at 0, because a
/// provider that answers `security-category` with 0 is saying something different from one that does
/// not answer it — and this function cannot tell the difference either way, since a failed
/// `get_params` leaves all four as they were.
///
/// The whole body is under `pk->keydata != NULL`, so an unassigned key keeps the zeros it was
/// allocated with.
///
/// # Safety
/// `pk` must be live and `keydata` must belong to its method.
pub(crate) unsafe fn evp_keymgmt_util_cache_keyinfo(pk: *mut EvpPkey) {
    // SAFETY: `pk` is live.
    let (keydata, keymgmt) = unsafe { ((*pk).keydata, (*pk).keymgmt) };
    if !keydata.is_null() {
        let mut bits: c_int = 0;
        let mut security_bits: c_int = 0;
        let mut security_category: c_int = -1;
        let mut size: c_int = 0;
        let mut params = [crate::params::END; 5];

        // SAFETY: each buffer is a live local of the type its constructor declares, and the array has
        // room for the four and the terminator.
        unsafe {
            params[0] = crate::params::OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, &mut bits);
            params[1] = crate::params::OSSL_PARAM_construct_int(
                OSSL_PKEY_PARAM_SECURITY_BITS,
                &mut security_bits,
            );
            params[2] = crate::params::OSSL_PARAM_construct_int(
                OSSL_PKEY_PARAM_SECURITY_CATEGORY,
                &mut security_category,
            );
            params[3] =
                crate::params::OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_MAX_SIZE, &mut size);
            params[4] = crate::params::OSSL_PARAM_construct_end();
        }

        // SAFETY: `keymgmt` is live, `keydata` belongs to it, and `params` is a terminated array
        // whose three data pointers are live locals.
        if unsafe { evp_keymgmt_get_params(keymgmt, keydata, params.as_mut_ptr()) } != 0 {
            // SAFETY: `pk` is live.
            unsafe {
                (*pk).cache.size = size;
                (*pk).cache.bits = bits;
                (*pk).cache.security_bits = security_bits;
                (*pk).cache.security_category = security_category;
            }
        }
    }
}

#[allow(dead_code)] // 7.4c: `EVP_PKEY_fromdata` and `EVP_PKEY_todata` are `pmeth_gn.c`'s
/// `void *evp_keymgmt_util_fromdata(EVP_PKEY *target, EVP_KEYMGMT *keymgmt, int selection,
/// const OSSL_PARAM params[])`.
///
/// The other constructor route: create empty key data, import into it, assign. Every failure frees
/// what was created — and the free is **unconditional**, because `evp_keymgmt_freedata` tolerates a
/// NULL key data, which is what makes the three-way `||` safe to write as one clause.
///
/// # Safety
/// `target` must be live; `keymgmt` must be live; `params` a terminated array.
pub(crate) unsafe fn evp_keymgmt_util_fromdata(
    target: *mut EvpPkey,
    keymgmt: *mut EvpKeyMgmt,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: `keymgmt` is live per the contract.
    let mut keydata = unsafe { evp_keymgmt_newdata(keymgmt) };

    /* The authority writes this as a three-clause `||` whose last two clauses are calls. Spelled out
     * because each call has its own safety argument, which a single `||` cannot carry -- and the
     * short-circuit is preserved: a NULL key data skips both. */
    let mut ok = !keydata.is_null();
    if ok {
        // SAFETY: `keymgmt` is live and `keydata` is its own fresh object; `params` is terminated.
        ok = unsafe { evp_keymgmt_import(keymgmt, keydata, selection, params) } != 0;
    }
    if ok {
        // SAFETY: `target` is live, `keymgmt` is live, and `keydata` belongs to `keymgmt`.
        ok = unsafe { evp_keymgmt_util_assign_pkey(target, keymgmt, keydata) } != 0;
    }
    if !ok {
        // SAFETY: `keymgmt` is live and `keydata` is NULL or its own object.
        unsafe { evp_keymgmt_freedata(keymgmt, keydata) };
        keydata = ptr::null_mut();
    }
    keydata
}

#[allow(dead_code)] // 7.4a-iii: the `EVP_PKEY_get_bits`-adjacent accessors and the `EVP_PKEY_check` family read it
/// `int evp_keymgmt_util_has(EVP_PKEY *pk, int selection)`.
///
/// One guard, then the method's own answer — and the guard is on `keymgmt`, not on `keydata`, so an
/// unassigned provider key reaches `evp_keymgmt_has` with a NULL key data. That is deliberate in the
/// authority: `evp_keymgmt_has` is mandatory and a provider's answer for "no key data" is its own.
///
/// # Safety
/// `pk` must be live.
pub(crate) unsafe fn evp_keymgmt_util_has(pk: *mut EvpPkey, selection: c_int) -> c_int {
    // SAFETY: `pk` is live.
    let (keymgmt, keydata) = unsafe { ((*pk).keymgmt, (*pk).keydata) };
    if keymgmt.is_null() {
        return 0;
    }
    // SAFETY: `keymgmt` is live and `keydata` belongs to it or is NULL.
    unsafe { evp_keymgmt_has(keymgmt, keydata, selection) }
}

#[allow(dead_code)] // 7.4a-iii: `EVP_PKEY_eq` and `EVP_PKEY_parameters_eq` are its first live callers
/// `int evp_keymgmt_util_match(EVP_PKEY *pk1, EVP_PKEY *pk2, int selection)`.
///
/// The comparison behind `EVP_PKEY_eq` and `EVP_PKEY_parameters_eq`, and its four answers are the
/// documented contract: **1** same key, **0** different key, **-1** different key *type*, **-2**
/// unsupported operation.
///
/// When the two keys come from different methods it attempts a cross export — **in one direction
/// only**, and the `ok` flag is what decides which: the authority tries to export `pk1` into `pk2`'s
/// provider if `pk2`'s method publishes `match`, and only if that fails does it try the other way.
/// Both directions would double the work and could disagree; the comment says so.
///
/// Two NULL inputs are **equal** (`pk1 == NULL && pk2 == NULL` → 1), which is a real answer and not a
/// guard: an empty comparison is a success.
///
/// The legacy arm is absent — see the module documentation. A legacy `pk` has `keymgmt == NULL` and
/// non-NULL `pkey.ptr`, and this function reads only the provider fields, so the absent arm is
/// reachable only through a state this crate cannot build.
///
/// # Safety
/// Both arguments NULL or live.
pub(crate) unsafe fn evp_keymgmt_util_match(
    pk1: *mut EvpPkey,
    pk2: *mut EvpPkey,
    selection: c_int,
) -> c_int {
    if pk1.is_null() || pk2.is_null() {
        return c_int::from(pk1.is_null() && pk2.is_null());
    }

    // SAFETY: both keys are live.
    let (mut keymgmt1, mut keydata1) = unsafe { ((*pk1).keymgmt, (*pk1).keydata) };
    // SAFETY: as above.
    let (mut keymgmt2, mut keydata2) = unsafe { ((*pk2).keymgmt, (*pk2).keydata) };

    if keymgmt1 != keymgmt2 {
        let mut ok = 0;

        if !keymgmt1.is_null() && !keymgmt2.is_null() {
            // SAFETY: both methods are live.
            if unsafe { match_type(keymgmt1, keymgmt2) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::KEYMGMT_LIB_388) };
                return -1;
            }
        }

        // SAFETY: `keymgmt2` is live.
        if !keymgmt2.is_null() && unsafe { (*keymgmt2).match_ }.is_some() {
            let mut tmp_keydata = ptr::null_mut();

            ok = 1;
            if !keydata1.is_null() {
                // SAFETY: `pk1` is live and `keymgmt2` is live.
                tmp_keydata =
                    unsafe { evp_keymgmt_util_export_to_provider(pk1, keymgmt2, selection) };
                ok = c_int::from(!tmp_keydata.is_null());
            }
            if ok != 0 {
                keymgmt1 = keymgmt2;
                keydata1 = tmp_keydata;
            }
        }
        // SAFETY: `keymgmt1` is live.
        if ok == 0 && !keymgmt1.is_null() && unsafe { (*keymgmt1).match_ }.is_some() {
            let mut tmp_keydata = ptr::null_mut();

            ok = 1;
            if !keydata2.is_null() {
                // SAFETY: `pk2` is live and `keymgmt1` is live.
                tmp_keydata =
                    unsafe { evp_keymgmt_util_export_to_provider(pk2, keymgmt1, selection) };
                ok = c_int::from(!tmp_keydata.is_null());
            }
            if ok != 0 {
                keymgmt2 = keymgmt1;
                keydata2 = tmp_keydata;
            }
        }
    }

    if keymgmt1 != keymgmt2 {
        return -2;
    }
    if keydata1.is_null() && keydata2.is_null() {
        return 1;
    }
    if keydata1.is_null() || keydata2.is_null() {
        return 0;
    }
    // SAFETY: both methods agree and both keydata are live for it.
    unsafe { evp_keymgmt_match(keymgmt1, keydata1, keydata2, selection) }
}

/// `int evp_keymgmt_util_copy(EVP_PKEY *to, EVP_PKEY *from, int selection)`.
///
/// `EVP_PKEY_dup`'s engine. Three routes, and the choice between them is the whole function:
///
///   1. **`dup`**, when the two keys share a method, `to` is unassigned, and the method publishes
///      `dup` — the provider duplicates its own key data, which is cheaper and exact;
///   2. **export/import**, when the two methods name the same type but are not identical;
///   3. neither, for a type mismatch, which raises `EVP_R_DIFFERENT_KEY_TYPES`.
///
/// The subtlety is that `to`'s method is *not* set until the end: `to_keymgmt` is a local that starts
/// as `to`'s own method, falls back to `from`'s when `to` is unassigned, and is written into `to` with
/// `EVP_PKEY_set_type_by_keymgmt` only after the key data exists — because the final assignment is
/// what gives `to` its type, and doing it earlier would leave a typed-but-unassigned key behind on a
/// failure. `alloc_keydata` is the same idea for the data: it tracks what this call allocated so the
/// failure paths free exactly that and not `to`'s pre-existing data.
///
/// Note `to_keymgmt == from->keymgmt` is a **pointer** comparison on the `dup` route while the
/// fallback uses `match_type`, and the authority writes both on purpose: duplication requires the
/// identical method object, because a `dup` implementation is allowed to assume its own layout.
///
/// # Safety
/// `to` must be live; `from` NULL or live.
pub(crate) unsafe fn evp_keymgmt_util_copy(
    to: *mut EvpPkey,
    from: *mut EvpPkey,
    selection: c_int,
) -> c_int {
    // SAFETY: `to` is live per the contract.
    let mut to_keymgmt = unsafe { (*to).keymgmt };
    // SAFETY: as above.
    let mut to_keydata = unsafe { (*to).keydata };
    let mut alloc_keydata: *mut c_void = ptr::null_mut();

    if from.is_null() {
        return 0;
    }
    // SAFETY: `from` is live.
    let (from_keymgmt, from_keydata) = unsafe { ((*from).keymgmt, (*from).keydata) };
    if from_keydata.is_null() {
        return 0;
    }

    if to_keymgmt.is_null() {
        to_keymgmt = from_keymgmt;
    }

    // SAFETY: `to_keymgmt` is live — either `to`'s own method or `from`'s.
    if to_keymgmt == from_keymgmt && unsafe { (*to_keymgmt).dup }.is_some() && to_keydata.is_null()
    {
        // SAFETY: `to_keymgmt` is live and `from_keydata` belongs to it.
        to_keydata = unsafe { evp_keymgmt_dup(to_keymgmt, from_keydata, selection) };
        alloc_keydata = to_keydata;
        if to_keydata.is_null() {
            return 0;
        }
    } else {
        // SAFETY: `to_keymgmt` is live and `from_keymgmt` is live.
        if unsafe { match_type(to_keymgmt, from_keymgmt) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::KEYMGMT_LIB_491) };
            return 0;
        }

        let mut import_data = TryImportData {
            keymgmt: to_keymgmt,
            keydata: to_keydata,
            selection,
        };

        // SAFETY: `from` is live and the callback is this file's own `try_import`.
        if unsafe {
            evp_keymgmt_util_export(
                from,
                selection,
                Some(evp_keymgmt_util_try_import),
                ptr::addr_of_mut!(import_data).cast::<c_void>(),
            )
        } == 0
        {
            return 0;
        }

        if to_keydata.is_null() {
            to_keydata = import_data.keydata;
            alloc_keydata = to_keydata;
        }
    }

    // SAFETY: `to` is live.
    if unsafe { (*to).keymgmt }.is_null() {
        // SAFETY: `to` is live and `to_keymgmt` is live.
        if unsafe { evp_pkey_set_type_by_keymgmt(to, to_keymgmt) } == 0 {
            // SAFETY: `to_keymgmt` is live and `alloc_keydata` is this call's own object or NULL.
            unsafe { evp_keymgmt_freedata(to_keymgmt, alloc_keydata) };
            return 0;
        }
    }
    // SAFETY: `to` is live.
    unsafe { (*to).keydata = to_keydata };
    // SAFETY: `to` is live.
    unsafe { evp_keymgmt_util_cache_keyinfo(to) };

    1
}

#[allow(dead_code)] // 7.4c: `EVP_PKEY_generate`/`EVP_PKEY_keygen` are `pmeth_gn.c`'s
/// `void *evp_keymgmt_util_gen(EVP_PKEY *target, EVP_KEYMGMT *keymgmt, void *genctx,
/// OSSL_CALLBACK *cb, void *cbarg)`.
///
/// Generate and assign, with the same unconditional-free failure shape as `fromdata`. The generator
/// callback is the *caller's*, so what it writes is the caller's business.
///
/// # Safety
/// `target` must be live; `keymgmt` must be live; `genctx` is the callback's own context.
pub(crate) unsafe fn evp_keymgmt_util_gen(
    target: *mut EvpPkey,
    keymgmt: *mut EvpKeyMgmt,
    genctx: *mut c_void,
    cb: Option<unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int>,
    cbarg: *mut c_void,
) -> *mut c_void {
    // SAFETY: `keymgmt` is live per the contract.
    let mut keydata = unsafe { evp_keymgmt_gen(keymgmt, genctx, cb, cbarg) };

    // SAFETY: as the contract, with `keydata` a fresh object of `keymgmt`'s.
    if keydata.is_null() || unsafe { evp_keymgmt_util_assign_pkey(target, keymgmt, keydata) } == 0 {
        // SAFETY: `keymgmt` is live and `keydata` is NULL or its own object.
        unsafe { evp_keymgmt_freedata(keymgmt, keydata) };
        keydata = ptr::null_mut();
    }
    keydata
}

#[allow(dead_code)] // 7.4a-iii: `EVP_PKEY_get_default_digest_name` is `p_lib.c`'s and is the first to read it
/// `int evp_keymgmt_util_get_deflt_digest_name(EVP_KEYMGMT *keymgmt, void *keydata, char *mdname,
/// size_t mdname_sz)`.
///
/// The two-parameter dance behind `EVP_PKEY_get_default_digest_name`, and the reason it returns a
/// **signed** value: `-2` means the method answered neither parameter, `0` means it answered the
/// `get_params` call with a failure, `1` means it filled `default-digest`, and `2` means it filled
/// `mandatory-digest` — a *mandatory* digest overrides a default one, which is why the two tests are
/// ordered the way they are.
///
/// The `<= 1` tests are not "empty string" tests: a `return_size` of 1 is a lone NUL, which is what
/// `OSSL_PARAM` records for a modified parameter whose value is the empty string, and both empty
/// values answer **`SN_undef`** rather than an empty name — the comment says `SN_undef` "corresponds to
/// what `EVP_PKEY_get_default_nid()` returns for no digest".
///
/// # Safety
/// `keymgmt` must be live; `keydata` NULL or live for it; `mdname` writable for `mdname_sz` bytes.
pub(crate) unsafe fn evp_keymgmt_util_get_deflt_digest_name(
    keymgmt: *mut EvpKeyMgmt,
    keydata: *mut c_void,
    mdname: *mut c_char,
    mdname_sz: usize,
) -> c_int {
    let mut mddefault = [0 as c_char; DIGEST_NAME_BUFFER];
    let mut mdmandatory = [0 as c_char; DIGEST_NAME_BUFFER];
    let mut rv: c_int = -2;
    let mut params = [crate::params::END; 3];

    // SAFETY: both buffers are live locals of the size the constructor declares.
    unsafe {
        params[0] = crate::params::OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_DEFAULT_DIGEST,
            mddefault.as_mut_ptr(),
            mddefault.len(),
        );
        params[1] = crate::params::OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_MANDATORY_DIGEST,
            mdmandatory.as_mut_ptr(),
            mdmandatory.len(),
        );
        params[2] = crate::params::OSSL_PARAM_construct_end();
    }

    // SAFETY: `keymgmt` is live, `keydata` belongs to it, and `params` is a terminated array whose
    // two data pointers are live locals.
    if unsafe { evp_keymgmt_get_params(keymgmt, keydata, params.as_mut_ptr()) } == 0 {
        return 0;
    }

    let mut result: *const c_char = ptr::null();
    // SAFETY: `params` is a live array of three and the index is in range.
    let mandatory_modified = unsafe { crate::params::OSSL_PARAM_modified(&params[1]) } != 0;
    // SAFETY: as above.
    let default_modified = unsafe { crate::params::OSSL_PARAM_modified(&params[0]) } != 0;

    if mandatory_modified {
        if params[1].return_size <= 1 {
            result = SN_undef;
        } else {
            result = mdmandatory.as_ptr();
        }
        rv = 2;
    } else if default_modified {
        if params[0].return_size <= 1 {
            result = SN_undef;
        } else {
            result = mddefault.as_ptr();
        }
        rv = 1;
    }
    if rv > 0 {
        // SAFETY: `mdname` is writable for `mdname_sz` and `result` is NUL-terminated.
        unsafe { OPENSSL_strlcpy(mdname, result, mdname_sz) };
    }
    rv
}

#[allow(dead_code)]
// 7.4a-iii: `EVP_PKEY_can_sign` is its first live caller; 7.4b's four method classes then use it for every operation
/// `const char *evp_keymgmt_util_query_operation_name(EVP_KEYMGMT *keymgmt, int op_id)`.
///
/// Ask the method for the operation's name, and **fall back to the key type's own name** when it has
/// no callback or answers NULL — which is what makes a key type usable as an operation name without
/// the provider having to say so.
///
/// A NULL method answers NULL, so the two "no name" cases are distinguishable only by the method
/// being NULL rather than by the answer.
///
/// # Safety
/// `keymgmt` NULL or live.
pub(crate) unsafe fn evp_keymgmt_util_query_operation_name(
    keymgmt: *mut EvpKeyMgmt,
    op_id: c_int,
) -> *const c_char {
    if keymgmt.is_null() {
        return ptr::null();
    }
    // SAFETY: `keymgmt` is live.
    let mut name: *const c_char = match unsafe { (*keymgmt).query_operation_name } {
        // SAFETY: the callback is the provider's own and takes only the operation id.
        Some(f) => unsafe { f(op_id) },
        None => ptr::null(),
    };
    if name.is_null() {
        // SAFETY: `keymgmt` is live.
        name = unsafe { EVP_KEYMGMT_get0_name(keymgmt) };
    }
    name
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::keymgmt::EvpKeyMgmt;
    use crate::evp::pkey::EVP_PKEY_new;
    use core::sync::atomic::AtomicI32;

    /// A hand-built method with nothing but a name, so the cache's identity test can be read without
    /// a provider. Two of them with the same `name_id` and the same `prov` are the *same origin*
    /// even though they are different objects — which is the whole point of the second clause.
    fn a_hand_built_keymgmt(
        name_id: c_int,
        prov: *mut crate::provider::OsslProvider,
    ) -> EvpKeyMgmt {
        EvpKeyMgmt {
            id: 0,
            name_id,
            legacy_alg: 0,
            type_name: ptr::null_mut(),
            description: ptr::null(),
            prov,
            refcnt: AtomicI32::new(1),
            new: None,
            free: None,
            get_params: None,
            gettable_params: None,
            set_params: None,
            settable_params: None,
            gen_init: None,
            gen_set_template: None,
            gen_get_params: None,
            gen_gettable_params: None,
            gen_set_params: None,
            gen_settable_params: None,
            gen: None,
            gen_cleanup: None,
            load: None,
            query_operation_name: None,
            has_: None,
            validate: None,
            match_: None,
            import: None,
            import_types: None,
            import_types_ex: None,
            export: None,
            export_types: None,
            export_types_ex: None,
            dup: None,
        }
    }

    /// A fresh key is **blank**: `type` and `save_type` are `EVP_PKEY_NONE`, every provider field is
    /// NULL, and the four cached properties are zero — except the security category, which starts at
    /// **-1** only once `cache_keyinfo` has run, because it is the *provider's* initial value and not
    /// the struct's.
    #[test]
    fn a_new_key_is_blank_and_untyped() {
        // SAFETY: no preconditions.
        let pkey = unsafe { EVP_PKEY_new() };
        assert!(!pkey.is_null(), "the allocation is the only way this fails");
        // SAFETY: `pkey` is this test's own object.
        unsafe {
            assert_eq!((*pkey).type_, crate::runtime::obj::NID_undef);
            assert_eq!((*pkey).save_type, crate::runtime::obj::NID_undef);
            assert!((*pkey).keymgmt.is_null());
            assert!((*pkey).keydata.is_null());
            assert!((*pkey).operation_cache.is_null());
            assert_eq!((*pkey).dirty_cnt, 0);
            assert_eq!((*pkey).cache.bits, 0);
            assert_eq!(
                (*pkey).cache.security_category,
                0,
                "the struct's zero, not the provider's -1"
            );
            crate::evp::pkey::EVP_PKEY_free(pkey);
        }
    }

    /// `evp_keymgmt_util_clear_operation_cache` answers **1** for a NULL key and for a key with no
    /// cache, so "can this fail" has no answer other than no.
    #[test]
    fn clearing_a_cache_that_does_not_exist_succeeds() {
        // SAFETY: NULL is the first case the function's own guard covers.
        let answer = unsafe { evp_keymgmt_util_clear_operation_cache(ptr::null_mut()) };
        assert_eq!(answer, 1);

        // SAFETY: no preconditions.
        let pkey = unsafe { EVP_PKEY_new() };
        assert!(!pkey.is_null());
        // SAFETY: `pkey` is this test's own object.
        assert_eq!(unsafe { evp_keymgmt_util_clear_operation_cache(pkey) }, 1);
        // SAFETY: `pkey` is this test's own object.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
    }

    /// `evp_keymgmt_util_match`'s two-NULL answer is **1**, and one NULL against a live key is **0**.
    /// Both are contract: an empty comparison is a success and half a comparison is a difference.
    #[test]
    fn matching_two_absent_keys_succeeds() {
        // SAFETY: NULL is a documented input for every argument.
        let both_absent = unsafe { evp_keymgmt_util_match(ptr::null_mut(), ptr::null_mut(), 0) };
        assert_eq!(both_absent, 1, "two absent keys are equal");
        // SAFETY: no preconditions.
        let pkey = unsafe { EVP_PKEY_new() };
        assert!(!pkey.is_null());
        // SAFETY: one live key and one NULL is the second documented case.
        unsafe {
            assert_eq!(evp_keymgmt_util_match(pkey, ptr::null_mut(), 0), 0);
            assert_eq!(evp_keymgmt_util_match(ptr::null_mut(), pkey, 0), 0);
            crate::evp::pkey::EVP_PKEY_free(pkey);
        }
    }

    /// The cache's match is a **subset** test on the selection: an entry imported for all three
    /// selectable bits satisfies a request for any one of them, and an entry imported for one does not
    /// satisfy a request for all. That asymmetry is what makes the cache safe to consult for a
    /// narrower operation than the one that filled it.
    #[test]
    fn the_cache_match_is_a_subset_test() {
        // SAFETY: no preconditions.
        let pkey = unsafe { EVP_PKEY_new() };
        assert!(!pkey.is_null());
        let mut wide = a_hand_built_keymgmt(71, ptr::null_mut());
        let wide_ptr: *mut EvpKeyMgmt = ptr::addr_of_mut!(wide);
        /* A live byte of this frame standing in for key data: the cache only stores the pointer, and
         * a literal would be a fabricated address that `clippy` rightly refuses. */
        let mut keydata_byte: u8 = 0;
        let keydata: *mut c_void = ptr::addr_of_mut!(keydata_byte).cast::<c_void>();

        // SAFETY: `pkey` is this test's own object and the selection is a plain bit set.
        unsafe {
            assert_eq!(
                evp_keymgmt_util_cache_keydata(pkey, wide_ptr, keydata, 0x07),
                1
            );
            assert!(
                !evp_keymgmt_util_find_operation_cache(pkey, wide_ptr, 0x01).is_null(),
                "a narrower request is satisfied by a wider entry"
            );
            assert!(
                !evp_keymgmt_util_find_operation_cache(pkey, wide_ptr, 0x07).is_null(),
                "an identical request is satisfied"
            );
            assert!(
                evp_keymgmt_util_find_operation_cache(pkey, wide_ptr, 0x08).is_null(),
                "a request the entry does not cover is not satisfied"
            );
            /* A different method with a different name id is not the same origin. */
            let mut other = a_hand_built_keymgmt(72, ptr::null_mut());
            let other_ptr: *mut EvpKeyMgmt = ptr::addr_of_mut!(other);
            assert!(
                evp_keymgmt_util_find_operation_cache(pkey, other_ptr, 0x01).is_null(),
                "a different name id is a different origin"
            );
            /* The same name id and the same provider is the same origin even for a different
             * object, which is the clause that survives a flushed fetch cache. */
            let mut same_origin = a_hand_built_keymgmt(71, ptr::null_mut());
            let same_origin_ptr: *mut EvpKeyMgmt = ptr::addr_of_mut!(same_origin);
            assert!(
                !evp_keymgmt_util_find_operation_cache(pkey, same_origin_ptr, 0x01).is_null(),
                "the same name id and provider is the same origin"
            );
            evp_keymgmt_util_clear_operation_cache(pkey);
            crate::evp::pkey::EVP_PKEY_free(pkey);
        }
    }
}
