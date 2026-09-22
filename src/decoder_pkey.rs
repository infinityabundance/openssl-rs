//! Phase 10 — `crypto/encode_decode/decoder_pkey.c`: the decoder **cache** and the four
//! `OSSL_DECODER_CTX_set_passphrase*` setters (D365).
//!
//! This is the third decoder unit and the previous brief's item 1. The cache is the decoder's twin
//! of D357's encoder store, with one structural difference that decides the whole shape: it is an
//! `LHASH` **keyed by a struct** rather than a method store keyed by a name-map id, and its entries
//! own an `OSSL_DECODER_CTX *template`. That ownership is why it could not land before
//! `src/decoder_lib.rs`: `decoder_cache_entry_free` (`:681-691`) calls `OSSL_DECODER_CTX_free`,
//! which is `decoder_meth.c`'s export over `ossl_decoder_instance_free`, `decoder_lib.c`'s. D363
//! measured that order; this unit is its first consequence.
//!
//! ## The pkey half landed with the chain it builds (D367)
//!
//! `decoder_construct_pkey` (`:71-202`), `decoder_clean_pkey_construct_arg` (`:204-233`),
//! `collect_decoder_keymgmt` (`:235-311`), `collect_decoder` (`:313-362`), `check_keymgmt`
//! (`:364-401`), `collect_keymgmt` (`:403-429`), `ossl_decoder_ctx_setup_for_pkey` (`:431-558`),
//! `keymgmt_dup` (`:560-573`), `ossl_decoder_ctx_for_pkey_dup` (`:575-660`), the cache's own lookup
//! (`:825-960`) and `OSSL_DECODER_CTX_new_for_pkey` (`:820-969`) are below. They are one path:
//! `new_for_pkey` calls `ossl_decoder_ctx_for_pkey_dup` for its cache lookup and
//! `ossl_decoder_ctx_setup_for_pkey` for its miss, the setup calls `collect_keymgmt` and
//! `collect_decoder`, and those register `decoder_construct_pkey` through
//! `OSSL_DECODER_CTX_set_construct`. They waited on `decoder_lib.c`'s chain-building block, which
//! landed in D367; that block is what this half's `OSSL_DECODER_CTX_add_extra` call reaches.
//!
//! ## The cache is a template cache, and `new_for_pkey` never returns the template
//!
//! The entry owns an `OSSL_DECODER_CTX` that was **set up once** and is duplicated for every
//! subsequent call through `ossl_decoder_ctx_for_pkey_dup`. That is why the entry's `template` is
//! never handed to a caller: the function ends with the dup, under the same read lock it took for
//! the lookup, or after the insert path has upgraded to a write lock. The two locks are the
//! authority's and the `write_lock` failure clears `ctx` before the `err:` label frees the new
//! entry, so a lock failure never double-frees the template.
//!
//! ## The cache is locked, and the lock's failure is answered rather than asserted
//!
//! `ossl_decoder_cache_flush` takes `CRYPTO_THREAD_write_lock` and, when it fails, raises
//! `ERR_R_OSSL_DECODER_LIB` and answers **0** -- where its three sibling store bridges answer 1 for
//! an absent store. That asymmetry is the authority's (`:805-816`) and is why the bridge in
//! `src/provider/stores.rs` is a delegation rather than a copy.
//!
//! ## Slot 11 and slot 20 are filled here, in the authority's own order
//!
//! `crypto/context.c:123-137` builds `decoder_store`, then `decoder_cache`, then `encoder_store`,
//! and `context_deinit_objs` releases them in the same order. `src/context/mod.rs` now does the
//! same, so this crate's three decoder bridges in `src/provider/stores.rs` delegate for real and
//! the `assert_slot_unfilled` invariant no longer covers them.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_ulong, c_void};
use core::mem::size_of;
use core::ptr;

use crate::context::namemap::{ossl_namemap_name2num, ossl_namemap_stored};
use crate::decoder_lib::{
    ossl_decoder_ctx_add_decoder_inst, ossl_decoder_ctx_set_harderr, ossl_decoder_instance_dup,
    ossl_decoder_instance_free, ossl_decoder_instance_new, OSSL_DECODER_CTX_add_extra,
    OSSL_DECODER_CTX_get_cleanup, OSSL_DECODER_CTX_get_construct,
    OSSL_DECODER_CTX_get_construct_data, OSSL_DECODER_CTX_get_num_decoders,
    OSSL_DECODER_CTX_set_cleanup, OSSL_DECODER_CTX_set_construct,
    OSSL_DECODER_CTX_set_construct_data, OSSL_DECODER_CTX_set_input_structure,
    OSSL_DECODER_CTX_set_input_type, OSSL_DECODER_CTX_set_selection,
    OSSL_DECODER_INSTANCE_get_decoder, OSSL_DECODER_INSTANCE_get_decoder_ctx,
};
use crate::decoder_meth::{
    ossl_decoder_parsed_properties, OSSL_DECODER_CTX_free, OSSL_DECODER_CTX_new,
    OSSL_DECODER_CTX_set_params, OSSL_DECODER_do_all_provided, OSSL_DECODER_get0_provider,
    OsslDecoder, OsslDecoderCtx, OsslDecoderInstance,
};
use crate::evp::keymgmt::{
    evp_keymgmt_freedata, evp_keymgmt_has_load, evp_keymgmt_load, EVP_KEYMGMT_do_all_provided,
    EVP_KEYMGMT_fetch, EVP_KEYMGMT_free, EVP_KEYMGMT_get0_provider, EVP_KEYMGMT_is_a,
    EVP_KEYMGMT_up_ref, EvpKeyMgmt,
};
use crate::evp::keymgmt_lib::{
    evp_keymgmt_util_make_pkey, evp_keymgmt_util_try_import, TryImportData,
};
use crate::evp::pkey::{EvpPkey, OSSL_KEYMGMT_SELECT_ALL_BITS};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_utf8_string,
    OSSL_PARAM_locate_const, OsslParam, OSSL_PARAM_OCTET_STRING,
};
use crate::passphrase::{
    ossl_pw_set_ossl_passphrase_cb, ossl_pw_set_passphrase, ossl_pw_set_pem_password_cb,
    ossl_pw_set_ui_method, OsslPassphraseCallback,
};
use crate::property::globals::ossl_ctx_global_properties;
use crate::property::list::OsslPropertyList;
use crate::property::parse::{
    ossl_parse_query, ossl_property_free, ossl_property_match_count, ossl_property_merge,
};
use crate::provider::stores::OSSL_LIB_CTX_DECODER_CACHE_INDEX;
use crate::provider::{OSSL_PROVIDER_get0_provider_ctx, OsslProvider};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::lhash::{
    ossl_lh_strcasehash, OPENSSL_LH_doall, OPENSSL_LH_error, OPENSSL_LH_flush, OPENSSL_LH_free,
    OPENSSL_LH_insert, OPENSSL_LH_new, OPENSSL_LH_retrieve, OpenSslLhash,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_deep_copy, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};
use crate::ui::ui_lib::UiMethod;

/// `int OSSL_DECODER_CTX_set_passphrase(OSSL_DECODER_CTX *ctx, const unsigned char *kstr,
/// size_t klen)` — `decoder_pkey.c:26-31`.
///
/// # Safety
/// `ctx` must be live; `kstr` readable for `klen` bytes.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_passphrase(
    ctx: *mut OsslDecoderCtx,
    kstr: *const c_uchar,
    klen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and its embedded passphrase data is its own.
    unsafe { ossl_pw_set_passphrase(ptr::addr_of_mut!((*ctx).pwdata), kstr, klen) }
}

/// `int OSSL_DECODER_CTX_set_passphrase_ui(OSSL_DECODER_CTX *ctx, const UI_METHOD *ui_method,
/// void *ui_data)` — `decoder_pkey.c:33-38`.
///
/// # Safety
/// `ctx` must be live; `ui_method` and `ui_data` are the caller's own.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_passphrase_ui(
    ctx: *mut OsslDecoderCtx,
    ui_method: *const UiMethod,
    ui_data: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live and its embedded passphrase data is its own.
    unsafe { ossl_pw_set_ui_method(ptr::addr_of_mut!((*ctx).pwdata), ui_method, ui_data) }
}

/// `int OSSL_DECODER_CTX_set_pem_password_cb(OSSL_DECODER_CTX *ctx, pem_password_cb *cb,
/// void *cbarg)` — `decoder_pkey.c:40-44`.
///
/// # Safety
/// `ctx` must be live; `cb` is the caller's callback.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_pem_password_cb(
    ctx: *mut OsslDecoderCtx,
    cb: Option<crate::evp::pem_bridge::PemPasswordCb>,
    cbarg: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live and its embedded passphrase data is its own.
    unsafe { ossl_pw_set_pem_password_cb(ptr::addr_of_mut!((*ctx).pwdata), cb, cbarg) }
}

/// `int OSSL_DECODER_CTX_set_passphrase_cb(OSSL_DECODER_CTX *ctx, OSSL_PASSPHRASE_CALLBACK *cb,
/// void *cbarg)` — `decoder_pkey.c:46-51`.
///
/// # Safety
/// `ctx` must be live; `cb` is the caller's callback.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_passphrase_cb(
    ctx: *mut OsslDecoderCtx,
    cb: Option<OsslPassphraseCallback>,
    cbarg: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live and its embedded passphrase data is its own.
    unsafe { ossl_pw_set_ossl_passphrase_cb(ptr::addr_of_mut!((*ctx).pwdata), cb, cbarg) }
}

/// `DECODER_CACHE_ENTRY` — `decoder_pkey.c:664-672`.
///
/// The cache's key and its payload at once: the five fields the hash and the comparison read, and
/// the `template` context the entry owns. The four strings are **copies** the entry frees; the
/// template is a real context.
#[repr(C)]
struct DecoderCacheEntry {
    /// `char *input_type` — owned.
    input_type: *mut c_char,
    /// `char *input_structure` — owned, may be NULL.
    input_structure: *mut c_char,
    /// `char *keytype` — owned, may be NULL.
    keytype: *mut c_char,
    /// `int selection`.
    selection: c_int,
    /// `char *propquery` — owned, may be NULL.
    propquery: *mut c_char,
    /// `OSSL_DECODER_CTX *template` — owned.
    template: *mut OsslDecoderCtx,
}

/// `DECODER_CACHE` — `decoder_pkey.c:676-679`.
#[repr(C)]
struct DecoderCache {
    /// `CRYPTO_RWLOCK *lock`.
    lock: *mut CryptoRwlock,
    /// `LHASH_OF(DECODER_CACHE_ENTRY) *hashtable`.
    hashtable: *mut OpenSslLhash,
}

/// `static void decoder_cache_entry_free(DECODER_CACHE_ENTRY *entry)` — `decoder_pkey.c:681-691`.
///
/// Four string releases and one context release, in the authority's order. The entry is reached by
/// `lh_DECODER_CACHE_ENTRY_doall` from both `ossl_decoder_cache_free` and
/// `ossl_decoder_cache_flush`, so it is the doall callback's `void *` shape rather than a
/// destructor of its own.
///
/// # Safety
/// `entry` must be NULL or a live entry this crate allocated.
unsafe extern "C" fn decoder_cache_entry_free(entry: *mut c_void) {
    let entry = entry.cast::<DecoderCacheEntry>();
    if entry.is_null() {
        return;
    }
    // SAFETY: `entry` is live, and each of the five pointers is the entry's own -- the authority
    // releases all four strings and the template unconditionally, `free` accepting NULL.
    unsafe {
        CRYPTO_free((*entry).input_type.cast(), ptr::null(), 0);
        CRYPTO_free((*entry).input_structure.cast(), ptr::null(), 0);
        CRYPTO_free((*entry).keytype.cast(), ptr::null(), 0);
        CRYPTO_free((*entry).propquery.cast(), ptr::null(), 0);
        OSSL_DECODER_CTX_free((*entry).template);
        CRYPTO_free(entry.cast(), ptr::null(), 0);
    }
}

/// `static unsigned long decoder_cache_entry_hash(const DECODER_CACHE_ENTRY *cache)` —
/// `decoder_pkey.c:693-717`.
///
/// Four conditional case-insensitive hashes folded by `hash * 23 +`, then `hash ^= selection`. The
/// NULL arms are **0**, not a hash of the empty string, which is what makes a NULL and an empty
/// string the same key -- and the crate's `ossl_lh_strcasehash` answers 0 for both, so the arm is
/// written as the authority wrote it and the equivalence is the same on both sides.
///
/// # Safety
/// `cache` must be a live entry, or the comparison's own first argument shape.
unsafe extern "C" fn decoder_cache_entry_hash(cache: *const c_void) -> c_ulong {
    let cache = cache.cast::<DecoderCacheEntry>();
    let mut hash: c_ulong = 17;
    // SAFETY: `cache` is the table's own key per the contract; the four strings are NULL or
    // NUL-terminated copies the entry owns.
    unsafe {
        hash = hash
            .wrapping_mul(23)
            .wrapping_add(if (*cache).propquery.is_null() {
                0
            } else {
                ossl_lh_strcasehash((*cache).propquery)
            });
        hash = hash
            .wrapping_mul(23)
            .wrapping_add(if (*cache).input_structure.is_null() {
                0
            } else {
                ossl_lh_strcasehash((*cache).input_structure)
            });
        hash = hash
            .wrapping_mul(23)
            .wrapping_add(if (*cache).input_type.is_null() {
                0
            } else {
                ossl_lh_strcasehash((*cache).input_type)
            });
        hash = hash
            .wrapping_mul(23)
            .wrapping_add(if (*cache).keytype.is_null() {
                0
            } else {
                ossl_lh_strcasehash((*cache).keytype)
            });

        hash ^= (*cache).selection as c_ulong;
    }
    hash
}

/// `static ossl_inline int nullstrcmp(const char *a, const char *b, int casecmp)` —
/// `decoder_pkey.c:719-736`.
///
/// The three-way NULL-aware comparison: two NULLs are equal, one NULL sorts **last** (`a` NULL
/// against a value is **1**, not -1), and otherwise `OPENSSL_strcasecmp` or `strcmp` by `casecmp`.
///
/// # Safety
/// `a` and `b` must each be NULL or NUL-terminated.
unsafe fn nullstrcmp(a: *const c_char, b: *const c_char, casecmp: c_int) -> c_int {
    if a.is_null() || b.is_null() {
        if a.is_null() {
            return if b.is_null() { 0 } else { 1 };
        }
        return -1;
    }
    if casecmp != 0 {
        // SAFETY: both are NUL-terminated per the contract.
        unsafe { OPENSSL_strcasecmp(a, b) }
    } else {
        // SAFETY: both are NUL-terminated per the contract.
        unsafe { crate::runtime::bio::sys::strcmp(a, b) }
    }
}

/// `static int decoder_cache_entry_cmp(const DECODER_CACHE_ENTRY *a,
/// const DECODER_CACHE_ENTRY *b)` — `decoder_pkey.c:738-761`.
///
/// `selection` first, then `keytype`, `input_type` and `input_structure` **case-insensitively**,
/// then `propquery` case-*sensitively* -- the asymmetry is the authority's and is the reason
/// [`nullstrcmp`] takes the flag rather than reading a global.
///
/// # Safety
/// `a` and `b` must be live entries.
unsafe extern "C" fn decoder_cache_entry_cmp(a: *const c_void, b: *const c_void) -> c_int {
    let a = a.cast::<DecoderCacheEntry>();
    let b = b.cast::<DecoderCacheEntry>();
    // SAFETY: both are live entries per the contract.
    unsafe {
        if (*a).selection != (*b).selection {
            return if (*a).selection < (*b).selection {
                -1
            } else {
                1
            };
        }

        let cmp = nullstrcmp((*a).keytype, (*b).keytype, 1);
        if cmp != 0 {
            return cmp;
        }
        let cmp = nullstrcmp((*a).input_type, (*b).input_type, 1);
        if cmp != 0 {
            return cmp;
        }
        let cmp = nullstrcmp((*a).input_structure, (*b).input_structure, 1);
        if cmp != 0 {
            return cmp;
        }
        nullstrcmp((*a).propquery, (*b).propquery, 0)
    }
}

/// `void *ossl_decoder_cache_new(OSSL_LIB_CTX *ctx)` — `decoder_pkey.c:763-784`.
///
/// The lock first, then the table; each failure releases what was built and answers NULL. The
/// `ctx` argument is the libctx the *caller* has, and the constructor does not read it -- the
/// authority's signature keeps it for its siblings' shape.
///
/// # Safety
/// No preconditions; the answer is NULL or a uniquely-owned cache.
pub(crate) unsafe fn ossl_decoder_cache_new(_ctx: *mut c_void) -> *mut c_void {
    // The constructor asks only for a block of the cache's size.
    let cache =
        CRYPTO_malloc(core::mem::size_of::<DecoderCache>(), ptr::null(), 0).cast::<DecoderCache>();
    if cache.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the lock constructor answers a live lock or NULL.
    let lock = CRYPTO_THREAD_lock_new();
    if lock.is_null() {
        // SAFETY: `cache` is live and owned here.
        unsafe { CRYPTO_free(cache.cast(), ptr::null(), 0) };
        return ptr::null_mut();
    }
    // SAFETY: `cache` is live and uniquely owned here.
    unsafe { (*cache).lock = lock };

    // SAFETY: the two callbacks are `unsafe extern "C"` items of the table's own key shape.
    let hashtable = OPENSSL_LH_new(
        Some(decoder_cache_entry_hash),
        Some(decoder_cache_entry_cmp),
    );
    if hashtable.is_null() {
        // SAFETY: `lock` and `cache` are this call's own.
        unsafe {
            CRYPTO_THREAD_lock_free(lock);
            CRYPTO_free(cache.cast(), ptr::null(), 0);
        }
        return ptr::null_mut();
    }
    // SAFETY: `cache` is live.
    unsafe { (*cache).hashtable = hashtable };

    cache.cast::<c_void>()
}

/// `void ossl_decoder_cache_free(void *vcache)` — `decoder_pkey.c:786-795`.
///
/// Four releases in the authority's order: every entry through the doall callback, the table, the
/// lock, then the cache.
///
/// # Safety
/// `vcache` must be a live cache this crate allocated.
pub(crate) unsafe fn ossl_decoder_cache_free(vcache: *mut c_void) {
    let cache = vcache.cast::<DecoderCache>();
    if cache.is_null() {
        return;
    }
    // SAFETY: `cache` is live and its table and lock are its own.
    unsafe {
        OPENSSL_LH_doall((*cache).hashtable, Some(decoder_cache_entry_free));
        OPENSSL_LH_free((*cache).hashtable);
        CRYPTO_THREAD_lock_free((*cache).lock);
        CRYPTO_free(cache.cast(), ptr::null(), 0);
    }
}

/// `int ossl_decoder_cache_flush(OSSL_LIB_CTX *libctx)` — `decoder_pkey.c:800-816`.
///
/// The one bridge whose absent case answers **0** -- the authority's own `if (cache == NULL) return
/// 0;` -- and the one whose body takes a **write lock**. A lock failure raises
/// `ERR_R_OSSL_DECODER_LIB` and answers 0; success empties the table without releasing it.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn ossl_decoder_cache_flush(libctx: *mut c_void) -> c_int {
    let cache = crate::context::lib_ctx_get_data(libctx, OSSL_LIB_CTX_DECODER_CACHE_INDEX)
        .cast::<DecoderCache>();
    if cache.is_null() {
        return 0;
    }

    // SAFETY: `cache` is live and its lock is its own.
    if unsafe { CRYPTO_THREAD_write_lock((*cache).lock) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_PKEY_809) };
        return 0;
    }

    // SAFETY: `cache` is live, the lock is held, and the table is its own.
    unsafe {
        OPENSSL_LH_doall((*cache).hashtable, Some(decoder_cache_entry_free));
        OPENSSL_LH_flush((*cache).hashtable);
        CRYPTO_THREAD_unlock((*cache).lock);
    }
    1
}

// ---------------------------------------------------------------------------
// The pkey half — `decoder_pkey.c:60-660`, `:820-969`
// ---------------------------------------------------------------------------

/// `OSSL_DECODER_PARAM_PROPERTIES` — `core_names.h`, the string `"properties"`, the same
/// `OSSL_ALG_PARAM_PROPERTIES` spelling `src/encoder_pkey.rs` carries.
const OSSL_DECODER_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_TYPE` — `core_names.h:358`, the string `"data-type"`.
const OSSL_OBJECT_PARAM_DATA_TYPE: *const c_char = c"data-type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_STRUCTURE` — `core_names.h:357`, the string `"data-structure"`.
const OSSL_OBJECT_PARAM_DATA_STRUCTURE: *const c_char = c"data-structure".as_ptr();
/// `OSSL_OBJECT_PARAM_REFERENCE` — `core_names.h:359`, the string `"reference"`.
const OSSL_OBJECT_PARAM_REFERENCE: *const c_char = c"reference".as_ptr();

/// `struct decoder_pkey_data_st` — `decoder_pkey.c:60-69`.
///
/// The construct data: the stack of candidate key managements, the object type the last decoder
/// reported, and **the slot the constructed `EVP_PKEY` is written through**. `object` is NULL in the
/// template the cache holds and non-NULL in every duplicate `ossl_decoder_ctx_for_pkey_dup` makes,
/// which is why `decoder_construct_pkey` dereferences it without a test.
struct DecoderPkeyData {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *propq` — owned, may be NULL.
    propq: *mut c_char,
    /// `int selection`.
    selection: c_int,
    /// `STACK_OF(EVP_KEYMGMT) *keymgmts` — owned.
    keymgmts: *mut OpenSslStack,
    /// `char *object_type` — owned, may be NULL.
    object_type: *mut c_char,
    /// `void **object` — where the result ends up.
    object: *mut *mut c_void,
    /// `OSSL_DECODER_CTX *ctx` — the parent context.
    ctx: *mut OsslDecoderCtx,
}

/// `struct collect_data_st` — `decoder_pkey.c:216-229`.
struct CollectData {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `OSSL_DECODER_CTX *ctx`.
    ctx: *mut OsslDecoderCtx,
    /// `const char *keytype` — the keytype requested, if any.
    keytype: *const c_char,
    /// `int keytype_id` — the key management name id, or 0.
    keytype_id: c_int,
    /// `int sm2_id` — the SM2 name id when the keytype is EC, else 0.
    sm2_id: c_int,
    /// `int total` — number of matching results.
    total: c_int,
    /// `char error_occurred`.
    error_occurred: c_char,
    /// `char keytype_resolved`.
    keytype_resolved: c_char,
    /// `OSSL_PROPERTY_LIST *pq` — the merged property query, borrowed.
    pq: *mut OsslPropertyList,
    /// `STACK_OF(EVP_KEYMGMT) *keymgmts` — borrowed from the setup's frame.
    keymgmts: *mut OpenSslStack,
}

/// `sk_EVP_KEYMGMT_pop_free`'s destructor: the crate's stack frees elements through a `void *`
/// callback, so `EVP_KEYMGMT_free` is reached through this thunk.
unsafe extern "C" fn keymgmt_free_thunk(p: *mut c_void) {
    // SAFETY: the stack's element is an `EvpKeyMgmt` whose reference the stack owns.
    unsafe { EVP_KEYMGMT_free(p.cast::<EvpKeyMgmt>()) };
}

/// `sk_OSSL_DECODER_INSTANCE_deep_copy`'s copy function: `ossl_decoder_instance_dup` has the typed
/// shape, so it is reached through this `*const c_void -> *mut c_void` adapter.
unsafe extern "C" fn decoder_instance_dup_thunk(src: *const c_void) -> *mut c_void {
    // SAFETY: the stack's element is a live `OsslDecoderInstance`.
    unsafe { ossl_decoder_instance_dup(src.cast::<OsslDecoderInstance>()).cast::<c_void>() }
}

/// `sk_OSSL_DECODER_INSTANCE_deep_copy`'s free function.
unsafe extern "C" fn decoder_instance_free_thunk(p: *mut c_void) {
    // SAFETY: the stack's element is a live `OsslDecoderInstance` the copy owns.
    unsafe { ossl_decoder_instance_free(p.cast::<OsslDecoderInstance>()) };
}

/// `static EVP_KEYMGMT *keymgmt_dup(const EVP_KEYMGMT *keymgmt)` — `decoder_pkey.c:560-566`.
///
/// The `const` on the authority's parameter is why the crate needs an adapter: taking a reference
/// is all this does, so the answer is the same pointer.
///
/// # Safety
/// `src` must be a live `EvpKeyMgmt` the stack owns an element for.
unsafe extern "C" fn keymgmt_dup_thunk(src: *const c_void) -> *mut c_void {
    let keymgmt = src.cast_mut().cast::<EvpKeyMgmt>();
    // SAFETY: `keymgmt` is live per the contract.
    unsafe {
        if EVP_KEYMGMT_up_ref(keymgmt) == 0 {
            ptr::null_mut()
        } else {
            keymgmt.cast::<c_void>()
        }
    }
}

/// `static int decoder_construct_pkey(OSSL_DECODER_INSTANCE *decoder_inst,
/// const OSSL_PARAM *params, void *construct_data)` — `decoder_pkey.c:71-202`.
///
/// The provider-reference path: the object is accepted only as an `OSSL_OBJECT_PARAM_REFERENCE`,
/// and the key management is chosen from the same provider as the decoder when one has a `load`
/// method, else fetched by the object's type. A key management from a **different** provider takes
/// the export/import pair instead. When both fail, `keydata` stays NULL and the context is marked
/// hard-error; the answer is then the state of `*data->object`, which the caller's constructor
/// contract turns into the walk's stop condition.
///
/// # Safety
/// `decoder_inst` must be live; `params` a terminated array; `construct_data` a live
/// [`DecoderPkeyData`].
unsafe extern "C" fn decoder_construct_pkey(
    decoder_inst: *mut OsslDecoderInstance,
    params: *const OsslParam,
    construct_data: *mut c_void,
) -> c_int {
    let data = construct_data.cast::<DecoderPkeyData>();
    // SAFETY: `decoder_inst` is live per the contract.
    let decoder = unsafe { OSSL_DECODER_INSTANCE_get_decoder(decoder_inst) };
    // SAFETY: `decoder_inst` is live.
    let decoderctx = unsafe { OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst) };
    // SAFETY: `decoder` is live.
    let decoder_prov = unsafe { OSSL_DECODER_get0_provider(decoder) };
    let mut keymgmt: *mut EvpKeyMgmt = ptr::null_mut();
    let mut keymgmt_prov: *const OsslProvider = ptr::null();
    let object_ref: *mut c_void;
    let object_ref_sz: usize;

    // SAFETY: `params` is a terminated array.
    let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE) };
    if !p.is_null() {
        let mut object_type: *mut c_char = ptr::null_mut();
        // SAFETY: `p` is live and `object_type` is this frame's own slot; `max_len` 0 asks the
        // descriptor to allocate the copy.
        if unsafe { OSSL_PARAM_get_utf8_string(p, ptr::addr_of_mut!(object_type), 0) } == 0 {
            return 0;
        }
        // SAFETY: `data` is live and its old `object_type` is the one it owns.
        unsafe {
            CRYPTO_free((*data).object_type.cast(), ptr::null(), 0);
            (*data).object_type = object_type;
        }
    }

    /*
     * For stuff that should end up in an EVP_PKEY, we only accept an object reference for the
     * moment. This enforces that the key data itself remains with the provider.
     */
    // SAFETY: `params` is a terminated array.
    let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE) };
    // SAFETY: `p` is NULL or a live descriptor.
    if p.is_null() || unsafe { (*p).data_type } != OSSL_PARAM_OCTET_STRING {
        return 0;
    }
    // SAFETY: `p` is live and its data is an octet string of `data_size` bytes.
    unsafe {
        object_ref = (*p).data;
        object_ref_sz = (*p).data_size;
    }

    /*
     * First, we try to find a keymgmt that comes from the same provider as the decoder that passed
     * the params.
     */
    // SAFETY: `data` is live and its keymgmt stack is its own.
    let end = unsafe { OPENSSL_sk_num((*data).keymgmts) };
    let mut i = 0;
    while i < end {
        // SAFETY: `i` is a valid index of the live stack.
        keymgmt = unsafe { OPENSSL_sk_value((*data).keymgmts, i) }.cast::<EvpKeyMgmt>();
        // SAFETY: `keymgmt` is live.
        keymgmt_prov = unsafe { EVP_KEYMGMT_get0_provider(keymgmt) };

        // SAFETY: `keymgmt` is live.
        let has_load = unsafe { evp_keymgmt_has_load(keymgmt) } != 0;
        // SAFETY: `keymgmt` is live and the object type is NULL or NUL-terminated.
        let is_a = unsafe { EVP_KEYMGMT_is_a(keymgmt, (*data).object_type) } != 0;
        if keymgmt_prov == decoder_prov && has_load && is_a {
            break;
        }
        i += 1;
    }
    if i < end {
        /* To allow it to be freed further down */
        // SAFETY: `keymgmt` is live per the loop's break.
        if unsafe { EVP_KEYMGMT_up_ref(keymgmt) } == 0 {
            return 0;
        }
    } else {
        // SAFETY: `data` is live; the two strings and the libctx are the caller's.
        keymgmt = unsafe { EVP_KEYMGMT_fetch((*data).libctx, (*data).object_type, (*data).propq) };
        if !keymgmt.is_null() {
            // SAFETY: `keymgmt` is live.
            keymgmt_prov = unsafe { EVP_KEYMGMT_get0_provider(keymgmt) };
        }
    }

    if !keymgmt.is_null() {
        let mut pkey: *mut EvpPkey = ptr::null_mut();

        /*
         * If the EVP_KEYMGMT and the OSSL_DECODER are from the same provider, we assume that the
         * KEYMGMT has a key loading function that can handle the provider reference we hold.
         * Otherwise, we export from the decoder and import the result in the keymgmt.
         */
        let keydata: *mut c_void = if keymgmt_prov == decoder_prov {
            // SAFETY: `keymgmt` is live and the reference is the decoder's own volatile block.
            unsafe { evp_keymgmt_load(keymgmt, object_ref, object_ref_sz) }
        } else {
            // SAFETY: `data` is live.
            let selection = unsafe { (*data).selection };
            let mut import_data = TryImportData {
                keymgmt,
                keydata: ptr::null_mut(),
                selection: if selection == 0 {
                    OSSL_KEYMGMT_SELECT_ALL_BITS
                } else {
                    selection
                },
            };

            /*
             * No need to check for errors here, the value of |import_data.keydata| is as much an
             * indicator.
             */
            // SAFETY: `decoder` is live, the reference is the caller's, and `import_data` is this
            // frame's own.
            unsafe {
                if let Some(export_object) = (*decoder).export_object {
                    export_object(
                        decoderctx,
                        object_ref,
                        object_ref_sz,
                        Some(evp_keymgmt_util_try_import),
                        ptr::addr_of_mut!(import_data).cast::<c_void>(),
                    );
                }
            }
            import_data.keydata
        };
        /*
         * When load or import fails, because this is not an acceptable key (despite the provided
         * key material being syntactically valid), the reason why the key is rejected would be
         * lost, unless we signal a hard error, and suppress resetting for another try.
         */
        if keydata.is_null() {
            // SAFETY: `data` is live and its parent context is its own field.
            unsafe { ossl_decoder_ctx_set_harderr((*data).ctx) };
        }

        if !keydata.is_null() {
            // SAFETY: `keymgmt` and `keydata` are live and belong together.
            pkey = unsafe { evp_keymgmt_util_make_pkey(keymgmt, keydata) };
            if pkey.is_null() {
                // SAFETY: `keymgmt` and `keydata` are live.
                unsafe { evp_keymgmt_freedata(keymgmt, keydata) };
            }
        }

        // SAFETY: `data` is live and `object` is the slot the duplicate set up for it.
        unsafe { *(*data).object = pkey.cast::<c_void>() };

        /*
         * evp_keymgmt_util_make_pkey() increments the reference count when assigning the EVP_PKEY,
         * so we can free the keymgmt here.
         */
        // SAFETY: `keymgmt` is live.
        unsafe { EVP_KEYMGMT_free(keymgmt) };
    }
    /*
     * We successfully looked through, |*ctx->object| determines if we actually found something.
     */
    // SAFETY: `data` is live and `object` is the slot the duplicate set up for it.
    c_int::from(!unsafe { *(*data).object }.is_null())
}

/// `static void decoder_clean_pkey_construct_arg(void *construct_data)` —
/// `decoder_pkey.c:204-214`.
///
/// Four releases and a NULL test: the keymgmt stack through its own destructor, then the property
/// query copy, the recorded object type, and the block. It is reached from the constructor's
/// `err:` label and from `OSSL_DECODER_CTX_new_for_pkey`, so it must accept NULL.
///
/// # Safety
/// `construct_data` must be NULL or a live [`DecoderPkeyData`] this crate allocated.
unsafe extern "C" fn decoder_clean_pkey_construct_arg(construct_data: *mut c_void) {
    let data = construct_data.cast::<DecoderPkeyData>();
    if data.is_null() {
        return;
    }
    // SAFETY: `data` is live and each field is its own allocation.
    unsafe {
        OPENSSL_sk_pop_free((*data).keymgmts, Some(keymgmt_free_thunk));
        CRYPTO_free((*data).propq.cast(), ptr::null(), 0);
        CRYPTO_free((*data).object_type.cast(), ptr::null(), 0);
        CRYPTO_free(construct_data, ptr::null(), 0);
    }
}

/// `static int collect_decoder_keymgmt(EVP_KEYMGMT *keymgmt, OSSL_DECODER *decoder, void *provctx,
/// struct collect_data_st *data)` — `decoder_pkey.c:235-311`.
///
/// The name-map ids must agree, the input types must be compatible (**except** that a `DER`
/// decoder is accepted when the start input type is `PEM` -- that pairing is the authority's and is
/// not a general case), and the property match must not be negative. Only then is an instance
/// built and appended.
///
/// # Safety
/// `keymgmt`, `decoder` and `data` must all be live.
unsafe extern "C" fn collect_decoder_keymgmt(
    keymgmt: *mut EvpKeyMgmt,
    decoder: *mut OsslDecoder,
    provctx: *mut c_void,
    data: *mut CollectData,
) -> c_int {
    /*
     * We already checked the EVP_KEYMGMT is applicable in check_keymgmt so we don't check it again
     * here.
     */

    // SAFETY: both are live per the contract.
    if unsafe { (*keymgmt).name_id } != unsafe { (*decoder).base.id } {
        /* Mismatch is not an error, continue. */
        return 0;
    }

    // SAFETY: `decoder` is live.
    let decoderctx = match unsafe { (*decoder).newctx } {
        // SAFETY: `newctx` is a live provider callback and `provctx` is its context.
        Some(newctx) => unsafe { newctx(provctx) },
        None => ptr::null_mut(),
    };
    if decoderctx.is_null() {
        // SAFETY: `data` is live.
        unsafe { (*data).error_occurred = 1 };
        return 0;
    }

    // SAFETY: `decoder` and `decoderctx` are live and belong together.
    let di = unsafe { ossl_decoder_instance_new(decoder, decoderctx) };
    if di.is_null() {
        // SAFETY: `decoder` is live and `decoderctx` is this frame's own.
        unsafe {
            if let Some(freectx) = (*decoder).freectx {
                freectx(decoderctx);
            }
            (*data).error_occurred = 1;
        }
        return 0;
    }

    /*
     * Input types must be compatible, but we must accept DER encoders when the start input type is
     * "PEM".
     */
    // SAFETY: `data` is live and `di`'s input type is the instance's own string.
    unsafe {
        if !(*(*data).ctx).start_input_type.is_null()
            && !(*di).input_type.is_null()
            && OPENSSL_strcasecmp((*di).input_type, (*(*data).ctx).start_input_type) != 0
            && (OPENSSL_strcasecmp((*di).input_type, c"DER".as_ptr()) != 0
                || OPENSSL_strcasecmp((*(*data).ctx).start_input_type, c"PEM".as_ptr()) != 0)
        {
            /* Mismatch is not an error, continue. */
            ossl_decoder_instance_free(di);
            return 0;
        }
    }

    /*
     * Get the property match score so the decoders can be prioritized later.
     */
    // SAFETY: `decoder` is live.
    let props = unsafe { ossl_decoder_parsed_properties(decoder) };
    // SAFETY: `data` is live; both property lists are live or NULL.
    unsafe {
        if !(*data).pq.is_null() && !props.is_null() {
            (*di).score = ossl_property_match_count((*data).pq, props);
            /*
             * Mismatch of mandatory properties is not an error, the decoder is just ignored,
             * continue.
             */
            if (*di).score < 0 {
                ossl_decoder_instance_free(di);
                return 0;
            }
        }

        if ossl_decoder_ctx_add_decoder_inst((*data).ctx, di) == 0 {
            ossl_decoder_instance_free(di);
            (*data).error_occurred = 1;
            return 0;
        }

        (*data).total += 1;
    }
    1
}

/// `static void collect_decoder(OSSL_DECODER *decoder, void *arg)` — `decoder_pkey.c:313-358`.
///
/// The `does_selection` gate is skipped when the decoder does not supply one, which the authority
/// reads as "takes anything". The first key management that accepts this decoder ends the inner
/// loop, which is what makes "only add this decoder once" true.
///
/// # Safety
/// `decoder` must be live; `arg` a live [`CollectData`].
unsafe extern "C" fn collect_decoder(decoder: *mut OsslDecoder, arg: *mut c_void) {
    let data = arg.cast::<CollectData>();
    // SAFETY: `data` is live.
    if unsafe { (*data).error_occurred } != 0 {
        return;
    }

    // SAFETY: `decoder` is live.
    let prov = unsafe { OSSL_DECODER_get0_provider(decoder) };
    // SAFETY: `prov` is the decoder's provider.
    let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(prov) };

    /*
     * Either the caller didn't give us a selection, or if they did, the decoder must tell us if it
     * supports that selection to be accepted. If the decoder doesn't have |does_selection|, it's
     * seen as taking anything.
     */
    // SAFETY: `decoder` and `data` are live; `provctx` is the provider's context.
    unsafe {
        if let Some(does_selection) = (*decoder).does_selection {
            if does_selection(provctx, (*(*data).ctx).selection) == 0 {
                return;
            }
        }
    }

    // SAFETY: `data` is live and its keymgmt stack is its own.
    let keymgmts = unsafe { (*data).keymgmts };
    // SAFETY: `keymgmts` is live.
    let end_i = unsafe { OPENSSL_sk_num(keymgmts) };
    for i in 0..end_i {
        // SAFETY: `i` is a valid index of the live stack.
        let keymgmt = unsafe { OPENSSL_sk_value(keymgmts, i) }.cast::<EvpKeyMgmt>();

        /* Only add this decoder once */
        // SAFETY: all three are live.
        if unsafe { collect_decoder_keymgmt(keymgmt, decoder, provctx, data) } != 0 {
            break;
        }
        // SAFETY: `data` is live.
        if unsafe { (*data).error_occurred } != 0 {
            return;
        }
    }
}

/// `static int check_keymgmt(EVP_KEYMGMT *keymgmt, struct collect_data_st *data)` —
/// `decoder_pkey.c:364-401`.
///
/// The keytype is resolved **once** and cached: `keytype_resolved` is set even when the name was
/// not found, so a later call does not retry the name map. The SM2 alias is collected only for the
/// two EC spellings the authority names.
///
/// # Safety
/// `keymgmt` and `data` must be live.
unsafe extern "C" fn check_keymgmt(keymgmt: *mut EvpKeyMgmt, data: *mut CollectData) -> c_int {
    /* If no keytype was specified, everything matches. */
    // SAFETY: `data` is live.
    if unsafe { (*data).keytype }.is_null() {
        return 1;
    }

    // SAFETY: `data` is live.
    if unsafe { (*data).keytype_resolved } == 0 {
        /* We haven't cached the IDs from the keytype string yet. */
        // SAFETY: `data` is live and its libctx is the caller's.
        let namemap = unsafe { ossl_namemap_stored((*data).libctx) };
        // SAFETY: `namemap` is live and the keytype is NUL-terminated.
        unsafe { (*data).keytype_id = ossl_namemap_name2num(namemap, (*data).keytype) };

        /*
         * If keytype is a value ambiguously used for both EC and SM2, collect the ID for SM2 as
         * well.
         */
        // SAFETY: `data` is live and the keytype is NUL-terminated.
        unsafe {
            if (*data).keytype_id != 0
                && (crate::runtime::bio::sys::strcmp((*data).keytype, c"id-ecPublicKey".as_ptr())
                    == 0
                    || crate::runtime::bio::sys::strcmp(
                        (*data).keytype,
                        c"1.2.840.10045.2.1".as_ptr(),
                    ) == 0)
            {
                (*data).sm2_id = ossl_namemap_name2num(namemap, c"SM2".as_ptr());
            }
        }

        /*
         * If keytype_id is zero the name was not found, but we still set keytype_resolved to avoid
         * trying all this again.
         */
        // SAFETY: `data` is live.
        unsafe { (*data).keytype_resolved = 1 };
    }

    /* Specified keytype could not be resolved, so nothing matches. */
    // SAFETY: `data` is live.
    if unsafe { (*data).keytype_id } == 0 {
        return 0;
    }

    /* Does not match the keytype specified, so skip. */
    // SAFETY: both are live.
    unsafe {
        if (*keymgmt).name_id != (*data).keytype_id && (*keymgmt).name_id != (*data).sm2_id {
            return 0;
        }
    }

    1
}

/// `static void collect_keymgmt(EVP_KEYMGMT *keymgmt, void *arg)` — `decoder_pkey.c:403-424`.
///
/// The reference is taken here because the accepted stack is handed to the constructor the setup
/// registers, and its cleanup unrefs every element.
///
/// # Safety
/// `keymgmt` must be live; `arg` a live [`CollectData`].
unsafe extern "C" fn collect_keymgmt(keymgmt: *mut EvpKeyMgmt, arg: *mut c_void) {
    let data = arg.cast::<CollectData>();

    // SAFETY: both are live.
    if unsafe { check_keymgmt(keymgmt, data) } == 0 {
        return;
    }

    /*
     * We have to ref EVP_KEYMGMT here because in the success case, data->keymgmts is referenced by
     * the constructor we register in the OSSL_DECODER_CTX. The registered cleanup function
     * (decoder_clean_pkey_construct_arg) unrefs every element of the stack and frees it.
     */
    // SAFETY: `keymgmt` is live.
    if unsafe { EVP_KEYMGMT_up_ref(keymgmt) } == 0 {
        return;
    }

    // SAFETY: `data` is live and its keymgmt stack is its own.
    unsafe {
        if OPENSSL_sk_push((*data).keymgmts, keymgmt.cast::<c_void>()) <= 0 {
            EVP_KEYMGMT_free(keymgmt);
            (*data).error_occurred = 1;
        }
    }
}

/// `static int ossl_decoder_ctx_setup_for_pkey(OSSL_DECODER_CTX *ctx, const char *keytype,
/// OSSL_LIB_CTX *libctx, const char *propquery)` — `decoder_pkey.c:431-557`.
///
/// The keytype string is resolved **lazily** by the first `collect_keymgmt` call (not here) so
/// that every loaded provider's names are registered first -- the authority's own comment says why.
/// The construct data is transferred to the context only when at least one decoder matched, and
/// `process_data = NULL` before the `err:` label is what keeps a half-built context safe to
/// release.
///
/// # Safety
/// `ctx` must be live; `keytype` NULL or NUL-terminated; `libctx` NULL or live; `propquery` NULL or
/// NUL-terminated.
unsafe fn ossl_decoder_ctx_setup_for_pkey(
    ctx: *mut OsslDecoderCtx,
    keytype: *const c_char,
    libctx: *mut c_void,
    propquery: *const c_char,
) -> c_int {
    let mut ok = 0;
    let mut process_data: *mut DecoderPkeyData;
    let mut pq: *mut OsslPropertyList = ptr::null_mut();
    let mut p2: *mut OsslPropertyList = ptr::null_mut();

    /* Allocate data. */
    // SAFETY: the constructor asks only for a zeroed block of the structure's size.
    process_data =
        CRYPTO_zalloc(size_of::<DecoderPkeyData>(), ptr::null(), 0).cast::<DecoderPkeyData>();
    if process_data.is_null() {
        // SAFETY: `process_data` is NULL, which the cleanup accepts; `p2` is NULL.
        return unsafe { setup_for_pkey_fail(ctx, process_data, p2, ok) };
    }
    if !propquery.is_null() {
        // SAFETY: `propquery` is NUL-terminated.
        let dup = unsafe { CRYPTO_strdup(propquery, ptr::null(), 0) };
        if dup.is_null() {
            // SAFETY: `process_data` is this call's own allocation.
            return unsafe { setup_for_pkey_fail(ctx, process_data, p2, ok) };
        }
        // SAFETY: `process_data` is live.
        unsafe { (*process_data).propq = dup };
    }

    /* Allocate our list of EVP_KEYMGMTs. */
    // SAFETY: no preconditions.
    let keymgmts = OPENSSL_sk_new_null();
    if keymgmts.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_PKEY_470) };
        // SAFETY: `process_data` is this call's own allocation.
        return unsafe { setup_for_pkey_fail(ctx, process_data, p2, ok) };
    }

    // SAFETY: `process_data` is live.
    unsafe {
        (*process_data).object = ptr::null_mut();
        (*process_data).libctx = libctx;
        (*process_data).selection = (*ctx).selection;
        (*process_data).keymgmts = keymgmts;
    }

    /* Collect passed and default properties to prioritize the decoders. */
    if !propquery.is_null() {
        // SAFETY: `libctx` is NULL or live and `propquery` is NUL-terminated.
        p2 = unsafe { ossl_parse_query(libctx, propquery, 1) };
        pq = p2;
    }

    // SAFETY: `libctx` is NULL or live.
    let plp = unsafe { ossl_ctx_global_properties(libctx, 0) };
    // SAFETY: `plp` is NULL or the slot's own pointer-to-list.
    if !plp.is_null() && !unsafe { *plp }.is_null() {
        if pq.is_null() {
            // SAFETY: `plp` is live and `*plp` is the context's list.
            pq = unsafe { *plp };
        } else {
            // SAFETY: both lists are live.
            p2 = unsafe { ossl_property_merge(pq, *plp) };
            // SAFETY: `pq` is live and this call owns it.
            unsafe { ossl_property_free(pq) };
            if p2.is_null() {
                // SAFETY: `process_data` is this call's own allocation.
                return unsafe { setup_for_pkey_fail(ctx, process_data, p2, ok) };
            }
            pq = p2;
        }
    }

    /*
     * Enumerate all keymgmts into a stack. The keytype string is resolved lazily on the first call
     * to collect_keymgmt made by EVP_KEYMGMT_do_all_provided, rather than upfront, as this ensures
     * that the names for all loaded providers have been registered by the time we try to resolve
     * the keytype string.
     */
    let mut collect_data = CollectData {
        libctx,
        ctx,
        keytype,
        keytype_id: 0,
        sm2_id: 0,
        total: 0,
        error_occurred: 0,
        keytype_resolved: 0,
        pq,
        keymgmts,
    };
    // SAFETY: `collect_data` is this frame's own and the visitor is this unit's.
    unsafe {
        EVP_KEYMGMT_do_all_provided(
            libctx,
            Some(collect_keymgmt),
            ptr::addr_of_mut!(collect_data).cast::<c_void>(),
        )
    };

    if collect_data.error_occurred != 0 {
        // SAFETY: `process_data` is this call's own allocation.
        return unsafe { setup_for_pkey_fail(ctx, process_data, p2, ok) };
    }

    /* Enumerate all matching decoders. */
    // SAFETY: `collect_data` is this frame's own and the visitor is this unit's.
    unsafe {
        OSSL_DECODER_do_all_provided(
            libctx,
            collect_decoder,
            ptr::addr_of_mut!(collect_data).cast::<c_void>(),
        )
    };

    if collect_data.error_occurred != 0 {
        // SAFETY: `process_data` is this call's own allocation.
        return unsafe { setup_for_pkey_fail(ctx, process_data, p2, ok) };
    }

    /*
     * Finish initializing the decoder context. If one or more decoders matched above then the
     * number of decoders attached to the OSSL_DECODER_CTX will be nonzero. Else nothing was found
     * and we do nothing.
     */
    // SAFETY: `ctx` is live.
    if unsafe { OSSL_DECODER_CTX_get_num_decoders(ctx) } != 0 {
        // SAFETY: `ctx` is live and each setter takes this call's own value.
        let wired = unsafe {
            OSSL_DECODER_CTX_set_construct(ctx, Some(decoder_construct_pkey)) != 0
                && OSSL_DECODER_CTX_set_construct_data(ctx, process_data.cast::<c_void>()) != 0
                && OSSL_DECODER_CTX_set_cleanup(ctx, Some(decoder_clean_pkey_construct_arg)) != 0
        };
        if !wired {
            // SAFETY: `process_data` is this call's own allocation.
            return unsafe { setup_for_pkey_fail(ctx, process_data, p2, ok) };
        }

        process_data = ptr::null_mut(); /* Avoid it being freed */
    }

    ok = 1;

    // SAFETY: `process_data` is NULL or this call's own allocation; `p2` is NULL or owned here.
    unsafe { setup_for_pkey_fail(ctx, process_data, p2, ok) }
}

/// The `err:` label of [`ossl_decoder_ctx_setup_for_pkey`] — `decoder_pkey.c:553-556`.
///
/// The authority's `decoder_clean_pkey_construct_arg(process_data)` and `ossl_property_free(p2)`
/// run on every path, including the success one (where both are NULL).
///
/// # Safety
/// `process_data` NULL or a live [`DecoderPkeyData`]; `p2` NULL or a live property list this call
/// owns.
unsafe fn setup_for_pkey_fail(
    _ctx: *mut OsslDecoderCtx,
    process_data: *mut DecoderPkeyData,
    p2: *mut OsslPropertyList,
    ok: c_int,
) -> c_int {
    // SAFETY: both are NULL or this call's own allocations.
    unsafe {
        decoder_clean_pkey_construct_arg(process_data.cast::<c_void>());
        ossl_property_free(p2);
    }
    ok
}

/// `static OSSL_DECODER_CTX *ossl_decoder_ctx_for_pkey_dup(OSSL_DECODER_CTX *src, EVP_PKEY **pkey,
/// const char *input_type, const char *input_structure)` — `decoder_pkey.c:574-663`.
///
/// The duplicate never copies `pwdata` -- the authority's comment says the template does not carry
/// it -- and it deep-copies both the instance chain and the keymgmt stack through their own copy
/// and free functions. The `err:` label releases the partial duplicate and the construct data that
/// was not yet handed over.
///
/// # Safety
/// `src` NULL or live; `pkey` must be live and is stored, not adopted; the two strings NULL or
/// NUL-terminated.
unsafe fn ossl_decoder_ctx_for_pkey_dup(
    src: *mut OsslDecoderCtx,
    pkey: *mut *mut EvpPkey,
    input_type: *const c_char,
    input_structure: *const c_char,
) -> *mut OsslDecoderCtx {
    if src.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: no preconditions.
    let dest = unsafe { OSSL_DECODER_CTX_new() };
    if dest.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_PKEY_587) };
        return ptr::null_mut();
    }

    // SAFETY: `dest` is live and both strings are NULL or NUL-terminated.
    let typed = unsafe {
        OSSL_DECODER_CTX_set_input_type(dest, input_type) != 0
            && OSSL_DECODER_CTX_set_input_structure(dest, input_structure) != 0
    };
    if !typed {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_PKEY_593) };
        // SAFETY: `dest` is live and this call owns it.
        unsafe { OSSL_DECODER_CTX_free(dest) };
        return ptr::null_mut();
    }
    // SAFETY: both are live.
    unsafe { (*dest).selection = (*src).selection };

    // SAFETY: both are live.
    if !unsafe { (*src).decoder_insts }.is_null() {
        // SAFETY: `src` is live and the two callbacks are this unit's own adapters.
        let copied = unsafe {
            OPENSSL_sk_deep_copy(
                (*src).decoder_insts,
                Some(decoder_instance_dup_thunk),
                Some(decoder_instance_free_thunk),
            )
        };
        // SAFETY: `dest` is live.
        unsafe { (*dest).decoder_insts = copied };
        if copied.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DECODER_PKEY_604) };
            // SAFETY: `dest` is live and this call owns it.
            unsafe { OSSL_DECODER_CTX_free(dest) };
            return ptr::null_mut();
        }
    }

    // SAFETY: both are live.
    if unsafe { OSSL_DECODER_CTX_set_construct(dest, OSSL_DECODER_CTX_get_construct(src)) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_PKEY_611) };
        // SAFETY: `dest` is live and this call owns it.
        unsafe { OSSL_DECODER_CTX_free(dest) };
        return ptr::null_mut();
    }

    // SAFETY: `src` is live.
    let process_data_src =
        unsafe { OSSL_DECODER_CTX_get_construct_data(src) }.cast::<DecoderPkeyData>();
    if !process_data_src.is_null() {
        // SAFETY: the constructor asks only for a zeroed block of the structure's size.
        let process_data_dest =
            CRYPTO_zalloc(size_of::<DecoderPkeyData>(), ptr::null(), 0).cast::<DecoderPkeyData>();
        if process_data_dest.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DECODER_PKEY_619) };
            // SAFETY: `dest` is live and this call owns it.
            unsafe { OSSL_DECODER_CTX_free(dest) };
            return ptr::null_mut();
        }
        // SAFETY: `process_data_src` is live.
        if !unsafe { (*process_data_src).propq }.is_null() {
            // SAFETY: `process_data_src`'s `propq` is NUL-terminated.
            let dup = unsafe { CRYPTO_strdup((*process_data_src).propq, ptr::null(), 0) };
            if dup.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::DECODER_PKEY_625) };
                // SAFETY: both are this call's own.
                unsafe {
                    decoder_clean_pkey_construct_arg(process_data_dest.cast::<c_void>());
                    OSSL_DECODER_CTX_free(dest);
                }
                return ptr::null_mut();
            }
            // SAFETY: `process_data_dest` is live.
            unsafe { (*process_data_dest).propq = dup };
        }

        // SAFETY: `process_data_src` is live.
        if !unsafe { (*process_data_src).keymgmts }.is_null() {
            // SAFETY: `process_data_src` is live and the two callbacks are this unit's own.
            let copied = unsafe {
                OPENSSL_sk_deep_copy(
                    (*process_data_src).keymgmts,
                    Some(keymgmt_dup_thunk),
                    Some(keymgmt_free_thunk),
                )
            };
            // SAFETY: `process_data_dest` is live.
            unsafe { (*process_data_dest).keymgmts = copied };
            if copied.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::DECODER_PKEY_636) };
                // SAFETY: both are this call's own.
                unsafe {
                    decoder_clean_pkey_construct_arg(process_data_dest.cast::<c_void>());
                    OSSL_DECODER_CTX_free(dest);
                }
                return ptr::null_mut();
            }
        }

        // SAFETY: `process_data_src` and `process_data_dest` are live.
        unsafe {
            (*process_data_dest).object = pkey.cast::<*mut c_void>();
            (*process_data_dest).libctx = (*process_data_src).libctx;
            (*process_data_dest).selection = (*process_data_src).selection;
            (*process_data_dest).ctx = dest;
        }
        // SAFETY: `dest` is live and `process_data_dest` is this call's own.
        if unsafe { OSSL_DECODER_CTX_set_construct_data(dest, process_data_dest.cast::<c_void>()) }
            == 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DECODER_PKEY_646) };
            // SAFETY: both are this call's own.
            unsafe {
                decoder_clean_pkey_construct_arg(process_data_dest.cast::<c_void>());
                OSSL_DECODER_CTX_free(dest);
            }
            return ptr::null_mut();
        }
    }

    // SAFETY: both are live.
    if unsafe { OSSL_DECODER_CTX_set_cleanup(dest, OSSL_DECODER_CTX_get_cleanup(src)) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_PKEY_654) };
        // SAFETY: `dest` is live and this call owns it.
        unsafe { OSSL_DECODER_CTX_free(dest) };
        return ptr::null_mut();
    }

    dest
}

/// `OSSL_DECODER_CTX *OSSL_DECODER_CTX_new_for_pkey(EVP_PKEY **pkey, const char *input_type,
/// const char *input_structure, const char *keytype, int selection, OSSL_LIB_CTX *libctx,
/// const char *propquery)` — `decoder_pkey.c:820-969`.
///
/// The cache lookup is under a **read** lock; a miss releases it, builds the template, and re-takes
/// a **write** lock, re-checking the table because another thread may have won the race. The loser
/// frees its own entry and uses the winner's template. Either way the template is duplicated for
/// the caller, so the answer is never the cached context itself.
///
/// # Safety
/// `pkey` must be live and writable; the four strings NULL or NUL-terminated; `libctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_new_for_pkey(
    pkey: *mut *mut EvpPkey,
    input_type: *const c_char,
    input_structure: *const c_char,
    keytype: *const c_char,
    selection: c_int,
    libctx: *mut c_void,
    propquery: *const c_char,
) -> *mut OsslDecoderCtx {
    let mut decoder_params: [OsslParam; 3] = [
        OSSL_PARAM_construct_end(),
        OSSL_PARAM_construct_end(),
        OSSL_PARAM_construct_end(),
    ];
    let mut i = 0usize;

    // SAFETY: `libctx` is NULL or live and the slot read accepts NULL.
    let cache = crate::context::lib_ctx_get_data(libctx, OSSL_LIB_CTX_DECODER_CACHE_INDEX)
        .cast::<DecoderCache>();
    if cache.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_PKEY_839) };
        return ptr::null_mut();
    }
    if !input_structure.is_null() {
        // SAFETY: the constructor fills a descriptor over the caller's string.
        decoder_params[i] = unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_STRUCTURE.cast_mut(),
                input_structure.cast_mut(),
                0,
            )
        };
        i += 1;
    }
    if !propquery.is_null() {
        // SAFETY: the constructor fills a descriptor over the caller's string.
        decoder_params[i] = unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_DECODER_PARAM_PROPERTIES.cast_mut(),
                propquery.cast_mut(),
                0,
            )
        };
    }

    /* It is safe to cast away the const here */
    let cacheent = DecoderCacheEntry {
        input_type: input_type.cast_mut(),
        input_structure: input_structure.cast_mut(),
        keytype: keytype.cast_mut(),
        selection,
        propquery: propquery.cast_mut(),
        template: ptr::null_mut(),
    };

    // SAFETY: `cache` is live and its lock is its own.
    if unsafe { CRYPTO_THREAD_read_lock((*cache).lock) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_PKEY_857) };
        return ptr::null_mut();
    }

    /* First see if we have a template OSSL_DECODER_CTX */
    // SAFETY: `cache` is live and `cacheent` is this frame's own key.
    let res = unsafe { OPENSSL_LH_retrieve((*cache).hashtable, ptr::addr_of!(cacheent).cast()) }
        .cast::<DecoderCacheEntry>();

    let mut ctx: *mut OsslDecoderCtx;

    if res.is_null() {
        /*
         * There is no template so we will have to construct one. This will be time consuming so
         * release the lock and we will later upgrade it to a write lock.
         */
        // SAFETY: `cache` is live and the lock is held.
        unsafe { CRYPTO_THREAD_unlock((*cache).lock) };

        // SAFETY: no preconditions.
        ctx = unsafe { OSSL_DECODER_CTX_new() };
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DECODER_PKEY_873) };
            return ptr::null_mut();
        }

        // SAFETY: `ctx` is live and the four arguments are the caller's.
        let built = unsafe {
            OSSL_DECODER_CTX_set_input_type(ctx, input_type) != 0
                && OSSL_DECODER_CTX_set_input_structure(ctx, input_structure) != 0
                && OSSL_DECODER_CTX_set_selection(ctx, selection) != 0
                && ossl_decoder_ctx_setup_for_pkey(ctx, keytype, libctx, propquery) != 0
                && OSSL_DECODER_CTX_add_extra(ctx, libctx, propquery) != 0
                && (propquery.is_null()
                    || OSSL_DECODER_CTX_set_params(ctx, decoder_params.as_ptr()) != 0)
        };
        if !built {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DECODER_PKEY_901) };
            // SAFETY: `ctx` is live and this call owns it.
            unsafe { OSSL_DECODER_CTX_free(ctx) };
            return ptr::null_mut();
        }

        // SAFETY: the constructor asks only for a zeroed block of the structure's size.
        let newcache = CRYPTO_zalloc(size_of::<DecoderCacheEntry>(), ptr::null(), 0)
            .cast::<DecoderCacheEntry>();
        if newcache.is_null() {
            // SAFETY: `ctx` is live and this call owns it.
            unsafe { OSSL_DECODER_CTX_free(ctx) };
            return ptr::null_mut();
        }

        if !input_type.is_null() {
            // SAFETY: `input_type` is NUL-terminated.
            let dup = unsafe { CRYPTO_strdup(input_type, ptr::null(), 0) };
            if dup.is_null() {
                // SAFETY: `newcache` and `ctx` are this call's own.
                unsafe {
                    decoder_cache_entry_free(newcache.cast());
                    OSSL_DECODER_CTX_free(ctx);
                }
                return ptr::null_mut();
            }
            // SAFETY: `newcache` is live.
            unsafe { (*newcache).input_type = dup };
        }
        if !input_structure.is_null() {
            // SAFETY: `input_structure` is NUL-terminated.
            let dup = unsafe { CRYPTO_strdup(input_structure, ptr::null(), 0) };
            if dup.is_null() {
                // SAFETY: `newcache` and `ctx` are this call's own.
                unsafe {
                    decoder_cache_entry_free(newcache.cast());
                    OSSL_DECODER_CTX_free(ctx);
                }
                return ptr::null_mut();
            }
            // SAFETY: `newcache` is live.
            unsafe { (*newcache).input_structure = dup };
        }
        if !keytype.is_null() {
            // SAFETY: `keytype` is NUL-terminated.
            let dup = unsafe { CRYPTO_strdup(keytype, ptr::null(), 0) };
            if dup.is_null() {
                // SAFETY: `newcache` and `ctx` are this call's own.
                unsafe {
                    decoder_cache_entry_free(newcache.cast());
                    OSSL_DECODER_CTX_free(ctx);
                }
                return ptr::null_mut();
            }
            // SAFETY: `newcache` is live.
            unsafe { (*newcache).keytype = dup };
        }
        if !propquery.is_null() {
            // SAFETY: `propquery` is NUL-terminated.
            let dup = unsafe { CRYPTO_strdup(propquery, ptr::null(), 0) };
            if dup.is_null() {
                // SAFETY: `newcache` and `ctx` are this call's own.
                unsafe {
                    decoder_cache_entry_free(newcache.cast());
                    OSSL_DECODER_CTX_free(ctx);
                }
                return ptr::null_mut();
            }
            // SAFETY: `newcache` is live.
            unsafe { (*newcache).propquery = dup };
        }
        // SAFETY: `newcache` is live.
        unsafe {
            (*newcache).selection = selection;
            (*newcache).template = ctx;
        }

        // SAFETY: `cache` is live and its lock is its own.
        if unsafe { CRYPTO_THREAD_write_lock((*cache).lock) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DECODER_PKEY_937) };
            // SAFETY: `newcache` is this call's own, and it still owns the template.
            unsafe { decoder_cache_entry_free(newcache.cast()) };
            return ptr::null_mut();
        }
        // SAFETY: `cache` is live and `cacheent` is this frame's own key.
        let res2 =
            unsafe { OPENSSL_LH_retrieve((*cache).hashtable, ptr::addr_of!(cacheent).cast()) }
                .cast::<DecoderCacheEntry>();
        if res2.is_null() {
            // SAFETY: `(void)` -- the authority ignores the inserted-pointer answer.
            unsafe {
                OPENSSL_LH_insert((*cache).hashtable, newcache.cast::<c_void>());
            };
            // SAFETY: `cache` is live and its table is its own.
            if unsafe { OPENSSL_LH_error((*cache).hashtable) } != 0 {
                // SAFETY: `cache` is live and the lock is held.
                unsafe { CRYPTO_THREAD_unlock((*cache).lock) };
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::DECODER_PKEY_946) };
                // SAFETY: `newcache` is this call's own, and it still owns the template.
                unsafe { decoder_cache_entry_free(newcache.cast()) };
                return ptr::null_mut();
            }
        } else {
            /*
             * We raced with another thread to construct this and lost. Free what we just created
             * and use the entry from the hashtable instead.
             */
            // SAFETY: `newcache` is this call's own.
            unsafe { decoder_cache_entry_free(newcache.cast()) };
            // SAFETY: `res2` is a live entry in the table.
            ctx = unsafe { (*res2).template };
        }
    } else {
        // SAFETY: `res` is a live entry in the table.
        ctx = unsafe { (*res).template };
    }

    // SAFETY: `ctx` is live and `pkey` is the caller's slot; the lock is held.
    let dup = unsafe { ossl_decoder_ctx_for_pkey_dup(ctx, pkey, input_type, input_structure) };
    // SAFETY: `cache` is live and the lock is held.
    unsafe { CRYPTO_THREAD_unlock((*cache).lock) };

    dup
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::lhash::{ossl_lh_strcasehash, OPENSSL_LH_num_items};

    /// `ossl_lh_strcasehash`'s three properties, each read off the authority's own body rather than
    /// from a recorded value: NULL and the empty string are **0** (the early return), two ASCII
    /// spellings differing only in case hash the same (`case_adjust = ~0x20` clears bit 5, so `A`
    /// and `a` mask to the same byte), and a non-empty name hashes non-zero (the loop runs at least
    /// once and `n = 0x100` is folded in).
    #[test]
    fn the_strcasehash_folds_case_and_zeroes_the_empty_forms() {
        // SAFETY: every argument is a NUL-terminated literal or NULL.
        unsafe {
            assert_eq!(ossl_lh_strcasehash(ptr::null()), 0);
            assert_eq!(ossl_lh_strcasehash(c"".as_ptr()), 0);
            assert_ne!(ossl_lh_strcasehash(c"input".as_ptr()), 0);
            for (a, b) in [
                (c"input".as_ptr(), c"INPUT".as_ptr()),
                (c"PrivateKeyInfo".as_ptr(), c"privatekeyinfo".as_ptr()),
                (c"DER".as_ptr(), c"der".as_ptr()),
            ] {
                assert_eq!(ossl_lh_strcasehash(a), ossl_lh_strcasehash(b));
            }
            /* A non-letter difference is not folded away. */
            assert_ne!(
                ossl_lh_strcasehash(c"der".as_ptr()),
                ossl_lh_strcasehash(c"DERx".as_ptr())
            );
        }
    }

    /// The cache's lifetime round trip: a fresh cache holds nothing, its lock and table are live,
    /// and freeing it releases both. A non-empty table cannot be built here -- the lookup that
    /// inserts an entry is withheld with the pkey half -- and the flush is reached through the
    /// context's slot, which `src/provider/stores.rs`'s bridge test observes; so what this test
    /// pins is the empty case, which is the only one a landed path can reach.
    #[test]
    fn a_fresh_cache_round_trips_and_flushes_empty() {
        // SAFETY: no preconditions.
        let cache = unsafe { ossl_decoder_cache_new(ptr::null_mut()) };
        assert!(!cache.is_null());
        // SAFETY: `cache` is this test's own.
        unsafe {
            let inner = cache.cast::<DecoderCache>();
            assert!(!(*inner).lock.is_null());
            assert!(!(*inner).hashtable.is_null());
            /* The table's key shape is a struct, so it starts empty and the flush is a no-op. */
            assert_eq!(OPENSSL_LH_num_items((*inner).hashtable), 0);
            ossl_decoder_cache_free(cache);
        }
    }

    /// `OSSL_DECODER_CTX_new_for_pkey` on a crate that publishes no provider decoder: the setup
    /// walks both stores, finds nothing, and answers a **duplicate** whose chain is empty. The
    /// template is inserted into slot 20's cache, so a second call exercises the cache-hit path --
    /// and it, too, answers zero decoders, which is the measurement behind D367's "the six readers
    /// cannot succeed yet".
    #[test]
    fn new_for_pkey_answers_a_context_with_no_decoders() {
        use crate::decoder_lib::OSSL_DECODER_CTX_get_num_decoders;
        use crate::decoder_meth::OSSL_DECODER_CTX_free;

        let mut slot: *mut EvpPkey = ptr::null_mut();
        for _ in 0..2 {
            // SAFETY: `slot` is this frame's own pointer slot, and with no provider decoder the
            // context is built with an empty chain, so `slot` is never dereferenced.
            let ctx = unsafe {
                OSSL_DECODER_CTX_new_for_pkey(
                    ptr::addr_of_mut!(slot),
                    c"PEM".as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    ptr::null(),
                )
            };
            assert!(!ctx.is_null());
            // SAFETY: `ctx` is this test's own.
            unsafe {
                assert_eq!(OSSL_DECODER_CTX_get_num_decoders(ctx), 0);
                OSSL_DECODER_CTX_free(ctx);
            }
        }
    }
}
