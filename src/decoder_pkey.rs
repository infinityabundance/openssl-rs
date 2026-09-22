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
//! ## What is withheld, as one named block: the pkey half
//!
//! `decoder_construct_pkey` (`:71-202`), `decoder_clean_pkey_construct_arg` (`:204-233`),
//! `collect_decoder_keymgmt` (`:235-311`), `collect_decoder` (`:313-362`), `check_keymgmt`
//! (`:364-401`), `collect_keymgmt` (`:403-429`), `ossl_decoder_ctx_setup_for_pkey` (`:431-558`),
//! `keymgmt_dup` (`:560-573`), `ossl_decoder_ctx_for_pkey_dup` (`:575-660`), the cache's own lookup
//! (`:825-960`) and `OSSL_DECODER_CTX_new_for_pkey` (`:820-969`). They are one block because they
//! are one path: `new_for_pkey` calls `ossl_decoder_ctx_for_pkey_dup` for its cache lookup and
//! `ossl_decoder_ctx_setup_for_pkey` for its miss, the setup calls `collect_keymgmt` and
//! `collect_decoder`, and those call `decoder_construct_pkey` through
//! `OSSL_DECODER_CTX_set_construct`. Every one of them also reaches `EVP_KEYMGMT_*`, which is what
//! makes them one unit's work rather than five.
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
use core::ptr;

use crate::decoder_meth::{OSSL_DECODER_CTX_free, OsslDecoderCtx};
use crate::passphrase::{
    ossl_pw_set_ossl_passphrase_cb, ossl_pw_set_passphrase, ossl_pw_set_pem_password_cb,
    ossl_pw_set_ui_method, OsslPassphraseCallback,
};
use crate::provider::stores::OSSL_LIB_CTX_DECODER_CACHE_INDEX;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::lhash::{
    ossl_lh_strcasehash, OPENSSL_LH_doall, OPENSSL_LH_flush, OPENSSL_LH_free, OPENSSL_LH_new,
    OpenSslLhash,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_unlock,
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
}
