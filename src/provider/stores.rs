//! Phase 6.8c — the five store bridges: four method stores and the decoder cache.
//!
//! Four of 6.8c's functions end in a call that is *not* this stratum's:
//!
//! * `provider_flush_store_cache` adds up `evp_method_store_cache_flush`,
//!   `ossl_encoder_store_cache_flush`, `ossl_decoder_store_cache_flush` and
//!   `ossl_store_loader_store_cache_flush`, and answers 1 only when the sum is 4.
//! * `provider_remove_store_methods` does the same with the `_remove_all_provided`
//!   four.
//! * `provider_activate` and `provider_deactivate` call `ossl_decoder_cache_flush`
//!   once the activation count reaches 1 and 0 respectively.
//!
//! Each of the nine is a **slot read plus a delegation**: `get_evp_method_store` is
//! `ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX)` and nothing
//! more, and the delegation only happens when the slot is non-NULL. So the part of
//! each that 6.8c can be certain of — the read, the NULL test, and the value the
//! authority answers when the store is absent — is exactly the part that decides
//! behaviour in this build, and it is written here verbatim.
//!
//! ## Why the delegation is a checked invariant rather than a stub
//!
//! The four method stores are created by `ossl_method_store_new(libctx, <namemap>)`
//! from each subsystem's own initialiser (`evp_method_store_init`, the encoder and
//! decoder initialisers, the store-loader initialiser), which are Phase 7 and
//! Phase 10 work; the decoder cache is created by `ossl_decoder_cache_new`, also
//! Phase 7. None of those five slots can be non-NULL in this build, and
//! `docs/PHASE-6-SUBPHASES.md`'s index table records each one as unfilled with its
//! owner.
//!
//! The delegation body — `ossl_method_store_cache_flush_all` and
//! `ossl_method_store_remove_all_provided`, both in `crypto/property/property.c` —
//! is 6.7c's, which 6.7 deferred to 6.8 and which has not landed either. So there is
//! nothing to call, and inventing a body would be a fabrication that reads as
//! evidence.
//!
//! What is written instead is the same shape `create_provider_children` uses: the
//! authority's branch, guarded by an `assert!` stating the invariant that the slot
//! is unfilled. That makes the invariant **checkable** rather than assumed — a later
//! stratum that fills one of these slots without landing the call fails loudly at the
//! first activation instead of silently flushing nothing, which is the failure mode
//! that would be hardest to attribute later. `the_five_slots_are_unfilled` below
//! turns the same invariant into a unit test.
//!
//! ## The return values are load-bearing
//!
//! A store that is *absent* is a **success**, not a failure: seven of the nine answer
//! 1, and the sums in `provider_flush_store_cache` and `provider_remove_store_methods`
//! compare against 4, so an absent store must contribute 1 or the whole activation
//! would report failure. `ossl_decoder_cache_flush` is the exception and answers
//! **0** for an absent cache; both of its callers discard the answer, which is why
//! that asymmetry is invisible in the authority and easy to "tidy" wrongly.
//!
//! SPDX-License-Identifier: Apache-2.0

// STAGING ALLOWANCE, with its condition stated rather than implied. Every item below is
// `pub(crate)` and has no caller yet, because the `OSSL_PROVIDER_*` exports that reach them
// are declared in the commit that lands `RT-PROVIDER` -- and the obligation ledger counts a
// symbol implemented the moment it is *defined*, so declaring them here would move
// twenty-two rows on evidence that does not exist. **This attribute is removed in that
// commit.** If it survives it, the store bridges have stopped being called, which is a
// defect and not a style matter.
#![allow(dead_code)]

use core::ffi::{c_int, c_void};

use crate::context::lib_ctx_get_data;
use crate::context::{
    OSSL_LIB_CTX_DECODER_STORE_INDEX, OSSL_LIB_CTX_ENCODER_STORE_INDEX,
    OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX, OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX,
};
use crate::provider::{ossl_provider_libctx, OsslProvider};

/// `OSSL_LIB_CTX_DECODER_CACHE_INDEX` — slot 20, from `include/internal/cryptlib.h`.
///
/// Not re-exported from `crate::context` because nothing else in this stratum names
/// it; the context module's own doc table is where the slot's ownership is recorded.
pub(crate) const OSSL_LIB_CTX_DECODER_CACHE_INDEX: c_int = 20;

/// The shared invariant of every bridge below, made checkable.
///
/// `name` is the authority's function name and `owner` is the stratum the slot's
/// owner is recorded as in `docs/PHASE-6-SUBPHASES.md`. Both are `&'static str`
/// literals, so a message never allocates and the check is free when it holds.
#[inline]
fn assert_slot_unfilled(slot: *mut c_void, name: &str, owner: &str) {
    assert!(
        slot.is_null(),
        "openssl-rs: {name} reached with its store slot filled, but {owner} has not \
         landed the store method it delegates to; the branch is not implemented rather \
         than silently skipped"
    );
}

/// `int evp_method_store_cache_flush(OSSL_LIB_CTX *libctx)` — `crypto/evp/evp_fetch.c`.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn evp_method_store_cache_flush(libctx: *mut c_void) -> c_int {
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX);
    assert_slot_unfilled(store, "evp_method_store_cache_flush", "Phase 7");
    1
}

/// `int ossl_encoder_store_cache_flush(OSSL_LIB_CTX *libctx)` —
/// `crypto/encode_decode/encoder_meth.c`.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn ossl_encoder_store_cache_flush(libctx: *mut c_void) -> c_int {
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_ENCODER_STORE_INDEX);
    assert_slot_unfilled(store, "ossl_encoder_store_cache_flush", "Phase 7");
    1
}

/// `int ossl_decoder_store_cache_flush(OSSL_LIB_CTX *libctx)` —
/// `crypto/encode_decode/decoder_meth.c`.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn ossl_decoder_store_cache_flush(libctx: *mut c_void) -> c_int {
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_DECODER_STORE_INDEX);
    assert_slot_unfilled(store, "ossl_decoder_store_cache_flush", "Phase 7");
    1
}

/// `int ossl_store_loader_store_cache_flush(OSSL_LIB_CTX *libctx)` —
/// `crypto/store/store_meth.c`.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn ossl_store_loader_store_cache_flush(libctx: *mut c_void) -> c_int {
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX);
    assert_slot_unfilled(store, "ossl_store_loader_store_cache_flush", "Phase 10");
    1
}

/// `int evp_method_store_remove_all_provided(const OSSL_PROVIDER *prov)` —
/// `crypto/evp/evp_fetch.c`.
///
/// The store is looked up through the provider's **own** context, not through a
/// caller-supplied one: that is the whole reason this function exists in the shape it
/// does, and it is one line of the authority.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn evp_method_store_remove_all_provided(prov: *const OsslProvider) -> c_int {
    // SAFETY: `prov` is live.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX);
    assert_slot_unfilled(store, "evp_method_store_remove_all_provided", "Phase 7");
    1
}

/// `int ossl_encoder_store_remove_all_provided(const OSSL_PROVIDER *prov)` —
/// `crypto/encode_decode/encoder_meth.c`.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn ossl_encoder_store_remove_all_provided(prov: *const OsslProvider) -> c_int {
    // SAFETY: `prov` is live.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_ENCODER_STORE_INDEX);
    assert_slot_unfilled(store, "ossl_encoder_store_remove_all_provided", "Phase 7");
    1
}

/// `int ossl_decoder_store_remove_all_provided(const OSSL_PROVIDER *prov)` —
/// `crypto/encode_decode/decoder_meth.c`.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn ossl_decoder_store_remove_all_provided(prov: *const OsslProvider) -> c_int {
    // SAFETY: `prov` is live.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_DECODER_STORE_INDEX);
    assert_slot_unfilled(store, "ossl_decoder_store_remove_all_provided", "Phase 7");
    1
}

/// `int ossl_store_loader_store_remove_all_provided(const OSSL_PROVIDER *prov)` —
/// `crypto/store/store_meth.c`.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn ossl_store_loader_store_remove_all_provided(
    prov: *const OsslProvider,
) -> c_int {
    // SAFETY: `prov` is live.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX);
    assert_slot_unfilled(
        store,
        "ossl_store_loader_store_remove_all_provided",
        "Phase 10",
    );
    1
}

/// `int ossl_decoder_cache_flush(OSSL_LIB_CTX *libctx)` — `crypto/encode_decode/decoder_pkey.c`.
///
/// The one bridge whose absent case answers **0**, and the one whose body the
/// authority writes with a lock: `CRYPTO_THREAD_write_lock(cache->lock)`, then
/// `lh_DECODER_CACHE_ENTRY_doall(hashtable, decoder_cache_entry_free)`, then
/// `lh_DECODER_CACHE_ENTRY_flush`. Both of those are the decoder cache's own, which
/// `ossl_decoder_cache_new` creates in Phase 7.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn ossl_decoder_cache_flush(libctx: *mut c_void) -> c_int {
    let cache = lib_ctx_get_data(libctx, OSSL_LIB_CTX_DECODER_CACHE_INDEX);
    if cache.is_null() {
        // The authority's `if (cache == NULL) return 0;`.
        return 0;
    }
    assert_slot_unfilled(cache, "ossl_decoder_cache_flush", "Phase 7");
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::OSSL_LIB_CTX_new;

    /// The invariant the five bridges rest on, checked rather than assumed: in this
    /// build no method store and no decoder cache exists, so every one of the nine
    /// delegations is unreachable and each answers the authority's *absent* value.
    ///
    /// If a later stratum fills one of these slots, this test fails **before** the
    /// first activation reaches the assertion in the bridge, which is the point: the
    /// reader learns which slot moved rather than which call happened to run first.
    #[test]
    fn the_five_slots_are_unfilled() {
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // `lib_ctx_get_data` is a SAFE function in this crate (D113), so this is not
        // guarded: a NULL context is the default one and the read is total.
        let empty = {
            let mut empty = 0;
            for index in [
                OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX,
                OSSL_LIB_CTX_ENCODER_STORE_INDEX,
                OSSL_LIB_CTX_DECODER_STORE_INDEX,
                OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX,
                OSSL_LIB_CTX_DECODER_CACHE_INDEX,
            ] {
                if !lib_ctx_get_data(ctx, index).is_null() {
                    empty += 1;
                }
            }
            empty
        };
        assert_eq!(
            empty, 0,
            "a method-store slot has been filled by another stratum"
        );
    }

    /// Each bridge answers the authority's *absent-store* value, which is what the
    /// two sums in `provider_flush_store_cache` and `provider_store_methods` compare
    /// against 4. Getting any of them wrong turns a successful activation into a
    /// reported failure, so the values are asserted rather than assumed.
    #[test]
    fn every_absent_store_answers_the_authoritys_value() {
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live and NULL-or-live is every one of these contracts.
        unsafe {
            assert_eq!(evp_method_store_cache_flush(ctx), 1);
            assert_eq!(ossl_encoder_store_cache_flush(ctx), 1);
            assert_eq!(ossl_decoder_store_cache_flush(ctx), 1);
            assert_eq!(ossl_store_loader_store_cache_flush(ctx), 1);
            // The exception: an absent decoder *cache* answers 0, not 1.
            assert_eq!(ossl_decoder_cache_flush(ctx), 0);
        }
    }
}
