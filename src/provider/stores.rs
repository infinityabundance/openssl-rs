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
/// **Implemented in D142**, when slot 0 stopped being unfilled: `context_init` builds the store
/// now, so the authority's branch — flush it if it is there, answer 1 if it is not — can be taken
/// and there is no longer anything to check rather than call. The absent arm still answers 1, which
/// is what `provider_flush_store_cache`'s `== 4` sum depends on.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn evp_method_store_cache_flush(libctx: *mut c_void) -> c_int {
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX)
        .cast::<crate::property::store::OsslMethodStore>();
    if !store.is_null() {
        // SAFETY: the slot holds a store `context_init` built and released once, so it is live
        // here; a store nobody has added to has an empty cache, which the flush handles.
        return unsafe { crate::property::store::ossl_method_store_cache_flush_all(store) };
    }
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
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX)
        .cast::<crate::property::store::OsslMethodStore>();
    if !store.is_null() {
        // SAFETY: the slot holds a store `context_init` built; `prov` is live, and the store
        // compares it by identity against the implementations it holds.
        return unsafe {
            crate::property::store::ossl_method_store_remove_all_provided(store, prov)
        };
    }
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

    /// The invariant the remaining bridges rest on, checked rather than assumed.
    ///
    /// **Slot 0 is no longer in the set.** D142 built the EVP method store — `context_init` fills
    /// slot 0 — and implemented the two bridges that delegate to it, so the assertion this test
    /// used to make fired exactly as designed and the answer is the one it pointed at: write the
    /// delegation. What remains unfilled is slots 10, 11, 15 and 20, whose readers are Phase 10's
    /// `encoder_meth.c`, `decoder_meth.c` and `store_meth.c` and Phase 10's decoder cache.
    #[test]
    fn the_evp_store_slot_is_filled_and_the_other_four_are_not() {
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // `lib_ctx_get_data` is a SAFE function in this crate (D113), so this is not
        // guarded: a NULL context is the default one and the read is total.
        assert!(
            !lib_ctx_get_data(ctx, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX).is_null(),
            "context_init builds the EVP method store"
        );
        let mut filled = 0;
        for index in [
            OSSL_LIB_CTX_ENCODER_STORE_INDEX,
            OSSL_LIB_CTX_DECODER_STORE_INDEX,
            OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX,
            OSSL_LIB_CTX_DECODER_CACHE_INDEX,
        ] {
            if !lib_ctx_get_data(ctx, index).is_null() {
                filled += 1;
            }
        }
        assert_eq!(
            filled, 0,
            "a Phase 10 slot has been filled without the delegation it needs"
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
