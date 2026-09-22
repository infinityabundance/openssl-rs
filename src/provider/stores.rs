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
//! Phase 10. **Slot 10 left the set in D357 and slots 11 and 20 left it in D365**: the encoder
//! landing built the encoder store and implemented its two delegations, and the decoder landing
//! built the decoder store and cache in `context_init` and implemented the three delegations
//! below, exactly as D142 did for slot 0. Slot 15 alone remains unfilled, and
//! `docs/PHASE-6-SUBPHASES.md`'s index table records it as unfilled with its owner.
//!
//! The delegation body -- `ossl_method_store_cache_flush_all` and
//! `ossl_method_store_remove_all_provided`, both in `crypto/property/property.c` --
//! landed with 6.7c, so a *filled* slot's delegation is a real call. What remains
//! unfilled (slots 11, 15 and 20) still has nothing to delegate to in this build,
//! and for those the authority's branch is written as the same shape
//! `create_provider_children` uses: guarded by an `assert!` stating the invariant that
//! the slot is unfilled. That makes the invariant **checkable** rather than assumed --
//! a later stratum that fills one of these slots without landing the call fails loudly
//! at the first activation instead of silently flushing nothing, which is the failure
//! mode that would be hardest to attribute later. That is exactly what happened to
//! slot 10 in D357: the assertion fired when `context_init` started building the
//! encoder store, and the answer was to write the delegation.
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
/// **Implemented in D357**, when slot 10 stopped being unfilled: `context_init` builds the encoder
/// store, so the authority's branch -- flush it if it is there, answer 1 if it is not -- can be
/// taken and there is no longer anything to check rather than call. The absent arm still answers 1,
/// which is what `provider_flush_store_cache`'s `== 4` sum depends on.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn ossl_encoder_store_cache_flush(libctx: *mut c_void) -> c_int {
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_ENCODER_STORE_INDEX)
        .cast::<crate::property::store::OsslMethodStore>();
    if !store.is_null() {
        // SAFETY: the slot holds a store `context_init` built and released once, so it is live
        // here; a store nothing has added to has an empty cache, which the flush handles.
        return unsafe { crate::property::store::ossl_method_store_cache_flush_all(store) };
    }
    1
}

/// `int ossl_decoder_store_cache_flush(OSSL_LIB_CTX *libctx)` —
/// `crypto/encode_decode/decoder_meth.c`.
///
/// **Implemented in D365**, when slot 11 stopped being unfilled: `context_init` builds the decoder
/// store in the authority's own position, so the branch can be taken and there is no longer
/// anything to assert rather than call.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn ossl_decoder_store_cache_flush(libctx: *mut c_void) -> c_int {
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_DECODER_STORE_INDEX)
        .cast::<crate::property::store::OsslMethodStore>();
    if !store.is_null() {
        // SAFETY: the slot holds a store `context_init` built and released once, so it is live
        // here; a store nobody has added to has an empty cache, which the flush handles.
        return unsafe { crate::property::store::ossl_method_store_cache_flush_all(store) };
    }
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
/// **Implemented in D357**, its sibling's reason one level down: the store the delegation needs
/// exists now, and the authority's own body reads it through the provider's context.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn ossl_encoder_store_remove_all_provided(prov: *const OsslProvider) -> c_int {
    // SAFETY: `prov` is live.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_ENCODER_STORE_INDEX)
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

/// `int ossl_decoder_store_remove_all_provided(const OSSL_PROVIDER *prov)` —
/// `crypto/encode_decode/decoder_meth.c`.
///
/// **Implemented in D365**, its sibling's reason one level down: the store the delegation needs
/// exists now, and the authority's own body reads it through the provider's context.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn ossl_decoder_store_remove_all_provided(prov: *const OsslProvider) -> c_int {
    // SAFETY: `prov` is live.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    let store = lib_ctx_get_data(libctx, OSSL_LIB_CTX_DECODER_STORE_INDEX)
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
/// The one bridge whose absent case answers **0**, and the one whose body the authority writes with
/// a lock. **Implemented in D365**, with the cache the same commit fills slot 20 with: this is a
/// delegation to `src/decoder_pkey.rs`'s own `ossl_decoder_cache_flush`, which is where the lock,
/// the doall and the flush live.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn ossl_decoder_cache_flush(libctx: *mut c_void) -> c_int {
    // SAFETY: `libctx` is NULL or live per the contract; the module it delegates to is this
    // crate's transcription of the same authority function.
    unsafe { crate::decoder_pkey::ossl_decoder_cache_flush(libctx) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::OSSL_LIB_CTX_new;

    /// The invariant the remaining bridge rests on, checked rather than assumed.
    ///
    /// **Slots 11 and 20 left the set in D365, the way slot 10 left it in D357 and slot 0 in
    /// D142.** The decoder landing fills both in `context_init`'s authority position -- the
    /// decoder store then the cache, before the encoder store -- and implements the three bridges
    /// that delegate to them, so the assertions this test used to make about those two fired
    /// exactly as designed. What remains unfilled is slot 15 alone, whose reader is Phase 10's
    /// `store_meth.c`.
    #[test]
    fn the_four_method_stores_and_the_cache_are_filled_and_slot_fifteen_is_not() {
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // `lib_ctx_get_data` is a SAFE function in this crate (D113), so this is not
        // guarded: a NULL context is the default one and the read is total.
        for (index, what) in [
            (OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX, "the EVP method store"),
            (OSSL_LIB_CTX_DECODER_STORE_INDEX, "the decoder method store"),
            (OSSL_LIB_CTX_DECODER_CACHE_INDEX, "the decoder cache"),
            (OSSL_LIB_CTX_ENCODER_STORE_INDEX, "the encoder method store"),
        ] {
            assert!(
                !lib_ctx_get_data(ctx, index).is_null(),
                "context_init builds {what}"
            );
        }
        assert!(
            lib_ctx_get_data(ctx, OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX).is_null(),
            "slot 15 is still filled by a stratum that has not landed"
        );
    }

    /// Each bridge answers the authority's value for the store its context now holds: the four
    /// method stores have empty caches, so the flush is the authority's own `!= 0` sum's **1**, and
    /// the decoder cache's flush is **1** too -- it is not absent any more, and its body takes the
    /// lock and empties an already-empty table.
    #[test]
    fn every_bridge_answers_the_authoritys_value() {
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live and NULL-or-live is every one of these contracts.
        unsafe {
            assert_eq!(evp_method_store_cache_flush(ctx), 1);
            assert_eq!(ossl_encoder_store_cache_flush(ctx), 1);
            assert_eq!(ossl_decoder_store_cache_flush(ctx), 1);
            assert_eq!(ossl_store_loader_store_cache_flush(ctx), 1);
            assert_eq!(ossl_decoder_cache_flush(ctx), 1);
        }
    }
}
