//! `crypto/evp/p_lib.c`'s engine remainder — `EVP_PKEY_set1_engine` and
//! `EVP_PKEY_get0_engine`.
//!
//! # Why these two are their own file, and what is *not* here
//!
//! `crypto/evp/p_lib.c` defines ninety-odd exports, and by the time this subphase runs every one of
//! them but these two has landed: the object, its lifetime and its provider half are
//! [`crate::evp::pkey`], the ASN.1 method surface is [`crate::evp::pkey_asn1`], and the parameter
//! accessors are split across their units. The two that remain are the pair a plain `#ifndef
//! OPENSSL_NO_ENGINE` guards (`p_lib.c:731-754`), and they are the only `p_lib.c` functions that
//! touch a live `ENGINE`.
//!
//! They are transcribed here rather than folded into [`crate::evp::pkey`] because the module layout
//! follows the authority's translation unit, and because their correctness is a property of the
//! engine framework ([`crate::engine`]) rather than of the key object: `EVP_PKEY_set1_engine`
//! validates the engine's key-method table before it keeps a reference, and `EVP_PKEY_get0_engine`
//! is a bare field read.
//!
//! # The two fields are not the same field
//!
//! `EVP_PKEY_set1_engine` stores its argument in `pkey->pmeth_engine` (`p_lib.c:746`), while
//! `EVP_PKEY_get0_engine` reads `pkey->engine` (`p_lib.c:752`). The authority's two accessors are
//! therefore **not** inverses, and this file transcribes that literally: it writes `pmeth_engine`
//! and reads `engine`, exactly as the C does, rather than "fixing" one spelling to the other.
//!
//! # The engine pointer's type at the boundary
//!
//! `struct evp_pkey_st` models its two engine slots as `*mut Engine` where `Engine` is
//! [`crate::evp::pkey_asn1`]'s opaque placeholder, declared before Phase 13.1 landed the framework.
//! This module works with the concrete [`crate::engine::eng_lib::Engine`], because that is what the
//! `ENGINE_*` entry points take, so the two crossings are explicit `.cast()`s. Both are thin
//! pointers to the same object, so the re-typing is free and preserves the stored value.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::engine::eng_init::{ENGINE_finish, ENGINE_init};
use crate::engine::eng_lib::Engine;
use crate::engine::tb_pkmeth::ENGINE_get_pkey_meth;
use crate::evp::pkey::EvpPkey;
use crate::evp::pkey_asn1::Engine as PkeyEngine;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;

/// `int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *e)` — `crypto/evp/p_lib.c:732-748`.
///
/// A non-NULL engine is acquired and validated first: `ENGINE_init` takes the functional reference,
/// and `ENGINE_get_pkey_meth(e, pkey->type)` must find a public-key method for the key's type or the
/// reference is dropped and the call refuses. Only then is the previous `pmeth_engine` released and
/// the new one stored. A NULL engine skips straight to the release-and-store, so clearing the slot
/// always succeeds.
///
/// The failure reasons are the authority's own sites: `ERR_R_ENGINE_LIB` when `ENGINE_init` fails
/// (`p_lib.c:736`) and `EVP_R_UNSUPPORTED_ALGORITHM` when the engine has no method for the type
/// (`p_lib.c:741`).
///
/// # Safety
/// `pkey` must point to a live [`EvpPkey`]; `e` must be NULL or point to a live engine.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_engine(pkey: *mut EvpPkey, e: *mut Engine) -> c_int {
    if !e.is_null() {
        // SAFETY: `e` is non-NULL and the caller handed a live engine.
        if unsafe { ENGINE_init(e) } == 0 {
            // SAFETY: a compile-time-constant site whose strings are static.
            unsafe { raise_site(&err_sites::P_LIB_736) };
            return 0;
        }
        // SAFETY: `pkey` is live per the caller's contract.
        let type_ = unsafe { (*pkey).type_ };
        // SAFETY: `e` is live and initialised.
        if unsafe { ENGINE_get_pkey_meth(e, type_) }.is_null() {
            // SAFETY: `e` is live and initialised, and this call releases the reference just taken.
            unsafe { ENGINE_finish(e) };
            // SAFETY: a compile-time-constant site whose strings are static.
            unsafe { raise_site(&err_sites::P_LIB_741) };
            return 0;
        }
    }
    // SAFETY: `pkey` is live; the field holds the crate's opaque engine pointer, re-typed here to
    // the concrete engine the release entry point takes.
    let previous = unsafe { (*pkey).pmeth_engine }.cast::<Engine>();
    // SAFETY: `previous` is NULL or a live engine the key held a reference to; `ENGINE_finish` is a
    // no-op for NULL.
    unsafe { ENGINE_finish(previous) };
    // SAFETY: `pkey` is live; the incoming engine is re-typed back to the field's declared type so
    // the value stored is the same pointer the caller passed.
    unsafe { (*pkey).pmeth_engine = e.cast::<PkeyEngine>() };
    1
}

/// `ENGINE *EVP_PKEY_get0_engine(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:750-753`.
///
/// A bare `return pkey->engine;`. It reads the field `p_lib.c` has `EVP_PKEY_set1_engine` write,
/// which is `pmeth_engine`, **not** `engine` — see this file's module doc. The returned pointer is
/// borrowed: no reference is taken, so the caller must not finish it.
///
/// # Safety
/// `pkey` must point to a live [`EvpPkey`].
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_engine(pkey: *const EvpPkey) -> *mut Engine {
    // SAFETY: `pkey` is live; the field holds the crate's opaque engine pointer, re-typed to the
    // concrete engine the accessor's signature publishes.
    unsafe { (*pkey).engine }.cast::<Engine>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new};

    /// With no engine ever set, both accessors agree the slot is empty, and clearing an already-NULL
    /// slot succeeds — the NULL arm the behavioural court also drives.
    #[test]
    fn a_fresh_key_has_no_engine_and_clears_to_null() {
        // SAFETY: `EVP_PKEY_new` allocates; the result is checked before use.
        let pkey = unsafe { EVP_PKEY_new() };
        assert!(!pkey.is_null());
        // SAFETY: `pkey` is live.
        assert!(unsafe { EVP_PKEY_get0_engine(pkey) }.is_null());
        // SAFETY: `pkey` is live; a NULL engine is the authority's clearing arm.
        let cleared = unsafe { EVP_PKEY_set1_engine(pkey, core::ptr::null_mut()) };
        assert_eq!(cleared, 1);
        // SAFETY: `pkey` is live.
        assert!(unsafe { EVP_PKEY_get0_engine(pkey) }.is_null());
        // SAFETY: `pkey` is this test's own allocation.
        unsafe { EVP_PKEY_free(pkey) };
    }
}
