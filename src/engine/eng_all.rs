//! Phase 13.1 — `crypto/engine/eng_all.c`: the built-in-engine loader.
//!
//! `eng_all.c` is 24 lines and publishes one export, `ENGINE_load_builtin_engines`
//! (`:13-16`), whose whole body is `OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN,
//! NULL)`. 10.9 withheld it by name because the crate's `OPENSSL_init_crypto` refused the
//! `ENGINE_*` bits (`INIT_UNSUPPORTED`, `src/runtime/init.rs`), so the call it is would have
//! been the crate's refusal rather than the authority's registration. 13.1 lands it: the call
//! is now the authority's, and the divergence that remains is recorded rather than hidden.
//!
//! ## What the call does on each side, measured rather than argued
//!
//! On the authority the bit is honoured: `ossl_init_engine_rdrand` and
//! `ossl_init_engine_dynamic` register the two engines this build carries — a probe against
//! `openssl-3.6.4-production` finds `rdrand` and `dynamic` in the registry afterwards, in
//! that order. In this crate the bit is still on `INIT_UNSUPPORTED`, so the call raises
//! `ERR_R_INIT_FAIL` and returns zero, and **no engine is registered**. Transcribing the
//! authority's body is still the right answer under `docs/SECURITY_DIVERGENCE_POLICY.md`: the
//! withheld alternative, an empty function, would answer the authority's own registration with
//! a silent no-op and leave no coordinate at all, whereas the transcribed call is the
//! authority's line and its effect is the recorded divergence.
//!
//! ## What the court therefore compares, and what it does not
//!
//! `RT-ENGINE` drives the loader but never observes the built-in registry directly: the two
//! sides' registries differ by exactly those two engines, so any arm that reads the list
//! (`ENGINE_get_first`) or looks up `rdrand`/`dynamic` would compare a difference the
//! subphase does not claim to have closed. The arm it does drive is the loader's *effect on an
//! engine the probe itself registered* — `ENGINE_by_id` still finds it afterwards, because the
//! loader appends rather than replaces — which is identical on both sides.
//!
//! `ENGINE_setup_bsd_cryptodev` (`:20-23`) is not in the admitted build — it is guarded by
//! `__OpenBSD__`/`__FreeBSD__`/`__DragonFly__` — so there is nothing to transcribe for it.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::init::OPENSSL_init_crypto;

/// `OPENSSL_INIT_ENGINE_ALL_BUILTIN` — `include/openssl/crypto.h`: the union of
/// `OPENSSL_INIT_ENGINE_RDRAND` (`0x0200`), `_DYNAMIC` (`0x0400`), `_OPENSSL` (`0x0800`),
/// `_CRYPTODEV` (`0x1000`), `_CAPI` (`0x2000`), `_PADLOCK` (`0x4000`) and `_AFALG` (`0x8000`).
const OPENSSL_INIT_ENGINE_ALL_BUILTIN: u64 = 0x0000_FE00;

/// `void ENGINE_load_builtin_engines(void)` — `crypto/engine/eng_all.c:13-16`.
///
/// The one call is `OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL)`; the
/// authority discards the answer, and so does this transcription.
///
/// # Safety
///
/// The caller must accept the process-global effect the authority's own call has: it drives
/// `OPENSSL_init_crypto`, which writes the run-once state and the registry (and, in this crate,
/// raises `ERR_R_INIT_FAIL` on the still-unsupported `ENGINE_*` bit).
#[no_mangle]
pub unsafe extern "C" fn ENGINE_load_builtin_engines() {
    guard_ffi((), || {
        // The settings pointer is NULL, which the authority's own call passes and which
        // `OPENSSL_init_crypto` accepts as "default settings".
        OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN, ptr::null());
    })
}
