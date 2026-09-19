//! Phase 8.3 — `providers/common/provider_util.c`'s `PROV_CIPHER` half, the layer a provider
//! row uses to resolve a *named* cipher in its own library context.
//!
//! `cmac_prov.c` is the first landed caller: `cmac_set_ctx_params` receives a `cipher` string
//! (`OSSL_MAC_PARAM_CIPHER`, which `ossl_siv128_init` sets to the CBC name it was handed) and
//! `ossl_prov_cipher_load` turns it into an `EVP_CIPHER` fetched in
//! `PROV_LIBCTX_OF(macctx->provctx)`. That is the whole reason this unit exists here rather than
//! with the digest and encoder rows that will use its sibling halves: CMAC's construction is
//! *parameterised by a cipher*, and the parameter arrives as a name.
//!
//! ## The ENGINE arms are narrowed, and the narrowing is named
//!
//! `provider_util.c`'s `set_engine` looks an engine up by name and takes a functional reference
//! to it, and its `ossl_prov_cipher_reset`/`_copy` release and re-take that reference. This crate
//! transcribes no `ENGINE` registry — `src/evp/cipher_ctx.rs` records the same boundary for
//! `evp_enc.c`'s engine arms, where `ctx->engine` is always NULL — so `ENGINE_by_id` has no
//! answer for any name here. A caller that supplies an `engine` parameter therefore gets the
//! authority's answer for an engine the registry does **not** hold (a refusal, `0`), and a
//! caller whose name the authority *does* hold gets a refusal where the authority succeeds.
//!
//! That is a narrowed claim rather than a hidden one, in `docs/SECURITY_DIVERGENCE_POLICY.md`
//! §4's sense: the parameter is reachable (it is a decoder key, not only a settable-list entry),
//! the divergence is recorded, and the *scope removed* is exactly "a caller that names an engine
//! the authority's build holds". No landed row and no court exercises it, because no engine is
//! built into this profile's provider set.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_up_ref, EvpCipher};
use crate::evp::legacy_evp::EVP_get_cipherbyname;
use crate::params::{OsslParam, OSSL_PARAM_UTF8_STRING};
use crate::runtime::err::{ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};

/// `EVP_ORIG_GLOBAL` — `crypto/evp/evp_lib.c`'s method-origin values, as
/// `src/evp/cipher.rs:85` declares it. Repeated rather than re-exported for the same reason the
/// authority repeats the constant per translation unit: it is a number, not a symbol.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `OSSL_ALG_PARAM_CIPHER` — `core_names.h:127` (`"cipher"`).
pub(crate) const OSSL_ALG_PARAM_CIPHER: *const core::ffi::c_char = c"cipher".as_ptr();
/// `OSSL_ALG_PARAM_PROPERTIES` — `core_names.h`, aliased by `OSSL_MAC_PARAM_PROPERTIES`.
pub(crate) const OSSL_ALG_PARAM_PROPERTIES: *const core::ffi::c_char = c"properties".as_ptr();
/// `OSSL_ALG_PARAM_ENGINE` — `core_names.h:129` (`"engine"`).
pub(crate) const OSSL_ALG_PARAM_ENGINE: *const core::ffi::c_char = c"engine".as_ptr();

/// `PROV_CIPHER` — `prov/provider_util.h:16-25`. `cipher` caches the cipher always, while
/// `alloc_cipher` holds the reference to an explicitly *fetched* one — the distinction
/// `ossl_prov_cipher_reset` exists to keep, because a cipher that was only looked up must not be
/// freed.
#[repr(C)]
pub(crate) struct ProvCipher {
    /// `const EVP_CIPHER *cipher`.
    pub cipher: *const EvpCipher,
    /// `EVP_CIPHER *alloc_cipher` — the fetched cipher.
    pub alloc_cipher: *mut EvpCipher,
    /// `ENGINE *engine` — always NULL here; see the module note.
    pub engine: *mut c_void,
}

/// `void ossl_prov_cipher_reset(PROV_CIPHER *pc)` — `provider_util.c:24-33`.
///
/// # Safety
/// `pc` points at a live, writable `PROV_CIPHER`.
pub(crate) unsafe fn ossl_prov_cipher_reset(pc: *mut ProvCipher) {
    // SAFETY: the caller's contract.
    unsafe {
        EVP_CIPHER_free((*pc).alloc_cipher);
        (*pc).alloc_cipher = ptr::null_mut();
        (*pc).cipher = ptr::null();
        // `ENGINE_finish(pc->engine)` follows in the authority under `!OPENSSL_NO_ENGINE`; the
        // field is always NULL here (the module note), so there is no reference to release.
        (*pc).engine = ptr::null_mut();
    }
}

/// `int ossl_prov_cipher_copy(PROV_CIPHER *dst, const PROV_CIPHER *src)` —
/// `provider_util.c:35-49`. The reference is up'd **before** the fields are written, so a failed
/// up-ref leaves `dst` untouched; that ordering is what `cmac_dup`'s cleanup path depends on.
///
/// # Safety
/// `dst` is writable and `src` readable; both point at live `PROV_CIPHER`s.
pub(crate) unsafe fn ossl_prov_cipher_copy(dst: *mut ProvCipher, src: *const ProvCipher) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if !(*src).alloc_cipher.is_null() && EVP_CIPHER_up_ref((*src).alloc_cipher) == 0 {
            return 0;
        }
        // `ENGINE_init(src->engine)` follows in the authority under `!OPENSSL_NO_ENGINE`; the
        // field is always NULL here, so there is nothing to take a reference to.
        (*dst).engine = (*src).engine;
        (*dst).cipher = (*src).cipher;
        (*dst).alloc_cipher = (*src).alloc_cipher;
        1
    }
}

/// `static int set_propq(const OSSL_PARAM *propq, const char **propquery)` —
/// `provider_util.c:51-60`. A non-UTF8 property query is a refusal rather than a NULL query.
///
/// # Safety
/// `propq` is NULL or a live descriptor.
unsafe fn set_propq(propq: *const OsslParam, propquery: *mut *const core::ffi::c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        *propquery = ptr::null();
        if !propq.is_null() {
            if (*propq).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            *propquery = (*propq).data.cast();
        }
        1
    }
}

/// `static int set_engine(const OSSL_PARAM *e, ENGINE **engine)` — `provider_util.c:62-90`,
/// narrowed: the crate builds no engine registry, so a non-NULL `engine` parameter is refused
/// and a NULL one is a no-op. See the module note for the exact scope removed from the claim.
///
/// # Safety
/// `engine` is writable; `e` is NULL or a live descriptor.
unsafe fn set_engine(e: *const OsslParam, engine: *mut *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        // `ENGINE_finish(*engine)` precedes this in the authority; the field is always NULL.
        *engine = ptr::null_mut();
        if !e.is_null() {
            if (*e).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            // `ENGINE_by_id(e->data)` + `ENGINE_init` + `ENGINE_free` in the authority. With no
            // registry there is no engine for any name, which is the authority's own answer for
            // a name it cannot resolve.
            return 0;
        }
        1
    }
}

/// `int ossl_prov_cipher_load(PROV_CIPHER *pc, const OSSL_PARAM *cipher,
/// const OSSL_PARAM *propq, const OSSL_PARAM *engine, OSSL_LIB_CTX *ctx)` —
/// `provider_util.c:90-123`.
///
/// Three details are contract rather than detail: the ERR mark is taken so a *failed* fetch does
/// not leave its error on the queue when the legacy fallback succeeds; the fallback excludes a
/// cipher whose `origin` is `EVP_ORIG_GLOBAL` ("Do not use global EVP_CIPHERs"); and a NULL
/// `cipher` descriptor is **success** with `pc->cipher` left NULL, which is how a caller asks for
/// "no cipher" rather than for a failure.
///
/// # Safety
/// `pc` is writable; the three descriptors are NULL or live; `ctx` is NULL or a live library
/// context.
pub(crate) unsafe fn ossl_prov_cipher_load(
    pc: *mut ProvCipher,
    cipher: *const OsslParam,
    propq: *const OsslParam,
    engine: *const OsslParam,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut propquery: *const core::ffi::c_char = ptr::null();

        if set_propq(propq, &mut propquery) == 0
            || set_engine(engine, ptr::addr_of_mut!((*pc).engine)) == 0
        {
            return 0;
        }

        if cipher.is_null() {
            return 1;
        }
        if (*cipher).data_type != OSSL_PARAM_UTF8_STRING {
            return 0;
        }

        EVP_CIPHER_free((*pc).alloc_cipher);
        ERR_set_mark();
        (*pc).alloc_cipher = EVP_CIPHER_fetch(ctx, (*cipher).data.cast(), propquery);
        (*pc).cipher = (*pc).alloc_cipher;
        if (*pc).cipher.is_null() {
            let evp_cipher = EVP_get_cipherbyname((*cipher).data.cast());

            /* Do not use global EVP_CIPHERs */
            if !evp_cipher.is_null() && (*evp_cipher).origin != EVP_ORIG_GLOBAL {
                (*pc).cipher = evp_cipher;
            }
        }
        if !(*pc).cipher.is_null() {
            ERR_pop_to_mark();
        } else {
            ERR_clear_last_mark();
        }
        c_int::from(!(*pc).cipher.is_null())
    }
}

/// `int ossl_prov_cipher_load_from_params(PROV_CIPHER *pc, const OSSL_PARAM params[],
/// OSSL_LIB_CTX *ctx)` — `provider_util.c:125-134`: the three-key form of the above.
///
/// # Safety
/// `pc` is writable; `params` is a terminated array; `ctx` is NULL or live.
#[allow(dead_code)] // the digest and encoder provider rows are the callers that will land
pub(crate) unsafe fn ossl_prov_cipher_load_from_params(
    pc: *mut ProvCipher,
    params: *const OsslParam,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_prov_cipher_load(
            pc,
            crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER),
            crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES),
            crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE),
            ctx,
        )
    }
}

/// `const EVP_CIPHER *ossl_prov_cipher_cipher(const PROV_CIPHER *pc)` —
/// `provider_util.c:136-139`.
///
/// # Safety
/// `pc` points at a live `PROV_CIPHER`.
pub(crate) unsafe fn ossl_prov_cipher_cipher(pc: *const ProvCipher) -> *const EvpCipher {
    // SAFETY: the caller's contract.
    unsafe { (*pc).cipher }
}

/// `ENGINE *ossl_prov_cipher_engine(const PROV_CIPHER *pc)` — `provider_util.c:141-144`. Always
/// NULL here, because nothing can set the field (the module note).
///
/// # Safety
/// `pc` points at a live `PROV_CIPHER`.
pub(crate) unsafe fn ossl_prov_cipher_engine(pc: *const ProvCipher) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { (*pc).engine }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_cipher_descriptor_is_success_with_a_null_cipher() {
        let mut pc = ProvCipher {
            cipher: ptr::null(),
            alloc_cipher: ptr::null_mut(),
            engine: ptr::null_mut(),
        };
        // SAFETY: `pc` is this frame's own struct; every descriptor is NULL.
        unsafe {
            assert_eq!(
                ossl_prov_cipher_load(
                    ptr::addr_of_mut!(pc),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                1
            );
            assert!(ossl_prov_cipher_cipher(ptr::addr_of!(pc)).is_null());
            assert!(ossl_prov_cipher_engine(ptr::addr_of!(pc)).is_null());
        }
    }

    #[test]
    fn a_non_utf8_property_query_is_refused() {
        let mut pc: ProvCipher = ProvCipher {
            cipher: ptr::null(),
            alloc_cipher: ptr::null_mut(),
            engine: ptr::null_mut(),
        };
        // A UNSIGNED_INTEGER descriptor in the `properties` position.
        let mut n: usize = 3;
        // SAFETY: `bad` is written once by the constructor into this frame's own slot.
        let bad = unsafe {
            crate::params::OSSL_PARAM_construct_size_t(
                OSSL_ALG_PARAM_PROPERTIES,
                ptr::addr_of_mut!(n),
            )
        };
        // SAFETY: `pc` is this frame's own struct and `bad` is a live descriptor.
        unsafe {
            assert_eq!(
                ossl_prov_cipher_load(
                    ptr::addr_of_mut!(pc),
                    ptr::null(),
                    ptr::addr_of!(bad),
                    ptr::null(),
                    ptr::null_mut()
                ),
                0
            );
        }
    }

    #[test]
    fn an_engine_parameter_is_refused_and_a_null_one_is_not() {
        let mut pc: ProvCipher = ProvCipher {
            cipher: ptr::null(),
            alloc_cipher: ptr::null_mut(),
            engine: ptr::null_mut(),
        };
        let mut name = *b"rdrand\0";
        // SAFETY: `eng` is written once by the constructor into this frame's own slot.
        let eng = unsafe {
            crate::params::OSSL_PARAM_construct_utf8_string(
                OSSL_ALG_PARAM_ENGINE,
                name.as_mut_ptr().cast(),
                0,
            )
        };
        // SAFETY: `pc` is this frame's own struct and `eng` is a live descriptor.
        unsafe {
            assert_eq!(
                ossl_prov_cipher_load(
                    ptr::addr_of_mut!(pc),
                    ptr::null(),
                    ptr::null(),
                    ptr::addr_of!(eng),
                    ptr::null_mut()
                ),
                0,
                "no engine registry, so naming one is refused"
            );
            assert!(pc.engine.is_null(), "the narrowing leaves the field NULL");
        }
    }
}
