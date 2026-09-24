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

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_up_ref, EvpCipher};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_up_ref, EvpMd};
use crate::evp::legacy_evp::{EVP_get_cipherbyname, EVP_get_digestbyname};
use crate::params::{OsslParam, OSSL_PARAM_UTF8_STRING};
use crate::runtime::err::{ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};

use crate::evp::mac::{
    EVP_MAC_CTX_free, EVP_MAC_CTX_new, EVP_MAC_CTX_set_params, EVP_MAC_fetch, EVP_MAC_free,
    EvpMacCtx,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_utf8_string_ptr,
};

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
/// `OSSL_ALG_PARAM_DIGEST` — `core_names.h` (`"digest"`). The digest half's own key, and the one
/// `hmac_prov.c`'s `set_ctx_params_decoder` locates.
pub(crate) const OSSL_ALG_PARAM_DIGEST: *const core::ffi::c_char = c"digest".as_ptr();

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
/// **`mac_legacy_kmgmt.c` is its first caller** (D389), which is why the `dead_code` allowance it
/// carried while only `hmac_prov.c`'s digest half and the encoder rows were anticipated is gone.
///
/// # Safety
/// `pc` is writable; `params` is a terminated array; `ctx` is NULL or live.
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

/// The `PROV_DIGEST` half, the layer a provider row that receives a digest **name** runs on.
///
/// **`hmac_prov.c` is the caller this half was landed for** (D251). It uses five of the eight
/// functions here: `reset` and `copy` for the row's context, `load` for the `digest`/`properties`
/// pair, and `md`/`engine` to hand the resolved method to `HMAC_Init_ex` and
/// `ssl3_cbc_digest_record`. `fetch` is those five's own callee. The remaining two name the callers
/// that will land rather than being transcribed-and-unused — the rule this crate follows
/// everywhere — and they are marked individually rather than by putting the allow back on the
/// module, so that a *new* dead function here cannot hide behind theirs.
pub(crate) mod prov_digest {
    use super::*;

    // ------------------------------------------------------------------------------------------
    // `PROV_DIGEST` — the same layer for a *named* digest, and the one `hmac_prov.c` runs on
    // ------------------------------------------------------------------------------------------
    //
    // `ossl_prov_digest_*` is `provider_util.c:146-241`, the cipher half's sibling. Both exist for the
    // same reason: a provider row receives a **name** and has to resolve it in its own library context.
    // The two differ in one way that matters -- a digest has a legacy fallback and a cipher has one too,
    // but the digest's is reached through `EVP_get_digestbyname` and is *rejected* when its `origin` is
    // `EVP_ORIG_GLOBAL`, because a global `EVP_MD` is the built-in table's and must not be handed out as
    // if it came from a fetch.

    /// `PROV_DIGEST` — `prov/provider_util.h:34-38`. Three fields, and the `md`/`alloc_md` split is the
    /// same distinction `PROV_CIPHER` keeps: `md` may be a *looked-up* method that was never fetched, so
    /// only `alloc_md` may be freed.
    #[repr(C)]
    pub(crate) struct ProvDigest {
        /// `const EVP_MD *md` — what the row will use.
        pub md: *const EvpMd,
        /// `EVP_MD *alloc_md` — the fetched method, which the row owns.
        pub alloc_md: *mut EvpMd,
        /// `ENGINE *engine` — always NULL here; see the module note on the cipher half's `engine`.
        pub engine: *mut c_void,
    }

    /// `void ossl_prov_digest_reset(PROV_DIGEST *pd)` — `provider_util.c:146-155`.
    ///
    /// # Safety
    /// `pd` points at a live, writable `PROV_DIGEST`.
    pub(crate) unsafe fn ossl_prov_digest_reset(pd: *mut ProvDigest) {
        // SAFETY: the caller's contract.
        unsafe {
            EVP_MD_free((*pd).alloc_md);
            (*pd).alloc_md = ptr::null_mut();
            (*pd).md = ptr::null();
            // The authority's `ENGINE_finish(pd->engine)` is behind `!defined(FIPS_MODULE) &&
            // !defined(OPENSSL_NO_ENGINE)`, and this crate transcribes no engine registry, so the field
            // is cleared and nothing is finished -- the same narrowing the cipher half records.
            (*pd).engine = ptr::null_mut();
        }
    }

    /// `int ossl_prov_digest_copy(PROV_DIGEST *dst, const PROV_DIGEST *src)` —
    /// `provider_util.c:157-171`.
    ///
    /// The reference is up'd **before** the fields are written and, on failure, the caller's `dst` is
    /// left with whatever it had. The `ENGINE_init` arm is narrowed away with the rest of the registry.
    ///
    /// # Safety
    /// `dst` is writable and `src` readable; both point at live `PROV_DIGEST`s.
    pub(crate) unsafe fn ossl_prov_digest_copy(
        dst: *mut ProvDigest,
        src: *const ProvDigest,
    ) -> c_int {
        // SAFETY: the caller's contract.
        unsafe {
            if !(*src).alloc_md.is_null() && EVP_MD_up_ref((*src).alloc_md) == 0 {
                return 0;
            }
            (*dst).engine = (*src).engine;
            (*dst).md = (*src).md;
            (*dst).alloc_md = (*src).alloc_md;
            1
        }
    }

    /// `const EVP_MD *ossl_prov_digest_fetch(PROV_DIGEST *pd, OSSL_LIB_CTX *libctx, const char *mdname,
    /// const char *propquery)` — `provider_util.c:173-180`.
    ///
    /// The previous fetch is released **first**, so a failed re-fetch leaves both fields NULL rather than
    /// leaving the old method in place under a name the caller no longer asked for.
    ///
    /// # Safety
    /// `pd` is writable; `libctx` is NULL or live; `mdname` is NUL-terminated and `propquery` NULL or so.
    pub(crate) unsafe fn ossl_prov_digest_fetch(
        pd: *mut ProvDigest,
        libctx: *mut c_void,
        mdname: *const core::ffi::c_char,
        propquery: *const core::ffi::c_char,
    ) -> *const EvpMd {
        // SAFETY: the caller's contract.
        unsafe {
            EVP_MD_free((*pd).alloc_md);
            (*pd).alloc_md = EVP_MD_fetch(libctx, mdname, propquery);
            (*pd).md = (*pd).alloc_md;
            (*pd).md
        }
    }

    /// `int ossl_prov_digest_load(PROV_DIGEST *pd, const OSSL_PARAM *digest, const OSSL_PARAM *propq,
    /// const OSSL_PARAM *engine, OSSL_LIB_CTX *ctx)` — `provider_util.c:182-213`.
    ///
    /// Three arms are contract. A NULL `digest` descriptor is **success** with nothing resolved, which is
    /// how a caller asks for "no digest yet". The legacy fallback is taken only when the fetch failed
    /// *and* the looked-up method's `origin` is not `EVP_ORIG_GLOBAL`, because a global method belongs to
    /// the built-in table and handing it out would make the row's behaviour depend on the process-wide
    /// table rather than on the fetch. And the error mark is popped on success and cleared on failure, so
    /// the failed fetch's queue entries do not survive a resolved fallback.
    ///
    /// # Safety
    /// `pd` is writable; the three descriptors are NULL or live; `ctx` is NULL or a live library context.
    pub(crate) unsafe fn ossl_prov_digest_load(
        pd: *mut ProvDigest,
        digest: *const OsslParam,
        propq: *const OsslParam,
        engine: *const OsslParam,
        ctx: *mut c_void,
    ) -> c_int {
        // SAFETY: the caller's contract.
        unsafe {
            let mut propquery: *const core::ffi::c_char = ptr::null();
            if set_propq(propq, &mut propquery) == 0
                || set_engine(engine, ptr::addr_of_mut!((*pd).engine)) == 0
            {
                return 0;
            }
            if digest.is_null() {
                return 1;
            }
            if (*digest).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }

            ERR_set_mark();
            ossl_prov_digest_fetch(pd, ctx, (*digest).data.cast(), propquery);
            if (*pd).md.is_null() {
                let md = EVP_get_digestbyname((*digest).data.cast());
                // `Do not use global EVP_MDs` -- the authority's own comment on this line.
                if !md.is_null() && (*md).origin != EVP_ORIG_GLOBAL {
                    (*pd).md = md;
                }
            }
            if !(*pd).md.is_null() {
                ERR_pop_to_mark();
            } else {
                ERR_clear_last_mark();
            }
            (!(*pd).md.is_null()) as c_int
        }
    }

    /// `int ossl_prov_digest_load_from_params(PROV_DIGEST *pd, const OSSL_PARAM params[],
    /// OSSL_LIB_CTX *ctx)` — `provider_util.c:215-224`.
    ///
    /// **Its first caller in this profile is the `KMAC-128`/`KMAC-256` row**, which uses it in
    /// `kmac_fetch_new` to resolve the digest the row is defined over from a one-entry `digest`
    /// descriptor; the remaining callers are the three KDF rows `hkdf.c`, `pvkkdf.c` and `pbkdf2.c`
    /// (Phase 10's).
    ///
    /// # Safety
    /// `pd` is writable; `params` is a terminated array; `ctx` is NULL or live.
    pub(crate) unsafe fn ossl_prov_digest_load_from_params(
        pd: *mut ProvDigest,
        params: *const OsslParam,
        ctx: *mut c_void,
    ) -> c_int {
        // SAFETY: the three descriptors are located in the caller's own array.
        unsafe {
            ossl_prov_digest_load(
                pd,
                crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST),
                crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES),
                crate::params::OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE),
                ctx,
            )
        }
    }

    /// `void ossl_prov_digest_set_md(PROV_DIGEST *pd, EVP_MD *md)` — `provider_util.c:226-230`.
    ///
    /// The caller transfers ownership of `md`, which is why the reset comes first and `alloc_md` takes
    /// the same pointer: a method handed in this way *is* the one to free.
    ///
    /// **No caller in this profile yet.** Its two authority callers are `drbg_hmac.c` and
    /// `drbg_hash.c`, the Phase 9 RAND rows, which build their HMAC over a digest they chose rather
    /// than over one a caller named.
    ///
    /// # Safety
    /// `pd` is writable; `md` is NULL or live and, if live, the caller gives up its reference.
    #[allow(dead_code)] // caller: the Phase 9 `DRBG-HMAC`/`DRBG-HASH` rows
    pub(crate) unsafe fn ossl_prov_digest_set_md(pd: *mut ProvDigest, md: *mut EvpMd) {
        // SAFETY: the caller's contract.
        unsafe {
            ossl_prov_digest_reset(pd);
            (*pd).md = md;
            (*pd).alloc_md = md;
        }
    }

    /// `const EVP_MD *ossl_prov_digest_md(const PROV_DIGEST *pd)` — `provider_util.c:232-235`.
    ///
    /// # Safety
    /// `pd` points at a live `PROV_DIGEST`.
    pub(crate) unsafe fn ossl_prov_digest_md(pd: *const ProvDigest) -> *const EvpMd {
        // SAFETY: the caller's contract.
        unsafe { (*pd).md }
    }

    /// `ENGINE *ossl_prov_digest_engine(const PROV_DIGEST *pd)` — `provider_util.c:237-241`. Always
    /// NULL, for the reason the module note gives.
    ///
    /// # Safety
    /// `pd` points at a live `PROV_DIGEST`.
    pub(crate) unsafe fn ossl_prov_digest_engine(pd: *const ProvDigest) -> *mut c_void {
        // SAFETY: the caller's contract.
        unsafe { (*pd).engine }
    }
}

// =============================================================================================
// `providers/common/provider_util.c` -- the MAC-context half (docs/DECISIONS.md D305)
// =============================================================================================
//
// The rest of `provider_util.c` is transcribed above; these two are the functions `drbg_hmac.c`
// reaches and `src/provider/util.rs` was missing. They are here rather than in a module of their
// own because the file they come from is already this module.

/// `int ossl_prov_set_macctx(EVP_MAC_CTX *macctx, const char *ciphername, const char *mdname,
/// const char *engine, const char *properties)` — `provider_util.c:242-269`.
///
/// The array is `OSSL_PARAM mac_params[5]`: at most `digest`, `cipher`, `properties` and
/// `engine`, plus the terminator. Only non-NULL names are appended, and the `engine` arm **is**
/// compiled in this profile (`OPENSSL_NO_ENGINE` and `FIPS_MODULE` are both undefined). The
/// descriptors borrow the caller's strings, so they must outlive the call — which they do,
/// because they are the parameters' own data.
///
/// # Safety
/// `macctx` is NULL or live; each name pointer is NULL or NUL-terminated and stays live for the
/// call.
#[allow(dead_code)] // the landing caller is `src/provider/rand.rs`'s HMAC-DRBG ctx load
pub(crate) unsafe fn ossl_prov_set_macctx(
    macctx: *mut EvpMacCtx,
    ciphername: *const c_char,
    mdname: *const c_char,
    engine: *const c_char,
    properties: *const c_char,
) -> c_int {
    let mut mac_params: [OsslParam; 5] = [crate::params::END; 5];
    let mut mp = 0usize;

    // SAFETY: each descriptor is built from a caller string that is NUL-terminated per the
    // contract, and `mp` stays below the array's length (four conditional entries at most).
    unsafe {
        if !mdname.is_null() {
            mac_params[mp] =
                OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_DIGEST, mdname.cast_mut(), 0);
            mp += 1;
        }
        if !ciphername.is_null() {
            mac_params[mp] =
                OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_CIPHER, ciphername.cast_mut(), 0);
            mp += 1;
        }
        if !properties.is_null() {
            mac_params[mp] = OSSL_PARAM_construct_utf8_string(
                OSSL_ALG_PARAM_PROPERTIES,
                properties.cast_mut(),
                0,
            );
            mp += 1;
        }
        // `#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)` — both undefined here.
        if !engine.is_null() {
            mac_params[mp] =
                OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_ENGINE, engine.cast_mut(), 0);
            mp += 1;
        }
        mac_params[mp] = OSSL_PARAM_construct_end();

        // The authority returns the setter's value directly; `1` is its "no set_ctx_params
        // callback" answer, which is this crate's too.
        EVP_MAC_CTX_set_params(macctx, mac_params.as_ptr())
    }
}

/// `int ossl_prov_macctx_load(EVP_MAC_CTX **macctx, const OSSL_PARAM *pmac,
/// const OSSL_PARAM *pcipher, const OSSL_PARAM *pdigest, const OSSL_PARAM *propq,
/// const OSSL_PARAM *pengine, const char *macname, const char *ciphername, const char *mdname,
/// OSSL_LIB_CTX *libctx)` — `provider_util.c:271-321`.
///
/// The explicit arguments are consulted only when the corresponding descriptor is absent, and the
/// descriptor only when the argument is NULL. `macname` is `mut` because the authority
/// reassigns it from the `mac` descriptor; so are `ciphername` and `mdname`.
///
/// # Safety
/// `macctx` is writable for one context pointer; the five descriptors are NULL or live; the
/// three names are NULL or NUL-terminated; `libctx` is NULL or a live library context.
#[allow(dead_code)] // the landing caller is `src/provider/rand.rs`'s HMAC-DRBG ctx load
#[allow(clippy::too_many_arguments)] // the authority's own signature has ten parameters: four
                                     // descriptors, four out-parameters, the context and the
                                     // library context. Folding them into a struct would be a
                                     // representation the authority does not have, and the
                                     // call sites pass them positionally from a parameter list.
pub(crate) unsafe fn ossl_prov_macctx_load(
    macctx: *mut *mut EvpMacCtx,
    pmac: *const OsslParam,
    pcipher: *const OsslParam,
    pdigest: *const OsslParam,
    propq: *const OsslParam,
    pengine: *const OsslParam,
    mut macname: *const c_char,
    mut ciphername: *const c_char,
    mut mdname: *const c_char,
    libctx: *mut c_void,
) -> c_int {
    let mut properties: *const c_char = ptr::null();
    let mut engine: *const c_char = ptr::null();

    // SAFETY: the descriptors are NULL or live and the out-parameters are this frame's own; every
    // string read is NUL-terminated by the descriptor's own type check inside
    // `OSSL_PARAM_get_utf8_string_ptr`.
    unsafe {
        if macname.is_null()
            && !pmac.is_null()
            && OSSL_PARAM_get_utf8_string_ptr(pmac, ptr::addr_of_mut!(macname)) == 0
        {
            return 0;
        }
        if !propq.is_null()
            && OSSL_PARAM_get_utf8_string_ptr(propq, ptr::addr_of_mut!(properties)) == 0
        {
            return 0;
        }

        // If we got a new MAC name, we make a new `EVP_MAC_CTX`.
        if !macname.is_null() {
            let mac = EVP_MAC_fetch(libctx, macname, properties);

            EVP_MAC_CTX_free(*macctx);
            *macctx = if mac.is_null() {
                ptr::null_mut()
            } else {
                EVP_MAC_CTX_new(mac)
            };
            // The context holds on to the MAC.
            EVP_MAC_free(mac);
            if (*macctx).is_null() {
                return 0;
            }
        }

        // If there is no MAC yet (and therefore no context), all other parameters are ignored.
        if (*macctx).is_null() {
            return 1;
        }

        if ciphername.is_null()
            && !pcipher.is_null()
            && OSSL_PARAM_get_utf8_string_ptr(pcipher, ptr::addr_of_mut!(ciphername)) == 0
        {
            return 0;
        }
        if mdname.is_null()
            && !pdigest.is_null()
            && OSSL_PARAM_get_utf8_string_ptr(pdigest, ptr::addr_of_mut!(mdname)) == 0
        {
            return 0;
        }
        if !pengine.is_null()
            && OSSL_PARAM_get_utf8_string_ptr(pengine, ptr::addr_of_mut!(engine)) == 0
        {
            return 0;
        }

        if ossl_prov_set_macctx(*macctx, ciphername, mdname, engine, properties) != 0 {
            return 1;
        }

        // The parameters were refused, so the context is released rather than left half-set.
        EVP_MAC_CTX_free(*macctx);
        *macctx = ptr::null_mut();
        0
    }
}

// ---------------------------------------------------------------------------------------------
// `providers/common/provider_util.c` -- the memory-copy helper (docs/DECISIONS.md D346)
// ---------------------------------------------------------------------------------------------
//
// It is here for the reason the MAC-context half above is: the file is already this module. Its
// two callers in this crate are the KDF rows `sskdf.c` and `x942kdf.c` transcribe, each of whose
// `dupctx` copies its own secret and info buffers with it.

/// `__FILE__` for `provider_util.c`, as the default provider's object carries it. The file is a
/// **source-tree** unit, so `strings` on `providers/common/libdefault-lib-provider_util.o`
/// answers the `../../src/openssl-3.6.4/`-prefixed spelling — the opposite of the `.c.in`-generated
/// provider units' bare build-relative path, and measured rather than assumed (D235's class).
const FILE_PROVIDER_UTIL: *const c_char =
    c"../../src/openssl-3.6.4/providers/common/provider_util.c".as_ptr();

/// `int ossl_prov_memdup(const void *src, size_t src_len, unsigned char **dest,
/// size_t *dest_len)` — `provider_util.c:353-365`.
///
/// **A NULL `src` is a success that clears the destination**, not a failure: `*dest` is set NULL
/// and `*dest_len` zero. That is the arm `dupctx` relies on for a context that never had a secret.
/// A non-NULL `src` is `OPENSSL_memdup`'s copy, and a failed allocation is the only refusal.
///
/// # Safety
/// `src` is NULL or readable for `src_len` bytes; `dest`/`dest_len` are writable and `*dest` is
/// either NULL or a block this allocator owns.
pub(crate) unsafe fn ossl_prov_memdup(
    src: *const c_void,
    src_len: usize,
    dest: *mut *mut u8,
    dest_len: *mut usize,
) -> c_int {
    // SAFETY: the out-parameters are this frame's caller's own, and `src` is readable per the
    // contract; `CRYPTO_memdup` is the authority's `OPENSSL_memdup`.
    unsafe {
        if !src.is_null() {
            let copy = crate::runtime::mem::CRYPTO_memdup(src, src_len, FILE_PROVIDER_UTIL, 0);
            if copy.is_null() {
                return 0;
            }
            *dest = copy.cast::<u8>();
            *dest_len = src_len;
        } else {
            *dest = ptr::null_mut();
            *dest_len = 0;
        }
    }
    1
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

    #[test]
    fn a_fresh_digest_carries_nothing() {
        // SAFETY: the struct is this frame's own, and a NULL library context is the global one.
        unsafe {
            let mut pd = prov_digest::ProvDigest {
                md: ptr::null(),
                alloc_md: ptr::null_mut(),
                engine: ptr::null_mut(),
            };
            assert!(prov_digest::ossl_prov_digest_md(ptr::addr_of!(pd)).is_null());
            assert!(prov_digest::ossl_prov_digest_engine(ptr::addr_of!(pd)).is_null());
            // A NULL `digest` descriptor is success with nothing resolved, which is how a caller
            // says "no digest yet" -- and `set_propq`/`set_engine` must not have refused it.
            assert_eq!(
                prov_digest::ossl_prov_digest_load(
                    ptr::addr_of_mut!(pd),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                1,
                "a NULL digest descriptor is a no-op, not a refusal"
            );
            assert!(pd.md.is_null());
            prov_digest::ossl_prov_digest_reset(ptr::addr_of_mut!(pd));
        }
    }

    #[test]
    fn a_named_digest_resolves_and_its_reference_is_owned() {
        let mut name = *b"SHA256\0";
        // SAFETY: the name is a local NUL-terminated buffer and the struct is this frame's own.
        unsafe {
            let mut pd = prov_digest::ProvDigest {
                md: ptr::null(),
                alloc_md: ptr::null_mut(),
                engine: ptr::null_mut(),
            };
            let desc = OsslParam {
                key: OSSL_ALG_PARAM_DIGEST.cast(),
                data_type: OSSL_PARAM_UTF8_STRING,
                data: name.as_mut_ptr().cast(),
                data_size: 6,
                return_size: 0,
            };
            assert_eq!(
                prov_digest::ossl_prov_digest_load(
                    ptr::addr_of_mut!(pd),
                    ptr::addr_of!(desc),
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                1
            );
            assert!(
                !pd.md.is_null(),
                "SHA256 resolves through the default provider"
            );
            // A fetched method is the one this struct owns, so both fields point at it.
            assert_eq!(pd.md, pd.alloc_md.cast_const());
            prov_digest::ossl_prov_digest_reset(ptr::addr_of_mut!(pd));
            assert!(pd.md.is_null() && pd.alloc_md.is_null());
        }
    }

    #[test]
    fn a_digest_descriptor_of_the_wrong_type_is_refused() {
        let mut name = *b"SHA256\0";
        // SAFETY: local descriptors and a local struct.
        unsafe {
            let mut pd = prov_digest::ProvDigest {
                md: ptr::null(),
                alloc_md: ptr::null_mut(),
                engine: ptr::null_mut(),
            };
            // An octet-string descriptor where a UTF8 string belongs is a bare refusal, and it is a
            // *different* arm from a name that fails to resolve.
            let desc = OsslParam {
                key: OSSL_ALG_PARAM_DIGEST.cast(),
                data_type: crate::params::OSSL_PARAM_OCTET_STRING,
                data: name.as_mut_ptr().cast(),
                data_size: 6,
                return_size: 0,
            };
            assert_eq!(
                prov_digest::ossl_prov_digest_load(
                    ptr::addr_of_mut!(pd),
                    ptr::addr_of!(desc),
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                0
            );
            assert!(pd.md.is_null(), "the refusal resolves nothing");
        }
    }

    #[test]
    fn a_copy_ups_the_reference_it_shares() {
        let mut name = *b"SHA256\0";
        // SAFETY: local structs, and the descriptors are this frame's own.
        unsafe {
            let mut src = prov_digest::ProvDigest {
                md: ptr::null(),
                alloc_md: ptr::null_mut(),
                engine: ptr::null_mut(),
            };
            let desc = OsslParam {
                key: OSSL_ALG_PARAM_DIGEST.cast(),
                data_type: OSSL_PARAM_UTF8_STRING,
                data: name.as_mut_ptr().cast(),
                data_size: 6,
                return_size: 0,
            };
            assert_eq!(
                prov_digest::ossl_prov_digest_load(
                    ptr::addr_of_mut!(src),
                    ptr::addr_of!(desc),
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                1
            );
            let mut dst = prov_digest::ProvDigest {
                md: ptr::null(),
                alloc_md: ptr::null_mut(),
                engine: ptr::null_mut(),
            };
            assert_eq!(
                prov_digest::ossl_prov_digest_copy(ptr::addr_of_mut!(dst), ptr::addr_of!(src)),
                1
            );
            assert_eq!(dst.md, src.md);
            assert_eq!(dst.alloc_md, src.alloc_md);
            // Both now hold a reference to one method, so both must release it.
            prov_digest::ossl_prov_digest_reset(ptr::addr_of_mut!(dst));
            prov_digest::ossl_prov_digest_reset(ptr::addr_of_mut!(src));
        }
    }
}
