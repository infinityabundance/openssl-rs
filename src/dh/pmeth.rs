//! `crypto/dh/dh_pmeth.c` — the `DH` and `DHX` `EVP_PKEY_METHOD` objects and their callbacks.
//!
//! Transcribed whole. The unit defines **two** objects over one set of callbacks — `dh_pkey_meth`
//! (`EVP_PKEY_DH`, `:459`) and `dhx_pkey_meth` (`EVP_PKEY_DHX`, `:498`) — whose only difference is
//! the `pkey_id` both carry, which is why `pkey_dh_keygen` assigns with `ctx->pmeth->pkey_id` rather
//! than a constant: the same body must produce a DH key on one context and a DHX key on the other.
//! That read is the reason `EvpPkeyCtx` grew a `pmeth` member in this slice.
//!
//! ## Two callbacks are shared with DSA, and that is the authority's shape
//!
//! `DH_generate_parameters_ex` is the *legacy* generator; `ffc_params_generate` is this unit's own
//! static and dispatches to `ossl_ffc_params_FIPS186_2_generate` or `_FIPS186_4_generate` by
//! `paramgen_type`. The `#ifndef FIPS_MODULE` around the 186-2 arm is compiled **in** on this
//! profile, so the two-way dispatch is present rather than reduced to the FIPS arm.
//!
//! ## The KDF is a `ctx->data` field, not a second context
//!
//! `kdf_type`, `kdf_oid`, `kdf_md`, `kdf_ukm`, `kdf_ukmlen` and `kdf_outlen` all live in
//! `DH_PKEY_CTX`, and `pkey_dh_derive` branches on `kdf_type` between the raw shared secret and the
//! X9.42 KDF. `kdf_ukm` is a *borrowed* buffer the caller hands in through
//! `EVP_PKEY_CTRL_DH_KDF_UKM` and this context frees on cleanup or on replacement — so a control
//! that stores it twice frees the first.
//!
//! ## What this module does not do
//!
//! `ossl_dh_pkey_method` and `ossl_dhx_pkey_method` are published as statics and named by
//! `src/evp/pkey_ctx.rs`'s `PMETH_STANDARD_METHODS`, so `EVP_PKEY_meth_find` answers them. No caller
//! builds an `EVP_PKEY_CTX` from either yet: that is `int_ctx_new`'s `pmeth` arm, still recorded as
//! absent.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::asn1::prim::ASN1_OBJECT_free;
use crate::bn::ctx::{BN_GENCB_free, BN_GENCB_new};
use crate::dh::ctrl::{
    EVP_PKEY_CTX_set_dh_pad, EVP_PKEY_CTX_set_dh_paramgen_generator,
    EVP_PKEY_CTX_set_dh_paramgen_prime_len, EVP_PKEY_CTX_set_dh_paramgen_subprime_len,
    EVP_PKEY_CTX_set_dh_paramgen_type,
};
use crate::dh::gen::DH_generate_parameters_ex;
use crate::dh::group_params::DH_new_by_nid;
use crate::dh::kdf::DH_KDF_X9_42;
use crate::dh::key::{DH_compute_key, DH_compute_key_padded, DH_generate_key};
use crate::dh::object::{DH_free, DH_new, DH_size};
use crate::dh::Dh;
use crate::evp::digest::{EVP_MD_get0_name, EvpMd};
use crate::evp::pkey::{EVP_PKEY_assign, EVP_PKEY_copy_parameters, EVP_PKEY_get0_DH, EvpPkey};
use crate::evp::pkey_ctx::{
    EvpPkeyCtx, EvpPkeyMethod, DH_PARAMGEN_TYPE_FIPS_186_2, DH_PARAMGEN_TYPE_FIPS_186_4,
    DH_PARAMGEN_TYPE_GENERATOR, EVP_PKEY_CTRL_DH_KDF_MD, EVP_PKEY_CTRL_DH_KDF_OID,
    EVP_PKEY_CTRL_DH_KDF_OUTLEN, EVP_PKEY_CTRL_DH_KDF_TYPE, EVP_PKEY_CTRL_DH_KDF_UKM,
    EVP_PKEY_CTRL_DH_NID, EVP_PKEY_CTRL_DH_PAD, EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR,
    EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN,
    EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, EVP_PKEY_CTRL_DH_RFC5114, EVP_PKEY_CTRL_GET_DH_KDF_MD,
    EVP_PKEY_CTRL_GET_DH_KDF_OID, EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, EVP_PKEY_CTRL_GET_DH_KDF_UKM,
    EVP_PKEY_CTRL_PEER_KEY, EVP_PKEY_DH, EVP_PKEY_DHX, EVP_PKEY_DH_KDF_NONE, EVP_PKEY_DH_KDF_X9_42,
};
use crate::evp::pmeth_gn::evp_pkey_set_cb_translate;
use crate::ffc::params::ossl_ffc_set_digest;
use crate::ffc::params_generate::{
    ossl_ffc_params_FIPS186_2_generate, ossl_ffc_params_FIPS186_4_generate,
};
use crate::ffc::FFC_PARAM_TYPE_DH;
use crate::rand::sys::atoi;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_zalloc,
};
use crate::runtime::obj::{Asn1Object, NID_undef, OBJ_dup, OBJ_sn2nid};

/// `crypto/dh/dh_pmeth.c` — the translation unit every allocation and error below is attributed to.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/dh/dh_pmeth.c".as_ptr();

/// `pkey_dh_init`'s `OPENSSL_zalloc(sizeof(*dctx))` (`:58`).
const LINE_ZALLOC_DCTX: c_int = 58;
/// `pkey_dh_cleanup`'s `OPENSSL_free(dctx->kdf_ukm)` (`:77`).
const LINE_FREE_KDF_UKM: c_int = 77;
/// `pkey_dh_cleanup`'s `OPENSSL_free(dctx)` (`:79`).
const LINE_FREE_DCTX: c_int = 79;
/// `pkey_dh_copy`'s `OPENSSL_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen)` (`:105`).
const LINE_MEMDUP_KDF_UKM: c_int = 105;
/// `pkey_dh_ctrl`'s `OPENSSL_free(dctx->kdf_ukm)` on replacement (`:194`).
const LINE_FREE_KDF_UKM_CTRL: c_int = 194;
/// `pkey_dh_derive`'s `OPENSSL_malloc(Zlen)` (`:443`).
const LINE_MALLOC_Z: c_int = 443;
/// `pkey_dh_derive`'s `OPENSSL_clear_free(Z, Zlen)` (`:453`).
const LINE_CLEAR_FREE_Z: c_int = 453;

/// `DH_PKEY_CTX` — `crypto/dh/dh_pmeth.c:29-52`.
///
/// Fifteen members. The authority's `char kdf_type` is a plain `char`, so [`c_char`]; the three
/// `size_t` fields and `gentmp`'s position are the layout's own, and `ctx->keygen_info` is the
/// address of `gentmp`.
#[repr(C)]
struct DhPkeyCtx {
    /// `int prime_len`.
    prime_len: c_int,
    /// `int generator`.
    generator: c_int,
    /// `int paramgen_type`.
    paramgen_type: c_int,
    /// `int subprime_len`.
    subprime_len: c_int,
    /// `int pad`.
    pad: c_int,
    /// `const EVP_MD *md` — the digest used for parameter generation.
    md: *const EvpMd,
    /// `int param_nid`.
    param_nid: c_int,
    /// `int gentmp[2]` — the keygen callback's scratch, published as `ctx->keygen_info`.
    gentmp: [c_int; 2],
    /// `char kdf_type` — `EVP_PKEY_DH_KDF_NONE` or `_X9_42`.
    kdf_type: c_char,
    /// `ASN1_OBJECT *kdf_oid` — owned.
    kdf_oid: *mut Asn1Object,
    /// `const EVP_MD *kdf_md` — borrowed.
    kdf_md: *const EvpMd,
    /// `unsigned char *kdf_ukm` — borrowed, but freed by this context on replacement and cleanup.
    kdf_ukm: *mut u8,
    /// `size_t kdf_ukmlen`.
    kdf_ukmlen: usize,
    /// `size_t kdf_outlen`.
    kdf_outlen: usize,
}

/// `strcmp(s, lit) == 0` in the crate's `CStr` idiom.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn cstr_is(s: *const c_char, lit: &[u8]) -> bool {
    // SAFETY: `s` is NUL-terminated per the contract.
    unsafe { CStr::from_ptr(s) }.to_bytes() == lit
}

/// `static int pkey_dh_init(EVP_PKEY_CTX *ctx)` — `:54`.
///
/// # Safety
/// `ctx` must be live.
unsafe extern "C" fn pkey_dh_init(ctx: *mut EvpPkeyCtx) -> c_int {
    /* `CRYPTO_zalloc` is a safe entry point of this crate. */
    let dctx = CRYPTO_zalloc(core::mem::size_of::<DhPkeyCtx>(), FILE, LINE_ZALLOC_DCTX)
        .cast::<DhPkeyCtx>();
    if dctx.is_null() {
        return 0;
    }
    // SAFETY: `dctx` is this call's own allocation and `ctx` is live per the contract.
    unsafe {
        (*dctx).prime_len = 2048;
        (*dctx).subprime_len = -1;
        (*dctx).generator = 2;
        (*dctx).kdf_type = EVP_PKEY_DH_KDF_NONE as c_char;

        (*ctx).data = dctx.cast::<c_void>();
        (*ctx).keygen_info = ptr::addr_of_mut!((*dctx).gentmp).cast::<c_int>();
        (*ctx).keygen_info_count = 2;
    }
    1
}

/// `static void pkey_dh_cleanup(EVP_PKEY_CTX *ctx)` — `:72`.
///
/// # Safety
/// `ctx` must be live.
unsafe extern "C" fn pkey_dh_cleanup(ctx: *mut EvpPkeyCtx) {
    // SAFETY: `ctx` is live per the contract.
    let dctx = unsafe { (*ctx).data }.cast::<DhPkeyCtx>();

    // SAFETY: `dctx` is NULL or this method's own live context.
    if !dctx.is_null() {
        // SAFETY: the fields are NULL or this context's own allocations, and `CRYPTO_free` accepts
        // NULL.
        unsafe {
            CRYPTO_free((*dctx).kdf_ukm.cast::<c_void>(), FILE, LINE_FREE_KDF_UKM);
            ASN1_OBJECT_free((*dctx).kdf_oid);
            CRYPTO_free(dctx.cast::<c_void>(), FILE, LINE_FREE_DCTX);
        }
    }
}

/// `static int pkey_dh_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)` — `:83`.
///
/// # Safety
/// `dst` and `src` must be live.
unsafe extern "C" fn pkey_dh_copy(dst: *mut EvpPkeyCtx, src: *const EvpPkeyCtx) -> c_int {
    // SAFETY: `dst` is live per the contract.
    if unsafe { pkey_dh_init(dst) } == 0 {
        return 0;
    }
    // SAFETY: both contexts are live and `init` installed `dst`'s own context.
    let (sctx, dctx) = unsafe {
        (
            (*src).data.cast::<DhPkeyCtx>(),
            (*dst).data.cast::<DhPkeyCtx>(),
        )
    };

    // SAFETY: `dctx` is live and writable.
    unsafe {
        (*dctx).prime_len = (*sctx).prime_len;
        (*dctx).subprime_len = (*sctx).subprime_len;
        (*dctx).generator = (*sctx).generator;
        (*dctx).paramgen_type = (*sctx).paramgen_type;
        (*dctx).pad = (*sctx).pad;
        (*dctx).md = (*sctx).md;
        (*dctx).param_nid = (*sctx).param_nid;

        (*dctx).kdf_type = (*sctx).kdf_type;
    }
    // SAFETY: `OBJ_dup` allocates; the source object is this context's own or NULL.
    let dup = unsafe { OBJ_dup((*sctx).kdf_oid) };
    // SAFETY: `dctx` is live.
    unsafe { (*dctx).kdf_oid = dup };
    if dup.is_null() {
        return 0;
    }
    // SAFETY: both contexts are live.
    unsafe { (*dctx).kdf_md = (*sctx).kdf_md };
    // SAFETY: `sctx` is live.
    if !unsafe { (*sctx).kdf_ukm }.is_null() {
        // SAFETY: the source buffer is readable for its recorded length.
        let ukm = unsafe {
            CRYPTO_memdup(
                (*sctx).kdf_ukm.cast::<c_void>(),
                (*sctx).kdf_ukmlen,
                FILE,
                LINE_MEMDUP_KDF_UKM,
            )
        };
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).kdf_ukm = ukm.cast::<u8>() };
        if ukm.is_null() {
            return 0;
        }
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).kdf_ukmlen = (*sctx).kdf_ukmlen };
    }
    // SAFETY: both contexts are live.
    unsafe { (*dctx).kdf_outlen = (*sctx).kdf_outlen };
    1
}

/// `static int pkey_dh_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)` — `:114`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethCtrlFn`].
unsafe extern "C" fn pkey_dh_ctrl(
    ctx: *mut EvpPkeyCtx,
    type_: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<DhPkeyCtx>();

    match type_ {
        EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN => {
            if p1 < 256 {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).prime_len = p1 };
            1
        }
        EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN => {
            // SAFETY: `dctx` is live.
            if unsafe { (*dctx).paramgen_type } == DH_PARAMGEN_TYPE_GENERATOR {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).subprime_len = p1 };
            1
        }
        EVP_PKEY_CTRL_DH_PAD => {
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).pad = p1 };
            1
        }
        EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR => {
            // SAFETY: `dctx` is live.
            if unsafe { (*dctx).paramgen_type } != DH_PARAMGEN_TYPE_GENERATOR {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).generator = p1 };
            1
        }
        EVP_PKEY_CTRL_DH_PARAMGEN_TYPE => {
            /* `OPENSSL_NO_DSA` is undefined on this profile, so the authority's three-way range test
             * is the arm that compiles. */
            if !(0..=2).contains(&p1) {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).paramgen_type = p1 };
            1
        }
        EVP_PKEY_CTRL_DH_RFC5114 => {
            // SAFETY: `dctx` is live.
            if !(1..=3).contains(&p1) || unsafe { (*dctx).param_nid } != NID_undef {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).param_nid = p1 };
            1
        }
        EVP_PKEY_CTRL_DH_NID => {
            // SAFETY: `dctx` is live.
            if p1 <= 0 || unsafe { (*dctx).param_nid } != NID_undef {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).param_nid = p1 };
            1
        }
        EVP_PKEY_CTRL_PEER_KEY => 1,
        EVP_PKEY_CTRL_DH_KDF_TYPE => {
            if p1 == -2 {
                // SAFETY: `dctx` is live.
                return unsafe { (*dctx).kdf_type } as c_int;
            }
            if p1 != EVP_PKEY_DH_KDF_NONE && p1 != EVP_PKEY_DH_KDF_X9_42 {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).kdf_type = p1 as c_char };
            1
        }
        EVP_PKEY_CTRL_DH_KDF_MD => {
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).kdf_md = p2.cast::<EvpMd>() };
            1
        }
        EVP_PKEY_CTRL_GET_DH_KDF_MD => {
            // SAFETY: `p2` is writable and `dctx` is live.
            unsafe { *p2.cast::<*const EvpMd>() = (*dctx).kdf_md };
            1
        }
        EVP_PKEY_CTRL_DH_KDF_OUTLEN => {
            if p1 <= 0 {
                return -2;
            }
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).kdf_outlen = p1 as usize };
            1
        }
        EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN => {
            // SAFETY: `p2` is writable and `dctx` is live.
            unsafe { *p2.cast::<c_int>() = (*dctx).kdf_outlen as c_int };
            1
        }
        EVP_PKEY_CTRL_DH_KDF_UKM => {
            // SAFETY: `dctx`'s field is this context's own or NULL, and `CRYPTO_free` accepts NULL.
            unsafe {
                CRYPTO_free(
                    (*dctx).kdf_ukm.cast::<c_void>(),
                    FILE,
                    LINE_FREE_KDF_UKM_CTRL,
                );
                (*dctx).kdf_ukm = p2.cast::<u8>();
                if !p2.is_null() {
                    (*dctx).kdf_ukmlen = p1 as usize;
                } else {
                    (*dctx).kdf_ukmlen = 0;
                }
            }
            1
        }
        EVP_PKEY_CTRL_GET_DH_KDF_UKM => {
            // SAFETY: `p2` is writable and `dctx` is live.
            unsafe { *p2.cast::<*mut u8>() = (*dctx).kdf_ukm };
            // SAFETY: `dctx` is live.
            unsafe { (*dctx).kdf_ukmlen as c_int }
        }
        EVP_PKEY_CTRL_DH_KDF_OID => {
            // SAFETY: `dctx`'s field is this context's own or NULL.
            unsafe {
                ASN1_OBJECT_free((*dctx).kdf_oid);
                (*dctx).kdf_oid = p2.cast::<Asn1Object>();
            }
            1
        }
        EVP_PKEY_CTRL_GET_DH_KDF_OID => {
            // SAFETY: `p2` is writable and `dctx` is live.
            unsafe { *p2.cast::<*mut Asn1Object>() = (*dctx).kdf_oid };
            1
        }
        _ => -2,
    }
}

/// `static int pkey_dh_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)` — `:220`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethCtrlStrFn`].
unsafe extern "C" fn pkey_dh_ctrl_str(
    ctx: *mut EvpPkeyCtx,
    type_: *const c_char,
    value: *const c_char,
) -> c_int {
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"dh_paramgen_prime_len") } {
        // SAFETY: `value` is NUL-terminated and `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, atoi(value)) };
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"dh_rfc5114") } {
        // SAFETY: `value` is NUL-terminated and `ctx` is live.
        let id = atoi(value);
        if !(0..=3).contains(&id) {
            return -2;
        }
        // SAFETY: `ctx` is live and `data` is this method's own context.
        unsafe { (*(*ctx).data.cast::<DhPkeyCtx>()).param_nid = id };
        return 1;
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"dh_param") } {
        // SAFETY: `value` is NUL-terminated per the contract.
        let nid = unsafe { OBJ_sn2nid(value) };
        if nid == NID_undef {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DH_PMETH_243) };
            return -2;
        }
        // SAFETY: `ctx` is live and `data` is this method's own context.
        unsafe { (*(*ctx).data.cast::<DhPkeyCtx>()).param_nid = nid };
        return 1;
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"dh_paramgen_generator") } {
        // SAFETY: `value` is NUL-terminated and `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, atoi(value)) };
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"dh_paramgen_subprime_len") } {
        // SAFETY: `value` is NUL-terminated and `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, atoi(value)) };
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"dh_paramgen_type") } {
        // SAFETY: `value` is NUL-terminated and `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_dh_paramgen_type(ctx, atoi(value)) };
    }
    // SAFETY: `type_` is NUL-terminated per the contract.
    if unsafe { cstr_is(type_, b"dh_pad") } {
        // SAFETY: `value` is NUL-terminated and `ctx` is live.
        return unsafe { EVP_PKEY_CTX_set_dh_pad(ctx, atoi(value)) };
    }
    -2
}

/// `static DH *ffc_params_generate(OSSL_LIB_CTX *libctx, DH_PKEY_CTX *dctx, BN_GENCB *pcb)` — `:272`.
///
/// # Safety
/// `dctx` must be live; `pcb` NULL or live.
unsafe fn ffc_params_generate(
    libctx: *mut c_void,
    dctx: *mut DhPkeyCtx,
    pcb: *mut crate::bn::ctx::BnGencb,
) -> *mut Dh {
    // SAFETY: `dctx` is live per the contract.
    if unsafe { (*dctx).paramgen_type } > DH_PARAMGEN_TYPE_FIPS_186_4 {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let ret = unsafe { DH_new() };
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `dctx` is live.
    let mut subprime_len = unsafe { (*dctx).subprime_len };
    if subprime_len == -1 {
        // SAFETY: `dctx` is live.
        subprime_len = if unsafe { (*dctx).prime_len } >= 2048 {
            256
        } else {
            160
        };
    }

    // SAFETY: `dctx` is live.
    if !unsafe { (*dctx).md }.is_null() {
        // SAFETY: `ret` is live and the digest is a live one on this arm.
        unsafe {
            ossl_ffc_set_digest(
                ptr::addr_of_mut!((*ret).params),
                EVP_MD_get0_name((*dctx).md),
                ptr::null(),
            )
        };
    }

    let mut rv: c_int = 0;
    let mut res: c_int = 0;
    // SAFETY: `dctx` is live.
    let (paramgen_type, prime_len) = unsafe { ((*dctx).paramgen_type, (*dctx).prime_len) };
    if paramgen_type == DH_PARAMGEN_TYPE_FIPS_186_2 {
        /* `#ifndef FIPS_MODULE` is compiled in on this profile. */
        // SAFETY: `ret` is live and its parameters are this call's to write.
        rv = unsafe {
            ossl_ffc_params_FIPS186_2_generate(
                libctx,
                ptr::addr_of_mut!((*ret).params),
                FFC_PARAM_TYPE_DH,
                prime_len as usize,
                subprime_len as usize,
                &mut res,
                pcb,
            )
        };
    } else if paramgen_type >= DH_PARAMGEN_TYPE_FIPS_186_2 {
        // SAFETY: as above.
        rv = unsafe {
            ossl_ffc_params_FIPS186_4_generate(
                libctx,
                ptr::addr_of_mut!((*ret).params),
                FFC_PARAM_TYPE_DH,
                prime_len as usize,
                subprime_len as usize,
                &mut res,
                pcb,
            )
        };
    }
    if rv <= 0 {
        // SAFETY: `ret` is this call's own object on this arm.
        unsafe { DH_free(ret) };
        return ptr::null_mut();
    }
    ret
}

/// `static int pkey_dh_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)` — `:318`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethParamgenFn`].
unsafe extern "C" fn pkey_dh_paramgen(ctx: *mut EvpPkeyCtx, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<DhPkeyCtx>();

    /* A named group short-circuits both generators: `RFC_5114` (nids 1..3) and the FFDHE/MODP
     * groups are built directly by `DH_new_by_nid`. */
    // SAFETY: `dctx` is live.
    if unsafe { (*dctx).param_nid } != NID_undef {
        // SAFETY: `dctx` is live.
        let type_ = if unsafe { (*dctx).param_nid } <= 3 {
            EVP_PKEY_DHX
        } else {
            EVP_PKEY_DH
        };
        // SAFETY: `dctx` is live.
        let dh = unsafe { DH_new_by_nid((*dctx).param_nid) };
        if dh.is_null() {
            return 0;
        }
        // SAFETY: `pkey` and `dh` are live.
        unsafe { EVP_PKEY_assign(pkey, type_, dh.cast::<c_void>()) };
        return 1;
    }

    // SAFETY: `ctx` is live.
    let pcb = if unsafe { (*ctx).pkey_gencb }.is_some() {
        // SAFETY: no preconditions.
        let cb = unsafe { BN_GENCB_new() };
        if cb.is_null() {
            return 0;
        }
        // SAFETY: `cb` is live and `ctx` is the caller's.
        unsafe { evp_pkey_set_cb_translate(cb, ctx) };
        cb
    } else {
        ptr::null_mut()
    };

    /* `#ifdef FIPS_MODULE` is not compiled, so `paramgen_type` is not overwritten here. */
    // SAFETY: `dctx` is live.
    if unsafe { (*dctx).paramgen_type } >= DH_PARAMGEN_TYPE_FIPS_186_2 {
        // SAFETY: `dctx` is live and `pcb` is NULL or live.
        let dh = unsafe { ffc_params_generate(ptr::null_mut(), dctx, pcb) };
        // SAFETY: `pcb` is NULL or this call's own object.
        unsafe { BN_GENCB_free(pcb) };
        if dh.is_null() {
            return 0;
        }
        // SAFETY: `pkey` and `dh` are live.
        unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DHX, dh.cast::<c_void>()) };
        return 1;
    }
    // SAFETY: no preconditions.
    let dh = unsafe { DH_new() };
    if dh.is_null() {
        // SAFETY: `pcb` is NULL or this call's own object.
        unsafe { BN_GENCB_free(pcb) };
        return 0;
    }
    // SAFETY: `dh` is live and `pcb` is NULL or live.
    let ret = unsafe { DH_generate_parameters_ex(dh, (*dctx).prime_len, (*dctx).generator, pcb) };
    // SAFETY: `pcb` is NULL or this call's own object.
    unsafe { BN_GENCB_free(pcb) };
    if ret != 0 {
        // SAFETY: `pkey` and `dh` are live.
        unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DH, dh.cast::<c_void>()) };
    } else {
        // SAFETY: `dh` is this call's own object on this arm.
        unsafe { DH_free(dh) };
    }
    ret
}

/// `static int pkey_dh_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)` — `:372`.
///
/// The assignment's type is **`ctx->pmeth->pkey_id`**, so the same body answers DH or DHX according
/// to which object the context was built from.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethParamgenFn`].
unsafe extern "C" fn pkey_dh_keygen(ctx: *mut EvpPkeyCtx, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<DhPkeyCtx>();

    // SAFETY: `ctx` and `dctx` are live.
    if unsafe { (*ctx).pkey }.is_null() && unsafe { (*dctx).param_nid } == NID_undef {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_PMETH_378) };
        return 0;
    }
    // SAFETY: `dctx` is live.
    let dh = if unsafe { (*dctx).param_nid } != NID_undef {
        // SAFETY: `dctx` is live.
        unsafe { DH_new_by_nid((*dctx).param_nid) }
    } else {
        // SAFETY: no preconditions.
        unsafe { DH_new() }
    };
    if dh.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live and `pmeth` is the method this context was built from.
    // SAFETY: `pkey` and `dh` are live.
    unsafe { EVP_PKEY_assign(pkey, (*(*ctx).pmeth).pkey_id, dh.cast::<c_void>()) };
    /* Note: if the copy fails, `pkey` is freed by the caller's own cleanup. */
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).pkey }.is_null() {
        // SAFETY: both keys are live per the contract.
        if unsafe { EVP_PKEY_copy_parameters(pkey, (*ctx).pkey) } == 0 {
            return 0;
        }
    }
    // SAFETY: `pkey` is live and holds the key just assigned.
    unsafe { DH_generate_key(EVP_PKEY_get0_DH(pkey) as *mut Dh) }
}

/// `static int pkey_dh_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)` — `:394`.
///
/// # Safety
/// As [`crate::evp::pkey_ctx::PkeyMethDeriveFn`].
unsafe extern "C" fn pkey_dh_derive(
    ctx: *mut EvpPkeyCtx,
    key: *mut u8,
    keylen: *mut usize,
) -> c_int {
    // SAFETY: `ctx` is live and `data` is this method's own context.
    let dctx = unsafe { (*ctx).data }.cast::<DhPkeyCtx>();

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).pkey }.is_null() || unsafe { (*ctx).peerkey }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_PMETH_404) };
        return 0;
    }
    // SAFETY: both keys are live.
    let dh = unsafe { EVP_PKEY_get0_DH((*ctx).pkey) } as *mut Dh;
    // SAFETY: the same.
    let dhpub = unsafe { EVP_PKEY_get0_DH((*ctx).peerkey) };
    if dhpub.is_null() || dh.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_PMETH_410) };
        return 0;
    }
    // SAFETY: `dhpub` is a live key.
    let dhpubbn = unsafe { (*dhpub).pub_key };

    // SAFETY: `dctx` is live.
    let kdf_type = unsafe { (*dctx).kdf_type } as c_int;
    if kdf_type == EVP_PKEY_DH_KDF_NONE {
        if key.is_null() {
            // SAFETY: `keylen` is writable per the contract and `dh` is live.
            unsafe { *keylen = DH_size(dh) as usize };
            return 1;
        }
        // SAFETY: `dctx` is live.
        let ret = if unsafe { (*dctx).pad } != 0 {
            // SAFETY: the caller's buffer and the two live keys.
            unsafe { DH_compute_key_padded(key, dhpubbn, dh) }
        } else {
            // SAFETY: the same.
            unsafe { DH_compute_key(key, dhpubbn, dh) }
        };
        if ret <= 0 {
            return ret;
        }
        // SAFETY: `keylen` is writable per the contract.
        unsafe { *keylen = ret as usize };
        return 1;
    } else if kdf_type == EVP_PKEY_DH_KDF_X9_42 {
        // SAFETY: `dctx` is live.
        let (kdf_outlen, kdf_oid) = unsafe { ((*dctx).kdf_outlen, (*dctx).kdf_oid) };
        if kdf_outlen == 0 || kdf_oid.is_null() {
            return 0;
        }
        if key.is_null() {
            // SAFETY: `keylen` is writable per the contract.
            unsafe { *keylen = kdf_outlen };
            return 1;
        }
        // SAFETY: `keylen` is readable per the contract.
        if unsafe { *keylen } != kdf_outlen {
            return 0;
        }
        let mut ret: c_int = 0;
        // SAFETY: `dh` is live.
        let zlen = unsafe { DH_size(dh) };
        if zlen <= 0 {
            return 0;
        }
        /* `CRYPTO_malloc` is a safe entry point of this crate. */
        let z = CRYPTO_malloc(zlen as usize, FILE, LINE_MALLOC_Z).cast::<u8>();
        if z.is_null() {
            return 0;
        }
        // SAFETY: `z` is this call's own buffer and `dhpubbn`/`dh` are live.
        if unsafe { DH_compute_key_padded(z, dhpubbn, dh) } <= 0 {
            // SAFETY: `z` is this call's own buffer.
            unsafe {
                CRYPTO_clear_free(z.cast::<c_void>(), zlen as usize, FILE, LINE_CLEAR_FREE_Z)
            };
            return ret;
        }
        // SAFETY: the caller's buffer, this call's buffer, the live context fields and the OID.
        let ok = unsafe {
            DH_KDF_X9_42(
                key,
                *keylen,
                z,
                zlen as usize,
                (*dctx).kdf_oid,
                (*dctx).kdf_ukm,
                (*dctx).kdf_ukmlen,
                (*dctx).kdf_md,
            )
        };
        if ok != 0 {
            // SAFETY: `keylen` is writable per the contract.
            unsafe { *keylen = kdf_outlen };
            ret = 1;
        }
        // SAFETY: `z` is this call's own buffer.
        unsafe { CRYPTO_clear_free(z.cast::<c_void>(), zlen as usize, FILE, LINE_CLEAR_FREE_Z) };
        return ret;
    }
    0
}

/// `static const EVP_PKEY_METHOD dh_pkey_meth` — `crypto/dh/dh_pmeth.c:459-491`.
///
/// Flags are **0**, and `derive` is set rather than any signature callback: DH is a key-agreement
/// method. `dhx_pkey_meth` (`:498`) is the same initializer with `EVP_PKEY_DHX` for `pkey_id`.
pub(crate) static DH_PKEY_METH: EvpPkeyMethod = EvpPkeyMethod {
    pkey_id: EVP_PKEY_DH,
    flags: 0,
    init: Some(pkey_dh_init),
    copy: Some(pkey_dh_copy),
    cleanup: Some(pkey_dh_cleanup),
    paramgen_init: None,
    paramgen: Some(pkey_dh_paramgen),
    keygen_init: None,
    keygen: Some(pkey_dh_keygen),
    sign_init: None,
    sign: None,
    verify_init: None,
    verify: None,
    verify_recover_init: None,
    verify_recover: None,
    signctx_init: None,
    signctx: None,
    verifyctx_init: None,
    verifyctx: None,
    encrypt_init: None,
    encrypt: None,
    decrypt_init: None,
    decrypt: None,
    derive_init: None,
    derive: Some(pkey_dh_derive),
    ctrl: Some(pkey_dh_ctrl),
    ctrl_str: Some(pkey_dh_ctrl_str),
    digestsign: None,
    digestverify: None,
    check: None,
    public_check: None,
    param_check: None,
    digest_custom: None,
};

/// `static const EVP_PKEY_METHOD dhx_pkey_meth` — `crypto/dh/dh_pmeth.c:498-530`.
pub(crate) static DHX_PKEY_METH: EvpPkeyMethod = EvpPkeyMethod {
    pkey_id: EVP_PKEY_DHX,
    flags: 0,
    init: Some(pkey_dh_init),
    copy: Some(pkey_dh_copy),
    cleanup: Some(pkey_dh_cleanup),
    paramgen_init: None,
    paramgen: Some(pkey_dh_paramgen),
    keygen_init: None,
    keygen: Some(pkey_dh_keygen),
    sign_init: None,
    sign: None,
    verify_init: None,
    verify: None,
    verify_recover_init: None,
    verify_recover: None,
    signctx_init: None,
    signctx: None,
    verifyctx_init: None,
    verifyctx: None,
    encrypt_init: None,
    encrypt: None,
    decrypt_init: None,
    decrypt: None,
    derive_init: None,
    derive: Some(pkey_dh_derive),
    ctrl: Some(pkey_dh_ctrl),
    ctrl_str: Some(pkey_dh_ctrl_str),
    digestsign: None,
    digestverify: None,
    check: None,
    public_check: None,
    param_check: None,
    digest_custom: None,
};

/// `const EVP_PKEY_METHOD *ossl_dh_pkey_method(void)` — `crypto/dh/dh_pmeth.c:493`.
///
/// # Safety
/// Nothing: the answer is a `static` of this module.
#[allow(dead_code)] // its only reader today is `PMETH_STANDARD_METHODS` in `src/evp/pkey_ctx.rs`
pub(crate) unsafe extern "C" fn ossl_dh_pkey_method() -> *const EvpPkeyMethod {
    ptr::addr_of!(DH_PKEY_METH)
}

/// `const EVP_PKEY_METHOD *ossl_dhx_pkey_method(void)` — `crypto/dh/dh_pmeth.c:532`.
///
/// # Safety
/// Nothing: the answer is a `static` of this module.
#[allow(dead_code)] // its only reader today is `PMETH_STANDARD_METHODS` in `src/evp/pkey_ctx.rs`
pub(crate) unsafe extern "C" fn ossl_dhx_pkey_method() -> *const EvpPkeyMethod {
    ptr::addr_of!(DHX_PKEY_METH)
}
