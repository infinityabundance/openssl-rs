//! Phase 8 — `providers/implementations/signature/dsa_sig.c`: the ten `DSA` `OSSL_OP_SIGNATURE`
//! rows.
//!
//! One thousand and ninety-nine source lines, twenty-four functions and ten dispatch tables. The
//! unit is the `DSA` face of the `DSA` key object `src/provider/dsa_kmgmt.rs` publishes (D391):
//! `PROV_DSA_CTX` holds a `DSA` borrow, an `EVP_MD`/`EVP_MD_CTX` pair for the message-digest path,
//! and the AlgorithmIdentifier the digest names. The plain `DSA` row is `dsa_sign_init`/
//! `dsa_verify_init` over `ossl_dsa_sign_int`/`DSA_verify`; the nine `DSA-<MD>` sigalgs are one
//! implementation with the digest name and the operation fixed at the call site.
//!
//! ## The two non-FIPS prerequisites, and why only two
//!
//! `dsa_setup_md` calls `ossl_digest_get_approved_nid` (`:170`) and
//! `ossl_DER_w_algorithmIdentifier_DSA_with_MD` (`:231`), both **unconditionally** on this
//! profile. Everything else the unit reaches is either already landed (`ossl_dsa_sign_int`,
//! `DSA_verify`, `DSA_size`, the `EVP_MD_CTX` layer, `WPACKET`) or inside a `#ifdef FIPS_MODULE`
//! arm. **`ossl_dsa_check_key` is one of the latter** — its only caller, `dsa_check_key`, is
//! inside `dsa_sig.c.in`'s `:252-280` FIPS block, so `providers/common/securitycheck.c` is *not*
//! this unit's prerequisite, which is the measurement that let `DSA` land before `RSA` and
//! `ECDSA`. The two sites are `src/provider/digest_to_nid.rs` and
//! `src/provider/der_dsa_sig.rs`.
//!
//! ## What the unit is, and what it does not publish
//!
//! The `DSA` row and the nine `DSA-<MD>` sigalgs both implement the **primitive** and the
//! **message** faces: `SIGN`/`VERIFY` take a digest (or, with `EVP_PKEY_OP_SIGNMSG`, a message
//! the unit digests itself), and `DIGEST_SIGN`/`DIGEST_VERIFY` drive the `EVP_MD_CTX`.
//! `dsa_sign_directly` refuses a `tbslen` that is neither zero nor the digest's size, and
//! `dsa_sign`/`dsa_verify` route on `operation`. `VRFY_RECOVER` is not published by either row,
//! because DSA has no message-recovery operation.
//!
//! ## The FIPS arms, and the two flags that are left
//!
//! Every `OSSL_FIPS_IND_*` macro is a no-op or a literal `1` when `FIPS_MODULE` is undefined
//! (`providers/fips/include/fips/fipsindicator.h`'s `#else` block), so the `fips` keys the
//! generated decoders carry are absent from the tables here and the indicator reads in
//! `dsa_get_ctx_params`/`dsa_common_set_ctx_params` collapse to nothing. The two `unsigned int : 1`
//! flags (`flag_sigalg`, `flag_allow_md`) are one storage lane, packed, as the authority packs
//! them.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::dsa::object::{DSA_free, DSA_up_ref};
use crate::dsa::sign::{ossl_dsa_sign_int, DSA_size, DSA_verify};
use crate::dsa::Dsa;
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex2, EVP_DigestUpdate, EVP_MD_CTX_dup, EVP_MD_CTX_free,
    EVP_MD_CTX_get_params, EVP_MD_CTX_new, EVP_MD_CTX_set_params, EVP_MD_fetch, EVP_MD_free,
    EVP_MD_get_size, EVP_MD_gettable_ctx_params, EVP_MD_is_a, EVP_MD_settable_ctx_params,
    EVP_MD_up_ref, EVP_MD_xof, EvpMd, EvpMdCtx,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_OP_SIGN, EVP_PKEY_OP_SIGNMSG, EVP_PKEY_OP_VERIFY, EVP_PKEY_OP_VERIFYMSG,
    OSSL_SIGNATURE_PARAM_DIGEST,
};
use crate::evp::signature::{
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SIGN, OSSL_FUNC_SIGNATURE_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
    OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE, OSSL_FUNC_SIGNATURE_VERIFY,
    OSSL_FUNC_SIGNATURE_VERIFY_INIT, OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
};
use crate::packet::{
    WPACKET_cleanup, WPACKET_finish, WPACKET_get_curr, WPACKET_get_total_written, WPACKET_init_der,
    Wpacket,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_get_octet_string,
    OSSL_PARAM_get_uint, OSSL_PARAM_get_utf8_string, OSSL_PARAM_set_octet_string,
    OSSL_PARAM_set_uint, OSSL_PARAM_set_utf8_string, OsslParam, END,
};
use crate::provider::cipher::{param_octet_string, param_uint, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::der_dsa_sig::ossl_DER_w_algorithmIdentifier_DSA_with_MD;
use crate::provider::digest_to_nid::ossl_digest_get_approved_nid;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::NID_undef;
use crate::runtime::str::{OPENSSL_strcasecmp, OPENSSL_strlcpy};

/// `OSSL_MAX_ALGORITHM_ID_SIZE` — `include/internal/sizes.h:20`.
const OSSL_MAX_ALGORITHM_ID_SIZE: usize = 256;

/// The unit's own `__FILE__`. `dsa_sig.c` is `.c.in`-generated, so the build compiles it from the
/// build tree and the compiler records the bare path, without the source-tree prefix D235 measured
/// on the plain-`.c` units.
const FILE: *const c_char = c"providers/implementations/signature/dsa_sig.c".as_ptr();

/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `OSSL_MAX_PROPQUERY_SIZE` — `include/internal/sizes.h:19`.
const OSSL_MAX_PROPQUERY_SIZE: usize = 256;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:449`.
const EVP_MAX_MD_SIZE: usize = 64;

/// `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` — `core_names.h:546`, which is
/// `OSSL_PKEY_PARAM_ALGORITHM_ID`.
const OSSL_SIGNATURE_PARAM_ALGORITHM_ID: *const c_char = c"algorithm-id".as_ptr();

/// `OSSL_SIGNATURE_PARAM_NONCE_TYPE` — `core_names.h:565`.
const OSSL_SIGNATURE_PARAM_NONCE_TYPE: *const c_char = c"nonce-type".as_ptr();

/// `OSSL_SIGNATURE_PARAM_PROPERTIES` — `core_names.h:567`, which is `OSSL_PKEY_PARAM_PROPERTIES`.
const OSSL_SIGNATURE_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();

/// `OSSL_SIGNATURE_PARAM_SIGNATURE` — `core_names.h:569`.
const OSSL_SIGNATURE_PARAM_SIGNATURE: *const c_char = c"signature".as_ptr();

/// `flag_sigalg`, the `unsigned int : 1` at `dsa_sig.c.in:92` — the low bit of the pair's storage
/// lane.
const FLAG_SIGALG: c_uint = 1;

/// `flag_allow_md`, the `unsigned int : 1` at `:99` — the high bit of the same lane.
const FLAG_ALLOW_MD: c_uint = 2;

/// `PROV_DSA_CTX` — `dsa_sig.c.in:76-118`. The `OSSL_FIPS_IND_DECLARE` at the foot is empty on
/// this profile, and `nonce_type` is the `unsigned int` at `:102` that selects a non-random `k`
/// for the deterministic sigalgs.
#[repr(C)]
struct ProvDsaCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `DSA *dsa` — a borrow carrying a reference.
    dsa: *mut Dsa,
    /// `int operation` — reuses `EVP_PKEY_OP_*`.
    operation: c_int,
    /// `unsigned int flag_sigalg : 1; unsigned int flag_allow_md : 1;` — one lane, two bits.
    flags: c_uint,
    /// `unsigned int nonce_type`.
    nonce_type: c_uint,
    /// `unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE]`.
    aid_buf: [u8; OSSL_MAX_ALGORITHM_ID_SIZE],
    /// `size_t aid_len`.
    aid_len: usize,
    /// `char mdname[OSSL_MAX_NAME_SIZE]` — purely informational.
    mdname: [c_char; OSSL_MAX_NAME_SIZE],
    /// `EVP_MD *md`.
    md: *mut EvpMd,
    /// `EVP_MD_CTX *mdctx`.
    mdctx: *mut EvpMdCtx,
    /// `unsigned char *sig` — for verification.
    sig: *mut u8,
    /// `size_t siglen`.
    siglen: usize,
}

/// `OSSL_FUNC_signature_set_ctx_params_fn` — the one callback `dsa_signverify_init` and
/// `dsa_sigalg_signverify_init` take.
type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static size_t dsa_get_md_size(const PROV_DSA_CTX *pdsactx)` — `dsa_sig.c.in:120-131`.
///
/// # Safety
/// `pdsactx` is live.
unsafe fn dsa_get_md_size(pdsactx: *const ProvDsaCtx) -> usize {
    // SAFETY: `pdsactx` is live per the contract.
    unsafe {
        if !(*pdsactx).md.is_null() {
            let md_size = EVP_MD_get_size((*pdsactx).md);
            if md_size <= 0 {
                return 0;
            }
            return md_size as usize;
        }
    }
    0
}

/// `static void *dsa_newctx(void *provctx, const char *propq)` — `dsa_sig.c.in:133-152`.
///
/// # Safety
/// The signature `newctx` dispatch contract; `propq` is NULL or NUL-terminated.
unsafe extern "C" fn dsa_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let pdsactx = CRYPTO_zalloc(core::mem::size_of::<ProvDsaCtx>(), FILE, 140).cast::<ProvDsaCtx>();
    if pdsactx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `pdsactx` is this call's own allocation; `propq` is NULL or NUL-terminated.
    unsafe {
        (*pdsactx).libctx = prov_libctx_of(provctx);
        (*pdsactx).flags = FLAG_ALLOW_MD;
        if !propq.is_null() {
            (*pdsactx).propq = CRYPTO_strdup(propq, FILE, 147);
            if (*pdsactx).propq.is_null() {
                CRYPTO_free(pdsactx.cast(), FILE, 148);
                return ptr::null_mut();
            }
        }
    }

    pdsactx.cast()
}

/// `static int dsa_setup_md(...)` — `dsa_sig.c.in:154-250`. The `#ifdef FIPS_MODULE` block at
/// `:192-206` is not this profile's arm, so the digest check is the `ossl_digest_get_approved_nid`
/// refusal alone.
///
/// # Safety
/// `ctx` is live; the three name/queries are NULL or NUL-terminated.
unsafe fn dsa_setup_md(
    ctx: *mut ProvDsaCtx,
    mdname: *const c_char,
    mdprops: *const c_char,
    _desc: *const c_char,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let mut mdprops = mdprops;
        if mdprops.is_null() {
            mdprops = (*ctx).propq;
        }

        if !mdname.is_null() {
            let mut pkt = core::mem::MaybeUninit::<Wpacket>::uninit();
            let mdname_len = CStr::from_ptr(mdname).to_bytes().len();

            let md = EVP_MD_fetch((*ctx).libctx, mdname, mdprops);
            // SAFETY: `md` is NULL or a live fetched digest.
            let md_nid = ossl_digest_get_approved_nid(md);

            if md.is_null() {
                raise_site(&err_sites::PROV_DSA_SIG_171);
                return dsa_setup_md_err(md);
            }
            if md_nid == NID_undef {
                raise_site(&err_sites::PROV_DSA_SIG_176);
                return dsa_setup_md_err(md);
            }
            if mdname_len >= OSSL_MAX_NAME_SIZE {
                raise_site(&err_sites::PROV_DSA_SIG_181);
                return dsa_setup_md_err(md);
            }
            /* XOF digests don't work. */
            if EVP_MD_xof(md) != 0 {
                raise_site(&err_sites::PROV_DSA_SIG_187);
                return dsa_setup_md_err(md);
            }

            if (*ctx).flags & FLAG_ALLOW_MD == 0 {
                if (*ctx).mdname[0] != 0 && EVP_MD_is_a(md, (*ctx).mdname.as_ptr()) == 0 {
                    raise_site(&err_sites::PROV_DSA_SIG_209);
                    return dsa_setup_md_err(md);
                }
                EVP_MD_free(md);
                return 1;
            }

            EVP_MD_CTX_free((*ctx).mdctx);
            EVP_MD_free((*ctx).md);

            /*
             * We do not care about DER writing errors: all it means is that there is no
             * AlgorithmIdentifier to be had, and the operation is still valid without one.
             */
            (*ctx).aid_len = 0;
            let pkt = pkt.as_mut_ptr();
            // SAFETY: `pkt` is a live local; the DER writer's contract.
            let mut aid: *mut u8 = ptr::null_mut();
            if WPACKET_init_der(pkt, (*ctx).aid_buf.as_mut_ptr(), OSSL_MAX_ALGORITHM_ID_SIZE) != 0
                && ossl_DER_w_algorithmIdentifier_DSA_with_MD(pkt, -1, (*ctx).dsa, md_nid) != 0
                && WPACKET_finish(pkt) != 0
            {
                WPACKET_get_total_written(pkt, ptr::addr_of_mut!((*ctx).aid_len));
                aid = WPACKET_get_curr(pkt).cast::<u8>();
            }
            WPACKET_cleanup(pkt);
            if !aid.is_null() && (*ctx).aid_len != 0 {
                ptr::copy(aid, (*ctx).aid_buf.as_mut_ptr(), (*ctx).aid_len);
            }

            (*ctx).mdctx = ptr::null_mut();
            (*ctx).md = md;
            OPENSSL_strlcpy((*ctx).mdname.as_mut_ptr(), mdname, OSSL_MAX_NAME_SIZE);
        }
    }

    1
}

/// The authority's `err:` arm (`dsa_sig.c.in:247-249`), reached from the five refusals in
/// [`dsa_setup_md`].
///
/// # Safety
/// `md` is NULL or a live fetched digest.
unsafe fn dsa_setup_md_err(md: *mut EvpMd) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { EVP_MD_free(md) };
    0
}

/// `static int dsa_signverify_init(...)` — `dsa_sig.c.in:282-323`, without the `FIPS_MODULE` tail
/// (`:311-321`), which is `dsa_sign_check_approved` and `dsa_check_key`.
///
/// # Safety
/// The signature init dispatch contract.
unsafe fn dsa_signverify_init(
    vpdsactx: *mut c_void,
    vdsa: *mut c_void,
    set_ctx_params: SetCtxParamsFn,
    params: *const OsslParam,
    operation: c_int,
    _desc: *const c_char,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    if is_running() == 0 || pdsactx.is_null() {
        return 0;
    }

    // SAFETY: `pdsactx` is this call's context and `vdsa` is NULL or the caller's key.
    unsafe {
        if vdsa.is_null() && (*pdsactx).dsa.is_null() {
            raise_site(&err_sites::PROV_DSA_SIG_293);
            return 0;
        }

        if !vdsa.is_null() {
            let key = vdsa.cast::<Dsa>();
            if DSA_up_ref(key) == 0 {
                return 0;
            }
            DSA_free((*pdsactx).dsa);
            (*pdsactx).dsa = key;
        }

        (*pdsactx).operation = operation;
    }

    // SAFETY: `pdsactx` is live and `params` is NULL or a key-terminated array.
    unsafe { set_ctx_params(vpdsactx, params) }
}

/// `static int dsa_sign_init(void *vpdsactx, void *vdsa, const OSSL_PARAM params[])` —
/// `dsa_sig.c.in:325-329`.
///
/// # Safety
/// The signature `sign_init` dispatch contract.
unsafe extern "C" fn dsa_sign_init(
    vpdsactx: *mut c_void,
    vdsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        dsa_signverify_init(
            vpdsactx,
            vdsa,
            dsa_set_ctx_params,
            params,
            EVP_PKEY_OP_SIGN,
            c"DSA Sign Init".as_ptr(),
        )
    }
}

/// `static int dsa_sign_directly(...)` — `dsa_sig.c.in:336-373`, without the FIPS arm at `:349-352`.
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe fn dsa_sign_directly(
    vpdsactx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        let dsasize = DSA_size((*pdsactx).dsa) as usize;
        let mdsize = dsa_get_md_size(pdsactx);

        if sig.is_null() {
            *siglen = dsasize;
            return 1;
        }

        if sigsize < dsasize {
            return 0;
        }

        if mdsize != 0 && tbslen != mdsize {
            return 0;
        }

        let mut sltmp: c_uint = 0;
        let ret = ossl_dsa_sign_int(
            0,
            tbs,
            tbslen as c_int,
            sig,
            &mut sltmp,
            (*pdsactx).dsa,
            (*pdsactx).nonce_type,
            (*pdsactx).mdname.as_ptr(),
            (*pdsactx).libctx,
            (*pdsactx).propq,
        );
        if ret <= 0 {
            return 0;
        }

        *siglen = sltmp as usize;
    }
    1
}

/// `static int dsa_signverify_message_update(...)` — `dsa_sig.c.in:375-385`.
///
/// # Safety
/// The signature `sign/verify_message_update` dispatch contract.
unsafe extern "C" fn dsa_signverify_message_update(
    vpdsactx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    if pdsactx.is_null() {
        return 0;
    }

    // SAFETY: `pdsactx` is the caller's context and its `mdctx` is live.
    unsafe { EVP_DigestUpdate((*pdsactx).mdctx, data.cast(), datalen) }
}

/// `static int dsa_sign_message_final(...)` — `dsa_sig.c.in:387-412`.
///
/// # Safety
/// The signature `sign_message_final` dispatch contract.
unsafe extern "C" fn dsa_sign_message_final(
    vpdsactx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();
    let mut digest = [0u8; EVP_MAX_MD_SIZE];
    let mut dlen: c_uint = 0;

    if is_running() == 0 || pdsactx.is_null() {
        return 0;
    }

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        if (*pdsactx).mdctx.is_null() {
            return 0;
        }
        /*
         * A NULL `sig` is the size query; the other fields are ignored and the answer is
         * `dsa_sign_directly`'s, which reports the size without touching the digest.
         */
        if !sig.is_null()
            && EVP_DigestFinal_ex((*pdsactx).mdctx, digest.as_mut_ptr(), &mut dlen) == 0
        {
            return 0;
        }

        dsa_sign_directly(
            vpdsactx,
            sig,
            siglen,
            sigsize,
            digest.as_ptr(),
            dlen as usize,
        )
    }
}

/// `static int dsa_sign(...)` — `dsa_sig.c.in:418-436`.
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe extern "C" fn dsa_sign(
    vpdsactx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        if (*pdsactx).operation == EVP_PKEY_OP_SIGNMSG {
            /*
             * If `sig` is NULL the caller is only asking for the length, and the input must NOT
             * be updated in that case.
             */
            if sig.is_null() {
                return dsa_sign_message_final(vpdsactx, sig, siglen, sigsize);
            }

            if dsa_signverify_message_update(vpdsactx, tbs, tbslen) <= 0 {
                return 0;
            }
            return dsa_sign_message_final(vpdsactx, sig, siglen, sigsize);
        }
        dsa_sign_directly(vpdsactx, sig, siglen, sigsize, tbs, tbslen)
    }
}

/// `static int dsa_verify_init(...)` — `dsa_sig.c.in:438-443`.
///
/// # Safety
/// The signature `verify_init` dispatch contract.
unsafe extern "C" fn dsa_verify_init(
    vpdsactx: *mut c_void,
    vdsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        dsa_signverify_init(
            vpdsactx,
            vdsa,
            dsa_set_ctx_params,
            params,
            EVP_PKEY_OP_VERIFY,
            c"DSA Verify Init".as_ptr(),
        )
    }
}

/// `static int dsa_verify_directly(...)` — `dsa_sig.c.in:445-456`.
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe fn dsa_verify_directly(
    vpdsactx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is live per the contract.
    unsafe {
        let mdsize = dsa_get_md_size(pdsactx);
        if is_running() == 0 || (mdsize != 0 && tbslen != mdsize) {
            return 0;
        }

        DSA_verify(
            0,
            tbs,
            tbslen as c_int,
            sig,
            siglen as c_int,
            (*pdsactx).dsa,
        )
    }
}

/// `static int dsa_verify_set_sig(...)` — `dsa_sig.c.in:458-468`.
///
/// # Safety
/// `vpdsactx` is live; `sig` readable for `siglen` bytes.
unsafe fn dsa_verify_set_sig(vpdsactx: *mut c_void, sig: *const u8, siglen: usize) -> c_int {
    let mut params = [END, END];
    // SAFETY: `params` is a live local array of two descriptors, and the constructor writes one.
    unsafe {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_SIGNATURE,
            sig.cast_mut().cast(),
            siglen,
        );
        params[1] = OSSL_PARAM_construct_end();
    }

    // SAFETY: `vpdsactx` is the caller's context and `params` is a terminated array.
    unsafe { dsa_sigalg_set_ctx_params(vpdsactx, params.as_ptr()) }
}

/// `static int dsa_verify_message_final(void *vpdsactx)` — `dsa_sig.c.in:470-491`.
///
/// # Safety
/// The signature `verify_message_final` dispatch contract.
unsafe extern "C" fn dsa_verify_message_final(vpdsactx: *mut c_void) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();
    let mut digest = [0u8; EVP_MAX_MD_SIZE];
    let mut dlen: c_uint = 0;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        if pdsactx.is_null() || (*pdsactx).mdctx.is_null() {
            return 0;
        }

        if EVP_DigestFinal_ex((*pdsactx).mdctx, digest.as_mut_ptr(), &mut dlen) == 0 {
            return 0;
        }

        dsa_verify_directly(
            vpdsactx,
            (*pdsactx).sig,
            (*pdsactx).siglen,
            digest.as_ptr(),
            dlen as usize,
        )
    }
}

/// `static int dsa_verify(...)` — `dsa_sig.c.in:497-511`.
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe extern "C" fn dsa_verify(
    vpdsactx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        if (*pdsactx).operation == EVP_PKEY_OP_VERIFYMSG {
            if dsa_verify_set_sig(vpdsactx, sig, siglen) <= 0 {
                return 0;
            }
            if dsa_signverify_message_update(vpdsactx, tbs, tbslen) <= 0 {
                return 0;
            }
            return dsa_verify_message_final(vpdsactx);
        }
        dsa_verify_directly(vpdsactx, sig, siglen, tbs, tbslen)
    }
}

/// `static int dsa_digest_signverify_init(...)` — `dsa_sig.c.in:515-551`.
///
/// # Safety
/// The signature `digest_sign/verify_init` dispatch contract.
unsafe fn dsa_digest_signverify_init(
    vpdsactx: *mut c_void,
    mdname: *const c_char,
    vdsa: *mut c_void,
    params: *const OsslParam,
    operation: c_int,
    desc: *const c_char,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        if dsa_signverify_init(vpdsactx, vdsa, dsa_set_ctx_params, params, operation, desc) == 0 {
            return 0;
        }

        if !mdname.is_null()
            /* was `dsa_setup_md` already called in `dsa_signverify_init`? */
            && ((*mdname) == 0 || OPENSSL_strcasecmp((*pdsactx).mdname.as_ptr(), mdname) != 0)
            && dsa_setup_md(pdsactx, mdname, ptr::null(), desc) == 0
        {
            return 0;
        }

        (*pdsactx).flags &= !FLAG_ALLOW_MD;

        if (*pdsactx).mdctx.is_null() {
            (*pdsactx).mdctx = EVP_MD_CTX_new();
            if (*pdsactx).mdctx.is_null() {
                return dsa_digest_signverify_init_err(pdsactx);
            }
        }

        if EVP_DigestInit_ex2((*pdsactx).mdctx, (*pdsactx).md, params) == 0 {
            return dsa_digest_signverify_init_err(pdsactx);
        }
    }

    1
}

/// The authority's `error:` arm (`dsa_sig.c.in:547-550`), reached from the two failures in
/// [`dsa_digest_signverify_init`].
///
/// # Safety
/// `pdsactx` is the caller's live context.
unsafe fn dsa_digest_signverify_init_err(pdsactx: *mut ProvDsaCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        EVP_MD_CTX_free((*pdsactx).mdctx);
        (*pdsactx).mdctx = ptr::null_mut();
    }
    0
}

/// `static int dsa_digest_sign_init(...)` — `dsa_sig.c.in:553-559`.
///
/// # Safety
/// The signature `digest_sign_init` dispatch contract.
unsafe extern "C" fn dsa_digest_sign_init(
    vpdsactx: *mut c_void,
    mdname: *const c_char,
    vdsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        dsa_digest_signverify_init(
            vpdsactx,
            mdname,
            vdsa,
            params,
            EVP_PKEY_OP_SIGNMSG,
            c"DSA Digest Sign Init".as_ptr(),
        )
    }
}

/// `static int dsa_digest_signverify_update(...)` — `dsa_sig.c.in:561-573`.
///
/// # Safety
/// The signature `digest_sign/verify_update` dispatch contract.
unsafe extern "C" fn dsa_digest_signverify_update(
    vpdsactx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    if pdsactx.is_null() {
        return 0;
    }
    /* Sigalg implementations shouldn't do `digest_sign`. */
    // SAFETY: `pdsactx` is the caller's context.
    if unsafe { (*pdsactx).flags } & FLAG_SIGALG != 0 {
        return 0;
    }

    // SAFETY: the caller's contract.
    unsafe { dsa_signverify_message_update(vpdsactx, data, datalen) }
}

/// `static int dsa_digest_sign_final(...)` — `dsa_sig.c.in:575-592`.
///
/// # Safety
/// The signature `digest_sign_final` dispatch contract.
unsafe extern "C" fn dsa_digest_sign_final(
    vpdsactx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    if pdsactx.is_null() {
        return 0;
    }
    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        /* Sigalg implementations shouldn't do `digest_sign`. */
        if (*pdsactx).flags & FLAG_SIGALG != 0 {
            return 0;
        }

        let ok = dsa_sign_message_final(vpdsactx, sig, siglen, sigsize);

        (*pdsactx).flags |= FLAG_ALLOW_MD;

        ok
    }
}

/// `static int dsa_digest_verify_init(...)` — `dsa_sig.c.in:594-600`.
///
/// # Safety
/// The signature `digest_verify_init` dispatch contract.
unsafe extern "C" fn dsa_digest_verify_init(
    vpdsactx: *mut c_void,
    mdname: *const c_char,
    vdsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        dsa_digest_signverify_init(
            vpdsactx,
            mdname,
            vdsa,
            params,
            EVP_PKEY_OP_VERIFYMSG,
            c"DSA Digest Verify Init".as_ptr(),
        )
    }
}

/// `int dsa_digest_verify_final(void *vpdsactx, const unsigned char *sig, size_t siglen)` —
/// `dsa_sig.c.in:602-620`. The authority's definition is non-`static`, which is why it is
/// `pub(crate) extern "C"` here rather than a module-private function.
///
/// # Safety
/// The signature `digest_verify_final` dispatch contract.
pub(crate) unsafe extern "C" fn dsa_digest_verify_final(
    vpdsactx: *mut c_void,
    sig: *const u8,
    siglen: usize,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();
    let mut ok = 0;

    if pdsactx.is_null() {
        return 0;
    }
    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        /* Sigalg implementations shouldn't do `digest_verify`. */
        if (*pdsactx).flags & FLAG_SIGALG != 0 {
            return 0;
        }

        if dsa_verify_set_sig(vpdsactx, sig, siglen) != 0 {
            ok = dsa_verify_message_final(vpdsactx);
        }

        (*pdsactx).flags |= FLAG_ALLOW_MD;

        ok
    }
}

/// `static void dsa_freectx(void *vpdsactx)` — `dsa_sig.c.in:622-632`.
///
/// # Safety
/// The signature `freectx` dispatch contract.
unsafe extern "C" fn dsa_freectx(vpdsactx: *mut c_void) {
    let ctx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `ctx` is the caller's context and every owned member is released here.
    unsafe {
        EVP_MD_CTX_free((*ctx).mdctx);
        EVP_MD_free((*ctx).md);
        CRYPTO_free((*ctx).sig.cast(), FILE, 628);
        CRYPTO_free((*ctx).propq.cast(), FILE, 629);
        DSA_free((*ctx).dsa);
        CRYPTO_free(ctx.cast(), FILE, 631);
    }
}

/// `static void *dsa_dupctx(void *vpdsactx)` — `dsa_sig.c.in:634-673`.
///
/// # Safety
/// The signature `dupctx` dispatch contract.
unsafe extern "C" fn dsa_dupctx(vpdsactx: *mut c_void) -> *mut c_void {
    let srcctx = vpdsactx.cast::<ProvDsaCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `srcctx` is the caller's live context; `CRYPTO_memdup` copies it.
    let dstctx = unsafe {
        CRYPTO_memdup(srcctx.cast(), core::mem::size_of::<ProvDsaCtx>(), FILE, 642)
            .cast::<ProvDsaCtx>()
    };
    if dstctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: both pointers are live per the contract; the copies are of this call's allocation.
    unsafe {
        (*dstctx).dsa = ptr::null_mut();
        (*dstctx).propq = ptr::null_mut();
        (*dstctx).md = ptr::null_mut();
        (*dstctx).mdctx = ptr::null_mut();
        (*dstctx).sig = ptr::null_mut();

        if !(*srcctx).dsa.is_null() && DSA_up_ref((*srcctx).dsa) == 0 {
            return dsa_dupctx_err(dstctx);
        }
        (*dstctx).dsa = (*srcctx).dsa;

        if !(*srcctx).md.is_null() && EVP_MD_up_ref((*srcctx).md) == 0 {
            return dsa_dupctx_err(dstctx);
        }
        (*dstctx).md = (*srcctx).md;

        if !(*srcctx).mdctx.is_null() {
            (*dstctx).mdctx = EVP_MD_CTX_dup((*srcctx).mdctx);
            if (*dstctx).mdctx.is_null() {
                return dsa_dupctx_err(dstctx);
            }
        }
        if !(*srcctx).propq.is_null() {
            (*dstctx).propq = CRYPTO_strdup((*srcctx).propq, FILE, 663);
            if (*dstctx).propq.is_null() {
                return dsa_dupctx_err(dstctx);
            }
        }
        if !(*srcctx).sig.is_null() {
            (*dstctx).sig =
                CRYPTO_memdup((*srcctx).sig.cast(), (*srcctx).siglen, FILE, 666).cast::<u8>();
            if (*dstctx).sig.is_null() {
                return dsa_dupctx_err(dstctx);
            }
        }
    }

    dstctx.cast()
}

/// The authority's `err:` arm (`dsa_sig.c.in:670-672`), reached from the five failures in
/// [`dsa_dupctx`].
///
/// # Safety
/// `dstctx` is this call's own allocation.
unsafe fn dsa_dupctx_err(dstctx: *mut ProvDsaCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { dsa_freectx(dstctx.cast()) };
    ptr::null_mut()
}

/// `struct dsa_get_ctx_params_st` — the `produce_param_decoder` expansion at
/// `dsa_sig.c.in:676-682`, generated from the four names. The `fips`-typed `ind` field is absent
/// because its key is `# if defined(FIPS_MODULE)`-guarded.
#[derive(Clone, Copy)]
struct GetCtxParams {
    algid: *const OsslParam,
    digest: *const OsslParam,
    nonce: *const OsslParam,
}

/// `dsa_get_ctx_params_decoder` — the decoder `produce_param_decoder` emits. A repeated key is
/// `PROV_R_REPEATED_PARAMETER` at the line the generated decoder raised it.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn dsa_get_ctx_params_decoder(params: *const OsslParam) -> Option<GetCtxParams> {
    let mut r = GetCtxParams {
        algid: ptr::null(),
        digest: ptr::null(),
        nonce: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key and the slots are this call's own.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            match s {
                b"algorithm-id" => {
                    if !r.algid.is_null() {
                        raise_site(&err_sites::PROV_DSA_SIG_714);
                        return None;
                    }
                    r.algid = p;
                }
                b"digest" => {
                    if !r.digest.is_null() {
                        raise_site(&err_sites::PROV_DSA_SIG_725);
                        return None;
                    }
                    r.digest = p;
                }
                b"nonce-type" => {
                    if !r.nonce.is_null() {
                        raise_site(&err_sites::PROV_DSA_SIG_737);
                        return None;
                    }
                    r.nonce = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM dsa_get_ctx_params_list[]` — `dsa_sig.c.in:676-681`.
static DSA_GET_CTX_PARAMS_LIST: [OsslParam; 4] = [
    param_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID),
    param_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST),
    param_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE),
    END,
];

/// `static int dsa_get_ctx_params(void *vpdsactx, OSSL_PARAM *params)` — `dsa_sig.c.in:684-708`.
///
/// # Safety
/// The signature `get_ctx_params` dispatch contract.
unsafe extern "C" fn dsa_get_ctx_params(vpdsactx: *mut c_void, params: *mut OsslParam) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if pdsactx.is_null() {
            return 0;
        }
        let Some(p) = dsa_get_ctx_params_decoder(params) else {
            return 0;
        };

        if !p.algid.is_null()
            && OSSL_PARAM_set_octet_string(
                p.algid.cast_mut(),
                if (*pdsactx).aid_len == 0 {
                    ptr::null()
                } else {
                    (*pdsactx).aid_buf.as_ptr().cast()
                },
                (*pdsactx).aid_len,
            ) == 0
        {
            return 0;
        }

        if !p.digest.is_null()
            && OSSL_PARAM_set_utf8_string(p.digest.cast_mut(), (*pdsactx).mdname.as_ptr()) == 0
        {
            return 0;
        }

        if !p.nonce.is_null() && OSSL_PARAM_set_uint(p.nonce.cast_mut(), (*pdsactx).nonce_type) == 0
        {
            return 0;
        }
    }

    1
}

/// `static const OSSL_PARAM *dsa_gettable_ctx_params(...)` — `dsa_sig.c.in:710-714`.
///
/// # Safety
/// The signature `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn dsa_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    DSA_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `struct dsa_all_set_ctx_params_st` — `dsa_sig.c.in:716-726`, without its three `FIPS_MODULE`
/// fields. The two generated set decoders fill different subsets of it and both pass it to
/// [`dsa_common_set_ctx_params`].
#[derive(Clone, Copy)]
struct AllSetCtxParams {
    digest: *const OsslParam,
    propq: *const OsslParam,
    nonce: *const OsslParam,
    sig: *const OsslParam,
}

/// `static int dsa_common_set_ctx_params(...)` — `dsa_sig.c.in:733-750`, without the three
/// `OSSL_FIPS_IND_SET_CTX_FROM_PARAM` calls, which expand to the literal 1 here.
///
/// # Safety
/// `pdsactx` is live.
unsafe fn dsa_common_set_ctx_params(pdsactx: *mut ProvDsaCtx, p: &AllSetCtxParams) -> c_int {
    // SAFETY: `pdsactx` is live and `p.nonce` is NULL or a live descriptor.
    unsafe {
        if !p.nonce.is_null()
            && OSSL_PARAM_get_uint(p.nonce, ptr::addr_of_mut!((*pdsactx).nonce_type)) == 0
        {
            return 0;
        }
    }
    1
}

/// `dsa_set_ctx_params_decoder` — the second generated decoder, over the six names of
/// `dsa_sig.c.in:755-762`.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn dsa_set_ctx_params_decoder(params: *const OsslParam) -> Option<AllSetCtxParams> {
    let mut r = AllSetCtxParams {
        digest: ptr::null(),
        propq: ptr::null(),
        nonce: ptr::null(),
        sig: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            match s {
                b"digest" => {
                    if !r.digest.is_null() {
                        raise_site(&err_sites::PROV_DSA_SIG_910);
                        return None;
                    }
                    r.digest = p;
                }
                b"properties" => {
                    if !r.propq.is_null() {
                        raise_site(&err_sites::PROV_DSA_SIG_920);
                        return None;
                    }
                    r.propq = p;
                }
                b"nonce-type" => {
                    if !r.nonce.is_null() {
                        raise_site(&err_sites::PROV_DSA_SIG_937);
                        return None;
                    }
                    r.nonce = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM dsa_set_ctx_params_list[]` — `dsa_sig.c.in:755-762`.
static DSA_SET_CTX_PARAMS_LIST: [OsslParam; 4] = [
    param_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST),
    param_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES),
    param_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE),
    END,
];

/// `static int dsa_set_ctx_params(void *vpdsactx, const OSSL_PARAM params[])` —
/// `dsa_sig.c.in:765-790`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn dsa_set_ctx_params(vpdsactx: *mut c_void, params: *const OsslParam) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if pdsactx.is_null() {
            return 0;
        }
        let Some(p) = dsa_set_ctx_params_decoder(params) else {
            return 0;
        };

        let ret = dsa_common_set_ctx_params(pdsactx, &p);
        if ret <= 0 {
            return ret;
        }

        if !p.digest.is_null() {
            let mut mdname = [0 as c_char; OSSL_MAX_NAME_SIZE];
            let mut pmdname = mdname.as_mut_ptr();
            let mut mdprops = [0 as c_char; OSSL_MAX_PROPQUERY_SIZE];
            let mut pmdprops = mdprops.as_mut_ptr();

            if OSSL_PARAM_get_utf8_string(p.digest, &mut pmdname, OSSL_MAX_NAME_SIZE) == 0 {
                return 0;
            }
            if !p.propq.is_null()
                && OSSL_PARAM_get_utf8_string(p.propq, &mut pmdprops, OSSL_MAX_PROPQUERY_SIZE) == 0
            {
                return 0;
            }
            if dsa_setup_md(
                pdsactx,
                mdname.as_ptr(),
                if p.propq.is_null() {
                    ptr::null()
                } else {
                    mdprops.as_ptr()
                },
                c"DSA Set Ctx".as_ptr(),
            ) == 0
            {
                return 0;
            }
        }
    }
    1
}

/// `static const OSSL_PARAM settable_ctx_params_no_digest[]` — `dsa_sig.c.in:792-794`.
static SETTABLE_CTX_PARAMS_NO_DIGEST: [OsslParam; 1] = [END];

/// `static const OSSL_PARAM *dsa_settable_ctx_params(...)` — `dsa_sig.c.in:796-804`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn dsa_settable_ctx_params(
    vpdsactx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is NULL or the caller's context.
    unsafe {
        if !pdsactx.is_null() && (*pdsactx).flags & FLAG_ALLOW_MD == 0 {
            return SETTABLE_CTX_PARAMS_NO_DIGEST.as_ptr();
        }
    }
    DSA_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int dsa_get_ctx_md_params(...)` — `dsa_sig.c.in:806-814`.
///
/// # Safety
/// The signature `get_ctx_md_params` dispatch contract.
unsafe extern "C" fn dsa_get_ctx_md_params(vpdsactx: *mut c_void, params: *mut OsslParam) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        if (*pdsactx).mdctx.is_null() {
            return 0;
        }

        EVP_MD_CTX_get_params((*pdsactx).mdctx, params)
    }
}

/// `static const OSSL_PARAM *dsa_gettable_ctx_md_params(void *vpdsactx)` —
/// `dsa_sig.c.in:816-824`.
///
/// # Safety
/// The signature `gettable_ctx_md_params` dispatch contract.
unsafe extern "C" fn dsa_gettable_ctx_md_params(vpdsactx: *mut c_void) -> *const OsslParam {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        if (*pdsactx).md.is_null() {
            return ptr::null();
        }

        EVP_MD_gettable_ctx_params((*pdsactx).md)
    }
}

/// `static int dsa_set_ctx_md_params(...)` — `dsa_sig.c.in:826-834`.
///
/// # Safety
/// The signature `set_ctx_md_params` dispatch contract.
unsafe extern "C" fn dsa_set_ctx_md_params(
    vpdsactx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        if (*pdsactx).mdctx.is_null() {
            return 0;
        }

        EVP_MD_CTX_set_params((*pdsactx).mdctx, params)
    }
}

/// `static const OSSL_PARAM *dsa_settable_ctx_md_params(void *vpdsactx)` —
/// `dsa_sig.c.in:836-844`.
///
/// # Safety
/// The signature `settable_ctx_md_params` dispatch contract.
unsafe extern "C" fn dsa_settable_ctx_md_params(vpdsactx: *mut c_void) -> *const OsslParam {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        if (*pdsactx).md.is_null() {
            return ptr::null();
        }

        EVP_MD_settable_ctx_params((*pdsactx).md)
    }
}

/// `const OSSL_DISPATCH ossl_dsa_signature_functions[]` — `dsa_sig.c.in:846-881`.
pub(crate) static DSA_SIGNATURE_FUNCTIONS: [OsslDispatch; 22] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: dsa_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: dsa_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN,
        function: dsa_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: dsa_verify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY,
        function: dsa_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: dsa_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: dsa_digest_signverify_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: dsa_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        function: dsa_digest_verify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
        function: dsa_digest_signverify_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
        function: dsa_digest_verify_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: dsa_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: dsa_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        function: dsa_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        function: dsa_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: dsa_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: dsa_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
        function: dsa_get_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
        function: dsa_gettable_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
        function: dsa_set_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
        function: dsa_settable_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static int dsa_sigalg_signverify_init(...)` — `dsa_sig.c.in:898-934`.
///
/// # Safety
/// The signature init dispatch contract.
unsafe fn dsa_sigalg_signverify_init(
    vpdsactx: *mut c_void,
    vdsa: *mut c_void,
    set_ctx_params: SetCtxParamsFn,
    params: *const OsslParam,
    mdname: *const c_char,
    operation: c_int,
    desc: *const c_char,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `pdsactx` is the caller's context.
    unsafe {
        if dsa_signverify_init(vpdsactx, vdsa, set_ctx_params, params, operation, desc) == 0 {
            return 0;
        }

        if dsa_setup_md(pdsactx, mdname, ptr::null(), desc) == 0 {
            return 0;
        }

        (*pdsactx).flags |= FLAG_SIGALG;
        (*pdsactx).flags &= !FLAG_ALLOW_MD;

        if (*pdsactx).mdctx.is_null() {
            (*pdsactx).mdctx = EVP_MD_CTX_new();
            if (*pdsactx).mdctx.is_null() {
                return dsa_digest_signverify_init_err(pdsactx);
            }
        }

        if EVP_DigestInit_ex2((*pdsactx).mdctx, (*pdsactx).md, params) == 0 {
            return dsa_digest_signverify_init_err(pdsactx);
        }
    }

    1
}

/// `static const char **dsa_sigalg_query_key_types(void)` — `dsa_sig.c.in:936-941`.
unsafe extern "C" fn dsa_sigalg_query_key_types() -> *mut *const c_char {
    /// `static const char *keytypes[] = { "DSA", NULL }`.
    #[repr(C)]
    struct KeyTypeNames([*const c_char; 2]);

    // SAFETY: the array holds `'static` literals and a NULL terminator; nothing mutates it.
    unsafe impl Sync for KeyTypeNames {}

    static KEYTYPES: KeyTypeNames = KeyTypeNames([c"DSA".as_ptr(), ptr::null()]);

    KEYTYPES.0.as_ptr().cast_mut()
}

/// `dsa_sigalg_set_ctx_params_decoder` — the third generated decoder, over the five names of
/// `dsa_sig.c.in:946-952`.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn dsa_sigalg_set_ctx_params_decoder(params: *const OsslParam) -> Option<AllSetCtxParams> {
    let mut r = AllSetCtxParams {
        digest: ptr::null(),
        propq: ptr::null(),
        nonce: ptr::null(),
        sig: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            match s {
                b"signature" => {
                    if !r.sig.is_null() {
                        raise_site(&err_sites::PROV_DSA_SIG_1219);
                        return None;
                    }
                    r.sig = p;
                }
                b"nonce-type" => {
                    if !r.nonce.is_null() {
                        raise_site(&err_sites::PROV_DSA_SIG_1232);
                        return None;
                    }
                    r.nonce = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM dsa_sigalg_set_ctx_params_list[]` — `dsa_sig.c.in:946-952`.
static DSA_SIGALG_SET_CTX_PARAMS_LIST: [OsslParam; 3] = [
    param_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE),
    param_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE),
    END,
];

/// `static const OSSL_PARAM *dsa_sigalg_settable_ctx_params(...)` — `dsa_sig.c.in:955-963`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn dsa_sigalg_settable_ctx_params(
    vpdsactx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is NULL or the caller's context.
    unsafe {
        if !pdsactx.is_null() && (*pdsactx).operation == EVP_PKEY_OP_VERIFYMSG {
            return DSA_SIGALG_SET_CTX_PARAMS_LIST.as_ptr();
        }
    }
    ptr::null()
}

/// `static int dsa_sigalg_set_ctx_params(...)` — `dsa_sig.c.in:965-994`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn dsa_sigalg_set_ctx_params(
    vpdsactx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let pdsactx = vpdsactx.cast::<ProvDsaCtx>();

    // SAFETY: `pdsactx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if pdsactx.is_null() {
            return 0;
        }
        let Some(p) = dsa_sigalg_set_ctx_params_decoder(params) else {
            return 0;
        };

        let ret = dsa_common_set_ctx_params(pdsactx, &p);
        if ret <= 0 {
            return ret;
        }

        if (*pdsactx).operation == EVP_PKEY_OP_VERIFYMSG && !p.sig.is_null() {
            CRYPTO_free((*pdsactx).sig.cast(), FILE, 979);
            (*pdsactx).sig = ptr::null_mut();
            (*pdsactx).siglen = 0;
            let mut sig: *mut c_void = ptr::null_mut();
            if OSSL_PARAM_get_octet_string(p.sig, &mut sig, 0, ptr::addr_of_mut!((*pdsactx).siglen))
                == 0
            {
                return 0;
            }
            (*pdsactx).sig = sig.cast::<u8>();
            /* The signature must not be empty. */
            if (*pdsactx).siglen == 0 {
                CRYPTO_free((*pdsactx).sig.cast(), FILE, 987);
                (*pdsactx).sig = ptr::null_mut();
                return 0;
            }
        }
    }
    1
}

/// One of the nine `DSA-<MD>` sigalgs' four init wrappers
/// (`dsa_sig.c.in:996-1054`'s `IMPL_DSA_SIGALG`, whose bodies differ only in the digest name, the
/// operation and the description).
macro_rules! dsa_sigalg_init {
    ($fn_name:ident, $md:literal, $op:expr, $desc:literal) => {
        unsafe extern "C" fn $fn_name(
            vpdsactx: *mut c_void,
            vdsa: *mut c_void,
            params: *const OsslParam,
        ) -> c_int {
            // SAFETY: the caller's contract.
            unsafe {
                dsa_sigalg_signverify_init(
                    vpdsactx,
                    vdsa,
                    dsa_sigalg_set_ctx_params,
                    params,
                    $md.as_ptr(),
                    $op,
                    $desc.as_ptr(),
                )
            }
        }
    };
}

dsa_sigalg_init!(
    dsa_sha1_sign_init,
    c"SHA1",
    EVP_PKEY_OP_SIGN,
    c"DSA-SHA1 Sign Init"
);
dsa_sigalg_init!(
    dsa_sha1_sign_message_init,
    c"SHA1",
    EVP_PKEY_OP_SIGNMSG,
    c"DSA-SHA1 Sign Message Init"
);
dsa_sigalg_init!(
    dsa_sha1_verify_init,
    c"SHA1",
    EVP_PKEY_OP_VERIFY,
    c"DSA-SHA1 Verify Init"
);
dsa_sigalg_init!(
    dsa_sha1_verify_message_init,
    c"SHA1",
    EVP_PKEY_OP_VERIFYMSG,
    c"DSA-SHA1 Verify Message Init"
);

dsa_sigalg_init!(
    dsa_sha224_sign_init,
    c"SHA2-224",
    EVP_PKEY_OP_SIGN,
    c"DSA-SHA2-224 Sign Init"
);
dsa_sigalg_init!(
    dsa_sha224_sign_message_init,
    c"SHA2-224",
    EVP_PKEY_OP_SIGNMSG,
    c"DSA-SHA2-224 Sign Message Init"
);
dsa_sigalg_init!(
    dsa_sha224_verify_init,
    c"SHA2-224",
    EVP_PKEY_OP_VERIFY,
    c"DSA-SHA2-224 Verify Init"
);
dsa_sigalg_init!(
    dsa_sha224_verify_message_init,
    c"SHA2-224",
    EVP_PKEY_OP_VERIFYMSG,
    c"DSA-SHA2-224 Verify Message Init"
);

dsa_sigalg_init!(
    dsa_sha256_sign_init,
    c"SHA2-256",
    EVP_PKEY_OP_SIGN,
    c"DSA-SHA2-256 Sign Init"
);
dsa_sigalg_init!(
    dsa_sha256_sign_message_init,
    c"SHA2-256",
    EVP_PKEY_OP_SIGNMSG,
    c"DSA-SHA2-256 Sign Message Init"
);
dsa_sigalg_init!(
    dsa_sha256_verify_init,
    c"SHA2-256",
    EVP_PKEY_OP_VERIFY,
    c"DSA-SHA2-256 Verify Init"
);
dsa_sigalg_init!(
    dsa_sha256_verify_message_init,
    c"SHA2-256",
    EVP_PKEY_OP_VERIFYMSG,
    c"DSA-SHA2-256 Verify Message Init"
);

dsa_sigalg_init!(
    dsa_sha384_sign_init,
    c"SHA2-384",
    EVP_PKEY_OP_SIGN,
    c"DSA-SHA2-384 Sign Init"
);
dsa_sigalg_init!(
    dsa_sha384_sign_message_init,
    c"SHA2-384",
    EVP_PKEY_OP_SIGNMSG,
    c"DSA-SHA2-384 Sign Message Init"
);
dsa_sigalg_init!(
    dsa_sha384_verify_init,
    c"SHA2-384",
    EVP_PKEY_OP_VERIFY,
    c"DSA-SHA2-384 Verify Init"
);
dsa_sigalg_init!(
    dsa_sha384_verify_message_init,
    c"SHA2-384",
    EVP_PKEY_OP_VERIFYMSG,
    c"DSA-SHA2-384 Verify Message Init"
);

dsa_sigalg_init!(
    dsa_sha512_sign_init,
    c"SHA2-512",
    EVP_PKEY_OP_SIGN,
    c"DSA-SHA2-512 Sign Init"
);
dsa_sigalg_init!(
    dsa_sha512_sign_message_init,
    c"SHA2-512",
    EVP_PKEY_OP_SIGNMSG,
    c"DSA-SHA2-512 Sign Message Init"
);
dsa_sigalg_init!(
    dsa_sha512_verify_init,
    c"SHA2-512",
    EVP_PKEY_OP_VERIFY,
    c"DSA-SHA2-512 Verify Init"
);
dsa_sigalg_init!(
    dsa_sha512_verify_message_init,
    c"SHA2-512",
    EVP_PKEY_OP_VERIFYMSG,
    c"DSA-SHA2-512 Verify Message Init"
);

dsa_sigalg_init!(
    dsa_sha3_224_sign_init,
    c"SHA3-224",
    EVP_PKEY_OP_SIGN,
    c"DSA-SHA3-224 Sign Init"
);
dsa_sigalg_init!(
    dsa_sha3_224_sign_message_init,
    c"SHA3-224",
    EVP_PKEY_OP_SIGNMSG,
    c"DSA-SHA3-224 Sign Message Init"
);
dsa_sigalg_init!(
    dsa_sha3_224_verify_init,
    c"SHA3-224",
    EVP_PKEY_OP_VERIFY,
    c"DSA-SHA3-224 Verify Init"
);
dsa_sigalg_init!(
    dsa_sha3_224_verify_message_init,
    c"SHA3-224",
    EVP_PKEY_OP_VERIFYMSG,
    c"DSA-SHA3-224 Verify Message Init"
);

dsa_sigalg_init!(
    dsa_sha3_256_sign_init,
    c"SHA3-256",
    EVP_PKEY_OP_SIGN,
    c"DSA-SHA3-256 Sign Init"
);
dsa_sigalg_init!(
    dsa_sha3_256_sign_message_init,
    c"SHA3-256",
    EVP_PKEY_OP_SIGNMSG,
    c"DSA-SHA3-256 Sign Message Init"
);
dsa_sigalg_init!(
    dsa_sha3_256_verify_init,
    c"SHA3-256",
    EVP_PKEY_OP_VERIFY,
    c"DSA-SHA3-256 Verify Init"
);
dsa_sigalg_init!(
    dsa_sha3_256_verify_message_init,
    c"SHA3-256",
    EVP_PKEY_OP_VERIFYMSG,
    c"DSA-SHA3-256 Verify Message Init"
);

dsa_sigalg_init!(
    dsa_sha3_384_sign_init,
    c"SHA3-384",
    EVP_PKEY_OP_SIGN,
    c"DSA-SHA3-384 Sign Init"
);
dsa_sigalg_init!(
    dsa_sha3_384_sign_message_init,
    c"SHA3-384",
    EVP_PKEY_OP_SIGNMSG,
    c"DSA-SHA3-384 Sign Message Init"
);
dsa_sigalg_init!(
    dsa_sha3_384_verify_init,
    c"SHA3-384",
    EVP_PKEY_OP_VERIFY,
    c"DSA-SHA3-384 Verify Init"
);
dsa_sigalg_init!(
    dsa_sha3_384_verify_message_init,
    c"SHA3-384",
    EVP_PKEY_OP_VERIFYMSG,
    c"DSA-SHA3-384 Verify Message Init"
);

dsa_sigalg_init!(
    dsa_sha3_512_sign_init,
    c"SHA3-512",
    EVP_PKEY_OP_SIGN,
    c"DSA-SHA3-512 Sign Init"
);
dsa_sigalg_init!(
    dsa_sha3_512_sign_message_init,
    c"SHA3-512",
    EVP_PKEY_OP_SIGNMSG,
    c"DSA-SHA3-512 Sign Message Init"
);
dsa_sigalg_init!(
    dsa_sha3_512_verify_init,
    c"SHA3-512",
    EVP_PKEY_OP_VERIFY,
    c"DSA-SHA3-512 Verify Init"
);
dsa_sigalg_init!(
    dsa_sha3_512_verify_message_init,
    c"SHA3-512",
    EVP_PKEY_OP_VERIFYMSG,
    c"DSA-SHA3-512 Verify Message Init"
);

/// One of the nine `DSA-<MD>` sigalgs' dispatch table (`dsa_sig.c.in:1056-1090`'s
/// `IMPL_DSA_SIGALG` tail, whose rows differ only in the four init slots).
macro_rules! dsa_sigalg_table {
    ($table:ident, $sign_init:ident, $sign_message_init:ident, $verify_init:ident, $verify_message_init:ident) => {
        pub(crate) static $table: [OsslDispatch; 19] = [
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
                function: dsa_newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
                function: $sign_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN,
                function: dsa_sign as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
                function: $sign_message_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
                function: dsa_signverify_message_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
                function: dsa_sign_message_final as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
                function: $verify_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY,
                function: dsa_verify as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
                function: $verify_message_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
                function: dsa_signverify_message_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
                function: dsa_verify_message_final as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_FREECTX,
                function: dsa_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
                function: dsa_dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
                function: dsa_sigalg_query_key_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
                function: dsa_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
                function: dsa_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
                function: dsa_sigalg_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
                function: dsa_sigalg_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

dsa_sigalg_table!(
    DSA_SHA1_SIGNATURE_FUNCTIONS,
    dsa_sha1_sign_init,
    dsa_sha1_sign_message_init,
    dsa_sha1_verify_init,
    dsa_sha1_verify_message_init
);
dsa_sigalg_table!(
    DSA_SHA224_SIGNATURE_FUNCTIONS,
    dsa_sha224_sign_init,
    dsa_sha224_sign_message_init,
    dsa_sha224_verify_init,
    dsa_sha224_verify_message_init
);
dsa_sigalg_table!(
    DSA_SHA256_SIGNATURE_FUNCTIONS,
    dsa_sha256_sign_init,
    dsa_sha256_sign_message_init,
    dsa_sha256_verify_init,
    dsa_sha256_verify_message_init
);
dsa_sigalg_table!(
    DSA_SHA384_SIGNATURE_FUNCTIONS,
    dsa_sha384_sign_init,
    dsa_sha384_sign_message_init,
    dsa_sha384_verify_init,
    dsa_sha384_verify_message_init
);
dsa_sigalg_table!(
    DSA_SHA512_SIGNATURE_FUNCTIONS,
    dsa_sha512_sign_init,
    dsa_sha512_sign_message_init,
    dsa_sha512_verify_init,
    dsa_sha512_verify_message_init
);
dsa_sigalg_table!(
    DSA_SHA3_224_SIGNATURE_FUNCTIONS,
    dsa_sha3_224_sign_init,
    dsa_sha3_224_sign_message_init,
    dsa_sha3_224_verify_init,
    dsa_sha3_224_verify_message_init
);
dsa_sigalg_table!(
    DSA_SHA3_256_SIGNATURE_FUNCTIONS,
    dsa_sha3_256_sign_init,
    dsa_sha3_256_sign_message_init,
    dsa_sha3_256_verify_init,
    dsa_sha3_256_verify_message_init
);
dsa_sigalg_table!(
    DSA_SHA3_384_SIGNATURE_FUNCTIONS,
    dsa_sha3_384_sign_init,
    dsa_sha3_384_sign_message_init,
    dsa_sha3_384_verify_init,
    dsa_sha3_384_verify_message_init
);
dsa_sigalg_table!(
    DSA_SHA3_512_SIGNATURE_FUNCTIONS,
    dsa_sha3_512_sign_init,
    dsa_sha3_512_sign_message_init,
    dsa_sha3_512_verify_init,
    dsa_sha3_512_verify_message_init
);
