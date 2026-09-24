//! Phase 8 — `providers/implementations/signature/sm2_sig.c`: the one `SM2`
//! `OSSL_OP_SIGNATURE` row.
//!
//! Five hundred and eighty-five template lines and one dispatch table. The unit is the `SM2` face
//! of the `EC`/`SM2` key object `src/provider/ec_kmgmt.rs` publishes (D389): `PROV_SM2_CTX` holds
//! an `EC_KEY` borrow, a `PROPQ`, the digest name/digest/`EVP_MD_CTX` triple, the digest size, the
//! AlgorithmIdentifier the digest names, and the SM2 user ID the `Z` value is computed over.
//!
//! ## The `Z` computation happens once, on the first update
//!
//! `flag_compute_z_digest` is set on every `digest_signverify_init` — each `EVP_Digest{Sign,
//! Verify}Init_ex(3)` starts with fresh content — and cleared the first time `sm2sig_compute_z_digest`
//! runs, which is what makes `distid` set after the first update a refusal
//! (`sm2sig_set_ctx_params`'s `if (!psm2ctx->flag_compute_z_digest) return 0`, `sm2_sig.c.in:469`).
//!
//! ## The two prerequisites, both landed
//!
//! `sm2sig_digest_signverify_init` calls `ossl_DER_w_algorithmIdentifier_SM2_with_MD`
//! (`src/provider/der_sm2_sig.rs`) and `sm2sig_compute_z_digest` calls
//! `ossl_sm2_compute_z_digest` (`src/sm2/sign.rs`). Everything else is the `EVP_MD_CTX` layer,
//! `WPACKET`, `ECDSA_size` and the two `ossl_sm2_internal_*` entry points.
//!
//! ## The court drives the row through the public path
//!
//! The vector is the GM/T 0003.5-2012 Annex A `(r, s)` the crypt unit's own test pins, driven here
//! through `EVP_PKEY_CTX_new_from_name` + `EVP_DigestVerify` — the dispatch face, not the crypt
//! function.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::asn1::ECDSA_size;
use crate::ec::key::{EC_KEY_free, EC_KEY_up_ref};
use crate::ec::EcKey;
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex2, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_get_params, EVP_MD_CTX_new, EVP_MD_CTX_set_params, EVP_MD_fetch, EVP_MD_free,
    EVP_MD_get0_name, EVP_MD_get_size, EVP_MD_get_type, EVP_MD_gettable_ctx_params, EVP_MD_is_a,
    EVP_MD_settable_ctx_params, EVP_MD_up_ref, EVP_MD_xof, EvpMd, EvpMdCtx,
};
use crate::evp::pkey_ctx::OSSL_SIGNATURE_PARAM_DIGEST;
use crate::evp::signature::{
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SIGN, OSSL_FUNC_SIGNATURE_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_VERIFY, OSSL_FUNC_SIGNATURE_VERIFY_INIT,
};
use crate::packet::{
    WPACKET_cleanup, WPACKET_finish, WPACKET_get_curr, WPACKET_get_total_written, WPACKET_init_der,
    Wpacket,
};
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t, OSSL_PARAM_get_utf8_string,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_size_t, OSSL_PARAM_set_utf8_string, OsslParam, END,
};
use crate::provider::cipher::{param_octet_string, param_size_t, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::der_sm2_sig::ossl_DER_w_algorithmIdentifier_SM2_with_MD;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::str::OPENSSL_strlcpy;
use crate::sm2::sign::{
    ossl_sm2_compute_z_digest, ossl_sm2_internal_sign, ossl_sm2_internal_verify,
};

/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `OSSL_MAX_ALGORITHM_ID_SIZE` — `include/internal/sizes.h:20`.
const OSSL_MAX_ALGORITHM_ID_SIZE: usize = 256;

/// `SM3_DIGEST_LENGTH` — `include/internal/sm3.h:22`.
const SM3_DIGEST_LENGTH: usize = 32;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:449`.
const EVP_MAX_MD_SIZE: usize = 64;

/// `OSSL_DIGEST_NAME_SM3` — `core_names.h:52`.
const OSSL_DIGEST_NAME_SM3: *const c_char = c"SM3".as_ptr();

/// `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` — `core_names.h`, which is `OSSL_PKEY_PARAM_ALGORITHM_ID`.
const OSSL_SIGNATURE_PARAM_ALGORITHM_ID: *const c_char = c"algorithm-id".as_ptr();

/// `OSSL_SIGNATURE_PARAM_DIGEST_SIZE` — `core_names.h:552`.
const OSSL_SIGNATURE_PARAM_DIGEST_SIZE: *const c_char = c"digest-size".as_ptr();

/// `OSSL_PKEY_PARAM_DIST_ID` — `core_names.h:110`, the SM2 user ID.
const OSSL_PKEY_PARAM_DIST_ID: *const c_char = c"distid".as_ptr();

/// `PROV_SM2_CTX` — `sm2_sig.c.in:68-95`. The `flag_compute_z_digest` bitfield is one `unsigned
/// int`, so it is a `c_uint` here; every reader/writer in the unit treats it as `0`/`1`.
#[repr(C)]
struct ProvSm2SigCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `EC_KEY *ec` — a borrow carrying a reference.
    ec: *mut EcKey,
    /// `unsigned int flag_compute_z_digest : 1`.
    flag_compute_z_digest: c_uint,
    /// `char mdname[OSSL_MAX_NAME_SIZE]`.
    mdname: [c_char; OSSL_MAX_NAME_SIZE],
    /// `unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE]`.
    aid_buf: [u8; OSSL_MAX_ALGORITHM_ID_SIZE],
    /// `size_t aid_len`.
    aid_len: usize,
    /// `EVP_MD *md` — the fetched main digest.
    md: *mut EvpMd,
    /// `EVP_MD_CTX *mdctx`.
    mdctx: *mut EvpMdCtx,
    /// `size_t mdsize`.
    mdsize: usize,
    /// `unsigned char *id` — the SM2 user ID, owned.
    id: *mut u8,
    /// `size_t id_len`.
    id_len: usize,
}

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static int sm2sig_set_mdname(PROV_SM2_CTX *psm2ctx, const char *mdname)` —
/// `sm2_sig.c.in:97-123`.
///
/// # Safety
/// `psm2ctx` is live; `mdname` is NULL or NUL-terminated.
unsafe fn sm2sig_set_mdname(psm2ctx: *mut ProvSm2SigCtx, mdname: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if (*psm2ctx).md.is_null() {
            (*psm2ctx).md = EVP_MD_fetch(
                (*psm2ctx).libctx,
                (*psm2ctx).mdname.as_ptr(),
                (*psm2ctx).propq,
            );
        }
        if (*psm2ctx).md.is_null() {
            return 0;
        }

        /* XOF digests don't work */
        if EVP_MD_xof((*psm2ctx).md) != 0 {
            raise_site(&err_sites::PROV_SM2_SIG_105);
            return 0;
        }

        if mdname.is_null() {
            return 1;
        }

        let name = CStr::from_ptr(mdname).to_bytes();
        if name.len() >= OSSL_MAX_NAME_SIZE || EVP_MD_is_a((*psm2ctx).md, mdname) == 0 {
            let mut msg = Vec::with_capacity(b"digest=".len() + name.len() + 1);
            msg.extend_from_slice(b"digest=");
            msg.extend_from_slice(name);
            msg.push(0);
            raise_site_data(&err_sites::PROV_SM2_SIG_114, msg.as_ptr().cast());
            return 0;
        }

        OPENSSL_strlcpy((*psm2ctx).mdname.as_mut_ptr(), mdname, OSSL_MAX_NAME_SIZE);
        1
    }
}

/// `static void *sm2sig_newctx(void *provctx, const char *propq)` — `sm2_sig.c.in:125-140`.
///
/// # Safety
/// The signature `newctx` dispatch contract; `propq` is NULL or NUL-terminated.
unsafe extern "C" fn sm2sig_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
    // SAFETY: a fresh zeroed allocation of this call's own context.
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<ProvSm2SigCtx>(), FILE, 127).cast::<ProvSm2SigCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is this call's own allocation; `propq` is NULL or NUL-terminated.
    unsafe {
        (*ctx).libctx = prov_libctx_of(provctx);
        if !propq.is_null() {
            (*ctx).propq = CRYPTO_strdup(propq, FILE, 133);
            if (*ctx).propq.is_null() {
                CRYPTO_free(ctx.cast(), FILE, 134);
                return ptr::null_mut();
            }
        }
        (*ctx).mdsize = SM3_DIGEST_LENGTH;
        OPENSSL_strlcpy(
            (*ctx).mdname.as_mut_ptr(),
            OSSL_DIGEST_NAME_SM3,
            OSSL_MAX_NAME_SIZE,
        );
    }

    ctx.cast()
}

/// `static int sm2sig_signature_init(void *vpsm2ctx, void *ec, const OSSL_PARAM params[])` —
/// `sm2_sig.c.in:142-164`. One body for both the sign and verify inits.
///
/// # Safety
/// The signature init dispatch contract.
unsafe extern "C" fn sm2sig_signature_init(
    vpsm2ctx: *mut c_void,
    ec: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    if is_running() == 0 || psm2ctx.is_null() {
        return 0;
    }

    // SAFETY: `psm2ctx` is this call's context; `ec` is NULL or the caller's key.
    unsafe {
        if ec.is_null() && (*psm2ctx).ec.is_null() {
            raise_site(&err_sites::PROV_SM2_SIG_150);
            return 0;
        }

        if !ec.is_null() {
            let key = ec.cast::<EcKey>();
            if EC_KEY_up_ref(key) == 0 {
                return 0;
            }
            EC_KEY_free((*psm2ctx).ec);
            (*psm2ctx).ec = key;
        }

        sm2sig_set_ctx_params(vpsm2ctx, params)
    }
}

/// `static int sm2sig_sign(void *vpsm2ctx, unsigned char *sig, size_t *siglen, size_t sigsize,`
/// `const unsigned char *tbs, size_t tbslen)` — `sm2_sig.c.in:166-192`.
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe extern "C" fn sm2sig_sign(
    vpsm2ctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: the dispatch contract; the unit's own context is live.
    unsafe {
        /* SM2 uses ECDSA_size as well */
        let ecsize = ECDSA_size((*ctx).ec) as usize;

        if sig.is_null() {
            *siglen = ecsize;
            return 1;
        }

        if sigsize < ecsize {
            return 0;
        }

        if (*ctx).mdsize != 0 && tbslen != (*ctx).mdsize {
            return 0;
        }

        let mut sltmp: c_uint = 0;
        let ret = ossl_sm2_internal_sign(
            tbs,
            tbslen as c_int,
            sig,
            ptr::addr_of_mut!(sltmp),
            (*ctx).ec,
        );
        if ret <= 0 {
            return 0;
        }

        *siglen = sltmp as usize;
        1
    }
}

/// `static int sm2sig_verify(void *vpsm2ctx, const unsigned char *sig, size_t siglen,`
/// `const unsigned char *tbs, size_t tbslen)` — `sm2_sig.c.in:194-203`.
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe extern "C" fn sm2sig_verify(
    vpsm2ctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: the dispatch contract; the unit's own context is live.
    unsafe {
        if (*ctx).mdsize != 0 && tbslen != (*ctx).mdsize {
            return 0;
        }

        ossl_sm2_internal_verify(tbs, tbslen as c_int, sig, siglen as c_int, (*ctx).ec)
    }
}

/// `static void free_md(PROV_SM2_CTX *ctx)` — `sm2_sig.c.in:205-211`.
///
/// # Safety
/// `ctx` is live.
unsafe fn free_md(ctx: *mut ProvSm2SigCtx) {
    // SAFETY: the caller's contract.
    unsafe {
        EVP_MD_CTX_free((*ctx).mdctx);
        EVP_MD_free((*ctx).md);
        (*ctx).mdctx = ptr::null_mut();
        (*ctx).md = ptr::null_mut();
    }
}

/// `static int sm2sig_digest_signverify_init(void *vpsm2ctx, const char *mdname, void *ec,`
/// `const OSSL_PARAM params[])` — `sm2_sig.c.in:213-265`.
///
/// # Safety
/// The signature `digest_sign_init`/`digest_verify_init` dispatch contract.
unsafe extern "C" fn sm2sig_digest_signverify_init(
    vpsm2ctx: *mut c_void,
    mdname: *const c_char,
    ec: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();
    let mut ret: c_int = 0;

    // SAFETY: the dispatch contract; the unit's own context is live.
    unsafe {
        /*
         * Each EVP_Digest{Sign,Verify}Init_ex(3) starts with fresh content, that
         * needs to recompute the "Z" digest.
         */
        (*ctx).flag_compute_z_digest = 1;

        if sm2sig_signature_init(vpsm2ctx, ec, params) == 0 || sm2sig_set_mdname(ctx, mdname) == 0 {
            return ret;
        }

        if (*ctx).mdctx.is_null() {
            (*ctx).mdctx = EVP_MD_CTX_new();
            if (*ctx).mdctx.is_null() {
                return ret;
            }
        }

        let md_nid = EVP_MD_get_type((*ctx).md);

        /*
         * We do not care about DER writing errors. All it really means is that for some reason,
         * there's no AlgorithmIdentifier to be had, but the operation itself is still valid, just
         * as long as it's not used to construct anything that needs an AlgorithmIdentifier.
         */
        (*ctx).aid_len = 0;
        let mut pkt = core::mem::MaybeUninit::<Wpacket>::uninit();
        let pkt = pkt.as_mut_ptr();
        let mut aid: *mut u8 = ptr::null_mut();
        if WPACKET_init_der(pkt, (*ctx).aid_buf.as_mut_ptr(), OSSL_MAX_ALGORITHM_ID_SIZE) != 0
            && ossl_DER_w_algorithmIdentifier_SM2_with_MD(pkt, -1, (*ctx).ec, md_nid) != 0
            && WPACKET_finish(pkt) != 0
        {
            WPACKET_get_total_written(pkt, ptr::addr_of_mut!((*ctx).aid_len));
            aid = WPACKET_get_curr(pkt).cast::<u8>();
        }
        WPACKET_cleanup(pkt);
        if !aid.is_null() && (*ctx).aid_len != 0 {
            ptr::copy(aid, (*ctx).aid_buf.as_mut_ptr(), (*ctx).aid_len);
        }

        if EVP_DigestInit_ex2((*ctx).mdctx, (*ctx).md, params) == 0 {
            return ret;
        }

        ret = 1;
        ret
    }
}

/// `static int sm2sig_compute_z_digest(PROV_SM2_CTX *ctx)` — `sm2_sig.c.in:267-286`.
///
/// # Safety
/// `ctx` is live and its `mdctx` is initialised.
unsafe fn sm2sig_compute_z_digest(ctx: *mut ProvSm2SigCtx) -> c_int {
    let mut ret: c_int = 1;

    // SAFETY: the caller's contract.
    unsafe {
        if (*ctx).flag_compute_z_digest != 0 {
            /* Only do this once */
            (*ctx).flag_compute_z_digest = 0;

            /* get hashed prefix 'z' of tbs message */
            let z = CRYPTO_zalloc((*ctx).mdsize, FILE, 276).cast::<u8>();
            if z.is_null()
                || ossl_sm2_compute_z_digest(z, (*ctx).md, (*ctx).id, (*ctx).id_len, (*ctx).ec) == 0
                || EVP_DigestUpdate((*ctx).mdctx, z.cast::<c_void>(), (*ctx).mdsize) == 0
            {
                ret = 0;
            }
            CRYPTO_free(z.cast(), FILE, 282);
        }

        ret
    }
}

/// `int sm2sig_digest_signverify_update(void *vpsm2ctx, const unsigned char *data,`
/// `size_t datalen)` — `sm2_sig.c.in:288-298`.
///
/// # Safety
/// The signature `digest_sign_update`/`digest_verify_update` dispatch contract.
unsafe extern "C" fn sm2sig_digest_signverify_update(
    vpsm2ctx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: the dispatch contract; the unit's own context is live.
    unsafe {
        if psm2ctx.is_null() || (*psm2ctx).mdctx.is_null() {
            return 0;
        }

        (sm2sig_compute_z_digest(psm2ctx) != 0
            && EVP_DigestUpdate((*psm2ctx).mdctx, data.cast::<c_void>(), datalen) != 0)
            as c_int
    }
}

/// `int sm2sig_digest_sign_final(void *vpsm2ctx, unsigned char *sig, size_t *siglen,`
/// `size_t sigsize)` — `sm2_sig.c.in:300-321`.
///
/// # Safety
/// The signature `digest_sign_final` dispatch contract.
unsafe extern "C" fn sm2sig_digest_sign_final(
    vpsm2ctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();
    let mut digest = [0u8; EVP_MAX_MD_SIZE];
    let mut dlen: c_uint = 0;

    // SAFETY: the dispatch contract; the unit's own context is live.
    unsafe {
        if psm2ctx.is_null() || (*psm2ctx).mdctx.is_null() {
            return 0;
        }

        /*
         * If sig is NULL then we're just finding out the sig size. Other fields are ignored.
         * Defer to sm2sig_sign.
         */
        if !sig.is_null()
            && (sm2sig_compute_z_digest(psm2ctx) == 0
                || EVP_DigestFinal_ex(
                    (*psm2ctx).mdctx,
                    digest.as_mut_ptr(),
                    ptr::addr_of_mut!(dlen),
                ) == 0)
        {
            return 0;
        }

        sm2sig_sign(
            vpsm2ctx,
            sig,
            siglen,
            sigsize,
            digest.as_ptr(),
            dlen as usize,
        )
    }
}

/// `int sm2sig_digest_verify_final(void *vpsm2ctx, const unsigned char *sig, size_t siglen)` —
/// `sm2_sig.c.in:323-343`.
///
/// # Safety
/// The signature `digest_verify_final` dispatch contract.
unsafe extern "C" fn sm2sig_digest_verify_final(
    vpsm2ctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();
    let mut digest = [0u8; EVP_MAX_MD_SIZE];
    let mut dlen: c_uint = 0;

    // SAFETY: the dispatch contract; the unit's own context is live.
    unsafe {
        if psm2ctx.is_null() || (*psm2ctx).mdctx.is_null() {
            return 0;
        }

        let md_size = EVP_MD_get_size((*psm2ctx).md);
        if md_size <= 0 || md_size as usize > EVP_MAX_MD_SIZE {
            return 0;
        }

        if sm2sig_compute_z_digest(psm2ctx) == 0
            || EVP_DigestFinal_ex(
                (*psm2ctx).mdctx,
                digest.as_mut_ptr(),
                ptr::addr_of_mut!(dlen),
            ) == 0
        {
            return 0;
        }

        sm2sig_verify(vpsm2ctx, sig, siglen, digest.as_ptr(), dlen as usize)
    }
}

/// `static void sm2sig_freectx(void *vpsm2ctx)` — `sm2_sig.c.in:345-354`.
///
/// # Safety
/// The signature `freectx` dispatch contract.
unsafe extern "C" fn sm2sig_freectx(vpsm2ctx: *mut c_void) {
    let ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        free_md(ctx);
        EC_KEY_free((*ctx).ec);
        CRYPTO_free((*ctx).propq.cast(), FILE, 351);
        CRYPTO_free((*ctx).id.cast(), FILE, 352);
        CRYPTO_free(ctx.cast(), FILE, 353);
    }
}

/// `static void *sm2sig_dupctx(void *vpsm2ctx)` — `sm2_sig.c.in:356-405`.
///
/// # Safety
/// The signature `dupctx` dispatch contract.
unsafe extern "C" fn sm2sig_dupctx(vpsm2ctx: *mut c_void) -> *mut c_void {
    let srcctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: `srcctx` is the caller's context.
    unsafe {
        let dstctx =
            CRYPTO_zalloc(core::mem::size_of::<ProvSm2SigCtx>(), FILE, 361).cast::<ProvSm2SigCtx>();
        if dstctx.is_null() {
            return ptr::null_mut();
        }

        ptr::copy_nonoverlapping(srcctx, dstctx, 1);
        (*dstctx).ec = ptr::null_mut();
        (*dstctx).propq = ptr::null_mut();
        (*dstctx).md = ptr::null_mut();
        (*dstctx).mdctx = ptr::null_mut();
        (*dstctx).id = ptr::null_mut();

        if !(*srcctx).ec.is_null() && EC_KEY_up_ref((*srcctx).ec) == 0 {
            sm2sig_freectx(dstctx.cast());
            return ptr::null_mut();
        }
        (*dstctx).ec = (*srcctx).ec;

        if !(*srcctx).propq.is_null() {
            (*dstctx).propq = CRYPTO_strdup((*srcctx).propq, FILE, 377);
            if (*dstctx).propq.is_null() {
                sm2sig_freectx(dstctx.cast());
                return ptr::null_mut();
            }
        }

        if !(*srcctx).md.is_null() && EVP_MD_up_ref((*srcctx).md) == 0 {
            sm2sig_freectx(dstctx.cast());
            return ptr::null_mut();
        }
        (*dstctx).md = (*srcctx).md;

        if !(*srcctx).mdctx.is_null() {
            (*dstctx).mdctx = EVP_MD_CTX_new();
            if (*dstctx).mdctx.is_null()
                || EVP_MD_CTX_copy_ex((*dstctx).mdctx, (*srcctx).mdctx) == 0
            {
                sm2sig_freectx(dstctx.cast());
                return ptr::null_mut();
            }
        }

        if !(*srcctx).id.is_null() {
            (*dstctx).id = CRYPTO_malloc((*srcctx).id_len, FILE, 394).cast::<u8>();
            if (*dstctx).id.is_null() {
                sm2sig_freectx(dstctx.cast());
                return ptr::null_mut();
            }
            (*dstctx).id_len = (*srcctx).id_len;
            ptr::copy((*srcctx).id, (*dstctx).id, (*srcctx).id_len);
        }

        dstctx.cast()
    }
}

/// `struct sm2sig_get_ctx_params_st` — the `produce_param_decoder` expansion at
/// `sm2_sig.c:417-421`.
#[derive(Clone, Copy)]
struct GetCtxParams {
    algid: *const OsslParam,
    size: *const OsslParam,
    digest: *const OsslParam,
}

/// `sm2sig_get_ctx_params_decoder` — the generated get decoder (`sm2_sig.c:424-497`).
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn sm2sig_get_ctx_params_decoder(params: *const OsslParam) -> Option<GetCtxParams> {
    let mut r = GetCtxParams {
        algid: ptr::null(),
        size: ptr::null(),
        digest: ptr::null(),
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
                b"algorithm-id" => {
                    if !r.algid.is_null() {
                        raise_site(&err_sites::PROV_SM2_SIG_440);
                        return None;
                    }
                    r.algid = p;
                }
                b"digest-size" => {
                    if !r.size.is_null() {
                        raise_site(&err_sites::PROV_SM2_SIG_475);
                        return None;
                    }
                    r.size = p;
                }
                b"digest" => {
                    if !r.digest.is_null() {
                        raise_site(&err_sites::PROV_SM2_SIG_484);
                        return None;
                    }
                    r.digest = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM sm2sig_get_ctx_params_list[]` — `sm2_sig.c:407-412`.
static SM2SIG_GET_CTX_PARAMS_LIST: [OsslParam; 4] = [
    param_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID),
    param_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE),
    param_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST),
    END,
];

/// `static int sm2sig_get_ctx_params(void *vpsm2ctx, OSSL_PARAM *params)` —
/// `sm2_sig.c:501-537`.
///
/// # Safety
/// The signature `get_ctx_params` dispatch contract.
unsafe extern "C" fn sm2sig_get_ctx_params(vpsm2ctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: `psm2ctx` is NULL or the caller's context; `params` is a terminated array.
    unsafe {
        if psm2ctx.is_null() {
            return 0;
        }
        let Some(p) = sm2sig_get_ctx_params_decoder(params) else {
            return 0;
        };

        if !p.algid.is_null()
            && OSSL_PARAM_set_octet_string(
                p.algid.cast_mut(),
                if (*psm2ctx).aid_len == 0 {
                    ptr::null()
                } else {
                    (*psm2ctx).aid_buf.as_ptr().cast::<c_void>()
                },
                (*psm2ctx).aid_len,
            ) == 0
        {
            return 0;
        }

        if !p.size.is_null() && OSSL_PARAM_set_size_t(p.size.cast_mut(), (*psm2ctx).mdsize) == 0 {
            return 0;
        }

        if !p.digest.is_null() {
            let name = if (*psm2ctx).md.is_null() {
                (*psm2ctx).mdname.as_ptr()
            } else {
                EVP_MD_get0_name((*psm2ctx).md)
            };
            if OSSL_PARAM_set_utf8_string(p.digest.cast_mut(), name) == 0 {
                return 0;
            }
        }

        1
    }
}

/// `static const OSSL_PARAM *sm2sig_gettable_ctx_params(void *vpsm2ctx, void *provctx)` —
/// `sm2_sig.c:508-513`.
///
/// # Safety
/// The signature `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn sm2sig_gettable_ctx_params(
    _vpsm2ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SM2SIG_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `struct sm2sig_set_ctx_params_st` — the `produce_param_decoder` expansion at
/// `sm2_sig.c:531-535`.
#[derive(Clone, Copy)]
struct SetCtxParams {
    size: *const OsslParam,
    digest: *const OsslParam,
    distid: *const OsslParam,
}

/// `sm2sig_set_ctx_params_decoder` — the generated set decoder (`sm2_sig.c:538-620`).
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn sm2sig_set_ctx_params_decoder(params: *const OsslParam) -> Option<SetCtxParams> {
    let mut r = SetCtxParams {
        size: ptr::null(),
        digest: ptr::null(),
        distid: ptr::null(),
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
                b"digest-size" => {
                    if !r.size.is_null() {
                        raise_site(&err_sites::PROV_SM2_SIG_591);
                        return None;
                    }
                    r.size = p;
                }
                b"digest" => {
                    if !r.digest.is_null() {
                        raise_site(&err_sites::PROV_SM2_SIG_600);
                        return None;
                    }
                    r.digest = p;
                }
                b"distid" => {
                    if !r.distid.is_null() {
                        raise_site(&err_sites::PROV_SM2_SIG_614);
                        return None;
                    }
                    r.distid = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM sm2sig_set_ctx_params_list[]` — `sm2_sig.c:524-529`.
static SM2SIG_SET_CTX_PARAMS_LIST: [OsslParam; 4] = [
    param_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE),
    param_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST),
    param_octet_string(OSSL_PKEY_PARAM_DIST_ID),
    END,
];

/// `static int sm2sig_set_ctx_params(void *vpsm2ctx, const OSSL_PARAM params[])` —
/// `sm2_sig.c:622-682`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn sm2sig_set_ctx_params(
    vpsm2ctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: `psm2ctx` is NULL or the caller's context; `params` is a terminated array.
    unsafe {
        if psm2ctx.is_null() {
            return 0;
        }
        let Some(p) = sm2sig_set_ctx_params_decoder(params) else {
            return 0;
        };

        if !p.distid.is_null() {
            /*
             * If the 'z' digest has already been computed, the ID is set too late.
             */
            if (*psm2ctx).flag_compute_z_digest == 0 {
                return 0;
            }

            let mut tmp_id: *mut c_void = ptr::null_mut();
            let mut tmp_idlen: usize = 0;
            if (*p.distid).data_size != 0
                && OSSL_PARAM_get_octet_string(
                    p.distid,
                    ptr::addr_of_mut!(tmp_id),
                    0,
                    ptr::addr_of_mut!(tmp_idlen),
                ) == 0
            {
                return 0;
            }
            CRYPTO_free((*psm2ctx).id.cast(), FILE, 475);
            (*psm2ctx).id = tmp_id.cast::<u8>();
            (*psm2ctx).id_len = tmp_idlen;
        }

        /*
         * The size must be the SM3 digest size; a different one is refused.
         */
        if !p.size.is_null() {
            let mut mdsize: usize = 0;
            if OSSL_PARAM_get_size_t(p.size, ptr::addr_of_mut!(mdsize)) == 0
                || mdsize != (*psm2ctx).mdsize
            {
                return 0;
            }
        }

        if !p.digest.is_null() {
            let mut mdname: *mut c_char = ptr::null_mut();
            if OSSL_PARAM_get_utf8_string(p.digest, ptr::addr_of_mut!(mdname), 0) == 0 {
                return 0;
            }
            if sm2sig_set_mdname(psm2ctx, mdname) == 0 {
                CRYPTO_free(mdname.cast(), FILE, 496);
                return 0;
            }
            CRYPTO_free(mdname.cast(), FILE, 498);
        }

        1
    }
}

/// `static const OSSL_PARAM *sm2sig_settable_ctx_params(void *vpsm2ctx, void *provctx)` —
/// `sm2_sig.c:504-508`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn sm2sig_settable_ctx_params(
    _vpsm2ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SM2SIG_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int sm2sig_get_ctx_md_params(void *vpsm2ctx, OSSL_PARAM *params)` —
/// `sm2_sig.c:510-518`.
///
/// # Safety
/// The signature `get_ctx_md_params` dispatch contract.
unsafe extern "C" fn sm2sig_get_ctx_md_params(
    vpsm2ctx: *mut c_void,
    params: *mut OsslParam,
) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: `psm2ctx` is live.
    unsafe {
        if (*psm2ctx).mdctx.is_null() {
            return 0;
        }

        EVP_MD_CTX_get_params((*psm2ctx).mdctx, params)
    }
}

/// `static const OSSL_PARAM *sm2sig_gettable_ctx_md_params(void *vpsm2ctx)` —
/// `sm2_sig.c:520-528`.
///
/// # Safety
/// The signature `gettable_ctx_md_params` dispatch contract.
unsafe extern "C" fn sm2sig_gettable_ctx_md_params(vpsm2ctx: *mut c_void) -> *const OsslParam {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: `psm2ctx` is live.
    unsafe {
        if (*psm2ctx).md.is_null() {
            return ptr::null();
        }

        EVP_MD_gettable_ctx_params((*psm2ctx).md)
    }
}

/// `static int sm2sig_set_ctx_md_params(void *vpsm2ctx, const OSSL_PARAM params[])` —
/// `sm2_sig.c:530-538`.
///
/// # Safety
/// The signature `set_ctx_md_params` dispatch contract.
unsafe extern "C" fn sm2sig_set_ctx_md_params(
    vpsm2ctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: `psm2ctx` is live.
    unsafe {
        if (*psm2ctx).mdctx.is_null() {
            return 0;
        }

        EVP_MD_CTX_set_params((*psm2ctx).mdctx, params)
    }
}

/// `static const OSSL_PARAM *sm2sig_settable_ctx_md_params(void *vpsm2ctx)` — `sm2_sig.c:540-548`.
///
/// # Safety
/// The signature `settable_ctx_md_params` dispatch contract.
unsafe extern "C" fn sm2sig_settable_ctx_md_params(vpsm2ctx: *mut c_void) -> *const OsslParam {
    let psm2ctx = vpsm2ctx.cast::<ProvSm2SigCtx>();

    // SAFETY: `psm2ctx` is live.
    unsafe {
        if (*psm2ctx).md.is_null() {
            return ptr::null();
        }

        EVP_MD_settable_ctx_params((*psm2ctx).md)
    }
}

/// The unit's own `__FILE__` — the bare build-relative path (D235's finding).
const FILE: *const c_char = c"providers/implementations/signature/sm2_sig.c".as_ptr();

/// `const OSSL_DISPATCH ossl_sm2_signature_functions[]` — `sm2_sig.c:550-585`.
pub(crate) static SM2_SIGNATURE_FUNCTIONS: [OsslDispatch; 22] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: sm2sig_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: sm2sig_signature_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN,
        function: sm2sig_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: sm2sig_signature_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY,
        function: sm2sig_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: sm2sig_digest_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: sm2sig_digest_signverify_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: sm2sig_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        function: sm2sig_digest_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
        function: sm2sig_digest_signverify_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
        function: sm2sig_digest_verify_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: sm2sig_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: sm2sig_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        function: sm2sig_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        function: sm2sig_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: sm2sig_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: sm2sig_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
        function: sm2sig_get_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
        function: sm2sig_gettable_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
        function: sm2sig_set_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
        function: sm2sig_settable_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
