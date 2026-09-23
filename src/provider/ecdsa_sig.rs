//! Phase 8 — `providers/implementations/signature/ecdsa_sig.c`: the ten `ECDSA`
//! `OSSL_OP_SIGNATURE` rows.
//!
//! The unit is the `ECDSA` face of the `EC` key object `src/provider/ec_kmgmt.rs` publishes (D390):
//! the `EC` row's keymgmt passes an `EC_KEY`, and `PROV_ECDSA_CTX` holds a borrow of it, an
//! `EVP_MD`/`EVP_MD_CTX` pair for the message-digest path, the digest's size, and the
//! AlgorithmIdentifier the digest names. The plain `ECDSA` row is `ecdsa_sign_init`/`ecdsa_verify_init`
//! over `ossl_ecdsa_deterministic_sign`/`ECDSA_sign_ex` and `ECDSA_verify`; the nine `ECDSA-<MD>`
//! sigalgs are one implementation with the digest name and the operation fixed at the call site.
//!
//! ## The one non-FIPS prerequisite, and why only one
//!
//! `ecdsa_setup_md` calls `ossl_digest_get_approved_nid` (`:207`, already landed as
//! `src/provider/digest_to_nid.rs`) and `ossl_DER_w_algorithmIdentifier_ECDSA_with_MD` (`:234`,
//! `src/provider/der_ec_sig.rs`), both **unconditionally** on this profile. Everything else the unit
//! reaches is either already landed (`ossl_ecdsa_deterministic_sign`, `ECDSA_sign_ex`, `ECDSA_verify`,
//! `ECDSA_size`, the `EVP_MD_CTX` layer, `WPACKET`), compiled out for this profile
//! (`OPENSSL_NO_ACVP_TESTS` is defined in `configuration.h:38-39`, so `ctx->kattest` and the
//! `ECDSA_sign_setup` arm at `:355-358` are absent), or inside a `#ifdef FIPS_MODULE` arm
//! (`ossl_fips_ind_digest_sign_check`, `ossl_fips_ind_ec_key_check`, `ctx->verify_message`).
//! `providers/common/securitycheck.c` is **not** this unit's prerequisite for the same reason
//! `ossl_dsa_check_key` is not DSA's: its only ECDSA caller is inside the FIPS block at `:301-307`.
//!
//! ## The one shape that differs from `DSA`
//!
//! `PROV_ECDSA_CTX` caches the digest size in a field, `mdsize`, rather than recomputing it from
//! `md` — DSA's `dsa_get_md_size` has no ECDSA counterpart, and the `DIGEST_SIZE` parameter both
//! reads and writes it. That field is what `ecdsa_sign_directly` compares `tbslen` against and what
//! `ECDSA_size` does *not* account for, which is why the plain row's `size` observation in the court
//! is the deterministic `ECDSA_size` maximum rather than `mdsize`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::bn::bignum::{BN_clear_free, BigNum};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::asn1::ECDSA_size;
use crate::ec::ecdsa::{ECDSA_sign_ex, ECDSA_verify};
use crate::ec::ecdsa_ossl::ossl_ecdsa_deterministic_sign;
use crate::ec::key::{EC_KEY_free, EC_KEY_up_ref};
use crate::ec::EcKey;
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex2, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_get_params, EVP_MD_CTX_new, EVP_MD_CTX_set_params, EVP_MD_fetch, EVP_MD_free,
    EVP_MD_get0_name, EVP_MD_get_size, EVP_MD_gettable_ctx_params, EVP_MD_is_a,
    EVP_MD_settable_ctx_params, EVP_MD_up_ref, EVP_MD_xof, EvpMd, EvpMdCtx,
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
    OSSL_PARAM_get_size_t, OSSL_PARAM_get_uint, OSSL_PARAM_get_utf8_string,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_size_t, OSSL_PARAM_set_uint,
    OSSL_PARAM_set_utf8_string, OsslParam, END,
};
use crate::provider::cipher::{param_octet_string, param_size_t, param_uint, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::der_ec_sig::ossl_DER_w_algorithmIdentifier_ECDSA_with_MD;
use crate::provider::digest_to_nid::ossl_digest_get_approved_nid;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::NID_undef;
use crate::runtime::str::{OPENSSL_strcasecmp, OPENSSL_strlcpy};

/// `OSSL_MAX_ALGORITHM_ID_SIZE` — `include/internal/sizes.h:20`.
const OSSL_MAX_ALGORITHM_ID_SIZE: usize = 256;

/// The unit's own `__FILE__`. `ecdsa_sig.c` is `.c.in`-generated, so the build compiles it from the
/// build tree and the compiler records the bare path (D235's finding).
const FILE: *const c_char = c"providers/implementations/signature/ecdsa_sig.c".as_ptr();

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

/// `OSSL_SIGNATURE_PARAM_DIGEST_SIZE` — `core_names.h:561`, which is `OSSL_PKEY_PARAM_MD_SIZE`.
const OSSL_SIGNATURE_PARAM_DIGEST_SIZE: *const c_char = c"digest-size".as_ptr();

/// `flag_sigalg`, the `unsigned int : 1` at `ecdsa_sig.c.in:89` — the low bit of the pair's storage
/// lane.
const FLAG_SIGALG: c_uint = 1;

/// `flag_allow_md`, the `unsigned int : 1` at `:96` — the high bit of the same lane.
const FLAG_ALLOW_MD: c_uint = 2;

/// `PROV_ECDSA_CTX` — `ecdsa_sig.c.in:72-121`. The `OSSL_FIPS_IND_DECLARE` at the foot is empty on
/// this profile, and the `OPENSSL_NO_ACVP_TESTS` `kattest` lane and the `FIPS_MODULE`
/// `verify_message` lane are both absent, so the context is exactly this field list.
#[repr(C)]
struct ProvEcdsaCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `EC_KEY *ec` — a borrow carrying a reference.
    ec: *mut EcKey,
    /// `int operation` — reuses `EVP_PKEY_OP_*`.
    operation: c_int,
    /// `unsigned int flag_sigalg : 1; unsigned int flag_allow_md : 1;` — one lane, two bits.
    flags: c_uint,
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
    /// `size_t mdsize` — the digest's own size, which the `DIGEST_SIZE` parameter reads and writes.
    mdsize: usize,
    /// `unsigned char *sig` — for verification.
    sig: *mut u8,
    /// `size_t siglen`.
    siglen: usize,
    /// `BIGNUM *kinv` — the CAVS precomputed nonce, always NULL on this profile.
    kinv: *mut BigNum,
    /// `BIGNUM *r` — the CAVS precomputed nonce's `r`, always NULL on this profile.
    r: *mut BigNum,
    /// `unsigned int nonce_type`.
    nonce_type: c_uint,
}

/// `OSSL_FUNC_signature_set_ctx_params_fn` — the one callback `ecdsa_signverify_init` and
/// `ecdsa_sigalg_signverify_init` take.
type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static void *ecdsa_newctx(void *provctx, const char *propq)` — `ecdsa_sig.c.in:124-152`.
///
/// # Safety
/// The signature `newctx` dispatch contract; `propq` is NULL or NUL-terminated.
unsafe extern "C" fn ecdsa_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvEcdsaCtx>(), FILE, 138).cast::<ProvEcdsaCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is this call's own allocation; `propq` is NULL or NUL-terminated.
    unsafe {
        (*ctx).libctx = prov_libctx_of(provctx);
        (*ctx).flags = FLAG_ALLOW_MD;
        if !propq.is_null() {
            (*ctx).propq = CRYPTO_strdup(propq, FILE, 147);
            if (*ctx).propq.is_null() {
                CRYPTO_free(ctx.cast(), FILE, 149);
                return ptr::null_mut();
            }
        }
    }

    ctx.cast()
}

/// `static int ecdsa_setup_md(...)` — `ecdsa_sig.c.in:155-274`. The `#ifdef FIPS_MODULE` blocks at
/// `:199-206` and `:219-231` are not this profile's arm.
///
/// # Safety
/// `ctx` is live; the three name/queries are NULL or NUL-terminated.
unsafe fn ecdsa_setup_md(
    ctx: *mut ProvEcdsaCtx,
    mdname: *const c_char,
    mdprops: *const c_char,
    _desc: *const c_char,
) -> c_int {
    if mdname.is_null() {
        return 1;
    }

    // SAFETY: `ctx` is live per the contract and the name is NUL-terminated.
    unsafe {
        let mut mdprops = mdprops;
        let mdname_len = CStr::from_ptr(mdname).to_bytes().len();

        // The name-length refusal is taken *before* the fetch, so the digest is never fetched when
        // the name cannot be stored. The order is the authority's and is observable through which
        // reason the record carries.
        if mdname_len >= OSSL_MAX_NAME_SIZE {
            raise_site(&err_sites::PROV_ECDSA_SIG_184);
            return 0;
        }
        if mdprops.is_null() {
            mdprops = (*ctx).propq;
        }
        let md = EVP_MD_fetch((*ctx).libctx, mdname, mdprops);
        if md.is_null() {
            raise_site(&err_sites::PROV_ECDSA_SIG_192);
            return 0;
        }
        let md_size = EVP_MD_get_size(md);
        if md_size <= 0 {
            raise_site(&err_sites::PROV_ECDSA_SIG_198);
            return ecdsa_setup_md_err(md);
        }
        let md_nid = ossl_digest_get_approved_nid(md);
        /* XOF digests don't work. */
        if EVP_MD_xof(md) != 0 {
            raise_site(&err_sites::PROV_ECDSA_SIG_212);
            return ecdsa_setup_md_err(md);
        }

        if (*ctx).flags & FLAG_ALLOW_MD == 0 {
            if (*ctx).mdname[0] != 0 && EVP_MD_is_a(md, (*ctx).mdname.as_ptr()) == 0 {
                raise_site(&err_sites::PROV_ECDSA_SIG_234);
                return ecdsa_setup_md_err(md);
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
        let mut pkt = core::mem::MaybeUninit::<Wpacket>::uninit();
        let pkt = pkt.as_mut_ptr();
        if md_nid != NID_undef {
            // SAFETY: `pkt` is a live local; the DER writer's contract.
            let mut aid: *mut u8 = ptr::null_mut();
            if WPACKET_init_der(pkt, (*ctx).aid_buf.as_mut_ptr(), OSSL_MAX_ALGORITHM_ID_SIZE) != 0
                && ossl_DER_w_algorithmIdentifier_ECDSA_with_MD(pkt, -1, (*ctx).ec, md_nid) != 0
                && WPACKET_finish(pkt) != 0
            {
                WPACKET_get_total_written(pkt, ptr::addr_of_mut!((*ctx).aid_len));
                aid = WPACKET_get_curr(pkt).cast::<u8>();
            }
            WPACKET_cleanup(pkt);
            if !aid.is_null() && (*ctx).aid_len != 0 {
                ptr::copy(aid, (*ctx).aid_buf.as_mut_ptr(), (*ctx).aid_len);
            }
        }

        (*ctx).mdctx = ptr::null_mut();
        (*ctx).md = md;
        (*ctx).mdsize = md_size as usize;
        OPENSSL_strlcpy((*ctx).mdname.as_mut_ptr(), mdname, OSSL_MAX_NAME_SIZE);
    }

    1
}

/// The authority's `err:` arm (`ecdsa_sig.c.in:271-273`), reached from the three refusals in
/// [`ecdsa_setup_md`].
///
/// # Safety
/// `md` is NULL or a live fetched digest.
unsafe fn ecdsa_setup_md_err(md: *mut EvpMd) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { EVP_MD_free(md) };
    0
}

/// `static int ecdsa_signverify_init(...)` — `ecdsa_sig.c.in:276-312`, without the `FIPS_MODULE`
/// tail (`:301-307`), which is `ossl_fips_ind_ec_key_check`.
///
/// # Safety
/// The signature init dispatch contract.
unsafe fn ecdsa_signverify_init(
    vctx: *mut c_void,
    vec: *mut c_void,
    set_ctx_params: SetCtxParamsFn,
    params: *const OsslParam,
    operation: c_int,
    _desc: *const c_char,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    if is_running() == 0 || ctx.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is this call's context and `vec` is NULL or the caller's key.
    unsafe {
        if vec.is_null() && (*ctx).ec.is_null() {
            raise_site(&err_sites::PROV_ECDSA_SIG_285);
            return 0;
        }

        if !vec.is_null() {
            let key = vec.cast::<EcKey>();
            if EC_KEY_up_ref(key) == 0 {
                return 0;
            }
            EC_KEY_free((*ctx).ec);
            (*ctx).ec = key;
        }

        (*ctx).operation = operation;
    }

    // SAFETY: `ctx` is live and `params` is NULL or a key-terminated array.
    unsafe { set_ctx_params(vctx, params) }
}

/// `static int ecdsa_sign_init(void *vctx, void *ec, const OSSL_PARAM params[])` —
/// `ecdsa_sig.c.in:314-323`.
///
/// # Safety
/// The signature `sign_init` dispatch contract.
unsafe extern "C" fn ecdsa_sign_init(
    vctx: *mut c_void,
    vec: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecdsa_signverify_init(
            vctx,
            vec,
            ecdsa_set_ctx_params,
            params,
            EVP_PKEY_OP_SIGN,
            c"ECDSA Sign Init".as_ptr(),
        )
    }
}

/// `static int ecdsa_sign_directly(...)` — `ecdsa_sig.c.in:329-373`, without the `OPENSSL_NO_ACVP_TESTS`
/// arm at `:355-358` (`kattest` and `ECDSA_sign_setup` are both absent on this profile).
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe fn ecdsa_sign_directly(
    vctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context.
    unsafe {
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
        let ret = if (*ctx).nonce_type != 0 {
            let mdname = if (*ctx).mdname[0] != 0 {
                (*ctx).mdname.as_ptr()
            } else {
                ptr::null()
            };
            ossl_ecdsa_deterministic_sign(
                tbs,
                tbslen as c_int,
                sig,
                &mut sltmp,
                (*ctx).ec,
                (*ctx).nonce_type,
                mdname,
                (*ctx).libctx,
                (*ctx).propq,
            )
        } else {
            ECDSA_sign_ex(
                0,
                tbs,
                tbslen as c_int,
                sig,
                &mut sltmp,
                (*ctx).kinv,
                (*ctx).r,
                (*ctx).ec,
            )
        };
        if ret <= 0 {
            return 0;
        }

        *siglen = sltmp as usize;
    }
    1
}

/// `static int ecdsa_signverify_message_update(...)` — `ecdsa_sig.c.in:375-385`.
///
/// # Safety
/// The signature `sign/verify_message_update` dispatch contract.
unsafe extern "C" fn ecdsa_signverify_message_update(
    vctx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    if ctx.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context and its `mdctx` is live.
    unsafe { EVP_DigestUpdate((*ctx).mdctx, data.cast(), datalen) }
}

/// `static int ecdsa_sign_message_final(...)` — `ecdsa_sig.c.in:387-406`.
///
/// # Safety
/// The signature `sign_message_final` dispatch contract.
unsafe extern "C" fn ecdsa_sign_message_final(
    vctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();
    let mut digest = [0u8; EVP_MAX_MD_SIZE];
    let mut dlen: c_uint = 0;

    if is_running() == 0 || ctx.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if (*ctx).mdctx.is_null() {
            return 0;
        }
        /*
         * A NULL `sig` is the size query; the other fields are ignored and the answer is
         * `ecdsa_sign_directly`'s, which reports the size without touching the digest.
         */
        if !sig.is_null() && EVP_DigestFinal_ex((*ctx).mdctx, digest.as_mut_ptr(), &mut dlen) == 0 {
            return 0;
        }

        ecdsa_sign_directly(vctx, sig, siglen, sigsize, digest.as_ptr(), dlen as usize)
    }
}

/// `static int ecdsa_sign(...)` — `ecdsa_sig.c.in:412-428`.
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe extern "C" fn ecdsa_sign(
    vctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if (*ctx).operation == EVP_PKEY_OP_SIGNMSG {
            /*
             * If `sig` is NULL the caller is only asking for the length, and the input must NOT
             * be updated in that case.
             */
            if sig.is_null() {
                return ecdsa_sign_message_final(vctx, sig, siglen, sigsize);
            }

            if ecdsa_signverify_message_update(vctx, tbs, tbslen) <= 0 {
                return 0;
            }
            return ecdsa_sign_message_final(vctx, sig, siglen, sigsize);
        }
        ecdsa_sign_directly(vctx, sig, siglen, sigsize, tbs, tbslen)
    }
}

/// `static int ecdsa_verify_init(...)` — `ecdsa_sig.c.in:430-439`.
///
/// # Safety
/// The signature `verify_init` dispatch contract.
unsafe extern "C" fn ecdsa_verify_init(
    vctx: *mut c_void,
    vec: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecdsa_signverify_init(
            vctx,
            vec,
            ecdsa_set_ctx_params,
            params,
            EVP_PKEY_OP_VERIFY,
            c"ECDSA Verify Init".as_ptr(),
        )
    }
}

/// `static int ecdsa_verify_directly(...)` — `ecdsa_sig.c.in:441-452`.
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe fn ecdsa_verify_directly(
    vctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if is_running() == 0 || ((*ctx).mdsize != 0 && tbslen != (*ctx).mdsize) {
            return 0;
        }

        ECDSA_verify(0, tbs, tbslen as c_int, sig, siglen as c_int, (*ctx).ec)
    }
}

/// `static int ecdsa_verify_set_sig(...)` — `ecdsa_sig.c.in:454-464`.
///
/// # Safety
/// `vctx` is live; `sig` readable for `siglen` bytes.
unsafe fn ecdsa_verify_set_sig(vctx: *mut c_void, sig: *const u8, siglen: usize) -> c_int {
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

    // SAFETY: `vctx` is the caller's context and `params` is a terminated array.
    unsafe { ecdsa_sigalg_set_ctx_params(vctx, params.as_ptr()) }
}

/// `static int ecdsa_verify_message_final(void *vctx)` — `ecdsa_sig.c.in:466-487`.
///
/// # Safety
/// The signature `verify_message_final` dispatch contract.
unsafe extern "C" fn ecdsa_verify_message_final(vctx: *mut c_void) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();
    let mut digest = [0u8; EVP_MAX_MD_SIZE];
    let mut dlen: c_uint = 0;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if ctx.is_null() || (*ctx).mdctx.is_null() {
            return 0;
        }

        if EVP_DigestFinal_ex((*ctx).mdctx, digest.as_mut_ptr(), &mut dlen) == 0 {
            return 0;
        }

        ecdsa_verify_directly(
            vctx,
            (*ctx).sig,
            (*ctx).siglen,
            digest.as_ptr(),
            dlen as usize,
        )
    }
}

/// `static int ecdsa_verify(...)` — `ecdsa_sig.c.in:493-507`.
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe extern "C" fn ecdsa_verify(
    vctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if (*ctx).operation == EVP_PKEY_OP_VERIFYMSG {
            if ecdsa_verify_set_sig(vctx, sig, siglen) <= 0 {
                return 0;
            }
            if ecdsa_signverify_message_update(vctx, tbs, tbslen) <= 0 {
                return 0;
            }
            return ecdsa_verify_message_final(vctx);
        }
        ecdsa_verify_directly(vctx, sig, siglen, tbs, tbslen)
    }
}

/// `static int ecdsa_digest_signverify_init(...)` — `ecdsa_sig.c.in:511-551`.
///
/// # Safety
/// The signature `digest_sign/verify_init` dispatch contract.
unsafe fn ecdsa_digest_signverify_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vec: *mut c_void,
    params: *const OsslParam,
    operation: c_int,
    desc: *const c_char,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if ecdsa_signverify_init(vctx, vec, ecdsa_set_ctx_params, params, operation, desc) == 0 {
            return 0;
        }

        if !mdname.is_null()
            /* was `ecdsa_setup_md` already called in `ecdsa_signverify_init`? */
            && ((*mdname) == 0 || OPENSSL_strcasecmp((*ctx).mdname.as_ptr(), mdname) != 0)
            && ecdsa_setup_md(ctx, mdname, ptr::null(), desc) == 0
        {
            return 0;
        }

        (*ctx).flags &= !FLAG_ALLOW_MD;

        if (*ctx).mdctx.is_null() {
            (*ctx).mdctx = EVP_MD_CTX_new();
            if (*ctx).mdctx.is_null() {
                return ecdsa_digest_signverify_init_err(ctx);
            }
        }

        if EVP_DigestInit_ex2((*ctx).mdctx, (*ctx).md, params) == 0 {
            return ecdsa_digest_signverify_init_err(ctx);
        }
    }

    1
}

/// The authority's `error:` arm (`ecdsa_sig.c.in:547-550`), reached from the two failures in
/// [`ecdsa_digest_signverify_init`].
///
/// # Safety
/// `ctx` is the caller's live context.
unsafe fn ecdsa_digest_signverify_init_err(ctx: *mut ProvEcdsaCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        EVP_MD_CTX_free((*ctx).mdctx);
        (*ctx).mdctx = ptr::null_mut();
    }
    0
}

/// `static int ecdsa_digest_sign_init(...)` — `ecdsa_sig.c.in:553-560`.
///
/// # Safety
/// The signature `digest_sign_init` dispatch contract.
unsafe extern "C" fn ecdsa_digest_sign_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vec: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecdsa_digest_signverify_init(
            vctx,
            mdname,
            vec,
            params,
            EVP_PKEY_OP_SIGNMSG,
            c"ECDSA Digest Sign Init".as_ptr(),
        )
    }
}

/// `static int ecdsa_digest_signverify_update(...)` — `ecdsa_sig.c.in:562-575`.
///
/// # Safety
/// The signature `digest_sign/verify_update` dispatch contract.
unsafe extern "C" fn ecdsa_digest_signverify_update(
    vctx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    if ctx.is_null() {
        return 0;
    }
    /* Sigalg implementations shouldn't do `digest_sign`. */
    // SAFETY: `ctx` is the caller's context.
    if unsafe { (*ctx).mdctx }.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is the caller's context and the field read is in bounds.
    if unsafe { (*ctx).flags } & FLAG_SIGALG != 0 {
        return 0;
    }

    // SAFETY: the caller's contract.
    unsafe { ecdsa_signverify_message_update(vctx, data, datalen) }
}

/// `int ecdsa_digest_sign_final(...)` — `ecdsa_sig.c.in:577-594`. The authority's definition is
/// non-`static`, so it is `pub(crate)` here.
///
/// # Safety
/// The signature `digest_sign_final` dispatch contract.
pub(crate) unsafe extern "C" fn ecdsa_digest_sign_final(
    vctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is the caller's context.
    unsafe {
        /* Sigalg implementations shouldn't do `digest_sign`. */
        if (*ctx).flags & FLAG_SIGALG != 0 {
            return 0;
        }

        let ok = ecdsa_sign_message_final(vctx, sig, siglen, sigsize);

        (*ctx).flags |= FLAG_ALLOW_MD;

        ok
    }
}

/// `static int ecdsa_digest_verify_init(...)` — `ecdsa_sig.c.in:596-603`.
///
/// # Safety
/// The signature `digest_verify_init` dispatch contract.
unsafe extern "C" fn ecdsa_digest_verify_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vec: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecdsa_digest_signverify_init(
            vctx,
            mdname,
            vec,
            params,
            EVP_PKEY_OP_VERIFYMSG,
            c"ECDSA Digest Verify Init".as_ptr(),
        )
    }
}

/// `int ecdsa_digest_verify_final(void *vctx, const unsigned char *sig, size_t siglen)` —
/// `ecdsa_sig.c.in:605-620`. The authority's definition is non-`static`, so it is `pub(crate)` here.
///
/// # Safety
/// The signature `digest_verify_final` dispatch contract.
pub(crate) unsafe extern "C" fn ecdsa_digest_verify_final(
    vctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();
    let mut ok = 0;

    // SAFETY: `ctx` is NULL or the caller's live context; the short-circuit leaves the field read
    // unreached when it is NULL.
    if is_running() == 0 || ctx.is_null() || unsafe { (*ctx).mdctx }.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is the caller's context.
    unsafe {
        /* Sigalg implementations shouldn't do `digest_verify`. */
        if (*ctx).flags & FLAG_SIGALG != 0 {
            return 0;
        }

        if ecdsa_verify_set_sig(vctx, sig, siglen) != 0 {
            ok = ecdsa_verify_message_final(vctx);
        }

        (*ctx).flags |= FLAG_ALLOW_MD;

        ok
    }
}

/// `static void ecdsa_freectx(void *vctx)` — `ecdsa_sig.c.in:622-634`.
///
/// # Safety
/// The signature `freectx` dispatch contract.
unsafe extern "C" fn ecdsa_freectx(vctx: *mut c_void) {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is the caller's context and every owned member is released here.
    unsafe {
        EVP_MD_CTX_free((*ctx).mdctx);
        EVP_MD_free((*ctx).md);
        CRYPTO_free((*ctx).propq.cast(), FILE, 628);
        CRYPTO_free((*ctx).sig.cast(), FILE, 629);
        EC_KEY_free((*ctx).ec);
        BN_clear_free((*ctx).kinv);
        BN_clear_free((*ctx).r);
        CRYPTO_free(ctx.cast(), FILE, 633);
    }
}

/// `static void *ecdsa_dupctx(void *vctx)` — `ecdsa_sig.c.in:636-676`.
///
/// # Safety
/// The signature `dupctx` dispatch contract.
unsafe extern "C" fn ecdsa_dupctx(vctx: *mut c_void) -> *mut c_void {
    let srcctx = vctx.cast::<ProvEcdsaCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `srcctx` is the caller's live context; `CRYPTO_memdup` copies it.
    let dstctx = unsafe {
        CRYPTO_memdup(
            srcctx.cast(),
            core::mem::size_of::<ProvEcdsaCtx>(),
            FILE,
            645,
        )
        .cast::<ProvEcdsaCtx>()
    };
    if dstctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: both pointers are live per the contract; the copies are of this call's allocation.
    unsafe {
        (*dstctx).ec = ptr::null_mut();
        (*dstctx).propq = ptr::null_mut();
        (*dstctx).md = ptr::null_mut();
        (*dstctx).mdctx = ptr::null_mut();
        (*dstctx).sig = ptr::null_mut();

        if !(*srcctx).ec.is_null() && EC_KEY_up_ref((*srcctx).ec) == 0 {
            return ecdsa_dupctx_err(dstctx);
        }
        (*dstctx).ec = (*srcctx).ec;

        if !(*srcctx).md.is_null() && EVP_MD_up_ref((*srcctx).md) == 0 {
            return ecdsa_dupctx_err(dstctx);
        }
        (*dstctx).md = (*srcctx).md;

        if !(*srcctx).mdctx.is_null() {
            (*dstctx).mdctx = EVP_MD_CTX_new();
            if (*dstctx).mdctx.is_null()
                || EVP_MD_CTX_copy_ex((*dstctx).mdctx, (*srcctx).mdctx) == 0
            {
                return ecdsa_dupctx_err(dstctx);
            }
        }
        if !(*srcctx).propq.is_null() {
            (*dstctx).propq = CRYPTO_strdup((*srcctx).propq, FILE, 667);
            if (*dstctx).propq.is_null() {
                return ecdsa_dupctx_err(dstctx);
            }
        }
        if !(*srcctx).sig.is_null() {
            (*dstctx).sig =
                CRYPTO_memdup((*srcctx).sig.cast(), (*srcctx).siglen, FILE, 670).cast::<u8>();
            if (*dstctx).sig.is_null() {
                return ecdsa_dupctx_err(dstctx);
            }
        }
    }

    dstctx.cast()
}

/// The authority's `err:` arm (`ecdsa_sig.c.in:673-675`), reached from the five failures in
/// [`ecdsa_dupctx`].
///
/// # Safety
/// `dstctx` is this call's own allocation.
unsafe fn ecdsa_dupctx_err(dstctx: *mut ProvEcdsaCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { ecdsa_freectx(dstctx.cast()) };
    ptr::null_mut()
}

/// `struct ecdsa_get_ctx_params_st` — the `produce_param_decoder` expansion at
/// `ecdsa_sig.c.in:678-691`, generated from the four names. The two `fips`-typed fields are absent
/// because their keys are `# if defined(FIPS_MODULE)`-guarded.
#[derive(Clone, Copy)]
struct GetCtxParams {
    algid: *const OsslParam,
    digest: *const OsslParam,
    nonce: *const OsslParam,
    size: *const OsslParam,
}

/// `ecdsa_get_ctx_params_decoder` — the decoder `produce_param_decoder` emits. A repeated key is
/// `PROV_R_REPEATED_PARAMETER` at the line the generated decoder raised it.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn ecdsa_get_ctx_params_decoder(params: *const OsslParam) -> Option<GetCtxParams> {
    let mut r = GetCtxParams {
        algid: ptr::null(),
        digest: ptr::null(),
        nonce: ptr::null(),
        size: ptr::null(),
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
                        raise_site(&err_sites::PROV_ECDSA_SIG_723);
                        return None;
                    }
                    r.algid = p;
                }
                b"digest-size" => {
                    if !r.size.is_null() {
                        raise_site(&err_sites::PROV_ECDSA_SIG_758);
                        return None;
                    }
                    r.size = p;
                }
                b"digest" => {
                    if !r.digest.is_null() {
                        raise_site(&err_sites::PROV_ECDSA_SIG_767);
                        return None;
                    }
                    r.digest = p;
                }
                b"nonce-type" => {
                    if !r.nonce.is_null() {
                        raise_site(&err_sites::PROV_ECDSA_SIG_796);
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

/// `static const OSSL_PARAM ecdsa_get_ctx_params_list[]` — `ecdsa_sig.c.in:678-691`.
static ECDSA_GET_CTX_PARAMS_LIST: [OsslParam; 5] = [
    param_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID),
    param_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE),
    param_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST),
    param_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE),
    END,
];

/// `static int ecdsa_get_ctx_params(void *vctx, OSSL_PARAM *params)` — `ecdsa_sig.c.in:694-724`.
///
/// # Safety
/// The signature `get_ctx_params` dispatch contract.
unsafe extern "C" fn ecdsa_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let Some(p) = ecdsa_get_ctx_params_decoder(params) else {
            return 0;
        };

        if !p.algid.is_null()
            && OSSL_PARAM_set_octet_string(
                p.algid.cast_mut(),
                if (*ctx).aid_len == 0 {
                    ptr::null()
                } else {
                    (*ctx).aid_buf.as_ptr().cast()
                },
                (*ctx).aid_len,
            ) == 0
        {
            return 0;
        }

        if !p.size.is_null() && OSSL_PARAM_set_size_t(p.size.cast_mut(), (*ctx).mdsize) == 0 {
            return 0;
        }

        if !p.digest.is_null()
            && OSSL_PARAM_set_utf8_string(
                p.digest.cast_mut(),
                if (*ctx).md.is_null() {
                    (*ctx).mdname.as_ptr()
                } else {
                    EVP_MD_get0_name((*ctx).md)
                },
            ) == 0
        {
            return 0;
        }

        if !p.nonce.is_null() && OSSL_PARAM_set_uint(p.nonce.cast_mut(), (*ctx).nonce_type) == 0 {
            return 0;
        }
    }

    1
}

/// `static const OSSL_PARAM *ecdsa_gettable_ctx_params(...)` — `ecdsa_sig.c.in:726-730`.
///
/// # Safety
/// The signature `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn ecdsa_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ECDSA_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `struct ecdsa_all_set_ctx_params_st` — `ecdsa_sig.c.in:732-746`, without its four
/// `FIPS_MODULE`/`ACVP` fields. The two generated set decoders fill different subsets of it and
/// both pass it to [`ecdsa_common_set_ctx_params`].
#[derive(Clone, Copy)]
struct AllSetCtxParams {
    digest: *const OsslParam,
    propq: *const OsslParam,
    size: *const OsslParam,
    nonce: *const OsslParam,
    sig: *const OsslParam,
}

/// `static int ecdsa_common_set_ctx_params(...)` — `ecdsa_sig.c.in:753-774`, without the two
/// `OSSL_FIPS_IND_SET_CTX_FROM_PARAM` calls (literal 1 here) and the `ACVP` `kat` arm.
///
/// # Safety
/// `ctx` is live.
unsafe fn ecdsa_common_set_ctx_params(ctx: *mut ProvEcdsaCtx, p: &AllSetCtxParams) -> c_int {
    // SAFETY: `ctx` is live and `p.nonce` is NULL or a live descriptor.
    unsafe {
        if !p.nonce.is_null()
            && OSSL_PARAM_get_uint(p.nonce, ptr::addr_of_mut!((*ctx).nonce_type)) == 0
        {
            return 0;
        }
    }
    1
}

/// `ecdsa_set_ctx_params_decoder` — the second generated decoder, over the four compiled names of
/// `ecdsa_sig.c.in:781-789`.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn ecdsa_set_ctx_params_decoder(params: *const OsslParam) -> Option<AllSetCtxParams> {
    let mut r = AllSetCtxParams {
        digest: ptr::null(),
        propq: ptr::null(),
        size: ptr::null(),
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
                b"digest-size" => {
                    if !r.size.is_null() {
                        raise_site(&err_sites::PROV_ECDSA_SIG_1001);
                        return None;
                    }
                    r.size = p;
                }
                b"digest" => {
                    if !r.digest.is_null() {
                        raise_site(&err_sites::PROV_ECDSA_SIG_1011);
                        return None;
                    }
                    r.digest = p;
                }
                b"nonce-type" => {
                    if !r.nonce.is_null() {
                        raise_site(&err_sites::PROV_ECDSA_SIG_1059);
                        return None;
                    }
                    r.nonce = p;
                }
                b"properties" => {
                    if !r.propq.is_null() {
                        raise_site(&err_sites::PROV_ECDSA_SIG_1070);
                        return None;
                    }
                    r.propq = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM ecdsa_set_ctx_params_list[]` — `ecdsa_sig.c.in:781-789`.
static ECDSA_SET_CTX_PARAMS_LIST: [OsslParam; 5] = [
    param_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST),
    param_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES),
    param_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE),
    param_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE),
    END,
];

/// `static int ecdsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `ecdsa_sig.c.in:792-825`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn ecdsa_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();
    let mut mdsize: usize = 0;

    // SAFETY: `ctx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let Some(p) = ecdsa_set_ctx_params_decoder(params) else {
            return 0;
        };

        let ret = ecdsa_common_set_ctx_params(ctx, &p);
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
            if ecdsa_setup_md(
                ctx,
                mdname.as_ptr(),
                if p.propq.is_null() {
                    ptr::null()
                } else {
                    mdprops.as_ptr()
                },
                c"ECDSA Set Ctx".as_ptr(),
            ) == 0
            {
                return 0;
            }
        }

        if !p.size.is_null() {
            if OSSL_PARAM_get_size_t(p.size, &mut mdsize) == 0
                || ((*ctx).flags & FLAG_ALLOW_MD == 0 && mdsize != (*ctx).mdsize)
            {
                return 0;
            }
            (*ctx).mdsize = mdsize;
        }
    }
    1
}

/// `static const OSSL_PARAM *ecdsa_settable_ctx_params(...)` — `ecdsa_sig.c.in:827-832`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn ecdsa_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ECDSA_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int ecdsa_get_ctx_md_params(...)` — `ecdsa_sig.c.in:834-842`.
///
/// # Safety
/// The signature `get_ctx_md_params` dispatch contract.
unsafe extern "C" fn ecdsa_get_ctx_md_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if (*ctx).mdctx.is_null() {
            return 0;
        }

        EVP_MD_CTX_get_params((*ctx).mdctx, params)
    }
}

/// `static const OSSL_PARAM *ecdsa_gettable_ctx_md_params(void *vctx)` —
/// `ecdsa_sig.c.in:844-852`.
///
/// # Safety
/// The signature `gettable_ctx_md_params` dispatch contract.
unsafe extern "C" fn ecdsa_gettable_ctx_md_params(vctx: *mut c_void) -> *const OsslParam {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if (*ctx).md.is_null() {
            return ptr::null();
        }

        EVP_MD_gettable_ctx_params((*ctx).md)
    }
}

/// `static int ecdsa_set_ctx_md_params(...)` — `ecdsa_sig.c.in:854-862`.
///
/// # Safety
/// The signature `set_ctx_md_params` dispatch contract.
unsafe extern "C" fn ecdsa_set_ctx_md_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if (*ctx).mdctx.is_null() {
            return 0;
        }

        EVP_MD_CTX_set_params((*ctx).mdctx, params)
    }
}

/// `static const OSSL_PARAM *ecdsa_settable_ctx_md_params(void *vctx)` —
/// `ecdsa_sig.c.in:864-872`.
///
/// # Safety
/// The signature `settable_ctx_md_params` dispatch contract.
unsafe extern "C" fn ecdsa_settable_ctx_md_params(vctx: *mut c_void) -> *const OsslParam {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if (*ctx).md.is_null() {
            return ptr::null();
        }

        EVP_MD_settable_ctx_params((*ctx).md)
    }
}

/// `const OSSL_DISPATCH ossl_ecdsa_signature_functions[]` — `ecdsa_sig.c.in:874-919`.
pub(crate) static ECDSA_SIGNATURE_FUNCTIONS: [OsslDispatch; 22] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: ecdsa_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: ecdsa_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN,
        function: ecdsa_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: ecdsa_verify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY,
        function: ecdsa_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: ecdsa_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: ecdsa_digest_signverify_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: ecdsa_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        function: ecdsa_digest_verify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
        function: ecdsa_digest_signverify_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
        function: ecdsa_digest_verify_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: ecdsa_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: ecdsa_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        function: ecdsa_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        function: ecdsa_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: ecdsa_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: ecdsa_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
        function: ecdsa_get_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
        function: ecdsa_gettable_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
        function: ecdsa_set_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
        function: ecdsa_settable_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static int ecdsa_sigalg_signverify_init(...)` — `ecdsa_sig.c.in:928-965`.
///
/// # Safety
/// The signature init dispatch contract.
unsafe fn ecdsa_sigalg_signverify_init(
    vctx: *mut c_void,
    vec: *mut c_void,
    set_ctx_params: SetCtxParamsFn,
    params: *const OsslParam,
    mdname: *const c_char,
    operation: c_int,
    desc: *const c_char,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if ecdsa_signverify_init(vctx, vec, set_ctx_params, params, operation, desc) == 0 {
            return 0;
        }

        if ecdsa_setup_md(ctx, mdname, ptr::null(), desc) == 0 {
            return 0;
        }

        (*ctx).flags |= FLAG_SIGALG;
        (*ctx).flags &= !FLAG_ALLOW_MD;

        if (*ctx).mdctx.is_null() {
            (*ctx).mdctx = EVP_MD_CTX_new();
            if (*ctx).mdctx.is_null() {
                return ecdsa_digest_signverify_init_err(ctx);
            }
        }

        if EVP_DigestInit_ex2((*ctx).mdctx, (*ctx).md, params) == 0 {
            return ecdsa_digest_signverify_init_err(ctx);
        }
    }

    1
}

/// `static const char **ecdsa_sigalg_query_key_types(void)` — `ecdsa_sig.c.in:967-972`.
unsafe extern "C" fn ecdsa_sigalg_query_key_types() -> *mut *const c_char {
    /// `static const char *keytypes[] = { "EC", NULL }`.
    #[repr(C)]
    struct KeyTypeNames([*const c_char; 2]);

    // SAFETY: the array holds `'static` literals and a NULL terminator; nothing mutates it.
    unsafe impl Sync for KeyTypeNames {}

    static KEYTYPES: KeyTypeNames = KeyTypeNames([c"EC".as_ptr(), ptr::null()]);

    KEYTYPES.0.as_ptr().cast_mut()
}

/// `ecdsa_sigalg_set_ctx_params_decoder` — the third generated decoder, over the two compiled names
/// of `ecdsa_sig.c.in:977-987`.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn ecdsa_sigalg_set_ctx_params_decoder(params: *const OsslParam) -> Option<AllSetCtxParams> {
    let mut r = AllSetCtxParams {
        digest: ptr::null(),
        propq: ptr::null(),
        size: ptr::null(),
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
                b"nonce-type" => {
                    if !r.nonce.is_null() {
                        raise_site(&err_sites::PROV_ECDSA_SIG_1359);
                        return None;
                    }
                    r.nonce = p;
                }
                b"signature" => {
                    if !r.sig.is_null() {
                        raise_site(&err_sites::PROV_ECDSA_SIG_1370);
                        return None;
                    }
                    r.sig = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM ecdsa_sigalg_set_ctx_params_list[]` — `ecdsa_sig.c.in:977-987`.
static ECDSA_SIGALG_SET_CTX_PARAMS_LIST: [OsslParam; 3] = [
    param_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE),
    param_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE),
    END,
];

/// `static const OSSL_PARAM *ecdsa_sigalg_settable_ctx_params(...)` — `ecdsa_sig.c.in:990-996`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn ecdsa_sigalg_settable_ctx_params(
    vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is NULL or the caller's context.
    unsafe {
        if !ctx.is_null() && (*ctx).operation == EVP_PKEY_OP_VERIFYMSG {
            return ECDSA_SIGALG_SET_CTX_PARAMS_LIST.as_ptr();
        }
    }
    ptr::null()
}

/// `static int ecdsa_sigalg_set_ctx_params(...)` — `ecdsa_sig.c.in:998-1027`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn ecdsa_sigalg_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<ProvEcdsaCtx>();

    // SAFETY: `ctx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let Some(p) = ecdsa_sigalg_set_ctx_params_decoder(params) else {
            return 0;
        };

        let ret = ecdsa_common_set_ctx_params(ctx, &p);
        if ret <= 0 {
            return ret;
        }

        if (*ctx).operation == EVP_PKEY_OP_VERIFYMSG && !p.sig.is_null() {
            CRYPTO_free((*ctx).sig.cast(), FILE, 1011);
            (*ctx).sig = ptr::null_mut();
            (*ctx).siglen = 0;
            let mut sig: *mut c_void = ptr::null_mut();
            if OSSL_PARAM_get_octet_string(p.sig, &mut sig, 0, ptr::addr_of_mut!((*ctx).siglen))
                == 0
            {
                return 0;
            }
            (*ctx).sig = sig.cast::<u8>();
            /* The signature must not be empty. */
            if (*ctx).siglen == 0 {
                CRYPTO_free((*ctx).sig.cast(), FILE, 1019);
                (*ctx).sig = ptr::null_mut();
                return 0;
            }
        }
    }
    1
}

/// One of the nine `ECDSA-<MD>` sigalgs' four init wrappers
/// (`ecdsa_sig.c.in:1029-1088`'s `IMPL_ECDSA_SIGALG`, whose bodies differ only in the digest name,
/// the operation and the description).
macro_rules! ecdsa_sigalg_init {
    ($fn_name:ident, $md:literal, $op:expr, $desc:literal) => {
        unsafe extern "C" fn $fn_name(
            vctx: *mut c_void,
            vec: *mut c_void,
            params: *const OsslParam,
        ) -> c_int {
            // SAFETY: the caller's contract.
            unsafe {
                ecdsa_sigalg_signverify_init(
                    vctx,
                    vec,
                    ecdsa_sigalg_set_ctx_params,
                    params,
                    $md.as_ptr(),
                    $op,
                    $desc.as_ptr(),
                )
            }
        }
    };
}

ecdsa_sigalg_init!(
    ecdsa_sha1_sign_init,
    c"SHA1",
    EVP_PKEY_OP_SIGN,
    c"ECDSA-SHA1 Sign Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha1_sign_message_init,
    c"SHA1",
    EVP_PKEY_OP_SIGNMSG,
    c"ECDSA-SHA1 Sign Message Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha1_verify_init,
    c"SHA1",
    EVP_PKEY_OP_VERIFY,
    c"ECDSA-SHA1 Verify Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha1_verify_message_init,
    c"SHA1",
    EVP_PKEY_OP_VERIFYMSG,
    c"ECDSA-SHA1 Verify Message Init"
);

ecdsa_sigalg_init!(
    ecdsa_sha224_sign_init,
    c"SHA2-224",
    EVP_PKEY_OP_SIGN,
    c"ECDSA-SHA2-224 Sign Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha224_sign_message_init,
    c"SHA2-224",
    EVP_PKEY_OP_SIGNMSG,
    c"ECDSA-SHA2-224 Sign Message Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha224_verify_init,
    c"SHA2-224",
    EVP_PKEY_OP_VERIFY,
    c"ECDSA-SHA2-224 Verify Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha224_verify_message_init,
    c"SHA2-224",
    EVP_PKEY_OP_VERIFYMSG,
    c"ECDSA-SHA2-224 Verify Message Init"
);

ecdsa_sigalg_init!(
    ecdsa_sha256_sign_init,
    c"SHA2-256",
    EVP_PKEY_OP_SIGN,
    c"ECDSA-SHA2-256 Sign Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha256_sign_message_init,
    c"SHA2-256",
    EVP_PKEY_OP_SIGNMSG,
    c"ECDSA-SHA2-256 Sign Message Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha256_verify_init,
    c"SHA2-256",
    EVP_PKEY_OP_VERIFY,
    c"ECDSA-SHA2-256 Verify Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha256_verify_message_init,
    c"SHA2-256",
    EVP_PKEY_OP_VERIFYMSG,
    c"ECDSA-SHA2-256 Verify Message Init"
);

ecdsa_sigalg_init!(
    ecdsa_sha384_sign_init,
    c"SHA2-384",
    EVP_PKEY_OP_SIGN,
    c"ECDSA-SHA2-384 Sign Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha384_sign_message_init,
    c"SHA2-384",
    EVP_PKEY_OP_SIGNMSG,
    c"ECDSA-SHA2-384 Sign Message Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha384_verify_init,
    c"SHA2-384",
    EVP_PKEY_OP_VERIFY,
    c"ECDSA-SHA2-384 Verify Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha384_verify_message_init,
    c"SHA2-384",
    EVP_PKEY_OP_VERIFYMSG,
    c"ECDSA-SHA2-384 Verify Message Init"
);

ecdsa_sigalg_init!(
    ecdsa_sha512_sign_init,
    c"SHA2-512",
    EVP_PKEY_OP_SIGN,
    c"ECDSA-SHA2-512 Sign Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha512_sign_message_init,
    c"SHA2-512",
    EVP_PKEY_OP_SIGNMSG,
    c"ECDSA-SHA2-512 Sign Message Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha512_verify_init,
    c"SHA2-512",
    EVP_PKEY_OP_VERIFY,
    c"ECDSA-SHA2-512 Verify Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha512_verify_message_init,
    c"SHA2-512",
    EVP_PKEY_OP_VERIFYMSG,
    c"ECDSA-SHA2-512 Verify Message Init"
);

ecdsa_sigalg_init!(
    ecdsa_sha3_224_sign_init,
    c"SHA3-224",
    EVP_PKEY_OP_SIGN,
    c"ECDSA-SHA3-224 Sign Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_224_sign_message_init,
    c"SHA3-224",
    EVP_PKEY_OP_SIGNMSG,
    c"ECDSA-SHA3-224 Sign Message Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_224_verify_init,
    c"SHA3-224",
    EVP_PKEY_OP_VERIFY,
    c"ECDSA-SHA3-224 Verify Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_224_verify_message_init,
    c"SHA3-224",
    EVP_PKEY_OP_VERIFYMSG,
    c"ECDSA-SHA3-224 Verify Message Init"
);

ecdsa_sigalg_init!(
    ecdsa_sha3_256_sign_init,
    c"SHA3-256",
    EVP_PKEY_OP_SIGN,
    c"ECDSA-SHA3-256 Sign Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_256_sign_message_init,
    c"SHA3-256",
    EVP_PKEY_OP_SIGNMSG,
    c"ECDSA-SHA3-256 Sign Message Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_256_verify_init,
    c"SHA3-256",
    EVP_PKEY_OP_VERIFY,
    c"ECDSA-SHA3-256 Verify Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_256_verify_message_init,
    c"SHA3-256",
    EVP_PKEY_OP_VERIFYMSG,
    c"ECDSA-SHA3-256 Verify Message Init"
);

ecdsa_sigalg_init!(
    ecdsa_sha3_384_sign_init,
    c"SHA3-384",
    EVP_PKEY_OP_SIGN,
    c"ECDSA-SHA3-384 Sign Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_384_sign_message_init,
    c"SHA3-384",
    EVP_PKEY_OP_SIGNMSG,
    c"ECDSA-SHA3-384 Sign Message Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_384_verify_init,
    c"SHA3-384",
    EVP_PKEY_OP_VERIFY,
    c"ECDSA-SHA3-384 Verify Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_384_verify_message_init,
    c"SHA3-384",
    EVP_PKEY_OP_VERIFYMSG,
    c"ECDSA-SHA3-384 Verify Message Init"
);

ecdsa_sigalg_init!(
    ecdsa_sha3_512_sign_init,
    c"SHA3-512",
    EVP_PKEY_OP_SIGN,
    c"ECDSA-SHA3-512 Sign Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_512_sign_message_init,
    c"SHA3-512",
    EVP_PKEY_OP_SIGNMSG,
    c"ECDSA-SHA3-512 Sign Message Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_512_verify_init,
    c"SHA3-512",
    EVP_PKEY_OP_VERIFY,
    c"ECDSA-SHA3-512 Verify Init"
);
ecdsa_sigalg_init!(
    ecdsa_sha3_512_verify_message_init,
    c"SHA3-512",
    EVP_PKEY_OP_VERIFYMSG,
    c"ECDSA-SHA3-512 Verify Message Init"
);

/// One of the nine `ECDSA-<MD>` sigalgs' dispatch table (`ecdsa_sig.c.in:1092-1129`'s
/// `IMPL_ECDSA_SIGALG` tail, whose rows differ only in the four init slots).
macro_rules! ecdsa_sigalg_table {
    ($table:ident, $sign_init:ident, $sign_message_init:ident, $verify_init:ident, $verify_message_init:ident) => {
        pub(crate) static $table: [OsslDispatch; 19] = [
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
                function: ecdsa_newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
                function: $sign_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN,
                function: ecdsa_sign as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
                function: $sign_message_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
                function: ecdsa_signverify_message_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
                function: ecdsa_sign_message_final as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
                function: $verify_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY,
                function: ecdsa_verify as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
                function: $verify_message_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
                function: ecdsa_signverify_message_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
                function: ecdsa_verify_message_final as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_FREECTX,
                function: ecdsa_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
                function: ecdsa_dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
                function: ecdsa_sigalg_query_key_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
                function: ecdsa_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
                function: ecdsa_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
                function: ecdsa_sigalg_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
                function: ecdsa_sigalg_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

ecdsa_sigalg_table!(
    ECDSA_SHA1_SIGNATURE_FUNCTIONS,
    ecdsa_sha1_sign_init,
    ecdsa_sha1_sign_message_init,
    ecdsa_sha1_verify_init,
    ecdsa_sha1_verify_message_init
);
ecdsa_sigalg_table!(
    ECDSA_SHA224_SIGNATURE_FUNCTIONS,
    ecdsa_sha224_sign_init,
    ecdsa_sha224_sign_message_init,
    ecdsa_sha224_verify_init,
    ecdsa_sha224_verify_message_init
);
ecdsa_sigalg_table!(
    ECDSA_SHA256_SIGNATURE_FUNCTIONS,
    ecdsa_sha256_sign_init,
    ecdsa_sha256_sign_message_init,
    ecdsa_sha256_verify_init,
    ecdsa_sha256_verify_message_init
);
ecdsa_sigalg_table!(
    ECDSA_SHA384_SIGNATURE_FUNCTIONS,
    ecdsa_sha384_sign_init,
    ecdsa_sha384_sign_message_init,
    ecdsa_sha384_verify_init,
    ecdsa_sha384_verify_message_init
);
ecdsa_sigalg_table!(
    ECDSA_SHA512_SIGNATURE_FUNCTIONS,
    ecdsa_sha512_sign_init,
    ecdsa_sha512_sign_message_init,
    ecdsa_sha512_verify_init,
    ecdsa_sha512_verify_message_init
);
ecdsa_sigalg_table!(
    ECDSA_SHA3_224_SIGNATURE_FUNCTIONS,
    ecdsa_sha3_224_sign_init,
    ecdsa_sha3_224_sign_message_init,
    ecdsa_sha3_224_verify_init,
    ecdsa_sha3_224_verify_message_init
);
ecdsa_sigalg_table!(
    ECDSA_SHA3_256_SIGNATURE_FUNCTIONS,
    ecdsa_sha3_256_sign_init,
    ecdsa_sha3_256_sign_message_init,
    ecdsa_sha3_256_verify_init,
    ecdsa_sha3_256_verify_message_init
);
ecdsa_sigalg_table!(
    ECDSA_SHA3_384_SIGNATURE_FUNCTIONS,
    ecdsa_sha3_384_sign_init,
    ecdsa_sha3_384_sign_message_init,
    ecdsa_sha3_384_verify_init,
    ecdsa_sha3_384_verify_message_init
);
ecdsa_sigalg_table!(
    ECDSA_SHA3_512_SIGNATURE_FUNCTIONS,
    ecdsa_sha3_512_sign_init,
    ecdsa_sha3_512_sign_message_init,
    ecdsa_sha3_512_verify_init,
    ecdsa_sha3_512_verify_message_init
);
