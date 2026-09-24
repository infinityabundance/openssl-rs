//! `crypto/rsa/rsa_ameth.c` — the whole unit: `ossl_rsa_asn1_meths[2]`, `ossl_rsa_pss_asn1_meth`
//! and every callback and helper they name.
//!
//! D341 measured this as the largest of the five object-bearing units (1,053 lines, 36 functions)
//! and the one whose PSS machinery reaches furthest: `rsa_int_export_to`/`rsa_int_import_from`
//! build an `RSA_PSS_PARAMS_30` out of the old `RSA_PSS_PARAMS`, and `rsa_item_sign`/
//! `rsa_item_verify`/`rsa_sig_info_set` are the signature callbacks the table carries. Every
//! callee it names landed in D348/D349/D351; the unit's own `ossl_rsa_pss_params_create`,
//! `ossl_rsa_ctx_to_pss_string`, `ossl_rsa_pss_to_ctx` and `ossl_rsa_pss_get_param` are the four
//! `crypto/rsa.h` internals it **defines** and they are transcribed with it.
//!
//! Three of the authority's own defects are carried verbatim and named at the site: `rsa_int_import_from`
//! raises with `ERR_LIB_DH` where every other RSA site uses `ERR_LIB_RSA` (`:862` — the generated
//! `RSA_AMETH_862` records `lib: 5`, which is what a caller's drained error says); the second
//! `strcmp` in `crypto/evp/p_lib.c`'s EC helper has no `== 0` (not this unit); and `rsa_pss_param_print`
//! writes its two `BIO_puts` return values unchecked, which is the authority's.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::asn_pack::ASN1_item_pack;
use crate::asn1::layout::{Asn1Pctx, Asn1String, V_ASN1_NULL, V_ASN1_SEQUENCE, V_ASN1_UNDEF};
use crate::asn1::p8_pkey::PKCS8_pkey_set0;
use crate::asn1::prim::ASN1_INTEGER_set;
use crate::asn1::string::{ASN1_INTEGER_new, ASN1_STRING_dup, ASN1_STRING_free};
use crate::asn1::t_pkey::ASN1_bn_print;
use crate::asn1::text::{i2a_ASN1_INTEGER, i2a_ASN1_OBJECT};
use crate::asn1::x_algor::{
    d2i_X509_ALGOR, ossl_x509_algor_md_to_mgf1, ossl_x509_algor_mgf1_decode,
    ossl_x509_algor_new_from_md, X509Algor,
};
use crate::bn::bignum::BigNum;
use crate::evp::digest::{
    EVP_DigestVerifyInit, EVP_MD_CTX_get_pkey_ctx, EVP_MD_get_size, EVP_MD_get_type, EvpMd,
    EvpMdCtx,
};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::pkey::{
    EVP_PKEY_assign, EVP_PKEY_get_bits, EVP_PKEY_get_size, EvpPkey, ASN1_PKEY_CTRL_DEFAULT_MD_NID,
    ASN1_PKEY_SIGPARAM_NULL,
};
use crate::evp::pkey_asn1::EvpPkeyAsn1Method;
use crate::evp::pkey_ctx::EVP_PKEY_RSA;
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_get0_pkey, EVP_PKEY_CTX_get_params, EVP_PKEY_CTX_get_signature_md, EvpPkeyCtx,
    RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_AUTO, RSA_PSS_SALTLEN_DIGEST,
    RSA_PSS_SALTLEN_MAX,
};
use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OsslParam};
use crate::rsa::asn1::{
    d2i_RSAPrivateKey, d2i_RSAPublicKey, i2d_RSAPrivateKey, i2d_RSAPublicKey, RSA_PSS_PARAMS_free,
    RSA_PSS_PARAMS_it, RSA_PSS_PARAMS_new,
};
use crate::rsa::backend::{
    ossl_rsa_dup, ossl_rsa_fromdata, ossl_rsa_key_from_pkcs8, ossl_rsa_param_decode,
    ossl_rsa_pss_decode, ossl_rsa_pss_get_param_unverified, ossl_rsa_pss_params_30_fromdata,
    ossl_rsa_pss_params_30_todata, ossl_rsa_todata,
};
use crate::rsa::ctrl::{
    EVP_PKEY_CTX_get_rsa_mgf1_md, EVP_PKEY_CTX_get_rsa_padding, EVP_PKEY_CTX_get_rsa_pss_saltlen,
    EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_CTX_set_rsa_pss_saltlen,
};
use crate::rsa::object::{
    ossl_rsa_new_with_ctx, RSA_clear_flags, RSA_flags, RSA_free, RSA_security_bits, RSA_set_flags,
    RSA_size, RSA_test_flags, RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA, RSA_FLAG_TYPE_RSASSAPSS,
};
use crate::rsa::pss::{
    ossl_rsa_pss_params_30_hashalg, ossl_rsa_pss_params_30_is_unrestricted,
    ossl_rsa_pss_params_30_maskgenhashalg, ossl_rsa_pss_params_30_saltlen,
    ossl_rsa_pss_params_30_set_defaults, ossl_rsa_pss_params_30_set_hashalg,
    ossl_rsa_pss_params_30_set_maskgenhashalg, ossl_rsa_pss_params_30_set_saltlen,
};
use crate::rsa::RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
use crate::rsa::{
    RSA_check_key_ex, Rsa, RsaPrimeInfo, RsaPssParams, RsaPssParams30, RSA_METHOD_FLAG_NO_CHECK,
};
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_clear_free;
use crate::runtime::obj::NID_rsassaPss;
use crate::runtime::obj::{
    NID_md5, NID_md5_sha1, NID_sha1, NID_sha256, NID_sha384, NID_sha512, OBJ_nid2obj, OBJ_obj2nid,
};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::t_x509::X509_signature_dump;
use crate::x509::x509_set::{X509SigInfo, X509_SIG_INFO_set};
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_get0_param, X509_PUBKEY_set0_param};

/// `EVP_PKEY_RSA_PSS` = `NID_rsassaPss` — `include/openssl/evp.h:65`.
const EVP_PKEY_RSA_PSS: c_int = NID_rsassaPss;
/// `EVP_PKEY_RSA2` = `NID_rsa` — `include/openssl/evp.h:64`.
const EVP_PKEY_RSA2: c_int = crate::runtime::obj::NID_rsa;
/// `X509_SIG_INFO_TLS` — `include/openssl/x509.h.in:68`.
/// `X509_SIG_INFO_TLS` — `include/openssl/x509.h.in:68`. `pub(crate)` since D372: `crypto/ec/ecx_meth.c`'s
/// `ecd_sig_info_set25519`/`_448` are the readers after this unit's own.
pub(crate) const X509_SIG_INFO_TLS: u32 = 0x2;
/// `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` — `include/openssl/core_names.h`.
const OSSL_SIGNATURE_PARAM_ALGORITHM_ID: *const c_char = c"algorithm-id".as_ptr();
/// The authority's translation unit, for the `OPENSSL_clear_free` site below.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_ameth.c".as_ptr();

/// `#define pkey_is_pss(pkey)` — `crypto/rsa/rsa_local.h:150`,
/// `(pkey->ameth->pkey_id == EVP_PKEY_RSA_PSS)`.
///
/// # Safety
/// `pkey` is live.
unsafe fn pkey_is_pss(pkey: *const EvpPkey) -> bool {
    // SAFETY: `pkey` is live per the contract.
    unsafe {
        (*pkey)
            .ameth
            .as_ref()
            .is_some_and(|m| m.pkey_id == EVP_PKEY_RSA_PSS)
    }
}

/// `#define EVP_get_digestbynid(a)` — `include/openssl/evp.h`, the macro
/// `EVP_get_digestbyname(OBJ_nid2sn(a))`. The crate's `EVP_get_digestbyname` answers NULL for
/// every built-in name until Phase 13 populates the legacy `OBJ_NAME` table (`src/evp/legacy_evp.rs`),
/// so this answers NULL for every NID today — the same recorded deferral `src/asn1/x_algor.rs`
/// carries.
///
/// # Safety
/// `nid` is any integer.
unsafe fn evp_get_digestbynid(nid: c_int) -> *const EvpMd {
    // SAFETY: `OBJ_nid2sn` answers a static string or NULL and `EVP_get_digestbyname` accepts both.
    unsafe { EVP_get_digestbyname(crate::runtime::obj::OBJ_nid2sn(nid)) }
}

/// `static int rsa_param_encode(const EVP_PKEY *pkey, ASN1_STRING **pstr, int *pstrtype)` —
/// `crypto/rsa/rsa_ameth.c:29-51`.
///
/// # Safety
/// `pkey` is live; both out-parameters are writable.
unsafe fn rsa_param_encode(
    pkey: *const EvpPkey,
    pstr: *mut *mut Asn1String,
    pstrtype: *mut c_int,
) -> c_int {
    // SAFETY: `pkey` is live.
    let rsa = unsafe { (*pkey).pkey.cast::<Rsa>() };

    // SAFETY: `pstr` is writable per the contract.
    unsafe { *pstr = ptr::null_mut() };
    /* If RSA it's just NULL type */
    // SAFETY: `rsa` is live.
    if unsafe { RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) } != RSA_FLAG_TYPE_RSASSAPSS {
        // SAFETY: `pstrtype` is writable per the contract.
        unsafe { *pstrtype = V_ASN1_NULL };
        return 1;
    }
    /* If no PSS parameters we omit parameters entirely */
    // SAFETY: `rsa` is live.
    if unsafe { (*rsa).pss }.is_null() {
        // SAFETY: `pstrtype` is writable per the contract.
        unsafe { *pstrtype = V_ASN1_UNDEF };
        return 1;
    }
    /* Encode PSS parameters */
    // SAFETY: `rsa` is live and `pstr` is writable.
    if unsafe { ASN1_item_pack((*rsa).pss.cast(), RSA_PSS_PARAMS_it(), pstr) }.is_null() {
        return 0;
    }

    // SAFETY: `pstrtype` is writable per the contract.
    unsafe { *pstrtype = V_ASN1_SEQUENCE };
    1
}

/// `static int rsa_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)` —
/// `crypto/rsa/rsa_ameth.c:53-74`.
///
/// # Safety
/// `pk` and `pkey` are live.
unsafe extern "C" fn rsa_pub_encode(pk: *mut X509Pubkey, pkey: *const EvpPkey) -> c_int {
    let mut penc: *mut c_uchar = ptr::null_mut();
    let mut str_: *mut Asn1String = ptr::null_mut();
    let mut strtype: c_int = 0;

    // SAFETY: `pkey` is live and both out-parameters are live locals.
    if unsafe { rsa_param_encode(pkey, &mut str_, &mut strtype) } == 0 {
        return 0;
    }
    // SAFETY: `pkey` is live and `penc` is a live out-parameter.
    let penclen = unsafe { i2d_RSAPublicKey((*pkey).pkey.cast::<Rsa>(), &mut penc) };
    if penclen <= 0 {
        // SAFETY: `str_` is live.
        unsafe { ASN1_STRING_free(str_) };
        return 0;
    }
    // SAFETY: `pk` is live and `str_`/`penc` are the objects the setter takes ownership of.
    if unsafe {
        X509_PUBKEY_set0_param(
            pk,
            OBJ_nid2obj((*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id)),
            strtype,
            str_.cast(),
            penc,
            penclen,
        )
    } != 0
    {
        return 1;
    }

    // SAFETY: both are live.
    unsafe {
        crate::runtime::mem::CRYPTO_free(penc.cast(), FILE, 71);
        ASN1_STRING_free(str_);
    }
    0
}

/// `static int rsa_pub_decode(EVP_PKEY *pkey, const X509_PUBKEY *pubkey)` —
/// `crypto/rsa/rsa_ameth.c:76-110`.
///
/// # Safety
/// `pkey` and `pubkey` are live.
unsafe extern "C" fn rsa_pub_decode(pkey: *mut EvpPkey, pubkey: *const X509Pubkey) -> c_int {
    let mut p: *const c_uchar = ptr::null();
    let mut pklen: c_int = 0;
    let mut alg: *mut X509Algor = ptr::null_mut();

    // SAFETY: `pubkey` is live and the three out-parameters are live locals.
    if unsafe { X509_PUBKEY_get0_param(ptr::null_mut(), &mut p, &mut pklen, &mut alg, pubkey) } == 0
    {
        return 0;
    }
    // SAFETY: `p` is the public-key octets, `pklen` bounds them, and the first argument is NULL.
    let rsa = unsafe { d2i_RSAPublicKey(ptr::null_mut(), &mut p, pklen as c_long) };
    if rsa.is_null() {
        return 0;
    }
    // SAFETY: `rsa` is live and `alg` is live.
    if unsafe { ossl_rsa_param_decode(rsa, alg) } == 0 {
        // SAFETY: `rsa` is live.
        unsafe { RSA_free(rsa) };
        return 0;
    }

    // SAFETY: `rsa` is live.
    unsafe { RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK) };
    // SAFETY: `pkey` is live.
    match unsafe { (*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id) } {
        EVP_PKEY_RSA => {
            // SAFETY: `rsa` is live.
            unsafe { RSA_set_flags(rsa, RSA_FLAG_TYPE_RSA) };
        }
        EVP_PKEY_RSA_PSS => {
            // SAFETY: `rsa` is live.
            unsafe { RSA_set_flags(rsa, RSA_FLAG_TYPE_RSASSAPSS) };
        }
        _ => { /* Leave the type bits zero */ }
    }

    // SAFETY: `pkey` is live.
    if unsafe {
        EVP_PKEY_assign(
            pkey,
            (*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id),
            rsa.cast(),
        )
    } == 0
    {
        // SAFETY: `rsa` is live.
        unsafe { RSA_free(rsa) };
        return 0;
    }
    1
}

/// `static int rsa_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)` —
/// `crypto/rsa/rsa_ameth.c:112-127`.
///
/// # Safety
/// `a` and `b` are live.
unsafe extern "C" fn rsa_pub_cmp(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    /* Don't check the public/private key, this is mostly for smart cards. */
    // SAFETY: both keys are live.
    if unsafe { RSA_flags((*a).pkey.cast::<Rsa>()) } & RSA_METHOD_FLAG_NO_CHECK != 0
        // SAFETY: both keys are live.
        || unsafe { RSA_flags((*b).pkey.cast::<Rsa>()) } & RSA_METHOD_FLAG_NO_CHECK != 0
    {
        return 1;
    }

    // SAFETY: both keys are live.
    if unsafe {
        crate::bn::arith::BN_cmp((*(*b).pkey.cast::<Rsa>()).n, (*(*a).pkey.cast::<Rsa>()).n) != 0
            || crate::bn::arith::BN_cmp((*(*b).pkey.cast::<Rsa>()).e, (*(*a).pkey.cast::<Rsa>()).e)
                != 0
    } {
        return 0;
    }
    1
}

/// `static int old_rsa_priv_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen)` —
/// `crypto/rsa/rsa_ameth.c:129-138`.
///
/// # Safety
/// `pkey` is live; `pder` is readable for `derlen` bytes.
unsafe extern "C" fn old_rsa_priv_decode(
    pkey: *mut EvpPkey,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: the caller's contract; the first argument is the authority's NULL.
    let rsa = unsafe { d2i_RSAPrivateKey(ptr::null_mut(), pder, derlen as c_long) };
    if rsa.is_null() {
        return 0;
    }
    // SAFETY: `pkey` and `rsa` are live.
    unsafe {
        EVP_PKEY_assign(
            pkey,
            (*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id),
            rsa.cast(),
        );
    }
    1
}

/// `static int old_rsa_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)` —
/// `crypto/rsa/rsa_ameth.c:140-143`.
///
/// # Safety
/// `pkey` is live; `pder` is a live out-parameter.
unsafe extern "C" fn old_rsa_priv_encode(pkey: *const EvpPkey, pder: *mut *mut c_uchar) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { i2d_RSAPrivateKey((*pkey).pkey.cast::<Rsa>(), pder) }
}

/// `static int rsa_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)` —
/// `crypto/rsa/rsa_ameth.c:145-171`.
///
/// # Safety
/// `p8` and `pkey` are live.
unsafe extern "C" fn rsa_priv_encode(
    p8: *mut crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
    pkey: *const EvpPkey,
) -> c_int {
    let mut rk: *mut c_uchar = ptr::null_mut();
    let mut str_: *mut Asn1String = ptr::null_mut();
    let mut strtype: c_int = 0;

    // SAFETY: `pkey` is live and both out-parameters are live locals.
    if unsafe { rsa_param_encode(pkey, &mut str_, &mut strtype) } == 0 {
        return 0;
    }
    // SAFETY: `pkey` is live and `rk` is a live out-parameter.
    let rklen = unsafe { i2d_RSAPrivateKey((*pkey).pkey.cast::<Rsa>(), &mut rk) };

    if rklen <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_AMETH_157) };
        // SAFETY: `str_` is live.
        unsafe { ASN1_STRING_free(str_) };
        return 0;
    }

    // SAFETY: `p8` is live and `str_`/`rk` are the objects the setter takes ownership of.
    if unsafe {
        PKCS8_pkey_set0(
            p8,
            OBJ_nid2obj((*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id)),
            0,
            strtype,
            str_.cast(),
            rk,
            rklen,
        )
    } == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_AMETH_164) };
        // SAFETY: both are live.
        unsafe {
            ASN1_STRING_free(str_);
            CRYPTO_clear_free(rk.cast(), rklen as usize, FILE, 166);
        }
        return 0;
    }

    1
}

/// `static int rsa_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)` —
/// `crypto/rsa/rsa_ameth.c:173-183`.
///
/// # Safety
/// `pkey` and `p8` are live.
unsafe extern "C" fn rsa_priv_decode(
    pkey: *mut EvpPkey,
    p8: *const crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
) -> c_int {
    // SAFETY: `p8` is live; the two trailing arguments are the authority's NULLs.
    let rsa = unsafe { ossl_rsa_key_from_pkcs8(p8, ptr::null_mut(), ptr::null()) };

    if !rsa.is_null() {
        // SAFETY: `pkey` and `rsa` are live.
        unsafe {
            EVP_PKEY_assign(
                pkey,
                (*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id),
                rsa.cast(),
            );
        }
        return 1;
    }
    0
}

/// `static int int_rsa_size(const EVP_PKEY *pkey)` — `crypto/rsa/rsa_ameth.c:185-188`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn int_rsa_size(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { RSA_size((*pkey).pkey.cast::<Rsa>()) }
}

/// `static int rsa_bits(const EVP_PKEY *pkey)` — `crypto/rsa/rsa_ameth.c:190-193`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn rsa_bits(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { crate::bn::bignum::BN_num_bits((*(*pkey).pkey.cast::<Rsa>()).n) }
}

/// `static int rsa_security_bits(const EVP_PKEY *pkey)` — `crypto/rsa/rsa_ameth.c:195-198`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn rsa_security_bits(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { RSA_security_bits((*pkey).pkey.cast::<Rsa>()) }
}

/// `static void int_rsa_free(EVP_PKEY *pkey)` — `crypto/rsa/rsa_ameth.c:200-203`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn int_rsa_free(pkey: *mut EvpPkey) {
    // SAFETY: `pkey` is live.
    unsafe { RSA_free((*pkey).pkey.cast::<Rsa>()) };
}

/// `static int rsa_pss_param_print(BIO *bp, int pss_key, RSA_PSS_PARAMS *pss, int indent)` —
/// `crypto/rsa/rsa_ameth.c:205-297`.
///
/// # Safety
/// `bp` is live; `pss` is NULL or live.
unsafe fn rsa_pss_param_print(
    bp: *mut Bio,
    pss_key: c_int,
    pss: *mut RsaPssParams,
    indent: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut mask_hash: *mut X509Algor = ptr::null_mut();

        if BIO_indent(bp, indent, 128) == 0 {
            return 0;
        }
        if pss_key != 0 {
            if pss.is_null() {
                if BIO_puts(bp, c"No PSS parameter restrictions\n".as_ptr()) <= 0 {
                    return 0;
                }
                return 1;
            } else if BIO_puts(bp, c"PSS parameter restrictions:".as_ptr()) <= 0 {
                return 0;
            }
        } else if pss.is_null() {
            if BIO_puts(bp, c"(INVALID PSS PARAMETERS)\n".as_ptr()) <= 0 {
                return 0;
            }
            return 1;
        }
        if BIO_puts(bp, c"\n".as_ptr()) <= 0 {
            return 0;
        }
        let indent = if pss_key != 0 { indent + 2 } else { indent };
        if BIO_indent(bp, indent, 128) == 0 {
            return 0;
        }
        if BIO_puts(bp, c"Hash Algorithm: ".as_ptr()) <= 0 {
            return 0;
        }

        if !(*pss).hash_algorithm.is_null() {
            if i2a_ASN1_OBJECT(bp, (*(*pss).hash_algorithm).algorithm as *const _) <= 0 {
                return 0;
            }
        } else if BIO_puts(bp, c"sha1 (default)".as_ptr()) <= 0 {
            return 0;
        }

        if BIO_puts(bp, c"\n".as_ptr()) <= 0 {
            return 0;
        }

        if BIO_indent(bp, indent, 128) == 0 {
            return 0;
        }

        if BIO_puts(bp, c"Mask Algorithm: ".as_ptr()) <= 0 {
            return 0;
        }
        if !(*pss).mask_gen_algorithm.is_null() {
            if i2a_ASN1_OBJECT(bp, (*(*pss).mask_gen_algorithm).algorithm as *const _) <= 0 {
                return 0;
            }
            if BIO_puts(bp, c" with ".as_ptr()) <= 0 {
                return 0;
            }
            mask_hash = ossl_x509_algor_mgf1_decode((*pss).mask_gen_algorithm);
            if !mask_hash.is_null() {
                if i2a_ASN1_OBJECT(bp, (*mask_hash).algorithm as *const _) <= 0 {
                    return 0;
                }
            } else if BIO_puts(bp, c"INVALID".as_ptr()) <= 0 {
                return 0;
            }
        } else if BIO_puts(bp, c"mgf1 with sha1 (default)".as_ptr()) <= 0 {
            return 0;
        }
        BIO_puts(bp, c"\n".as_ptr());

        if BIO_indent(bp, indent, 128) == 0 {
            return 0;
        }
        if BIO_printf(
            bp,
            c"%s Salt Length: 0x".as_ptr(),
            if pss_key != 0 {
                c"Minimum".as_ptr()
            } else {
                c"".as_ptr()
            },
        ) <= 0
        {
            return 0;
        }
        if !(*pss).salt_length.is_null() {
            if i2a_ASN1_INTEGER(bp, (*pss).salt_length) <= 0 {
                return 0;
            }
        } else if BIO_puts(bp, c"14 (default)".as_ptr()) <= 0 {
            return 0;
        }
        BIO_puts(bp, c"\n".as_ptr());

        if BIO_indent(bp, indent, 128) == 0 {
            return 0;
        }
        if BIO_puts(bp, c"Trailer Field: 0x".as_ptr()) <= 0 {
            return 0;
        }
        if !(*pss).trailer_field.is_null() {
            if i2a_ASN1_INTEGER(bp, (*pss).trailer_field) <= 0 {
                return 0;
            }
        } else if BIO_puts(bp, c"01 (default)".as_ptr()) <= 0 {
            return 0;
        }
        BIO_puts(bp, c"\n".as_ptr());

        let rv = 1;

        x509_algor_free_local(mask_hash);
        rv
    }
}

/// `X509_ALGOR_free` — `crypto/asn1/x_algor.c`, re-exported for the local binding below.
unsafe fn x509_algor_free_local(a: *mut X509Algor) {
    // SAFETY: `a` is NULL or live.
    unsafe { crate::asn1::x_algor::X509_ALGOR_free(a) };
}

/// `static int pkey_rsa_print(BIO *bp, const EVP_PKEY *pkey, int off, int priv)` —
/// `crypto/rsa/rsa_ameth.c:299-387`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe fn pkey_rsa_print(bp: *mut Bio, pkey: *const EvpPkey, off: c_int, priv_: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let x = (*pkey).pkey.cast::<Rsa>();
        let mut mod_len = 0;

        if !(*x).n.is_null() {
            mod_len = crate::bn::bignum::BN_num_bits((*x).n);
        }
        let ex_primes = OPENSSL_sk_num((*x).prime_infos);

        if BIO_indent(bp, off, 128) == 0 {
            return 0;
        }

        if BIO_printf(
            bp,
            c"%s ".as_ptr(),
            if pkey_is_pss(pkey) {
                c"RSA-PSS".as_ptr()
            } else {
                c"RSA".as_ptr()
            },
        ) <= 0
        {
            return 0;
        }

        let str_: *const c_char;
        let s: *const c_char;
        if priv_ != 0 && !(*x).d.is_null() {
            if BIO_printf(
                bp,
                c"Private-Key: (%d bit, %d primes)\n".as_ptr(),
                mod_len,
                if ex_primes <= 0 { 2 } else { ex_primes + 2 },
            ) <= 0
            {
                return 0;
            }
            str_ = c"modulus:".as_ptr();
            s = c"publicExponent:".as_ptr();
        } else {
            if BIO_printf(bp, c"Public-Key: (%d bit)\n".as_ptr(), mod_len) <= 0 {
                return 0;
            }
            str_ = c"Modulus:".as_ptr();
            s = c"Exponent:".as_ptr();
        }
        if ASN1_bn_print(bp, str_, (*x).n, ptr::null_mut(), off) == 0 {
            return 0;
        }
        if ASN1_bn_print(bp, s, (*x).e, ptr::null_mut(), off) == 0 {
            return 0;
        }
        if priv_ != 0 {
            if ASN1_bn_print(
                bp,
                c"privateExponent:".as_ptr(),
                (*x).d,
                ptr::null_mut(),
                off,
            ) == 0
            {
                return 0;
            }
            if ASN1_bn_print(bp, c"prime1:".as_ptr(), (*x).p, ptr::null_mut(), off) == 0 {
                return 0;
            }
            if ASN1_bn_print(bp, c"prime2:".as_ptr(), (*x).q, ptr::null_mut(), off) == 0 {
                return 0;
            }
            if ASN1_bn_print(bp, c"exponent1:".as_ptr(), (*x).dmp1, ptr::null_mut(), off) == 0 {
                return 0;
            }
            if ASN1_bn_print(bp, c"exponent2:".as_ptr(), (*x).dmq1, ptr::null_mut(), off) == 0 {
                return 0;
            }
            if ASN1_bn_print(
                bp,
                c"coefficient:".as_ptr(),
                (*x).iqmp,
                ptr::null_mut(),
                off,
            ) == 0
            {
                return 0;
            }
            let mut i = 0;
            while i < OPENSSL_sk_num((*x).prime_infos) {
                let pinfo = OPENSSL_sk_value((*x).prime_infos, i).cast::<RsaPrimeInfo>();
                let mut j = 0;
                while j < 3 {
                    if BIO_indent(bp, off, 128) == 0 {
                        return 0;
                    }
                    let bn: *mut BigNum = match j {
                        0 => {
                            if BIO_printf(bp, c"prime%d:".as_ptr(), i + 3) <= 0 {
                                return 0;
                            }
                            (*pinfo).r
                        }
                        1 => {
                            if BIO_printf(bp, c"exponent%d:".as_ptr(), i + 3) <= 0 {
                                return 0;
                            }
                            (*pinfo).d
                        }
                        _ => {
                            if BIO_printf(bp, c"coefficient%d:".as_ptr(), i + 3) <= 0 {
                                return 0;
                            }
                            (*pinfo).t
                        }
                    };
                    if ASN1_bn_print(bp, c"".as_ptr(), bn, ptr::null_mut(), off) == 0 {
                        return 0;
                    }
                    j += 1;
                }
                i += 1;
            }
        }
        if pkey_is_pss(pkey) && rsa_pss_param_print(bp, 1, (*x).pss, off) == 0 {
            return 0;
        }
        1
    }
}

/// `static int rsa_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/rsa/rsa_ameth.c:389-393`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn rsa_pub_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: both are live.
    unsafe { pkey_rsa_print(bp, pkey, indent, 0) }
}

/// `static int rsa_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/rsa/rsa_ameth.c:395-399`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn rsa_priv_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: both are live.
    unsafe { pkey_rsa_print(bp, pkey, indent, 1) }
}

/// `static int rsa_sig_print(BIO *bp, const X509_ALGOR *sigalg, const ASN1_STRING *sig, int indent,
/// ASN1_PCTX *pctx)` — `crypto/rsa/rsa_ameth.c:401-418`.
///
/// # Safety
/// `bp` and `sigalg` are live; `sig` is NULL or live.
unsafe extern "C" fn rsa_sig_print(
    bp: *mut Bio,
    sigalg: *const X509Algor,
    sig: *const Asn1String,
    indent: c_int,
    _pctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `sigalg` is live.
    if unsafe { OBJ_obj2nid((*sigalg).algorithm as *const _) } == EVP_PKEY_RSA_PSS {
        // SAFETY: `sigalg` is live.
        let pss = unsafe { ossl_rsa_pss_decode(sigalg) };

        // SAFETY: `bp` is live.
        let rv = unsafe { rsa_pss_param_print(bp, 0, pss, indent) };
        // SAFETY: `pss` is live or NULL.
        unsafe { RSA_PSS_PARAMS_free(pss) };
        if rv == 0 {
            return 0;
        }
    // SAFETY: `bp` is live.
    } else if unsafe { BIO_puts(bp, c"\n".as_ptr()) } <= 0 {
        return 0;
    }
    if !sig.is_null() {
        // SAFETY: both are live.
        return unsafe { X509_signature_dump(bp, sig, indent) };
    }
    1
}

/// `static int rsa_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)` —
/// `crypto/rsa/rsa_ameth.c:420-444`.
///
/// # Safety
/// `pkey` is live; `arg2` is a writable `int *` for the one supported operation.
unsafe extern "C" fn rsa_pkey_ctrl(
    pkey: *mut EvpPkey,
    op: c_int,
    _arg1: c_long,
    arg2: *mut c_void,
) -> c_int {
    match op {
        ASN1_PKEY_CTRL_DEFAULT_MD_NID => {
            // SAFETY: `pkey` is live.
            if !unsafe { (*(*pkey).pkey.cast::<Rsa>()).pss }.is_null() {
                let mut md: *const EvpMd = ptr::null();
                let mut mgf1md: *const EvpMd = ptr::null();
                let mut min_saltlen: c_int = 0;
                // SAFETY: the PSS params are live and the three out-parameters are live locals.
                if unsafe {
                    ossl_rsa_pss_get_param(
                        (*(*pkey).pkey.cast::<Rsa>()).pss,
                        &mut md,
                        &mut mgf1md,
                        &mut min_saltlen,
                    )
                } == 0
                {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::RSA_AMETH_431) };
                    return 0;
                }
                // SAFETY: `md` is live.
                unsafe { *(arg2.cast::<c_int>()) = EVP_MD_get_type(md) };
                /* Return of 2 indicates this MD is mandatory */
                return 2;
            }
            // SAFETY: `arg2` is the caller's writable `int *`.
            unsafe { *(arg2.cast::<c_int>()) = NID_sha256 };
            1
        }
        _ => -2,
    }
}

/// `static RSA_PSS_PARAMS *rsa_ctx_to_pss(EVP_PKEY_CTX *pkctx)` —
/// `crypto/rsa/rsa_ameth.c:451-492`.
///
/// # Safety
/// `pkctx` is live.
unsafe fn rsa_ctx_to_pss(pkctx: *mut EvpPkeyCtx) -> *mut RsaPssParams {
    // SAFETY: `pkctx` is live.
    let pk = unsafe { EVP_PKEY_CTX_get0_pkey(pkctx) };
    let mut saltlen_max: c_int = -1;
    let mut sigmd: *const EvpMd = ptr::null();
    let mut mgf1md: *const EvpMd = ptr::null();

    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_CTX_get_signature_md(pkctx, &mut sigmd) } <= 0 {
        return ptr::null_mut();
    }
    // SAFETY: `sigmd` is live.
    let md_size = unsafe { EVP_MD_get_size(sigmd) };
    if md_size <= 0 {
        return ptr::null_mut();
    }
    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mut mgf1md) } <= 0 {
        return ptr::null_mut();
    }
    let mut saltlen: c_int = 0;
    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_CTX_get_rsa_pss_saltlen(pkctx, &mut saltlen) } <= 0 {
        return ptr::null_mut();
    }
    if saltlen == RSA_PSS_SALTLEN_DIGEST {
        saltlen = md_size;
    } else if saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX {
        saltlen = RSA_PSS_SALTLEN_MAX;
        saltlen_max = md_size;
    }
    if saltlen == RSA_PSS_SALTLEN_MAX || saltlen == RSA_PSS_SALTLEN_AUTO {
        // SAFETY: `pk` is live.
        saltlen = unsafe { EVP_PKEY_get_size(pk) } - md_size - 2;
        // SAFETY: `pk` is live.
        if unsafe { EVP_PKEY_get_bits(pk) } & 0x7 == 1 {
            saltlen -= 1;
        }
        if saltlen < 0 {
            return ptr::null_mut();
        }
        if saltlen_max >= 0 && saltlen > saltlen_max {
            saltlen = saltlen_max;
        }
    }

    // SAFETY: `sigmd`/`mgf1md` are live.
    unsafe { ossl_rsa_pss_params_create(sigmd, mgf1md, saltlen) }
}

/// `RSA_PSS_PARAMS *ossl_rsa_pss_params_create(const EVP_MD *sigmd, const EVP_MD *mgf1md,
/// int saltlen)` — `crypto/rsa/rsa_ameth.c:494-520`.
///
/// # Safety
/// `sigmd` is live; `mgf1md` is NULL or live.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn ossl_rsa_pss_params_create(
    sigmd: *const EvpMd,
    mgf1md: *const EvpMd,
    saltlen: c_int,
) -> *mut RsaPssParams {
    let pss = RSA_PSS_PARAMS_new();

    if pss.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pss` is live.
    unsafe {
        if saltlen != 20 {
            (*pss).salt_length = ASN1_INTEGER_new();
            if (*pss).salt_length.is_null() {
                RSA_PSS_PARAMS_free(pss);
                return ptr::null_mut();
            }
            if ASN1_INTEGER_set((*pss).salt_length, saltlen as c_long) == 0 {
                RSA_PSS_PARAMS_free(pss);
                return ptr::null_mut();
            }
        }
        if ossl_x509_algor_new_from_md(&mut (*pss).hash_algorithm, sigmd) == 0 {
            RSA_PSS_PARAMS_free(pss);
            return ptr::null_mut();
        }
        let mgf1md = if mgf1md.is_null() { sigmd } else { mgf1md };
        if ossl_x509_algor_md_to_mgf1(&mut (*pss).mask_gen_algorithm, mgf1md) == 0 {
            RSA_PSS_PARAMS_free(pss);
            return ptr::null_mut();
        }
        if ossl_x509_algor_new_from_md(&mut (*pss).mask_hash, mgf1md) == 0 {
            RSA_PSS_PARAMS_free(pss);
            return ptr::null_mut();
        }
    }
    pss
}

/// `ASN1_STRING *ossl_rsa_ctx_to_pss_string(EVP_PKEY_CTX *pkctx)` —
/// `crypto/rsa/rsa_ameth.c:522-533`.
///
/// # Safety
/// `pkctx` is live.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn ossl_rsa_ctx_to_pss_string(pkctx: *mut EvpPkeyCtx) -> *mut Asn1String {
    // SAFETY: `pkctx` is live.
    let pss = unsafe { rsa_ctx_to_pss(pkctx) };

    if pss.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `pss` is live and the third argument is the authority's NULL.
    let os = unsafe { ASN1_item_pack(pss.cast(), RSA_PSS_PARAMS_it(), ptr::null_mut()) };
    // SAFETY: `pss` is live.
    unsafe { RSA_PSS_PARAMS_free(pss) };
    os
}

/// `int ossl_rsa_pss_to_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pkctx, const X509_ALGOR *sigalg,
/// EVP_PKEY *pkey)` — `crypto/rsa/rsa_ameth.c:541-590`.
///
/// # Safety
/// `ctx`/`pkctx` are live; `sigalg` is live; `pkey` is NULL or live.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn ossl_rsa_pss_to_ctx(
    ctx: *mut EvpMdCtx,
    pkctx: *mut EvpPkeyCtx,
    sigalg: *const X509Algor,
    pkey: *mut EvpPkey,
) -> c_int {
    let mut rv: c_int = -1;
    let mut mgf1md: *const EvpMd = ptr::null();
    let mut md: *const EvpMd = ptr::null();
    let mut saltlen: c_int = 0;

    /* Sanity check: make sure it is PSS */
    // SAFETY: `sigalg` is live.
    if unsafe { OBJ_obj2nid((*sigalg).algorithm as *const _) } != EVP_PKEY_RSA_PSS {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_AMETH_551) };
        return -1;
    }
    /* Decode PSS parameters */
    // SAFETY: `sigalg` is live.
    let pss = unsafe { ossl_rsa_pss_decode(sigalg) };

    // SAFETY: `pss` is live or NULL.
    if unsafe { ossl_rsa_pss_get_param(pss, &mut md, &mut mgf1md, &mut saltlen) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_AMETH_558) };
        // goto err
        // SAFETY: `pss` is live or NULL.
        unsafe { RSA_PSS_PARAMS_free(pss) };
        return rv;
    }

    let mut pkctx = pkctx;
    /* We have all parameters now set up context */
    if !pkey.is_null() {
        // SAFETY: every pointer is live.
        if unsafe { EVP_DigestVerifyInit(ctx, &mut pkctx, md, ptr::null_mut(), pkey) } == 0 {
            // goto err
            // SAFETY: `pss` is live or NULL.
            unsafe { RSA_PSS_PARAMS_free(pss) };
            return rv;
        }
    } else {
        let mut checkmd: *const EvpMd = ptr::null();
        // SAFETY: `pkctx` is live.
        if unsafe { EVP_PKEY_CTX_get_signature_md(pkctx, &mut checkmd) } <= 0 {
            // goto err
            // SAFETY: `pss` is live or NULL.
            unsafe { RSA_PSS_PARAMS_free(pss) };
            return rv;
        }
        // SAFETY: both are live.
        if unsafe { EVP_MD_get_type(md) } != unsafe { EVP_MD_get_type(checkmd) } {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::RSA_AMETH_571) };
            // goto err
            // SAFETY: `pss` is live or NULL.
            unsafe { RSA_PSS_PARAMS_free(pss) };
            return rv;
        }
    }

    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) } <= 0 {
        // goto err
        // SAFETY: `pss` is live or NULL.
        unsafe { RSA_PSS_PARAMS_free(pss) };
        return rv;
    }

    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen) } <= 0 {
        // goto err
        // SAFETY: `pss` is live or NULL.
        unsafe { RSA_PSS_PARAMS_free(pss) };
        return rv;
    }

    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) } <= 0 {
        // goto err
        // SAFETY: `pss` is live or NULL.
        unsafe { RSA_PSS_PARAMS_free(pss) };
        return rv;
    }
    /* Carry on */
    rv = 1;

    // SAFETY: `pss` is live or NULL.
    unsafe { RSA_PSS_PARAMS_free(pss) };
    rv
}

/// `static int rsa_pss_verify_param(const EVP_MD **pmd, const EVP_MD **pmgf1md, int *psaltlen,
/// int *ptrailerField)` — `crypto/rsa/rsa_ameth.c:592-608`.
///
/// # Safety
/// `psaltlen` and `ptrailerField` are NULL or live.
unsafe fn rsa_pss_verify_param(
    _pmd: *mut *const EvpMd,
    _pmgf1md: *mut *const EvpMd,
    psaltlen: *mut c_int,
    ptrailerfield: *mut c_int,
) -> c_int {
    // SAFETY: `psaltlen` is NULL or live.
    if !psaltlen.is_null() && unsafe { *psaltlen } < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_AMETH_596) };
        return 0;
    }
    /* low-level routines support only trailer field 0xbc (value 1) */
    // SAFETY: `ptrailerfield` is NULL or live.
    if !ptrailerfield.is_null() && unsafe { *ptrailerfield } != 1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_AMETH_604) };
        return 0;
    }
    1
}

/// `int ossl_rsa_pss_get_param(const RSA_PSS_PARAMS *pss, const EVP_MD **pmd,
/// const EVP_MD **pmgf1md, int *psaltlen)` — `crypto/rsa/rsa_ameth.c:610-626`.
///
/// # Safety
/// `pss` is NULL or live; the three out-parameters are live.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn ossl_rsa_pss_get_param(
    pss: *const RsaPssParams,
    pmd: *mut *const EvpMd,
    pmgf1md: *mut *const EvpMd,
    psaltlen: *mut c_int,
) -> c_int {
    let mut trailer_field: c_int = 0;

    // SAFETY: the caller's contract; the trailer field is this frame's slot.
    c_int::from(unsafe {
        ossl_rsa_pss_get_param_unverified(pss, pmd, pmgf1md, psaltlen, &mut trailer_field) != 0
            && rsa_pss_verify_param(pmd, pmgf1md, psaltlen, &mut trailer_field) != 0
    })
}

/// `static int rsa_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, const void *asn,
/// const X509_ALGOR *sigalg, const ASN1_BIT_STRING *sig, EVP_PKEY *pkey)` —
/// `crypto/rsa/rsa_ameth.c:633-647`.
///
/// # Safety
/// `ctx` and `sigalg` are live; `pkey` is live.
unsafe extern "C" fn rsa_item_verify(
    ctx: *mut EvpMdCtx,
    _it: *const crate::asn1::layout::Asn1Item,
    _asn: *const c_void,
    sigalg: *const X509Algor,
    _sig: *const crate::evp::pkey_asn1::Asn1BitString,
    pkey: *mut EvpPkey,
) -> c_int {
    /* Sanity check: make sure it is PSS */
    // SAFETY: `sigalg` is live.
    if unsafe { OBJ_obj2nid((*sigalg).algorithm as *const _) } != EVP_PKEY_RSA_PSS {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_AMETH_639) };
        return -1;
    }
    // SAFETY: all three are live.
    if unsafe { ossl_rsa_pss_to_ctx(ctx, ptr::null_mut(), sigalg, pkey) } > 0 {
        /* Carry on */
        return 2;
    }
    -1
}

/// `static int rsa_item_sign(EVP_MD_CTX *ctx, const ASN1_ITEM *it, const void *asn,
/// X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *sig)` —
/// `crypto/rsa/rsa_ameth.c:649-720`.
///
/// # Safety
/// `ctx` is live; `alg1`/`alg2` are NULL or live.
unsafe extern "C" fn rsa_item_sign(
    ctx: *mut EvpMdCtx,
    _it: *const crate::asn1::layout::Asn1Item,
    _asn: *const c_void,
    alg1: *mut X509Algor,
    alg2: *mut X509Algor,
    _sig: *mut crate::evp::pkey_asn1::Asn1BitString,
) -> c_int {
    let mut alg1 = alg1;
    let mut alg2 = alg2;
    // SAFETY: `ctx` is live.
    let pkctx = unsafe { EVP_MD_CTX_get_pkey_ctx(ctx) };

    let mut pad_mode: c_int = 0;
    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_CTX_get_rsa_padding(pkctx, &mut pad_mode) } <= 0 {
        return 0;
    }
    if pad_mode == RSA_PKCS1_PADDING {
        return 2;
    }
    if pad_mode == RSA_PKCS1_PSS_PADDING {
        let mut aid = [0 as c_uchar; 128];

        // SAFETY: `pkctx` is live.
        if unsafe { (*pkctx).is_legacy() } {
            /* No provider -> we cannot query it for algorithm ID. */
            // SAFETY: `pkctx` is live.
            let os1 = unsafe { ossl_rsa_ctx_to_pss_string(pkctx) };
            if os1.is_null() {
                return 0;
            }
            /* Duplicate parameters if we have to */
            if !alg2.is_null() {
                // SAFETY: `os1` is live.
                let os2 = unsafe { ASN1_STRING_dup(os1) };

                if os2.is_null() {
                    // SAFETY: `os1` is live.
                    unsafe { ASN1_STRING_free(os1) };
                    return 0;
                }
                // SAFETY: `alg2` is live and `os2` is the object the setter takes.
                if unsafe {
                    crate::asn1::x_algor::X509_ALGOR_set0(
                        alg2,
                        OBJ_nid2obj(EVP_PKEY_RSA_PSS),
                        V_ASN1_SEQUENCE,
                        os2.cast(),
                    )
                } == 0
                {
                    // SAFETY: both are live.
                    unsafe {
                        ASN1_STRING_free(os1);
                        ASN1_STRING_free(os2);
                    }
                    return 0;
                }
            }
            // SAFETY: `alg1` is live and `os1` is the object the setter takes.
            if unsafe {
                crate::asn1::x_algor::X509_ALGOR_set0(
                    alg1,
                    OBJ_nid2obj(EVP_PKEY_RSA_PSS),
                    V_ASN1_SEQUENCE,
                    os1.cast(),
                )
            } == 0
            {
                // SAFETY: `os1` is live.
                unsafe { ASN1_STRING_free(os1) };
                return 0;
            }
            return 3;
        }

        let mut params: [OsslParam; 2] = [crate::params::END; 2];
        // SAFETY: `aid` is a live local buffer.
        params[0] = unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
                aid.as_mut_ptr().cast(),
                aid.len(),
            )
        };
        params[1] = OSSL_PARAM_construct_end();

        // SAFETY: `pkctx` is live and `params` is a live terminated array.
        if unsafe { EVP_PKEY_CTX_get_params(pkctx, params.as_mut_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `params` is a live local array whose first slot the getter filled.
        let aid_len = params[0].return_size;
        if aid_len == 0 {
            return 0;
        }

        if !alg1.is_null() {
            let mut pp = aid.as_ptr();
            // SAFETY: `pp` reads the `aid_len` bytes the getter filled.
            if unsafe { d2i_X509_ALGOR(&mut alg1, &mut pp, aid_len as c_long) }.is_null() {
                return 0;
            }
        }
        if !alg2.is_null() {
            let mut pp = aid.as_ptr();
            // SAFETY: `pp` reads the `aid_len` bytes the getter filled.
            if unsafe { d2i_X509_ALGOR(&mut alg2, &mut pp, aid_len as c_long) }.is_null() {
                return 0;
            }
        }

        return 3;
    }
    2
}

/// `static int rsa_sig_info_set(X509_SIG_INFO *siginf, const X509_ALGOR *sigalg,
/// const ASN1_STRING *sig)` — `crypto/rsa/rsa_ameth.c:722-777`.
///
/// # Safety
/// `siginf` and `sigalg` are live; `sig` is NULL or live.
unsafe extern "C" fn rsa_sig_info_set(
    siginf: *mut X509SigInfo,
    sigalg: *const X509Algor,
    _sig: *const Asn1String,
) -> c_int {
    let mut rv = 0;
    let mut mgf1md: *const EvpMd = ptr::null();
    let mut md: *const EvpMd = ptr::null();
    let mut saltlen: c_int = 0;

    /* Sanity check: make sure it is PSS */
    // SAFETY: `sigalg` is live.
    if unsafe { OBJ_obj2nid((*sigalg).algorithm as *const _) } != EVP_PKEY_RSA_PSS {
        return 0;
    }
    /* Decode PSS parameters */
    // SAFETY: `sigalg` is live.
    let pss = unsafe { ossl_rsa_pss_decode(sigalg) };
    // SAFETY: `pss` is live or NULL.
    if unsafe { ossl_rsa_pss_get_param(pss, &mut md, &mut mgf1md, &mut saltlen) } == 0 {
        // goto err
        // SAFETY: `pss` is live or NULL.
        unsafe { RSA_PSS_PARAMS_free(pss) };
        return rv;
    }
    // SAFETY: `md` is live.
    let md_size = unsafe { EVP_MD_get_size(md) };
    if md_size <= 0 {
        // goto err
        // SAFETY: `pss` is live or NULL.
        unsafe { RSA_PSS_PARAMS_free(pss) };
        return rv;
    }
    // SAFETY: `md` is live.
    let mdnid = unsafe { EVP_MD_get_type(md) };
    let flags = if (mdnid == NID_sha256 || mdnid == NID_sha384 || mdnid == NID_sha512)
        // SAFETY: `mgf1md` is live.
        && mdnid == unsafe { EVP_MD_get_type(mgf1md) }
        && saltlen == md_size
    {
        X509_SIG_INFO_TLS
    } else {
        0
    };
    /* Note: security bits half number of digest bits */
    let secbits = md_size * 4;
    let secbits = if mdnid == NID_sha1 {
        64
    } else if mdnid == NID_md5_sha1 {
        68
    } else if mdnid == NID_md5 {
        39
    } else {
        secbits
    };
    // SAFETY: `siginf` is live.
    unsafe { X509_SIG_INFO_set(siginf, mdnid, EVP_PKEY_RSA_PSS, secbits, flags) };
    rv = 1;
    // SAFETY: `pss` is live or NULL.
    unsafe { RSA_PSS_PARAMS_free(pss) };
    rv
}

/// `static int rsa_pkey_check(const EVP_PKEY *pkey)` — `crypto/rsa/rsa_ameth.c:779-782`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn rsa_pkey_check(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live and the callback is the authority's NULL.
    unsafe { RSA_check_key_ex((*pkey).pkey.cast::<Rsa>(), ptr::null_mut()) }
}

/// `static size_t rsa_pkey_dirty_cnt(const EVP_PKEY *pkey)` — `crypto/rsa/rsa_ameth.c:784-787`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn rsa_pkey_dirty_cnt(pkey: *const EvpPkey) -> usize {
    // SAFETY: `pkey` is live.
    unsafe { (*(*pkey).pkey.cast::<Rsa>()).dirty_cnt as usize }
}

/// `static int rsa_int_export_to(const EVP_PKEY *from, int rsa_type, void *to_keydata,
/// OSSL_FUNC_keymgmt_import_fn *importer, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/rsa/rsa_ameth.c:793-847`.
///
/// # Safety
/// `from` is live; `to_keydata` is the importer's own object.
unsafe fn rsa_int_export_to(
    from: *const EvpPkey,
    _rsa_type: c_int,
    to_keydata: *mut c_void,
    importer: Option<crate::evp::keymgmt::KeymgmtImportFn>,
    _libctx: *mut c_void,
    _propq: *const c_char,
) -> c_int {
    let mut selection: c_int = 0;

    // SAFETY: `from` is live.
    let rsa = unsafe { (*from).pkey.cast::<Rsa>() };

    let tmpl = OSSL_PARAM_BLD_new();
    if tmpl.is_null() {
        return 0;
    }
    /* Public parameters must always be present */
    // SAFETY: `rsa` is live.
    if unsafe { (*rsa).n }.is_null() || unsafe { (*rsa).e }.is_null() {
        // goto err
        // SAFETY: `tmpl` is live.
        unsafe { OSSL_PARAM_BLD_free(tmpl) };
        return 0;
    }

    // SAFETY: `rsa` and `tmpl` are live.
    if unsafe { ossl_rsa_todata(rsa, tmpl, ptr::null_mut(), 1) } == 0 {
        // goto err
        // SAFETY: `tmpl` is live.
        unsafe { OSSL_PARAM_BLD_free(tmpl) };
        return 0;
    }

    selection |= crate::evp::pkey::OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    // SAFETY: `rsa` is live.
    if !unsafe { (*rsa).d }.is_null() {
        selection |= crate::evp::pkey::OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    }

    // SAFETY: `rsa` is live.
    if !unsafe { (*rsa).pss }.is_null() {
        let mut md: *const EvpMd = ptr::null();
        let mut mgf1md: *const EvpMd = ptr::null();
        let mut saltlen: c_int = 0;
        let mut trailerfield: c_int = 0;
        // SAFETY: `rsa`'s PSS params are live and the four out-parameters are live locals.
        if unsafe {
            ossl_rsa_pss_get_param_unverified(
                (*rsa).pss,
                &mut md,
                &mut mgf1md,
                &mut saltlen,
                &mut trailerfield,
            )
        } == 0
        {
            // goto err
            // SAFETY: `tmpl` is live.
            unsafe { OSSL_PARAM_BLD_free(tmpl) };
            return 0;
        }
        // SAFETY: `md`/`mgf1md` are live.
        let md_nid = unsafe { EVP_MD_get_type(md) };
        // SAFETY: `mgf1md` is live.
        let mgf1md_nid = unsafe { EVP_MD_get_type(mgf1md) };
        // SAFETY: a `RsaPssParams30` is an aggregate of integers, so zeroed is a valid value.
        let mut pss_params: RsaPssParams30 = unsafe { core::mem::zeroed() };
        // SAFETY: `pss_params` is a live local and `tmpl` is live.
        if unsafe {
            ossl_rsa_pss_params_30_set_defaults(&mut pss_params) == 0
                || ossl_rsa_pss_params_30_set_hashalg(&mut pss_params, md_nid) == 0
                || ossl_rsa_pss_params_30_set_maskgenhashalg(&mut pss_params, mgf1md_nid) == 0
                || ossl_rsa_pss_params_30_set_saltlen(&mut pss_params, saltlen) == 0
                || ossl_rsa_pss_params_30_todata(&pss_params, tmpl, ptr::null_mut()) == 0
        } {
            // goto err
            // SAFETY: `tmpl` is live.
            unsafe { OSSL_PARAM_BLD_free(tmpl) };
            return 0;
        }
        selection |= crate::evp::pkey::OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
    }

    // SAFETY: `tmpl` is live.
    let params = unsafe { OSSL_PARAM_BLD_to_param(tmpl) };
    if params.is_null() {
        // goto err
        // SAFETY: `tmpl` is live.
        unsafe { OSSL_PARAM_BLD_free(tmpl) };
        return 0;
    }

    /* We export, the provider imports */
    // SAFETY: `importer` is the destination's own function.
    let rv = unsafe { importer.map_or(0, |f| f(to_keydata, selection, params)) };

    // SAFETY: both are live.
    unsafe {
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(tmpl);
    }
    rv
}

/// `static int rsa_int_import_from(const OSSL_PARAM params[], void *vpctx, int rsa_type)` —
/// `crypto/rsa/rsa_ameth.c:849-922`.
///
/// # Safety
/// `params` is a live parameter array; `vpctx` is a live `EVP_PKEY_CTX`.
unsafe fn rsa_int_import_from(
    params: *const OsslParam,
    vpctx: *mut c_void,
    rsa_type: c_int,
) -> c_int {
    let pctx = vpctx.cast::<EvpPkeyCtx>();
    // SAFETY: `pctx` is live per the contract.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
    // SAFETY: `pctx` is live.
    let rsa = unsafe { ossl_rsa_new_with_ctx((*pctx).libctx) };
    // SAFETY: a `RsaPssParams30` is an aggregate of integers, so zeroed is a valid value.
    let mut rsa_pss_params: RsaPssParams30 = unsafe { core::mem::zeroed() };
    let mut pss_defaults_set: c_int = 0;
    let mut ok = 0;

    if rsa.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::RSA_AMETH_862) };
        return 0;
    }

    // SAFETY: `rsa` is live.
    unsafe {
        RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
        RSA_set_flags(rsa, rsa_type);
    }

    // SAFETY: `rsa_pss_params` is a live local and `pctx` is live.
    if unsafe {
        ossl_rsa_pss_params_30_fromdata(
            &mut rsa_pss_params,
            &mut pss_defaults_set,
            params,
            (*pctx).libctx,
        )
    } == 0
    {
        // goto err
        // SAFETY: `rsa` is live.
        unsafe { RSA_free(rsa) };
        return ok;
    }

    match rsa_type {
        RSA_FLAG_TYPE_RSA => {
            /* Were PSS parameters filled in? In that case, something's wrong */
            // SAFETY: `rsa_pss_params` is a live local.
            if unsafe { ossl_rsa_pss_params_30_is_unrestricted(&rsa_pss_params) } == 0 {
                // goto err
                // SAFETY: `rsa` is live.
                unsafe { RSA_free(rsa) };
                return ok;
            }
        }
        RSA_FLAG_TYPE_RSASSAPSS => {
            /* Were PSS parameters filled in?  In that case, create the old RSA_PSS_PARAMS. */
            // SAFETY: `rsa_pss_params` is a live local.
            if unsafe { ossl_rsa_pss_params_30_is_unrestricted(&rsa_pss_params) } == 0 {
                // SAFETY: `rsa_pss_params` is a live local.
                let md_nid = unsafe { ossl_rsa_pss_params_30_hashalg(&rsa_pss_params) };
                // SAFETY: `rsa_pss_params` is a live local.
                let mgf1md_nid = unsafe { ossl_rsa_pss_params_30_maskgenhashalg(&rsa_pss_params) };
                // SAFETY: `rsa_pss_params` is a live local.
                let saltlen = unsafe { ossl_rsa_pss_params_30_saltlen(&rsa_pss_params) };
                // SAFETY: no preconditions on the NIDs.
                let md = unsafe { evp_get_digestbynid(md_nid) };
                // SAFETY: no preconditions on the NIDs.
                let mgf1md = unsafe { evp_get_digestbynid(mgf1md_nid) };

                // SAFETY: `md`/`mgf1md` are NULL or live.
                let pss = unsafe { ossl_rsa_pss_params_create(md, mgf1md, saltlen) };
                // SAFETY: `rsa` is live.
                unsafe { (*rsa).pss = pss };
                if pss.is_null() {
                    // goto err
                    // SAFETY: `rsa` is live.
                    unsafe { RSA_free(rsa) };
                    return ok;
                }
            }
        }
        _ => {
            /* RSA key sub-types we don't know how to handle yet */
            // goto err
            // SAFETY: `rsa` is live.
            unsafe { RSA_free(rsa) };
            return ok;
        }
    }

    // SAFETY: `rsa` is live and `params` is the caller's array.
    if unsafe { ossl_rsa_fromdata(rsa, params, 1) } == 0 {
        // goto err
        // SAFETY: `rsa` is live.
        unsafe { RSA_free(rsa) };
        return ok;
    }

    match rsa_type {
        RSA_FLAG_TYPE_RSA => {
            // SAFETY: `pkey` is live.
            ok = unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa.cast()) };
        }
        RSA_FLAG_TYPE_RSASSAPSS => {
            // SAFETY: `pkey` is live.
            ok = unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_RSA_PSS, rsa.cast()) };
        }
        _ => {}
    }

    if ok == 0 {
        // SAFETY: `rsa` is live.
        unsafe { RSA_free(rsa) };
    }
    ok
}

/// `static int rsa_pkey_export_to(const EVP_PKEY *from, void *to_keydata,
/// OSSL_FUNC_keymgmt_import_fn *importer, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/rsa/rsa_ameth.c:924-930`.
///
/// # Safety
/// As [`rsa_int_export_to`].
unsafe extern "C" fn rsa_pkey_export_to(
    from: *const EvpPkey,
    to_keydata: *mut c_void,
    importer: Option<crate::evp::keymgmt::KeymgmtImportFn>,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { rsa_int_export_to(from, RSA_FLAG_TYPE_RSA, to_keydata, importer, libctx, propq) }
}

/// `static int rsa_pss_pkey_export_to(const EVP_PKEY *from, void *to_keydata,
/// OSSL_FUNC_keymgmt_import_fn *importer, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/rsa/rsa_ameth.c:932-938`.
///
/// # Safety
/// As [`rsa_int_export_to`].
unsafe extern "C" fn rsa_pss_pkey_export_to(
    from: *const EvpPkey,
    to_keydata: *mut c_void,
    importer: Option<crate::evp::keymgmt::KeymgmtImportFn>,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        rsa_int_export_to(
            from,
            RSA_FLAG_TYPE_RSASSAPSS,
            to_keydata,
            importer,
            libctx,
            propq,
        )
    }
}

/// `static int rsa_pkey_import_from(const OSSL_PARAM params[], void *vpctx)` —
/// `crypto/rsa/rsa_ameth.c:940-943`.
///
/// # Safety
/// As [`rsa_int_import_from`].
unsafe extern "C" fn rsa_pkey_import_from(params: *const OsslParam, vpctx: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { rsa_int_import_from(params, vpctx, RSA_FLAG_TYPE_RSA) }
}

/// `static int rsa_pss_pkey_import_from(const OSSL_PARAM params[], void *vpctx)` —
/// `crypto/rsa/rsa_ameth.c:945-948`.
///
/// # Safety
/// As [`rsa_int_import_from`].
unsafe extern "C" fn rsa_pss_pkey_import_from(
    params: *const OsslParam,
    vpctx: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { rsa_int_import_from(params, vpctx, RSA_FLAG_TYPE_RSASSAPSS) }
}

/// `static int rsa_pkey_copy(EVP_PKEY *to, EVP_PKEY *from)` — `crypto/rsa/rsa_ameth.c:950-966`.
///
/// # Safety
/// `to` and `from` are live.
unsafe extern "C" fn rsa_pkey_copy(to: *mut EvpPkey, from: *mut EvpPkey) -> c_int {
    // SAFETY: `from` is live.
    let rsa = unsafe { (*from).pkey.cast::<Rsa>() };
    let mut dupkey: *mut Rsa = ptr::null_mut();

    if !rsa.is_null() {
        // SAFETY: `rsa` is live.
        dupkey = unsafe { ossl_rsa_dup(rsa, crate::evp::pkey::OSSL_KEYMGMT_SELECT_ALL_BITS) };
        if dupkey.is_null() {
            return 0;
        }
    }

    // SAFETY: `to` is live.
    let ret = unsafe { EVP_PKEY_assign(to, (*from).type_, dupkey.cast()) };
    if ret == 0 {
        // SAFETY: `dupkey` is live.
        unsafe { RSA_free(dupkey) };
    }
    ret
}

/// `const EVP_PKEY_ASN1_METHOD ossl_rsa_asn1_meths[2]` — `crypto/rsa/rsa_ameth.c:968-1012`.
///
/// Row `[0]` is the method; row `[1]` is the `EVP_PKEY_RSA2` alias `{ EVP_PKEY_RSA2, EVP_PKEY_RSA }`.
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_rsa_asn1_meths: [EvpPkeyAsn1Method; 2] = [
    EvpPkeyAsn1Method {
        pkey_id: EVP_PKEY_RSA,
        pkey_base_id: EVP_PKEY_RSA,
        pkey_flags: ASN1_PKEY_SIGPARAM_NULL,
        pem_str: c"RSA".as_ptr().cast_mut(),
        info: c"OpenSSL RSA method".as_ptr().cast_mut(),
        pub_decode: Some(rsa_pub_decode),
        pub_encode: Some(rsa_pub_encode),
        pub_cmp: Some(rsa_pub_cmp),
        pub_print: Some(rsa_pub_print),
        priv_decode: Some(rsa_priv_decode),
        priv_encode: Some(rsa_priv_encode),
        priv_print: Some(rsa_priv_print),
        pkey_size: Some(int_rsa_size),
        pkey_bits: Some(rsa_bits),
        pkey_security_bits: Some(rsa_security_bits),
        param_decode: None,
        param_encode: None,
        param_missing: None,
        param_copy: None,
        param_cmp: None,
        param_print: None,
        sig_print: Some(rsa_sig_print),
        pkey_free: Some(int_rsa_free),
        pkey_ctrl: Some(rsa_pkey_ctrl),
        old_priv_decode: Some(old_rsa_priv_decode),
        old_priv_encode: Some(old_rsa_priv_encode),
        item_verify: Some(rsa_item_verify),
        item_sign: Some(rsa_item_sign),
        siginf_set: Some(rsa_sig_info_set),
        pkey_check: Some(rsa_pkey_check),
        pkey_public_check: None,
        pkey_param_check: None,
        set_priv_key: None,
        set_pub_key: None,
        get_priv_key: None,
        get_pub_key: None,
        dirty_cnt: Some(rsa_pkey_dirty_cnt),
        export_to: Some(rsa_pkey_export_to),
        import_from: Some(rsa_pkey_import_from),
        copy: Some(rsa_pkey_copy),
        priv_decode_ex: None,
    },
    EvpPkeyAsn1Method {
        pkey_id: EVP_PKEY_RSA2,
        pkey_base_id: EVP_PKEY_RSA,
        pkey_flags: crate::evp::pkey_asn1::ASN1_PKEY_ALIAS,
        pem_str: ptr::null_mut(),
        info: ptr::null_mut(),
        pub_decode: None,
        pub_encode: None,
        pub_cmp: None,
        pub_print: None,
        priv_decode: None,
        priv_encode: None,
        priv_print: None,
        pkey_size: None,
        pkey_bits: None,
        pkey_security_bits: None,
        param_decode: None,
        param_encode: None,
        param_missing: None,
        param_copy: None,
        param_cmp: None,
        param_print: None,
        sig_print: None,
        pkey_free: None,
        pkey_ctrl: None,
        old_priv_decode: None,
        old_priv_encode: None,
        item_verify: None,
        item_sign: None,
        siginf_set: None,
        pkey_check: None,
        pkey_public_check: None,
        pkey_param_check: None,
        set_priv_key: None,
        set_pub_key: None,
        get_priv_key: None,
        get_pub_key: None,
        dirty_cnt: None,
        export_to: None,
        import_from: None,
        copy: None,
        priv_decode_ex: None,
    },
];

/// `const EVP_PKEY_ASN1_METHOD ossl_rsa_pss_asn1_meth` — `crypto/rsa/rsa_ameth.c:1014-1053`.
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_rsa_pss_asn1_meth: EvpPkeyAsn1Method = EvpPkeyAsn1Method {
    pkey_id: EVP_PKEY_RSA_PSS,
    pkey_base_id: EVP_PKEY_RSA_PSS,
    pkey_flags: ASN1_PKEY_SIGPARAM_NULL,
    pem_str: c"RSA-PSS".as_ptr().cast_mut(),
    info: c"OpenSSL RSA-PSS method".as_ptr().cast_mut(),
    pub_decode: Some(rsa_pub_decode),
    pub_encode: Some(rsa_pub_encode),
    pub_cmp: Some(rsa_pub_cmp),
    pub_print: Some(rsa_pub_print),
    priv_decode: Some(rsa_priv_decode),
    priv_encode: Some(rsa_priv_encode),
    priv_print: Some(rsa_priv_print),
    pkey_size: Some(int_rsa_size),
    pkey_bits: Some(rsa_bits),
    pkey_security_bits: Some(rsa_security_bits),
    param_decode: None,
    param_encode: None,
    param_missing: None,
    param_copy: None,
    param_cmp: None,
    param_print: None,
    sig_print: Some(rsa_sig_print),
    pkey_free: Some(int_rsa_free),
    pkey_ctrl: Some(rsa_pkey_ctrl),
    old_priv_decode: None,
    old_priv_encode: None,
    item_verify: Some(rsa_item_verify),
    item_sign: Some(rsa_item_sign),
    siginf_set: Some(rsa_sig_info_set),
    pkey_check: Some(rsa_pkey_check),
    pkey_public_check: None,
    pkey_param_check: None,
    set_priv_key: None,
    set_pub_key: None,
    get_priv_key: None,
    get_pub_key: None,
    dirty_cnt: Some(rsa_pkey_dirty_cnt),
    export_to: Some(rsa_pss_pkey_export_to),
    import_from: Some(rsa_pss_pkey_import_from),
    copy: Some(rsa_pkey_copy),
    priv_decode_ex: None,
};

// SPDX-License-Identifier: Apache-2.0
