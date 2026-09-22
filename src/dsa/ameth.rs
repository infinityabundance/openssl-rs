//! `crypto/dsa/dsa_ameth.c` — the whole unit: the four-element `ossl_dsa_asn1_meths[]` array and
//! every callback it names.
//!
//! D341 measured this unit as one of the five object-bearing units whose callbacks reached Phase
//! 11, and 8.8 lands it once D348/D349/D351 closed that closure. The four rows are an **alias
//! group**: `[0]`/`[1]`/`[2]` are `ASN1_PKEY_ALIAS` objects with no callbacks — they map the three
//! historical DSA NIDs onto `EVP_PKEY_DSA` and `EVP_PKEY_DSA2` — and only `[3]` carries the method.
//! The array is `static` so each row has one address, which is what `EVP_PKEY_asn1_find`'s alias
//! walk and `standard_methods[]` both need.
//!
//! The unit raises sixteen times (`DSA_AMETH_*`), so it joins
//! `gen_err_raise_sites.py`'s covered set with `crypto/dh/dh_ameth.c`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_INTEGER_it;
use crate::asn1::layout::{Asn1Pctx, Asn1String, V_ASN1_NULL, V_ASN1_SEQUENCE, V_ASN1_UNDEF};
use crate::asn1::p8_pkey::PKCS8_pkey_set0;
use crate::asn1::prim::{ASN1_INTEGER_to_BN, BN_to_ASN1_INTEGER};
use crate::asn1::string::{ASN1_STRING_clear_free, ASN1_STRING_free, ASN1_STRING_new};
use crate::asn1::t_pkey::ASN1_bn_print;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0};
use crate::bn::arith::BN_cmp;
use crate::bn::bignum::BigNum;
use crate::dsa::asn1::{d2i_DSAPrivateKey, d2i_DSAparams, i2d_DSAPrivateKey, i2d_DSAparams};
use crate::dsa::backend::{ossl_dsa_dup, ossl_dsa_key_from_pkcs8, ossl_dsa_key_fromdata};
use crate::dsa::object::ossl_dsa_ffc_params_fromdata;
use crate::dsa::object::{
    ossl_dsa_new, DSA_bits, DSA_free, DSA_get0_g, DSA_get0_p, DSA_get0_priv_key, DSA_get0_pub_key,
    DSA_get0_q, DSA_new, DSA_security_bits,
};
use crate::dsa::sign::{d2i_DSA_SIG, DSA_SIG_free, DSA_SIG_get0, DSA_size};
use crate::dsa::Dsa;
use crate::evp::keymgmt::KeymgmtImportFn;
use crate::evp::pkey::{
    EVP_PKEY_assign, EvpPkey, ASN1_PKEY_CTRL_DEFAULT_MD_NID, OSSL_KEYMGMT_SELECT_ALL_BITS,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
};
use crate::evp::pkey_asn1::{EvpPkeyAsn1Method, ASN1_PKEY_ALIAS};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_get0_pkey, EVP_PKEY_DSA, OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_P,
    OSSL_PKEY_PARAM_FFC_Q,
};
use crate::ffc::params::{ossl_ffc_params_cmp, ossl_ffc_params_copy, ossl_ffc_params_print};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN, OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::OsslParam;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{
    NID_dsa, NID_dsaWithSHA, NID_dsaWithSHA1, NID_dsaWithSHA1_2, NID_dsa_2, NID_sha256, OBJ_nid2obj,
};
use crate::x509::t_x509::X509_signature_dump;
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_get0_param, X509_PUBKEY_set0_param};

/// `EVP_PKEY_DSA1` — `include/openssl/evp.h:66`, `NID_dsa_2`.
const EVP_PKEY_DSA1: c_int = NID_dsa_2;
/// `EVP_PKEY_DSA2` — `include/openssl/evp.h:67`, `NID_dsaWithSHA`.
const EVP_PKEY_DSA2: c_int = NID_dsaWithSHA;
/// `EVP_PKEY_DSA3` — `include/openssl/evp.h:68`, `NID_dsaWithSHA1`.
const EVP_PKEY_DSA3: c_int = NID_dsaWithSHA1;
/// `EVP_PKEY_DSA4` — `include/openssl/evp.h:69`, `NID_dsaWithSHA1_2`.
const EVP_PKEY_DSA4: c_int = NID_dsaWithSHA1_2;
/// The authority's translation unit, for the `OPENSSL_free`/`OPENSSL_clear_free` sites below.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/dsa/dsa_ameth.c".as_ptr();

/// `static int dsa_pub_decode(EVP_PKEY *pkey, const X509_PUBKEY *pubkey)` —
/// `crypto/dsa/dsa_ameth.c:29-84`.
///
/// # Safety
/// `pkey` and `pubkey` are live.
unsafe extern "C" fn dsa_pub_decode(pkey: *mut EvpPkey, pubkey: *const X509Pubkey) -> c_int {
    let mut p: *const c_uchar = ptr::null();
    let mut pklen: c_int = 0;
    let mut ptype: c_int = 0;
    let mut pval: *const c_void = ptr::null();
    let mut palg: *mut X509Algor = ptr::null_mut();
    let mut public_key: *mut Asn1String = ptr::null_mut();
    let mut dsa: *mut Dsa = ptr::null_mut();

    // SAFETY: `pubkey` is live, the four out-parameters are live locals, and the first argument is
    // the authority's own NULL.
    if unsafe { X509_PUBKEY_get0_param(ptr::null_mut(), &mut p, &mut pklen, &mut palg, pubkey) }
        == 0
    {
        return 0;
    }
    // SAFETY: `palg` is live and the three out-parameters are live locals.
    unsafe { X509_ALGOR_get0(ptr::null_mut(), &mut ptype, &mut pval, palg) };

    if ptype == V_ASN1_SEQUENCE {
        let pstr = pval.cast::<Asn1String>();
        // SAFETY: `pstr` is the ASN1_STRING the algorithm identifier carries.
        let mut pm = unsafe { (*pstr).data }.cast_const();
        // SAFETY: `pstr` is the ASN1_STRING whose content `pm` points into.
        let pmlen = unsafe { (*pstr).length } as c_long;

        // SAFETY: the caller's contract; the first argument is the authority's NULL.
        dsa = unsafe { d2i_DSAparams(ptr::null_mut(), &mut pm, pmlen) };
        if dsa.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSA_AMETH_51) };
            // SAFETY: both are NULL on this path.
            unsafe {
                ASN1_STRING_free(public_key);
                DSA_free(dsa);
            }
            return 0;
        }
    } else if ptype == V_ASN1_NULL || ptype == V_ASN1_UNDEF {
        // SAFETY: no preconditions.
        dsa = unsafe { DSA_new() };
        if dsa.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSA_AMETH_57) };
            // SAFETY: both are NULL on this path.
            unsafe {
                ASN1_STRING_free(public_key);
                DSA_free(dsa);
            }
            return 0;
        }
    } else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_61) };
        // SAFETY: both are NULL on this path.
        unsafe {
            ASN1_STRING_free(public_key);
            DSA_free(dsa);
        }
        return 0;
    }

    // SAFETY: `p` is the public-key octets, `pklen` bounds them, and the first argument is NULL.
    public_key = unsafe {
        ASN1_item_d2i(ptr::null_mut(), &mut p, pklen as c_long, ASN1_INTEGER_it())
            .cast::<Asn1String>()
    };
    if public_key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_66) };
        // SAFETY: both are live or NULL.
        unsafe {
            ASN1_STRING_free(public_key);
            DSA_free(dsa);
        }
        return 0;
    }

    // SAFETY: `dsa` and `public_key` are live.
    unsafe { (*dsa).pub_key = ASN1_INTEGER_to_BN(public_key, ptr::null_mut()) };
    // SAFETY: `dsa` is live.
    if unsafe { (*dsa).pub_key }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_71) };
        // SAFETY: both are live.
        unsafe {
            ASN1_STRING_free(public_key);
            DSA_free(dsa);
        }
        return 0;
    }

    // SAFETY: `dsa` and `public_key` are live.
    unsafe {
        (*dsa).dirty_cnt += 1;
        ASN1_STRING_free(public_key);
        EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa.cast());
    }
    1
}

/// `static int dsa_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)` —
/// `crypto/dsa/dsa_ameth.c:86-142`.
///
/// # Safety
/// `pk` and `pkey` are live.
unsafe extern "C" fn dsa_pub_encode(pk: *mut X509Pubkey, pkey: *const EvpPkey) -> c_int {
    let mut penc: *mut c_uchar = ptr::null_mut();
    let mut str_: *mut Asn1String = ptr::null_mut();

    // SAFETY: `pkey` is live.
    let dsa = unsafe { (*pkey).pkey.cast::<Dsa>() };
    /* The authority's condition is `save_parameters` plus three non-NULL tests; written as a
     * Boolean so `ptype` is the if-expression rather than a late initialization. */
    // SAFETY: `pkey` and `dsa` are live.
    let has_params = unsafe {
        (*pkey).save_parameters != 0
            && !(*dsa).params.p.is_null()
            && !(*dsa).params.q.is_null()
            && !(*dsa).params.g.is_null()
    };
    let ptype = if has_params {
        str_ = ASN1_STRING_new();
        if str_.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSA_AMETH_103) };
            // goto err
            // SAFETY: `penc` is NULL.
            unsafe { CRYPTO_free(penc.cast(), FILE, 139) };
            return 0;
        }
        // SAFETY: `dsa` and `str_` are live.
        unsafe { (*str_).length = i2d_DSAparams(dsa, &mut (*str_).data) };
        // SAFETY: `str_` is live.
        if unsafe { (*str_).length } <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSA_AMETH_108) };
            // goto err
            // SAFETY: `penc` is NULL and `str_` is live.
            unsafe {
                CRYPTO_free(penc.cast(), FILE, 139);
                ASN1_STRING_free(str_);
            }
            return 0;
        }
        V_ASN1_SEQUENCE
    } else {
        V_ASN1_UNDEF
    };

    // SAFETY: `dsa` is live.
    let pubint = unsafe { BN_to_ASN1_INTEGER((*dsa).pub_key, ptr::null_mut()) };

    if pubint.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_118) };
        // goto err
        // SAFETY: `penc` is NULL and `str_` is live.
        unsafe {
            CRYPTO_free(penc.cast(), FILE, 139);
            ASN1_STRING_free(str_);
        }
        return 0;
    }

    // SAFETY: `pubint` is live and `penc` is a live out-parameter.
    let penclen = unsafe { ASN1_item_i2d(pubint.cast(), &mut penc, ASN1_INTEGER_it()) };
    // SAFETY: `pubint` is live.
    unsafe { ASN1_STRING_free(pubint) };

    if penclen <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_126) };
        // goto err
        // SAFETY: `penc` is NULL and `str_` is live.
        unsafe {
            CRYPTO_free(penc.cast(), FILE, 139);
            ASN1_STRING_free(str_);
        }
        return 0;
    }

    // SAFETY: no preconditions.
    let aobj = OBJ_nid2obj(EVP_PKEY_DSA);
    if aobj.is_null() {
        // goto err
        // SAFETY: `penc` is NULL and `str_` is live.
        unsafe {
            CRYPTO_free(penc.cast(), FILE, 139);
            ASN1_STRING_free(str_);
        }
        return 0;
    }

    // SAFETY: `pk` is live and `str_`/`penc` are the objects the setter takes ownership of.
    if unsafe { X509_PUBKEY_set0_param(pk, aobj, ptype, str_.cast(), penc, penclen) } != 0 {
        return 1;
    }

    // SAFETY: both are live.
    unsafe {
        CRYPTO_free(penc.cast(), FILE, 139);
        ASN1_STRING_free(str_);
    }
    0
}

/// `static int dsa_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)` —
/// `crypto/dsa/dsa_ameth.c:149-160`.
///
/// # Safety
/// `pkey` and `p8` are live.
unsafe extern "C" fn dsa_priv_decode(
    pkey: *mut EvpPkey,
    p8: *const crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
) -> c_int {
    // SAFETY: `p8` is live; the two trailing arguments are the authority's NULLs.
    let dsa = unsafe { ossl_dsa_key_from_pkcs8(p8, ptr::null_mut(), ptr::null()) };

    if !dsa.is_null() {
        // SAFETY: `pkey` and `dsa` are live.
        unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa.cast()) };
        return 1;
    }

    0
}

/// `static int dsa_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)` —
/// `crypto/dsa/dsa_ameth.c:162-215`.
///
/// # Safety
/// `p8` and `pkey` are live.
unsafe extern "C" fn dsa_priv_encode(
    p8: *mut crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
    pkey: *const EvpPkey,
) -> c_int {
    let mut dp: *mut c_uchar = ptr::null_mut();

    // SAFETY: `pkey` is live.
    let dsa = unsafe { (*pkey).pkey.cast::<Dsa>() };

    // SAFETY: `pkey` is live.
    if unsafe { (*pkey).pkey.is_null() }
        // SAFETY: `dsa` is live.
        || unsafe { (*dsa).priv_key.is_null() }
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_170) };
        return 0;
    }

    let params = ASN1_STRING_new();

    if params.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_177) };
        // goto err
        // SAFETY: `params` is live.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }

    // SAFETY: `dsa` and `params` are live.
    unsafe { (*params).length = i2d_DSAparams(dsa, &mut (*params).data) };
    // SAFETY: `params` is live.
    if unsafe { (*params).length } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_183) };
        // goto err
        // SAFETY: `params` is live.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }
    // SAFETY: `params` is live.
    unsafe { (*params).type_ = V_ASN1_SEQUENCE };

    /* Get private key into integer */
    // SAFETY: `dsa` is live.
    let prkey = unsafe { BN_to_ASN1_INTEGER((*dsa).priv_key, ptr::null_mut()) };

    if prkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_192) };
        // goto err
        // SAFETY: `params` is live.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }

    // SAFETY: `prkey` is live and `dp` is a live out-parameter.
    let dplen = unsafe { ASN1_item_i2d(prkey.cast(), &mut dp, ASN1_INTEGER_it()) };

    // SAFETY: `prkey` is live.
    unsafe { ASN1_STRING_clear_free(prkey) };

    if dplen <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_201) };
        // goto err
        // SAFETY: `params` is live.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }

    // SAFETY: `p8` is live, the OID is a constant, and `params`/`dp` are the objects the setter
    // takes ownership of.
    if unsafe {
        PKCS8_pkey_set0(
            p8,
            OBJ_nid2obj(NID_dsa),
            0,
            V_ASN1_SEQUENCE,
            params.cast(),
            dp,
            dplen,
        )
    } == 0
    {
        // SAFETY: `dp` is the buffer `dplen` long.
        unsafe { crate::runtime::mem::CRYPTO_clear_free(dp.cast(), dplen as usize, FILE, 207) };
        // goto err
        // SAFETY: `params` is live.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }
    1
}

/// `static int int_dsa_size(const EVP_PKEY *pkey)` — `crypto/dsa/dsa_ameth.c:217-220`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn int_dsa_size(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { DSA_size((*pkey).pkey.cast::<Dsa>()) }
}

/// `static int dsa_bits(const EVP_PKEY *pkey)` — `crypto/dsa/dsa_ameth.c:222-225`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn dsa_bits(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { DSA_bits((*pkey).pkey.cast::<Dsa>()) }
}

/// `static int dsa_security_bits(const EVP_PKEY *pkey)` — `crypto/dsa/dsa_ameth.c:227-230`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn dsa_security_bits(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { DSA_security_bits((*pkey).pkey.cast::<Dsa>()) }
}

/// `static int dsa_missing_parameters(const EVP_PKEY *pkey)` — `crypto/dsa/dsa_ameth.c:232-240`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn dsa_missing_parameters(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe {
        let dsa = (*pkey).pkey.cast::<Dsa>();
        c_int::from(
            dsa.is_null()
                || (*dsa).params.p.is_null()
                || (*dsa).params.q.is_null()
                || (*dsa).params.g.is_null(),
        )
    }
}

/// `static int dsa_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)` —
/// `crypto/dsa/dsa_ameth.c:242-254`.
///
/// # Safety
/// `to` and `from` are live.
unsafe extern "C" fn dsa_copy_parameters(to: *mut EvpPkey, from: *const EvpPkey) -> c_int {
    // SAFETY: `to` is live.
    unsafe {
        if (*to).pkey.is_null() {
            (*to).pkey = DSA_new().cast();
            if (*to).pkey.is_null() {
                return 0;
            }
        }
        if ossl_ffc_params_copy(
            &raw mut (*(*to).pkey.cast::<Dsa>()).params,
            &(*(*from).pkey.cast::<Dsa>()).params,
        ) == 0
        {
            return 0;
        }

        (*(*to).pkey.cast::<Dsa>()).dirty_cnt += 1;
        1
    }
}

/// `static int dsa_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)` —
/// `crypto/dsa/dsa_ameth.c:256-259`.
///
/// # Safety
/// `a` and `b` are live.
unsafe extern "C" fn dsa_cmp_parameters(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    // SAFETY: both keys are live.
    unsafe {
        ossl_ffc_params_cmp(
            &(*(*a).pkey.cast::<Dsa>()).params,
            &(*(*b).pkey.cast::<Dsa>()).params,
            1,
        )
    }
}

/// `static int dsa_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)` —
/// `crypto/dsa/dsa_ameth.c:261-264`.
///
/// # Safety
/// `a` and `b` are live.
unsafe extern "C" fn dsa_pub_cmp(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    // SAFETY: both keys are live.
    unsafe {
        c_int::from(
            BN_cmp(
                (*(*b).pkey.cast::<Dsa>()).pub_key,
                (*(*a).pkey.cast::<Dsa>()).pub_key,
            ) == 0,
        )
    }
}

/// `static void int_dsa_free(EVP_PKEY *pkey)` — `crypto/dsa/dsa_ameth.c:266-269`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn int_dsa_free(pkey: *mut EvpPkey) {
    // SAFETY: `pkey` is live.
    unsafe { DSA_free((*pkey).pkey.cast::<Dsa>()) };
}

/// `static int do_dsa_print(BIO *bp, const DSA *x, int off, int ptype)` —
/// `crypto/dsa/dsa_ameth.c:271-317`.
///
/// # Safety
/// `bp` and `x` are live.
unsafe fn do_dsa_print(bp: *mut Bio, x: *const Dsa, off: c_int, ptype: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut mod_len = 0;
        if !(*x).params.p.is_null() {
            mod_len = DSA_bits(x);
        }

        let priv_key = if ptype == 2 {
            (*x).priv_key
        } else {
            ptr::null_mut()
        };
        let pub_key = if ptype > 0 {
            (*x).pub_key
        } else {
            ptr::null_mut()
        };

        let ktype: *const c_char = if ptype == 2 {
            c"Private-Key".as_ptr()
        } else if ptype == 1 {
            c"Public-Key".as_ptr()
        } else {
            c"DSA-Parameters".as_ptr()
        };

        if !priv_key.is_null() {
            if BIO_indent(bp, off, 128) == 0 {
                return 0;
            }
            if BIO_printf(bp, c"%s: (%d bit)\n".as_ptr(), ktype, mod_len) <= 0 {
                return 0;
            }
        } else if BIO_printf(bp, c"Public-Key: (%d bit)\n".as_ptr(), mod_len) <= 0 {
            return 0;
        }

        if ASN1_bn_print(bp, c"priv:".as_ptr(), priv_key, ptr::null_mut(), off) == 0 {
            return 0;
        }
        if ASN1_bn_print(bp, c"pub: ".as_ptr(), pub_key, ptr::null_mut(), off) == 0 {
            return 0;
        }
        if ossl_ffc_params_print(bp, &(*x).params, off) == 0 {
            return 0;
        }
        1
    }
}

/// `static int dsa_param_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen)` —
/// `crypto/dsa/dsa_ameth.c:319-330`.
///
/// # Safety
/// `pkey` is live; `pder` is a live pointer-to-pointer readable for `derlen` bytes.
unsafe extern "C" fn dsa_param_decode(
    pkey: *mut EvpPkey,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: the caller's contract; the first argument is the authority's NULL.
    let dsa = unsafe { d2i_DSAparams(ptr::null_mut(), pder, derlen as c_long) };
    if dsa.is_null() {
        return 0;
    }

    // SAFETY: `dsa` is live.
    unsafe {
        (*dsa).dirty_cnt += 1;
        EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa.cast());
    }
    1
}

/// `static int dsa_param_encode(const EVP_PKEY *pkey, unsigned char **pder)` —
/// `crypto/dsa/dsa_ameth.c:332-335`.
///
/// # Safety
/// `pkey` is live; `pder` is a live out-parameter.
unsafe extern "C" fn dsa_param_encode(pkey: *const EvpPkey, pder: *mut *mut c_uchar) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { i2d_DSAparams((*pkey).pkey.cast::<Dsa>(), pder) }
}

/// `static int dsa_param_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/dsa/dsa_ameth.c:337-341`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn dsa_param_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { do_dsa_print(bp, (*pkey).pkey.cast::<Dsa>(), indent, 0) }
}

/// `static int dsa_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/dsa/dsa_ameth.c:343-347`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn dsa_pub_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { do_dsa_print(bp, (*pkey).pkey.cast::<Dsa>(), indent, 1) }
}

/// `static int dsa_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/dsa/dsa_ameth.c:349-353`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn dsa_priv_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { do_dsa_print(bp, (*pkey).pkey.cast::<Dsa>(), indent, 2) }
}

/// `static int old_dsa_priv_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen)` —
/// `crypto/dsa/dsa_ameth.c:355-367`.
///
/// # Safety
/// `pkey` is live; `pder` is a live pointer-to-pointer readable for `derlen` bytes.
unsafe extern "C" fn old_dsa_priv_decode(
    pkey: *mut EvpPkey,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: the caller's contract; the first argument is the authority's NULL.
    let dsa = unsafe { d2i_DSAPrivateKey(ptr::null_mut(), pder, derlen as c_long) };
    if dsa.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_361) };
        return 0;
    }
    // SAFETY: `dsa` is live.
    unsafe {
        (*dsa).dirty_cnt += 1;
        EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa.cast());
    }
    1
}

/// `static int old_dsa_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)` —
/// `crypto/dsa/dsa_ameth.c:369-372`.
///
/// # Safety
/// `pkey` is live; `pder` is a live out-parameter.
unsafe extern "C" fn old_dsa_priv_encode(pkey: *const EvpPkey, pder: *mut *mut c_uchar) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { i2d_DSAPrivateKey((*pkey).pkey.cast::<Dsa>(), pder) }
}

/// `static int dsa_sig_print(BIO *bp, const X509_ALGOR *sigalg, const ASN1_STRING *sig, int indent,
/// ASN1_PCTX *pctx)` — `crypto/dsa/dsa_ameth.c:374-409`.
///
/// # Safety
/// `bp` is live; `sig` is NULL or an ASN1_STRING readable for its length.
unsafe extern "C" fn dsa_sig_print(
    bp: *mut Bio,
    _sigalg: *const X509Algor,
    sig: *const Asn1String,
    indent: c_int,
    _pctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `bp` is live.
    if sig.is_null() {
        // SAFETY: `bp` is live.
        if unsafe { BIO_puts(bp, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
        return 1;
    }
    // SAFETY: `sig` is live.
    let p = unsafe { (*sig).data };
    // SAFETY: `sig` is live and `p` is its content of that length.
    let mut p = p.cast_const();
    // SAFETY: `sig` is live and `p` is its content of that length; the first argument is the
    // authority's NULL.
    let dsa_sig = unsafe { d2i_DSA_SIG(ptr::null_mut(), &mut p, (*sig).length as c_long) };
    if !dsa_sig.is_null() {
        let mut rv = 0;
        let mut r: *const BigNum = ptr::null();
        let mut s: *const BigNum = ptr::null();

        // SAFETY: `dsa_sig` is live and both out-parameters are live locals.
        unsafe { DSA_SIG_get0(dsa_sig, &mut r, &mut s) };

        // SAFETY: `bp` is live.
        if unsafe { BIO_write(bp, c"\n".as_ptr().cast(), 1) } != 1 {
            // SAFETY: `dsa_sig` is live.
            unsafe { DSA_SIG_free(dsa_sig) };
            return rv;
        }

        // SAFETY: `bp` is live and `r`/`s` are live.
        if unsafe { ASN1_bn_print(bp, c"r:   ".as_ptr(), r, ptr::null_mut(), indent) } == 0
            // SAFETY: `bp` is live.
            || unsafe { ASN1_bn_print(bp, c"s:   ".as_ptr(), s, ptr::null_mut(), indent) } == 0
        {
            // SAFETY: `dsa_sig` is live.
            unsafe { DSA_SIG_free(dsa_sig) };
            return rv;
        }
        rv = 1;
        // SAFETY: `dsa_sig` is live.
        unsafe { DSA_SIG_free(dsa_sig) };
        return rv;
    }
    // SAFETY: `bp` is live.
    if unsafe { BIO_puts(bp, c"\n".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `bp` and `sig` are live.
    unsafe { X509_signature_dump(bp, sig, indent) }
}

/// `static int dsa_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)` —
/// `crypto/dsa/dsa_ameth.c:411-421`.
///
/// The one supported operation answers SHA-256 and returns 1 — not 2, so the digest is not marked
/// mandatory.
///
/// # Safety
/// `arg2` is a writable `int *` for the one supported operation.
unsafe extern "C" fn dsa_pkey_ctrl(
    _pkey: *mut EvpPkey,
    op: c_int,
    _arg1: c_long,
    arg2: *mut c_void,
) -> c_int {
    match op {
        ASN1_PKEY_CTRL_DEFAULT_MD_NID => {
            // SAFETY: `arg2` is the caller's writable `int *`.
            unsafe { *(arg2.cast::<c_int>()) = NID_sha256 };
            1
        }
        _ => -2,
    }
}

/// `static size_t dsa_pkey_dirty_cnt(const EVP_PKEY *pkey)` — `crypto/dsa/dsa_ameth.c:423-426`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn dsa_pkey_dirty_cnt(pkey: *const EvpPkey) -> usize {
    // SAFETY: `pkey` is live.
    unsafe { (*(*pkey).pkey.cast::<Dsa>()).dirty_cnt }
}

/// `static int dsa_pkey_export_to(const EVP_PKEY *from, void *to_keydata,
/// OSSL_FUNC_keymgmt_import_fn *importer, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/dsa/dsa_ameth.c:428-476`.
///
/// # Safety
/// `from` is live; `to_keydata` is the importer's own object.
unsafe extern "C" fn dsa_pkey_export_to(
    from: *const EvpPkey,
    to_keydata: *mut c_void,
    importer: Option<KeymgmtImportFn>,
    _libctx: *mut c_void,
    _propq: *const c_char,
) -> c_int {
    let mut selection: c_int = 0;

    // SAFETY: `from` is live.
    let dsa = unsafe { (*from).pkey.cast::<Dsa>() };
    // SAFETY: `dsa` is live.
    let (p, g) = unsafe { (DSA_get0_p(dsa), DSA_get0_g(dsa)) };
    // SAFETY: `dsa` is live.
    let (q, pub_key) = unsafe { (DSA_get0_q(dsa), DSA_get0_pub_key(dsa)) };
    // SAFETY: `dsa` is live.
    let priv_key = unsafe { DSA_get0_priv_key(dsa) };

    if p.is_null() || q.is_null() || g.is_null() {
        return 0;
    }

    let tmpl = OSSL_PARAM_BLD_new();
    if tmpl.is_null() {
        return 0;
    }

    // SAFETY: `tmpl` is live and the three BIGNUMs are live.
    if unsafe {
        OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, p) == 0
            || OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_Q, q) == 0
            || OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, g) == 0
    } {
        // goto err
        // SAFETY: `tmpl` is live.
        unsafe { OSSL_PARAM_BLD_free(tmpl) };
        return 0;
    }
    selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
    if !pub_key.is_null() {
        // SAFETY: `tmpl` is live and `pub_key` is live.
        if unsafe { OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PUB_KEY, pub_key) } == 0 {
            // SAFETY: `tmpl` is live.
            unsafe { OSSL_PARAM_BLD_free(tmpl) };
            return 0;
        }
        selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    }
    if !priv_key.is_null() {
        // SAFETY: `tmpl` is live and `priv_key` is live.
        if unsafe { OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, priv_key) } == 0 {
            // SAFETY: `tmpl` is live.
            unsafe { OSSL_PARAM_BLD_free(tmpl) };
            return 0;
        }
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    }

    // SAFETY: `tmpl` is live.
    let params = unsafe { OSSL_PARAM_BLD_to_param(tmpl) };
    if params.is_null() {
        // SAFETY: `tmpl` is live.
        unsafe { OSSL_PARAM_BLD_free(tmpl) };
        return 0;
    }

    /* We export, the provider imports */
    // SAFETY: `importer` is the destination's own function.
    let rv = unsafe { importer.map_or(0, |f| f(to_keydata, selection, params)) };

    // SAFETY: `params` is live.
    unsafe { OSSL_PARAM_free(params) };
    // SAFETY: `tmpl` is live.
    unsafe { OSSL_PARAM_BLD_free(tmpl) };
    rv
}

/// `static int dsa_pkey_import_from(const OSSL_PARAM params[], void *vpctx)` —
/// `crypto/dsa/dsa_ameth.c:478-496`.
///
/// # Safety
/// `params` is a live parameter array; `vpctx` is a live `EVP_PKEY_CTX`.
unsafe extern "C" fn dsa_pkey_import_from(params: *const OsslParam, vpctx: *mut c_void) -> c_int {
    let pctx = vpctx.cast::<crate::evp::pkey_ctx::EvpPkeyCtx>();
    // SAFETY: `pctx` is live per the contract.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
    // SAFETY: `pctx` is live.
    let dsa = unsafe { ossl_dsa_new((*pctx).libctx) };

    if dsa.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_AMETH_485) };
        return 0;
    }

    // SAFETY: `dsa` is live, `params` is the caller's array, and `pkey` is live.
    if unsafe {
        ossl_dsa_ffc_params_fromdata(dsa, params) == 0
            || ossl_dsa_key_fromdata(dsa, params, 1) == 0
            || EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa.cast()) == 0
    } {
        // SAFETY: `dsa` is live.
        unsafe { DSA_free(dsa) };
        return 0;
    }
    1
}

/// `static int dsa_pkey_copy(EVP_PKEY *to, EVP_PKEY *from)` — `crypto/dsa/dsa_ameth.c:498-514`.
///
/// # Safety
/// `to` and `from` are live.
unsafe extern "C" fn dsa_pkey_copy(to: *mut EvpPkey, from: *mut EvpPkey) -> c_int {
    // SAFETY: `from` is live.
    let dsa = unsafe { (*from).pkey.cast::<Dsa>() };
    let mut dupkey: *mut Dsa = ptr::null_mut();

    if !dsa.is_null() {
        // SAFETY: `dsa` is live.
        dupkey = unsafe { ossl_dsa_dup(dsa, OSSL_KEYMGMT_SELECT_ALL_BITS) };
        if dupkey.is_null() {
            return 0;
        }
    }

    // SAFETY: `to` is live.
    let ret = unsafe { EVP_PKEY_assign(to, EVP_PKEY_DSA, dupkey.cast()) };
    if ret == 0 {
        // SAFETY: `dupkey` is live.
        unsafe { DSA_free(dupkey) };
    }
    ret
}

/// `const EVP_PKEY_ASN1_METHOD ossl_dsa_asn1_meths[4]` — `crypto/dsa/dsa_ameth.c:518-579`.
///
/// Sorted by `pkey_id`, lowest first, which the authority's own comment says. Rows `[0]`, `[1]` and
/// `[2]` are aliases: DSA1 → DSA, DSA4 → DSA2 and DSA3 → DSA2, where the macros expand to
/// `NID_dsa_2`, `NID_dsaWithSHA1_2` and `NID_dsaWithSHA1` and the bases to `NID_dsa` and
/// `NID_dsaWithSHA`.
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_dsa_asn1_meths: [EvpPkeyAsn1Method; 4] = [
    EvpPkeyAsn1Method {
        pkey_id: EVP_PKEY_DSA1,
        pkey_base_id: EVP_PKEY_DSA,
        pkey_flags: ASN1_PKEY_ALIAS,
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
    EvpPkeyAsn1Method {
        pkey_id: EVP_PKEY_DSA4,
        pkey_base_id: EVP_PKEY_DSA2,
        pkey_flags: ASN1_PKEY_ALIAS,
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
    EvpPkeyAsn1Method {
        pkey_id: EVP_PKEY_DSA3,
        pkey_base_id: EVP_PKEY_DSA2,
        pkey_flags: ASN1_PKEY_ALIAS,
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
    EvpPkeyAsn1Method {
        pkey_id: EVP_PKEY_DSA,
        pkey_base_id: EVP_PKEY_DSA,
        pkey_flags: 0,
        pem_str: c"DSA".as_ptr().cast_mut(),
        info: c"OpenSSL DSA method".as_ptr().cast_mut(),
        pub_decode: Some(dsa_pub_decode),
        pub_encode: Some(dsa_pub_encode),
        pub_cmp: Some(dsa_pub_cmp),
        pub_print: Some(dsa_pub_print),
        priv_decode: Some(dsa_priv_decode),
        priv_encode: Some(dsa_priv_encode),
        priv_print: Some(dsa_priv_print),
        pkey_size: Some(int_dsa_size),
        pkey_bits: Some(dsa_bits),
        pkey_security_bits: Some(dsa_security_bits),
        param_decode: Some(dsa_param_decode),
        param_encode: Some(dsa_param_encode),
        param_missing: Some(dsa_missing_parameters),
        param_copy: Some(dsa_copy_parameters),
        param_cmp: Some(dsa_cmp_parameters),
        param_print: Some(dsa_param_print),
        sig_print: Some(dsa_sig_print),
        pkey_free: Some(int_dsa_free),
        pkey_ctrl: Some(dsa_pkey_ctrl),
        old_priv_decode: Some(old_dsa_priv_decode),
        old_priv_encode: Some(old_dsa_priv_encode),
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
        dirty_cnt: Some(dsa_pkey_dirty_cnt),
        export_to: Some(dsa_pkey_export_to),
        import_from: Some(dsa_pkey_import_from),
        copy: Some(dsa_pkey_copy),
        priv_decode_ex: None,
    },
];
