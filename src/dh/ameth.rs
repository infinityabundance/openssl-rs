//! `crypto/dh/dh_ameth.c` — the whole unit: the two `EVP_PKEY_ASN1_METHOD` objects and every
//! callback they name.
//!
//! D345 landed two of the file's exports (`DHparams_dup`, `DHparams_print`) in this module while the
//! method objects were withheld on D341's cycle, and recorded that `dh_ameth.c` then had no module
//! of its own edge. 8.8 lands the objects, and the unit is now transcribed **whole**: the decode and
//! encode callbacks, the two private-key readers, the three prints, the six FFC parameter callbacks,
//! the five key checks and the provider bridge (`export_to`/`import_from`/`copy`), plus the two
//! `const EVP_PKEY_ASN1_METHOD` objects at `:560-648`.
//!
//! ## The identity comparisons are addresses, and the objects are `static` for that reason
//!
//! `d2i_dhp`, `i2d_dhp`, `dh_cmp_parameters` and `dh_copy_parameters` all compare `pkey->ameth`
//! against `&ossl_dhx_asn1_meth` to decide PKCS#3 versus X9.42. That is only meaningful if every
//! `EVP_PKEY_ASN1_METHOD *` for that object is the same address, so the eleven objects are declared
//! `static` (and `EvpPkeyAsn1Method` carries a documented `unsafe impl Sync` — see
//! `src/evp/pkey_asn1.rs`), not `const`s whose addresses the compiler may duplicate.
//!
//! ## The raise sites are generated, and the one that was hand-reconstructed retires
//!
//! D345's partial transcription reconstructed `do_dh_print`'s `ERR_raise` at `dh_ameth.c:297` by
//! hand because the unit was not in `gen_err_raise_sites.py`'s covered set. It is now: the generator
//! emits the unit's fourteen sites, `DO_DH_PRINT`'s among them as `DH_AMETH_297` with
//! `dynamic_reason` true (the authority raises a variable `reason`), so the site is raised with
//! `raise_site_dynamic` and the hand-written constant is gone.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_INTEGER_it;
use crate::asn1::layout::{Asn1Pctx, Asn1String, V_ASN1_SEQUENCE};
use crate::asn1::p8_pkey::PKCS8_pkey_set0;
use crate::asn1::prim::{ASN1_INTEGER_to_BN, BN_to_ASN1_INTEGER};
use crate::asn1::string::{ASN1_STRING_clear_free, ASN1_STRING_free, ASN1_STRING_new};
use crate::asn1::t_pkey::ASN1_bn_print;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0};
use crate::bn::arith::BN_cmp;
use crate::dh::asn1::{d2i_DHparams, d2i_DHxparams, i2d_DHparams, i2d_DHxparams};
use crate::dh::backend::{
    ossl_dh_dup, ossl_dh_key_from_pkcs8, ossl_dh_key_fromdata, ossl_dh_params_fromdata,
};
use crate::dh::check::{DH_check_ex, DH_check_pub_key_ex};
use crate::dh::key::{ossl_dh_buf2key, ossl_dh_key2buf};
use crate::dh::object::{
    ossl_dh_new_ex, DH_bits, DH_clear_flags, DH_free, DH_get0_g, DH_get0_p, DH_get0_priv_key,
    DH_get0_pub_key, DH_get0_q, DH_get_length, DH_new, DH_security_bits, DH_set_flags, DH_size,
};
use crate::dh::Dh;
use crate::evp::keymgmt::KeymgmtImportFn;
use crate::evp::pkey::{
    evp_pkey_get0_DH_int, evp_pkey_is_legacy, EVP_PKEY_assign, EvpPkey,
    OSSL_KEYMGMT_SELECT_ALL_BITS, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
    OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
};
use crate::evp::pkey_asn1::EvpPkeyAsn1Method;
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_get0_pkey, EVP_PKEY_DH, EVP_PKEY_DHX, OSSL_PKEY_PARAM_DH_PRIV_LEN,
    OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_Q,
};
use crate::ffc::params::{ossl_ffc_params_cmp, ossl_ffc_params_copy, ossl_ffc_params_print};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN, OSSL_PARAM_BLD_push_long,
    OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::OsslParam;
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site, raise_site_dynamic};
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::OBJ_nid2obj;
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_get0_param, X509_PUBKEY_set0_param};

/// `ASN1_PKEY_CTRL_SET1_TLS_ENCPT` — `include/openssl/evp.h:1614`.
const ASN1_PKEY_CTRL_SET1_TLS_ENCPT: c_int = 0x9;
/// `ASN1_PKEY_CTRL_GET1_TLS_ENCPT` — `include/openssl/evp.h:1615`.
const ASN1_PKEY_CTRL_GET1_TLS_ENCPT: c_int = 0xa;
/// `DH_FLAG_TYPE_MASK` — `include/openssl/dh.h:110`.
const DH_FLAG_TYPE_MASK: c_int = 0xF000;
/// `DH_FLAG_TYPE_DH` — `include/openssl/dh.h:111`. The zero word: a PKCS#3 parameter set.
const DH_FLAG_TYPE_DH: c_int = 0x0000;
/// `DH_FLAG_TYPE_DHX` — `include/openssl/dh.h:112`. X9.42.
const DH_FLAG_TYPE_DHX: c_int = 0x1000;
/// The authority's translation unit, for the two `OPENSSL_free`/`OPENSSL_clear_free` sites below
/// whose authority marks are recorded against it.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/dh/dh_ameth.c".as_ptr();

/// `static DH *d2i_dhp(const EVP_PKEY *pkey, const unsigned char **pp, long length)` —
/// `crypto/dh/dh_ameth.c:34-46`.
///
/// The PKCS#3/X9.42 choice is the method's identity, not the encoding.
///
/// # Safety
/// `pkey` is live; `pp` is a live pointer-to-pointer; `length` bounds it.
unsafe fn d2i_dhp(pkey: *const EvpPkey, pp: *mut *const c_uchar, length: c_long) -> *mut Dh {
    let is_dhx = ptr::eq(
        // SAFETY: `pkey` is live per the contract.
        unsafe { (*pkey).ameth.cast_const() },
        &raw const ossl_dhx_asn1_meth,
    );

    if is_dhx {
        // SAFETY: the caller's contract.
        unsafe { d2i_DHxparams(ptr::null_mut(), pp, length) }
    } else {
        // SAFETY: the caller's contract.
        unsafe { d2i_DHparams(ptr::null_mut(), pp, length) }
    }
}

/// `static int i2d_dhp(const EVP_PKEY *pkey, const DH *a, unsigned char **pp)` —
/// `crypto/dh/dh_ameth.c:48-53`.
///
/// # Safety
/// `pkey` and `a` are live; `pp` is a live out-parameter.
unsafe fn i2d_dhp(pkey: *const EvpPkey, a: *const Dh, pp: *mut *mut c_uchar) -> c_int {
    let is_dhx = ptr::eq(
        // SAFETY: `pkey` is live per the contract.
        unsafe { (*pkey).ameth.cast_const() },
        &raw const ossl_dhx_asn1_meth,
    );

    if is_dhx {
        // SAFETY: the caller's contract.
        unsafe { i2d_DHxparams(a, pp) }
    } else {
        // SAFETY: the caller's contract.
        unsafe { i2d_DHparams(a, pp) }
    }
}

/// `static void int_dh_free(EVP_PKEY *pkey)` — `crypto/dh/dh_ameth.c:55-58`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn int_dh_free(pkey: *mut EvpPkey) {
    // SAFETY: `pkey` is live.
    unsafe { DH_free((*pkey).pkey.cast::<Dh>()) };
}

/// `static int dh_pub_decode(EVP_PKEY *pkey, const X509_PUBKEY *pubkey)` —
/// `crypto/dh/dh_ameth.c:60-109`.
///
/// # Safety
/// `pkey` and `pubkey` are live.
unsafe extern "C" fn dh_pub_decode(pkey: *mut EvpPkey, pubkey: *const X509Pubkey) -> c_int {
    let mut p: *const c_uchar = ptr::null();
    let mut pklen: c_int = 0;
    let mut ptype: c_int = 0;
    let mut pval: *const c_void = ptr::null();
    let mut palg: *mut X509Algor = ptr::null_mut();
    let mut public_key: *mut Asn1String = ptr::null_mut();
    let mut dh: *mut Dh = ptr::null_mut();

    // SAFETY: `pubkey` is live, the four out-parameters are live locals, and the first argument is
    // the authority's own NULL.
    if unsafe { X509_PUBKEY_get0_param(ptr::null_mut(), &mut p, &mut pklen, &mut palg, pubkey) }
        == 0
    {
        return 0;
    }
    // SAFETY: `palg` is live and the three out-parameters are live locals.
    unsafe { X509_ALGOR_get0(ptr::null_mut(), &mut ptype, &mut pval, palg) };

    if ptype != V_ASN1_SEQUENCE {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_77) };
        // goto err
        // SAFETY: `public_key` is NULL and `dh` is NULL on this path.
        unsafe {
            ASN1_STRING_free(public_key);
            DH_free(dh);
        }
        return 0;
    }

    /* pstr = pval; pm = pstr->data; pmlen = pstr->length; */
    let pstr = pval.cast::<Asn1String>();
    // SAFETY: `pstr` is the ASN1_STRING the algorithm identifier carries.
    let mut pm = unsafe { (*pstr).data }.cast_const();
    // SAFETY: `pstr` is the ASN1_STRING whose content `pm` points into.
    let pmlen = unsafe { (*pstr).length } as c_long;

    // SAFETY: `pkey` is live; `pm`/`pmlen` are the string's content.
    dh = unsafe { d2i_dhp(pkey, &mut pm, pmlen) };
    if dh.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_86) };
        // goto err
        // SAFETY: the decode just failed, so `dh` is NULL and `public_key` is still NULL.
        unsafe {
            ASN1_STRING_free(public_key);
            DH_free(dh);
        }
        return 0;
    }

    // SAFETY: `p` is the public-key octets and `pklen` bounds them; the item decoder's first
    // argument is the authority's NULL.
    public_key = unsafe {
        ASN1_item_d2i(ptr::null_mut(), &mut p, pklen as c_long, ASN1_INTEGER_it())
            .cast::<Asn1String>()
    };
    if public_key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_91) };
        // goto err
        // SAFETY: `dh` is live and owns the reference; `public_key` is NULL.
        unsafe {
            ASN1_STRING_free(public_key);
            DH_free(dh);
        }
        return 0;
    }

    /* We have parameters now set public key */
    // SAFETY: `dh` is live and `public_key` is live.
    unsafe { (*dh).pub_key = ASN1_INTEGER_to_BN(public_key, ptr::null_mut()) };
    // SAFETY: `dh` is live.
    if unsafe { (*dh).pub_key }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_97) };
        // goto err
        // SAFETY: `dh` and `public_key` are both live.
        unsafe {
            ASN1_STRING_free(public_key);
            DH_free(dh);
        }
        return 0;
    }

    // SAFETY: both are live.
    unsafe {
        ASN1_STRING_free(public_key);
        EVP_PKEY_assign(
            pkey,
            (*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id),
            dh.cast(),
        );
    }
    1
}

/// `static int dh_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)` —
/// `crypto/dh/dh_ameth.c:111-156`.
///
/// # Safety
/// `pk` and `pkey` are live.
unsafe extern "C" fn dh_pub_encode(pk: *mut X509Pubkey, pkey: *const EvpPkey) -> c_int {
    let mut penc: *mut c_uchar = ptr::null_mut();

    // SAFETY: `pkey` is live.
    let dh = unsafe { (*pkey).pkey.cast::<Dh>() };

    let str_ = ASN1_STRING_new();
    if str_.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_124) };
        // goto err
        // SAFETY: `penc` is NULL and `str_` is NULL on this path.
        unsafe {
            CRYPTO_free(penc.cast(), FILE, 152);
            ASN1_STRING_free(str_);
        }
        return 0;
    }
    // SAFETY: `pkey` and `dh` are live; `str_` is live.
    unsafe { (*str_).length = i2d_dhp(pkey, dh, &mut (*str_).data) };
    // SAFETY: `str_` is live.
    if unsafe { (*str_).length } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_129) };
        // goto err
        // SAFETY: `penc` is the buffer `enc` bytes long and `str_` is live.
        unsafe {
            CRYPTO_free(penc.cast(), FILE, 152);
            ASN1_STRING_free(str_);
        }
        return 0;
    }
    let ptype = V_ASN1_SEQUENCE;

    // SAFETY: `dh` is live.
    let pub_key = unsafe { BN_to_ASN1_INTEGER((*dh).pub_key, ptr::null_mut()) };
    if pub_key.is_null() {
        // goto err
        // SAFETY: both are live.
        unsafe {
            CRYPTO_free(penc.cast(), FILE, 152);
            ASN1_STRING_free(str_);
        }
        return 0;
    }

    // SAFETY: `pub_key` is live and `penc` is a live out-parameter.
    let penclen = unsafe { ASN1_item_i2d(pub_key.cast(), &mut penc, ASN1_INTEGER_it()) };

    // SAFETY: `pub_key` is live.
    unsafe { ASN1_STRING_free(pub_key) };

    if penclen <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_143) };
        // goto err
        // SAFETY: `penc` is the buffer `enc` bytes long and `str_` is live.
        unsafe {
            CRYPTO_free(penc.cast(), FILE, 152);
            ASN1_STRING_free(str_);
        }
        return 0;
    }

    // SAFETY: `pk` is live, `pkey->ameth` is live, and `str_`/`penc` are the objects the setter
    // takes ownership of.
    if unsafe {
        X509_PUBKEY_set0_param(
            pk,
            OBJ_nid2obj((*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id)),
            ptype,
            str_.cast(),
            penc,
            penclen,
        )
    } != 0
    {
        return 1;
    }

    // SAFETY: no failure arm is reachable past the setter's own refusal.
    unsafe {
        CRYPTO_free(penc.cast(), FILE, 152);
        ASN1_STRING_free(str_);
    }
    0
}

/// `static int dh_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)` —
/// `crypto/dh/dh_ameth.c:164-175`.
///
/// # Safety
/// `pkey` and `p8` are live.
unsafe extern "C" fn dh_priv_decode(
    pkey: *mut EvpPkey,
    p8: *const crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
) -> c_int {
    // SAFETY: `p8` is live; the two trailing arguments are the authority's NULLs.
    let dh = unsafe { ossl_dh_key_from_pkcs8(p8, ptr::null_mut(), ptr::null()) };

    if !dh.is_null() {
        // SAFETY: `pkey` is live and `dh` is live.
        unsafe {
            EVP_PKEY_assign(
                pkey,
                (*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id),
                dh.cast(),
            );
        }
        return 1;
    }

    0
}

/// `static int dh_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)` —
/// `crypto/dh/dh_ameth.c:177-225`.
///
/// # Safety
/// `p8` and `pkey` are live.
unsafe extern "C" fn dh_priv_encode(
    p8: *mut crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
    pkey: *const EvpPkey,
) -> c_int {
    let mut dp: *mut c_uchar = ptr::null_mut();

    let params = ASN1_STRING_new();

    if params.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_187) };
        // goto err
        // SAFETY: `params` is NULL on this path.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }

    // SAFETY: `pkey` is live; `params` is live.
    unsafe { (*params).length = i2d_dhp(pkey, (*pkey).pkey.cast::<Dh>(), &mut (*params).data) };
    // SAFETY: `params` is live.
    if unsafe { (*params).length } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_193) };
        // goto err
        // SAFETY: `params` is live.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }
    // SAFETY: `params` is live.
    unsafe { (*params).type_ = V_ASN1_SEQUENCE };

    /* Get private key into integer */
    // SAFETY: `pkey` is live.
    let prkey =
        unsafe { BN_to_ASN1_INTEGER((*(*pkey).pkey.cast::<Dh>()).priv_key, ptr::null_mut()) };

    if prkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_202) };
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
        unsafe { raise_site(&err_sites::DH_AMETH_211) };
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
            OBJ_nid2obj((*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id)),
            0,
            V_ASN1_SEQUENCE,
            params.cast(),
            dp,
            dplen,
        )
    } == 0
    {
        // SAFETY: `dp` is the buffer `dplen` long.
        unsafe { crate::runtime::mem::CRYPTO_clear_free(dp.cast(), dplen as usize, FILE, 217) };
        // goto err
        // SAFETY: `params` is live.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }
    1
}

/// `static int dh_param_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen)` —
/// `crypto/dh/dh_ameth.c:227-237`.
///
/// # Safety
/// `pkey` is live; `pder` is a live pointer-to-pointer readable for `derlen` bytes.
unsafe extern "C" fn dh_param_decode(
    pkey: *mut EvpPkey,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: `pkey` is live and the two other arguments are the caller's.
    let dh = unsafe { d2i_dhp(pkey, pder, derlen as c_long) };
    if dh.is_null() {
        return 0;
    }
    // SAFETY: `dh` is live.
    unsafe {
        (*dh).dirty_cnt += 1;
        EVP_PKEY_assign(
            pkey,
            (*pkey).ameth.as_ref().map_or(0, |m| m.pkey_id),
            dh.cast(),
        );
    }
    1
}

/// `static int dh_param_encode(const EVP_PKEY *pkey, unsigned char **pder)` —
/// `crypto/dh/dh_ameth.c:239-242`.
///
/// # Safety
/// `pkey` is live; `pder` is a live out-parameter.
unsafe extern "C" fn dh_param_encode(pkey: *const EvpPkey, pder: *mut *mut c_uchar) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { i2d_dhp(pkey, (*pkey).pkey.cast::<Dh>(), pder) }
}

/// `static int do_dh_print(BIO *bp, const DH *x, int indent, int ptype)` —
/// `crypto/dh/dh_ameth.c:244-299`.
///
/// `ptype` is `0` for parameters, `1` for a public key and `2` for a private one; the authority
/// writes one function because the three prints differ only in which of the two scalars they
/// show and the label they lead with.
///
/// # Safety
/// `bp` is a live BIO; `x` is a live key.
unsafe fn do_dh_print(bp: *mut Bio, x: *const Dh, indent: c_int, ptype: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut reason = ERR_R_BUF_LIB;

        let priv_key = if ptype == 2 {
            (*x).priv_key
        } else {
            core::ptr::null_mut()
        };
        let pub_key = if ptype > 0 {
            (*x).pub_key
        } else {
            core::ptr::null_mut()
        };

        if (*x).params.p.is_null()
            || (ptype == 2 && priv_key.is_null())
            || (ptype > 0 && pub_key.is_null())
        {
            reason = ERR_R_PASSED_NULL_PARAMETER;
            // goto err
            raise_site_dynamic(&err_sites::DH_AMETH_297, reason);
            return 0;
        }

        let ktype: *const c_char = if ptype == 2 {
            c"DH Private-Key".as_ptr()
        } else if ptype == 1 {
            c"DH Public-Key".as_ptr()
        } else {
            c"DH Parameters".as_ptr()
        };

        if BIO_indent(bp, indent, 128) == 0
            || BIO_printf(bp, c"%s: (%d bit)\n".as_ptr(), ktype, DH_bits(x)) <= 0
        {
            raise_site_dynamic(&err_sites::DH_AMETH_297, reason);
            return 0;
        }
        let indent = indent + 4;

        if ASN1_bn_print(
            bp,
            c"private-key:".as_ptr(),
            priv_key,
            core::ptr::null_mut(),
            indent,
        ) == 0
        {
            raise_site_dynamic(&err_sites::DH_AMETH_297, reason);
            return 0;
        }
        if ASN1_bn_print(
            bp,
            c"public-key:".as_ptr(),
            pub_key,
            core::ptr::null_mut(),
            indent,
        ) == 0
        {
            raise_site_dynamic(&err_sites::DH_AMETH_297, reason);
            return 0;
        }

        if ossl_ffc_params_print(bp, &(*x).params, indent) == 0 {
            raise_site_dynamic(&err_sites::DH_AMETH_297, reason);
            return 0;
        }

        if (*x).length != 0
            && (BIO_indent(bp, indent, 128) == 0
                || BIO_printf(
                    bp,
                    c"recommended-private-length: %d bits\n".as_ptr(),
                    (*x).length,
                ) <= 0)
        {
            raise_site_dynamic(&err_sites::DH_AMETH_297, reason);
            return 0;
        }

        1
    }
}

/// `static int int_dh_size(const EVP_PKEY *pkey)` — `crypto/dh/dh_ameth.c:301-304`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn int_dh_size(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { DH_size((*pkey).pkey.cast::<Dh>()) }
}

/// `static int dh_bits(const EVP_PKEY *pkey)` — `crypto/dh/dh_ameth.c:306-309`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn dh_bits(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { DH_bits((*pkey).pkey.cast::<Dh>()) }
}

/// `static int dh_security_bits(const EVP_PKEY *pkey)` — `crypto/dh/dh_ameth.c:311-314`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn dh_security_bits(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { DH_security_bits((*pkey).pkey.cast::<Dh>()) }
}

/// `static int dh_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)` —
/// `crypto/dh/dh_ameth.c:316-320`.
///
/// The last argument is `a->ameth != &ossl_dhx_asn1_meth`: PKCS#3 parameters are compared with the
/// `q`-less rule and X9.42 with the `q`-aware one.
///
/// # Safety
/// `a` and `b` are live.
unsafe extern "C" fn dh_cmp_parameters(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    let not_dhx = c_int::from(!ptr::eq(
        // SAFETY: `a` is live.
        unsafe { (*a).ameth.cast_const() },
        &raw const ossl_dhx_asn1_meth,
    ));
    // SAFETY: both keys are live.
    unsafe {
        ossl_ffc_params_cmp(
            &(*(*a).pkey.cast::<Dh>()).params,
            &(*(*b).pkey.cast::<Dh>()).params,
            not_dhx,
        )
    }
}

/// `static int int_dh_param_copy(DH *to, const DH *from, int is_x942)` —
/// `crypto/dh/dh_ameth.c:322-332`.
///
/// `is_x942 == -1` asks the function to read the object: a `q` means X9.42, and in that case the
/// `length` field is left alone because it describes a `q`-less PKCS#3 recommendation.
///
/// # Safety
/// `to` is a live, writable key; `from` is a live key; neither is the other.
unsafe fn int_dh_param_copy(to: *mut Dh, from: *const Dh, is_x942: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut is_x942 = is_x942;
        if is_x942 == -1 {
            is_x942 = c_int::from(!(*from).params.q.is_null());
        }
        if ossl_ffc_params_copy(&raw mut (*to).params, &(*from).params) == 0 {
            return 0;
        }
        if is_x942 == 0 {
            (*to).length = (*from).length;
        }
        (*to).dirty_cnt += 1;
        1
    }
}

/// `DH *DHparams_dup(const DH *dh)` — `crypto/dh/dh_ameth.c:334-345`.
///
/// A fresh object with the same FFC parameters. `-1` is the authority's "read `is_x942` from the
/// source" argument, and the duplicate's old value is released on a copy failure.
///
/// # Safety
/// `dh` is a live key.
#[no_mangle]
pub unsafe extern "C" fn DHparams_dup(dh: *const Dh) -> *mut Dh {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let ret = DH_new();
        if ret.is_null() {
            return ret;
        }
        if int_dh_param_copy(ret, dh, -1) == 0 {
            DH_free(ret);
            return core::ptr::null_mut();
        }
        ret
    }
}

/// `static int dh_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)` —
/// `crypto/dh/dh_ameth.c:347-356`.
///
/// # Safety
/// `to` and `from` are live.
unsafe extern "C" fn dh_copy_parameters(to: *mut EvpPkey, from: *const EvpPkey) -> c_int {
    // SAFETY: `to` is live.
    unsafe {
        if (*to).pkey.is_null() {
            (*to).pkey = DH_new().cast();
            if (*to).pkey.is_null() {
                return 0;
            }
        }
        let is_x942 = c_int::from(ptr::eq(
            (*from).ameth.cast_const(),
            &raw const ossl_dhx_asn1_meth,
        ));
        int_dh_param_copy((*to).pkey.cast::<Dh>(), (*from).pkey.cast::<Dh>(), is_x942)
    }
}

/// `static int dh_missing_parameters(const EVP_PKEY *a)` — `crypto/dh/dh_ameth.c:358-363`.
///
/// # Safety
/// `a` is live.
unsafe extern "C" fn dh_missing_parameters(a: *const EvpPkey) -> c_int {
    // SAFETY: `a` is live.
    unsafe {
        let dh = (*a).pkey.cast::<Dh>();
        c_int::from(dh.is_null() || (*dh).params.p.is_null() || (*dh).params.g.is_null())
    }
}

/// `static int dh_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)` —
/// `crypto/dh/dh_ameth.c:365-373`.
///
/// # Safety
/// `a` and `b` are live.
unsafe extern "C" fn dh_pub_cmp(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    // SAFETY: both keys are live.
    if unsafe { dh_cmp_parameters(a, b) } == 0 {
        return 0;
    }
    // SAFETY: both keys are live.
    if unsafe {
        BN_cmp(
            (*(*b).pkey.cast::<Dh>()).pub_key,
            (*(*a).pkey.cast::<Dh>()).pub_key,
        )
    } != 0
    {
        0
    } else {
        1
    }
}

/// `static int dh_param_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/dh/dh_ameth.c:375-379`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn dh_param_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { do_dh_print(bp, (*pkey).pkey.cast::<Dh>(), indent, 0) }
}

/// `static int dh_public_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/dh/dh_ameth.c:381-385`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn dh_public_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { do_dh_print(bp, (*pkey).pkey.cast::<Dh>(), indent, 1) }
}

/// `static int dh_private_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/dh/dh_ameth.c:387-391`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn dh_private_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { do_dh_print(bp, (*pkey).pkey.cast::<Dh>(), indent, 2) }
}

/// `int DHparams_print(BIO *bp, const DH *x)` — `crypto/dh/dh_ameth.c:393-396`.
///
/// The parameters spelling of [`do_dh_print`], with the authority's own `indent == 4`.
///
/// # Safety
/// `bp` is a live BIO; `x` is a live key.
#[no_mangle]
pub unsafe extern "C" fn DHparams_print(bp: *mut Bio, x: *const Dh) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { do_dh_print(bp, x, 4, 0) }
}

/// `static int dh_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)` —
/// `crypto/dh/dh_ameth.c:398-418`.
///
/// The two TLS arms are the only `ASN1_PKEY_CTRL` operations the method supports, and each refuses
/// with `0` when the low-level key is absent. `ossl_assert` under `NDEBUG` is `(x) != 0`, so the
/// legacy-key guard is a released-build refusal and is transcribed as one.
///
/// # Safety
/// `pkey` is live; `arg2` is the operation's buffer.
unsafe extern "C" fn dh_pkey_ctrl(
    pkey: *mut EvpPkey,
    op: c_int,
    arg1: c_long,
    arg2: *mut c_void,
) -> c_int {
    match op {
        ASN1_PKEY_CTRL_SET1_TLS_ENCPT => {
            /* We should only be here if we have a legacy key */
            // SAFETY: `pkey` is live.
            if unsafe { evp_pkey_is_legacy(pkey) } == 0 {
                return 0;
            }
            // SAFETY: `pkey` is live.
            let dh = unsafe { evp_pkey_get0_DH_int(pkey) };
            if dh.is_null() {
                return 0;
            }
            // SAFETY: `dh` is live and `arg2` is the operation's buffer of `arg1` bytes.
            unsafe { ossl_dh_buf2key(dh, arg2.cast::<c_uchar>(), arg1 as usize) }
        }
        ASN1_PKEY_CTRL_GET1_TLS_ENCPT => {
            // SAFETY: `pkey` is live.
            let dh = unsafe { evp_pkey_get0_DH_int(pkey) };
            if dh.is_null() {
                return 0;
            }
            // SAFETY: `dh` is live and `arg2` is the caller's `unsigned char **`.
            unsafe { ossl_dh_key2buf(dh, arg2.cast::<*mut c_uchar>(), 0, 1) as c_int }
        }
        _ => -2,
    }
}

/// `static int dhx_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)` —
/// `crypto/dh/dh_ameth.c:420-426`.
///
/// X9.42 supports no control at all, so every operation is `-2` (unsupported).
///
/// # Safety
/// No pointer argument is read.
unsafe extern "C" fn dhx_pkey_ctrl(
    _pkey: *mut EvpPkey,
    _op: c_int,
    _arg1: c_long,
    _arg2: *mut c_void,
) -> c_int {
    -2
}

/// `static int dh_pkey_public_check(const EVP_PKEY *pkey)` — `crypto/dh/dh_ameth.c:428-438`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn dh_pkey_public_check(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    let dh = unsafe { (*pkey).pkey.cast::<Dh>() };

    // SAFETY: `dh` is live.
    if unsafe { (*dh).pub_key }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_433) };
        return 0;
    }

    // SAFETY: `dh` is live and its public key is non-NULL past the guard.
    unsafe { DH_check_pub_key_ex(dh, (*dh).pub_key) }
}

/// `static int dh_pkey_param_check(const EVP_PKEY *pkey)` — `crypto/dh/dh_ameth.c:440-445`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn dh_pkey_param_check(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { DH_check_ex((*pkey).pkey.cast::<Dh>()) }
}

/// `static size_t dh_pkey_dirty_cnt(const EVP_PKEY *pkey)` — `crypto/dh/dh_ameth.c:447-450`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn dh_pkey_dirty_cnt(pkey: *const EvpPkey) -> usize {
    // SAFETY: `pkey` is live.
    unsafe { (*(*pkey).pkey.cast::<Dh>()).dirty_cnt }
}

/// `static int dh_pkey_export_to(const EVP_PKEY *from, void *to_keydata,
/// OSSL_FUNC_keymgmt_import_fn *importer, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/dh/dh_ameth.c:452-507`.
///
/// # Safety
/// `from` is live; `to_keydata` is the importer's own object; `importer` is the destination's
/// import function.
unsafe extern "C" fn dh_pkey_export_to(
    from: *const EvpPkey,
    to_keydata: *mut c_void,
    importer: Option<KeymgmtImportFn>,
    _libctx: *mut c_void,
    _propq: *const c_char,
) -> c_int {
    let mut selection: c_int = 0;

    // SAFETY: `from` is live.
    let dh = unsafe { (*from).pkey.cast::<Dh>() };
    // SAFETY: `dh` is live.
    let (p, g, q) = unsafe { (DH_get0_p(dh), DH_get0_g(dh), DH_get0_q(dh)) };
    // SAFETY: `dh` is live.
    let l = unsafe { DH_get_length(dh) };
    // SAFETY: `dh` is live.
    let (pub_key, priv_key) = unsafe { (DH_get0_pub_key(dh), DH_get0_priv_key(dh)) };

    if p.is_null() || g.is_null() {
        return 0;
    }

    let tmpl = OSSL_PARAM_BLD_new();
    if tmpl.is_null() {
        return 0;
    }
    // SAFETY: `tmpl` is live and the three BIGNUMs are live.
    if unsafe {
        OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, p) == 0
            || OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, g) == 0
    } {
        // goto err
        // SAFETY: `tmpl` is live.
        unsafe { OSSL_PARAM_BLD_free(tmpl) };
        return 0;
    }
    if !q.is_null() {
        // SAFETY: `tmpl` is live and `q` is live.
        if unsafe { OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_Q, q) } == 0 {
            // SAFETY: `tmpl` is live.
            unsafe { OSSL_PARAM_BLD_free(tmpl) };
            return 0;
        }
    }
    selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
    if l > 0 {
        // SAFETY: `tmpl` is live.
        if unsafe { OSSL_PARAM_BLD_push_long(tmpl, OSSL_PKEY_PARAM_DH_PRIV_LEN, l) } == 0 {
            // SAFETY: `tmpl` is live.
            unsafe { OSSL_PARAM_BLD_free(tmpl) };
            return 0;
        }
        selection |= OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
    }
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
    // SAFETY: `importer` is the destination's own function and the parameters belong to it.
    let rv = unsafe { importer.map_or(0, |f| f(to_keydata, selection, params)) };

    // SAFETY: `params` is live.
    unsafe { OSSL_PARAM_free(params) };
    // SAFETY: `tmpl` is live.
    unsafe { OSSL_PARAM_BLD_free(tmpl) };
    rv
}

/// `static int dh_pkey_import_from_type(const OSSL_PARAM params[], void *vpctx, int type)` —
/// `crypto/dh/dh_ameth.c:509-530`.
///
/// # Safety
/// `params` is a live parameter array; `vpctx` is a live `EVP_PKEY_CTX`.
unsafe fn dh_pkey_import_from_type(
    params: *const OsslParam,
    vpctx: *mut c_void,
    type_: c_int,
) -> c_int {
    let pctx = vpctx.cast::<crate::evp::pkey_ctx::EvpPkeyCtx>();
    // SAFETY: `pctx` is live per the contract.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
    // SAFETY: `pctx` is live.
    let dh = unsafe { ossl_dh_new_ex((*pctx).libctx) };

    if dh.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_AMETH_517) };
        return 0;
    }
    // SAFETY: `dh` is live.
    unsafe {
        DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
        DH_set_flags(
            dh,
            if type_ == EVP_PKEY_DH {
                DH_FLAG_TYPE_DH
            } else {
                DH_FLAG_TYPE_DHX
            },
        );
    }

    // SAFETY: `dh` is live, `params` is the caller's array, and `pkey` is live.
    if unsafe {
        ossl_dh_params_fromdata(dh, params) == 0
            || ossl_dh_key_fromdata(dh, params, 1) == 0
            || EVP_PKEY_assign(pkey, type_, dh.cast()) == 0
    } {
        // SAFETY: `dh` is live.
        unsafe { DH_free(dh) };
        return 0;
    }
    1
}

/// `static int dh_pkey_import_from(const OSSL_PARAM params[], void *vpctx)` —
/// `crypto/dh/dh_ameth.c:532-535`.
///
/// # Safety
/// As [`dh_pkey_import_from_type`].
unsafe extern "C" fn dh_pkey_import_from(params: *const OsslParam, vpctx: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { dh_pkey_import_from_type(params, vpctx, EVP_PKEY_DH) }
}

/// `static int dhx_pkey_import_from(const OSSL_PARAM params[], void *vpctx)` —
/// `crypto/dh/dh_ameth.c:537-540`.
///
/// # Safety
/// As [`dh_pkey_import_from_type`].
unsafe extern "C" fn dhx_pkey_import_from(params: *const OsslParam, vpctx: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { dh_pkey_import_from_type(params, vpctx, EVP_PKEY_DHX) }
}

/// `static int dh_pkey_copy(EVP_PKEY *to, EVP_PKEY *from)` — `crypto/dh/dh_ameth.c:542-558`.
///
/// # Safety
/// `to` and `from` are live.
unsafe extern "C" fn dh_pkey_copy(to: *mut EvpPkey, from: *mut EvpPkey) -> c_int {
    // SAFETY: `from` is live.
    let dh = unsafe { (*from).pkey.cast::<Dh>() };
    let mut dupkey: *mut Dh = ptr::null_mut();

    if !dh.is_null() {
        // SAFETY: `dh` is live.
        dupkey = unsafe { ossl_dh_dup(dh, OSSL_KEYMGMT_SELECT_ALL_BITS) };
        if dupkey.is_null() {
            return 0;
        }
    }

    // SAFETY: `to` is live.
    let ret = unsafe { EVP_PKEY_assign(to, (*from).type_, dupkey.cast()) };
    if ret == 0 {
        // SAFETY: `dupkey` is live.
        unsafe { DH_free(dupkey) };
    }
    ret
}

/// `const EVP_PKEY_ASN1_METHOD ossl_dh_asn1_meth` — `crypto/dh/dh_ameth.c:560-604`.
///
/// `static` so the address `d2i_dhp`/`i2d_dhp`/`dh_cmp_parameters`/`dh_copy_parameters` compare
/// against is the one `standard_methods[]` carries.
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_dh_asn1_meth: EvpPkeyAsn1Method = EvpPkeyAsn1Method {
    pkey_id: EVP_PKEY_DH,
    pkey_base_id: EVP_PKEY_DH,
    pkey_flags: 0,
    pem_str: c"DH".as_ptr().cast_mut(),
    info: c"OpenSSL PKCS#3 DH method".as_ptr().cast_mut(),
    pub_decode: Some(dh_pub_decode),
    pub_encode: Some(dh_pub_encode),
    pub_cmp: Some(dh_pub_cmp),
    pub_print: Some(dh_public_print),
    priv_decode: Some(dh_priv_decode),
    priv_encode: Some(dh_priv_encode),
    priv_print: Some(dh_private_print),
    pkey_size: Some(int_dh_size),
    pkey_bits: Some(dh_bits),
    pkey_security_bits: Some(dh_security_bits),
    param_decode: Some(dh_param_decode),
    param_encode: Some(dh_param_encode),
    param_missing: Some(dh_missing_parameters),
    param_copy: Some(dh_copy_parameters),
    param_cmp: Some(dh_cmp_parameters),
    param_print: Some(dh_param_print),
    sig_print: None,
    pkey_free: Some(int_dh_free),
    pkey_ctrl: Some(dh_pkey_ctrl),
    old_priv_decode: None,
    old_priv_encode: None,
    item_verify: None,
    item_sign: None,
    siginf_set: None,
    pkey_check: None,
    pkey_public_check: Some(dh_pkey_public_check),
    pkey_param_check: Some(dh_pkey_param_check),
    set_priv_key: None,
    set_pub_key: None,
    get_priv_key: None,
    get_pub_key: None,
    dirty_cnt: Some(dh_pkey_dirty_cnt),
    export_to: Some(dh_pkey_export_to),
    import_from: Some(dh_pkey_import_from),
    copy: Some(dh_pkey_copy),
    priv_decode_ex: None,
};

/// `const EVP_PKEY_ASN1_METHOD ossl_dhx_asn1_meth` — `crypto/dh/dh_ameth.c:606-648`.
///
/// The X9.42 sibling: the same callbacks except the `pkey_ctrl` (which supports nothing) and the
/// `import_from` (which builds an `EVP_PKEY_DHX`).
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_dhx_asn1_meth: EvpPkeyAsn1Method = EvpPkeyAsn1Method {
    pkey_id: EVP_PKEY_DHX,
    pkey_base_id: EVP_PKEY_DHX,
    pkey_flags: 0,
    pem_str: c"X9.42 DH".as_ptr().cast_mut(),
    info: c"OpenSSL X9.42 DH method".as_ptr().cast_mut(),
    pub_decode: Some(dh_pub_decode),
    pub_encode: Some(dh_pub_encode),
    pub_cmp: Some(dh_pub_cmp),
    pub_print: Some(dh_public_print),
    priv_decode: Some(dh_priv_decode),
    priv_encode: Some(dh_priv_encode),
    priv_print: Some(dh_private_print),
    pkey_size: Some(int_dh_size),
    pkey_bits: Some(dh_bits),
    pkey_security_bits: Some(dh_security_bits),
    param_decode: Some(dh_param_decode),
    param_encode: Some(dh_param_encode),
    param_missing: Some(dh_missing_parameters),
    param_copy: Some(dh_copy_parameters),
    param_cmp: Some(dh_cmp_parameters),
    param_print: Some(dh_param_print),
    sig_print: None,
    pkey_free: Some(int_dh_free),
    pkey_ctrl: Some(dhx_pkey_ctrl),
    old_priv_decode: None,
    old_priv_encode: None,
    item_verify: None,
    item_sign: None,
    siginf_set: None,
    pkey_check: None,
    pkey_public_check: Some(dh_pkey_public_check),
    pkey_param_check: Some(dh_pkey_param_check),
    set_priv_key: None,
    set_pub_key: None,
    get_priv_key: None,
    get_pub_key: None,
    dirty_cnt: Some(dh_pkey_dirty_cnt),
    export_to: Some(dh_pkey_export_to),
    import_from: Some(dhx_pkey_import_from),
    copy: Some(dh_pkey_copy),
    priv_decode_ex: None,
};

/// `ERR_R_BUF_LIB` — `include/openssl/err.h:323`, `ERR_LIB_BUF (7) | ERR_RFLAG_COMMON (0x2 << 18)`.
/// The `do_dh_print` initial reason, reached only below the null check.
const ERR_R_BUF_LIB: c_int = 7 | (0x2 << 18);
/// `ERR_R_FATAL` — `include/openssl/err.h:353`, `ERR_RFLAG_FATAL (0x1 << 18) | ERR_RFLAG_COMMON
/// (0x2 << 18)`. The two flag bits are both set on every fatal reason.
const ERR_R_FATAL: c_int = (0x1 << 18) | (0x2 << 18);
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h:356`, `258 | ERR_R_FATAL`. The reason a
/// parameters print answers when `x->params.p` is absent.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 258 | ERR_R_FATAL;

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    use crate::bn::arith::BN_cmp;
    use crate::dh::group_params::DH_new_by_nid;
    use crate::dh::object::{DH_get0_pqg, DH_new};
    use crate::dh::prn::DHparams_print_fp;
    use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_get0_DH, EVP_PKEY_new, EVP_PKEY_set1_DH};
    use crate::evp::pkey_ctx::EVP_PKEY_DH;
    use crate::runtime::bio::bss_mem::BIO_s_mem;
    use crate::runtime::bio::sys::{fclose, FILE};
    use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, BIO_CTRL_INFO};
    use crate::runtime::obj::NID_ffdhe2048;

    extern "C" {
        /// `FILE *tmpfile(void)` — the libc constructor `dh_prn.c`'s caller uses to obtain the
        /// `FILE *` it passes. It is not part of the crate's BIO surface, which exposes only
        /// `fopen`, so the test declares it; `fclose` and `FILE` come from
        /// [`crate::runtime::bio::sys`] so the declarations cannot disagree.
        fn tmpfile() -> *mut FILE;
    }

    /// `DHparams_dup` is `DH_new` plus the FFC copy, so the duplicate's three parameters compare
    /// with the original's.
    #[test]
    fn the_duplicate_has_the_same_parameters() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let d = DH_new_by_nid(NID_ffdhe2048);
            let dup = DHparams_dup(d);
            assert!(!dup.is_null());
            let (mut sp, mut sq, mut sg) = (ptr::null(), ptr::null(), ptr::null());
            let (mut dp, mut dq, mut dg) = (ptr::null(), ptr::null(), ptr::null());
            DH_get0_pqg(d, &mut sp, &mut sq, &mut sg);
            DH_get0_pqg(dup, &mut dp, &mut dq, &mut dg);
            assert_eq!(BN_cmp(dp, sp), 0);
            assert_eq!(BN_cmp(dq, sq), 0);
            assert_eq!(BN_cmp(dg, sg), 0);
            DH_free(dup);
            DH_free(d);
        }
    }

    /// A parameters print writes the group and answers 1; the text opens with the authority's own
    /// four-space indent and then its `DH Parameters` label.
    #[test]
    fn the_print_writes_the_parameters_and_answers_one() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let d = DH_new_by_nid(NID_ffdhe2048);
            let b = BIO_new(BIO_s_mem());
            assert!(!b.is_null());
            assert_eq!(DHparams_print(b, d), 1);
            let mut data: *mut core::ffi::c_char = ptr::null_mut();
            let len = BIO_ctrl(b, BIO_CTRL_INFO, 0, ptr::addr_of_mut!(data).cast());
            assert!(len > 6 && !data.is_null());
            // SAFETY: `data` is the BIO's own buffer, `len` bytes long.
            let text = core::slice::from_raw_parts(data.cast::<u8>(), len as usize);
            assert!(
                text.starts_with(b"    DH Parameters:"),
                "indent is 4, then the label"
            );
            BIO_free(b);
            DH_free(d);
        }
    }

    /// A key with no `p` prints nothing and raises the null-parameter reason at `dh_ameth.c:297`,
    /// with the authority's own file, line and function name — the coordinate generated now that
    /// the unit is in the raise-site generator's covered set.
    #[test]
    fn a_key_without_p_is_refused_with_the_coordinate() {
        // SAFETY: every pointer below is this test's own live object, and each out-parameter of
        // `ERR_get_error_all` is this frame's slot.
        unsafe {
            use core::ffi::CStr;

            let empty = DH_new();
            let b = BIO_new(BIO_s_mem());
            crate::runtime::err::ERR_clear_error();
            assert_eq!(DHparams_print(b, empty), 0);

            let mut file: *const c_char = ptr::null();
            let mut line: c_int = 0;
            let mut func: *const c_char = ptr::null();
            assert_ne!(
                crate::runtime::err::ERR_get_error_all(
                    &mut file,
                    &mut line,
                    &mut func,
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
                0
            );
            assert!(CStr::from_ptr(file)
                .to_bytes()
                .ends_with(b"crypto/dh/dh_ameth.c"));
            assert_eq!(line, 297);
            assert_eq!(CStr::from_ptr(func).to_bytes(), b"do_dh_print");

            BIO_free(b);
            DH_free(empty);
        }
    }

    /// The `FILE *` wrapper answers the print's verdict.
    #[test]
    fn the_file_pointer_wrapper_answers_the_print() {
        // SAFETY: `fp` is libc's own temporary file and every other pointer is this test's.
        unsafe {
            let d = DH_new_by_nid(NID_ffdhe2048);
            let fp = tmpfile();
            assert!(!fp.is_null());
            assert_eq!(DHparams_print_fp(fp.cast(), d), 1);
            fclose(fp);
            DH_free(d);
        }
    }

    /// `EVP_PKEY_set1_DH` types the key, `EVP_PKEY_get_id` answers the legacy NID, and
    /// `EVP_PKEY_get0_DH` hands the same low-level object back — the round trip that needs both
    /// the table row and the legacy union.
    #[test]
    fn the_set1_and_get0_round_trip_through_the_table() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let d = DH_new_by_nid(NID_ffdhe2048);
            let k = EVP_PKEY_new();
            assert!(!k.is_null());
            assert_eq!(EVP_PKEY_set1_DH(k, d), 1);
            assert_eq!(
                crate::evp::pkey::EVP_PKEY_get_id(k),
                EVP_PKEY_DH,
                "a PKCS#3 key types as EVP_PKEY_DH"
            );
            assert_eq!(EVP_PKEY_get0_DH(k), d.cast_const());
            EVP_PKEY_free(k);
            DH_free(d);
        }
    }
}
