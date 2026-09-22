//! `crypto/ec/ec_ameth.c` — the whole unit: `ossl_eckey_asn1_meth`, its three-line SM2 sibling
//! `ossl_sm2_asn1_meth`, and every callback they name.
//!
//! D347 landed this file's `ECParameters_print` export while the method objects were withheld on
//! D341's cycle; the object and its SM2 alias land now that D348/D349/D351 closed the call closure.
//! The SM2 row was measured rather than assumed: `ossl_sm2_asn1_meth` (`:702-707`) is a **three-line
//! alias** with no callback fields, so its only closure is the literal itself.
//!
//! Two things about the unit are worth naming at the top. `eckey_priv_encode` takes `EC_KEY
//! ec_key = *(pkey->pkey.ec)` — a **by-value shallow copy** the authority mutates (it ORs
//! `EC_PKEY_NO_PARAMETERS` into `enc_flag`) so the original is untouched; the crate reproduces the
//! copy with `ptr::read`, which is a bitwise duplicate over a struct of raw pointers and scalars and
//! has no destructor to run twice. And `ec_pkey_ctrl`'s two TLS arms are the only place the EC
//! method reads the legacy key.
//!
//! The unit is already in `gen_err_raise_sites.py`'s covered set (D347 added it for
//! `ECParameters_print`), so its raise sites are generated as `EC_AMETH_*`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::layout::{Asn1Pctx, Asn1String, V_ASN1_OBJECT, V_ASN1_SEQUENCE};
use crate::asn1::p8_pkey::PKCS8_pkey_set0;
use crate::asn1::string::{ASN1_STRING_free, ASN1_STRING_new};
use crate::asn1::t_pkey::ASN1_buf_print;
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_new_ex, BN_CTX_start};
use crate::ec::asn1::{
    d2i_ECParameters, d2i_ECPrivateKey, i2d_ECParameters, i2d_ECPrivateKey, i2o_ECPublicKey,
    o2i_ECPublicKey, ECDSA_size,
};
use crate::ec::backend::{
    ossl_ec_group_fromdata, ossl_ec_group_todata, ossl_ec_key_from_pkcs8, ossl_ec_key_fromdata,
    ossl_ec_key_otherparams_fromdata, ossl_ec_key_param_from_x509_algor,
};
use crate::ec::check::EC_GROUP_check;
use crate::ec::key::{
    EC_KEY_check_key, EC_KEY_dup, EC_KEY_free, EC_KEY_get0_group, EC_KEY_get0_private_key,
    EC_KEY_get0_public_key, EC_KEY_get_conv_form, EC_KEY_get_enc_flags, EC_KEY_get_flags,
    EC_KEY_key2buf, EC_KEY_new, EC_KEY_new_ex, EC_KEY_oct2key, EC_KEY_priv2buf,
    EC_KEY_set_enc_flags, EC_KEY_set_group, EC_FLAG_COFACTOR_ECDH,
};
use crate::ec::lib::{
    EC_GROUP_cmp, EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get_asn1_flag, EC_GROUP_get_curve_name,
    EC_GROUP_order_bits,
};
use crate::ec::oct::EC_POINT_point2buf;
use crate::ec::prn::ECPKParameters_print;
use crate::ec::{EcKey, POINT_CONVERSION_UNCOMPRESSED};
use crate::evp::keymgmt::KeymgmtImportFn;
use crate::evp::p_legacy_assign::{evp_pkey_get0_EC_KEY_int, EVP_PKEY_get0_EC_KEY};
use crate::evp::pkey::{
    evp_pkey_is_legacy, EVP_PKEY_assign, EVP_PKEY_get_id, EvpPkey, ASN1_PKEY_CTRL_DEFAULT_MD_NID,
    ASN1_PKEY_CTRL_GET1_TLS_ENCPT, ASN1_PKEY_CTRL_SET1_TLS_ENCPT,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PUB_KEY,
};
use crate::evp::pkey_asn1::{EvpPkeyAsn1Method, ASN1_PKEY_ALIAS};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_get0_pkey, EVP_PKEY_EC, EVP_PKEY_SM2};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN_pad, OSSL_PARAM_BLD_push_int,
    OSSL_PARAM_BLD_push_octet_string, OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::OsslParam;
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{NID_X9_62_id_ecPublicKey, NID_sha256, NID_sm3, OBJ_length, OBJ_nid2obj};
use crate::x509::x_pubkey::{
    ossl_x509_PUBKEY_get0_libctx, X509Pubkey, X509_PUBKEY_get0_param, X509_PUBKEY_set0_param,
};

/// `EC_PKEY_NO_PARAMETERS` — `include/openssl/ec.h:950`. An `enc_flag` bit `i2d_ECPrivateKey`
/// honours; `EC_PKEY_NO_PUBKEY` is the other one and lives in [`crate::ec::key`].
const EC_PKEY_NO_PARAMETERS: c_int = 0x001;
/// `OSSL_PKEY_PARAM_USE_COFACTOR_ECDH` — `include/openssl/core_names.h:400`.
const OSSL_PKEY_PARAM_USE_COFACTOR_ECDH: *const c_char = c"use-cofactor-ecdh".as_ptr();
/// The authority's translation unit, for the `OPENSSL_free`/`OPENSSL_clear_free` sites below.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/ec_ameth.c".as_ptr();

/// `static int eckey_param2type(int *pptype, void **ppval, const EC_KEY *ec_key)` —
/// `crypto/ec/ec_ameth.c:29-66`.
///
/// A named curve becomes a bare OID (`V_ASN1_OBJECT`); anything else becomes an explicit
/// `ECParameters` SEQUENCE.
///
/// # Safety
/// `pptype` and `ppval` are writable slots; `ec_key` is NULL or live.
unsafe fn eckey_param2type(
    pptype: *mut c_int,
    ppval: *mut *mut c_void,
    ec_key: *const EcKey,
) -> c_int {
    if ec_key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_35) };
        return 0;
    }
    // SAFETY: `ec_key` is live.
    let group = unsafe { EC_KEY_get0_group(ec_key) };
    if group.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_35) };
        return 0;
    }
    // SAFETY: `group` is live.
    if unsafe { EC_GROUP_get_asn1_flag(group) } != 0 {
        // SAFETY: `group` is live.
        let nid = unsafe { EC_GROUP_get_curve_name(group) };
        if nid != 0 {
            /* we have a 'named curve' => just set the OID */
            let asn1obj = OBJ_nid2obj(nid);
            // SAFETY: `asn1obj` is NULL or live.
            if asn1obj.is_null() || unsafe { OBJ_length(asn1obj) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EC_AMETH_45) };
                return 0;
            }
            // SAFETY: both out-parameters are writable per the contract.
            unsafe {
                *ppval = asn1obj.cast();
                *pptype = V_ASN1_OBJECT;
            }
            return 1;
        }
    }

    /* explicit parameters */
    let pstr = ASN1_STRING_new();
    if pstr.is_null() {
        return 0;
    }
    // SAFETY: `ec_key` and `pstr` are live.
    unsafe { (*pstr).length = i2d_ECParameters(ec_key, &mut (*pstr).data) };
    // SAFETY: `pstr` is live.
    if unsafe { (*pstr).length } <= 0 {
        // SAFETY: `pstr` is live.
        unsafe { ASN1_STRING_free(pstr) };
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_59) };
        return 0;
    }
    // SAFETY: both out-parameters are writable per the contract.
    unsafe {
        *ppval = pstr.cast();
        *pptype = V_ASN1_SEQUENCE;
    }
    1
}

/// `static int eckey_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)` —
/// `crypto/ec/ec_ameth.c:68-98`.
///
/// # Safety
/// `pk` and `pkey` are live.
unsafe extern "C" fn eckey_pub_encode(pk: *mut X509Pubkey, pkey: *const EvpPkey) -> c_int {
    let mut pval: *mut c_void = ptr::null_mut();
    let mut ptype: c_int = 0;
    let mut penc: *mut c_uchar = ptr::null_mut();

    // SAFETY: `pkey` is live.
    let ec_key = unsafe { (*pkey).pkey.cast::<EcKey>() };

    // SAFETY: `pval`/`ptype` are live locals and `ec_key` is live.
    if unsafe { eckey_param2type(&mut ptype, &mut pval, ec_key) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_77) };
        return 0;
    }
    // SAFETY: `ec_key` is live and NULL is the size query.
    let mut penclen = unsafe { i2o_ECPublicKey(ec_key, ptr::null_mut()) };
    if penclen <= 0 {
        // goto err
        // SAFETY: `ptype` names what `pval` is.
        unsafe {
            if ptype == V_ASN1_SEQUENCE {
                ASN1_STRING_free(pval.cast::<Asn1String>());
            }
            CRYPTO_free(penc.cast(), FILE, 96);
        }
        return 0;
    }
    // SAFETY: `penclen` is a positive size.
    penc = CRYPTO_malloc(penclen as usize, FILE, 83).cast::<c_uchar>();
    if penc.is_null() {
        // goto err
        // SAFETY: `ptype` names what `pval` is, and `penc` is the NULL the allocation returned.
        unsafe {
            if ptype == V_ASN1_SEQUENCE {
                ASN1_STRING_free(pval.cast::<Asn1String>());
            }
            CRYPTO_free(penc.cast(), FILE, 96);
        }
        return 0;
    }
    let mut p = penc;
    // SAFETY: `ec_key` is live and `p` points into the `penclen` buffer.
    penclen = unsafe { i2o_ECPublicKey(ec_key, &mut p) };
    if penclen <= 0 {
        // goto err
        // SAFETY: `ptype` names what `pval` is and `penc` is the buffer this call filled.
        unsafe {
            if ptype == V_ASN1_SEQUENCE {
                ASN1_STRING_free(pval.cast::<Asn1String>());
            }
            CRYPTO_free(penc.cast(), FILE, 96);
        }
        return 0;
    }
    // SAFETY: `pk` is live and `pval`/`penc` are the objects the setter takes ownership of.
    if unsafe { X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_EC), ptype, pval, penc, penclen) }
        != 0
    {
        return 1;
    }
    // goto err
    // SAFETY: `ptype` names what `pval` is and `penc` is the buffer this call filled.
    unsafe {
        if ptype == V_ASN1_SEQUENCE {
            ASN1_STRING_free(pval.cast::<Asn1String>());
        }
        CRYPTO_free(penc.cast(), FILE, 96);
    }
    0
}

/// `static int eckey_pub_decode(EVP_PKEY *pkey, const X509_PUBKEY *pubkey)` —
/// `crypto/ec/ec_ameth.c:100-129`.
///
/// # Safety
/// `pkey` and `pubkey` are live.
unsafe extern "C" fn eckey_pub_decode(pkey: *mut EvpPkey, pubkey: *const X509Pubkey) -> c_int {
    let mut p: *const c_uchar = ptr::null();
    let mut pklen: c_int = 0;
    let mut palg: *mut crate::asn1::x_algor::X509Algor = ptr::null_mut();
    let mut libctx: *mut c_void = ptr::null_mut();
    let mut propq: *const c_char = ptr::null();

    // SAFETY: `pubkey` is live and both out-parameters are live locals.
    if unsafe { ossl_x509_PUBKEY_get0_libctx(&mut libctx, &mut propq, pubkey) } == 0
        // SAFETY: `pubkey` is live and the four out-parameters are live locals.
        || unsafe { X509_PUBKEY_get0_param(ptr::null_mut(), &mut p, &mut pklen, &mut palg, pubkey) }
            == 0
    {
        return 0;
    }
    // SAFETY: `palg` is live.
    let eckey = unsafe { ossl_ec_key_param_from_x509_algor(palg, libctx, propq) };

    if eckey.is_null() {
        return 0;
    }

    /* We have parameters now set public key */
    // SAFETY: `eckey` is a live local pointer and `p` points into the decoded octets.
    let mut eckey = eckey;
    // SAFETY: `p` is the public-key octets and `pklen` bounds them.
    if unsafe { o2i_ECPublicKey(&mut eckey, &mut p, pklen as c_long) }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_119) };
        // goto ecerr
        // SAFETY: `eckey` is live.
        unsafe { EC_KEY_free(eckey) };
        return 0;
    }

    // SAFETY: `pkey` is live.
    unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_EC, eckey.cast()) };
    1
}

/// `static int eckey_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)` —
/// `crypto/ec/ec_ameth.c:131-146`.
///
/// # Safety
/// `a` and `b` are live.
unsafe extern "C" fn eckey_pub_cmp(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    // SAFETY: both keys are live.
    let group = unsafe { EC_KEY_get0_group((*b).pkey.cast::<EcKey>()) };
    // SAFETY: both keys are live.
    let pa = unsafe { EC_KEY_get0_public_key((*a).pkey.cast::<EcKey>()) };
    // SAFETY: both keys are live.
    let pb = unsafe { EC_KEY_get0_public_key((*b).pkey.cast::<EcKey>()) };

    if group.is_null() || pa.is_null() || pb.is_null() {
        return -2;
    }
    // SAFETY: all three are live.
    let r = unsafe { crate::ec::lib::EC_POINT_cmp(group, pa, pb, ptr::null_mut()) };
    if r == 0 {
        return 1;
    }
    if r == 1 {
        return 0;
    }
    -2
}

/// `static int eckey_priv_decode_ex(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/ec/ec_ameth.c:148-160`.
///
/// # Safety
/// `pkey` and `p8` are live; `libctx`/`propq` are the caller's.
unsafe extern "C" fn eckey_priv_decode_ex(
    pkey: *mut EvpPkey,
    p8: *const crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `p8` is live.
    let eckey = unsafe { ossl_ec_key_from_pkcs8(p8, libctx, propq) };

    if !eckey.is_null() {
        // SAFETY: `pkey` and `eckey` are live.
        unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_EC, eckey.cast()) };
        return 1;
    }

    0
}

/// `static int eckey_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)` —
/// `crypto/ec/ec_ameth.c:162-203`.
///
/// The authority works on a **copy** of the key (`EC_KEY ec_key = *(pkey->pkey.ec)`) because it ORs
/// `EC_PKEY_NO_PARAMETERS` into `enc_flag` and must not disturb the original. `ptr::read` is that
/// copy: a bitwise duplicate of a `#[repr(C)]` struct of raw pointers and scalars, with no
/// destructor to run twice.
///
/// # Safety
/// `p8` and `pkey` are live.
unsafe extern "C" fn eckey_priv_encode(
    p8: *mut crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
    pkey: *const EvpPkey,
) -> c_int {
    let mut ep: *mut c_uchar = ptr::null_mut();
    let mut pval: *mut c_void = ptr::null_mut();
    let mut ptype: c_int = 0;

    // SAFETY: `pkey` is live; the read duplicates the key's storage, and `EcKey` has no destructor.
    let mut ec_key: EcKey = unsafe { ptr::read((*pkey).pkey.cast::<EcKey>()) };

    // SAFETY: `pval`/`ptype` are live locals and `ec_key` is a live copy.
    if unsafe { eckey_param2type(&mut ptype, &mut pval, &raw const ec_key) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_171) };
        return 0;
    }

    /* do not include the parameters in the SEC1 private key see PKCS#11 12.11 */
    // SAFETY: `ec_key` is a live local.
    let old_flags = unsafe { EC_KEY_get_enc_flags(&raw const ec_key) };
    // SAFETY: `ec_key` is a live local.
    unsafe { EC_KEY_set_enc_flags(&mut ec_key, old_flags | EC_PKEY_NO_PARAMETERS as c_uint) };

    // SAFETY: `ec_key` is a live local and `ep` is a live out-parameter.
    let eplen = unsafe { i2d_ECPrivateKey(&raw const ec_key, &mut ep) };
    if eplen <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_186) };
        // goto err
        // SAFETY: `ptype` names what `pval` is and `ep` is the buffer this call filled.
        unsafe {
            if ptype == V_ASN1_SEQUENCE {
                ASN1_STRING_free(pval.cast::<Asn1String>());
            }
        }
        return 0;
    }

    // SAFETY: `p8` is live and `pval`/`ep` are the objects the setter takes ownership of.
    if unsafe {
        PKCS8_pkey_set0(
            p8,
            OBJ_nid2obj(NID_X9_62_id_ecPublicKey),
            0,
            ptype,
            pval,
            ep,
            eplen,
        )
    } == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_192) };
        // SAFETY: `ep` is the buffer `eplen` long.
        unsafe { CRYPTO_clear_free(ep.cast(), eplen as usize, FILE, 193) };
        // goto err
        // SAFETY: `ptype` names what `pval` is.
        unsafe {
            if ptype == V_ASN1_SEQUENCE {
                ASN1_STRING_free(pval.cast::<Asn1String>());
            }
        }
        return 0;
    }

    1
}

/// `static int int_ec_size(const EVP_PKEY *pkey)` — `crypto/ec/ec_ameth.c:205-208`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn int_ec_size(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { ECDSA_size((*pkey).pkey.cast::<EcKey>()) }
}

/// `static int ec_bits(const EVP_PKEY *pkey)` — `crypto/ec/ec_ameth.c:210-213`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ec_bits(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { EC_GROUP_order_bits(EC_KEY_get0_group((*pkey).pkey.cast::<EcKey>())) }
}

/// `static int ec_security_bits(const EVP_PKEY *pkey)` — `crypto/ec/ec_ameth.c:215-230`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ec_security_bits(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    let ecbits = unsafe { ec_bits(pkey) };

    if ecbits >= 512 {
        return 256;
    }
    if ecbits >= 384 {
        return 192;
    }
    if ecbits >= 256 {
        return 128;
    }
    if ecbits >= 224 {
        return 112;
    }
    if ecbits >= 160 {
        return 80;
    }
    ecbits / 2
}

/// `static int ec_missing_parameters(const EVP_PKEY *pkey)` — `crypto/ec/ec_ameth.c:232-237`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ec_missing_parameters(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe {
        if (*pkey).pkey.is_null() || EC_KEY_get0_group((*pkey).pkey.cast::<EcKey>()).is_null() {
            return 1;
        }
    }
    0
}

/// `static int ec_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)` —
/// `crypto/ec/ec_ameth.c:239-257`.
///
/// # Safety
/// `to` and `from` are live.
unsafe extern "C" fn ec_copy_parameters(to: *mut EvpPkey, from: *const EvpPkey) -> c_int {
    // SAFETY: `from` is live.
    let group = unsafe { EC_GROUP_dup(EC_KEY_get0_group((*from).pkey.cast::<EcKey>())) };

    if group.is_null() {
        return 0;
    }
    // SAFETY: `to` is live.
    unsafe {
        if (*to).pkey.is_null() {
            (*to).pkey = EC_KEY_new().cast();
            if (*to).pkey.is_null() {
                // goto err
                EC_GROUP_free(group);
                return 0;
            }
        }
        if EC_KEY_set_group((*to).pkey.cast::<EcKey>(), group) == 0 {
            // goto err
            EC_GROUP_free(group);
            return 0;
        }
        EC_GROUP_free(group);
    }
    1
}

/// `static int ec_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)` —
/// `crypto/ec/ec_ameth.c:259-270`.
///
/// # Safety
/// `a` and `b` are live.
unsafe extern "C" fn ec_cmp_parameters(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    // SAFETY: both keys are live.
    let group_a = unsafe { EC_KEY_get0_group((*a).pkey.cast::<EcKey>()) };
    // SAFETY: both keys are live.
    let group_b = unsafe { EC_KEY_get0_group((*b).pkey.cast::<EcKey>()) };

    if group_a.is_null() || group_b.is_null() {
        return -2;
    }
    // SAFETY: both groups are live.
    if unsafe { EC_GROUP_cmp(group_a, group_b, ptr::null_mut()) } != 0 {
        0
    } else {
        1
    }
}

/// `static void int_ec_free(EVP_PKEY *pkey)` — `crypto/ec/ec_ameth.c:272-275`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn int_ec_free(pkey: *mut EvpPkey) {
    // SAFETY: `pkey` is live.
    unsafe { EC_KEY_free((*pkey).pkey.cast::<EcKey>()) };
}

/// `ec_print_t` — `crypto/ec/ec_ameth.c:277-281`.
#[derive(Clone, Copy, PartialEq)]
enum EcPrintT {
    Private,
    Public,
    Param,
}

/// `static int do_EC_KEY_print(BIO *bp, const EC_KEY *x, int off, ec_print_t ktype)` —
/// `crypto/ec/ec_ameth.c:283-345`.
///
/// # Safety
/// `bp` and `x` are live.
unsafe fn do_ec_key_print(bp: *mut Bio, x: *const EcKey, off: c_int, ktype: EcPrintT) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut priv_: *mut c_uchar = ptr::null_mut();
        let mut pub_: *mut c_uchar = ptr::null_mut();
        let mut privlen: usize = 0;
        let mut publen: usize = 0;

        if x.is_null() {
            raise_site(&err_sites::EC_AMETH_292);
            return 0;
        }
        let group = EC_KEY_get0_group(x);
        if group.is_null() {
            raise_site(&err_sites::EC_AMETH_292);
            return 0;
        }

        if ktype != EcPrintT::Param && !EC_KEY_get0_public_key(x).is_null() {
            publen = EC_KEY_key2buf(x, EC_KEY_get_conv_form(x), &mut pub_, ptr::null_mut());
            if publen == 0 {
                // goto err
                raise_site(&err_sites::EC_AMETH_341);
                CRYPTO_clear_free(priv_.cast(), privlen, FILE, 342);
                CRYPTO_free(pub_.cast(), FILE, 343);
                return 0;
            }
        }

        if ktype == EcPrintT::Private && !EC_KEY_get0_private_key(x).is_null() {
            privlen = EC_KEY_priv2buf(x, &mut priv_);
            if privlen == 0 {
                raise_site(&err_sites::EC_AMETH_341);
                CRYPTO_clear_free(priv_.cast(), privlen, FILE, 342);
                CRYPTO_free(pub_.cast(), FILE, 343);
                return 0;
            }
        }

        let ecstr: *const c_char = match ktype {
            EcPrintT::Private => c"Private-Key".as_ptr(),
            EcPrintT::Public => c"Public-Key".as_ptr(),
            EcPrintT::Param => c"ECDSA-Parameters".as_ptr(),
        };

        if BIO_indent(bp, off, 128) == 0
            || BIO_printf(
                bp,
                c"%s: (%d bit)\n".as_ptr(),
                ecstr,
                EC_GROUP_order_bits(group),
            ) <= 0
        {
            raise_site(&err_sites::EC_AMETH_341);
            CRYPTO_clear_free(priv_.cast(), privlen, FILE, 342);
            CRYPTO_free(pub_.cast(), FILE, 343);
            return 0;
        }

        if privlen != 0
            && (BIO_printf(bp, c"%*spriv:\n".as_ptr(), off, c"".as_ptr()) <= 0
                || ASN1_buf_print(bp, priv_, privlen, off + 4) == 0)
        {
            raise_site(&err_sites::EC_AMETH_341);
            CRYPTO_clear_free(priv_.cast(), privlen, FILE, 342);
            CRYPTO_free(pub_.cast(), FILE, 343);
            return 0;
        }

        if publen != 0
            && (BIO_printf(bp, c"%*spub:\n".as_ptr(), off, c"".as_ptr()) <= 0
                || ASN1_buf_print(bp, pub_, publen, off + 4) == 0)
        {
            raise_site(&err_sites::EC_AMETH_341);
            CRYPTO_clear_free(priv_.cast(), privlen, FILE, 342);
            CRYPTO_free(pub_.cast(), FILE, 343);
            return 0;
        }

        if ECPKParameters_print(bp, group, off) == 0 {
            raise_site(&err_sites::EC_AMETH_341);
            CRYPTO_clear_free(priv_.cast(), privlen, FILE, 342);
            CRYPTO_free(pub_.cast(), FILE, 343);
            return 0;
        }

        CRYPTO_clear_free(priv_.cast(), privlen, FILE, 342);
        CRYPTO_free(pub_.cast(), FILE, 343);
        1
    }
}

/// `static int eckey_param_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen)` —
/// `crypto/ec/ec_ameth.c:347-356`.
///
/// # Safety
/// `pkey` is live; `pder` is a live pointer-to-pointer readable for `derlen` bytes.
unsafe extern "C" fn eckey_param_decode(
    pkey: *mut EvpPkey,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: the caller's contract; the first argument is the authority's NULL.
    let eckey = unsafe { d2i_ECParameters(ptr::null_mut(), pder, derlen as c_long) };
    if eckey.is_null() {
        return 0;
    }
    // SAFETY: `pkey` and `eckey` are live.
    unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_EC, eckey.cast()) };
    1
}

/// `static int eckey_param_encode(const EVP_PKEY *pkey, unsigned char **pder)` —
/// `crypto/ec/ec_ameth.c:358-361`.
///
/// # Safety
/// `pkey` is live; `pder` is a live out-parameter.
unsafe extern "C" fn eckey_param_encode(pkey: *const EvpPkey, pder: *mut *mut c_uchar) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { i2d_ECParameters((*pkey).pkey.cast::<EcKey>(), pder) }
}

/// `static int eckey_param_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/ec/ec_ameth.c:363-367`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn eckey_param_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { do_ec_key_print(bp, (*pkey).pkey.cast::<EcKey>(), indent, EcPrintT::Param) }
}

/// `static int eckey_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/ec/ec_ameth.c:369-373`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn eckey_pub_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { do_ec_key_print(bp, (*pkey).pkey.cast::<EcKey>(), indent, EcPrintT::Public) }
}

/// `static int eckey_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/ec/ec_ameth.c:375-379`.
///
/// # Safety
/// `bp` and `pkey` are live.
unsafe extern "C" fn eckey_priv_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { do_ec_key_print(bp, (*pkey).pkey.cast::<EcKey>(), indent, EcPrintT::Private) }
}

/// `int EC_KEY_print(BIO *bp, const EC_KEY *x, int off)` — `crypto/ec/ec_ameth.c:709-714`.
///
/// The legacy `EC_KEY` printer D347 withheld with the ameth surface: the `ktype` is **private when
/// the key holds a private scalar**, public otherwise, and both arms are the same [`do_ec_key_print`]
/// the three `*_print` callbacks above use. It is what [`crate::ec::prn::EC_KEY_print_fp`] wraps.
///
/// # Safety
/// `bp` and `x` are live.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_print(bp: *mut Bio, x: *const EcKey, off: c_int) -> c_int {
    // SAFETY: `x` is live per the contract.
    let private = unsafe { !EC_KEY_get0_private_key(x).is_null() };
    // SAFETY: `bp` and `x` are live; the `ktype` is this function's own choice.
    unsafe {
        do_ec_key_print(
            bp,
            x,
            off,
            if private {
                EcPrintT::Private
            } else {
                EcPrintT::Public
            },
        )
    }
}

/// `static int old_ec_priv_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen)` —
/// `crypto/ec/ec_ameth.c:381-390`.
///
/// # Safety
/// `pkey` is live; `pder` is a live pointer-to-pointer readable for `derlen` bytes.
unsafe extern "C" fn old_ec_priv_decode(
    pkey: *mut EvpPkey,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: the caller's contract; the first argument is the authority's NULL.
    let ec = unsafe { d2i_ECPrivateKey(ptr::null_mut(), pder, derlen as c_long) };
    if ec.is_null() {
        return 0;
    }
    // SAFETY: `pkey` and `ec` are live.
    unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec.cast()) };
    1
}

/// `static int old_ec_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)` —
/// `crypto/ec/ec_ameth.c:392-395`.
///
/// # Safety
/// `pkey` is live; `pder` is a live out-parameter.
unsafe extern "C" fn old_ec_priv_encode(pkey: *const EvpPkey, pder: *mut *mut c_uchar) -> c_int {
    // SAFETY: `pkey` is live.
    unsafe { i2d_ECPrivateKey((*pkey).pkey.cast::<EcKey>(), pder) }
}

/// `static int ec_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)` —
/// `crypto/ec/ec_ameth.c:397-422`.
///
/// # Safety
/// `pkey` is live; `arg2` is the operation's buffer and, for the default-digest arm, a writable
/// `int *`.
unsafe extern "C" fn ec_pkey_ctrl(
    pkey: *mut EvpPkey,
    op: c_int,
    arg1: c_long,
    arg2: *mut c_void,
) -> c_int {
    match op {
        ASN1_PKEY_CTRL_DEFAULT_MD_NID => {
            // SAFETY: `pkey` is live.
            if unsafe { EVP_PKEY_get_id(pkey) } == EVP_PKEY_SM2 {
                /* For SM2, the only valid digest-alg is SM3 */
                // SAFETY: `arg2` is the caller's writable `int *`.
                unsafe { *(arg2.cast::<c_int>()) = NID_sm3 };
                return 2; /* Make it mandatory */
            }
            // SAFETY: `arg2` is the caller's writable `int *`.
            unsafe { *(arg2.cast::<c_int>()) = NID_sha256 };
            1
        }
        ASN1_PKEY_CTRL_SET1_TLS_ENCPT => {
            /* We should only be here if we have a legacy key */
            // SAFETY: `pkey` is live.
            if unsafe { evp_pkey_is_legacy(pkey) } == 0 {
                return 0;
            }
            // SAFETY: `pkey` is live and `arg2` is the operation's buffer of `arg1` bytes.
            unsafe {
                EC_KEY_oct2key(
                    evp_pkey_get0_EC_KEY_int(pkey),
                    arg2.cast::<c_uchar>(),
                    arg1 as usize,
                    ptr::null_mut(),
                )
            }
        }
        ASN1_PKEY_CTRL_GET1_TLS_ENCPT => {
            // SAFETY: `pkey` is live and `arg2` is the caller's `unsigned char **`.
            unsafe {
                EC_KEY_key2buf(
                    EVP_PKEY_get0_EC_KEY(pkey),
                    POINT_CONVERSION_UNCOMPRESSED,
                    arg2.cast::<*mut c_uchar>(),
                    ptr::null_mut(),
                ) as c_int
            }
        }
        _ => -2,
    }
}

/// `static int ec_pkey_check(const EVP_PKEY *pkey)` — `crypto/ec/ec_ameth.c:424-435`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ec_pkey_check(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    let eckey = unsafe { (*pkey).pkey.cast::<EcKey>() };

    /* stay consistent to what EVP_PKEY_check demands */
    // SAFETY: `eckey` is live.
    if unsafe { (*eckey).priv_key }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_430) };
        return 0;
    }

    // SAFETY: `eckey` is live.
    unsafe { EC_KEY_check_key(eckey) }
}

/// `static int ec_pkey_public_check(const EVP_PKEY *pkey)` — `crypto/ec/ec_ameth.c:437-451`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ec_pkey_public_check(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    let eckey = unsafe { (*pkey).pkey.cast::<EcKey>() };

    // SAFETY: `eckey` is live.
    unsafe { EC_KEY_check_key(eckey) }
}

/// `static int ec_pkey_param_check(const EVP_PKEY *pkey)` — `crypto/ec/ec_ameth.c:453-464`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ec_pkey_param_check(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live.
    let eckey = unsafe { (*pkey).pkey.cast::<EcKey>() };

    /* stay consistent to what EVP_PKEY_check demands */
    // SAFETY: `eckey` is live.
    if unsafe { (*eckey).group }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_459) };
        return 0;
    }

    // SAFETY: `eckey` is live.
    unsafe { EC_GROUP_check((*eckey).group, ptr::null_mut()) }
}

/// `static size_t ec_pkey_dirty_cnt(const EVP_PKEY *pkey)` — `crypto/ec/ec_ameth.c:466-469`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ec_pkey_dirty_cnt(pkey: *const EvpPkey) -> usize {
    // SAFETY: `pkey` is live.
    unsafe { (*(*pkey).pkey.cast::<EcKey>()).dirty_cnt }
}

/// `static int ec_pkey_export_to(const EVP_PKEY *from, void *to_keydata,
/// OSSL_FUNC_keymgmt_import_fn *importer, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/ec/ec_ameth.c:471-606`.
///
/// # Safety
/// `from` is live; `to_keydata` is the importer's own object.
unsafe extern "C" fn ec_pkey_export_to(
    from: *const EvpPkey,
    to_keydata: *mut c_void,
    importer: Option<KeymgmtImportFn>,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut selection: c_int = 0;
    let mut pub_key_buf: *mut c_uchar = ptr::null_mut();
    let mut gen_buf: *mut c_uchar = ptr::null_mut();

    if from.is_null() {
        return 0;
    }
    // SAFETY: `from` is live.
    let eckey = unsafe { (*from).pkey.cast::<EcKey>() };
    if eckey.is_null() {
        return 0;
    }
    // SAFETY: `eckey` is live.
    let ecg = unsafe { EC_KEY_get0_group(eckey) };
    if ecg.is_null() {
        return 0;
    }

    let tmpl = OSSL_PARAM_BLD_new();
    if tmpl.is_null() {
        return 0;
    }

    /* EC_POINT_point2buf() can generate random numbers in some implementations so we need to
     * ensure we use the correct libctx. */
    // SAFETY: no preconditions.
    let bnctx = unsafe { BN_CTX_new_ex(libctx) };
    if bnctx.is_null() {
        // goto err
        // SAFETY: `tmpl` is live.
        unsafe { OSSL_PARAM_BLD_free(tmpl) };
        return 0;
    }
    // SAFETY: `bnctx` is live.
    unsafe { BN_CTX_start(bnctx) };

    /* export the domain parameters */
    // SAFETY: `ecg` is live and every other argument is the caller's.
    if unsafe {
        ossl_ec_group_todata(
            ecg,
            tmpl,
            ptr::null_mut(),
            libctx,
            propq,
            bnctx,
            &mut gen_buf,
        )
    } == 0
    {
        // goto err
        // SAFETY: `tmpl`, `bnctx`, and the buffers are live.
        unsafe {
            OSSL_PARAM_BLD_free(tmpl);
            CRYPTO_free(pub_key_buf.cast(), FILE, 601);
            CRYPTO_free(gen_buf.cast(), FILE, 602);
            BN_CTX_end(bnctx);
            BN_CTX_free(bnctx);
        }
        return 0;
    }
    selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;

    // SAFETY: `eckey` is live.
    let priv_key = unsafe { EC_KEY_get0_private_key(eckey) };
    // SAFETY: `eckey` is live.
    let pub_point = unsafe { EC_KEY_get0_public_key(eckey) };

    if !pub_point.is_null() {
        /* convert pub_point to a octet string according to the SECG standard */
        // SAFETY: `eckey` is live.
        let format = unsafe { EC_KEY_get_conv_form(eckey) };

        // SAFETY: `ecg`/`pub_point` are live and every other argument is the caller's.
        let pub_key_buflen =
            unsafe { EC_POINT_point2buf(ecg, pub_point, format, &mut pub_key_buf, bnctx) };
        if pub_key_buflen == 0
            // SAFETY: `tmpl` is live and the buffer is `pub_key_buflen` long.
            || unsafe {
                OSSL_PARAM_BLD_push_octet_string(
                    tmpl,
                    OSSL_PKEY_PARAM_PUB_KEY,
                    pub_key_buf.cast(),
                    pub_key_buflen,
                )
            } == 0
        {
            // goto err
            // SAFETY: `tmpl` is live and the buffers/context this arm has built are owned here.
            unsafe {
                OSSL_PARAM_BLD_free(tmpl);
                CRYPTO_free(pub_key_buf.cast(), FILE, 601);
                CRYPTO_free(gen_buf.cast(), FILE, 602);
                BN_CTX_end(bnctx);
                BN_CTX_free(bnctx);
            }
            return 0;
        }
        selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    }

    if !priv_key.is_null() {
        // SAFETY: `ecg` is live.
        let ecbits = unsafe { EC_GROUP_order_bits(ecg) };
        if ecbits <= 0 {
            // goto err
            // SAFETY: `tmpl` is live and the buffers/context this arm has built are owned here.
            unsafe {
                OSSL_PARAM_BLD_free(tmpl);
                CRYPTO_free(pub_key_buf.cast(), FILE, 601);
                CRYPTO_free(gen_buf.cast(), FILE, 602);
                BN_CTX_end(bnctx);
                BN_CTX_free(bnctx);
            }
            return 0;
        }

        let sz = ((ecbits + 7) / 8) as usize;
        // SAFETY: `tmpl` is live and `priv_key` is live.
        if unsafe { OSSL_PARAM_BLD_push_BN_pad(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, priv_key, sz) } == 0
        {
            // goto err
            // SAFETY: `tmpl` is live and the buffers/context this arm has built are owned here.
            unsafe {
                OSSL_PARAM_BLD_free(tmpl);
                CRYPTO_free(pub_key_buf.cast(), FILE, 601);
                CRYPTO_free(gen_buf.cast(), FILE, 602);
                BN_CTX_end(bnctx);
                BN_CTX_free(bnctx);
            }
            return 0;
        }
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

        /* The ECDH Cofactor Mode is defined only if the EC_KEY actually contains a private key. */
        // SAFETY: `eckey` is live.
        let ecdh_cofactor_mode = if unsafe { EC_KEY_get_flags(eckey) } & EC_FLAG_COFACTOR_ECDH != 0
        {
            1
        } else {
            0
        };

        // SAFETY: `tmpl` is live.
        if unsafe {
            OSSL_PARAM_BLD_push_int(tmpl, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, ecdh_cofactor_mode)
        } == 0
        {
            // goto err
            // SAFETY: `tmpl` is live and the buffers/context this arm has built are owned here.
            unsafe {
                OSSL_PARAM_BLD_free(tmpl);
                CRYPTO_free(pub_key_buf.cast(), FILE, 601);
                CRYPTO_free(gen_buf.cast(), FILE, 602);
                BN_CTX_end(bnctx);
                BN_CTX_free(bnctx);
            }
            return 0;
        }
        selection |= OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
    }

    // SAFETY: `tmpl` is live.
    let params = unsafe { OSSL_PARAM_BLD_to_param(tmpl) };

    /* We export, the provider imports */
    // SAFETY: `importer` is the destination's own function.
    let rv = unsafe { importer.map_or(0, |f| f(to_keydata, selection, params)) };

    // SAFETY: every pointer is live.
    unsafe {
        OSSL_PARAM_BLD_free(tmpl);
        OSSL_PARAM_free(params);
        CRYPTO_free(pub_key_buf.cast(), FILE, 601);
        CRYPTO_free(gen_buf.cast(), FILE, 602);
        BN_CTX_end(bnctx);
        BN_CTX_free(bnctx);
    }
    rv
}

/// `static int ec_pkey_import_from(const OSSL_PARAM params[], void *vpctx)` —
/// `crypto/ec/ec_ameth.c:608-627`.
///
/// # Safety
/// `params` is a live parameter array; `vpctx` is a live `EVP_PKEY_CTX`.
unsafe extern "C" fn ec_pkey_import_from(params: *const OsslParam, vpctx: *mut c_void) -> c_int {
    let pctx = vpctx.cast::<crate::evp::pkey_ctx::EvpPkeyCtx>();
    // SAFETY: `pctx` is live per the contract.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
    // SAFETY: `pctx` is live.
    let ec = unsafe { EC_KEY_new_ex((*pctx).libctx, (*pctx).propquery) };

    if ec.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EC_AMETH_615) };
        return 0;
    }

    // SAFETY: `ec` is live, `params` is the caller's array, and `pkey` is live.
    if unsafe {
        ossl_ec_group_fromdata(ec, params) == 0
            || ossl_ec_key_otherparams_fromdata(ec, params) == 0
            || ossl_ec_key_fromdata(ec, params, 1) == 0
            || EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec.cast()) == 0
    } {
        // SAFETY: `ec` is live.
        unsafe { EC_KEY_free(ec) };
        return 0;
    }
    1
}

/// `static int ec_pkey_copy(EVP_PKEY *to, EVP_PKEY *from)` — `crypto/ec/ec_ameth.c:629-648`.
///
/// # Safety
/// `to` and `from` are live.
unsafe extern "C" fn ec_pkey_copy(to: *mut EvpPkey, from: *mut EvpPkey) -> c_int {
    // SAFETY: `from` is live.
    let eckey = unsafe { (*from).pkey.cast::<EcKey>() };

    let dupkey: *mut EcKey = if !eckey.is_null() {
        // SAFETY: `eckey` is live.
        let d = unsafe { EC_KEY_dup(eckey) };
        if d.is_null() {
            return 0;
        }
        d
    } else {
        /* necessary to properly copy empty SM2 keys */
        // SAFETY: `to` and `from` are live.
        return unsafe { crate::evp::pkey::EVP_PKEY_set_type(to, (*from).type_) };
    };

    // SAFETY: `to` is live.
    let ret = unsafe { EVP_PKEY_assign(to, EVP_PKEY_EC, dupkey.cast()) };
    if ret == 0 {
        // SAFETY: `dupkey` is live.
        unsafe { EC_KEY_free(dupkey) };
    }
    ret
}

/// `const EVP_PKEY_ASN1_METHOD ossl_eckey_asn1_meth` — `crypto/ec/ec_ameth.c:650-699`.
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_eckey_asn1_meth: EvpPkeyAsn1Method = EvpPkeyAsn1Method {
    pkey_id: EVP_PKEY_EC,
    pkey_base_id: EVP_PKEY_EC,
    pkey_flags: 0,
    pem_str: c"EC".as_ptr().cast_mut(),
    info: c"OpenSSL EC algorithm".as_ptr().cast_mut(),
    pub_decode: Some(eckey_pub_decode),
    pub_encode: Some(eckey_pub_encode),
    pub_cmp: Some(eckey_pub_cmp),
    pub_print: Some(eckey_pub_print),
    priv_decode: None,
    priv_encode: Some(eckey_priv_encode),
    priv_print: Some(eckey_priv_print),
    pkey_size: Some(int_ec_size),
    pkey_bits: Some(ec_bits),
    pkey_security_bits: Some(ec_security_bits),
    param_decode: Some(eckey_param_decode),
    param_encode: Some(eckey_param_encode),
    param_missing: Some(ec_missing_parameters),
    param_copy: Some(ec_copy_parameters),
    param_cmp: Some(ec_cmp_parameters),
    param_print: Some(eckey_param_print),
    sig_print: None,
    pkey_free: Some(int_ec_free),
    pkey_ctrl: Some(ec_pkey_ctrl),
    old_priv_decode: Some(old_ec_priv_decode),
    old_priv_encode: Some(old_ec_priv_encode),
    item_verify: None,
    item_sign: None,
    siginf_set: None,
    pkey_check: Some(ec_pkey_check),
    pkey_public_check: Some(ec_pkey_public_check),
    pkey_param_check: Some(ec_pkey_param_check),
    set_priv_key: None,
    set_pub_key: None,
    get_priv_key: None,
    get_pub_key: None,
    dirty_cnt: Some(ec_pkey_dirty_cnt),
    export_to: Some(ec_pkey_export_to),
    import_from: Some(ec_pkey_import_from),
    copy: Some(ec_pkey_copy),
    priv_decode_ex: Some(eckey_priv_decode_ex),
};

/// `const EVP_PKEY_ASN1_METHOD ossl_sm2_asn1_meth` — `crypto/ec/ec_ameth.c:702-707`.
///
/// A three-line alias: SM2 has no method of its own, it resolves to `EVP_PKEY_EC`'s, and the
/// distinction the SM2 row makes is the **`pkey_ctrl`**'s, which tests `EVP_PKEY_get_id(pkey)`
/// against `EVP_PKEY_SM2` and answers SM3 rather than SHA-256.
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_sm2_asn1_meth: EvpPkeyAsn1Method = EvpPkeyAsn1Method {
    pkey_id: EVP_PKEY_SM2,
    pkey_base_id: EVP_PKEY_EC,
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
};
