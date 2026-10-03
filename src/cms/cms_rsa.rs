//! `crypto/cms/cms_rsa.c` — the RSA sign and envelope arms `cms_sd.c`/`cms_env.c` dispatch to.
//! Phase 12.3b.
//!
//! The unit defines no export the atlas attributes to this stratum; it is pulled forward because
//! `cms_sd.c` and `cms_env.c` reach it and it is cms-local.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_type::ASN1_TYPE_unpack_sequence;
use crate::asn1::asn_pack::ASN1_item_pack;
use crate::asn1::layout::{Asn1String, V_ASN1_NULL, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE};
use crate::asn1::string::{
    ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set, ASN1_STRING_free,
    ASN1_STRING_get0_data, ASN1_STRING_length,
};
use crate::asn1::x_algor::{
    d2i_X509_ALGOR, ossl_X509_ALGOR_from_nid, ossl_x509_algor_get_md, ossl_x509_algor_md_to_mgf1,
    ossl_x509_algor_mgf1_decode, ossl_x509_algor_new_from_md, X509Algor, X509_ALGOR_get0,
    X509_ALGOR_set0,
};
use crate::evp::digest::EvpMd;
use crate::evp::pkey::EVP_PKEY_is_a;
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_get0_pkey, EVP_PKEY_CTX_get_params, EVP_PKEY_RSA_PSS};
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OsslParam};
use crate::rsa::ameth::{ossl_rsa_ctx_to_pss_string, ossl_rsa_pss_to_ctx};
use crate::rsa::asn1::{RSA_OAEP_PARAMS_free, RSA_OAEP_PARAMS_it, RSA_OAEP_PARAMS_new};
use crate::rsa::ctrl::{
    EVP_PKEY_CTX_get0_rsa_oaep_label, EVP_PKEY_CTX_get_rsa_mgf1_md, EVP_PKEY_CTX_get_rsa_oaep_md,
    EVP_PKEY_CTX_get_rsa_padding, EVP_PKEY_CTX_set0_rsa_oaep_label, EVP_PKEY_CTX_set_rsa_mgf1_md,
    EVP_PKEY_CTX_set_rsa_oaep_md, EVP_PKEY_CTX_set_rsa_padding,
};
use crate::rsa::RsaOaepParams;
use crate::runtime::err::err_reasons;
use crate::runtime::err::raise_with;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup};
use crate::runtime::obj::{
    Asn1Object, NID_pSpecified, NID_rsaEncryption, NID_rsaesOaep, OBJ_find_sigid_algs, OBJ_nid2obj,
    OBJ_obj2nid,
};

use super::cms_asn1::{CmsRecipientInfo, CmsSignerInfo};
use super::cms_lib::raise_cms;

/// `ERR_LIB_RSA` — `include/openssl/err.h.in:84`.
const ERR_LIB_RSA: c_int = 4;
/// `RSA_PKCS1_PADDING` — `include/openssl/rsa.h:317`.
const RSA_PKCS1_PADDING: c_int = 1;
/// `RSA_PKCS1_OAEP_PADDING` — `include/openssl/rsa.h:319`.
const RSA_PKCS1_OAEP_PADDING: c_int = 4;
/// `RSA_PKCS1_PSS_PADDING` — `include/openssl/rsa.h:321`.
const RSA_PKCS1_PSS_PADDING: c_int = 6;

/// `int rsa_cms_sign(CMS_SignerInfo *si)` — `cms_rsa.c:202-249`.
///
/// # Safety
/// `si` is live.
unsafe fn rsa_cms_sign(si: *mut CmsSignerInfo) -> c_int {
    let mut pad_mode = RSA_PKCS1_PADDING;
    let mut alg: *mut X509Algor = ptr::null_mut();
    // SAFETY: `si` is live.
    let pkctx = unsafe { super::cms_sd::CMS_SignerInfo_get0_pkey_ctx(si) };
    // SAFETY: `si` is live.
    unsafe {
        super::cms_sd::CMS_SignerInfo_get0_algs(
            si,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut alg,
        )
    };
    // SAFETY: `pkctx` is NULL or live.
    if !pkctx.is_null() && unsafe { EVP_PKEY_CTX_get_rsa_padding(pkctx, &mut pad_mode) } <= 0 {
        return 0;
    }
    if pad_mode == RSA_PKCS1_PADDING {
        // SAFETY: `alg` is live.
        return unsafe {
            X509_ALGOR_set0(
                alg,
                OBJ_nid2obj(NID_rsaEncryption),
                V_ASN1_NULL,
                ptr::null_mut(),
            )
        };
    }
    if pad_mode != RSA_PKCS1_PSS_PADDING {
        return 0;
    }
    // SAFETY: `pkctx` is live.
    if unsafe { (*pkctx).is_legacy() } {
        // SAFETY: `pkctx` is live.
        let os = unsafe { ossl_rsa_ctx_to_pss_string(pkctx) };
        if os.is_null() {
            return 0;
        }
        // SAFETY: `alg` is live.
        if unsafe {
            X509_ALGOR_set0(
                alg,
                OBJ_nid2obj(EVP_PKEY_RSA_PSS),
                V_ASN1_SEQUENCE,
                os.cast(),
            )
        } != 0
        {
            return 1;
        }
        // SAFETY: `os` is owned here.
        unsafe { ASN1_STRING_free(os) };
        return 0;
    }
    let mut aid = [0u8; 128];
    let mut pp: *const c_uchar = aid.as_ptr();
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    // SAFETY: `OSSL_PARAM_construct_octet_string` writes a descriptor into the caller's slot.
    params[0] = unsafe {
        OSSL_PARAM_construct_octet_string(
            c"algorithm-id".as_ptr(),
            aid.as_mut_ptr().cast(),
            aid.len(),
        )
    };
    // SAFETY: `pkctx` is live; `params` is readable.
    if unsafe { EVP_PKEY_CTX_get_params(pkctx, params.as_mut_ptr()) } <= 0 {
        return 0;
    }
    let aid_len = params[0].return_size;
    if aid_len == 0 {
        return 0;
    }
    // SAFETY: `pp` is readable for `aid_len`.
    if unsafe { d2i_X509_ALGOR(&mut alg, &mut pp, aid_len as c_long) }.is_null() {
        return 0;
    }
    1
}

/// `int rsa_cms_verify(CMS_SignerInfo *si)` — `cms_rsa.c:251-275`.
///
/// # Safety
/// `si` is live.
unsafe fn rsa_cms_verify(si: *mut CmsSignerInfo) -> c_int {
    let mut alg: *mut X509Algor = ptr::null_mut();
    // SAFETY: `si` is live.
    let pkctx = unsafe { super::cms_sd::CMS_SignerInfo_get0_pkey_ctx(si) };
    // SAFETY: `pkctx` is live.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(pkctx) };
    // SAFETY: `si` is live.
    unsafe {
        super::cms_sd::CMS_SignerInfo_get0_algs(
            si,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut alg,
        )
    };
    // SAFETY: `alg` is live.
    let nid = unsafe { OBJ_obj2nid((*alg).algorithm) };
    if nid == EVP_PKEY_RSA_PSS {
        // SAFETY: `pkctx`/`alg` are live.
        return c_int::from(
            unsafe { ossl_rsa_pss_to_ctx(ptr::null_mut(), pkctx, alg, ptr::null_mut()) } > 0,
        );
    }
    // SAFETY: `pkey` is live.
    if unsafe { EVP_PKEY_is_a(pkey, c"RSA-PSS".as_ptr()) } != 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_with(
                ERR_LIB_RSA,
                err_reasons::RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE,
                c"cms_rsa.c".as_ptr(),
                264,
            )
        };
        return 0;
    }
    if nid == NID_rsaEncryption {
        return 1;
    }
    let mut nid2 = 0;
    // SAFETY: `nid` is an integer.
    if unsafe { OBJ_find_sigid_algs(nid, ptr::null_mut(), &mut nid2) } != 0
        && nid2 == NID_rsaEncryption
    {
        return 1;
    }
    0
}

/// `RSA_OAEP_PARAMS *rsa_oaep_decode(const X509_ALGOR *alg)` — `cms_rsa.c:19-37`.
///
/// # Safety
/// `alg` is live.
unsafe fn rsa_oaep_decode(alg: *const X509Algor) -> *mut RsaOaepParams {
    // SAFETY: `alg` is live; `RSA_OAEP_PARAMS_it` is a static item.
    let oaep = unsafe {
        ASN1_TYPE_unpack_sequence(RSA_OAEP_PARAMS_it(), (*alg).parameter).cast::<RsaOaepParams>()
    };
    if oaep.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `oaep` is live.
    if !unsafe { (*oaep).mask_gen_func }.is_null() {
        // SAFETY: `oaep` is live.
        let mask_hash = unsafe { ossl_x509_algor_mgf1_decode((*oaep).mask_gen_func) };
        // SAFETY: `oaep` is live.
        unsafe { (*oaep).mask_hash = mask_hash };
        if mask_hash.is_null() {
            // SAFETY: `oaep` is owned here.
            unsafe { RSA_OAEP_PARAMS_free(oaep) };
            return ptr::null_mut();
        }
    }
    oaep
}

/// `int rsa_cms_decrypt(CMS_RecipientInfo *ri)` — `cms_rsa.c:39-119`.
///
/// # Safety
/// `ri` is live.
unsafe fn rsa_cms_decrypt(ri: *mut CmsRecipientInfo) -> c_int {
    let mut cmsalg: *mut X509Algor = ptr::null_mut();
    let mut rv = -1;
    let mut label: *const c_uchar = ptr::null();
    let mut labellen = 0;
    let mut mgf1md: *const EvpMd = ptr::null();
    let mut md: *const EvpMd = ptr::null();
    let mut oaep: *mut RsaOaepParams = ptr::null_mut();
    let mut aoid: *const Asn1Object = ptr::null();
    let mut parameter: *const c_void = ptr::null();
    let mut ptype = 0;

    // SAFETY: `ri` is live.
    let pkctx = unsafe { super::cms_env::CMS_RecipientInfo_get0_pkey_ctx(ri) };
    if pkctx.is_null() {
        return 0;
    }
    // SAFETY: `ri` is live; the three slots are this frame's.
    if unsafe {
        super::cms_env::CMS_RecipientInfo_ktri_get0_algs(
            ri,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut cmsalg,
        )
    } == 0
    {
        return -1;
    }
    // SAFETY: `cmsalg` is live.
    let nid = unsafe { OBJ_obj2nid((*cmsalg).algorithm) };
    if nid == NID_rsaEncryption {
        return 1;
    }
    if nid != NID_rsaesOaep {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                62,
                c"rsa_cms_decrypt",
                err_reasons::CMS_R_UNSUPPORTED_ENCRYPTION_TYPE,
            )
        };
        return -1;
    }
    // Decode OAEP parameters.
    // SAFETY: `cmsalg` is live.
    oaep = unsafe { rsa_oaep_decode(cmsalg) };
    if oaep.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                69,
                c"rsa_cms_decrypt",
                err_reasons::CMS_R_INVALID_OAEP_PARAMETERS,
            )
        };
        return rv;
    }
    'body: {
        // SAFETY: `oaep` is live.
        mgf1md = unsafe { ossl_x509_algor_get_md((*oaep).mask_hash) };
        if mgf1md.is_null() {
            break 'body;
        }
        // SAFETY: `oaep` is live.
        md = unsafe { ossl_x509_algor_get_md((*oaep).hash_func) };
        if md.is_null() {
            break 'body;
        }
        // SAFETY: `oaep` is live.
        if !unsafe { (*oaep).p_source_func }.is_null() {
            // SAFETY: `oaep` is live; the three slots are this frame's.
            unsafe {
                X509_ALGOR_get0(&mut aoid, &mut ptype, &mut parameter, (*oaep).p_source_func)
            };
            // SAFETY: `aoid` is live.
            if unsafe { OBJ_obj2nid(aoid) } != NID_pSpecified {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        84,
                        c"rsa_cms_decrypt",
                        err_reasons::CMS_R_UNSUPPORTED_LABEL_SOURCE,
                    )
                };
                break 'body;
            }
            if ptype != V_ASN1_OCTET_STRING {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cms(88, c"rsa_cms_decrypt", err_reasons::CMS_R_INVALID_LABEL) };
                break 'body;
            }
            // SAFETY: `parameter` is a live string.
            label = unsafe { ASN1_STRING_get0_data(parameter.cast::<Asn1String>()) };
            // SAFETY: `parameter` is a live string.
            labellen = unsafe { ASN1_STRING_length(parameter.cast::<Asn1String>()) };
        }
        // SAFETY: `pkctx` is live.
        if unsafe { EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_OAEP_PADDING) } <= 0 {
            break 'body;
        }
        // SAFETY: `pkctx`/`md` are live.
        if unsafe { EVP_PKEY_CTX_set_rsa_oaep_md(pkctx, md) } <= 0 {
            break 'body;
        }
        // SAFETY: `pkctx`/`mgf1md` are live.
        if unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) } <= 0 {
            break 'body;
        }
        if !label.is_null() {
            // SAFETY: `label` is readable for `labellen`.
            let dup_label = unsafe {
                CRYPTO_memdup(label.cast(), labellen as usize, c"cms_rsa.c".as_ptr(), 103)
            };
            if dup_label.is_null() {
                break 'body;
            }
            // SAFETY: `pkctx` is live; `dup_label` ownership transfers.
            if unsafe { EVP_PKEY_CTX_set0_rsa_oaep_label(pkctx, dup_label, labellen) } <= 0 {
                // SAFETY: `dup_label` is owned here.
                unsafe { CRYPTO_free(dup_label, c"cms_rsa.c".as_ptr(), 109) };
                break 'body;
            }
        }
        rv = 1;
    }
    // SAFETY: `oaep` is owned here.
    unsafe { RSA_OAEP_PARAMS_free(oaep) };
    rv
}

/// `int rsa_cms_encrypt(CMS_RecipientInfo *ri)` — `cms_rsa.c:121-186`.
///
/// # Safety
/// `ri` is live.
unsafe fn rsa_cms_encrypt(ri: *mut CmsRecipientInfo) -> c_int {
    let mut md: *const EvpMd = ptr::null();
    let mut mgf1md: *const EvpMd = ptr::null();
    let mut oaep: *mut RsaOaepParams = ptr::null_mut();
    let mut os: *mut Asn1String = ptr::null_mut();
    let mut los: *mut Asn1String = ptr::null_mut();
    let mut alg: *mut X509Algor = ptr::null_mut();
    // SAFETY: `ri` is live.
    let pkctx = unsafe { super::cms_env::CMS_RecipientInfo_get0_pkey_ctx(ri) };
    let mut pad_mode = RSA_PKCS1_PADDING;
    let mut rv = 0;
    let mut label: *mut c_uchar = ptr::null_mut();

    // SAFETY: `ri` is live.
    if unsafe {
        super::cms_env::CMS_RecipientInfo_ktri_get0_algs(
            ri,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut alg,
        )
    } <= 0
    {
        return 0;
    }
    if !pkctx.is_null() {
        // SAFETY: `pkctx` is live.
        if unsafe { EVP_PKEY_CTX_get_rsa_padding(pkctx, &mut pad_mode) } <= 0 {
            return 0;
        }
    }
    if pad_mode == RSA_PKCS1_PADDING {
        // SAFETY: `alg` is live.
        return unsafe {
            X509_ALGOR_set0(
                alg,
                OBJ_nid2obj(NID_rsaEncryption),
                V_ASN1_NULL,
                ptr::null_mut(),
            )
        };
    }
    if pad_mode != RSA_PKCS1_OAEP_PADDING {
        return 0;
    }
    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_CTX_get_rsa_oaep_md(pkctx, &mut md) } <= 0 {
        return 0;
    }
    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mut mgf1md) } <= 0 {
        return 0;
    }
    // SAFETY: `pkctx` is live; `label` is this frame's slot.
    let labellen = unsafe { EVP_PKEY_CTX_get0_rsa_oaep_label(pkctx, &mut label) };
    if labellen < 0 {
        return 0;
    }
    'enc: {
        // SAFETY: the allocator answers a fresh value.
        oaep = RSA_OAEP_PARAMS_new();
        if oaep.is_null() {
            break 'enc;
        }
        // SAFETY: `oaep` is live.
        if unsafe { ossl_x509_algor_new_from_md(&mut (*oaep).hash_func, md) } == 0 {
            break 'enc;
        }
        // SAFETY: `oaep` is live.
        if unsafe { ossl_x509_algor_md_to_mgf1(&mut (*oaep).mask_gen_func, mgf1md) } == 0 {
            break 'enc;
        }
        if labellen > 0 {
            // SAFETY: the allocator answers a fresh value.
            los = ASN1_OCTET_STRING_new();
            if los.is_null() {
                break 'enc;
            }
            // SAFETY: `los` is live; `label` is readable for `labellen`.
            if unsafe { ASN1_OCTET_STRING_set(los, label, labellen) } == 0 {
                break 'enc;
            }
            // SAFETY: `los` ownership transfers to the identifier.
            let ps = unsafe {
                ossl_X509_ALGOR_from_nid(NID_pSpecified, V_ASN1_OCTET_STRING, los.cast())
            };
            // SAFETY: `oaep` is live.
            unsafe { (*oaep).p_source_func = ps };
            if ps.is_null() {
                break 'enc;
            }
            los = ptr::null_mut();
        }
        // SAFETY: `oaep` is live; `os` is this frame's slot.
        if unsafe { ASN1_item_pack(oaep.cast(), RSA_OAEP_PARAMS_it(), &mut os) }.is_null() {
            break 'enc;
        }
        // SAFETY: `alg`/`os` are live.
        if unsafe { X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaesOaep), V_ASN1_SEQUENCE, os.cast()) }
            == 0
        {
            break 'enc;
        }
        os = ptr::null_mut();
        rv = 1;
    }
    // SAFETY: each is NULL or owned here.
    unsafe {
        RSA_OAEP_PARAMS_free(oaep);
        ASN1_STRING_free(os);
        ASN1_OCTET_STRING_free(los);
    }
    rv
}

/// `int ossl_cms_rsa_envelope(CMS_RecipientInfo *ri, int decrypt)` — `cms_rsa.c:188-200`.
///
/// # Safety
/// `ri` is live.
pub(crate) unsafe extern "C" fn ossl_cms_rsa_envelope(
    ri: *mut CmsRecipientInfo,
    decrypt: c_int,
) -> c_int {
    if decrypt == 1 {
        // SAFETY: `ri` is live.
        return unsafe { rsa_cms_decrypt(ri) };
    }
    if decrypt == 0 {
        // SAFETY: `ri` is live.
        return unsafe { rsa_cms_encrypt(ri) };
    }
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_cms(
            198,
            c"ossl_cms_rsa_envelope",
            err_reasons::CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE,
        )
    };
    0
}

/// `int ossl_cms_rsa_sign(CMS_SignerInfo *si, int verify)` — `cms_rsa.c:277-289`.
///
/// # Safety
/// `si` is live.
pub(crate) unsafe extern "C" fn ossl_cms_rsa_sign(si: *mut CmsSignerInfo, verify: c_int) -> c_int {
    if verify == 1 {
        // SAFETY: `si` is live.
        return unsafe { rsa_cms_verify(si) };
    }
    if verify == 0 {
        // SAFETY: `si` is live.
        return unsafe { rsa_cms_sign(si) };
    }
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_cms(
            287,
            c"ossl_cms_rsa_sign",
            err_reasons::CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE,
        )
    };
    0
}
