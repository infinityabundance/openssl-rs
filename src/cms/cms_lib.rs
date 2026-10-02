//! `crypto/cms/cms_lib.c` — the `CMS_ContentInfo` object model: its allocation, the per-content
//! accessors, the certificate/CRL choice stacks, the content BIO and the data init/final arms.
//! Phase 12.3.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i_ex;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::new::{ASN1_item_new, ASN1_item_new_ex};
use crate::asn1::string::{
    ASN1_OCTET_STRING_cmp, ASN1_STRING_copy, ASN1_STRING_dup, ASN1_STRING_new, ASN1_STRING_set0,
};
use crate::asn1::tasn_prn::ASN1_item_print;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0};
use crate::evp::bio_enc::BIO_f_md;
use crate::evp::digest::{
    EVP_MD_CTX_copy_ex, EVP_MD_CTX_get0_md, EVP_MD_CTX_set_params, EVP_MD_fetch, EVP_MD_free,
    EVP_MD_get_pkey_type, EVP_MD_get_type, EVP_MD_is_a, EVP_MD_xof, EvpMd,
};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_size_t, OsslParam};
use crate::runtime::bio::bss_mem::{BIO_new_mem_buf, BIO_s_mem};
use crate::runtime::bio::bss_null::BIO_s_null;
use crate::runtime::bio::{
    BIO_ctrl, BIO_find_type, BIO_free, BIO_new, BIO_push, BIO_set_flags, Bio, BIO_CTRL_INFO,
    BIO_C_GET_MD_CTX, BIO_C_SET_BUF_MEM_EOF_RETURN, BIO_C_SET_MD, BIO_FLAGS_MEM_RDONLY,
    BIO_TYPE_MD, BIO_TYPE_MEM,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::CRYPTO_strdup;
use crate::runtime::obj::{OBJ_dup, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_purp::X509_get0_subject_key_id;
use crate::x509::x509_cmp::{
    X509_NAME_cmp, X509_add_cert, X509_cmp, X509_get0_serialNumber, X509_get_issuer_name,
};
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_crl::{X509Crl, X509_CRL_free, X509_CRL_up_ref};
use crate::x509::x_name::X509_NAME_set;
use crate::x509::x_x509::{ossl_x509_set0_libctx, X509_free, X509};

use super::cms_asn1::*;
use super::cms_cd::ossl_cms_CompressedData_init_bio;
use super::cms_dd::{ossl_cms_DigestedData_do_final, ossl_cms_DigestedData_init_bio};
use super::cms_enc::ossl_cms_EncryptedData_init_bio;
use super::cms_env::{
    ossl_cms_AuthEnvelopedData_final, ossl_cms_AuthEnvelopedData_init_bio,
    ossl_cms_EnvelopedData_final, ossl_cms_EnvelopedData_init_bio,
};
use super::cms_sd::{ossl_cms_SignedData_final, ossl_cms_SignedData_init_bio};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cms/cms_lib.c";

/// `ERR_LIB_CMS` — `include/openssl/err.h.in:111`.
pub(crate) const ERR_LIB_CMS: c_int = 46;
/// `ERR_R_ASN1_LIB` — `(13 | ERR_RFLAG_COMMON)`.
pub(crate) const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_X509_LIB` — `(11 | ERR_RFLAG_COMMON)`.
pub(crate) const ERR_R_X509_LIB: c_int = 524299;
/// `ERR_R_EVP_LIB` — `(6 | ERR_RFLAG_COMMON)`.
pub(crate) const ERR_R_EVP_LIB: c_int = 524294;
/// `ERR_R_BIO_LIB` — `(32 | ERR_RFLAG_COMMON)`.
pub(crate) const ERR_R_BIO_LIB: c_int = 524320;
/// `ERR_R_CRYPTO_LIB` — `(15 | ERR_RFLAG_COMMON)`.
pub(crate) const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_CMS_LIB` — `(46 | ERR_RFLAG_COMMON)`.
pub(crate) const ERR_R_CMS_LIB: c_int = 524334;
/// `ERR_R_PASSED_NULL_PARAMETER` — `258 | ERR_R_FATAL`.
pub(crate) const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;
/// `ERR_R_MALLOC_FAILURE` — `256 | ERR_R_FATAL`.
pub(crate) const ERR_R_MALLOC_FAILURE: c_int = 786688;

/// `OSSL_MAX_NAME_SIZE` — `internal/sizes.h:15`.
pub(crate) const OSSL_MAX_NAME_SIZE: usize = 50;

/// One `cms_lib.c` raise coordinate, declared locally because this unit is not in
/// `gen_err_raise_sites.py`'s covered set.
const fn cms_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: FILE,
        line,
        func,
        lib: ERR_LIB_CMS,
        reason,
        dynamic_reason: false,
    }
}

/// `ERR_raise(ERR_LIB_CMS, reason)` at an authority coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
pub(crate) unsafe fn raise_cms(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_site(&cms_site(line, func, reason)) };
}

/// `CMS_ContentInfo *CMS_ContentInfo_new(void)` — `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` at
/// `cms_lib.c:28`.
#[no_mangle]
pub(crate) extern "C" fn CMS_ContentInfo_new() -> *mut CmsContentInfo {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(CMS_ContentInfo_it()) }.cast()
}

/// `void CMS_ContentInfo_free(CMS_ContentInfo *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_ContentInfo_free(a: *mut CmsContentInfo) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { crate::asn1::fre::ASN1_item_free(a.cast(), CMS_ContentInfo_it()) };
}

/// `int CMS_ContentInfo_print_ctx(BIO *out, CMS_ContentInfo *a, int indent, const ASN1_PCTX *pctx)`
/// — `IMPLEMENT_ASN1_PRINT_FUNCTION` at `cms_lib.c:29`.
///
/// # Safety
/// `out` is live; `a` is NULL or live; `pctx` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_ContentInfo_print_ctx(
    out: *mut Bio,
    a: *const CmsContentInfo,
    indent: c_int,
    pctx: *const c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_print(out, a.cast(), indent, CMS_ContentInfo_it(), pctx.cast()) }
}

/// `CMS_ContentInfo *d2i_CMS_ContentInfo(CMS_ContentInfo **a, const unsigned char **in, long len)`
/// — `cms_lib.c:31-47`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_CMS_ContentInfo(
    a: *mut *mut CmsContentInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut CmsContentInfo {
    // SAFETY: `a` is NULL or the caller's writable slot.
    let existing = if a.is_null() {
        ptr::null()
    } else {
        // SAFETY: `a` is non-null and the caller's writable slot.
        unsafe { *a }
    };
    // SAFETY: `existing` is NULL or live.
    let ctx = unsafe { ossl_cms_get0_cmsctx(existing) };
    // SAFETY: the caller's contract.
    let ci = unsafe {
        ASN1_item_d2i_ex(
            a.cast(),
            in_,
            len,
            CMS_ContentInfo_it(),
            ossl_cms_ctx_get0_libctx(ctx),
            ossl_cms_ctx_get0_propq(ctx),
        )
    }
    .cast::<CmsContentInfo>();
    if !ci.is_null() {
        // The authority wraps the libctx resolution in an error mark so the lookups it makes
        // cannot leak their refusals onto the caller's queue (`cms_lib.c:41-43`).
        crate::runtime::err::ERR_set_mark();
        // SAFETY: `ci` is a live decoded value.
        unsafe {
            ossl_cms_resolve_libctx(ci);
        }
        crate::runtime::err::ERR_pop_to_mark();
    }
    ci
}

/// `int i2d_CMS_ContentInfo(const CMS_ContentInfo *a, unsigned char **out)` — `cms_lib.c:49-52`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_CMS_ContentInfo(
    a: *const CmsContentInfo,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, CMS_ContentInfo_it()) }
}

/// `CMS_ContentInfo *CMS_ContentInfo_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `cms_lib.c:54-72`.
///
/// # Safety
/// `propq` is NULL or a NUL-terminated string; the answer is owned by the caller.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_ContentInfo_new_ex(
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmsContentInfo {
    // SAFETY: the accessor answers a static item.
    let ci =
        unsafe { ASN1_item_new_ex(CMS_ContentInfo_it(), libctx, propq) }.cast::<CmsContentInfo>();
    if !ci.is_null() {
        // SAFETY: `ci` was just allocated.
        unsafe {
            (*ci).ctx.libctx = libctx;
            (*ci).ctx.propq = ptr::null_mut();
            if !propq.is_null() {
                (*ci).ctx.propq = CRYPTO_strdup(propq, FILE.as_ptr(), 64);
                if (*ci).ctx.propq.is_null() {
                    CMS_ContentInfo_free(ci);
                    return ptr::null_mut();
                }
            }
        }
    }
    ci
}

/// `const CMS_CTX *ossl_cms_get0_cmsctx(const CMS_ContentInfo *cms)` — `cms_lib.c:74-77`.
///
/// # Safety
/// `cms` is NULL or live; a non-null answer borrows its context.
pub(crate) unsafe fn ossl_cms_get0_cmsctx(cms: *const CmsContentInfo) -> *const CmsCtx {
    if cms.is_null() {
        ptr::null()
    } else {
        // SAFETY: `cms` is live per the contract.
        unsafe { ptr::addr_of!((*cms).ctx) }
    }
}

/// `OSSL_LIB_CTX *ossl_cms_ctx_get0_libctx(const CMS_CTX *ctx)` — `cms_lib.c:79-82`.
///
/// # Safety
/// `ctx` is NULL or live.
pub(crate) unsafe fn ossl_cms_ctx_get0_libctx(ctx: *const CmsCtx) -> *mut c_void {
    if ctx.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `ctx` is live per the contract.
        unsafe { (*ctx).libctx }
    }
}

/// `const char *ossl_cms_ctx_get0_propq(const CMS_CTX *ctx)` — `cms_lib.c:84-87`.
///
/// # Safety
/// `ctx` is NULL or live.
pub(crate) unsafe fn ossl_cms_ctx_get0_propq(ctx: *const CmsCtx) -> *const c_char {
    if ctx.is_null() {
        ptr::null()
    } else {
        // SAFETY: `ctx` is live per the contract.
        unsafe { (*ctx).propq }
    }
}

/// `void ossl_cms_resolve_libctx(CMS_ContentInfo *ci)` — `cms_lib.c:89-109`.
///
/// # Safety
/// `ci` is NULL or live.
pub(crate) unsafe fn ossl_cms_resolve_libctx(ci: *mut CmsContentInfo) {
    if ci.is_null() {
        return;
    }
    // SAFETY: `ci` is live.
    unsafe {
        let ctx = ossl_cms_get0_cmsctx(ci);
        let libctx = ossl_cms_ctx_get0_libctx(ctx);
        let propq = ossl_cms_ctx_get0_propq(ctx);
        super::cms_sd::ossl_cms_SignerInfos_set_cmsctx(ci);
        super::cms_env::ossl_cms_RecipientInfos_set_cmsctx(ci);
        let pcerts = cms_get0_certificate_choices(ci);
        if !pcerts.is_null() {
            let n = OPENSSL_sk_num(*pcerts);
            for i in 0..n {
                let cch = OPENSSL_sk_value(*pcerts, i).cast::<CmsCertificateChoices>();
                if (*cch).type_ == CMS_CERTCHOICE_CERT {
                    ossl_x509_set0_libctx((*cch).d.cast(), libctx, propq);
                }
            }
        }
    }
}

/// `const ASN1_OBJECT *CMS_get0_type(const CMS_ContentInfo *cms)` — `cms_lib.c:111-114`.
///
/// # Safety
/// `cms` is live; the answer borrows its content type.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_get0_type(
    cms: *const CmsContentInfo,
) -> *const crate::runtime::obj::Asn1Object {
    // SAFETY: `cms` is live per the contract.
    unsafe { (*cms).content_type }
}

/// `CMS_ContentInfo *ossl_cms_Data_create(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `cms_lib.c:116-126`.
///
/// # Safety
/// `propq` is NULL or a NUL-terminated string.
pub(crate) unsafe extern "C" fn ossl_cms_Data_create(
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmsContentInfo {
    // SAFETY: the caller's contract.
    let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    if !cms.is_null() {
        // SAFETY: `cms` is live.
        unsafe {
            (*cms).content_type = OBJ_nid2obj(crate::runtime::obj::NID_pkcs7_data);
            CMS_set_detached(cms, 0);
        }
    }
    cms
}

/// `BIO *ossl_cms_content_bio(CMS_ContentInfo *cms)` — `cms_lib.c:128-144`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_content_bio(cms: *mut CmsContentInfo) -> *mut Bio {
    // SAFETY: `cms` is live per the contract.
    let pos = unsafe { CMS_get0_content(cms) };
    if pos.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pos` is a live slot.
    let content = unsafe { *pos };
    if content.is_null() {
        // SAFETY: the null method is a compile-time constant.
        return unsafe { BIO_new(BIO_s_null()) };
    }
    // SAFETY: `content` is live.
    if unsafe { (*content).flags } == crate::asn1::layout::ASN1_STRING_FLAG_CONT {
        // SAFETY: the memory method is a compile-time constant.
        return unsafe { BIO_new(BIO_s_mem()) };
    }
    // SAFETY: `content` is live and owns `data`/`length`.
    unsafe { BIO_new_mem_buf((*content).data.cast(), (*content).length) }
}

/// `BIO *CMS_dataInit(CMS_ContentInfo *cms, BIO *icont)` — `cms_lib.c:146-198`.
///
/// # Safety
/// `cms` is live; `icont` is NULL or a live BIO.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_dataInit(
    cms: *mut CmsContentInfo,
    icont: *mut Bio,
) -> *mut Bio {
    // SAFETY: `cms` is live per the contract.
    let cont = if !icont.is_null() {
        icont
    } else {
        // SAFETY: `cms` is live per the contract.
        unsafe { ossl_cms_content_bio(cms) }
    };
    if cont.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                154,
                c"CMS_dataInit",
                crate::runtime::err::err_reasons::CMS_R_NO_CONTENT,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `cms` is live.
    let cmsbio = match unsafe { OBJ_obj2nid((*cms).content_type) } {
        crate::runtime::obj::NID_pkcs7_data => return cont,
        crate::runtime::obj::NID_pkcs7_signed => {
            // SAFETY: `cms` is live per the contract.
            unsafe { ossl_cms_SignedData_init_bio(cms) }
        }
        crate::runtime::obj::NID_pkcs7_digest => {
            // SAFETY: `cms` is live per the contract.
            unsafe { ossl_cms_DigestedData_init_bio(cms) }
        }
        crate::runtime::obj::NID_id_smime_ct_compressedData => {
            // SAFETY: `cms` is live per the contract.
            unsafe { ossl_cms_CompressedData_init_bio(cms) }
        }
        crate::runtime::obj::NID_pkcs7_encrypted => {
            // SAFETY: `cms` is live per the contract.
            unsafe { ossl_cms_EncryptedData_init_bio(cms) }
        }
        crate::runtime::obj::NID_pkcs7_enveloped => {
            // SAFETY: `cms` is live per the contract.
            unsafe { ossl_cms_EnvelopedData_init_bio(cms) }
        }
        crate::runtime::obj::NID_id_smime_ct_authEnvelopedData => {
            // SAFETY: `cms` is live per the contract.
            unsafe { ossl_cms_AuthEnvelopedData_init_bio(cms) }
        }
        _ => {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    188,
                    c"CMS_dataInit",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_TYPE,
                )
            };
            if icont.is_null() {
                // SAFETY: `cont` is a live BIO this call owns.
                unsafe { BIO_free(cont) };
            }
            return ptr::null_mut();
        }
    };
    if !cmsbio.is_null() {
        // SAFETY: `cmsbio` and `cont` are live.
        return unsafe { BIO_push(cmsbio, cont) };
    }
    if icont.is_null() {
        // SAFETY: `cont` is a live BIO this call owns.
        unsafe { BIO_free(cont) };
    }
    ptr::null_mut()
}

/// `int CMS_dataFinal(CMS_ContentInfo *cms, BIO *cmsbio)` — `cms_lib.c:201-204`.
///
/// # Safety
/// `cms` and `cmsbio` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_dataFinal(cms: *mut CmsContentInfo, cmsbio: *mut Bio) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ossl_cms_DataFinal(cms, cmsbio, ptr::null(), 0) }
}

/// `int ossl_cms_DataFinal(CMS_ContentInfo *cms, BIO *cmsbio, const unsigned char *precomp_md,`
/// `unsigned int precomp_mdlen)` — `cms_lib.c:206-256`.
///
/// # Safety
/// `cms` and `cmsbio` are live; `precomp_md` is NULL or readable for `precomp_mdlen`.
pub(crate) unsafe extern "C" fn ossl_cms_DataFinal(
    cms: *mut CmsContentInfo,
    cmsbio: *mut Bio,
    precomp_md: *const c_uchar,
    precomp_mdlen: u32,
) -> c_int {
    // SAFETY: `cms` is live.
    let pos = unsafe { CMS_get0_content(cms) };
    if pos.is_null() {
        return 0;
    }
    // SAFETY: `pos` is a live slot.
    unsafe {
        if !(*pos).is_null() && ((*(*pos)).flags & crate::asn1::layout::ASN1_STRING_FLAG_CONT) != 0
        {
            let mbio = BIO_find_type(cmsbio, BIO_TYPE_MEM);
            if mbio.is_null() {
                raise_cms(
                    221,
                    c"ossl_cms_DataFinal",
                    crate::runtime::err::err_reasons::CMS_R_CONTENT_NOT_FOUND,
                );
                return 0;
            }
            let mut cont: *mut c_char = ptr::null_mut();
            let contlen = BIO_ctrl(
                mbio,
                BIO_CTRL_INFO,
                0,
                (&mut cont as *mut *mut c_char).cast(),
            );
            BIO_set_flags(mbio, BIO_FLAGS_MEM_RDONLY);
            BIO_ctrl(mbio, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, ptr::null_mut());
            let s = *pos;
            ASN1_STRING_set0(s, cont.cast(), contlen as c_int);
            (*s).flags &= !crate::asn1::layout::ASN1_STRING_FLAG_CONT;
        }
        match OBJ_obj2nid((*cms).content_type) {
            crate::runtime::obj::NID_pkcs7_data
            | crate::runtime::obj::NID_pkcs7_encrypted
            | crate::runtime::obj::NID_id_smime_ct_compressedData => 1,
            crate::runtime::obj::NID_pkcs7_enveloped => ossl_cms_EnvelopedData_final(cms, cmsbio),
            crate::runtime::obj::NID_id_smime_ct_authEnvelopedData => {
                ossl_cms_AuthEnvelopedData_final(cms, cmsbio)
            }
            crate::runtime::obj::NID_pkcs7_signed => {
                ossl_cms_SignedData_final(cms, cmsbio, precomp_md, precomp_mdlen)
            }
            crate::runtime::obj::NID_pkcs7_digest => ossl_cms_DigestedData_do_final(cms, cmsbio, 0),
            _ => {
                raise_cms(
                    253,
                    c"ossl_cms_DataFinal",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_TYPE,
                );
                0
            }
        }
    }
}

/// `ASN1_OCTET_STRING **CMS_get0_content(CMS_ContentInfo *cms)` — `cms_lib.c:263-298`.
///
/// # Safety
/// `cms` is live; a non-null answer is a pointer into it.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_get0_content(
    cms: *mut CmsContentInfo,
) -> *mut *mut crate::asn1::layout::Asn1String {
    // SAFETY: `cms` is live.
    unsafe {
        match OBJ_obj2nid((*cms).content_type) {
            crate::runtime::obj::NID_pkcs7_data => {
                ptr::addr_of_mut!((*cms).d).cast::<*mut crate::asn1::layout::Asn1String>()
            }
            crate::runtime::obj::NID_pkcs7_signed => {
                let sd = (*cms).d.cast::<CmsSignedData>();
                ptr::addr_of_mut!((*(*sd).encap_content_info).e_content)
            }
            crate::runtime::obj::NID_pkcs7_enveloped => {
                let ed = (*cms).d.cast::<CmsEnvelopedData>();
                ptr::addr_of_mut!((*(*ed).encrypted_content_info).encrypted_content)
            }
            crate::runtime::obj::NID_pkcs7_digest => {
                let dd = (*cms).d.cast::<CmsDigestedData>();
                ptr::addr_of_mut!((*(*dd).encap_content_info).e_content)
            }
            crate::runtime::obj::NID_pkcs7_encrypted => {
                let ed = (*cms).d.cast::<CmsEncryptedData>();
                ptr::addr_of_mut!((*(*ed).encrypted_content_info).encrypted_content)
            }
            crate::runtime::obj::NID_id_smime_ct_authEnvelopedData => {
                let aed = (*cms).d.cast::<CmsAuthEnvelopedData>();
                ptr::addr_of_mut!((*(*aed).auth_encrypted_content_info).encrypted_content)
            }
            crate::runtime::obj::NID_id_smime_ct_authData => {
                let ad = (*cms).d.cast::<CmsAuthenticatedData>();
                ptr::addr_of_mut!((*(*ad).encap_content_info).e_content)
            }
            crate::runtime::obj::NID_id_smime_ct_compressedData => {
                let cd = (*cms).d.cast::<CmsCompressedData>();
                ptr::addr_of_mut!((*(*cd).encap_content_info).e_content)
            }
            _ => {
                let other = (*cms).d.cast::<crate::asn1::layout::Asn1Type>();
                if (*other).type_ == crate::asn1::layout::V_ASN1_OCTET_STRING {
                    ptr::addr_of_mut!((*other).value).cast::<*mut crate::asn1::layout::Asn1String>()
                } else {
                    raise_cms(
                        295,
                        c"CMS_get0_content",
                        crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_CONTENT_TYPE,
                    );
                    ptr::null_mut()
                }
            }
        }
    }
}

/// `ASN1_OBJECT **cms_get0_econtent_type(CMS_ContentInfo *cms)` — `cms_lib.c:305-334`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_get0_econtent_type(
    cms: *mut CmsContentInfo,
) -> *mut *mut crate::runtime::obj::Asn1Object {
    // SAFETY: `cms` is live.
    unsafe {
        match OBJ_obj2nid((*cms).content_type) {
            crate::runtime::obj::NID_pkcs7_signed => {
                let sd = (*cms).d.cast::<CmsSignedData>();
                ptr::addr_of_mut!((*(*sd).encap_content_info).e_content_type)
            }
            crate::runtime::obj::NID_pkcs7_enveloped => {
                let ed = (*cms).d.cast::<CmsEnvelopedData>();
                ptr::addr_of_mut!((*(*ed).encrypted_content_info).content_type)
            }
            crate::runtime::obj::NID_pkcs7_digest => {
                let dd = (*cms).d.cast::<CmsDigestedData>();
                ptr::addr_of_mut!((*(*dd).encap_content_info).e_content_type)
            }
            crate::runtime::obj::NID_pkcs7_encrypted => {
                let ed = (*cms).d.cast::<CmsEncryptedData>();
                ptr::addr_of_mut!((*(*ed).encrypted_content_info).content_type)
            }
            crate::runtime::obj::NID_id_smime_ct_authEnvelopedData => {
                let aed = (*cms).d.cast::<CmsAuthEnvelopedData>();
                ptr::addr_of_mut!((*(*aed).auth_encrypted_content_info).content_type)
            }
            crate::runtime::obj::NID_id_smime_ct_authData => {
                let ad = (*cms).d.cast::<CmsAuthenticatedData>();
                ptr::addr_of_mut!((*(*ad).encap_content_info).e_content_type)
            }
            crate::runtime::obj::NID_id_smime_ct_compressedData => {
                let cd = (*cms).d.cast::<CmsCompressedData>();
                ptr::addr_of_mut!((*(*cd).encap_content_info).e_content_type)
            }
            _ => {
                raise_cms(
                    331,
                    c"cms_get0_econtent_type",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_CONTENT_TYPE,
                );
                ptr::null_mut()
            }
        }
    }
}

/// `const ASN1_OBJECT *CMS_get0_eContentType(CMS_ContentInfo *cms)` — `cms_lib.c:336-343`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_get0_eContentType(
    cms: *mut CmsContentInfo,
) -> *const crate::runtime::obj::Asn1Object {
    // SAFETY: `cms` is live.
    let petype = unsafe { cms_get0_econtent_type(cms) };
    if !petype.is_null() {
        // SAFETY: `petype` is a live slot.
        return unsafe { *petype };
    }
    ptr::null()
}

/// `int CMS_set1_eContentType(CMS_ContentInfo *cms, const ASN1_OBJECT *oid)` — `cms_lib.c:345-360`.
///
/// # Safety
/// `cms` is live; `oid` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_set1_eContentType(
    cms: *mut CmsContentInfo,
    oid: *const crate::runtime::obj::Asn1Object,
) -> c_int {
    // SAFETY: `cms` is live.
    let petype = unsafe { cms_get0_econtent_type(cms) };
    if petype.is_null() {
        return 0;
    }
    if oid.is_null() {
        return 1;
    }
    // SAFETY: `oid` is live.
    let etype = unsafe { OBJ_dup(oid) };
    if etype.is_null() {
        return 0;
    }
    // SAFETY: `petype` is a live slot.
    unsafe {
        crate::asn1::prim::ASN1_OBJECT_free(*petype);
        *petype = etype;
    }
    1
}

/// `int CMS_is_detached(CMS_ContentInfo *cms)` — `cms_lib.c:362-372`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_is_detached(cms: *mut CmsContentInfo) -> c_int {
    // SAFETY: `cms` is live.
    let pos = unsafe { CMS_get0_content(cms) };
    if pos.is_null() {
        return -1;
    }
    // SAFETY: `pos` is a live slot.
    if unsafe { !(*pos).is_null() } {
        0
    } else {
        1
    }
}

/// `int CMS_set_detached(CMS_ContentInfo *cms, int detached)` — `cms_lib.c:374-397`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_set_detached(
    cms: *mut CmsContentInfo,
    detached: c_int,
) -> c_int {
    // SAFETY: `cms` is live.
    let pos = unsafe { CMS_get0_content(cms) };
    if pos.is_null() {
        return 0;
    }
    // SAFETY: `pos` is a live slot.
    unsafe {
        if detached != 0 {
            crate::asn1::string::ASN1_STRING_free(*pos);
            *pos = ptr::null_mut();
            return 1;
        }
        if (*pos).is_null() {
            *pos = ASN1_STRING_new();
        }
        if !(*pos).is_null() {
            (*(*pos)).flags |= crate::asn1::layout::ASN1_STRING_FLAG_CONT;
            return 1;
        }
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cms(395, c"CMS_set_detached", ERR_R_ASN1_LIB) };
    0
}

/// `BIO *ossl_cms_DigestAlgorithm_init_bio(X509_ALGOR *digestAlgorithm, const CMS_CTX *ctx)` —
/// `cms_lib.c:401-458`.
///
/// # Safety
/// `digest_algorithm` is live; `ctx` is NULL or live.
pub(crate) unsafe fn ossl_cms_DigestAlgorithm_init_bio(
    digest_algorithm: *mut X509Algor,
    ctx: *const CmsCtx,
) -> *mut Bio {
    let mut digestoid: *const crate::runtime::obj::Asn1Object = ptr::null();
    // SAFETY: `digest_algorithm` is live.
    unsafe {
        X509_ALGOR_get0(
            &mut digestoid,
            ptr::null_mut(),
            ptr::null_mut(),
            digest_algorithm,
        )
    };
    let mut alg = [0 as c_char; OSSL_MAX_NAME_SIZE];
    // SAFETY: `digestoid` is live; `alg` is writable.
    unsafe { OBJ_obj2txt(alg.as_mut_ptr(), OSSL_MAX_NAME_SIZE as c_int, digestoid, 0) };
    // SAFETY: the caller's contract.
    let fetched = unsafe {
        EVP_MD_fetch(
            ossl_cms_ctx_get0_libctx(ctx),
            alg.as_ptr(),
            ossl_cms_ctx_get0_propq(ctx),
        )
    };
    let digest = if !fetched.is_null() {
        fetched
    } else {
        // SAFETY: `digestoid` is live.
        unsafe {
            let nid = OBJ_obj2nid(digestoid);
            EVP_get_digestbyname(OBJ_nid2sn(nid))
        }
    };
    if digest.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            EVP_MD_free(fetched);
            raise_cms(
                424,
                c"ossl_cms_DigestAlgorithm_init_bio",
                crate::runtime::err::err_reasons::CMS_R_UNKNOWN_DIGEST_ALGORITHM,
            );
        };
        return ptr::null_mut();
    }
    // SAFETY: the digest method is a compile-time constant.
    let mdbio = unsafe { BIO_new(BIO_f_md()) };
    // SAFETY: `mdbio` is NULL or live.
    if mdbio.is_null() || unsafe { bio_set_md(mdbio, digest) } <= 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                431,
                c"ossl_cms_DigestAlgorithm_init_bio",
                crate::runtime::err::err_reasons::CMS_R_MD_BIO_INIT_ERROR,
            )
        };
        // SAFETY: `fetched`/`mdbio` are NULL or owned.
        unsafe {
            EVP_MD_free(fetched);
            BIO_free(mdbio);
        }
        return ptr::null_mut();
    }
    // SAFETY: `digest` is live.
    if unsafe { EVP_MD_xof(digest) } != 0 {
        let mut xof_len: usize = 0;
        // SAFETY: `digest` is live.
        unsafe {
            if EVP_MD_is_a(digest, c"SHAKE128".as_ptr()) != 0 {
                xof_len = 32;
            } else if EVP_MD_is_a(digest, c"SHAKE256".as_ptr()) != 0 {
                xof_len = 64;
            }
        }
        if xof_len > 0 {
            let mut mdctx: *mut crate::evp::digest::EvpMdCtx = ptr::null_mut();
            // SAFETY: `mdbio` is live; `mdctx` is writable.
            if unsafe { bio_get_md_ctx(mdbio, &mut mdctx) } <= 0 || mdctx.is_null() {
                // SAFETY: `fetched`/`mdbio` are owned.
                unsafe {
                    EVP_MD_free(fetched);
                    BIO_free(mdbio);
                }
                return ptr::null_mut();
            }
            let mut params: [OsslParam; 2] =
                [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
            // SAFETY: `OSSL_PARAM_construct_size_t` writes a descriptor into the caller's slot.
            params[0] = unsafe {
                OSSL_PARAM_construct_size_t(c"xoflen".as_ptr(), &mut xof_len as *mut usize)
            };
            // SAFETY: `mdctx` is live; `params` is readable and NUL-terminated.
            if unsafe { EVP_MD_CTX_set_params(mdctx, params.as_ptr()) } == 0 {
                // SAFETY: `fetched`/`mdbio` are owned.
                unsafe {
                    EVP_MD_free(fetched);
                    BIO_free(mdbio);
                }
                return ptr::null_mut();
            }
        }
    }
    // SAFETY: `fetched` is NULL or owned.
    unsafe { EVP_MD_free(fetched) };
    mdbio
}

/// `int ossl_cms_DigestAlgorithm_find_ctx(EVP_MD_CTX *mctx, BIO *chain, X509_ALGOR *mdalg)` —
/// `cms_lib.c:462-487`.
///
/// # Safety
/// `mctx` is live; `chain` is NULL or a live BIO chain; `mdalg` is live.
pub(crate) unsafe fn ossl_cms_DigestAlgorithm_find_ctx(
    mctx: *mut crate::evp::digest::EvpMdCtx,
    mut chain: *mut Bio,
    mdalg: *mut X509Algor,
) -> c_int {
    let mut mdoid: *const crate::runtime::obj::Asn1Object = ptr::null();
    // SAFETY: `mdalg` is live.
    unsafe { X509_ALGOR_get0(&mut mdoid, ptr::null_mut(), ptr::null_mut(), mdalg) };
    // SAFETY: `mdoid` is live.
    let nid = unsafe { OBJ_obj2nid(mdoid) };
    loop {
        // SAFETY: `chain` is NULL or live.
        chain = unsafe { BIO_find_type(chain, BIO_TYPE_MD) };
        if chain.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    474,
                    c"ossl_cms_DigestAlgorithm_find_ctx",
                    crate::runtime::err::err_reasons::CMS_R_NO_MATCHING_DIGEST,
                )
            };
            return 0;
        }
        let mut mtmp: *mut crate::evp::digest::EvpMdCtx = ptr::null_mut();
        // SAFETY: `chain` is live; `mtmp` is writable.
        unsafe { bio_get_md_ctx(chain, &mut mtmp) };
        // SAFETY: `mtmp` is live.
        let found = unsafe {
            let md = EVP_MD_CTX_get0_md(mtmp);
            EVP_MD_get_type(md) == nid || EVP_MD_get_pkey_type(md) == nid
        };
        if found {
            // SAFETY: `mctx` and `mtmp` are live.
            return unsafe { EVP_MD_CTX_copy_ex(mctx, mtmp) };
        }
        // SAFETY: `chain` is live.
        chain = unsafe { crate::runtime::bio::BIO_next(chain) };
    }
}

/// `BIO_set_md(BIO *, const EVP_MD *)` — `BIO_ctrl(b, BIO_C_SET_MD, 0, md)`.
///
/// # Safety
/// `b` is a live digest BIO; `md` is live.
unsafe fn bio_set_md(b: *mut Bio, md: *const EvpMd) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_C_SET_MD, 0, md.cast_mut().cast()) as c_int }
}

/// `BIO_get_md_ctx(BIO *, EVP_MD_CTX **)` — `BIO_ctrl(b, BIO_C_GET_MD_CTX, 0, pmdc)`.
///
/// # Safety
/// `b` is a live digest BIO; `pmdc` is writable.
pub(crate) unsafe fn bio_get_md_ctx(
    b: *mut Bio,
    pmdc: *mut *mut crate::evp::digest::EvpMdCtx,
) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_C_GET_MD_CTX, 0, pmdc.cast()) as c_int }
}

/// `STACK_OF(CMS_CertificateChoices) **cms_get0_certificate_choices(CMS_ContentInfo *cms)` —
/// `cms_lib.c:489-512`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_get0_certificate_choices(cms: *mut CmsContentInfo) -> *mut *mut OpenSslStack {
    // SAFETY: `cms` is live.
    unsafe {
        match OBJ_obj2nid((*cms).content_type) {
            crate::runtime::obj::NID_pkcs7_signed => {
                let sd = (*cms).d.cast::<CmsSignedData>();
                ptr::addr_of_mut!((*sd).certificates)
            }
            crate::runtime::obj::NID_pkcs7_enveloped => {
                let ed = (*cms).d.cast::<CmsEnvelopedData>();
                if (*ed).originator_info.is_null() {
                    ptr::null_mut()
                } else {
                    ptr::addr_of_mut!((*(*ed).originator_info).certificates)
                }
            }
            crate::runtime::obj::NID_id_smime_ct_authEnvelopedData => {
                let aed = (*cms).d.cast::<CmsAuthEnvelopedData>();
                if (*aed).originator_info.is_null() {
                    ptr::null_mut()
                } else {
                    ptr::addr_of_mut!((*(*aed).originator_info).certificates)
                }
            }
            _ => {
                raise_cms(
                    509,
                    c"cms_get0_certificate_choices",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_CONTENT_TYPE,
                );
                ptr::null_mut()
            }
        }
    }
}

/// `CMS_CertificateChoices *CMS_add0_CertificateChoices(CMS_ContentInfo *cms)` —
/// `cms_lib.c:514-534`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add0_CertificateChoices(
    cms: *mut CmsContentInfo,
) -> *mut CmsCertificateChoices {
    // SAFETY: `cms` is live.
    let pcerts = unsafe { cms_get0_certificate_choices(cms) };
    if pcerts.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pcerts` is a live slot.
    unsafe {
        if (*pcerts).is_null() {
            *pcerts = OPENSSL_sk_new_null();
        }
        if (*pcerts).is_null() {
            return ptr::null_mut();
        }
        let cch = m_asn1_new(cms_certificatechoices_it()).cast::<CmsCertificateChoices>();
        if cch.is_null() {
            return ptr::null_mut();
        }
        if OPENSSL_sk_push(*pcerts, cch.cast()) == 0 {
            m_asn1_free(cch.cast(), cms_certificatechoices_it());
            return ptr::null_mut();
        }
        cch
    }
}

/// `int CMS_add0_cert(CMS_ContentInfo *cms, X509 *cert)` — `cms_lib.c:536-560`.
///
/// # Safety
/// `cms` is live; `cert` is live and ownership passes to `cms`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add0_cert(cms: *mut CmsContentInfo, cert: *mut X509) -> c_int {
    // SAFETY: `cms` is live.
    let pcerts = unsafe { cms_get0_certificate_choices(cms) };
    if pcerts.is_null() {
        return 0;
    }
    // SAFETY: `pcerts` is a live slot holding live choices.
    unsafe {
        let n = OPENSSL_sk_num(*pcerts);
        for i in 0..n {
            let cch = OPENSSL_sk_value(*pcerts, i).cast::<CmsCertificateChoices>();
            if (*cch).type_ == CMS_CERTCHOICE_CERT && X509_cmp((*cch).d.cast(), cert) == 0 {
                X509_free(cert);
                return 1;
            }
        }
        let cch = CMS_add0_CertificateChoices(cms);
        if cch.is_null() {
            return 0;
        }
        (*cch).type_ = CMS_CERTCHOICE_CERT;
        (*cch).d = cert.cast();
        1
    }
}

/// `int CMS_add1_cert(CMS_ContentInfo *cms, X509 *cert)` — `cms_lib.c:562-570`.
///
/// # Safety
/// `cms` and `cert` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add1_cert(cms: *mut CmsContentInfo, cert: *mut X509) -> c_int {
    // SAFETY: `cert` is live.
    if unsafe { X509_up_ref(cert) } == 0 {
        return 0;
    }
    // SAFETY: `cms` is live.
    if unsafe { CMS_add0_cert(cms, cert) } != 0 {
        return 1;
    }
    // SAFETY: `cert` is live and the reference added above is ours.
    unsafe { X509_free(cert) };
    0
}

/// `STACK_OF(CMS_RevocationInfoChoice) **cms_get0_revocation_choices(CMS_ContentInfo *cms)` —
/// `cms_lib.c:572-595`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_get0_revocation_choices(cms: *mut CmsContentInfo) -> *mut *mut OpenSslStack {
    // SAFETY: `cms` is live.
    unsafe {
        match OBJ_obj2nid((*cms).content_type) {
            crate::runtime::obj::NID_pkcs7_signed => {
                let sd = (*cms).d.cast::<CmsSignedData>();
                ptr::addr_of_mut!((*sd).crls)
            }
            crate::runtime::obj::NID_pkcs7_enveloped => {
                let ed = (*cms).d.cast::<CmsEnvelopedData>();
                if (*ed).originator_info.is_null() {
                    ptr::null_mut()
                } else {
                    ptr::addr_of_mut!((*(*ed).originator_info).crls)
                }
            }
            crate::runtime::obj::NID_id_smime_ct_authEnvelopedData => {
                let aed = (*cms).d.cast::<CmsAuthEnvelopedData>();
                if (*aed).originator_info.is_null() {
                    ptr::null_mut()
                } else {
                    ptr::addr_of_mut!((*(*aed).originator_info).crls)
                }
            }
            _ => {
                raise_cms(
                    592,
                    c"cms_get0_revocation_choices",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_CONTENT_TYPE,
                );
                ptr::null_mut()
            }
        }
    }
}

/// `CMS_RevocationInfoChoice *CMS_add0_RevocationInfoChoice(CMS_ContentInfo *cms)` —
/// `cms_lib.c:597-617`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add0_RevocationInfoChoice(
    cms: *mut CmsContentInfo,
) -> *mut CmsRevocationInfoChoice {
    // SAFETY: `cms` is live.
    let pcrls = unsafe { cms_get0_revocation_choices(cms) };
    if pcrls.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pcrls` is a live slot.
    unsafe {
        if (*pcrls).is_null() {
            *pcrls = OPENSSL_sk_new_null();
        }
        if (*pcrls).is_null() {
            return ptr::null_mut();
        }
        let rch = m_asn1_new(cms_revocationinfochoice_it()).cast::<CmsRevocationInfoChoice>();
        if rch.is_null() {
            return ptr::null_mut();
        }
        if OPENSSL_sk_push(*pcrls, rch.cast()) == 0 {
            m_asn1_free(rch.cast(), cms_revocationinfochoice_it());
            return ptr::null_mut();
        }
        rch
    }
}

/// `int CMS_add0_crl(CMS_ContentInfo *cms, X509_CRL *crl)` — `cms_lib.c:619-628`.
///
/// # Safety
/// `cms` is live; `crl` is live and ownership passes to `cms`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add0_crl(cms: *mut CmsContentInfo, crl: *mut X509Crl) -> c_int {
    // SAFETY: `cms` is live.
    let rch = unsafe { CMS_add0_RevocationInfoChoice(cms) };
    if rch.is_null() {
        return 0;
    }
    // SAFETY: `rch` is live.
    unsafe {
        (*rch).type_ = CMS_REVCHOICE_CRL;
        (*rch).d = crl.cast();
    }
    1
}

/// `int CMS_add1_crl(CMS_ContentInfo *cms, X509_CRL *crl)` — `cms_lib.c:630-638`.
///
/// # Safety
/// `cms` and `crl` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add1_crl(cms: *mut CmsContentInfo, crl: *mut X509Crl) -> c_int {
    // SAFETY: `crl` is live.
    if unsafe { X509_CRL_up_ref(crl) } == 0 {
        return 0;
    }
    // SAFETY: `cms` is live.
    if unsafe { CMS_add0_crl(cms, crl) } != 0 {
        return 1;
    }
    // SAFETY: `crl` is live and the reference added above is ours.
    unsafe { X509_CRL_free(crl) };
    0
}

/// `STACK_OF(X509) *CMS_get1_certs(CMS_ContentInfo *cms)` — `cms_lib.c:640-651`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_get1_certs(cms: *mut CmsContentInfo) -> *mut OpenSslStack {
    let mut certs: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `cms` is live; `certs` is writable.
    if unsafe { ossl_cms_get1_certs_ex(cms, &mut certs) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `certs` is a live stack.
    if unsafe { OPENSSL_sk_num(certs) } == 0 {
        // SAFETY: `certs` is owned by this call.
        unsafe { OPENSSL_sk_free(certs) };
        return ptr::null_mut();
    }
    certs
}

/// `int ossl_cms_get1_certs_ex(CMS_ContentInfo *cms, STACK_OF(X509) **certs)` —
/// `cms_lib.c:653-683`.
///
/// # Safety
/// `cms` is live; `certs` is writable.
pub(crate) unsafe fn ossl_cms_get1_certs_ex(
    cms: *mut CmsContentInfo,
    certs: *mut *mut OpenSslStack,
) -> c_int {
    if certs.is_null() {
        return 0;
    }
    // SAFETY: `certs` is writable.
    unsafe { *certs = ptr::null_mut() };
    // SAFETY: `cms` is live.
    let pcerts = unsafe { cms_get0_certificate_choices(cms) };
    if pcerts.is_null() {
        return 0;
    }
    // SAFETY: `pcerts` is a live slot.
    unsafe {
        let n = OPENSSL_sk_num(*pcerts);
        *certs = OPENSSL_sk_new_reserve(None, n);
        if (*certs).is_null() {
            return 0;
        }
        for i in 0..n {
            let cch = OPENSSL_sk_value(*pcerts, i).cast::<CmsCertificateChoices>();
            if (*cch).type_ == 0 && X509_add_cert(*certs, (*cch).d.cast(), 0x1) == 0 {
                OPENSSL_sk_pop_free(*certs, Some(x509_free_void));
                *certs = ptr::null_mut();
                return 0;
            }
        }
        1
    }
}

/// `STACK_OF(X509_CRL) *CMS_get1_crls(CMS_ContentInfo *cms)` — `cms_lib.c:685-696`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_get1_crls(cms: *mut CmsContentInfo) -> *mut OpenSslStack {
    let mut crls: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `cms` is live; `crls` is writable.
    if unsafe { ossl_cms_get1_crls_ex(cms, &mut crls) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `crls` is a live stack.
    if unsafe { OPENSSL_sk_num(crls) } == 0 {
        // SAFETY: `crls` is owned by this call.
        unsafe { OPENSSL_sk_free(crls) };
        return ptr::null_mut();
    }
    crls
}

/// `int ossl_cms_get1_crls_ex(CMS_ContentInfo *cms, STACK_OF(X509_CRL) **crls)` —
/// `cms_lib.c:698-729`.
///
/// # Safety
/// `cms` is live; `crls` is writable.
pub(crate) unsafe fn ossl_cms_get1_crls_ex(
    cms: *mut CmsContentInfo,
    crls: *mut *mut OpenSslStack,
) -> c_int {
    if crls.is_null() {
        return 0;
    }
    // SAFETY: `crls` is writable.
    unsafe { *crls = ptr::null_mut() };
    // SAFETY: `cms` is live.
    let pcrls = unsafe { cms_get0_revocation_choices(cms) };
    if pcrls.is_null() {
        return 0;
    }
    // SAFETY: `pcrls` is a live slot.
    unsafe {
        let n = OPENSSL_sk_num(*pcrls);
        *crls = OPENSSL_sk_new_reserve(None, n);
        if (*crls).is_null() {
            return 0;
        }
        for i in 0..n {
            let rch = OPENSSL_sk_value(*pcrls, i).cast::<CmsRevocationInfoChoice>();
            if (*rch).type_ == 0
                && (X509_CRL_up_ref((*rch).d.cast()) == 0 || OPENSSL_sk_push(*crls, (*rch).d) == 0)
            {
                OPENSSL_sk_pop_free(*crls, Some(x509_crl_free_void));
                *crls = ptr::null_mut();
                return 0;
            }
        }
        1
    }
}

/// `int ossl_cms_ias_cert_cmp(CMS_IssuerAndSerialNumber *ias, X509 *cert)` — `cms_lib.c:731-738`.
///
/// # Safety
/// `ias` and `cert` are live.
pub(crate) unsafe fn ossl_cms_ias_cert_cmp(
    ias: *mut CmsIssuerAndSerialNumber,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `ias` and `cert` are live.
    unsafe {
        let ret = X509_NAME_cmp((*ias).issuer, X509_get_issuer_name(cert));
        if ret != 0 {
            return ret;
        }
        crate::asn1::prim::ASN1_INTEGER_cmp((*ias).serial_number, X509_get0_serialNumber(cert))
    }
}

/// `int ossl_cms_keyid_cert_cmp(ASN1_OCTET_STRING *keyid, X509 *cert)` — `cms_lib.c:740-747`.
///
/// # Safety
/// `keyid` and `cert` are live.
pub(crate) unsafe fn ossl_cms_keyid_cert_cmp(
    keyid: *mut crate::asn1::layout::Asn1String,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `cert` is live.
    let cert_keyid = unsafe { X509_get0_subject_key_id(cert) };
    if cert_keyid.is_null() {
        return -1;
    }
    // SAFETY: `keyid` and `cert_keyid` are live.
    unsafe { ASN1_OCTET_STRING_cmp(keyid, cert_keyid) }
}

/// `int ossl_cms_set1_ias(CMS_IssuerAndSerialNumber **pias, X509 *cert)` — `cms_lib.c:749-771`.
///
/// # Safety
/// `pias` is writable; `cert` is live.
pub(crate) unsafe fn ossl_cms_set1_ias(
    pias: *mut *mut CmsIssuerAndSerialNumber,
    cert: *mut X509,
) -> c_int {
    // SAFETY: the accessor answers a static item.
    let ias = unsafe { ASN1_item_new(cms_issuerandserial_it()) }.cast::<CmsIssuerAndSerialNumber>();
    if ias.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(754, c"ossl_cms_set1_ias", ERR_R_ASN1_LIB) };
        return 0;
    }
    // SAFETY: `ias` and `cert` are live.
    unsafe {
        if X509_NAME_set(&mut (*ias).issuer, X509_get_issuer_name(cert)) == 0 {
            raise_cms(758, c"ossl_cms_set1_ias", ERR_R_X509_LIB);
            m_asn1_free(ias.cast(), cms_issuerandserial_it());
            return 0;
        }
        if ASN1_STRING_copy((*ias).serial_number, X509_get0_serialNumber(cert)) == 0 {
            raise_cms(762, c"ossl_cms_set1_ias", ERR_R_ASN1_LIB);
            m_asn1_free(ias.cast(), cms_issuerandserial_it());
            return 0;
        }
        m_asn1_free((*pias).cast(), cms_issuerandserial_it());
        *pias = ias;
    }
    1
}

/// `int ossl_cms_set1_keyid(ASN1_OCTET_STRING **pkeyid, X509 *cert)` — `cms_lib.c:773-790`.
///
/// # Safety
/// `pkeyid` is writable; `cert` is live.
pub(crate) unsafe fn ossl_cms_set1_keyid(
    pkeyid: *mut *mut crate::asn1::layout::Asn1String,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `cert` is live.
    let cert_keyid = unsafe { X509_get0_subject_key_id(cert) };
    if cert_keyid.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                779,
                c"ossl_cms_set1_keyid",
                crate::runtime::err::err_reasons::CMS_R_CERTIFICATE_HAS_NO_KEYID,
            )
        };
        return 0;
    }
    // SAFETY: `cert_keyid` is live.
    let keyid = unsafe { ASN1_STRING_dup(cert_keyid) }.cast::<crate::asn1::layout::Asn1String>();
    if keyid.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(784, c"ossl_cms_set1_keyid", ERR_R_ASN1_LIB) };
        return 0;
    }
    // SAFETY: `pkeyid` is writable.
    unsafe {
        crate::asn1::string::ASN1_STRING_free(*pkeyid);
        *pkeyid = keyid;
    }
    1
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for [`X509_free`].
unsafe extern "C" fn x509_free_void(p: *mut c_void) {
    // SAFETY: `p` is an `X509` per the stack's element type.
    unsafe { X509_free(p.cast()) };
}

/// The `void (*)(void *)` shape for [`X509_CRL_free`].
unsafe extern "C" fn x509_crl_free_void(p: *mut c_void) {
    // SAFETY: `p` is an `X509_CRL` per the stack's element type.
    unsafe { X509_CRL_free(p.cast()) };
}
