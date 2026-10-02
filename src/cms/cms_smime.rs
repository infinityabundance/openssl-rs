//! `crypto/cms/cms_smime.c` — the top-level sign/verify/encrypt/decrypt surface. Phase 12.3c.
//!
//! The S/MIME content copier (`cms_get_text_bio`, `cms_copy_content`, `check_content`,
//! `do_free_upto`), the plain-content surface (`CMS_data`, `CMS_data_create`,
//! `CMS_digest_verify`, `CMS_digest_create`, `CMS_EncryptedData_decrypt`,
//! `CMS_EncryptedData_encrypt`), the signer/verifier (`CMS_verify`, `CMS_verify_receipt`,
//! `CMS_sign`, `CMS_sign_receipt`), the enveloped engine (`CMS_encrypt`, `CMS_decrypt*`), the
//! content finalisers (`CMS_final`, `CMS_final_digest`) and the compression pair (`CMS_compress`,
//! `CMS_uncompress`).
//!
//! ## The one delegate that is 12.9's
//!
//! `cms_copy_content` and `CMS_verify` call `SMIME_text` under `CMS_TEXT`
//! (`cms_smime.c:93,484`), and `SMIME_text`'s owning unit is `crypto/asn1/asn_mime.c`, one of the
//! Phase-5 hand-offs 12.9 lands. The declaration below is the authority's own `asn1.h` prototype,
//! so when 12.9 lands the unit the arm binds to it, exactly as `pk7_smime.rs` names it.
//!
//! `ERR_raise_data`'s formatted data is also unusual here: the crate's error API exposes the
//! reason and coordinate without data. The certificate-verify arm at `cms_smime.c:329` raises its
//! `CMS_R_CERTIFICATE_VERIFY_ERROR` through [`raise_cms`], so the reason and the coordinate are
//! exact and the `"Verify error: %s"` textual suffix is not reproduced.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::asn_mime::SMIME_crlf_copy;
use crate::asn1::string::ASN1_STRING_free;
use crate::evp::cipher::{EVP_CIPHER_get_flags, EvpCipher};
use crate::evp::cipher_ctx::{EVP_CIPHER_CTX_get0_cipher, EvpCipherCtx};
use crate::evp::digest::EvpMd;
use crate::evp::legacy_sha::EVP_sha1;
use crate::evp::pkey::{EVP_PKEY_up_ref, EvpPkey};
use crate::pkcs7::pk7_doit::{bio_get_cipher_status, bio_set_mem_eof_return};
use crate::runtime::bio::bss_mem::{BIO_new_mem_buf, BIO_s_mem};
use crate::runtime::bio::bss_null::BIO_s_null;
use crate::runtime::bio::{
    BIO_ctrl, BIO_free, BIO_free_all, BIO_method_type, BIO_new, BIO_pop, BIO_read, BIO_write, Bio,
    BIO_CTRL_FLUSH, BIO_CTRL_INFO, BIO_C_GET_CIPHER_CTX, BIO_TYPE_CIPHER, BIO_TYPE_MEM,
};
use crate::runtime::err::ERR_clear_error;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::{
    NID_id_ct_asciiTextWithCRLF, NID_id_smime_ct_authEnvelopedData, NID_id_smime_ct_receipt,
    NID_pkcs7_data, NID_pkcs7_digest, NID_pkcs7_encrypted, NID_pkcs7_enveloped, OBJ_nid2obj,
    OBJ_obj2nid,
};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};
use crate::x509::x509_cmp::ossl_x509_add_certs_new;
use crate::x509::x509_lu::X509Store;
use crate::x509::x509_txt::X509_verify_cert_error_string;
use crate::x509::x509_vfy::{
    X509_STORE_CTX_free, X509_STORE_CTX_get1_chain, X509_STORE_CTX_get_error, X509_STORE_CTX_init,
    X509_STORE_CTX_new_ex, X509_STORE_CTX_set0_crls, X509_STORE_CTX_set_default, X509_verify_cert,
};
use crate::x509::x_crl::X509_CRL_free;
use crate::x509::x_x509::{X509_free, X509};

use super::cms_asn1::{
    CmsContentInfo, CmsCtx, CmsRecipientEncryptedKey, CmsRecipientInfo, CmsSignerInfo,
};
use super::cms_att::CMS_signed_get_attr_count;
use super::cms_dd::{ossl_cms_DigestedData_create, ossl_cms_DigestedData_do_final};
use super::cms_enc::CMS_EncryptedData_set1_key;
use super::cms_env::{
    ossl_cms_get0_env_enc_content, ossl_cms_pkey_get_ri_type, ossl_cms_pkey_is_ri_type_supported,
    CMS_AuthEnvelopedData_create_ex, CMS_EnvelopedData_create_ex, CMS_RecipientInfo_decrypt,
    CMS_RecipientInfo_kekri_id_cmp, CMS_RecipientInfo_ktri_cert_cmp, CMS_RecipientInfo_set0_key,
    CMS_RecipientInfo_set0_pkey, CMS_RecipientInfo_type, CMS_add1_recipient_cert,
    CMS_get0_RecipientInfos,
};
use super::cms_ess::{
    ossl_cms_Receipt_verify, ossl_cms_check_signing_certs, ossl_cms_encode_Receipt,
    ossl_cms_msgSigDigest_add1,
};
use super::cms_kari::{
    CMS_RecipientEncryptedKey_cert_cmp, CMS_RecipientInfo_kari_decrypt,
    CMS_RecipientInfo_kari_get0_reks, CMS_RecipientInfo_kari_set0_pkey,
    CMS_RecipientInfo_kari_set0_pkey_and_peer,
};
use super::cms_kemri::{CMS_RecipientInfo_kemri_cert_cmp, CMS_RecipientInfo_kemri_set0_pkey};
use super::cms_lib::{
    ossl_cms_DataFinal, ossl_cms_Data_create, ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq,
    ossl_cms_get0_cmsctx, ossl_cms_get1_certs_ex, ossl_cms_get1_crls_ex, raise_cms,
    CMS_ContentInfo_free, CMS_ContentInfo_new_ex, CMS_add1_cert, CMS_dataFinal, CMS_dataInit,
    CMS_get0_content, CMS_get0_eContentType, CMS_get0_type, CMS_set1_eContentType,
    CMS_set_detached, ERR_R_BIO_LIB, ERR_R_CMS_LIB, ERR_R_X509_LIB,
};
use super::cms_sd::{
    CMS_SignedData_init, CMS_SignerInfo_get0_algs, CMS_SignerInfo_verify,
    CMS_SignerInfo_verify_content, CMS_add1_signer, CMS_get0_SignerInfos, CMS_set1_signers_certs,
};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cms/cms_smime.c";

/// `BUFFERSIZE` — the stack buffer `cms_copy_content` reads through (`cms_smime.c:36`).
const BUFFERSIZE: usize = 4096;

/// `X509_ADD_FLAG_UP_REF` — `include/openssl/x509.h:995`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;
/// `X509_ADD_FLAG_NO_DUP` — `include/openssl/x509.h:997`.
const X509_ADD_FLAG_NO_DUP: c_int = 0x4;
/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h:325`.
const EVP_CIPH_FLAG_AEAD_CIPHER: core::ffi::c_ulong = 0x20_0000;

/// `CMS_TEXT` — `cms.h.in:120`.
const CMS_TEXT: c_uint = 0x1;
/// `CMS_NOCERTS` — `cms.h.in:121`.
const CMS_NOCERTS: c_uint = 0x2;
/// `CMS_NO_CONTENT_VERIFY` — `cms.h.in:122`.
const CMS_NO_CONTENT_VERIFY: c_uint = 0x4;
/// `CMS_NO_ATTR_VERIFY` — `cms.h.in:123`.
const CMS_NO_ATTR_VERIFY: c_uint = 0x8;
/// `CMS_NOINTERN` — `cms.h.in:124`.
const CMS_NOINTERN: c_uint = 0x10;
/// `CMS_NO_SIGNER_CERT_VERIFY` — `cms.h.in:125`.
const CMS_NO_SIGNER_CERT_VERIFY: c_uint = 0x20;
/// `CMS_DETACHED` — `cms.h.in:126`.
const CMS_DETACHED: c_uint = 0x40;
/// `CMS_BINARY` — `cms.h.in:127`.
const CMS_BINARY: c_uint = 0x80;
/// `CMS_NOATTR` — `cms.h.in:128`.
const CMS_NOATTR: c_uint = 0x100;
/// `CMS_NOSMIMECAP` — `cms.h.in:129`.
const CMS_NOSMIMECAP: c_uint = 0x200;
/// `CMS_NOOLDMIMETYPE` — `cms.h.in:130`.
const CMS_NOOLDMIMETYPE: c_uint = 0x400;
/// `CMS_CRLFEOL` — `cms.h.in:131`.
const CMS_CRLFEOL: c_uint = 0x800;
/// `CMS_STREAM` — `cms.h.in:132`.
const CMS_STREAM: c_uint = 0x1000;
/// `CMS_NOCRL` — `cms.h.in:133`.
const CMS_NOCRL: c_uint = 0x2000;
/// `CMS_PARTIAL` — `cms.h.in:134`.
const CMS_PARTIAL: c_uint = 0x4000;
/// `CMS_REUSE_DIGEST` — `cms.h.in:135`.
const CMS_REUSE_DIGEST: c_uint = 0x8000;
/// `CMS_USE_KEYID` — `cms.h.in:136`.
const CMS_USE_KEYID: c_uint = 0x10000;
/// `CMS_DEBUG_DECRYPT` — `cms.h.in:137`.
const CMS_DEBUG_DECRYPT: c_uint = 0x20000;
/// `CMS_KEY_PARAM` — `cms.h.in:138`.
const CMS_KEY_PARAM: c_uint = 0x40000;
/// `CMS_ASCIICRLF` — `cms.h.in:139`.
const CMS_ASCIICRLF: c_uint = 0x80000;
/// `CMS_CADES` — `cms.h.in:140`.
const CMS_CADES: c_uint = 0x100000;
/// `CMS_USE_ORIGINATOR_KEYID` — `cms.h.in:141`.
const CMS_USE_ORIGINATOR_KEYID: c_uint = 0x200000;
/// `CMS_NO_SIGNING_TIME` — `cms.h.in:142`.
const CMS_NO_SIGNING_TIME: c_uint = 0x400000;

/// `SMIME_TEXT` — `include/openssl/asn1.h:1106`, numerically equal to `CMS_TEXT`.
const SMIME_TEXT: c_uint = 0x1;
/// `SMIME_BINARY` — `include/openssl/asn1.h:1110`, numerically equal to `CMS_BINARY`.
const SMIME_BINARY: c_uint = 0x80;

extern "C" {
    /// `int SMIME_text(BIO *in, BIO *out)` — `crypto/asn1/asn_mime.c`, 12.9's.
    fn SMIME_text(in_: *mut Bio, out: *mut Bio) -> c_int;
}

/// The `X509_free` destructor shape `OPENSSL_sk_pop_free` takes.
///
/// # Safety
/// `p` is null or an `X509` this item layer owns.
unsafe extern "C" fn x509_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_free(p.cast()) };
}

/// The `X509_CRL_free` destructor shape `OPENSSL_sk_pop_free` takes.
///
/// # Safety
/// `p` is null or an `X509_CRL` this item layer owns.
unsafe extern "C" fn x509_crl_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_CRL_free(p.cast()) };
}

/// `BIO_get_cipher_ctx(BIO *, EVP_CIPHER_CTX **)` — `BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, pctx)`.
///
/// # Safety
/// `b` is a live cipher BIO; `pctx` is writable.
unsafe fn bio_get_cipher_ctx(b: *mut Bio, pctx: *mut *mut EvpCipherCtx) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, pctx.cast()) as c_int }
}

/// `BIO_get_mem_data(BIO *, char **)` — `BIO_ctrl(b, BIO_CTRL_INFO, 0, pp)`.
///
/// # Safety
/// `b` is a live memory BIO; `pp` is writable.
unsafe fn bio_get_mem_data(b: *mut Bio, pp: *mut *mut c_char) -> c_long {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_CTRL_INFO, 0, pp.cast()) }
}

/// `BIO_flush(BIO *)` — `BIO_ctrl(b, BIO_CTRL_FLUSH, 0, NULL)`.
///
/// # Safety
/// `b` is a live BIO.
unsafe fn bio_flush(b: *mut Bio) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_CTRL_FLUSH, 0, ptr::null_mut()) as c_int }
}

/// `static BIO *cms_get_text_bio(BIO *out, unsigned int flags)` — `cms_smime.c:20-32`.
///
/// # Safety
/// `out` is NULL or a live BIO.
unsafe fn cms_get_text_bio(out: *mut Bio, flags: c_uint) -> *mut Bio {
    if out.is_null() {
        // SAFETY: the null method is a compile-time constant.
        unsafe { BIO_new(BIO_s_null()) }
    } else if (flags & CMS_TEXT) != 0 {
        // SAFETY: the memory method is a compile-time constant.
        let rbio = unsafe { BIO_new(BIO_s_mem()) };
        // SAFETY: `rbio` is NULL or a live memory BIO.
        unsafe { bio_set_mem_eof_return(rbio, 0) };
        rbio
    } else {
        out
    }
}

/// `static int cms_copy_content(BIO *out, BIO *in, unsigned int flags)` — `cms_smime.c:34-115`.
///
/// # Safety
/// `in` is a live BIO; `out` is NULL or a live BIO.
unsafe fn cms_copy_content(out: *mut Bio, in_: *mut Bio, flags: c_uint) -> c_int {
    let mut buf = [0u8; BUFFERSIZE];
    let mut r = 0;
    let mut aeadbuf: *mut Bio = ptr::null_mut();
    let mut tmpout: *mut Bio = ptr::null_mut();

    'err: {
        // SAFETY: `out` is NULL or live.
        tmpout = unsafe { cms_get_text_bio(out, flags) };

        if tmpout.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(44, c"cms_copy_content", ERR_R_CMS_LIB) };
            break 'err;
        }

        /*
         * For AEAD content (AuthEnvelopedData) the integrity tag is only verified once all the
         * ciphertext has been processed, by the `BIO_get_cipher_status()` call below. Buffer the
         * plaintext until the tag has been checked; when `CMS_TEXT` is set `tmpout` is already a
         * memory BIO flushed only on success, so the extra buffering is not needed.
         */
        // SAFETY: `in_` is a live BIO.
        if tmpout == out && unsafe { BIO_method_type(in_) } == BIO_TYPE_CIPHER {
            let mut ctx: *mut EvpCipherCtx = ptr::null_mut();

            // SAFETY: `in_` is a live cipher BIO; `ctx` is this frame's slot.
            let is_aead = unsafe { bio_get_cipher_ctx(in_, &mut ctx) } > 0
                && !ctx.is_null()
                // SAFETY: `ctx` is live.
                && (unsafe { EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx)) }
                    & EVP_CIPH_FLAG_AEAD_CIPHER)
                    != 0;
            if is_aead {
                // SAFETY: the memory method is a compile-time constant.
                aeadbuf = unsafe { BIO_new(BIO_s_mem()) };
                if aeadbuf.is_null() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_cms(66, c"cms_copy_content", ERR_R_BIO_LIB) };
                    break 'err;
                }
                /* Return 0 (EOF) rather than a retryable -1 once drained. */
                // SAFETY: `aeadbuf` is a live memory BIO.
                unsafe { bio_set_mem_eof_return(aeadbuf, 0) };
                tmpout = aeadbuf;
            }
        }

        /* Read all content through chain to process digest, decrypt etc */
        loop {
            // SAFETY: `in_` is live and `buf` is `BUFFERSIZE` bytes.
            let i = unsafe { BIO_read(in_, buf.as_mut_ptr().cast(), BUFFERSIZE as c_int) };
            if i <= 0 {
                // SAFETY: `in_` is a live BIO.
                if unsafe { BIO_method_type(in_) } == BIO_TYPE_CIPHER {
                    // SAFETY: `in_` is a live cipher BIO.
                    if unsafe { bio_get_cipher_status(in_) } <= 0 {
                        break 'err;
                    }
                }
                if i < 0 {
                    break 'err;
                }
                break;
            }

            // SAFETY: `buf` is readable for `i`; `tmpout` is NULL or live.
            if !tmpout.is_null() && (unsafe { BIO_write(tmpout, buf.as_ptr().cast(), i) } != i) {
                break 'err;
            }
        }

        if (flags & CMS_TEXT) != 0 {
            // SAFETY: `tmpout`/`out` are live BIOs.
            if unsafe { SMIME_text(tmpout, out) } == 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        94,
                        c"cms_copy_content",
                        crate::runtime::err::err_reasons::CMS_R_SMIME_TEXT_ERROR,
                    )
                };
                break 'err;
            }
        } else if !aeadbuf.is_null() {
            /* Forward the AEAD BIO to out BIO as the tag has been verified. */
            loop {
                // SAFETY: `aeadbuf` is live and `buf` is `BUFFERSIZE` bytes.
                let i = unsafe { BIO_read(aeadbuf, buf.as_mut_ptr().cast(), BUFFERSIZE as c_int) };
                if i < 0 {
                    break 'err;
                }
                if i == 0 {
                    break;
                }
                // SAFETY: `out` is a live BIO; `buf` is readable for `i`.
                if unsafe { BIO_write(out, buf.as_ptr().cast(), i) } != i {
                    break 'err;
                }
            }
        }

        r = 1;
    }

    if tmpout != out {
        // SAFETY: `tmpout` is NULL or a BIO this call owns.
        unsafe { BIO_free(tmpout) };
    }
    r
}

/// `static int check_content(CMS_ContentInfo *cms)` — `cms_smime.c:117-126`.
///
/// # Safety
/// `cms` is live.
unsafe fn check_content(cms: *mut CmsContentInfo) -> c_int {
    // SAFETY: `cms` is live.
    let pos = unsafe { CMS_get0_content(cms) };
    let pos_empty = pos.is_null() || {
        // SAFETY: `pos` is a live slot (non-null per the short circuit).
        unsafe { *pos }.is_null()
    };

    if pos_empty {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                122,
                c"check_content",
                crate::runtime::err::err_reasons::CMS_R_NO_CONTENT,
            )
        };
        return 0;
    }
    1
}

/// `static void do_free_upto(BIO *f, BIO *upto)` — `cms_smime.c:128-141`.
///
/// # Safety
/// `f` is NULL or a live BIO chain; `upto` is NULL or a member of it.
unsafe fn do_free_upto(f: *mut Bio, upto: *mut Bio) {
    if !upto.is_null() {
        let mut f = f;

        loop {
            // SAFETY: `f` is a live chain.
            let tbio = unsafe { BIO_pop(f) };
            // SAFETY: `f` is live and owned here.
            unsafe { BIO_free(f) };
            f = tbio;
            if f.is_null() || f == upto {
                break;
            }
        }
    } else {
        // SAFETY: `f` is NULL or a BIO chain this call owns.
        unsafe { BIO_free_all(f) };
    }
}

/// `int CMS_data(CMS_ContentInfo *cms, BIO *out, unsigned int flags)` — `cms_smime.c:143-158`.
///
/// # Safety
/// `cms`/`out` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_data(
    cms: *mut CmsContentInfo,
    out: *mut Bio,
    flags: c_uint,
) -> c_int {
    // SAFETY: `cms` is live.
    if unsafe { OBJ_obj2nid(CMS_get0_type(cms)) } != NID_pkcs7_data {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                149,
                c"CMS_data",
                crate::runtime::err::err_reasons::CMS_R_TYPE_NOT_DATA,
            )
        };
        return 0;
    }
    // SAFETY: `cms` is live.
    let cont = unsafe { CMS_dataInit(cms, ptr::null_mut()) };
    if cont.is_null() {
        return 0;
    }
    // SAFETY: `out`/`cont` are live.
    let r = unsafe { cms_copy_content(out, cont, flags) };
    // SAFETY: `cont` is a BIO chain this call owns.
    unsafe { BIO_free_all(cont) };
    r
}

/// `CMS_ContentInfo *CMS_data_create_ex(BIO *in, unsigned int flags, OSSL_LIB_CTX *libctx,`
/// `const char *propq)` — `cms_smime.c:160-173`.
///
/// # Safety
/// `in` is NULL or a live BIO; `propq` is NULL or a NUL-terminated string.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_data_create_ex(
    in_: *mut Bio,
    flags: c_uint,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmsContentInfo {
    // SAFETY: the caller's contract.
    let cms = unsafe { ossl_cms_Data_create(libctx, propq) };
    if cms.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `cms`/`in_` are live as required.
    if (flags & CMS_STREAM) != 0 || unsafe { CMS_final(cms, in_, ptr::null_mut(), flags) } != 0 {
        return cms;
    }

    // SAFETY: `cms` is owned here.
    unsafe { CMS_ContentInfo_free(cms) };
    ptr::null_mut()
}

/// `CMS_ContentInfo *CMS_data_create(BIO *in, unsigned int flags)` — `cms_smime.c:175-178`.
///
/// # Safety
/// `in` is NULL or a live BIO.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_data_create(
    in_: *mut Bio,
    flags: c_uint,
) -> *mut CmsContentInfo {
    // SAFETY: the arguments to the `_ex` form are the caller's.
    unsafe { CMS_data_create_ex(in_, flags, ptr::null_mut(), ptr::null()) }
}

/// `int CMS_digest_verify(CMS_ContentInfo *cms, BIO *dcont, BIO *out, unsigned int flags)` —
/// `cms_smime.c:180-203`.
///
/// # Safety
/// `cms` is live; `dcont`/`out` are NULL or live BIOs.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_digest_verify(
    cms: *mut CmsContentInfo,
    dcont: *mut Bio,
    out: *mut Bio,
    flags: c_uint,
) -> c_int {
    // SAFETY: `cms` is live.
    if unsafe { OBJ_obj2nid(CMS_get0_type(cms)) } != NID_pkcs7_digest {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                187,
                c"CMS_digest_verify",
                crate::runtime::err::err_reasons::CMS_R_TYPE_NOT_DIGESTED_DATA,
            )
        };
        return 0;
    }

    if dcont.is_null() {
        // SAFETY: `cms` is live.
        if unsafe { check_content(cms) } == 0 {
            return 0;
        }
    }

    // SAFETY: `cms` is live; `dcont` is NULL or live.
    let cont = unsafe { CMS_dataInit(cms, dcont) };
    if cont.is_null() {
        return 0;
    }

    // SAFETY: `out`/`cont` are live.
    let mut r = unsafe { cms_copy_content(out, cont, flags) };
    if r != 0 {
        // SAFETY: `cms`/`cont` are live.
        r = unsafe { ossl_cms_DigestedData_do_final(cms, cont, 1) };
    }
    // SAFETY: `cont` is a live chain; `dcont` is NULL or its tail.
    unsafe { do_free_upto(cont, dcont) };
    r
}

/// `CMS_ContentInfo *CMS_digest_create_ex(BIO *in, const EVP_MD *md, unsigned int flags,`
/// `OSSL_LIB_CTX *ctx, const char *propq)` — `cms_smime.c:205-229`.
///
/// # Safety
/// `in` is NULL or a live BIO; `md` is NULL or live; `propq` is NULL or a NUL-terminated string.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_digest_create_ex(
    in_: *mut Bio,
    md: *const EvpMd,
    flags: c_uint,
    ctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmsContentInfo {
    /*
     * Because the EVP_MD is cached and can be a legacy algorithm, we cannot fetch the algorithm
     * if it isn't supplied.
     */
    let md = if md.is_null() { EVP_sha1() } else { md };
    // SAFETY: `md` is live.
    let cms = unsafe { ossl_cms_DigestedData_create(md, ctx, propq) };
    if cms.is_null() {
        return ptr::null_mut();
    }

    if (flags & CMS_DETACHED) == 0 {
        // SAFETY: `cms` is live.
        unsafe { CMS_set_detached(cms, 0) };
    }

    // SAFETY: `cms`/`in_` are live as required.
    if (flags & CMS_STREAM) != 0 || unsafe { CMS_final(cms, in_, ptr::null_mut(), flags) } != 0 {
        return cms;
    }

    // SAFETY: `cms` is owned here.
    unsafe { CMS_ContentInfo_free(cms) };
    ptr::null_mut()
}

/// `CMS_ContentInfo *CMS_digest_create(BIO *in, const EVP_MD *md, unsigned int flags)` —
/// `cms_smime.c:231-235`.
///
/// # Safety
/// `in` is NULL or a live BIO; `md` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_digest_create(
    in_: *mut Bio,
    md: *const EvpMd,
    flags: c_uint,
) -> *mut CmsContentInfo {
    // SAFETY: the arguments to the `_ex` form are the caller's.
    unsafe { CMS_digest_create_ex(in_, md, flags, ptr::null_mut(), ptr::null()) }
}

/// `int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms, const unsigned char *key, size_t keylen,`
/// `BIO *dcont, BIO *out, unsigned int flags)` — `cms_smime.c:237-260`.
///
/// # Safety
/// `cms` is live; `key` is readable for `keylen` or NULL; `dcont`/`out` are NULL or live BIOs.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_EncryptedData_decrypt(
    cms: *mut CmsContentInfo,
    key: *const c_uchar,
    keylen: usize,
    dcont: *mut Bio,
    out: *mut Bio,
    flags: c_uint,
) -> c_int {
    // SAFETY: `cms` is live.
    if unsafe { OBJ_obj2nid(CMS_get0_type(cms)) } != NID_pkcs7_encrypted {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                245,
                c"CMS_EncryptedData_decrypt",
                crate::runtime::err::err_reasons::CMS_R_TYPE_NOT_ENCRYPTED_DATA,
            )
        };
        return 0;
    }

    if dcont.is_null() {
        // SAFETY: `cms` is live.
        if unsafe { check_content(cms) } == 0 {
            return 0;
        }
    }

    // SAFETY: `cms` is live; `key` is readable for `keylen` or NULL.
    if unsafe { CMS_EncryptedData_set1_key(cms, ptr::null(), key, keylen) } <= 0 {
        return 0;
    }
    // SAFETY: `cms` is live; `dcont` is NULL or live.
    let cont = unsafe { CMS_dataInit(cms, dcont) };
    if cont.is_null() {
        return 0;
    }
    // SAFETY: `out`/`cont` are live.
    let r = unsafe { cms_copy_content(out, cont, flags) };
    // SAFETY: `cont` is a live chain; `dcont` is NULL or its tail.
    unsafe { do_free_upto(cont, dcont) };
    r
}

/// `CMS_ContentInfo *CMS_EncryptedData_encrypt_ex(BIO *in, const EVP_CIPHER *cipher,`
/// `const unsigned char *key, size_t keylen, unsigned int flags, OSSL_LIB_CTX *libctx,`
/// `const char *propq)` — `cms_smime.c:262-290`.
///
/// # Safety
/// `in` is NULL or a live BIO; `cipher` is live; `key` is readable for `keylen` or NULL; `propq` is
/// NULL or a NUL-terminated string.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_EncryptedData_encrypt_ex(
    in_: *mut Bio,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    keylen: usize,
    flags: c_uint,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmsContentInfo {
    if cipher.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                271,
                c"CMS_EncryptedData_encrypt_ex",
                crate::runtime::err::err_reasons::CMS_R_NO_CIPHER,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: the caller's contract.
    let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    if cms.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cms`/`cipher` are live; `key` is readable for `keylen` or NULL.
    if unsafe { CMS_EncryptedData_set1_key(cms, cipher, key, keylen) } == 0 {
        // SAFETY: `cms` is owned here.
        unsafe { CMS_ContentInfo_free(cms) };
        return ptr::null_mut();
    }

    if (flags & CMS_DETACHED) == 0 {
        // SAFETY: `cms` is live.
        unsafe { CMS_set_detached(cms, 0) };
    }

    // SAFETY: `cms`/`in_` are live as required.
    if (flags & (CMS_STREAM | CMS_PARTIAL)) != 0
        // SAFETY: `cms`/`in_` are live as required.
        || unsafe { CMS_final(cms, in_, ptr::null_mut(), flags) } != 0
    {
        return cms;
    }

    // SAFETY: `cms` is owned here.
    unsafe { CMS_ContentInfo_free(cms) };
    ptr::null_mut()
}

/// `CMS_ContentInfo *CMS_digest_create(BIO *in, const EVP_MD *md, unsigned int flags)` —
/// `CMS_ContentInfo *CMS_EncryptedData_encrypt(BIO *in, const EVP_CIPHER *cipher,`
/// `const unsigned char *key, size_t keylen, unsigned int flags)` — `cms_smime.c:292-298`.
///
/// # Safety
/// `in` is NULL or a live BIO; `cipher` is live; `key` is readable for `keylen` or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_EncryptedData_encrypt(
    in_: *mut Bio,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    keylen: usize,
    flags: c_uint,
) -> *mut CmsContentInfo {
    // SAFETY: the arguments to the `_ex` form are the caller's.
    unsafe {
        CMS_EncryptedData_encrypt_ex(
            in_,
            cipher,
            key,
            keylen,
            flags,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `static int cms_signerinfo_verify_cert(CMS_SignerInfo *si, X509_STORE *store,`
/// `STACK_OF(X509) *untrusted, STACK_OF(X509_CRL) *crls, STACK_OF(X509) **chain,`
/// `const CMS_CTX *cms_ctx)` — `cms_smime.c:300-341`.
///
/// # Safety
/// `si`/`store` are live; `untrusted`/`crls` are NULL or live stacks; `chain` is NULL or writable;
/// `cms_ctx` is live.
unsafe fn cms_signerinfo_verify_cert(
    si: *mut CmsSignerInfo,
    store: *mut X509Store,
    untrusted: *mut OpenSslStack,
    crls: *mut OpenSslStack,
    chain: *mut *mut OpenSslStack,
    cms_ctx: *const CmsCtx,
) -> c_int {
    let mut r = 0;

    // SAFETY: `cms_ctx` is live.
    let ctx = unsafe {
        X509_STORE_CTX_new_ex(
            ossl_cms_ctx_get0_libctx(cms_ctx),
            ossl_cms_ctx_get0_propq(cms_ctx),
        )
    };
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(314, c"cms_signerinfo_verify_cert", ERR_R_X509_LIB) };
        return r;
    }

    let mut signer: *mut X509 = ptr::null_mut();
    // SAFETY: `si` is live; `signer` is this frame's slot.
    unsafe {
        CMS_SignerInfo_get0_algs(
            si,
            ptr::null_mut(),
            &mut signer,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    // SAFETY: `ctx`/`store`/`signer` are live; `untrusted` is NULL or live.
    if unsafe { X509_STORE_CTX_init(ctx, store, signer, untrusted) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                319,
                c"cms_signerinfo_verify_cert",
                crate::runtime::err::err_reasons::CMS_R_STORE_INIT_ERROR,
            )
        };
        // SAFETY: `ctx` is owned here.
        unsafe { X509_STORE_CTX_free(ctx) };
        return r;
    }
    // SAFETY: `ctx` is live.
    unsafe { X509_STORE_CTX_set_default(ctx, c"smime_sign".as_ptr()) };
    if !crls.is_null() {
        // SAFETY: `ctx` is live; `crls` is live.
        unsafe { X509_STORE_CTX_set0_crls(ctx, crls) };
    }

    // SAFETY: `ctx` is live.
    let i = unsafe { X509_verify_cert(ctx) };
    if i <= 0 {
        // SAFETY: `ctx` is live.
        let j = unsafe { X509_STORE_CTX_get_error(ctx) };
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                329,
                c"cms_signerinfo_verify_cert",
                crate::runtime::err::err_reasons::CMS_R_CERTIFICATE_VERIFY_ERROR,
            )
        };
        let _ = X509_verify_cert_error_string(j as c_long);
        // SAFETY: `ctx` is owned here.
        unsafe { X509_STORE_CTX_free(ctx) };
        return r;
    }
    r = 1;

    /* also send back the trust chain when required */
    if !chain.is_null() {
        // SAFETY: `ctx` is live; `chain` is writable.
        unsafe { *chain = X509_STORE_CTX_get1_chain(ctx) };
    }

    // SAFETY: `ctx` is owned here.
    unsafe { X509_STORE_CTX_free(ctx) };
    r
}

/// `int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *store, BIO *dcont,`
/// `BIO *out, unsigned int flags)` — `cms_smime.c:344-535`.
///
/// # Safety
/// `cms`/`store` are live; `certs` is NULL or a live stack; `dcont`/`out` are NULL or live BIOs.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_verify(
    cms: *mut CmsContentInfo,
    certs: *mut OpenSslStack,
    store: *mut X509Store,
    dcont: *mut Bio,
    out: *mut Bio,
    flags: c_uint,
) -> c_int {
    let sinfos: *mut OpenSslStack;
    let mut untrusted: *mut OpenSslStack = ptr::null_mut();
    let mut crls: *mut OpenSslStack = ptr::null_mut();
    let mut si_chains: *mut *mut OpenSslStack = ptr::null_mut();
    let mut signer: *mut X509 = ptr::null_mut();
    let mut scount = 0;
    let mut ret = 0;
    let mut cmsbio: *mut Bio = ptr::null_mut();
    let mut tmpin: *mut Bio = ptr::null_mut();
    let mut tmpout: *mut Bio = ptr::null_mut();
    let cades_verify = (flags & CMS_CADES) != 0;
    // SAFETY: `cms` is live.
    let ctx = unsafe { ossl_cms_get0_cmsctx(cms) };

    if dcont.is_null() {
        // SAFETY: `cms` is live.
        if unsafe { check_content(cms) } == 0 {
            return 0;
        }
    }
    let mut flags = flags;
    if !dcont.is_null() && (flags & CMS_BINARY) == 0 {
        // SAFETY: `cms` is live.
        let coid = unsafe { CMS_get0_eContentType(cms) };

        // SAFETY: `coid` is live.
        if unsafe { OBJ_obj2nid(coid) } == NID_id_ct_asciiTextWithCRLF {
            flags |= CMS_ASCIICRLF;
        }
    }

    'err2: {
        /* Attempt to find all signer certificates */

        // SAFETY: `cms` is live.
        sinfos = unsafe { CMS_get0_SignerInfos(cms) };

        // SAFETY: `sinfos` is NULL or a live stack.
        if sinfos.is_null() || unsafe { OPENSSL_sk_num(sinfos) } <= 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    372,
                    c"CMS_verify",
                    crate::runtime::err::err_reasons::CMS_R_NO_SIGNERS,
                )
            };
            break 'err2;
        }

        // SAFETY: `sinfos` is a live stack.
        let nsiginfos = unsafe { OPENSSL_sk_num(sinfos) };
        let mut i = 0;
        while i < nsiginfos {
            // SAFETY: `i` is in range.
            let si = unsafe { OPENSSL_sk_value(sinfos, i) }.cast::<CmsSignerInfo>();
            // SAFETY: `si` is live; `signer` is this frame's slot.
            unsafe {
                CMS_SignerInfo_get0_algs(
                    si,
                    ptr::null_mut(),
                    &mut signer,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if !signer.is_null() {
                scount += 1;
            }
            i += 1;
        }

        if scount != nsiginfos {
            // SAFETY: `cms` is live; `certs` is NULL or live.
            scount += unsafe { CMS_set1_signers_certs(cms, certs, flags) };
        }

        if scount != nsiginfos {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    387,
                    c"CMS_verify",
                    crate::runtime::err::err_reasons::CMS_R_SIGNER_CERTIFICATE_NOT_FOUND,
                )
            };
            break 'err2;
        }

        /* Attempt to verify all signers certs */
        /* at this point scount == sk_CMS_SignerInfo_num(sinfos) */

        if (flags & CMS_NO_SIGNER_CERT_VERIFY) == 0 || cades_verify {
            if cades_verify {
                /* Certificate trust chain is required to check CAdES signature */
                // SAFETY: the allocator answers a fresh, zeroed array.
                si_chains = CRYPTO_zalloc(
                    scount as usize * core::mem::size_of::<*mut OpenSslStack>(),
                    FILE.as_ptr(),
                    397,
                )
                .cast::<*mut OpenSslStack>();
                if si_chains.is_null() {
                    break 'err2;
                }
            }
            // SAFETY: `cms` is live; `untrusted` is this frame's slot.
            if unsafe { ossl_cms_get1_certs_ex(cms, &mut untrusted) } == 0 {
                break 'err2;
            }
            // SAFETY: `certs` is NULL or live; `untrusted` is live.
            if unsafe { OPENSSL_sk_num(certs) } > 0
                // SAFETY: `certs`/`untrusted` are live.
                && unsafe {
                    ossl_x509_add_certs_new(
                        &mut untrusted,
                        certs,
                        X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP,
                    )
                } == 0
            {
                break 'err2;
            }

            // SAFETY: `cms` is live; `crls` is this frame's slot.
            if (flags & CMS_NOCRL) == 0 && unsafe { ossl_cms_get1_crls_ex(cms, &mut crls) } == 0 {
                break 'err2;
            }
            let mut i = 0;
            while i < scount {
                // SAFETY: `i` is in range.
                let si = unsafe { OPENSSL_sk_value(sinfos, i) }.cast::<CmsSignerInfo>();

                // SAFETY: `si`/`store` are live; `untrusted`/`crls` are NULL or live.
                let chain = if si_chains.is_null() {
                    ptr::null_mut()
                } else {
                    // SAFETY: `i < scount`, the array's length.
                    unsafe { si_chains.add(i as usize) }
                };
                // SAFETY: as above.
                if unsafe { cms_signerinfo_verify_cert(si, store, untrusted, crls, chain, ctx) }
                    == 0
                {
                    break 'err2;
                }
                i += 1;
            }
        }

        /* Attempt to verify all SignerInfo signed attribute signatures */

        if (flags & CMS_NO_ATTR_VERIFY) == 0 || cades_verify {
            let mut i = 0;
            while i < scount {
                // SAFETY: `i` is in range.
                let si = unsafe { OPENSSL_sk_value(sinfos, i) }.cast::<CmsSignerInfo>();
                // SAFETY: `si` is live.
                if unsafe { CMS_signed_get_attr_count(si) } < 0 {
                    i += 1;
                    continue;
                }
                // SAFETY: `si` is live.
                if unsafe { CMS_SignerInfo_verify(si) } <= 0 {
                    break 'err2;
                }
                if cades_verify {
                    let si_chain = if si_chains.is_null() {
                        ptr::null_mut()
                    } else {
                        // SAFETY: `i < scount`, the array's length.
                        unsafe { *si_chains.add(i as usize) }
                    };

                    // SAFETY: `si` is live; `si_chain` is NULL or live.
                    if unsafe { ossl_cms_check_signing_certs(si, si_chain) } <= 0 {
                        break 'err2;
                    }
                }
                i += 1;
            }
        }

        /*
         * Performance optimization: if the content is a memory BIO then store its contents in a
         * temporary read only memory BIO. This avoids potentially large numbers of slow copies of
         * data which will occur when reading from a read write memory BIO when signatures are
         * calculated.
         */

        // SAFETY: `dcont` is NULL or a live BIO.
        if !dcont.is_null() && unsafe { BIO_method_type(dcont) } == BIO_TYPE_MEM {
            let mut p: *mut c_char = ptr::null_mut();

            // SAFETY: `dcont` is a live memory BIO; `p` is this frame's slot.
            let len = unsafe { bio_get_mem_data(dcont, &mut p) };
            tmpin = if len == 0 {
                dcont
            } else {
                // SAFETY: `p` is readable for `len`.
                unsafe { BIO_new_mem_buf(p.cast(), len as c_int) }
            };
            if tmpin.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cms(453, c"CMS_verify", ERR_R_BIO_LIB) };
                break 'err2;
            }
        } else {
            tmpin = dcont;
        }
        /*
         * If not binary mode and detached generate digests by *writing* through the BIO. That
         * makes it possible to canonicalise the input.
         */
        if (flags & SMIME_BINARY) == 0 && !dcont.is_null() {
            /*
             * Create output BIO so we can either handle text or to ensure included content doesn't
             * override detached content.
             */
            // SAFETY: `out` is NULL or live.
            tmpout = unsafe { cms_get_text_bio(out, flags) };
            if tmpout.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cms(470, c"CMS_verify", ERR_R_CMS_LIB) };
                break 'err2;
            }
            // SAFETY: `cms`/`tmpout` are live.
            cmsbio = unsafe { CMS_dataInit(cms, tmpout) };
            if cmsbio.is_null() {
                break 'err2;
            }
            /*
             * Don't use SMIME_TEXT for verify: it adds headers and we want to remove them.
             */
            // SAFETY: `dcont`/`cmsbio` are live.
            if unsafe { SMIME_crlf_copy(dcont, cmsbio, (flags & !SMIME_TEXT) as c_int) } == 0 {
                break 'err2;
            }

            if (flags & CMS_TEXT) != 0 {
                // SAFETY: `tmpout`/`out` are live.
                if unsafe { SMIME_text(tmpout, out) } == 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe {
                        raise_cms(
                            485,
                            c"CMS_verify",
                            crate::runtime::err::err_reasons::CMS_R_SMIME_TEXT_ERROR,
                        )
                    };
                    break 'err2;
                }
            }
        } else {
            // SAFETY: `cms`/`tmpin` are live as required.
            cmsbio = unsafe { CMS_dataInit(cms, tmpin) };
            if cmsbio.is_null() {
                break 'err2;
            }

            // SAFETY: `out`/`cmsbio` are live.
            if unsafe { cms_copy_content(out, cmsbio, flags) } == 0 {
                break 'err2;
            }
        }
        if (flags & CMS_NO_CONTENT_VERIFY) == 0 {
            let mut i = 0;
            while i < nsiginfos {
                // SAFETY: `i` is in range.
                let si = unsafe { OPENSSL_sk_value(sinfos, i) }.cast::<CmsSignerInfo>();
                // SAFETY: `si`/`cmsbio` are live.
                if unsafe { CMS_SignerInfo_verify_content(si, cmsbio) } <= 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe {
                        raise_cms(
                            501,
                            c"CMS_verify",
                            crate::runtime::err::err_reasons::CMS_R_CONTENT_VERIFY_ERROR,
                        )
                    };
                    break 'err2;
                }
                i += 1;
            }
        }

        ret = 1;

        // (the C `err:` label)
        if (flags & SMIME_BINARY) == 0 && !dcont.is_null() {
            // SAFETY: `cmsbio` is NULL or a live chain; `tmpout` is NULL or its tail.
            unsafe { do_free_upto(cmsbio, tmpout) };
            if tmpin != dcont {
                // SAFETY: `tmpin` is NULL or a BIO this call owns.
                unsafe { BIO_free(tmpin) };
            }
        } else if !dcont.is_null() && tmpin == dcont {
            // SAFETY: `cmsbio` is a live chain; `dcont` is its tail.
            unsafe { do_free_upto(cmsbio, dcont) };
        } else if !cmsbio.is_null() {
            // SAFETY: `cmsbio` is a chain this call owns.
            unsafe { BIO_free_all(cmsbio) };
        } else {
            // SAFETY: `tmpin` is NULL or a BIO this call owns.
            unsafe { BIO_free(tmpin) };
        }

        if out != tmpout {
            // SAFETY: `tmpout` is NULL or a chain this call owns.
            unsafe { BIO_free_all(tmpout) };
        }
    }

    if !si_chains.is_null() {
        let mut i = 0;
        while i < scount {
            // SAFETY: `i < scount`, the array's length.
            let chain = unsafe { *si_chains.add(i as usize) };
            // SAFETY: `chain` is NULL or a stack of `X509` this call owns.
            unsafe { OPENSSL_sk_pop_free(chain, Some(x509_free_void)) };
            i += 1;
        }
        // SAFETY: `si_chains` is the array allocated above.
        unsafe { CRYPTO_free(si_chains.cast(), FILE.as_ptr(), 529) };
    }
    // SAFETY: each is NULL or a stack this call owns.
    unsafe {
        OPENSSL_sk_pop_free(untrusted, Some(x509_free_void));
        OPENSSL_sk_pop_free(crls, Some(x509_crl_free_void));
    }

    ret
}

/// `int CMS_verify_receipt(CMS_ContentInfo *rcms, CMS_ContentInfo *ocms, STACK_OF(X509) *certs,`
/// `X509_STORE *store, unsigned int flags)` — `cms_smime.c:537-548`.
///
/// # Safety
/// `rcms`/`ocms`/`store` are live; `certs` is NULL or a live stack.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_verify_receipt(
    rcms: *mut CmsContentInfo,
    ocms: *mut CmsContentInfo,
    certs: *mut OpenSslStack,
    store: *mut X509Store,
    flags: c_uint,
) -> c_int {
    let flags = flags & !(CMS_DETACHED | CMS_TEXT);

    // SAFETY: `rcms`/`store` are live; `certs` is NULL or live.
    let r = unsafe { CMS_verify(rcms, certs, store, ptr::null_mut(), ptr::null_mut(), flags) };
    if r <= 0 {
        return r;
    }
    // SAFETY: `rcms`/`ocms` are live.
    unsafe { ossl_cms_Receipt_verify(rcms, ocms) }
}

/// `CMS_ContentInfo *CMS_sign_ex(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,`
/// `BIO *data, unsigned int flags, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `cms_smime.c:550-596`.
///
/// # Safety
/// `signcert`/`pkey` are NULL or live; `certs` is NULL or a live stack; `data` is NULL or a live
/// BIO; `propq` is NULL or a NUL-terminated string.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_sign_ex(
    signcert: *mut X509,
    pkey: *mut EvpPkey,
    certs: *mut OpenSslStack,
    data: *mut Bio,
    flags: c_uint,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmsContentInfo {
    // SAFETY: the caller's contract.
    let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    if cms.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(560, c"CMS_sign_ex", ERR_R_CMS_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: `cms` is live.
    if unsafe { CMS_SignedData_init(cms) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(560, c"CMS_sign_ex", ERR_R_CMS_LIB) };
        // SAFETY: `cms` is owned here.
        unsafe { CMS_ContentInfo_free(cms) };
        return ptr::null_mut();
    }
    if (flags & CMS_ASCIICRLF) != 0 {
        // SAFETY: `cms` is live; the object is a static.
        if unsafe { CMS_set1_eContentType(cms, OBJ_nid2obj(NID_id_ct_asciiTextWithCRLF)) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(566, c"CMS_sign_ex", ERR_R_CMS_LIB) };
            // SAFETY: `cms` is owned here.
            unsafe { CMS_ContentInfo_free(cms) };
            return ptr::null_mut();
        }
    }

    // SAFETY: `cms` is live; `signcert`/`pkey` are NULL or live.
    if !pkey.is_null()
        // SAFETY: `cms` is live; `signcert`/`pkey` are live.
        && unsafe { CMS_add1_signer(cms, signcert, pkey, ptr::null(), flags) }.is_null()
    {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                571,
                c"CMS_sign_ex",
                crate::runtime::err::err_reasons::CMS_R_ADD_SIGNER_ERROR,
            )
        };
        // SAFETY: `cms` is owned here.
        unsafe { CMS_ContentInfo_free(cms) };
        return ptr::null_mut();
    }

    // SAFETY: `certs` is NULL or a live stack.
    let ncerts = unsafe { OPENSSL_sk_num(certs) };
    let mut i = 0;
    while i < ncerts {
        // SAFETY: `i` is in range.
        let x = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();

        // SAFETY: `cms`/`x` are live.
        if unsafe { CMS_add1_cert(cms, x) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(579, c"CMS_sign_ex", ERR_R_CMS_LIB) };
            // SAFETY: `cms` is owned here.
            unsafe { CMS_ContentInfo_free(cms) };
            return ptr::null_mut();
        }
        i += 1;
    }

    if (flags & CMS_DETACHED) == 0 {
        // SAFETY: `cms` is live.
        unsafe { CMS_set_detached(cms, 0) };
    }

    // SAFETY: `cms`/`data` are live as required.
    if (flags & (CMS_STREAM | CMS_PARTIAL)) != 0
        // SAFETY: `cms`/`data` are live as required.
        || unsafe { CMS_final(cms, data, ptr::null_mut(), flags) } != 0
    {
        return cms;
    }

    // SAFETY: `cms` is owned here.
    unsafe { CMS_ContentInfo_free(cms) };
    ptr::null_mut()
}

/// `CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs, BIO *data,`
/// `unsigned int flags)` — `cms_smime.c:598-602`.
///
/// # Safety
/// `signcert`/`pkey` are NULL or live; `certs` is NULL or a live stack; `data` is NULL or a live BIO.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_sign(
    signcert: *mut X509,
    pkey: *mut EvpPkey,
    certs: *mut OpenSslStack,
    data: *mut Bio,
    flags: c_uint,
) -> *mut CmsContentInfo {
    // SAFETY: the arguments to the `_ex` form are the caller's.
    unsafe {
        CMS_sign_ex(
            signcert,
            pkey,
            certs,
            data,
            flags,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `CMS_ContentInfo *CMS_sign_receipt(CMS_SignerInfo *si, X509 *signcert, EVP_PKEY *pkey,`
/// `STACK_OF(X509) *certs, unsigned int flags)` — `cms_smime.c:604-674`.
///
/// # Safety
/// `si`/`signcert`/`pkey` are live; `certs` is NULL or a live stack.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_sign_receipt(
    si: *mut CmsSignerInfo,
    signcert: *mut X509,
    pkey: *mut EvpPkey,
    certs: *mut OpenSslStack,
    flags: c_uint,
) -> *mut CmsContentInfo {
    let mut rct_si: *mut CmsSignerInfo = ptr::null_mut();
    let mut cms: *mut CmsContentInfo = ptr::null_mut();
    let mut os: *mut crate::asn1::layout::Asn1String = ptr::null_mut();
    let mut rct_cont: *mut Bio = ptr::null_mut();
    let mut r = 0;
    // SAFETY: `si` is live.
    let ctx = unsafe { (*si).cms_ctx };

    let flags = (flags & !(CMS_STREAM | CMS_TEXT)) | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED;
    if pkey.is_null() || signcert.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                619,
                c"CMS_sign_receipt",
                crate::runtime::err::err_reasons::CMS_R_NO_KEY_OR_CERT,
            )
        };
        return ptr::null_mut();
    }

    /* Initialize signed data */

    'err: {
        // SAFETY: `ctx` is live; `certs` is NULL or live.
        cms = unsafe {
            CMS_sign_ex(
                ptr::null_mut(),
                ptr::null_mut(),
                certs,
                ptr::null_mut(),
                flags,
                ossl_cms_ctx_get0_libctx(ctx),
                ossl_cms_ctx_get0_propq(ctx),
            )
        };
        if cms.is_null() {
            break 'err;
        }

        /* Set inner content type to signed receipt */
        // SAFETY: `cms` is live; the object is a static.
        if unsafe { CMS_set1_eContentType(cms, OBJ_nid2obj(NID_id_smime_ct_receipt)) } == 0 {
            break 'err;
        }

        // SAFETY: `cms` is live; `signcert`/`pkey` are live.
        rct_si = unsafe { CMS_add1_signer(cms, signcert, pkey, ptr::null(), flags) };
        if rct_si.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    637,
                    c"CMS_sign_receipt",
                    crate::runtime::err::err_reasons::CMS_R_ADD_SIGNER_ERROR,
                )
            };
            break 'err;
        }

        // SAFETY: `si` is live.
        os = unsafe { ossl_cms_encode_Receipt(si) };
        if os.is_null() {
            break 'err;
        }

        /* Set content to digest */
        // SAFETY: `os` is live.
        rct_cont = unsafe { BIO_new_mem_buf((*os).data.cast(), (*os).length) };
        if rct_cont.is_null() {
            break 'err;
        }

        /* Add msgSigDigest attribute */

        // SAFETY: `rct_si`/`si` are live.
        if unsafe { ossl_cms_msgSigDigest_add1(rct_si, si) } == 0 {
            break 'err;
        }

        /* Finalize structure */
        // SAFETY: `cms`/`rct_cont` are live.
        if unsafe { CMS_final(cms, rct_cont, ptr::null_mut(), flags) } == 0 {
            break 'err;
        }

        /* Set embedded content */
        // SAFETY: `cms` is live.
        let pos = unsafe { CMS_get0_content(cms) };
        if pos.is_null() {
            break 'err;
        }
        // SAFETY: `pos` is a live slot.
        unsafe { *pos = os };

        r = 1;
    }

    // (the C `err:` label)
    // SAFETY: `rct_cont` is NULL or a BIO this call owns.
    unsafe { BIO_free(rct_cont) };
    if r != 0 {
        return cms;
    }
    // SAFETY: `cms` is NULL or owned here; `os` is NULL or owned here.
    unsafe {
        CMS_ContentInfo_free(cms);
        ASN1_STRING_free(os);
    }
    ptr::null_mut()
}

/// `CMS_ContentInfo *CMS_encrypt_ex(STACK_OF(X509) *certs, BIO *data, const EVP_CIPHER *cipher,`
/// `unsigned int flags, OSSL_LIB_CTX *libctx, const char *propq)` — `cms_smime.c:676-711`.
///
/// # Safety
/// `certs` is NULL or a live stack; `data` is NULL or a live BIO; `cipher` is live; `propq` is NULL
/// or a NUL-terminated string.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_encrypt_ex(
    certs: *mut OpenSslStack,
    data: *mut Bio,
    cipher: *const EvpCipher,
    flags: c_uint,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmsContentInfo {
    // SAFETY: `cipher` is live.
    let cms = if (unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_FLAG_AEAD_CIPHER) != 0 {
        // SAFETY: the caller's contract.
        unsafe { CMS_AuthEnvelopedData_create_ex(cipher, libctx, propq) }
    } else {
        // SAFETY: the caller's contract.
        unsafe { CMS_EnvelopedData_create_ex(cipher, libctx, propq) }
    };
    if cms.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(688, c"CMS_encrypt_ex", ERR_R_CMS_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: `certs` is NULL or a live stack.
    let ncerts = unsafe { OPENSSL_sk_num(certs) };
    let mut i = 0;
    while i < ncerts {
        // SAFETY: `i` is in range.
        let recip = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        // SAFETY: `cms`/`recip` are live.
        if unsafe { CMS_add1_recipient_cert(cms, recip, flags) }.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    695,
                    c"CMS_encrypt_ex",
                    crate::runtime::err::err_reasons::CMS_R_RECIPIENT_ERROR,
                )
            };
            // SAFETY: `cms` is owned here.
            unsafe { CMS_ContentInfo_free(cms) };
            return ptr::null_mut();
        }
        i += 1;
    }

    if (flags & CMS_DETACHED) == 0 {
        // SAFETY: `cms` is live.
        unsafe { CMS_set_detached(cms, 0) };
    }

    // SAFETY: `cms`/`data` are live as required.
    if (flags & (CMS_STREAM | CMS_PARTIAL)) != 0
        // SAFETY: `cms`/`data` are live as required.
        || unsafe { CMS_final(cms, data, ptr::null_mut(), flags) } != 0
    {
        return cms;
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cms(706, c"CMS_encrypt_ex", ERR_R_CMS_LIB) };

    // SAFETY: `cms` is owned here.
    unsafe { CMS_ContentInfo_free(cms) };
    ptr::null_mut()
}

/// `CMS_ContentInfo *CMS_encrypt(STACK_OF(X509) *certs, BIO *data, const EVP_CIPHER *cipher,`
/// `unsigned int flags)` — `cms_smime.c:713-717`.
///
/// # Safety
/// `certs` is NULL or a live stack; `data` is NULL or a live BIO; `cipher` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_encrypt(
    certs: *mut OpenSslStack,
    data: *mut Bio,
    cipher: *const EvpCipher,
    flags: c_uint,
) -> *mut CmsContentInfo {
    // SAFETY: the arguments to the `_ex` form are the caller's.
    unsafe { CMS_encrypt_ex(certs, data, cipher, flags, ptr::null_mut(), ptr::null()) }
}

/// `static int cms_kari_set1_pkey_and_peer(CMS_ContentInfo *cms, CMS_RecipientInfo *ri,`
/// `EVP_PKEY *pk, X509 *cert, X509 *peer)` — `cms_smime.c:719-742`.
///
/// # Safety
/// `cms`/`ri`/`pk` are live; `cert`/`peer` are NULL or live.
unsafe fn cms_kari_set1_pkey_and_peer(
    cms: *mut CmsContentInfo,
    ri: *mut CmsRecipientInfo,
    pk: *mut EvpPkey,
    cert: *mut X509,
    peer: *mut X509,
) -> c_int {
    // SAFETY: `ri` is live.
    let reks = unsafe { CMS_RecipientInfo_kari_get0_reks(ri) };
    // SAFETY: `reks` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(reks) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range.
        let rek = unsafe { OPENSSL_sk_value(reks, i) }.cast::<CmsRecipientEncryptedKey>();
        // SAFETY: `rek`/`cert` are live as required.
        if !cert.is_null() && unsafe { CMS_RecipientEncryptedKey_cert_cmp(rek, cert) } != 0 {
            i += 1;
            continue;
        }
        // SAFETY: `ri`/`pk` are live; `peer` is NULL or live.
        unsafe { CMS_RecipientInfo_kari_set0_pkey_and_peer(ri, pk, peer) };
        // SAFETY: `cms`/`ri`/`rek` are live.
        let rv = unsafe { CMS_RecipientInfo_kari_decrypt(cms, ri, rek) };
        // SAFETY: `ri` is live.
        unsafe { CMS_RecipientInfo_kari_set0_pkey(ri, ptr::null_mut()) };
        if rv > 0 {
            return 1;
        }
        return if cert.is_null() { 0 } else { -1 };
    }
    0
}

/// `int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert)` —
/// `cms_smime.c:744-747`.
///
/// # Safety
/// `cms`/`pk` are live; `cert` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_decrypt_set1_pkey(
    cms: *mut CmsContentInfo,
    pk: *mut EvpPkey,
    cert: *mut X509,
) -> c_int {
    // SAFETY: the arguments to the `_and_peer` form are the caller's.
    unsafe { CMS_decrypt_set1_pkey_and_peer(cms, pk, cert, ptr::null_mut()) }
}

/// `int CMS_decrypt_set1_pkey_and_peer(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert,`
/// `X509 *peer)` — `cms_smime.c:749-839`.
///
/// # Safety
/// `cms`/`pk` are live; `cert`/`peer` are NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_decrypt_set1_pkey_and_peer(
    cms: *mut CmsContentInfo,
    pk: *mut EvpPkey,
    cert: *mut X509,
    peer: *mut X509,
) -> c_int {
    // SAFETY: `cms` is live.
    let ris = unsafe { CMS_get0_RecipientInfos(cms) };
    let mut debug = 0;
    let mut match_ri = 0;
    // SAFETY: `cms` is live.
    let ec = unsafe { ossl_cms_get0_env_enc_content(cms) };

    /* Prevent mem leak on earlier CMS_decrypt_set1_{pkey_and_peer,password} */
    if !ec.is_null() {
        // SAFETY: `ec` is live.
        unsafe {
            super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
            (*ec).key = ptr::null_mut();
            (*ec).keylen = 0;
        }
    }

    if !ris.is_null() && !ec.is_null() {
        // SAFETY: `ec` is live.
        debug = unsafe { (*ec).debug };
    }

    // SAFETY: `pk` is live.
    let cms_pkey_ri_type = unsafe { ossl_cms_pkey_get_ri_type(pk) };
    if cms_pkey_ri_type == super::cms_asn1::CMS_RECIPINFO_NONE {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                770,
                c"CMS_decrypt_set1_pkey_and_peer",
                crate::runtime::err::err_reasons::CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE,
            )
        };
        return 0;
    }

    // SAFETY: `ris` is NULL or a live stack.
    let nris = unsafe { OPENSSL_sk_num(ris) };
    let mut i = 0;
    while i < nris {
        // SAFETY: `i` is in range.
        let ri = unsafe { OPENSSL_sk_value(ris, i) }.cast::<CmsRecipientInfo>();
        // SAFETY: `ri` is live.
        let ri_type = unsafe { CMS_RecipientInfo_type(ri) };
        // SAFETY: `pk` is live.
        if unsafe { ossl_cms_pkey_is_ri_type_supported(pk, ri_type) } == 0 {
            i += 1;
            continue;
        }
        match_ri = 1;
        if ri_type == super::cms_asn1::CMS_RECIPINFO_AGREE {
            // SAFETY: `cms`/`ri`/`pk` are live; `cert`/`peer` are NULL or live.
            let r = unsafe { cms_kari_set1_pkey_and_peer(cms, ri, pk, cert, peer) };
            if r > 0 {
                return 1;
            }
            if r < 0 {
                return 0;
            }
        } else if ri_type == super::cms_asn1::CMS_RECIPINFO_KEM {
            // SAFETY: `ri`/`cert` are live as required.
            if cert.is_null() || unsafe { CMS_RecipientInfo_kemri_cert_cmp(ri, cert) } == 0 {
                // SAFETY: `ri`/`pk` are live.
                unsafe { CMS_RecipientInfo_kemri_set0_pkey(ri, pk) };
                // SAFETY: `cms`/`ri` are live.
                let r = unsafe { CMS_RecipientInfo_decrypt(cms, ri) };
                // SAFETY: `ri` is live.
                unsafe { CMS_RecipientInfo_kemri_set0_pkey(ri, ptr::null_mut()) };
                if !cert.is_null() || r > 0 {
                    return r;
                }
            }
        }
        /* If we have a cert, try matching RecipientInfo, else try them all */
        else if cert.is_null()
            // SAFETY: `ri` is live; `cert` is non-null per the short circuit.
            || unsafe { CMS_RecipientInfo_ktri_cert_cmp(ri, cert) } == 0
        {
            // SAFETY: `pk` is live.
            if unsafe { EVP_PKEY_up_ref(pk) } == 0 {
                return 0;
            }
            // SAFETY: `ri`/`pk` are live.
            unsafe { CMS_RecipientInfo_set0_pkey(ri, pk) };
            // SAFETY: `cms`/`ri` are live.
            let r = unsafe { CMS_RecipientInfo_decrypt(cms, ri) };
            // SAFETY: `ri` is live.
            unsafe { CMS_RecipientInfo_set0_pkey(ri, ptr::null_mut()) };
            if !cert.is_null() {
                /*
                 * If not debugging clear any error and return success to avoid leaking of
                 * information useful to MMA
                 */
                if debug == 0 {
                    ERR_clear_error();
                    return 1;
                }
                if r > 0 {
                    return 1;
                }
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        816,
                        c"CMS_decrypt_set1_pkey_and_peer",
                        crate::runtime::err::err_reasons::CMS_R_DECRYPT_ERROR,
                    )
                };
                return 0;
            }
            /*
             * If no cert and not debugging don't leave loop after first successful decrypt. Always
             * attempt to decrypt all recipients to avoid leaking timing of a successful decrypt.
             */
            else if r > 0
                && (debug != 0 || cms_pkey_ri_type != super::cms_asn1::CMS_RECIPINFO_TRANS)
            {
                return 1;
            }
        }
        i += 1;
    }
    /* If no cert, key transport and not debugging always return success */
    if cert.is_null()
        && cms_pkey_ri_type == super::cms_asn1::CMS_RECIPINFO_TRANS
        && match_ri != 0
        && debug == 0
    {
        ERR_clear_error();
        return 1;
    }

    if match_ri == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                837,
                c"CMS_decrypt_set1_pkey_and_peer",
                crate::runtime::err::err_reasons::CMS_R_NO_MATCHING_RECIPIENT,
            )
        };
    }
    0
}

/// `int CMS_decrypt_set1_key(CMS_ContentInfo *cms, unsigned char *key, size_t keylen,`
/// `const unsigned char *id, size_t idlen)` — `cms_smime.c:841-875`.
///
/// # Safety
/// `cms` is live; `key` is writable for `keylen` or NULL; `id` is readable for `idlen` or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_decrypt_set1_key(
    cms: *mut CmsContentInfo,
    key: *mut c_uchar,
    keylen: usize,
    id: *const c_uchar,
    idlen: usize,
) -> c_int {
    let mut match_ri = 0;

    // SAFETY: `cms` is live.
    let ris = unsafe { CMS_get0_RecipientInfos(cms) };
    // SAFETY: `ris` is NULL or a live stack.
    let nris = unsafe { OPENSSL_sk_num(ris) };
    let mut i = 0;
    while i < nris {
        // SAFETY: `i` is in range.
        let ri = unsafe { OPENSSL_sk_value(ris, i) }.cast::<CmsRecipientInfo>();
        // SAFETY: `ri` is live.
        if unsafe { CMS_RecipientInfo_type(ri) } != super::cms_asn1::CMS_RECIPINFO_KEK {
            i += 1;
            continue;
        }

        /* If we have an id, try matching RecipientInfo, else try them all */
        // SAFETY: `ri` is live; `id` is readable for `idlen` or NULL.
        if id.is_null() || unsafe { CMS_RecipientInfo_kekri_id_cmp(ri, id, idlen) } == 0 {
            match_ri = 1;
            // SAFETY: `ri` is live; `key` is writable for `keylen` or NULL.
            unsafe { CMS_RecipientInfo_set0_key(ri, key, keylen) };
            // SAFETY: `cms`/`ri` are live.
            let r = unsafe { CMS_RecipientInfo_decrypt(cms, ri) };
            // SAFETY: `ri` is live.
            unsafe { CMS_RecipientInfo_set0_key(ri, ptr::null_mut(), 0) };
            if r > 0 {
                return 1;
            }
            if !id.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        865,
                        c"CMS_decrypt_set1_key",
                        crate::runtime::err::err_reasons::CMS_R_DECRYPT_ERROR,
                    )
                };
                return 0;
            }
            ERR_clear_error();
        }
        i += 1;
    }

    if match_ri == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                873,
                c"CMS_decrypt_set1_key",
                crate::runtime::err::err_reasons::CMS_R_NO_MATCHING_RECIPIENT,
            )
        };
    }
    0
}

/// `int CMS_decrypt_set1_password(CMS_ContentInfo *cms, unsigned char *pass,`
/// `ossl_ssize_t passlen)` — `cms_smime.c:877-909`.
///
/// # Safety
/// `cms` is live; `pass` is writable for `passlen` or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_decrypt_set1_password(
    cms: *mut CmsContentInfo,
    pass: *mut c_uchar,
    passlen: isize,
) -> c_int {
    // SAFETY: `cms` is live.
    let ris = unsafe { CMS_get0_RecipientInfos(cms) };
    let mut match_ri = 0;
    // SAFETY: `cms` is live.
    let ec = unsafe { ossl_cms_get0_env_enc_content(cms) };

    /* Prevent mem leak on earlier CMS_decrypt_set1_{pkey_and_peer,password} */
    if !ec.is_null() {
        // SAFETY: `ec` is live.
        unsafe {
            super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
            (*ec).key = ptr::null_mut();
            (*ec).keylen = 0;
        }
    }

    // SAFETY: `ris` is NULL or a live stack.
    let nris = unsafe { OPENSSL_sk_num(ris) };
    let mut i = 0;
    while i < nris {
        // SAFETY: `i` is in range.
        let ri = unsafe { OPENSSL_sk_value(ris, i) }.cast::<CmsRecipientInfo>();
        // SAFETY: `ri` is live.
        if unsafe { CMS_RecipientInfo_type(ri) } != super::cms_asn1::CMS_RECIPINFO_PASS {
            i += 1;
            continue;
        }

        /* Must try each PasswordRecipientInfo */
        match_ri = 1;
        // SAFETY: `ri` is live; `pass` is writable for `passlen` or NULL.
        unsafe { super::cms_pwri::CMS_RecipientInfo_set0_password(ri, pass, passlen) };
        // SAFETY: `cms`/`ri` are live.
        let r = unsafe { CMS_RecipientInfo_decrypt(cms, ri) };
        // SAFETY: `ri` is live.
        unsafe { super::cms_pwri::CMS_RecipientInfo_set0_password(ri, ptr::null_mut(), 0) };
        if r > 0 {
            return 1;
        }
        i += 1;
    }

    if match_ri == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                907,
                c"CMS_decrypt_set1_password",
                crate::runtime::err::err_reasons::CMS_R_NO_MATCHING_RECIPIENT,
            )
        };
    }
    0
}

/// `int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert, BIO *dcont, BIO *out,`
/// `unsigned int flags)` — `cms_smime.c:911-939`.
///
/// # Safety
/// `cms` is live; `pk`/`cert` are NULL or live; `dcont`/`out` are NULL or live BIOs.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_decrypt(
    cms: *mut CmsContentInfo,
    pk: *mut EvpPkey,
    cert: *mut X509,
    dcont: *mut Bio,
    out: *mut Bio,
    flags: c_uint,
) -> c_int {
    // SAFETY: `cms` is live.
    let nid = unsafe { OBJ_obj2nid(CMS_get0_type(cms)) };

    if nid != NID_pkcs7_enveloped && nid != NID_id_smime_ct_authEnvelopedData {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                921,
                c"CMS_decrypt",
                crate::runtime::err::err_reasons::CMS_R_TYPE_NOT_ENVELOPED_DATA,
            )
        };
        return 0;
    }
    if dcont.is_null() {
        // SAFETY: `cms` is live.
        if unsafe { check_content(cms) } == 0 {
            return 0;
        }
    }
    // SAFETY: `cms` is live.
    let ec = unsafe { ossl_cms_get0_env_enc_content(cms) };
    // SAFETY: `ec` is live.
    unsafe {
        (*ec).debug = c_int::from((flags & CMS_DEBUG_DECRYPT) != 0);
        (*ec).havenocert = c_int::from(cert.is_null());
    }
    if pk.is_null() && cert.is_null() && dcont.is_null() && out.is_null() {
        return 1;
    }
    // SAFETY: `cms`/`pk` are live; `cert` is NULL or live.
    if !pk.is_null() && unsafe { CMS_decrypt_set1_pkey(cms, pk, cert) } == 0 {
        return 0;
    }
    // SAFETY: `cms`/`dcont` are live as required.
    let cont = unsafe { CMS_dataInit(cms, dcont) };
    if cont.is_null() {
        return 0;
    }
    // SAFETY: `out`/`cont` are live.
    let r = unsafe { cms_copy_content(out, cont, flags) };
    // SAFETY: `cont` is a live chain; `dcont` is NULL or its tail.
    unsafe { do_free_upto(cont, dcont) };
    r
}

/// `int CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont, unsigned int flags)` —
/// `cms_smime.c:941-968`.
///
/// # Safety
/// `cms`/`data` are live; `dcont` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_final(
    cms: *mut CmsContentInfo,
    data: *mut Bio,
    dcont: *mut Bio,
    flags: c_uint,
) -> c_int {
    let mut ret = 0;

    // SAFETY: `cms`/`dcont` are live as required.
    let cmsbio = unsafe { CMS_dataInit(cms, dcont) };
    if cmsbio.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(947, c"CMS_final", ERR_R_CMS_LIB) };
        return 0;
    }

    'err: {
        // SAFETY: `data`/`cmsbio` are live.
        if unsafe { SMIME_crlf_copy(data, cmsbio, flags as c_int) } == 0 {
            break 'err;
        }

        // SAFETY: `cmsbio` is live.
        unsafe { bio_flush(cmsbio) };

        // SAFETY: `cms`/`cmsbio` are live.
        if unsafe { CMS_dataFinal(cms, cmsbio) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    958,
                    c"CMS_final",
                    crate::runtime::err::err_reasons::CMS_R_CMS_DATAFINAL_ERROR,
                )
            };
            break 'err;
        }

        ret = 1;
    }

    // SAFETY: `cmsbio` is a live chain; `dcont` is NULL or its tail.
    unsafe { do_free_upto(cmsbio, dcont) };

    ret
}

/// `int CMS_final_digest(CMS_ContentInfo *cms, const unsigned char *md, unsigned int mdlen,`
/// `BIO *dcont, unsigned int flags)` — `cms_smime.c:970-993`.
///
/// # Safety
/// `cms` is live; `md` is readable for `mdlen` or NULL; `dcont` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_final_digest(
    cms: *mut CmsContentInfo,
    md: *const c_uchar,
    mdlen: c_uint,
    dcont: *mut Bio,
    _flags: c_uint,
) -> c_int {
    let mut ret = 0;

    // SAFETY: `cms`/`dcont` are live as required.
    let cmsbio = unsafe { CMS_dataInit(cms, dcont) };
    if cmsbio.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(978, c"CMS_final_digest", ERR_R_CMS_LIB) };
        return 0;
    }

    'err: {
        // SAFETY: `cmsbio` is live.
        unsafe { bio_flush(cmsbio) };

        // SAFETY: `cms`/`cmsbio` are live; `md` is readable for `mdlen` or NULL.
        if unsafe { ossl_cms_DataFinal(cms, cmsbio, md, mdlen) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    985,
                    c"CMS_final_digest",
                    crate::runtime::err::err_reasons::CMS_R_CMS_DATAFINAL_ERROR,
                )
            };
            break 'err;
        }
        ret = 1;
    }

    // SAFETY: `cmsbio` is a live chain; `dcont` is NULL or its tail.
    unsafe { do_free_upto(cmsbio, dcont) };
    ret
}

/// `int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out, unsigned int flags)` —
/// `cms_smime.c:1041-1046` (the `#else` arm; the admitted authority is built
/// `OPENSSL_NO_ZLIB`, so this is the arm its `cms_smime.c` compiled).
///
/// # Safety
/// Any argument may be NULL; the refusal arm dereferences none of them.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_uncompress(
    _cms: *mut CmsContentInfo,
    _dcont: *mut Bio,
    _out: *mut Bio,
    _flags: c_uint,
) -> c_int {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_cms(
            1044,
            c"CMS_uncompress",
            crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM,
        )
    };
    0
}

/// `CMS_ContentInfo *CMS_compress(BIO *in, int comp_nid, unsigned int flags)` —
/// `cms_smime.c:1048-1052` (the `#else` arm; the admitted authority is built
/// `OPENSSL_NO_ZLIB`, so this is the arm its `cms_smime.c` compiled).
///
/// # Safety
/// Any argument may be NULL; the refusal arm dereferences none of them.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_compress(
    _in: *mut Bio,
    _comp_nid: c_int,
    _flags: c_uint,
) -> *mut CmsContentInfo {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_cms(
            1050,
            c"CMS_compress",
            crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM,
        )
    };
    ptr::null_mut()
}
