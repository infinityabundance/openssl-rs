//! `crypto/pkcs7/pk7_doit.c` — the `PKCS7` sign/verify/encrypt/decrypt chain and the attribute
//! accessors. Phase 12.2.
//!
//! ## What lands
//!
//! The streaming engine (`PKCS7_dataInit`, `PKCS7_dataDecode`, `PKCS7_dataFinal`), the
//! signature path (`PKCS7_SIGNER_INFO_sign`, `PKCS7_dataVerify`, `PKCS7_signatureVerify`) and
//! the attribute surface (`PKCS7_add_attribute`, `PKCS7_get_signed_attribute`,
//! `PKCS7_set_signed_attributes`, `PKCS7_digest_from_attributes` and their companions).
//!
//! ## The macros this module expands
//!
//! `EVP_MD_CTX_get_type(m)` is `EVP_MD_get_type(EVP_MD_CTX_get0_md(m))`,
//! `EVP_get_digestbyobj(o)` is `EVP_get_digestbynid(OBJ_obj2nid(o))` and `EVP_get_digestbynid(n)`
//! is `EVP_get_digestbyname(OBJ_nid2sn(n))` (`include/openssl/evp.h:548,554,593`). `BIO_set_md`,
//! `BIO_get_md_ctx`, `BIO_get_cipher_ctx`, `BIO_get_cipher_status`, `BIO_get_mem_data` and
//! `BIO_set_mem_eof_return` are `BIO_ctrl` wrappers (`include/openssl/bio.h`) and are expanded
//! inline through the crate's `BIO_ctrl`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::der::ASN1_get_object;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{
    Asn1String, Asn1Type, V_ASN1_CONSTRUCTED, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE,
};
use crate::asn1::string::{
    ASN1_OCTET_STRING_dup, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set, ASN1_STRING_set0,
};
use crate::evp::asymcipher::{
    evp_pkey_decrypt_alloc, EVP_PKEY_decrypt_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init,
};
use crate::evp::bio_enc::{BIO_f_cipher, BIO_f_md};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get0_name, EVP_CIPHER_get_iv_length,
    EVP_CIPHER_get_key_length, EVP_CIPHER_get_type, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_rand_key, EVP_CIPHER_CTX_set_key_length,
    EVP_CIPHER_asn1_to_param, EVP_CIPHER_param_to_asn1, EVP_CipherInit_ex, EvpCipherCtx,
};
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestSignFinal, EVP_DigestSignInit_ex,
    EVP_DigestSignUpdate, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_get0_md, EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free, EVP_MD_get_pkey_type,
    EVP_MD_get_type, EvpMd, EvpMdCtx,
};
use crate::evp::legacy_evp::{EVP_get_cipherbyname, EVP_get_digestbyname};
use crate::evp::p_legacy::{EVP_SignFinal_ex, EVP_VerifyFinal_ex};
use crate::evp::pkey::{EVP_PKEY_get_size, EvpPkey};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, EvpPkeyCtx};
use crate::pkcs7::pk7_asn1::{
    PKCS7_ATTR_SIGN_it, PKCS7_ATTR_VERIFY_it, Pkcs7, Pkcs7Ctx, Pkcs7IssuerAndSerial,
    Pkcs7RecipInfo, Pkcs7SignerInfo,
};
use crate::pkcs7::pk7_attr::{PKCS7_add0_attrib_signing_time, PKCS7_add1_attrib_digest};
use crate::pkcs7::pk7_lib::{
    ossl_pkcs7_ctx_get0_libctx, ossl_pkcs7_ctx_get0_propq, ossl_pkcs7_get0_ctx, pkcs7_is_detached,
    pkcs7_type_is_data, pkcs7_type_is_signed, pkcs7_type_is_signed_and_enveloped, PKCS7_S_HEADER,
};
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::bio::bss_mem::{BIO_new_mem_buf, BIO_s_mem};
use crate::runtime::bio::bss_null::BIO_s_null;
use crate::runtime::bio::{
    BIO_ctrl, BIO_find_type, BIO_free, BIO_free_all, BIO_new, BIO_next, BIO_push, BIO_set_flags,
    BIO_write, Bio, BIO_CTRL_INFO, BIO_C_GET_CIPHER_CTX, BIO_C_GET_CIPHER_STATUS, BIO_C_GET_MD_CTX,
    BIO_C_SET_BUF_MEM_EOF_RETURN, BIO_C_SET_MD, BIO_FLAGS_MEM_RDONLY, BIO_TYPE_MD, BIO_TYPE_MEM,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, OPENSSL_cleanse};
use crate::runtime::obj::{
    NID_pkcs9_messageDigest, NID_pkcs9_signingTime, OBJ_obj2nid, OBJ_obj2txt,
};
use crate::runtime::stack::{
    OPENSSL_sk_deep_copy, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_set,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::x509_att::{X509_ATTRIBUTE_get0_object, X509at_get_attr, X509at_get_attr_by_NID};
use crate::x509::x509_cmp::{X509_find_by_issuer_and_serial, X509_get0_pubkey};
use crate::x509::x509_lu::{X509Store, X509StoreCtx};
use crate::x509::x509_vfy::{X509_STORE_CTX_init, X509_STORE_CTX_set_purpose, X509_verify_cert};
use crate::x509::x_attrib::{X509Attribute, X509_ATTRIBUTE_dup, X509_ATTRIBUTE_free};
use crate::x509::x_x509::X509;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/pkcs7/pk7_doit.c";

/// `OSSL_MAX_NAME_SIZE` — `internal/sizes.h:15`.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:43`.
const EVP_MAX_MD_SIZE: usize = 64;
/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:45`.
const EVP_MAX_KEY_LENGTH: usize = 64;
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:46`.
const EVP_MAX_IV_LENGTH: usize = 16;
/// `X509_PURPOSE_SMIME_SIGN` — `include/openssl/x509v3.h:769`.
const X509_PURPOSE_SMIME_SIGN: c_int = 4;

extern "C" {
    /// `int memcmp(const void *, const void *, size_t)`.
    fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
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
unsafe fn bio_get_md_ctx(b: *mut Bio, pmdc: *mut *mut EvpMdCtx) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_C_GET_MD_CTX, 0, pmdc.cast()) as c_int }
}

/// `BIO_get_cipher_ctx(BIO *, EVP_CIPHER_CTX **)` — `BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, pctx)`.
///
/// # Safety
/// `b` is a live cipher BIO; `pctx` is writable.
unsafe fn bio_get_cipher_ctx(b: *mut Bio, pctx: *mut *mut EvpCipherCtx) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, pctx.cast()) as c_int }
}

/// `BIO_get_cipher_status(BIO *)` — `BIO_ctrl(b, BIO_C_GET_CIPHER_STATUS, 0, NULL)`.
///
/// # Safety
/// `b` is a live cipher BIO.
pub(crate) unsafe fn bio_get_cipher_status(b: *mut Bio) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_STATUS, 0, ptr::null_mut()) as c_int }
}

/// `BIO_get_mem_data(BIO *, char **)` — `BIO_ctrl(b, BIO_CTRL_INFO, 0, pp)`.
///
/// # Safety
/// `b` is a live memory BIO; `pp` is writable.
unsafe fn bio_get_mem_data(b: *mut Bio, pp: *mut *mut c_char) -> c_long {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_CTRL_INFO, 0, pp.cast()) }
}

/// `BIO_set_mem_eof_return(BIO *, int)` — `BIO_ctrl(b, BIO_C_SET_BUF_MEM_EOF_RETURN, v, NULL)`.
///
/// # Safety
/// `b` is a live memory BIO.
pub(crate) unsafe fn bio_set_mem_eof_return(b: *mut Bio, v: c_int) {
    // SAFETY: per this function's contract.
    unsafe {
        BIO_ctrl(
            b,
            BIO_C_SET_BUF_MEM_EOF_RETURN,
            v as c_long,
            ptr::null_mut(),
        )
    };
}

/// `int PKCS7_type_is_other(PKCS7 *p7)` — `pk7_doit.c:25-45`.
///
/// # Safety
/// `p7` is live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_type_is_other(p7: *mut Pkcs7) -> c_int {
    // SAFETY: `p7` is live.
    let nid = unsafe { OBJ_obj2nid((*p7).type_) };
    match nid {
        crate::runtime::obj::NID_pkcs7_data
        | crate::runtime::obj::NID_pkcs7_signed
        | crate::runtime::obj::NID_pkcs7_enveloped
        | crate::runtime::obj::NID_pkcs7_signedAndEnveloped
        | crate::runtime::obj::NID_pkcs7_digest
        | crate::runtime::obj::NID_pkcs7_encrypted => 0,
        _ => 1,
    }
}

/// `ASN1_OCTET_STRING *PKCS7_get_octet_string(PKCS7 *p7)` — `pk7_doit.c:47-55`.
///
/// # Safety
/// `p7` is live; a non-null answer borrows the content.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_octet_string(p7: *mut Pkcs7) -> *mut Asn1String {
    if pkcs7_type_is_data(p7) {
        // SAFETY: `p7` is a live data structure.
        return unsafe { (*p7).d.data };
    }
    // SAFETY: `p7` is live.
    if unsafe { PKCS7_type_is_other(p7) } != 0 {
        // SAFETY: `p7` is live.
        let other = unsafe { (*p7).d.other };
        if !other.is_null() {
            // SAFETY: `other` is live.
            if unsafe { (*other).type_ } == V_ASN1_OCTET_STRING {
                // SAFETY: the union's `octet_string` member is the string.
                return unsafe { (*other).value.ptr.cast::<Asn1String>() };
            }
        }
    }
    ptr::null_mut()
}

/// `pkcs7_get1_data(PKCS7 *p7)` — `pk7_doit.c:57-92`.
///
/// # Safety
/// `p7` is live; a non-null answer is a fresh duplicate the caller owns.
unsafe fn pkcs7_get1_data(p7: *mut Pkcs7) -> *mut Asn1String {
    // SAFETY: `p7` is live.
    let os = unsafe { PKCS7_get_octet_string(p7) };
    if !os.is_null() {
        // SAFETY: `os` is live.
        let osdup = unsafe { ASN1_OCTET_STRING_dup(os) };
        // SAFETY: `os` is live.
        if !osdup.is_null()
            // SAFETY: `os` is live.
            && (unsafe { (*os).flags } & crate::asn1::layout::ASN1_STRING_FLAG_NDEF) != 0
        {
            // SAFETY: `osdup` is fresh and owned here.
            unsafe { ASN1_STRING_set0(osdup, ptr::null_mut(), 0) };
        }
        return osdup;
    }

    // SAFETY: `p7` is live.
    if unsafe { PKCS7_type_is_other(p7) } != 0 {
        // SAFETY: `p7` is live.
        let other = unsafe { (*p7).d.other };
        if !other.is_null()
            // SAFETY: `other` is live.
            && unsafe { (*other).type_ } == V_ASN1_SEQUENCE
            // SAFETY: as above.
            && !unsafe { (*other).value.ptr }.is_null()
        {
            // SAFETY: the union's `sequence` member is the string.
            let seq = unsafe { (*other).value.ptr.cast::<Asn1String>() };
            // SAFETY: `seq` is live.
            if unsafe { (*seq).length } > 0 {
                // SAFETY: `seq` is live.
                let mut data: *const c_uchar = unsafe { (*seq).data };
                let mut len: c_long = 0;
                let mut tag: c_int = 0;
                let mut class: c_int = 0;
                // SAFETY: `data`/`seq` are live; the out-pointers are writable.
                let inf = unsafe {
                    ASN1_get_object(
                        &mut data,
                        &mut len,
                        &mut tag,
                        &mut class,
                        (*seq).length as c_long,
                    )
                };
                // SAFETY: no preconditions.
                let out = ASN1_OCTET_STRING_new();
                if out.is_null() {
                    return ptr::null_mut();
                }
                if inf != V_ASN1_CONSTRUCTED
                    || tag != V_ASN1_SEQUENCE
                    // SAFETY: `out` is live; `data`/`len` describe the inner content.
                    || unsafe { ASN1_OCTET_STRING_set(out, data, len as c_int) } == 0
                {
                    // SAFETY: `out` is live and owned here.
                    unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(out) };
                    return ptr::null_mut();
                }
                return out;
            }
        }
    }
    ptr::null_mut()
}

/// `pkcs7_bio_add_digest(BIO **pbio, X509_ALGOR *alg, const PKCS7_CTX *ctx)` —
/// `pk7_doit.c:94-143`.
///
/// # Safety
/// `pbio` is a live out-pointer; `alg` and `ctx` are live.
unsafe fn pkcs7_bio_add_digest(
    pbio: *mut *mut Bio,
    alg: *mut crate::asn1::x_algor::X509Algor,
    ctx: *const Pkcs7Ctx,
) -> c_int {
    // SAFETY: no preconditions.
    let btmp = unsafe { BIO_new(BIO_f_md()) };
    if btmp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_103) };
        return 0;
    }
    let mut name = [0 as c_char; OSSL_MAX_NAME_SIZE];
    // SAFETY: `alg` is live; the buffer and OID are the caller's.
    unsafe {
        OBJ_obj2txt(
            name.as_mut_ptr(),
            OSSL_MAX_NAME_SIZE as c_int,
            (*alg).algorithm,
            0,
        )
    };

    // SAFETY: `ctx` is the caller's; `name` is NUL-terminated.
    let fetched = unsafe {
        EVP_MD_fetch(
            ossl_pkcs7_ctx_get0_libctx(ctx),
            name.as_ptr(),
            ossl_pkcs7_ctx_get0_propq(ctx),
        )
    };
    let md: *const EvpMd = if !fetched.is_null() {
        fetched
    } else {
        // SAFETY: `name` is NUL-terminated.
        unsafe { EVP_get_digestbyname(name.as_ptr()) }
    };
    if md.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_119) };
        // SAFETY: `btmp` is live and owned here.
        unsafe { BIO_free(btmp) };
        return 0;
    }
    // SAFETY: `btmp`/`md` are live.
    if unsafe { bio_set_md(btmp, md) } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_125) };
        // SAFETY: `btmp` is live and owned here; `fetched` is this unit's.
        unsafe {
            EVP_MD_free(fetched);
            BIO_free(btmp);
        }
        return 0;
    }
    // SAFETY: `fetched` is null or this unit's fetch.
    unsafe { EVP_MD_free(fetched) };
    // SAFETY: `pbio` is a live out-pointer.
    if unsafe { *pbio }.is_null() {
        // SAFETY: `pbio` is writable.
        unsafe { *pbio = btmp };
    // SAFETY: `*pbio`/`btmp` are live.
    } else if unsafe { BIO_push(*pbio, btmp) }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_133) };
        // SAFETY: `btmp` is live and owned here.
        unsafe { BIO_free(btmp) };
        return 0;
    }
    1
}

/// `pkcs7_encode_rinfo(PKCS7_RECIP_INFO *ri, unsigned char *key, int keylen)` —
/// `pk7_doit.c:145-186`.
///
/// # Safety
/// `ri` is live; `key` is `keylen` readable bytes.
unsafe fn pkcs7_encode_rinfo(ri: *mut Pkcs7RecipInfo, key: *mut u8, keylen: c_int) -> c_int {
    // SAFETY: `ri` is live.
    let pkey = unsafe { X509_get0_pubkey((*ri).cert) };
    if pkey.is_null() {
        return 0;
    }
    // SAFETY: `ri` is live.
    let ctx = unsafe { (*ri).ctx };
    // SAFETY: `ctx` is the recipient's borrowed context; `pkey` is live.
    let pctx = unsafe {
        EVP_PKEY_CTX_new_from_pkey(
            ossl_pkcs7_ctx_get0_libctx(ctx),
            pkey,
            ossl_pkcs7_ctx_get0_propq(ctx),
        )
    };
    if pctx.is_null() {
        return 0;
    }
    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_encrypt_init(pctx) } <= 0 {
        // SAFETY: `pctx` is live and owned here.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        return 0;
    }
    let mut eklen: usize = 0;
    // SAFETY: `pctx`/`key` are live; the out-pointer is writable.
    if unsafe { EVP_PKEY_encrypt(pctx, ptr::null_mut(), &mut eklen, key, keylen as usize) } <= 0 {
        // SAFETY: `pctx` is live and owned here.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        return 0;
    }
    // SAFETY: no preconditions.
    let ek = CRYPTO_malloc(eklen, FILE.as_ptr(), 170).cast::<u8>();
    if ek.is_null() {
        // SAFETY: `pctx` is live and owned here.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        return 0;
    }
    // SAFETY: `pctx`/`ek`/`key` are live; the out-pointer is writable.
    if unsafe { EVP_PKEY_encrypt(pctx, ek, &mut eklen, key, keylen as usize) } <= 0 {
        // SAFETY: `ek` is live and owned here; `pctx` is live.
        unsafe {
            CRYPTO_free(ek.cast(), FILE.as_ptr(), 174);
            EVP_PKEY_CTX_free(pctx);
        }
        return 0;
    }
    // SAFETY: `ri` is live and its `enc_key` is live.
    unsafe { ASN1_STRING_set0((*ri).enc_key, ek.cast(), eklen as c_int) };
    // SAFETY: `pctx` is live and owned here.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    1
}

/// `pkcs7_decrypt_rinfo(unsigned char **pek, int *peklen, PKCS7_RECIP_INFO *ri, EVP_PKEY *pkey,
/// size_t fixlen)` — `pk7_doit.c:188-223`.
///
/// # Safety
/// `pek`/`peklen` are writable; `ri` and `pkey` are live.
unsafe fn pkcs7_decrypt_rinfo(
    pek: *mut *mut u8,
    peklen: *mut c_int,
    ri: *mut Pkcs7RecipInfo,
    pkey: *mut EvpPkey,
    fixlen: usize,
) -> c_int {
    // SAFETY: `ri` is live.
    let ctx = unsafe { (*ri).ctx };
    // SAFETY: `pkey` is live; `ctx` is the recipient's borrow.
    let pctx = unsafe {
        EVP_PKEY_CTX_new_from_pkey(
            ossl_pkcs7_ctx_get0_libctx(ctx),
            pkey,
            ossl_pkcs7_ctx_get0_propq(ctx),
        )
    };
    if pctx.is_null() {
        return -1;
    }
    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_decrypt_init(pctx) } <= 0 {
        // SAFETY: `pctx` is live and owned here.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        return -1;
    }
    let mut ek: *mut u8 = ptr::null_mut();
    let mut eklen: usize = 0;
    // SAFETY: `ri` is live; its `enc_key` is the ciphertext.
    let ret = unsafe {
        evp_pkey_decrypt_alloc(
            pctx,
            &mut ek,
            &mut eklen,
            fixlen,
            (*ri)
                .enc_key
                .cast::<Asn1String>()
                .as_ref()
                .map_or(ptr::null(), |s| s.data),
            (*ri).enc_key.as_ref().map_or(0, |s| s.length as usize),
        )
    };
    if ret <= 0 {
        // SAFETY: `pctx` is live and owned here.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        if ret == 0 {
            // `evp_pkey_decrypt_alloc` frees on failure; nothing to release.
        }
        return -1;
    }
    // SAFETY: `pek`/`peklen` are writable; the old buffer is the caller's.
    unsafe {
        CRYPTO_clear_free((*pek).cast(), *peklen as usize, FILE.as_ptr(), 213);
        *pek = ek;
        *peklen = eklen as c_int;
        EVP_PKEY_CTX_free(pctx);
    }
    1
}

/// `BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio)` — `pk7_doit.c:225-416`.
///
/// # Safety
/// `p7` is live; `bio` is null or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_dataInit(p7: *mut Pkcs7, bio: *mut Bio) -> *mut Bio {
    if p7.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_243) };
        return ptr::null_mut();
    }
    // SAFETY: `p7` is live.
    let p7_ctx = unsafe { ossl_pkcs7_get0_ctx(p7) };
    // SAFETY: `p7_ctx` is live.
    let libctx = unsafe { ossl_pkcs7_ctx_get0_libctx(p7_ctx) };
    // SAFETY: `p7_ctx` is live.
    let propq = unsafe { ossl_pkcs7_ctx_get0_propq(p7_ctx) };

    // SAFETY: `p7` is live.
    if unsafe { (*p7).d.ptr }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_261) };
        return ptr::null_mut();
    }

    let mut out: *mut Bio = ptr::null_mut();
    let btmp: *mut Bio;
    let mut xa: *mut crate::asn1::x_algor::X509Algor = ptr::null_mut();
    let fetched_cipher: *mut EvpCipher;
    let cipher: *const EvpCipher;
    let mut evp_cipher: *const EvpCipher = ptr::null();
    let mut md_sk: *mut OpenSslStack = ptr::null_mut();
    let mut rsk: *mut OpenSslStack = ptr::null_mut();
    let mut xalg: *mut crate::asn1::x_algor::X509Algor = ptr::null_mut();
    let mut os: *mut Asn1String = ptr::null_mut();
    let mut bio = bio;

    // SAFETY: `p7` is live.
    let i = unsafe { OBJ_obj2nid((*p7).type_) };
    // SAFETY: `p7` is live.
    unsafe { (*p7).state = PKCS7_S_HEADER };

    // SAFETY: `p7` is live.
    let arm_ok = unsafe {
        match i {
            crate::runtime::obj::NID_pkcs7_signed => {
                let sign = (*p7).d.sign;
                md_sk = (*sign).md_algs;
                os = pkcs7_get1_data((*sign).contents);
                1
            }
            crate::runtime::obj::NID_pkcs7_signedAndEnveloped => {
                let se = (*p7).d.signed_and_enveloped;
                rsk = (*se).recipientinfo;
                md_sk = (*se).md_algs;
                xalg = (*(*se).enc_data).algorithm;
                evp_cipher = (*(*se).enc_data).cipher.cast();
                if evp_cipher.is_null() {
                    raise_site(&err_sites::PKCS7_DOIT_279);
                    0
                } else {
                    1
                }
            }
            crate::runtime::obj::NID_pkcs7_enveloped => {
                let env = (*p7).d.enveloped;
                rsk = (*env).recipientinfo;
                xalg = (*(*env).enc_data).algorithm;
                evp_cipher = (*(*env).enc_data).cipher.cast();
                if evp_cipher.is_null() {
                    raise_site(&err_sites::PKCS7_DOIT_288);
                    0
                } else {
                    1
                }
            }
            crate::runtime::obj::NID_pkcs7_digest => {
                xa = (*p7).d.digest.as_ref().map_or(ptr::null_mut(), |d| d.md);
                os = pkcs7_get1_data(
                    (*p7)
                        .d
                        .digest
                        .as_ref()
                        .map_or(ptr::null_mut(), |d| d.contents),
                );
                1
            }
            crate::runtime::obj::NID_pkcs7_data => 1,
            _ => {
                raise_site(&err_sites::PKCS7_DOIT_299);
                0
            }
        }
    };
    if arm_ok == 0 {
        // SAFETY: `os` is null or owned here.
        unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(os) };
        return ptr::null_mut();
    }

    // SAFETY: `md_sk` is null or a live stack.
    let n = unsafe { OPENSSL_sk_num(md_sk) };
    let mut k = 0;
    while k < n {
        // SAFETY: `md_sk` is a live stack and `k` is in range.
        let alg = unsafe { OPENSSL_sk_value(md_sk, k) }.cast::<crate::asn1::x_algor::X509Algor>();
        // SAFETY: `out` is null or live; `alg`/`p7_ctx` are live.
        if unsafe { pkcs7_bio_add_digest(&mut out, alg, p7_ctx) } == 0 {
            // SAFETY: `os` is null or owned here.
            unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(os) };
            return ptr::null_mut();
        }
        k += 1;
    }

    if !xa.is_null() {
        // SAFETY: `out` is null or live; `xa`/`p7_ctx` are live.
        if unsafe { pkcs7_bio_add_digest(&mut out, xa, p7_ctx) } == 0 {
            // SAFETY: `os` is null or owned here.
            unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(os) };
            return ptr::null_mut();
        }
    }

    if !evp_cipher.is_null() {
        let mut key = [0 as c_uchar; EVP_MAX_KEY_LENGTH];
        let mut iv = [0 as c_uchar; EVP_MAX_IV_LENGTH];
        // SAFETY: no preconditions.
        btmp = unsafe { BIO_new(BIO_f_cipher()) };
        if btmp.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_DOIT_317) };
            // SAFETY: `os` is null or owned here.
            unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(os) };
            return ptr::null_mut();
        }
        let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
        // SAFETY: `btmp` is live; `ctx` is writable.
        unsafe { bio_get_cipher_ctx(btmp, &mut ctx) };
        // SAFETY: `evp_cipher` is live.
        let keylen = unsafe { EVP_CIPHER_get_key_length(evp_cipher) };
        // SAFETY: `evp_cipher` is live.
        let ivlen = unsafe { EVP_CIPHER_get_iv_length(evp_cipher) };
        // SAFETY: `xalg`/`evp_cipher` are live.
        unsafe {
            (*xalg).algorithm = crate::runtime::obj::OBJ_nid2obj(EVP_CIPHER_get_type(evp_cipher))
        };
        if ivlen > 0 {
            // SAFETY: `libctx` is the object's; the buffer is `ivlen` bytes.
            if unsafe { RAND_bytes_ex(libctx, iv.as_mut_ptr(), ivlen as usize, 0) } <= 0 {
                // SAFETY: `os` is null or owned here; `btmp` is owned here.
                unsafe {
                    crate::asn1::string::ASN1_OCTET_STRING_free(os);
                    BIO_free_all(btmp);
                }
                return ptr::null_mut();
            }
        }
        // SAFETY: `evp_cipher` is live; `libctx`/`propq` are the object's.
        fetched_cipher =
            unsafe { EVP_CIPHER_fetch(libctx, EVP_CIPHER_get0_name(evp_cipher), propq) };
        cipher = if !fetched_cipher.is_null() {
            fetched_cipher
        } else {
            evp_cipher
        };
        // SAFETY: `ctx`/`cipher` are live.
        if unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null(), 1) }
            <= 0
        {
            // SAFETY: `os`/`fetched_cipher`/`btmp` are owned here.
            unsafe {
                crate::asn1::string::ASN1_OCTET_STRING_free(os);
                EVP_CIPHER_free(fetched_cipher);
                BIO_free_all(btmp);
            }
            return ptr::null_mut();
        }
        // SAFETY: `fetched_cipher` is owned here.
        unsafe { EVP_CIPHER_free(fetched_cipher) };

        // SAFETY: `ctx` is live; the buffer is `keylen` bytes.
        if unsafe { EVP_CIPHER_CTX_rand_key(ctx, key.as_mut_ptr()) } <= 0 {
            // SAFETY: `os`/`btmp` are owned here.
            unsafe {
                crate::asn1::string::ASN1_OCTET_STRING_free(os);
                BIO_free_all(btmp);
            }
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is live.
        if unsafe {
            EVP_CipherInit_ex(
                ctx,
                ptr::null(),
                ptr::null_mut(),
                key.as_ptr(),
                iv.as_ptr(),
                1,
            )
        } <= 0
        {
            // SAFETY: `os`/`btmp` are owned here.
            unsafe {
                crate::asn1::string::ASN1_OCTET_STRING_free(os);
                BIO_free_all(btmp);
            }
            return ptr::null_mut();
        }

        if ivlen > 0 {
            // SAFETY: `xalg` is live.
            unsafe {
                if (*xalg).parameter.is_null() {
                    (*xalg).parameter = crate::asn1::a_type::ASN1_TYPE_new();
                    if (*xalg).parameter.is_null() {
                        crate::asn1::string::ASN1_OCTET_STRING_free(os);
                        BIO_free_all(btmp);
                        return ptr::null_mut();
                    }
                }
            }
            // SAFETY: `ctx`/`xalg` are live.
            if unsafe { EVP_CIPHER_param_to_asn1(ctx, (*xalg).parameter) } <= 0 {
                // SAFETY: `xalg` is live.
                unsafe {
                    crate::asn1::a_type::ASN1_TYPE_free((*xalg).parameter);
                    (*xalg).parameter = ptr::null_mut();
                    crate::asn1::string::ASN1_OCTET_STRING_free(os);
                    BIO_free_all(btmp);
                }
                return ptr::null_mut();
            }
        }

        // SAFETY: `rsk` is null or a live stack.
        let rn = unsafe { OPENSSL_sk_num(rsk) };
        let mut ri_i = 0;
        while ri_i < rn {
            // SAFETY: `rsk` is a live stack and `ri_i` is in range.
            let ri = unsafe { OPENSSL_sk_value(rsk, ri_i) }.cast::<Pkcs7RecipInfo>();
            // SAFETY: `ri` is live; `key` is the random key.
            if unsafe { pkcs7_encode_rinfo(ri, key.as_mut_ptr(), keylen) } <= 0 {
                // SAFETY: `os`/`btmp` are owned here.
                unsafe {
                    crate::asn1::string::ASN1_OCTET_STRING_free(os);
                    BIO_free_all(btmp);
                }
                return ptr::null_mut();
            }
            ri_i += 1;
        }
        // SAFETY: `key` is `keylen` bytes.
        unsafe { OPENSSL_cleanse(key.as_mut_ptr().cast(), keylen as usize) };

        if out.is_null() {
            out = btmp;
        } else {
            // SAFETY: `out`/`btmp` are live.
            unsafe { BIO_push(out, btmp) };
        }
    }

    if bio.is_null() {
        // SAFETY: `p7` is live.
        if pkcs7_is_detached(p7) {
            // SAFETY: no preconditions.
            bio = unsafe { BIO_new(BIO_s_null()) };
        } else if !os.is_null()
            // SAFETY: `os` is live.
            && unsafe { (*os).length } > 0
        {
            // SAFETY: no preconditions.
            bio = unsafe { BIO_new(BIO_s_mem()) };
            if !bio.is_null() {
                // SAFETY: `bio` is live.
                unsafe {
                    bio_set_mem_eof_return(bio, 0);
                    if BIO_write(bio, (*os).data.cast(), (*os).length) != (*os).length {
                        BIO_free_all(bio);
                        bio = ptr::null_mut();
                    }
                }
            }
        } else {
            // SAFETY: no preconditions.
            bio = unsafe { BIO_new(BIO_s_mem()) };
            if bio.is_null() {
                // SAFETY: `os` is null or owned here.
                unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(os) };
                return ptr::null_mut();
            }
            // SAFETY: `bio` is live.
            unsafe { bio_set_mem_eof_return(bio, 0) };
        }
        if bio.is_null() {
            // SAFETY: `os` is null or owned here.
            unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(os) };
            return ptr::null_mut();
        }
    }
    // SAFETY: `out` is null or live; `bio` is live.
    if !out.is_null() {
        // SAFETY: `out`/`bio` are live.
        unsafe { BIO_push(out, bio) };
    } else {
        out = bio;
    }

    // SAFETY: `os` is null or owned here.
    unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(os) };
    out
}

/// `pkcs7_cmp_ri(PKCS7_RECIP_INFO *ri, X509 *pcert)` — `pk7_doit.c:418-427`.
///
/// # Safety
/// `ri` and `pcert` are live.
unsafe fn pkcs7_cmp_ri(ri: *mut Pkcs7RecipInfo, pcert: *const X509) -> c_int {
    // SAFETY: `ri`/`pcert` are live.
    let ret = unsafe {
        crate::x509::x509_cmp::X509_NAME_cmp(
            (*(*ri).issuer_and_serial).issuer,
            crate::x509::x509_cmp::X509_get_issuer_name(pcert),
        )
    };
    if ret != 0 {
        return ret;
    }
    // SAFETY: `ri`/`pcert` are live.
    unsafe {
        crate::asn1::prim::ASN1_INTEGER_cmp(
            crate::x509::x509_cmp::X509_get0_serialNumber(pcert),
            (*(*ri).issuer_and_serial).serial,
        )
    }
}

/// `BIO *PKCS7_dataDecode(PKCS7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert)` —
/// `pk7_doit.c:430-711`.
///
/// # Safety
/// `p7` is live; `pkey`/`in_bio`/`pcert` are null or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_dataDecode(
    p7: *mut Pkcs7,
    pkey: *mut EvpPkey,
    in_bio: *mut Bio,
    pcert: *mut X509,
) -> *mut Bio {
    if p7.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_453) };
        return ptr::null_mut();
    }
    // SAFETY: `p7` is live.
    let p7_ctx = unsafe { ossl_pkcs7_get0_ctx(p7) };
    // SAFETY: `p7_ctx` is live.
    let libctx = unsafe { ossl_pkcs7_ctx_get0_libctx(p7_ctx) };
    // SAFETY: `p7_ctx` is live.
    let propq = unsafe { ossl_pkcs7_ctx_get0_propq(p7_ctx) };

    // SAFETY: `p7` is live.
    if unsafe { (*p7).d.ptr }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_462) };
        return ptr::null_mut();
    }

    let mut out: *mut Bio = ptr::null_mut();
    let mut btmp: *mut Bio;
    let etmp: *mut Bio;
    let bio: *mut Bio;
    let mut data_body: *mut Asn1String = ptr::null_mut();
    let mut evp_cipher: *mut EvpCipher = ptr::null_mut();
    let mut cipher: *const EvpCipher = ptr::null();
    let mut enc_alg: *mut crate::asn1::x_algor::X509Algor = ptr::null_mut();
    let mut md_sk: *mut OpenSslStack = ptr::null_mut();
    let mut rsk: *mut OpenSslStack = ptr::null_mut();
    let mut ek: *mut u8 = ptr::null_mut();
    let mut tkey: *mut u8;
    let mut eklen: c_int = 0;
    let tkeylen: c_int;
    let mut name = [0 as c_char; OSSL_MAX_NAME_SIZE];

    // SAFETY: `p7` is live.
    let i = unsafe { OBJ_obj2nid((*p7).type_) };
    // SAFETY: `p7` is live.
    unsafe { (*p7).state = PKCS7_S_HEADER };

    // SAFETY: `p7` is live.
    let arm_ok = unsafe {
        match i {
            crate::runtime::obj::NID_pkcs7_signed => {
                let sign = (*p7).d.sign;
                data_body = PKCS7_get_octet_string((*sign).contents);
                if !pkcs7_is_detached(p7) && data_body.is_null() {
                    raise_site(&err_sites::PKCS7_DOIT_479);
                    0
                } else {
                    md_sk = (*sign).md_algs;
                    1
                }
            }
            crate::runtime::obj::NID_pkcs7_signedAndEnveloped => {
                let se = (*p7).d.signed_and_enveloped;
                rsk = (*se).recipientinfo;
                md_sk = (*se).md_algs;
                data_body = (*(*se).enc_data).enc_data;
                enc_alg = (*(*se).enc_data).algorithm;
                OBJ_obj2txt(
                    name.as_mut_ptr(),
                    OSSL_MAX_NAME_SIZE as c_int,
                    (*enc_alg).algorithm,
                    0,
                );
                evp_cipher = EVP_CIPHER_fetch(libctx, name.as_ptr(), propq);
                cipher = if !evp_cipher.is_null() {
                    evp_cipher
                } else {
                    EVP_get_cipherbyname(name.as_ptr())
                };
                if cipher.is_null() {
                    raise_site(&err_sites::PKCS7_DOIT_502);
                    0
                } else {
                    1
                }
            }
            crate::runtime::obj::NID_pkcs7_enveloped => {
                let env = (*p7).d.enveloped;
                rsk = (*env).recipientinfo;
                enc_alg = (*(*env).enc_data).algorithm;
                data_body = (*(*env).enc_data).enc_data;
                OBJ_obj2txt(
                    name.as_mut_ptr(),
                    OSSL_MAX_NAME_SIZE as c_int,
                    (*enc_alg).algorithm,
                    0,
                );
                evp_cipher = EVP_CIPHER_fetch(libctx, name.as_ptr(), propq);
                cipher = if !evp_cipher.is_null() {
                    evp_cipher
                } else {
                    EVP_get_cipherbyname(name.as_ptr())
                };
                if cipher.is_null() {
                    raise_site(&err_sites::PKCS7_DOIT_523);
                    0
                } else {
                    1
                }
            }
            _ => {
                raise_site(&err_sites::PKCS7_DOIT_529);
                0
            }
        }
    };
    if arm_ok == 0 {
        // SAFETY: `evp_cipher` is null or owned here.
        unsafe { EVP_CIPHER_free(evp_cipher) };
        return ptr::null_mut();
    }

    if data_body.is_null() && in_bio.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_535) };
        // SAFETY: `evp_cipher` is null or owned here.
        unsafe { EVP_CIPHER_free(evp_cipher) };
        return ptr::null_mut();
    }

    if !md_sk.is_null() {
        // SAFETY: `md_sk` is a live stack.
        let n = unsafe { OPENSSL_sk_num(md_sk) };
        let mut k = 0;
        while k < n {
            // SAFETY: `md_sk` is a live stack and `k` is in range.
            let xa =
                unsafe { OPENSSL_sk_value(md_sk, k) }.cast::<crate::asn1::x_algor::X509Algor>();
            // SAFETY: no preconditions.
            btmp = unsafe { BIO_new(BIO_f_md()) };
            if btmp.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS7_DOIT_544) };
                // SAFETY: `evp_cipher`/`out` are owned here.
                unsafe {
                    EVP_CIPHER_free(evp_cipher);
                    BIO_free_all(out);
                }
                return ptr::null_mut();
            }
            // SAFETY: `xa` is live.
            unsafe {
                OBJ_obj2txt(
                    name.as_mut_ptr(),
                    OSSL_MAX_NAME_SIZE as c_int,
                    (*xa).algorithm,
                    0,
                )
            };
            // SAFETY: `libctx`/`propq` are the object's; `name` is NUL-terminated.
            let fetched = unsafe { EVP_MD_fetch(libctx, name.as_ptr(), propq) };
            let md: *const EvpMd = if !fetched.is_null() {
                fetched
            } else {
                // SAFETY: `name` is NUL-terminated.
                unsafe { EVP_get_digestbyname(name.as_ptr()) }
            };
            if md.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS7_DOIT_559) };
                // SAFETY: `evp_cipher`/`out`/`btmp` are owned here.
                unsafe {
                    EVP_CIPHER_free(evp_cipher);
                    BIO_free_all(out);
                    BIO_free_all(btmp);
                }
                return ptr::null_mut();
            }
            // SAFETY: `btmp`/`md` are live.
            if unsafe { bio_set_md(btmp, md) } <= 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS7_DOIT_566) };
                // SAFETY: `fetched`/`out`/`btmp` are owned here.
                unsafe {
                    EVP_MD_free(fetched);
                    EVP_CIPHER_free(evp_cipher);
                    BIO_free_all(out);
                    BIO_free_all(btmp);
                }
                return ptr::null_mut();
            }
            // SAFETY: `fetched` is null or owned here.
            unsafe { EVP_MD_free(fetched) };
            if out.is_null() {
                out = btmp;
            } else {
                // SAFETY: `out`/`btmp` are live.
                unsafe { BIO_push(out, btmp) };
            }
            k += 1;
        }
    }

    if !cipher.is_null() {
        // SAFETY: no preconditions.
        etmp = unsafe { BIO_new(BIO_f_cipher()) };
        if etmp.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_DOIT_580) };
            // SAFETY: `evp_cipher`/`out` are owned here.
            unsafe {
                EVP_CIPHER_free(evp_cipher);
                BIO_free_all(out);
            }
            return ptr::null_mut();
        }

        let mut rmatch: *mut Pkcs7RecipInfo = ptr::null_mut();
        if !pcert.is_null() {
            // SAFETY: `rsk` is a live stack.
            let n = unsafe { OPENSSL_sk_num(rsk) };
            let mut k = 0;
            while k < n {
                // SAFETY: `rsk` is a live stack and `k` is in range.
                let ri = unsafe { OPENSSL_sk_value(rsk, k) }.cast::<Pkcs7RecipInfo>();
                // SAFETY: `ri`/`pcert` are live.
                if unsafe { pkcs7_cmp_ri(ri, pcert) } == 0 {
                    rmatch = ri;
                    break;
                }
                rmatch = ptr::null_mut();
                k += 1;
            }
            if rmatch.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS7_DOIT_602) };
                // SAFETY: `evp_cipher`/`out`/`etmp` are owned here.
                unsafe {
                    EVP_CIPHER_free(evp_cipher);
                    BIO_free_all(out);
                    BIO_free_all(etmp);
                }
                return ptr::null_mut();
            }
        }

        if pcert.is_null() {
            // SAFETY: `rsk` is a live stack.
            let n = unsafe { OPENSSL_sk_num(rsk) };
            let mut k = 0;
            while k < n {
                // SAFETY: `rsk` is a live stack and `k` is in range.
                let ri = unsafe { OPENSSL_sk_value(rsk, k) }.cast::<Pkcs7RecipInfo>();
                // SAFETY: `ri` is live.
                unsafe { (*ri).ctx = p7_ctx };
                // SAFETY: `ri`/`pkey` are live; `cipher` gives the fixed length.
                let r = unsafe {
                    pkcs7_decrypt_rinfo(
                        &mut ek,
                        &mut eklen,
                        ri,
                        pkey,
                        EVP_CIPHER_get_key_length(cipher) as usize,
                    )
                };
                if r < 0 {
                    // SAFETY: `ek`/`evp_cipher`/`out`/`etmp` are owned here.
                    unsafe {
                        CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 620);
                        EVP_CIPHER_free(evp_cipher);
                        BIO_free_all(out);
                        BIO_free_all(etmp);
                    }
                    return ptr::null_mut();
                }
                crate::runtime::err::ERR_clear_error();
                k += 1;
            }
        } else {
            // SAFETY: `rmatch` is live.
            unsafe { (*rmatch).ctx = p7_ctx };
            // SAFETY: `rmatch`/`pkey` are live.
            let r = unsafe { pkcs7_decrypt_rinfo(&mut ek, &mut eklen, rmatch, pkey, 0) };
            if r < 0 {
                // SAFETY: `ek`/`evp_cipher`/`out`/`etmp` are owned here.
                unsafe {
                    CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 627);
                    EVP_CIPHER_free(evp_cipher);
                    BIO_free_all(out);
                    BIO_free_all(etmp);
                }
                return ptr::null_mut();
            }
            crate::runtime::err::ERR_clear_error();
        }

        let mut evp_ctx: *mut EvpCipherCtx = ptr::null_mut();
        // SAFETY: `etmp` is live; `evp_ctx` is writable.
        unsafe { bio_get_cipher_ctx(etmp, &mut evp_ctx) };
        // SAFETY: `evp_ctx`/`cipher` are live.
        if unsafe {
            EVP_CipherInit_ex(
                evp_ctx,
                cipher,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                0,
            )
        } <= 0
        {
            // SAFETY: `ek`/`evp_cipher`/`out`/`etmp` are owned here.
            unsafe {
                CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 633);
                EVP_CIPHER_free(evp_cipher);
                BIO_free_all(out);
                BIO_free_all(etmp);
            }
            return ptr::null_mut();
        }
        // SAFETY: `evp_ctx`/`enc_alg` are live.
        if unsafe { EVP_CIPHER_asn1_to_param(evp_ctx, (*enc_alg).parameter) } <= 0 {
            // SAFETY: `ek`/`evp_cipher`/`out`/`etmp` are owned here.
            unsafe {
                CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 635);
                EVP_CIPHER_free(evp_cipher);
                BIO_free_all(out);
                BIO_free_all(etmp);
            }
            return ptr::null_mut();
        }
        // SAFETY: `evp_ctx` is live.
        let len = unsafe { EVP_CIPHER_CTX_get_key_length(evp_ctx) };
        if len <= 0 {
            // SAFETY: `ek`/`evp_cipher`/`out`/`etmp` are owned here.
            unsafe {
                CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 639);
                EVP_CIPHER_free(evp_cipher);
                BIO_free_all(out);
                BIO_free_all(etmp);
            }
            return ptr::null_mut();
        }
        tkeylen = len;
        // SAFETY: no preconditions.
        tkey = CRYPTO_malloc(tkeylen as usize, FILE.as_ptr(), 642).cast::<u8>();
        if tkey.is_null() {
            // SAFETY: `ek`/`evp_cipher`/`out`/`etmp` are owned here.
            unsafe {
                CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 643);
                EVP_CIPHER_free(evp_cipher);
                BIO_free_all(out);
                BIO_free_all(etmp);
            }
            return ptr::null_mut();
        }
        // SAFETY: `evp_ctx`/`tkey` are live.
        if unsafe { EVP_CIPHER_CTX_rand_key(evp_ctx, tkey) } <= 0 {
            // SAFETY: `ek`/`tkey`/`evp_cipher`/`out`/`etmp` are owned here.
            unsafe {
                CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 645);
                CRYPTO_clear_free(tkey.cast(), tkeylen as usize, FILE.as_ptr(), 645);
                EVP_CIPHER_free(evp_cipher);
                BIO_free_all(out);
                BIO_free_all(etmp);
            }
            return ptr::null_mut();
        }
        if ek.is_null() {
            ek = tkey;
            eklen = tkeylen;
            tkey = ptr::null_mut();
        }

        // SAFETY: `evp_ctx` is live.
        let cur_key_len = unsafe { EVP_CIPHER_CTX_get_key_length(evp_ctx) };
        if eklen != cur_key_len {
            // SAFETY: `evp_ctx` is live.
            if unsafe { EVP_CIPHER_CTX_set_key_length(evp_ctx, eklen) } <= 0 {
                // SAFETY: `ek` is owned here; `tkey` is owned here.
                unsafe {
                    CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 661);
                    ek = tkey;
                    eklen = tkeylen;
                    tkey = ptr::null_mut();
                }
            }
        }
        crate::runtime::err::ERR_clear_error();
        // SAFETY: `evp_ctx`/`ek` are live.
        if unsafe { EVP_CipherInit_ex(evp_ctx, ptr::null(), ptr::null_mut(), ek, ptr::null(), 0) }
            <= 0
        {
            // SAFETY: `ek`/`tkey`/`evp_cipher`/`out`/`etmp` are owned here.
            unsafe {
                CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 669);
                CRYPTO_clear_free(tkey.cast(), tkeylen as usize, FILE.as_ptr(), 669);
                EVP_CIPHER_free(evp_cipher);
                BIO_free_all(out);
                BIO_free_all(etmp);
            }
            return ptr::null_mut();
        }
        // SAFETY: `ek`/`tkey` are owned here.
        unsafe {
            CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 672);
            ek = ptr::null_mut();
            CRYPTO_clear_free(tkey.cast(), tkeylen as usize, FILE.as_ptr(), 674);
        }

        if out.is_null() {
            out = etmp;
        } else {
            // SAFETY: `out`/`etmp` are live.
            unsafe { BIO_push(out, etmp) };
        }
    }

    if !in_bio.is_null() {
        bio = in_bio;
    } else {
        // SAFETY: `data_body` is live on this arm.
        if unsafe { (*data_body).length } > 0 {
            // SAFETY: `data_body` is live.
            bio = unsafe { BIO_new_mem_buf((*data_body).data.cast(), (*data_body).length) };
        } else {
            // SAFETY: no preconditions.
            bio = unsafe { BIO_new(BIO_s_mem()) };
            if bio.is_null() {
                // SAFETY: `ek`/`evp_cipher`/`out` are owned here.
                unsafe {
                    CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 691);
                    EVP_CIPHER_free(evp_cipher);
                    BIO_free_all(out);
                }
                return ptr::null_mut();
            }
            // SAFETY: `bio` is live.
            unsafe { bio_set_mem_eof_return(bio, 0) };
        }
        if bio.is_null() {
            // SAFETY: `ek`/`evp_cipher`/`out` are owned here.
            unsafe {
                CRYPTO_clear_free(ek.cast(), eklen as usize, FILE.as_ptr(), 694);
                EVP_CIPHER_free(evp_cipher);
                BIO_free_all(out);
            }
            return ptr::null_mut();
        }
    }
    // SAFETY: `out` is live and `bio` is live.
    unsafe { BIO_push(out, bio) };
    // SAFETY: `evp_cipher` is null or owned here.
    unsafe { EVP_CIPHER_free(evp_cipher) };
    out
}

/// `PKCS7_find_digest(EVP_MD_CTX **pmd, BIO *bio, int nid)` — `pk7_doit.c:713-731`.
///
/// # Safety
/// `pmd` is writable; `bio` is a live chain.
unsafe fn pkcs7_find_digest(pmd: *mut *mut EvpMdCtx, bio: *mut Bio, nid: c_int) -> *mut Bio {
    let mut bio = bio;
    loop {
        // SAFETY: `bio` is a live chain.
        bio = unsafe { BIO_find_type(bio, BIO_TYPE_MD) };
        if bio.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_DOIT_718) };
            return ptr::null_mut();
        }
        // SAFETY: `bio` is live; `pmd` is writable.
        unsafe { bio_get_md_ctx(bio, pmd) };
        // SAFETY: `pmd` is writable.
        if unsafe { *pmd }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_DOIT_723) };
            return ptr::null_mut();
        }
        // SAFETY: `*pmd` is live.
        let md = unsafe { EVP_MD_CTX_get0_md(*pmd) };
        // SAFETY: `md` is live.
        if unsafe { EVP_MD_get_type(md) } == nid {
            return bio;
        }
        // SAFETY: `bio` is live.
        bio = unsafe { BIO_next(bio) };
    }
}

/// `do_pkcs7_signed_attrib(PKCS7_SIGNER_INFO *si, EVP_MD_CTX *mctx)` — `pk7_doit.c:733-761`.
///
/// # Safety
/// `si` and `mctx` are live.
unsafe fn do_pkcs7_signed_attrib(si: *mut Pkcs7SignerInfo, mctx: *mut EvpMdCtx) -> c_int {
    let mut md_data = [0 as c_uchar; EVP_MAX_MD_SIZE];
    let mut md_len: c_uint = 0;
    // SAFETY: `si` is live.
    if unsafe { PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime) }.is_null() {
        // SAFETY: `si` is live.
        if unsafe { PKCS7_add0_attrib_signing_time(si, ptr::null_mut()) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_DOIT_741) };
            return 0;
        }
    }
    // SAFETY: `mctx` is live; the buffer is writable.
    if unsafe { EVP_DigestFinal_ex(mctx, md_data.as_mut_ptr(), &mut md_len) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_748) };
        return 0;
    }
    // SAFETY: `si` is live; `md_data`/`md_len` describe the digest.
    if unsafe { PKCS7_add1_attrib_digest(si, md_data.as_ptr(), md_len as c_int) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_752) };
        return 0;
    }
    // SAFETY: `si` is live.
    unsafe { PKCS7_SIGNER_INFO_sign(si) }
}

/// `int PKCS7_dataFinal(PKCS7 *p7, BIO *bio)` — `pk7_doit.c:763-947`.
///
/// # Safety
/// `p7`/`bio` are live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_dataFinal(p7: *mut Pkcs7, bio: *mut Bio) -> c_int {
    if p7.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_776) };
        return 0;
    }
    // SAFETY: `p7` is live.
    let p7_ctx = unsafe { ossl_pkcs7_get0_ctx(p7) };
    // SAFETY: `p7` is live.
    if unsafe { (*p7).d.ptr }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_783) };
        return 0;
    }
    let ctx_tmp = EVP_MD_CTX_new();
    if ctx_tmp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_789) };
        return 0;
    }

    // SAFETY: `p7` is live.
    let i = unsafe { OBJ_obj2nid((*p7).type_) };
    // SAFETY: `p7` is live.
    unsafe { (*p7).state = PKCS7_S_HEADER };

    let mut si_sk: *mut OpenSslStack = ptr::null_mut();
    let mut os: *mut Asn1String = ptr::null_mut();
    // SAFETY: `p7` is live.
    let prep_ok = unsafe {
        match i {
            crate::runtime::obj::NID_pkcs7_data => {
                os = (*p7).d.data;
                1
            }
            crate::runtime::obj::NID_pkcs7_signedAndEnveloped => {
                let se = (*p7).d.signed_and_enveloped;
                si_sk = (*se).signer_info;
                os = (*(*se).enc_data).enc_data;
                if os.is_null() {
                    os = ASN1_OCTET_STRING_new();
                    if os.is_null() {
                        raise_site(&err_sites::PKCS7_DOIT_807);
                        0
                    } else {
                        (*(*se).enc_data).enc_data = os;
                        1
                    }
                } else {
                    1
                }
            }
            crate::runtime::obj::NID_pkcs7_enveloped => {
                let env = (*p7).d.enveloped;
                os = (*(*env).enc_data).enc_data;
                if os.is_null() {
                    os = ASN1_OCTET_STRING_new();
                    if os.is_null() {
                        raise_site(&err_sites::PKCS7_DOIT_819);
                        0
                    } else {
                        (*(*env).enc_data).enc_data = os;
                        1
                    }
                } else {
                    1
                }
            }
            crate::runtime::obj::NID_pkcs7_signed => {
                let sign = (*p7).d.sign;
                si_sk = (*sign).signer_info;
                if (*sign).contents.is_null() {
                    raise_site(&err_sites::PKCS7_DOIT_828);
                    0
                } else {
                    os = PKCS7_get_octet_string((*sign).contents);
                    if pkcs7_type_is_data((*sign).contents) && (*p7).detached != 0 {
                        crate::asn1::string::ASN1_OCTET_STRING_free(os);
                        os = ptr::null_mut();
                        (*(*sign).contents).d.data = ptr::null_mut();
                    }
                    1
                }
            }
            crate::runtime::obj::NID_pkcs7_digest => {
                let digest = (*p7).d.digest;
                if (*digest).contents.is_null() {
                    raise_site(&err_sites::PKCS7_DOIT_842);
                    0
                } else {
                    os = PKCS7_get_octet_string((*digest).contents);
                    if pkcs7_type_is_data((*digest).contents) && (*p7).detached != 0 {
                        crate::asn1::string::ASN1_OCTET_STRING_free(os);
                        os = ptr::null_mut();
                        (*(*digest).contents).d.data = ptr::null_mut();
                    }
                    1
                }
            }
            _ => {
                raise_site(&err_sites::PKCS7_DOIT_855);
                0
            }
        }
    };
    if prep_ok == 0 {
        // SAFETY: `ctx_tmp` is live and owned here.
        unsafe { EVP_MD_CTX_free(ctx_tmp) };
        return 0;
    }

    if !si_sk.is_null() {
        // SAFETY: `si_sk` is a live stack.
        let n = unsafe { OPENSSL_sk_num(si_sk) };
        let mut k = 0;
        while k < n {
            // SAFETY: `si_sk` is a live stack and `k` is in range.
            let si = unsafe { OPENSSL_sk_value(si_sk, k) }.cast::<Pkcs7SignerInfo>();
            // SAFETY: `si` is live.
            if unsafe { (*si).pkey }.is_null() {
                k += 1;
                continue;
            }
            // SAFETY: `si` is live.
            let j = unsafe { OBJ_obj2nid((*(*si).digest_alg).algorithm) };
            let mut mdc: *mut EvpMdCtx = ptr::null_mut();
            // SAFETY: `bio` is a live chain; `mdc` is writable.
            let btmp = unsafe { pkcs7_find_digest(&mut mdc, bio, j) };
            if btmp.is_null() {
                // SAFETY: `ctx_tmp` is live and owned here.
                unsafe { EVP_MD_CTX_free(ctx_tmp) };
                return 0;
            }
            // SAFETY: `ctx_tmp`/`mdc` are live.
            if unsafe { EVP_MD_CTX_copy_ex(ctx_tmp, mdc) } == 0 {
                // SAFETY: `ctx_tmp` is live and owned here.
                unsafe { EVP_MD_CTX_free(ctx_tmp) };
                return 0;
            }
            // SAFETY: `si` is live.
            let sk = unsafe { (*si).auth_attr };
            // SAFETY: `sk` is null or a live stack.
            if unsafe { OPENSSL_sk_num(sk) } > 0 {
                // SAFETY: `si`/`ctx_tmp` are live.
                if unsafe { do_pkcs7_signed_attrib(si, ctx_tmp) } == 0 {
                    // SAFETY: `ctx_tmp` is live and owned here.
                    unsafe { EVP_MD_CTX_free(ctx_tmp) };
                    return 0;
                }
            } else {
                // SAFETY: `si` is live.
                let abuflen0 = unsafe { EVP_PKEY_get_size((*si).pkey) };
                if abuflen0 == 0 {
                    // SAFETY: `ctx_tmp` is live and owned here.
                    unsafe { EVP_MD_CTX_free(ctx_tmp) };
                    return 0;
                }
                let mut abuflen: c_uint = abuflen0 as c_uint;
                // SAFETY: no preconditions.
                let abuf = CRYPTO_malloc(abuflen as usize, FILE.as_ptr(), 893).cast::<c_uchar>();
                if abuf.is_null() {
                    // SAFETY: `ctx_tmp` is live and owned here.
                    unsafe { EVP_MD_CTX_free(ctx_tmp) };
                    return 0;
                }
                // SAFETY: `ctx_tmp`/`abuf`/`si` are live.
                let ok = unsafe {
                    EVP_SignFinal_ex(
                        ctx_tmp,
                        abuf,
                        &mut abuflen,
                        (*si).pkey,
                        ossl_pkcs7_ctx_get0_libctx(p7_ctx),
                        ossl_pkcs7_ctx_get0_propq(p7_ctx),
                    )
                };
                if ok == 0 {
                    // SAFETY: `abuf`/`ctx_tmp` are owned here.
                    unsafe {
                        CRYPTO_free(abuf.cast(), FILE.as_ptr(), 900);
                        raise_site(&err_sites::PKCS7_DOIT_900);
                        EVP_MD_CTX_free(ctx_tmp);
                    }
                    return 0;
                }
                // SAFETY: `si` is live; `abuf` is the signature.
                unsafe { ASN1_STRING_set0((*si).enc_digest, abuf.cast(), abuflen as c_int) };
            }
            k += 1;
        }
    } else if i == crate::runtime::obj::NID_pkcs7_digest {
        let mut md_data = [0 as c_uchar; EVP_MAX_MD_SIZE];
        let mut md_len: c_uint = 0;
        // SAFETY: `p7` is live.
        let digest_md = unsafe { (*(*p7).d.digest).md };
        // SAFETY: `digest_md` is live.
        let dg_nid = unsafe { OBJ_obj2nid((*digest_md).algorithm) };
        let mut mdc: *mut EvpMdCtx = ptr::null_mut();
        // SAFETY: `bio` is a live chain; `mdc` is writable.
        if unsafe { pkcs7_find_digest(&mut mdc, bio, dg_nid) }.is_null() {
            // SAFETY: `ctx_tmp` is live and owned here.
            unsafe { EVP_MD_CTX_free(ctx_tmp) };
            return 0;
        }
        // SAFETY: `mdc` is live.
        if unsafe { EVP_DigestFinal_ex(mdc, md_data.as_mut_ptr(), &mut md_len) } == 0 {
            // SAFETY: `ctx_tmp` is live and owned here.
            unsafe { EVP_MD_CTX_free(ctx_tmp) };
            return 0;
        }
        // SAFETY: `p7` is live; the digest slot is live.
        if unsafe {
            ASN1_OCTET_STRING_set((*(*p7).d.digest).digest, md_data.as_ptr(), md_len as c_int)
        } == 0
        {
            // SAFETY: `ctx_tmp` is live and owned here.
            unsafe { EVP_MD_CTX_free(ctx_tmp) };
            return 0;
        }
    }

    if !pkcs7_is_detached(p7) {
        if os.is_null() {
            // SAFETY: `ctx_tmp` is live and owned here.
            unsafe { EVP_MD_CTX_free(ctx_tmp) };
            return 0;
        }
        // SAFETY: `os` is live.
        if (unsafe { (*os).flags } & crate::asn1::layout::ASN1_STRING_FLAG_NDEF) == 0 {
            // SAFETY: `bio` is a live chain.
            let btmp = unsafe { BIO_find_type(bio, BIO_TYPE_MEM) };
            if btmp.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe {
                    raise_site(&err_sites::PKCS7_DOIT_930);
                    EVP_MD_CTX_free(ctx_tmp);
                }
                return 0;
            }
            let mut cont: *mut c_char = ptr::null_mut();
            // SAFETY: `btmp` is a live memory BIO; `cont` is writable.
            let contlen = unsafe { bio_get_mem_data(btmp, &mut cont) };
            // SAFETY: `btmp` is live.
            unsafe { BIO_set_flags(btmp, BIO_FLAGS_MEM_RDONLY) };
            // SAFETY: `btmp` is live.
            unsafe { bio_set_mem_eof_return(btmp, 0) };
            // SAFETY: `os` is live; `cont`/`contlen` describe the bytes.
            unsafe { ASN1_STRING_set0(os, cont.cast(), contlen as c_int) };
        }
    }
    // SAFETY: `ctx_tmp` is live and owned here.
    unsafe { EVP_MD_CTX_free(ctx_tmp) };
    1
}

/// `int PKCS7_SIGNER_INFO_sign(PKCS7_SIGNER_INFO *si)` — `pk7_doit.c:949-1002`.
///
/// # Safety
/// `si` is live with a live private key.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNER_INFO_sign(si: *mut Pkcs7SignerInfo) -> c_int {
    // SAFETY: `si` is live.
    let ctx = unsafe { (*si).ctx };
    // SAFETY: `si` is live; its digest algorithm is live.
    let md_alg = unsafe { (*(*si).digest_alg).algorithm };
    // SAFETY: `md_alg` is live.
    let nid = unsafe { OBJ_obj2nid(md_alg) };
    // SAFETY: `nid` names the digest; the macro is `EVP_get_digestbynid`.
    let md = unsafe { EVP_get_digestbyname(crate::runtime::obj::OBJ_nid2sn(nid)) };
    if md.is_null() {
        return 0;
    }
    let mctx = EVP_MD_CTX_new();
    if mctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_965) };
        return 0;
    }
    let mut pctx: *mut EvpPkeyCtx = ptr::null_mut();
    // SAFETY: `mctx`/`si` are live; the name is the digest's.
    let init = unsafe {
        EVP_DigestSignInit_ex(
            mctx,
            &mut pctx,
            crate::evp::digest::EVP_MD_get0_name(md),
            ossl_pkcs7_ctx_get0_libctx(ctx),
            ossl_pkcs7_ctx_get0_propq(ctx),
            (*si).pkey,
            ptr::null(),
        )
    };
    if init <= 0 {
        // SAFETY: `mctx` is live and owned here.
        unsafe { EVP_MD_CTX_free(mctx) };
        return 0;
    }
    let mut abuf: *mut c_uchar = ptr::null_mut();
    // SAFETY: `si` is live; `abuf` is an out-cursor.
    let alen = unsafe { ASN1_item_i2d((*si).auth_attr.cast(), &mut abuf, PKCS7_ATTR_SIGN_it()) };
    if alen < 0 || abuf.is_null() {
        // SAFETY: `mctx` is live and owned here.
        unsafe { EVP_MD_CTX_free(mctx) };
        return 0;
    }
    // SAFETY: `mctx`/`abuf` are live.
    if unsafe { EVP_DigestSignUpdate(mctx, abuf.cast(), alen as usize) } <= 0 {
        // SAFETY: `abuf`/`mctx` are owned here.
        unsafe {
            CRYPTO_free(abuf.cast(), FILE.as_ptr(), 982);
            EVP_MD_CTX_free(mctx);
        }
        return 0;
    }
    // SAFETY: `abuf` is owned here.
    unsafe { CRYPTO_free(abuf.cast(), FILE.as_ptr(), 982) };
    let mut siglen: usize = 0;
    // SAFETY: `mctx` is live; the out-pointer is writable.
    if unsafe { EVP_DigestSignFinal(mctx, ptr::null_mut(), &mut siglen) } <= 0 {
        // SAFETY: `mctx` is live and owned here.
        unsafe { EVP_MD_CTX_free(mctx) };
        return 0;
    }
    // SAFETY: no preconditions.
    abuf = CRYPTO_malloc(siglen, FILE.as_ptr(), 986).cast::<c_uchar>();
    if abuf.is_null() {
        // SAFETY: `mctx` is live and owned here.
        unsafe { EVP_MD_CTX_free(mctx) };
        return 0;
    }
    // SAFETY: `mctx`/`abuf` are live.
    if unsafe { EVP_DigestSignFinal(mctx, abuf, &mut siglen) } <= 0 {
        // SAFETY: `abuf`/`mctx` are owned here.
        unsafe {
            CRYPTO_free(abuf.cast(), FILE.as_ptr(), 999);
            EVP_MD_CTX_free(mctx);
        }
        return 0;
    }
    // SAFETY: `mctx` is live and owned here.
    unsafe { EVP_MD_CTX_free(mctx) };
    // SAFETY: `si` is live; `abuf` is the signature.
    unsafe { ASN1_STRING_set0((*si).enc_digest, abuf.cast(), siglen as c_int) };
    1
}

/// `int PKCS7_dataVerify(X509_STORE *cert_store, X509_STORE_CTX *ctx, BIO *bio, PKCS7 *p7,
/// PKCS7_SIGNER_INFO *si)` — `pk7_doit.c:1005-1062`.
///
/// # Safety
/// The store, context, BIO, `p7` and `si` are live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_dataVerify(
    cert_store: *mut X509Store,
    ctx: *mut X509StoreCtx,
    bio: *mut Bio,
    p7: *mut Pkcs7,
    si: *mut Pkcs7SignerInfo,
) -> c_int {
    if p7.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_1015) };
        return 0;
    }
    // SAFETY: `p7` is live.
    if unsafe { (*p7).d.ptr }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_1020) };
        return 0;
    }
    let (untrusted, crls) = if pkcs7_type_is_signed(p7) {
        // SAFETY: `p7` is a live signed structure.
        unsafe { ((*(*p7).d.sign).cert, (*(*p7).d.sign).crl) }
    } else if pkcs7_type_is_signed_and_enveloped(p7) {
        // SAFETY: `p7` is a live signed-and-enveloped structure.
        unsafe {
            (
                (*(*p7).d.signed_and_enveloped).cert,
                (*(*p7).d.signed_and_enveloped).crl,
            )
        }
    } else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_1031) };
        return 0;
    };
    // SAFETY: `ctx` is live.
    unsafe { crate::x509::x509_vfy::X509_STORE_CTX_set0_crls(ctx, crls) };

    // SAFETY: `si` is live.
    let ias = unsafe { (*si).issuer_and_serial };
    // SAFETY: `untrusted`/`ias` are live.
    let signer = unsafe { X509_find_by_issuer_and_serial(untrusted, (*ias).issuer, (*ias).serial) };
    if signer.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_1043) };
        return 0;
    }
    // SAFETY: `ctx`/`cert_store`/`signer`/`untrusted` are live.
    if unsafe { X509_STORE_CTX_init(ctx, cert_store, signer, untrusted) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_1049) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SMIME_SIGN) };
    // SAFETY: `ctx` is live.
    let i = unsafe { X509_verify_cert(ctx) };
    if i <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_1055) };
        return 0;
    }
    // SAFETY: all five are live per the caller's contract.
    unsafe { PKCS7_signatureVerify(bio, p7, si, signer) }
}

/// `int PKCS7_signatureVerify(BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si, X509 *signer)` —
/// `pk7_doit.c:1064-1187`.
///
/// # Safety
/// `bio`, `p7`, `si` and `signer` are live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_signatureVerify(
    bio: *mut Bio,
    p7: *mut Pkcs7,
    si: *mut Pkcs7SignerInfo,
    signer: *mut X509,
) -> c_int {
    let mdc_tmp = EVP_MD_CTX_new();
    if mdc_tmp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_1083) };
        return 0;
    }
    if !pkcs7_type_is_signed(p7) && !pkcs7_type_is_signed_and_enveloped(p7) {
        // SAFETY: a compile-time-constant site.
        unsafe {
            raise_site(&err_sites::PKCS7_DOIT_1088);
            EVP_MD_CTX_free(mdc_tmp);
        }
        return 0;
    }
    // SAFETY: `si` is live.
    let md_type = unsafe { OBJ_obj2nid((*(*si).digest_alg).algorithm) };

    // SAFETY: `p7` is live.
    let ctx = unsafe { ossl_pkcs7_get0_ctx(p7) };
    // SAFETY: `ctx` is live.
    let libctx = unsafe { ossl_pkcs7_ctx_get0_libctx(ctx) };
    // SAFETY: `ctx` is live.
    let propq = unsafe { ossl_pkcs7_ctx_get0_propq(ctx) };

    let mut btmp = bio;
    let mut mdc: *mut EvpMdCtx = ptr::null_mut();
    loop {
        if btmp.is_null() {
            // SAFETY: `mdc_tmp` is live and owned here.
            unsafe {
                raise_site(&err_sites::PKCS7_DOIT_1097);
                EVP_MD_CTX_free(mdc_tmp);
            }
            return 0;
        }
        // SAFETY: `btmp` is a live chain.
        btmp = unsafe { BIO_find_type(btmp, BIO_TYPE_MD) };
        if btmp.is_null() {
            // SAFETY: `mdc_tmp` is live and owned here.
            unsafe {
                raise_site(&err_sites::PKCS7_DOIT_1097);
                EVP_MD_CTX_free(mdc_tmp);
            }
            return 0;
        }
        // SAFETY: `btmp` is live; `mdc` is writable.
        unsafe { bio_get_md_ctx(btmp, &mut mdc) };
        if mdc.is_null() {
            // SAFETY: `mdc_tmp` is live and owned here.
            unsafe {
                raise_site(&err_sites::PKCS7_DOIT_1102);
                EVP_MD_CTX_free(mdc_tmp);
            }
            return 0;
        }
        // SAFETY: `mdc` is live.
        let mdc_md = unsafe { EVP_MD_CTX_get0_md(mdc) };
        // SAFETY: `mdc_md` is live.
        if unsafe { EVP_MD_get_type(mdc_md) } == md_type {
            break;
        }
        // SAFETY: `mdc_md` is live.
        if unsafe { EVP_MD_get_pkey_type(mdc_md) } == md_type {
            break;
        }
        // SAFETY: `btmp` is live.
        btmp = unsafe { BIO_next(btmp) };
    }

    // SAFETY: `mdc_tmp`/`mdc` are live.
    if unsafe { EVP_MD_CTX_copy_ex(mdc_tmp, mdc) } == 0 {
        // SAFETY: `mdc_tmp` is live and owned here.
        unsafe { EVP_MD_CTX_free(mdc_tmp) };
        return 0;
    }

    // SAFETY: `si` is live.
    let sk = unsafe { (*si).auth_attr };
    // SAFETY: `sk` is null or a live stack.
    if !sk.is_null() && unsafe { OPENSSL_sk_num(sk) } != 0 {
        let mut md_dat = [0 as c_uchar; EVP_MAX_MD_SIZE];
        let mut md_len: c_uint = 0;
        // SAFETY: `mdc_tmp` is live.
        if unsafe { EVP_DigestFinal_ex(mdc_tmp, md_dat.as_mut_ptr(), &mut md_len) } == 0 {
            // SAFETY: `mdc_tmp` is live and owned here.
            unsafe { EVP_MD_CTX_free(mdc_tmp) };
            return 0;
        }
        // SAFETY: `sk` is a live stack.
        let message_digest = unsafe { PKCS7_digest_from_attributes(sk) };
        if message_digest.is_null() {
            // SAFETY: `mdc_tmp` is live and owned here.
            unsafe {
                raise_site(&err_sites::PKCS7_DOIT_1134);
                EVP_MD_CTX_free(mdc_tmp);
            }
            return 0;
        }
        // SAFETY: `message_digest` is live.
        let bad = unsafe {
            (*message_digest).length != md_len as c_int
                || memcmp(
                    (*message_digest).data.cast(),
                    md_dat.as_ptr().cast(),
                    md_len as usize,
                ) != 0
        };
        if bad {
            // SAFETY: `mdc_tmp` is live and owned here.
            unsafe {
                raise_site(&err_sites::PKCS7_DOIT_1138);
                EVP_MD_CTX_free(mdc_tmp);
            }
            return -1;
        }

        // SAFETY: `md_type` names the digest; the macro is `EVP_get_digestbynid`.
        let fetched_md =
            unsafe { EVP_MD_fetch(libctx, crate::runtime::obj::OBJ_nid2sn(md_type), propq) };
        let md: *const EvpMd = if !fetched_md.is_null() {
            fetched_md
        } else {
            // SAFETY: `md_type` names the digest.
            unsafe { EVP_get_digestbyname(crate::runtime::obj::OBJ_nid2sn(md_type)) }
        };
        // SAFETY: `mdc_tmp`/`md` are live.
        let vinit = md.is_null() || unsafe { EVP_DigestInit_ex(mdc_tmp, md, ptr::null_mut()) } == 0;
        if vinit {
            // SAFETY: `fetched_md`/`mdc_tmp` are owned here.
            unsafe {
                EVP_MD_free(fetched_md);
                EVP_MD_CTX_free(mdc_tmp);
            }
            return 0;
        }
        let mut abuf: *mut c_uchar = ptr::null_mut();
        // SAFETY: `sk` is live; `abuf` is an out-cursor.
        let alen = unsafe { ASN1_item_i2d(sk.cast(), &mut abuf, PKCS7_ATTR_VERIFY_it()) };
        if alen <= 0 || abuf.is_null() {
            // SAFETY: `fetched_md`/`mdc_tmp` are owned here.
            unsafe {
                raise_site(&err_sites::PKCS7_DOIT_1160);
                EVP_MD_free(fetched_md);
                EVP_MD_CTX_free(mdc_tmp);
            }
            return -1;
        }
        // SAFETY: `mdc_tmp`/`abuf` are live.
        if unsafe { EVP_DigestUpdate(mdc_tmp, abuf.cast(), alen as usize) } == 0 {
            // SAFETY: `abuf`/`fetched_md`/`mdc_tmp` are owned here.
            unsafe {
                CRYPTO_free(abuf.cast(), FILE.as_ptr(), 1164);
                EVP_MD_free(fetched_md);
                EVP_MD_CTX_free(mdc_tmp);
            }
            return 0;
        }
        // SAFETY: `abuf` is owned here.
        unsafe { CRYPTO_free(abuf.cast(), FILE.as_ptr(), 1164) };
        // SAFETY: `fetched_md` is null or owned here.
        unsafe { EVP_MD_free(fetched_md) };
    }

    // SAFETY: `si` is live.
    let os = unsafe { (*si).enc_digest };
    // SAFETY: `signer` is live.
    let pkey = unsafe { X509_get0_pubkey(signer) };
    if pkey.is_null() {
        // SAFETY: `mdc_tmp` is live and owned here.
        unsafe { EVP_MD_CTX_free(mdc_tmp) };
        return -1;
    }
    // SAFETY: `mdc_tmp`/`os`/`pkey` are live.
    let i = unsafe {
        EVP_VerifyFinal_ex(
            mdc_tmp,
            (*os).data,
            (*os).length as c_uint,
            pkey,
            libctx,
            propq,
        )
    };
    // SAFETY: `mdc_tmp` is live and owned here.
    unsafe { EVP_MD_CTX_free(mdc_tmp) };
    if i <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_DOIT_1177) };
        return -1;
    }
    1
}

/// `PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx)` —
/// `pk7_doit.c:1189-1207`.
///
/// # Safety
/// `p7` is live; a non-null answer borrows the recipient info.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_issuer_and_serial(
    p7: *mut Pkcs7,
    idx: c_int,
) -> *mut Pkcs7IssuerAndSerial {
    // SAFETY: `p7` is live.
    let i = unsafe { OBJ_obj2nid((*p7).type_) };
    if i != crate::runtime::obj::NID_pkcs7_signedAndEnveloped {
        return ptr::null_mut();
    }
    // SAFETY: `p7` is live.
    let se = unsafe { (*p7).d.signed_and_enveloped };
    if se.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `se` is live.
    let rsk = unsafe { (*se).recipientinfo };
    if rsk.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `rsk` is a live stack.
    let n = unsafe { OPENSSL_sk_num(rsk) };
    if idx < 0 || n <= idx {
        return ptr::null_mut();
    }
    // SAFETY: `rsk` is a live stack and `idx` is in range.
    let ri = unsafe { OPENSSL_sk_value(rsk, idx) }.cast::<Pkcs7RecipInfo>();
    // SAFETY: `ri` is live.
    unsafe { (*ri).issuer_and_serial }
}

/// `ASN1_TYPE *PKCS7_get_signed_attribute(const PKCS7_SIGNER_INFO *si, int nid)` —
/// `pk7_doit.c:1209-1212`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_signed_attribute(
    si: *const Pkcs7SignerInfo,
    nid: c_int,
) -> *mut Asn1Type {
    // SAFETY: `si` is live.
    unsafe { get_attribute((*si).auth_attr, nid) }
}

/// `ASN1_TYPE *PKCS7_get_attribute(const PKCS7_SIGNER_INFO *si, int nid)` — `pk7_doit.c:1214-1217`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_attribute(
    si: *const Pkcs7SignerInfo,
    nid: c_int,
) -> *mut Asn1Type {
    // SAFETY: `si` is live.
    unsafe { get_attribute((*si).unauth_attr, nid) }
}

/// `get_attribute(const STACK_OF(X509_ATTRIBUTE) *sk, int nid)` — `pk7_doit.c:1219-1226`.
///
/// # Safety
/// `sk` is null or a live stack.
unsafe fn get_attribute(sk: *const OpenSslStack, nid: c_int) -> *mut Asn1Type {
    // SAFETY: `sk` is null or a live stack.
    let idx = unsafe { X509at_get_attr_by_NID(sk, nid, -1) };
    if idx < 0 {
        return ptr::null_mut();
    }
    // SAFETY: `sk` is a live stack and `idx` is in range.
    let attr = unsafe { X509at_get_attr(sk, idx) };
    // SAFETY: `attr` is live.
    unsafe { crate::x509::x509_att::X509_ATTRIBUTE_get0_type(attr, 0) }
}

/// `ASN1_OCTET_STRING *PKCS7_digest_from_attributes(STACK_OF(X509_ATTRIBUTE) *sk)` —
/// `pk7_doit.c:1228-1236`.
///
/// # Safety
/// `sk` is null or a live stack.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_digest_from_attributes(sk: *mut OpenSslStack) -> *mut Asn1String {
    // SAFETY: `sk` is null or a live stack.
    let astype = unsafe { get_attribute(sk, NID_pkcs9_messageDigest) };
    if astype.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `astype` is live.
    if unsafe { (*astype).type_ } != V_ASN1_OCTET_STRING {
        return ptr::null_mut();
    }
    // SAFETY: the union's octet-string member is the digest.
    unsafe { (*astype).value.ptr.cast::<Asn1String>() }
}

/// The `X509_ATTRIBUTE_free` destructor shape `OPENSSL_sk_pop_free`/`_deep_copy` take.
///
/// # Safety
/// `p` is null or an `X509_ATTRIBUTE` this item layer owns.
unsafe extern "C" fn x509_attribute_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_ATTRIBUTE_free(p.cast::<X509Attribute>()) };
}

/// The `X509_ATTRIBUTE_dup` copy shape `OPENSSL_sk_deep_copy` takes.
///
/// # Safety
/// `p` is null or a live `X509_ATTRIBUTE`.
unsafe extern "C" fn x509_attribute_dup_void(p: *const c_void) -> *mut c_void {
    // SAFETY: per this function's contract.
    unsafe { X509_ATTRIBUTE_dup(p.cast::<X509Attribute>()) }.cast()
}

/// `int PKCS7_set_signed_attributes(PKCS7_SIGNER_INFO *p7si, STACK_OF(X509_ATTRIBUTE) *sk)` —
/// `pk7_doit.c:1238-1246`.
///
/// # Safety
/// `p7si` is live; `sk` is null or a live stack.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_signed_attributes(
    p7si: *mut Pkcs7SignerInfo,
    sk: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `p7si` is live.
    unsafe {
        OPENSSL_sk_pop_free((*p7si).auth_attr, Some(x509_attribute_free_void));
        (*p7si).auth_attr = OPENSSL_sk_deep_copy(
            sk,
            Some(x509_attribute_dup_void),
            Some(x509_attribute_free_void),
        );
        if (*p7si).auth_attr.is_null() {
            return 0;
        }
    }
    1
}

/// `int PKCS7_set_attributes(PKCS7_SIGNER_INFO *p7si, STACK_OF(X509_ATTRIBUTE) *sk)` —
/// `pk7_doit.c:1248-1256`.
///
/// # Safety
/// `p7si` is live; `sk` is null or a live stack.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_attributes(
    p7si: *mut Pkcs7SignerInfo,
    sk: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `p7si` is live.
    unsafe {
        OPENSSL_sk_pop_free((*p7si).unauth_attr, Some(x509_attribute_free_void));
        (*p7si).unauth_attr = OPENSSL_sk_deep_copy(
            sk,
            Some(x509_attribute_dup_void),
            Some(x509_attribute_free_void),
        );
        if (*p7si).unauth_attr.is_null() {
            return 0;
        }
    }
    1
}

/// `int PKCS7_add_signed_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int atrtype, void *value)` —
/// `pk7_doit.c:1258-1262`.
///
/// # Safety
/// `p7si` is live; `value` is adopted on success.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_signed_attribute(
    p7si: *mut Pkcs7SignerInfo,
    nid: c_int,
    atrtype: c_int,
    value: *mut c_void,
) -> c_int {
    // SAFETY: `p7si` is live.
    unsafe { add_attribute(ptr::addr_of_mut!((*p7si).auth_attr), nid, atrtype, value) }
}

/// `int PKCS7_add_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int atrtype, void *value)` —
/// `pk7_doit.c:1264-1268`.
///
/// # Safety
/// `p7si` is live; `value` is adopted on success.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_attribute(
    p7si: *mut Pkcs7SignerInfo,
    nid: c_int,
    atrtype: c_int,
    value: *mut c_void,
) -> c_int {
    // SAFETY: `p7si` is live.
    unsafe { add_attribute(ptr::addr_of_mut!((*p7si).unauth_attr), nid, atrtype, value) }
}

/// `add_attribute(STACK_OF(X509_ATTRIBUTE) **sk, int nid, int atrtype, void *value)` —
/// `pk7_doit.c:1270-1299`.
///
/// # Safety
/// `sk` is a live out-pointer; `value` is adopted on success.
unsafe fn add_attribute(
    sk: *mut *mut OpenSslStack,
    nid: c_int,
    atrtype: c_int,
    value: *mut c_void,
) -> c_int {
    // SAFETY: `sk` is a live out-pointer.
    if unsafe { (*sk).is_null() } {
        // SAFETY: no preconditions.
        let fresh = crate::runtime::stack::OPENSSL_sk_new_null();
        // SAFETY: `sk` is writable.
        unsafe { *sk = fresh };
        if fresh.is_null() {
            return 0;
        }
    }
    // SAFETY: `*sk` is a live stack.
    let n = unsafe { OPENSSL_sk_num(*sk) };
    let mut i = 0;
    let mut found = false;
    while i < n {
        // SAFETY: `*sk` is a live stack and `i` is in range.
        let attr = unsafe { OPENSSL_sk_value(*sk, i) }.cast::<X509Attribute>();
        // SAFETY: `attr` is live.
        let obj = unsafe { X509_ATTRIBUTE_get0_object(attr) };
        // SAFETY: `obj` is live.
        if unsafe { OBJ_obj2nid(obj) } == nid {
            found = true;
            break;
        }
        i += 1;
    }
    if !found {
        // SAFETY: `*sk` is a live stack.
        if unsafe { OPENSSL_sk_push(*sk, ptr::null()) } == 0 {
            return 0;
        }
    }
    // SAFETY: `nid` names the attribute; `value` is the caller's.
    let attr = unsafe { crate::x509::x_attrib::X509_ATTRIBUTE_create(nid, atrtype, value) };
    if attr.is_null() {
        if !found {
            // SAFETY: `*sk` is a live stack.
            unsafe { crate::runtime::stack::OPENSSL_sk_pop(*sk) };
        }
        return 0;
    }
    // SAFETY: `*sk` is a live stack and `i` is in range.
    let old = unsafe { OPENSSL_sk_value(*sk, i) }.cast::<X509Attribute>();
    // SAFETY: `old` is null or an attribute in the stack.
    unsafe { X509_ATTRIBUTE_free(old) };
    // SAFETY: `*sk` is a live stack; `attr` is fresh.
    unsafe { OPENSSL_sk_set(*sk, i, attr.cast()) };
    1
}
