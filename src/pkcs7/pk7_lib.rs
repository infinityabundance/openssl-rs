//! `crypto/pkcs7/pk7_lib.c` — the `PKCS7` object layer. Phase 10 landed the PKCS#12 subset
//! (`PKCS7_set_type` for `data`/`digest`/`encrypted` and the five `ossl_pkcs7_*` context
//! helpers); Phase 12.2 lands the remainder: the control, content, signer, certificate,
//! recipient and cipher surface, with `PKCS7_stream` for the streaming callback.
//!
//! ## The one authority arm the crate does not model
//!
//! `PKCS7_SIGNER_INFO_set` (`pk7_lib.c:346-394`) and `PKCS7_RECIP_INFO_set`
//! (`pk7_lib.c:625-677`) end their key-type ladder with a call through the key's
//! `ameth->pkey_ctrl`. The crate's `EVP_PKEY` models the provider path and does not expose the
//! legacy `ameth` table, so for a key that is neither `EC`/`DSA` nor `RSA` the arm raises the
//! authority's own terminal reason (`PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE`,
//! `pk7_lib.c:392`; `PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE`, `pk7_lib.c:652`)
//! rather than calling a method the crate has no handle on. The citation is the arm it stands
//! in for.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::asn1::a_type::ASN1_TYPE_new;
use crate::asn1::prim::{ASN1_INTEGER_dup, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_OCTET_STRING_new};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_free, X509_ALGOR_new, X509_ALGOR_set0};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::pkey::{
    EVP_PKEY_get_default_digest_nid, EVP_PKEY_get_id, EVP_PKEY_is_a, EVP_PKEY_up_ref, EvpPkey,
};
use crate::pkcs7::pk7_asn1::{
    PKCS7_DIGEST_new, PKCS7_ENCRYPT_new, PKCS7_ENVELOPE_new, PKCS7_RECIP_INFO_free,
    PKCS7_RECIP_INFO_new, PKCS7_SIGNED_free, PKCS7_SIGNED_new, PKCS7_SIGNER_INFO_free,
    PKCS7_SIGNER_INFO_new, PKCS7_SIGN_ENVELOPE_new, Pkcs7, Pkcs7Ctx, Pkcs7EncContent,
    Pkcs7RecipInfo, Pkcs7SignerInfo,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::runtime::obj::{
    NID_pkcs7_data, NID_pkcs7_digest, NID_pkcs7_encrypted, NID_pkcs7_enveloped, NID_pkcs7_signed,
    NID_pkcs7_signedAndEnveloped, NID_rsaEncryption, NID_undef, OBJ_cmp, OBJ_dup,
    OBJ_find_sigid_by_algs, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::x509_cmp::{
    ossl_x509_add_cert_new, X509_find_by_issuer_and_serial, X509_get0_pubkey,
    X509_get0_serialNumber, X509_get_issuer_name,
};
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_crl::{X509Crl, X509_CRL_free, X509_CRL_up_ref};
use crate::x509::x_name::X509_NAME_set;
use crate::x509::x_x509::{ossl_x509_set0_libctx, X509};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/pkcs7/pk7_lib.c";

/// `X509_ADD_FLAG_UP_REF` — `include/openssl/x509.h:995`, the word `PKCS7_add_certificate`
/// passes to `ossl_x509_add_cert_new`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;

/// `PKCS7_S_HEADER` — `pkcs7.h.in:147`, the processing state `PKCS7_dataInit`/`_dataFinal` set.
pub(crate) const PKCS7_S_HEADER: c_int = 0;

// ---------------------------------------------------------------------------------------------
// The `PKCS7_type_is_*` macros — `pkcs7.h.in:189-195`.
// ---------------------------------------------------------------------------------------------

/// `PKCS7_type_is_data(a)` — `pkcs7.h.in:194`.
pub(crate) fn pkcs7_type_is_data(p7: *const Pkcs7) -> bool {
    // SAFETY: `p7` is null or live per the caller's contract.
    unsafe { obj_nid_of(p7) == NID_pkcs7_data }
}

/// `PKCS7_type_is_signed(a)` — `pkcs7.h.in:189`.
pub(crate) fn pkcs7_type_is_signed(p7: *const Pkcs7) -> bool {
    // SAFETY: `p7` is null or live per the caller's contract.
    unsafe { obj_nid_of(p7) == NID_pkcs7_signed }
}

/// `PKCS7_type_is_enveloped(a)` — `pkcs7.h.in:191`.
pub(crate) fn pkcs7_type_is_enveloped(p7: *const Pkcs7) -> bool {
    // SAFETY: `p7` is null or live per the caller's contract.
    unsafe { obj_nid_of(p7) == NID_pkcs7_enveloped }
}

/// `PKCS7_type_is_signedAndEnveloped(a)` — `pkcs7.h.in:192`.
pub(crate) fn pkcs7_type_is_signed_and_enveloped(p7: *const Pkcs7) -> bool {
    // SAFETY: `p7` is null or live per the caller's contract.
    unsafe { obj_nid_of(p7) == NID_pkcs7_signedAndEnveloped }
}

/// `PKCS7_type_is_digest(a)` — `pkcs7.h.in:195`.
pub(crate) fn pkcs7_type_is_digest(p7: *const Pkcs7) -> bool {
    // SAFETY: `p7` is null or live per the caller's contract.
    unsafe { obj_nid_of(p7) == NID_pkcs7_digest }
}

/// The `OBJ_obj2nid((a)->type)` every macro above is.
///
/// # Safety
/// `p7` is null or live.
pub(crate) unsafe fn obj_nid_of(p7: *const Pkcs7) -> c_int {
    if p7.is_null() {
        return NID_undef;
    }
    // SAFETY: `p7` is live per the contract.
    unsafe { OBJ_obj2nid((*p7).type_) }
}

/// `PKCS7_get_detached(p)` — `pkcs7.h.in:200`, the detached word through [`PKCS7_ctrl`].
///
/// # Safety
/// `p7` is live.
pub(crate) fn pkcs7_get_detached(p7: *mut Pkcs7) -> bool {
    // SAFETY: `p7` is live per the contract.
    unsafe { PKCS7_ctrl(p7, 2, 0, ptr::null_mut()) != 0 }
}

/// `PKCS7_is_detached(p7)` — `pkcs7.h.in:202`.
///
/// # Safety
/// `p7` is live.
pub(crate) fn pkcs7_is_detached(p7: *mut Pkcs7) -> bool {
    pkcs7_type_is_signed(p7) && pkcs7_get_detached(p7)
}

/// `long PKCS7_ctrl(PKCS7 *p7, int cmd, long larg, char *parg)` — `pk7_lib.c:20-70`.
///
/// The two detached-signature operations and the catch-all refusal. `PKCS7_OP_SET_DETACHED_SIGNATURE`
/// is 1 and `PKCS7_OP_GET_DETACHED_SIGNATURE` is 2 (`pkcs7.h.in:183-184`).
///
/// # Safety
/// `p7` is a live `PKCS7`; `parg` is unused by both commands.
#[allow(non_upper_case_globals)] // the authority's own command names
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ctrl(
    p7: *mut Pkcs7,
    cmd: c_int,
    larg: c_long,
    _parg: *mut c_char,
) -> c_long {
    // SAFETY: `p7` is live per the caller's contract.
    let nid = unsafe { OBJ_obj2nid((*p7).type_) };
    let ret: c_long;
    match cmd {
        1 => {
            if nid == NID_pkcs7_signed {
                // SAFETY: `p7` is live.
                if unsafe { (*p7).d.sign }.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PKCS7_LIB_32) };
                    return 0;
                }
                // SAFETY: `p7` is live and its `d.sign` is non-null on this arm.
                unsafe { (*p7).detached = larg as c_int };
                ret = larg;
                // SAFETY: as above.
                if ret != 0 && pkcs7_type_is_data(unsafe { (*(*p7).d.sign).contents }) {
                    // SAFETY: `contents` is a live `PKCS7` of type `data`.
                    let os = unsafe { (*(*p7).d.sign).contents };
                    let _ = os;
                    // SAFETY: `p7`, its `d.sign` and the nested `contents` are live on this arm.
                    unsafe {
                        let inner = (*p7).d.sign;
                        let contents = (*inner).contents;
                        let data = (*contents).d.data;
                        crate::asn1::string::ASN1_OCTET_STRING_free(data);
                        (*contents).d.data = ptr::null_mut();
                    }
                }
            } else {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS7_LIB_44) };
                ret = 0;
            }
        }
        2 => {
            if nid == NID_pkcs7_signed {
                // SAFETY: `p7` is live.
                let retv = unsafe {
                    if (*p7).d.sign.is_null()
                        || (*(*p7).d.sign).contents.is_null()
                        || (*(*(*p7).d.sign).contents).d.ptr.is_null()
                    {
                        1
                    } else {
                        0
                    }
                };
                ret = retv;
                // SAFETY: `p7` is live.
                unsafe { (*p7).detached = ret as c_int };
            } else {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS7_LIB_59) };
                ret = 0;
            }
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_66) };
            ret = 0;
        }
    }
    ret
}

/// `int PKCS7_content_new(PKCS7 *p7, int type)` — `pk7_lib.c:72-87`.
///
/// # Safety
/// `p7` is a live `PKCS7`.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_content_new(p7: *mut Pkcs7, type_: c_int) -> c_int {
    let ret = crate::pkcs7::pk7_asn1::PKCS7_new();
    if ret.is_null() {
        return 0;
    }
    // SAFETY: `ret` is live and fresh.
    if unsafe { PKCS7_set_type(ret, type_) } == 0 {
        // SAFETY: `ret` is live and owned here.
        unsafe { crate::pkcs7::pk7_asn1::PKCS7_free(ret) };
        return 0;
    }
    // SAFETY: both are live.
    if unsafe { PKCS7_set_content(p7, ret) } == 0 {
        // SAFETY: `ret` is live and owned here.
        unsafe { crate::pkcs7::pk7_asn1::PKCS7_free(ret) };
        return 0;
    }
    1
}

/// `int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data)` — `pk7_lib.c:89-114`.
///
/// # Safety
/// `p7` and `p7_data` are live `PKCS7`s; `p7_data` is adopted.
#[allow(non_upper_case_globals)] // the authority's own `NID_pkcs7_*` spellings
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_content(p7: *mut Pkcs7, p7_data: *mut Pkcs7) -> c_int {
    // SAFETY: `p7` is live.
    let i = unsafe { OBJ_obj2nid((*p7).type_) };
    match i {
        NID_pkcs7_signed => {
            // SAFETY: `p7` is live and its `d.sign` is non-null by the type.
            unsafe {
                let sign = (*p7).d.sign;
                crate::pkcs7::pk7_asn1::PKCS7_free((*sign).contents);
                (*sign).contents = p7_data;
            }
            1
        }
        NID_pkcs7_digest => {
            // SAFETY: `p7` is live and its `d.digest` is non-null by the type.
            unsafe {
                let digest = (*p7).d.digest;
                crate::pkcs7::pk7_asn1::PKCS7_free((*digest).contents);
                (*digest).contents = p7_data;
            }
            1
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_108) };
            0
        }
    }
}

/// `int PKCS7_set_type(PKCS7 *p7, int type)` — `pk7_lib.c:116-185`.
///
/// All six arms are transcribed. `signed` (`version` 1), `signedAndEnveloped` (`version` 1,
/// `pkcs7-data` content type), `enveloped` (`version` 0, `pkcs7-data`), `encrypted` (`version`
/// 0, `pkcs7-data`), `digest` (`version` 0) and `data`.
///
/// # Safety
/// `p7` is a live `PKCS7` whose content union has no arm yet.
#[allow(non_upper_case_globals)] // the authority's own `NID_pkcs7_*` spellings
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_type(p7: *mut Pkcs7, type_: c_int) -> c_int {
    // SAFETY: no preconditions.
    let obj = OBJ_nid2obj(type_);

    match type_ {
        NID_pkcs7_signed => {
            // SAFETY: `p7` is the caller's live object.
            unsafe { (*p7).type_ = obj };
            // SAFETY: no preconditions.
            let sign = PKCS7_SIGNED_new();
            // SAFETY: `p7` is live and its `d` union is writable.
            unsafe { (*p7).d.sign = sign };
            if sign.is_null() {
                return 0;
            }
            // SAFETY: `p7` is live; `sign` is the fresh arm.
            unsafe {
                if ASN1_INTEGER_set((*sign).version, 1) == 0 {
                    PKCS7_SIGNED_free(sign);
                    (*p7).d.sign = ptr::null_mut();
                    return 0;
                }
            }
            1
        }
        NID_pkcs7_data => {
            // SAFETY: `p7` is the caller's live object.
            unsafe { (*p7).type_ = obj };
            // SAFETY: as above; the `data` arm is the union's storage.
            let os = ASN1_OCTET_STRING_new();
            if os.is_null() {
                return 0;
            }
            // SAFETY: `p7` is live and its `d` union is writable.
            unsafe { (*p7).d.data = os };
            1
        }
        NID_pkcs7_signedAndEnveloped => {
            // SAFETY: `p7` is the caller's live object.
            unsafe { (*p7).type_ = obj };
            // SAFETY: no preconditions.
            let se = PKCS7_SIGN_ENVELOPE_new();
            // SAFETY: `p7` is live and its `d` union is writable.
            unsafe { (*p7).d.signed_and_enveloped = se };
            if se.is_null() {
                return 0;
            }
            // SAFETY: `se` is the fresh arm.
            unsafe {
                if ASN1_INTEGER_set((*se).version, 1) == 0 {
                    return 0;
                }
                (*(*se).enc_data).content_type = OBJ_nid2obj(NID_pkcs7_data);
            }
            1
        }
        NID_pkcs7_enveloped => {
            // SAFETY: `p7` is the caller's live object.
            unsafe { (*p7).type_ = obj };
            // SAFETY: no preconditions.
            let env = PKCS7_ENVELOPE_new();
            // SAFETY: `p7` is live and its `d` union is writable.
            unsafe { (*p7).d.enveloped = env };
            if env.is_null() {
                return 0;
            }
            // SAFETY: `env` is the fresh arm.
            unsafe {
                if ASN1_INTEGER_set((*env).version, 0) == 0 {
                    return 0;
                }
                (*(*env).enc_data).content_type = OBJ_nid2obj(NID_pkcs7_data);
            }
            1
        }
        NID_pkcs7_encrypted => {
            // SAFETY: `p7` is the caller's live object.
            unsafe { (*p7).type_ = obj };
            // SAFETY: no preconditions.
            let enc = PKCS7_ENCRYPT_new();
            if enc.is_null() {
                return 0;
            }
            // SAFETY: `p7` is live and its `d` union is writable; `enc` is the fresh arm.
            unsafe {
                (*p7).d.encrypted = enc;
                if ASN1_INTEGER_set((*enc).version, 0) == 0 {
                    return 0;
                }
                (*(*enc).enc_data).content_type = OBJ_nid2obj(NID_pkcs7_data);
            }
            1
        }
        NID_pkcs7_digest => {
            // SAFETY: `p7` is the caller's live object.
            unsafe { (*p7).type_ = obj };
            // SAFETY: no preconditions.
            let digest = PKCS7_DIGEST_new();
            if digest.is_null() {
                return 0;
            }
            // SAFETY: `p7` is live and its `d` union is writable; `digest` is the fresh arm.
            unsafe {
                (*p7).d.digest = digest;
                if ASN1_INTEGER_set((*digest).version, 0) == 0 {
                    return 0;
                }
            }
            1
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_179) };
            0
        }
    }
}

/// `int PKCS7_set0_type_other(PKCS7 *p7, int type, ASN1_TYPE *other)` — `pk7_lib.c:187-192`.
///
/// # Safety
/// `p7` is a live `PKCS7`; `other` is adopted.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set0_type_other(
    p7: *mut Pkcs7,
    type_: c_int,
    other: *mut crate::asn1::layout::Asn1Type,
) -> c_int {
    // SAFETY: `p7` is live.
    unsafe {
        (*p7).type_ = OBJ_nid2obj(type_);
        (*p7).d.other = other;
    }
    1
}

/// `int PKCS7_add_signer(PKCS7 *p7, PKCS7_SIGNER_INFO *psi)` — `pk7_lib.c:194-255`.
///
/// # Safety
/// `p7` and `psi` are live; `psi` is adopted on success.
#[allow(non_upper_case_globals)] // the authority's own `NID_pkcs7_*` spellings
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_signer(p7: *mut Pkcs7, psi: *mut Pkcs7SignerInfo) -> c_int {
    // SAFETY: `p7` is live.
    let i = unsafe { OBJ_obj2nid((*p7).type_) };
    let (signer_sk, md_sk) = match i {
        NID_pkcs7_signed => {
            // SAFETY: `p7` is live and its `d.sign` is non-null by the type.
            let s = unsafe { (*p7).d.sign };
            // SAFETY: `s` is live.
            (unsafe { (*s).signer_info }, unsafe { (*s).md_algs })
        }
        NID_pkcs7_signedAndEnveloped => {
            // SAFETY: `p7` is live and its `d.signed_and_enveloped` is non-null by the type.
            let s = unsafe { (*p7).d.signed_and_enveloped };
            // SAFETY: `s` is live.
            (unsafe { (*s).signer_info }, unsafe { (*s).md_algs })
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_213) };
            return 0;
        }
    };

    // SAFETY: `psi` is live.
    let obj = unsafe { (*psi).digest_alg };
    // SAFETY: `obj` is live; the algorithm is its first member.
    let obj = unsafe { (*obj).algorithm };
    let mut j = false;
    // SAFETY: `md_sk` is either null or a live stack.
    let n = unsafe { OPENSSL_sk_num(md_sk) };
    let mut i = 0;
    while i < n {
        // SAFETY: `md_sk` is a live stack and `i` is in range.
        let alg = unsafe { OPENSSL_sk_value(md_sk, i) }.cast::<X509Algor>();
        // SAFETY: `alg` is a live `X509_ALGOR`.
        if unsafe { OBJ_cmp(obj, (*alg).algorithm) } == 0 {
            j = true;
            break;
        }
        i += 1;
    }
    if !j {
        // SAFETY: no preconditions.
        let alg = X509_ALGOR_new();
        // SAFETY: `alg` is null or fresh.
        let param = if alg.is_null() {
            ptr::null_mut()
        } else {
            ASN1_TYPE_new()
        };
        // SAFETY: as above.
        if !alg.is_null() {
            // SAFETY: `alg` is live.
            unsafe { (*alg).parameter = param };
        }
        if alg.is_null() || param.is_null() {
            // SAFETY: `alg` is null or live.
            unsafe { X509_ALGOR_free(alg) };
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_233) };
            return 0;
        }
        // SAFETY: `obj` is live.
        let nid = unsafe { OBJ_obj2nid(obj) };
        // SAFETY: `alg` is live and its algorithm slot is writable.
        unsafe {
            if nid != NID_undef {
                (*alg).algorithm = OBJ_nid2obj(nid);
            } else {
                (*alg).algorithm = OBJ_dup(obj);
            }
        }
        // SAFETY: `param` is live.
        unsafe { (*param).type_ = crate::asn1::layout::V_ASN1_NULL };
        // SAFETY: `alg` is live; its algorithm may be null on a failed dup.
        let alg_ok = unsafe { !(*alg).algorithm.is_null() };
        // SAFETY: `md_sk` is null or live, `alg` is live.
        let pushed = alg_ok && unsafe { OPENSSL_sk_push(md_sk, alg.cast()) } > 0;
        if !pushed {
            // SAFETY: `alg` is live.
            unsafe { X509_ALGOR_free(alg) };
            return 0;
        }
    }

    // SAFETY: `p7` is live.
    unsafe { (*psi).ctx = ossl_pkcs7_get0_ctx(p7) };
    // SAFETY: `signer_sk` is null or live, `psi` is live.
    if unsafe { OPENSSL_sk_push(signer_sk, psi.cast()) } == 0 {
        return 0;
    }
    1
}

/// `int PKCS7_add_certificate(PKCS7 *p7, X509 *x509)` — `pk7_lib.c:257-276`.
///
/// # Safety
/// `p7` is live; `x509` is live and up-referenced.
#[allow(non_upper_case_globals)] // the authority's own `NID_pkcs7_*` spellings
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_certificate(p7: *mut Pkcs7, x509: *mut X509) -> c_int {
    // SAFETY: `p7` is live.
    let i = unsafe { OBJ_obj2nid((*p7).type_) };
    let sk: *mut *mut OpenSslStack = match i {
        NID_pkcs7_signed => {
            // SAFETY: `p7` is live.
            unsafe { ptr::addr_of_mut!((*(*p7).d.sign).cert) }
        }
        NID_pkcs7_signedAndEnveloped => {
            // SAFETY: `p7` is live.
            unsafe { ptr::addr_of_mut!((*(*p7).d.signed_and_enveloped).cert) }
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_271) };
            return 0;
        }
    };
    // SAFETY: `sk` is a live out-pointer; `x509` is the caller's.
    unsafe { ossl_x509_add_cert_new(sk, x509, X509_ADD_FLAG_UP_REF) }
}

/// `int PKCS7_add_crl(PKCS7 *p7, X509_CRL *crl)` — `pk7_lib.c:278-310`.
///
/// # Safety
/// `p7` is live; `crl` is live and up-referenced on success.
#[allow(non_upper_case_globals)] // the authority's own `NID_pkcs7_*` spellings
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_crl(p7: *mut Pkcs7, crl: *mut X509Crl) -> c_int {
    // SAFETY: `p7` is live.
    let i = unsafe { OBJ_obj2nid((*p7).type_) };
    let sk: *mut *mut OpenSslStack = match i {
        NID_pkcs7_signed => {
            // SAFETY: `p7` is live.
            unsafe { ptr::addr_of_mut!((*(*p7).d.sign).crl) }
        }
        NID_pkcs7_signedAndEnveloped => {
            // SAFETY: `p7` is live.
            unsafe { ptr::addr_of_mut!((*(*p7).d.signed_and_enveloped).crl) }
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_292) };
            return 0;
        }
    };
    // SAFETY: `sk` is a live out-pointer.
    if unsafe { (*sk).is_null() } {
        // SAFETY: no preconditions.
        let fresh = OPENSSL_sk_new_null();
        // SAFETY: `sk` is writable.
        unsafe { *sk = fresh };
    }
    // SAFETY: `sk` is a live out-pointer.
    if unsafe { (*sk).is_null() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_LIB_299) };
        return 0;
    }
    // SAFETY: `crl` is live.
    if unsafe { X509_CRL_up_ref(crl) } == 0 {
        return 0;
    }
    // SAFETY: `*sk` is a live stack; `crl` is live.
    if unsafe { OPENSSL_sk_push(*sk, crl.cast()) } == 0 {
        // SAFETY: `crl` is live and the up-ref is owned here.
        unsafe { X509_CRL_free(crl) };
        return 0;
    }
    1
}

/// `pkcs7_ecdsa_or_dsa_sign_verify_setup(si, verify)` — `pk7_lib.c:312-331`. Only the
/// `verify == 0` arm does anything.
///
/// # Safety
/// `si` is a live signer info with a live `pkey`.
unsafe fn pkcs7_ecdsa_or_dsa_sign_verify_setup(si: *mut Pkcs7SignerInfo, verify: c_int) -> c_int {
    if verify == 0 {
        // SAFETY: `si` is live.
        let pkey = unsafe { (*si).pkey };
        let mut alg1: *mut X509Algor = ptr::null_mut();
        let mut alg2: *mut X509Algor = ptr::null_mut();
        // SAFETY: `si` is live and the two out-pointers are writable.
        unsafe { PKCS7_SIGNER_INFO_get0_algs(si, ptr::null_mut(), &mut alg1, &mut alg2) };
        if alg1.is_null() {
            return -1;
        }
        // SAFETY: `alg1` is live.
        let alg1_alg = unsafe { (*alg1).algorithm };
        if alg1_alg.is_null() {
            return -1;
        }
        // SAFETY: `alg1_alg` is live.
        let hnid = unsafe { OBJ_obj2nid(alg1_alg) };
        if hnid == NID_undef {
            return -1;
        }
        let mut snid: c_int = 0;
        // SAFETY: `pkey` is live; the out-pointer is writable.
        let found = unsafe { OBJ_find_sigid_by_algs(&mut snid, hnid, EVP_PKEY_get_id(pkey)) };
        if found == 0 {
            return -1;
        }
        // SAFETY: `alg2` is live.
        unsafe {
            X509_ALGOR_set0(
                alg2,
                OBJ_nid2obj(snid),
                crate::asn1::layout::V_ASN1_UNDEF,
                ptr::null_mut(),
            )
        }
    } else {
        1
    }
}

/// `pkcs7_rsa_sign_verify_setup(si, verify)` — `pk7_lib.c:333-344`.
///
/// # Safety
/// `si` is a live signer info.
unsafe fn pkcs7_rsa_sign_verify_setup(si: *mut Pkcs7SignerInfo, verify: c_int) -> c_int {
    if verify == 0 {
        let mut alg: *mut X509Algor = ptr::null_mut();
        // SAFETY: `si` is live and the out-pointer is writable.
        unsafe { PKCS7_SIGNER_INFO_get0_algs(si, ptr::null_mut(), ptr::null_mut(), &mut alg) };
        if !alg.is_null() {
            // SAFETY: `alg` is live.
            return unsafe {
                X509_ALGOR_set0(
                    alg,
                    OBJ_nid2obj(NID_rsaEncryption),
                    crate::asn1::layout::V_ASN1_NULL,
                    ptr::null_mut(),
                )
            };
        }
    }
    1
}

/// `int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i, X509 *x509, EVP_PKEY *pkey,
/// const EVP_MD *dgst)` — `pk7_lib.c:346-394`.
///
/// # Safety
/// `p7i` is live; `x509` and `pkey` are live and up-referenced on success.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNER_INFO_set(
    p7i: *mut Pkcs7SignerInfo,
    x509: *mut X509,
    pkey: *mut EvpPkey,
    dgst: *const crate::evp::digest::EvpMd,
) -> c_int {
    // SAFETY: `p7i` is live.
    if unsafe { ASN1_INTEGER_set((*p7i).version, 1) } == 0 {
        return 0;
    }
    // SAFETY: `p7i` is live; `X509_get_issuer_name` borrows `x509`.
    let iss = unsafe { X509_get_issuer_name(x509) };
    // SAFETY: `p7i` is live and its issuer slot is writable; `iss` is the certificate's.
    if unsafe {
        X509_NAME_set(
            ptr::addr_of_mut!((*(*p7i).issuer_and_serial).issuer),
            iss.cast_const(),
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `p7i` is live.
    unsafe {
        ASN1_INTEGER_free((*(*p7i).issuer_and_serial).serial);
    }
    // SAFETY: `x509` is live.
    let serial = unsafe { X509_get0_serialNumber(x509) };
    // SAFETY: `serial` is the certificate's own; `ASN1_INTEGER_dup` copies it.
    let dup = unsafe { ASN1_INTEGER_dup(serial) };
    // SAFETY: `p7i` is live and its serial slot is writable.
    unsafe { (*(*p7i).issuer_and_serial).serial = dup };
    if dup.is_null() {
        return 0;
    }
    // SAFETY: `pkey` is live.
    if unsafe { EVP_PKEY_up_ref(pkey) } == 0 {
        return 0;
    }
    // SAFETY: `p7i` is live.
    unsafe { (*p7i).pkey = pkey };

    // SAFETY: `dgst` is live; `p7i` is live.
    let mdtype = unsafe { crate::evp::digest::EVP_MD_get_type(dgst) };
    // SAFETY: `p7i` is live and its `digest_alg` is live.
    unsafe {
        if X509_ALGOR_set0(
            (*p7i).digest_alg,
            OBJ_nid2obj(mdtype),
            crate::asn1::layout::V_ASN1_NULL,
            ptr::null_mut(),
        ) == 0
        {
            return 0;
        }
    }

    // SAFETY: `pkey` is live; the names are NUL-terminated literals.
    let is_ec = unsafe { EVP_PKEY_is_a(pkey, c"EC".as_ptr()) } != 0;
    // SAFETY: `pkey` is live; the name is a NUL-terminated literal.
    let is_dsa = unsafe { EVP_PKEY_is_a(pkey, c"DSA".as_ptr()) } != 0;
    // SAFETY: `pkey` is live; the name is a NUL-terminated literal.
    let is_rsa = unsafe { EVP_PKEY_is_a(pkey, c"RSA".as_ptr()) } != 0;
    if is_ec || is_dsa {
        // SAFETY: `p7i` is live.
        return unsafe { pkcs7_ecdsa_or_dsa_sign_verify_setup(p7i, 0) };
    }
    if is_rsa {
        // SAFETY: `p7i` is live.
        return unsafe { pkcs7_rsa_sign_verify_setup(p7i, 0) };
    }

    // The authority reaches `pkey->ameth->pkey_ctrl` here; the crate's provider-modelled
    // `EVP_PKEY` has no `ameth` handle, so the terminal reason stands in (see the module note).
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PKCS7_LIB_392) };
    0
}

/// `PKCS7_SIGNER_INFO *PKCS7_add_signature(PKCS7 *p7, X509 *x509, EVP_PKEY *pkey,
/// const EVP_MD *dgst)` — `pk7_lib.c:396-422`.
///
/// # Safety
/// `p7` is live; `x509` and `pkey` are live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_signature(
    p7: *mut Pkcs7,
    x509: *mut X509,
    pkey: *mut EvpPkey,
    dgst: *const crate::evp::digest::EvpMd,
) -> *mut Pkcs7SignerInfo {
    let mut dgst = dgst;
    if dgst.is_null() {
        let mut def_nid: c_int = 0;
        // SAFETY: `pkey` is live and the out-pointer is writable.
        if unsafe { EVP_PKEY_get_default_digest_nid(pkey, &mut def_nid) } <= 0 {
            return ptr::null_mut();
        }
        // SAFETY: `def_nid` is the key's default.
        dgst = unsafe { EVP_get_digestbyname(OBJ_nid2sn(def_nid)) };
        if dgst.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_407) };
            return ptr::null_mut();
        }
    }
    // SAFETY: no preconditions.
    let si = PKCS7_SIGNER_INFO_new();
    if si.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `si` is live; the rest are the caller's.
    if unsafe { PKCS7_SIGNER_INFO_set(si, x509, pkey, dgst) } <= 0 {
        // SAFETY: `si` is live and owned here.
        unsafe { PKCS7_SIGNER_INFO_free(si) };
        return ptr::null_mut();
    }
    // SAFETY: `p7`/`si` are live.
    if unsafe { PKCS7_add_signer(p7, si) } == 0 {
        // SAFETY: `si` is live and owned here.
        unsafe { PKCS7_SIGNER_INFO_free(si) };
        return ptr::null_mut();
    }
    si
}

/// `pkcs7_get0_certificates(p7)` — `pk7_lib.c:424-433`. Internal (`crypto/pkcs7.h`), so
/// `pub(crate)`; `pk7_smime.c`'s verifier reaches it.
///
/// # Safety
/// `p7` is live.
pub(crate) unsafe fn pkcs7_get0_certificates(p7: *const Pkcs7) -> *mut OpenSslStack {
    // SAFETY: `p7` is live.
    if unsafe { (*p7).d.ptr }.is_null() {
        return ptr::null_mut();
    }
    if pkcs7_type_is_signed(p7) {
        // SAFETY: `p7` is a live signed structure.
        return unsafe { (*(*p7).d.sign).cert };
    }
    if pkcs7_type_is_signed_and_enveloped(p7) {
        // SAFETY: `p7` is a live signed-and-enveloped structure.
        return unsafe { (*(*p7).d.signed_and_enveloped).cert };
    }
    ptr::null_mut()
}

/// `pkcs7_get_recipient_info(p7)` — `pk7_lib.c:435-444`.
///
/// # Safety
/// `p7` is live.
unsafe fn pkcs7_get_recipient_info(p7: *const Pkcs7) -> *mut OpenSslStack {
    // SAFETY: `p7` is live.
    if unsafe { (*p7).d.ptr }.is_null() {
        return ptr::null_mut();
    }
    if pkcs7_type_is_signed_and_enveloped(p7) {
        // SAFETY: `p7` is live.
        return unsafe { (*(*p7).d.signed_and_enveloped).recipientinfo };
    }
    if pkcs7_type_is_enveloped(p7) {
        // SAFETY: `p7` is live.
        return unsafe { (*(*p7).d.enveloped).recipientinfo };
    }
    ptr::null_mut()
}

/// `void ossl_pkcs7_resolve_libctx(PKCS7 *p7)` — `pk7_lib.c:450-482`.
///
/// Propagates the context into every certificate, recipient info and signer info the structure
/// holds. The three stacks are null **by the arm's type** for `data`/`digest`/`encrypted`.
///
/// # Safety
/// `p7` is a live `PKCS7`.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_resolve_libctx(p7: *mut Pkcs7) {
    // SAFETY: `p7` is live.
    let ctx = unsafe { ossl_pkcs7_get0_ctx(p7) };
    // SAFETY: `p7` is live and its `d` union is readable.
    if ctx.is_null() || unsafe { (*p7).d.ptr }.is_null() {
        return;
    }
    // SAFETY: `ctx` is live.
    let libctx = unsafe { ossl_pkcs7_ctx_get0_libctx(ctx) };
    // SAFETY: `ctx` is live.
    let propq = unsafe { ossl_pkcs7_ctx_get0_propq(ctx) };
    // SAFETY: `p7` is live.
    let rinfos = unsafe { pkcs7_get_recipient_info(p7) };
    // SAFETY: `p7` is live.
    let sinfos = unsafe { PKCS7_get_signer_info(p7) };
    // SAFETY: `p7` is live.
    let certs = unsafe { pkcs7_get0_certificates(p7) };

    // SAFETY: `certs` is null or a live stack.
    let n = unsafe { OPENSSL_sk_num(certs) };
    let mut i = 0;
    while i < n {
        // SAFETY: `certs` is a live stack and `i` is in range.
        let cert = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        // SAFETY: `cert` is live.
        unsafe { ossl_x509_set0_libctx(cert, libctx, propq) };
        i += 1;
    }

    // SAFETY: `rinfos` is null or a live stack.
    let n = unsafe { OPENSSL_sk_num(rinfos) };
    let mut i = 0;
    while i < n {
        // SAFETY: `rinfos` is a live stack and `i` is in range.
        let ri = unsafe { OPENSSL_sk_value(rinfos, i) }.cast::<Pkcs7RecipInfo>();
        // SAFETY: `ri` is live.
        unsafe { ossl_x509_set0_libctx((*ri).cert, libctx, propq) };
        i += 1;
    }

    // SAFETY: `sinfos` is null or a live stack.
    let n = unsafe { OPENSSL_sk_num(sinfos) };
    let mut i = 0;
    while i < n {
        // SAFETY: `sinfos` is a live stack and `i` is in range.
        let si = unsafe { OPENSSL_sk_value(sinfos, i) }.cast::<Pkcs7SignerInfo>();
        if !si.is_null() {
            // SAFETY: `si` is live.
            unsafe { (*si).ctx = ctx };
        }
        i += 1;
    }
}

/// `const PKCS7_CTX *ossl_pkcs7_get0_ctx(const PKCS7 *p7)` — `pk7_lib.c:484-487`.
///
/// # Safety
/// `p7` is null or a live `PKCS7`; a non-null answer borrows its context.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_get0_ctx(p7: *const Pkcs7) -> *const Pkcs7Ctx {
    if p7.is_null() {
        ptr::null()
    } else {
        // SAFETY: `p7` is live per the caller's contract.
        unsafe { ptr::addr_of!((*p7).ctx) }
    }
}

/// `void ossl_pkcs7_set0_libctx(PKCS7 *p7, OSSL_LIB_CTX *ctx)` — `pk7_lib.c:489-492`.
///
/// # Safety
/// `p7` is a live `PKCS7`.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_set0_libctx(p7: *mut Pkcs7, ctx: *mut c_void) {
    // SAFETY: `p7` is live per the caller's contract.
    unsafe { (*p7).ctx.libctx = ctx };
}

/// `int ossl_pkcs7_set1_propq(PKCS7 *p7, const char *propq)` — `pk7_lib.c:494-506`.
///
/// Takes a **copy** of `propq`, releasing any query already held; a null `propq` clears the slot.
/// A failed copy answers 0 and leaves the slot null.
///
/// # Safety
/// `p7` is a live `PKCS7`; `propq` is null or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_set1_propq(p7: *mut Pkcs7, propq: *const c_char) -> c_int {
    // SAFETY: `p7` is live; its `ctx.propq` is either null or this object's own copy.
    unsafe {
        if !(*p7).ctx.propq.is_null() {
            CRYPTO_free((*p7).ctx.propq.cast(), FILE.as_ptr(), 497);
            (*p7).ctx.propq = ptr::null_mut();
        }
    }
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the caller's contract.
        let copy = unsafe { CRYPTO_strdup(propq, FILE.as_ptr(), 501) };
        if copy.is_null() {
            return 0;
        }
        // SAFETY: `p7` is live and its `ctx.propq` slot is writable.
        unsafe { (*p7).ctx.propq = copy };
    }
    1
}

/// `int ossl_pkcs7_ctx_propagate(const PKCS7 *from, PKCS7 *to)` — `pk7_lib.c:508-516`.
///
/// # Safety
/// `from` and `to` are live `PKCS7`s.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_ctx_propagate(from: *const Pkcs7, to: *mut Pkcs7) -> c_int {
    // SAFETY: both are live per the caller's contract.
    unsafe {
        ossl_pkcs7_set0_libctx(to, (*from).ctx.libctx);
        if ossl_pkcs7_set1_propq(to, (*from).ctx.propq) == 0 {
            return 0;
        }
        ossl_pkcs7_resolve_libctx(to);
    }
    1
}

/// `OSSL_LIB_CTX *ossl_pkcs7_ctx_get0_libctx(const PKCS7_CTX *ctx)` — `pk7_lib.c:518-521`.
///
/// # Safety
/// `ctx` is null or a live `PKCS7_CTX`.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_ctx_get0_libctx(ctx: *const Pkcs7Ctx) -> *mut c_void {
    if ctx.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).libctx }
    }
}

/// `const char *ossl_pkcs7_ctx_get0_propq(const PKCS7_CTX *ctx)` — `pk7_lib.c:522-525`.
///
/// # Safety
/// `ctx` is null or a live `PKCS7_CTX`.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_ctx_get0_propq(ctx: *const Pkcs7Ctx) -> *const c_char {
    if ctx.is_null() {
        ptr::null()
    } else {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).propq }
    }
}

/// `int PKCS7_set_digest(PKCS7 *p7, const EVP_MD *md)` — `pk7_lib.c:527-541`.
///
/// # Safety
/// `p7` is a live `PKCS7`; `md` is null or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_digest(
    p7: *mut Pkcs7,
    md: *const crate::evp::digest::EvpMd,
) -> c_int {
    if pkcs7_type_is_digest(p7) {
        // SAFETY: `p7` is a live digest structure.
        unsafe {
            let digest = (*p7).d.digest;
            let param = ASN1_TYPE_new();
            if param.is_null() {
                // SAFETY: a compile-time-constant site.
                raise_site(&err_sites::PKCS7_LIB_531);
                return 0;
            }
            (*(*digest).md).parameter = param;
            (*param).type_ = crate::asn1::layout::V_ASN1_NULL;
            (*(*digest).md).algorithm = OBJ_nid2obj(crate::evp::digest::EVP_MD_get_type(md));
        }
        return 1;
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PKCS7_LIB_539) };
    0
}

/// `STACK_OF(PKCS7_SIGNER_INFO) *PKCS7_get_signer_info(PKCS7 *p7)` — `pk7_lib.c:543-553`.
///
/// # Safety
/// `p7` is null or live; a non-null answer borrows its stack.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_signer_info(p7: *mut Pkcs7) -> *mut OpenSslStack {
    // SAFETY: `p7` is live and its `d` union is readable.
    if p7.is_null() || unsafe { (*p7).d.ptr }.is_null() {
        return ptr::null_mut();
    }
    if pkcs7_type_is_signed(p7) {
        // SAFETY: `p7` is a live signed structure.
        return unsafe { (*(*p7).d.sign).signer_info };
    }
    if pkcs7_type_is_signed_and_enveloped(p7) {
        // SAFETY: `p7` is a live signed-and-enveloped structure.
        return unsafe { (*(*p7).d.signed_and_enveloped).signer_info };
    }
    ptr::null_mut()
}

/// `void PKCS7_SIGNER_INFO_get0_algs(PKCS7_SIGNER_INFO *si, EVP_PKEY **pk, X509_ALGOR **pdig,
/// X509_ALGOR **psig)` — `pk7_lib.c:555-564`.
///
/// # Safety
/// `si` is live; each out-pointer is null or writable.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNER_INFO_get0_algs(
    si: *mut Pkcs7SignerInfo,
    pk: *mut *mut EvpPkey,
    pdig: *mut *mut X509Algor,
    psig: *mut *mut X509Algor,
) {
    // SAFETY: `si` is live.
    unsafe {
        if !pk.is_null() {
            *pk = (*si).pkey;
        }
        if !pdig.is_null() {
            *pdig = (*si).digest_alg;
        }
        if !psig.is_null() {
            *psig = (*si).digest_enc_alg;
        }
    }
}

/// `void PKCS7_RECIP_INFO_get0_alg(PKCS7_RECIP_INFO *ri, X509_ALGOR **penc)` — `pk7_lib.c:566-570`.
///
/// # Safety
/// `ri` is live; `penc` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_RECIP_INFO_get0_alg(
    ri: *mut Pkcs7RecipInfo,
    penc: *mut *mut X509Algor,
) {
    // SAFETY: `ri` is live.
    unsafe {
        if !penc.is_null() {
            *penc = (*ri).key_enc_algor;
        }
    }
}

/// `PKCS7_RECIP_INFO *PKCS7_add_recipient(PKCS7 *p7, X509 *x509)` — `pk7_lib.c:572-587`.
///
/// # Safety
/// `p7` is live; `x509` is live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_recipient(
    p7: *mut Pkcs7,
    x509: *mut X509,
) -> *mut Pkcs7RecipInfo {
    // SAFETY: no preconditions.
    let ri = PKCS7_RECIP_INFO_new();
    if ri.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ri` is live.
    if unsafe { PKCS7_RECIP_INFO_set(ri, x509) } <= 0 {
        // SAFETY: `ri` is live and owned here.
        unsafe { PKCS7_RECIP_INFO_free(ri) };
        return ptr::null_mut();
    }
    // SAFETY: `p7`/`ri` are live.
    if unsafe { PKCS7_add_recipient_info(p7, ri) } == 0 {
        // SAFETY: `ri` is live and owned here.
        unsafe { PKCS7_RECIP_INFO_free(ri) };
        return ptr::null_mut();
    }
    // SAFETY: `p7` is live.
    unsafe { (*ri).ctx = ossl_pkcs7_get0_ctx(p7) };
    ri
}

/// `int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri)` — `pk7_lib.c:589-610`.
///
/// # Safety
/// `p7` and `ri` are live; `ri` is adopted on success.
#[allow(non_upper_case_globals)] // the authority's own `NID_pkcs7_*` spellings
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_recipient_info(
    p7: *mut Pkcs7,
    ri: *mut Pkcs7RecipInfo,
) -> c_int {
    // SAFETY: `p7` is live.
    let i = unsafe { OBJ_obj2nid((*p7).type_) };
    let sk = match i {
        NID_pkcs7_signedAndEnveloped => {
            // SAFETY: `p7` is live.
            unsafe { (*(*p7).d.signed_and_enveloped).recipientinfo }
        }
        NID_pkcs7_enveloped => {
            // SAFETY: `p7` is live.
            unsafe { (*(*p7).d.enveloped).recipientinfo }
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_603) };
            return 0;
        }
    };
    // SAFETY: `sk` is null or live; `ri` is live.
    if unsafe { OPENSSL_sk_push(sk, ri.cast()) } == 0 {
        return 0;
    }
    1
}

/// `pkcs7_rsa_encrypt_decrypt_setup(ri, decrypt)` — `pk7_lib.c:612-623`.
///
/// # Safety
/// `ri` is live.
unsafe fn pkcs7_rsa_encrypt_decrypt_setup(ri: *mut Pkcs7RecipInfo, decrypt: c_int) -> c_int {
    if decrypt == 0 {
        let mut alg: *mut X509Algor = ptr::null_mut();
        // SAFETY: `ri` is live and the out-pointer is writable.
        unsafe { PKCS7_RECIP_INFO_get0_alg(ri, &mut alg) };
        if !alg.is_null() {
            // SAFETY: `alg` is live.
            return unsafe {
                X509_ALGOR_set0(
                    alg,
                    OBJ_nid2obj(NID_rsaEncryption),
                    crate::asn1::layout::V_ASN1_NULL,
                    ptr::null_mut(),
                )
            };
        }
    }
    1
}

/// `int PKCS7_RECIP_INFO_set(PKCS7_RECIP_INFO *p7i, X509 *x509)` — `pk7_lib.c:625-677`.
///
/// # Safety
/// `p7i` is live; `x509` is live and up-referenced on success.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_RECIP_INFO_set(p7i: *mut Pkcs7RecipInfo, x509: *mut X509) -> c_int {
    // SAFETY: `p7i` is live.
    if unsafe { ASN1_INTEGER_set((*p7i).version, 0) } == 0 {
        return 0;
    }
    // SAFETY: `x509` is live.
    let iss = unsafe { X509_get_issuer_name(x509) };
    // SAFETY: `p7i` is live and its issuer slot is writable.
    if unsafe {
        X509_NAME_set(
            ptr::addr_of_mut!((*(*p7i).issuer_and_serial).issuer),
            iss.cast_const(),
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `p7i` is live.
    unsafe { ASN1_INTEGER_free((*(*p7i).issuer_and_serial).serial) };
    // SAFETY: `x509` is live.
    let serial = unsafe { X509_get0_serialNumber(x509) };
    // SAFETY: `serial` is the certificate's own; `ASN1_INTEGER_dup` copies it.
    let dup = unsafe { ASN1_INTEGER_dup(serial) };
    // SAFETY: `p7i` is live and its serial slot is writable.
    unsafe { (*(*p7i).issuer_and_serial).serial = dup };
    if dup.is_null() {
        return 0;
    }

    // SAFETY: `x509` is live.
    let pkey = unsafe { X509_get0_pubkey(x509) };
    if pkey.is_null() {
        return 0;
    }
    // SAFETY: `pkey` is live.
    if unsafe { EVP_PKEY_is_a(pkey, c"RSA-PSS".as_ptr()) } != 0 {
        return -2;
    }
    // SAFETY: `pkey` is live.
    if unsafe { EVP_PKEY_is_a(pkey, c"RSA".as_ptr()) } != 0 {
        // SAFETY: `p7i` is live.
        if unsafe { pkcs7_rsa_encrypt_decrypt_setup(p7i, 0) } <= 0 {
            return 0;
        }
        // SAFETY: `x509` is live.
        if unsafe { X509_up_ref(x509) } == 0 {
            return 0;
        }
        // SAFETY: `p7i` is live.
        unsafe { (*p7i).cert = x509 };
        return 1;
    }

    // The authority reaches `pkey->ameth->pkey_ctrl` here; the crate's provider-modelled
    // `EVP_PKEY` has no `ameth` handle, so the terminal reason stands in (see the module note).
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PKCS7_LIB_652) };
    0
}

/// `X509 *PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si)` — `pk7_lib.c:679-687`.
///
/// # Safety
/// `p7` and `si` are live; a non-null answer borrows a certificate from `p7`.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_cert_from_signer_info(
    p7: *mut Pkcs7,
    si: *mut Pkcs7SignerInfo,
) -> *mut X509 {
    if pkcs7_type_is_signed(p7) {
        // SAFETY: `p7`/`si` are live.
        return unsafe {
            X509_find_by_issuer_and_serial(
                (*(*p7).d.sign).cert,
                (*(*si).issuer_and_serial).issuer,
                (*(*si).issuer_and_serial).serial,
            )
        };
    }
    ptr::null_mut()
}

/// `int PKCS7_set_cipher(PKCS7 *p7, const EVP_CIPHER *cipher)` — `pk7_lib.c:689-717`.
///
/// # Safety
/// `p7` is live; `cipher` is live.
#[allow(non_upper_case_globals)] // the authority's own `NID_pkcs7_*` spellings
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_cipher(
    p7: *mut Pkcs7,
    cipher: *const crate::evp::cipher::EvpCipher,
) -> c_int {
    // SAFETY: `p7` is live.
    let i = unsafe { OBJ_obj2nid((*p7).type_) };
    let ec: *mut Pkcs7EncContent = match i {
        NID_pkcs7_signedAndEnveloped => {
            // SAFETY: `p7` is live.
            unsafe { (*(*p7).d.signed_and_enveloped).enc_data }
        }
        NID_pkcs7_enveloped => {
            // SAFETY: `p7` is live.
            unsafe { (*(*p7).d.enveloped).enc_data }
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_703) };
            return 0;
        }
    };
    // SAFETY: `cipher` is live.
    let i = unsafe { crate::evp::cipher::EVP_CIPHER_get_type(cipher) };
    if i == NID_undef {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_LIB_710) };
        return 0;
    }
    // SAFETY: `ec` and `p7` are live.
    unsafe {
        (*ec).cipher = cipher.cast();
        (*ec).ctx = ossl_pkcs7_get0_ctx(p7);
    }
    1
}

/// `int PKCS7_stream(unsigned char ***boundary, PKCS7 *p7)` — `pk7_lib.c:720-779`.
///
/// # Safety
/// `p7` is live; `boundary` is writable.
#[allow(non_upper_case_globals)] // the authority's own `NID_pkcs7_*` spellings
#[no_mangle]
pub unsafe extern "C" fn PKCS7_stream(boundary: *mut *mut *mut u8, p7: *mut Pkcs7) -> c_int {
    // SAFETY: `p7` is live.
    let nid = unsafe { OBJ_obj2nid((*p7).type_) };
    let os = match nid {
        NID_pkcs7_data => {
            // SAFETY: `p7` is a live data structure.
            unsafe { (*p7).d.data }
        }
        NID_pkcs7_signedAndEnveloped => {
            // SAFETY: `p7` is live.
            unsafe {
                let se = (*p7).d.signed_and_enveloped;
                if se.is_null() || (*se).enc_data.is_null() {
                    // SAFETY: a compile-time-constant site.
                    raise_site(&err_sites::PKCS7_LIB_731);
                    return 0;
                }
                let mut os = (*(*se).enc_data).enc_data;
                if os.is_null() {
                    os = ASN1_OCTET_STRING_new();
                    (*(*se).enc_data).enc_data = os;
                }
                os
            }
        }
        NID_pkcs7_enveloped => {
            // SAFETY: `p7` is live.
            unsafe {
                let env = (*p7).d.enveloped;
                if env.is_null() || (*env).enc_data.is_null() {
                    // SAFETY: a compile-time-constant site.
                    raise_site(&err_sites::PKCS7_LIB_743);
                    return 0;
                }
                let mut os = (*(*env).enc_data).enc_data;
                if os.is_null() {
                    os = ASN1_OCTET_STRING_new();
                    (*(*env).enc_data).enc_data = os;
                }
                os
            }
        }
        NID_pkcs7_signed => {
            // SAFETY: `p7` is live.
            unsafe {
                let sign = (*p7).d.sign;
                if sign.is_null() || (*sign).contents.is_null() {
                    // SAFETY: a compile-time-constant site.
                    raise_site(&err_sites::PKCS7_LIB_755);
                    return 0;
                }
                if !pkcs7_type_is_data((*sign).contents) {
                    // SAFETY: a compile-time-constant site.
                    raise_site(&err_sites::PKCS7_LIB_760);
                    return 0;
                }
                crate::pkcs7::pk7_doit::PKCS7_get_octet_string((*sign).contents)
            }
        }
        _ => ptr::null_mut(),
    };

    if os.is_null() {
        return 0;
    }
    // SAFETY: `os` is a live `ASN1_OCTET_STRING`.
    unsafe {
        (*os).flags |= crate::asn1::layout::ASN1_STRING_FLAG_NDEF;
        *boundary = ptr::addr_of_mut!((*os).data);
    }
    1
}
