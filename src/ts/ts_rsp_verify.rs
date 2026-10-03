//! `crypto/ts/ts_rsp_verify.c` — the RFC 3161 response verifier. Phase 12.5b.
//!
//! The three exports the `ts.h` surface declares — `TS_RESP_verify_signature` (`:87-165`),
//! `TS_RESP_verify_response` (`:248-262`) and `TS_RESP_verify_token` (`:268-277`) — and every
//! static they reach: `ts_verify_cert` (`:171-204`), `ossl_ess_get_signing_cert[_v2]`
//! (`:206-228`), `ts_check_signing_certs` (`:230-240`), `int_ts_RESP_verify_token` (`:291-348`),
//! `ts_check_status_info` (`:350-397`), `ts_get_status_text` (`:399-402`), `ts_check_policy`
//! (`:404-415`), `ts_compute_imprint` (`:417-483`), `ts_check_imprints` (`:485-510`),
//! `ts_check_nonces` (`:512-528`), `ts_check_signer_name` (`:534-558`) and `ts_find_name`
//! (`:561-569`).
//!
//! This unit waited on 12.7's ESS item group and its `OSSL_ESS_check_signing_certs` checker, which
//! `ts_check_signing_certs` reaches through the `SigningCertificate` signed attribute. The ESS
//! decode pair `ossl_ess_get_signing_cert[_v2]` are this file's own statics, transcribed here.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, CStr};
use core::ptr;

use crate::asn1::a_type::ASN1_TYPE_get;
use crate::asn1::bitstr::ASN1_BIT_STRING_get_bit;
use crate::asn1::layout::Asn1String;
use crate::asn1::layout::V_ASN1_NULL;
use crate::asn1::prim::{ASN1_INTEGER_cmp, ASN1_INTEGER_get};
use crate::asn1::string::{
    ossl_sk_ASN1_UTF8STRING2text, ASN1_STRING_get0_data, ASN1_STRING_length,
};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_dup, X509_ALGOR_free};
use crate::ess::ess_asn1::{
    d2i_ESS_SIGNING_CERT, d2i_ESS_SIGNING_CERT_V2, ESS_SIGNING_CERT_V2_free, ESS_SIGNING_CERT_free,
    EssSigningCert, EssSigningCertV2,
};
use crate::ess::ess_lib::OSSL_ESS_check_signing_certs;
use crate::evp::digest::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EvpMd, EvpMdCtx,
};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::pkcs7::pk7_asn1::{Pkcs7, Pkcs7SignerInfo};
use crate::pkcs7::pk7_doit::{PKCS7_dataInit, PKCS7_get_signed_attribute, PKCS7_signatureVerify};
use crate::pkcs7::pk7_lib::{pkcs7_get_detached, pkcs7_type_is_signed, PKCS7_get_signer_info};
use crate::pkcs7::pk7_smime::PKCS7_get0_signers;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::{BIO_free_all, BIO_read, Bio};
use crate::runtime::err::{ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{
    Asn1Object, NID_id_smime_aa_signingCertificate, NID_id_smime_aa_signingCertificateV2,
    NID_subject_alt_name, OBJ_cmp, OBJ_obj2txt,
};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::v3_genn::{GENERAL_NAMES_free, GENERAL_NAME_cmp, GeneralName, GEN_DIRNAME};
use crate::x509::x509_cmp::{X509_NAME_cmp, X509_add_certs, X509_get_subject_name};
use crate::x509::x509_ext::X509_get_ext_d2i;
use crate::x509::x509_lu::X509Store;
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x509_txt::X509_verify_cert_error_string;
use crate::x509::x509_vfy::{
    X509_STORE_CTX_free, X509_STORE_CTX_get1_chain, X509_STORE_CTX_get_error, X509_STORE_CTX_init,
    X509_STORE_CTX_new, X509_STORE_CTX_set_purpose, X509_verify_cert,
};
use crate::x509::x_x509::{X509_free, X509};

use super::ts_asn1::{PKCS7_to_TS_TST_INFO, TsMsgImprint, TsResp, TsStatusInfo, TsTstInfo};
use super::ts_rsp_utils::TS_TST_INFO_get_version;
use super::ts_verify_ctx::TsVerifyCtx;
use super::{raise_ts, raise_ts_data, ERR_R_EVP_LIB, ERR_R_X509_LIB};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ts/ts_rsp_verify.c";

/// `X509_PURPOSE_TIMESTAMP_SIGN` — `include/openssl/x509v3.h`.
const X509_PURPOSE_TIMESTAMP_SIGN: c_int = 9;

/// `TS_STATUS_BUF_SIZE` — `ts_rsp_verify.c:45`.
const TS_STATUS_BUF_SIZE: usize = 256;
/// `TS_MAX_STATUS_LENGTH` — `include/openssl/ts.h:315`.
const TS_MAX_STATUS_LENGTH: usize = 1024 * 1024;
/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `V_ASN1_SEQUENCE` — `include/openssl/asn1.h`.
const V_ASN1_SEQUENCE: c_int = 16;

/// `TS_VFY_SIGNATURE` — `include/openssl/ts.h:367`.
const TS_VFY_SIGNATURE: u32 = 1 << 0;
/// `TS_VFY_VERSION` — `include/openssl/ts.h:369`.
const TS_VFY_VERSION: u32 = 1 << 1;
/// `TS_VFY_POLICY` — `include/openssl/ts.h:371`.
const TS_VFY_POLICY: u32 = 1 << 2;
/// `TS_VFY_IMPRINT` — `include/openssl/ts.h:376`.
const TS_VFY_IMPRINT: u32 = 1 << 3;
/// `TS_VFY_DATA` — `include/openssl/ts.h:382`.
const TS_VFY_DATA: u32 = 1 << 4;
/// `TS_VFY_NONCE` — `include/openssl/ts.h:384`.
const TS_VFY_NONCE: u32 = 1 << 5;
/// `TS_VFY_SIGNER` — `include/openssl/ts.h:386`.
const TS_VFY_SIGNER: u32 = 1 << 6;
/// `TS_VFY_TSA_NAME` — `include/openssl/ts.h:388`.
const TS_VFY_TSA_NAME: u32 = 1 << 7;

/// `TS_R_INVALID_NULL_POINTER` — `include/openssl/tserr.h`.
const TS_R_INVALID_NULL_POINTER: c_int = 102;
/// `TS_R_WRONG_CONTENT_TYPE` — `include/openssl/tserr.h`.
const TS_R_WRONG_CONTENT_TYPE: c_int = 114;
/// `TS_R_THERE_MUST_BE_ONE_SIGNER` — `include/openssl/tserr.h`.
const TS_R_THERE_MUST_BE_ONE_SIGNER: c_int = 110;
/// `TS_R_NO_CONTENT` — `include/openssl/tserr.h`.
const TS_R_NO_CONTENT: c_int = 106;
/// `TS_R_SIGNATURE_FAILURE` — `include/openssl/tserr.h`.
const TS_R_SIGNATURE_FAILURE: c_int = 109;
/// `TS_R_CERTIFICATE_VERIFY_ERROR` — `include/openssl/tserr.h`.
const TS_R_CERTIFICATE_VERIFY_ERROR: c_int = 100;
/// `TS_R_UNSUPPORTED_VERSION` — `include/openssl/tserr.h`.
const TS_R_UNSUPPORTED_VERSION: c_int = 113;
/// `TS_R_POLICY_MISMATCH` — `include/openssl/tserr.h`.
const TS_R_POLICY_MISMATCH: c_int = 108;
/// `TS_R_MESSAGE_IMPRINT_MISMATCH` — `include/openssl/tserr.h`.
const TS_R_MESSAGE_IMPRINT_MISMATCH: c_int = 103;
/// `TS_R_NONCE_NOT_RETURNED` — `include/openssl/tserr.h`.
const TS_R_NONCE_NOT_RETURNED: c_int = 105;
/// `TS_R_NONCE_MISMATCH` — `include/openssl/tserr.h`.
const TS_R_NONCE_MISMATCH: c_int = 104;
/// `TS_R_TSA_NAME_MISMATCH` — `include/openssl/tserr.h`.
const TS_R_TSA_NAME_MISMATCH: c_int = 111;
/// `TS_R_TSA_UNTRUSTED` — `include/openssl/tserr.h`.
const TS_R_TSA_UNTRUSTED: c_int = 112;
/// `TS_R_NO_TIME_STAMP_TOKEN` — `include/openssl/tserr.h`.
const TS_R_NO_TIME_STAMP_TOKEN: c_int = 107;

/// `ts_status_text[]` — `ts_rsp_verify.c:50-57`.
static TS_STATUS_TEXT: [&CStr; 6] = [
    c"granted",
    c"grantedWithMods",
    c"rejection",
    c"waiting",
    c"revocationWarning",
    c"revocationNotification",
];

/// `ts_failure_info[]` — `ts_rsp_verify.c:61-73`.
static TS_FAILURE_INFO: [(c_int, &CStr); 8] = [
    (0, c"badAlg"),
    (2, c"badRequest"),
    (5, c"badDataFormat"),
    (14, c"timeNotAvailable"),
    (15, c"unacceptedPolicy"),
    (16, c"unacceptedExtension"),
    (17, c"addInfoNotAvailable"),
    (25, c"systemFailure"),
];

/// `memcmp` — hidden behind this file rather than a libc dependency, exactly as `ocsp_vfy.rs` does.
///
/// # Safety
/// `a` and `b` each point at `n` readable bytes.
unsafe fn memcmp(a: *const c_uchar, b: *const c_uchar, n: c_int) -> c_int {
    let mut i = 0;
    while i < n {
        // SAFETY: `0 <= i < n`, so both offsets are within the readable ranges.
        let (x, y) = unsafe { (*a.add(i as usize), *b.add(i as usize)) };
        if x != y {
            return c_int::from(x) - c_int::from(y);
        }
        i += 1;
    }
    0
}

/// `int TS_RESP_verify_signature(PKCS7 *token, STACK_OF(X509) *certs, X509_STORE *store, X509`
/// `**signer_out)` — `ts_rsp_verify.c:87-165`.
///
/// Checks there is exactly one signer, finds its certificate, builds and validates its chain under
/// the timestamping purpose, checks the `SigningCertificate` attribute, and verifies the signature.
/// On success and a non-NULL `signer_out`, the signer certificate's reference is incremented and
/// stored.
///
/// # Safety
/// `token` is NULL or a live `PKCS7`; `certs` is NULL or a live stack of `X509`; `store` is NULL or
/// a live store; `signer_out` is NULL or writable.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_verify_signature(
    token: *mut Pkcs7,
    certs: *mut OpenSslStack,
    store: *mut X509Store,
    signer_out: *mut *mut X509,
) -> c_int {
    let mut untrusted: *mut OpenSslStack = ptr::null_mut();
    let mut signers: *mut OpenSslStack = ptr::null_mut();
    let mut chain: *mut OpenSslStack = ptr::null_mut();
    let mut buf = [0 as c_char; 4096];
    let mut ret = 0;
    let mut p7bio: *mut Bio = ptr::null_mut();

    'err: {
        if token.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe {
                raise_ts(
                    FILE,
                    102,
                    c"TS_RESP_verify_signature",
                    TS_R_INVALID_NULL_POINTER,
                )
            };
            break 'err;
        }
        // SAFETY: `token` is live.
        if !pkcs7_type_is_signed(token) {
            // SAFETY: a compile-time coordinate.
            unsafe {
                raise_ts(
                    FILE,
                    106,
                    c"TS_RESP_verify_signature",
                    TS_R_WRONG_CONTENT_TYPE,
                )
            };
            break 'err;
        }
        // SAFETY: `token` is live.
        let sinfos = unsafe { PKCS7_get_signer_info(token) };
        if sinfos.is_null()
            // SAFETY: `sinfos` is live per the null check.
            || unsafe { OPENSSL_sk_num(sinfos) } != 1
        {
            // SAFETY: a compile-time coordinate.
            unsafe {
                raise_ts(
                    FILE,
                    111,
                    c"TS_RESP_verify_signature",
                    TS_R_THERE_MUST_BE_ONE_SIGNER,
                )
            };
            break 'err;
        }
        // SAFETY: `sinfos` holds exactly one element.
        let si = unsafe { OPENSSL_sk_value(sinfos, 0) }.cast::<Pkcs7SignerInfo>();
        // SAFETY: `token` is live.
        if pkcs7_get_detached(token) {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 116, c"TS_RESP_verify_signature", TS_R_NO_CONTENT) };
            break 'err;
        }

        // SAFETY: `token` and `certs` are NULL or live per the contract.
        signers = unsafe { PKCS7_get0_signers(token, certs, 0) };
        if signers.is_null()
            // SAFETY: `signers` is live per the null check.
            || unsafe { OPENSSL_sk_num(signers) } != 1
        {
            break 'err;
        }
        // SAFETY: `signers` holds exactly one element.
        let signer = unsafe { OPENSSL_sk_value(signers, 0) }.cast::<X509>();

        // SAFETY: `token` is live.
        let embedded = unsafe { (*(*token).d.sign).cert };
        // SAFETY: `certs` and `embedded` are NULL or live stacks; `sk_num` accepts NULL.
        let reserve = unsafe { OPENSSL_sk_num(certs) } + unsafe { OPENSSL_sk_num(embedded) };
        // SAFETY: no preconditions.
        untrusted = OPENSSL_sk_new_reserve(None, reserve);
        // SAFETY: the stacks are NULL or live per the contract.
        let mut add_ok = !untrusted.is_null();
        if add_ok {
            // SAFETY: `untrusted` and `certs` are NULL or live per the contract.
            add_ok = unsafe { X509_add_certs(untrusted, certs, 0) } != 0;
        }
        if add_ok {
            // SAFETY: `untrusted` and `embedded` are NULL or live per the contract.
            add_ok = unsafe { X509_add_certs(untrusted, embedded, 0) } != 0;
        }
        if !add_ok {
            break 'err;
        }
        // SAFETY: `store`, `untrusted` and `signer` are NULL or live per the contract.
        if unsafe { ts_verify_cert(store, untrusted, signer, &mut chain) } == 0 {
            break 'err;
        }
        // SAFETY: `si` and `chain` are live.
        if unsafe { ts_check_signing_certs(si, chain) } == 0 {
            break 'err;
        }
        // SAFETY: `token` is live; the NULL BIO is the authority's own argument.
        p7bio = unsafe { PKCS7_dataInit(token, ptr::null_mut()) };

        // We now have to 'read' from p7bio to calculate digests etc.
        // SAFETY: `p7bio` is live and `buf` is writable for its length.
        while unsafe { BIO_read(p7bio, buf.as_mut_ptr().cast(), buf.len() as c_int) } > 0 {
            continue;
        }

        // SAFETY: `p7bio`, `token`, `si` and `signer` are live.
        if unsafe { PKCS7_signatureVerify(p7bio, token, si, signer) } <= 0 {
            // SAFETY: a compile-time coordinate.
            unsafe {
                raise_ts(
                    FILE,
                    146,
                    c"TS_RESP_verify_signature",
                    TS_R_SIGNATURE_FAILURE,
                )
            };
            break 'err;
        }

        if !signer_out.is_null() {
            // SAFETY: `signer` is live.
            if unsafe { X509_up_ref(signer) } == 0 {
                break 'err;
            }
            // SAFETY: `signer_out` is writable per the contract.
            unsafe { *signer_out = signer };
        }
        ret = 1;
    }

    // SAFETY: each pointer is NULL or owned/borrowed per the authority's own cleanup.
    unsafe {
        BIO_free_all(p7bio);
        OPENSSL_sk_free(untrusted);
        OSSL_STACK_OF_X509_free(chain);
        OPENSSL_sk_free(signers);
    }

    ret
}

/// `static int ts_verify_cert(X509_STORE *store, STACK_OF(X509) *untrusted, X509 *signer,`
/// `STACK_OF(X509) **chain)` — `ts_rsp_verify.c:171-204`.
///
/// # Safety
/// `untrusted` and `signer` are live; `store` is NULL or live; `chain` is writable.
unsafe fn ts_verify_cert(
    store: *mut X509Store,
    untrusted: *mut OpenSslStack,
    signer: *mut X509,
    chain: *mut *mut OpenSslStack,
) -> c_int {
    // SAFETY: `chain` is writable per the contract.
    unsafe { *chain = ptr::null_mut() };
    let mut ret = 0;

    // SAFETY: no preconditions.
    let cert_ctx = X509_STORE_CTX_new();
    if cert_ctx.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 181, c"ts_verify_cert", ERR_R_X509_LIB) };
        return 0;
    }

    'end: {
        // SAFETY: `cert_ctx`, `store`, `signer` and `untrusted` are NULL or live per the contract.
        if unsafe { X509_STORE_CTX_init(cert_ctx, store, signer, untrusted) } == 0 {
            break 'end;
        }
        // SAFETY: `cert_ctx` is live.
        unsafe { X509_STORE_CTX_set_purpose(cert_ctx, X509_PURPOSE_TIMESTAMP_SIGN) };
        // SAFETY: `cert_ctx` is live.
        let i = unsafe { X509_verify_cert(cert_ctx) };
        if i <= 0 {
            // SAFETY: `cert_ctx` is live.
            let j = unsafe { X509_STORE_CTX_get_error(cert_ctx) };
            // SAFETY: `X509_verify_cert_error_string` answers a static C string; the message is
            // this frame's and NUL-terminated.
            let mut msg = [0 as c_char; 256];
            // SAFETY: `msg` is this frame's buffer and the format's `%s` argument is static.
            unsafe {
                BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"Verify error:%s".as_ptr(),
                    X509_verify_cert_error_string(j as c_long),
                );
                raise_ts_data(
                    FILE,
                    190,
                    c"ts_verify_cert",
                    TS_R_CERTIFICATE_VERIFY_ERROR,
                    msg.as_ptr(),
                );
            }
            break 'end;
        }
        // SAFETY: `cert_ctx` is live.
        unsafe { *chain = X509_STORE_CTX_get1_chain(cert_ctx) };
        ret = 1;
    }

    // SAFETY: `cert_ctx` is live and owned here.
    unsafe { X509_STORE_CTX_free(cert_ctx) };
    ret
}

/// `static ESS_SIGNING_CERT *ossl_ess_get_signing_cert(const PKCS7_SIGNER_INFO *si)` —
/// `ts_rsp_verify.c:206-216`.
///
/// # Safety
/// `si` is live.
unsafe fn ossl_ess_get_signing_cert(si: *const Pkcs7SignerInfo) -> *mut EssSigningCert {
    // SAFETY: `si` is live.
    let attr = unsafe { PKCS7_get_signed_attribute(si, NID_id_smime_aa_signingCertificate) };
    if attr.is_null()
        // SAFETY: `attr` is live per the null check.
        || unsafe { (*attr).type_ } != V_ASN1_SEQUENCE
    {
        return ptr::null_mut();
    }
    // SAFETY: `attr` is a live SEQUENCE; the union holds an `ASN1_STRING`.
    let seq = unsafe { (*attr).value.ptr }.cast::<Asn1String>();
    // SAFETY: `seq` is live.
    let mut p: *const c_uchar = unsafe { (*seq).data };
    // SAFETY: `p` is a readable cursor over `seq`'s content; the decode is bounded by the length.
    unsafe { d2i_ESS_SIGNING_CERT(ptr::null_mut(), &mut p, (*seq).length as c_long) }
}

/// `static ESS_SIGNING_CERT_V2 *ossl_ess_get_signing_cert_v2(const PKCS7_SIGNER_INFO *si)` —
/// `ts_rsp_verify.c:218-228`.
///
/// # Safety
/// `si` is live.
unsafe fn ossl_ess_get_signing_cert_v2(si: *const Pkcs7SignerInfo) -> *mut EssSigningCertV2 {
    // SAFETY: `si` is live.
    let attr = unsafe { PKCS7_get_signed_attribute(si, NID_id_smime_aa_signingCertificateV2) };
    if attr.is_null()
        // SAFETY: `attr` is live per the null check.
        || unsafe { (*attr).type_ } != V_ASN1_SEQUENCE
    {
        return ptr::null_mut();
    }
    // SAFETY: `attr` is a live SEQUENCE; the union holds an `ASN1_STRING`.
    let seq = unsafe { (*attr).value.ptr }.cast::<Asn1String>();
    // SAFETY: `seq` is live.
    let mut p: *const c_uchar = unsafe { (*seq).data };
    // SAFETY: `p` is a readable cursor over `seq`'s content; the decode is bounded by the length.
    unsafe { d2i_ESS_SIGNING_CERT_V2(ptr::null_mut(), &mut p, (*seq).length as c_long) }
}

/// `static int ts_check_signing_certs(const PKCS7_SIGNER_INFO *si, const STACK_OF(X509) *chain)` —
/// `ts_rsp_verify.c:230-240`.
///
/// # Safety
/// `si` is live; `chain` is live.
unsafe fn ts_check_signing_certs(si: *const Pkcs7SignerInfo, chain: *const OpenSslStack) -> c_int {
    // SAFETY: `si` is live.
    let ss = unsafe { ossl_ess_get_signing_cert(si) };
    // SAFETY: `si` is live.
    let ssv2 = unsafe { ossl_ess_get_signing_cert_v2(si) };
    // SAFETY: `ss`/`ssv2` are NULL or live, `chain` is live; the required-certificate flag is 1.
    let ret = c_int::from(unsafe { OSSL_ESS_check_signing_certs(ss, ssv2, chain, 1) } > 0);

    // SAFETY: `ss` is NULL or owned here.
    unsafe { ESS_SIGNING_CERT_free(ss) };
    // SAFETY: `ssv2` is NULL or owned here.
    unsafe { ESS_SIGNING_CERT_V2_free(ssv2) };
    ret
}

/// `int TS_RESP_verify_response(TS_VERIFY_CTX *ctx, TS_RESP *response)` —
/// `ts_rsp_verify.c:248-262`.
///
/// # Safety
/// `ctx` is live; `response` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_verify_response(
    ctx: *mut TsVerifyCtx,
    response: *mut TsResp,
) -> c_int {
    // SAFETY: `response` is live.
    let token = unsafe { (*response).token };
    // SAFETY: `response` is live.
    let tst_info = unsafe { (*response).tst_info };
    let mut ret = 0;

    // SAFETY: `response` is live.
    if unsafe { ts_check_status_info(response) } == 0 {
        return ret;
    }
    // SAFETY: `ctx`, `token` and `tst_info` are live.
    if unsafe { int_ts_RESP_verify_token(ctx, token, tst_info) } == 0 {
        return ret;
    }
    ret = 1;

    ret
}

/// `int TS_RESP_verify_token(TS_VERIFY_CTX *ctx, PKCS7 *token)` — `ts_rsp_verify.c:268-277`.
///
/// # Safety
/// `ctx` is live; `token` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_verify_token(
    ctx: *mut TsVerifyCtx,
    token: *mut Pkcs7,
) -> c_int {
    // SAFETY: `token` is live.
    let tst_info = unsafe { PKCS7_to_TS_TST_INFO(token) };
    let mut ret = 0;
    if !tst_info.is_null() {
        // SAFETY: `ctx`, `token` and `tst_info` are live.
        ret = unsafe { int_ts_RESP_verify_token(ctx, token, tst_info) };
        // SAFETY: `tst_info` is owned here.
        unsafe { super::ts_asn1::TS_TST_INFO_free(tst_info) };
    }
    ret
}

/// `static int int_ts_RESP_verify_token(TS_VERIFY_CTX *ctx, PKCS7 *token, TS_TST_INFO *tst_info)` —
/// `ts_rsp_verify.c:291-348`.
///
/// # Safety
/// `ctx` is live; `token` is live; `tst_info` is live.
unsafe fn int_ts_RESP_verify_token(
    ctx: *mut TsVerifyCtx,
    token: *mut Pkcs7,
    tst_info: *mut TsTstInfo,
) -> c_int {
    let mut signer: *mut X509 = ptr::null_mut();
    // SAFETY: `tst_info` is live.
    let tsa_name = unsafe { (*tst_info).tsa };
    let mut md_alg: *mut X509Algor = ptr::null_mut();
    let mut imprint: *mut c_uchar = ptr::null_mut();
    let mut imprint_len: c_uint = 0;
    let mut ret = 0;
    // SAFETY: `ctx` is live.
    let mut flags = unsafe { (*ctx).flags };

    // Some options require us to also check the signature.
    if ((flags & TS_VFY_SIGNER) != 0 && !tsa_name.is_null()) || (flags & TS_VFY_TSA_NAME) != 0 {
        flags |= TS_VFY_SIGNATURE;
    }

    'err: {
        // SAFETY: `ctx` is live.
        let (certs, store) = unsafe { ((*ctx).certs, (*ctx).store) };
        if (flags & TS_VFY_SIGNATURE) != 0
            // SAFETY: `token`, `certs` and `store` are NULL or live per the contract.
            && unsafe { TS_RESP_verify_signature(token, certs, store, &mut signer) } == 0
        {
            break 'err;
        }
        if (flags & TS_VFY_VERSION) != 0
            // SAFETY: `tst_info` is live.
            && unsafe { TS_TST_INFO_get_version(tst_info) } != 1
        {
            // SAFETY: a compile-time coordinate.
            unsafe {
                raise_ts(
                    FILE,
                    313,
                    c"int_ts_RESP_verify_token",
                    TS_R_UNSUPPORTED_VERSION,
                )
            };
            break 'err;
        }
        // SAFETY: `ctx` is live.
        let policy = unsafe { (*ctx).policy };
        if (flags & TS_VFY_POLICY) != 0
            // SAFETY: `policy` and `tst_info` are live.
            && unsafe { ts_check_policy(policy, tst_info) } == 0
        {
            break 'err;
        }
        // SAFETY: `ctx` is live.
        let (ctx_md_alg, ctx_imprint, ctx_imprint_len) =
            unsafe { ((*ctx).md_alg, (*ctx).imprint, (*ctx).imprint_len) };
        if (flags & TS_VFY_IMPRINT) != 0
            // SAFETY: the ctx pointers and `tst_info` are live; the imprint is readable for its
            // length.
            && unsafe { ts_check_imprints(ctx_md_alg, ctx_imprint, ctx_imprint_len, tst_info) } == 0
        {
            break 'err;
        }
        // SAFETY: `ctx` is live.
        let data = unsafe { (*ctx).data };
        if (flags & TS_VFY_DATA) != 0 {
            // SAFETY: `data` and `tst_info` are live; the out-pointers are writable locals.
            let computed = unsafe {
                ts_compute_imprint(data, tst_info, &mut md_alg, &mut imprint, &mut imprint_len)
            };
            if computed == 0
                // SAFETY: `md_alg` and `imprint` are live per the successful compute.
                || unsafe { ts_check_imprints(md_alg, imprint, imprint_len, tst_info) } == 0
            {
                break 'err;
            }
        }
        // SAFETY: `ctx` is live.
        let nonce = unsafe { (*ctx).nonce };
        if (flags & TS_VFY_NONCE) != 0
            // SAFETY: `nonce` and `tst_info` are live.
            && unsafe { ts_check_nonces(nonce, tst_info) } == 0
        {
            break 'err;
        }
        if (flags & TS_VFY_SIGNER) != 0
            && !tsa_name.is_null()
            // SAFETY: `signer` is live when the signature arm ran; `tsa_name` is live per the
            // null check.
            && unsafe { ts_check_signer_name(tsa_name, signer) } == 0
        {
            // SAFETY: a compile-time coordinate.
            unsafe {
                raise_ts(
                    FILE,
                    333,
                    c"int_ts_RESP_verify_token",
                    TS_R_TSA_NAME_MISMATCH,
                )
            };
            break 'err;
        }
        // SAFETY: `ctx` is live.
        let ctx_tsa_name = unsafe { (*ctx).tsa_name };
        if (flags & TS_VFY_TSA_NAME) != 0
            // SAFETY: `ctx_tsa_name` and `signer` are live.
            && unsafe { ts_check_signer_name(ctx_tsa_name, signer) } == 0
        {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 338, c"int_ts_RESP_verify_token", TS_R_TSA_UNTRUSTED) };
            break 'err;
        }
        ret = 1;
    }

    // SAFETY: each pointer is NULL or owned by this frame.
    unsafe {
        X509_free(signer);
        X509_ALGOR_free(md_alg);
        CRYPTO_free(imprint.cast(), FILE.as_ptr(), 346);
    }
    ret
}

/// `static int ts_check_status_info(TS_RESP *response)` — `ts_rsp_verify.c:350-397`.
///
/// # Safety
/// `response` is live and its `status_info` is live.
unsafe fn ts_check_status_info(response: *mut TsResp) -> c_int {
    // SAFETY: `response` is live.
    let info: *mut TsStatusInfo = unsafe { (*response).status_info };
    // SAFETY: `info` is live.
    let status = unsafe { ASN1_INTEGER_get((*info).status) };

    if status == 0 || status == 1 {
        return 1;
    }

    // There was an error, get the description in `status_text`.
    let status_text: *const c_char = if (0..TS_STATUS_TEXT.len() as c_long).contains(&status) {
        TS_STATUS_TEXT[status as usize].as_ptr()
    } else {
        c"unknown code".as_ptr()
    };

    let mut embedded_status_text: *mut c_char = ptr::null_mut();
    // SAFETY: `info` is live; its `text` is NULL or a live stack.
    if unsafe { OPENSSL_sk_num((*info).text) } > 0 {
        // SAFETY: `info`'s text stack is live.
        embedded_status_text = unsafe { ts_get_status_text((*info).text) };
        if embedded_status_text.is_null() {
            return 0;
        }
    }

    // Fill in `failure_text` with the failure information.
    let mut failure_text = [0 as c_char; TS_STATUS_BUF_SIZE];
    let mut used: usize = 0;
    // SAFETY: `info` is live.
    let failure_info = unsafe { (*info).failure_info };
    if !failure_info.is_null() {
        let mut first = true;
        for (code, text) in TS_FAILURE_INFO {
            // SAFETY: `failure_info` is live.
            if unsafe { ASN1_BIT_STRING_get_bit(failure_info, code) } != 0 {
                if !first {
                    failure_text[used] = b',' as c_char;
                    used += 1;
                } else {
                    first = false;
                }
                // SAFETY: the borrowed C string is NUL-terminated.
                let bytes = text.to_bytes();
                failure_text[used..used + bytes.len()].copy_from_slice(
                    // SAFETY: the borrow is live for the copy.
                    unsafe { core::slice::from_raw_parts(text.as_ptr(), bytes.len()) },
                );
                used += bytes.len();
            }
        }
    }
    let failure_text: *const c_char = if used == 0 {
        c"unspecified".as_ptr()
    } else {
        failure_text[used] = 0;
        failure_text.as_mut_ptr()
    };

    // SAFETY: `BIO_snprintf` writes a NUL-terminated message; `embedded_status_text` is NULL or a
    // live C string, so the `%s` arguments are both valid.
    let mut msg = [0 as c_char; 1024];
    // SAFETY: `BIO_snprintf` writes a NUL-terminated message; the `%s` arguments are live C
    // strings, and `raise_ts_data`/`CRYPTO_free` are the authority's own paths.
    unsafe {
        BIO_snprintf(
            msg.as_mut_ptr(),
            msg.len(),
            c"status code: %s, status text: %s, failure codes: %s".as_ptr(),
            status_text,
            if embedded_status_text.is_null() {
                c"unspecified".as_ptr()
            } else {
                embedded_status_text
            },
            failure_text,
        );
        raise_ts_data(
            FILE,
            389,
            c"ts_check_status_info",
            TS_R_NO_TIME_STAMP_TOKEN,
            msg.as_ptr(),
        );
        CRYPTO_free(embedded_status_text.cast(), FILE.as_ptr(), 394);
    }

    0
}

/// `static char *ts_get_status_text(STACK_OF(ASN1_UTF8STRING) *text)` — `ts_rsp_verify.c:399-402`.
///
/// # Safety
/// `text` is live.
unsafe fn ts_get_status_text(text: *mut OpenSslStack) -> *mut c_char {
    // SAFETY: `text` is a live stack of live UTF8 strings; the separator and cap are constants.
    unsafe { ossl_sk_ASN1_UTF8STRING2text(text, c"/".as_ptr(), TS_MAX_STATUS_LENGTH) }
}

/// `static int ts_check_policy(const ASN1_OBJECT *req_oid, const TS_TST_INFO *tst_info)` —
/// `ts_rsp_verify.c:404-415`.
///
/// # Safety
/// `req_oid` and `tst_info` are live.
unsafe fn ts_check_policy(req_oid: *const Asn1Object, tst_info: *const TsTstInfo) -> c_int {
    // SAFETY: `tst_info` is live.
    let resp_oid = unsafe { (*tst_info).policy_id };

    // SAFETY: `req_oid` and `resp_oid` are live.
    if unsafe { OBJ_cmp(req_oid, resp_oid) } != 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 410, c"ts_check_policy", TS_R_POLICY_MISMATCH) };
        return 0;
    }

    1
}

/// `static int ts_compute_imprint(BIO *data, TS_TST_INFO *tst_info, X509_ALGOR **md_alg, unsigned`
/// `char **imprint, unsigned *imprint_len)` — `ts_rsp_verify.c:417-483`.
///
/// # Safety
/// `data` and `tst_info` are live; `md_alg`, `imprint` and `imprint_len` are writable.
unsafe fn ts_compute_imprint(
    data: *mut Bio,
    tst_info: *mut TsTstInfo,
    md_alg: *mut *mut X509Algor,
    imprint: *mut *mut c_uchar,
    imprint_len: *mut c_uint,
) -> c_int {
    // SAFETY: `tst_info` is live.
    let msg_imprint = unsafe { (*tst_info).msg_imprint };
    // SAFETY: `msg_imprint` is live.
    let md_alg_resp = unsafe { (*msg_imprint).hash_algo };
    let mut md: *mut EvpMd = ptr::null_mut();
    let mut md_ctx: *mut EvpMdCtx = ptr::null_mut();
    let mut buffer = [0 as c_uchar; 4096];
    let mut name = [0 as c_char; OSSL_MAX_NAME_SIZE];

    // SAFETY: the out-pointers are writable per the contract.
    unsafe {
        *md_alg = ptr::null_mut();
        *imprint = ptr::null_mut();
    }

    // SAFETY: `md_alg_resp` is live.
    unsafe { *md_alg = X509_ALGOR_dup(md_alg_resp) };
    // SAFETY: the out-pointer is writable.
    if unsafe { *md_alg }.is_null() {
        // SAFETY: the err arm releases the owners of every pointer per its contract.
        return unsafe { ts_compute_imprint_err(md_alg, imprint, imprint_len, md, md_ctx) };
    }

    // SAFETY: `name` is writable for its length and `md_alg_resp` is live.
    unsafe {
        OBJ_obj2txt(
            name.as_mut_ptr(),
            name.len() as c_int,
            (*md_alg_resp).algorithm,
            0,
        );
    }

    // SAFETY: the mark operations are this thread's error queue.
    ERR_set_mark();
    // SAFETY: `name` is NUL-terminated; the fetch's two context arguments are NULL.
    md = unsafe { EVP_MD_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };

    if md.is_null() {
        // SAFETY: `name` is NUL-terminated.
        md = unsafe { EVP_get_digestbyname(name.as_ptr()) }.cast_mut();
    }

    if md.is_null() {
        // SAFETY: the mark operations are this thread's error queue.
        ERR_clear_last_mark();
        // SAFETY: the err arm releases the owners of every pointer per its contract.
        return unsafe { ts_compute_imprint_err(md_alg, imprint, imprint_len, md, md_ctx) };
    }
    // SAFETY: the mark operations are this thread's error queue.
    ERR_pop_to_mark();

    // SAFETY: `md` is live.
    let length = unsafe { EVP_MD_get_size(md) };
    if length <= 0 {
        // SAFETY: the err arm releases the owners of every pointer per its contract.
        return unsafe { ts_compute_imprint_err(md_alg, imprint, imprint_len, md, md_ctx) };
    }
    // SAFETY: the out-pointer is writable.
    unsafe { *imprint_len = length as c_uint };
    // SAFETY: the allocation is `OPENSSL_malloc(*imprint_len)` at `:453`.
    let fresh = CRYPTO_malloc(length as usize, FILE.as_ptr(), 453).cast::<c_uchar>();
    // SAFETY: the out-pointer is writable.
    unsafe { *imprint = fresh };
    if fresh.is_null() {
        // SAFETY: the err arm releases the owners of every pointer per its contract.
        return unsafe { ts_compute_imprint_err(md_alg, imprint, imprint_len, md, md_ctx) };
    }

    // SAFETY: no preconditions.
    md_ctx = EVP_MD_CTX_new();
    if md_ctx.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe {
            raise_ts(FILE, 458, c"ts_compute_imprint", ERR_R_EVP_LIB);
        }
        // SAFETY: the err arm releases the owners of every pointer per its contract.
        return unsafe { ts_compute_imprint_err(md_alg, imprint, imprint_len, md, md_ctx) };
    }
    // SAFETY: `md_ctx` and `md` are live.
    if unsafe { EVP_DigestInit(md_ctx, md) } == 0 {
        // SAFETY: the err arm releases the owners of every pointer per its contract.
        return unsafe { ts_compute_imprint_err(md_alg, imprint, imprint_len, md, md_ctx) };
    }
    // SAFETY: `md` is owned here.
    unsafe { EVP_MD_free(md) };
    md = ptr::null_mut();
    loop {
        // SAFETY: `data` is live and `buffer` is writable for its length.
        let n = unsafe { BIO_read(data, buffer.as_mut_ptr().cast(), buffer.len() as c_int) };
        if n <= 0 {
            break;
        }
        // SAFETY: `md_ctx` is live and `buffer` holds `n` readable bytes.
        if unsafe { EVP_DigestUpdate(md_ctx, buffer.as_ptr().cast(), n as usize) } == 0 {
            // SAFETY: the err arm releases the owners of every pointer per its contract.
            return unsafe { ts_compute_imprint_err(md_alg, imprint, imprint_len, md, md_ctx) };
        }
    }
    // SAFETY: `md_ctx` is live and the out-pointer is writable.
    if unsafe { EVP_DigestFinal(md_ctx, *imprint, ptr::null_mut()) } == 0 {
        // SAFETY: the err arm releases the owners of every pointer per its contract.
        return unsafe { ts_compute_imprint_err(md_alg, imprint, imprint_len, md, md_ctx) };
    }
    // SAFETY: `md_ctx` is owned here.
    unsafe { EVP_MD_CTX_free(md_ctx) };

    1
}

/// The `err:` arm of [`ts_compute_imprint`] — `ts_rsp_verify.c:474-482`.
///
/// # Safety
/// `md_ctx` is NULL or live; `md` is NULL or live; the out-pointers are writable.
unsafe fn ts_compute_imprint_err(
    md_alg: *mut *mut X509Algor,
    imprint: *mut *mut c_uchar,
    imprint_len: *mut c_uint,
    md: *mut EvpMd,
    md_ctx: *mut EvpMdCtx,
) -> c_int {
    // SAFETY: each pointer is NULL or owned by the caller of [`ts_compute_imprint`].
    unsafe {
        EVP_MD_CTX_free(md_ctx);
        EVP_MD_free(md);
        X509_ALGOR_free(*md_alg);
        *md_alg = ptr::null_mut();
        CRYPTO_free((*imprint).cast(), FILE.as_ptr(), 479);
        *imprint_len = 0;
        *imprint = ptr::null_mut();
    }
    0
}

/// `static int ts_check_imprints(X509_ALGOR *algor_a, const unsigned char *imprint_a, unsigned`
/// `len_a, TS_TST_INFO *tst_info)` — `ts_rsp_verify.c:485-510`.
///
/// # Safety
/// `algor_a` is NULL or live; `imprint_a` is readable for `len_a` bytes; `tst_info` is live.
unsafe fn ts_check_imprints(
    algor_a: *mut X509Algor,
    imprint_a: *const c_uchar,
    len_a: c_uint,
    tst_info: *mut TsTstInfo,
) -> c_int {
    // SAFETY: `tst_info` is live.
    let b: *mut TsMsgImprint = unsafe { (*tst_info).msg_imprint };
    // SAFETY: `b` is live.
    let algor_b = unsafe { (*b).hash_algo };
    let mut ret = 0;

    let mut mismatch = false;
    if !algor_a.is_null() {
        // SAFETY: `algor_a` and `algor_b` are live.
        if unsafe { OBJ_cmp((*algor_a).algorithm, (*algor_b).algorithm) } != 0 {
            mismatch = true;
        } else {
            // SAFETY: the parameters are NULL or live.
            let bad = unsafe {
                (!(*algor_a).parameter.is_null()
                    && ASN1_TYPE_get((*algor_a).parameter) != V_ASN1_NULL)
                    || (!(*algor_b).parameter.is_null()
                        && ASN1_TYPE_get((*algor_b).parameter) != V_ASN1_NULL)
            };
            if bad {
                mismatch = true;
            }
        }
    }

    if !mismatch {
        // SAFETY: `b` is live.
        let hashed = unsafe { (*b).hashed_msg };
        // SAFETY: `hashed` is live.
        let hash_len = unsafe { ASN1_STRING_length(hashed) };
        ret = c_int::from(
            len_a as c_int == hash_len
                // SAFETY: `imprint_a` is readable for `len_a` and `hashed` holds `len_a` bytes.
                && unsafe {
                    memcmp(imprint_a, ASN1_STRING_get0_data(hashed), len_a as c_int)
                } == 0,
        );
    }

    if ret == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe {
            raise_ts(
                FILE,
                508,
                c"ts_check_imprints",
                TS_R_MESSAGE_IMPRINT_MISMATCH,
            )
        };
    }
    ret
}

/// `static int ts_check_nonces(const ASN1_INTEGER *a, TS_TST_INFO *tst_info)` —
/// `ts_rsp_verify.c:512-528`.
///
/// # Safety
/// `a` is live; `tst_info` is live.
unsafe fn ts_check_nonces(a: *const Asn1String, tst_info: *mut TsTstInfo) -> c_int {
    // SAFETY: `tst_info` is live.
    let b = unsafe { (*tst_info).nonce };

    if b.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 517, c"ts_check_nonces", TS_R_NONCE_NOT_RETURNED) };
        return 0;
    }

    // SAFETY: `a` and `b` are live.
    if unsafe { ASN1_INTEGER_cmp(a, b) } != 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 523, c"ts_check_nonces", TS_R_NONCE_MISMATCH) };
        return 0;
    }

    1
}

/// `static int ts_check_signer_name(GENERAL_NAME *tsa_name, X509 *signer)` —
/// `ts_rsp_verify.c:534-558`.
///
/// # Safety
/// `tsa_name` is live; `signer` is live.
unsafe fn ts_check_signer_name(tsa_name: *mut GeneralName, signer: *mut X509) -> c_int {
    let mut idx = -1;
    let mut found = 0;

    // SAFETY: `tsa_name` is live.
    if unsafe { (*tsa_name).type_ } == GEN_DIRNAME
        // SAFETY: the directory name and the signer's subject are live.
        && unsafe { X509_NAME_cmp((*tsa_name).d.directoryName, X509_get_subject_name(signer)) } == 0
    {
        return 1;
    }
    // SAFETY: `signer` is live and `idx` is writable.
    let mut gen_names =
        unsafe { X509_get_ext_d2i(signer, NID_subject_alt_name, ptr::null_mut(), &mut idx) }
            .cast::<OpenSslStack>();
    while !gen_names.is_null() {
        // SAFETY: `gen_names` is live and `tsa_name` is live.
        found = c_int::from(unsafe { ts_find_name(gen_names, tsa_name) } >= 0);
        if found != 0 {
            break;
        }
        // Get the next subject alternative name, although there should be no more than one.
        // SAFETY: `gen_names` is live and owned here.
        unsafe { GENERAL_NAMES_free(gen_names) };
        // SAFETY: `signer` is live and `idx` is writable.
        gen_names =
            unsafe { X509_get_ext_d2i(signer, NID_subject_alt_name, ptr::null_mut(), &mut idx) }
                .cast::<OpenSslStack>();
    }
    // SAFETY: `gen_names` is NULL or owned here.
    unsafe { GENERAL_NAMES_free(gen_names) };

    found
}

/// `static int ts_find_name(STACK_OF(GENERAL_NAME) *gen_names, GENERAL_NAME *name)` —
/// `ts_rsp_verify.c:561-569`.
///
/// # Safety
/// `gen_names` is live; `name` is live.
unsafe fn ts_find_name(gen_names: *mut OpenSslStack, name: *mut GeneralName) -> c_int {
    let mut i = 0;
    let mut found = 0;
    // SAFETY: `gen_names` is live.
    while found == 0 && i < unsafe { OPENSSL_sk_num(gen_names) } {
        // SAFETY: `i` is in range of the live stack.
        let current = unsafe { OPENSSL_sk_value(gen_names, i) }.cast::<GeneralName>();
        // SAFETY: `current` and `name` are live.
        found = c_int::from(unsafe { GENERAL_NAME_cmp(current, name) } == 0);
        i += 1;
    }
    if found != 0 {
        i - 1
    } else {
        -1
    }
}
