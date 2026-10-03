//! `crypto/ts/ts_rsp_sign.c` — the response-generation engine. Phase 12.5.
//!
//! The `TS_RESP_CTX` object model: its allocation and release, the signer certificate/key/digest
//! and certificate-chain setters, the acceptable-policy and acceptable-digest stacks, the accuracy
//! triple and the clock-precision control, the three callbacks and their default implementations,
//! the flags, and the status/failure mutators.
//!
//! Phase 12.5b lands the response builder itself: `TS_RESP_create_response` (`:373-423`) and the
//! statics it reaches — `ts_RESP_CTX_init`/`_cleanup` (`:426-442`), `ts_RESP_check_request`
//! (`:445-498`), `ts_RESP_get_policy` (`:501-528`), `ts_RESP_create_tst_info` (`:531-608`),
//! `ts_RESP_process_extensions` (`:611-629`), `ossl_ess_add1_signing_cert[_v2]` (`:632-684`),
//! `ts_RESP_sign` (`:686-801`), `ts_TST_INFO_content_new` (`:803-828`) and
//! `TS_RESP_set_genTime_with_precision` (`:830-896`). It waited on 12.7's ESS item group and its
//! `OSSL_ESS_signing_cert[_v2]_new_init` builders, which `ts_RESP_sign` reaches through the
//! `SigningCertificate` signed attribute.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_get, ASN1_TYPE_new, ASN1_TYPE_set};
use crate::asn1::bitstr::ASN1_BIT_STRING_set_bit;
use crate::asn1::layout::{
    Asn1String, V_ASN1_NULL, V_ASN1_OBJECT, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE,
};
use crate::asn1::prim::{ASN1_INTEGER_get, ASN1_INTEGER_set, ASN1_OBJECT_free};
use crate::asn1::string::{
    ASN1_BIT_STRING_new, ASN1_GENERALIZEDTIME_free, ASN1_GENERALIZEDTIME_new, ASN1_INTEGER_free,
    ASN1_INTEGER_new, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_STRING_free,
    ASN1_STRING_new, ASN1_STRING_set, ASN1_UTF8STRING_free, ASN1_UTF8STRING_new,
};
use crate::asn1::time::ASN1_GENERALIZEDTIME_set_string;
use crate::ess::ess_asn1::{
    i2d_ESS_SIGNING_CERT, i2d_ESS_SIGNING_CERT_V2, ESS_SIGNING_CERT_V2_free, ESS_SIGNING_CERT_free,
    EssSigningCert, EssSigningCertV2,
};
use crate::ess::ess_lib::{OSSL_ESS_signing_cert_new_init, OSSL_ESS_signing_cert_v2_new_init};
use crate::evp::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EVP_MD_get0_provider, EVP_MD_get_size,
    EVP_MD_is_a, EvpMd,
};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref, EvpPkey};
use crate::pkcs7::pk7_asn1::{PKCS7_free, PKCS7_new, PKCS7_new_ex, Pkcs7, Pkcs7SignerInfo};
use crate::pkcs7::pk7_doit::{PKCS7_add_signed_attribute, PKCS7_dataFinal, PKCS7_dataInit};
use crate::pkcs7::pk7_lib::{
    PKCS7_add_certificate, PKCS7_add_signature, PKCS7_set_content, PKCS7_set_type,
};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::sys::{gettimeofday, Timeval};
use crate::runtime::bio::{BIO_free_all, Bio};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::{
    Asn1Object, NID_id_smime_aa_signingCertificate, NID_id_smime_aa_signingCertificateV2,
    NID_id_smime_ct_TSTInfo, NID_pkcs7_signed, NID_pkcs9_contentType, OBJ_cmp, OBJ_dup,
    OBJ_nid2obj, OBJ_obj2txt,
};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::time::{OPENSSL_gmtime, TimeT, Tm};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::v3_genn::{GENERAL_NAME_free, GENERAL_NAME_new, GeneralName, GEN_DIRNAME};
use crate::x509::v3_purp::X509_check_purpose;
use crate::x509::x509_cmp::{X509_chain_up_ref, X509_check_private_key, X509_get_subject_name};
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_exten::X509Extension;
use crate::x509::x_name::X509_NAME_dup;
use crate::x509::x_x509::{X509_free, X509};

use super::ts_asn1::{
    d2i_TS_REQ_bio, i2d_TS_TST_INFO_bio, TS_ACCURACY_free, TS_ACCURACY_new, TS_REQ_free,
    TS_RESP_free, TS_RESP_new, TS_STATUS_INFO_free, TS_TST_INFO_free, TS_TST_INFO_new, TsAccuracy,
    TsReq, TsResp, TsTstInfo,
};
use super::ts_req_utils::TS_REQ_get_version;
use super::ts_rsp_utils::{
    TS_ACCURACY_set_micros, TS_ACCURACY_set_millis, TS_ACCURACY_set_seconds,
    TS_RESP_set_status_info, TS_TST_INFO_set_accuracy, TS_TST_INFO_set_msg_imprint,
    TS_TST_INFO_set_nonce, TS_TST_INFO_set_ordering, TS_TST_INFO_set_policy_id,
    TS_TST_INFO_set_serial, TS_TST_INFO_set_time, TS_TST_INFO_set_tsa, TS_TST_INFO_set_version,
};
use super::{
    raise_ts, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, ERR_R_OBJ_LIB, ERR_R_PKCS7_LIB, ERR_R_TS_LIB,
};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ts/ts_rsp_sign.c";

/// `X509_PURPOSE_TIMESTAMP_SIGN` — `include/openssl/x509v3.h`.
const X509_PURPOSE_TIMESTAMP_SIGN: c_int = 9;

/// `TS_MAX_CLOCK_PRECISION_DIGITS` — `include/openssl/ts.h:312`.
const TS_MAX_CLOCK_PRECISION_DIGITS: u32 = 6;
/// `TS_STATUS_GRANTED` — `include/openssl/ts.h:48`.
const TS_STATUS_GRANTED: c_int = 0;
/// `TS_STATUS_REJECTION` — `include/openssl/ts.h:50`.
const TS_STATUS_REJECTION: c_int = 2;
/// `TS_INFO_TIME_NOT_AVAILABLE` — `include/openssl/ts.h:59`.
const TS_INFO_TIME_NOT_AVAILABLE: c_int = 14;
/// `TS_INFO_BAD_ALG` — `include/openssl/ts.h:56`.
const TS_INFO_BAD_ALG: c_int = 0;
/// `TS_INFO_BAD_REQUEST` — `include/openssl/ts.h:57`.
const TS_INFO_BAD_REQUEST: c_int = 2;
/// `TS_INFO_BAD_DATA_FORMAT` — `include/openssl/ts.h:58`.
const TS_INFO_BAD_DATA_FORMAT: c_int = 5;
/// `TS_INFO_UNACCEPTED_POLICY` — `include/openssl/ts.h:60`.
const TS_INFO_UNACCEPTED_POLICY: c_int = 15;
/// `TS_INFO_UNACCEPTED_EXTENSION` — `include/openssl/ts.h:61`.
const TS_INFO_UNACCEPTED_EXTENSION: c_int = 16;

/// `TS_TSA_NAME` — `include/openssl/ts.h:232`.
const TS_TSA_NAME: u32 = 0x01;
/// `TS_ORDERING` — `include/openssl/ts.h:235`.
const TS_ORDERING: u32 = 0x02;
/// `TS_ESS_CERT_ID_CHAIN` — `include/openssl/ts.h:242`.
const TS_ESS_CERT_ID_CHAIN: u32 = 0x04;

/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `SN_sha1` — `include/openssl/obj_mac.h`.
#[allow(non_upper_case_globals)]
const SN_sha1: &core::ffi::CStr = c"SHA1";

/// `TS_R_TIME_SYSCALL_ERROR` — `include/openssl/tserr.h`.
const TS_R_TIME_SYSCALL_ERROR: c_int = 122;
/// `TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE` — `include/openssl/tserr.h`.
const TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE: c_int = 117;
/// `TS_R_INVALID_NULL_POINTER` — `include/openssl/tserr.h`.
const TS_R_INVALID_NULL_POINTER: c_int = 102;
/// `TS_R_RESPONSE_SETUP_ERROR` — `include/openssl/tserr.h`.
const TS_R_RESPONSE_SETUP_ERROR: c_int = 121;
/// `TS_R_UNACCEPTABLE_POLICY` — `include/openssl/tserr.h`.
const TS_R_UNACCEPTABLE_POLICY: c_int = 125;
/// `TS_R_TST_INFO_SETUP_ERROR` — `include/openssl/tserr.h`.
const TS_R_TST_INFO_SETUP_ERROR: c_int = 123;
/// `TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE` — `include/openssl/tserr.h`.
const TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE: c_int = 120;
/// `TS_R_PKCS7_ADD_SIGNATURE_ERROR` — `include/openssl/tserr.h`.
const TS_R_PKCS7_ADD_SIGNATURE_ERROR: c_int = 118;
/// `TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR` — `include/openssl/tserr.h`.
const TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR: c_int = 119;
/// `TS_R_ESS_ADD_SIGNING_CERT_ERROR` — `include/openssl/tserr.h`.
const TS_R_ESS_ADD_SIGNING_CERT_ERROR: c_int = 116;
/// `TS_R_ESS_ADD_SIGNING_CERT_V2_ERROR` — `include/openssl/tserr.h`.
const TS_R_ESS_ADD_SIGNING_CERT_V2_ERROR: c_int = 139;
/// `TS_R_TS_DATASIGN` — `include/openssl/tserr.h`.
const TS_R_TS_DATASIGN: c_int = 124;
/// `TS_R_COULD_NOT_SET_TIME` — `include/openssl/tserr.h`.
const TS_R_COULD_NOT_SET_TIME: c_int = 115;

/// `TS_serial_cb` — `include/openssl/ts.h:248`.
pub(crate) type TsSerialCb = unsafe extern "C" fn(*mut TsRespCtx, *mut c_void) -> *mut Asn1String;
/// `TS_time_cb` — `include/openssl/ts.h:255-256`.
pub(crate) type TsTimeCb =
    unsafe extern "C" fn(*mut TsRespCtx, *mut c_void, *mut c_long, *mut c_long) -> c_int;
/// `TS_extension_cb` — `include/openssl/ts.h:263-264`.
pub(crate) type TsExtensionCb =
    unsafe extern "C" fn(*mut TsRespCtx, *mut X509Extension, *mut c_void) -> c_int;

/// `TS_resp_ctx` — `ts_local.h:101-129`.
#[repr(C)]
pub(crate) struct TsRespCtx {
    pub(crate) signer_cert: *mut X509,
    pub(crate) signer_key: *mut EvpPkey,
    pub(crate) signer_md: *const EvpMd,
    pub(crate) ess_cert_id_digest: *const EvpMd,
    pub(crate) certs: *mut OpenSslStack,
    pub(crate) policies: *mut OpenSslStack,
    pub(crate) default_policy: *mut Asn1Object,
    pub(crate) mds: *mut OpenSslStack,
    pub(crate) seconds: *mut Asn1String,
    pub(crate) millis: *mut Asn1String,
    pub(crate) micros: *mut Asn1String,
    pub(crate) clock_precision_digits: u32,
    pub(crate) flags: u32,
    pub(crate) serial_cb: Option<TsSerialCb>,
    pub(crate) serial_cb_data: *mut c_void,
    pub(crate) time_cb: Option<TsTimeCb>,
    pub(crate) time_cb_data: *mut c_void,
    pub(crate) extension_cb: Option<TsExtensionCb>,
    pub(crate) extension_cb_data: *mut c_void,
    pub(crate) request: *mut TsReq,
    pub(crate) response: *mut TsResp,
    pub(crate) tst_info: *mut TsTstInfo,
    pub(crate) libctx: *mut c_void,
    pub(crate) propq: *mut core::ffi::c_char,
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `ASN1_OBJECT_free`.
///
/// # Safety
/// `p` is an `ASN1_OBJECT` per the stack's element type.
unsafe extern "C" fn asn1_object_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { ASN1_OBJECT_free(p.cast()) };
}

// ---------------------------------------------------------------------------------------------
// The default callbacks
// ---------------------------------------------------------------------------------------------

/// `def_serial_cb(struct TS_resp_ctx *ctx, void *data)` — `ts_rsp_sign.c:43-59`.
///
/// # Safety
/// `ctx` is live; `_data` is unused.
unsafe extern "C" fn def_serial_cb(ctx: *mut TsRespCtx, _data: *mut c_void) -> *mut Asn1String {
    // SAFETY: no preconditions.
    let serial = ASN1_INTEGER_new();
    if serial.is_null() {
        // SAFETY: the err: arm releases the serial per the authority.
        return unsafe { def_serial_err(ctx, serial) };
    }
    // SAFETY: `serial` is live.
    if unsafe { ASN1_INTEGER_set(serial, 1) } == 0 {
        // SAFETY: the err: arm releases the serial per the authority.
        return unsafe { def_serial_err(ctx, serial) };
    }
    serial
}

/// The `err:` arm shared by `def_serial_cb`'s two failure paths.
///
/// # Safety
/// `ctx` is live; `serial` is NULL or live.
unsafe fn def_serial_err(ctx: *mut TsRespCtx, serial: *mut Asn1String) -> *mut Asn1String {
    // SAFETY: a compile-time coordinate.
    unsafe { raise_ts(FILE, 54, c"def_serial_cb", ERR_R_ASN1_LIB) };
    // SAFETY: `ctx` is live.
    unsafe {
        TS_RESP_CTX_set_status_info(
            ctx,
            TS_STATUS_REJECTION,
            c"Error during serial number generation.".as_ptr(),
        )
    };
    // SAFETY: `serial` is NULL or live.
    unsafe { ASN1_INTEGER_free(serial) };
    ptr::null_mut()
}

/// `OSSL_TIME` — `internal/time.h:26-28`. Nanoseconds since the epoch.
#[repr(transparent)]
struct OsslTime(u64);

/// `OSSL_TIME_US` — `internal/time.h:37`.
const OSSL_TIME_US: u64 = 1000;

/// `ossl_time_now()` — `crypto/time.c:15-48`, the non-Windows arm. Private to this unit because
/// `crypto/time.c` is not a landed stratum file; `ct_policy.rs` and `bss_dgram.rs` carry their own
/// copies of the same shape.
fn ossl_time_now() -> OsslTime {
    let mut tv = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a live local and the timezone argument is NULL.
    if unsafe { gettimeofday(&mut tv, ptr::null_mut()) } < 0 {
        return OsslTime(0);
    }
    if tv.tv_sec <= 0 {
        return if tv.tv_usec <= 0 {
            OsslTime(0)
        } else {
            OsslTime((tv.tv_usec as u64).wrapping_mul(OSSL_TIME_US))
        };
    }
    OsslTime(
        ((tv.tv_sec as u64)
            .wrapping_mul(1_000_000)
            .wrapping_add(tv.tv_usec as u64))
        .wrapping_mul(OSSL_TIME_US),
    )
}

/// `ossl_time_to_timeval(OSSL_TIME t)` — `internal/time.h:90-110`.
fn ossl_time_to_timeval(t: OsslTime) -> Timeval {
    let rounded = t.0.saturating_add(OSSL_TIME_US - 1);
    Timeval {
        tv_sec: (rounded / 1_000_000_000) as c_long,
        tv_usec: ((rounded % 1_000_000_000) / OSSL_TIME_US) as c_long,
    }
}

/// `def_time_cb(struct TS_resp_ctx *ctx, void *data, long *sec, long *usec)` —
/// `ts_rsp_sign.c:61-80`.
///
/// # Safety
/// `ctx` is live; `sec`/`usec` are writable.
unsafe extern "C" fn def_time_cb(
    ctx: *mut TsRespCtx,
    _data: *mut c_void,
    sec: *mut c_long,
    usec: *mut c_long,
) -> c_int {
    let t = ossl_time_now();
    if t.0 == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 69, c"def_time_cb", TS_R_TIME_SYSCALL_ERROR) };
        // SAFETY: `ctx` is live.
        unsafe {
            TS_RESP_CTX_set_status_info(
                ctx,
                TS_STATUS_REJECTION,
                c"Time is not available.".as_ptr(),
            )
        };
        // SAFETY: `ctx` is live.
        unsafe { TS_RESP_CTX_add_failure_info(ctx, TS_INFO_TIME_NOT_AVAILABLE) };
        return 0;
    }
    let tv = ossl_time_to_timeval(t);
    // SAFETY: `sec`/`usec` are writable per the contract.
    unsafe {
        *sec = tv.tv_sec;
        *usec = tv.tv_usec;
    }
    1
}

/// `def_extension_cb(struct TS_resp_ctx *ctx, X509_EXTENSION *ext, void *data)` —
/// `ts_rsp_sign.c:82-89`.
///
/// # Safety
/// `ctx` is live; `_ext`/`_data` are unused.
unsafe extern "C" fn def_extension_cb(
    ctx: *mut TsRespCtx,
    _ext: *mut X509Extension,
    _data: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION, c"Unsupported extension.".as_ptr())
    };
    // SAFETY: `ctx` is live.
    unsafe { TS_RESP_CTX_add_failure_info(ctx, TS_INFO_UNACCEPTED_EXTENSION) };
    0
}

// ---------------------------------------------------------------------------------------------
// TS_RESP_CTX management
// ---------------------------------------------------------------------------------------------

/// `TS_RESP_CTX *TS_RESP_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `ts_rsp_sign.c:93-113`.
///
/// # Safety
/// `_libctx` is NULL or live; `propq` is NULL or NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_new_ex(
    _libctx: *mut c_void,
    propq: *const core::ffi::c_char,
) -> *mut TsRespCtx {
    // SAFETY: `OPENSSL_zalloc` on a positive size.
    let ctx: *mut TsRespCtx =
        CRYPTO_zalloc(core::mem::size_of::<TsRespCtx>(), FILE.as_ptr(), 97).cast();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated.
        let dup = unsafe { CRYPTO_strdup(propq, FILE.as_ptr(), 101) };
        if dup.is_null() {
            // SAFETY: `ctx` is an `OPENSSL_zalloc` allocation.
            unsafe { CRYPTO_free(ctx.cast(), FILE.as_ptr(), 103) };
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).propq = dup };
    }
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).libctx = _libctx;
        (*ctx).serial_cb = Some(def_serial_cb);
        (*ctx).time_cb = Some(def_time_cb);
        (*ctx).extension_cb = Some(def_extension_cb);
    }

    ctx
}

/// `TS_RESP_CTX *TS_RESP_CTX_new(void)` — `ts_rsp_sign.c:115-118`.
///
/// # Safety
/// The returned pointer must be released with [`TS_RESP_CTX_free`].
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_new() -> *mut TsRespCtx {
    // SAFETY: no preconditions.
    unsafe { TS_RESP_CTX_new_ex(ptr::null_mut(), ptr::null()) }
}

/// `void TS_RESP_CTX_free(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:120-136`.
///
/// # Safety
/// `ctx` is NULL or a value [`TS_RESP_CTX_new`] returned.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_free(ctx: *mut TsRespCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live; every member is NULL or owned by the context.
    unsafe {
        CRYPTO_free((*ctx).propq.cast(), FILE.as_ptr(), 125);
        X509_free((*ctx).signer_cert);
        EVP_PKEY_free((*ctx).signer_key);
        OSSL_STACK_OF_X509_free((*ctx).certs);
        OPENSSL_sk_pop_free((*ctx).policies, Some(asn1_object_free_void));
        ASN1_OBJECT_free((*ctx).default_policy);
        OPENSSL_sk_free((*ctx).mds);
        ASN1_INTEGER_free((*ctx).seconds);
        ASN1_INTEGER_free((*ctx).millis);
        ASN1_INTEGER_free((*ctx).micros);
        CRYPTO_free(ctx.cast(), FILE.as_ptr(), 135);
    }
}

/// `int TS_RESP_CTX_set_signer_cert(TS_RESP_CTX *ctx, X509 *signer)` — `ts_rsp_sign.c:138-151`.
///
/// # Safety
/// `ctx` is live; `signer` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_signer_cert(
    ctx: *mut TsRespCtx,
    signer: *mut X509,
) -> c_int {
    // SAFETY: `signer` is live.
    if unsafe { X509_check_purpose(signer, X509_PURPOSE_TIMESTAMP_SIGN, 0) } != 1 {
        // SAFETY: a compile-time coordinate.
        unsafe {
            raise_ts(
                FILE,
                141,
                c"TS_RESP_CTX_set_signer_cert",
                TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE,
            )
        };
        return 0;
    }
    // SAFETY: `signer` is live.
    if unsafe { X509_up_ref(signer) } == 0 {
        return 0;
    }

    // SAFETY: `ctx` is live.
    unsafe {
        X509_free((*ctx).signer_cert);
        (*ctx).signer_cert = signer;
    }
    1
}

/// `int TS_RESP_CTX_set_signer_key(TS_RESP_CTX *ctx, EVP_PKEY *key)` — `ts_rsp_sign.c:153-162`.
///
/// # Safety
/// `ctx` is live; `key` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_signer_key(
    ctx: *mut TsRespCtx,
    key: *mut EvpPkey,
) -> c_int {
    // SAFETY: `key` is live.
    if unsafe { EVP_PKEY_up_ref(key) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        EVP_PKEY_free((*ctx).signer_key);
        (*ctx).signer_key = key;
    }
    1
}

/// `int TS_RESP_CTX_set_signer_digest(TS_RESP_CTX *ctx, const EVP_MD *md)` —
/// `ts_rsp_sign.c:164-168`.
///
/// # Safety
/// `ctx` is live; `md` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_signer_digest(
    ctx: *mut TsRespCtx,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).signer_md = md };
    1
}

/// `int TS_RESP_CTX_set_def_policy(TS_RESP_CTX *ctx, const ASN1_OBJECT *def_policy)` —
/// `ts_rsp_sign.c:170-179`.
///
/// # Safety
/// `ctx` is live; `def_policy` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_def_policy(
    ctx: *mut TsRespCtx,
    def_policy: *const Asn1Object,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { ASN1_OBJECT_free((*ctx).default_policy) };
    // SAFETY: `def_policy` is live.
    let dup = unsafe { OBJ_dup(def_policy) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).default_policy = dup };
    if dup.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 177, c"TS_RESP_CTX_set_def_policy", ERR_R_OBJ_LIB) };
        return 0;
    }
    1
}

/// `int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs)` — `ts_rsp_sign.c:181-187`.
///
/// # Safety
/// `ctx` is live; `certs` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_certs(
    ctx: *mut TsRespCtx,
    certs: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe {
        OSSL_STACK_OF_X509_free((*ctx).certs);
        (*ctx).certs = ptr::null_mut();
    }

    if certs.is_null() {
        return 1;
    }
    // SAFETY: `certs` is live.
    let dup = unsafe { X509_chain_up_ref(certs) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).certs = dup };
    (!dup.is_null()) as c_int
}

/// `int TS_RESP_CTX_add_policy(TS_RESP_CTX *ctx, const ASN1_OBJECT *policy)` —
/// `ts_rsp_sign.c:189-211`.
///
/// # Safety
/// `ctx` is live; `policy` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_add_policy(
    ctx: *mut TsRespCtx,
    policy: *const Asn1Object,
) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).policies }.is_null() {
        // SAFETY: no preconditions.
        let fresh = OPENSSL_sk_new_null();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).policies = fresh };
        if fresh.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 195, c"TS_RESP_CTX_add_policy", ERR_R_CRYPTO_LIB) };
            return 0;
        }
    }
    // SAFETY: `policy` is live.
    let copy = unsafe { OBJ_dup(policy) };
    if copy.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 199, c"TS_RESP_CTX_add_policy", ERR_R_OBJ_LIB) };
        return 0;
    }
    // SAFETY: `ctx` is live; `copy` is owned.
    if unsafe { OPENSSL_sk_push((*ctx).policies, copy.cast()) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 203, c"TS_RESP_CTX_add_policy", ERR_R_CRYPTO_LIB) };
        // SAFETY: `copy` is live.
        unsafe { ASN1_OBJECT_free(copy) };
        return 0;
    }
    1
}

/// `int TS_RESP_CTX_add_md(TS_RESP_CTX *ctx, const EVP_MD *md)` — `ts_rsp_sign.c:213-225`.
///
/// # Safety
/// `ctx` is live; `md` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_add_md(ctx: *mut TsRespCtx, md: *const EvpMd) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).mds }.is_null() {
        // SAFETY: no preconditions.
        let fresh = OPENSSL_sk_new_null();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).mds = fresh };
        if fresh.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 217, c"TS_RESP_CTX_add_md", ERR_R_CRYPTO_LIB) };
            return 0;
        }
    }
    // SAFETY: `ctx` is live; `md` is copied by pointer, exactly as the comment records.
    if unsafe { OPENSSL_sk_push((*ctx).mds, md.cast()) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 219, c"TS_RESP_CTX_add_md", ERR_R_CRYPTO_LIB) };
        return 0;
    }
    1
}

/// The `TS_RESP_CTX_accuracy_free(ctx)` macro — `ts_rsp_sign.c:227-233`.
///
/// # Safety
/// `ctx` is live.
unsafe fn ts_resp_ctx_accuracy_free(ctx: *mut TsRespCtx) {
    // SAFETY: `ctx` is live.
    unsafe {
        ASN1_INTEGER_free((*ctx).seconds);
        (*ctx).seconds = ptr::null_mut();
        ASN1_INTEGER_free((*ctx).millis);
        (*ctx).millis = ptr::null_mut();
        ASN1_INTEGER_free((*ctx).micros);
        (*ctx).micros = ptr::null_mut();
    }
}

/// `int TS_RESP_CTX_set_accuracy(TS_RESP_CTX *ctx, int secs, int millis, int micros)` —
/// `ts_rsp_sign.c:235-258`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_accuracy(
    ctx: *mut TsRespCtx,
    secs: c_int,
    millis: c_int,
    micros: c_int,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { ts_resp_ctx_accuracy_free(ctx) };

    if secs != 0 {
        // SAFETY: no preconditions.
        let s = ASN1_INTEGER_new();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).seconds = s };
        let mut ok = !s.is_null();
        if ok {
            // SAFETY: `s` is live.
            ok = unsafe { ASN1_INTEGER_set(s, secs as c_long) } != 0;
        }
        if !ok {
            // SAFETY: the err: arm releases the accuracy triple per the authority.
            return unsafe { ts_resp_ctx_accuracy_err(ctx) };
        }
    }
    if millis != 0 {
        // SAFETY: no preconditions.
        let m = ASN1_INTEGER_new();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).millis = m };
        let mut ok = !m.is_null();
        if ok {
            // SAFETY: `m` is live.
            ok = unsafe { ASN1_INTEGER_set(m, millis as c_long) } != 0;
        }
        if !ok {
            // SAFETY: the err: arm releases the accuracy triple per the authority.
            return unsafe { ts_resp_ctx_accuracy_err(ctx) };
        }
    }
    if micros != 0 {
        // SAFETY: no preconditions.
        let u = ASN1_INTEGER_new();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).micros = u };
        let mut ok = !u.is_null();
        if ok {
            // SAFETY: `u` is live.
            ok = unsafe { ASN1_INTEGER_set(u, micros as c_long) } != 0;
        }
        if !ok {
            // SAFETY: the err: arm releases the accuracy triple per the authority.
            return unsafe { ts_resp_ctx_accuracy_err(ctx) };
        }
    }

    1
}

/// The `err:` arm of [`TS_RESP_CTX_set_accuracy`] — `ts_rsp_sign.c:254-257`.
///
/// # Safety
/// `ctx` is live.
unsafe fn ts_resp_ctx_accuracy_err(ctx: *mut TsRespCtx) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { ts_resp_ctx_accuracy_free(ctx) };
    // SAFETY: a compile-time coordinate.
    unsafe { raise_ts(FILE, 256, c"TS_RESP_CTX_set_accuracy", ERR_R_ASN1_LIB) };
    0
}

/// `void TS_RESP_CTX_add_flags(TS_RESP_CTX *ctx, int flags)` — `ts_rsp_sign.c:260-263`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_add_flags(ctx: *mut TsRespCtx, flags: c_int) {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).flags |= flags as u32 };
}

/// `void TS_RESP_CTX_set_serial_cb(TS_RESP_CTX *ctx, TS_serial_cb cb, void *data)` —
/// `ts_rsp_sign.c:265-269`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_serial_cb(
    ctx: *mut TsRespCtx,
    cb: Option<TsSerialCb>,
    data: *mut c_void,
) {
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).serial_cb = cb;
        (*ctx).serial_cb_data = data;
    }
}

/// `void TS_RESP_CTX_set_time_cb(TS_RESP_CTX *ctx, TS_time_cb cb, void *data)` —
/// `ts_rsp_sign.c:271-275`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_time_cb(
    ctx: *mut TsRespCtx,
    cb: Option<TsTimeCb>,
    data: *mut c_void,
) {
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).time_cb = cb;
        (*ctx).time_cb_data = data;
    }
}

/// `void TS_RESP_CTX_set_extension_cb(TS_RESP_CTX *ctx, TS_extension_cb cb, void *data)` —
/// `ts_rsp_sign.c:277-282`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_extension_cb(
    ctx: *mut TsRespCtx,
    cb: Option<TsExtensionCb>,
    data: *mut c_void,
) {
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).extension_cb = cb;
        (*ctx).extension_cb_data = data;
    }
}

/// `int TS_RESP_CTX_set_status_info(TS_RESP_CTX *ctx, int status, const char *text)` —
/// `ts_rsp_sign.c:284-325`.
///
/// # Safety
/// `ctx` is live and its `response` is live; `text` is NULL or NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_status_info(
    ctx: *mut TsRespCtx,
    status: c_int,
    text: *const core::ffi::c_char,
) -> c_int {
    // SAFETY: no preconditions.
    let si = unsafe { super::ts_asn1::TS_STATUS_INFO_new() };
    let mut utf8_text: *mut Asn1String = ptr::null_mut();
    let mut ret = 0;
    if si.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 292, c"TS_RESP_CTX_set_status_info", ERR_R_TS_LIB) };
        // SAFETY: `si` is NULL, `utf8_text` is NULL.
        unsafe { TS_STATUS_INFO_free(si) };
        return ret;
    }
    // SAFETY: `si` is live.
    if unsafe { ASN1_INTEGER_set((*si).status, status as c_long) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 296, c"TS_RESP_CTX_set_status_info", ERR_R_ASN1_LIB) };
        // SAFETY: `si` is live.
        unsafe { TS_STATUS_INFO_free(si) };
        return ret;
    }
    if !text.is_null() {
        // SAFETY: no preconditions.
        utf8_text = ASN1_UTF8STRING_new();
        // SAFETY: `text` is NUL-terminated.
        let text_len = unsafe { core::ffi::CStr::from_ptr(text) }.to_bytes().len() as c_int;
        let mut set_failed = utf8_text.is_null();
        if !set_failed {
            // SAFETY: `utf8_text` is live.
            set_failed = unsafe { ASN1_STRING_set(utf8_text, text.cast(), text_len) } == 0;
        }
        if set_failed {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 302, c"TS_RESP_CTX_set_status_info", ERR_R_ASN1_LIB) };
            // SAFETY: `si` is live, `utf8_text` is NULL or live.
            unsafe {
                TS_STATUS_INFO_free(si);
                ASN1_UTF8STRING_free(utf8_text);
            }
            return ret;
        }
        // SAFETY: `si` is live.
        if unsafe { (*si).text }.is_null() {
            // SAFETY: no preconditions.
            let fresh = OPENSSL_sk_new_null();
            // SAFETY: `si` is live.
            unsafe { (*si).text = fresh };
            if fresh.is_null() {
                // SAFETY: a compile-time coordinate.
                unsafe { raise_ts(FILE, 307, c"TS_RESP_CTX_set_status_info", ERR_R_CRYPTO_LIB) };
                // SAFETY: `si` is live, `utf8_text` is live.
                unsafe {
                    TS_STATUS_INFO_free(si);
                    ASN1_UTF8STRING_free(utf8_text);
                }
                return ret;
            }
        }
        // SAFETY: `si` is live; the push takes ownership of `utf8_text`.
        if unsafe { OPENSSL_sk_push((*si).text, utf8_text.cast()) } == 0 {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 311, c"TS_RESP_CTX_set_status_info", ERR_R_CRYPTO_LIB) };
            // SAFETY: `si` is live, `utf8_text` is live.
            unsafe {
                TS_STATUS_INFO_free(si);
                ASN1_UTF8STRING_free(utf8_text);
            }
            return ret;
        }
        utf8_text = ptr::null_mut(); /* Ownership is lost. */
    }
    // SAFETY: `ctx` is live and its response is live.
    if unsafe { TS_RESP_set_status_info((*ctx).response, si) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 317, c"TS_RESP_CTX_set_status_info", ERR_R_TS_LIB) };
        // SAFETY: `si` is live, `utf8_text` is NULL.
        unsafe {
            TS_STATUS_INFO_free(si);
            ASN1_UTF8STRING_free(utf8_text);
        }
        return ret;
    }
    ret = 1;
    // SAFETY: `si` is live and now either owned by the response or freed.
    unsafe {
        TS_STATUS_INFO_free(si);
        ASN1_UTF8STRING_free(utf8_text);
    }
    ret
}

/// `int TS_RESP_CTX_set_status_info_cond(TS_RESP_CTX *ctx, int status, const char *text)` —
/// `ts_rsp_sign.c:327-337`.
///
/// # Safety
/// `ctx` is live and its `response` is live; `text` is NULL or NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_status_info_cond(
    ctx: *mut TsRespCtx,
    status: c_int,
    text: *const core::ffi::c_char,
) -> c_int {
    // SAFETY: `ctx` is live and its response is live.
    let si = unsafe { (*(*ctx).response).status_info };
    // SAFETY: `si` is live.
    if unsafe { ASN1_INTEGER_get((*si).status) } == TS_STATUS_GRANTED as c_long {
        // SAFETY: `ctx` is live; `text` is the caller's.
        return unsafe { TS_RESP_CTX_set_status_info(ctx, status, text) };
    }
    1
}

/// `int TS_RESP_CTX_add_failure_info(TS_RESP_CTX *ctx, int failure)` — `ts_rsp_sign.c:339-351`.
///
/// # Safety
/// `ctx` is live and its `response` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_add_failure_info(
    ctx: *mut TsRespCtx,
    failure: c_int,
) -> c_int {
    // SAFETY: `ctx` is live and its response is live.
    let si = unsafe { (*(*ctx).response).status_info };
    // SAFETY: `si` is live.
    if unsafe { (*si).failure_info }.is_null() {
        // SAFETY: no preconditions.
        let fresh = ASN1_BIT_STRING_new();
        // SAFETY: `si` is live.
        unsafe { (*si).failure_info = fresh };
        if fresh.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 349, c"TS_RESP_CTX_add_failure_info", ERR_R_ASN1_LIB) };
            return 0;
        }
    }
    // SAFETY: `si` is live and `failure_info` is live.
    if unsafe { ASN1_BIT_STRING_set_bit((*si).failure_info, failure, 1) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 349, c"TS_RESP_CTX_add_failure_info", ERR_R_ASN1_LIB) };
        return 0;
    }
    1
}

/// `TS_REQ *TS_RESP_CTX_get_request(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:353-356`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_get_request(ctx: *mut TsRespCtx) -> *mut TsReq {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).request }
}

/// `TS_TST_INFO *TS_RESP_CTX_get_tst_info(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:358-361`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_get_tst_info(ctx: *mut TsRespCtx) -> *mut TsTstInfo {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).tst_info }
}

/// `int TS_RESP_CTX_set_clock_precision_digits(TS_RESP_CTX *ctx, unsigned precision)` —
/// `ts_rsp_sign.c:363-370`.
///
/// # Safety
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_clock_precision_digits(
    ctx: *mut TsRespCtx,
    precision: u32,
) -> c_int {
    if precision > TS_MAX_CLOCK_PRECISION_DIGITS {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).clock_precision_digits = precision };
    1
}

/// `int TS_RESP_CTX_set_ess_cert_id_digest(TS_RESP_CTX *ctx, const EVP_MD *md)` —
/// `ts_rsp_sign.c:898-902`.
///
/// # Safety
/// `ctx` is live; `md` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_CTX_set_ess_cert_id_digest(
    ctx: *mut TsRespCtx,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).ess_cert_id_digest = md };
    1
}

// ---------------------------------------------------------------------------------------------
// The response builder — `TS_RESP_create_response` and the statics it reaches
// ---------------------------------------------------------------------------------------------

/// `TS_RESP *TS_RESP_create_response(TS_RESP_CTX *ctx, BIO *req_bio)` — `ts_rsp_sign.c:373-423`.
///
/// The `end:` cleanup is transcribed with a labelled block: the authority's `goto end` sets no
/// local, so the block merely reaches the shared tail, and the tail's `result` flag is what
/// distinguishes the success path from every one of the eight failure arms.
///
/// # Safety
/// `ctx` is live and owned by the caller; `req_bio` is a live `BIO` holding a DER `TS_REQ`; the
/// returned value is owned by the caller.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_create_response(
    ctx: *mut TsRespCtx,
    req_bio: *mut Bio,
) -> *mut TsResp {
    let mut result = false;

    // SAFETY: `ctx` is live.
    unsafe { ts_resp_ctx_init(ctx) };

    'end: {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).response = TS_RESP_new() };
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).response }.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 382, c"TS_RESP_create_response", ERR_R_TS_LIB) };
            break 'end;
        }
        // SAFETY: `req_bio` is live and the out-pointer is null, so the request is fresh.
        unsafe { (*ctx).request = d2i_TS_REQ_bio(req_bio, ptr::null_mut()) };
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).request }.is_null() {
            // SAFETY: `ctx` is live and its response is live.
            unsafe {
                TS_RESP_CTX_set_status_info(
                    ctx,
                    TS_STATUS_REJECTION,
                    c"Bad request format or system error.".as_ptr(),
                );
                TS_RESP_CTX_add_failure_info(ctx, TS_INFO_BAD_DATA_FORMAT);
            }
            break 'end;
        }
        // SAFETY: `ctx` is live and its response is live; the NULL text is the authority's.
        if unsafe { TS_RESP_CTX_set_status_info(ctx, TS_STATUS_GRANTED, ptr::null()) } == 0 {
            break 'end;
        }
        // SAFETY: `ctx` is live.
        if unsafe { ts_RESP_check_request(ctx) } == 0 {
            break 'end;
        }
        // SAFETY: `ctx` is live.
        let policy = unsafe { ts_RESP_get_policy(ctx) };
        if policy.is_null() {
            break 'end;
        }
        // SAFETY: `ctx` is live and `policy` is live.
        unsafe { (*ctx).tst_info = ts_RESP_create_tst_info(ctx, policy) };
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).tst_info }.is_null() {
            break 'end;
        }
        // SAFETY: `ctx` is live.
        if unsafe { ts_RESP_process_extensions(ctx) } == 0 {
            break 'end;
        }
        // SAFETY: `ctx` is live.
        if unsafe { ts_RESP_sign(ctx) } == 0 {
            break 'end;
        }
        result = true;
    }

    if !result {
        // SAFETY: a compile-time coordinate.
        unsafe {
            raise_ts(
                FILE,
                407,
                c"TS_RESP_create_response",
                TS_R_RESPONSE_SETUP_ERROR,
            )
        };
        // SAFETY: `ctx` is live.
        if !unsafe { (*ctx).response }.is_null() {
            // SAFETY: `ctx` is live and its response is live.
            if unsafe {
                TS_RESP_CTX_set_status_info_cond(
                    ctx,
                    TS_STATUS_REJECTION,
                    c"Error during response generation.".as_ptr(),
                )
            } == 0
            {
                // SAFETY: `ctx` is live and its response is live and owned by this frame.
                unsafe {
                    TS_RESP_free((*ctx).response);
                    (*ctx).response = ptr::null_mut();
                }
            }
        }
    }
    // SAFETY: `ctx` is live.
    let response = unsafe { (*ctx).response };
    // SAFETY: `ctx` is live; ownership of the response passes to the caller.
    unsafe {
        (*ctx).response = ptr::null_mut();
        ts_resp_ctx_cleanup(ctx);
    }
    response
}

/// `static void ts_RESP_CTX_init(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:426-431`.
///
/// # Safety
/// `ctx` is live.
unsafe fn ts_resp_ctx_init(ctx: *mut TsRespCtx) {
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).request = ptr::null_mut();
        (*ctx).response = ptr::null_mut();
        (*ctx).tst_info = ptr::null_mut();
    }
}

/// `static void ts_RESP_CTX_cleanup(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:434-442`.
///
/// # Safety
/// `ctx` is live; each of the three members is NULL or owned by the context.
unsafe fn ts_resp_ctx_cleanup(ctx: *mut TsRespCtx) {
    // SAFETY: `ctx` is live; each member is NULL or owned.
    unsafe {
        TS_REQ_free((*ctx).request);
        (*ctx).request = ptr::null_mut();
        TS_RESP_free((*ctx).response);
        (*ctx).response = ptr::null_mut();
        TS_TST_INFO_free((*ctx).tst_info);
        (*ctx).tst_info = ptr::null_mut();
    }
}

/// `static int ts_RESP_check_request(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:445-498`.
///
/// # Safety
/// `ctx` is live and its `request` is live; `ctx->response` is live so the status mutators may
/// write it.
unsafe fn ts_RESP_check_request(ctx: *mut TsRespCtx) -> c_int {
    // SAFETY: `ctx` is live.
    let request = unsafe { (*ctx).request };
    // SAFETY: `request` is live.
    if unsafe { TS_REQ_get_version(request) } != 1 {
        // SAFETY: `ctx` is live and its response is live.
        unsafe {
            TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION, c"Bad request version.".as_ptr());
            TS_RESP_CTX_add_failure_info(ctx, TS_INFO_BAD_REQUEST);
        }
        return 0;
    }
    // SAFETY: `request` is live.
    let msg_imprint = unsafe { (*request).msg_imprint };
    // SAFETY: `msg_imprint` is live.
    let md_alg = unsafe { (*msg_imprint).hash_algo };
    let mut md_alg_name = [0 as c_char; OSSL_MAX_NAME_SIZE];
    // SAFETY: `md_alg_name` is writable for its whole length and `md_alg` is live.
    unsafe {
        OBJ_obj2txt(
            md_alg_name.as_mut_ptr(),
            md_alg_name.len() as c_int,
            (*md_alg).algorithm,
            0,
        );
    }
    let mut md: *const EvpMd = ptr::null();
    let mut i = 0;
    // SAFETY: `ctx` is live, so its `mds` is NULL or a live stack.
    while md.is_null() && i < unsafe { OPENSSL_sk_num((*ctx).mds) } {
        // SAFETY: `i` is in range of the live stack.
        let current_md = unsafe { OPENSSL_sk_value((*ctx).mds, i) }.cast::<EvpMd>();
        // SAFETY: `current_md` and `md_alg_name` are live.
        if unsafe { EVP_MD_is_a(current_md, md_alg_name.as_ptr()) } != 0 {
            md = current_md;
        }
        i += 1;
    }
    if md.is_null() {
        // SAFETY: `ctx` is live and its response is live.
        unsafe {
            TS_RESP_CTX_set_status_info(
                ctx,
                TS_STATUS_REJECTION,
                c"Message digest algorithm is not supported.".as_ptr(),
            );
            TS_RESP_CTX_add_failure_info(ctx, TS_INFO_BAD_ALG);
        }
        return 0;
    }
    // SAFETY: `md` is live.
    let md_size = unsafe { EVP_MD_get_size(md) };
    if md_size <= 0 {
        return 0;
    }
    // SAFETY: `md_alg` is live.
    if !unsafe { (*md_alg).parameter }.is_null()
        // SAFETY: the parameter is live per the null check.
        && unsafe { ASN1_TYPE_get((*md_alg).parameter) } != V_ASN1_NULL
    {
        // SAFETY: `ctx` is live and its response is live.
        unsafe {
            TS_RESP_CTX_set_status_info(
                ctx,
                TS_STATUS_REJECTION,
                c"Superfluous message digest parameter.".as_ptr(),
            );
            TS_RESP_CTX_add_failure_info(ctx, TS_INFO_BAD_ALG);
        }
        return 0;
    }
    // SAFETY: `msg_imprint` is live.
    let digest = unsafe { (*msg_imprint).hashed_msg };
    // SAFETY: `digest` is live.
    if unsafe { (*digest).length } != md_size {
        // SAFETY: `ctx` is live and its response is live.
        unsafe {
            TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION, c"Bad message digest.".as_ptr());
            TS_RESP_CTX_add_failure_info(ctx, TS_INFO_BAD_DATA_FORMAT);
        }
        return 0;
    }

    1
}

/// `static ASN1_OBJECT *ts_RESP_get_policy(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:501-528`.
///
/// # Safety
/// `ctx` is live and its `request` is live; `ctx->response` is live so the status mutators may
/// write it.
unsafe fn ts_RESP_get_policy(ctx: *mut TsRespCtx) -> *mut Asn1Object {
    // SAFETY: `ctx` and its request are live.
    let requested = unsafe { (*(*ctx).request).policy_id };
    let mut policy: *mut Asn1Object = ptr::null_mut();
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).default_policy }.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 508, c"ts_RESP_get_policy", TS_R_INVALID_NULL_POINTER) };
        return ptr::null_mut();
    }
    // SAFETY: `requested` is NULL or live, and `default_policy` is live.
    if requested.is_null() || unsafe { OBJ_cmp(requested, (*ctx).default_policy) } == 0 {
        // SAFETY: `ctx` is live.
        policy = unsafe { (*ctx).default_policy };
    }
    let mut i = 0;
    // SAFETY: `ctx` is live, so its `policies` is NULL or a live stack.
    while policy.is_null() && i < unsafe { OPENSSL_sk_num((*ctx).policies) } {
        // SAFETY: `i` is in range of the live stack.
        let current = unsafe { OPENSSL_sk_value((*ctx).policies, i) }.cast::<Asn1Object>();
        // SAFETY: `requested` and `current` are live.
        if unsafe { OBJ_cmp(requested, current) } == 0 {
            policy = current;
        }
        i += 1;
    }
    if policy.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 521, c"ts_RESP_get_policy", TS_R_UNACCEPTABLE_POLICY) };
        // SAFETY: `ctx` is live and its response is live.
        unsafe {
            TS_RESP_CTX_set_status_info(
                ctx,
                TS_STATUS_REJECTION,
                c"Requested policy is not supported.".as_ptr(),
            );
            TS_RESP_CTX_add_failure_info(ctx, TS_INFO_UNACCEPTED_POLICY);
        }
    }
    policy
}

/// `static TS_TST_INFO *ts_RESP_create_tst_info(TS_RESP_CTX *ctx, ASN1_OBJECT *policy)` —
/// `ts_rsp_sign.c:531-608`.
///
/// # Safety
/// `ctx` is live and its `request`/`signer_cert` are live where the arms reach them; `policy` is
/// live; `ctx->response` is live so the status mutator may write it.
unsafe fn ts_RESP_create_tst_info(ctx: *mut TsRespCtx, policy: *mut Asn1Object) -> *mut TsTstInfo {
    let mut result = false;
    let mut tst_info: *mut TsTstInfo;
    let mut serial: *mut Asn1String = ptr::null_mut();
    let mut asn1_time: *mut Asn1String = ptr::null_mut();
    let mut accuracy: *mut TsAccuracy = ptr::null_mut();
    let mut tsa_name: *mut GeneralName = ptr::null_mut();

    'end: {
        // SAFETY: no preconditions.
        tst_info = unsafe { TS_TST_INFO_new() };
        if tst_info.is_null() {
            break 'end;
        }
        // SAFETY: `tst_info` is live.
        if unsafe { TS_TST_INFO_set_version(tst_info, 1) } == 0 {
            break 'end;
        }
        // SAFETY: `tst_info` and `policy` are live.
        if unsafe { TS_TST_INFO_set_policy_id(tst_info, policy) } == 0 {
            break 'end;
        }
        // SAFETY: `tst_info` is live, and the request's imprint is live.
        if unsafe { TS_TST_INFO_set_msg_imprint(tst_info, (*(*ctx).request).msg_imprint) } == 0 {
            break 'end;
        }
        // SAFETY: `ctx` is live and its `serial_cb` is a live callback.
        serial = match unsafe { (*ctx).serial_cb } {
            // SAFETY: `ctx` and its data are live per the callback's contract.
            Some(cb) => unsafe { cb(ctx, (*ctx).serial_cb_data) },
            None => ptr::null_mut(),
        };
        if serial.is_null()
            // SAFETY: `tst_info` and `serial` are live.
            || unsafe { TS_TST_INFO_set_serial(tst_info, serial) } == 0
        {
            break 'end;
        }
        let mut sec: c_long = 0;
        let mut usec: c_long = 0;
        // SAFETY: `ctx` and its data are live, and `sec`/`usec` are writable.
        let timed = match unsafe { (*ctx).time_cb } {
            // SAFETY: `ctx` and its data are live, and `sec`/`usec` are writable.
            Some(cb) => unsafe { cb(ctx, (*ctx).time_cb_data, &mut sec, &mut usec) },
            None => 0,
        };
        if timed == 0 {
            break 'end;
        }
        // SAFETY: no preconditions.
        asn1_time = unsafe {
            ts_resp_set_gentime_with_precision(
                ptr::null_mut(),
                sec,
                usec,
                (*ctx).clock_precision_digits,
            )
        };
        if asn1_time.is_null()
            // SAFETY: `tst_info` and `asn1_time` are live.
            || unsafe { TS_TST_INFO_set_time(tst_info, asn1_time) } == 0
        {
            break 'end;
        }

        // SAFETY: `ctx` is live.
        if !unsafe { (*ctx).seconds }.is_null()
            // SAFETY: `ctx` is live.
            || !unsafe { (*ctx).millis }.is_null()
            // SAFETY: `ctx` is live.
            || !unsafe { (*ctx).micros }.is_null()
        {
            // SAFETY: no preconditions.
            accuracy = unsafe { TS_ACCURACY_new() };
            if accuracy.is_null() {
                break 'end;
            }
        }
        // SAFETY: `ctx` is live.
        if !unsafe { (*ctx).seconds }.is_null()
            // SAFETY: `accuracy` and the context's seconds are live.
            && unsafe { TS_ACCURACY_set_seconds(accuracy, (*ctx).seconds) } == 0
        {
            break 'end;
        }
        // SAFETY: `ctx` is live.
        if !unsafe { (*ctx).millis }.is_null()
            // SAFETY: `accuracy` and the context's millis are live.
            && unsafe { TS_ACCURACY_set_millis(accuracy, (*ctx).millis) } == 0
        {
            break 'end;
        }
        // SAFETY: `ctx` is live.
        if !unsafe { (*ctx).micros }.is_null()
            // SAFETY: `accuracy` and the context's micros are live.
            && unsafe { TS_ACCURACY_set_micros(accuracy, (*ctx).micros) } == 0
        {
            break 'end;
        }
        if !accuracy.is_null()
            // SAFETY: `tst_info` and `accuracy` are live.
            && unsafe { TS_TST_INFO_set_accuracy(tst_info, accuracy) } == 0
        {
            break 'end;
        }

        // SAFETY: `ctx` is live.
        if (unsafe { (*ctx).flags } & TS_ORDERING) != 0
            // SAFETY: `tst_info` is live.
            && unsafe { TS_TST_INFO_set_ordering(tst_info, 1) } == 0
        {
            break 'end;
        }

        // SAFETY: `ctx` and its request are live.
        let nonce = unsafe { (*(*ctx).request).nonce };
        if !nonce.is_null()
            // SAFETY: `tst_info` and `nonce` are live.
            && unsafe { TS_TST_INFO_set_nonce(tst_info, nonce) } == 0
        {
            break 'end;
        }

        // SAFETY: `ctx` is live.
        if (unsafe { (*ctx).flags } & TS_TSA_NAME) != 0 {
            // SAFETY: no preconditions.
            tsa_name = GENERAL_NAME_new();
            if tsa_name.is_null() {
                break 'end;
            }
            // SAFETY: `tsa_name` is live; the subject name is borrowed and dup'ed.
            unsafe {
                (*tsa_name).type_ = GEN_DIRNAME;
                (*tsa_name).d.directoryName =
                    X509_NAME_dup(X509_get_subject_name((*ctx).signer_cert));
            }
            // SAFETY: `tsa_name` is live.
            if unsafe { (*tsa_name).d.directoryName }.is_null() {
                break 'end;
            }
            // SAFETY: `tst_info` and `tsa_name` are live.
            if unsafe { TS_TST_INFO_set_tsa(tst_info, tsa_name) } == 0 {
                break 'end;
            }
        }

        result = true;
    }

    if !result {
        // SAFETY: `tst_info` is NULL or owned by this frame.
        unsafe { TS_TST_INFO_free(tst_info) };
        tst_info = ptr::null_mut();
        // SAFETY: a compile-time coordinate.
        unsafe {
            raise_ts(
                FILE,
                597,
                c"ts_RESP_create_tst_info",
                TS_R_TST_INFO_SETUP_ERROR,
            )
        };
        // SAFETY: `ctx` is live and its response is live.
        unsafe {
            TS_RESP_CTX_set_status_info_cond(
                ctx,
                TS_STATUS_REJECTION,
                c"Error during TSTInfo generation.".as_ptr(),
            )
        };
    }
    // SAFETY: each pointer is NULL or owned by this frame.
    unsafe {
        GENERAL_NAME_free(tsa_name);
        TS_ACCURACY_free(accuracy);
        ASN1_GENERALIZEDTIME_free(asn1_time);
        ASN1_INTEGER_free(serial);
    }

    tst_info
}

/// `static int ts_RESP_process_extensions(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:611-629`.
///
/// # Safety
/// `ctx` is live and its `request` and `extension_cb` are live.
unsafe fn ts_RESP_process_extensions(ctx: *mut TsRespCtx) -> c_int {
    // SAFETY: `ctx` and its request are live.
    let exts = unsafe { (*(*ctx).request).extensions };
    let mut i = 0;
    let mut ok: c_int = 1;
    // SAFETY: `exts` is NULL or a live stack.
    while ok != 0 && i < unsafe { OPENSSL_sk_num(exts) } {
        // SAFETY: `i` is in range of the live stack.
        let ext = unsafe { OPENSSL_sk_value(exts, i) }.cast::<X509Extension>();
        // SAFETY: `ctx`, `ext` and the callback's data are live; the authority passes NULL for the
        // third argument (see `:619-624`).
        ok = match unsafe { (*ctx).extension_cb } {
            // SAFETY: `ctx`, `ext` and the callback's data are live.
            Some(cb) => unsafe { cb(ctx, ext, ptr::null_mut()) },
            None => 0,
        };
        i += 1;
    }

    ok
}

/// `static int ossl_ess_add1_signing_cert(PKCS7_SIGNER_INFO *si, const ESS_SIGNING_CERT *sc)` —
/// `ts_rsp_sign.c:632-657`.
///
/// # Safety
/// `si` is live; `sc` is live.
unsafe fn ossl_ess_add1_signing_cert(si: *mut Pkcs7SignerInfo, sc: *const EssSigningCert) -> c_int {
    // SAFETY: `sc` is live; a NULL out-pointer measures the encoding.
    let len = unsafe { i2d_ESS_SIGNING_CERT(sc, ptr::null_mut()) };
    // SAFETY: `len` is positive for a live value; the malloc is `OPENSSL_malloc(len)` at `:637`.
    let pp = CRYPTO_malloc(len as usize, FILE.as_ptr(), 637).cast::<core::ffi::c_uchar>();
    if pp.is_null() {
        return 0;
    }

    let mut p = pp;
    // SAFETY: `pp` holds `len` bytes and `sc` is live.
    unsafe { i2d_ESS_SIGNING_CERT(sc, &mut p) };
    // SAFETY: no preconditions.
    let seq = ASN1_STRING_new();
    let mut set_failed = seq.is_null();
    if !set_failed {
        // SAFETY: `seq` is live and `pp` holds `len` bytes.
        set_failed = unsafe { ASN1_STRING_set(seq, pp.cast(), len) } == 0;
    }
    if set_failed {
        // SAFETY: `seq` is NULL or owned here, and `pp` is owned here.
        unsafe {
            ASN1_STRING_free(seq);
            CRYPTO_free(pp.cast(), FILE.as_ptr(), 648);
        }
        return 0;
    }

    // SAFETY: `pp` is owned here.
    unsafe { CRYPTO_free(pp.cast(), FILE.as_ptr(), 650) };
    // SAFETY: `si` is live and `seq` is live; the attribute takes a reference.
    if unsafe {
        PKCS7_add_signed_attribute(
            si,
            NID_id_smime_aa_signingCertificate,
            V_ASN1_SEQUENCE,
            seq.cast(),
        )
    } == 0
    {
        // SAFETY: `seq` is owned here.
        unsafe { ASN1_STRING_free(seq) };
        return 0;
    }
    1
}

/// `static int ossl_ess_add1_signing_cert_v2(PKCS7_SIGNER_INFO *si, const ESS_SIGNING_CERT_V2 *sc)`
/// — `ts_rsp_sign.c:659-684`.
///
/// # Safety
/// `si` is live; `sc` is live.
unsafe fn ossl_ess_add1_signing_cert_v2(
    si: *mut Pkcs7SignerInfo,
    sc: *const EssSigningCertV2,
) -> c_int {
    // SAFETY: `sc` is live; a NULL out-pointer measures the encoding.
    let len = unsafe { i2d_ESS_SIGNING_CERT_V2(sc, ptr::null_mut()) };
    // SAFETY: `len` is positive for a live value; the malloc is `OPENSSL_malloc(len)` at `:664`.
    let pp = CRYPTO_malloc(len as usize, FILE.as_ptr(), 664).cast::<core::ffi::c_uchar>();
    if pp.is_null() {
        return 0;
    }

    let mut p = pp;
    // SAFETY: `pp` holds `len` bytes and `sc` is live.
    unsafe { i2d_ESS_SIGNING_CERT_V2(sc, &mut p) };
    // SAFETY: no preconditions.
    let seq = ASN1_STRING_new();
    let mut set_failed = seq.is_null();
    if !set_failed {
        // SAFETY: `seq` is live and `pp` holds `len` bytes.
        set_failed = unsafe { ASN1_STRING_set(seq, pp.cast(), len) } == 0;
    }
    if set_failed {
        // SAFETY: `seq` is NULL or owned here, and `pp` is owned here.
        unsafe {
            ASN1_STRING_free(seq);
            CRYPTO_free(pp.cast(), FILE.as_ptr(), 675);
        }
        return 0;
    }

    // SAFETY: `pp` is owned here.
    unsafe { CRYPTO_free(pp.cast(), FILE.as_ptr(), 677) };
    // SAFETY: `si` is live and `seq` is live; the attribute takes a reference.
    if unsafe {
        PKCS7_add_signed_attribute(
            si,
            NID_id_smime_aa_signingCertificateV2,
            V_ASN1_SEQUENCE,
            seq.cast(),
        )
    } == 0
    {
        // SAFETY: `seq` is owned here.
        unsafe { ASN1_STRING_free(seq) };
        return 0;
    }
    1
}

/// `static int ts_RESP_sign(TS_RESP_CTX *ctx)` — `ts_rsp_sign.c:686-801`.
///
/// The authority's `goto err` is transcribed with a labelled block and an `owned` flag; the
/// `err:` tail frees the fetched digest when it is not the caller's own, sets the conditional
/// status, and releases the partial `PKCS7`, the two signing-cert values and the BIO.
///
/// # Safety
/// `ctx` is live with a live `signer_cert`, `signer_key` and `response`.
unsafe fn ts_RESP_sign(ctx: *mut TsRespCtx) -> c_int {
    let mut ret = false;
    let mut p7: *mut Pkcs7 = ptr::null_mut();
    let mut sc2: *mut EssSigningCertV2 = ptr::null_mut();
    let mut sc: *mut EssSigningCert = ptr::null_mut();
    let mut p7bio: *mut Bio = ptr::null_mut();
    let mut signer_md: *mut EvpMd = ptr::null_mut();

    'err: {
        // SAFETY: `ctx` is live and its signer certificate and key are live.
        if unsafe { X509_check_private_key((*ctx).signer_cert, (*ctx).signer_key) } == 0 {
            // SAFETY: a compile-time coordinate.
            unsafe {
                raise_ts(
                    FILE,
                    700,
                    c"ts_RESP_sign",
                    TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE,
                )
            };
            break 'err;
        }

        // SAFETY: `ctx` is live; its `libctx`/`propq` are the caller's.
        p7 = unsafe { PKCS7_new_ex((*ctx).libctx, (*ctx).propq) };
        if p7.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 705, c"ts_RESP_sign", ERR_R_ASN1_LIB) };
            break 'err;
        }
        // SAFETY: `p7` is live.
        if unsafe { PKCS7_set_type(p7, NID_pkcs7_signed) } == 0 {
            break 'err;
        }
        // SAFETY: `p7` is live and is a signed structure by the previous call.
        if unsafe { ASN1_INTEGER_set((*(*p7).d.sign).version, 3) } == 0 {
            break 'err;
        }

        // SAFETY: `ctx` and its request are live.
        if unsafe { (*(*ctx).request).cert_req } != 0 {
            // SAFETY: `p7` and the signer certificate are live.
            unsafe { PKCS7_add_certificate(p7, (*ctx).signer_cert) };
            // SAFETY: `ctx` is live, so its `certs` is NULL or a live stack.
            if !unsafe { (*ctx).certs }.is_null() {
                let mut i = 0;
                // SAFETY: `ctx` is live and its `certs` is a live stack.
                while i < unsafe { OPENSSL_sk_num((*ctx).certs) } {
                    // SAFETY: `i` is in range of the live stack.
                    let cert = unsafe { OPENSSL_sk_value((*ctx).certs, i) }.cast::<X509>();
                    // SAFETY: `p7` and `cert` are live.
                    unsafe { PKCS7_add_certificate(p7, cert) };
                    i += 1;
                }
            }
        }

        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).signer_md }.is_null() {
            // SAFETY: no preconditions; the `SHA256` name is the authority's own.
            signer_md = unsafe { EVP_MD_fetch((*ctx).libctx, c"SHA256".as_ptr(), (*ctx).propq) };
        } else {
            // SAFETY: `ctx` is live and its signer digest is live.
            if unsafe { EVP_MD_get0_provider((*ctx).signer_md) }.is_null() {
                // SAFETY: the signer digest's name is the fetch's algorithm argument.
                signer_md = unsafe {
                    EVP_MD_fetch(
                        (*ctx).libctx,
                        EVP_MD_get0_name((*ctx).signer_md),
                        (*ctx).propq,
                    )
                };
            } else {
                // SAFETY: `ctx` is live; the digest is the caller's own and must not be freed.
                signer_md = unsafe { (*ctx).signer_md }.cast_mut();
            }
        }

        // SAFETY: `p7`, the signer certificate/key and `signer_md` are live.
        let si =
            unsafe { PKCS7_add_signature(p7, (*ctx).signer_cert, (*ctx).signer_key, signer_md) };
        if si.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 734, c"ts_RESP_sign", TS_R_PKCS7_ADD_SIGNATURE_ERROR) };
            break 'err;
        }

        // SAFETY: no preconditions.
        let oid = OBJ_nid2obj(NID_id_smime_ct_TSTInfo);
        // SAFETY: `si` and `oid` are live; the attribute takes a reference.
        if unsafe {
            PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, oid.cast())
        } == 0
        {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 741, c"ts_RESP_sign", TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR) };
            break 'err;
        }

        // SAFETY: `ctx` is live.
        let certs = if (unsafe { (*ctx).flags } & TS_ESS_CERT_ID_CHAIN) != 0 {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).certs }
        } else {
            ptr::null_mut()
        };
        // SAFETY: `ctx` is live.
        let use_v1 = unsafe { (*ctx).ess_cert_id_digest }.is_null()
            // SAFETY: the signer digest is live; the `SN_sha1` name is the authority's own.
            || unsafe { EVP_MD_is_a((*ctx).ess_cert_id_digest, SN_sha1.as_ptr()) } != 0;
        if use_v1 {
            // SAFETY: `ctx`'s signer certificate is live; `certs` is NULL or live.
            sc = unsafe { OSSL_ESS_signing_cert_new_init((*ctx).signer_cert, certs, 0) };
            if sc.is_null() {
                break 'err;
            }
            // SAFETY: `si` and `sc` are live.
            if unsafe { ossl_ess_add1_signing_cert(si, sc) } == 0 {
                // SAFETY: a compile-time coordinate.
                unsafe { raise_ts(FILE, 754, c"ts_RESP_sign", TS_R_ESS_ADD_SIGNING_CERT_ERROR) };
                break 'err;
            }
        } else {
            // SAFETY: `ctx`'s `ess_cert_id_digest`, signer certificate are live; `certs` NULL/live.
            sc2 = unsafe {
                OSSL_ESS_signing_cert_v2_new_init(
                    (*ctx).ess_cert_id_digest,
                    (*ctx).signer_cert,
                    certs,
                    0,
                )
            };
            if sc2.is_null() {
                break 'err;
            }
            // SAFETY: `si` and `sc2` are live.
            if unsafe { ossl_ess_add1_signing_cert_v2(si, sc2) } == 0 {
                // SAFETY: a compile-time coordinate.
                unsafe {
                    raise_ts(
                        FILE,
                        764,
                        c"ts_RESP_sign",
                        TS_R_ESS_ADD_SIGNING_CERT_V2_ERROR,
                    )
                };
                break 'err;
            }
        }

        // SAFETY: `p7` is live.
        if unsafe { ts_TST_INFO_content_new(p7) } == 0 {
            break 'err;
        }
        // SAFETY: `p7` is live; the NULL BIO is the authority's own argument.
        p7bio = unsafe { PKCS7_dataInit(p7, ptr::null_mut()) };
        if p7bio.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 772, c"ts_RESP_sign", ERR_R_PKCS7_LIB) };
            break 'err;
        }
        // SAFETY: `p7bio` and `ctx`'s pending TST_INFO are live.
        if unsafe { i2d_TS_TST_INFO_bio(p7bio, (*ctx).tst_info) } == 0 {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 776, c"ts_RESP_sign", TS_R_TS_DATASIGN) };
            break 'err;
        }
        // SAFETY: `p7` and `p7bio` are live.
        if unsafe { PKCS7_dataFinal(p7, p7bio) } == 0 {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 780, c"ts_RESP_sign", TS_R_TS_DATASIGN) };
            break 'err;
        }
        // SAFETY: `ctx`'s response and pending TST_INFO are live; ownership transfers.
        unsafe { super::ts_rsp_utils::TS_RESP_set_tst_info((*ctx).response, p7, (*ctx).tst_info) };
        p7 = ptr::null_mut();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).tst_info = ptr::null_mut() };

        ret = true;
    }

    // SAFETY: `signer_md` is NULL or the fetched digest; the signer's own digest is owned by the
    // caller and must not be released.
    if !signer_md.is_null() && !core::ptr::eq(signer_md.cast_const(), unsafe { (*ctx).signer_md }) {
        // SAFETY: `signer_md` is owned by this frame.
        unsafe { EVP_MD_free(signer_md) };
    }

    if !ret {
        // SAFETY: `ctx` is live and its response is live.
        unsafe {
            TS_RESP_CTX_set_status_info_cond(
                ctx,
                TS_STATUS_REJECTION,
                c"Error during signature generation.".as_ptr(),
            )
        };
    }
    // SAFETY: each pointer is NULL or owned by this frame.
    unsafe {
        BIO_free_all(p7bio);
        ESS_SIGNING_CERT_V2_free(sc2);
        ESS_SIGNING_CERT_free(sc);
        PKCS7_free(p7);
    }
    ret as c_int
}

/// `static int ts_TST_INFO_content_new(PKCS7 *p7)` — `ts_rsp_sign.c:803-828`.
///
/// # Safety
/// `p7` is live and is a signed structure.
unsafe fn ts_TST_INFO_content_new(p7: *mut Pkcs7) -> c_int {
    let mut octet_string: *mut Asn1String = ptr::null_mut();

    // SAFETY: no preconditions.
    let ret = PKCS7_new();
    if ret.is_null() {
        return 0;
    }
    // SAFETY: `ret` is live and its `d.other` slot is writable.
    unsafe { (*ret).d.other = ASN1_TYPE_new() };
    // SAFETY: `ret` is live.
    if unsafe { (*ret).d.other }.is_null() {
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            ASN1_OCTET_STRING_free(octet_string);
            PKCS7_free(ret);
        }
        return 0;
    }
    // SAFETY: `ret` is live; the OID is the authority's own.
    unsafe { (*ret).type_ = OBJ_nid2obj(NID_id_smime_ct_TSTInfo) };
    // SAFETY: no preconditions.
    octet_string = ASN1_OCTET_STRING_new();
    if octet_string.is_null() {
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            ASN1_OCTET_STRING_free(octet_string);
            PKCS7_free(ret);
        }
        return 0;
    }
    // SAFETY: `ret`'s `d.other` is live and takes ownership of `octet_string`.
    unsafe { ASN1_TYPE_set((*ret).d.other, V_ASN1_OCTET_STRING, octet_string.cast()) };
    octet_string = ptr::null_mut();

    // SAFETY: `p7` and `ret` are live; `PKCS7_set_content` takes ownership of `ret`.
    if unsafe { PKCS7_set_content(p7, ret) } == 0 {
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            ASN1_OCTET_STRING_free(octet_string);
            PKCS7_free(ret);
        }
        return 0;
    }

    1
}

/// `static ASN1_GENERALIZEDTIME *TS_RESP_set_genTime_with_precision(ASN1_GENERALIZEDTIME *asn1_time,`
/// `long sec, long usec, unsigned precision)` — `ts_rsp_sign.c:830-896`.
///
/// # Safety
/// `asn1_time` is NULL or a live value owned by the caller.
unsafe fn ts_resp_set_gentime_with_precision(
    asn1_time: *mut Asn1String,
    sec: c_long,
    usec: c_long,
    precision: u32,
) -> *mut Asn1String {
    let time_sec: TimeT = sec;
    // SAFETY: `Tm` is a plain C struct of integers; a zeroed value is a valid out-parameter.
    let mut tm_result: Tm = unsafe { core::mem::zeroed() };
    let mut gen_time_str = [0 as c_char; 17 + TS_MAX_CLOCK_PRECISION_DIGITS as usize];
    let base = gen_time_str.as_mut_ptr();
    let mut p = base;
    // SAFETY: `base` points at the start of `gen_time_str`; the offset is its length.
    let p_end = unsafe { base.add(gen_time_str.len()) };

    if precision > TS_MAX_CLOCK_PRECISION_DIGITS {
        // SAFETY: no preconditions.
        return unsafe { ts_gentime_err() };
    }

    // SAFETY: `time_sec` and `tm_result` are live.
    let tm = unsafe { OPENSSL_gmtime(&time_sec, &mut tm_result) };
    if tm.is_null() {
        // SAFETY: no preconditions.
        return unsafe { ts_gentime_err() };
    }

    // SAFETY: `p` is within `gen_time_str` and `p_end - p` is the writable remainder.
    let written = unsafe {
        BIO_snprintf(
            p,
            p_end.offset_from(p) as usize,
            c"%04d%02d%02d%02d%02d%02d".as_ptr(),
            (*tm).tm_year + 1900,
            (*tm).tm_mon + 1,
            (*tm).tm_mday,
            (*tm).tm_hour,
            (*tm).tm_min,
            (*tm).tm_sec,
        )
    };
    // SAFETY: `p` is within `gen_time_str` and the written length keeps it so.
    p = unsafe { p.add(written as usize) };
    if precision > 0 {
        // SAFETY: `p` has at least `2 + precision` writable bytes remaining.
        unsafe { BIO_snprintf(p, (2 + precision) as usize, c".%06ld".as_ptr(), usec) };
        // SAFETY: `BIO_snprintf` NUL-terminated the fraction it wrote.
        p = unsafe { p.add(core::ffi::CStr::from_ptr(p).to_bytes().len()) };

        // SAFETY: the loop walks back over the fraction's trailing zeros; the dot that
        // `BIO_snprintf` wrote is the exit condition even when every digit is zero.
        unsafe {
            loop {
                p = p.sub(1);
                if *p != b'0' as c_char {
                    break;
                }
            }
            if *p != b'.' as c_char {
                p = p.add(1);
            }
        }
    }
    // SAFETY: `p` is within `gen_time_str`; two bytes remain for the `Z` and the terminator.
    unsafe {
        *p = b'Z' as c_char;
        p = p.add(1);
        *p = 0;
    }

    let mut out = asn1_time;
    if out.is_null() {
        // SAFETY: no preconditions.
        out = ASN1_GENERALIZEDTIME_new();
        if out.is_null() {
            // SAFETY: no preconditions.
            return unsafe { ts_gentime_err() };
        }
    }
    // SAFETY: `out` is live and `gen_time_str` is NUL-terminated.
    if unsafe { ASN1_GENERALIZEDTIME_set_string(out, base) } == 0 {
        // SAFETY: `out` is owned here.
        unsafe { ASN1_GENERALIZEDTIME_free(out) };
        // SAFETY: no preconditions.
        return unsafe { ts_gentime_err() };
    }
    out
}

/// The `err:` arm of [`ts_resp_set_gentime_with_precision`] — `ts_rsp_sign.c:893-895`.
///
/// # Safety
/// No preconditions.
unsafe fn ts_gentime_err() -> *mut Asn1String {
    // SAFETY: a compile-time coordinate.
    unsafe {
        raise_ts(
            FILE,
            894,
            c"TS_RESP_set_genTime_with_precision",
            TS_R_COULD_NOT_SET_TIME,
        )
    };
    ptr::null_mut()
}
