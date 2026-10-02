//! `crypto/cmp/cmp_msg.c` — PKIMessage construction and (de)serialisation. Phase 12.4.
//!
//! This unit lands the self-contained part of `cmp_msg.c`: the message lifecycle and its
//! item-group plumbing (`OSSL_CMP_MSG_new`/`_free`, the `OSSL_CMP_MSG_get0_*` getters, the
//! `d2i_`/`i2d_` wrappers and the file reader/writer). The construction arms that build a
//! `CertTemplate`/`POPO` (`OSSL_CMP_CTX_setup_CRM`) and read a request's public key
//! (`OSSL_CMP_MSG_get0_certreq_publickey`) are left open: both reach the `crmf_lib.c` accessors,
//! which the plan lands in 12.7 (`docs/PHASE-12-SUBPHASES.md` §2.1 orders 12.4 before 12.7, so the
//! CRMF *item groups* could be pulled forward crate-internally but the CRMF *library* could not).
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::ASN1_item_d2i_bio_ex;
use crate::asn1::a_i2d_fp::ASN1_i2d_bio;
use crate::asn1::a_type::{ASN1_TYPE_new, ASN1_TYPE_set};
use crate::asn1::d2i::ASN1_item_d2i_ex;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{Asn1String, I2dOfVoid, V_ASN1_NULL};
use crate::asn1::new::ASN1_item_new_ex;
use crate::asn1::prim::{ASN1_ENUMERATED_set, ASN1_INTEGER_set, ASN1_INTEGER_set_int64};
use crate::asn1::string::{
    ASN1_ENUMERATED_free, ASN1_ENUMERATED_new, ASN1_INTEGER_new, ASN1_OCTET_STRING_free,
    ASN1_TIME_free,
};
use crate::asn1::time::ASN1_TIME_adj;
use crate::asn1::x_algor::{X509_ALGOR_new, X509_ALGOR_set_md};
use crate::cmp::cmp_asn::*;
use crate::cmp::cmp_ctx::{
    ossl_cmp_ctx_get0_newPubkey, OSSL_CMP_CTX_get0_newPkey, OSSL_CMP_CTX_get_option,
    OSSL_CMP_CTX_reqExtensions_have_SAN, OSSL_CMP_CTX_set0_newPkey, OsslCmpCtx,
};
use crate::cmp::cmp_hdr::{
    ossl_cmp_hdr_generalInfo_push1_items, ossl_cmp_hdr_init, ossl_cmp_hdr_set_implicitConfirm,
    ossl_cmp_hdr_set_pvno, ossl_cmp_hdr_set_transactionID,
};
use crate::cmp::cmp_protect::{ossl_cmp_msg_protect, ossl_cmp_set_own_chain};
use crate::cmp::cmp_status::{
    ossl_cmp_pkisi_get_status, OSSL_CMP_PKISTATUS_rejection, OSSL_CMP_STATUSINFO_new,
};
use crate::cmp::cmp_util::{ossl_cmp_asn1_octet_string_set1, ossl_cmp_sk_ASN1_UTF8STRING_push_str};
use crate::cms::cms_lib::ossl_cms_sign_encrypt;
use crate::crmf::crmf_asn::{
    CrmfCertId, CrmfEncryptedKey, CrmfMsg, OSSL_CRMF_CERTID_dup, OSSL_CRMF_CERTID_free,
    OSSL_CRMF_MSGS_new, OSSL_CRMF_MSG_dup, OSSL_CRMF_MSG_free, OSSL_CRMF_MSG_new,
};
use crate::crmf::crmf_lib::{
    OSSL_CRMF_CERTID_gen, OSSL_CRMF_CERTTEMPLATE_fill, OSSL_CRMF_CERTTEMPLATE_get0_publicKey,
    OSSL_CRMF_ENCRYPTEDKEY_get1_encCert, OSSL_CRMF_ENCRYPTEDKEY_get1_pkey,
    OSSL_CRMF_ENCRYPTEDKEY_init_envdata, OSSL_CRMF_MSG_create_popo, OSSL_CRMF_MSG_get0_tmpl,
    OSSL_CRMF_MSG_set0_extensions, OSSL_CRMF_MSG_set0_validity,
    OSSL_CRMF_MSG_set1_regCtrl_oldCertID, OSSL_CRMF_MSG_set_certReqId,
};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free};
use crate::evp::digest::{EVP_MD_free, EvpMd};
use crate::evp::pkey::EvpPkey;
use crate::runtime::bio::bss_file::BIO_new_file;
use crate::runtime::bio::bss_mem::BIO_s_mem;
use crate::runtime::bio::sys::time;
use crate::runtime::bio::{BIO_free, BIO_new, Bio};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, ERR_lib_error_string, ERR_reason_error_string};
use crate::runtime::obj::{NID_certificate_policies, NID_crl_reason, NID_subject_alt_name};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::v3_conf::X509V3_EXT_i2d;
use crate::x509::v3_genn::GENERAL_NAME_free;
use crate::x509::v3_lib::X509V3_get_d2i;
use crate::x509::x509_cmp::{
    ossl_x509_add_certs_new, X509_add_cert, X509_chain_up_ref, X509_get0_serialNumber,
    X509_get_issuer_name, X509_get_subject_name,
};
use crate::x509::x509_req::{
    X509_REQ_get0_pubkey, X509_REQ_get_extensions, X509_REQ_get_subject_name,
};
use crate::x509::x509_set::{X509_get0_extensions, X509_up_ref};
use crate::x509::x509_v3::{X509v3_add_ext, X509v3_add_extensions};
use crate::x509::x509name::X509_NAME_entry_count;
use crate::x509::x_all::{i2d_PrivateKey_bio, X509_digest_sig};
use crate::x509::x_exten::X509_EXTENSION_free;
use crate::x509::x_name::X509Name;
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_set0_public_key};
use crate::x509::x_req::X509_REQ_dup;
use crate::x509::x_x509::{ossl_x509_set0_libctx, X509_dup, X509};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_msg.c";

/// `ERR_LIB_CMP`.
const ERR_LIB_CMP: c_int = 58;
/// `CMP_R_NULL_ARGUMENT` — `include/openssl/cmperr.h`.
const CMP_R_NULL_ARGUMENT: c_int = 103;
/// `ERR_R_CMP_LIB` — `(ERR_LIB_CMP | ERR_RFLAG_COMMON)`.
const ERR_R_CMP_LIB: c_int = 524346;

/// `OSSL_CMP_PKIBODY_POLLREP` — `cmp_local.h:929`, and `OSSL_CMP_PKIBODY_TYPE_MAX` alongside.
const OSSL_CMP_PKIBODY_TYPE_MAX: c_int = 26;
/// `OSSL_CMP_PKIBODY_ERROR` — `cmp_local.h:926`.
const OSSL_CMP_PKIBODY_ERROR: c_int = 23;

/// The authority's non-dying `ossl_assert` (`-DNDEBUG` is not set for the authority, but the
/// macro's contract is the same): the value of the expression.
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

/// `ERR_raise(ERR_LIB_CMP, reason)` at an authority coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_cmp(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_site(&ErrSite {
            file: FILE,
            line,
            func,
            lib: ERR_LIB_CMP,
            reason,
            dynamic_reason: false,
        })
    };
}

/// `OSSL_CMP_MSG *OSSL_CMP_MSG_new(OSSL_LIB_CTX *libctx, const char *propq)` — `cmp_msg.c:18-29`.
/// Crate-internal: `cmp.h` does not declare it.
///
/// # Safety
/// `libctx` is NULL or a live library context; `propq` NULL or NUL-terminated.
pub(crate) unsafe fn OSSL_CMP_MSG_new(libctx: *mut c_void, propq: *const c_char) -> *mut CmpMsg {
    // SAFETY: the accessor answers a static item.
    let msg = unsafe { ASN1_item_new_ex(cmp_msg_it(), libctx, propq) }.cast::<CmpMsg>();
    if !msg.is_null()
        // SAFETY: `msg` is live.
        && unsafe { ossl_cmp_msg_set0_libctx(msg, libctx, propq) } == 0
    {
        // SAFETY: `msg` is live.
        unsafe { OSSL_CMP_MSG_free(msg) };
        return ptr::null_mut();
    }
    msg
}

/// `void OSSL_CMP_MSG_free(OSSL_CMP_MSG *msg)` — `cmp_msg.c:31-34`.
///
/// # Safety
/// `msg` is NULL or a value the item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_MSG_free(msg: *mut CmpMsg) {
    // SAFETY: `msg` is NULL or a live item value.
    unsafe { ASN1_item_free(msg.cast(), cmp_msg_it()) };
}

/// `OSSL_CMP_PKIHEADER *OSSL_CMP_MSG_get0_header(const OSSL_CMP_MSG *msg)` — `cmp_msg.c:57-64`.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CMP_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_MSG_get0_header(msg: *const CmpMsg) -> *mut CmpPkiHeader {
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(60, c"OSSL_CMP_MSG_get0_header", CMP_R_NULL_ARGUMENT) };
        return ptr::null_mut();
    }
    // SAFETY: `msg` is live.
    unsafe { (*msg).header }
}

/// `const char *ossl_cmp_bodytype_to_string(int type)` — `cmp_msg.c:66-101`. Crate-internal.
///
/// # Safety
/// No preconditions; the returned string is a static.
pub(crate) unsafe fn ossl_cmp_bodytype_to_string(type_: c_int) -> *const c_char {
    if !(0..=OSSL_CMP_PKIBODY_TYPE_MAX).contains(&type_) {
        return c"illegal body type".as_ptr();
    }
    let name: &'static core::ffi::CStr = match type_ {
        0 => c"IR",
        1 => c"IP",
        2 => c"CR",
        3 => c"CP",
        4 => c"P10CR",
        5 => c"POPDECC",
        6 => c"POPDECR",
        7 => c"KUR",
        8 => c"KUP",
        9 => c"KRR",
        10 => c"KRP",
        11 => c"RR",
        12 => c"RP",
        13 => c"CCR",
        14 => c"CCP",
        15 => c"CKUANN",
        16 => c"CANN",
        17 => c"RANN",
        18 => c"CRLANN",
        19 => c"PKICONF",
        20 => c"NESTED",
        21 => c"GENM",
        22 => c"GENP",
        23 => c"ERROR",
        24 => c"CERTCONF",
        25 => c"POLLREQ",
        26 => c"POLLREP",
        _ => c"illegal body type",
    };
    name.as_ptr()
}

/// `int ossl_cmp_msg_set_bodytype(OSSL_CMP_MSG *msg, int type)` — `cmp_msg.c:103-110`. Internal.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CMP_MSG` with a live body.
pub(crate) unsafe fn ossl_cmp_msg_set_bodytype(msg: *mut CmpMsg, type_: c_int) -> c_int {
    let ok = !msg.is_null() && {
        // SAFETY: `msg` is non-NULL, so the read is in bounds.
        let body = unsafe { (*msg).body };
        !body.is_null()
    };
    if ossl_assert(ok) == 0 {
        return 0;
    }
    // SAFETY: `msg` is live and its body is live per the check above.
    unsafe { (*(*msg).body).type_ = type_ };
    1
}

/// `int OSSL_CMP_MSG_get_bodytype(const OSSL_CMP_MSG *msg)` — `cmp_msg.c:112-118`.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CMP_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_MSG_get_bodytype(msg: *const CmpMsg) -> c_int {
    let ok = !msg.is_null() && {
        // SAFETY: `msg` is non-NULL, so the read is in bounds.
        let body = unsafe { (*msg).body };
        !body.is_null()
    };
    if ossl_assert(ok) == 0 {
        return -1;
    }
    // SAFETY: `msg` is live and its body is live per the check above.
    unsafe { (*(*msg).body).type_ }
}

/// `OSSL_CMP_MSG *OSSL_CMP_MSG_read(const char *file, OSSL_LIB_CTX *libctx, const char *propq)`
/// — `cmp_msg.c:1210-1234`.
///
/// # Safety
/// `file` is NULL or a NUL-terminated path; `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_MSG_read(
    file: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmpMsg {
    if file.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(1217, c"OSSL_CMP_MSG_read", CMP_R_NULL_ARGUMENT) };
        return ptr::null_mut();
    }

    // SAFETY: `libctx`/`propq` are the caller's.
    let mut msg = unsafe { OSSL_CMP_MSG_new(libctx, propq) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(1223, c"OSSL_CMP_MSG_read", ERR_R_CMP_LIB) };
        return ptr::null_mut();
    }

    // SAFETY: `file` is NUL-terminated per the contract.
    let bio = unsafe { BIO_new_file(file, c"rb".as_ptr()) };
    // SAFETY: `bio` is NULL or live; `&mut msg` is a writable slot.
    if bio.is_null() || unsafe { d2i_OSSL_CMP_MSG_bio(bio, &mut msg) }.is_null() {
        // SAFETY: `msg` is live.
        unsafe { OSSL_CMP_MSG_free(msg) };
        msg = ptr::null_mut();
    }
    // SAFETY: `bio` is NULL or live.
    unsafe { BIO_free(bio) };
    msg
}

/// `int OSSL_CMP_MSG_write(const char *file, const OSSL_CMP_MSG *msg)` — `cmp_msg.c:1236-1252`.
///
/// # Safety
/// `file` is NULL or a NUL-terminated path; `msg` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_MSG_write(file: *const c_char, msg: *const CmpMsg) -> c_int {
    if file.is_null() || msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(1242, c"OSSL_CMP_MSG_write", CMP_R_NULL_ARGUMENT) };
        return -1;
    }

    // SAFETY: `file` is NUL-terminated per the contract.
    let bio = unsafe { BIO_new_file(file, c"wb".as_ptr()) };
    if bio.is_null() {
        return -2;
    }
    // SAFETY: `bio` is live and `msg` live.
    let res = unsafe { i2d_OSSL_CMP_MSG_bio(bio, msg) };
    // SAFETY: `bio` is live.
    unsafe { BIO_free(bio) };
    res
}

/// `OSSL_CMP_MSG *d2i_OSSL_CMP_MSG(OSSL_CMP_MSG **msg, const unsigned char **in, long len)`
/// — `cmp_msg.c:1254-1268`.
///
/// # Safety
/// `msg` NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_CMP_MSG(
    msg: *mut *mut CmpMsg,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut CmpMsg {
    let mut libctx: *mut c_void = ptr::null_mut();
    let mut propq: *const c_char = ptr::null();
    if !msg.is_null() {
        // SAFETY: `msg` is a writable slot per the contract.
        let existing = unsafe { *msg };
        if !existing.is_null() {
            // SAFETY: `existing` is live.
            unsafe {
                libctx = (*existing).libctx;
                propq = (*existing).propq;
            }
        }
    }
    // SAFETY: the caller's contract; the captured context is passed through.
    unsafe { ASN1_item_d2i_ex(msg.cast(), in_, len, cmp_msg_it(), libctx, propq) }.cast()
}

/// `int i2d_OSSL_CMP_MSG(const OSSL_CMP_MSG *msg, unsigned char **out)` — `cmp_msg.c:1270-1274`.
///
/// # Safety
/// `msg` NULL or live; `out` NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_CMP_MSG(msg: *const CmpMsg, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(msg.cast(), out, cmp_msg_it()) }
}

/// `OSSL_CMP_MSG *d2i_OSSL_CMP_MSG_bio(BIO *bio, OSSL_CMP_MSG **msg)` — `cmp_msg.c:1276-1288`.
///
/// # Safety
/// `bio` live; `msg` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_CMP_MSG_bio(bio: *mut Bio, msg: *mut *mut CmpMsg) -> *mut CmpMsg {
    let mut libctx: *mut c_void = ptr::null_mut();
    let mut propq: *const c_char = ptr::null();
    if !msg.is_null() {
        // SAFETY: `msg` is a writable slot per the contract.
        let existing = unsafe { *msg };
        if !existing.is_null() {
            // SAFETY: `existing` is live.
            unsafe {
                libctx = (*existing).libctx;
                propq = (*existing).propq;
            }
        }
    }
    // SAFETY: the caller's contract; the captured context is passed through.
    unsafe { ASN1_item_d2i_bio_ex(cmp_msg_it(), bio, msg.cast(), libctx, propq) }.cast()
}

/// `int i2d_OSSL_CMP_MSG_bio(BIO *bio, const OSSL_CMP_MSG *msg)` — `cmp_msg.c:1290-1293`.
///
/// # Safety
/// `bio` live; `msg` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_CMP_MSG_bio(bio: *mut Bio, msg: *const CmpMsg) -> c_int {
    // SAFETY: this wrapper restates `i2d_OSSL_CMP_MSG`'s contract in `I2dOfVoid`'s terms.
    unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
        // SAFETY: the caller's contract, restated in the typed encoder's terms.
        unsafe { i2d_OSSL_CMP_MSG(x.cast::<CmpMsg>(), out) }
    }
    let i2d: I2dOfVoid = i2d_void;
    // SAFETY: `bio` is live, `i2d` is the encoder above, `msg` is live.
    unsafe { ASN1_i2d_bio(i2d, bio, msg.cast::<c_void>()) }
}

/// `int ossl_cmp_is_error_with_waiting(const OSSL_CMP_MSG *msg)` — `cmp_msg.c:1295-1303`.
/// Crate-internal.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CMP_MSG`.
pub(crate) unsafe fn ossl_cmp_is_error_with_waiting(msg: *const CmpMsg) -> c_int {
    if ossl_assert(!msg.is_null()) == 0 {
        return 0;
    }
    // SAFETY: `msg` is live per the check above.
    unsafe {
        if OSSL_CMP_MSG_get_bodytype(msg) != OSSL_CMP_PKIBODY_ERROR {
            return 0;
        }
        let error = (*(*msg).body).value.error;
        if error.is_null() {
            return 0;
        }
        c_int::from(
            crate::cmp::cmp_status::ossl_cmp_pkisi_get_status((*error).pki_status_info)
                == crate::cmp::cmp_status::OSSL_CMP_PKISTATUS_waiting,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The construction engine — `cmp_msg.c:148-1208`
// ---------------------------------------------------------------------------------------------

/// `OSSL_CMP_PKIBODY_*` selectors — `cmp_local.h:903-931`.
const OSSL_CMP_PKIBODY_IR: c_int = 0;
const OSSL_CMP_PKIBODY_IP: c_int = 1;
const OSSL_CMP_PKIBODY_CR: c_int = 2;
const OSSL_CMP_PKIBODY_CP: c_int = 3;
const OSSL_CMP_PKIBODY_P10CR: c_int = 4;
const OSSL_CMP_PKIBODY_KUR: c_int = 7;
const OSSL_CMP_PKIBODY_KUP: c_int = 8;
const OSSL_CMP_PKIBODY_RR: c_int = 11;
const OSSL_CMP_PKIBODY_RP: c_int = 12;
const OSSL_CMP_PKIBODY_PKICONF: c_int = 19;
const OSSL_CMP_PKIBODY_GENM: c_int = 21;
const OSSL_CMP_PKIBODY_GENP: c_int = 22;
const OSSL_CMP_PKIBODY_CERTCONF: c_int = 24;
const OSSL_CMP_PKIBODY_POLLREQ: c_int = 25;
const OSSL_CMP_PKIBODY_POLLREP: c_int = 26;
/// `OSSL_CMP_CERTREQID`, `_NONE`, `_INVALID` — `cmp_local.h:932-935`.
#[allow(dead_code)]
const OSSL_CMP_CERTREQID: c_int = 0;
const OSSL_CMP_CERTREQID_NONE: c_int = -1;
const OSSL_CMP_CERTREQID_INVALID: c_int = -2;
/// `OSSL_CMP_CERTORENCCERT_CERTIFICATE` — `include/openssl/cmp.h.in:216`.
const OSSL_CMP_CERTORENCCERT_CERTIFICATE: c_int = 0;
/// `OSSL_CMP_PVNO_3` — `include/openssl/cmp.h.in:42`.
const OSSL_CMP_PVNO_3: c_int = 3;
/// `OSSL_CMP_OPT_POPO_METHOD` — `include/openssl/cmp.h.in:369`.
const OSSL_CMP_OPT_POPO_METHOD: c_int = 24;
/// `OSSL_CRMF_POPO_NONE`/`_SIGNATURE` — `include/openssl/crmf.h.in:160-164`.
const OSSL_CRMF_POPO_NONE: c_int = -1;
const OSSL_CRMF_POPO_SIGNATURE: c_int = 1;
/// `CRL_REASON_NONE`.
const CRL_REASON_NONE: c_int = 0;
/// `OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN` — `include/openssl/cmp.h.in:140-141`.
const OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN: c_uint = (1u32 << 27) - 1;
/// `ERR_SYSTEM_FLAG` — `include/openssl/err.h.in` (`0x8000_0000`).
const ERR_SYSTEM_FLAG: c_ulong = 0x8000_0000;
/// `CMS_BINARY` — `include/openssl/cms.h.in:91`.
const CMS_BINARY: c_uint = 0x80;

/// `static int add1_extension(X509_EXTENSIONS **pexts, int nid, int crit, void *ex)` —
/// `cmp_msg.c:149-163`.
///
/// # Safety
/// `pexts` is a writable slot; `ex` is NULL or the value `nid` expects.
unsafe fn add1_extension(
    pexts: *mut *mut OpenSslStack,
    nid: c_int,
    crit: c_int,
    ex: *mut c_void,
) -> c_int {
    if pexts.is_null() {
        return 0;
    }
    // SAFETY: `ex` is the value `nid` expects.
    let ext = unsafe { X509V3_EXT_i2d(nid, crit, ex) };
    if ext.is_null() {
        return 0;
    }
    // SAFETY: `pexts` is a writable slot; `ext` is live.
    let res = c_int::from(!unsafe { X509v3_add_ext(pexts, ext, 0) }.is_null());
    // SAFETY: `ext` is this call's own object.
    unsafe { X509_EXTENSION_free(ext) };
    res
}

/// `static int add_crl_reason_extension(X509_EXTENSIONS **pexts, int reason_code)` —
/// `cmp_msg.c:166-175`.
///
/// # Safety
/// `pexts` is a writable slot.
unsafe fn add_crl_reason_extension(pexts: *mut *mut OpenSslStack, reason_code: c_int) -> c_int {
    // SAFETY: `ASN1_ENUMERATED_new` returns a fresh string or NULL.
    let val = ASN1_ENUMERATED_new();
    let mut res = 0;
    // SAFETY: `val` is NULL or live.
    if !val.is_null() && unsafe { ASN1_ENUMERATED_set(val, reason_code as c_long) } != 0 {
        // SAFETY: `val` is live; `pexts` is a writable slot.
        res = unsafe { add1_extension(pexts, NID_crl_reason, 0, val.cast()) };
    }
    // SAFETY: `val` is NULL or this call's own.
    unsafe { ASN1_ENUMERATED_free(val) };
    res
}

/// `OSSL_CMP_MSG *ossl_cmp_msg_create(OSSL_CMP_CTX *ctx, int bodytype)` — `cmp_msg.c:177-265`.
/// Internal.
///
/// # Safety
/// `ctx` is NULL or a live `OSSL_CMP_CTX`.
pub(crate) unsafe fn ossl_cmp_msg_create(ctx: *mut OsslCmpCtx, bodytype: c_int) -> *mut CmpMsg {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let msg = unsafe { OSSL_CMP_MSG_new((*ctx).libctx, (*ctx).propq) };
    if msg.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx`/`msg` are live.
    let hdr_ok = unsafe { ossl_cmp_hdr_init(ctx, (*msg).header) } != 0
        && unsafe { ossl_cmp_msg_set_bodytype(msg, bodytype) } != 0;
    // SAFETY: `ctx` is live.
    let gens_ok = unsafe { (*ctx).geninfo_itavs }.is_null()
        || unsafe { ossl_cmp_hdr_generalInfo_push1_items((*msg).header, (*ctx).geninfo_itavs) }
            != 0;
    if !hdr_ok || !gens_ok {
        // SAFETY: `msg` is live and owned here.
        unsafe { OSSL_CMP_MSG_free(msg) };
        return ptr::null_mut();
    }

    // SAFETY: `msg` is live; the union arm selected by `bodytype` is written once.
    let built = unsafe {
        match bodytype {
            OSSL_CMP_PKIBODY_IR | OSSL_CMP_PKIBODY_CR | OSSL_CMP_PKIBODY_KUR => {
                let v = OSSL_CRMF_MSGS_new();
                (*(*msg).body).value.ir = v;
                !v.is_null()
            }
            OSSL_CMP_PKIBODY_P10CR => {
                if (*ctx).p10_csr.is_null() {
                    raise_cmp(204, c"ossl_cmp_msg_create", 121);
                    false
                } else {
                    let v = X509_REQ_dup((*ctx).p10_csr.cast());
                    (*(*msg).body).value.p10cr = v.cast();
                    !v.is_null()
                }
            }
            OSSL_CMP_PKIBODY_IP | OSSL_CMP_PKIBODY_CP | OSSL_CMP_PKIBODY_KUP => {
                let v = OSSL_CMP_CERTREPMESSAGE_new();
                (*(*msg).body).value.ip = v;
                !v.is_null()
            }
            OSSL_CMP_PKIBODY_RR => {
                let v = OPENSSL_sk_new_null();
                (*(*msg).body).value.rr = v;
                !v.is_null()
            }
            OSSL_CMP_PKIBODY_RP => {
                let v = OSSL_CMP_REVREPCONTENT_new();
                (*(*msg).body).value.rp = v;
                !v.is_null()
            }
            OSSL_CMP_PKIBODY_CERTCONF => {
                let v = OPENSSL_sk_new_null();
                (*(*msg).body).value.cert_conf = v;
                !v.is_null()
            }
            OSSL_CMP_PKIBODY_PKICONF => {
                let v = ASN1_TYPE_new();
                (*(*msg).body).value.pkiconf = v;
                if !v.is_null() {
                    ASN1_TYPE_set(v, V_ASN1_NULL, ptr::null_mut());
                }
                !v.is_null()
            }
            OSSL_CMP_PKIBODY_POLLREQ => {
                let v = OPENSSL_sk_new_null();
                (*(*msg).body).value.poll_req = v;
                !v.is_null()
            }
            OSSL_CMP_PKIBODY_POLLREP => {
                let v = OPENSSL_sk_new_null();
                (*(*msg).body).value.poll_rep = v;
                !v.is_null()
            }
            OSSL_CMP_PKIBODY_GENM | OSSL_CMP_PKIBODY_GENP => {
                let v = OPENSSL_sk_new_null();
                (*(*msg).body).value.genm = v;
                !v.is_null()
            }
            OSSL_CMP_PKIBODY_ERROR => {
                let v = OSSL_CMP_ERRORMSGCONTENT_new();
                (*(*msg).body).value.error = v;
                !v.is_null()
            }
            _ => {
                raise_cmp(258, c"ossl_cmp_msg_create", 133);
                false
            }
        }
    };
    if !built {
        // SAFETY: `msg` is live and owned here.
        unsafe { OSSL_CMP_MSG_free(msg) };
        return ptr::null_mut();
    }
    msg
}

/// `#define HAS_SAN(ctx)` — `cmp_msg.c:267-269`.
///
/// # Safety
/// `ctx` is a live `OSSL_CMP_CTX`.
unsafe fn has_san(ctx: *const OsslCmpCtx) -> bool {
    // SAFETY: `ctx` is live.
    unsafe {
        OPENSSL_sk_num((*ctx).subject_alt_names) > 0
            || OSSL_CMP_CTX_reqExtensions_have_SAN(ctx.cast_mut()) == 1
    }
}

/// `static const X509_NAME *determine_subj(...)` — `cmp_msg.c:271-285`.
///
/// # Safety
/// `ctx` is a live `OSSL_CMP_CTX`; `ref_subj` is NULL or live.
unsafe fn determine_subj(
    ctx: *mut OsslCmpCtx,
    for_kur: c_int,
    ref_subj: *const X509Name,
) -> *const X509Name {
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).subject_name }.is_null() {
        // SAFETY: `ctx` is live.
        let sn = unsafe { (*ctx).subject_name };
        // SAFETY: `sn` is live.
        return if unsafe { X509_NAME_entry_count(sn) } == 0 {
            ptr::null()
        } else {
            sn
        };
    }
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).p10_csr }.is_null() {
        // SAFETY: `ctx`'s CSR is live.
        return unsafe { X509_REQ_get_subject_name((*ctx).p10_csr.cast()) };
    }
    // SAFETY: `ctx` is live.
    if for_kur != 0 || !unsafe { has_san(ctx) } {
        return ref_subj;
    }
    ptr::null()
}

/// `X509_EXTENSION` stack element releaser for [`OPENSSL_sk_pop_free`].
///
/// # Safety
/// `p` is an `X509_EXTENSION`.
unsafe extern "C" fn x509_extension_free_void(p: *mut c_void) {
    // SAFETY: `p` is an `X509_EXTENSION` per the contract.
    unsafe { X509_EXTENSION_free(p.cast()) };
}

/// `GENERAL_NAME` stack element releaser for [`OPENSSL_sk_pop_free`].
///
/// # Safety
/// `p` is a `GENERAL_NAME`.
unsafe extern "C" fn general_name_free_void(p: *mut c_void) {
    // SAFETY: `p` is a `GENERAL_NAME` per the contract.
    unsafe { GENERAL_NAME_free(p.cast()) };
}

/// `OSSL_CRMF_MSG *OSSL_CMP_CTX_setup_CRM(OSSL_CMP_CTX *ctx, int for_KUR, int rid)` —
/// `cmp_msg.c:287-396`.
///
/// # Safety
/// `ctx` is a live `OSSL_CMP_CTX`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_setup_CRM(
    ctx: *mut OsslCmpCtx,
    for_kur: c_int,
    rid: c_int,
) -> *mut CrmfMsg {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let central_keygen =
        unsafe { OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_POPO_METHOD) } == OSSL_CRMF_POPO_NONE;
    // SAFETY: `ctx` is live.
    let refcert = unsafe {
        if !(*ctx).old_cert.is_null() {
            (*ctx).old_cert
        } else {
            (*ctx).cert
        }
    };
    // SAFETY: `ctx` is live.
    let rkey = unsafe { ossl_cmp_ctx_get0_newPubkey(ctx) };
    let mut default_sans: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `refcert` is NULL or live.
    let ref_subj = if refcert.is_null() {
        ptr::null()
    } else {
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        unsafe { X509_get_subject_name(refcert) }
    };
    // SAFETY: `ctx` is live.
    let subject = unsafe { determine_subj(ctx, for_kur, ref_subj) };
    // SAFETY: `ctx`/`refcert` are live or NULL as checked.
    let issuer = unsafe {
        if !(*ctx).issuer.is_null() || refcert.is_null() {
            if X509_NAME_entry_count((*ctx).issuer) == 0 {
                ptr::null()
            } else {
                (*ctx).issuer
            }
        } else {
            X509_get_issuer_name(refcert)
        }
    };
    // SAFETY: `ctx` is live.
    let crit =
        c_int::from(unsafe { (*ctx).set_subject_alt_name_critical } != 0 || subject.is_null());
    let mut exts: *mut OpenSslStack = ptr::null_mut();

    // SAFETY: `ctx` is live.
    if rkey.is_null() && !central_keygen {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(308, c"OSSL_CMP_CTX_setup_CRM", 183) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    if for_kur != 0 && refcert.is_null() && unsafe { (*ctx).p10_csr }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(313, c"OSSL_CMP_CTX_setup_CRM", 168) };
        return ptr::null_mut();
    }
    // SAFETY: `OSSL_CRMF_MSG_new` returns a fresh value or NULL.
    let crm = OSSL_CRMF_MSG_new();
    if crm.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `crm` is live.
    let tmpl = unsafe { OSSL_CRMF_MSG_get0_tmpl(crm) };
    // SAFETY: `crm` is live; the pointers are the caller's contract.
    let filled = unsafe {
        OSSL_CRMF_MSG_set_certReqId(crm, rid) != 0
            && OSSL_CRMF_CERTTEMPLATE_fill(
                OSSL_CRMF_MSG_get0_tmpl(crm),
                rkey.cast::<EvpPkey>(),
                subject,
                issuer,
                ptr::null(),
            ) != 0
    };
    if !filled {
        // SAFETY: `crm` is live and owned here; the extension stack is NULL.
        unsafe {
            OSSL_CRMF_MSG_free(crm);
            OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
            OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
        }
        return ptr::null_mut();
    }
    // SAFETY: `rkey` and `tmpl` are live.
    if !rkey.is_null() && central_keygen {
        // SAFETY: `tmpl`'s public key is live.
        unsafe {
            X509_PUBKEY_set0_public_key(
                OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl),
                ptr::null_mut(),
                0,
            )
        };
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).days } != 0 {
        // SAFETY: `time` is the C library's; `ASN1_TIME_adj` returns a fresh time or NULL.
        let (not_before, not_after) = unsafe {
            let now = time(ptr::null_mut());
            (
                ASN1_TIME_adj(ptr::null_mut(), now, 0, 0),
                ASN1_TIME_adj(ptr::null_mut(), now, (*ctx).days, 0),
            )
        };
        // SAFETY: both are NULL or live, and `crm` is live.
        if not_before.is_null()
            || not_after.is_null()
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            || unsafe { OSSL_CRMF_MSG_set0_validity(crm, not_before, not_after) } == 0
        {
            // SAFETY: both are NULL or this call's own.
            unsafe {
                ASN1_TIME_free(not_before);
                ASN1_TIME_free(not_after);
                OSSL_CRMF_MSG_free(crm);
                OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
                OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
            }
            return ptr::null_mut();
        }
    }

    /* extensions */
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).p10_csr }.is_null() {
        // SAFETY: `ctx`'s CSR is live.
        exts = unsafe { X509_REQ_get_extensions((*ctx).p10_csr.cast()) };
        if exts.is_null() {
            // SAFETY: `crm` is live and owned here.
            unsafe {
                OSSL_CRMF_MSG_free(crm);
                OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
            }
            return ptr::null_mut();
        }
    }
    // SAFETY: `ctx`/`refcert` are live.
    if unsafe { (*ctx).subject_alt_name_nodefault } == 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && !unsafe { has_san(ctx) }
        && !refcert.is_null()
    {
        // SAFETY: `refcert`'s extensions are live.
        default_sans = unsafe {
            X509V3_get_d2i(
                X509_get0_extensions(refcert),
                NID_subject_alt_name,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        }
        .cast::<OpenSslStack>();
        // SAFETY: `default_sans` is NULL or a live stack; `exts` is a writable slot.
        if !default_sans.is_null()
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            && unsafe { add1_extension(&mut exts, NID_subject_alt_name, crit, default_sans.cast()) }
                == 0
        {
            // SAFETY: `crm` is live and owned here.
            unsafe {
                OSSL_CRMF_MSG_free(crm);
                OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
                OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
            }
            return ptr::null_mut();
        }
    }
    // SAFETY: `ctx` is live.
    if unsafe { OPENSSL_sk_num((*ctx).req_extensions) } > 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { X509v3_add_extensions(&mut exts, (*ctx).req_extensions) }.is_null()
    {
        // SAFETY: `crm` is live and owned here.
        unsafe {
            OSSL_CRMF_MSG_free(crm);
            OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
            OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
        }
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    if unsafe { OPENSSL_sk_num((*ctx).subject_alt_names) } > 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe {
            add1_extension(
                &mut exts,
                NID_subject_alt_name,
                crit,
                (*ctx).subject_alt_names.cast(),
            )
        } == 0
    {
        // SAFETY: `crm` is live and owned here.
        unsafe {
            OSSL_CRMF_MSG_free(crm);
            OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
            OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
        }
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).policies }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe {
            add1_extension(
                &mut exts,
                NID_certificate_policies,
                (*ctx).set_policies_critical,
                (*ctx).policies.cast(),
            )
        } == 0
    {
        // SAFETY: `crm` is live and owned here.
        unsafe {
            OSSL_CRMF_MSG_free(crm);
            OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
            OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
        }
        return ptr::null_mut();
    }
    // SAFETY: `crm` is live; `exts` transfers to it.
    if unsafe { OSSL_CRMF_MSG_set0_extensions(crm, exts) } == 0 {
        // SAFETY: `crm` is live and owned here.
        unsafe {
            OSSL_CRMF_MSG_free(crm);
            OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
            OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
        }
        return ptr::null_mut();
    }
    exts = ptr::null_mut();

    /* for KUR, set OldCertId according to D.6 */
    // SAFETY: `refcert` is live per the check.
    if for_kur != 0 && !refcert.is_null() {
        // SAFETY: `refcert` is live.
        let cid = unsafe {
            OSSL_CRMF_CERTID_gen(
                X509_get_issuer_name(refcert),
                X509_get0_serialNumber(refcert),
            )
        };
        if cid.is_null() {
            // SAFETY: `crm` is live and owned here.
            unsafe {
                OSSL_CRMF_MSG_free(crm);
                OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
                OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
            }
            return ptr::null_mut();
        }
        // SAFETY: `crm`/`cid` are live.
        let ret = unsafe { OSSL_CRMF_MSG_set1_regCtrl_oldCertID(crm, cid) };
        // SAFETY: `cid` is this call's own reference.
        unsafe { crate::crmf::crmf_asn::OSSL_CRMF_CERTID_free(cid) };
        if ret == 0 {
            // SAFETY: `crm` is live and owned here.
            unsafe {
                OSSL_CRMF_MSG_free(crm);
                OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
                OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
            }
            return ptr::null_mut();
        }
    }

    // SAFETY: `exts` is NULL (ownership moved) and `default_sans` is NULL or this call's own.
    unsafe {
        OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
        OPENSSL_sk_pop_free(default_sans, Some(general_name_free_void));
    }
    crm
}

/// `X509_ADD_FLAG_UP_REF` — `include/openssl/x509.h.in:801`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;
/// `X509_ADD_FLAG_NO_DUP` — `include/openssl/x509.h.in:803`.
const X509_ADD_FLAG_NO_DUP: c_int = 0x4;

/// `OSSL_CMP_MSG *ossl_cmp_certreq_new(OSSL_CMP_CTX *ctx, int type, const OSSL_CRMF_MSG *crm)` —
/// `cmp_msg.c:398-464`. Internal.
///
/// # Safety
/// `ctx` is live; `crm` is NULL or live.
pub(crate) unsafe fn ossl_cmp_certreq_new(
    ctx: *mut OsslCmpCtx,
    type_: c_int,
    crm: *const CrmfMsg,
) -> *mut CmpMsg {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    if type_ != OSSL_CMP_PKIBODY_IR
        && type_ != OSSL_CMP_PKIBODY_CR
        && type_ != OSSL_CMP_PKIBODY_KUR
        && type_ != OSSL_CMP_PKIBODY_P10CR
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(409, c"ossl_cmp_certreq_new", 100) };
        return ptr::null_mut();
    }
    if type_ == OSSL_CMP_PKIBODY_P10CR && !crm.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(413, c"ossl_cmp_certreq_new", 100) };
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_msg_create(ctx, type_) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(460, c"ossl_cmp_certreq_new", 163) };
        return ptr::null_mut();
    }

    /* header */
    // SAFETY: `ctx`/`msg` are live.
    if unsafe { (*ctx).implicit_confirm } != 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { ossl_cmp_hdr_set_implicitConfirm((*msg).header) } == 0
    {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(460, c"ossl_cmp_certreq_new", 163);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }

    /* body */
    let mut local_crm: *mut CrmfMsg = ptr::null_mut();
    if type_ != OSSL_CMP_PKIBODY_P10CR {
        // SAFETY: `ctx` is live.
        let privkey = unsafe { OSSL_CMP_CTX_get0_newPkey(ctx, 1) };
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).popo_method } >= OSSL_CRMF_POPO_SIGNATURE && privkey.is_null() {
            // SAFETY: `msg` is live and owned here.
            unsafe {
                raise_cmp(431, c"ossl_cmp_certreq_new", 190);
                raise_cmp(460, c"ossl_cmp_certreq_new", 163);
                OSSL_CRMF_MSG_free(local_crm);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
        if crm.is_null() {
            // SAFETY: `ctx` is live.
            local_crm = unsafe {
                OSSL_CMP_CTX_setup_CRM(
                    ctx,
                    c_int::from(type_ == OSSL_CMP_PKIBODY_KUR),
                    OSSL_CMP_CERTREQID,
                )
            };
            // SAFETY: `ctx`/`local_crm` are live; `privkey` is NULL or live.
            if local_crm.is_null()
                // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
                || unsafe {
                    OSSL_CRMF_MSG_create_popo(
                        (*ctx).popo_method,
                        local_crm,
                        privkey.cast::<EvpPkey>(),
                        (*ctx).digest,
                        (*ctx).libctx,
                        (*ctx).propq,
                    )
                } == 0
            {
                // SAFETY: `msg` is live and owned here.
                unsafe {
                    raise_cmp(460, c"ossl_cmp_certreq_new", 163);
                    OSSL_CRMF_MSG_free(local_crm);
                    OSSL_CMP_MSG_free(msg);
                }
                return ptr::null_mut();
            }
        } else {
            // SAFETY: `crm` is live.
            local_crm = unsafe { OSSL_CRMF_MSG_dup(crm) };
            if local_crm.is_null() {
                // SAFETY: `msg` is live and owned here.
                unsafe {
                    raise_cmp(460, c"ossl_cmp_certreq_new", 163);
                    OSSL_CMP_MSG_free(msg);
                }
                return ptr::null_mut();
            }
        }

        /* value.ir is same for cr and kur */
        // SAFETY: `msg`'s body is an `ir` stack and `local_crm` is live.
        if unsafe { OPENSSL_sk_push((*(*msg).body).value.ir, local_crm.cast()) } == 0 {
            // SAFETY: `msg` is live and owned here; `local_crm` is owned here.
            unsafe {
                raise_cmp(460, c"ossl_cmp_certreq_new", 163);
                OSSL_CRMF_MSG_free(local_crm);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
        local_crm = ptr::null_mut();
    }

    // SAFETY: `ctx`/`msg` are live.
    if unsafe { ossl_cmp_msg_protect(ctx, msg) } == 0 {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(460, c"ossl_cmp_certreq_new", 163);
            OSSL_CRMF_MSG_free(local_crm);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    msg
}

/// `static OSSL_CRMF_ENCRYPTEDKEY *enc_privkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey)` —
/// `cmp_msg.c:467-500`.
///
/// # Safety
/// `ctx` is live; `pkey` is live.
unsafe fn enc_privkey(ctx: *mut OsslCmpCtx, pkey: *const EvpPkey) -> *mut CrmfEncryptedKey {
    use crate::cms::cms_asn1::CMS_EnvelopedData_it;

    let mut priv_bio: *mut Bio = ptr::null_mut();
    // SAFETY: `ctx` is live.
    let recip = unsafe { (*ctx).validated_srv_cert };
    let encryption_recips = OPENSSL_sk_new_reserve(None, 1);

    // SAFETY: `encryption_recips` is NULL or a fresh stack; `recip` is live.
    if encryption_recips.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { X509_add_cert(encryption_recips, recip, X509_ADD_FLAG_UP_REF) } == 0
    {
        // SAFETY: the stack is NULL or this call's own; the BIO is NULL.
        unsafe {
            OSSL_STACK_OF_X509_free(encryption_recips);
            BIO_free(priv_bio);
        }
        return ptr::null_mut();
    }

    // SAFETY: `BIO_s_mem` answers a static method.
    priv_bio = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: `priv_bio` is NULL or live; `pkey` is live.
    let priv_ok = !priv_bio.is_null() && unsafe { i2d_PrivateKey_bio(priv_bio, pkey) } > 0;
    if !priv_ok {
        // SAFETY: the stack and BIO are this call's own.
        unsafe {
            OSSL_STACK_OF_X509_free(encryption_recips);
            BIO_free(priv_bio);
        }
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    unsafe { ossl_cmp_set_own_chain(ctx) };
    // SAFETY: `ctx` is live.
    let cipher = unsafe { EVP_CIPHER_fetch((*ctx).libctx, c"AES-256-CBC".as_ptr(), (*ctx).propq) };
    // SAFETY: `ctx` is live; the BIO and cipher are this call's own.
    let env_data = unsafe {
        ossl_cms_sign_encrypt(
            priv_bio,
            (*ctx).cert,
            (*ctx).chain,
            (*ctx).pkey,
            CMS_BINARY,
            encryption_recips,
            cipher,
            CMS_BINARY,
            (*ctx).libctx,
            (*ctx).propq,
        )
    };
    // SAFETY: `cipher` is NULL or this call's own.
    unsafe { EVP_CIPHER_free(cipher) };
    if env_data.is_null() {
        // SAFETY: the stack and BIO are this call's own.
        unsafe {
            OSSL_STACK_OF_X509_free(encryption_recips);
            BIO_free(priv_bio);
        }
        return ptr::null_mut();
    }
    // SAFETY: `env_data` is live and transfers into the result.
    let ek = unsafe { OSSL_CRMF_ENCRYPTEDKEY_init_envdata(env_data) };

    // SAFETY: the stack and BIO are this call's own.
    unsafe {
        OSSL_STACK_OF_X509_free(encryption_recips);
        BIO_free(priv_bio);
    }
    if ek.is_null() {
        // SAFETY: `env_data` is live and owned here.
        unsafe { ASN1_item_free(env_data.cast(), CMS_EnvelopedData_it()) };
    }
    ek
}

/// `ERR_R_UNSUPPORTED` — `include/openssl/err.h.in:366`, `268 | ERR_RFLAG_COMMON`.
const ERR_R_UNSUPPORTED: c_int = 268 | (0x2 << 18);

/// `OSSL_CMP_MSG *ossl_cmp_certrep_new(...)` — `cmp_msg.c:503-585`. Internal.
///
/// # Safety
/// `ctx`/`si` are live; the cert, key and stacks are NULL or live.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn ossl_cmp_certrep_new(
    ctx: *mut OsslCmpCtx,
    bodytype: c_int,
    cert_req_id: c_int,
    si: *const CmpPkisi,
    cert: *mut X509,
    pkey: *const EvpPkey,
    encryption_recip: *const X509,
    chain: *mut OpenSslStack,
    ca_pubs: *mut OpenSslStack,
    unprotected_errors: c_int,
) -> *mut CmpMsg {
    if ctx.is_null() || si.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_msg_create(ctx, bodytype) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(581, c"ossl_cmp_certrep_new", 117) };
        return ptr::null_mut();
    }
    // SAFETY: `msg` is live.
    let rep_msg = unsafe { (*(*msg).body).value.ip };

    /* header */
    // SAFETY: `ctx`/`msg` are live.
    if unsafe { (*ctx).implicit_confirm } != 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { ossl_cmp_hdr_set_implicitConfirm((*msg).header) } == 0
    {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(581, c"ossl_cmp_certrep_new", 117);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }

    /* body */
    // SAFETY: the accessor answers a fresh item value.
    let resp = unsafe { OSSL_CMP_CERTRESPONSE_new() };
    if resp.is_null() {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(581, c"ossl_cmp_certrep_new", 117);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    // SAFETY: `resp` is live.
    unsafe {
        OSSL_CMP_PKISI_free((*resp).status);
        (*resp).status = OSSL_CMP_PKISI_dup(si);
    }
    // SAFETY: `resp` is live and its status slot holds the duplicate.
    let status_set = !unsafe { (*resp).status }.is_null()
        && unsafe { ASN1_INTEGER_set((*resp).cert_req_id, cert_req_id as c_long) } != 0;
    if !status_set {
        // SAFETY: `resp`/`msg` are live and owned here.
        unsafe {
            raise_cmp(581, c"ossl_cmp_certrep_new", 117);
            OSSL_CMP_CERTRESPONSE_free(resp);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }

    // SAFETY: `resp`'s status is live.
    let status = unsafe { ossl_cmp_pkisi_get_status((*resp).status) };
    if status != OSSL_CMP_PKISTATUS_rejection
        && status != crate::cmp::cmp_status::OSSL_CMP_PKISTATUS_waiting
        && !cert.is_null()
    {
        if !encryption_recip.is_null() {
            // SAFETY: `msg`/`resp` are live and owned here.
            unsafe {
                raise_cmp(538, c"ossl_cmp_certrep_new", ERR_R_UNSUPPORTED);
                raise_cmp(581, c"ossl_cmp_certrep_new", 117);
                OSSL_CMP_CERTRESPONSE_free(resp);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
        // SAFETY: the item allocator answers a fresh item value.
        let ckp = unsafe { OSSL_CMP_CERTIFIEDKEYPAIR_new() };
        // SAFETY: `resp` is live.
        unsafe { (*resp).certified_key_pair = ckp };
        if ckp.is_null() {
            // SAFETY: `resp`/`msg` are live and owned here.
            unsafe {
                raise_cmp(581, c"ossl_cmp_certrep_new", 117);
                OSSL_CMP_CERTRESPONSE_free(resp);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
        // SAFETY: `ckp` is live and its cert-or-enc cert is mandatory.
        unsafe {
            (*(*ckp).cert_or_enc_cert).type_ = OSSL_CMP_CERTORENCCERT_CERTIFICATE;
        }
        // SAFETY: `cert` is live.
        if unsafe { X509_up_ref(cert) } == 0 {
            // SAFETY: `resp`/`msg` are live and owned here.
            unsafe {
                raise_cmp(581, c"ossl_cmp_certrep_new", 117);
                OSSL_CMP_CERTRESPONSE_free(resp);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
        // SAFETY: `ckp`'s cert slot is writable; ownership of `cert` moved in.
        unsafe {
            (*(*ckp).cert_or_enc_cert).value.certificate = cert;
        }

        if !pkey.is_null() {
            // SAFETY: `ctx` is live; `pkey` is live.
            let ek = unsafe { enc_privkey(ctx, pkey) };
            // SAFETY: `ckp` is live.
            unsafe { (*ckp).private_key = ek.cast() };
            if ek.is_null() {
                // SAFETY: `resp`/`msg` are live and owned here.
                unsafe {
                    raise_cmp(581, c"ossl_cmp_certrep_new", 117);
                    OSSL_CMP_CERTRESPONSE_free(resp);
                    OSSL_CMP_MSG_free(msg);
                }
                return ptr::null_mut();
            }
        }
    }

    // SAFETY: `rep_msg` is live and its response stack is mandatory.
    if unsafe { OPENSSL_sk_push((*rep_msg).response, resp.cast()) } == 0 {
        // SAFETY: `resp`/`msg` are live and owned here.
        unsafe {
            raise_cmp(581, c"ossl_cmp_certrep_new", 117);
            OSSL_CMP_CERTRESPONSE_free(resp);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }

    // SAFETY: `rep_msg` is live.
    if bodytype == OSSL_CMP_PKIBODY_IP && !ca_pubs.is_null() {
        // SAFETY: `ca_pubs` is live.
        let up = unsafe { X509_chain_up_ref(ca_pubs) };
        // SAFETY: `rep_msg` is live.
        unsafe { (*rep_msg).ca_pubs = up };
        if up.is_null() {
            // SAFETY: `msg` is live and owned here.
            unsafe {
                raise_cmp(581, c"ossl_cmp_certrep_new", 117);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
    }
    // SAFETY: `msg` is live and its extra-certs slot is writable; `chain` is NULL or live.
    if unsafe { OPENSSL_sk_num(chain) } > 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe {
            ossl_x509_add_certs_new(
                &mut (*msg).extra_certs,
                chain,
                X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP,
            )
        } == 0
    {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(581, c"ossl_cmp_certrep_new", 117);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }

    // SAFETY: `ctx`/`msg`/`si` are live.
    if unprotected_errors == 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { ossl_cmp_pkisi_get_status(si) } != OSSL_CMP_PKISTATUS_rejection
    {
        // SAFETY: `ctx`/`msg` are live.
        if unsafe { ossl_cmp_msg_protect(ctx, msg) } == 0 {
            // SAFETY: `msg` is live and owned here.
            unsafe {
                raise_cmp(581, c"ossl_cmp_certrep_new", 117);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
    }
    msg
}

/// `OSSL_CMP_MSG *ossl_cmp_rr_new(OSSL_CMP_CTX *ctx)` — `cmp_msg.c:587-648`. Internal.
///
/// # Safety
/// `ctx` is live.
pub(crate) unsafe fn ossl_cmp_rr_new(ctx: *mut OsslCmpCtx) -> *mut CmpMsg {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let precondition = unsafe {
        !(*ctx).old_cert.is_null()
            || !(*ctx).p10_csr.is_null()
            || (!(*ctx).serial_number.is_null() && !(*ctx).issuer.is_null())
    };
    if !precondition {
        return ptr::null_mut();
    }

    // SAFETY: the accessor answers a fresh item value.
    let mut rd = unsafe { OSSL_CMP_REVDETAILS_new() };
    if rd.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(644, c"ossl_cmp_rr_new", 126) };
        return ptr::null_mut();
    }

    let mut issuer: *const X509Name = ptr::null();
    let mut subject: *const X509Name = ptr::null();
    let mut serial_number: *const Asn1String = ptr::null();
    let mut pubkey: *mut EvpPkey = ptr::null_mut();
    // SAFETY: `ctx` is live.
    unsafe {
        if !(*ctx).serial_number.is_null() && !(*ctx).issuer.is_null() {
            issuer = (*ctx).issuer;
            serial_number = (*ctx).serial_number;
        } else if !(*ctx).old_cert.is_null() {
            issuer = X509_get_issuer_name((*ctx).old_cert);
            serial_number = X509_get0_serialNumber((*ctx).old_cert);
        } else if !(*ctx).p10_csr.is_null() {
            pubkey = X509_REQ_get0_pubkey((*ctx).p10_csr.cast());
            subject = X509_REQ_get_subject_name((*ctx).p10_csr.cast());
        }
    }
    // SAFETY: `rd` is live; the four pointers are NULL or live.
    if unsafe {
        OSSL_CRMF_CERTTEMPLATE_fill((*rd).cert_details, pubkey, subject, issuer, serial_number)
    } == 0
    {
        // SAFETY: `rd` is live and owned here.
        unsafe {
            raise_cmp(644, c"ossl_cmp_rr_new", 126);
            OSSL_CMP_REVDETAILS_free(rd);
        }
        return ptr::null_mut();
    }

    /* revocation reason code is optional */
    // SAFETY: `ctx` is live; `rd`'s entry-details slot is writable.
    if unsafe { (*ctx).revocation_reason } != CRL_REASON_NONE
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe {
            add_crl_reason_extension(
                ptr::addr_of_mut!((*rd).crl_entry_details),
                (*ctx).revocation_reason,
            )
        } == 0
    {
        // SAFETY: `rd` is live and owned here.
        unsafe {
            raise_cmp(644, c"ossl_cmp_rr_new", 126);
            OSSL_CMP_REVDETAILS_free(rd);
        }
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_RR) };
    if msg.is_null() {
        // SAFETY: `rd` is live and owned here.
        unsafe {
            raise_cmp(644, c"ossl_cmp_rr_new", 126);
            OSSL_CMP_REVDETAILS_free(rd);
        }
        return ptr::null_mut();
    }

    // SAFETY: `msg`'s rr stack is mandatory and `rd` is live.
    if unsafe { OPENSSL_sk_push((*(*msg).body).value.rr, rd.cast()) } == 0 {
        // SAFETY: `rd`/`msg` are live and owned here.
        unsafe {
            raise_cmp(644, c"ossl_cmp_rr_new", 126);
            OSSL_CMP_REVDETAILS_free(rd);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    rd = ptr::null_mut();

    // SAFETY: `ctx`/`msg` are live.
    if unsafe { ossl_cmp_msg_protect(ctx, msg) } == 0 {
        // SAFETY: `rd` is NULL; `msg` is live and owned here.
        unsafe {
            raise_cmp(644, c"ossl_cmp_rr_new", 126);
            OSSL_CMP_REVDETAILS_free(rd);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    msg
}

/// `OSSL_CMP_MSG *ossl_cmp_rp_new(OSSL_CMP_CTX *ctx, const OSSL_CMP_PKISI *si, const
/// OSSL_CRMF_CERTID *cid, int unprotectedErrors)` — `cmp_msg.c:650-694`. Internal.
///
/// # Safety
/// `ctx`/`si` are live; `cid` is NULL or live.
pub(crate) unsafe fn ossl_cmp_rp_new(
    ctx: *mut OsslCmpCtx,
    si: *const CmpPkisi,
    cid: *const CrmfCertId,
    unprotected_errors: c_int,
) -> *mut CmpMsg {
    if ctx.is_null() || si.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_RP) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(689, c"ossl_cmp_rp_new", 125) };
        return ptr::null_mut();
    }
    // SAFETY: `msg` is live.
    let rep = unsafe { (*(*msg).body).value.rp };

    // SAFETY: `si` is live.
    let si1 = unsafe { OSSL_CMP_PKISI_dup(si) };
    // SAFETY: `rep` is live and its status stack is mandatory; `si1` is live.
    if si1.is_null() || unsafe { OPENSSL_sk_push((*rep).status, si1.cast()) } == 0 {
        // SAFETY: `si1`/`msg` are live and owned here.
        unsafe {
            raise_cmp(689, c"ossl_cmp_rp_new", 125);
            OSSL_CMP_PKISI_free(si1);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }

    // SAFETY: `rep` is live and its rev-certs slot is writable.
    let rev_certs = OPENSSL_sk_new_null();
    // SAFETY: `rep` is live.
    unsafe { (*rep).rev_certs = rev_certs };
    if rev_certs.is_null() {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(689, c"ossl_cmp_rp_new", 125);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    if !cid.is_null() {
        // SAFETY: `cid` is live.
        let cid_copy = unsafe { OSSL_CRMF_CERTID_dup(cid) };
        // SAFETY: `rep`'s rev-certs stack is live; `cid_copy` is live.
        if cid_copy.is_null() || unsafe { OPENSSL_sk_push((*rep).rev_certs, cid_copy.cast()) } == 0
        {
            // SAFETY: `cid_copy`/`msg` are live and owned here.
            unsafe {
                raise_cmp(689, c"ossl_cmp_rp_new", 125);
                OSSL_CRMF_CERTID_free(cid_copy);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
    }

    // SAFETY: `ctx`/`msg`/`si` are live.
    if unprotected_errors == 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { ossl_cmp_pkisi_get_status(si) } != OSSL_CMP_PKISTATUS_rejection
    {
        // SAFETY: `ctx`/`msg` are live.
        if unsafe { ossl_cmp_msg_protect(ctx, msg) } == 0 {
            // SAFETY: `msg` is live and owned here.
            unsafe {
                raise_cmp(689, c"ossl_cmp_rp_new", 125);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
    }
    msg
}

/// `OSSL_CMP_MSG *ossl_cmp_pkiconf_new(OSSL_CMP_CTX *ctx)` — `cmp_msg.c:696-712`. Internal.
///
/// # Safety
/// `ctx` is live.
pub(crate) unsafe fn ossl_cmp_pkiconf_new(ctx: *mut OsslCmpCtx) -> *mut CmpMsg {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_PKICONF) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(709, c"ossl_cmp_pkiconf_new", 122) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx`/`msg` are live.
    if unsafe { ossl_cmp_msg_protect(ctx, msg) } != 0 {
        return msg;
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cmp(709, c"ossl_cmp_pkiconf_new", 122) };
    // SAFETY: `msg` is live and owned here.
    unsafe { OSSL_CMP_MSG_free(msg) };
    ptr::null_mut()
}

/// `int ossl_cmp_msg_gen_push0_ITAV(OSSL_CMP_MSG *msg, OSSL_CMP_ITAV *itav)` — `cmp_msg.c:714-730`.
/// Internal.
///
/// # Safety
/// `msg`/`itav` are live; ownership of `itav` transfers to `msg`.
pub(crate) unsafe fn ossl_cmp_msg_gen_push0_ITAV(msg: *mut CmpMsg, itav: *mut CmpItav) -> c_int {
    if msg.is_null() || itav.is_null() {
        return 0;
    }
    // SAFETY: `msg` is live.
    let bodytype = unsafe { OSSL_CMP_MSG_get_bodytype(msg) };
    if bodytype != OSSL_CMP_PKIBODY_GENM && bodytype != OSSL_CMP_PKIBODY_GENP {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(724, c"ossl_cmp_msg_gen_push0_ITAV", 100) };
        return 0;
    }
    // SAFETY: `msg` is live and its genm stack is mandatory; `itav` transfers in.
    unsafe { OSSL_CMP_ITAV_push0_stack_item(ptr::addr_of_mut!((*(*msg).body).value.genm), itav) }
}

/// `int ossl_cmp_msg_gen_push1_ITAVs(OSSL_CMP_MSG *msg, const STACK_OF(OSSL_CMP_ITAV) *itavs)` —
/// `cmp_msg.c:732-750`. Internal.
///
/// # Safety
/// `msg` is live; `itavs` is NULL or a live stack.
pub(crate) unsafe fn ossl_cmp_msg_gen_push1_ITAVs(
    msg: *mut CmpMsg,
    itavs: *const OpenSslStack,
) -> c_int {
    if msg.is_null() {
        return 0;
    }
    // SAFETY: `itavs` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(itavs as *mut OpenSslStack) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range.
        let src = unsafe { OPENSSL_sk_value(itavs as *mut OpenSslStack, i) }.cast::<CmpItav>();
        // SAFETY: `src` is a live element.
        let itav = unsafe { OSSL_CMP_ITAV_dup(src) };
        // SAFETY: `msg`/`itav` are live.
        if itav.is_null() || unsafe { ossl_cmp_msg_gen_push0_ITAV(msg, itav) } == 0 {
            // SAFETY: `itav` is NULL or live.
            unsafe { OSSL_CMP_ITAV_free(itav) };
            return 0;
        }
        i += 1;
    }
    1
}

/// `static OSSL_CMP_MSG *gen_new(...)` — `cmp_msg.c:756-780`.
///
/// # Safety
/// `ctx` is live; `itavs` is NULL or a live stack.
unsafe fn gen_new(
    ctx: *mut OsslCmpCtx,
    itavs: *const OpenSslStack,
    body_type: c_int,
    err_code: c_int,
) -> *mut CmpMsg {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_msg_create(ctx, body_type) };
    if msg.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `msg` is live; `itavs` is NULL or live.
    let items_ok = itavs.is_null() || unsafe { ossl_cmp_msg_gen_push1_ITAVs(msg, itavs) } != 0;
    // SAFETY: `ctx`/`msg` are live.
    if !items_ok || unsafe { ossl_cmp_msg_protect(ctx, msg) } == 0 {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(777, c"gen_new", err_code);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    msg
}

/// `OSSL_CMP_MSG *ossl_cmp_genm_new(OSSL_CMP_CTX *ctx)` — `cmp_msg.c:782-786`. Internal.
///
/// # Safety
/// `ctx` is live.
pub(crate) unsafe fn ossl_cmp_genm_new(ctx: *mut OsslCmpCtx) -> *mut CmpMsg {
    // SAFETY: `ctx` is live.
    unsafe { gen_new(ctx, (*ctx).genm_itavs, OSSL_CMP_PKIBODY_GENM, 119) }
}

/// `OSSL_CMP_MSG *ossl_cmp_genp_new(OSSL_CMP_CTX *ctx, const STACK_OF(OSSL_CMP_ITAV) *itavs)` —
/// `cmp_msg.c:788-793`. Internal.
///
/// # Safety
/// `ctx` is live; `itavs` is NULL or a live stack.
pub(crate) unsafe fn ossl_cmp_genp_new(
    ctx: *mut OsslCmpCtx,
    itavs: *const OpenSslStack,
) -> *mut CmpMsg {
    // SAFETY: `ctx` is live; `itavs` is NULL or live.
    unsafe { gen_new(ctx, itavs, OSSL_CMP_PKIBODY_GENP, 120) }
}

/// `OSSL_CMP_MSG *ossl_cmp_error_new(OSSL_CMP_CTX *ctx, const OSSL_CMP_PKISI *si, int64_t`
/// `errorCode, const char *details, int unprotected)` — `cmp_msg.c:795-845`. Internal.
///
/// # Safety
/// `ctx`/`si` are live; `details` is NULL or NUL-terminated.
pub(crate) unsafe fn ossl_cmp_error_new(
    ctx: *mut OsslCmpCtx,
    si: *const CmpPkisi,
    error_code: i64,
    details: *const c_char,
    unprotected: c_int,
) -> *mut CmpMsg {
    if ctx.is_null() || si.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_ERROR) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(842, c"ossl_cmp_error_new", 118) };
        return ptr::null_mut();
    }
    // SAFETY: `msg` is live.
    let error = unsafe { (*(*msg).body).value.error };

    // SAFETY: `error` is live.
    unsafe {
        OSSL_CMP_PKISI_free((*error).pki_status_info);
        (*error).pki_status_info = OSSL_CMP_PKISI_dup(si);
    }
    // SAFETY: `error` is live.
    if unsafe { (*error).pki_status_info }.is_null() {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(842, c"ossl_cmp_error_new", 118);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    // SAFETY: `ASN1_INTEGER_new` returns a fresh integer or NULL.
    let code = ASN1_INTEGER_new();
    // SAFETY: `error` is live.
    unsafe { (*error).error_code = code };
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if code.is_null() || unsafe { ASN1_INTEGER_set_int64(code, error_code) } == 0 {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(842, c"ossl_cmp_error_new", 118);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }

    let mut lib: *const c_char = ptr::null();
    let mut reason: *const c_char = ptr::null();
    if error_code > 0 && (error_code as u64) < (ERR_SYSTEM_FLAG << 1) {
        // SAFETY: the error code names a queued library/reason pair.
        lib = ERR_lib_error_string(error_code as c_ulong);
        reason = ERR_reason_error_string(error_code as c_ulong);
    }
    // SAFETY: all three strings are NULL or NUL-terminated.
    let any_text = !lib.is_null() || !reason.is_null() || !details.is_null();
    if any_text {
        let ft = OPENSSL_sk_new_null();
        // SAFETY: `error` is live.
        unsafe { (*error).error_details = ft };
        if ft.is_null() {
            // SAFETY: `msg` is live and owned here.
            unsafe {
                raise_cmp(842, c"ossl_cmp_error_new", 118);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
        // SAFETY: each string is NULL or NUL-terminated; `ft` is live.
        let pushed = unsafe {
            (!(!lib.is_null() && *lib != 0)
                || ossl_cmp_sk_ASN1_UTF8STRING_push_str(ft, lib, -1) != 0)
                && (!(!reason.is_null() && *reason != 0)
                    || ossl_cmp_sk_ASN1_UTF8STRING_push_str(ft, reason, -1) != 0)
                && (details.is_null() || ossl_cmp_sk_ASN1_UTF8STRING_push_str(ft, details, -1) != 0)
        };
        if !pushed {
            // SAFETY: `msg` is live and owned here.
            unsafe {
                raise_cmp(842, c"ossl_cmp_error_new", 118);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
    }

    // SAFETY: `ctx`/`msg` are live.
    if unprotected == 0 && unsafe { ossl_cmp_msg_protect(ctx, msg) } == 0 {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(842, c"ossl_cmp_error_new", 118);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    msg
}

/// `int ossl_cmp_certstatus_set0_certHash(OSSL_CMP_CERTSTATUS *certStatus, ASN1_OCTET_STRING`
/// `*hash)` — `cmp_msg.c:852-860`. Internal.
///
/// # Safety
/// `cert_status` is live; `hash` transfers in.
pub(crate) unsafe fn ossl_cmp_certstatus_set0_certHash(
    cert_status: *mut CmpCertStatus,
    hash: *mut Asn1String,
) -> c_int {
    if cert_status.is_null() {
        return 0;
    }
    // SAFETY: `cert_status` is live.
    unsafe {
        ASN1_OCTET_STRING_free((*cert_status).cert_hash);
        (*cert_status).cert_hash = hash;
    }
    1
}

/// `OSSL_CMP_MSG *ossl_cmp_certConf_new(OSSL_CMP_CTX *ctx, int certReqId, int fail_info, const`
/// `char *text)` — `cmp_msg.c:862-939`. Internal.
///
/// # Safety
/// `ctx` is live with a live `newCert`; `text` is NULL or NUL-terminated.
pub(crate) unsafe fn ossl_cmp_certConf_new(
    ctx: *mut OsslCmpCtx,
    cert_req_id: c_int,
    fail_info: c_int,
    text: *const c_char,
) -> *mut CmpMsg {
    if ctx.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { (*ctx).new_cert }.is_null()
        || (cert_req_id != OSSL_CMP_CERTREQID && cert_req_id != OSSL_CMP_CERTREQID_NONE)
    {
        return ptr::null_mut();
    }
    if fail_info as c_uint > OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(878, c"ossl_cmp_certConf_new", 129) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_CERTCONF) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(935, c"ossl_cmp_certConf_new", 116) };
        return ptr::null_mut();
    }
    // SAFETY: the accessor answers a fresh item value.
    let cert_status = unsafe { OSSL_CMP_CERTSTATUS_new() };
    if cert_status.is_null() {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(935, c"ossl_cmp_certConf_new", 116);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    // SAFETY: `msg`'s certConf stack is mandatory; `cert_status` transfers in.
    if unsafe { OPENSSL_sk_push((*(*msg).body).value.cert_conf, cert_status.cast()) } < 1 {
        // SAFETY: `cert_status`/`msg` are live and owned here.
        unsafe {
            raise_cmp(935, c"ossl_cmp_certConf_new", 116);
            OSSL_CMP_CERTSTATUS_free(cert_status);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    // SAFETY: `cert_status` is live.
    if unsafe { ASN1_INTEGER_set((*cert_status).cert_req_id, cert_req_id as c_long) } == 0 {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(935, c"ossl_cmp_certConf_new", 116);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    // SAFETY: `cert_status` is live.
    unsafe { (*cert_status).hash_alg = ptr::null_mut() };

    let mut md: *mut EvpMd = ptr::null_mut();
    let mut is_fallback: c_int = 0;
    // SAFETY: `ctx`'s new cert is live.
    let cert_hash = unsafe { X509_digest_sig((*ctx).new_cert, &mut md, &mut is_fallback) };
    if cert_hash.is_null() {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(935, c"ossl_cmp_certConf_new", 116);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    if is_fallback != 0 {
        // SAFETY: `msg` is live.
        if unsafe { ossl_cmp_hdr_set_pvno((*msg).header, OSSL_CMP_PVNO_3) } == 0 {
            // SAFETY: `cert_hash`/`msg` are live and owned here.
            unsafe {
                raise_cmp(935, c"ossl_cmp_certConf_new", 116);
                ASN1_OCTET_STRING_free(cert_hash);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
        // SAFETY: `X509_ALGOR_new` returns a fresh algorithm or NULL.
        let alg = X509_ALGOR_new();
        // SAFETY: `cert_status` is live.
        unsafe { (*cert_status).hash_alg = alg };
        if alg.is_null() {
            // SAFETY: `cert_hash`/`msg` are live and owned here.
            unsafe {
                raise_cmp(935, c"ossl_cmp_certConf_new", 116);
                ASN1_OCTET_STRING_free(cert_hash);
                OSSL_CMP_MSG_free(msg);
            }
            return ptr::null_mut();
        }
        // SAFETY: `alg`/`md` are live.
        unsafe { X509_ALGOR_set_md(alg, md) };
    }
    // SAFETY: `md` is NULL or this call's own.
    unsafe { EVP_MD_free(md) };

    // SAFETY: `cert_status`/`cert_hash` are live; ownership moves in.
    if unsafe { ossl_cmp_certstatus_set0_certHash(cert_status, cert_hash) } == 0 {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(935, c"ossl_cmp_certConf_new", 116);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }

    // SAFETY: `text` is NULL or NUL-terminated.
    let sinfo = unsafe {
        if fail_info != 0 {
            OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection, fail_info, text)
        } else {
            OSSL_CMP_STATUSINFO_new(crate::cmp::cmp_status::OSSL_CMP_PKISTATUS_accepted, 0, text)
        }
    };
    if sinfo.is_null() {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(935, c"ossl_cmp_certConf_new", 116);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    // SAFETY: `cert_status` is live; ownership of `sinfo` moves in.
    unsafe { (*cert_status).status_info = sinfo };

    // SAFETY: `ctx`/`msg` are live.
    if unsafe { ossl_cmp_msg_protect(ctx, msg) } == 0 {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(935, c"ossl_cmp_certConf_new", 116);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    msg
}

/// `OSSL_CMP_MSG *ossl_cmp_pollReq_new(OSSL_CMP_CTX *ctx, int crid)` — `cmp_msg.c:941-968`.
/// Internal.
///
/// # Safety
/// `ctx` is live.
pub(crate) unsafe fn ossl_cmp_pollReq_new(ctx: *mut OsslCmpCtx, crid: c_int) -> *mut CmpMsg {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_POLLREQ) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(964, c"ossl_cmp_pollReq_new", 124) };
        return ptr::null_mut();
    }
    // SAFETY: the accessor answers a fresh item value.
    let preq = unsafe { OSSL_CMP_POLLREQ_new() };
    // SAFETY: `preq` is NULL or live.
    if preq.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe { ASN1_INTEGER_set((*preq).cert_req_id, crid as c_long) } == 0
        // SAFETY: `msg`'s pollReq stack is mandatory; `preq` transfers in.
        || unsafe { OPENSSL_sk_push((*(*msg).body).value.poll_req, preq.cast()) } == 0
    {
        // SAFETY: `preq`/`msg` are live and owned here.
        unsafe {
            raise_cmp(964, c"ossl_cmp_pollReq_new", 124);
            OSSL_CMP_POLLREQ_free(preq);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    // SAFETY: `ctx`/`msg` are live.
    if unsafe { ossl_cmp_msg_protect(ctx, msg) } == 0 {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(964, c"ossl_cmp_pollReq_new", 124);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    msg
}

/// `OSSL_CMP_MSG *ossl_cmp_pollRep_new(OSSL_CMP_CTX *ctx, int crid, int64_t poll_after)` —
/// `cmp_msg.c:970-998`. Internal.
///
/// # Safety
/// `ctx` is live.
pub(crate) unsafe fn ossl_cmp_pollRep_new(
    ctx: *mut OsslCmpCtx,
    crid: c_int,
    poll_after: i64,
) -> *mut CmpMsg {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let msg = unsafe { ossl_cmp_msg_create(ctx, OSSL_CMP_PKIBODY_POLLREP) };
    if msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(995, c"ossl_cmp_pollRep_new", 123) };
        return ptr::null_mut();
    }
    // SAFETY: the accessor answers a fresh item value.
    let prep = unsafe { OSSL_CMP_POLLREP_new() };
    if prep.is_null() {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(995, c"ossl_cmp_pollRep_new", 123);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    // SAFETY: `msg`'s pollRep stack is mandatory; `prep` transfers in.
    let ok = unsafe { OPENSSL_sk_push((*(*msg).body).value.poll_rep, prep.cast()) } != 0
        && unsafe { ASN1_INTEGER_set((*prep).cert_req_id, crid as c_long) } != 0
        && unsafe { ASN1_INTEGER_set_int64((*prep).check_after, poll_after) } != 0;
    // SAFETY: `ctx`/`msg` are live.
    if !ok || unsafe { ossl_cmp_msg_protect(ctx, msg) } == 0 {
        // SAFETY: `msg` is live and owned here.
        unsafe {
            raise_cmp(995, c"ossl_cmp_pollRep_new", 123);
            OSSL_CMP_MSG_free(msg);
        }
        return ptr::null_mut();
    }
    msg
}

/// `OSSL_CMP_PKISI *ossl_cmp_revrepcontent_get_pkisi(OSSL_CMP_REVREPCONTENT *rrep, int rsid)` —
/// `cmp_msg.c:1007-1020`. Internal.
///
/// # Safety
/// `rrep` is NULL or live.
pub(crate) unsafe fn ossl_cmp_revrepcontent_get_pkisi(
    rrep: *mut CmpRevRepContent,
    rsid: c_int,
) -> *mut CmpPkisi {
    if rrep.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `rrep` is live and its status stack is mandatory.
    let status = unsafe { OPENSSL_sk_value((*rrep).status, rsid) }.cast::<CmpPkisi>();
    if !status.is_null() {
        return status;
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cmp(1018, c"ossl_cmp_revrepcontent_get_pkisi", 132) };
    ptr::null_mut()
}

/// `OSSL_CRMF_CERTID *ossl_cmp_revrepcontent_get_CertId(OSSL_CMP_REVREPCONTENT *rrep, int rsid)` —
/// `cmp_msg.c:1029-1042`. Internal.
///
/// # Safety
/// `rrep` is NULL or live.
pub(crate) unsafe fn ossl_cmp_revrepcontent_get_CertId(
    rrep: *mut CmpRevRepContent,
    rsid: c_int,
) -> *mut CrmfCertId {
    if rrep.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `rrep` is live; `revCerts` is NULL or a live stack.
    let cid = unsafe { OPENSSL_sk_value((*rrep).rev_certs, rsid) }.cast::<CrmfCertId>();
    if !cid.is_null() {
        return cid;
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cmp(1040, c"ossl_cmp_revrepcontent_get_CertId", 109) };
    ptr::null_mut()
}

/// `static int suitable_rid(const ASN1_INTEGER *certReqId, int rid)` — `cmp_msg.c:1044-1057`.
///
/// # Safety
/// `cert_req_id` is live.
unsafe fn suitable_rid(cert_req_id: *const Asn1String, rid: c_int) -> c_int {
    if rid == OSSL_CMP_CERTREQID_NONE {
        return 1;
    }
    // SAFETY: `cert_req_id` is live.
    let trid = unsafe { ossl_cmp_asn1_get_int(cert_req_id) };
    if trid <= OSSL_CMP_CERTREQID_INVALID {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(1053, c"suitable_rid", 108) };
        return 0;
    }
    c_int::from(rid == trid)
}

/// `OSSL_CMP_POLLREP *ossl_cmp_pollrepcontent_get0_pollrep(const OSSL_CMP_POLLREPCONTENT *prc,`
/// `int rid)` — `cmp_msg.c:1064-1083`. Internal.
///
/// # Safety
/// `prc` is NULL or live.
pub(crate) unsafe fn ossl_cmp_pollrepcontent_get0_pollrep(
    prc: *const OpenSslStack,
    rid: c_int,
) -> *mut CmpPollRep {
    if prc.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `prc` is a live stack.
    let n = unsafe { OPENSSL_sk_num(prc) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range.
        let poll_rep = unsafe { OPENSSL_sk_value(prc, i) }.cast::<CmpPollRep>();
        // SAFETY: `poll_rep` is a live element.
        if unsafe { suitable_rid((*poll_rep).cert_req_id, rid) } != 0 {
            return poll_rep;
        }
        i += 1;
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cmp(1080, c"ossl_cmp_pollrepcontent_get0_pollrep", 113) };
    ptr::null_mut()
}

/// `OSSL_CMP_CERTRESPONSE *ossl_cmp_certrepmessage_get0_certresponse(const`
/// `OSSL_CMP_CERTREPMESSAGE *crm, int rid)` — `cmp_msg.c:1090-1109`. Internal.
///
/// # Safety
/// `crm` is NULL or live.
pub(crate) unsafe fn ossl_cmp_certrepmessage_get0_certresponse(
    crm: *const CmpCertRepMessage,
    rid: c_int,
) -> *mut CmpCertResponse {
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if crm.is_null() || unsafe { (*crm).response }.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `crm`'s response stack is live.
    let n = unsafe { OPENSSL_sk_num((*crm).response) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range.
        let crep = unsafe { OPENSSL_sk_value((*crm).response, i) }.cast::<CmpCertResponse>();
        // SAFETY: `crep` is a live element.
        if unsafe { suitable_rid((*crep).cert_req_id, rid) } != 0 {
            return crep;
        }
        i += 1;
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cmp(1106, c"ossl_cmp_certrepmessage_get0_certresponse", 113) };
    ptr::null_mut()
}

/// `X509 *ossl_cmp_certresponse_get1_cert(const OSSL_CMP_CTX *ctx, const`
/// `OSSL_CMP_CERTRESPONSE *crep)` — `cmp_msg.c:1117-1182`. Internal.
///
/// # Safety
/// `ctx`/`crep` are live.
pub(crate) unsafe fn ossl_cmp_certresponse_get1_cert(
    ctx: *const OsslCmpCtx,
    crep: *const CmpCertResponse,
) -> *mut X509 {
    // SAFETY: `ctx` is live.
    let central_keygen =
        unsafe { OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_POPO_METHOD) } == OSSL_CRMF_POPO_NONE;
    // SAFETY: `crep` is live.
    if unsafe { (*crep).certified_key_pair }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(1127, c"ossl_cmp_certresponse_get1_cert", 112) };
        return ptr::null_mut();
    }
    // SAFETY: `crep` is live.
    let encr_key = unsafe { (*(*crep).certified_key_pair).private_key }.cast::<CrmfEncryptedKey>();
    if encr_key.is_null() && central_keygen {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(1132, c"ossl_cmp_certresponse_get1_cert", 204) };
        return ptr::null_mut();
    }
    let mut pkey: *mut EvpPkey;
    if !encr_key.is_null() {
        if !central_keygen {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(1137, c"ossl_cmp_certresponse_get1_cert", 205) };
            return ptr::null_mut();
        }
        // SAFETY: `ctx`/`encr_key` are live; the key is owned by the caller.
        pkey = unsafe {
            OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(
                encr_key,
                (*ctx).trusted,
                (*ctx).untrusted,
                (*ctx).pkey,
                (*ctx).cert,
                (*ctx).secret_value,
                (*ctx).libctx,
                (*ctx).propq,
            )
        };
        if pkey.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(1147, c"ossl_cmp_certresponse_get1_cert", 203) };
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is live; ownership of `pkey` moves into it.
        unsafe { OSSL_CMP_CTX_set0_newPkey(ctx.cast_mut(), 1, pkey) };
    }

    let mut crt: *mut X509 = ptr::null_mut();
    // SAFETY: `crep`'s key pair is live.
    let coec = unsafe { (*(*crep).certified_key_pair).cert_or_enc_cert };
    if !coec.is_null() {
        // SAFETY: `coec` is live.
        match unsafe { (*coec).type_ } {
            OSSL_CMP_CERTORENCCERT_CERTIFICATE => {
                // SAFETY: the certificate arm is set.
                crt = unsafe { X509_dup((*coec).value.certificate) };
            }
            1 => {
                // SAFETY: `ctx` is live.
                pkey = unsafe { OSSL_CMP_CTX_get0_newPkey(ctx, 1) }.cast::<EvpPkey>();
                if pkey.is_null() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_cmp(1166, c"ossl_cmp_certresponse_get1_cert", 131) };
                    return ptr::null_mut();
                }
                // SAFETY: `coec`/`pkey` are live; `ctx` is live.
                crt = unsafe {
                    OSSL_CRMF_ENCRYPTEDKEY_get1_encCert(
                        (*coec).value.encrypted_cert.cast(),
                        (*ctx).libctx,
                        (*ctx).propq,
                        pkey,
                        0,
                    )
                };
            }
            _ => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(1173, c"ossl_cmp_certresponse_get1_cert", 135) };
                return ptr::null_mut();
            }
        }
    }
    if crt.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(1178, c"ossl_cmp_certresponse_get1_cert", 112) };
    } else {
        // SAFETY: `crt` and `ctx` are live.
        unsafe { ossl_x509_set0_libctx(crt, (*ctx).libctx, (*ctx).propq) };
    }
    crt
}

/// `X509_PUBKEY *OSSL_CMP_MSG_get0_certreq_publickey(const OSSL_CMP_MSG *msg)` —
/// `cmp_msg.c:120-146`.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CMP_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_MSG_get0_certreq_publickey(
    msg: *const CmpMsg,
) -> *mut X509Pubkey {
    // SAFETY: `msg` is NULL or live.
    match unsafe { OSSL_CMP_MSG_get_bodytype(msg) } {
        OSSL_CMP_PKIBODY_IR | OSSL_CMP_PKIBODY_CR | OSSL_CMP_PKIBODY_KUR => {
            // SAFETY: `msg` is live.
            let reqs = unsafe { (*(*msg).body).value.ir };
            // SAFETY: `reqs` is live; the first element may be absent.
            let crm = unsafe { OPENSSL_sk_value(reqs, 0) }.cast::<CrmfMsg>();
            if crm.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(133, c"OSSL_CMP_MSG_get0_certreq_publickey", 157) };
                return ptr::null_mut();
            }
            // SAFETY: `crm` is live.
            let tmpl = unsafe { OSSL_CRMF_MSG_get0_tmpl(crm) };
            // SAFETY: `tmpl` is live or NULL.
            let pubkey = if tmpl.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
                unsafe { OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl) }
            };
            if pubkey.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(138, c"OSSL_CMP_MSG_get0_certreq_publickey", 118) };
                return ptr::null_mut();
            }
            pubkey
        }
        _ => {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(143, c"OSSL_CMP_MSG_get0_certreq_publickey", 133) };
            ptr::null_mut()
        }
    }
}

/// `int OSSL_CMP_MSG_update_transactionID(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)` —
/// `cmp_msg.c:1184-1194`.
///
/// # Safety
/// `ctx`/`msg` are NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_MSG_update_transactionID(
    ctx: *mut OsslCmpCtx,
    msg: *mut CmpMsg,
) -> c_int {
    if ctx.is_null() || msg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                1187,
                c"OSSL_CMP_MSG_update_transactionID",
                CMP_R_NULL_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `ctx`/`msg` are live.
    if unsafe { ossl_cmp_hdr_set_transactionID(ctx, (*msg).header) } == 0 {
        return 0;
    }
    // SAFETY: `msg` is live.
    if unsafe { (*(*msg).header).protection_alg }.is_null() {
        return 1;
    }
    // SAFETY: `ctx`/`msg` are live.
    unsafe { ossl_cmp_msg_protect(ctx, msg) }
}

/// `int OSSL_CMP_MSG_update_recipNonce(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)` —
/// `cmp_msg.c:1196-1208`.
///
/// # Safety
/// `ctx`/`msg` are NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_MSG_update_recipNonce(
    ctx: *mut OsslCmpCtx,
    msg: *mut CmpMsg,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if ctx.is_null() || msg.is_null() || unsafe { (*msg).header }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(1199, c"OSSL_CMP_MSG_update_recipNonce", CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).recip_nonce }.is_null() {
        return 1;
    }
    // SAFETY: `ctx`/`msg` are live; the header's recipient-nonce slot is writable.
    if unsafe {
        ossl_cmp_asn1_octet_string_set1(
            ptr::addr_of_mut!((*(*msg).header).recip_nonce),
            (*ctx).recip_nonce,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `msg` is live.
    if unsafe { (*(*msg).header).protection_alg }.is_null() {
        return 1;
    }
    // SAFETY: `ctx`/`msg` are live.
    unsafe { ossl_cmp_msg_protect(ctx, msg) }
}
