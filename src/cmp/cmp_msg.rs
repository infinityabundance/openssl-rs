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

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::ASN1_item_d2i_bio_ex;
use crate::asn1::a_i2d_fp::ASN1_i2d_bio;
use crate::asn1::d2i::ASN1_item_d2i_ex;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::I2dOfVoid;
use crate::asn1::new::ASN1_item_new_ex;
use crate::cmp::cmp_asn::{cmp_msg_it, ossl_cmp_msg_set0_libctx, CmpMsg, CmpPkiHeader};
use crate::runtime::bio::bss_file::BIO_new_file;
use crate::runtime::bio::{BIO_free, Bio};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;

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
