//! `crypto/cmp/cmp_status.c` — the CMP `PKIStatusInfo` handling. Phase 12.4.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces, unused_assignments)]

use core::ffi::{c_char, c_int, c_long};
use core::ptr;

use crate::asn1::bitstr::{ASN1_BIT_STRING_get_bit, ASN1_BIT_STRING_set_bit};
use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::asn1::prim::ASN1_INTEGER_set;
use crate::asn1::string::ASN1_STRING_set;
use crate::asn1::string::{ASN1_BIT_STRING_new, ASN1_UTF8STRING_free, ASN1_UTF8STRING_new};
use crate::cmp::cmp_asn::{
    ossl_cmp_asn1_get_int, CmpPkisi, OSSL_CMP_PKISI_free, OSSL_CMP_PKISI_new,
};
use crate::cmp::cmp_ctx::OsslCmpCtx;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_status.c";

/// `ERR_LIB_CMP`.
const ERR_LIB_CMP: c_int = 58;

/// The `PKIStatus` values — `include/openssl/cmp.h.in:199-211`.
pub(crate) const OSSL_CMP_PKISTATUS_rejected_by_client: c_int = -5;
pub(crate) const OSSL_CMP_PKISTATUS_checking_response: c_int = -4;
pub(crate) const OSSL_CMP_PKISTATUS_request: c_int = -3;
pub(crate) const OSSL_CMP_PKISTATUS_trans: c_int = -2;
pub(crate) const OSSL_CMP_PKISTATUS_unspecified: c_int = -1;
pub(crate) const OSSL_CMP_PKISTATUS_accepted: c_int = 0;
pub(crate) const OSSL_CMP_PKISTATUS_grantedWithMods: c_int = 1;
pub(crate) const OSSL_CMP_PKISTATUS_rejection: c_int = 2;
pub(crate) const OSSL_CMP_PKISTATUS_waiting: c_int = 3;
pub(crate) const OSSL_CMP_PKISTATUS_revocationWarning: c_int = 4;
pub(crate) const OSSL_CMP_PKISTATUS_revocationNotification: c_int = 5;
pub(crate) const OSSL_CMP_PKISTATUS_keyUpdateWarning: c_int = 6;

/// `OSSL_CMP_PKIFAILUREINFO_MAX` — the highest defined failure bit.
pub(crate) const OSSL_CMP_PKIFAILUREINFO_MAX: c_int = 26;

/// One raise coordinate of this unit.
const fn cmp_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: FILE,
        line,
        func,
        lib: ERR_LIB_CMP,
        reason,
        dynamic_reason: false,
    }
}

/// `ERR_raise(ERR_LIB_CMP, reason)` at a coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_cmp(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_site(&cmp_site(line, func, reason)) };
}

/// `int ossl_cmp_pkisi_get_status(const OSSL_CMP_PKISI *si)` — `cmp_status.c:18-26`. Internal.
///
/// # Safety
/// `si` is NULL or live.
pub(crate) unsafe fn ossl_cmp_pkisi_get_status(si: *const CmpPkisi) -> c_int {
    if si.is_null() {
        return -1;
    }
    // SAFETY: `si` is live.
    let status = unsafe { (*si).status };
    if status.is_null() {
        return -1;
    }
    // SAFETY: `status` is live.
    let res = unsafe { ossl_cmp_asn1_get_int(status) };
    if res == -2 {
        -1
    } else {
        res
    }
}

/// `const char *ossl_cmp_PKIStatus_to_string(int status)` — `cmp_status.c:28-50`. Internal.
///
/// # Safety
/// The site is a compile-time constant when the status is invalid.
pub(crate) unsafe fn ossl_cmp_PKIStatus_to_string(status: c_int) -> *const c_char {
    match status {
        OSSL_CMP_PKISTATUS_accepted => c"PKIStatus: accepted".as_ptr(),
        OSSL_CMP_PKISTATUS_grantedWithMods => c"PKIStatus: granted with modifications".as_ptr(),
        OSSL_CMP_PKISTATUS_rejection => c"PKIStatus: rejection".as_ptr(),
        OSSL_CMP_PKISTATUS_waiting => c"PKIStatus: waiting".as_ptr(),
        OSSL_CMP_PKISTATUS_revocationWarning => {
            c"PKIStatus: revocation warning - a revocation of the cert is imminent".as_ptr()
        }
        OSSL_CMP_PKISTATUS_revocationNotification => {
            c"PKIStatus: revocation notification - a revocation of the cert has occurred".as_ptr()
        }
        OSSL_CMP_PKISTATUS_keyUpdateWarning => {
            c"PKIStatus: key update warning - update already done for the cert".as_ptr()
        }
        _ => {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(46, c"ossl_cmp_PKIStatus_to_string", 107) };
            ptr::null()
        }
    }
}

/// `OSSL_CMP_PKIFREETEXT *ossl_cmp_pkisi_get0_statusString(const OSSL_CMP_PKISI *si)` —
/// `cmp_status.c:52-57`. Internal.
///
/// # Safety
/// `si` is NULL or live.
pub(crate) unsafe fn ossl_cmp_pkisi_get0_statusString(
    si: *const CmpPkisi,
) -> *mut crate::runtime::stack::OpenSslStack {
    if si.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `si` is live.
    unsafe { (*si).status_string }
}

/// `int ossl_cmp_pkisi_get_pkifailureinfo(const OSSL_CMP_PKISI *si)` — `cmp_status.c:59-71`.
/// Internal.
///
/// # Safety
/// `si` is NULL or live.
pub(crate) unsafe fn ossl_cmp_pkisi_get_pkifailureinfo(si: *const CmpPkisi) -> c_int {
    if si.is_null() {
        return -1;
    }
    // SAFETY: `si` is live.
    let fail_info = unsafe { (*si).fail_info };
    let mut res = 0;
    if !fail_info.is_null() {
        let mut i = 0;
        while i <= OSSL_CMP_PKIFAILUREINFO_MAX {
            // SAFETY: `fail_info` is live.
            if unsafe { ASN1_BIT_STRING_get_bit(fail_info, i) } != 0 {
                res |= 1 << i;
            }
            i += 1;
        }
    }
    res
}

/// `static const char *CMP_PKIFAILUREINFO_to_string(int number)` — `cmp_status.c:77-137`.
fn pkifailureinfo_to_string(number: c_int) -> *const c_char {
    match number {
        0 => c"badAlg".as_ptr(),
        1 => c"badMessageCheck".as_ptr(),
        2 => c"badRequest".as_ptr(),
        3 => c"badTime".as_ptr(),
        4 => c"badCertId".as_ptr(),
        5 => c"badDataFormat".as_ptr(),
        6 => c"wrongAuthority".as_ptr(),
        7 => c"incorrectData".as_ptr(),
        8 => c"missingTimeStamp".as_ptr(),
        9 => c"badPOP".as_ptr(),
        10 => c"certRevoked".as_ptr(),
        11 => c"certConfirmed".as_ptr(),
        12 => c"wrongIntegrity".as_ptr(),
        13 => c"badRecipientNonce".as_ptr(),
        14 => c"timeNotAvailable".as_ptr(),
        15 => c"unacceptedPolicy".as_ptr(),
        16 => c"unacceptedExtension".as_ptr(),
        17 => c"addInfoNotAvailable".as_ptr(),
        18 => c"badSenderNonce".as_ptr(),
        19 => c"badCertTemplate".as_ptr(),
        20 => c"signerNotTrusted".as_ptr(),
        21 => c"transactionIdInUse".as_ptr(),
        22 => c"unsupportedVersion".as_ptr(),
        23 => c"notAuthorized".as_ptr(),
        24 => c"systemUnavail".as_ptr(),
        25 => c"systemFailure".as_ptr(),
        26 => c"duplicateCertReq".as_ptr(),
        _ => ptr::null(),
    }
}

/// `int ossl_cmp_pkisi_check_pkifailureinfo(const OSSL_CMP_PKISI *si, int bit_index)` —
/// `cmp_status.c:139-149`. Internal.
///
/// # Safety
/// `si` is NULL or live.
pub(crate) unsafe fn ossl_cmp_pkisi_check_pkifailureinfo(
    si: *const CmpPkisi,
    bit_index: c_int,
) -> c_int {
    if si.is_null() {
        return -1;
    }
    // SAFETY: `si` is live.
    let fail_info = unsafe { (*si).fail_info };
    if fail_info.is_null() {
        return -1;
    }
    if !(0..=OSSL_CMP_PKIFAILUREINFO_MAX).contains(&bit_index) {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(144, c"ossl_cmp_pkisi_check_pkifailureinfo", 100) };
        return -1;
    }
    // SAFETY: `fail_info` is live.
    unsafe { ASN1_BIT_STRING_get_bit(fail_info, bit_index) }
}

/// `static char *snprint_PKIStatusInfo_parts(...)` — `cmp_status.c:155-225`.
///
/// # Safety
/// `buf` is writable for `bufsize` bytes; `status_strings` is NULL or a live stack.
unsafe fn snprint_pkistatusinfo_parts(
    status: c_int,
    fail_info: c_int,
    status_strings: *const crate::runtime::stack::OpenSslStack,
    buf: *mut c_char,
    bufsize: usize,
) -> *mut c_char {
    if buf.is_null() || status < 0 {
        return ptr::null_mut();
    }
    // SAFETY: the site is a compile-time constant.
    let status_string = unsafe { ossl_cmp_PKIStatus_to_string(status) };
    if status_string.is_null() {
        return ptr::null_mut();
    }
    let mut write_ptr = buf;
    let mut size = bufsize;
    // SAFETY: `write_ptr`/`size` describe the writable buffer.
    let mut printed = unsafe { BIO_snprintf(write_ptr, size, c"%s".as_ptr(), status_string) };
    if printed < 0 || printed as usize >= size {
        return ptr::null_mut();
    }
    // SAFETY: `printed` bytes were written.
    write_ptr = unsafe { write_ptr.add(printed as usize) };
    size -= printed as usize;

    let mut failinfo_found = false;
    if fail_info != -1 && fail_info != 0 {
        // SAFETY: the buffer and its remaining size are valid.
        printed = unsafe { BIO_snprintf(write_ptr, size, c"; PKIFailureInfo: ".as_ptr()) };
        if printed < 0 || printed as usize >= size {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        write_ptr = unsafe { write_ptr.add(printed as usize) };
        size -= printed as usize;
        let mut failure = 0;
        while failure <= OSSL_CMP_PKIFAILUREINFO_MAX {
            if (fail_info & (1 << failure)) != 0 {
                let fs = pkifailureinfo_to_string(failure);
                if !fs.is_null() {
                    // SAFETY: the buffer is valid; the format and arguments are valid.
                    printed = unsafe {
                        BIO_snprintf(
                            write_ptr,
                            size,
                            c"%s%s".as_ptr(),
                            if failinfo_found {
                                c", ".as_ptr()
                            } else {
                                c"".as_ptr()
                            },
                            fs,
                        )
                    };
                    if printed < 0 || printed as usize >= size {
                        return ptr::null_mut();
                    }
                    // SAFETY: as above.
                    write_ptr = unsafe { write_ptr.add(printed as usize) };
                    size -= printed as usize;
                    failinfo_found = true;
                }
            }
            failure += 1;
        }
    }
    if !failinfo_found
        && status != OSSL_CMP_PKISTATUS_accepted
        && status != OSSL_CMP_PKISTATUS_grantedWithMods
    {
        // SAFETY: the buffer is valid.
        printed = unsafe { BIO_snprintf(write_ptr, size, c"; <no failure info>".as_ptr()) };
        if printed < 0 || printed as usize >= size {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        write_ptr = unsafe { write_ptr.add(printed as usize) };
        size -= printed as usize;
    }

    // SAFETY: `status_strings` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(status_strings) };
    if n > 0 {
        // SAFETY: the buffer is valid.
        printed = unsafe {
            BIO_snprintf(
                write_ptr,
                size,
                c"; StatusString%s: ".as_ptr(),
                if n > 1 { c"s".as_ptr() } else { c"".as_ptr() },
            )
        };
        if printed < 0 || printed as usize >= size {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        write_ptr = unsafe { write_ptr.add(printed as usize) };
        size -= printed as usize;
        let mut i = 0;
        while i < n {
            // SAFETY: `i` is in range.
            let text = unsafe { OPENSSL_sk_value(status_strings, i) } as *const Asn1String;
            // SAFETY: `text` is a live element.
            let (tlen, tdata) = unsafe { ((*text).length, (*text).data) };
            // SAFETY: the buffer is valid; `tdata` is readable for `tlen` bytes.
            printed = unsafe {
                BIO_snprintf(
                    write_ptr,
                    size,
                    c"\"%.*s\"%s".as_ptr(),
                    tlen,
                    tdata,
                    if i < n - 1 {
                        c", ".as_ptr()
                    } else {
                        c"".as_ptr()
                    },
                )
            };
            if printed < 0 || printed as usize >= size {
                return ptr::null_mut();
            }
            // SAFETY: as above.
            write_ptr = unsafe { write_ptr.add(printed as usize) };
            size -= printed as usize;
            i += 1;
        }
    }
    buf
}

/// `char *OSSL_CMP_snprint_PKIStatusInfo(const OSSL_CMP_PKISI *statusInfo, char *buf,
/// size_t bufsize)` — `cmp_status.c:227-242`.
///
/// # Safety
/// `statusInfo` is NULL or live; `buf` is writable for `bufsize` bytes.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_snprint_PKIStatusInfo(
    status_info: *const CmpPkisi,
    buf: *mut c_char,
    bufsize: usize,
) -> *mut c_char {
    if status_info.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(233, c"OSSL_CMP_snprint_PKIStatusInfo", 103) };
        return ptr::null_mut();
    }
    // SAFETY: `status_info` is live.
    let failure_info = unsafe { ossl_cmp_pkisi_get_pkifailureinfo(status_info) };
    // SAFETY: `status_info` is live.
    let status = unsafe { ASN1_INTEGER_get((*status_info).status) };
    // SAFETY: `status_info` is live.
    let strings = unsafe { (*status_info).status_string };
    // SAFETY: the arguments are valid per the contract.
    unsafe { snprint_pkistatusinfo_parts(status as c_int, failure_info, strings, buf, bufsize) }
}

/// `char *OSSL_CMP_CTX_snprint_PKIStatus(const OSSL_CMP_CTX *ctx, char *buf, size_t bufsize)` —
/// `cmp_status.c:244-256`.
///
/// # Safety
/// `ctx` is NULL or live; `buf` is writable for `bufsize` bytes.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_snprint_PKIStatus(
    ctx: *const OsslCmpCtx,
    buf: *mut c_char,
    bufsize: usize,
) -> *mut c_char {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(248, c"OSSL_CMP_CTX_snprint_PKIStatus", 103) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let (status, fail_info, strings) =
        unsafe { ((*ctx).status, (*ctx).fail_info_code, (*ctx).status_string) };
    // SAFETY: the arguments are valid per the contract.
    unsafe { snprint_pkistatusinfo_parts(status, fail_info, strings, buf, bufsize) }
}

/// `OSSL_CMP_PKISI *OSSL_CMP_STATUSINFO_new(int status, int fail_info, const char *text)` —
/// `cmp_status.c:264-303`.
///
/// # Safety
/// `text` is NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_STATUSINFO_new(
    status: c_int,
    fail_info: c_int,
    text: *const c_char,
) -> *mut CmpPkisi {
    let si = OSSL_CMP_PKISI_new();
    if si.is_null() {
        return ptr::null_mut();
    }
    let mut utf8_text: *mut Asn1String = ptr::null_mut();
    // SAFETY: `si` is live.
    if unsafe { ASN1_INTEGER_set((*si).status, status as c_long) } == 0 {
        // SAFETY: `si` is live.
        unsafe { OSSL_CMP_PKISI_free(si) };
        return ptr::null_mut();
    }
    if !text.is_null() {
        utf8_text = ASN1_UTF8STRING_new();
        // SAFETY: `text` is NUL-terminated.
        if utf8_text.is_null() || unsafe { ASN1_STRING_set(utf8_text, text.cast(), -1) } == 0 {
            // SAFETY: `si`/`utf8_text` are NULL or live.
            unsafe {
                OSSL_CMP_PKISI_free(si);
                ASN1_UTF8STRING_free(utf8_text);
            }
            return ptr::null_mut();
        }
        let sk = OPENSSL_sk_new_null();
        // SAFETY: `si` is live.
        unsafe { (*si).status_string = sk };
        if sk.is_null() {
            // SAFETY: `si`/`utf8_text` are live.
            unsafe {
                OSSL_CMP_PKISI_free(si);
                ASN1_UTF8STRING_free(utf8_text);
            }
            return ptr::null_mut();
        }
        // SAFETY: `sk` and `utf8_text` are live.
        if unsafe { OPENSSL_sk_push(sk, utf8_text.cast()) } == 0 {
            // SAFETY: `si`/`utf8_text` are live.
            unsafe {
                OSSL_CMP_PKISI_free(si);
                ASN1_UTF8STRING_free(utf8_text);
            }
            return ptr::null_mut();
        }
        utf8_text = ptr::null_mut(); /* ownership lost */
    }
    let mut failure = 0;
    while failure <= OSSL_CMP_PKIFAILUREINFO_MAX {
        if (fail_info & (1 << failure)) != 0 {
            // SAFETY: `si` is live.
            if unsafe { (*si).fail_info }.is_null() {
                let b = ASN1_BIT_STRING_new();
                // SAFETY: `si` is live.
                unsafe { (*si).fail_info = b };
                if b.is_null() {
                    // SAFETY: `si` is live.
                    unsafe { OSSL_CMP_PKISI_free(si) };
                    return ptr::null_mut();
                }
            }
            // SAFETY: `si` is live.
            let fi = unsafe { (*si).fail_info };
            // SAFETY: `fi` is live.
            if unsafe { ASN1_BIT_STRING_set_bit(fi, failure, 1) } == 0 {
                // SAFETY: `si` is live.
                unsafe { OSSL_CMP_PKISI_free(si) };
                return ptr::null_mut();
            }
        }
        failure += 1;
    }
    si
}
