//! `crypto/cmp/cmp_util.c` — the CMP logging and small ASN.1 helpers. Phase 12.4.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces, non_camel_case_types, unused_assignments)]

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;

use crate::asn1::string::{
    ASN1_OCTET_STRING_dup, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set,
    ASN1_STRING_set, ASN1_UTF8STRING_free, ASN1_UTF8STRING_new,
};
use crate::runtime::bio::print::{BIO_printf, BIO_snprintf};
use crate::runtime::bio::Bio;
use crate::runtime::err::{ERR_get_error_all, ERR_lib_error_string, ERR_reason_error_string};
use crate::runtime::mem::CRYPTO_strndup;
use crate::runtime::stack::{OPENSSL_sk_push, OpenSslStack};
use crate::runtime::trace::OSSL_trace_set_channel;
use crate::x509::x509_lu::X509_STORE_add_cert;
use crate::x509::x509_vfy::X509_self_signed;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_util.c";

/// `OSSL_CMP_LOG_PREFIX` — `include/openssl/cmp_util.h:28`.
pub(crate) const OSSL_CMP_LOG_PREFIX: &core::ffi::CStr = c"CMP ";

/// The severity levels — `include/openssl/cmp_util.h:34-43`.
pub(crate) const OSSL_CMP_LOG_EMERG: c_int = 0;
pub(crate) const OSSL_CMP_LOG_ALERT: c_int = 1;
pub(crate) const OSSL_CMP_LOG_CRIT: c_int = 2;
pub(crate) const OSSL_CMP_LOG_ERR: c_int = 3;
pub(crate) const OSSL_CMP_LOG_WARNING: c_int = 4;
pub(crate) const OSSL_CMP_LOG_NOTICE: c_int = 5;
pub(crate) const OSSL_CMP_LOG_INFO: c_int = 6;
pub(crate) const OSSL_CMP_LOG_DEBUG: c_int = 7;
pub(crate) const OSSL_CMP_LOG_MAX: c_int = 8;

/// `OSSL_TRACE_CATEGORY_CMP` — `include/openssl/trace.h`.
const OSSL_TRACE_CATEGORY_CMP: c_int = 4;
/// `BIO_NOCLOSE`.
const BIO_NOCLOSE: c_int = 0;

/// `ERR_SYSTEM_FLAG`.
const ERR_SYSTEM_FLAG: c_ulong = 0x8000_0000;
/// `ERR_REASON_MASK`.
const ERR_REASON_MASK: c_ulong = 0x007F_FFFF;
/// `ERR_R_SYS_LIB`'s reason masking is not needed here; `ERR_TXT_STRING`.
const ERR_TXT_STRING: c_int = 0x02;

extern "C" {
    /// `strcmp`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    /// `strchr`.
    fn strchr(s: *const c_char, c: c_int) -> *mut c_char;
    /// `strtol`.
    fn strtol(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_long;
}

/// `OSSL_CMP_log_cb_t` — `include/openssl/cmp_util.h:44-45`.
pub(crate) type OSSL_CMP_log_cb_t =
    unsafe extern "C" fn(*const c_char, *const c_char, c_int, c_int, *const c_char) -> c_int;

/// `int OSSL_CMP_log_open(void)` — `cmp_util.c:23-38`. The admitted authority is built
/// `OPENSSL_NO_TRACE` (`include/openssl/configuration.h`), so the trace-channel arm is compiled
/// out and the function answers 1.
#[no_mangle]
pub extern "C" fn OSSL_CMP_log_open() -> c_int {
    1
}

/// `void OSSL_CMP_log_close(void)` — `cmp_util.c:40-43`.
///
/// # Safety
/// No preconditions; the trace channel is process-global.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_log_close() {
    // SAFETY: the trace channel is process-global and NULL is a valid channel.
    OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_CMP, ptr::null_mut());
}

/// `static OSSL_CMP_severity parse_level(const char *level)` — `cmp_util.c:47-70`. Internal.
///
/// # Safety
/// `level` is a NUL-terminated string.
unsafe fn parse_level(level: *const c_char) -> c_int {
    // SAFETY: `level` is NUL-terminated per the contract.
    let end = unsafe { strchr(level, b':' as c_int) };
    if end.is_null() {
        return -1;
    }
    let mut p = level;
    // HAS_PREFIX(level, "CMP ")
    // SAFETY: both are NUL-terminated.
    if unsafe {
        *p == b'C' as c_char
            && *p.add(1) == b'M' as c_char
            && *p.add(2) == b'P' as c_char
            && *p.add(3) == b' ' as c_char
    } {
        // SAFETY: `p` is readable for at least four bytes (`CMP `).
        p = unsafe { p.add(4) };
    }
    let len = (end as usize).wrapping_sub(p as usize);
    if len > 5 {
        return -1;
    }
    let mut buf = [0 as c_char; 6];
    let mut i = 0;
    while i < len {
        // SAFETY: `p` is readable for `len` bytes.
        buf[i] = unsafe { *p.add(i) };
        i += 1;
    }
    let name = core::ffi::CStr::from_bytes_until_nul(cast_slice(&buf)).unwrap_or(c"");
    match name.to_bytes() {
        b"EMERG" => OSSL_CMP_LOG_EMERG,
        b"ALERT" => OSSL_CMP_LOG_ALERT,
        b"CRIT" => OSSL_CMP_LOG_CRIT,
        b"ERROR" => OSSL_CMP_LOG_ERR,
        b"WARN" => OSSL_CMP_LOG_WARNING,
        b"NOTE" => OSSL_CMP_LOG_NOTICE,
        b"INFO" => OSSL_CMP_LOG_INFO,
        b"DEBUG" => OSSL_CMP_LOG_DEBUG,
        _ => -1,
    }
}

/// Reinterpret a `[c_char; N]` as bytes, for `CStr::from_bytes_until_nul`.
fn cast_slice(buf: &[c_char]) -> &[u8] {
    // SAFETY: `c_char` is `i8`/`u8`; reinterpreting the signed array as bytes is valid.
    unsafe { core::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len()) }
}

/// `const char *ossl_cmp_log_parse_metadata(const char *buf, ...)` — `cmp_util.c:72-109`. Internal.
///
/// # Safety
/// `buf` is NULL or a NUL-terminated string; the output pointers are NULL or writable.
pub(crate) unsafe fn ossl_cmp_log_parse_metadata(
    buf: *const c_char,
    level: *mut c_int,
    func: *mut *mut c_char,
    file: *mut *mut c_char,
    line: *mut c_int,
) -> *const c_char {
    let p_func = buf;
    let p_file = if buf.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `buf` is NUL-terminated per the contract.
        unsafe { strchr(buf, b':' as c_int) }
    };
    let mut msg = buf;
    // SAFETY: the output pointers are writable per the contract.
    unsafe {
        *level = -1;
        *func = ptr::null_mut();
        *file = ptr::null_mut();
        *line = 0;
    }
    if p_file.is_null() {
        return msg;
    }
    // SAFETY: `p_file` is within `buf`.
    let p_line = unsafe { strchr(p_file.add(1), b':' as c_int) };
    // SAFETY: `buf` is NUL-terminated.
    let lvl = unsafe { parse_level(buf) };
    if lvl < 0 && !p_line.is_null() {
        let mut endp: *mut c_char = ptr::null_mut();
        // SAFETY: `p_line` points at a `:`, so the next char begins a number.
        let line_number = unsafe { strtol(p_line.add(1), &mut endp, 10) };
        let mut p_level = endp;
        // SAFETY: `p_line` points within `buf`; `endp` and `p_level` are valid.
        if p_level > unsafe { p_line.add(1) } && unsafe { *p_level } == b':' as c_char {
            // SAFETY: `p_level` is readable.
            p_level = unsafe { p_level.add(1) };
            // SAFETY: `p_level` is NUL-terminated within `buf`.
            let l2 = unsafe { parse_level(p_level) };
            if l2 >= 0 {
                // SAFETY: the string spans `buf`..`p_file`; copy it.
                let flen = (p_file as usize)
                    .wrapping_sub(1)
                    .wrapping_sub(p_func as usize);
                // SAFETY: the output pointers are writable per the contract.
                unsafe {
                    *level = l2;
                    *func = CRYPTO_strndup(p_func, flen, FILE.as_ptr(), 97);
                    *file = CRYPTO_strndup(
                        p_file,
                        (p_line as usize)
                            .wrapping_sub(1)
                            .wrapping_sub(p_file as usize),
                        FILE.as_ptr(),
                        98,
                    );
                    *line = line_number as c_int;
                }
                // SAFETY: `p_level` is NUL-terminated within `buf`.
                msg = unsafe { strchr(p_level, b':' as c_int) };
                if !msg.is_null() {
                    // SAFETY: `msg` points at the `:`.
                    let next = unsafe { msg.add(1) };
                    // SAFETY: `next` is within `buf`.
                    msg = if unsafe { *next } == b' ' as c_char {
                        // SAFETY: `next` is within `buf`.
                        unsafe { next.add(1) }
                    } else {
                        next
                    };
                }
            }
        }
    }
    msg
}

/// `static const char *improve_location_name(const char *func, const char *fallback)` —
/// `cmp_util.c:116-124`.
///
/// # Safety
/// `func` and `fallback` are NULL or NUL-terminated.
unsafe fn improve_location_name(func: *const c_char, fallback: *const c_char) -> *const c_char {
    if fallback.is_null() {
        return if func.is_null() {
            c"(unknown function)".as_ptr()
        } else {
            func
        };
    }
    if func.is_null()
        // SAFETY: `func` is NULL or NUL-terminated per the contract.
        || unsafe { *func } == 0
        // SAFETY: both strings are NUL-terminated.
        || unsafe { strcmp(func, c"(unknown function)".as_ptr()) } == 0
    {
        fallback
    } else {
        func
    }
}

/// `int OSSL_CMP_print_to_bio(BIO *bio, const char *component, const char *file, int line,
/// OSSL_CMP_severity level, const char *msg)` — `cmp_util.c:126-147`.
///
/// # Safety
/// `bio` is a live BIO; the `const char *` arguments are NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_print_to_bio(
    bio: *mut Bio,
    _component: *const c_char,
    _file: *const c_char,
    _line: c_int,
    level: c_int,
    msg: *const c_char,
) -> c_int {
    let level_string = match level {
        OSSL_CMP_LOG_EMERG => c"EMERG".as_ptr(),
        OSSL_CMP_LOG_ALERT => c"ALERT".as_ptr(),
        OSSL_CMP_LOG_CRIT => c"CRIT".as_ptr(),
        OSSL_CMP_LOG_ERR => c"error".as_ptr(),
        OSSL_CMP_LOG_WARNING => c"warning".as_ptr(),
        OSSL_CMP_LOG_NOTICE => c"NOTE".as_ptr(),
        OSSL_CMP_LOG_INFO => c"info".as_ptr(),
        OSSL_CMP_LOG_DEBUG => c"DEBUG".as_ptr(),
        _ => c"(unknown level)".as_ptr(),
    };
    // NDEBUG is defined for the admitted production build, so the `#ifndef NDEBUG` location
    // prefix is not emitted; the second `BIO_printf` is the whole body.
    // SAFETY: `bio` is live; the format and its arguments are valid.
    ((unsafe { BIO_printf(bio, c"CMP %s: %s\n".as_ptr(), level_string, msg) }) >= 0) as c_int
}

/// `void OSSL_CMP_print_errors_cb(OSSL_CMP_log_cb_t log_fn)` — `cmp_util.c:151-198`.
///
/// # Safety
/// `log_fn` is NULL or a valid callback.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_print_errors_cb(log_fn: Option<OSSL_CMP_log_cb_t>) {
    const BUF: usize = 4096;
    let mut msg = [0 as c_char; BUF];
    let mut rsbuf = [0 as c_char; 256];
    loop {
        let mut file: *const c_char = ptr::null();
        let mut func: *const c_char = ptr::null();
        let mut data: *const c_char = ptr::null();
        let mut line: c_int = 0;
        let mut flags: c_int = 0;
        // SAFETY: all output pointers are writable.
        let err =
            unsafe { ERR_get_error_all(&mut file, &mut line, &mut func, &mut data, &mut flags) };
        if err == 0 {
            break;
        }
        // SAFETY: `err` is a live error code.
        let component = unsafe { improve_location_name(func, ERR_lib_error_string(err)) };
        let reason = if (err & ERR_SYSTEM_FLAG) != 0 {
            err
        } else {
            err & ERR_REASON_MASK
        };
        // SAFETY: `err` is a live error code.
        let mut rs = ERR_reason_error_string(err);
        if rs.is_null() {
            // SAFETY: `rsbuf` is writable for its length.
            unsafe {
                BIO_snprintf(
                    rsbuf.as_mut_ptr(),
                    rsbuf.len(),
                    c"reason(%lu)".as_ptr(),
                    reason,
                )
            };
            rs = rsbuf.as_ptr();
        }
        // SAFETY: `msg` is writable for `BUF`; `rs` and `data` are NUL-terminated.
        unsafe {
            if !data.is_null() && (flags & ERR_TXT_STRING) != 0 {
                BIO_snprintf(msg.as_mut_ptr(), BUF, c"%s:%s".as_ptr(), rs, data);
            } else {
                BIO_snprintf(msg.as_mut_ptr(), BUF, c"%s".as_ptr(), rs);
            }
        }
        match log_fn {
            None => {
                // SAFETY: `stderr` is the C library's FILE.
                let bio = unsafe {
                    crate::runtime::bio::bss_file::BIO_new_fp(
                        crate::runtime::bio::sys::stderr.cast::<c_void>(),
                        BIO_NOCLOSE,
                    )
                };
                if !bio.is_null() {
                    // SAFETY: `bio` is live; the arguments are valid.
                    unsafe {
                        OSSL_CMP_print_to_bio(
                            bio,
                            component,
                            file,
                            line,
                            OSSL_CMP_LOG_ERR,
                            msg.as_ptr(),
                        )
                    };
                    // SAFETY: `bio` is live.
                    unsafe { crate::runtime::bio::BIO_free(bio) };
                }
            }
            Some(cb) => {
                // SAFETY: `msg.as_ptr()` is NUL-terminated; the callback is the caller's.
                if unsafe { cb(component, file, line, OSSL_CMP_LOG_ERR, msg.as_ptr()) } <= 0 {
                    break;
                }
            }
        }
    }
}

/// `int ossl_cmp_X509_STORE_add1_certs(X509_STORE *store, STACK_OF(X509) *certs,
/// int only_self_signed)` — `cmp_util.c:200-219`. Internal.
///
/// # Safety
/// `store` is NULL or live; `certs` is NULL or a live stack.
pub(crate) unsafe fn ossl_cmp_X509_STORE_add1_certs(
    store: *mut crate::x509::x509_lu::X509Store,
    certs: *mut OpenSslStack,
    only_self_signed: c_int,
) -> c_int {
    if store.is_null() {
        return 0;
    }
    if certs.is_null() {
        return 1;
    }
    // SAFETY: `certs` is a live stack.
    let n = unsafe { crate::runtime::stack::OPENSSL_sk_num(certs) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range.
        let cert = unsafe { crate::runtime::stack::OPENSSL_sk_value(certs, i) }
            as *mut crate::x509::x_x509::X509;
        let ok = if only_self_signed == 0
            // SAFETY: `cert` is a live element.
            || unsafe { X509_self_signed(cert, 0) } == 1
        {
            // SAFETY: `store` and `cert` are live.
            (unsafe { X509_STORE_add_cert(store, cert) }) != 0
        } else {
            true
        };
        if !ok {
            return 0;
        }
        i += 1;
    }
    1
}

/// `int ossl_cmp_sk_ASN1_UTF8STRING_push_str(STACK_OF(ASN1_UTF8STRING) *sk, const char *text,
/// int len)` — `cmp_util.c:221-239`. Internal.
///
/// # Safety
/// `sk` is a live stack; `text` is NULL or readable for `len` bytes.
pub(crate) unsafe fn ossl_cmp_sk_ASN1_UTF8STRING_push_str(
    sk: *mut OpenSslStack,
    text: *const c_char,
    len: c_int,
) -> c_int {
    if sk.is_null() || text.is_null() {
        return 0;
    }
    let utf8 = ASN1_UTF8STRING_new();
    if utf8.is_null() {
        return 0;
    }
    // SAFETY: `utf8` is live; `text` is readable for `len` bytes.
    if unsafe { ASN1_STRING_set(utf8, text.cast(), len) } == 0 {
        // SAFETY: `utf8` is live.
        unsafe { ASN1_UTF8STRING_free(utf8) };
        return 0;
    }
    // SAFETY: `sk` and `utf8` are live.
    if unsafe { OPENSSL_sk_push(sk, utf8.cast()) } == 0 {
        // SAFETY: `utf8` is live.
        unsafe { ASN1_UTF8STRING_free(utf8) };
        return 0;
    }
    1
}

/// `int ossl_cmp_asn1_octet_string_set1(ASN1_OCTET_STRING **tgt, const ASN1_OCTET_STRING *src)` —
/// `cmp_util.c:241-263`. Internal.
///
/// # Safety
/// `tgt` is NULL or a writable slot; `src` is NULL or live.
pub(crate) unsafe fn ossl_cmp_asn1_octet_string_set1(
    tgt: *mut *mut crate::asn1::layout::Asn1String,
    src: *const crate::asn1::layout::Asn1String,
) -> c_int {
    if tgt.is_null() {
        return 0;
    }
    // SAFETY: `tgt` is writable.
    if unsafe { *tgt } == src.cast_mut() {
        return 1;
    }
    let new = if !src.is_null() {
        // SAFETY: `src` is live.
        unsafe { ASN1_OCTET_STRING_dup(src) }
    } else {
        ptr::null_mut()
    };
    if !src.is_null() && new.is_null() {
        return 0;
    }
    // SAFETY: `tgt` is writable.
    unsafe {
        ASN1_OCTET_STRING_free(*tgt);
        *tgt = new;
    }
    1
}

/// `int ossl_cmp_asn1_octet_string_set1_bytes(ASN1_OCTET_STRING **tgt, const unsigned char *bytes,
/// int len)` — `cmp_util.c:265-285`. Internal.
///
/// # Safety
/// `tgt` is NULL or a writable slot; `bytes` is NULL or readable for `len` bytes.
pub(crate) unsafe fn ossl_cmp_asn1_octet_string_set1_bytes(
    tgt: *mut *mut crate::asn1::layout::Asn1String,
    bytes: *const u8,
    len: c_int,
) -> c_int {
    if tgt.is_null() {
        return 0;
    }
    let mut new: *mut crate::asn1::layout::Asn1String = ptr::null_mut();
    if !bytes.is_null() {
        new = ASN1_OCTET_STRING_new();
        if new.is_null() {
            return 0;
        }
        // SAFETY: `new` is live; `bytes` is readable for `len` bytes.
        if unsafe { ASN1_OCTET_STRING_set(new, bytes, len) } == 0 {
            // SAFETY: `new` is live.
            unsafe { ASN1_OCTET_STRING_free(new) };
            return 0;
        }
    }
    // SAFETY: `tgt` is writable.
    unsafe {
        ASN1_OCTET_STRING_free(*tgt);
        *tgt = new;
    }
    1
}
