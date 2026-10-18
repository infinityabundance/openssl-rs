//! `crypto/ct/ct_b64.c` — the base64 SCT and CT-log constructors. Phase 10.14.15's CT layer.
//!
//! `crypto/ct/ct_b64.c` is 174 lines and transcribes whole: the `static` decoder
//! `ct_base64_decode`, and the three exports `SCT_new_from_base64`,
//! `CTLOG_new_from_base64_ex` and `CTLOG_new_from_base64` (`include/openssl/ct.h.in:156-161`,
//! `:454-464`).
//!
//! **Withheld by name**: none.
//!
//! ## The raise sites
//!
//! `crypto/ct/ct_b64.c` is not an entry in `gen_err_raise_sites.py`, so its nine coordinates are
//! **declared locally**, their reason values read from `include/openssl/cterr.h` and
//! `include/openssl/err.h.in`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use crate::runtime::owned_buf::OwnedBuf;
use core::ffi::{c_char, c_int, c_long, c_uchar, c_void, CStr};
use core::ptr;

use crate::ct::ct_log::{CTLOG_new_ex, Ctlog};
use crate::ct::ct_oct::o2i_SCT_signature;
use crate::ct::ct_sct::{
    SCT_free, SCT_new, SCT_set0_extensions, SCT_set0_log_id, SCT_set_log_entry_type,
    SCT_set_timestamp, SCT_set_version, Sct,
};
use crate::evp::encode::EVP_DecodeBlock;
use crate::evp::pkey::EVP_PKEY_free;
use crate::runtime::bio::sys;
use crate::runtime::err::err_reasons::{
    CT_R_BASE64_DECODE_ERROR, CT_R_LOG_CONF_INVALID_KEY, CT_R_SCT_UNSUPPORTED_VERSION,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem_coords::SeamFile;
use crate::x509::x_pubkey::d2i_PUBKEY_ex;

/// `ERR_LIB_CT` — `include/openssl/err.h.in:115`.
const ERR_LIB_CT: c_int = 50;
/// `ERR_R_CT_LIB` — `include/openssl/err.h.in:345`, `(ERR_LIB_CT /* 50 */ | ERR_RFLAG_COMMON)`.
const ERR_R_CT_LIB: c_int = 50 | (0x2 << 18);
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `include/openssl/err.h.in:360`, `(262 | ERR_RFLAG_COMMON)`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 262 | (0x2 << 18);

/// One `ct_b64.c` raise coordinate, declared locally (see the module doc).
const fn ct_b64_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/ct/ct_b64.c",
        line,
        func,
        lib: ERR_LIB_CT,
        reason,
        dynamic_reason: false,
    }
}

/// `ct_base64_decode` at `crypto/ct/ct_b64.c:42`.
const CT_B64_42: ErrSite = ct_b64_site(42, c"ct_base64_decode", CT_R_BASE64_DECODE_ERROR);
/// `SCT_new_from_base64` at `crypto/ct/ct_b64.c:72`.
const CT_B64_72: ErrSite = ct_b64_site(72, c"SCT_new_from_base64", ERR_R_CT_LIB);
/// `SCT_new_from_base64` at `crypto/ct/ct_b64.c:81`.
const CT_B64_81: ErrSite = ct_b64_site(81, c"SCT_new_from_base64", CT_R_SCT_UNSUPPORTED_VERSION);
/// `SCT_new_from_base64` at `crypto/ct/ct_b64.c:87`.
const CT_B64_87: ErrSite = ct_b64_site(87, c"SCT_new_from_base64", CT_R_BASE64_DECODE_ERROR);
/// `SCT_new_from_base64` at `crypto/ct/ct_b64.c:96`.
const CT_B64_96: ErrSite = ct_b64_site(96, c"SCT_new_from_base64", CT_R_BASE64_DECODE_ERROR);
/// `SCT_new_from_base64` at `crypto/ct/ct_b64.c:104`.
const CT_B64_104: ErrSite = ct_b64_site(104, c"SCT_new_from_base64", CT_R_BASE64_DECODE_ERROR);
/// `CTLOG_new_from_base64_ex` at `crypto/ct/ct_b64.c:143`.
const CT_B64_143: ErrSite = ct_b64_site(
    143,
    c"CTLOG_new_from_base64_ex",
    ERR_R_PASSED_INVALID_ARGUMENT,
);
/// `CTLOG_new_from_base64_ex` at `crypto/ct/ct_b64.c:149`.
const CT_B64_149: ErrSite =
    ct_b64_site(149, c"CTLOG_new_from_base64_ex", CT_R_LOG_CONF_INVALID_KEY);
/// `CTLOG_new_from_base64_ex` at `crypto/ct/ct_b64.c:157`.
const CT_B64_157: ErrSite =
    ct_b64_site(157, c"CTLOG_new_from_base64_ex", CT_R_LOG_CONF_INVALID_KEY);

// ---------------------------------------------------------------------------------------------
// Ownership of a scratch buffer
// ---------------------------------------------------------------------------------------------

/// `static int ct_base64_decode(const char *in, unsigned char **out)` —
/// `crypto/ct/ct_b64.c:24-59`.
///
/// Decodes the base64 string `in` into a newly allocated `*out` the caller owns. Answers the byte
/// count, `0` for an empty or over-long input, or `-1` after raising.
///
/// # Safety
///
/// `in` is NUL-terminated; `out` is writable.
unsafe fn ct_base64_decode(in_: *const c_char, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: `in_` is NUL-terminated per the contract.
    let inlen = unsafe { sys::strlen(in_) };

    if inlen == 0 || inlen > c_int::MAX as usize {
        // SAFETY: `out` is writable per the contract.
        unsafe { *out = ptr::null_mut() };
        return 0;
    }

    let outlen: c_int = ((inlen / 4) * 3) as c_int;
    // SAFETY: `outlen` is non-negative (`3 * (inlen/4) <= 3 * INT_MAX/4`).
    let Some(buf) = OwnedBuf::new(outlen as usize, SeamFile::NULL, 0) else {
        return -1;
    };

    // SAFETY: `buf` has `outlen` writable bytes; `in_` is readable for `inlen`.
    let mut outlen =
        unsafe { EVP_DecodeBlock(buf.as_ptr(), in_.cast::<c_uchar>(), inlen as c_int) };
    if outlen < 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_B64_42) };
        // `buf`'s `Drop` is the authority's own `CRYPTO_free` on this failure tail.
        return -1;
    }

    // Subtract padding bytes from |outlen|. Any more than 2 is malformed.
    let mut i: c_int = 0;
    let mut idx = inlen;
    loop {
        // SAFETY: the cursor is within `in_`'s NUL-terminated buffer.
        idx -= 1;
        // SAFETY: `idx < inlen` addresses a readable byte.
        if unsafe { *in_.add(idx) } != b'=' as c_char {
            break;
        }
        outlen -= 1;
        i += 1;
        if i > 2 {
            // `buf`'s `Drop` is the authority's own `CRYPTO_free` on this failure tail.
            return -1;
        }
    }

    // SAFETY: `out` is writable per the contract; the block is handed to the caller.
    unsafe { *out = buf.into_raw() };
    outlen
}

/// `SCT *SCT_new_from_base64(unsigned char version, const char *logid_base64, ct_log_entry_type_t
/// entry_type, uint64_t timestamp, const char *extensions_base64, const char
/// *signature_base64)` — `crypto/ct/ct_b64.c:61-125`.
///
/// # Safety
///
/// Each string argument is NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SCT_new_from_base64(
    version: c_uchar,
    logid_base64: *const c_char,
    entry_type: c_int,
    timestamp: u64,
    extensions_base64: *const c_char,
    signature_base64: *const c_char,
) -> *mut Sct {
    let sct = SCT_new();

    if sct.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_B64_72) };
        return ptr::null_mut();
    }

    // SAFETY: `sct` is live; `version` is a value the version setter validates.
    if unsafe { SCT_set_version(sct, version as c_int) } == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_B64_81) };
        // SAFETY: `sct` is the value this call owns.
        unsafe { SCT_free(sct) };
        return ptr::null_mut();
    }

    // The log id. A decoder failure leaves `dec` NULL, so there is nothing to release.
    let mut dec: *mut c_uchar = ptr::null_mut();
    // SAFETY: `logid_base64` is NUL-terminated; `&mut dec` is writable.
    let declen = unsafe { ct_base64_decode(logid_base64, &mut dec) };
    if declen < 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_B64_87) };
        // SAFETY: `sct` is the value this call owns.
        unsafe { SCT_free(sct) };
        return ptr::null_mut();
    }
    // SAFETY: `dec` is the decoder's block, left for this frame and owned by no one else.
    let dec = unsafe { OwnedBuf::adopt_plain_nullable(dec, SeamFile::NULL, 0) };
    // SAFETY: `sct` is live; `dec` is handed to it only when the setter answers non-zero.
    if unsafe { SCT_set0_log_id(sct, dec.as_ptr(), declen as usize) } == 0 {
        // The setter kept ownership, so release the block and the half-built value.
        drop(dec);
        // SAFETY: `sct` is this call's value.
        unsafe { SCT_free(sct) };
        return ptr::null_mut();
    }
    // The value owns the log id now.
    let _ = dec.into_raw();

    // The extensions. `SCT_set0_extensions` never fails, so the block is handed over outright.
    let mut dec: *mut c_uchar = ptr::null_mut();
    // SAFETY: `extensions_base64` is NUL-terminated; `&mut dec` is writable.
    let declen = unsafe { ct_base64_decode(extensions_base64, &mut dec) };
    if declen < 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_B64_96) };
        // SAFETY: `sct` is the value this call owns.
        unsafe { SCT_free(sct) };
        return ptr::null_mut();
    }
    // SAFETY: `dec` is the decoder's block, left for this frame and owned by no one else.
    let dec = unsafe { OwnedBuf::adopt_plain_nullable(dec, SeamFile::NULL, 0) };
    // SAFETY: `sct` is live; the setter takes the block over.
    unsafe { SCT_set0_extensions(sct, dec.as_ptr(), declen as usize) };
    // The value owns the extensions now.
    let _ = dec.into_raw();

    // The signature. `o2i_SCT_signature` only reads the block, so it stays this frame's.
    let mut dec: *mut c_uchar = ptr::null_mut();
    // SAFETY: `signature_base64` is NUL-terminated; `&mut dec` is writable.
    let declen = unsafe { ct_base64_decode(signature_base64, &mut dec) };
    if declen < 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_B64_104) };
        // SAFETY: `sct` is the value this call owns.
        unsafe { SCT_free(sct) };
        return ptr::null_mut();
    }
    // SAFETY: `dec` is the decoder's block, left for this frame and owned by no one else.
    let dec = unsafe { OwnedBuf::adopt_plain_nullable(dec, SeamFile::NULL, 0) };
    let mut p: *const c_uchar = dec.as_ptr();
    // SAFETY: `sct` is live; `p` is readable for `declen` bytes.
    if unsafe { o2i_SCT_signature(sct, &mut p, declen as usize) } <= 0 {
        // The block is still this frame's; `dec`'s `Drop` releases it.
        drop(dec);
        // SAFETY: `sct` is this call's value.
        unsafe { SCT_free(sct) };
        return ptr::null_mut();
    }
    // The signature has been copied out, so the scratch block is released.
    drop(dec);

    // SAFETY: `sct` is live.
    unsafe { SCT_set_timestamp(sct, timestamp) };

    // SAFETY: `sct` is live; `entry_type` is a value the setter validates.
    if unsafe { SCT_set_log_entry_type(sct, entry_type) } == 0 {
        // SAFETY: `sct` is the value this call owns.
        unsafe { SCT_free(sct) };
        return ptr::null_mut();
    }

    sct
}

/// `int CTLOG_new_from_base64_ex(CTLOG **ct_log, const char *pkey_base64, const char *name,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/ct/ct_b64.c:133-168`.
///
/// # Safety
///
/// `ct_log` is a writable slot; `pkey_base64` is NUL-terminated; `name` is NUL-terminated;
/// `libctx` is NULL or live; `propq` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_new_from_base64_ex(
    ct_log: *mut *mut Ctlog,
    pkey_base64: *const c_char,
    name: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut pkey_der: *mut c_uchar = ptr::null_mut();

    if ct_log.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_B64_143) };
        return 0;
    }

    // SAFETY: `pkey_base64` is NUL-terminated; `&mut pkey_der` is writable.
    let pkey_der_len = unsafe { ct_base64_decode(pkey_base64, &mut pkey_der) };
    if pkey_der_len < 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_B64_149) };
        return 0;
    }

    // SAFETY: `pkey_der` is the decoder's block, left for this frame and owned by no one else.
    let der = unsafe { OwnedBuf::adopt_plain_nullable(pkey_der, SeamFile::NULL, 0) };
    let mut p: *const c_uchar = der.as_ptr();
    // SAFETY: `p` is readable for `pkey_der_len` bytes; the optional args are checked values.
    let pkey = unsafe {
        d2i_PUBKEY_ex(
            ptr::null_mut(),
            &mut p,
            pkey_der_len as c_long,
            libctx,
            propq,
        )
    };
    // The decoder's block has been read in full; `der`'s `Drop` is the authority's own release.
    drop(der);
    if pkey.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_B64_157) };
        return 0;
    }

    // SAFETY: `ct_log` is a writable slot; `pkey` is live; the strings are NUL-terminated.
    let new_log = unsafe { CTLOG_new_ex(pkey, name, libctx, propq) };
    // SAFETY: `ct_log` is writable per the contract.
    unsafe { *ct_log = new_log };
    if new_log.is_null() {
        // SAFETY: `pkey` is the reference this call owns.
        unsafe { EVP_PKEY_free(pkey) };
        return 0;
    }

    1
}

/// `int CTLOG_new_from_base64(CTLOG **ct_log, const char *pkey_base64, const char *name)` —
/// `crypto/ct/ct_b64.c:170-174`.
///
/// # Safety
///
/// `ct_log` is a writable slot; `pkey_base64` and `name` are NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_new_from_base64(
    ct_log: *mut *mut Ctlog,
    pkey_base64: *const c_char,
    name: *const c_char,
) -> c_int {
    // SAFETY: the pointers are forwarded under this function's contract; the optional args are NULL.
    unsafe { CTLOG_new_from_base64_ex(ct_log, pkey_base64, name, ptr::null_mut(), ptr::null()) }
}
