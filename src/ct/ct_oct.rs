//! `crypto/ct/ct_oct.c` — the TLS-format SCT serializer/deserializer and the DER `SCT_LIST`
//! codec. Phase 10.14.15's CT layer. This unit carries the four names `ct_x509v3.c` is blocked
//! on: `d2i_SCT_LIST`, `i2d_SCT_LIST`, `o2i_SCT_LIST` and `i2o_SCT_LIST`.
//!
//! `crypto/ct/ct_oct.c` is 403 lines and transcribes whole. It is a **hand-written** codec, not an
//! `ASN1_SEQUENCE` template: each function walks the RFC 6962 `SignedCertificateTimestamp` layout
//! byte by byte through the `n2s`/`s2n`/`l2n3`/`n2l8`/`l2n8` network-order macros of
//! `crypto/ct/ct_local.h:28-55`. Those five macros are shared with `ct_vfy.c`, so they are defined
//! once here as `pub(crate)` functions and reached by Rust path
//! (`crate::ct::ct_oct::l2n8(..)`), never duplicated.
//!
//! The two DER-facing entries, `d2i_SCT_LIST`/`i2d_SCT_LIST`, delegate to the crate's
//! `d2i_ASN1_OCTET_STRING`/`i2d_ASN1_OCTET_STRING` (`crate::asn1::typ`) exactly as the authority's
//! do; they carry no item group of their own.
//!
//! **Withheld by name**: none.
//!
//! ## The raise sites
//!
//! `crypto/ct/ct_oct.c` is not an entry in `gen_err_raise_sites.py`, so its sixteen coordinates are
//! **declared locally**, their reason values read from `include/openssl/cterr.h`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_uint, c_void, CStr};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::string::ASN1_OCTET_STRING_free;
use crate::asn1::typ::{d2i_ASN1_OCTET_STRING, i2d_ASN1_OCTET_STRING};
use crate::ct::ct_sct::{
    SCT_LIST_free, SCT_free, SCT_get_signature_nid, SCT_is_complete, SCT_new, SCT_set1_signature,
    SCT_signature_is_complete, Sct, CT_V1_HASHLEN, SCT_VERSION_V1,
};
use crate::runtime::err::err_reasons::{
    CT_R_SCT_INVALID, CT_R_SCT_INVALID_SIGNATURE, CT_R_SCT_LIST_INVALID, CT_R_SCT_NOT_SET,
    CT_R_UNSUPPORTED_VERSION,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup};
use crate::runtime::obj::NID_undef;
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};

/// `ERR_LIB_CT` — `include/openssl/err.h.in:115`.
const ERR_LIB_CT: c_int = 50;

/// `MAX_SCT_SIZE` — `crypto/ct/ct_local.h:21`, `65535`.
const MAX_SCT_SIZE: usize = 65535;
/// `MAX_SCT_LIST_SIZE` — `crypto/ct/ct_local.h:22`, `MAX_SCT_SIZE`.
const MAX_SCT_LIST_SIZE: usize = MAX_SCT_SIZE;

/// One `ct_oct.c` raise coordinate, declared locally (see the module doc).
const fn ct_oct_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/ct/ct_oct.c",
        line,
        func,
        lib: ERR_LIB_CT,
        reason,
        dynamic_reason: false,
    }
}

/// `o2i_SCT_signature` at `crypto/ct/ct_oct.c:31`.
const CT_OCT_31: ErrSite = ct_oct_site(31, c"o2i_SCT_signature", CT_R_UNSUPPORTED_VERSION);
/// `o2i_SCT_signature` at `crypto/ct/ct_oct.c:42`.
const CT_OCT_42: ErrSite = ct_oct_site(42, c"o2i_SCT_signature", CT_R_SCT_INVALID_SIGNATURE);
/// `o2i_SCT_signature` at `crypto/ct/ct_oct.c:51`.
const CT_OCT_51: ErrSite = ct_oct_site(51, c"o2i_SCT_signature", CT_R_SCT_INVALID_SIGNATURE);
/// `o2i_SCT_signature` at `crypto/ct/ct_oct.c:58`.
const CT_OCT_58: ErrSite = ct_oct_site(58, c"o2i_SCT_signature", CT_R_SCT_INVALID_SIGNATURE);
/// `o2i_SCT` at `crypto/ct/ct_oct.c:76`.
const CT_OCT_76: ErrSite = ct_oct_site(76, c"o2i_SCT", CT_R_SCT_INVALID);
/// `o2i_SCT` at `crypto/ct/ct_oct.c:99`.
const CT_OCT_99: ErrSite = ct_oct_site(99, c"o2i_SCT", CT_R_SCT_INVALID);
/// `o2i_SCT` at `crypto/ct/ct_oct.c:114`.
const CT_OCT_114: ErrSite = ct_oct_site(114, c"o2i_SCT", CT_R_SCT_INVALID);
/// `o2i_SCT` at `crypto/ct/ct_oct.c:128`.
const CT_OCT_128: ErrSite = ct_oct_site(128, c"o2i_SCT", CT_R_SCT_INVALID);
/// `i2o_SCT_signature` at `crypto/ct/ct_oct.c:159`.
const CT_OCT_159: ErrSite = ct_oct_site(159, c"i2o_SCT_signature", CT_R_SCT_INVALID_SIGNATURE);
/// `i2o_SCT_signature` at `crypto/ct/ct_oct.c:164`.
const CT_OCT_164: ErrSite = ct_oct_site(164, c"i2o_SCT_signature", CT_R_UNSUPPORTED_VERSION);
/// `i2o_SCT` at `crypto/ct/ct_oct.c:204`.
const CT_OCT_204: ErrSite = ct_oct_site(204, c"i2o_SCT", CT_R_SCT_NOT_SET);
/// `o2i_SCT_LIST` at `crypto/ct/ct_oct.c:262`.
const CT_OCT_262: ErrSite = ct_oct_site(262, c"o2i_SCT_LIST", CT_R_SCT_LIST_INVALID);
/// `o2i_SCT_LIST` at `crypto/ct/ct_oct.c:268`.
const CT_OCT_268: ErrSite = ct_oct_site(268, c"o2i_SCT_LIST", CT_R_SCT_LIST_INVALID);
/// `o2i_SCT_LIST` at `crypto/ct/ct_oct.c:289`.
const CT_OCT_289: ErrSite = ct_oct_site(289, c"o2i_SCT_LIST", CT_R_SCT_LIST_INVALID);
/// `o2i_SCT_LIST` at `crypto/ct/ct_oct.c:296`.
const CT_OCT_296: ErrSite = ct_oct_site(296, c"o2i_SCT_LIST", CT_R_SCT_LIST_INVALID);
/// `i2o_SCT_LIST` at `crypto/ct/ct_oct.c:328`.
const CT_OCT_328: ErrSite = ct_oct_site(328, c"i2o_SCT_LIST", CT_R_SCT_LIST_INVALID);

// -------------------------------------------------------------------------------------------
// The network-order macros of `crypto/ct/ct_local.h:28-55`.
//
// They are `static inline`-equivalent expansions shared by `ct_oct.c` and `ct_vfy.c`; the
// authority spells them in the header for the same reason this module defines them once.
// -------------------------------------------------------------------------------------------

/// `#define n2s(c, s)` — `crypto/ct/ct_local.h:28`. Reads a big-endian 16-bit word and advances `c`.
///
/// # Safety
///
/// `c` points to a cursor with at least two readable bytes.
pub(crate) unsafe fn n2s(c: *mut *const c_uchar) -> c_uint {
    // SAFETY: `c` and the two bytes it addresses are readable per the contract.
    unsafe {
        let p = *c;
        let s = ((*p as c_uint) << 8) | (*p.add(1) as c_uint);
        *c = p.add(2);
        s
    }
}

/// `#define s2n(s, c)` — `crypto/ct/ct_local.h:30`. Writes a big-endian 16-bit word and advances `c`.
///
/// # Safety
///
/// `c` points to a cursor with at least two writable bytes.
pub(crate) unsafe fn s2n(s: u64, c: *mut *mut c_uchar) {
    // SAFETY: `c` and the two bytes it addresses are writable per the contract.
    unsafe {
        let p = *c;
        *p = ((s >> 8) & 0xff) as c_uchar;
        *p.add(1) = (s & 0xff) as c_uchar;
        *c = p.add(2);
    }
}

/// `#define l2n3(l, c)` — `crypto/ct/ct_local.h:34`. Writes a big-endian 24-bit word and advances `c`.
///
/// # Safety
///
/// `c` points to a cursor with at least three writable bytes.
pub(crate) unsafe fn l2n3(l: u64, c: *mut *mut c_uchar) {
    // SAFETY: `c` and the three bytes it addresses are writable per the contract.
    unsafe {
        let p = *c;
        *p = ((l >> 16) & 0xff) as c_uchar;
        *p.add(1) = ((l >> 8) & 0xff) as c_uchar;
        *p.add(2) = (l & 0xff) as c_uchar;
        *c = p.add(3);
    }
}

/// `#define n2l8(c, l)` — `crypto/ct/ct_local.h:39`. Reads a big-endian 64-bit word and advances `c`.
///
/// # Safety
///
/// `c` points to a cursor with at least eight readable bytes.
pub(crate) unsafe fn n2l8(c: *mut *const c_uchar) -> u64 {
    // SAFETY: `c` and the eight bytes it addresses are readable per the contract.
    unsafe {
        let p = *c;
        let mut l: u64 = 0;
        let mut i = 0;
        while i < 8 {
            l = (l << 8) | (*p.add(i) as u64);
            i += 1;
        }
        *c = p.add(8);
        l
    }
}

/// `#define l2n8(l, c)` — `crypto/ct/ct_local.h:48`. Writes a big-endian 64-bit word and advances `c`.
///
/// # Safety
///
/// `c` points to a cursor with at least eight writable bytes.
pub(crate) unsafe fn l2n8(l: u64, c: *mut *mut c_uchar) {
    // SAFETY: `c` and the eight bytes it addresses are writable per the contract.
    unsafe {
        let p = *c;
        let mut i = 0;
        while i < 8 {
            *p.add(i) = ((l >> (56 - 8 * i)) & 0xff) as c_uchar;
            i += 1;
        }
        *c = p.add(8);
    }
}

/// `int o2i_SCT_signature(SCT *sct, const unsigned char **in, size_t len)` —
/// `crypto/ct/ct_oct.c:24-68`.
///
/// Declared in `crypto/ct/ct_local.h:213`, so it is **not** an export.
///
/// # Safety
///
/// `sct` is a live `SCT`; `in` points at a readable cursor for at least `len` bytes.
pub(crate) unsafe fn o2i_SCT_signature(
    sct: *mut Sct,
    in_: *mut *const c_uchar,
    len: usize,
) -> c_int {
    let mut len_remaining = len;

    // SAFETY: `sct` is live per the contract.
    if unsafe { (*sct).version } != SCT_VERSION_V1 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_OCT_31) };
        return -1;
    }
    if len <= 4 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_OCT_42) };
        return -1;
    }

    // SAFETY: `in_` points at a readable cursor per the contract.
    let mut p = unsafe { *in_ };
    // Get hash and signature algorithm.
    // SAFETY: the header check above proves at least five readable bytes.
    unsafe {
        (*sct).hash_alg = *p;
        p = p.add(1);
        (*sct).sig_alg = *p;
        p = p.add(1);
    }
    // SAFETY: `sct` is live per the contract.
    if unsafe { SCT_get_signature_nid(sct) } == NID_undef {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_OCT_51) };
        return -1;
    }

    // Retrieve the signature and check it is consistent with the buffer length.
    // SAFETY: `p` addresses at least three readable bytes (the two algorithms above consumed two
    // of the `len > 4` bytes).
    let siglen = unsafe { n2s(&mut p) } as usize;
    // SAFETY: `p` and `*in_` are within the same readable region.
    len_remaining -= unsafe { p.offset_from(*in_) } as usize;
    if siglen > len_remaining {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_OCT_58) };
        return -1;
    }

    // SAFETY: `p` is readable for `siglen` bytes; `sct` is live.
    if unsafe { SCT_set1_signature(sct, p, siglen) } != 1 {
        return -1;
    }
    len_remaining -= siglen;
    // SAFETY: `p` is readable for `siglen` bytes per the check above.
    unsafe { *in_ = p.add(siglen) };

    (len - len_remaining) as c_int
}

/// `SCT *o2i_SCT(SCT **psct, const unsigned char **in, size_t len)` —
/// `crypto/ct/ct_oct.c:70-151`.
///
/// # Safety
///
/// `psct` is NULL or a writable slot; `in` points at a readable cursor for at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn o2i_SCT(
    psct: *mut *mut Sct,
    in_: *mut *const c_uchar,
    len: usize,
) -> *mut Sct {
    if len == 0 || len > MAX_SCT_SIZE {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_OCT_76) };
        return ptr::null_mut();
    }

    let sct = SCT_new();
    if sct.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `in_` points at a readable cursor per the contract.
    let start = unsafe { *in_ };

    // SAFETY: `len >= 1`, so the first byte is readable; `sct` is live.
    let version = unsafe { *start };
    // SAFETY: `sct` is live.
    unsafe { (*sct).version = version as c_int };

    'blk: {
        if version as c_int == SCT_VERSION_V1 {
            let mut p = start;
            let mut len = len;
            /*-
             * Fixed-length header:
             *   struct {
             *     Version sct_version;     (1 byte)
             *     log_id id;               (32 bytes)
             *     uint64 timestamp;        (8 bytes)
             *     CtExtensions extensions; (2 bytes + ?)
             *   }
             */
            if len < 43 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&CT_OCT_99) };
                break 'blk;
            }
            len -= 43;
            // SAFETY: `p` points at the version octet; 43 bytes are readable.
            p = unsafe { p.add(1) };
            // SAFETY: 32 bytes are readable from `p`.
            let log_id =
                unsafe { CRYPTO_memdup(p.cast::<c_void>(), CT_V1_HASHLEN, ptr::null(), 0) }
                    .cast::<c_uchar>();
            if log_id.is_null() {
                break 'blk;
            }
            // SAFETY: `sct` is live; `log_id` is the copy this call owns.
            unsafe {
                (*sct).log_id = log_id;
                (*sct).log_id_len = CT_V1_HASHLEN;
                p = p.add(CT_V1_HASHLEN);
            }

            // SAFETY: eight bytes are readable from `p`; `sct` is live.
            let timestamp = unsafe { n2l8(&mut p) };
            // SAFETY: `sct` is live.
            unsafe { (*sct).timestamp = timestamp };

            // SAFETY: two bytes are readable from `p`.
            let ext_len = unsafe { n2s(&mut p) } as usize;
            if len < ext_len {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&CT_OCT_114) };
                break 'blk;
            }
            if ext_len > 0 {
                // SAFETY: `p` is readable for `ext_len` bytes per the check above.
                let ext = unsafe { CRYPTO_memdup(p.cast::<c_void>(), ext_len, ptr::null(), 0) }
                    .cast::<c_uchar>();
                if ext.is_null() {
                    break 'blk;
                }
                // SAFETY: `sct` is live; `ext` is the copy this call owns.
                unsafe { (*sct).ext = ext };
            }
            // SAFETY: `sct` is live.
            unsafe { (*sct).ext_len = ext_len };
            // SAFETY: `p` is readable for `ext_len` bytes.
            p = unsafe { p.add(ext_len) };
            len -= ext_len;

            // SAFETY: `sct` is live; `p` addresses the remaining `len` readable bytes.
            let sig_len = unsafe { o2i_SCT_signature(sct, &mut p, len) };
            if sig_len <= 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&CT_OCT_128) };
                break 'blk;
            }
            len -= sig_len as usize;
            // SAFETY: `in_` is the caller's writable cursor slot; `p` points just past the
            // signature and `len` is the tail, so their sum is the first byte after this SCT.
            unsafe { *in_ = p.add(len) };
        } else {
            // If not V1 just cache the encoding.
            // SAFETY: the caller guarantees `len` readable bytes from `start`.
            let dup = unsafe { CRYPTO_memdup(start.cast::<c_void>(), len, ptr::null(), 0) }
                .cast::<c_uchar>();
            if dup.is_null() {
                break 'blk;
            }
            // SAFETY: `sct` is live; `dup` is the copy this call owns.
            unsafe {
                (*sct).sct = dup;
                (*sct).sct_len = len;
                *in_ = start.add(len);
            }
        }

        if !psct.is_null() {
            // SAFETY: `psct` is writable; its old value is NULL or a live `SCT`.
            unsafe {
                SCT_free(*psct);
                *psct = sct;
            }
        }
        return sct;
    }

    // SAFETY: `sct` is NULL or the value this call built.
    unsafe { SCT_free(sct) };
    ptr::null_mut()
}

/// `int i2o_SCT_signature(const SCT *sct, unsigned char **out)` — `crypto/ct/ct_oct.c:153-196`.
///
/// Declared in `crypto/ct/ct_local.h:202`, so it is **not** an export.
///
/// # Safety
///
/// `sct` is a live `SCT`; `out` is NULL or a writable cursor slot.
pub(crate) unsafe fn i2o_SCT_signature(sct: *const Sct, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: `sct` is live per the contract.
    if unsafe { SCT_signature_is_complete(sct) } == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_OCT_159) };
        return -1;
    }
    // SAFETY: `sct` is live per the contract.
    if unsafe { (*sct).version } != SCT_VERSION_V1 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_OCT_164) };
        return -1;
    }

    // SAFETY: `sct` is live per the contract.
    let sig_len = unsafe { (*sct).sig_len };
    let len = 4 + sig_len;

    if !out.is_null() {
        // SAFETY: `out` is a writable cursor slot.
        let mut p = unsafe {
            if !(*out).is_null() {
                let p = *out;
                *out = p.add(len);
                p
            } else {
                let p = CRYPTO_malloc(len, ptr::null(), 0).cast::<c_uchar>();
                if p.is_null() {
                    return -1;
                }
                *out = p;
                p
            }
        };

        // SAFETY: `p` has `len >= 4` writable bytes; `sct` is live.
        unsafe {
            *p = (*sct).hash_alg;
            p = p.add(1);
            *p = (*sct).sig_alg;
            p = p.add(1);
            s2n(sig_len as u64, &mut p);
            ptr::copy_nonoverlapping((*sct).sig, p, sig_len);
        }
    }

    len as c_int
}

/// `int i2o_SCT(const SCT *sct, unsigned char **out)` — `crypto/ct/ct_oct.c:198-253`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `out` is NULL or a writable cursor slot.
#[no_mangle]
pub unsafe extern "C" fn i2o_SCT(sct: *const Sct, out: *mut *mut c_uchar) -> c_int {
    let mut pstart: *mut c_uchar = ptr::null_mut();

    // SAFETY: `sct` is live per the contract.
    if unsafe { SCT_is_complete(sct) } == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_OCT_204) };
        return -1;
    }

    // SAFETY: `sct` is live per the contract.
    let len = unsafe {
        if (*sct).version == SCT_VERSION_V1 {
            43 + (*sct).ext_len + 4 + (*sct).sig_len
        } else {
            (*sct).sct_len
        }
    };

    if len > c_int::MAX as usize {
        return -1;
    }
    if out.is_null() {
        return len as c_int;
    }

    // SAFETY: `out` is a writable cursor slot.
    let mut p = unsafe {
        if !(*out).is_null() {
            let p = *out;
            *out = p.add(len);
            p
        } else {
            let p = CRYPTO_malloc(len, ptr::null(), 0).cast::<c_uchar>();
            if p.is_null() {
                // SAFETY: `pstart` is NULL.
                CRYPTO_free(pstart.cast::<c_void>(), ptr::null(), 0);
                return -1;
            }
            pstart = p;
            *out = p;
            p
        }
    };

    'blk: {
        // SAFETY: `sct` is live per the contract.
        if unsafe { (*sct).version } == SCT_VERSION_V1 {
            // SAFETY: `p` has `len` writable bytes and `sct`'s fields describe them.
            let ok = unsafe { i2o_sct_v1(sct, &mut p, len) };
            if ok == 0 {
                break 'blk;
            }
        } else {
            // SAFETY: `p` has `len` writable bytes; `sct->sct` is readable for `len`.
            unsafe { ptr::copy_nonoverlapping((*sct).sct, p, len) };
        }

        return len as c_int;
    }

    // SAFETY: `pstart` is NULL or the block this call allocated.
    unsafe { CRYPTO_free(pstart.cast::<c_void>(), ptr::null(), 0) };
    -1
}

/// The V1 arm of [`i2o_SCT`] — `crypto/ct/ct_oct.c:233-244`. Answers 1 on success and 0 when the
/// signature encoder failed.
///
/// # Safety
///
/// `sct` is a live complete V1 `SCT`; `p` is a writable cursor with `len` bytes.
unsafe fn i2o_sct_v1(sct: *const Sct, p: *mut *mut c_uchar, len: usize) -> c_int {
    let _ = len;
    // SAFETY: `p` and `sct` are live per the contract.
    let mut cursor = unsafe { *p };
    // SAFETY: `cursor` has at least `43 + ext_len + 4 + sig_len` writable bytes.
    unsafe {
        *cursor = (*sct).version as c_uchar;
        cursor = cursor.add(1);
        ptr::copy_nonoverlapping((*sct).log_id, cursor, CT_V1_HASHLEN);
        cursor = cursor.add(CT_V1_HASHLEN);
        l2n8((*sct).timestamp, &mut cursor);
        s2n((*sct).ext_len as u64, &mut cursor);
    }
    // SAFETY: `sct` is live per the contract.
    if unsafe { (*sct).ext_len } > 0 {
        // SAFETY: `cursor` has `ext_len` writable bytes; `sct->ext` is readable for `ext_len`.
        unsafe {
            ptr::copy_nonoverlapping((*sct).ext, cursor, (*sct).ext_len);
            cursor = cursor.add((*sct).ext_len);
        }
    }
    // SAFETY: `sct` is live; `cursor` is a writable slot with the signature's bytes.
    if unsafe { i2o_SCT_signature(sct, &mut cursor) } <= 0 {
        return 0;
    }
    // SAFETY: `p` is the caller's cursor slot.
    unsafe { *p = cursor };
    1
}

/// `STACK_OF(SCT) *o2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp, size_t len)` —
/// `crypto/ct/ct_oct.c:255-317`.
///
/// # Safety
///
/// `a` is NULL or a writable stack slot; `pp` addresses a readable cursor for at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn o2i_SCT_LIST(
    a: *mut *mut OpenSslStack,
    pp: *mut *const c_uchar,
    len: usize,
) -> *mut OpenSslStack {
    if !(2..=MAX_SCT_LIST_SIZE).contains(&len) {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_OCT_262) };
        return ptr::null_mut();
    }

    // SAFETY: `pp` addresses at least two readable bytes.
    let list_len = unsafe { n2s(pp) } as usize;
    if list_len != len - 2 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_OCT_268) };
        return ptr::null_mut();
    }

    let sk: *mut OpenSslStack;
    // SAFETY: `a` is NULL or a writable stack slot per the contract.
    if a.is_null() || unsafe { (*a).is_null() } {
        sk = OPENSSL_sk_new_null();
        if sk.is_null() {
            return ptr::null_mut();
        }
    } else {
        // Use the given stack, but empty it first.
        // SAFETY: `*a` is a live stack.
        sk = unsafe { *a };
        loop {
            // SAFETY: `sk` is a live stack.
            let sct = unsafe { OPENSSL_sk_pop(sk) };
            if sct.is_null() {
                break;
            }
            // SAFETY: the popped element is a live `SCT`.
            unsafe { SCT_free(sct.cast::<Sct>()) };
        }
    }

    let mut remaining = list_len;
    while remaining > 0 {
        if remaining < 2 {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&CT_OCT_289) };
            // SAFETY: `a` is NULL or points at NULL per the branches above.
            unsafe { o2i_sct_list_err(a, sk) };
            return ptr::null_mut();
        }
        // SAFETY: `pp` addresses two more readable bytes.
        let sct_len = unsafe { n2s(pp) } as usize;
        remaining -= 2;

        if sct_len == 0 || sct_len > remaining {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&CT_OCT_296) };
            // SAFETY: `a` is NULL or points at NULL per the branches above.
            unsafe { o2i_sct_list_err(a, sk) };
            return ptr::null_mut();
        }
        remaining -= sct_len;

        // SAFETY: `pp` addresses `sct_len` readable bytes; NULL keeps the new value local.
        let sct = unsafe { o2i_SCT(ptr::null_mut(), pp, sct_len) };
        if sct.is_null() {
            // SAFETY: `a` is NULL or points at NULL per the branches above.
            unsafe { o2i_sct_list_err(a, sk) };
            return ptr::null_mut();
        }
        // SAFETY: `sk` is live; `sct` is the value `o2i_SCT` just produced.
        if unsafe { OPENSSL_sk_push(sk, sct.cast::<c_void>()) } == 0 {
            // SAFETY: `sct` is the value this call owns until the push succeeds.
            unsafe { SCT_free(sct) };
            // SAFETY: `a` is NULL or points at NULL per the branches above.
            unsafe { o2i_sct_list_err(a, sk) };
            return ptr::null_mut();
        }
    }

    // SAFETY: `a` is NULL or a writable slot.
    unsafe {
        if !a.is_null() && (*a).is_null() {
            *a = sk;
        }
    }
    sk
}

/// The `err:` arm of [`o2i_SCT_LIST`] — `crypto/ct/ct_oct.c:313-316`. Releases the scratch stack
/// only when the caller did not supply one.
///
/// # Safety
///
/// `a` is NULL or a writable slot holding NULL; `sk` is NULL or a live stack this call owns.
unsafe fn o2i_sct_list_err(a: *mut *mut OpenSslStack, sk: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live slot per the contract.
    if a.is_null() || unsafe { (*a).is_null() } {
        // SAFETY: `sk` is NULL or a live stack of `SCT` values.
        unsafe { SCT_LIST_free(sk) };
    }
}

/// `int i2o_SCT_LIST(const STACK_OF(SCT) *a, unsigned char **pp)` — `crypto/ct/ct_oct.c:319-370`.
///
/// # Safety
///
/// `a` is a live `STACK_OF(SCT)`; `pp` is NULL or a writable cursor slot.
#[no_mangle]
pub unsafe extern "C" fn i2o_SCT_LIST(a: *const OpenSslStack, pp: *mut *mut c_uchar) -> c_int {
    let mut is_pp_new: c_int = 0;
    let mut p: *mut c_uchar = ptr::null_mut();

    if !pp.is_null() {
        // SAFETY: `pp` is a writable slot.
        unsafe {
            if (*pp).is_null() {
                let len = i2o_SCT_LIST(a, ptr::null_mut());
                if len == -1 {
                    // SAFETY: the site is a compiled-in constant.
                    raise_site(&CT_OCT_328);
                    return -1;
                }
                let fresh = CRYPTO_malloc(len as usize, ptr::null(), 0).cast::<c_uchar>();
                if fresh.is_null() {
                    return -1;
                }
                *pp = fresh;
                is_pp_new = 1;
            }
            p = (*pp).add(2);
        }
    }

    let mut len2: usize = 2;
    // SAFETY: `a` is live per the contract.
    let num = unsafe { OPENSSL_sk_num(a) };
    let mut i = 0;
    while i < num {
        // SAFETY: `a` is live and `i` is in bounds.
        let sct = unsafe { OPENSSL_sk_value(a, i) }.cast::<Sct>();
        let sct_len;
        if !pp.is_null() {
            let mut p2 = p;
            // SAFETY: `p` has room for the 2-byte length plus the element.
            p = unsafe { p.add(2) };
            // SAFETY: `sct` is live and `p` is a writable cursor slot.
            sct_len = unsafe { i2o_SCT(sct, &mut p) };
            if sct_len == -1 {
                break;
            }
            // SAFETY: `p2` addresses the two length bytes.
            unsafe { s2n(sct_len as u64, &mut p2) };
        } else {
            // SAFETY: `sct` is live; the NULL `out` asks only for the length.
            sct_len = unsafe { i2o_SCT(sct, ptr::null_mut()) };
            if sct_len == -1 {
                break;
            }
        }
        len2 += 2 + sct_len as usize;
        i += 1;
    }

    // If the loop broke on an encoder failure, `i < num`; the `err:` arm below handles it.
    if i < num || len2 > MAX_SCT_LIST_SIZE {
        // SAFETY: `is_pp_new` is 1 only when `pp` and `*pp` are the block this call allocated.
        unsafe {
            if is_pp_new != 0 {
                CRYPTO_free((*pp).cast::<c_void>(), ptr::null(), 0);
                *pp = ptr::null_mut();
            }
        }
        return -1;
    }

    if !pp.is_null() {
        // SAFETY: `pp` is a writable slot holding a block with at least two bytes.
        unsafe {
            let mut q = *pp;
            s2n((len2 - 2) as u64, &mut q);
            if is_pp_new == 0 {
                *pp = (*pp).add(len2);
            }
        }
    }
    len2 as c_int
}

/// `STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp, long len)` —
/// `crypto/ct/ct_oct.c:372-389`.
///
/// # Safety
///
/// `a` is NULL or a writable stack slot; `pp` addresses a readable cursor for at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_SCT_LIST(
    a: *mut *mut OpenSslStack,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    let mut oct: *mut Asn1String = ptr::null_mut();

    // SAFETY: `pp` addresses a readable cursor per the contract.
    let mut p = unsafe { *pp };
    // SAFETY: `&mut oct` is a writable slot; `p` is readable for `len`.
    if unsafe { d2i_ASN1_OCTET_STRING(&mut oct, &mut p, len) }.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `oct` is the live value the decoder just produced.
    p = unsafe { (*oct).data };
    // SAFETY: `p` is readable for `oct->length` bytes; `a` is NULL or a writable slot.
    let sk = unsafe { o2i_SCT_LIST(a, &mut p, (*oct).length as usize) };
    if !sk.is_null() {
        // SAFETY: `pp` is a writable cursor slot.
        unsafe { *pp = (*pp).add(len as usize) };
    }

    // SAFETY: `oct` is the live value this call owns.
    unsafe { ASN1_OCTET_STRING_free(oct) };
    sk
}

/// `int i2d_SCT_LIST(const STACK_OF(SCT) *a, unsigned char **out)` — `crypto/ct/ct_oct.c:391-403`.
///
/// # Safety
///
/// `a` is a live `STACK_OF(SCT)`; `out` is NULL or a writable cursor slot.
#[no_mangle]
pub unsafe extern "C" fn i2d_SCT_LIST(a: *const OpenSslStack, out: *mut *mut c_uchar) -> c_int {
    // The authority constructs a stack-local `ASN1_OCTET_STRING oct;` and writes only `data` and
    // `length` before the encoder; the remaining fields are indeterminate exactly as there.
    let mut oct = core::mem::MaybeUninit::<Asn1String>::uninit();
    let octp = oct.as_mut_ptr();

    // SAFETY: `oct` is a distinct local; this writes its `data` field.
    unsafe { (*octp).data = ptr::null_mut() };
    // SAFETY: `a` is live; `&mut (*octp).data` is a writable slot.
    let list_len = unsafe { i2o_SCT_LIST(a, &raw mut (*octp).data) };
    if list_len == -1 {
        return -1;
    }
    // SAFETY: `oct`'s `length` field is writable.
    unsafe { (*octp).length = list_len };

    // SAFETY: `octp` is a live octet string whose `data`/`length` are set.
    let len = unsafe { i2d_ASN1_OCTET_STRING(octp, out) };
    // SAFETY: `(*octp).data` is NULL or the block `i2o_SCT_LIST` allocated.
    unsafe { CRYPTO_free((*octp).data.cast::<c_void>(), ptr::null(), 0) };
    len
}
