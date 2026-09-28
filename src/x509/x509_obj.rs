//! Phase 10.10 — `crypto/x509/x509_obj.c`: the byte-exact DN printer `X509_NAME_oneline`.
//!
//! The unit is 179 lines and publishes exactly one function. It is what 10.8's `x_name.rs`
//! recorded as the blocker for `X509_NAME_print` (`crypto/x509/x_name.c:502`), and landing it
//! here advances that unit's frontier: `X509_NAME_print` is un-withheld in
//! [`crate::x509::x_name`] with this subphase.
//!
//! ## What the printer promises
//!
//! `X509_NAME_oneline` renders a `X509_NAME` as the `/CN=…/O=…` form every `openssl` tool
//! prints. Two things make it more than formatting:
//!
//! * **The buffer is either the caller's or the printer's.** With `buf == NULL` it allocates
//!   a `BUF_MEM`, growing it as it goes, and returns the `BUF_MEM`'s own data pointer after
//!   freeing the `BUF_MEM` *structure* — the caller owns the bytes. With a caller buffer and
//!   enough room it writes in place; with too little room it stops at the first entry that
//!   would not fit rather than truncating mid-entry.
//! * **A `GeneralString` of a multiple of four bytes is packed four-to-a-cell.** The
//!   authority's `gs_doit[4]` mask decides which of the four interleaved bytes are printed:
//!   if the first three cells are all zero the fourth is printed alone, and otherwise all
//!   four are. That is the one branch a naive `/`-joiner gets wrong, and it is reproduced.
//!
//! The EBCDIC conversion in the authority (`#ifdef CHARSET_EBCDIC`) is not built by this
//! profile, so `ossl_toascii` is the identity and the non-EBCDIC arms are the ones below.
//!
//! ## The two refusals
//!
//! A name component longer than `NAME_ONELINE_MAX` (1 MiB) and a name whose rendering would
//! exceed it both raise `ERR_LIB_X509`/`X509_R_NAME_TOO_LONG` and answer NULL; an allocation
//! or grow failure raises `ERR_LIB_X509`/`ERR_R_BUF_LIB` and answers NULL. The coordinates are
//! the generated `X509_OBJ_75`/`X509_OBJ_175`, because `crypto/x509/x509_obj.c` joins
//! `gen_err_raise_sites.py`'s covered set with this subphase.
//!
//! ## The court
//!
//! `RT-STORE` carries the arms: the fixed certificate's subject and issuer are printed with a
//! caller buffer and with the allocating spelling, and the `NULL`-name and zero-length arms
//! are driven too. The output is a literal string or a length, never an address.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::asn1::layout::V_ASN1_GENERALSTRING;
use crate::asn1::text::{i2t_ASN1_OBJECT, to_hex};
use crate::ffi::guard_ffi;
use crate::runtime::buffer::{BUF_MEM_free, BUF_MEM_grow, BUF_MEM_new, BufMem};
use crate::runtime::err::err_sites::{self, ErrSite};
use crate::runtime::err::raise_site;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{NID_undef, OBJ_nid2sn, OBJ_obj2nid};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::x_name::{X509Name, X509NameEntry};

/// `NAME_ONELINE_MAX` (`:23`) — the limit past which a name is refused rather than overflowed.
const NAME_ONELINE_MAX: c_int = 1024 * 1024;

/// The authority translation unit for this file's `OPENSSL_free` expansions.
const FILE: &CStr = c"crypto/x509/x509_obj.c";
/// `OPENSSL_free(b)` in the `a == NULL` arm (`:54`).
const LINE_FREE_NULL_NAME: c_int = 54;
/// `OPENSSL_free(b)` at the end of the printer (`:168`).
const LINE_FREE_RESULT: c_int = 168;

/// How many bytes precede the NUL of a C string.
///
/// # Safety
///
/// `s` must point to a NUL-terminated string.
unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated, so the scan stops at the terminator.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// `strncpy(buf, "NO X509_NAME", len)`, for the `a == NULL` arm.
///
/// # Safety
///
/// `buf` must be writable for `len` bytes and `len` must be positive.
unsafe fn strncpy_no_name(buf: *mut c_char, len: c_int) {
    const SRC: &[u8] = b"NO X509_NAME\0";
    let n = len as usize;
    let mut k = 0usize;
    while k < n {
        let c = if k < SRC.len() { SRC[k] } else { 0 };
        // SAFETY: `buf` is writable for `len` bytes.
        unsafe { *buf.add(k) = c as c_char };
        k += 1;
    }
}

/// The `buferr:`/`end:` tail: raise (when `buferr`) and release the `BUF_MEM`, then NULL.
///
/// # Safety
///
/// `b` must be NULL or an owned `BUF_MEM`.
unsafe fn free_and_null(b: *mut BufMem) -> *mut c_char {
    // SAFETY: `b` is NULL or an owned `BUF_MEM`.
    unsafe { BUF_MEM_free(b) };
    ptr::null_mut()
}

/// Raises `site`, then runs the `end:` tail. The authority's `buferr:` label.
///
/// # Safety
///
/// `b` must be NULL or an owned `BUF_MEM`.
unsafe fn raise_and_free(site: &ErrSite, b: *mut BufMem) -> *mut c_char {
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(site) };
    // SAFETY: `b` is NULL or an owned `BUF_MEM`.
    unsafe { free_and_null(b) }
}

/// `char *X509_NAME_oneline(const X509_NAME *a, char *buf, int len)` —
/// `crypto/x509/x509_obj.c:25-179`.
///
/// # Safety
///
/// `a` must be NULL or a live `X509_NAME`; `buf` NULL (which makes this call allocate and hand
/// back its own result) or writable for `len` bytes; `len` the caller's buffer size, or 0.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_oneline(
    a: *const X509Name,
    mut buf: *mut c_char,
    mut len: c_int,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        let mut b: *mut BufMem = ptr::null_mut();
        let mut l: c_int = 0;
        let mut prev_set: c_int = -1;
        let mut tmp_buf = [0 as c_char; 80];
        let mut gs_doit: [c_int; 4];

        if buf.is_null() {
            b = BUF_MEM_new();
            if b.is_null() {
                // SAFETY: `b` is NULL here, which `raise_and_free` accepts.
                return unsafe { raise_and_free(&err_sites::X509_OBJ_175, b) };
            }
            // SAFETY: `b` is live and uniquely owned.
            if unsafe { BUF_MEM_grow(b, 200) } == 0 {
                // SAFETY: `b` is NULL or an owned `BUF_MEM`.
                return unsafe { raise_and_free(&err_sites::X509_OBJ_175, b) };
            }
            // SAFETY: `b` is live and its `data` holds at least one byte.
            unsafe { *(*b).data = 0 };
            len = 200;
        } else if len == 0 {
            return ptr::null_mut();
        }

        if a.is_null() {
            if !b.is_null() {
                // SAFETY: `b` is live and uniquely owned; its data block is transferred to
                // the caller and only the `BUF_MEM` structure is freed.
                unsafe {
                    buf = (*b).data;
                    CRYPTO_free(b.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_NULL_NAME);
                }
            }
            // SAFETY: `buf` is writable for `len` bytes and `len` is positive.
            unsafe {
                strncpy_no_name(buf, len);
                *buf.add((len - 1) as usize) = 0;
            }
            return buf;
        }

        len -= 1;
        // SAFETY: `a` is live per the check above.
        let entries = unsafe { (*a).entries };
        // SAFETY: `entries` is the name's own stack, always non-NULL.
        let n_entries = unsafe { OPENSSL_sk_num(entries) };
        let mut i: c_int = 0;

        while i < n_entries {
            // SAFETY: `entries` is live and `i` is in range.
            let ne = unsafe { OPENSSL_sk_value(entries, i) }.cast::<X509NameEntry>();
            // SAFETY: `ne` is a live entry of the name's own stack.
            let (object, value) = unsafe { ((*ne).object, (*ne).value) };

            // SAFETY: `object` is a live object; `OBJ_obj2nid` accepts it.
            let n = unsafe { OBJ_obj2nid(object) };
            let mut s: *const c_char = ptr::null();
            if n != NID_undef {
                s = OBJ_nid2sn(n);
            }
            if n == NID_undef || s.is_null() {
                // SAFETY: `tmp_buf` is an 80-byte writable buffer and `object` is live.
                unsafe { i2t_ASN1_OBJECT(tmp_buf.as_mut_ptr(), 80, object) };
                s = tmp_buf.as_ptr();
            }
            // SAFETY: `s` is a NUL-terminated name.
            let l1 = unsafe { c_strlen(s) } as c_int;

            // SAFETY: `value` is a live `ASN1_STRING`.
            let (type_, num, q) = unsafe { ((*value).type_, (*value).length, (*value).data) };
            if num > NAME_ONELINE_MAX {
                // SAFETY: `b` is NULL or an owned `BUF_MEM`.
                return unsafe { raise_and_free(&err_sites::X509_OBJ_75, b) };
            }

            if type_ == V_ASN1_GENERALSTRING && (num % 4) == 0 {
                gs_doit = [0, 0, 0, 0];
                let mut j = 0;
                while j < num {
                    // SAFETY: `q` holds `num` readable bytes.
                    if unsafe { *q.add(j as usize) } != 0 {
                        gs_doit[(j & 3) as usize] = 1;
                    }
                    j += 1;
                }
                if (gs_doit[0] | gs_doit[1] | gs_doit[2]) != 0 {
                    gs_doit = [1, 1, 1, 1];
                } else {
                    gs_doit = [0, 0, 0, 1];
                }
            } else {
                gs_doit = [1, 1, 1, 1];
            }

            let mut l2: c_int = 0;
            let mut j: c_int = 0;
            while j < num {
                if gs_doit[(j & 3) as usize] == 0 {
                    j += 1;
                    continue;
                }
                l2 += 1;
                // SAFETY: `q` holds `num` readable bytes.
                let ch = unsafe { *q.add(j as usize) };
                if ch == b'/' || ch == b'+' {
                    l2 += 1;
                } else if !(b' '..=b'~').contains(&ch) {
                    l2 += 3;
                }
                j += 1;
            }

            let lold = l;
            l += 1 + l1 + 1 + l2;
            if l > NAME_ONELINE_MAX {
                // SAFETY: `b` is NULL or an owned `BUF_MEM`.
                return unsafe { raise_and_free(&err_sites::X509_OBJ_116, b) };
            }

            let mut p: *mut c_char;
            if !b.is_null() {
                // SAFETY: `b` is live; the grow either succeeds or fails.
                if unsafe { BUF_MEM_grow(b, (l + 1) as usize) } == 0 {
                    // SAFETY: `b` is NULL or an owned `BUF_MEM`.
                    return unsafe { raise_and_free(&err_sites::X509_OBJ_175, b) };
                }
                // SAFETY: `b` is live and holds `l + 1` bytes, so `lold` is in range.
                p = unsafe { (*b).data.add(lold as usize) };
            } else if l > len {
                break;
            } else {
                // SAFETY: `buf` is writable for `len + 1` bytes and `lold <= l <= len`.
                p = unsafe { buf.add(lold as usize) };
            }

            // SAFETY: `p` has room for the one separator byte.
            let sep = if prev_set == unsafe { (*ne).set } {
                b'+'
            } else {
                b'/'
            };
            // SAFETY: `p` has room for the separator, the name and the '=' written here.
            unsafe {
                *p = sep as c_char;
                p = p.add(1);
                ptr::copy_nonoverlapping(s, p, l1 as usize);
                p = p.add(l1 as usize);
                *p = b'=' as c_char;
                p = p.add(1);
            }

            // The EBCDIC re-read is not built here: `q` still points at `value->data`.
            let mut j: c_int = 0;
            while j < num {
                if gs_doit[(j & 3) as usize] == 0 {
                    j += 1;
                    continue;
                }
                // SAFETY: `q` holds `num` readable bytes.
                let ch = unsafe { *q.add(j as usize) };
                // SAFETY: `p` has room for the escaped form, and `q` holds `num` bytes.
                unsafe {
                    if !(b' '..=b'~').contains(&ch) {
                        *p = b'\\' as c_char;
                        *p.add(1) = b'x' as c_char;
                        let mut two = [0u8; 2];
                        to_hex(&mut two, ch);
                        *p.add(2) = two[0] as c_char;
                        *p.add(3) = two[1] as c_char;
                        p = p.add(4);
                    } else {
                        if ch == b'/' || ch == b'+' {
                            *p = b'\\' as c_char;
                            p = p.add(1);
                        }
                        *p = ch as c_char;
                        p = p.add(1);
                    }
                }
                j += 1;
            }
            // SAFETY: `p` is inside the buffer and has room for the terminator.
            unsafe { *p = 0 };
            // SAFETY: `ne` is live.
            prev_set = unsafe { (*ne).set };
            i += 1;
        }

        let p = if !b.is_null() {
            // SAFETY: `b` is live and uniquely owned; its data is transferred to the caller.
            unsafe {
                let d = (*b).data;
                CRYPTO_free(b.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_RESULT);
                d
            }
        } else {
            buf
        };
        if i == 0 {
            // SAFETY: `p` is the buffer this call returns, and it has room for one NUL.
            unsafe { *p = 0 };
        }
        p
    })
}
