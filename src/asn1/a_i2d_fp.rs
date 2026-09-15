//! Phase 5 — `a_i2d_fp.c`: encode an item to a `BIO`, a `FILE`, or a memory BIO.
//!
//! Every function here is the same three lines around a different destination, and the
//! only behaviour worth writing down is the **write loop**:
//!
//! ```text
//! i = BIO_write(out, &b[j], n);
//! if (i == n) break;      /* the whole remainder was taken */
//! if (i <= 0) { ret = 0; break; }   /* a failure, or nothing left to give */
//! j += i; n -= i;         /* a short write: ask again for the rest */
//! ```
//!
//! A BIO that writes fewer bytes than asked is normal — a socket BIO under backpressure
//! does it — so a short write is not an error, and the loop asks for the remainder from
//! where it stopped. What *is* an error is `0` or a negative answer, and the two are not
//! distinguished here: neither is a reason name, so the caller gets `0` with no raise.
//! That is why an `i2d_*_bio` failure over a closed BIO reports nothing on the error
//! queue, while a failure to encode does.
//!
//! The `_mem_bio` variant is the only one that answers a BIO rather than an `int`; it
//! frees the BIO it made when the write fails, so a caller sees either a BIO holding the
//! whole encoding or null.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{Asn1Item, I2dOfVoid};
use crate::ffi::guard_ffi;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::bss_mem::BIO_s_mem;
use crate::runtime::bio::iolib::{BIO_ctrl, BIO_write};
use crate::runtime::bio::sys::FILE;
use crate::runtime::bio::{BIO_free, BIO_new, Bio, BIO_NOCLOSE};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

/// The authority translation unit for the encode-to-a-stream path.
pub(crate) const FILE_NAME: &core::ffi::CStr = c"crypto/asn1/a_i2d_fp.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `BIO_C_SET_FILE_PTR` — the ctrl that `BIO_set_fp` is a macro for.
///
/// `BIO_set_fp(b, fp, c)` is `BIO_ctrl(b, BIO_C_SET_FILE_PTR, c, (char *)fp)`, so the
/// close flag travels as the ctrl's `long` argument and the `FILE *` as its `void *`.
const BIO_C_SET_FILE_PTR: c_int = 106;

/// Wrap a `FILE *` in a file BIO, run `f`, and free it.
///
/// The authority repeats this shape in `ASN1_i2d_fp` and `ASN1_item_i2d_fp`; it is one
/// function here because the two differ only in which encoder they hand to it, and the
/// error raised when the BIO cannot be made is the caller's — its line is part of the
/// recorded error, so the site is passed in.
///
/// `BIO_NOCLOSE` is deliberate: the caller owns the `FILE` and this call must not close
/// it. A failure of `BIO_ctrl` is not checked, here or in the authority — the macro's
/// result is discarded.
///
/// # Safety
///
/// `out` must be a live `FILE *` and `run` must accept the BIO it is given.
unsafe fn with_file_bio(
    out: *mut FILE,
    site: &ErrSite,
    run: impl FnOnce(*mut Bio) -> c_int,
) -> c_int {
    // SAFETY: `BIO_s_file()` answers a static method and `BIO_new` copies what it needs.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: the site is the caller's compile-time constant.
        unsafe { raise_site(site) };
        return 0;
    }
    // SAFETY: `b` is the BIO just made and `out` is the caller's live `FILE`.
    unsafe {
        BIO_ctrl(
            b,
            BIO_C_SET_FILE_PTR,
            c_long::from(BIO_NOCLOSE),
            out.cast::<c_void>(),
        )
    };
    let ret = run(b);
    // SAFETY: `b` is this call's BIO and the caller still owns the `FILE`.
    unsafe { BIO_free(b) };
    ret
}

/// `int ASN1_i2d_fp(i2d_of_void *i2d, FILE *out, const void *x)`
///
/// # Safety
///
/// `i2d` must be a live encoder for `x`'s type; `out` must be a live `FILE *`; `x` must
/// be null or a live value of that type.
#[no_mangle]
pub unsafe extern "C" fn ASN1_i2d_fp(i2d: I2dOfVoid, out: *mut FILE, x: *const c_void) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `out` is the caller's `FILE` and `run` only uses the BIO it is given.
        unsafe { with_file_bio(out, &err_sites::A_I2D_FP_24, |b| ASN1_i2d_bio(i2d, b, x)) }
    })
}

/// `int ASN1_i2d_bio(i2d_of_void *i2d, BIO *out, const void *x)`
///
/// The legacy pair's stream writer. `i2d` is called twice — once to size, once to fill —
/// and a sizing answer of `0` or less is a plain failure with no raise, which is the
/// legacy convention `ASN1_dup` shares.
///
/// # Safety
///
/// `i2d` must be a live encoder for `x`'s type; `out` must be a live BIO; `x` must be
/// null or a live value of that type.
#[no_mangle]
pub unsafe extern "C" fn ASN1_i2d_bio(i2d: I2dOfVoid, out: *mut Bio, x: *const c_void) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `i2d` is the caller's live function.
        let n = unsafe { i2d(x, core::ptr::null_mut()) };
        if n <= 0 {
            return 0;
        }
        let b = CRYPTO_malloc(n as usize, FILE_NAME.as_ptr(), LINE) as *mut c_uchar;
        if b.is_null() {
            return 0;
        }
        let mut p = b;
        // SAFETY: `p` has room for the length the sizing pass reported.
        unsafe { i2d(x, &mut p) };

        // SAFETY: `out` is the caller's live BIO and `b` is readable for `n` bytes.
        let ret = unsafe { write_all(out, b, n) };
        // SAFETY: `b` came from this allocator and is not owned elsewhere.
        unsafe { CRYPTO_free(b.cast::<c_void>(), FILE_NAME.as_ptr(), LINE) };
        ret
    })
}

/// `int ASN1_item_i2d_fp(const ASN1_ITEM *it, FILE *out, const void *x)`
///
/// # Safety
///
/// `it` must be a live item; `out` must be a live `FILE *`; `x` must be null or a live
/// value of `it`'s type.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_i2d_fp(
    it: *const Asn1Item,
    out: *mut FILE,
    x: *const c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `out` is the caller's `FILE`.
        unsafe {
            with_file_bio(out, &err_sites::A_I2D_FP_75, |b| {
                ASN1_item_i2d_bio(it, b, x)
            })
        }
    })
}

/// `int ASN1_item_i2d_bio(const ASN1_ITEM *it, BIO *out, const void *x)`
///
/// The difference from [`ASN1_i2d_bio`] is the failure classification: the item encoder
/// reports a *negative* length for an error and `0` for "nothing to encode", and this
/// treats both as a failure but raises `ERR_R_ASN1_LIB` for it.
///
/// # Safety
///
/// `it` must be a live item; `out` must be a live BIO; `x` must be null or a live value
/// of `it`'s type.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_i2d_bio(
    it: *const Asn1Item,
    out: *mut Bio,
    x: *const c_void,
) -> c_int {
    guard_ffi(0, || {
        let mut b: *mut c_uchar = core::ptr::null_mut();
        // SAFETY: a null `out` slot is what asks the item encoder to allocate.
        let n = unsafe { ASN1_item_i2d(x, &mut b, it) };
        if n < 0 || b.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_I2D_FP_92) };
            return 0;
        }
        // SAFETY: `out` is the caller's live BIO and `b` is readable for `n` bytes.
        let ret = unsafe { write_all(out, b, n) };
        // SAFETY: `b` came from this allocator and is not owned elsewhere.
        unsafe { CRYPTO_free(b.cast::<c_void>(), FILE_NAME.as_ptr(), LINE) };
        ret
    })
}

/// `BIO *ASN1_item_i2d_mem_bio(const ASN1_ITEM *it, const ASN1_VALUE *val)`
///
/// A memory BIO holding the encoding, or null. A null `it` or `val` is refused with
/// `ERR_R_PASSED_NULL_PARAMETER` **before** the BIO is made, and a failed write releases
/// the BIO rather than answering one that holds a partial encoding.
///
/// # Safety
///
/// `it` must be a live item; `val` must be a live value of `it`'s type.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_i2d_mem_bio(
    it: *const Asn1Item,
    val: *const c_void,
) -> *mut Bio {
    guard_ffi(core::ptr::null_mut(), || {
        if it.is_null() || val.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_I2D_FP_116) };
            return core::ptr::null_mut();
        }
        // SAFETY: `BIO_s_mem()` answers a static method.
        let res = unsafe { BIO_new(BIO_s_mem()) };
        if res.is_null() {
            // The authority returns here without raising: the allocation failure is the
            // only information, and the caller reads it from the null.
            return core::ptr::null_mut();
        }
        // SAFETY: `res` is this call's BIO and the item/value are the caller's.
        if unsafe { ASN1_item_i2d_bio(it, res, val) } <= 0 {
            // SAFETY: `res` is this call's BIO and nothing else holds it.
            unsafe { BIO_free(res) };
            return core::ptr::null_mut();
        }
        res
    })
}

/// The authority's short-write loop: ask for the remainder until it is all taken.
///
/// Extracted because both stream writers have it verbatim, and because the `i <= 0` arm
/// is a failure that raises nothing — which is a property of the loop, not of either
/// caller.
///
/// # Safety
///
/// `out` must be a live BIO; `b` must be readable for `n` bytes.
unsafe fn write_all(out: *mut Bio, b: *mut c_uchar, n: c_int) -> c_int {
    let mut j: c_int = 0;
    let mut remaining = n;
    loop {
        // SAFETY: `b + j` is readable for `remaining` bytes.
        let i = unsafe { BIO_write(out, b.add(j as usize).cast::<c_void>(), remaining) };
        if i == remaining {
            return 1;
        }
        if i <= 0 {
            return 0;
        }
        j += i;
        remaining -= i;
    }
}
