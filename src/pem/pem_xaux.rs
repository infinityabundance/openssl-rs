//! `crypto/pem/pem_xaux.c` — the `X509_AUX` PEM reader and writer pair. Phase 11.6.
//!
//! `crypto/pem/pem_xaux.c` is 18 lines and one macro invocation,
//! `IMPLEMENT_PEM_rw(X509_AUX, X509, PEM_STRING_X509_TRUSTED, X509_AUX)` (`:18`). The macro's
//! `name` is `X509_AUX` and its `asn1` argument is `X509_AUX`, so the four generated functions
//! are `PEM_read[_bio]_X509_AUX` and `PEM_write[_bio]_X509_AUX`, and they read and write the
//! **trust-augmented** certificate through `d2i_X509_AUX`/`i2d_X509_AUX` — the codecs that carry
//! the `X509_CERT_AUX` trust/reject/alias block after the `Certificate` DER.
//!
//! The block header is `PEM_STRING_X509_TRUSTED` (`"TRUSTED CERTIFICATE"`), which is what
//! [`crate::x509::by_file::X509_load_cert_file_ex`]'s PEM arm reads through
//! `PEM_read_bio_X509_AUX`.
//! The `X509_AUX` item group's codec and the trust block itself are Phase 10's
//! (`src/x509/x_x509.rs`), so this unit's closure is complete.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::evp::pem_bridge::PemPasswordCb;
use crate::pem::pem_lib::{
    PEM_ASN1_read, PEM_ASN1_write, PEM_ASN1_write_bio, PEM_STRING_X509_TRUSTED,
};
use crate::pem::pem_oth::PEM_ASN1_read_bio;
use crate::runtime::bio::Bio;
use crate::x509::x_x509::{d2i_X509_AUX, i2d_X509_AUX, X509};

/// `(d2i_of_void *)d2i_X509_AUX` — the cast `IMPLEMENT_PEM_read_*` spells.
///
/// # Safety
/// The `void *` arguments must be `d2i_X509_AUX`'s own arguments, which the reader's call site
/// guarantees.
unsafe extern "C" fn d2i_void(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { d2i_X509_AUX(a.cast::<*mut X509>(), in_, len).cast::<c_void>() }
}

/// `(i2d_of_void *)i2d_X509_AUX` — the cast `IMPLEMENT_PEM_write_*` spells.
///
/// # Safety
/// `x` must be live and `out` the encoder's own cursor.
unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_X509_AUX(x.cast::<X509>(), out) }
}

/// `X509 *PEM_read_X509_AUX(FILE *fp, X509 **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_xaux.c:18`'s `IMPLEMENT_PEM_read_fp`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_X509_AUX(
    fp: *mut c_void,
    x: *mut *mut X509,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509 {
    // SAFETY: `d2i_X509_AUX` is the augmented-certificate decoder and the arguments are the
    // caller's.
    unsafe {
        PEM_ASN1_read(
            d2i_void,
            PEM_STRING_X509_TRUSTED,
            fp,
            x.cast::<*mut c_void>(),
            cb,
            u,
        )
    }
    .cast::<X509>()
}

/// `X509 *PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_xaux.c:18`'s `IMPLEMENT_PEM_read_bio`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_X509_AUX(
    bp: *mut Bio,
    x: *mut *mut X509,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509 {
    // SAFETY: `d2i_X509_AUX` is the augmented-certificate decoder and the arguments are the
    // caller's.
    unsafe {
        PEM_ASN1_read_bio(
            d2i_void,
            PEM_STRING_X509_TRUSTED,
            bp,
            x.cast::<*mut c_void>(),
            cb,
            u,
        )
    }
    .cast::<X509>()
}

/// `int PEM_write_X509_AUX(FILE *out, const X509 *x)` — `crypto/pem/pem_xaux.c:18`'s
/// `IMPLEMENT_PEM_write_fp`.
///
/// # Safety
/// `out` an open writable stream; `x` a live certificate.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_X509_AUX(out: *mut c_void, x: *const X509) -> c_int {
    // SAFETY: `i2d_X509_AUX` is the encoder and the arguments are the caller's; the two NULLs are
    // the macro's no-cipher arms.
    unsafe {
        PEM_ASN1_write(
            Some(i2d_void),
            PEM_STRING_X509_TRUSTED,
            out,
            x.cast::<c_void>(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

/// `int PEM_write_bio_X509_AUX(BIO *out, const X509 *x)` — `crypto/pem/pem_xaux.c:18`'s
/// `IMPLEMENT_PEM_write_bio`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live certificate.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_X509_AUX(out: *mut Bio, x: *const X509) -> c_int {
    // SAFETY: `i2d_X509_AUX` is the encoder and the arguments are the caller's; the two NULLs are
    // the macro's no-cipher arms.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d_void),
            PEM_STRING_X509_TRUSTED,
            out,
            x.cast::<c_void>(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}
