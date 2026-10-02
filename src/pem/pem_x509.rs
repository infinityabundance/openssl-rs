//! `crypto/pem/pem_x509.c` — the `X509` PEM reader and writer pair. Phase 11.6.
//!
//! `crypto/pem/pem_x509.c` is 18 lines and one macro invocation,
//! `IMPLEMENT_PEM_rw(X509, X509, PEM_STRING_X509, X509)` (`:18`), whose expansion is
//! `include/openssl/pem.h:116-206`'s `IMPLEMENT_PEM_read_fp`/`IMPLEMENT_PEM_read_bio` for the
//! readers and `IMPLEMENT_PEM_write_fp`/`IMPLEMENT_PEM_write_bio` for the writers. The crate has
//! no C preprocessor, so the four `#[no_mangle]` functions below are that expansion written out:
//! each is one `PEM_ASN1_read`/`PEM_ASN1_read_bio`/`PEM_ASN1_write`/`PEM_ASN1_write_bio` call with
//! the `(d2i_of_void *)d2i_X509` / `(i2d_of_void *)i2d_X509` cast the macro spells written as a
//! shim, exactly as `src/pem/key_legacy.rs` does for Phase 8's names.
//!
//! The `X509` item group and both codecs are Phase 10's (`src/x509/x_x509.rs`, D451), so this
//! unit's own closure is complete and the four names are transcribable whole. The writer emits
//! `PEM_STRING_X509` (`"CERTIFICATE"`), which is the block header `PEM_read_bio_X509` looks for.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::evp::pem_bridge::PemPasswordCb;
use crate::pem::pem_lib::{PEM_ASN1_read, PEM_ASN1_write, PEM_ASN1_write_bio, PEM_STRING_X509};
use crate::pem::pem_oth::PEM_ASN1_read_bio;
use crate::runtime::bio::Bio;
use crate::x509::x_x509::{d2i_X509, i2d_X509, X509};

/// `(d2i_of_void *)d2i_X509` — the cast `IMPLEMENT_PEM_read_*` spells.
///
/// # Safety
/// The `void *` arguments must be `d2i_X509`'s own arguments, which the reader's call site
/// guarantees.
unsafe extern "C" fn d2i_void(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { d2i_X509(a.cast::<*mut X509>(), in_, len).cast::<c_void>() }
}

/// `(i2d_of_void *)i2d_X509` — the cast `IMPLEMENT_PEM_write_*` spells.
///
/// # Safety
/// `x` must be live and `out` the encoder's own cursor.
unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_X509(x.cast::<X509>(), out) }
}

/// `X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_x509.c:18`'s `IMPLEMENT_PEM_read_fp`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_X509(
    fp: *mut c_void,
    x: *mut *mut X509,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509 {
    // SAFETY: `d2i_X509` is the certificate decoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_read(
            d2i_void,
            PEM_STRING_X509,
            fp,
            x.cast::<*mut c_void>(),
            cb,
            u,
        )
    }
    .cast::<X509>()
}

/// `X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_x509.c:18`'s `IMPLEMENT_PEM_read_bio`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_X509(
    bp: *mut Bio,
    x: *mut *mut X509,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509 {
    // SAFETY: `d2i_X509` is the certificate decoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_read_bio(
            d2i_void,
            PEM_STRING_X509,
            bp,
            x.cast::<*mut c_void>(),
            cb,
            u,
        )
    }
    .cast::<X509>()
}

/// `int PEM_write_X509(FILE *out, const X509 *x)` — `crypto/pem/pem_x509.c:18`'s
/// `IMPLEMENT_PEM_write_fp`.
///
/// # Safety
/// `out` an open writable stream; `x` a live certificate.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_X509(out: *mut c_void, x: *const X509) -> c_int {
    // SAFETY: `i2d_X509` is the encoder and the arguments are the caller's; the two NULLs are the
    // macro's no-cipher arms.
    unsafe {
        PEM_ASN1_write(
            Some(i2d_void),
            PEM_STRING_X509,
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

/// `int PEM_write_bio_X509(BIO *out, const X509 *x)` — `crypto/pem/pem_x509.c:18`'s
/// `IMPLEMENT_PEM_write_bio`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live certificate.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_X509(out: *mut Bio, x: *const X509) -> c_int {
    // SAFETY: `i2d_X509` is the encoder and the arguments are the caller's; the two NULLs are the
    // macro's no-cipher arms.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d_void),
            PEM_STRING_X509,
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
