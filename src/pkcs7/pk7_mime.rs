//! `crypto/pkcs7/pk7_mime.c` — the generalised stream and S/MIME wrappers round `PKCS7`.
//! Phase 12.2.
//!
//! `i2d_PKCS7_bio_stream` and `PEM_write_bio_PKCS7_stream` are one call each into Phase 5's
//! `i2d_ASN1_bio_stream`/`PEM_write_bio_ASN1_stream`. `SMIME_write_PKCS7`,
//! `SMIME_read_PKCS7_ex` and `SMIME_read_PKCS7` delegate to the `SMIME_*_ASN1` reader and writer,
//! which are the Phase 5 hand-off assigned to 12.9 (`crypto/asn1/asn_mime.c`); the declarations
//! below are the authority's own, so when 12.9 lands them the delegates bind to the landed unit.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::asn1::asn_mime::i2d_ASN1_bio_stream;
use crate::asn1::layout::Asn1Item;
use crate::evp::pem_bridge::PEM_write_bio_ASN1_stream;
use crate::pkcs7::pk7_asn1::{PKCS7_it, Pkcs7, Pkcs7Ctx};
use crate::pkcs7::pk7_lib::{
    ossl_pkcs7_ctx_get0_libctx, ossl_pkcs7_ctx_get0_propq, ossl_pkcs7_get0_ctx,
    ossl_pkcs7_resolve_libctx,
};
use crate::runtime::bio::Bio;
use crate::runtime::obj::{NID_pkcs7_signed, NID_undef, OBJ_obj2nid};
use crate::runtime::stack::OpenSslStack;

/// `SMIME_OLDMIME` — `include/openssl/asn1.h:1108`.
const SMIME_OLDMIME: c_int = 0x400;

extern "C" {
    /// `int SMIME_write_ASN1_ex(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
    /// int ctype_nid, int econt_nid, STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it,
    /// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/asn1/asn_mime.c`, 12.9's.
    fn SMIME_write_ASN1_ex(
        bio: *mut Bio,
        val: *mut c_void,
        data: *mut Bio,
        flags: c_int,
        ctype_nid: c_int,
        econt_nid: c_int,
        mdalgs: *mut OpenSslStack,
        it: *const Asn1Item,
        libctx: *mut c_void,
        propq: *const c_char,
    ) -> c_int;

    /// `ASN1_VALUE *SMIME_read_ASN1_ex(BIO *bio, int flags, BIO **bcont, const ASN1_ITEM *it,
    /// ASN1_VALUE **x, OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/asn1/asn_mime.c`, 12.9's.
    fn SMIME_read_ASN1_ex(
        bio: *mut Bio,
        flags: c_int,
        bcont: *mut *mut Bio,
        it: *const Asn1Item,
        x: *mut *mut c_void,
        libctx: *mut c_void,
        propq: *const c_char,
    ) -> *mut c_void;
}

/// `int i2d_PKCS7_bio_stream(BIO *out, PKCS7 *p7, BIO *in, int flags)` — `pk7_mime.c:18-22`.
///
/// # Safety
/// `out`/`in` are live BIOs; `p7` is live.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_bio_stream(
    out: *mut Bio,
    p7: *mut Pkcs7,
    in_: *mut Bio,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller's contract; `PKCS7_it()` is a static item.
    unsafe { i2d_ASN1_bio_stream(out, p7.cast(), in_, flags, PKCS7_it()) }
}

/// `int PEM_write_bio_PKCS7_stream(BIO *out, PKCS7 *p7, BIO *in, int flags)` — `pk7_mime.c:24-28`.
///
/// # Safety
/// `out`/`in` are live BIOs; `p7` is live.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_PKCS7_stream(
    out: *mut Bio,
    p7: *mut Pkcs7,
    in_: *mut Bio,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller's contract; the name and item are static.
    unsafe { PEM_write_bio_ASN1_stream(out, p7.cast(), in_, flags, c"PKCS7".as_ptr(), PKCS7_it()) }
}

/// `int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags)` — `pk7_mime.c:30-50`.
///
/// # Safety
/// `bio`/`data` are live BIOs; `p7` is live.
#[no_mangle]
pub unsafe extern "C" fn SMIME_write_PKCS7(
    bio: *mut Bio,
    p7: *mut Pkcs7,
    data: *mut Bio,
    flags: c_int,
) -> c_int {
    // SAFETY: `p7` is live.
    let ctype_nid = unsafe { OBJ_obj2nid((*p7).type_) };
    // SAFETY: `p7` is live.
    let ctx = unsafe { ossl_pkcs7_get0_ctx(p7) };
    let mdalgs = if ctype_nid == NID_pkcs7_signed {
        // SAFETY: `p7` is live.
        let sign = unsafe { (*p7).d.sign };
        if sign.is_null() {
            return 0;
        }
        // SAFETY: `sign` is live.
        unsafe { (*sign).md_algs }
    } else {
        core::ptr::null_mut()
    };
    let flags = flags ^ SMIME_OLDMIME;
    // SAFETY: the caller's contract; the context helpers read `ctx`.
    unsafe {
        SMIME_write_ASN1_ex(
            bio,
            p7.cast(),
            data,
            flags,
            ctype_nid,
            NID_undef,
            mdalgs,
            PKCS7_it(),
            ossl_pkcs7_ctx_get0_libctx(ctx),
            ossl_pkcs7_ctx_get0_propq(ctx),
        )
    }
}

/// `PKCS7 *SMIME_read_PKCS7_ex(BIO *bio, BIO **bcont, PKCS7 **p7)` — `pk7_mime.c:52-68`.
///
/// # Safety
/// `bio` is live; `bcont` is null or writable; `p7` is null or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn SMIME_read_PKCS7_ex(
    bio: *mut Bio,
    bcont: *mut *mut Bio,
    p7: *mut *mut Pkcs7,
) -> *mut Pkcs7 {
    let mut libctx: *mut c_void = core::ptr::null_mut();
    let mut propq: *const c_char = core::ptr::null();
    // SAFETY: `*p7` is the caller's live `PKCS7` slot when non-null.
    if !p7.is_null() && !unsafe { *p7 }.is_null() {
        // SAFETY: `*p7` is live per the caller's contract.
        unsafe {
            libctx = (**p7).ctx.libctx;
            propq = (**p7).ctx.propq;
        }
    }
    // SAFETY: the caller's contract; `PKCS7_it()` is a static item.
    let ret = unsafe { SMIME_read_ASN1_ex(bio, 0, bcont, PKCS7_it(), p7.cast(), libctx, propq) }
        .cast::<Pkcs7>();
    if !ret.is_null() {
        // SAFETY: `ret` is a fresh live `PKCS7`.
        unsafe { ossl_pkcs7_resolve_libctx(ret) };
    }
    ret
}

/// `PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont)` — `pk7_mime.c:70-73`.
///
/// # Safety
/// `bio` is live; `bcont` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn SMIME_read_PKCS7(bio: *mut Bio, bcont: *mut *mut Bio) -> *mut Pkcs7 {
    // SAFETY: the caller's contract.
    unsafe { SMIME_read_PKCS7_ex(bio, bcont, core::ptr::null_mut()) }
}

/// A `Pkcs7Ctx`-typed marker so the imported type is used even on the `SMIME_write` arm's
/// untyped context path.
type _Ctx = Pkcs7Ctx;
