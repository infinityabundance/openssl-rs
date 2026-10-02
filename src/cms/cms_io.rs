//! `crypto/cms/cms_io.c` — the CMS <-> BIO/PEM/S/MIME readers. Phase 12.3c.
//!
//! [`CMS_stream`] is the streaming callback's boundary hook and `cms_asn1.rs`/`cms_lib.rs` reach
//! it; the rest of this unit is the BIO/PEM codec (`d2i_CMS_bio`/`i2d_CMS_bio`, the four
//! `PEM_*_CMS`, `BIO_new_CMS`), the streaming wrappers (`i2d_CMS_bio_stream`,
//! `PEM_write_bio_CMS_stream`) and the S/MIME wrappers (`SMIME_write_CMS`, `SMIME_read_CMS_ex`,
//! `SMIME_read_CMS`).
//!
//! ## The three delegates that are 12.9's
//!
//! `SMIME_write_CMS`/`SMIME_read_CMS_ex` call `SMIME_write_ASN1_ex`/`SMIME_read_ASN1_ex`
//! (`cms_io.c:93,106`), whose owning unit is `crypto/asn1/asn_mime.c`, one of the Phase-5
//! hand-offs 12.9 lands. The declarations below are the authority's own `asn1.h` prototypes, so
//! when 12.9 lands the unit the arms bind to it, exactly as `pk7_mime.rs` names them.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::ASN1_item_d2i_bio_ex;
use crate::asn1::a_i2d_fp::ASN1_item_i2d_bio;
use crate::asn1::asn_mime::i2d_ASN1_bio_stream;
use crate::asn1::bio_asn1::BIO_new_NDEF;
use crate::asn1::layout::{Asn1Item, I2dOfVoid, ASN1_STRING_FLAG_CONT, ASN1_STRING_FLAG_NDEF};
use crate::asn1::string::ASN1_STRING_new;
use crate::evp::pem_bridge::{PEM_write_bio_ASN1_stream, PemPasswordCb};
use crate::pem::pem_lib::{PEM_ASN1_read, PEM_ASN1_write, PEM_ASN1_write_bio};
use crate::pem::pem_oth::PEM_ASN1_read_bio;
use crate::runtime::bio::Bio;
use crate::runtime::obj::{NID_pkcs7_signed, OBJ_obj2nid};
use crate::runtime::stack::OpenSslStack;

use super::cms_asn1::*;
use super::cms_lib::{
    d2i_CMS_ContentInfo, i2d_CMS_ContentInfo, ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq,
    ossl_cms_get0_cmsctx, ossl_cms_resolve_libctx, raise_cms, CMS_get0_content,
    CMS_get0_eContentType, ERR_R_CMS_LIB,
};

/// `PEM_STRING_CMS` — `include/openssl/pem.h:46`.
const PEM_STRING_CMS: *const c_char = c"CMS".as_ptr();

extern "C" {
    /// `int SMIME_write_ASN1_ex(BIO *bio, ASN1_VALUE *val, BIO *data, int flags, int ctype_nid,`
    /// `int econt_nid, STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it, OSSL_LIB_CTX *libctx,`
    /// `const char *propq)` — `crypto/asn1/asn_mime.c`, 12.9's.
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

    /// `ASN1_VALUE *SMIME_read_ASN1_ex(BIO *bio, int flags, BIO **bcont, const ASN1_ITEM *it,`
    /// `ASN1_VALUE **x, OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/asn1/asn_mime.c`,
    /// 12.9's.
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

/// The `(d2i_of_void *)` cast for `d2i_CMS_ContentInfo`.
///
/// # Safety
/// The `void *` arguments are the typed decoder's own arguments.
unsafe extern "C" fn d2i_void_cms(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { d2i_CMS_ContentInfo(a.cast::<*mut CmsContentInfo>(), in_, len).cast::<c_void>() }
}

/// The `(i2d_of_void *)` cast for `i2d_CMS_ContentInfo`.
///
/// # Safety
/// `x` is live and `out` is the encoder's own cursor.
unsafe extern "C" fn i2d_void_cms(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_CMS_ContentInfo(x.cast::<CmsContentInfo>(), out) }
}

/// The shared body of every plain writer: one `PEM_ASN1_write`.
///
/// # Safety
/// `out` is writable; `x` is live and `i2d` its encoder.
unsafe fn plain_write(i2d: I2dOfVoid, out: *mut c_void, x: *const c_void) -> c_int {
    // SAFETY: the caller's contract; the two NULLs are the macro's no-cipher arms.
    unsafe {
        PEM_ASN1_write(
            Some(i2d),
            PEM_STRING_CMS,
            out,
            x,
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

/// The shared body of every plain BIO writer: one `PEM_ASN1_write_bio`.
///
/// # Safety
/// `out` is a live BIO; `x` is live and `i2d` its encoder.
unsafe fn plain_write_bio(i2d: I2dOfVoid, out: *mut Bio, x: *const c_void) -> c_int {
    // SAFETY: the caller's contract; the two NULLs are the macro's no-cipher arms.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d),
            PEM_STRING_CMS,
            out,
            x,
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

/// `int CMS_stream(unsigned char ***boundary, CMS_ContentInfo *cms)` — `cms_io.c:18-35`.
///
/// # Safety
/// `boundary` is writable; `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_stream(
    boundary: *mut *mut *mut u8,
    cms: *mut CmsContentInfo,
) -> c_int {
    // SAFETY: `cms` is live.
    let pos = unsafe { CMS_get0_content(cms) };
    if pos.is_null() {
        return 0;
    }
    // SAFETY: `pos` is a live slot.
    unsafe {
        if (*pos).is_null() {
            *pos = ASN1_STRING_new();
        }
        if !(*pos).is_null() {
            (*(*pos)).flags |= ASN1_STRING_FLAG_NDEF;
            (*(*pos)).flags &= !ASN1_STRING_FLAG_CONT;
            *boundary = ptr::addr_of_mut!((*(*pos)).data);
            return 1;
        }
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cms(33, c"CMS_stream", ERR_R_CMS_LIB) };
    0
}

/// `CMS_ContentInfo *d2i_CMS_bio(BIO *bp, CMS_ContentInfo **cms)` — `cms_io.c:37-51`.
///
/// # Safety
/// `bp` is a live readable BIO; `cms` is NULL or the decoder's destination.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_CMS_bio(
    bp: *mut Bio,
    cms: *mut *mut CmsContentInfo,
) -> *mut CmsContentInfo {
    // SAFETY: `cms` is NULL or writable.
    let ctx = unsafe { ossl_cms_get0_cmsctx(if cms.is_null() { ptr::null() } else { *cms }) };

    // SAFETY: `bp` is live; `cms` is the decoder's destination; `ctx` is live.
    let ci = unsafe {
        ASN1_item_d2i_bio_ex(
            CMS_ContentInfo_it(),
            bp,
            cms.cast(),
            ossl_cms_ctx_get0_libctx(ctx),
            ossl_cms_ctx_get0_propq(ctx),
        )
    }
    .cast::<CmsContentInfo>();
    if !ci.is_null() {
        crate::runtime::err::ERR_set_mark();
        // SAFETY: `ci` is live.
        unsafe { ossl_cms_resolve_libctx(ci) };
        crate::runtime::err::ERR_pop_to_mark();
    }
    ci
}

/// `int i2d_CMS_bio(BIO *bp, CMS_ContentInfo *cms)` — `cms_io.c:53-56`.
///
/// # Safety
/// `bp` is a live writable BIO; `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_CMS_bio(bp: *mut Bio, cms: *mut CmsContentInfo) -> c_int {
    // SAFETY: `bp`/`cms` are live; `CMS_ContentInfo_it()` is a static item.
    unsafe { ASN1_item_i2d_bio(CMS_ContentInfo_it(), bp, cms.cast()) }
}

// `IMPLEMENT_PEM_rw(CMS, CMS_ContentInfo, PEM_STRING_CMS, CMS_ContentInfo)` — `cms_io.c:58`.

/// `CMS_ContentInfo *PEM_read_CMS(FILE *fp, CMS_ContentInfo **x, pem_password_cb *cb, void *u)` —
/// `cms_io.c:58`.
///
/// # Safety
/// `fp` is an open readable stream; `x` is the decoder's destination; `cb`/`u` are passed to the
/// reader.
#[no_mangle]
pub(crate) unsafe extern "C" fn PEM_read_CMS(
    fp: *mut c_void,
    x: *mut *mut CmsContentInfo,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut CmsContentInfo {
    // SAFETY: `d2i_void_cms` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read(d2i_void_cms, PEM_STRING_CMS, fp, x.cast(), cb, u) }
        .cast::<CmsContentInfo>()
}

/// `CMS_ContentInfo *PEM_read_bio_CMS(BIO *bp, CMS_ContentInfo **x, pem_password_cb *cb,`
/// `void *u)` — `cms_io.c:58`.
///
/// # Safety
/// `bp` is a live readable BIO; `x` is the decoder's destination; `cb`/`u` are passed to the
/// reader.
#[no_mangle]
pub(crate) unsafe extern "C" fn PEM_read_bio_CMS(
    bp: *mut Bio,
    x: *mut *mut CmsContentInfo,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut CmsContentInfo {
    // SAFETY: `d2i_void_cms` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read_bio(d2i_void_cms, PEM_STRING_CMS, bp, x.cast(), cb, u) }
        .cast::<CmsContentInfo>()
}

/// `int PEM_write_CMS(FILE *out, const CMS_ContentInfo *x)` — `cms_io.c:58`.
///
/// # Safety
/// `out` is an open writable stream; `x` is a live container.
#[no_mangle]
pub(crate) unsafe extern "C" fn PEM_write_CMS(out: *mut c_void, x: *const CmsContentInfo) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_cms` is the encoder.
    unsafe { plain_write(i2d_void_cms, out, x.cast()) }
}

/// `int PEM_write_bio_CMS(BIO *out, const CMS_ContentInfo *x)` — `cms_io.c:58`.
///
/// # Safety
/// `out` is a live writable BIO; `x` is a live container.
#[no_mangle]
pub(crate) unsafe extern "C" fn PEM_write_bio_CMS(
    out: *mut Bio,
    x: *const CmsContentInfo,
) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_cms` is the encoder.
    unsafe { plain_write_bio(i2d_void_cms, out, x.cast()) }
}

/// `BIO *BIO_new_CMS(BIO *out, CMS_ContentInfo *cms)` — `cms_io.c:60-64`.
///
/// # Safety
/// `out` is a live BIO; `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn BIO_new_CMS(out: *mut Bio, cms: *mut CmsContentInfo) -> *mut Bio {
    // SAFETY: `out`/`cms` are live; `CMS_ContentInfo_it()` is a static item.
    unsafe { BIO_new_NDEF(out, cms.cast(), CMS_ContentInfo_it()) }
}

/// `int i2d_CMS_bio_stream(BIO *out, CMS_ContentInfo *cms, BIO *in, int flags)` —
/// `cms_io.c:68-72`.
///
/// # Safety
/// `out`/`in` are live BIOs; `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_CMS_bio_stream(
    out: *mut Bio,
    cms: *mut CmsContentInfo,
    in_: *mut Bio,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller's contract; `CMS_ContentInfo_it()` is a static item.
    unsafe { i2d_ASN1_bio_stream(out, cms.cast(), in_, flags, CMS_ContentInfo_it()) }
}

/// `int PEM_write_bio_CMS_stream(BIO *out, CMS_ContentInfo *cms, BIO *in, int flags)` —
/// `cms_io.c:74-79`.
///
/// # Safety
/// `out`/`in` are live BIOs; `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn PEM_write_bio_CMS_stream(
    out: *mut Bio,
    cms: *mut CmsContentInfo,
    in_: *mut Bio,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller's contract; `CMS_ContentInfo_it()` is a static item.
    unsafe {
        PEM_write_bio_ASN1_stream(
            out,
            cms.cast(),
            in_,
            flags,
            PEM_STRING_CMS,
            CMS_ContentInfo_it(),
        )
    }
}

/// `int SMIME_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data, int flags)` — `cms_io.c:81-98`.
///
/// # Safety
/// `bio`/`cms` are live; `data` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn SMIME_write_CMS(
    bio: *mut Bio,
    cms: *mut CmsContentInfo,
    data: *mut Bio,
    flags: c_int,
) -> c_int {
    // SAFETY: `cms` is live.
    let ctype_nid = unsafe { OBJ_obj2nid((*cms).content_type) };
    // SAFETY: `cms` is live.
    let econt_nid = unsafe { OBJ_obj2nid(CMS_get0_eContentType(cms)) };
    // SAFETY: `cms` is live.
    let ctx = unsafe { ossl_cms_get0_cmsctx(cms) };

    let mdalgs = if ctype_nid == NID_pkcs7_signed {
        // SAFETY: `cms` is live and its type is signed.
        unsafe { (*(*cms).d.cast::<CmsSignedData>()).digest_algorithms }
    } else {
        ptr::null_mut()
    };

    // SAFETY: `bio`/`cms` are live; `ctx` is live; `CMS_ContentInfo_it()` is a static item.
    unsafe {
        SMIME_write_ASN1_ex(
            bio,
            cms.cast(),
            data,
            flags,
            ctype_nid,
            econt_nid,
            mdalgs,
            CMS_ContentInfo_it(),
            ossl_cms_ctx_get0_libctx(ctx),
            ossl_cms_ctx_get0_propq(ctx),
        )
    }
}

/// `CMS_ContentInfo *SMIME_read_CMS_ex(BIO *bio, int flags, BIO **bcont,`
/// `CMS_ContentInfo **cms)` — `cms_io.c:100-117`.
///
/// # Safety
/// `bio` is a live BIO; `bcont` is NULL or writable; `cms` is NULL or the decoder's destination.
#[no_mangle]
pub(crate) unsafe extern "C" fn SMIME_read_CMS_ex(
    bio: *mut Bio,
    flags: c_int,
    bcont: *mut *mut Bio,
    cms: *mut *mut CmsContentInfo,
) -> *mut CmsContentInfo {
    // SAFETY: `cms` is NULL or writable.
    let ctx = unsafe { ossl_cms_get0_cmsctx(if cms.is_null() { ptr::null() } else { *cms }) };

    // SAFETY: `bio`/`ctx` are live; `bcont` is NULL or writable; `cms` is the decoder's slot.
    let ci = unsafe {
        SMIME_read_ASN1_ex(
            bio,
            flags,
            bcont,
            CMS_ContentInfo_it(),
            cms.cast(),
            ossl_cms_ctx_get0_libctx(ctx),
            ossl_cms_ctx_get0_propq(ctx),
        )
    }
    .cast::<CmsContentInfo>();
    if !ci.is_null() {
        crate::runtime::err::ERR_set_mark();
        // SAFETY: `ci` is live.
        unsafe { ossl_cms_resolve_libctx(ci) };
        crate::runtime::err::ERR_pop_to_mark();
    }
    ci
}

/// `CMS_ContentInfo *SMIME_read_CMS(BIO *bio, BIO **bcont)` — `cms_io.c:119-122`.
///
/// # Safety
/// `bio` is a live BIO; `bcont` is NULL or writable.
#[no_mangle]
pub(crate) unsafe extern "C" fn SMIME_read_CMS(
    bio: *mut Bio,
    bcont: *mut *mut Bio,
) -> *mut CmsContentInfo {
    // SAFETY: the arguments to the `_ex` form are the caller's.
    unsafe { SMIME_read_CMS_ex(bio, 0, bcont, ptr::null_mut()) }
}
