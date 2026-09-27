//! `crypto/asn1/x_val.c` — the `X509_VAL` family, transcribed whole. Phase 10.8.
//!
//! `crypto/asn1/x_val.c` is 20 lines: the `ASN1_SEQUENCE(X509_VAL)` template and the
//! `IMPLEMENT_ASN1_FUNCTIONS(X509_VAL)` group over it. `X509_VAL` is the `Validity` pair an
//! `X509_CINF` embeds — `notBefore` and `notAfter`, both `ASN1_TIME` — and it lands here because
//! the `X509_CINF` template `crypto/x509/x_x509.c:23` names its item, which is what 10.8's
//! `d2i_X509`/`i2d_X509` decode through.
//!
//! ## The layout
//!
//! `struct X509_val_st` is declared in `include/openssl/x509.h`: two `ASN1_TIME *` members. The
//! item layer reads both offsets, so they are asserted rather than read by eye. `X509_CINF` places
//! this struct **embedded** at offset 56 (`courts/layout/measure-x509.c`), which is why the size
//! is asserted too.
//!
//! ## What the item layer generates
//!
//! `ASN1_SEQUENCE_END(X509_VAL)` gives [`X509_VAL_it`]; `IMPLEMENT_ASN1_FUNCTIONS(X509_VAL)` adds
//! `_new`, `_free`, `d2i_` and `i2d_`. There is no `X509_VAL_dup`: the file calls no
//! `IMPLEMENT_ASN1_DUP_FUNCTION`, which is the one asymmetry against its `x_sig.c` sibling.
//!
//! ## No raise, and the court
//!
//! The template raises nothing and there is no hand-written function, so `crypto/asn1/x_val.c` is
//! deliberately **not** an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`. The unit's
//! evidence is its round trip, driven from `X509`'s: a decoded certificate's `validity` is two
//! `ASN1_TIME`s that re-encode to the same bytes.
//!
//! SPDX-License-Identifier: Apache-2.0

// The structure below carries the authority's own member names (`notBefore`/`notAfter`), so a
// reader can line it up with `include/openssl/x509.h` without a translation table.
#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_TIME_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;

/// `struct X509_val_st` — `X509_VAL`, from `include/openssl/x509.h`.
///
/// The authority's two fields in order, both mandatory and both pointers:
/// `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`.
#[repr(C)]
pub struct X509Val {
    /// `ASN1_TIME *notBefore` — the start time.
    pub(crate) notBefore: *mut Asn1String,
    /// `ASN1_TIME *notAfter` — the end time.
    pub(crate) notAfter: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<X509Val>() == 16);
    assert!(core::mem::offset_of!(X509Val, notBefore) == 0);
    assert!(core::mem::offset_of!(X509Val, notAfter) == 8);
};

/// `X509_VAL_seq_tt` — `crypto/asn1/x_val.c:16-19`'s `ASN1_SEQUENCE(X509_VAL)`:
/// `ASN1_SIMPLE(X509_VAL, notBefore, ASN1_TIME)` and
/// `ASN1_SIMPLE(X509_VAL, notAfter, ASN1_TIME)`.
static X509_VAL_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"notBefore".as_ptr(),
        item: ASN1_TIME_it as *mut core::ffi::c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"notAfter".as_ptr(),
        item: ASN1_TIME_it as *mut core::ffi::c_void,
    },
];

/// `X509_VAL_it`'s descriptor — `ASN1_SEQUENCE_END(X509_VAL)` at `crypto/asn1/x_val.c:19`.
static X509_VAL_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_VAL_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509Val>() as c_long,
    sname: c"X509_VAL".as_ptr(),
};

/// `const ASN1_ITEM *X509_VAL_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END(X509_VAL)`.
#[no_mangle]
pub extern "C" fn X509_VAL_it() -> *const Asn1Item {
    &X509_VAL_ITEM
}

/// `X509_VAL *X509_VAL_new(void)` — `crypto/asn1/x_val.c:21`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_VAL)`.
#[no_mangle]
pub extern "C" fn X509_VAL_new() -> *mut X509Val {
    // SAFETY: `X509_VAL_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_VAL_it()).cast::<X509Val>() }
}

/// `void X509_VAL_free(X509_VAL *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_VAL_free(a: *mut X509Val) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_VAL_it()) }
}

/// `X509_VAL *d2i_X509_VAL(X509_VAL **a, const unsigned char **in, long len)` —
/// `crypto/asn1/x_val.c:21`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_VAL(
    a: *mut *mut X509Val,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Val {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_VAL_it()).cast::<X509Val>() }
}

/// `int i2d_X509_VAL(const X509_VAL *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_VAL(a: *const X509Val, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_VAL_it()) }
}
