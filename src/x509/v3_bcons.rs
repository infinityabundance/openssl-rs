//! `crypto/x509/v3_bcons.c` — the `BASIC_CONSTRAINTS` item. Phase 10.14.6, landed at function
//! granularity.
//!
//! `crypto/x509/v3_bcons.c` is 85 lines. **The item group lands; the extension method and its
//! callbacks are withheld by name**:
//!
//! * `BASIC_CONSTRAINTS ::= SEQUENCE { ca BOOLEAN DEFAULT FALSE, pathlen INTEGER OPTIONAL }`
//!   (`:38-41`) lands, with `BASIC_CONSTRAINTS_it` and the `_new`/`_free`/`d2i_`/`i2d_` group
//!   `IMPLEMENT_ASN1_FUNCTIONS` emits (`:43`). All five are public exports (`x509v3.h`) the
//!   admitted DSO carries, so the differential plane can build one, encode it, decode the bytes
//!   back and free it. **`BASIC_CONSTRAINTS_free` is the seventh name
//!   `ossl_x509v3_cache_extensions` (`v3_purp.c`) was measured to need** — it frees the decoded
//!   `bs` after reading `ca`/`pathlen` — which is why this item lands before the table.
//! * `ossl_v3_bcons` (`:27-35`) is **withheld by name**: internal, the admitted DSO exports no
//!   `ossl_v3_*` (`nm -D`), and its only authority reach is `X509V3_add_standard_extensions`
//!   (`crypto/x509/v3_lib.c:127`) and the dispatch `X509V3_EXT_get_nid` (`:52-71`), which is
//!   withheld behind the ~63-row `standard_exts[]`. It is an entry of that table and cannot be
//!   published while the array is incomplete (D456).
//! * `i2v_BASIC_CONSTRAINTS` (`:45-54`) and `v2i_BASIC_CONSTRAINTS` (`:55-85`) are **withheld by
//!   name**: `static` callbacks reached only through the withheld table, so landing them would be
//!   dead code with no court. They are also the unit's only `ERR_raise` sites, so
//!   `crypto/x509/v3_bcons.c` is deliberately not added to `gen_err_raise_sites.py`'s covered set.
//!
//! Nothing is stubbed: the three withheld names are named rather than declared.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.14.6 arms build a `BASIC_CONSTRAINTS`, set `ca` and `pathlen` through the
//! public structure, encode it, decode the bytes back, re-encode and compare byte for byte, then
//! free both — driving `_new`/`_free`/`d2i_`/`i2d_`/`_it` and popping the error queue first.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BOOLEAN_it, ASN1_INTEGER_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;

/// `struct BASIC_CONSTRAINTS_st` — `BASIC_CONSTRAINTS`, from `include/openssl/x509v3.h:127-130`.
///
/// The authority's `int ca` and `ASN1_INTEGER *pathlen`. The internal `X509` struct already
/// models a `BASIC_CONSTRAINTS` as an opaque pointer, so this is the one definition of the name.
#[repr(C)]
pub struct BasicConstraints {
    /// `int ca` — the `ASN1_BOOLEAN`, `FALSE` by default so the encoder may omit it.
    pub ca: c_int,
    /// `ASN1_INTEGER *pathlen` — optional.
    pub pathlen: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<BasicConstraints>() == 16);
    assert!(core::mem::offset_of!(BasicConstraints, ca) == 0);
    assert!(core::mem::offset_of!(BasicConstraints, pathlen) == 8);
};

/// `BASIC_CONSTRAINTS_seq_tt` — `ASN1_SEQUENCE(BASIC_CONSTRAINTS)`
/// (`crypto/x509/v3_bcons.c:38-41`): two `ASN1_OPT` rows, `ca` over `ASN1_FBOOLEAN` and `pathlen`
/// over `ASN1_INTEGER`.
static BASIC_CONSTRAINTS_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"ca".as_ptr(),
        item: ASN1_BOOLEAN_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"pathlen".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `BASIC_CONSTRAINTS_it`'s descriptor — `ASN1_SEQUENCE_END(BASIC_CONSTRAINTS)` at
/// `crypto/x509/v3_bcons.c:41`.
static BASIC_CONSTRAINTS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: BASIC_CONSTRAINTS_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<BasicConstraints>() as c_long,
    sname: c"BASIC_CONSTRAINTS".as_ptr(),
};

/// `const ASN1_ITEM *BASIC_CONSTRAINTS_it(void)` — `include/openssl/x509v3.h`, from
/// `DECLARE_ASN1_FUNCTIONS(BASIC_CONSTRAINTS)`.
#[no_mangle]
pub extern "C" fn BASIC_CONSTRAINTS_it() -> *const Asn1Item {
    &BASIC_CONSTRAINTS_ITEM
}

/// `BASIC_CONSTRAINTS *BASIC_CONSTRAINTS_new(void)` — `crypto/x509/v3_bcons.c:43`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(BASIC_CONSTRAINTS)`.
#[no_mangle]
pub extern "C" fn BASIC_CONSTRAINTS_new() -> *mut BasicConstraints {
    // SAFETY: `BASIC_CONSTRAINTS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(BASIC_CONSTRAINTS_it()).cast::<BasicConstraints>() }
}

/// `void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a)` — the same macro's free half.
///
/// The seventh name `ossl_x509v3_cache_extensions` needs.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn BASIC_CONSTRAINTS_free(a: *mut BasicConstraints) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), BASIC_CONSTRAINTS_it()) }
}

/// `BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS **a, const unsigned char **in,
/// long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_BASIC_CONSTRAINTS(
    a: *mut *mut BasicConstraints,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut BasicConstraints {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, BASIC_CONSTRAINTS_it()).cast::<BasicConstraints>() }
}

/// `int i2d_BASIC_CONSTRAINTS(const BASIC_CONSTRAINTS *a, unsigned char **out)` — the same
/// macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_BASIC_CONSTRAINTS(
    a: *const BasicConstraints,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, BASIC_CONSTRAINTS_it()) }
}
