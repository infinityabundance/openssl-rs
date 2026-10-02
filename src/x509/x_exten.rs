//! `crypto/x509/x_exten.c` — the `X509_EXTENSION` item and the `X509_EXTENSIONS` wrapper.
//! Phase 10.8 landed the item; Phase 11.4b lands the wrapper.
//!
//! `crypto/x509/x_exten.c` is 27 lines: the `ASN1_SEQUENCE(X509_EXTENSION)` template, the
//! `X509_EXTENSIONS` `SEQUENCE OF` wrapper, and the `IMPLEMENT_ASN1_FUNCTIONS` /
//! `IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname` / `IMPLEMENT_ASN1_DUP_FUNCTION` groups over them. The
//! `X509_CINF` template's `extensions` column is an `ASN1_EXP_SEQUENCE_OF_OPT` over
//! `X509_EXTENSION`, not over `X509_EXTENSIONS`, so the object core does not name the wrapper —
//! but `X509_REQ`, `X509_CRL` and the `X509V3_EXT_*` builders do, which is why 11.4b lands it.
//!
//! ## The one symbol the macros do not emit
//!
//! The authority's `IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(X509_EXTENSIONS, X509_EXTENSIONS,
//! X509_EXTENSIONS)` (`asn1t.h:813-821`) emits `d2i_X509_EXTENSIONS` and `i2d_X509_EXTENSIONS` and
//! **no** `X509_EXTENSIONS_dup`: the `_dup` half belongs to `IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname`,
//! which this file does not use for the wrapper. The public `X509_EXTENSIONS_it()` comes from
//! `ASN1_ITEM_TEMPLATE_END` (`asn1t.h:115-124`). So the wrapper contributes exactly three exports,
//! which is what `forensics/phase11-obligations.json` records.
//!
//! ## The layout
//!
//! `struct X509_extension_st` is declared in `crypto/x509/x509_local.h` (not a public header):
//! `ASN1_OBJECT *object`, `ASN1_BOOLEAN critical`, `ASN1_OCTET_STRING value`, in that order. The
//! authority's `ASN1_BOOLEAN` is an `int`, so `critical` is four bytes at offset 8 and the
//! embedded `value` begins at 16; `courts/layout/measure-x509.c` is where those numbers come
//! from. The item layer stores the boolean **in the field's own slot** (`src/asn1/d2i.rs:783`)
//! rather than through a pointer, which is why the field is a `c_int` and not a `*mut`.
//!
//! ## No raise, and the court
//!
//! The template raises nothing and there is no hand-written function, so `crypto/x509/x_exten.c`
//! is deliberately **not** an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`. The unit's
//! evidence is `X509`'s round trip: a certificate with an extension decodes and re-encodes to the
//! same bytes.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_FBOOLEAN_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::obj::Asn1Object;
use crate::runtime::stack::OpenSslStack;

/// `struct X509_extension_st` — `X509_EXTENSION`, from `crypto/x509/x509_local.h:52-56`.
///
/// The authority's three fields in order:
/// `Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE,
/// extnValue OCTET STRING }`.
#[repr(C)]
pub struct X509Extension {
    /// `ASN1_OBJECT *object` — the extension's OID.
    pub(crate) object: *mut Asn1Object,
    /// `ASN1_BOOLEAN critical` — an `int` the item layer reads and writes in the slot itself.
    pub(crate) critical: c_int,
    /// `ASN1_OCTET_STRING value` — the DER of the extension's own value, embedded rather than
    /// pointed at (`ASN1_EMBED`).
    pub(crate) value: Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<X509Extension>() == 40);
    assert!(core::mem::offset_of!(X509Extension, object) == 0);
    assert!(core::mem::offset_of!(X509Extension, critical) == 8);
    assert!(core::mem::offset_of!(X509Extension, value) == 16);
};

/// `X509_EXTENSION_seq_tt` — `crypto/x509/x_exten.c:16-20`'s `ASN1_SEQUENCE(X509_EXTENSION)`:
/// `ASN1_SIMPLE(X509_EXTENSION, object, ASN1_OBJECT)`,
/// `ASN1_OPT(X509_EXTENSION, critical, ASN1_FBOOLEAN)` and
/// `ASN1_EMBED(X509_EXTENSION, value, ASN1_OCTET_STRING)`.
static X509_EXTENSION_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"object".as_ptr(),
        item: ASN1_OBJECT_it as *mut core::ffi::c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"critical".as_ptr(),
        item: ASN1_FBOOLEAN_it as *mut core::ffi::c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 16,
        field_name: c"value".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut core::ffi::c_void,
    },
];

/// `X509_EXTENSION_it`'s descriptor — `ASN1_SEQUENCE_END(X509_EXTENSION)` at
/// `crypto/x509/x_exten.c:20`.
static X509_EXTENSION_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_EXTENSION_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509Extension>() as c_long,
    sname: c"X509_EXTENSION".as_ptr(),
};

/// `const ASN1_ITEM *X509_EXTENSION_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END(X509_EXTENSION)`.
#[no_mangle]
pub extern "C" fn X509_EXTENSION_it() -> *const Asn1Item {
    &X509_EXTENSION_ITEM
}

/// `X509_EXTENSION *X509_EXTENSION_new(void)` — `crypto/x509/x_exten.c:25`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_EXTENSION)`.
#[no_mangle]
pub extern "C" fn X509_EXTENSION_new() -> *mut X509Extension {
    // SAFETY: `X509_EXTENSION_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_EXTENSION_it()).cast::<X509Extension>() }
}

/// `void X509_EXTENSION_free(X509_EXTENSION *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_EXTENSION_free(a: *mut X509Extension) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_EXTENSION_it()) }
}

/// `X509_EXTENSION *X509_EXTENSION_dup(const X509_EXTENSION *a)` — the file's
/// `IMPLEMENT_ASN1_DUP_FUNCTION(X509_EXTENSION)` (`:27`).
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn X509_EXTENSION_dup(a: *const X509Extension) -> *mut X509Extension {
    // SAFETY: `a` is NULL or live per the contract; `X509_EXTENSION_it()` is a static item.
    unsafe { ASN1_item_dup(X509_EXTENSION_it(), a.cast()).cast::<X509Extension>() }
}

/// `X509_EXTENSION *d2i_X509_EXTENSION(X509_EXTENSION **a, const unsigned char **in,
/// long len)` — `crypto/x509/x_exten.c:25`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_EXTENSION(
    a: *mut *mut X509Extension,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Extension {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_EXTENSION_it()).cast::<X509Extension>() }
}

/// `int i2d_X509_EXTENSION(const X509_EXTENSION *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_EXTENSION(
    a: *const X509Extension,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_EXTENSION_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `X509_EXTENSIONS` SEQUENCE OF wrapper (`crypto/x509/x_exten.c:22-23`)
// ---------------------------------------------------------------------------------------------

/// `X509_EXTENSIONS_item_tt` — `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Extension,
/// X509_EXTENSION)` at `crypto/x509/x_exten.c:22`. The value is a `STACK_OF(X509_EXTENSION)`, which
/// is the type `X509_EXTENSIONS` names (`include/openssl/x509.h`).
static X509_EXTENSIONS_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"Extension".as_ptr(),
    item: X509_EXTENSION_it as *mut c_void,
};

/// `X509_EXTENSIONS_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(X509_EXTENSIONS)` at
/// `crypto/x509/x_exten.c:22`: a `PRIMITIVE` item over one `SEQUENCE OF` template, `utype` `-1`,
/// `tcount` 0, `size` 0.
static X509_EXTENSIONS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &X509_EXTENSIONS_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"X509_EXTENSIONS".as_ptr(),
};

/// `const ASN1_ITEM *X509_EXTENSIONS_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_ITEM_TEMPLATE_END(X509_EXTENSIONS)`.
#[no_mangle]
pub extern "C" fn X509_EXTENSIONS_it() -> *const Asn1Item {
    &X509_EXTENSIONS_ITEM
}

/// `X509_EXTENSIONS *d2i_X509_EXTENSIONS(X509_EXTENSIONS **a, const unsigned char **in, long len)`
/// — `crypto/x509/x_exten.c:23`'s `IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname` decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_EXTENSIONS(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_EXTENSIONS_it()).cast::<OpenSslStack>() }
}

/// `int i2d_X509_EXTENSIONS(const X509_EXTENSIONS *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_EXTENSIONS(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_EXTENSIONS_it()) }
}
