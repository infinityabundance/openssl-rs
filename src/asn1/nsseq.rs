//! `crypto/asn1/nsseq.c` — the `NETSCAPE_CERT_SEQUENCE` item. Phase 11.7.
//!
//! `crypto/asn1/nsseq.c` is 34 lines: the `ASN1_SEQUENCE_cb(NETSCAPE_CERT_SEQUENCE, nsseq_cb)`
//! template (`:29-32`), the `nsseq_cb` informational callback (`:16-25`) and the
//! `IMPLEMENT_ASN1_FUNCTIONS(NETSCAPE_CERT_SEQUENCE)` group (`:34`) that adds `_new`, `_free`,
//! `d2i_` and `i2d_`. The five exports this unit publishes land here.
//!
//! ## The layout
//!
//! `struct Netscape_certificate_sequence` is declared in `include/openssl/x509.h.in:247-250`:
//! `ASN1_OBJECT *type` then `STACK_OF(X509) *certs`. The item layer reads the two offsets below,
//! so they are asserted rather than typed twice.
//!
//! ## `nsseq_cb` seeds `type` on `ASN1_OP_NEW_POST`
//!
//! The sequence's first field is an `OBJECT` the template alone would leave empty, so the
//! authority's callback assigns `OBJ_nid2obj(NID_netscape_cert_sequence)` when a fresh value is
//! built (`:19-23`). That is what makes a `NETSCAPE_CERT_SEQUENCE_new()` round-trip encode the
//! Netscape sequence OID before the caller sets anything, and why this file carries an
//! `ASN1_AUX` at all.
//!
//! ## Why this 11.7 unit lands with 11.6
//!
//! `PEM_read[_bio]_NETSCAPE_CERT_SEQUENCE` and its two writers are `crypto/pem/pem_all.c`'s
//! (`docs/PHASE-11-SUBPHASES.md` section 2 row 11.6, exports 33 of `pem_all.c`), and each is one
//! `PEM_ASN1_*` call over this file's `d2i_NETSCAPE_CERT_SEQUENCE`/`i2d_NETSCAPE_CERT_SEQUENCE`.
//! The 11.6 slice cannot land its four names without this item, so the item lands with it and is
//! named here rather than forced into the 11.7 row (`docs/PHASE-11-SUBPHASES.md` section 5: a
//! slice that discovers its unit is somewhere else records that rather than forcing the row).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_OBJECT_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::obj::{Asn1Object, NID_netscape_cert_sequence, OBJ_nid2obj};
use crate::runtime::stack::OpenSslStack;
use crate::x509::x_x509::X509_it;

/// `struct Netscape_certificate_sequence` — `NETSCAPE_CERT_SEQUENCE`, from
/// `include/openssl/x509.h.in:247-250`.
///
/// The authority's two fields in order: the sequence's OID and the certificate stack the
/// optional `[0]` element carries.
#[repr(C)]
pub struct NetScapeCertSequence {
    /// `ASN1_OBJECT *type` — seeded by `nsseq_cb` on a fresh value and re-read on decode.
    pub(crate) type_: *mut Asn1Object,
    /// `STACK_OF(X509) *certs` — the `[0] EXPLICIT SEQUENCE OF X509`, optional.
    pub(crate) certs: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<NetScapeCertSequence>() == 16);
    assert!(core::mem::offset_of!(NetScapeCertSequence, type_) == 0);
    assert!(core::mem::offset_of!(NetScapeCertSequence, certs) == 8);
};

/// `static int nsseq_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/asn1/nsseq.c:16-25`.
///
/// Only the `ASN1_OP_NEW_POST` arm does anything: it seeds the value's `type` with the Netscape
/// sequence OID. Every other operation answers 1, as the authority does.
///
/// # Safety
/// `pval` points at a live `NETSCAPE_CERT_SEQUENCE *` for `ASN1_OP_NEW_POST`, per the callback
/// contract the item layer establishes.
unsafe extern "C" fn nsseq_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_NEW_POST {
        // SAFETY: the item layer hands a freshly built value here.
        let nsseq = unsafe { *pval }.cast::<NetScapeCertSequence>();
        // SAFETY: `nsseq` is live and `type` is its own field; `OBJ_nid2obj` answers a shared
        // object the value borrows.
        unsafe { (*nsseq).type_ = OBJ_nid2obj(NID_netscape_cert_sequence) };
    }
    1
}

/// `NETSCAPE_CERT_SEQUENCE`'s `ASN1_AUX` — `ASN1_SEQUENCE_cb(NETSCAPE_CERT_SEQUENCE, nsseq_cb)`:
/// flags and offsets zero, the callback `nsseq_cb`.
struct SyncAux(Asn1Aux);

// SAFETY: a `static` compiled from constants and one function pointer, written once by the
// loader, with no interior mutability reachable through the shared reference the item takes.
unsafe impl Sync for SyncAux {}

/// The `ASN1_AUX` block named above.
static NS_SEQ_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(nsseq_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `NETSCAPE_CERT_SEQUENCE_seq_tt` — `crypto/asn1/nsseq.c:30-31`:
/// `ASN1_SIMPLE(NETSCAPE_CERT_SEQUENCE, type, ASN1_OBJECT)` and
/// `ASN1_EXP_SEQUENCE_OF_OPT(NETSCAPE_CERT_SEQUENCE, certs, X509, 0)`.
static NETSCAPE_CERT_SEQUENCE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"type".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"certs".as_ptr(),
        item: X509_it as *mut c_void,
    },
];

/// `NETSCAPE_CERT_SEQUENCE_it`'s descriptor — `ASN1_SEQUENCE_END_cb(NETSCAPE_CERT_SEQUENCE,
/// NETSCAPE_CERT_SEQUENCE)` at `crypto/asn1/nsseq.c:32`.
static NETSCAPE_CERT_SEQUENCE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: NETSCAPE_CERT_SEQUENCE_TT.as_ptr(),
    tcount: 2,
    funcs: (&NS_SEQ_AUX.0) as *const Asn1Aux as *const c_void,
    size: core::mem::size_of::<NetScapeCertSequence>() as c_long,
    sname: c"NETSCAPE_CERT_SEQUENCE".as_ptr(),
};

/// `const ASN1_ITEM *NETSCAPE_CERT_SEQUENCE_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END_cb(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE)`.
#[no_mangle]
pub extern "C" fn NETSCAPE_CERT_SEQUENCE_it() -> *const Asn1Item {
    &NETSCAPE_CERT_SEQUENCE_ITEM
}

/// `NETSCAPE_CERT_SEQUENCE *NETSCAPE_CERT_SEQUENCE_new(void)` — `crypto/asn1/nsseq.c:34`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(NETSCAPE_CERT_SEQUENCE)`.
#[no_mangle]
pub extern "C" fn NETSCAPE_CERT_SEQUENCE_new() -> *mut NetScapeCertSequence {
    // SAFETY: `NETSCAPE_CERT_SEQUENCE_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(NETSCAPE_CERT_SEQUENCE_it()).cast::<NetScapeCertSequence>() }
}

/// `void NETSCAPE_CERT_SEQUENCE_free(NETSCAPE_CERT_SEQUENCE *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn NETSCAPE_CERT_SEQUENCE_free(a: *mut NetScapeCertSequence) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), NETSCAPE_CERT_SEQUENCE_it()) }
}

/// `NETSCAPE_CERT_SEQUENCE *d2i_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE **a, const
/// unsigned char **in, long len)` — `crypto/asn1/nsseq.c:34`'s generated decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_NETSCAPE_CERT_SEQUENCE(
    a: *mut *mut NetScapeCertSequence,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut NetScapeCertSequence {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, NETSCAPE_CERT_SEQUENCE_it()).cast() }
}

/// `int i2d_NETSCAPE_CERT_SEQUENCE(const NETSCAPE_CERT_SEQUENCE *a, unsigned char **out)` — the
/// same macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_NETSCAPE_CERT_SEQUENCE(
    a: *const NetScapeCertSequence,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, NETSCAPE_CERT_SEQUENCE_it()) }
}
