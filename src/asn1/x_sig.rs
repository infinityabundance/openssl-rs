//! `crypto/asn1/x_sig.c` — the `X509_SIG` family, transcribed whole.
//!
//! `crypto/asn1/x_sig.c` is 39 lines: the `ASN1_SEQUENCE(X509_SIG)` template and the
//! `IMPLEMENT_ASN1_FUNCTIONS(X509_SIG)` group over it, plus the `get0`/`getm` pair. It is the
//! `EncryptedPrivateKeyInfo` type — `PKCS#8`'s encrypted spelling — and Phase 10's
//! `PKCS8_decrypt` reads it through [`X509_SIG_get0`], which is why it lands here.
//!
//! ## The layout
//!
//! `struct X509_sig_st` is declared in `include/openssl/x509.h`: `X509_ALGOR *algor` then
//! `ASN1_OCTET_STRING *digest`. The item layer reads the two offsets below, so they are asserted
//! rather than typed twice.
//!
//! ## What the item layer generates
//!
//! `ASN1_SEQUENCE_END(X509_SIG)` gives [`X509_SIG_it`]; `IMPLEMENT_ASN1_FUNCTIONS(X509_SIG)` adds
//! `_new`, `_free`, `d2i_` and `i2d_`. There is **no** `X509_SIG_dup`: the file calls no
//! `IMPLEMENT_ASN1_DUP_FUNCTION`, which is the one asymmetry against its `x_algor.c` sibling.
//!
//! ## No raise, and the court
//!
//! Neither hand-written function raises, and the template adds none, so `crypto/asn1/x_sig.c` is
//! deliberately **not** an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`. The unit's
//! evidence is its round trip: `crypto/asn1/x_sig.c`'s two `ASN1_SIMPLE` columns mean a built
//! value encodes and decodes back with the same identifier and octets.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_OCTET_STRING_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};

/// `struct X509_sig_st` — `X509_SIG`, from `include/openssl/x509.h`.
///
/// The authority's two fields in order: the digest algorithm identifier and the encrypted octets
/// (`EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, encryptedData
/// OCTET STRING }`).
#[repr(C)]
pub struct X509Sig {
    /// `X509_ALGOR *algor` — the encryption algorithm, read by `get0`/`getm`.
    pub(crate) algor: *mut X509Algor,
    /// `ASN1_OCTET_STRING *digest` — the encrypted data, read by `get0`/`getm`.
    pub(crate) digest: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<X509Sig>() == 16);
    assert!(core::mem::offset_of!(X509Sig, algor) == 0);
    assert!(core::mem::offset_of!(X509Sig, digest) == 8);
};

/// `X509_SIG_seq_tt` — `crypto/asn1/x_sig.c:18-21`'s `ASN1_SEQUENCE(X509_SIG)`:
/// `ASN1_SIMPLE(X509_SIG, algor, X509_ALGOR)` and
/// `ASN1_SIMPLE(X509_SIG, digest, ASN1_OCTET_STRING)`.
static X509_SIG_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"algor".as_ptr(),
        item: X509_ALGOR_it as *mut core::ffi::c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"digest".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut core::ffi::c_void,
    },
];

/// `X509_SIG_it`'s descriptor — `ASN1_SEQUENCE_END(X509_SIG)` at `crypto/asn1/x_sig.c:21`.
static X509_SIG_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_SIG_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509Sig>() as c_long,
    sname: c"X509_SIG".as_ptr(),
};

/// `const ASN1_ITEM *X509_SIG_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END(X509_SIG)`.
#[no_mangle]
pub extern "C" fn X509_SIG_it() -> *const Asn1Item {
    &X509_SIG_ITEM
}

/// `X509_SIG *X509_SIG_new(void)` — `crypto/asn1/x_sig.c:23`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_SIG)`.
#[no_mangle]
pub extern "C" fn X509_SIG_new() -> *mut X509Sig {
    // SAFETY: `X509_SIG_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_SIG_it()).cast::<X509Sig>() }
}

/// `void X509_SIG_free(X509_SIG *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_SIG_free(a: *mut X509Sig) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_SIG_it()) }
}

/// `X509_SIG *d2i_X509_SIG(X509_SIG **a, const unsigned char **in, long len)` —
/// `crypto/asn1/x_sig.c:23`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_SIG(
    a: *mut *mut X509Sig,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Sig {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_SIG_it()).cast::<X509Sig>() }
}

/// `int i2d_X509_SIG(const X509_SIG *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_SIG(a: *const X509Sig, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_SIG_it()) }
}

/// `void X509_SIG_get0(const X509_SIG *sig, const X509_ALGOR **palg,
/// const ASN1_OCTET_STRING **pdigest)` — `crypto/asn1/x_sig.c:27-35`.
///
/// Both out-parameters are optional and independently skipped, and both answers are borrowed.
///
/// # Safety
///
/// `sig` is live; each out-pointer is NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn X509_SIG_get0(
    sig: *const X509Sig,
    palg: *mut *const X509Algor,
    pdigest: *mut *const Asn1String,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read and write.
    unsafe {
        if !palg.is_null() {
            *palg = (*sig).algor;
        }
        if !pdigest.is_null() {
            *pdigest = (*sig).digest;
        }
    }
}

/// `void X509_SIG_getm(X509_SIG *sig, X509_ALGOR **palg, ASN1_OCTET_STRING **pdigest)` —
/// `crypto/asn1/x_sig.c:37-45`.
///
/// The mutable twin of [`X509_SIG_get0`]: same reads, answer shaped for a caller that will write
/// through it.
///
/// # Safety
///
/// `sig` is live; each out-pointer is NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn X509_SIG_getm(
    sig: *mut X509Sig,
    palg: *mut *mut X509Algor,
    pdigest: *mut *mut Asn1String,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read and write.
    unsafe {
        if !palg.is_null() {
            *palg = (*sig).algor;
        }
        if !pdigest.is_null() {
            *pdigest = (*sig).digest;
        }
    }
}
