//! Phase 10.14.2 — `crypto/asn1/x_spki.c`: the Netscape SPKI items.
//!
//! `crypto/asn1/x_spki.c` is 28 lines: two `ASN1_SEQUENCE` templates and their
//! `IMPLEMENT_ASN1_FUNCTIONS` groups.
//!
//! ```text
//! NETSCAPE_SPKAC ::= SEQUENCE { pubkey X509_PUBKEY, challenge IA5String }
//! NETSCAPE_SPKI  ::= SEQUENCE { spkac NETSCAPE_SPKAC, sig_algor X509_ALGOR,
//!                               signature BIT STRING }
//! ```
//!
//! **Both items and their whole lifecycle land**, because this subphase also lands the
//! `x509spki.c` functions and the two `x_all.c` faces that name them (`NETSCAPE_SPKI_verify`,
//! `NETSCAPE_SPKI_sign`), so the object is the closure they reach. `crypto/asn1/x_spki.c` raises
//! nothing, so it is deliberately **not** listed in `gen_err_raise_sites.py`'s covered set.
//!
//! ## The layouts
//!
//! `struct Netscape_spkac_st` and `struct Netscape_spki_st` are public
//! (`include/openssl/x509.h:429-438`). `NETSCAPE_SPKAC` is two pointers; `NETSCAPE_SPKI` is a
//! `NETSCAPE_SPKAC *`, an **embedded** `X509_ALGOR` (16 bytes) and an `ASN1_BIT_STRING *`. The
//! embedded algorithm begins at offset 8 and the bit-string pointer at offset 24.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BIT_STRING_it, ASN1_IA5STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_it};

/// `struct Netscape_spkac_st` — `NETSCAPE_SPKAC`, from `include/openssl/x509.h:429-432`.
#[repr(C)]
pub struct NetScapeSpkac {
    /// `X509_PUBKEY *pubkey` — the public key the challenge is bound to.
    pub(crate) pubkey: *mut X509Pubkey,
    /// `ASN1_IA5STRING *challenge` — the challenge string.
    pub(crate) challenge: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<NetScapeSpkac>() == 16);
    assert!(core::mem::offset_of!(NetScapeSpkac, pubkey) == 0);
    assert!(core::mem::offset_of!(NetScapeSpkac, challenge) == 8);
};

/// `struct Netscape_spki_st` — `NETSCAPE_SPKI`, from `include/openssl/x509.h:434-438`.
#[repr(C)]
pub struct NetScapeSpki {
    /// `NETSCAPE_SPKAC *spkac` — the signed public key and challenge, optional by pointer.
    pub(crate) spkac: *mut NetScapeSpkac,
    /// `X509_ALGOR sig_algor` — the signature algorithm, embedded (`ASN1_EMBED`).
    pub(crate) sig_algor: X509Algor,
    /// `ASN1_BIT_STRING *signature` — the signature bits.
    pub(crate) signature: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<NetScapeSpki>() == 32);
    assert!(core::mem::offset_of!(NetScapeSpki, spkac) == 0);
    assert!(core::mem::offset_of!(NetScapeSpki, sig_algor) == 8);
    assert!(core::mem::offset_of!(NetScapeSpki, signature) == 24);
};

/// `NETSCAPE_SPKAC_seq_tt` — `crypto/asn1/x_spki.c:15-18`'s `ASN1_SEQUENCE(NETSCAPE_SPKAC)`:
/// `ASN1_SIMPLE(pubkey, X509_PUBKEY)` and `ASN1_SIMPLE(challenge, ASN1_IA5STRING)`.
static NETSCAPE_SPKAC_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"pubkey".as_ptr(),
        item: X509_PUBKEY_it as *mut core::ffi::c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"challenge".as_ptr(),
        item: ASN1_IA5STRING_it as *mut core::ffi::c_void,
    },
];

/// `NETSCAPE_SPKAC_it`'s descriptor — `ASN1_SEQUENCE_END(NETSCAPE_SPKAC)` at
/// `crypto/asn1/x_spki.c:18`.
static NETSCAPE_SPKAC_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: NETSCAPE_SPKAC_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<NetScapeSpkac>() as c_long,
    sname: c"NETSCAPE_SPKAC".as_ptr(),
};

/// `const ASN1_ITEM *NETSCAPE_SPKAC_it(void)` — `include/openssl/x509.h:811`, from
/// `ASN1_SEQUENCE_END(NETSCAPE_SPKAC)`.
#[no_mangle]
pub extern "C" fn NETSCAPE_SPKAC_it() -> *const Asn1Item {
    &NETSCAPE_SPKAC_ITEM
}

/// `NETSCAPE_SPKI_seq_tt` — `crypto/asn1/x_spki.c:22-26`'s `ASN1_SEQUENCE(NETSCAPE_SPKI)`:
/// `ASN1_SIMPLE(spkac, NETSCAPE_SPKAC)`, `ASN1_EMBED(sig_algor, X509_ALGOR)` and
/// `ASN1_SIMPLE(signature, ASN1_BIT_STRING)`.
static NETSCAPE_SPKI_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"spkac".as_ptr(),
        item: NETSCAPE_SPKAC_it as *mut core::ffi::c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 8,
        field_name: c"sig_algor".as_ptr(),
        item: X509_ALGOR_it as *mut core::ffi::c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"signature".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut core::ffi::c_void,
    },
];

/// `NETSCAPE_SPKI_it`'s descriptor — `ASN1_SEQUENCE_END(NETSCAPE_SPKI)` at
/// `crypto/asn1/x_spki.c:26`.
static NETSCAPE_SPKI_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: NETSCAPE_SPKI_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<NetScapeSpki>() as c_long,
    sname: c"NETSCAPE_SPKI".as_ptr(),
};

/// `const ASN1_ITEM *NETSCAPE_SPKI_it(void)` — `include/openssl/x509.h:810`, from
/// `ASN1_SEQUENCE_END(NETSCAPE_SPKI)`.
#[no_mangle]
pub extern "C" fn NETSCAPE_SPKI_it() -> *const Asn1Item {
    &NETSCAPE_SPKI_ITEM
}

/// `NETSCAPE_SPKAC *NETSCAPE_SPKAC_new(void)` — `crypto/asn1/x_spki.c:20`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(NETSCAPE_SPKAC)`.
#[no_mangle]
pub extern "C" fn NETSCAPE_SPKAC_new() -> *mut NetScapeSpkac {
    // SAFETY: `NETSCAPE_SPKAC_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(NETSCAPE_SPKAC_it()).cast::<NetScapeSpkac>() }
}

/// `void NETSCAPE_SPKAC_free(NETSCAPE_SPKAC *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn NETSCAPE_SPKAC_free(a: *mut NetScapeSpkac) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), NETSCAPE_SPKAC_it()) }
}

/// `NETSCAPE_SPKAC *d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC **a, const unsigned char **in, long len)`
/// — the macro's generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_NETSCAPE_SPKAC(
    a: *mut *mut NetScapeSpkac,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut NetScapeSpkac {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, NETSCAPE_SPKAC_it()).cast::<NetScapeSpkac>() }
}

/// `int i2d_NETSCAPE_SPKAC(const NETSCAPE_SPKAC *a, unsigned char **out)` — the macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_NETSCAPE_SPKAC(
    a: *const NetScapeSpkac,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, NETSCAPE_SPKAC_it()) }
}

/// `NETSCAPE_SPKI *NETSCAPE_SPKI_new(void)` — `crypto/asn1/x_spki.c:28`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(NETSCAPE_SPKI)`.
#[no_mangle]
pub extern "C" fn NETSCAPE_SPKI_new() -> *mut NetScapeSpki {
    // SAFETY: `NETSCAPE_SPKI_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(NETSCAPE_SPKI_it()).cast::<NetScapeSpki>() }
}

/// `void NETSCAPE_SPKI_free(NETSCAPE_SPKI *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn NETSCAPE_SPKI_free(a: *mut NetScapeSpki) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), NETSCAPE_SPKI_it()) }
}

/// `NETSCAPE_SPKI *d2i_NETSCAPE_SPKI(NETSCAPE_SPKI **a, const unsigned char **in, long len)` —
/// the macro's generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_NETSCAPE_SPKI(
    a: *mut *mut NetScapeSpki,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut NetScapeSpki {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, NETSCAPE_SPKI_it()).cast::<NetScapeSpki>() }
}

/// `int i2d_NETSCAPE_SPKI(const NETSCAPE_SPKI *a, unsigned char **out)` — the macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_NETSCAPE_SPKI(
    a: *const NetScapeSpki,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, NETSCAPE_SPKI_it()) }
}
