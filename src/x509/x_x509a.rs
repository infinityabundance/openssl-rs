//! `crypto/x509/x_x509a.c` — the `X509_CERT_AUX` item and the trust/alias surface. Phase 10.12.
//!
//! `crypto/x509/x_x509a.c` is 174 lines and **lands whole**. It is the suffix a certificate
//! carries when it is written by the `*_X509_AUX` routines: a `SEQUENCE` of trust objects, a
//! `[0]`-tagged `SEQUENCE` of reject objects, an optional `UTF8String` alias, an optional
//! `OCTET STRING` key id and a `[1]`-tagged `SEQUENCE` of `X509_ALGOR` "other" entries
//! (`:26-32`). The authority's own comment says why it is separate from `X509` itself: the extra
//! data is appended to the encoding when the `*_X509_AUX` routines are used, so the traditional
//! routines simply ignore it (`:17-22`).
//!
//! **The item and its generated lifecycle land** (`ASN1_SEQUENCE`, `:26-34`): `X509_CERT_AUX_it`
//! and the `_new`/`_free`/`d2i_`/`i2d_` group `IMPLEMENT_ASN1_FUNCTIONS` emits. **The hand-written
//! surface lands** (`:36-174`): `X509_trusted`, the file-local `aux_get`, the alias and key-id
//! setters and their two `get0` readers, the trust/reject adders, clearers and readers. Nothing in
//! the unit is withheld: every callee (`ASN1_OCTET_STRING_new`/`_free`, `ASN1_UTF8STRING_new`/
//! `_free`, `ASN1_STRING_set`, `OBJ_dup`, `ASN1_OBJECT_free`, the `OPENSSL_sk_*` stack) is landed.
//!
//! ## Why this unit is the subphase's first landing
//!
//! `X509_alias_get0` and `X509_keyid_get0` are two of the names D447 measured as blocking
//! `PKCS12_create`/`PKCS12_add_cert`, and `d2i_X509_AUX` — the `crypto/x509/x_x509.c` half this
//! module unblocks — is on `store_result.c`'s path. Landing the item here lets
//! `d2i_X509_AUX`/`i2d_X509_AUX` be transcribed in `x_x509.rs` rather than withheld.
//!
//! ## The layout
//!
//! `struct x509_cert_aux_st` is declared in `crypto/x509.h`. Five pointers, so the offsets are
//! 0, 8, 16, 24 and 32 and the size is 40; `courts/layout/measure-x509.c` is where those numbers
//! come from.
//!
//! ## No raise, and the court
//!
//! `crypto/x509/x_x509a.c` raises nothing, so it is deliberately **not** an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`. Its evidence is `RT-STORE`'s 10.12 arms: a
//! certificate serialised with `i2d_X509_AUX` re-decodes with `d2i_X509_AUX` to the same bytes,
//! the alias/key-id setters are read back through their accessors, and the item round-trips
//! `X509_CERT_AUX` byte for byte.
//!
//! SPDX-License-Identifier: Apache-2.0

// The structure carries the authority's own member names so a reader can line them up with
// `crypto/x509.h` without a translation table.
#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_UTF8STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::{
    ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_STRING_set, ASN1_UTF8STRING_free,
    ASN1_UTF8STRING_new,
};
use crate::asn1::x_algor::X509_ALGOR_it;
use crate::runtime::obj::{Asn1Object, OBJ_dup};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_pop_free, OPENSSL_sk_push, OpenSslStack,
};
use crate::x509::x_x509::X509;

/// `struct x509_cert_aux_st` — `X509_CERT_AUX`, from `crypto/x509.h`.
///
/// ```text
/// struct x509_cert_aux_st {
///     STACK_OF(ASN1_OBJECT) *trust;   /* trusted uses */
///     STACK_OF(ASN1_OBJECT) *reject;  /* rejected uses */
///     ASN1_UTF8STRING *alias;         /* "friendly name" */
///     ASN1_OCTET_STRING *keyid;       /* key id of private key */
///     STACK_OF(X509_ALGOR) *other;    /* other unspecified info */
/// };
/// ```
#[repr(C)]
pub struct X509CertAux {
    /// `STACK_OF(ASN1_OBJECT) *trust` — the `SEQUENCE OF` trust OIDs.
    pub(crate) trust: *mut OpenSslStack,
    /// `STACK_OF(ASN1_OBJECT) *reject` — the `[0]`-tagged reject OIDs.
    pub(crate) reject: *mut OpenSslStack,
    /// `ASN1_UTF8STRING *alias` — the friendly name, or null.
    pub(crate) alias: *mut Asn1String,
    /// `ASN1_OCTET_STRING *keyid` — the private key id, or null.
    pub(crate) keyid: *mut Asn1String,
    /// `STACK_OF(X509_ALGOR) *other` — the `[1]`-tagged other info.
    pub(crate) other: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<X509CertAux>() == 40);
    assert!(core::mem::offset_of!(X509CertAux, trust) == 0);
    assert!(core::mem::offset_of!(X509CertAux, reject) == 8);
    assert!(core::mem::offset_of!(X509CertAux, alias) == 16);
    assert!(core::mem::offset_of!(X509CertAux, keyid) == 24);
    assert!(core::mem::offset_of!(X509CertAux, other) == 32);
};

// ---------------------------------------------------------------------------------------------
// The `X509_CERT_AUX` item — `ASN1_SEQUENCE(X509_CERT_AUX)` (`:26-34`)
// ---------------------------------------------------------------------------------------------

/// `X509_CERT_AUX_seq_tt` — `ASN1_SEQUENCE(X509_CERT_AUX)` (`crypto/x509/x_x509a.c:26-32`):
/// `ASN1_SEQUENCE_OF_OPT(trust)`, `ASN1_IMP_SEQUENCE_OF_OPT(reject, 0)`,
/// `ASN1_OPT(alias)`, `ASN1_OPT(keyid)` and `ASN1_IMP_SEQUENCE_OF_OPT(other, 1)`.
static X509_CERT_AUX_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"trust".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"reject".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"alias".as_ptr(),
        item: ASN1_UTF8STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"keyid".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 32,
        field_name: c"other".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
];

/// `X509_CERT_AUX_it`'s descriptor — `ASN1_SEQUENCE_END(X509_CERT_AUX)` at
/// `crypto/x509/x_x509a.c:32`.
static X509_CERT_AUX_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_CERT_AUX_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509CertAux>() as c_long,
    sname: c"X509_CERT_AUX".as_ptr(),
};

/// `const ASN1_ITEM *X509_CERT_AUX_it(void)` — `include/crypto/x509.h`, from
/// `ASN1_SEQUENCE_END(X509_CERT_AUX)`.
#[no_mangle]
pub extern "C" fn X509_CERT_AUX_it() -> *const Asn1Item {
    &X509_CERT_AUX_ITEM
}

/// `X509_CERT_AUX *X509_CERT_AUX_new(void)` — `crypto/x509/x_x509a.c:34`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_CERT_AUX)`.
#[no_mangle]
pub extern "C" fn X509_CERT_AUX_new() -> *mut X509CertAux {
    // SAFETY: `X509_CERT_AUX_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_CERT_AUX_it()).cast::<X509CertAux>() }
}

/// `void X509_CERT_AUX_free(X509_CERT_AUX *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_CERT_AUX_free(a: *mut X509CertAux) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_CERT_AUX_it()) }
}

/// `X509_CERT_AUX *d2i_X509_CERT_AUX(X509_CERT_AUX **a, const unsigned char **in, long len)` —
/// the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_CERT_AUX(
    a: *mut *mut X509CertAux,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509CertAux {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_CERT_AUX_it()).cast::<X509CertAux>() }
}

/// `int i2d_X509_CERT_AUX(const X509_CERT_AUX *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_CERT_AUX(a: *const X509CertAux, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_CERT_AUX_it()) }
}

// ---------------------------------------------------------------------------------------------
// The trust/alias surface — `crypto/x509/x_x509a.c:36-174`
// ---------------------------------------------------------------------------------------------

/// The element thunk `sk_ASN1_OBJECT_pop_free` passes to `OPENSSL_sk_pop_free` — the authority
/// spells it `ASN1_OBJECT_free` (`:149`, `:157`).
///
/// # Safety
///
/// `elem` must be NULL or an `ASN1_OBJECT` this crate allocated.
unsafe extern "C" fn free_object(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or an `ASN1_OBJECT`, and `ASN1_OBJECT_free` accepts NULL.
    unsafe { ASN1_OBJECT_free(elem.cast::<Asn1Object>()) };
}

/// `static X509_CERT_AUX *aux_get(X509 *x)` — `crypto/x509/x_x509a.c:41-48`.
///
/// # Safety
///
/// `x` is NULL or a live `X509`.
unsafe fn aux_get(x: *mut X509) -> *mut X509CertAux {
    if x.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `x` is live per the contract, and `aux` is its own field.
    unsafe {
        if (*x).aux.is_null() {
            (*x).aux = X509_CERT_AUX_new().cast::<c_void>();
            if (*x).aux.is_null() {
                return ptr::null_mut();
            }
        }
        (*x).aux.cast::<X509CertAux>()
    }
}

/// `int X509_trusted(const X509 *x)` — `crypto/x509/x_x509a.c:36-39`.
///
/// # Safety
///
/// `x` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_trusted(x: *const X509) -> c_int {
    // SAFETY: `x` is live and `aux` is its own field.
    unsafe {
        if (*x).aux.is_null() {
            0
        } else {
            1
        }
    }
}

/// `int X509_alias_set1(X509 *x, const unsigned char *name, int len)` —
/// `crypto/x509/x_x509a.c:50-65`.
///
/// A NULL `name` clears the alias and succeeds; a non-NULL one goes through [`aux_get`]. The
/// authority frees the old alias only in the clear branch, and here the setter's own field write
/// is the same.
///
/// # Safety
///
/// `x` is NULL or live; `name` is NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn X509_alias_set1(x: *mut X509, name: *const c_uchar, len: c_int) -> c_int {
    if name.is_null() {
        // SAFETY: `x` is null or live per the contract; `aux`/`alias` are its own fields.
        unsafe {
            if x.is_null() || (*x).aux.is_null() {
                return 1;
            }
            let aux = (*x).aux.cast::<X509CertAux>();
            if (*aux).alias.is_null() {
                return 1;
            }
            ASN1_UTF8STRING_free((*aux).alias);
            (*aux).alias = ptr::null_mut();
        }
        return 1;
    }
    // SAFETY: `x` is null or live per the contract.
    let aux = unsafe { aux_get(x) };
    if aux.is_null() {
        return 0;
    }
    // SAFETY: `aux` is live; `alias` is its own field.
    unsafe {
        if (*aux).alias.is_null() {
            (*aux).alias = ASN1_UTF8STRING_new();
            if (*aux).alias.is_null() {
                return 0;
            }
        }
        ASN1_STRING_set((*aux).alias, name.cast::<c_void>(), len)
    }
}

/// `int X509_keyid_set1(X509 *x, const unsigned char *id, int len)` —
/// `crypto/x509/x_x509a.c:67-83`.
///
/// # Safety
///
/// `x` is NULL or live; `id` is NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn X509_keyid_set1(x: *mut X509, id: *const c_uchar, len: c_int) -> c_int {
    if id.is_null() {
        // SAFETY: `x` is null or live per the contract; `aux`/`keyid` are its own fields.
        unsafe {
            if x.is_null() || (*x).aux.is_null() {
                return 1;
            }
            let aux = (*x).aux.cast::<X509CertAux>();
            if (*aux).keyid.is_null() {
                return 1;
            }
            ASN1_OCTET_STRING_free((*aux).keyid);
            (*aux).keyid = ptr::null_mut();
        }
        return 1;
    }
    // SAFETY: `x` is null or live per the contract.
    let aux = unsafe { aux_get(x) };
    if aux.is_null() {
        return 0;
    }
    // SAFETY: `aux` is live; `keyid` is its own field.
    unsafe {
        if (*aux).keyid.is_null() {
            (*aux).keyid = ASN1_OCTET_STRING_new();
            if (*aux).keyid.is_null() {
                return 0;
            }
        }
        ASN1_STRING_set((*aux).keyid, id.cast::<c_void>(), len)
    }
}

/// `unsigned char *X509_alias_get0(X509 *x, int *len)` — `crypto/x509/x_x509a.c:85-92`.
///
/// # Safety
///
/// `x` is live; `len` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_alias_get0(x: *mut X509, len: *mut c_int) -> *mut c_uchar {
    // SAFETY: `x` is live and `aux`/`alias` are its own fields.
    unsafe {
        if (*x).aux.is_null() {
            return ptr::null_mut();
        }
        let aux = (*x).aux.cast::<X509CertAux>();
        if (*aux).alias.is_null() {
            return ptr::null_mut();
        }
        if !len.is_null() {
            *len = (*(*aux).alias).length;
        }
        (*(*aux).alias).data
    }
}

/// `unsigned char *X509_keyid_get0(X509 *x, int *len)` — `crypto/x509/x_x509a.c:94-101`.
///
/// # Safety
///
/// `x` is live; `len` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_keyid_get0(x: *mut X509, len: *mut c_int) -> *mut c_uchar {
    // SAFETY: `x` is live and `aux`/`keyid` are its own fields.
    unsafe {
        if (*x).aux.is_null() {
            return ptr::null_mut();
        }
        let aux = (*x).aux.cast::<X509CertAux>();
        if (*aux).keyid.is_null() {
            return ptr::null_mut();
        }
        if !len.is_null() {
            *len = (*(*aux).keyid).length;
        }
        (*(*aux).keyid).data
    }
}

/// `int X509_add1_trust_object(X509 *x, const ASN1_OBJECT *obj)` —
/// `crypto/x509/x_x509a.c:103-122`.
///
/// # Safety
///
/// `x` is NULL or live; `obj` is NULL or a live `ASN1_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn X509_add1_trust_object(x: *mut X509, obj: *const Asn1Object) -> c_int {
    let mut objtmp: *mut Asn1Object = ptr::null_mut();
    if !obj.is_null() {
        // SAFETY: `obj` is live per the contract; `OBJ_dup` answers a fresh object or NULL.
        objtmp = unsafe { OBJ_dup(obj) };
        if objtmp.is_null() {
            return 0;
        }
    }
    // SAFETY: `x` is null or live per the contract.
    let aux = unsafe { aux_get(x) };
    if aux.is_null() {
        // SAFETY: `objtmp` is null or a fresh object this call owns.
        return unsafe { trust_reject_err(objtmp) };
    }
    // SAFETY: `aux` is live; `trust` is its own field.
    unsafe {
        if (*aux).trust.is_null() {
            (*aux).trust = OPENSSL_sk_new_null();
            if (*aux).trust.is_null() {
                return trust_reject_err(objtmp);
            }
        }
        if objtmp.is_null() || OPENSSL_sk_push((*aux).trust, objtmp.cast::<c_void>()) != 0 {
            return 1;
        }
        trust_reject_err(objtmp)
    }
}

/// `int X509_add1_reject_object(X509 *x, const ASN1_OBJECT *obj)` —
/// `crypto/x509/x_x509a.c:124-144`.
///
/// # Safety
///
/// `x` is NULL or live; `obj` is NULL or a live `ASN1_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn X509_add1_reject_object(x: *mut X509, obj: *const Asn1Object) -> c_int {
    // SAFETY: `obj` is null or live per the contract; `OBJ_dup` answers a fresh object or NULL.
    let objtmp = unsafe { OBJ_dup(obj) };
    if objtmp.is_null() {
        return 0;
    }
    // SAFETY: `x` is null or live per the contract.
    let aux = unsafe { aux_get(x) };
    if aux.is_null() {
        // SAFETY: `objtmp` is a fresh object this call owns.
        return unsafe { trust_reject_err(objtmp) };
    }
    // SAFETY: `aux` is live; `reject` is its own field.
    unsafe {
        if (*aux).reject.is_null() {
            (*aux).reject = OPENSSL_sk_new_null();
            if (*aux).reject.is_null() {
                return trust_reject_err(objtmp);
            }
        }
        if OPENSSL_sk_push((*aux).reject, objtmp.cast::<c_void>()) > 0 {
            return 1;
        }
        trust_reject_err(objtmp)
    }
}

/// The shared `err:` label of the two adders — free the duplicate and answer 0.
///
/// # Safety
///
/// `objtmp` is NULL or a fresh object this call owns.
unsafe fn trust_reject_err(objtmp: *mut Asn1Object) -> c_int {
    // SAFETY: `objtmp` is null or owned per the contract.
    unsafe { ASN1_OBJECT_free(objtmp) };
    0
}

/// `void X509_trust_clear(X509 *x)` — `crypto/x509/x_x509a.c:146-152`.
///
/// # Safety
///
/// `x` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_trust_clear(x: *mut X509) {
    // SAFETY: `x` is live and `aux`/`trust` are its own fields.
    unsafe {
        if !(*x).aux.is_null() {
            let aux = (*x).aux.cast::<X509CertAux>();
            OPENSSL_sk_pop_free((*aux).trust, Some(free_object));
            (*aux).trust = ptr::null_mut();
        }
    }
}

/// `void X509_reject_clear(X509 *x)` — `crypto/x509/x_x509a.c:154-160`.
///
/// # Safety
///
/// `x` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_reject_clear(x: *mut X509) {
    // SAFETY: `x` is live and `aux`/`reject` are its own fields.
    unsafe {
        if !(*x).aux.is_null() {
            let aux = (*x).aux.cast::<X509CertAux>();
            OPENSSL_sk_pop_free((*aux).reject, Some(free_object));
            (*aux).reject = ptr::null_mut();
        }
    }
}

/// `STACK_OF(ASN1_OBJECT) *X509_get0_trust_objects(X509 *x)` —
/// `crypto/x509/x_x509a.c:162-167`.
///
/// # Safety
///
/// `x` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_get0_trust_objects(x: *mut X509) -> *mut OpenSslStack {
    // SAFETY: `x` is live and `aux`/`trust` are its own fields.
    unsafe {
        if (*x).aux.is_null() {
            return ptr::null_mut();
        }
        (*(*x).aux.cast::<X509CertAux>()).trust
    }
}

/// `STACK_OF(ASN1_OBJECT) *X509_get0_reject_objects(X509 *x)` —
/// `crypto/x509/x_x509a.c:169-174`.
///
/// # Safety
///
/// `x` is live.
#[no_mangle]
pub unsafe extern "C" fn X509_get0_reject_objects(x: *mut X509) -> *mut OpenSslStack {
    // SAFETY: `x` is live and `aux`/`reject` are its own fields.
    unsafe {
        if (*x).aux.is_null() {
            return ptr::null_mut();
        }
        (*(*x).aux.cast::<X509CertAux>()).reject
    }
}
