//! `crypto/x509/v3_akeya.c` — the `AUTHORITY_KEYID` item group. Phase 10.14's blocked-unit pivots,
//! landed whole.
//!
//! `crypto/x509/v3_akeya.c` is 23 lines and transcribes whole:
//!
//! * `AUTHORITY_KEYID ::= SEQUENCE { keyid [0] IMPLICIT OCTET STRING OPTIONAL, issuer [1] IMPLICIT
//!   SEQUENCE OF GENERAL_NAME OPTIONAL, serial [2] IMPLICIT INTEGER OPTIONAL }` (`:17-21`) lands,
//!   with the `_it`/`_new`/`_free`/`d2i_`/`i2d_` group `IMPLEMENT_ASN1_FUNCTIONS(AUTHORITY_KEYID)`
//!   (`:23`) emits. The struct is `struct AUTHORITY_KEYID_st`
//!   (`include/openssl/x509v3.h:369-373`); the header declares no `d2i_`/`i2d_`-only half beyond
//!   `DECLARE_ASN1_FUNCTIONS` (`include/openssl/x509v3.h:821`).
//!
//! `IMPLEMENT_ASN1_FUNCTIONS` expands to `IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname` plus
//! `IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname` (`include/openssl/asn1t.h:808-810`), and
//! `DECLARE_ASN1_FUNCTIONS` expands to `DECLARE_ASN1_ALLOC_FUNCTIONS` plus
//! `DECLARE_ASN1_ENCODE_FUNCTIONS` (`include/openssl/asn1.h:304-309`): the pair emits `_it`,
//! `_new`, `_free`, `d2i_` and `i2d_` and **no `_dup`**. There is therefore no `AUTHORITY_KEYID_dup`
//! to land: the macro pair does not produce one, the header does not declare one, and the admitted
//! DSO's ABI surface (`artifacts/phase2/libcrypto.ld`, `.frf/objects/sha256/...`) lists only
//! `AUTHORITY_KEYID_free`/`_it`/`_new`/`d2i_AUTHORITY_KEYID`/`i2d_AUTHORITY_KEYID`.
//!
//! This unit's surface is a **blocker** for `crypto/x509/v3_akid.c`, whose `ossl_v3_akey_id` row
//! names `ASN1_ITEM_ref(AUTHORITY_KEYID)` (`crypto/x509/v3_akid.c:29`) and whose
//! `v2i_AUTHORITY_KEYID` calls `AUTHORITY_KEYID_new` (`:111`) and `AUTHORITY_KEYID_free` (`:235`).
//! The `AUTHORITY_KEYID` **row** is that other unit's; this module lands only the item group the
//! authority declares here.
//!
//! **Withheld by name**: `standard_exts[]` (`crypto/x509/standard_exts.h:15-95`) and the six lookup
//! names in `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/
//! `_add1_i2d`). A partial array would silently change `OBJ_bsearch_ext` for every missing NID
//! (D456). The `AUTHORITY_KEYID` NID is `90` (`obj_mac.h:2765`) and its row is `v3_akid.c`'s, so
//! this unit contributes no row of its own to the array. Nothing else is withheld: the item group
//! is the whole of the file.
//!
//! ## No raise
//!
//! The unit raises nothing (it is the `ASN1_SEQUENCE` macro and `IMPLEMENT_ASN1_FUNCTIONS` only),
//! so `crypto/x509/v3_akeya.c` is deliberately not an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`. Its raise set is empty and no `ErrSite` is declared.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_INTEGER_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::stack::OpenSslStack;
use crate::x509::v3_genn::GENERAL_NAME_it;

/// `struct AUTHORITY_KEYID_st` — `AUTHORITY_KEYID`, from `include/openssl/x509v3.h:369-373`.
///
/// The authority's three fields in order: the key identifier, the issuer's
/// `GENERAL_NAMES` and the issuer's serial number.
#[repr(C)]
pub struct AuthorityKeyid {
    /// `ASN1_OCTET_STRING *keyid` — `[0]` implicit, optional.
    pub keyid: *mut Asn1String,
    /// `GENERAL_NAMES *issuer` — `[1]` implicit `SEQUENCE OF GENERAL_NAME`, optional.
    pub issuer: *mut OpenSslStack,
    /// `ASN1_INTEGER *serial` — `[2]` implicit, optional.
    pub serial: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<AuthorityKeyid>() == 24);
    assert!(core::mem::offset_of!(AuthorityKeyid, keyid) == 0);
    assert!(core::mem::offset_of!(AuthorityKeyid, issuer) == 8);
    assert!(core::mem::offset_of!(AuthorityKeyid, serial) == 16);
};

/// `AUTHORITY_KEYID_seq_tt` — `ASN1_SEQUENCE(AUTHORITY_KEYID)` (`crypto/x509/v3_akeya.c:17-21`):
/// `ASN1_IMP_OPT(AUTHORITY_KEYID, keyid, ASN1_OCTET_STRING, 0)`,
/// `ASN1_IMP_SEQUENCE_OF_OPT(AUTHORITY_KEYID, issuer, GENERAL_NAME, 1)` and
/// `ASN1_IMP_OPT(AUTHORITY_KEYID, serial, ASN1_INTEGER, 2)`. Each is implicit-tagged and optional.
static AUTHORITY_KEYID_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"keyid".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_SEQUENCE_OF,
        tag: 1,
        offset: 8,
        field_name: c"issuer".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"serial".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `AUTHORITY_KEYID_it`'s descriptor — `ASN1_SEQUENCE_END(AUTHORITY_KEYID)` at
/// `crypto/x509/v3_akeya.c:21`.
static AUTHORITY_KEYID_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: AUTHORITY_KEYID_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<AuthorityKeyid>() as c_long,
    sname: c"AUTHORITY_KEYID".as_ptr(),
};

/// `const ASN1_ITEM *AUTHORITY_KEYID_it(void)` — `include/openssl/x509v3.h:821`, from
/// `ASN1_SEQUENCE_END(AUTHORITY_KEYID)`.
#[no_mangle]
pub extern "C" fn AUTHORITY_KEYID_it() -> *const Asn1Item {
    &AUTHORITY_KEYID_ITEM
}

/// `AUTHORITY_KEYID *AUTHORITY_KEYID_new(void)` — `crypto/x509/v3_akeya.c:23`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(AUTHORITY_KEYID)`'s allocator half.
#[no_mangle]
pub extern "C" fn AUTHORITY_KEYID_new() -> *mut AuthorityKeyid {
    // SAFETY: `AUTHORITY_KEYID_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(AUTHORITY_KEYID_it()).cast::<AuthorityKeyid>() }
}

/// `void AUTHORITY_KEYID_free(AUTHORITY_KEYID *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn AUTHORITY_KEYID_free(a: *mut AuthorityKeyid) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), AUTHORITY_KEYID_it()) }
}

/// `AUTHORITY_KEYID *d2i_AUTHORITY_KEYID(AUTHORITY_KEYID **a, const unsigned char **in, long len)` —
/// the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_AUTHORITY_KEYID(
    a: *mut *mut AuthorityKeyid,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut AuthorityKeyid {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, AUTHORITY_KEYID_it()).cast::<AuthorityKeyid>() }
}

/// `int i2d_AUTHORITY_KEYID(const AUTHORITY_KEYID *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_AUTHORITY_KEYID(
    a: *const AuthorityKeyid,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, AUTHORITY_KEYID_it()) }
}
