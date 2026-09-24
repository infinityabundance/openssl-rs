//! `crypto/asn1/p8_pkey.c`'s setter/getter pair and item — `PKCS8_pkey_set0`, `PKCS8_pkey_get0`,
//! the `PKCS8_PRIV_KEY_INFO` item group and `PKCS8_pkey_get0_attrs`. Phase 8.8 (D349), completed
//! by D368.
//!
//! ## The item half, and the cycle D349 measured (landed here)
//!
//! `ASN1_SEQUENCE_cb(PKCS8_PRIV_KEY_INFO, pkey_cb)` (`:43-49`) names `X509_ATTRIBUTE_it` for its
//! `attributes` column, and D349 withheld the whole item group because `crypto/x509/x_attrib.c`
//! had no crate module. D368 lands `src/x509/x_attrib.rs`, so the template, its `pkey_cb`
//! (`ASN1_OP_FREE_PRE`'s cleanse and `ASN1_OP_D2I_POST`'s version check) and the five
//! `IMPLEMENT_ASN1_FUNCTIONS` names are here: [`PKCS8_PRIV_KEY_INFO_it`], `_new`, `_free`,
//! `d2i_PKCS8_PRIV_KEY_INFO` and `i2d_PKCS8_PRIV_KEY_INFO`.
//!
//! ## What is withheld, with its coordinate
//!
//! Nothing. The three `PKCS8_pkey_add1_attr` spellings (`:92-109`) were withheld by D349 as
//! one call each to `X509at_add1_attr_by_NID`/`_by_OBJ`/`X509at_add1_attr`
//! (`crypto/x509/x509_att.c:118`, `:151`, `:187`); D368 lands `crypto/x509/x509_att.c` as
//! [`crate::x509::x509_att`], so they land here and the unit is whole (11 of 11 exports).
//! `PKCS8_pkey_get0_attrs` (`:86-90`) is the `attributes` reader and needs nothing but the
//! struct.
//!
//! The unit defines no internal symbol at all — its only file-local function is the `static
//! pkey_cb` — so this module needs **no** divergence row. That is measured rather than assumed:
//! the prerequisite gate reports nothing for this unit (D349, D368).
//!
//! ## The `Pkcs8PrivKeyInfo` layout
//!
//! `struct pkcs8_priv_key_info_st` is declared in `include/crypto/x509.h:291-297`, an internal
//! header. This module is its canonical definition because `crypto/asn1/p8_pkey.c` is its
//! authority unit. `src/evp/pkey_asn1.rs` re-exports the name for the `priv_decode`/`priv_encode`
//! callback signatures rather than declaring a placeholder (D348's rule). The `attributes` member
//! is `STACK_OF(X509_ATTRIBUTE) *`, projected as `*mut OpenSslStack`.
//!
//! ## The court
//!
//! `crypto/asn1/p8_pkey.c` raises nothing, so it is deliberately **not** in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`. The evidence is the round trip below over a real `PKCS8_PRIV_KEY_INFO` built
//! through its own item, which the five landed constructors now make possible.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_STRING_get0_data, ASN1_STRING_length, ASN1_STRING_set0};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it, X509_ALGOR_set0};
use crate::runtime::mem::OPENSSL_cleanse;
use crate::runtime::obj::Asn1Object;
use crate::runtime::stack::OpenSslStack;
use crate::x509::x509_att::{X509at_add1_attr, X509at_add1_attr_by_NID, X509at_add1_attr_by_OBJ};
use crate::x509::x_attrib::{X509Attribute, X509_ATTRIBUTE_it};

/// `struct pkcs8_priv_key_info_st` — `PKCS8_PRIV_KEY_INFO`, from
/// `include/crypto/x509.h:291-297`.
///
/// The authority's five members in order, which are also the item's five columns
/// (`version`, `pkeyalg`, `pkey`, the optional `attributes` and the optional `kpub`). The
/// two accessors below read `version`, `pkeyalg` and `pkey`; `attributes` and `kpub` are
/// read only by the withheld `PKCS8_pkey_get0_attrs` and the template's `ASN1_IMP_OPT`
/// arms.
#[repr(C)]
pub struct Pkcs8PrivKeyInfo {
    /// `ASN1_INTEGER *version` — 0 for PKCS#8 v1, 1 for v2.
    pub(crate) version: *mut Asn1String,
    /// `X509_ALGOR *pkeyalg` — the private-key algorithm, read by both accessors.
    pub(crate) pkeyalg: *mut X509Algor,
    /// `ASN1_OCTET_STRING *pkey` — the `PrivateKey` octets.
    pub(crate) pkey: *mut Asn1String,
    /// `STACK_OF(X509_ATTRIBUTE) *attributes` — the optional attribute set, read by the
    /// withheld `PKCS8_pkey_get0_attrs`.
    pub(crate) attributes: *mut OpenSslStack,
    /// `ASN1_OCTET_STRING *kpub` — the optional v2 public key, added by the `ASN1_IMP_OPT`
    /// column.
    pub(crate) kpub: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<Pkcs8PrivKeyInfo>() == 40);
    assert!(core::mem::offset_of!(Pkcs8PrivKeyInfo, version) == 0);
    assert!(core::mem::offset_of!(Pkcs8PrivKeyInfo, pkeyalg) == 8);
    assert!(core::mem::offset_of!(Pkcs8PrivKeyInfo, pkey) == 16);
    assert!(core::mem::offset_of!(Pkcs8PrivKeyInfo, attributes) == 24);
    assert!(core::mem::offset_of!(Pkcs8PrivKeyInfo, kpub) == 32);
};

/// `int PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *aobj, int version,
/// int ptype, void *pval, unsigned char *penc, int penclen)` —
/// `crypto/asn1/p8_pkey.c:53-69`.
///
/// Three guards in the authority's order. `version < 0` means "leave the version word
/// alone"; a version above 1 is refused before anything is written, so a v2-only caller
/// gets a clean 0 rather than a half-filled object. The algorithm is set second and its
/// failure is left where it is — `X509_ALGOR_set0` may already have adopted `aobj`. A NULL
/// `penc` keeps the existing octet string, which is why the third step is guarded.
///
/// # Safety
///
/// `priv_` is a live `PKCS8_PRIV_KEY_INFO` with live `version`, `pkeyalg` and `pkey`
/// members; `aobj` and `pval` are values `X509_ALGOR_set0` may adopt; `penc` is NULL or a
/// buffer of `penclen` bytes transferred to the object.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_pkey_set0(
    priv_: *mut Pkcs8PrivKeyInfo,
    aobj: *mut Asn1Object,
    version: c_int,
    ptype: c_int,
    pval: *mut c_void,
    penc: *mut u8,
    penclen: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        if version >= 0 {
            // Only PKCS#8 v1 (0) and v2 (1) exist.
            if version > 1 {
                return 0;
            }
            if ASN1_INTEGER_set((*priv_).version, c_long::from(version)) == 0 {
                return 0;
            }
        }
        if X509_ALGOR_set0((*priv_).pkeyalg, aobj, ptype, pval) == 0 {
            return 0;
        }
        if !penc.is_null() {
            ASN1_STRING_set0((*priv_).pkey, penc.cast::<c_void>(), penclen);
        }
    }
    1
}

/// `int PKCS8_pkey_get0(const ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen,
/// const X509_ALGOR **pa, const PKCS8_PRIV_KEY_INFO *p8)` — `crypto/asn1/p8_pkey.c:71-84`.
///
/// Each of the four out-parameters is optional and independently skipped, and all three
/// answers are borrowed. The octets come back through the `ASN1_STRING` accessors rather
/// than the struct's `data`/`length` fields directly, which is the authority's own spelling
/// here (`X509_PUBKEY_get0_param` reads the fields, this one calls the accessors); both
/// answer the same pair.
///
/// # Safety
///
/// `p8` is a live `PKCS8_PRIV_KEY_INFO` whose `pkeyalg` and `pkey` are live. Each
/// out-pointer is NULL or writable for its type; the answers are borrowed from `p8`.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_pkey_get0(
    ppkalg: *mut *const Asn1Object,
    pk: *mut *const u8,
    ppklen: *mut c_int,
    pa: *mut *const X509Algor,
    p8: *const Pkcs8PrivKeyInfo,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read and write.
    unsafe {
        if !ppkalg.is_null() {
            *ppkalg = (*(*p8).pkeyalg).algorithm;
        }
        if !pk.is_null() {
            *pk = ASN1_STRING_get0_data((*p8).pkey);
            *ppklen = ASN1_STRING_length((*p8).pkey);
        }
        if !pa.is_null() {
            *pa = (*p8).pkeyalg;
        }
    }
    1
}

/// `static int pkey_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)` —
/// `crypto/asn1/p8_pkey.c:17-41`.
///
/// Two operations. `ASN1_OP_FREE_PRE` **cleanses the private-key octets** while the structure is
/// still valid — this is a `PKCS#8` private key, so the bytes are secret and are zeroed before the
/// allocator sees them again. `ASN1_OP_D2I_POST` insists on a valid version *after* the structure
/// is decoded: only v1 (0) and v2 (1) exist, and a v1 structure must not carry the v2 `kpub`.
///
/// # Safety
/// The item layer's own callback contract: `pval` points at a live value for the item this
/// callback belongs to, and `it` is that item.
unsafe extern "C" fn pkey_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    it: *const Asn1Item,
    exarg: *mut c_void,
) -> c_int {
    let _ = (it, exarg);
    match operation {
        ASN1_OP_FREE_PRE => {
            // SAFETY: `pval` points at a live `Pkcs8PrivKeyInfo` for this operation.
            let key = unsafe { (*pval).cast::<Pkcs8PrivKeyInfo>() };
            // SAFETY: `key` is live and its `pkey` is its own octet string.
            unsafe {
                if !(*key).pkey.is_null() {
                    OPENSSL_cleanse(
                        (*key).pkey.cast::<c_void>(),
                        core::mem::size_of::<Asn1String>(),
                    );
                    OPENSSL_cleanse(
                        (*(*key).pkey).data.cast::<c_void>(),
                        (*(*key).pkey).length as usize,
                    );
                }
            }
        }
        ASN1_OP_D2I_POST => {
            // SAFETY: `pval` points at a live `Pkcs8PrivKeyInfo` for this operation.
            let key = unsafe { (*pval).cast::<Pkcs8PrivKeyInfo>() };
            // SAFETY: `key` is live and its `version` and `kpub` are its own.
            let (version, kpub) = unsafe { (ASN1_INTEGER_get((*key).version), (*key).kpub) };
            if !(0..=1).contains(&version) {
                return 0;
            }
            if version == 0 && !kpub.is_null() {
                return 0;
            }
        }
        _ => {}
    }
    1
}

/// The `PKCS8_PRIV_KEY_INFO` item's `ASN1_AUX`. Wrapped for the same reason
/// [`crate::dsa::asn1`] wraps its own: [`Asn1Aux`] holds raw pointers and so is not `Sync` by
/// itself.
#[repr(transparent)]
struct SyncAux(Asn1Aux);

// SAFETY: built from constants (a null `app_data`, integer offsets, a `None` const-callback and
// one function pointer), written once by the loader, and with no interior mutability reachable
// through a shared reference. The machinery reads only `asn1_cb` out of it.
unsafe impl Sync for SyncAux {}

/// `static const ASN1_AUX PKCS8_PRIV_KEY_INFO_aux = { NULL, 0, 0, 0, pkey_cb, 0, NULL }` —
/// `ASN1_SEQUENCE_cb(PKCS8_PRIV_KEY_INFO, pkey_cb)`.
static P8_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(pkey_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `PKCS8_PRIV_KEY_INFO_seq_tt` — `ASN1_SEQUENCE_cb(PKCS8_PRIV_KEY_INFO, pkey_cb)`
/// (`crypto/asn1/p8_pkey.c:43-49`): `ASN1_SIMPLE(version, ASN1_INTEGER)`,
/// `ASN1_SIMPLE(pkeyalg, X509_ALGOR)`, `ASN1_SIMPLE(pkey, ASN1_OCTET_STRING)`,
/// `ASN1_IMP_SET_OF_OPT(attributes, X509_ATTRIBUTE, 0)` and `ASN1_IMP_OPT(kpub, ASN1_BIT_STRING,
/// 1)`.
static P8_SEQ_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"pkeyalg".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"pkey".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"attributes".as_ptr(),
        item: X509_ATTRIBUTE_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 32,
        field_name: c"kpub".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// `PKCS8_PRIV_KEY_INFO_it`'s descriptor — `ASN1_SEQUENCE_END_cb(PKCS8_PRIV_KEY_INFO,
/// PKCS8_PRIV_KEY_INFO)` at `crypto/asn1/p8_pkey.c:49`.
static P8_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: P8_SEQ_TT.as_ptr(),
    tcount: 5,
    funcs: (&P8_AUX.0) as *const Asn1Aux as *const c_void,
    size: core::mem::size_of::<Pkcs8PrivKeyInfo>() as c_long,
    sname: c"PKCS8_PRIV_KEY_INFO".as_ptr(),
};

/// `const ASN1_ITEM *PKCS8_PRIV_KEY_INFO_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END_cb(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO)`.
#[no_mangle]
pub extern "C" fn PKCS8_PRIV_KEY_INFO_it() -> *const Asn1Item {
    &P8_ITEM
}

/// `PKCS8_PRIV_KEY_INFO *PKCS8_PRIV_KEY_INFO_new(void)` — `crypto/asn1/p8_pkey.c:51`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO)`.
#[no_mangle]
pub extern "C" fn PKCS8_PRIV_KEY_INFO_new() -> *mut Pkcs8PrivKeyInfo {
    // SAFETY: `PKCS8_PRIV_KEY_INFO_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS8_PRIV_KEY_INFO_it()).cast::<Pkcs8PrivKeyInfo>() }
}

/// `void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO *a)` — the same macro's free half. The
/// `pkey_cb` `ASN1_OP_FREE_PRE` arm cleanses the octets as part of this release.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_PRIV_KEY_INFO_free(a: *mut Pkcs8PrivKeyInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS8_PRIV_KEY_INFO_it()) }
}

/// `PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO **a,
/// const unsigned char **in, long len)` — `crypto/asn1/p8_pkey.c:51`'s generated decoder.
///
/// The `pkey_cb` `ASN1_OP_D2I_POST` arm refuses a version outside 0..=1 or a v1 structure with a
/// `kpub`, so that refusal is this function's answer too.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS8_PRIV_KEY_INFO(
    a: *mut *mut Pkcs8PrivKeyInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs8PrivKeyInfo {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, PKCS8_PRIV_KEY_INFO_it()).cast::<Pkcs8PrivKeyInfo>()
    }
}

/// `int i2d_PKCS8_PRIV_KEY_INFO(const PKCS8_PRIV_KEY_INFO *a, unsigned char **out)` — the same
/// macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS8_PRIV_KEY_INFO(
    a: *const Pkcs8PrivKeyInfo,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS8_PRIV_KEY_INFO_it()) }
}

/// `const STACK_OF(X509_ATTRIBUTE) *PKCS8_pkey_get0_attrs(const PKCS8_PRIV_KEY_INFO *p8)` —
/// `crypto/asn1/p8_pkey.c:86-90`.
///
/// The `attributes` reader, borrowed rather than copied.
///
/// # Safety
/// `p8` is a live `PKCS8_PRIV_KEY_INFO`; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_pkey_get0_attrs(p8: *const Pkcs8PrivKeyInfo) -> *const OpenSslStack {
    // SAFETY: `p8` is live per the contract.
    unsafe { (*p8).attributes }
}

/// `int PKCS8_pkey_add1_attr_by_NID(PKCS8_PRIV_KEY_INFO *p8, int nid, int type,
/// const unsigned char *bytes, int len)` — `crypto/asn1/p8_pkey.c:92-98`.
///
/// One call to [`X509at_add1_attr_by_NID`], whose answer is the stack rather than a status;
/// the export is the status, so a NULL stack becomes 0.
///
/// # Safety
/// `p8` is a live `PKCS8_PRIV_KEY_INFO`; `bytes` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_pkey_add1_attr_by_NID(
    p8: *mut Pkcs8PrivKeyInfo,
    nid: c_int,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: `p8` is live, so its `attributes` slot is writable; `bytes`/`len` are the caller's.
    let ret = unsafe { X509at_add1_attr_by_NID(&raw mut (*p8).attributes, nid, type_, bytes, len) };
    c_int::from(!ret.is_null())
}

/// `int PKCS8_pkey_add1_attr_by_OBJ(PKCS8_PRIV_KEY_INFO *p8, const ASN1_OBJECT *obj, int type,
/// const unsigned char *bytes, int len)` — `crypto/asn1/p8_pkey.c:100-104`.
///
/// # Safety
/// `p8` is a live `PKCS8_PRIV_KEY_INFO`; `obj` is live; `bytes` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_pkey_add1_attr_by_OBJ(
    p8: *mut Pkcs8PrivKeyInfo,
    obj: *const Asn1Object,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: `p8` is live; `obj` is live; `bytes`/`len` are the caller's.
    let ret = unsafe { X509at_add1_attr_by_OBJ(&raw mut (*p8).attributes, obj, type_, bytes, len) };
    c_int::from(!ret.is_null())
}

/// `int PKCS8_pkey_add1_attr(PKCS8_PRIV_KEY_INFO *p8, X509_ATTRIBUTE *attr)` —
/// `crypto/asn1/p8_pkey.c:106-109`.
///
/// # Safety
/// `p8` is a live `PKCS8_PRIV_KEY_INFO`; `attr` is live and is duplicated before it is stored.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_pkey_add1_attr(
    p8: *mut Pkcs8PrivKeyInfo,
    attr: *mut X509Attribute,
) -> c_int {
    // SAFETY: `p8` is live, so its `attributes` slot is writable; `attr` is live.
    let ret = unsafe { X509at_add1_attr(&raw mut (*p8).attributes, attr) };
    c_int::from(!ret.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::layout::V_ASN1_UNDEF;
    use crate::asn1::prim::ASN1_INTEGER_get;
    use crate::asn1::string::{ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_OCTET_STRING_new};
    use crate::asn1::x_algor::{X509_ALGOR_free, X509_ALGOR_new};
    use crate::runtime::obj::{NID_rsaEncryption, OBJ_nid2obj, OBJ_obj2nid};
    use core::ptr;

    fn blank_p8() -> Pkcs8PrivKeyInfo {
        Pkcs8PrivKeyInfo {
            version: ASN1_INTEGER_new(),
            pkeyalg: X509_ALGOR_new(),
            pkey: ASN1_OCTET_STRING_new(),
            attributes: ptr::null_mut(),
            kpub: ptr::null_mut(),
        }
    }

    unsafe fn free_p8(p8: &mut Pkcs8PrivKeyInfo) {
        // SAFETY: the three members were allocated by the `_new` constructors above.
        unsafe {
            ASN1_INTEGER_free(p8.version);
            X509_ALGOR_free(p8.pkeyalg);
            crate::asn1::string::ASN1_OCTET_STRING_free(p8.pkey);
        }
    }

    /// A v1 encode/decode round trip: version 0, the identifier and the octets come back.
    #[test]
    fn set0_v1_and_get0_agree() {
        let mut p8 = blank_p8();
        let enc = vec![0x30u8, 0x2e, 0x02, 0x01, 0x00];
        let penc = enc.as_ptr() as *mut u8;
        core::mem::forget(enc);

        // SAFETY: the object's three members are live; `penc` is a fresh heap buffer.
        let rc = unsafe {
            PKCS8_pkey_set0(
                &raw mut p8,
                OBJ_nid2obj(NID_rsaEncryption),
                0,
                V_ASN1_UNDEF,
                ptr::null_mut(),
                penc,
                5,
            )
        };
        assert_eq!(rc, 1);
        // SAFETY: the version word was allocated and written.
        unsafe { assert_eq!(ASN1_INTEGER_get(p8.version), 0) };

        let mut o: *const _ = ptr::null();
        let mut pk: *const u8 = ptr::null();
        let mut pklen = -1;
        let mut pa: *const X509Algor = ptr::null();
        // SAFETY: the object is live and every out-pointer is writable.
        let rc =
            unsafe { PKCS8_pkey_get0(&raw mut o, &raw mut pk, &raw mut pklen, &raw mut pa, &p8) };
        assert_eq!(rc, 1);
        // SAFETY: the answers are borrowed from the live object.
        unsafe {
            assert_eq!(OBJ_obj2nid(o), NID_rsaEncryption);
            assert_eq!(pklen, 5);
            assert_eq!(
                core::slice::from_raw_parts(pk, 5),
                &[0x30, 0x2e, 0x02, 0x01, 0x00]
            );
            assert_eq!(pa, p8.pkeyalg);
            free_p8(&mut p8);
        }
    }

    /// A version above 1 is refused before anything is touched.
    #[test]
    fn a_version_above_one_is_refused() {
        let mut p8 = blank_p8();
        // SAFETY: the object's members are live; the call must return before writing.
        let rc = unsafe {
            PKCS8_pkey_set0(
                &raw mut p8,
                OBJ_nid2obj(NID_rsaEncryption),
                2,
                V_ASN1_UNDEF,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: the three members are live and unmodified.
        unsafe { free_p8(&mut p8) };
    }

    /// A negative version leaves the version word alone.
    #[test]
    fn a_negative_version_leaves_the_word_alone() {
        let mut p8 = blank_p8();
        // SAFETY: the object's members are live; `penc` NULL keeps the octet string.
        let rc = unsafe {
            PKCS8_pkey_set0(
                &raw mut p8,
                OBJ_nid2obj(NID_rsaEncryption),
                -1,
                V_ASN1_UNDEF,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, 1);
        // SAFETY: the version member is live and was never written, so it is still the
        // zero-length integer `ASN1_INTEGER_new` produced.
        unsafe {
            assert_eq!((*p8.version).length, 0);
            free_p8(&mut p8);
        }
    }
}
