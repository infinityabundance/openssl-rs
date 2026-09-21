//! `crypto/asn1/p8_pkey.c`'s setter/getter pair — `PKCS8_pkey_set0` and
//! `PKCS8_pkey_get0` — and the `PKCS8_PRIV_KEY_INFO` layout they read. Phase 8.8 (D349).
//!
//! ## A partial unit, and what it withholds
//!
//! `crypto/asn1/p8_pkey.c` is 109 lines and **11 exports**. This module lands **two**
//! (`:53`, `:71`) — the pair every one of the five ASN.1 method objects reaches from its
//! `priv_encode` and `priv_decode` columns (D341's table). The other nine are withheld, and
//! the brief's own account of them is corrected by the measurement:
//!
//! * **Five are `IMPLEMENT_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO)`'s** (`PKCS8_PRIV_KEY_INFO_new`,
//!   `_free`, `_it`, `d2i_PKCS8_PRIV_KEY_INFO`, `i2d_PKCS8_PRIV_KEY_INFO`). They are
//!   macro-generated, so an identifier scan of the file cannot see them, and they are
//!   **blocked rather than withheld by preference**: the template they come from,
//!   `ASN1_SEQUENCE_cb(PKCS8_PRIV_KEY_INFO, pkey_cb)` (`:43-49`), names
//!   `X509_ATTRIBUTE_it` for its `attributes` field, and `crypto/x509/x_attrib.c` is
//!   Phase 11's and has no crate module. A `static` naming an item function the crate does
//!   not define does not compile, so the template cannot be transcribed on this stratum.
//!   The `pkey_cb` `ASN1_OP_FREE_PRE` cleanse and the `ASN1_OP_D2I_POST` version check go
//!   with it.
//! * **`PKCS8_pkey_get0_attrs`** (`:86-90`) is the `attributes` reader; it belongs with the
//!   `add1_attr` family below and no crate caller reaches it, so it is withheld with them.
//! * **Three are the `PKCS8_pkey_add1_attr*` family** (`:92-109`, the brief's "other
//!   three"). Each is one call to `X509at_add1_attr_by_NID`, `X509at_add1_attr_by_OBJ` or
//!   `X509at_add1_attr` — all three are `crypto/x509/x509_att.c`'s (`:118`, `:151`, `:187`)
//!   and Phase 11's with no crate module, so transcribing them would name three unwired
//!   functions, and the measurement says there is no partial form: each body is exactly
//!   that one call. The brief also names `crypto/x509/x_attrib.c` as reached by these three,
//!   and the measurement corrects that: `x_attrib.c`'s `X509_ATTRIBUTE_it` is reached by the
//!   *template* above, not by the `add1_attr` trio. They are withheld, and the decision is
//!   recorded here rather than left as an omission.
//!
//! The unit defines no internal symbol at all — its only file-local function is the
//! `static pkey_cb`, which is not in the internal-symbol universe — so this module needs
//! **no** divergence row, and `crypto/asn1/p8_pkey.c`'s direction-B set is empty. That is
//! the one place this slice differs from its three siblings, and it is measured rather
//! than assumed: the prerequisite gate reports nothing for this unit (D349).
//!
//! ## The `Pkcs8PrivKeyInfo` layout
//!
//! `struct pkcs8_priv_key_info_st` is declared in `include/crypto/x509.h:291-297`, an
//! internal header. This module is its canonical definition because
//! `crypto/asn1/p8_pkey.c` is its authority unit — the file that defines the item over it
//! and both hand-written accessors. `src/evp/pkey_asn1.rs` re-exports the name for the
//! `priv_decode`/`priv_encode` callback signatures rather than declaring a placeholder
//! (D348's rule). The `attributes` member is `STACK_OF(X509_ATTRIBUTE) *`, which the crate
//! projects as `*mut OpenSslStack`, the same spelling `EvpPkey`'s own stack fields use.
//!
//! ## No raise, and the court
//!
//! Neither function raises: `PKCS8_pkey_set0` answers `0` on its three failure arms and
//! `PKCS8_pkey_get0` always answers `1`. So `crypto/asn1/p8_pkey.c` is deliberately **not**
//! added to `gen_err_raise_sites.py`'s `COVERED_FILES`. The arms live in
//! `RT-ASN1-TEMPLATE`: a `PKCS8_PRIV_KEY_INFO` cannot be built through a landed entry point
//! (its constructors are among the five withheld above), so the probe declares the
//! authority's own `struct pkcs8_priv_key_info_st` locally and drives both accessors over
//! live `ASN1_INTEGER`/`X509_ALGOR`/`ASN1_OCTET_STRING` members, printing return codes, the
//! OID the probe compares itself, and the bytes of a public constant it chose.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_void};

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_INTEGER_set;
use crate::asn1::string::{ASN1_STRING_get0_data, ASN1_STRING_length, ASN1_STRING_set0};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_set0};
use crate::runtime::obj::Asn1Object;
use crate::runtime::stack::OpenSslStack;

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
