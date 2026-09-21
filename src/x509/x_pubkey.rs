//! `crypto/x509/x_pubkey.c`'s accessor slice — `X509_PUBKEY_set0_public_key`,
//! `X509_PUBKEY_set0_param`, `X509_PUBKEY_get0_param` and the internal
//! `ossl_x509_PUBKEY_get0_libctx`. Phase 8.8 (D349).
//!
//! ## A partial unit, and the measured boundary of this slice
//!
//! `crypto/x509/x_pubkey.c` is 1,079 lines, **24 exports** and **17 internals**. This
//! module lands **three** of the exports (`:1010`, `:1017`, `:1028`) and **one** of the
//! internals (`:1071`). It is the slice the five `EVP_PKEY_ASN1_METHOD` objects of
//! Phase 8.8 call by address: every one of `rsa_ameth.c`, `dh_ameth.c`, `dsa_ameth.c`,
//! `ec_ameth.c` and `ecx_meth.c` reaches `X509_PUBKEY_set0_param` from its `pub_encode`
//! and `X509_PUBKEY_get0_param` from its `pub_decode` (D341's table), and the libctx accessor's
//! two callers are `ec_ameth.c:109` and `crypto/x509/v3_skid.c:69`.
//!
//! What is withheld is measured rather than implied, and the reason the rest of the unit
//! cannot land is a cycle rather than a preference:
//!
//! * **Twenty-one exports.** The `i2d_*_PUBKEY`/`d2i_*_PUBKEY` family
//!   (`i2d_PUBKEY`, `i2d_RSA_PUBKEY`, `i2d_DSA_PUBKEY`, `i2d_EC_PUBKEY`, their `d2i_`
//!   siblings and the `X509_PUBKEY_{new,new_ex,free,dup,it,get,get0,set,eq}` object
//!   layer), whose bodies build a temporary `EVP_PKEY` and call `EVP_PKEY_assign`. That
//!   function sets `pkey->ameth = EVP_PKEY_asn1_find(NULL, type)`, which reads the
//!   `standard_methods[]` table this subphase exists to populate and which is empty here
//!   (`src/evp/pkey_asn1.rs`'s `D-PKEY-AMETH-1`); landing any of them would compile a
//!   body that answers differently from the authority's for every standard type. That is
//!   D341's cycle.
//! * **Sixteen internals**, `ossl_d2i_*_PUBKEY`/`ossl_i2d_*_PUBKEY` (fourteen) plus
//!   `ossl_d2i_X509_PUBKEY_INTERNAL`/`ossl_X509_PUBKEY_INTERNAL_free`. The first fourteen
//!   are that same `EVP_PKEY_assign` body; the last two are the `X509_PUBKEY_INTERNAL`
//!   item and its free path. The `ASN1_SEQUENCE(X509_PUBKEY_INTERNAL)` item (`:63-66`)
//!   itself reaches only landed names, but its decoder is `ossl_d2i_X509_PUBKEY_INTERNAL`,
//!   whose caller is the withheld `d2i_PUBKEY` family — an item no landed function can
//!   build (D327's rule), so it is withheld with them rather than landed dead.
//! * The `x509_pubkey_ex_d2i_ex` decoder arm reaches `OSSL_DECODER_CTX_new_for_pkey` and
//!   the encoder arm `OSSL_ENCODER_CTX_*`, which are **Phase 10's** and already recorded
//!   as a `blocking_dependency` (`forensics/atlas/prerequisite-gate.json`).
//!
//! The sixteen internals are the `covers` of this module's divergence row in
//! `forensics/prerequisites.json`, recorded exactly so the prerequisite gate's direction B
//! reports nothing unwired and direction D rejects the row the day one of them is built.
//!
//! ## The `X509Pubkey` layout, and the coordinate the brief gives
//!
//! The three accessors read `pub->algor`, `pub->public_key`, `key->libctx` and
//! `key->propq`, so the **structure** they read is `struct X509_pubkey_st`
//! (`crypto/x509/x_pubkey.c:31-43`, the file's own definition). The brief's coordinate
//! `:63-78` is the `ASN1_SEQUENCE(X509_PUBKEY_INTERNAL)` template and
//! `ossl_d2i_X509_PUBKEY_INTERNAL`, which restate the same two leading fields as item
//! columns; the item is withheld with the decoders above, and what the accessors need is
//! the struct, transcribed here. The authority declares the field `ASN1_BIT_STRING
//! *public_key`; `ASN1_BIT_STRING` is a `typedef` of the same `struct asn1_string_st` as
//! `ASN1_STRING`, so the field is `*mut Asn1String` here, the spelling
//! `src/asn1/bitstr.rs` uses for every `ASN1_BIT_STRING *` it takes.
//!
//! ## No raise, and the court
//!
//! None of the four functions raises: each answers `1`, or `0` when a callee fails, and
//! the authority has no `ERR_raise` on any path. So `crypto/x509/x_pubkey.c` is
//! deliberately **not** added to `gen_err_raise_sites.py`'s `COVERED_FILES`.
//!
//! The arms live in `RT-ASN1-TEMPLATE` (`courts/phase5/rt_asn1_template_probe.c`), the
//! probe D348 already extended for `X509_ALGOR`: an `X509_PUBKEY` cannot be built through
//! any landed entry point (its constructors are in the withheld twenty-one), so the probe
//! declares the authority's own `struct X509_pubkey_st` locally, allocates one, and drives
//! the accessors over live `X509_ALGOR`/`ASN1_BIT_STRING` members — which is the same
//! "declare the structure, drive the entry point" method that probe uses throughout, and
//! which measures the layout agreement between the two libraries as well as the accessors'
//! answers. Every observation is a return code, an OID the probe compares itself, or the
//! bytes of a public constant the probe chose.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};

use crate::asn1::bitstr::set_bits_left;
use crate::asn1::layout::Asn1String;
use crate::asn1::string::ASN1_STRING_set0;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_set0};
use crate::evp::pkey::EvpPkey;
use crate::runtime::obj::Asn1Object;

/// `struct X509_pubkey_st` — `X509_PUBKEY`, from `crypto/x509/x_pubkey.c:31-43`.
///
/// The file's own definition, not a header's, so its fields are crate-private. The three
/// accessors below read `algor`, `public_key`, `libctx` and `propq`; `pkey` and the
/// `flag_force_legacy` bit are read only by the withheld `X509_PUBKEY_get`/`d2i_PUBKEY_ex`
/// halves and are the authority's layout until then.
///
/// The authority writes the trailing member as `unsigned int flag_force_legacy : 1`; a C
/// bitfield has no Rust spelling, so it is a `c_uint` occupying the same four bytes at the
/// same offset, and the struct's size is unchanged. That is the same modelling
/// `src/ec/backend.rs` records for the authority's flag words: the bitfield is read by no
/// landed function, so only its storage is projected.
#[repr(C)]
pub struct X509Pubkey {
    /// `X509_ALGOR *algor` — the subjectPublicKeyInfo algorithm, read by `set0_param` and
    /// `get0_param` and written by [`X509_PUBKEY_set0_param`].
    pub(crate) algor: *mut X509Algor,
    /// `ASN1_BIT_STRING *public_key` — the `subjectPublicKey` bit string, written by
    /// [`X509_PUBKEY_set0_public_key`] and read by [`X509_PUBKEY_get0_param`].
    pub(crate) public_key: *mut Asn1String,
    /// `EVP_PKEY *pkey` — the decoded key, filled by the withheld `X509_PUBKEY_get`.
    pub(crate) pkey: *mut EvpPkey,
    /// `OSSL_LIB_CTX *libctx` — the decoding library context, read by
    /// [`ossl_x509_PUBKEY_get0_libctx`]. The crate models an `OSSL_LIB_CTX *` as
    /// `*mut c_void`, as `EVP_CIPHER_fetch` and every other landed entry point do.
    pub(crate) libctx: *mut c_void,
    /// `char *propq` — the decoding property query, read by
    /// [`ossl_x509_PUBKEY_get0_libctx`] and owned by the object.
    pub(crate) propq: *mut c_char,
    /// `unsigned int flag_force_legacy : 1` — the bitfield's storage, read by the
    /// withheld legacy-decode arm.
    pub(crate) flag_force_legacy: c_uint,
}

const _: () = {
    assert!(core::mem::size_of::<X509Pubkey>() == 48);
    assert!(core::mem::offset_of!(X509Pubkey, algor) == 0);
    assert!(core::mem::offset_of!(X509Pubkey, public_key) == 8);
    assert!(core::mem::offset_of!(X509Pubkey, pkey) == 16);
    assert!(core::mem::offset_of!(X509Pubkey, libctx) == 24);
    assert!(core::mem::offset_of!(X509Pubkey, propq) == 32);
    assert!(core::mem::offset_of!(X509Pubkey, flag_force_legacy) == 40);
};

/// `void X509_PUBKEY_set0_public_key(X509_PUBKEY *pub, unsigned char *penc, int penclen)`
/// — `crypto/x509/x_pubkey.c:1010-1015`.
///
/// The bit string adopts `penc`, and `ossl_asn1_string_set_bits_left(..., 0)` records that
/// its last octet is whole. The authority does not test `pub` or `penc` for NULL; a caller
/// that does is the withheld `X509_PUBKEY_set0_param`, which may be handed a NULL `penc`
/// and skips this call.
///
/// # Safety
///
/// `pub` is a live `X509_PUBKEY` whose `public_key` is live; `penc` is NULL or a buffer of
/// `penclen` bytes the caller transfers ownership of.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_set0_public_key(
    pub_: *mut X509Pubkey,
    penc: *mut u8,
    penclen: c_int,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for both reads.
    unsafe {
        ASN1_STRING_set0((*pub_).public_key, penc.cast::<c_void>(), penclen);
        set_bits_left((*pub_).public_key, 0);
    }
}

/// `int X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *aobj, int ptype, void *pval,
/// unsigned char *penc, int penclen)` — `crypto/x509/x_pubkey.c:1017-1026`.
///
/// The algorithm is set first and owns the decision: a failed `X509_ALGOR_set0` leaves the
/// bit string untouched and answers 0. A NULL `penc` means "keep the existing bit string",
/// which is why the second call is guarded rather than unconditional.
///
/// # Safety
///
/// `pub` is a live `X509_PUBKEY` with live `algor` and `public_key` members; `aobj` and
/// `pval` are the values `X509_ALGOR_set0` may adopt; `penc` is NULL or a buffer of
/// `penclen` bytes transferred to the object.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_set0_param(
    pub_: *mut X509Pubkey,
    aobj: *mut Asn1Object,
    ptype: c_int,
    pval: *mut c_void,
    penc: *mut u8,
    penclen: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        if X509_ALGOR_set0((*pub_).algor, aobj, ptype, pval) == 0 {
            return 0;
        }
        if !penc.is_null() {
            X509_PUBKEY_set0_public_key(pub_, penc, penclen);
        }
    }
    1
}

/// `int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen,
/// X509_ALGOR **pa, const X509_PUBKEY *pub)` — `crypto/x509/x_pubkey.c:1028-1041`.
///
/// Each of the four out-parameters is optional and independently skipped. `ppkalg` is
/// `ASN1_OBJECT **`, **not** `const ASN1_OBJECT **` — the authority writes a non-const
/// pointer through it, and the `const` on the two `get0` answers below is the *caller's*
/// reading, not this signature's. The bit string's answer is its `data`/`length` pair
/// **borrowed**, which is the authority's `get0` naming and what a caller must not free.
///
/// # Safety
///
/// `pub` is a live `X509_PUBKEY` whose `algor` and `public_key` are live. Each out-pointer
/// is NULL or writable for its type; `ppkalg` receives a borrowed OID, `pk` a borrowed
/// buffer of `*ppklen` bytes, `pa` a borrowed identifier.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_get0_param(
    ppkalg: *mut *mut Asn1Object,
    pk: *mut *const u8,
    ppklen: *mut c_int,
    pa: *mut *mut X509Algor,
    pub_: *const X509Pubkey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read and write.
    unsafe {
        if !ppkalg.is_null() {
            *ppkalg = (*(*pub_).algor).algorithm;
        }
        if !pk.is_null() {
            *pk = (*(*pub_).public_key).data;
            *ppklen = (*(*pub_).public_key).length;
        }
        if !pa.is_null() {
            *pa = (*pub_).algor;
        }
    }
    1
}

/// `int ossl_x509_PUBKEY_get0_libctx(OSSL_LIB_CTX **plibctx, const char **ppropq,
/// const X509_PUBKEY *key)` — `crypto/x509/x_pubkey.c:1071-1079`. Internal
/// (`include/crypto/x509.h:333`), so `pub(crate)`.
///
/// Both out-parameters are optional and independently skipped, and both answers are
/// borrowed. Its two authority callers are `crypto/ec/ec_ameth.c:109` (withheld with that
/// unit's method object, D341) and `crypto/x509/v3_skid.c:69` (a later Phase-11 unit), so
/// the only reader today is the unit test below; the annotation says so rather than hiding
/// it.
///
/// # Safety
///
/// `key` is a live `X509_PUBKEY`. Each out-pointer is NULL or writable for its type.
#[allow(dead_code)] // read by `crypto/ec/ec_ameth.c:109` and `crypto/x509/v3_skid.c:69`, both unlanded.
#[allow(non_snake_case)] // the authority's own spelling, as `src/ec/mont.rs` keeps `ossl_ec_GFp_*`.
pub(crate) unsafe extern "C" fn ossl_x509_PUBKEY_get0_libctx(
    plibctx: *mut *mut c_void,
    ppropq: *mut *const c_char,
    key: *const X509Pubkey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read and write.
    unsafe {
        if !plibctx.is_null() {
            *plibctx = (*key).libctx;
        }
        if !ppropq.is_null() {
            *ppropq = (*key).propq;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::layout::V_ASN1_UNDEF;
    use crate::asn1::string::{ASN1_BIT_STRING_free, ASN1_BIT_STRING_new};
    use crate::asn1::x_algor::{X509_ALGOR_free, X509_ALGOR_new};
    use crate::runtime::obj::{NID_rsaEncryption, OBJ_nid2obj, OBJ_obj2nid};
    use core::ffi::c_void;

    /// A key whose two ASN.1 members are live, built from this module's own definitions.
    fn blank_pubkey() -> X509Pubkey {
        X509Pubkey {
            algor: X509_ALGOR_new(),
            public_key: ASN1_BIT_STRING_new(),
            pkey: core::ptr::null_mut(),
            libctx: core::ptr::null_mut(),
            propq: core::ptr::null_mut(),
            flag_force_legacy: 0,
        }
    }

    unsafe fn free_pubkey(pub_: &mut X509Pubkey) {
        // SAFETY: the two members were allocated by the `_new` constructors above.
        unsafe {
            X509_ALGOR_free(pub_.algor);
            ASN1_BIT_STRING_free(pub_.public_key);
        }
    }

    /// The three accessors round-trip the identifier and the bit string they were given.
    #[test]
    fn set0_and_get0_are_the_same_identifier_and_bytes() {
        let mut pub_ = blank_pubkey();
        // The bytes are handed to the object, which owns them.
        let enc = vec![0x04u8, 0xaa, 0xbb];
        let penc = enc.as_ptr() as *mut u8;
        core::mem::forget(enc);

        // SAFETY: the object's two members are live; `penc` is a fresh heap buffer.
        let rc = unsafe {
            X509_PUBKEY_set0_param(
                &raw mut pub_,
                OBJ_nid2obj(NID_rsaEncryption),
                V_ASN1_UNDEF,
                core::ptr::null_mut(),
                penc,
                3,
            )
        };
        assert_eq!(rc, 1);

        let mut o: *mut Asn1Object = core::ptr::null_mut();
        let mut pk: *const u8 = core::ptr::null();
        let mut pklen = -1;
        let mut pa: *mut X509Algor = core::ptr::null_mut();
        // SAFETY: the object is live and every out-pointer is writable.
        let rc = unsafe {
            X509_PUBKEY_get0_param(&raw mut o, &raw mut pk, &raw mut pklen, &raw mut pa, &pub_)
        };
        assert_eq!(rc, 1);
        // SAFETY: `o` and `pk` were filled by the call and are owned by the object.
        unsafe {
            assert_eq!(OBJ_obj2nid(o), NID_rsaEncryption);
            assert_eq!(pklen, 3);
            assert_eq!(core::slice::from_raw_parts(pk, 3), &[0x04, 0xaa, 0xbb]);
            assert_eq!(pa, pub_.algor);
            free_pubkey(&mut pub_);
        }
    }

    /// A NULL out-pointer is skipped, and a NULL `penc` leaves the bit string alone.
    #[test]
    fn absent_arguments_are_skipped() {
        let mut pub_ = blank_pubkey();
        // SAFETY: the object's members are live; `penc` NULL is the "keep" arm.
        let rc = unsafe {
            X509_PUBKEY_set0_param(
                &raw mut pub_,
                OBJ_nid2obj(NID_rsaEncryption),
                V_ASN1_UNDEF,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, 1);
        // SAFETY: every out-pointer is NULL, which the function skips.
        let rc = unsafe {
            X509_PUBKEY_get0_param(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &pub_,
            )
        };
        assert_eq!(rc, 1);
        // SAFETY: the bit string was never written, so it is still empty.
        unsafe {
            assert_eq!((*pub_.public_key).length, 0);
            free_pubkey(&mut pub_);
        }
    }

    /// The libctx accessor hands back what the object holds, borrowed.
    #[test]
    fn libctx_and_propq_are_borrowed_back() {
        let mut sentinel = 0u8;
        let propq = c"test-property-query";
        let mut pub_ = blank_pubkey();
        pub_.libctx = (&raw mut sentinel).cast::<c_void>();
        pub_.propq = propq.as_ptr() as *mut c_char;

        let mut seen_ctx: *mut c_void = core::ptr::null_mut();
        let mut seen_propq: *const c_char = core::ptr::null();
        // SAFETY: the object is live and both out-pointers are writable.
        let rc =
            unsafe { ossl_x509_PUBKEY_get0_libctx(&raw mut seen_ctx, &raw mut seen_propq, &pub_) };
        assert_eq!(rc, 1);
        assert_eq!(seen_ctx, pub_.libctx);
        assert_eq!(seen_propq, propq.as_ptr());
        // SAFETY: the object's two members are live.
        unsafe { free_pubkey(&mut pub_) };
    }
}
