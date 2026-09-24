//! Phase 8 — `providers/common/der/der_rsa_key.c`: the RSA-PSS `AlgorithmIdentifier` writers, the
//! `RSASSA-PSS-params` writer, and the precompiled hash/MGF1 identifiers they select from.
//!
//! This unit is the second of `rsa_sig.c.in`'s three non-FIPS prerequisites. `rsa_sig.c.in`'s
//! `rsa_generate_signature_aid` chooses between it and `src/provider/der_rsa_sig.rs` on the pad
//! mode: PKCS#1 v1.5 writes `ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption`, and
//! `RSA_PKCS1_PSS_PADDING` writes `ossl_DER_w_algorithmIdentifier_RSA_PSS` with a
//! `RSA_PSS_PARAMS_30` built from the context's salt length and MGF1 digest.
//!
//! ## The precompiled sequences are DER of a fixed shape, transcribed rather than computed
//!
//! Seven `ossl_der_aid_*Identifier` arrays are `SEQUENCE { OID, NULL }` — the hash
//! AlgorithmIdentifier RFC 4055 §2.1 spells. Six `der_aid_mgf1*Identifier` arrays are
//! `SEQUENCE { id-mgf1, <hash AlgorithmIdentifier> }`. Every byte below is read back from the
//! authority's own generated headers (`der_digests.h`'s `DER_OID_V_*`, `der_rsa.h`'s `DER_OID_V_id_mgf1`)
//! rather than typed from the ASN.1, because both sides agreeing on a wrong constant is invisible
//! to a differential court.
//!
//! ## `DER_w_MaskGenAlgorithm`'s `break`, and why the cases after it are still live
//!
//! `der_rsa_key.c:254-265` has `case NID_sha1: break;` physically **before** the five
//! `MGF1_SHA_CASE` expansions. A C `switch` jumps straight to the matching case label, so the
//! `break` only stops case `NID_sha1` falling through; the `NID_sha224`…`NID_sha512_256` labels
//! below it stay reachable and each *is* selected for its own hash. The transcription is the
//! natural `match`: `SHA1` writes nothing and answers 1 (its identifier is the default and is
//! omitted), the five others write their own identifier, and any other hash answers 0.
//!
//! ## What is here, and what is not
//!
//! The four functions and thirteen arrays of this unit are transcribed whole (D327).
//! `ossl_DER_w_algorithmIdentifier_RSA` is the last of them and the only one nothing in this crate
//! reaches yet: it is the *key* AlgorithmIdentifier, whose reader is the RSA key encoder's
//! `rsa_set_ctx_params`/`rsa_export` path, and it carries a stated `#[allow(dead_code)]` rather than
//! being dropped, so the unit closes whole.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};

use crate::der_writer::{
    ossl_DER_w_begin_sequence, ossl_DER_w_end_sequence, ossl_DER_w_precompiled, ossl_DER_w_uint32,
};
use crate::packet::Wpacket;
use crate::rsa::object::{
    ossl_rsa_get0_pss_params_30, RSA_test_flags, RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA,
    RSA_FLAG_TYPE_RSASSAPSS,
};
use crate::rsa::pss::{
    ossl_rsa_pss_params_30_hashalg, ossl_rsa_pss_params_30_is_unrestricted,
    ossl_rsa_pss_params_30_maskgenalg, ossl_rsa_pss_params_30_maskgenhashalg,
    ossl_rsa_pss_params_30_saltlen, ossl_rsa_pss_params_30_trailerfield,
};
use crate::rsa::Rsa;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{
    NID_mgf1, NID_rsaEncryption, NID_rsassaPss, NID_sha1, NID_sha224, NID_sha256, NID_sha384,
    NID_sha512, NID_sha512_224, NID_sha512_256,
};

/// `ossl_assert(x)` under `NDEBUG` is `(x) != 0`; this unit's own copy, as the authority's macro is
/// per-file.
#[inline]
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

/// `DER_OID_V_rsaEncryption` — `der_rsa.h`.
static OID_RSA_ENCRYPTION: [u8; 11] = [
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];
/// `DER_OID_V_id_RSASSA_PSS` — `der_rsa.h`, which `ossl_der_oid_rsassaPss` aliases.
static OID_ID_RSASSA_PSS: [u8; 11] = [
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,
];

/// `ossl_der_aid_sha1Identifier` — `SEQUENCE { id-sha1, NULL }`.
static OSSL_DER_AID_SHA1_IDENTIFIER: [u8; 11] = [
    0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
];
/// `ossl_der_aid_sha224Identifier`.
static OSSL_DER_AID_SHA224_IDENTIFIER: [u8; 15] = [
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00,
];
/// `ossl_der_aid_sha256Identifier`.
static OSSL_DER_AID_SHA256_IDENTIFIER: [u8; 15] = [
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
];
/// `ossl_der_aid_sha384Identifier`.
static OSSL_DER_AID_SHA384_IDENTIFIER: [u8; 15] = [
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
];
/// `ossl_der_aid_sha512Identifier`.
static OSSL_DER_AID_SHA512_IDENTIFIER: [u8; 15] = [
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
];
/// `ossl_der_aid_sha512_224Identifier`.
static OSSL_DER_AID_SHA512_224_IDENTIFIER: [u8; 15] = [
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00,
];
/// `ossl_der_aid_sha512_256Identifier`.
static OSSL_DER_AID_SHA512_256_IDENTIFIER: [u8; 15] = [
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00,
];

/// `der_aid_mgf1SHA224Identifier` — `SEQUENCE { id-mgf1, sha224Identifier }`.
static DER_AID_MGF1_SHA224_IDENTIFIER: [u8; 28] = [
    0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00,
];
/// `der_aid_mgf1SHA256Identifier`.
static DER_AID_MGF1_SHA256_IDENTIFIER: [u8; 28] = [
    0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
];
/// `der_aid_mgf1SHA384Identifier`.
static DER_AID_MGF1_SHA384_IDENTIFIER: [u8; 28] = [
    0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
];
/// `der_aid_mgf1SHA512Identifier`.
static DER_AID_MGF1_SHA512_IDENTIFIER: [u8; 28] = [
    0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
];
/// `der_aid_mgf1SHA512_224Identifier`.
static DER_AID_MGF1_SHA512_224_IDENTIFIER: [u8; 28] = [
    0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00,
];
/// `der_aid_mgf1SHA512_256Identifier`.
static DER_AID_MGF1_SHA512_256_IDENTIFIER: [u8; 28] = [
    0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00,
];

/// `static int DER_w_MaskGenAlgorithm(WPACKET *pkt, int tag, const RSA_PSS_PARAMS_30 *pss)` —
/// `der_rsa_key.c:246-274`. See the module documentation for the reachable-case reading of its
/// `break`-before-the-cases switch.
///
/// # Safety
/// `pkt` live; `pss` is NULL or a live object.
#[allow(non_upper_case_globals)] // the `NID_*` constants are the authority's own spellings
unsafe fn der_w_maskgen_algorithm(
    pkt: *mut Wpacket,
    tag: c_int,
    pss: *const crate::rsa::RsaPssParams30,
) -> c_int {
    if pss.is_null() {
        return 0;
    }
    // SAFETY: `pss` is non-NULL and live per the contract.
    let maskgenalg = unsafe { ossl_rsa_pss_params_30_maskgenalg(pss) };
    if maskgenalg != NID_mgf1 {
        return 0;
    }

    // SAFETY: `pss` is live per the contract.
    let maskgenalg_nid = unsafe { ossl_rsa_pss_params_30_maskgenhashalg(pss) };
    // `case NID_sha1: break;` leaves `maskgenalg` NULL, which the tail reads as "write nothing".
    let maskgenalg: &[u8] = match maskgenalg_nid {
        NID_sha1 => return 1,
        NID_sha224 => &DER_AID_MGF1_SHA224_IDENTIFIER,
        NID_sha256 => &DER_AID_MGF1_SHA256_IDENTIFIER,
        NID_sha384 => &DER_AID_MGF1_SHA384_IDENTIFIER,
        NID_sha512 => &DER_AID_MGF1_SHA512_IDENTIFIER,
        NID_sha512_224 => &DER_AID_MGF1_SHA512_224_IDENTIFIER,
        NID_sha512_256 => &DER_AID_MGF1_SHA512_256_IDENTIFIER,
        _ => return 0,
    };

    // SAFETY: `pkt` is live; `maskgenalg` is `'static` and its length is passed.
    unsafe {
        ossl_DER_w_precompiled(
            pkt,
            tag,
            maskgenalg.as_ptr().cast::<c_uchar>(),
            maskgenalg.len(),
        )
    }
}

/// `int ossl_DER_w_RSASSA_PSS_params(WPACKET *pkt, int tag, const RSA_PSS_PARAMS_30 *pss)` —
/// `der_rsa_key.c:282-355`.
///
/// The two `ERR_LIB_RSA` refusals are the authority's: a negative salt length and a trailer field
/// other than 1, both of which are also what the OAEP-PSS defaults make non-default fields of.
///
/// # Safety
/// `pkt` live; `pss` is NULL or a live object.
#[allow(non_snake_case)] // the authority's name is the contract
#[allow(non_upper_case_globals)] // the `NID_*` constants are the authority's own spellings
pub(crate) unsafe fn ossl_DER_w_RSASSA_PSS_params(
    pkt: *mut Wpacket,
    tag: c_int,
    pss: *const crate::rsa::RsaPssParams30,
) -> c_int {
    // SAFETY: `pss` is NULL or live per the contract; the PSS accessors accept NULL.
    unsafe {
        if ossl_assert(!pss.is_null() && ossl_rsa_pss_params_30_is_unrestricted(pss) == 0) == 0 {
            return 0;
        }

        let hashalg_nid = ossl_rsa_pss_params_30_hashalg(pss);
        let saltlen = ossl_rsa_pss_params_30_saltlen(pss);
        let trailerfield = ossl_rsa_pss_params_30_trailerfield(pss);

        if saltlen < 0 {
            raise_site(&err_sites::DER_RSA_KEY_308);
            return 0;
        }
        if trailerfield != 1 {
            raise_site(&err_sites::DER_RSA_KEY_312);
            return 0;
        }

        /* Getting default values */
        let default_hashalg_nid = ossl_rsa_pss_params_30_hashalg(core::ptr::null());
        let default_saltlen = ossl_rsa_pss_params_30_saltlen(core::ptr::null());
        let default_trailerfield = ossl_rsa_pss_params_30_trailerfield(core::ptr::null());

        let hashalg: &[u8] = match hashalg_nid {
            NID_sha1 => &OSSL_DER_AID_SHA1_IDENTIFIER,
            NID_sha224 => &OSSL_DER_AID_SHA224_IDENTIFIER,
            NID_sha256 => &OSSL_DER_AID_SHA256_IDENTIFIER,
            NID_sha384 => &OSSL_DER_AID_SHA384_IDENTIFIER,
            NID_sha512 => &OSSL_DER_AID_SHA512_IDENTIFIER,
            NID_sha512_224 => &OSSL_DER_AID_SHA512_224_IDENTIFIER,
            NID_sha512_256 => &OSSL_DER_AID_SHA512_256_IDENTIFIER,
            _ => return 0,
        };

        (ossl_DER_w_begin_sequence(pkt, tag) != 0
            && (trailerfield == default_trailerfield
                || ossl_DER_w_uint32(pkt, 3, trailerfield as u32) != 0)
            && (saltlen == default_saltlen || ossl_DER_w_uint32(pkt, 2, saltlen as u32) != 0)
            && der_w_maskgen_algorithm(pkt, 1, pss) != 0
            && (hashalg_nid == default_hashalg_nid
                || ossl_DER_w_precompiled(
                    pkt,
                    0,
                    hashalg.as_ptr().cast::<c_uchar>(),
                    hashalg.len(),
                ) != 0)
            && ossl_DER_w_end_sequence(pkt, tag) != 0) as c_int
    }
}

/// `int ossl_DER_w_algorithmIdentifier_RSA_PSS(WPACKET *pkt, int tag, int rsa_type, const
/// RSA_PSS_PARAMS_30 *pss)` — `der_rsa_key.c:366-390`.
///
/// `rsa_sig.c.in`'s PSS arm passes `RSA_FLAG_TYPE_RSASSAPSS`, so the `id-RSASSA-PSS` OID is the one
/// written; the `rsaEncryption` arm is the same function reached with `RSA_FLAG_TYPE_RSA`, which
/// the unit's `RSA_CASE` macro covers even though nothing in this crate calls it that way yet.
///
/// # Safety
/// `pkt` live; `pss` is NULL or a live object.
#[allow(non_snake_case)] // the authority's name is the contract
#[allow(non_upper_case_globals)] // `RSA_FLAG_TYPE_*` are the authority's own spellings
pub(crate) unsafe fn ossl_DER_w_algorithmIdentifier_RSA_PSS(
    pkt: *mut Wpacket,
    tag: c_int,
    rsa_type: c_int,
    pss: *const crate::rsa::RsaPssParams30,
) -> c_int {
    let (rsa_nid, rsa_oid): (c_int, &[u8]) = match rsa_type {
        RSA_FLAG_TYPE_RSA => (NID_rsaEncryption, &OID_RSA_ENCRYPTION),
        RSA_FLAG_TYPE_RSASSAPSS => (NID_rsassaPss, &OID_ID_RSASSA_PSS),
        _ => return 0,
    };

    // SAFETY: `pkt` is live; `pss` is NULL or live per the contract.
    unsafe {
        (ossl_DER_w_begin_sequence(pkt, tag) != 0
            && (rsa_nid != NID_rsassaPss
                || ossl_rsa_pss_params_30_is_unrestricted(pss) != 0
                || ossl_DER_w_RSASSA_PSS_params(pkt, -1, pss) != 0)
            && ossl_DER_w_precompiled(pkt, -1, rsa_oid.as_ptr().cast::<c_uchar>(), rsa_oid.len())
                != 0
            && ossl_DER_w_end_sequence(pkt, tag) != 0) as c_int
    }
}

/// `int ossl_DER_w_algorithmIdentifier_RSA(WPACKET *pkt, int tag, RSA *rsa)` —
/// `der_rsa_key.c:392-399`.
///
/// The RSA **key** AlgorithmIdentifier. Nothing in this crate reaches it yet: its caller is the
/// provider key encoder's `rsa_export` path, which is a later stratum. It is transcribed rather
/// than dropped so the unit closes whole (D327), and the `#[allow(dead_code)]` carries the reason.
///
/// # Safety
/// `pkt` live; `rsa` is a live object.
#[allow(dead_code)] // the reader is the RSA key encoder's export path, not yet in this crate
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_DER_w_algorithmIdentifier_RSA(
    pkt: *mut Wpacket,
    tag: c_int,
    rsa: *mut Rsa,
) -> c_int {
    // SAFETY: `rsa` is live per the contract.
    unsafe {
        let rsa_type = RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK);
        let pss_params = ossl_rsa_get0_pss_params_30(rsa);
        ossl_DER_w_algorithmIdentifier_RSA_PSS(pkt, tag, rsa_type, pss_params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{WPACKET_get_total_written, WPACKET_init_der, Wpacket};

    /// The thirteen precompiled arrays are the authority's own bytes: a `SEQUENCE` over the OID
    /// followed by `NULL` (`05 00`), and the MGF1 wrappers over `id-mgf1`. The check names the
    /// authority's `DER_OID_V_*` values rather than a second transcription.
    #[test]
    fn the_pss_identifiers_are_the_authoritys_bytes() {
        assert_eq!(
            OSSL_DER_AID_SHA1_IDENTIFIER,
            [0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00]
        );
        assert_eq!(
            OSSL_DER_AID_SHA256_IDENTIFIER,
            [
                0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00
            ]
        );
        // `SEQUENCE { id-mgf1 (11 bytes), sha256Identifier (15 bytes) }` is `0x1A` bytes of content.
        assert_eq!(DER_AID_MGF1_SHA256_IDENTIFIER.len(), 28);
        assert_eq!(DER_AID_MGF1_SHA256_IDENTIFIER[0], 0x30);
        assert_eq!(DER_AID_MGF1_SHA256_IDENTIFIER[1], 0x1A);
        assert_eq!(
            &DER_AID_MGF1_SHA256_IDENTIFIER[2..13],
            &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08]
        );
        assert_eq!(
            &DER_AID_MGF1_SHA256_IDENTIFIER[13..],
            &OSSL_DER_AID_SHA256_IDENTIFIER
        );
        assert_eq!(
            &DER_AID_MGF1_SHA512_256_IDENTIFIER[13..],
            &OSSL_DER_AID_SHA512_256_IDENTIFIER
        );
        assert_eq!(
            OID_RSA_ENCRYPTION,
            [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        );
        assert_eq!(
            OID_ID_RSASSA_PSS,
            [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A]
        );
    }

    /// A NULL `pss` makes `DER_w_MaskGenAlgorithm` answer 0, which is `pss != NULL && …`'s first
    /// arm — the shape the `ossl_assert` in front of `ossl_DER_w_RSASSA_PSS_params` also refuses.
    #[test]
    fn a_null_pss_is_refused_by_the_params_writer() {
        let mut pkt = core::mem::MaybeUninit::<Wpacket>::uninit();
        let mut buf = [0u8; 64];
        // SAFETY: `pkt` is a live local, `buf` this call's own, and the pointers are NULL.
        unsafe {
            assert_eq!(WPACKET_init_der(pkt.as_mut_ptr(), buf.as_mut_ptr(), 64), 1);
            assert_eq!(
                ossl_DER_w_RSASSA_PSS_params(pkt.as_mut_ptr(), -1, core::ptr::null()),
                0
            );
            let mut written = 0usize;
            WPACKET_get_total_written(pkt.as_mut_ptr(), &mut written);
            assert_eq!(written, 0);
            crate::packet::WPACKET_cleanup(pkt.as_mut_ptr());
        }
    }
}
