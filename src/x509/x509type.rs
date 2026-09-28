//! Phase 10.14.1 — `crypto/x509/x509type.c`: `X509_certificate_type`, whole.
//!
//! `crypto/x509/x509type.c` is 84 lines and publishes one function. It answers the authority's
//! `EVP_PK_*`/`EVP_PKT_*`/`EVP_PKS_*` bitmask describing what the certificate's public key can
//! be used for: the key's own class and purposes from its type, then the signature algorithm's
//! class when `OBJ_find_sigid_algs` can map it to a key type.
//!
//! ## The `EVP_PK_*` words are deprecated `evp.h` macros and are not modelled elsewhere
//!
//! All ten are declared in `include/openssl/evp.h:50-59` under `OPENSSL_NO_DEPRECATED_3_0`. The
//! admitted profile does not define that guard — the authority compiles this unit that reads
//! them — so they are transcribed here with their header lines cited rather than pulled from an
//! unlanded EVP unit.
//!
//! The `EVP_PKEY_*` identifiers the `switch` arms compare are the crate's own
//! ([`crate::evp::pkey_ctx`]), so the two halves of this function meet at a name rather than a
//! number.
//!
//! ## No raise
//!
//! The unit signals failure by a 0 return and never calls `ERR_raise*`, so
//! `crypto/x509/x509type.c` is deliberately **not** an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
// The NID constants are matched by name, and the authority spells them lower case (`NID_rsa`, ...);
// the crate's own object table uses the same spellings, so the pattern names are kept as they are
// and the lint is silenced rather than the names bent into an uppercase the header does not use.
#![allow(non_upper_case_globals)]

use core::ffi::c_int;

use crate::evp::pkey::{EVP_PKEY_get_id, EvpPkey};
use crate::evp::pkey_ctx::{
    EVP_PKEY_DH, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED25519, EVP_PKEY_ED448, EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS,
};
use crate::runtime::obj::{
    NID_X9_62_id_ecPublicKey, NID_dsa, NID_dsa_2, NID_id_GostR3410_2001, NID_id_GostR3410_2012_256,
    NID_id_GostR3410_2012_512, NID_rsa, NID_rsaEncryption, OBJ_find_sigid_algs,
};
use crate::x509::x509_cmp::X509_get0_pubkey;
use crate::x509::x_x509::{X509_get_signature_nid, X509};

/// `EVP_PK_RSA` — `include/openssl/evp.h:50`.
const EVP_PK_RSA: c_int = 0x0001;
/// `EVP_PK_DSA` — `include/openssl/evp.h:51`.
const EVP_PK_DSA: c_int = 0x0002;
/// `EVP_PK_DH` — `include/openssl/evp.h:52`.
const EVP_PK_DH: c_int = 0x0004;
/// `EVP_PK_EC` — `include/openssl/evp.h:53`.
const EVP_PK_EC: c_int = 0x0008;
/// `EVP_PKT_SIGN` — `include/openssl/evp.h:54`.
const EVP_PKT_SIGN: c_int = 0x0010;
/// `EVP_PKT_ENC` — `include/openssl/evp.h:55`.
const EVP_PKT_ENC: c_int = 0x0020;
/// `EVP_PKT_EXCH` — `include/openssl/evp.h:56`.
const EVP_PKT_EXCH: c_int = 0x0040;
/// `EVP_PKS_RSA` — `include/openssl/evp.h:57`.
const EVP_PKS_RSA: c_int = 0x0100;
/// `EVP_PKS_DSA` — `include/openssl/evp.h:58`.
const EVP_PKS_DSA: c_int = 0x0200;
/// `EVP_PKS_EC` — `include/openssl/evp.h:59`.
const EVP_PKS_EC: c_int = 0x0400;

/// `int X509_certificate_type(const X509 *x, const EVP_PKEY *pkey)` —
/// `crypto/x509/x509type.c:16-84`.
///
/// A NULL `x` or a certificate with no resolvable public key answers 0. When `pkey` is non-NULL
/// it is used instead of the certificate's key, which is what lets a caller ask about a
/// *proposed* key.
///
/// # Safety
///
/// `x` must be a live `X509`; `pkey` must be NULL or a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn X509_certificate_type(x: *const X509, pkey: *const EvpPkey) -> c_int {
    if x.is_null() {
        return 0;
    }
    let pk = if pkey.is_null() {
        // SAFETY: `x` is live per the contract.
        unsafe { X509_get0_pubkey(x) }
    } else {
        pkey.cast_mut()
    };
    if pk.is_null() {
        return 0;
    }
    let mut ret: c_int = 0;
    // SAFETY: `pk` is live.
    match unsafe { EVP_PKEY_get_id(pk) } {
        EVP_PKEY_RSA => {
            ret = EVP_PK_RSA | EVP_PKT_SIGN;
            ret |= EVP_PKT_ENC;
        }
        EVP_PKEY_RSA_PSS => ret = EVP_PK_RSA | EVP_PKT_SIGN,
        EVP_PKEY_DSA => ret = EVP_PK_DSA | EVP_PKT_SIGN,
        EVP_PKEY_EC => ret = EVP_PK_EC | EVP_PKT_SIGN | EVP_PKT_EXCH,
        EVP_PKEY_ED448 | EVP_PKEY_ED25519 => ret = EVP_PKT_SIGN,
        EVP_PKEY_DH => ret = EVP_PK_DH | EVP_PKT_EXCH,
        NID_id_GostR3410_2001 | NID_id_GostR3410_2012_256 | NID_id_GostR3410_2012_512 => {
            ret = EVP_PKT_EXCH | EVP_PKT_SIGN;
        }
        _ => {}
    }
    // SAFETY: `x` is live.
    let i = unsafe { X509_get_signature_nid(x) };
    if i != 0 {
        let mut sig = i;
        // SAFETY: `sig` is a writable local; the second out-pointer is the authority's NULL.
        if unsafe { OBJ_find_sigid_algs(i, core::ptr::null_mut(), &raw mut sig) } != 0 {
            match sig {
                NID_rsaEncryption | NID_rsa => ret |= EVP_PKS_RSA,
                NID_dsa | NID_dsa_2 => ret |= EVP_PKS_DSA,
                NID_X9_62_id_ecPublicKey => ret |= EVP_PKS_EC,
                _ => {}
            }
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two `switch`es meet at the NID names, not at numbers: the first arm's `RSA` class and
    /// the second's `PKS_RSA` class are the two halves of the same `EVP_PKEY_RSA` answer. This
    /// test pins the constants rather than a certificate, which the court drives.
    #[test]
    fn the_two_bit_families_do_not_overlap() {
        assert_eq!(EVP_PK_RSA & EVP_PKS_RSA, 0);
        assert_eq!(EVP_PKT_SIGN & EVP_PKT_ENC, 0);
        assert_eq!(EVP_PKT_SIGN | EVP_PKT_ENC | EVP_PKT_EXCH, 0x70);
    }
}
