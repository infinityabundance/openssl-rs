//! Phase 8 — `providers/common/securitycheck.c`: the provider layer's key and parameter checks.
//!
//! This unit is `rsa_sig.c.in`'s third non-FIPS prerequisite, and the only one of its nine
//! functions this profile reaches is **`ossl_rsa_key_op_get_protect`**: `rsa_signverify_init`
//! calls it unconditionally (`rsa_sig.c.in:530`) to decide whether an operation is a "protect"
//! (signing or encryption) or an "allow" (verifying or decryption). The other eight —
//! `ossl_rsa_check_key_size`, `ossl_kdf_check_key_size`, `ossl_mac_check_key_size`,
//! `ossl_ec_check_curve_allowed`, `ossl_ec_check_security_strength`, `ossl_dsa_check_key` and
//! `ossl_dh_check_key` — are reached only from the FIPS key-check arms of their units, which are
//! not this profile's arm (D391's measurement for `ossl_dsa_check_key`, repeated). They are
//! transcribed here **whole** because this is one unit (D327), so a later FIPS profile does not
//! re-open the file; the `#[allow(dead_code)]` on each carries that reason rather than an
//! omission.
//!
//! ## The one guarded region, and the guard is this profile's
//!
//! `#ifndef OPENSSL_NO_EC` (`:91-141`) and `#ifndef OPENSSL_NO_DSA` (`:143-187`) and
//! `#ifndef OPENSSL_NO_DH` (`:189-222`) are all *defined away* in this build, so the EC, DSA and DH
//! checks are compiled as the authority compiles them. `OPENSSL_NO_EC` is not set on this profile,
//! which is itself observable: `ossl_ec_check_curve_allowed` exists in the authority's DSO.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::bn::bignum::BN_num_bits;
use crate::dh::object::{DH_get0_p, DH_get0_q};
use crate::dh::Dh;
use crate::dsa::object::{DSA_get0_p, DSA_get0_q};
use crate::dsa::Dsa;
use crate::ec::curve::EC_curve_nid2nist;
use crate::ec::lib::{EC_GROUP_get_curve_name, EC_GROUP_order_bits};
use crate::ec::EcGroup;
use crate::evp::pkey_ctx::{
    EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_DECRYPT, EVP_PKEY_OP_ENCAPSULATE, EVP_PKEY_OP_ENCRYPT,
    EVP_PKEY_OP_SIGN, EVP_PKEY_OP_SIGNMSG, EVP_PKEY_OP_VERIFY, EVP_PKEY_OP_VERIFYMSG,
    EVP_PKEY_OP_VERIFYRECOVER,
};
use crate::rsa::object::{RSA_bits, RSA_test_flags, RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSASSAPSS};
use crate::rsa::Rsa;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site_data};
use crate::runtime::obj::NID_undef;

/// `OSSL_FIPS_MIN_SECURITY_STRENGTH_BITS` — `securitycheck.c:23`.
const OSSL_FIPS_MIN_SECURITY_STRENGTH_BITS: c_int = 112;

/// `int ossl_rsa_key_op_get_protect(const RSA *rsa, int operation, int *outprotect)` —
/// `securitycheck.c:25-60`.
///
/// The `switch`'s fallthroughs are the authority's and they are the whole point: sign is protect,
/// verify is not, but *both* accept any RSA key; encrypt is protect, decrypt is not, and a
/// `RSASSA-PSS` key **refuses** any of the four decryption-family operations with
/// `PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` because PSS-only keys cannot decrypt. An
/// operation outside the eight answers `ERR_R_INTERNAL_ERROR`.
///
/// # Safety
/// `rsa` is a live object; `outprotect` is writable.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_rsa_key_op_get_protect(
    rsa: *const Rsa,
    operation: c_int,
    outprotect: *mut c_int,
) -> c_int {
    let mut protect: c_int = 0;

    // The fallthroughs are written as the explicit operation-sets the authority's `case` labels
    // form: the sign family sets `protect`, the verify family does not, and the encrypt family
    // shares the PSS refusal with the decrypt one.
    let pss_refusal = match operation {
        EVP_PKEY_OP_SIGN | EVP_PKEY_OP_SIGNMSG => {
            protect = 1;
            false
        }
        EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYMSG => false,
        EVP_PKEY_OP_ENCAPSULATE | EVP_PKEY_OP_ENCRYPT => {
            protect = 1;
            true
        }
        EVP_PKEY_OP_VERIFYRECOVER | EVP_PKEY_OP_DECAPSULATE | EVP_PKEY_OP_DECRYPT => true,
        _ => {
            // SAFETY: `outprotect` is writable per the contract.
            let mut msg = [0u8; 64];
            // SAFETY: `msg` is this call's own buffer.
            unsafe {
                BIO_snprintf(
                    msg.as_mut_ptr().cast(),
                    msg.len(),
                    c"invalid operation: %d".as_ptr(),
                    operation,
                );
                raise_site_data(&err_sites::SECURITYCHECK_54, msg.as_ptr().cast());
            }
            return 0;
        }
    };

    if pss_refusal
        // SAFETY: `rsa` is live per the contract.
        && unsafe { RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) } == RSA_FLAG_TYPE_RSASSAPSS
    {
        let mut msg = [0u8; 64];
        // SAFETY: `msg` is this call's own buffer.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr().cast(),
                msg.len(),
                c"operation: %d".as_ptr(),
                operation,
            );
            raise_site_data(&err_sites::SECURITYCHECK_47, msg.as_ptr().cast());
        }
        return 0;
    }

    // SAFETY: `outprotect` is writable per the contract.
    unsafe { *outprotect = protect };
    1
}

/// `int ossl_rsa_check_key_size(const RSA *rsa, int protect)` — `securitycheck.c:68-75`.
///
/// # Safety
/// `rsa` is a live object.
#[allow(dead_code)] // reached from the FIPS key-check arm, not this profile's
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_rsa_check_key_size(rsa: *const Rsa, protect: c_int) -> c_int {
    // SAFETY: `rsa` is live per the contract.
    let sz = unsafe { RSA_bits(rsa) };

    c_int::from(if protect != 0 { sz >= 2048 } else { sz >= 1024 })
}

/// `int ossl_kdf_check_key_size(size_t keylen)` — `securitycheck.c:81-84`.
#[allow(dead_code)] // reached from the FIPS key-check arm, not this profile's
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) fn ossl_kdf_check_key_size(keylen: usize) -> c_int {
    c_int::from((keylen * 8) >= OSSL_FIPS_MIN_SECURITY_STRENGTH_BITS as usize)
}

/// `int ossl_mac_check_key_size(size_t keylen)` — `securitycheck.c:86-89`.
#[allow(dead_code)] // reached from the FIPS key-check arm, not this profile's
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) fn ossl_mac_check_key_size(keylen: usize) -> c_int {
    ossl_kdf_check_key_size(keylen)
}

/// `int ossl_ec_check_curve_allowed(const EC_GROUP *group)` — `securitycheck.c:93-106`.
///
/// # Safety
/// `group` is a live object.
#[allow(dead_code)] // reached from the FIPS key-check arm, not this profile's
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_ec_check_curve_allowed(group: *const EcGroup) -> c_int {
    // SAFETY: `group` is live per the contract.
    unsafe {
        let nid = EC_GROUP_get_curve_name(group);

        /* Explicit curves are not FIPS approved */
        if nid == NID_undef {
            return 0;
        }
        /* Only NIST curves are FIPS approved */
        if EC_curve_nid2nist(nid).is_null() {
            return 0;
        }
    }
    1
}

/// `int ossl_ec_check_security_strength(const EC_GROUP *group, int protect)` —
/// `securitycheck.c:122-139`.
///
/// # Safety
/// `group` is a live object.
#[allow(dead_code)] // reached from the FIPS key-check arm, not this profile's
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_ec_check_security_strength(
    group: *const EcGroup,
    protect: c_int,
) -> c_int {
    // SAFETY: `group` is live per the contract.
    let strength = unsafe { EC_GROUP_order_bits(group) } / 2;
    /* The min security strength allowed for legacy verification is 80 bits */
    if strength < 80 {
        return 0;
    }
    /*
     * For signing or key agreement only allow curves with at least 112 bits of
     * security strength
     */
    if protect != 0 && strength < OSSL_FIPS_MIN_SECURITY_STRENGTH_BITS {
        return 0;
    }
    1
}

/// `int ossl_dsa_check_key(const DSA *dsa, int sign)` — `securitycheck.c:149-186`.
///
/// # Safety
/// `dsa` is NULL or a live object.
#[allow(dead_code)] // reached from the FIPS key-check arm, not this profile's
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_dsa_check_key(dsa: *const Dsa, sign: c_int) -> c_int {
    if dsa.is_null() {
        return 0;
    }

    // SAFETY: `dsa` is live per the contract.
    unsafe {
        let p = DSA_get0_p(dsa);
        let q = DSA_get0_q(dsa);
        if p.is_null() || q.is_null() {
            return 0;
        }

        let l = BN_num_bits(p);
        let n = BN_num_bits(q);

        /*
         * For Digital signature verification DSA keys with < 112 bits of
         * security strength, are still allowed for legacy
         * use. The bounds given in SP 800-131Ar2 - Table 2 are
         * (512 <= L < 2048 or 160 <= N < 224).
         *
         * We are a little stricter and insist that both minimums are met.
         */
        if sign == 0 {
            if l < 512 || n < 160 {
                return 0;
            }
            if l < 2048 || n < 224 {
                return 1;
            }
        }

        /* Valid sizes for both sign and verify */
        if l == 2048 && (n == 224 || n == 256) {
            return 1;
        }
        c_int::from(l == 3072 && n == 256)
    }
}

/// `int ossl_dh_check_key(const DH *dh)` — `securitycheck.c:196-221`.
///
/// # Safety
/// `dh` is NULL or a live object.
#[allow(dead_code)] // reached from the FIPS key-check arm, not this profile's
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_dh_check_key(dh: *const Dh) -> c_int {
    if dh.is_null() {
        return 0;
    }

    // SAFETY: `dh` is live per the contract.
    unsafe {
        let p = DH_get0_p(dh);
        let q = DH_get0_q(dh);
        if p.is_null() || q.is_null() {
            return 0;
        }

        let l = BN_num_bits(p);
        if l < 2048 {
            return 0;
        }

        /* If it is a safe prime group then it is ok */
        if crate::dh::group_params::DH_get_nid(dh) != 0 {
            return 1;
        }

        /* If not then it must be FFC, which only allows certain sizes. */
        let n = BN_num_bits(q);

        c_int::from(l == 2048 && (n == 224 || n == 256))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::object::RSA_new;

    /// The operation classing is the observable contract of `ossl_rsa_key_op_get_protect`: sign
    /// and encrypt are "protect", verify and decrypt are not, and an out-of-range operation is
    /// `ERR_R_INTERNAL_ERROR` rather than a silent `protect = 0`.
    #[test]
    fn the_operation_classing_is_the_authoritys() {
        // SAFETY: a fresh RSA object of this call's own.
        let rsa = unsafe { RSA_new() };
        assert!(!rsa.is_null());
        for (op, expect_ret, expect_protect) in [
            (EVP_PKEY_OP_SIGN, 1, 1),
            (EVP_PKEY_OP_SIGNMSG, 1, 1),
            (EVP_PKEY_OP_VERIFY, 1, 0),
            (EVP_PKEY_OP_VERIFYMSG, 1, 0),
            (EVP_PKEY_OP_ENCRYPT, 1, 1),
            (EVP_PKEY_OP_DECRYPT, 1, 0),
        ] {
            let mut protect = -1;
            // SAFETY: `rsa` is live and `protect` is this call's own.
            let ret = unsafe { ossl_rsa_key_op_get_protect(rsa, op, &mut protect) };
            assert_eq!(ret, expect_ret, "op {op}");
            assert_eq!(protect, expect_protect, "op {op}");
        }
        let mut protect = -1;
        // SAFETY: `rsa` is live and `protect` is this call's own; operation 0 is outside the eight.
        let refused = unsafe { ossl_rsa_key_op_get_protect(rsa, 0, &mut protect) };
        assert_eq!(refused, 0);
        // SAFETY: `rsa` is this call's own and is released once.
        unsafe { crate::rsa::object::RSA_free(rsa) };
    }
}
