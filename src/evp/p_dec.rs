//! `crypto/evp/p_dec.c` — `EVP_PKEY_decrypt_old`, the RSA-only legacy decrypt.
//!
//! One export, and its whole body is `evp_pkey_get0_RSA_int` (a type test plus
//! `evp_pkey_get_legacy`, `crypto/evp/p_legacy.c`'s) followed by one `RSA_private_decrypt` call
//! with PKCS#1 v1.5 padding. The brief for 8.8 placed it in `crypto/evp/p_lib.c`; the authority
//! defines it in `p_dec.c:21`, and this module is therefore its own unit's.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};

use crate::evp::p_legacy_assign::evp_pkey_get0_RSA_int;
use crate::evp::pkey::{EVP_PKEY_get_id, EvpPkey};
use crate::evp::pkey_ctx::{EVP_PKEY_RSA, RSA_PKCS1_PADDING};
use crate::rsa::object::RSA_private_decrypt;
use crate::runtime::err::{err_sites, raise_site};

/// `int EVP_PKEY_decrypt_old(unsigned char *key, const unsigned char *ek, int ekl,
/// EVP_PKEY *priv)` — `crypto/evp/p_dec.c:21`.
///
/// The result is `-1` on any refusal and the decrypt's own length on success, which is the
/// authority's `int ret = -1;` initialiser rather than a bare zero.
///
/// # Safety
/// `key`, `ek` and `priv` must be live per the call's own lengths; `key` is writable for the
/// decrypted plaintext and `ek` readable for `ekl` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decrypt_old(
    key: *mut c_uchar,
    ek: *const c_uchar,
    ekl: c_int,
    priv_: *mut EvpPkey,
) -> c_int {
    let mut ret: c_int = -1;

    // SAFETY: `priv_` is live per the contract.
    if unsafe { EVP_PKEY_get_id(priv_) } != EVP_PKEY_RSA {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_DEC_28) };
        return ret;
    }

    // SAFETY: `priv_` is live and this answers NULL for any non-RSA type, already refused above.
    let rsa = unsafe { evp_pkey_get0_RSA_int(priv_) };
    if rsa.is_null() {
        return ret;
    }

    // SAFETY: the caller's contract covers the buffers and `rsa` is live.
    ret = unsafe { RSA_private_decrypt(ekl, ek, key, rsa, RSA_PKCS1_PADDING) };
    ret
}
