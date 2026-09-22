//! `crypto/evp/p_enc.c` — `EVP_PKEY_encrypt_old`, the RSA-only legacy encrypt.
//!
//! One export, and its whole body is `evp_pkey_get0_RSA_int` (a type test plus
//! `evp_pkey_get_legacy`, `crypto/evp/p_legacy.c`'s) followed by one `RSA_public_encrypt` call
//! with PKCS#1 v1.5 padding. The brief for 8.8 placed it in `crypto/evp/p_lib.c`; the authority
//! defines it in `p_enc.c:21`, and this module is therefore its own unit's.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};

use crate::evp::p_legacy_assign::evp_pkey_get0_RSA_int;
use crate::evp::pkey::{EVP_PKEY_get_id, EvpPkey};
use crate::evp::pkey_ctx::{EVP_PKEY_RSA, RSA_PKCS1_PADDING};
use crate::rsa::object::RSA_public_encrypt;
use crate::runtime::err::{err_sites, raise_site};

/// `int EVP_PKEY_encrypt_old(unsigned char *ek, const unsigned char *key, int key_len,
/// EVP_PKEY *pubk)` — `crypto/evp/p_enc.c:21`.
///
/// The result is `0` on any refusal and the ciphertext length on success, which is the authority's
/// `int ret = 0;` initialiser — the sibling of `EVP_PKEY_decrypt_old`'s `-1`.
///
/// # Safety
/// `ek`, `key` and `pubk` must be live per the call's own lengths; `ek` is writable for the
/// ciphertext and `key` readable for `key_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encrypt_old(
    ek: *mut c_uchar,
    key: *const c_uchar,
    key_len: c_int,
    pubk: *mut EvpPkey,
) -> c_int {
    let mut ret: c_int = 0;

    // SAFETY: `pubk` is live per the contract.
    if unsafe { EVP_PKEY_get_id(pubk) } != EVP_PKEY_RSA {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_ENC_28) };
        return ret;
    }

    // SAFETY: `pubk` is live and this answers NULL for any non-RSA type, already refused above.
    let rsa = unsafe { evp_pkey_get0_RSA_int(pubk) };
    if rsa.is_null() {
        return ret;
    }

    // SAFETY: the caller's contract covers the buffers and `rsa` is live.
    ret = unsafe { RSA_public_encrypt(key_len, key, ek, rsa, RSA_PKCS1_PADDING) };
    ret
}
