//! Phase 13.6 — `crypto/evp/c_allc.c`: `openssl_add_all_ciphers_int`.
//!
//! The legacy `EVP_CIPHER` statics that `src/evp/e_*.rs` build are inert until something
//! registers them in the `OBJ_NAME` cipher table, and this is that `something`. The authority's
//! `OPENSSL_init_crypto` calls it under `RUN_ONCE(&add_all_ciphers, ...)` for
//! `OPENSSL_INIT_ADD_ALL_CIPHERS`, and `EVP_get_cipherbyname`/`EVP_CIPHER_do_all` each call
//! `OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)` themselves — which is why
//! `EVP_get_cipherbyname` can answer at all once this lands.
//!
//! It also registers the table `set_legacy_nid` (`src/evp/cipher.rs`) searches: a fetched
//! provider cipher whose names include a legacy short name takes that method's NID from the
//! `EVP_CIPHER` this file inserted, which is the observable `D-EVP-CIPHER-LEGACY-NID-1` records.
//!
//! ## What is transcribed, and what is not
//!
//! One `EVP_add_cipher` per static and one `EVP_add_cipher_alias` per alias, in the authority's
//! order. `EVP_add_cipher_alias` is a macro over `OBJ_NAME_add` in `evp.h`, so the alias calls go
//! straight to `OBJ_NAME_add` with the same type expression the macro expands to.
//! `EVP_aes_128_cfb` and its eight siblings are macros over the `cfb128` accessors, so the crate
//! names are the `_cfb128` ones.
//!
//! The `OPENSSL_NO_RC5` block is not transcribed: the admitted profile is configured `no-rc5`
//! (`forensics/authorities/build/openssl-3.6.4-production/configdata.pm`), so the authority's
//! `EVP_rc5_*` calls are compiled out and the crate has no `e_rc5.rs` to name.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::evp::cipher::{EvpCipher, OBJ_NAME_TYPE_CIPHER_METH};
use crate::evp::e_aes::{
    EVP_aes_128_cbc, EVP_aes_128_ccm, EVP_aes_128_cfb1, EVP_aes_128_cfb128, EVP_aes_128_cfb8,
    EVP_aes_128_ctr, EVP_aes_128_ecb, EVP_aes_128_gcm, EVP_aes_128_ocb, EVP_aes_128_ofb,
    EVP_aes_128_wrap, EVP_aes_128_wrap_pad, EVP_aes_128_xts, EVP_aes_192_cbc, EVP_aes_192_ccm,
    EVP_aes_192_cfb1, EVP_aes_192_cfb128, EVP_aes_192_cfb8, EVP_aes_192_ctr, EVP_aes_192_ecb,
    EVP_aes_192_gcm, EVP_aes_192_ocb, EVP_aes_192_ofb, EVP_aes_192_wrap, EVP_aes_192_wrap_pad,
    EVP_aes_256_cbc, EVP_aes_256_ccm, EVP_aes_256_cfb1, EVP_aes_256_cfb128, EVP_aes_256_cfb8,
    EVP_aes_256_ctr, EVP_aes_256_ecb, EVP_aes_256_gcm, EVP_aes_256_ocb, EVP_aes_256_ofb,
    EVP_aes_256_wrap, EVP_aes_256_wrap_pad, EVP_aes_256_xts,
};
use crate::evp::e_aes_cbc_hmac_sha1::{EVP_aes_128_cbc_hmac_sha1, EVP_aes_256_cbc_hmac_sha1};
use crate::evp::e_aes_cbc_hmac_sha256::{EVP_aes_128_cbc_hmac_sha256, EVP_aes_256_cbc_hmac_sha256};
use crate::evp::e_aria::{
    EVP_aria_128_cbc, EVP_aria_128_ccm, EVP_aria_128_cfb1, EVP_aria_128_cfb128, EVP_aria_128_cfb8,
    EVP_aria_128_ctr, EVP_aria_128_ecb, EVP_aria_128_gcm, EVP_aria_128_ofb, EVP_aria_192_cbc,
    EVP_aria_192_ccm, EVP_aria_192_cfb1, EVP_aria_192_cfb128, EVP_aria_192_cfb8, EVP_aria_192_ctr,
    EVP_aria_192_ecb, EVP_aria_192_gcm, EVP_aria_192_ofb, EVP_aria_256_cbc, EVP_aria_256_ccm,
    EVP_aria_256_cfb1, EVP_aria_256_cfb128, EVP_aria_256_cfb8, EVP_aria_256_ctr, EVP_aria_256_ecb,
    EVP_aria_256_gcm, EVP_aria_256_ofb,
};
use crate::evp::e_bf::{EVP_bf_cbc, EVP_bf_cfb64, EVP_bf_ecb, EVP_bf_ofb};
use crate::evp::e_camellia::{
    EVP_camellia_128_cbc, EVP_camellia_128_cfb1, EVP_camellia_128_cfb128, EVP_camellia_128_cfb8,
    EVP_camellia_128_ctr, EVP_camellia_128_ecb, EVP_camellia_128_ofb, EVP_camellia_192_cbc,
    EVP_camellia_192_cfb1, EVP_camellia_192_cfb128, EVP_camellia_192_cfb8, EVP_camellia_192_ctr,
    EVP_camellia_192_ecb, EVP_camellia_192_ofb, EVP_camellia_256_cbc, EVP_camellia_256_cfb1,
    EVP_camellia_256_cfb128, EVP_camellia_256_cfb8, EVP_camellia_256_ctr, EVP_camellia_256_ecb,
    EVP_camellia_256_ofb,
};
use crate::evp::e_cast::{EVP_cast5_cbc, EVP_cast5_cfb64, EVP_cast5_ecb, EVP_cast5_ofb};
use crate::evp::e_chacha20_poly1305::{EVP_chacha20, EVP_chacha20_poly1305};
use crate::evp::e_des::{
    EVP_des_cbc, EVP_des_cfb1, EVP_des_cfb64, EVP_des_cfb8, EVP_des_ecb, EVP_des_ofb,
};
use crate::evp::e_des3::{
    EVP_des_ede, EVP_des_ede3, EVP_des_ede3_cbc, EVP_des_ede3_cfb1, EVP_des_ede3_cfb64,
    EVP_des_ede3_cfb8, EVP_des_ede3_ofb, EVP_des_ede3_wrap, EVP_des_ede_cbc, EVP_des_ede_cfb64,
    EVP_des_ede_ofb,
};
use crate::evp::e_idea::{EVP_idea_cbc, EVP_idea_cfb64, EVP_idea_ecb, EVP_idea_ofb};
use crate::evp::e_rc2::{
    EVP_rc2_40_cbc, EVP_rc2_64_cbc, EVP_rc2_cbc, EVP_rc2_cfb64, EVP_rc2_ecb, EVP_rc2_ofb,
};
use crate::evp::e_rc4::{EVP_rc4, EVP_rc4_40};
use crate::evp::e_rc4_hmac_md5::EVP_rc4_hmac_md5;
use crate::evp::e_seed::{EVP_seed_cbc, EVP_seed_cfb128, EVP_seed_ecb, EVP_seed_ofb};
use crate::evp::e_sm4::{EVP_sm4_cbc, EVP_sm4_cfb128, EVP_sm4_ctr, EVP_sm4_ecb, EVP_sm4_ofb};
use crate::evp::e_xcbc_d::EVP_desx_cbc;
use crate::evp::legacy_evp::EVP_add_cipher;
use crate::runtime::obj::{
    NID_aes_128_cbc, NID_aes_192_cbc, NID_aes_256_cbc, NID_aria_128_cbc, NID_aria_192_cbc,
    NID_aria_256_cbc, NID_bf_cbc, NID_camellia_128_cbc, NID_camellia_192_cbc, NID_camellia_256_cbc,
    NID_cast5_cbc, NID_des_cbc, NID_des_ede3_cbc, NID_des_ede3_ecb, NID_des_ede_ecb, NID_desx_cbc,
    NID_id_aes128_wrap, NID_id_aes128_wrap_pad, NID_id_aes192_wrap, NID_id_aes192_wrap_pad,
    NID_id_aes256_wrap, NID_id_aes256_wrap_pad, NID_id_smime_alg_CMS3DESwrap, NID_idea_cbc,
    NID_rc2_40_cbc, NID_rc2_64_cbc, NID_rc2_cbc, NID_seed_cbc, NID_sm4_cbc, OBJ_NAME_add,
    OBJ_nid2sn, OBJ_NAME_ALIAS,
};

/// `EVP_add_cipher`'s answer is ignored here exactly as `c_allc.c` ignores it.
///
/// # Safety
/// `c` must be a live `EVP_CIPHER` (every caller hands one of the accessor statics).
unsafe fn add(c: *const EvpCipher) {
    // SAFETY: `c` is live per the contract.
    let _ = unsafe { EVP_add_cipher(c) };
}

/// The `EVP_add_cipher_alias(n, alias)` macro from `include/openssl/evp.h`.
///
/// # Safety
/// `alias` must be a static NUL-terminated string.
unsafe fn alias(target_nid: c_int, alias_name: *const c_char) {
    // SAFETY: `alias_name` is a static string and `OBJ_nid2sn` answers a static for a NID the
    // object table holds, both borrowed by the table.
    unsafe {
        OBJ_NAME_add(
            alias_name,
            OBJ_NAME_TYPE_CIPHER_METH | OBJ_NAME_ALIAS,
            OBJ_nid2sn(target_nid),
        );
    }
}

/// `void openssl_add_all_ciphers_int(void)` — `crypto/evp/c_allc.c`.
///
/// Not an export: the authority keeps it local to `libcrypto.so.3` (its `nm` binding is `t`), so
/// it is `pub(crate)` and reached only from `OPENSSL_init_crypto`.
pub(crate) fn openssl_add_all_ciphers_int() {
    // SAFETY: every pointer handed to `add` is one of the crate's own live statics and every
    // alias name is a `c"..."` literal.
    unsafe {
        add(EVP_des_cfb64());
        add(EVP_des_cfb1());
        add(EVP_des_cfb8());
        add(EVP_des_ede_cfb64());
        add(EVP_des_ede3_cfb64());
        add(EVP_des_ede3_cfb1());
        add(EVP_des_ede3_cfb8());

        add(EVP_des_ofb());
        add(EVP_des_ede_ofb());
        add(EVP_des_ede3_ofb());

        add(EVP_desx_cbc());
        alias(NID_desx_cbc, c"DESX".as_ptr());
        alias(NID_desx_cbc, c"desx".as_ptr());

        add(EVP_des_cbc());
        alias(NID_des_cbc, c"DES".as_ptr());
        alias(NID_des_cbc, c"des".as_ptr());
        add(EVP_des_ede_cbc());
        add(EVP_des_ede3_cbc());
        alias(NID_des_ede3_cbc, c"DES3".as_ptr());
        alias(NID_des_ede3_cbc, c"des3".as_ptr());

        add(EVP_des_ecb());
        add(EVP_des_ede());
        alias(NID_des_ede_ecb, c"DES-EDE-ECB".as_ptr());
        alias(NID_des_ede_ecb, c"des-ede-ecb".as_ptr());
        add(EVP_des_ede3());
        alias(NID_des_ede3_ecb, c"DES-EDE3-ECB".as_ptr());
        alias(NID_des_ede3_ecb, c"des-ede3-ecb".as_ptr());
        add(EVP_des_ede3_wrap());
        alias(NID_id_smime_alg_CMS3DESwrap, c"des3-wrap".as_ptr());

        add(EVP_rc4());
        add(EVP_rc4_40());
        add(EVP_rc4_hmac_md5());

        add(EVP_idea_ecb());
        add(EVP_idea_cfb64());
        add(EVP_idea_ofb());
        add(EVP_idea_cbc());
        alias(NID_idea_cbc, c"IDEA".as_ptr());
        alias(NID_idea_cbc, c"idea".as_ptr());

        add(EVP_seed_ecb());
        add(EVP_seed_cfb128());
        add(EVP_seed_ofb());
        add(EVP_seed_cbc());
        alias(NID_seed_cbc, c"SEED".as_ptr());
        alias(NID_seed_cbc, c"seed".as_ptr());

        add(EVP_sm4_ecb());
        add(EVP_sm4_cbc());
        add(EVP_sm4_cfb128());
        add(EVP_sm4_ofb());
        add(EVP_sm4_ctr());
        alias(NID_sm4_cbc, c"SM4".as_ptr());
        alias(NID_sm4_cbc, c"sm4".as_ptr());

        add(EVP_rc2_ecb());
        add(EVP_rc2_cfb64());
        add(EVP_rc2_ofb());
        add(EVP_rc2_cbc());
        add(EVP_rc2_40_cbc());
        add(EVP_rc2_64_cbc());
        alias(NID_rc2_cbc, c"RC2".as_ptr());
        alias(NID_rc2_cbc, c"rc2".as_ptr());
        alias(NID_rc2_cbc, c"rc2-128".as_ptr());
        alias(NID_rc2_64_cbc, c"rc2-64".as_ptr());
        alias(NID_rc2_40_cbc, c"rc2-40".as_ptr());

        add(EVP_bf_ecb());
        add(EVP_bf_cfb64());
        add(EVP_bf_ofb());
        add(EVP_bf_cbc());
        alias(NID_bf_cbc, c"BF".as_ptr());
        alias(NID_bf_cbc, c"bf".as_ptr());
        alias(NID_bf_cbc, c"blowfish".as_ptr());

        add(EVP_cast5_ecb());
        add(EVP_cast5_cfb64());
        add(EVP_cast5_ofb());
        add(EVP_cast5_cbc());
        alias(NID_cast5_cbc, c"CAST".as_ptr());
        alias(NID_cast5_cbc, c"cast".as_ptr());
        alias(NID_cast5_cbc, c"CAST-cbc".as_ptr());
        alias(NID_cast5_cbc, c"cast-cbc".as_ptr());

        add(EVP_aes_128_ecb());
        add(EVP_aes_128_cbc());
        add(EVP_aes_128_cfb128());
        add(EVP_aes_128_cfb1());
        add(EVP_aes_128_cfb8());
        add(EVP_aes_128_ofb());
        add(EVP_aes_128_ctr());
        add(EVP_aes_128_gcm());
        add(EVP_aes_128_ocb());
        add(EVP_aes_128_xts());
        add(EVP_aes_128_ccm());
        add(EVP_aes_128_wrap());
        alias(NID_id_aes128_wrap, c"aes128-wrap".as_ptr());
        add(EVP_aes_128_wrap_pad());
        alias(NID_id_aes128_wrap_pad, c"aes128-wrap-pad".as_ptr());
        alias(NID_aes_128_cbc, c"AES128".as_ptr());
        alias(NID_aes_128_cbc, c"aes128".as_ptr());
        add(EVP_aes_192_ecb());
        add(EVP_aes_192_cbc());
        add(EVP_aes_192_cfb128());
        add(EVP_aes_192_cfb1());
        add(EVP_aes_192_cfb8());
        add(EVP_aes_192_ofb());
        add(EVP_aes_192_ctr());
        add(EVP_aes_192_gcm());
        add(EVP_aes_192_ocb());
        add(EVP_aes_192_ccm());
        add(EVP_aes_192_wrap());
        alias(NID_id_aes192_wrap, c"aes192-wrap".as_ptr());
        add(EVP_aes_192_wrap_pad());
        alias(NID_id_aes192_wrap_pad, c"aes192-wrap-pad".as_ptr());
        alias(NID_aes_192_cbc, c"AES192".as_ptr());
        alias(NID_aes_192_cbc, c"aes192".as_ptr());
        add(EVP_aes_256_ecb());
        add(EVP_aes_256_cbc());
        add(EVP_aes_256_cfb128());
        add(EVP_aes_256_cfb1());
        add(EVP_aes_256_cfb8());
        add(EVP_aes_256_ofb());
        add(EVP_aes_256_ctr());
        add(EVP_aes_256_gcm());
        add(EVP_aes_256_ocb());
        add(EVP_aes_256_xts());
        add(EVP_aes_256_ccm());
        add(EVP_aes_256_wrap());
        alias(NID_id_aes256_wrap, c"aes256-wrap".as_ptr());
        add(EVP_aes_256_wrap_pad());
        alias(NID_id_aes256_wrap_pad, c"aes256-wrap-pad".as_ptr());
        alias(NID_aes_256_cbc, c"AES256".as_ptr());
        alias(NID_aes_256_cbc, c"aes256".as_ptr());
        add(EVP_aes_128_cbc_hmac_sha1());
        add(EVP_aes_256_cbc_hmac_sha1());
        add(EVP_aes_128_cbc_hmac_sha256());
        add(EVP_aes_256_cbc_hmac_sha256());

        add(EVP_aria_128_ecb());
        add(EVP_aria_128_cbc());
        add(EVP_aria_128_cfb128());
        add(EVP_aria_128_cfb1());
        add(EVP_aria_128_cfb8());
        add(EVP_aria_128_ctr());
        add(EVP_aria_128_ofb());
        add(EVP_aria_128_gcm());
        add(EVP_aria_128_ccm());
        alias(NID_aria_128_cbc, c"ARIA128".as_ptr());
        alias(NID_aria_128_cbc, c"aria128".as_ptr());
        add(EVP_aria_192_ecb());
        add(EVP_aria_192_cbc());
        add(EVP_aria_192_cfb128());
        add(EVP_aria_192_cfb1());
        add(EVP_aria_192_cfb8());
        add(EVP_aria_192_ctr());
        add(EVP_aria_192_ofb());
        add(EVP_aria_192_gcm());
        add(EVP_aria_192_ccm());
        alias(NID_aria_192_cbc, c"ARIA192".as_ptr());
        alias(NID_aria_192_cbc, c"aria192".as_ptr());
        add(EVP_aria_256_ecb());
        add(EVP_aria_256_cbc());
        add(EVP_aria_256_cfb128());
        add(EVP_aria_256_cfb1());
        add(EVP_aria_256_cfb8());
        add(EVP_aria_256_ctr());
        add(EVP_aria_256_ofb());
        add(EVP_aria_256_gcm());
        add(EVP_aria_256_ccm());
        alias(NID_aria_256_cbc, c"ARIA256".as_ptr());
        alias(NID_aria_256_cbc, c"aria256".as_ptr());

        add(EVP_camellia_128_ecb());
        add(EVP_camellia_128_cbc());
        add(EVP_camellia_128_cfb128());
        add(EVP_camellia_128_cfb1());
        add(EVP_camellia_128_cfb8());
        add(EVP_camellia_128_ofb());
        alias(NID_camellia_128_cbc, c"CAMELLIA128".as_ptr());
        alias(NID_camellia_128_cbc, c"camellia128".as_ptr());
        add(EVP_camellia_192_ecb());
        add(EVP_camellia_192_cbc());
        add(EVP_camellia_192_cfb128());
        add(EVP_camellia_192_cfb1());
        add(EVP_camellia_192_cfb8());
        add(EVP_camellia_192_ofb());
        alias(NID_camellia_192_cbc, c"CAMELLIA192".as_ptr());
        alias(NID_camellia_192_cbc, c"camellia192".as_ptr());
        add(EVP_camellia_256_ecb());
        add(EVP_camellia_256_cbc());
        add(EVP_camellia_256_cfb128());
        add(EVP_camellia_256_cfb1());
        add(EVP_camellia_256_cfb8());
        add(EVP_camellia_256_ofb());
        alias(NID_camellia_256_cbc, c"CAMELLIA256".as_ptr());
        alias(NID_camellia_256_cbc, c"camellia256".as_ptr());
        add(EVP_camellia_128_ctr());
        add(EVP_camellia_192_ctr());
        add(EVP_camellia_256_ctr());

        add(EVP_chacha20());
        add(EVP_chacha20_poly1305());
    }
}
