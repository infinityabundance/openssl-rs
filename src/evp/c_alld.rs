//! Phase 13.6 — `crypto/evp/c_alld.c`: `openssl_add_all_digests_int`.
//!
//! The digest half of the legacy `OBJ_NAME` registration `src/evp/c_allc.rs` does for ciphers.
//! `OPENSSL_init_crypto` calls it for `OPENSSL_INIT_ADD_DIGESTS`, and `EVP_get_digestbyname` and
//! `EVP_MD_do_all` each call `OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)`
//! themselves — so a legacy digest name answers from the table exactly as the authority's does.
//!
//! `EVP_add_digest` reads each method's `type` and registers both the short and long name, and
//! then — when `pkey_type` names a different object — that object's short and long names as
//! `EVP_NAME_ALIAS` entries. The extra `EVP_add_digest_alias` calls below are the authority's own
//! four (`ssl3-md5`, `ssl3-sha1`, and the two `ripemd` spellings) plus the `sha1WithRSA` alias of
//! `sha1WithRSAEncryption`; `EVP_add_digest_alias` is a macro over `OBJ_NAME_add`.
//!
//! `no-md2` is configured for the admitted profile, so `EVP_md2` is not in the authority's list
//! and is not here either.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::evp::digest::{EvpMd, OBJ_NAME_TYPE_MD_METH};
use crate::evp::legacy_blake2::{EVP_blake2b512, EVP_blake2s256};
use crate::evp::legacy_evp::EVP_add_digest;
use crate::evp::legacy_md4::EVP_md4;
use crate::evp::legacy_md5::{EVP_md5, EVP_md5_sha1};
use crate::evp::legacy_mdc2::EVP_mdc2;
use crate::evp::legacy_ripemd::EVP_ripemd160;
use crate::evp::legacy_sha::{
    EVP_sha1, EVP_sha224, EVP_sha256, EVP_sha384, EVP_sha512, EVP_sha512_224, EVP_sha512_256,
};
use crate::evp::legacy_sha3::{EVP_sha3_224, EVP_sha3_256, EVP_sha3_384, EVP_sha3_512};
use crate::evp::legacy_sha3::{EVP_shake128, EVP_shake256};
use crate::evp::legacy_wp::EVP_whirlpool;
use crate::legacy_sm3::EVP_sm3;
use crate::runtime::obj::{
    NID_md5, NID_ripemd160, NID_sha1, NID_sha1WithRSAEncryption, OBJ_NAME_add, OBJ_nid2sn,
    OBJ_NAME_ALIAS,
};

/// `EVP_add_digest`'s answer is ignored here exactly as `c_alld.c` ignores it.
///
/// # Safety
/// `md` must be a live `EVP_MD` (every caller hands one of the accessor statics).
unsafe fn add(md: *const EvpMd) {
    // SAFETY: `md` is live per the contract.
    let _ = unsafe { EVP_add_digest(md) };
}

/// The `EVP_add_digest_alias(n, alias)` macro from `include/openssl/evp.h`.
///
/// # Safety
/// `alias_name` must be a static NUL-terminated string.
unsafe fn alias(target_nid: c_int, alias_name: *const c_char) {
    // SAFETY: `alias_name` is a static string and `OBJ_nid2sn` answers a static for a NID the
    // object table holds, both borrowed by the table.
    unsafe {
        OBJ_NAME_add(
            alias_name,
            OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS,
            OBJ_nid2sn(target_nid),
        );
    }
}

/// `void openssl_add_all_digests_int(void)` — `crypto/evp/c_alld.c`.
///
/// Not an export: the authority keeps it local to `libcrypto.so.3`, so it is `pub(crate)` and
/// reached only from `OPENSSL_init_crypto`.
pub(crate) fn openssl_add_all_digests_int() {
    // SAFETY: every pointer handed to `add` is one of the crate's own live statics and every
    // alias name is a `c"..."` literal.
    unsafe {
        add(EVP_md4());
        add(EVP_md5());
        alias(NID_md5, c"ssl3-md5".as_ptr());
        add(EVP_md5_sha1());
        add(EVP_sha1());
        alias(NID_sha1, c"ssl3-sha1".as_ptr());
        alias(NID_sha1WithRSAEncryption, c"sha1WithRSA".as_ptr());
        add(EVP_mdc2());
        add(EVP_ripemd160());
        alias(NID_ripemd160, c"ripemd".as_ptr());
        alias(NID_ripemd160, c"rmd160".as_ptr());
        add(EVP_sha224());
        add(EVP_sha256());
        add(EVP_sha384());
        add(EVP_sha512());
        add(EVP_sha512_224());
        add(EVP_sha512_256());
        add(EVP_whirlpool());
        add(EVP_sm3());
        add(EVP_blake2b512());
        add(EVP_blake2s256());
        add(EVP_sha3_224());
        add(EVP_sha3_256());
        add(EVP_sha3_384());
        add(EVP_sha3_512());
        add(EVP_shake128());
        add(EVP_shake256());
    }
}
