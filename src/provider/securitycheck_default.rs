//! Phase 8 — `providers/common/securitycheck_default.c`: the default provider's security-check
//! policy and its RSA digest map.
//!
//! This unit is the fourth of `rsa_sig.c.in`'s non-FIPS prerequisites. Both of its functions are
//! transcribed whole (D327):
//!
//!   * `ossl_digest_rsa_sign_get_md_nid` is called by `rsa_setup_md` (`rsa_sig.c.in:394`) and
//!     `rsa_setup_mgf1_md` (`:485`) — it is a superset of `ossl_digest_get_approved_nid`
//!     (`src/provider/digest_to_nid.rs`) that also accepts the five legacy digests RSA signatures
//!     may be made over, so it is what lets `RSA-MD5`, `RSA-RIPEMD160` and their siblings fetch a
//!     digest at all.
//!   * `ossl_fips_config_securitycheck_enabled` returns **0** — the default provider's own
//!     statement that FIPS key checks are *disabled* here. It is reached only from the
//!     `OSSL_FIPS_IND_*` machinery, which is not this profile's arm, so it carries a stated
//!     `#[allow(dead_code)]` rather than being dropped.
//!
//! The seven-row map is the file's own, and its order is the authority's: it is a linear walk, so
//! `MD5` is tried before `MD5-SHA1` and a digest that answers to both names resolves to `NID_md5`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::evp::digest::EvpMd;
use crate::provider::digest_to_nid::{
    ossl_digest_get_approved_nid, ossl_digest_md_to_nid, OsslItem,
};
use crate::runtime::obj::{
    NID_md2, NID_md4, NID_md5, NID_md5_sha1, NID_mdc2, NID_ripemd160, NID_sm3, NID_undef,
};

/// `OSSL_DIGEST_NAME_MD5` — `include/openssl/core_names.h:33`.
const OSSL_DIGEST_NAME_MD5: *const c_char = c"MD5".as_ptr();
/// `OSSL_DIGEST_NAME_MD5_SHA1` — `core_names.h:36`.
const OSSL_DIGEST_NAME_MD5_SHA1: *const c_char = c"MD5-SHA1".as_ptr();
/// `OSSL_DIGEST_NAME_MD2` — `core_names.h:30`. `MD2` is deprecated 3.0 but the name is live.
const OSSL_DIGEST_NAME_MD2: *const c_char = c"MD2".as_ptr();
/// `OSSL_DIGEST_NAME_MD4` — `core_names.h:31`.
const OSSL_DIGEST_NAME_MD4: *const c_char = c"MD4".as_ptr();
/// `OSSL_DIGEST_NAME_MDC2` — `core_names.h:34`.
const OSSL_DIGEST_NAME_MDC2: *const c_char = c"MDC2".as_ptr();
/// `OSSL_DIGEST_NAME_RIPEMD160` — `core_names.h:35`.
const OSSL_DIGEST_NAME_RIPEMD160: *const c_char = c"RIPEMD160".as_ptr();
/// `OSSL_DIGEST_NAME_SM3` — `core_names.h:52`.
const OSSL_DIGEST_NAME_SM3: *const c_char = c"SM3".as_ptr();

/// `int ossl_fips_config_securitycheck_enabled(OSSL_LIB_CTX *libctx)` —
/// `securitycheck_default.c:20-23`. The default provider answers **0**: security checks are off.
#[allow(dead_code)] // reached only from the FIPS indicator machinery, not this profile's arm
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) fn ossl_fips_config_securitycheck_enabled(_libctx: *mut c_void) -> c_int {
    0
}

/// `static const OSSL_ITEM name_to_nid[]` — `securitycheck_default.c:29-37`, the seven digests an
/// RSA signature may be made over that `ossl_digest_get_approved_nid` alone does not cover.
static NAME_TO_NID: [OsslItem; 7] = [
    OsslItem {
        id: NID_md5,
        ptr: OSSL_DIGEST_NAME_MD5,
    },
    OsslItem {
        id: NID_md5_sha1,
        ptr: OSSL_DIGEST_NAME_MD5_SHA1,
    },
    OsslItem {
        id: NID_md2,
        ptr: OSSL_DIGEST_NAME_MD2,
    },
    OsslItem {
        id: NID_md4,
        ptr: OSSL_DIGEST_NAME_MD4,
    },
    OsslItem {
        id: NID_mdc2,
        ptr: OSSL_DIGEST_NAME_MDC2,
    },
    OsslItem {
        id: NID_ripemd160,
        ptr: OSSL_DIGEST_NAME_RIPEMD160,
    },
    OsslItem {
        id: NID_sm3,
        ptr: OSSL_DIGEST_NAME_SM3,
    },
];

/// `int ossl_digest_rsa_sign_get_md_nid(const EVP_MD *md)` — `securitycheck_default.c:25-43`.
///
/// The approved-digest answer first, and only when it is `NID_undef` the seven-row RSA map. So a
/// `SHA256` resolves through the approved table and a `MD5` through this one; the union is what
/// `rsa_setup_md` treats as "a digest this provider may sign with".
///
/// # Safety
/// `md` is NULL or a live `EVP_MD`.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_digest_rsa_sign_get_md_nid(md: *const EvpMd) -> c_int {
    // SAFETY: `md` is NULL or live per the contract; the map is `'static`.
    unsafe {
        let mut mdnid = ossl_digest_get_approved_nid(md);
        if mdnid == NID_undef {
            mdnid = ossl_digest_md_to_nid(md, NAME_TO_NID.as_ptr(), NAME_TO_NID.len());
        }
        mdnid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The map is a superset of the approved table: `MD5` resolves to `NID_md5` here (it is not
    /// approved), and a NULL `EVP_MD` resolves to `NID_undef` through both halves.
    #[test]
    fn the_null_digest_resolves_to_undef() {
        // SAFETY: NULL is the documented "no digest" input to both halves.
        let nid = unsafe { ossl_digest_rsa_sign_get_md_nid(core::ptr::null()) };
        assert_eq!(nid, NID_undef);
    }

    /// The seven rows are the authority's, in its order, and each names its own NID.
    #[test]
    fn the_seven_rows_are_the_authoritys() {
        assert_eq!(NAME_TO_NID.len(), 7);
        assert_eq!(NAME_TO_NID[0].id, NID_md5);
        assert_eq!(NAME_TO_NID[1].id, NID_md5_sha1);
        assert_eq!(NAME_TO_NID[2].id, NID_md2);
        assert_eq!(NAME_TO_NID[3].id, NID_md4);
        assert_eq!(NAME_TO_NID[4].id, NID_mdc2);
        assert_eq!(NAME_TO_NID[5].id, NID_ripemd160);
        assert_eq!(NAME_TO_NID[6].id, NID_sm3);
    }
}
