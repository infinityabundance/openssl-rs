//! Phase 8 — `providers/common/digest_to_nid.c`: the name-to-NID resolver the provider
//! signature units use to decide whether a fetched digest is one they may sign or verify with.
//!
//! This is the DSA and ECDSA signature units' one non-FIPS prerequisite, beside their
//! `providers/common/der/` AlgorithmIdentifier writers. `dsa_setup_md` and its ECDSA sibling both
//! call `ossl_digest_get_approved_nid` on the fetched `EVP_MD` and refuse the operation with
//! `PROV_R_DIGEST_NOT_ALLOWED` when the answer is `NID_undef` — which is how a provider signature
//! row confines itself to the digests the provider publishes, rather than trusting the name the
//! caller supplied.
//!
//! ## What is here, and what is not
//!
//! `digest_to_nid.c` defines exactly two functions and both are transcribed. The rest of the
//! `providers/common/` security layer is separate units and is not landed:
//!
//!   * `securitycheck.c`'s nine key-size and curve checks are reached only from the
//!     `FIPS_MODULE` arms of the signature units, which are not this profile's — the DSA key
//!     check `ossl_dsa_check_key` is inside `dsa_sig.c.in`'s `#ifdef FIPS_MODULE` block at
//!     `:266`, and the ECDSA and RSA ones are the same shape. Two of its functions
//!     (`ossl_rsa_key_op_get_protect` and `ossl_digest_rsa_sign_get_md_nid`'s unit,
//!     `securitycheck_default.c`) *are* reached on this profile by `rsa_sig.c.in`, so they land
//!     with that unit rather than here.
//!   * `securitycheck_default.c`'s two functions, for the reason just given.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::evp::digest::{EVP_MD_is_a, EvpMd};
use crate::evp::pkey_ctx::{
    OSSL_DIGEST_NAME_SHA1, OSSL_DIGEST_NAME_SHA2_224, OSSL_DIGEST_NAME_SHA2_256,
    OSSL_DIGEST_NAME_SHA2_384, OSSL_DIGEST_NAME_SHA2_512, OSSL_DIGEST_NAME_SHA2_512_224,
    OSSL_DIGEST_NAME_SHA2_512_256,
};
use crate::runtime::obj::{
    NID_sha1, NID_sha224, NID_sha256, NID_sha384, NID_sha3_224, NID_sha3_256, NID_sha3_384,
    NID_sha3_512, NID_sha512, NID_sha512_224, NID_sha512_256, NID_undef,
};

/// `OSSL_DIGEST_NAME_SHA3_224` — `include/openssl/core_names.h:46`.
const OSSL_DIGEST_NAME_SHA3_224: *const c_char = c"SHA3-224".as_ptr();

/// `OSSL_DIGEST_NAME_SHA3_256` — `include/openssl/core_names.h:47`.
const OSSL_DIGEST_NAME_SHA3_256: *const c_char = c"SHA3-256".as_ptr();

/// `OSSL_DIGEST_NAME_SHA3_384` — `include/openssl/core_names.h:48`.
const OSSL_DIGEST_NAME_SHA3_384: *const c_char = c"SHA3-384".as_ptr();

/// `OSSL_DIGEST_NAME_SHA3_512` — `include/openssl/core_names.h:49`.
const OSSL_DIGEST_NAME_SHA3_512: *const c_char = c"SHA3-512".as_ptr();

/// `OSSL_ITEM` — `include/openssl/core.h`'s `struct ossl_item_st { int id; const char *ptr; }`.
///
/// The fields are `pub(crate)` because a second unit (`securitycheck_default.c`, transcribed as
/// `src/provider/securitycheck_default.rs`) declares its own seven-row map of the same type and
/// hands it to [`ossl_digest_md_to_nid`].
#[repr(C)]
pub(crate) struct OsslItem {
    pub(crate) id: c_int,
    pub(crate) ptr: *const c_char,
}

// SAFETY: every instance points at `'static` literals; nothing mutates a map.
unsafe impl Sync for OsslItem {}

/// `int ossl_digest_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it, size_t it_len)` —
/// `digest_to_nid.c:23-34`.
///
/// A linear walk of the caller's map, matched with `EVP_MD_is_a` so a digest is recognised by any
/// of its names rather than by one spelling.
///
/// # Safety
/// `it` is readable for `it_len` entries; every entry's `ptr` is NUL-terminated.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_digest_md_to_nid(
    md: *const EvpMd,
    it: *const OsslItem,
    it_len: usize,
) -> c_int {
    if md.is_null() {
        return NID_undef;
    }

    // SAFETY: `it` is readable for `it_len` entries and every `ptr` is a NUL-terminated string;
    // `md` is live.
    unsafe {
        for i in 0..it_len {
            if EVP_MD_is_a(md, (*it.add(i)).ptr) != 0 {
                return (*it.add(i)).id;
            }
        }
    }
    NID_undef
}

/// `static const OSSL_ITEM name_to_nid[]` — `digest_to_nid.c:43-55`, the eleven FIPS-approved
/// hashes of FIPS 180-4 and FIPS 202. The order is the file's: the four SHA-2s, the two truncated
/// ones, then the four SHA-3s.
static NAME_TO_NID: [OsslItem; 11] = [
    OsslItem {
        id: NID_sha1,
        ptr: OSSL_DIGEST_NAME_SHA1,
    },
    OsslItem {
        id: NID_sha224,
        ptr: OSSL_DIGEST_NAME_SHA2_224,
    },
    OsslItem {
        id: NID_sha256,
        ptr: OSSL_DIGEST_NAME_SHA2_256,
    },
    OsslItem {
        id: NID_sha384,
        ptr: OSSL_DIGEST_NAME_SHA2_384,
    },
    OsslItem {
        id: NID_sha512,
        ptr: OSSL_DIGEST_NAME_SHA2_512,
    },
    OsslItem {
        id: NID_sha512_224,
        ptr: OSSL_DIGEST_NAME_SHA2_512_224,
    },
    OsslItem {
        id: NID_sha512_256,
        ptr: OSSL_DIGEST_NAME_SHA2_512_256,
    },
    OsslItem {
        id: NID_sha3_224,
        ptr: OSSL_DIGEST_NAME_SHA3_224,
    },
    OsslItem {
        id: NID_sha3_256,
        ptr: OSSL_DIGEST_NAME_SHA3_256,
    },
    OsslItem {
        id: NID_sha3_384,
        ptr: OSSL_DIGEST_NAME_SHA3_384,
    },
    OsslItem {
        id: NID_sha3_512,
        ptr: OSSL_DIGEST_NAME_SHA3_512,
    },
];

/// `int ossl_digest_get_approved_nid(const EVP_MD *md)` — `digest_to_nid.c:40-58`.
///
/// # Safety
/// `md` is NULL or a live `EVP_MD`.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_digest_get_approved_nid(md: *const EvpMd) -> c_int {
    // SAFETY: the map is `'static` and its length is the array's own; `md` is the caller's.
    unsafe { ossl_digest_md_to_nid(md, NAME_TO_NID.as_ptr(), NAME_TO_NID.len()) }
}
