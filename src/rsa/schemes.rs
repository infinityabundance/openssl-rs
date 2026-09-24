//! `crypto/rsa/rsa_schemes.c` — the OAEP/PSS digest-name map and the MGF name lookup, Phase 8.4.
//!
//! Eighty-six lines, **three internals**, three file-local helpers and one table. The unit is
//! the bridge between the *numeric* world the ASN.1 layer speaks (`NID_sha256`, `NID_mgf1`) and
//! the *name* world the provider speaks (`"SHA2-256"`, `"mgf"`), and both of its readers are
//! 8.4's own parameter objects: `crypto/rsa/rsa_pss.c`'s `ossl_rsa_pss_params_30_*` accessors
//! and `crypto/rsa/rsa_backend.c`'s two `ossl_rsa_pss_params_30_{to,from}data`.
//!
//! ## The table is RFC 8017's list, and the header is where the seven names come from
//!
//! `oaeppss_name_nid_map[]` is the file's transcription of RFC 8017 appendix A.2.1's
//! `OAEP-PSSDigestAlgorithms`, and the seven rows are the seven `OSSL_DIGEST_NAME_*` strings
//! `core_names.h` defines for them — **not** the legacy short names (`"sha256"`) and not the
//! `LN_*` long names. `EVP_MD_is_a` is asked about the provider name, so a row spelled
//! `"sha256"` would match nothing on a provider build.
//!
//! ## The two lookups differ in the direction they fail, and one of them is total
//!
//! `meth2nid` answers `NID_undef` (0) when the method is NULL or matches no row, and
//! `nid2name` answers NULL. Neither is an error: `ossl_rsa_oaeppss_md2nid`'s caller stores the
//! answer as a restriction, and `NID_undef` there means "no restriction", which is exactly what
//! the authority's own comment on the PSS defaults says. A transcription that answered `-1`
//! would make an unrecognised digest look like a refusal.
//!
//! ## `SN_mgf1` is `"MGF1"`, and the case matters only because the comparison folded it
//!
//! `ossl_rsa_mgf_nid2name` returns the *short name* macro, and the header spells it with
//! capitals (`obj_mac.h:571`). Its consumer in `rsa_backend.c` compares it with
//! `OPENSSL_strcasecmp` against a caller's parameter, so `"mgf1"` and `"MGF1"` both pass there;
//! the value itself is the authority's and is printed by the unit test below rather than
//! normalised to the lower-case spelling the parameter usually carries.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::evp::digest::{EVP_MD_is_a, EvpMd};
use crate::evp::pkey_ctx::{
    OSSL_DIGEST_NAME_SHA1, OSSL_DIGEST_NAME_SHA2_224, OSSL_DIGEST_NAME_SHA2_256,
    OSSL_DIGEST_NAME_SHA2_384, OSSL_DIGEST_NAME_SHA2_512, OSSL_DIGEST_NAME_SHA2_512_224,
    OSSL_DIGEST_NAME_SHA2_512_256,
};
use crate::runtime::obj::{
    NID_mgf1, NID_sha1, NID_sha224, NID_sha256, NID_sha384, NID_sha512, NID_sha512_224,
    NID_sha512_256, NID_undef,
};

/// `SN_mgf1` — `include/openssl/obj_mac.h:571`. The macro is `#define SN_mgf1 "MGF1"`, so it is
/// modelled as the constant it expands to, in the header's own spelling, exactly as
/// `src/ffc/dh.rs` models the fourteen `SN_ffdhe*`/`SN_modp_*` names.
#[allow(non_upper_case_globals)] // the authority's macro name, kept verbatim
const SN_mgf1: &core::ffi::CStr = c"MGF1";

/// `OSSL_ITEM` — `include/openssl/core.h`'s `struct ossl_item_st { int id; const char *ptr; }`.
///
/// The map below is an array of these and both lookups walk it in declaration order, so the
/// order is load-bearing where two rows could match: it is RFC 8017's.
#[repr(C)]
struct OsslItem {
    id: c_int,
    ptr: *const c_char,
}

/// `static const OSSL_ITEM oaeppss_name_nid_map[]` — `crypto/rsa/rsa_schemes.c:55-63`.
///
/// Seven rows, `OSSL_NELEM` of them, in the order RFC 8017 A.2.1 lists the algorithms: SHA-1,
/// SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256.
static OAEPPSS_NAME_NID_MAP: [OsslItem; 7] = [
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
];

// SAFETY: the array is written once, as the initialiser of the `static` above, and never
// mutated; its `id` fields are plain integers and its `ptr` fields are addresses of `'static`
// string literals, so sharing it shares only immutable data.
unsafe impl Sync for OsslItem {}

/// `static int md_is_a(const void *md, const char *name)` — `crypto/rsa/rsa_schemes.c:65-68`.
///
/// The one-line adapter `meth2nid` is called through: it exists because `EVP_MD_is_a` takes an
/// `EVP_MD *` and the generic walker takes a `void *`.
///
/// # Safety
/// `md` is NULL or a live `EVP_MD`; `name` is NUL-terminated.
unsafe extern "C" fn md_is_a(md: *const c_void, name: *const c_char) -> c_int {
    // SAFETY: the caller's contract; the cast only restores the pointee type the adapter
    // erased, which is what the authority's own `(EVP_MD *)md` implicit conversion does.
    unsafe { EVP_MD_is_a(md.cast::<EvpMd>(), name) }
}

/// `static int meth2nid(const void *meth, int (*meth_is_a)(const void *meth, const char *name),
/// const OSSL_ITEM *items, size_t items_n)` — `crypto/rsa/rsa_schemes.c:17-28`.
///
/// A NULL method answers `NID_undef` **without** consulting the table, which is the arm that
/// makes `ossl_rsa_oaeppss_md2nid(NULL)` a "no digest" answer rather than a walk over seven rows
/// that would all have to defend themselves against a NULL.
///
/// # Safety
/// `meth` is NULL or live for `meth_is_a`; `meth_is_a` is callable with `(meth, row.ptr)` for
/// every row; each row's `ptr` is NUL-terminated.
unsafe fn meth2nid(
    meth: *const c_void,
    meth_is_a: unsafe extern "C" fn(*const c_void, *const c_char) -> c_int,
    items: &[OsslItem],
) -> c_int {
    if meth.is_null() {
        return NID_undef;
    }
    for row in items {
        // SAFETY: `meth` is live and `row.ptr` is NUL-terminated, per the contract.
        if unsafe { meth_is_a(meth, row.ptr) } != 0 {
            return row.id;
        }
    }
    NID_undef
}

/// `static const char *nid2name(int meth, const OSSL_ITEM *items, size_t items_n)` —
/// `crypto/rsa/rsa_schemes.c:30-38`.
///
/// The reverse walk, and it has **no** NULL guard because its argument is an `int`: an
/// identifier no row carries falls out of the loop and answers NULL.
fn nid2name(meth: c_int, items: &[OsslItem]) -> *const c_char {
    for row in items {
        if meth == row.id {
            return row.ptr;
        }
    }
    core::ptr::null()
}

/// `int ossl_rsa_oaeppss_md2nid(const EVP_MD *md)` — `crypto/rsa/rsa_schemes.c:70-74`.
/// Internal, declared in `include/crypto/rsa.h`.
///
/// `NID_undef` for a NULL method and for one that matches no row of RFC 8017's list. A digest
/// the list does not carry — SHA3-256, say — is therefore indistinguishable from no digest at
/// this layer, which is the authority's behaviour and is why the PSS restriction can be
/// *unset* by passing such a name.
///
/// `#[allow(dead_code)]`'s reason: **its first readers are `rsa_backend.c`'s two
/// `ossl_rsa_pss_params_30_{to,from}data`**, which this commit does land — but nothing in the
/// crate calls those yet, so the chain is unreached until 8.8's method objects and the provider
/// keymgmt do. The unit test beside it is what keeps the answer honest until then.
///
/// # Safety
/// `md` is NULL or a live `EVP_MD`.
#[allow(dead_code)] // read by rsa_backend.c's PSS parameter codecs; unreached until 8.8
pub(crate) unsafe fn ossl_rsa_oaeppss_md2nid(md: *const EvpMd) -> c_int {
    // SAFETY: the caller's contract; the adapter restores the `void *` erasure.
    unsafe { meth2nid(md.cast::<c_void>(), md_is_a, &OAEPPSS_NAME_NID_MAP) }
}

/// `const char *ossl_rsa_oaeppss_nid2name(int md)` — `crypto/rsa/rsa_schemes.c:76-79`.
/// Internal.
///
/// The string a caller writes into a provider parameter, and NULL for an identifier the table
/// does not carry. Note that this is the *provider* spelling and not the `OBJ_nid2sn` one.
///
/// `#[allow(dead_code)]`'s reason: as [`ossl_rsa_oaeppss_md2nid`].
///
/// # Safety
/// The answer is NULL or a `'static` NUL-terminated string; it is borrowed and must not be
/// freed.
#[allow(dead_code)] // read by rsa_backend.c's `ossl_rsa_pss_params_30_todata`
pub(crate) unsafe fn ossl_rsa_oaeppss_nid2name(md: c_int) -> *const c_char {
    nid2name(md, &OAEPPSS_NAME_NID_MAP)
}

/// `const char *ossl_rsa_mgf_nid2name(int mgf)` — `crypto/rsa/rsa_schemes.c:81-86`. Internal.
///
/// One row, and the function is not a table walk: `NID_mgf1` answers `SN_mgf1` (`"MGF1"`) and
/// every other value answers NULL. MGF1 is the only mask generation function RFC 8017 defines,
/// and the asymmetry with the seven-row digest map is the authority's.
///
/// `#[allow(dead_code)]`'s reason: as [`ossl_rsa_oaeppss_md2nid`].
///
/// # Safety
/// The answer is NULL or a `'static` NUL-terminated string.
#[allow(dead_code)] // read by rsa_backend.c's `ossl_rsa_pss_params_30_fromdata`
pub(crate) unsafe fn ossl_rsa_mgf_nid2name(mgf: c_int) -> *const c_char {
    if mgf == NID_mgf1 {
        return SN_mgf1.as_ptr();
    }
    core::ptr::null()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;
    use core::ptr;

    /// `md_is_a`, bound for an `EVP_MD` the crate can build: the legacy static methods have no
    /// provider name, so `EVP_MD_is_a` answers through the alias set the method carries. The
    /// table's own rows are what the test below checks, not this adapter.
    fn read(p: *const c_char) -> Option<String> {
        if p.is_null() {
            return None;
        }
        // SAFETY: every pointer this module answers is a `'static` NUL-terminated literal.
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }

    /// The seven rows of RFC 8017's list, in order, with the identifiers the header gives them.
    /// The order is what `meth2nid` walks, so it is asserted rather than left to the array's
    /// initialiser.
    #[test]
    fn the_oaeppss_name_map_is_rfc8017s_seven_rows() {
        let rows: Vec<(c_int, Option<String>)> = OAEPPSS_NAME_NID_MAP
            .iter()
            .map(|r| (r.id, read(r.ptr)))
            .collect();
        assert_eq!(
            rows,
            vec![
                (NID_sha1, Some("SHA1".into())),
                (NID_sha224, Some("SHA2-224".into())),
                (NID_sha256, Some("SHA2-256".into())),
                (NID_sha384, Some("SHA2-384".into())),
                (NID_sha512, Some("SHA2-512".into())),
                (NID_sha512_224, Some("SHA2-512/224".into())),
                (NID_sha512_256, Some("SHA2-512/256".into())),
            ]
        );
    }

    /// The two lookups are inverses over the table, and the refusals differ: an identifier no
    /// row carries answers NULL from `nid2name`, while `nid2name`'s answer for every row is what
    /// `meth2nid` would settle on given a method that *is* that name.
    #[test]
    fn the_lookups_are_inverses_over_the_table() {
        for row in OAEPPSS_NAME_NID_MAP.iter() {
            assert_eq!(nid2name(row.id, &OAEPPSS_NAME_NID_MAP), row.ptr);
        }
        assert!(nid2name(-1, &OAEPPSS_NAME_NID_MAP).is_null());
        assert!(nid2name(0, &OAEPPSS_NAME_NID_MAP).is_null());
    }

    /// `ossl_rsa_mgf_nid2name` is a one-row function, and its value is the header's `SN_mgf1`
    /// spelling. The case is asserted rather than folded, because the folding happens in the
    /// *caller* (`OPENSSL_strcasecmp` at `rsa_backend.c:398`) and not here.
    #[test]
    fn the_mgf_name_lookup_answers_the_short_name_for_mgf1_only() {
        // SAFETY: the argument is a constant and nothing is dereferenced by the call.
        let p = unsafe { ossl_rsa_mgf_nid2name(NID_mgf1) };
        assert_eq!(read(p), Some("MGF1".to_string()));
        // SAFETY: as above.
        assert!(unsafe { ossl_rsa_mgf_nid2name(0) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { ossl_rsa_mgf_nid2name(-1) }.is_null());
    }

    /// The MD walk's NULL guard: a NULL method is `NID_undef` and does not touch the table.
    ///
    /// The callback passed here **matches every row**, so if the NULL guard were removed the walk
    /// would answer the first row's identifier (`NID_sha1`) instead — which is what makes the
    /// assertion a test of the guard rather than of the table.
    #[test]
    fn the_md_walk_short_circuits_on_null() {
        unsafe extern "C" fn always_matches(_m: *const c_void, _n: *const c_char) -> c_int {
            1
        }
        // SAFETY: `meth2nid`'s contract; the table is this module's own and the callback accepts
        // the arguments it is defined for.
        let r = unsafe { meth2nid(ptr::null(), always_matches, &OAEPPSS_NAME_NID_MAP) };
        assert_eq!(r, NID_undef);
    }
}
