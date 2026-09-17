//! Phase 7.4c — `crypto/evp/evp_pbe.c`: the PBE algorithm registry.
//!
//! Eight exports and one table, and the table is the whole of the file: `builtin_pbe[]` holds
//! **thirty-four** rows (`crypto/evp/evp_pbe.c:35-94`), each naming a PBE algorithm by NID, the
//! cipher NID and digest NID it derives for, and the keygen function that does the derivation.
//! `EVP_PBE_find`/`_ex` searches it; `EVP_PBE_get` walks it by index; `EVP_PBE_alg_add*` appends
//! to a *second*, caller-filled registry beside it; `EVP_PBE_cleanup` releases that second
//! registry and leaves the table alone; and `EVP_PBE_CipherInit*` is the only caller of the
//! keygen pointers.
//!
//! ## The count is thirty-four, not forty
//!
//! The task's brief for this slice said "forty rows" and the number is read here from the
//! authority rather than repeated: `sed -n '35,94p' crypto/evp/evp_pbe.c | grep -c '{ EVP_PBE_TYPE'`
//! answers **34** — fourteen `EVP_PBE_TYPE_OUTER`, eighteen `EVP_PBE_TYPE_PRF` and two
//! `EVP_PBE_TYPE_KDF`. All thirty-four are transcribed, in source order, and the court walks every
//! one of them by index so a miscount cannot survive a run.
//!
//! The order is not cosmetic. `EVP_PBE_find_ex` searches the table with `OBJ_bsearch_pbe2`, which
//! is `bsearch` under `pbe2_cmp`, and the table is sorted by `(pbe_type, pbe_nid)`: OUTER is `0x0`,
//! PRF `0x1`, KDF `0x2`, and each group ascends. `EVP_PBE_get` answers the rows *in that order*,
//! which is what makes the order an observable rather than an implementation detail.
//!
//! ## `pbe_cmp` and `pbe2_cmp` sort on the *same* keys
//!
//! The two comparators are easy to read as a pair that sorts differently, and they do not:
//!
//! ```text
//! pbe2_cmp(const EVP_PBE_CTL *pbe1, const EVP_PBE_CTL *pbe2)          -> (type, nid) of the values
//! pbe_cmp(const EVP_PBE_CTL *const *a, const EVP_PBE_CTL *const *b)    -> (type, nid) of the pointed-to
//! ```
//!
//! The difference is one level of dereference and nothing else. What *is* different is where each
//! is used, and that is the whole reason both exist: `pbe2_cmp` is `bsearch`'s comparator, which
//! the C library hands two element *values*; `pbe_cmp` is the `STACK_OF` comparator, which
//! `OPENSSL_sk_*` hands two *slot addresses*. The names in the authority (`DECLARE_OBJ_BSEARCH_CMP_FN`
//! and `IMPLEMENT_OBJ_BSEARCH_CMP_FN`) are what generate the `_ex`-looking spelling, not a
//! difference in the key set.
//!
//! ## The six `PKCS12_PBE_keyivgen` rows, and why they are `None` here
//!
//! Six of the fourteen OUTER rows name `PKCS12_PBE_keyivgen` and `&PKCS12_PBE_keyivgen_ex`, which
//! are `crypto/pkcs12/p12_crpt.c`'s and are **`owner_phase: 10`** in
//! `forensics/atlas/symbol-ownership.json`. A Rust `static` is fully initialised or it does not
//! exist, so those two slots are `None` in this build, the rows stay *in* the table — which keeps
//! `EVP_PBE_find`'s return value and both NID out-parameters exactly the authority's for all six —
//! and the two presence answers differ. That is
//! `docs/SECURITY_DIVERGENCE_POLICY.md` **D-PBE-PKCS12-KEYGEN-1**, which names all six NIDs, the
//! exact answers that change, and Phase 10 as the stratum that retires it.
//!
//! The deferral alternative was measured and cannot be built: `EVP_PBE_find_ex` and `EVP_PBE_find`
//! are called by this slice's *own* `PKCS5_v2_PBE_keyivgen_ex` (`p5_crpt2.c:133`) and
//! `PKCS5_v2_PBKDF2_keyivgen_ex` (`p5_crpt2.c:230`), so withholding them would take four of this
//! slice's mandated exports with them and leave the court unable to observe the thirty-four rows
//! at all — which is the observation this court exists to make. `docs/DECISIONS.md` D192 carries
//! the argument and the cost.
//!
//! ## What the authority does that this crate cannot, and one guard
//!
//! `EVP_PBE_CipherInit_ex`'s last statement is a bare `keygen(ctx, ...)` on the else arm. For a
//! row whose `keygen_ex` is NULL and whose `keygen` is NULL — which the authority's own table has
//! eighteen of, the PRF rows — `EVP_PBE_find` answers 1 and the call faults. This crate returns 0
//! there instead, with no raise: the same guard that keeps a crash out of the harness, and the
//! reason it is safe is that no *derivation* was ever reachable through those rows on either side.
//! It is named at the site and is part of D-PBE-PKCS12-KEYGEN-1's record rather than a second one,
//! because after Phase 10 the six PKCS12 rows stop taking it.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::layout::Asn1Type;
use crate::asn1::text::i2t_ASN1_OBJECT;
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_nid, EvpCipher};
use crate::evp::cipher_ctx::EvpCipherCtx;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_type, EvpMd};
use crate::evp::legacy_evp::{EVP_get_cipherbyname, EVP_get_digestbyname};
use crate::runtime::bio::sys::strlen;
use crate::runtime::err::{
    err_sites, raise_site, raise_site_data, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::{
    Asn1Object, NID_des_cbc, NID_des_ede3_cbc, NID_des_ede_cbc, NID_hmacWithMD5, NID_hmacWithSHA1,
    NID_hmacWithSHA224, NID_hmacWithSHA256, NID_hmacWithSHA384, NID_hmacWithSHA512,
    NID_hmacWithSHA512_224, NID_hmacWithSHA512_256, NID_hmacWithSM3, NID_hmac_md5, NID_hmac_sha1,
    NID_hmac_sha3_224, NID_hmac_sha3_256, NID_hmac_sha3_384, NID_hmac_sha3_512,
    NID_id_GostR3411_2012_256, NID_id_GostR3411_2012_512, NID_id_GostR3411_94,
    NID_id_HMACGostR3411_94, NID_id_pbkdf2, NID_id_scrypt, NID_id_tc26_hmac_gost_3411_2012_256,
    NID_id_tc26_hmac_gost_3411_2012_512, NID_md2, NID_md5, NID_pbeWithMD2AndDES_CBC,
    NID_pbeWithMD2AndRC2_CBC, NID_pbeWithMD5AndDES_CBC, NID_pbeWithMD5AndRC2_CBC,
    NID_pbeWithSHA1AndDES_CBC, NID_pbeWithSHA1AndRC2_CBC, NID_pbe_WithSHA1And128BitRC2_CBC,
    NID_pbe_WithSHA1And128BitRC4, NID_pbe_WithSHA1And2_Key_TripleDES_CBC,
    NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_pbe_WithSHA1And40BitRC2_CBC,
    NID_pbe_WithSHA1And40BitRC4, NID_pbes2, NID_rc2_40_cbc, NID_rc2_64_cbc, NID_rc2_cbc, NID_rc4,
    NID_rc4_40, NID_sha1, NID_sha224, NID_sha256, NID_sha384, NID_sha3_224, NID_sha3_256,
    NID_sha3_384, NID_sha3_512, NID_sha512, NID_sha512_224, NID_sha512_256, NID_sm3, NID_undef,
    OBJ_nid2sn, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_sort,
    OPENSSL_sk_value, OpenSslStack,
};

/// `EVP_PBE_TYPE_OUTER` — `include/openssl/evp.h:1586`.
pub(crate) const EVP_PBE_TYPE_OUTER: c_int = 0x0;
/// `EVP_PBE_TYPE_PRF` — `include/openssl/evp.h:1588`.
pub(crate) const EVP_PBE_TYPE_PRF: c_int = 0x1;
/// `EVP_PBE_TYPE_KDF` — `include/openssl/evp.h:1590`.
pub(crate) const EVP_PBE_TYPE_KDF: c_int = 0x2;

/// `EVP_PBE_KEYGEN` — `include/openssl/evp.h:499-503`.
pub type EvpPbeKeygen = unsafe extern "C" fn(
    ctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    cipher: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
) -> c_int;

/// `EVP_PBE_KEYGEN_EX` — `include/openssl/evp.h:505-509`.
pub type EvpPbeKeygenEx = unsafe extern "C" fn(
    ctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    cipher: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int;

/// `struct evp_pbe_st` — `crypto/evp/evp_pbe.c:24-31`, and the typedef `EVP_PBE_CTL` that
/// `crypto/evp/evp_local.h` gives it.
#[repr(C)]
pub(crate) struct EvpPbeCtl {
    /// `int pbe_type` — one of `EVP_PBE_TYPE_*`.
    pub(crate) pbe_type: c_int,
    /// `int pbe_nid` — the PBE algorithm's NID.
    pub(crate) pbe_nid: c_int,
    /// `int cipher_nid` — or `-1` when the row has no cipher of its own.
    pub(crate) cipher_nid: c_int,
    /// `int md_nid` — or `-1`.
    pub(crate) md_nid: c_int,
    /// `EVP_PBE_KEYGEN *keygen` — the plain keygen, or `None` where the authority holds `0`.
    pub(crate) keygen: Option<EvpPbeKeygen>,
    /// `EVP_PBE_KEYGEN_EX *keygen_ex` — the `ex` keygen, or `None`.
    pub(crate) keygen_ex: Option<EvpPbeKeygenEx>,
}

/// `static const EVP_PBE_CTL builtin_pbe[]` — `crypto/evp/evp_pbe.c:35-94`.
///
/// Thirty-four rows, in source order, with `-1` spelled as `-1` and the authority's `0` spelled
/// where it appears. The six rows whose keygen is `PKCS12_PBE_keyivgen` carry `None` for both
/// slots; see the module doc and D-PBE-PKCS12-KEYGEN-1.
pub(crate) static BUILTIN_PBE: [EvpPbeCtl; 34] = [
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbeWithMD2AndDES_CBC,
        cipher_nid: NID_des_cbc,
        md_nid: NID_md2,
        keygen: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen),
        keygen_ex: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen_ex),
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbeWithMD5AndDES_CBC,
        cipher_nid: NID_des_cbc,
        md_nid: NID_md5,
        keygen: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen),
        keygen_ex: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen_ex),
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbeWithSHA1AndRC2_CBC,
        cipher_nid: NID_rc2_64_cbc,
        md_nid: NID_sha1,
        keygen: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen),
        keygen_ex: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen_ex),
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_id_pbkdf2,
        cipher_nid: -1,
        md_nid: -1,
        keygen: Some(crate::evp::p5_crpt2::PKCS5_v2_PBKDF2_keyivgen),
        keygen_ex: Some(crate::evp::p5_crpt2::PKCS5_v2_PBKDF2_keyivgen_ex),
    },
    /* The six PKCS12 rows: `PKCS12_PBE_keyivgen` and `&PKCS12_PBE_keyivgen_ex` in the authority,
     * `None` here because both are `crypto/pkcs12/p12_crpt.c`'s and Phase 10's
     * (`docs/SECURITY_DIVERGENCE_POLICY.md` D-PBE-PKCS12-KEYGEN-1). */
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbe_WithSHA1And128BitRC4,
        cipher_nid: NID_rc4,
        md_nid: NID_sha1,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbe_WithSHA1And40BitRC4,
        cipher_nid: NID_rc4_40,
        md_nid: NID_sha1,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
        cipher_nid: NID_des_ede3_cbc,
        md_nid: NID_sha1,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbe_WithSHA1And2_Key_TripleDES_CBC,
        cipher_nid: NID_des_ede_cbc,
        md_nid: NID_sha1,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbe_WithSHA1And128BitRC2_CBC,
        cipher_nid: NID_rc2_cbc,
        md_nid: NID_sha1,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbe_WithSHA1And40BitRC2_CBC,
        cipher_nid: NID_rc2_40_cbc,
        md_nid: NID_sha1,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbes2,
        cipher_nid: -1,
        md_nid: -1,
        keygen: Some(crate::evp::p5_crpt2::PKCS5_v2_PBE_keyivgen),
        keygen_ex: Some(crate::evp::p5_crpt2::PKCS5_v2_PBE_keyivgen_ex),
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbeWithMD2AndRC2_CBC,
        cipher_nid: NID_rc2_64_cbc,
        md_nid: NID_md2,
        keygen: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen),
        keygen_ex: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen_ex),
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbeWithMD5AndRC2_CBC,
        cipher_nid: NID_rc2_64_cbc,
        md_nid: NID_md5,
        keygen: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen),
        keygen_ex: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen_ex),
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: NID_pbeWithSHA1AndDES_CBC,
        cipher_nid: NID_des_cbc,
        md_nid: NID_sha1,
        keygen: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen),
        keygen_ex: Some(crate::evp::p5_crpt::PKCS5_PBE_keyivgen_ex),
    },
    /* The eighteen PRF rows: no keygen at all, which the authority spells `0`. */
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmacWithSHA1,
        cipher_nid: -1,
        md_nid: NID_sha1,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmac_md5,
        cipher_nid: -1,
        md_nid: NID_md5,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmac_sha1,
        cipher_nid: -1,
        md_nid: NID_sha1,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmacWithMD5,
        cipher_nid: -1,
        md_nid: NID_md5,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmacWithSHA224,
        cipher_nid: -1,
        md_nid: NID_sha224,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmacWithSHA256,
        cipher_nid: -1,
        md_nid: NID_sha256,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmacWithSHA384,
        cipher_nid: -1,
        md_nid: NID_sha384,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmacWithSHA512,
        cipher_nid: -1,
        md_nid: NID_sha512,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_id_HMACGostR3411_94,
        cipher_nid: -1,
        md_nid: NID_id_GostR3411_94,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_id_tc26_hmac_gost_3411_2012_256,
        cipher_nid: -1,
        md_nid: NID_id_GostR3411_2012_256,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_id_tc26_hmac_gost_3411_2012_512,
        cipher_nid: -1,
        md_nid: NID_id_GostR3411_2012_512,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmac_sha3_224,
        cipher_nid: -1,
        md_nid: NID_sha3_224,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmac_sha3_256,
        cipher_nid: -1,
        md_nid: NID_sha3_256,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmac_sha3_384,
        cipher_nid: -1,
        md_nid: NID_sha3_384,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmac_sha3_512,
        cipher_nid: -1,
        md_nid: NID_sha3_512,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmacWithSHA512_224,
        cipher_nid: -1,
        md_nid: NID_sha512_224,
        keygen: None,
        keygen_ex: None,
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmacWithSHA512_256,
        cipher_nid: -1,
        md_nid: NID_sha512_256,
        keygen: None,
        keygen_ex: None,
    },
    /* `#ifndef OPENSSL_NO_SM3` is not taken out of this build, so the row is live. */
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: NID_hmacWithSM3,
        cipher_nid: -1,
        md_nid: NID_sm3,
        keygen: None,
        keygen_ex: None,
    },
    /* The two KDF rows. `#ifndef OPENSSL_NO_SCRYPT` is likewise not taken. */
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_KDF,
        pbe_nid: NID_id_pbkdf2,
        cipher_nid: -1,
        md_nid: -1,
        keygen: Some(crate::evp::p5_crpt2::PKCS5_v2_PBKDF2_keyivgen),
        keygen_ex: Some(crate::evp::p5_crpt2::PKCS5_v2_PBKDF2_keyivgen_ex),
    },
    EvpPbeCtl {
        pbe_type: EVP_PBE_TYPE_KDF,
        pbe_nid: NID_id_scrypt,
        cipher_nid: -1,
        md_nid: -1,
        keygen: Some(crate::evp::p5_scrypt::PKCS5_v2_scrypt_keyivgen),
        keygen_ex: Some(crate::evp::p5_scrypt::PKCS5_v2_scrypt_keyivgen_ex),
    },
];

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/evp_pbe.c".as_ptr();
/// `OPENSSL_zalloc(sizeof(*pbe_tmp))` — `crypto/evp/evp_pbe.c:212`.
const LINE_ZALLOC_CTL: c_int = 212;

/// `static STACK_OF(EVP_PBE_CTL) *pbe_algs` — `crypto/evp/evp_pbe.c:33`.
///
/// The caller-filled registry beside `builtin_pbe[]`. The authority's accessors are the
/// `sk_EVP_PBE_CTL_*` macros over `OPENSSL_sk_*` with [`pbe_cmp`] as the comparator, so it is the
/// crate's own stack here for the same reason: `OPENSSL_sk_find`'s comparator calling convention
/// is part of what makes the sort order observable.
static mut PBE_ALGS: *mut OpenSslStack = ptr::null_mut();

/// `static int pbe2_cmp(const EVP_PBE_CTL *pbe1, const EVP_PBE_CTL *pbe2)` —
/// `crypto/evp/evp_pbe.c:177-184`.
///
/// `bsearch`'s comparator, so both arguments are element *values*.
///
/// # Safety
/// Both arguments must point at live `EvpPbeCtl` values.
unsafe extern "C" fn pbe2_cmp(a: *const c_void, b: *const c_void) -> c_int {
    let a = a.cast::<EvpPbeCtl>();
    let b = b.cast::<EvpPbeCtl>();
    // SAFETY: both arguments are live values per the contract.
    let (x, y) = unsafe { ((*a).pbe_type, (*b).pbe_type) };
    if x != y {
        return x - y;
    }
    // SAFETY: as above.
    unsafe { (*a).pbe_nid - (*b).pbe_nid }
}

/// `static int pbe_cmp(const EVP_PBE_CTL *const *a, const EVP_PBE_CTL *const *b)` —
/// `crypto/evp/evp_pbe.c:188-195`.
///
/// The `STACK_OF` comparator, so both arguments are *slot addresses*. The key set is the same as
/// [`pbe2_cmp`]'s; only the dereference depth differs.
///
/// # Safety
/// Both arguments must point at live `*const EvpPbeCtl` slots.
unsafe extern "C" fn pbe_cmp(a: *const c_void, b: *const c_void) -> c_int {
    let a = a.cast::<*const EvpPbeCtl>();
    let b = b.cast::<*const EvpPbeCtl>();
    // SAFETY: both arguments are slots holding live rows per the contract.
    let (x, y) = unsafe { ((**a).pbe_type, (**b).pbe_type) };
    if x != y {
        return x - y;
    }
    // SAFETY: as above.
    unsafe { (**a).pbe_nid - (**b).pbe_nid }
}

/// `EVP_PBE_find_ex`'s table search, which the authority spells `OBJ_bsearch_pbe2`.
///
/// A `bsearch` under [`pbe2_cmp`] over a sorted array. `bsearch`'s answer for a key that *is*
/// present is that element, and for a key that is not is NULL; implemented as an exact binary
/// search so the two agree for every key the table can hold, whether the table is sorted or not
/// (it is: `(pbe_type, pbe_nid)` ascending).
fn builtin_search(key: &EvpPbeCtl) -> Option<&'static EvpPbeCtl> {
    let mut lo = 0usize;
    let mut hi = BUILTIN_PBE.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let row = &BUILTIN_PBE[mid];
        // SAFETY: both arguments are live values, which is what `pbe2_cmp` reads.
        let cmp = unsafe {
            pbe2_cmp(
                ptr::from_ref(row).cast::<c_void>(),
                ptr::from_ref(key).cast::<c_void>(),
            )
        };
        if cmp < 0 {
            lo = mid + 1;
        } else if cmp > 0 {
            hi = mid;
        } else {
            return Some(row);
        }
    }
    None
}

/// `int EVP_PBE_CipherInit_ex(ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
/// ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/evp/evp_pbe.c:96`.
///
/// The only consumer of the table's keygen pointers, and therefore the only place the
/// `D-PBE-PKCS12-KEYGEN-1` divergence could have turned into a crash: for a row whose two
/// keygen slots are both empty this answers 0 instead of calling through one. See the module doc.
///
/// The two `ERR_set_mark`/`ERR_pop_to_mark` pairs are load-bearing: a fetch that *succeeds* on
/// the legacy fallback must leave the queue exactly as `EVP_CIPHER_fetch`'s own failure left it,
/// so the fallback's "no such algorithm" record is dropped and only a real failure raises.
///
/// # Safety
/// `pbe_obj` must be NULL or a live `ASN1_OBJECT`; `pass` NULL or a NUL-terminated string of
/// `passlen` bytes (or `passlen == -1`); `param` NULL or a live `ASN1_TYPE`; `ctx` must be a live
/// `EVP_CIPHER_CTX` whenever a row with a cipher is found; `libctx` NULL or live; `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PBE_CipherInit_ex(
    pbe_obj: *mut Asn1Object,
    pass: *const c_char,
    mut passlen: c_int,
    param: *mut Asn1Type,
    ctx: *mut EvpCipherCtx,
    en_de: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut ret: c_int = 0;
    let mut cipher_nid: c_int = 0;
    let mut md_nid: c_int = 0;
    let mut keygen: Option<EvpPbeKeygen> = None;
    let mut keygen_ex: Option<EvpPbeKeygenEx> = None;

    // SAFETY: `pbe_obj` is NULL or live per the contract; an integer in.
    let nid = unsafe { OBJ_obj2nid(pbe_obj) };
    // SAFETY: the arguments are forwarded under this function's contract.
    if unsafe {
        EVP_PBE_find_ex(
            EVP_PBE_TYPE_OUTER,
            nid,
            &mut cipher_nid,
            &mut md_nid,
            &mut keygen,
            &mut keygen_ex,
        )
    } == 0
    {
        let mut obj_tmp = [0 as c_char; 80];
        if pbe_obj.is_null() {
            let null = c"NULL";
            // SAFETY: the destination is this frame's 80-byte buffer, which is larger than the
            // five bytes copied.
            unsafe { ptr::copy_nonoverlapping(null.as_ptr(), obj_tmp.as_mut_ptr(), 5) };
        } else {
            // SAFETY: `pbe_obj` is live and the destination has room for 80 bytes.
            unsafe { i2t_ASN1_OBJECT(obj_tmp.as_mut_ptr(), 80, pbe_obj) };
        }
        // SAFETY: `i2t_ASN1_OBJECT` and the literal both NUL-terminate inside `obj_tmp`.
        let obj = unsafe { core::ffi::CStr::from_ptr(obj_tmp.as_ptr()) }.to_string_lossy();
        let msg = format!("TYPE={obj}\0");
        // SAFETY: a compile-time-constant site and a NUL-terminated message.
        unsafe { raise_site_data(&err_sites::EVP_PBE_116, msg.as_ptr().cast()) };
        return ret;
    }

    if pass.is_null() {
        passlen = 0;
    } else if passlen == -1 {
        // SAFETY: `pass` is NUL-terminated per the contract.
        passlen = unsafe { strlen(pass) } as c_int;
    }

    let mut cipher: *const EvpCipher = ptr::null();
    let mut cipher_fetch: *mut EvpCipher = ptr::null_mut();
    let mut md: *const EvpMd = ptr::null();
    let mut md_fetch: *mut EvpMd = ptr::null_mut();

    if cipher_nid != -1 {
        /* `ERR_set_mark` is a safe entry point of this crate. */
        ERR_set_mark();
        let sn = OBJ_nid2sn(cipher_nid);
        // SAFETY: `sn` is NULL or a static string, and the rest are the caller's.
        cipher_fetch = unsafe { EVP_CIPHER_fetch(libctx, sn, propq) };
        cipher = cipher_fetch;
        /* Fallback to legacy method */
        if cipher.is_null() {
            // SAFETY: `sn` is NULL or a static string.
            cipher = unsafe { EVP_get_cipherbyname(sn) };
        }
        if cipher.is_null() {
            ERR_clear_last_mark();
            let msg = format!(
                "{}\0",
                if sn.is_null() {
                    ""
                } else {
                    // SAFETY: `sn` is a static NUL-terminated string here.
                    unsafe { core::ffi::CStr::from_ptr(sn) }
                        .to_str()
                        .unwrap_or("")
                }
            );
            // SAFETY: a compile-time-constant site and a NUL-terminated message.
            unsafe { raise_site_data(&err_sites::EVP_PBE_134, msg.as_ptr().cast()) };
            // SAFETY: both fetches are NULL or a reference this frame holds.
            unsafe {
                EVP_CIPHER_free(cipher_fetch);
                EVP_MD_free(md_fetch);
            }
            return ret;
        }
        ERR_pop_to_mark();
    }

    if md_nid != -1 {
        /* `ERR_set_mark` is a safe entry point of this crate. */
        ERR_set_mark();
        let sn = OBJ_nid2sn(md_nid);
        // SAFETY: `sn` is NULL or a static string, and the rest are the caller's.
        md_fetch = unsafe { EVP_MD_fetch(libctx, sn, propq) };
        md = md_fetch;
        /* Fallback to legacy method */
        if md.is_null() {
            // SAFETY: `sn` is NULL or a static string.
            md = unsafe { EVP_get_digestbyname(sn) };
        }
        if md.is_null() {
            ERR_clear_last_mark();
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_PBE_150) };
            // SAFETY: `cipher_fetch` is NULL or a reference this frame holds.
            unsafe {
                EVP_CIPHER_free(cipher_fetch);
                EVP_MD_free(md_fetch);
            }
            return ret;
        }
        ERR_pop_to_mark();
    }

    /* Try extended keygen with libctx/propq first, fall back to legacy keygen. The authority
     * reaches `keygen` unconditionally; this crate answers 0 when both are empty, which is a
     * row the authority holds with neither pointer and would fault on. */
    if let Some(kge) = keygen_ex {
        // SAFETY: `kge` is the table's own keygen and the arguments are the caller's.
        ret = unsafe { kge(ctx, pass, passlen, param, cipher, md, en_de, libctx, propq) };
    } else if let Some(kg) = keygen {
        // SAFETY: as above.
        ret = unsafe { kg(ctx, pass, passlen, param, cipher, md, en_de) };
    }

    // SAFETY: both fetches are NULL or a reference this frame holds.
    unsafe {
        EVP_CIPHER_free(cipher_fetch);
        EVP_MD_free(md_fetch);
    }
    ret
}

/// `int EVP_PBE_CipherInit(ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
/// ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de)` — `crypto/evp/evp_pbe.c:169`.
///
/// # Safety
/// As [`EVP_PBE_CipherInit_ex`], with a NULL library context and property query.
#[no_mangle]
pub unsafe extern "C" fn EVP_PBE_CipherInit(
    pbe_obj: *mut Asn1Object,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    ctx: *mut EvpCipherCtx,
    en_de: c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with the two NULLs the
    // authority passes.
    unsafe {
        EVP_PBE_CipherInit_ex(
            pbe_obj,
            pass,
            passlen,
            param,
            ctx,
            en_de,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid, int md_nid,
/// EVP_PBE_KEYGEN *keygen)` — `crypto/evp/evp_pbe.c:199`.
///
/// **No validation of `pbe_type`.** The three `EVP_PBE_TYPE_*` arms are not a switch here: the
/// value is stored verbatim and is part of the sort key, so an unknown type is accepted and is
/// findable afterwards with that same type. The two refusals are allocation failures, and the
/// `OPENSSL_zalloc` is *after* the stack's creation so that the stack outlives a failed row.
///
/// # Safety
/// `keygen` must be NULL or a function of exactly `EVP_PBE_KEYGEN`'s type that outlives the
/// registry.
#[no_mangle]
pub unsafe extern "C" fn EVP_PBE_alg_add_type(
    pbe_type: c_int,
    pbe_nid: c_int,
    cipher_nid: c_int,
    md_nid: c_int,
    keygen: Option<EvpPbeKeygen>,
) -> c_int {
    // SAFETY: `PBE_ALGS` is NULL or a stack this module owns.
    if unsafe { PBE_ALGS }.is_null() {
        /* SAFETY: `pbe_cmp` reads only the two integer keys of the slots it is handed. */
        let st = OPENSSL_sk_new(Some(pbe_cmp));
        if st.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_PBE_207) };
            return 0;
        }
        // SAFETY: this module owns the pointer and nothing else writes it.
        unsafe { PBE_ALGS = st };
    }

    let pbe_tmp =
        CRYPTO_zalloc(core::mem::size_of::<EvpPbeCtl>(), FILE, LINE_ZALLOC_CTL).cast::<EvpPbeCtl>();
    if pbe_tmp.is_null() {
        return 0;
    }

    // SAFETY: `pbe_tmp` is this call's own freshly allocated block.
    unsafe {
        (*pbe_tmp).pbe_type = pbe_type;
        (*pbe_tmp).pbe_nid = pbe_nid;
        (*pbe_tmp).cipher_nid = cipher_nid;
        (*pbe_tmp).md_nid = md_nid;
        (*pbe_tmp).keygen = keygen;
        (*pbe_tmp).keygen_ex = None;
    }

    // SAFETY: `PBE_ALGS` is live and `pbe_tmp` outlives the registry until `EVP_PBE_cleanup`.
    if unsafe { OPENSSL_sk_push(PBE_ALGS, pbe_tmp.cast::<c_void>()) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_PBE_222) };
        // SAFETY: the row was allocated by this call and was not registered.
        unsafe { CRYPTO_free(pbe_tmp.cast::<c_void>(), FILE, LINE_ZALLOC_CTL) };
        return 0;
    }
    1
}

/// `int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
/// EVP_PBE_KEYGEN *keygen)` — `crypto/evp/evp_pbe.c:232`.
///
/// Two reads, and both have a `-1` arm: a NULL cipher or a NULL digest stores `-1` rather than
/// being refused, so a row can be added that names no cipher or no digest. The type is always
/// `EVP_PBE_TYPE_OUTER` — this entry point cannot add a PRF or KDF row.
///
/// # Safety
/// `cipher` and `md` must be NULL or live; `keygen` as [`EVP_PBE_alg_add_type`].
#[no_mangle]
pub unsafe extern "C" fn EVP_PBE_alg_add(
    nid: c_int,
    cipher: *const EvpCipher,
    md: *const EvpMd,
    keygen: Option<EvpPbeKeygen>,
) -> c_int {
    let cipher_nid = if cipher.is_null() {
        -1
    } else {
        // SAFETY: `cipher` is live per the check above.
        unsafe { EVP_CIPHER_get_nid(cipher) }
    };
    let md_nid = if md.is_null() {
        -1
    } else {
        // SAFETY: `md` is live per the check above.
        unsafe { EVP_MD_get_type(md) }
    };

    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, nid, cipher_nid, md_nid, keygen) }
}

/// `int EVP_PBE_find_ex(int type, int pbe_nid, int *pcnid, int *pmnid,
/// EVP_PBE_KEYGEN **pkeygen, EVP_PBE_KEYGEN_EX **pkeygen_ex)` — `crypto/evp/evp_pbe.c:250`.
///
/// Two searches in a fixed order: the application registry first (sorted first, because the
/// authority sorts it here with a comment admitting there is no lock), then the builtin table.
/// `NID_undef` is refused before either, so a row *cannot* be found for NID 0 even if a caller
/// adds one.
///
/// # Safety
/// Every out-parameter must be NULL or point at a writable slot of its own type.
#[no_mangle]
pub unsafe extern "C" fn EVP_PBE_find_ex(
    type_: c_int,
    pbe_nid: c_int,
    pcnid: *mut c_int,
    pmnid: *mut c_int,
    pkeygen: *mut Option<EvpPbeKeygen>,
    pkeygen_ex: *mut Option<EvpPbeKeygenEx>,
) -> c_int {
    if pbe_nid == NID_undef {
        return 0;
    }

    let pbelu = EvpPbeCtl {
        pbe_type: type_,
        pbe_nid,
        cipher_nid: 0,
        md_nid: 0,
        keygen: None,
        keygen_ex: None,
    };

    let mut pbetmp: *const EvpPbeCtl = ptr::null();
    // SAFETY: `PBE_ALGS` is NULL or a stack this module owns.
    if !unsafe { PBE_ALGS }.is_null() {
        /* Ideally, this would be done under lock. */
        // SAFETY: `PBE_ALGS` is live.
        unsafe { OPENSSL_sk_sort(PBE_ALGS) };
        // SAFETY: `PBE_ALGS` is live and `pbelu` is a live local the comparator reads two
        // integers from.
        let i = unsafe { OPENSSL_sk_find(PBE_ALGS, ptr::addr_of!(pbelu).cast::<c_void>()) };
        // SAFETY: `PBE_ALGS` is live; an index the find answered, negative or not.
        pbetmp = unsafe { OPENSSL_sk_value(PBE_ALGS, i) }.cast::<EvpPbeCtl>();
    }
    if pbetmp.is_null() {
        pbetmp = match builtin_search(&pbelu) {
            Some(row) => row,
            None => return 0,
        };
    }
    // SAFETY: `pbetmp` is a live row per the two branches above.
    unsafe {
        if !pcnid.is_null() {
            *pcnid = (*pbetmp).cipher_nid;
        }
        if !pmnid.is_null() {
            *pmnid = (*pbetmp).md_nid;
        }
        if !pkeygen.is_null() {
            *pkeygen = (*pbetmp).keygen;
        }
        if !pkeygen_ex.is_null() {
            *pkeygen_ex = (*pbetmp).keygen_ex;
        }
    }
    1
}

/// `int EVP_PBE_find(int type, int pbe_nid, int *pcnid, int *pmnid,
/// EVP_PBE_KEYGEN **pkeygen)` — `crypto/evp/evp_pbe.c:283`.
///
/// # Safety
/// Every out-parameter must be NULL or point at a writable slot of its own type.
#[no_mangle]
pub unsafe extern "C" fn EVP_PBE_find(
    type_: c_int,
    pbe_nid: c_int,
    pcnid: *mut c_int,
    pmnid: *mut c_int,
    pkeygen: *mut Option<EvpPbeKeygen>,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with the NULL the
    // authority passes.
    unsafe { EVP_PBE_find_ex(type_, pbe_nid, pcnid, pmnid, pkeygen, ptr::null_mut()) }
}

/// `static void free_evp_pbe_ctl(EVP_PBE_CTL *pbe)` — `crypto/evp/evp_pbe.c:289`.
///
/// # Safety
/// `pbe` must be NULL or a row this module allocated with `CRYPTO_zalloc`.
unsafe extern "C" fn free_evp_pbe_ctl(pbe: *mut c_void) {
    // SAFETY: `pbe` is NULL or this module's own allocation, and `CRYPTO_free` releases it.
    unsafe { CRYPTO_free(pbe, FILE, LINE_ZALLOC_CTL) };
}

/// `void EVP_PBE_cleanup(void)` — `crypto/evp/evp_pbe.c:294`.
///
/// The application registry is released **and** the pointer is cleared, and the builtin table is
/// not touched: a caller that cleans up and then finds a builtin NID still gets its row. A second
/// call is a no-op because `sk_EVP_PBE_CTL_pop_free(NULL, ...)` is.
///
/// # Safety
/// Nothing: it touches only this module's own registry.
#[no_mangle]
pub unsafe extern "C" fn EVP_PBE_cleanup() {
    // SAFETY: `PBE_ALGS` is NULL or a stack this module owns whose every element is a row this
    // module allocated.
    unsafe { OPENSSL_sk_pop_free(PBE_ALGS, Some(free_evp_pbe_ctl)) };
    // SAFETY: this module owns the pointer.
    unsafe { PBE_ALGS = ptr::null_mut() };
}

/// `int EVP_PBE_get(int *ptype, int *ppbe_nid, size_t num)` — `crypto/evp/evp_pbe.c:300`.
///
/// **The type and the NID only.** The two keygen columns are not readable through this entry
/// point, which is why it is faithful even for the six rows this build holds with `None` — and
/// why the court can walk all thirty-four rows on both sides without a residual.
///
/// # Safety
/// `ptype` and `ppbe_nid` must be NULL or point at writable `int` slots.
#[no_mangle]
pub unsafe extern "C" fn EVP_PBE_get(ptype: *mut c_int, ppbe_nid: *mut c_int, num: usize) -> c_int {
    if num >= BUILTIN_PBE.len() {
        return 0;
    }

    let tpbe = &BUILTIN_PBE[num];
    // SAFETY: both slots are NULL or writable per the contract.
    unsafe {
        if !ptype.is_null() {
            *ptype = tpbe.pbe_type;
        }
        if !ppbe_nid.is_null() {
            *ppbe_nid = tpbe.pbe_nid;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table's own invariants, asserted rather than read: thirty-four rows, sorted by
    /// `(pbe_type, pbe_nid)` so that `builtin_search` and `bsearch` agree, and no duplicate key.
    #[test]
    fn builtin_table_is_sorted_and_keyed_uniquely() {
        assert_eq!(BUILTIN_PBE.len(), 34);
        for i in 1..BUILTIN_PBE.len() {
            let a = &BUILTIN_PBE[i - 1];
            let b = &BUILTIN_PBE[i];
            assert!(
                (a.pbe_type, a.pbe_nid) < (b.pbe_type, b.pbe_nid),
                "row {i} is out of order"
            );
        }
    }

    /// `EVP_PBE_get` walks by index and refuses at the end, and a NULL out-parameter is legal.
    #[test]
    fn get_walks_and_refuses_past_the_end() {
        let mut t: c_int = -1;
        let mut n: c_int = -1;
        // SAFETY: two live locals and an in-range index.
        let first = unsafe { EVP_PBE_get(&mut t, &mut n, 0) };
        assert_eq!(first, 1);
        assert_eq!((t, n), (EVP_PBE_TYPE_OUTER, NID_pbeWithMD2AndDES_CBC));
        // SAFETY: as above, with the last index.
        let last = unsafe { EVP_PBE_get(&mut t, &mut n, 33) };
        assert_eq!(last, 1);
        assert_eq!((t, n), (EVP_PBE_TYPE_KDF, NID_id_scrypt));
        // SAFETY: NULL out-parameters are legal, and the index is past the end.
        let past = unsafe { EVP_PBE_get(ptr::null_mut(), ptr::null_mut(), 34) };
        assert_eq!(past, 0);
        // SAFETY: NULL out-parameters with an in-range index answer 1.
        let nulls = unsafe { EVP_PBE_get(ptr::null_mut(), ptr::null_mut(), 0) };
        assert_eq!(nulls, 1);
    }

    /// `EVP_PBE_find` reaches the builtin table when the application registry is empty, and the
    /// six PKCS12 rows answer 1 with the right NIDs and empty keygens — the recorded divergence,
    /// pinned here so its shape cannot change silently.
    #[test]
    fn find_reads_the_builtin_rows() {
        let mut cn: c_int = 0;
        let mut mn: c_int = 0;
        let mut kg: Option<EvpPbeKeygen> = None;
        let mut kge: Option<EvpPbeKeygenEx> = None;
        // SAFETY: four live locals.
        let r = unsafe {
            EVP_PBE_find_ex(
                EVP_PBE_TYPE_OUTER,
                NID_pbeWithMD5AndDES_CBC,
                &mut cn,
                &mut mn,
                &mut kg,
                &mut kge,
            )
        };
        assert_eq!(r, 1);
        assert_eq!((cn, mn), (NID_des_cbc, NID_md5));
        assert!(kg.is_some() && kge.is_some());
        // SAFETY: four live locals.
        let r = unsafe {
            EVP_PBE_find_ex(
                EVP_PBE_TYPE_OUTER,
                NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                &mut cn,
                &mut mn,
                &mut kg,
                &mut kge,
            )
        };
        assert_eq!(r, 1);
        assert_eq!((cn, mn), (NID_des_ede3_cbc, NID_sha1));
        assert!(kg.is_none() && kge.is_none());
        // SAFETY: `NID_undef` is refused before either registry.
        let undef =
            unsafe { EVP_PBE_find(EVP_PBE_TYPE_OUTER, NID_undef, &mut cn, &mut mn, &mut kg) };
        assert_eq!(undef, 0);
    }

    /// The registry: an added row is found under its own type, `EVP_PBE_cleanup` removes it, and
    /// the builtin table survives the cleanup.
    #[test]
    fn alg_add_round_trip_and_cleanup() {
        const NEW: c_int = NID_hmac_sha1 + 100_000;
        // SAFETY: the keygen slot is None and the rest are integers.
        let added = unsafe { EVP_PBE_alg_add_type(EVP_PBE_TYPE_PRF, NEW, 7, 8, None) };
        assert_eq!(added, 1);
        let mut cn: c_int = -1;
        let mut mn: c_int = -1;
        // SAFETY: two live locals and a NULL keygen slot.
        let found =
            unsafe { EVP_PBE_find(EVP_PBE_TYPE_PRF, NEW, &mut cn, &mut mn, ptr::null_mut()) };
        assert_eq!(found, 1);
        assert_eq!((cn, mn), (7, 8));
        // SAFETY: this module's own registry.
        unsafe { EVP_PBE_cleanup() };
        // SAFETY: as above; the row is gone.
        let gone =
            unsafe { EVP_PBE_find(EVP_PBE_TYPE_PRF, NEW, &mut cn, &mut mn, ptr::null_mut()) };
        assert_eq!(gone, 0);
        // SAFETY: the builtin table is not the application registry.
        let builtin = unsafe {
            EVP_PBE_find(
                EVP_PBE_TYPE_PRF,
                NID_hmac_sha1,
                &mut cn,
                &mut mn,
                ptr::null_mut(),
            )
        };
        assert_eq!(builtin, 1);
        assert_eq!((cn, mn), (-1, NID_sha1));
    }
}
