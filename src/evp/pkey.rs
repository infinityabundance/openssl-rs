//! Phase 7.4 — the `EVP_PKEY` object.
//!
//! `crypto/evp/p_lib.c`'s **provider half**: the object, its lifetime, and the two name/type
//! translations every other unit of this stratum reaches for. What is *not* here is the legacy
//! half, and it is not here for a reason that has to be stated rather than discovered — see the
//! section at the end.
//!
//! ## The object
//!
//! `struct evp_pkey_st` is three objects in one struct, and the authority says so: a **legacy
//! attribute** block (`ameth`, `engine`, `pmeth_engine`, and two unions holding a low-level key), a
//! **common** block (`references`, `lock`, attributes, `ex_data`), and a **provider** block
//! (`keymgmt`, `keydata`, the dirty counter, an operation cache, and a cache of four computed key
//! properties). An `EVP_PKEY` is exactly one of the first and third at a time; the comment the
//! authority writes on the provider pair — *"This is never used at the same time as the legacy key
//! data above"* — is the invariant every function in this unit is written against, and every one of
//! them branches on `keymgmt == NULL` rather than on a state flag.
//!
//! ## The two translations, and one deliberate gap
//!
//! `evp_pkey_name2type` answers the legacy NID for a key-type name, and `evp_pkey_type2name` the
//! other way round. Both begin with a **hard-coded table of twelve names** — the authority's own
//! comment calls it "pure hackery to get around the fact that names in
//! `crypto/objects/objects.txt` are a mess", because there is no `"EC"` object and `"RSA"` resolves
//! to a NID that has fallen out of favour. Only a name *outside* those twelve falls through to
//! `EVP_PKEY_type(OBJ_sn2nid(name))`.
//!
//! **That fallback is Phase 8's, and its absence is named here rather than hidden.** `EVP_PKEY_type`
//! is `crypto/evp/evp_pkey_type.c`'s and calls `EVP_PKEY_asn1_find`, which searches
//! `crypto/asn1/ameth_lib.c`'s `standard_methods[]` — a compile-time table of the twelve
//! `ossl_<alg>_asn1_meth` objects that `crypto/rsa/rsa_ameth.c` and its siblings define. Those
//! objects *are* Phase 8's, so the fallback cannot be written before that stratum lands, and neither
//! can `EVP_PKEY_type` itself. `docs/DECISIONS.md` D163 records the dependency and
//! `docs/PHASE-7-SUBPHASES.md` splits 7.4 accordingly.
//!
//! ## What else is not here, and why each is a stratum boundary rather than a choice
//!
//! Four omissions, each recorded where its first reader will be rather than only here:
//!
//!   * **`pkey_set_type`'s legacy-method lookup.** The authority finds an `EVP_PKEY_ASN1_METHOD` by
//!     name and takes its **legacy NID** into `pkey->type` even for a provider-side key, so
//!     `EVP_PKEY_get_id` on a method named `"RSA"` answers `EVP_PKEY_RSA`. That lookup is Phase 8's,
//!     and its absence is the one *reachable* difference in this file:
//!     `docs/SECURITY_DIVERGENCE_POLICY.md` **D-PKEY-AMETH-1** records it, names the trigger, and
//!     says which comparisons stop being claimed.
//!   * **the legacy block of `struct evp_pkey_st`** — `ameth`, `engine`, `pmeth_engine` and the two
//!     low-level-key unions. `EVP_PKEY_ASN1_METHOD` is Phase 8's and `ENGINE` is Phase 13's, so the
//!     fields would be untyped placeholders. The state they represent — a *legacy origin key*,
//!     `keymgmt == NULL` with `type != EVP_PKEY_NONE` — is therefore one this crate cannot enter, and
//!     that is what makes `EVP_PKEY_get0_description`'s and `EVP_PKEY_dup`'s legacy arms unreachable
//!     rather than merely untested.
//!   * **`attributes`** — a `STACK_OF(X509_ATTRIBUTE)` whose element destructor is
//!     `X509_ATTRIBUTE_free`, a Phase 12 symbol. No function in `p_lib.c` sets it (the
//!     `EVP_PKEY_add1_attr` family is `crypto/x509/`'s), so `EVP_PKEY_free` has a field to name and
//!     no branch to omit.
//!   * **the arms that read a legacy origin** in the functions that *are* here. Each is marked at the
//!     site with the stratum that fills it, because a reader of one function should not have to find
//!     this paragraph first.
//!
//! What that means concretely, and it is the strongest statement the two name translations can make:
//! **no exported function in this crate can observe the `name2type` gap yet.** `evp_pkey_name2type`'s callers are
//! `EVP_PKEY_is_a`'s legacy arm, `EVP_PKEY_type_names_do_all`'s legacy arm and `keymgmt_meth.c`'s
//! `legacy_alg` fill — and all three read it through a `pkey->ameth` path or through
//! `evp_keymgmt_get_legacy_alg`, which the legacy half owns. The moment Phase 8 lands the fallback
//! is the first thing that has to be filled. A **deferral row in `forensics/prerequisites.json` is
//! not the right record for it**, and that is worth writing down: the gate refuses a deferral whose
//! name the crate already defines (`stale_deferral`), and this name is defined here — partially and
//! by design. So the record is the decision entry, this section, and the site comment.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void, CStr};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::asn1::layout::{Asn1Pctx, Asn1String};
use crate::bn::bignum::BigNum;
use crate::dh::backend::ossl_dh_is_foreign;
use crate::dh::group_params::ossl_dh_is_named_safe_prime_group;
use crate::dh::object::{DH_free, DH_get0_q, DH_up_ref};
use crate::dh::Dh;
use crate::dsa::backend::ossl_dsa_is_foreign;
use crate::dsa::object::{DSA_free, DSA_up_ref};
use crate::dsa::Dsa;
use crate::ec::backend::ossl_ec_key_is_foreign;
use crate::ec::ecx_key::{ossl_ecx_key_up_ref, EcxKey};
use crate::ec::key::{EC_KEY_get0_group, EC_KEY_get_conv_form};
use crate::ec::lib::{EC_GROUP_get_curve_name, EC_GROUP_get_field_type};
use crate::ec::EcKey;
use crate::encoder_lib::{OSSL_ENCODER_CTX_get_num_encoders, OSSL_ENCODER_to_bio};
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::evp::cipher::EVP_CIPHER_get0_name;
use crate::evp::cipher::EvpCipher;
use crate::evp::digest::{
    EVP_DigestSignInit_ex, EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free,
};
use crate::evp::keymgmt::{
    evp_keymgmt_dup, evp_keymgmt_export, EVP_KEYMGMT_free, EVP_KEYMGMT_get0_name,
    EVP_KEYMGMT_get0_provider, EVP_KEYMGMT_is_a, EVP_KEYMGMT_names_do_all, EVP_KEYMGMT_up_ref,
    EvpKeyMgmt,
};
use crate::evp::keymgmt_lib::{
    evp_keymgmt_util_clear_operation_cache, evp_keymgmt_util_copy, evp_keymgmt_util_export,
    evp_keymgmt_util_get_deflt_digest_name, evp_keymgmt_util_has,
    evp_keymgmt_util_query_operation_name,
};
use crate::evp::pkey_asn1::{EVP_PKEY_type, Engine, EvpPkeyAsn1Method};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_CTX_new_from_pkey,
    EVP_PKEY_CTX_set_params, EvpPkeyCtx, EVP_PKEY_DH, EVP_PKEY_DHX, EVP_PKEY_DSA, EVP_PKEY_EC,
    EVP_PKEY_ED25519, EVP_PKEY_ED448, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_SM2,
    EVP_PKEY_X25519, EVP_PKEY_X448,
};
use crate::evp::pmeth_gn::{
    EVP_PKEY_fromdata, EVP_PKEY_fromdata_init, EVP_PKEY_generate, EVP_PKEY_keygen_init,
};
use crate::evp::signature::{EVP_SIGNATURE_fetch, EVP_SIGNATURE_free, OSSL_OP_SIGNATURE};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    OSSL_PARAM_get_octet_string, OSSL_PARAM_locate_const, OsslParam,
};
use crate::provider::{ossl_provider_libctx, OsslProvider};
use crate::rsa::backend::ossl_rsa_is_foreign;
use crate::rsa::Rsa;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::{
    bf_prefix::BIO_f_prefix,
    print::{BIO_indent, BIO_printf},
    BIO_ctrl, BIO_free, BIO_new, BIO_new_fp, BIO_pop, BIO_push, Bio, BIO_CTRL_GET_INDENT,
    BIO_CTRL_SET_INDENT, BIO_NOCLOSE,
};
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::err::{ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::ex_data::{
    CRYPTO_dup_ex_data, CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data,
    CRYPTO_set_ex_data, CryptoExData, CRYPTO_EX_INDEX_EVP_PKEY,
};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::obj::{
    NID_X9_62_characteristic_two_field, NID_X9_62_id_ecPublicKey, NID_X9_62_prime_field,
    NID_dhKeyAgreement, NID_dhpublicnumber, NID_dsa, NID_hmac, NID_poly1305, NID_rsaEncryption,
    NID_rsassaPss, NID_siphash, NID_sm2, NID_undef, OBJ_ln2nid, OBJ_nid2ln, OBJ_nid2sn, OBJ_sn2nid,
    NID_ED25519, NID_ED448, NID_X25519, NID_X448,
};
use crate::runtime::str::OPENSSL_strlcpy;
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};

/// `EVP_PKEY_NONE` — `include/openssl/evp.h`, which spells it `NID_undef`.
#[allow(dead_code)] // read by `pkey_set_type` and `EVP_PKEY_get_id`, both of which 7.4a's next slice lands
pub(crate) const EVP_PKEY_NONE: c_int = NID_undef;
/// `EVP_PKEY_KEYMGMT` — **`-1`**, and the one pseudo-NID in the family that is not `-2`.
///
/// A provider-only key reports this from `EVP_PKEY_get_id` and its `keymgmt` from
/// `EVP_PKEY_get_base_id`, which is why the two are separate entry points rather than one.
#[allow(dead_code)] // read by `EVP_PKEY_get_id`'s provider arm, which 7.4a's next slice lands
pub(crate) const EVP_PKEY_KEYMGMT: c_int = -1;

/// `static const OSSL_ITEM standard_name2type[]`.
///
/// Twelve entries, and `EVP_PKEY_DHX` appears **twice** — under `"X9.42 DH"` and under `"DHX"`,
/// which is how the authority spells the second name. A transcription that deduplicated them would
/// answer `NID_undef` for one of the two spellings, and `evp_pkey_type2name` would answer the wrong
/// one of them: it returns the **first** entry whose id matches, so `EVPP_PKEY_DHX` answers
/// `"X9.42 DH"` and never `"DHX"`.
///
/// The strings are `&CStr` rather than `&str` because `evp_pkey_type2name` hands one of them to a
/// caller as a `const char *`, and the authority hands out its table's own storage.
#[allow(dead_code)] // the table itself is private to this file's two readers; the enum below is the public shape
pub(crate) const STANDARD_NAME2TYPE: [(c_int, &CStr); 12] = [
    (NID_rsaEncryption, c"RSA"),
    (NID_rsassaPss, c"RSA-PSS"),
    (NID_X9_62_id_ecPublicKey, c"EC"),
    (NID_ED25519, c"ED25519"),
    (NID_ED448, c"ED448"),
    (NID_X25519, c"X25519"),
    (NID_X448, c"X448"),
    (NID_sm2, c"SM2"),
    (NID_dhKeyAgreement, c"DH"),
    (NID_dhpublicnumber, c"X9.42 DH"),
    (NID_dhpublicnumber, c"DHX"),
    (NID_dsa, c"DSA"),
];

/// `int evp_pkey_name2type(const char *name)`.
///
/// The twelve-name table first, compared with **`OPENSSL_strcasecmp`** — so `"rsa"`, `"Rsa"` and
/// `"RSA"` are one name — and then the `EVP_PKEY_type` fallback, which is Phase 8's and is the one
/// line of this function that is not here. See the module documentation: nothing exported can
/// observe the gap, and the record for it is D163.
///
/// `name` is **not** guarded against NULL and the authority does not guard it either: the first
/// thing the body does is hand it to a comparison, so a NULL is the caller's fault on both sides.
///
/// # Safety
/// `name` must be a NUL-terminated C string.
#[allow(dead_code)] // no caller until `keymgmt_meth.c`'s `legacy_alg` fill lands, in this subphase
pub(crate) unsafe fn evp_pkey_name2type(name: *const c_char) -> c_int {
    // SAFETY: `name` is NUL-terminated per the contract.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    for (id, spelling) in STANDARD_NAME2TYPE {
        if bytes.eq_ignore_ascii_case(spelling.to_bytes()) {
            return id;
        }
    }
    /* Phase 8: `EVP_PKEY_type(OBJ_sn2nid(name))` and then `EVP_PKEY_type(OBJ_ln2nid(name))`. Both
     * are absent because `EVP_PKEY_type` seaches a table of method objects that stratum defines.
     * The two object lookups themselves are available, and they are named here so that the gap is
     * exactly three lines wide rather than a paragraph: a name that is neither one of the twelve
     * above nor a provider-published key type answers `NID_undef` today, and will answer a NID once
     * Phase 8 lands. */
    let _ = (OBJ_sn2nid, OBJ_ln2nid);
    NID_undef
}

/// `const char *evp_pkey_type2name(int type)`.
///
/// The inverse, and the same shape: the twelve names, then **`OBJ_nid2sn`**. Its fallback *is*
/// writable, because `OBJ_nid2sn` is the object table's and not the method table's — so this
/// function is complete, and the asymmetry between it and `evp_pkey_name2type` is a real property of
/// the two directions rather than an oversight.
#[allow(dead_code)] // no caller until `EVP_PKEY_get0_type_name` and `EVP_PKEY_get_base_id` land
pub(crate) fn evp_pkey_type2name(type_: c_int) -> *const c_char {
    for (id, spelling) in STANDARD_NAME2TYPE {
        if type_ == id {
            return spelling.as_ptr();
        }
    }
    OBJ_nid2sn(type_)
}

// ---------------------------------------------------------------------------------------------
// The object
// ---------------------------------------------------------------------------------------------

/// `struct evp_pkey_st`'s `cache` member — four key properties every `EVP_PKEY_get_*` accessor
/// answers from, filled once per assignment by `evp_keymgmt_util_cache_keyinfo`.
///
/// `security_category` is the one field whose *unfilled* value differs from zero, and the difference
/// is the authority's: the provider's own initial value is `-1`, so a provider that answers the
/// parameter with 0 is saying something the cache can distinguish from a provider that does not
/// answer at all — but only if the cache is filled. An unfilled cache holds the struct's zero.
#[repr(C)]
pub struct EvpPkeyCache {
    /// `int bits`.
    pub(crate) bits: c_int,
    /// `int security_bits`.
    pub(crate) security_bits: c_int,
    /// `int security_category`.
    pub(crate) security_category: c_int,
    /// `int size`.
    pub(crate) size: c_int,
}

/// `struct evp_pkey_st` — the whole object, legacy block and provider block, in the authority's
/// member order.
///
/// **The legacy block landed with 8.8.** Phase 7.4a modelled only `ameth` and left `engine`,
/// `pmeth_engine`, the `pkey` / `legacy_cache_pkey` union, `attributes` and `foreign` absent, because
/// `EVP_PKEY_ASN1_METHOD` was then Phase 8's and `ENGINE` is Phase 13's. The eleven
/// `ossl_<alg>_asn1_meth` objects 8.8 lands read `pkey->pkey.<alg>` in every callback, so the block is
/// now modelled in full: `engine`, `pmeth_engine` and `attributes` are typed pointers that nothing in
/// this crate sets (Phase 13's and Phase 12's), the union is its `.ptr` spelling, and `foreign` is set
/// by [`detect_foreign_key`]. The effect is the state the authority calls a **legacy origin key**
/// (`keymgmt == NULL` with `type_ != EVP_PKEY_NONE`) — now enterable, and the tests below enter it.
///
/// The offsets are the authority's, measured rather than read, and pinned by the `const _` block
/// under the struct. See `courts/layout/measure-evp-pkey.c`.
#[repr(C)]
pub struct EvpPkey {
    /// `int type` — the legacy NID, `EVP_PKEY_KEYMGMT` for an unnamed provider key, or
    /// `EVP_PKEY_NONE` for a blank one. Rust reserves `type`, so the field takes the trailing
    /// underscore the project uses for a reserved word.
    pub(crate) type_: c_int,
    /// `int save_type` — the type as it was *asked for*, before the ameth lookup may have rewritten
    /// `type`.
    pub(crate) save_type: c_int,
    /// `const EVP_PKEY_ASN1_METHOD *ameth` — the legacy method of an origin key.
    ///
    /// **8.8 is its writer's enabler.** `pkey_set_type` is the authority's only writer, and its
    /// lookup is `EVP_PKEY_asn1_find_str`/`_find`, whose `standard_methods[]` is now populated with
    /// the eleven `ossl_<alg>_asn1_meth` objects, so a legacy type resolves to its method and the
    /// field is set. Before 8.8 the table was empty and this was always NULL, which the register
    /// carried as `D-PKEY-AMETH-1`; that divergence is retired with the table. `EVP_PKEY_get0_asn1`
    /// reads the field, and `evp_pkey_is_legacy` is `type_ != NONE && keymgmt == NULL`.
    pub(crate) ameth: *mut EvpPkeyAsn1Method,
    /// `ENGINE *engine` — "functional reference if 'meth' is ENGINE-provided". Phase 13's object;
    /// present so the offsets below match the authority's `struct evp_pkey_st` (measured by
    /// `courts/layout/measure-evp-pkey.c`), and written by nothing in this crate.
    pub(crate) engine: *mut Engine,
    /// `ENGINE *pmeth_engine` — "If not NULL public key ENGINE to use". Phase 13's, like `engine`.
    pub(crate) pmeth_engine: *mut Engine,
    /// `union legacy_pkey_st pkey` — the **origin** legacy low-level key. The authority's union has
    /// a member per key type (`pkey.rsa`, `pkey.dsa`, `pkey.dh`, `pkey.ec`, ...) sharing one
    /// address; the crate models the union as its `.ptr` spelling and each ameth callback casts it
    /// to its own key type, which is the same storage the authority reads by a different name.
    pub(crate) pkey: *mut c_void,
    /// `union legacy_pkey_st legacy_cache_pkey` — the **non-origin** legacy key: a downgraded copy
    /// of a provider key, cached by [`evp_pkey_get_legacy`]. Distinct from `pkey`, which is the
    /// origin key, and the two never hold a key at once.
    pub(crate) legacy_cache_pkey: *mut c_void,
    /// `CRYPTO_REF_COUNT references`.
    pub(crate) references: AtomicI32,
    /// `CRYPTO_RWLOCK *lock` — guards the operation cache and the dirty counters.
    pub(crate) lock: *mut CryptoRwlock,
    /// `STACK_OF(X509_ATTRIBUTE) *attributes` — `[ 0 ]`. Phase 12's element destructor
    /// (`X509_ATTRIBUTE_free`), so nothing in this crate sets it; present for the offset.
    pub(crate) attributes: *mut crate::runtime::stack::OpenSslStack,
    /// `int save_parameters` — set to **1** by `EVP_PKEY_new`, and read and written by
    /// `EVP_PKEY_save_parameters`'s two arms. Both test `type` against a legacy NID, and
    /// `pkey_set_type` writes `EVP_PKEY_KEYMGMT` into `type` for every key that has a method
    /// (`D-PKEY-AMETH-1`), so neither arm is reachable here and the field is the authority's
    /// layout rather than a state this crate enters. `attributes` and `foreign`, the two
    /// neighbouring legacy fields, are absent for the reasons this file's module doc gives.
    pub(crate) save_parameters: c_int,
    /// `unsigned int foreign : 1` — set by `detect_foreign_key` when the low-level key is
    /// engine-backed or application-method-backed, i.e. when its contents may not be readable
    /// directly. Projected as its four-byte storage, as `X509_pubkey_st`'s `flag_force_legacy` is.
    pub(crate) foreign: c_int,
    /// `CRYPTO_EX_DATA ex_data`.
    pub(crate) ex_data: CryptoExData,
    /// `EVP_KEYMGMT *keymgmt` — the provider method that owns `keydata`, holding a reference.
    pub(crate) keymgmt: *mut EvpKeyMgmt,
    /// `void *keydata` — the provider-side key, owned by `keymgmt`.
    pub(crate) keydata: *mut c_void,
    /// `size_t dirty_cnt` — incremented whenever anything modifies the key data.
    pub(crate) dirty_cnt: usize,
    /// `STACK_OF(OP_CACHE_ELEM) *operation_cache` — the exported copies, one per destination method.
    pub(crate) operation_cache: *mut crate::runtime::stack::OpenSslStack,
    /// `size_t dirty_cnt_copy` — `dirty_cnt` as of the last cache synchronisation.
    pub(crate) dirty_cnt_copy: usize,
    /// `struct { int bits; ... } cache`.
    pub(crate) cache: EvpPkeyCache,
}

/// The measured layout, pinned member by member.
///
/// `courts/layout/measure-evp-pkey.c` compiles the authority's own `struct evp_pkey_st` against the
/// admitted build's headers and prints its size and every member's offset; the numbers below are
/// those and not a reading of the declaration. `foreign` has no `offsetof` — it is a bitfield — so
/// its four-byte storage is asserted through `ex_data` at 80 following `save_parameters` at 72,
/// which is the only place it can be.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<EvpPkey>() == 152);
    assert!(align_of::<EvpPkey>() == 8);
    assert!(offset_of!(EvpPkey, type_) == 0);
    assert!(offset_of!(EvpPkey, save_type) == 4);
    assert!(offset_of!(EvpPkey, ameth) == 8);
    assert!(offset_of!(EvpPkey, engine) == 16);
    assert!(offset_of!(EvpPkey, pmeth_engine) == 24);
    assert!(offset_of!(EvpPkey, pkey) == 32);
    assert!(offset_of!(EvpPkey, legacy_cache_pkey) == 40);
    assert!(offset_of!(EvpPkey, references) == 48);
    assert!(offset_of!(EvpPkey, lock) == 56);
    assert!(offset_of!(EvpPkey, attributes) == 64);
    assert!(offset_of!(EvpPkey, save_parameters) == 72);
    assert!(offset_of!(EvpPkey, foreign) == 76);
    assert!(offset_of!(EvpPkey, ex_data) == 80);
    assert!(offset_of!(EvpPkey, keymgmt) == 96);
    assert!(offset_of!(EvpPkey, keydata) == 104);
    assert!(offset_of!(EvpPkey, dirty_cnt) == 112);
    assert!(offset_of!(EvpPkey, operation_cache) == 120);
    assert!(offset_of!(EvpPkey, dirty_cnt_copy) == 128);
    assert!(offset_of!(EvpPkey, cache) == 136);
};

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/p_lib.c".as_ptr();
/// `EVP_PKEY_new`'s `OPENSSL_zalloc(sizeof(*ret))` (line 1491).
const LINE_ZALLOC_PKEY: c_int = 1491;
/// `EVP_PKEY_get_bn_param`'s `OPENSSL_zalloc(buf_sz)` (line 2232).
const LINE_ZALLOC_BN_BUFFER: c_int = 2232;
/// `EVP_PKEY_get_bn_param`'s two frees of that buffer (lines 2248 and 2250).
const LINE_FREE_BN_BUFFER: c_int = 2248;

/// `EVP_PKEY *EVP_PKEY_new(void)`.
///
/// Two allocations and an ex-data initialisation, and the failure path is the reason the order is
/// what it is: the reference counter is created **before** the lock, so the `err` label can free the
/// counter whether or not the lock exists, and `CRYPTO_THREAD_lock_free(NULL)` is a no-op for the
/// same reason. `save_parameters = 1` is the one non-zero default, and it is set on the *legacy*
/// half's behalf: a `d2i` of a key with parameters saves them unless told otherwise.
///
/// # Safety
/// No preconditions. The function is `unsafe` because it is an exported `extern "C"` entry point
/// whose result is a raw pointer, not because it reads anything of the caller's.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new() -> *mut EvpPkey {
    /* `CRYPTO_zalloc` is one of the safe entry points of this crate: it validates its own argument
     * and answers NULL rather than reading anything of the caller's. */
    let ret =
        CRYPTO_zalloc(core::mem::size_of::<EvpPkey>(), FILE, LINE_ZALLOC_PKEY).cast::<EvpPkey>();

    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ret` is this call's own allocation.
    unsafe {
        (*ret).type_ = EVP_PKEY_NONE;
        (*ret).save_type = EVP_PKEY_NONE;
        (*ret).references = AtomicI32::new(1);
    }

    let lock = CRYPTO_THREAD_lock_new();
    if lock.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_1504) };
        // SAFETY: `ret` is this call's own allocation, not yet published.
        unsafe { CRYPTO_free(ret.cast(), FILE, LINE_ZALLOC_PKEY) };
        return ptr::null_mut();
    }
    // SAFETY: `ret` is live.
    unsafe { (*ret).lock = lock };

    /* The authority sets this immediately before the ex-data block, on the legacy half's behalf:
     * a `d2i` of a key with parameters saves them unless told otherwise. */
    // SAFETY: `ret` is live.
    unsafe { (*ret).save_parameters = 1 };

    // SAFETY: `ret` is live and `ex_data` is a field of it.
    if unsafe {
        CRYPTO_new_ex_data(
            CRYPTO_EX_INDEX_EVP_PKEY,
            ret.cast(),
            ptr::addr_of_mut!((*ret).ex_data),
        )
    } == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_1511) };
        // SAFETY: `lock` is live and `ret` is this call's own allocation.
        unsafe { CRYPTO_THREAD_lock_free(lock) };
        // SAFETY: `ret` is this call's own allocation, not yet published.
        unsafe { CRYPTO_free(ret.cast(), FILE, LINE_ZALLOC_PKEY) };
        return ptr::null_mut();
    }
    ret
}

/// `int EVP_PKEY_up_ref(EVP_PKEY *pkey)`.
///
/// Answers **1** for any live key, and that is not a simplification: the authority's `CRYPTO_UP_REF`
/// cannot fail for a positive count, so the `i > 1` test it does afterwards is true for every
/// object that can reach here.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_up_ref(pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    unsafe { (*pkey).references.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `static void evp_pkey_free_it(EVP_PKEY *x)` — release the key data, keeping the object.
///
/// The authority's comment says "x is never NULL", and it is the only function here that says so.
/// The **order** is the contract: the operation cache is cleared *first*, because every cached entry
/// holds a reference to its `keymgmt` and a key data derived from `x->keydata`, and releasing
/// `x->keymgmt` before the cache would leave the entries pointing at a freed method.
///
/// # Safety
/// `x` must be live.
unsafe fn evp_pkey_free_it(x: *mut EvpPkey) {
    // SAFETY: `x` is live per the contract.
    unsafe { evp_keymgmt_util_clear_operation_cache(x) };

    // SAFETY: `x` is live; the legacy origin/cache key is released before the provider one, which
    // is the authority's own order.
    unsafe { evp_pkey_free_legacy(x) };

    // SAFETY: `x` is live.
    let keymgmt = unsafe { (*x).keymgmt };
    if !keymgmt.is_null() {
        // SAFETY: `keymgmt` is live and `keydata` belongs to it.
        unsafe { crate::evp::keymgmt::evp_keymgmt_freedata(keymgmt, (*x).keydata) };
        // SAFETY: `keymgmt` is live and this key holds the reference `pkey_set_type` took.
        unsafe { EVP_KEYMGMT_free(keymgmt) };
        // SAFETY: `x` is live.
        unsafe {
            (*x).keymgmt = ptr::null_mut();
            (*x).keydata = ptr::null_mut();
        }
    }
    // SAFETY: `x` is live.
    unsafe { (*x).type_ = EVP_PKEY_NONE };
}

/// `void evp_pkey_free_legacy(EVP_PKEY *x)` — `crypto/evp/p_lib.c:1777`.
///
/// The authority's body releases a legacy **origin** key through `ameth->pkey_free`, and it also
/// releases a legacy **cache** key: when `ameth` is NULL but `legacy_cache_pkey.ptr` is set it
/// re-finds the method by `x->type`, then makes the cache key look like an origin key so that the
/// one `pkey_free` call covers both. The crate transcribes both halves; the four `ENGINE_finish`
/// calls are each handed a NULL because `ENGINE` is Phase 13's and this crate registers no engine.
///
/// The `ameth == NULL && legacy_cache_pkey.ptr != NULL` arm is unreachable on every path this
/// crate can enter — a legacy cache key is only ever made by [`evp_pkey_get_legacy`], which first
/// needs an ameth for the type — but it is written because `EVP_PKEY_asn1_find` is landed and the
/// transcription is then the authority's.
///
/// # Safety
/// `x` must be NULL or a live `EvpPkey`.
#[allow(dead_code)] // first live caller is `EVP_PKEY_generate` in `pmeth_gn.rs`
pub(crate) unsafe fn evp_pkey_free_legacy(x: *mut EvpPkey) {
    // SAFETY: `x` is live per the contract.
    unsafe {
        let mut ameth = (*x).ameth;
        /* The re-find arm: `ameth == NULL && legacy_cache_pkey.ptr != NULL`. */
        if ameth.is_null() && !(*x).legacy_cache_pkey.is_null() {
            ameth = crate::evp::pkey_asn1::EVP_PKEY_asn1_find(ptr::null_mut(), (*x).type_)
                as *mut EvpPkeyAsn1Method;
        }

        if !ameth.is_null() {
            if !(*x).legacy_cache_pkey.is_null() {
                /* The authority asserts `x->pkey.ptr == NULL` here: an origin and a cache key are
                 * never both set. The assert is a no-op in the released build the crate mirrors. */
                (*x).pkey = (*x).legacy_cache_pkey;
                (*x).legacy_cache_pkey = ptr::null_mut();
            }
            if let Some(pkey_free) = (*ameth).pkey_free {
                // SAFETY: `pkey_free` is the method's destructor and `x` is its key.
                pkey_free(x);
            }
            (*x).pkey = ptr::null_mut();
        }
    }
}

/// `void EVP_PKEY_free(EVP_PKEY *x)`.
///
/// The release order matches the authority's, and the release-then-free pair is `fetch_sub`'s return:
/// the object is freed exactly by the call that observes a count of **1**, and a key with no
/// references left reports `0` because the count was already 1 and not because anything set it.
///
/// # Safety
/// `x` must be NULL or a live `EvpPkey`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_free(x: *mut EvpPkey) {
    if x.is_null() {
        return;
    }

    // SAFETY: `x` is live per the contract.
    let last = unsafe { (*x).references.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }

    // SAFETY: `x` is live and this is the last reference.
    unsafe { evp_pkey_free_it(x) };
    // SAFETY: `x` is live and `ex_data` is a field of it.
    unsafe {
        CRYPTO_free_ex_data(
            CRYPTO_EX_INDEX_EVP_PKEY,
            x.cast(),
            ptr::addr_of_mut!((*x).ex_data),
        )
    };
    // SAFETY: `x` is live and `lock` is the lock `EVP_PKEY_new` created.
    let lock = unsafe { (*x).lock };
    // SAFETY: `lock` is live and not yet freed.
    unsafe { CRYPTO_THREAD_lock_free(lock) };
    // SAFETY: `x` is this object's own allocation.
    unsafe { CRYPTO_free(x.cast(), FILE, LINE_ZALLOC_PKEY) };
}

/// `static int pkey_set_type(EVP_PKEY *pkey, ENGINE *e, int type, const char *str, int len,
/// EVP_KEYMGMT *keymgmt)`.
///
/// The ameth lookup and the provider path. A `str` is resolved with `EVP_PKEY_asn1_find_str` and a
/// non-`NONE` type with `EVP_PKEY_asn1_find`; a method found with `keymgmt == NULL` makes the key a
/// **legacy origin** key whose `type_` is the method's own `pkey_id`, and no method with a
/// `keymgmt` is an unsupported-algorithm refusal. The `ENGINE **eptr` half of the authority's calls
/// is absent because `ENGINE` is Phase 13's, and the two `ENGINE_finish` pairs collapse to nothing
/// for the same reason — the crate registers no engine, so the authority's own arm would hand them
/// NULLs and answer identically.
///
/// Three things that look like details and are not:
///
///   * `ossl_assert(x)` under `NDEBUG` is `(x) != 0`, which is the identity on a boolean, so the
///     authority's opening guard is `if (!C)` — a **refusal**, not a no-op: a caller supplying both
///     a legacy type and a provider method gets `ERR_R_INTERNAL_ERROR` and a 0 return. Both clauses
///     are unsatisifiable here — there is no `ENGINE` in this crate and every caller passes
///     `EVP_PKEY_NONE` — so the guard is deliberately not transcribed. That is a documented
///     simplification, not a released-build behaviour (`docs/DECISIONS.md` D167);
///   * `free_it` is true when the key is **assigned**, in either half, and it releases the key data
///     *before* the new type is looked up: reassigning is destructive even if the new type turns
///     out not to exist;
///   * the `up_ref` is taken **after** the "unsupported" refusal, so a failed call takes nothing.
///
/// # Safety
/// `pkey` must be NULL or live; `keymgmt` must be NULL or live; `str` must be NULL or NUL-terminated
/// readable for `len` bytes when `len` is not `-1`.
unsafe fn pkey_set_type(
    pkey: *mut EvpPkey,
    type_: c_int,
    str_: *const c_char,
    len: c_int,
    keymgmt: *mut EvpKeyMgmt,
) -> c_int {
    if !pkey.is_null() {
        // SAFETY: `pkey` is live.
        let free_it = unsafe { !(*pkey).pkey.is_null() || !(*pkey).keydata.is_null() };
        if free_it {
            // SAFETY: `pkey` is live.
            unsafe { evp_pkey_free_it(pkey) };
        }
        /* The authority's fast path: an already-matching type with a method is a success without a
         * second lookup. */
        // SAFETY: `pkey` is live.
        if unsafe {
            (*pkey).type_ != EVP_PKEY_NONE && type_ == (*pkey).save_type && !(*pkey).ameth.is_null()
        } {
            return 1;
        }
    }

    /* The ameth lookup. The authority's `ENGINE **eptr` is a NULL slot here: `EVP_PKEY_asn1_find`
     * and `_find_str` are handed a NULL `pe`, which is what their own engine arm would answer with. */
    // SAFETY: no preconditions; both lookups search this crate's own tables.
    let ameth = unsafe {
        if !str_.is_null() {
            crate::evp::pkey_asn1::EVP_PKEY_asn1_find_str(ptr::null_mut(), str_, len)
        } else if type_ != EVP_PKEY_NONE {
            crate::evp::pkey_asn1::EVP_PKEY_asn1_find(ptr::null_mut(), type_)
        } else {
            ptr::null()
        }
    };

    /* The authority's `check`: no method and no keymgmt is a refusal. The guard above it refuses
     * with `ERR_R_INTERNAL_ERROR` and is unreachable here; see this function's doc comment (D167). */
    if ameth.is_null() && keymgmt.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_1601) };
        return 0;
    }

    if !pkey.is_null() {
        if !keymgmt.is_null() {
            // SAFETY: `keymgmt` is live and this takes the key's own reference to it.
            if unsafe { EVP_KEYMGMT_up_ref(keymgmt) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::P_LIB_1607) };
                return 0;
            }
        }

        // SAFETY: `pkey` is live.
        unsafe {
            (*pkey).keymgmt = keymgmt;
            (*pkey).save_type = type_;
            (*pkey).type_ = type_;

            /* The authority's `if (keymgmt == NULL) pkey->ameth = ameth;` and its two-arm type
             * fix-up: a method's own `pkey_id` wins over `EVP_PKEY_NONE`, and a key with neither a
             * method nor a provider is the `EVP_PKEY_KEYMGMT` pseudo-NID. */
            if keymgmt.is_null() {
                (*pkey).ameth = ameth.cast_mut();
            }
            if !ameth.is_null() {
                if type_ == EVP_PKEY_NONE {
                    (*pkey).type_ = (*ameth).pkey_id;
                }
            } else {
                (*pkey).type_ = EVP_PKEY_KEYMGMT;
            }
        }
    }
    1
}

/// `int EVP_PKEY_set_type_by_keymgmt(EVP_PKEY *pkey, EVP_KEYMGMT *keymgmt)`.
///
/// The public entry point, and the **only** one the authority has: there is no internal
/// `evp_pkey_set_type_by_keymgmt` in `crypto/evp/p_lib.c` or its header, and `keymgmt_lib.c`'s
/// `evp_keymgmt_util_assign_pkey`/`evp_keymgmt_util_copy` call *this* function, name walk and all.
/// A crate-local helper that called [`pkey_set_type`] with a NULL `str` would skip the walk and
/// leave a provider key named `"RSA"` typed `EVP_PKEY_KEYMGMT` where the authority types it
/// `EVP_PKEY_RSA` -- the `D-PKEY-AMETH-1` observable, measured by `RT-KEYFORMAT`.
///
/// The authority first walks the method's **names** looking for one that
/// an `EVP_PKEY_ASN1_METHOD` exists for, refuses if it finds two, and passes the one it found on;
/// the walk is what makes the *ambiguity* refusal reachable, and with the table populated it now
/// finds a method for a provider key named `"RSA"` and types it with the legacy NID.
///
/// # Safety
/// `pkey` must be live; `keymgmt` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_type_by_keymgmt(
    pkey: *mut EvpPkey,
    keymgmt: *mut EvpKeyMgmt,
) -> c_int {
    let mut found: [*const c_char; 2] = [ptr::null(); 2];

    // SAFETY: `keymgmt` is live per the contract, the visitor is this file's own, and `found` is a
    // live local of two entries.
    let walked = unsafe {
        EVP_KEYMGMT_names_do_all(
            keymgmt,
            Some(find_ameth),
            ptr::addr_of_mut!(found).cast::<c_void>(),
        )
    };
    if walked == 0 || !found[1].is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_1688) };
        return 0;
    }

    // SAFETY: `pkey` is live and `keymgmt` is live.
    unsafe { pkey_set_type(pkey, EVP_PKEY_NONE, found[0], -1, keymgmt) }
}

/// `static void find_ameth(const char *name, void *data)` — the visitor
/// `EVP_PKEY_set_type_by_keymgmt` uses. It records at most **two** names, and the second makes an
/// ambiguous match a refusal rather than a choice.
///
/// The authority's body calls `pkey_set_type(NULL, NULL, EVP_PKEY_NONE, name, strlen(name), NULL)`
/// purely to ask whether an ameth exists, wrapped in `ERR_set_mark`/`ERR_pop_to_mark` because "the
/// error messages from `pkey_set_type()` are uninteresting here, and misleading". A non-NULL answer
/// is recorded in the caller's two-slot array.
///
/// # Safety
/// `data` must point at a two-element array of `const char *`; `name` must be NUL-terminated.
unsafe extern "C" fn find_ameth(name: *const c_char, data: *mut c_void) {
    crate::runtime::err::ERR_set_mark();
    // SAFETY: `data` points at a two-element array per the contract.
    let found = data.cast::<*const c_char>();
    // SAFETY: `name` is NUL-terminated per the contract.
    let len = unsafe { crate::runtime::bio::sys::strlen(name) } as c_int;
    // SAFETY: no preconditions; the lookup searches this crate's own tables.
    let ameth =
        unsafe { crate::evp::pkey_asn1::EVP_PKEY_asn1_find_str(ptr::null_mut(), name, len) };
    if !ameth.is_null() {
        // SAFETY: `found` has two slots per the contract.
        unsafe {
            if (*found).is_null() {
                *found = name;
            } else {
                *found.add(1) = name;
            }
        }
    }
    crate::runtime::err::ERR_pop_to_mark();
}

/// `int EVP_PKEY_get_id(const EVP_PKEY *pkey)`.
///
/// A field read. For a provider key the type is `EVP_PKEY_KEYMGMT` unless one of the method's names
/// found a legacy method, in which case `pkey_set_type` stored the method's legacy NID — which is
/// what `EVP_PKEY_set_type_by_keymgmt`'s `find_ameth` walk now produces.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_id(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    unsafe { (*pkey).type_ }
}

/// `int EVP_PKEY_is_a(const EVP_PKEY *pkey, const char *name)`.
///
/// Two arms, and the first is a **NULL guard that answers 0** rather than a fault. The legacy arm
/// compares the key's type against `evp_pkey_name2type(name)`, whose `EVP_PKEY_type` fallback is
/// Phase 8's — a real gap, unreachable here because a legacy origin cannot be constructed, and
/// recorded in this file's module doc and D163.
///
/// # Safety
/// `pkey` NULL or live; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_is_a(pkey: *const EvpPkey, name: *const c_char) -> c_int {
    if pkey.is_null() {
        return 0;
    }
    // SAFETY: `pkey` is live per the contract.
    let keymgmt = unsafe { (*pkey).keymgmt };
    if keymgmt.is_null() {
        // SAFETY: `pkey` is live and `name` is NUL-terminated per the contract.
        let type_ = unsafe { (*pkey).type_ };
        // SAFETY: `name` is NUL-terminated.
        return c_int::from(type_ == unsafe { evp_pkey_name2type(name) });
    }
    // SAFETY: `keymgmt` is live and `name` is NUL-terminated.
    unsafe { EVP_KEYMGMT_is_a(keymgmt, name) }
}

/// `int EVP_PKEY_type_names_do_all(const EVP_PKEY *pkey, void (*fn)(const char *, void *),
/// void *data)`.
///
/// A **typed** key is required and a blank one answers 0 — the only refusal, and it is tested with
/// `evp_pkey_is_typed`, which is true when *either* half has a type. The legacy arm visits exactly
/// one name, from the object table; the provider arm delegates to the method's own walk.
///
/// # Safety
/// `pkey` must be live; `fn` must be a valid visitor.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_type_names_do_all(
    pkey: *const EvpPkey,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let (type_, keymgmt) = unsafe { ((*pkey).type_, (*pkey).keymgmt) };
    if type_ == EVP_PKEY_NONE && keymgmt.is_null() {
        return 0;
    }

    if keymgmt.is_null() {
        let name = OBJ_nid2sn(type_);
        if let Some(f) = fn_ {
            // SAFETY: `f` is the caller's visitor and `name` is a NUL-terminated string of the
            // object table alives for the process's lifetime.
            unsafe { f(name, data) };
        }
        return 1;
    }
    // SAFETY: `keymgmt` is live and `fn_` is the caller's visitor.
    unsafe { EVP_KEYMGMT_names_do_all(keymgmt, fn_, data) }
}

/// `const char *EVP_PKEY_get0_description(const EVP_PKEY *pkey)`.
///
/// Two refusals that look like one: an **unassigned** key answers NULL, and an assigned one whose
/// method publishes no description answers NULL as well. The distinction is that the first is about
/// the key having no data and the second about the provider having no prose.
///
/// # Safety
/// `pkey` must be live.
///
/// The `pkey->ameth->info` arm is Phase 8's and unreachable here; the authority's own order puts the
/// provider's description first, so a provider key never reaches it.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_description(pkey: *const EvpPkey) -> *const c_char {
    // SAFETY: `pkey` is live per the contract.
    let (keydata, keymgmt) = unsafe { ((*pkey).keydata, (*pkey).keymgmt) };
    if keydata.is_null() {
        return ptr::null();
    }

    if !keymgmt.is_null() {
        // SAFETY: `keymgmt` is live.
        let description = unsafe { (*keymgmt).description };
        if !description.is_null() {
            return description;
        }
    }
    ptr::null()
}

/// `const OSSL_PROVIDER *EVP_PKEY_get0_provider(const EVP_PKEY *key)`.
///
/// One arm, and it answers NULL for a key that is not provider-side rather than faulting. The
/// authority writes the test as `evp_pkey_is_provided`, i.e. `keymgmt != NULL`.
///
/// # Safety
/// `key` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_provider(key: *const EvpPkey) -> *const OsslProvider {
    // SAFETY: `key` is live per the contract.
    let keymgmt = unsafe { (*key).keymgmt };
    if keymgmt.is_null() {
        return ptr::null();
    }
    // SAFETY: `keymgmt` is live.
    unsafe { EVP_KEYMGMT_get0_provider(keymgmt) }
}

/// `const char *EVP_PKEY_get0_type_name(const EVP_PKEY *key)`.
///
/// The provider arm answers the method's first name; the legacy arm asks the ameth for an info string
/// and is Phase 8's, so an unnamed key answers NULL.
///
/// # Safety
/// `key` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_type_name(key: *const EvpPkey) -> *const c_char {
    // SAFETY: `key` is live per the contract.
    let keymgmt = unsafe { (*key).keymgmt };
    if !keymgmt.is_null() {
        // SAFETY: `keymgmt` is live.
        return unsafe { EVP_KEYMGMT_get0_name(keymgmt) };
    }
    ptr::null()
}

/// `int EVP_PKEY_get_size(const EVP_PKEY *pkey)`.
///
/// Answers the cached `size` and **raises** `EVP_R_UNKNOWN_MAX_SIZE` when it is not positive, so a
/// key whose provider does not publish `max-size` is a *reported* failure rather than a zero.
///
/// # Safety
/// `pkey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_size(pkey: *const EvpPkey) -> c_int {
    let mut size = 0;

    if !pkey.is_null() {
        // SAFETY: `pkey` is live per the contract.
        size = unsafe { (*pkey).cache.size };
        /* D369: the `ameth` override below `FIPS_MODULE`. `pkey_set_type`'s lookup now finds
         * every `standard_methods[]` row (D353), so a legacy key's method answers where the cache
         * is empty -- the arm D163/D165's comment recorded as unreachable. */
        // SAFETY: `pkey` is live.
        let ameth = unsafe { (*pkey).ameth };
        if !ameth.is_null() {
            // SAFETY: `ameth` is the key's own method table.
            if let Some(f) = unsafe { (*ameth).pkey_size } {
                // SAFETY: the callback is the key's own, with the authority's signature.
                size = unsafe { f(pkey) };
            }
        }
    }
    if size <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_1866) };
        return 0;
    }
    size
}

/// `int EVP_PKEY_set_ex_data(EVP_PKEY *key, int idx, void *arg)`.
///
/// # Safety
/// `key` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_ex_data(
    key: *mut EvpPkey,
    idx: c_int,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: `key` is live and `ex_data` is a field of it.
    unsafe { CRYPTO_set_ex_data(ptr::addr_of_mut!((*key).ex_data), idx, arg) }
}

/// `void *EVP_PKEY_get_ex_data(const EVP_PKEY *key, int idx)`.
///
/// # Safety
/// `key` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_ex_data(key: *const EvpPkey, idx: c_int) -> *mut c_void {
    // SAFETY: `key` is live and `ex_data` is a field of it.
    unsafe { CRYPTO_get_ex_data(ptr::addr_of!((*key).ex_data), idx) }
}

/// `EVP_PKEY *EVP_PKEY_dup(EVP_PKEY *pkey)`.
///
/// Public key is **required** and a NULL one raises `ERR_R_PASSED_NULL_PARAMETER`, which is the only
/// place in this unit that raises for a NULL argument rather than answering a value.
///
/// A **blank** key is duplicated as a blank key — the `goto done` — and the difference from a typed
/// but unassigned one is the whole reason `is_blank` exists beside `is_typed`. `done` copies the
/// ex-data for every non-blank key, so a key's `CRYPTO_EX_DATA` callbacks see the duplicate.
///
/// The `attributes` copy is Phase 12's `ossl_x509at_dup`, and the field it copies cannot be non-NULL
/// in this crate — see `EvpPkey`'s doc comment.
///
/// # Safety
/// `pkey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_dup(pkey: *mut EvpPkey) -> *mut EvpPkey {
    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_1720) };
        return ptr::null_mut();
    }

    // SAFETY: no preconditions.
    let dup_pk = unsafe { EVP_PKEY_new() };
    if dup_pk.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `pkey` is live per the contract.
    let (type_, keymgmt) = unsafe { ((*pkey).type_, (*pkey).keymgmt) };
    /* Blank: nothing to copy, and the duplicate stays blank. */
    if type_ == EVP_PKEY_NONE && keymgmt.is_null() {
        // SAFETY: `dup_pk` is this call's own object and `pkey` is live.
        return unsafe { pkey_dup_done(dup_pk, pkey) };
    }

    if keymgmt.is_null() {
        /* A legacy key: Phase 8's `ameth->copy`, or a type-only assign. Neither is reachable in
         * this crate, because `pkey_set_type` cannot produce a legacy origin. */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_1748) };
        // SAFETY: `dup_pk` is this call's own object.
        unsafe { EVP_PKEY_free(dup_pk) };
        return ptr::null_mut();
    }

    /* The provider arm. The authority's `#ifndef FIPS_MODULE` guard is around the *test*, so the
     * provider path is the only one a key with a method can take. */
    // SAFETY: both keys are live and the selection is the authority's constant.
    if unsafe {
        crate::evp::keymgmt_lib::evp_keymgmt_util_copy(dup_pk, pkey, OSSL_KEYMGMT_SELECT_ALL)
    } == 0
    {
        // SAFETY: `dup_pk` is this call's own object.
        unsafe { EVP_PKEY_free(dup_pk) };
        return ptr::null_mut();
    }

    // SAFETY: `dup_pk` is this call's own object and `pkey` is live.
    unsafe { pkey_dup_done(dup_pk, pkey) }
}

/// The authority's `done:` label — copy the ex-data and hand back the duplicate.
///
/// # Safety
/// `dup_pk` must be this call's own, unpublished object; `pkey` must be live.
unsafe fn pkey_dup_done(dup_pk: *mut EvpPkey, pkey: *const EvpPkey) -> *mut EvpPkey {
    // SAFETY: both keys are live and their `ex_data` fields are live.
    if unsafe {
        CRYPTO_dup_ex_data(
            CRYPTO_EX_INDEX_EVP_PKEY,
            ptr::addr_of_mut!((*dup_pk).ex_data),
            ptr::addr_of!((*pkey).ex_data),
        )
    } == 0
    {
        // SAFETY: `dup_pk` is this call's own object.
        unsafe { EVP_PKEY_free(dup_pk) };
        return ptr::null_mut();
    }
    dup_pk
}

/// `OSSL_KEYMGMT_SELECT_ALL` — `include/openssl/core_dispatch.h`, spelled out as the authority
/// composes it: the key pair (`PRIVATE_KEY | PUBLIC_KEY`) and all parameters
/// (`DOMAIN_PARAMETERS | OTHER_PARAMETERS`). `pub(crate)` since D372: `crypto/ec/ecx_meth.c`'s
/// `ecx_pkey_copy` passes it to [`crate::ec::ecx_backend::ossl_ecx_key_dup`].
pub(crate) const OSSL_KEYMGMT_SELECT_ALL: c_int = (0x01 | 0x02) | (0x04 | 0x80);
/// `OSSL_KEYMGMT_SELECT_ALL` under its authority spelling, for the `*_ameth.c` `export_to`
/// callbacks. `OSS_L_KEYMGMT_SELECT_ALL` is the same value; the private name above is kept for the
/// call sites that read the macro as the authority spells it there.
pub(crate) const OSSL_KEYMGMT_SELECT_ALL_BITS: c_int = (0x01 | 0x02) | (0x04 | 0x80);

// ---------------------------------------------------------------------------------------------
// The parameter family
// ---------------------------------------------------------------------------------------------
//
// Ten accessors over one pair of delegations. Every one of them builds a **one-parameter**
// `OSSL_PARAM` array addressed at a caller-supplied buffer, hands it to `EVP_PKEY_get_params` or
// `EVP_PKEY_set_params`, and then reads the `return_size`/`modified` information back — so the shape
// of the whole family is decided by two facts about the parameter contract:
//
//   * a `get` that succeeds may still not have filled the parameter, which is why every reader
//     checks `OSSL_PARAM_modified` as well as the call's own return, and
//   * a `get` that *fails* may have failed **only because the buffer was too small**, which is why
//     `EVP_PKEY_get_bn_param` retries into an allocation sized by `return_size`. That retry is the
//     only member of the family with a heap allocation, and its two cleanup paths differ: a buffer
//     that was filled is cleared before it is freed, and one that was not is freed plain.

/// `int EVP_PKEY_get_bn_param(const EVP_PKEY *pkey, const char *key_name, BIGNUM **bn)`.
///
/// The **retry** member. A 2048-byte stack buffer first, then a sized heap buffer if the call failed
/// with the parameter *modified* — which is the authority's way of saying "the destination was too
/// small, here is the size you need". `OSSL_PARAM_modified` is tested three times in three different
/// senses and each one is load-bearing:
///
///   * after the first failure, to tell "too small" from "not supported" (an unmodified parameter
///     means the provider never looked at it, so there is nothing to retry and nothing to report),
///   * after the retry block, to tell "filled" from "absent" — a provider that answers `get_params`
///     successfully while leaving the parameter unset is a *failure* here,
///   * in the cleanup, to choose between `OPENSSL_clear_free` (the buffer holds key material) and
///     `OPENSSL_free` (it does not), and between clearing the stack buffer and leaving it.
///
/// # Safety
/// `pkey` must be NULL or live; `key_name` NULL or NUL-terminated; `bn` NULL or a live `BIGNUM **`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_bn_param(
    pkey: *const EvpPkey,
    key_name: *const c_char,
    bn: *mut *mut BigNum,
) -> c_int {
    let mut params = [crate::params::END; 2];
    /* The authority memsets this to zero before handing it to the constructor, which matters for the
     * cleanup rather than for the read: an unfilled buffer is cleansed on the way out, and cleansing
     * uninitialised bytes would be a read of them. */
    let mut buffer = [0u8; 2048];
    let mut buf: *mut u8 = ptr::null_mut();
    let mut buf_sz: usize = 0;

    if key_name.is_null() || bn.is_null() {
        return 0;
    }

    // SAFETY: `key_name` is NUL-terminated and `buffer` is a live 2048-byte buffer.
    unsafe {
        params[0] =
            crate::params::OSSL_PARAM_construct_BN(key_name, buffer.as_mut_ptr(), buffer.len());
        params[1] = crate::params::OSSL_PARAM_construct_end();
    }
    // SAFETY: `pkey` is NULL or live and `params` is a terminated array whose data pointer is live.
    if unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) } == 0 {
        // SAFETY: `params` is a live array.
        if unsafe { crate::params::OSSL_PARAM_modified(params.as_ptr()) } == 0
            || params[0].return_size == 0
        {
            return 0;
        }
        buf_sz = params[0].return_size;
        /* `CRYPTO_zalloc` is a safe entry point of this crate: it validates its own argument and
         * answers NULL rather than reading anything of the caller's. */
        buf = CRYPTO_zalloc(buf_sz, FILE, LINE_ZALLOC_BN_BUFFER).cast::<u8>();
        if buf.is_null() {
            return 0;
        }
        params[0].data = buf.cast::<c_void>();
        params[0].data_size = buf_sz;

        // SAFETY: `pkey` is NULL or live and the buffer is now `buf_sz` bytes of `buf`.
        if unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) } == 0 {
            // SAFETY: both are this call's own.
            return unsafe { bn_param_cleanup(buf, buf_sz, &mut params, &mut buffer, 0) };
        }
    }
    /* Fail if the param was not found. */
    // SAFETY: `params` is a live array.
    if unsafe { crate::params::OSSL_PARAM_modified(params.as_ptr()) } == 0 {
        // SAFETY: both are this call's own.
        return unsafe { bn_param_cleanup(buf, buf_sz, &mut params, &mut buffer, 0) };
    }
    // SAFETY: `params` holds one modified BN parameter and `bn` is a live out-parameter.
    let ret = unsafe { crate::params::OSSL_PARAM_get_BN(params.as_ptr(), bn) };
    // SAFETY: both are this call's own.
    unsafe { bn_param_cleanup(buf, buf_sz, &mut params, &mut buffer, ret) }
}

/// The `err:` label of `EVP_PKEY_get_bn_param`, which is reached with `ret` still zero.
///
/// # Safety
/// `buf` must be NULL or `buf_sz` bytes allocated by this call; `params` and `buffer` must be the
/// live locals of the caller.
unsafe fn bn_param_cleanup(
    buf: *mut u8,
    buf_sz: usize,
    params: &mut [crate::params::OsslParam; 2],
    buffer: &mut [u8; 2048],
    ret: c_int,
) -> c_int {
    // SAFETY: `params` is a live array of two.
    let modified = unsafe { crate::params::OSSL_PARAM_modified(params.as_ptr()) } != 0;
    if !buf.is_null() {
        if modified {
            // SAFETY: `buf` is `buf_sz` bytes this call allocated and `modified` says the provider
            // wrote into it, so it may hold key material.
            unsafe { CRYPTO_clear_free(buf.cast(), buf_sz, FILE, LINE_FREE_BN_BUFFER) };
        } else {
            // SAFETY: `buf` is `buf_sz` bytes this call allocated and nothing was written.
            unsafe { CRYPTO_free(buf.cast(), FILE, LINE_FREE_BN_BUFFER) };
        }
    } else if modified {
        // SAFETY: `buffer` is a live 2048-byte buffer and the provider wrote
        // `params[0].data_size` bytes into it.
        unsafe {
            crate::runtime::mem::OPENSSL_cleanse(buffer.as_mut_ptr().cast(), params[0].data_size)
        };
    }
    ret
}

/// `int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name,
/// unsigned char *buf, size_t max_buf_sz, size_t *out_len)`.
///
/// Two return values folded into one: the call's own success **and** the parameter's modification,
/// so a provider that answered successfully without filling the parameter reports failure. The
/// length out-parameter is written only when both are true.
///
/// # Safety
/// `pkey` NULL or live; `key_name` NULL or NUL-terminated; `buf` NULL or writable for `max_buf_sz`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_octet_string_param(
    pkey: *const EvpPkey,
    key_name: *const c_char,
    buf: *mut u8,
    max_buf_sz: usize,
    out_len: *mut usize,
) -> c_int {
    let mut params = [crate::params::END; 2];
    let mut ret2 = 0;

    if key_name.is_null() {
        return 0;
    }

    // SAFETY: `key_name` is NUL-terminated and `buf` is writable for `max_buf_sz`.
    unsafe {
        params[0] =
            crate::params::OSSL_PARAM_construct_octet_string(key_name, buf.cast(), max_buf_sz);
        params[1] = crate::params::OSSL_PARAM_construct_end();
    }
    // SAFETY: `pkey` is NULL or live and `params` is a terminated array.
    let ret1 = unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) };
    if ret1 != 0 {
        // SAFETY: `params` is a live array.
        ret2 = unsafe { crate::params::OSSL_PARAM_modified(params.as_ptr()) };
    }
    if ret2 != 0 && !out_len.is_null() {
        // SAFETY: `out_len` is non-NULL.
        unsafe { *out_len = params[0].return_size };
    }
    c_int::from(ret1 != 0 && ret2 != 0)
}

/// `int EVP_PKEY_get_utf8_string_param(const EVP_PKEY *pkey, const char *key_name, char *str,
/// size_t max_buf_sz, size_t *out_len)`.
///
/// The octet-string shape with two additions, and both are about the **terminator**: a `return_size`
/// equal to the buffer size means there was no room for a NUL, which is a failure rather than a
/// truncated success; otherwise a NUL is written *one past the reported length*, which is safe
/// exactly because of that test.
///
/// # Safety
/// `pkey` NULL or live; `key_name` NULL or NUL-terminated; `str` NULL or writable for `max_buf_sz`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_utf8_string_param(
    pkey: *const EvpPkey,
    key_name: *const c_char,
    str_: *mut c_char,
    max_buf_sz: usize,
    out_len: *mut usize,
) -> c_int {
    let mut params = [crate::params::END; 2];
    let mut ret2 = 0;

    if key_name.is_null() {
        return 0;
    }

    // SAFETY: `key_name` is NUL-terminated and `str_` is writable for `max_buf_sz`.
    unsafe {
        params[0] = crate::params::OSSL_PARAM_construct_utf8_string(key_name, str_, max_buf_sz);
        params[1] = crate::params::OSSL_PARAM_construct_end();
    }
    // SAFETY: `pkey` is NULL or live and `params` is a terminated array.
    let ret1 = unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) };
    if ret1 != 0 {
        // SAFETY: `params` is a live array.
        ret2 = unsafe { crate::params::OSSL_PARAM_modified(params.as_ptr()) };
    }
    if ret2 != 0 && !out_len.is_null() {
        // SAFETY: `out_len` is non-NULL.
        unsafe { *out_len = params[0].return_size };
    }

    if ret2 != 0 && params[0].return_size == max_buf_sz {
        /* There was no space for a NUL byte. */
        return 0;
    }
    if ret2 != 0 && !str_.is_null() {
        // SAFETY: `str_` is writable for `max_buf_sz` and `return_size < max_buf_sz`.
        unsafe { *str_.add(params[0].return_size) = 0 };
    }

    c_int::from(ret1 != 0 && ret2 != 0)
}

/// `int EVP_PKEY_get_int_param(const EVP_PKEY *pkey, const char *key_name, int *out)`.
///
/// The short shape: the call's return **and** the modification, with the destination written by the
/// provider through the descriptor rather than by this function.
///
/// # Safety
/// `pkey` NULL or live; `key_name` NULL or NUL-terminated; `out` NULL or a live `int`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_int_param(
    pkey: *const EvpPkey,
    key_name: *const c_char,
    out: *mut c_int,
) -> c_int {
    let mut params = [crate::params::END; 2];

    if key_name.is_null() {
        return 0;
    }

    // SAFETY: `key_name` is NUL-terminated and `out` is a live `int`.
    unsafe {
        params[0] = crate::params::OSSL_PARAM_construct_int(key_name, out);
        params[1] = crate::params::OSSL_PARAM_construct_end();
    }
    // SAFETY: `pkey` is NULL or live and `params` is a terminated array.
    let got = unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) };
    if got == 0 {
        return 0;
    }
    // SAFETY: `params` is a live array.
    unsafe { crate::params::OSSL_PARAM_modified(params.as_ptr()) }
}

/// `int EVP_PKEY_get_size_t_param(const EVP_PKEY *pkey, const char *key_name, size_t *out)`.
///
/// # Safety
/// `pkey` NULL or live; `key_name` NULL or NUL-terminated; `out` NULL or a live `size_t`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_size_t_param(
    pkey: *const EvpPkey,
    key_name: *const c_char,
    out: *mut usize,
) -> c_int {
    let mut params = [crate::params::END; 2];

    if key_name.is_null() {
        return 0;
    }

    // SAFETY: `key_name` is NUL-terminated and `out` is a live `size_t`.
    unsafe {
        params[0] = crate::params::OSSL_PARAM_construct_size_t(key_name, out);
        params[1] = crate::params::OSSL_PARAM_construct_end();
    }
    // SAFETY: `pkey` is NULL or live and `params` is a terminated array.
    let got = unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) };
    if got == 0 {
        return 0;
    }
    // SAFETY: `params` is a live array.
    unsafe { crate::params::OSSL_PARAM_modified(params.as_ptr()) }
}

/// `int EVP_PKEY_set_int_param(EVP_PKEY *pkey, const char *key_name, int in)`.
///
/// The setter shape: **no** modification test, because a setter writes the value itself and there is
/// nothing for the provider to report back. The value's address is a local of this function, which is
/// what makes the descriptor valid only for the duration of the call.
///
/// # Safety
/// `pkey` NULL or live; `key_name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_int_param(
    pkey: *mut EvpPkey,
    key_name: *const c_char,
    value: c_int,
) -> c_int {
    let mut params = [crate::params::END; 2];

    if key_name.is_null() {
        return 0;
    }

    // SAFETY: `key_name` is NUL-terminated and `value` is a live local.
    unsafe {
        params[0] =
            crate::params::OSSL_PARAM_construct_int(key_name, ptr::addr_of!(value).cast_mut());
        params[1] = crate::params::OSSL_PARAM_construct_end();
    }
    // SAFETY: `pkey` is NULL or live and `params` is a terminated array.
    unsafe { EVP_PKEY_set_params(pkey, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_set_size_t_param(EVP_PKEY *pkey, const char *key_name, size_t in)`.
///
/// # Safety
/// `pkey` NULL or live; `key_name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_size_t_param(
    pkey: *mut EvpPkey,
    key_name: *const c_char,
    value: usize,
) -> c_int {
    let mut params = [crate::params::END; 2];

    if key_name.is_null() {
        return 0;
    }

    // SAFETY: `key_name` is NUL-terminated and `value` is a live local.
    unsafe {
        params[0] =
            crate::params::OSSL_PARAM_construct_size_t(key_name, ptr::addr_of!(value).cast_mut());
        params[1] = crate::params::OSSL_PARAM_construct_end();
    }
    // SAFETY: `pkey` is NULL or live and `params` is a terminated array.
    unsafe { EVP_PKEY_set_params(pkey, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_set_bn_param(EVP_PKEY *pkey, const char *key_name, const BIGNUM *bn)`.
///
/// The one setter with a **length** and the one with a **NULL test on the key**: an unassigned key
/// refuses before anything is converted. The conversion is `BN_bn2nativepad` into a 2048-byte stack
/// buffer, which writes the magnitude **little-endian in the host's word order** — the "native" in the
/// name — and it is what a provider's `set_params` expects for a `BN` parameter.
///
/// `ossl_assert(bsize <= sizeof(buffer))` is `(bsize <= sizeof(buffer)) != 0` under `NDEBUG`, so the
/// released authority **refuses** an oversized `BIGNUM` — `xor %eax,%eax; ret` — and never writes
/// past the buffer. The crate refuses for the same reason, by the same test, so the two agree; the
/// measurement is in `docs/DECISIONS.md` D167.
///
/// # Safety
/// `pkey` NULL or live; `key_name` NULL or NUL-terminated; `bn` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_bn_param(
    pkey: *mut EvpPkey,
    key_name: *const c_char,
    bn: *const BigNum,
) -> c_int {
    let mut params = [crate::params::END; 2];
    let mut buffer = [0u8; 2048];

    if key_name.is_null() || bn.is_null() || pkey.is_null() {
        return 0;
    }
    // SAFETY: `pkey` is live and non-NULL.
    if unsafe { (*pkey).keymgmt.is_null() && (*pkey).keydata.is_null() } {
        return 0;
    }

    // SAFETY: `bn` is live per the contract.
    let bsize = (unsafe { crate::bn::bignum::BN_num_bits(bn) } + 7) / 8;
    if bsize <= 0 || bsize as usize > buffer.len() {
        return 0;
    }

    // SAFETY: `bn` is live and `buffer` is `bsize` writable bytes.
    if unsafe { crate::bn::bignum::BN_bn2nativepad(bn, buffer.as_mut_ptr(), bsize) } < 0 {
        return 0;
    }
    // SAFETY: `key_name` is NUL-terminated and `buffer` is live for `bsize` bytes.
    unsafe {
        params[0] =
            crate::params::OSSL_PARAM_construct_BN(key_name, buffer.as_mut_ptr(), bsize as usize);
        params[1] = crate::params::OSSL_PARAM_construct_end();
    }
    // SAFETY: `pkey` is NULL or live and `params` is a terminated array.
    unsafe { EVP_PKEY_set_params(pkey, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_set_utf8_string_param(EVP_PKEY *pkey, const char *key_name, const char *str)`.
///
/// The size is passed as **0**, which for a `UTF8_STRING` parameter means "the string is
/// NUL-terminated, measure it yourself" — the one place in this family where a size of zero is
/// meaningful rather than absent.
///
/// # Safety
/// `pkey` NULL or live; `key_name` NULL or NUL-terminated; `str_` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_utf8_string_param(
    pkey: *mut EvpPkey,
    key_name: *const c_char,
    str_: *const c_char,
) -> c_int {
    let mut params = [crate::params::END; 2];

    if key_name.is_null() {
        return 0;
    }

    // SAFETY: `key_name` is NUL-terminated and `str_` is NUL-terminated.
    unsafe {
        params[0] = crate::params::OSSL_PARAM_construct_utf8_string(key_name, str_.cast_mut(), 0);
        params[1] = crate::params::OSSL_PARAM_construct_end();
    }
    // SAFETY: `pkey` is NULL or live and `params` is a terminated array.
    unsafe { EVP_PKEY_set_params(pkey, params.as_mut_ptr()) }
}

/// `int EVP_PKEY_set_octet_string_param(EVP_PKEY *pkey, const char *key_name,
/// const unsigned char *buf, size_t bsize)`.
///
/// # Safety
/// `pkey` NULL or live; `key_name` NULL or NUL-terminated; `buf` NULL or readable for `bsize`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_octet_string_param(
    pkey: *mut EvpPkey,
    key_name: *const c_char,
    buf: *const u8,
    bsize: usize,
) -> c_int {
    let mut params = [crate::params::END; 2];

    if key_name.is_null() {
        return 0;
    }

    // SAFETY: `key_name` is NUL-terminated and `buf` is readable for `bsize`.
    unsafe {
        params[0] = crate::params::OSSL_PARAM_construct_octet_string(
            key_name,
            buf.cast_mut().cast(),
            bsize,
        );
        params[1] = crate::params::OSSL_PARAM_construct_end();
    }
    // SAFETY: `pkey` is NULL or live and `params` is a terminated array.
    unsafe { EVP_PKEY_set_params(pkey, params.as_mut_ptr()) }
}

/// `const OSSL_PARAM *EVP_PKEY_settable_params(const EVP_PKEY *pkey)`.
///
/// A **provider-only** answer: a legacy key's settable parameters are not modelled, so the test is
/// `is_provided` and a NULL key falls into the same arm as a legacy one.
///
/// # Safety
/// `pkey` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_settable_params(pkey: *const EvpPkey) -> *const OsslParam {
    if pkey.is_null() {
        return ptr::null();
    }
    // SAFETY: `pkey` is live.
    let keymgmt = unsafe { (*pkey).keymgmt };
    if keymgmt.is_null() {
        return ptr::null();
    }
    // SAFETY: `keymgmt` is live.
    unsafe { crate::evp::keymgmt::EVP_KEYMGMT_settable_params(keymgmt) }
}

/// `int EVP_PKEY_set_params(EVP_PKEY *pkey, OSSL_PARAM params[])`.
///
/// The **dirty counter is incremented before the call**, not after and not conditionally: a provider
/// that fails may still have modified the key, and the cache must be invalidated for either outcome.
/// That is the one line in this function that a plausible transcription gets wrong, and it is
/// invisible until an operation hits a stale cache entry.
///
/// A NULL key and a legacy key reach the same `ERR_R_INVALID_KEY`, because the authority's legacy arm
/// is `#if 0` — commented out, with a comment saying it can "safely be removed when #legacy support is
/// removed". So a legacy key is *refused* rather than handled, and there is no arm to omit here.
///
/// # Safety
/// `pkey` NULL or live; `params` a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_params(pkey: *mut EvpPkey, params: *mut OsslParam) -> c_int {
    if !pkey.is_null() {
        // SAFETY: `pkey` is live.
        let (keymgmt, keydata) = unsafe { ((*pkey).keymgmt, (*pkey).keydata) };
        if !keymgmt.is_null() {
            // SAFETY: `pkey` is live.
            unsafe { (*pkey).dirty_cnt += 1 };
            // SAFETY: `keymgmt` is live, `keydata` belongs to it, and `params` is terminated.
            return unsafe {
                crate::evp::keymgmt::evp_keymgmt_set_params(keymgmt, keydata, params)
            };
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::P_LIB_2434) };
    0
}

/// `const OSSL_PARAM *EVP_PKEY_gettable_params(const EVP_PKEY *pkey)`.
///
/// # Safety
/// `pkey` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_gettable_params(pkey: *const EvpPkey) -> *const OsslParam {
    if pkey.is_null() {
        return ptr::null();
    }
    // SAFETY: `pkey` is live.
    let keymgmt = unsafe { (*pkey).keymgmt };
    if keymgmt.is_null() {
        return ptr::null();
    }
    // SAFETY: `keymgmt` is live.
    unsafe { crate::evp::keymgmt::EVP_KEYMGMT_gettable_params(keymgmt) }
}

/// `int EVP_PKEY_get_params(const EVP_PKEY *pkey, OSSL_PARAM params[])`.
///
/// The read half, and it is **`> 0`** rather than `!= 0`: `evp_keymgmt_get_params` answers `1` for a
/// method with no callback and the provider's own value otherwise, and the authority normalises both
/// through a positivity test. The error is raised for a NULL key and for a legacy key alike.
///
/// # Safety
/// `pkey` NULL or live; `params` a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_params(
    pkey: *const EvpPkey,
    params: *mut OsslParam,
) -> c_int {
    if !pkey.is_null() {
        // SAFETY: `pkey` is live.
        let (keymgmt, keydata) = unsafe { ((*pkey).keymgmt, (*pkey).keydata) };
        if !keymgmt.is_null() {
            // SAFETY: `keymgmt` is live, `keydata` belongs to it, and `params` is terminated.
            let answer =
                unsafe { crate::evp::keymgmt::evp_keymgmt_get_params(keymgmt, keydata, params) };
            return c_int::from(answer > 0);
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::P_LIB_2455) };
    0
}

/// `void *evp_pkey_export_to_provider(EVP_PKEY *pk, OSSL_LIB_CTX *libctx, EVP_KEYMGMT **keymgmt,
/// const char *propquery)`.
///
/// The **outer** half of the export/import protocol whose inner half is
/// `evp_keymgmt_util_export_to_provider`. The two differ in what they do about *finding* a destination:
/// the inner one is handed a method and exports into it, and this one can find one when the caller has
/// none, caches what it found nowhere, and has a **legacy-origin arm** that this crate cannot reach.
///
/// The `*keymgmt` argument is an **in/out** parameter and the nulling is the contract: the caller's
/// method is taken and cleared on entry, and written back only if something was exported. The reason is
/// the authority's own comment at the end — "if nothing was exported, `tmp_keymgmt` might point at a
/// freed `EVP_KEYMGMT`, so we clear it to be safe" — and it makes the two failure modes
/// distinguishable to the caller: `*keymgmt == NULL` on return means "this call could not use your
/// method", and a non-NULL `*keymgmt` with a non-NULL return means it did.
///
/// **What is absent: the default-method lookup and the legacy-origin arm, and they are different
/// kinds of absence.** The legacy arm — `pk->pkey.ptr != NULL`, `pk->ameth->dirty_cnt`, and the
/// `ameth->export_to` call with its own cache dance — needs a legacy origin key, which this crate
/// cannot construct. The default-method lookup is reachable in principle and is **7.4c's**: it is
/// `EVP_PKEY_CTX_new_from_pkey`, which `pmeth_lib.c` owns, and the authority uses it to let the
/// construction path find a method, steal it from the context, and let the context be freed. Until
/// 7.4c a caller must supply one, which every caller in the crate does.
///
/// # Safety
/// `pk` NULL or live; `keymgmt` NULL or a live `EVP_KEYMGMT **`; `propquery` NULL or NUL-terminated.
#[allow(dead_code)] // first live caller is 7.4b's method classes and `EVP_PKEY_dup`'s cross-method arm
pub(crate) unsafe fn evp_pkey_export_to_provider(
    pk: *mut EvpPkey,
    libctx: *mut c_void,
    keymgmt: *mut *mut EvpKeyMgmt,
    propquery: *const c_char,
) -> *mut c_void {
    let selection = OSSL_KEYMGMT_SELECT_ALL;
    let mut tmp_keymgmt: *mut EvpKeyMgmt = ptr::null_mut();

    if pk.is_null() {
        return ptr::null_mut();
    }

    /* No key data => nothing to export. The authority's `check` is two clauses with the legacy one
     * compiled in and always true here; with no legacy origin it reduces to this. */
    // SAFETY: `pk` is live.
    if unsafe { (*pk).keydata.is_null() } {
        return ptr::null_mut();
    }

    if !keymgmt.is_null() {
        // SAFETY: `keymgmt` is a live out-parameter per the contract.
        tmp_keymgmt = unsafe { *keymgmt };
        // SAFETY: as above.
        unsafe { *keymgmt = ptr::null_mut() };
    }

    /* Phase 7.4c: when no method was given, the authority calls `EVP_PKEY_CTX_new_from_pkey(libctx,
     * pk, propquery)` -- which `pmeth_lib.c` owns -- takes `ctx->keymgmt`, clears the context's copy
     * and frees the context. `libctx` and `propquery` are read only by that call, which is why they
     * are named here and unused: the parameters are part of the contract even where the call is not
     * yet written. */
    let _ = (libctx, propquery);
    if tmp_keymgmt.is_null() {
        return ptr::null_mut();
    }

    /* The legacy-origin arm -- `pk->pkey.ptr != NULL` and the whole `ameth->export_to` cache dance --
     * is absent for the reason `evp_pkey_cmp_any`'s is: a legacy origin cannot be constructed here. */

    // SAFETY: `pk` is live and `tmp_keymgmt` is live.
    let keydata = unsafe {
        crate::evp::keymgmt_lib::evp_keymgmt_util_export_to_provider(pk, tmp_keymgmt, selection)
    };

    /* `end:` -- the temporary is cleared when nothing was exported, because the caller must not be
     * handed a method this call could not use. `allocated_keymgmt` is always NULL here: it is set
     * only by the 7.4c lookup above. */
    if keydata.is_null() {
        tmp_keymgmt = ptr::null_mut();
    }

    if !keymgmt.is_null() && !tmp_keymgmt.is_null() {
        // SAFETY: `keymgmt` is a live out-parameter per the contract.
        unsafe { *keymgmt = tmp_keymgmt };
    }

    keydata
}

// ---------------------------------------------------------------------------------------------
// Equality, and the four answers it can give
// ---------------------------------------------------------------------------------------------
//
// `EVP_PKEY_eq` returns **1** same key, **0** different key, **-1** different key *type* and **-2**
// unsupported operation. The four are the contract that `evp_keymgmt_util_match` documents from the
// other side, and the two functions divide the work: this one decides *which selection* to compare
// over, and the util decides how.
//
// The selection is not a constant, and that is the part a plausible transcription gets wrong.
// `EVP_PKEY_eq` asks each key whether it **has** a public key and compares over
// `SELECT_DOMAIN_PARAMETERS | PUBLIC_KEY` when both do, over `SELECT_DOMAIN_PARAMETERS | KEYPAIR`
// otherwise. So a pair of keys that both lack a public key is compared over *more* than a pair that
// has them -- because a key with no public key must be compared with its private half included, or
// two private keys with the same parameters would compare equal.

/// `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS` — the authority's `SELECT_PARAMETERS`.
///
/// The name is the authority's and it is narrower than it reads: the macro is **one** bit, and
/// `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS` is deliberately not in it. The four `*_ameth.c` units'
/// `export_to` callbacks spell all four bits out, so the four are `pub(crate)` here.
pub(crate) const OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS: c_int = 0x04;
/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY`.
pub(crate) const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `OSSL_KEYMGMT_SELECT_PUBLIC_KEY`.
pub(crate) const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
/// `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS`.
pub(crate) const OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS: c_int = 0x80;
/// `OSSL_PKEY_PARAM_PRIV_KEY` — `include/openssl/core_names.h`, the generated one.
pub(crate) const OSSL_PKEY_PARAM_PRIV_KEY: *const c_char = c"priv".as_ptr();
/// `OSSL_PKEY_PARAM_PUB_KEY` — the same header and the same note.
pub(crate) const OSSL_PKEY_PARAM_PUB_KEY: *const c_char = c"pub".as_ptr();
/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `PRIVATE_KEY | PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int = 0x01 | 0x02;
/// `EVP_PKEY_KEYPAIR` — `include/openssl/evp.h:112`, `PUBLIC_KEY | PRIVATE_KEY`, which expands to
/// `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS | 0x02 | 0x01`. The `EVP_PKEY_KEY_PARAMETERS` the macro
/// names is `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` — `DOMAIN_PARAMETERS | OTHER_PARAMETERS` — not the
/// narrower `SELECT_PARAMETERS` above.
const EVP_PKEY_KEYPAIR: c_int = 0x04 | 0x80 | 0x01 | 0x02;

/// `static int evp_pkey_cmp_any(const EVP_PKEY *a, const EVP_PKEY *b, int selection)`.
///
/// The mixed-legacy-path function, and in this crate it has exactly two arms: the assertion that at
/// least one key is provider-side, and the case where both are. Everything past that — comparing a
/// legacy NID against a provider method's names, then cross-exporting with
/// `evp_pkey_export_to_provider` — needs a legacy origin key, which is a state this crate cannot
/// build, and `evp_pkey_export_to_provider` besides, which is 7.4c's. The authority's own comment on
/// the `#ifdef FIPS_MODULE` arm says the whole function "will just call
/// `evp_keymgmt_util_match` when legacy support is gone", which is precisely the crate's situation.
///
/// # Safety
/// `a` and `b` must be live.
unsafe fn evp_pkey_cmp_any(a: *const EvpPkey, b: *const EvpPkey, selection: c_int) -> c_int {
    // SAFETY: both keys are live per the contract.
    let (a_provided, b_provided) = unsafe { (!(*a).keymgmt.is_null(), !(*b).keymgmt.is_null()) };

    /* `ossl_assert(C)` under `NDEBUG` is `C`, so `!ossl_assert(C)` is `!C` and the released build
     * *does* take the -2 here. The crate's test is that same negation, so the two agree
     * (`docs/DECISIONS.md` D167). */
    if !a_provided && !b_provided {
        return -2;
    }

    if a_provided && b_provided {
        // SAFETY: both keys are live and provider-side.
        return unsafe {
            crate::evp::keymgmt_lib::evp_keymgmt_util_match(a.cast_mut(), b.cast_mut(), selection)
        };
    }

    /* Phase 8: one key is provider-side and the other is a legacy origin, which this crate cannot
     * construct. See this function's doc comment. */
    -2
}

/// `int EVP_PKEY_parameters_eq(const EVP_PKEY *a, const EVP_PKEY *b)`.
///
/// Parameters only. If **either** key is provider-side it defers to `evp_pkey_cmp_any`; otherwise
/// both are legacy, and the answer is the legacy NID comparison followed by the method's own
/// `param_cmp` -- **-1** when the two NIDs differ, the callback's answer when it exists, and **-2**
/// when a legacy key has no `param_cmp` at all. D353 made the ameth arm reachable by publishing the
/// `standard_methods[]` rows.
///
/// # Safety
/// `a` and `b` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_parameters_eq(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    // SAFETY: both keys are live per the contract.
    if unsafe { !(*a).keymgmt.is_null() || !(*b).keymgmt.is_null() } {
        // SAFETY: both keys are live.
        return unsafe { evp_pkey_cmp_any(a, b, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) };
    }
    /* All legacy keys. */
    // SAFETY: both keys are live.
    if unsafe { (*a).type_ != (*b).type_ } {
        return -1;
    }
    // SAFETY: `a` is live.
    let f = unsafe { (*a).ameth.as_ref() }.and_then(|m| m.param_cmp);
    if let Some(param_cmp) = f {
        // SAFETY: `param_cmp` is the method's own callback and both keys are live.
        return unsafe { param_cmp(a, b) };
    }
    -2
}

/// `int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)` — the deprecated spelling.
///
/// Literally `EVP_PKEY_parameters_eq`, behind `#ifndef OPENSSL_NO_DEPRECATED_3_0`. The wrapper exists
/// so that a program built against the older header links, and it is **not** a second implementation:
/// a difference between the two would be a defect, so there is nothing here to transcribe.
///
/// # Safety
/// `a` and `b` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_cmp_parameters(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    // SAFETY: both keys are live per the contract.
    unsafe { EVP_PKEY_parameters_eq(a, b) }
}

/// `int EVP_PKEY_eq(const EVP_PKEY *a, const EVP_PKEY *b)`.
///
/// Two **trivial shortcuts** first, and both are contract rather than optimisation: a key is equal to
/// itself even if it is blank or has no key data (`a == b` → **1**), and a NULL against anything else
/// is a difference rather than an error (`a == NULL || b == NULL` → **0**). So `EVP_PKEY_eq(NULL,
/// NULL)` is **1** through the first test and `EVP_PKEY_eq(NULL, key)` is **0** through the second.
///
/// Then the selection, and then `evp_pkey_cmp_any`. The `has` questions are asked **both ways**: a
/// pair where only one key reports a public key takes the `KEYPAIR` arm, not a one-sided comparison.
///
/// # Safety
/// `a` and `b` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_eq(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    if a == b {
        return 1;
    }
    if a.is_null() || b.is_null() {
        return 0;
    }

    // SAFETY: both keys are live per the contract.
    if unsafe { !(*a).keymgmt.is_null() || !(*b).keymgmt.is_null() } {
        let mut selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;

        /* SAFETY: both keys are live and the selection is a plain bit set. */
        let both_have_public = unsafe {
            crate::evp::keymgmt_lib::evp_keymgmt_util_has(
                a.cast_mut(),
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            ) != 0
                && crate::evp::keymgmt_lib::evp_keymgmt_util_has(
                    b.cast_mut(),
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                ) != 0
        };
        if both_have_public {
            selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        } else {
            selection |= OSSL_KEYMGMT_SELECT_KEYPAIR;
        }
        // SAFETY: both keys are live.
        return unsafe { evp_pkey_cmp_any(a, b, selection) };
    }

    /* All legacy keys: Phase 8's `a->ameth->param_cmp` then `pub_cmp`, unreachable here. */
    // SAFETY: both keys are live.
    if unsafe { (*a).type_ != (*b).type_ } {
        return -1;
    }
    -2
}

/// `int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b)` — the deprecated spelling.
///
/// Literally `EVP_PKEY_eq`, behind the same `#ifndef OPENSSL_NO_DEPRECATED_3_0`, and the two are
/// separate exported symbols on purpose: a program linked against either name must reach the same
/// answer, and the only way to guarantee that is for one of them to be the other.
///
/// # Safety
/// `a` and `b` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_cmp(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    // SAFETY: both keys are NULL or live per the contract.
    unsafe { EVP_PKEY_eq(a, b) }
}

//`struct raw_key_details_st` — `crypto/evp/p_lib.c:562`.
#[repr(C)]
struct RawKeyDetails {
    /// `unsigned char **key` — the caller's pointer-to-buffer, or NULL for a length query.
    key: *mut *mut u8,
    /// `size_t *len` — the caller's length, in and out.
    len: *mut usize,
    /// `int selection` — which of the two keys this call is asking for.
    selection: c_int,
}

/// `static int get_raw_key_details(const OSSL_PARAM params[], void *arg)` —
/// `crypto/evp/p_lib.c:569`.
///
/// The callback the two `EVP_PKEY_get_raw_*` entry points hand [`evp_keymgmt_util_export`], and the
/// whole of its shape is one `OSSL_PARAM_get_octet_string` call whose `max_len` is
/// **`raw_key->key == NULL ? 0 : *raw_key->len`**. That ternary is what makes a NULL buffer a
/// *length query*: the caller gets the length back through the same pointer and is not asked to
/// allocate twice.
///
/// The outer `if` is a selection test and **not** a NULL test on the located parameter: a params
/// array with no `priv` in it answers 0 (the export failed) rather than being skipped.
///
/// # Safety
/// `arg` must be a live `RawKeyDetails` whose `len` is the caller's pointer.
unsafe extern "C" fn get_raw_key_details(params: *const OsslParam, arg: *mut c_void) -> c_int {
    let raw_key = arg.cast::<RawKeyDetails>();

    // SAFETY: `raw_key` is live per the contract.
    let selection = unsafe { (*raw_key).selection };
    let name = if selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY {
        OSSL_PKEY_PARAM_PRIV_KEY
    } else if selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY {
        OSSL_PKEY_PARAM_PUB_KEY
    } else {
        return 0;
    };

    // SAFETY: `params` is NULL or a terminated array and `name` is NUL-terminated.
    let p = unsafe { OSSL_PARAM_locate_const(params, name) };
    if p.is_null() {
        return 0;
    }
    // SAFETY: `raw_key` is live.
    let (key, len) = unsafe { ((*raw_key).key, (*raw_key).len) };
    let max_len = if key.is_null() {
        0
    } else {
        // SAFETY: `key` is non-NULL, so `len` is the caller's valid length per the contract.
        unsafe { *len }
    };
    // SAFETY: `p` is a live entry of the array; `key` is NULL or writable; `len` is the caller's.
    unsafe { OSSL_PARAM_get_octet_string(p, key.cast::<*mut c_void>(), max_len, len) }
}

/// `int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv, size_t *len)` —
/// `crypto/evp/p_lib.c:591`.
///
/// Two paths and the first is the whole of this crate's: a key with a `keymgmt` (every key it can
/// build) exports through `evp_keymgmt_util_export`, and a key without one needs `pkey->ameth` —
/// `EVP_PKEY_ASN1_METHOD`, Phase 8's, whose `get_priv_key` the authority falls back to. With
/// `ameth` always NULL here the second path is unreachable, and it answers exactly what the
/// authority answers for a key with no method: `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`.
///
/// # Safety
/// `pkey` must be live; `priv` NULL or `*len` writable bytes; `len` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_raw_private_key(
    pkey: *const EvpPkey,
    mut priv_: *mut u8,
    len: *mut usize,
) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let keymgmt = unsafe { (*pkey).keymgmt };
    if !keymgmt.is_null() {
        let mut raw_key = RawKeyDetails {
            key: if priv_.is_null() {
                ptr::null_mut()
            } else {
                ptr::addr_of_mut!(priv_)
            },
            len,
            selection: OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        };
        /* SAFETY: `pkey` is live, the callback is this file's own, and `raw_key` is a live local
         * whose address the callback writes through. */
        return unsafe {
            evp_keymgmt_util_export(
                pkey,
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                Some(get_raw_key_details),
                ptr::addr_of_mut!(raw_key).cast::<c_void>(),
            )
        };
    }

    /* The legacy path: `pkey->ameth == NULL` or `ameth->get_priv_key == NULL` — one reason code,
     * `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`, raised at two sites. `ameth` is Phase 8's
     * and is always NULL here, so the second site is unreachable and the first is the answer. */
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::P_LIB_606) };
    0
}

/// `int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len)` —
/// `crypto/evp/p_lib.c:623`.
///
/// The sibling of the getter above, differing in one selection and one parameter name. Written out
/// rather than folded into it for the same reason the authority writes it out: the two are separate
/// exports whose error *sites* are separate, and a shared body would have to be told which site to
/// raise.
///
/// # Safety
/// `pkey` must be live; `pub_` NULL or `*len` writable bytes; `len` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_raw_public_key(
    pkey: *const EvpPkey,
    mut pub_: *mut u8,
    len: *mut usize,
) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let keymgmt = unsafe { (*pkey).keymgmt };
    if !keymgmt.is_null() {
        let mut raw_key = RawKeyDetails {
            key: if pub_.is_null() {
                ptr::null_mut()
            } else {
                ptr::addr_of_mut!(pub_)
            },
            len,
            selection: OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        };
        // SAFETY: as the private getter above.
        return unsafe {
            evp_keymgmt_util_export(
                pkey,
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                Some(get_raw_key_details),
                ptr::addr_of_mut!(raw_key).cast::<c_void>(),
            )
        };
    }

    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::P_LIB_638) };
    0
}
/// `static EVP_PKEY *new_raw_key_int(OSSL_LIB_CTX *libctx, const char *strtype, const char *propq,
/// int nidtype, ENGINE *e, const unsigned char *key, size_t len, int key_is_priv)` —
/// `crypto/evp/p_lib.c:416`.
///
/// The four `EVP_PKEY_new_raw_*` constructors' shared body. What it produces is decided by two
/// things, and the first is the one a reader has to be told rather than left to infer.
///
/// **The engine block (`p_lib.c:432-445`) answers `ameth = NULL` for every input in this build.**
/// The authority writes
///
/// ```text
/// if (e == NULL) {
///     ENGINE *tmpe = NULL;
///     if (strtype != NULL)       ameth = EVP_PKEY_asn1_find_str(&tmpe, strtype, -1);
///     else if (nidtype != EVP_PKEY_NONE) ameth = EVP_PKEY_asn1_find(&tmpe, nidtype);
///     if (tmpe == NULL) ameth = NULL;
///     ENGINE_finish(tmpe);
/// }
/// ```
///
/// and `tmpe` is NULL on every path: `EVP_PKEY_asn1_find_str` and `EVP_PKEY_asn1_find` set `*pe` from
/// the **engine registry** — which is empty, because no ENGINE can be obtained in this crate
/// (`ENGINE` is Phase 13) — so the method one of them may return is **discarded** by the next line.
/// That is the same shape `docs/DECISIONS.md` D181 sanctions for `EVP_PKEY_get0_asn1` ("the crate
/// writes the same `*pe = NULL` and the answers are identical"), and the same rule D167 records for
/// a macro read as code: transcribe the *answer*, name the mechanism at the site. So the block is
/// written as the single `let ameth = null` below, and `e == NULL && ameth == NULL` — the condition
/// of the provider branch — is true for every call this crate can make. `ENGINE_finish(NULL)` is
/// the no-op the authority's own line is handed.
///
/// The second is the **name**: `strtype` for the two `_ex` spellings, and `OBJ_nid2sn(nidtype)` for
/// the two that take a legacy type. The two are different strings for the same key type and must
/// not be conflated, which is why the arms of `RT-EVP-PKEY` drive both.
///
/// The legacy half below — `EVP_PKEY_new`, `pkey_set_type`, the `ossl_assert(ameth != NULL)` gate
/// and the two `set_priv_key`/`set_pub_key` arms — is transcribed in full and is **unreachable**:
/// it is entered only when the context exists and `EVP_PKEY_fromdata_init` refuses, and
/// `int_ctx_new` always sets both `keytype` and `keymgmt` on a context it returns, so the init
/// cannot refuse. Each site names that, and each callback arm names the stratum that would fill it
/// (`EVP_PKEY_ASN1_METHOD`'s two setters are Phase 8's objects).
///
/// # Safety
/// `libctx` NULL or live; `strtype` NULL or NUL-terminated; `propq` NULL or NUL-terminated;
/// `key` NULL or readable for `len` bytes; `e` must be NULL.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn new_raw_key_int(
    libctx: *mut c_void,
    strtype: *const c_char,
    propq: *const c_char,
    nidtype: c_int,
    e: *mut Engine,
    key: *const u8,
    len: usize,
    key_is_priv: c_int,
) -> *mut EvpPkey {
    let mut pkey: *mut EvpPkey = ptr::null_mut();
    let mut ctx: *mut EvpPkeyCtx = ptr::null_mut();
    let mut result = 0;

    /* The engine block, as the answer it produces; see this function's doc comment. The condition
     * below is the authority's own `e == NULL && ameth == NULL`, written with both operands so that
     * the reader can see which one the engine block refuses to make true; `e == NULL` is the only
     * value this crate can pass. */
    let ameth: *const EvpPkeyAsn1Method = ptr::null();

    if e.is_null() && ameth.is_null() {
        /*
         * "No engine is claiming to support this type, so lets see if we have a provider."
         */
        let name = if !strtype.is_null() {
            strtype
        } else {
            OBJ_nid2sn(nidtype)
        };
        // SAFETY: `name` is NUL-terminated -- either the caller's, under this function's contract,
        // or the object table's -- and `propq` is NULL or NUL-terminated.
        ctx = unsafe { EVP_PKEY_CTX_new_from_name(libctx, name, propq) };
        if ctx.is_null() {
            /* `goto err` with `pkey` NULL and `result` 0: nothing to free but the NULL context. */
            return ptr::null_mut();
        }

        // The authority's own comment: "May fail if no provider available".
        ERR_set_mark();
        // SAFETY: `ctx` is live.
        if unsafe { EVP_PKEY_fromdata_init(ctx) } == 1 {
            ERR_clear_last_mark();
            let mut params: [OsslParam; 2] = [crate::params::END; 2];
            // SAFETY: each constructor writes one entry of this frame's two-slot array; `key` is
            // readable for `len` bytes and outlives the call into the provider.
            unsafe {
                params[0] = OSSL_PARAM_construct_octet_string(
                    if key_is_priv != 0 {
                        OSSL_PKEY_PARAM_PRIV_KEY
                    } else {
                        OSSL_PKEY_PARAM_PUB_KEY
                    },
                    key.cast_mut().cast::<c_void>(),
                    len,
                );
                params[1] = OSSL_PARAM_construct_end();
            }

            // SAFETY: `ctx` is live, `pkey` is this frame's writable local, and `params` is this
            // frame's terminated array.
            if unsafe {
                EVP_PKEY_fromdata(
                    ctx,
                    ptr::addr_of_mut!(pkey),
                    EVP_PKEY_KEYPAIR,
                    params.as_mut_ptr(),
                )
            } != 1
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::P_LIB_471) };
                /* `goto err`: `EVP_PKEY_fromdata` assigns `*ppkey` only on success, so `pkey` is
                 * still NULL and the `!result` free has nothing to release. */
                // SAFETY: `ctx` is live and this is the one release.
                unsafe { EVP_PKEY_CTX_free(ctx) };
                return ptr::null_mut();
            }

            // SAFETY: `ctx` is live and this is the one release.
            unsafe { EVP_PKEY_CTX_free(ctx) };
            return pkey;
        }
        ERR_pop_to_mark();
        /* "else not supported so fallback to legacy" -- and `ctx` stays live for the `err:` tail,
         * exactly as the authority's does. */
    }

    /*
     * Legacy code path. Unreachable: see this function's doc comment. The `err:` bookkeeping is the
     * `if result == 0` block at the end, so every failure below simply leaves `result` at 0.
     */
    // SAFETY: the constructor takes no arguments.
    pkey = unsafe { EVP_PKEY_new() };
    if !pkey.is_null() {
        /* `pkey_set_type(pkey, e, nidtype, strtype, -1, NULL)`: the ameth lookup it performs now
         * finds the method the name or type names, and raises `EVP_R_UNSUPPORTED_ALGORITHM` for a
         * name no method carries. */
        // SAFETY: `pkey` is live; `strtype` is NULL or NUL-terminated.
        if unsafe { pkey_set_type(pkey, nidtype, strtype, -1, ptr::null_mut()) } != 0 {
            // SAFETY: `pkey` is live.
            let ameth = unsafe { (*pkey).ameth };
            /* `if (!ossl_assert(pkey->ameth != NULL)) goto err;` -- under `NDEBUG` that is
             * `ameth == NULL`, a released-build *refusal* rather than a no-op (`docs/DECISIONS.md`
             * D167). `ameth` is always NULL here, so this is the legacy half's real end. */
            if !ameth.is_null() {
                /* Phase 8: the two `EVP_PKEY_ASN1_METHOD` setters, transcribed so that the fill
                 * inherits them. Reaching here needs a non-NULL `ameth`, which needs a
                 * `standard_methods[]` entry. */
                // SAFETY: `ameth` is non-NULL on this path.
                let ameth_ref = unsafe { &*ameth };
                let ok = if key_is_priv != 0 {
                    match ameth_ref.set_priv_key {
                        None => {
                            // SAFETY: a compile-time-constant site.
                            unsafe { raise_site(&err_sites::P_LIB_501) };
                            false
                        }
                        Some(set) => {
                            // SAFETY: `set` is the method's own callback, `pkey` is live, and `key`
                            // is readable for `len` bytes.
                            let ok = unsafe { set(pkey, key, len) } != 0;
                            if !ok {
                                // SAFETY: a compile-time-constant site.
                                unsafe { raise_site(&err_sites::P_LIB_506) };
                            }
                            ok
                        }
                    }
                } else {
                    match ameth_ref.set_pub_key {
                        None => {
                            // SAFETY: a compile-time-constant site.
                            unsafe { raise_site(&err_sites::P_LIB_511) };
                            false
                        }
                        Some(set) => {
                            // SAFETY: as the private arm above.
                            let ok = unsafe { set(pkey, key, len) } != 0;
                            if !ok {
                                // SAFETY: a compile-time-constant site.
                                unsafe { raise_site(&err_sites::P_LIB_516) };
                            }
                            ok
                        }
                    }
                };
                if ok {
                    result = 1;
                }
            }
        }
    } else {
        /* SAFETY: a compile-time-constant site. */
        unsafe { raise_site(&err_sites::P_LIB_487) };
    }

    /* `err:` */
    if result == 0 {
        // SAFETY: `pkey` is NULL or this call's own object.
        unsafe { EVP_PKEY_free(pkey) };
        pkey = ptr::null_mut();
    }
    // SAFETY: `ctx` is NULL or live and this is the one release on this path.
    unsafe { EVP_PKEY_CTX_free(ctx) };
    pkey
}

/// `EVP_PKEY *EVP_PKEY_new_raw_private_key_ex(OSSL_LIB_CTX *libctx, const char *keytype,
/// const char *propq, const unsigned char *priv, size_t len)` — `crypto/evp/p_lib.c:522`.
///
/// The **name-taking** spelling: `strtype` is the caller's `keytype` and `nidtype` is
/// `EVP_PKEY_NONE`, so the context is fetched by the name the caller wrote. That is a different
/// string from the legacy-type spellings' `OBJ_nid2sn(nidtype)`, and the two reach the same
/// provider by different roads.
///
/// # Safety
/// `libctx` NULL or live; `keytype` NUL-terminated; `propq` NULL or NUL-terminated; `priv` NULL or
/// readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new_raw_private_key_ex(
    libctx: *mut c_void,
    keytype: *const c_char,
    propq: *const c_char,
    priv_: *const u8,
    len: usize,
) -> *mut EvpPkey {
    // SAFETY: the arguments are forwarded under this function's contract; the NULL engine and the
    // `EVP_PKEY_NONE` type are this spelling's own.
    unsafe {
        new_raw_key_int(
            libctx,
            keytype,
            propq,
            EVP_PKEY_NONE,
            ptr::null_mut(),
            priv_,
            len,
            1,
        )
    }
}

/// `EVP_PKEY *EVP_PKEY_new_raw_public_key_ex(OSSL_LIB_CTX *libctx, const char *keytype,
/// const char *propq, const unsigned char *pub, size_t len)` — `crypto/evp/p_lib.c:534`.
///
/// # Safety
/// As its private sibling, with a public key.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new_raw_public_key_ex(
    libctx: *mut c_void,
    keytype: *const c_char,
    propq: *const c_char,
    pub_: *const u8,
    len: usize,
) -> *mut EvpPkey {
    // SAFETY: as above, with `key_is_priv` 0.
    unsafe {
        new_raw_key_int(
            libctx,
            keytype,
            propq,
            EVP_PKEY_NONE,
            ptr::null_mut(),
            pub_,
            len,
            0,
        )
    }
}

/// `EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e, const unsigned char *priv,
/// size_t len)` — `crypto/evp/p_lib.c:531`.
///
/// The **legacy-type** spelling: no name and no library context, so the key type is `type` and both
/// `strtype` and `libctx` are NULL. The context is therefore fetched by `OBJ_nid2sn(type)` from the
/// **default** library context, which is a property of the call and not of the caller.
///
/// # Safety
/// `e` must be NULL (`ENGINE` is Phase 13); `priv` NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new_raw_private_key(
    type_: c_int,
    e: *mut Engine,
    priv_: *const u8,
    len: usize,
) -> *mut EvpPkey {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        new_raw_key_int(
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            type_,
            e,
            priv_,
            len,
            1,
        )
    }
}

/// `EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e, const unsigned char *pub,
/// size_t len)` — `crypto/evp/p_lib.c:543`.
///
/// # Safety
/// As its private sibling.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new_raw_public_key(
    type_: c_int,
    e: *mut Engine,
    pub_: *const u8,
    len: usize,
) -> *mut EvpPkey {
    // SAFETY: as above, with `key_is_priv` 0.
    unsafe {
        new_raw_key_int(
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            type_,
            e,
            pub_,
            len,
            0,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// 7.4e — `p_lib.c`'s provider half continued.
//
// Eighteen exports: the four cache-backed accessors, the parameter-presence and parameter-copy
// pair, the two type setters, the two encoded-public-key codecs, the CMAC constructor, the two
// default-digest accessors and the `EVP_PKEY_CTX`-free key generator. Everything below is the
// provider path; each legacy arm is named at its site with the stratum that fills it, because a
// reader of one function should not have to find `docs/DECISIONS.md` first.
// ---------------------------------------------------------------------------------------------

/// `ASN1_PKEY_CTRL_DEFAULT_MD_NID` — `include/openssl/evp.h:1609`. `pub(crate)` because the
/// `rsa_ameth.c`, `dsa_ameth.c` and `ec_ameth.c` `pkey_ctrl` callbacks read it.
pub(crate) const ASN1_PKEY_CTRL_DEFAULT_MD_NID: c_int = 0x3;
/// `ASN1_PKEY_CTRL_SET1_TLS_ENCPT` — `include/openssl/evp.h:1614`.
pub(crate) const ASN1_PKEY_CTRL_SET1_TLS_ENCPT: c_int = 0x9;
/// `ASN1_PKEY_CTRL_GET1_TLS_ENCPT` — `include/openssl/evp.h:1615`.
pub(crate) const ASN1_PKEY_CTRL_GET1_TLS_ENCPT: c_int = 0xa;
/// `ASN1_PKEY_SIGPARAM_NULL` — `include/openssl/evp.h:1605`, the `pkey_flags` bit the RSA
/// methods set so `ASN1_item_sign` writes an explicit `NULL` parameter.
pub(crate) const ASN1_PKEY_SIGPARAM_NULL: c_long = 0x4;

/// `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` — `include/openssl/core_names.h:398`.
const OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY: *const c_char = c"encoded-pub-key".as_ptr();
/// `OSSL_PKEY_PARAM_PROPERTIES` = `OSSL_ALG_PARAM_PROPERTIES` — `include/openssl/core_names.h:440`.
const OSSL_PKEY_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_PKEY_PARAM_CIPHER` = `OSSL_ALG_PARAM_CIPHER` — `include/openssl/core_names.h:367`.
const OSSL_PKEY_PARAM_CIPHER: *const c_char = c"cipher".as_ptr();

/// `EVP_PKEY_get1_encoded_public_key`'s `OPENSSL_malloc(return_size)` (line 1463).
const LINE_MALLOC_ENCODED_PUBKEY: c_int = 1463;
/// Its `OPENSSL_free(buf)` (line 1470).
const LINE_FREE_ENCODED_PUBKEY: c_int = 1470;

/// `int EVP_PKEY_get_bits(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:61`.
///
/// A field read and a positivity test. The `ameth` override the authority writes between them is
/// Phase 8's and **cannot fire here**: `pkey->ameth` is always NULL in this crate
/// (`docs/SECURITY_DIVERGENCE_POLICY.md` D-PKEY-AMETH-1), so the cache is the whole of the answer.
/// A non-positive cache is a *reported* refusal rather than a zero — `EVP_R_UNKNOWN_BITS` and `0` —
/// which is what a provider that does not publish `bits` gets.
///
/// # Safety
/// `pkey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_bits(pkey: *const EvpPkey) -> c_int {
    let mut size = 0;

    if !pkey.is_null() {
        // SAFETY: `pkey` is live per the contract.
        size = unsafe { (*pkey).cache.bits };
        /* D369: the `ameth` override, as in `EVP_PKEY_get_size`. */
        // SAFETY: `pkey` is live.
        let ameth = unsafe { (*pkey).ameth };
        if !ameth.is_null() {
            // SAFETY: `ameth` is the key's own method table.
            if let Some(f) = unsafe { (*ameth).pkey_bits } {
                // SAFETY: the callback is the key's own, with the authority's signature.
                size = unsafe { f(pkey) };
            }
        }
    }
    if size <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_71) };
        return 0;
    }
    size
}

/// `int EVP_PKEY_get_security_bits(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:77`.
///
/// The same shape as its sibling, over the second cache field, with its own reason string. The
/// `ameth` override is Phase 8's for the same reason.
///
/// # Safety
/// `pkey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_security_bits(pkey: *const EvpPkey) -> c_int {
    let mut size = 0;

    if !pkey.is_null() {
        // SAFETY: `pkey` is live per the contract.
        size = unsafe { (*pkey).cache.security_bits };
        /* D369: the `ameth->pkey_security_bits` override, as above. */
        // SAFETY: `pkey` is live.
        let ameth = unsafe { (*pkey).ameth };
        if !ameth.is_null() {
            // SAFETY: `ameth` is the key's own method table.
            if let Some(f) = unsafe { (*ameth).pkey_security_bits } {
                // SAFETY: the callback is the key's own, with the authority's signature.
                size = unsafe { f(pkey) };
            }
        }
    }
    if size <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_87) };
        return 0;
    }
    size
}

/// `int EVP_PKEY_get_security_category(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:93`.
///
/// The one accessor in the family with **no refinement and no raise**: a NULL key answers `-1` and a
/// key answers its cache field verbatim. That `-1` is also the cache's own initial value
/// (`evp_keymgmt_util_cache_keyinfo`), so a caller cannot tell "not filled" from "the provider said
/// -1" — which is why the field exists and `bits` does not have it.
///
/// # Safety
/// `pkey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_security_category(pkey: *const EvpPkey) -> c_int {
    if pkey.is_null() {
        return -1;
    }
    // SAFETY: `pkey` is live per the contract.
    unsafe { (*pkey).cache.security_category }
}

/// `int EVP_PKEY_save_parameters(EVP_PKEY *pkey, int mode)` — `crypto/evp/p_lib.c:98`.
///
/// Two arms, one per legacy type, and **both are unreachable in this crate**: they test
/// `pkey->type == EVP_PKEY_DSA` and `== EVP_PKEY_EC`, and `pkey_set_type` writes
/// `EVP_PKEY_KEYMGMT` into `type` for every key that has a method (D-PKEY-AMETH-1), so no key here
/// carries a legacy NID. The two arms are written rather than collapsed to `return 0` because the
/// field they read and write is the authority's and because that is the shape Phase 8 fills.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_save_parameters(pkey: *mut EvpPkey, mode: c_int) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let type_ = unsafe { (*pkey).type_ };

    if type_ == NID_dsa {
        // SAFETY: `pkey` is live.
        let ret = unsafe { (*pkey).save_parameters };
        if mode >= 0 {
            // SAFETY: `pkey` is live.
            unsafe { (*pkey).save_parameters = mode };
        }
        return ret;
    }
    if type_ == NID_X9_62_id_ecPublicKey {
        // SAFETY: `pkey` is live.
        let ret = unsafe { (*pkey).save_parameters };
        if mode >= 0 {
            // SAFETY: `pkey` is live.
            unsafe { (*pkey).save_parameters = mode };
        }
        return ret;
    }
    0
}

/// `int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)` — `crypto/evp/p_lib.c:132`.
///
/// Transcribed whole, legacy arms included, because D353 made them reachable: the crate can build a
/// legacy key now, so `evp_pkey_is_legacy(to)`, `evp_pkey_is_blank(to)` and the two-legacy
/// `from->ameth->param_copy` arm are all live code paths rather than the Phase-7 reductions they
/// were written as.
///
/// The order is the authority's and each step is a different refusal: a legacy `to` with a provider
/// `from` is first downgraded; an untyped `to` takes `from`'s type (by legacy NID or by method); a
/// legacy `to` whose NID differs from `from`'s is `EVP_R_DIFFERENT_KEY_TYPES`; **`from`'s** missing
/// parameters are asked for **before** `to`'s, so an empty `from` refuses even when `to` is empty
/// too; a `to` that already has parameters is *compared* rather than overwritten; and only then does
/// the copy happen — through the keymgmt utility for two provider keys, through an export/dup for a
/// provider `to` and a legacy `from`, or through the legacy method's own `param_copy` for two legacy
/// keys.
///
/// **One reduction remains**, and it is `evp_pkey_export_to_provider`'s, not this function's: that
/// helper's legacy-origin arm (the `ameth->export_to` call) is absent, so the provider-`to` /
/// legacy-`from` arm below can reach a helper that answers NULL for a legacy origin. Both keys in
/// that arm are still typed and non-NULL here; the helper's own doc records the omission.
///
/// # Safety
/// `to` must be live; `from` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_copy_parameters(to: *mut EvpPkey, from: *const EvpPkey) -> c_int {
    let mut ok = 0;
    let mut downgraded_from: *mut EvpPkey = ptr::null_mut();
    let mut from_pk = from;

    'end: {
        /* The opening block: a legacy `to` takes a downgraded copy of a provider `from`. */
        // SAFETY: `to` and `from_pk` are live per the contract.
        if unsafe { evp_pkey_is_legacy(to) != 0 && evp_pkey_is_provided(from_pk) != 0 } {
            // SAFETY: `downgraded_from` is a writable slot and `from_pk` is live.
            if unsafe { evp_pkey_copy_downgraded(&mut downgraded_from, from_pk) } == 0 {
                break 'end;
            }
            from_pk = downgraded_from;
        }

        /* `evp_pkey_is_blank(to)` and `evp_pkey_is_legacy(to)` are read once, into locals, because
         * clippy requires the safety comment to sit directly above an unsafe block rather than
         * inside a condition. */
        // SAFETY: `to` is live.
        let to_blank = unsafe { evp_pkey_is_blank(to) } != 0;
        // SAFETY: `to` is live.
        let to_legacy = unsafe { evp_pkey_is_legacy(to) } != 0;
        // SAFETY: `from_pk` is live.
        let from_legacy = unsafe { evp_pkey_is_legacy(from_pk) } != 0;

        if to_blank {
            if from_legacy {
                // SAFETY: `to` and `from_pk` are live.
                if unsafe { EVP_PKEY_set_type(to, (*from_pk).type_) } == 0 {
                    break 'end;
                }
            // SAFETY: `to` and `from_pk` are live.
            } else if unsafe { EVP_PKEY_set_type_by_keymgmt(to, (*from_pk).keymgmt) } == 0 {
                break 'end;
            }
        } else if to_legacy {
            /* A legacy `to` and a `from` of a different key type. */
            // SAFETY: both keys are live.
            if unsafe { (*to).type_ != (*from_pk).type_ } {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::P_LIB_180) };
                break 'end;
            }
        }

        // SAFETY: `from_pk` is live per the contract.
        if unsafe { EVP_PKEY_missing_parameters(from_pk) } != 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::P_LIB_187) };
            break 'end;
        }

        // SAFETY: `to` is live.
        if unsafe { EVP_PKEY_missing_parameters(to) } == 0 {
            // SAFETY: both keys are live.
            if unsafe { EVP_PKEY_parameters_eq(to, from_pk) } == 1 {
                ok = 1;
            } else {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::P_LIB_195) };
            }
            break 'end;
        }

        /* For purely provided keys, the keymgmt utility does the work. */
        // SAFETY: both keys are live.
        if unsafe { !(*to).keymgmt.is_null() && !(*from_pk).keymgmt.is_null() } {
            // SAFETY: both keys are live and each has a method.
            ok = unsafe {
                evp_keymgmt_util_copy(
                    to,
                    from_pk.cast_mut(),
                    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                )
            };
            break 'end;
        }

        /* A provider `to` with no keydata yet and a legacy `from`: export, then duplicate into
         * `to->keydata`. */
        // SAFETY: `to` is live.
        if unsafe { !(*to).keymgmt.is_null() && (*to).keydata.is_null() } {
            /* The authority hands the destination method to the export and writes it back on
             * success; the local is the in/out slot. */
            // SAFETY: `to` is live.
            let mut to_keymgmt = unsafe { (*to).keymgmt };
            // SAFETY: `from_pk` is live; the method slot is a live local and the authority passes
            // NULL for the library context and the property query.
            let from_keydata = unsafe {
                evp_pkey_export_to_provider(
                    from_pk.cast_mut(),
                    ptr::null_mut(),
                    &mut to_keymgmt,
                    ptr::null(),
                )
            };

            if from_keydata.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::P_LIB_223) };
            } else {
                // SAFETY: `to` is live and has a method; `from_keydata` is the exported key of that
                // method.
                let dup = unsafe {
                    evp_keymgmt_dup(
                        (*to).keymgmt,
                        from_keydata,
                        OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                    )
                };
                // SAFETY: `to` is live.
                unsafe { (*to).keydata = dup };
                ok = c_int::from(!dup.is_null());
            }
            break 'end;
        }

        /* Both keys are legacy: the source method's own `param_copy`. */
        // SAFETY: `from_pk` is live.
        let param_copy = unsafe { (*from_pk).ameth.as_ref() }.and_then(|m| m.param_copy);
        if let Some(param_copy) = param_copy {
            // SAFETY: `param_copy` is the source method's own callback and both keys are live.
            ok = unsafe { param_copy(to, from_pk) };
        }
    }

    // SAFETY: `downgraded_from` is NULL or the downgraded key this call owns.
    unsafe { EVP_PKEY_free(downgraded_from) };
    ok
}

/// `int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:241`.
///
/// Three statements and one answer: a provider key asks its own method whether it **has** the
/// domain parameters, a legacy one asks its ameth's `param_missing`, and a NULL key is not missing
/// anything (which is how the authority spells "this function was called on nothing"). The legacy
/// arm became reachable when D353 published the `standard_methods[]` rows.
///
/// Note the inversion: this function's `1` means *absent* and `evp_keymgmt_util_has`'s `1` means
/// *present*, so the `!` is the whole of the translation.
///
/// # Safety
/// `pkey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_missing_parameters(pkey: *const EvpPkey) -> c_int {
    if !pkey.is_null() {
        // SAFETY: `pkey` is live per the contract.
        let keymgmt = unsafe { (*pkey).keymgmt };
        if !keymgmt.is_null() {
            // SAFETY: `pkey` is live and has a method.
            return c_int::from(
                unsafe {
                    evp_keymgmt_util_has(pkey.cast_mut(), OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)
                } == 0,
            );
        }
        /* `if (pkey->ameth != NULL && pkey->ameth->param_missing != NULL) return
         * pkey->ameth->param_missing(pkey);` — the legacy arm, reachable since D353. */
        // SAFETY: `pkey` is live.
        let param_missing = unsafe { (*pkey).ameth.as_ref() }.and_then(|m| m.param_missing);
        if let Some(param_missing) = param_missing {
            // SAFETY: `param_missing` is the method's own callback and `pkey` is live.
            return unsafe { param_missing(pkey) };
        }
    }
    0
}

/// `int EVP_PKEY_can_sign(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:1112`.
///
/// The provider arm asks the key type which **signature** it prefers and then tries to fetch one:
/// the answer is about the *provider* rather than the key, so a key type with no signature
/// implementation answers 0 however well-formed its key data is. The name comes from
/// `evp_keymgmt_util_query_operation_name`, which falls back to the key type's own name — that
/// fallback is what makes a signature named after the key type reachable without the provider
/// saying anything.
///
/// The legacy arm is a switch over `EVP_PKEY_get_base_id` that reads the low-level key for the
/// EC case; it is Phase 8's for its primitives and unreachable for its guard, since
/// `keymgmt == NULL` with a type is a legacy origin.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_can_sign(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let keymgmt = unsafe { (*pkey).keymgmt };

    if keymgmt.is_null() {
        /* Phase 8: the `EVP_PKEY_RSA`/`_RSA_PSS`/`_DSA`/`_ED25519`/`_ED448`/`_EC` switch, whose EC
         * arm calls `EC_KEY_can_sign(pkey->pkey.ec)`. Unreachable: a key with no method and a type
         * is a legacy origin. */
        return 0;
    }

    // SAFETY: `keymgmt` is live.
    let prov = unsafe { EVP_KEYMGMT_get0_provider(keymgmt) };
    // SAFETY: `prov` is the method's own provider, which is live while the method is.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    // SAFETY: `keymgmt` is live.
    let name = unsafe { evp_keymgmt_util_query_operation_name(keymgmt, OSSL_OP_SIGNATURE) };
    // SAFETY: `name` is NUL-terminated or NULL, which the fetch documents.
    let sig = unsafe { EVP_SIGNATURE_fetch(libctx, name, ptr::null()) };
    if !sig.is_null() {
        // SAFETY: `sig` is live and this call holds the only reference.
        unsafe { EVP_SIGNATURE_free(sig) };
        return 1;
    }
    0
}

/// `int EVP_PKEY_get_base_id(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:1028`.
///
/// Literally `EVP_PKEY_type(pkey->type)`, and the resolution follows the `type` field's two
/// reachable values:
///
///   * a **provider** key's `type` is `EVP_PKEY_KEYMGMT` (`-1`), which is what `EVP_PKEY_get_id`
///     answers and what no method table names;
///   * a **blank** key's `type` is `EVP_PKEY_NONE` (`0`).
///
/// The lookup itself is `EVP_PKEY_type`, which landed with the eleven `standard_methods[]` rows
/// (D353) and lives beside `EVP_PKEY_asn1_find`, the table search it needs. For a value no method
/// row names — `EVP_PKEY_KEYMGMT` (`-1`) or `EVP_PKEY_NONE` (`0`) — it answers `NID_undef`, exactly as
/// the authority does.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_base_id(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let type_ = unsafe { (*pkey).type_ };
    // SAFETY: no preconditions.
    unsafe { EVP_PKEY_type(type_) }
}

/// `void *EVP_PKEY_get0(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:825`.
///
/// A provided key answers NULL *by the authority's own `return NULL`*; a legacy key answers its
/// origin `pkey.ptr`. Both arms are now real, because 8.8 modelled the union and a legacy origin key
/// is a state this crate can enter.
///
/// # Safety
/// `pkey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0(pkey: *const EvpPkey) -> *mut c_void {
    if pkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pkey` is live per the contract.
    unsafe {
        if !(*pkey).keymgmt.is_null() {
            return ptr::null_mut();
        }
        (*pkey).pkey
    }
}

/// `int EVP_PKEY_set_type(EVP_PKEY *pkey, int type)` — `crypto/evp/p_lib.c:721`.
///
/// `pkey_set_type(pkey, NULL, type, NULL, -1, NULL)`: an ameth is looked up by the legacy NID and
/// the key becomes a **legacy origin** key, so it answers 1 for every one of the legacy types the
/// `standard_methods[]` table carries and 0 with `EVP_R_UNSUPPORTED_ALGORITHM` for a type no table
/// row names.
///
/// # Safety
/// `pkey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_type(pkey: *mut EvpPkey, type_: c_int) -> c_int {
    // SAFETY: `pkey` is NULL or live per the contract.
    unsafe { pkey_set_type(pkey, type_, ptr::null(), -1, ptr::null_mut()) }
}

/// `int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len)` —
/// `crypto/evp/p_lib.c:726`.
///
/// The same call with `EVP_PKEY_NONE` and the name: the lookup is `EVP_PKEY_asn1_find_str`, whose
/// search is now over a populated `standard_methods[]`. A name no method carries answers 0 with
/// `EVP_R_UNSUPPORTED_ALGORITHM`; a name an application registered with `EVP_PKEY_asn1_add0` is
/// found by the same lookup, as the authority's is.
///
/// # Safety
/// `pkey` must be NULL or live; `str` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_type_str(
    pkey: *mut EvpPkey,
    str_: *const c_char,
    len: c_int,
) -> c_int {
    // SAFETY: `pkey` is NULL or live and `str_` is NULL or NUL-terminated per the contract.
    unsafe { pkey_set_type(pkey, EVP_PKEY_NONE, str_, len, ptr::null_mut()) }
}

/// `static EVP_PKEY *new_cmac_key_int(const unsigned char *priv, size_t len,
/// const char *cipher_name, const EVP_CIPHER *cipher, OSSL_LIB_CTX *libctx, const char *propq,
/// ENGINE *e)` — `crypto/evp/p_lib.c:655`.
///
/// A `fromdata` of a CMAC key, and the whole of it is the parameter array: the key is handed to a
/// provider named `"CMAC"` as `priv` plus the cipher's **name**. Two details are contract rather
/// than plumbing:
///
///   * a `cipher` argument *overrides* `cipher_name`, and a NULL `cipher_name` afterwards is the
///     first refusal — so `EVP_PKEY_new_CMAC_key(e, priv, len, NULL)` never builds a context at
///     all;
///   * the provider is asked for by **name**, so this is a call into the default library context
///     unless the caller supplies one, and a build with no CMAC provider answers NULL with nothing
///     on the error queue.
///
/// `e` is Phase 13's `ENGINE`; it is always NULL here, so the authority's `engine_id` is NULL and
/// the fifth parameter slot is never filled.
///
/// # Safety
/// `priv_` NULL or readable for `len`; `cipher_name` NULL or NUL-terminated; `cipher` NULL or live;
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
unsafe fn new_cmac_key_int(
    priv_: *const u8,
    len: usize,
    cipher_name: *const c_char,
    cipher: *const EvpCipher,
    libctx: *mut c_void,
    propq: *const c_char,
    e: *mut Engine,
) -> *mut EvpPkey {
    let mut cipher_name = cipher_name;
    let mut params: [OsslParam; 5] = [crate::params::END; 5];
    let mut pkey: *mut EvpPkey = ptr::null_mut();

    /* Phase 13: `const char *engine_id = e != NULL ? ENGINE_get_id(e) : NULL;`. */
    let _ = e;

    if !cipher.is_null() {
        // SAFETY: `cipher` is live per the contract.
        cipher_name = unsafe { EVP_CIPHER_get0_name(cipher) };
    }
    if cipher_name.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_673) };
        return ptr::null_mut();
    }

    // SAFETY: `cipher_name` is NUL-terminated and `propq` is NULL or NUL-terminated.
    let ctx = unsafe { EVP_PKEY_CTX_new_from_name(libctx, c"CMAC".as_ptr(), propq) };
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live.
    if unsafe { EVP_PKEY_fromdata_init(ctx) } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_682) };
        // SAFETY: `ctx` is live and `pkey` is still NULL.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        return ptr::null_mut();
    }

    let mut n = 0usize;
    // SAFETY: each constructor writes one entry of this frame's five-slot array, which holds the
    // three parameters and the terminator at most.
    unsafe {
        params[n] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY,
            priv_.cast_mut().cast(),
            len,
        );
        n += 1;
        params[n] =
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER, cipher_name.cast_mut(), 0);
        n += 1;
        /* `propq` is NULL for the one caller this crate has, and the clause is written because the
         * authority's is: `EVP_PKEY_new_CMAC_key` is not the function's only shape. */
        if !propq.is_null() {
            params[n] =
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, propq.cast_mut(), 0);
            n += 1;
        }
        /* Phase 13: the `OSSL_PKEY_PARAM_ENGINE` slot, which needs `ENGINE_get_id`. */
        params[n] = OSSL_PARAM_construct_end();
    }

    // SAFETY: `ctx` is live, `params` is this frame's terminated array, and `pkey` is writable.
    if unsafe {
        EVP_PKEY_fromdata(
            ctx,
            ptr::addr_of_mut!(pkey),
            EVP_PKEY_KEYPAIR,
            params.as_mut_ptr(),
        )
    } <= 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_701) };
    }

    // SAFETY: `ctx` is live and this is the one release.
    unsafe { EVP_PKEY_CTX_free(ctx) };
    pkey
}

/// `EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv, size_t len,
/// const EVP_CIPHER *cipher)` — `crypto/evp/p_lib.c:715`.
///
/// The same function with `libctx` and `propq` NULL, which is what puts it in the **default**
/// library context: a caller who never installed a CMAC provider gets NULL, and the probe that
/// drives this entry point observes exactly that.
///
/// # Safety
/// `e` is Phase 13's `ENGINE` and must be NULL; `priv` NULL or readable for `len`; `cipher` NULL or
/// live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new_CMAC_key(
    e: *mut Engine,
    priv_: *const u8,
    len: usize,
    cipher: *const EvpCipher,
) -> *mut EvpPkey {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        new_cmac_key_int(
            priv_,
            len,
            ptr::null(),
            cipher,
            ptr::null_mut(),
            ptr::null(),
            e,
        )
    }
}

/// `static void mdname2nid(const char *mdname, void *data)` — `crypto/evp/p_lib.c:1298`.
///
/// The visitor `ossl_namemap_doall_names` walks a digest's aliases with: the **first** spelling
/// that resolves in the object table wins, and the guard at the top is what makes "first" true
/// rather than "last".
///
/// # Safety
/// `mdname` must be NUL-terminated; `data` must point at a live `int`.
unsafe extern "C" fn mdname2nid(mdname: *const c_char, data: *mut c_void) {
    let nid = data.cast::<c_int>();

    // SAFETY: `nid` is live per the contract.
    if unsafe { *nid } != NID_undef {
        return;
    }
    // SAFETY: `mdname` is NUL-terminated.
    let mut resolved = unsafe { OBJ_sn2nid(mdname) };
    if resolved == NID_undef {
        // SAFETY: `mdname` is NUL-terminated.
        resolved = unsafe { OBJ_ln2nid(mdname) };
    }
    // SAFETY: `nid` is live.
    unsafe { *nid = resolved };
}

/// `static int legacy_asn1_ctrl_to_param(EVP_PKEY *pkey, int op, int arg1, void *arg2)` —
/// `crypto/evp/p_lib.c:1308`.
///
/// What a legacy control becomes for a **provider** key, and it exists for exactly one command
/// today: `ASN1_PKEY_CTRL_DEFAULT_MD_NID` asks the method for its default digest *name*, fetches
/// that digest so the **namemap** learns the name, and then maps the namemap's number back to an
/// object NID. Three refusals are folded into that: a key with no method at all answers `0`; a
/// namemap number of `0` — a digest name nothing registered — answers `0`; and a name that resolves
/// to no NID answers the `rv` with `arg2` untouched.
///
/// The `default:` arm answers `-2`, which is the ctrl family's "not supported". It is written and
/// **unreachable through this subphase's exports**, because `EVP_PKEY_get_default_digest_nid` is the
/// only caller and it passes `DEFAULT_MD_NID`; it becomes reachable with `EVP_PKEY_set1_encoded_public_key`
/// after Phase 8, whose legacy arm passes `SET1_TLS_ENCPT`.
///
/// # Safety
/// `pkey` must be live; `arg2` must be NULL or point at a live `int` for the one command handled.
unsafe fn legacy_asn1_ctrl_to_param(
    pkey: *mut EvpPkey,
    op: c_int,
    arg1: c_int,
    arg2: *mut c_void,
) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let keymgmt = unsafe { (*pkey).keymgmt };
    if keymgmt.is_null() {
        return 0;
    }
    /* The two arguments the authority's single command does not read are named here because they
     * are part of its signature and a Phase-8 fill needs them. */
    let _ = arg1;

    if op == ASN1_PKEY_CTRL_DEFAULT_MD_NID {
        let mut mdname = [0 as c_char; 80];
        // SAFETY: `pkey` is live and `mdname` is an 80-byte writable buffer.
        let rv =
            unsafe { EVP_PKEY_get_default_digest_name(pkey, mdname.as_mut_ptr(), mdname.len()) };
        if rv > 0 {
            let mut nid: c_int = NID_undef;

            // SAFETY: `keymgmt` is live; its provider is live while it is.
            let libctx = unsafe { ossl_provider_libctx((*keymgmt).prov) };
            crate::runtime::err::ERR_set_mark();
            // SAFETY: `mdname` is NUL-terminated and `libctx` is live.
            let md = unsafe { EVP_MD_fetch(libctx, mdname.as_ptr(), ptr::null()) };
            crate::runtime::err::ERR_pop_to_mark();
            // SAFETY: `libctx` is live, which is all the namemap constructor needs.
            let namemap = crate::context::namemap::ossl_namemap_stored(libctx);
            /* The fetch's only purpose was to register the name; the method is not wanted. */
            // SAFETY: `md` is NULL or live.
            unsafe { EVP_MD_free(md) };

            // SAFETY: `namemap` is live and `mdname` is NUL-terminated.
            let mdnum =
                unsafe { crate::context::namemap::ossl_namemap_name2num(namemap, mdname.as_ptr()) };
            if mdnum == 0 {
                return 0;
            }
            // SAFETY: `namemap` is live, the visitor is this file's own, and `nid` is a live local.
            if unsafe {
                crate::context::namemap::ossl_namemap_doall_names(
                    namemap,
                    mdnum,
                    Some(mdname2nid),
                    ptr::addr_of_mut!(nid).cast::<c_void>(),
                )
            } == 0
            {
                return 0;
            }
            // SAFETY: `arg2` is the caller's live `int` for this command.
            unsafe { *arg2.cast::<c_int>() = nid };
        }
        return rv;
    }
    -2
}

/// `static int evp_pkey_asn1_ctrl(EVP_PKEY *pkey, int op, int arg1, void *arg2)` —
/// `crypto/evp/p_lib.c:1356`.
///
/// The dispatch: a key with an `EVP_PKEY_ASN1_METHOD` asks it, and a **provider** key goes through
/// `legacy_asn1_ctrl_to_param`. The ameth half is Phase 8's and unreachable — nothing in this crate
/// sets `ameth` — so the two statements it contains are named rather than written, and the `-2`
/// that follows is the authority's answer for an ameth with no `pkey_ctrl`.
///
/// # Safety
/// `pkey` must be live.
unsafe fn evp_pkey_asn1_ctrl(
    pkey: *mut EvpPkey,
    op: c_int,
    arg1: c_int,
    arg2: *mut c_void,
) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    if unsafe { (*pkey).ameth }.is_null() {
        // SAFETY: `pkey` is live.
        return unsafe { legacy_asn1_ctrl_to_param(pkey, op, arg1, arg2) };
    }
    /* Phase 8: `if (pkey->ameth->pkey_ctrl == NULL) return -2; return
     * pkey->ameth->pkey_ctrl(pkey, op, arg1, arg2);` */
    -2
}

/// `int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid)` —
/// `crypto/evp/p_lib.c:1365`.
///
/// One arm for a NULL key and a delegation for everything else — and in this crate the delegation
/// always goes through `legacy_asn1_ctrl_to_param`, because no key has an ameth. The answer is
/// therefore the *name* path's answer converted back to a NID, and `0` when the name is not in the
/// namemap.
///
/// # Safety
/// `pkey` must be NULL or live; `pnid` NULL or a live `int`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_default_digest_nid(
    pkey: *mut EvpPkey,
    pnid: *mut c_int,
) -> c_int {
    if pkey.is_null() {
        return 0;
    }
    // SAFETY: `pkey` is live and `pnid` is the caller's.
    unsafe {
        evp_pkey_asn1_ctrl(
            pkey,
            ASN1_PKEY_CTRL_DEFAULT_MD_NID,
            0,
            pnid.cast::<c_void>(),
        )
    }
}

/// `int EVP_PKEY_get_default_digest_name(EVP_PKEY *pkey, char *mdname, size_t mdname_sz)` —
/// `crypto/evp/p_lib.c:1372`.
///
/// Two halves again, and the provider half is the interesting one: it returns the method's own
/// **signed** answer, where `-2` means neither parameter was answered, `1` means `default-digest`
/// and `2` means `mandatory-digest` — a mandatory digest overrides a default one. The ameth half
/// turns a NID back into a short name; it is written in full and is unreachable, because `ameth` is
/// always NULL.
///
/// # Safety
/// `pkey` must be live; `mdname` NULL or writable for `mdname_sz` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_default_digest_name(
    pkey: *mut EvpPkey,
    mdname: *mut c_char,
    mdname_sz: usize,
) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let (ameth, keymgmt, keydata) = unsafe { ((*pkey).ameth, (*pkey).keymgmt, (*pkey).keydata) };

    if ameth.is_null() {
        // SAFETY: `keymgmt` is live per the contract, `keydata` belongs to it, and `mdname` is
        // writable for `mdname_sz` bytes.
        return unsafe {
            evp_keymgmt_util_get_deflt_digest_name(keymgmt, keydata, mdname, mdname_sz)
        };
    }

    /* Phase 8, and unreachable: an ameth's NID converted back to a name. Complete, so that the day
     * the lookup lands this function is the authority's rather than a stub. */
    let mut nid: c_int = NID_undef;
    // SAFETY: `pkey` is live and `nid` is a live local.
    let rv = unsafe { EVP_PKEY_get_default_digest_nid(pkey, ptr::addr_of_mut!(nid)) };
    if rv > 0 {
        let name = OBJ_nid2sn(nid);
        // SAFETY: `name` is NUL-terminated and `mdname` is writable for `mdname_sz` bytes.
        unsafe { OPENSSL_strlcpy(mdname, name, mdname_sz) };
    }
    rv
}

/// `int EVP_PKEY_get_group_name(const EVP_PKEY *pkey, char *gname, size_t gname_sz,
/// size_t *gname_len)` — `crypto/evp/p_lib.c:1391`.
///
/// A one-line delegation to the UTF-8 string reader under the key's own `group` parameter, so every
/// detail — the terminator rule, the modification test and the length out-parameter — is that
/// function's.
///
/// # Safety
/// `pkey` must be NULL or live; `gname` NULL or writable for `gname_sz`; `gname_len` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_group_name(
    pkey: *const EvpPkey,
    gname: *mut c_char,
    gname_sz: usize,
    gname_len: *mut usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        EVP_PKEY_get_utf8_string_param(
            pkey,
            crate::evp::pkey_ctx::OSSL_PKEY_PARAM_GROUP_NAME,
            gname,
            gname_sz,
            gname_len,
        )
    }
}

/// `int EVP_PKEY_digestsign_supports_digest(EVP_PKEY *pkey, OSSL_LIB_CTX *libctx, const char *name,
/// const char *propq)` — `crypto/evp/p_lib.c:1398`.
///
/// Three statements around one question: can this key digest-sign with `name`? The answer is a
/// fresh `EVP_MD_CTX` put through `EVP_DigestSignInit_ex` — which is `m_sigver.c`'s provider half —
/// with the context freed immediately afterwards, so nothing but the return code survives.
///
/// **The `ERR_set_mark`/`ERR_pop_to_mark` pair is why a bad digest name is observable as an
/// *empty* error queue.** `do_sigver_init` raises for a name that cannot be fetched, and the pop
/// removes every one of those errors before the caller can see them, so a caller that looks at the
/// queue rather than the return code reads `0` and nothing else. That is the authority's shape and
/// the court observes it rather than the raise.
///
/// `-1` is the `EVP_MD_CTX_new` failure, and it is **unreachable in the court**: the allocation
/// has no injectable failure point, and a probe that faked one would be measuring its own seam
/// rather than this function. It is named rather than driven.
///
/// # Safety
/// `pkey` must be NULL or live; `libctx` NULL or live; `name` and `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_digestsign_supports_digest(
    pkey: *mut EvpPkey,
    libctx: *mut c_void,
    name: *const c_char,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `EVP_MD_CTX_new` allocates a zeroed context and cannot fail for a live allocator;
    // the NULL arm below is written anyway because it is the authority's.
    let ctx = EVP_MD_CTX_new();
    if ctx.is_null() {
        return -1;
    }

    ERR_set_mark();
    // SAFETY: `ctx` is live, `name`/`propq` are NULL or NUL-terminated, and `pkey` is NULL or
    // live per the contract.
    let rv = unsafe {
        EVP_DigestSignInit_ex(ctx, ptr::null_mut(), name, libctx, propq, pkey, ptr::null())
    };
    ERR_pop_to_mark();

    // SAFETY: `ctx` is this call's own context and nothing else holds it.
    unsafe { EVP_MD_CTX_free(ctx) };
    rv
}

/// `int EVP_PKEY_set1_encoded_public_key(EVP_PKEY *pkey, const unsigned char *pub,
/// size_t publen)` — `crypto/evp/p_lib.c:1417`.
///
/// The older name for `EVP_PKEY_set1_tls_encodedpoint`. A provided key writes the parameter; a key
/// **without a method answers 0 through the ctrl path**, and it is worth stating why that is an
/// observation rather than an unreachable branch: `evp_pkey_asn1_ctrl` finds no ameth and forwards
/// to `legacy_asn1_ctrl_to_param`, which refuses a key with no `keymgmt`, so a blank key's answer is
/// `0` — the same `0` the authority answers for it.
///
/// The `publen > INT_MAX` test is the authority's and sits in the legacy half, which is why it is
/// written after the provided arm rather than before it.
///
/// # Safety
/// `pkey` must be NULL or live; `pub_` NULL or readable for `publen`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_encoded_public_key(
    pkey: *mut EvpPkey,
    pub_: *const u8,
    publen: usize,
) -> c_int {
    if pkey.is_null() {
        return 0;
    }
    // SAFETY: `pkey` is live per the contract.
    if !unsafe { (*pkey).keymgmt }.is_null() {
        // SAFETY: `pkey` is live, the name is NUL-terminated and `pub_` is readable for `publen`.
        return unsafe {
            EVP_PKEY_set_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub_, publen)
        };
    }

    if publen > c_int::MAX as usize {
        return 0;
    }
    // SAFETY: `pkey` is live and `pub_` is readable for `publen`, which fits an `int`.
    if unsafe {
        evp_pkey_asn1_ctrl(
            pkey,
            ASN1_PKEY_CTRL_SET1_TLS_ENCPT,
            publen as c_int,
            pub_.cast_mut().cast::<c_void>(),
        )
    } <= 0
    {
        return 0;
    }
    1
}

/// `size_t EVP_PKEY_get1_encoded_public_key(EVP_PKEY *pkey, unsigned char **ppub)` —
/// `crypto/evp/p_lib.c:1441`.
///
/// **Two passes**, because the parameter's length is not known first: the reader is asked with a
/// NULL buffer, which fills `return_size` and nothing else, and the bytes are then fetched into a
/// block of exactly that size. `OSSL_PARAM_UNMODIFIED` is the sentinel that says the first pass
/// answered nothing, and it is why a provider with no such parameter costs one call rather than an
/// allocation.
///
/// The caller's `*ppub` is set to NULL *before* the allocation, so a failing second pass frees the
/// block and leaves the caller's pointer NULL rather than dangling.
///
/// # Safety
/// `pkey` must be NULL or live; `ppub` must be live and writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get1_encoded_public_key(
    pkey: *mut EvpPkey,
    ppub: *mut *mut u8,
) -> usize {
    if pkey.is_null() {
        return 0;
    }
    // SAFETY: `pkey` is live per the contract.
    if !unsafe { (*pkey).keymgmt }.is_null() {
        let mut return_size: usize = crate::params::OSSL_PARAM_UNMODIFIED;

        /* "We know that this is going to fail, but it will give us a size to allocate." */
        // SAFETY: `pkey` is live, the name is NUL-terminated, the buffer is NULL with size 0, and
        // `return_size` is a live local.
        unsafe {
            EVP_PKEY_get_octet_string_param(
                pkey,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                ptr::null_mut(),
                0,
                ptr::addr_of_mut!(return_size),
            )
        };
        if return_size == crate::params::OSSL_PARAM_UNMODIFIED {
            return 0;
        }

        // SAFETY: `ppub` is the caller's writable slot.
        unsafe { *ppub = ptr::null_mut() };
        // This allocates `return_size` bytes, which is the authority's `OPENSSL_malloc`; the crate's
        // `CRYPTO_malloc` carries the authority's coordinates and its own failure raise.
        let buf = CRYPTO_malloc(return_size, FILE, LINE_MALLOC_ENCODED_PUBKEY).cast::<u8>();
        if buf.is_null() {
            return 0;
        }

        // SAFETY: `pkey` is live, `buf` is `return_size` writable bytes and the name is
        // NUL-terminated.
        if unsafe {
            EVP_PKEY_get_octet_string_param(
                pkey,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                buf,
                return_size,
                ptr::null_mut(),
            )
        } == 0
        {
            // SAFETY: `buf` is this call's own block.
            unsafe { CRYPTO_free(buf.cast::<c_void>(), FILE, LINE_FREE_ENCODED_PUBKEY) };
            return 0;
        }
        // SAFETY: `ppub` is writable.
        unsafe { *ppub = buf };
        return return_size;
    }

    /* The legacy arm -- `evp_pkey_asn1_ctrl(pkey, ASN1_PKEY_CTRL_GET1_TLS_ENCPT, 0, ppub)` -- is
     * written, and for a blank key it answers `0` on both sides: see
     * `EVP_PKEY_set1_encoded_public_key`'s doc comment for why the ctrl refuses one. */
    // SAFETY: `pkey` is live and `ppub` is the caller's writable slot.
    let rv = unsafe {
        evp_pkey_asn1_ctrl(
            pkey,
            ASN1_PKEY_CTRL_GET1_TLS_ENCPT,
            0,
            ppub.cast::<c_void>(),
        )
    };
    if rv <= 0 {
        return 0;
    }
    rv as usize
}

/// `static EVP_PKEY *evp_pkey_keygen(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
/// const OSSL_PARAM *params)` — `crypto/evp/evp_lib.c:1204`.
///
/// The `EVP_PKEY_CTX` dance folded into one call, and its **short-circuit chain is the contract**:
/// a context that cannot be built, an init that refuses and a parameter array the provider rejects
/// all skip the generation, and all three still return the NULL `pkey`. The `(void)` around the
/// generate is the authority's: a generation that fails inside the context is reported through the
/// error queue and not through this function's answer.
///
/// # Safety
/// `libctx` NULL or live; `name` NUL-terminated; `propq` NULL or NUL-terminated; `params` NULL or a
/// terminated array.
pub(crate) unsafe fn evp_pkey_keygen(
    libctx: *mut c_void,
    name: *const c_char,
    propq: *const c_char,
    params: *const OsslParam,
) -> *mut EvpPkey {
    let mut pkey: *mut EvpPkey = ptr::null_mut();

    // SAFETY: `name` and `propq` are NUL-terminated or NULL.
    let ctx = unsafe { EVP_PKEY_CTX_new_from_name(libctx, name, propq) };
    if !ctx.is_null()
        // SAFETY: `ctx` is live.
        && unsafe { EVP_PKEY_keygen_init(ctx) } > 0
        // SAFETY: `ctx` is live and `params` is a terminated array.
        && unsafe { EVP_PKEY_CTX_set_params(ctx, params) } != 0
    {
        // SAFETY: `ctx` is live and `pkey` is this frame's writable local.
        unsafe { EVP_PKEY_generate(ctx, ptr::addr_of_mut!(pkey)) };
    }

    // SAFETY: `ctx` is NULL or live.
    unsafe { EVP_PKEY_CTX_free(ctx) };
    pkey
}

/// The Rust half of `EVP_PKEY_Q_keygen` — `crypto/evp/evp_lib.c:1219`.
///
/// The export is **C-variadic**, which stable Rust cannot define, so the `va_arg` walk lives in
/// `src/evp/pkey_q_keygen_variadic.c` and hands its result here. The two halves together are the
/// authority's walk and neither decides anything alone: the shim compares the type name and reads
/// the argument that name takes — one `size_t` for `"RSA"`, one `char *` for `"EC"`, and nothing
/// at all for any other name — and reports which class it read as `kind` (`0` none, `1` bits,
/// `2` name); this half builds the `OSSL_PARAM` the authority builds, under the authority's key,
/// and calls `evp_pkey_keygen`.
///
/// The parameter array is built here rather than in C because the adapter has **no include path**:
/// `build.rs` compiles the C adapters with none (see `src/runtime/bio/bio_variadic.c`), and a
/// private copy of `struct ossl_param_st` in a `.c` file would be a second definition of a public
/// ABI type.
///
/// The name is a plain C identifier rather than a rustc mangling because the shim must link to it;
/// it is an internal symbol, hidden by the version script, and `implemented_surface.py` records it
/// as such.
///
/// # Safety
/// `libctx` NULL or live; `propq` NULL or NUL-terminated; `type_` NUL-terminated; `name` NULL or
/// NUL-terminated, and non-NULL exactly when `kind` is 2.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_evp_pkey_q_keygen(
    libctx: *mut c_void,
    propq: *const c_char,
    type_: *const c_char,
    kind: c_int,
    mut bits: usize,
    name: *const c_char,
) -> *mut EvpPkey {
    let mut params: [OsslParam; 2] = [crate::params::END; 2];

    // SAFETY: each constructor writes one entry of this frame's array; `bits` and `name` are this
    // call's own arguments and outlive the array.
    unsafe {
        if kind == 1 {
            params[0] = crate::params::OSSL_PARAM_construct_size_t(
                crate::evp::pkey_ctx::OSSL_PKEY_PARAM_RSA_BITS,
                ptr::addr_of_mut!(bits),
            );
        } else if kind == 2 {
            params[0] = OSSL_PARAM_construct_utf8_string(
                crate::evp::pkey_ctx::OSSL_PKEY_PARAM_GROUP_NAME,
                name.cast_mut(),
                0,
            );
        }
        params[1] = OSSL_PARAM_construct_end();
    }

    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_keygen(libctx, type_, propq, params.as_ptr()) }
}

// ---------------------------------------------------------------------------------------------
// `crypto/evp/p_lib.c`'s legacy half — the readers and the assignment the eleven
// `EVP_PKEY_ASN1_METHOD` objects name. Phase 7.4a withheld each of them because it reads
// `pkey->ameth` or `pkey->pkey`, the legacy block the crate declined to model while
// `EVP_PKEY_ASN1_METHOD` was Phase 8's; 8.8 lands the type and the objects, so the block and its
// readers land with them. The one formatted `ERR_raise_data` message is built with `BIO_snprintf`
// into a stack buffer, the pattern `src/evp/asymcipher.rs` and `src/evp/signature.rs` carry.
// ---------------------------------------------------------------------------------------------

/// `EVP_PKEY_HMAC` — `include/openssl/evp.h:76`, `NID_hmac`.
const EVP_PKEY_HMAC: c_int = NID_hmac;
/// `EVP_PKEY_POLY1305` — `include/openssl/evp.h:81`, `NID_poly1305`.
const EVP_PKEY_POLY1305: c_int = NID_poly1305;
/// `EVP_PKEY_SIPHASH` — `include/openssl/evp.h:82`, `NID_siphash`.
const EVP_PKEY_SIPHASH: c_int = NID_siphash;
/// `OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT` — `include/openssl/core_names.h:394`.
const OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT: *const c_char = c"point-format".as_ptr();
/// `OSSL_PKEY_PARAM_EC_FIELD_TYPE` — `include/openssl/core_names.h:392`.
const OSSL_PKEY_PARAM_EC_FIELD_TYPE: *const c_char = c"field-type".as_ptr();
/// The authority's `ERR_DATA_BUFFER_SIZE`: the `char[1024]` `ERR_vset_error` formats into.
const ERR_DATA_BUFFER: usize = 1024;

/// `#define evp_pkey_is_legacy(pk)` — `include/crypto/evp.h:649`,
/// `(pk)->type != EVP_PKEY_NONE && (pk)->keymgmt == NULL`.
///
/// The header macro has no function; it is written here because the three `*_ameth.c` units that
/// read it are separate modules and a bare field test in each would be the same expression three
/// times.
///
/// # Safety
/// `pkey` must be live.
#[allow(dead_code)] // its reader is the three `*_ameth.c` modules that check `evp_pkey_is_legacy`
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn evp_pkey_is_legacy(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    c_int::from(unsafe { (*pkey).type_ != EVP_PKEY_NONE && (*pkey).keymgmt.is_null() })
}

/// `#define evp_pkey_is_blank(pk)` — `include/crypto/evp.h:638`,
/// `(pk)->type == EVP_PKEY_NONE && (pk)->keymgmt == NULL`.
///
/// Note that a **legacy** key is not blank by this test even though both `keymgmt` and `keydata` are
/// NULL: the type is what distinguishes them, which is why reading the macro as "no key data" would
/// send `EVP_PKEY_copy_parameters` down the wrong arm.
///
/// # Safety
/// `pkey` must be live.
#[allow(non_snake_case)] // the authority's own macro name
pub(crate) unsafe fn evp_pkey_is_blank(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    c_int::from(unsafe { (*pkey).type_ == EVP_PKEY_NONE && (*pkey).keymgmt.is_null() })
}

/// `#define evp_pkey_is_provided(pk)` — `include/crypto/evp.h:651`, `(pk)->keymgmt != NULL`.
///
/// # Safety
/// `pkey` must be live.
#[allow(non_snake_case)] // the authority's own macro name
pub(crate) unsafe fn evp_pkey_is_provided(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    c_int::from(unsafe { !(*pkey).keymgmt.is_null() })
}

/// `static void detect_foreign_key(EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:757`.
///
/// Sets `pkey->foreign` when the low-level key is engine-backed or application-method-backed, the
/// flag that tells a later reader the key's contents may not be readable directly. The `SM2` arm is
/// the authority's empty one — an SM2 key is an `EC_KEY` under the same union member and its
/// classification is left to the EC arm — and `DHX` takes the `default` arm, which the authority's
/// own `switch` does too.
///
/// # Safety
/// `pkey` must be live.
unsafe fn detect_foreign_key(pkey: *mut EvpPkey) {
    // SAFETY: `pkey` is live per the contract; every key pointer below is that of a live key of
    // the matched type, because `EVP_PKEY_assign` sets `type_` and `pkey` together.
    let foreign = unsafe {
        match (*pkey).type_ {
            EVP_PKEY_RSA | EVP_PKEY_RSA_PSS => {
                let rsa = (*pkey).pkey.cast::<Rsa>();
                !rsa.is_null() && ossl_rsa_is_foreign(rsa) != 0
            }
            EVP_PKEY_SM2 => false,
            EVP_PKEY_EC => {
                let ec = (*pkey).pkey.cast::<EcKey>();
                !ec.is_null() && ossl_ec_key_is_foreign(ec) != 0
            }
            EVP_PKEY_DSA => {
                let dsa = (*pkey).pkey.cast::<Dsa>();
                !dsa.is_null() && ossl_dsa_is_foreign(dsa) != 0
            }
            EVP_PKEY_DH => {
                let dh = (*pkey).pkey.cast::<Dh>();
                !dh.is_null() && ossl_dh_is_foreign(dh) != 0
            }
            _ => false,
        }
    };
    // SAFETY: `pkey` is live.
    unsafe { (*pkey).foreign = c_int::from(foreign) };
}

/// `int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key)` — `crypto/evp/p_lib.c:791`.
///
/// The EC arm rewrites the requested type from the key's own curve: an SM2 curve is `EVP_PKEY_SM2`
/// and any other is `EVP_PKEY_EC`, whichever was asked for — which is why `EVP_PKEY_type` is
/// consulted (and must answer) before the type is stored.
///
/// # Safety
/// `pkey` must be live; `key` must be NULL or a live low-level key of the type named.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_assign(
    pkey: *mut EvpPkey,
    type_: c_int,
    key: *mut c_void,
) -> c_int {
    let mut type_ = type_;
    // SAFETY: no preconditions; the lookup searches this crate's own tables.
    let pktype = unsafe { EVP_PKEY_type(type_) };
    if !key.is_null() && (pktype == EVP_PKEY_EC || pktype == EVP_PKEY_SM2) {
        // SAFETY: `key` is a live `EC_KEY` on this branch per the contract.
        let group = unsafe { EC_KEY_get0_group(key.cast::<EcKey>()) };
        if !group.is_null() {
            // SAFETY: `group` is live.
            let curve = unsafe { EC_GROUP_get_curve_name(group) };
            if curve == NID_sm2 && pktype == EVP_PKEY_EC {
                type_ = EVP_PKEY_SM2;
            } else if curve != NID_sm2 && pktype == EVP_PKEY_SM2 {
                type_ = EVP_PKEY_EC;
            }
        }
    }

    if pkey.is_null()
        // SAFETY: `pkey` is non-NULL on this branch and live per the contract.
        || unsafe { EVP_PKEY_set_type(pkey, type_) } == 0
    {
        return 0;
    }
    // SAFETY: `pkey` is live.
    unsafe {
        (*pkey).pkey = key;
        detect_foreign_key(pkey);
    }
    c_int::from(!key.is_null())
}

/// `int evp_pkey_copy_downgraded(EVP_PKEY **dest, const EVP_PKEY *src)` —
/// `crypto/evp/p_lib.c:2066`.
///
/// Downgrades a **provider** key to a legacy one: it types `*dest`, then exports `src`'s keydata
/// through the source keymgmt and imports it with the destination method's `import_from`, syncing
/// `dirty_cnt_copy`. The `import_from == NULL` arm is unreachable for the four key types this crate
/// carries a method for (each installs one); it is transcribed with its reason rather than omitted.
///
/// # Safety
/// `dest` must point at a writable `EVP_PKEY *` slot; `src` must be live.
pub(crate) unsafe fn evp_pkey_copy_downgraded(
    dest: *mut *mut EvpPkey,
    src: *const EvpPkey,
) -> c_int {
    if dest.is_null() {
        return 0;
    }
    // SAFETY: `dest` is a writable slot and `src` is live per the contract.
    unsafe {
        /* `evp_pkey_is_assigned(src) && evp_pkey_is_provided(src)`. */
        if ((*src).pkey.is_null() && (*src).keydata.is_null()) || (*src).keymgmt.is_null() {
            return 0;
        }

        let keymgmt = (*src).keymgmt;
        let keydata = (*src).keydata;
        let type_ = (*src).type_;
        let mut keytype = EVP_KEYMGMT_get0_name(keymgmt);

        if type_ == EVP_PKEY_NONE {
            let mut msg = [0 as c_char; ERR_DATA_BUFFER];
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"keymgmt key type = %s but legacy type = EVP_PKEY_NONE".as_ptr(),
                keytype,
            );
            raise_site_data(&err_sites::P_LIB_2088, msg.as_ptr());
            return 0;
        }

        /* Prefer the legacy key type name for error reporting. */
        if type_ != EVP_PKEY_KEYMGMT {
            keytype = OBJ_nid2sn(type_);
        }

        if (*dest).is_null() {
            *dest = EVP_PKEY_new();
            if (*dest).is_null() {
                raise_site(&err_sites::P_LIB_2102);
                return 0;
            }
        } else {
            evp_pkey_free_it(*dest);
        }

        if EVP_PKEY_set_type(*dest, type_) != 0 {
            /* If the key is typed but empty, we're done. */
            if keydata.is_null() {
                return 1;
            }

            let ameth = (**dest).ameth;
            let import_from = if ameth.is_null() {
                None
            } else {
                (*ameth).import_from
            };
            if import_from.is_none() {
                let mut msg = [0 as c_char; ERR_DATA_BUFFER];
                BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"key type = %s".as_ptr(),
                    keytype,
                );
                raise_site_data(&err_sites::P_LIB_2115, msg.as_ptr());
            } else {
                /* We perform the export in the same libctx as the keymgmt. */
                let libctx = ossl_provider_libctx((*keymgmt).prov).cast::<c_void>();
                let pctx = EVP_PKEY_CTX_new_from_pkey(libctx, *dest, ptr::null_mut());
                if pctx.is_null() {
                    raise_site(&err_sites::P_LIB_2126);
                }
                if !pctx.is_null()
                    && evp_keymgmt_export(
                        keymgmt,
                        keydata,
                        OSSL_KEYMGMT_SELECT_ALL,
                        import_from,
                        pctx.cast(),
                    ) != 0
                {
                    if let Some(dirty_cnt) = (*ameth).dirty_cnt {
                        (**dest).dirty_cnt_copy = dirty_cnt(*dest);
                    }
                    EVP_PKEY_CTX_free(pctx);
                    return 1;
                }
                EVP_PKEY_CTX_free(pctx);
            }

            let mut msg = [0 as c_char; ERR_DATA_BUFFER];
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"key type = %s".as_ptr(),
                keytype,
            );
            raise_site_data(&err_sites::P_LIB_2142, msg.as_ptr());
        }
    }
    0
}

/// `void *evp_pkey_get_legacy(EVP_PKEY *pk)` — `crypto/evp/p_lib.c:2154`.
///
/// The origin legacy key if there is one, otherwise a cached downgrade of the provider key, made
/// once under `pk->lock` and shared from then on. The cache is `legacy_cache_pkey`, distinct from
/// the origin `pkey`, and the `pkey` half of a temporary copy is stolen into it so the copy's
/// destructor does not take the key back.
///
/// # Safety
/// `pk` must be live.
pub(crate) unsafe fn evp_pkey_get_legacy(pk: *mut EvpPkey) -> *mut c_void {
    let mut tmp_copy: *mut EvpPkey = ptr::null_mut();

    if pk.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pk` is live per the contract.
    unsafe {
        /* `!evp_pkey_is_assigned(pk)`: an unassigned key has no legacy key either. */
        if (*pk).pkey.is_null() && (*pk).keydata.is_null() {
            return ptr::null_mut();
        }
        /* `!evp_pkey_is_provided(pk)`: an origin legacy key is returned directly. */
        if (*pk).keymgmt.is_null() {
            return (*pk).pkey;
        }

        if CRYPTO_THREAD_read_lock((*pk).lock) == 0 {
            return ptr::null_mut();
        }
        let mut ret = (*pk).legacy_cache_pkey;
        if CRYPTO_THREAD_unlock((*pk).lock) == 0 {
            return ptr::null_mut();
        }
        if !ret.is_null() {
            return ret;
        }

        if evp_pkey_copy_downgraded(ptr::addr_of_mut!(tmp_copy), pk) == 0 {
            EVP_PKEY_free(tmp_copy);
            return ptr::null_mut();
        }

        if CRYPTO_THREAD_write_lock((*pk).lock) == 0 {
            EVP_PKEY_free(tmp_copy);
            return ptr::null_mut();
        }

        /* Check again in case some other thread updated it in the meantime. */
        ret = (*pk).legacy_cache_pkey;
        if ret.is_null() {
            /* Steal the legacy key reference from the temporary copy. */
            ret = (*tmp_copy).pkey;
            (*pk).legacy_cache_pkey = ret;
            (*tmp_copy).pkey = ptr::null_mut();
        }

        if CRYPTO_THREAD_unlock((*pk).lock) == 0 {
            ret = ptr::null_mut();
        }
        EVP_PKEY_free(tmp_copy);
        ret
    }
}

/// `const unsigned char *EVP_PKEY_get0_hmac(const EVP_PKEY *pkey, size_t *len)` —
/// `crypto/evp/p_lib.c:836`.
///
/// # Safety
/// `pkey` must be live; `len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_hmac(
    pkey: *const EvpPkey,
    len: *mut usize,
) -> *const c_uchar {
    // SAFETY: `pkey` is live per the contract.
    if unsafe { (*pkey).type_ } != EVP_PKEY_HMAC {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_840) };
        return ptr::null();
    }
    // SAFETY: `pkey` is live, cast to the mutable form the accessor takes.
    let os = unsafe { evp_pkey_get_legacy(pkey as *mut EvpPkey) }.cast::<Asn1String>();
    if !os.is_null() {
        // SAFETY: `len` is writable and `os` is live.
        unsafe {
            *len = (*os).length as usize;
            return (*os).data;
        }
    }
    ptr::null()
}

/// `const unsigned char *EVP_PKEY_get0_poly1305(const EVP_PKEY *pkey, size_t *len)` —
/// `crypto/evp/p_lib.c:852`.
///
/// # Safety
/// `pkey` must be live; `len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_poly1305(
    pkey: *const EvpPkey,
    len: *mut usize,
) -> *const c_uchar {
    // SAFETY: `pkey` is live per the contract.
    if unsafe { (*pkey).type_ } != EVP_PKEY_POLY1305 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_856) };
        return ptr::null();
    }
    // SAFETY: `pkey` is live, cast to the mutable form the accessor takes.
    let os = unsafe { evp_pkey_get_legacy(pkey as *mut EvpPkey) }.cast::<Asn1String>();
    if !os.is_null() {
        // SAFETY: `len` is writable and `os` is live.
        unsafe {
            *len = (*os).length as usize;
            return (*os).data;
        }
    }
    ptr::null()
}

/// `const unsigned char *EVP_PKEY_get0_siphash(const EVP_PKEY *pkey, size_t *len)` —
/// `crypto/evp/p_lib.c:869`.
///
/// # Safety
/// `pkey` must be live; `len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_siphash(
    pkey: *const EvpPkey,
    len: *mut usize,
) -> *const c_uchar {
    // SAFETY: `pkey` is live per the contract.
    if unsafe { (*pkey).type_ } != EVP_PKEY_SIPHASH {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_874) };
        return ptr::null();
    }
    // SAFETY: `pkey` is live, cast to the mutable form the accessor takes.
    let os = unsafe { evp_pkey_get_legacy(pkey as *mut EvpPkey) }.cast::<Asn1String>();
    if !os.is_null() {
        // SAFETY: `len` is writable and `os` is live.
        unsafe {
            *len = (*os).length as usize;
            return (*os).data;
        }
    }
    ptr::null()
}

/// `static DSA *evp_pkey_get0_DSA_int(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:887`.
///
/// # Safety
/// `pkey` must be live.
#[allow(non_snake_case)] // the authority's own internal name
unsafe fn evp_pkey_get0_DSA_int(pkey: *const EvpPkey) -> *mut Dsa {
    // SAFETY: `pkey` is live per the contract.
    if unsafe { (*pkey).type_ } != EVP_PKEY_DSA {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_890) };
        return ptr::null_mut();
    }
    // SAFETY: `pkey` is live, cast to the mutable form the accessor takes.
    unsafe { evp_pkey_get_legacy(pkey as *mut EvpPkey) }.cast::<Dsa>()
}

/// `const DSA *EVP_PKEY_get0_DSA(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:896`.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_DSA(pkey: *const EvpPkey) -> *const Dsa {
    // SAFETY: `pkey` is live per the contract.
    unsafe { evp_pkey_get0_DSA_int(pkey) }
}

/// `int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key)` — `crypto/evp/p_lib.c:901`.
///
/// # Safety
/// `pkey` must be live; `key` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_DSA(pkey: *mut EvpPkey, key: *mut Dsa) -> c_int {
    // SAFETY: `key` is live per the contract.
    if unsafe { DSA_up_ref(key) } == 0 {
        return 0;
    }
    // SAFETY: `pkey` and `key` are live.
    let ret = unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DSA, key.cast()) };
    if ret == 0 {
        // SAFETY: `key` is live; the reference taken above is released.
        unsafe { DSA_free(key) };
    }
    ret
}

/// `DSA *EVP_PKEY_get1_DSA(EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:915`.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get1_DSA(pkey: *mut EvpPkey) -> *mut Dsa {
    // SAFETY: `pkey` is live per the contract.
    let ret = unsafe { evp_pkey_get0_DSA_int(pkey) };
    // SAFETY: `ret` is non-NULL and therefore a live `DSA` per the accessor's contract.
    if !ret.is_null() && unsafe { DSA_up_ref(ret) } == 0 {
        return ptr::null_mut();
    }
    ret
}

/// `static const ECX_KEY *evp_pkey_get0_ECX_KEY(const EVP_PKEY *pkey, int type)` —
/// `crypto/evp/p_lib.c:926`.
///
/// The type test is `EVP_PKEY_get_base_id(pkey) != type`, **not** a direct `pkey->type`
/// comparison: an Ed25519 key carries `EVP_PKEY_ED25519` at both `type` and `save_type`, so the
/// two spellings agree here, but the authority writes the base-id form and this is it.
///
/// # Safety
/// `pkey` must be live.
#[allow(non_snake_case)] // the authority's own internal name
unsafe fn evp_pkey_get0_ECX_KEY(pkey: *const EvpPkey, type_: c_int) -> *const EcxKey {
    // SAFETY: `pkey` is live per the contract.
    if unsafe { EVP_PKEY_get_base_id(pkey) } != type_ {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_930) };
        return ptr::null();
    }
    // SAFETY: `pkey` is live, cast to the mutable form the accessor takes.
    unsafe { evp_pkey_get_legacy(pkey as *mut EvpPkey) }.cast::<EcxKey>()
}

/// `static ECX_KEY *evp_pkey_get1_ECX_KEY(EVP_PKEY *pkey, int type)` —
/// `crypto/evp/p_lib.c:935`.
///
/// # Safety
/// `pkey` must be live.
#[allow(non_snake_case)] // the authority's own internal name
unsafe fn evp_pkey_get1_ECX_KEY(pkey: *mut EvpPkey, type_: c_int) -> *mut EcxKey {
    // SAFETY: `pkey` is live per the contract.
    let mut ret = unsafe { evp_pkey_get0_ECX_KEY(pkey, type_) } as *mut EcxKey;
    // SAFETY: `ret` is NULL or live.
    if !ret.is_null() && unsafe { ossl_ecx_key_up_ref(ret) } == 0 {
        ret = ptr::null_mut();
    }
    ret
}

/// `ECX_KEY *ossl_evp_pkey_get1_X25519(EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:943`, the
/// `IMPLEMENT_ECX_VARIANT(X25519)` expansion.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn ossl_evp_pkey_get1_X25519(pkey: *mut EvpPkey) -> *mut EcxKey {
    // SAFETY: `pkey` is live per the contract.
    unsafe { evp_pkey_get1_ECX_KEY(pkey, EVP_PKEY_X25519) }
}

/// `ECX_KEY *ossl_evp_pkey_get1_X448(EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:944`, the
/// `IMPLEMENT_ECX_VARIANT(X448)` expansion.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn ossl_evp_pkey_get1_X448(pkey: *mut EvpPkey) -> *mut EcxKey {
    // SAFETY: `pkey` is live per the contract.
    unsafe { evp_pkey_get1_ECX_KEY(pkey, EVP_PKEY_X448) }
}

/// `ECX_KEY *ossl_evp_pkey_get1_ED25519(EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:945`, the
/// `IMPLEMENT_ECX_VARIANT(ED25519)` expansion.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn ossl_evp_pkey_get1_ED25519(pkey: *mut EvpPkey) -> *mut EcxKey {
    // SAFETY: `pkey` is live per the contract.
    unsafe { evp_pkey_get1_ECX_KEY(pkey, EVP_PKEY_ED25519) }
}

/// `ECX_KEY *ossl_evp_pkey_get1_ED448(EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:946`, the
/// `IMPLEMENT_ECX_VARIANT(ED448)` expansion.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn ossl_evp_pkey_get1_ED448(pkey: *mut EvpPkey) -> *mut EcxKey {
    // SAFETY: `pkey` is live per the contract.
    unsafe { evp_pkey_get1_ECX_KEY(pkey, EVP_PKEY_ED448) }
}

/// `DH *evp_pkey_get0_DH_int(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:998`.
///
/// # Safety
/// `pkey` must be live.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn evp_pkey_get0_DH_int(pkey: *const EvpPkey) -> *mut Dh {
    // SAFETY: `pkey` is live per the contract.
    let t = unsafe { (*pkey).type_ };
    if t != EVP_PKEY_DH && t != EVP_PKEY_DHX {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_1001) };
        return ptr::null_mut();
    }
    // SAFETY: `pkey` is live, cast to the mutable form the accessor takes.
    unsafe { evp_pkey_get_legacy(pkey as *mut EvpPkey) }.cast::<Dh>()
}

/// `const DH *EVP_PKEY_get0_DH(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:1007`.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_DH(pkey: *const EvpPkey) -> *const Dh {
    // SAFETY: `pkey` is live per the contract.
    unsafe { evp_pkey_get0_DH_int(pkey) }
}

/// `int EVP_PKEY_set1_DH(EVP_PKEY *pkey, DH *dhkey)` — `crypto/evp/p_lib.c:959`.
///
/// The type is chosen from the key: a named safe-prime group (ffdhe/modp) is `EVP_PKEY_DH`, and
/// otherwise a missing `q` is PKCS#3 `EVP_PKEY_DH` while a present `q` is X9.42 `EVP_PKEY_DHX`.
///
/// # Safety
/// `pkey` must be live; `dhkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_DH(pkey: *mut EvpPkey, dhkey: *mut Dh) -> c_int {
    // SAFETY: `dhkey` is live per the contract.
    let type_ = if unsafe { ossl_dh_is_named_safe_prime_group(dhkey) } != 0 {
        EVP_PKEY_DH
    } else {
        /* The authority spells this arm as a ternary; the nesting keeps its two outcomes
         * distinct, which a flat `else if` would collapse into one clippy reads as a copy. */
        // SAFETY: `dhkey` is live.
        if unsafe { DH_get0_q(dhkey) }.is_null() {
            EVP_PKEY_DH
        } else {
            EVP_PKEY_DHX
        }
    };

    // SAFETY: `dhkey` is live per the contract.
    if unsafe { DH_up_ref(dhkey) } == 0 {
        return 0;
    }
    // SAFETY: `pkey` and `dhkey` are live.
    let ret = unsafe { EVP_PKEY_assign(pkey, type_, dhkey.cast()) };
    if ret == 0 {
        // SAFETY: `dhkey` is live; the reference taken above is released.
        unsafe { DH_free(dhkey) };
    }
    ret
}

/// `DH *EVP_PKEY_get1_DH(EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:1012`.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get1_DH(pkey: *mut EvpPkey) -> *mut Dh {
    // SAFETY: `pkey` is live per the contract.
    let ret = unsafe { evp_pkey_get0_DH_int(pkey) };
    // SAFETY: `ret` is non-NULL and therefore a live `DH` per the accessor's contract.
    if !ret.is_null() && unsafe { DH_up_ref(ret) } == 0 {
        return ptr::null_mut();
    }
    ret
}

/// `int EVP_PKEY_get_ec_point_conv_form(const EVP_PKEY *pkey)` —
/// `crypto/evp/p_lib.c:2460`.
///
/// The provider path reads the `point-format` string parameter; the legacy path falls back to the
/// EC key's own conversion form. The legacy arm calls `EVP_PKEY_get0_EC_KEY`, which is
/// `crypto/evp/p_legacy.c`'s.
///
/// # Safety
/// `pkey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_ec_point_conv_form(pkey: *const EvpPkey) -> c_int {
    if pkey.is_null() {
        return 0;
    }
    // SAFETY: `pkey` is live per the contract.
    if unsafe { (*pkey).keymgmt.is_null() || (*pkey).keydata.is_null() } {
        /* Might work through the legacy route. */
        // SAFETY: `pkey` is live.
        let ec = unsafe { crate::evp::p_legacy_assign::EVP_PKEY_get0_EC_KEY(pkey) };
        if ec.is_null() {
            return 0;
        }
        // SAFETY: `ec` is a live EC key.
        return unsafe { EC_KEY_get_conv_form(ec) };
    }

    let mut name = [0 as c_char; 80];
    let mut name_len: usize = 0;
    // SAFETY: `name` is 80 writable bytes and the key holds the named string.
    if unsafe {
        EVP_PKEY_get_utf8_string_param(
            pkey,
            OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
            name.as_mut_ptr(),
            name.len(),
            &mut name_len,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `name` is NUL-terminated by the parameter reader.
    unsafe {
        if crate::runtime::bio::sys::strcmp(name.as_ptr(), c"uncompressed".as_ptr()) == 0 {
            return crate::ec::POINT_CONVERSION_UNCOMPRESSED;
        }
        if crate::runtime::bio::sys::strcmp(name.as_ptr(), c"compressed".as_ptr()) == 0 {
            return crate::ec::POINT_CONVERSION_COMPRESSED;
        }
        if crate::runtime::bio::sys::strcmp(name.as_ptr(), c"hybrid".as_ptr()) == 0 {
            return crate::ec::POINT_CONVERSION_HYBRID;
        }
    }
    0
}

/// `int EVP_PKEY_get_field_type(const EVP_PKEY *pkey)` — `crypto/evp/p_lib.c:2500`.
///
/// The provider path reads the `field-type` string parameter; the legacy path reads the EC key's
/// group. The legacy arm calls `EVP_PKEY_get0_EC_KEY`, which is `crypto/evp/p_legacy.c`'s.
///
/// # Safety
/// `pkey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_field_type(pkey: *const EvpPkey) -> c_int {
    if pkey.is_null() {
        return 0;
    }
    // SAFETY: `pkey` is live per the contract.
    if unsafe { (*pkey).keymgmt.is_null() || (*pkey).keydata.is_null() } {
        /* Might work through the legacy route. */
        // SAFETY: `pkey` is live.
        let ec = unsafe { crate::evp::p_legacy_assign::EVP_PKEY_get0_EC_KEY(pkey) };
        if ec.is_null() {
            return 0;
        }
        // SAFETY: `ec` is live.
        let grp = unsafe { EC_KEY_get0_group(ec) };
        if grp.is_null() {
            return 0;
        }
        // SAFETY: `grp` is live.
        return unsafe { EC_GROUP_get_field_type(grp) };
    }

    let mut fstr = [0 as c_char; 80];
    let mut fstrlen: usize = 0;
    // SAFETY: `fstr` is 80 writable bytes and the key holds the named string.
    if unsafe {
        EVP_PKEY_get_utf8_string_param(
            pkey,
            OSSL_PKEY_PARAM_EC_FIELD_TYPE,
            fstr.as_mut_ptr(),
            fstr.len(),
            &mut fstrlen,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `fstr` is NUL-terminated by the parameter reader.
    unsafe {
        /* `SN_X9_62_prime_field` and `SN_X9_62_characteristic_two_field` — `obj_mac.h`. The second
         * `strcmp`'s missing `== 0` is the authority's own: any string that is not `prime-field`
         * answers the two-field NID, including an unknown one. It is transcribed rather than
         * repaired, and that is the observable it produces. */
        if crate::runtime::bio::sys::strcmp(fstr.as_ptr(), c"prime-field".as_ptr()) == 0 {
            return NID_X9_62_prime_field;
        } else if crate::runtime::bio::sys::strcmp(
            fstr.as_ptr(),
            c"characteristic-two-field".as_ptr(),
        ) != 0
        {
            return NID_X9_62_characteristic_two_field;
        }
    }
    0
}

// ---------------------------------------------------------------------------------------------
// The printers (`crypto/evp/p_lib.c:1150-1293`)
// ---------------------------------------------------------------------------------------------

/// `EVP_PKEY_KEY_PARAMETERS` — `include/openssl/evp.h:106`, which expands to
/// `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS`, the union of the domain and other descriptors.
const EVP_PKEY_KEY_PARAMETERS: c_int =
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
/// `EVP_PKEY_PRIVATE_KEY` — `include/openssl/evp.h:108`, `KEY_PARAMETERS | SELECT_PRIVATE_KEY`.
const EVP_PKEY_PRIVATE_KEY: c_int = EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
/// `EVP_PKEY_PUBLIC_KEY` — `include/openssl/evp.h:110`, `KEY_PARAMETERS | SELECT_PUBLIC_KEY`.
const EVP_PKEY_PUBLIC_KEY: c_int = EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

/// `static int print_reset_indent(BIO **out, int pop_f_prefix, long saved_indent)` —
/// `crypto/evp/p_lib.c:1150-1160`.
///
/// Restores the saved indent and, when a prefix BIO was pushed on, pops and frees it. The
/// `BIO_set_indent` the authority spells is this crate's `BIO_ctrl` with `BIO_CTRL_SET_INDENT`,
/// which is what the header macro expands to.
///
/// # Safety
/// `out` must point at a live `BIO *`.
unsafe fn print_reset_indent(
    out: *mut *mut Bio,
    pop_f_prefix: c_int,
    saved_indent: c_long,
) -> c_int {
    // SAFETY: `out` points at a live `BIO *` per the contract.
    unsafe {
        BIO_ctrl(*out, BIO_CTRL_SET_INDENT, saved_indent, ptr::null_mut());
        if pop_f_prefix != 0 {
            let next = BIO_pop(*out);
            BIO_free(*out);
            *out = next;
        }
    }
    1
}

/// `static int print_set_indent(BIO **out, int *pop_f_prefix, long *saved_indent, long indent)` —
/// `crypto/evp/p_lib.c:1162-1185`.
///
/// A positive `indent` is saved, then set **twice**: when the sink refuses the first set a
/// `BIO_f_prefix` is pushed on and the set retried. The second attempt is what makes a plain memory
/// BIO take the indent through the prefix filter, and the authority's own comment on the first
/// attempt's failure path is why the prefix BIO exists at all.
///
/// # Safety
/// `out` must point at a live `BIO *`; `pop_f_prefix` and `saved_indent` must be writable.
unsafe fn print_set_indent(
    out: *mut *mut Bio,
    pop_f_prefix: *mut c_int,
    saved_indent: *mut c_long,
    indent: c_long,
) -> c_int {
    // SAFETY: the two out-parameters are writable and `out` points at a live `BIO *`.
    unsafe {
        *pop_f_prefix = 0;
        *saved_indent = 0;
        if indent > 0 {
            let i = BIO_ctrl(*out, BIO_CTRL_GET_INDENT, 0, ptr::null_mut());
            *saved_indent = if i < 0 { 0 } else { i };
            if BIO_ctrl(*out, BIO_CTRL_SET_INDENT, indent, ptr::null_mut()) <= 0 {
                let prefbio = BIO_new(BIO_f_prefix());
                if prefbio.is_null() {
                    return 0;
                }
                *out = BIO_push(prefbio, *out);
                *pop_f_prefix = 1;
            }
            if BIO_ctrl(*out, BIO_CTRL_SET_INDENT, indent, ptr::null_mut()) <= 0 {
                print_reset_indent(out, *pop_f_prefix, *saved_indent);
                return 0;
            }
        }
    }
    1
}

/// `static int unsup_alg(BIO *out, const EVP_PKEY *pkey, int indent, const char *kstr)` —
/// `crypto/evp/p_lib.c:1187-1194`.
///
/// The one line a key with neither an encoder nor a legacy print callback reaches: the indent, then
/// `"<kstr> algorithm \"<long name>\" unsupported"` with the key's own type's long name.
///
/// # Safety
/// `out` and `pkey` must be live; `kstr` NUL-terminated.
unsafe fn unsup_alg(
    out: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    kstr: *const c_char,
) -> c_int {
    // SAFETY: `out` and `pkey` are live, and `kstr` is a NUL-terminated static at both call sites.
    unsafe {
        c_int::from(
            BIO_indent(out, indent, 128) != 0
                && BIO_printf(
                    out,
                    c"%s algorithm \"%s\" unsupported\n".as_ptr(),
                    kstr,
                    OBJ_nid2ln((*pkey).type_),
                ) > 0,
        )
    }
}

/// `static int print_pkey(const EVP_PKEY *pkey, BIO *out, int indent, int selection,
/// const char *propquery, int (*legacy_print)(BIO *, const EVP_PKEY *, int, ASN1_PCTX *),
/// ASN1_PCTX *legacy_pctx)` — `crypto/evp/p_lib.c:1196-1229`.
///
/// **The encoder-first arm is the authority's, not a reduction.** The context is built and asked
/// for its encoder count, and only when that count is **0** — which is every key this crate can
/// build, because no provider encoder implementation is registered here — does `ret` stay `-2` and
/// the legacy branch run. `-2` is the authority's own "unsupported" default and the value that
/// decides the fall-through, so the printers reach `ameth->priv_print`/`params_print`/`pub_print`
/// **through this function's own code path**.
///
/// `propquery` is NULL from all six callers below, which is also what makes the `"TEXT"`/NULL
/// constructor arm the one taken.
///
/// # Safety
/// `pkey` must be live; `out` a live BIO; `propquery` NULL or NUL-terminated; `legacy_print` the
/// ameth's own callback, which must be a live function pointer.
unsafe fn print_pkey(
    pkey: *const EvpPkey,
    mut out: *mut Bio,
    indent: c_int,
    selection: c_int,
    propquery: *const c_char,
    legacy_print: Option<
        unsafe extern "C" fn(*mut Bio, *const EvpPkey, c_int, *mut Asn1Pctx) -> c_int,
    >,
    legacy_pctx: *mut Asn1Pctx,
) -> c_int {
    let mut pop_f_prefix: c_int = 0;
    let mut saved_indent: c_long = 0;
    /* The authority's sentinel: anything other than -2 means an arm above answered. */
    let mut ret = -2;

    // SAFETY: `out`'s address and both out-parameters are this frame's; `pkey` is live.
    if unsafe {
        print_set_indent(
            &mut out,
            &mut pop_f_prefix,
            &mut saved_indent,
            indent as c_long,
        )
    } == 0
    {
        return 0;
    }

    // SAFETY: `pkey` is live, `"TEXT"` is a static, and `propquery` is NULL or NUL-terminated.
    let ctx = unsafe {
        OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, c"TEXT".as_ptr(), ptr::null(), propquery)
    };
    // SAFETY: `ctx` is NULL or a live context, and the count answers 0 for NULL.
    if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } != 0 {
        // SAFETY: `ctx` is live and `out` is the caller's BIO.
        ret = unsafe { OSSL_ENCODER_to_bio(ctx, out) };
    }
    // SAFETY: `ctx` is NULL or live, and this call owns the reference the constructor took.
    unsafe { OSSL_ENCODER_CTX_free(ctx) };

    if ret != -2 {
        // SAFETY: `out` is live and both out-parameters are this frame's.
        unsafe { print_reset_indent(&mut out, pop_f_prefix, saved_indent) };
        return ret;
    }

    /* legacy fallback */
    if let Some(legacy_print) = legacy_print {
        // SAFETY: `legacy_print` is the ameth's own callback, and `out`/`pkey` are live.
        ret = unsafe { legacy_print(out, pkey, 0, legacy_pctx) };
    } else {
        // SAFETY: `out` and `pkey` are live; the string is a static.
        ret = unsafe { unsup_alg(out, pkey, 0, c"Public Key".as_ptr()) };
    }

    // SAFETY: `out` is live and both out-parameters are this frame's.
    unsafe { print_reset_indent(&mut out, pop_f_prefix, saved_indent) };
    ret
}

/// `int EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)` —
/// `crypto/evp/p_lib.c:1231-1236`.
///
/// The `EVP_PKEY_PUBLIC_KEY` selection and the ameth's `pub_print`.
///
/// # Safety
/// `out` and `pkey` must be live; `pctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_print_public(
    out: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    pctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live; the ameth pointer is NULL or live and its callback field is copied out.
    let legacy_print = unsafe {
        if (*pkey).ameth.is_null() {
            None
        } else {
            (*((*pkey).ameth)).pub_print
        }
    };
    // SAFETY: every argument's preconditions are the caller's, checked above or by the contract.
    unsafe {
        print_pkey(
            pkey,
            out,
            indent,
            EVP_PKEY_PUBLIC_KEY,
            ptr::null(),
            legacy_print,
            pctx,
        )
    }
}

/// `int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)` —
/// `crypto/evp/p_lib.c:1238-1243`.
///
/// The `EVP_PKEY_PRIVATE_KEY` selection and the ameth's `priv_print`.
///
/// # Safety
/// `out` and `pkey` must be live; `pctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_print_private(
    out: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    pctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live; the ameth pointer is NULL or live and its callback field is copied out.
    let legacy_print = unsafe {
        if (*pkey).ameth.is_null() {
            None
        } else {
            (*((*pkey).ameth)).priv_print
        }
    };
    // SAFETY: every argument's preconditions are the caller's, checked above or by the contract.
    unsafe {
        print_pkey(
            pkey,
            out,
            indent,
            EVP_PKEY_PRIVATE_KEY,
            ptr::null(),
            legacy_print,
            pctx,
        )
    }
}

/// `int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)` —
/// `crypto/evp/p_lib.c:1245-1250`.
///
/// The `EVP_PKEY_KEY_PARAMETERS` selection and the ameth's `param_print`.
///
/// # Safety
/// `out` and `pkey` must be live; `pctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_print_params(
    out: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    pctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `pkey` is live; the ameth pointer is NULL or live and its callback field is copied out.
    let legacy_print = unsafe {
        if (*pkey).ameth.is_null() {
            None
        } else {
            (*((*pkey).ameth)).param_print
        }
    };
    // SAFETY: every argument's preconditions are the caller's, checked above or by the contract.
    unsafe {
        print_pkey(
            pkey,
            out,
            indent,
            EVP_PKEY_KEY_PARAMETERS,
            ptr::null(),
            legacy_print,
            pctx,
        )
    }
}

/// `int EVP_PKEY_print_public_fp(FILE *fp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)` —
/// `crypto/evp/p_lib.c:1253-1264`.
///
/// A `FILE` BIO with `BIO_NOCLOSE` around `EVP_PKEY_print_public`; the caller's `FILE` is left open.
///
/// # Safety
/// `fp` must be a live `FILE *`; `pkey` live; `pctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_print_public_fp(
    fp: *mut c_void,
    pkey: *const EvpPkey,
    indent: c_int,
    pctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `fp` is a live `FILE *` per the contract.
    let b = unsafe { BIO_new_fp(fp, BIO_NOCLOSE) };
    if b.is_null() {
        return 0;
    }
    // SAFETY: `b` is a live BIO and `pkey` is live.
    let ret = unsafe { EVP_PKEY_print_public(b, pkey, indent, pctx) };
    // SAFETY: `b` is this frame's own BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `int EVP_PKEY_print_private_fp(FILE *fp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)` —
/// `crypto/evp/p_lib.c:1266-1277`.
///
/// # Safety
/// `fp` must be a live `FILE *`; `pkey` live; `pctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_print_private_fp(
    fp: *mut c_void,
    pkey: *const EvpPkey,
    indent: c_int,
    pctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `fp` is a live `FILE *` per the contract.
    let b = unsafe { BIO_new_fp(fp, BIO_NOCLOSE) };
    if b.is_null() {
        return 0;
    }
    // SAFETY: `b` is a live BIO and `pkey` is live.
    let ret = unsafe { EVP_PKEY_print_private(b, pkey, indent, pctx) };
    // SAFETY: `b` is this frame's own BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `int EVP_PKEY_print_params_fp(FILE *fp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)` —
/// `crypto/evp/p_lib.c:1279-1290`.
///
/// # Safety
/// `fp` must be a live `FILE *`; `pkey` live; `pctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_print_params_fp(
    fp: *mut c_void,
    pkey: *const EvpPkey,
    indent: c_int,
    pctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: `fp` is a live `FILE *` per the contract.
    let b = unsafe { BIO_new_fp(fp, BIO_NOCLOSE) };
    if b.is_null() {
        return 0;
    }
    // SAFETY: `b` is a live BIO and `pkey` is live.
    let ret = unsafe { EVP_PKEY_print_params(b, pkey, indent, pctx) };
    // SAFETY: `b` is this frame's own BIO.
    unsafe { BIO_free(b) };
    ret
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;

    /// `EVP_PKEY_get_params` and `EVP_PKEY_set_params` refuse a **blank** key, and the refusal is the
    /// same `EVP_R_INVALID_KEY` a NULL key gets -- because the authority's legacy arm is `#if 0`, so a
    /// key with no provider method has nothing to delegate to. Both leave one error on the queue,
    /// which is the observation.
    #[test]
    fn the_parameter_delegations_refuse_a_key_with_no_method() {
        // SAFETY: no preconditions.
        let pkey = unsafe { EVP_PKEY_new() };
        assert!(!pkey.is_null());
        let mut params = [crate::params::END; 2];

        // SAFETY: `pkey` is this test's own blank key and `params` is a terminated array.
        unsafe {
            assert_eq!(EVP_PKEY_get_params(pkey, params.as_mut_ptr()), 0);
            assert_ne!(
                crate::runtime::err::ERR_peek_error(),
                0,
                "the refusal raises"
            );
            crate::runtime::err::ERR_clear_error();
            assert_eq!(EVP_PKEY_set_params(pkey, params.as_mut_ptr()), 0);
            assert_ne!(crate::runtime::err::ERR_peek_error(), 0);
            crate::runtime::err::ERR_clear_error();

            /* A NULL key takes the same arm and therefore raises the same error. */
            assert_eq!(EVP_PKEY_get_params(ptr::null(), params.as_mut_ptr()), 0);
            crate::runtime::err::ERR_clear_error();
            assert_eq!(EVP_PKEY_set_params(ptr::null_mut(), params.as_mut_ptr()), 0);
            crate::runtime::err::ERR_clear_error();

            EVP_PKEY_free(pkey);
        }
    }

    /// The two descriptor accessors answer NULL for a NULL key **and** for a blank one, because both
    /// are tested with `keymgmt != NULL` rather than with a state flag. A single NULL is the point:
    /// there is no third answer.
    #[test]
    fn the_descriptor_accessors_answer_null_without_a_method() {
        // SAFETY: no preconditions.
        let pkey = unsafe { EVP_PKEY_new() };
        assert!(!pkey.is_null());
        // SAFETY: `pkey` is this test's own blank key; NULL is the other documented input.
        unsafe {
            assert!(EVP_PKEY_gettable_params(pkey).is_null());
            assert!(EVP_PKEY_settable_params(pkey).is_null());
            assert!(EVP_PKEY_gettable_params(ptr::null()).is_null());
            assert!(EVP_PKEY_settable_params(ptr::null()).is_null());
            EVP_PKEY_free(pkey);
        }
    }

    /// The four answers `EVP_PKEY_eq` can give, without a provider: identity is **1** even for a blank
    /// key, a NULL against anything else is **0**, and two blank keys reach `evp_pkey_cmp_any`'s
    /// assertion arm and answer **-2** -- unsupported, not equal, and not different.
    #[test]
    fn equality_answers_its_four_values() {
        // SAFETY: no preconditions.
        let a = unsafe { EVP_PKEY_new() };
        // SAFETY: no preconditions.
        let b = unsafe { EVP_PKEY_new() };
        assert!(!a.is_null() && !b.is_null());

        // SAFETY: both keys are this test's own, and NULL is the other documented input.
        unsafe {
            assert_eq!(
                EVP_PKEY_eq(a, a),
                1,
                "identity, without asking anything of the key"
            );
            assert_eq!(
                EVP_PKEY_eq(ptr::null(), ptr::null()),
                1,
                "the same test, both NULL"
            );
            assert_eq!(
                EVP_PKEY_eq(a, ptr::null()),
                0,
                "NULL against a key is a difference"
            );
            assert_eq!(EVP_PKEY_eq(ptr::null(), b), 0);
            assert_eq!(
                EVP_PKEY_eq(a, b),
                -2,
                "two blank keys are unsupported, not equal"
            );
            assert_eq!(EVP_PKEY_parameters_eq(a, b), -2);
            crate::runtime::err::ERR_clear_error();

            /* The deprecated spellings are the same functions, and that is the whole claim. */
            assert_eq!(EVP_PKEY_cmp(a, b), EVP_PKEY_eq(a, b));
            assert_eq!(EVP_PKEY_cmp_parameters(a, b), EVP_PKEY_parameters_eq(a, b));
            crate::runtime::err::ERR_clear_error();

            EVP_PKEY_free(a);
            EVP_PKEY_free(b);
        }
    }

    /// `EVP_PKEY_get_bn_param`'s two NULL guards come **before** anything is allocated or read, so
    /// each answers 0 with the error queue untouched -- unlike the delegations above, this is a silent
    /// refusal and the distinction is the contract.
    #[test]
    fn the_bn_reader_refuses_its_two_null_arguments_silently() {
        // SAFETY: no preconditions.
        let pkey = unsafe { EVP_PKEY_new() };
        assert!(!pkey.is_null());
        let mut out: *mut BigNum = ptr::null_mut();

        // SAFETY: `pkey` is this test's own key; the NULLs are the documented refusals.
        unsafe {
            assert_eq!(
                EVP_PKEY_get_bn_param(pkey, ptr::null(), ptr::addr_of_mut!(out)),
                0
            );
            assert_eq!(
                crate::runtime::err::ERR_peek_error(),
                0,
                "no error for a NULL name"
            );
            assert_eq!(
                EVP_PKEY_get_bn_param(pkey, c"n".as_ptr(), ptr::null_mut()),
                0
            );
            assert_eq!(
                crate::runtime::err::ERR_peek_error(),
                0,
                "no error for a NULL out"
            );
            EVP_PKEY_free(pkey);
        }
    }

    /// A new key's four cached properties are zero, and `EVP_PKEY_get_size` **raises** rather than
    /// answering a silent zero when the size is not positive -- which is also the answer for a NULL
    /// key, and the two are indistinguishable by the return value alone.
    #[test]
    fn a_size_of_zero_is_a_reported_failure() {
        // SAFETY: no preconditions.
        let pkey = unsafe { EVP_PKEY_new() };
        assert!(!pkey.is_null());
        // SAFETY: `pkey` is this test's own key; NULL is the other documented input.
        unsafe {
            assert_eq!(EVP_PKEY_get_size(pkey), 0);
            assert_ne!(crate::runtime::err::ERR_peek_error(), 0);
            crate::runtime::err::ERR_clear_error();
            assert_eq!(EVP_PKEY_get_size(ptr::null()), 0);
            assert_ne!(crate::runtime::err::ERR_peek_error(), 0);
            crate::runtime::err::ERR_clear_error();
            EVP_PKEY_free(pkey);
        }
    }
    #[test]
    fn the_twelve_standard_names_resolve_case_insensitively() {
        // SAFETY: every argument is a NUL-terminated constant.
        unsafe {
            assert_eq!(evp_pkey_name2type(c"RSA".as_ptr()), NID_rsaEncryption);
            assert_eq!(evp_pkey_name2type(c"rsa".as_ptr()), NID_rsaEncryption);
            assert_eq!(evp_pkey_name2type(c"Rsa".as_ptr()), NID_rsaEncryption);
            assert_eq!(evp_pkey_name2type(c"RSA-PSS".as_ptr()), NID_rsassaPss);
            assert_eq!(evp_pkey_name2type(c"EC".as_ptr()), NID_X9_62_id_ecPublicKey);
            assert_eq!(evp_pkey_name2type(c"ED25519".as_ptr()), NID_ED25519);
            assert_eq!(evp_pkey_name2type(c"ED448".as_ptr()), NID_ED448);
            assert_eq!(evp_pkey_name2type(c"X25519".as_ptr()), NID_X25519);
            assert_eq!(evp_pkey_name2type(c"X448".as_ptr()), NID_X448);
            assert_eq!(evp_pkey_name2type(c"SM2".as_ptr()), NID_sm2);
            assert_eq!(evp_pkey_name2type(c"DH".as_ptr()), NID_dhKeyAgreement);
            assert_eq!(evp_pkey_name2type(c"DSA".as_ptr()), NID_dsa);
        }
    }

    /// `DHX` has **two** spellings and both answer the same NID — and `type2name` answers the
    /// *first* of them, which is the observation that makes the duplicate row load-bearing rather
    /// than untidy.
    #[test]
    fn the_dhx_nid_has_two_spellings_and_one_inverse() {
        // SAFETY: both arguments are NUL-terminated constants.
        unsafe {
            assert_eq!(evp_pkey_name2type(c"DHX".as_ptr()), NID_dhpublicnumber);
            assert_eq!(evp_pkey_name2type(c"X9.42 DH".as_ptr()), NID_dhpublicnumber);
        }
        assert_eq!(
            // SAFETY: the answer is a NUL-terminated constant of this crate.
            unsafe { CStr::from_ptr(evp_pkey_type2name(NID_dhpublicnumber)) },
            c"X9.42 DH",
            "the first matching row wins, so DHX answers the long spelling"
        );
    }

    /// The inverse answers the table's own spelling for a table NID and the object table's short
    /// name for anything else — the half of the pair that does not need Phase 8.
    #[test]
    fn the_inverse_answers_a_name_for_every_nid() {
        // SAFETY: the answers are NUL-terminated strings owned by this crate or the object table.
        unsafe {
            assert_eq!(CStr::from_ptr(evp_pkey_type2name(NID_ED25519)), c"ED25519");
            assert_eq!(CStr::from_ptr(evp_pkey_type2name(NID_X448)), c"X448");
            assert_eq!(
                CStr::from_ptr(evp_pkey_type2name(NID_rsassaPss)),
                c"RSA-PSS"
            );
            assert_eq!(CStr::from_ptr(evp_pkey_type2name(NID_undef)), c"UNDEF");
        }
    }

    /// The documented gap, asserted so that its size is a test rather than a claim: a name outside
    /// the twelve answers `NID_undef` today and will answer a NID once Phase 8 lands.
    #[test]
    fn a_name_outside_the_table_is_the_phase_8_gap() {
        // SAFETY: the argument is a NUL-terminated constant.
        let unknown = unsafe { evp_pkey_name2type(c"openssl-rs-not-a-key-type".as_ptr()) };
        assert_eq!(unknown, NID_undef);
    }
}
