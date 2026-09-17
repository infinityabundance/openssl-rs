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

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::bn::bignum::BigNum;
use crate::evp::keymgmt::{
    EVP_KEYMGMT_free, EVP_KEYMGMT_get0_name, EVP_KEYMGMT_get0_provider, EVP_KEYMGMT_is_a,
    EVP_KEYMGMT_names_do_all, EVP_KEYMGMT_up_ref, EvpKeyMgmt,
};
use crate::evp::keymgmt_lib::{evp_keymgmt_util_clear_operation_cache, evp_keymgmt_util_export};
use crate::evp::pkey_asn1::EvpPkeyAsn1Method;
use crate::params::{OSSL_PARAM_get_octet_string, OSSL_PARAM_locate_const, OsslParam};
use crate::provider::OsslProvider;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::ex_data::{
    CRYPTO_dup_ex_data, CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data,
    CRYPTO_set_ex_data, CryptoExData, CRYPTO_EX_INDEX_EVP_PKEY,
};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::{
    NID_X9_62_id_ecPublicKey, NID_dhKeyAgreement, NID_dhpublicnumber, NID_dsa, NID_rsaEncryption,
    NID_rsassaPss, NID_sm2, NID_undef, OBJ_ln2nid, OBJ_nid2sn, OBJ_sn2nid, NID_ED25519, NID_ED448,
    NID_X25519, NID_X448,
};
use crate::runtime::thread::{CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CryptoRwlock};

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

/// `struct evp_pkey_st` — the provider block and the block both halves share.
///
/// **Most of the legacy block is deliberately absent**, and the part that is present is `ameth`.
/// `EVP_PKEY_ASN1_METHOD` is this stratum's type — D176: the accessors are declared in `evp.h`, so
/// the ownership atlas assigns them to Phase 7, and `src/evp/pkey_asn1.rs` defines the struct — so
/// the field is typed rather than a placeholder, which is what `EVP_PKEY_get0_asn1` needs. Still
/// absent: `engine`, `pmeth_engine`, the `pkey` / `legacy_cache_pkey` union and `attributes`,
/// because `ENGINE` is Phase 13's and `X509_ATTRIBUTE_free` is Phase 12's. The effect is exactly one
/// state this crate cannot enter — `keymgmt == NULL` with `type_ != EVP_PKEY_NONE`, a *legacy origin
/// key* — which is why every provider-path function below tests `keymgmt` rather than a state flag,
/// and why the functions that have a legacy arm in the authority record that arm as absent at the
/// site.
///
/// `attributes` is absent for the same reason: it is a `STACK_OF(X509_ATTRIBUTE)` whose element
/// destructor is `X509_ATTRIBUTE_free`, a Phase 12 symbol. Nothing in this crate can make it
/// non-NULL — no `p_lib.c` function sets it, and the `EVP_PKEY_add1_attr` family is `crypto/x509/`'s —
/// so `EVP_PKEY_free` has no branch to omit, only a field to name.
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
    /// **Nothing in this crate sets it.** `pkey_set_type` is the authority's only writer and its
    /// lookup is `EVP_PKEY_asn1_find_str`, whose `standard_methods[]` is empty, so it answers NULL for
    /// every legacy type; the register carries that as `D-PKEY-AMETH-1`. Declaring the field and
    /// landing `EVP_PKEY_get0_asn1` against it makes the accessor answer what the authority answers
    /// for every key this crate can build, and an accessor that synthesised NULL from nowhere would
    /// be a different function.
    pub(crate) ameth: *mut EvpPkeyAsn1Method,
    /// `CRYPTO_REF_COUNT references`.
    pub(crate) references: AtomicI32,
    /// `CRYPTO_RWLOCK *lock` — guards the operation cache and the dirty counters.
    pub(crate) lock: *mut CryptoRwlock,
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
/// **The body is empty here, and that is a transcription rather than an omission.** Every statement
/// the authority's function has is `ameth` or `ENGINE` work:
///
/// ```c
/// const EVP_PKEY_ASN1_METHOD *ameth = x->ameth;
/// if (ameth == NULL && x->legacy_cache_pkey.ptr != NULL)
///     ameth = EVP_PKEY_asn1_find(&tmpe, x->type);
/// if (ameth != NULL) { ...; ameth->pkey_free(x); }
/// ENGINE_finish(tmpe); ENGINE_finish(x->engine); ...
/// ```
///
/// `EVP_PKEY_ASN1_METHOD` and `EVP_PKEY_asn1_find` are Phase 8's (D163, D165), `ENGINE` is Phase
/// 13's, and this crate has neither an `ameth` nor an `engine` field — so `ameth` is NULL on entry,
/// the block it guards is skipped, and the four `ENGINE_finish` calls are each handed a NULL. The
/// function is called where the authority calls it (the success path of `EVP_PKEY_generate`, whose
/// `#if` guard does **not** remove it in this build, D172) so that the site reads as the authority's
/// and so that the day Phase 8 lands, the body is the authority's.
///
/// # Safety
/// `x` must be NULL or a live `EvpPkey`.
#[allow(dead_code)] // first live caller is `EVP_PKEY_generate` in `pmeth_gn.rs`
pub(crate) unsafe fn evp_pkey_free_legacy(x: *mut EvpPkey) {
    /* Nothing to release without an `EVP_PKEY_ASN1_METHOD` or an `ENGINE`. The parameter is named
     * rather than elided because the contract above is about it. */
    let _ = x;
}

/// `void EVP_PKEY_free(EVP_PKEY *x)`.
///
/// `EVP_PKEY_free` has no legacy `pkey->ameth->pkey_free` for now, but is otherwise complete.
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
/// The provider path only, and the two clauses that would find an `EVP_PKEY_ASN1_METHOD` are absent
/// — `EVP_PKEY_asn1_find_str` and `EVP_PKEY_asn1_find` are `ameth_lib.c`'s and search a table of
/// Phase 8's objects (`docs/DECISIONS.md` D163/D165), and `ENGINE` is Phase 13's. What that costs is
/// one observable, and it is recorded as `D-PKEY-AMETH-1`: with `ameth` always NULL the last block
/// takes its `else` arm, so a provider key reports `EVP_PKEY_KEYMGMT` from `EVP_PKEY_get_id` where
/// the authority reports the *legacy* NID for any name that has a legacy method — `EVP_PKEY_RSA`
/// for a key type named `"RSA"`.
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
/// `pkey` must be NULL or live; `keymgmt` must be NULL or live.
unsafe fn pkey_set_type(pkey: *mut EvpPkey, type_: c_int, keymgmt: *mut EvpKeyMgmt) -> c_int {
    if !pkey.is_null() {
        // SAFETY: `pkey` is live.
        let free_it = unsafe { !(*pkey).keydata.is_null() };
        if free_it {
            // SAFETY: `pkey` is live.
            unsafe { evp_pkey_free_it(pkey) };
        }
    }

    /* The authority's `check`, not its opening `ossl_assert` guard: `ameth == NULL && keymgmt ==
     * NULL` refuses with `EVP_R_UNSUPPORTED_ALGORITHM`. This crate's `ameth` is always NULL --
     * `EVP_PKEY_asn1_find_str` and `EVP_PKEY_asn1_find` are Phase 8's (D163, D165) -- so the pair
     * collapses to `keymgmt == NULL`, which is exactly this test. The guard above it refuses with
     * `ERR_R_INTERNAL_ERROR` and is unreachable here; see this function's doc comment (D167). */
    if keymgmt.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LIB_1601) };
        return 0;
    }

    if !pkey.is_null() {
        // SAFETY: `keymgmt` is live and this takes the key's own reference to it.
        if unsafe { EVP_KEYMGMT_up_ref(keymgmt) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::P_LIB_1607) };
            return 0;
        }

        // SAFETY: `pkey` is live.
        unsafe {
            (*pkey).keymgmt = keymgmt;
            (*pkey).save_type = type_;
            (*pkey).type_ = type_;
            /* The authority's `else` arm: no ameth was found, so the type is the pseudo-NID that
             * says "this key has a provider method and no legacy implementation". See the note
             * above -- this is D-PKEY-AMETH-1's site, and the `if (ameth != NULL)` arm it replaces
             * is Phase 8's. */
            (*pkey).type_ = EVP_PKEY_KEYMGMT;
        }
    }
    1
}

/// `int evp_pkey_set_type_by_keymgmt(EVP_PKEY *pkey, EVP_KEYMGMT *keymgmt)` — the internal name the
/// unit exports to `keymgmt_lib.c`.
///
/// # Safety
/// `pkey` must be live; `keymgmt` must be live.
pub(crate) unsafe fn evp_pkey_set_type_by_keymgmt(
    pkey: *mut EvpPkey,
    keymgmt: *mut EvpKeyMgmt,
) -> c_int {
    // SAFETY: `pkey` is live and `keymgmt` is live.
    unsafe { pkey_set_type(pkey, EVP_PKEY_NONE, keymgmt) }
}

/// `int EVP_PKEY_set_type_by_keymgmt(EVP_PKEY *pkey, EVP_KEYMGMT *keymgmt)`.
///
/// The public entry point, and the asymmetry between it and its sibling above is the whole of 7.4a's
/// ameth gap in one function: the authority first walks the method's **names** looking for one that
/// an `EVP_PKEY_ASN1_METHOD` exists for, refuses if it finds two, and passes the one it found on. The
/// walk is here and the lookup is Phase 8's, so `str[0]` is always NULL and `pkey_set_type`'s ameth
/// argument is always NULL. **The walk is written rather than omitted** so that the day Phase 8 lands,
/// the only change is the loop body — and because the walk is what makes the *ambiguity* refusal
/// reachable, which is a behaviour the crate does own.
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
    unsafe { pkey_set_type(pkey, EVP_PKEY_NONE, keymgmt) }
}

/// `static void find_ameth(const char *name, void *data)` — the visitor `find_ameth` is named after
/// above: it records at most **two** names, and the second is what makes an ambiguous match a
/// refusal rather than a choice.
///
/// The authority's body calls `pkey_set_type(NULL, NULL, EVP_PKEY_NONE, name, strlen(name), NULL)`
/// purely to ask whether an ameth exists, wrapped in `ERR_set_mark`/`ERR_pop_to_mark` because "the
/// error messages from `pkey_set_type()` are uninteresting here, and misleading". With the ameth
/// lookup absent the question has no answer, so the visitor records **nothing** — which makes every
/// `EVP_PKEY_set_type_by_keymgmt` call agree with `found[1] == NULL` and reach `pkey_set_type`. Its
/// mark/pop pair is kept because it is what a Phase-8 fill needs, and because leaving it out would
/// make the fill's diff larger than the fill.
///
/// # Safety
/// `data` must point at a two-element array of `const char *`; `name` must be NUL-terminated.
unsafe extern "C" fn find_ameth(_name: *const c_char, data: *mut c_void) {
    crate::runtime::err::ERR_set_mark();
    /* Phase 8: `pkey_set_type(NULL, NULL, EVP_PKEY_NONE, name, strlen(name), NULL)` and the two
     * `str[i] == NULL` stores. See this function's doc comment. */
    let _ = data;
    crate::runtime::err::ERR_pop_to_mark();
}

/// `int EVP_PKEY_get_id(const EVP_PKEY *pkey)`.
///
/// A field read, and the field is the interesting part: for a provider key it is
/// `EVP_PKEY_KEYMGMT` unless an ameth was found for one of the method's names, which is Phase 8's
/// and is recorded as `D-PKEY-AMETH-1`.
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
/// (`DOMAIN_PARAMETERS | OTHER_PARAMETERS`).
const OSSL_KEYMGMT_SELECT_ALL: c_int = (0x01 | 0x02) | (0x04 | 0x80);

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
/// `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS` is deliberately not in it.
const SELECT_PARAMETERS: c_int = 0x04;
/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `OSSL_KEYMGMT_SELECT_PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
/// `OSSL_PKEY_PARAM_PRIV_KEY` — `include/openssl/core_names.h`, the generated one.
const OSSL_PKEY_PARAM_PRIV_KEY: *const c_char = c"priv".as_ptr();
/// `OSSL_PKEY_PARAM_PUB_KEY` — the same header and the same note.
const OSSL_PKEY_PARAM_PUB_KEY: *const c_char = c"pub".as_ptr();
/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `PRIVATE_KEY | PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int = 0x01 | 0x02;

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
/// Parameters only, and the **first** thing it does is decide whether either key is provider-side: if
/// so it defers to `evp_pkey_cmp_any`, and if neither is, it compares legacy NIDs directly and then
/// the ameth's `param_cmp` — Phase 8's, and unreachable here because neither key can be legacy.
///
/// # Safety
/// `a` and `b` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_parameters_eq(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    // SAFETY: both keys are live per the contract.
    if unsafe { !(*a).keymgmt.is_null() || !(*b).keymgmt.is_null() } {
        // SAFETY: both keys are live.
        return unsafe { evp_pkey_cmp_any(a, b, SELECT_PARAMETERS) };
    }
    /* All legacy keys: Phase 8's `a->ameth->param_cmp`, unreachable here. */
    // SAFETY: both keys are live.
    if unsafe { (*a).type_ != (*b).type_ } {
        return -1;
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
        let mut selection = SELECT_PARAMETERS;

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
