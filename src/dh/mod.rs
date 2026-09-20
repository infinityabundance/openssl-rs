//! `crypto/dh/` — the `DH` object, its method table and its key layer, Phase 8.5.
//!
//! This module is Phase 8.5's, and like Phase 8.4's `src/rsa/mod.rs` it is being built in the
//! slices the ledger's labels separate rather than all at once, because the block is ninety-seven
//! labels and its parts have different prerequisites. **The method table is LANDED (D329)**: the
//! twenty-one `DH_meth_*` labels of `crypto/dh/dh_meth.c` are the first slice because they are
//! the one part of the block whose bodies allocate a table, store a pointer in it, or read one
//! back, and therefore the one part with no cryptographic callee at all. **The object layer, the
//! key layer, the generator and the validators are LANDED (D331)**: `crypto/dh/dh_lib.c`,
//! `dh_key.c`, `dh_gen.c`, `dh_check.c` and `dh_depr.c` are this module's `object`, `key`, `gen`,
//! `check` and `depr` children, and [`Dh`] below is the object's real shape rather than the
//! forward declaration D329 left.
//!
//! **Why the method table was first, and why it was not the plan's first item.** `docs/PHASE-8-
//! SUBPHASES.md` orders 8.5's landing as the FFC primitives, then the object layer, then the key
//! generation and agreement, then the parameter generation, then the controls. The method table
//! is *reachable from none of those* and blocks none of them: `dh_meth.c` is twenty-one
//! allocation-and-store entry points that read only `DH_METHOD`'s own shape. It is landed first
//! because it is the only slice whose prerequisites are already in, which is the same reading —
//! and the same precedent — as 8.4's slice B (D284): the object's shape had to be transcribed
//! there anyway, and the method table was the one slice that did not also need the crypt layer.
//!
//! **The object layer and the key layer landed together, and that is the cycle D329 measured.**
//! `dh_new_intern` (`crypto/dh/dh_lib.c:95`) reads `DH_get_default_method()`, whose
//! `default_DH_method` is `&dh_ossl` — and `dh_ossl` is `crypto/dh/dh_key.c:165-175`. So neither
//! can precede the other. `DH_get_default_method`, `DH_set_default_method` and `DH_OpenSSL` are
//! therefore in [`key`] beside the table they name, and the object's constructor reads them.
//!
//! **What is still not here, named rather than implied.** `crypto/dh/dh_group_params.c` is the
//! named-group unit — `DH_get_nid`, `DH_new_by_nid` and `ossl_dh_cache_named_group` — and it
//! waits with `crypto/bn/bn_dh.c`'s twenty-six constants and `ffc_dh.c`'s `dh_named_groups[]`,
//! which D329/D330 left as one separable large data transcription; the three sites in this slice
//! that call `DH_get_nid` and the one that calls the cache are written as the `params.nid` read
//! they reduce to, and each says so.
//! `dh_asn1.c`'s `d2i_`/`i2d_DHparams` and the `DHparams_*` family are 8.8's ASN.1 machinery,
//! `DH_KDF_X9_42` (`dh_kdf.c`) fetches an `OSSL_KDF` name from a provider, and the
//! `EVP_PKEY_CTX_*dh*` controls of `crypto/evp/dh_ctrl.c` are 8.5's slice E. Everything that is
//! here is a transcription: no stub, no `todo!()`, and no fabricated value.
//!
//! ## `DH_METHOD` is 72 bytes with nine members, and the shape is the whole contract
//!
//! `struct dh_method` (`crypto/dh/dh_local.h:47-64`) is declared in `dh_local.h` and is opaque in
//! `crypto/dh/dh_local.h:47-64`) is declared in `dh_local.h` and is opaque in
//! the installed header, so nothing a consumer can compile names its fields. It is still a real
//! layout: `DH_meth_dup` copies it with one `memcpy` of `sizeof(*dhm)`, `DH_meth_free` releases
//! `name` **before** the table, and each of the twenty-one entry points reads or writes exactly
//! one member. The numbers below are `courts/layout/measure-dh-method.c`'s, and the offsets are
//! asserted in the unit tests rather than only the size, because the two spellings of a wrong
//! order are different bugs — a swap of `init` and `finish` keeps the size and moves two calls.
//!
//! ```text
//! name              0     char *name
//! generate_key      8     int (*generate_key)(DH *)
//! compute_key      16     int (*compute_key)(unsigned char *, const BIGNUM *, DH *)
//! bn_mod_exp       24     int (*bn_mod_exp)(const DH *, BIGNUM *, const BIGNUM *, const BIGNUM *,
//!                                              const BIGNUM *, BN_CTX *, BN_MONT_CTX *)
//! init             32     int (*init)(DH *)
//! finish           40     int (*finish)(DH *)
//! flags            48     int flags
//! (padding)        52
//! app_data         56     char *app_data
//! generate_params  64     int (*generate_params)(DH *, int, int, BN_GENCB *)
//! ```
//!
//! `flags` is a four-byte `int` at 48 and `app_data` is a pointer at 56, so the four bytes at
//! 52..56 are padding and the two are **not** adjacent in the way the declaration order suggests.
//! A transcription that made `flags` pointer-sized would be eight bytes too wide and would move
//! `generate_params` to 72.
//!
//! ## The three function-pointer member pairs are `Option`s, and the two lifecycle ones are the
//! reason
//!
//! `DH_meth_new` zero-allocates the table, so every member starts NULL, and `DH_meth_get_*`
//! answers exactly what was stored. Five of the six function-pointer members are nullable by the
//! authority's own construction: `dh_ossl` (`dh_key.c:180-190`) leaves `app_data` and
//! `generate_params` NULL, and the header's own comment marks `bn_mod_exp` "Can be null". So each
//! is an `Option` and the null is expressed as `None` rather than by a fabricated address. That
//! is observable rather than cosmetic: `DH_meth_get0_app_data` and `DH_meth_get_generate_params`
//! on a fresh table must answer `None`, and `DH_meth_set0_app_data(m, NULL)` must answer 1 while
//! leaving the getter NULL.
//!
//! ## The allocation the arms observe, and the `file` they carry
//!
//! `crypto/dh/dh_meth.c` is a source-tree file, so its `OPENSSL_FILE` is
//! `../../src/openssl-3.6.4/crypto/dh/dh_meth.c` — measured the same way D280's cipher units
//! were, by reading the string out of the authority's own object file. `RT-DH` installs an
//! allocator and records the ordered `(kind, size, file)` sequence of each arm's window, which is
//! how "this unit's allocation is attributed to this unit's translation unit" becomes a diff
//! rather than a constant here. `DH_meth_new` allocates a 72-byte table and then a name;
//! `DH_meth_dup` allocates a 72-byte table, copies, and then a name; `DH_meth_free` releases the
//! name and then the table, in that order.
//!
//! The line number is `__LINE__`, which is inert under `OPENSSL_NO_CRYPTO_MDEBUG` and is passed
//! as zero, exactly as `src/rsa/mod.rs`'s `LINE` is. It is the *file* that a caller's allocator
//! observes.
//!
//! ## Scope: what is transcribed, and what is left
//!
//! Transcribed in **this file**, in authority order: [`DH_meth_new`] (`dh_meth.c:20-35`),
//! [`DH_meth_free`] (`:37-43`), [`DH_meth_dup`] (`:45-60`), [`DH_meth_get0_name`] (`:62-65`),
//! [`DH_meth_set1_name`] (`:67-78`), [`DH_meth_get_flags`] (`:80-83`), [`DH_meth_set_flags`]
//! (`:85-89`), [`DH_meth_get0_app_data`] (`:91-94`), [`DH_meth_set0_app_data`] (`:96-100`),
//! [`DH_meth_get_generate_key`] (`:102-105`), [`DH_meth_set_generate_key`] (`:107-111`),
//! [`DH_meth_get_compute_key`] (`:113-117`), [`DH_meth_set_compute_key`] (`:118-124`),
//! [`DH_meth_get_bn_mod_exp`] (`:125-130`), [`DH_meth_set_bn_mod_exp`] (`:131-138`),
//! [`DH_meth_get_init`] (`:139-143`), [`DH_meth_set_init`] (`:144-149`),
//! [`DH_meth_get_finish`] (`:150-154`), [`DH_meth_set_finish`] (`:155-160`),
//! [`DH_meth_get_generate_params`] (`:161-165`) and [`DH_meth_set_generate_params`]
//! (`:166-171`). That is all twenty-one labels, and `DH_meth.c` defines nothing else — every
//! other definition in the file is one of these. So that unit has **no internals**, which is why
//! it adds no name the prerequisite gate has to count (the unit-module rule D327 records).
//!
//! The other five units are this module's children, each with the authority file it transcribes in
//! its own header: [`object`] is `dh_lib.c`, [`key`] is `dh_key.c`, [`gen`] is `dh_gen.c`,
//! [`check`] is `dh_check.c` and [`depr`] is `dh_depr.c`.
//!
//! Left for the rest of 8.5, each named rather than silently dropped:
//!
//! * **`crypto/dh/dh_group_params.c`.** The named-group unit — `DH_get_nid`, `DH_new_by_nid`,
//!   `ossl_dh_cache_named_group`, `ossl_dh_new_by_nid_ex` — waits with the two tables it reads,
//!   `crypto/bn/bn_dh.c`'s twenty-six constants and `crypto/ffc/ffc_dh.c`'s `dh_named_groups[]`.
//!   D329 recorded the wait; D331 lands the three callers of it as the `params.nid` read they
//!   reduce to and says why at each site.
//! * **`dh_asn1.c`.** `d2i_DHparams`, `i2d_DHparams` and the `DHparams_*` family are 8.8's ASN.1
//!   method objects; nothing on this slice's path reaches them.
//! * **`dh_kdf.c`.** `DH_KDF_X9_42` fetches `OSSL_KDF_NAME_X942KDF_ASN1` through the provider
//!   fetch machinery, so it belongs with the provider surfaces rather than with the object.
//! * **`crypto/evp/dh_ctrl.c`.** The `EVP_PKEY_CTX_*dh*` controls are ABI surfaces over
//!   `EVP_PKEY_CTX`, which this stratum's slice E owns. There is **no `crypto/dh/dh_ctrl.c` in the
//!   authority**: the DH controls live beside the other key types' under `crypto/evp/`.
//!
//! ## The court that drives it: `RT-DH`
//!
//! `courts/phase8/rt_dh_probe.c` **calls all sixty exports** — the twenty-one `DH_meth_*`
//! labels and the thirty-nine the object, key, generator and validator units add — and prints
//! only return codes, names, flags, the *result* of pointer comparisons and the allocator
//! windows. No address is ever printed and no function-pointer sentinel is ever called: each
//! sentinel returns a constant so that a transcription which *did* call one would be visible in
//! the transcript rather than merely wrong. A generated 512-bit safe-prime group is the
//! parameter set every key arm uses, and every refusal is observed through both its return value
//! and the coordinate `ERR_get_error_all` reports. `docs/PHASE-8-SUBPHASES.md`'s two anchored
//! clauses and `docs/DECISIONS.md` D329/D331 record what the court observed.

pub mod check;
pub mod depr;
pub mod gen;
pub mod key;
pub mod object;

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::sync::atomic::AtomicI32;

use crate::bn::bignum::BigNum;
use crate::bn::ctx::{BnCtx, BnGencb};
use crate::bn::mont::MontCtx;
use crate::evp::pkey_asn1::Engine;
use crate::ffc::FfcParams;
use crate::runtime::ex_data::CryptoExData;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::thread::CryptoRwlock;

/// `DH_MIN_MODULUS_BITS` — `crypto/dh/dh_local.h:14`.
///
/// The smallest modulus the key layer and the parameter generator accept. `BN_num_bits(p)` below
/// this is `DH_R_MODULUS_TOO_SMALL` rather than a warning, which is why a `DH` built by hand below
/// 512 bits can be constructed but neither generated from nor agreed over.
pub(crate) const DH_MIN_MODULUS_BITS: c_int = 512;

/// `OPENSSL_DH_MAX_MODULUS_BITS` — `include/openssl/dh.h:99`.
pub(crate) const OPENSSL_DH_MAX_MODULUS_BITS: c_int = 10000;

/// `OPENSSL_DH_CHECK_MAX_MODULUS_BITS` — `include/openssl/dh.h:103`.
///
/// Deliberately **three times** the generation bound: `DH_check` refuses to run its primality
/// tests above this and answers `DH_MODULUS_TOO_LARGE`, while `DH_generate_key` already refuses
/// above the 10000 above.
pub(crate) const OPENSSL_DH_CHECK_MAX_MODULUS_BITS: c_int = 32768;

/// `DH_FLAG_CACHE_MONT_P` — `include/openssl/dh.h:108`. `dh_ossl`'s `init` sets it on every
/// object the default table constructs.
pub(crate) const DH_FLAG_CACHE_MONT_P: c_int = 0x01;

/// `DH_FLAG_FIPS_METHOD` — `include/openssl/dh.h:129`. The word `dh_ossl`'s initialiser carries.
pub(crate) const DH_FLAG_FIPS_METHOD: c_int = 0x0400;

/// `DH_GENERATOR_2` — `include/openssl/dh.h:147`. The only generator `dh_builtin_genparams`
/// special-cases in the key layer; `dh_gen.c` also names 5.
pub(crate) const DH_GENERATOR_2: c_int = 2;
/// `DH_GENERATOR_5` — `include/openssl/dh.h:149`.
pub(crate) const DH_GENERATOR_5: c_int = 5;

/// `DH_PARAMGEN_TYPE_FIPS_186_2` — `include/openssl/dh.h:34`. Selects the legacy generator in
/// `ossl_dh_generate_ffc_parameters`.
pub(crate) const DH_PARAMGEN_TYPE_FIPS_186_2: c_int = 1;

/// `DH_CHECK_P_NOT_PRIME` — `include/openssl/dh.h:156`.
pub(crate) const DH_CHECK_P_NOT_PRIME: c_int = 0x01;
/// `DH_CHECK_P_NOT_SAFE_PRIME` — `include/openssl/dh.h:157`.
pub(crate) const DH_CHECK_P_NOT_SAFE_PRIME: c_int = 0x02;
/// `DH_UNABLE_TO_CHECK_GENERATOR` — `include/openssl/dh.h:158`.
pub(crate) const DH_UNABLE_TO_CHECK_GENERATOR: c_int = 0x04;
/// `DH_NOT_SUITABLE_GENERATOR` — `include/openssl/dh.h:159`.
pub(crate) const DH_NOT_SUITABLE_GENERATOR: c_int = 0x08;
/// `DH_CHECK_Q_NOT_PRIME` — `include/openssl/dh.h:160`.
pub(crate) const DH_CHECK_Q_NOT_PRIME: c_int = 0x10;
/// `DH_CHECK_INVALID_Q_VALUE` — `include/openssl/dh.h:161`.
pub(crate) const DH_CHECK_INVALID_Q_VALUE: c_int = 0x20;
/// `DH_CHECK_INVALID_J_VALUE` — `include/openssl/dh.h:162`.
pub(crate) const DH_CHECK_INVALID_J_VALUE: c_int = 0x40;
/// `DH_MODULUS_TOO_SMALL` — `include/openssl/dh.h:163`.
pub(crate) const DH_MODULUS_TOO_SMALL: c_int = 0x80;
/// `DH_MODULUS_TOO_LARGE` — `include/openssl/dh.h:164`.
pub(crate) const DH_MODULUS_TOO_LARGE: c_int = 0x100;

/// `DH_CHECK_PUBKEY_TOO_SMALL` — `include/openssl/dh.h:167`.
pub(crate) const DH_CHECK_PUBKEY_TOO_SMALL: c_int = 0x01;
/// `DH_CHECK_PUBKEY_TOO_LARGE` — `include/openssl/dh.h:168`.
pub(crate) const DH_CHECK_PUBKEY_TOO_LARGE: c_int = 0x02;
/// `DH_CHECK_PUBKEY_INVALID` — `include/openssl/dh.h:169`.
pub(crate) const DH_CHECK_PUBKEY_INVALID: c_int = 0x04;

/// `struct dh_st` — `crypto/dh/dh_local.h:16-41`.
///
/// **208 bytes, alignment 8**, measured by `courts/layout/measure-dh.c` and asserted member by
/// member in the test below. The first two members are the authority's own comment made concrete:
/// `pad` is "used to pick up errors when a DH is passed instead of a EVP_PKEY" and `version` is the
/// second, so both are plain `int`s at 0 and 4 and the embedded [`FfcParams`] starts eight-aligned
/// at 8. `length` at 104 is a four-byte `int32_t`, so 108..112 is padding before `pub_key`; and
/// `references` is a four-byte `_Atomic int` at 144, so `ex_data` is eight-aligned at 152 rather
/// than adjacent.
///
/// `ex_data` and `engine` are inside `#ifndef FIPS_MODULE` (`dh_local.h:31-34`), which holds on
/// this profile, so both members are present and part of the layout. `dirty_cnt` is a `size_t`
/// rather than an `int` — the provider's change counter — which is why it is the one member after
/// `lock` and why its width is pointer-sized.
#[repr(C)]
pub struct Dh {
    /// `int pad` — the first of the two `EVP_PKEY` type-check words.
    pub(crate) pad: c_int,
    /// `int version`.
    pub(crate) version: c_int,
    /// `FFC_PARAMS params` — the domain parameters, **embedded by value**, so their 96 bytes are
    /// part of this object and `ossl_ffc_params_init`'s `memset` writes inside it.
    pub(crate) params: FfcParams,
    /// `int32_t length` — the maximum generated private-key length; may be less than `len(q)`.
    pub(crate) length: i32,
    /// `BIGNUM *pub_key` — `g^x mod p`.
    pub(crate) pub_key: *mut BigNum,
    /// `BIGNUM *priv_key` — `x`.
    pub(crate) priv_key: *mut BigNum,
    /// `int flags` — the `DH_FLAG_*` bit set.
    pub(crate) flags: c_int,
    /// `BN_MONT_CTX *method_mont_p` — the cached Montgomery context, valid only while
    /// `DH_FLAG_CACHE_MONT_P` is set.
    pub(crate) method_mont_p: *mut MontCtx,
    /// `CRYPTO_REF_COUNT references` — `_Atomic int` in this profile, so [`AtomicI32`] rather than
    /// a plain integer, exactly as [`crate::rsa::Rsa::references`] is.
    pub(crate) references: AtomicI32,
    /// `CRYPTO_EX_DATA ex_data` — inside `#ifndef FIPS_MODULE`.
    pub(crate) ex_data: CryptoExData,
    /// `ENGINE *engine` — inside `#ifndef FIPS_MODULE`. NULL on every object this crate can build.
    pub(crate) engine: *mut Engine,
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `const DH_METHOD *meth` — borrowed, never owned.
    pub(crate) meth: *const DhMethod,
    /// `CRYPTO_RWLOCK *lock` — guards `method_mont_p`.
    pub(crate) lock: *mut CryptoRwlock,
    /// `size_t dirty_cnt` — bumped by every mutator so provider caches are discarded.
    pub(crate) dirty_cnt: usize,
}

/// `int (*generate_key)(DH *dh)` — `crypto/dh/dh_local.h:50`.
pub type DhGenerateKeyFn = unsafe extern "C" fn(dh: *mut Dh) -> c_int;

/// `int (*compute_key)(unsigned char *key, const BIGNUM *pub_key, DH *dh)` —
/// `crypto/dh/dh_local.h:52`.
pub type DhComputeKeyFn =
    unsafe extern "C" fn(key: *mut c_uchar, pub_key: *const BigNum, dh: *mut Dh) -> c_int;

/// `int (*bn_mod_exp)(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,`
/// `const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)` — `crypto/dh/dh_local.h:56-58`.
pub type DhBnModExpFn = unsafe extern "C" fn(
    dh: *const Dh,
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
    m_ctx: *mut MontCtx,
) -> c_int;

/// `int (*init)(DH *dh)` / `int (*finish)(DH *dh)` — `crypto/dh/dh_local.h:59-60`. One type
/// because the authority spells both with the same signature.
pub type DhLifecycleFn = unsafe extern "C" fn(dh: *mut Dh) -> c_int;

/// `int (*generate_params)(DH *dh, int prime_len, int generator, BN_GENCB *cb)` —
/// `crypto/dh/dh_local.h:62-63`.
pub type DhGenerateParamsFn = unsafe extern "C" fn(
    dh: *mut Dh,
    prime_len: c_int,
    generator: c_int,
    cb: *mut BnGencb,
) -> c_int;

/// `struct dh_method` — `crypto/dh/dh_local.h:47-64`.
///
/// Measured **72** bytes with the nine members at the offsets the module documentation lists.
/// `flags` is a four-byte `int` at 48 and `app_data` is a pointer at 56, so the four bytes at
/// 52..56 are padding; a transcription that made `flags` pointer-sized would be eight bytes too
/// wide and would move `generate_params` to 72. The unit tests assert every offset.
#[repr(C)]
pub struct DhMethod {
    /// `char *name` — the string `DH_meth_get0_name` returns and `DH_meth_free` releases.
    pub name: *mut c_char,
    /// `int (*generate_key)(DH *dh)` — NULL for a hand-built table.
    pub generate_key: Option<DhGenerateKeyFn>,
    /// `int (*compute_key)(unsigned char *key, const BIGNUM *pub_key, DH *dh)`.
    pub compute_key: Option<DhComputeKeyFn>,
    /// `int (*bn_mod_exp)(...)` — the header's own comment marks it "Can be null".
    pub bn_mod_exp: Option<DhBnModExpFn>,
    /// `int (*init)(DH *dh)` — called at new.
    pub init: Option<DhLifecycleFn>,
    /// `int (*finish)(DH *dh)` — called at free.
    pub finish: Option<DhLifecycleFn>,
    /// `int flags` — `DH_FLAG_*`.
    pub(crate) flags: c_int,
    /// `char *app_data`.
    pub app_data: *mut c_void,
    /// `int (*generate_params)(...)` — NULL in the authority's own table.
    pub generate_params: Option<DhGenerateParamsFn>,
}

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/dh/dh_meth.c` is a source-tree file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — read out of the authority's own
/// `build/.../crypto/dh/libcrypto-lib-dh_meth.o`, the check D280 applied to the cipher units. It
/// reaches an application through `CRYPTO_set_mem_functions`, so it is part of the contract and
/// `RT-DH` compares it.
const FILE_DH_METH: *const c_char = c"../../src/openssl-3.6.4/crypto/dh/dh_meth.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `DH_METHOD *DH_meth_new(const char *name, int flags)` — `crypto/dh/dh_meth.c:20-35`.
///
/// A zero-allocated table with `flags` stored and `name` duplicated. **A failed `OPENSSL_strdup`
/// releases the whole object**, so a caller that gets NULL never holds a half-built table;
/// `flags` is stored *before* the name is duplicated, which is what makes that release safe.
///
/// # Safety
///
/// `name` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_new(name: *const c_char, flags: c_int) -> *mut DhMethod {
    // SAFETY: the caller's contract.
    unsafe {
        let dhm =
            CRYPTO_zalloc(core::mem::size_of::<DhMethod>(), FILE_DH_METH, LINE).cast::<DhMethod>();

        if !dhm.is_null() {
            (*dhm).flags = flags;
            (*dhm).name = CRYPTO_strdup(name, FILE_DH_METH, LINE);
            if !(*dhm).name.is_null() {
                return dhm;
            }
            CRYPTO_free(dhm.cast(), FILE_DH_METH, LINE);
        }
        core::ptr::null_mut()
    }
}

/// `void DH_meth_free(DH_METHOD *dhm)` — `crypto/dh/dh_meth.c:37-43`. NULL is a no-op, and the
/// name is released **before** the table so that a caller's allocator sees them in that order.
///
/// # Safety
///
/// `dhm` is NULL or a table [`DH_meth_new`] or [`DH_meth_dup`] returned.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_free(dhm: *mut DhMethod) {
    // SAFETY: the caller's contract.
    unsafe {
        if !dhm.is_null() {
            CRYPTO_free((*dhm).name.cast(), FILE_DH_METH, LINE);
            CRYPTO_free(dhm.cast(), FILE_DH_METH, LINE);
        }
    }
}

/// `DH_METHOD *DH_meth_dup(const DH_METHOD *dhm)` — `crypto/dh/dh_meth.c:45-60`.
///
/// **A whole-struct `memcpy` followed by one deep field.** Everything but `name` is shared with
/// the original — including `app_data`, which is why the header warns that a method's application
/// data must outlive every duplicate of it. A NULL `dhm->name` makes `OPENSSL_strdup` answer NULL
/// and therefore makes the *duplicate* fail, because this crate's `CRYPTO_strdup` mirrors the
/// authority's and refuses NULL rather than inventing an empty string.
///
/// The allocation is `OPENSSL_malloc`, not `OPENSSL_zalloc`: the `memcpy` overwrites all 72
/// bytes, so zeroing first would only be visible to an allocator as the same two requests.
///
/// # Safety
///
/// `dhm` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_dup(dhm: *const DhMethod) -> *mut DhMethod {
    // SAFETY: the caller's contract.
    unsafe {
        let ret =
            CRYPTO_malloc(core::mem::size_of::<DhMethod>(), FILE_DH_METH, LINE).cast::<DhMethod>();

        if !ret.is_null() {
            core::ptr::copy_nonoverlapping(dhm, ret, 1);
            (*ret).name = CRYPTO_strdup((*dhm).name, FILE_DH_METH, LINE);
            if !(*ret).name.is_null() {
                return ret;
            }
            CRYPTO_free(ret.cast(), FILE_DH_METH, LINE);
        }
        core::ptr::null_mut()
    }
}

/// `const char *DH_meth_get0_name(const DH_METHOD *dhm)` — `crypto/dh/dh_meth.c:62-65`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get0_name(dhm: *const DhMethod) -> *const c_char {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).name }
}

/// `int DH_meth_set1_name(DH_METHOD *dhm, const char *name)` — `crypto/dh/dh_meth.c:67-78`.
///
/// **The duplicate happens first and the old name is released second**, so a failed `strdup`
/// leaves the table's name untouched rather than freeing it and storing NULL.
///
/// # Safety
///
/// `dhm` is a live table; `name` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set1_name(dhm: *mut DhMethod, name: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let tmpname = CRYPTO_strdup(name, FILE_DH_METH, LINE);

        if tmpname.is_null() {
            return 0;
        }
        CRYPTO_free((*dhm).name.cast(), FILE_DH_METH, LINE);
        (*dhm).name = tmpname;
        1
    }
}

/// `int DH_meth_get_flags(const DH_METHOD *dhm)` — `crypto/dh/dh_meth.c:80-83`.
///
/// # Safety
///
/// `dhm` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_flags(dhm: *const DhMethod) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).flags }
}

/// `int DH_meth_set_flags(DH_METHOD *dhm, int flags)` — `crypto/dh/dh_meth.c:85-89`. Stores the
/// word and answers 1 unconditionally.
///
/// # Safety
///
/// `dhm` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_flags(dhm: *mut DhMethod, flags: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).flags = flags;
    }
    1
}

/// `void *DH_meth_get0_app_data(const DH_METHOD *dhm)` — `crypto/dh/dh_meth.c:91-94`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get0_app_data(dhm: *const DhMethod) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).app_data }
}

/// `int DH_meth_set0_app_data(DH_METHOD *dhm, void *app_data)` — `crypto/dh/dh_meth.c:96-100`.
/// Stores the pointer and answers 1; NULL is a legal value and is what a fresh table holds.
///
/// # Safety
///
/// `dhm` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set0_app_data(dhm: *mut DhMethod, app_data: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).app_data = app_data;
    }
    1
}

/// `int (*DH_meth_get_generate_key(const DH_METHOD *dhm))(DH *)` — `crypto/dh/dh_meth.c:102-105`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_generate_key(dhm: *const DhMethod) -> Option<DhGenerateKeyFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).generate_key }
}

/// `int DH_meth_set_generate_key(DH_METHOD *dhm, int (*generate_key)(DH *))` —
/// `crypto/dh/dh_meth.c:107-111`.
///
/// # Safety
///
/// `dhm` is a live table; `generate_key` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_generate_key(
    dhm: *mut DhMethod,
    generate_key: Option<DhGenerateKeyFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).generate_key = generate_key;
    }
    1
}

/// `int (*DH_meth_get_compute_key(const DH_METHOD *dhm))(unsigned char *, const BIGNUM *, DH *)`
/// — `crypto/dh/dh_meth.c:113-117`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_compute_key(dhm: *const DhMethod) -> Option<DhComputeKeyFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).compute_key }
}

/// `int DH_meth_set_compute_key(DH_METHOD *dhm, int (*compute_key)(unsigned char *,`
/// `const BIGNUM *, DH *))` — `crypto/dh/dh_meth.c:118-124`.
///
/// # Safety
///
/// `dhm` is a live table; `compute_key` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_compute_key(
    dhm: *mut DhMethod,
    compute_key: Option<DhComputeKeyFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).compute_key = compute_key;
    }
    1
}

/// `int (*DH_meth_get_bn_mod_exp(const DH_METHOD *dhm))(const DH *, BIGNUM *, const BIGNUM *,`
/// `const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *)` — `crypto/dh/dh_meth.c:125-130`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_bn_mod_exp(dhm: *const DhMethod) -> Option<DhBnModExpFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).bn_mod_exp }
}

/// `int DH_meth_set_bn_mod_exp(DH_METHOD *dhm, int (*bn_mod_exp)(const DH *, BIGNUM *,`
/// `const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *))` —
/// `crypto/dh/dh_meth.c:131-138`.
///
/// # Safety
///
/// `dhm` is a live table; `bn_mod_exp` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_bn_mod_exp(
    dhm: *mut DhMethod,
    bn_mod_exp: Option<DhBnModExpFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).bn_mod_exp = bn_mod_exp;
    }
    1
}

/// `int (*DH_meth_get_init(const DH_METHOD *dhm))(DH *)` — `crypto/dh/dh_meth.c:139-143`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_init(dhm: *const DhMethod) -> Option<DhLifecycleFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).init }
}

/// `int DH_meth_set_init(DH_METHOD *dhm, int (*init)(DH *))` — `crypto/dh/dh_meth.c:144-149`.
///
/// # Safety
///
/// `dhm` is a live table; `init` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_init(
    dhm: *mut DhMethod,
    init: Option<DhLifecycleFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).init = init;
    }
    1
}

/// `int (*DH_meth_get_finish(const DH_METHOD *dhm))(DH *)` — `crypto/dh/dh_meth.c:150-154`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_finish(dhm: *const DhMethod) -> Option<DhLifecycleFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).finish }
}

/// `int DH_meth_set_finish(DH_METHOD *dhm, int (*finish)(DH *))` — `crypto/dh/dh_meth.c:155-160`.
///
/// # Safety
///
/// `dhm` is a live table; `finish` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_finish(
    dhm: *mut DhMethod,
    finish: Option<DhLifecycleFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).finish = finish;
    }
    1
}

/// `int (*DH_meth_get_generate_params(const DH_METHOD *dhm))(DH *, int, int, BN_GENCB *)` —
/// `crypto/dh/dh_meth.c:161-165`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_generate_params(
    dhm: *const DhMethod,
) -> Option<DhGenerateParamsFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).generate_params }
}

/// `int DH_meth_set_generate_params(DH_METHOD *dhm, int (*generate_params)(DH *, int, int,`
/// `BN_GENCB *))` — `crypto/dh/dh_meth.c:166-171`.
///
/// # Safety
///
/// `dhm` is a live table; `generate_params` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_generate_params(
    dhm: *mut DhMethod,
    generate_params: Option<DhGenerateParamsFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).generate_params = generate_params;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five sentinels as *function pointers*, so `Some(const)` is an `Option<fn>` and
    /// compares with `assert_eq!` (a bare fn item is a distinct type and implements no `Debug`).
    const SENT_GK: DhGenerateKeyFn = sentinel_generate_key;
    /// The compute-key sentinel.
    const SENT_CK: DhComputeKeyFn = sentinel_compute_key;
    /// The modular-exponentiation sentinel.
    const SENT_BM: DhBnModExpFn = sentinel_bn_mod_exp;
    /// The lifecycle (`init`/`finish`) sentinel.
    const SENT_LF: DhLifecycleFn = sentinel_life;
    /// The parameter-generation sentinel.
    const SENT_GP: DhGenerateParamsFn = sentinel_generate_params;

    /// **`DH_METHOD`, field for field.** 72 bytes with `name` 0, `generate_key` 8, `compute_key`
    /// 16, `bn_mod_exp` 24, `init` 32, `finish` 40, `flags` **48**, `app_data` 56 and
    /// `generate_params` 64.
    ///
    /// The offset that matters most is 56: `flags` is a four-byte `int` at 48, so the four bytes
    /// at 52..56 are padding and a transcription that gave `flags` a pointer's width would move
    /// every member after it by eight — which the size assertion catches and the offsets make
    /// legible.
    #[test]
    fn the_dh_method_is_the_authoritys_shape() {
        assert_eq!(core::mem::size_of::<DhMethod>(), 72);
        assert_eq!(core::mem::align_of::<DhMethod>(), 8);
        assert_eq!(core::mem::offset_of!(DhMethod, name), 0);
        assert_eq!(core::mem::offset_of!(DhMethod, generate_key), 8);
        assert_eq!(core::mem::offset_of!(DhMethod, compute_key), 16);
        assert_eq!(core::mem::offset_of!(DhMethod, bn_mod_exp), 24);
        assert_eq!(core::mem::offset_of!(DhMethod, init), 32);
        assert_eq!(core::mem::offset_of!(DhMethod, finish), 40);
        assert_eq!(core::mem::offset_of!(DhMethod, flags), 48);
        assert_eq!(core::mem::offset_of!(DhMethod, app_data), 56);
        assert_eq!(core::mem::offset_of!(DhMethod, generate_params), 64);
    }

    /// The lifecycle sentinels. They are stored and read back, never called, so each returns a
    /// constant that would be visible if a transcription called one.
    unsafe extern "C" fn sentinel_generate_key(_dh: *mut Dh) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_compute_key(
        _key: *mut c_uchar,
        _pub_key: *const BigNum,
        _dh: *mut Dh,
    ) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_bn_mod_exp(
        _dh: *const Dh,
        _r: *mut BigNum,
        _a: *const BigNum,
        _p: *const BigNum,
        _m: *const BigNum,
        _ctx: *mut BnCtx,
        _m_ctx: *mut MontCtx,
    ) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_life(_dh: *mut Dh) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_generate_params(
        _dh: *mut Dh,
        _prime_len: c_int,
        _generator: c_int,
        _cb: *mut BnGencb,
    ) -> c_int {
        7
    }

    /// **A fresh table is all NULLs**, which is `OPENSSL_zalloc`'s contribution and the reason
    /// every getter answers `None`/NULL before its setter runs. The name getter is not NULL
    /// because `DH_meth_new` duplicates the caller's string.
    #[test]
    fn a_fresh_method_table_is_zeroed() {
        // SAFETY: the argument is a literal NUL-terminated string.
        let m = unsafe { DH_meth_new(c"probe".as_ptr(), 0x1234) };
        assert!(!m.is_null());
        // SAFETY: `m` is a live table for the length of this test.
        unsafe {
            assert!((*m).generate_key.is_none());
            assert!((*m).compute_key.is_none());
            assert!((*m).bn_mod_exp.is_none());
            assert!((*m).init.is_none());
            assert!((*m).finish.is_none());
            assert!((*m).generate_params.is_none());
            assert!((*m).app_data.is_null());
            assert_eq!(DH_meth_get_flags(m), 0x1234);
            assert_eq!(
                core::ffi::CStr::from_ptr(DH_meth_get0_name(m)).to_str(),
                Ok("probe")
            );
            DH_meth_free(m);
        }
    }

    /// **Every setter/getter pair round-trips the sentinel and then NULL.** The `bn_mod_exp`,
    /// `init`, `finish`, `generate_key`, `compute_key` and `generate_params` members are the six
    /// function-pointer fields; each is NULL on the fresh table, answers its setter's 1, answers
    /// the sentinel, accepts NULL and is NULL again. The round trip leaves every member NULL, so
    /// one table serves all six without order dependence.
    #[test]
    fn every_member_round_trips() {
        // SAFETY: the argument is a literal NUL-terminated string; `m` is live throughout.
        let m = unsafe { DH_meth_new(c"round".as_ptr(), 0) };
        assert!(!m.is_null());
        // SAFETY: `m` is a live table for the remainder of this test, and every `Some(SENT_*)`
        // is a function the test never calls.
        unsafe {
            assert_eq!(DH_meth_set_generate_key(m, Some(SENT_GK)), 1);
            assert!(DH_meth_get_generate_key(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_GK)));
            assert_eq!(DH_meth_set_generate_key(m, None), 1);
            assert!(DH_meth_get_generate_key(m).is_none());

            assert_eq!(DH_meth_set_compute_key(m, Some(SENT_CK)), 1);
            assert!(DH_meth_get_compute_key(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_CK)));
            assert_eq!(DH_meth_set_compute_key(m, None), 1);
            assert!(DH_meth_get_compute_key(m).is_none());

            assert_eq!(DH_meth_set_bn_mod_exp(m, Some(SENT_BM)), 1);
            assert!(DH_meth_get_bn_mod_exp(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_BM)));
            assert_eq!(DH_meth_set_bn_mod_exp(m, None), 1);
            assert!(DH_meth_get_bn_mod_exp(m).is_none());

            assert_eq!(DH_meth_set_init(m, Some(SENT_LF)), 1);
            assert!(DH_meth_get_init(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_LF)));
            assert_eq!(DH_meth_set_init(m, None), 1);
            assert!(DH_meth_get_init(m).is_none());

            assert_eq!(DH_meth_set_finish(m, Some(SENT_LF)), 1);
            assert!(DH_meth_get_finish(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_LF)));
            assert_eq!(DH_meth_set_finish(m, None), 1);
            assert!(DH_meth_get_finish(m).is_none());

            assert_eq!(DH_meth_set_generate_params(m, Some(SENT_GP)), 1);
            assert!(
                DH_meth_get_generate_params(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_GP))
            );
            assert_eq!(DH_meth_set_generate_params(m, None), 1);
            assert!(DH_meth_get_generate_params(m).is_none());

            // `app_data` is not a function pointer and its NULL is a value, not a refusal.
            let marker = 0x1234_usize as *mut c_void;
            assert_eq!(DH_meth_set0_app_data(m, marker), 1);
            assert_eq!(DH_meth_get0_app_data(m), marker);
            assert_eq!(DH_meth_set0_app_data(m, core::ptr::null_mut()), 1);
            assert!(DH_meth_get0_app_data(m).is_null());

            assert_eq!(DH_meth_set_flags(m, 0x0f0f), 1);
            assert_eq!(DH_meth_get_flags(m), 0x0f0f);

            DH_meth_free(m);
        }
    }

    /// **`DH_meth_dup` copies every member and deep-copies the name.** The duplicate's name is a
    /// different pointer (`strdup`) holding the same bytes, and every other member is shared
    /// *by value* — including `app_data`, which is why the header says a method's application
    /// data must outlive every duplicate of it. Releasing the original leaves the duplicate
    /// valid; the duplicate is released by the getter read after the free.
    #[test]
    fn dup_copies_the_table_and_deep_copies_the_name() {
        // SAFETY: the argument is a literal NUL-terminated string; both tables are live until
        // their own frees.
        unsafe {
            let orig = DH_meth_new(c"dup-me".as_ptr(), 0x42);
            assert!(!orig.is_null());
            assert_eq!(DH_meth_set_generate_key(orig, Some(SENT_GK)), 1);
            let marker = 0x5678_usize as *mut c_void;
            assert_eq!(DH_meth_set0_app_data(orig, marker), 1);

            let copy = DH_meth_dup(orig);
            assert!(!copy.is_null());
            assert_eq!(DH_meth_get_flags(copy), 0x42);
            assert_eq!(
                core::ffi::CStr::from_ptr(DH_meth_get0_name(copy)).to_str(),
                Ok("dup-me")
            );
            assert_eq!(DH_meth_get0_app_data(copy), marker);
            assert!(
                DH_meth_get_generate_key(copy).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_GK))
            );
            // The name is a second allocation, not a shared pointer.
            assert_ne!(DH_meth_get0_name(copy), DH_meth_get0_name(orig));

            DH_meth_free(orig);
            // The duplicate survives the original's release, name and all.
            assert_eq!(
                core::ffi::CStr::from_ptr(DH_meth_get0_name(copy)).to_str(),
                Ok("dup-me")
            );
            DH_meth_free(copy);
        }
    }

    /// **`DH_meth_set1_name` duplicates first and releases second.** The observable half is that
    /// a successful set changes the name's identity, and that `DH_meth_set1_name(m, NULL)`
    /// answers 0 and leaves the old name in place — because a NULL argument makes
    /// `CRYPTO_strdup` answer NULL, which the authority treats as the failure arm.
    #[test]
    fn set1_name_is_a_duplicate_then_a_release() {
        // SAFETY: the arguments are literal NUL-terminated strings, or NULL; `m` is live.
        unsafe {
            let m = DH_meth_new(c"first".as_ptr(), 0);
            assert!(!m.is_null());
            let before = DH_meth_get0_name(m);
            assert_eq!(DH_meth_set1_name(m, c"second".as_ptr()), 1);
            let after = DH_meth_get0_name(m);
            assert_ne!(before, after);
            assert_eq!(core::ffi::CStr::from_ptr(after).to_str(), Ok("second"));
            // A NULL name refuses, and the refusal is not the free-then-store path.
            assert_eq!(DH_meth_set1_name(m, core::ptr::null()), 0);
            assert_eq!(
                core::ffi::CStr::from_ptr(DH_meth_get0_name(m)).to_str(),
                Ok("second")
            );
            DH_meth_free(m);
        }
    }

    /// **NULL is accepted where the authority accepts it.** `DH_meth_free(NULL)` is a no-op and
    /// the getters are not called on NULL (the authority dereferences unconditionally), so the
    /// only NULL-legal entry point is the free.
    #[test]
    fn free_accepts_null() {
        // SAFETY: NULL is the documented no-op argument.
        unsafe { DH_meth_free(core::ptr::null_mut()) };
    }

    /// `struct dh_st` is **208** bytes with the sixteen members at the offsets
    /// `courts/layout/measure-dh.c` printed. The two that cannot be reasoned about from the
    /// declaration are `length` at 104 — a four-byte `int32_t` followed by four bytes of padding
    /// before the pointer `pub_key` at 112 — and `ex_data` at 152, because `references` at 144 is
    /// a four-byte `_Atomic int`. The embedded `params` at 8 is `FFC_PARAMS`: if it moved, every
    /// member after it would move with it, which is why `src/ffc/mod.rs` pins its own 96.
    #[test]
    fn the_dh_object_is_the_authoritys_shape() {
        use core::mem::{align_of, offset_of, size_of};

        assert_eq!(size_of::<Dh>(), 208);
        assert_eq!(align_of::<Dh>(), 8);
        assert_eq!(offset_of!(Dh, pad), 0);
        assert_eq!(offset_of!(Dh, version), 4);
        assert_eq!(offset_of!(Dh, params), 8);
        assert_eq!(offset_of!(Dh, length), 104);
        assert_eq!(offset_of!(Dh, pub_key), 112);
        assert_eq!(offset_of!(Dh, priv_key), 120);
        assert_eq!(offset_of!(Dh, flags), 128);
        assert_eq!(offset_of!(Dh, method_mont_p), 136);
        assert_eq!(offset_of!(Dh, references), 144);
        assert_eq!(offset_of!(Dh, ex_data), 152);
        assert_eq!(offset_of!(Dh, engine), 168);
        assert_eq!(offset_of!(Dh, libctx), 176);
        assert_eq!(offset_of!(Dh, meth), 184);
        assert_eq!(offset_of!(Dh, lock), 192);
        assert_eq!(offset_of!(Dh, dirty_cnt), 200);
    }

    /// A fresh object's whole observable surface, which is the constructor's contract: the
    /// default method installed, its `init` run (so `DH_FLAG_CACHE_MONT_P` set), no engine,
    /// no parameters, no key, and the four readers at their `-1`/`0` sentinels.
    #[test]
    fn a_fresh_object_is_the_constructed_state() {
        use crate::dh::object::{
            DH_bits, DH_free, DH_get0_engine, DH_get0_g, DH_get0_key, DH_get0_p, DH_get0_pqg,
            DH_get0_priv_key, DH_get0_pub_key, DH_get0_q, DH_get_length, DH_new, DH_security_bits,
            DH_size, DH_test_flags,
        };

        // SAFETY: every call below is on the object this test constructs, and none of them is
        // given a NULL out-parameter that the authority would write through.
        unsafe {
            let dh = DH_new();
            assert!(!dh.is_null());
            assert!(DH_get0_engine(dh).is_null());
            assert_ne!(DH_test_flags(dh, DH_FLAG_CACHE_MONT_P), 0);
            assert_eq!(DH_bits(dh), -1);
            assert_eq!(DH_size(dh), -1);
            assert_eq!(DH_security_bits(dh), -1);
            assert_eq!(DH_get_length(dh), 0);
            assert!(DH_get0_p(dh).is_null());
            assert!(DH_get0_q(dh).is_null());
            assert!(DH_get0_g(dh).is_null());
            assert!(DH_get0_priv_key(dh).is_null());
            assert!(DH_get0_pub_key(dh).is_null());

            let mut p: *const BigNum = core::ptr::null();
            let mut q: *const BigNum = core::ptr::null();
            let mut g: *const BigNum = core::ptr::null();
            DH_get0_pqg(dh, &raw mut p, &raw mut q, &raw mut g);
            assert!(p.is_null() && q.is_null() && g.is_null());
            let mut pub_key: *const BigNum = core::ptr::null();
            let mut priv_key: *const BigNum = core::ptr::null();
            DH_get0_key(dh, &raw mut pub_key, &raw mut priv_key);
            assert!(pub_key.is_null() && priv_key.is_null());

            // The reference is real: one free leaves the object for the second.
            assert_eq!(crate::dh::object::DH_up_ref(dh), 1);
            DH_free(dh);
            DH_free(dh);
        }
    }

    /// **Two parties over one generated group agree**, and the padded and unpadded agreement
    /// functions are consistent with each other. A 512-bit safe prime is the smallest group
    /// every entry point accepts, so this is the layer's end-to-end property in one test.
    #[test]
    fn two_parties_agree_on_a_generated_group() {
        use crate::bn::bignum::{BN_dup, BN_free, BN_num_bits, BN_value_one};

        // SAFETY: every object below is this test's own and every call follows the `DH` API's
        // contract; the two key buffers are sized for the 512-bit group's 64-byte secret.
        unsafe {
            let a = crate::dh::object::DH_new();
            assert!(!a.is_null());
            assert_eq!(
                crate::dh::gen::DH_generate_parameters_ex(a, 512, 2, core::ptr::null_mut()),
                1
            );
            assert_eq!(crate::dh::object::DH_bits(a), 512);
            assert_eq!(crate::dh::object::DH_size(a), 64);

            // A second object with the same `p` and `g`, duplicated through the public readers.
            let mut p: *const BigNum = core::ptr::null();
            let mut g: *const BigNum = core::ptr::null();
            crate::dh::object::DH_get0_pqg(a, &raw mut p, core::ptr::null_mut(), &raw mut g);
            assert!(!p.is_null() && !g.is_null());
            let b = crate::dh::object::DH_new();
            let p2 = BN_dup(p);
            let g2 = BN_dup(g);
            assert!(!p2.is_null() && !g2.is_null());
            assert_eq!(
                crate::dh::object::DH_set0_pqg(b, p2, core::ptr::null_mut(), g2),
                1
            );

            assert_eq!(crate::dh::key::DH_generate_key(a), 1);
            assert_eq!(crate::dh::key::DH_generate_key(b), 1);
            // `BN_RAND_TOP_ONE` means the private exponent's bit width is exactly `length`, and
            // `length` is the RFC 7919 key length `dh_builtin_genparams` stored — 125 for a
            // 512-bit group. The peer carries no `length`, so its exponent is `len(p) - 2`.
            let length = crate::dh::object::DH_get_length(a) as i32;
            assert_eq!(length, 125);
            assert_eq!(BN_num_bits(crate::dh::object::DH_get0_priv_key(a)), length);
            assert_eq!(crate::dh::object::DH_get_length(b), 0);
            assert!(BN_num_bits(crate::dh::object::DH_get0_priv_key(b)) <= 510);

            let mut k1 = [0u8; 64];
            let mut k2 = [0u8; 64];
            let mut u1 = [0u8; 64];
            let n1 = crate::dh::key::DH_compute_key_padded(
                k1.as_mut_ptr(),
                crate::dh::object::DH_get0_pub_key(b),
                a,
            );
            let n2 = crate::dh::key::DH_compute_key_padded(
                k2.as_mut_ptr(),
                crate::dh::object::DH_get0_pub_key(a),
                b,
            );
            assert_eq!(n1, 64);
            assert_eq!(n2, 64);
            assert_eq!(k1, k2);

            let un = crate::dh::key::DH_compute_key(
                u1.as_mut_ptr(),
                crate::dh::object::DH_get0_pub_key(b),
                a,
            );
            assert!(un > 0 && un <= 64);
            assert_eq!(&u1[..un as usize], &k1[64 - un as usize..]);

            // A body with no private value refuses the agreement with -1 rather than 0, which is
            // the asymmetry `ossl_dh_compute_key`'s two bounds do not have.
            let c = crate::dh::object::DH_new();
            let p3 = BN_dup(p);
            let g3 = BN_dup(g);
            assert_eq!(
                crate::dh::object::DH_set0_pqg(c, p3, core::ptr::null_mut(), g3),
                1
            );
            assert_eq!(
                crate::dh::key::DH_compute_key(
                    u1.as_mut_ptr(),
                    crate::dh::object::DH_get0_pub_key(a),
                    c
                ),
                -1
            );
            // `DH_check_pub_key` accepts the agreed public key and rejects the two range ends.
            let mut flags: i32 = -1;
            assert_eq!(
                crate::dh::check::DH_check_pub_key(
                    a,
                    crate::dh::object::DH_get0_pub_key(a),
                    &raw mut flags
                ),
                1
            );
            assert_eq!(flags, 0);
            let one = BN_value_one();
            assert_eq!(
                crate::dh::check::DH_check_pub_key(a, one, &raw mut flags),
                1
            );
            assert_eq!(flags, DH_CHECK_PUBKEY_TOO_SMALL);
            let pm1 = crate::bn::bignum::BN_new();
            assert!(!crate::bn::bignum::BN_copy(pm1, p).is_null());
            assert_ne!(crate::bn::arith::BN_sub_word(pm1, 1), 0);
            assert_eq!(
                crate::dh::check::DH_check_pub_key(a, pm1, &raw mut flags),
                1
            );
            assert_eq!(flags, DH_CHECK_PUBKEY_TOO_LARGE);
            BN_free(pm1);

            crate::dh::object::DH_free(c);
            crate::dh::object::DH_free(b);
            crate::dh::object::DH_free(a);
        }
    }

    /// The refusals that need no group: the modulus bounds, the bad generator's **two** records,
    /// and the structural flags a body with no modulus and a 5-bit group report.
    #[test]
    fn the_generators_refusals_are_refusals() {
        use crate::bn::bignum::{BN_new, BN_set_word, BN_value_one};

        // SAFETY: every object below is this test's own; `DH_generate_parameters_ex`'s two
        // refusing arms allocate and free inside the call.
        unsafe {
            let dh = crate::dh::object::DH_new();
            assert!(!dh.is_null());

            // A modulus below `DH_MIN_MODULUS_BITS`: one reason, one record, answer 0.
            assert_eq!(
                crate::dh::gen::DH_generate_parameters_ex(dh, 256, 2, core::ptr::null_mut()),
                0
            );
            // A generator of 1 is `DH_R_BAD_GENERATOR` and then the shared `err:` label's
            // `ERR_R_BN_LIB`, which is why a refusing generator leaves two records.
            assert_eq!(
                crate::dh::gen::DH_generate_parameters_ex(dh, 512, 1, core::ptr::null_mut()),
                0
            );
            crate::dh::object::DH_free(dh);

            // A 5-bit group is refused by the key layer and by both parameter validators, and the
            // refusals are the *same* flag the structural check reports.
            let tiny = crate::dh::object::DH_new();
            let p = BN_new();
            let q = BN_new();
            let g = BN_new();
            assert_ne!(BN_set_word(p, 23), 0);
            assert_ne!(BN_set_word(q, 11), 0);
            assert_ne!(BN_set_word(g, 2), 0);
            assert_eq!(crate::dh::object::DH_set0_pqg(tiny, p, q, g), 1);
            assert_eq!(crate::dh::object::DH_bits(tiny), 5);
            assert_eq!(crate::dh::key::DH_generate_key(tiny), 0);
            let mut flags: i32 = -1;
            assert_eq!(crate::dh::check::DH_check_params(tiny, &raw mut flags), 1);
            assert_eq!(flags, DH_MODULUS_TOO_SMALL);
            assert_eq!(crate::dh::check::DH_check(tiny, &raw mut flags), 1);
            assert_eq!(flags, DH_MODULUS_TOO_SMALL);
            assert_eq!(crate::dh::check::DH_check_params_ex(tiny), 0);
            assert_eq!(crate::dh::check::DH_check_ex(tiny), 0);
            crate::dh::object::DH_free(tiny);

            // No modulus at all: the structural checks report the pair of bits through `*ret`
            // rather than dereferencing either NULL.
            let empty = crate::dh::object::DH_new();
            assert_eq!(crate::dh::check::DH_check_params(empty, &raw mut flags), 1);
            assert_eq!(flags, DH_NOT_SUITABLE_GENERATOR | DH_CHECK_P_NOT_PRIME);
            assert_eq!(
                crate::dh::check::DH_check_pub_key(empty, BN_value_one(), &raw mut flags),
                1
            );
            assert_eq!(flags, DH_CHECK_PUBKEY_INVALID);
            crate::dh::object::DH_free(empty);
        }
    }

    /// The object accessors that store rather than compute: the flag trio, the length setter, the
    /// ex-data pair and the two `set0` refusals. Each is checked against the same object so the
    /// order is the observation.
    #[test]
    fn the_object_accessors_round_trip() {
        use crate::bn::bignum::{BN_free, BN_new, BN_set_word};

        // SAFETY: every call is on this test's own object; the ex-data index is the one this test
        // stores with, and the marker pointer is a stack local that outlives the object.
        unsafe {
            let dh = crate::dh::object::DH_new();
            let marker = 0x4321usize as *mut core::ffi::c_void;

            crate::dh::object::DH_set_flags(dh, 0x1234);
            assert_ne!(crate::dh::object::DH_test_flags(dh, 0x1234), 0);
            crate::dh::object::DH_clear_flags(dh, 0x0034);
            assert_eq!(crate::dh::object::DH_test_flags(dh, 0x1234), 0x1200);
            assert_eq!(crate::dh::object::DH_set_length(dh, 42), 1);
            assert_eq!(crate::dh::object::DH_get_length(dh), 42);

            assert_eq!(crate::dh::object::DH_set_ex_data(dh, 0, marker), 1);
            assert_eq!(crate::dh::object::DH_get_ex_data(dh, 0), marker);
            assert!(crate::dh::object::DH_get_ex_data(dh, 999).is_null());

            // The two `set0_pqg` refusals, and the fact that a refusal stores nothing.
            assert_eq!(
                crate::dh::object::DH_set0_pqg(
                    dh,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                0
            );
            let p = BN_new();
            assert_ne!(BN_set_word(p, 7), 0);
            assert_eq!(
                crate::dh::object::DH_set0_pqg(dh, p, core::ptr::null_mut(), core::ptr::null_mut()),
                0
            );
            assert!(crate::dh::object::DH_get0_p(dh).is_null());
            BN_free(p);

            // `DH_set0_key` accepts NULLs and answers 1 either way; a NULL leaves the slot alone.
            assert_eq!(
                crate::dh::object::DH_set0_key(dh, core::ptr::null_mut(), core::ptr::null_mut()),
                1
            );
            assert!(crate::dh::object::DH_get0_pub_key(dh).is_null());
            let pub_key = BN_new();
            assert_ne!(BN_set_word(pub_key, 7), 0);
            assert_eq!(
                crate::dh::object::DH_set0_key(dh, pub_key, core::ptr::null_mut()),
                1
            );
            assert_eq!(crate::dh::object::DH_get0_pub_key(dh), pub_key);

            crate::dh::object::DH_free(dh);
        }
    }
}
