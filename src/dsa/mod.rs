//! `crypto/dsa/` — the `DSA` object, its method table and its key, generation and signature
//! layers, Phase 8.6.
//!
//! This module is Phase 8.6's. Like 8.4's `src/rsa/mod.rs` and 8.5's `src/dh/mod.rs` it is built in
//! the slices the ledger's labels separate rather than all at once, because the block is ninety
//! labels and its parts have different prerequisites. **The method table is LANDED**, in this file:
//! the twenty-seven `DSA_meth_*` labels of `crypto/dsa/dsa_meth.c` are the first slice, because
//! they are the one part of the block whose bodies allocate a table, store a pointer in it,
//! duplicate one, release one, or read one back, and therefore the one part with no cryptographic
//! callee at all — the reading, and the precedent, of 8.4's slice B (D284) and 8.5's first slice
//! (D329). **[`object`] and [`ossl`] land in the same slice and close the cycle D329/D331 measured**:
//! `dsa_new_intern` (`crypto/dsa/dsa_lib.c:153`) reads `DSA_get_default_method()`, whose table
//! `openssl_dsa_meth` is `crypto/dsa/dsa_ossl.c:53-67`, so neither can precede the other. [`key`],
//! [`gen`], [`sign`], [`vrf`] and [`depr`] are the same slice's key generation, parameter
//! generation, signature surface, verification and deprecated wrapper.
//!
//! ## `struct dsa_st` and `struct dsa_method` are measured, not reasoned about
//!
//! `courts/layout/measure-dsa.c` prints them against the admitted authority: `struct dsa_st` is
//! **200 bytes**, alignment 8, with `params` — the embedded [`FfcParams`] — at 8;
//! `struct dsa_method` is **96 bytes** with twelve members; `struct DSA_SIG_st` is 16. The two
//! object offsets that cannot be read off a declaration are `method_mont_p` at **128** (`flags` is
//! a four-byte `int` at 120, so 124..128 is padding) and `ex_data` at **144** (`references` is a
//! four-byte `_Atomic int` at 136, and `CRYPTO_EX_DATA` is two pointers). In the method table the
//! offset a wrong order moves without moving the size is `app_data` at 72: `flags` is a four-byte
//! `int` at 64, so 68..72 is padding. Every one of those numbers is asserted in the tests below
//! rather than described, because a swap of `init` and `finish` keeps the size and moves two calls.
//!
//! ## The method table's own shape, and the five members that are NULL in the authority
//!
//! `openssl_dsa_meth` (`dsa_ossl.c:53-67`) gives `dsa_do_sign`, `dsa_sign_setup`, `dsa_do_verify`,
//! `dsa_init` and `dsa_finish` real bodies, gives `flags` the word `DSA_FLAG_FIPS_METHOD`, and
//! leaves **NULL** in `dsa_mod_exp`, `bn_mod_exp`, `app_data`, `dsa_paramgen` and `dsa_keygen`.
//! The last two NULLs are load-bearing rather than incidental: `DSA_generate_parameters_ex` falls
//! through to `dsa_gen.c`'s FFC generator when `dsa_paramgen` is NULL, and `DSA_generate_key` falls
//! through to `dsa_key.c`'s static `dsa_keygen`. That is why key generation is landable while the
//! table keeps the authority's own NULLs rather than calling its own functions through them — the
//! dispatch is a fall-through in the authority, not a call.
//!
//! ## The two flag constants that share a value, and what a fresh object's flags therefore are
//!
//! `DSA_FLAG_FIPS_METHOD` and `DSA_FLAG_NON_FIPS_ALLOW` are both `0x0400`
//! (`include/openssl/dsa.h:90`, `:98`) — the same bit, named twice for its two readers. So
//! `dsa_new_intern`'s `ret->flags = ret->meth->flags & ~DSA_FLAG_NON_FIPS_ALLOW` clears the bit the
//! table just supplied, and a fresh object's flags are exactly `dsa_init`'s `DSA_FLAG_CACHE_MONT_P`
//! (`0x01`). `DSA_test_flags(d, DSA_FLAG_FIPS_METHOD) == 0` on a fresh object is therefore the
//! authority's answer rather than a defect, and `RT-DSA` observes both.
//!
//! ## Scope: what is transcribed in this file, and what is deliberately not
//!
//! Transcribed here, in authority order, are all twenty-seven labels of
//! `crypto/dsa/dsa_meth.c:24-219`: [`DSA_meth_new`], [`DSA_meth_free`], [`DSA_meth_dup`],
//! [`DSA_meth_get0_name`], [`DSA_meth_set1_name`], [`DSA_meth_get_flags`], [`DSA_meth_set_flags`],
//! [`DSA_meth_get0_app_data`], [`DSA_meth_set0_app_data`], and the nine getter/setter pairs
//! `sign`, `sign_setup`, `verify`, `mod_exp`, `bn_mod_exp`, `init`, `finish`, `paramgen` and
//! `keygen`. `dsa_meth.c` defines nothing else — the whole file is one
//! `#ifndef OPENSSL_NO_DEPRECATED_3_0` block over these definitions — so the unit has **no
//! internals**, which is why it adds no name the prerequisite gate has to count (D327's rule) and
//! why it is absent from `gen_err_raise_sites.py`'s covered set: it raises nothing.
//!
//! Left for the rest of 8.6, each named rather than silently dropped:
//!
//! * **`dsa_ameth.c` and `dsa_prn.c`.** The `EVP_PKEY_ASN1_METHOD` object and the two printers are
//!   8.8's ASN.1 method machinery, reached through `standard_methods[]`.
//! * **`dsa_asn1.c`.** `d2i_DSAparams`/`i2d_DSAparams` and the four key encoders are that
//!   stratum's ASN.1 surface. **`dsa_sign.c`'s `i2d_DSA_SIG`/`d2i_DSA_SIG` are not in that file**:
//!   the sig encoder and decoder are defined *inside* `dsa_sign.c` — it is one of the FIPS-shared
//!   `$COMMON` units of `crypto/dsa/build.info` — so they live in [`sign`] rather than with the
//!   method objects, which is what `DSA_size`, `DSA_sign` and `DSA_verify` require, since all
//!   three call them.
//! * **`crypto/evp/dsa_ctrl.c`.** There is **no `crypto/dsa/dsa_ctrl.c` in the authority**: the
//!   `EVP_PKEY_CTX_*dsa*` controls live beside the other key types' under `crypto/evp/`, and they
//!   are 8.6's slice E over `EVP_PKEY_CTX`. `dsa_pmeth.c` — the `EVP_PKEY_METHOD` — is the same
//!   stratum's, and its `nonce_type == 1` arm is the only caller of
//!   `crypto/deterministic_nonce.c`'s `ossl_gen_deterministic_nonce_rfc6979`.
//! * **`dsa_check.c`, `dsa_backend.c`, `dsa_err.c`.** The three validators, the provider backend
//!   and the generated reason table are the provider-facing half of 8.6.
//!
//! ## The court that drives it: `RT-DSA`
//!
//! `courts/phase8/rt_dsa_probe.c` calls the method table's twenty-seven labels and the object,
//! generation and signature exports this slice adds, and prints only return codes, names, flags,
//! the *result* of pointer comparisons and the allocator windows. `dsa_meth.c` is a source-tree
//! file, so its `OPENSSL_FILE` carries the `../../src/openssl-3.6.4/` prefix and the probe installs
//! an allocator and compares the ordered `(kind, size, file)` sequence of each arm's window. No
//! address is printed and no function-pointer sentinel is ever called: each sentinel returns a
//! constant so that a transcription which *did* call one would be visible in the transcript rather
//! than merely wrong.

pub mod ctrl;
pub mod depr;
pub mod gen;
pub mod key;
pub mod object;
pub mod ossl;
pub mod sign;
pub mod vrf;

use core::ffi::{c_char, c_int, c_uchar, c_ulong, c_void};
use core::sync::atomic::AtomicI32;

use crate::bn::bignum::BigNum;
use crate::bn::ctx::{BnCtx, BnGencb};
use crate::bn::mont::MontCtx;
use crate::evp::pkey_asn1::Engine;
use crate::ffc::FfcParams;
use crate::runtime::ex_data::CryptoExData;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::thread::CryptoRwlock;

/// `OPENSSL_DSA_MAX_MODULUS_BITS` — `include/openssl/dsa.h:61`.
///
/// `DSA_do_verify` refuses a signature whose group's modulus is wider than this with
/// `DSA_R_MODULUS_TOO_LARGE` before it computes anything.
pub(crate) const OPENSSL_DSA_MAX_MODULUS_BITS: c_int = 10000;

/// `OPENSSL_DSA_FIPS_MIN_MODULUS_BITS` — `include/openssl/dsa.h:64`. The FIPS boundary the
/// provider's paramgen enforces.
///
/// `#[allow(dead_code)]`'s reason: **its reader is `crypto/dsa/dsa_pmeth.c`**, the
/// `EVP_PKEY_METHOD` that is slice E. The core-side generator (`dsa_gen.c`) does not read it.
#[allow(dead_code)] // read by `crypto/dsa/dsa_pmeth.c`, which is slice E
pub(crate) const OPENSSL_DSA_FIPS_MIN_MODULUS_BITS: c_int = 1024;

/// `DSA_FLAG_NO_EXP_CONSTTIME` — `include/openssl/dsa.h:77`. A zero: the bit is the *absence* of
/// the constant-time exponentiation flag, which is why it is a name rather than a bit.
///
/// `#[allow(dead_code)]`'s reason: **no authority unit on this profile reads it either** — a
/// `grep` of `crypto/dsa/`, `crypto/evp/dsa_ctrl.c` and `providers/` finds the header's
/// definition and nothing else — so there is no reader to name. It is transcribed because the
/// block it belongs to is transcribed whole, which is D327's rule for an unreachable name.
#[allow(dead_code)] // no reader in the authority on this profile
pub(crate) const DSA_FLAG_NO_EXP_CONSTTIME: c_int = 0x00;

/// `DSA_FLAG_CACHE_MONT_P` — `include/openssl/dsa.h:81`. `dsa_init` sets it on every object the
/// default table constructs, which is why a fresh `DSA`'s flag word is exactly `0x01`.
pub(crate) const DSA_FLAG_CACHE_MONT_P: c_int = 0x01;

/// `DSA_FLAG_FIPS_METHOD` — `include/openssl/dsa.h:90`. The word `openssl_dsa_meth` carries.
pub(crate) const DSA_FLAG_FIPS_METHOD: c_int = 0x0400;

/// `DSA_FLAG_NON_FIPS_ALLOW` — `include/openssl/dsa.h:98`. **The same bit as
/// [`DSA_FLAG_FIPS_METHOD`]**, and the mask `dsa_new_intern` clears.
pub(crate) const DSA_FLAG_NON_FIPS_ALLOW: c_int = 0x0400;

/// `DSA_FLAG_FIPS_CHECKED` — `include/openssl/dsa.h:99`. The bit a FIPS build sets after the
/// parameter check; no unit on this profile reads or writes it.
///
/// `#[allow(dead_code)]`'s reason: **its readers are `crypto/dsa/dsa_pmeth.c` and the FIPS
/// provider's keymgmt**, neither of which is in this slice.
#[allow(dead_code)] // read by `crypto/dsa/dsa_pmeth.c` and the FIPS provider, which are later
pub(crate) const DSA_FLAG_FIPS_CHECKED: c_int = 0x0800;

/// `DSA_PARAMGEN_TYPE_FIPS_186_4` — `include/crypto/dsa.h:28`.
pub(crate) const DSA_PARAMGEN_TYPE_FIPS_186_4: c_int = 0;
/// `DSA_PARAMGEN_TYPE_FIPS_186_2` — `include/crypto/dsa.h:29`.
pub(crate) const DSA_PARAMGEN_TYPE_FIPS_186_2: c_int = 1;
/// `DSA_PARAMGEN_TYPE_FIPS_DEFAULT` — `include/crypto/dsa.h:30`. The provider's "choose from
/// `L`" selector.
///
/// `#[allow(dead_code)]`'s reason: **its reader is `crypto/dsa/dsa_pmeth.c`**, which is slice E;
/// `ossl_dsa_generate_ffc_parameters` takes the FIPS 186-4 arm for every value that is not
/// `_186_2`, so it never names this one.
#[allow(dead_code)] // read by `crypto/dsa/dsa_pmeth.c`, which is slice E
pub(crate) const DSA_PARAMGEN_TYPE_FIPS_DEFAULT: c_int = 2;

/// `MIN_DSA_SIGN_QBITS` — `crypto/dsa/dsa_ossl.c:23`. Below this the sign path refuses rather
/// than drawing a nonce over a `q` too small to be safe for it, which is why a group whose `q` is
/// narrower than 128 bits can be *constructed* but not signed with.
pub(crate) const MIN_DSA_SIGN_QBITS: c_int = 128;

/// `MAX_DSA_SIGN_RETRIES` — `crypto/dsa/dsa_ossl.c:24`. FIPS 186-4 §4.6 requires a redo when `r`
/// or `s` is zero; this bounds the redo so bad domain parameters cannot loop forever.
pub(crate) const MAX_DSA_SIGN_RETRIES: c_int = 8;

/// `struct dsa_st` — `crypto/dsa/dsa_local.h:18-41`.
///
/// **200 bytes, alignment 8**, measured by `courts/layout/measure-dsa.c` and asserted member by
/// member below. `pad` is the type-check word the authority's own comment describes ("used to pick
/// up errors where a DSA is passed instead of a EVP_PKEY"), `version` is a four-byte `int32_t`,
/// and the embedded [`FfcParams`] starts eight-aligned at 8 with its 96 bytes.
///
/// `flags` at 120 is a four-byte `int`, so 124..128 is padding before `method_mont_p` at 128; and
/// `references` at 136 is a four-byte `_Atomic int`, so `ex_data` — two pointers — is at 144
/// rather than adjacent. `ex_data` and `engine` are inside `#ifndef FIPS_MODULE`
/// (`dsa_local.h:32-34`), which holds on this profile, so both members are present and part of the
/// layout.
#[repr(C)]
pub struct Dsa {
    /// `int pad` — the first of the two `EVP_PKEY` type-check words.
    pub(crate) pad: c_int,
    /// `int32_t version`.
    pub(crate) version: i32,
    /// `FFC_PARAMS params` — the domain parameters, **embedded by value**, so their 96 bytes are
    /// part of this object and `ossl_ffc_params_init`'s `memset` writes inside it.
    pub(crate) params: FfcParams,
    /// `BIGNUM *pub_key` — `y`, the public key.
    pub(crate) pub_key: *mut BigNum,
    /// `BIGNUM *priv_key` — `x`, the private key.
    pub(crate) priv_key: *mut BigNum,
    /// `int flags` — the `DSA_FLAG_*` bit set.
    pub(crate) flags: c_int,
    /// `BN_MONT_CTX *method_mont_p` — the cached Montgomery context, valid only while
    /// `DSA_FLAG_CACHE_MONT_P` is set.
    pub(crate) method_mont_p: *mut MontCtx,
    /// `CRYPTO_REF_COUNT references` — `_Atomic int` in this profile, so [`AtomicI32`] rather than
    /// a plain integer, exactly as [`crate::dh::Dh::references`] is.
    pub(crate) references: AtomicI32,
    /// `CRYPTO_EX_DATA ex_data` — inside `#ifndef FIPS_MODULE`.
    pub(crate) ex_data: CryptoExData,
    /// `const DSA_METHOD *meth` — borrowed, never owned.
    pub(crate) meth: *const DsaMethod,
    /// `ENGINE *engine` — inside `#ifndef FIPS_MODULE`. NULL on every object this crate can build.
    pub(crate) engine: *mut Engine,
    /// `CRYPTO_RWLOCK *lock` — guards `method_mont_p`.
    pub(crate) lock: *mut CryptoRwlock,
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `size_t dirty_cnt` — bumped by every mutator so provider caches are discarded.
    pub(crate) dirty_cnt: usize,
}

/// `struct DSA_SIG_st` — `crypto/dsa/dsa_local.h:43-46`.
///
/// **16 bytes**, two pointers, measured by the same program. It is opaque to a caller: the whole
/// surface is [`sign::DSA_SIG_new`], [`sign::DSA_SIG_get0`] and [`sign::DSA_SIG_set0`].
#[repr(C)]
pub struct DsaSig {
    /// `BIGNUM *r`.
    pub(crate) r: *mut BigNum,
    /// `BIGNUM *s`.
    pub(crate) s: *mut BigNum,
}

/// `DSA_SIG *(*dsa_do_sign)(const unsigned char *dgst, int dlen, DSA *dsa)` —
/// `crypto/dsa/dsa_local.h:50`.
pub type DsaDoSignFn =
    unsafe extern "C" fn(dgst: *const c_uchar, dlen: c_int, dsa: *mut Dsa) -> *mut DsaSig;

/// `int (*dsa_sign_setup)(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)` —
/// `crypto/dsa/dsa_local.h:51-52`. Note the **two** out-parameters: `r` is written through `rp`
/// and the inverse of `k` is *returned* through `kinvp`.
pub type DsaSignSetupFn = unsafe extern "C" fn(
    dsa: *mut Dsa,
    ctx_in: *mut BnCtx,
    kinvp: *mut *mut BigNum,
    rp: *mut *mut BigNum,
) -> c_int;

/// `int (*dsa_do_verify)(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa)` —
/// `crypto/dsa/dsa_local.h:53-54`.
pub type DsaDoVerifyFn = unsafe extern "C" fn(
    dgst: *const c_uchar,
    dgst_len: c_int,
    sig: *mut DsaSig,
    dsa: *mut Dsa,
) -> c_int;

/// `int (*dsa_mod_exp)(DSA *dsa, BIGNUM *rr, const BIGNUM *a1, const BIGNUM *p1,`
/// `const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)` —
/// `crypto/dsa/dsa_local.h:55-57`. NULL in the authority's own table.
pub type DsaModExpFn = unsafe extern "C" fn(
    dsa: *mut Dsa,
    rr: *mut BigNum,
    a1: *const BigNum,
    p1: *const BigNum,
    a2: *const BigNum,
    p2: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
    in_mont: *mut MontCtx,
) -> c_int;

/// `int (*bn_mod_exp)(DSA *dsa, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,`
/// `const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)` — `crypto/dsa/dsa_local.h:59-60`. The
/// header's own comment marks it "Can be null", and the authority's table leaves it NULL.
pub type DsaBnModExpFn = unsafe extern "C" fn(
    dsa: *mut Dsa,
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
    m_ctx: *mut MontCtx,
) -> c_int;

/// `int (*init)(DSA *dsa)` / `int (*finish)(DSA *dsa)` — `crypto/dsa/dsa_local.h:61-62`. One type
/// because the authority spells both with the same signature.
pub type DsaLifecycleFn = unsafe extern "C" fn(dsa: *mut Dsa) -> c_int;

/// `int (*dsa_paramgen)(DSA *dsa, int bits, const unsigned char *seed, int seed_len,`
/// `int *counter_ret, unsigned long *h_ret, BN_GENCB *cb)` — `crypto/dsa/dsa_local.h:65-67`.
pub type DsaParamgenFn = unsafe extern "C" fn(
    dsa: *mut Dsa,
    bits: c_int,
    seed: *const c_uchar,
    seed_len: c_int,
    counter_ret: *mut c_int,
    h_ret: *mut c_ulong,
    cb: *mut BnGencb,
) -> c_int;

/// `int (*dsa_keygen)(DSA *dsa)` — `crypto/dsa/dsa_local.h:69`.
pub type DsaKeygenFn = unsafe extern "C" fn(dsa: *mut Dsa) -> c_int;

/// `struct dsa_method` — `crypto/dsa/dsa_local.h:48-70`.
///
/// **96 bytes with twelve members**, measured with the offsets the module documentation lists. The
/// member that cannot be reasoned about from the declaration is `app_data` at **72**: `flags` is a
/// four-byte `int` at 64, so 68..72 is padding, and a pointer-sized reading of `flags` would move
/// both `app_data` and `dsa_paramgen`.
#[repr(C)]
pub struct DsaMethod {
    /// `char *name` — the string `DSA_meth_get0_name` returns and `DSA_meth_free` releases.
    pub name: *mut c_char,
    /// `DSA_SIG *(*dsa_do_sign)(const unsigned char *, int, DSA *)`.
    pub dsa_do_sign: Option<DsaDoSignFn>,
    /// `int (*dsa_sign_setup)(DSA *, BN_CTX *, BIGNUM **, BIGNUM **)`.
    pub dsa_sign_setup: Option<DsaSignSetupFn>,
    /// `int (*dsa_do_verify)(const unsigned char *, int, DSA_SIG *, DSA *)`.
    pub dsa_do_verify: Option<DsaDoVerifyFn>,
    /// `int (*dsa_mod_exp)(...)` — NULL in the authority's own table.
    pub dsa_mod_exp: Option<DsaModExpFn>,
    /// `int (*bn_mod_exp)(...)` — the header marks it "Can be null"; NULL in the authority's table.
    pub bn_mod_exp: Option<DsaBnModExpFn>,
    /// `int (*init)(DSA *)` — called at new.
    pub init: Option<DsaLifecycleFn>,
    /// `int (*finish)(DSA *)` — called at free.
    pub finish: Option<DsaLifecycleFn>,
    /// `int flags` — `DSA_FLAG_*`.
    pub(crate) flags: c_int,
    /// `void *app_data`.
    pub app_data: *mut c_void,
    /// `int (*dsa_paramgen)(...)` — NULL in the authority's own table.
    pub dsa_paramgen: Option<DsaParamgenFn>,
    /// `int (*dsa_keygen)(DSA *)` — NULL in the authority's own table.
    pub dsa_keygen: Option<DsaKeygenFn>,
}

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/dsa/dsa_meth.c` is a source-tree file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — the check D280 applied to the cipher units and D329/D331 to
/// the two DH units. It reaches an application through `CRYPTO_set_mem_functions`, so it is part of
/// the contract and `RT-DSA` compares it.
const FILE_DSA_METH: *const c_char = c"../../src/openssl-3.6.4/crypto/dsa/dsa_meth.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `DSA_METHOD *DSA_meth_new(const char *name, int flags)` — `crypto/dsa/dsa_meth.c:24-39`.
///
/// A zero-allocated table with `flags` stored and `name` duplicated. **A failed `OPENSSL_strdup`
/// releases the whole object**, so a caller that gets NULL never holds a half-built table; `flags`
/// is stored *before* the name is duplicated, which is what makes that release safe.
///
/// # Safety
///
/// `name` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_new(name: *const c_char, flags: c_int) -> *mut DsaMethod {
    // SAFETY: the caller's contract.
    unsafe {
        let dsam = CRYPTO_zalloc(core::mem::size_of::<DsaMethod>(), FILE_DSA_METH, LINE)
            .cast::<DsaMethod>();

        if !dsam.is_null() {
            (*dsam).flags = flags;
            (*dsam).name = CRYPTO_strdup(name, FILE_DSA_METH, LINE);
            if !(*dsam).name.is_null() {
                return dsam;
            }
            CRYPTO_free(dsam.cast(), FILE_DSA_METH, LINE);
        }
        core::ptr::null_mut()
    }
}

/// `void DSA_meth_free(DSA_METHOD *dsam)` — `crypto/dsa/dsa_meth.c:41-47`. NULL is a no-op, and
/// the name is released **before** the table so that a caller's allocator sees them in that order.
///
/// # Safety
///
/// `dsam` is NULL or a table [`DSA_meth_new`] or [`DSA_meth_dup`] returned.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_free(dsam: *mut DsaMethod) {
    // SAFETY: the caller's contract.
    unsafe {
        if !dsam.is_null() {
            CRYPTO_free((*dsam).name.cast(), FILE_DSA_METH, LINE);
            CRYPTO_free(dsam.cast(), FILE_DSA_METH, LINE);
        }
    }
}

/// `DSA_METHOD *DSA_meth_dup(const DSA_METHOD *dsam)` — `crypto/dsa/dsa_meth.c:49-63`.
///
/// A whole-struct `memcpy` followed by one deep field: everything but `name` is shared with the
/// original — including `app_data`, which is why the header warns that a method's application data
/// must outlive every duplicate of it. The allocation is `OPENSSL_malloc` rather than
/// `OPENSSL_zalloc`, because the copy overwrites all 96 bytes.
///
/// # Safety
///
/// `dsam` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_dup(dsam: *const DsaMethod) -> *mut DsaMethod {
    // SAFETY: the caller's contract.
    unsafe {
        let ret = CRYPTO_malloc(core::mem::size_of::<DsaMethod>(), FILE_DSA_METH, LINE)
            .cast::<DsaMethod>();

        if !ret.is_null() {
            core::ptr::copy_nonoverlapping(dsam, ret, 1);
            (*ret).name = CRYPTO_strdup((*dsam).name, FILE_DSA_METH, LINE);
            if !(*ret).name.is_null() {
                return ret;
            }
            CRYPTO_free(ret.cast(), FILE_DSA_METH, LINE);
        }
        core::ptr::null_mut()
    }
}

/// `const char *DSA_meth_get0_name(const DSA_METHOD *dsam)` — `crypto/dsa/dsa_meth.c:65-68`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get0_name(dsam: *const DsaMethod) -> *const c_char {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).name }
}

/// `int DSA_meth_set1_name(DSA_METHOD *dsam, const char *name)` — `crypto/dsa/dsa_meth.c:70-81`.
///
/// **The duplicate happens first and the old name is released second**, so a failed `strdup` leaves
/// the table's name untouched rather than freeing it and storing NULL.
///
/// # Safety
///
/// `dsam` is a live table; `name` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set1_name(dsam: *mut DsaMethod, name: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let tmpname = CRYPTO_strdup(name, FILE_DSA_METH, LINE);

        if tmpname.is_null() {
            return 0;
        }
        CRYPTO_free((*dsam).name.cast(), FILE_DSA_METH, LINE);
        (*dsam).name = tmpname;
        1
    }
}

/// `int DSA_meth_get_flags(const DSA_METHOD *dsam)` — `crypto/dsa/dsa_meth.c:83-86`.
///
/// # Safety
///
/// `dsam` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get_flags(dsam: *const DsaMethod) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).flags }
}

/// `int DSA_meth_set_flags(DSA_METHOD *dsam, int flags)` — `crypto/dsa/dsa_meth.c:88-92`. Stores
/// the word and answers 1 unconditionally.
///
/// # Safety
///
/// `dsam` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set_flags(dsam: *mut DsaMethod, flags: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).flags = flags;
    }
    1
}

/// `void *DSA_meth_get0_app_data(const DSA_METHOD *dsam)` — `crypto/dsa/dsa_meth.c:94-97`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get0_app_data(dsam: *const DsaMethod) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).app_data }
}

/// `int DSA_meth_set0_app_data(DSA_METHOD *dsam, void *app_data)` — `crypto/dsa/dsa_meth.c:99-103`.
///
/// # Safety
///
/// `dsam` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set0_app_data(
    dsam: *mut DsaMethod,
    app_data: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).app_data = app_data;
    }
    1
}

/// `DSA_SIG *(*DSA_meth_get_sign(const DSA_METHOD *dsam))(const unsigned char *, int, DSA *)` —
/// `crypto/dsa/dsa_meth.c:105-108`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get_sign(dsam: *const DsaMethod) -> Option<DsaDoSignFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).dsa_do_sign }
}

/// `int DSA_meth_set_sign(DSA_METHOD *dsam, DSA_SIG *(*sign)(const unsigned char *, int, DSA *))`
/// — `crypto/dsa/dsa_meth.c:110-115`.
///
/// # Safety
///
/// `dsam` is a live table; `sign` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set_sign(
    dsam: *mut DsaMethod,
    sign: Option<DsaDoSignFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).dsa_do_sign = sign;
    }
    1
}

/// `int (*DSA_meth_get_sign_setup(const DSA_METHOD *dsam))(DSA *, BN_CTX *, BIGNUM **, BIGNUM **)`
/// — `crypto/dsa/dsa_meth.c:117-120`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get_sign_setup(dsam: *const DsaMethod) -> Option<DsaSignSetupFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).dsa_sign_setup }
}

/// `int DSA_meth_set_sign_setup(DSA_METHOD *dsam, int (*sign_setup)(DSA *, BN_CTX *, BIGNUM **,`
/// `BIGNUM **))` — `crypto/dsa/dsa_meth.c:122-128`.
///
/// # Safety
///
/// `dsam` is a live table; `sign_setup` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set_sign_setup(
    dsam: *mut DsaMethod,
    sign_setup: Option<DsaSignSetupFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).dsa_sign_setup = sign_setup;
    }
    1
}

/// `int (*DSA_meth_get_verify(const DSA_METHOD *dsam))(const unsigned char *, int, DSA_SIG *,`
/// `DSA *)` — `crypto/dsa/dsa_meth.c:130-133`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get_verify(dsam: *const DsaMethod) -> Option<DsaDoVerifyFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).dsa_do_verify }
}

/// `int DSA_meth_set_verify(DSA_METHOD *dsam, int (*verify)(const unsigned char *, int, DSA_SIG *,`
/// `DSA *))` — `crypto/dsa/dsa_meth.c:135-140`.
///
/// # Safety
///
/// `dsam` is a live table; `verify` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set_verify(
    dsam: *mut DsaMethod,
    verify: Option<DsaDoVerifyFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).dsa_do_verify = verify;
    }
    1
}

/// `int (*DSA_meth_get_mod_exp(const DSA_METHOD *dsam))(...)` — `crypto/dsa/dsa_meth.c:142-148`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get_mod_exp(dsam: *const DsaMethod) -> Option<DsaModExpFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).dsa_mod_exp }
}

/// `int DSA_meth_set_mod_exp(DSA_METHOD *dsam, int (*mod_exp)(...))` —
/// `crypto/dsa/dsa_meth.c:150-157`.
///
/// # Safety
///
/// `dsam` is a live table; `mod_exp` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set_mod_exp(
    dsam: *mut DsaMethod,
    mod_exp: Option<DsaModExpFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).dsa_mod_exp = mod_exp;
    }
    1
}

/// `int (*DSA_meth_get_bn_mod_exp(const DSA_METHOD *dsam))(...)` — `crypto/dsa/dsa_meth.c:159-163`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get_bn_mod_exp(dsam: *const DsaMethod) -> Option<DsaBnModExpFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).bn_mod_exp }
}

/// `int DSA_meth_set_bn_mod_exp(DSA_METHOD *dsam, int (*bn_mod_exp)(...))` —
/// `crypto/dsa/dsa_meth.c:165-171`.
///
/// # Safety
///
/// `dsam` is a live table; `bn_mod_exp` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set_bn_mod_exp(
    dsam: *mut DsaMethod,
    bn_mod_exp: Option<DsaBnModExpFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).bn_mod_exp = bn_mod_exp;
    }
    1
}

/// `int (*DSA_meth_get_init(const DSA_METHOD *dsam))(DSA *)` — `crypto/dsa/dsa_meth.c:173-176`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get_init(dsam: *const DsaMethod) -> Option<DsaLifecycleFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).init }
}

/// `int DSA_meth_set_init(DSA_METHOD *dsam, int (*init)(DSA *))` — `crypto/dsa/dsa_meth.c:178-182`.
///
/// # Safety
///
/// `dsam` is a live table; `init` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set_init(
    dsam: *mut DsaMethod,
    init: Option<DsaLifecycleFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).init = init;
    }
    1
}

/// `int (*DSA_meth_get_finish(const DSA_METHOD *dsam))(DSA *)` — `crypto/dsa/dsa_meth.c:184-187`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get_finish(dsam: *const DsaMethod) -> Option<DsaLifecycleFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).finish }
}

/// `int DSA_meth_set_finish(DSA_METHOD *dsam, int (*finish)(DSA *))` —
/// `crypto/dsa/dsa_meth.c:189-193`.
///
/// # Safety
///
/// `dsam` is a live table; `finish` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set_finish(
    dsam: *mut DsaMethod,
    finish: Option<DsaLifecycleFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).finish = finish;
    }
    1
}

/// `int (*DSA_meth_get_paramgen(const DSA_METHOD *dsam))(...)` — `crypto/dsa/dsa_meth.c:195-200`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get_paramgen(dsam: *const DsaMethod) -> Option<DsaParamgenFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).dsa_paramgen }
}

/// `int DSA_meth_set_paramgen(DSA_METHOD *dsam, int (*paramgen)(...))` —
/// `crypto/dsa/dsa_meth.c:202-208`.
///
/// # Safety
///
/// `dsam` is a live table; `paramgen` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set_paramgen(
    dsam: *mut DsaMethod,
    paramgen: Option<DsaParamgenFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).dsa_paramgen = paramgen;
    }
    1
}

/// `int (*DSA_meth_get_keygen(const DSA_METHOD *dsam))(DSA *)` — `crypto/dsa/dsa_meth.c:210-213`.
///
/// # Safety
///
/// `dsam` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_get_keygen(dsam: *const DsaMethod) -> Option<DsaKeygenFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dsam).dsa_keygen }
}

/// `int DSA_meth_set_keygen(DSA_METHOD *dsam, int (*keygen)(DSA *))` —
/// `crypto/dsa/dsa_meth.c:215-219`.
///
/// # Safety
///
/// `dsam` is a live table; `keygen` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DSA_meth_set_keygen(
    dsam: *mut DsaMethod,
    keygen: Option<DsaKeygenFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dsam).dsa_keygen = keygen;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nine sentinels as *function pointers*, so `Some(const)` is an `Option<fn>` and compares
    /// with `assert_eq!` (a bare fn item is a distinct type and implements no `Debug`).
    const SENT_SIGN: DsaDoSignFn = sentinel_do_sign;
    /// The sign-setup sentinel.
    const SENT_SETUP: DsaSignSetupFn = sentinel_sign_setup;
    /// The verify sentinel.
    const SENT_VERIFY: DsaDoVerifyFn = sentinel_do_verify;
    /// The `dsa_mod_exp` sentinel.
    const SENT_MODEXP: DsaModExpFn = sentinel_mod_exp;
    /// The `bn_mod_exp` sentinel.
    const SENT_BNMODEXP: DsaBnModExpFn = sentinel_bn_mod_exp;
    /// The lifecycle (`init`/`finish`) sentinel.
    const SENT_LIFE: DsaLifecycleFn = sentinel_life;
    /// The parameter-generation sentinel.
    const SENT_PARAMGEN: DsaParamgenFn = sentinel_paramgen;
    /// The key-generation sentinel.
    const SENT_KEYGEN: DsaKeygenFn = sentinel_keygen;

    /// Stored and compared, never called. Each returns its own constant so that a transcription
    /// which *did* call one would be visible rather than merely wrong.
    unsafe extern "C" fn sentinel_do_sign(
        _dgst: *const c_uchar,
        _dlen: c_int,
        _dsa: *mut Dsa,
    ) -> *mut DsaSig {
        core::ptr::null_mut()
    }
    unsafe extern "C" fn sentinel_sign_setup(
        _dsa: *mut Dsa,
        _ctx_in: *mut BnCtx,
        _kinvp: *mut *mut BigNum,
        _rp: *mut *mut BigNum,
    ) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_do_verify(
        _dgst: *const c_uchar,
        _dgst_len: c_int,
        _sig: *mut DsaSig,
        _dsa: *mut Dsa,
    ) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_mod_exp(
        _dsa: *mut Dsa,
        _rr: *mut BigNum,
        _a1: *const BigNum,
        _p1: *const BigNum,
        _a2: *const BigNum,
        _p2: *const BigNum,
        _m: *const BigNum,
        _ctx: *mut BnCtx,
        _in_mont: *mut MontCtx,
    ) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_bn_mod_exp(
        _dsa: *mut Dsa,
        _r: *mut BigNum,
        _a: *const BigNum,
        _p: *const BigNum,
        _m: *const BigNum,
        _ctx: *mut BnCtx,
        _m_ctx: *mut MontCtx,
    ) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_life(_dsa: *mut Dsa) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_paramgen(
        _dsa: *mut Dsa,
        _bits: c_int,
        _seed: *const c_uchar,
        _seed_len: c_int,
        _counter_ret: *mut c_int,
        _h_ret: *mut c_ulong,
        _cb: *mut BnGencb,
    ) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_keygen(_dsa: *mut Dsa) -> c_int {
        7
    }

    /// **`DSA_METHOD`, field for field.** 96 bytes with `name` 0, `dsa_do_sign` 8, `dsa_sign_setup`
    /// 16, `dsa_do_verify` 24, `dsa_mod_exp` 32, `bn_mod_exp` 40, `init` 48, `finish` 56, `flags`
    /// **64**, `app_data` 72, `dsa_paramgen` 80 and `dsa_keygen` 88.
    ///
    /// The offset that cannot be reasoned about from the declaration is 72: `flags` is a four-byte
    /// `int` at 64, so 68..72 is padding, and a transcription that gave `flags` a pointer's width
    /// would move both members after it by eight while keeping a plausible-looking table.
    #[test]
    fn the_dsa_method_is_the_authoritys_shape() {
        assert_eq!(core::mem::size_of::<DsaMethod>(), 96);
        assert_eq!(core::mem::align_of::<DsaMethod>(), 8);
        assert_eq!(core::mem::offset_of!(DsaMethod, name), 0);
        assert_eq!(core::mem::offset_of!(DsaMethod, dsa_do_sign), 8);
        assert_eq!(core::mem::offset_of!(DsaMethod, dsa_sign_setup), 16);
        assert_eq!(core::mem::offset_of!(DsaMethod, dsa_do_verify), 24);
        assert_eq!(core::mem::offset_of!(DsaMethod, dsa_mod_exp), 32);
        assert_eq!(core::mem::offset_of!(DsaMethod, bn_mod_exp), 40);
        assert_eq!(core::mem::offset_of!(DsaMethod, init), 48);
        assert_eq!(core::mem::offset_of!(DsaMethod, finish), 56);
        assert_eq!(core::mem::offset_of!(DsaMethod, flags), 64);
        assert_eq!(core::mem::offset_of!(DsaMethod, app_data), 72);
        assert_eq!(core::mem::offset_of!(DsaMethod, dsa_paramgen), 80);
        assert_eq!(core::mem::offset_of!(DsaMethod, dsa_keygen), 88);
    }

    /// **`struct dsa_st` is 200 bytes** with the fourteen members at the offsets
    /// `courts/layout/measure-dsa.c` printed. The two that cannot be reasoned about from the
    /// declaration are `method_mont_p` at 128 — `flags` is a four-byte `int` at 120, so 124..128 is
    /// padding — and `ex_data` at 144, because `references` at 136 is a four-byte `_Atomic int` and
    /// `CRYPTO_EX_DATA` is two pointers. The embedded `params` at 8 is `FFC_PARAMS`: if it moved,
    /// every member after it would move with it, which is why `src/ffc/mod.rs` pins its own 96.
    #[test]
    fn the_dsa_object_is_the_authoritys_shape() {
        use core::mem::{align_of, offset_of, size_of};

        assert_eq!(size_of::<Dsa>(), 200);
        assert_eq!(align_of::<Dsa>(), 8);
        assert_eq!(offset_of!(Dsa, pad), 0);
        assert_eq!(offset_of!(Dsa, version), 4);
        assert_eq!(offset_of!(Dsa, params), 8);
        assert_eq!(offset_of!(Dsa, pub_key), 104);
        assert_eq!(offset_of!(Dsa, priv_key), 112);
        assert_eq!(offset_of!(Dsa, flags), 120);
        assert_eq!(offset_of!(Dsa, method_mont_p), 128);
        assert_eq!(offset_of!(Dsa, references), 136);
        assert_eq!(offset_of!(Dsa, ex_data), 144);
        assert_eq!(offset_of!(Dsa, meth), 160);
        assert_eq!(offset_of!(Dsa, engine), 168);
        assert_eq!(offset_of!(Dsa, lock), 176);
        assert_eq!(offset_of!(Dsa, libctx), 184);
        assert_eq!(offset_of!(Dsa, dirty_cnt), 192);
    }

    /// `struct DSA_SIG_st` is two pointers and nothing else, which is why `DSA_SIG_get0` is a
    /// two-field read and `DSA_SIG_set0`'s refusal is a two-pointer test.
    #[test]
    fn the_dsa_sig_is_two_pointers() {
        assert_eq!(core::mem::size_of::<DsaSig>(), 16);
        assert_eq!(core::mem::offset_of!(DsaSig, r), 0);
        assert_eq!(core::mem::offset_of!(DsaSig, s), 8);
    }

    /// The two public flag constants that share one bit. `0x0400` is `DSA_FLAG_FIPS_METHOD` and
    /// `DSA_FLAG_NON_FIPS_ALLOW` at once — which is why a fresh object's flag word is
    /// `DSA_FLAG_CACHE_MONT_P` and *not* `FIPS_METHOD | CACHE_MONT_P`.
    #[test]
    fn the_two_shared_flag_bits_are_one_bit() {
        assert_eq!(DSA_FLAG_FIPS_METHOD, DSA_FLAG_NON_FIPS_ALLOW);
        assert_eq!(DSA_FLAG_FIPS_METHOD, 0x0400);
        assert_ne!(DSA_FLAG_CACHE_MONT_P, DSA_FLAG_FIPS_METHOD);
        assert_ne!(DSA_FLAG_FIPS_CHECKED, DSA_FLAG_FIPS_METHOD);
        // The constructor's mask, applied to the table's own word, is what a fresh object keeps.
        assert_eq!(DSA_FLAG_FIPS_METHOD & !DSA_FLAG_NON_FIPS_ALLOW, 0);
    }

    /// **A fresh table is all NULLs**, which is `OPENSSL_zalloc`'s contribution; the name getter is
    /// not NULL because `DSA_meth_new` duplicates the caller's string.
    #[test]
    fn a_fresh_method_table_is_zeroed() {
        // SAFETY: the argument is a literal NUL-terminated string.
        let m = unsafe { DSA_meth_new(c"probe".as_ptr(), 0x1234) };
        assert!(!m.is_null());
        // SAFETY: `m` is a live table for the length of this test.
        unsafe {
            assert!((*m).dsa_do_sign.is_none());
            assert!((*m).dsa_sign_setup.is_none());
            assert!((*m).dsa_do_verify.is_none());
            assert!((*m).dsa_mod_exp.is_none());
            assert!((*m).bn_mod_exp.is_none());
            assert!((*m).init.is_none());
            assert!((*m).finish.is_none());
            assert!((*m).app_data.is_null());
            assert!((*m).dsa_paramgen.is_none());
            assert!((*m).dsa_keygen.is_none());
            assert_eq!(DSA_meth_get_flags(m), 0x1234);
            assert_eq!(
                core::ffi::CStr::from_ptr(DSA_meth_get0_name(m)).to_str(),
                Ok("probe")
            );
            DSA_meth_free(m);
        }
    }

    /// **Every one of the nine function-pointer pairs round-trips the sentinel and then NULL**, and
    /// the two value members round-trip theirs. The round trip leaves every member NULL, so one
    /// table serves all nine without order dependence.
    #[test]
    fn every_member_round_trips() {
        macro_rules! pair {
            ($t:expr, $set:ident, $get:ident, $sent:expr) => {
                assert_eq!($set($t, Some($sent)), 1);
                assert!($get($t).is_some_and(|f| core::ptr::fn_addr_eq(f, $sent)));
                assert_eq!($set($t, None), 1);
                assert!($get($t).is_none());
            };
        }

        // SAFETY: the argument is a literal NUL-terminated string; `m` is live throughout and
        // every `Some(SENT_*)` is a function this test never calls.
        let m = unsafe { DSA_meth_new(c"round".as_ptr(), 0) };
        assert!(!m.is_null());
        // SAFETY: `m` is a live table for the remainder of this test.
        unsafe {
            pair!(m, DSA_meth_set_sign, DSA_meth_get_sign, SENT_SIGN);
            pair!(
                m,
                DSA_meth_set_sign_setup,
                DSA_meth_get_sign_setup,
                SENT_SETUP
            );
            pair!(m, DSA_meth_set_verify, DSA_meth_get_verify, SENT_VERIFY);
            pair!(m, DSA_meth_set_mod_exp, DSA_meth_get_mod_exp, SENT_MODEXP);
            pair!(
                m,
                DSA_meth_set_bn_mod_exp,
                DSA_meth_get_bn_mod_exp,
                SENT_BNMODEXP
            );
            pair!(m, DSA_meth_set_init, DSA_meth_get_init, SENT_LIFE);
            pair!(m, DSA_meth_set_finish, DSA_meth_get_finish, SENT_LIFE);
            pair!(
                m,
                DSA_meth_set_paramgen,
                DSA_meth_get_paramgen,
                SENT_PARAMGEN
            );
            pair!(m, DSA_meth_set_keygen, DSA_meth_get_keygen, SENT_KEYGEN);

            // `app_data` is not a function pointer and its NULL is a value, not a refusal.
            let marker = 0x1234_usize as *mut c_void;
            assert_eq!(DSA_meth_set0_app_data(m, marker), 1);
            assert_eq!(DSA_meth_get0_app_data(m), marker);
            assert_eq!(DSA_meth_set0_app_data(m, core::ptr::null_mut()), 1);
            assert!(DSA_meth_get0_app_data(m).is_null());

            assert_eq!(DSA_meth_set_flags(m, 0x0f0f), 1);
            assert_eq!(DSA_meth_get_flags(m), 0x0f0f);

            DSA_meth_free(m);
        }
    }

    /// **`DSA_meth_dup` copies every member and deep-copies the name.** The duplicate's name is a
    /// different pointer holding the same bytes; every other member is shared *by value*.
    #[test]
    fn dup_copies_the_table_and_deep_copies_the_name() {
        // SAFETY: the argument is a literal NUL-terminated string; both tables are live until
        // their own frees.
        unsafe {
            let orig = DSA_meth_new(c"dup-me".as_ptr(), 0x42);
            assert!(!orig.is_null());
            assert_eq!(DSA_meth_set_keygen(orig, Some(SENT_KEYGEN)), 1);
            let marker = 0x5678_usize as *mut c_void;
            assert_eq!(DSA_meth_set0_app_data(orig, marker), 1);

            let copy = DSA_meth_dup(orig);
            assert!(!copy.is_null());
            assert_eq!(DSA_meth_get_flags(copy), 0x42);
            assert_eq!(
                core::ffi::CStr::from_ptr(DSA_meth_get0_name(copy)).to_str(),
                Ok("dup-me")
            );
            assert_eq!(DSA_meth_get0_app_data(copy), marker);
            assert!(
                DSA_meth_get_keygen(copy).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_KEYGEN))
            );
            // The name is a second allocation, not a shared pointer.
            assert_ne!(DSA_meth_get0_name(copy), DSA_meth_get0_name(orig));

            DSA_meth_free(orig);
            // The duplicate survives the original's release, name and all.
            assert_eq!(
                core::ffi::CStr::from_ptr(DSA_meth_get0_name(copy)).to_str(),
                Ok("dup-me")
            );
            DSA_meth_free(copy);
        }
    }

    /// **`DSA_meth_set1_name` duplicates first and releases second.** A successful set changes the
    /// name's identity, and `DSA_meth_set1_name(m, NULL)` answers 0 and leaves the old name in
    /// place, because a NULL argument makes `CRYPTO_strdup` answer NULL.
    #[test]
    fn set1_name_is_a_duplicate_then_a_release() {
        // SAFETY: the arguments are literal NUL-terminated strings, or NULL; `m` is live.
        unsafe {
            let m = DSA_meth_new(c"first".as_ptr(), 0);
            assert!(!m.is_null());
            let before = DSA_meth_get0_name(m);
            assert_eq!(DSA_meth_set1_name(m, c"second".as_ptr()), 1);
            let after = DSA_meth_get0_name(m);
            assert_ne!(before, after);
            assert_eq!(core::ffi::CStr::from_ptr(after).to_str(), Ok("second"));
            assert_eq!(DSA_meth_set1_name(m, core::ptr::null()), 0);
            assert_eq!(
                core::ffi::CStr::from_ptr(DSA_meth_get0_name(m)).to_str(),
                Ok("second")
            );
            DSA_meth_free(m);
        }
    }

    /// NULL is accepted where the authority accepts it: `DSA_meth_free(NULL)` is a no-op.
    #[test]
    fn free_accepts_null() {
        // SAFETY: NULL is the documented no-op argument.
        unsafe { DSA_meth_free(core::ptr::null_mut()) };
    }

    /// **The default table is the authority's own, member for member.** `DSA_OpenSSL()` and
    /// `DSA_get_default_method()` answer one address, `DSA_get_default_method` answers the table
    /// `DSA_OpenSSL` names, and the five members the authority leaves NULL are `None` here.
    #[test]
    fn the_default_method_is_the_authoritys_table() {
        use crate::dsa::ossl::{DSA_OpenSSL, DSA_get_default_method, DSA_set_default_method};

        assert_eq!(DSA_get_default_method(), DSA_OpenSSL());
        // SAFETY: the default table is this module's own static and is never freed.
        unsafe {
            let m = DSA_OpenSSL();
            assert!(!m.is_null());
            assert_eq!(DSA_meth_get_flags(m), DSA_FLAG_FIPS_METHOD);
            assert!(DSA_meth_get_sign(m).is_some());
            assert!(DSA_meth_get_sign_setup(m).is_some());
            assert!(DSA_meth_get_verify(m).is_some());
            assert!(DSA_meth_get_init(m).is_some());
            assert!(DSA_meth_get_finish(m).is_some());
            assert!(DSA_meth_get_mod_exp(m).is_none());
            assert!(DSA_meth_get_bn_mod_exp(m).is_none());
            assert!(DSA_meth_get0_app_data(m).is_null());
            assert!(DSA_meth_get_paramgen(m).is_none());
            assert!(DSA_meth_get_keygen(m).is_none());
            assert_eq!(
                core::ffi::CStr::from_ptr(DSA_meth_get0_name(m)).to_str(),
                Ok("OpenSSL DSA method")
            );

            // A caller may install its own table — including NULL — and the getter answers it.
            DSA_set_default_method(core::ptr::null());
            assert!(DSA_get_default_method().is_null());
            DSA_set_default_method(DSA_OpenSSL());
            assert_eq!(DSA_get_default_method(), DSA_OpenSSL());
        }
    }

    /// **A fresh object's whole observable surface** is the constructor's contract: the default
    /// method installed, the method's `init` run, no engine, no parameters, no key, and the three
    /// readers at their `-1` sentinel. `DSA_test_flags(d, DSA_FLAG_FIPS_METHOD)` is **0** because
    /// the constructor clears the bit the table's flag word shares with `DSA_FLAG_NON_FIPS_ALLOW`.
    #[test]
    fn a_fresh_object_is_the_constructed_state() {
        use crate::dsa::object::{
            DSA_bits, DSA_free, DSA_get0_engine, DSA_get0_g, DSA_get0_key, DSA_get0_p,
            DSA_get0_pqg, DSA_get0_priv_key, DSA_get0_pub_key, DSA_get0_q, DSA_new,
            DSA_security_bits, DSA_test_flags, DSA_up_ref,
        };

        // SAFETY: every call below is on the object this test constructs, and each out-parameter is
        // a live local the authority writes through.
        unsafe {
            let dsa = DSA_new();
            assert!(!dsa.is_null());
            assert!(DSA_get0_engine(dsa).is_null());
            assert_ne!(DSA_test_flags(dsa, DSA_FLAG_CACHE_MONT_P), 0);
            assert_eq!(DSA_test_flags(dsa, DSA_FLAG_FIPS_METHOD), 0);
            assert_eq!(DSA_bits(dsa), -1);
            assert_eq!(DSA_security_bits(dsa), -1);
            assert!(DSA_get0_p(dsa).is_null());
            assert!(DSA_get0_q(dsa).is_null());
            assert!(DSA_get0_g(dsa).is_null());
            assert!(DSA_get0_priv_key(dsa).is_null());
            assert!(DSA_get0_pub_key(dsa).is_null());

            let mut p: *const BigNum = core::ptr::null();
            let mut q: *const BigNum = core::ptr::null();
            let mut g: *const BigNum = core::ptr::null();
            DSA_get0_pqg(dsa, &raw mut p, &raw mut q, &raw mut g);
            assert!(p.is_null() && q.is_null() && g.is_null());
            let mut pub_key: *const BigNum = core::ptr::null();
            let mut priv_key: *const BigNum = core::ptr::null();
            DSA_get0_key(dsa, &raw mut pub_key, &raw mut priv_key);
            assert!(pub_key.is_null() && priv_key.is_null());

            // The reference is real: one free leaves the object for the second.
            assert_eq!(DSA_up_ref(dsa), 1);
            DSA_free(dsa);
            DSA_free(dsa);
        }
    }

    /// **A 1024/160 group, a key pair, and a sign-then-verify round trip with two refusals.** The
    /// smallest group a *key* can be generated over — `ffc_validate_LN`'s non-FIPS arm requires
    /// `L >= 1024 && N >= 160` for DSA, so a 512-bit group is constructible and signable-with but
    /// not `DSA_generate_key`-able, which is why this test does not use the probe's smaller shape.
    ///
    /// Every assertion is a *property*: the two halves of the signature are in `[1, q)`, the
    /// verdict is 1, and a tampered copy and a changed digest both refuse. No `r`, no `s` and no
    /// private key is ever compared by value.
    #[test]
    fn a_signature_verifies_and_a_tampered_one_does_not() {
        use crate::bn::arith::{BN_add_word, BN_ucmp};
        use crate::bn::bignum::{BN_dup, BN_is_zero};
        use crate::dsa::gen::DSA_generate_parameters_ex;
        use crate::dsa::key::DSA_generate_key;
        use crate::dsa::object::{DSA_free, DSA_get0_q, DSA_new};
        use crate::dsa::sign::{
            DSA_SIG_free, DSA_SIG_get0, DSA_SIG_new, DSA_SIG_set0, DSA_do_sign,
        };
        use crate::dsa::vrf::DSA_do_verify;

        // SAFETY: every call below is on an object this test owns; the digest is a local buffer and
        // every signature is one this test built.
        unsafe {
            let dsa = DSA_new();
            assert!(!dsa.is_null());
            // 1024 bits with no seed is the legacy FIPS 186-2 generator with a 160-bit `q`.
            assert_eq!(
                DSA_generate_parameters_ex(
                    dsa,
                    1024,
                    core::ptr::null(),
                    0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                ),
                1
            );
            assert_eq!(DSA_generate_key(dsa), 1);

            let dgst: [u8; 20] = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c,
            ];
            let sig = DSA_do_sign(dgst.as_ptr(), dgst.len() as c_int, dsa);
            assert!(!sig.is_null());
            assert_eq!(
                DSA_do_verify(dgst.as_ptr(), dgst.len() as c_int, sig, dsa),
                1
            );

            // `r` and `s` are in `[1, q)` and neither is zero — FIPS 186-4 §4.6's rejection rule
            // stated as a property.
            let mut r: *const BigNum = core::ptr::null();
            let mut s: *const BigNum = core::ptr::null();
            DSA_SIG_get0(sig, &raw mut r, &raw mut s);
            let q = DSA_get0_q(dsa);
            assert!(!r.is_null() && !s.is_null());
            assert_eq!(BN_is_zero(r), 0);
            assert_eq!(BN_is_zero(s), 0);
            assert!(BN_ucmp(r, q) < 0);
            assert!(BN_ucmp(s, q) < 0);

            // A tampered signature is a *new* object: `r + 1` against the signer's `s`.
            let bad = DSA_SIG_new();
            assert!(!bad.is_null());
            let r_bad = BN_dup(r);
            assert_eq!(BN_add_word(r_bad, 1), 1);
            assert_eq!(DSA_SIG_set0(bad, r_bad, BN_dup(s)), 1);
            assert_eq!(
                DSA_do_verify(dgst.as_ptr(), dgst.len() as c_int, bad, dsa),
                0
            );
            DSA_SIG_free(bad);

            // A changed digest is a refusal too, and the original still verifies afterwards.
            let mut other = dgst;
            other[0] ^= 0x01;
            assert_eq!(
                DSA_do_verify(other.as_ptr(), other.len() as c_int, sig, dsa),
                0
            );
            assert_eq!(
                DSA_do_verify(dgst.as_ptr(), dgst.len() as c_int, sig, dsa),
                1
            );

            // `DSA_SIG_new` gives two NULL halves and `DSA_SIG_set0` refuses a NULL pair.
            let fresh = DSA_SIG_new();
            assert!(!fresh.is_null());
            let mut fr: *const BigNum = core::ptr::null();
            let mut fs: *const BigNum = core::ptr::null();
            DSA_SIG_get0(fresh, &raw mut fr, &raw mut fs);
            assert!(fr.is_null() && fs.is_null());
            assert_eq!(DSA_SIG_set0(fresh, core::ptr::null_mut(), BN_dup(s)), 0);
            DSA_SIG_free(fresh);

            DSA_SIG_free(sig);
            DSA_free(dsa);
        }
    }
}
