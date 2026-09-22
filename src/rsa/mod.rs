//! `crypto/rsa/` — the `RSA` object and its method table.
//!
//! This module is Phase 8.4's, and it is being built in the slices D283 measured rather than all at
//! once, because the block is 150 labels and its parts have different prerequisites. What is here
//! now is the **method table** (`crypto/rsa/rsa_meth.c`, D284), the **object layer**
//! (`crypto/rsa/rsa_lib.c` plus `rsa_crpt.c`'s accessors, D321), and **all fifteen of the padding
//! functions** (`rsa_none.c`, `rsa_x931.c`, `rsa_pk1.c`'s two add/check pairs, `rsa_oaep.c`'s
//! `PKCS1_MGF1` with its two adds and two checks, and `rsa_pss.c`'s two adds) -- the RAND-free
//! half in D285 and the randomised half in D323.
//!
//! **The padding family's block expired rather than being worked around.** D285 measured five of
//! the randomised *add* labels plus the type-2 *check* as Phase 9 hand-offs on `RAND_bytes_ex` and
//! recorded the deferral; D313 landed the random layer, D322 measured that the deferral was no
//! longer a deferral at all, and D323 lands them. One of D285's coordinates is corrected by it:
//! the function whose refusal is randomised is `ossl_rsa_padding_check_PKCS1_type_2_TLS`
//! (`rsa_pk1.c:546`, whose `RAND_priv_bytes_ex` sits at `:569`), **not**
//! `RSA_padding_check_PKCS1_type_2` (`:170`), which is a pure function of its input and always
//! was -- it was in the hand-off list under the TLS function's call.
//!
//! **D285's second finding is unchanged by that correction, and it is why the constructor is still
//! open.** `RAND_bytes_ex` is reached by the five randomised adds and — one level further out — by
//! the `RSA` object's own constructor, because `rsa_new_intern` takes its method from
//! `RSA_get_default_method()` and that table's first member is `rsa_ossl_public_encrypt`, which
//! pads randomly through `ossl_rsa_padding_add_PKCS1_type_2_ex` (`rsa_ossl.c:144`). So the four
//! constructor labels remain recorded Phase 9 hand-offs in
//! `forensics/tools/phase8_obligations.py`'s `BLOCKED_HANDOFFS`, and the table they would occupy
//! is what still cannot be built.
//!
//! The other six slices, and what each still needs:
//!
//! * **B**, 33 labels, **landed** (D284): the method table.
//! * **C**, the padding add/check pairs for the five paddings (15) -- **landed** (D285 for the
//!   RAND-free half, D323 for the rest): the `none` and X9.31 paddings, `RSA_X931_hash_id`,
//!   PKCS#1 v1.5 type 1, the two OAEP checks and `PKCS1_MGF1` in D285's commit, then the five
//!   randomised adds and the type-2 check in D323;
//! * **D**, `RSA_public_encrypt`/`_decrypt`, `RSA_private_*`, `RSA_sign`/`RSA_verify`, the two
//!   `PKCS1_PSS` verifiers and `PKCS1_MGF1` (11) -- and this is also where `RSA_PKCS1_OpenSSL`'s
//!   table belongs, because thirteen of its fifteen members are `rsa_ossl_*` entry points that
//!   slice D defines and the other two are `0`;
//! * **A**, the `RSA` object and its accessors (41 labels) -- its *shape* is here, because
//!   `RSA_METHOD`'s members take `RSA *` and the measured layout is what slice A's accessors will
//!   hand out as writable addresses; its lifetime and accessor *functions* are not. **Its lifetime
//!   is a Phase 9 hand-off** and its accessors cannot be courted before it, because a probe has no
//!   other way to obtain an `RSA *` (D285);
//! * **E**, the `EVP_PKEY_CTX_set_rsa_*`/`get_rsa_*` controls and the three `EVP_PKEY_*RSA`
//!   bridges (26);
//! * **F**, the four `d2i_`/`i2d_` pairs and their `_it` tables (19), which need 8.8's
//!   `ossl_*_asn1_meth` machinery and therefore cannot close inside 8.4;
//! * **G**, `RSA_check_key`/`_ex` and the two printers (4).
//!
//! **The `RSA_METHOD` object is 120 bytes with fifteen members, measured** by
//! `courts/layout/measure-rsa-ctx.c`: `name` 0, the four `rsa_*_enc`/`_dec` entry points at 8, 16,
//! 24 and 32, `rsa_mod_exp` 40, `bn_mod_exp` 48, `init` 56, `finish` 64, `flags` **72**,
//! `app_data` 80, `rsa_sign` 88, `rsa_verify` 96, `rsa_keygen` 104 and `rsa_multi_prime_keygen`
//! 112. The four bytes at 76..80 are the padding `app_data`'s alignment leaves after the `int
//! flags`, which is why `flags` and `app_data` are not adjacent in the way their declaration order
//! suggests.
//!
//! **Six of the fifteen members are nullable, and the authority's own tables are the evidence.**
//! `rsa_pkcs1_ossl_meth` (`rsa_ossl.c:60-79`) writes the integer `0` into `rsa_sign` and
//! `rsa_verify`, both of its `rsa_keygen` members are NULL, and the header's own comments mark
//! `rsa_mod_exp` and `bn_mod_exp` "Can be null". So every function-pointer member is an `Option`,
//! and the null is expressed as `None` rather than by a fabricated address.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::sync::atomic::AtomicI32;

use crate::bn::arith::{BN_cmp, BN_div, BN_gcd, BN_mod_inverse, BN_mod_mul, BN_mul, BN_sub};
use crate::bn::bignum::{
    BN_dup, BN_free, BN_is_odd, BN_is_one, BN_new, BN_num_bits, BN_value_one, BigNum,
};
use crate::bn::ctx::{
    BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new, BN_CTX_new_ex, BN_CTX_start, BnCtx, BnGencb,
};
use crate::bn::mont::MontCtx;
use crate::bn::primes::{
    BN_X931_derive_prime_ex, BN_X931_generate_Xpq, BN_X931_generate_prime_ex, BN_check_prime,
};
use crate::digest::sha2::SHA256_DIGEST_LENGTH;
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EvpMd,
};
use crate::evp::pkey_asn1::Engine;
use crate::mac::hmac::{
    HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update, HmacCtx,
};
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::ex_data::CryptoExData;
use crate::runtime::mem::{cleanse, CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::{NID_sha1, NID_sha256, NID_sha384, NID_sha512};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::runtime::thread::CryptoRwlock;

pub mod ameth;
pub mod asn1;
pub(crate) mod backend;
pub mod ctrl;
pub mod gen;
mod mp;
pub(crate) mod mp_names;
pub mod object;
pub mod ossl;
pub mod pss;
pub(crate) mod schemes;
pub mod sign;
pub(crate) mod sp800;

/// `RSA_METHOD_FLAG_NO_CHECK` — `include/openssl/rsa.h:64`. The only `RSA_METHOD_FLAG_*` constant
/// this authority still defines; its siblings were absorbed into `RSA_FLAG_*`.
///
/// `#[allow(dead_code)]`'s reason: **the one reader is 8.8's.** The authority tests it only in
/// `crypto/rsa/rsa_ameth.c:118-119`, inside `ossl_rsa_asn1_meth`'s comparison callback, so the
/// constant is a transcription of the header's `#define` that acquires a caller when 8.8 lands --
/// not here. The unit test below is what keeps its value honest until then.
#[allow(dead_code)]
const RSA_METHOD_FLAG_NO_CHECK: c_int = 0x0001;

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/rsa/rsa_meth.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — measured with `strings` on
/// `build/.../crypto/rsa/libcrypto-lib-rsa_meth.o`, the same check D279 and D280 applied to the
/// cipher units. It matters here for the same reason: `file` reaches an application through
/// `CRYPTO_set_mem_functions`.
const FILE_RSA_METH: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_meth.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `RSA_PSS_PARAMS_30` — `include/crypto/rsa.h:20-27`. Measured **20** bytes: five `int`s, not the
/// three pointers its member name in the `RSA` object suggests. It is the *provider-side* PSS
/// restriction held by value inside the object, where `RSA_PSS_PARAMS *pss` is the older
/// pointer-to-ASN.1-structure form `rsa_ameth.c` uses for the same fact.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RsaPssParams30 {
    /// `int hash_algorithm_nid`.
    pub hash_algorithm_nid: c_int,
    /// `struct { int algorithm_nid; int hash_algorithm_nid; } mask_gen`.
    pub mask_gen: RsaPssMaskGen,
    /// `int salt_len`.
    pub salt_len: c_int,
    /// `int trailer_field`.
    pub trailer_field: c_int,
}

/// The anonymous `mask_gen` member of [`RsaPssParams30`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RsaPssMaskGen {
    /// `int algorithm_nid` — "currently always `NID_mgf1`", per the header's own comment.
    pub algorithm_nid: c_int,
    /// `int hash_algorithm_nid`.
    pub hash_algorithm_nid: c_int,
}

/// `RSA_PSS_PARAMS` — the ASN.1-restriction form, declared in `rsa.h` and defined in
/// `crypto/rsa/rsa_asn1.c`. Five pointers: the four `ASN1_*` fields the `RSA_PSS_PARAMS` template
/// encodes, plus `maskHash`, the decoded hash the `rsa_pss_cb` free hook releases and the template
/// never touches.
///
/// It was opaque here until D348, because nothing in this slice dereferenced one: slice F's
/// `d2i_`/`i2d_` pair and `RSA_PSS_PARAMS_dup` are where its members acquire a user, and this
/// commit lands them. The offsets are the authority's field order, asserted in `src/rsa/asn1.rs`.
#[repr(C)]
pub struct RsaPssParams {
    /// `X509_ALGOR *hashAlgorithm`.
    pub hash_algorithm: *mut crate::asn1::x_algor::X509Algor,
    /// `X509_ALGOR *maskGenAlgorithm`.
    pub mask_gen_algorithm: *mut crate::asn1::x_algor::X509Algor,
    /// `ASN1_INTEGER *saltLength`.
    pub salt_length: *mut crate::asn1::layout::Asn1String,
    /// `ASN1_INTEGER *trailerField`.
    pub trailer_field: *mut crate::asn1::layout::Asn1String,
    /// `X509_ALGOR *maskHash` — "Decoded hash algorithm from maskGenAlgorithm".
    pub mask_hash: *mut crate::asn1::x_algor::X509Algor,
}

/// `RSA_OAEP_PARAMS` — the OAEP counterpart of [`RsaPssParams`], declared in `rsa.h` and defined in
/// `crypto/rsa/rsa_asn1.c`. Four pointers: the three `X509_ALGOR` fields the template encodes and
/// the `maskHash` the `rsa_oaep_cb` free hook releases.
#[repr(C)]
pub struct RsaOaepParams {
    /// `X509_ALGOR *hashFunc`.
    pub hash_func: *mut crate::asn1::x_algor::X509Algor,
    /// `X509_ALGOR *maskGenFunc`.
    pub mask_gen_func: *mut crate::asn1::x_algor::X509Algor,
    /// `X509_ALGOR *pSourceFunc`.
    pub p_source_func: *mut crate::asn1::x_algor::X509Algor,
    /// `X509_ALGOR *maskHash` — "Decoded hash algorithm from maskGenFunc".
    pub mask_hash: *mut crate::asn1::x_algor::X509Algor,
}

/// `struct rsa_st` — `crypto/rsa/rsa_local.h:22-101`.
///
/// Measured **216** bytes, eight-aligned, by `courts/layout/measure-rsa-ctx.c`, with every member
/// offset recorded there. Two things about it are the measurement's point rather than its detail:
///
/// * **`dummy_zero` is first on purpose.** The header says "THIS MUST REMAIN THE FIRST FIELD", and
///   the field exists to catch an `EVP_PKEY` handed to an `RSA` function. A transcription that
///   reordered members for tidiness would silently delete that check's premise.
/// * **The layout is profile-dependent.** `pss`, `prime_infos` and `ex_data` sit inside
///   `#ifndef FIPS_MODULE`, so a build that took the module branch is 32 bytes shorter from
///   `prime_infos` onwards. This crate reproduces the non-module object, which is the one the
///   pinned authority's `libcrypto` publishes.
#[repr(C)]
pub struct Rsa {
    /// `int dummy_zero` — "always zero", the first field by the header's instruction.
    pub dummy_zero: c_int,
    /// `OSSL_LIB_CTX *libctx`.
    pub libctx: *mut c_void,
    /// `int32_t version`.
    pub version: i32,
    /// `const RSA_METHOD *meth`.
    pub meth: *const RsaMethod,
    /// `ENGINE *engine` — "functional reference if 'meth' is ENGINE-provided".
    pub engine: *mut Engine,
    /// `BIGNUM *n`.
    pub n: *mut BigNum,
    /// `BIGNUM *e`.
    pub e: *mut BigNum,
    /// `BIGNUM *d`.
    pub d: *mut BigNum,
    /// `BIGNUM *p`.
    pub p: *mut BigNum,
    /// `BIGNUM *q`.
    pub q: *mut BigNum,
    /// `BIGNUM *dmp1`.
    pub dmp1: *mut BigNum,
    /// `BIGNUM *dmq1`.
    pub dmq1: *mut BigNum,
    /// `BIGNUM *iqmp`.
    pub iqmp: *mut BigNum,
    /// `RSA_PSS_PARAMS_30 pss_params` — the provider-side PSS restriction, by value.
    pub pss_params: RsaPssParams30,
    /// `RSA_PSS_PARAMS *pss` — inside `#ifndef FIPS_MODULE`.
    pub pss: *mut RsaPssParams,
    /// `STACK_OF(RSA_PRIME_INFO) *prime_infos` — inside `#ifndef FIPS_MODULE`.
    pub prime_infos: *mut OpenSslStack,
    /// `CRYPTO_EX_DATA ex_data` — inside `#ifndef FIPS_MODULE`.
    pub ex_data: CryptoExData,
    /// `CRYPTO_REF_COUNT references` — `_Atomic int` in this profile, which is why the field is
    /// [`AtomicI32`] and not a plain integer: `RSA_up_ref`/`RSA_free` reach it with an atomic
    /// read-modify-write. It stays four bytes at offset 160, so the retype is layout-neutral and
    /// the object's own test below is what proves that rather than asserts it.
    pub references: AtomicI32,
    /// `int flags`.
    pub flags: c_int,
    /// `BN_MONT_CTX *_method_mod_n`.
    pub _method_mod_n: *mut MontCtx,
    /// `BN_MONT_CTX *_method_mod_p`.
    pub _method_mod_p: *mut MontCtx,
    /// `BN_MONT_CTX *_method_mod_q`.
    pub _method_mod_q: *mut MontCtx,
    /// `void *blindings_sa` — a `DEFINE_SPARSE_ARRAY_OF(BN_BLINDING)`. The object has **no**
    /// `blinding` member in this version: blinding moved into the per-operation context, which is
    /// why D283's reconnaissance found `ossl_rsa_alloc_blinding` rather than a field.
    pub blindings_sa: *mut c_void,
    /// `CRYPTO_RWLOCK *lock`.
    pub lock: *mut CryptoRwlock,
    /// `int dirty_cnt` — bumped by `RSA_set0_*` so a cached Montgomery value is discarded rather
    /// than reused.
    pub dirty_cnt: c_int,
}

/// `RSA_PRIME_INFO` — `crypto/rsa/rsa_local.h:18-25`: one extra prime's parameters, held by the
/// `STACK_OF(RSA_PRIME_INFO)` that `Rsa::prime_infos` points at.
///
/// Measured **40** bytes, eight-aligned, five pointers, at the offsets the test below pins. It
/// lives here, beside [`Rsa`], rather than in the object module: **two** translation units read
/// and write its members — `rsa_lib.c`'s accessors and `rsa_mp.c`'s five functions — so a second
/// declaration anywhere else would be a second layout for one object.
///
/// `m` is a `BN_MONT_CTX *`, so its type is [`MontCtx`] and not `c_void`: the field is written by
/// no one in this stratum yet, but typing it as the authority does keeps the day it is written
/// from being a retype.
#[repr(C)]
pub struct RsaPrimeInfo {
    /// `BIGNUM *r` — the extra prime.
    pub r: *mut BigNum,
    /// `BIGNUM *d` — its exponent.
    pub d: *mut BigNum,
    /// `BIGNUM *t` — its coefficient.
    pub t: *mut BigNum,
    /// `BIGNUM *pp` — "save product of primes prior to this one".
    pub pp: *mut BigNum,
    /// `BN_MONT_CTX *m` — the cached Montgomery context.
    pub m: *mut MontCtx,
}

/// The five-argument crypt entry points: `rsa_pub_enc`, `rsa_pub_dec`, `rsa_priv_enc` and
/// `rsa_priv_dec` all have this shape.
pub type RsaCryptFn = unsafe extern "C" fn(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    rsa: *mut Rsa,
    padding: c_int,
) -> c_int;

/// `int (*rsa_mod_exp)(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)`.
pub type RsaModExpFn = unsafe extern "C" fn(
    r0: *mut BigNum,
    i: *const BigNum,
    rsa: *mut Rsa,
    ctx: *mut BnCtx,
) -> c_int;

/// `int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
/// BN_MONT_CTX *m_ctx)`.
pub type RsaBnModExpFn = unsafe extern "C" fn(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
    m_ctx: *mut MontCtx,
) -> c_int;

/// `int (*init)(RSA *rsa)` and `int (*finish)(RSA *rsa)`.
pub type RsaLifecycleFn = unsafe extern "C" fn(rsa: *mut Rsa) -> c_int;

/// `int (*rsa_sign)(int type, const unsigned char *m, unsigned int m_length, unsigned char
/// *sigret, unsigned int *siglen, const RSA *rsa)`.
pub type RsaSignFn = unsafe extern "C" fn(
    type_: c_int,
    m: *const c_uchar,
    m_length: c_uint,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    rsa: *const Rsa,
) -> c_int;

/// `int (*rsa_verify)(int dtype, const unsigned char *m, unsigned int m_length, const unsigned
/// char *sigbuf, unsigned int siglen, const RSA *rsa)`.
pub type RsaVerifyFn = unsafe extern "C" fn(
    dtype: c_int,
    m: *const c_uchar,
    m_length: c_uint,
    sigbuf: *const c_uchar,
    siglen: c_uint,
    rsa: *const Rsa,
) -> c_int;

/// `int (*rsa_keygen)(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)`.
pub type RsaKeygenFn =
    unsafe extern "C" fn(rsa: *mut Rsa, bits: c_int, e: *mut BigNum, cb: *mut BnGencb) -> c_int;

/// `int (*rsa_multi_prime_keygen)(RSA *rsa, int bits, int primes, BIGNUM *e, BN_GENCB *cb)`.
pub type RsaMultiPrimeKeygenFn = unsafe extern "C" fn(
    rsa: *mut Rsa,
    bits: c_int,
    primes: c_int,
    e: *mut BigNum,
    cb: *mut BnGencb,
) -> c_int;

/// `struct rsa_meth_st` — `crypto/rsa/rsa_local.h:103-146`.
///
/// Measured **120** bytes with the fifteen members at the offsets the module documentation lists.
/// `flags` is an `int` and `app_data` is a pointer, so the four bytes at 76..80 are padding and the
/// two are not adjacent; a transcription that made `flags` pointer-sized would be eight bytes too
/// wide and would move `rsa_sign` onwards.
#[repr(C)]
pub struct RsaMethod {
    /// `char *name` — the string `RSA_meth_get0_name` returns and `RSA_meth_free` releases.
    pub name: *mut c_char,
    /// `int (*rsa_pub_enc)(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
    /// int padding)`.
    pub rsa_pub_enc: Option<RsaCryptFn>,
    /// `int (*rsa_pub_dec)(...)`.
    pub rsa_pub_dec: Option<RsaCryptFn>,
    /// `int (*rsa_priv_enc)(...)`.
    pub rsa_priv_enc: Option<RsaCryptFn>,
    /// `int (*rsa_priv_dec)(...)`.
    pub rsa_priv_dec: Option<RsaCryptFn>,
    /// `int (*rsa_mod_exp)(...)` — "Can be null".
    pub rsa_mod_exp: Option<RsaModExpFn>,
    /// `int (*bn_mod_exp)(...)` — "Can be null".
    pub bn_mod_exp: Option<RsaBnModExpFn>,
    /// `int (*init)(RSA *rsa)` — called at new.
    pub init: Option<RsaLifecycleFn>,
    /// `int (*finish)(RSA *rsa)` — called at free.
    pub finish: Option<RsaLifecycleFn>,
    /// `int flags` — `RSA_METHOD_FLAG_*`.
    pub flags: c_int,
    /// `char *app_data`.
    pub app_data: *mut c_char,
    /// `int (*rsa_sign)(...)` — `0` in the authority's own PKCS#1 table.
    pub rsa_sign: Option<RsaSignFn>,
    /// `int (*rsa_verify)(...)` — `0` in the authority's own PKCS#1 table.
    pub rsa_verify: Option<RsaVerifyFn>,
    /// `int (*rsa_keygen)(...)` — NULL in both of the authority's own tables.
    pub rsa_keygen: Option<RsaKeygenFn>,
    /// `int (*rsa_multi_prime_keygen)(...)` — NULL in both of the authority's own tables.
    pub rsa_multi_prime_keygen: Option<RsaMultiPrimeKeygenFn>,
}

/// `RSA_METHOD *RSA_meth_new(const char *name, int flags)` — `rsa_meth.c:20-35`.
///
/// **A failed `OPENSSL_strdup` releases the whole object**, so a caller that gets NULL never holds
/// a half-built table. `flags` is stored *before* the name is duplicated, which is what makes that
/// release safe.
///
/// # Safety
/// `name` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_new(name: *const c_char, flags: c_int) -> *mut RsaMethod {
    // SAFETY: the caller's contract.
    unsafe {
        let meth = CRYPTO_zalloc(core::mem::size_of::<RsaMethod>(), FILE_RSA_METH, LINE)
            .cast::<RsaMethod>();

        if !meth.is_null() {
            (*meth).flags = flags;
            (*meth).name = CRYPTO_strdup(name, FILE_RSA_METH, LINE);
            if !(*meth).name.is_null() {
                return meth;
            }
            CRYPTO_free(meth.cast(), FILE_RSA_METH, LINE);
        }
        core::ptr::null_mut()
    }
}

/// `void RSA_meth_free(RSA_METHOD *meth)` — `rsa_meth.c:37-43`. NULL is a no-op, and the name is
/// released before the table so that a caller's allocator sees them in that order.
///
/// # Safety
/// `meth` is NULL or a table [`RSA_meth_new`] or [`RSA_meth_dup`] returned.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_free(meth: *mut RsaMethod) {
    // SAFETY: the caller's contract.
    unsafe {
        if !meth.is_null() {
            CRYPTO_free((*meth).name.cast(), FILE_RSA_METH, LINE);
            CRYPTO_free(meth.cast(), FILE_RSA_METH, LINE);
        }
    }
}

/// `RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth)` — `rsa_meth.c:45-60`.
///
/// **A whole-struct `memcpy` followed by one deep field.** Everything but `name` is shared with the
/// original -- including `app_data`, which is why the header warns that a method's application data
/// must outlive every duplicate of it. A NULL `meth->name` makes `OPENSSL_strdup` answer NULL and
/// therefore makes the *duplicate* fail, because this crate's `CRYPTO_strdup` mirrors the
/// authority's and refuses NULL rather than inventing an empty string.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_dup(meth: *const RsaMethod) -> *mut RsaMethod {
    // SAFETY: the caller's contract.
    unsafe {
        let ret = CRYPTO_malloc(core::mem::size_of::<RsaMethod>(), FILE_RSA_METH, LINE)
            .cast::<RsaMethod>();

        if !ret.is_null() {
            core::ptr::copy_nonoverlapping(meth, ret, 1);
            (*ret).name = CRYPTO_strdup((*meth).name, FILE_RSA_METH, LINE);
            if !(*ret).name.is_null() {
                return ret;
            }
            CRYPTO_free(ret.cast(), FILE_RSA_METH, LINE);
        }
        core::ptr::null_mut()
    }
}

/// `const char *RSA_meth_get0_name(const RSA_METHOD *meth)` — `rsa_meth.c:62-65`.
///
/// # Safety
/// `meth` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get0_name(meth: *const RsaMethod) -> *const c_char {
    // SAFETY: the caller's contract.
    unsafe { (*meth).name }
}

/// `int RSA_meth_set1_name(RSA_METHOD *meth, const char *name)` — `rsa_meth.c:67-78`.
///
/// **The duplicate happens first and the old name is released second**, so a failed `strdup` leaves
/// the table's name untouched rather than freeing it and storing NULL.
///
/// # Safety
/// `meth` is a live table; `name` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set1_name(meth: *mut RsaMethod, name: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let tmpname = CRYPTO_strdup(name, FILE_RSA_METH, LINE);

        if tmpname.is_null() {
            return 0;
        }
        CRYPTO_free((*meth).name.cast(), FILE_RSA_METH, LINE);
        (*meth).name = tmpname;
        1
    }
}

/// `int RSA_meth_get_flags(const RSA_METHOD *meth)` — `rsa_meth.c:80-83`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_flags(meth: *const RsaMethod) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*meth).flags }
}

/// `int RSA_meth_set_flags(RSA_METHOD *meth, int flags)` — `rsa_meth.c:85-89`. Always answers 1.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_flags(meth: *mut RsaMethod, flags: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).flags = flags;
        1
    }
}

/// `void *RSA_meth_get0_app_data(const RSA_METHOD *meth)` — `rsa_meth.c:91-94`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get0_app_data(meth: *const RsaMethod) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { (*meth).app_data.cast() }
}

/// `int RSA_meth_set0_app_data(RSA_METHOD *meth, void *app_data)` — `rsa_meth.c:96-100`. Always
/// answers 1 and takes ownership of **nothing**: the caller must keep the object alive for as long
/// as every duplicate of this table.
///
/// # Safety
/// `meth` is a live table; `app_data` outlives it or is NULL.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set0_app_data(
    meth: *mut RsaMethod,
    app_data: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).app_data = app_data.cast();
        1
    }
}

/// `int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))(...)` — `rsa_meth.c:102-106`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_pub_enc(meth: *const RsaMethod) -> Option<RsaCryptFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).rsa_pub_enc }
}

/// `int RSA_meth_set_pub_enc(RSA_METHOD *meth, int (*pub_enc)(...))` — `rsa_meth.c:108-115`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_pub_enc(
    meth: *mut RsaMethod,
    f: Option<RsaCryptFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).rsa_pub_enc = f;
        1
    }
}

/// `int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))(...)` — `rsa_meth.c:117-121`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_pub_dec(meth: *const RsaMethod) -> Option<RsaCryptFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).rsa_pub_dec }
}

/// `int RSA_meth_set_pub_dec(RSA_METHOD *meth, int (*pub_dec)(...))` — `rsa_meth.c:123-130`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_pub_dec(
    meth: *mut RsaMethod,
    f: Option<RsaCryptFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).rsa_pub_dec = f;
        1
    }
}

/// `int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))(...)` — `rsa_meth.c:132-136`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_priv_enc(meth: *const RsaMethod) -> Option<RsaCryptFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).rsa_priv_enc }
}

/// `int RSA_meth_set_priv_enc(RSA_METHOD *meth, int (*priv_enc)(...))` — `rsa_meth.c:138-145`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_priv_enc(
    meth: *mut RsaMethod,
    f: Option<RsaCryptFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).rsa_priv_enc = f;
        1
    }
}

/// `int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))(...)` — `rsa_meth.c:147-151`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_priv_dec(meth: *const RsaMethod) -> Option<RsaCryptFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).rsa_priv_dec }
}

/// `int RSA_meth_set_priv_dec(RSA_METHOD *meth, int (*priv_dec)(...))` — `rsa_meth.c:153-160`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_priv_dec(
    meth: *mut RsaMethod,
    f: Option<RsaCryptFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).rsa_priv_dec = f;
        1
    }
}

/// `int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))(...)` — `rsa_meth.c:163-166`. The member the header marks "Can be null".
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_mod_exp(meth: *const RsaMethod) -> Option<RsaModExpFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).rsa_mod_exp }
}

/// `int RSA_meth_set_mod_exp(RSA_METHOD *meth, int (*mod_exp)(...))` — `rsa_meth.c:168-174`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_mod_exp(
    meth: *mut RsaMethod,
    f: Option<RsaModExpFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).rsa_mod_exp = f;
        1
    }
}

/// `int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))(...)` — `rsa_meth.c:177-181`. The second member the header marks "Can be null".
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_bn_mod_exp(meth: *const RsaMethod) -> Option<RsaBnModExpFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).bn_mod_exp }
}

/// `int RSA_meth_set_bn_mod_exp(RSA_METHOD *meth, int (*bn_mod_exp)(...))` — `rsa_meth.c:183-193`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_bn_mod_exp(
    meth: *mut RsaMethod,
    f: Option<RsaBnModExpFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).bn_mod_exp = f;
        1
    }
}

/// `int (*RSA_meth_get_init(const RSA_METHOD *meth))(RSA *rsa)` — `rsa_meth.c:196-199`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_init(meth: *const RsaMethod) -> Option<RsaLifecycleFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).init }
}

/// `int RSA_meth_set_init(RSA_METHOD *meth, int (*init)(RSA *rsa))` — `rsa_meth.c:201-205`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_init(
    meth: *mut RsaMethod,
    f: Option<RsaLifecycleFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).init = f;
        1
    }
}

/// `int (*RSA_meth_get_finish(const RSA_METHOD *meth))(RSA *rsa)` — `rsa_meth.c:208-211`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_finish(meth: *const RsaMethod) -> Option<RsaLifecycleFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).finish }
}

/// `int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish)(RSA *rsa))` — `rsa_meth.c:213-217`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_finish(
    meth: *mut RsaMethod,
    f: Option<RsaLifecycleFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).finish = f;
        1
    }
}

/// `int (*RSA_meth_get_sign(const RSA_METHOD *meth))(...)` — `rsa_meth.c:219-225`. `0` in the authority's own PKCS#1 table, so this getter answers NULL for the default method.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_sign(meth: *const RsaMethod) -> Option<RsaSignFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).rsa_sign }
}

/// `int RSA_meth_set_sign(RSA_METHOD *meth, int (*sign)(...))` — `rsa_meth.c:227-235`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_sign(meth: *mut RsaMethod, f: Option<RsaSignFn>) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).rsa_sign = f;
        1
    }
}

/// `int (*RSA_meth_get_verify(const RSA_METHOD *meth))(...)` — `rsa_meth.c:237-242`. The second member the PKCS#1 table leaves NULL.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_verify(meth: *const RsaMethod) -> Option<RsaVerifyFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).rsa_verify }
}

/// `int RSA_meth_set_verify(RSA_METHOD *meth, int (*verify)(...))` — `rsa_meth.c:244-252`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_verify(
    meth: *mut RsaMethod,
    f: Option<RsaVerifyFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).rsa_verify = f;
        1
    }
}

/// `int (*RSA_meth_get_keygen(const RSA_METHOD *meth))(...)` — `rsa_meth.c:254-257`. NULL in both of the authority's own tables.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_keygen(meth: *const RsaMethod) -> Option<RsaKeygenFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).rsa_keygen }
}

/// `int RSA_meth_set_keygen(RSA_METHOD *meth, int (*keygen)(...))` — `rsa_meth.c:259-265`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_keygen(
    meth: *mut RsaMethod,
    f: Option<RsaKeygenFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).rsa_keygen = f;
        1
    }
}

/// `int (*RSA_meth_get_multi_prime_keygen(const RSA_METHOD *meth))(...)` — `rsa_meth.c:267-270`. NULL in both of the authority's own tables.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_get_multi_prime_keygen(
    meth: *const RsaMethod,
) -> Option<RsaMultiPrimeKeygenFn> {
    // SAFETY: the caller's contract.
    unsafe { (*meth).rsa_multi_prime_keygen }
}

/// `int RSA_meth_set_multi_prime_keygen(RSA_METHOD *meth, int (*keygen)(...))` — `rsa_meth.c:272-279`.
///
/// # Safety
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_multi_prime_keygen(
    meth: *mut RsaMethod,
    f: Option<RsaMultiPrimeKeygenFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*meth).rsa_multi_prime_keygen = f;
        1
    }
}

/// `const RSA_METHOD *RSA_null_method(void)` — `rsa_ossl.c:99-102`.
///
/// **It answers NULL, not a table of stubs.** The name reads like the `rsa_null_meth` such a
/// function would once have returned, but this authority's body is a single `return NULL;` -- so a
/// caller that guards on a non-NULL answer is guarding on nothing, and a transcription that
/// invented a default-method table here would change what that caller does.
///
/// # Safety
/// None: the answer is a constant.
#[no_mangle]
pub extern "C" fn RSA_null_method() -> *const RsaMethod {
    core::ptr::null()
}

// =============================================================================================
// Slice C, first part — the RAND-free half of the padding functions (D285)
// =============================================================================================
//
// Three of the eight padding *add* functions need `RAND_bytes_ex` for the bytes they insert
// `rsa_pk1.c:147`, `rsa_oaep.c:122`, `rsa_pss.c`'s salt), and three of the six *checks* need it
// for implicit rejection. What lands here first is the half whose output is a **pure function of
// its input**: the `none` padding, X9.31, PKCS#1 v1.5 type 1, and the X9.31 hash ids. The other
// half was recorded as a Phase 9 hand-off in `docs/DECISIONS.md` D285; **that record expired and the
// half landed in D323**, at the second Slice C banner further down this file. The two functions
// below are neither half: they are `rsa_pk1.c`'s other two internals, landed last because
// `rsa_ossl_private_decrypt` is the first caller they ever had (`docs/DECISIONS.md` D325).

/// `RSA_PKCS1_PADDING_SIZE` — `include/openssl/rsa.h:206`. Eleven: the two header octets, eight
/// mandatory `0xFF` octets and the separating zero.
///
/// `pub(crate)` rather than private because `rsa_sign.c` is its second reader: `RSA_sign` and
/// `RSA_sign_ASN1_OCTET_STRING` both compare an encoded length plus these eleven octets against
/// `RSA_size`, and `src/rsa/sign.rs` imports this one rather than declaring a second copy.
pub(crate) const RSA_PKCS1_PADDING_SIZE: c_int = 11;

/// `int RSA_padding_add_none(unsigned char *to, int tlen, const unsigned char *from, int flen)` —
/// `rsa_none.c:20-35`.
///
/// **Both length disagreements are refusals**, and they raise *different* reasons: too long is
/// `RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE` and too short is `RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE`. The
/// `none` padding is the one that does not pad, so the message must be exactly the modulus width.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_none(
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if flen > tlen {
            raise_site(&err_sites::RSA_NONE_24);
            return 0;
        }
        if flen < tlen {
            raise_site(&err_sites::RSA_NONE_29);
            return 0;
        }
        core::ptr::copy_nonoverlapping(from, to, flen as usize);
        1
    }
}

/// `int RSA_padding_check_none(unsigned char *to, int tlen, const unsigned char *from, int flen,
/// int num)` — `rsa_none.c:37-49`.
///
/// **It left-aligns by zero-filling**, not by stripping: the message is copied to the *end* of the
/// output buffer and the leading `tlen - flen` bytes are zeroed. The `num` argument is accepted and
/// read nowhere, which is the authority's own signature rather than a transcription choice.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_check_none(
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
    _num: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if flen > tlen {
            raise_site(&err_sites::RSA_NONE_42);
            return -1;
        }
        core::ptr::write_bytes(to, 0, (tlen - flen) as usize);
        core::ptr::copy_nonoverlapping(from, to.offset((tlen - flen) as isize), flen as usize);
        tlen
    }
}

/// `int RSA_padding_add_X931(unsigned char *to, int tlen, const unsigned char *from, int flen)` —
/// `rsa_x931.c:43-77`.
///
/// The `j == 0` arm is the whole point of the header: it emits the single octet `0x6A`, which is
/// the four-bit header `0x6` and the four-bit terminator `0xA` **in one byte**, where the padding
/// case emits `0x6B`, the `0xBB` run and `0xBA` as separate octets. A transcription that always took
/// the second path would be one byte too long for the smallest legal key.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_X931(
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let j = tlen - flen - 2;

        if j < 0 {
            raise_site(&err_sites::RSA_X931_56);
            return -1;
        }
        let mut p = to;

        if j == 0 {
            *p = 0x6a;
            p = p.offset(1);
        } else {
            *p = 0x6b;
            p = p.offset(1);
            if j > 1 {
                core::ptr::write_bytes(p, 0xbb, (j - 1) as usize);
                p = p.offset((j - 1) as isize);
            }
            *p = 0xba;
            p = p.offset(1);
        }
        core::ptr::copy_nonoverlapping(from, p, flen as usize);
        *p.offset(flen as isize) = 0xcc;
        1
    }
}

/// `int RSA_padding_check_X931(unsigned char *to, int tlen, const unsigned char *from, int flen,
/// int num)` — `rsa_x931.c:79-122`.
///
/// Three distinct refusals, and the third is the one a reader gets wrong: an `0x6B` header
/// followed immediately by the terminator (`i == 0`) is **invalid padding**, because the format
/// requires at least one padding octet between them. `num != flen` is checked first, so a
/// truncated input is refused as an invalid header rather than read past its end.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_check_X931(
    to: *mut c_uchar,
    _tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
    num: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut p = from;
        let mut i: c_int = 0;

        if num != flen || (*p != 0x6a && *p != 0x6b) {
            raise_site(&err_sites::RSA_X931_87);
            return -1;
        }
        let header = *p;
        p = p.offset(1);

        if header == 0x6b {
            let limit = flen - 3;

            while i < limit {
                let c = *p;
                p = p.offset(1);
                if c == 0xba {
                    break;
                }
                if c != 0xbb {
                    raise_site(&err_sites::RSA_X931_98);
                    return -1;
                }
                i += 1;
            }
            if i == 0 {
                raise_site(&err_sites::RSA_X931_106);
                return -1;
            }
            let j = limit - i;
            if *p.offset(j as isize) != 0xcc {
                raise_site(&err_sites::RSA_X931_115);
                return -1;
            }
            core::ptr::copy_nonoverlapping(p, to, j as usize);
            return j;
        }
        let j = flen - 2;
        if *p.offset(j as isize) != 0xcc {
            raise_site(&err_sites::RSA_X931_115);
            return -1;
        }
        core::ptr::copy_nonoverlapping(p, to, j as usize);
        j
    }
}

/// `int RSA_X931_hash_id(int nid)` — `rsa_x931.c:131-147`.
///
/// The ISO/IEC 10118 part numbers, and the four are **not** in the order the digests were
/// standardised: SHA-384 is `0x36` and SHA-512 is `0x35`. An unknown NID answers `-1`, which is
/// what a caller writing the trailer must refuse on.
///
/// # Safety
/// None: the answer depends on the argument alone.
#[no_mangle]
pub extern "C" fn RSA_X931_hash_id(nid: c_int) -> c_int {
    // A comparison chain rather than a `match`: the four subjects are `const`s named after the
    // authority's own `NID_*` spelling, and a constant pattern trips `non_upper_case_globals` —
    // the lint is right about Rust naming and the authority's spelling is part of this crate's
    // transcription, so the spelling is kept and the pattern form is the one that goes.
    if nid == NID_sha1 {
        0x33
    } else if nid == NID_sha256 {
        0x34
    } else if nid == NID_sha384 {
        0x36
    } else if nid == NID_sha512 {
        0x35
    } else {
        -1
    }
}

/// `int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen, const unsigned char *from,
/// int flen)` — `rsa_pk1.c:34-52`.
///
/// `00 || 01 || 0xFF... || 00 || D`. Nothing here is random: block type 1 is the *signing*
/// padding, where the `0xFF` run is fixed, and that is why it can land without the RAND stratum
/// while its type-2 sibling cannot.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_type_1(
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if flen > (tlen - RSA_PKCS1_PADDING_SIZE) {
            raise_site(&err_sites::RSA_PK1_38);
            return 0;
        }
        let mut p = to;

        *p = 0;
        p = p.offset(1);
        *p = 1;
        p = p.offset(1);
        let j = tlen - 3 - flen;
        core::ptr::write_bytes(p, 0xff, j as usize);
        p = p.offset(j as isize);
        *p = 0;
        p = p.offset(1);
        core::ptr::copy_nonoverlapping(from, p, flen as usize);
        1
    }
}

/// `int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen, const unsigned char *from,
/// int flen, int num)` — `rsa_pk1.c:55-121`.
///
/// **The leading zero is optional.** A decoded block arrives with `num == flen` and starts `00 01`;
/// a caller that already stripped the leading zero arrives with `num == flen + 1`. Both are
/// accepted, and the rest of the walk is the same. The eight-octet minimum `0xFF` run is what
/// `i < 8` refuses, and it is a **security** parameter rather than a format detail.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_check_PKCS1_type_1(
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
    num: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if num < RSA_PKCS1_PADDING_SIZE {
            return -1;
        }
        let mut p = from;
        let mut flen = flen;

        if num == flen {
            if *p != 0x00 {
                raise_site(&err_sites::RSA_PK1_78);
                return -1;
            }
            p = p.offset(1);
            flen -= 1;
        }
        if num != (flen + 1) || *p != 0x01 {
            raise_site(&err_sites::RSA_PK1_85);
            return -1;
        }
        p = p.offset(1);

        let j = flen - 1;
        let mut i: c_int = 0;

        while i < j {
            if *p != 0xff {
                if *p == 0 {
                    p = p.offset(1);
                    break;
                }
                raise_site(&err_sites::RSA_PK1_97);
                return -1;
            }
            p = p.offset(1);
            i += 1;
        }
        if i == j {
            raise_site(&err_sites::RSA_PK1_105);
            return -1;
        }
        if i < 8 {
            raise_site(&err_sites::RSA_PK1_110);
            return -1;
        }
        i += 1;
        let j = j - i;
        if j > tlen {
            raise_site(&err_sites::RSA_PK1_116);
            return -1;
        }
        core::ptr::copy_nonoverlapping(p, to, j as usize);
        j
    }
}

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`. Sixty-four, the widest digest this crate
/// publishes.
const EVP_MAX_MD_SIZE: usize = 64;

/// `int PKCS1_MGF1(unsigned char *mask, long len, const unsigned char *seed, long seedlen,
/// const EVP_MD *dgst)` — `rsa_oaep.c:350-393`.
///
/// NIST SP 800-56B section 7.2.2.2's mask generation function, and the **counter is big-endian and
/// four octets wide** even though the loop counter is a `long` -- a transcription that wrote the
/// counter in native order, or widened it to eight octets, would produce a mask that is correct for
/// the first block and wrong for every later one. The final partial block is truncated to the
/// caller's remaining length rather than written whole.
///
/// **`len <= 0` answers `0`, not `-1`**: the loop's condition is `outlen < len`, so a
/// non-positive length performs no work and the function reaches its success label. That is the
/// authority's own behaviour and a caller relying on it would break under a "reject empty"
/// transcription.
///
/// # Safety
/// `mask` is writable for `len` bytes; `seed` is readable for `seedlen`; `dgst` is a live digest
/// method.
#[no_mangle]
pub unsafe extern "C" fn PKCS1_MGF1(
    mask: *mut c_uchar,
    len: c_long,
    seed: *const c_uchar,
    seedlen: c_long,
    dgst: *const EvpMd,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let c = EVP_MD_CTX_new();
        let mut md = [0u8; EVP_MAX_MD_SIZE];
        let mut cnt = [0u8; 4];
        let mut i: c_long = 0;
        let mut outlen: c_long = 0;

        // The authority's `goto err`: every exit that is not the loop's own condition reports
        // `-1`, and the `cleanse` and the context release happen on both paths.
        let completed = 'body: {
            if c.is_null() {
                break 'body false;
            }
            let mdlen = EVP_MD_get_size(dgst);

            if mdlen <= 0 {
                break 'body false;
            }
            while outlen < len {
                cnt[0] = ((i >> 24) & 255) as u8;
                cnt[1] = ((i >> 16) & 255) as u8;
                cnt[2] = ((i >> 8) & 255) as u8;
                cnt[3] = (i & 255) as u8;
                if EVP_DigestInit_ex(c, dgst, core::ptr::null_mut()) == 0
                    || EVP_DigestUpdate(c, seed.cast(), seedlen as usize) == 0
                    || EVP_DigestUpdate(c, cnt.as_ptr().cast(), 4) == 0
                {
                    break 'body false;
                }
                if outlen + mdlen as c_long <= len {
                    if EVP_DigestFinal_ex(c, mask.offset(outlen as isize), core::ptr::null_mut())
                        == 0
                    {
                        break 'body false;
                    }
                    outlen += mdlen as c_long;
                } else {
                    if EVP_DigestFinal_ex(c, md.as_mut_ptr(), core::ptr::null_mut()) == 0 {
                        break 'body false;
                    }
                    core::ptr::copy_nonoverlapping(
                        md.as_ptr(),
                        mask.offset(outlen as isize),
                        (len - outlen) as usize,
                    );
                    outlen = len;
                }
                i += 1;
            }
            true
        };
        cleanse(md.as_mut_ptr(), md.len());
        EVP_MD_CTX_free(c);
        if completed {
            0
        } else {
            -1
        }
    }
}

/// The allocation-tracking `file` argument for `rsa_oaep.c`'s allocations.
///
/// Like `crypto/rsa/rsa_meth.c` above, `rsa_oaep.c` is a source-tree file, so its `__FILE__`
/// carries the `../../src/openssl-3.6.4/` prefix. The string is observable through
/// `CRYPTO_set_mem_functions`, so the prefix is not cosmetic.
const FILE_RSA_OAEP: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_oaep.c".as_ptr();

/// `int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen, const unsigned char *from,
/// int flen, int num, const unsigned char *param, int plen)` — `rsa_oaep.c:160-166`.
///
/// The default-digest wrapper: it forwards to `RSA_padding_check_PKCS1_OAEP_mgf1` with `md` and
/// `mgf1md` both NULL, which that function turns into `EVP_sha1()` for both. PKCS #1 v2.2's default
/// hash is SHA-1, so this is the historical entry point and the `_mgf1` form is the one a caller
/// uses to choose otherwise.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes; `param` is readable for
/// `plen` bytes, and NULL with `plen == 0` is the empty label.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_check_PKCS1_OAEP(
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
    num: c_int,
    param: *const c_uchar,
    plen: c_int,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged; both digest arguments are NULL, which the
    // callee documents as "use the default".
    unsafe {
        RSA_padding_check_PKCS1_OAEP_mgf1(
            to,
            tlen,
            from,
            flen,
            num,
            param,
            plen,
            core::ptr::null(),
            core::ptr::null(),
        )
    }
}

/// `int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen, const unsigned char *from,
/// int flen, int num, const unsigned char *param, int plen, const EVP_MD *md,
/// const EVP_MD *mgf1md)` — `rsa_oaep.c:168-341`.
///
/// PKCS #1 v2.2 section 7.1.2's EME-OAEP decoding check, written the way the authority writes it:
/// **every validity decision is folded into `good` with the constant-time helpers**, and the
/// plaintext is written back with a masked, duplicated move so that neither the pass/fail bit nor
/// the plaintext length leaks through timing.
///
/// The authority's own notes, preserved because each explains a non-obvious choice:
///
/// * `em` is the encoded message, zero-padded to exactly `num` bytes: `em = Y || maskedSeed ||
///   maskedDB`.
/// * `num` is the modulus length and `flen` the encoded message length, so for any `from` that came
///   out of a decryption `flen <= num` must hold; independently, `num >= 2 * mdlen + 2` must hold
///   for the modulus, per PKCS #1 v2.2 section 7.1.2. Those two checks leak no side-channel
///   information.
/// * The caller is encouraged to hand in a zero-padded message from `BN_bn2binpad`. Because `from`
///   cannot be read out of bounds, an invariant memory-access pattern is impossible when `from` was
///   not already zero-padded — so the copy loop advances a pointer under a mask rather than
///   indexing.
/// * The first byte must be zero, **and whether it was must not leak**; this is the fix for James
///   H. Manger's chosen-ciphertext attack ("A Chosen Ciphertext Attack on RSA Optimal Asymmetric
///   Encryption Padding (OAEP) [...]", CRYPTO 2001).
/// * Once `good` has absorbed every check it is zero unless the plaintext was valid, so
///   plaintext-awareness means timing side-channels are no longer a concern.
/// * The in-place move copies memory back in a way that does not reveal the size of the data being
///   copied: parts of the buffer are copied multiple times, once per set bit of the real length,
///   under a mask, so clear bits do an identically-shaped non-copy. Its cost is O(N*log(N)).
/// * To avoid chosen-ciphertext attacks the error raised on failure must not reveal which kind of
///   decoding error happened. In FIPS builds libcrypto owns the error stack and the trick below
///   cannot be used, so the authority there puts no error on the stack at all; the arm reproduced
///   here is the `#ifndef FIPS_MODULE` one.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes; `param` is readable for
/// `plen` bytes (NULL with 0 is the empty label); `md` and `mgf1md` are NULL or live digest
/// methods.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_check_PKCS1_OAEP_mgf1(
    to: *mut c_uchar,
    mut tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
    num: c_int,
    param: *const c_uchar,
    plen: c_int,
    md: *const EvpMd,
    mgf1md: *const EvpMd,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        // The authority writes `dblen = 0` and `db = NULL` here; neither initial value is ever
        // read (`dblen` is assigned before the first `goto cleanup`, and `db` is assigned as the
        // first act of the `'body` block), so Rust declares them where they are first written.
        let mut mlen: c_int = -1;
        let mut good: u32 = 0;
        let db: *mut c_uchar;
        let mut em: *mut c_uchar = core::ptr::null_mut();
        let mut seed = [0u8; EVP_MAX_MD_SIZE];

        let mut md = md;
        if md.is_null() {
            // The authority's `#ifndef FIPS_MODULE` arm only; this crate has no FIPS branch.
            md = crate::evp::legacy_sha::EVP_sha1();
        }
        let mut mgf1md = mgf1md;
        if mgf1md.is_null() {
            mgf1md = md;
        }

        // SAFETY: `md` is live (the default above when the caller passed NULL).
        let mdlen: c_int = EVP_MD_get_size(md);

        if tlen <= 0 || flen <= 0 || mdlen <= 0 {
            return -1;
        }
        // `num` is the modulus length and `flen` the encoded message length: `flen <= num` for any
        // decrypted block, and `num >= 2 * mdlen + 2` for the modulus. Neither check leaks.
        if num < flen || num < 2 * mdlen + 2 {
            raise_site(&err_sites::RSA_OAEP_222);
            return -1;
        }

        let dblen: c_int = num - mdlen - 1;

        let completed = 'body: {
            // SAFETY: `dblen` is positive because `num >= 2 * mdlen + 2`.
            db = crate::runtime::mem::CRYPTO_malloc(dblen as usize, FILE_RSA_OAEP, LINE)
                .cast::<c_uchar>();
            if db.is_null() {
                break 'body false;
            }

            // SAFETY: `num` is positive.
            em = crate::runtime::mem::CRYPTO_malloc(num as usize, FILE_RSA_OAEP, LINE)
                .cast::<c_uchar>();
            if em.is_null() {
                break 'body false;
            }

            // Copy `from` (up to `flen` bytes) into the tail of `em` (`num` bytes): right-aligned,
            // zero-padded on the left. The source pointer is advanced under a mask so the same
            // addresses are touched whatever `flen` is, and `from` is never read before its start.
            let mut from = from;
            let mut flen = flen;
            let mut i: c_int;
            let mut mask: u32;
            from = from.offset(flen as isize);
            em = em.offset(num as isize);
            i = 0;
            while i < num {
                mask = !crate::runtime::constant_time::constant_time_is_zero_u32(flen as u32);
                flen = flen.wrapping_sub((1 & mask) as c_int);
                from = from.offset(-((1 & mask) as isize));
                em = em.offset(-1);
                *em = ((*from) as u32 & mask) as u8;
                i += 1;
            }

            // The first byte must be zero; whether it was must not leak. Manger's chosen-ciphertext
            // attack is the reason.
            good = crate::runtime::constant_time::constant_time_is_zero_u32(*em as u32);

            let maskedseed = em.offset(1);
            let maskeddb = em.offset((1 + mdlen) as isize);

            if PKCS1_MGF1(
                seed.as_mut_ptr(),
                mdlen as c_long,
                maskeddb,
                dblen as c_long,
                mgf1md,
            ) != 0
            {
                break 'body false;
            }
            i = 0;
            while i < mdlen {
                seed[i as usize] ^= *maskedseed.offset(i as isize);
                i += 1;
            }

            if PKCS1_MGF1(db, dblen as c_long, seed.as_ptr(), mdlen as c_long, mgf1md) != 0 {
                break 'body false;
            }
            i = 0;
            while i < dblen {
                *db.offset(i as isize) ^= *maskeddb.offset(i as isize);
                i += 1;
            }

            let mut phash = [0u8; EVP_MAX_MD_SIZE];
            if crate::evp::digest::EVP_Digest(
                param.cast::<c_void>(),
                plen as usize,
                phash.as_mut_ptr(),
                core::ptr::null_mut(),
                md,
                core::ptr::null_mut(),
            ) == 0
            {
                break 'body false;
            }

            good &= crate::runtime::constant_time::constant_time_is_zero_u32(
                crate::runtime::mem::CRYPTO_memcmp(
                    db.cast::<c_void>(),
                    phash.as_ptr().cast::<c_void>(),
                    mdlen as usize,
                ) as u32,
            );

            let mut found_one_byte: u32 = 0;
            let mut one_index: c_int = 0;
            i = mdlen;
            while i < dblen {
                // The padding is a number of 0-bytes followed by a 1.
                let equals1 = crate::runtime::constant_time::constant_time_eq_u32(
                    *db.offset(i as isize) as u32,
                    1,
                );
                let equals0 = crate::runtime::constant_time::constant_time_is_zero_u32(
                    *db.offset(i as isize) as u32,
                );
                one_index = crate::runtime::constant_time::constant_time_select_int(
                    !found_one_byte & equals1,
                    i,
                    one_index,
                );
                found_one_byte |= equals1;
                good &= found_one_byte | equals0;
                i += 1;
            }

            good &= found_one_byte;

            // At this point `good` is zero unless the plaintext was valid, so plaintext-awareness
            // ensures timing side-channels are no longer a concern.
            let msg_index = one_index + 1;
            mlen = dblen - msg_index;

            // For good measure, do this check in constant time as well.
            good &= crate::runtime::constant_time::constant_time_ge_u32(tlen as u32, mlen as u32);

            // Move the result in place by `dblen - mdlen - 1 - mlen` bytes to the left. Then, if
            // `good`, move `mlen` bytes from `db + mdlen + 1` to `to`; otherwise leave `to`
            // unchanged. The copy is arranged so it does not reveal the size of the data being
            // copied via a timing side channel: parts of the buffer are copied multiple times,
            // based on the bits set in the real length, and clear bits do a non-copy with an
            // identical access pattern. Overall complexity O(N*log(N)).
            tlen = crate::runtime::constant_time::constant_time_select_int(
                crate::runtime::constant_time::constant_time_lt_u32(
                    (dblen - mdlen - 1) as u32,
                    tlen as u32,
                ),
                dblen - mdlen - 1,
                tlen,
            );
            let mut msg_index = 1;
            while msg_index < dblen - mdlen - 1 {
                mask = !crate::runtime::constant_time::constant_time_eq_u32(
                    (msg_index & (dblen - mdlen - 1 - mlen)) as u32,
                    0,
                );
                i = mdlen + 1;
                while i < dblen - msg_index {
                    let keep = *db.offset(i as isize);
                    let moved = *db.offset((i + msg_index) as isize);
                    *db.offset(i as isize) = crate::runtime::constant_time::constant_time_select_8(
                        mask as u8, moved, keep,
                    );
                    i += 1;
                }
                msg_index <<= 1;
            }
            i = 0;
            while i < tlen {
                mask = good
                    & crate::runtime::constant_time::constant_time_lt_u32(i as u32, mlen as u32);
                let keep = *to.offset(i as isize);
                let moved = *db.offset((i + mdlen + 1) as isize);
                *to.offset(i as isize) =
                    crate::runtime::constant_time::constant_time_select_8(mask as u8, moved, keep);
                i += 1;
            }

            true
        };

        if completed {
            // To avoid chosen-ciphertext attacks the error must not reveal which kind of decoding
            // error happened; `err_clear_last_constant_time` then removes it again when the
            // plaintext was in fact good. This is the authority's `#ifndef FIPS_MODULE` arm.
            raise_site(&err_sites::RSA_OAEP_332);
            crate::runtime::err::err_clear_last_constant_time((1 & good) as c_int);
        }

        // The authority's `cleanup:` label, reached both by falling through and by every
        // `break 'body false` above.
        crate::runtime::mem::cleanse(seed.as_mut_ptr(), EVP_MAX_MD_SIZE);
        crate::runtime::mem::CRYPTO_clear_free(
            db.cast::<c_void>(),
            dblen as usize,
            FILE_RSA_OAEP,
            LINE,
        );
        crate::runtime::mem::CRYPTO_clear_free(
            em.cast::<c_void>(),
            num as usize,
            FILE_RSA_OAEP,
            LINE,
        );

        crate::runtime::constant_time::constant_time_select_int(good, mlen, -1)
    }
}

// Slice C, second part — the randomised half of the padding functions (D323)
// =============================================================================================
//
// The other six of the fifteen. Five are *adds* whose inserted bytes the format requires to be
// unpredictable — the type-2 padding, both OAEP seeds and both PSS salts — and they reach
// `RAND_bytes_ex` through the context their caller supplies. The sixth is the PKCS#1 v1.5 type-2
// *check*, and it is here because D285's table said so rather than because it is randomised: the
// `RAND_priv_bytes_ex` that put the label in the hand-off list is
// `ossl_rsa_padding_check_PKCS1_type_2_TLS`'s (`rsa_pk1.c:569`), a different function in the same
// file whose body answers a *TLS* decoding failure with a random premaster secret. This one's
// refusal is a constant-time `-1` and a raised error, and its body is a pure function of its
// input — which is why it could have landed with D285's half, and why it is landed here rather
// than left for a stratum that has nothing to do with it.

/// The allocation-tracking `file` argument for `rsa_pk1.c`'s allocation.
///
/// Measured the same way as [`FILE_RSA_METH`] and [`FILE_RSA_OAEP`]: `strings` on
/// `forensics/authorities/build/openssl-3.6.4-production/crypto/rsa/libcrypto-lib-rsa_pk1.o`
/// carries the `../../src/openssl-3.6.4/` prefix. The string reaches an application through
/// `CRYPTO_set_mem_functions`, so the prefix is part of the observable contract and not cosmetic.
const FILE_RSA_PK1: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_pk1.c".as_ptr();

/// `int ossl_rsa_padding_add_PKCS1_type_2_ex(OSSL_LIB_CTX *libctx, unsigned char *to, int tlen,
/// const unsigned char *from, int flen)` — `rsa_pk1.c:124-162`. Internal, and declared in
/// `crypto/rsa/rsa_local.h:195-197`.
///
/// `00 || 02 || nonzero random || 00 || D`, and **the retry loop is the whole point**. The first
/// `RAND_bytes_ex` fills all `j` padding octets in one request, and then each octet that came back
/// zero is re-drawn **one octet at a time** until it is non-zero. A transcription that stopped
/// after the first request would emit a block whose first zero octet is inside the padding, so the
/// type-2 check would read the message as starting there; and the loop is written as `do { } while`
/// rather than `while` so that a re-drawn zero is *itself* re-drawn rather than accepted.
///
/// **The `libctx` is the caller's and not the object's.** That is the whole reason the `_ex` form
/// exists: [`RSA_padding_add_PKCS1_type_2`] below passes NULL and `rsa_ossl.c:144` passes
/// `rsa->libctx`, and both land in this one body with a different random context.
///
/// # Safety
/// `libctx` is NULL or live; `to` is writable for `tlen` bytes; `from` is readable for `flen`
/// bytes.
#[allow(non_snake_case)] // the authority's name, kept verbatim like every other one
pub(crate) unsafe fn ossl_rsa_padding_add_PKCS1_type_2_ex(
    libctx: *mut c_void,
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if flen > (tlen - RSA_PKCS1_PADDING_SIZE) {
            raise_site(&err_sites::RSA_PK1_132);
            return 0;
        } else if flen < 0 {
            raise_site(&err_sites::RSA_PK1_135);
            return 0;
        }

        let mut p = to;

        *p = 0;
        p = p.offset(1);
        *p = 2; // Public Key BT (Block Type)
        p = p.offset(1);

        // `j >= 8` here: the two refusals above leave `0 <= flen <= tlen - 11`, so `j` is
        // `tlen - 3 - flen >= 8` and the length the random call is handed is never negative.
        let j = tlen - 3 - flen;

        if RAND_bytes_ex(libctx, p, j as usize, 0) <= 0 {
            return 0;
        }
        let mut i: c_int = 0;
        while i < j {
            if *p == 0 {
                // The authority's `do { ... } while (*p == '\0')`.
                loop {
                    if RAND_bytes_ex(libctx, p, 1, 0) <= 0 {
                        return 0;
                    }
                    if *p != 0 {
                        break;
                    }
                }
            }
            p = p.offset(1);
            i += 1;
        }

        *p = 0;
        p = p.offset(1);
        core::ptr::copy_nonoverlapping(from, p, flen as usize);
        1
    }
}

/// `int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen, const unsigned char *from,
/// int flen)` — `rsa_pk1.c:164-168`.
///
/// The default-context wrapper: NULL in, the block out. It is a separate exported function in the
/// authority because it is the one callers already had, and the `_ex` form was added underneath it
/// when RSA grew a libctx.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_type_2(
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
) -> c_int {
    // SAFETY: the caller's contract, forwarded with the default context.
    unsafe { ossl_rsa_padding_add_PKCS1_type_2_ex(core::ptr::null_mut(), to, tlen, from, flen) }
}

/// `int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen, const unsigned char *from,
/// int flen, int num)` — `rsa_pk1.c:170-275`.
///
/// PKCS #1 v2.2 section 7.2.2's EME-PKCS1-v1_5 decoding check. **Its refusal is an error and a
/// `-1`, not a random premaster secret**: the Bleichenbacher mitigation that answers with random
/// bytes is `ossl_rsa_padding_check_PKCS1_type_2_TLS` (`:546`), a different function in the same
/// file that only the TLS record layer calls, and it is D285's `RAND_priv_bytes_ex` coordinate that
/// put this label into the Phase 9 hand-off list (D323).
///
/// The structure is the same one the OAEP check above uses, and for the same reason: `flen <= num`
/// and `num >= RSA_PKCS1_PADDING_SIZE` are checked in the clear because they leak nothing about
/// the plaintext, everything after that is folded into `good`, and the message is moved back with
/// a masked, duplicated copy so that neither the pass/fail bit nor the message length is visible in
/// timing. The one place this differs from OAEP is the error: this check **raises and then flags**
/// the record rather than removing it, so a caller that ignores the return value still finds the
/// error on the queue, and a successful decode has it cleared again.
///
/// Two of the authority's initialisers are dropped, and both are dead rather than load-bearing:
/// `em`'s `NULL` is overwritten by the allocation before anything reads it, and `mlen`'s `-1` is
/// overwritten by `num - msg_index` on every path that reaches its readers. `zero_index`'s `0` is
/// **not** dead -- it is what the constant-time accumulator starts from and what a block with no
/// zero octet at all answers with -- so it keeps its initial value here.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_check_PKCS1_type_2(
    to: *mut c_uchar,
    mut tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
    num: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut i: c_int;
        let mut found_zero_byte: u32;
        let mut mask: u32;
        let mut zero_index: c_int = 0;
        let mut msg_index: c_int;

        if tlen <= 0 || flen <= 0 {
            return -1;
        }

        if flen > num || num < RSA_PKCS1_PADDING_SIZE {
            raise_site(&err_sites::RSA_PK1_189);
            return -1;
        }

        // `num >= RSA_PKCS1_PADDING_SIZE` above, so this is a non-zero request.
        let mut em = CRYPTO_malloc(num as usize, FILE_RSA_PK1, LINE).cast::<c_uchar>();
        if em.is_null() {
            return -1;
        }

        // Copy `from` (up to `flen` bytes) into the tail of `em` (`num` bytes): right-aligned,
        // zero-padded on the left, with the source pointer advanced under a mask so that the same
        // addresses are touched whatever `flen` is. The loop's `*--em` leaves `em` back at the
        // start when it ends, which is why the cleanup below can hand it over unchanged.
        let mut from = from;
        let mut flen = flen;
        from = from.offset(flen as isize);
        em = em.offset(num as isize);
        i = 0;
        while i < num {
            mask = !crate::runtime::constant_time::constant_time_is_zero_u32(flen as u32);
            flen = flen.wrapping_sub((1 & mask) as c_int);
            from = from.offset(-((1 & mask) as isize));
            em = em.offset(-1);
            *em = ((*from) as u32 & mask) as u8;
            i += 1;
        }

        let mut good: u32 = crate::runtime::constant_time::constant_time_is_zero_u32(*em as u32);
        good &= crate::runtime::constant_time::constant_time_eq_u32(*em.offset(1) as u32, 2);

        // Scan over the padding string for the first zero octet, which is the separator.
        found_zero_byte = 0;
        i = 2;
        while i < num {
            let equals0 = crate::runtime::constant_time::constant_time_is_zero_u32(
                *em.offset(i as isize) as u32,
            );
            zero_index = crate::runtime::constant_time::constant_time_select_int(
                !found_zero_byte & equals0,
                i,
                zero_index,
            );
            found_zero_byte |= equals0;
            i += 1;
        }

        // The padding string must be at least 8 octets and starts two octets into `em`. If no zero
        // octet was found then `zero_index` is 0 and this also fails.
        good &= crate::runtime::constant_time::constant_time_ge_u32(zero_index as u32, 2 + 8);

        // Skip the separator. This is wrong if there was none, but then the message is not copied
        // out either.
        msg_index = zero_index + 1;
        let mlen = num - msg_index;

        // For good measure, do this check in constant time as well.
        good &= crate::runtime::constant_time::constant_time_ge_u32(tlen as u32, mlen as u32);

        // Move the result in place by `num - RSA_PKCS1_PADDING_SIZE - mlen` bytes to the left, then
        // if `good` move `mlen` bytes from `em + RSA_PKCS1_PADDING_SIZE` to `to`; otherwise leave
        // `to` unchanged. The copy is arranged so that it does not reveal the size of the data
        // being copied through a timing side channel: parts of the buffer are copied multiple
        // times, once per set bit of the real length, under a mask, so clear bits do an
        // identically-shaped non-copy. Overall cost O(N*log(N)).
        tlen = crate::runtime::constant_time::constant_time_select_int(
            crate::runtime::constant_time::constant_time_lt_u32(
                (num - RSA_PKCS1_PADDING_SIZE) as u32,
                tlen as u32,
            ),
            num - RSA_PKCS1_PADDING_SIZE,
            tlen,
        );
        msg_index = 1;
        while msg_index < num - RSA_PKCS1_PADDING_SIZE {
            mask = !crate::runtime::constant_time::constant_time_eq_u32(
                (msg_index & (num - RSA_PKCS1_PADDING_SIZE - mlen)) as u32,
                0,
            );
            i = RSA_PKCS1_PADDING_SIZE;
            while i < num - msg_index {
                let keep = *em.offset(i as isize);
                let moved = *em.offset((i + msg_index) as isize);
                *em.offset(i as isize) =
                    crate::runtime::constant_time::constant_time_select_8(mask as u8, moved, keep);
                i += 1;
            }
            msg_index <<= 1;
        }
        i = 0;
        while i < tlen {
            mask =
                good & crate::runtime::constant_time::constant_time_lt_u32(i as u32, mlen as u32);
            let keep = *to.offset(i as isize);
            let moved = *em.offset((i + RSA_PKCS1_PADDING_SIZE) as isize);
            *to.offset(i as isize) =
                crate::runtime::constant_time::constant_time_select_8(mask as u8, moved, keep);
            i += 1;
        }

        crate::runtime::mem::CRYPTO_clear_free(
            em.cast::<c_void>(),
            num as usize,
            FILE_RSA_PK1,
            LINE,
        );
        // The authority's `#ifndef FIPS_MODULE` arm: raise, then *flag* the record rather than
        // remove it when the plaintext was in fact good. A transcription that guarded the raise on
        // `!good` would get exactly the case the flag exists for wrong.
        raise_site(&err_sites::RSA_PK1_270);
        crate::runtime::err::err_clear_last_constant_time((1 & good) as c_int);

        crate::runtime::constant_time::constant_time_select_int(good, mlen, -1)
    }
}

/// `static int ossl_rsa_prf(OSSL_LIB_CTX *ctx, unsigned char *to, int tlen, const char *label,`
/// `int llen, const unsigned char *kdk, uint16_t bitlen)` — `rsa_pk1.c:277-373`.
///
/// The HMAC-SHA256 counter-mode PRF the implicit rejection is built out of: `HMAC(K, ...)` over
/// `be_iter || label || be_bitlen`, iterated over the output in `SHA256_DIGEST_LENGTH` chunks, and
/// truncated through an intermediate buffer on the last, unaligned one so that `HMAC_Final` is never
/// handed a short destination. The hash is hardcoded to SHA-256 for the reason the authority's own
/// comment gives: a version that migrated its PRF would be a Bleichenbacher oracle, because an
/// attacker who can see that two versions answer differently for the same ciphertext knows the
/// message is synthetic.
///
/// **`0` is success and `-1` is failure** — the opposite polarity of the `1`/`0` its neighbours
/// answer — which is why [`ossl_rsa_padding_check_PKCS1_type_2`] tests it with `< 0`.
///
/// Every failure but the length disagreement leaves through the authority's `err:` label, and the
/// label releases both handles whether or not they were ever created: `HMAC_CTX_free(NULL)` and
/// `EVP_MD_free(NULL)` are no-ops in both libraries.
///
/// `bitlen` is a `uint16_t` at the ABI boundary and the authority's `tlen * 8 != bitlen` test is
/// therefore against the **truncated** product; a caller whose output is longer than 8191 bytes
/// disagrees with its own length and is refused. Both callers below are inside that bound for every
/// modulus this library admits (the largest is 16384 bits, 2048 bytes), so the truncation is
/// transcribed rather than avoided. The `* 8` is a wrapping multiply for the same reason.
///
/// # Safety
/// `ctx` is NULL or live; `to` is writable for `tlen` bytes; `label` is readable for `llen` bytes;
/// `kdk` is readable for `SHA256_DIGEST_LENGTH` bytes.
unsafe fn ossl_rsa_prf(
    ctx: *mut c_void,
    to: *mut c_uchar,
    tlen: c_int,
    label: *const c_char,
    llen: c_int,
    kdk: *const c_uchar,
    bitlen: u16,
) -> c_int {
    let mut hmac: *mut HmacCtx = core::ptr::null_mut();
    let mut md: *mut EvpMd = core::ptr::null_mut();
    let mut hmac_out = [0u8; SHA256_DIGEST_LENGTH as usize];
    let mut be_iter = [0u8; 2];
    let mut be_bitlen = [0u8; 2];
    let mut iter: u16 = 0;

    // The authority's `int ret = -1;`, which its `err:` label hands back and which its last
    // statement before that label sets to 0.
    let mut ret: c_int = -1;

    // SAFETY: the caller's contract: `ctx`, `to`, `label` and `kdk` are as documented, and every
    // length a callee below is handed is the one `tlen`/`llen`/`bitlen` describes. The two
    // handles are NULL until they are created and are released at the authority's `err:` label.
    'body: {
        // SAFETY: as above.
        unsafe {
            if tlen.wrapping_mul(8) != bitlen as c_int {
                raise_site(&err_sites::RSA_PK1_294);
                break 'body;
            }

            be_bitlen[0] = ((bitlen >> 8) & 0xff) as u8;
            be_bitlen[1] = (bitlen & 0xff) as u8;

            hmac = HMAC_CTX_new();
            if hmac.is_null() {
                raise_site(&err_sites::RSA_PK1_303);
                break 'body;
            }

            md = EVP_MD_fetch(ctx, c"sha256".as_ptr(), core::ptr::null());
            if md.is_null() {
                raise_site(&err_sites::RSA_PK1_316);
                break 'body;
            }

            if HMAC_Init_ex(
                hmac,
                kdk.cast::<c_void>(),
                SHA256_DIGEST_LENGTH as c_int,
                md,
                core::ptr::null_mut(),
            ) <= 0
            {
                raise_site(&err_sites::RSA_PK1_321);
                break 'body;
            }

            // The authority's `for (pos = 0; pos < tlen; pos += SHA256_DIGEST_LENGTH, iter++)`. The
            // increment is at the foot of this loop for that reason, and `iter` is a `uint16_t` that
            // wraps exactly as the authority's does.
            let mut pos: c_int = 0;
            while pos < tlen {
                if HMAC_Init_ex(
                    hmac,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                ) <= 0
                {
                    raise_site(&err_sites::RSA_PK1_327);
                    break 'body;
                }

                be_iter[0] = ((iter >> 8) & 0xff) as u8;
                be_iter[1] = (iter & 0xff) as u8;

                if HMAC_Update(hmac, be_iter.as_ptr(), be_iter.len()) <= 0 {
                    raise_site(&err_sites::RSA_PK1_335);
                    break 'body;
                }
                if HMAC_Update(hmac, label.cast::<c_uchar>(), llen as usize) <= 0 {
                    raise_site(&err_sites::RSA_PK1_339);
                    break 'body;
                }
                if HMAC_Update(hmac, be_bitlen.as_ptr(), be_bitlen.len()) <= 0 {
                    raise_site(&err_sites::RSA_PK1_343);
                    break 'body;
                }

                // `HMAC_Final` requires the destination to fit the whole MAC, so the last, unaligned
                // chunk is finalised into the intermediate buffer and copied out of it.
                let mut md_len: c_uint = SHA256_DIGEST_LENGTH;
                if pos + SHA256_DIGEST_LENGTH as c_int > tlen {
                    if HMAC_Final(hmac, hmac_out.as_mut_ptr(), core::ptr::addr_of_mut!(md_len)) <= 0
                    {
                        raise_site(&err_sites::RSA_PK1_355);
                        break 'body;
                    }
                    core::ptr::copy_nonoverlapping(
                        hmac_out.as_ptr(),
                        to.offset(pos as isize),
                        (tlen - pos) as usize,
                    );
                } else if HMAC_Final(
                    hmac,
                    to.offset(pos as isize),
                    core::ptr::addr_of_mut!(md_len),
                ) <= 0
                {
                    raise_site(&err_sites::RSA_PK1_361);
                    break 'body;
                }

                pos += SHA256_DIGEST_LENGTH as c_int;
                iter = iter.wrapping_add(1);
            }
            // The authority's `ret = 0;` immediately before its `err:` label.
            ret = 0;
        }
    }

    // The authority's `err:` label. Both releases accept NULL, so an early failure runs it whole.
    // SAFETY: `hmac` and `md` are each NULL or a live handle this call owns.
    unsafe {
        HMAC_CTX_free(hmac);
        EVP_MD_free(md);
    }

    ret
}

/// `int ossl_rsa_padding_check_PKCS1_type_2(OSSL_LIB_CTX *ctx, unsigned char *to, int tlen,`
/// `const unsigned char *from, int flen, int num, unsigned char *kdk)` — `rsa_pk1.c:387-523`.
/// Internal, and declared in `include/crypto/rsa.h:92-95`.
///
/// **The same type-2 check with implicit rejection instead of a refusal.** Where
/// [`RSA_padding_check_PKCS1_type_2`] raises and answers `-1`, this answers a message derived from
/// the private exponent and the ciphertext — so a caller that cannot see the plaintext cannot tell
/// a bad padding from a good one, which is Bleichenbacher's oracle closed on the PKCS#1 v1.5
/// decryption path. The message is not *random*: it is [`ossl_rsa_prf`]'s output under the KDK
/// `derive_kdk` computed, so this function is a pure function of its inputs and a court can compare
/// it byte for byte.
///
/// The structure is the authority's: the synthetic message and a 128-candidate synthetic *length*
/// are produced first, the check over `from` folds into `good`, and `msg_index` is then selected
/// between the real one and the synthetic one under that same mask. The final copy reads both
/// buffers on every iteration so that the cache access pattern does not leak which was selected.
///
/// `ret < 0` is reachable only for a publicly invalid call (`num != flen`, a non-positive length, or
/// an allocation failure), which is why the error is raised on the way out rather than in constant
/// time.
///
/// # Safety
/// `ctx` is NULL or live; `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes;
/// `kdk` is readable for `SHA256_DIGEST_LENGTH` bytes.
#[allow(non_snake_case)] // the authority's name, kept verbatim like every other one
pub(crate) unsafe fn ossl_rsa_padding_check_PKCS1_type_2(
    ctx: *mut c_void,
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
    num: c_int,
    kdk: *mut c_uchar,
) -> c_int {
    /// `MAX_LEN_GEN_TRIES` — `rsa_pk1.c:399`. The number of candidate lengths drawn, 128 of them
    /// so that the chance none is small enough is 2^-128.
    const MAX_LEN_GEN_TRIES: usize = 128;

    // SAFETY: the caller's contract.
    unsafe {
        // The authority initialises `synthetic` to NULL and immediately overwrites it; that
        // initialiser is dead and is dropped, exactly as this file's type-2 check drops its own
        // `em`/`mlen` initialisers. `len_candidate` and `j` are likewise declared where the
        // authority first assigns them rather than at the top of the block.
        let mut synthetic_length: c_int;
        let mut len_candidate: u16;
        let mut candidate_lengths = [0u8; MAX_LEN_GEN_TRIES * 2];
        let mut ret: c_int = -1;
        let mut j: c_int;

        if num != flen || tlen <= 0 || flen <= 0 {
            raise_site(&err_sites::RSA_PK1_419);
            return -1;
        }

        let synthetic = CRYPTO_malloc(flen as usize, FILE_RSA_PK1, LINE).cast::<c_uchar>();
        if synthetic.is_null() {
            raise_site(&err_sites::RSA_PK1_426);
            return -1;
        }

        // The authority's `sizeof(candidate_lengths)` and `MAX_LEN_GEN_TRIES *
        // sizeof(len_candidate) * 8` are written as those quantities: the buffers above are the
        // authority's own sizes. The outcome travels in `ret`, which is what the authority's
        // `err:` label reads and raises on; the block itself carries nothing.
        'body: {
            if ossl_rsa_prf(
                ctx,
                synthetic,
                flen,
                c"message".as_ptr(),
                7,
                kdk,
                (flen * 8) as u16,
            ) < 0
            {
                break 'body;
            }
            if ossl_rsa_prf(
                ctx,
                candidate_lengths.as_mut_ptr(),
                candidate_lengths.len() as c_int,
                c"length".as_ptr(),
                6,
                kdk,
                (MAX_LEN_GEN_TRIES * 2 * 8) as u16,
            ) < 0
            {
                break 'body;
            }

            // The largest message the modulus can hold: two header octets and eight mandatory
            // padding octets are not message.
            let mut len_mask: u16 = (flen - 2 - 8) as u16;
            let max_sep_offset: u16 = len_mask;
            // Propagate the top set bit down, so the mask the candidates are reduced by is one less
            // than a power of two.
            len_mask |= len_mask >> 1;
            len_mask |= len_mask >> 2;
            len_mask |= len_mask >> 4;
            len_mask |= len_mask >> 8;

            synthetic_length = 0;
            let mut i: usize = 0;
            while i < candidate_lengths.len() {
                len_candidate =
                    ((candidate_lengths[i] as u16) << 8) | candidate_lengths[i + 1] as u16;
                len_candidate &= len_mask;

                synthetic_length = crate::runtime::constant_time::constant_time_select_int(
                    crate::runtime::constant_time::constant_time_lt_u32(
                        len_candidate as u32,
                        max_sep_offset as u32,
                    ),
                    len_candidate as c_int,
                    synthetic_length,
                );
                i += 2;
            }

            let synth_msg_index = flen - synthetic_length;

            let mut good: u32 =
                crate::runtime::constant_time::constant_time_is_zero_u32(*from as u32);
            good &= crate::runtime::constant_time::constant_time_eq_u32(*from.offset(1) as u32, 2);

            // The separator is the first zero octet, accumulated rather than branched on.
            let mut found_zero_byte: u32 = 0;
            let mut zero_index: c_int = 0;
            let mut i: c_int = 2;
            while i < flen {
                let equals0 = crate::runtime::constant_time::constant_time_is_zero_u32(
                    *from.offset(i as isize) as u32,
                );
                zero_index = crate::runtime::constant_time::constant_time_select_int(
                    !found_zero_byte & equals0,
                    i,
                    zero_index,
                );
                found_zero_byte |= equals0;
                i += 1;
            }

            // The padding must be at least eight octets long and starts two octets into `from`.
            good &= crate::runtime::constant_time::constant_time_ge_u32(zero_index as u32, 2 + 8);

            // Skip the separator. This is wrong if there was none, but then the message is not
            // copied out either.
            let mut msg_index = zero_index + 1;

            // A message that does not fit is *not* an error here: the synthetic one is returned
            // instead, because refusing would leak what the refusal was about.
            good &= crate::runtime::constant_time::constant_time_ge_u32(
                tlen as u32,
                (num - msg_index) as u32,
            );

            msg_index = crate::runtime::constant_time::constant_time_select_int(
                good,
                msg_index,
                synth_msg_index,
            );

            // Both buffers are read on every pass, so the access pattern is the same whichever
            // branch `good` selected.
            j = 0;
            let mut i = msg_index;
            while i < flen && j < tlen {
                *to.offset(j as isize) = crate::runtime::constant_time::constant_time_select_8(
                    good as u8,
                    *from.offset(i as isize),
                    *synthetic.offset(i as isize),
                );
                i += 1;
                j += 1;
            }
            ret = j;
        }

        // The authority's `err:` label. `ret < 0` is the publicly-invalid case, and this is the
        // only raise on the way out.
        if ret < 0 {
            raise_site(&err_sites::RSA_PK1_520);
        }
        crate::runtime::mem::CRYPTO_free(synthetic.cast::<c_void>(), FILE_RSA_PK1, LINE);
        ret
    }
}

/// `RSA_PSS_SALTLEN_AUTO_DIGEST_MAX` — `include/openssl/rsa.h:144`.
///
/// **`rsa.h` defines five salt-length names and only four distinct values.**
/// `RSA_PSS_SALTLEN_DIGEST` is -1, `AUTO` is -2, `MAX` is -3, this one is -4, and
/// `RSA_PSS_SALTLEN_MAX_SIGN` is -2 again under the header's own gloss "old compatible max salt
/// length for sign only". `src/evp/pkey_ctx.rs` already publishes the three the ctrl-string map
/// speaks; the two this pair adds are declared here because the authority's `rsa_pss.c` is their
/// reader -- they are `pub(crate)` since that unit is now [`crate::rsa::pss`] -- and they are
/// transcribed as the header writes them rather than folded into `-2`/`-4` literals at the use
/// site, because the authority's own `sLen == MAX_SIGN || sLen == AUTO` test is a statement about
/// two names.
pub(crate) const RSA_PSS_SALTLEN_AUTO_DIGEST_MAX: c_int = -4;

/// `RSA_PSS_SALTLEN_MAX_SIGN` — `include/openssl/rsa.h:146`. See
/// [`RSA_PSS_SALTLEN_AUTO_DIGEST_MAX`] for why it is a name here and not the literal `-2`.
pub(crate) const RSA_PSS_SALTLEN_MAX_SIGN: c_int = -2;

/// `int ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(OSSL_LIB_CTX *libctx, unsigned char *to, int tlen,
/// const unsigned char *from, int flen, const unsigned char *param, int plen, const EVP_MD *md,
/// const EVP_MD *mgf1md)` — `rsa_oaep.c:54-149`.
///
/// NIST SP 800-56B section 7.2.2.3's EME-OAEP encoding, with the step letters the authority's own
/// comments carry so the two can be read side by side. The shape a reader has to get right is that
/// **`EM` is built in the caller's buffer and the two masks are applied in place**: `DB` lives at
/// `to + mdlen + 1` and is masked with `MGF1(seed)`, and then `seed` at `to + 1` is masked with
/// `MGF1(maskedDB)` — so the second mask is computed over the *already masked* data block, which
/// is what makes the encoding invertible by the check above.
///
/// **The `libctx` is the caller's.** Same reason as the type-2 `_ex` above: the two exports below
/// pass NULL and the provider's decrypt path passes the operation's context.
///
/// The `#ifdef FIPS_MODULE` arms of the authority are not transcribed, and this is the second file
/// to say so: this crate has no FIPS branch, so the `EVP_MD_xof` refusals (`:79-89`) do not exist
/// here. The `md == NULL` arm is the `#ifndef FIPS_MODULE` one, which is `EVP_sha1()`.
///
/// # Safety
/// `libctx` is NULL or live; `to` is writable for `tlen` bytes; `from` is readable for `flen`
/// bytes; `param` is readable for `plen` bytes (NULL with 0 is the empty label); `md` and `mgf1md`
/// are NULL or live digest methods.
#[allow(non_snake_case)] // the authority's name, kept verbatim like every other one
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(
    libctx: *mut c_void,
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
    param: *const c_uchar,
    plen: c_int,
    md: *const EvpMd,
    mgf1md: *const EvpMd,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let emlen: c_int = tlen - 1;
        let mut dbmask: *mut c_uchar = core::ptr::null_mut();
        let mut seedmask = [0u8; EVP_MAX_MD_SIZE];
        let mut dbmask_len: c_int = 0;

        let mut md = md;
        if md.is_null() {
            // The authority's `#ifndef FIPS_MODULE` arm only; this crate has no FIPS branch.
            md = crate::evp::legacy_sha::EVP_sha1();
        }
        let mut mgf1md = mgf1md;
        if mgf1md.is_null() {
            mgf1md = md;
        }

        // SAFETY: `md` is live (the default above when the caller passed NULL).
        let mdlen: c_int = EVP_MD_get_size(md);
        if mdlen <= 0 {
            raise_site(&err_sites::RSA_OAEP_93);
            return 0;
        }

        // step 2b: check KLen > nLen - 2 HLen - 2
        if flen > emlen - 2 * mdlen - 1 {
            raise_site(&err_sites::RSA_OAEP_99);
            return 0;
        }

        if emlen < 2 * mdlen + 1 {
            raise_site(&err_sites::RSA_OAEP_104);
            return 0;
        }

        // step 3i: EM = 00000000 || maskedMGF || maskedDB
        *to = 0;
        let seed = to.offset(1);
        let db = to.offset((mdlen + 1) as isize);

        let completed = 'body: {
            // step 3a: hash the additional input
            if crate::evp::digest::EVP_Digest(
                param.cast::<c_void>(),
                plen as usize,
                db,
                core::ptr::null_mut(),
                md,
                core::ptr::null_mut(),
            ) == 0
            {
                break 'body false;
            }
            // step 3b: zero bytes array of length nLen - KLen - 2 HLen - 2
            core::ptr::write_bytes(
                db.offset(mdlen as isize),
                0,
                (emlen - flen - 2 * mdlen - 1) as usize,
            );
            // step 3c: DB = HA || PS || 00000001 || K
            *db.offset((emlen - flen - mdlen - 1) as isize) = 0x01;
            core::ptr::copy_nonoverlapping(
                from,
                db.offset((emlen - flen - mdlen) as isize),
                flen as usize,
            );
            // step 3d: generate random byte string
            if RAND_bytes_ex(libctx, seed, mdlen as usize, 0) <= 0 {
                break 'body false;
            }

            dbmask_len = emlen - mdlen;
            dbmask = CRYPTO_malloc(dbmask_len as usize, FILE_RSA_OAEP, LINE).cast::<c_uchar>();
            if dbmask.is_null() {
                break 'body false;
            }

            // step 3e: dbMask = MGF(mgfSeed, nLen - HLen - 1)
            if PKCS1_MGF1(dbmask, dbmask_len as c_long, seed, mdlen as c_long, mgf1md) < 0 {
                break 'body false;
            }
            // step 3f: maskedDB = DB XOR dbMask
            let mut i: c_int = 0;
            while i < dbmask_len {
                *db.offset(i as isize) ^= *dbmask.offset(i as isize);
                i += 1;
            }

            // step 3g: mgfSeed = MGF(maskedDB, HLen)
            if PKCS1_MGF1(
                seedmask.as_mut_ptr(),
                mdlen as c_long,
                db,
                dbmask_len as c_long,
                mgf1md,
            ) < 0
            {
                break 'body false;
            }
            // step 3h: maskedMGFSeed = mgfSeed XOR mgfSeedMask
            i = 0;
            while i < mdlen {
                *seed.offset(i as isize) ^= seedmask[i as usize];
                i += 1;
            }
            true
        };

        // The authority's `err:` label, reached by falling through and by every `goto err` in the
        // block above. `dbmask_len` is 0 when the first `goto err` is taken, so the release is
        // `(NULL, 0)` there -- the authority's own argument, transcribed rather than folded.
        cleanse(seedmask.as_mut_ptr(), EVP_MAX_MD_SIZE);
        crate::runtime::mem::CRYPTO_clear_free(
            dbmask.cast::<c_void>(),
            dbmask_len as usize,
            FILE_RSA_OAEP,
            LINE,
        );
        if completed {
            1
        } else {
            0
        }
    }
}

/// `int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen, const unsigned char *from,
/// int flen, const unsigned char *param, int plen)` — `rsa_oaep.c:39-45`.
///
/// Both digest arguments are NULL, so the `_ex` body substitutes `EVP_sha1()` for both. PKCS #1
/// v2.2's default hash is SHA-1, which is what makes this the historical entry point and the
/// `_mgf1` form the one a caller uses to choose otherwise.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes; `param` is readable for
/// `plen` bytes, and NULL with `plen == 0` is the empty label.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_OAEP(
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
    param: *const c_uchar,
    plen: c_int,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged; both digest arguments are NULL, which
    // the callee documents as "use the default".
    unsafe {
        ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(
            core::ptr::null_mut(),
            to,
            tlen,
            from,
            flen,
            param,
            plen,
            core::ptr::null(),
            core::ptr::null(),
        )
    }
}

/// `int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen, const unsigned char *from,
/// int flen, const unsigned char *param, int plen, const EVP_MD *md, const EVP_MD *mgf1md)` —
/// `rsa_oaep.c:151-158`.
///
/// The same wrapper with the caller's digests: NULL `libctx`, everything else forwarded. The
/// NULL-digest defaults are the `_ex` body's, so a caller that passes NULL `mgf1md` gets `md`.
///
/// # Safety
/// `to` is writable for `tlen` bytes; `from` is readable for `flen` bytes; `param` is readable for
/// `plen` bytes (NULL with 0 is the empty label); `md` and `mgf1md` are NULL or live digest
/// methods.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_OAEP_mgf1(
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
    param: *const c_uchar,
    plen: c_int,
    md: *const EvpMd,
    mgf1md: *const EvpMd,
) -> c_int {
    // SAFETY: the caller's contract, forwarded with the default context.
    unsafe {
        ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(
            core::ptr::null_mut(),
            to,
            tlen,
            from,
            flen,
            param,
            plen,
            md,
            mgf1md,
        )
    }
}

// =============================================================================================
// Slice E, first part — the X9.31 key generator (`crypto/rsa/rsa_x931g.c`)
// =============================================================================================
//
// **Two labels, and they are the whole of `rsa_x931g.c`.** `RSA_X931_generate_key_ex` draws its
// two seed values `Xp`/`Xq` with `BN_X931_generate_Xpq` and derives a prime from each with
// `BN_X931_generate_prime_ex`; `RSA_X931_derive_ex` is the caller that finishes the object off,
// and is also a public entry point in its own right because a test program may want to supply
// some of the parameters and read the rest back. Both bodies are entirely arithmetic over the
// prime layer D324 landed, so they are reachable now and are the half of 8.4's slice E that needs
// nothing from `BN_generate_prime_ex2`'s successors.
//
// **The generator pair is not the whole of slice E, and the rest is named rather than implied.**
// `RSA_generate_key_ex`/`RSA_generate_multi_prime_key`/`RSA_generate_key` are `rsa_gen.c`'s and
// their common path is *not* `rsa_multiprime_keygen`: the authority's static `rsa_keygen` sends
// `primes == 2 && bits >= 2048 && BN_num_bits(e) > 16` to `ossl_rsa_sp800_56b_generate_key`
// (`crypto/rsa/rsa_sp800_56b_gen.c:365`), whose prime generation is
// `ossl_bn_rsa_fips186_4_gen_prob_primes` (`crypto/bn/bn_rsa_fips186_4.c:184`) -- a `crypto/bn`
// internal this crate does not have, over `ossl_bn_check_generated_prime` and
// `ossl_bn_get0_small_factors` (`crypto/bn/bn_prime.c:258`, `:65`), which it does not have either.
// So the block on those three labels is a `crypto/bn` unit and not `BN_generate_prime_ex2`; see
// `docs/DECISIONS.md` D326.

// There is no `FILE_RSA_X931G` beside `FILE_RSA_METH`/`FILE_RSA_OAEP`, and that is a measurement
// rather than an omission. The two bodies below allocate only `BN_CTX` and `BIGNUM` objects, and
// this crate's `BnCtx` and `BigNum` are Rust-native structures that never route an allocation
// through `CRYPTO_set_mem_functions` (D321 records that plane). So `rsa_x931g.c` has no
// `OPENSSL_zalloc`/`OPENSSL_malloc` call for a `file` string to attribute.

/// `int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2, BIGNUM *q1, BIGNUM *q2,`
/// `const BIGNUM *Xp1, const BIGNUM *Xp2, const BIGNUM *Xp, const BIGNUM *Xq1,`
/// `const BIGNUM *Xq2, const BIGNUM *Xq, const BIGNUM *e, BN_GENCB *cb)` -- `rsa_x931g.c:25-148`.
///
/// **`2` is a real answer and not a failure.** If only one of `p`/`q` exists after the derivation
/// -- which is what happens when a caller passes `Xp` or `Xq` alone -- the two primes are not both
/// present and the object cannot be finished, so the function releases its contexts and answers
/// `2` with `rsa->p`/`rsa->q` left as they are. A caller that tested `!= 0` would read that as
/// success, which is why the number is in the signature's contract rather than a detail.
///
/// **`e` is a local, and it is reassigned, because a non-NULL `rsa->e` wins.** The authority
/// overwrites its own parameter when the object already carries an exponent, so the `rsa->e` on
/// every later line is the *object's* and not the caller's.
///
/// **The `err:` label is reached with a NULL context.** The first statement after the `rsa == NULL`
/// guard allocates `ctx`, so a NULL `rsa` jumps to the release label with `ctx == NULL`, and both
/// `BN_CTX_end` and `BN_CTX_free` tolerate that here as they do in the authority.
///
/// # Safety
/// `rsa` is NULL or a live object that stays live for the call; `p1`/`p2`/`q1`/`q2` are NULL or
/// live destinations; the `X` arguments and `e` are NULL or live; `cb` is NULL or a live callback.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub unsafe extern "C" fn RSA_X931_derive_ex(
    rsa: *mut Rsa,
    p1: *mut BigNum,
    p2: *mut BigNum,
    q1: *mut BigNum,
    q2: *mut BigNum,
    xp1: *const BigNum,
    xp2: *const BigNum,
    xp: *const BigNum,
    xq1: *const BigNum,
    xq2: *const BigNum,
    xq: *const BigNum,
    e: *const BigNum,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut e = e;
        let mut ret: c_int = 0;
        let mut ctx: *mut BnCtx = core::ptr::null_mut();
        let mut ctx2: *mut BnCtx = core::ptr::null_mut();

        'body: {
            if rsa.is_null() {
                break 'body;
            }

            ctx = BN_CTX_new_ex((*rsa).libctx);
            if ctx.is_null() {
                break 'body;
            }
            BN_CTX_start(ctx);

            let r0 = BN_CTX_get(ctx);
            let r1 = BN_CTX_get(ctx);
            let r2 = BN_CTX_get(ctx);
            let r3 = BN_CTX_get(ctx);
            // The authority checks only the fourth, because a failed `BN_CTX_get` leaves the pool
            // short for every later one -- so this single test is the allocation check, transcribed
            // rather than widened.
            if r3.is_null() {
                break 'body;
            }

            if (*rsa).e.is_null() {
                (*rsa).e = BN_dup(e);
                if (*rsa).e.is_null() {
                    break 'body;
                }
            } else {
                e = (*rsa).e;
            }

            if !xp.is_null() && (*rsa).p.is_null() {
                (*rsa).p = BN_new();
                if (*rsa).p.is_null() {
                    break 'body;
                }
                if BN_X931_derive_prime_ex((*rsa).p, p1, p2, xp, xp1, xp2, e, ctx, cb) == 0 {
                    break 'body;
                }
            }

            if !xq.is_null() && (*rsa).q.is_null() {
                (*rsa).q = BN_new();
                if (*rsa).q.is_null() {
                    break 'body;
                }
                if BN_X931_derive_prime_ex((*rsa).q, q1, q2, xq, xq1, xq2, e, ctx, cb) == 0 {
                    break 'body;
                }
            }

            if (*rsa).p.is_null() || (*rsa).q.is_null() {
                BN_CTX_end(ctx);
                BN_CTX_free(ctx);
                return 2;
            }

            (*rsa).n = BN_new();
            if (*rsa).n.is_null() {
                break 'body;
            }
            if BN_mul((*rsa).n, (*rsa).p, (*rsa).q, ctx) == 0 {
                break 'body;
            }

            if BN_sub(r1, (*rsa).p, BN_value_one()) == 0 {
                break 'body;
            }
            if BN_sub(r2, (*rsa).q, BN_value_one()) == 0 {
                break 'body;
            }
            if BN_mul(r0, r1, r2, ctx) == 0 {
                break 'body;
            }

            if BN_gcd(r3, r1, r2, ctx) == 0 {
                break 'body;
            }

            // This is `BN_div(r0, NULL, r0, r3, ctx)` -- the **quotient**, not the header's
            // `BN_mod` macro: the product is divided by the gcd to give the lcm, and a
            // transcription that put the result in the remainder slot would compute
            // `(p-1)(q-1) mod gcd`, which is zero because the gcd divides both factors.
            if BN_div(r0, core::ptr::null_mut(), r0, r3, ctx) == 0 {
                break 'body;
            }

            ctx2 = BN_CTX_new();
            if ctx2.is_null() {
                break 'body;
            }

            (*rsa).d = BN_mod_inverse(core::ptr::null_mut(), (*rsa).e, r0, ctx2);
            if (*rsa).d.is_null() {
                break 'body;
            }

            (*rsa).dmp1 = BN_new();
            if (*rsa).dmp1.is_null() {
                break 'body;
            }
            if BN_div(core::ptr::null_mut(), (*rsa).dmp1, (*rsa).d, r1, ctx) == 0 {
                break 'body;
            }

            (*rsa).dmq1 = BN_new();
            if (*rsa).dmq1.is_null() {
                break 'body;
            }
            if BN_div(core::ptr::null_mut(), (*rsa).dmq1, (*rsa).d, r2, ctx) == 0 {
                break 'body;
            }

            (*rsa).iqmp = BN_mod_inverse(core::ptr::null_mut(), (*rsa).q, (*rsa).p, ctx2);
            if (*rsa).iqmp.is_null() {
                break 'body;
            }

            (*rsa).dirty_cnt += 1;
            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        BN_CTX_free(ctx2);

        ret
    }
}

/// `int RSA_X931_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e, BN_GENCB *cb)` --
/// `rsa_x931g.c:150-204`.
///
/// **The `bits` guard belongs to `BN_X931_generate_Xpq` and not here.** The seed generator accepts
/// `bits >= 1024` and a multiple of 256 (`(nbits & 0xff) == 0`), and refuses everything else with
/// `0`; this function turns any refusal into its own `0`. So `RSA_X931_generate_key_ex(rsa, 512, e,
/// cb)` is a refusal with an **empty error queue**, and that is the authority's behaviour rather
/// than an omission.
///
/// **A refusal leaves `rsa->p`/`rsa->q` allocated and possibly set.** The two `BN_new`s are
/// unconditional once the seeds exist, and the derivation writes into them; a later refusal does
/// not undo that, because the authority releases only its `BN_CTX`. That is exactly why the return
/// code and not the object's state is what a caller must read.
///
/// # Safety
/// `rsa` is a live object with a live `libctx`; `e` is NULL or live; `cb` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn RSA_X931_generate_key_ex(
    rsa: *mut Rsa,
    bits: c_int,
    e: *const BigNum,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ok = 0;
        let ctx = BN_CTX_new_ex((*rsa).libctx);

        if !ctx.is_null() {
            BN_CTX_start(ctx);
            let xp = BN_CTX_get(ctx);
            let xq = BN_CTX_get(ctx);

            if !xq.is_null() && BN_X931_generate_Xpq(xp, xq, bits, ctx) != 0 {
                (*rsa).p = BN_new();
                (*rsa).q = BN_new();

                if !(*rsa).p.is_null() && !(*rsa).q.is_null() {
                    let derived = BN_X931_generate_prime_ex(
                        (*rsa).p,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        xp,
                        e,
                        ctx,
                        cb,
                    ) != 0
                        && BN_X931_generate_prime_ex(
                            (*rsa).q,
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                            xq,
                            e,
                            ctx,
                            cb,
                        ) != 0;

                    if derived
                        && RSA_X931_derive_ex(
                            rsa,
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                            core::ptr::null(),
                            core::ptr::null(),
                            core::ptr::null(),
                            core::ptr::null(),
                            core::ptr::null(),
                            core::ptr::null(),
                            e,
                            cb,
                        ) != 0
                    {
                        (*rsa).dirty_cnt += 1;
                        ok = 1;
                    }
                }
            }

            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
        }

        if ok != 0 {
            1
        } else {
            0
        }
    }
}

// =============================================================================================
// Slice G, first half — the key checkers (`crypto/rsa/rsa_chk.c`)
// =============================================================================================
//
// **Two of the file's five functions are here and the other three are named rather than implied.**
// `rsa_chk.c` defines `ossl_rsa_validate_public`, `ossl_rsa_validate_private` and
// `ossl_rsa_validate_pairwise` as well, and in this profile the third is a one-line call to
// `rsa_validate_keypair_multiprime` -- the function below. The first two are one-line calls to
// `ossl_rsa_sp800_56b_check_public` and `ossl_rsa_sp800_56b_check_private`
// (`crypto/rsa/rsa_sp800_56b_check.c`), which D327 deliberately did not transcribe because nothing
// on the generate path reaches them; transcribing them here would be the dead code that decision
// refused. So they are absent, and their absence is why this file does **not** get a module of its
// own: an authority unit with a crate module makes every internal its text calls countable to
// `forensics/tools/prerequisite_gate.py`, and a unit whose own functions cannot be built is a
// finding rather than a census entry. `RSA_check_key` and `RSA_check_key_ex` therefore land in this
// module, whose dominant unit stays `rsa_meth.c`.
//
// **`rsa_validate_keypair_multiprime` has three answers, not two.** `-1` is "the arithmetic
// failed" (an allocation, and the authority raises `ERR_R_BN_LIB` for it), `0` is "this key is
// wrong" and `1` is "this key is right". The `ret = -1` paths are *not* the `ret = 0` paths: the
// first three refusals (`e == 1`, `e` even, a composite `p`) strip an earlier `1` back to `0` and
// keep walking, which is what lets one call report several independent problems in the error
// queue. `RSA_check_key` and `RSA_check_key_ex` hand that number straight back, so a caller sees
// `-1` as well.

/// `static int rsa_validate_keypair_multiprime(const RSA *key, BN_GENCB *cb)` --
/// `rsa_chk.c:22-234`.
///
/// The non-FIPS half of `RSA_check_key_ex`, and the whole of what this build runs.
///
/// **Sixteen error sites and only two of them end the walk.** Every check sets `ret` and keeps
/// going -- the eight `ret = 0` sites continue so that a key with several faults reports all of
/// them -- while the eleven arithmetic failures (`ret = -1`) jump to `err:`. That asymmetry is the
/// function's observable contract: one call populates the queue with every reason the key is wrong
/// rather than with the first.
///
/// **`d*e = 1 mod lambda(n)` is computed with a gcd division, not a multiplication.** The lcm is
/// built as `(p-1)(q-1) / gcd(p-1, q-1)` with `BN_div`'s **quotient** slot, then folded with each
/// extra prime's `r-1` the same way. `BN_div(m, NULL, l, m, ctx)` in the authority is the header's
/// four-argument form, and a transcription that swapped the two result slots would compute a
/// remainder that is zero by construction and then test `d*e mod 0`.
///
/// **The multi-prime count is checked against the *modulus*, not against a constant.**
/// `ossl_rsa_multip_cap(BN_num_bits(key->n))` is the modulus-dependent ladder `mp.rs` transcribes,
/// so the refusal for a bad count depends on the key's width.
///
/// # Safety
/// `key` is a live object; `cb` is NULL or a live callback. The `BN_*` calls are the crate's own,
/// whose contracts are the authority's.
unsafe fn rsa_validate_keypair_multiprime(key: *const Rsa, cb: *mut BnGencb) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret: c_int = 1;
        let mut ex_primes: c_int = 0;
        let mut idx: c_int;
        /* Declared without initialisers and assigned inside the block below, which is the
         * authority's own shape: the five `BN_new`s and the `BN_CTX_new_ex` happen after the two
         * early refusals, so a multi-prime key with a bad count never allocates anything. Rust's
         * definite-assignment analysis accepts this because every `break 'body` below follows the
         * assignments. */
        let i: *mut BigNum;
        let j: *mut BigNum;
        let k: *mut BigNum;
        let l: *mut BigNum;
        let m: *mut BigNum;
        let ctx: *mut BnCtx;

        // SAFETY: `key` is live per the contract.
        let (p, q, n, e, d) = ((*key).p, (*key).q, (*key).n, (*key).e, (*key).d);
        if p.is_null() || q.is_null() || n.is_null() || e.is_null() || d.is_null() {
            raise_site(&err_sites::RSA_CHK_31);
            return 0;
        }

        'body: {
            // multi-prime?
            // SAFETY: `key` is live and its `prime_infos` is NULL or its own stack.
            if (*key).version == object::RSA_ASN1_VERSION_MULTI {
                // SAFETY: `prime_infos` is NULL or the object's own stack.
                ex_primes = OPENSSL_sk_num((*key).prime_infos);
                if ex_primes <= 0 || (ex_primes + 2) > mp::ossl_rsa_multip_cap(BN_num_bits(n)) {
                    raise_site(&err_sites::RSA_CHK_40);
                    return 0;
                }
            }

            i = BN_new();
            j = BN_new();
            k = BN_new();
            l = BN_new();
            m = BN_new();
            // SAFETY: `key` is live and its `libctx` is NULL or live.
            ctx = BN_CTX_new_ex((*key).libctx);
            if i.is_null()
                || j.is_null()
                || k.is_null()
                || l.is_null()
                || m.is_null()
                || ctx.is_null()
            {
                ret = -1;
                raise_site(&err_sites::RSA_CHK_54);
                break 'body;
            }

            if BN_is_one(e) != 0 {
                ret = 0;
                raise_site(&err_sites::RSA_CHK_60);
            }
            if BN_is_odd(e) == 0 {
                ret = 0;
                raise_site(&err_sites::RSA_CHK_64);
            }

            // p prime?
            if BN_check_prime(p, ctx, cb) != 1 {
                ret = 0;
                raise_site(&err_sites::RSA_CHK_70);
            }

            // q prime?
            if BN_check_prime(q, ctx, cb) != 1 {
                ret = 0;
                raise_site(&err_sites::RSA_CHK_76);
            }

            // r_i prime?
            idx = 0;
            while idx < ex_primes {
                // SAFETY: `prime_infos` is the object's own stack, with `ex_primes` live elements.
                let pinfo = OPENSSL_sk_value((*key).prime_infos, idx).cast::<RsaPrimeInfo>();
                // SAFETY: `pinfo` is a live record whose `r` is NULL or live.
                if BN_check_prime((*pinfo).r, ctx, cb) != 1 {
                    ret = 0;
                    raise_site(&err_sites::RSA_CHK_84);
                }
                idx += 1;
            }

            // n = p*q * r_3...r_i?
            if BN_mul(i, p, q, ctx) == 0 {
                ret = -1;
                break 'body;
            }
            idx = 0;
            while idx < ex_primes {
                // SAFETY: as above.
                let pinfo = OPENSSL_sk_value((*key).prime_infos, idx).cast::<RsaPrimeInfo>();
                // SAFETY: `pinfo` is live.
                if BN_mul(i, i, (*pinfo).r, ctx) == 0 {
                    ret = -1;
                    break 'body;
                }
                idx += 1;
            }
            if BN_cmp(i, n) != 0 {
                ret = 0;
                if ex_primes != 0 {
                    raise_site(&err_sites::RSA_CHK_103);
                } else {
                    raise_site(&err_sites::RSA_CHK_105);
                }
            }

            // d*e = 1 mod \lambda(n)?
            if BN_sub(i, p, BN_value_one()) == 0 {
                ret = -1;
                break 'body;
            }
            if BN_sub(j, q, BN_value_one()) == 0 {
                ret = -1;
                break 'body;
            }

            // now compute k = \lambda(n) = LCM(i, j, r_3 - 1...)
            if BN_mul(l, i, j, ctx) == 0 {
                ret = -1;
                break 'body;
            }
            if BN_gcd(m, i, j, ctx) == 0 {
                ret = -1;
                break 'body;
            }
            // The header's macro is `BN_div(NULL, m, l, m, ctx)`; here it is written out for the
            // reason the doc comment gives -- the quotient is the lcm and the remainder is zero.
            if BN_div(m, core::ptr::null_mut(), l, m, ctx) == 0 {
                ret = -1;
                break 'body;
            }
            idx = 0;
            while idx < ex_primes {
                // SAFETY: as above.
                let pinfo = OPENSSL_sk_value((*key).prime_infos, idx).cast::<RsaPrimeInfo>();
                // SAFETY: `pinfo` is live.
                if BN_sub(k, (*pinfo).r, BN_value_one()) == 0 {
                    ret = -1;
                    break 'body;
                }
                if BN_mul(l, m, k, ctx) == 0 {
                    ret = -1;
                    break 'body;
                }
                if BN_gcd(m, m, k, ctx) == 0 {
                    ret = -1;
                    break 'body;
                }
                if BN_div(m, core::ptr::null_mut(), l, m, ctx) == 0 {
                    ret = -1;
                    break 'body;
                }
                idx += 1;
            }
            if BN_mod_mul(i, d, e, m, ctx) == 0 {
                ret = -1;
                break 'body;
            }

            if BN_is_one(i) == 0 {
                ret = 0;
                raise_site(&err_sites::RSA_CHK_157);
            }

            // SAFETY: `key` is live; the three CRT members are NULL or live.
            let have_crt =
                !(*key).dmp1.is_null() && !(*key).dmq1.is_null() && !(*key).iqmp.is_null();
            if have_crt {
                let (dmp1, dmq1, iqmp) =
                    // SAFETY: `key` is live.
                    ((*key).dmp1, (*key).dmq1, (*key).iqmp);

                // dmp1 = d mod (p-1)?
                if BN_sub(i, p, BN_value_one()) == 0 {
                    ret = -1;
                    break 'body;
                }
                // `BN_mod(j, d, i, ctx)`, the header's macro over `BN_div(NULL, j, d, i, ctx)`.
                if BN_div(core::ptr::null_mut(), j, d, i, ctx) == 0 {
                    ret = -1;
                    break 'body;
                }
                if BN_cmp(j, dmp1) != 0 {
                    ret = 0;
                    raise_site(&err_sites::RSA_CHK_172);
                }

                // dmq1 = d mod (q-1)?
                if BN_sub(i, q, BN_value_one()) == 0 {
                    ret = -1;
                    break 'body;
                }
                if BN_div(core::ptr::null_mut(), j, d, i, ctx) == 0 {
                    ret = -1;
                    break 'body;
                }
                if BN_cmp(j, dmq1) != 0 {
                    ret = 0;
                    raise_site(&err_sites::RSA_CHK_186);
                }

                // iqmp = q^-1 mod p?
                if BN_mod_inverse(i, q, p, ctx).is_null() {
                    ret = -1;
                    break 'body;
                }
                if BN_cmp(i, iqmp) != 0 {
                    ret = 0;
                    raise_site(&err_sites::RSA_CHK_196);
                }
            }

            idx = 0;
            while idx < ex_primes {
                // SAFETY: as above.
                let pinfo = OPENSSL_sk_value((*key).prime_infos, idx).cast::<RsaPrimeInfo>();
                // d_i = d mod (r_i - 1)?
                if BN_sub(i, (*pinfo).r, BN_value_one()) == 0 {
                    ret = -1;
                    break 'body;
                }
                if BN_div(core::ptr::null_mut(), j, d, i, ctx) == 0 {
                    ret = -1;
                    break 'body;
                }
                if BN_cmp(j, (*pinfo).d) != 0 {
                    ret = 0;
                    raise_site(&err_sites::RSA_CHK_213);
                }
                // t_i = R_i ^ -1 mod r_i?
                if BN_mod_inverse(i, (*pinfo).pp, (*pinfo).r, ctx).is_null() {
                    ret = -1;
                    break 'body;
                }
                if BN_cmp(i, (*pinfo).t) != 0 {
                    ret = 0;
                    raise_site(&err_sites::RSA_CHK_222);
                }
                idx += 1;
            }
        }

        // The authority's `err:` label. `BN_free` and `BN_CTX_free` both tolerate NULL, which is
        // what the five locals and `ctx` are when the allocation check above jumps here.
        BN_free(i);
        BN_free(j);
        BN_free(k);
        BN_free(l);
        BN_free(m);
        BN_CTX_free(ctx);
        ret
    }
}

/// `int RSA_check_key_ex(const RSA *key, BN_GENCB *cb)` -- `rsa_chk.c:261-269`.
///
/// `#ifdef FIPS_MODULE` has the three-call chain -- `ossl_rsa_validate_public` &&
/// `ossl_rsa_validate_private` && `ossl_rsa_validate_pairwise` -- and this build, which has no FIPS
/// branch, takes the one call below. The failure code a caller sees is therefore `-1` and not `0`
/// for an arithmetic failure, which the two validators above could not have produced.
///
/// # Safety
/// `key` is a live object; `cb` is NULL or a live callback.
#[no_mangle]
pub unsafe extern "C" fn RSA_check_key_ex(key: *const Rsa, cb: *mut BnGencb) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe { rsa_validate_keypair_multiprime(key, cb) }
}

/// `int RSA_check_key(const RSA *key)` -- `rsa_chk.c:256-259`.
///
/// The `_ex` form with a NULL callback, which every `BN_check_prime` call then treats as "no
/// progress reporting". The check itself is unchanged, so the two answer the same number for the
/// same key.
///
/// # Safety
/// `key` is a live object.
#[no_mangle]
pub unsafe extern "C" fn RSA_check_key(key: *const Rsa) -> c_int {
    // SAFETY: the caller's contract; a NULL callback is the no-callback form.
    unsafe { RSA_check_key_ex(key, core::ptr::null_mut()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The PSS pair moved to its own module with D351, so the arms below name it explicitly.
    use crate::evp::pkey_ctx::{RSA_PSS_SALTLEN_AUTO, RSA_PSS_SALTLEN_DIGEST, RSA_PSS_SALTLEN_MAX};
    use crate::rsa::pss::{
        ossl_rsa_padding_add_PKCS1_PSS_mgf1, RSA_padding_add_PKCS1_PSS,
        RSA_padding_add_PKCS1_PSS_mgf1,
    };

    /// **`RSA_METHOD`, field for field.** The numbers are `courts/layout/measure-rsa-ctx.c`'s: 120
    /// bytes with `name` 0, the four crypt entry points at 8/16/24/32, the two mod-exp members at
    /// 40/48, `init` 56, `finish` 64, `flags` **72**, `app_data` 80, `rsa_sign` 88, `rsa_verify`
    /// 96, `rsa_keygen` 104 and `rsa_multi_prime_keygen` 112.
    ///
    /// The offset that matters most is 80: `flags` is a four-byte `int` at 72, so a transcription
    /// that gave it a pointer's width would move everything after it by eight -- which the size
    /// assertion catches and the offsets make legible.
    #[test]
    fn the_rsa_method_is_the_authoritys_shape() {
        assert_eq!(core::mem::size_of::<RsaMethod>(), 120);
        assert_eq!(core::mem::align_of::<RsaMethod>(), 8);
        assert_eq!(core::mem::offset_of!(RsaMethod, name), 0);
        assert_eq!(core::mem::offset_of!(RsaMethod, rsa_pub_enc), 8);
        assert_eq!(core::mem::offset_of!(RsaMethod, rsa_pub_dec), 16);
        assert_eq!(core::mem::offset_of!(RsaMethod, rsa_priv_enc), 24);
        assert_eq!(core::mem::offset_of!(RsaMethod, rsa_priv_dec), 32);
        assert_eq!(core::mem::offset_of!(RsaMethod, rsa_mod_exp), 40);
        assert_eq!(core::mem::offset_of!(RsaMethod, bn_mod_exp), 48);
        assert_eq!(core::mem::offset_of!(RsaMethod, init), 56);
        assert_eq!(core::mem::offset_of!(RsaMethod, finish), 64);
        assert_eq!(core::mem::offset_of!(RsaMethod, flags), 72);
        assert_eq!(core::mem::offset_of!(RsaMethod, app_data), 80);
        assert_eq!(core::mem::offset_of!(RsaMethod, rsa_sign), 88);
        assert_eq!(core::mem::offset_of!(RsaMethod, rsa_verify), 96);
        assert_eq!(core::mem::offset_of!(RsaMethod, rsa_keygen), 104);
        assert_eq!(
            core::mem::offset_of!(RsaMethod, rsa_multi_prime_keygen),
            112
        );
    }

    /// **The `RSA` object, field for field**, measured by the same program: 216 bytes with the
    /// offsets the module documentation lists, including the `#ifndef FIPS_MODULE` block that makes
    /// the layout profile-dependent and the `pss_params` value-member at 104 whose five `int`s are
    /// what pushes `pss` to 128 rather than 112.
    #[test]
    fn the_rsa_object_is_the_authoritys_shape() {
        assert_eq!(core::mem::size_of::<Rsa>(), 216);
        assert_eq!(core::mem::align_of::<Rsa>(), 8);
        assert_eq!(core::mem::offset_of!(Rsa, dummy_zero), 0);
        assert_eq!(core::mem::offset_of!(Rsa, libctx), 8);
        assert_eq!(core::mem::offset_of!(Rsa, version), 16);
        assert_eq!(core::mem::offset_of!(Rsa, meth), 24);
        assert_eq!(core::mem::offset_of!(Rsa, engine), 32);
        assert_eq!(core::mem::offset_of!(Rsa, n), 40);
        assert_eq!(core::mem::offset_of!(Rsa, e), 48);
        assert_eq!(core::mem::offset_of!(Rsa, d), 56);
        assert_eq!(core::mem::offset_of!(Rsa, p), 64);
        assert_eq!(core::mem::offset_of!(Rsa, q), 72);
        assert_eq!(core::mem::offset_of!(Rsa, dmp1), 80);
        assert_eq!(core::mem::offset_of!(Rsa, dmq1), 88);
        assert_eq!(core::mem::offset_of!(Rsa, iqmp), 96);
        assert_eq!(core::mem::offset_of!(Rsa, pss_params), 104);
        assert_eq!(core::mem::offset_of!(Rsa, pss), 128);
        assert_eq!(core::mem::offset_of!(Rsa, prime_infos), 136);
        assert_eq!(core::mem::offset_of!(Rsa, ex_data), 144);
        assert_eq!(core::mem::offset_of!(Rsa, references), 160);
        assert_eq!(core::mem::offset_of!(Rsa, flags), 164);
        assert_eq!(core::mem::offset_of!(Rsa, _method_mod_n), 168);
        assert_eq!(core::mem::offset_of!(Rsa, lock), 200);
        assert_eq!(core::mem::offset_of!(Rsa, dirty_cnt), 208);
        // The two members a reader would guess wrong: `pss_params` is five `int`s by value, and the
        // object has no `blinding` member at all.
        assert_eq!(core::mem::size_of::<RsaPssParams30>(), 20);
        assert_eq!(core::mem::size_of::<RsaPssMaskGen>(), 8);
        assert_eq!(core::mem::size_of::<CryptoExData>(), 16);
        assert_eq!(RSA_METHOD_FLAG_NO_CHECK, 0x0001);
    }

    /// **`RSA_PRIME_INFO`, field for field.** Five pointers, so 40 bytes and eight-aligned, at the
    /// offsets `crypto/rsa/rsa_local.h:18-25`'s declaration order gives. The offsets are asserted
    /// rather than only the size because the two spellings of a wrong order are different bugs: a
    /// swap of `pp` and `m` keeps the size and moves two reads, and it is exactly the pair a
    /// reader transcribing from a comment would confuse.
    #[test]
    fn the_rsa_prime_info_is_the_authoritys_shape() {
        assert_eq!(core::mem::size_of::<RsaPrimeInfo>(), 40);
        assert_eq!(core::mem::align_of::<RsaPrimeInfo>(), 8);
        assert_eq!(core::mem::offset_of!(RsaPrimeInfo, r), 0);
        assert_eq!(core::mem::offset_of!(RsaPrimeInfo, d), 8);
        assert_eq!(core::mem::offset_of!(RsaPrimeInfo, t), 16);
        assert_eq!(core::mem::offset_of!(RsaPrimeInfo, pp), 24);
        assert_eq!(core::mem::offset_of!(RsaPrimeInfo, m), 32);
    }

    // ---------------------------------------------------------------------------------------
    // Slice C's randomised half (D323): the round trips the format makes possible, and the
    // refusals. **Nothing below asserts a random byte**: the padding octets, the OAEP seed and
    // the PSS salt are all drawn from the DRBG, so every arm is either a return code, a
    // structural predicate over the block, or an add-then-check round trip whose *answer* is
    // deterministic even though the bytes between the two calls are not.
    // ---------------------------------------------------------------------------------------

    /// `flen` octets of a recognisable, non-zero message.
    const MSG: [u8; 64] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc,
        0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
        0xdc, 0xdd, 0xde, 0xdf,
    ];

    /// **The type-2 add's block and its round trip through the type-2 check.**
    ///
    /// The structural assertions are the format: `00 02`, then `tlen - flen - 3` padding octets
    /// **none of which is zero**, then the separating zero, then the message. The non-zero
    /// assertion is the retry loop's whole observable effect and it is deterministic -- the loop
    /// exists precisely to make it true whatever the DRBG drew.
    ///
    /// The round trip is the part that would catch a transcription error the format alone would
    /// not: the check scans for the *first* zero octet from index 2, so a padding octet that was
    /// allowed to stay zero would move `msg_index` and the check would answer a different length
    /// than the one written.
    #[test]
    fn the_type_2_padding_round_trips_through_its_check() {
        let mut block = [0u8; 16];
        let mut out = [0x5au8; 64];

        // SAFETY: `block` is 16 writable octets, `MSG` is 5 readable ones.
        let added =
            unsafe { RSA_padding_add_PKCS1_type_2(block.as_mut_ptr(), 16, MSG.as_ptr(), 5) };
        assert_eq!(added, 1);
        assert_eq!(block[0], 0x00);
        assert_eq!(block[1], 0x02);
        /* `j = 16 - 3 - 5 = 8` padding octets at 2..10, then the separator at 10. */
        assert!(block[2..10].iter().all(|b| *b != 0));
        assert_eq!(block[10], 0x00);
        assert_eq!(&block[11..16], &MSG[..5]);

        // SAFETY: `block` is 16 readable octets, `out` is 64 writable ones.
        let checked =
            unsafe { RSA_padding_check_PKCS1_type_2(out.as_mut_ptr(), 64, block.as_ptr(), 16, 16) };
        assert_eq!(checked, 5);
        assert_eq!(&out[..5], &MSG[..5]);

        /* A block whose padding string is eight octets wide is the *minimum* the check accepts,
         * and it is the case `zero_index >= 2 + 8` exists for. One octet narrower must fail. */
        let mut narrow = [0x11u8; 16];
        narrow[0] = 0x00;
        narrow[1] = 0x02;
        narrow[9] = 0x00;
        // SAFETY: as above.
        let checked = unsafe {
            RSA_padding_check_PKCS1_type_2(out.as_mut_ptr(), 64, narrow.as_ptr(), 16, 16)
        };
        assert_eq!(checked, -1);
    }

    /// **The type-2 pair's refusals, and how many of them raise.**
    ///
    /// The two add refusals raise *different* reasons -- too long is
    /// `RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE` and negative is `RSA_R_INVALID_LENGTH` -- and they are
    /// checked in that order, so a negative `flen` at a `tlen` under the padding size is the
    /// *first* refusal rather than the second. `flen < 0` is otherwise unreachable from a caller
    /// with a real message, which is why it is written here: it is the arm the second error site
    /// exists for.
    #[test]
    fn the_type_2_padding_refuses_what_the_authority_refuses() {
        let mut block = [0u8; 16];
        let mut out = [0u8; 64];

        // SAFETY: every buffer is at least as long as the length argument, and each refusal is
        // decided before the message is read.
        unsafe {
            /* `flen > tlen - RSA_PKCS1_PADDING_SIZE`: 6 > 16 - 11. */
            assert_eq!(
                RSA_padding_add_PKCS1_type_2(block.as_mut_ptr(), 16, MSG.as_ptr(), 6),
                0
            );
            /* `flen < 0`, which the first test above does not catch. */
            assert_eq!(
                RSA_padding_add_PKCS1_type_2(block.as_mut_ptr(), 16, MSG.as_ptr(), -1),
                0
            );
            /* A `tlen` exactly at the padding size: the maximum message is `tlen - 11` octets,
             * so a one-octet message is already too long and this is the first arm again rather
             * than the `flen < 0` one. */
            assert_eq!(
                RSA_padding_add_PKCS1_type_2(block.as_mut_ptr(), 11, MSG.as_ptr(), 1),
                0
            );

            /* The check's two silent refusals: `tlen <= 0 || flen <= 0` answers `-1` and
             * raises nothing. */
            assert_eq!(
                RSA_padding_check_PKCS1_type_2(out.as_mut_ptr(), 0, block.as_ptr(), 16, 16),
                -1
            );
            assert_eq!(
                RSA_padding_check_PKCS1_type_2(out.as_mut_ptr(), 64, block.as_ptr(), 0, 16),
                -1
            );
            assert_eq!(
                RSA_padding_check_PKCS1_type_2(out.as_mut_ptr(), 64, block.as_ptr(), 16, 16),
                -1
            );
        }

        /* `num < RSA_PKCS1_PADDING_SIZE`, which raises: eight octets cannot hold the eleven-octet
         * minimum. */
        assert_eq!(
            // SAFETY: `block` is 16 readable octets and `out` is 64 writable ones.
            unsafe { RSA_padding_check_PKCS1_type_2(out.as_mut_ptr(), 64, block.as_ptr(), 8, 8) },
            -1
        );

        /* A header that is not `00 02`, and a padding string with no separator at all. Both are
         * the constant-time refusal: `-1`, and the error left on the queue rather than cleared. */
        let mut block = [0x11u8; 16];
        block[0] = 0x01;
        block[1] = 0x02;
        assert_eq!(
            // SAFETY: as above.
            unsafe { RSA_padding_check_PKCS1_type_2(out.as_mut_ptr(), 64, block.as_ptr(), 16, 16) },
            -1
        );
        block[0] = 0x00;
        block[1] = 0x03;
        assert_eq!(
            // SAFETY: as above.
            unsafe { RSA_padding_check_PKCS1_type_2(out.as_mut_ptr(), 64, block.as_ptr(), 16, 16) },
            -1
        );
        block[1] = 0x02;
        assert_eq!(
            // SAFETY: as above; no octet of `block` is zero, so the scan finds no separator.
            unsafe { RSA_padding_check_PKCS1_type_2(out.as_mut_ptr(), 64, block.as_ptr(), 16, 16) },
            -1
        );
    }

    /// **The OAEP adds round-trip through the already-landed OAEP checks.**
    ///
    /// The check is a pure function of its input, so this is a genuine differential observation in
    /// both courts and a genuine round trip here: the seed is random, the *answer* is not. Both
    /// entry points are exercised, because they reach the same body through different NULL
    /// substitutions -- `RSA_padding_add_PKCS1_OAEP` takes SHA-1 for both digests, and the `_mgf1`
    /// form takes the caller's and defaults only `mgf1md` to `md`.
    #[test]
    fn the_oaep_padding_round_trips_through_its_check() {
        let md = crate::evp::legacy_sha::EVP_sha1();
        let label: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut em = [0u8; 128];
        let mut out = [0x5au8; 128];

        // SAFETY: `em` is 128 writable octets, the message and label are as long as they say, and
        // `md` is a live method the padding layer reads.
        unsafe {
            assert_eq!(
                RSA_padding_add_PKCS1_OAEP_mgf1(
                    em.as_mut_ptr(),
                    128,
                    MSG.as_ptr(),
                    16,
                    label.as_ptr(),
                    5,
                    md,
                    md,
                ),
                1
            );
            /* The one structural fact that is not random: `EM`'s first octet is the version. */
            assert_eq!(em[0], 0x00);
            let checked = RSA_padding_check_PKCS1_OAEP_mgf1(
                out.as_mut_ptr(),
                128,
                em.as_ptr(),
                128,
                128,
                label.as_ptr(),
                5,
                md,
                md,
            );
            assert_eq!(checked, 16);
            assert_eq!(&out[..16], &MSG[..16]);

            /* The wrapper: NULL digests mean SHA-1 for both, and the label is empty. */
            assert_eq!(
                RSA_padding_add_PKCS1_OAEP(
                    em.as_mut_ptr(),
                    128,
                    MSG.as_ptr(),
                    16,
                    core::ptr::null(),
                    0,
                ),
                1
            );
            let checked = RSA_padding_check_PKCS1_OAEP(
                out.as_mut_ptr(),
                128,
                em.as_ptr(),
                128,
                128,
                core::ptr::null(),
                0,
            );
            assert_eq!(checked, 16);
            assert_eq!(&out[..16], &MSG[..16]);

            /* A label the two sides disagree about must not decode: the label is hashed into
             * `DB`, so the hash comparison is what refuses it. */
            assert_eq!(
                RSA_padding_add_PKCS1_OAEP_mgf1(
                    em.as_mut_ptr(),
                    128,
                    MSG.as_ptr(),
                    16,
                    label.as_ptr(),
                    5,
                    md,
                    md,
                ),
                1
            );
            let checked = RSA_padding_check_PKCS1_OAEP_mgf1(
                out.as_mut_ptr(),
                128,
                em.as_ptr(),
                128,
                128,
                core::ptr::null(),
                0,
                md,
                md,
            );
            assert_eq!(checked, -1);
        }
    }

    /// **The OAEP add's two length refusals, and the reason one of them needs a negative `flen`.**
    ///
    /// `emlen` is `tlen - 1` and the two checks are ordered, so at any modulus too small for the
    /// digest the *first* one fires for every non-negative message length: `emlen < 2*mdlen + 1`
    /// means the largest accepted `flen` is `emlen - 2*mdlen - 1 <= -1`. The
    /// `RSA_R_KEY_SIZE_TOO_SMALL` site is therefore reachable only through the `flen < 0` the
    /// authority never checks for, and this arm is what says so rather than leaving the site
    /// unexercised.
    #[test]
    fn the_oaep_padding_refuses_the_two_lengths_it_names() {
        let md = crate::evp::legacy_sha::EVP_sha1();
        let mut em = [0u8; 128];

        // SAFETY: `em` is 128 writable octets and every refusal below is decided before `MSG` is
        // read, so the length arguments do not have to be real message lengths.
        unsafe {
            /* `flen (87) > emlen (127) - 2*mdlen (40) - 1 (86)`. */
            assert_eq!(
                RSA_padding_add_PKCS1_OAEP_mgf1(
                    em.as_mut_ptr(),
                    128,
                    MSG.as_ptr(),
                    87,
                    core::ptr::null(),
                    0,
                    md,
                    md,
                ),
                0
            );
            /* `emlen (40) < 2*mdlen + 1 (41)`, reached only with `flen == -1`. */
            assert_eq!(
                RSA_padding_add_PKCS1_OAEP_mgf1(
                    em.as_mut_ptr(),
                    41,
                    MSG.as_ptr(),
                    -1,
                    core::ptr::null(),
                    0,
                    md,
                    md,
                ),
                0
            );
            /* The largest length the 128-octet modulus takes is 86, and it must be accepted. */
            assert_eq!(
                RSA_padding_add_PKCS1_OAEP_mgf1(
                    em.as_mut_ptr(),
                    128,
                    MSG.as_ptr(),
                    64,
                    core::ptr::null(),
                    0,
                    md,
                    md,
                ),
                1
            );
        }
    }

    /// An `RSA` with only `n` set, which is all the PSS add reads: `BN_num_bits(n)` for the
    /// leading bits and `RSA_size` for the block width. The rest is zeroed for the reason
    /// `object.rs`'s own `blank_object` gives -- an all-zero bit pattern is a valid `Rsa` -- and
    /// the object is never passed to `RSA_free`.
    fn pss_object(bits: c_int) -> (Rsa, *mut BigNum) {
        use crate::bn::bignum::{BN_new, BN_set_bit};

        // SAFETY: `Rsa` is a plain aggregate of integers, pointers and pointer-only data structs.
        let mut rsa: Rsa = unsafe { core::mem::zeroed() };
        // SAFETY: `BN_new` answers a fresh object or NULL, which is asserted.
        let n = unsafe { BN_new() };
        assert!(!n.is_null());
        // SAFETY: `n` is live and `bits >= 1` at every call site below.
        assert_eq!(unsafe { BN_set_bit(n, bits - 1) }, 1);
        rsa.n = n;
        (rsa, n)
    }

    /// **The recovery `ossl_rsa_verify_PKCS1_PSS_mgf1` performs, written out here** because this
    /// module is `rsa_meth.c`'s and the verifier is [`crate::rsa::pss`]'s: unmask `DB` with
    /// `MGF1(H)`, drop the bits `MSBits` forbids, find the `0x01`, and recompute
    /// `H = Hash(0x00 * 8 || mHash || salt)`.
    ///
    /// **This is a round trip and not a restatement of the writer.** A block that fails it is one
    /// the authority's own verifier refuses, and the property it checks is exactly the one the
    /// salt's randomness makes unprintable: the recovered salt has to be the octets the writer
    /// drew, and the only way to know that without reading randomness is to hash them again.
    fn pss_block_decodes(
        em: &[u8],
        msbits: c_int,
        m_hash: &[u8],
        h_len: usize,
        md: *const EvpMd,
        mgf1: *const EvpMd,
        want_s_len: c_int,
    ) -> bool {
        let Some(masked_dblen) = em.len().checked_sub(h_len + 1) else {
            return false;
        };
        let mut db = [0u8; 256];
        if masked_dblen == 0 || masked_dblen > db.len() {
            return false;
        }
        let h = &em[masked_dblen..masked_dblen + h_len];

        // SAFETY: every buffer is the length `PKCS1_MGF1` is told, `h_len` is a digest size and
        // `mgf1` is a live method.
        if unsafe {
            PKCS1_MGF1(
                db.as_mut_ptr(),
                masked_dblen as c_long,
                h.as_ptr(),
                h_len as c_long,
                mgf1,
            )
        } != 0
        {
            return false;
        }
        for i in 0..masked_dblen {
            db[i] ^= em[i];
        }
        if msbits != 0 {
            db[0] &= (0xffu16 >> (8 - msbits)) as u8;
        }

        /* The authority's own scan, including its "the separator may be the last octet" arm. */
        let mut i = 0usize;
        while i < masked_dblen - 1 && db[i] == 0 {
            i += 1;
        }
        if db[i] != 0x1 {
            return false;
        }
        i += 1;
        let s_len = masked_dblen - i;
        if s_len != want_s_len as usize {
            return false;
        }

        let mut buf = [0u8; 8 + EVP_MAX_MD_SIZE + 256];
        buf[8..8 + m_hash.len()].copy_from_slice(m_hash);
        buf[8 + m_hash.len()..8 + m_hash.len() + s_len].copy_from_slice(&db[i..i + s_len]);
        let mut h2 = [0u8; EVP_MAX_MD_SIZE];
        // SAFETY: `buf` is `8 + m_hash.len() + s_len` readable octets, which is the length passed;
        // `h2` is `EVP_MAX_MD_SIZE` and the digest is no wider; `md` is live.
        let ok = unsafe {
            crate::evp::digest::EVP_Digest(
                buf.as_ptr().cast(),
                8 + m_hash.len() + s_len,
                h2.as_mut_ptr(),
                core::ptr::null_mut(),
                md,
                core::ptr::null_mut(),
            )
        } == 1;
        ok && &h2[..h_len] == h
    }

    /// **The PSS add round-trips through that recovery, and the salt-length conventions are the
    /// observation.**
    ///
    /// The cases are the five negative spellings -- `-1` is the digest length, `-2`/`-3` the
    /// modulus maximum, `-4` the maximum capped at the digest length -- plus a positive length, at
    /// two moduli: one whose `MSBits` is 7 (a 1024-bit `n`) and one whose `MSBits` **is zero** (a
    /// 1025-bit `n`), which is the case that spends an octet on a leading zero and shrinks `emLen`
    /// to match. That arm is the reason the effective block below is offset by one.
    #[test]
    fn the_pss_padding_writes_a_block_its_own_recovery_accepts() {
        use crate::bn::bignum::BN_free;

        let md = crate::evp::legacy_sha::EVP_sha1();
        let m_hash = [0x5au8; 20];
        let h_len = 20usize;

        /* (modulus bits, requested sLen, resolved sLen) */
        let cases: [(c_int, c_int, c_int); 7] = [
            (1024, 20, 20),
            (1024, RSA_PSS_SALTLEN_DIGEST, 20),
            (1024, RSA_PSS_SALTLEN_MAX, 106),
            (1024, RSA_PSS_SALTLEN_AUTO, 106),
            (1024, RSA_PSS_SALTLEN_MAX_SIGN, 106),
            (1024, RSA_PSS_SALTLEN_AUTO_DIGEST_MAX, 20),
            (1025, 20, 20),
        ];

        for (bits, s_len, want) in cases {
            let (mut rsa, n) = pss_object(bits);
            let mut em = [0u8; 129];

            // SAFETY: `n` is live at `bits` bits, so `RSA_size` is at most 129 and `em` holds the
            // whole block; `m_hash` is `EVP_MD_get_size(EVP_sha1())` octets; `md` is live.
            let added = unsafe {
                RSA_padding_add_PKCS1_PSS(&mut rsa, em.as_mut_ptr(), m_hash.as_ptr(), md, s_len)
            };
            assert_eq!(added, 1, "the add refused sLen {s_len} at {bits} bits");

            // SAFETY: `n` is live, so `BN_num_bits` reads a valid `BIGNUM`.
            let msbits = unsafe { (BN_num_bits(n) - 1) & 0x7 };
            let base = if msbits == 0 { 1usize } else { 0usize };
            // SAFETY: `rsa` is live with a live `n`, which is all `RSA_size` reads.
            let em_len = unsafe { object::RSA_size(&rsa) } as usize - base;

            /* The authority's first-octet test, `EM[0] & (0xFF << MSBits) == 0`: with `MSBits`
             * zero that mask is `0xFF`, so the test is the leading zero octet itself. */
            assert_eq!(em[0] as u32 & (0xffu32 << msbits), 0);
            /* The trailer, once. */
            assert_eq!(em[em_len + base - 1], 0xbc);

            assert!(
                pss_block_decodes(
                    &em[base..base + em_len],
                    msbits,
                    &m_hash,
                    h_len,
                    md,
                    md,
                    want
                ),
                "sLen {s_len} at {bits} bits did not decode back to its own salt length"
            );

            // SAFETY: `n` was allocated by `BN_new` in `pss_object` and is not used again.
            unsafe { BN_free(n) };
        }
    }

    /// **The internal's `sLenOut` write-back, and the one `sLenMax` exists for.** `-4` is the only
    /// convention that is `min(hLen, maximum)` rather than one of the two, so a transcription that
    /// lost `sLenMax` would answer 106 here where the authority answers 20 -- and the block would
    /// still verify, because the recovery uses whatever length the block encodes.
    #[test]
    fn the_pss_internal_answers_with_the_salt_length_it_resolved() {
        use crate::bn::bignum::BN_free;

        let md = crate::evp::legacy_sha::EVP_sha1();
        let m_hash = [0x5au8; 20];
        let (mut rsa, n) = pss_object(1024);

        for (requested, resolved) in [
            (RSA_PSS_SALTLEN_DIGEST, 20),
            (RSA_PSS_SALTLEN_MAX, 106),
            (RSA_PSS_SALTLEN_AUTO_DIGEST_MAX, 20),
            (0, 0),
            (106, 106),
        ] {
            let mut s_len: c_int = requested;
            let mut em = [0u8; 128];
            // SAFETY: the same contract as the round-trip test above; `s_len` is a live local the
            // callee may write back.
            let ret = unsafe {
                ossl_rsa_padding_add_PKCS1_PSS_mgf1(
                    &mut rsa,
                    em.as_mut_ptr(),
                    m_hash.as_ptr(),
                    md,
                    md,
                    &mut s_len,
                )
            };
            assert_eq!(ret, 1, "the internal refused sLen {requested}");
            assert_eq!(s_len, resolved, "sLen {requested} resolved differently");
            /* A zero-length salt is legal and draws nothing: the trailer is still written. */
            assert_eq!(em[127], 0xbc);
        }

        // SAFETY: `n` was allocated by `BN_new` in `pss_object` and is not used again.
        unsafe { BN_free(n) };
    }

    /// **The PSS add's three refusals.** A salt length below the lowest convention, a salt length
    /// above what the modulus allows, and a modulus too small to hold the hash plus the two
    /// mandatory octets -- each a different error site.
    #[test]
    fn the_pss_padding_refuses_an_impossible_salt_length() {
        use crate::bn::bignum::BN_free;

        let md = crate::evp::legacy_sha::EVP_sha1();
        let m_hash = [0x5au8; 20];
        let (mut rsa, n) = pss_object(1024);
        let mut em = [0u8; 129];

        // SAFETY: `rsa` has a live 1024-bit `n`, so `RSA_size` is 128 and `em` holds it; every
        // refusal below is decided before the salt is drawn or the block is written.
        unsafe {
            /* `sLen (107) > emLen (128) - hLen (20) - 2 (106)`. */
            assert_eq!(
                RSA_padding_add_PKCS1_PSS(&mut rsa, em.as_mut_ptr(), m_hash.as_ptr(), md, 107),
                0
            );
            /* `-5 < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX (-4)`: a refusal, not a clamp. */
            assert_eq!(
                RSA_padding_add_PKCS1_PSS(&mut rsa, em.as_mut_ptr(), m_hash.as_ptr(), md, -5),
                0
            );
        }

        // SAFETY: `n` was allocated by `BN_new` in `pss_object` and is not used again.
        unsafe { BN_free(n) };

        /* A 64-bit modulus is eight octets, which is less than `hLen + 2` for SHA-1 -- and the
         * refusal is reached before the block is touched, so the eight-octet buffer is enough. */
        let (mut small, n) = pss_object(64);
        let mut tiny = [0u8; 8];
        assert_eq!(
            unsafe {
                // SAFETY: `small` has a live 64-bit `n`, so `RSA_size` is 8 and `tiny` holds it;
                // the refusal is decided before the block is written, so `tiny` is never read.
                RSA_padding_add_PKCS1_PSS_mgf1(
                    &mut small,
                    tiny.as_mut_ptr(),
                    m_hash.as_ptr(),
                    md,
                    md,
                    0,
                )
            },
            0
        );
        // SAFETY: `n` was allocated by `BN_new` in `pss_object` and is not used again.
        unsafe { BN_free(n) };
    }

    /// **The PSS add with two different digests.** `Hash` decides `hLen` and therefore the block's
    /// split; `mgf1Hash` decides only the mask. A transcription that used one for the other would
    /// produce a block that still carries the trailer and the leading bits, so the recovery is the
    /// arm that catches it.
    #[test]
    fn the_pss_padding_takes_its_two_digests_separately() {
        use crate::bn::bignum::BN_free;

        let hash = crate::evp::legacy_sha::EVP_sha256();
        let mgf1 = crate::evp::legacy_sha::EVP_sha1();
        let m_hash = [0x5au8; 32];
        let (mut rsa, n) = pss_object(1024);
        let mut em = [0u8; 128];

        /* `hLen` is the *hash*'s 32, so the maximum salt is 128 - 32 - 2 = 94. */
        // SAFETY: `rsa` has a live 1024-bit `n`; `m_hash` is `EVP_MD_get_size(EVP_sha256())`
        // octets; both methods are live.
        let added = unsafe {
            RSA_padding_add_PKCS1_PSS_mgf1(
                &mut rsa,
                em.as_mut_ptr(),
                m_hash.as_ptr(),
                hash,
                mgf1,
                94,
            )
        };
        assert_eq!(added, 1);
        assert_eq!(em[127], 0xbc);
        assert!(pss_block_decodes(
            &em[..128],
            7,
            &m_hash,
            32,
            hash,
            mgf1,
            94
        ));
        /* The same block under the wrong MGF1 hash is a different block. */
        assert!(!pss_block_decodes(
            &em[..128],
            7,
            &m_hash,
            32,
            hash,
            hash,
            94
        ));

        // SAFETY: `n` was allocated by `BN_new` in `pss_object` and is not used again.
        unsafe { BN_free(n) };
    }

    /// **The X9.31 generator's key is assertable by property and not by value.** Every component
    /// is drawn, so nothing below compares a `BIGNUM` against a constant; what is compared is what
    /// the algorithm *guarantees*: `p` and `q` are odd primes (`BN_check_prime`, D324's), `n` is
    /// their product, `d` inverts `e` modulo both `p - 1` and `q - 1`, and the three CRT parameters
    /// are the residues and the inverse they are named for.
    ///
    /// **`RSA_size` is the one width assertion and it is an inequality.** `Xp` carries two set top
    /// bits and `Yp0` starts at `Xp`, so a 1024-bit request gives a 512-bit seed and the modulus is
    /// 1023 or 1024 bits -- always 128 octets, never fewer. Asserting the exact `BN_num_bits` would
    /// be asserting which of the two the DRBG happened to produce.
    ///
    /// The refusals are the seed generator's own: `bits < 1024` and a `bits` that is not a multiple
    /// of 256 both answer `0` with an empty error queue, because the guard is in `BN_X931_generate_Xpq`
    /// (`crypto/bn/bn_x931p.c:170`) and this function only forwards the refusal.
    #[test]
    fn the_x931_generator_builds_a_consistent_key() {
        use crate::bn::arith::{BN_cmp, BN_div, BN_mul, BN_sub};
        use crate::bn::bignum::{BN_free, BN_is_one, BN_set_word};
        use crate::bn::ctx::{BN_CTX_free, BN_CTX_new};
        use crate::bn::primes::BN_check_prime;
        use crate::rsa::object::{
            RSA_free, RSA_get0_crt_params, RSA_get0_factors, RSA_get0_key, RSA_new, RSA_size,
        };

        // SAFETY: every pointer is a fresh allocation this test owns and every out-parameter below
        // is a writable local; the BN calls are the contract of their `# Safety` sections.
        unsafe {
            let e = BN_new();
            assert!(!e.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);

            let rsa = RSA_new();
            assert!(!rsa.is_null());
            assert_eq!(
                RSA_X931_generate_key_ex(rsa, 1024, e, core::ptr::null_mut()),
                1
            );
            assert!(RSA_size(rsa) >= 128);

            let mut n: *const BigNum = core::ptr::null();
            let mut ep: *const BigNum = core::ptr::null();
            let mut d: *const BigNum = core::ptr::null();
            RSA_get0_key(rsa, &mut n, &mut ep, &mut d);
            let mut p: *const BigNum = core::ptr::null();
            let mut q: *const BigNum = core::ptr::null();
            RSA_get0_factors(rsa, &mut p, &mut q);
            let mut dmp1: *const BigNum = core::ptr::null();
            let mut dmq1: *const BigNum = core::ptr::null();
            let mut iqmp: *const BigNum = core::ptr::null();
            RSA_get0_crt_params(rsa, &mut dmp1, &mut dmq1, &mut iqmp);
            assert!(!n.is_null() && !ep.is_null() && !d.is_null());
            assert!(!p.is_null() && !q.is_null());
            assert!(!dmp1.is_null() && !dmq1.is_null() && !iqmp.is_null());

            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());

            /* Both factors are the primes the derivation promises. */
            assert_eq!(BN_check_prime(p, ctx, core::ptr::null_mut()), 1);
            assert_eq!(BN_check_prime(q, ctx, core::ptr::null_mut()), 1);

            /* `n == p * q`. */
            let prod = BN_new();
            assert!(!prod.is_null());
            assert_eq!(BN_mul(prod, p, q, ctx), 1);
            assert_eq!(BN_cmp(prod, n), 0);

            /* `dmp1 == d mod (p-1)` and `dmq1 == d mod (q-1)`. */
            let pm1 = BN_new();
            let qm1 = BN_new();
            let t = BN_new();
            assert!(!pm1.is_null() && !qm1.is_null() && !t.is_null());
            assert_eq!(BN_sub(pm1, p, BN_value_one()), 1);
            assert_eq!(BN_sub(qm1, q, BN_value_one()), 1);
            assert_eq!(BN_div(core::ptr::null_mut(), t, d, pm1, ctx), 1);
            assert_eq!(BN_cmp(t, dmp1), 0);
            assert_eq!(BN_div(core::ptr::null_mut(), t, d, qm1, ctx), 1);
            assert_eq!(BN_cmp(t, dmq1), 0);

            /* `e * d == 1 (mod p-1)` and `(mod q-1)`: `d` is the inverse modulo the *lcm*, which
             * divides both, so this is the property the CRT path depends on and not a restatement
             * of the derivation. */
            let ed = BN_new();
            assert!(!ed.is_null());
            assert_eq!(BN_mul(ed, ep, d, ctx), 1);
            assert_eq!(BN_div(core::ptr::null_mut(), t, ed, pm1, ctx), 1);
            assert_eq!(BN_is_one(t), 1);
            assert_eq!(BN_div(core::ptr::null_mut(), t, ed, qm1, ctx), 1);
            assert_eq!(BN_is_one(t), 1);

            /* `q * iqmp == 1 (mod p)`. */
            assert_eq!(BN_mul(prod, q, iqmp, ctx), 1);
            assert_eq!(BN_div(core::ptr::null_mut(), t, prod, p, ctx), 1);
            assert_eq!(BN_is_one(t), 1);

            /* The two refusals the seed generator owns. */
            let rsa_small = RSA_new();
            assert!(!rsa_small.is_null());
            assert_eq!(
                RSA_X931_generate_key_ex(rsa_small, 512, e, core::ptr::null_mut()),
                0
            );
            assert_eq!(
                RSA_X931_generate_key_ex(rsa_small, 1025, e, core::ptr::null_mut()),
                0
            );

            RSA_free(rsa_small);
            RSA_free(rsa);
            BN_free(prod);
            BN_free(pm1);
            BN_free(qm1);
            BN_free(t);
            BN_free(ed);
            BN_free(e);
            BN_CTX_free(ctx);
        }
    }

    /// **`RSA_X931_derive_ex`'s three answers, on the arms that need no arithmetic.** The `2` is
    /// the one worth pinning: with an exponent and neither `Xp` nor `Xq` the object still has no
    /// primes, so the function releases its contexts and answers `2` -- a success-looking number
    /// that means "incomplete", which is why it is in the signature's contract. A NULL `rsa` is the
    /// `err:` label instead, and it is reached with a NULL context, which is what makes the null
    /// tolerance of `BN_CTX_end`/`BN_CTX_free` observable here rather than assumed.
    #[test]
    fn the_x931_derive_answers_two_and_zero_on_its_two_incomplete_arms() {
        use crate::bn::bignum::{BN_free, BN_set_word};

        // SAFETY: `e` is a fresh allocation and the null arguments are the contract of each call.
        unsafe {
            let e = BN_new();
            assert!(!e.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);

            let rsa = crate::rsa::object::RSA_new();
            assert!(!rsa.is_null());
            assert_eq!(
                RSA_X931_derive_ex(
                    rsa,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    e,
                    core::ptr::null_mut(),
                ),
                2
            );
            crate::rsa::object::RSA_free(rsa);

            assert_eq!(
                RSA_X931_derive_ex(
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    e,
                    core::ptr::null_mut(),
                ),
                0
            );
            BN_free(e);
        }
    }
}
