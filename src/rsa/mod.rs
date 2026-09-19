//! `crypto/rsa/` — the `RSA` object and its method table.
//!
//! This module is Phase 8.4's, and it is being built in the slices D283 measured rather than all at
//! once, because the block is 150 labels and its parts have different prerequisites. What is here
//! now is the **method table** (`crypto/rsa/rsa_meth.c`, D284) and **the half of the padding
//! functions whose output is a pure function of its input** (`rsa_none.c`, `rsa_x931.c` and the
//! type-1 pair in `rsa_pk1.c`, D285).
//!
//! **The block is much more Phase 9-bound than D283's table implied, and D285 measured it.**
//! `RAND_bytes_ex` is Phase 9's, and it is reached by five of the padding *add* functions (the type
//! 2, both OAEP and both PSS adds), by the type-2 *check*'s implicit rejection, and — one level
//! further out — by the `RSA` object's own constructor, because `rsa_new_intern` takes its method
//! from `RSA_get_default_method()` and that table's first member is `rsa_ossl_public_encrypt`,
//! which pads randomly. Those six padding labels and the four constructor labels are recorded
//! Phase 9 hand-offs in `forensics/tools/phase8_obligations.py`'s `BLOCKED_HANDOFFS`.
//!
//! The other six slices, and what each still needs:
//!
//! * **B**, 33 labels, **landed** (D284): the method table.
//! * **C**, the padding add/check pairs for the five paddings (15) -- **its RAND-free half landed in
//!   D285**: `RSA_padding_add_none`, `_check_none`, `_add_X931`, `_check_X931`, `RSA_X931_hash_id`,
//!   `_add_PKCS1_type_1`, `_check_PKCS1_type_1`. What remains is the five randomised *adds* and the
//!   randomised type-2 *check* -- six Phase 9 hand-offs on `RAND_bytes_ex` -- plus the two OAEP
//!   checks and `PKCS1_MGF1`, which D285 measured as landable and which are not yet transcribed;
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

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};

use crate::bn::bignum::BigNum;
use crate::bn::ctx::{BnCtx, BnGencb};
use crate::bn::mont::MontCtx;
use crate::evp::pkey_asn1::Engine;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::ex_data::CryptoExData;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::{NID_sha1, NID_sha256, NID_sha384, NID_sha512};
use crate::runtime::stack::OpenSslStack;
use crate::runtime::thread::CryptoRwlock;

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
/// `crypto/rsa/rsa_asn1.c`. Opaque here because nothing in this slice dereferences it; slice F's
/// `d2i_`/`i2d_` pair and `RSA_PSS_PARAMS_dup` are where its members acquire a user.
#[repr(C)]
pub struct RsaPssParams {
    _private: [u8; 0],
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
    /// `CRYPTO_REF_COUNT references` — `_Atomic int` in this profile.
    pub references: c_uint,
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
// (`rsa_pk1.c:147`, `rsa_oaep.c:122`, `rsa_pss.c`'s salt), and three of the six *checks* need it
// for implicit rejection. What lands here is the half whose output is a **pure function of its
// input**: the `none` padding, X9.31, PKCS#1 v1.5 type 1, and the X9.31 hash ids. The other half is
// a Phase 9 hand-off, recorded in `docs/DECISIONS.md` D285 rather than left as unstated open work.

/// `RSA_PKCS1_PADDING_SIZE` — `include/openssl/rsa.h:206`. Eleven: the two header octets, eight
/// mandatory `0xFF` octets and the separating zero.
const RSA_PKCS1_PADDING_SIZE: c_int = 11;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
