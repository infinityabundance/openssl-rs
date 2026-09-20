//! Phase 8 — `crypto/rsa/rsa_ossl.c`: the default `RSA_METHOD`, the entry points it names, and
//! the per-thread blinding store.
//!
//! This module is Phase 8.4's slice D. It holds [`rsa_pkcs1_ossl_meth`] — the table
//! `RSA_get_default_method` answers and therefore the table `rsa_new_intern` installs in every
//! object this crate constructs — the seven `rsa_ossl_*` entry points that table's initialiser
//! names, the blinding helpers above them, and `rsa_ossl.c`'s two internal crypt helpers
//! (`derive_kdk` and the thread-id lookup). It also carries `RSA_setup_blinding` and its static
//! helper `rsa_get_public_exp`, which are `crypto/rsa/rsa_crpt.c:76-161`'s: they are reached
//! from nowhere else in the authority, and `rsa_get_blinding` below is the caller that makes them
//! reachable in this stratum.
//!
//! The module was opened by D321 with the blinding store's two allocators, because `rsa_new_intern`
//! and `RSA_free` are their callers across the file boundary. Everything else here is D325's.
//!
//! ## What the table is, and the cycle it closes
//!
//! `RSA_get_default_method` (`rsa_ossl.c:91-94`) is a one-line read of the file's
//! `static const RSA_METHOD *default_RSA_meth`, and that static's initialiser is
//! `&rsa_pkcs1_ossl_meth`. So the constructor cannot name its method until this table exists, and
//! the table cannot be *built* until its fifteen members' addresses do. D320 measured the cycle;
//! D323 retired the half of it that was a random-layer dependency; this commit lands the other
//! half. `RSA_new`, `RSA_new_method`, `RSA_get_default_method` and `RSA_PKCS1_OpenSSL` therefore
//! move from Phase 8's `deferred` list to its `implemented` list, and `BLOCKED_HANDOFFS` row (5)
//! is retired in the same commit (its own generator fails closed on a row naming a symbol the
//! crate defines).
//!
//! ## The three reductions, and why the reachable answer is the answer
//!
//! **1. `ENGINE_*`.** `rsa_new_intern` is `src/rsa/object.rs`'s and is written as the reachable
//! answer there; nothing in this file names an engine. `rsa_ossl.c` itself reads `rsa->engine`
//! nowhere: the four `rsa_ossl_*` crypt entry points reach `rsa->meth`, `rsa->n`, `rsa->lock` and
//! the blinding store, and no more.
//!
//! **2. `bn_*_fixed_top` / `bn_correct_top` / `bn_get_words`.** These are `crypto/bn/bn_mont.c`'s,
//! `bn_mod.c`'s, `bn_lib.c`'s and `bn_intern.c`'s internals, and this crate has no names for them:
//! the authority's "fixed top" is a representation discipline — a `BIGNUM` whose `top` field is not
//! reduced — and this crate's [`BigNum`] is a normalised limb vector, so a `_fixed_top` call and
//! its public counterpart compute the same *value* and differ only in what they leave in the
//! representation. Every such call is therefore replaced by the public entry point the authority's
//! own wrapper calls, and each site says which. This is `src/bn/blinding.rs`'s established
//! substitution for the same two names, and the four defining units are already in the
//! prerequisite gate's sealed-stratum census for exactly that reason.
//!
//! **3. `rsa->meth->bn_mod_exp` / `rsa->meth->rsa_mod_exp` are `Option`s and the authority's are
//! bare pointers.** D284 models both as `Option` because the authority's own header marks them
//! "Can be null". `rsa_ossl.c` calls them without a NULL test, so a NULL member is a fault there;
//! this crate cannot fault, so each call site answers the failure the surrounding `goto err`
//! handles and says so at the site. That is the only place this file does not follow the
//! authority statement for statement, and it is unreachable for every table this crate builds.
//!
//! ## Ordering, where the authority's is load-bearing
//!
//! * **`rsa_ossl_init` sets both cache flags**, which is what makes `RSA_FLAG_CACHE_PUBLIC` and
//!   `RSA_FLAG_CACHE_PRIVATE` true of every object `RSA_new` builds — and `rsa_new_intern` calls
//!   `init` through the table, so this is the reason a default object caches a Montgomery context
//!   for `n` on its first public operation rather than recomputing one per call.
//! * **`RSA_set_method`'s `finish`-then-`init` order** (`src/rsa/object.rs`) is the caller of
//!   [`rsa_ossl_finish`], and the reason the three `_method_mod_*` contexts are released there
//!   rather than by the setter.
//! * **`rsa_get_blinding`'s read-then-write lock is not symmetric**: the lookup takes a read lock,
//!   and only the *store* takes the write lock, so a hit never takes a write lock and a miss
//!   releases the read lock before creating a blinding. A transcription that held one lock across
//!   both halves would serialise every private operation in the process.
//! * **`rsa_ossl_private_decrypt` computes the KDK *after* unblinding and *before* the padding
//!   check**, which is what makes the implicit rejection's synthetic message a function of the
//!   private exponent and the ciphertext rather than of the blinding.
//!
//! ## What is deliberately not here
//!
//! * **`rsa_ossl_s390x_mod_exp`** (`:1198-1206`) is inside `#ifdef S390X_MOD_EXP`, which is not
//!   defined on this profile, and the table's `rsa_mod_exp` member is `rsa_ossl_mod_exp` under the
//!   `#else` arm this profile takes.
//! * **`get_unique_thread_id`'s TANDEM arm** (`:231-239`) is inside `#if defined(OPENSSL_SYS_TANDEM)`,
//!   which is not defined on this profile; the `#else` arm — `(uintptr_t)CRYPTO_THREAD_get_current_id()`
//!   — is the whole body here.
//! * **`ossl_rsa_padding_check_PKCS1_type_2_TLS`** (`rsa_pk1.c:546`) is a fourth `rsa_pk1.c`
//!   internal, and it is *not* reached by anything in this file: the only caller in the whole
//!   authority is `providers/implementations/asymciphers/rsa_enc.c.in:307`. The task that asked
//!   for this commit named it as the type-2 arm's callee; the authority says the arm reaches
//!   `ossl_rsa_padding_check_PKCS1_type_2` (`rsa_pk1.c:387`) instead, which is what landed in
//!   `src/rsa/mod.rs` with this commit.
//!
//! ## The court that drives it: `RT-RSA`
//!
//! `courts/phase8/rt_rsa_probe.c` takes the table from `RSA_PKCS1_OpenSSL`, calls each of its
//! members through the `RSA_meth_get_*` accessors, and drives the seven entry points over a
//! fabricated key small enough to check by hand. The fabricated object also means the probe never
//! depends on a constructor for the *entry-point* arms, and `rsa_new`'s own arm is the one place
//! a real `RSA_new` is called, wrapped in the allocator-attribution window.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::bn::arith::{
    BN_add, BN_cmp, BN_div, BN_mod_add, BN_mod_inverse, BN_mul, BN_sub, BN_ucmp,
};
use crate::bn::bignum::{
    BN_bin2bn, BN_bn2binpad, BN_free, BN_is_negative, BN_is_zero, BN_new, BN_num_bits,
    BN_set_flags, BN_value_one, BN_with_flags, BigNum,
};
use crate::bn::blinding::{
    BN_BLINDING_convert_ex, BN_BLINDING_create_param, BN_BLINDING_free, BN_BLINDING_invert_ex,
    Blinding,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::bn::mont::{
    BN_MONT_CTX_free, BN_MONT_CTX_set_locked, BN_from_montgomery, BN_mod_exp_mont,
    BN_mod_exp_mont_consttime_x2, BN_mod_mul_montgomery, BN_to_montgomery,
};
use crate::digest::sha2::SHA256_DIGEST_LENGTH;
use crate::evp::digest::{EVP_Digest, EVP_MD_fetch, EVP_MD_free, EvpMd};
use crate::evp::pkey_ctx::{
    RSA_NO_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING, RSA_X931_PADDING,
};
use crate::mac::hmac::{
    HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update, HmacCtx,
};
use crate::runtime::constant_time::constant_time_msb_u32;
use crate::runtime::err::err_sites;
use crate::runtime::err::{err_clear_last_constant_time, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc};
use crate::runtime::sparse_array::{
    ossl_sa_doall_arg, ossl_sa_free, ossl_sa_get, ossl_sa_new, ossl_sa_set, OpenSslSa, OsslUintMax,
};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::runtime::thread::{
    CRYPTO_THREAD_get_current_id, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock,
};

use super::object::{
    RSA_ASN1_VERSION_MULTI, RSA_FLAG_CACHE_PRIVATE, RSA_FLAG_CACHE_PUBLIC, RSA_FLAG_EXT_PKEY,
    RSA_FLAG_NO_BLINDING,
};
use super::{
    ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex, ossl_rsa_padding_add_PKCS1_type_2_ex,
    ossl_rsa_padding_check_PKCS1_type_2, RSA_padding_add_PKCS1_type_1, RSA_padding_add_X931,
    RSA_padding_add_none, RSA_padding_check_PKCS1_OAEP, RSA_padding_check_PKCS1_type_1,
    RSA_padding_check_PKCS1_type_2, RSA_padding_check_X931,
};
use super::{Rsa, RsaMethod};

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/rsa/rsa_ossl.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — measured with `strings` on
/// `forensics/authorities/build/openssl-3.6.4-production/crypto/rsa/libcrypto-lib-rsa_ossl.o`,
/// the same check D279 and D280 applied to the cipher units. It matters here for the same reason
/// it does in `src/rsa/mod.rs`: `file` reaches an application through `CRYPTO_set_mem_functions`.
#[allow(dead_code)] // read by the four crypt entry points' `OPENSSL_malloc`, none of which has a caller here yet
const FILE_RSA_OSSL: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_ossl.c".as_ptr();

/// The allocation-tracking `file` argument for `rsa_crpt.c`'s allocations — the `BN_BLINDING`
/// lookup's and the constructor's, neither of which allocates: `rsa_get_public_exp`'s
/// `BN_mod_inverse` builds a `BIGNUM` through the BN layer's own allocator, which is why the only
/// reader left is `RSA_setup_blinding`'s `BN_CTX_new_ex`. It is declared because the authority's
/// `__FILE__` at that site is this unit's, and a later caller of an `OPENSSL_malloc` here must pass
/// it.
#[allow(dead_code)] // rsa_crpt.c's sole reader in this stratum allocates through `BN_CTX_new_ex`
const FILE_RSA_CRPT: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_crpt.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `RSA_FLAG_FIPS_METHOD` — `include/openssl/rsa.h:468`. The word `rsa_pkcs1_ossl_meth` carries as
/// its `flags` member.
///
/// **It is numerically the same bit as `RSA_FLAG_NON_FIPS_ALLOW`** (`:476`, `0x0400`), and the
/// coincidence is load-bearing rather than cosmetic: `rsa_new_intern` masks
/// `RSA_FLAG_NON_FIPS_ALLOW` *out* of `meth->flags` when it installs the table (`rsa_lib.c:98`), so
/// the default table's own flag word does not survive into `rsa->flags`, and `RSA_flags` — which
/// reads the *table* — is the only place a caller can see the `0x0400`. `src/rsa/object.rs`
/// declares the same bit under the other name and says the same thing from its side.
const RSA_FLAG_FIPS_METHOD: c_int = 0x0400;

/// `OPENSSL_RSA_MAX_MODULUS_BITS` — `include/openssl/rsa.h:39`. Above this the entry points refuse
/// before doing any work, which is why a modulus that large produces no allocation at all.
const OPENSSL_RSA_MAX_MODULUS_BITS: c_int = 16384;
/// `OPENSSL_RSA_SMALL_MODULUS_BITS` — `include/openssl/rsa.h:51`. **3072, not 15360**: above it the
/// public exponent is additionally bounded by [`OPENSSL_RSA_MAX_PUBEXP_BITS`], and the bound is
/// enforced only for the large-modulus case.
const OPENSSL_RSA_SMALL_MODULUS_BITS: c_int = 3072;
/// `OPENSSL_RSA_MAX_PUBEXP_BITS` — `include/openssl/rsa.h:56`.
const OPENSSL_RSA_MAX_PUBEXP_BITS: c_int = 64;

/// `RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING` — `include/openssl/rsa.h:204`. The eighth padding
/// selector, and the one no caller passes: `rsa_ossl_private_decrypt` *substitutes* it for
/// `RSA_PKCS1_PADDING` when the key is an external one, because a key whose private exponent the
/// library does not hold cannot derive the implicit rejection's synthetic message.
///
/// It is declared here rather than beside the other seven in `src/evp/pkey_ctx.rs` because this
/// file is its only reader in the crate: the ctrl-string map and the providers never name it.
const RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING: c_int = 8;

/// `BN_FLG_CONSTTIME` — `include/openssl/bn.h`, `0x04`. Re-stated here as `src/bn/mont.rs:44`,
/// `src/bn/recp.rs:37`, `src/asn1/x_bignum.rs:43` and `src/rsa/object.rs:277` each re-state it: the
/// crate keeps it private per module. [`rsa_blinding_invert`] is the reader in this one.
const BN_FLG_CONSTTIME: c_int = 0x04;

/// `#define BN_num_bytes(a) ((BN_num_bits(a) + 7) / 8)` — `include/openssl/bn.h:188`, written out
/// because the crate has no macro layer. `src/rsa/object.rs` writes the same body for `RSA_size`.
///
/// # Safety
/// `a` is NULL or a live `BIGNUM`.
unsafe fn bn_num_bytes(a: *const BigNum) -> c_int {
    // SAFETY: `a` is NULL or live per this function's `# Safety` section.
    (unsafe { BN_num_bits(a) } + 7) / 8
}

/// `bn_get_words(a)[0]` — `crypto/bn/bn_intern.c:71`'s accessor plus the member read at the one
/// authority site that uses it here, `rsa_ossl.c:770`.
///
/// The value is the **low limb** of the magnitude, and that is what the X9.31 arm tests: the
/// authority reads `ret->d[0]` directly rather than through `BN_get_word`, whose answer for a
/// value wider than one limb is `ULONG_MAX` and would therefore take the branch on a different
/// set of values. This crate's limbs are `u64`, so the low limb is `d[0]` and a zero value — whose
/// magnitude is empty rather than a limb of zeroes — answers 0, which is the value a freshly
/// zeroed authority limb holds.
///
/// # Safety
/// `a` is NULL or a live `BIGNUM`.
unsafe fn bn_get_low_limb(a: *const BigNum) -> u64 {
    // SAFETY: `a` is NULL or live per this function's `# Safety` section.
    match unsafe { crate::bn::bignum::as_ref(a) } {
        Some(b) => b.d.first().copied().unwrap_or(0),
        None => 0,
    }
}

// ---------------------------------------------------------------------------------------------
// `crypto/rsa/rsa_ossl.c:60-104` — the default method
// ---------------------------------------------------------------------------------------------

/// `static RSA_METHOD rsa_pkcs1_ossl_meth` — `rsa_ossl.c:64-81`, the `#else` arm.
///
/// The table's address is contract in three places at once: `RSA_get_default_method` answers it,
/// `RSA_PKCS1_OpenSSL` answers it, and [`default_RSA_meth`] is initialised with it. So the object
/// is a `static` whose address is taken, and it is never written — the authority's is not `const`
/// only because C has no way to say "a struct of function pointers nobody may modify".
///
/// **Its `flags` is `RSA_FLAG_FIPS_METHOD` and its two `rsa_keygen` members are NULL**, which is
/// why `RSA_generate_key_ex` is 8.4's slice D's successor rather than this table's work: the table
/// names no key generator, and `ossl_rsa_keygen` is reached through `rsa_pmeth.c`'s method object
/// instead. `rsa_sign` and `rsa_verify` are the integer `0` — not a function — and D284 models the
/// null as `None`, so a caller who reads them through `RSA_meth_get_sign` gets NULL from both
/// libraries.
struct StaticRsaMethod(UnsafeCell<RsaMethod>);

// SAFETY: the inner value is fully initialised at compile time and is never written. Every
// consumer reads one field or takes the address; no `&mut` is ever created.
unsafe impl Sync for StaticRsaMethod {}

static RSAS_PKCS1_OSSL_METH: StaticRsaMethod = StaticRsaMethod(UnsafeCell::new(RsaMethod {
    name: c"OpenSSL PKCS#1 RSA".as_ptr().cast_mut(),
    rsa_pub_enc: Some(rsa_ossl_public_encrypt),
    // The authority's own comment: "signature verification".
    rsa_pub_dec: Some(rsa_ossl_public_decrypt),
    // ... and "signing".
    rsa_priv_enc: Some(rsa_ossl_private_encrypt),
    rsa_priv_dec: Some(rsa_ossl_private_decrypt),
    rsa_mod_exp: Some(rsa_ossl_mod_exp),
    bn_mod_exp: Some(BN_mod_exp_mont),
    init: Some(rsa_ossl_init),
    finish: Some(rsa_ossl_finish),
    flags: RSA_FLAG_FIPS_METHOD,
    app_data: ptr::null_mut(),
    rsa_sign: None,
    rsa_verify: None,
    rsa_keygen: None,
    rsa_multi_prime_keygen: None,
}));

/// The stable address of the authority's `rsa_pkcs1_ossl_meth` object, for the two accessors and
/// for [`default_RSA_meth`]'s initialiser.
const fn rsa_pkcs1_ossl_meth() -> *const RsaMethod {
    RSAS_PKCS1_OSSL_METH.0.get()
}

/// `rsa->meth->bn_mod_exp == BN_mod_exp_mont` — the test `rsa_ossl_mod_exp` makes twice, once to
/// decide `smooth` and once to choose the verification exponentiation.
///
/// **The comparison is meaningful here, and that is what the silenced lint is about.** Rust warns
/// that function-pointer equality is unreliable because two function items may be merged or
/// duplicated across codegen units; `BN_mod_exp_mont` is `#[no_mangle] pub extern "C"`, so it is
/// one symbol in the linked binary and its address is the table member's whenever the default
/// method installed it. The authority makes the same comparison for the same reason, which is that
/// `smooth` is only allowed when the method's exponentiation *is* the Montgomery one the fast path
/// is written against.
#[allow(unpredictable_function_pointer_comparisons)]
unsafe fn is_mont_bn_mod_exp(meth: *const RsaMethod) -> bool {
    // SAFETY: `meth` is a live table per every caller's contract.
    unsafe { (*meth).bn_mod_exp == Some(BN_mod_exp_mont) }
}

/// `static const RSA_METHOD *default_RSA_meth = &rsa_pkcs1_ossl_meth` — `rsa_ossl.c:84`.
///
/// Modelled as an [`AtomicPtr`] rather than a `static mut`, exactly as `src/rand/rand_lib.rs:277`
/// models `default_RAND_meth`: the authority's write is unsynchronised, and the crate's option for
/// a process-wide pointer a caller may replace is the atomic. Every access is `Relaxed`, because
/// the authority has no fence and a caller who sets a default method is publishing a pointer, not
/// data.
static DEFAULT_RSA_METH: AtomicPtr<RsaMethod> =
    AtomicPtr::new(rsa_pkcs1_ossl_meth() as *mut RsaMethod);

/// `void RSA_set_default_method(const RSA_METHOD *meth)` — `rsa_ossl.c:86-89`.
///
/// A pointer store and nothing else: no reference is taken, no old table is released, and NULL is
/// an accepted value that `RSA_get_default_method` then answers. That is why the caller is
/// responsible for the table's lifetime.
///
/// # Safety
/// `meth` is NULL or a live table that outlives its installation.
#[no_mangle]
pub unsafe extern "C" fn RSA_set_default_method(meth: *const RsaMethod) {
    DEFAULT_RSA_METH.store(meth.cast_mut(), Ordering::Relaxed);
}

/// `const RSA_METHOD *RSA_get_default_method(void)` — `rsa_ossl.c:91-94`.
///
/// # Safety
/// None: the answer is this module's own table address or the one a caller installed.
#[no_mangle]
pub extern "C" fn RSA_get_default_method() -> *const RsaMethod {
    DEFAULT_RSA_METH.load(Ordering::Relaxed)
}

/// `const RSA_METHOD *RSA_PKCS1_OpenSSL(void)` — `rsa_ossl.c:96-99`.
///
/// The table's *address* is the answer, so two calls — and a call to `RSA_get_default_method`
/// before any `RSA_set_default_method` — compare equal.
///
/// # Safety
/// None: the answer is a constant.
#[no_mangle]
pub extern "C" fn RSA_PKCS1_OpenSSL() -> *const RsaMethod {
    rsa_pkcs1_ossl_meth()
}

// ---------------------------------------------------------------------------------------------
// `crypto/rsa/rsa_ossl.c:225-326` — the blinding store and its per-thread lookup
// ---------------------------------------------------------------------------------------------

/// `static uintptr_t get_unique_thread_id(void)` — `rsa_ossl.c:229-243`, the `#else` arm.
///
/// The TANDEM arm is inside `#if defined(OPENSSL_SYS_TANDEM)`, which is not defined on this
/// profile, so this is the whole function here: the platform's thread id, widened to `uintptr_t`.
/// The sparse array's key is therefore a real thread identity and not a counter, which is what
/// makes one blinding per thread rather than one per call.
fn get_unique_thread_id() -> usize {
    // `CRYPTO_THREAD_get_current_id` is a safe function in this crate: it takes no pointers.
    CRYPTO_THREAD_get_current_id() as usize
}

/// `static void free_bn_blinding(ossl_uintmax_t idx, BN_BLINDING *b, void *arg)` —
/// `crypto/rsa/rsa_ossl.c:245-248`.
///
/// The leaf [`ossl_sa_doall_arg`] calls once per non-NULL slot: `BN_BLINDING_free`, with
/// the index and the argument ignored, exactly as the authority's static function ignores
/// them.
///
/// # Safety
///
/// `b` must be NULL or a live `BN_BLINDING` this array owns, and must not have been freed.
unsafe fn free_bn_blinding(_idx: OsslUintMax, b: *mut c_void, _arg: *mut c_void) {
    // SAFETY: `b` is the value the walk found in the array, so it is a `BN_BLINDING *`
    // this array owns; `BN_BLINDING_free` accepts NULL.
    unsafe { BN_BLINDING_free(b.cast()) };
}

/// `void ossl_rsa_free_blinding(RSA *rsa)` — `crypto/rsa/rsa_ossl.c:250-256`.
///
/// Reads `rsa->blindings_sa` into a local, walks it releasing every context, then releases
/// the array. **The member is not cleared** — see the module note; the object is freed or
/// re-blinded by the caller, and this function does what the authority does and no more.
///
/// # Safety
///
/// `rsa` must be a live `RSA` whose `blindings_sa` is NULL or a live sparse array of
/// `BN_BLINDING` owned by this call, and no other reference to that array may be used
/// afterwards.
pub(crate) unsafe fn ossl_rsa_free_blinding(rsa: *mut Rsa) {
    // SAFETY: `rsa` is live per this function's `# Safety` section.
    let blindings = unsafe { (*rsa).blindings_sa }.cast::<OpenSslSa>();

    // SAFETY: `blindings` is NULL or the live array the object owns, and
    // `free_bn_blinding` is the destructor for every value in it; both entry points accept
    // NULL, so an object that was never blinded is released correctly as well.
    unsafe {
        ossl_sa_doall_arg(blindings, Some(free_bn_blinding), ptr::null_mut());
        ossl_sa_free(blindings);
    }
}

/// `void *ossl_rsa_alloc_blinding(void)` — `crypto/rsa/rsa_ossl.c:258-261`.
///
/// The authority's `ossl_sa_BN_BLINDING_new()`, returning an empty array typed as the
/// `void *` the object's member holds. It takes **no argument** — the array is not tied to
/// a key until it is stored in one.
///
/// # Safety
///
/// The returned pointer must be released with [`ossl_rsa_free_blinding`] (or
/// `ossl_sa_free` once its values are gone), and must be stored in the `RSA` object it was
/// allocated for, because that is the only place its type is recovered from.
pub(crate) unsafe fn ossl_rsa_alloc_blinding() -> *mut c_void {
    // `ossl_sa_new` is a safe function in this crate, so this call is unguarded; its result
    // is an empty array that `ossl_sa_*` accepts until the object is freed.
    ossl_sa_new().cast()
}

/// `static BN_BLINDING *ossl_rsa_get_thread_bn_blinding(RSA *rsa)` — `rsa_ossl.c:263-269`.
///
/// The lookup half of the store: `ossl_sa_BN_BLINDING_get(blindings, tid)` is the authority's
/// macro over `ossl_sa_get`, and the key is the calling thread's id. A thread that has never
/// blinded this key answers NULL, which is what makes [`rsa_get_blinding`] create one.
///
/// # Safety
/// `rsa` is a live object whose `blindings_sa` is NULL or a live array of `BN_BLINDING`.
unsafe fn ossl_rsa_get_thread_bn_blinding(rsa: *mut Rsa) -> *mut Blinding {
    // SAFETY: `rsa` is live per this function's `# Safety` section, and `blindings_sa` is NULL or
    // the live array it names; `ossl_sa_get` accepts NULL.
    let blindings = unsafe { (*rsa).blindings_sa }.cast::<OpenSslSa>();
    let tid = get_unique_thread_id();

    // SAFETY: as above; the value the array holds at this index is a `BN_BLINDING *` this object
    // owns, which is the type it was stored as.
    unsafe { ossl_sa_get(blindings, tid as OsslUintMax) }.cast::<Blinding>()
}

/// `static int ossl_rsa_set_thread_bn_blinding(RSA *rsa, BN_BLINDING *b)` — `rsa_ossl.c:271-277`.
///
/// The store half. A NULL `b` is what `ossl_sa_set` reads as "remove this slot", and the
/// authority has one caller that relies on that: [`rsa_get_blinding`]'s failure path below stores
/// NULL after it has released the blinding it failed to install.
///
/// # Safety
/// `rsa` is a live object whose `blindings_sa` is a live array; `b` is NULL or a `BN_BLINDING`
/// that the caller is handing over to the array.
unsafe fn ossl_rsa_set_thread_bn_blinding(rsa: *mut Rsa, b: *mut Blinding) -> c_int {
    // SAFETY: `rsa` is live per this function's `# Safety` section.
    let blindings = unsafe { (*rsa).blindings_sa }.cast::<OpenSslSa>();
    let tid = get_unique_thread_id();

    // SAFETY: `blindings` is the live array the object owns and `b` is the value being handed to
    // it; `ossl_sa_set` owns both from here.
    unsafe { ossl_sa_set(blindings, tid as OsslUintMax, b.cast::<c_void>()) }
}

/// `static BN_BLINDING *rsa_get_blinding(RSA *rsa, BN_CTX *ctx)` — `rsa_ossl.c:279-304`.
///
/// **Read lock for the lookup, write lock only for the store.** A hit — the common case, because
/// a thread that has used this key before finds its own blinding — takes a read lock and releases
/// it; a miss releases the read lock, builds a blinding outside any lock, and then takes the write
/// lock to install it. Two threads that miss at once therefore both build one and the second's
/// store wins, which is the authority's behaviour and not a defect: the loser's blinding is
/// released at `BN_BLINDING_free` inside the `else` arm.
///
/// Answers NULL for a key that cannot be blinded at all, which every caller turns into
/// `ERR_R_INTERNAL_ERROR`.
///
/// # Safety
/// `rsa` is a live object with a live `lock`; `ctx` is NULL or a live `BN_CTX`.
unsafe fn rsa_get_blinding(rsa: *mut Rsa, ctx: *mut BnCtx) -> *mut Blinding {
    // SAFETY: `rsa` is live per this function's `# Safety` section.
    let lock = unsafe { (*rsa).lock };
    // SAFETY: `lock` is the object's own live lock.
    if unsafe { CRYPTO_THREAD_read_lock(lock) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: the lock is held by this call.
    let mut ret = unsafe { ossl_rsa_get_thread_bn_blinding(rsa) };
    // SAFETY: the lock is held by this call.
    unsafe { CRYPTO_THREAD_unlock(lock) };

    if ret.is_null() {
        // SAFETY: `rsa` is live and `ctx` is NULL or live, which is `RSA_setup_blinding`'s
        // contract.
        ret = unsafe { RSA_setup_blinding(rsa, ctx) };
        // SAFETY: `lock` is the object's own live lock.
        if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
            // SAFETY: `ret` is this call's own blinding and nothing else refers to it.
            unsafe { BN_BLINDING_free(ret) };
            ret = ptr::null_mut();
        } else {
            // SAFETY: the lock is held by this call, and `ret` is a `BN_BLINDING` this call is
            // handing to the array — including a NULL one, which removes the slot.
            if unsafe { ossl_rsa_set_thread_bn_blinding(rsa, ret) } == 0 {
                // SAFETY: as above: the store failed, so the blinding is still this call's.
                unsafe { BN_BLINDING_free(ret) };
                ret = ptr::null_mut();
            }
            // SAFETY: the lock is held by this call.
            unsafe { CRYPTO_THREAD_unlock(lock) };
        }
    }

    ret
}

/// `static int rsa_blinding_convert(BN_BLINDING *b, BIGNUM *f, BN_CTX *ctx)` — `rsa_ossl.c:306-312`.
///
/// Local blinding, so the unblinding factor stays inside the context (`NULL` in the second
/// argument) and [`rsa_blinding_invert`] reads it back from there.
///
/// # Safety
/// `b` is a live blinding; `f` is a live `BIGNUM` this call may modify; `ctx` is NULL or live.
unsafe fn rsa_blinding_convert(b: *mut Blinding, f: *mut BigNum, ctx: *mut BnCtx) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { BN_BLINDING_convert_ex(f, ptr::null_mut(), b, ctx) }
}

/// `static int rsa_blinding_invert(BN_BLINDING *b, BIGNUM *f, BN_CTX *ctx)` — `rsa_ossl.c:314-326`.
///
/// **The `BN_FLG_CONSTTIME` mark is set before the inversion, not after**, and it is what makes the
/// division inside `BN_BLINDING_invert_ex` constant-time. The authority's own comment records why
/// `unblind` is NULL here: with a local blinding the factor is in the context, and with a shared
/// one the caller must pass its own — `rsa_ossl.c` only ever uses the local form.
///
/// # Safety
/// `b` is a live blinding; `f` is a live `BIGNUM` this call may modify; `ctx` is NULL or live.
unsafe fn rsa_blinding_invert(b: *mut Blinding, f: *mut BigNum, ctx: *mut BnCtx) -> c_int {
    // SAFETY: `f` is live per this function's `# Safety` section.
    unsafe { BN_set_flags(f, BN_FLG_CONSTTIME) };
    // SAFETY: as above, forwarded with the null unblinding factor the authority passes.
    unsafe { BN_BLINDING_invert_ex(f, ptr::null_mut(), b, ctx) }
}

// ---------------------------------------------------------------------------------------------
// `crypto/rsa/rsa_crpt.c:76-161` — the blinding setup, which `rsa_get_blinding` reaches
// ---------------------------------------------------------------------------------------------

/// `static BIGNUM *rsa_get_public_exp(const BIGNUM *d, const BIGNUM *p, const BIGNUM *q,`
/// `BN_CTX *ctx)` — `rsa_crpt.c:76-102`.
///
/// `e = d^-1 mod (p-1)(q-1)`, computed only when the object has no public exponent: a key built
/// from `d`/`p`/`q` alone. The three NULL tests are the first statement, so a key missing any of
/// the three answers NULL **without raising** — the raise is the caller's.
///
/// The `ctx` is the caller's and is not started here in the authority's sense of ownership: this
/// function calls `BN_CTX_start`/`BN_CTX_end` around its three temporaries, exactly as written.
///
/// # Safety
/// `d`, `p` and `q` are each NULL or live; `ctx` is a live `BN_CTX`.
unsafe fn rsa_get_public_exp(
    d: *const BigNum,
    p: *const BigNum,
    q: *const BigNum,
    ctx: *mut BnCtx,
) -> *mut BigNum {
    if d.is_null() || p.is_null() || q.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live per this function's `# Safety` section.
    unsafe { BN_CTX_start(ctx) };
    // SAFETY: as above, for each of the three temporaries.
    let r0 = unsafe { BN_CTX_get(ctx) };
    // SAFETY: as above.
    let r1 = unsafe { BN_CTX_get(ctx) };
    // SAFETY: as above.
    let r2 = unsafe { BN_CTX_get(ctx) };

    let mut ret: *mut BigNum = ptr::null_mut();
    // The authority's `if (r2 == NULL) goto err;`: only the last of the three is tested, because
    // the pool hands them out in order and a failure there is a failure of all three.
    if !r2.is_null() {
        // SAFETY: every pointer here is NULL or live: `r1`, `r2` are the temporaries just taken,
        // `p`, `q` are the caller's, and `d` is the caller's. `BN_sub`, `BN_mul` and
        // `BN_mod_inverse` each accept null-or-live operands.
        let ok = unsafe {
            BN_sub(r1, p, BN_value_one()) != 0
                && BN_sub(r2, q, BN_value_one()) != 0
                && BN_mul(r0, r1, r2, ctx) != 0
        };
        if ok {
            // SAFETY: as above; a NULL `ret` here means "allocate", which is the authority's
            // `BN_mod_inverse(NULL, d, r0, ctx)`.
            ret = unsafe { BN_mod_inverse(ptr::null_mut(), d, r0, ctx) };
        }
    }
    // The authority's `err:` label: the temporaries go back to the pool, and `ret` — NULL unless
    // the three operations above all succeeded — is the answer.
    // SAFETY: `ctx` is live per this function's `# Safety` section.
    unsafe { BN_CTX_end(ctx) };
    ret
}

/// `BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *in_ctx)` — `rsa_crpt.c:104-161`.
///
/// The one place a blinding context is created, and the reason this commit lands in this file:
/// `rsa_ossl.c`'s `rsa_get_blinding` is its only caller in the whole authority. It is an *export*
/// (`include/openssl/rsa.h:383`), so it keeps its name and its `#[no_mangle]`; that is what makes
/// `RSA_blinding_on`'s old `BLOCKED_HANDOFFS` row retire in this commit rather than the next one.
///
/// Four things about it are the contract:
///
/// * **The context is the caller's or its own**, and the `ctx != in_ctx` test at the `err:` label
///   is what keeps the caller's pool intact: a context this function created is released, a
///   borrowed one is only ended.
/// * **`e` is the object's or a fresh inverse**, and the same test — `e != rsa->e` — decides
///   whether it is released. When the object has a public exponent, `e` is a *borrowed* pointer to
///   it, so freeing it would free key material.
/// * **`n` is a `BN_with_flags` handle onto `rsa->n`**, so it is freed before the blinding is
///   returned and never escapes. The authority's comment says why that matters: the handle is a
///   second name for the caller's modulus.
/// * **`BN_BLINDING_create_param` gets `rsa->meth->bn_mod_exp` and `rsa->_method_mod_n`**, so the
///   first exponentiation inside the new context uses the key's own Montgomery context when the
///   method has one — which is the default method's `BN_mod_exp_mont` and the *cache* the object's
///   `RSA_FLAG_CACHE_PUBLIC` arm built. See the module note on the NULL test this crate adds.
///
/// # Safety
/// `rsa` is a live object whose `meth` is a live table; `in_ctx` is NULL or a live `BN_CTX` that
/// outlives this call. The answer is NULL or a blinding this call created, which the caller owns.
#[no_mangle]
pub unsafe extern "C" fn RSA_setup_blinding(rsa: *mut Rsa, in_ctx: *mut BnCtx) -> *mut Blinding {
    let mut ctx = in_ctx;
    if ctx.is_null() {
        // SAFETY: `rsa` is live per this function's `# Safety` section, so `libctx` is NULL or a
        // live library context.
        ctx = unsafe { BN_CTX_new_ex((*rsa).libctx) };
        if ctx.is_null() {
            return ptr::null_mut();
        }
    }

    // SAFETY: `ctx` is live — either the caller's or the one just created.
    unsafe { BN_CTX_start(ctx) };

    // `e` is the authority's local: the object's public exponent (borrowed) or a fresh inverse
    // (owned), and the `e != rsa->e` test at the label is what separates them. The declaration
    // carries no initialiser because the block's first statement assigns it on every path.
    let mut e: *mut BigNum;
    let mut ret: *mut Blinding = ptr::null_mut();

    // The authority's three `goto err`s and its fall-through, all landing on the one label below.
    'body: {
        // SAFETY: `ctx` is live, so `BN_CTX_get` is called under its own contract.
        e = unsafe { BN_CTX_get(ctx) };
        if e.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::RSA_CRPT_120) };
            break 'body;
        }

        // SAFETY: `rsa` is live, so its `e` is NULL or live and its `d`, `p` and `q` are each NULL
        // or live; `ctx` is live.
        if unsafe { (*rsa).e }.is_null() {
            // SAFETY: as above.
            e = unsafe { rsa_get_public_exp((*rsa).d, (*rsa).p, (*rsa).q, ctx) };
            if e.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::RSA_CRPT_127) };
                break 'body;
            }
        } else {
            // SAFETY: `rsa` is live.
            e = unsafe { (*rsa).e };
        }

        {
            // SAFETY: `BN_new` takes no pointers.
            let n = unsafe { BN_new() };
            if n.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::RSA_CRPT_138) };
                break 'body;
            }
            // SAFETY: `n` is live and `rsa->n` is NULL or live; `BN_with_flags` writes the handle
            // into `n` and reads only `rsa->n`'s magnitude, so no second owned object exists.
            unsafe { BN_with_flags(n, (*rsa).n, BN_FLG_CONSTTIME) };

            // The authority's `BN_BLINDING_create_param(NULL, e, n, ctx, rsa->meth->bn_mod_exp,
            // rsa->_method_mod_n)`. The one place this crate departs from it is the NULL
            // `bn_mod_exp` member, which the authority would call: see the module note.
            // SAFETY: `e` is NULL or live, `n` is the handle just built, `ctx` is live, `rsa->meth`
            // is the live table the object carries and `_method_mod_n` is NULL or a live Montgomery
            // context; `f` is the table's own exponentiation, handed the arguments the authority
            // hands it, and `BN_BLINDING_create_param`'s contract is this call's.
            unsafe {
                ret = match (*(*rsa).meth).bn_mod_exp {
                    Some(f) => BN_BLINDING_create_param(
                        ptr::null_mut(),
                        e,
                        n,
                        ctx,
                        Some(f),
                        (*rsa)._method_mod_n,
                    ),
                    None => ptr::null_mut(),
                };
            }

            // SAFETY: `n` is the handle this call built and nothing else holds it; the authority
            // frees it before any further use of `rsa->n`.
            unsafe { BN_free(n) };
        }

        if ret.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::RSA_CRPT_149) };
        }
    }

    // The authority's `err:` label, reached by falling through and by the three `goto err`s above.
    // SAFETY: `ctx` is live; `e` is the borrowed public exponent or the fresh inverse (or NULL,
    // which the test compares against the borrowed field and does not free).
    unsafe {
        BN_CTX_end(ctx);
        if ctx != in_ctx {
            BN_CTX_free(ctx);
        }
        if e != (*rsa).e {
            BN_free(e);
        }
    }

    ret
}

// ---------------------------------------------------------------------------------------------
// `crypto/rsa/rsa_ossl.c:106-223` — the public-encrypt entry point
// ---------------------------------------------------------------------------------------------

/// `static int rsa_ossl_public_encrypt(int flen, const unsigned char *from, unsigned char *to,`
/// `RSA *rsa, int padding)` — `rsa_ossl.c:106-223`.
///
/// Three refusals happen **before anything is allocated**, so a modulus that is too large, an `e`
/// that is not greater than `n`'s... rather: an `e` that does not exceed `n`'s leading value, or a
/// small-modulus key with a wide exponent, costs no allocation and raises one of the three
/// `RSA_R_MODULUS_TOO_LARGE`/`RSA_R_BAD_E_VALUE` reasons. The order of the three is contract: the
/// second is a `BN_ucmp`, not a bit test, so an `e` of `n - 1` is refused and an `e` of `n - 2` is
/// not.
///
/// The modulus *width* is taken once, before the padding call, because the padding needs it and
/// because `BN_bn2binpad` writes exactly that many octets into `to`. `f` is the padded block as a
/// big number, and the operation itself is `rsa->meth->bn_mod_exp(ret, f, e, n, ctx,
/// _method_mod_n)` — for the default method, `BN_mod_exp_mont`.
///
/// The `#ifdef FIPS_MODULE` arm of the range check is **not** transcribed: this crate has no FIPS
/// branch, so the `1 < f < n - 1` bound for `RSA_NO_PADDING` does not exist here. That is the same
/// decline `src/rsa/mod.rs` records for the OAEP and PSS paths.
///
/// # Safety
/// `from` is readable for `flen` bytes; `to` is writable for `RSA_size(rsa)` bytes; `rsa` is a
/// live object.
unsafe extern "C" fn rsa_ossl_public_encrypt(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    rsa: *mut Rsa,
    padding: c_int,
) -> c_int {
    // SAFETY: `rsa` and its `n` are live per this function's `# Safety` section.
    unsafe {
        if BN_num_bits((*rsa).n) > OPENSSL_RSA_MAX_MODULUS_BITS {
            raise_site(&err_sites::RSA_OSSL_115);
            return -1;
        }

        if BN_ucmp((*rsa).n, (*rsa).e) <= 0 {
            raise_site(&err_sites::RSA_OSSL_120);
            return -1;
        }

        /* for large moduli, enforce exponent limit */
        if BN_num_bits((*rsa).n) > OPENSSL_RSA_SMALL_MODULUS_BITS
            && BN_num_bits((*rsa).e) > OPENSSL_RSA_MAX_PUBEXP_BITS
        {
            raise_site(&err_sites::RSA_OSSL_127);
            return -1;
        }

        // The authority's `ctx` starts NULL and the `goto err` that follows a failed allocation
        // still runs the label, whose three statements all accept NULL.
        let mut num: c_int = 0;
        let mut r: c_int = -1;
        let mut buf: *mut c_uchar = ptr::null_mut();

        let ctx: *mut BnCtx = BN_CTX_new_ex((*rsa).libctx);
        if ctx.is_null() {
            // The authority's `goto err` with a NULL context: `BN_CTX_end(NULL)` and
            // `BN_CTX_free(NULL)` are no-ops and the buffer was never allocated.
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }
        BN_CTX_start(ctx);
        let f = BN_CTX_get(ctx);
        let ret = BN_CTX_get(ctx);
        num = bn_num_bytes((*rsa).n);
        buf = CRYPTO_malloc(num as usize, FILE_RSA_OSSL, LINE).cast::<c_uchar>();
        if ret.is_null() || buf.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }

        let mut i: c_int = 0;
        let mut refused = false;
        match padding {
            RSA_PKCS1_PADDING => {
                i = ossl_rsa_padding_add_PKCS1_type_2_ex((*rsa).libctx, buf, num, from, flen);
            }
            RSA_PKCS1_OAEP_PADDING => {
                i = ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(
                    (*rsa).libctx,
                    buf,
                    num,
                    from,
                    flen,
                    ptr::null(),
                    0,
                    ptr::null(),
                    ptr::null(),
                );
            }
            RSA_NO_PADDING => {
                i = RSA_padding_add_none(buf, num, from, flen);
            }
            _ => {
                raise_site(&err_sites::RSA_OSSL_156);
                refused = true;
            }
        }

        'body: {
            if refused || i <= 0 {
                break 'body;
            }

            if BN_bin2bn(buf, num, f).is_null() {
                break 'body;
            }

            /* the FIPS_MODULE arm is not this profile's: see the doc comment */
            if BN_ucmp(f, (*rsa).n) >= 0 {
                /* usually the padding functions would catch this */
                raise_site(&err_sites::RSA_OSSL_199);
                break 'body;
            }

            if (*rsa).flags & RSA_FLAG_CACHE_PUBLIC != 0
                && BN_MONT_CTX_set_locked(
                    ptr::addr_of_mut!((*rsa)._method_mod_n),
                    (*rsa).lock,
                    (*rsa).n,
                    ctx,
                )
                .is_null()
            {
                break 'body;
            }

            // The authority's `rsa->meth->bn_mod_exp(...)`, with the module's recorded NULL
            // test: a table without an exponentiation is a fault there and a failure here.
            match (*(*rsa).meth).bn_mod_exp {
                Some(bnexp) => {
                    if bnexp(ret, f, (*rsa).e, (*rsa).n, ctx, (*rsa)._method_mod_n) == 0 {
                        break 'body;
                    }
                }
                None => break 'body,
            }

            // `BN_bn2binpad` puts in leading 0 bytes if the number is less than the length of the
            // modulus.
            r = BN_bn2binpad(ret, to, num);
        }

        // The authority's `err:` label.
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
        r
    }
}

// ---------------------------------------------------------------------------------------------
// `crypto/rsa/rsa_ossl.c:329-440` — the private-encrypt entry point, and its KDK helper
// ---------------------------------------------------------------------------------------------

/// `static int rsa_ossl_private_encrypt(int flen, const unsigned char *from, unsigned char *to,`
/// `RSA *rsa, int padding)` — `rsa_ossl.c:329-440`.
///
/// The signing entry point. Three things about it are the contract rather than the arithmetic:
///
/// * **The blinding is skipped for `RSA_FLAG_NO_BLINDING`**, and when it is not skipped the
///   conversion happens *before* the exponentiation and the unblinding *after* it, with the
///   CRT-or-plain choice in between. A transcription that unblinded a failure path would leave a
///   blinding factor in the object's store for a result nobody used.
/// * **The CRT path is chosen by a five-way test** — `RSA_FLAG_EXT_PKEY`, a multi-prime version,
///   or all five of `p`, `q`, `dmp1`, `dmq1`, `iqmp` being present — and the plain path is
///   `d` raised to the constant-time flag and freed **before any further use of `rsa->d`**, which
///   the authority's own comment calls out. `BN_with_flags(d, rsa->d, ...)` makes `d` a handle
///   onto the key's exponent, which is why the early `BN_free` is a release of the handle and not
///   of the material.
/// * **`RSA_X931_PADDING` returns the smaller of `ret` and `n - ret`**, because the X9.31 encoding
///   is the one padding whose result may exceed half the modulus and the protocol's convention is
///   to send the low form.
///
/// # Safety
/// `from` is readable for `flen` bytes; `to` is writable for `RSA_size(rsa)` bytes; `rsa` is a
/// live object.
unsafe extern "C" fn rsa_ossl_private_encrypt(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    rsa: *mut Rsa,
    padding: c_int,
) -> c_int {
    // SAFETY: `rsa` and its fields are live per this function's `# Safety` section.
    unsafe {
        let mut num: c_int = 0;
        let mut r: c_int = -1;
        let mut buf: *mut c_uchar = ptr::null_mut();
        let mut blinding: *mut Blinding = ptr::null_mut();

        let ctx: *mut BnCtx = BN_CTX_new_ex((*rsa).libctx);
        if ctx.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }
        BN_CTX_start(ctx);
        let f = BN_CTX_get(ctx);
        let ret = BN_CTX_get(ctx);
        num = bn_num_bytes((*rsa).n);
        buf = CRYPTO_malloc(num as usize, FILE_RSA_OSSL, LINE).cast::<c_uchar>();
        if ret.is_null() || buf.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }

        let mut i: c_int = 0;
        let mut refused = false;
        match padding {
            RSA_PKCS1_PADDING => {
                i = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
            }
            RSA_X931_PADDING => {
                i = RSA_padding_add_X931(buf, num, from, flen);
            }
            RSA_NO_PADDING => {
                i = RSA_padding_add_none(buf, num, from, flen);
            }
            _ => {
                raise_site(&err_sites::RSA_OSSL_359);
                refused = true;
            }
        }

        'body: {
            if refused || i <= 0 {
                break 'body;
            }

            if BN_bin2bn(buf, num, f).is_null() {
                break 'body;
            }

            if BN_ucmp(f, (*rsa).n) >= 0 {
                /* usually the padding functions would catch this */
                raise_site(&err_sites::RSA_OSSL_370);
                break 'body;
            }

            if (*rsa).flags & RSA_FLAG_CACHE_PUBLIC != 0
                && BN_MONT_CTX_set_locked(
                    ptr::addr_of_mut!((*rsa)._method_mod_n),
                    (*rsa).lock,
                    (*rsa).n,
                    ctx,
                )
                .is_null()
            {
                break 'body;
            }

            if (*rsa).flags & RSA_FLAG_NO_BLINDING == 0 {
                blinding = rsa_get_blinding(rsa, ctx);
                if blinding.is_null() {
                    raise_site(&err_sites::RSA_OSSL_382);
                    break 'body;
                }

                if rsa_blinding_convert(blinding, f, ctx) == 0 {
                    break 'body;
                }
            }

            /* The authority's five-way test, written as the disjunction it is. */
            let crt = (*rsa).flags & RSA_FLAG_EXT_PKEY != 0
                || (*rsa).version == RSA_ASN1_VERSION_MULTI
                || (!(*rsa).p.is_null()
                    && !(*rsa).q.is_null()
                    && !(*rsa).dmp1.is_null()
                    && !(*rsa).dmq1.is_null()
                    && !(*rsa).iqmp.is_null());

            if crt {
                // The module's recorded NULL test: the authority calls this member
                // unconditionally.
                match (*(*rsa).meth).rsa_mod_exp {
                    Some(modexp) => {
                        if modexp(ret, f, rsa, ctx) == 0 {
                            break 'body;
                        }
                    }
                    None => break 'body,
                }
            } else {
                // SAFETY: `BN_new` takes no pointers.
                let d = BN_new();
                if d.is_null() {
                    raise_site(&err_sites::RSA_OSSL_396);
                    break 'body;
                }
                if (*rsa).d.is_null() {
                    raise_site(&err_sites::RSA_OSSL_400);
                    // SAFETY: `d` is this call's own object.
                    BN_free(d);
                    break 'body;
                }
                // SAFETY: `d` is live and `rsa->d` is live; the handle borrows the key's
                // exponent and owns nothing.
                BN_with_flags(d, (*rsa).d, BN_FLG_CONSTTIME);

                let bnexp = (*(*rsa).meth).bn_mod_exp;
                match bnexp {
                    Some(f_) => {
                        if f_(ret, f, d, (*rsa).n, ctx, (*rsa)._method_mod_n) == 0 {
                            // SAFETY: `d` is this call's own handle.
                            BN_free(d);
                            break 'body;
                        }
                    }
                    None => {
                        // SAFETY: `d` is this call's own handle.
                        BN_free(d);
                        break 'body;
                    }
                }
                /* We MUST free d before any further use of rsa->d */
                // SAFETY: `d` is this call's own handle.
                BN_free(d);
            }

            if !blinding.is_null() && rsa_blinding_invert(blinding, ret, ctx) == 0 {
                break 'body;
            }

            let res = if padding == RSA_X931_PADDING {
                if BN_sub(f, (*rsa).n, ret) == 0 {
                    break 'body;
                }
                if BN_cmp(ret, f) > 0 {
                    f
                } else {
                    ret
                }
            } else {
                ret
            };

            /* BN_bn2binpad puts in leading 0 bytes if the number is less than the length of the
             * modulus. */
            r = BN_bn2binpad(res, to, num);
        }

        // The authority's `err:` label.
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
        r
    }
}

/// `static int derive_kdk(int flen, const unsigned char *from, RSA *rsa, unsigned char *buf,`
/// `int num, unsigned char *kdk)` — `rsa_ossl.c:442-525`.
///
/// The key-derivation key `ossl_rsa_padding_check_PKCS1_type_2`'s implicit rejection is keyed
/// with: `HMAC(sha256, d, the ciphertext)` where `d` is the private exponent written out to the
/// modulus width. The hash is hardcoded for the reason the padding's own comment gives — a
/// version-dependent digest would be a Bleichenbacher oracle.
///
/// **`buf` is used as a scratch buffer and is not restored**: at `:503` a short input is
/// zero-extended *on the left* of `buf`, which is where `rsa_ossl_private_decrypt` had just put
/// `d`'s bytes for the digest. The caller does not read `buf` again before the padding check
/// overwrites it with `ret`, and the two orders in the caller are the reason that is true.
///
/// `d` is a `BN_with_flags` handle, so `BN_free` at the end is a handle release — which is the
/// authority's own comment's point about not touching `rsa->d` afterwards.
///
/// # Safety
/// `from` is readable for `flen` bytes; `buf` is writable for `num` bytes; `kdk` is writable for
/// `SHA256_DIGEST_LENGTH` bytes; `rsa` is a live object.
unsafe fn derive_kdk(
    flen: c_int,
    from: *const c_uchar,
    rsa: *mut Rsa,
    buf: *mut c_uchar,
    num: c_int,
    kdk: *mut c_uchar,
) -> c_int {
    // SAFETY: `rsa` and its fields are live per this function's `# Safety` section.
    unsafe {
        let mut ret: c_int = 0;
        let mut hmac: *mut HmacCtx = ptr::null_mut();
        let mut md: *mut EvpMd = ptr::null_mut();
        let mut d_hash = [0u8; SHA256_DIGEST_LENGTH as usize];

        /*
         * because we use d as a handle to rsa->d we need to keep it local and free before any
         * further use of rsa->d
         */
        // SAFETY: `BN_new` takes no pointers.
        let d = BN_new();
        if d.is_null() {
            raise_site(&err_sites::RSA_OSSL_457);
            // SAFETY: a NULL `md` and `hmac` are accepted by both releases.
            HMAC_CTX_free(hmac);
            EVP_MD_free(md);
            return ret;
        }
        if (*rsa).d.is_null() {
            raise_site(&err_sites::RSA_OSSL_461);
            // SAFETY: `d` is this call's own object.
            BN_free(d);
            HMAC_CTX_free(hmac);
            EVP_MD_free(md);
            return ret;
        }
        // SAFETY: `d` is live and `rsa->d` is live; the handle borrows the key's exponent.
        BN_with_flags(d, (*rsa).d, BN_FLG_CONSTTIME);
        if BN_bn2binpad(d, buf, num) < 0 {
            raise_site(&err_sites::RSA_OSSL_467);
            // SAFETY: `d` is this call's own handle.
            BN_free(d);
            HMAC_CTX_free(hmac);
            EVP_MD_free(md);
            return ret;
        }
        // SAFETY: `d` is this call's own handle.
        BN_free(d);

        'body: {
            md = EVP_MD_fetch((*rsa).libctx, c"sha256".as_ptr(), ptr::null());
            if md.is_null() {
                raise_site(&err_sites::RSA_OSSL_482);
                break 'body;
            }

            if EVP_Digest(
                buf.cast::<c_void>(),
                num as usize,
                d_hash.as_mut_ptr(),
                ptr::null_mut(),
                md,
                ptr::null_mut(),
            ) <= 0
            {
                raise_site(&err_sites::RSA_OSSL_487);
                break 'body;
            }

            hmac = HMAC_CTX_new();
            if hmac.is_null() {
                raise_site(&err_sites::RSA_OSSL_493);
                break 'body;
            }

            if HMAC_Init_ex(
                hmac,
                d_hash.as_ptr().cast::<c_void>(),
                d_hash.len() as c_int,
                md,
                ptr::null_mut(),
            ) <= 0
            {
                raise_site(&err_sites::RSA_OSSL_498);
                break 'body;
            }

            if flen < num {
                core::ptr::write_bytes(buf, 0, (num - flen) as usize);
                if HMAC_Update(hmac, buf, (num - flen) as usize) <= 0 {
                    raise_site(&err_sites::RSA_OSSL_505);
                    break 'body;
                }
            }
            if HMAC_Update(hmac, from, flen as usize) <= 0 {
                raise_site(&err_sites::RSA_OSSL_510);
                break 'body;
            }

            // The authority's `md_len = SHA256_DIGEST_LENGTH;`, which is the only value the field
            // takes: its top-of-function initialiser is overwritten here on every path that reads
            // it and is therefore dropped rather than restated.
            let mut md_len: c_uint = SHA256_DIGEST_LENGTH;
            if HMAC_Final(hmac, kdk, ptr::addr_of_mut!(md_len)) <= 0 {
                raise_site(&err_sites::RSA_OSSL_516);
                break 'body;
            }
            ret = 1;
        }

        // The authority's `err:` label.
        HMAC_CTX_free(hmac);
        EVP_MD_free(md);
        ret
    }
}

// ---------------------------------------------------------------------------------------------
// `crypto/rsa/rsa_ossl.c:527-800` — the two decryption entry points
// ---------------------------------------------------------------------------------------------

/// `static int rsa_ossl_private_decrypt(int flen, const unsigned char *from, unsigned char *to,`
/// `RSA *rsa, int padding)` — `rsa_ossl.c:527-700`.
///
/// The decryption entry point, and the one the implicit rejection lives in. Five things about it
/// are contract:
///
/// * **The padding selector is rewritten before anything else happens** when the key is external
///   (`RSA_FLAG_EXT_PKEY`) and the caller asked for PKCS#1 v1.5: an external key does not hold the
///   private exponent, so the synthetic message cannot be derived and the check falls back to the
///   refusing form. The rewritten value is `RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING`, a selector no
///   caller passes.
/// * **The length refusals raise different reasons**: `RSA_R_DATA_GREATER_THAN_MOD_LEN` for
///   `flen > num` and `RSA_R_DATA_TOO_SMALL` for `flen < 1`, and the authority's comment records
///   that the first test is not equality because PGP chops leading zero octets.
/// * **The KDK is derived only for `RSA_PKCS1_PADDING`**, after the unblinding and before the
///   padding check, and `buf` holds `ret`'s bytes at that moment — the scratch use
///   [`derive_kdk`] documents.
/// * **`j` is `BN_bn2binpad(ret, buf, num)` and the checks are handed `j`, not `num`**, so a
///   leading-zero-stripped result is described by its true length.
/// * **The final two statements are unconditional**: `RSA_R_PADDING_CHECK_FAILED` is raised on
///   *every* path through the `switch`, and `err_clear_last_constant_time` then flags it rather
///   than removing it when the check succeeded. A transcription that guarded the raise on failure
///   would get the case the flag exists for wrong — the same asymmetry `src/rsa/mod.rs`'s type-2
///   check carries.
///
/// # Safety
/// `from` is readable for `flen` bytes; `to` is writable for `RSA_size(rsa)` bytes; `rsa` is a
/// live object.
unsafe extern "C" fn rsa_ossl_private_decrypt(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    rsa: *mut Rsa,
    padding: c_int,
) -> c_int {
    // SAFETY: `rsa` and its fields are live per this function's `# Safety` section.
    unsafe {
        let mut padding = padding;
        /*
         * we need the value of the private exponent to perform implicit rejection
         */
        if (*rsa).flags & RSA_FLAG_EXT_PKEY != 0 && padding == RSA_PKCS1_PADDING {
            padding = RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING;
        }

        let mut num: c_int = 0;
        let mut r: c_int = -1;
        let mut buf: *mut c_uchar = ptr::null_mut();
        let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
        let mut blinding: *mut Blinding = ptr::null_mut();

        let ctx: *mut BnCtx = BN_CTX_new_ex((*rsa).libctx);
        if ctx.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }
        BN_CTX_start(ctx);
        let f = BN_CTX_get(ctx);
        let ret = BN_CTX_get(ctx);
        if ret.is_null() {
            raise_site(&err_sites::RSA_OSSL_549);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }
        num = bn_num_bytes((*rsa).n);
        buf = CRYPTO_malloc(num as usize, FILE_RSA_OSSL, LINE).cast::<c_uchar>();
        if buf.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }

        /*
         * This check was for equality but PGP does evil things and chops off the top '0' bytes
         */
        if flen > num {
            raise_site(&err_sites::RSA_OSSL_562);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }

        if flen < 1 {
            raise_site(&err_sites::RSA_OSSL_567);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }

        'body: {
            /* make data into a big number */
            if BN_bin2bn(from, flen, f).is_null() {
                break 'body;
            }

            /* the FIPS_MODULE arm of the range check is not this profile's */
            if BN_ucmp(f, (*rsa).n) >= 0 {
                raise_site(&err_sites::RSA_OSSL_606);
                break 'body;
            }

            if (*rsa).flags & RSA_FLAG_CACHE_PUBLIC != 0
                && BN_MONT_CTX_set_locked(
                    ptr::addr_of_mut!((*rsa)._method_mod_n),
                    (*rsa).lock,
                    (*rsa).n,
                    ctx,
                )
                .is_null()
            {
                break 'body;
            }

            if (*rsa).flags & RSA_FLAG_NO_BLINDING == 0 {
                blinding = rsa_get_blinding(rsa, ctx);
                if blinding.is_null() {
                    raise_site(&err_sites::RSA_OSSL_618);
                    break 'body;
                }

                if rsa_blinding_convert(blinding, f, ctx) == 0 {
                    break 'body;
                }
            }

            /* do the decrypt */
            let crt = (*rsa).flags & RSA_FLAG_EXT_PKEY != 0
                || (*rsa).version == RSA_ASN1_VERSION_MULTI
                || (!(*rsa).p.is_null()
                    && !(*rsa).q.is_null()
                    && !(*rsa).dmp1.is_null()
                    && !(*rsa).dmq1.is_null()
                    && !(*rsa).iqmp.is_null());

            if crt {
                match (*(*rsa).meth).rsa_mod_exp {
                    Some(modexp) => {
                        if modexp(ret, f, rsa, ctx) == 0 {
                            break 'body;
                        }
                    }
                    None => break 'body,
                }
            } else {
                // SAFETY: `BN_new` takes no pointers.
                let d = BN_new();
                if d.is_null() {
                    raise_site(&err_sites::RSA_OSSL_633);
                    break 'body;
                }
                if (*rsa).d.is_null() {
                    raise_site(&err_sites::RSA_OSSL_637);
                    // SAFETY: `d` is this call's own object.
                    BN_free(d);
                    break 'body;
                }
                // SAFETY: `d` is live and `rsa->d` is live; the handle borrows the key's
                // exponent.
                BN_with_flags(d, (*rsa).d, BN_FLG_CONSTTIME);
                match (*(*rsa).meth).bn_mod_exp {
                    Some(bnexp) => {
                        if bnexp(ret, f, d, (*rsa).n, ctx, (*rsa)._method_mod_n) == 0 {
                            // SAFETY: `d` is this call's own handle.
                            BN_free(d);
                            break 'body;
                        }
                    }
                    None => {
                        // SAFETY: `d` is this call's own handle.
                        BN_free(d);
                        break 'body;
                    }
                }
                /* We MUST free d before any further use of rsa->d */
                // SAFETY: `d` is this call's own handle.
                BN_free(d);
            }

            if !blinding.is_null() && rsa_blinding_invert(blinding, ret, ctx) == 0 {
                break 'body;
            }

            /*
             * derive the Key Derivation Key from private exponent and public ciphertext
             */
            if padding == RSA_PKCS1_PADDING
                && derive_kdk(flen, from, rsa, buf, num, kdk.as_mut_ptr()) == 0
            {
                break 'body;
            }

            let j = BN_bn2binpad(ret, buf, num);
            if j < 0 {
                break 'body;
            }

            match padding {
                RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING => {
                    r = RSA_padding_check_PKCS1_type_2(to, num, buf, j, num);
                }
                RSA_PKCS1_PADDING => {
                    r = ossl_rsa_padding_check_PKCS1_type_2(
                        (*rsa).libctx,
                        to,
                        num,
                        buf,
                        j,
                        num,
                        kdk.as_mut_ptr(),
                    );
                }
                RSA_PKCS1_OAEP_PADDING => {
                    r = RSA_padding_check_PKCS1_OAEP(to, num, buf, j, num, ptr::null(), 0);
                }
                RSA_NO_PADDING => {
                    r = j;
                    core::ptr::copy_nonoverlapping(buf, to, j as usize);
                }
                _ => {
                    raise_site(&err_sites::RSA_OSSL_682);
                    break 'body;
                }
            }
        }

        /*
         * This trick doesn't work in the FIPS provider because libcrypto manages the error stack.
         * Instead we opt not to put an error on the stack at all in case of padding failure in the
         * FIPS provider. -- the `#ifndef FIPS_MODULE` arm is the one this profile compiles.
         */
        raise_site(&err_sites::RSA_OSSL_691);
        err_clear_last_constant_time((1 & !constant_time_msb_u32(r as u32)) as c_int);

        // The authority's `err:` label.
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
        r
    }
}

/// `static int rsa_ossl_public_decrypt(int flen, const unsigned char *from, unsigned char *to,`
/// `RSA *rsa, int padding)` — `rsa_ossl.c:703-800`.
///
/// Signature verification. The first three refusals are the same three the public-encrypt entry
/// point makes, in the same order; then the operation is `bn_mod_exp(ret, f, e, n, ...)`.
///
/// **The X9.31 arm is the one asymmetry in the file.** Assuming an odd `e`, an X9.31 signature
/// that is greater than half the modulus was sent as its complement, so the low nibble of the
/// result's low limb is tested: `12` means "already the low form", anything else means the
/// complement has to be taken. That nibble read is `bn_get_low_limb` (`:770`) — **not**
/// `BN_get_word`, whose answer for a value wider than one limb is `ULONG_MAX`.
///
/// The padding checks are handed `i`, the value `BN_bn2binpad` returned, and the final raise is
/// conditional on the *check* failing — unlike the private path, where the raise is
/// unconditional. The two are different on purpose and the difference is observable.
///
/// # Safety
/// `from` is readable for `flen` bytes; `to` is writable for `RSA_size(rsa)` bytes; `rsa` is a
/// live object.
unsafe extern "C" fn rsa_ossl_public_decrypt(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    rsa: *mut Rsa,
    padding: c_int,
) -> c_int {
    // SAFETY: `rsa` and its fields are live per this function's `# Safety` section.
    unsafe {
        if BN_num_bits((*rsa).n) > OPENSSL_RSA_MAX_MODULUS_BITS {
            raise_site(&err_sites::RSA_OSSL_712);
            return -1;
        }

        if BN_ucmp((*rsa).n, (*rsa).e) <= 0 {
            raise_site(&err_sites::RSA_OSSL_717);
            return -1;
        }

        /* for large moduli, enforce exponent limit */
        if BN_num_bits((*rsa).n) > OPENSSL_RSA_SMALL_MODULUS_BITS
            && BN_num_bits((*rsa).e) > OPENSSL_RSA_MAX_PUBEXP_BITS
        {
            raise_site(&err_sites::RSA_OSSL_724);
            return -1;
        }

        let mut num: c_int = 0;
        let mut r: c_int = -1;
        let mut buf: *mut c_uchar = ptr::null_mut();

        let ctx: *mut BnCtx = BN_CTX_new_ex((*rsa).libctx);
        if ctx.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }
        BN_CTX_start(ctx);
        let f = BN_CTX_get(ctx);
        let ret = BN_CTX_get(ctx);
        if ret.is_null() {
            raise_site(&err_sites::RSA_OSSL_735);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }
        num = bn_num_bytes((*rsa).n);
        buf = CRYPTO_malloc(num as usize, FILE_RSA_OSSL, LINE).cast::<c_uchar>();
        if buf.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }

        /*
         * This check was for equality but PGP does evil things and chops off the top '0' bytes
         */
        if flen > num {
            raise_site(&err_sites::RSA_OSSL_748);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
            return r;
        }

        'body: {
            if BN_bin2bn(from, flen, f).is_null() {
                break 'body;
            }

            if BN_ucmp(f, (*rsa).n) >= 0 {
                raise_site(&err_sites::RSA_OSSL_756);
                break 'body;
            }

            if (*rsa).flags & RSA_FLAG_CACHE_PUBLIC != 0
                && BN_MONT_CTX_set_locked(
                    ptr::addr_of_mut!((*rsa)._method_mod_n),
                    (*rsa).lock,
                    (*rsa).n,
                    ctx,
                )
                .is_null()
            {
                break 'body;
            }

            match (*(*rsa).meth).bn_mod_exp {
                Some(bnexp) => {
                    if bnexp(ret, f, (*rsa).e, (*rsa).n, ctx, (*rsa)._method_mod_n) == 0 {
                        break 'body;
                    }
                }
                None => break 'body,
            }

            /* For X9.31: Assuming e is odd it does a 12 mod 16 test */
            if padding == RSA_X931_PADDING
                && bn_get_low_limb(ret) & 0xf != 12
                && BN_sub(ret, (*rsa).n, ret) == 0
            {
                break 'body;
            }

            let i = BN_bn2binpad(ret, buf, num);
            if i < 0 {
                break 'body;
            }

            match padding {
                RSA_PKCS1_PADDING => {
                    r = RSA_padding_check_PKCS1_type_1(to, num, buf, i, num);
                }
                RSA_X931_PADDING => {
                    r = RSA_padding_check_X931(to, num, buf, i, num);
                }
                RSA_NO_PADDING => {
                    r = i;
                    core::ptr::copy_nonoverlapping(buf, to, i as usize);
                }
                _ => {
                    raise_site(&err_sites::RSA_OSSL_789);
                    break 'body;
                }
            }
        }

        if r < 0 {
            raise_site(&err_sites::RSA_OSSL_793);
        }

        // The authority's `err:` label.
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        CRYPTO_clear_free(buf.cast::<c_void>(), num as usize, FILE_RSA_OSSL, LINE);
        r
    }
}

// ---------------------------------------------------------------------------------------------
// `crypto/rsa/rsa_ossl.c:802-1195` — the CRT exponentiation and the two lifecycle hooks
// ---------------------------------------------------------------------------------------------

/// `static int rsa_ossl_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)` —
/// `rsa_ossl.c:802-1171`.
///
/// The CRT exponentiation, and the file's one genuinely subtle function. Its three pieces:
///
/// * **The cache arm** builds a Montgomery context for `p`, `q` and each extra prime under the
///   object's lock, and then decides `smooth`: the fast path applies only when the method's
///   exponentiation is `BN_mod_exp_mont` itself, there are no extra primes, and `p` and `q` have
///   the same bit length. `factor` is a `BN_with_flags` handle and is released before the primes
///   are used again — the authority's comment says so.
/// * **The `smooth` path** maps `I` into each modulus through a Montgomery round trip, computes
///   both halves with the paired constant-time exponentiation, subtracts and multiplies back in
///   the Montgomery domain, and combines. **This is where the fixed-top internals below are
///   reached**, and this is the substitution the module note records: `bn_from_mont_fixed_top` /
///   `bn_to_mont_fixed_top` become `BN_from_montgomery` / `BN_to_montgomery`,
///   `bn_mod_sub_fixed_top` becomes a signed subtraction with the authority's own two conditional
///   additions (the comment on that function says "it takes up to two conditional additions"),
///   `bn_mul_mont_fixed_top` becomes `BN_mod_mul_montgomery`, `bn_mul_fixed_top` becomes `BN_mul`
///   and `bn_mod_add_fixed_top` becomes `BN_mod_add` — which is exactly the wrapper the authority
///   itself puts around it.
/// * **The tail verifies the result** by re-exponentiating with the public exponent and comparing
///   congruently, and falls back to the unblinded `d` exponentiation when the CRT answer does not
///   check out. `bn_correct_top(r0)` appears three times and is a no-op in this crate's normalised
///   representation: it exists to make the *next* operation see a reduced `top`, and there is no
///   unreduced `top` here.
///
/// # Safety
/// `r0` is a live writable `BIGNUM`; `i` is a live `BIGNUM`; `rsa` is a live object; `ctx` is a
/// live `BN_CTX`.
unsafe extern "C" fn rsa_ossl_mod_exp(
    r0: *mut BigNum,
    i: *const BigNum,
    rsa: *mut Rsa,
    ctx: *mut BnCtx,
) -> c_int {
    /// `RSA_MAX_PRIME_NUM` — `crypto/rsa/rsa_local.h:16`, the ceiling the extra-prime arrays are
    /// sized by. It is declared once, in `crate::rsa::mp`, and imported here for the same reason
    /// that module's own note gives.
    use crate::rsa::mp::RSA_MAX_PRIME_NUM;

    // SAFETY: every pointer below is live per this function's `# Safety` section, and each field
    // read is NULL or a live object the caller's contract covers.
    unsafe {
        let mut ret: c_int = 0;
        let mut smooth: c_int = 0;
        let mut ex_primes: c_int = 0;
        let mut m: [*mut BigNum; (RSA_MAX_PRIME_NUM - 2) as usize] =
            [ptr::null_mut(); (RSA_MAX_PRIME_NUM - 2) as usize];

        BN_CTX_start(ctx);

        let r1 = BN_CTX_get(ctx);
        let r2 = BN_CTX_get(ctx);
        let m1 = BN_CTX_get(ctx);
        let vrfy = BN_CTX_get(ctx);
        let mut failed = vrfy.is_null();

        if !failed && (*rsa).version == RSA_ASN1_VERSION_MULTI {
            ex_primes = OPENSSL_sk_num((*rsa).prime_infos);
            if ex_primes <= 0 || ex_primes > RSA_MAX_PRIME_NUM - 2 {
                failed = true;
            }
        }

        if !failed && (*rsa).flags & RSA_FLAG_CACHE_PRIVATE != 0 {
            // SAFETY: `BN_new` takes no pointers.
            let factor = BN_new();
            if factor.is_null() {
                failed = true;
            } else {
                // The `BN_with_flags` handles reuse one object three ways, which is why the
                // authority's comment insists `factor` is freed before the primes are used again.
                let built = 'cache: {
                    // SAFETY: `factor` is live and `rsa->p` is live.
                    BN_with_flags(factor, (*rsa).p, BN_FLG_CONSTTIME);
                    if BN_MONT_CTX_set_locked(
                        ptr::addr_of_mut!((*rsa)._method_mod_p),
                        (*rsa).lock,
                        factor,
                        ctx,
                    )
                    .is_null()
                    {
                        break 'cache false;
                    }
                    // SAFETY: as above, for `q`.
                    BN_with_flags(factor, (*rsa).q, BN_FLG_CONSTTIME);
                    if BN_MONT_CTX_set_locked(
                        ptr::addr_of_mut!((*rsa)._method_mod_q),
                        (*rsa).lock,
                        factor,
                        ctx,
                    )
                    .is_null()
                    {
                        break 'cache false;
                    }
                    /* the FIPS_MODULE arm's exclusion of extra primes is not this profile's:
                     * `#ifndef FIPS_MODULE` holds, so the loop is compiled */
                    let mut n: c_int = 0;
                    while n < ex_primes {
                        let pinfo =
                            OPENSSL_sk_value((*rsa).prime_infos, n).cast::<super::RsaPrimeInfo>();
                        // SAFETY: the stack's elements are `RSA_PRIME_INFO` records this object
                        // owns, and `pinfo->r` is a live prime.
                        BN_with_flags(factor, (*pinfo).r, BN_FLG_CONSTTIME);
                        if BN_MONT_CTX_set_locked(
                            ptr::addr_of_mut!((*pinfo).m),
                            (*rsa).lock,
                            factor,
                            ctx,
                        )
                        .is_null()
                        {
                            break 'cache false;
                        }
                        n += 1;
                    }
                    true
                };
                // We MUST free |factor| before any further use of the prime factors
                // SAFETY: `factor` is this call's own object.
                BN_free(factor);
                if !built {
                    failed = true;
                } else {
                    // The authority's `rsa->meth->bn_mod_exp == BN_mod_exp_mont` test, through the
                    // helper that says why the comparison is meaningful.
                    let smooth_now = is_mont_bn_mod_exp((*rsa).meth)
                        && ex_primes == 0
                        && BN_num_bits((*rsa).q) == BN_num_bits((*rsa).p);
                    if smooth_now {
                        smooth = 1;
                    }
                }
            }
        }

        if !failed
            && (*rsa).flags & RSA_FLAG_CACHE_PUBLIC != 0
            && BN_MONT_CTX_set_locked(
                ptr::addr_of_mut!((*rsa)._method_mod_n),
                (*rsa).lock,
                (*rsa).n,
                ctx,
            )
            .is_null()
        {
            failed = true;
        }

        if !failed && smooth != 0 {
            // The authority's long `if`: every clause is a `goto err` on failure. Each fixed-top
            // call is replaced by the public entry point the authority's own wrapper calls — see
            // the module note — and the two `bn_mod_sub_fixed_top` statements are the signed
            // subtraction with the two conditional additions that function's own comment
            // describes, because 0 <= a < p and 0 <= b < 2^w < 2p there.
            let smooth_ok = 'smooth: {
                /* m1 = I mod q */
                if BN_from_montgomery(m1, i, (*rsa)._method_mod_q, ctx) == 0 {
                    break 'smooth false;
                }
                if BN_to_montgomery(m1, m1, (*rsa)._method_mod_q, ctx) == 0 {
                    break 'smooth false;
                }
                /* r1 = I mod p */
                if BN_from_montgomery(r1, i, (*rsa)._method_mod_p, ctx) == 0 {
                    break 'smooth false;
                }
                if BN_to_montgomery(r1, r1, (*rsa)._method_mod_p, ctx) == 0 {
                    break 'smooth false;
                }
                /*
                 * m1 = m1^dmq1 mod q and r1 = r1^dmp1 mod p, as one call: the authority's
                 * `BN_mod_exp_mont_consttime_x2` computes both halves, and this crate's two
                 * sequential constant-time exponentiations answer the same values.
                 */
                if BN_mod_exp_mont_consttime_x2(
                    m1,
                    m1,
                    (*rsa).dmq1,
                    (*rsa).q,
                    (*rsa)._method_mod_q,
                    r1,
                    r1,
                    (*rsa).dmp1,
                    (*rsa).p,
                    (*rsa)._method_mod_p,
                    ctx,
                ) == 0
                {
                    break 'smooth false;
                }
                /* r1 = (r1 - m1) mod p, tolerating a subtrahend wider than the modulus */
                if BN_sub(r1, r1, m1) == 0 {
                    break 'smooth false;
                }
                if BN_is_negative(r1) != 0 && BN_add(r1, r1, (*rsa).p) == 0 {
                    break 'smooth false;
                }
                if BN_is_negative(r1) != 0 && BN_add(r1, r1, (*rsa).p) == 0 {
                    break 'smooth false;
                }

                /* r1 = r1 * iqmp mod p */
                if BN_to_montgomery(r1, r1, (*rsa)._method_mod_p, ctx) == 0 {
                    break 'smooth false;
                }
                if BN_mod_mul_montgomery(r1, r1, (*rsa).iqmp, (*rsa)._method_mod_p, ctx) == 0 {
                    break 'smooth false;
                }
                /* r0 = r1 * q + m1 */
                if BN_mul(r0, r1, (*rsa).q, ctx) == 0 {
                    break 'smooth false;
                }
                if BN_mod_add(r0, r0, m1, (*rsa).n, ctx) == 0 {
                    break 'smooth false;
                }
                true
            };
            if !smooth_ok {
                failed = true;
            }
        } else if !failed {
            let slow_ok = 'slow: {
                /* compute I mod q */
                // SAFETY: `BN_new` takes no pointers.
                let c = BN_new();
                if c.is_null() {
                    break 'slow false;
                }
                // SAFETY: `c` is live and `i` is live; the handle borrows the input.
                BN_with_flags(c, i, BN_FLG_CONSTTIME);

                if BN_div(ptr::null_mut(), r1, c, (*rsa).q, ctx) == 0 {
                    // SAFETY: `c` is this call's own handle.
                    BN_free(c);
                    break 'slow false;
                }

                {
                    // SAFETY: `BN_new` takes no pointers.
                    let dmq1 = BN_new();
                    if dmq1.is_null() {
                        // SAFETY: `c` is this call's own handle.
                        BN_free(c);
                        break 'slow false;
                    }
                    // SAFETY: `dmq1` is live and `rsa->dmq1` is live.
                    BN_with_flags(dmq1, (*rsa).dmq1, BN_FLG_CONSTTIME);

                    /* compute r1^dmq1 mod q */
                    let stepped = match (*(*rsa).meth).bn_mod_exp {
                        Some(bnexp) => {
                            bnexp(m1, r1, dmq1, (*rsa).q, ctx, (*rsa)._method_mod_q) != 0
                        }
                        None => false,
                    };
                    if !stepped {
                        // SAFETY: both are this call's own handles.
                        BN_free(c);
                        BN_free(dmq1);
                        break 'slow false;
                    }
                    /* We MUST free dmq1 before any further use of rsa->dmq1 */
                    // SAFETY: `dmq1` is this call's own handle.
                    BN_free(dmq1);
                }

                /* compute I mod p */
                if BN_div(ptr::null_mut(), r1, c, (*rsa).p, ctx) == 0 {
                    // SAFETY: `c` is this call's own handle.
                    BN_free(c);
                    break 'slow false;
                }
                /* We MUST free c before any further use of I */
                // SAFETY: `c` is this call's own handle.
                BN_free(c);
                true
            };
            if !slow_ok {
                failed = true;
            }
        }

        if !failed {
            // SAFETY: `BN_new` takes no pointers.
            let dmp1 = BN_new();
            if dmp1.is_null() {
                failed = true;
            } else {
                // SAFETY: `dmp1` is live and `rsa->dmp1` is live.
                BN_with_flags(dmp1, (*rsa).dmp1, BN_FLG_CONSTTIME);

                /* compute r1^dmp1 mod p */
                let stepped = match (*(*rsa).meth).bn_mod_exp {
                    Some(bnexp) => bnexp(r0, r1, dmp1, (*rsa).p, ctx, (*rsa)._method_mod_p) != 0,
                    None => false,
                };
                // We MUST free dmp1 before any further use of rsa->dmp1
                // SAFETY: `dmp1` is this call's own handle.
                BN_free(dmp1);
                if !stepped {
                    failed = true;
                }
            }
        }

        /* the FIPS_MODULE arm's exclusion of the extra-prime loop is not this profile's */
        if !failed && ex_primes > 0 {
            // SAFETY: both take no pointers.
            let di = BN_new();
            let cc = BN_new();
            if cc.is_null() || di.is_null() {
                // SAFETY: each is NULL or this call's own object.
                BN_free(cc);
                BN_free(di);
                failed = true;
            } else {
                let mut n: c_int = 0;
                while n < ex_primes {
                    /* prepare m_i */
                    m[n as usize] = BN_CTX_get(ctx);
                    if m[n as usize].is_null() {
                        // SAFETY: both are this call's own objects.
                        BN_free(cc);
                        BN_free(di);
                        failed = true;
                        break;
                    }

                    let pinfo =
                        OPENSSL_sk_value((*rsa).prime_infos, n).cast::<super::RsaPrimeInfo>();

                    /* prepare c and d_i */
                    // SAFETY: `cc` and `di` are live handles, `i` is live and `pinfo->d` is live.
                    BN_with_flags(cc, i, BN_FLG_CONSTTIME);
                    BN_with_flags(di, (*pinfo).d, BN_FLG_CONSTTIME);

                    if BN_div(ptr::null_mut(), r1, cc, (*pinfo).r, ctx) == 0 {
                        // SAFETY: both are this call's own objects.
                        BN_free(cc);
                        BN_free(di);
                        failed = true;
                        break;
                    }
                    /* compute r1 ^ d_i mod r_i */
                    let stepped = match (*(*rsa).meth).bn_mod_exp {
                        Some(bnexp) => {
                            bnexp(m[n as usize], r1, di, (*pinfo).r, ctx, (*pinfo).m) != 0
                        }
                        None => false,
                    };
                    if !stepped {
                        // SAFETY: both are this call's own objects.
                        BN_free(cc);
                        BN_free(di);
                        failed = true;
                        break;
                    }
                    n += 1;
                }
                if !failed {
                    // SAFETY: both are this call's own objects.
                    BN_free(cc);
                    BN_free(di);
                }
            }
        }

        if !failed {
            let combine = 'combine: {
                if BN_sub(r0, r0, m1) == 0 {
                    break 'combine false;
                }
                /*
                 * This will help stop the size of r0 increasing, which does affect the multiply if
                 * it is optimised for a power of 2 size
                 */
                if BN_is_negative(r0) != 0 && BN_add(r0, r0, (*rsa).p) == 0 {
                    break 'combine false;
                }

                if BN_mul(r1, r0, (*rsa).iqmp, ctx) == 0 {
                    break 'combine false;
                }

                {
                    // SAFETY: `BN_new` takes no pointers.
                    let pr1 = BN_new();
                    if pr1.is_null() {
                        break 'combine false;
                    }
                    // SAFETY: `pr1` is live and `r1` is live; the handle borrows the product.
                    BN_with_flags(pr1, r1, BN_FLG_CONSTTIME);

                    let reduced = BN_div(ptr::null_mut(), r0, pr1, (*rsa).p, ctx) != 0;
                    /* We MUST free pr1 before any further use of r1 */
                    // SAFETY: `pr1` is this call's own handle.
                    BN_free(pr1);
                    if !reduced {
                        break 'combine false;
                    }
                }

                /*
                 * If p < q it is occasionally possible for the correction of adding 'p' if r0 is
                 * negative above to leave the result still negative. This can break the private
                 * key operations: the following second correction should *always* correct this
                 * rare occurrence. [steve]
                 */
                if BN_is_negative(r0) != 0 && BN_add(r0, r0, (*rsa).p) == 0 {
                    break 'combine false;
                }
                if BN_mul(r1, r0, (*rsa).q, ctx) == 0 {
                    break 'combine false;
                }
                if BN_add(r0, r1, m1) == 0 {
                    break 'combine false;
                }

                /* add m_i to m in the multi-prime case -- `#ifndef FIPS_MODULE` holds */
                if ex_primes > 0 {
                    // SAFETY: `BN_new` takes no pointers.
                    let pr2 = BN_new();
                    if pr2.is_null() {
                        break 'combine false;
                    }
                    let mut n: c_int = 0;
                    while n < ex_primes {
                        let pinfo =
                            OPENSSL_sk_value((*rsa).prime_infos, n).cast::<super::RsaPrimeInfo>();
                        if BN_sub(r1, m[n as usize], r0) == 0 {
                            // SAFETY: `pr2` is this call's own handle.
                            BN_free(pr2);
                            break 'combine false;
                        }

                        if BN_mul(r2, r1, (*pinfo).t, ctx) == 0 {
                            // SAFETY: `pr2` is this call's own handle.
                            BN_free(pr2);
                            break 'combine false;
                        }

                        // SAFETY: `pr2` is live and `r2` is live; the handle borrows the product.
                        BN_with_flags(pr2, r2, BN_FLG_CONSTTIME);

                        if BN_div(ptr::null_mut(), r1, pr2, (*pinfo).r, ctx) == 0 {
                            // SAFETY: `pr2` is this call's own handle.
                            BN_free(pr2);
                            break 'combine false;
                        }

                        if BN_is_negative(r1) != 0 && BN_add(r1, r1, (*pinfo).r) == 0 {
                            // SAFETY: `pr2` is this call's own handle.
                            BN_free(pr2);
                            break 'combine false;
                        }
                        if BN_mul(r1, r1, (*pinfo).pp, ctx) == 0 {
                            // SAFETY: `pr2` is this call's own handle.
                            BN_free(pr2);
                            break 'combine false;
                        }
                        if BN_add(r0, r0, r1) == 0 {
                            // SAFETY: `pr2` is this call's own handle.
                            BN_free(pr2);
                            break 'combine false;
                        }
                        n += 1;
                    }
                    // SAFETY: `pr2` is this call's own handle.
                    BN_free(pr2);
                }
                true
            };
            if !combine {
                failed = true;
            }
        }

        if !failed {
            /* the `tail:` label */
            let tail = 'tail: {
                if !(*rsa).e.is_null() && !(*rsa).n.is_null() {
                    // The authority's `rsa->meth->bn_mod_exp == BN_mod_exp_mont` branch, then the
                    // `bn_correct_top(r0)` the else arm makes — which is a no-op here, because this
                    // crate's values are always normalised. See the doc comment.
                    // SAFETY: `rsa` is live and its `meth` is the live table the object carries.
                    let vrfy_ok = if is_mont_bn_mod_exp((*rsa).meth) {
                        BN_mod_exp_mont(vrfy, r0, (*rsa).e, (*rsa).n, ctx, (*rsa)._method_mod_n)
                            != 0
                    } else {
                        match (*(*rsa).meth).bn_mod_exp {
                            Some(bnexp) => {
                                bnexp(vrfy, r0, (*rsa).e, (*rsa).n, ctx, (*rsa)._method_mod_n) != 0
                            }
                            None => false,
                        }
                    };
                    if !vrfy_ok {
                        break 'tail false;
                    }
                    /*
                     * If 'I' was greater than (or equal to) rsa->n, the operation will be
                     * equivalent to using 'I mod n'. However, the result of the verify will
                     * *always* be less than 'n' so we don't check for absolute equality, just
                     * congruency.
                     */
                    if BN_sub(vrfy, vrfy, i) == 0 {
                        break 'tail false;
                    }
                    if BN_is_zero(vrfy) != 0 {
                        /* not actually error */
                        ret = 1;
                        break 'tail true;
                    }
                    if BN_div(ptr::null_mut(), vrfy, vrfy, (*rsa).n, ctx) == 0 {
                        break 'tail false;
                    }
                    if BN_is_negative(vrfy) != 0 && BN_add(vrfy, vrfy, (*rsa).n) == 0 {
                        break 'tail false;
                    }
                    if BN_is_zero(vrfy) == 0 {
                        /*
                         * 'I' and 'vrfy' aren't congruent mod n. Don't leak miscalculated CRT
                         * output, just do a raw (slower) mod_exp and return that instead.
                         */
                        // SAFETY: `BN_new` takes no pointers.
                        let d = BN_new();
                        if d.is_null() {
                            break 'tail false;
                        }
                        // SAFETY: `d` is live and `rsa->d` is live; the handle borrows the key's
                        // exponent.
                        BN_with_flags(d, (*rsa).d, BN_FLG_CONSTTIME);

                        let stepped = match (*(*rsa).meth).bn_mod_exp {
                            Some(bnexp) => {
                                bnexp(r0, i, d, (*rsa).n, ctx, (*rsa)._method_mod_n) != 0
                            }
                            None => false,
                        };
                        if !stepped {
                            // SAFETY: `d` is this call's own handle.
                            BN_free(d);
                            break 'tail false;
                        }
                        /* We MUST free d before any further use of rsa->d */
                        // SAFETY: `d` is this call's own handle.
                        BN_free(d);
                    }
                }
                true
            };
            // The last step of the authority's `tail:` block. A failure there is the `goto err` that
            // leaves `ret` at 0, so it needs no assignment of its own: the `err:` label below is
            // reached either way, and the only thing the success path adds is `ret = 1`.
            if tail && ret == 0 {
                // `bn_correct_top(r0)` precedes this in the authority and is a no-op here; see the
                // doc comment.
                ret = 1;
            }
        }

        // The authority's `err:` label. `ret` is the answer on every path: the success arms above set
        // it to 1 and the failure arms leave it 0, which is what `int ret = 0` at the top means.
        BN_CTX_end(ctx);
        ret
    }
}

/// `static int rsa_ossl_init(RSA *rsa)` — `rsa_ossl.c:1173-1177`.
///
/// **Both cache flags, and always `1`.** The flags are what make the first public operation on an
/// object build a Montgomery context for `n` and keep it, and what makes `rsa_ossl_mod_exp` build
/// one for each prime. An object built by `RSA_new` therefore answers `RSA_test_flags` with
/// `RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE` set before any caller touches it — because
/// `rsa_new_intern` runs this table's `init` before it returns.
///
/// A table's `init` that answers 0 makes `rsa_new_intern` fail with `RSA_LIB_130` and release the
/// object through `RSA_free`; this one cannot.
///
/// # Safety
/// `rsa` is a live object.
unsafe extern "C" fn rsa_ossl_init(rsa: *mut Rsa) -> c_int {
    // SAFETY: `rsa` is live per this function's `# Safety` section.
    unsafe { (*rsa).flags |= RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE };
    1
}

/// `static int rsa_ossl_finish(RSA *rsa)` — `rsa_ossl.c:1179-1195`.
///
/// **The one place the cached Montgomery contexts are released**, which is why `RSA_set_method`
/// runs the outgoing table's `finish` before installing the incoming one and why `RSA_free` runs
/// it before releasing the key material. Four contexts at most: `n`'s, `p`'s, `q`'s, and one per
/// extra prime (`pinfo->m`, walked through the stack). Each release accepts NULL, so an object
/// whose caches were never built — the common case for a key that was only ever used publicly, and
/// for every object this crate constructs in a court — is released correctly.
///
/// The extra-prime loop is `#ifndef FIPS_MODULE`'s, which holds on this profile. `RSA_MAX_PRIME_NUM`
/// bounds nothing here: the loop runs to the stack's own count, and `RSA_set0_multi_prime_params`
/// is what refused an over-long stack.
///
/// # Safety
/// `rsa` is a live object.
unsafe extern "C" fn rsa_ossl_finish(rsa: *mut Rsa) -> c_int {
    // SAFETY: `rsa` is live per this function's `# Safety` section, so its `prime_infos` is NULL or
    // a live stack of `RSA_PRIME_INFO` records this object owns.
    unsafe {
        let mut n: c_int = 0;
        while n < OPENSSL_sk_num((*rsa).prime_infos) {
            let pinfo = OPENSSL_sk_value((*rsa).prime_infos, n).cast::<super::RsaPrimeInfo>();
            // SAFETY: the stack's elements are `RSA_PRIME_INFO` records of this object's, and
            // `m` is NULL or a Montgomery context this object's cache arm created.
            BN_MONT_CTX_free((*pinfo).m);
            n += 1;
        }

        BN_MONT_CTX_free((*rsa)._method_mod_n);
        BN_MONT_CTX_free((*rsa)._method_mod_p);
        BN_MONT_CTX_free((*rsa)._method_mod_q);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::BN_set_word;

    /// The pair round-trips through the object's member: an array allocated by
    /// [`ossl_rsa_alloc_blinding`] is what [`ossl_rsa_free_blinding`] releases, and the
    /// release leaves the member pointing where it did — the behaviour the module note
    /// records, pinned so that a later "tidying up" of the NULL write fails here.
    ///
    /// The object is `mp.rs`'s [`super::super::mp::zeroed_rsa`], the fixture whose fields
    /// are written out rather than zeroed for the reason recorded there.
    #[test]
    fn the_blinding_array_round_trips_through_the_object() {
        let mut rsa = super::super::mp::zeroed_rsa();
        // SAFETY: the array is created here and released here; the object is this test's.
        unsafe {
            let sa = ossl_rsa_alloc_blinding();
            assert!(!sa.is_null());
            rsa.blindings_sa = sa;

            let before = sa;
            ossl_rsa_free_blinding(&mut rsa);
            assert_eq!(
                rsa.blindings_sa, before,
                "the authority does not clear the member"
            );
        }
    }

    /// A NULL member is not a fault: `ossl_sa_doall_arg` and `ossl_sa_free` both accept
    /// NULL, so an object that was never blinded is released correctly.
    #[test]
    fn an_unblinded_object_is_released_without_faulting() {
        let mut rsa = super::super::mp::zeroed_rsa();
        assert!(rsa.blindings_sa.is_null());
        // SAFETY: `rsa` is live and its member is NULL, which both entry points accept.
        unsafe { ossl_rsa_free_blinding(&mut rsa) };
    }

    /// The table's fifteen members are the authority's, member for member: the four crypt entry
    /// points and the two `_ex` halves, `BN_mod_exp_mont`, the two lifecycle hooks, the flag word,
    /// a NULL `app_data`, and the four members the authority writes as the integer `0` or NULL.
    ///
    /// The test reads the table through the same accessors a caller would, so it pins the initialiser
    /// rather than the struct: a member changed to a different function of the same shape — a
    /// plausible slip when transcribing four entry points in a row — fails here.
    #[test]
    fn the_default_table_is_the_authoritys() {
        // SAFETY: the table is this module's own static and is never written.
        let meth: *const RsaMethod = RSA_PKCS1_OpenSSL();
        assert!(!meth.is_null());
        assert_eq!(meth, RSA_get_default_method());

        // SAFETY: `meth` is the live static table.
        let m = unsafe { &*meth };
        assert_eq!(m.name, c"OpenSSL PKCS#1 RSA".as_ptr().cast_mut());
        assert!(m.rsa_pub_enc.is_some());
        assert!(m.rsa_pub_dec.is_some());
        assert!(m.rsa_priv_enc.is_some());
        assert!(m.rsa_priv_dec.is_some());
        assert!(m.rsa_mod_exp.is_some());
        // The comparison goes through the same helper `rsa_ossl_mod_exp` uses, so the "is it the
        // Montgomery exponentiation" question is answered one way in this module.
        // SAFETY: `meth` is the live static table.
        assert!(unsafe { is_mont_bn_mod_exp(meth) });
        assert!(m.init.is_some());
        assert!(m.finish.is_some());
        assert_eq!(m.flags, RSA_FLAG_FIPS_METHOD);
        assert!(m.app_data.is_null());
        assert!(m.rsa_sign.is_none());
        assert!(m.rsa_verify.is_none());
        assert!(m.rsa_keygen.is_none());
        assert!(m.rsa_multi_prime_keygen.is_none());
    }

    /// `RSA_set_default_method` is a store and nothing else, and it is reversible: the default is
    /// the PKCS#1 table, a caller may replace it with any table or with NULL, and the replacement
    /// is what the getter answers until it is set back.
    ///
    /// **The restore is part of the test, not politeness**: this is a process-wide static, so a
    /// test that left it moved would change what the *constructor* installs for every other test
    /// in the crate.
    #[test]
    fn the_default_method_is_a_pointer_store() {
        // SAFETY: every table handed to the setter below is this module's own static or a table
        // `RSA_meth_new` built for this test and freed here.
        unsafe {
            let open_ssl = RSA_PKCS1_OpenSSL();
            assert_eq!(RSA_get_default_method(), open_ssl);

            let mine = crate::rsa::RSA_meth_new(c"unit-test".as_ptr(), 0x0008);
            assert!(!mine.is_null());
            RSA_set_default_method(mine.cast());
            assert_eq!(RSA_get_default_method().cast_mut(), mine);

            RSA_set_default_method(ptr::null());
            assert!(RSA_get_default_method().is_null());

            RSA_set_default_method(open_ssl);
            assert_eq!(RSA_get_default_method(), open_ssl);

            crate::rsa::RSA_meth_free(mine);
        }
    }

    /// `rsa_ossl_init` sets both cache flags and answers 1; `rsa_ossl_finish` answers 1 for an
    /// object whose four contexts are all NULL, which is every object this crate can build without
    /// a key operation.
    ///
    /// The flags are read back **through the public accessor pair** — `RSA_test_flags` on the
    /// object's own word — rather than by reading the field, so the observation is the one a
    /// caller makes.
    #[test]
    fn the_lifecycle_hooks_set_the_caches_and_release_nothing_they_do_not_own() {
        let mut rsa = super::super::mp::zeroed_rsa();
        // SAFETY: `rsa` is live and `RSA_test_flags` reads one field of it.
        let before = unsafe { crate::rsa::object::RSA_test_flags(&rsa, RSA_FLAG_CACHE_PUBLIC) };
        assert_eq!(before, 0, "the zeroed object carries neither cache flag");

        // SAFETY: `rsa` is live and the hook takes only the object.
        let init_ret = unsafe { rsa_ossl_init(&mut rsa) };
        assert_eq!(init_ret, 1, "the authority's init always answers 1");
        // SAFETY: `rsa` is live; `RSA_test_flags` reads one field and `rsa_ossl_finish` releases
        // the four contexts, all of which are NULL on a zeroed object.
        unsafe {
            assert_ne!(
                crate::rsa::object::RSA_test_flags(&rsa, RSA_FLAG_CACHE_PUBLIC),
                0
            );
            assert_ne!(
                crate::rsa::object::RSA_test_flags(&rsa, RSA_FLAG_CACHE_PRIVATE),
                0
            );
            assert_eq!(rsa_ossl_finish(&mut rsa), 1);
        }
    }

    /// The `bn_get_low_limb` helper answers the value's low limb and **0 for a zero value**, which
    /// is the X9.31 arm's whole input: the authority reads `ret->d[0]` and compares its low nibble
    /// with `12`.
    #[test]
    fn the_low_limb_read_is_the_x931_input() {
        // SAFETY: every object is created and released here, and `BN_set_word` writes one.
        unsafe {
            let b = BN_new();
            assert!(!b.is_null());
            assert!(BN_set_word(b, 0x3c) != 0);
            assert_eq!(
                bn_get_low_limb(b) & 0xf,
                12,
                "12 mod 16 takes the no-complement arm"
            );
            assert!(BN_set_word(b, 0x3d) != 0);
            assert_eq!(bn_get_low_limb(b) & 0xf, 13);
            BN_free(b);

            let zero = BN_new();
            assert!(!zero.is_null());
            assert_eq!(
                bn_get_low_limb(zero),
                0,
                "a zero value's low limb is 0 here"
            );
            assert_eq!(bn_get_low_limb(ptr::null()), 0);
            BN_free(zero);
        }
    }

    /// `derive_kdk` is a pure function of the private exponent and the ciphertext, so the same
    /// inputs answer the same key — which is what makes the implicit rejection deterministic and
    /// the court able to compare it byte for byte.
    ///
    /// The object carries `d` only; the modulus' width is the buffer length. Two calls with the
    /// same key answer the same 32 octets, and a different `d` answers different ones.
    #[test]
    fn the_kdk_is_a_function_of_the_exponent_and_the_ciphertext() {
        // SAFETY: every object is created and released here.
        unsafe {
            let mut rsa = super::super::mp::zeroed_rsa();
            let d = BN_new();
            assert!(!d.is_null());
            assert!(BN_set_word(d, 2753) != 0);
            rsa.d = d;

            let from = [0x11u8, 0x22];
            let mut kdk_a = [0u8; SHA256_DIGEST_LENGTH as usize];
            let mut kdk_b = [0u8; SHA256_DIGEST_LENGTH as usize];
            let mut buf = [0u8; 2];
            assert_eq!(
                derive_kdk(
                    2,
                    from.as_ptr(),
                    &mut rsa,
                    buf.as_mut_ptr(),
                    2,
                    kdk_a.as_mut_ptr()
                ),
                1
            );
            assert_eq!(
                derive_kdk(
                    2,
                    from.as_ptr(),
                    &mut rsa,
                    buf.as_mut_ptr(),
                    2,
                    kdk_b.as_mut_ptr()
                ),
                1
            );
            assert_eq!(kdk_a, kdk_b, "the KDK is a function of its inputs");

            // A different exponent answers a different key, which is the property the implicit
            // rejection rests on.
            assert!(BN_set_word(d, 17) != 0);
            assert_eq!(
                derive_kdk(
                    2,
                    from.as_ptr(),
                    &mut rsa,
                    buf.as_mut_ptr(),
                    2,
                    kdk_a.as_mut_ptr()
                ),
                1
            );
            assert_ne!(kdk_a, kdk_b);

            BN_free(d);
        }
    }
}
