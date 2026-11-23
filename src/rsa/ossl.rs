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
//!   private key material and the ciphertext rather than of the blinding. There are exactly three
//!   KDK paths, each resting on its own assumption: `d` when the object holds it (the authority's
//!   `HMAC-SHA-256(SHA-256(d), ciphertext)`; `d` is private); otherwise `p` and `q` when the
//!   object holds them (`HMAC-SHA-256(SHA-256(label || p || q), label || ciphertext)`; both primes
//!   are private); otherwise a 32-byte per-object secret drawn once with `RAND_priv_bytes`
//!   (`HMAC-SHA-256(secret, label || ciphertext)`; the RNG is unpredictable and the secret never
//!   leaves the side table). No path hashes the decrypted block: for an attacker-constructed
//!   ciphertext that value is public, and the withdrawn construction that keyed the PRF with it
//!   is recorded in `evidence/haz-15/KDK-CORRECTION.md`. The first-use secret initialisation holds
//!   the side table's lock only for its own state transitions and never across `RAND_priv_bytes`,
//!   which may reach an application RNG method (`evidence/haz-15/REENTRANCY-AND-LENGTH.md`). The
//!   divergence from the authority is recorded in `docs/SECURITY_DIVERGENCE_POLICY.md`
//!   (`D-RSA-EXTKEY-ORACLE-1`).
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
#[cfg(test)]
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::{AtomicPtr, Ordering};

use std::sync::{Condvar, Mutex, MutexGuard};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use crate::bn::arith::{
    BN_add, BN_cmp, BN_div, BN_mod_add, BN_mod_inverse, BN_mul, BN_sub, BN_ucmp,
};
use crate::bn::bignum::{
    bn_num_bits_consttime, BN_bin2bn, BN_bn2binpad, BN_free, BN_is_negative, BN_is_zero, BN_new,
    BN_num_bits, BN_set_flags, BN_value_one, BN_with_flags, BigNum,
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
use crate::digest::sha2::{SHA256, SHA256_DIGEST_LENGTH};
use crate::evp::digest::{EVP_Digest, EVP_MD_fetch, EVP_MD_free, EvpMd};
use crate::evp::pkey_ctx::{
    RSA_NO_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING, RSA_X931_PADDING,
};
use crate::mac::hmac::{
    HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update, HmacCtx,
};
use crate::rand::rand_lib::RAND_priv_bytes;
use crate::runtime::constant_time::constant_time_msb_u32;
use crate::runtime::err::err_sites;
use crate::runtime::err::{err_clear_last_constant_time, raise_site};
use crate::runtime::owned_buf::OwnedBuf;
use crate::runtime::secret::{SecretArray, SecretBuf};
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
use crate::runtime::mem::cleanse;
use crate::runtime::mem_coords::SeamFile;

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/rsa/rsa_ossl.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — measured with `strings` on
/// `forensics/authorities/build/openssl-3.6.4-production/crypto/rsa/libcrypto-lib-rsa_ossl.o`,
/// the same check D279 and D280 applied to the cipher units. It matters here for the same reason
/// it does in `src/rsa/mod.rs`: `file` reaches an application through `CRYPTO_set_mem_functions`.
#[allow(dead_code)] // read by the four crypt entry points' `OPENSSL_malloc`, none of which has a caller here yet
const FILE_RSA_OSSL: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_ossl.c".as_ptr();
const FILE_RSA_OSSL_SEAM: SeamFile =
    SeamFile::new(c"../../src/openssl-3.6.4/crypto/rsa/rsa_ossl.c");

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

/// Test-only counter of entries to the CRT tail's congruence fallback — the raw `d`
/// exponentiation taken when the per-prime result does not re-exponentiate to the input.
///
/// T6 found that a missing `goto tail` made this fallback run on every private operation while
/// still returning the right answer, so no value comparison could see it. This counter lets a
/// test observe the path itself. It exists only under `cfg(test)`, writes only a relaxed atomic,
/// and never changes the value the operation returns.
#[cfg(test)]
static TAIL_FALLBACK_COUNT: AtomicUsize = AtomicUsize::new(0);

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
/// selector, an explicit opt-out of implicit rejection that `rsa_ossl_private_decrypt` honours for
/// the caller that passes it. The authority also *substitutes* it for `RSA_PKCS1_PADDING` when the
/// key is external; this crate does not, because that substitution is the padding oracle recorded
/// as HAZ-15. An external key now takes the same implicit-rejection arm as an internal one, with
/// the KDK derived from private key material and the ciphertext (see [`derive_external_kdk`]).
///
/// It is declared here rather than beside the other seven in `src/evp/pkey_ctx.rs` because this
/// file is its only reader in the crate: the ctrl-string map and the providers never name it.
pub(crate) const RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING: c_int = 8;

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
///
/// # Safety
///
/// `meth` is a non-NULL, live `RSA_METHOD`. Established by `rsa_ossl_mod_exp` and the other
/// in-file callers, which read it from the live `RSA` they were handed.
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

/// [`free_bn_blinding`]'s clearing twin: release the value **and** remove its slot.
///
/// `rsa_ossl_finish` uses this rather than `free_bn_blinding` because a method transition must
/// leave the store empty. Every stored blinding borrows `rsa->_method_mod_n` as its `m_ctx`
/// (`RSA_setup_blinding` passes it to `BN_BLINDING_create_param`), and the same hook releases
/// that context; a blinding left behind would hand the next private operation a released
/// pointer. A NULL value is `ossl_sa_set`'s removal, and `ossl_sa_doall_arg` snapshots the
/// leaves before it calls back, so re-entering the array here is sound.
///
/// # Safety
///
/// `b` must be NULL or a live `BN_BLINDING` this array owns, and `arg` must be the live
/// `OpenSslSa` the walk is over.
unsafe fn free_bn_blinding_and_clear(idx: OsslUintMax, b: *mut c_void, arg: *mut c_void) {
    // SAFETY: `arg` is the live array the walk is over and `idx` is a slot the snapshot found
    // non-NULL; a NULL value removes it.
    unsafe { ossl_sa_set(arg.cast::<OpenSslSa>(), idx, ptr::null_mut()) };
    // SAFETY: `b` is the value the snapshot found in the array, so it is a `BN_BLINDING *` this
    // array owns; `BN_BLINDING_free` accepts NULL.
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
        let mut r: c_int = -1;

        let ctx: *mut BnCtx = BN_CTX_new_ex((*rsa).libctx);
        if ctx.is_null() {
            // The authority's `goto err` with a NULL context: `BN_CTX_end(NULL)` and
            // `BN_CTX_free(NULL)` are no-ops and the buffer was never allocated.
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        }
        BN_CTX_start(ctx);
        let f = BN_CTX_get(ctx);
        let ret = BN_CTX_get(ctx);
        let num: c_int = bn_num_bytes((*rsa).n);
        // `CRYPTO_malloc` at the authority's exact size/`file`/`line`; `Drop` is its single release.
        let Some(buf_owner) = OwnedBuf::new_cleansed(num as usize, FILE_RSA_OSSL_SEAM, LINE) else {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        };
        if ret.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        }
        let buf = buf_owner.as_ptr();

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

        // The authority's `err:` label. `buf_owner`'s `Drop` performs the buffer's single release
        // after `r` is evaluated, at the authority's own cleansing site.
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
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
        let mut r: c_int = -1;
        let mut blinding: *mut Blinding = ptr::null_mut();

        let ctx: *mut BnCtx = BN_CTX_new_ex((*rsa).libctx);
        if ctx.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        }
        BN_CTX_start(ctx);
        let f = BN_CTX_get(ctx);
        let ret = BN_CTX_get(ctx);
        let num: c_int = bn_num_bytes((*rsa).n);
        // `CRYPTO_malloc` at the authority's exact size/`file`/`line`; `Drop` is its single release.
        let Some(buf_owner) = OwnedBuf::new_cleansed(num as usize, FILE_RSA_OSSL_SEAM, LINE) else {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        };
        if ret.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        }
        let buf = buf_owner.as_ptr();

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

        // The authority's `err:` label. `buf_owner`'s `Drop` performs the buffer's single release
        // after `r` is evaluated, at the authority's own cleansing site.
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
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
        // `d_hash` is `SHA-256(d)`: a value from which the KDK is keyed. The authority leaves it
        // on the stack; this crate wipes it on every exit (a safety improvement, not an
        // observable change).
        cleanse(d_hash.as_mut_ptr(), d_hash.len());
        ret
    }
}

// ---------------------------------------------------------------------------------------------
// `crypto/rsa/rsa_ossl.c:527-800` — the two decryption entry points
// ---------------------------------------------------------------------------------------------

/// Domain-separation label for the CRT-derived PRF key (`SHA-256(label || p || q)`).
const EXT_KDK_KEY_LABEL: &[u8] = b"openssl-rs/rsa/ext-kdk/crt-key/v1";
/// Domain-separation label for the PRF itself (`HMAC(key, label || ciphertext)`).
const EXT_KDK_MAC_LABEL: &[u8] = b"openssl-rs/rsa/ext-kdk/ciphertext/v1";
/// Domain-separation label for the per-object random-secret PRF. Distinct from the CRT label so a
/// random secret and a CRT-derived key can never be used under the same derivation.
const EXT_KDK_RANDOM_MAC_LABEL: &[u8] = b"openssl-rs/rsa/ext-kdk/random-ciphertext/v1";
/// The secret width: one SHA-256 output.
const EXT_KDK_SECRET_LEN: usize = SHA256_DIGEST_LENGTH as usize;

/// The external-key KDK: a PRF, keyed by secret material, over the ciphertext.
///
/// [`derive_kdk`] needs `d`; a key with `RSA_FLAG_EXT_PKEY` does not hold it. The synthetic
/// message must nevertheless be **unpredictable to an attacker who knows the ciphertext and the
/// public key**, and deterministic for one ciphertext, which is what the implicit rejection needs.
/// The previous revision keyed the PRF with `SHA-256(decrypted block)`. That value is not secret
/// for a ciphertext the attacker constructed (`c = m^e mod n` returns the known `m`), so the
/// attacker could compute the synthetic answer and recover the padding-validity distinction. The
/// construction is therefore replaced, in this order:
///
/// 1. **Private CRT material.** When the object holds `p` and `q`, the PRF key is
///    `SHA-256(KEY_LABEL || p || q)`. Both primes are private to the key holder and never leave
///    the object, so the attacker cannot compute the key. The derivation is deterministic for the
///    key material, so the same ciphertext answers the same bytes even across two `RSA` objects
///    built from that material.
/// 2. **A per-key random secret.** A key that holds no private material at all (the
///    engine-backed `(n, e)` shape) has nothing secret to derive from. At first use a 32-byte
///    secret is drawn with [`RAND_priv_bytes`] and stored against the object; the PRF key is that
///    secret. RNG failure and allocation failure answer the defined error (a zero return, which
///    the caller turns into the ordinary refusal) — there is **no** fallback to a
///    publicly-derivable value. The secret is owned by the side table, cleansed when the entry is
///    released, and released when the `RSA` object is destroyed. Two objects built from the same
///    public-only material therefore receive independent secrets; the synthetic answer is
///    deterministic per object and ciphertext, not across objects. That residual is recorded in
///    `evidence/haz-15/KDK-CORRECTION.md` rather than hidden.
///
/// Every derivation is domain-separated by a label kept distinct from the padding check's own
/// `"message"`/`"length"` labels, and the KDK is used for nothing except [`ossl_rsa_prf`].
///
/// # Safety
/// `rsa` is a live object; `from` is readable for `flen` bytes; `kdk` is writable for
/// `SHA256_DIGEST_LENGTH` bytes.
unsafe fn derive_external_kdk(
    rsa: *mut Rsa,
    from: *const c_uchar,
    flen: c_int,
    kdk: *mut c_uchar,
) -> c_int {
    // SAFETY: `rsa` and its fields are live per this function's `# Safety` section.
    unsafe {
        if flen < 0 {
            return 0;
        }
        if !(*rsa).p.is_null() && !(*rsa).q.is_null() {
            return if derive_crt_kdk(rsa, from, flen, kdk) {
                1
            } else {
                0
            };
        }
        let Ok(secret) = per_key_ext_kdk_secret(rsa) else {
            return 0;
        };
        if hmac_sha256_kdf(
            (*rsa).libctx,
            secret.as_ptr(),
            EXT_KDK_SECRET_LEN,
            EXT_KDK_RANDOM_MAC_LABEL,
            from,
            flen as usize,
            kdk,
        ) {
            1
        } else {
            0
        }
    }
}

/// The PRF key derived once from the CRT primes: `SHA-256(KEY_LABEL || p || q)`.
///
/// The two primes are written at their own widths, so the length is unambiguous without a
/// separate encoding. The concatenation is held in a [`SecretBuf`] and cleansed on every exit;
/// the resulting key is a stack [`SecretArray`], likewise cleansed.
///
/// # Safety
/// `rsa` is live and holds non-NULL `p` and `q`; `from` is readable for `flen` bytes; `kdk` is
/// writable for `SHA256_DIGEST_LENGTH` bytes.
unsafe fn derive_crt_kdk(
    rsa: *mut Rsa,
    from: *const c_uchar,
    flen: c_int,
    kdk: *mut c_uchar,
) -> bool {
    // SAFETY: `rsa` is live per this function's `# Safety` section.
    unsafe {
        let p = (*rsa).p;
        let q = (*rsa).q;
        let p_len = bn_num_bytes(p);
        let q_len = bn_num_bytes(q);
        if p_len <= 0 || q_len <= 0 {
            return false;
        }
        let total = EXT_KDK_KEY_LABEL.len() + p_len as usize + q_len as usize;
        let Some(mut material) = SecretBuf::<u8>::try_zeroed(total) else {
            return false;
        };
        material[..EXT_KDK_KEY_LABEL.len()].copy_from_slice(EXT_KDK_KEY_LABEL);
        let p_at = EXT_KDK_KEY_LABEL.len();
        let q_at = p_at + p_len as usize;
        if BN_bn2binpad(p, material[p_at..].as_mut_ptr(), p_len) != p_len
            || BN_bn2binpad(q, material[q_at..].as_mut_ptr(), q_len) != q_len
        {
            return false;
        }

        let mut key = SecretArray::<EXT_KDK_SECRET_LEN>::new();
        // SAFETY: `material` is readable for `total` bytes and `key` is writable for the digest
        // length; the output is checked by the caller's use of the KDK only.
        SHA256(material.as_ptr(), total, key.as_mut_ptr());

        hmac_sha256_kdf(
            (*rsa).libctx,
            key.as_ptr(),
            EXT_KDK_SECRET_LEN,
            EXT_KDK_MAC_LABEL,
            from,
            flen as usize,
            kdk,
        )
    }
}

/// HMAC-SHA-256 over `label || data`, keyed by `key`.
///
/// The two updates are separate so the label cannot be confused with the first bytes of a
/// ciphertext. Every handle is released on every exit; a failure answers `false` and leaves `out`
/// unspecified, which the caller treats as no KDK at all.
///
/// # Safety
/// `key` is readable for `key_len` bytes; `data` is readable for `data_len` bytes; `out` is
/// writable for `SHA256_DIGEST_LENGTH` bytes.
unsafe fn hmac_sha256_kdf(
    libctx: *mut c_void,
    key: *const c_uchar,
    key_len: usize,
    label: &[u8],
    data: *const c_uchar,
    data_len: usize,
    out: *mut c_uchar,
) -> bool {
    // SAFETY: the caller's contract; the handles below are NULL until created and are released
    // together at the end of this function.
    unsafe {
        let hmac = HMAC_CTX_new();
        if hmac.is_null() {
            return false;
        }
        let md = EVP_MD_fetch(libctx, c"sha256".as_ptr(), ptr::null());
        if md.is_null() {
            HMAC_CTX_free(hmac);
            return false;
        }
        let mut ok = HMAC_Init_ex(
            hmac,
            key.cast::<c_void>(),
            key_len as c_int,
            md,
            ptr::null_mut(),
        ) > 0
            && HMAC_Update(hmac, label.as_ptr(), label.len()) > 0
            && HMAC_Update(hmac, data, data_len) > 0;
        if ok {
            let mut md_len: c_uint = SHA256_DIGEST_LENGTH;
            ok = HMAC_Final(hmac, out, ptr::addr_of_mut!(md_len)) > 0;
        }
        HMAC_CTX_free(hmac);
        EVP_MD_free(md);
        ok
    }
}

/// How long a thread that finds a peer's `INITIALIZING` reservation will block on the store's
/// condition variable before answering the defined refusal.
///
/// The bound exists so a peer that never publishes — a panicked or wedged initialiser, or a
/// cross-thread reservation cycle — cannot turn the wait into an unbounded one. A normal `RNG`
/// draw is a single `RAND_priv_bytes` call.
const EXT_KDK_WAIT_LIMIT: Duration = Duration::from_secs(5);

/// Why a first-use secret could not be obtained.
///
/// Every variant is a refusal: the caller (`derive_external_kdk`) answers `0`, and
/// `rsa_ossl_private_decrypt` takes its ordinary error path. No variant falls back to a
/// publicly-derivable value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtKdkRefusal {
    /// The calling thread already owns this object's `INITIALIZING` reservation. This is the
    /// same-thread re-entry an application RNG callback can cause; waiting on it would deadlock.
    ReentrantInitialization,
    /// The reservation disappeared before the secret could be published or consulted: the object
    /// was destroyed, or the initialiser abandoned the reservation after a failure.
    ReservationAbandoned,
    /// No peer published or abandoned the reservation within [`EXT_KDK_WAIT_LIMIT`].
    WaitTimedOut,
    /// `RAND_priv_bytes` refused.
    RngFailure,
    /// A reservation or secret allocation was refused.
    AllocationFailure,
}

/// One per-object entry: the object it belongs to, the reservation that owns it, and either the
/// thread initialising it or the published secret.
///
/// The key is the `RSA` pointer's address, which is stable for the object's lifetime and is
/// removed by [`forget_ext_kdk_secret`] when the object is destroyed. The secret is a
/// [`SecretBuf`], so releasing the entry wipes the whole allocation; an `Initializing` entry owns
/// no secret at all.
struct ExtKdkEntry {
    rsa: usize,
    reservation: u64,
    state: ExtKdkState,
}

enum ExtKdkState {
    /// Reserved by `owner`, which is drawing the secret with the lock released. A peer waits on
    /// the store's condition variable; the owner re-enters should it call itself.
    Initializing { owner: ThreadId },
    /// The one secret for this object.
    Ready(SecretBuf<u8>),
}

/// The per-object secret store for external keys with no private material.
///
/// This is a side table rather than an `Rsa` field on purpose: `Rsa` is a `#[repr(C)]`
/// transcription of the authority's `struct rsa_st` whose size and offsets are asserted, and the
/// hard constraint on this correction is that those layouts are preserved. The table adds no
/// field to any exported or measured object.
///
/// The entries are boxed so the reservation itself is a single fallible allocation independent of
/// the vector's spare capacity; every growth goes through [`crate::runtime::alloc::try_reserve`],
/// and the secret through [`SecretBuf::try_zeroed`]. Nothing on the path pushes infallibly.
struct ExtKdkStore {
    // The entry is boxed so its allocation is a single fallible step independent of the vector's
    // spare capacity; that is what makes the reservation's failure injectable and testable.
    #[allow(clippy::vec_box)]
    entries: Vec<Box<ExtKdkEntry>>,
    next_reservation: u64,
}

static EXT_KDK_STORE: Mutex<ExtKdkStore> = Mutex::new(ExtKdkStore {
    entries: Vec::new(),
    next_reservation: 1,
});

/// Wakes a peer when a reservation is published or abandoned. Always paired with
/// [`EXT_KDK_STORE`]: a waiter holds the store's lock while it checks the entry and calls
/// `wait`, so no notification can be lost between the check and the wait.
static EXT_KDK_STORE_CV: Condvar = Condvar::new();

/// Test-only count of threads blocked on [`EXT_KDK_STORE_CV`]. It lets a control wait until a
/// peer is genuinely parked rather than sleeping for a guessed interval.
#[cfg(test)]
static EXT_KDK_WAITERS: AtomicUsize = AtomicUsize::new(0);

/// Take the store's lock, recovering from a poisoned lock rather than making every later
/// decryption fail. Every mutation is a single vector operation under the lock, so a caught
/// panic cannot leave a half-published entry behind.
fn lock_ext_kdk_store() -> MutexGuard<'static, ExtKdkStore> {
    match EXT_KDK_STORE.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Block on the store's condition variable for at most `timeout`.
///
/// `None` means the wait timed out; a spurious wake answers `Some` and the caller re-checks the
/// entry. A poisoned mutex is recovered exactly as [`lock_ext_kdk_store`] does.
fn wait_ext_kdk_store<'a>(
    guard: MutexGuard<'a, ExtKdkStore>,
    timeout: Duration,
) -> Option<MutexGuard<'a, ExtKdkStore>> {
    match EXT_KDK_STORE_CV.wait_timeout(guard, timeout) {
        Ok((guard, status)) => (!status.timed_out()).then_some(guard),
        Err(poisoned) => {
            let (guard, status) = poisoned.into_inner();
            (!status.timed_out()).then_some(guard)
        }
    }
}

/// Reserve an `INITIALIZING` entry for `key` and return its failure-atomic guard.
///
/// Both allocations are fallible: the entry's box and the vector's growth. A failure publishes
/// nothing and the vector is left as it was. The guard is constructed as the last step, after the
/// entry is installed and with no panic-capable operation between them, so an installation that
/// succeeded always has an owner that removes it.
fn reserve_ext_kdk_entry(
    store: &mut ExtKdkStore,
    key: usize,
    owner: ThreadId,
) -> Result<ExtKdkReservation, ExtKdkRefusal> {
    let reservation = store.next_reservation;
    store.next_reservation = store.next_reservation.wrapping_add(1);
    let entry = match crate::runtime::alloc::try_boxed(ExtKdkEntry {
        rsa: key,
        reservation,
        state: ExtKdkState::Initializing { owner },
    }) {
        // SAFETY: `try_boxed` returned a fresh allocation for exactly one `ExtKdkEntry`.
        Ok(raw) => unsafe { Box::from_raw(raw) },
        Err(_) => return Err(ExtKdkRefusal::AllocationFailure),
    };
    if !crate::runtime::alloc::try_reserve(&mut store.entries, 1) {
        return Err(ExtKdkRefusal::AllocationFailure);
    }
    store.entries.push(entry);
    Ok(ExtKdkReservation {
        key,
        reservation,
        published: false,
    })
}

/// Publish `fresh` into the reservation if it is still the exact entry this thread owns.
///
/// The exact reservation id is required, not merely the address: when the object was destroyed
/// during initialisation the entry is gone, and when the address was reused the new object holds
/// a different reservation. Neither case may receive this secret. On refusal `fresh` is dropped
/// here and therefore cleansed.
fn publish_ext_kdk_secret(
    key: usize,
    reservation: u64,
    owner: ThreadId,
    fresh: SecretBuf<u8>,
) -> Result<SecretArray<EXT_KDK_SECRET_LEN>, ExtKdkRefusal> {
    let mut store = lock_ext_kdk_store();
    let index = store.entries.iter().position(|entry| {
        entry.rsa == key
            && entry.reservation == reservation
            && matches!(&entry.state, ExtKdkState::Initializing { owner: recorded } if *recorded == owner)
    });
    let Some(index) = index else {
        return Err(ExtKdkRefusal::ReservationAbandoned);
    };
    #[cfg(test)]
    ext_kdk_hooks::maybe_panic(ext_kdk_hooks::Stage::PublishBeforeInstall);
    let mut out = SecretArray::<EXT_KDK_SECRET_LEN>::new();
    out.as_mut_slice().copy_from_slice(&fresh[..]);
    store.entries[index].state = ExtKdkState::Ready(fresh);
    #[cfg(test)]
    ext_kdk_hooks::maybe_panic(ext_kdk_hooks::Stage::PublishAfterInstall);
    EXT_KDK_STORE_CV.notify_all();
    Ok(out)
}

/// Remove a reservation this thread owns after a failure, waking any peer waiting on it.
///
/// Removal is by the exact reservation id, so a later attempt's entry at the same address is not
/// disturbed. Retaining in place does not allocate.
fn abandon_ext_kdk_reservation(key: usize, reservation: u64) {
    let mut store = lock_ext_kdk_store();
    let before = store.entries.len();
    store
        .entries
        .retain(|entry| !(entry.rsa == key && entry.reservation == reservation));
    if store.entries.len() != before {
        EXT_KDK_STORE_CV.notify_all();
    }
}

/// Failure-atomic ownership of a reservation: unless the secret is published, dropping this guard
/// removes the reservation and wakes any waiter.
///
/// The early returns cover allocation and RNG failure; the guard additionally covers unwinding, so
/// a panic between reservation and publication cannot leave a permanent `INITIALIZING` entry that
/// every later call for the object would refuse.
struct ExtKdkReservation {
    key: usize,
    reservation: u64,
    published: bool,
}

impl Drop for ExtKdkReservation {
    fn drop(&mut self) {
        if !self.published {
            abandon_ext_kdk_reservation(self.key, self.reservation);
        }
    }
}

/// Test-only panic injection at the fallible steps of the first-use path.
///
/// The hook is thread-local and one-shot, so a control can name the exact step to
/// interrupt and no other thread is affected. It exists only in test builds; the
/// release path has no branch to it.
#[cfg(test)]
pub(crate) mod ext_kdk_hooks {
    use core::cell::Cell;

    /// The steps a control can interrupt.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum Stage {
        /// The reservation has been installed and the guard exists.
        AfterReserve,
        /// The secret has been drawn and is held in a `SecretBuf`, unpublished.
        AfterDraw,
        /// The draw failed: the failure path is about to abandon the reservation.
        DrawFailureAbandon,
        /// Publication has found its reservation, under the store's lock, and is
        /// about to install the secret.
        PublishBeforeInstall,
        /// The secret has been installed `Ready` and the guard has not yet been
        /// marked published.
        PublishAfterInstall,
    }

    std::thread_local! {
        static ARMED: Cell<Option<Stage>> = const { Cell::new(None) };
    }

    /// Disarms the injection when the control leaves scope, including on a panic.
    pub(crate) struct Armed;

    impl Drop for Armed {
        fn drop(&mut self) {
            ARMED.with(|cell| cell.set(None));
        }
    }

    /// Arm the injection at `stage` on this thread.
    pub(crate) fn arm(stage: Stage) -> Armed {
        ARMED.with(|cell| cell.set(Some(stage)));
        Armed
    }

    #[allow(clippy::panic)] // the injected defect is the point of the hook
    pub(crate) fn maybe_panic(stage: Stage) {
        ARMED.with(|cell| {
            if cell.get() == Some(stage) {
                cell.set(None);
                panic!("injected defect: panic at {stage:?}");
            }
        });
    }
}

/// The first-use secret for an `RSA` with no `d`, `p` or `q`.
///
/// The store's lock is held for lookup, reservation, publication and removal only. **It is not
/// held across [`RAND_priv_bytes`]**, which may reach an application-provided RNG method; a
/// callback that re-enters RSA decryption therefore cannot deadlock against this lock.
///
/// States and transitions:
///
/// * a hit on `Ready` copies the secret out and returns it;
/// * a miss reserves an `Initializing` entry recording the calling thread, releases the lock,
///   draws 32 bytes, then re-acquires and publishes them;
/// * a peer that finds `Initializing` blocks on the condition variable until the entry is
///   published (and copies the same secret) or removed (and receives [`ReservationAbandoned`]);
/// * the owning thread that finds its own `Initializing` entry receives
///   [`ReentrantInitialization`] immediately — it does not wait on itself;
/// * the wait is bounded by [`EXT_KDK_WAIT_LIMIT`], so a peer that never returns is a refusal,
///   not an unbounded wait;
/// * destruction ([`forget_ext_kdk_secret`]) removes the entry and wakes the waiters; a later
///   publish finds no matching reservation and is refused, so no secret is published into a
///   freed object.
///
/// Allocation, RNG failure and abandonment remove the reservation before returning; the drawn
/// secret is a [`SecretBuf`] and is cleansed on every path that does not publish it. The
/// reservation is held by an [`ExtKdkReservation`] guard, so an unwind between the reservation and
/// the publication also removes it.
///
/// **Lock ordering on the unwind path.** The reservation's guard is created inside the critical
/// section as its last step, and the lock is released immediately afterwards with no
/// panic-capable operation in between. The guard's `Drop` takes that same non-reentrant lock, so
/// this ordering is what makes an unwind reached with the lock held — a panicking application RNG
/// method called from `RAND_priv_bytes`, or a panic inside publication — release the reservation
/// on a lock the frame no longer holds instead of deadlocking on it. A panic taken inside a
/// critical section poisons the lock; [`lock_ext_kdk_store`] recovers the guard from the poison,
/// which is what keeps a later decryption working.
fn per_key_ext_kdk_secret(rsa: *mut Rsa) -> Result<SecretArray<EXT_KDK_SECRET_LEN>, ExtKdkRefusal> {
    let key = rsa as usize;
    let me = std::thread::current().id();
    let deadline = Instant::now() + EXT_KDK_WAIT_LIMIT;
    let mut store = lock_ext_kdk_store();

    // Serve an existing secret, or wait on a peer's reservation. A waiter accepts only the exact
    // reservation it observed: a different reservation at the same address means the original
    // was abandoned or the object destroyed, and it is not adopted.
    while let Some(index) = store.entries.iter().position(|entry| entry.rsa == key) {
        let reservation = store.entries[index].reservation;
        match &store.entries[index].state {
            ExtKdkState::Ready(secret) => {
                let mut out = SecretArray::<EXT_KDK_SECRET_LEN>::new();
                out.as_mut_slice().copy_from_slice(&secret[..]);
                return Ok(out);
            }
            ExtKdkState::Initializing { owner } => {
                if *owner == me {
                    return Err(ExtKdkRefusal::ReentrantInitialization);
                }
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(ExtKdkRefusal::WaitTimedOut);
        }
        let Some(guard) = ({
            #[cfg(test)]
            EXT_KDK_WAITERS.fetch_add(1, Ordering::SeqCst);
            let waited = wait_ext_kdk_store(store, deadline - now);
            #[cfg(test)]
            EXT_KDK_WAITERS.fetch_sub(1, Ordering::SeqCst);
            waited
        }) else {
            return Err(ExtKdkRefusal::WaitTimedOut);
        };
        store = guard;
        if !store
            .entries
            .iter()
            .any(|entry| entry.rsa == key && entry.reservation == reservation)
        {
            return Err(ExtKdkRefusal::ReservationAbandoned);
        }
    }

    let mut reservation_guard = reserve_ext_kdk_entry(&mut store, key, me)?;
    let reservation = reservation_guard.reservation;
    // **The guard is never dropped while this frame holds the lock.** Its `Drop` takes the same
    // non-reentrant lock to remove the reservation, so the lock is released immediately after the
    // reservation returns; the only statements in between are a field read and this `drop`, neither
    // of which can panic. Dropping the lock first is what makes every later panic point release the
    // reservation instead of deadlocking on a lock the frame still holds.
    drop(store);
    // The reservation is installed and the guard exists: from here every exit, normal
    // or unwinding, removes the reservation unless it publishes.
    #[cfg(test)]
    ext_kdk_hooks::maybe_panic(ext_kdk_hooks::Stage::AfterReserve);

    let mut fresh = match SecretBuf::<u8>::try_zeroed(EXT_KDK_SECRET_LEN) {
        Some(buffer) => buffer,
        // Dropping the guard removes the reservation and wakes any waiter.
        None => return Err(ExtKdkRefusal::AllocationFailure),
    };
    // The store's lock is **not** held here: `RAND_priv_bytes` may reach an application RNG
    // method, which may re-enter RSA decryption.
    // SAFETY: `fresh` is writable for `EXT_KDK_SECRET_LEN` bytes and the call is this crate's
    // `RAND_priv_bytes`, whose contract is the authority's.
    if unsafe { RAND_priv_bytes(fresh.as_mut_ptr(), EXT_KDK_SECRET_LEN as c_int) } <= 0 {
        // Dropping the guard removes the reservation and wakes any waiter.
        #[cfg(test)]
        ext_kdk_hooks::maybe_panic(ext_kdk_hooks::Stage::DrawFailureAbandon);
        return Err(ExtKdkRefusal::RngFailure);
    }
    // The draw succeeded and the secret is still unpublished.
    #[cfg(test)]
    ext_kdk_hooks::maybe_panic(ext_kdk_hooks::Stage::AfterDraw);
    let result = publish_ext_kdk_secret(key, reservation, me, fresh);
    if result.is_ok() {
        reservation_guard.published = true;
    }
    result
}

/// Release the per-object entry when the `RSA` object is destroyed.
///
/// Removal is unconditional and happens under the store's lock, so an address reused by a later
/// allocation cannot observe a stale secret. Dropping the entry cleanses the `SecretBuf` before
/// its allocation is released. An `Initializing` entry is removed at the same time: its owner's
/// publication will find no matching reservation and is refused, and every waiter is woken and
/// receives [`ExtKdkRefusal::ReservationAbandoned`].
///
/// # Safety
/// `rsa` is the address of an object whose last reference is being released; it is read only as
/// an integer and never dereferenced.
pub(crate) fn forget_ext_kdk_secret(rsa: *mut Rsa) {
    let key = rsa as usize;
    let mut store = lock_ext_kdk_store();
    let before = store.entries.len();
    let mut removed_initializing = false;
    store.entries.retain(|entry| {
        if entry.rsa != key {
            return true;
        }
        if matches!(&entry.state, ExtKdkState::Initializing { .. }) {
            removed_initializing = true;
        }
        false
    });
    if removed_initializing || store.entries.len() != before {
        EXT_KDK_STORE_CV.notify_all();
    }
}

/// The number of threads blocked on the store's condition variable. Test-only.
#[cfg(test)]
fn ext_kdk_waiter_count() -> usize {
    EXT_KDK_WAITERS.load(Ordering::SeqCst)
}

/// The number of store entries for `rsa`, whatever their state. Test-only observation of the
/// "exactly one secret per object" invariant.
#[cfg(test)]
fn ext_kdk_entry_count(rsa: *mut Rsa) -> usize {
    let store = lock_ext_kdk_store();
    store
        .entries
        .iter()
        .filter(|entry| entry.rsa == rsa as usize)
        .count()
}

/// The number of `INITIALIZING` entries for `rsa`. Test-only observation of the state machine.
#[cfg(test)]
fn ext_kdk_initializing_count(rsa: *mut Rsa) -> usize {
    let store = lock_ext_kdk_store();
    store
        .entries
        .iter()
        .filter(|entry| {
            entry.rsa == rsa as usize && matches!(&entry.state, ExtKdkState::Initializing { .. })
        })
        .count()
}

/// The number of `Ready` entries for `rsa`. Test-only observation of publication.
#[cfg(test)]
fn ext_kdk_ready_count(rsa: *mut Rsa) -> usize {
    let store = lock_ext_kdk_store();
    store
        .entries
        .iter()
        .filter(|entry| entry.rsa == rsa as usize && matches!(&entry.state, ExtKdkState::Ready(_)))
        .count()
}

/// `static int rsa_ossl_private_decrypt(int flen, const unsigned char *from, unsigned char *to,`
/// `RSA *rsa, int padding)` — `rsa_ossl.c:527-700`.
///
/// The decryption entry point, and the one the implicit rejection lives in. Five things about it
/// are contract:
///
/// * **The implicit-rejection arm is the one an external key takes.** The authority rewrites the
///   selector when the key is external (`RSA_FLAG_EXT_PKEY`) and the caller asked for PKCS#1 v1.5,
///   falling back to the refusing check because an external key does not hold the private
///   exponent. That is the padding oracle recorded as HAZ-15; this crate keeps the implicit arm.
///   The KDK is constructed on exactly one of three paths, each with its own assumption:
///   1. **`d` present.** [`derive_kdk`] computes
///      `HMAC-SHA-256(SHA-256(d padded to the modulus width), ciphertext)`. Assumption: `d` is
///      private to the key holder and never leaves the object. This is the authority's own
///      construction, kept unchanged so the internal-key synthetic bytes stay byte-identical.
///   2. **`d` absent, `p` and `q` present.** [`derive_external_kdk`] derives
///      `K = SHA-256(CRT_KEY_LABEL || p || q)` and then
///      `HMAC-SHA-256(K, CRT_MAC_LABEL || ciphertext)`. Assumption: both primes are private to
///      the key holder.
///   3. **No private material at all.** A 32-byte secret is drawn once per object with
///      [`RAND_priv_bytes`] and the synthetic answer is keyed by
///      `HMAC-SHA-256(secret, RANDOM_MAC_LABEL || ciphertext)`. Assumption: the RNG output is
///      unpredictable to the attacker and the side table keeps the secret for the object's
///      lifetime. A draw or allocation failure is a refusal, never a publicly-derivable fallback.
///
///   No path hashes the decrypted block, because for an attacker-chosen block that value is
///   public. The content axes do not distinguish valid from invalid padding on any path; the
///   returned **length** is a separate, still-open channel
///   (`evidence/haz-15/REENTRANCY-AND-LENGTH.md`). The explicit selector
///   `RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING` still selects the refusing check for a caller that
///   passes it.
/// * **The length refusals raise different reasons**: `RSA_R_DATA_GREATER_THAN_MOD_LEN` for
///   `flen > num` and `RSA_R_DATA_TOO_SMALL` for `flen < 1`, and the authority's comment records
///   that the first test is not equality because PGP chops leading zero octets.
/// * **The KDK is derived only for `RSA_PKCS1_PADDING`**, after the unblinding. With `d` present
///   it is derived by [`derive_kdk`] and `buf` holds `ret`'s bytes at that moment — the scratch
///   use [`derive_kdk`] documents; with `d` absent it is derived by [`derive_external_kdk`] inside
///   the switch, from the CRT primes or the first-use secret, and `buf` is only read.
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
        /*
         * The authority substitutes RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING here when the key is
         * external and the caller asked for PKCS#1 v1.5, because it cannot derive the KDK without
         * the private exponent. That refusal is observable (a negative return, an untouched output
         * buffer and `RSA_R_PADDING_CHECK_FAILED` on the queue) and is the padding oracle HAZ-15.
         * This crate keeps `RSA_PKCS1_PADDING` so the implicit-rejection arm runs. The KDK below
         * is derived from private key material, never from the decrypted block: `d` when the
         * object holds it, otherwise the CRT primes, otherwise a first-use RNG secret held in the
         * side table. See `derive_external_kdk` for the assumption each path relies on. The
         * divergence is recorded in `docs/SECURITY_DIVERGENCE_POLICY.md` as
         * `D-RSA-EXTKEY-ORACLE-1`.
         */

        let mut r: c_int = -1;
        let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
        let mut blinding: *mut Blinding = ptr::null_mut();

        let ctx: *mut BnCtx = BN_CTX_new_ex((*rsa).libctx);
        if ctx.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        }
        BN_CTX_start(ctx);
        let f = BN_CTX_get(ctx);
        let ret = BN_CTX_get(ctx);
        if ret.is_null() {
            raise_site(&err_sites::RSA_OSSL_549);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        }
        let num: c_int = bn_num_bytes((*rsa).n);
        // `CRYPTO_malloc` at the authority's exact size/`file`/`line`; `Drop` is its single release.
        let Some(buf_owner) = OwnedBuf::new_cleansed(num as usize, FILE_RSA_OSSL_SEAM, LINE) else {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        };
        let buf = buf_owner.as_ptr();

        /*
         * This check was for equality but PGP does evil things and chops off the top '0' bytes
         */
        if flen > num {
            raise_site(&err_sites::RSA_OSSL_562);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        }

        if flen < 1 {
            raise_site(&err_sites::RSA_OSSL_567);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
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
             * Path 1 (`d` present): derive the Key Derivation Key from the private exponent and
             * the public ciphertext. The two absent-`d` paths are decided in the switch below.
             */
            if padding == RSA_PKCS1_PADDING
                && !(*rsa).d.is_null()
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
                    /*
                     * Paths 2 and 3 (`d` absent). An external key does not hold `d`, so the KDK
                     * above was not derived. Derive it from private key material and the
                     * ciphertext: the CRT primes when the object holds them (assumption: both
                     * primes are private), otherwise a per-key secret drawn at first use
                     * (assumption: the RNG is unpredictable and the side table keeps the secret).
                     * A hash of the decrypted block is *not* used — for an attacker-chosen block
                     * that value is public, which makes the synthetic answer predictable and
                     * restores the padding oracle (see `evidence/haz-15/KDK-CORRECTION.md`).
                     */
                    if (*rsa).d.is_null()
                        && derive_external_kdk(rsa, from, flen, kdk.as_mut_ptr()) == 0
                    {
                        break 'body;
                    }
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

        // The authority's `err:` label. `buf_owner`'s `Drop` performs the buffer's single release
        // after `r` is evaluated, at the authority's own cleansing site.
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        // The KDK is derived from secret key material; wipe the stack copy on every exit. The
        // authority leaves it; this crate does not (a safety improvement, not an observable
        // change).
        cleanse(kdk.as_mut_ptr(), kdk.len());
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

        let mut r: c_int = -1;

        let ctx: *mut BnCtx = BN_CTX_new_ex((*rsa).libctx);
        if ctx.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        }
        BN_CTX_start(ctx);
        let f = BN_CTX_get(ctx);
        let ret = BN_CTX_get(ctx);
        if ret.is_null() {
            raise_site(&err_sites::RSA_OSSL_735);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        }
        let num: c_int = bn_num_bytes((*rsa).n);
        // `CRYPTO_malloc` at the authority's exact size/`file`/`line`; `Drop` is its single release.
        let Some(buf_owner) = OwnedBuf::new_cleansed(num as usize, FILE_RSA_OSSL_SEAM, LINE) else {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return r;
        };
        let buf = buf_owner.as_ptr();

        /*
         * This check was for equality but PGP does evil things and chops off the top '0' bytes
         */
        if flen > num {
            raise_site(&err_sites::RSA_OSSL_748);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
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

        // The authority's `err:` label. `buf_owner`'s `Drop` performs the buffer's single release
        // after `r` is evaluated, at the authority's own cleansing site.
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
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
                        && bn_num_bits_consttime((*rsa).q) == bn_num_bits_consttime((*rsa).p);
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

        // Upstream's smooth arm ends with `goto tail`: the combine above is the whole
        // CRT computation for that path, so the generic per-prime exponentiation and
        // combine below are for the non-smooth path only. Without this gate the smooth
        // result was overwritten and the tail verification would fall back to the
        // unblinded `d` exponentiation on every private operation.
        if !failed && smooth == 0 {
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

        if !failed && smooth == 0 {
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
                        // Test-only observation point for the T11 regression case: the fallback
                        // below is the path T6 found being taken on *every* private operation.
                        // It is compiled out of every non-test build, has no effect on the
                        // computation, and the test reads it with a single-threaded `Relaxed`
                        // load/store, so it cannot change exported behaviour.
                        #[cfg(test)]
                        TAIL_FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
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
/// **Every released slot is cleared.** `RSA_set_method` calls this hook on each method transition
/// and then installs the new table; the authority leaves the freed pointers in the slots, so a
/// second `RSA_set_method` (or the next private operation, through `BN_MONT_CTX_set_locked`'s
/// non-NULL fast path) would read or release freed storage. Clearing the slots is a deliberate
/// divergence from `rsa_ossl.c:1179-1195` (§17: do not reproduce the authority's UB) and is not
/// observable to any caller that uses a released context correctly.
///
/// **The blinding store is emptied for the same reason.** Each stored `BN_BLINDING` borrows
/// `_method_mod_n` as its `m_ctx`, so leaving the store populated across the release above would
/// let the next private operation dereference a released Montgomery context. The values are
/// released and their slots cleared in place (no allocation can fail during a transition); the
/// next operation draws a fresh blinding. This is the same §17 divergence, applied to the second
/// alias of the released cache.
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
        // Release the blindings before the `n` cache they borrow. `rsa_get_blinding` finds them
        // again only if they are still in the store, and every one holds `_method_mod_n` as its
        // `m_ctx`; see the doc comment on this hook.
        let blindings = (*rsa).blindings_sa.cast::<OpenSslSa>();
        ossl_sa_doall_arg(
            blindings,
            Some(free_bn_blinding_and_clear),
            blindings.cast(),
        );

        let mut n: c_int = 0;
        while n < OPENSSL_sk_num((*rsa).prime_infos) {
            let pinfo = OPENSSL_sk_value((*rsa).prime_infos, n).cast::<super::RsaPrimeInfo>();
            // SAFETY: the stack's elements are `RSA_PRIME_INFO` records of this object's, and
            // `m` is NULL or a Montgomery context this object's cache arm created.
            BN_MONT_CTX_free((*pinfo).m);
            // SAFETY: `pinfo` is the same live record read above; the context it named was just
            // released, so the slot is cleared before any second `finish` can see it.
            (*pinfo).m = ptr::null_mut();
            n += 1;
        }

        BN_MONT_CTX_free((*rsa)._method_mod_n);
        (*rsa)._method_mod_n = ptr::null_mut();
        BN_MONT_CTX_free((*rsa)._method_mod_p);
        (*rsa)._method_mod_p = ptr::null_mut();
        BN_MONT_CTX_free((*rsa)._method_mod_q);
        (*rsa)._method_mod_q = ptr::null_mut();
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::BN_set_word;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::sync::mpsc;
    use std::sync::OnceLock;

    // ---------------------------------------------------------------------------------------
    // Test-only control of the process RNG method. The table replaces only the `bytes` callback;
    // every thread that did not arm a script delegates to the default generator, so unrelated
    // parallel tests observe identical bytes. The scripts make the application callback a real
    // re-entrancy edge: it can re-enter RSA decryption or park until the control releases it.
    // ---------------------------------------------------------------------------------------

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RngAction {
        Delegate,
        ReenterSame,
        ReenterOther,
        Fail,
        Block,
        /// Destroy the object whose first-use secret is being drawn.
        DestroyTarget,
    }

    thread_local! {
        static RNG_ACTION: Cell<RngAction> = const { Cell::new(RngAction::Delegate) };
        static RNG_SAME: Cell<usize> = const { Cell::new(0) };
        static RNG_OTHER: Cell<usize> = const { Cell::new(0) };
        static RNG_DEPTH: Cell<u32> = const { Cell::new(0) };
        static RNG_REENTRY_RESULT: Cell<c_int> = const { Cell::new(c_int::MIN) };
        static RNG_REENTRY_VARIANT_OK: Cell<bool> = const { Cell::new(false) };
    }

    /// Set when the callback could not acquire the store's lock. With the previous implementation
    /// the lock was held across `RAND_priv_bytes`, so the callback would have found it taken and a
    /// same-thread re-entry would have deadlocked on it.
    static RNG_STORE_LOCK_HELD: AtomicBool = AtomicBool::new(false);

    const RNG_TEST_CT: [u8; 8] = *b"haz15ct!";

    struct GateState {
        entered: bool,
        released: bool,
    }

    struct Gate {
        state: Mutex<GateState>,
        cv: Condvar,
    }

    impl Gate {
        const fn new() -> Self {
            Self {
                state: Mutex::new(GateState {
                    entered: false,
                    released: false,
                }),
                cv: Condvar::new(),
            }
        }

        fn lock(&self) -> MutexGuard<'_, GateState> {
            match self.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            }
        }

        fn reset(&self) {
            let mut state = self.lock();
            state.entered = false;
            state.released = false;
            self.cv.notify_all();
        }

        fn enter_and_wait(&self) {
            let mut state = self.lock();
            state.entered = true;
            self.cv.notify_all();
            while !state.released {
                state = match self.cv.wait(state) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
        }

        fn wait_entered(&self, limit: Duration) -> bool {
            let deadline = Instant::now() + limit;
            let mut state = self.lock();
            while !state.entered {
                let now = Instant::now();
                if now >= deadline {
                    return false;
                }
                state = match self.cv.wait_timeout(state, deadline - now) {
                    Ok((guard, _)) => guard,
                    Err(poisoned) => poisoned.into_inner().0,
                };
            }
            true
        }

        fn release(&self) {
            let mut state = self.lock();
            state.released = true;
            self.cv.notify_all();
        }
    }

    static RNG_GATE: Gate = Gate::new();
    static RNG_TEST_LOCK: Mutex<()> = Mutex::new(());
    static RNG_METHOD: OnceLock<crate::rand::rand_lib::RandMethod> = OnceLock::new();

    /// The default generator, called directly so a scripted invocation cannot recurse through the
    /// installed table.
    unsafe fn default_rng_bytes(buf: *mut c_uchar, num: c_int) -> c_int {
        let table = crate::rand::rand_lib::ossl_rand_meth();
        // SAFETY: `table` is the crate's live default method table.
        match unsafe { (*table).bytes } {
            // SAFETY: the callback is the default table's own and `buf` is the caller's contract.
            Some(callback) => unsafe { callback(buf, num) },
            None => 0,
        }
    }

    /// Record whether the store's lock is free while an application callback is running.
    ///
    /// A lock held by *this* thread never becomes available; a peer's brief hold does, so a
    /// bounded retry separates the defect from ordinary contention.
    fn note_store_lock_state() {
        for _ in 0..200 {
            if let Ok(guard) = EXT_KDK_STORE.try_lock() {
                drop(guard);
                return;
            }
            // Contention from a peer is transient; a lock this thread already holds is not.
            std::thread::sleep(Duration::from_millis(1));
        }
        RNG_STORE_LOCK_HELD.store(true, AtomicOrdering::SeqCst);
    }

    unsafe extern "C" fn scripted_bytes(buf: *mut c_uchar, num: c_int) -> c_int {
        let action = RNG_ACTION.with(Cell::get);
        let depth = RNG_DEPTH.with(Cell::get);
        if depth > 0 || action == RngAction::Delegate {
            // SAFETY: `buf` is the caller's contract, forwarded to the default generator.
            return unsafe { default_rng_bytes(buf, num) };
        }
        // One shot: a nested draw from the re-entered call is the default generator's.
        RNG_ACTION.with(|cell| cell.set(RngAction::Delegate));
        match action {
            RngAction::Delegate => {
                // SAFETY: `buf` is the caller's contract.
                unsafe { default_rng_bytes(buf, num) }
            }
            RngAction::Fail => 0,
            RngAction::DestroyTarget => {
                let target = RNG_SAME.with(Cell::get);
                // SAFETY: the test armed this address for exactly this callback, and the
                // object is live until this release; the enclosing frame reads no field of
                // it after the draw returns.
                unsafe { crate::rsa::object::RSA_free(target as *mut Rsa) };
                // SAFETY: `buf` is the caller's contract.
                unsafe { default_rng_bytes(buf, num) }
            }
            RngAction::Block => {
                RNG_GATE.enter_and_wait();
                // SAFETY: `buf` is the caller's contract.
                unsafe { default_rng_bytes(buf, num) }
            }
            RngAction::ReenterSame | RngAction::ReenterOther => {
                let target = if action == RngAction::ReenterSame {
                    RNG_SAME.with(Cell::get)
                } else {
                    RNG_OTHER.with(Cell::get)
                };
                note_store_lock_state();
                if action == RngAction::ReenterSame {
                    // The condition the refusal names: this thread already owns the reservation.
                    let variant_ok = matches!(
                        per_key_ext_kdk_secret(target as *mut Rsa),
                        Err(ExtKdkRefusal::ReentrantInitialization)
                    );
                    RNG_REENTRY_VARIANT_OK.with(|cell| cell.set(variant_ok));
                }
                RNG_DEPTH.with(|cell| cell.set(depth + 1));
                let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
                // SAFETY: `target` is a fixture owned by the test that armed the script and is
                // live for the whole re-entry; the ciphertext is this frame's fixed array.
                let result = unsafe {
                    derive_external_kdk(
                        target as *mut Rsa,
                        RNG_TEST_CT.as_ptr(),
                        RNG_TEST_CT.len() as c_int,
                        kdk.as_mut_ptr(),
                    )
                };
                RNG_DEPTH.with(|cell| cell.set(depth));
                RNG_REENTRY_RESULT.with(|cell| cell.set(result));
                // SAFETY: `buf` is the caller's contract.
                unsafe { default_rng_bytes(buf, num) }
            }
        }
    }

    fn arm_rng(action: RngAction, same: usize, other: usize) {
        RNG_ACTION.with(|cell| cell.set(action));
        RNG_SAME.with(|cell| cell.set(same));
        RNG_OTHER.with(|cell| cell.set(other));
        RNG_DEPTH.with(|cell| cell.set(0));
        RNG_REENTRY_RESULT.with(|cell| cell.set(c_int::MIN));
        RNG_REENTRY_VARIANT_OK.with(|cell| cell.set(false));
    }

    struct RngInstalled;

    impl Drop for RngInstalled {
        fn drop(&mut self) {
            // SAFETY: removes the table installed by `install_rng_script`; the default table is
            // restored and every later draw uses it.
            let _ = unsafe { crate::rand::rand_lib::RAND_set_rand_method(ptr::null()) };
        }
    }

    /// Install the scripted method for the duration of one test, serialising those tests.
    fn install_rng_script() -> (MutexGuard<'static, ()>, RngInstalled) {
        let serial = match RNG_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let table = RNG_METHOD.get_or_init(|| {
            let default = crate::rand::rand_lib::ossl_rand_meth();
            // SAFETY: `default` is the crate's live default method table; only `bytes` is
            // replaced, and every other callback keeps the default generator's behaviour.
            unsafe {
                crate::rand::rand_lib::RandMethod {
                    seed: (*default).seed,
                    bytes: Some(scripted_bytes),
                    cleanup: (*default).cleanup,
                    add: (*default).add,
                    pseudorand: (*default).pseudorand,
                    status: (*default).status,
                }
            }
        });
        assert_eq!(
            // SAFETY: `table` lives for the process and every thread that did not arm a script
            // delegates to the default generator.
            unsafe { crate::rand::rand_lib::RAND_set_rand_method(table as *const _) },
            1
        );
        RNG_STORE_LOCK_HELD.store(false, AtomicOrdering::SeqCst);
        (serial, RngInstalled)
    }

    fn wait_for_waiter(limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if ext_kdk_waiter_count() > 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        ext_kdk_waiter_count() > 0
    }

    /// A WaitTimeout for a `recv_timeout` is a test failure; a hung worker must not hang the
    /// suite.
    #[allow(clippy::panic)] // the message is the failure of a bounded wait, not a panic path
    fn receive<T>(receiver: &mpsc::Receiver<T>, message: &str) -> T {
        match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(value) => value,
            Err(_) => panic!("{message}"),
        }
    }

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

    /// `rsa_ossl_finish` clears every slot it releases, so calling it twice is a no-op rather
    /// than a second release of freed storage. `RSA_set_method` invokes it on every method
    /// transition, so the dangling-pointer state the authority leaves behind would be reachable
    /// through a second `RSA_set_method` (or the next private operation's cache lookup).
    #[test]
    fn the_finish_hook_clears_every_slot_it_releases() {
        // SAFETY: every object is created and released here; the hook takes only the object.
        unsafe {
            let mut rsa = super::super::mp::zeroed_rsa();
            let mont = crate::bn::mont::BN_MONT_CTX_new();
            assert!(!mont.is_null());
            rsa._method_mod_n = mont;

            assert_eq!(rsa_ossl_finish(&mut rsa), 1);
            assert!(rsa._method_mod_n.is_null());
            // The negative control: before the repair this second call released the same block.
            assert_eq!(rsa_ossl_finish(&mut rsa), 1);
        }
    }

    /// **A method transition empties the blinding store.**
    ///
    /// Every stored `BN_BLINDING` borrows `rsa->_method_mod_n` as its `m_ctx`
    /// (`RSA_setup_blinding` hands that context to `BN_BLINDING_create_param`), and
    /// `RSA_set_method` runs `rsa_ossl_finish`, which releases it. A blinding that survived the
    /// transition would hand the next private operation a released pointer. The lookup is the
    /// observable: before the fix it still answered the old blinding after the transition.
    #[test]
    fn a_method_transition_drops_blindings_that_borrow_the_released_cache() {
        use crate::evp::pkey_ctx::RSA_NO_PADDING;
        use crate::rsa::gen::RSA_generate_key_ex;
        use crate::rsa::object::{
            RSA_free, RSA_new, RSA_private_encrypt, RSA_set_method, RSA_size,
        };

        // SAFETY: every object is created and released here, and every buffer is its own length.
        unsafe {
            let e = BN_new();
            assert!(!e.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);
            let rsa = RSA_new();
            assert!(!rsa.is_null());
            assert_eq!(RSA_generate_key_ex(rsa, 1024, e, ptr::null_mut()), 1);

            let n = RSA_size(rsa) as usize;
            let mut pt = vec![0u8; n];
            pt[n - 1] = 0x42;
            let mut ct = vec![0u8; n];
            assert_eq!(
                RSA_private_encrypt(
                    n as c_int,
                    pt.as_ptr(),
                    ct.as_mut_ptr(),
                    rsa,
                    RSA_NO_PADDING
                ),
                n as c_int
            );
            assert!(
                !ossl_rsa_get_thread_bn_blinding(rsa).is_null(),
                "the private operation left a per-thread blinding"
            );

            assert_eq!(RSA_set_method(rsa, RSA_PKCS1_OpenSSL()), 1);
            assert!(
                ossl_rsa_get_thread_bn_blinding(rsa).is_null(),
                "a blinding must not outlive the cache it borrows as `m_ctx`"
            );

            // The next operation draws a fresh blinding and still answers `m^d mod n`.
            let mut ct2 = vec![0u8; n];
            assert_eq!(
                RSA_private_encrypt(
                    n as c_int,
                    pt.as_ptr(),
                    ct2.as_mut_ptr(),
                    rsa,
                    RSA_NO_PADDING
                ),
                n as c_int
            );
            assert_eq!(ct, ct2, "the fresh blinding cancels to the same value");

            RSA_free(rsa);
            BN_free(e);
        }
    }

    /// **The smooth and slow CRT arms agree, with and without blinding, and the tail's public
    /// verification accepts both.**
    ///
    /// The default method and equal-width primes select the `smooth` arm; clearing
    /// `RSA_FLAG_CACHE_PRIVATE` skips the cache arm so `smooth` stays 0 and the generic
    /// per-prime exponentiation and combine run. The raw result is deterministic, so all three
    /// paths must answer the same octets, and re-exponentiating with the public exponent must
    /// recover the message. This pins the two arms' value parity; the distinct T6 gate (the
    /// `smooth` test before the generic combine) is what stops the smooth result being
    /// overwritten, which no value comparison can see because the tail verification falls back
    /// to the unblinded exponentiation when it is.
    #[test]
    fn the_smooth_and_slow_crt_arms_agree_and_the_blinding_cancels() {
        use crate::evp::pkey_ctx::RSA_NO_PADDING;
        use crate::rsa::gen::RSA_generate_key_ex;
        use crate::rsa::object::{
            RSA_free, RSA_new, RSA_private_encrypt, RSA_public_decrypt, RSA_size,
        };

        // SAFETY: every object is created and released here, and every buffer is its own length.
        unsafe {
            let e = BN_new();
            assert!(!e.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);
            let rsa = RSA_new();
            assert!(!rsa.is_null());
            assert_eq!(RSA_generate_key_ex(rsa, 1024, e, ptr::null_mut()), 1);

            let n = RSA_size(rsa) as usize;
            let mut pt = vec![0u8; n];
            pt[n - 1] = 0x42;

            // Smooth arm with the object's blinding.
            let mut ct_blinded = vec![0u8; n];
            assert_eq!(
                RSA_private_encrypt(
                    n as c_int,
                    pt.as_ptr(),
                    ct_blinded.as_mut_ptr(),
                    rsa,
                    RSA_NO_PADDING
                ),
                n as c_int
            );

            // Smooth arm unblinded: the blinding must cancel to the same value.
            (*rsa).flags |= RSA_FLAG_NO_BLINDING;
            let mut ct_smooth = vec![0u8; n];
            assert_eq!(
                RSA_private_encrypt(
                    n as c_int,
                    pt.as_ptr(),
                    ct_smooth.as_mut_ptr(),
                    rsa,
                    RSA_NO_PADDING
                ),
                n as c_int
            );
            assert_eq!(ct_blinded, ct_smooth, "blinding cancels");

            // Slow arm: no private cache arm, so `smooth` stays 0.
            (*rsa).flags &= !RSA_FLAG_CACHE_PRIVATE;
            let mut ct_slow = vec![0u8; n];
            assert_eq!(
                RSA_private_encrypt(
                    n as c_int,
                    pt.as_ptr(),
                    ct_slow.as_mut_ptr(),
                    rsa,
                    RSA_NO_PADDING
                ),
                n as c_int
            );
            assert_eq!(ct_smooth, ct_slow, "smooth and slow CRT arms agree");

            // Public reference: ct^e == m mod n.
            let mut back = vec![0u8; n];
            assert_eq!(
                RSA_public_decrypt(
                    n as c_int,
                    ct_slow.as_ptr(),
                    back.as_mut_ptr(),
                    rsa,
                    RSA_NO_PADDING
                ),
                n as c_int
            );
            assert_eq!(&back[..], &pt[..], "the CRT result is m^d mod n");

            RSA_free(rsa);
            BN_free(e);
        }
    }

    /// **A normal private operation with blinding on never takes the CRT tail's congruence
    /// fallback.**
    ///
    /// T6 found the smooth arm's result being overwritten because the transcription was missing
    /// the authority's `goto tail`: every private operation then silently fell back to the raw
    /// unblinded `d` exponentiation. The existing value-parity test cannot see that because the
    /// fallback returns the same answer. This test observes the fallback itself through the
    /// test-only `TAIL_FALLBACK_COUNT` (see its comment) with blinding left **on**, which is the
    /// lifecycle the ctgrind case deliberately removes with `RSA_FLAG_NO_BLINDING`.
    ///
    /// The negative control corrupts `dmp1` by one limb-value so the per-prime result is
    /// genuinely non-congruent: the tail must then take the fallback (the counter fires), repair
    /// the answer through `d`, and still return `m^d mod n`. That is both the documented recovery
    /// behaviour and the proof that the observation point can observe.
    #[test]
    fn a_blinded_private_operation_does_not_take_the_crt_tail_fallback() {
        use crate::bn::bignum::{BN_dup, BN_free as BN_release};
        use crate::evp::pkey_ctx::RSA_NO_PADDING;
        use crate::rsa::gen::RSA_generate_key_ex;
        use crate::rsa::object::{
            RSA_free, RSA_new, RSA_private_encrypt, RSA_public_decrypt, RSA_size,
        };

        // SAFETY: every object is created and released here, every buffer is its own length, and
        // `dmp1` is restored before the object is released.
        unsafe {
            let e = BN_new();
            assert!(!e.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);
            let rsa = RSA_new();
            assert!(!rsa.is_null());
            assert_eq!(RSA_generate_key_ex(rsa, 1024, e, ptr::null_mut()), 1);

            assert_eq!(
                (*rsa).flags & RSA_FLAG_NO_BLINDING,
                0,
                "blinding is on by default"
            );

            let n = RSA_size(rsa) as usize;
            let mut pt = vec![0u8; n];
            pt[n - 1] = 0x42;

            // The real lifecycle: blinding on, a fresh per-thread blinding created lazily, the
            // CRT path taken and the tail verification satisfied. The fallback must not run.
            TAIL_FALLBACK_COUNT.store(0, Ordering::Relaxed);
            let mut ct = vec![0u8; n];
            assert_eq!(
                RSA_private_encrypt(
                    n as c_int,
                    pt.as_ptr(),
                    ct.as_mut_ptr(),
                    rsa,
                    RSA_NO_PADDING
                ),
                n as c_int
            );
            assert!(
                !ossl_rsa_get_thread_bn_blinding(rsa).is_null(),
                "the operation ran with a blinding"
            );
            assert_eq!(
                TAIL_FALLBACK_COUNT.load(Ordering::Relaxed),
                0,
                "a valid CRT operation must not fall back to the raw `d` exponentiation"
            );

            // Negative control: break the per-prime exponent so the CRT answer is wrong, and
            // confirm the fallback is reachable and repairs the result.
            let saved_dmp1 = (*rsa).dmp1;
            let wrong = BN_dup(saved_dmp1);
            assert!(!wrong.is_null());
            assert_eq!(crate::bn::arith::BN_add_word(wrong, 1), 1);
            (*rsa).dmp1 = wrong;

            TAIL_FALLBACK_COUNT.store(0, Ordering::Relaxed);
            let mut ct_bad = vec![0u8; n];
            assert_eq!(
                RSA_private_encrypt(
                    n as c_int,
                    pt.as_ptr(),
                    ct_bad.as_mut_ptr(),
                    rsa,
                    RSA_NO_PADDING
                ),
                n as c_int
            );
            assert!(
                TAIL_FALLBACK_COUNT.load(Ordering::Relaxed) > 0,
                "a corrupted CRT result takes the raw-`d` fallback"
            );
            let mut back = vec![0u8; n];
            assert_eq!(
                RSA_public_decrypt(
                    n as c_int,
                    ct_bad.as_ptr(),
                    back.as_mut_ptr(),
                    rsa,
                    RSA_NO_PADDING
                ),
                n as c_int
            );
            assert_eq!(&back[..], &pt[..], "the fallback returns m^d mod n anyway");

            (*rsa).dmp1 = saved_dmp1;
            BN_release(wrong);
            RSA_free(rsa);
            BN_free(e);
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

    /// A ciphertext whose raw decryption is `block`: `block^e mod n` for `rsa`'s public key.
    ///
    /// # Safety
    /// `rsa` is live and holds `n` and `e`; `block` is no longer than the modulus.
    #[cfg(test)]
    unsafe fn ciphertext_for_block(rsa: *mut Rsa, block: &[u8]) -> Vec<u8> {
        use crate::bn::arith::BN_mod_exp;
        use crate::rsa::object::{RSA_get0_key, RSA_size};

        // SAFETY: the caller's contract, forwarded; `n` and `e` are borrowed from `rsa` for the
        // length of this call and every buffer is its own length.
        unsafe {
            let (mut n, mut e): (*const BigNum, *const BigNum) = (ptr::null(), ptr::null());
            RSA_get0_key(rsa, &mut n, &mut e, ptr::null_mut());
            let num = RSA_size(rsa) as usize;
            let ctx = BN_CTX_new_ex(ptr::null_mut());
            let m = BN_bin2bn(block.as_ptr(), block.len() as c_int, ptr::null_mut());
            let c = BN_new();
            let mut out = vec![0u8; num];
            assert!(!ctx.is_null() && !m.is_null() && !c.is_null());
            assert_eq!(BN_mod_exp(c, m, e, n, ctx), 1);
            assert_eq!(
                BN_bn2binpad(c, out.as_mut_ptr(), num as c_int),
                num as c_int
            );
            BN_free(m);
            BN_free(c);
            BN_CTX_free(ctx);
            out
        }
    }

    /// **An external key's PKCS#1 v1.5 decryption does not answer a padding verdict.**
    ///
    /// A key with `RSA_FLAG_EXT_PKEY` and no private exponent takes the same implicit-rejection
    /// arm as an internal key: a valid block and an invalid block both answer a positive length,
    /// both write bytes to the output buffer, and both leave the error queue empty. The synthetic
    /// answer is deterministic for one ciphertext, which is what keeps a repeated query from
    /// distinguishing it from a real message.
    ///
    /// This fails on the authority's behaviour: the invalid block answers `-1`, leaves the output
    /// buffer untouched and raises `RSA_R_PADDING_CHECK_FAILED`, which is the HAZ-15 oracle.
    #[test]
    fn external_key_pkcs1_decryption_does_not_distinguish_padding() {
        use crate::bn::bignum::BN_dup;
        use crate::rsa::gen::RSA_generate_key_ex;
        use crate::rsa::object::{
            RSA_free, RSA_get0_crt_params, RSA_get0_factors, RSA_get0_key, RSA_new,
            RSA_private_decrypt, RSA_set0_crt_params, RSA_set0_factors, RSA_set0_key,
            RSA_set_flags, RSA_size,
        };
        use crate::rsa::RSA_padding_add_PKCS1_type_2;
        use crate::runtime::err::{ERR_clear_error, ERR_peek_error};

        const MSG: &[u8] = b"HAZ15VAL";

        // SAFETY: every object and buffer is created and released here; the pointers borrowed
        // from `full` live until the copy has been made.
        unsafe {
            let e = BN_new();
            assert_eq!(BN_set_word(e, 65537), 1);
            let full = RSA_new();
            assert!(RSA_generate_key_ex(full, 1024, e, ptr::null_mut()) == 1);

            let (mut n, mut ee, mut _d) = (ptr::null(), ptr::null(), ptr::null());
            RSA_get0_key(full, &mut n, &mut ee, &mut _d);
            let (mut p, mut q) = (ptr::null(), ptr::null());
            RSA_get0_factors(full, &mut p, &mut q);
            let (mut dmp1, mut dmq1, mut iqmp) = (ptr::null(), ptr::null(), ptr::null());
            RSA_get0_crt_params(full, &mut dmp1, &mut dmq1, &mut iqmp);

            let ext = RSA_new();
            assert_eq!(RSA_set0_key(ext, BN_dup(n), BN_dup(ee), ptr::null_mut()), 1);
            assert_eq!(RSA_set0_factors(ext, BN_dup(p), BN_dup(q)), 1);
            assert_eq!(
                RSA_set0_crt_params(ext, BN_dup(dmp1), BN_dup(dmq1), BN_dup(iqmp)),
                1
            );
            RSA_set_flags(ext, RSA_FLAG_EXT_PKEY);
            assert!(
                (*ext).d.is_null(),
                "the external shape holds no private exponent"
            );

            let num = RSA_size(ext) as usize;
            let mut good_block = vec![0u8; num];
            assert_eq!(
                RSA_padding_add_PKCS1_type_2(
                    good_block.as_mut_ptr(),
                    num as c_int,
                    MSG.as_ptr(),
                    MSG.len() as c_int
                ),
                1
            );

            let good_ct = ciphertext_for_block(ext, &good_block);
            let mut out_good = vec![0xAAu8; num];
            ERR_clear_error();
            let r_good = RSA_private_decrypt(
                num as c_int,
                good_ct.as_ptr(),
                out_good.as_mut_ptr(),
                ext,
                RSA_PKCS1_PADDING,
            );
            assert_eq!(
                r_good,
                MSG.len() as c_int,
                "a valid block yields its message"
            );
            assert_eq!(&out_good[..MSG.len()], MSG);
            assert_eq!(ERR_peek_error(), 0);

            // Wrong block type: invalid padding.
            let mut bad_block = good_block.clone();
            bad_block[1] = 0x03;
            let bad_ct = ciphertext_for_block(ext, &bad_block);
            let mut out_bad = vec![0xAAu8; num];
            ERR_clear_error();
            let r_bad = RSA_private_decrypt(
                num as c_int,
                bad_ct.as_ptr(),
                out_bad.as_mut_ptr(),
                ext,
                RSA_PKCS1_PADDING,
            );
            assert!(
                r_bad > 0,
                "an invalid block answers a synthetic message, not -1"
            );
            assert_ne!(
                out_bad,
                vec![0xAAu8; num],
                "the synthetic message is written"
            );
            assert_eq!(
                ERR_peek_error(),
                0,
                "no error is left for the caller to see"
            );

            // The padding string below the eight-octet minimum is the length refusal inside the
            // check; it must take the same synthetic arm.
            let mut short_block = vec![0u8; num];
            short_block[0] = 0x00;
            short_block[1] = 0x02;
            for byte in short_block.iter_mut().take(7).skip(2) {
                *byte = 0x11;
            }
            short_block[7] = 0x00;
            for byte in short_block.iter_mut().skip(8) {
                *byte = 0x22;
            }
            let short_ct = ciphertext_for_block(ext, &short_block);
            let mut out_short = vec![0xAAu8; num];
            ERR_clear_error();
            let r_short = RSA_private_decrypt(
                num as c_int,
                short_ct.as_ptr(),
                out_short.as_mut_ptr(),
                ext,
                RSA_PKCS1_PADDING,
            );
            assert!(
                r_short > 0,
                "a short padding string is answered, not refused"
            );
            assert_eq!(ERR_peek_error(), 0);

            // Determinism: the same ciphertext answers the same bytes, so a repeated query is
            // not a distinguisher.
            let mut out_repeat = vec![0xAAu8; num];
            assert_eq!(
                RSA_private_decrypt(
                    num as c_int,
                    bad_ct.as_ptr(),
                    out_repeat.as_mut_ptr(),
                    ext,
                    RSA_PKCS1_PADDING,
                ),
                r_bad
            );
            assert_eq!(out_repeat, out_bad);

            RSA_free(ext);
            RSA_free(full);
            BN_free(e);
        }
    }

    /// Build an external-shape copy of `full`: `n`, `e`, `p`, `q`, `dmp1`, `dmq1`, `iqmp`, no
    /// `d`, and `RSA_FLAG_EXT_PKEY`. Used by the tests that need the shape with private CRT
    /// material but no private exponent.
    ///
    /// # Safety
    /// `full` is a live `RSA` holding a complete key.
    #[cfg(test)]
    unsafe fn external_shape_with_crt(full: *mut Rsa) -> *mut Rsa {
        use crate::bn::bignum::BN_dup;
        use crate::rsa::object::{
            RSA_get0_crt_params, RSA_get0_factors, RSA_get0_key, RSA_new, RSA_set0_crt_params,
            RSA_set0_factors, RSA_set0_key, RSA_set_flags, RSA_size,
        };

        // SAFETY: `full` is live; every borrowed pointer lives until the duplicate is made.
        unsafe {
            let (mut n, mut e, mut _d) = (ptr::null(), ptr::null(), ptr::null());
            RSA_get0_key(full, &mut n, &mut e, &mut _d);
            let (mut p, mut q) = (ptr::null(), ptr::null());
            RSA_get0_factors(full, &mut p, &mut q);
            let (mut dmp1, mut dmq1, mut iqmp) = (ptr::null(), ptr::null(), ptr::null());
            RSA_get0_crt_params(full, &mut dmp1, &mut dmq1, &mut iqmp);

            let ext = RSA_new();
            assert!(!ext.is_null());
            assert_eq!(RSA_set0_key(ext, BN_dup(n), BN_dup(e), ptr::null_mut()), 1);
            assert_eq!(RSA_set0_factors(ext, BN_dup(p), BN_dup(q)), 1);
            assert_eq!(
                RSA_set0_crt_params(ext, BN_dup(dmp1), BN_dup(dmq1), BN_dup(iqmp)),
                1
            );
            RSA_set_flags(ext, RSA_FLAG_EXT_PKEY);
            assert!(
                (*ext).d.is_null(),
                "the external shape holds no private exponent"
            );
            assert!(RSA_size(ext) > 0);
            ext
        }
    }

    /// **The synthetic answer is not the withdrawn attacker-computable construction.**
    ///
    /// For an attacker-chosen block `m` with deliberately invalid padding, the attacker forms
    /// `c = m^e mod n` and knows `m`. The withdrawn revision keyed the PRF with `SHA-256(m)`, so
    /// the returned message was exactly `ossl_rsa_padding_check_PKCS1_type_2(..., SHA-256(m))`.
    /// This test computes that prediction from public data and requires the candidate not to
    /// return it. On the withdrawn construction the two agree and the test fails.
    ///
    /// It also pins the two properties the implicit rejection still needs: the answer is
    /// deterministic for one ciphertext, and a second query of the same ciphertext returns the
    /// same bytes.
    #[test]
    fn the_external_synthetic_answer_is_not_attacker_computable() {
        use crate::rsa::gen::RSA_generate_key_ex;
        use crate::rsa::object::{RSA_free, RSA_new, RSA_private_decrypt, RSA_size};
        use crate::runtime::err::{ERR_clear_error, ERR_peek_error};

        // SAFETY: every object and buffer is created and released here.
        unsafe {
            let e = BN_new();
            assert_eq!(BN_set_word(e, 65537), 1);
            let full = RSA_new();
            assert_eq!(RSA_generate_key_ex(full, 1024, e, ptr::null_mut()), 1);
            let ext = external_shape_with_crt(full);
            let num = RSA_size(ext) as usize;

            // A block the attacker chose, with the wrong block type: invalid padding.
            let mut block = vec![0u8; num];
            block[0] = 0x00;
            block[1] = 0x03;
            for byte in block.iter_mut().skip(2) {
                *byte = 0x5a;
            }
            let ct = ciphertext_for_block(ext, &block);

            let mut out_a = vec![0u8; num];
            ERR_clear_error();
            let r_a = RSA_private_decrypt(
                num as c_int,
                ct.as_ptr(),
                out_a.as_mut_ptr(),
                ext,
                RSA_PKCS1_PADDING,
            );
            assert!(r_a > 0);
            assert_eq!(ERR_peek_error(), 0);

            // Deterministic for one ciphertext and one key.
            let mut out_b = vec![0u8; num];
            assert_eq!(
                RSA_private_decrypt(
                    num as c_int,
                    ct.as_ptr(),
                    out_b.as_mut_ptr(),
                    ext,
                    RSA_PKCS1_PADDING,
                ),
                r_a
            );
            assert_eq!(out_a[..r_a as usize], out_b[..r_a as usize]);

            // The withdrawn prediction: the padding check keyed by SHA-256 of the block the
            // attacker knows, over the same decrypted block.
            let mut old_kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
            SHA256(block.as_ptr(), num, old_kdk.as_mut_ptr());
            let mut old_out = vec![0u8; num];
            let old_ret = ossl_rsa_padding_check_PKCS1_type_2(
                ptr::null_mut(),
                old_out.as_mut_ptr(),
                num as c_int,
                block.as_ptr(),
                num as c_int,
                num as c_int,
                old_kdk.as_mut_ptr(),
            );
            assert!(old_ret > 0, "the attacker computes a synthetic message");
            let common = (r_a as usize).min(old_ret as usize);
            assert!(
                r_a != old_ret || out_a[..common] != old_out[..common],
                "the returned message must not be the SHA-256(block)-keyed synthetic one"
            );

            RSA_free(ext);
            RSA_free(full);
            BN_free(e);
        }
    }

    /// **The per-object secret path for a key with no private material.**
    ///
    /// A public-only `(n, e)` object has nothing private to derive from. The first use draws a
    /// 32-byte secret, the second use of the same object answers the same KDK, the KDK is not
    /// `SHA-256(ciphertext)`, a second object with the same public material answers a different
    /// KDK (the recorded residual), and releasing the object's entry makes the next draw fresh.
    /// An allocation failure at the secret's allocation answers the defined refusal, not a
    /// fallback: `derive_external_kdk` returns 0.
    #[test]
    fn the_public_only_key_gets_a_secret_that_is_not_the_public_hash() {
        // SAFETY: every BIGNUM is created and released here; the objects are stack fixtures whose
        // side-table entries are explicitly released with `forget_ext_kdk_secret`.
        unsafe {
            let mut first = super::super::mp::zeroed_rsa();
            let mut second = super::super::mp::zeroed_rsa();
            assert!(first.p.is_null() && first.q.is_null());
            assert!(second.p.is_null() && second.q.is_null());

            let ct = [0x11u8, 0x22, 0x33, 0x44];
            let mut kdk_a = [0u8; SHA256_DIGEST_LENGTH as usize];
            let mut kdk_b = [0u8; SHA256_DIGEST_LENGTH as usize];
            let mut kdk_c = [0u8; SHA256_DIGEST_LENGTH as usize];

            assert_eq!(
                derive_external_kdk(
                    &mut first,
                    ct.as_ptr(),
                    ct.len() as c_int,
                    kdk_a.as_mut_ptr()
                ),
                1
            );
            assert_eq!(
                derive_external_kdk(
                    &mut first,
                    ct.as_ptr(),
                    ct.len() as c_int,
                    kdk_b.as_mut_ptr()
                ),
                1
            );
            assert_eq!(kdk_a, kdk_b, "one object, one ciphertext: one KDK");

            let mut public_hash = [0u8; SHA256_DIGEST_LENGTH as usize];
            SHA256(ct.as_ptr(), ct.len(), public_hash.as_mut_ptr());
            assert_ne!(kdk_a, public_hash, "the KDK is not a hash of public data");

            assert_eq!(
                derive_external_kdk(
                    &mut second,
                    ct.as_ptr(),
                    ct.len() as c_int,
                    kdk_c.as_mut_ptr()
                ),
                1
            );
            assert_ne!(
                kdk_a, kdk_c,
                "two public-only objects hold independent per-object secrets"
            );

            // Releasing the entry wipes it; a later use of the same object starts again.
            forget_ext_kdk_secret(&mut first);
            let mut kdk_d = [0u8; SHA256_DIGEST_LENGTH as usize];
            assert_eq!(
                derive_external_kdk(
                    &mut first,
                    ct.as_ptr(),
                    ct.len() as c_int,
                    kdk_d.as_mut_ptr()
                ),
                1
            );
            assert_ne!(kdk_a, kdk_d, "the released secret is not reused");

            // An allocation failure in the secret's allocation is the defined refusal. A fresh
            // object is used so the draw (not a copy of an existing entry) is the step that runs.
            let mut third = super::super::mp::zeroed_rsa();
            let mut kdk_failed = [0u8; SHA256_DIGEST_LENGTH as usize];
            let guard = crate::runtime::alloc::test_fail::fail_after(0);
            let refused = derive_external_kdk(
                &mut third,
                ct.as_ptr(),
                ct.len() as c_int,
                kdk_failed.as_mut_ptr(),
            );
            drop(guard);
            assert_eq!(
                refused, 0,
                "allocation failure is a refusal, not a fallback"
            );
            assert_eq!(
                refused, 0,
                "allocation failure is a refusal, not a fallback"
            );

            forget_ext_kdk_secret(&mut first);
            forget_ext_kdk_secret(&mut third);
            forget_ext_kdk_secret(&mut second);
        }
    }

    /// One hex field of the pinned 2048-bit RSA vector, read from the tracked JSON.
    ///
    /// The population below must be reproducible, so it uses the same fixed key as the
    /// differential harness (`forensics/etp5_crypto/vectors/rsa_key.json`) rather than a key
    /// generated anew on each run.
    #[cfg(test)]
    #[allow(clippy::expect_used, clippy::panic)] // a test fixture: a malformed tracked vector must fail the test
    fn pinned_vector_hex(field: &str) -> String {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/forensics/etp5_crypto/vectors/rsa_key.json"
        );
        let text = std::fs::read_to_string(path).expect("the pinned RSA vector must be readable");
        let needle = format!("\"{field}\": \"");
        let start = text
            .find(&needle)
            .unwrap_or_else(|| panic!("field {field} absent from the pinned vector"))
            + needle.len();
        let rest = &text[start..];
        let end = rest.find('"').expect("unterminated hex string");
        rest[..end].to_string()
    }

    /// A `BIGNUM` from a hex string; the caller owns the result.
    ///
    /// # Safety
    /// Takes no pointers; the returned value is released with `BN_free`.
    #[cfg(test)]
    unsafe fn bn_from_hex(hex: &str) -> *mut BigNum {
        use crate::bn::bignum::BN_hex2bn;
        use crate::runtime::mem::CRYPTO_free;

        let c = crate::bn::bignum::dup_cstring(hex);
        let mut p: *mut BigNum = ptr::null_mut();
        // SAFETY: `p` is this frame's slot and `c` is NUL-terminated and live.
        unsafe {
            assert!(BN_hex2bn(&mut p, c) > 0);
            CRYPTO_free(c.cast(), ptr::null(), 0);
        }
        p
    }

    /// **The returned length is observable and it distinguishes the two classes — measured, not
    /// illustrated.**
    ///
    /// A valid block answers its message length; an invalid block answers the implicit
    /// rejection's synthetic length. The synthetic length is selected from 128 candidates reduced
    /// to the range `0 ..= num - 11`, so each invalid block answers one value in that range with
    /// probability close to `1 / 2^k` for the range's power-of-two width — not zero. The earlier
    /// 64-block sample's "no collision with a valid length" was therefore a statement about a
    /// sample, not a bound. This test extends the population to thousands of attacker-chosen
    /// blocks on the fixed 2048-bit key the differential harness uses, records the complete
    /// empirical distribution, and reports the match count for each protocol-relevant length.
    ///
    /// An invalid block may answer `0` (the synthetic length is allowed to be zero), which an
    /// application that tests only `ret > 0` would read as a failure; the population records it
    /// rather than asserting it away. Every call leaves the error queue empty.
    ///
    /// If the distributions overlap, that is a finding, not a pass; it is recorded in
    /// `evidence/haz-15/REENTRANCY-AND-LENGTH.md`.
    #[test]
    fn the_external_length_channel_is_measured() {
        use crate::rsa::object::{
            RSA_free, RSA_new, RSA_private_decrypt, RSA_set0_crt_params, RSA_set0_factors,
            RSA_set0_key, RSA_set_flags, RSA_size,
        };
        use crate::rsa::RSA_padding_add_PKCS1_type_2;
        use crate::runtime::err::{ERR_clear_error, ERR_peek_error};

        /// The synthetic length is the last of 128 candidates below `num - 10`; the population is
        /// large enough that a per-value probability near `1/256` is visible, while keeping the
        /// test's wall time within the gate's budget.
        const INVALID_SAMPLES: usize = 2048;

        // SAFETY: every object and buffer is created and released here; the pinned key's
        // components are owned by `ext` after the `set0` calls.
        unsafe {
            let ext = RSA_new();
            assert!(!ext.is_null());
            assert_eq!(
                RSA_set0_key(
                    ext,
                    bn_from_hex(&pinned_vector_hex("n")),
                    bn_from_hex("010001"),
                    ptr::null_mut()
                ),
                1
            );
            assert_eq!(
                RSA_set0_factors(
                    ext,
                    bn_from_hex(&pinned_vector_hex("p")),
                    bn_from_hex(&pinned_vector_hex("q"))
                ),
                1
            );
            assert_eq!(
                RSA_set0_crt_params(
                    ext,
                    bn_from_hex(&pinned_vector_hex("dmp1")),
                    bn_from_hex(&pinned_vector_hex("dmq1")),
                    bn_from_hex(&pinned_vector_hex("iqmp"))
                ),
                1
            );
            RSA_set_flags(ext, RSA_FLAG_EXT_PKEY);
            assert!((*ext).d.is_null());
            let num = RSA_size(ext) as usize;
            assert_eq!(num, 256, "the pinned vector is 2048-bit");

            let mut valid_lengths = Vec::new();
            for msg_len in [8usize, 16, 32, 48] {
                let msg = vec![0x42u8; msg_len];
                let mut block = vec![0u8; num];
                assert_eq!(
                    RSA_padding_add_PKCS1_type_2(
                        block.as_mut_ptr(),
                        num as c_int,
                        msg.as_ptr(),
                        msg_len as c_int
                    ),
                    1
                );
                let ct = ciphertext_for_block(ext, &block);
                let mut out = vec![0u8; num];
                ERR_clear_error();
                let ret = RSA_private_decrypt(
                    num as c_int,
                    ct.as_ptr(),
                    out.as_mut_ptr(),
                    ext,
                    RSA_PKCS1_PADDING,
                );
                assert_eq!(ret, msg_len as c_int, "a valid block answers its length");
                assert_eq!(&out[..msg_len], &msg[..]);
                assert_eq!(ERR_peek_error(), 0);
                valid_lengths.push(ret);
            }

            // Thousands of distinct invalid blocks: wrong type, a short padding string, no
            // separator, and a block that does not start with 00. Every one is attacker-chosen
            // and fully known; the body comes from a fixed PRNG so the population is
            // reproducible and the ciphertexts are distinct.
            let mut histogram = vec![0usize; 256];
            let mut invalid_lengths = Vec::with_capacity(INVALID_SAMPLES);
            for i in 0..INVALID_SAMPLES {
                let mut block = vec![0u8; num];
                let mut state =
                    0x9e37_79b9_7f4a_7c15u64 ^ (i as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                for byte in block.iter_mut() {
                    let value = splitmix64(&mut state) as u8;
                    *byte = if value == 0 { 1 } else { value };
                }
                match i % 4 {
                    0 => {
                        // Wrong block type.
                        block[0] = 0x00;
                        block[1] = 0x03;
                    }
                    1 => {
                        // Padding string shorter than eight octets: the first zero is at 6.
                        block[0] = 0x00;
                        block[1] = 0x02;
                        block[6] = 0x00;
                    }
                    2 => {
                        // No separator at all: every body octet is non-zero.
                        block[0] = 0x00;
                        block[1] = 0x02;
                    }
                    _ => {
                        // Does not start with a zero octet.
                        block[0] = 0x01;
                        block[1] = 0x02;
                    }
                }
                let ct = ciphertext_for_block(ext, &block);
                let mut out = vec![0u8; num];
                ERR_clear_error();
                let ret = RSA_private_decrypt(
                    num as c_int,
                    ct.as_ptr(),
                    out.as_mut_ptr(),
                    ext,
                    RSA_PKCS1_PADDING,
                );
                assert!(
                    ret >= 0,
                    "invalid block {i} must not be refused: the whole point is a defined answer"
                );
                assert_eq!(ERR_peek_error(), 0, "invalid block {i} leaves no error");
                histogram[ret as usize] += 1;
                invalid_lengths.push(ret);
            }

            let mut distinct = invalid_lengths.clone();
            distinct.sort_unstable();
            distinct.dedup();
            let minimum = *distinct.first().unwrap_or(&0);
            let maximum = *distinct.last().unwrap_or(&0);
            // 8 and the valid-case message lengths, then the authority's internal-key synthetic
            // lengths (`observables.json`: 244 for bad_type, 107 for short_ps) and the
            // candidate's external synthetic lengths (189, 180).
            let expected: [usize; 8] = [8, 16, 32, 48, 107, 180, 189, 244];
            let matches: Vec<(usize, usize)> = expected
                .iter()
                .map(|&length| (length, histogram[length]))
                .collect();
            println!(
                "HAZ15POP samples={INVALID_SAMPLES} valid={valid_lengths:?} distinct={} \
                 min={minimum} max={maximum} matches={matches:?} histogram={:?}",
                distinct.len(),
                &histogram[..num - 10],
            );

            // The synthetic range is `0 .. num - 10`; anything above it would mean the wrong
            // check ran.
            assert!(invalid_lengths
                .iter()
                .all(|&length| length >= 0 && (length as usize) < num - 10));
            // The population covers the range rather than a constant.
            assert!(
                distinct.len() >= 230,
                "the synthetic population must cover the range: distinct={}",
                distinct.len()
            );
            // The earlier 64-sample zero was not a bound: with thousands of samples, at least one
            // expected length is matched. The TLS pre-master length (48) is the decisive one.
            assert!(
                matches.iter().any(|&(_, count)| count > 0),
                "the synthetic lengths must collide with an expected length over this population"
            );
            assert!(
                histogram[48] > 0,
                "the 48-byte TLS pre-master length must be reachable by the synthetic length"
            );

            RSA_free(ext);
        }
    }

    /// SplitMix64: a fixed, deterministic filler for the length population's block bodies.
    /// The test only needs reproducibility, not a cryptographic generator.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// **The TLS-shaped fixed-length check does not expose a length channel.**
    ///
    /// `ossl_rsa_padding_check_PKCS1_type_2_TLS` always answers `SSL_MAX_MASTER_KEY_LENGTH` (48)
    /// and always writes 48 bytes: a valid TLS-shaped block copies the submitted pre-master
    /// secret, an invalid one copies a random secret selected under the same constant-time mask.
    /// The measurement is over thousands of invalid blocks, so a zero in the length axis is a
    /// statement about the whole population rather than an illustration.
    ///
    /// This function is the authority's answer for TLS; the generic `RSA_private_decrypt` arm in
    /// this file does not call it. The application obligation that follows — select the
    /// fixed-length check rather than exposing the generic length — is recorded in
    /// `evidence/haz-15/REENTRANCY-AND-LENGTH.md`.
    #[test]
    fn the_tls_shaped_padding_check_answers_one_length() {
        const INVALID_SAMPLES: usize = 4096;
        let num = 256usize;
        let pms = 48usize;
        let version: c_int = 0x0303;

        // A valid TLS-shaped block: 00 02, a long non-zero padding string, a zero separator,
        // then the 48-octet pre-master secret whose first two octets are the client version.
        let mut valid = vec![0x5au8; num];
        valid[0] = 0x00;
        valid[1] = 0x02;
        valid[num - pms - 1] = 0x00;
        valid[num - pms] = 0x03;
        valid[num - pms + 1] = 0x03;

        // SAFETY: the function reads exactly `num` bytes from `valid`/`invalid` and writes `pms`
        // bytes to `out`; every buffer is this frame's own and correctly sized.
        unsafe {
            let mut out = vec![0u8; pms];
            let ret = crate::rsa::ossl_rsa_padding_check_PKCS1_type_2_TLS(
                ptr::null_mut(),
                out.as_mut_ptr(),
                pms,
                valid.as_ptr(),
                num,
                version,
                0,
            );
            assert_eq!(ret, pms as c_int);
            assert_eq!(
                &out[..],
                &valid[num - pms..],
                "a valid block returns the secret"
            );

            let mut bad_lengths = Vec::with_capacity(INVALID_SAMPLES);
            for i in 0..INVALID_SAMPLES {
                let mut invalid = valid.clone();
                let mut state = 0x1234_5678_9abc_def0u64 ^ (i as u64);
                let position = (splitmix64(&mut state) as usize) % num;
                let flip = (splitmix64(&mut state) as u8) | 1;
                invalid[position] ^= flip;
                let mut out = vec![0u8; pms];
                let ret = crate::rsa::ossl_rsa_padding_check_PKCS1_type_2_TLS(
                    ptr::null_mut(),
                    out.as_mut_ptr(),
                    pms,
                    invalid.as_ptr(),
                    num,
                    version,
                    0,
                );
                assert_eq!(
                    ret, pms as c_int,
                    "invalid block {i} answers the fixed length"
                );
                bad_lengths.push(ret);
            }
            let distinct: std::collections::BTreeSet<c_int> = bad_lengths.iter().copied().collect();
            println!(
                "HAZ15TLS samples={INVALID_SAMPLES} distinct_returned_lengths={:?}",
                distinct
            );
            assert_eq!(
                distinct.len(),
                1,
                "the fixed-length check has no length channel"
            );
            assert!(distinct.contains(&(pms as c_int)));
        }
    }

    /// **The internal-key PKCS#1 v1.5 path is unchanged.** The same valid ciphertext that
    /// `RSA_public_encrypt` builds is decrypted to exactly the submitted message, and an invalid
    /// block still takes the implicit-rejection arm. This pins the pre-existing behaviour the
    /// external-key correction must not move.
    #[test]
    fn internal_key_pkcs1_decryption_is_unchanged() {
        use crate::rsa::gen::RSA_generate_key_ex;
        use crate::rsa::object::{
            RSA_free, RSA_new, RSA_private_decrypt, RSA_public_encrypt, RSA_size,
        };
        use crate::rsa::RSA_padding_add_PKCS1_type_2;
        use crate::runtime::err::{ERR_clear_error, ERR_peek_error};

        const MSG: &[u8] = b"HAZ15VAL";

        // SAFETY: every object and buffer is created and released here.
        unsafe {
            let e = BN_new();
            assert_eq!(BN_set_word(e, 65537), 1);
            let rsa = RSA_new();
            assert!(RSA_generate_key_ex(rsa, 1024, e, ptr::null_mut()) == 1);

            let num = RSA_size(rsa) as usize;
            let mut ct = vec![0u8; num];
            assert_eq!(
                RSA_public_encrypt(
                    MSG.len() as c_int,
                    MSG.as_ptr(),
                    ct.as_mut_ptr(),
                    rsa,
                    RSA_PKCS1_PADDING
                ),
                num as c_int
            );

            let mut out = vec![0xAAu8; num];
            ERR_clear_error();
            assert_eq!(
                RSA_private_decrypt(
                    num as c_int,
                    ct.as_ptr(),
                    out.as_mut_ptr(),
                    rsa,
                    RSA_PKCS1_PADDING
                ),
                MSG.len() as c_int
            );
            assert_eq!(&out[..MSG.len()], MSG);
            assert_eq!(ERR_peek_error(), 0);

            // An invalid block on an internal key is the arm that already existed.
            let mut bad_block = vec![0u8; num];
            assert_eq!(
                RSA_padding_add_PKCS1_type_2(
                    bad_block.as_mut_ptr(),
                    num as c_int,
                    MSG.as_ptr(),
                    MSG.len() as c_int
                ),
                1
            );
            bad_block[1] = 0x03;
            let bad_ct = ciphertext_for_block(rsa, &bad_block);
            let mut bad_out = vec![0xAAu8; num];
            ERR_clear_error();
            assert!(
                RSA_private_decrypt(
                    num as c_int,
                    bad_ct.as_ptr(),
                    bad_out.as_mut_ptr(),
                    rsa,
                    RSA_PKCS1_PADDING
                ) > 0
            );
            assert_eq!(ERR_peek_error(), 0);

            RSA_free(rsa);
            BN_free(e);
        }
    }

    /// `VALGRIND_MAKE_MEM_UNDEFINED` as the amd64 client request.
    ///
    /// Same sequence as `bn::arith`'s test helper: `valgrind.h`'s preamble and
    /// an `xchgq rbx, rbx`, which valgrind replaces during translation. Outside
    /// valgrind it is a few harmless register rotations.
    #[cfg(target_arch = "x86_64")]
    unsafe fn valgrind_make_mem_undefined(addr: *mut u8, len: usize) {
        let args: [usize; 6] = [0x4D43_0001, addr as usize, len, 0, 0, 0];
        let _result: usize;
        // SAFETY: the sequence is the documented valgrind client-request
        // pattern; `args` lives for the duration of the asm and is only read.
        unsafe {
            core::arch::asm!(
                "rol rdi, 3",
                "rol rdi, 13",
                "rol rdi, 61",
                "rol rdi, 51",
                "xchg rbx, rbx",
                in("rax") args.as_ptr(),
                inout("rdx") 0usize => _result,
                out("rdi") _,
                options(nostack),
            );
        }
    }

    /// ctgrind case for T6: the RSA CRT moduli are secret (only their width is
    /// public), so the Montgomery precomputation `rsa_ossl_mod_exp` runs on
    /// `p` and `q` must not branch on, index memory by, or size a loop from
    /// their *contents*.
    ///
    /// The key is generated (so no constant is embedded), its prime Montgomery
    /// caches are cleared because `RSA_generate_key_ex`'s pairwise test already
    /// built them, and then the limb storage of `rsa->p` and `rsa->q` is marked
    /// undefined. Only the modulus contents are tainted: `d`, `dmp1`, `dmq1`,
    /// `iqmp` and the message stay defined, which is what distinguishes this
    /// case from the exponent-only runs. `RSA_FLAG_NO_BLINDING` keeps the DRBG
    /// out of the workload; the CRT path is the same either way.
    ///
    /// Gate: `valgrind --tool=memcheck --error-exitcode=99 <test-bin> --exact
    /// rsa::ossl::tests::ctgrind_rsa_crt_secret_moduli --nocapture`.
    /// `CTGRIND_CONTROL=1` adds a deliberate branch on a marked modulus limb,
    /// which memcheck must report (negative control).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ctgrind_rsa_crt_secret_moduli() {
        use crate::evp::pkey_ctx::RSA_NO_PADDING;
        use crate::rsa::gen::RSA_generate_key_ex;
        use crate::rsa::object::{
            RSA_free, RSA_get0_factors, RSA_new, RSA_private_encrypt, RSA_size,
        };

        // SAFETY: every pointer below is a fresh object this test owns, null-
        // checked, and every length is the buffer's own.
        unsafe {
            let e = BN_new();
            assert!(!e.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);
            let rsa = RSA_new();
            assert!(!rsa.is_null());
            assert_eq!(RSA_generate_key_ex(rsa, 2048, e, core::ptr::null_mut()), 1);

            // The keygen pairwise test runs a private operation, which caches a
            // Montgomery context for each prime. Clear them so the
            // precomputation we want to watch runs after the taint is applied.
            BN_MONT_CTX_free((*rsa)._method_mod_p);
            (*rsa)._method_mod_p = ptr::null_mut();
            BN_MONT_CTX_free((*rsa)._method_mod_q);
            (*rsa)._method_mod_q = ptr::null_mut();
            (*rsa).flags |= RSA_FLAG_NO_BLINDING;

            let mut p: *const BigNum = ptr::null();
            let mut q: *const BigNum = ptr::null();
            RSA_get0_factors(rsa, &mut p, &mut q);
            assert!(!p.is_null() && !q.is_null());
            assert_eq!(BN_num_bits(p), 1024);
            assert_eq!(BN_num_bits(q), 1024);

            // Taint the modulus *contents* only.
            for m in [p, q] {
                let limbs = &(*m).d;
                valgrind_make_mem_undefined(limbs.as_ptr() as *mut u8, limbs.len() * 8);
            }
            if std::env::var_os("CTGRIND_CONTROL").is_some() {
                // Negative control: memcheck must flag this branch on a marked
                // modulus limb.
                let mut acc = 0u64;
                for &limb in &(*p).d {
                    if limb & 1 == 1 {
                        acc += 1;
                    }
                }
                assert!(acc > 0);
            }

            let n = RSA_size(rsa) as usize;
            assert_eq!(n, 256);
            let mut pt = [0u8; 256];
            pt[255] = 0x42;
            let mut ct = [0u8; 256];
            assert_eq!(
                RSA_private_encrypt(
                    n as c_int,
                    pt.as_ptr(),
                    ct.as_mut_ptr(),
                    rsa,
                    RSA_NO_PADDING
                ),
                n as c_int
            );

            RSA_free(rsa);
            BN_free(e);
        }
    }

    /// Sweep every seam-visible allocation in the CRT private operation
    /// (`rsa_ossl_mod_exp`) through both arms: the smooth combined exponentiation
    /// and the generic per-prime arm. Each injected failure must return the
    /// operation's error rather than aborting.
    #[test]
    fn every_allocation_failure_in_rsa_crt_returns_an_error() {
        use crate::bn::bignum::{BN_new, BN_set_word};
        use crate::bn::ctx::{BN_CTX_free, BN_CTX_new};
        use crate::rsa::gen::RSA_generate_key_ex;
        use crate::rsa::object::{RSA_free, RSA_new};

        // SAFETY: every object below is created and released here and is live for
        // each call.
        unsafe {
            let e = BN_new();
            let rsa = RSA_new();
            assert!(!e.is_null() && !rsa.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);
            assert_eq!(RSA_generate_key_ex(rsa, 1024, e, core::ptr::null_mut()), 1);

            let r0 = BN_new();
            let input = BN_new();
            assert!(!r0.is_null() && !input.is_null());
            assert_eq!(BN_set_word(input, 0x42), 1);

            // Each run starts from cleared caches and a fresh context, so every
            // stateful allocation site (the Montgomery contexts included) is
            // reachable from the same state rather than only on the first run.
            let op = |slow: bool| -> bool {
                BN_MONT_CTX_free((*rsa)._method_mod_p);
                (*rsa)._method_mod_p = core::ptr::null_mut();
                BN_MONT_CTX_free((*rsa)._method_mod_q);
                (*rsa)._method_mod_q = core::ptr::null_mut();
                BN_MONT_CTX_free((*rsa)._method_mod_n);
                (*rsa)._method_mod_n = core::ptr::null_mut();
                if slow {
                    (*rsa).flags &= !RSA_FLAG_CACHE_PRIVATE;
                } else {
                    (*rsa).flags |= RSA_FLAG_CACHE_PRIVATE;
                }
                let ctx = BN_CTX_new();
                if ctx.is_null() {
                    return false;
                }
                let ok = rsa_ossl_mod_exp(r0, input, rsa, ctx) == 1;
                BN_CTX_free(ctx);
                ok
            };

            assert!(op(false));
            let smooth = crate::bn::alloc::test_fail::sweep_sites(|| op(false));
            assert!(smooth > 0, "the seam must see the smooth CRT arm");

            assert!(op(true));
            let slow = crate::bn::alloc::test_fail::sweep_sites(|| op(true));
            assert!(slow > 0, "the seam must see the generic CRT arm");
            eprintln!("T22 sites: rsa_crt smooth={smooth} generic={slow}");

            assert!(op(false));
            BN_free(r0);
            BN_free(input);
            RSA_free(rsa);
            BN_free(e);
        }
    }

    /// PFP-1: the CRT path with cached prepared domains (`RSA_FLAG_CACHE_PRIVATE`
    /// set) answers exactly what the path with every context rebuilt answers.
    /// The uncached arm is the mutation control: the reuse is removed, not the
    /// operation.
    #[test]
    fn the_prepared_crt_path_answers_what_the_unprepared_path_answers() {
        use crate::bn::arith::BN_ucmp;
        use crate::bn::bignum::{BN_new, BN_set_word};
        use crate::bn::ctx::{BN_CTX_free, BN_CTX_new};
        use crate::rsa::gen::RSA_generate_key_ex;
        use crate::rsa::object::{RSA_free, RSA_new};

        // SAFETY: every object below is created and released here and is live for
        // each call.
        unsafe {
            let e = BN_new();
            let rsa = RSA_new();
            assert!(!e.is_null() && !rsa.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);
            assert_eq!(RSA_generate_key_ex(rsa, 2048, e, core::ptr::null_mut()), 1);

            let input = BN_new();
            assert!(!input.is_null());
            assert_eq!(BN_set_word(input, 0x42), 1);

            let run = |cache_private: bool, out: *mut BigNum| -> bool {
                BN_MONT_CTX_free((*rsa)._method_mod_p);
                (*rsa)._method_mod_p = core::ptr::null_mut();
                BN_MONT_CTX_free((*rsa)._method_mod_q);
                (*rsa)._method_mod_q = core::ptr::null_mut();
                BN_MONT_CTX_free((*rsa)._method_mod_n);
                (*rsa)._method_mod_n = core::ptr::null_mut();
                if cache_private {
                    (*rsa).flags |= RSA_FLAG_CACHE_PRIVATE;
                } else {
                    (*rsa).flags &= !RSA_FLAG_CACHE_PRIVATE;
                }
                let ctx = BN_CTX_new();
                if ctx.is_null() {
                    return false;
                }
                let ok = rsa_ossl_mod_exp(out, input, rsa, ctx) == 1;
                BN_CTX_free(ctx);
                ok
            };

            let prepared = BN_new();
            let unprepared = BN_new();
            assert!(!prepared.is_null() && !unprepared.is_null());
            assert!(run(true, prepared), "the prepared CRT arm must succeed");
            // The prepared arm cached p and q; the unprepared arm clears them and
            // disables the cache, forcing the precomputation on every operation.
            assert!(
                run(false, unprepared),
                "the unprepared CRT arm must succeed"
            );
            assert_eq!(
                BN_ucmp(prepared, unprepared),
                0,
                "prepared vs unprepared CRT"
            );

            BN_free(prepared);
            BN_free(unprepared);
            BN_free(input);
            RSA_free(rsa);
            BN_free(e);
        }
    }

    /// **An application RNG callback may re-enter RSA decryption.**
    ///
    /// The first-use secret for a key with no private material is drawn by `RAND_priv_bytes`,
    /// which an application can replace. With the store's lock held across that call, a callback
    /// that re-enters RSA decryption would deadlock on the non-reentrant mutex. The repair records
    /// an `INITIALIZING` reservation, releases the lock for the draw, and publishes under a fresh
    /// acquisition; the same thread that already owns the reservation is refused immediately, and
    /// a different key's re-entry completes on its own reservation.
    ///
    /// The control is bounded: a hang is a test failure, not an outcome. It also checks from
    /// inside the callback that the store's lock is free, which is the property that makes the
    /// same-thread refusal possible.
    #[test]
    #[allow(clippy::panic)] // a bounded-wait failure is the test's observation
    fn a_first_use_rng_callback_may_reenter_rsa_decryption() {
        let (_serial, _installed) = install_rng_script();
        RNG_GATE.reset();

        let mut same = Box::new(super::super::mp::zeroed_rsa());
        let mut other = Box::new(super::super::mp::zeroed_rsa());
        let same_addr = (&mut *same) as *mut Rsa as usize;
        let other_addr = (&mut *other) as *mut Rsa as usize;

        // Same key: the callback re-enters the object whose reservation the outer call owns.
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        let worker = std::thread::spawn(move || {
            arm_rng(RngAction::ReenterSame, same_addr, other_addr);
            let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
            // SAFETY: the fixtures outlive this join; the re-entered target is the same live
            // object and the ciphertext is this frame's fixed array.
            let outer = unsafe {
                derive_external_kdk(
                    same_addr as *mut Rsa,
                    RNG_TEST_CT.as_ptr(),
                    RNG_TEST_CT.len() as c_int,
                    kdk.as_mut_ptr(),
                )
            };
            let inner = RNG_REENTRY_RESULT.with(Cell::get);
            let variant_ok = RNG_REENTRY_VARIANT_OK.with(Cell::get);
            let _ = tx.send((outer, inner, variant_ok));
        });
        let observed = receive(
            &rx,
            "same-thread re-entry deadlocked across the RNG callback",
        );
        assert!(worker.join().is_ok(), "the worker must not panic");
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(observed.0, 1, "the outer first use completes");
        assert_eq!(observed.1, 0, "same-thread re-entry is the defined refusal");
        assert!(observed.2, "the refusal names ReentrantInitialization");
        assert!(
            !RNG_STORE_LOCK_HELD.load(AtomicOrdering::SeqCst),
            "the store lock must not be held across the RNG callback"
        );
        assert_eq!(ext_kdk_ready_count(same_addr as *mut Rsa), 1);
        forget_ext_kdk_secret(same_addr as *mut Rsa);

        // A different key: the callback's inner call reserves its own entry and completes.
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        let worker = std::thread::spawn(move || {
            arm_rng(RngAction::ReenterOther, same_addr, other_addr);
            let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
            // SAFETY: both fixtures outlive this join.
            let outer = unsafe {
                derive_external_kdk(
                    same_addr as *mut Rsa,
                    RNG_TEST_CT.as_ptr(),
                    RNG_TEST_CT.len() as c_int,
                    kdk.as_mut_ptr(),
                )
            };
            let inner = RNG_REENTRY_RESULT.with(Cell::get);
            let _ = tx.send((outer, inner));
        });
        let observed = receive(&rx, "different-key re-entry deadlocked");
        assert!(worker.join().is_ok());
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(observed.0, 1, "the outer call completes");
        assert_eq!(observed.1, 1, "a different key's inner call completes");
        assert_eq!(ext_kdk_ready_count(same_addr as *mut Rsa), 1);
        assert_eq!(ext_kdk_ready_count(other_addr as *mut Rsa), 1);
        forget_ext_kdk_secret(same_addr as *mut Rsa);
        forget_ext_kdk_secret(other_addr as *mut Rsa);
        assert_eq!(ext_kdk_entry_count(same_addr as *mut Rsa), 0);
        assert_eq!(ext_kdk_entry_count(other_addr as *mut Rsa), 0);
    }

    /// **Concurrent first uses install exactly one secret and agree on it.**
    ///
    /// The first thread reserves and parks in the RNG callback; the rest must block on the store's
    /// condition variable rather than spin or draw their own secret. On publication every caller
    /// copies the same secret, so the KDK and the synthetic answer are identical, and the store
    /// holds exactly one `Ready` entry.
    #[test]
    #[allow(clippy::panic)] // bounded waits are the observation
    fn concurrent_first_use_installs_exactly_one_secret() {
        let (_serial, _installed) = install_rng_script();
        RNG_GATE.reset();

        let mut key = Box::new(super::super::mp::zeroed_rsa());
        let addr = (&mut *key) as *mut Rsa as usize;
        const THREADS: usize = 8;

        let (tx, rx) = mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..THREADS {
            let tx = tx.clone();
            workers.push(std::thread::spawn(move || {
                arm_rng(RngAction::Block, addr, 0);
                let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
                // SAFETY: the fixture outlives every join below.
                let result = unsafe {
                    derive_external_kdk(
                        addr as *mut Rsa,
                        RNG_TEST_CT.as_ptr(),
                        RNG_TEST_CT.len() as c_int,
                        kdk.as_mut_ptr(),
                    )
                };
                let _ = tx.send((result, kdk));
            }));
        }
        drop(tx);
        assert!(
            RNG_GATE.wait_entered(Duration::from_secs(10)),
            "the owner must reach the RNG callback"
        );
        assert_eq!(
            ext_kdk_initializing_count(addr as *mut Rsa),
            1,
            "exactly one reservation"
        );
        // Wait until a peer is genuinely parked on the condition variable, not for a guessed
        // interval.
        assert!(
            wait_for_waiter(Duration::from_secs(10)),
            "a concurrent caller must block on the condition variable"
        );
        assert_eq!(ext_kdk_entry_count(addr as *mut Rsa), 1);
        assert_eq!(ext_kdk_initializing_count(addr as *mut Rsa), 1);
        RNG_GATE.release();

        let mut results = Vec::new();
        for _ in 0..THREADS {
            results.push(receive(&rx, "a concurrent first use did not complete"));
        }
        for worker in workers {
            assert!(worker.join().is_ok());
        }
        let (first_result, first_kdk) = results[0];
        assert_eq!(first_result, 1);
        for (result, kdk) in &results {
            assert_eq!(*result, 1, "every caller gets a secret");
            assert_eq!(*kdk, first_kdk, "all callers agree on the KDK");
        }
        assert_eq!(ext_kdk_ready_count(addr as *mut Rsa), 1);
        assert_eq!(ext_kdk_initializing_count(addr as *mut Rsa), 0);
        forget_ext_kdk_secret(addr as *mut Rsa);
        assert_eq!(ext_kdk_entry_count(addr as *mut Rsa), 0);
    }

    /// **Destruction during initialisation is defined and publishes nothing.**
    ///
    /// The owner is parked in the RNG callback, a second thread is parked on the condition
    /// variable, and the key is destroyed. Removal wakes the waiter, and the owner's later
    /// publication finds no matching reservation. Neither path writes into the freed object: the
    /// waiter never dereferences it, and the owner's abandoned path returns before reading
    /// `libctx`. No entry survives.
    #[test]
    #[allow(clippy::panic)] // bounded waits are the observation
    fn destruction_during_initialisation_is_a_defined_refusal() {
        use crate::rsa::object::{RSA_free, RSA_new, RSA_set0_key};

        let (_serial, _installed) = install_rng_script();
        RNG_GATE.reset();

        // SAFETY: the object is created here; both workers finish before it is freed, and after
        // the free neither dereferences it.
        let rsa = unsafe {
            let rsa = RSA_new();
            assert!(!rsa.is_null());
            let n = BN_new();
            let e = BN_new();
            assert!(!n.is_null() && !e.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);
            assert_eq!(BN_set_word(n, 0x0100_0001), 1);
            assert_eq!(RSA_set0_key(rsa, n, e, ptr::null_mut()), 1);
            rsa
        };
        let addr = rsa as usize;

        let (owner_tx, owner_rx) = mpsc::channel();
        let owner = std::thread::spawn(move || {
            arm_rng(RngAction::Block, addr, 0);
            let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
            // SAFETY: the object is live until the free below, and the abandoned path returns
            // before reading it again.
            let result = unsafe {
                derive_external_kdk(
                    addr as *mut Rsa,
                    RNG_TEST_CT.as_ptr(),
                    RNG_TEST_CT.len() as c_int,
                    kdk.as_mut_ptr(),
                )
            };
            let _ = owner_tx.send(result);
        });
        assert!(RNG_GATE.wait_entered(Duration::from_secs(10)));
        assert_eq!(ext_kdk_initializing_count(addr as *mut Rsa), 1);

        let (waiter_tx, waiter_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            // The waiter only consults the side table; it never dereferences the object.
            let refusal = per_key_ext_kdk_secret(addr as *mut Rsa).err();
            let _ = waiter_tx.send(refusal);
        });
        assert!(
            wait_for_waiter(Duration::from_secs(10)),
            "the waiter must block on the condition variable"
        );
        assert_eq!(ext_kdk_entry_count(addr as *mut Rsa), 1);

        // SAFETY: this is the destruction hook `RSA_free` runs; both workers are outside any
        // dereference of the object and are woken by the removal.
        unsafe { RSA_free(rsa) };
        assert_eq!(
            ext_kdk_entry_count(addr as *mut Rsa),
            0,
            "no secret survives destruction"
        );

        RNG_GATE.release();
        let owner_result = receive(&owner_rx, "the abandoned initialiser was not refused");
        let waiter_refusal = receive(&waiter_rx, "the waiter was not woken");
        assert!(owner.join().is_ok());
        assert!(waiter.join().is_ok());
        assert_eq!(owner_result, 0, "the abandoned initialiser refuses");
        assert_eq!(waiter_refusal, Some(ExtKdkRefusal::ReservationAbandoned));
        assert_eq!(ext_kdk_entry_count(addr as *mut Rsa), 0);
    }

    /// **RNG and allocation failure publish nothing and are the defined refusal.**
    ///
    /// The RNG is failed through the application callback, the entry reservation through the
    /// test allocation seam, and the secret's own allocation through the same seam with the
    /// vector pre-grown. Each case must leave no entry and answer `0`/`AllocationFailure`; the
    /// RNG case also shows that the abandoned reservation does not poison a later attempt.
    #[test]
    fn rng_and_allocation_failure_publish_nothing() {
        let (_serial, _installed) = install_rng_script();

        let mut key = Box::new(super::super::mp::zeroed_rsa());
        let addr = (&mut *key) as *mut Rsa as usize;
        let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];

        // RNG failure at the draw.
        arm_rng(RngAction::Fail, 0, 0);
        // SAFETY: the fixture is live and every buffer is this frame's.
        let refused = unsafe {
            derive_external_kdk(
                addr as *mut Rsa,
                RNG_TEST_CT.as_ptr(),
                RNG_TEST_CT.len() as c_int,
                kdk.as_mut_ptr(),
            )
        };
        assert_eq!(refused, 0, "an RNG failure is the defined refusal");
        assert_eq!(ext_kdk_entry_count(addr as *mut Rsa), 0);

        // The reservation was abandoned, so a later attempt succeeds.
        arm_rng(RngAction::Delegate, 0, 0);
        // SAFETY: as above.
        let retried = unsafe {
            derive_external_kdk(
                addr as *mut Rsa,
                RNG_TEST_CT.as_ptr(),
                RNG_TEST_CT.len() as c_int,
                kdk.as_mut_ptr(),
            )
        };
        assert_eq!(
            retried, 1,
            "the abandoned reservation does not poison the next attempt"
        );
        assert_eq!(ext_kdk_ready_count(addr as *mut Rsa), 1);
        forget_ext_kdk_secret(addr as *mut Rsa);

        // Reservation allocation failure: the entry's box is the first seam-visible allocation.
        let mut reserve_fail = Box::new(super::super::mp::zeroed_rsa());
        let reserve_fail_addr = (&mut *reserve_fail) as *mut Rsa as usize;
        let guard = crate::runtime::alloc::test_fail::fail_after(0);
        let refused = per_key_ext_kdk_secret(reserve_fail_addr as *mut Rsa);
        drop(guard);
        assert!(
            matches!(refused, Err(ExtKdkRefusal::AllocationFailure)),
            "a refused reservation is an allocation failure"
        );
        assert_eq!(ext_kdk_entry_count(reserve_fail_addr as *mut Rsa), 0);

        // Secret allocation failure: spare vector capacity makes the reservation allocation-free,
        // so the budget's single success is the entry box and the next failure is the secret.
        {
            let mut store = lock_ext_kdk_store();
            let _ = store.entries.try_reserve(4);
        }
        let mut secret_fail = Box::new(super::super::mp::zeroed_rsa());
        let secret_fail_addr = (&mut *secret_fail) as *mut Rsa as usize;
        let guard = crate::runtime::alloc::test_fail::fail_after(1);
        let refused = per_key_ext_kdk_secret(secret_fail_addr as *mut Rsa);
        drop(guard);
        assert!(
            matches!(refused, Err(ExtKdkRefusal::AllocationFailure)),
            "a refused secret is an allocation failure"
        );
        assert_eq!(ext_kdk_entry_count(secret_fail_addr as *mut Rsa), 0);
    }

    /// **A re-entrant call for the object that is mid-initialisation is the defined
    /// refusal, and the object ends with exactly one published secret.**
    ///
    /// The outer call owns the `INITIALIZING` reservation when the application RNG
    /// callback re-enters RSA decryption for the same object. The inner call must not
    /// wait on its own reservation; it answers `0` and the internal refusal is
    /// `ReentrantInitialization`. The outer call then publishes the one secret, and a
    /// later use of the object returns byte-identical key material.
    #[test]
    #[allow(clippy::panic)] // a bounded-wait failure is the test's observation
    fn a_reentrant_call_for_the_mid_initialisation_object_is_refused() {
        let (_serial, _installed) = install_rng_script();
        RNG_GATE.reset();

        let mut key = Box::new(super::super::mp::zeroed_rsa());
        let addr = (&mut *key) as *mut Rsa as usize;

        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        let worker = std::thread::spawn(move || {
            arm_rng(RngAction::ReenterSame, addr, 0);
            let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
            // SAFETY: the fixture outlives this join; the re-entered target is the same
            // live object and the ciphertext is this frame's fixed array.
            let outer = unsafe {
                derive_external_kdk(
                    addr as *mut Rsa,
                    RNG_TEST_CT.as_ptr(),
                    RNG_TEST_CT.len() as c_int,
                    kdk.as_mut_ptr(),
                )
            };
            let inner = RNG_REENTRY_RESULT.with(Cell::get);
            let inner_variant = RNG_REENTRY_VARIANT_OK.with(Cell::get);
            let _ = tx.send((outer, inner, inner_variant, kdk));
        });
        let observed = receive(&rx, "same-object re-entry during initialisation deadlocked");
        assert!(worker.join().is_ok(), "the worker must not panic");
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(observed.0, 1, "the outer first use completes");
        assert_eq!(observed.1, 0, "the re-entrant call is refused");
        assert!(observed.2, "the refusal names ReentrantInitialization");
        assert_eq!(
            ext_kdk_initializing_count(addr as *mut Rsa),
            0,
            "no reservation survives the completed first use"
        );
        assert_eq!(
            ext_kdk_ready_count(addr as *mut Rsa),
            1,
            "exactly one secret is published"
        );

        // The published secret is the one the outer call derived: a later use copies
        // the same bytes.
        arm_rng(RngAction::Delegate, 0, 0);
        let mut later = [0u8; SHA256_DIGEST_LENGTH as usize];
        // SAFETY: the fixture is live and every buffer is this frame's.
        let later_result = unsafe {
            derive_external_kdk(
                addr as *mut Rsa,
                RNG_TEST_CT.as_ptr(),
                RNG_TEST_CT.len() as c_int,
                later.as_mut_ptr(),
            )
        };
        assert_eq!(later_result, 1);
        assert_eq!(
            later, observed.3,
            "the published secret is the outer call's"
        );
        assert_eq!(ext_kdk_ready_count(addr as *mut Rsa), 1);

        forget_ext_kdk_secret(addr as *mut Rsa);
        assert_eq!(ext_kdk_entry_count(addr as *mut Rsa), 0);
    }

    /// **An RNG callback that destroys the object mid-initialisation publishes nothing.**
    ///
    /// The callback releases the only reference to the object whose first-use secret is
    /// being drawn. `RSA_free` removes the side-table reservation before returning; the
    /// outer publication then matches no reservation and the call answers `0`. The
    /// initialiser reads no field of the freed object: the refusal is produced before
    /// `libctx` is touched, and `rsa_ossl_private_decrypt` performs no field access after
    /// the KDK call returns.
    ///
    /// The store must still be usable afterwards, which also shows the destruction did
    /// not leave a reservation that every later call would see.
    #[test]
    #[allow(clippy::panic)] // a bounded-wait failure is the test's observation
    fn an_rng_callback_that_destroys_the_object_publishes_nothing() {
        use crate::rsa::object::{RSA_new, RSA_set0_key};

        let (_serial, _installed) = install_rng_script();

        // SAFETY: the object is created here, released by the callback below, and never
        // dereferenced by this test after that.
        let rsa = unsafe {
            let rsa = RSA_new();
            assert!(!rsa.is_null());
            let n = BN_new();
            let e = BN_new();
            assert!(!n.is_null() && !e.is_null());
            assert_eq!(BN_set_word(e, 65537), 1);
            assert_eq!(BN_set_word(n, 0x0100_0001), 1);
            assert_eq!(RSA_set0_key(rsa, n, e, ptr::null_mut()), 1);
            rsa
        };
        let addr = rsa as usize;

        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        let worker = std::thread::spawn(move || {
            arm_rng(RngAction::DestroyTarget, addr, 0);
            let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
            // SAFETY: the object is live until the callback releases it; the abandoned
            // path returns before reading it again.
            let result = unsafe {
                derive_external_kdk(
                    addr as *mut Rsa,
                    RNG_TEST_CT.as_ptr(),
                    RNG_TEST_CT.len() as c_int,
                    kdk.as_mut_ptr(),
                )
            };
            let _ = tx.send(result);
        });
        let observed = receive(&rx, "the destroying callback deadlocked");
        assert!(worker.join().is_ok(), "the worker must not panic");
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(
            observed, 0,
            "destruction during initialisation is the defined refusal"
        );
        assert_eq!(
            ext_kdk_entry_count(addr as *mut Rsa),
            0,
            "no entry survives the destruction"
        );

        // The store is still usable: a fresh object completes its first use.
        let mut fresh = Box::new(super::super::mp::zeroed_rsa());
        let fresh_addr = (&mut *fresh) as *mut Rsa as usize;
        arm_rng(RngAction::Delegate, 0, 0);
        let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
        // SAFETY: the fresh fixture is live and every buffer is this frame's.
        let fresh_result = unsafe {
            derive_external_kdk(
                fresh_addr as *mut Rsa,
                RNG_TEST_CT.as_ptr(),
                RNG_TEST_CT.len() as c_int,
                kdk.as_mut_ptr(),
            )
        };
        assert_eq!(fresh_result, 1, "the store still serves a new object");
        forget_ext_kdk_secret(fresh_addr as *mut Rsa);
    }

    /// **A panic at every fallible step of the first-use path removes the reservation,
    /// publishes nothing and does not poison the store against legitimate use.**
    ///
    /// The steps are the reservation install, the draw, the draw-failure abandonment and
    /// publication before and after the `Ready` install. The confirmation guard is what
    /// makes the unwinding case safe: every exit that has not published removes the
    /// reservation by its exact id and wakes any waiter. The guard's removal takes the
    /// store's lock, which is why the lock is released before the guard exists — without
    /// that ordering the reservation-install panic deadlocks on the non-reentrant lock.
    ///
    /// The whole loop runs on a worker thread and reports each stage through a channel, so
    /// a deadlock fails this control at its bounded wait instead of hanging the suite.
    ///
    /// A panic taken while the store's lock is held poisons it; the store's lock helper
    /// recovers the guard from the poison, so a later attempt completes. Poisoning is
    /// therefore tolerated rather than repaired, and this control observes the tolerance,
    /// not the poison flag (another test may have left the process-wide store poisoned).
    #[test]
    #[allow(clippy::panic)] // the injected panic and a deadlock are the observations
    fn a_panic_at_each_fallible_step_leaves_no_entry_and_the_next_attempt_succeeds() {
        let (_serial, _installed) = install_rng_script();

        const STAGES: [ext_kdk_hooks::Stage; 5] = [
            ext_kdk_hooks::Stage::AfterReserve,
            ext_kdk_hooks::Stage::AfterDraw,
            ext_kdk_hooks::Stage::DrawFailureAbandon,
            ext_kdk_hooks::Stage::PublishBeforeInstall,
            ext_kdk_hooks::Stage::PublishAfterInstall,
        ];

        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            for stage in STAGES {
                let mut key = Box::new(super::super::mp::zeroed_rsa());
                let addr = (&mut *key) as *mut Rsa as usize;
                arm_rng(
                    if stage == ext_kdk_hooks::Stage::DrawFailureAbandon {
                        RngAction::Fail
                    } else {
                        RngAction::Delegate
                    },
                    0,
                    0,
                );

                let hook = ext_kdk_hooks::arm(stage);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    per_key_ext_kdk_secret(addr as *mut Rsa)
                }));
                drop(hook);
                let unwound = outcome.is_err();
                let initializing = ext_kdk_initializing_count(addr as *mut Rsa);
                let entries = ext_kdk_entry_count(addr as *mut Rsa);

                arm_rng(RngAction::Delegate, 0, 0);
                let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
                // SAFETY: the fixture is live and every buffer is this frame's.
                let retried = unsafe {
                    derive_external_kdk(
                        addr as *mut Rsa,
                        RNG_TEST_CT.as_ptr(),
                        RNG_TEST_CT.len() as c_int,
                        kdk.as_mut_ptr(),
                    )
                };
                let ready = ext_kdk_ready_count(addr as *mut Rsa);
                forget_ext_kdk_secret(addr as *mut Rsa);
                let after = ext_kdk_entry_count(addr as *mut Rsa);
                let _ = tx.send((stage, unwound, initializing, entries, retried, ready, after));
            }
        });

        for stage in STAGES {
            let message = format!("{stage:?}: the injected panic deadlocked the initialiser");
            let observed = receive(&rx, &message);
            assert_eq!(observed.0, stage);
            assert!(
                observed.1,
                "{stage:?}: the injected panic must propagate out of the initialiser"
            );
            assert_eq!(
                observed.2, 0,
                "{stage:?}: no INITIALIZING entry survives the unwind"
            );
            assert_eq!(observed.3, 0, "{stage:?}: no secret survives the unwind");
            assert_eq!(
                observed.4, 1,
                "{stage:?}: a later attempt succeeds after the unwind"
            );
            assert_eq!(
                observed.5, 1,
                "{stage:?}: exactly one secret is installed by the retry"
            );
            assert_eq!(observed.6, 0, "{stage:?}: the release leaves no entry");
        }
        assert!(
            worker.join().is_ok(),
            "the panic-injection worker must finish"
        );
    }

    /// **The store's transitions are explored exhaustively within a stated bound, and no
    /// reachable interleaving violates the invariants.**
    ///
    /// Three actors over up to two objects: a concurrent first use with a destruction, a
    /// cross-object pair, and three callers on one object. Each exploration enumerates
    /// every reachable combination of the model's modes and store states and checks at
    /// every state: at most one entry and one secret per object, every secret published
    /// under its own (current) reservation, every secret tagged for its own object,
    /// destruction leaving no entry, and a refused re-entry leaving the store unchanged.
    /// The bound is `ext_kdk_model::NODE_BUDGET`; the test refuses a truncated run, so
    /// the claim is completeness inside the bound, not beyond it.
    #[test]
    fn the_state_machine_exploration_finds_no_invariant_violation() {
        use super::super::ext_kdk_model as model;

        let scenarios: [(&str, [model::Mode; model::ACTORS], bool); 3] = [
            (
                "a concurrent first use and a destruction",
                [
                    model::Mode::Start(0),
                    model::Mode::Start(0),
                    model::Mode::Destroying(0),
                ],
                true,
            ),
            (
                "two objects and a re-entrant caller",
                [
                    model::Mode::Start(0),
                    model::Mode::Start(1),
                    model::Mode::Start(0),
                ],
                false,
            ),
            (
                "three callers on one object",
                [
                    model::Mode::Start(0),
                    model::Mode::Start(0),
                    model::Mode::Start(0),
                ],
                false,
            ),
        ];

        for (name, initial, has_destroyer) in scenarios {
            let report = model::explore(initial, model::Fault::None);
            assert!(
                !report.truncated,
                "{name}: the exploration exceeded its bound"
            );
            assert_eq!(
                report.violation, None,
                "{name}: a reachable interleaving violated an invariant"
            );
            assert!(
                report.states > 1,
                "{name}: the exploration visited one state"
            );
            assert!(
                report.states < 20_000,
                "{name}: the exploration grew beyond its recorded working size ({})",
                report.states
            );
            for outcome in [
                model::Outcome::Reserved,
                model::Outcome::Drawn,
                model::Outcome::Published,
                model::Outcome::Reentrant,
                model::Outcome::Parked,
                model::Outcome::Abandoned,
                model::Outcome::WaitTimedOut,
            ] {
                assert!(
                    report.outcomes.contains(&outcome),
                    "{name}: the transition to {outcome:?} is not reachable"
                );
            }
            if has_destroyer {
                for outcome in [
                    model::Outcome::Destroyed,
                    model::Outcome::PublishRefused,
                    model::Outcome::ReservationAbandoned,
                ] {
                    assert!(
                        report.outcomes.contains(&outcome),
                        "{name}: the destruction transition to {outcome:?} is not reachable"
                    );
                }
            } else {
                assert!(
                    !report.outcomes.contains(&model::Outcome::Destroyed),
                    "{name}: a scenario without a destroyer reached destruction"
                );
            }
            assert!(
                report
                    .outcomes
                    .iter()
                    .any(|outcome| matches!(outcome, model::Outcome::Secret(_))),
                "{name}: no interleaving serves a secret"
            );
        }
    }

    /// **Every invariant has a negative control the exploration catches.**
    ///
    /// Each armed fault is a deliberately wrong transition; the exploration must reach it
    /// and report the matching violation. Without this, a green exploration would not show
    /// that the checker is connected to anything.
    #[test]
    #[allow(clippy::expect_used)] // a detected fault is the control's expectation
    fn every_invariant_has_a_fault_the_exploration_catches() {
        use super::super::ext_kdk_model as model;

        let initial = [
            model::Mode::Start(0),
            model::Mode::Start(0),
            model::Mode::Destroying(0),
        ];
        let controls = [
            (
                model::Fault::ReserveOverExisting,
                model::Violation::DuplicateEntry,
            ),
            (
                model::Fault::PublishIgnoresReservation,
                model::Violation::PublishedIntoStaleReservation,
            ),
            (
                model::Fault::CrossObjectSecret,
                model::Violation::CrossObjectSecret,
            ),
            (
                model::Fault::DestroyKeepsEntry,
                model::Violation::DestroyLeftEntry,
            ),
            (
                model::Fault::ReentryPushes,
                model::Violation::RefusalMutatedStore,
            ),
        ];

        for (fault, expected) in controls {
            let report = model::explore(initial, fault);
            let (violation, trace) = report
                .violation
                .expect("the armed fault must be detected as a violation");
            assert_eq!(violation, expected, "{fault:?}");
            assert!(
                !trace.is_empty(),
                "{fault:?}: the violation must name the path that reached it"
            );
        }
    }

    /// **A peer wait that is never satisfied answers the bounded timeout.**
    ///
    /// The owner parks in the RNG callback and the gate is never released while a peer
    /// waits, so nothing publishes and nothing is removed. The peer must refuse with
    /// `WaitTimedOut` after `EXT_KDK_WAIT_LIMIT` rather than waiting without a bound; the
    /// owner's reservation is then still publishable, and it publishes to exactly one
    /// secret. The control's own waiting is bounded at 10 s against the store's 5 s.
    #[test]
    #[allow(clippy::panic)] // a bounded-wait failure is the test's observation
    fn a_peer_wait_that_is_never_satisfied_is_the_bounded_timeout() {
        let (_serial, _installed) = install_rng_script();
        RNG_GATE.reset();

        let mut key = Box::new(super::super::mp::zeroed_rsa());
        let addr = (&mut *key) as *mut Rsa as usize;

        let (owner_tx, owner_rx) = mpsc::channel();
        let start = Instant::now();
        let owner = std::thread::spawn(move || {
            arm_rng(RngAction::Block, addr, 0);
            let mut kdk = [0u8; SHA256_DIGEST_LENGTH as usize];
            // SAFETY: the fixture outlives this join and the ciphertext is this frame's.
            let result = unsafe {
                derive_external_kdk(
                    addr as *mut Rsa,
                    RNG_TEST_CT.as_ptr(),
                    RNG_TEST_CT.len() as c_int,
                    kdk.as_mut_ptr(),
                )
            };
            let _ = owner_tx.send(result);
        });
        assert!(
            RNG_GATE.wait_entered(Duration::from_secs(10)),
            "the owner must reach the RNG callback"
        );
        assert_eq!(ext_kdk_initializing_count(addr as *mut Rsa), 1);

        let (peer_tx, peer_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let refusal = per_key_ext_kdk_secret(addr as *mut Rsa).err();
            let _ = peer_tx.send(refusal);
        });
        assert!(
            wait_for_waiter(Duration::from_secs(10)),
            "the peer must block on the condition variable"
        );
        let refusal = receive(&peer_rx, "the peer wait was not bounded");
        assert_eq!(
            refusal,
            Some(ExtKdkRefusal::WaitTimedOut),
            "an unsatisfied wait is the defined timeout"
        );
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the timeout must be bounded, not merely eventual"
        );

        // The owner's reservation was never removed, so it still publishes.
        RNG_GATE.release();
        let owner_result = receive(&owner_rx, "the owner never published");
        assert!(owner.join().is_ok());
        assert!(peer.join().is_ok());
        assert_eq!(owner_result, 1);
        assert_eq!(ext_kdk_ready_count(addr as *mut Rsa), 1);
        forget_ext_kdk_secret(addr as *mut Rsa);
        assert_eq!(ext_kdk_entry_count(addr as *mut Rsa), 0);
    }

    /// **The model's transition function agrees with the store on the scenarios that can
    /// be run without a second thread, and its other rows name the controls that
    /// establish the corresponding store outcome.**
    ///
    /// The model is an abstraction, so this is a conformance check on named rows, not a
    /// proof of equivalence: the refinement gap — what the model omits and which store
    /// controls establish the remaining rows — is recorded in
    /// `evidence/haz-15/STATE-MACHINE.md`.
    #[test]
    #[allow(clippy::unwrap_used)] // the script is fixed by the test itself
    fn the_model_agrees_with_the_store_on_the_named_scenarios() {
        use super::super::ext_kdk_model as model;

        // Same-thread re-entry: the owner's second reserve is the named refusal and the
        // first publication still completes.
        let outcomes = model::run_linear(&[
            (0, model::Event::Reserve(0)),
            (0, model::Event::DrawSuccess(0)),
            (0, model::Event::Reserve(0)),
            (0, model::Event::Publish(0)),
        ])
        .unwrap();
        assert_eq!(
            outcomes,
            vec![
                model::Outcome::Reserved,
                model::Outcome::Drawn,
                model::Outcome::Reentrant,
                model::Outcome::Published
            ]
        );

        // Destruction during initialisation: the publication finds no reservation and the
        // parked waiter sees it removed.
        let outcomes = model::run_linear(&[
            (0, model::Event::Reserve(0)),
            (1, model::Event::Reserve(0)),
            (0, model::Event::DrawSuccess(0)),
            (2, model::Event::Destroy(0)),
            (0, model::Event::Publish(0)),
            (1, model::Event::Woken(0)),
        ])
        .unwrap();
        assert_eq!(
            outcomes,
            vec![
                model::Outcome::Reserved,
                model::Outcome::Parked,
                model::Outcome::Drawn,
                model::Outcome::Destroyed,
                model::Outcome::PublishRefused,
                model::Outcome::ReservationAbandoned
            ]
        );

        // A draw failure abandons the reservation; a later attempt reserves afresh.
        let outcomes = model::run_linear(&[
            (0, model::Event::Reserve(0)),
            (0, model::Event::DrawFailure(0)),
            (0, model::Event::Reserve(0)),
        ])
        .unwrap();
        assert_eq!(
            outcomes,
            vec![
                model::Outcome::Reserved,
                model::Outcome::Abandoned,
                model::Outcome::Reserved
            ]
        );

        // The bounded wait expires when nothing publishes or removes the reservation.
        let outcomes = model::run_linear(&[
            (0, model::Event::Reserve(0)),
            (1, model::Event::Reserve(0)),
            (1, model::Event::Timeout(0)),
        ])
        .unwrap();
        assert_eq!(
            outcomes,
            vec![
                model::Outcome::Reserved,
                model::Outcome::Parked,
                model::Outcome::WaitTimedOut
            ]
        );

        // The two rows the store can execute directly. The draw failure is the model's
        // `DrawFailure`/`Abandoned` transition and leaves no entry; the retry is the
        // model's fresh `Reserve`.
        let (_serial, _installed) = install_rng_script();
        let mut key = Box::new(super::super::mp::zeroed_rsa());
        let addr = (&mut *key) as *mut Rsa as usize;
        arm_rng(RngAction::Fail, 0, 0);
        assert!(
            matches!(
                per_key_ext_kdk_secret(addr as *mut Rsa),
                Err(ExtKdkRefusal::RngFailure)
            ),
            "the store answers the model's abandoned reservation"
        );
        assert_eq!(ext_kdk_entry_count(addr as *mut Rsa), 0);
        arm_rng(RngAction::Delegate, 0, 0);
        assert!(
            per_key_ext_kdk_secret(addr as *mut Rsa).is_ok(),
            "the store's retry reserves afresh, as the model's second Reserve does"
        );
        forget_ext_kdk_secret(addr as *mut Rsa);

        // The reservation-allocation failure is the model's abandonment after Reserve.
        let mut second = Box::new(super::super::mp::zeroed_rsa());
        let second_addr = (&mut *second) as *mut Rsa as usize;
        let guard = crate::runtime::alloc::test_fail::fail_after(0);
        let refused = per_key_ext_kdk_secret(second_addr as *mut Rsa);
        drop(guard);
        assert!(
            matches!(refused, Err(ExtKdkRefusal::AllocationFailure)),
            "a refused reservation is the model's abandonment"
        );
        assert_eq!(ext_kdk_entry_count(second_addr as *mut Rsa), 0);
    }
}
