//! Phase 8 — 8.4's slice A, the `RSA` object: `crypto/rsa/rsa_lib.c`'s object layer
//! (`:32-959`), plus the three object accessors at `crypto/rsa/rsa_crpt.c:23-60` that the plan's
//! slice A names beside it.
//!
//! Thirty-four exports and twelve internals, and the constants they compare against. Every one is a
//! transcription: no stub, no `todo!()`, and no fabricated value.
//!
//! The `RSA` and `RSA_METHOD` shapes are **not** re-declared here. Slice B landed them in
//! [`crate::rsa`], measured (216 and 120 bytes) and pinned by that module's own layout tests, and
//! `RSA_PRIME_INFO` lives there too, beside [`Rsa`] — two translation units read and write its
//! fields, so a second declaration anywhere would be a second layout for one object. This file
//! imports all three.
//!
//! ## What this commit lands, and what a later commit owns
//!
//! `RSA_new`, `RSA_new_method`, `rsa_new_intern` and `ossl_rsa_new_with_ctx` are **not** here.
//! Their bodies are transcribed in the staged file and land in the commit that first makes
//! `RSA_get_default_method` reachable, because `rsa_new_intern` reads it (`rsa_lib.c:101`) and the
//! default method's table is `crypto/rsa/rsa_ossl.c`'s. Nothing else in this file reads the
//! default method, so the object's whole *accessor* surface is complete without it: every function
//! below touches only the object's own fields, `src/bn/`, the runtime, and the two callee modules
//! `crate::rsa::mp` and `crate::rsa::ossl`.
//!
//! ## The two reductions, and why the reachable answer is the answer
//!
//! **1. `ENGINE_*`.** [`RSA_set_method`] and [`RSA_free`] call `ENGINE_finish(rsa->engine)` in the
//! authority (`rsa_lib.c:56`, `:157`); `rsa_new_intern` additionally calls `ENGINE_init`,
//! `ENGINE_get_default_RSA` and `ENGINE_get_RSA` (`:105`, `:111`, `:114`). None of the four is in
//! this crate. `#ifndef OPENSSL_NO_ENGINE` is **undefined** on this profile, so the authority's
//! blocks are compiled, but `ENGINE_*` is Phase 13's (`docs/DECISIONS.md` D181) and there is no
//! engine registry to register one in. With no engine registered, `ENGINE_get_default_RSA()`
//! selects from an empty table and answers NULL (`tb_rsa.c:59`), `ENGINE_finish(NULL)` returns 1
//! without touching anything (`eng_init.c:108-111`), and `(*rsa).engine` is therefore NULL on
//! every state this crate can reach. So the two `ENGINE_finish` calls are written as the reachable
//! answer: omitted, with `rsa->engine = NULL;` kept where the authority sets it. This is
//! `src/evp/pkey_asn1.rs:54-60`'s established reduction and D313's argument, and its observable
//! half is that [`RSA_get0_engine`] answers NULL for every object the crate can build.
//!
//! **2. `RSA_PSS_PARAMS_free`.** [`RSA_free`] and [`ossl_rsa_set0_pss_params`] call it
//! (`rsa_lib.c:186`, `:702`). No state this crate can reach has a non-NULL `r->pss`: the field's
//! only writer is [`ossl_rsa_set0_pss_params`], whose only authority caller is
//! `crypto/rsa/rsa_backend.c:669`, and every `RSA_PSS_PARAMS *` comes from slice F's
//! `d2i_RSA_PSS_PARAMS`, which needs 8.8's `ASN1_ITEM` machinery. Both omitted calls are
//! `free(NULL)`, which `ossl_asn1_item_embed_free` answers by returning immediately
//! (`tasn_fre.c:36-39`). The symbol is **not** defined as an export either: a fabricated
//! `RSA_PSS_PARAMS_free` would put a wrong body on the ABI surface, which a consumer could link
//! and call. The day slice F lands, the calls replace the omission.
//!
//! Neither reduction is a `forensics/prerequisites.json` `divergences` row: the gate resolves
//! **internal** symbols only, so a row covering an export is refused with
//! `divergence_record_does_not_match`. The record is the transcribed site, the integration plan's
//! steps 4-5, and the commit's decision entry.
//!
//! ## Ordering, where the authority's is load-bearing
//!
//! * [`RSA_set_method`] shuts the outgoing table down **before** it installs the incoming one:
//!   `finish` on the old table, then the engine release, then the store, then `init` on the new.
//!   An object whose method was set by hand must not hold a *functional* engine reference it no
//!   longer has a table for.
//! * [`RSA_free`] decrements first and returns **without touching anything** on a positive
//!   remainder; then the method's `finish`, then the engine, then the ex-data and the lock, then
//!   the key material, then the PSS pointer, the multi-prime stack, the blinding store and finally
//!   the object. `n` and `e` are `BN_free`d and the six secret components `BN_clear_free`d,
//!   because `OPENSSL_PEDANTIC_ZEROIZATION` is not defined on this profile.
//! * [`RSA_set0_multi_prime_params`] is a transaction. The old stack is released only after the
//!   new one is installed *and* `ossl_rsa_multip_calc_product` has succeeded, and a failure
//!   restores `r->prime_infos` before the `err:` label releases the new stack.
//!
//! ## Macro spellings, checked rather than assumed
//!
//! * `BN_num_bytes(a)` (`include/openssl/bn.h`) is `((BN_num_bits(a) + 7) / 8)`, so [`RSA_size`] is
//!   written as the body behind it, exactly as `court/bn-rand.rs` documents for `BN_zero`.
//! * `CRYPTO_NEW_REF` / `CRYPTO_FREE_REF`, `CRYPTO_UP_REF` / `CRYPTO_DOWN_REF` and
//!   `REF_ASSERT_ISNT` / `REF_PRINT_COUNT` are `include/internal/refcount.h`. The profile's arm is
//!   the `__GNUC__` one (`HAVE_ATOMICS`, `int val`, `__atomic_fetch_*`), so `CRYPTO_DOWN_REF` is a
//!   release fetch-sub with an acquire fence at zero, `CRYPTO_UP_REF` is a relaxed fetch-add, and
//!   `CRYPTO_FREE_REF` is empty. `REF_ASSERT_ISNT` is `NDEBUG`-gated and `NDEBUG` **is** defined
//!   in the admitted build (`docs/DECISIONS.md` D167's measurement), so it is empty;
//!   `REF_PRINT_COUNT` is an `OSSL_TRACE3`, which is not part of the observable contract when
//!   tracing is off, so it is omitted with this sentence as its record.
//! * The typed stacks are `DEFINE_STACK_OF(RSA_PRIME_INFO)` (`rsa_local.h:28`),
//!   `DEFINE_STACK_OF(BIGNUM)` (`:752`) and `DEFINE_SPECIAL_STACK_OF_CONST(BIGNUM_const, BIGNUM)`
//!   (`:874`), so each generated call is transcribed as the generic `OPENSSL_sk_*` entry point —
//!   the same substitution `src/asn1/i2d.rs:815` and `src/asn1/d2i.rs:2013` make. The one place it
//!   is not a plain rename is `pop_free`: the generated form takes a *typed* destructor, so
//!   `multip_info_free_thunk` and `multip_info_free_ex_thunk` (defined once in `crate::rsa::mp`)
//!   are the adapters this crate's stacks take directly.
//! * `OPENSSL_free` is `CRYPTO_free(p, OPENSSL_FILE, OPENSSL_LINE)` in this profile, so it is
//!   written with `rsa_lib.c`'s own file string.
//! * `ossl_assert(x)` at `:823` is `NDEBUG`-gated: `(x) != 0`, a plain check that returns its
//!   argument and **not** the `OPENSSL_die` form, so it is written as the test it reduces to.
//! * `safe_BN_num_bits` (`:911`) is spelled out as [`safe_bn_num_bits`], so a NULL component counts
//!   as **zero** bits rather than faulting.
//! * `#ifdef OPENSSL_PEDANTIC_ZEROIZATION` does not hold on this profile — no
//!   `-DOPENSSL_PEDANTIC_ZEROIZATION` appears in the pinned Configure line — so [`RSA_free`]
//!   releases `n` and `e` with `BN_free`, not `BN_clear_free`. `#ifndef FIPS_MODULE` holds
//!   throughout, so every `#ifndef FIPS_MODULE` block is compiled and its `#ifdef FIPS_MODULE`
//!   twin is not.
//!
//! ## The two `err:` labels in this file, and exactly what each frees
//!
//! * [`RSA_set0_multi_prime_params`] (`:549`): frees the **new** stack with
//!   `ossl_rsa_multip_info_free_ex` — the variant that releases only `pp` and the record, never
//!   `r`/`d`/`t`, because those now belong to the caller's key. `r->prime_infos` is left alone on
//!   this path except on the `calc_product` failure, which restores the *old* stack before
//!   jumping.
//! * [`ossl_rsa_set0_all_params`] (`:867`): the same pair of facts, with `old_infos` saved
//!   *before* the loop rather than inside it.
//!
//! The third, `rsa_new_intern`'s (`:136`), lands with the constructor in the later commit. It is
//! safe there for the same reason: by the time each of its five failures is reached the reference
//! count is already 1 and every field set so far is one [`RSA_free`] knows how to release.
//!
//! ## Scope: what is transcribed, and what is deliberately left
//!
//! Transcribed here, in authority order: [`RSA_get_method`] (`:40-43`), [`RSA_set_method`]
//! (`:45-63`), [`RSA_free`] (`:141-191`), [`RSA_up_ref`] (`:193-203`), the
//! [`ossl_rsa_get0_libctx`]/[`ossl_rsa_set0_libctx`] pair (`:205-213`),
//! [`RSA_set_ex_data`]/[`RSA_get_ex_data`] (`:216-224`), the fixed-point arithmetic and
//! [`ossl_ifc_ffc_compute_security_bits`] (`:235-385`), [`RSA_security_bits`] (`:387-401`), the
//! three `set0_*` setters (`:403-483`), [`RSA_set0_multi_prime_params`] (`:490-553`), the twelve
//! `get0_*` readers and [`RSA_get_multi_prime_extra_count`] (`:556-685`), the PSS pair
//! (`:687-712`), the flag and version accessors (`:714-733`), [`RSA_get0_engine`] (`:736-739`),
//! [`ossl_rsa_set0_all_params`] (`:752-872`), [`ossl_rsa_get0_all_params`] (`:876-909`) and
//! [`ossl_rsa_check_factors`] (`:912-959`) — and, from the adjacent translation unit,
//! [`RSA_bits`] (`rsa_crpt.c:23-26`), [`RSA_size`] (`:28-31`) and [`RSA_flags`] (`:57-60`).
//!
//! Left out of this slice, each named rather than silently dropped:
//!
//! * **`RSA_pkey_ctx_ctrl`** (`:741-749`). Its first act is to read `ctx->pmeth->pkey_id`, so it is
//!   `EVP_PKEY_CTX` glue rather than an object accessor, and it belongs with 8.4's slice E.
//! * **`int_set_rsa_md_name` / `int_get_rsa_md_name`** (`:963-1036`). They take an `EVP_PKEY_CTX`
//!   and dispatch through `EVP_PKEY_CTX_get_signature_md`, so they are the provider-side digest
//!   plumbing; their raise sites (`err_sites::RSA_LIB_973`, `RSA_LIB_1013`) are already staged.
//! * **The twenty-three `EVP_PKEY_CTX_*rsa_*` controls** (`:1039-1385`, the file's tail). Slice E,
//!   by name and by construction.
//! * **Everything that belongs to the provider.** The nine `ossl_*` symbols `rsa_lib.c` defines
//!   are all here (the three pure field accessors, the three "all params" helpers,
//!   [`ossl_rsa_set0_pss_params`], [`ossl_rsa_new_with_ctx`]'s is deferred with the constructor,
//!   and [`ossl_ifc_ffc_compute_security_bits`]). What is *not* here is any `ossl_rsa_*` that
//!   reaches the provider layer, and there is none left in the file: every other definition is a
//!   public `RSA_*` entry point or the static `rsa_new_intern` and its arithmetic.
//! * **`RSA_generate_key_ex` is not in this file at all.** It is `crypto/rsa/rsa_gen.c:41`, and it
//!   is `BLOCKED_HANDOFFS` row (3)'s — Phase 9, on `BN_generate_prime_ex2` → `RAND_bytes_ex`.
//! * **`RSA_dup` does not exist in 3.6.4.** Nor does `RSA_get0_provider`, `RSA_get0_libctx`,
//!   `RSA_PKCS1_SSLeay`, `RSA_method_name` or `RSA_method_modes`: a case-sensitive search of the
//!   whole authority tree finds none of the six. The nearest names, named rather than substituted:
//!   `ossl_rsa_dup(const RSA *, int selection)` (`crypto/rsa/rsa_backend.c:467`, a provider-backend
//!   copy), [`ossl_rsa_get0_libctx`] (`:205` here), and the `RSA_meth_*` family's
//!   `RSA_meth_get0_name` (`rsa_meth.c:62`). The default method family — `RSA_get_default_method`,
//!   `RSA_set_default_method`, `RSA_PKCS1_OpenSSL`, `RSA_null_method` — is
//!   `crypto/rsa/rsa_ossl.c:86-102` and **not** `rsa_lib.c`; three of the four are Phase 9's
//!   hand-off, and the fourth, `RSA_null_method`, is already landed in `crate::rsa`.
//! * **The `RSA_meth_*` family** is `crypto/rsa/rsa_meth.c:20-279`, already transcribed in
//!   `crate::rsa` (slice B, D284).
//! * **`RSA_padding_add_*` / `RSA_padding_check_*` and the `RSA_PKCS1_*` padding selectors** live in
//!   `rsa_none.c`, `rsa_x931.c`, `rsa_pk1.c`, `rsa_oaep.c`, `rsa_pss.c` and `rsa_ssl.c`, and their
//!   landed half is in `crate::rsa` (slice C, D285). No body in this file reads a selector, so
//!   none is transcribed.
//! * [`RSA_flags`] is **not** `r->flags`. It answers `r->meth->flags` (`rsa_crpt.c:59`), and
//!   answers `0` for a NULL object — the only accessor in this slice with a NULL guard. It is here
//!   because the plan's slice A names it beside [`RSA_set_flags`]; the reader that would notice
//!   the difference is 8.4's slice D.
//!
//! ## The court that will drive it: `RT-RSA`
//!
//! `courts/phase8/rt_rsa_probe.c` has **no arm for any export in this file** yet, and that is not
//! an oversight: every arm it has calls a symbol from `rsa_meth.c`, `rsa_none.c`, `rsa_x931.c`,
//! `rsa_pk1.c` or `rsa_oaep.c` — slice B's and slice C's — and the probe never calls one from
//! `rsa_lib.c` or `rsa_crpt.c`. Its header says why the nearest names are absent: `RSA_set_method`,
//! `RSA_get_default_method` and `RSA_set_default_method` "are slice A's, and until slice A lands
//! they are not symbols the candidate shell publishes".
//!
//! What the probe already supplies is the machinery those arms need, and the observability is worth
//! writing down before the arms are written:
//!
//! * `drain(arm)` prints each queued record's packed code **and** its coordinate, which is what the
//!   refusal arms call. The observation it will make is that the three `set0_*` refusals and the
//!   three multi-prime refusals raise **nothing** — `rsa_lib.c` has no `ERR_raise` in any accessor;
//!   the whole file's four `raise_site` calls are inside `rsa_new_intern` — so their `drain`
//!   transcript is an **empty queue**, and that emptiness is the observation.
//! * `begin()`/`end()` with an installed `CRYPTO_set_mem_functions` is the allocator-attribution
//!   plane [`RSA_free`] needs, and the plane on which its `BN_free`-for-`n`/`e` asymmetry is
//!   visible at all.
//! * An arm for any accessor needs an `RSA *`, and no constructor exists on the candidate side
//!   until the later commit. The integration plan's §4a supplies the object by fabricating it in the
//!   probe — 216 bytes, `memset`, every offset pinned by a `_Static_assert` — and holds it to the
//!   same bytes on both sides; the layout tests in `crate::rsa` are what pin the *candidate's*
//!   offsets against that fabric.
//! * [`RSA_bits`]/[`RSA_size`]/[`RSA_security_bits`] are pure functions of `n`, and
//!   [`RSA_flags`]/[`RSA_free`] need no object at all (their NULL arms), so those are the arms that
//!   need no fabrication. The unit tests below are their Rust-side half.
//!
//! SPDX-License-Identifier: Apache-2.0

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use crate::bn::bignum::{BN_clear_free, BN_free, BN_num_bits, BN_set_flags, BigNum};
use crate::evp::pkey_asn1::Engine;
use crate::rsa::mp::{
    multip_info_free_ex_thunk, multip_info_free_thunk, ossl_rsa_multip_calc_product,
    ossl_rsa_multip_cap, ossl_rsa_multip_info_free, ossl_rsa_multip_info_new,
};
use crate::rsa::ossl::ossl_rsa_free_blinding;
use crate::rsa::{Rsa, RsaMethod, RsaPrimeInfo, RsaPssParams, RsaPssParams30};
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_set_ex_data, CRYPTO_EX_INDEX_RSA,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_new_reserve,
    OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::runtime::thread::CRYPTO_THREAD_lock_free;

/// `__FILE__` at `rsa_lib.c`'s allocation and free sites, for the `CRYPTO_zalloc`/`CRYPTO_free`
/// records [`RSA_free`] and [`ossl_rsa_set0_all_params`] make. `rsa_lib.c` is a source-tree file,
/// so the compiler's path carries the prefix — the same string `src/runtime/err_sites.rs:20177`
/// records for `RSA_LIB_85`.
const FILE_RSA_LIB: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_lib.c".as_ptr();
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `RSA_ASN1_VERSION_DEFAULT` — `include/openssl/rsa.h:61`. The `version` a two-prime key has.
const RSA_ASN1_VERSION_DEFAULT: i32 = 0;
/// `RSA_ASN1_VERSION_MULTI` — `include/openssl/rsa.h:62`. Set by [`RSA_set0_multi_prime_params`] and
/// by [`ossl_rsa_set0_all_params`] when there are more than two primes, and the flag
/// [`RSA_security_bits`] reads before trusting `prime_infos`.
const RSA_ASN1_VERSION_MULTI: i32 = 1;

/// `RSA_FLAG_CACHE_PUBLIC` — `include/openssl/rsa.h:65`.
#[allow(dead_code)] // read by slice D's crypt entry points, not yet in this crate
const RSA_FLAG_CACHE_PUBLIC: c_int = 0x0002;
/// `RSA_FLAG_CACHE_PRIVATE` — `include/openssl/rsa.h:66`.
#[allow(dead_code)] // read by slice D's crypt entry points, not yet in this crate
const RSA_FLAG_CACHE_PRIVATE: c_int = 0x0004;
/// `RSA_FLAG_BLINDING` — `include/openssl/rsa.h:67`.
#[allow(dead_code)] // read by RSA_blinding_on/_off, which are Phase 9's (BLOCKED_HANDOFFS row 2)
const RSA_FLAG_BLINDING: c_int = 0x0008;
/// `RSA_FLAG_THREAD_SAFE` — `include/openssl/rsa.h:68`.
#[allow(dead_code)] // read by slice D's crypt entry points, not yet in this crate
const RSA_FLAG_THREAD_SAFE: c_int = 0x0010;
/// `RSA_FLAG_EXT_PKEY` — `include/openssl/rsa.h:75`.
#[allow(dead_code)] // read by slice D's crypt entry points, not yet in this crate
const RSA_FLAG_EXT_PKEY: c_int = 0x0020;
/// `RSA_FLAG_NO_BLINDING` — `include/openssl/rsa.h:83`.
#[allow(dead_code)] // read by RSA_blinding_on/_off, which are Phase 9's (BLOCKED_HANDOFFS row 2)
const RSA_FLAG_NO_BLINDING: c_int = 0x0080;
/// `RSA_FLAG_NON_FIPS_ALLOW` — `include/openssl/rsa.h:476`. The **only** flag this slice reads: the
/// constructor masks it *out* of the method's flags twice, so an engine cannot make a key
/// non-FIPS-allowing by supplying a table that sets it.
#[allow(dead_code)] // read by the constructor (`rsa_new_intern`), which lands in a later commit
const RSA_FLAG_NON_FIPS_ALLOW: c_int = 0x0400;
/// `RSA_FLAG_TYPE_MASK` — `include/openssl/rsa.h:117`.
#[allow(dead_code)] // read by rsa_ameth.c's ASN.1 method, which is 8.8's
const RSA_FLAG_TYPE_MASK: c_int = 0xF000;
/// `RSA_FLAG_TYPE_RSA` — `include/openssl/rsa.h:118`.
#[allow(dead_code)] // read by rsa_ameth.c's ASN.1 method, which is 8.8's
const RSA_FLAG_TYPE_RSA: c_int = 0x0000;
/// `RSA_FLAG_TYPE_RSASSAPSS` — `include/openssl/rsa.h:119`.
#[allow(dead_code)] // read by rsa_ameth.c's ASN.1 method, which is 8.8's
const RSA_FLAG_TYPE_RSASSAPSS: c_int = 0x1000;
/// `RSA_FLAG_TYPE_RSAESOAEP` — `include/openssl/rsa.h:120`.
#[allow(dead_code)] // read by rsa_ameth.c's ASN.1 method, which is 8.8's
const RSA_FLAG_TYPE_RSAESOAEP: c_int = 0x2000;

/// `BN_FLG_CONSTTIME` — `include/openssl/bn.h`, `0x04`. Re-stated here as `src/bn/mont.rs:44`,
/// `src/bn/recp.rs:37` and `src/asn1/x_bignum.rs:43` each re-state it: the crate keeps it private
/// per module, and every one of the three `set0_*` setters below passes it to `BN_set_flags` on
/// the operands it takes ownership of.
const BN_FLG_CONSTTIME: c_int = 0x04;

// `RSA_MAX_PRIME_NUM` is **not** re-declared here. Its one reader is `crate::rsa::mp`'s
// `ossl_rsa_multip_cap`, so that module defines it (`src/rsa/mp.rs:59`) and pins it in its own
// ladder test; a second copy in this file would be a second source of truth. It is private to
// `mp`, so this module names it nowhere — no body here reads it.

/// `safe_BN_num_bits(k)` — `rsa_lib.c:911`'s macro, spelled out because the crate has no macro
/// layer. It exists so that a NULL key component counts as **zero** bits rather than faulting,
/// which is why [`ossl_rsa_check_factors`] answers 1 for an object with nothing in it.
///
/// # Safety
/// `k` is NULL or a live `BIGNUM`.
unsafe fn safe_bn_num_bits(k: *const BigNum) -> c_int {
    if k.is_null() {
        0
    } else {
        // SAFETY: `k` is non-NULL and live per the caller's contract.
        unsafe { BN_num_bits(k) }
    }
}

/// `const RSA_METHOD *RSA_get_method(const RSA *rsa)` — `rsa_lib.c:40-43`.
///
/// No copy and no reference: the pointer is the object's own `meth`, borrowed for as long as the
/// object lives.
///
/// # Safety
/// `rsa` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get_method(rsa: *const Rsa) -> *const RsaMethod {
    // SAFETY: `rsa` is live per the contract.
    unsafe { (*rsa).meth }
}

/// `int RSA_set_method(RSA *rsa, const RSA_METHOD *meth)` — `rsa_lib.c:45-63`.
///
/// **Always answers 1, and the old method is shut down before the new one is installed.** The
/// caller is taking responsibility for the engine (the authority's own comment says so), which is
/// why this function releases the object's engine reference and clears the field rather than
/// transferring anything: an object whose method was set by hand must not hold a *functional*
/// engine reference it no longer has a table for.
///
/// The order is load-bearing and is preserved: `finish` on the outgoing table, then the engine
/// release, then the store, then `init` on the incoming table.
///
/// **`ENGINE_finish` is the reachable answer, not a call.** The authority calls
/// `ENGINE_finish(rsa->engine)` between the `finish` and the store; this crate has no engine
/// registry, so `(*rsa).engine` is NULL on every state it can reach and `ENGINE_finish(NULL)`
/// returns 1 without touching anything (`eng_init.c:108-111`). The call is therefore omitted and
/// the `rsa->engine = NULL;` assignment the authority makes beside it is kept — the reduction
/// `src/evp/pkey_asn1.rs:54-60` established. See the module documentation.
///
/// # Safety
/// `rsa` is a live object; `meth` is a live table that outlives its use.
#[no_mangle]
pub unsafe extern "C" fn RSA_set_method(rsa: *mut Rsa, meth: *const RsaMethod) -> c_int {
    // SAFETY: `rsa` is live per the contract.
    let mtmp = unsafe { (*rsa).meth };
    // SAFETY: `mtmp` is the object's own table and is live.
    if let Some(finish) = unsafe { (*mtmp).finish } {
        // SAFETY: `finish` is that table's own destructor for this object.
        unsafe { finish(rsa) };
    }
    // The authority's `ENGINE_finish(rsa->engine)` is omitted: `rsa->engine` is NULL on every
    // state this crate can reach (there is no engine registry to attach one), and
    // `ENGINE_finish(NULL)` returns 1 without touching anything (`eng_init.c:108-111`). The clear
    // below is the assignment the authority makes beside the call.
    // SAFETY: `rsa` is live per the contract.
    unsafe { (*rsa).engine = ptr::null_mut() };
    // SAFETY: `rsa` is live per the contract.
    unsafe { (*rsa).meth = meth };
    // SAFETY: `meth` is live per the contract.
    if let Some(init) = unsafe { (*meth).init } {
        // SAFETY: `init` is that table's own initialiser for this object.
        unsafe { init(rsa) };
    }
    1
}

/// `void RSA_free(RSA *r)` — `rsa_lib.c:141-191`.
///
/// NULL is a no-op. The release order is the contract, and it is transcribed statement for
/// statement:
///
/// 1. the count is decremented and a positive remainder returns **without** touching anything;
/// 2. the method's `finish` (the object is still whole, so a table may read it);
/// 3. the engine release, which has no call on this crate's reachable states (see below);
/// 4. `CRYPTO_free_ex_data`, then the lock, then `CRYPTO_FREE_REF` (a no-op on this profile);
/// 5. then the key material — `BN_free` for `n` and `e` and `BN_clear_free` for the six secret
///    components, which is the profile's answer because `OPENSSL_PEDANTIC_ZEROIZATION` is not
///    defined here;
/// 6. then the PSS parameters, the multi-prime stack through `ossl_rsa_multip_info_free` (the
///    *full* destructor — this is the object's last reference, so `r`/`d`/`t` really are its own),
///    the blinding store, and finally the object.
///
/// The `REF_ASSERT_ISNT(i < 0)` between (1) and (2) is empty under this profile's `NDEBUG`.
///
/// **Two calls the authority makes between (2) and (6) are reduced, and both reductions are
/// reachable answers rather than omissions.** `ENGINE_finish(r->engine)` (step 3) is not a call:
/// there is no engine registry in this crate, so `r->engine` is NULL and `ENGINE_finish(NULL)`
/// returns 1 without touching anything (`eng_init.c:108-111`) — the
/// `src/evp/pkey_asn1.rs:54-60` reduction. `RSA_PSS_PARAMS_free(r->pss)` is not a call either: no
/// state this crate can reach has a non-NULL `r->pss`, so it is `free(NULL)`, which returns
/// immediately (`tasn_fre.c:36-39`).
///
/// # Safety
/// `r` is NULL or a live object, and must not be used again after this call unless a reference
/// remains.
#[no_mangle]
pub unsafe extern "C" fn RSA_free(r: *mut Rsa) {
    if r.is_null() {
        return;
    }

    // `CRYPTO_DOWN_REF(&r->references, &i)`: a release fetch-sub, then the header's conditional
    // acquire fence when the count reaches zero — the object's other mutations must be visible to
    // the destructor, and the destructor must not be reordered ahead of them.
    // SAFETY: `r` is live per the contract.
    let i = unsafe { (*r).references.fetch_sub(1, Ordering::Release) }.wrapping_sub(1);
    if i == 0 {
        core::sync::atomic::fence(Ordering::Acquire);
    }
    if i > 0 {
        return;
    }

    // The authority's `if (r->meth != NULL && r->meth->finish != NULL)`.
    // SAFETY: `r` is live and this is the last reference.
    let meth = unsafe { (*r).meth };
    if !meth.is_null() {
        // SAFETY: `meth` is the object's own table, alive until this statement.
        if let Some(finish) = unsafe { (*meth).finish } {
            // SAFETY: `finish` is that table's own destructor for this object.
            unsafe { finish(r) };
        }
    }

    // The authority's `ENGINE_finish(r->engine)` is omitted: `r->engine` is NULL on every state
    // this crate can reach, and `ENGINE_finish(NULL)` returns 1 without touching anything
    // (`eng_init.c:108-111`). See the module documentation and `src/evp/pkey_asn1.rs:54-60`.

    // SAFETY: `r` is live and `ex_data` is a field of it.
    unsafe {
        CRYPTO_free_ex_data(
            CRYPTO_EX_INDEX_RSA,
            r.cast(),
            ptr::addr_of_mut!((*r).ex_data),
        )
    };
    // SAFETY: `r` is live and `lock` is the lock the constructor created.
    unsafe { CRYPTO_THREAD_lock_free((*r).lock) };

    // `CRYPTO_FREE_REF(&r->references)` is empty on this profile's arm of the header.

    // `#ifdef OPENSSL_PEDANTIC_ZEROIZATION` does not hold, so `n` and `e` are *freed* and the six
    // secret components are *cleared* — the asymmetry is the authority's and is part of what a
    // caller-installed allocator sees.
    // SAFETY: each field is NULL or the object's own `BIGNUM`, and this is the last reference.
    unsafe {
        BN_free((*r).n);
        BN_free((*r).e);
        BN_clear_free((*r).d);
        BN_clear_free((*r).p);
        BN_clear_free((*r).q);
        BN_clear_free((*r).dmp1);
        BN_clear_free((*r).dmq1);
        BN_clear_free((*r).iqmp);
    }

    // The authority's `RSA_PSS_PARAMS_free(r->pss)` is omitted: `r->pss` is NULL on every state
    // this crate can reach, so the call is `free(NULL)`, which returns immediately
    // (`tasn_fre.c:36-39`). See the module documentation.

    // SAFETY: `prime_infos` is NULL or the object's own stack, whose elements are `RSA_PRIME_INFO`
    // records this object owns in their entirety — the *full* destructor, unlike the two `err:`
    // labels, because the key is going away rather than changing hands.
    unsafe {
        OPENSSL_sk_pop_free((*r).prime_infos, Some(multip_info_free_thunk));
    }
    // SAFETY: `r` is live and this is the last reference; the blinding store is its own.
    unsafe { ossl_rsa_free_blinding(r) };
    // SAFETY: `r` is this object's own allocation, released last.
    unsafe { CRYPTO_free(r.cast(), FILE_RSA_LIB, LINE) };
}

/// `int RSA_up_ref(RSA *r)` — `rsa_lib.c:193-203`.
///
/// Answers **1** for any object a caller can legitimately hold, and the `i > 1` test that looks
/// like a condition is the authority's own: `CRYPTO_UP_REF` cannot fail, so the only way to answer
/// 0 is to hand in an object whose count has already reached zero — which is a bug in the caller,
/// not a failure mode of this function. `REF_ASSERT_ISNT(i < 2)` is empty here.
///
/// # Safety
/// `r` is a live object.
#[no_mangle]
pub unsafe extern "C" fn RSA_up_ref(r: *mut Rsa) -> c_int {
    // `CRYPTO_UP_REF` is a *relaxed* fetch-add, and the relaxedness is deliberate: the caller is
    // about to use only those writes it can already see.
    // SAFETY: `r` is live per the contract.
    let i = unsafe { (*r).references.fetch_add(1, Ordering::Relaxed) }.wrapping_add(1);
    if i > 1 {
        1
    } else {
        0
    }
}

/// `OSSL_LIB_CTX *ossl_rsa_get0_libctx(RSA *r)` — `rsa_lib.c:205-208`. Internal
/// (`include/crypto/rsa.h:62`), so `pub(crate)`.
///
/// The parameter is non-`const` in the authority and reads nothing mutable; it is transcribed that
/// way rather than tidied, because the symbol is called from other translation units through this
/// prototype.
///
/// `#[allow(dead_code)]`'s reason: **the first readers are the provider stratum's.** The authority
/// calls it from `providers/implementations/keymgmt/rsa_kmgmt.c:189` (and the KEM's
/// `rsa_kem.c`), which is beyond this phase; no crate code calls it yet.
///
/// # Safety
/// `r` is a live object.
#[allow(dead_code)] // read by the provider keymgmt/KEM, which are a later stratum
pub(crate) unsafe fn ossl_rsa_get0_libctx(r: *mut Rsa) -> *mut c_void {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).libctx }
}

/// `void ossl_rsa_set0_libctx(RSA *r, OSSL_LIB_CTX *libctx)` — `rsa_lib.c:210-213`. Internal.
///
/// A bare store with no reference taken: the context is the caller's to keep alive. Every `set0`
/// shape in this file is the same kind of store, and this is the smallest of them.
///
/// `#[allow(dead_code)]`'s reason: **the first readers are the provider stratum's decode paths**
/// (`decode_der2key.c`, `decode_pvk2key.c` and `decode_msblob2key.c`), which are beyond this phase.
///
/// # Safety
/// `r` is a live object; `libctx` is NULL or live for as long as it is read.
#[allow(dead_code)] // read by the provider decode paths, which are a later stratum
pub(crate) unsafe fn ossl_rsa_set0_libctx(r: *mut Rsa, libctx: *mut c_void) {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).libctx = libctx };
}

/// `int RSA_set_ex_data(RSA *r, int idx, void *arg)` — `rsa_lib.c:216-219`.
///
/// # Safety
/// `r` is a live object; `arg` is whatever the index's own free callback expects.
#[no_mangle]
pub unsafe extern "C" fn RSA_set_ex_data(r: *mut Rsa, idx: c_int, arg: *mut c_void) -> c_int {
    // SAFETY: `r` is live and `ex_data` is a field of it.
    unsafe { CRYPTO_set_ex_data(ptr::addr_of_mut!((*r).ex_data), idx, arg) }
}

/// `void *RSA_get_ex_data(const RSA *r, int idx)` — `rsa_lib.c:221-224`.
///
/// # Safety
/// `r` is a live object. The returned pointer is whatever was stored, or NULL.
#[no_mangle]
pub unsafe extern "C" fn RSA_get_ex_data(r: *const Rsa, idx: c_int) -> *mut c_void {
    // SAFETY: `r` is live and `ex_data` is a field of it.
    unsafe { CRYPTO_get_ex_data(ptr::addr_of!((*r).ex_data), idx) }
}

/// The scaling constant of the fixed-point arithmetic below — `rsa_lib.c:235`. A power of two,
/// which the base-two logarithm code assumes, and a multiple of three's exponent so that the scale
/// factor has an exact cube root.
const SCALE: u32 = 1 << 18;
/// `cbrt_scale` — `rsa_lib.c:236`, `1 << (2 * 18 / 3)`.
const CBRT_SCALE: u32 = 1 << (2 * 18 / 3);
/// `log_2` — `rsa_lib.c:239`, `scale * log(2)`.
const LOG_2: u32 = 0x02c5c8;
/// `log_e` — `rsa_lib.c:240`, `scale * log2(M_E)`.
const LOG_E: u32 = 0x05c551;
/// `c1_923` — `rsa_lib.c:241`, `scale * 1.923`, the constant of the SP 800-56B Appendix D formula.
const C1_923: u32 = 0x07b126;
/// `c4_690` — `rsa_lib.c:242`, `scale * 4.690`, the second constant of the same formula.
const C4_690: u32 = 0x12c28f;

/// `static ossl_inline uint64_t mul2(uint64_t a, uint64_t b)` — `rsa_lib.c:247-250`. Multiply two
/// scaled integers and rescale. `wrapping_mul` is the authority's `uint64_t` multiply, which wraps
/// rather than trapping.
fn mul2(a: u64, b: u64) -> u64 {
    a.wrapping_mul(b) / SCALE as u64
}

/// `static uint64_t icbrt64(uint64_t x)` — `rsa_lib.c:259-274`, the shifting nth-root algorithm
/// with the authority's algebraic simplifications. Returns a *scaled* cube root, which is why the
/// return is 64 bits even though the cube root of a 64-bit number is not.
fn icbrt64(x: u64) -> u64 {
    let mut x = x;
    let mut r: u64 = 0;

    let mut s: i32 = 63;
    while s >= 0 {
        r <<= 1;
        let b = 3u64.wrapping_mul(r).wrapping_mul(r + 1).wrapping_add(1);
        if (x >> s) >= b {
            x = x.wrapping_sub(b << s);
            r += 1;
        }
        s -= 3;
    }
    r.wrapping_mul(CBRT_SCALE as u64)
}

/// `static uint32_t ilog_e(uint64_t v)` — `rsa_lib.c:283-307`: a base-two logarithm scaled by
/// `scale`, then rescaled into base `e`. The argument must exceed one, so the authority's
/// fractional-input loop — and the signedness it would force on `r` — is absent, as its comment
/// says.
fn ilog_e(v: u64) -> u32 {
    let mut v = v;
    let mut r: u32 = 0;

    while v >= 2 * SCALE as u64 {
        v >>= 1;
        r = r.wrapping_add(SCALE);
    }
    let mut i: u32 = SCALE / 2;
    while i != 0 {
        v = mul2(v, v);
        if v >= 2 * SCALE as u64 {
            v >>= 1;
            r = r.wrapping_add(i);
        }
        i /= 2;
    }
    (r.wrapping_mul(SCALE) as u64 / LOG_E as u64) as u32
}

/// `uint16_t ossl_ifc_ffc_compute_security_bits(int n)` — `rsa_lib.c:326-385`.
///
/// NIST SP 800-56B rev 2 Appendix D's maximum-security-strength estimate. Internal — declared
/// `include/crypto/security_bits.h:14` — so `pub(crate)`; **and it is shared with DH**:
/// `crypto/dh/dh_gen.c:224` and `crypto/dh/dh_key.c:314` call it, and 8.5 will need the same
/// symbol, which is why there is **one** copy rather than one per module.
///
/// The body is a ladder, and each rung is a different kind of answer:
///
/// * seven **canonical** values come first, answered before any arithmetic, because the standards
///   define them and the formula does not reproduce them exactly;
/// * `n >= 687737` answers the saturating 1200: the authority's comment records that the first
///   inexact result is at `n = 699668` and that the threshold was taken from the smallest `n`
///   whose true answer is 1200, so the clamp starts *below* the formula's own failure;
/// * `n < 8` answers 0;
/// * and the formula's answer is rounded to a multiple of eight, then capped by a rung that exists
///   solely to keep the function non-decreasing — the cap is the authority's own device for the two
///   values the formula over-estimates.
///
/// The two casts are kept rather than widened: `y` is a `uint16_t` in the authority, so the
/// formula's result is truncated at the cast and the `(y + 4) & ~7` is an `int` expression assigned
/// back into 16 bits. `(y as u32 + 4) & !7` with a truncating cast back is that pair of
/// conversions exactly.
///
/// This function reads no pointer and can therefore be called from any context; it is **safe**
/// rather than `unsafe` for exactly that reason, as [`mul2`], [`icbrt64`] and [`ilog_e`] are. The
/// authority's `ossl_` prefix marks it internal, not its callers' obligation.
pub(crate) fn ossl_ifc_ffc_compute_security_bits(n: c_int) -> u16 {
    match n {
        2048 => return 112,  /* SP 800-56B rev 2 Appendix D and FIPS 140-2 IG 7.5 */
        3072 => return 128,  /* SP 800-56B rev 2 Appendix D and FIPS 140-2 IG 7.5 */
        4096 => return 152,  /* SP 800-56B rev 2 Appendix D */
        6144 => return 176,  /* SP 800-56B rev 2 Appendix D */
        7680 => return 192,  /* FIPS 140-2 IG 7.5 */
        8192 => return 200,  /* SP 800-56B rev 2 Appendix D */
        15360 => return 256, /* FIPS 140-2 IG 7.5 */
        _ => {}
    }

    if n >= 687737 {
        return 1200;
    }
    if n < 8 {
        return 0;
    }

    let cap: u16 = if n <= 7680 {
        192
    } else if n <= 15360 {
        256
    } else {
        1200
    };

    // `n` is at least 8 here, so the `int`-to-`uint64_t` conversion the authority spells out is a
    // widening of a positive value.
    let x = n as u64 * LOG_2 as u64;
    let lx = ilog_e(x);
    // `(uint16_t)` is the authority's own cast on the formula's result.
    let mut y = (mul2(C1_923 as u64, icbrt64(mul2(mul2(x, lx as u64), lx as u64)))
        .wrapping_sub(C4_690 as u64)
        / LOG_2 as u64) as u16;
    y = ((y as u32 + 4) & !7u32) as u16;
    if y > cap {
        y = cap;
    }
    y
}

/// `int RSA_security_bits(const RSA *rsa)` — `rsa_lib.c:387-401`.
///
/// **The multi-prime version is a refusal, not a lookup.** When the object's version says
/// multi-prime, the extra-prime count must be positive *and* the key must be wide enough for that
/// many primes (`ex_primes + 2 <= ossl_rsa_multip_cap(bits)`); otherwise the answer is 0 rather
/// than the modulus's strength. The authority's comment says why the version is trusted at all:
/// "This ought to mean that we have private key at hand."
///
/// # Safety
/// `rsa` is a live object with a live `n`.
#[no_mangle]
pub unsafe extern "C" fn RSA_security_bits(rsa: *const Rsa) -> c_int {
    // SAFETY: `rsa` is live per the contract and `n` is a live `BIGNUM` — the authority does not
    // test it either.
    let bits = unsafe { BN_num_bits((*rsa).n) };

    /* `#ifndef FIPS_MODULE` — compiled here. */
    // SAFETY: `rsa` is live per the contract.
    if unsafe { (*rsa).version } == RSA_ASN1_VERSION_MULTI {
        // SAFETY: `rsa` is live; `prime_infos` is NULL or the object's own stack, and
        // `OPENSSL_sk_num` answers -1 for NULL rather than faulting.
        let ex_primes = unsafe { OPENSSL_sk_num((*rsa).prime_infos) };
        if ex_primes <= 0 {
            return 0;
        }
        // The authority's single `||` short-circuits here, so the cap is asked for only when there
        // is an extra-prime count to compare against it. `ossl_rsa_multip_cap` reads no pointer and
        // is safe in this crate.
        let cap = ossl_rsa_multip_cap(bits);
        if ex_primes + 2 > cap {
            return 0;
        }
    }

    ossl_ifc_ffc_compute_security_bits(bits) as c_int
}

/// `int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)` — `rsa_lib.c:403-429`.
///
/// **The refusal is about the object, not about the arguments.** A NULL argument is legal whenever
/// the corresponding field is already non-NULL; it is refused only when it would leave `n` or `e`
/// NULL, because a public key without them is not a key. `d` may always be NULL.
///
/// The three fields are replaced **individually and only when the argument is non-NULL**, which
/// makes this file's `set0` family different from the `RSA_meth_*` setters' all-or-nothing shape: a
/// call that stores nothing still answers 1 and still bumps `dirty_cnt`, because the count is
/// bumped unconditionally at the end. The asymmetry between the releases is the authority's: `n`
/// and `e` are `BN_free`d, and `d` — which is secret — is `BN_clear_free`d and marked
/// `BN_FLG_CONSTTIME`.
///
/// # Safety
/// `r` is a live object. On success each non-NULL argument's ownership passes to `r`.
#[no_mangle]
pub unsafe extern "C" fn RSA_set0_key(
    r: *mut Rsa,
    n: *mut BigNum,
    e: *mut BigNum,
    d: *mut BigNum,
) -> c_int {
    // The authority's guard reads both fields, and reading them into locals first keeps every
    // `unsafe` block here a statement preceded by its own `SAFETY` note rather than one hidden
    // inside a compound expression.
    // SAFETY: `r` is live per the contract.
    let (cur_n, cur_e) = unsafe { ((*r).n, (*r).e) };
    if (cur_n.is_null() && n.is_null()) || (cur_e.is_null() && e.is_null()) {
        return 0;
    }

    if !n.is_null() {
        // SAFETY: `r` is live; `r->n` is NULL or the object's own `BIGNUM`.
        unsafe {
            BN_free((*r).n);
            (*r).n = n;
        }
    }
    if !e.is_null() {
        // SAFETY: as above, for `e`.
        unsafe {
            BN_free((*r).e);
            (*r).e = e;
        }
    }
    if !d.is_null() {
        // SAFETY: `r` is live; `r->d` is NULL or the object's own `BIGNUM`, and `d` is the
        // caller's, whose ownership this call takes.
        unsafe {
            BN_clear_free((*r).d);
            (*r).d = d;
            BN_set_flags((*r).d, BN_FLG_CONSTTIME);
        }
    }
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).dirty_cnt = (*r).dirty_cnt.wrapping_add(1) };

    1
}

/// `int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)` — `rsa_lib.c:431-453`.
///
/// The same refusal shape as [`RSA_set0_key`], on the two factors, and both are **secret**: each is
/// `BN_clear_free`d when replaced and marked `BN_FLG_CONSTTIME` on the way in.
///
/// # Safety
/// `r` is a live object. On success each non-NULL argument's ownership passes to `r`.
#[no_mangle]
pub unsafe extern "C" fn RSA_set0_factors(r: *mut Rsa, p: *mut BigNum, q: *mut BigNum) -> c_int {
    // SAFETY: `r` is live per the contract. Read into locals for the same reason as
    // [`RSA_set0_key`]'s guard.
    let (cur_p, cur_q) = unsafe { ((*r).p, (*r).q) };
    if (cur_p.is_null() && p.is_null()) || (cur_q.is_null() && q.is_null()) {
        return 0;
    }

    if !p.is_null() {
        // SAFETY: `r` is live; `r->p` is NULL or the object's own `BIGNUM`.
        unsafe {
            BN_clear_free((*r).p);
            (*r).p = p;
            BN_set_flags((*r).p, BN_FLG_CONSTTIME);
        }
    }
    if !q.is_null() {
        // SAFETY: as above, for `q`.
        unsafe {
            BN_clear_free((*r).q);
            (*r).q = q;
            BN_set_flags((*r).q, BN_FLG_CONSTTIME);
        }
    }
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).dirty_cnt = (*r).dirty_cnt.wrapping_add(1) };

    1
}

/// `int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)` — `rsa_lib.c:455-483`.
///
/// Three fields, three clear-frees, three `BN_FLG_CONSTTIME` marks, and the same refusal rule
/// applied to each: a NULL argument is refused only when that field is empty.
///
/// # Safety
/// `r` is a live object. On success each non-NULL argument's ownership passes to `r`.
#[no_mangle]
pub unsafe extern "C" fn RSA_set0_crt_params(
    r: *mut Rsa,
    dmp1: *mut BigNum,
    dmq1: *mut BigNum,
    iqmp: *mut BigNum,
) -> c_int {
    // SAFETY: `r` is live per the contract. Read into locals for the same reason as
    // [`RSA_set0_key`]'s guard.
    let (cur_dmp1, cur_dmq1, cur_iqmp) = unsafe { ((*r).dmp1, (*r).dmq1, (*r).iqmp) };
    if (cur_dmp1.is_null() && dmp1.is_null())
        || (cur_dmq1.is_null() && dmq1.is_null())
        || (cur_iqmp.is_null() && iqmp.is_null())
    {
        return 0;
    }

    if !dmp1.is_null() {
        // SAFETY: `r` is live; `r->dmp1` is NULL or the object's own `BIGNUM`.
        unsafe {
            BN_clear_free((*r).dmp1);
            (*r).dmp1 = dmp1;
            BN_set_flags((*r).dmp1, BN_FLG_CONSTTIME);
        }
    }
    if !dmq1.is_null() {
        // SAFETY: as above, for `dmq1`.
        unsafe {
            BN_clear_free((*r).dmq1);
            (*r).dmq1 = dmq1;
            BN_set_flags((*r).dmq1, BN_FLG_CONSTTIME);
        }
    }
    if !iqmp.is_null() {
        // SAFETY: as above, for `iqmp`.
        unsafe {
            BN_clear_free((*r).iqmp);
            (*r).iqmp = iqmp;
            BN_set_flags((*r).iqmp, BN_FLG_CONSTTIME);
        }
    }
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).dirty_cnt = (*r).dirty_cnt.wrapping_add(1) };

    1
}

/// `int RSA_set0_multi_prime_params(RSA *r, BIGNUM *primes[], BIGNUM *exps[], BIGNUM *coeffs[],
/// int pnum)` — `rsa_lib.c:490-553`.
///
/// The one setter that is a transaction. Three things about it are the contract:
///
/// * **The refusal is up front and complete**: any of the three arrays NULL, or `pnum == 0`. Each
///   `primes[i]`/`exps[i]`/`coeffs[i]` triple must then be entirely non-NULL — a partial triple
///   sends the new record to `ossl_rsa_multip_info_free` and the whole call to `err:`, which makes
///   this setter all-or-nothing in a way the three above are not.
/// * **Each record's `r`/`d`/`t` placeholders are released before being replaced.**
///   `ossl_rsa_multip_info_new` hands back a record whose three components are fresh allocations,
///   so the caller's are stored over freed ones and nothing leaks.
/// * **The old stack is freed only on success, and the version only on success.** A failed
///   `ossl_rsa_multip_calc_product` restores `r->prime_infos` to the old stack first, and only then
///   does the `err:` label release the new one — so the object is left exactly as it was apart
///   from the placeholders, which the caller never saw.
///
/// # Safety
/// `r` is a live object; each of the three arrays has at least `pnum` elements, all NULL or live;
/// on success the ownership of every non-NULL element passes to `r`.
#[no_mangle]
pub unsafe extern "C" fn RSA_set0_multi_prime_params(
    r: *mut Rsa,
    primes: *mut *mut BigNum,
    exps: *mut *mut BigNum,
    coeffs: *mut *mut BigNum,
    pnum: c_int,
) -> c_int {
    if primes.is_null() || exps.is_null() || coeffs.is_null() || pnum == 0 {
        return 0;
    }

    // `sk_RSA_PRIME_INFO_new_reserve(NULL, pnum)`. `OPENSSL_sk_new_reserve` is safe in this crate;
    // the comparator slot is unused for this stack.
    let prime_infos = OPENSSL_sk_new_reserve(None, pnum);
    if prime_infos.is_null() {
        return 0;
    }

    // SAFETY: `r` is live per the contract; `old` borrows the object's own stack for the duration
    // of this call, and the field is only ever restored to it, never read through.
    let old = unsafe { (*r).prime_infos };

    let ok = 'build: {
        let mut i: c_int = 0;
        while i < pnum {
            // SAFETY: `ossl_rsa_multip_info_new` reads no caller pointer beyond its argument and
            // answers a fresh record or NULL.
            let pinfo = unsafe { ossl_rsa_multip_info_new() };
            if pinfo.is_null() {
                break 'build false;
            }
            // SAFETY: each array has at least `pnum` elements per the contract.
            let (p, e, c) = unsafe {
                (
                    *primes.add(i as usize),
                    *exps.add(i as usize),
                    *coeffs.add(i as usize),
                )
            };
            if p.is_null() || e.is_null() || c.is_null() {
                /* The authority's `else`: release the fresh record in full -- its `r`/`d`/`t`
                 * are the placeholders `ossl_rsa_multip_info_new` made, so the *full*
                 * destructor is correct here, and the record is not on the stack yet. */
                // SAFETY: `pinfo` is this iteration's own record.
                unsafe { ossl_rsa_multip_info_free(pinfo) };
                break 'build false;
            }

            // SAFETY: `pinfo` is this iteration's record; its three components are its own
            // placeholders, and the caller's values are about to be stored over them.
            unsafe {
                BN_clear_free((*pinfo).r);
                BN_clear_free((*pinfo).d);
                BN_clear_free((*pinfo).t);
                (*pinfo).r = p;
                (*pinfo).d = e;
                (*pinfo).t = c;
                BN_set_flags((*pinfo).r, BN_FLG_CONSTTIME);
                BN_set_flags((*pinfo).d, BN_FLG_CONSTTIME);
                BN_set_flags((*pinfo).t, BN_FLG_CONSTTIME);
            }
            // The authority discards this result: a failed push leaves the record out of the
            // stack, and the `err:` path cannot see it. Transcribed rather than added to.
            // SAFETY: `prime_infos` is this call's own stack and `pinfo` is a live record.
            unsafe { OPENSSL_sk_push(prime_infos, pinfo.cast()) };
            i += 1;
        }

        // SAFETY: `r` is live per the contract.
        unsafe { (*r).prime_infos = prime_infos };

        // SAFETY: `ossl_rsa_multip_calc_product` takes the object whose stack was just installed
        // and answers 0 on failure.
        if unsafe { ossl_rsa_multip_calc_product(r) } == 0 {
            // SAFETY: `r` is live; the old stack is still the object's own.
            unsafe { (*r).prime_infos = old };
            break 'build false;
        }

        if !old.is_null() {
            /* The authority's comment: the old records "could also be set by this function and
             * r, d, t should not be freed in that case", so it stays consistent with the other
             * `set0` functions and just frees the stack -- with the *full* destructor, because
             * these records are the key's own old parameters being replaced. */
            // SAFETY: `old` is the object's own previous stack and is no longer referenced.
            unsafe { OPENSSL_sk_pop_free(old, Some(multip_info_free_thunk)) };
        }

        // SAFETY: `r` is live per the contract.
        unsafe {
            (*r).version = RSA_ASN1_VERSION_MULTI;
            (*r).dirty_cnt = (*r).dirty_cnt.wrapping_add(1);
        }
        true
    };

    if !ok {
        /* The `err:` label: `r`, `d` and `t` are not freed -- they now belong to the caller's
         * key, which is what `ossl_rsa_multip_info_free_ex` exists for. */
        // SAFETY: `prime_infos` is this call's own stack; `r->prime_infos` was restored to the old
        // stack on the only path that reaches here with a live object.
        unsafe { OPENSSL_sk_pop_free(prime_infos, Some(multip_info_free_ex_thunk)) };
        return 0;
    }

    1
}

/// `void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)` —
/// `rsa_lib.c:556-565`.
///
/// The authority's `get0` convention: **every out-parameter is optional**, and each is written only
/// when it is non-NULL. A caller that wants one component passes NULL for the others.
///
/// # Safety
/// `r` is a live object. Each non-NULL out-parameter is writable; the values written are borrowed
/// from `r` and must not outlive it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_key(
    r: *const Rsa,
    n: *mut *const BigNum,
    e: *mut *const BigNum,
    d: *mut *const BigNum,
) {
    if !n.is_null() {
        // SAFETY: `r` is live and `n` is the caller's writable slot.
        unsafe { *n = (*r).n };
    }
    if !e.is_null() {
        // SAFETY: as above.
        unsafe { *e = (*r).e };
    }
    if !d.is_null() {
        // SAFETY: as above.
        unsafe { *d = (*r).d };
    }
}

/// `void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)` — `rsa_lib.c:567-573`.
///
/// # Safety
/// `r` is a live object; each non-NULL out-parameter is writable.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_factors(
    r: *const Rsa,
    p: *mut *const BigNum,
    q: *mut *const BigNum,
) {
    if !p.is_null() {
        // SAFETY: `r` is live and `p` is the caller's writable slot.
        unsafe { *p = (*r).p };
    }
    if !q.is_null() {
        // SAFETY: as above.
        unsafe { *q = (*r).q };
    }
}

/// `int RSA_get_multi_prime_extra_count(const RSA *r)` — `rsa_lib.c:576-584`.
///
/// **The `pnum <= 0` fold is the whole function.** `OPENSSL_sk_num` answers **-1** for a NULL
/// stack, and a key with no extra primes must answer 0 rather than -1, so the count is folded.
/// Every reader of the extra primes in this file calls this first and treats 0 as "none", which is
/// why an object that has never seen [`RSA_set0_multi_prime_params`] answers 0 here and not a
/// negative number.
///
/// # Safety
/// `r` is a live object.
#[no_mangle]
pub unsafe extern "C" fn RSA_get_multi_prime_extra_count(r: *const Rsa) -> c_int {
    // SAFETY: `r` is live; `prime_infos` is NULL or the object's own stack.
    let pnum = unsafe { OPENSSL_sk_num((*r).prime_infos) };
    if pnum <= 0 {
        0
    } else {
        pnum
    }
}

/// `int RSA_get0_multi_prime_factors(const RSA *r, const BIGNUM *primes[])` — `rsa_lib.c:586-604`.
///
/// Answers **0** — not a partial fill — when there are no extra primes, and requires the caller to
/// have allocated `primes[count]` itself: the authority's own comment says so, and that is why there
/// is no length out-parameter to check it against.
///
/// # Safety
/// `r` is a live object; `primes` has room for [`RSA_get_multi_prime_extra_count`] pointers.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_multi_prime_factors(
    r: *const Rsa,
    primes: *mut *const BigNum,
) -> c_int {
    // SAFETY: `r` is live per the contract.
    let pnum = unsafe { RSA_get_multi_prime_extra_count(r) };
    if pnum == 0 {
        return 0;
    }

    let mut i: c_int = 0;
    while i < pnum {
        // SAFETY: `r` is live and the stack holds at least `pnum` elements, since the count came
        // from it.
        let pinfo = unsafe { OPENSSL_sk_value((*r).prime_infos, i) }.cast::<RsaPrimeInfo>();
        // SAFETY: `pinfo` is a live record and `primes` is the caller's array.
        unsafe { *primes.add(i as usize) = (*pinfo).r };
        i += 1;
    }

    1
}

/// `void RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1,
/// const BIGNUM **iqmp)` — `rsa_lib.c:607-617`.
///
/// # Safety
/// `r` is a live object; each non-NULL out-parameter is writable.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_crt_params(
    r: *const Rsa,
    dmp1: *mut *const BigNum,
    dmq1: *mut *const BigNum,
    iqmp: *mut *const BigNum,
) {
    if !dmp1.is_null() {
        // SAFETY: `r` is live and `dmp1` is the caller's writable slot.
        unsafe { *dmp1 = (*r).dmp1 };
    }
    if !dmq1.is_null() {
        // SAFETY: as above.
        unsafe { *dmq1 = (*r).dmq1 };
    }
    if !iqmp.is_null() {
        // SAFETY: as above.
        unsafe { *iqmp = (*r).iqmp };
    }
}

/// `int RSA_get0_multi_prime_crt_params(const RSA *r, const BIGNUM *exps[],
/// const BIGNUM *coeffs[])` — `rsa_lib.c:620-644`.
///
/// Unlike [`RSA_get0_multi_prime_factors`], **the two arrays are independently optional**: either
/// may be NULL, and only the non-NULL one is filled. The no-extra-primes arm still answers 0.
///
/// # Safety
/// `r` is a live object; each non-NULL array has room for [`RSA_get_multi_prime_extra_count`]
/// pointers.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_multi_prime_crt_params(
    r: *const Rsa,
    exps: *mut *const BigNum,
    coeffs: *mut *const BigNum,
) -> c_int {
    // SAFETY: `r` is live per the contract.
    let pnum = unsafe { RSA_get_multi_prime_extra_count(r) };
    if pnum == 0 {
        return 0;
    }

    /* The authority's own comment: "it's the user's job to guarantee the buffer length". */
    if !exps.is_null() || !coeffs.is_null() {
        let mut i: c_int = 0;
        while i < pnum {
            // SAFETY: `r` is live and the stack holds at least `pnum` elements.
            let pinfo = unsafe { OPENSSL_sk_value((*r).prime_infos, i) }.cast::<RsaPrimeInfo>();
            if !exps.is_null() {
                // SAFETY: `pinfo` is live and `exps` is the caller's array.
                unsafe { *exps.add(i as usize) = (*pinfo).d };
            }
            if !coeffs.is_null() {
                // SAFETY: as above, for `coeffs`.
                unsafe { *coeffs.add(i as usize) = (*pinfo).t };
            }
            i += 1;
        }
    }

    1
}

/// `const BIGNUM *RSA_get0_n(const RSA *r)` — `rsa_lib.c:647-650`.
///
/// # Safety
/// `r` is a live object. The result is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_n(r: *const Rsa) -> *const BigNum {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).n }
}

/// `const BIGNUM *RSA_get0_e(const RSA *r)` — `rsa_lib.c:652-655`.
///
/// # Safety
/// `r` is a live object. The result is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_e(r: *const Rsa) -> *const BigNum {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).e }
}

/// `const BIGNUM *RSA_get0_d(const RSA *r)` — `rsa_lib.c:657-660`.
///
/// # Safety
/// `r` is a live object. The result is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_d(r: *const Rsa) -> *const BigNum {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).d }
}

/// `const BIGNUM *RSA_get0_p(const RSA *r)` — `rsa_lib.c:662-665`.
///
/// # Safety
/// `r` is a live object. The result is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_p(r: *const Rsa) -> *const BigNum {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).p }
}

/// `const BIGNUM *RSA_get0_q(const RSA *r)` — `rsa_lib.c:667-670`.
///
/// # Safety
/// `r` is a live object. The result is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_q(r: *const Rsa) -> *const BigNum {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).q }
}

/// `const BIGNUM *RSA_get0_dmp1(const RSA *r)` — `rsa_lib.c:672-675`.
///
/// # Safety
/// `r` is a live object. The result is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_dmp1(r: *const Rsa) -> *const BigNum {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).dmp1 }
}

/// `const BIGNUM *RSA_get0_dmq1(const RSA *r)` — `rsa_lib.c:677-680`.
///
/// # Safety
/// `r` is a live object. The result is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_dmq1(r: *const Rsa) -> *const BigNum {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).dmq1 }
}

/// `const BIGNUM *RSA_get0_iqmp(const RSA *r)` — `rsa_lib.c:682-685`.
///
/// # Safety
/// `r` is a live object. The result is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_iqmp(r: *const Rsa) -> *const BigNum {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).iqmp }
}

/// `const RSA_PSS_PARAMS *RSA_get0_pss_params(const RSA *r)` — `rsa_lib.c:687-694`.
///
/// The `#ifdef FIPS_MODULE` arm answers NULL; this profile is not the module, so the body is the
/// field read. That matters because it makes the *pair* of PSS carriers — this pointer and the
/// by-value `pss_params` — two different facts about the same key, and only this one is visible to
/// `rsa_ameth.c`'s ASN.1 method.
///
/// # Safety
/// `r` is a live object. The result is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_pss_params(r: *const Rsa) -> *const RsaPssParams {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).pss }
}

/// `int ossl_rsa_set0_pss_params(RSA *r, RSA_PSS_PARAMS *pss)` — `rsa_lib.c:697-706`. Internal.
///
/// Always answers 1 on this profile: the `#ifdef FIPS_MODULE` arm that answers 0 is not compiled.
/// The old parameters are released first, so a caller replacing them does not leak the old set.
///
/// **The release is written as the reachable answer.** The authority calls
/// `RSA_PSS_PARAMS_free(r->pss)`, which would be `free(NULL)` on every state this crate can reach —
/// this function's own writer is the only way `r->pss` becomes non-NULL, its caller is
/// `crypto/rsa/rsa_backend.c:669`, and every `RSA_PSS_PARAMS *` comes from slice F's
/// `d2i_RSA_PSS_PARAMS`, which is not landed. The call is therefore omitted, and
/// `RSA_PSS_PARAMS_free` is not exported at all. See the module documentation.
///
/// `#[allow(dead_code)]`'s reason: **the first reader is Phase 9's**
/// `ossl_rsa_set0_all_params`/`rsa_backend.c` key loader (`:669`); nothing in this commit calls it.
///
/// # Safety
/// `r` is a live object; on return `r` owns `pss`.
#[allow(dead_code)] // read by rsa_backend.c's key loader, which is Phase 9's
pub(crate) unsafe fn ossl_rsa_set0_pss_params(r: *mut Rsa, pss: *mut RsaPssParams) -> c_int {
    // SAFETY: `r` is live and `pss` is the caller's, whose ownership this call takes. The
    // authority's `RSA_PSS_PARAMS_free(r->pss)` is omitted — it is `free(NULL)` on every reachable
    // state (`tasn_fre.c:36-39`).
    unsafe { (*r).pss = pss };
    1
}

/// `RSA_PSS_PARAMS_30 *ossl_rsa_get0_pss_params_30(RSA *r)` — `rsa_lib.c:709-712`. Internal.
///
/// **A pointer to the object's own by-value member**, not a copy and not a borrow of a separate
/// allocation: the caller is handed the address of `r->pss_params` and may write through it. That is
/// why the parameter is non-`const` in the authority, and why the return type is not.
///
/// `#[allow(dead_code)]`'s reason: **the first readers are Phase 9's and the provider stratum's**
/// — `crypto/rsa/rsa_backend.c:591` and the provider keymgmt/signature/der modules; nothing in this
/// commit calls it.
///
/// # Safety
/// `r` is a live object. The result aliases its storage and must not outlive it.
#[allow(dead_code)] // read by rsa_backend.c and the provider keymgmt/signature/der, all later
pub(crate) unsafe fn ossl_rsa_get0_pss_params_30(r: *mut Rsa) -> *mut RsaPssParams30 {
    // SAFETY: `r` is live per the contract. `addr_of_mut!` avoids forming an intermediate
    // reference to the member, but its place projection still dereferences the raw pointer, so the
    // computation is inside this block.
    unsafe { ptr::addr_of_mut!((*r).pss_params) }
}

/// `void RSA_clear_flags(RSA *r, int flags)` — `rsa_lib.c:714-717`.
///
/// # Safety
/// `r` is a live object.
#[no_mangle]
pub unsafe extern "C" fn RSA_clear_flags(r: *mut Rsa, flags: c_int) {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).flags &= !flags };
}

/// `int RSA_test_flags(const RSA *r, int flags)` — `rsa_lib.c:719-722`.
///
/// **It answers the masked word, not a boolean.** A caller that tests one flag and compares against
/// 1 is reading a value this function never promised; the `RT-RSA` arms that will cover it must
/// compare against the flag itself, as the probe's `ROUNDTRIP` pairs already do for the method
/// table's members. There is no NULL guard: unlike [`RSA_flags`], which reads `r->meth->flags`, this
/// one is a plain field read.
///
/// # Safety
/// `r` is a live object.
#[no_mangle]
pub unsafe extern "C" fn RSA_test_flags(r: *const Rsa, flags: c_int) -> c_int {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).flags & flags }
}

/// `void RSA_set_flags(RSA *r, int flags)` — `rsa_lib.c:724-727`.
///
/// # Safety
/// `r` is a live object.
#[no_mangle]
pub unsafe extern "C" fn RSA_set_flags(r: *mut Rsa, flags: c_int) {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).flags |= flags };
}

/// `int RSA_get_version(RSA *r)` — `rsa_lib.c:729-733`.
///
/// The header's comment is the whole contract: "`{ two-prime(0), multi(1) }`". The parameter is
/// non-`const` in the authority, and this is the reader [`RSA_security_bits`] uses to decide whether
/// the extra primes are trustworthy.
///
/// # Safety
/// `r` is a live object.
#[no_mangle]
pub unsafe extern "C" fn RSA_get_version(r: *mut Rsa) -> c_int {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).version }
}

/// `ENGINE *RSA_get0_engine(const RSA *r)` — `rsa_lib.c:736-739`.
///
/// No reference is taken or given: the pointer is the object's own functional reference, which
/// [`RSA_free`] and [`RSA_set_method`] are what release.
///
/// **NULL for every object this crate can build** — the observable consequence of the engine
/// reduction, since there is no engine registry to attach one.
///
/// # Safety
/// `r` is a live object. The result is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_engine(r: *const Rsa) -> *mut Engine {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).engine }
}

/// `int ossl_rsa_set0_all_params(RSA *r, STACK_OF(BIGNUM) *primes, STACK_OF(BIGNUM) *exps,
/// STACK_OF(BIGNUM) *coeffs)` — `rsa_lib.c:752-872`. Internal.
///
/// The stack-shaped form of the whole key, and **the one function in this file that consumes its
/// input**: the authority's own comment says the values are deleted from the caller's stacks "as
/// they are consumed and set in the RSA key", so that a failed call leaves the uncontested elements
/// behind for the caller to free and a successful one leaves the stacks empty of everything the key
/// took. The deletion is done with `delete 0` twice rather than two `pop`s, because index 0 is the
/// front and the authority is explicit about why.
///
/// **The shapes are checked as a triple, not one at a time**: `pnum == num(exps) && pnum ==
/// num(coeffs) + 1` decides whether the CRT parameters are taken at all. A caller that supplies
/// primes and no exponents gets a key with factors and no CRT parameters rather than a refusal —
/// which is why the version store at the end can say `MULTI` for a key whose `p` is set and whose
/// `iqmp` is not.
///
/// `#[allow(dead_code)]`'s reason: **the first reader is Phase 9's** key loader,
/// `crypto/rsa/rsa_backend.c:198`/`:216`; nothing in this commit calls it.
///
/// # Safety
/// `r` is a live object; each stack is NULL or live and holds live `BIGNUM`s; the key takes
/// ownership of the elements it consumes.
#[allow(dead_code)] // read by rsa_backend.c's key loader, which is Phase 9's
pub(crate) unsafe fn ossl_rsa_set0_all_params(
    r: *mut Rsa,
    primes: *mut OpenSslStack,
    exps: *mut OpenSslStack,
    coeffs: *mut OpenSslStack,
) -> c_int {
    if primes.is_null() || exps.is_null() || coeffs.is_null() {
        return 0;
    }

    // SAFETY: the three stacks are live per the contract.
    let pnum = unsafe { OPENSSL_sk_num(primes) };
    /* "we need at least 2 primes" */
    if pnum < 2 {
        return 0;
    }

    // SAFETY: `r` is live and the stack holds at least two `BIGNUM`s; ownership of the first two
    // moves to the key when this succeeds. `sk_BIGNUM_value(st, i)` is the generic form of the
    // generated getter.
    if unsafe {
        RSA_set0_factors(
            r,
            OPENSSL_sk_value(primes, 0).cast::<BigNum>(),
            OPENSSL_sk_value(primes, 1).cast::<BigNum>(),
        )
    } == 0
    {
        return 0;
    }

    /* "we also use delete 0 here as we are grabbing items from the end of the stack rather than
     * the start, otherwise we could use pop" -- and the second delete sees the third element
     * shifted down into slot 0. */
    // SAFETY: `primes` is live and holds at least the two elements just consumed.
    unsafe {
        OPENSSL_sk_delete(primes, 0);
        OPENSSL_sk_delete(primes, 0);
    }

    // SAFETY: the three stacks are live per the contract.
    if pnum == unsafe { OPENSSL_sk_num(exps) } && pnum == unsafe { OPENSSL_sk_num(coeffs) } + 1 {
        // SAFETY: `r` is live and both stacks have the element count the test just established.
        if unsafe {
            RSA_set0_crt_params(
                r,
                OPENSSL_sk_value(exps, 0).cast::<BigNum>(),
                OPENSSL_sk_value(exps, 1).cast::<BigNum>(),
                OPENSSL_sk_value(coeffs, 0).cast::<BigNum>(),
            )
        } == 0
        {
            return 0;
        }

        // SAFETY: the two stacks hold at least the elements just consumed.
        unsafe {
            OPENSSL_sk_delete(exps, 0);
            OPENSSL_sk_delete(exps, 0);
            OPENSSL_sk_delete(coeffs, 0);
        }
    }

    // SAFETY: `r` is live per the contract.
    let old_infos = unsafe { (*r).prime_infos };
    /* The authority declares `prime_infos` at function scope, next to `old_infos`, and assigns it
     * inside the `pnum > 2` block; the `err:` label is inside that block too, so the release below
     * can only be reached with a stack in hand. It is hoisted to function scope here for the same
     * reason. */
    let mut prime_infos: *mut OpenSslStack = ptr::null_mut();

    let ok = 'build: {
        if pnum > 2 {
            // `sk_RSA_PRIME_INFO_new_reserve(NULL, pnum)`. `OPENSSL_sk_new_reserve` is safe in this
            // crate; the comparator slot is unused for this stack.
            prime_infos = OPENSSL_sk_new_reserve(None, pnum);
            if prime_infos.is_null() {
                break 'build false;
            }

            let mut i: c_int = 2;
            while i < pnum {
                // SAFETY: each stack still holds the elements from index 2 up.
                let (prime, exp, coeff) = unsafe {
                    (
                        OPENSSL_sk_pop(primes).cast::<BigNum>(),
                        OPENSSL_sk_pop(exps).cast::<BigNum>(),
                        OPENSSL_sk_pop(coeffs).cast::<BigNum>(),
                    )
                };
                /* `ossl_assert(prime != NULL && exp != NULL && coeff != NULL)`: a plain check
                 * under this profile's NDEBUG, not the `OPENSSL_die` form. */
                if prime.is_null() || exp.is_null() || coeff.is_null() {
                    break 'build false;
                }

                /* "Using ossl_rsa_multip_info_new() is wasteful, so allocate directly": a zeroed
                 * record, so `pp` and `m` start NULL and `ossl_rsa_multip_calc_product` fills `pp`
                 * later. `CRYPTO_zalloc` is safe in this crate. */
                let pinfo = CRYPTO_zalloc(core::mem::size_of::<RsaPrimeInfo>(), FILE_RSA_LIB, LINE)
                    .cast::<RsaPrimeInfo>();
                if pinfo.is_null() {
                    break 'build false;
                }

                // SAFETY: `pinfo` is this iteration's own record and the three values are the ones
                // just consumed from the caller's stacks.
                unsafe {
                    (*pinfo).r = prime;
                    (*pinfo).d = exp;
                    (*pinfo).t = coeff;
                    BN_set_flags((*pinfo).r, BN_FLG_CONSTTIME);
                    BN_set_flags((*pinfo).d, BN_FLG_CONSTTIME);
                    BN_set_flags((*pinfo).t, BN_FLG_CONSTTIME);
                }
                // SAFETY: `prime_infos` is this block's own stack and `pinfo` is a live record.
                unsafe { OPENSSL_sk_push(prime_infos, pinfo.cast()) };
                i += 1;
            }

            // SAFETY: `r` is live per the contract.
            unsafe { (*r).prime_infos = prime_infos };

            // SAFETY: `ossl_rsa_multip_calc_product` answers 0 on failure.
            if unsafe { ossl_rsa_multip_calc_product(r) } == 0 {
                // SAFETY: `r` is live; the old stack is still the object's own.
                unsafe { (*r).prime_infos = old_infos };
                break 'build false;
            }
        }

        if !old_infos.is_null() {
            /* The same "hard to deal with" comment as `RSA_set0_multi_prime_params`: "just free
             * it". */
            // SAFETY: `old_infos` is the object's previous stack and is no longer referenced.
            unsafe { OPENSSL_sk_pop_free(old_infos, Some(multip_info_free_thunk)) };
        }

        // SAFETY: `r` is live per the contract.
        unsafe {
            (*r).version = if pnum > 2 {
                RSA_ASN1_VERSION_MULTI
            } else {
                RSA_ASN1_VERSION_DEFAULT
            };
            (*r).dirty_cnt = (*r).dirty_cnt.wrapping_add(1);
        }
        true
    };

    if !ok {
        /* The `err:` label, reached only from inside the `pnum > 2` block -- the non-`pnum > 2`
         * arms of this function cannot fail -- so `prime_infos` is the stack that block built and
         * the variant that leaves `r`/`d`/`t` to the caller is the right release. */
        // SAFETY: `prime_infos` is this call's own stack or NULL, and its records' `r`/`d`/`t` now
        // belong to the caller's key.
        unsafe { OPENSSL_sk_pop_free(prime_infos, Some(multip_info_free_ex_thunk)) };
        return 0;
    }

    1
}

/// `int ossl_rsa_get0_all_params(RSA *r, STACK_OF(BIGNUM_const) *primes,
/// STACK_OF(BIGNUM_const) *exps, STACK_OF(BIGNUM_const) *coeffs)` — `rsa_lib.c:876-909`. Internal.
///
/// The reader that mirrors the setter above, and unlike it this one **takes nothing**: it pushes
/// borrowed `const BIGNUM *` pointers into the caller's three stacks, which the caller then owns the
/// *stacks* of and none of the elements within. There is no name for the three, either: the second
/// and third stacks are filled in the order `dmp1, dmq1` and `iqmp` — a CRT triple, not a pair and a
/// single — and the extra primes are appended to all three stacks as `r`, `d`, `t`.
///
/// **A public-only key is a success with nothing in the stacks**: "If |p| is NULL, there are no CRT
/// parameters" is an early 1, and a NULL object is a 0.
///
/// `#[allow(dead_code)]`'s reason: **this commit's only reference is [`ossl_rsa_check_factors`]**,
/// which is itself unreached; its first external reader is Phase 9's `rsa_backend.c` and the
/// provider decode path.
///
/// # Safety
/// `r` is NULL or live; each stack is live and writable.
#[allow(dead_code)] // referenced only by `ossl_rsa_check_factors`, whose first caller is Phase 9's
pub(crate) unsafe fn ossl_rsa_get0_all_params(
    r: *mut Rsa,
    primes: *mut OpenSslStack,
    exps: *mut OpenSslStack,
    coeffs: *mut OpenSslStack,
) -> c_int {
    if r.is_null() {
        return 0;
    }

    // SAFETY: `r` is live per the contract.
    if unsafe { RSA_get0_p(r) }.is_null() {
        return 1;
    }

    // SAFETY: `r` is live and each stack is the caller's; the pushed pointers are borrowed from `r`
    // and the caller must not outlive it.
    unsafe {
        OPENSSL_sk_push(primes, RSA_get0_p(r).cast());
        OPENSSL_sk_push(primes, RSA_get0_q(r).cast());
        OPENSSL_sk_push(exps, RSA_get0_dmp1(r).cast());
        OPENSSL_sk_push(exps, RSA_get0_dmq1(r).cast());
        OPENSSL_sk_push(coeffs, RSA_get0_iqmp(r).cast());
    }

    /* `#ifndef FIPS_MODULE` -- compiled here. */
    // SAFETY: `r` is live per the contract.
    let pnum = unsafe { RSA_get_multi_prime_extra_count(r) };
    let mut i: c_int = 0;
    while i < pnum {
        // SAFETY: `r` is live and the stack holds at least `pnum` elements.
        let pinfo = unsafe { OPENSSL_sk_value((*r).prime_infos, i) }.cast::<RsaPrimeInfo>();
        // SAFETY: `pinfo` is live and each stack is the caller's.
        unsafe {
            OPENSSL_sk_push(primes, (*pinfo).r.cast());
            OPENSSL_sk_push(exps, (*pinfo).d.cast());
            OPENSSL_sk_push(coeffs, (*pinfo).t.cast());
        }
        i += 1;
    }

    1
}

/// `int ossl_rsa_check_factors(RSA *r)` — `rsa_lib.c:912-959`. Internal.
///
/// Not a key check: a **sanity** check that every parameter this object holds is no wider than its
/// modulus, asked by the provider layer before it trusts a key it has been handed. It builds the
/// three stacks, fills them with [`ossl_rsa_get0_all_params`] — whose 0 is *discarded*, which is why
/// a completely empty object passes: with no `n`, [`safe_bn_num_bits`] folds every NULL to 0, and
/// "at most 0 bits" is true of the empty comparison — then answers 1 unless some component is
/// strictly wider than `n`.
///
/// The three stacks are released on **both** exits, through the `done:` label the authority's
/// `goto`s share.
///
/// `#[allow(dead_code)]`'s reason: **the first readers are Phase 9's and the provider stratum's** —
/// `crypto/rsa/rsa_backend.c:231` and `decode_der2key.c:933`; nothing in this commit calls it.
///
/// # Safety
/// `r` is a live object; the object's components are live `BIGNUM`s or NULL.
#[allow(dead_code)] // read by rsa_backend.c and the provider decode path, both later
pub(crate) unsafe fn ossl_rsa_check_factors(r: *mut Rsa) -> c_int {
    let mut valid = 0;

    // `sk_BIGNUM_const_new_null()`: `OPENSSL_sk_new_null` is safe in this crate and answers a fresh
    // stack or NULL.
    let factors = OPENSSL_sk_new_null();
    let exps = OPENSSL_sk_new_null();
    let coeffs = OPENSSL_sk_new_null();

    let _done: bool = 'check: {
        if factors.is_null() || exps.is_null() || coeffs.is_null() {
            break 'check false;
        }

        /* The authority discards this result: a public-only key fills nothing and is not a failure
         * here. */
        // SAFETY: `r` is live and the three stacks are this call's own, non-NULL.
        unsafe { ossl_rsa_get0_all_params(r, factors, exps, coeffs) };

        // SAFETY: `r` is live per the contract.
        let n = unsafe { safe_bn_num_bits(RSA_get0_n(r)) };

        // SAFETY: `r` is live per the contract.
        if unsafe { safe_bn_num_bits(RSA_get0_d(r)) } > n {
            break 'check false;
        }

        // SAFETY: the stacks are this call's own and live.
        let nexps = unsafe { OPENSSL_sk_num(exps) };
        let mut i: c_int = 0;
        while i < nexps {
            // SAFETY: `exps` holds borrowed pointers and `i` is within its count.
            let bits = unsafe { safe_bn_num_bits(OPENSSL_sk_value(exps, i).cast::<BigNum>()) };
            if bits > n {
                break 'check false;
            }
            i += 1;
        }

        // SAFETY: as above, for `factors`.
        let nfactors = unsafe { OPENSSL_sk_num(factors) };
        let mut i: c_int = 0;
        while i < nfactors {
            // SAFETY: `factors` holds borrowed pointers and `i` is within its count.
            let bits = unsafe { safe_bn_num_bits(OPENSSL_sk_value(factors, i).cast::<BigNum>()) };
            if bits > n {
                break 'check false;
            }
            i += 1;
        }

        // SAFETY: as above, for `coeffs`.
        let ncoeffs = unsafe { OPENSSL_sk_num(coeffs) };
        let mut i: c_int = 0;
        while i < ncoeffs {
            // SAFETY: `coeffs` holds borrowed pointers and `i` is within its count.
            let bits = unsafe { safe_bn_num_bits(OPENSSL_sk_value(coeffs, i).cast::<BigNum>()) };
            if bits > n {
                break 'check false;
            }
            i += 1;
        }

        valid = 1;
        true
    };

    /* The `done:` label. The stacks hold *borrowed* pointers, so the plain free is the right
     * release: `pop_free` here would free key material this object still owns. */
    // SAFETY: each stack is this call's own allocation.
    unsafe {
        OPENSSL_sk_free(factors);
        OPENSSL_sk_free(exps);
        OPENSSL_sk_free(coeffs);
    }

    valid
}

/// `int RSA_bits(const RSA *r)` — `crypto/rsa/rsa_crpt.c:23-26`.
///
/// The modulus's bit length and nothing else: it is `BN_num_bits(r->n)`, so a zero modulus answers
/// **0** rather than 1, and a caller that wants a byte count wants [`RSA_size`]. There is no NULL
/// guard on `n`, in the authority or here.
///
/// # Safety
/// `r` is a live object with a live `n`.
#[no_mangle]
pub unsafe extern "C" fn RSA_bits(r: *const Rsa) -> c_int {
    // SAFETY: `r` is live per the contract.
    unsafe { BN_num_bits((*r).n) }
}

/// `int RSA_size(const RSA *r)` — `crypto/rsa/rsa_crpt.c:28-31`.
///
/// `BN_num_bytes(r->n)`, written out as the header's macro body — `((BN_num_bits(a) + 7) / 8)` —
/// because the crate has no macro layer and no `BN_num_bytes` symbol; see the module
/// documentation's note on macro spellings. The consequence a caller must know is that the answer is
/// the *modulus's* width and not the key's security level: for a 2048-bit modulus it is 256, and for
/// a zero modulus it is **0**, not 1.
///
/// # Safety
/// `r` is a live object with a live `n`.
#[no_mangle]
pub unsafe extern "C" fn RSA_size(r: *const Rsa) -> c_int {
    // SAFETY: `r` is live per the contract.
    (unsafe { BN_num_bits((*r).n) }.wrapping_add(7)) / 8
}

/// `int RSA_flags(const RSA *r)` — `crypto/rsa/rsa_crpt.c:57-60`.
///
/// **The method table's flags, not the object's.** `r->flags` — the word [`RSA_set_flags`],
/// [`RSA_test_flags`] and [`RSA_clear_flags`] read and write, and the word the constructor masks
/// `RSA_FLAG_NON_FIPS_ALLOW` out of — is a *different* value from the one this function answers,
/// which is `r->meth->flags` on the table that happens to be installed. The NULL guard is the other
/// difference: this is the only accessor in this slice that answers `0` for a NULL object instead of
/// faulting.
///
/// # Safety
/// `r` is NULL or a live object whose `meth` is live.
#[no_mangle]
pub unsafe extern "C" fn RSA_flags(r: *const Rsa) -> c_int {
    if r.is_null() {
        return 0;
    }
    // SAFETY: `r` is non-NULL and live per the contract, and `meth` is its own table.
    unsafe { (*(*r).meth).flags }
}

#[cfg(test)]
mod tests {
    //! The arms that can be justified **from the source alone**: the constants the header defines,
    //! the security-bits ladder's canonical answers and clamps, the `set0_*` refusal and ownership
    //! rules, the `get0` convention that every out-parameter is optional, the flag accessors'
    //! masked-word answer, and the `RSA_bits` / `RSA_size` / `RSA_security_bits` arithmetic over a
    //! plain modulus.
    //!
    //! The two callee modules `crate::rsa::mp` and `crate::rsa::ossl` have landed, so the
    //! multi-prime refusal and the `pnum == 1` setter arm — both of which reach
    //! `ossl_rsa_multip_info_new` / `ossl_rsa_multip_cap` — are testable here and are tested below.
    //!
    //! **What is deliberately not here, and why.** Nothing that needs a real key. The constructor
    //! quartet (`RSA_new`, `RSA_new_method`, `rsa_new_intern`, `ossl_rsa_new_with_ctx`) is not
    //! defined in this commit, and `RSA_free`/`RSA_up_ref` are exercised only through the arms the
    //! caller can build by hand; a test that stubbed a missing name would be a test of the stub,
    //! which is the objection the module documentation makes to a stubbed transcription.

    use super::*;
    use crate::bn::bignum::{BN_get_flags, BN_new, BN_set_bit, BN_set_word};

    /// A zeroed object, which is the state every "no key at all" arm below needs: all eight
    /// `BIGNUM` fields NULL, `prime_infos` NULL, `flags` 0, `version` 0. It is **not** a usable key
    /// and is never passed to [`RSA_free`] — the arms that allocate components release them
    /// themselves.
    fn blank_object() -> Rsa {
        // SAFETY: `Rsa` is a plain aggregate of integers, pointers and two pointer-only data
        // structs, so the all-zero bit pattern is a valid value for it. This is the same device
        // `src/runtime/ex_data.rs`'s tests use for `CRYPTO_EX_DATA`.
        unsafe { core::mem::zeroed() }
    }

    /// `RSA_PRIME_INFO` is five pointers, in the header's order, and the two that this file never
    /// writes (`pp`, `m`) are what makes `ossl_rsa_multip_info_free_ex`'s comment -- "free pp and
    /// pinfo only" -- a statement about a field rather than a whole record. The declaration is
    /// `mp.rs`'s and this arm only reads it, for the reason the module documentation gives.
    #[test]
    fn the_prime_info_is_five_pointers() {
        assert_eq!(core::mem::size_of::<RsaPrimeInfo>(), 40);
        assert_eq!(core::mem::align_of::<RsaPrimeInfo>(), 8);
        assert_eq!(core::mem::offset_of!(RsaPrimeInfo, r), 0);
        assert_eq!(core::mem::offset_of!(RsaPrimeInfo, d), 8);
        assert_eq!(core::mem::offset_of!(RsaPrimeInfo, t), 16);
        assert_eq!(core::mem::offset_of!(RsaPrimeInfo, pp), 24);
        assert_eq!(core::mem::offset_of!(RsaPrimeInfo, m), 32);
    }

    /// **The constants, from the header rather than from the crate's own code.** The two that
    /// matter to this file's behaviour are `RSA_ASN1_VERSION_MULTI`, which [`RSA_security_bits`]
    /// compares against, and `RSA_FLAG_NON_FIPS_ALLOW`, which the constructor masks out; the rest
    /// are the vocabulary of the three flag accessors.
    ///
    /// `RSA_MAX_PRIME_NUM` is deliberately absent: its one reader is `crate::rsa::mp`'s
    /// `ossl_rsa_multip_cap`, so it is declared and pinned there rather than copied here.
    #[test]
    fn the_constants_are_the_headers() {
        assert_eq!(RSA_ASN1_VERSION_DEFAULT, 0);
        assert_eq!(RSA_ASN1_VERSION_MULTI, 1);
        assert_eq!(RSA_FLAG_CACHE_PUBLIC, 0x0002);
        assert_eq!(RSA_FLAG_CACHE_PRIVATE, 0x0004);
        assert_eq!(RSA_FLAG_BLINDING, 0x0008);
        assert_eq!(RSA_FLAG_THREAD_SAFE, 0x0010);
        assert_eq!(RSA_FLAG_EXT_PKEY, 0x0020);
        assert_eq!(RSA_FLAG_NO_BLINDING, 0x0080);
        assert_eq!(RSA_FLAG_NON_FIPS_ALLOW, 0x0400);
        assert_eq!(RSA_FLAG_TYPE_MASK, 0xF000);
        assert_eq!(RSA_FLAG_TYPE_RSASSAPSS, 0x1000);
        assert_eq!(RSA_FLAG_TYPE_RSAESOAEP, 0x2000);
        assert_eq!(BN_FLG_CONSTTIME, 0x04);
    }

    /// The seven canonical answers are returned **before** any arithmetic, so they are the arms
    /// that need no faith in the formula; `n >= 687737` and `n < 8` are the two clamps around it,
    /// and the third loop checks the property the `cap` rung exists to give: the answer is always
    /// a multiple of eight and never above the cap for its band.
    #[test]
    fn the_security_bits_calculator_answers_the_canonical_values_and_its_clamps() {
        assert_eq!(ossl_ifc_ffc_compute_security_bits(2048), 112);
        assert_eq!(ossl_ifc_ffc_compute_security_bits(3072), 128);
        assert_eq!(ossl_ifc_ffc_compute_security_bits(4096), 152);
        assert_eq!(ossl_ifc_ffc_compute_security_bits(6144), 176);
        assert_eq!(ossl_ifc_ffc_compute_security_bits(7680), 192);
        assert_eq!(ossl_ifc_ffc_compute_security_bits(8192), 200);
        assert_eq!(ossl_ifc_ffc_compute_security_bits(15360), 256);

        assert_eq!(ossl_ifc_ffc_compute_security_bits(687737), 1200);
        assert_eq!(ossl_ifc_ffc_compute_security_bits(c_int::MAX), 1200);

        /* The `n < 8` arm, including the negative `n` a caller can reach by passing a width that
         * was computed rather than checked: neither the switch nor the 687737 clamp matches, so
         * the answer is 0. */
        for n in -4..8 {
            assert_eq!(ossl_ifc_ffc_compute_security_bits(n), 0);
        }

        /* The cap bands. `y = (y + 4) & ~7` rounds to a multiple of eight and each cap is a
         * multiple of eight, so no band can escape the property. */
        for n in [9, 16, 1024, 2047, 4095, 5000, 7680] {
            let y = ossl_ifc_ffc_compute_security_bits(n);
            assert!(y <= 192, "n = {n} answered {y}");
            assert_eq!(y % 8, 0, "n = {n} answered {y}");
        }
        for n in [7681, 10000, 15360] {
            let y = ossl_ifc_ffc_compute_security_bits(n);
            assert!(y <= 256, "n = {n} answered {y}");
            assert_eq!(y % 8, 0, "n = {n} answered {y}");
        }
        for n in [15361, 100000, 687736] {
            let y = ossl_ifc_ffc_compute_security_bits(n);
            assert!(y <= 1200, "n = {n} answered {y}");
            assert_eq!(y % 8, 0, "n = {n} answered {y}");
        }
    }

    /// **`RSA_security_bits` on the two-prime path is the calculator plus the modulus's width.**
    /// The arm that matters is the second: `version == RSA_ASN1_VERSION_MULTI` with a NULL
    /// `prime_infos` is the *refusal*. A key whose modulus is 2048 bits answers the canonical 112
    /// whatever its exponent, because 2048 is one of the seven values the ladder answers before any
    /// arithmetic.
    #[test]
    fn rsa_security_bits_is_the_modulus_width_for_a_two_prime_key() {
        let mut r = blank_object();
        // SAFETY: `BN_new` takes no pointers and answers a fresh `BIGNUM` this test owns.
        let n = unsafe { BN_new() };
        r.n = n;
        r.version = RSA_ASN1_VERSION_DEFAULT;

        // SAFETY: `r` and `n` are this test's own; `BN_set_bit(n, 2047)` makes the modulus 2048
        // bits wide without needing a real key or a random prime.
        unsafe {
            assert_eq!(BN_set_bit(n, 2047), 1);
            assert_eq!(RSA_bits(&r), 2048);
            assert_eq!(RSA_size(&r), 256);
            assert_eq!(RSA_security_bits(&r), 112);

            BN_free(n);
        }
    }

    /// **The multi-prime refusal.** `version == RSA_ASN1_VERSION_MULTI` makes
    /// [`RSA_security_bits`] consult the extra-prime count and the cap instead of answering the
    /// modulus's strength, and the three outcomes are distinct:
    ///
    /// * a NULL stack counts as 0 extra primes (`OPENSSL_sk_num(NULL)` is -1, and the `<= 0` fold
    ///   covers both), which is the refusal;
    /// * two extra primes plus `p` and `q` is four, and `ossl_rsa_multip_cap` answers 3 for a
    ///   1024-bit modulus, so the refusal fires on the cap;
    /// * one extra prime is within the cap, and the modulus's strength is the answer.
    ///
    /// The pushed elements are never dereferenced — the function reads the stack's length only —
    /// so two empty `BIGNUM`s stand in for the extra primes.
    #[test]
    fn rsa_security_bits_refuses_a_multi_prime_key_the_cap_cannot_describe() {
        let mut r = blank_object();
        // SAFETY: `BN_new` takes no pointers and answers a fresh `BIGNUM` this test owns.
        let n = unsafe { BN_new() };
        r.n = n;
        r.version = RSA_ASN1_VERSION_MULTI;

        // SAFETY: `r`, `n` and the stack are this test's own; `RSA_security_bits` reads the
        // object's fields and the stack's length only, never the elements' contents.
        unsafe {
            assert_eq!(BN_set_bit(n, 1023), 1);

            // Version says multi-prime but there is no stack: the count folds to 0, which is the
            // refusal rather than the modulus's strength.
            assert_eq!(RSA_security_bits(&r), 0);

            let infos = OPENSSL_sk_new_null();
            let a = BN_new();
            let b = BN_new();
            // `OPENSSL_sk_push` answers the stack's **new count**, so the two pushes answer 1 and
            // 2 -- the count the refusal below is about.
            assert_eq!(OPENSSL_sk_push(infos, a.cast()), 1);
            assert_eq!(OPENSSL_sk_push(infos, b.cast()), 2);
            r.prime_infos = infos;

            // Two extra primes plus p and q is four, and the cap for 1024 bits is three.
            assert_eq!(RSA_security_bits(&r), 0);

            // One extra prime is within the cap, so the modulus's strength is the answer.
            // `OPENSSL_sk_pop` removes from the **end**, so it answers `b` and leaves `a` on the
            // stack -- the count the cap test above is about, not the element's identity.
            assert_eq!(OPENSSL_sk_pop(infos), b.cast::<c_void>());
            assert_eq!(
                RSA_security_bits(&r),
                ossl_ifc_ffc_compute_security_bits(1024) as c_int
            );

            OPENSSL_sk_free(infos);
            BN_free(a);
            BN_free(b);
            BN_free(n);
        }
    }

    /// **`set0_key`'s refusal, six ways.** The rule is about the *object*: a NULL argument is
    /// refused only when it would leave `n` or `e` NULL, and `d` is never refused. Each of the two
    /// refusals is checked on a blank object, then the same call is shown to succeed *after* the
    /// field is populated -- which is the difference between "NULL is refused" and "NULL is refused
    /// only in the empty case".
    #[test]
    fn set0_key_refuses_only_what_would_leave_a_public_key_incomplete() {
        let mut r = blank_object();

        // SAFETY: `r` is this test's own object and every argument is NULL.
        unsafe {
            assert_eq!(
                RSA_set0_key(&mut r, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()),
                0
            );

            let n = BN_new();
            let e = BN_new();
            let d = BN_new();
            assert!(!n.is_null() && !e.is_null() && !d.is_null());

            // `r->n` is NULL and `n` is NULL: refused, and nothing was consumed.
            assert_eq!(RSA_set0_key(&mut r, ptr::null_mut(), e, ptr::null_mut()), 0);
            // `r->e` is still NULL and `e` is NULL: refused too.
            assert_eq!(RSA_set0_key(&mut r, n, ptr::null_mut(), ptr::null_mut()), 0);
            assert!(r.n.is_null() && r.e.is_null() && r.d.is_null());
            assert_eq!(r.dirty_cnt, 0);

            // Both supplied, and `d` too: taken, in this order, and `d` marked const-time.
            assert_eq!(RSA_set0_key(&mut r, n, e, d), 1);
            assert_eq!(r.n, n);
            assert_eq!(r.e, e);
            assert_eq!(r.d, d);
            assert_eq!(BN_get_flags(d, BN_FLG_CONSTTIME), BN_FLG_CONSTTIME);
            assert_eq!(r.dirty_cnt, 1);

            // `d == NULL` is legal while `r->d` is set -- and it stores nothing.
            assert_eq!(
                RSA_set0_key(&mut r, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()),
                1
            );
            assert_eq!(r.n, n);
            assert_eq!(r.d, d);
            assert_eq!(r.dirty_cnt, 2);

            BN_free(n);
            BN_free(e);
            BN_clear_free(d);
        }
    }

    /// `set0_factors` and `set0_crt_params` are the same shape with their own fields, and both mark
    /// every field they take as secret. The refusal is checked on the empty object for each.
    #[test]
    fn set0_factors_and_crt_params_mark_every_component_consttime() {
        let mut r = blank_object();

        // SAFETY: `r` is this test's own object; each `BIGNUM` is this test's own allocation and
        // its ownership passes on success.
        unsafe {
            assert_eq!(
                RSA_set0_factors(&mut r, ptr::null_mut(), ptr::null_mut()),
                0
            );
            let p = BN_new();
            assert_eq!(RSA_set0_factors(&mut r, p, ptr::null_mut()), 0);
            let q = BN_new();
            assert_eq!(RSA_set0_factors(&mut r, p, q), 1);
            assert_eq!(r.p, p);
            assert_eq!(BN_get_flags(p, BN_FLG_CONSTTIME), BN_FLG_CONSTTIME);
            assert_eq!(BN_get_flags(q, BN_FLG_CONSTTIME), BN_FLG_CONSTTIME);
            assert_eq!(r.dirty_cnt, 1);

            assert_eq!(
                RSA_set0_crt_params(&mut r, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()),
                0
            );
            let dmp1 = BN_new();
            let dmq1 = BN_new();
            let iqmp = BN_new();
            assert_eq!(
                RSA_set0_crt_params(&mut r, ptr::null_mut(), dmq1, ptr::null_mut()),
                0
            );
            assert_eq!(RSA_set0_crt_params(&mut r, dmp1, dmq1, iqmp), 1);
            assert_eq!(BN_get_flags(dmp1, BN_FLG_CONSTTIME), BN_FLG_CONSTTIME);
            assert_eq!(BN_get_flags(dmq1, BN_FLG_CONSTTIME), BN_FLG_CONSTTIME);
            assert_eq!(BN_get_flags(iqmp, BN_FLG_CONSTTIME), BN_FLG_CONSTTIME);
            assert_eq!(r.dirty_cnt, 2);

            BN_clear_free(p);
            BN_clear_free(q);
            BN_clear_free(dmp1);
            BN_clear_free(dmq1);
            BN_clear_free(iqmp);
        }
    }

    /// **The `get0` convention**: every out-parameter is optional. A NULL slot is not written and
    /// does not fault, which is the whole reason the authority guards each with `if (x != NULL)`
    /// rather than trusting callers to fill all of them.
    #[test]
    fn get0_writes_only_the_slots_it_was_given() {
        let mut r = blank_object();
        let mut slot: *const BigNum = core::ptr::null();

        // SAFETY: `r` is this test's own object; `slot` is this test's own writable slot and the
        // NULL slots are accepted by contract.
        unsafe {
            RSA_get0_key(&r, &mut slot, ptr::null_mut(), ptr::null_mut());
            assert_eq!(slot, ptr::null());
            RSA_get0_factors(&r, ptr::null_mut(), &mut slot);
            assert_eq!(slot, ptr::null());
            RSA_get0_crt_params(&r, ptr::null_mut(), ptr::null_mut(), &mut slot);
            assert_eq!(slot, ptr::null());

            let n = BN_new();
            assert_eq!(RSA_set0_key(&mut r, n, BN_new(), ptr::null_mut()), 1);
            RSA_get0_key(&r, &mut slot, ptr::null_mut(), ptr::null_mut());
            assert_eq!(slot, n);

            BN_free(n);
            BN_free(r.e);
        }
    }

    /// **The multi-prime accessors answer 0 when there is nothing extra**, and the setters refuse
    /// before doing anything. `OPENSSL_sk_num(NULL)` is -1, so the count's fold is what makes the
    /// first three answers 0 rather than -1. The `pnum == 1` setter arm reaches
    /// `ossl_rsa_multip_info_new` — the record is built, the triple is all-NULL, the record is
    /// released with the *full* destructor and the call answers 0 having stored nothing.
    #[test]
    fn the_multi_prime_accessors_refuse_without_extra_primes() {
        let r = blank_object();
        let mut factors_out: *const BigNum = core::ptr::null();
        let mut exps_out: *const BigNum = core::ptr::null();
        let mut coeffs_out: *const BigNum = core::ptr::null();

        // SAFETY: `r` is this test's own object; the NULL arguments are what the refusal arms need,
        // and the three slots are this test's own (unwritten on these paths).
        unsafe {
            assert_eq!(RSA_get_multi_prime_extra_count(&r), 0);
            assert_eq!(RSA_get0_multi_prime_factors(&r, &mut factors_out), 0);
            assert_eq!(
                RSA_get0_multi_prime_crt_params(&r, &mut exps_out, &mut coeffs_out),
                0
            );
            assert!(factors_out.is_null() && exps_out.is_null() && coeffs_out.is_null());
        }

        let mut r = blank_object();
        let mut primes = [ptr::null_mut::<BigNum>(); 3];
        let mut exps = [ptr::null_mut::<BigNum>(); 3];
        let mut coeffs = [ptr::null_mut::<BigNum>(); 3];

        // SAFETY: `r` is this test's own object; the arrays are this test's own and `pnum == 1`
        // with all-NULL elements is a refusal that stores nothing.
        unsafe {
            assert_eq!(
                RSA_set0_multi_prime_params(
                    &mut r,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    3
                ),
                0
            );
            assert_eq!(
                RSA_set0_multi_prime_params(
                    &mut r,
                    primes.as_mut_ptr(),
                    exps.as_mut_ptr(),
                    coeffs.as_mut_ptr(),
                    0
                ),
                0
            );
            assert_eq!(
                RSA_set0_multi_prime_params(
                    &mut r,
                    primes.as_mut_ptr(),
                    exps.as_mut_ptr(),
                    coeffs.as_mut_ptr(),
                    1
                ),
                0
            );
            assert_eq!(RSA_get_version(&mut r), RSA_ASN1_VERSION_DEFAULT);
            assert_eq!(r.dirty_cnt, 0);
        }
    }

    /// **`RSA_test_flags` answers the masked word**, so a two-flag query against one set flag
    /// answers that flag and not 1; and the flags word this file reads and writes is **not** the one
    /// `RSA_flags` answers, which reads the method table's `flags`.
    #[test]
    fn the_flag_accessors_round_trip_and_rsa_flags_reads_the_table() {
        /* A table of this crate's own, borrowed for the length of the test. It is a local rather
         * than a `static` because `RsaMethod` holds raw pointers and is therefore not `Sync`, and
         * because the point of the arm is the *word* `RSA_flags` reads, not where the table lives.
         */
        let meth = RsaMethod {
            name: core::ptr::null_mut(),
            rsa_pub_enc: None,
            rsa_pub_dec: None,
            rsa_priv_enc: None,
            rsa_priv_dec: None,
            rsa_mod_exp: None,
            bn_mod_exp: None,
            init: None,
            finish: None,
            flags: 0x002a,
            app_data: core::ptr::null_mut(),
            rsa_sign: None,
            rsa_verify: None,
            rsa_keygen: None,
            rsa_multi_prime_keygen: None,
        };

        let mut r = blank_object();

        // SAFETY: `r` is this test's own object and `meth` outlives every use below.
        unsafe {
            assert_eq!(RSA_get_version(&mut r), RSA_ASN1_VERSION_DEFAULT);
            assert_eq!(RSA_test_flags(&r, RSA_FLAG_CACHE_PRIVATE), 0);

            RSA_set_flags(&mut r, RSA_FLAG_CACHE_PRIVATE);
            assert_eq!(
                RSA_test_flags(&r, RSA_FLAG_CACHE_PRIVATE),
                RSA_FLAG_CACHE_PRIVATE
            );
            // The masked-word answer, not a boolean.
            assert_eq!(
                RSA_test_flags(&r, RSA_FLAG_BLINDING | RSA_FLAG_CACHE_PRIVATE),
                RSA_FLAG_CACHE_PRIVATE
            );

            RSA_clear_flags(&mut r, RSA_FLAG_CACHE_PRIVATE);
            assert_eq!(RSA_test_flags(&r, RSA_FLAG_CACHE_PRIVATE), 0);

            // `RSA_flags` is the table's word, and it is the one accessor with a NULL arm.
            assert_eq!(RSA_flags(ptr::null()), 0);
            r.meth = ptr::addr_of!(meth);
            assert_eq!(RSA_flags(&r), 0x002a);
            assert_eq!(r.flags, 0);
        }
    }

    /// **`RSA_bits` and `RSA_size` are the modulus's width and its byte count**, and the two
    /// interesting arms are the ones a caller guesses wrong: a zero modulus answers 0 for both, and
    /// a modulus whose bit length is an exact multiple of eight does not round up. `RSA_size` is
    /// `(BN_num_bits + 7) / 8`, so its answer for 2^8 is 2 and for 2^8 - 1 is 1.
    #[test]
    fn rsa_bits_and_size_are_the_modulus_width_and_byte_count() {
        let mut r = blank_object();
        // SAFETY: `BN_new` takes no pointers and answers a fresh `BIGNUM` this test owns.
        let n = unsafe { BN_new() };
        r.n = n;

        // SAFETY: `r` and `n` are this test's own; the setters take ownership of nothing here.
        unsafe {
            assert_eq!(BN_set_word(n, 0), 1);
            assert_eq!(RSA_bits(&r), 0);
            assert_eq!(RSA_size(&r), 0);

            assert_eq!(BN_set_word(n, 1), 1);
            assert_eq!(RSA_bits(&r), 1);
            assert_eq!(RSA_size(&r), 1);

            assert_eq!(BN_set_word(n, 255), 1);
            assert_eq!(RSA_bits(&r), 8);
            assert_eq!(RSA_size(&r), 1);

            assert_eq!(BN_set_word(n, 256), 1);
            assert_eq!(RSA_bits(&r), 9);
            assert_eq!(RSA_size(&r), 2);

            assert_eq!(BN_set_word(n, 65535), 1);
            assert_eq!(RSA_bits(&r), 16);
            assert_eq!(RSA_size(&r), 2);

            BN_free(n);
        }
    }

    /// The library context is a bare store and a bare read, and the object's PSS member is handed
    /// out **by address**: the pointer `ossl_rsa_get0_pss_params_30` answers has to be the object's
    /// own storage, or a caller that writes through it would be writing into a copy.
    #[test]
    fn the_libctx_store_and_the_pss_pointer_are_bare_field_access() {
        let mut r = blank_object();
        let key = 0x1234usize;
        /* Read the expected address before the call, so the two expressions do not borrow the
         * object at once. */
        let expected: *mut RsaPssParams30 = ptr::addr_of_mut!(r.pss_params);

        // SAFETY: `r` is this test's own object, and the integer is used as an opaque handle for
        // the duration of this test only -- no library context is dereferenced.
        unsafe {
            assert_eq!(ossl_rsa_get0_libctx(&mut r), ptr::null_mut());
            ossl_rsa_set0_libctx(&mut r, key as *mut c_void);
            assert_eq!(ossl_rsa_get0_libctx(&mut r), key as *mut c_void);

            assert_eq!(ossl_rsa_get0_pss_params_30(&mut r), expected);
        }
    }

    /// **`ossl_rsa_get0_all_params` answers 1 for a public-only key and 0 for no key at all**, and
    /// the setter refuses three ways before it touches anything. `ossl_rsa_check_factors` is the arm
    /// worth reading twice: on an object with no `n` the width of every component folds to 0, so an
    /// *empty* object passes the sanity check -- which is what makes it a check on the parameters
    /// that are present rather than on the key's completeness.
    #[test]
    fn the_all_params_pair_and_the_factor_sanity_check() {
        let mut r = blank_object();

        // SAFETY: `r` is this test's own object; the NULL stacks are the refusal arm.
        unsafe {
            assert_eq!(
                ossl_rsa_set0_all_params(&mut r, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()),
                0
            );
        }

        // `OPENSSL_sk_new_null` is safe in this crate and answers a fresh stack.
        let primes = OPENSSL_sk_new_null();
        let exps = OPENSSL_sk_new_null();
        let coeffs = OPENSSL_sk_new_null();
        assert!(!primes.is_null() && !exps.is_null() && !coeffs.is_null());

        // SAFETY: the three stacks are this test's own and live.
        unsafe {
            // One prime, and "we need at least 2 primes".
            let only = BN_new();
            OPENSSL_sk_push(primes, only.cast());
            assert_eq!(ossl_rsa_set0_all_params(&mut r, primes, exps, coeffs), 0);
            assert_eq!(OPENSSL_sk_delete(primes, 0), only.cast::<c_void>());
            BN_free(only);

            // No key at all is refused; a key with no `p` is a *success* with nothing pushed.
            assert_eq!(
                ossl_rsa_get0_all_params(ptr::null_mut(), primes, exps, coeffs),
                0
            );
            assert_eq!(ossl_rsa_get0_all_params(&mut r, primes, exps, coeffs), 1);
            assert_eq!(
                OPENSSL_sk_num(primes) + OPENSSL_sk_num(exps) + OPENSSL_sk_num(coeffs),
                0
            );

            // The empty object passes the sanity check, and the stacks it built are released on
            // both exits.
            assert_eq!(ossl_rsa_check_factors(&mut r), 1);

            OPENSSL_sk_free(primes);
            OPENSSL_sk_free(exps);
            OPENSSL_sk_free(coeffs);
        }
    }
}
