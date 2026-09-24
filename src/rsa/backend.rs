//! `crypto/rsa/rsa_backend.c` — the RSA provider/legacy bridge, Phase 8.4.
//!
//! Seven hundred and thirteen lines and **ten internals** plus two file-local helpers. The
//! unit's own header says what it is for: "the intention with the 'backend' source file is to
//! offer backend support for legacy backends (`EVP_PKEY_ASN1_METHOD` and `EVP_PKEY_METHOD`) and
//! provider implementations alike", and every one of the ten is on one of two paths —
//!
//! * the **parameter paths**, which move an `RSA` in and out of an `OSSL_PARAM[]`:
//!   [`ossl_rsa_fromdata`]/[`ossl_rsa_todata`] for the key itself and the two
//!   `ossl_rsa_pss_params_30_{to,from}data` for the PSS restriction;
//! * the **object paths**, which build, copy and classify an `RSA`:
//!   [`ossl_rsa_dup`], [`ossl_rsa_is_foreign`], [`ossl_rsa_pss_decode`],
//!   [`ossl_rsa_pss_get_param_unverified`], [`ossl_rsa_param_decode`] and
//!   [`ossl_rsa_key_from_pkcs8`].
//!
//! ## Why this unit is the precondition of 8.8 rather than a part of it
//!
//! `crypto/rsa/rsa_ameth.c`'s `pkey_priv_decode`, `pkey_pub_decode`, `pkey_priv_encode` and
//! `pkey_ctrl` read exactly these: the two `todata`/`fromdata` pairs for the PSS restriction,
//! `ossl_rsa_pss_get_param_unverified` for the ASN.1 restriction, `ossl_rsa_key_from_pkcs8` for
//! the PKCS#8 decoder and `ossl_rsa_dup` for `EVP_PKEY_dup`. None of them is a `rsa.h` export —
//! the version script's `local: *;` hides every name here from the DSO — so landing them moves
//! **no ledger row and no court-coverage arm**; what says the work landed is the unit tests
//! beside each transcription, and the compiler. D351 states that in its own terms rather than
//! implying progress.
//!
//! ## The one authority coordinate D348 recorded as waiting for this file
//!
//! [`ossl_rsa_param_decode`] is the function that makes `r->pss` non-NULL, and D348 re-derived
//! that fact when it reconciled `RSA_free`'s omitted `RSA_PSS_PARAMS_free` call: the only writer
//! of the field is `ossl_rsa_set0_pss_params` (`rsa_lib.c:697-706`), whose only authority caller
//! is `ossl_rsa_param_decode` (`rsa_backend.c:669`). That call site now exists, so the omitted
//! free in `src/rsa/object.rs` is one step closer to being reachable -- but `ossl_rsa_param_decode`
//! is itself reached only from [`ossl_rsa_key_from_pkcs8`], which nothing in the crate calls
//! yet. The `#[allow(dead_code)]` notes below carry the reader chain, and D348's two comments in
//! `src/rsa/object.rs` stand unchanged: a function that no landed path calls does not make a
//! field non-NULL.
//!
//! ## What is deliberately **not** here
//!
//! Two authority arms are absent because this profile does not compile them or because the name
//! is not this unit's:
//!
//! * the `#else` `ERR_raise(ERR_LIB_RSA, ERR_R_UNSUPPORTED)` of `ossl_rsa_fromdata`'s multiprime
//!   `derive_from_pq` arm is inside `#ifdef FIPS_MODULE`, which is absent from the admitted
//!   `configuration.h`; the `#ifndef` arm above it is transcribed;
//! * `ossl_rsa_acvp_test_get_params` (`rsa_backend.c:298`) is inside
//!   `#if defined(FIPS_MODULE) && !defined(OPENSSL_NO_ACVP_TESTS)` and is absent for the same
//!   reason.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::a_type::ASN1_TYPE_unpack_sequence;
use crate::asn1::x_algor::{
    ossl_x509_algor_get_md, ossl_x509_algor_mgf1_decode, X509Algor, X509_ALGOR_get0,
};
use crate::bn::bignum::{BN_clear_free, BN_dup, BN_free, BigNum};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex, BnCtx};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_type, EvpMd};
use crate::evp::pkey_ctx::{
    EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, OSSL_PKEY_PARAM_RSA_D, OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ,
    OSSL_PKEY_PARAM_RSA_DIGEST, OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, OSSL_PKEY_PARAM_RSA_E,
    OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PKEY_PARAM_RSA_FACTOR2, OSSL_PKEY_PARAM_RSA_MASKGENFUNC,
    OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, OSSL_PKEY_PARAM_RSA_N, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN,
};
use crate::param_build_set::{
    ossl_param_build_set_bn, ossl_param_build_set_int, ossl_param_build_set_multi_key_bn,
    ossl_param_build_set_utf8_string,
};
use crate::params::build::OSSL_PARAM_BLD;
use crate::params::{
    OSSL_PARAM_get_BN, OSSL_PARAM_get_int, OSSL_PARAM_get_utf8_ptr, OSSL_PARAM_locate_const,
    OsslParam, OSSL_PARAM_UTF8_STRING,
};
use crate::rsa::asn1::{
    d2i_RSAPrivateKey, RSA_PSS_PARAMS_dup, RSA_PSS_PARAMS_free, RSA_PSS_PARAMS_it,
};
use crate::rsa::gen::ossl_rsa_multiprime_derive;
use crate::rsa::mp::ossl_rsa_multip_calc_product;
use crate::rsa::mp_names::{
    ossl_rsa_mp_coeff_names, ossl_rsa_mp_exp_names, ossl_rsa_mp_factor_names,
};
use crate::rsa::object::{
    ossl_rsa_check_factors, ossl_rsa_get0_all_params, ossl_rsa_get0_pss_params_30,
    ossl_rsa_new_with_ctx, ossl_rsa_set0_all_params, ossl_rsa_set0_pss_params, RSA_bits,
    RSA_clear_flags, RSA_free, RSA_get0_key, RSA_get0_pss_params, RSA_get_method, RSA_set0_factors,
    RSA_set0_key, RSA_set_flags, RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA, RSA_FLAG_TYPE_RSASSAPSS,
};
use crate::rsa::ossl::RSA_PKCS1_OpenSSL;
use crate::rsa::pss::{
    ossl_rsa_pss_params_30_hashalg, ossl_rsa_pss_params_30_is_unrestricted,
    ossl_rsa_pss_params_30_maskgenalg, ossl_rsa_pss_params_30_maskgenhashalg,
    ossl_rsa_pss_params_30_saltlen, ossl_rsa_pss_params_30_set_defaults,
    ossl_rsa_pss_params_30_set_hashalg, ossl_rsa_pss_params_30_set_maskgenhashalg,
    ossl_rsa_pss_params_30_set_saltlen, ossl_rsa_pss_params_30_set_trailerfield,
    ossl_rsa_pss_params_30_trailerfield,
};
use crate::rsa::schemes::{
    ossl_rsa_mgf_nid2name, ossl_rsa_oaeppss_md2nid, ossl_rsa_oaeppss_nid2name,
};
use crate::rsa::sp800::ossl_rsa_sp800_56b_derive_params_from_pq;
use crate::rsa::{Rsa, RsaPrimeInfo, RsaPssMaskGen, RsaPssParams, RsaPssParams30};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::ex_data::{CRYPTO_dup_ex_data, CRYPTO_EX_INDEX_RSA};
use crate::runtime::mem::CRYPTO_zalloc;
use crate::runtime::obj::{Asn1Object, OBJ_obj2nid};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::OPENSSL_strcasecmp;

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// A **source-tree** file, so its `__FILE__` carries the `../../src/openssl-3.6.4/` prefix,
/// measured with `strings` on
/// `forensics/authorities/build/openssl-3.6.4-production/crypto/rsa/libcrypto-lib-rsa_backend.o`
/// the same way `src/rsa/mod.rs` measures `rsa_meth.c`'s. It reaches an application through
/// `CRYPTO_set_mem_functions`.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_backend.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

// `OSSL_KEYMGMT_SELECT_*` — `include/openssl/core_dispatch.h:640-652`. Restated per module, as
// `src/ec/backend.rs` and `src/evp/pkey.rs` each restate them: they are properties of the
// provider selection interface and not of this unit.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

/// The `OPENSSL_sk_pop_free` destructor for a stack of `BIGNUM`s, `sk_BIGNUM_pop_free`'s
/// `BN_clear_free` argument in a form the generic stack can call.
///
/// # Safety
/// `p` is NULL or a live `BIGNUM`; the stack's elements are consumed by the call.
pub(crate) unsafe extern "C" fn bn_clear_free_thunk(p: *mut c_void) {
    // SAFETY: the caller's contract; `BN_clear_free` accepts NULL.
    unsafe { BN_clear_free(p.cast::<BigNum>()) };
}

/// `static int collect_numbers(STACK_OF(BIGNUM) *numbers, const OSSL_PARAM params[], const
/// char *names[])` — `rsa_backend.c:38-62`.
///
/// The walker `ossl_rsa_fromdata` uses three times, once per table of
/// [`crate::rsa::mp_names`]: for every name in `names` — which is NULL-terminated, so the loop
/// bound is the table and not a length — a present parameter is converted to a `BIGNUM` and
/// **pushed**; a name the caller did not supply is skipped rather than stored as a NULL.
///
/// The two refusals differ in what they release. A failed conversion leaves nothing to release
/// because `OSSL_PARAM_get_BN` answers a NULL `tmp` on failure; a failed push releases `tmp`
/// itself, because the stack did not take it. A NULL `numbers` is an immediate 0 — the one
/// guard, and it exists because the caller builds the three stacks in one expression.
///
/// # Safety
/// `numbers` is NULL or a live stack; `params` is a key-terminated descriptor array; `names` is
/// a NULL-terminated array of NUL-terminated strings.
unsafe fn collect_numbers(
    numbers: *mut OpenSslStack,
    params: *const OsslParam,
    names: *const *const c_char,
) -> c_int {
    if numbers.is_null() {
        return 0;
    }

    let mut i: usize = 0;
    loop {
        // SAFETY: `names` is NULL-terminated, so the loop ends at the terminator.
        let name = unsafe { *names.add(i) };
        if name.is_null() {
            break;
        }
        // SAFETY: `params` is a key-terminated descriptor array.
        let p = unsafe { OSSL_PARAM_locate_const(params, name) };
        if !p.is_null() {
            let mut tmp: *mut BigNum = ptr::null_mut();
            // SAFETY: `p` is a located live descriptor and `tmp` is writable.
            if unsafe { OSSL_PARAM_get_BN(p, &mut tmp) } == 0 {
                return 0;
            }
            // SAFETY: `numbers` is live and `tmp` is the value just produced.
            if unsafe { OPENSSL_sk_push(numbers, tmp.cast()) } == 0 {
                // SAFETY: the push refused, so this call still owns `tmp`.
                unsafe { BN_clear_free(tmp) };
                return 0;
            }
        }
        i += 1;
    }

    1
}

/// `int ossl_rsa_fromdata(RSA *rsa, const OSSL_PARAM params[], int include_private)` —
/// `rsa_backend.c:64-256`. Internal, declared in `include/crypto/rsa.h`.
///
/// The provider's import path into an `RSA`, and the one function of this unit whose body has
/// three distinct shapes rather than one:
///
/// * **`n` and `e` are mandatory, and the refusal is raised.** The two are converted together in
///   one test, so `ERR_R_PASSED_NULL_PARAMETER` covers "absent" and "present but not a
///   `BIGNUM`" alike.
/// * **`derive_from_pq` is the provider's "compute the rest for me" flag.** With it set, `p` and
///   `q` become mandatory and everything else is derived: two factors go through
///   `ossl_rsa_sp800_56b_derive_params_from_pq`, more than two through
///   `ossl_rsa_multiprime_derive` and `ossl_rsa_set0_all_params`. The authority's comment on the
///   `> 2` arm is why the two `n`/`d` parameters are re-checked there: with three or more extra
///   primes the derivation needs the modulus, and a caller that supplied only factors is refused.
/// * **without it, `n`/`e`/`d` alone is a valid key.** The comment says so — "It's ok if this
///   private key just has n, e and d but only if we're not using derive_from_pq" — and the
///   `sk_BIGNUM_num(factors) != 0` guard is what keeps a key with *some* extra parameters from
///   silently ignoring them.
///
/// The final `ossl_rsa_check_factors` is a **sanity** check rather than a key check: every
/// component must be no wider than `n`, and the refusal's `ERR_raise_data` carries the message
/// the authority's own `#ifndef FIPS_MODULE` compile produces. The authority's `#else` FIPS arm
/// is absent from this profile and is not invented.
///
/// `#[allow(dead_code)]`'s reason: **the readers are the provider keymgmt's `import` and
/// `import_from` and 8.8's `rsa_ameth.c`**, neither of which is in this crate yet; nothing here
/// calls it. The unit test below drives it directly, and is what keeps its three arms honest
/// until then.
///
/// # Safety
/// `rsa` is NULL or a live object; `params` is a key-terminated descriptor array. On success the
/// converted values' ownership passes to `rsa`.
#[allow(dead_code)] // read by the provider keymgmt and 8.8's rsa_ameth.c
pub(crate) unsafe fn ossl_rsa_fromdata(
    rsa: *mut Rsa,
    params: *const OsslParam,
    include_private: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if rsa.is_null() {
            return 0;
        }

        let mut p: *mut BigNum = ptr::null_mut();
        let mut q: *mut BigNum = ptr::null_mut();
        let mut n: *mut BigNum = ptr::null_mut();
        let mut e: *mut BigNum = ptr::null_mut();
        let mut d: *mut BigNum = ptr::null_mut();
        let mut factors: *mut OpenSslStack = ptr::null_mut();
        let mut exps: *mut OpenSslStack = ptr::null_mut();
        let mut coeffs: *mut OpenSslStack = ptr::null_mut();
        let mut derive_from_pq: c_int = 0;
        let mut ctx: *mut BnCtx = ptr::null_mut();

        let param_n = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
        let param_e = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
        let mut param_d: *const OsslParam = ptr::null();

        if param_n.is_null()
            || OSSL_PARAM_get_BN(param_n, &mut n) == 0
            || param_e.is_null()
            || OSSL_PARAM_get_BN(param_e, &mut e) == 0
        {
            raise_site(&err_sites::RSA_BACKEND_83);
            return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
        }

        if include_private != 0 {
            let param_derive = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ);
            if !param_derive.is_null() && OSSL_PARAM_get_int(param_derive, &mut derive_from_pq) == 0
            {
                return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
            }

            param_d = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
            if !param_d.is_null() && OSSL_PARAM_get_BN(param_d, &mut d) == 0 {
                raise_site(&err_sites::RSA_BACKEND_97);
                return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
            }

            if derive_from_pq != 0 {
                ctx = BN_CTX_new_ex((*rsa).libctx);
                if ctx.is_null() {
                    return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
                }

                /* we need at minimum p, q */
                let param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR1);
                let param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR2);
                if param_p.is_null()
                    || OSSL_PARAM_get_BN(param_p, &mut p) == 0
                    || param_q.is_null()
                    || OSSL_PARAM_get_BN(param_q, &mut q) == 0
                {
                    raise_site(&err_sites::RSA_BACKEND_111);
                    return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
                }
            }
        }

        let is_private = !d.is_null();

        if RSA_set0_key(rsa, n, e, d) == 0 {
            return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
        }
        // The key took the three; clearing the locals is what stops the `err:` label from
        // releasing values the object now owns.
        n = ptr::null_mut();
        e = ptr::null_mut();
        d = ptr::null_mut();

        if is_private {
            factors = OPENSSL_sk_new_null();
            exps = OPENSSL_sk_new_null();
            coeffs = OPENSSL_sk_new_null();
            if collect_numbers(factors, params, ossl_rsa_mp_factor_names.0.as_ptr()) == 0
                || collect_numbers(exps, params, ossl_rsa_mp_exp_names.0.as_ptr()) == 0
                || collect_numbers(coeffs, params, ossl_rsa_mp_coeff_names.0.as_ptr()) == 0
            {
                return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
            }

            if derive_from_pq != 0 && OPENSSL_sk_num(exps) == 0 && OPENSSL_sk_num(coeffs) == 0 {
                /*
                 * If we want to use crt to derive our exponents/coefficients, we need to have at
                 * least 2 factors
                 */
                if OPENSSL_sk_num(factors) < 2 {
                    raise_site(&err_sites::RSA_BACKEND_139);
                    return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
                }

                /*
                 * if we have more than two factors, n and d must also have been provided
                 */
                if OPENSSL_sk_num(factors) > 2 && (param_n.is_null() || param_d.is_null()) {
                    raise_site(&err_sites::RSA_BACKEND_149);
                    return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
                }

                if OPENSSL_sk_num(factors) == 2 {
                    if RSA_set0_factors(
                        rsa,
                        OPENSSL_sk_value(factors, 0).cast::<BigNum>(),
                        OPENSSL_sk_value(factors, 1).cast::<BigNum>(),
                    ) == 0
                    {
                        raise_site(&err_sites::RSA_BACKEND_158);
                        return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
                    }
                    /*
                     * once consumed by RSA_set0_factors, pop those off the stack so we don't free
                     * them below
                     */
                    OPENSSL_sk_pop(factors);
                    OPENSSL_sk_pop(factors);

                    /*
                     * Note: Because we only have 2 factors here, there will be no additional
                     * pinfo fields to hold additional factors, and since we set our key and 2
                     * factors above we can skip the call to ossl_rsa_set0_all_params
                     */
                    if ossl_rsa_sp800_56b_derive_params_from_pq(
                        rsa,
                        RSA_bits(rsa),
                        ptr::null(),
                        ctx,
                    ) == 0
                    {
                        raise_site(&err_sites::RSA_BACKEND_177);
                        return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
                    }
                } else {
                    if ossl_rsa_multiprime_derive(
                        rsa,
                        RSA_bits(rsa),
                        OPENSSL_sk_num(factors),
                        (*rsa).e,
                        factors,
                        exps,
                        coeffs,
                    ) == 0
                    {
                        raise_site(&err_sites::RSA_BACKEND_190);
                        return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
                    }

                    if ossl_rsa_set0_all_params(rsa, factors, exps, coeffs) == 0 {
                        raise_site(&err_sites::RSA_BACKEND_199);
                        return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
                    }
                }
            } else if OPENSSL_sk_num(factors) != 0
                && ossl_rsa_set0_all_params(rsa, factors, exps, coeffs) == 0
            {
                /*
                 * It's ok if this private key just has n, e and d but only if we're not using
                 * derive_from_pq
                 */
                return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
            }

            /* sanity check to ensure we used everything in our stacks */
            if OPENSSL_sk_num(factors) != 0
                || OPENSSL_sk_num(exps) != 0
                || OPENSSL_sk_num(coeffs) != 0
            {
                // The authority's `ERR_raise_data` with a format and three counts: assembled with
                // `BIO_snprintf` and then raised, which is how this crate reproduces a formatted
                // data string.
                let mut msg = [0 as c_char; 96];
                BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"There are %d, %d, %d elements left on our factors, exps, coeffs stacks\n"
                        .as_ptr(),
                    OPENSSL_sk_num(factors),
                    OPENSSL_sk_num(exps),
                    OPENSSL_sk_num(coeffs),
                );
                raise_site_data(&err_sites::RSA_BACKEND_223, msg.as_ptr());
                return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
            }
        }

        if ossl_rsa_check_factors(rsa) == 0 {
            raise_site_data(
                &err_sites::RSA_BACKEND_232,
                c"RSA factors/exponents are too big for for n-modulus\n".as_ptr(),
            );
            return fromdata_err(n, e, d, p, q, factors, exps, coeffs, ctx);
        }

        BN_clear_free(p);
        BN_clear_free(q);
        OPENSSL_sk_free(factors);
        OPENSSL_sk_free(exps);
        OPENSSL_sk_free(coeffs);
        BN_CTX_free(ctx);
        1
    }
}

/// The authority's `err:` label of [`ossl_rsa_fromdata`], factored out so every `goto err` above
/// is one call rather than a repeated block.
///
/// It is a **function and not a closure** because the label takes five live locals plus three
/// stacks; the authority's own label reads exactly these, in this order, and `n`/`e`/`d` are NULL
/// on every path that reaches it after [`RSA_set0_key`] consumed them.
///
/// # Safety
/// Each pointer is NULL or an object this call owns and has not yet released.
#[allow(clippy::too_many_arguments)] // the authority's own `err:` label reads this many locals
unsafe fn fromdata_err(
    n: *mut BigNum,
    e: *mut BigNum,
    d: *mut BigNum,
    p: *mut BigNum,
    q: *mut BigNum,
    factors: *mut OpenSslStack,
    exps: *mut OpenSslStack,
    coeffs: *mut OpenSslStack,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: every pointer is NULL or this call's own, per the contract.
    unsafe {
        BN_free(n);
        BN_free(e);
        BN_free(d);
        BN_clear_free(p);
        BN_clear_free(q);
        OPENSSL_sk_pop_free(factors, Some(bn_clear_free_thunk));
        OPENSSL_sk_pop_free(exps, Some(bn_clear_free_thunk));
        OPENSSL_sk_pop_free(coeffs, Some(bn_clear_free_thunk));
        BN_CTX_free(ctx);
    }
    0
}

/// `int ossl_rsa_todata(RSA *rsa, OSSL_PARAM_BLD *bld, OSSL_PARAM params[], int
/// include_private)` — `rsa_backend.c:260-306`. Internal.
///
/// The mirror of [`ossl_rsa_fromdata`], and the three stacks are **`BIGNUM_const`** ones here:
/// `ossl_param_build_set_bn` borrows what it is handed, so nothing in this function may take
/// ownership of a value out of `rsa`. The authority's `DEFINE_SPECIAL_STACK_OF_CONST` above it is
/// that distinction made into a type; in Rust the stack is the same `OpenSslStack` and the
/// distinction is the `*const BigNum` the borrowed pointers are read as.
///
/// **The private block is guarded twice**, on `include_private` and on `rsa_d != NULL`: a public
/// key asked for its private half answers 1 with nothing written, which is what makes
/// `EVP_PKEY_todata` on a public key a success rather than a refusal.
///
/// `#[allow(dead_code)]`'s reason: as [`ossl_rsa_fromdata`].
///
/// # Safety
/// `rsa` is NULL or a live object; `bld` is NULL or a live builder; `params` is NULL or a
/// key-terminated descriptor array.
#[allow(dead_code)] // read by the provider keymgmt's `export` and 8.8's rsa_ameth.c
pub(crate) unsafe fn ossl_rsa_todata(
    rsa: *mut Rsa,
    bld: *mut OSSL_PARAM_BLD,
    params: *mut OsslParam,
    include_private: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut rsa_d: *const BigNum = ptr::null();
        let mut rsa_n: *const BigNum = ptr::null();
        let mut rsa_e: *const BigNum = ptr::null();
        let factors = OPENSSL_sk_new_null();
        let exps = OPENSSL_sk_new_null();
        let coeffs = OPENSSL_sk_new_null();

        let ok = 'build: {
            if rsa.is_null() || factors.is_null() || exps.is_null() || coeffs.is_null() {
                break 'build false;
            }

            RSA_get0_key(
                rsa,
                &mut rsa_n as *mut *const BigNum,
                &mut rsa_e as *mut *const BigNum,
                &mut rsa_d as *mut *const BigNum,
            );
            ossl_rsa_get0_all_params(rsa, factors, exps, coeffs);

            if ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_N, rsa_n) == 0
                || ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_E, rsa_e) == 0
            {
                break 'build false;
            }

            /* Check private key data integrity */
            if include_private != 0
                && !rsa_d.is_null()
                && (ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_D, rsa_d) == 0
                    || ossl_param_build_set_multi_key_bn(
                        bld,
                        params,
                        ossl_rsa_mp_factor_names.0.as_ptr(),
                        factors,
                    ) == 0
                    || ossl_param_build_set_multi_key_bn(
                        bld,
                        params,
                        ossl_rsa_mp_exp_names.0.as_ptr(),
                        exps,
                    ) == 0
                    || ossl_param_build_set_multi_key_bn(
                        bld,
                        params,
                        ossl_rsa_mp_coeff_names.0.as_ptr(),
                        coeffs,
                    ) == 0)
            {
                break 'build false;
            }
            true
        };

        // The authority's `err:` label, reached by falling through as well as by every `goto err`.
        OPENSSL_sk_free(factors);
        OPENSSL_sk_free(exps);
        OPENSSL_sk_free(coeffs);
        if ok {
            1
        } else {
            0
        }
    }
}

/// `int ossl_rsa_pss_params_30_todata(const RSA_PSS_PARAMS_30 *pss, OSSL_PARAM_BLD *bld,
/// OSSL_PARAM params[])` — `rsa_backend.c:308-350`. Internal, declared in
/// `include/crypto/rsa.h`.
///
/// The provider's writer for the PSS restriction, and its whole subtlety is the **defaults are
/// omitted rather than written**: for each of the digest, the MGF and the MGF's digest, a value
/// equal to the default is written as NULL (skipped) so that the recipient does not read the
/// parameter set as restricted. The authority's comment is explicit about the consequence —
/// "To ensure that the key isn't seen as unrestricted by the recipient, we make sure that at
/// least one PSS-related parameter is passed, even if it has a default value; saltlen" — which is
/// why `key_saltlen` is written **unconditionally** while the other three are conditional.
///
/// A *fully default* restriction and an unrestricted one are therefore distinguishable on the
/// wire: the first writes `saltlen` and nothing else; the second — the `is_unrestricted` early
/// return — writes nothing at all.
///
/// `#[allow(dead_code)]`'s reason: as [`ossl_rsa_fromdata`].
///
/// # Safety
/// `pss` is NULL or a readable `RSA_PSS_PARAMS_30`; `bld` is NULL or a live builder; `params` is
/// NULL or a key-terminated descriptor array.
#[allow(dead_code)] // read by the provider keymgmt's `export` and 8.8's rsa_pmeth.c
pub(crate) unsafe fn ossl_rsa_pss_params_30_todata(
    pss: *const RsaPssParams30,
    bld: *mut OSSL_PARAM_BLD,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if ossl_rsa_pss_params_30_is_unrestricted(pss) == 0 {
            let hashalg_nid = ossl_rsa_pss_params_30_hashalg(pss);
            let maskgenalg_nid = ossl_rsa_pss_params_30_maskgenalg(pss);
            let maskgenhashalg_nid = ossl_rsa_pss_params_30_maskgenhashalg(pss);
            let saltlen = ossl_rsa_pss_params_30_saltlen(pss);
            let default_hashalg_nid = ossl_rsa_pss_params_30_hashalg(ptr::null());
            let default_maskgenalg_nid = ossl_rsa_pss_params_30_maskgenalg(ptr::null());
            let default_maskgenhashalg_nid = ossl_rsa_pss_params_30_maskgenhashalg(ptr::null());
            let mdname = if hashalg_nid == default_hashalg_nid {
                ptr::null()
            } else {
                ossl_rsa_oaeppss_nid2name(hashalg_nid)
            };
            let mgfname = if maskgenalg_nid == default_maskgenalg_nid {
                ptr::null()
            } else {
                ossl_rsa_oaeppss_nid2name(maskgenalg_nid)
            };
            let mgf1mdname = if maskgenhashalg_nid == default_maskgenhashalg_nid {
                ptr::null()
            } else {
                ossl_rsa_oaeppss_nid2name(maskgenhashalg_nid)
            };

            if (!mdname.is_null()
                && ossl_param_build_set_utf8_string(
                    bld,
                    params,
                    OSSL_PKEY_PARAM_RSA_DIGEST,
                    mdname,
                ) == 0)
                || (!mgfname.is_null()
                    && ossl_param_build_set_utf8_string(
                        bld,
                        params,
                        OSSL_PKEY_PARAM_RSA_MASKGENFUNC,
                        mgfname,
                    ) == 0)
                || (!mgf1mdname.is_null()
                    && ossl_param_build_set_utf8_string(
                        bld,
                        params,
                        OSSL_PKEY_PARAM_RSA_MGF1_DIGEST,
                        mgf1mdname,
                    ) == 0)
                || ossl_param_build_set_int(bld, params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, saltlen)
                    == 0
            {
                return 0;
            }
        }
        1
    }
}

/// `int ossl_rsa_pss_params_30_fromdata(RSA_PSS_PARAMS_30 *pss_params, int *defaults_set, const
/// OSSL_PARAM params[], OSSL_LIB_CTX *libctx)` — `rsa_backend.c:352-449`. Internal.
///
/// The reader, and it is the reverse of the writer in one respect that matters: the MGF name is
/// compared **case-insensitively** against [`ossl_rsa_mgf_nid2name`]'s answer and anything other
/// than MGF1 is refused, while the digest names are *fetched* through `EVP_MD_fetch` and only
/// then converted to NIDs. So an unknown MGF is a 0 before any fetch, and an unknown digest is a
/// 0 after one.
///
/// **The authority's two `OSSL_PARAM_get_utf8_ptr` calls pass `param_mgf` where the surrounding
/// code reads `param_md` and `param_mgf1md`** (`rsa_backend.c:414` and `:428`). That is the
/// authority's own text and it is transcribed rather than corrected: the arm is only reached when
/// the parameter's type is neither `OSSL_PARAM_UTF8_STRING` nor a string either, so it converts
/// the *wrong descriptor* — and a transcription that "fixed" it would answer differently from
/// the library this crate exists to reproduce. The `ptr`-typed parameter is what the arm is for,
/// and neither a probe nor this crate's tests exercise it.
///
/// `#[allow(dead_code)]`'s reason: as [`ossl_rsa_fromdata`].
///
/// # Safety
/// `pss_params` is NULL or writable for `sizeof(RSA_PSS_PARAMS_30)`; `defaults_set` is a live
/// `int`; `params` is a key-terminated descriptor array; `libctx` is NULL or live.
#[allow(dead_code)] // read by the provider keymgmt's `import` and 8.8's rsa_pmeth.c
pub(crate) unsafe fn ossl_rsa_pss_params_30_fromdata(
    pss_params: *mut RsaPssParams30,
    defaults_set: *mut c_int,
    params: *const OsslParam,
    libctx: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut propq: *const c_char = ptr::null();
        let mut md: *mut EvpMd = ptr::null_mut();
        let mut mgf1md: *mut EvpMd = ptr::null_mut();
        let mut saltlen: c_int = 0;

        if pss_params.is_null() {
            return 0;
        }
        let param_propq = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST_PROPS);
        let param_md = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST);
        let param_mgf = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MASKGENFUNC);
        let param_mgf1md = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST);
        let param_saltlen = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN);

        if !param_propq.is_null() && (*param_propq).data_type == OSSL_PARAM_UTF8_STRING {
            propq = (*param_propq).data.cast::<c_char>();
        }
        /*
         * If we get any of the parameters, we know we have at least some restrictions, so we
         * start by setting default values, and let each parameter override their specific
         * restriction data.
         */
        if *defaults_set == 0
            && (!param_md.is_null()
                || !param_mgf.is_null()
                || !param_mgf1md.is_null()
                || !param_saltlen.is_null())
        {
            if ossl_rsa_pss_params_30_set_defaults(pss_params) == 0 {
                return 0;
            }
            *defaults_set = 1;
        }

        let ok = 'body: {
            if !param_mgf.is_null() {
                let default_maskgenalg_nid = ossl_rsa_pss_params_30_maskgenalg(ptr::null());

                if (*param_mgf).data_type != OSSL_PARAM_UTF8_STRING {
                    // The authority reads `param_mgf` here as well; see the function's own note.
                    let mut mgfname: *const c_char = ptr::null();
                    if OSSL_PARAM_get_utf8_ptr(param_mgf, &mut mgfname) == 0 {
                        break 'body false;
                    }
                }

                if OPENSSL_strcasecmp(
                    (*param_mgf).data.cast::<c_char>(),
                    ossl_rsa_mgf_nid2name(default_maskgenalg_nid),
                ) != 0
                {
                    break 'body false;
                }
            }

            /*
             * We're only interested in the NIDs that correspond to the MDs, so the exact
             * propquery is unimportant in the EVP_MD_fetch() calls below.
             */

            if !param_md.is_null() {
                let mdname: *const c_char = if (*param_md).data_type == OSSL_PARAM_UTF8_STRING {
                    (*param_md).data.cast::<c_char>()
                } else {
                    let mut p: *const c_char = ptr::null();
                    // The authority's own coordinate: `param_mgf`, not `param_md`.
                    if OSSL_PARAM_get_utf8_ptr(param_mgf, &mut p) == 0 {
                        break 'body false;
                    }
                    p
                };

                md = EVP_MD_fetch(libctx, mdname, propq);
                if md.is_null()
                    || ossl_rsa_pss_params_30_set_hashalg(pss_params, ossl_rsa_oaeppss_md2nid(md))
                        == 0
                {
                    break 'body false;
                }
            }

            if !param_mgf1md.is_null() {
                let mgf1mdname: *const c_char =
                    if (*param_mgf1md).data_type == OSSL_PARAM_UTF8_STRING {
                        (*param_mgf1md).data.cast::<c_char>()
                    } else {
                        let mut p: *const c_char = ptr::null();
                        // The authority's own coordinate: `param_mgf`, not `param_mgf1md`.
                        if OSSL_PARAM_get_utf8_ptr(param_mgf, &mut p) == 0 {
                            break 'body false;
                        }
                        p
                    };

                mgf1md = EVP_MD_fetch(libctx, mgf1mdname, propq);
                if mgf1md.is_null()
                    || ossl_rsa_pss_params_30_set_maskgenhashalg(
                        pss_params,
                        ossl_rsa_oaeppss_md2nid(mgf1md),
                    ) == 0
                {
                    break 'body false;
                }
            }

            if !param_saltlen.is_null()
                && (OSSL_PARAM_get_int(param_saltlen, &mut saltlen) == 0
                    || ossl_rsa_pss_params_30_set_saltlen(pss_params, saltlen) == 0)
            {
                break 'body false;
            }

            true
        };

        // The authority's `err:` label; both releases accept NULL on the early paths.
        EVP_MD_free(md);
        EVP_MD_free(mgf1md);
        if ok {
            1
        } else {
            0
        }
    }
}

/// `int ossl_rsa_is_foreign(const RSA *rsa)` — `rsa_backend.c:451-458`. Internal.
///
/// "Foreign" means **not this crate's own default method**: an object carrying an `ENGINE` or a
/// method other than `RSA_PKCS1_OpenSSL()` is one whose internals a provider must not copy
/// wholesale, which is why [`ossl_rsa_dup`] refuses exactly these. The `#ifndef FIPS_MODULE`
/// guard holds on this profile, so the test is compiled; the FIPS build would answer 0 for every
/// object.
///
/// `#[allow(dead_code)]`'s reason: **`crypto/evp/p_lib.c`'s static `detect_foreign_key` is its
/// reader**, with the DH and DSA twins, whenever a legacy key is attached to an `EVP_PKEY`.
///
/// # Safety
/// `rsa` is a live object.
#[allow(dead_code)] // read by crypto/evp/p_lib.c's `detect_foreign_key`, which is later
pub(crate) unsafe fn ossl_rsa_is_foreign(rsa: *const Rsa) -> c_int {
    // SAFETY: `rsa` is live per the contract.
    unsafe {
        if !(*rsa).engine.is_null() || !ptr::eq(RSA_get_method(rsa), RSA_PKCS1_OpenSSL()) {
            return 1;
        }
    }
    0
}

/// `static ossl_inline int rsa_bn_dup_check(BIGNUM **out, const BIGNUM *f)` —
/// `rsa_backend.c:460-465`.
///
/// The one-line `BN_dup` wrapper `ossl_rsa_dup` uses eleven times. A NULL source is a **success
/// with nothing written**, which is what lets a public-only key be duplicated and why the
/// function is a success/failure rather than a value.
///
/// # Safety
/// `out` is writable; `f` is NULL or a live `BIGNUM`. On success `*out` is this call's own
/// duplicate.
unsafe fn rsa_bn_dup_check(out: *mut *mut BigNum, f: *const BigNum) -> c_int {
    if !f.is_null() {
        // SAFETY: `f` is live and `out` is the caller's writable slot.
        unsafe {
            *out = BN_dup(f);
            if (*out).is_null() {
                return 0;
            }
        }
    }
    1
}

/// `RSA *ossl_rsa_dup(const RSA *rsa, int selection)` — `rsa_backend.c:467-560`. Internal.
///
/// The copier `EVP_PKEY_dup` reaches through the keymgmt, and the four things a reader has to get
/// right are all selection decisions rather than copies:
///
/// * **a foreign key returns NULL before anything is allocated.** The authority's comment says
///   why: "Do not try to duplicate foreign RSA keys".
/// * **the three groups do not nest.** `KEYPAIR` copies `n`/`e`; `PRIVATE_KEY` copies `d`, the
///   factors and the CRT parameters; and the multiprime block is *inside* `PRIVATE_KEY`, so a
///   public-only duplication never walks `prime_infos`.
/// * **`version`, `flags` and `pss_params` are copied unconditionally**, including for a
///   public-only selection — the comment on the third says so: "we always copy the PSS parameters
///   regardless of selection".
/// * **`rsa->pss` is duplicated through `RSA_PSS_PARAMS_dup` and its `maskHash` is decoded
///   again.** The authority tests `maskGenAlgorithm != NULL && maskHash == NULL` after the dup,
///   because `RSA_PSS_PARAMS_dup` copies the ASN.1 template's four pointers and the template does
///   not know about `maskHash` — it is the free hook's field, not an item column.
///
/// **The `err:` label releases the half-built object**, which is the pattern the whole function
/// depends on: `RSA_free` tolerates every partially populated field, and `ex_data` is duplicated
/// *last* so that a failure before it leaves the copy's `ex_data` zeroed.
///
/// `#[allow(dead_code)]`'s reason: **the provider keymgmt's `dup` method is its reader**; the
/// `EVP_PKEY`-level path that would reach it is 8.8's.
///
/// # Safety
/// `rsa` is a live object; on success the answer is a new object the caller owns.
#[allow(dead_code)] // read by the provider keymgmt's `dup`
pub(crate) unsafe fn ossl_rsa_dup(rsa: *const Rsa, selection: c_int) -> *mut Rsa {
    // SAFETY: the caller's contract; every pointer below is checked before use.
    unsafe {
        /* Do not try to duplicate foreign RSA keys */
        if ossl_rsa_is_foreign(rsa) != 0 {
            return ptr::null_mut();
        }

        let dupkey = ossl_rsa_new_with_ctx((*rsa).libctx);
        if dupkey.is_null() {
            return ptr::null_mut();
        }

        let ok = 'build: {
            /* public key */
            if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
                if rsa_bn_dup_check(&mut (*dupkey).n, (*rsa).n) == 0 {
                    break 'build false;
                }
                if rsa_bn_dup_check(&mut (*dupkey).e, (*rsa).e) == 0 {
                    break 'build false;
                }
            }

            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                /* private key */
                if rsa_bn_dup_check(&mut (*dupkey).d, (*rsa).d) == 0 {
                    break 'build false;
                }

                /* factors and crt params */
                if rsa_bn_dup_check(&mut (*dupkey).p, (*rsa).p) == 0 {
                    break 'build false;
                }
                if rsa_bn_dup_check(&mut (*dupkey).q, (*rsa).q) == 0 {
                    break 'build false;
                }
                if rsa_bn_dup_check(&mut (*dupkey).dmp1, (*rsa).dmp1) == 0 {
                    break 'build false;
                }
                if rsa_bn_dup_check(&mut (*dupkey).dmq1, (*rsa).dmq1) == 0 {
                    break 'build false;
                }
                if rsa_bn_dup_check(&mut (*dupkey).iqmp, (*rsa).iqmp) == 0 {
                    break 'build false;
                }
            }

            (*dupkey).version = (*rsa).version;
            (*dupkey).flags = (*rsa).flags;
            /* we always copy the PSS parameters regardless of selection */
            (*dupkey).pss_params = (*rsa).pss_params;

            /* multiprime */
            let pnum = OPENSSL_sk_num((*rsa).prime_infos);
            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && pnum > 0 {
                (*dupkey).prime_infos = OPENSSL_sk_new_reserve(None, pnum);
                if (*dupkey).prime_infos.is_null() {
                    break 'build false;
                }
                let mut i: c_int = 0;
                while i < pnum {
                    let duppinfo = CRYPTO_zalloc(core::mem::size_of::<RsaPrimeInfo>(), FILE, LINE)
                        .cast::<RsaPrimeInfo>();
                    if duppinfo.is_null() {
                        break 'build false;
                    }
                    /* push first so cleanup in error case works */
                    OPENSSL_sk_push((*dupkey).prime_infos, duppinfo.cast());

                    let pinfo = OPENSSL_sk_value((*rsa).prime_infos, i).cast::<RsaPrimeInfo>();
                    if rsa_bn_dup_check(&mut (*duppinfo).r, (*pinfo).r) == 0 {
                        break 'build false;
                    }
                    if rsa_bn_dup_check(&mut (*duppinfo).d, (*pinfo).d) == 0 {
                        break 'build false;
                    }
                    if rsa_bn_dup_check(&mut (*duppinfo).t, (*pinfo).t) == 0 {
                        break 'build false;
                    }
                    i += 1;
                }
                if ossl_rsa_multip_calc_product(dupkey) == 0 {
                    break 'build false;
                }
            }

            if !(*rsa).pss.is_null() {
                (*dupkey).pss = RSA_PSS_PARAMS_dup((*rsa).pss);
                if !(*(*rsa).pss).mask_gen_algorithm.is_null() && (*dupkey).pss.is_null() {
                    // `RSA_PSS_PARAMS_dup` answered NULL, so `(*dupkey).pss` is NULL and the
                    // authority's next line would dereference it; the authority's own test is
                    // `dupkey->pss->maskGenAlgorithm == NULL`, which is inside `if (!dupkey->pss)`
                    // in no version of this file -- it is reached only when the dup succeeded.
                    break 'build false;
                }
                if !(*dupkey).pss.is_null() && !(*(*dupkey).pss).mask_gen_algorithm.is_null() {
                    (*(*dupkey).pss).mask_hash =
                        ossl_x509_algor_mgf1_decode((*(*dupkey).pss).mask_gen_algorithm);
                    if (*(*dupkey).pss).mask_hash.is_null() {
                        break 'build false;
                    }
                }
            }

            if CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_RSA, &mut (*dupkey).ex_data, &(*rsa).ex_data) == 0
            {
                break 'build false;
            }

            true
        };

        if !ok {
            RSA_free(dupkey);
            return ptr::null_mut();
        }

        dupkey
    }
}

/// `RSA_PSS_PARAMS *ossl_rsa_pss_decode(const X509_ALGOR *alg)` — `rsa_backend.c:563-582`.
/// Internal, inside `#ifndef FIPS_MODULE`.
///
/// The `RSASSA-PSS-params` decoder: `ASN1_TYPE_unpack_sequence` over the algorithm's parameter,
/// then the one field the item template cannot carry. `maskHash` is *derived* from
/// `maskGenAlgorithm` rather than decoded from the bytes, and a `maskGenAlgorithm` that is not
/// MGF1 makes `ossl_x509_algor_mgf1_decode` answer NULL — which releases the whole object rather
/// than returning a half-filled one, because a PSS restriction whose mask function is unknown is
/// not a restriction this library can honour.
///
/// `#[allow(dead_code)]`'s reason: **its only caller is [`ossl_rsa_param_decode`]**, which is
/// itself reached only from [`ossl_rsa_key_from_pkcs8`].
///
/// # Safety
/// `alg` is a live `X509_ALGOR`. On success the answer is a new object the caller owns.
#[allow(dead_code)] // reached only through ossl_rsa_param_decode
pub(crate) unsafe fn ossl_rsa_pss_decode(alg: *const X509Algor) -> *mut RsaPssParams {
    // SAFETY: the caller's contract.
    unsafe {
        let pss =
            ASN1_TYPE_unpack_sequence(RSA_PSS_PARAMS_it(), (*alg).parameter).cast::<RsaPssParams>();
        if pss.is_null() {
            return ptr::null_mut();
        }

        if !(*pss).mask_gen_algorithm.is_null() {
            (*pss).mask_hash = ossl_x509_algor_mgf1_decode((*pss).mask_gen_algorithm);
            if (*pss).mask_hash.is_null() {
                RSA_PSS_PARAMS_free(pss);
                return ptr::null_mut();
            }
        }

        pss
    }
}

/// `static int ossl_rsa_sync_to_pss_params_30(RSA *rsa)` — `rsa_backend.c:584-621`.
///
/// The one-way synchronisation from the **legacy** `RSA_PSS_PARAMS *pss` to the **provider's**
/// `RSA_PSS_PARAMS_30 pss_params`, and the authority's comment on its own body is the contract:
/// "We don't care about the validity of the fields here, we just want to synchronise values.
/// Verifying here makes it impossible to even read a key with invalid values, making it hard to
/// test a bad situation."
///
/// That is why it calls `ossl_rsa_pss_get_param_unverified` rather than the checking variant, and
/// why **a NULL `rsa`, a NULL `pss` or a NULL `pss_params` is a success with nothing written**
/// rather than a failure: the three-way `&&` in the condition means the function's answer is 1
/// unless the *conversion* failed.
///
/// # Safety
/// `rsa` is NULL or a live object.
unsafe fn ossl_rsa_sync_to_pss_params_30(rsa: *mut Rsa) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if !rsa.is_null() {
            let legacy_pss = RSA_get0_pss_params(rsa);
            if !legacy_pss.is_null() {
                let pss = ossl_rsa_get0_pss_params_30(rsa);
                if !pss.is_null() {
                    let mut md: *const EvpMd = ptr::null();
                    let mut mgf1md: *const EvpMd = ptr::null();
                    let mut saltlen: c_int = 0;
                    let mut trailer_field: c_int = 0;
                    let mut pss_params = RsaPssParams30 {
                        hash_algorithm_nid: 0,
                        mask_gen: RsaPssMaskGen {
                            algorithm_nid: 0,
                            hash_algorithm_nid: 0,
                        },
                        salt_len: 0,
                        trailer_field: 0,
                    };

                    if ossl_rsa_pss_get_param_unverified(
                        legacy_pss,
                        &mut md,
                        &mut mgf1md,
                        &mut saltlen,
                        &mut trailer_field,
                    ) == 0
                    {
                        return 0;
                    }
                    let md_nid = EVP_MD_get_type(md);
                    let mgf1md_nid = EVP_MD_get_type(mgf1md);
                    if ossl_rsa_pss_params_30_set_defaults(&mut pss_params) == 0
                        || ossl_rsa_pss_params_30_set_hashalg(&mut pss_params, md_nid) == 0
                        || ossl_rsa_pss_params_30_set_maskgenhashalg(&mut pss_params, mgf1md_nid)
                            == 0
                        || ossl_rsa_pss_params_30_set_saltlen(&mut pss_params, saltlen) == 0
                        || ossl_rsa_pss_params_30_set_trailerfield(&mut pss_params, trailer_field)
                            == 0
                    {
                        return 0;
                    }
                    *pss = pss_params;
                }
            }
        }
        1
    }
}

/// `int ossl_rsa_pss_get_param_unverified(const RSA_PSS_PARAMS *pss, const EVP_MD **pmd, const
/// EVP_MD **pmgf1md, int *psaltlen, int *ptrailerField)` — `rsa_backend.c:623-650`. Internal.
///
/// The **unchecking** reader of an ASN.1 PSS restriction: it resolves the two digests through
/// [`ossl_x509_algor_get_md`] and reads the two integers, and it deliberately does not verify
/// that the salt length is legal or that the trailer field is 1. The caller
/// [`ossl_rsa_sync_to_pss_params_30`] says why in its own comment, and the eventual checker is
/// `ossl_rsa_pss_get_param` (`rsa_pss.c`'s successor in `rsa_ameth.c`'s path).
///
/// **The "defaults" are fetched from the ONE place** — the authority's comment — and that place
/// is a *local* `RSA_PSS_PARAMS_30` filled by `ossl_rsa_pss_params_30_set_defaults` whose return
/// value is **discarded** (`(void)`): the defaults cannot fail for a live local, and the absent
/// salt length and trailer field are read out of it.
///
/// `#[allow(dead_code)]`'s reason: as [`ossl_rsa_pss_decode`]; its readers are
/// `ossl_rsa_sync_to_pss_params_30` and 8.8's `rsa_ameth.c`.
///
/// # Safety
/// `pss` is NULL or live; each out-parameter is NULL or writable, and the two digest pointers
/// borrow from the library's static or fetched methods.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_rsa_pss_get_param_unverified(
    pss: *const RsaPssParams,
    pmd: *mut *const EvpMd,
    pmgf1md: *mut *const EvpMd,
    psaltlen: *mut c_int,
    ptrailer_field: *mut c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut pss_params = RsaPssParams30 {
            hash_algorithm_nid: 0,
            mask_gen: RsaPssMaskGen {
                algorithm_nid: 0,
                hash_algorithm_nid: 0,
            },
            salt_len: 0,
            trailer_field: 0,
        };

        /* Get the defaults from the ONE place */
        let _ = ossl_rsa_pss_params_30_set_defaults(&mut pss_params);

        if pss.is_null() {
            return 0;
        }
        *pmd = ossl_x509_algor_get_md((*pss).hash_algorithm);
        if (*pmd).is_null() {
            return 0;
        }
        *pmgf1md = ossl_x509_algor_get_md((*pss).mask_hash);
        if (*pmgf1md).is_null() {
            return 0;
        }
        if !(*pss).salt_length.is_null() {
            *psaltlen = crate::asn1::prim::ASN1_INTEGER_get((*pss).salt_length) as c_int;
        } else {
            *psaltlen = ossl_rsa_pss_params_30_saltlen(&pss_params);
        }
        if !(*pss).trailer_field.is_null() {
            *ptrailer_field = crate::asn1::prim::ASN1_INTEGER_get((*pss).trailer_field) as c_int;
        } else {
            *ptrailer_field = ossl_rsa_pss_params_30_trailerfield(&pss_params);
        }

        1
    }
}

/// `int ossl_rsa_param_decode(RSA *rsa, const X509_ALGOR *alg)` — `rsa_backend.c:652-676`.
/// Internal, inside `#ifndef FIPS_MODULE`.
///
/// The three-way dispatch on the algorithm identifier that decides whether an `RSA` has a PSS
/// restriction at all, and every one of the three early returns is a **success**:
///
/// * an identifier that is not `rsaPSS` answers 1 with nothing written — a plain `rsaEncryption`
///   key has no restriction;
/// * `algptype == V_ASN1_UNDEF` answers 1 for the same reason: the parameters are absent, so
///   there is nothing to decode. This is the RFC 4055 spelling of the *default* restriction;
/// * anything other than `V_ASN1_SEQUENCE` is `RSA_R_INVALID_PSS_PARAMETERS`, because a PSS
///   identifier **must** carry a sequence when it carries anything.
///
/// `ossl_rsa_sync_to_pss_params_30` is the last step and is **not guarded on its own answer's
/// kind**: it returns 1 for a key with no `pss` field, so the final `return 1` is reached for a
/// key the decode just gave a restriction to as well.
///
/// `#[allow(dead_code)]`'s reason: as [`ossl_rsa_pss_decode`].
///
/// # Safety
/// `rsa` is a live object; `alg` is a live `X509_ALGOR`.
#[allow(dead_code)] // reached only through ossl_rsa_key_from_pkcs8
pub(crate) unsafe fn ossl_rsa_param_decode(rsa: *mut Rsa, alg: *const X509Algor) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut algptype: c_int = 0;
        let mut algp: *const c_void = ptr::null();
        let mut algoid: *const Asn1Object = ptr::null();

        X509_ALGOR_get0(
            &mut algoid as *mut *const Asn1Object,
            &mut algptype,
            &mut algp as *mut *const c_void,
            alg,
        );
        if OBJ_obj2nid(algoid) != EVP_PKEY_RSA_PSS {
            return 1;
        }
        if algptype == crate::asn1::layout::V_ASN1_UNDEF {
            return 1;
        }
        if algptype != crate::asn1::layout::V_ASN1_SEQUENCE {
            raise_site(&err_sites::RSA_BACKEND_665);
            return 0;
        }
        let pss = ossl_rsa_pss_decode(alg);
        if pss.is_null() || ossl_rsa_set0_pss_params(rsa, pss) == 0 {
            RSA_PSS_PARAMS_free(pss);
            return 0;
        }
        if ossl_rsa_sync_to_pss_params_30(rsa) == 0 {
            return 0;
        }
        1
    }
}

/// `RSA *ossl_rsa_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *libctx, const
/// char *propq)` — `rsa_backend.c:678-712`. Internal, inside `#ifndef FIPS_MODULE`.
///
/// The PKCS#8 decoder's RSA half: pull the private key octets and the algorithm identifier out of
/// the container, decode the key with the **template** decoder (`d2i_RSAPrivateKey`, not the
/// ASN.1 method object), then apply the identifier — which is where a PSS key is told apart from
/// a plain one.
///
/// **The four `RSA_FLAG_TYPE_*` bits are cleared and exactly one is set**, and the `default` arm
/// is what leaves them zero for an identifier the switch does not know. The type bits are what
/// `RSA_get0_pss_params`' callers and `EVP_PKEY_get_id` read back, which is why
/// `RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK)` comes first rather than being folded into the
/// two arms.
///
/// `libctx` and `propq` are accepted and **unused**: the template decoder has no fetch in it.
/// The parameters are kept because the header's signature carries them and because the EC and DH
/// twins use theirs, and a transcription that dropped them would be a different function.
///
/// `#[allow(dead_code)]`'s reason: **the PKCS#8 decoder's `priv_decode` callback in 8.8's
/// `rsa_ameth.c` is its reader**, and D348's reconciliation of `RSA_free`'s omitted
/// `RSA_PSS_PARAMS_free` call names this function as the coordinate that will make `r->pss`
/// non-NULL.
///
/// # Safety
/// `p8inf` is a live `PKCS8_PRIV_KEY_INFO`; on success the answer is a new `RSA` the caller owns.
#[allow(dead_code)] // read by 8.8's rsa_ameth.c `priv_decode`; named by D348
pub(crate) unsafe fn ossl_rsa_key_from_pkcs8(
    p8inf: *const crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Rsa {
    // The two parameters are the authority's and are unreached on this path; naming them keeps
    // the signature and the `let _` keeps the compiler from warning about them.
    let _ = (libctx, propq);

    // SAFETY: the caller's contract.
    unsafe {
        let mut p: *const u8 = ptr::null();
        let mut pklen: c_int = 0;
        let mut alg: *const X509Algor = ptr::null();

        if crate::asn1::p8_pkey::PKCS8_pkey_get0(
            ptr::null_mut(),
            &mut p,
            &mut pklen,
            &mut alg,
            p8inf,
        ) == 0
        {
            return ptr::null_mut();
        }
        let rsa = d2i_RSAPrivateKey(ptr::null_mut(), &mut p, pklen as core::ffi::c_long);
        if rsa.is_null() {
            raise_site(&err_sites::RSA_BACKEND_690);
            return ptr::null_mut();
        }
        if ossl_rsa_param_decode(rsa, alg) == 0 {
            RSA_free(rsa);
            return ptr::null_mut();
        }

        RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
        match OBJ_obj2nid((*alg).algorithm) {
            EVP_PKEY_RSA => {
                RSA_set_flags(rsa, RSA_FLAG_TYPE_RSA);
            }
            EVP_PKEY_RSA_PSS => {
                RSA_set_flags(rsa, RSA_FLAG_TYPE_RSASSAPSS);
            }
            _ => { /* Leave the type bits zero */ }
        }

        rsa
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
    use crate::params::dup::OSSL_PARAM_free;
    use crate::params::{
        OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_utf8_string,
        OSSL_PARAM_get_int, OSSL_PARAM_locate,
    };

    /// A live `RSA`, freed on drop.
    struct OwnedRsa(*mut Rsa);

    impl OwnedRsa {
        fn new() -> Self {
            // SAFETY: a NULL libctx is the default context; the constructor answers NULL only on
            // allocation failure, which the assertion covers.
            let rsa = unsafe { ossl_rsa_new_with_ctx(ptr::null_mut()) };
            assert!(!rsa.is_null());
            OwnedRsa(rsa)
        }
    }

    impl Drop for OwnedRsa {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live object this test owns.
            unsafe { RSA_free(self.0) };
        }
    }

    /// A fresh object takes the default method, so it is not foreign; and the public-only import
    /// is a success through `RSA_set0_key` and the `ossl_rsa_check_factors` sanity check, whose
    /// empty-factor arm is the `p == NULL` early return of `ossl_rsa_get0_all_params`.
    #[test]
    fn a_public_only_import_succeeds_and_the_object_is_not_foreign() {
        let mut n_buf = [0x0bu8];
        let mut e_buf = [0x11u8];
        // SAFETY: every buffer outlives the array.
        let params = unsafe {
            [
                crate::params::OSSL_PARAM_construct_BN(
                    OSSL_PKEY_PARAM_RSA_N,
                    n_buf.as_mut_ptr(),
                    n_buf.len(),
                ),
                crate::params::OSSL_PARAM_construct_BN(
                    OSSL_PKEY_PARAM_RSA_E,
                    e_buf.as_mut_ptr(),
                    e_buf.len(),
                ),
                OSSL_PARAM_construct_end(),
            ]
        };

        let rsa = OwnedRsa::new();
        // SAFETY: the object is live and the array is key-terminated.
        unsafe {
            assert_eq!(ossl_rsa_is_foreign(rsa.0), 0);
            assert_eq!(ossl_rsa_fromdata(rsa.0, params.as_ptr(), 0), 1);
            assert_eq!(crate::bn::bignum::BN_num_bits((*rsa.0).n), 4);
            assert_eq!(crate::bn::bignum::BN_num_bits((*rsa.0).e), 5);
            assert!((*rsa.0).d.is_null());
        }

        /* The writer, read back through the builder. */
        let bld = OSSL_PARAM_BLD_new();
        assert!(!bld.is_null());
        // SAFETY: every object here is live.
        unsafe {
            assert_eq!(ossl_rsa_todata(rsa.0, bld, ptr::null_mut(), 0), 1);
            let out = OSSL_PARAM_BLD_to_param(bld);
            assert!(!out.is_null());
            assert!(!OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_RSA_N).is_null());
            assert!(!OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_RSA_E).is_null());
            /* The private half was not asked for, so its key is absent. */
            assert!(OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_RSA_D).is_null());
            OSSL_PARAM_free(out);
            OSSL_PARAM_BLD_free(bld);
        }
    }

    /// The PSS parameter writer's one asymmetry: an **unrestricted** restriction writes *nothing*,
    /// while a restriction at the defaults writes `saltlen` and omits the three name parameters
    /// because they equal the defaults. That is what makes a restricted-but-default key
    /// distinguishable from an unrestricted one on the wire.
    #[test]
    fn the_pss_writer_omits_defaults_and_still_writes_saltlen() {
        let unrestricted = RsaPssParams30 {
            hash_algorithm_nid: 0,
            mask_gen: RsaPssMaskGen {
                algorithm_nid: 0,
                hash_algorithm_nid: 0,
            },
            salt_len: 0,
            trailer_field: 0,
        };
        let mut restricted = unrestricted;
        // SAFETY: the object is live; the setter's contract is the local's own storage.
        unsafe {
            assert_eq!(
                crate::rsa::pss::ossl_rsa_pss_params_30_set_defaults(&mut restricted),
                1
            );
        }

        /* Unrestricted: nothing at all. */
        let bld = OSSL_PARAM_BLD_new();
        // SAFETY: every object here is live.
        unsafe {
            assert_eq!(
                ossl_rsa_pss_params_30_todata(&unrestricted, bld, ptr::null_mut()),
                1
            );
            let out = OSSL_PARAM_BLD_to_param(bld);
            assert!(OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN).is_null());
            assert!(OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_RSA_DIGEST).is_null());
            OSSL_PARAM_free(out);
            OSSL_PARAM_BLD_free(bld);
        }

        /* At the defaults: `saltlen` only. */
        let bld = OSSL_PARAM_BLD_new();
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                ossl_rsa_pss_params_30_todata(&restricted, bld, ptr::null_mut()),
                1
            );
            let out = OSSL_PARAM_BLD_to_param(bld);
            let mut saltlen: c_int = 0;
            assert_eq!(
                OSSL_PARAM_get_int(
                    OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN),
                    &mut saltlen
                ),
                1
            );
            assert_eq!(saltlen, 20);
            assert!(OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_RSA_DIGEST).is_null());
            assert!(OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_RSA_MASKGENFUNC).is_null());
            assert!(OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST).is_null());
            OSSL_PARAM_free(out);
            OSSL_PARAM_BLD_free(bld);
        }
    }

    /// The PSS parameter reader's MGF arm: the comparison is **case-insensitive** against
    /// `ossl_rsa_mgf_nid2name`'s answer, so `"mgf1"` is MGF1 and anything else is a refusal —
    /// before any digest is fetched. The `defaults_set` out-parameter is the second observation:
    /// the presence of *any* PSS parameter installs the defaults first.
    #[test]
    fn the_pss_reader_accepts_only_mgf1_case_insensitively() {
        let mut pss = RsaPssParams30 {
            hash_algorithm_nid: 0,
            mask_gen: RsaPssMaskGen {
                algorithm_nid: 0,
                hash_algorithm_nid: 0,
            },
            salt_len: 0,
            trailer_field: 0,
        };
        let mut defaults_set: c_int = 0;

        let mut mgf_buf = *b"mgf1\0";
        // SAFETY: the buffer outlives the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_RSA_MASKGENFUNC,
                    mgf_buf.as_mut_ptr().cast(),
                    0,
                ),
                OSSL_PARAM_construct_end(),
            ]
        };
        // SAFETY: the objects are live and the array is key-terminated.
        unsafe {
            assert_eq!(
                ossl_rsa_pss_params_30_fromdata(
                    &mut pss,
                    &mut defaults_set,
                    params.as_ptr(),
                    ptr::null_mut()
                ),
                1
            );
            assert_eq!(defaults_set, 1);
            assert_eq!(pss.salt_len, 20);
        }

        /* A different MGF name is refused, and the defaults are not installed for that call. */
        let mut pss = RsaPssParams30 {
            hash_algorithm_nid: 0,
            mask_gen: RsaPssMaskGen {
                algorithm_nid: 0,
                hash_algorithm_nid: 0,
            },
            salt_len: 0,
            trailer_field: 0,
        };
        let mut defaults_set: c_int = 0;
        let mut bad_buf = *b"mgf2\0";
        // SAFETY: the buffer outlives the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_RSA_MASKGENFUNC,
                    bad_buf.as_mut_ptr().cast(),
                    0,
                ),
                OSSL_PARAM_construct_end(),
            ]
        };
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                ossl_rsa_pss_params_30_fromdata(
                    &mut pss,
                    &mut defaults_set,
                    params.as_ptr(),
                    ptr::null_mut()
                ),
                0
            );
        }

        /* A NULL object is the reader's own refusal. */
        // SAFETY: the contract allows a NULL object, which is the arm under test.
        unsafe {
            assert_eq!(
                ossl_rsa_pss_params_30_fromdata(
                    ptr::null_mut(),
                    &mut defaults_set,
                    params.as_ptr(),
                    ptr::null_mut()
                ),
                0
            );
        }
    }

    /// The salt-length-only path, which is the one arm that reaches `set_saltlen` without a
    /// digest fetch: the reader stores the integer and leaves the identifiers at their defaults.
    #[test]
    fn a_saltlen_only_array_sets_the_length_and_nothing_else() {
        let mut pss = RsaPssParams30 {
            hash_algorithm_nid: 0,
            mask_gen: RsaPssMaskGen {
                algorithm_nid: 0,
                hash_algorithm_nid: 0,
            },
            salt_len: 0,
            trailer_field: 0,
        };
        let mut defaults_set: c_int = 0;
        let mut saltlen: c_int = 32;
        // SAFETY: the integer outlives the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, &mut saltlen),
                OSSL_PARAM_construct_end(),
            ]
        };
        // SAFETY: the objects are live and the array is key-terminated.
        unsafe {
            assert_eq!(
                ossl_rsa_pss_params_30_fromdata(
                    &mut pss,
                    &mut defaults_set,
                    params.as_ptr(),
                    ptr::null_mut()
                ),
                1
            );
            assert_eq!(defaults_set, 1);
            assert_eq!(pss.salt_len, 32);
            assert_eq!(pss.hash_algorithm_nid, crate::runtime::obj::NID_sha1);
            assert_eq!(
                pss.mask_gen.hash_algorithm_nid,
                crate::runtime::obj::NID_sha1
            );
            assert_eq!(pss.trailer_field, 1);
        }
    }
}
