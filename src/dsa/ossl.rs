//! Phase 8 — `crypto/dsa/dsa_ossl.c`: the OpenSSL `DSA_METHOD`, signing, verification and the
//! two lifecycle callbacks.
//!
//! Nine definitions in authority order: the `openssl_dsa_meth` table (`:53-67`), the default-method
//! family [`DSA_set_default_method`]/[`DSA_get_default_method`]/[`DSA_OpenSSL`] (`:69-86`), the
//! internal [`ossl_dsa_do_sign_int`] (`:88-200`), the three static sign entry points
//! `dsa_do_sign`/`dsa_sign_setup_no_digest`/`dsa_sign_setup` (`:202-353`), the static
//! `dsa_do_verify` (`:355-457`), the two lifecycle callbacks `dsa_init`/`dsa_finish` (`:459-471`)
//! and `dsa_mod_inverse_fermat` (`:473-500`).
//!
//! ## Why the table and the object land together
//!
//! `dsa_new_intern` (`crypto/dsa/dsa_lib.c:153`) reads `DSA_get_default_method()`, whose
//! `default_DSA_method` is `&openssl_dsa_meth` — the static in this file. So the object cannot be
//! built before the table exists and the table cannot be built before its five member functions'
//! addresses do. That is the cycle D329 measured for DH and D331 closed; this slice closes it for
//! DSA, which is why [`crate::dsa::object`] and this module landed together.
//!
//! ## The nonce draws, and the third one this crate cannot make
//!
//! `dsa_sign_setup` draws `k` on one of three arms:
//!
//! * **no digest** (`DSA_sign_setup`, the method table's own `dsa_sign_setup` member): a private
//!   draw in `[0, q)` with the constant-time flag set — `ossl_bn_priv_rand_range_fixed_top`,
//!   which D314 deferred and this slice lands in [`crate::bn::rand`];
//! * **a digest and `nonce_type != 1`** (`DSA_do_sign`, `DSA_sign`): SHA-512 over the padded
//!   private key, the digest and a fresh random draw — `ossl_bn_gen_dsa_nonce_fixed_top`, landed
//!   beside it;
//! * **a digest and `nonce_type == 1`**: `ossl_gen_deterministic_nonce_rfc6979`
//!   (`crypto/deterministic_nonce.c:181`), the RFC 6979 deterministic nonce.
//!
//! The third is **recorded as a reduction rather than transcribed**, and the argument is that its
//! reachable answer is the same either way: that function's first act is
//! `EVP_KDF_fetch(libctx, "HMAC-DRBG-KDF", propq)` (`crypto/deterministic_nonce.c:140`) and its
//! `kdf_setup` returns NULL when the fetch does, which makes the arm fail through the same `goto
//! err`. `forensics/atlas/provider-algorithms.json` records the default provider's
//! `HMAC-DRBG-KDF` row as `implementation_state: "unimplemented"`, and `crypto/deterministic_nonce.c`
//! itself is a unit with **no crate module and no plan row**, so the function cannot be called at
//! all. Its only authority caller that passes `nonce_type == 1` is `crypto/dsa/dsa_pmeth.c`, which
//! is slice E. The arm is therefore written as the refusal it is, with this paragraph as the
//! record — and what unblocks it is the `OSSL_OP_KDF` rows, not this stratum's work.
//!
//! ## The `-1`/`0`/`1` asymmetry, and the one shared `err:` label
//!
//! `dsa_do_verify` answers **-1** for a missing parameter, a `q` that is not 160/224/256 bits, a
//! modulus past `OPENSSL_DSA_MAX_MODULUS_BITS` and any internal failure, **0** for a signature
//! whose `r` or `s` is zero, negative or not below `q`, and **1** for a signature that verifies.
//! `dsa_sign_setup` answers 0 on every arm. `ossl_dsa_do_sign_int` raises its **reason code** from
//! one shared `err:` label with the default `ERR_R_BN_LIB`, so a caller sees one queue record for
//! a missing private key and one for a missing parameter, and the generated site
//! `err_sites::DSA_OSS_195` is the authority's only **dynamic-reason** site in this stratum —
//! which is why the transcription routes it through `raise_site_dynamic`.
//!
//! ## The blinding, and why its observables are properties rather than values
//!
//! The second half of the signature is computed as `s = blind⁻¹ · k⁻¹ · (blind·m + blind·r·x) mod
//! q` rather than the naive `k⁻¹(m + rx)`, so that the multiply by the private key is not directly
//! observable in `s`. Nothing about that is visible in a transcript except that the answer
//! verifies — which is the point, and `RT-DSA` observes the blinded and unblinded spellings as one
//! verdict rather than as two values.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::bn::arith::{BN_add, BN_div, BN_mod_add_quick, BN_mod_inverse, BN_mod_mul, BN_sub};
use crate::bn::bignum::{
    bn_get_top, bn_wexpand, ossl_bn_is_word_fixed_top, BN_bin2bn, BN_clear_free, BN_consttime_swap,
    BN_free, BN_is_bit_set, BN_is_negative, BN_is_zero, BN_new, BN_num_bits, BN_set_flags,
    BN_set_word, BigNum, BN_FLG_CONSTTIME,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::bn::mont::{
    BN_MONT_CTX_free, BN_MONT_CTX_set_locked, BN_mod_exp2_mont, BN_mod_exp_mont, MontCtx,
};
use crate::bn::rand::{
    ossl_bn_gen_dsa_nonce_fixed_top, ossl_bn_priv_rand_range_fixed_top, BN_priv_rand_ex,
    BN_RAND_BOTTOM_ANY, BN_RAND_TOP_ANY,
};
use crate::runtime::bio::ERR_RFLAG_COMMON;
use crate::runtime::err::err_reasons;
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_dynamic};

use super::{
    Dsa, DsaDoSignFn, DsaDoVerifyFn, DsaLifecycleFn, DsaMethod, DsaSig, DsaSignSetupFn,
    DSA_FLAG_CACHE_MONT_P, DSA_FLAG_FIPS_METHOD, MAX_DSA_SIGN_RETRIES, MIN_DSA_SIGN_QBITS,
    OPENSSL_DSA_MAX_MODULUS_BITS,
};

/// `ERR_R_BN_LIB` — `include/openssl/err.h:317`: `(ERR_LIB_BN /* 3 */ | ERR_RFLAG_COMMON)`.
///
/// The default reason `ossl_dsa_do_sign_int`'s `err:` label raises, and the only `ERR_R_*` code
/// this unit names. The crate's home for the `ERR_R_*` family is `src/runtime/bio/mod.rs`, which
/// defines the flag and the codes it needed and not this one; it is named here with its coordinate
/// rather than added there, because a constant with one reader belongs beside it.
const ERR_R_BN_LIB: c_int = 3 /* ERR_LIB_BN */ | ERR_RFLAG_COMMON;

/// `static DSA_METHOD openssl_dsa_meth` — `dsa_ossl.c:53-67`.
///
/// Twelve members, five of them real: `dsa_do_sign`, `dsa_sign_setup`, `dsa_do_verify`, `dsa_init`
/// and `dsa_finish`. The other five are **NULL in the authority's own initialiser** — `dsa_mod_exp`
/// and `bn_mod_exp` (the header marks `bn_mod_exp` "Can be null"), `app_data`, `dsa_paramgen` and
/// `dsa_keygen`. The last two are load-bearing rather than incidental: their NULL is what makes
/// `DSA_generate_parameters_ex` and `DSA_generate_key` fall through to `dsa_gen.c`'s and
/// `dsa_key.c`'s own bodies instead of dispatching. `flags` is the word `DSA_FLAG_FIPS_METHOD`
/// (`0x0400`), which `dsa_new_intern` then masks with `~DSA_FLAG_NON_FIPS_ALLOW` — the same bit —
/// so a fresh object's flag word carries only `dsa_init`'s `DSA_FLAG_CACHE_MONT_P`.
///
/// The address is contract in three places: [`DSA_get_default_method`] answers it, [`DSA_OpenSSL`]
/// answers it, and `DEFAULT_DSA_METHOD` is initialised with it.
struct StaticDsaMethod(core::cell::UnsafeCell<DsaMethod>);

// SAFETY: the inner value is fully initialised at compile time and is never written. Every consumer
// reads one field or takes the address; no `&mut` is ever created.
unsafe impl Sync for StaticDsaMethod {}

static DSA_OSSL: StaticDsaMethod = StaticDsaMethod(core::cell::UnsafeCell::new(DsaMethod {
    name: c"OpenSSL DSA method".as_ptr().cast_mut(),
    dsa_do_sign: Some(dsa_do_sign as DsaDoSignFn),
    dsa_sign_setup: Some(dsa_sign_setup_no_digest as DsaSignSetupFn),
    dsa_do_verify: Some(dsa_do_verify as DsaDoVerifyFn),
    dsa_mod_exp: None,
    bn_mod_exp: None,
    init: Some(dsa_init as DsaLifecycleFn),
    finish: Some(dsa_finish as DsaLifecycleFn),
    flags: DSA_FLAG_FIPS_METHOD,
    app_data: ptr::null_mut(),
    dsa_paramgen: None,
    dsa_keygen: None,
}));

/// The stable address of the authority's `openssl_dsa_meth` object, for the two accessors and for
/// `DEFAULT_DSA_METHOD`'s initialiser.
const fn dsa_ossl() -> *const DsaMethod {
    DSA_OSSL.0.get()
}

/// `static const DSA_METHOD *default_DSA_method = &openssl_dsa_meth` — `dsa_ossl.c:69`.
///
/// Modelled as an [`AtomicPtr`] rather than a `static mut`, exactly as `src/dh/key.rs` models
/// `default_DH_method` and `src/rsa/ossl.rs` models `default_RSA_meth`: the authority's write is
/// unsynchronised, and the crate's option for a process-wide pointer a caller may replace is the
/// atomic. Every access is `Relaxed`, because the authority has no fence.
static DEFAULT_DSA_METHOD: AtomicPtr<DsaMethod> = AtomicPtr::new(dsa_ossl() as *mut DsaMethod);

/// `void DSA_set_default_method(const DSA_METHOD *meth)` — `dsa_ossl.c:71-74`.
///
/// A pointer store and nothing else: no reference is taken, no old table is released, and NULL is
/// an accepted value that [`DSA_get_default_method`] then answers.
///
/// # Safety
///
/// `meth` is NULL or a live table that outlives its installation.
#[no_mangle]
pub unsafe extern "C" fn DSA_set_default_method(meth: *const DsaMethod) {
    DEFAULT_DSA_METHOD.store(meth.cast_mut(), Ordering::Relaxed);
}

/// `const DSA_METHOD *DSA_get_default_method(void)` — `dsa_ossl.c:76-79`.
///
/// # Safety
///
/// None: the answer is this module's own table address, or the one a caller installed.
#[no_mangle]
pub extern "C" fn DSA_get_default_method() -> *const DsaMethod {
    DEFAULT_DSA_METHOD.load(Ordering::Relaxed)
}

/// `const DSA_METHOD *DSA_OpenSSL(void)` — `dsa_ossl.c:81-84`.
///
/// The table's *address* is the answer, so two calls — and a call to [`DSA_get_default_method`]
/// before any [`DSA_set_default_method`] — compare equal.
///
/// # Safety
///
/// None: the answer is a constant.
#[no_mangle]
pub extern "C" fn DSA_OpenSSL() -> *const DsaMethod {
    dsa_ossl()
}

/// `DSA_SIG *ossl_dsa_do_sign_int(const unsigned char *dgst, int dlen, DSA *dsa,`
/// `unsigned int nonce_type, const char *digestname, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `dsa_ossl.c:88-200`. Internal (`include/crypto/dsa.h:39`), so `pub(crate)`.
///
/// The blinded signature: `r = (g^k mod p) mod q` from [`dsa_sign_setup`] and `s = blind⁻¹ · k⁻¹ ·
/// (blind·m + blind·r·x) mod q`. `dlen` is truncated to `BN_num_bytes(q)` — FIPS 186-3 §4.2's
/// leftmost-bits rule — and the whole computation is retried when `r` or `s` is zero, bounded by
/// [`MAX_DSA_SIGN_RETRIES`].
///
/// # Safety
///
/// `dgst` is readable for `dlen` bytes; `dsa` is a live object whose parameters and private key the
/// caller set. `digestname`, `libctx` and `propq` are NULL on every path this crate reaches
/// (`dsa_do_sign` passes them), so none is read.
pub(crate) unsafe fn ossl_dsa_do_sign_int(
    dgst: *const c_uchar,
    dlen: c_int,
    dsa: *mut Dsa,
    nonce_type: c_uint,
    _digestname: *const c_char,
    _libctx: *mut c_void,
    _propq: *const c_char,
) -> *mut DsaSig {
    let mut kinv: *mut BigNum = ptr::null_mut();
    let mut reason: c_int = ERR_R_BN_LIB;
    let mut ret: *mut DsaSig = ptr::null_mut();
    let mut rv: c_int = 0;
    let mut retries: c_int = 0;
    let mut dlen = dlen;

    // SAFETY: `dsa` is live per the contract.
    unsafe {
        if (*dsa).params.p.is_null() || (*dsa).params.q.is_null() || (*dsa).params.g.is_null() {
            reason = err_reasons::DSA_R_MISSING_PARAMETERS;
            return finish_sign_int(ret, rv, reason, ptr::null_mut(), kinv);
        }
        if (*dsa).priv_key.is_null() {
            reason = err_reasons::DSA_R_MISSING_PRIVATE_KEY;
            return finish_sign_int(ret, rv, reason, ptr::null_mut(), kinv);
        }
    }

    // SAFETY: `DSA_SIG_new` takes no pointers.
    ret = unsafe { crate::dsa::sign::DSA_SIG_new() };
    if ret.is_null() {
        // SAFETY: `ret` is NULL and every other argument is NULL or a local.
        return unsafe { finish_sign_int(ret, rv, reason, ptr::null_mut(), kinv) };
    }
    // SAFETY: `ret` is this call's own object and each slot is NULL or live.
    unsafe {
        (*ret).r = BN_new();
        (*ret).s = BN_new();
        if (*ret).r.is_null() || (*ret).s.is_null() {
            return finish_sign_int(ret, rv, reason, ptr::null_mut(), kinv);
        }
    }

    /* The authority passes `dsa->libctx`; `DSA_new` leaves it NULL, so the default context is
     * selected exactly as `BN_CTX_new_ex(NULL)` selects it. */
    // SAFETY: `dsa` is live per the contract.
    let ctx: *mut BnCtx = unsafe { BN_CTX_new_ex((*dsa).libctx) };
    if ctx.is_null() {
        // SAFETY: `ctx` is NULL; `ret` and `kinv` are NULL or this call's own.
        return unsafe { finish_sign_int(ret, rv, reason, ctx, kinv) };
    }

    /* The authority's four `BN_CTX_get` results, named because the body reads them. */
    // SAFETY: `ctx` is live and every `BN_CTX_get` answers a slot the context owns until the next
    // `BN_CTX_start`.
    let (m, blind, blindm, tmp) = unsafe {
        (
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
            BN_CTX_get(ctx),
        )
    };
    if tmp.is_null() {
        // SAFETY: every argument is NULL, this call's own, or a live context.
        return unsafe { finish_sign_int(ret, rv, reason, ctx, kinv) };
    }

    'redo: loop {
        // SAFETY: `dsa` is live, `ctx` is live, and the two out-parameters are locals; `ret` is
        // this call's own object, so `&raw mut (*ret).r` is a live slot.
        if unsafe {
            dsa_sign_setup(
                dsa,
                ctx,
                &raw mut kinv,
                &raw mut (*ret).r,
                dgst,
                dlen,
                nonce_type,
            )
        } == 0
        {
            break 'redo;
        }

        // SAFETY: `dsa` is live.
        if dlen > unsafe { (BN_num_bits((*dsa).params.q) + 7) / 8 } {
            /*
             * if the digest length is greater than the size of q use the
             * BN_num_bits(dsa->q) leftmost bits of the digest, see fips 186-3,
             * 4.2
             */
            // SAFETY: `dsa` is live.
            dlen = unsafe { (BN_num_bits((*dsa).params.q) + 7) / 8 };
        }
        // SAFETY: `dgst` is readable for `dlen` bytes and `m` is a live slot.
        if unsafe { BN_bin2bn(dgst, dlen, m) }.is_null() {
            break 'redo;
        }

        /*
         * The normal signature calculation is:
         *
         *   s := k^-1 * (m + r * priv_key) mod q
         *
         * We will blind this to protect against side channel attacks
         *
         *   s := blind^-1 * k^-1 * (blind * m + blind * r * priv_key) mod q
         *
         * Generate a blinding value. The size of q is tested in dsa_sign_setup() so there should
         * not be an infinite loop here.
         */
        loop {
            // SAFETY: `dsa` is live, `blind` is a live slot and `ctx` is live.
            if unsafe {
                BN_priv_rand_ex(
                    blind,
                    BN_num_bits((*dsa).params.q) - 1,
                    BN_RAND_TOP_ANY,
                    BN_RAND_BOTTOM_ANY,
                    0,
                    ctx,
                )
            } == 0
            {
                break 'redo;
            }
            // SAFETY: `blind` is a live slot.
            if unsafe { BN_is_zero(blind) } == 0 {
                break;
            }
        }
        // SAFETY: `blind`, `blindm` and `tmp` are live slots.
        unsafe {
            BN_set_flags(blind, BN_FLG_CONSTTIME);
            BN_set_flags(blindm, BN_FLG_CONSTTIME);
            BN_set_flags(tmp, BN_FLG_CONSTTIME);
        }

        // SAFETY: every `BIGNUM` here is live; `dsa` and `ret` are this call's own.
        unsafe {
            /* tmp := blind * priv_key * r mod q */
            if BN_mod_mul(tmp, blind, (*dsa).priv_key, (*dsa).params.q, ctx) == 0
                || BN_mod_mul(tmp, tmp, (*ret).r, (*dsa).params.q, ctx) == 0
            {
                break 'redo;
            }

            /* blindm := blind * m mod q */
            if BN_mod_mul(blindm, blind, m, (*dsa).params.q, ctx) == 0 {
                break 'redo;
            }

            /* s : = (blind * priv_key * r) + (blind * m) mod q */
            if BN_mod_add_quick((*ret).s, tmp, blindm, (*dsa).params.q) == 0 {
                break 'redo;
            }

            /* s := s * k^-1 mod q */
            if BN_mod_mul((*ret).s, (*ret).s, kinv, (*dsa).params.q, ctx) == 0 {
                break 'redo;
            }

            /* s:= s * blind^-1 mod q */
            if BN_mod_inverse(blind, blind, (*dsa).params.q, ctx).is_null() {
                break 'redo;
            }
            if BN_mod_mul((*ret).s, (*ret).s, blind, (*dsa).params.q, ctx) == 0 {
                break 'redo;
            }

            /*
             * Redo if r or s is zero as required by FIPS 186-4: Section 4.6
             * This is very unlikely.
             * Limit the retries so there is no possibility of an infinite
             * loop for bad domain parameter values.
             */
            if BN_is_zero((*ret).r) != 0 || BN_is_zero((*ret).s) != 0 {
                retries += 1;
                if retries > MAX_DSA_SIGN_RETRIES {
                    reason = err_reasons::DSA_R_TOO_MANY_RETRIES;
                    break 'redo;
                }
                continue 'redo;
            }
        }
        rv = 1;
        break 'redo;
    }

    // SAFETY: `ret` is NULL or this call's own; `ctx` is this call's own; `kinv` is NULL or this
    // call's own.
    unsafe { finish_sign_int(ret, rv, reason, ctx, kinv) }
}

/// The authority's `err:` label of [`ossl_dsa_do_sign_int`] (`dsa_ossl.c:194-199`): the reason is
/// raised when the computation did not succeed, then the object is released, then the context, and
/// finally the nonce inverse is **cleared** — it is the inverse of key material.
///
/// # Safety
///
/// `ret` is NULL or this call's own object; `ctx` is NULL or this call's own context; `kinv` is
/// NULL or this call's own `BIGNUM`.
unsafe fn finish_sign_int(
    ret: *mut DsaSig,
    rv: c_int,
    reason: c_int,
    ctx: *mut BnCtx,
    kinv: *mut BigNum,
) -> *mut DsaSig {
    let mut ret = ret;
    if rv == 0 {
        // SAFETY: `DSA_OSS_195` is the generated dynamic-reason site at that line, and `reason` is
        // one of the four codes the authority's `ERR_raise(ERR_LIB_DSA, reason)` can carry there.
        unsafe { raise_site_dynamic(&err_sites::DSA_OSS_195, reason) };
        // SAFETY: `ret` is NULL or this call's own object, and `DSA_SIG_free` accepts NULL.
        unsafe { crate::dsa::sign::DSA_SIG_free(ret) };
        ret = ptr::null_mut();
    }
    // SAFETY: `ctx` is NULL or this call's own; `BN_CTX_free` accepts NULL.
    unsafe { BN_CTX_free(ctx) };
    // SAFETY: `kinv` is NULL or this call's own; `BN_clear_free` accepts NULL.
    unsafe { BN_clear_free(kinv) };
    ret
}

/// `static DSA_SIG *dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)` —
/// `dsa_ossl.c:202-207`.
///
/// The method table's own `dsa_do_sign` member: a call to [`ossl_dsa_do_sign_int`] with
/// `nonce_type = 0` and the three library-context arguments NULL.
///
/// # Safety
///
/// As `DSA_do_sign`'s contract: `dgst` is readable for `dlen` bytes and `dsa` is live.
unsafe extern "C" fn dsa_do_sign(dgst: *const c_uchar, dlen: c_int, dsa: *mut Dsa) -> *mut DsaSig {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        ossl_dsa_do_sign_int(
            dgst,
            dlen,
            dsa,
            0,
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `static int dsa_sign_setup_no_digest(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)` —
/// `dsa_ossl.c:209-215`.
///
/// The method table's `dsa_sign_setup` member: the same call with no digest, which selects the
/// private-draw arm.
///
/// # Safety
///
/// As `DSA_sign_setup`'s contract.
unsafe extern "C" fn dsa_sign_setup_no_digest(
    dsa: *mut Dsa,
    ctx_in: *mut BnCtx,
    kinvp: *mut *mut BigNum,
    rp: *mut *mut BigNum,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { dsa_sign_setup(dsa, ctx_in, kinvp, rp, ptr::null(), 0, 0) }
}

/// `static int dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp,`
/// `const unsigned char *dgst, int dlen, unsigned int nonce_type)` — `dsa_ossl.c:217-353`.
///
/// Draws the nonce `k`, computes `r = (g^k mod p) mod q` into `*rp` and **returns** `k⁻¹ mod q`
/// through `kinvp`, releasing the caller's previous inverse first.
///
/// Four things in the body are contract rather than detail:
///
/// * **The `q_bits < MIN_DSA_SIGN_QBITS` refusal comes before any draw**, so a group too small to
///   sign over is refused rather than signed weakly.
/// * **`k` is drawn so its *width* does not reveal its value**: the authority computes `l = k + q`,
///   then `k = l + q`, and swaps on `BN_is_bit_set(l, q_bits)` — the "equivalent scalar of fixed
///   bit-length" dance its own comment explains. A transcription that computed `g^k` directly
///   would be faster and would leak.
/// * **`k⁻¹` is `k^(q-2) mod q` by Fermat** rather than `BN_mod_inverse`: both the exponent and the
///   modulus are public, so a mod-exp that does not leak the base is enough.
/// * **The nonce is rejected when it is zero**, which is why the loop re-draws.
///
/// `ctx_in` is optional, and the authority's `ctx != ctx_in` test at the `err:` label is what makes
/// a caller's context survive the call while a privately created one does not.
///
/// **One graceful extension, and a court cannot observe it.** The authority declares
/// `BIGNUM *r = *rp;` in its *declaration block*, so a NULL `rp` is dereferenced before any guard
/// runs; this transcription reads `*rp` after the three refusals, so a NULL `rp` on a body with no
/// parameters or no private key is answered `0` rather than crashing. That is the same shape
/// `src/bn/rand.rs` records for a NULL `range` — the crate's `as_ref` convention, *not* a claim
/// about the authority's null dereference — and `RT-DSA` passes a live `BIGNUM` at every one of its
/// four `DSA_sign_setup` arms for exactly that reason: a probe that kills the authority compares
/// nothing.
///
/// # Safety
///
/// `dsa` is a live object with `p`, `q`, `g` and a private key; `ctx_in` is NULL or live; `kinvp`
/// and `rp` are live out-parameters; `dgst` is NULL or readable for `dlen` bytes.
#[allow(clippy::too_many_arguments)]
unsafe fn dsa_sign_setup(
    dsa: *mut Dsa,
    ctx_in: *mut BnCtx,
    kinvp: *mut *mut BigNum,
    rp: *mut *mut BigNum,
    dgst: *const c_uchar,
    dlen: c_int,
    nonce_type: c_uint,
) -> c_int {
    let mut kinv: *mut BigNum = ptr::null_mut();
    let mut ret: c_int = 0;

    // SAFETY: `dsa` is live per the contract.
    unsafe {
        if (*dsa).params.p.is_null() || (*dsa).params.q.is_null() || (*dsa).params.g.is_null() {
            raise_site(&err_sites::DSA_OSS_230);
            return 0;
        }

        /* Reject obviously invalid parameters */
        if BN_is_zero((*dsa).params.p) != 0
            || BN_is_zero((*dsa).params.q) != 0
            || BN_is_zero((*dsa).params.g) != 0
            || BN_is_negative((*dsa).params.p) != 0
            || BN_is_negative((*dsa).params.q) != 0
            || BN_is_negative((*dsa).params.g) != 0
        {
            raise_site(&err_sites::DSA_OSS_241);
            return 0;
        }
        if (*dsa).priv_key.is_null() {
            raise_site(&err_sites::DSA_OSS_245);
            return 0;
        }
    }

    // SAFETY: `BN_new` allocates without touching a caller pointer.
    let k = unsafe { BN_new() };
    // SAFETY: as above.
    let l = unsafe { BN_new() };
    // SAFETY: `rp` is a live out-parameter.
    let r = unsafe { *rp };
    if k.is_null() || l.is_null() {
        // SAFETY: both are NULL or this call's own, and `BN_clear_free` accepts NULL.
        unsafe {
            BN_clear_free(k);
            BN_clear_free(l);
        }
        return ret;
    }

    /* if you don't pass in ctx_in you get a default libctx */
    let ctx: *mut BnCtx = if ctx_in.is_null() {
        // SAFETY: `BN_CTX_new_ex` reads no caller pointer.
        unsafe { BN_CTX_new_ex(ptr::null_mut()) }
    } else {
        ctx_in
    };

    /* Preallocate space */
    // SAFETY: `dsa` is live and `k` and `l` are live.
    let (q_bits, q_words) = unsafe { (BN_num_bits((*dsa).params.q), bn_get_top((*dsa).params.q)) };
    if q_bits < MIN_DSA_SIGN_QBITS
        // SAFETY: `k` is live and `q_words + 2` is its own width's bound.
        || unsafe { bn_wexpand(k, q_words + 2) }.is_null()
        // SAFETY: `l` is live and `q_words + 2` is `k`'s own width's bound.
        || unsafe { bn_wexpand(l, q_words + 2) }.is_null()
    {
        // SAFETY: `ctx`, `k` and `l` are this call's own or the caller's.
        unsafe { sign_setup_err(0, ctx, ctx_in, k, l, kinv) };
        return ret;
    }

    /* Get random k */
    loop {
        if !dgst.is_null() {
            if nonce_type == 1 {
                // D333's recorded reduction: the authority calls
                // `ossl_gen_deterministic_nonce_rfc6979` (`crypto/deterministic_nonce.c:181`)
                // here, whose first act is a fetch of the `HMAC-DRBG-KDF` row this crate's default
                // provider does not publish, so a faithful transcription answers 0 through the
                // same `goto err`. See this module's header.
                // SAFETY: `ctx`, `k` and `l` are this call's own or the caller's.
                unsafe { sign_setup_err(0, ctx, ctx_in, k, l, kinv) };
                return ret;
            } else {
                /*
                 * We calculate k from SHA512(private_key + H(message) + random).
                 * This protects the private key from a weak PRNG.
                 */
                // SAFETY: `dsa` is live; `dgst` is readable for `dlen`; `k` and `ctx` are live.
                let ok = unsafe {
                    ossl_bn_gen_dsa_nonce_fixed_top(
                        k,
                        (*dsa).params.q,
                        (*dsa).priv_key,
                        dgst,
                        dlen.max(0) as usize,
                        ctx,
                    )
                };
                if ok == 0 {
                    // SAFETY: `ctx`, `k` and `l` are this call's own or the caller's.
                    unsafe { sign_setup_err(0, ctx, ctx_in, k, l, kinv) };
                    return ret;
                }
            }
        // SAFETY: `k` and `ctx` are live and `dsa` is the live object the caller passed.
        } else if unsafe { ossl_bn_priv_rand_range_fixed_top(k, (*dsa).params.q, 0, ctx) } == 0 {
            // SAFETY: `ctx`, `k` and `l` are this call's own or the caller's.
            unsafe { sign_setup_err(0, ctx, ctx_in, k, l, kinv) };
            return ret;
        }
        // SAFETY: `k` is live.
        if unsafe { ossl_bn_is_word_fixed_top(k, 0) } == 0 {
            break;
        }
    }

    // SAFETY: both are live.
    unsafe {
        BN_set_flags(k, BN_FLG_CONSTTIME);
        BN_set_flags(l, BN_FLG_CONSTTIME);
    }

    // SAFETY: `dsa` is live.
    if unsafe { (*dsa).flags & DSA_FLAG_CACHE_MONT_P } != 0 {
        // SAFETY: `dsa` is live, `ctx` is live, and the slot is the object's own.
        let mont = unsafe {
            BN_MONT_CTX_set_locked(
                ptr::addr_of_mut!((*dsa).method_mont_p),
                (*dsa).lock,
                (*dsa).params.p,
                ctx,
            )
        };
        if mont.is_null() {
            // SAFETY: `ctx`, `k` and `l` are this call's own or the caller's.
            unsafe { sign_setup_err(0, ctx, ctx_in, k, l, kinv) };
            return ret;
        }
    }

    /* Compute r = (g^k mod p) mod q */

    /*
     * We do not want timing information to leak the length of k, so we
     * compute G^k using an equivalent scalar of fixed bit-length.
     *
     * We unconditionally perform both of these additions to prevent a
     * small timing information leakage.  We then choose the sum that is
     * one bit longer than the modulus.
     *
     * There are some concerns about the efficacy of doing this.  More
     * specifically refer to the discussion starting with:
     *     https://github.com/openssl/openssl/pull/7486#discussion_r228323705
     * The fix is to rework BN so these gymnastics aren't required.
     */
    // SAFETY: `l`, `k`, `dsa`, `r` and `ctx` are live.
    unsafe {
        if BN_add(l, k, (*dsa).params.q) == 0 || BN_add(k, l, (*dsa).params.q) == 0 {
            sign_setup_err(0, ctx, ctx_in, k, l, kinv);
            return ret;
        }

        BN_consttime_swap(BN_is_bit_set(l, q_bits) as c_ulong, k, l, q_words + 2);

        let meth = (*dsa).meth;
        let exp = if meth.is_null() {
            None
        } else {
            (*meth).bn_mod_exp
        };
        let ok = match exp {
            // SAFETY: `f` is the table's entry point, handed the arguments the authority hands it.
            Some(f) => f(
                dsa,
                r,
                (*dsa).params.g,
                k,
                (*dsa).params.p,
                ctx,
                (*dsa).method_mont_p,
            ),
            // SAFETY: every argument is live.
            None => BN_mod_exp_mont(
                r,
                (*dsa).params.g,
                k,
                (*dsa).params.p,
                ctx,
                (*dsa).method_mont_p,
            ),
        };
        if ok == 0 {
            sign_setup_err(0, ctx, ctx_in, k, l, kinv);
            return ret;
        }

        /* `BN_mod(r, r, q, ctx)` is the header's macro over `BN_div(NULL, r, r, q, ctx)`. */
        if BN_div(ptr::null_mut(), r, r, (*dsa).params.q, ctx) == 0 {
            sign_setup_err(0, ctx, ctx_in, k, l, kinv);
            return ret;
        }

        /* Compute part of 's = inv(k) (m + xr) mod q' */
        kinv = dsa_mod_inverse_fermat(k, (*dsa).params.q, ctx);
        if kinv.is_null() {
            sign_setup_err(0, ctx, ctx_in, k, l, kinv);
            return ret;
        }

        BN_clear_free(*kinvp);
        *kinvp = kinv;
        kinv = ptr::null_mut();
        ret = 1;
    }

    // The authority's `err:` label, reached by falling through on success.
    // SAFETY: `ctx` is NULL, the caller's or this call's own; `k` and `l` are this call's own and
    // `kinv` is NULL because it has been handed to the caller.
    unsafe { sign_setup_err(ret, ctx, ctx_in, k, l, kinv) };
    ret
}

/// `dsa_sign_setup`'s `err:` label (`dsa_ossl.c:346-353`): `ERR_R_BN_LIB` when the call failed,
/// then the context — **only when it was not the caller's** — then the two scratch values and the
/// inverse, cleared because all three are key material.
///
/// # Safety
///
/// `ctx` is NULL, the caller's, or this call's own; `ctx_in` is the caller's; `k`, `l` and `kinv`
/// are NULL or this call's own.
unsafe fn sign_setup_err(
    ret: c_int,
    ctx: *mut BnCtx,
    ctx_in: *mut BnCtx,
    k: *mut BigNum,
    l: *mut BigNum,
    kinv: *mut BigNum,
) {
    // The authority reaches this label on success too, where `ret` is 1 and **nothing is raised**;
    // the guard is the authority's own `if (!ret)`.
    if ret == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_OSS_347) };
    }
    // SAFETY: `ctx` is NULL, the caller's or this call's own.
    unsafe {
        if ctx != ctx_in {
            BN_CTX_free(ctx);
        }
        BN_clear_free(k);
        BN_clear_free(l);
        BN_clear_free(kinv);
    }
}

/// `static int dsa_do_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa)` —
/// `dsa_ossl.c:355-457`.
///
/// Three refusals before any arithmetic — a missing parameter, a `q` that is not 160/224/256 bits
/// (`DSA_R_BAD_Q_VALUE`) and a modulus past [`OPENSSL_DSA_MAX_MODULUS_BITS`] — then `u1 = m·w mod
/// q`, `u2 = r·w mod q` with `w = s⁻¹ mod q`, and the single comparison `g^u1·y^u2 mod p mod q ==
/// r`. The two range tests on `r` and `s` answer **0** rather than -1: a signature out of range is
/// a wrong signature, not a broken caller.
///
/// # Safety
///
/// `dgst` is readable for `dgst_len` bytes; `sig` is a live signature object; `dsa` is a live
/// object.
unsafe extern "C" fn dsa_do_verify(
    dgst: *const c_uchar,
    dgst_len: c_int,
    sig: *mut DsaSig,
    dsa: *mut Dsa,
) -> c_int {
    let mut mont: *mut MontCtx = ptr::null_mut();
    let mut ret: c_int = -1;
    let mut dgst_len = dgst_len;

    // SAFETY: `dsa` is live per the contract.
    if unsafe {
        (*dsa).params.p.is_null() || (*dsa).params.q.is_null() || (*dsa).params.g.is_null()
    } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_OSS_367) };
        return -1;
    }

    // SAFETY: `dsa` is live.
    let i = unsafe { BN_num_bits((*dsa).params.q) };
    /* fips 186-3 allows only different sizes for q */
    if i != 160 && i != 224 && i != 256 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_OSS_374) };
        return -1;
    }

    // SAFETY: `dsa` is live.
    if unsafe { BN_num_bits((*dsa).params.p) } > OPENSSL_DSA_MAX_MODULUS_BITS {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_OSS_379) };
        return -1;
    }

    // SAFETY: `BN_new` allocates without touching a caller pointer.
    let u1 = unsafe { BN_new() };
    // SAFETY: as above.
    let u2 = unsafe { BN_new() };
    // SAFETY: as above.
    let t1 = unsafe { BN_new() };
    /* verify does not need a libctx */
    // SAFETY: `BN_CTX_new_ex` reads no caller pointer.
    let ctx: *mut BnCtx = unsafe { BN_CTX_new_ex(ptr::null_mut()) };
    if u1.is_null() || u2.is_null() || t1.is_null() || ctx.is_null() {
        // SAFETY: each pointer is NULL or this call's own.
        return unsafe { verify_epilogue(ret, ctx, u1, u2, t1) };
    }

    let mut r: *const BigNum = ptr::null();
    let mut s: *const BigNum = ptr::null();
    // SAFETY: `sig` is live and the two out-parameters are locals.
    unsafe { crate::dsa::sign::DSA_SIG_get0(sig, &raw mut r, &raw mut s) };

    // SAFETY: `r`, `s`, `dsa` and `ctx` are live.
    unsafe {
        if BN_is_zero(r) != 0
            || BN_is_negative(r) != 0
            || crate::bn::arith::BN_ucmp(r, (*dsa).params.q) >= 0
        {
            return verify_epilogue(0, ctx, u1, u2, t1);
        }
        if BN_is_zero(s) != 0
            || BN_is_negative(s) != 0
            || crate::bn::arith::BN_ucmp(s, (*dsa).params.q) >= 0
        {
            return verify_epilogue(0, ctx, u1, u2, t1);
        }

        /* Calculate W = inv(S) mod Q save W in u2 */
        if BN_mod_inverse(u2, s, (*dsa).params.q, ctx).is_null() {
            return verify_epilogue(ret, ctx, u1, u2, t1);
        }

        /* save M in u1 */
        if dgst_len > (i >> 3) {
            /*
             * if the digest length is greater than the size of q use the
             * BN_num_bits(dsa->q) leftmost bits of the digest, see fips 186-3, 4.2
             */
            dgst_len = i >> 3;
        }
        if BN_bin2bn(dgst, dgst_len, u1).is_null() {
            return verify_epilogue(ret, ctx, u1, u2, t1);
        }

        /* u1 = M * w mod q */
        if BN_mod_mul(u1, u1, u2, (*dsa).params.q, ctx) == 0 {
            return verify_epilogue(ret, ctx, u1, u2, t1);
        }

        /* u2 = r * w mod q */
        if BN_mod_mul(u2, r, u2, (*dsa).params.q, ctx) == 0 {
            return verify_epilogue(ret, ctx, u1, u2, t1);
        }

        if (*dsa).flags & DSA_FLAG_CACHE_MONT_P != 0 {
            mont = BN_MONT_CTX_set_locked(
                ptr::addr_of_mut!((*dsa).method_mont_p),
                (*dsa).lock,
                (*dsa).params.p,
                ctx,
            );
            if mont.is_null() {
                return verify_epilogue(ret, ctx, u1, u2, t1);
            }
        }

        let meth = (*dsa).meth;
        let exp = if meth.is_null() {
            None
        } else {
            (*meth).dsa_mod_exp
        };
        let ok = match exp {
            // SAFETY: `f` is the table's entry point, handed the arguments the authority hands it.
            Some(f) => f(
                dsa,
                t1,
                (*dsa).params.g,
                u1,
                (*dsa).pub_key,
                u2,
                (*dsa).params.p,
                ctx,
                mont,
            ),
            // SAFETY: every argument is live.
            None => BN_mod_exp2_mont(
                t1,
                (*dsa).params.g,
                u1,
                (*dsa).pub_key,
                u2,
                (*dsa).params.p,
                ctx,
                mont,
            ),
        };
        if ok == 0 {
            return verify_epilogue(ret, ctx, u1, u2, t1);
        }

        /* let u1 = u1 mod q */
        if BN_div(ptr::null_mut(), u1, t1, (*dsa).params.q, ctx) == 0 {
            return verify_epilogue(ret, ctx, u1, u2, t1);
        }

        /*
         * V is now in u1.  If the signature is correct, it will be equal to R.
         */
        ret = c_int::from(crate::bn::arith::BN_ucmp(u1, r) == 0);
    }

    // SAFETY: `ctx` and the three temporaries are this call's own.
    unsafe { verify_epilogue(ret, ctx, u1, u2, t1) }
}

/// `dsa_do_verify`'s `err:` label (`dsa_ossl.c:452-457`): a negative answer raises `ERR_R_BN_LIB`,
/// then the context and the three temporaries are released. `0` and `1` raise nothing.
///
/// # Safety
///
/// `ctx` is NULL or this call's own; `u1`, `u2` and `t1` are NULL or this call's own.
unsafe fn verify_epilogue(
    ret: c_int,
    ctx: *mut BnCtx,
    u1: *mut BigNum,
    u2: *mut BigNum,
    t1: *mut BigNum,
) -> c_int {
    if ret < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_OSS_453) };
    }
    // SAFETY: each is NULL or this call's own; `BN_CTX_free` and `BN_free` accept NULL.
    unsafe {
        BN_CTX_free(ctx);
        BN_free(u1);
        BN_free(u2);
        BN_free(t1);
    }
    ret
}

/// `static int dsa_init(DSA *dsa)` — `dsa_ossl.c:459-464`.
///
/// Sets the Montgomery-cache flag and bumps the provider's change counter, which is why every
/// object `DSA_new` builds caches a context for `p` on its first sign or verify rather than
/// recomputing one per call.
///
/// # Safety
///
/// `dsa` is a live object.
unsafe extern "C" fn dsa_init(dsa: *mut Dsa) -> c_int {
    // SAFETY: `dsa` is live per the contract.
    unsafe {
        (*dsa).flags |= DSA_FLAG_CACHE_MONT_P;
        (*dsa).dirty_cnt += 1;
    }
    1
}

/// `static int dsa_finish(DSA *dsa)` — `dsa_ossl.c:466-471`. Releases the cached Montgomery
/// context.
///
/// # Safety
///
/// `dsa` is a live object.
unsafe extern "C" fn dsa_finish(dsa: *mut Dsa) -> c_int {
    // SAFETY: `dsa` is live and `method_mont_p` is NULL or the object's own context.
    unsafe { BN_MONT_CTX_free((*dsa).method_mont_p) };
    1
}

/// `static BIGNUM *dsa_mod_inverse_fermat(const BIGNUM *k, const BIGNUM *q, BN_CTX *ctx)` —
/// `dsa_ossl.c:473-500`.
///
/// The authority's own comment: "Since q is prime, Fermat's Little Theorem applies, which reduces
/// this to mod-exp operation. Both the exponent and modulus are public information so a mod-exp
/// that doesn't leak the base is sufficient. A newly allocated BIGNUM is returned which the caller
/// must free."
///
/// `res` is answered only when **all four** of `BN_CTX_get`, `BN_set_word(r, 2)`, `BN_sub(e, q, r)`
/// and `BN_mod_exp_mont(r, k, e, q, ctx, NULL)` succeed, so a `BN_CTX_get` that answers NULL falls
/// into the release arm rather than dereferencing the NULL.
///
/// # Safety
///
/// `k` and `q` are live; `ctx` is live.
unsafe fn dsa_mod_inverse_fermat(
    k: *const BigNum,
    q: *const BigNum,
    ctx: *mut BnCtx,
) -> *mut BigNum {
    // SAFETY: `BN_new` allocates without touching a caller pointer.
    let r = unsafe { BN_new() };
    if r.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live per the contract.
    unsafe {
        BN_CTX_start(ctx);
        let e = BN_CTX_get(ctx);
        if !e.is_null()
            && BN_set_word(r, 2) != 0
            && BN_sub(e, q, r) != 0
            && BN_mod_exp_mont(r, k, e, q, ctx, ptr::null_mut()) != 0
        {
            BN_CTX_end(ctx);
            return r;
        }
        BN_free(r);
        BN_CTX_end(ctx);
    }
    ptr::null_mut()
}
