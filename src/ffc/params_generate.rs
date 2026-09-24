//! Phase 8 — `crypto/ffc/ffc_params_generate.c`: FIPS 186-4 and 186-2 parameter generation
//! *and* validation.
//!
//! This is the unit D329 measured as the FFC layer's largest and named as the reason the layer
//! was not half-landed: 1,071 lines carrying one shared generator/verifier, six static helpers
//! and four entry points. **Validation lives here and not in `ffc_params_validate.c`** — the
//! authority's own header comment says so — and the split is why the `mode` parameter exists:
//! `ossl_ffc_params_FIPS186_4_gen_verify` walks the same seed chain in both directions and
//! compares its arithmetic against the caller's `p`, `q` and `g` in verify mode.
//!
//! ## The profile's arms, which are the `#else` halves throughout
//!
//! * `ffc_validate_LN` has a `#ifdef FIPS_MODULE` arm and an `#else` one, and they disagree about
//!   what is acceptable. This profile takes the `#else`: for **DH** only `1024/160` and
//!   `2048/224|256`, and for **DSA** anything with `L >= 1024`, `N >= 160` and `N <= 512`, with
//!   the strength stepping at 3072/256, 2048/224 and 1024/160. The FIPS arm is stricter and drops
//!   the legacy 1024/160 DH pair; it is named here rather than compiled.
//! * `N > 512` for DSA is refused with `ERR_raise_data`, so its coordinate's *message* is part of
//!   the observable record and is formatted here rather than stored as a constant.
//! * The `#else` arm's `verify` parameter is **unused**: the legacy 1024/160 DH pair is allowed in
//!   a verify run and in a generate run alike, where the FIPS arm distinguishes them. The
//!   parameter is kept because the call site passes it.
//!
//! ## What each generator promises, and where the promise is checked
//!
//! * `generate_q_fips186_4` builds `q` from `Hash(seed)` with the top and bottom bits forced, and
//!   **fails hard when the seed was passed in** (`FFC_CHECK_Q_NOT_PRIME`) rather than trying
//!   another seed — a caller-supplied seed that does not produce a prime is a caller error, and
//!   retrying it would loop forever.
//! * `generate_p` walks `offset` from 1 up to `4L - 1`, hashing `seed + offset + j` for
//!   `j = 0..n`, and accepts the first `p >= 2^(L-1)` that is probably prime. Its answer is
//!   three-valued: `1` found, `0` exhausted (`FFC_CHECK_P_NOT_PRIME`), `-1` error.
//! * `generate_canonical_g` hashes `seed || "ggen" || index || counter` and raises the result to
//!   `e = (p-1)/q`; it tries counters `1..0xFFFF` and its failure sets `FFC_CHECK_INVALID_G`.
//! * `generate_unverifiable_g` searches `h = 2, 3, ...` for the first `h^e mod p > 1`, and that
//!   terminating condition is what makes the result a generator of the order-`q` subgroup.
//!
//! ## The buffers, and the one that is copied before every attempt
//!
//! `seed_tmp` is the working copy: `generate_p` **increments it in place** (`buf[k]++` from the
//! low byte), so the caller `memcpy`s the seed into it immediately before every `generate_p` call
//! and the caller's seed survives. That `memcpy` sits *inside* the outer loop, which is what makes
//! a retried `p` search start from the same seed rather than from the incremented buffer.
//!
//! ## The `BN_CTX` temporaries are one pool, and `p`/`q` are not always from it
//!
//! `g`, `pm1`, `e`, `test` and `tmp` come from `BN_CTX_get` in that order; `p` and `q` come from
//! two more **only on the arms that generate them**. The `g_only` path aliases `params->p` and
//! `params->q` instead, so a transcription that took them from the pool unconditionally would
//! copy the caller's numbers where the authority reads them — and the verify-mode comparisons
//! against `params->q` and `params->p` would then be comparing a number with itself.
//!
//! ## The `pass:` label falls into the `err:` epilogue
//!
//! Both verifiers' `pass:` label is *immediately followed* by the cleanup, so the
//! "validating `p` and `q` only" early exit releases the context, the Montgomery context, the
//! digest context and the digest exactly as the failure paths do. Missing that would leak a
//! `BN_CTX` and an `EVP_MD` on every `VALIDATE_PQ`-only call.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::bn::arith::{
    BN_add, BN_add_word, BN_cmp, BN_div, BN_lshift, BN_lshift1, BN_mask_bits, BN_sub,
};
use crate::bn::bignum::{
    BN_bin2bn, BN_copy, BN_dup, BN_free, BN_set_word, BN_value_one, BN_zero_ex, BigNum,
};
use crate::bn::ctx::{
    ossl_bn_get_libctx, BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start,
    BN_GENCB_call, BnCtx, BnGencb,
};
use crate::bn::mont::{
    BN_MONT_CTX_free, BN_MONT_CTX_new, BN_MONT_CTX_set, BN_mod_exp_mont, MontCtx,
};
use crate::bn::primes::BN_check_prime;
use crate::evp::digest::{
    EVP_Digest, EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EvpMd, EvpMdCtx,
};
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::err::err_sites::{
    FFC_PARAMS_GENERATE_77, FFC_PARAMS_GENERATE_82, FFC_PARAMS_GENERATE_94,
};
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

use super::params::{ossl_ffc_params_enable_flags, ossl_ffc_params_set_validate_params};
use super::params_validate::ossl_ffc_params_validate_unverifiable_g;
use super::{
    FfcParams, FFC_CHECK_BAD_LN_PAIR, FFC_CHECK_COUNTER_MISMATCH, FFC_CHECK_G_MISMATCH,
    FFC_CHECK_INVALID_COUNTER, FFC_CHECK_INVALID_G, FFC_CHECK_INVALID_PQ,
    FFC_CHECK_INVALID_Q_VALUE, FFC_CHECK_INVALID_SEED_SIZE, FFC_CHECK_MISSING_SEED_OR_COUNTER,
    FFC_CHECK_P_MISMATCH, FFC_CHECK_P_NOT_PRIME, FFC_CHECK_Q_MISMATCH, FFC_CHECK_Q_NOT_PRIME,
    FFC_PARAM_FLAG_VALIDATE_G, FFC_PARAM_FLAG_VALIDATE_LEGACY, FFC_PARAM_FLAG_VALIDATE_PQ,
    FFC_PARAM_FLAG_VALIDATE_PQG, FFC_PARAM_MODE_GENERATE, FFC_PARAM_MODE_VERIFY,
    FFC_PARAM_RET_STATUS_FAILED, FFC_PARAM_RET_STATUS_SUCCESS, FFC_PARAM_RET_STATUS_UNVERIFIABLE_G,
    FFC_PARAM_TYPE_DH, FFC_PARAM_TYPE_DSA, FFC_UNVERIFIABLE_GINDEX,
};

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`.
///
/// The width of the scratch digests in `generate_canonical_g` and `generate_p`, and of the
/// stacked arrays in the 186-2 verifier.
const EVP_MAX_MD_SIZE: usize = 64;

/// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h:28`.
const SHA_DIGEST_LENGTH: usize = 20;
/// `SHA224_DIGEST_LENGTH` — `include/openssl/sha.h:78`.
const SHA224_DIGEST_LENGTH: usize = 28;
/// `SHA256_DIGEST_LENGTH` — `include/openssl/sha.h:79`.
const SHA256_DIGEST_LENGTH: usize = 32;

/// `160` — the SHA-1 digest length the FIPS 186-2 verifier divides by in `n = (L - 1) / 160`.
///
/// It is hard-coded rather than `SHA_DIGEST_LENGTH` in the authority too: the 186-2 `q` chain is
/// SHA-1-shaped even when the digest the caller chose is SHA-256, which is what the
/// `test/ffc_internal_test.c` 186-2 comparison relies on.
const FIPS186_2_N_DIVISOR: usize = 160;

/// The allocation-tracking `file` argument for this unit's seed buffers.
///
/// `crypto/ffc/ffc_params_generate.c` is a source-tree file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — the spelling D280 read out of the authority's own object
/// files.
const FILE_FFC_PARAMS_GENERATE: *const c_char =
    c"../../src/openssl-3.6.4/crypto/ffc/ffc_params_generate.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `static int ffc_validate_LN(size_t L, size_t N, int type, int verify)` —
/// `crypto/ffc/ffc_params_generate.c:67-98`. **The `#else` arm.**
///
/// Returns the security strength, or 0 for "not an acceptable pair". The DH table is
/// SP800-56A r3 §5.5.1 Table 1's `2048/224|256` plus the legacy `1024/160` the non-FIPS arm
/// allows; the DSA table is FIPS 186-4 §4.2's, expressed as three `L`/`N` thresholds rather than
/// equalities, so `L = 4096, N = 256` is a valid DSA pair with strength 128.
///
/// `verify` is **not read on this arm**: the `#ifdef FIPS_MODULE` arm uses it to allow 1024/160
/// only when verifying, and the `#else` arm allows it in both modes. The parameter is kept
/// because the call site passes it and because the FIPS arm's shape is the reference.
#[allow(non_snake_case)] // the authority's name, kept verbatim
fn ffc_validate_LN(l: usize, n: usize, type_: c_int, _verify: c_int) -> c_int {
    if type_ == FFC_PARAM_TYPE_DH {
        /* Allow legacy 1024/160 in non fips mode */
        if l == 1024 && n == 160 {
            return 80;
        }
        /* Valid DH L,N parameters from SP800-56Ar3 5.5.1 Table 1 */
        if l == 2048 && (n == 224 || n == 256) {
            return 112;
        }
        // SAFETY: the site is a generated constant and `raise_site` takes its address.
        unsafe { raise_site(&FFC_PARAMS_GENERATE_77) };
    } else if type_ == FFC_PARAM_TYPE_DSA {
        if n > 512 {
            let msg = format!("N is {n}, but the maximum supported N is 512\0");
            // SAFETY: `msg` is NUL-terminated and outlives the call.
            unsafe { raise_site_data(&FFC_PARAMS_GENERATE_82, msg.as_ptr().cast()) };
            return 0;
        }
        if l >= 3072 && n >= 256 {
            return 128;
        }
        if l >= 2048 && n >= 224 {
            return 112;
        }
        if l >= 1024 && n >= 160 {
            return 80;
        }
        // SAFETY: the site is a generated constant and `raise_site` takes its address.
        unsafe { raise_site(&FFC_PARAMS_GENERATE_94) };
    }
    0
}

/// `static int generate_unverifiable_g(BN_CTX *ctx, BN_MONT_CTX *mont, BIGNUM *g, BIGNUM *hbn,`
/// `const BIGNUM *p, const BIGNUM *e, const BIGNUM *pm1, int *hret)` —
/// `crypto/ffc/ffc_params_generate.c:102-128`.
///
/// FIPS 186-4 A.2.1's unverifiable generation of `g`. The search starts at `h = 2` and tries
/// `g = h^e mod p` (with `e = (p - 1) / q`), accepting the first `g > 1`; the guard
/// `BN_cmp(hbn, pm1) >= 0` gives up when `h` reaches `p - 1`, which is a refusal rather than a
/// `g = 1`.
///
/// `*hret` is written **only on success**, so a caller's `h` is untouched by a refusal — which is
/// why `ossl_ffc_params_FIPS186_4_gen_verify` initialises its `hret` to 0 and the 186-2 twin
/// initialises its own to -1.
///
/// # Safety
///
/// Every pointer must be live; `mont` must have been set for `p`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn generate_unverifiable_g(
    ctx: *mut BnCtx,
    mont: *mut MontCtx,
    g: *mut BigNum,
    hbn: *mut BigNum,
    p: *const BigNum,
    e: *const BigNum,
    pm1: *const BigNum,
    hret: *mut c_int,
) -> c_int {
    let mut h: c_int = 2;

    /* Step (2): choose h (where 1 < h) */
    // SAFETY: every pointer is live per this function's `# Safety` section.
    unsafe {
        if BN_set_word(hbn, 2) == 0 {
            return 0;
        }

        loop {
            /* Step (3): g = h^e % p */
            if BN_mod_exp_mont(g, hbn, e, p, ctx, mont) == 0 {
                return 0;
            }
            /* Step (4): Finish if g > 1 */
            if BN_cmp(g, BN_value_one()) > 0 {
                break;
            }

            /* Step (2) Choose any h in the range 1 < h < (p-1) */
            if BN_add_word(hbn, 1) == 0 || BN_cmp(hbn, pm1) >= 0 {
                return 0;
            }
            h += 1;
        }
        *hret = h;
    }
    1
}

/// `static int generate_canonical_g(BN_CTX *ctx, BN_MONT_CTX *mont, const EVP_MD *evpmd,`
/// `BIGNUM *g, BIGNUM *tmp, const BIGNUM *p, const BIGNUM *e, int gindex,`
/// `unsigned char *seed, size_t seedlen)` — `crypto/ffc/ffc_params_generate.c:139-195`.
///
/// FIPS 186-4 A.2.3's canonical generation of `g`: `W = Hash(seed || "ggen" || index || counter)`
/// and `g = W^e mod p`, for `counter` from 1 to `0xFFFF`, accepting the first `g > 1`.
///
/// **The three `md[0..3]` assignments are the message, and `md` is then overwritten by the
/// digest.** The authority reuses one buffer for both, which is why the index/counter bytes are
/// written *before* `EVP_DigestInit_ex` and the digest replaces them at the final. Two buffers
/// would be behaviourally identical and structurally different; this keeps the single buffer
/// because the overlap is what the authority's code means.
///
/// The `break` on a failed operation exits the loop and answers the current `ret` — so an
/// `EVP_DigestUpdate` failure and "every counter produced `g == 1`" are the same answer, 0.
///
/// # Safety
///
/// Every pointer must be live; `mont` must have been set for `p`; `seed` must be readable for
/// `seedlen` bytes; `evpmd` must be a live fetched digest.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn generate_canonical_g(
    ctx: *mut BnCtx,
    mont: *mut MontCtx,
    evpmd: *const EvpMd,
    g: *mut BigNum,
    tmp: *mut BigNum,
    p: *const BigNum,
    e: *const BigNum,
    gindex: c_int,
    seed: *mut u8,
    seedlen: usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut md = [0u8; EVP_MAX_MD_SIZE];

    // SAFETY: `evpmd` is live per this function's `# Safety` section.
    let mdsize = unsafe { EVP_MD_get_size(evpmd) };
    if mdsize <= 0 {
        return 0;
    }

    // SAFETY: `EVP_MD_CTX_new` answers NULL or a fresh context.
    let mctx: *mut EvpMdCtx = EVP_MD_CTX_new();
    if mctx.is_null() {
        return 0;
    }

    /*
     * A.2.3 Step (4) & (5)
     * A.2.4 Step (6) & (7)
     * counter = 0; counter += 1
     */
    let mut counter: c_int = 1;
    while counter <= 0xFFFF {
        /*
         * A.2.3 Step (7) & (8) & (9)
         * A.2.4 Step (9) & (10) & (11)
         * W = Hash(seed || "ggen" || index || counter)
         * g = W^e % p
         */
        const GGEN: [u8; 4] = [0x67, 0x67, 0x65, 0x6e];

        md[0] = (gindex & 0xff) as u8;
        md[1] = ((counter >> 8) & 0xff) as u8;
        md[2] = (counter & 0xff) as u8;
        // SAFETY: `mctx` is live, `evpmd` is live, `seed` is readable for `seedlen`, `md` is this
        // frame's array and every pointer/length below is within it.
        let ok = unsafe {
            EVP_DigestInit_ex(mctx, evpmd, ptr::null_mut()) != 0
                && EVP_DigestUpdate(mctx, seed.cast(), seedlen) != 0
                && EVP_DigestUpdate(mctx, GGEN.as_ptr().cast(), GGEN.len()) != 0
                && EVP_DigestUpdate(mctx, md.as_ptr().cast(), 3) != 0
                && EVP_DigestFinal_ex(mctx, md.as_mut_ptr(), ptr::null_mut()) != 0
        };
        if !ok {
            break; /* exit on failure */
        }
        // SAFETY: `md` holds `mdsize` bytes from the final; `tmp`, `g`, `p`, `e` are live and
        // `ctx`/`mont` are live.
        let ok = unsafe {
            !BN_bin2bn(md.as_ptr(), mdsize, tmp).is_null()
                && BN_mod_exp_mont(g, tmp, e, p, ctx, mont) != 0
        };
        if !ok {
            break; /* exit on failure */
        }
        /*
         * A.2.3 Step (10)
         * A.2.4 Step (12)
         * Found a value for g if (g >= 2)
         */
        // SAFETY: `g` is live.
        if unsafe { BN_cmp(g, BN_value_one()) } > 0 {
            ret = 1;
            break; /* found g */
        }
        counter += 1;
    }
    // SAFETY: `mctx` is live and `EVP_MD_CTX_free` accepts it.
    unsafe { EVP_MD_CTX_free(mctx) };
    ret
}

/// `static int generate_p(BN_CTX *ctx, const EVP_MD *evpmd, int max_counter, int n,`
/// `unsigned char *buf, size_t buf_len, const BIGNUM *q, BIGNUM *p, int L, BN_GENCB *cb,`
/// `int *counter, int *res)` — `crypto/ffc/ffc_params_generate.c:198-318`.
///
/// "Generation of p is the same for FIPS 186-4 & FIPS 186-2" — the one helper both verifiers
/// share, and the reason two different L/N tables can sit over one piece of arithmetic.
///
/// FIPS 186-4 A.1.1.2/A.1.1.3 steps (11)/(13): for each offset,
/// `W = sum V(j) * 2^(outlen*j)` for `j = 0..n` where `V(j) = Hash((seed + offset + j) mod
/// 2^seedlen)`, then `X = W + 2^(L-1)` with `W` masked to `L-1` bits, `c = X mod 2q` and
/// **`p = X - (c - 1)`** — which is `X - c + 1`, the next value congruent to 1 mod 2q at or above
/// `X`.
///
/// The three-valued answer is the contract: `1` found, `0` exhausted (with
/// `FFC_CHECK_P_NOT_PRIME` OR-ed in), `-1` error. `BN_check_prime`'s own three values are
/// propagated: `r > 0` accepts, `r == 0` continues to the next offset, and `r < 0` ends the
/// search rather than being treated as "composite".
///
/// `buf` is **incremented in place**, low byte first, once per `j` — so the caller's `seed_tmp`
/// comes back advanced by `n + 1` increments, which is the authority's "offset = offset + n + 1
/// is done auto-magically".
///
/// # Safety
///
/// Every pointer must be live; `buf` must be writable and readable for `buf_len` bytes; `q` must
/// be live and non-zero.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn generate_p(
    ctx: *mut BnCtx,
    evpmd: *const EvpMd,
    max_counter: c_int,
    n: c_int,
    buf: *mut u8,
    buf_len: usize,
    q: *const BigNum,
    p: *mut BigNum,
    l: c_int,
    cb: *mut BnGencb,
    counter: *mut c_int,
    res: *mut c_int,
) -> c_int {
    let mut ret: c_int = -1;
    let mut md = [0u8; EVP_MAX_MD_SIZE];
    let w: *mut BigNum;
    let x: *mut BigNum;
    let c: *mut BigNum;
    let test: *mut BigNum;
    let tmp: *mut BigNum;

    // SAFETY: `ctx` is live per this function's `# Safety` section.
    unsafe { BN_CTX_start(ctx) };
    // SAFETY: `ctx` is live; each allocation is a pool slot or NULL.
    unsafe {
        w = BN_CTX_get(ctx);
        x = BN_CTX_get(ctx);
        c = BN_CTX_get(ctx);
        test = BN_CTX_get(ctx);
        tmp = BN_CTX_get(ctx);
    }

    /// `generate_p`'s `err:` epilogue, named rather than repeated because the function has
    /// eight exits and every one must pop the pool `BN_CTX_start` pushed.
    ///
    /// # Safety
    ///
    /// `ctx` must be live and must have been started by the caller.
    fn epilogue(ctx: *mut BnCtx) {
        // SAFETY: `ctx` is live and started per this function's own contract.
        unsafe { BN_CTX_end(ctx) };
    }

    if tmp.is_null() {
        epilogue(ctx);
        return ret;
    }

    // SAFETY: `test` is live and `BN_value_one` is static storage this call only reads.
    if unsafe { BN_lshift(test, BN_value_one(), l - 1) } == 0 {
        epilogue(ctx);
        return ret;
    }

    // SAFETY: `evpmd` is live.
    let mdsize = unsafe { EVP_MD_get_size(evpmd) };
    if mdsize <= 0 {
        epilogue(ctx);
        return ret;
    }

    /* A.1.1.2 Step (10) AND
     * A.1.1.2 Step (12)
     * offset = 1 (this is handled below)
     */
    /*
     * A.1.1.2 Step (11) AND
     * A.1.1.3 Step (13)
     */
    let mut i: c_int = 0;
    while i <= max_counter {
        if i != 0 {
            // SAFETY: `cb` is NULL or live.
            if unsafe { BN_GENCB_call(cb, 0, i) } == 0 {
                epilogue(ctx);
                return ret;
            }
        }

        // SAFETY: `w` is live.
        unsafe { BN_zero_ex(w) };
        /* seed_tmp buffer contains "seed + offset - 1" */
        let mut failed = false;
        let mut j: c_int = 0;
        while j <= n {
            /* obtain "seed + offset + j" by incrementing by 1: */
            // SAFETY: `buf` is writable for `buf_len` bytes.
            unsafe {
                let mut k = buf_len as isize - 1;
                while k >= 0 {
                    let byte = buf.offset(k);
                    let next = (*byte).wrapping_add(1);
                    *byte = next;
                    if next != 0 {
                        break;
                    }
                    k -= 1;
                }
            }
            /*
             * A.1.1.2 Step (11.1) AND
             * A.1.1.3 Step (13.1)
             * tmp = V(j) = Hash((seed + offset + j) % 2^seedlen)
             */
            // SAFETY: `buf` is readable for `buf_len` bytes; `md` is this frame's array and
            // `mdsize <= EVP_MAX_MD_SIZE`; `tmp`, `w` and `evpmd` are live.
            let ok = unsafe {
                EVP_Digest(
                    buf.cast(),
                    buf_len,
                    md.as_mut_ptr(),
                    ptr::null_mut(),
                    evpmd,
                    ptr::null_mut(),
                ) != 0
                    && !BN_bin2bn(md.as_ptr(), mdsize, tmp).is_null()
                    /*
                     * A.1.1.2 Step (11.2)
                     * A.1.1.3 Step (13.2)
                     * W += V(j) * 2^(outlen * j)
                     */
                    && BN_lshift(tmp, tmp, (mdsize << 3) * j) != 0
                    && BN_add(w, w, tmp) != 0
            };
            if !ok {
                failed = true;
                break;
            }
            j += 1;
        }
        if failed {
            epilogue(ctx);
            return ret;
        }

        /*
         * A.1.1.2 Step (11.3) AND
         * A.1.1.3 Step (13.3)
         * X = W + 2^(L-1) where W < 2^(L-1)
         */
        // SAFETY: every `BIGNUM` below is live. `tmp` is reused as the `2q` scratch and then as
        // the `c - 1` scratch, exactly as the authority reuses it.
        let ok = unsafe {
            BN_mask_bits(w, l - 1) != 0
                && !BN_copy(x, w).is_null()
                && BN_add(x, x, test) != 0
                /*
                 * A.1.1.2 Step (11.4) AND
                 * A.1.1.3 Step (13.4)
                 * c = X mod 2q
                 */
                && BN_lshift1(tmp, q) != 0
                && BN_div(ptr::null_mut(), c, x, tmp, ctx) != 0
                /*
                 * A.1.1.2 Step (11.5) AND
                 * A.1.1.3 Step (13.5)
                 * p = X - (c - 1)
                 */
                && BN_sub(tmp, c, BN_value_one()) != 0
                && BN_sub(p, x, tmp) != 0
        };
        if !ok {
            epilogue(ctx);
            return ret;
        }

        /*
         * A.1.1.2 Step (11.6) AND
         * A.1.1.3 Step (13.6)
         * if (p < 2 ^ (L-1)) continue
         * This makes sure the top bit is set.
         */
        // SAFETY: `p` and `test` are live.
        if unsafe { BN_cmp(p, test) } >= 0 {
            /*
             * A.1.1.2 Step (11.7) AND
             * A.1.1.3 Step (13.7)
             * Test if p is prime
             * (This also makes sure the bottom bit is set)
             */
            // SAFETY: `p` is live, `ctx` is live, `cb` is NULL or live.
            let r = unsafe { BN_check_prime(p, ctx, cb) };
            /* A.1.1.2 Step (11.8) : Return if p is prime */
            if r > 0 {
                // SAFETY: `counter` is writable.
                unsafe { *counter = i };
                epilogue(ctx);
                return 1; /* return success */
            }
            if r != 0 {
                epilogue(ctx);
                return ret;
            }
        }
        /* Step (11.9) : offset = offset + n + 1 is done auto-magically */
        i += 1;
    }
    /* No prime P found */
    ret = 0;
    // SAFETY: `res` is writable.
    unsafe { *res |= FFC_CHECK_P_NOT_PRIME };
    epilogue(ctx);
    ret
}

/// `static int generate_q_fips186_4(BN_CTX *ctx, BIGNUM *q, const EVP_MD *evpmd, int qsize,`
/// `unsigned char *seed, size_t seedlen, int generate_seed, int *retm, int *res,`
/// `BN_GENCB *cb)` — `crypto/ffc/ffc_params_generate.c:320-394`.
///
/// FIPS 186-4 A.1.1.2/A.1.1.3 steps (5)–(9): `U = Hash(seed)` and
/// `q = U + 2^(N-1) + (1 - U mod 2)`, which the authority spells as forcing the top bit of the
/// first byte and the bottom bit of the last. The "least significant bits of `md`" reading is the
/// `mdsize > qsize` arm; the `mdsize < qsize` arm zero-fills the tail first so the forced top bit
/// is still the top bit.
///
/// **`generate_seed` is what makes the loop retryable, and what makes it terminate.** With it
/// set, a `q` that is not prime draws a fresh seed and tries again; without it — a caller-supplied
/// seed — the failure is `FFC_CHECK_Q_NOT_PRIME` and the function returns, because retrying a
/// fixed seed would loop forever. `m` (the callback counter) is carried in `*retm` and advanced
/// even by the failing iteration.
///
/// # Safety
///
/// Every pointer must be live; `seed` must be writable for `seedlen` bytes; `ctx` must carry a
/// library context for `RAND_bytes_ex`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn generate_q_fips186_4(
    ctx: *mut BnCtx,
    q: *mut BigNum,
    evpmd: *const EvpMd,
    qsize: c_int,
    seed: *mut u8,
    seedlen: usize,
    generate_seed: c_int,
    retm: *mut c_int,
    res: *mut c_int,
    cb: *mut BnGencb,
) -> c_int {
    let mut ret: c_int = 0;
    let mut md = [0u8; EVP_MAX_MD_SIZE];
    // SAFETY: `retm` is readable per the caller's contract.
    let mut m: c_int = unsafe { *retm };

    // SAFETY: `evpmd` is live.
    let mdsize = unsafe { EVP_MD_get_size(evpmd) };
    if mdsize <= 0 {
        return ret;
    }
    // SAFETY: `ctx` is live.
    let libctx = unsafe { ossl_bn_get_libctx(ctx) };

    /* find q */
    loop {
        /* `BN_GENCB_call(cb, 0, m++)`: the callback sees the *pre*-increment value and `m`
         * advances whether or not the callback accepts, which is what the post-increment
         * inside the argument means. Getting that wrong moves `*retm` by one on the refusal
         * path and nowhere else. */
        let cb_m = m;
        m += 1;
        // SAFETY: `cb` is NULL or live.
        if unsafe { BN_GENCB_call(cb, 0, cb_m) } == 0 {
            break;
        }

        /* A.1.1.2 Step (5) : generate seed with size seed_len */
        if generate_seed != 0 {
            // SAFETY: `seed` is writable for `seedlen` bytes.
            if unsafe { RAND_bytes_ex(libctx, seed, seedlen, 0) } <= 0 {
                break;
            }
        }
        /*
         * A.1.1.2 Step (6) AND
         * A.1.1.3 Step (7)
         * U = Hash(seed) % (2^(N-1))
         */
        // SAFETY: `seed` is readable for `seedlen`; `md` is this frame's array; `evpmd` is live.
        if unsafe {
            EVP_Digest(
                seed.cast(),
                seedlen,
                md.as_mut_ptr(),
                ptr::null_mut(),
                evpmd,
                ptr::null_mut(),
            )
        } == 0
        {
            break;
        }
        /* Take least significant bits of md */
        let pmd_off = if mdsize > qsize {
            (mdsize - qsize) as usize
        } else {
            0
        };
        if mdsize < qsize {
            // SAFETY: `qsize <= 32` and `mdsize >= 0`, so the range is inside the array.
            unsafe {
                ptr::write_bytes(
                    md.as_mut_ptr().add(mdsize as usize),
                    0,
                    (qsize - mdsize) as usize,
                )
            };
        }

        /*
         * A.1.1.2 Step (7) AND
         * A.1.1.3 Step (8)
         * q = U + 2^(N-1) + (1 - U %2) (This sets top and bottom bits)
         */
        // SAFETY: `pmd_off + qsize <= EVP_MAX_MD_SIZE` because `qsize <= 32`.
        unsafe {
            *md.as_mut_ptr().add(pmd_off) |= 0x80;
            *md.as_mut_ptr().add(pmd_off + qsize as usize - 1) |= 0x01;
        }
        // SAFETY: `md` holds `qsize` significant bytes at `pmd_off`; `q` is live.
        if unsafe { BN_bin2bn(md.as_ptr().add(pmd_off), qsize, q) }.is_null() {
            break;
        }

        /*
         * A.1.1.2 Step (8) AND
         * A.1.1.3 Step (9)
         * Test if q is prime
         */
        // SAFETY: `q` is live, `ctx` is live, `cb` is NULL or live.
        let r = unsafe { BN_check_prime(q, ctx, cb) };
        if r > 0 {
            ret = 1;
            break;
        }
        /*
         * A.1.1.3 Step (9) : If the provided seed didn't produce a prime q
         * return an error.
         */
        if generate_seed == 0 {
            // SAFETY: `res` is writable.
            unsafe { *res |= FFC_CHECK_Q_NOT_PRIME };
            break;
        }
        if r != 0 {
            break;
        }
        /* A.1.1.2 Step (9) : if q is not prime, try another q */
    }
    // SAFETY: `retm` is writable.
    unsafe { *retm = m };
    ret
}

/// `static int generate_q_fips186_2(BN_CTX *ctx, BIGNUM *q, const EVP_MD *evpmd,`
/// `unsigned char *buf, unsigned char *seed, size_t qsize, int generate_seed, int *retm,`
/// `int *res, BN_GENCB *cb)` — `crypto/ffc/ffc_params_generate.c:396-454`.
///
/// FIPS 186-2's `q` generator, and its whole difference from the 186-4 one is the message: it
/// hashes `seed` and `seed + 1` separately and **XORs the two digests**, which is what makes the
/// two standards produce different `q` for the same seed — the property
/// `test/ffc_internal_test.c:409-419` relies on.
///
/// It writes into two borrowed buffers: `buf` receives `seed + 1` (so the caller's `buf` comes
/// back advanced) and `buf2` is a stack digest. The digests are `qsize` bytes wide, not the
/// digest's full width, because this arm is the pre-SHA-2 one and `q` is exactly one digest long.
///
/// `res` is written by this function only through its callee's failures — the 186-2 `q` loop has
/// no reason of its own except the retryable `generate_seed` — and the parameter is kept because
/// the caller's `res` must stay the one object both generators write.
///
/// # Safety
///
/// Every pointer must be live; `buf` and `seed` must each be readable and writable for `qsize`
/// bytes; `qsize` must be one of 20, 28 or 32 — the caller checks that before calling.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn generate_q_fips186_2(
    ctx: *mut BnCtx,
    q: *mut BigNum,
    evpmd: *const EvpMd,
    buf: *mut u8,
    seed: *mut u8,
    qsize: usize,
    mut generate_seed: c_int,
    retm: *mut c_int,
    _res: *mut c_int,
    cb: *mut BnGencb,
) -> c_int {
    let mut buf2 = [0u8; SHA256_DIGEST_LENGTH];
    let mut md = [0u8; SHA256_DIGEST_LENGTH];
    let mut ret: c_int = 0;
    // SAFETY: `retm` is readable per the caller's contract.
    let mut m: c_int = unsafe { *retm };
    // SAFETY: `ctx` is live.
    let libctx = unsafe { ossl_bn_get_libctx(ctx) };

    /* find q */
    loop {
        /* step 1: `BN_GENCB_call(cb, 0, m++)` -- the callback sees the pre-increment value and
         * `m` advances either way. */
        let cb_m = m;
        m += 1;
        // SAFETY: `cb` is NULL or live.
        if unsafe { BN_GENCB_call(cb, 0, cb_m) } == 0 {
            break;
        }

        // SAFETY: `seed` is writable for `qsize` bytes; `buf` and `buf2` are this frame's
        // arrays and `qsize <= 32`; `q` and `ctx`/`cb` are live.
        let r = unsafe {
            if generate_seed != 0 && RAND_bytes_ex(libctx, seed, qsize, 0) <= 0 {
                None
            } else {
                ptr::copy_nonoverlapping(seed, buf, qsize);
                ptr::copy_nonoverlapping(seed, buf2.as_mut_ptr(), qsize);

                /* precompute "SEED + 1" for step 7: */
                let mut i = qsize as isize - 1;
                while i >= 0 {
                    let byte = buf.offset(i);
                    let next = (*byte).wrapping_add(1);
                    *byte = next;
                    if next != 0 {
                        break;
                    }
                    i -= 1;
                }

                /* step 2 */
                let digests_ok = EVP_Digest(
                    seed.cast(),
                    qsize,
                    md.as_mut_ptr(),
                    ptr::null_mut(),
                    evpmd,
                    ptr::null_mut(),
                ) != 0
                    && EVP_Digest(
                        buf.cast(),
                        qsize,
                        buf2.as_mut_ptr(),
                        ptr::null_mut(),
                        evpmd,
                        ptr::null_mut(),
                    ) != 0;
                if !digests_ok {
                    None
                } else {
                    let mut i: usize = 0;
                    while i < qsize {
                        md[i] ^= buf2[i];
                        i += 1;
                    }

                    /* step 3 */
                    md[0] |= 0x80;
                    md[qsize - 1] |= 0x01;
                    if BN_bin2bn(md.as_ptr(), qsize as c_int, q).is_null() {
                        None
                    } else {
                        /* step 4 */
                        Some(BN_check_prime(q, ctx, cb))
                    }
                }
            }
        };

        match r {
            /* An error on the way to a `q`, or a callback that refused: `goto err`. */
            None => break,
            Some(r) if r > 0 => {
                /* Found a prime */
                ret = 1;
                break;
            }
            Some(r) if r != 0 => break, /* Exit if error */
            /* "Try another iteration if it wasn't prime - was in old code.." — the authority
             * forces a fresh seed for every subsequent iteration, which is why the loop always
             * terminates rather than drawing the same `q` again. */
            Some(_) => generate_seed = 1,
        }
    }
    // SAFETY: `retm` is writable.
    unsafe { *retm = m };
    ret
}

/// `static const char *default_mdname(size_t N)` — `crypto/ffc/ffc_params_generate.c:456-465`.
///
/// The digest chosen from `N` when the caller names none: `SHA1` for 160 (the *deprecated*
/// spelling with no hyphen, which is what `EVP_MD_fetch` resolves), `SHA-224` for 224 and
/// `SHA-256` for 256. **NULL for anything else**, which the caller turns into
/// `FFC_CHECK_INVALID_Q_VALUE` rather than a guess — so a caller that asks for `N = 384` with no
/// digest gets a refusal, not SHA-384.
fn default_mdname(n: usize) -> *const c_char {
    if n == 160 {
        c"SHA1".as_ptr()
    } else if n == 224 {
        c"SHA-224".as_ptr()
    } else if n == 256 {
        c"SHA-256".as_ptr()
    } else {
        ptr::null()
    }
}

/// The 186-4 verifier's `err:` epilogue, and the 186-2 verifier's is the same minus the two seed
/// buffers. Transcribed as one function so the six release steps cannot diverge between the arms.
///
/// The first line is the interesting one: **`seed` is released only when it is not the caller's**
/// — the pointer comparison is the ownership test, which is why an allocated seed is never
/// installed in `params` before the epilogue runs.
///
/// # Safety
///
/// `seed` must be NULL or a block this crate allocated (never the caller's `params->seed`);
/// `params_seed` must be NULL or the caller's pointer; `seed_tmp` must be NULL or such a block;
/// `ctx`, `mont`, `mctx` and `md` must each be NULL or live.
unsafe fn fips186_4_epilogue(
    ctx: *mut BnCtx,
    mont: *mut MontCtx,
    mctx: *mut EvpMdCtx,
    md: *mut EvpMd,
    seed: *mut u8,
    params_seed: *mut u8,
    seed_tmp: *mut u8,
) {
    // SAFETY: every pointer is NULL or live per this function's `# Safety` section.
    unsafe {
        if seed != params_seed {
            CRYPTO_free(seed.cast(), FILE_FFC_PARAMS_GENERATE, LINE);
        }
        CRYPTO_free(seed_tmp.cast(), FILE_FFC_PARAMS_GENERATE, LINE);
        if !ctx.is_null() {
            BN_CTX_end(ctx);
        }
        BN_CTX_free(ctx);
        BN_MONT_CTX_free(mont);
        EVP_MD_CTX_free(mctx);
        EVP_MD_free(md);
    }
}

/// The 186-2 verifier's `err:` epilogue: no seed buffers, both are stack arrays.
///
/// # Safety
///
/// Each argument must be NULL or live.
unsafe fn fips186_2_epilogue(ctx: *mut BnCtx, mont: *mut MontCtx, md: *mut EvpMd) {
    // SAFETY: each pointer is NULL or live per this function's `# Safety` section.
    unsafe {
        if !ctx.is_null() {
            BN_CTX_end(ctx);
        }
        BN_CTX_free(ctx);
        BN_MONT_CTX_free(mont);
        EVP_MD_free(md);
    }
}

/// The authority's `pass:` label, shared by both verifiers: "Return for the case where g is
/// partially valid".
///
/// The 186-4 verifier guards it with `canonical_g == 0` because there *is* a canonical-`g` arm;
/// the 186-2 verifier has none, so it reduces to the flag test.
fn pass_answer(flags: u32, canonical_g: c_int) -> c_int {
    if (flags & FFC_PARAM_FLAG_VALIDATE_G) != 0 && canonical_g == 0 {
        FFC_PARAM_RET_STATUS_UNVERIFIABLE_G
    } else {
        FFC_PARAM_RET_STATUS_SUCCESS
    }
}

/// `int ossl_ffc_params_FIPS186_4_gen_verify(OSSL_LIB_CTX *libctx, FFC_PARAMS *params,`
/// `int mode, int type, size_t L, size_t N, int *res, BN_GENCB *cb)` —
/// `crypto/ffc/ffc_params_generate.c:523-813`.
///
/// The shared generator/verifier. The comment above the authority's definition is the
/// specification; what belongs at this call site is the list of decisions a reader has to hold:
///
/// * `*res = 0` is the **first** statement, so every refusal below writes a reason into a zeroed
///   word.
/// * `N == 0` is resolved twice: against `L` to choose the *digest*, and then against the
///   digest's own size to choose `qsize`. With `mdname` set the first resolution is skipped, which
///   is why a caller can ask for a 224-bit `q` and a SHA-512 digest.
/// * `L <= N` is checked **separately from** `ffc_validate_LN`, and both answer
///   `FFC_CHECK_BAD_LN_PAIR`.
/// * `flags` is `params->flags` in verify mode and **0** in generate mode — so a generation run
///   cannot accidentally validate, and the `VALIDATE_PQ`/`VALIDATE_G` tests below are
///   verify-only.
/// * The "p and q are passed in" shortcut is `params->p != NULL && (flags & VALIDATE_PQ) == 0`, and
///   it jumps to `g_only` — the same label the `VALIDATE_PQ`-only run falls through to, so the g
///   handling is shared.
/// * `counter` is `4L - 1` for generation and `params->pcounter` for verification, after a
///   `pcounter > 4L - 1` refusal.
/// * In verify mode the two comparisons are `q != params->q`, immediately after the q generator
///   and with its own reason, and `pcounter != counter || p != params->p` after the p generator
///   and without one.
/// * A `p` search that exhausts **with a caller-supplied seed** is `FFC_CHECK_P_NOT_PRIME`; with a
///   generated one it retries the whole loop with a fresh seed.
/// * On success in generate mode the three numbers are `BN_dup`ed into the caller's object unless
///   they are *already* the caller's pointers, and the seed and counter are stored.
///
/// # Safety
///
/// `params` must be a live, writable `FFC_PARAMS` whose `pqg` slots are NULL or live `BIGNUM`s it
/// owns; `res` must be writable; `cb` must be NULL or a live `BN_GENCB`; `libctx` must be NULL or
/// a live library context.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(non_snake_case)] // the authority's name, kept verbatim
pub(crate) unsafe fn ossl_ffc_params_FIPS186_4_gen_verify(
    libctx: *mut c_void,
    params: *mut FfcParams,
    mode: c_int,
    type_: c_int,
    l: usize,
    mut n: usize,
    res: *mut c_int,
    cb: *mut BnGencb,
) -> c_int {
    let mut ok: c_int = FFC_PARAM_RET_STATUS_FAILED;
    let mut seed: *mut u8 = ptr::null_mut();
    let mut seed_tmp: *mut u8 = ptr::null_mut();
    let mut counter: c_int;
    let mut pcounter: c_int = 0;
    let mut seedlen: usize;
    let mut m: c_int = 0;
    let mut canonical_g: c_int = 0;
    let mut hret: c_int = 0;
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut mctx: *mut EvpMdCtx = ptr::null_mut();
    let md: *mut EvpMd;
    let g: *mut BigNum;
    let q: *mut BigNum;
    let p: *mut BigNum;
    let mut mont: *mut MontCtx = ptr::null_mut();
    let pm1: *mut BigNum;
    let e: *mut BigNum;
    let test: *mut BigNum;
    let tmp: *mut BigNum;

    let verify = mode == FFC_PARAM_MODE_VERIFY;
    // SAFETY: `params` is live per this function's `# Safety` section.
    let flags: u32 = unsafe {
        if verify {
            (*params).flags
        } else {
            0
        }
    };

    // SAFETY: `res` is writable.
    unsafe { *res = 0 };
    // The caller's seed pointer is captured once: every later comparison is against this value,
    // which is what makes "the seed was allocated" and "the seed was passed in" one test.
    // SAFETY: `params` is live.
    let params_seed: *mut u8 = unsafe { (*params).seed };

    // SAFETY: `params` is live; `mdname`/`mdprops` are NULL or NUL-terminated and borrowed.
    unsafe {
        md = if !(*params).mdname.is_null() {
            EVP_MD_fetch(libctx, (*params).mdname, (*params).mdprops)
        } else {
            if n == 0 {
                n = if l >= 2048 {
                    SHA256_DIGEST_LENGTH
                } else {
                    SHA_DIGEST_LENGTH
                } * 8;
            }
            let def_name = default_mdname(n);
            if def_name.is_null() {
                *res = FFC_CHECK_INVALID_Q_VALUE;
                return ok;
            }
            EVP_MD_fetch(libctx, def_name, (*params).mdprops)
        };
    }
    if md.is_null() {
        /* The authority's `goto err`, whose six releases are all no-ops here. */
        // SAFETY: every handle is NULL at this point.
        unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
        return ok;
    }
    // SAFETY: `md` is live.
    let mdsize = unsafe { EVP_MD_get_size(md) };
    if mdsize <= 0 {
        // SAFETY: `md` is live; the rest are NULL here.
        unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
        return ok;
    }

    if n == 0 {
        n = (mdsize as usize) * 8;
    }
    let qsize = (n >> 3) as c_int;

    /*
     * A.1.1.2 Step (1) AND
     * A.1.1.3 Step (3)
     * Check that the L,N pair is an acceptable pair.
     */
    if l <= n || ffc_validate_LN(l, n, type_, c_int::from(verify)) == 0 {
        // SAFETY: `res` is writable and every handle is NULL or live.
        unsafe {
            *res = FFC_CHECK_BAD_LN_PAIR;
            fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
        }
        return ok;
    }

    // SAFETY: `EVP_MD_CTX_new` answers NULL or a fresh context. It is a safe `extern "C"`
    // function in this crate, so no `unsafe` block is needed and none is written.
    mctx = EVP_MD_CTX_new();
    if mctx.is_null() {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
        return ok;
    }

    // SAFETY: `BN_CTX_new_ex` answers NULL or a fresh context.
    ctx = unsafe { BN_CTX_new_ex(libctx) };
    if ctx.is_null() {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
        return ok;
    }

    // SAFETY: `ctx` is live; each allocation is a pool slot or NULL.
    unsafe {
        BN_CTX_start(ctx);
        g = BN_CTX_get(ctx);
        pm1 = BN_CTX_get(ctx);
        e = BN_CTX_get(ctx);
        test = BN_CTX_get(ctx);
        tmp = BN_CTX_get(ctx);
    }
    if tmp.is_null() {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
        return ok;
    }

    // SAFETY: `params` is live.
    unsafe {
        seedlen = (*params).seedlen;
    }
    if seedlen == 0 {
        seedlen = mdsize as usize;
    }
    /* If the seed was passed in - use this value as the seed */
    if !params_seed.is_null() {
        seed = params_seed;
    }

    // SAFETY: `params` is live and `res` is writable.
    unsafe {
        if !verify {
            /* For generation: p & q must both be NULL or NON-NULL */
            if ((*params).p.is_null()) != ((*params).q.is_null()) {
                *res = FFC_CHECK_INVALID_PQ;
                fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
                return ok;
            }
        } else {
            /* Validation of p,q requires seed and counter to be valid */
            if (flags & FFC_PARAM_FLAG_VALIDATE_PQ) != 0
                && (seed.is_null() || (*params).pcounter < 0)
            {
                *res = FFC_CHECK_MISSING_SEED_OR_COUNTER;
                fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
                return ok;
            }
            /* Validation of g also requires g to be set */
            if (flags & FFC_PARAM_FLAG_VALIDATE_G) != 0 && (*params).g.is_null() {
                *res = FFC_CHECK_INVALID_G;
                fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
                return ok;
            }
        }
    }

    /*
     * If p & q are passed in and
     *   validate_flags = 0 then skip the generation of PQ.
     *   validate_flags = VALIDATE_G then also skip the validation of PQ.
     */
    // SAFETY: `params` is live.
    let g_only = unsafe { !(*params).p.is_null() && (flags & FFC_PARAM_FLAG_VALIDATE_PQ) == 0 };

    if g_only {
        /* p and q already exist, so only g is generated or validated. */
        // SAFETY: `params` is live and the two slots are live on this arm.
        unsafe {
            p = (*params).p;
            q = (*params).q;
        }
    } else {
        /* p & q will be used for generation and validation */
        // SAFETY: `ctx` is live.
        unsafe {
            p = BN_CTX_get(ctx);
            q = BN_CTX_get(ctx);
        }
        if q.is_null() {
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
            return ok;
        }

        /*
         * A.1.1.2 Step (2) AND
         * A.1.1.3 Step (6)
         * Return invalid if seedlen  < N
         */
        if (seedlen * 8) < n {
            // SAFETY: `res` is writable and every handle is NULL or live.
            unsafe {
                *res = FFC_CHECK_INVALID_SEED_SIZE;
                fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
            }
            return ok;
        }

        // SAFETY: `CRYPTO_malloc` is a safe `extern "C"` function here and answers NULL or
        // `seedlen` bytes.
        seed_tmp = CRYPTO_malloc(seedlen, FILE_FFC_PARAMS_GENERATE, LINE).cast();
        if seed_tmp.is_null() {
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
            return ok;
        }

        if seed.is_null() {
            /* Validation requires the seed to be supplied */
            if verify {
                // SAFETY: `res` is writable and every handle is NULL or live.
                unsafe {
                    *res = FFC_CHECK_MISSING_SEED_OR_COUNTER;
                    fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
                }
                return ok;
            }
            /* if the seed is not supplied then alloc a seed buffer */
            // SAFETY: as above; `CRYPTO_malloc` answers NULL or `seedlen` bytes.
            seed = CRYPTO_malloc(seedlen, FILE_FFC_PARAMS_GENERATE, LINE).cast();
            if seed.is_null() {
                // SAFETY: every handle is NULL or live.
                unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
                return ok;
            }
        }

        /* A.1.1.2 Step (11): max loop count = 4L - 1 */
        counter = (4 * l) as c_int - 1;
        /* Validation requires the counter to be supplied */
        if verify {
            /* A.1.1.3 Step (4) : if (counter > (4L -1)) return INVALID */
            // SAFETY: `params` is live and `res` is writable.
            if unsafe { (*params).pcounter } > counter {
                // SAFETY: `res` is writable and every handle is NULL or live.
                unsafe {
                    *res = FFC_CHECK_INVALID_COUNTER;
                    fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
                }
                return ok;
            }
            // SAFETY: `params` is live.
            counter = unsafe { (*params).pcounter };
        }

        /*
         * A.1.1.2 Step (3) AND
         * A.1.1.3 Step (10)
         * n = floor(L / hash_outlen) - 1
         */
        let n_inner = ((l - 1) / ((mdsize as usize) << 3)) as c_int;

        /* Calculate 2^(L-1): Used in step A.1.1.2 Step (11.3) */
        // SAFETY: `test` is live and `BN_value_one` is static storage this call only reads.
        if unsafe { BN_lshift(test, BN_value_one(), (l - 1) as c_int) } == 0 {
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
            return ok;
        }

        loop {
            // SAFETY: `ctx`, `q`, `md`, `seed` and `res` are live; `cb` is NULL or live.
            let qok = unsafe {
                generate_q_fips186_4(
                    ctx,
                    q,
                    md,
                    qsize,
                    seed,
                    seedlen,
                    c_int::from(seed != params_seed),
                    &raw mut m,
                    res,
                    cb,
                )
            };
            if qok == 0 {
                // SAFETY: every handle is NULL or live.
                unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
                return ok;
            }
            /* A.1.1.3 Step (9): Verify that q matches the expected value */
            // SAFETY: `params` and `q` are live.
            if verify && unsafe { BN_cmp(q, (*params).q) } != 0 {
                // SAFETY: `res` is writable and every handle is NULL or live.
                unsafe {
                    *res = FFC_CHECK_Q_MISMATCH;
                    fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
                }
                return ok;
            }
            // SAFETY: `cb` is NULL or live.
            if unsafe { BN_GENCB_call(cb, 2, 0) } == 0 || unsafe { BN_GENCB_call(cb, 3, 0) } == 0 {
                // SAFETY: every handle is NULL or live.
                unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
                return ok;
            }

            // SAFETY: `seed_tmp` is writable for `seedlen` bytes and `seed` is readable for it.
            unsafe { ptr::copy_nonoverlapping(seed, seed_tmp, seedlen) };
            // SAFETY: every pointer is live.
            let r = unsafe {
                generate_p(
                    ctx,
                    md,
                    counter,
                    n_inner,
                    seed_tmp,
                    seedlen,
                    q,
                    p,
                    l as c_int,
                    cb,
                    &raw mut pcounter,
                    res,
                )
            };
            if r > 0 {
                break; /* found p */
            }
            if r < 0 {
                // SAFETY: every handle is NULL or live.
                unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
                return ok;
            }
            /*
             * A.1.1.3 Step (14):
             * If we get here we failed to get a p for the given seed. If the
             * seed is not random then it needs to fail (as it will always fail).
             */
            if seed == params_seed {
                // SAFETY: `res` is writable and every handle is NULL or live.
                unsafe {
                    *res = FFC_CHECK_P_NOT_PRIME;
                    fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
                }
                return ok;
            }
        }
        // SAFETY: `cb` is NULL or live.
        if unsafe { BN_GENCB_call(cb, 2, 1) } == 0 {
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
            return ok;
        }
        /*
         * Gets here if we found p.
         * A.1.1.3 Step (14): return error if i != counter OR computed_p != known_p.
         */
        // SAFETY: `params` and `p` are live.
        if verify && (pcounter != counter || unsafe { BN_cmp(p, (*params).p) } != 0) {
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
            return ok;
        }

        /* If validating p & q only then skip the g validation test */
        if (flags & FFC_PARAM_FLAG_VALIDATE_PQG) == FFC_PARAM_FLAG_VALIDATE_PQ {
            let answer = pass_answer(flags, canonical_g);
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
            return answer;
        }
    }

    /* The authority's `g_only:` label. */
    // SAFETY: `BN_MONT_CTX_new` answers NULL or a fresh context.
    mont = unsafe { BN_MONT_CTX_new() };
    if mont.is_null() {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
        return ok;
    }
    // SAFETY: `mont` and `p` are live and `ctx` is live.
    if unsafe { BN_MONT_CTX_set(mont, p, ctx) } == 0 {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
        return ok;
    }

    if (flags & FFC_PARAM_FLAG_VALIDATE_G) != 0 {
        // SAFETY: `ctx`, `mont`, `p`, `q` and `tmp` are live; `params->g` is NULL or live; `res`
        // is writable.
        let vok = unsafe {
            ossl_ffc_params_validate_unverifiable_g(ctx, mont, p, q, (*params).g, tmp, res)
        };
        if vok == 0 {
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
            return ok;
        }
    }

    /*
     * A.2.1 Step (1) AND
     * A.2.3 Step (3) AND
     * A.2.4 Step (5)
     * e = (p - 1) / q (i.e- Cofactor 'e' is given by p = q * e + 1)
     */
    // SAFETY: `pm1`, `p`, `e`, `q` and `ctx` are live.
    if unsafe {
        BN_sub(pm1, p, BN_value_one()) == 0 || BN_div(e, ptr::null_mut(), pm1, q, ctx) == 0
    } {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
        return ok;
    }

    /* Canonical g requires a seed and index to be set */
    // SAFETY: `params` is live.
    let gindex = unsafe { (*params).gindex };
    if !seed.is_null() && gindex != FFC_UNVERIFIABLE_GINDEX {
        canonical_g = 1;
        // SAFETY: `ctx`, `mont`, `md`, `g`, `tmp`, `p`, `e`, `seed` are live.
        let cok =
            unsafe { generate_canonical_g(ctx, mont, md, g, tmp, p, e, gindex, seed, seedlen) };
        if cok == 0 {
            // SAFETY: `res` is writable and every handle is NULL or live.
            unsafe {
                *res = FFC_CHECK_INVALID_G;
                fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
            }
            return ok;
        }
        /* A.2.4 Step (13): Return valid if computed_g == g */
        // SAFETY: `params` and `g` are live.
        if verify && unsafe { BN_cmp(g, (*params).g) } != 0 {
            // SAFETY: `res` is writable and every handle is NULL or live.
            unsafe {
                *res = FFC_CHECK_G_MISMATCH;
                fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
            }
            return ok;
        }
    } else if !verify {
        // SAFETY: `ctx`, `mont`, `g`, `tmp`, `p`, `e`, `pm1` are live.
        if unsafe { generate_unverifiable_g(ctx, mont, g, tmp, p, e, pm1, &raw mut hret) } == 0 {
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
            return ok;
        }
    }

    // SAFETY: `cb` is NULL or live.
    if unsafe { BN_GENCB_call(cb, 3, 1) } == 0 {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
        return ok;
    }

    if !verify {
        // SAFETY: `params` is live, `seed` is readable for `seedlen` bytes, and every `BIGNUM`
        // below is live.
        unsafe {
            if p != (*params).p {
                BN_free((*params).p);
                (*params).p = BN_dup(p);
            }
            if q != (*params).q {
                BN_free((*params).q);
                (*params).q = BN_dup(q);
            }
            if g != (*params).g {
                BN_free((*params).g);
                (*params).g = BN_dup(g);
            }
            if (*params).p.is_null() || (*params).q.is_null() || (*params).g.is_null() {
                fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
                return ok;
            }
            if ossl_ffc_params_set_validate_params(params, seed, seedlen, pcounter) == 0 {
                fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp);
                return ok;
            }
            (*params).h = hret;
        }
    }

    /* `pass:` — falls straight into the `err:` epilogue. */
    ok = pass_answer(flags, canonical_g);
    // SAFETY: every handle is NULL or live.
    unsafe { fips186_4_epilogue(ctx, mont, mctx, md, seed, params_seed, seed_tmp) };
    ok
}

/// `int ossl_ffc_params_FIPS186_4_generate(OSSL_LIB_CTX *libctx, FFC_PARAMS *params,`
/// `int type, size_t L, size_t N, int *res, BN_GENCB *cb)` —
/// `crypto/ffc/ffc_params_generate.c:1050-1057`.
///
/// One line: the shared entry point with `FFC_PARAM_MODE_GENERATE`.
///
/// # Safety
///
/// As [`ossl_ffc_params_FIPS186_4_gen_verify`].
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(non_snake_case)] // the authority's name, kept verbatim
pub(crate) unsafe fn ossl_ffc_params_FIPS186_4_generate(
    libctx: *mut c_void,
    params: *mut FfcParams,
    type_: c_int,
    l: usize,
    n: usize,
    res: *mut c_int,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        ossl_ffc_params_FIPS186_4_gen_verify(
            libctx,
            params,
            FFC_PARAM_MODE_GENERATE,
            type_,
            l,
            n,
            res,
            cb,
        )
    }
}

/// `int ossl_ffc_params_FIPS186_2_gen_verify(OSSL_LIB_CTX *libctx, FFC_PARAMS *params,`
/// `int mode, int type, size_t L, size_t N, int *res, BN_GENCB *cb)` —
/// `crypto/ffc/ffc_params_generate.c:816-1048`.
///
/// "Note this function is only used for verification in fips mode" — and on this profile it is
/// reached from `ossl_ffc_params_FIPS186_2_generate` and from the `VALIDATE_LEGACY` arm of
/// `ossl_ffc_params_simple_validate`.
///
/// What differs from the 186-4 twin, and each is a real difference rather than a spelling:
///
/// * **There is no canonical `g`.** 186-2 has no `ggen` chain, so this verifier always uses the
///   `h`-search and `pass` answers `UNVERIFIABLE_G` whenever `VALIDATE_G` is set — where the
///   186-4 twin requires `canonical_g == 0`, which there is a live possibility of being false.
/// * **Its refusals carry different reasons**: `FFC_CHECK_COUNTER_MISMATCH` and
///   `FFC_CHECK_P_MISMATCH` where the 186-4 twin has a bare failure, and `L < 512` is
///   `FFC_CHECK_BAD_LN_PAIR` before `qsize` is looked at.
/// * `qsize` must be exactly 20, 28 or 32 — the digest lengths, not a range — and `L` is rounded
///   **up** to a multiple of 64 (`L = (L + 63) / 64 * 64`) before anything else.
/// * The seed is a stack array, copied from the caller's and **truncated to `qsize`** when it is
///   longer, with `FFC_CHECK_INVALID_SEED_SIZE` when it is shorter.
/// * `n` is `(L - 1) / 160` — the SHA-1 digest length, hard-coded.
/// * `hret` starts at **-1** here and 0 in the 186-4 twin, and `params->h` receives it either
///   way — so a group that generated no `g` carries `h == -1` rather than `h == 0`.
///
/// # Safety
///
/// As [`ossl_ffc_params_FIPS186_4_gen_verify`].
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(non_snake_case)] // the authority's name, kept verbatim
pub(crate) unsafe fn ossl_ffc_params_FIPS186_2_gen_verify(
    libctx: *mut c_void,
    params: *mut FfcParams,
    mode: c_int,
    _type_: c_int,
    mut l: usize,
    mut n: usize,
    res: *mut c_int,
    cb: *mut BnGencb,
) -> c_int {
    let mut ok: c_int = FFC_PARAM_RET_STATUS_FAILED;
    let mut seed = [0u8; SHA256_DIGEST_LENGTH];
    let mut buf = [0u8; SHA256_DIGEST_LENGTH];
    let mut counter: c_int;
    let mut pcounter: c_int = 0;
    let mut m: c_int = 0;
    let md: *mut EvpMd;
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut mont: *mut MontCtx = ptr::null_mut();
    let r0: *mut BigNum;
    let test: *mut BigNum;
    let tmp: *mut BigNum;
    let g: *mut BigNum;
    let mut q: *mut BigNum;
    let mut p: *mut BigNum;
    let mut hret: c_int = -1;

    let verify = mode == FFC_PARAM_MODE_VERIFY;
    // SAFETY: `params` is live per this function's `# Safety` section.
    let flags: u32 = unsafe {
        if verify {
            (*params).flags
        } else {
            0
        }
    };
    // SAFETY: `params` is live.
    let seed_in = unsafe { (*params).seed };
    // SAFETY: `params` is live.
    let mut seed_len = unsafe { (*params).seedlen };

    // SAFETY: `res` is writable.
    unsafe { *res = 0 };

    // SAFETY: `params` is live.
    unsafe {
        md = if !(*params).mdname.is_null() {
            EVP_MD_fetch(libctx, (*params).mdname, (*params).mdprops)
        } else {
            if n == 0 {
                n = if l >= 2048 {
                    SHA256_DIGEST_LENGTH
                } else {
                    SHA_DIGEST_LENGTH
                } * 8;
            }
            let def_name = default_mdname(n);
            if def_name.is_null() {
                *res = FFC_CHECK_INVALID_Q_VALUE;
                return ok;
            }
            EVP_MD_fetch(libctx, def_name, (*params).mdprops)
        };
    }
    if md.is_null() {
        /* The authority's `goto err`, whose four releases are all no-ops here. */
        // SAFETY: every handle is NULL at this point.
        unsafe { fips186_2_epilogue(ctx, mont, md) };
        return ok;
    }
    // SAFETY: `md` is live.
    let md_size = unsafe { EVP_MD_get_size(md) };
    if md_size <= 0 {
        // SAFETY: `md` is live; the other two handles are NULL here.
        unsafe { fips186_2_epilogue(ctx, mont, md) };
        return ok;
    }
    if n == 0 {
        n = (md_size as usize) * 8;
    }
    let qsize = n >> 3;

    /*
     * The original spec allowed L = 512 + 64*j (j = 0.. 8)
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
     * says that 512 can be used for legacy verification.
     */
    if l < 512 {
        // SAFETY: `res` is writable; the two handles are NULL here.
        unsafe {
            *res = FFC_CHECK_BAD_LN_PAIR;
            fips186_2_epilogue(ctx, mont, md);
        }
        return ok;
    }
    if qsize != SHA_DIGEST_LENGTH && qsize != SHA224_DIGEST_LENGTH && qsize != SHA256_DIGEST_LENGTH
    {
        /* invalid q size */
        // SAFETY: `res` is writable.
        unsafe {
            *res = FFC_CHECK_INVALID_Q_VALUE;
            fips186_2_epilogue(ctx, mont, md);
        }
        return ok;
    }

    l = l.div_ceil(64) * 64;

    if !seed_in.is_null() {
        if seed_len < qsize {
            // SAFETY: `res` is writable.
            unsafe {
                *res = FFC_CHECK_INVALID_SEED_SIZE;
                fips186_2_epilogue(ctx, mont, md);
            }
            return ok;
        }
        /* Only consume as much seed as is expected. */
        if seed_len > qsize {
            seed_len = qsize;
        }
        // SAFETY: `seed_in` is readable for `seed_len` bytes and `seed` is this frame's array.
        unsafe { ptr::copy_nonoverlapping(seed_in, seed.as_mut_ptr(), seed_len) };
    }

    // SAFETY: `BN_CTX_new_ex` answers NULL or a fresh context.
    ctx = unsafe { BN_CTX_new_ex(libctx) };
    if ctx.is_null() {
        // SAFETY: `md` is live.
        unsafe { fips186_2_epilogue(ctx, mont, md) };
        return ok;
    }

    // SAFETY: `ctx` is live; each allocation is a pool slot or NULL.
    unsafe {
        BN_CTX_start(ctx);
        r0 = BN_CTX_get(ctx);
        g = BN_CTX_get(ctx);
        q = BN_CTX_get(ctx);
        p = BN_CTX_get(ctx);
        tmp = BN_CTX_get(ctx);
        test = BN_CTX_get(ctx);
    }
    if test.is_null() {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_2_epilogue(ctx, mont, md) };
        return ok;
    }

    // SAFETY: `test` is live and `BN_value_one` is static storage this call only reads.
    if unsafe { BN_lshift(test, BN_value_one(), (l - 1) as c_int) } == 0 {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_2_epilogue(ctx, mont, md) };
        return ok;
    }

    // SAFETY: `params` is live and `res` is writable.
    unsafe {
        if !verify {
            /* For generation: p & q must both be NULL or NON-NULL */
            if ((*params).p.is_null()) != ((*params).q.is_null()) {
                *res = FFC_CHECK_INVALID_PQ;
                fips186_2_epilogue(ctx, mont, md);
                return ok;
            }
        } else {
            if (flags & FFC_PARAM_FLAG_VALIDATE_PQ) != 0
                && (seed_in.is_null() || (*params).pcounter < 0)
            {
                *res = FFC_CHECK_MISSING_SEED_OR_COUNTER;
                fips186_2_epilogue(ctx, mont, md);
                return ok;
            }
            if (flags & FFC_PARAM_FLAG_VALIDATE_G) != 0 && (*params).g.is_null() {
                *res = FFC_CHECK_INVALID_G;
                fips186_2_epilogue(ctx, mont, md);
                return ok;
            }
        }
    }

    // SAFETY: `params` is live.
    let g_only = unsafe { !(*params).p.is_null() && (flags & FFC_PARAM_FLAG_VALIDATE_PQ) == 0 };

    if g_only {
        // SAFETY: `params` is live and the two slots are live on this arm.
        unsafe {
            p = (*params).p;
            q = (*params).q;
        }
    } else {
        let mut use_random_seed = c_int::from(seed_in.is_null());
        loop {
            // SAFETY: `ctx`, `q`, `md`, `buf` and `seed` are live; `res` is writable.
            let qok = unsafe {
                generate_q_fips186_2(
                    ctx,
                    q,
                    md,
                    buf.as_mut_ptr(),
                    seed.as_mut_ptr(),
                    qsize,
                    use_random_seed,
                    &raw mut m,
                    res,
                    cb,
                )
            };
            if qok == 0 {
                // SAFETY: every handle is NULL or live.
                unsafe { fips186_2_epilogue(ctx, mont, md) };
                return ok;
            }

            // SAFETY: `cb` is NULL or live.
            if unsafe { BN_GENCB_call(cb, 2, 0) } == 0 || unsafe { BN_GENCB_call(cb, 3, 0) } == 0 {
                // SAFETY: every handle is NULL or live.
                unsafe { fips186_2_epilogue(ctx, mont, md) };
                return ok;
            }

            /* step 6 */
            let n_inner = ((l - 1) / FIPS186_2_N_DIVISOR) as c_int;
            counter = (4 * l) as c_int - 1; /* Was 4096 */
            /* Validation requires the counter to be supplied */
            if verify {
                // SAFETY: `params` is live and `res` is writable.
                if unsafe { (*params).pcounter } > counter {
                    // SAFETY: `res` is writable and every handle is NULL or live.
                    unsafe {
                        *res = FFC_CHECK_INVALID_COUNTER;
                        fips186_2_epilogue(ctx, mont, md);
                    }
                    return ok;
                }
                // SAFETY: `params` is live.
                counter = unsafe { (*params).pcounter };
            }

            // SAFETY: every pointer is live.
            let rv = unsafe {
                generate_p(
                    ctx,
                    md,
                    counter,
                    n_inner,
                    buf.as_mut_ptr(),
                    qsize,
                    q,
                    p,
                    l as c_int,
                    cb,
                    &raw mut pcounter,
                    res,
                )
            };
            if rv > 0 {
                break; /* found it */
            }
            if rv == -1 {
                // SAFETY: every handle is NULL or live.
                unsafe { fips186_2_epilogue(ctx, mont, md) };
                return ok;
            }
            /* This is what the old code did - probably not a good idea! */
            use_random_seed = 1;
        }

        // SAFETY: `cb` is NULL or live.
        if unsafe { BN_GENCB_call(cb, 2, 1) } == 0 {
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_2_epilogue(ctx, mont, md) };
            return ok;
        }

        if verify {
            // SAFETY: `res` is writable; `p` and `params` are live.
            unsafe {
                if pcounter != counter {
                    *res = FFC_CHECK_COUNTER_MISMATCH;
                    fips186_2_epilogue(ctx, mont, md);
                    return ok;
                }
                if BN_cmp(p, (*params).p) != 0 {
                    *res = FFC_CHECK_P_MISMATCH;
                    fips186_2_epilogue(ctx, mont, md);
                    return ok;
                }
            }
        }
        /* If validating p & q only then skip the g validation test */
        if (flags & FFC_PARAM_FLAG_VALIDATE_PQG) == FFC_PARAM_FLAG_VALIDATE_PQ {
            let answer = if (flags & FFC_PARAM_FLAG_VALIDATE_G) != 0 {
                FFC_PARAM_RET_STATUS_UNVERIFIABLE_G
            } else {
                FFC_PARAM_RET_STATUS_SUCCESS
            };
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_2_epilogue(ctx, mont, md) };
            return answer;
        }
    }

    /* The authority's `g_only:` label. */
    // SAFETY: `BN_MONT_CTX_new` answers NULL or a fresh context.
    mont = unsafe { BN_MONT_CTX_new() };
    if mont.is_null() {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_2_epilogue(ctx, mont, md) };
        return ok;
    }
    // SAFETY: `mont`, `p` and `ctx` are live.
    if unsafe { BN_MONT_CTX_set(mont, p, ctx) } == 0 {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_2_epilogue(ctx, mont, md) };
        return ok;
    }

    if !verify {
        /* We now need to generate g */
        /* set test = p - 1 */
        // SAFETY: every `BIGNUM` below is live and `ctx` is live.
        let gen_ok = unsafe {
            BN_sub(test, p, BN_value_one()) != 0
                /* Set r0 = (p - 1) / q */
                && BN_div(r0, ptr::null_mut(), test, q, ctx) != 0
                && generate_unverifiable_g(ctx, mont, g, tmp, p, r0, test, &raw mut hret) != 0
        };
        if !gen_ok {
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_2_epilogue(ctx, mont, md) };
            return ok;
        }
    } else if (flags & FFC_PARAM_FLAG_VALIDATE_G) != 0 {
        // SAFETY: `ctx`, `mont`, `p`, `q` and `tmp` are live; `params->g` is NULL or live; `res`
        // is writable.
        let vok = unsafe {
            ossl_ffc_params_validate_unverifiable_g(ctx, mont, p, q, (*params).g, tmp, res)
        };
        if vok == 0 {
            // SAFETY: every handle is NULL or live.
            unsafe { fips186_2_epilogue(ctx, mont, md) };
            return ok;
        }
    }

    // SAFETY: `cb` is NULL or live.
    if unsafe { BN_GENCB_call(cb, 3, 1) } == 0 {
        // SAFETY: every handle is NULL or live.
        unsafe { fips186_2_epilogue(ctx, mont, md) };
        return ok;
    }

    if !verify {
        // SAFETY: `params` is live, `seed` is readable for `qsize` bytes and every `BIGNUM`
        // below is live.
        unsafe {
            if p != (*params).p {
                BN_free((*params).p);
                (*params).p = BN_dup(p);
            }
            if q != (*params).q {
                BN_free((*params).q);
                (*params).q = BN_dup(q);
            }
            if g != (*params).g {
                BN_free((*params).g);
                (*params).g = BN_dup(g);
            }
            if (*params).p.is_null() || (*params).q.is_null() || (*params).g.is_null() {
                fips186_2_epilogue(ctx, mont, md);
                return ok;
            }
            if ossl_ffc_params_set_validate_params(params, seed.as_ptr(), qsize, pcounter) == 0 {
                fips186_2_epilogue(ctx, mont, md);
                return ok;
            }
            (*params).h = hret;
        }
    }

    /* `pass:` — the 186-2 verifier has no canonical g, so `VALIDATE_G` here always means
     * "partially valid". */
    ok = if (flags & FFC_PARAM_FLAG_VALIDATE_G) != 0 {
        FFC_PARAM_RET_STATUS_UNVERIFIABLE_G
    } else {
        FFC_PARAM_RET_STATUS_SUCCESS
    };
    // SAFETY: every handle is NULL or live.
    unsafe { fips186_2_epilogue(ctx, mont, md) };
    ok
}

/// `int ossl_ffc_params_FIPS186_2_generate(OSSL_LIB_CTX *libctx, FFC_PARAMS *params,`
/// `int type, size_t L, size_t N, int *res, BN_GENCB *cb)` —
/// `crypto/ffc/ffc_params_generate.c:1060-1071`.
///
/// "This should no longer be used in FIPS mode." The wrapper is two lines and one difference from
/// the 186-4 twin: **on success it sets `FFC_PARAM_FLAG_VALIDATE_LEGACY` on the caller's object**,
/// which is how a group generated the 186-2 way is later validated the 186-2 way by
/// `ossl_ffc_params_full_validate`'s seed arm.
///
/// # Safety
///
/// As [`ossl_ffc_params_FIPS186_2_gen_verify`].
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(non_snake_case)] // the authority's name, kept verbatim
pub(crate) unsafe fn ossl_ffc_params_FIPS186_2_generate(
    libctx: *mut c_void,
    params: *mut FfcParams,
    type_: c_int,
    l: usize,
    n: usize,
    res: *mut c_int,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        if ossl_ffc_params_FIPS186_2_gen_verify(
            libctx,
            params,
            FFC_PARAM_MODE_GENERATE,
            type_,
            l,
            n,
            res,
            cb,
        ) == 0
        {
            return 0;
        }
        ossl_ffc_params_enable_flags(params, FFC_PARAM_FLAG_VALIDATE_LEGACY, 1);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bn::bignum::{BN_is_odd, BN_is_one, BN_is_zero, BN_new, BN_num_bits, BN_set_word};
    use crate::bn::ctx::BN_CTX_get;
    use crate::ffc::params::{
        ossl_ffc_params_cleanup, ossl_ffc_params_init, ossl_ffc_params_set0_pqg,
        ossl_ffc_params_set_gindex, ossl_ffc_set_digest,
    };
    use crate::ffc::params_validate::{
        ossl_ffc_params_FIPS186_2_validate, ossl_ffc_params_FIPS186_4_validate,
    };

    /// A fresh params object, released on drop. This unit's tests need one of their own because
    /// none of the others is reachable from here.
    struct Params(FfcParams);

    impl Params {
        fn new() -> Self {
            let mut p = core::mem::MaybeUninit::<FfcParams>::uninit();
            // SAFETY: `p` is live and writable; `ossl_ffc_params_init` writes every byte.
            let inner = unsafe {
                ossl_ffc_params_init(p.as_mut_ptr());
                p.assume_init()
            };
            Params(inner)
        }

        fn as_mut(&mut self) -> *mut FfcParams {
            &raw mut self.0
        }

        fn as_ref(&self) -> *const FfcParams {
            &raw const self.0
        }
    }

    impl Drop for Params {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live object this test owns.
            unsafe { ossl_ffc_params_cleanup(&raw mut self.0) };
        }
    }

    /// **The congruences a FIPS 186-4 generation must install, asserted on the object it
    /// returns.** Nothing here is a generated *value*: the assertions are the bit widths the
    /// caller asked for, the two arithmetic relations that make the pair a group
    /// (`q | p - 1` and `p ≡ 1 mod 2q`), the primality of both, the order of the generator, and
    /// the four scalars the install path writes.
    ///
    /// `p ≡ 1 mod 2q` is the *construction's* invariant — `generate_p` emits
    /// `p = X - (c - 1)` with `c = X mod 2q` — and it is what makes the group's order `q * e`
    /// rather than something the `g` search has to discover.
    #[test]
    fn a_fips186_4_generation_installs_a_well_formed_group() {
        let mut p = Params::new();
        let mut res: c_int = -1;
        // SAFETY: the object is live and owned by this test.
        unsafe {
            assert_eq!(
                ossl_ffc_params_FIPS186_4_generate(
                    ptr::null_mut(),
                    p.as_mut(),
                    FFC_PARAM_TYPE_DH,
                    2048,
                    256,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_SUCCESS
            );
            assert_eq!(res, 0, "a successful generation names no reason");

            let (bp, bq, bg) = ((*p.as_ref()).p, (*p.as_ref()).q, (*p.as_ref()).g);
            assert!(!bp.is_null() && !bq.is_null() && !bg.is_null());

            /* The widths are the caller's L and N. */
            assert_eq!(BN_num_bits(bp), 2048);
            assert_eq!(BN_num_bits(bq), 256);

            /* `p` is odd — the search refuses a `p` below `2^(L-1)`, which is what forces the
             * bottom bit along with the top. */
            assert_eq!(
                BN_is_odd(bp),
                1,
                "the top-bit test is also the bottom-bit test"
            );

            /* Both are prime, and `q | p - 1` — the latter checked by division rather than by
             * a prime test, because the `g` search's `e = (p-1)/q` needs it to be exact. */
            let ctx = BN_CTX_new_ex(ptr::null_mut());
            assert!(!ctx.is_null());
            assert_eq!(BN_check_prime(bp, ctx, ptr::null_mut()), 1);
            assert_eq!(BN_check_prime(bq, ctx, ptr::null_mut()), 1);

            /* `p ≡ 1 mod 2q`, which is `(p - 1) mod 2q == 0`. */
            BN_CTX_start(ctx);
            let two_q = BN_CTX_get(ctx);
            assert!(!two_q.is_null());
            assert!(BN_lshift1(two_q, bq) != 0);
            let pm1 = BN_CTX_get(ctx);
            assert!(!pm1.is_null());
            assert!(BN_sub(pm1, bp, BN_value_one()) != 0);
            let rem = BN_CTX_get(ctx);
            assert!(!rem.is_null());
            assert!(BN_div(ptr::null_mut(), rem, pm1, two_q, ctx) != 0);
            assert_eq!(
                BN_is_zero(rem),
                1,
                "the construction gives p = X - (X mod 2q) + 1"
            );

            /* `g` has order `q`: `g^q mod p == 1` and `g > 1`. */
            let one = BN_CTX_get(ctx);
            assert!(!one.is_null());
            assert!(BN_set_word(one, 1) != 0);
            assert!(BN_cmp(bg, one) > 0);
            let gq = BN_CTX_get(ctx);
            assert!(!gq.is_null());
            assert!(BN_mod_exp_mont(gq, bg, bq, bp, ctx, ptr::null_mut()) != 0);
            assert_eq!(BN_is_one(gq), 1);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);

            /* The scalars the install path writes: a seed of the digest's width, a counter the
             * search finished at, an `h` the unverifiable-`g` search produced, and the
             * `gindex` sentinel still in place because the caller never set one. */
            assert!(!(*p.as_ref()).seed.is_null());
            assert_eq!((*p.as_ref()).seedlen, SHA256_DIGEST_LENGTH);
            assert!((*p.as_ref()).pcounter >= 0);
            assert!(
                (*p.as_ref()).h >= 2,
                "the h-search starts at 2 and records the h it stopped at"
            );
            assert_eq!((*p.as_ref()).gindex, FFC_UNVERIFIABLE_GINDEX);
            assert_eq!((*p.as_ref()).flags, FFC_PARAM_FLAG_VALIDATE_PQG);

            /* And the independent check: the validator that walks the same chain backwards. */
            let mut vres: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut vres,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_UNVERIFIABLE_G
            );
            assert_eq!(vres, 0);
        }
    }

    /// **`generate_canonical_g` is testable without knowing the group**: with `gindex` set
    /// before the generation, the `ggen` chain runs and the object comes back with a canonical
    /// `g`. Two assertions make that observable — validation then answers `SUCCESS` rather than
    /// `UNVERIFIABLE_G` (which is exactly the `canonical_g == 0` test in the `pass:` label), and
    /// **changing `gindex` alone makes it fail with `FFC_CHECK_G_MISMATCH`**, because the chain
    /// hashes the index.
    ///
    /// The second is the load-bearing one: a transcription that ignored `gindex` in the hash
    /// would still produce *a* `g`, still validate at `gindex = 1`, and still pass every
    /// property test above.
    #[test]
    fn a_canonical_generation_binds_the_index_and_flips_on_it() {
        let mut p = Params::new();
        let mut res: c_int = -1;
        // SAFETY: the object is live and owned by this test.
        unsafe {
            ossl_ffc_params_set_gindex(p.as_mut(), 1);
            assert_eq!(
                ossl_ffc_params_FIPS186_4_generate(
                    ptr::null_mut(),
                    p.as_mut(),
                    FFC_PARAM_TYPE_DH,
                    2048,
                    256,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_SUCCESS
            );

            let mut vres: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut vres,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_SUCCESS,
                "a canonical g is fully verifiable, so `pass` answers SUCCESS"
            );
            assert_eq!(vres, 0);

            /* The index is part of the hash: a different one is a different g. */
            ossl_ffc_params_set_gindex(p.as_mut(), 2);
            let mut vres: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut vres,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(vres, FFC_CHECK_G_MISMATCH);

            /* And the seed is part of it too: the index back, one seed byte changed. **Which
             * refusal arrives is not asserted**, because the object's seed is random and a
             * changed seed may fail the `q` chain before the `g` chain is ever reached — the
             * authority's own test records the same ("As the params are randomly generated the
             * error is one of the following", `test/ffc_internal_test.c:417`). What *is*
             * asserted is that the generation is no longer reproducible from its own stored
             * inputs, which is the property the seed's presence means. */
            ossl_ffc_params_set_gindex(p.as_mut(), 1);
            *(*p.as_mut()).seed ^= 0x01;
            let mut vres: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut vres,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert!(
                vres == FFC_CHECK_G_MISMATCH
                    || vres == FFC_CHECK_Q_MISMATCH
                    || vres == FFC_CHECK_Q_NOT_PRIME,
                "a changed seed leaves the seed chain, at q or at g; got {vres:#x}"
            );
        }
    }

    /// **The FIPS 186-2 twin, and its two differences from the 186-4 one**: it generates the
    /// 1024/160 pair the 186-4 `#else` DH table also allows but whose `q` comes from the
    /// SHA-1-shaped XOR chain rather than from `Hash(seed)`, and its wrapper sets
    /// `FFC_PARAM_FLAG_VALIDATE_LEGACY` on the caller's object — which is what later makes
    /// `ossl_ffc_params_full_validate` take the 186-2 arm.
    ///
    /// The 186-4 validator is then asked the same question and **must fail**, because the two
    /// standards derive different `q` from the same seed. That is the property
    /// `test/ffc_internal_test.c:409-419` asserts, and it is the one thing that says the two
    /// chains are not the same code.
    #[test]
    fn a_fips186_2_generation_is_legacy_and_the_186_4_validator_refuses_it() {
        let mut p = Params::new();
        let mut res: c_int = -1;
        // SAFETY: the object is live and owned by this test.
        unsafe {
            assert_eq!(
                ossl_ffc_params_FIPS186_2_generate(
                    ptr::null_mut(),
                    p.as_mut(),
                    FFC_PARAM_TYPE_DH,
                    1024,
                    160,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_SUCCESS
            );

            assert_eq!(BN_num_bits((*p.as_ref()).p), 1024);
            assert_eq!(BN_num_bits((*p.as_ref()).q), 160);
            assert_eq!(
                (*p.as_ref()).flags & FFC_PARAM_FLAG_VALIDATE_LEGACY,
                FFC_PARAM_FLAG_VALIDATE_LEGACY,
                "the 186-2 wrapper marks the object it generated"
            );
            /* The seed it stores is `qsize` bytes — one digest wide — not the digest's own
             * `mdsize`, which is the 186-2 chain's spelling. */
            assert_eq!((*p.as_ref()).seedlen, SHA_DIGEST_LENGTH);

            /* Its own validator accepts it. */
            let mut vres: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_2_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut vres,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_UNVERIFIABLE_G,
                "the 186-2 verifier has no canonical g, so VALIDATE_G always answers 2"
            );

            /* The 186-4 validator does not: the two q chains differ. */
            let mut vres4: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut vres4,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert!(
                vres4 == FFC_CHECK_Q_MISMATCH || vres4 == FFC_CHECK_Q_NOT_PRIME,
                "as the authority's own test says, the error is one of the two; got {vres4:#x}"
            );
        }
    }

    /// The refusals that happen **before any arithmetic**, so this test is cheap: the L/N pair
    /// is type-dependent, an `N` with no default digest is `FFC_CHECK_INVALID_Q_VALUE`, a
    /// generation with only one of `p`/`q` set is `FFC_CHECK_INVALID_PQ`, and the 186-2 twin
    /// refuses `L < 512` and a `qsize` outside its three digest widths.
    #[test]
    fn the_cheap_refusals_name_their_reasons() {
        let mut p = Params::new();
        let mut res: c_int = -1;
        // SAFETY: the object is live and owned by this test.
        unsafe {
            /* 2048/160 is not in the DH table. */
            assert_eq!(
                ossl_ffc_params_FIPS186_4_generate(
                    ptr::null_mut(),
                    p.as_mut(),
                    FFC_PARAM_TYPE_DH,
                    2048,
                    160,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res, FFC_CHECK_BAD_LN_PAIR);
            assert_eq!((*p.as_ref()).p, ptr::null_mut(), "nothing was generated");

            /* `default_mdname` knows 160, 224 and 256 only. */
            let mut res2: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_generate(
                    ptr::null_mut(),
                    p.as_mut(),
                    FFC_PARAM_TYPE_DSA,
                    2048,
                    384,
                    &raw mut res2,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res2, FFC_CHECK_INVALID_Q_VALUE);

            /* One of `p`/`q` without the other is a generation error. */
            let bp = BN_new();
            assert!(BN_set_word(bp, 23) != 0);
            ossl_ffc_params_set0_pqg(p.as_mut(), bp, ptr::null_mut(), ptr::null_mut());
            let mut res3: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_generate(
                    ptr::null_mut(),
                    p.as_mut(),
                    FFC_PARAM_TYPE_DH,
                    2048,
                    256,
                    &raw mut res3,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res3, FFC_CHECK_INVALID_PQ);

            /* The 186-2 twin's two cheap refusals. */
            let mut p2 = Params::new();
            let mut res4: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_2_generate(
                    ptr::null_mut(),
                    p2.as_mut(),
                    FFC_PARAM_TYPE_DH,
                    448,
                    160,
                    &raw mut res4,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res4, FFC_CHECK_BAD_LN_PAIR);

            let mut res5: c_int = -1;
            /* A named digest, so the refusal is the `qsize` test and not the digest choice:
             * `N = 192` gives `qsize = 24`, which is not one of 20, 28 or 32. */
            ossl_ffc_set_digest(p2.as_mut(), c"SHA-1".as_ptr(), ptr::null());
            assert_eq!(
                ossl_ffc_params_FIPS186_2_generate(
                    ptr::null_mut(),
                    p2.as_mut(),
                    FFC_PARAM_TYPE_DH,
                    1024,
                    192,
                    &raw mut res5,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res5, FFC_CHECK_INVALID_Q_VALUE);

            /* `type` is not read by the 186-2 verifier: the same object is refused the same
             * way as DSA. */
            let mut res6: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_2_generate(
                    ptr::null_mut(),
                    p2.as_mut(),
                    FFC_PARAM_TYPE_DSA,
                    448,
                    160,
                    &raw mut res6,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res6, FFC_CHECK_BAD_LN_PAIR);
        }
    }
}
