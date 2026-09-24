//! Phase 8 — `crypto/bn/bn_intern.c`, the `BIGNUM` internals Phase 8.7's EC closure reaches.
//!
//! The authority file is 195 lines and defines eight functions: `bn_compute_wNAF`, the
//! two accessors `bn_get_top`/`bn_get_dmax`, `bn_set_all_zero`, the two word-array
//! bridges `bn_copy_words`/`bn_get_words`, `bn_set_static_words` and `bn_set_words`.
//! Nothing else, and no export: `internal-symbols.json` records all eight as internals of
//! this translation unit, which is why the unit can be given a crate module without moving
//! `forensics/phase8-obligations.json` — the ledger counts exports.
//!
//! ## Why this module exists before its callers, and which caller each name is for
//!
//! `docs/PHASE-8-EC-INTEGRATION-PLAN.md` §1 step 2 lands this unit *before* the EC layer
//! that calls it, and the plan's §3 closure table is the reason: a callee belonging to
//! another stratum's directory has to exist before the module that names it does, or the
//! prerequisite gate's direction A reports `undefined_prerequisite` for it. The callers,
//! measured from the authority rather than assumed:
//!
//! * [`bn_compute_wNAF`] — `crypto/ec/ec_mult.c:530` and `:560`, the two `bn_compute_wNAF`
//!   calls of `ossl_ec_wNAF_mul`'s pre-computation and its per-digit accumulation.
//! * [`bn_mod_exp_mont_fixed_top`](crate::bn::exp::bn_mod_exp_mont_fixed_top) —
//!   `crypto/ec/ec_lib.c:1271`, `ossl_ec_group_do_inverse_ord`'s Fermat inversion. **The
//!   plan's §2e names this call as `ecp_smpl.c`'s `field_inv` path; it is `ec_lib.c`'s
//!   `ossl_ec_group_do_inverse_ord`**, and `ecp_smpl.c`'s own `field_inv` reaches
//!   `BN_mod_inverse` instead. The correction changes nothing about what lands, and it is
//!   recorded here because a module doc that points at the wrong call site is the class of
//!   error the next session would waste an hour on.
//! * [`bn_set_all_zero`] — `crypto/ec/ec2_smpl.c:93`, `:94`, `:120` and `:128`, the
//!   binary-curve `group_copy` and `group_set_curve_GF2m` paths.
//! * [`bn_get_top`], [`bn_get_dmax`], [`bn_copy_words`], [`bn_get_words`] and
//!   [`bn_set_words`] — `crypto/ec/ecp_nistz256.c` and `crypto/ec/ecp_sm2p256.c` only,
//!   with `bn_get_words` also reached by `crypto/asn1/t_pkey.c:67-68`,
//!   `crypto/rsa/rsa_ossl.c:770`, `crypto/der_writer.c:140` and
//!   `crypto/encode_decode/encoder_lib.c:727`, all of which are earlier strata's and
//!   which substitute for it as this crate does. `ecp_nistz256.c` is the unit
//!   `docs/SECURITY_DIVERGENCE_POLICY.md`'s D-EC-2 excludes, so the five are landed for
//!   the *unit* rather than for a caller in this block: D327's rule is that a unit given a
//!   crate module must answer for every internal it defines, and a partial `bn_intern.c`
//!   would be a finding rather than a smaller landing.
//!
//! ## The one name that is already transcribed somewhere else
//!
//! `bn_get_top` is `bn_intern.c`'s, and `src/bn/bignum.rs:1755` already implements it,
//! because the modules that call it — `crypto/dsa/dsa_ossl.c`'s `dsa_sign_setup` and
//! `crypto/deterministic_nonce.c` — landed in Phases 8.6 and 7 respectively and
//! `dsa_ossl.rs` needed it then. The plan's §2e says "none of them implemented"; that is
//! true of seven of the eight and false of this one, and the resolution is a *reference*
//! rather than a second definition: this module imports it and uses it, which is what the
//! gate's direction B accepts (`prerequisite_gate.py:500`, "the module that does own it
//! answers for the name") and what keeps one function from existing twice with two doc
//! comments that could drift apart.
//!
//! ## Three representational gaps, named rather than papered over
//!
//! This crate's `BIGNUM` is a `Vec<Limb>` normalised on every store (`src/bn/limbs.rs`),
//! with no `top` distinct from its length, no `dmax` distinct from its capacity and no
//! pointer into storage the library does not own (`src/bn/bignum.rs:67`). Three of the
//! eight functions are functions *of* that representation in the authority:
//!
//! * `bn_get_dmax` answers `a->dmax`, the allocated width, which can exceed `a->top`. Here
//!   the two are the same number, so the accessor answers `a->d.len()` — the same answer
//!   `bn_get_top` gives, and the same *value* every caller that compares the two would see
//!   after `bn_correct_top`.
//! * `bn_set_all_zero` executes `for (i = a->top; i < a->dmax; i++) a->d[i] = 0;`, a loop
//!   over the padding between the value and the allocation. Here the range is empty by
//!   construction. The body is written as the loop over `b.d[top..dmax]` rather than as a
//!   `todo!()`, because the loop *is* the contract and it is empty rather than absent.
//! * `bn_set_static_words` is **withheld**, not stubbed: it aliases the caller's
//!   `const BN_ULONG *` into `a->d` under `BN_FLG_STATIC_DATA`, and a `Vec<Limb>` cannot
//!   alias foreign storage, so a transcription would either copy (a different function) or
//!   hand out a pointer `BN_free`'s static-data path then declines to release. The
//!   authority has **no caller for it anywhere outside `bn_intern.c` itself**, so the
//!   difference is unreachable, and it is recorded as one of `forensics/prerequisites.json`'s
//!   divergence rows with this module as its owner — the shape D334 used for
//!   `ec_curve.c`'s withheld internal.
//!
//! ## The scope that stops here
//!
//! `crypto/bn/bn_exp.c` is 1,379 lines and defines one internal,
//! `bn_mod_exp_mont_fixed_top`; it lands beside this module in `src/bn/exp.rs`. Nothing
//! else of either unit is in this slice, and no export of either is touched: both files'
//! public names (`BN_mod_exp_mont`, `BN_mod_exp_mont_consttime`, …) were 8.4's and 8.5's
//! and are already implemented in `src/bn/mont.rs`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, CStr};

use crate::bn::bignum::{
    as_mut, as_ref, bn_get_top, bn_wexpand, BN_is_bit_set, BN_is_negative, BN_is_zero, BN_num_bits,
    BigNum,
};
use crate::bn::limbs::{self, Limb};
use crate::runtime::err::err_sites::{
    BN_INTERN_109, BN_INTERN_120, BN_INTERN_126, BN_INTERN_187, BN_INTERN_41, BN_INTERN_53,
    BN_INTERN_97,
};
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

/// The authority's `__FILE__` for every raise site this unit defines, and the line the
/// generated table records instead — `raise_site` reads the site, and these two arguments
/// exist only so the allocation sites can name their own caller.
const FILE: &CStr = c"crypto/bn/bn_intern.c";
const LINE: c_int = 0;

/// `signed char *bn_compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len)` —
/// `crypto/bn/bn_intern.c:22-134`.
///
/// The modified width-`(w+1)` non-adjacent form of `scalar`: an array of digits, each zero
/// or odd with `|r[j]| < 2^w`, satisfying `scalar = sum_j r[j] * 2^j`, with at most one
/// non-zero digit in any `w+1` consecutive positions. The *modified* part is the `#if 1`
/// arm at `:78-86`: once no new bits can enter the window, the negative digit is replaced
/// by a positive one, which shortens the representation by one digit and is why
/// `ec_mult.c` can rely on the length it is given.
///
/// The buffer is `OPENSSL_malloc`'d and the caller releases it with `OPENSSL_free`, so it
/// is `CRYPTO_malloc`/`CRYPTO_free` here. `ret_len` is the authority's `size_t *`.
///
/// Every refusal is the authority's, at the authority's own coordinate: `w` outside
/// `1..=7` (`:41`), an object with no limbs (`:53`, unreachable behind the zero test and
/// kept anyway, because it is the authority's own second guard), a digit outside
/// `(-2^w, 2^w)` or even (`:97`), a residual window that is neither zero nor `2^w` nor
/// `2^(w+1)` (`:109`), a window past `2^(w+1)` (`:120`), and a length past `len + 1`
/// (`:126`). A refusal frees the buffer and answers NULL, which is the authority's `goto
/// err` with `r` in hand.
///
/// # Safety
///
/// `scalar` must be null or point to a live `BIGNUM`, and `ret_len` must point to a
/// writable `usize`. The returned pointer is null or owned by the caller, who must release
/// it with `CRYPTO_free`.
// The caller is `crypto/ec/ec_mult.c`'s `ossl_ec_wNAF_mul`, which lands with the rest of
// the EC layer; nothing in the tree calls this yet, which is the plan's ordering rather
// than an oversight.
// The name is the authority's — `wNAF` is a term of art rather than a word — and the
// prerequisite gate resolves this crate's definitions by it, so it is kept verbatim.
#[allow(non_snake_case)]
#[allow(dead_code)]
pub(crate) unsafe fn bn_compute_wNAF(
    scalar: *const BigNum,
    w: c_int,
    ret_len: *mut usize,
) -> *mut c_char {
    let mut sign: c_int = 1;

    // SAFETY: `scalar` is null-or-live per this function's `# Safety` section.
    if unsafe { BN_is_zero(scalar) } != 0 {
        // SAFETY: `CRYPTO_malloc` needs no caller pointer and answers null on failure.
        let r = CRYPTO_malloc(1, FILE.as_ptr(), LINE).cast::<u8>();
        if r.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `r` owns the one byte just allocated, and `ret_len` is writable.
        unsafe {
            *r = 0;
            *ret_len = 1;
        }
        return r.cast::<c_char>();
    }

    if w <= 0 || w > 7 {
        // 'signed char' can represent integers with absolute values less than 2^7.
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BN_INTERN_41) };
        return core::ptr::null_mut();
    }
    let bit: c_int = 1 << w; // at most 128
    let next_bit: c_int = bit << 1; // at most 256
    let mask: c_int = next_bit - 1; // at most 255

    // SAFETY: `scalar` is null-or-live per this function's `# Safety` section.
    if unsafe { BN_is_negative(scalar) } != 0 {
        sign = -1;
    }

    // `scalar->d == NULL || scalar->top == 0`. In this representation both are `d.is_empty()`,
    // and the zero test above has already answered it; the guard is the authority's and is
    // written as it is because an unreachable branch that is *dropped* is a branch a reader
    // cannot check.
    // SAFETY: `scalar` is null-or-live per this function's `# Safety` section.
    let Some(limbs_of_scalar) = (unsafe { as_ref(scalar) }) else {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BN_INTERN_53) };
        return core::ptr::null_mut();
    };
    if limbs_of_scalar.d.is_empty() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BN_INTERN_53) };
        return core::ptr::null_mut();
    }

    // Modified wNAF may be one digit longer than the binary representation, so the
    // authority allocates `BN_num_bits(scalar) + 1` — bits, not bytes, which is an
    // over-allocation it is the authority's to make. `ret_len` becomes the *used* length.
    // SAFETY: `scalar` is live here — the guard above answered NULL — and `BN_num_bits`
    // reads it without mutating.
    let len = usize::try_from(unsafe { BN_num_bits(scalar) }).unwrap_or_default();

    // SAFETY: `CRYPTO_malloc` needs no caller pointer and answers null on failure.
    let r = CRYPTO_malloc(len + 1, FILE.as_ptr(), LINE).cast::<u8>();
    // SAFETY: `r` is null here, and the authority's `goto err` releases it and answers NULL.
    if r.is_null() {
        return core::ptr::null_mut();
    }

    // The whole body from here to the end of the loop is the authority's, and a refusal
    // leaves through `free_and_null` with `r` already allocated — the authority's `err:`.
    let bail = |r: *mut u8| -> *mut c_char {
        // SAFETY: `r` came from the `CRYPTO_malloc` above and is released exactly once.
        unsafe { CRYPTO_free(r.cast(), FILE.as_ptr(), LINE) };
        core::ptr::null_mut()
    };

    let mut window_val: c_int = (limbs_of_scalar.d[0] & (mask as u64)) as c_int;
    let mut j: usize = 0;

    while (window_val != 0) || (j + (w as usize) + 1 < len) {
        // If `j + w + 1 >= len`, `window_val` will not increase.
        let mut digit: c_int = 0;

        // 0 <= window_val <= 2^(w+1).
        if (window_val & 1) != 0 {
            // 0 < window_val < 2^(w+1).
            if (window_val & bit) != 0 {
                digit = window_val - next_bit; // -2^w < digit < 0

                // The modified-wNAF arm (`#if 1` at `:78`): no new bits will be added
                // into `window_val`, so a positive digit shortens the representation.
                if j + (w as usize) + 1 >= len {
                    digit = window_val & (mask >> 1); // 0 < digit < 2^w
                }
            } else {
                digit = window_val; // 0 < digit < 2^w
            }

            if digit <= -bit || digit >= bit || (digit & 1) == 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_INTERN_97) };
                return bail(r);
            }

            window_val -= digit;

            // `window_val` is now either 0 or 2^(w+1) in standard wNAF generation; for
            // modified window NAFs it may also be 2^w.
            if window_val != 0 && window_val != next_bit && window_val != bit {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_INTERN_109) };
                return bail(r);
            }
        }

        // SAFETY: `j < len + 1` is maintained by the loop's own bound and the check below,
        // and `r` owns `len + 1` bytes, so this store is in bounds.
        unsafe { *r.add(j) = (sign * digit) as u8 };
        j += 1;
        window_val >>= 1;
        // SAFETY: `scalar` is live per this function's `# Safety` section.
        window_val += bit * (unsafe { BN_is_bit_set(scalar, (j + w as usize) as c_int) });

        if window_val > next_bit {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_INTERN_120) };
            return bail(r);
        }
    }

    if j > len + 1 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BN_INTERN_126) };
        return bail(r);
    }
    // SAFETY: `ret_len` is writable per this function's `# Safety` section.
    unsafe { *ret_len = j };
    r.cast::<c_char>()
}

/// `int bn_get_dmax(const BIGNUM *a)` — `crypto/bn/bn_intern.c:142-145`.
///
/// The allocated width. **See the module doc**: this representation normalises on every
/// store, so there is no width above the value and the answer is the value's own length —
/// which is also [`bn_get_top`]'s answer, and the answer every caller sees once the
/// authority has `bn_correct_top`'d.
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[allow(dead_code)]
pub(crate) unsafe fn bn_get_dmax(a: *const BigNum) -> c_int {
    // SAFETY: `a` is null-or-live per this function's `# Safety` section.
    unsafe { bn_get_top(a) }
}

/// `void bn_set_all_zero(BIGNUM *a)` — `crypto/bn/bn_intern.c:147-153`.
///
/// Clears the padding between the value's top limb and the allocation. In this
/// representation the two coincide, so the range is empty and the function leaves the
/// magnitude, the sign and the flags exactly as it found them. The loop is written out
/// because the loop *is* the contract.
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM` that is not otherwise borrowed.
#[allow(dead_code)]
pub(crate) unsafe fn bn_set_all_zero(a: *mut BigNum) {
    // SAFETY: `a` is null-or-live, and uniquely owned, per this function's `# Safety` section.
    if let Some(b) = unsafe { as_mut(a) } {
        let top = c_int::try_from(b.d.len()).unwrap_or(c_int::MAX);
        // SAFETY: `a` is live per this function's `# Safety` section; `bn_get_dmax` reads
        // the same object through a shared reference, which is not a mutable borrow.
        let dmax = unsafe { bn_get_dmax(a) };
        if dmax > top {
            let dmax = dmax as usize;
            b.d[top as usize..dmax].fill(0);
        }
    }
}

/// `int bn_copy_words(BN_ULONG *out, const BIGNUM *in, int size)` —
/// `crypto/bn/bn_intern.c:155-164`.
///
/// Copies `in`'s limbs into a caller-provided array of `size` limbs, zero-padding the tail,
/// and answers 0 without writing when the value does not fit. The authority's `memset`
/// covers the whole array and its `memcpy` only `in->top` limbs, so the tail is zero even
/// when the value is shorter.
///
/// # Safety
///
/// `out` must be writable for `size` limbs, `size` must not be negative, and `value` must
/// be null or point to a live `BIGNUM`.
#[allow(dead_code)]
pub(crate) unsafe fn bn_copy_words(out: *mut Limb, value: *const BigNum, size: c_int) -> c_int {
    // SAFETY: `value` is null-or-live per this function's `# Safety` section.
    let top = unsafe { bn_get_top(value) };
    if top > size {
        return 0;
    }
    // SAFETY: `out` is writable for `size` limbs and `size` is not negative per this
    // function's `# Safety` section.
    unsafe { core::ptr::write_bytes(out, 0, size as usize) };
    // SAFETY: `value` is null-or-live per this function's `# Safety` section.
    let Some(src) = (unsafe { as_ref(value) }) else {
        return 1;
    };
    if !src.d.is_empty() {
        // SAFETY: the source has `top <= size` limbs and `out` is writable for `size`.
        unsafe { core::ptr::copy_nonoverlapping(src.d.as_ptr(), out, src.d.len()) };
    }
    1
}

/// `BN_ULONG *bn_get_words(const BIGNUM *a)` — `crypto/bn/bn_intern.c:166-169`.
///
/// The value's limbs, for a caller that wants the representation rather than the number.
/// The authority answers `a->d`, a pointer into the object's own storage; here it is the
/// `Vec`'s buffer, and `Vec<Limb>` has no capacity above its length (`bn_wexpand` reserves
/// for that reason and not to publish a wider array), so a caller that writes through this
/// pointer is confined to `d.len()` limbs.
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`. The answer is valid only while `a` is
/// alive, unmodified, and not borrowed mutably.
#[allow(dead_code)]
pub(crate) unsafe fn bn_get_words(a: *const BigNum) -> *mut Limb {
    // SAFETY: `a` is null-or-live per this function's `# Safety` section.
    match unsafe { as_ref(a) } {
        // The authority's return type is non-const because its own callers write through it;
        // no caller on this crate's paths does, and the pointer is handed back unchanged.
        Some(b) => b.d.as_ptr().cast_mut(),
        None => core::ptr::null_mut(),
    }
}

/// `int bn_set_words(BIGNUM *a, const BN_ULONG *words, int num_words)` —
/// `crypto/bn/bn_intern.c:184-195`.
///
/// Replaces `a`'s magnitude with `num_words` limbs and normalises — the authority's
/// `bn_correct_top`, written here as [`limbs::normalise`] because this representation is
/// always corrected (the authority itself names that pair as one operation; see
/// `ossl_bn_mask_bits_fixed_top`'s doc in `src/bn/bignum.rs`). **`neg` and the flags are
/// untouched**, which is the authority's behaviour rather than an omission: its body writes
/// `d`, `top` and nothing else.
///
/// The room is made by `bn_wexpand` first, so the failure is the authority's: a null `a`
/// answers NULL from the expansion and the refusal is raised at `:187`.
///
/// # Safety
///
/// `a` must be null or point to a live, uniquely-owned `BIGNUM`, `words` must be readable
/// for `num_words` limbs (or `num_words` must be zero), and `num_words` must not be
/// negative.
#[allow(dead_code)]
pub(crate) unsafe fn bn_set_words(a: *mut BigNum, words: *const Limb, num_words: c_int) -> c_int {
    // SAFETY: `a` is null-or-live per this function's `# Safety` section.
    if unsafe { bn_wexpand(a, num_words) }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BN_INTERN_187) };
        return 0;
    }
    // SAFETY: `a` is null-or-live, and uniquely owned, per this function's `# Safety` section.
    let Some(dst) = (unsafe { as_mut(a) }) else {
        return 0;
    };
    let n = match usize::try_from(num_words) {
        Ok(n) => n,
        Err(_) => {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_INTERN_187) };
            return 0;
        }
    };
    let mut d = if n == 0 {
        Vec::new()
    } else {
        // SAFETY: `words` is readable for `n` limbs per this function's `# Safety` section.
        unsafe { core::slice::from_raw_parts(words, n) }.to_vec()
    };
    limbs::normalise(&mut d);
    dst.d = d;
    1
}

// `unwrap_used`, `expect_used` and `panic` are denied for product code, where a panic on
// the FFI path is worse than a failure value; in a test a failing unwrap *is* the report.
// The same three are allowed on the test modules of `src/runtime/obj.rs`, `src/mac/poly1305.rs`
// and their neighbours.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::{new_owned, BN_free};

    /// The digits of a wNAF buffer, copied out of the caller-owned allocation so the test
    /// can release it.
    fn wnaf(scalar: *const BigNum, w: c_int) -> Option<Vec<i8>> {
        let mut len: usize = 0;
        // SAFETY: `scalar` is a live object the caller owns, and `len` is writable.
        let p = unsafe { bn_compute_wNAF(scalar, w, &mut len) };
        if p.is_null() {
            return None;
        }
        // SAFETY: a non-null answer owns `len` digits, per the function's contract.
        let digits = unsafe { core::slice::from_raw_parts(p.cast::<i8>(), len) }.to_vec();
        // SAFETY: the buffer came from `CRYPTO_malloc` and has not been released.
        unsafe { CRYPTO_free(p.cast(), FILE.as_ptr(), LINE) };
        Some(digits)
    }

    /// The scalar as `i128`, for scalars the tests keep small enough to compare exactly.
    fn value(digits: &[i8]) -> i128 {
        digits
            .iter()
            .enumerate()
            .map(|(j, &d)| i128::from(d) * (1i128 << j))
            .sum()
    }

    #[test]
    fn the_wnaf_of_zero_is_a_single_zero_digit() {
        // SAFETY: the test owns every object it passes.
        unsafe {
            let a = new_owned(Vec::new(), 0);
            let digits = wnaf(a, 4).expect("zero has a representation");
            assert_eq!(digits, vec![0]);
            BN_free(a);
        }
    }

    #[test]
    fn the_wnaf_reconstructs_the_scalar_at_every_window() {
        // The properties the authority's own comment states: `scalar = sum_j r[j] * 2^j`,
        // every digit zero or odd with `|r[j]| < 2^w`, and at most one non-zero digit in
        // any `w + 1` consecutive positions — **with the stated exception that the most
        // significant digit may be only `w - 1` zeros away from the next non-zero one**,
        // which is what the modified form buys (its `#if 1` arm at `:78-86`). The window
        // walk below therefore stops before the final digit: `3` at `w = 1` is `[1, 1]` on
        // the authority and here, and that is the exception rather than a defect — it was
        // the first thing this test's own first version got wrong.
        for &n in &[
            1i128, 2, 3, 7, 8, 15, 16, 255, 256, 12345, 65535, 65536, 1000003,
        ] {
            for w in 1..=7i32 {
                // SAFETY: the test owns every object it passes.
                unsafe {
                    let a = new_owned(vec![n as u64], 0);
                    let digits = wnaf(a, w).expect("every window has a representation");
                    assert_eq!(value(&digits), n, "n={n} w={w} digits={digits:?}");
                    for &d in &digits {
                        assert!(
                            d == 0 || ((d.unsigned_abs() as i32) < (1 << w) && d % 2 != 0),
                            "digit {d} is outside (-2^{w}, 2^{w}) or even"
                        );
                    }
                    let interior = digits.len().saturating_sub(1);
                    for j in 0..interior {
                        let end = (j + w as usize + 1).min(interior);
                        assert!(
                            digits[j..end].iter().filter(|&&d| d != 0).count() <= 1,
                            "two non-zero digits within w+1 of each other below the top: {digits:?}"
                        );
                    }
                    BN_free(a);
                }
            }
        }
    }

    #[test]
    fn the_wnaf_of_a_negative_scalar_negates_every_digit() {
        // SAFETY: the test owns every object it passes.
        unsafe {
            let a = new_owned(vec![12345], 0);
            let b = new_owned(vec![12345], 1);
            let positive = wnaf(a, 5).expect("positive");
            let negative = wnaf(b, 5).expect("negative");
            assert_eq!(
                negative,
                positive.iter().map(|&d| -d).collect::<Vec<i8>>(),
                "a negative scalar is the same digits, negated"
            );
            BN_free(a);
            BN_free(b);
        }
    }

    #[test]
    fn an_out_of_range_window_is_refused() {
        // SAFETY: the test owns every object it passes.
        unsafe {
            let a = new_owned(vec![255], 0);
            let mut len: usize = 0;
            assert!(bn_compute_wNAF(a, 0, &mut len).is_null(), "w = 0");
            assert!(bn_compute_wNAF(a, 8, &mut len).is_null(), "w = 8");
            assert!(bn_compute_wNAF(a, -1, &mut len).is_null(), "w = -1");
            BN_free(a);
        }
    }

    #[test]
    fn copy_words_pads_the_tail_and_refuses_a_value_that_does_not_fit() {
        // SAFETY: the test owns every object it passes and every buffer it writes.
        unsafe {
            let a = new_owned(vec![0xdead_beef, 0x1234], 0);
            let mut out = [Limb::MAX; 4];
            assert_eq!(bn_copy_words(out.as_mut_ptr(), a, 4), 1);
            assert_eq!(out, [0xdead_beef, 0x1234, 0, 0], "the tail is cleared");
            let mut small = [Limb::MAX; 1];
            assert_eq!(bn_copy_words(small.as_mut_ptr(), a, 1), 0);
            assert_eq!(small, [Limb::MAX], "a refusal writes nothing");
            BN_free(a);
        }
    }

    #[test]
    fn set_words_normalises_and_leaves_the_sign_alone() {
        // SAFETY: the test owns every object it passes.
        unsafe {
            let a = new_owned(vec![7], 1);
            let words = [9 as Limb, 0, 0];
            assert_eq!(bn_set_words(a, words.as_ptr(), 3), 1);
            let (d, neg) = crate::bn::bignum::parts(as_ref(a));
            assert_eq!(d, vec![9], "the trailing zeros are normalised away");
            assert!(neg, "bn_set_words does not touch `neg`");
            BN_free(a);
        }
    }

    #[test]
    fn the_three_accessors_answer_the_value_they_are_given() {
        // SAFETY: the test owns every object it passes.
        unsafe {
            let a = new_owned(vec![1, 2, 3], 0);
            assert_eq!(bn_get_top(a as *const BigNum), 3);
            assert_eq!(bn_get_dmax(a as *const BigNum), 3);
            let words = bn_get_words(a as *const BigNum);
            assert_eq!(core::slice::from_raw_parts(words, 3), &[1, 2, 3]);
            bn_set_all_zero(a);
            let (d, _) = crate::bn::bignum::parts(as_ref(a));
            assert_eq!(d, vec![1, 2, 3], "there is no padding to clear");
            BN_free(a);
            assert!(bn_get_words(core::ptr::null()).is_null());
            assert_eq!(bn_get_dmax(core::ptr::null()), 0);
        }
    }
}
