//! Phase 5 — the `BN_GF2m_*` family: arithmetic in `GF(2)[x]/(p)`.
//!
//! ## The two spellings of a field element
//!
//! A `BIGNUM` is the natural carrier: bit `i` is the coefficient of `x^i`, so the
//! value *is* the polynomial. The `_arr` entry points take the same thing in the
//! authority's other spelling, an `int` array where `p[0]` is the degree, `p[1..]` are
//! the remaining exponents in decreasing order, and the list ends at the `0` entry —
//! which is also the `x^0` term, present because `BN_GF2m_poly2arr` refuses a value
//! whose constant term is missing. The `-1` that `poly2arr` writes after that is for
//! readers that want the length; the arithmetic loops stop at the `0` and never see
//! it.
//!
//! ## Why this implementation is not the authority's
//!
//! `bn_gf2m.c` is a set of unrolled carry chains written for speed. What is
//! reproduced here is the **value**: for every input the authority accepts, the
//! result is the same field element, because `GF(2)[x]/(p)` arithmetic has exactly
//! one canonical representative and both routes reach it. The probe checks the values
//! against the authority rather than against a definition.
//!
//! ## The one place the value is not the whole story
//!
//! `BN_GF2m_mod_inv` in the authority **blinds** the inversion: it draws a random
//! factor with `BN_priv_rand_ex`, multiplies, inverts vartime and multiplies back, so
//! that the timing of the vartime inversion is not a function of the secret. This
//! implementation computes the same inverse without the blinding, because RAND is
//! Phase 9. The returned value is identical; the timing profile is not, and that is
//! recorded as a security divergence in `docs/SECURITY_DIVERGENCE_POLICY.md` rather
//! than left for a reader to notice.

use core::ffi::c_int;

use crate::bn::arith::BN_ucmp;
use crate::bn::bignum::{
    as_mut, as_ref, new_owned, parts, store, BN_copy, BN_free, BN_is_zero, BN_set_bit, BN_zero_ex,
    BigNum,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_get, BN_CTX_start, BnCtx};
use crate::bn::limbs::{self, Limb};
use crate::bn::rand::{BN_priv_rand_ex, BN_RAND_BOTTOM_ANY, BN_RAND_TOP_ONE};
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BN_GF2M_1065, BN_GF2M_1075, BN_GF2M_1111, BN_GF2M_389, BN_GF2M_472, BN_GF2M_532, BN_GF2M_915,
    BN_GF2M_977,
};
use crate::runtime::err::raise_site;

/// The authority's `OSSL_NELEM(arr)` bound for the fixed-size wrappers: `arr[6]` in
/// `BN_GF2m_mod` is the smallest of them, and the others derive their bound from
/// `BN_num_bits(p) + 1`.
const FIXED_ARR: usize = 6;

/// `MAX_ITERATIONS` — `crypto/bn/bn_gf2m.c:24`. The ceiling on the even-degree
/// `BN_GF2m_mod_solve_quad_arr` retry loop before it raises `BN_R_TOO_MANY_ITERATIONS`.
/// The loop redraws while the accumulated `w` is zero; for an irreducible modulus the
/// trace functional is non-zero and a draw clears it about half the time, so the ceiling
/// is reached only when the modulus is reducible enough that `w` vanishes identically.
const MAX_ITERATIONS: c_int = 50;

/// `OPENSSL_ECC_MAX_FIELD_BITS`, which `BN_GF2m_poly2arr` refuses to exceed.
const MAX_FIELD_BITS: c_int = 661;

/// The degree `p[0]`, or 0 for an empty array.
fn degree(p: &[c_int]) -> c_int {
    p.first().copied().unwrap_or(0)
}

/// The modulus polynomial as limbs: `x^degree` plus every exponent before the `0`
/// terminator, plus the `x^0` term the terminator stands for.
fn modulus_poly(p: &[c_int]) -> Vec<Limb> {
    let n = degree(p);
    if n <= 0 {
        return Vec::new();
    }
    let mut m = vec![0u64; (n as usize / 64) + 1];
    let set = |e: usize, m: &mut Vec<Limb>| {
        if e / 64 >= m.len() {
            m.resize(e / 64 + 1, 0);
        }
        m[e / 64] |= 1u64 << (e % 64);
    };
    set(n as usize, &mut m);
    let mut k = 1;
    while k < p.len() && p[k] != 0 {
        if p[k] > 0 {
            set(p[k] as usize, &mut m);
        }
        k += 1;
    }
    // The `x^0` term, which is what the `/* reducing component t^0 */` block in the
    // authority's reducer handles separately.
    set(0, &mut m);
    limbs::normalise(&mut m);
    m
}

/// `a ^ b` on magnitudes, limbwise.
fn poly_xor(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let mut out: Vec<Limb> = (0..a.len().max(b.len()))
        .map(|i| *a.get(i).unwrap_or(&0) ^ *b.get(i).unwrap_or(&0))
        .collect();
    limbs::normalise(&mut out);
    out
}

/// Carry-less multiply: the product in `GF(2)[x]`.
fn clmul(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let mut out = vec![0u64; a.len() + b.len() + 1];
    for (i, &x) in a.iter().enumerate() {
        let mut w = x;
        while w != 0 {
            let bit = i * 64 + w.trailing_zeros() as usize;
            w &= w - 1;
            // XOR `b << bit` into `out`.
            let (word, off) = (bit / 64, bit % 64);
            for (j, &y) in b.iter().enumerate() {
                if off == 0 {
                    out[word + j] ^= y;
                } else {
                    out[word + j] ^= y << off;
                    out[word + j + 1] ^= y >> (64 - off);
                }
            }
        }
    }
    limbs::normalise(&mut out);
    out
}

/// `a mod p` over `GF(2)[x]`, by shift-and-xor against the modulus polynomial.
///
/// Each step clears the top set bit of the working value, so the result is the unique
/// canonical remainder below `x^degree`. The authority's reducer reaches the same
/// representative through unrolled carry chains.
fn poly_rem(a: &[Limb], p: &[c_int]) -> Vec<Limb> {
    let n = degree(p);
    if n == 0 {
        return Vec::new();
    }
    let m = modulus_poly(p);
    let mut v = a.to_vec();
    limbs::normalise(&mut v);
    // A bit at index >= n is above the field, and XOR-ing the modulus shifted so its
    // top bit aligns with the value's clears exactly that bit. The condition is on the
    // *degree*, not on the modulus's bit length: a value one bit longer than the
    // modulus still needs one reduction, and testing `bit_len(v) > bit_len(m)` skips
    // it — which is the bug the court found here on its first run.
    while limbs::bit_len(&v) > n as usize {
        let shift = limbs::bit_len(&v) - 1 - n as usize;
        v = poly_xor(&v, &limbs::shl(&m, shift));
    }
    v
}

/// Polynomial quotient and remainder: `(q, r)` with `a = q*b + r` and `deg r < deg b`.
fn poly_div_rem(a: &[Limb], b: &[Limb]) -> (Vec<Limb>, Vec<Limb>) {
    let blen = limbs::bit_len(b);
    if blen == 0 {
        return (Vec::new(), Vec::new());
    }
    let mut r = a.to_vec();
    limbs::normalise(&mut r);
    let mut q: Vec<Limb> = Vec::new();
    while !r.is_empty() && limbs::bit_len(&r) >= blen {
        let shift = limbs::bit_len(&r) - blen;
        q = poly_xor(&q, &limbs::shl(&[1u64], shift));
        r = poly_xor(&r, &limbs::shl(b, shift));
    }
    limbs::normalise(&mut q);
    (q, r)
}

/// The multiplicative inverse of `a` modulo the polynomial `p`, or `None` when one
/// does not exist — the extended Euclidean algorithm over `GF(2)[x]`, which detects
/// that case as "the gcd is not 1" rather than as a wrong answer.
fn poly_inv(a: &[Limb], p: &[c_int]) -> Option<Vec<Limb>> {
    let field = modulus_poly(p);
    if field.is_empty() {
        return None;
    }
    let (mut r0, mut r1) = (field, poly_rem(a, p));
    if r1.is_empty() {
        return None;
    }
    let (mut t0, mut t1): (Vec<Limb>, Vec<Limb>) = (Vec::new(), vec![1u64]);
    while !r1.is_empty() {
        let (q, r2) = poly_div_rem(&r0, &r1);
        let t2 = poly_xor(&t0, &clmul(&q, &t1));
        r0 = r1;
        r1 = r2;
        t0 = t1;
        t1 = t2;
    }
    if r0.len() == 1 && r0[0] == 1 {
        Some(poly_rem(&t0, p))
    } else {
        None
    }
}

/// `a^e mod p` by square-and-multiply, with the accumulator starting at one so a zero
/// exponent answers one. The authority's ladder reads `BN_is_bit_set`, so the sign of
/// the exponent is not consulted.
fn poly_pow(a: &[Limb], e: &[Limb], p: &[c_int]) -> Vec<Limb> {
    let mut acc: Vec<Limb> = vec![1u64];
    let mut base = poly_rem(a, p);
    let bits = limbs::bit_len(e);
    for i in 0..bits {
        if limbs::bit(e, i) {
            acc = poly_rem(&clmul(&acc, &base), p);
        }
        if i + 1 < bits {
            base = poly_rem(&clmul(&base, &base), p);
        }
    }
    poly_rem(&acc, p)
}

/// Store a result into `dst`, keeping whatever sign the destination already had —
/// the authority's `bn_correct_top` clears `neg` only when the value becomes zero.
fn store_keeping_sign(dst: Option<&mut BigNum>, value: Vec<Limb>) -> bool {
    let existing = dst.as_ref().map(|d| d.neg != 0).unwrap_or(false);
    store(dst, value, existing)
}

/// `int BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `b` must each be null
/// or live.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_add(r: *mut BigNum, a: *const BigNum, b: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(b)) };
        let (ad, _) = parts(x);
        let (bd, _) = parts(y);
        c_int::from(store_keeping_sign(dst, poly_xor(&ad, &bd)))
    })
}

/// `int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max)`
///
/// Answers 0 for an even polynomial — one without a constant term — which is the
/// authority's `!BN_is_odd(a)`.
///
/// # Safety
///
/// `a` must be null or live; `p` must point to at least `max` writable `c_int`s.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_poly2arr(a: *const BigNum, p: *mut c_int, max: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (ad, _) = parts(unsafe { as_ref(a) });
        if limbs::is_even(&ad) {
            return 0;
        }
        if p.is_null() || max <= 0 {
            return 0;
        }
        // SAFETY: the caller guarantees `p` covers `max` writable `c_int`s.
        let out = unsafe { core::slice::from_raw_parts_mut(p, max as usize) };
        let mut k = 0usize;
        for i in (0..ad.len()).rev() {
            if ad[i] == 0 {
                continue;
            }
            for j in (0..64).rev() {
                if ad[i] & (1u64 << j) != 0 {
                    if k < max as usize {
                        out[k] = (64 * i + j) as c_int;
                    }
                    k += 1;
                }
            }
        }
        if k > 0 && out[0] > MAX_FIELD_BITS {
            return 0;
        }
        if k < max as usize {
            out[k] = -1;
        }
        (k + 1) as c_int
    })
}

/// `int BN_GF2m_arr2poly(const int p[], BIGNUM *a)`
///
/// # Safety
///
/// `p` must be a NUL-free `int` array terminated by `-1`; `a` must be null or a live,
/// uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_arr2poly(p: *const c_int, a: *mut BigNum) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            return 0;
        }
        let mut limbs_out: Vec<Limb> = Vec::new();
        let mut i = 0isize;
        loop {
            // SAFETY: the caller guarantees a `-1`-terminated array, so every index
            // before the terminator is inside it.
            let e = unsafe { *p.offset(i) };
            if e == -1 {
                break;
            }
            if e < 0 {
                return 0;
            }
            limbs::set_bit(&mut limbs_out, e as usize);
            i += 1;
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        c_int::from(store(unsafe { as_mut(a) }, limbs_out, false))
    })
}

/// `int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[])`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` must be null or live; `p`
/// must be a `0`-terminated exponent array whose first entry is the degree.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_arr(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x) = unsafe { (as_mut(r), as_ref(a)) };
        let (ad, _) = parts(x);
        if p.is_null() {
            return 0;
        }
        // SAFETY: the caller guarantees a `0`-terminated array, so a short read of
        // its first entry is inside it.
        let arr_first = unsafe { *p };
        if arr_first == 0 {
            return c_int::from(store_keeping_sign(dst, Vec::new()));
        }
        // SAFETY: as above; the array is terminated, so the scan below stops inside
        // it on every input the caller is allowed to pass.
        let arr = unsafe { exponent_slice(p) };
        c_int::from(store_keeping_sign(dst, poly_rem(&ad, &arr)))
    })
}

/// The `int` array from `p` up to and including its `0` terminator.
///
/// # Safety
///
/// `p` must be a `0`-terminated `int` array.
unsafe fn exponent_slice(p: *const c_int) -> Vec<c_int> {
    let mut out = Vec::new();
    let mut i = 0isize;
    loop {
        // SAFETY: the caller guarantees the terminator exists, so every index read
        // before it is inside the array.
        let e = unsafe { *p.offset(i) };
        out.push(e);
        if e == 0 {
            return out;
        }
        i += 1;
    }
}

/// `int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p)`
///
/// The fixed-size `arr[6]` bound is the authority's, and exceeding it is the
/// `BN_R_INVALID_LENGTH` failure rather than a larger allocation.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `p` must each be null
/// or live.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod(r: *mut BigNum, a: *const BigNum, p: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null or live per this function's `# Safety` section.
        let arr = match unsafe { to_array(p, FIXED_ARR) } {
            Ok(arr) => arr,
            Err(()) => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_GF2M_389) };
                return 0;
            }
        };
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { BN_GF2m_mod_arr(r, a, arr.as_ptr()) }
    })
}

/// The `poly2arr` conversion the variable-size wrappers perform, with the authority's
/// `max = BN_num_bits(p) + 1` bound.
///
/// # Safety
///
/// `p` must be null or a live `BIGNUM`.
unsafe fn to_array(p: *const BigNum, fixed_max: usize) -> Result<Vec<c_int>, ()> {
    // SAFETY: null-or-live per the caller's contract.
    let (pd, _) = parts(unsafe { as_ref(p) });
    let max = if fixed_max == 0 {
        limbs::bit_len(&pd) + 1
    } else {
        fixed_max
    };
    let mut arr: Vec<c_int> = vec![0; max];
    // SAFETY: `arr` owns `max` writable `c_int`s and `p` is null or live.
    let n = unsafe { BN_GF2m_poly2arr(p, arr.as_mut_ptr(), max as c_int) };
    if n == 0 || n as usize > max {
        return Err(());
    }
    Ok(arr)
}

/// `int BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,`
/// `const int p[], BN_CTX *ctx)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `b` must each be null
/// or live; `p` must be a `0`-terminated exponent array; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_mul_arr(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    p: *const c_int,
    _ctx: *mut BnCtx,
) -> c_int {
    if a == b {
        // SAFETY: `BN_GF2m_mod_sqr_arr`'s contract is this function's contract.
        return unsafe { BN_GF2m_mod_sqr_arr(r, a, p, _ctx) };
    }
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(b)) };
        let (ad, _) = parts(x);
        let (bd, _) = parts(y);
        if p.is_null() {
            return 0;
        }
        // SAFETY: the caller guarantees a `0`-terminated array.
        let arr = unsafe { exponent_slice(p) };
        c_int::from(store_keeping_sign(dst, poly_rem(&clmul(&ad, &bd), &arr)))
    })
}

/// `int BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,`
/// `const BIGNUM *p, BN_CTX *ctx)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a`, `b` and `p` must each be
/// null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_mul(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    p: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null or live per this function's `# Safety` section.
        let arr = match unsafe { to_array(p, 0) } {
            Ok(arr) => arr,
            Err(()) => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_GF2M_472) };
                return 0;
            }
        };
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { BN_GF2m_mod_mul_arr(r, a, b, arr.as_ptr(), ctx) }
    })
}

/// `int BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const int p[], BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_GF2m_mod_mul_arr`, without `b`.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_sqr_arr(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const c_int,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x) = unsafe { (as_mut(r), as_ref(a)) };
        let (ad, _) = parts(x);
        if p.is_null() {
            return 0;
        }
        // SAFETY: the caller guarantees a `0`-terminated array.
        let arr = unsafe { exponent_slice(p) };
        c_int::from(store_keeping_sign(dst, poly_rem(&clmul(&ad, &ad), &arr)))
    })
}

/// `int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `p` must each be null
/// or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_sqr(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null or live per this function's `# Safety` section.
        let arr = match unsafe { to_array(p, 0) } {
            Ok(arr) => arr,
            Err(()) => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_GF2M_532) };
                return 0;
            }
        };
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { BN_GF2m_mod_sqr_arr(r, a, arr.as_ptr(), ctx) }
    })
}

/// `int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,`
/// `const int p[], BN_CTX *ctx)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `b` must each be null
/// or live; `p` must be a `0`-terminated exponent array; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_exp_arr(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    p: *const c_int,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(b)) };
        let (ad, _) = parts(x);
        let (bd, _) = parts(y);
        if p.is_null() {
            return 0;
        }
        // SAFETY: the caller guarantees a `0`-terminated array.
        let arr = unsafe { exponent_slice(p) };
        c_int::from(store_keeping_sign(dst, poly_pow(&ad, &bd, &arr)))
    })
}

/// `int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,`
/// `const BIGNUM *p, BN_CTX *ctx)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a`, `b` and `p` must each be
/// null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_exp(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    p: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null or live per this function's `# Safety` section.
        let arr = match unsafe { to_array(p, 0) } {
            Ok(arr) => arr,
            Err(()) => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_GF2M_915) };
                return 0;
            }
        };
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { BN_GF2m_mod_exp_arr(r, a, b, arr.as_ptr(), ctx) }
    })
}

/// `int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)`
///
/// The authority blinds this inversion; see this module's header for why the value is
/// the same without the blinding and the timing profile is not.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `p` must each be null
/// or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_inv(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(p)) };
        let (ad, _) = parts(x);
        let (pd, _) = parts(y);
        // A modulus of degree at most one has no field to invert in, and the
        // authority fails on it before drawing anything.
        if limbs::bit_len(&pd) <= 1 {
            return 0;
        }
        // SAFETY: `p` is null or live per this function's `# Safety` section.
        let arr = match unsafe { to_array(p, 0) } {
            Ok(arr) => arr,
            Err(()) => {
                // The authority reaches an invalid modulus through
                // `BN_GF2m_mod_mul`, so the coordinate is that function's.
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_GF2M_472) };
                return 0;
            }
        };
        match poly_inv(&ad, &arr) {
            Some(v) => c_int::from(store_keeping_sign(dst, v)),
            None => 0,
        }
    })
}

/// `int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *xx, const int p[], BN_CTX *ctx)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `xx` must be null or live; `p`
/// must be a `0`-terminated exponent array; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_inv_arr(
    r: *mut BigNum,
    xx: *const BigNum,
    p: *const c_int,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is a `-1`-terminated array per this function's contract.
        let field = match unsafe { array_to_bignum(p) } {
            Some(f) => f,
            None => return 0,
        };
        // SAFETY: `field` is live and uniquely owned here.
        let out = unsafe { BN_GF2m_mod_inv(r, xx, field, ctx) };
        // SAFETY: `field` is the object this call allocated.
        unsafe { BN_free(field) };
        out
    })
}

/// The `arr2poly` conversion the `_arr` wrappers perform before delegating.
///
/// # Safety
///
/// `p` must be a `-1`-terminated exponent array.
unsafe fn array_to_bignum(p: *const c_int) -> Option<*mut BigNum> {
    if p.is_null() {
        return None;
    }
    let fresh = new_owned(Vec::new(), 0);
    // SAFETY: `fresh` is live and uniquely owned here; the array contract is the
    // caller's.
    if unsafe { BN_GF2m_arr2poly(p, fresh) } == 0 {
        // SAFETY: `fresh` is the object this call allocated.
        unsafe { BN_free(fresh) };
        return None;
    }
    Some(fresh)
}

/// `int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *y, const BIGNUM *x,`
/// `const BIGNUM *p, BN_CTX *ctx)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `y`, `x` and `p` must each be
/// null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_div(
    r: *mut BigNum,
    y: *const BigNum,
    x: *const BigNum,
    p: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        let xinv = new_owned(Vec::new(), 0);
        // SAFETY: `xinv` is live and uniquely owned here.
        let ok = unsafe { BN_GF2m_mod_inv(xinv, x, p, ctx) };
        if ok == 0 {
            // SAFETY: `xinv` is the object this call allocated.
            unsafe { BN_free(xinv) };
            return 0;
        }
        // SAFETY: `xinv` is live; `BN_GF2m_mod_mul`'s contract is this function's.
        let out = unsafe { BN_GF2m_mod_mul(r, y, xinv, p, ctx) };
        // SAFETY: `xinv` is the object this call allocated.
        unsafe { BN_free(xinv) };
        out
    })
}

/// `int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *yy, const BIGNUM *xx,`
/// `const int p[], BN_CTX *ctx)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `yy` and `xx` must each be
/// null or live; `p` must be a `-1`-terminated exponent array; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_div_arr(
    r: *mut BigNum,
    yy: *const BigNum,
    xx: *const BigNum,
    p: *const c_int,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is a `-1`-terminated array per this function's contract.
        let field = match unsafe { array_to_bignum(p) } {
            Some(f) => f,
            None => return 0,
        };
        // SAFETY: `field` is live; `BN_GF2m_mod_div`'s contract is this function's.
        let out = unsafe { BN_GF2m_mod_div(r, yy, xx, field, ctx) };
        // SAFETY: `field` is the object this call allocated.
        unsafe { BN_free(field) };
        out
    })
}

/// `int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a, const int p[], BN_CTX *ctx)`
///
/// The square root in `GF(2)[x]/(p)` is `a^(2^(m - 1))`, the exponentiation IEEE P1363's
/// A.4.1 names. The Frobenius map `x |-> x^2` is an automorphism of degree `m`, so its
/// inverse is the `m - 1`-fold iterate and every element has exactly one square root.
/// A degree-zero modulus is the authority's `reduction mod 1` arm and answers zero
/// without touching `ctx`.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` must be null or live; `p`
/// must be a `0`-terminated exponent array whose first entry is the degree; `ctx` must be
/// null or a live, uniquely-owned `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_sqrt_arr(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const c_int,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            return 0;
        }
        // SAFETY: the caller guarantees a `0`-terminated array, so this scan stops inside it.
        let arr = unsafe { exponent_slice(p) };
        let m = degree(&arr);
        if m == 0 {
            // Reduction mod 1 answers zero.
            // SAFETY: `r` is null-or-live per this function's `# Safety` section.
            return c_int::from(store_keeping_sign(unsafe { as_mut(r) }, Vec::new()));
        }
        // SAFETY: `ctx` is null-or-live per this function's `# Safety` section.
        unsafe { BN_CTX_start(ctx) };
        let mut ret = 0;
        'body: {
            // SAFETY: `ctx` is null-or-live per this function's `# Safety` section.
            let u = unsafe { BN_CTX_get(ctx) };
            if u.is_null() {
                break 'body;
            }
            // `u = 2^(p[0] - 1)`, the exponent `2^(m - 1)`.
            // SAFETY: `u` is live.
            if unsafe { BN_set_bit(u, m - 1) } == 0 {
                break 'body;
            }
            // SAFETY: every pointer is as this function's `# Safety` section says.
            ret = unsafe { BN_GF2m_mod_exp_arr(r, a, u, p, ctx) };
        }
        // SAFETY: `ctx` is null-or-live.
        unsafe { BN_CTX_end(ctx) };
        ret
    })
}

/// `int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)`
///
/// The `BN_GF2m_poly2arr` conversion, with the authority's `max = BN_num_bits(p) + 1`
/// bound, then `BN_GF2m_mod_sqrt_arr`. A modulus whose constant term is missing is not
/// odd, so `poly2arr` answers `0` and this raises `BN_R_INVALID_LENGTH`.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `p` must each be null or
/// live; `ctx` must be null or a live, uniquely-owned `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_sqrt(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null or live per this function's `# Safety` section.
        let arr = match unsafe { to_array(p, 0) } {
            Ok(arr) => arr,
            Err(()) => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_GF2M_977) };
                return 0;
            }
        };
        // SAFETY: every pointer is as this function's `# Safety` section says.
        unsafe { BN_GF2m_mod_sqrt_arr(r, a, arr.as_ptr(), ctx) }
    })
}

/// `int BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a_, const int p[], BN_CTX *ctx)`
///
/// Answers `z` with `z^2 + z = a (mod p)`, or `0` when no root exists. For odd `m` the
/// root is the half-trace `a + a^4 + ... + a^(2^(m - 1))`, computed directly; for even `m`
/// the authority draws `rho` and accumulates until `w` is non-zero (IEEE P1363's A.4.6),
/// retrying at most [`MAX_ITERATIONS`] times. In both arms the candidate is checked with
/// `z^2 + z == a` and `BN_R_NO_SOLUTION` is raised when the check fails.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a_` must be null or live; `p`
/// must be a `0`-terminated exponent array whose first entry is the degree; `ctx` must be
/// null or a live, uniquely-owned `BN_CTX` (and live when `m` is even, which draws).
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_solve_quad_arr(
    r: *mut BigNum,
    a_: *const BigNum,
    p: *const c_int,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        if p.is_null() {
            return 0;
        }
        // SAFETY: the caller guarantees a `0`-terminated array, so this scan stops inside it.
        let arr = unsafe { exponent_slice(p) };
        let m = degree(&arr);
        if m == 0 {
            // Reduction mod 1 answers zero.
            // SAFETY: `r` is null-or-live per this function's `# Safety` section.
            return c_int::from(store_keeping_sign(unsafe { as_mut(r) }, Vec::new()));
        }
        // SAFETY: `ctx` is null-or-live per this function's `# Safety` section.
        unsafe { BN_CTX_start(ctx) };
        let mut ret = 0;
        'body: {
            // SAFETY: `ctx` is null-or-live per this function's `# Safety` section.
            let a = unsafe { BN_CTX_get(ctx) };
            // SAFETY: `ctx` is null-or-live per this function's `# Safety` section.
            let z = unsafe { BN_CTX_get(ctx) };
            // SAFETY: `ctx` is null-or-live per this function's `# Safety` section.
            let w = unsafe { BN_CTX_get(ctx) };
            // The authority checks only `w`, because `BN_CTX_get` fails from the first
            // request on: an exhausted context hands back NULL for all three.
            if w.is_null() {
                break 'body;
            }
            // SAFETY: every pointer is as this function's `# Safety` section says.
            if unsafe { BN_GF2m_mod_arr(a, a_, p) } == 0 {
                break 'body;
            }
            // SAFETY: `a` is live.
            if unsafe { BN_is_zero(a) } != 0 {
                // SAFETY: `r` is null-or-live.
                unsafe { BN_zero_ex(r) };
                ret = 1;
                break 'body;
            }
            if m & 1 == 1 {
                // `m` is odd: the half-trace of `a`.
                // SAFETY: `z` and `a` are live.
                if unsafe { BN_copy(z, a) }.is_null() {
                    break 'body;
                }
                for _j in 1..=(m - 1) / 2 {
                    // SAFETY: every pointer is as this function's `# Safety` section says.
                    if unsafe { BN_GF2m_mod_sqr_arr(z, z, p, ctx) } == 0 {
                        break 'body;
                    }
                    // SAFETY: every pointer is as this function's `# Safety` section says.
                    if unsafe { BN_GF2m_mod_sqr_arr(z, z, p, ctx) } == 0 {
                        break 'body;
                    }
                    // SAFETY: `z` and `a` are live.
                    if unsafe { BN_GF2m_add(z, z, a) } == 0 {
                        break 'body;
                    }
                }
            } else {
                // `m` is even: draw until `w` is non-zero, then `z` is the candidate.
                // SAFETY: `ctx` is null-or-live per this function's `# Safety` section.
                let rho = unsafe { BN_CTX_get(ctx) };
                // SAFETY: `ctx` is null-or-live per this function's `# Safety` section.
                let w2 = unsafe { BN_CTX_get(ctx) };
                // SAFETY: `ctx` is null-or-live per this function's `# Safety` section.
                let tmp = unsafe { BN_CTX_get(ctx) };
                if tmp.is_null() {
                    break 'body;
                }
                let mut count = 0;
                loop {
                    // SAFETY: every pointer is as this function's `# Safety` section says.
                    if unsafe {
                        BN_priv_rand_ex(rho, m, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, ctx)
                    } == 0
                    {
                        break 'body;
                    }
                    // SAFETY: `rho` is live and `p` is a `0`-terminated array.
                    if unsafe { BN_GF2m_mod_arr(rho, rho, p) } == 0 {
                        break 'body;
                    }
                    // SAFETY: `z` is live.
                    unsafe { BN_zero_ex(z) };
                    // SAFETY: `w` and `rho` are live.
                    if unsafe { BN_copy(w, rho) }.is_null() {
                        break 'body;
                    }
                    for _j in 1..=m - 1 {
                        // SAFETY: every pointer is as this function's `# Safety` section says.
                        if unsafe { BN_GF2m_mod_sqr_arr(z, z, p, ctx) } == 0 {
                            break 'body;
                        }
                        // SAFETY: every pointer is as this function's `# Safety` section says.
                        if unsafe { BN_GF2m_mod_sqr_arr(w2, w, p, ctx) } == 0 {
                            break 'body;
                        }
                        // SAFETY: every pointer is as this function's `# Safety` section says.
                        if unsafe { BN_GF2m_mod_mul_arr(tmp, w2, a, p, ctx) } == 0 {
                            break 'body;
                        }
                        // SAFETY: `z` and `tmp` are live.
                        if unsafe { BN_GF2m_add(z, z, tmp) } == 0 {
                            break 'body;
                        }
                        // SAFETY: `w`, `w2` and `rho` are live.
                        if unsafe { BN_GF2m_add(w, w2, rho) } == 0 {
                            break 'body;
                        }
                    }
                    count += 1;
                    // The authority's `while (BN_is_zero(w) && count < MAX_ITERATIONS)`.
                    // SAFETY: `w` is live.
                    if unsafe { BN_is_zero(w) } == 0 || count >= MAX_ITERATIONS {
                        break;
                    }
                }
                // SAFETY: `w` is live.
                if unsafe { BN_is_zero(w) } != 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&BN_GF2M_1065) };
                    break 'body;
                }
            }
            // `w = z^2 + z`.
            // SAFETY: every pointer is as this function's `# Safety` section says.
            if unsafe { BN_GF2m_mod_sqr_arr(w, z, p, ctx) } == 0 {
                break 'body;
            }
            // SAFETY: `w` and `z` are live.
            if unsafe { BN_GF2m_add(w, z, w) } == 0 {
                break 'body;
            }
            // `BN_GF2m_cmp(w, a)` is `BN_ucmp((w), (a))`; a non-zero answer is no root.
            // SAFETY: `w` and `a` are live.
            if unsafe { BN_ucmp(w, a) } != 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_GF2M_1075) };
                break 'body;
            }
            // SAFETY: `r` and `z` are live.
            if unsafe { BN_copy(r, z) }.is_null() {
                break 'body;
            }
            ret = 1;
        }
        // SAFETY: `ctx` is null-or-live.
        unsafe { BN_CTX_end(ctx) };
        ret
    })
}

/// `int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)`
///
/// The `BN_GF2m_poly2arr` conversion, with the authority's `max = BN_num_bits(p) + 1`
/// bound, then `BN_GF2m_mod_solve_quad_arr`. A modulus whose constant term is missing is
/// not odd, so `poly2arr` answers `0` and this raises `BN_R_INVALID_LENGTH`.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `p` must each be null or
/// live; `ctx` must be null or a live, uniquely-owned `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn BN_GF2m_mod_solve_quad(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `p` is null or live per this function's `# Safety` section.
        let arr = match unsafe { to_array(p, 0) } {
            Ok(arr) => arr,
            Err(()) => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_GF2M_1111) };
                return 0;
            }
        };
        // SAFETY: every pointer is as this function's `# Safety` section says.
        unsafe { BN_GF2m_mod_solve_quad_arr(r, a, arr.as_ptr(), ctx) }
    })
}

// =============================================================================================
// Tests — the defining relations and the refusals.
//
// A field element is never printed: the sqrt arm asserts `y^2 == a (mod f)` and the quadratic
// arm asserts `z^2 + z == a (mod f)`, the relations IEEE P1363's A.4.1 and A.4.7 name, against
// committed fields. The even-degree solve draws, so its *value* is not an assertion anywhere;
// the odd-degree arm's root is the half-trace and therefore deterministic, but the same
// relation is what is checked so the two arms are observed the same way.
// =============================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_ulong;

    use crate::bn::bignum::{BN_hex2bn, BN_new, BN_set_word};
    use crate::bn::ctx::BN_CTX_new;
    use crate::runtime::err::{err_sites, ERR_clear_error, ERR_peek_error};

    /// The packed code `ERR_peek_error` reports for a recorded site:
    /// `(lib & 0xff) << 23 | (reason & 0x7fffff`, read from the generated table.
    fn packed(site: &err_sites::ErrSite) -> c_ulong {
        (((site.lib as c_ulong) & 0xff) << 23) | ((site.reason as c_ulong) & 0x7f_ffff)
    }

    /// A `BIGNUM` holding a machine word.
    fn word(w: c_ulong) -> *mut BigNum {
        // SAFETY: `BN_new` takes no pointers.
        let b = unsafe { BN_new() };
        // SAFETY: `b` is live.
        unsafe { BN_set_word(b, w) };
        b
    }

    /// A `BIGNUM` from a hex string.
    fn hex(s: &str) -> *mut BigNum {
        let c = crate::bn::bignum::dup_cstring(s);
        let mut p: *mut BigNum = core::ptr::null_mut();
        // SAFETY: `p` is this frame's slot and `c` is NUL-terminated and live.
        unsafe {
            assert!(BN_hex2bn(&mut p, c) > 0);
            crate::runtime::mem::CRYPTO_free(c.cast(), core::ptr::null(), 0);
        }
        p
    }

    /// The polynomial an exponent array names, as a `BIGNUM` (every listed exponent set).
    fn field(exps: &[c_int]) -> *mut BigNum {
        // SAFETY: `BN_new` takes no pointers.
        let b = unsafe { BN_new() };
        for &e in exps {
            // SAFETY: `b` is live and `e` is an exponent.
            unsafe { BN_set_bit(b, e) };
        }
        b
    }

    /// `a mod p`, reduced.
    fn reduce(a: *const BigNum, p: *const c_int) -> *mut BigNum {
        // SAFETY: `BN_new` takes no pointers.
        let out = unsafe { BN_new() };
        // SAFETY: every pointer is live and `p` is a `0`-terminated array.
        assert_eq!(unsafe { BN_GF2m_mod_arr(out, a, p) }, 1);
        out
    }

    /// `(y^2 + y) mod p`, or `y^2 mod p` when `plus_y` is false — the left side of the
    /// quadratic and square-root relations.
    fn left(y: *const BigNum, p: *const c_int, ctx: *mut BnCtx, plus_y: bool) -> *mut BigNum {
        // SAFETY: `BN_new` takes no pointers.
        let s = unsafe { BN_new() };
        // SAFETY: every pointer is live and `p` is a `0`-terminated array.
        assert_eq!(unsafe { BN_GF2m_mod_sqr_arr(s, y, p, ctx) }, 1);
        if plus_y {
            // SAFETY: `s` and `y` are live.
            assert_eq!(unsafe { BN_GF2m_add(s, s, y) }, 1);
        }
        s
    }

    /// `x^163 + x^7 + x^6 + x^3 + 1` — an irreducible odd-degree binary field.
    const F163: [c_int; 5] = [163, 7, 6, 3, 0];
    /// `x^8 + x^4 + x^3 + x + 1` — the AES field, even degree.
    const F8: [c_int; 5] = [8, 4, 3, 1, 0];
    /// `x^6 + x^5 + x^4 + x^3 + x^2 + x + 1 = (x^3 + x + 1)(x^3 + x^2 + 1)`: reducible, and
    /// its absolute trace vanishes identically, so the even-degree retry loop never sees a
    /// non-zero `w` and reaches its ceiling.
    const F6_REDUCIBLE: [c_int; 7] = [6, 5, 4, 3, 2, 1, 0];

    #[test]
    fn the_square_root_satisfies_its_defining_relation() {
        // SAFETY: `BN_CTX_new` takes no pointers.
        let ctx = unsafe { BN_CTX_new() };
        for a in [
            hex("1ABCDEF0123456789ABCDEF0123456789ABCDEF"),
            word(3),
            word(1),
            word(0),
        ] {
            // SAFETY: `BN_new` takes no pointers.
            let y = unsafe { BN_new() };
            ERR_clear_error();
            // SAFETY: every argument is a live object and `F163` is a `0`-terminated array.
            assert_eq!(unsafe { BN_GF2m_mod_sqrt_arr(y, a, F163.as_ptr(), ctx) }, 1);
            assert_eq!(ERR_peek_error(), 0, "the square root raised nothing");
            // SAFETY: every pointer is live.
            let rel =
                unsafe { BN_ucmp(left(y, F163.as_ptr(), ctx, false), reduce(a, F163.as_ptr())) };
            assert_eq!(rel, 0, "y^2 == a mod f");
        }

        // The even-degree field, through the `BN_GF2m_poly2arr` wrapper.
        let p8 = field(&F8);
        let a = hex("57");
        // SAFETY: `BN_new` takes no pointers.
        let y = unsafe { BN_new() };
        ERR_clear_error();
        // SAFETY: every argument is live.
        assert_eq!(unsafe { BN_GF2m_mod_sqrt(y, a, p8, ctx) }, 1);
        assert_eq!(ERR_peek_error(), 0);
        // SAFETY: every pointer is live.
        let rel = unsafe { BN_ucmp(left(y, F8.as_ptr(), ctx, false), reduce(a, F8.as_ptr())) };
        assert_eq!(rel, 0);
    }

    #[test]
    fn the_quadratic_solve_finds_a_root_or_refuses() {
        // SAFETY: `BN_CTX_new` takes no pointers.
        let ctx = unsafe { BN_CTX_new() };
        // SAFETY: `BN_new` takes no pointers.
        let z = unsafe { BN_new() };
        let one = word(1);

        // Odd `m`: `a = x^2 + x` for `x = 2` has `6` as a root on both sides; the half-trace
        // makes the value deterministic, and the relation is what is asserted.
        let a = word(6);
        ERR_clear_error();
        // SAFETY: every argument is live and `F163` is a `0`-terminated array.
        let ret = unsafe { BN_GF2m_mod_solve_quad_arr(z, a, F163.as_ptr(), ctx) };
        assert_eq!(ret, 1);
        assert_eq!(ERR_peek_error(), 0);
        // SAFETY: every pointer is live.
        let rel = unsafe { BN_ucmp(left(z, F163.as_ptr(), ctx, true), reduce(a, F163.as_ptr())) };
        assert_eq!(rel, 0, "z^2 + z == a mod f");

        // Odd `m` and `a = 1`: `trace(1) = m mod 2 = 1`, so no root exists and the half-trace
        // check raises `BN_R_NO_SOLUTION`.
        ERR_clear_error();
        // SAFETY: every argument is live and `F163` is a `0`-terminated array.
        let ret = unsafe { BN_GF2m_mod_solve_quad_arr(z, one, F163.as_ptr(), ctx) };
        assert_eq!(ret, 0);
        assert_eq!(ERR_peek_error(), packed(&err_sites::BN_GF2M_1075));

        // Even `m`: the root is a draw, so the relation is the observation.
        for a in [word(1), word(6)] {
            ERR_clear_error();
            // SAFETY: every argument is live and `F8` is a `0`-terminated array.
            let ret = unsafe { BN_GF2m_mod_solve_quad_arr(z, a, F8.as_ptr(), ctx) };
            assert_eq!(ret, 1);
            assert_eq!(ERR_peek_error(), 0);
            // SAFETY: every pointer is live.
            let rel = unsafe { BN_ucmp(left(z, F8.as_ptr(), ctx, true), reduce(a, F8.as_ptr())) };
            assert_eq!(rel, 0, "z^2 + z == a mod f");
        }

        // Even `m` on a reducible modulus whose trace vanishes: the retry ceiling is reached.
        ERR_clear_error();
        // SAFETY: every argument is live and `F6_REDUCIBLE` is a `0`-terminated array.
        let ret = unsafe { BN_GF2m_mod_solve_quad_arr(z, one, F6_REDUCIBLE.as_ptr(), ctx) };
        assert_eq!(ret, 0);
        assert_eq!(ERR_peek_error(), packed(&err_sites::BN_GF2M_1065));

        // `a == 0` answers zero without a draw.
        let zero = word(0);
        ERR_clear_error();
        // SAFETY: every argument is live and `F163` is a `0`-terminated array.
        let ret = unsafe { BN_GF2m_mod_solve_quad_arr(z, zero, F163.as_ptr(), ctx) };
        assert_eq!(ret, 1);
        // SAFETY: `z` is live.
        assert_eq!(unsafe { BN_is_zero(z) }, 1);
        assert_eq!(ERR_peek_error(), 0);
    }

    #[test]
    fn the_wrappers_convert_the_modulus_and_refuse_a_non_odd_one() {
        // SAFETY: `BN_CTX_new` takes no pointers.
        let ctx = unsafe { BN_CTX_new() };
        let p163 = field(&F163);
        let a = word(3);
        // SAFETY: `BN_new` takes no pointers.
        let out = unsafe { BN_new() };
        ERR_clear_error();
        // SAFETY: every argument is live.
        assert_eq!(unsafe { BN_GF2m_mod_sqrt(out, a, p163, ctx) }, 1);
        assert_eq!(ERR_peek_error(), 0);
        // SAFETY: every pointer is live.
        let rel = unsafe {
            BN_ucmp(
                left(out, F163.as_ptr(), ctx, false),
                reduce(a, F163.as_ptr()),
            )
        };
        assert_eq!(rel, 0, "the wrapper's y^2 == a mod f");

        let six = word(6);
        ERR_clear_error();
        // SAFETY: every argument is live.
        assert_eq!(unsafe { BN_GF2m_mod_solve_quad(out, six, p163, ctx) }, 1);
        assert_eq!(ERR_peek_error(), 0);
        // SAFETY: every pointer is live.
        let rel = unsafe {
            BN_ucmp(
                left(out, F163.as_ptr(), ctx, true),
                reduce(six, F163.as_ptr()),
            )
        };
        assert_eq!(rel, 0, "the wrapper's z^2 + z == a mod f");

        // A modulus whose constant term is missing is not odd, so `BN_GF2m_poly2arr` answers
        // `0` and the wrapper raises `BN_R_INVALID_LENGTH` at its own site.
        // SAFETY: `BN_new` takes no pointers.
        let peven = unsafe { BN_new() };
        // SAFETY: `peven` is live.
        unsafe { BN_set_bit(peven, 8) };
        // SAFETY: `peven` is live.
        unsafe { BN_set_bit(peven, 4) };
        ERR_clear_error();
        // SAFETY: every argument is live.
        assert_eq!(unsafe { BN_GF2m_mod_sqrt(out, a, peven, ctx) }, 0);
        assert_eq!(ERR_peek_error(), packed(&err_sites::BN_GF2M_977));
        ERR_clear_error();
        // SAFETY: every argument is live.
        assert_eq!(unsafe { BN_GF2m_mod_solve_quad(out, a, peven, ctx) }, 0);
        assert_eq!(ERR_peek_error(), packed(&err_sites::BN_GF2M_1111));
    }

    #[test]
    fn a_degree_zero_modulus_answers_zero() {
        // SAFETY: `BN_CTX_new` takes no pointers.
        let ctx = unsafe { BN_CTX_new() };
        let zero_arr: [c_int; 2] = [0, 0];
        let a = word(7);
        // SAFETY: `BN_new` takes no pointers.
        let out = unsafe { BN_new() };
        for solve_quad in [false, true] {
            // SAFETY: `out` is live.
            unsafe { BN_set_word(out, 0x77) };
            ERR_clear_error();
            // SAFETY: every argument is live and `zero_arr` is `0`-terminated.
            let ret = unsafe {
                if solve_quad {
                    BN_GF2m_mod_solve_quad_arr(out, a, zero_arr.as_ptr(), ctx)
                } else {
                    BN_GF2m_mod_sqrt_arr(out, a, zero_arr.as_ptr(), ctx)
                }
            };
            assert_eq!(ret, 1, "solve_quad={solve_quad}");
            // SAFETY: `out` is live.
            assert_eq!(unsafe { BN_is_zero(out) }, 1, "solve_quad={solve_quad}");
            assert_eq!(ERR_peek_error(), 0);
        }
    }
}
