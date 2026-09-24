//! `crypto/ml_dsa/ml_dsa_poly.h`, `ml_dsa_vector.h` and `ml_dsa_matrix.h` — the polynomial,
//! vector and matrix objects and their `static ossl_inline` bodies.
//!
//! These three headers are not translation units: they are the inlines every ML-DSA unit includes,
//! so their functions are not part of the exported surface and have no owning phase of their own.
//! They are transcribed whole here, with each body's coordinate recorded, because the call graph
//! the authority's own compiler sees is this one and the four units that follow (`ntt.rs`,
//! `key_compress.rs`, `sample.rs`, and the encoders) are written against it.
//!
//! ## `Vector` and `Matrix` carry the C's own shape
//!
//! `ml_dsa_vector.h:14-17` is `{ POLY *poly; size_t num_poly; }` and `ml_dsa_matrix.h:11-14` is
//! `{ POLY *m_poly; size_t k, l; }`. Both are reproduced `#[repr(C)]` with raw pointers, because
//! the key's `s1`/`s2`/`t0` vectors share one allocation and are recovered by pointer arithmetic
//! (`ml_dsa_key.h:55`), which only a real pointer models.
//!
//! ## The allocation macros are the caller's `__FILE__`/`__LINE__`
//!
//! `OPENSSL_malloc_array`, `OPENSSL_secure_malloc_array`, `OPENSSL_free` and
//! `OPENSSL_secure_clear_free` are macros, so an expansion reports the *call site's* coordinates,
//! not the header's. The allocation helpers here therefore take `file`/`line` as parameters and
//! every caller passes its own, exactly as `ml_kem/key.rs` does.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::evp::digest::{EvpMd, EvpMdCtx};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memcmp};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_malloc};

use super::key_compress::{
    ossl_ml_dsa_key_compress_high_bits, ossl_ml_dsa_key_compress_low_bits,
    ossl_ml_dsa_key_compress_make_hint, ossl_ml_dsa_key_compress_power2_round,
    ossl_ml_dsa_key_compress_use_hint,
};
use super::ntt::ossl_ml_dsa_poly_ntt;
use super::sample::{
    ossl_ml_dsa_matrix_expand_A, ossl_ml_dsa_poly_expand_mask, ossl_ml_dsa_poly_sample_in_ball,
    ossl_ml_dsa_vector_expand_S,
};
use super::{
    abs_mod_prime, abs_signed, maximum, mod_sub, reduce_once, ML_DSA_D_BITS,
    ML_DSA_NUM_POLY_COEFFICIENTS, ML_DSA_Q, ML_DSA_RHO_PRIME_BYTES,
};

/// `struct poly_st` — `ml_dsa_poly.h:14-16`, 256 unsigned 32-bit coefficients.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Poly {
    /// `uint32_t coeff[ML_DSA_NUM_POLY_COEFFICIENTS]`.
    pub(crate) coeff: [u32; ML_DSA_NUM_POLY_COEFFICIENTS],
}

/// `struct vector_st` — `ml_dsa_vector.h:14-17`.
#[repr(C)]
pub(crate) struct Vector {
    /// `POLY *poly` — borrowed or owned, depending on how the vector was made.
    pub(crate) poly: *mut Poly,
    /// `size_t num_poly` — `k` or `l`.
    pub(crate) num_poly: usize,
}

/// `struct matrix_st` — `ml_dsa_matrix.h:11-14`, a `k` by `l` matrix.
#[repr(C)]
pub(crate) struct Matrix {
    /// `POLY *m_poly` — `k * l` polynomials.
    pub(crate) m_poly: *mut Poly,
    /// `size_t k` — the number of rows.
    pub(crate) k: usize,
    /// `size_t l` — the number of columns.
    pub(crate) l: usize,
}

// ---------------------------------------------------------------------------
// `ml_dsa_poly.h`
// ---------------------------------------------------------------------------

/// `poly_zero(p)` — `ml_dsa_poly.h:18-22`.
pub(crate) fn poly_zero(p: &mut Poly) {
    p.coeff = [0u32; ML_DSA_NUM_POLY_COEFFICIENTS];
}

/// `poly_add(lhs, rhs, out)` — `ml_dsa_poly.h:33-40`.
pub(crate) fn poly_add(lhs: &Poly, rhs: &Poly, out: &mut Poly) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        out.coeff[i] = reduce_once(lhs.coeff[i].wrapping_add(rhs.coeff[i]));
    }
}

/// `poly_sub(lhs, rhs, out)` — `ml_dsa_poly.h:51-58`.
pub(crate) fn poly_sub(lhs: &Poly, rhs: &Poly, out: &mut Poly) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        out.coeff[i] = mod_sub(lhs.coeff[i], rhs.coeff[i]);
    }
}

/// `poly_equal(a, b)` — `ml_dsa_poly.h:61-65`, `CRYPTO_memcmp(a, b, sizeof(*a)) == 0`.
pub(crate) fn poly_equal(a: &Poly, b: &Poly) -> c_int {
    // SAFETY: both references are valid for `size_of::<Poly>()` bytes.
    let rv = unsafe {
        CRYPTO_memcmp(
            ptr::from_ref(a).cast(),
            ptr::from_ref(b).cast(),
            core::mem::size_of::<Poly>(),
        )
    };
    (rv == 0) as c_int
}

/// `poly_ntt(p)` — `ml_dsa_poly.h:67-71`, in place.
pub(crate) fn poly_ntt(p: &mut Poly) {
    ossl_ml_dsa_poly_ntt(p);
}

/// `poly_power2_round(t, t1, t0)` — `ml_dsa_poly.h:101-109`.
pub(crate) fn poly_power2_round(t: &Poly, t1: &mut Poly, t0: &mut Poly) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        let (r1, r0) = ossl_ml_dsa_key_compress_power2_round(t.coeff[i]);
        t1.coeff[i] = r1;
        t0.coeff[i] = r0;
    }
}

/// `poly_scale_power2_round(in, out)` — `ml_dsa_poly.h:111-118`, `out[i] = in[i] << D_BITS`.
pub(crate) fn poly_scale_power2_round(input: &Poly, out: &mut Poly) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        out.coeff[i] = input.coeff[i] << ML_DSA_D_BITS;
    }
}

/// `poly_high_bits(in, gamma2, out)` — `ml_dsa_poly.h:120-127`.
pub(crate) fn poly_high_bits(input: &Poly, gamma2: u32, out: &mut Poly) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        out.coeff[i] = ossl_ml_dsa_key_compress_high_bits(input.coeff[i], gamma2);
    }
}

/// `poly_low_bits(in, gamma2, out)` — `ml_dsa_poly.h:129-136`.
pub(crate) fn poly_low_bits(input: &Poly, gamma2: u32, out: &mut Poly) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        out.coeff[i] = ossl_ml_dsa_key_compress_low_bits(input.coeff[i], gamma2) as u32;
    }
}

/// `poly_make_hint(ct0, cs2, w, gamma2, out)` — `ml_dsa_poly.h:138-148`.
pub(crate) fn poly_make_hint(ct0: &Poly, cs2: &Poly, w: &Poly, gamma2: u32, out: &mut Poly) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        out.coeff[i] =
            ossl_ml_dsa_key_compress_make_hint(ct0.coeff[i], cs2.coeff[i], gamma2, w.coeff[i])
                as u32;
    }
}

/// `poly_use_hint(h, r, gamma2, out)` — `ml_dsa_poly.h:150-158`.
pub(crate) fn poly_use_hint(h: &Poly, r: &Poly, gamma2: u32, out: &mut Poly) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        out.coeff[i] = ossl_ml_dsa_key_compress_use_hint(h.coeff[i], r.coeff[i], gamma2);
    }
}

/// `poly_max(p, mx)` — `ml_dsa_poly.h:160-171`, folds the maximum `abs_mod_prime` into `*mx`.
pub(crate) fn poly_max(p: &Poly, mx: &mut u32) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        let abs = abs_mod_prime(p.coeff[i]);
        *mx = maximum(*mx, abs);
    }
}

/// `poly_max_signed(p, mx)` — `ml_dsa_poly.h:173-184`, folds the maximum `abs_signed` into `*mx`.
pub(crate) fn poly_max_signed(p: &Poly, mx: &mut u32) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        let abs = abs_signed(p.coeff[i]);
        *mx = maximum(*mx, abs);
    }
}

// ---------------------------------------------------------------------------
// `ml_dsa_vector.h`
// ---------------------------------------------------------------------------

impl Vector {
    /// The all-NULL vector, for `#[repr(C)]` struct initialisation before `init`/`alloc`.
    pub(crate) const fn empty() -> Vector {
        Vector {
            poly: ptr::null_mut(),
            num_poly: 0,
        }
    }

    /// `vector_init(v, polys, num_polys)` — `ml_dsa_vector.h:27-31`. `|v|` does not own `polys`.
    pub(crate) fn init(polys: *mut Poly, num_polys: usize) -> Vector {
        Vector {
            poly: polys,
            num_poly: num_polys,
        }
    }

    /// `vector_alloc(v, num_polys)` — `ml_dsa_vector.h:33-40`, `OPENSSL_malloc_array`.
    ///
    /// Returns 1 on success and 0 on allocation failure, as the C does.
    ///
    /// # Safety
    /// `file` must be a NUL-terminated C string.
    pub(crate) unsafe fn alloc(
        &mut self,
        num_polys: usize,
        file: *const c_char,
        line: c_int,
    ) -> c_int {
        // SAFETY: `CRYPTO_malloc` answers NULL on failure, which is checked.
        let p = CRYPTO_malloc(num_polys * core::mem::size_of::<Poly>(), file, line).cast::<Poly>();
        if p.is_null() {
            return 0;
        }
        self.poly = p;
        self.num_poly = num_polys;
        1
    }

    /// `vector_secure_alloc(v, num_polys)` — `ml_dsa_vector.h:42-49`, `OPENSSL_secure_malloc_array`.
    ///
    /// # Safety
    /// `file` must be a NUL-terminated C string.
    pub(crate) unsafe fn secure_alloc(
        &mut self,
        num_polys: usize,
        file: *const c_char,
        line: c_int,
    ) -> c_int {
        // SAFETY: `CRYPTO_secure_malloc` answers NULL on failure, which is checked.
        let p =
            unsafe { CRYPTO_secure_malloc(num_polys * core::mem::size_of::<Poly>(), file, line) }
                .cast::<Poly>();
        if p.is_null() {
            return 0;
        }
        self.poly = p;
        self.num_poly = num_polys;
        1
    }

    /// `vector_free(v)` — `ml_dsa_vector.h:51-56`.
    ///
    /// # Safety
    /// `file` must be a NUL-terminated C string, and the block must have come from
    /// [`Vector::alloc`].
    pub(crate) unsafe fn free(&mut self, file: *const c_char, line: c_int) {
        // SAFETY: the contract says the block came from `CRYPTO_malloc`.
        unsafe { CRYPTO_free(self.poly.cast(), file, line) };
        self.poly = ptr::null_mut();
        self.num_poly = 0;
    }

    /// `vector_secure_free(v, rank)` — `ml_dsa_vector.h:58-63`, `OPENSSL_secure_clear_free`.
    ///
    /// # Safety
    /// `file` must be a NUL-terminated C string, and the block must have come from
    /// [`Vector::secure_alloc`].
    pub(crate) unsafe fn secure_free(&mut self, rank: usize, file: *const c_char, line: c_int) {
        // SAFETY: the contract says the block came from `CRYPTO_secure_malloc`.
        unsafe {
            CRYPTO_secure_clear_free(
                self.poly.cast(),
                rank * core::mem::size_of::<Poly>(),
                file,
                line,
            )
        };
        self.poly = ptr::null_mut();
        self.num_poly = 0;
    }

    /// `vector_zero(va)` — `ml_dsa_vector.h:66-70`.
    pub(crate) fn zero(&mut self) {
        if !self.poly.is_null() {
            // SAFETY: the NULL check above means `poly` names `num_poly` polynomials.
            unsafe { ptr::write_bytes(self.poly, 0, self.num_poly) };
        }
    }

    /// The `num_poly` polynomials this vector names.
    ///
    /// # Safety
    /// `poly` must name at least `num_poly` initialised polynomials.
    pub(crate) unsafe fn as_slice(&self) -> &[Poly] {
        // SAFETY: the contract says `poly` names `num_poly` polynomials.
        unsafe { core::slice::from_raw_parts(self.poly, self.num_poly) }
    }

    /// The same, mutably.
    ///
    /// # Safety
    /// `poly` must name at least `num_poly` initialised polynomials, and no other reference may
    /// alias them for the borrow's lifetime.
    pub(crate) unsafe fn as_mut_slice(&mut self) -> &mut [Poly] {
        // SAFETY: the contract says `poly` names `num_poly` polynomials.
        unsafe { core::slice::from_raw_parts_mut(self.poly, self.num_poly) }
    }
}

/// `vector_copy(dst, src)` — `ml_dsa_vector.h:76-81`. `|dst|` must already be initialised.
///
/// # Safety
/// Both vectors must name `num_poly` initialised polynomials, and they must not alias.
pub(crate) unsafe fn vector_copy(dst: &mut Vector, src: &Vector) {
    debug_assert_eq!(dst.num_poly, src.num_poly);
    // SAFETY: the contract says both name `num_poly` polynomials and do not alias.
    unsafe {
        ptr::copy_nonoverlapping(src.poly, dst.poly, src.num_poly);
    }
}

/// `vector_equal(a, b)` — `ml_dsa_vector.h:84-96`.
///
/// # Safety
/// Both vectors must name `num_poly` initialised polynomials.
pub(crate) unsafe fn vector_equal(a: &Vector, b: &Vector) -> c_int {
    if a.num_poly != b.num_poly {
        return 0;
    }
    // SAFETY: the contract says both name `num_poly` polynomials.
    let (sa, sb) = unsafe { (a.as_slice(), b.as_slice()) };
    for (pa, pb) in sa.iter().zip(sb.iter()) {
        if poly_equal(pa, pb) == 0 {
            return 0;
        }
    }
    1
}

/// `vector_add(lhs, rhs, out)` — `ml_dsa_vector.h:99-106`.
///
/// # Safety
/// All three must name `lhs.num_poly` initialised polynomials; `out` must not alias `lhs`/`rhs`.
pub(crate) unsafe fn vector_add(lhs: &Vector, rhs: &Vector, out: &mut Vector) {
    // SAFETY: the contract says all three name the same count, and `out` does not alias.
    let (sl, sr, so) = unsafe { (lhs.as_slice(), rhs.as_slice(), out.as_mut_slice()) };
    for i in 0..lhs.num_poly {
        poly_add(&sl[i], &sr[i], &mut so[i]);
    }
}

/// `vector_sub(lhs, rhs, out)` — `ml_dsa_vector.h:109-116`.
///
/// # Safety
/// All three must name `lhs.num_poly` initialised polynomials; `out` must not alias `lhs`/`rhs`.
pub(crate) unsafe fn vector_sub(lhs: &Vector, rhs: &Vector, out: &mut Vector) {
    // SAFETY: the contract says all three name the same count, and `out` does not alias.
    let (sl, sr, so) = unsafe { (lhs.as_slice(), rhs.as_slice(), out.as_mut_slice()) };
    for i in 0..lhs.num_poly {
        poly_sub(&sl[i], &sr[i], &mut so[i]);
    }
}

/// `vector_ntt(va)` — `ml_dsa_vector.h:119-126`.
///
/// # Safety
/// `va` must name `num_poly` initialised polynomials.
pub(crate) unsafe fn vector_ntt(va: &mut Vector) {
    // SAFETY: the contract says `poly` names `num_poly` polynomials.
    for p in unsafe { va.as_mut_slice() } {
        ossl_ml_dsa_poly_ntt(p);
    }
}

/// `vector_ntt_inverse(va)` — `ml_dsa_vector.h:129-136`.
///
/// # Safety
/// `va` must name `num_poly` initialised polynomials.
pub(crate) unsafe fn vector_ntt_inverse(va: &mut Vector) {
    // SAFETY: the contract says `poly` names `num_poly` polynomials.
    for p in unsafe { va.as_mut_slice() } {
        super::ntt::ossl_ml_dsa_poly_ntt_inverse(p);
    }
}

/// `vector_mult_scalar(lhs, rhs, out)` — `ml_dsa_vector.h:139-146`.
///
/// # Safety
/// All three must name `lhs.num_poly` initialised polynomials; `out` must not alias `lhs`.
pub(crate) unsafe fn vector_mult_scalar(lhs: &Vector, rhs: &Poly, out: &mut Vector) {
    // SAFETY: the contract says all three name the same count, and `out` does not alias `lhs`.
    let (sl, so) = unsafe { (lhs.as_slice(), out.as_mut_slice()) };
    for i in 0..lhs.num_poly {
        super::ntt::ossl_ml_dsa_poly_ntt_mult(&sl[i], rhs, &mut so[i]);
    }
}

/// `vector_scale_power2_round_ntt(in, out)` — `ml_dsa_vector.h:177-185`.
///
/// # Safety
/// Both must name `in.num_poly` initialised polynomials; `out` must not alias `in`.
pub(crate) unsafe fn vector_scale_power2_round_ntt(input: &Vector, out: &mut Vector) {
    // SAFETY: the contract says both name the same count, and `out` does not alias `in`.
    let (si, so) = unsafe { (input.as_slice(), out.as_mut_slice()) };
    for i in 0..input.num_poly {
        poly_scale_power2_round(&si[i], &mut so[i]);
    }
    // SAFETY: `out` still names its polynomials; `poly_scale_power2_round` did not move them.
    unsafe { vector_ntt(out) };
}

/// `vector_power2_round(t, t1, t0)` — `ml_dsa_vector.h:192-199`.
///
/// # Safety
/// All three must name `t.num_poly` initialised polynomials; `t1`/`t0` must not alias `t`.
pub(crate) unsafe fn vector_power2_round(t: &Vector, t1: &mut Vector, t0: &mut Vector) {
    // SAFETY: the contract says all three name the same count and do not alias.
    let (st, s1, s0) = unsafe { (t.as_slice(), t1.as_mut_slice(), t0.as_mut_slice()) };
    for i in 0..t.num_poly {
        poly_power2_round(&st[i], &mut s1[i], &mut s0[i]);
    }
}

/// `vector_high_bits(in, gamma2, out)` — `ml_dsa_vector.h:201-208`.
///
/// # Safety
/// Both must name `out.num_poly` initialised polynomials; `out` must not alias `in`.
pub(crate) unsafe fn vector_high_bits(input: &Vector, gamma2: u32, out: &mut Vector) {
    let n = out.num_poly;
    // SAFETY: the contract says both name the same count and do not alias.
    let (si, so) = unsafe { (input.as_slice(), out.as_mut_slice()) };
    for i in 0..n {
        poly_high_bits(&si[i], gamma2, &mut so[i]);
    }
}

/// `vector_low_bits(in, gamma2, out)` — `ml_dsa_vector.h:210-217`.
///
/// # Safety
/// Both must name `out.num_poly` initialised polynomials; `out` must not alias `in`.
pub(crate) unsafe fn vector_low_bits(input: &Vector, gamma2: u32, out: &mut Vector) {
    let n = out.num_poly;
    // SAFETY: the contract says both name the same count and do not alias.
    let (si, so) = unsafe { (input.as_slice(), out.as_mut_slice()) };
    for i in 0..n {
        poly_low_bits(&si[i], gamma2, &mut so[i]);
    }
}

/// `vector_max(v)` — `ml_dsa_vector.h:219-228`.
///
/// # Safety
/// `v` must name `num_poly` initialised polynomials.
pub(crate) unsafe fn vector_max(v: &Vector) -> u32 {
    let mut mx = 0u32;
    // SAFETY: the contract says `v` names `num_poly` polynomials.
    for p in unsafe { v.as_slice() } {
        poly_max(p, &mut mx);
    }
    mx
}

/// `vector_max_signed(v)` — `ml_dsa_vector.h:230-239`.
///
/// # Safety
/// `v` must name `num_poly` initialised polynomials.
pub(crate) unsafe fn vector_max_signed(v: &Vector) -> u32 {
    let mut mx = 0u32;
    // SAFETY: the contract says `v` names `num_poly` polynomials.
    for p in unsafe { v.as_slice() } {
        poly_max_signed(p, &mut mx);
    }
    mx
}

/// `vector_count_ones(v)` — `ml_dsa_vector.h:241-251`.
///
/// # Safety
/// `v` must name `num_poly` initialised polynomials.
pub(crate) unsafe fn vector_count_ones(v: &Vector) -> usize {
    let mut count = 0usize;
    // SAFETY: the contract says `v` names `num_poly` polynomials.
    for p in unsafe { v.as_slice() } {
        for j in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
            count += p.coeff[j] as usize;
        }
    }
    count
}

/// `vector_make_hint(ct0, cs2, w, gamma2, out)` — `ml_dsa_vector.h:253-262`.
///
/// # Safety
/// All four must name `out.num_poly` initialised polynomials; `out` must not alias the inputs.
pub(crate) unsafe fn vector_make_hint(
    ct0: &Vector,
    cs2: &Vector,
    w: &Vector,
    gamma2: u32,
    out: &mut Vector,
) {
    let n = out.num_poly;
    // SAFETY: the contract says all four name the same count and `out` does not alias.
    let (a, b, c, o) = unsafe {
        (
            ct0.as_slice(),
            cs2.as_slice(),
            w.as_slice(),
            out.as_mut_slice(),
        )
    };
    for i in 0..n {
        poly_make_hint(&a[i], &b[i], &c[i], gamma2, &mut o[i]);
    }
}

/// `vector_use_hint(h, r, gamma2, out)` — `ml_dsa_vector.h:264-271`.
///
/// # Safety
/// All three must name `out.num_poly` initialised polynomials; `out` must not alias the inputs.
pub(crate) unsafe fn vector_use_hint(h: &Vector, r: &Vector, gamma2: u32, out: &mut Vector) {
    let n = out.num_poly;
    // SAFETY: the contract says all three name the same count and `out` does not alias.
    let (sh, sr, so) = unsafe { (h.as_slice(), r.as_slice(), out.as_mut_slice()) };
    for i in 0..n {
        poly_use_hint(&sh[i], &sr[i], gamma2, &mut so[i]);
    }
}

// ---------------------------------------------------------------------------
// `ml_dsa_matrix.h`
// ---------------------------------------------------------------------------

/// `matrix_init(m, polys, k, l)` — `ml_dsa_matrix.h:25-31`. `|m|` does not own `polys`.
pub(crate) fn matrix_init(polys: *mut Poly, k: usize, l: usize) -> Matrix {
    Matrix {
        m_poly: polys,
        k,
        l,
    }
}

/// The `k * l` polynomials this matrix names.
///
/// # Safety
/// `m_poly` must name at least `k * l` initialised polynomials.
pub(crate) unsafe fn matrix_as_slice(m: &Matrix) -> &[Poly] {
    // SAFETY: the contract says `m_poly` names `k * l` polynomials.
    unsafe { core::slice::from_raw_parts(m.m_poly, m.k * m.l) }
}

/// `matrix_mult_vector(a, s, t)` — `ml_dsa_matrix.h:33-37`, `ml_dsa_matrix.c:24-41`.
///
/// # Safety
/// `a` must name `a.k * a.l` polynomials, `s` must name `a.l` polynomials and `t` must name `a.k`
/// polynomials, all initialised; `t` must not alias `s`.
pub(crate) unsafe fn matrix_mult_vector(a: &Matrix, s: &Vector, t: &mut Vector) {
    // SAFETY: the contract is this function's own; it is forwarded unchanged.
    unsafe { super::ntt::ossl_ml_dsa_matrix_mult_vector(a, s, t) };
}

/// `matrix_expand_A(g_ctx, md, rho, out)` — `ml_dsa_matrix.h:39-44`, a forwarder to
/// `ossl_ml_dsa_matrix_expand_A` (`ml_dsa_sample.c:209-239`).
///
/// # Safety
/// `g_ctx` must be a live digest context, `md` a fetched SHAKE128, `rho` readable for
/// `ML_DSA_RHO_BYTES` bytes, and `out` must name a `k` by `l` block of polynomials.
#[allow(non_snake_case)] // the authority's own spelling (`matrix_expand_A`)
pub(crate) unsafe fn matrix_expand_A(
    g_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    rho: *const u8,
    out: *mut Matrix,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { ossl_ml_dsa_matrix_expand_A(g_ctx, md, rho, &mut *out) }
}

/// `poly_sample_in_ball_ntt(out, seed, seed_len, h_ctx, md, tau)` — `ml_dsa_poly.h:73-81`, a
/// sample-then-`poly_ntt` pair.
///
/// # Safety
/// `out` must name one initialised polynomial, `seed` readable for `seed_len` bytes, and
/// `h_ctx`/`md` live.
pub(crate) unsafe fn poly_sample_in_ball_ntt(
    out: *mut Poly,
    seed: *const u8,
    seed_len: c_int,
    h_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    tau: u32,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    if unsafe { ossl_ml_dsa_poly_sample_in_ball(&mut *out, seed, seed_len, h_ctx, md, tau) } == 0 {
        return 0;
    }
    // SAFETY: `out` names one initialised polynomial per the contract.
    poly_ntt(unsafe { &mut *out });
    1
}

/// `poly_expand_mask(out, seed, seed_len, gamma1, h_ctx, md)` — `ml_dsa_poly.h:83-88`, a forwarder
/// to `ossl_ml_dsa_poly_expand_mask` (`ml_dsa_sample.c:298-309`).
///
/// # Safety
/// `out` must name one initialised polynomial, `seed` readable for `seed_len` bytes, and
/// `h_ctx`/`md` live.
pub(crate) unsafe fn poly_expand_mask(
    out: *mut Poly,
    seed: *const u8,
    seed_len: usize,
    gamma1: u32,
    h_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { ossl_ml_dsa_poly_expand_mask(&mut *out, seed, seed_len, gamma1, h_ctx, md) }
}

/// `vector_expand_S(h_ctx, md, eta, seed, s1, s2)` — `ml_dsa_vector.h:148-153`, a forwarder to
/// `ossl_ml_dsa_vector_expand_S` (`ml_dsa_sample.c:259-295`).
///
/// # Safety
/// `s1` must name `l` polynomials, `s2` must name `k` polynomials, `seed` must be readable for
/// `ML_DSA_PRIV_SEED_BYTES` bytes, and `h_ctx`/`md` must be live.
#[allow(non_snake_case)] // the authority's own spelling (`vector_expand_S`)
pub(crate) unsafe fn vector_expand_S(
    h_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    eta: c_int,
    seed: *const u8,
    s1: *mut Vector,
    s2: *mut Vector,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { ossl_ml_dsa_vector_expand_S(h_ctx, md, eta, seed, &mut *s1, &mut *s2) }
}

/// `vector_expand_mask(out, rho_prime, rho_prime_len, kappa, gamma1, h_ctx, md)` —
/// `ml_dsa_vector.h:155-174`.
///
/// The header copies its fixed `ML_DSA_RHO_PRIME_BYTES` bytes, not the `rho_prime_len` it is
/// handed, and puts the two counter bytes after them; the length is kept as a parameter because the
/// header takes it, and is unused exactly as it is there.
///
/// # Safety
/// `rho_prime` must be readable for `ML_DSA_RHO_PRIME_BYTES` bytes, `out` must name `num_poly`
/// initialised polynomials, and `h_ctx`/`md` must be live.
pub(crate) unsafe fn vector_expand_mask(
    out: *mut Vector,
    rho_prime: *const u8,
    _rho_prime_len: usize,
    kappa: u32,
    gamma1: u32,
    h_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
) {
    let mut derived_seed = [0u8; VECTOR_EXPAND_MASK_SEED_LEN];
    // SAFETY: `rho_prime` is readable for `ML_DSA_RHO_PRIME_BYTES` bytes per the contract.
    unsafe {
        ptr::copy_nonoverlapping(rho_prime, derived_seed.as_mut_ptr(), ML_DSA_RHO_PRIME_BYTES)
    };

    // SAFETY: `out` names `num_poly` polynomials per the contract.
    let vector = unsafe { &mut *out };
    let n = vector.num_poly;
    for i in 0..n {
        let index = kappa + i as u32;
        derived_seed[ML_DSA_RHO_PRIME_BYTES] = (index & 0xFF) as u8;
        derived_seed[ML_DSA_RHO_PRIME_BYTES + 1] = ((index >> 8) & 0xFF) as u8;
        // SAFETY: `out.poly + i` names one initialised polynomial and `derived_seed` is a live
        // `ML_DSA_RHO_PRIME_BYTES + 2`-byte buffer.
        unsafe {
            poly_expand_mask(
                vector.poly.add(i),
                derived_seed.as_ptr(),
                derived_seed.len(),
                gamma1,
                h_ctx,
                md,
            );
        }
    }
    // `OPENSSL_cleanse(derived_seed, sizeof(derived_seed))`.
    // SAFETY: `derived_seed` is a live local of exactly that size.
    unsafe {
        crate::runtime::mem::OPENSSL_cleanse(derived_seed.as_mut_ptr().cast(), derived_seed.len())
    };
}

/// The `ML_DSA_RHO_PRIME_BYTES + 2`-byte derivation buffer `vector_expand_mask` fills.
///
/// Declared here so the length is read from the header rather than typed at the call site.
pub(crate) const VECTOR_EXPAND_MASK_SEED_LEN: usize = ML_DSA_RHO_PRIME_BYTES + 2;

/// The `ML_DSA_Q` value the header spells `ML_DSA_Q`, re-exported for the units that use it.
pub(crate) const POLY_MODULUS: u32 = ML_DSA_Q;
