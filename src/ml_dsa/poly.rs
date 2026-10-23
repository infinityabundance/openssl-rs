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
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc_array, CRYPTO_memcmp};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_malloc_array};

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

/// The `(poly, num_poly)` member of a [`Vector`] — the `(ptr, len)` blob variant of
/// `MEMBER-BUFFER-MODEL.md` §2.6.
///
/// The pair is either `(NULL, 0)` or a single owned block of exactly `num_poly` `Poly`s produced
/// by the matching allocator seam. Borrowing both fields together means a release cannot move one
/// without the other, and the only release paths leave the empty state.
struct VectorBuf<'a> {
    poly: &'a mut *mut Poly,
    num_poly: &'a mut usize,
}

impl<'a> VectorBuf<'a> {
    /// Derive the handle over a vector's member.
    ///
    /// # Safety
    /// `vector` is live and its pair currently obeys the member invariant: `(NULL, 0)`, or a
    /// single block of exactly `num_poly` `Poly`s produced by the crate's allocator seam and owned
    /// by the vector.
    unsafe fn of(vector: &'a mut Vector) -> VectorBuf<'a> {
        VectorBuf {
            poly: &mut vector.poly,
            num_poly: &mut vector.num_poly,
        }
    }

    /// Release the incumbent at the authority's own `file`/`line` and leave `(NULL, 0)`.
    ///
    /// Given a handle from [`Self::of`], the incumbent is by definition the member's own single
    /// block, so the release is sound. `CRYPTO_free` accepts NULL.
    fn clear_plain(&mut self, file: *const c_char, line: c_int) {
        // SAFETY: the invariant says `*self.poly` is NULL or this member's owned block.
        unsafe { CRYPTO_free((*self.poly).cast(), file, line) };
        *self.poly = ptr::null_mut();
        *self.num_poly = 0;
    }

    /// `OPENSSL_secure_clear_free(poly, rank * sizeof(POLY))`, leaving `(NULL, 0)`.
    fn clear_secure(&mut self, rank: usize, file: *const c_char, line: c_int) {
        // `secure_alloc` allocated this block with a checked element-count product, so the same
        // product cannot overflow for a member satisfying `of`'s contract; the fallback keeps the
        // release sound on the impossible path.
        let num = rank.checked_mul(core::mem::size_of::<Poly>()).unwrap_or(0);
        // SAFETY: `*self.poly` is NULL or the member's owned secure block, `num` is its byte
        // extent, and `CRYPTO_secure_clear_free` accepts NULL.
        unsafe { CRYPTO_secure_clear_free((*self.poly).cast(), num, file, line) };
        *self.poly = ptr::null_mut();
        *self.num_poly = 0;
    }
}

/// A freshly allocated `Poly` block this frame owns until it is published into a `Vector`.
///
/// `Vector::{alloc,secure_alloc}` are this unit's only allocations. An owner checks the
/// element-count product once, releases the block if a future early return appears between the
/// allocator call and publication, and makes the secure arm's release the cleansing one. `into_raw`
/// is the single transfer into the member slot.
///
/// ## Allocated storage is not a `Poly` until this owner has initialised it
///
/// `OPENSSL_malloc_array` returns storage, not values: nothing in the allocator establishes that a
/// `Poly` is valid there. The owner therefore keeps the block as `NonNull<MaybeUninit<Poly>>` — a
/// state from which no `Poly` reference can be formed — and zero-initialises the whole extent in
/// the constructor, before [`Self::into_raw`] can publish it. Zero is a valid and meaningful value
/// for this element type: `Poly` is `#[repr(C)] { coeff: [u32; 256] }`, every bit pattern is a
/// valid `Poly`, and the authority's own `poly_zero`/`vector_zero` (`ml_dsa_poly.h:18-22`,
/// `ml_dsa_vector.h:66-70`) writes exactly this all-zero polynomial before a coefficient is read.
///
/// The authority's `vector_alloc` deliberately leaves the block uninitialised and initialises at
/// the caller's first fill; initialising here instead is a deliberate safety improvement with no
/// observable behavioural change (no reader consumes an indeterminate coefficient — that would be
/// undefined in the authority too). It is what makes `Vector::as_slice`/`as_mut_slice` sound
/// immediately after `alloc`, instead of requiring callers to form a reference over uninitialised
/// storage merely to zero it (AGENTS.md §2).
struct PolyBlock {
    ptr: ptr::NonNull<core::mem::MaybeUninit<Poly>>,
    bytes: usize,
    file: *const c_char,
    line: c_int,
    secure: bool,
}

impl PolyBlock {
    /// `OPENSSL_malloc_array(count, sizeof(POLY))`, initialised to `count` zero polynomials.
    fn malloc(count: usize, file: *const c_char, line: c_int) -> Option<PolyBlock> {
        let elem = core::mem::size_of::<Poly>();
        let bytes = count.checked_mul(elem);
        // SAFETY: `file` is NULL or a valid NUL-terminated coordinate; the array allocator checks
        // the product itself and raises the authority's overflow error there.
        let raw = unsafe { CRYPTO_malloc_array(count, elem, file, line) }
            .cast::<core::mem::MaybeUninit<Poly>>();
        let ptr = ptr::NonNull::new(raw)?;
        let Some(bytes) = bytes else {
            // The allocator should already have refused; release if it did not, so an overflowing
            // count can never leave an unpublishable block behind.
            // SAFETY: `raw` is a live block this call owns.
            unsafe { CRYPTO_free(raw.cast(), file, line) };
            return None;
        };
        let block = PolyBlock {
            ptr,
            bytes,
            file,
            line,
            secure: false,
        };
        block.initialise_zeroed(count);
        Some(block)
    }

    /// `OPENSSL_secure_malloc_array(count, sizeof(POLY))`, initialised to `count` zero
    /// polynomials.
    fn secure_malloc(count: usize, file: *const c_char, line: c_int) -> Option<PolyBlock> {
        let elem = core::mem::size_of::<Poly>();
        let bytes = count.checked_mul(elem);
        // SAFETY: as in `malloc`; the secure array allocator checks the product too.
        let raw = unsafe { CRYPTO_secure_malloc_array(count, elem, file, line) }
            .cast::<core::mem::MaybeUninit<Poly>>();
        let ptr = ptr::NonNull::new(raw)?;
        let Some(bytes) = bytes else {
            // SAFETY: `raw` is a live secure block this call owns; the release cleanses it.
            unsafe { CRYPTO_secure_clear_free(raw.cast(), 0, file, line) };
            return None;
        };
        let block = PolyBlock {
            ptr,
            bytes,
            file,
            line,
            secure: true,
        };
        block.initialise_zeroed(count);
        Some(block)
    }

    /// Write `count` all-zero `Poly` values into the block, making every element a valid `Poly`.
    ///
    /// This is the only transition out of `MaybeUninit`, and it runs in both constructors before
    /// the handle is returned, so a `PolyBlock` never names uninitialised storage at a point where
    /// another function can observe it.
    fn initialise_zeroed(&self, count: usize) {
        // SAFETY: `self.ptr` is the exclusively owned, writable block of `count`
        // `MaybeUninit<Poly>` elements this handle allocated. Writing zero bytes through a raw
        // pointer to `MaybeUninit` is defined; zero is a valid `Poly` (see the type's note), so
        // every element is initialised afterwards.
        unsafe { ptr::write_bytes(self.ptr.as_ptr(), 0u8, count) };
    }

    /// The validated transition: transfer the now-initialised block into a `Vector` member slot.
    fn into_raw(self) -> *mut Poly {
        // `MaybeUninit<Poly>` and `Poly` have the same layout, and both constructors initialised
        // every element, so the cast preserves the provenance and extent of a valid `Poly` block.
        let p = self.ptr.as_ptr().cast::<Poly>();
        core::mem::forget(self);
        p
    }
}

impl Drop for PolyBlock {
    fn drop(&mut self) {
        // SAFETY: `ptr` is the exclusively owned block this handle allocated and has not released,
        // `bytes` its checked extent, and `Drop` runs once. The secure arm cleanses.
        unsafe {
            if self.secure {
                CRYPTO_secure_clear_free(self.ptr.as_ptr().cast(), self.bytes, self.file, self.line)
            } else {
                CRYPTO_free(self.ptr.as_ptr().cast(), self.file, self.line)
            }
        }
    }
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
    /// On success every one of the `num_polys` polynomials is initialised (all-zero, the value
    /// `vector_zero` would write), so [`Self::as_slice`]/[`Self::as_mut_slice`] are valid
    /// immediately. The authority leaves the block uninitialised until its caller fills it; this
    /// owner establishes the invariant itself so no typed borrow can precede initialisation.
    ///
    /// # Safety
    /// `file` must be a NUL-terminated C string, and `self` must not already own a block (the
    /// authority's `vector_alloc` precondition); an incumbent would be leaked exactly as in the C.
    pub(crate) unsafe fn alloc(
        &mut self,
        num_polys: usize,
        file: *const c_char,
        line: c_int,
    ) -> c_int {
        // The owner checks the element-count product and is the single release until publication.
        let Some(block) = PolyBlock::malloc(num_polys, file, line) else {
            return 0;
        };
        // The pair is published together; no allocation event or observer runs between the two
        // stores, so the member invariant holds from the next observation.
        self.poly = block.into_raw();
        self.num_poly = num_polys;
        1
    }

    /// `vector_secure_alloc(v, num_polys)` — `ml_dsa_vector.h:42-49`, `OPENSSL_secure_malloc_array`.
    ///
    /// As [`Self::alloc`], a successful call publishes `num_polys` initialised (all-zero)
    /// polynomials; the block stays the authority's secure allocation and its release still
    /// cleanses.
    ///
    /// # Safety
    /// `file` must be a NUL-terminated C string, and `self` must not already own a block (the
    /// authority's `vector_secure_alloc` precondition); an incumbent would be leaked exactly as in
    /// the C.
    pub(crate) unsafe fn secure_alloc(
        &mut self,
        num_polys: usize,
        file: *const c_char,
        line: c_int,
    ) -> c_int {
        // The owner checks the product and its `Drop` is the cleansing release until publication.
        let Some(block) = PolyBlock::secure_malloc(num_polys, file, line) else {
            return 0;
        };
        // As in `alloc`: the pair is published together and the member invariant is restored.
        self.poly = block.into_raw();
        self.num_poly = num_polys;
        1
    }

    /// `vector_free(v)` — `ml_dsa_vector.h:51-56`.
    ///
    /// # Safety
    /// `file` must be a NUL-terminated C string, and the block must have come from
    /// [`Vector::alloc`].
    pub(crate) unsafe fn free(&mut self, file: *const c_char, line: c_int) {
        // SAFETY: the contract says the block came from `Vector::alloc`, so the pair obeys the
        // member invariant; the handle releases it at the authority's own site and empties it.
        unsafe { VectorBuf::of(self) }.clear_plain(file, line);
    }

    /// `vector_secure_free(v, rank)` — `ml_dsa_vector.h:58-63`, `OPENSSL_secure_clear_free`.
    ///
    /// # Safety
    /// `file` must be a NUL-terminated C string, and the block must have come from
    /// [`Vector::secure_alloc`].
    pub(crate) unsafe fn secure_free(&mut self, rank: usize, file: *const c_char, line: c_int) {
        // SAFETY: the contract says the block came from `Vector::secure_alloc`, so the pair obeys
        // the member invariant; the handle cleanses and releases it, then empties it.
        unsafe { VectorBuf::of(self) }.clear_secure(rank, file, line);
    }

    /// `vector_zero(va)` — `ml_dsa_vector.h:66-70`, over a proven slice.
    pub(crate) fn zero(v: &mut [Poly]) {
        for p in v {
            poly_zero(p);
        }
    }

    /// The `num_poly` polynomials this vector names.
    ///
    /// `alloc`/`secure_alloc` initialise every element they publish, so a vector this module
    /// constructed has no partially initialised borrow window.
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
pub(crate) fn vector_copy(dst: &mut [Poly], src: &[Poly]) {
    // The authority's `assert` disappears under `NDEBUG` and its `memcpy` then writes
    // `src->num_poly` elements into `dst`. A shape mismatch is refused in release too rather than
    // reproduce the write beyond `dst`'s extent (§17).
    assert_eq!(dst.len(), src.len());
    dst.copy_from_slice(src);
}

/// `vector_equal(a, b)` — `ml_dsa_vector.h:84-96`.
///
/// # Safety
/// Both vectors must name `num_poly` initialised polynomials.
pub(crate) fn vector_equal(a: &[Poly], b: &[Poly]) -> c_int {
    if a.len() != b.len() {
        return 0;
    }
    for (pa, pb) in a.iter().zip(b) {
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
pub(crate) fn vector_ntt(va: &mut [Poly]) {
    for p in va {
        ossl_ml_dsa_poly_ntt(p);
    }
}

/// `vector_ntt_inverse(va)` — `ml_dsa_vector.h:129-136`.
///
/// # Safety
/// `va` must name `num_poly` initialised polynomials.
pub(crate) fn vector_ntt_inverse(va: &mut [Poly]) {
    for p in va {
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
    vector_ntt(unsafe { out.as_mut_slice() });
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
pub(crate) fn vector_max(v: &[Poly]) -> u32 {
    let mut mx = 0u32;
    for p in v {
        poly_max(p, &mut mx);
    }
    mx
}

/// `vector_max_signed(v)` — `ml_dsa_vector.h:230-239`.
///
/// # Safety
/// `v` must name `num_poly` initialised polynomials.
pub(crate) fn vector_max_signed(v: &[Poly]) -> u32 {
    let mut mx = 0u32;
    for p in v {
        poly_max_signed(p, &mut mx);
    }
    mx
}

/// `vector_count_ones(v)` — `ml_dsa_vector.h:241-251`.
///
/// # Safety
/// `v` must name `num_poly` initialised polynomials.
pub(crate) fn vector_count_ones(v: &[Poly]) -> usize {
    let mut count = 0usize;
    for p in v {
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
    // A shape whose product overflows cannot name a block (the authority would wrap the product
    // and read out of bounds); the defined refusal is the empty slice (§3).
    let Some(n) = m.k.checked_mul(m.l) else {
        return &[];
    };
    if n == 0 || m.m_poly.is_null() {
        return &[];
    }
    // SAFETY: the contract says `m_poly` names `k * l` polynomials.
    unsafe { core::slice::from_raw_parts(m.m_poly, n) }
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
    // SAFETY: `out` names `num_poly` polynomials per the contract.
    let polys = unsafe { vector.as_mut_slice() };
    for (i, p) in polys.iter_mut().enumerate() {
        let index = kappa + i as u32;
        derived_seed[ML_DSA_RHO_PRIME_BYTES] = (index & 0xFF) as u8;
        derived_seed[ML_DSA_RHO_PRIME_BYTES + 1] = ((index >> 8) & 0xFF) as u8;
        // SAFETY: `out.poly + i` names one initialised polynomial and `derived_seed` is a live
        // `ML_DSA_RHO_PRIME_BYTES + 2`-byte buffer.
        unsafe {
            poly_expand_mask(
                ptr::from_mut(p),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_vector_allocation_round_trips_and_frees_once() {
        let _g = crate::test_support::lock_global_state();
        let mut v = Vector::empty();
        // SAFETY: `v` is empty and NULL is the allocator's default coordinate.
        assert_eq!(unsafe { v.alloc(4, ptr::null(), 0) }, 1);
        assert_eq!(v.num_poly, 4);
        /* `OPENSSL_malloc_array` is `CRYPTO_malloc_array`, which does **not** zero the block; the
         * authority's callers zero it explicitly (`vector_zero`) before the first read. Reading a
         * coefficient of the untouched allocation asserted a guarantee the allocator never made —
         * it passed only while the allocator happened to hand back fresh zero pages. Initialise
         * here, then test the extent and the release. */
        // SAFETY: `poly` names `num_poly` allocated polynomials and zero is a valid `Poly`.
        unsafe { ptr::write_bytes(v.poly, 0u8, v.num_poly) };
        // SAFETY: the vector owns four now-initialised polynomials.
        unsafe {
            let s = v.as_mut_slice();
            assert_eq!(s.len(), 4);
            s[0].coeff[0] = 7;
            assert_eq!(s[0].coeff[0], 7);
            assert_eq!(s[3].coeff[0], 0);
        }
        // SAFETY: the block came from `alloc` and is released exactly once here.
        unsafe { v.free(ptr::null(), 0) };
        assert!(v.poly.is_null() && v.num_poly == 0);
    }

    #[test]
    fn an_overflowing_element_count_is_refused_without_publication() {
        let _g = crate::test_support::lock_global_state();
        let mut v = Vector::empty();
        // SAFETY: `v` is empty; the count makes the element-count product overflow.
        assert_eq!(unsafe { v.alloc(usize::MAX, ptr::null(), 0) }, 0);
        assert!(v.poly.is_null() && v.num_poly == 0);
        // SAFETY: as above, through the secure arm.
        assert_eq!(unsafe { v.secure_alloc(usize::MAX, ptr::null(), 0) }, 0);
        assert!(v.poly.is_null() && v.num_poly == 0);
    }

    #[test]
    fn a_matrix_with_an_overflowing_shape_names_nothing() {
        let m = Matrix {
            m_poly: ptr::NonNull::<Poly>::dangling().as_ptr(),
            k: usize::MAX,
            l: 2,
        };
        // SAFETY: the checked product refuses before any slice is formed, so the pointer is never
        // read.
        assert!(unsafe { matrix_as_slice(&m) }.is_empty());
    }

    /// A freshly allocated vector is immediately safe to read: every polynomial the owner
    /// published is initialised, so no caller has to form a reference over uninitialised storage
    /// just to zero it (the S21-O1 defect).
    #[test]
    fn ml_dsa_uninit_a_fresh_vector_is_safe_to_read() {
        let _g = crate::test_support::lock_global_state();
        for n in [1usize, 4] {
            let mut v = Vector::empty();
            // SAFETY: `v` is empty and NULL is the allocator's default coordinate.
            assert_eq!(unsafe { v.alloc(n, ptr::null(), 0) }, 1);
            assert_eq!(v.num_poly, n);
            // SAFETY: `alloc` establishes the postcondition that every element is initialised.
            unsafe {
                let s = v.as_slice();
                assert_eq!(s.len(), n);
                for p in s {
                    assert_eq!(p.coeff, [0u32; ML_DSA_NUM_POLY_COEFFICIENTS]);
                }
                // The same borrow is writable and defined.
                let m = v.as_mut_slice();
                m[n - 1].coeff[0] = 0x1234_5678;
                assert_eq!(v.as_slice()[n - 1].coeff[0], 0x1234_5678);
            }
            // SAFETY: the block came from `alloc` and is released exactly once here.
            unsafe { v.free(ptr::null(), 0) };
            assert!(v.poly.is_null() && v.num_poly == 0);
        }
    }

    /// The secret-bearing arm keeps both obligations: the owner releases the secure block and the
    /// release cleanses it. With no secure heap initialised, `CRYPTO_secure_clear_free` takes its
    /// documented plain fallback (cleanse `num` bytes, then free); the release seam's test-only
    /// probe captures the bytes *after* the cleanse and *before* the free, so this never reads
    /// freed memory.
    #[test]
    fn ml_dsa_uninit_a_secure_vector_is_cleansed_on_release() {
        use crate::runtime::secure::cleanse_probe;

        let _g = crate::test_support::lock_global_state();
        // No heap: make sure a previous test's heap (if any) is torn down. `done` refuses while
        // anything is live, and the probe below then reports `None` rather than a false pass.
        let _ = crate::runtime::secure::CRYPTO_secure_malloc_done();

        let n = 3usize;
        let bytes = n * core::mem::size_of::<Poly>();
        let mut v = Vector::empty();
        // SAFETY: `v` is empty and NULL is the allocator's default coordinate.
        assert_eq!(unsafe { v.secure_alloc(n, ptr::null(), 0) }, 1);
        // SAFETY: `secure_alloc` initialises every element it publishes.
        unsafe {
            for p in v.as_mut_slice() {
                p.coeff = [0xA5A5_A5A5; ML_DSA_NUM_POLY_COEFFICIENTS];
            }
        }

        cleanse_probe::arm(v.poly.cast::<u8>(), bytes);
        // SAFETY: the block came from `secure_alloc`; this is its single cleansing release.
        unsafe { v.secure_free(n, ptr::null(), 0) };
        assert_eq!(v.num_poly, 0);

        let observed = cleanse_probe::observed()
            .expect("the secure release must take the cleansing path (the probe must fire)");
        assert_eq!(observed.len(), bytes);
        assert!(
            observed.iter().all(|&b| b == 0),
            "the secure release must cleanse the secret polynomials"
        );
    }

    /// Negative control for the S21-O1 defect class, test-only (the module is `#[cfg(test)]`).
    ///
    /// The pre-fix `Vector::alloc` published the raw `OPENSSL_malloc_array` block without
    /// establishing any `Poly` value, and `as_slice` then observed whatever bytes were there. The
    /// canary models that block's contents with a sentinel and reads it through the pre-fix shape,
    /// then shows the new owner publishes zeros over the same seam allocation instead: the
    /// uninitialised state is no longer reachable from the type.
    #[test]
    fn ml_dsa_uninit_canary_the_prefix_shape_exposed_allocator_contents() {
        let _g = crate::test_support::lock_global_state();
        let n = 2usize;
        let elem = core::mem::size_of::<Poly>();

        // Pre-fix shape: allocate on the same seam, publish it, borrow it. The sentinel stands in
        // for the indeterminate contents `OPENSSL_malloc_array` leaves behind.
        // SAFETY: `file` is NULL and the seam answers a live block of `n * elem` bytes.
        let raw = unsafe { CRYPTO_malloc_array(n, elem, ptr::null(), 0) }.cast::<Poly>();
        assert!(!raw.is_null());
        // SAFETY: `raw` owns `n * elem` writable bytes.
        unsafe { ptr::write_bytes(raw.cast::<u8>(), 0xA5, n * elem) };
        // SAFETY: the pre-fix accessor contract was the claim under test; this models its shape
        // over a block the owner never initialised.
        let prefix = unsafe { core::slice::from_raw_parts(raw, n) };
        assert!(
            prefix.iter().all(|p| p.coeff[0] == 0xA5A5_A5A5),
            "the pre-fix shape exposes bytes the owner never initialised"
        );
        // SAFETY: `raw` is this test's block, released once.
        unsafe { CRYPTO_free(raw.cast(), ptr::null(), 0) };

        // New design: the same seam allocation is initialised by the owner before publication, so
        // the same borrow observes defined values.
        let mut v = Vector::empty();
        // SAFETY: `v` is empty and NULL is the allocator's default coordinate.
        assert_eq!(unsafe { v.alloc(n, ptr::null(), 0) }, 1);
        // SAFETY: `alloc` initialises every element it publishes.
        unsafe {
            let s = v.as_slice();
            assert_eq!(s.len(), n);
            assert!(
                s.iter().all(|p| p.coeff.iter().all(|&c| c == 0)),
                "the owner must publish initialised storage"
            );
            v.free(ptr::null(), 0);
        }
    }
}

#[cfg(test)]
mod slice_tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn poly(v: u32) -> Poly {
        Poly {
            coeff: [v; ML_DSA_NUM_POLY_COEFFICIENTS],
        }
    }

    #[test]
    fn the_safe_vector_operations_hold_their_preconditions() {
        let mut a = [poly(1), poly(2)];
        let mut b = [poly(3), poly(4)];

        vector_copy(&mut b, &a);
        assert_eq!(vector_equal(&a, &b), 1);
        assert_eq!(
            vector_equal(&a, &[poly(1)]),
            0,
            "a length mismatch is unequal"
        );

        Vector::zero(&mut b);
        assert_eq!(vector_equal(&a, &b), 0);

        assert_eq!(vector_max(&a), maximum(0, abs_mod_prime(2)));
        assert_eq!(vector_max_signed(&a), abs_signed(2));
        assert_eq!(
            vector_count_ones(&[poly(1), poly(1)]),
            2 * ML_DSA_NUM_POLY_COEFFICIENTS
        );

        // In-place NTT and its inverse are safe over the slice.
        let before = a;
        vector_ntt(&mut a);
        assert_eq!(vector_equal(&a, &before), 0);
        vector_ntt_inverse(&mut a);
        // `poly_ntt` multiplies by the Montgomery factor; the round trip scales by R, so compare
        // against the same scaling the crate's scalar NTT test uses.
        let mut expected = before;
        for p in &mut expected {
            ossl_ml_dsa_poly_ntt(p);
            super::super::ntt::ossl_ml_dsa_poly_ntt_inverse(p);
        }
        assert_eq!(vector_equal(&a, &expected), 1);
    }
}
