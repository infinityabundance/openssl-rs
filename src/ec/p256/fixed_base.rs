//! PFP-3 — fixed-base P-256 multiplication from tracked generator data.
//!
//! The authority computes `k·G` through the same Montgomery ladder it uses for
//! a variable point (`ossl_ec_wNAF_mul` sends a lone generator scalar to
//! `ossl_ec_scalar_mul_ladder`). PFP-3 keeps that ladder for every point and
//! every generator it is not *exactly* the standard one, and adds one fast arm
//! that is reachable only when the group **is** P-256 and its generator **is**
//! the tracked `(Gx, Gy)`.
//!
//! ## Where the table comes from
//!
//! The base point is not a literal in this file. It is read from
//! [`crate::ec::curve_data::_EC_X9_62_PRIME_256V1_DATA`], the byte array the
//! generator read back from the admitted authority's own `EC_CURVE_DATA`; the
//! same array supplies `p`, `a`, `b`, `Gx`, `Gy` and `n`, and the admission
//! predicate below compares the live group against it member for member. The
//! multiples are derived at **first use** with the complete formulas in this
//! module and cached in a `OnceLock`; nothing is transcribed as a table.
//!
//! ## The comb
//!
//! With `WINDOW = 4` and `COLUMNS = 64` (`WINDOW * COLUMNS = 256`), split the
//! 256-bit scalar bit `t = i + j·COLUMNS` (`i < COLUMNS`, `j < WINDOW`) and
//! precompute
//!
//! ```text
//!   Q[v] = Σ_j v_j · 2^{j·COLUMNS} · G        v ∈ [0, 2^WINDOW)
//! ```
//!
//! so that `k·G = Σ_i 2^i · Q[column_i]`, evaluated by Horner's rule as
//! `acc ← 2·acc + Q[column_i]` over `i = COLUMNS-1 … 0`: exactly 64 doublings
//! and 64 additions per multiplication, independent of the scalar. The table has
//! only 16 points and is built once.
//!
//! ## Constant-time selection
//!
//! `column_i` is secret-derived, so it is never used as an index. Each column
//! scans all sixteen table entries and folds the match with a full-width mask;
//! the cost is 15 masked selects per column (64·15 = 960 selects), a fixed
//! function of the public parameters and not of the scalar.
//!
//! ## Admission
//!
//! A modified generator, a custom curve and a foreign method each keep their own
//! semantics: [`admits`] refuses them and the caller stays on the ladder. The
//! refusal tests in this module's test section drive each case.

use core::ffi::c_int;
use std::sync::OnceLock;

use crate::bn::bignum::BigNum;
use crate::ec::smpl::{ec_method_field_is_plain, ossl_ec_GFp_simple_ladder_step, store_coordinate};
use crate::ec::{EcGroup, EcLadderFn, EcPoint};

use super::*;

/// Bits taken from one scalar column.
pub(crate) const WINDOW: usize = 4;
/// Number of columns: `WINDOW * COLUMNS == 256`.
pub(crate) const COLUMNS: usize = 64;
/// Table entries: one per `WINDOW`-bit value.
pub(crate) const TABLE_LEN: usize = 1 << WINDOW;

/// The tracked `data[]` offset of a 32-byte field: `p = 0`, `a = 1`, `b = 2`,
/// `Gx = 3`, `Gy = 4`, `n = 5`, after the 20-byte seed.
fn tracked_field(index: usize) -> [Limb; LIMBS] {
    const SEED: usize = 20;
    let data = &crate::ec::curve_data::_EC_X9_62_PRIME_256V1_DATA;
    let start = SEED + index * 32;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[start..start + 32]);
    limbs_from_be(&bytes)
}

/// `p - 3`, the curve's `a` for P-256.
fn p_minus_3() -> [Limb; LIMBS] {
    let mut a = FIELD_MODULUS;
    a[0] -= 3;
    a
}

fn tracked_b() -> [Limb; LIMBS] {
    tracked_field(2)
}

fn tracked_gx() -> [Limb; LIMBS] {
    tracked_field(3)
}

fn tracked_gy() -> [Limb; LIMBS] {
    tracked_field(4)
}

// ---------------------------------------------------------------------------
// Field helpers (alias-safe: every result is a fresh guarded value)
// ---------------------------------------------------------------------------

fn one<K: FieldKernel<FieldDomain>>(kernel: &K) -> P256Field<K> {
    let mut ordinary = [0u64; LIMBS];
    ordinary[0] = 1;
    P256Field::from_canonical(kernel, &ordinary)
}

fn fadd<K: FieldKernel<FieldDomain>>(k: &K, a: &P256Field<K>, b: &P256Field<K>) -> P256Field<K> {
    let mut out = P256Field::zero();
    out.add_into(k, a, b);
    out
}

fn fsub<K: FieldKernel<FieldDomain>>(k: &K, a: &P256Field<K>, b: &P256Field<K>) -> P256Field<K> {
    let mut out = P256Field::zero();
    out.sub_into(k, a, b);
    out
}

fn fmul<K: FieldKernel<FieldDomain>>(k: &K, a: &P256Field<K>, b: &P256Field<K>) -> P256Field<K> {
    let mut out = P256Field::zero();
    out.mul_into(k, a, b);
    out
}

fn fsqr<K: FieldKernel<FieldDomain>>(k: &K, a: &P256Field<K>) -> P256Field<K> {
    let mut out = P256Field::zero();
    out.sqr_into(k, a);
    out
}

/// `out = mask ? a : b`, one full-width field element.
fn fselect<K: FieldKernel<FieldDomain>>(
    k: &K,
    mask: Limb,
    a: &P256Field<K>,
    b: &P256Field<K>,
) -> P256Field<K> {
    let mut out = P256Field::zero();
    k.select(out.limbs_mut(), mask, a.limbs(), b.limbs());
    out
}

// ---------------------------------------------------------------------------
// Point arithmetic
// ---------------------------------------------------------------------------

/// Renes–Costello–Batina complete addition (EUROCRYPT 2016, Algorithm 4).
///
/// The addition law does not depend on `a`, so this is the `a = -3` schedule's
/// addition arm as well. The formula is complete: `P + Q`, `P = Q`, `P = -Q` and
/// either operand at infinity all produce the correct projective result with no
/// data-dependent branch.
fn rcb_add<K: FieldKernel<FieldDomain>>(
    k: &K,
    cb: &P256Field<K>,
    p: &P256Projective<K>,
    q: &P256Projective<K>,
) -> P256Projective<K> {
    let mut t0 = fmul(k, &p.x, &q.x);
    let mut t1 = fmul(k, &p.y, &q.y);
    let mut t2 = fmul(k, &p.z, &q.z);
    let mut t3 = fadd(k, &p.x, &p.y);
    let mut t4 = fadd(k, &q.x, &q.y);
    t3 = fmul(k, &t3, &t4);
    t4 = fadd(k, &t0, &t1);
    t3 = fsub(k, &t3, &t4);
    t4 = fadd(k, &p.y, &p.z);
    let mut x3 = fadd(k, &q.y, &q.z);
    t4 = fmul(k, &t4, &x3);
    x3 = fadd(k, &t1, &t2);
    t4 = fsub(k, &t4, &x3);
    x3 = fadd(k, &p.x, &p.z);
    let mut y3 = fadd(k, &q.x, &q.z);
    x3 = fmul(k, &x3, &y3);
    y3 = fadd(k, &t0, &t2);
    y3 = fsub(k, &x3, &y3);
    let mut z3 = fmul(k, cb, &t2);
    x3 = fsub(k, &y3, &z3);
    z3 = fadd(k, &x3, &x3);
    x3 = fadd(k, &x3, &z3);
    z3 = fsub(k, &t1, &x3);
    x3 = fadd(k, &t1, &x3);
    y3 = fmul(k, cb, &y3);
    t1 = fadd(k, &t2, &t2);
    t2 = fadd(k, &t1, &t2);
    y3 = fsub(k, &y3, &t2);
    y3 = fsub(k, &y3, &t0);
    t1 = fadd(k, &y3, &y3);
    y3 = fadd(k, &t1, &y3);
    t1 = fadd(k, &t0, &t0);
    t0 = fadd(k, &t1, &t0);
    t0 = fsub(k, &t0, &t2);
    t1 = fmul(k, &t4, &y3);
    t2 = fmul(k, &t0, &y3);
    y3 = fmul(k, &x3, &z3);
    y3 = fadd(k, &y3, &t2);
    x3 = fmul(k, &t3, &x3);
    x3 = fsub(k, &x3, &t1);
    z3 = fmul(k, &t4, &z3);
    t1 = fmul(k, &t3, &t0);
    z3 = fadd(k, &z3, &t1);
    P256Projective::new(x3, y3, z3)
}

/// Complete doubling for the admitted path.
///
/// The complete addition applied with `P = Q` is `2P` in the same homogeneous
/// projective coordinates, so this is complete for every input (including
/// infinity) without a dedicated schedule. The dedicated `a = -3` schedule is
/// kept as the measured reference arm below.
fn rcb_double<K: FieldKernel<FieldDomain>>(
    k: &K,
    ca: &P256Field<K>,
    cb: &P256Field<K>,
    p: &P256Projective<K>,
) -> P256Projective<K> {
    let _ = ca;
    rcb_add(k, cb, p, p)
}

/// The measured reference arm: Jacobian addition and `a = -3` doubling.
///
/// The doubling is `dbl-2001-b` (3M + 5S for `a = -3`). The addition is
/// `add-2007-bl` on Jacobian coordinates; it is **not** complete — it assumes
/// `P ≠ ±Q` and neither operand at infinity — so it is used only as a reference
/// and never on the secret path. The comparison in `FORMULAS.md` reports the raw
/// schedules and the completeness/constant-time admission decision.
pub(crate) mod jacobian {
    use super::*;

    fn mul_small<K: FieldKernel<FieldDomain>>(k: &K, a: &P256Field<K>, n: usize) -> P256Field<K> {
        let mut acc = fadd(k, a, a); // 2a
        let mut reached = 2usize;
        while reached < n {
            acc = fadd(k, &acc, &acc);
            reached *= 2;
        }
        debug_assert_eq!(reached, n, "mul_small only multiplies by powers of two");
        acc
    }

    /// Jacobian doubling with `a = -3`.
    pub(crate) fn double<K: FieldKernel<FieldDomain>>(
        k: &K,
        p: &P256Projective<K>,
    ) -> P256Projective<K> {
        let delta = fsqr(k, &p.z);
        let gamma = fsqr(k, &p.y);
        let beta = fmul(k, &p.x, &gamma);
        let x_minus = fsub(k, &p.x, &delta);
        let x_plus = fadd(k, &p.x, &delta);
        let alpha = fmul(k, &x_minus, &x_plus);
        let alpha3 = fadd(k, &fadd(k, &alpha, &alpha), &alpha);
        let x3 = fsub(k, &fsqr(k, &alpha3), &mul_small(k, &beta, 8));
        let zp = fadd(k, &p.y, &p.z);
        let z3 = fsub(k, &fsub(k, &fsqr(k, &zp), &gamma), &delta);
        let four_beta = mul_small(k, &beta, 4);
        let y3 = fsub(
            k,
            &fmul(k, &alpha3, &fsub(k, &four_beta, &x3)),
            &mul_small(k, &fsqr(k, &gamma), 8),
        );
        P256Projective::new(x3, y3, z3)
    }

    /// Jacobian addition (`add-2007-bl`); non-complete.
    pub(crate) fn add<K: FieldKernel<FieldDomain>>(
        k: &K,
        p: &P256Projective<K>,
        q: &P256Projective<K>,
    ) -> P256Projective<K> {
        let z1z1 = fsqr(k, &p.z);
        let z2z2 = fsqr(k, &q.z);
        let u1 = fmul(k, &p.x, &z2z2);
        let u2 = fmul(k, &q.x, &z1z1);
        let s1 = fmul(k, &fmul(k, &p.y, &q.z), &z2z2);
        let s2 = fmul(k, &fmul(k, &q.y, &p.z), &z1z1);
        let h = fsub(k, &u2, &u1);
        let i = fsqr(k, &fadd(k, &h, &h));
        let j = fmul(k, &h, &i);
        let r = fadd(k, &fsub(k, &s2, &s1), &fsub(k, &s2, &s1));
        let v = fmul(k, &u1, &i);
        let x3 = fsub(k, &fsub(k, &fsqr(k, &r), &j), &fadd(k, &v, &v));
        let s1j = fmul(k, &s1, &j);
        let y3 = fsub(k, &fmul(k, &r, &fsub(k, &v, &x3)), &fadd(k, &s1j, &s1j));
        let zsum = fsqr(k, &fadd(k, &p.z, &q.z));
        let z3 = fmul(k, &fsub(k, &fsub(k, &zsum, &z1z1), &z2z2), &h);
        P256Projective::new(x3, y3, z3)
    }
}

// ---------------------------------------------------------------------------
// Table construction and the comb
// ---------------------------------------------------------------------------

/// The precomputed multiplier table for one standard generator.
pub(crate) struct Table<K> {
    q: [P256Projective<K>; TABLE_LEN],
}

/// Build `Q[v] = Σ_j v_j · 2^{j·COLUMNS} · G` from the tracked base point.
fn build_table<K: FieldKernel<FieldDomain>>(
    k: &K,
    ca: &P256Field<K>,
    cb: &P256Field<K>,
    gx: &[Limb; LIMBS],
    gy: &[Limb; LIMBS],
) -> Table<K> {
    let g = P256Projective::new(
        P256Field::from_canonical(k, gx),
        P256Field::from_canonical(k, gy),
        one(k),
    );

    // B[j] = 2^{j·COLUMNS} · G, each derived from the previous by COLUMNS doublings.
    fn advance<K: FieldKernel<FieldDomain>>(
        k: &K,
        ca: &P256Field<K>,
        cb: &P256Field<K>,
        start: &P256Projective<K>,
    ) -> P256Projective<K> {
        let mut current = rcb_double(k, ca, cb, start);
        for _ in 1..COLUMNS {
            current = rcb_double(k, ca, cb, &current);
        }
        current
    }
    let b0 = g;
    let b1 = advance(k, ca, cb, &b0);
    let b2 = advance(k, ca, cb, &b1);
    let b3 = advance(k, ca, cb, &b2);
    let base = [b0, b1, b2, b3];

    let mut q: [P256Projective<K>; TABLE_LEN] = core::array::from_fn(|_| {
        P256Projective::new(P256Field::zero(), P256Field::zero(), P256Field::zero())
    });
    // Q[0] is the point at infinity, encoded as (0 : 1 : 0).
    q[0] = P256Projective::new(P256Field::zero(), one(k), P256Field::zero());
    for v in 1..TABLE_LEN {
        let low = v.isolate_lowest_one();
        let index = low.trailing_zeros() as usize;
        // `v ^ low < v`, so the low operand is already built. `split_at_mut`
        // keeps the immutable read of `q[v ^ low]` disjoint from the write to
        // `q[v]`; there is no raw pointer here.
        let (built, rest) = q.split_at_mut(v);
        rest[0] = rcb_add(k, cb, &built[v ^ low], &base[index]);
    }
    Table { q }
}

/// The fixed-base table, built once from the tracked generator and cached.
static MONT_TABLE: OnceLock<Table<Mont<FieldDomain>>> = OnceLock::new();

fn mont_table() -> &'static Table<Mont<FieldDomain>> {
    let kernel = Mont::<FieldDomain>::default();
    MONT_TABLE.get_or_init(|| {
        let ca = P256Field::from_canonical(&kernel, &p_minus_3());
        let cb = P256Field::from_canonical(&kernel, &tracked_b());
        build_table(&kernel, &ca, &cb, &tracked_gx(), &tracked_gy())
    })
}

// ---------------------------------------------------------------------------
// Constant-time selection and the comb
// ---------------------------------------------------------------------------

/// All ones when `a == b`, zero otherwise, with no branch.
#[inline(always)]
fn ct_eq_u64(a: Limb, b: Limb) -> Limb {
    let x = a ^ b;
    let y = x | x.wrapping_neg();
    ((y >> 63).wrapping_sub(1)) & Limb::MAX
}

/// The `WINDOW` scalar bits `{i, i + COLUMNS, …, i + (WINDOW-1)·COLUMNS}` packed
/// little-endian into one value. This is arithmetic on secret bits, not an
/// index: the returned value is used only by [`select_point`]'s masked scan.
#[inline(always)]
fn column(scalar: &[Limb; LIMBS], i: usize) -> Limb {
    let mut value = 0u64;
    let mut j = 0;
    while j < WINDOW {
        let index = i + j * COLUMNS;
        let bit = (scalar[index / 64] >> (index % 64)) & 1;
        value |= bit << j;
        j += 1;
    }
    value
}

/// Select `Q[col]` by scanning every table entry and folding the match with a
/// full-width mask. The cost is fixed at `TABLE_LEN - 1` masked selects of a
/// projective point (3 field elements), independent of `col`.
fn select_point<K: FieldKernel<FieldDomain>>(
    k: &K,
    table: &Table<K>,
    col: Limb,
) -> P256Projective<K> {
    let mut x = P256Field::zero();
    x.copy_from(&table.q[0].x);
    let mut y = P256Field::zero();
    y.copy_from(&table.q[0].y);
    let mut z = P256Field::zero();
    z.copy_from(&table.q[0].z);
    let mut v = 1usize;
    while v < TABLE_LEN {
        let mask = ct_eq_u64(v as Limb, col);
        x = fselect(k, mask, &table.q[v].x, &x);
        y = fselect(k, mask, &table.q[v].y, &y);
        z = fselect(k, mask, &table.q[v].z, &z);
        v += 1;
    }
    P256Projective::new(x, y, z)
}

/// `k·G` by Horner over the comb columns: 64 doublings and 64 additions.
fn table_mul<K: FieldKernel<FieldDomain>>(
    k: &K,
    ca: &P256Field<K>,
    cb: &P256Field<K>,
    table: &Table<K>,
    scalar: &[Limb; LIMBS],
) -> P256Projective<K> {
    let mut acc = P256Projective::new(P256Field::zero(), one(k), P256Field::zero());
    let mut i = COLUMNS;
    while i > 0 {
        i -= 1;
        acc = rcb_double(k, ca, cb, &acc);
        let selected = select_point(k, table, column(scalar, i));
        acc = rcb_add(k, cb, &acc, &selected);
    }
    acc
}

// ---------------------------------------------------------------------------
// Inversion and affine export
// ---------------------------------------------------------------------------

/// `p - 2`, the public Fermat exponent. `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`.
const P_MINUS_2: [Limb; LIMBS] = [
    0xFFFF_FFFF_FFFF_FFFD,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// `a^(p-2)` by square-and-multiply over the **public** exponent `p-2`.
///
/// The exponent is a compile-time constant, so the branch on its bits carries no
/// secret; the base is secret and only ever feeds field multiplications. `a = 0`
/// maps to `0`, which is what the infinity export relies on.
fn invert<K: FieldKernel<FieldDomain>>(k: &K, a: &P256Field<K>) -> P256Field<K> {
    let mut result = one(k);
    let mut bit = 256;
    while bit > 0 {
        bit -= 1;
        result = fsqr(k, &result);
        let word = P_MINUS_2[bit / 64] >> (bit % 64);
        if word & 1 == 1 {
            result = fmul(k, &result, a);
        }
    }
    result
}

struct Affine {
    x: Canonical4,
    y: Canonical4,
    /// All ones when the projective input was the point at infinity.
    infinity: Limb,
}

fn to_affine<K: FieldKernel<FieldDomain>>(k: &K, p: &P256Projective<K>) -> Affine {
    // RCB's complete formulas are homogeneous projective: (X:Y:Z) denotes
    // the affine point (X/Z, Y/Z).
    let zinv = invert(k, &p.z);
    let x = fmul(k, &p.x, &zinv);
    let y = fmul(k, &p.y, &zinv);
    Affine {
        x: x.to_canonical(k),
        y: y.to_canonical(k),
        infinity: p.z.is_zero_mask(),
    }
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

/// True only when this group **is** the standard P-256 group: matching prime,
/// `a`, `b`, order, cofactor, generator and plain ladder method.
///
/// A modified generator fails the coordinate comparison; a custom curve fails
/// the curve-member comparison; a foreign method fails
/// [`ec_method_field_is_plain`] or the ladder-step identity. Each then keeps its
/// own semantics on the caller's ladder.
///
/// # Safety
///
/// `group` is NULL or a live `EC_GROUP`.
pub(crate) unsafe fn admits(group: *const EcGroup) -> bool {
    // SAFETY: the caller guarantees `group` is NULL or live; every field and
    // member read below belongs to that group.
    unsafe {
        if group.is_null() {
            return false;
        }
        let group = &*group;
        if group.field.is_null()
            || group.a.is_null()
            || group.b.is_null()
            || group.order.is_null()
            || group.cofactor.is_null()
            || group.generator.is_null()
        {
            return false;
        }

        // The method must be exactly the plain prime-field ladder this engine
        // mirrors. A custom curve built through `EC_GROUP_new_curve_GFp` uses the
        // Montgomery method and fails here.
        if !ec_method_field_is_plain(group.meth) {
            return false;
        }
        let step_ok = (*group.meth).ladder_step.is_some_and(|step| {
            core::ptr::fn_addr_eq(step, ossl_ec_GFp_simple_ladder_step as EcLadderFn)
        });
        if !step_ok {
            return false;
        }

        if (*group.field).d.as_slice() != FIELD_MODULUS.as_slice()
            || (*group.order).d.as_slice() != ORDER_MODULUS.as_slice()
            || (*group.a).d.as_slice() != p_minus_3().as_slice()
            || (*group.b).d.as_slice() != tracked_b().as_slice()
            || (*group.cofactor).d.as_slice() != [1u64].as_slice()
        {
            return false;
        }

        let generator = &*group.generator;
        if generator.z_is_one == 0 || generator.x.is_null() || generator.y.is_null() {
            return false;
        }
        if (*generator.x).d.as_slice() != tracked_gx().as_slice()
            || (*generator.y).d.as_slice() != tracked_gy().as_slice()
        {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[cfg(test)]
mod probe {
    use core::cell::Cell;

    thread_local! {
        static TAKEN: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn record() {
        TAKEN.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn count() -> u64 {
        TAKEN.with(|c| c.get())
    }
}

/// Attempt `k·G` on the fixed-base comb.
///
/// `None` means the call is not admitted (a different group, generator, method,
/// an out-of-range scalar, or a non-Mont kernel) and the caller must stay on the
/// ladder. `Some(1)` is a written result; `Some(0)` is a write-back failure.
///
/// # Safety
///
/// `group` is a live group; `r` is a live point compatible with it; `scalar` is a
/// live non-negative `BIGNUM` with at most four limbs. The caller (the
/// fixed-base arm of `ossl_ec_wNAF_mul`) establishes all three.
pub(crate) unsafe fn try_fixed_base_mul(
    group: *const EcGroup,
    r: *mut EcPoint,
    scalar: *const BigNum,
) -> Option<c_int> {
    // SAFETY: the caller guarantees the live objects above; `admits` re-checks
    // the group's identity, and every following read is of a live member.
    unsafe {
        if r.is_null() || scalar.is_null() {
            return None;
        }
        if !admits(group) {
            return None;
        }

        let scalar = &*scalar;
        if scalar.neg != 0 || scalar.d.len() > LIMBS {
            return None;
        }
        let mut k = [0u64; LIMBS];
        k[..scalar.d.len()].copy_from_slice(&scalar.d);
        // `k·G` for `k ≥ n` (or with high bits) keeps the generic path's own
        // mod-`n` semantics; the secret path is admitted only below `n`.
        if ct_ge(&k, &ORDER_MODULUS) != 0 {
            return None;
        }

        let SelectedFieldKernel::Mont(kernel) = select_field_kernel() else {
            return None;
        };
        let ca = P256Field::from_canonical(&kernel, &p_minus_3());
        let cb = P256Field::from_canonical(&kernel, &tracked_b());
        let table = mont_table();

        let proj = table_mul(&kernel, &ca, &cb, table, &k);
        let affine = to_affine(&kernel, &proj);

        // Affine write-back. `z` is 1 for a finite result and 0 for infinity; the
        // masks are already all-ones/all-zero, so the choice is branch-free.
        let z_value: Limb = 1 & !affine.infinity;
        if !store_coordinate((*r).x, affine.x.as_limbs())
            || !store_coordinate((*r).y, affine.y.as_limbs())
            || !store_coordinate((*r).z, core::slice::from_ref(&z_value))
        {
            return Some(0);
        }
        (*r).z_is_one = (!affine.infinity & 1) as c_int;

        #[cfg(test)]
        probe::record();

        Some(1)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod tests {
    use core::ptr;

    use super::*;
    use crate::bn::ctx::{BN_CTX_free, BN_CTX_new, BnCtx};
    use crate::bn::limbs;
    use crate::ec::curve::EC_GROUP_new_by_curve_name;
    use crate::ec::cvt::EC_GROUP_new_curve_GFp;
    use crate::ec::lib::{
        EC_GROUP_free, EC_GROUP_get0_generator, EC_GROUP_set_generator, EC_POINT_cmp,
        EC_POINT_copy, EC_POINT_free, EC_POINT_is_at_infinity, EC_POINT_mul, EC_POINT_new,
        EC_POINT_set_affine_coordinates,
    };
    use crate::runtime::obj::NID_X9_62_prime256v1;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn bn(limbs: Vec<Limb>) -> BigNum {
        let mut d = limbs;
        limbs::normalise(&mut d);
        BigNum {
            d,
            neg: 0,
            flags: 0,
        }
    }

    fn reduce_mod_order(v: &[Limb]) -> BigNum {
        let m = ORDER_MODULUS.to_vec();
        let r = limbs::rem_fallible(v, &m).expect("reference reduction mod order");
        bn(r)
    }

    struct Ctx {
        group: *mut EcGroup,
        ctx: *mut BnCtx,
        fast: *mut EcPoint,
        ladder: *mut EcPoint,
    }

    impl Ctx {
        unsafe fn new() -> Self {
            // SAFETY: every object is created here and released in `Drop`.
            unsafe {
                let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
                assert!(!group.is_null());
                let ctx = BN_CTX_new();
                assert!(!ctx.is_null());
                let fast = EC_POINT_new(group);
                let ladder = EC_POINT_new(group);
                assert!(!fast.is_null() && !ladder.is_null());
                Self {
                    group,
                    ctx,
                    fast,
                    ladder,
                }
            }
        }
    }

    impl Drop for Ctx {
        fn drop(&mut self) {
            // SAFETY: the pointers were created in `new` and are released once.
            unsafe {
                EC_POINT_free(self.fast);
                EC_POINT_free(self.ladder);
                BN_CTX_free(self.ctx);
                EC_GROUP_free(self.group);
            }
        }
    }

    /// `k·G` through the fast arm and through the variable-base ladder must be
    /// the same point for every admitted scalar. The population includes the
    /// exceptional scalars and several thousand pseudorandom values reduced mod
    /// `n`.
    #[test]
    fn fixed_and_variable_base_agree_over_thousands() {
        const CASES: usize = 4096;
        // SAFETY: all objects live for the test and are released by `Ctx`.
        unsafe {
            let c = Ctx::new();
            let generator = EC_GROUP_get0_generator(c.group);
            assert!(!generator.is_null());
            assert!(admits(c.group), "the standard group must be admitted");

            let mut rng = Rng(0x5046_5033_5046_5033);
            let before = probe::count();
            for case in 0..CASES {
                let scalar = match case {
                    0 => bn(Vec::new()),
                    1 => bn(vec![1]),
                    2 => bn(vec![2]),
                    3 => bn(vec![3]),
                    4 => {
                        let mut n_minus_1 = ORDER_MODULUS.to_vec();
                        n_minus_1[0] -= 1;
                        bn(n_minus_1)
                    }
                    5 => {
                        let mut n_minus_2 = ORDER_MODULUS.to_vec();
                        n_minus_2[0] -= 2;
                        bn(n_minus_2)
                    }
                    6 => bn(vec![0, 1]),
                    7 => bn(vec![0, 0, 1]),
                    8 => bn(vec![0, 0, 0, 1]),
                    9 => bn(vec![u64::MAX, u64::MAX, u64::MAX, 0]),
                    _ => {
                        let raw = [rng.next(), rng.next(), rng.next(), rng.next()];
                        reduce_mod_order(&raw)
                    }
                };

                assert_eq!(
                    EC_POINT_mul(
                        c.group,
                        c.fast,
                        &scalar,
                        ptr::null(),
                        ptr::null_mut(),
                        c.ctx
                    ),
                    1,
                    "case {case}: fixed-base arm"
                );
                assert_eq!(
                    EC_POINT_mul(c.group, c.ladder, ptr::null(), generator, &scalar, c.ctx),
                    1,
                    "case {case}: ladder arm"
                );
                assert_eq!(
                    EC_POINT_cmp(c.group, c.fast, c.ladder, c.ctx),
                    0,
                    "case {case}: the fixed-base arm moved the point, scalar {:x?}",
                    scalar.d
                );
                match case {
                    0 => assert_eq!(EC_POINT_is_at_infinity(c.group, c.fast), 1),
                    1 => assert_eq!(EC_POINT_cmp(c.group, c.fast, generator, c.ctx), 0),
                    _ => {}
                }
            }
            // The fast arm must actually have run, not fallen back 4,096 times.
            assert_eq!(probe::count() - before, CASES as u64);
        }
    }

    /// The admitted arm is the one `EC_POINT_mul` takes for `k·G` on the standard
    /// group, and it yields the generator for `k = 1`.
    #[test]
    fn the_fast_arm_is_reachable() {
        // SAFETY: all objects live for the test and are released by `Ctx`.
        unsafe {
            let c = Ctx::new();
            let before = probe::count();
            let one = bn(vec![1]);
            assert_eq!(
                EC_POINT_mul(c.group, c.fast, &one, ptr::null(), ptr::null_mut(), c.ctx),
                1
            );
            assert_eq!(probe::count(), before + 1);
            let generator = EC_GROUP_get0_generator(c.group);
            assert_eq!(EC_POINT_cmp(c.group, c.fast, generator, c.ctx), 0);
        }
    }

    /// Drive `k·point` on a group that must be refused and confirm (a) admission
    /// fails, (b) the fast arm is not entered, and (c) the result still matches
    /// the variable-base ladder on that same group.
    unsafe fn refusal_case(group: *mut EcGroup) {
        // SAFETY: the caller supplies a live group; points and a context are made
        // and released here.
        unsafe {
            assert!(!admits(group), "the non-standard group must be refused");
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let fast = EC_POINT_new(group);
            let ladder = EC_POINT_new(group);
            assert!(!fast.is_null() && !ladder.is_null());
            let generator = EC_GROUP_get0_generator(group);
            assert!(!generator.is_null());

            let scalar = bn(vec![0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321]);
            let before = probe::count();
            assert_eq!(
                EC_POINT_mul(group, fast, &scalar, ptr::null(), ptr::null_mut(), ctx),
                1
            );
            assert_eq!(probe::count(), before, "the fast arm must not run");
            assert_eq!(
                EC_POINT_mul(group, ladder, ptr::null(), generator, &scalar, ctx),
                1
            );
            assert_eq!(EC_POINT_cmp(group, fast, ladder, ctx), 0);

            EC_POINT_free(fast);
            EC_POINT_free(ladder);
            BN_CTX_free(ctx);
        }
    }

    /// A modified generator keeps its own semantics.
    #[test]
    fn a_modified_generator_is_refused() {
        // SAFETY: all objects live for the test and are released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!group.is_null());
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let two = bn(vec![2]);
            let two_g = EC_POINT_new(group);
            assert!(!two_g.is_null());
            assert_eq!(
                EC_POINT_mul(group, two_g, &two, ptr::null(), ptr::null_mut(), ctx),
                1
            );
            assert_eq!(
                EC_GROUP_set_generator(group, two_g, (*group).order, (*group).cofactor),
                1
            );
            refusal_case(group);

            EC_POINT_free(two_g);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
        }
    }

    /// A group whose generator is standard but whose order is not keeps its own
    /// semantics.
    #[test]
    fn a_modified_order_is_refused() {
        // SAFETY: all objects live for the test and are released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!group.is_null());
            let generator_copy = EC_POINT_new(group);
            assert!(!generator_copy.is_null());
            assert_eq!(
                EC_POINT_copy(generator_copy, EC_GROUP_get0_generator(group)),
                1
            );
            let mut n_minus_1 = ORDER_MODULUS.to_vec();
            n_minus_1[0] -= 1;
            let n_minus_1 = bn(n_minus_1);
            assert_eq!(
                EC_GROUP_set_generator(group, generator_copy, &n_minus_1, (*group).cofactor),
                1
            );
            refusal_case(group);

            EC_POINT_free(generator_copy);
            EC_GROUP_free(group);
        }
    }

    /// A foreign method (`EC_GFp_mont_method`, the method
    /// `EC_GROUP_new_curve_GFp` installs) with the standard prime, curve and
    /// generator is refused on the method predicate alone.
    #[test]
    fn a_foreign_method_is_refused() {
        // SAFETY: all objects live for the test and are released here.
        unsafe {
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let p = bn(FIELD_MODULUS.to_vec());
            let a = bn(p_minus_3().to_vec());
            let b = bn(tracked_b().to_vec());
            let group = EC_GROUP_new_curve_GFp(&p, &a, &b, ctx);
            assert!(!group.is_null());
            let g = EC_POINT_new(group);
            assert!(!g.is_null());
            let gx = bn(tracked_gx().to_vec());
            let gy = bn(tracked_gy().to_vec());
            assert_eq!(EC_POINT_set_affine_coordinates(group, g, &gx, &gy, ctx), 1);
            let order = bn(ORDER_MODULUS.to_vec());
            let cofactor = bn(vec![1]);
            assert_eq!(EC_GROUP_set_generator(group, g, &order, &cofactor), 1);
            refusal_case(group);

            EC_POINT_free(g);
            EC_GROUP_free(group);
            BN_CTX_free(ctx);
        }
    }

    /// A custom curve — a different named curve with its own valid generator —
    /// keeps its own semantics.
    #[test]
    fn a_different_curve_is_refused() {
        use crate::runtime::obj::NID_secp256k1;
        // SAFETY: all objects live for the test and are released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp256k1);
            assert!(!group.is_null());
            refusal_case(group);
            EC_GROUP_free(group);
        }
    }

    /// Convert a Jacobian point to affine `(x, y)`: `(X/Z², Y/Z³)`.
    fn jacobian_affine(
        kernel: &Mont<FieldDomain>,
        p: &P256Projective<Mont<FieldDomain>>,
    ) -> (Canonical4, Canonical4) {
        let zinv = invert(kernel, &p.z);
        let zinv2 = fsqr(kernel, &zinv);
        let zinv3 = fmul(kernel, &zinv2, &zinv);
        let x = fmul(kernel, &p.x, &zinv2);
        let y = fmul(kernel, &p.y, &zinv3);
        (x.to_canonical(kernel), y.to_canonical(kernel))
    }

    /// The Jacobian reference schedule is correct on the non-exceptional inputs it
    /// admits (`dbl-2001-b` a=-3 doubling, `add-2007-bl` addition), checked against
    /// the variable-base ladder.
    #[test]
    fn the_jacobian_reference_matches_the_ladder() {
        // SAFETY: all objects live for the test and are released here.
        unsafe {
            let c = Ctx::new();
            let kernel = Mont::<FieldDomain>::default();
            let g = P256Projective::new(
                P256Field::from_canonical(&kernel, &tracked_gx()),
                P256Field::from_canonical(&kernel, &tracked_gy()),
                one(&kernel),
            );

            let two = jacobian::double(&kernel, &g);
            let three = jacobian::add(&kernel, &g, &two);

            let point = EC_POINT_new(c.group);
            let expected = EC_POINT_new(c.group);
            assert!(!point.is_null() && !expected.is_null());
            let generator = EC_GROUP_get0_generator(c.group);

            for (actual, scalar) in [(two, 2u64), (three, 3u64)] {
                let (x, y) = jacobian_affine(&kernel, &actual);
                let xb = bn(x.as_limbs().to_vec());
                let yb = bn(y.as_limbs().to_vec());
                assert_eq!(
                    EC_POINT_set_affine_coordinates(c.group, point, &xb, &yb, c.ctx),
                    1
                );
                let k = bn(vec![scalar]);
                assert_eq!(
                    EC_POINT_mul(c.group, expected, ptr::null(), generator, &k, c.ctx),
                    1
                );
                assert_eq!(
                    EC_POINT_cmp(c.group, point, expected, c.ctx),
                    0,
                    "Jacobian reference disagrees with the ladder for {scalar}G"
                );
            }

            EC_POINT_free(point);
            EC_POINT_free(expected);
        }
    }

    /// Homogeneous projective equality: `(X1:Y1:Z1) ~ (X2:Y2:Z2)` when
    /// `X1·Z2 = X2·Z1` and `Y1·Z2 = Y2·Z1` (both at infinity when `Z1 = Z2 = 0`).
    fn projectively_equal(
        kernel: &Mont<FieldDomain>,
        a: &P256Projective<Mont<FieldDomain>>,
        b: &P256Projective<Mont<FieldDomain>>,
    ) -> bool {
        let zero = P256Field::<Mont<FieldDomain>>::zero();
        let xz = fsub(kernel, &fmul(kernel, &a.x, &b.z), &fmul(kernel, &b.x, &a.z));
        let yz = fsub(kernel, &fmul(kernel, &a.y, &b.z), &fmul(kernel, &b.y, &a.z));
        let _ = zero;
        xz.is_zero_mask() != 0 && yz.is_zero_mask() != 0
    }

    /// The complete formula pins the exceptional cases PFP-22 names: infinity,
    /// doubling, `P + (-P)`, and the generator as a non-special point.
    #[test]
    fn the_complete_formula_pins_the_exceptional_cases() {
        let kernel = Mont::<FieldDomain>::default();
        let ca = P256Field::from_canonical(&kernel, &p_minus_3());
        let cb = P256Field::from_canonical(&kernel, &tracked_b());
        let g = P256Projective::new(
            P256Field::from_canonical(&kernel, &tracked_gx()),
            P256Field::from_canonical(&kernel, &tracked_gy()),
            one(&kernel),
        );
        let infinity = P256Projective::new(P256Field::zero(), one(&kernel), P256Field::zero());

        // infinity + G = G and G + infinity = G
        assert!(projectively_equal(
            &kernel,
            &rcb_add(&kernel, &cb, &infinity, &g),
            &g
        ));
        assert!(projectively_equal(
            &kernel,
            &rcb_add(&kernel, &cb, &g, &infinity),
            &g
        ));

        // G + G = 2G, the doubling case.
        let two = rcb_add(&kernel, &cb, &g, &g);
        assert!(projectively_equal(
            &kernel,
            &two,
            &rcb_double(&kernel, &ca, &cb, &g)
        ));

        // G + (-G) = infinity.
        let mut neg_x = P256Field::zero();
        neg_x.copy_from(&g.x);
        let mut neg_z = P256Field::zero();
        neg_z.copy_from(&g.z);
        let neg_y = fsub(&kernel, &P256Field::zero(), &g.y);
        let neg_g = P256Projective::new(neg_x, neg_y, neg_z);
        let sum = rcb_add(&kernel, &cb, &g, &neg_g);
        assert_ne!(sum.z.is_zero_mask(), 0, "G + (-G) must be infinity");

        // 2·infinity = infinity.
        let doubled_infinity = rcb_double(&kernel, &ca, &cb, &infinity);
        assert_ne!(doubled_infinity.z.is_zero_mask(), 0);
    }

    /// A field kernel that counts multiplications and squarings, so the formula
    /// comparison is measured rather than asserted.
    struct Counting {
        inner: Mont<FieldDomain>,
        m: core::cell::Cell<usize>,
        s: core::cell::Cell<usize>,
    }

    impl Counting {
        fn new() -> Self {
            Self {
                inner: Mont::<FieldDomain>::default(),
                m: core::cell::Cell::new(0),
                s: core::cell::Cell::new(0),
            }
        }

        fn reset(&self) {
            self.m.set(0);
            self.s.set(0);
        }

        fn counts(&self) -> (usize, usize, f64) {
            let m = self.m.get();
            let s = self.s.get();
            // Conventional weights: one multiplication 1.0, one squaring 0.8.
            (m, s, m as f64 + 0.8 * s as f64)
        }
    }

    impl FieldKernel<FieldDomain> for Counting {
        const ID: KernelId = KernelId::Mont;

        fn from_limbs(&self, out: &mut [Limb; LIMBS], ordinary: &[Limb; LIMBS]) {
            self.inner.from_limbs(out, ordinary)
        }
        fn to_limbs(&self, out: &mut [Limb; LIMBS], repr: &[Limb; LIMBS]) {
            self.inner.to_limbs(out, repr)
        }
        fn mul(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
            self.m.set(self.m.get() + 1);
            self.inner.mul(out, a, b)
        }
        fn sqr(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS]) {
            self.s.set(self.s.get() + 1);
            self.inner.sqr(out, a)
        }
        fn add(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
            self.inner.add(out, a, b)
        }
        fn sub(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
            self.inner.sub(out, a, b)
        }
        fn reduce(&self, out: &mut [Limb; LIMBS], wide: &[Limb; 8]) {
            self.inner.reduce(out, wide)
        }
        fn select(
            &self,
            out: &mut [Limb; LIMBS],
            mask: Limb,
            a: &[Limb; LIMBS],
            b: &[Limb; LIMBS],
        ) {
            self.inner.select(out, mask, a, b)
        }
        fn cswap(&self, mask: Limb, a: &mut [Limb; LIMBS], b: &mut [Limb; LIMBS]) {
            self.inner.cswap(mask, a, b)
        }
    }

    /// Measure both schedules' multiplication/squaring counts and the weighted cost
    /// of the comb's actual mix (64 additions + 64 doublings).
    #[test]
    fn formula_weighted_cost_is_measured() {
        let k = Counting::new();
        let ca = P256Field::from_canonical(&k, &p_minus_3());
        let cb = P256Field::from_canonical(&k, &tracked_b());
        let g = P256Projective::new(
            P256Field::from_canonical(&k, &tracked_gx()),
            P256Field::from_canonical(&k, &tracked_gy()),
            one(&k),
        );
        let two = jacobian::double(&k, &g);

        k.reset();
        let _ = rcb_add(&k, &cb, &g, &g);
        let rcb_add_cost = k.counts();

        k.reset();
        let _ = rcb_double(&k, &ca, &cb, &g);
        let rcb_dbl_cost = k.counts();

        k.reset();
        let _ = jacobian::double(&k, &g);
        let jac_dbl_cost = k.counts();

        k.reset();
        let _ = jacobian::add(&k, &g, &two);
        let jac_add_cost = k.counts();

        // Structure of the schedules (M, S).
        assert_eq!((rcb_add_cost.0, rcb_add_cost.1), (14, 0));
        assert_eq!((rcb_dbl_cost.0, rcb_dbl_cost.1), (14, 0));
        assert_eq!((jac_dbl_cost.0, jac_dbl_cost.1), (3, 5));
        assert_eq!((jac_add_cost.0, jac_add_cost.1), (11, 5));

        let rcb_mix = 64.0 * (rcb_add_cost.2 + rcb_dbl_cost.2);
        let jac_mix = 64.0 * (jac_add_cost.2 + jac_dbl_cost.2);
        println!(
            "RCB add {:.1} dbl {:.1} mix {:.1}; Jacobian add {:.1} dbl {:.1} mix {:.1}",
            rcb_add_cost.2, rcb_dbl_cost.2, rcb_mix, jac_add_cost.2, jac_dbl_cost.2, jac_mix
        );
        // The raw Jacobian mix is cheaper; the admitted arm is RCB because the
        // Jacobian addition is not complete. Record the measured relationship.
        assert!(jac_mix < rcb_mix);
    }
}
