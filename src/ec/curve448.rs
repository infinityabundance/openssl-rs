//! `crypto/ec/curve448/` — X448 and Ed448, Phase 8.7.
//!
//! Six translation units, 3,400-odd lines: `scalar.c` (the scalar ring `Z/l`), `f_generic.c`
//! (the field operations the per-architecture units do not provide), `arch_64/f_impl64.c`
//! (the 64-bit field multiply, square and multiply-by-constant), `curve448.c` (the Edwards
//! group, the X448 ladder and the variable-time double scalar multiplication), `eddsa.c`
//! (the Ed448 signature scheme) and `curve448_tables.c` (two constant tables, generated).
//! On the admitted profile `ARCH_WORD_BITS` and `C448_WORD_BITS` are both 64, so `word_t` is
//! `u64`, `NLIMBS` is 8 and `C448_SCALAR_LIMBS` is 7; the 32-bit arms are not compiled and
//! are not here.
//!
//! ## What this module keeps, and the two places it deliberately differs
//!
//! The field is base `2^56` with **headroom 9999** (`arch_64/f_impl.h`), so `gf_bias` is a
//! no-op and only `gf_add_RAW`/`gf_sub_RAW` weakly reduce; `gf_sub_nr`/`gf_subx_nr` are
//! therefore `gf_sub_RAW` on this profile and the "3+e"/"6+e" comments in `curve448.c` are
//! the authority's own accounting for the arithmetic that *does* happen. That is transcribed
//! as written, and the difference is recorded at the sites below rather than smoothed.
//!
//! Two shapes a reader should know before comparing this file with the C:
//!
//! * `value_barrier_64` is OpenSSL's optimisation barrier, an empty inline-asm statement whose
//!   job is to stop the compiler turning a masked select into a branch. The Rust equivalent is
//!   [`core::hint::black_box`], and it is used at exactly the two sites the C uses the barrier
//!   (`constant_time_select_64` and `constant_time_cond_swap_64`, plus `scalar_halve`).
//! * `constant_time_lookup` copies a table row byte by byte. [`ct_lookup_niels`] selects
//!   limb by limb over the `niels_t` fields instead — the same masked selection over the same
//!   bytes, with the same fixed iteration count and no secret-dependent branch.
//!
//! ## The boundary this module does not cross
//!
//! Every one of these names is an internal symbol; none is an export, and the six units raise
//! nothing (`ERR_raise` count zero in all six), so none is in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`. `RT-ECX`'s differential arms arrive with `ecx_meth.c`'s method tables,
//! which are still withheld; the evidence here is `src/ec/curve448.rs`'s unit tests, which run
//! RFC 7748 §6.2's X448 vectors and RFC 8032 §7.4's Ed448 vectors (empty, one-byte and
//! 11-byte messages; sign and verify; the RFC's own public-key derivation) and therefore
//! exercise every entry of the generated comb table.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::hint::black_box;
use core::ptr;

use crate::ec::curve448_tables::{CURVE448_PRECOMPUTED_BASE, CURVE448_WNAF_BASE};
use crate::evp::digest::{
    EVP_DigestFinalXOF, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free, EvpMdCtx,
};
use crate::runtime::mem::OPENSSL_cleanse;

const NLIMBS: usize = 8;
const SER_BYTES: usize = 56;
const X_SER_BYTES: usize = 56;
const LIMB_MASK: u64 = (1u64 << 56) - 1;
const X_PRIVATE_BITS: usize = 448;
const COFACTOR: u8 = 4;

/// `C448_SCALAR_LIMBS` — `point_448.h:38`.
const SCALAR_LIMBS: usize = 7;
/// `C448_SCALAR_BITS` — `point_448.h:41`.
const SCALAR_BITS: usize = 446;
/// `C448_SCALAR_BYTES` — `point_448.h:44`.
const SCALAR_BYTES: usize = 56;
/// `C448_EDDSA_ENCODE_RATIO` — `ed448.h:28`.
const EDDSA_ENCODE_RATIO: usize = 4;
/// `EDDSA_448_PUBLIC_BYTES` — `ed448.h:19`.
const EDDSA_PUBLIC_BYTES: usize = 57;
/// `EDDSA_448_PRIVATE_BYTES` — `ed448.h:22`.
const EDDSA_PRIVATE_BYTES: usize = 57;
/// `EDDSA_448_SIGNATURE_BYTES` — `ed448.h:25`.
const EDDSA_SIGNATURE_BYTES: usize = 114;
/// `C448_WNAF_FIXED_TABLE_BITS` — `curve448.c:23`.
const WNAF_FIXED_TABLE_BITS: usize = 5;
/// `C448_WNAF_VAR_TABLE_BITS` — `curve448.c:24`.
const WNAF_VAR_TABLE_BITS: usize = 3;
/// `EDWARDS_D` — `curve448.c:26`.
const EDWARDS_D: i32 = -39081;
/// `TWISTED_D` — `curve448.c:33`.
const TWISTED_D: i32 = EDWARDS_D - 1;
/// `COMBS_N`, `COMBS_T`, `COMBS_S` — `point_448.h:20-22`.
const COMBS_N: usize = 5;
const COMBS_T: usize = 5;
const COMBS_S: usize = 18;

const C448_SUCCESS: c_int = -1;
const C448_FAILURE: c_int = 0;

/// A base-`2^56` field element, eight limbs with headroom 9999 — `arch_64/f_impl.h`.
type Gf = [u64; NLIMBS];
/// A packed scalar, `C448_SCALAR_LIMBS` words — `point_448.h:67`.
type Scalar = [u64; SCALAR_LIMBS];

/// `niels_s` — projective Niels `(a, b, c)` — `point_448.h:25`.
#[derive(Clone, Copy)]
struct Niels {
    a: Gf,
    b: Gf,
    c: Gf,
}

/// `pniels_t` — `(n, z)` — `point_448.h:28`.
#[derive(Clone, Copy)]
struct Pniels {
    n: Niels,
    z: Gf,
}

/// `curve448_point_s` — extended `(x, y, z, t)` — `point_448.h:56`.
#[derive(Clone, Copy)]
struct Point {
    x: Gf,
    y: Gf,
    z: Gf,
    t: Gf,
}

/// `struct smvt_control` — `curve448.c:501`.
#[derive(Clone, Copy)]
struct SmvtControl {
    power: c_int,
    addend: c_int,
}

const ZERO: Gf = [0; NLIMBS];
const ONE: Gf = [1, 0, 0, 0, 0, 0, 0, 0];

/// `MODULUS` — `f_generic.c:14`.
const MODULUS: Gf = [
    0xffffffffffffff,
    0xffffffffffffff,
    0xffffffffffffff,
    0xffffffffffffff,
    0xfffffffffffffe,
    0xffffffffffffff,
    0xffffffffffffff,
    0xffffffffffffff,
];

/// `sc_p` — `scalar.c:18`.
const SC_P: Scalar = [
    0x2378c292ab5844f3,
    0x216cc2728dc58f55,
    0xc44edb49aed63690,
    0xffffffff7cca23e9,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x3fffffffffffffff,
];

/// `sc_r2` — `scalar.c:24`.
const SC_R2: Scalar = [
    0xe3539257049b9b60,
    0x7af32c4bc1b195d9,
    0x0d66de2388ea1859,
    0xae17cf725ee4d838,
    0x1a9cc14ba3c47c44,
    0x2052bcb7e4d070af,
    0x3402a939f823b729,
];

/// `MONTGOMERY_FACTOR` — `scalar.c:17`.
const MONTGOMERY_FACTOR: u64 = 0x3bd440fae918bc5;

/// `precomputed_scalarmul_adjustment` — `curve448.c:28`.
const PRECOMPUTED_ADJUSTMENT: Scalar = [
    0xc873d6d54a7bb0cf,
    0xe933d8d723a70aad,
    0xbb124b65129c96fd,
    0x00000008335dc163,
    0,
    0,
    0,
];

const SCALAR_ONE: Scalar = [1, 0, 0, 0, 0, 0, 0];
const SCALAR_ZERO: Scalar = [0; SCALAR_LIMBS];

/// `ossl_curve448_point_identity` — `curve448.c:54`.
const POINT_IDENTITY: Point = Point {
    x: ZERO,
    y: ONE,
    z: ONE,
    t: ZERO,
};

/// `ossl_curve448_point_identity` — `curve448.c:54`; the C global, as its four `gf` limbs.
#[no_mangle]
pub static ossl_curve448_point_identity: [[u64; NLIMBS]; 4] = [ZERO, ONE, ONE, ZERO];

/// `ossl_curve448_scalar_one` — `scalar.c:30`.
#[no_mangle]
pub static ossl_curve448_scalar_one: Scalar = SCALAR_ONE;

/// `ossl_curve448_scalar_zero` — `scalar.c:31`.
#[no_mangle]
pub static ossl_curve448_scalar_zero: Scalar = SCALAR_ZERO;

/// `ossl_curve448_precomputed_base` — `curve448_tables.c:1138`; a `const struct
/// curve448_precomputed_s *`, held as a reference to the generated table.
#[no_mangle]
pub static ossl_curve448_precomputed_base: &[u64; 80 * 3 * NLIMBS] = &CURVE448_PRECOMPUTED_BASE;

/// `ossl_curve448_wnaf_base` — `curve448_tables.c:1591`.
#[no_mangle]
pub static ossl_curve448_wnaf_base: &[u64; 32 * 3 * NLIMBS] = &CURVE448_WNAF_BASE;

// =====================================================================================
// The constant-time helpers (`include/internal/constant_time.h`, 64-bit arms)
// =====================================================================================

/// `constant_time_msb_64(a) = 0 - (a >> 63)`.
fn ct_msb_64(a: u64) -> u64 {
    0u64.wrapping_sub(a >> 63)
}

/// `constant_time_is_zero_64(a) = constant_time_msb_64(~a & (a - 1))`.
fn ct_is_zero_64(a: u64) -> u64 {
    ct_msb_64((!a) & a.wrapping_sub(1))
}

/// `value_barrier_64(a)` — `constant_time.h:300`; the Rust barrier is [`black_box`].
fn value_barrier_64(a: u64) -> u64 {
    black_box(a)
}

/// `constant_time_select_64(mask, a, b)` — `constant_time.h:374`.
fn ct_select_64(mask: u64, a: u64, b: u64) -> u64 {
    (value_barrier_64(mask) & a) | (value_barrier_64(!mask) & b)
}

/// `constant_time_cond_swap_64(mask, a, b)` — `constant_time.h:410`.
fn ct_cond_swap_64(mask: u64, a: &mut u64, b: &mut u64) {
    let mut xor = *a ^ *b;
    xor &= value_barrier_64(mask);
    *a ^= xor;
    *b ^= xor;
}

/// `constant_time_lookup` over `niels_t` rows — `curve25519.c`'s `constant_time_lookup_niels`
/// analogue at `curve448.c:220`.
#[allow(clippy::needless_range_loop)] // the row index is the mask's position
fn ct_lookup_niels(table: &[Niels], nelts: usize, idx: usize) -> Niels {
    let mut out = Niels {
        a: [0; NLIMBS],
        b: [0; NLIMBS],
        c: [0; NLIMBS],
    };
    let mut idx = idx;
    for i in 0..nelts {
        // `idx` may underflow, and that is well defined in the authority's `size_t` walk.
        let mask = ct_is_zero_64(idx as u64);
        for limb in 0..NLIMBS {
            out.a[limb] |= mask & table[i].a[limb];
            out.b[limb] |= mask & table[i].b[limb];
            out.c[limb] |= mask & table[i].c[limb];
        }
        idx = idx.wrapping_sub(1);
    }
    out
}

// =====================================================================================
// `arch_64/f_impl64.c` and `arch_64/f_impl.h`: the field
// =====================================================================================

/// `gf_weak_reduce` — `arch_64/f_impl.h:51`.
fn gf_weak_reduce(a: &mut Gf) {
    let tmp = a[NLIMBS - 1] >> 56;
    a[NLIMBS / 2] = a[NLIMBS / 2].wrapping_add(tmp);
    for i in (1..NLIMBS).rev() {
        a[i] = (a[i] & LIMB_MASK) + (a[i - 1] >> 56);
    }
    a[0] = (a[0] & LIMB_MASK) + tmp;
}

/// `gf_add_RAW` — `arch_64/f_impl.h:26`.
fn gf_add_raw(a: &Gf, b: &Gf) -> Gf {
    let mut out = [0u64; NLIMBS];
    for i in 0..NLIMBS {
        out[i] = a[i].wrapping_add(b[i]);
    }
    gf_weak_reduce(&mut out);
    out
}

/// `gf_sub_RAW` — `arch_64/f_impl.h:36`.
fn gf_sub_raw(a: &Gf, b: &Gf) -> Gf {
    let co1 = ((1u64 << 56) - 1) * 2;
    let co2 = co1 - 2;
    let mut out = [0u64; NLIMBS];
    for i in 0..NLIMBS {
        out[i] = a[i]
            .wrapping_sub(b[i])
            .wrapping_add(if i == NLIMBS / 2 { co2 } else { co1 });
    }
    gf_weak_reduce(&mut out);
    out
}

/// `gf_bias` — `arch_64/f_impl.h:47`: headroom 9999 makes this a no-op on this profile.
fn gf_bias(_a: &mut Gf, _amt: c_int) {}

/// `gf_add_nr` — `field.h:100`.
fn gf_add_nr(a: &Gf, b: &Gf) -> Gf {
    gf_add_raw(a, b)
}

/// `gf_sub_nr` — `field.h:103`; `GF_HEADROOM >= 3` here so the reduce is skipped.
fn gf_sub_nr(a: &Gf, b: &Gf) -> Gf {
    gf_sub_raw(a, b)
}

/// `gf_subx_nr` — `field.h:112`; the headroom test is false here so the reduce is skipped.
fn gf_subx_nr(a: &Gf, b: &Gf, _amt: c_int) -> Gf {
    gf_sub_raw(a, b)
}

/// `ossl_gf_mulw_unsigned` — `arch_64/f_impl64.c:76`.
fn gf_mulw_unsigned(a: &Gf, b: u32) -> Gf {
    let mut c = [0u64; NLIMBS];
    let mut accum0: u128 = 0;
    let mut accum4: u128 = 0;
    for i in 0..4 {
        accum0 = accum0.wrapping_add((b as u128).wrapping_mul(a[i] as u128));
        accum4 = accum4.wrapping_add((b as u128).wrapping_mul(a[i + 4] as u128));
        c[i] = (accum0 as u64) & LIMB_MASK;
        accum0 >>= 56;
        c[i + 4] = (accum4 as u64) & LIMB_MASK;
        accum4 >>= 56;
    }
    accum0 = accum0.wrapping_add(accum4).wrapping_add(c[4] as u128);
    c[4] = (accum0 as u64) & LIMB_MASK;
    c[5] = c[5].wrapping_add((accum0 >> 56) as u64);
    accum4 = accum4.wrapping_add(c[0] as u128);
    c[0] = (accum4 as u64) & LIMB_MASK;
    c[1] = c[1].wrapping_add((accum4 >> 56) as u64);
    c
}

/// `gf_mulw` — `field.h:121`; not constant-time in the sign of `w`, exactly as the authority
/// notes.
fn gf_mulw(a: &Gf, w: i32) -> Gf {
    if w > 0 {
        gf_mulw_unsigned(a, w as u32)
    } else {
        let c = gf_mulw_unsigned(a, (-w) as u32);
        gf_sub_raw(&ZERO, &c)
    }
}

/// `ossl_gf_mul` — `arch_64/f_impl64.c:24`.
fn gf_mul(as_: &Gf, bs: &Gf) -> Gf {
    let a = as_;
    let b = bs;
    let mut c = [0u64; NLIMBS];
    let mut accum0: u128 = 0;
    let mut accum1: u128 = 0;
    let mut accum2: u128;
    let mut aa = [0u64; 4];
    let mut bb = [0u64; 4];
    let mut bbb = [0u64; 4];

    for i in 0..4 {
        aa[i] = a[i].wrapping_add(a[i + 4]);
        bb[i] = b[i].wrapping_add(b[i + 4]);
        bbb[i] = bb[i].wrapping_add(b[i + 4]);
    }

    for i in 0..4 {
        accum2 = 0;
        let mut j = 0;
        while j <= i {
            accum2 = accum2.wrapping_add((a[j] as u128).wrapping_mul(b[i - j] as u128));
            accum1 = accum1.wrapping_add((aa[j] as u128).wrapping_mul(bb[i - j] as u128));
            accum0 = accum0.wrapping_add((a[j + 4] as u128).wrapping_mul(b[i - j + 4] as u128));
            j += 1;
        }
        while j < 4 {
            accum2 = accum2.wrapping_add((a[j] as u128).wrapping_mul(b[i + 8 - j] as u128));
            accum1 = accum1.wrapping_add((aa[j] as u128).wrapping_mul(bbb[i + 4 - j] as u128));
            accum0 = accum0.wrapping_add((a[j + 4] as u128).wrapping_mul(bb[i + 4 - j] as u128));
            j += 1;
        }
        accum1 = accum1.wrapping_sub(accum2);
        accum0 = accum0.wrapping_add(accum2);

        c[i] = (accum0 as u64) & LIMB_MASK;
        c[i + 4] = (accum1 as u64) & LIMB_MASK;
        accum0 >>= 56;
        accum1 >>= 56;
    }

    accum0 = accum0.wrapping_add(accum1);
    accum0 = accum0.wrapping_add(c[4] as u128);
    accum1 = accum1.wrapping_add(c[0] as u128);
    c[4] = (accum0 as u64) & LIMB_MASK;
    c[0] = (accum1 as u64) & LIMB_MASK;
    accum0 >>= 56;
    accum1 >>= 56;
    c[5] = c[5].wrapping_add(accum0 as u64);
    c[1] = c[1].wrapping_add(accum1 as u64);
    c
}

/// `ossl_gf_sqr` — `arch_64/f_impl64.c:102`.
fn gf_sqr(as_: &Gf) -> Gf {
    let a = as_;
    let mut c = [0u64; NLIMBS];
    let mut accum0: u128;
    let mut accum1: u128;
    let mut accum2: u128;
    let mut aa = [0u64; 4];

    for i in 0..4 {
        aa[i] = a[i].wrapping_add(a[i + 4]);
    }

    accum2 = (a[0] as u128).wrapping_mul(a[3] as u128);
    accum0 = (aa[0] as u128).wrapping_mul(aa[3] as u128);
    accum1 = (a[4] as u128).wrapping_mul(a[7] as u128);
    accum2 = accum2.wrapping_add((a[1] as u128).wrapping_mul(a[2] as u128));
    accum0 = accum0.wrapping_add((aa[1] as u128).wrapping_mul(aa[2] as u128));
    accum1 = accum1.wrapping_add((a[5] as u128).wrapping_mul(a[6] as u128));
    accum0 = accum0.wrapping_sub(accum2);
    accum1 = accum1.wrapping_add(accum2);

    c[3] = ((accum1 as u64) << 1) & LIMB_MASK;
    c[7] = ((accum0 as u64) << 1) & LIMB_MASK;
    accum0 >>= 55;
    accum1 >>= 55;

    accum0 = accum0.wrapping_add(((2 * aa[1]) as u128).wrapping_mul(aa[3] as u128));
    accum1 = accum1.wrapping_add(((2 * a[5]) as u128).wrapping_mul(a[7] as u128));
    accum0 = accum0.wrapping_add((aa[2] as u128).wrapping_mul(aa[2] as u128));
    accum1 = accum1.wrapping_add(accum0);
    accum0 = accum0.wrapping_sub(((2 * a[1]) as u128).wrapping_mul(a[3] as u128));
    accum1 = accum1.wrapping_add((a[6] as u128).wrapping_mul(a[6] as u128));
    accum2 = (a[0] as u128).wrapping_mul(a[0] as u128);
    accum1 = accum1.wrapping_sub(accum2);
    accum0 = accum0.wrapping_add(accum2);
    accum0 = accum0.wrapping_sub((a[2] as u128).wrapping_mul(a[2] as u128));
    accum1 = accum1.wrapping_add((aa[0] as u128).wrapping_mul(aa[0] as u128));
    accum0 = accum0.wrapping_add((a[4] as u128).wrapping_mul(a[4] as u128));
    c[0] = (accum0 as u64) & LIMB_MASK;
    c[4] = (accum1 as u64) & LIMB_MASK;
    accum0 >>= 56;
    accum1 >>= 56;

    accum2 = ((2 * aa[2]) as u128).wrapping_mul(aa[3] as u128);
    accum0 = accum0.wrapping_sub(((2 * a[2]) as u128).wrapping_mul(a[3] as u128));
    accum1 = accum1.wrapping_add(((2 * a[6]) as u128).wrapping_mul(a[7] as u128));
    accum1 = accum1.wrapping_add(accum2);
    accum0 = accum0.wrapping_add(accum2);
    accum2 = ((2 * a[0]) as u128).wrapping_mul(a[1] as u128);
    accum1 = accum1.wrapping_add(((2 * aa[0]) as u128).wrapping_mul(aa[1] as u128));
    accum0 = accum0.wrapping_add(((2 * a[4]) as u128).wrapping_mul(a[5] as u128));
    accum1 = accum1.wrapping_sub(accum2);
    accum0 = accum0.wrapping_add(accum2);
    c[1] = (accum0 as u64) & LIMB_MASK;
    c[5] = (accum1 as u64) & LIMB_MASK;
    accum0 >>= 56;
    accum1 >>= 56;

    accum2 = (aa[3] as u128).wrapping_mul(aa[3] as u128);
    accum0 = accum0.wrapping_sub((a[3] as u128).wrapping_mul(a[3] as u128));
    accum1 = accum1.wrapping_add((a[7] as u128).wrapping_mul(a[7] as u128));
    accum1 = accum1.wrapping_add(accum2);
    accum0 = accum0.wrapping_add(accum2);
    accum2 = ((2 * a[0]) as u128).wrapping_mul(a[2] as u128);
    accum1 = accum1.wrapping_add(((2 * aa[0]) as u128).wrapping_mul(aa[2] as u128));
    accum0 = accum0.wrapping_add(((2 * a[4]) as u128).wrapping_mul(a[6] as u128));
    accum2 = accum2.wrapping_add((a[1] as u128).wrapping_mul(a[1] as u128));
    accum1 = accum1.wrapping_add((aa[1] as u128).wrapping_mul(aa[1] as u128));
    accum0 = accum0.wrapping_add((a[5] as u128).wrapping_mul(a[5] as u128));
    accum1 = accum1.wrapping_sub(accum2);
    accum0 = accum0.wrapping_add(accum2);
    c[2] = (accum0 as u64) & LIMB_MASK;
    c[6] = (accum1 as u64) & LIMB_MASK;
    accum0 >>= 56;
    accum1 >>= 56;

    accum0 = accum0.wrapping_add(c[3] as u128);
    accum1 = accum1.wrapping_add(c[7] as u128);
    c[3] = (accum0 as u64) & LIMB_MASK;
    c[7] = (accum1 as u64) & LIMB_MASK;
    accum0 >>= 56;
    accum1 >>= 56;
    c[4] = c[4].wrapping_add(accum0 as u64).wrapping_add(accum1 as u64);
    c[0] = c[0].wrapping_add(accum1 as u64);
    c
}

// =====================================================================================
// `f_generic.c`: the field operations the arch units do not provide
// =====================================================================================

// `gf_copy` is the authority's `field.h:44`; the Rust value type makes it the identity, so
// it is not written.

/// `gf_serialize` — `f_generic.c:21`.
#[allow(clippy::needless_range_loop)] // the byte position is the loop index
fn gf_serialize(x: &Gf, with_hibit: bool) -> [u8; SER_BYTES] {
    let red = gf_strong_reduce(x);
    let mut serial = [0u8; SER_BYTES];
    let mut buffer: u128 = 0;
    let mut fill: u32 = 0;
    let mut j = 0usize;
    let n = if with_hibit { X_SER_BYTES } else { SER_BYTES };
    for i in 0..n {
        if fill < 8 && j < NLIMBS {
            buffer |= (red[j] as u128) << fill;
            fill += 56;
            j += 1;
        }
        serial[i] = buffer as u8;
        fill -= 8;
        buffer >>= 8;
    }
    serial
}

/// `gf_hibit` — `f_generic.c:46`; returns the all-ones mask when set.
fn gf_hibit(x: &Gf) -> u64 {
    let y = gf_add(x, x);
    let y = gf_strong_reduce(&y);
    0u64.wrapping_sub(y[0] & 1)
}

/// `gf_lobit` — `f_generic.c:56`.
fn gf_lobit(x: &Gf) -> u64 {
    let y = gf_strong_reduce(x);
    0u64.wrapping_sub(y[0] & 1)
}

/// `gf_deserialize` — `f_generic.c:66`; all-ones on success, zero on failure.
#[allow(clippy::needless_range_loop)] // the byte position is the loop index
fn gf_deserialize(serial: &[u8], with_hibit: bool, hi_nmask: u8) -> (Gf, u64) {
    let nbytes = if with_hibit { X_SER_BYTES } else { SER_BYTES };
    let mut x = [0u64; NLIMBS];
    let mut j = 0usize;
    let mut fill: u32 = 0;
    let mut buffer: u128 = 0;
    let mut scarry: i128 = 0;

    for i in 0..NLIMBS {
        while fill < 56 && j < nbytes {
            let mut sj = serial[j];
            if j == nbytes - 1 {
                sj &= !hi_nmask;
            }
            buffer |= (sj as u128) << fill;
            fill += 8;
            j += 1;
        }
        x[i] = if i < NLIMBS - 1 {
            (buffer as u64) & LIMB_MASK
        } else {
            buffer as u64
        };
        fill -= 56;
        buffer >>= 56;
        scarry = (scarry + x[i] as i128).wrapping_sub(MODULUS[i] as i128) >> 64;
    }
    let succ = if with_hibit { u64::MAX } else { !gf_hibit(&x) };
    let ok = succ & ct_is_zero_64(buffer as u64) & !ct_is_zero_64(scarry as u64);
    (x, ok)
}

/// `gf_strong_reduce` — `f_generic.c:97`.
fn gf_strong_reduce(a: &Gf) -> Gf {
    let mut out = *a;
    gf_weak_reduce(&mut out);

    let mut scarry: i128 = 0;
    for i in 0..NLIMBS {
        scarry = (scarry + out[i] as i128).wrapping_sub(MODULUS[i] as i128);
        out[i] = (scarry as u64) & LIMB_MASK;
        scarry >>= 56;
    }

    let scarry_0 = scarry as u64;
    let mut carry: u128 = 0;
    for i in 0..NLIMBS {
        carry = (carry + out[i] as u128).wrapping_add((scarry_0 & MODULUS[i]) as u128);
        out[i] = (carry as u64) & LIMB_MASK;
        carry >>= 56;
    }
    out
}

/// `gf_sub` — `f_generic.c:137`.
fn gf_sub(a: &Gf, b: &Gf) -> Gf {
    let mut d = gf_sub_raw(a, b);
    gf_bias(&mut d, 2);
    gf_weak_reduce(&mut d);
    d
}

/// `gf_add` — `f_generic.c:145`.
fn gf_add(a: &Gf, b: &Gf) -> Gf {
    let mut d = gf_add_raw(a, b);
    gf_weak_reduce(&mut d);
    d
}

/// `gf_eq` — `f_generic.c:152`; all-ones when equal.
fn gf_eq(a: &Gf, b: &Gf) -> u64 {
    let c = gf_strong_reduce(&gf_sub(a, b));
    let mut ret = 0u64;
    for limb in c.iter() {
        ret |= *limb;
    }
    ct_is_zero_64(ret)
}

/// `gf_isr` — `f_generic.c:167`; all-ones on success. `a = x^(-1/2)` when successful.
fn gf_isr(x: &Gf) -> (Gf, u64) {
    let mut l0: Gf;
    let mut l1: Gf = gf_sqr(x);
    let mut l2: Gf = gf_mul(x, &l1);
    l1 = gf_sqr(&l2);
    l2 = gf_mul(x, &l1);
    l1 = gf_sqrn(&l2, 3);
    l0 = gf_mul(&l2, &l1);
    l1 = gf_sqrn(&l0, 3);
    l0 = gf_mul(&l2, &l1);
    l2 = gf_sqrn(&l0, 9);
    l1 = gf_mul(&l0, &l2);
    l0 = gf_sqr(&l1);
    l2 = gf_mul(x, &l0);
    l0 = gf_sqrn(&l2, 18);
    l2 = gf_mul(&l1, &l0);
    l0 = gf_sqrn(&l2, 37);
    l1 = gf_mul(&l2, &l0);
    l0 = gf_sqrn(&l1, 37);
    l1 = gf_mul(&l2, &l0);
    l0 = gf_sqrn(&l1, 111);
    l2 = gf_mul(&l1, &l0);
    l0 = gf_sqr(&l2);
    l1 = gf_mul(x, &l0);
    l0 = gf_sqrn(&l1, 223);
    l1 = gf_mul(&l2, &l0);
    l2 = gf_sqr(&l1);
    l0 = gf_mul(&l2, x);
    (l1, gf_eq(&l0, &ONE))
}

/// `gf_sqrn` — `field.h:81`; `n` must be positive.
fn gf_sqrn(x: &Gf, n: u32) -> Gf {
    let mut tmp;
    let mut y;
    let mut n = n;
    if n & 1 == 1 {
        y = gf_sqr(x);
        n -= 1;
    } else {
        tmp = gf_sqr(x);
        y = gf_sqr(&tmp);
        n -= 2;
    }
    while n != 0 {
        tmp = gf_sqr(&y);
        y = gf_sqr(&tmp);
        n -= 2;
    }
    y
}

/// `gf_cond_sel` — `field.h:132`; `x = is_z ? z : y`.
fn gf_cond_sel(y: &Gf, z: &Gf, is_z: u64) -> Gf {
    let mut x = [0u64; NLIMBS];
    for i in 0..NLIMBS {
        x[i] = ct_select_64(is_z, z[i], y[i]);
    }
    x
}

/// `gf_cond_neg` — `field.h:149`.
fn gf_cond_neg(x: &mut Gf, neg: u64) {
    let y = gf_sub(&ZERO, x);
    *x = gf_cond_sel(x, &y, neg);
}

/// `gf_cond_swap` — `field.h:158`.
fn gf_cond_swap(x: &mut Gf, y: &mut Gf, swap: u64) {
    for i in 0..NLIMBS {
        ct_cond_swap_64(swap, &mut x[i], &mut y[i]);
    }
}

/// `gf_invert` — `curve448.c:38`.
fn gf_invert(x: &Gf) -> Gf {
    let t1 = gf_sqr(x);
    let (t2, _ret) = gf_isr(&t1);
    let t1 = gf_sqr(&t2);
    gf_mul(&t1, x)
}

// =====================================================================================
// `curve448.c`: the group
// =====================================================================================

/// `point_double_internal` — `curve448.c:58`.
fn point_double_internal(q: &Point, before_double: bool) -> Point {
    let c = gf_sqr(&q.x);
    let a = gf_sqr(&q.y);
    let d = gf_add_nr(&c, &a);
    let t0 = gf_add_nr(&q.y, &q.x);
    let b = gf_subx_nr(&gf_sqr(&t0), &d, 3);
    let pt = gf_sub_nr(&a, &c);
    let px = gf_sqr(&q.z);
    let pz = gf_add_nr(&px, &px);
    let a2 = gf_subx_nr(&pz, &pt, 4);
    let out_x = gf_mul(&a2, &b);
    let out_z = gf_mul(&pt, &a2);
    let out_y = gf_mul(&pt, &d);
    let out_t = if before_double {
        [0u64; NLIMBS]
    } else {
        gf_mul(&b, &d)
    };
    Point {
        x: out_x,
        y: out_y,
        z: out_z,
        t: out_t,
    }
}

/// `ossl_curve448_point_double` — `curve448.c:82`.
fn point_double(q: &Point) -> Point {
    point_double_internal(q, false)
}

/// `cond_neg_niels` — `curve448.c:88`.
fn cond_neg_niels(n: &mut Niels, neg: u64) {
    gf_cond_swap(&mut n.a, &mut n.b, neg);
    gf_cond_neg(&mut n.c, neg);
}

/// `pt_to_pniels` — `curve448.c:94`.
fn pt_to_pniels(a: &Point) -> Pniels {
    Pniels {
        n: Niels {
            a: gf_sub(&a.y, &a.x),
            b: gf_add(&a.x, &a.y),
            c: gf_mulw(&a.t, 2 * TWISTED_D),
        },
        z: gf_add(&a.z, &a.z),
    }
}

/// `pniels_to_pt` — `curve448.c:102`.
fn pniels_to_pt(d: &Pniels) -> Point {
    let eu = gf_add(&d.n.b, &d.n.a);
    let y = gf_sub(&d.n.b, &d.n.a);
    let t = gf_mul(&y, &eu);
    let x = gf_mul(&d.z, &y);
    let y2 = gf_mul(&d.z, &eu);
    let z = gf_sqr(&d.z);
    Point { x, y: y2, z, t }
}

/// `niels_to_pt` — `curve448.c:114`.
fn niels_to_pt(n: &Niels) -> Point {
    let y = gf_add(&n.b, &n.a);
    let x = gf_sub(&n.b, &n.a);
    let t = gf_mul(&y, &x);
    Point { x, y, z: ONE, t }
}

/// `add_niels_to_pt` — `curve448.c:122`.
fn add_niels_to_pt(d: &mut Point, e: &Niels, before_double: bool) {
    let b0 = gf_sub_nr(&d.y, &d.x);
    let a = gf_mul(&e.a, &b0);
    let b1 = gf_add_nr(&d.x, &d.y);
    let dy = gf_mul(&e.b, &b1);
    let dx = gf_mul(&e.c, &d.t);
    let c = gf_add_nr(&a, &dy);
    let b2 = gf_sub_nr(&dy, &a);
    let dy2 = gf_sub_nr(&d.z, &dx);
    let a2 = gf_add_nr(&dx, &d.z);
    let dz = gf_mul(&a2, &dy2);
    let dx2 = gf_mul(&dy2, &b2);
    let dy3 = gf_mul(&a2, &c);
    let dt = if before_double {
        [0u64; NLIMBS]
    } else {
        gf_mul(&b2, &c)
    };
    d.x = dx2;
    d.y = dy3;
    d.z = dz;
    d.t = dt;
}

/// `sub_niels_from_pt` — `curve448.c:143`.
fn sub_niels_from_pt(d: &mut Point, e: &Niels, before_double: bool) {
    let b0 = gf_sub_nr(&d.y, &d.x);
    let a = gf_mul(&e.b, &b0);
    let b1 = gf_add_nr(&d.x, &d.y);
    let dy = gf_mul(&e.a, &b1);
    let dx = gf_mul(&e.c, &d.t);
    let c = gf_add_nr(&a, &dy);
    let b2 = gf_sub_nr(&dy, &a);
    let dy2 = gf_add_nr(&d.z, &dx);
    let a2 = gf_sub_nr(&d.z, &dx);
    let dz = gf_mul(&a2, &dy2);
    let dx2 = gf_mul(&dy2, &b2);
    let dy3 = gf_mul(&a2, &c);
    let dt = if before_double {
        [0u64; NLIMBS]
    } else {
        gf_mul(&b2, &c)
    };
    d.x = dx2;
    d.y = dy3;
    d.z = dz;
    d.t = dt;
}

/// `add_pniels_to_pt` — `curve448.c:164`.
fn add_pniels_to_pt(p: &mut Point, pn: &Pniels, before_double: bool) {
    p.z = gf_mul(&p.z, &pn.z);
    add_niels_to_pt(p, &pn.n, before_double);
}

/// `sub_pniels_from_pt` — `curve448.c:174`.
fn sub_pniels_from_pt(p: &mut Point, pn: &Pniels, before_double: bool) {
    p.z = gf_mul(&p.z, &pn.z);
    sub_niels_from_pt(p, &pn.n, before_double);
}

/// `ossl_curve448_point_eq` — `curve448.c:184`; `C448_TRUE`/`C448_FALSE`.
fn point_eq(p: &Point, q: &Point) -> u64 {
    let a = gf_mul(&p.y, &q.x);
    let b = gf_mul(&q.y, &p.x);
    gf_eq(&a, &b)
}

/// `ossl_curve448_point_valid` — `curve448.c:199`.
fn point_valid(p: &Point) -> u64 {
    let a = gf_mul(&p.x, &p.y);
    let b = gf_mul(&p.z, &p.t);
    let mut out = gf_eq(&a, &b);
    let a = gf_sqr(&p.x);
    let b = gf_sqr(&p.y);
    let a = gf_sub(&b, &a);
    let b = gf_sqr(&p.t);
    let c = gf_mulw(&b, TWISTED_D);
    let b = gf_sqr(&p.z);
    let b = gf_add(&b, &c);
    out &= gf_eq(&a, &b);
    out &= !gf_eq(&p.z, &ZERO);
    out
}

/// `precomputed_entry` — the `niels_t` at `i` of the generated table.
fn precomputed_entry(i: usize) -> Niels {
    let base = i * 3 * NLIMBS;
    let mut a = [0u64; NLIMBS];
    let mut b = [0u64; NLIMBS];
    let mut c = [0u64; NLIMBS];
    a.copy_from_slice(&CURVE448_PRECOMPUTED_BASE[base..base + NLIMBS]);
    b.copy_from_slice(&CURVE448_PRECOMPUTED_BASE[base + NLIMBS..base + 2 * NLIMBS]);
    c.copy_from_slice(&CURVE448_PRECOMPUTED_BASE[base + 2 * NLIMBS..base + 3 * NLIMBS]);
    Niels { a, b, c }
}

/// `ossl_curve448_precomputed_base[i]` — the generated table.
fn wnaf_entry(i: usize) -> Niels {
    let base = i * 3 * NLIMBS;
    let mut a = [0u64; NLIMBS];
    let mut b = [0u64; NLIMBS];
    let mut c = [0u64; NLIMBS];
    a.copy_from_slice(&CURVE448_WNAF_BASE[base..base + NLIMBS]);
    b.copy_from_slice(&CURVE448_WNAF_BASE[base + NLIMBS..base + 2 * NLIMBS]);
    c.copy_from_slice(&CURVE448_WNAF_BASE[base + 2 * NLIMBS..base + 3 * NLIMBS]);
    Niels { a, b, c }
}

/// `ossl_curve448_precomputed_scalarmul` — `curve448.c:227`.
fn precomputed_scalarmul(scalar: &Scalar) -> Point {
    let n = COMBS_N;
    let t = COMBS_T;
    let s = COMBS_S;

    let mut scalar1x = scalar_add(scalar, &PRECOMPUTED_ADJUSTMENT);
    scalar1x = scalar_halve(&scalar1x);

    let mut out = POINT_IDENTITY;

    let mut i = s;
    while i > 0 {
        if i != s {
            out = point_double_internal(&out, false);
        }
        for j in 0..n {
            let mut tab: u32 = 0;
            for k in 0..t {
                let bit = (i - 1) + s * (k + j * t);
                if bit < SCALAR_BITS {
                    tab |= (((scalar1x[bit / 64] >> (bit % 64)) & 1) as u32) << k;
                }
            }
            let invert: u64 = if (tab >> (t - 1)) == 0 { u64::MAX } else { 0 };
            let idx = if (tab >> (t - 1)) == 0 {
                ((!tab) & 15) as usize
            } else {
                (tab & 15) as usize
            };
            let row = j << (t - 1);
            let table: Vec<Niels> = (0..(1 << (t - 1)))
                .map(|e| precomputed_entry(row + e))
                .collect();
            let mut ni = ct_lookup_niels(&table, 1 << (t - 1), idx);
            cond_neg_niels(&mut ni, invert);
            if i != s || j != 0 {
                add_niels_to_pt(&mut out, &ni, j == n - 1 && i != 1);
            } else {
                out = niels_to_pt(&ni);
            }
        }
        i -= 1;
    }
    out
}

/// `ossl_curve448_point_mul_by_ratio_and_encode_like_eddsa` — `curve448.c:273`.
fn point_encode_like_eddsa(p: &Point) -> [u8; EDDSA_PUBLIC_BYTES] {
    let q = *p;

    let x0 = gf_sqr(&q.x);
    let t0 = gf_sqr(&q.y);
    let u = gf_add(&x0, &t0);
    let z0 = gf_add(&q.y, &q.x);
    let y0 = gf_sqr(&z0);
    let y1 = gf_sub(&y0, &u);
    let z1 = gf_sub(&t0, &x0);
    let x1 = gf_sqr(&q.z);
    let t1 = gf_add(&x1, &x1);
    let t2 = gf_sub(&t1, &z1);
    let x2 = gf_mul(&t2, &y1);
    let y2 = gf_mul(&z1, &u);
    let z2 = gf_mul(&u, &t2);

    let zinv = gf_invert(&z2);
    let t = gf_mul(&x2, &zinv);
    let x = gf_mul(&y2, &zinv);

    let mut enc = [0u8; EDDSA_PUBLIC_BYTES];
    enc[EDDSA_PRIVATE_BYTES - 1] = 0;
    let ser = gf_serialize(&x, true);
    enc[..SER_BYTES].copy_from_slice(&ser);
    enc[EDDSA_PRIVATE_BYTES - 1] |= 0x80 & (gf_lobit(&t) as u8);
    enc
}

/// `ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio` — `curve448.c:320`.
fn point_decode_like_eddsa(enc: &[u8]) -> Option<Point> {
    let mut enc2 = [0u8; EDDSA_PUBLIC_BYTES];
    enc2.copy_from_slice(&enc[..EDDSA_PUBLIC_BYTES]);

    let low = !ct_is_zero_64((enc2[EDDSA_PRIVATE_BYTES - 1] & 0x80) as u64);
    enc2[EDDSA_PRIVATE_BYTES - 1] &= !0x80;

    let (y0, mut succ) = gf_deserialize(&enc2, true, 0);
    succ &= ct_is_zero_64(enc2[EDDSA_PRIVATE_BYTES - 1] as u64);

    let x0 = gf_sqr(&y0);
    let z0 = gf_sub(&ONE, &x0);
    let t0 = gf_mulw(&x0, EDWARDS_D);
    let t1 = gf_sub(&ONE, &t0);

    let x1 = gf_mul(&z0, &t1);
    let (t2, isr) = gf_isr(&x1);
    succ &= isr;

    let mut x = gf_mul(&t2, &z0);
    let l = gf_lobit(&x);
    gf_cond_neg(&mut x, l ^ low);

    let mut p = Point {
        x,
        y: y0,
        z: ONE,
        t: ZERO,
    };

    let c = gf_sqr(&p.x);
    let a = gf_sqr(&p.y);
    let d = gf_add(&c, &a);
    let pt0 = gf_add(&p.y, &p.x);
    let b = gf_sqr(&pt0);
    let b = gf_sub(&b, &d);
    let pt1 = gf_sub(&a, &c);
    let pz = gf_sqr(&p.z);
    let pz = gf_add(&pz, &pz);
    let a = gf_sub(&pz, &d);
    p.x = gf_mul(&a, &b);
    p.z = gf_mul(&pt1, &a);
    p.y = gf_mul(&pt1, &d);
    p.t = gf_mul(&b, &d);

    if succ == 0 {
        return None;
    }
    Some(p)
}

/// `ossl_x448_int` — `curve448.c:379`; `C448_SUCCESS`/`C448_FAILURE`.
fn x448_int(base: &[u8], scalar: &[u8]) -> (Option<[u8; X_SER_BYTES]>, c_int) {
    let (x1, _) = gf_deserialize(base, true, 0);
    let mut x2 = ONE;
    let mut z2 = ZERO;
    let mut x3 = x1;
    let mut z3 = ONE;
    let mut swap: u64 = 0;

    let mut t = X_PRIVATE_BITS;
    loop {
        t -= 1;
        let mut sb = scalar[t / 8];
        if t / 8 == 0 {
            sb &= (0u8).wrapping_sub(COFACTOR);
        } else if t == X_PRIVATE_BITS - 1 {
            sb = 0xff;
        }
        let mut k_t = ((sb >> (t % 8)) & 1) as u64;
        k_t = k_t.wrapping_neg();

        swap ^= k_t;
        gf_cond_swap(&mut x2, &mut x3, swap);
        gf_cond_swap(&mut z2, &mut z3, swap);
        swap = k_t;

        let t1 = gf_add_nr(&x2, &z2);
        let mut t2 = gf_sub_nr(&x2, &z2);
        z2 = gf_sub_nr(&x3, &z3);
        x2 = gf_mul(&t1, &z2);
        z2 = gf_add_nr(&z3, &x3);
        x3 = gf_mul(&t2, &z2);
        z3 = gf_sub_nr(&x2, &x3);
        z2 = gf_sqr(&z3);
        z3 = gf_mul(&x1, &z2);
        z2 = gf_add_nr(&x2, &x3);
        x3 = gf_sqr(&z2);

        z2 = gf_sqr(&t1);
        let t1b = gf_sqr(&t2);
        x2 = gf_mul(&z2, &t1b);
        t2 = gf_sub_nr(&z2, &t1b);

        let t1c = gf_mulw(&t2, -EDWARDS_D);
        let t1d = gf_add_nr(&t1c, &z2);
        z2 = gf_mul(&t2, &t1d);

        if t == 0 {
            break;
        }
    }

    gf_cond_swap(&mut x2, &mut x3, swap);
    gf_cond_swap(&mut z2, &mut z3, swap);
    let z2i = gf_invert(&z2);
    let x1r = gf_mul(&x2, &z2i);
    let out = gf_serialize(&x1r, true);
    let nz = !gf_eq(&x1r, &ZERO);
    // `c448_succeed_if(mask_to_bool(nz))`: all-ones is `C448_SUCCESS` (-1), zero is failure.
    let ret = if nz == u64::MAX {
        C448_SUCCESS
    } else {
        C448_FAILURE
    };
    (Some(out), ret)
}

/// `ossl_curve448_point_mul_by_ratio_and_encode_like_x448` — `curve448.c:459`.
fn point_encode_like_x448(p: &Point) -> [u8; X_SER_BYTES] {
    let mut q = *p;
    let ti = gf_invert(&q.x);
    q.z = gf_mul(&ti, &q.y);
    q.y = gf_sqr(&q.z);
    gf_serialize(&q.y, true)
}

/// `ossl_x448_derive_public_key` — `curve448.c:473`.
fn x448_derive_public_key(scalar: &[u8]) -> [u8; X_SER_BYTES] {
    let mut scalar2 = [0u8; SCALAR_BYTES];
    scalar2.copy_from_slice(&scalar[..SCALAR_BYTES]);
    scalar2[0] &= (0u8).wrapping_sub(COFACTOR);
    scalar2[SCALAR_BYTES - 1] &= !((0u8).wrapping_sub(1) << ((X_PRIVATE_BITS + 7) % 8));
    scalar2[SCALAR_BYTES - 1] |= 1u8 << ((X_PRIVATE_BITS + 7) % 8);

    let mut the_scalar = scalar_decode_long(&scalar2);

    let mut i = 1;
    while i < 2 {
        // X448_ENCODE_RATIO == 2
        the_scalar = scalar_halve(&the_scalar);
        i <<= 1;
    }

    let p = precomputed_scalarmul(&the_scalar);
    point_encode_like_x448(&p)
}

/// `recode_wnaf` — `curve448.c:545`; returns the number of controls (minus the end marker).
fn recode_wnaf(scalar: &Scalar, table_bits: u32) -> Vec<SmvtControl> {
    let table_size = SCALAR_BITS / (table_bits as usize + 1) + 3;
    let mut control = vec![
        SmvtControl {
            power: 0,
            addend: 0
        };
        table_size
    ];
    let mut position: isize = table_size as isize - 1;
    let mut current: u64 = scalar[0] & 0xFFFF;
    let mask: u32 = (1u32 << (table_bits + 1)) - 1;
    let b_over_16: usize = core::mem::size_of::<u64>() / 2;

    control[position as usize].power = -1;
    control[position as usize].addend = 0;
    position -= 1;

    let mut w: usize = 1;
    while w < (SCALAR_BITS - 1) / 16 + 3 {
        if w < (SCALAR_BITS - 1) / 16 + 1 {
            // The C is `(uint32_t)((limb >> (16 * (w % B_OVER_16))) << 16)`, whose
            // top-level `uint32_t` cast keeps only the low 16 bits of the shifted limb.
            let window = (scalar[w / b_over_16] >> (16 * (w % b_over_16))) & 0xFFFF;
            current = current.wrapping_add(window << 16);
        }
        while (current & 0xFFFF) != 0 {
            let pos = (current as u32).trailing_zeros();
            let odd = (current as u32) >> pos;
            let mut delta = (odd & mask) as i32;
            if odd & (1 << (table_bits + 1)) != 0 {
                delta -= 1 << (table_bits + 1);
            }
            current = current.wrapping_sub((delta as i64 as u64) << pos);
            control[position as usize].power = (pos + 16 * (w as u32 - 1)) as c_int;
            control[position as usize].addend = delta;
            position -= 1;
        }
        current >>= 16;
        w += 1;
    }

    position += 1;
    let n = table_size as isize - position;
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        out.push(control[(i + position) as usize]);
    }
    out
}

/// `prepare_wnaf_table` — `curve448.c:609`.
fn prepare_wnaf_table(working: &Point, tbits: u32) -> Vec<Pniels> {
    let mut output = Vec::with_capacity(1 << tbits);
    output.push(pt_to_pniels(working));
    if tbits == 0 {
        return output;
    }
    let tmp = point_double(working);
    let twop = pt_to_pniels(&tmp);
    let mut tmp = tmp;
    add_pniels_to_pt(&mut tmp, &output[0], false);
    output.push(pt_to_pniels(&tmp));

    for _ in 2..(1 << tbits) {
        add_pniels_to_pt(&mut tmp, &twop, false);
        output.push(pt_to_pniels(&tmp));
    }
    output
}

/// `ossl_curve448_base_double_scalarmul_non_secret` — `curve448.c:637`.
fn base_double_scalarmul_non_secret(scalar1: &Scalar, base2: &Point, scalar2: &Scalar) -> Point {
    let table_bits_var = WNAF_VAR_TABLE_BITS;
    let table_bits_pre = WNAF_FIXED_TABLE_BITS;
    let control_var = recode_wnaf(scalar2, table_bits_var as u32);
    let control_pre = recode_wnaf(scalar1, table_bits_pre as u32);
    let precmp_var = prepare_wnaf_table(base2, table_bits_var as u32);
    let mut contp = 0usize;
    let mut contv = 0usize;

    let mut i = control_var[0].power;
    let mut combo;
    if i < 0 {
        return POINT_IDENTITY;
    } else if i > control_pre[0].power {
        combo = pniels_to_pt(&precmp_var[(control_var[0].addend >> 1) as usize]);
        contv += 1;
    } else if i == control_pre[0].power && i >= 0 {
        combo = pniels_to_pt(&precmp_var[(control_var[0].addend >> 1) as usize]);
        add_niels_to_pt(
            &mut combo,
            &wnaf_entry((control_pre[0].addend >> 1) as usize),
            i != 0,
        );
        contv += 1;
        contp += 1;
    } else {
        i = control_pre[0].power;
        combo = niels_to_pt(&wnaf_entry((control_pre[0].addend >> 1) as usize));
        contp += 1;
    }

    i -= 1;
    while i >= 0 {
        let cv = i == control_var[contv].power;
        let cp = i == control_pre[contp].power;
        combo = point_double_internal(&combo, i != 0 && !(cv || cp));

        if cv {
            let addend = control_var[contv].addend;
            if addend > 0 {
                add_pniels_to_pt(
                    &mut combo,
                    &precmp_var[(addend >> 1) as usize],
                    i != 0 && !cp,
                );
            } else {
                sub_pniels_from_pt(
                    &mut combo,
                    &precmp_var[((-addend) >> 1) as usize],
                    i != 0 && !cp,
                );
            }
            contv += 1;
        }

        if cp {
            let addend = control_pre[contp].addend;
            if addend > 0 {
                add_niels_to_pt(&mut combo, &wnaf_entry((addend >> 1) as usize), i != 0);
            } else {
                sub_niels_from_pt(&mut combo, &wnaf_entry(((-addend) >> 1) as usize), i != 0);
            }
            contp += 1;
        }
        i -= 1;
    }
    combo
}

// =====================================================================================
// `scalar.c`: the scalar ring
// =====================================================================================

/// `sc_subx` — `scalar.c:37`.
fn sc_subx(accum: &[u64], sub: &Scalar, p: &Scalar, extra: u64) -> Scalar {
    let mut out = [0u64; SCALAR_LIMBS];
    let mut chain: i128 = 0;
    for i in 0..SCALAR_LIMBS {
        chain = (chain + accum[i] as i128).wrapping_sub(sub[i] as i128);
        out[i] = chain as u64;
        chain >>= 64;
    }
    let borrow = (chain as u64).wrapping_add(extra);

    chain = 0;
    for i in 0..SCALAR_LIMBS {
        chain = (chain + out[i] as i128).wrapping_add((p[i] & borrow) as i128);
        out[i] = chain as u64;
        chain >>= 64;
    }
    out
}

/// `sc_montmul` — `scalar.c:61`.
#[allow(clippy::needless_range_loop)] // the limb index drives two arrays
fn sc_montmul(a: &Scalar, b: &Scalar) -> Scalar {
    let mut accum = [0u64; SCALAR_LIMBS + 1];
    let mut hi_carry: u64 = 0;

    for i in 0..SCALAR_LIMBS {
        let mand0 = a[i];
        let mier = b;
        let mut chain: u128 = 0;
        let mut j = 0;
        while j < SCALAR_LIMBS {
            chain = chain
                .wrapping_add((mand0 as u128).wrapping_mul(mier[j] as u128))
                .wrapping_add(accum[j] as u128);
            accum[j] = chain as u64;
            chain >>= 64;
            j += 1;
        }
        accum[j] = chain as u64;

        let mand = accum[0].wrapping_mul(MONTGOMERY_FACTOR);
        chain = 0;
        let mier = &SC_P;
        j = 0;
        while j < SCALAR_LIMBS {
            chain = chain
                .wrapping_add((mand as u128).wrapping_mul(mier[j] as u128))
                .wrapping_add(accum[j] as u128);
            if j != 0 {
                accum[j - 1] = chain as u64;
            }
            chain >>= 64;
            j += 1;
        }
        chain = chain.wrapping_add(accum[j] as u128);
        chain = chain.wrapping_add(hi_carry as u128);
        accum[j - 1] = chain as u64;
        hi_carry = (chain >> 64) as u64;
    }

    sc_subx(&accum[..SCALAR_LIMBS], &SC_P, &SC_P, hi_carry)
}

/// `ossl_curve448_scalar_mul` — `scalar.c:98`.
fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
    let out = sc_montmul(a, b);
    sc_montmul(&out, &SC_R2)
}

/// `ossl_curve448_scalar_sub` — `scalar.c:105`.
fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
    sc_subx(a, b, &SC_P, 0)
}

/// `ossl_curve448_scalar_add` — `scalar.c:111`.
fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
    let mut out = [0u64; SCALAR_LIMBS];
    let mut chain: u128 = 0;
    for i in 0..SCALAR_LIMBS {
        chain = (chain + a[i] as u128).wrapping_add(b[i] as u128);
        out[i] = chain as u64;
        chain >>= 64;
    }
    sc_subx(&out, &SC_P, &SC_P, chain as u64)
}

/// `scalar_decode_short` — `scalar.c:125`.
fn scalar_decode_short(ser: &[u8]) -> Scalar {
    let mut s = [0u64; SCALAR_LIMBS];
    let mut k = 0usize;
    for limb in s.iter_mut() {
        let mut out = 0u64;
        for j in 0..8 {
            if k < ser.len() {
                out |= (ser[k] as u64) << (8 * j);
                k += 1;
            }
        }
        *limb = out;
    }
    s
}

/// `ossl_curve448_scalar_decode` — `scalar.c:140`; `C448_SUCCESS` if it was in range.
fn scalar_decode(ser: &[u8]) -> (Scalar, c_int) {
    let s = scalar_decode_short(&ser[..SCALAR_BYTES]);
    let mut accum: i128 = 0;
    for i in 0..SCALAR_LIMBS {
        accum = (accum + s[i] as i128 - SC_P[i] as i128) >> 64;
    }
    let s = scalar_mul(&s, &SCALAR_ONE);
    let ok = !ct_is_zero_64(accum as u32 as u64);
    (
        s,
        if ok == u64::MAX {
            C448_SUCCESS
        } else {
            C448_FAILURE
        },
    )
}

/// `ossl_curve448_scalar_decode_long` — `scalar.c:162`.
fn scalar_decode_long(ser: &[u8]) -> Scalar {
    let ser_len = ser.len();
    if ser_len == 0 {
        return SCALAR_ZERO;
    }
    let mut i = ser_len - (ser_len % SCALAR_BYTES);
    if i == ser_len {
        i -= SCALAR_BYTES;
    }
    let mut t1 = scalar_decode_short(&ser[i..]);

    if ser_len == SCALAR_BYTES {
        return scalar_mul(&t1, &SCALAR_ONE);
    }

    while i != 0 {
        i -= SCALAR_BYTES;
        t1 = sc_montmul(&t1, &SC_R2);
        let (t2, _) = scalar_decode(&ser[i..]);
        t1 = scalar_add(&t1, &t2);
    }
    t1
}

/// `ossl_curve448_scalar_encode` — `scalar.c:199`.
fn scalar_encode(s: &Scalar) -> [u8; SCALAR_BYTES] {
    let mut ser = [0u8; SCALAR_BYTES];
    let mut k = 0usize;
    for limb in s.iter() {
        for j in 0..8 {
            ser[k] = (limb >> (8 * j)) as u8;
            k += 1;
        }
    }
    ser
}

/// `ossl_curve448_scalar_halve` — `scalar.c:210`.
fn scalar_halve(a: &Scalar) -> Scalar {
    let mut mask = 0u64.wrapping_sub(a[0] & 1);
    let mut out = [0u64; SCALAR_LIMBS];
    let mut chain: u128 = 0;
    mask = value_barrier_64(mask);
    for i in 0..SCALAR_LIMBS {
        chain = (chain + a[i] as u128).wrapping_add((SC_P[i] & mask) as u128);
        out[i] = chain as u64;
        chain >>= 64;
    }
    let mut i = 0;
    while i < SCALAR_LIMBS - 1 {
        out[i] = (out[i] >> 1) | (out[i + 1] << 63);
        i += 1;
    }
    out[i] = (out[i] >> 1) | ((chain as u64) << 63);
    out
}

/// `ossl_curve448_scalar_destroy` — `scalar.c:157`.
fn scalar_destroy(s: &mut Scalar) {
    // SAFETY: `s` is this call's own seven-word buffer.
    unsafe { OPENSSL_cleanse(s.as_mut_ptr().cast(), SCALAR_BYTES) };
}

// `curve448_scalar_copy` — `point_448.h:162`; the Rust value type makes the C copy the
// identity, so it is not written.

// =====================================================================================
// `eddsa.c`: the Ed448 signature scheme
// =====================================================================================

/// `oneshot_hash` — `eddsa.c:23`; `C448_SUCCESS`/`C448_FAILURE`.
fn oneshot_hash(ctx: *mut c_void, out: &mut [u8], input: &[u8], propq: *const c_char) -> c_int {
    let hashctx = EVP_MD_CTX_new();
    if hashctx.is_null() {
        return C448_FAILURE;
    }
    // SAFETY: `ctx`/`propq` are the caller's; the name is a compile-time constant.
    let shake256 = unsafe { EVP_MD_fetch(ctx, c"SHAKE256".as_ptr(), propq) };
    if shake256.is_null() {
        // SAFETY: `hashctx` is live.
        unsafe { EVP_MD_CTX_free(hashctx) };
        return C448_FAILURE;
    }
    // SAFETY: all pointers are live and each buffer is valid for its length.
    let ok = unsafe {
        EVP_DigestInit_ex(hashctx, shake256, ptr::null_mut()) != 0
            && EVP_DigestUpdate(hashctx, input.as_ptr().cast(), input.len()) != 0
            && EVP_DigestFinalXOF(hashctx, out.as_mut_ptr(), out.len()) != 0
    };
    // SAFETY: both are live.
    unsafe {
        EVP_MD_CTX_free(hashctx);
        EVP_MD_free(shake256);
    }
    if ok {
        C448_SUCCESS
    } else {
        C448_FAILURE
    }
}

/// `clamp` — `eddsa.c:50`.
fn clamp(b: &mut [u8]) {
    b[0] &= (-(COFACTOR as i8)) as u8;
    b[EDDSA_PRIVATE_BYTES - 1] = 0;
    b[EDDSA_PRIVATE_BYTES - 2] |= 0x80;
}

/// `hash_init_with_dom` — `eddsa.c:57`.
fn hash_init_with_dom(
    ctx: *mut c_void,
    hashctx: *mut EvpMdCtx,
    prehashed: u8,
    for_prehash: u8,
    context: &[u8],
    propq: *const c_char,
) -> c_int {
    const DOM_S: &[u8; 8] = b"SigEd448";
    let mut dom = [0u8; 2];

    if context.len() > u8::MAX as usize {
        return C448_FAILURE;
    }
    dom[0] = 2 - (if prehashed == 0 { 1u8 } else { 0 }) - (if for_prehash == 0 { 1u8 } else { 0 });
    dom[1] = context.len() as u8;

    // SAFETY: `ctx`/`propq` are the caller's; the name is a compile-time constant.
    let shake256 = unsafe { EVP_MD_fetch(ctx, c"SHAKE256".as_ptr(), propq) };
    if shake256.is_null() {
        return C448_FAILURE;
    }
    // SAFETY: all pointers are live and each buffer is valid for its length.
    let ok = unsafe {
        EVP_DigestInit_ex(hashctx, shake256, ptr::null_mut()) != 0
            && EVP_DigestUpdate(hashctx, DOM_S.as_ptr().cast(), DOM_S.len()) != 0
            && EVP_DigestUpdate(hashctx, dom.as_ptr().cast(), dom.len()) != 0
            && EVP_DigestUpdate(hashctx, context.as_ptr().cast(), context.len()) != 0
    };
    // SAFETY: `shake256` is live.
    unsafe { EVP_MD_free(shake256) };
    if ok {
        C448_SUCCESS
    } else {
        C448_FAILURE
    }
}

/// `ossl_c448_ed448_derive_public_key` — `eddsa.c:106`.
fn c448_ed448_derive_public_key(
    ctx: *mut c_void,
    privkey: &[u8],
    propq: *const c_char,
) -> (Option<[u8; EDDSA_PUBLIC_BYTES]>, c_int) {
    let mut secret_scalar_ser = [0u8; EDDSA_PRIVATE_BYTES];
    if oneshot_hash(
        ctx,
        &mut secret_scalar_ser,
        &privkey[..EDDSA_PRIVATE_BYTES],
        propq,
    ) != C448_SUCCESS
    {
        return (None, C448_FAILURE);
    }

    clamp(&mut secret_scalar_ser);

    let mut secret_scalar = scalar_decode_long(&secret_scalar_ser);

    let mut c = 1;
    while c < EDDSA_ENCODE_RATIO {
        secret_scalar = scalar_halve(&secret_scalar);
        c <<= 1;
    }

    let p = precomputed_scalarmul(&secret_scalar);
    let pubkey = point_encode_like_eddsa(&p);
    scalar_destroy(&mut secret_scalar);
    (Some(pubkey), C448_SUCCESS)
}

/// `ossl_c448_ed448_sign` — `eddsa.c:154`.
#[allow(clippy::too_many_arguments)]
fn c448_ed448_sign(
    ctx: *mut c_void,
    privkey: &[u8],
    pubkey: &[u8],
    message: &[u8],
    prehashed: u8,
    context: &[u8],
    propq: *const c_char,
) -> (Option<[u8; EDDSA_SIGNATURE_BYTES]>, c_int) {
    let hashctx = EVP_MD_CTX_new();
    if hashctx.is_null() {
        return (None, C448_FAILURE);
    }

    let mut secret_scalar;
    let mut nonce_scalar;
    let mut challenge_scalar;
    let nonce_point: [u8; EDDSA_PUBLIC_BYTES];

    {
        let mut expanded = [0u8; EDDSA_PRIVATE_BYTES * 2];
        if oneshot_hash(ctx, &mut expanded, &privkey[..EDDSA_PRIVATE_BYTES], propq) != C448_SUCCESS
        {
            // SAFETY: `hashctx` is live.
            unsafe { EVP_MD_CTX_free(hashctx) };
            return (None, C448_FAILURE);
        }
        clamp(&mut expanded);
        let es = {
            let mut v = [0u8; EDDSA_PRIVATE_BYTES];
            v.copy_from_slice(&expanded[..EDDSA_PRIVATE_BYTES]);
            v
        };
        secret_scalar = scalar_decode_long(&es);

        // SAFETY: all pointers are live and each buffer is valid for its length.
        let ok = unsafe {
            hash_init_with_dom(ctx, hashctx, prehashed, 0, context, propq) != 0
                && EVP_DigestUpdate(
                    hashctx,
                    expanded[EDDSA_PRIVATE_BYTES..].as_ptr().cast(),
                    EDDSA_PRIVATE_BYTES,
                ) != 0
                && EVP_DigestUpdate(hashctx, message.as_ptr().cast(), message.len()) != 0
        };
        // SAFETY: `expanded` is this block's own buffer.
        unsafe { OPENSSL_cleanse(expanded.as_mut_ptr().cast(), expanded.len()) };
        if !ok {
            // SAFETY: `hashctx` is live.
            unsafe { EVP_MD_CTX_free(hashctx) };
            return (None, C448_FAILURE);
        }
    }

    {
        let mut nonce = [0u8; 2 * EDDSA_PRIVATE_BYTES];
        // SAFETY: `hashctx` is live and `nonce` is a 114-byte buffer.
        if unsafe { EVP_DigestFinalXOF(hashctx, nonce.as_mut_ptr(), nonce.len()) } == 0 {
            // SAFETY: `hashctx` is live.
            unsafe { EVP_MD_CTX_free(hashctx) };
            return (None, C448_FAILURE);
        }
        nonce_scalar = scalar_decode_long(&nonce);
        // SAFETY: `nonce` is this block's own buffer.
        unsafe { OPENSSL_cleanse(nonce.as_mut_ptr().cast(), nonce.len()) };
    }

    {
        let mut nonce_scalar_2 = scalar_halve(&nonce_scalar);
        let mut c = 2;
        while c < EDDSA_ENCODE_RATIO {
            nonce_scalar_2 = scalar_halve(&nonce_scalar_2);
            c <<= 1;
        }
        let p = precomputed_scalarmul(&nonce_scalar_2);
        nonce_point = point_encode_like_eddsa(&p);
    }

    {
        let mut challenge = [0u8; 2 * EDDSA_PRIVATE_BYTES];
        // SAFETY: all pointers are live and each buffer is valid for its length.
        let ok = unsafe {
            hash_init_with_dom(ctx, hashctx, prehashed, 0, context, propq) != 0
                && EVP_DigestUpdate(hashctx, nonce_point.as_ptr().cast(), nonce_point.len()) != 0
                && EVP_DigestUpdate(hashctx, pubkey.as_ptr().cast(), EDDSA_PUBLIC_BYTES) != 0
                && EVP_DigestUpdate(hashctx, message.as_ptr().cast(), message.len()) != 0
                && EVP_DigestFinalXOF(hashctx, challenge.as_mut_ptr(), challenge.len()) != 0
        };
        if !ok {
            // SAFETY: `hashctx` is live.
            unsafe { EVP_MD_CTX_free(hashctx) };
            return (None, C448_FAILURE);
        }
        challenge_scalar = scalar_decode_long(&challenge);
        // SAFETY: `challenge` is this block's own buffer.
        unsafe { OPENSSL_cleanse(challenge.as_mut_ptr().cast(), challenge.len()) };
    }

    challenge_scalar = scalar_mul(&challenge_scalar, &secret_scalar);
    challenge_scalar = scalar_add(&challenge_scalar, &nonce_scalar);

    let mut signature = [0u8; EDDSA_SIGNATURE_BYTES];
    signature[..EDDSA_PUBLIC_BYTES].copy_from_slice(&nonce_point);
    signature[EDDSA_PUBLIC_BYTES..EDDSA_PUBLIC_BYTES + SCALAR_BYTES]
        .copy_from_slice(&scalar_encode(&challenge_scalar));

    scalar_destroy(&mut secret_scalar);
    scalar_destroy(&mut nonce_scalar);
    scalar_destroy(&mut challenge_scalar);

    // SAFETY: `hashctx` is live.
    unsafe { EVP_MD_CTX_free(hashctx) };
    (Some(signature), C448_SUCCESS)
}

/// `ossl_c448_ed448_verify` — `eddsa.c:286`.
fn c448_ed448_verify(
    ctx: *mut c_void,
    signature: &[u8],
    pubkey: &[u8],
    message: &[u8],
    prehashed: u8,
    context: &[u8],
    propq: *const c_char,
) -> c_int {
    // Order in little-endian format.
    const ORDER: [u8; 57] = [
        0xF3, 0x44, 0x58, 0xAB, 0x92, 0xC2, 0x78, 0x23, 0x55, 0x8F, 0xC5, 0x8D, 0x72, 0xC2, 0x6C,
        0x21, 0x90, 0x36, 0xD6, 0xAE, 0x49, 0xDB, 0x4E, 0xC4, 0xE9, 0x23, 0xCA, 0x7C, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x00,
    ];

    let mut i: isize = EDDSA_PUBLIC_BYTES as isize - 1;
    while i >= 0 {
        let s = signature[i as usize + EDDSA_PUBLIC_BYTES];
        if s > ORDER[i as usize] {
            return C448_FAILURE;
        }
        if s < ORDER[i as usize] {
            break;
        }
        i -= 1;
    }
    if i < 0 {
        return C448_FAILURE;
    }

    let pk_point = match point_decode_like_eddsa(pubkey) {
        Some(p) => p,
        None => return C448_FAILURE,
    };
    let r_point = match point_decode_like_eddsa(signature) {
        Some(p) => p,
        None => return C448_FAILURE,
    };

    let challenge_scalar = {
        let hashctx = EVP_MD_CTX_new();
        let mut challenge = [0u8; 2 * EDDSA_PRIVATE_BYTES];
        // SAFETY: all pointers are live and each buffer is valid for its length.
        let ok = unsafe {
            !hashctx.is_null()
                && hash_init_with_dom(ctx, hashctx, prehashed, 0, context, propq) != 0
                && EVP_DigestUpdate(hashctx, signature.as_ptr().cast(), EDDSA_PUBLIC_BYTES) != 0
                && EVP_DigestUpdate(hashctx, pubkey.as_ptr().cast(), EDDSA_PUBLIC_BYTES) != 0
                && EVP_DigestUpdate(hashctx, message.as_ptr().cast(), message.len()) != 0
                && EVP_DigestFinalXOF(hashctx, challenge.as_mut_ptr(), challenge.len()) != 0
        };
        // SAFETY: `hashctx` is NULL or live.
        unsafe { EVP_MD_CTX_free(hashctx) };
        if !ok {
            return C448_FAILURE;
        }
        let cs = scalar_decode_long(&challenge);
        // SAFETY: `challenge` is this block's own buffer.
        unsafe { OPENSSL_cleanse(challenge.as_mut_ptr().cast(), challenge.len()) };
        cs
    };
    let challenge_scalar = scalar_sub(&SCALAR_ZERO, &challenge_scalar);

    let response_scalar = scalar_decode_long(&signature[EDDSA_PUBLIC_BYTES..]);

    // pk_point = -c(x(P)) + (cx + k)G = kG
    let combo = base_double_scalarmul_non_secret(&response_scalar, &pk_point, &challenge_scalar);
    if point_eq(&combo, &r_point) == u64::MAX {
        C448_SUCCESS
    } else {
        C448_FAILURE
    }
}

/// `c448_ed448_pubkey_verify` — `eddsa.c:275`.
fn c448_ed448_pubkey_verify(pub_: &[u8]) -> c_int {
    if pub_.len() != EDDSA_PUBLIC_BYTES {
        return C448_FAILURE;
    }
    match point_decode_like_eddsa(pub_) {
        Some(_) => C448_SUCCESS,
        None => C448_FAILURE,
    }
}

/// `ossl_c448_ed448_convert_private_key_to_x448` — `eddsa.c:93`.
fn c448_ed448_convert_private_key_to_x448(
    ctx: *mut c_void,
    ed: &[u8],
    propq: *const c_char,
) -> (Option<[u8; X_SER_BYTES]>, c_int) {
    let mut x = [0u8; X_SER_BYTES];
    let r = oneshot_hash(ctx, &mut x, &ed[..EDDSA_PRIVATE_BYTES], propq);
    (Some(x), r)
}

// =====================================================================================
// The published internals
// =====================================================================================

/// A slice view of a C buffer that may be NULL when its length is zero — the authority's
/// `hash_init_with_dom` accepts a NULL `context` with `context_len == 0`, and
/// `EVP_DigestUpdate` answers 1 for a zero count without reading it.
///
/// # Safety
/// If `len != 0`, `p` must be readable for `len` bytes.
unsafe fn buf<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: the caller's contract gives `p` `len` readable bytes.
        unsafe { core::slice::from_raw_parts(p, len) }
    }
}

/// `void ossl_gf_mul(gf_s *cs, const gf as, const gf bs)` — `arch_64/f_impl64.c:24`.
///
/// # Safety
/// `cs` writable and `as`/`bs` readable for eight `u64` each.
#[no_mangle]
pub unsafe extern "C" fn ossl_gf_mul(cs: *mut u64, as_: *const u64, bs: *const u64) {
    // SAFETY: the contract gives each pointer eight readable/writable `u64`.
    let a = unsafe { *(as_ as *const Gf) };
    // SAFETY: as above.
    let b = unsafe { *(bs as *const Gf) };
    let r = gf_mul(&a, &b);
    // SAFETY: `cs` is writable for eight `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), cs, NLIMBS) };
}

/// `void ossl_gf_sqr(gf_s *cs, const gf as)` — `arch_64/f_impl64.c:102`.
///
/// # Safety
/// `cs` writable and `as` readable for eight `u64`.
#[no_mangle]
pub unsafe extern "C" fn ossl_gf_sqr(cs: *mut u64, as_: *const u64) {
    // SAFETY: the contract gives the pointer eight readable `u64`.
    let a = unsafe { *(as_ as *const Gf) };
    let r = gf_sqr(&a);
    // SAFETY: `cs` is writable for eight `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), cs, NLIMBS) };
}

/// `void ossl_gf_mulw_unsigned(gf_s *cs, const gf as, uint32_t b)` — `arch_64/f_impl64.c:76`.
///
/// # Safety
/// `cs` writable and `as` readable for eight `u64`.
#[no_mangle]
pub unsafe extern "C" fn ossl_gf_mulw_unsigned(cs: *mut u64, as_: *const u64, b: u32) {
    // SAFETY: the contract gives the pointer eight readable `u64`.
    let a = unsafe { *(as_ as *const Gf) };
    let r = gf_mulw_unsigned(&a, b);
    // SAFETY: `cs` is writable for eight `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), cs, NLIMBS) };
}

/// `gf_strong_reduce` — `f_generic.c:97`; the C symbol, since the Rust helper of the same
/// name exists.
///
/// # Safety
/// `inout` readable and writable for eight `u64`.
#[export_name = "gf_strong_reduce"]
pub unsafe extern "C" fn gf_strong_reduce_c(inout: *mut u64) {
    // SAFETY: the contract gives the pointer eight readable/writable `u64`.
    let a = unsafe { *(inout as *const Gf) };
    let r = gf_strong_reduce(&a);
    // SAFETY: `inout` is writable for eight `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), inout, NLIMBS) };
}

/// `gf_add` — `f_generic.c:145`; the C symbol.
///
/// # Safety
/// `out` writable and `a`/`b` readable for eight `u64` each.
#[export_name = "gf_add"]
pub unsafe extern "C" fn gf_add_c(out: *mut u64, a: *const u64, b: *const u64) {
    // SAFETY: the contract gives each pointer eight readable/writable `u64`.
    let av = unsafe { *(a as *const Gf) };
    // SAFETY: as above.
    let bv = unsafe { *(b as *const Gf) };
    let r = gf_add(&av, &bv);
    // SAFETY: `out` is writable for eight `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), out, NLIMBS) };
}

/// `gf_sub` — `f_generic.c:137`; the C symbol.
///
/// # Safety
/// `d` writable and `a`/`b` readable for eight `u64` each.
#[export_name = "gf_sub"]
pub unsafe extern "C" fn gf_sub_c(d: *mut u64, a: *const u64, b: *const u64) {
    // SAFETY: the contract gives each pointer eight readable/writable `u64`.
    let av = unsafe { *(a as *const Gf) };
    // SAFETY: as above.
    let bv = unsafe { *(b as *const Gf) };
    let r = gf_sub(&av, &bv);
    // SAFETY: `d` is writable for eight `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), d, NLIMBS) };
}

/// `gf_serialize` — `f_generic.c:21`; the C symbol.
///
/// # Safety
/// `serial` writable for 56 bytes and `x` readable for eight `u64`.
#[export_name = "gf_serialize"]
pub unsafe extern "C" fn gf_serialize_c(serial: *mut u8, x: *const u64, with_hibit: c_int) {
    // SAFETY: the contract gives the pointer eight readable `u64`.
    let xv = unsafe { *(x as *const Gf) };
    let r = gf_serialize(&xv, with_hibit != 0);
    // SAFETY: `serial` is writable for 56 bytes.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), serial, SER_BYTES) };
}

/// `gf_deserialize` — `f_generic.c:66`; the C symbol.
///
/// # Safety
/// `x` writable for eight `u64` and `serial` readable for 56 bytes.
#[export_name = "gf_deserialize"]
pub unsafe extern "C" fn gf_deserialize_c(
    x: *mut u64,
    serial: *const u8,
    with_hibit: c_int,
    hi_nmask: u8,
) -> u64 {
    // SAFETY: the contract gives `serial` 56 readable bytes.
    let ser = unsafe { core::slice::from_raw_parts(serial, SER_BYTES) };
    let (r, ok) = gf_deserialize(ser, with_hibit != 0, hi_nmask);
    // SAFETY: `x` is writable for eight `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), x, NLIMBS) };
    ok
}

/// `gf_isr` — `f_generic.c:167`; the C symbol.
///
/// # Safety
/// `a` writable and `x` readable for eight `u64`.
#[export_name = "gf_isr"]
pub unsafe extern "C" fn gf_isr_c(a: *mut u64, x: *const u64) -> u64 {
    // SAFETY: the contract gives the pointer eight readable `u64`.
    let xv = unsafe { *(x as *const Gf) };
    let (r, ok) = gf_isr(&xv);
    // SAFETY: `a` is writable for eight `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), a, NLIMBS) };
    ok
}

/// `gf_eq` — `f_generic.c:152`; the C symbol.
///
/// # Safety
/// `x`/`y` readable for eight `u64` each.
#[export_name = "gf_eq"]
pub unsafe extern "C" fn gf_eq_c(x: *const u64, y: *const u64) -> u64 {
    // SAFETY: the contract gives each pointer eight readable `u64`.
    let xv = unsafe { *(x as *const Gf) };
    // SAFETY: as above.
    let yv = unsafe { *(y as *const Gf) };
    gf_eq(&xv, &yv)
}

/// `gf_lobit` — `f_generic.c:56`; the C symbol.
///
/// # Safety
/// `x` readable for eight `u64`.
#[export_name = "gf_lobit"]
pub unsafe extern "C" fn gf_lobit_c(x: *const u64) -> u64 {
    // SAFETY: the contract gives the pointer eight readable `u64`.
    gf_lobit(unsafe { &*(x as *const Gf) })
}

/// `gf_hibit` — `f_generic.c:46`; the C symbol.
///
/// # Safety
/// `x` readable for eight `u64`.
#[export_name = "gf_hibit"]
pub unsafe extern "C" fn gf_hibit_c(x: *const u64) -> u64 {
    // SAFETY: the contract gives the pointer eight readable `u64`.
    gf_hibit(unsafe { &*(x as *const Gf) })
}

/// `void ossl_curve448_point_double(curve448_point_t p, const curve448_point_t q)` —
/// `curve448.c:82`.
///
/// # Safety
/// `p` writable and `q` readable for thirty-two `u64` each.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_point_double(p: *mut u64, q: *const u64) {
    // SAFETY: the contract gives each pointer thirty-two readable/writable `u64`.
    let qv = unsafe { *(q as *const Point) };
    let r = point_double(&qv);
    // SAFETY: `p` is writable for thirty-two `u64`.
    unsafe { ptr::copy_nonoverlapping(&r as *const Point as *const u64, p, 32) };
}

/// `c448_bool_t ossl_curve448_point_eq(const curve448_point_t p, const curve448_point_t q)` —
/// `curve448.c:184`.
///
/// # Safety
/// `p`/`q` readable for thirty-two `u64` each.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_point_eq(p: *const u64, q: *const u64) -> u64 {
    // SAFETY: the contract gives each pointer thirty-two readable `u64`.
    let pv = unsafe { *(p as *const Point) };
    // SAFETY: as above.
    let qv = unsafe { *(q as *const Point) };
    point_eq(&pv, &qv)
}

/// `c448_bool_t ossl_curve448_point_valid(const curve448_point_t p)` — `curve448.c:199`.
///
/// # Safety
/// `p` readable for thirty-two `u64`.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_point_valid(p: *const u64) -> u64 {
    // SAFETY: the contract gives the pointer thirty-two readable `u64`.
    point_valid(unsafe { &*(p as *const Point) })
}

/// `void ossl_curve448_point_destroy(curve448_point_t point)` — `curve448.c:725`.
///
/// # Safety
/// `point` readable and writable for thirty-two `u64`.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_point_destroy(point: *mut u64) {
    // SAFETY: the contract gives the pointer thirty-two writable `u64`.
    unsafe { OPENSSL_cleanse(point.cast(), 32 * 8) };
}

/// `void ossl_curve448_point_mul_by_ratio_and_encode_like_eddsa(uint8_t enc[57],
/// const curve448_point_t p)` — `curve448.c:273`.
///
/// # Safety
/// `enc` writable for 57 bytes and `p` readable for thirty-two `u64`.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_point_mul_by_ratio_and_encode_like_eddsa(
    enc: *mut u8,
    p: *const u64,
) {
    // SAFETY: the contract gives the pointer thirty-two readable `u64`.
    let pv = unsafe { *(p as *const Point) };
    let r = point_encode_like_eddsa(&pv);
    // SAFETY: `enc` is writable for 57 bytes.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), enc, EDDSA_PUBLIC_BYTES) };
}

/// `c448_error_t ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio(curve448_point_t p,
/// const uint8_t enc[57])` — `curve448.c:320`.
///
/// # Safety
/// `p` writable for thirty-two `u64` and `enc` readable for 57 bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio(
    p: *mut u64,
    enc: *const u8,
) -> c_int {
    // SAFETY: the contract gives `enc` 57 readable bytes.
    let e = unsafe { core::slice::from_raw_parts(enc, EDDSA_PUBLIC_BYTES) };
    match point_decode_like_eddsa(e) {
        Some(r) => {
            // SAFETY: `p` is writable for thirty-two `u64`.
            unsafe { ptr::copy_nonoverlapping(&r as *const Point as *const u64, p, 32) };
            C448_SUCCESS
        }
        None => C448_FAILURE,
    }
}

/// `c448_error_t ossl_x448_int(uint8_t out[56], const uint8_t base[56],
/// const uint8_t scalar[56])` — `curve448.c:379`.
///
/// # Safety
/// `out` writable for 56 bytes; `base`/`scalar` readable for 56 each.
#[no_mangle]
pub unsafe extern "C" fn ossl_x448_int(out: *mut u8, base: *const u8, scalar: *const u8) -> c_int {
    // SAFETY: the contract gives each input pointer 56 readable bytes.
    let (b, s) = unsafe {
        (
            core::slice::from_raw_parts(base, X_SER_BYTES),
            core::slice::from_raw_parts(scalar, X_SER_BYTES),
        )
    };
    let (res, ret) = x448_int(b, s);
    if let Some(r) = res {
        // SAFETY: `out` is writable for 56 bytes.
        unsafe { ptr::copy_nonoverlapping(r.as_ptr(), out, X_SER_BYTES) };
    }
    ret
}

/// `void ossl_curve448_point_mul_by_ratio_and_encode_like_x448(uint8_t out[56],
/// const curve448_point_t p)` — `curve448.c:459`.
///
/// # Safety
/// `out` writable for 56 bytes and `p` readable for thirty-two `u64`.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_point_mul_by_ratio_and_encode_like_x448(
    out: *mut u8,
    p: *const u64,
) {
    // SAFETY: the contract gives the pointer thirty-two readable `u64`.
    let pv = unsafe { *(p as *const Point) };
    let r = point_encode_like_x448(&pv);
    // SAFETY: `out` is writable for 56 bytes.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), out, X_SER_BYTES) };
}

/// `void ossl_x448_derive_public_key(uint8_t out[56], const uint8_t scalar[56])` —
/// `curve448.c:473`.
///
/// # Safety
/// `out` writable for 56 bytes and `scalar` readable for 56.
#[no_mangle]
pub unsafe extern "C" fn ossl_x448_derive_public_key(out: *mut u8, scalar: *const u8) {
    // SAFETY: the contract gives `scalar` 56 readable bytes.
    let s = unsafe { core::slice::from_raw_parts(scalar, X_SER_BYTES) };
    let r = x448_derive_public_key(s);
    // SAFETY: `out` is writable for 56 bytes.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), out, X_SER_BYTES) };
}

/// `void ossl_curve448_precomputed_scalarmul(curve448_point_t out,
/// const curve448_precomputed_s *table, const curve448_scalar_t scalar)` — `curve448.c:227`.
///
/// # Safety
/// `out` writable for thirty-two `u64`; `table` ignored (the crate's own generated table is
/// used, since it is the same object) and `scalar` readable for seven `u64`.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_precomputed_scalarmul(
    out: *mut u64,
    table: *const c_void,
    scalar: *const u64,
) {
    let _ = table;
    // SAFETY: the contract gives `scalar` seven readable `u64`.
    let s = unsafe { *(scalar as *const Scalar) };
    let r = precomputed_scalarmul(&s);
    // SAFETY: `out` is writable for thirty-two `u64`.
    unsafe { ptr::copy_nonoverlapping(&r as *const Point as *const u64, out, 32) };
}

/// `void ossl_curve448_base_double_scalarmul_non_secret(curve448_point_t combo,
/// const curve448_scalar_t scalar1, const curve448_point_t base2,
/// const curve448_scalar_t scalar2)` — `curve448.c:637`.
///
/// # Safety
/// `combo` writable for thirty-two `u64`; `scalar1`/`scalar2` readable for seven `u64` each and
/// `base2` for thirty-two.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_base_double_scalarmul_non_secret(
    combo: *mut u64,
    scalar1: *const u64,
    base2: *const u64,
    scalar2: *const u64,
) {
    // SAFETY: the contract gives each pointer its readable length.
    let (s1, b2, s2) = unsafe {
        (
            *(scalar1 as *const Scalar),
            *(base2 as *const Point),
            *(scalar2 as *const Scalar),
        )
    };
    let r = base_double_scalarmul_non_secret(&s1, &b2, &s2);
    // SAFETY: `combo` is writable for thirty-two `u64`.
    unsafe { ptr::copy_nonoverlapping(&r as *const Point as *const u64, combo, 32) };
}

/// `void ossl_curve448_scalar_add(curve448_scalar_t out, const curve448_scalar_t a,
/// const curve448_scalar_t b)` — `scalar.c:111`.
///
/// # Safety
/// `out` writable and `a`/`b` readable for seven `u64` each.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_scalar_add(out: *mut u64, a: *const u64, b: *const u64) {
    // SAFETY: the contract gives each pointer seven readable/writable `u64`.
    let (av, bv) = unsafe { (*(a as *const Scalar), *(b as *const Scalar)) };
    let r = scalar_add(&av, &bv);
    // SAFETY: `out` is writable for seven `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), out, SCALAR_LIMBS) };
}

/// `void ossl_curve448_scalar_sub(curve448_scalar_t out, const curve448_scalar_t a,
/// const curve448_scalar_t b)` — `scalar.c:105`.
///
/// # Safety
/// `out` writable and `a`/`b` readable for seven `u64` each.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_scalar_sub(out: *mut u64, a: *const u64, b: *const u64) {
    // SAFETY: the contract gives each pointer seven readable/writable `u64`.
    let (av, bv) = unsafe { (*(a as *const Scalar), *(b as *const Scalar)) };
    let r = scalar_sub(&av, &bv);
    // SAFETY: `out` is writable for seven `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), out, SCALAR_LIMBS) };
}

/// `void ossl_curve448_scalar_mul(curve448_scalar_t out, const curve448_scalar_t a,
/// const curve448_scalar_t b)` — `scalar.c:98`.
///
/// # Safety
/// `out` writable and `a`/`b` readable for seven `u64` each.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_scalar_mul(out: *mut u64, a: *const u64, b: *const u64) {
    // SAFETY: the contract gives each pointer seven readable/writable `u64`.
    let (av, bv) = unsafe { (*(a as *const Scalar), *(b as *const Scalar)) };
    let r = scalar_mul(&av, &bv);
    // SAFETY: `out` is writable for seven `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), out, SCALAR_LIMBS) };
}

/// `void ossl_curve448_scalar_halve(curve448_scalar_t out, const curve448_scalar_t a)` —
/// `scalar.c:210`.
///
/// # Safety
/// `out` writable and `a` readable for seven `u64`.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_scalar_halve(out: *mut u64, a: *const u64) {
    // SAFETY: the contract gives the pointer seven readable `u64`.
    let av = unsafe { *(a as *const Scalar) };
    let r = scalar_halve(&av);
    // SAFETY: `out` is writable for seven `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), out, SCALAR_LIMBS) };
}

/// `c448_error_t ossl_curve448_scalar_decode(curve448_scalar_t s,
/// const unsigned char ser[56])` — `scalar.c:140`.
///
/// # Safety
/// `s` writable for seven `u64` and `ser` readable for 56 bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_scalar_decode(s: *mut u64, ser: *const u8) -> c_int {
    // SAFETY: the contract gives `ser` 56 readable bytes.
    let v = unsafe { core::slice::from_raw_parts(ser, SCALAR_BYTES) };
    let (r, ret) = scalar_decode(v);
    // SAFETY: `s` is writable for seven `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), s, SCALAR_LIMBS) };
    ret
}

/// `void ossl_curve448_scalar_decode_long(curve448_scalar_t s, const unsigned char *ser,
/// size_t ser_len)` — `scalar.c:162`.
///
/// # Safety
/// `s` writable for seven `u64`; `ser` readable for `ser_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_scalar_decode_long(
    s: *mut u64,
    ser: *const u8,
    ser_len: usize,
) {
    // SAFETY: the contract gives `ser` `ser_len` readable bytes.
    let v = unsafe { core::slice::from_raw_parts(ser, ser_len) };
    let r = scalar_decode_long(v);
    // SAFETY: `s` is writable for seven `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), s, SCALAR_LIMBS) };
}

/// `void ossl_curve448_scalar_encode(unsigned char ser[56], const curve448_scalar_t s)` —
/// `scalar.c:199`.
///
/// # Safety
/// `ser` writable for 56 bytes and `s` readable for seven `u64`.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_scalar_encode(ser: *mut u8, s: *const u64) {
    // SAFETY: the contract gives the pointer seven readable `u64`.
    let sv = unsafe { *(s as *const Scalar) };
    let r = scalar_encode(&sv);
    // SAFETY: `ser` is writable for 56 bytes.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), ser, SCALAR_BYTES) };
}

/// `void ossl_curve448_scalar_destroy(curve448_scalar_t scalar)` — `scalar.c:157`.
///
/// # Safety
/// `scalar` writable for seven `u64`.
#[no_mangle]
pub unsafe extern "C" fn ossl_curve448_scalar_destroy(scalar: *mut u64) {
    // SAFETY: the contract gives the pointer seven writable `u64`.
    unsafe { OPENSSL_cleanse(scalar.cast(), SCALAR_BYTES) };
}

/// `int ossl_x448(uint8_t out_shared_key[56], const uint8_t private_key[56],
/// const uint8_t peer_public_value[56])` — `curve448.c:730`.
///
/// # Safety
/// `out_shared_key` writable for 56 bytes; the two inputs readable for 56.
#[no_mangle]
pub unsafe extern "C" fn ossl_x448(
    out_shared_key: *mut u8,
    private_key: *const u8,
    peer_public_value: *const u8,
) -> c_int {
    // SAFETY: each pointer is readable/writable for 56 bytes per the contract.
    let (_res, ret) = unsafe { x448_int_public(out_shared_key, peer_public_value, private_key) };
    if ret == C448_SUCCESS {
        1
    } else {
        0
    }
}

/// The `ossl_x448_int` body as `ossl_x448` uses it: read both inputs, write the output.
///
/// # Safety
/// As [`ossl_x448_int`]'s contract.
unsafe fn x448_int_public(
    out: *mut u8,
    base: *const u8,
    scalar: *const u8,
) -> (Option<[u8; X_SER_BYTES]>, c_int) {
    // SAFETY: forwarded under the caller's contract.
    unsafe { ossl_x448_int(out, base, scalar) };
    // SAFETY: each input is readable for 56 bytes per the caller's contract.
    let b = unsafe { core::slice::from_raw_parts(base, X_SER_BYTES) };
    // SAFETY: as above.
    let s = unsafe { core::slice::from_raw_parts(scalar, X_SER_BYTES) };
    x448_int(b, s)
}

/// `void ossl_x448_public_from_private(uint8_t out_public_value[56],
/// const uint8_t private_key[56])` — `curve448.c:737`.
///
/// # Safety
/// `out_public_value` writable for 56 bytes; `private_key` readable for 56.
#[no_mangle]
pub unsafe extern "C" fn ossl_x448_public_from_private(
    out_public_value: *mut u8,
    private_key: *const u8,
) {
    // SAFETY: the contract gives the input 56 readable bytes and the output 56 writable.
    unsafe { ossl_x448_derive_public_key(out_public_value, private_key) };
}

/// `c448_error_t ossl_c448_ed448_derive_public_key(...)` — `eddsa.c:106`.
///
/// # Safety
/// `ctx`/`propq` NULL or live; `pubkey` writable for 57 bytes; `privkey` readable for 57.
#[no_mangle]
pub unsafe extern "C" fn ossl_c448_ed448_derive_public_key(
    ctx: *mut c_void,
    pubkey: *mut u8,
    privkey: *const u8,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the contract gives the input 57 readable bytes.
    let pk = unsafe { core::slice::from_raw_parts(privkey, EDDSA_PRIVATE_BYTES) };
    let (res, ret) = c448_ed448_derive_public_key(ctx, pk, propq);
    if let Some(r) = res {
        // SAFETY: `pubkey` is writable for 57 bytes.
        unsafe { ptr::copy_nonoverlapping(r.as_ptr(), pubkey, EDDSA_PUBLIC_BYTES) };
    }
    ret
}

/// `c448_error_t ossl_c448_ed448_sign(...)` — `eddsa.c:154`.
///
/// # Safety
/// `signature` writable for 114 bytes; `privkey`/`pubkey`/`message` readable for their
/// lengths; `context` readable for `context_len`; `ctx`/`propq` NULL or live.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ossl_c448_ed448_sign(
    ctx: *mut c_void,
    signature: *mut u8,
    privkey: *const u8,
    pubkey: *const u8,
    message: *const u8,
    message_len: usize,
    prehashed: u8,
    context: *const u8,
    context_len: usize,
    propq: *const c_char,
) -> c_int {
    // SAFETY: each pointer is readable/writable for the length the contract gives it.
    let (sk, pk, msg, cx) = unsafe {
        (
            core::slice::from_raw_parts(privkey, EDDSA_PRIVATE_BYTES),
            core::slice::from_raw_parts(pubkey, EDDSA_PUBLIC_BYTES),
            buf(message, message_len),
            buf(context, context_len),
        )
    };
    let (res, ret) = c448_ed448_sign(ctx, sk, pk, msg, prehashed, cx, propq);
    if let Some(r) = res {
        // SAFETY: `signature` is writable for 114 bytes.
        unsafe { ptr::copy_nonoverlapping(r.as_ptr(), signature, EDDSA_SIGNATURE_BYTES) };
    }
    ret
}

/// `c448_error_t ossl_c448_ed448_sign_prehash(...)` — `eddsa.c:262`.
///
/// # Safety
/// As [`ossl_c448_ed448_sign`], with `hash` readable for 64 bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ossl_c448_ed448_sign_prehash(
    ctx: *mut c_void,
    signature: *mut u8,
    privkey: *const u8,
    pubkey: *const u8,
    hash: *const u8,
    context: *const u8,
    context_len: usize,
    propq: *const c_char,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        ossl_c448_ed448_sign(
            ctx,
            signature,
            privkey,
            pubkey,
            hash,
            64,
            1,
            context,
            context_len,
            propq,
        )
    }
}

/// `c448_error_t ossl_c448_ed448_verify(...)` — `eddsa.c:286`.
///
/// # Safety
/// `signature`/`pubkey`/`message` readable for their lengths; `context` for `context_len`;
/// `ctx`/`propq` NULL or live.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ossl_c448_ed448_verify(
    ctx: *mut c_void,
    signature: *const u8,
    pubkey: *const u8,
    message: *const u8,
    message_len: usize,
    prehashed: u8,
    context: *const u8,
    context_len: u8,
    propq: *const c_char,
) -> c_int {
    // SAFETY: each pointer is readable for the length the contract gives it.
    let (sig, pk, msg, cx) = unsafe {
        (
            core::slice::from_raw_parts(signature, EDDSA_SIGNATURE_BYTES),
            core::slice::from_raw_parts(pubkey, EDDSA_PUBLIC_BYTES),
            buf(message, message_len),
            buf(context, context_len as usize),
        )
    };
    c448_ed448_verify(ctx, sig, pk, msg, prehashed, cx, propq)
}

/// `c448_error_t ossl_c448_ed448_verify_prehash(...)` — `eddsa.c:368`.
///
/// # Safety
/// As [`ossl_c448_ed448_verify`], with `hash` readable for 64 bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ossl_c448_ed448_verify_prehash(
    ctx: *mut c_void,
    signature: *const u8,
    pubkey: *const u8,
    hash: *const u8,
    context: *const u8,
    context_len: u8,
    propq: *const c_char,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        ossl_c448_ed448_verify(
            ctx,
            signature,
            pubkey,
            hash,
            64,
            1,
            context,
            context_len,
            propq,
        )
    }
}

/// `c448_error_t ossl_c448_ed448_convert_private_key_to_x448(...)` — `eddsa.c:93`.
///
/// # Safety
/// `x` writable for 56 bytes; `ed` readable for 57; `ctx`/`propq` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn ossl_c448_ed448_convert_private_key_to_x448(
    ctx: *mut c_void,
    x: *mut u8,
    ed: *const u8,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the contract gives `ed` 57 readable bytes.
    let e = unsafe { core::slice::from_raw_parts(ed, EDDSA_PRIVATE_BYTES) };
    let (res, ret) = c448_ed448_convert_private_key_to_x448(ctx, e, propq);
    if let Some(r) = res {
        // SAFETY: `x` is writable for 56 bytes.
        unsafe { ptr::copy_nonoverlapping(r.as_ptr(), x, X_SER_BYTES) };
    }
    ret
}

/// `int ossl_ed448_sign(OSSL_LIB_CTX *ctx, uint8_t *out_sig, const uint8_t *message,
/// size_t message_len, const uint8_t public_key[57], const uint8_t private_key[57],
/// const uint8_t *context, size_t context_len, const uint8_t phflag, const char *propq)` —
/// `eddsa.c:380`.
///
/// # Safety
/// As [`ossl_c448_ed448_sign`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ossl_ed448_sign(
    ctx: *mut c_void,
    out_sig: *mut u8,
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    private_key: *const u8,
    context: *const u8,
    context_len: usize,
    phflag: u8,
    propq: *const c_char,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    let r = unsafe {
        ossl_c448_ed448_sign(
            ctx,
            out_sig,
            private_key,
            public_key,
            message,
            message_len,
            phflag,
            context,
            context_len,
            propq,
        )
    };
    if r == C448_SUCCESS {
        1
    } else {
        0
    }
}

/// `int ossl_ed448_pubkey_verify(const uint8_t *pub, size_t pub_len)` — `eddsa.c:397`.
///
/// # Safety
/// `pub` readable for `pub_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_ed448_pubkey_verify(pub_: *const u8, pub_len: usize) -> c_int {
    if pub_len != EDDSA_PUBLIC_BYTES {
        return 0;
    }
    // SAFETY: `pub_` is readable for 57 bytes per the check above.
    let p = unsafe { core::slice::from_raw_parts(pub_, EDDSA_PUBLIC_BYTES) };
    if c448_ed448_pubkey_verify(p) == C448_SUCCESS {
        1
    } else {
        0
    }
}

/// `int ossl_ed448_verify(OSSL_LIB_CTX *ctx, const uint8_t *message, size_t message_len,
/// const uint8_t signature[114], const uint8_t public_key[57], const uint8_t *context,
/// size_t context_len, const uint8_t phflag, const char *propq)` — `eddsa.c:402`.
///
/// # Safety
/// As [`ossl_c448_ed448_verify`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ossl_ed448_verify(
    ctx: *mut c_void,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    public_key: *const u8,
    context: *const u8,
    context_len: usize,
    phflag: u8,
    propq: *const c_char,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    let r = unsafe {
        ossl_c448_ed448_verify(
            ctx,
            signature,
            public_key,
            message,
            message_len,
            phflag,
            context,
            context_len as u8,
            propq,
        )
    };
    if r == C448_SUCCESS {
        1
    } else {
        0
    }
}

/// `int ossl_ed448_public_from_private(OSSL_LIB_CTX *ctx, uint8_t out_public_key[57],
/// const uint8_t private_key[57], const char *propq)` — `eddsa.c:414`.
///
/// # Safety
/// `out_public_key` writable for 57 bytes; `private_key` readable for 57; `ctx`/`propq` NULL
/// or live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ed448_public_from_private(
    ctx: *mut c_void,
    out_public_key: *mut u8,
    private_key: *const u8,
    propq: *const c_char,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    let r = unsafe { ossl_c448_ed448_derive_public_key(ctx, out_public_key, private_key, propq) };
    if r == C448_SUCCESS {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexn(s: &str, n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect()
    }

    /// RFC 7748 §6.2 — the X448 key exchange, as `evppkey_ecx.txt`'s "X448 test vectors
    /// (from RFC7748 6.2)" carries it: both public keys, both derivations, and the shared
    /// secret.
    #[test]
    fn x448_rfc7748_section_6_2() {
        let alice_sk = hexn(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
            56,
        );
        let alice_pk_hex = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
        let bob_sk = hexn(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
            56,
        );
        let bob_pk_hex = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
        let shared_hex = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

        let mut alice_pk = [0u8; 56];
        let mut bob_pk = [0u8; 56];
        // SAFETY: each pointer is live for the lengths used.
        unsafe {
            ossl_x448_public_from_private(alice_pk.as_mut_ptr(), alice_sk.as_ptr());
            ossl_x448_public_from_private(bob_pk.as_mut_ptr(), bob_sk.as_ptr());
        }
        assert_eq!(alice_pk[..], hexn(alice_pk_hex, 56)[..], "Alice public");
        assert_eq!(bob_pk[..], hexn(bob_pk_hex, 56)[..], "Bob public");

        let mut a_shared = [0u8; 56];
        let mut b_shared = [0u8; 56];
        // SAFETY: each pointer is live for the lengths used.
        unsafe {
            assert_eq!(
                ossl_x448(a_shared.as_mut_ptr(), alice_sk.as_ptr(), bob_pk.as_ptr()),
                1
            );
            assert_eq!(
                ossl_x448(b_shared.as_mut_ptr(), bob_sk.as_ptr(), alice_pk.as_ptr()),
                1
            );
        }
        assert_eq!(a_shared, b_shared);
        assert_eq!(a_shared[..], hexn(shared_hex, 56)[..], "shared secret");
    }

    /// RFC 8032 §7.4 — Ed448 `Sign-Message` vectors 1 and 2 as the authority's own
    /// `evppkey_ecx_sigalg.txt` records them: the public key, the signature for the message,
    /// and verification of that signature.
    #[test]
    fn ed448_rfc8032_section_7_4() {
        let sk1 = "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
        let pk1 = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
        let sig1 = "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600";
        let sk2 = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e";
        let pk2 = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480";
        let sig2 = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00";

        let cases: [(&str, &str, &str, &[u8]); 2] =
            [(sk1, pk1, sig1, &[]), (sk2, pk2, sig2, &[0x03])];
        for (sk_hex, pk_hex, sig_hex, msg) in cases {
            let sk = hexn(sk_hex, 57);
            let pk = hexn(pk_hex, 57);
            let mut out_pk = [0u8; 57];
            // SAFETY: each pointer is live for the lengths used.
            unsafe {
                assert_eq!(
                    ossl_ed448_public_from_private(
                        ptr::null_mut(),
                        out_pk.as_mut_ptr(),
                        sk.as_ptr(),
                        ptr::null(),
                    ),
                    1
                );
            }
            assert_eq!(out_pk[..], pk[..], "public key");

            let mut sig = [0u8; 114];
            // SAFETY: each pointer is live for the lengths used.
            unsafe {
                assert_eq!(
                    ossl_ed448_sign(
                        ptr::null_mut(),
                        sig.as_mut_ptr(),
                        msg.as_ptr(),
                        msg.len(),
                        pk.as_ptr(),
                        sk.as_ptr(),
                        ptr::null(),
                        0,
                        0,
                        ptr::null(),
                    ),
                    1
                );
            }
            assert_eq!(sig[..], hexn(sig_hex, 114)[..], "signature");

            // SAFETY: each pointer is live for the lengths used.
            unsafe {
                assert_eq!(
                    ossl_ed448_verify(
                        ptr::null_mut(),
                        msg.as_ptr(),
                        msg.len(),
                        sig.as_ptr(),
                        pk.as_ptr(),
                        ptr::null(),
                        0,
                        0,
                        ptr::null(),
                    ),
                    1
                );
            }
        }
    }
}
