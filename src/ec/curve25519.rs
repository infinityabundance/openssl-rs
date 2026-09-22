//! `crypto/ec/curve25519.c` — X25519 and Ed25519, and the `x25519-x86_64.pl` primitives,
//! Phase 8.7.
//!
//! Five thousand, eight hundred and seventy-nine lines, six non-static functions
//! (`ossl_x25519`, `ossl_x25519_public_from_private`, `ossl_ed25519_sign`,
//! `ossl_ed25519_pubkey_verify`, `ossl_ed25519_verify`, `ossl_ed25519_public_from_private`)
//! and the ten field primitives the authority's build takes from
//! `crypto/ec/asm/x25519-x86_64.pl` rather than from the C file's own reference arms.
//!
//! ## What the authority's build selects, and what that makes this module
//!
//! `Include/configdata.pm` defines `X25519_ASM` on this profile, so `curve25519.c` compiles
//! its **base 2^64** arm for the X25519 ladder (`x25519_scalar_mulx`) and its **base 2^51**
//! arm for the fallback, and takes `x25519_fe64_mul`, `_sqr`, `_mul121666`, `_add`, `_sub`,
//! `_tobytes`, `x25519_fe64_eligible`, `x25519_fe51_mul`, `_sqr` and `_mul121666` from the
//! perlasm unit. The Ed25519 half — the `fe` base-2^25.5 field, the Edwards group `ge_*`,
//! `ge_scalarmult_base`, `slide` and `ge_double_scalarmult_vartime` — is the C file's own on
//! every profile, and it is transcribed from the C. `x25519_scalar_mult_generic`'s 32-bit `fe`
//! body is **not** compiled on this profile (`#if !defined(BASE_2_51_IMPLEMENTED)`), so it is
//! not here.
//!
//! **The ten perlasm primitives are written as Rust, and `RT-ECX` is what proves they are the
//! same observable function.** The assembly and the crate's Rust are not textually related —
//! they cannot be, one is `mulx`/`adcx` and the other is `u128` schoolbook — and the precedent
//! is `crypto/aes/asm/aes-x86_64.pl` -> [`crate::aes`]: the differential court compiles one
//! probe against each library and diffs the shared secret, so agreement is a measurement
//! rather than a claim. Where the asm reduces *lazily* (its `mul`/`sqr`/`mul121666` leave a
//! representative in `[0, 2^256)`, congruent mod `2^256-38`), this module reduces fully; the
//! two are congruent mod the ring the following operations live in and `x25519_fe64_tobytes`
//! canonicalises, which is the only place the representative is observable. `fe64_eligible`
//! reads the two `CPUID.(EAX=7,ECX=0).EBX` bits (`BMI2` | `ADX`) the asm's
//! `OPENSSL_ia32cap_P[2] & 0x80100 == 0x80100` test reads, so which arm the ladder takes is
//! the same decision on either side.
//!
//! ## The one shape a transcription gets wrong here, and this one keeps
//!
//! `fe_mul`'s ten `h_k` are **not** a plain schoolbook convolution folded by 19. The `fe`
//! limbs carry weight `2^ceil(25.5*i)`, and for an `i+j = k+10` term with both `i` and `j`
//! odd the reduction by `2^255 = 19` picks up an extra factor of two (`ceil(25.5 i)+ceil(25.5
//! j)-ceil(25.5(i+j)) = 1` exactly then), which is why the authority's `h0` reads
//! `f1g9_38 + f2g8_19 + f3g7_38 + ...` and not `f1g9_19 + ...`. [`fe_conv`] derives the
//! coefficient from the exponents rather than recalling it, and [`fe_reduce`] is the
//! authority's carry chain verbatim. `fe_sq` is `fe_mul(f, f)` — the same integer sum, and
//! `fe_sq2` is that convolution doubled before its carry, which is the authority's own shape.
//!
//! ## Arithmetic and the profile
//!
//! `overflow-checks` is on in release, so an arithmetic overflow is a loud failure rather than
//! a wrap. Every field operation's intermediate range is the authority's own bound comment,
//! and the scalar reduction ([`x25519_sc_reduce`], [`sc_muladd`]) is a fixed-iteration masked
//! long division rather than the authority's unrolled Barrett-like form: the two are
//! congruent, and the loop count and the masked conditional subtract are both fixed, so the
//! constant-time property the unrolled form has is kept.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::ec::curve25519_data::{BI, K25519_PRECOMP};
use crate::evp::digest::{
    EVP_Digest, EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free, EvpMd, EvpMdCtx,
};
use crate::runtime::mem::{CRYPTO_memcmp, OPENSSL_cleanse};

/// `SHA512_DIGEST_LENGTH` — `include/openssl/sha.h:81`.
const SHA512_LEN: usize = 64;

/// The carry masks `fe_mul`/`fe_reduce` and `fe_frombytes` use — `curve25519.c:804-808`.
const K_BOTTOM_26: i32 = 0x3ffffff;
const K_BOTTOM_25: i32 = 0x1ffffff;
const K_TOP_39: i64 = 0xfffffffffe000000u64 as i64;
const K_TOP_38: i64 = 0xfffffffffc000000u64 as i64;

/// `MASK51` — `curve25519.c:278`.
const MASK51: u64 = 0x7ffffffffffff;

/// A base-`2^25.5` field element: ten signed limbs, `t[0] + 2^26 t[1] + 2^51 t[2] + ...`.
type Fe = [i32; 10];
/// A base-`2^51` field element: five limbs.
type Fe51 = [u64; 5];
/// A base-`2^64` field element modulo `2^256-38`: four limbs.
type Fe64 = [u64; 4];

/// `ge_p2` — projective `(X:Y:Z)` with `x = X/Z`, `y = Y/Z` — `curve25519.c:1930`.
#[derive(Clone, Copy)]
struct GeP2 {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// `ge_p3` — extended `(X:Y:Z:T)` with `XY = ZT` — `curve25519.c:1936`.
#[derive(Clone, Copy)]
struct GeP3 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// `ge_p1p1` — completed `((X:Z),(Y:T))` — `curve25519.c:1943`.
#[derive(Clone, Copy)]
struct GeP1P1 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// `ge_precomp` — Duif's `(y+x, y-x, 2dxy)` — `curve25519.c:1950`.
#[derive(Clone, Copy)]
struct GePrecomp {
    yplusx: Fe,
    yminusx: Fe,
    xy2d: Fe,
}

/// `ge_cached` — `(Y+X, Y-X, Z, 2dT)` — `curve25519.c:1956`.
#[derive(Clone, Copy)]
struct GeCached {
    yplusx: Fe,
    yminusx: Fe,
    z: Fe,
    t2d: Fe,
}

/// `d = -121665/121666` — `curve25519.c:1989`.
const D: Fe = [
    -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448,
    -12055116,
];

/// `sqrt(-1)` — `curve25519.c:1994`.
const SQRTM1: Fe = [
    -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482,
];

/// `d2 = 2*d` — `curve25519.c:2068`.
const D2: Fe = [
    -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968,
    9444199,
];

// =====================================================================================
// The `x25519-x86_64.pl` primitives: base 2^64 mod 2^256-38, and base 2^51
// =====================================================================================

/// `x25519_fe64_eligible` — `x25519-x86_64.pl:496`.
///
/// The asm answers `OPENSSL_ia32cap_P[2] & 0x80100` if that equals `0x80100` and zero
/// otherwise; `OPENSSL_ia32cap_P[2]` is `CPUID.(EAX=7,ECX=0).EBX`, whose bits 8 and 19 are
/// `BMI2` and `ADX`. The ladder's *result* is the same mathematical function either way, so
/// only a caller that reads this answer as a value can see the difference.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn x25519_fe64_eligible() -> c_int {
    // SAFETY: `__cpuid_count` is a pure register read for a leaf this CPU defines.
    let ebx = core::arch::x86_64::__cpuid_count(7, 0).ebx;
    let m = ebx & 0x80100;
    if m == 0x80100 {
        m as c_int
    } else {
        0
    }
}

/// A non-x86 build takes the C file's `#else` spelling, which answers zero — `x25519-x86_64.pl:891`.
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub extern "C" fn x25519_fe64_eligible() -> c_int {
    0
}

/// `fe64_fold` — `low + 38*high` mod `2^256-38`, the `.Lreduce64` block's arithmetic
/// (`x25519-x86_64.pl:680-710`).
fn fe64_fold(lo: Fe64, hi: Fe64) -> Fe64 {
    let mask = u64::MAX as u128;
    let mut r = [0u128; 5];
    for i in 0..4 {
        r[i] = lo[i] as u128 + 38 * (hi[i] as u128);
    }
    let mut carry = 0u128;
    for v in r.iter_mut().take(4) {
        let s = *v + carry;
        *v = s & mask;
        carry = s >> 64;
    }
    r[4] = carry;
    // Fold the top limb back in, twice: `38*2^64 < 2^70` so one pass leaves at most a
    // six-bit carry, and the second pass clears even that.
    for _ in 0..2 {
        r[0] += 38 * r[4];
        r[4] = 0;
        let mut carry = 0u128;
        for v in r.iter_mut().take(4) {
            let s = *v + carry;
            *v = s & mask;
            carry = s >> 64;
        }
        r[4] = carry;
    }
    [r[0] as u64, r[1] as u64, r[2] as u64, r[3] as u64]
}

/// The full 512-bit product of two base-`2^64` field elements.
fn fe64_full_mul(f: &Fe64, g: &Fe64) -> [u64; 8] {
    let mut p = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let cur = p[i + j] as u128 + (f[i] as u128) * (g[j] as u128) + carry;
            p[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + 4;
        while carry != 0 && k < 8 {
            let cur = p[k] as u128 + carry;
            p[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }
    p
}

/// `void x25519_fe64_mul(fe64 h, const fe64 f, const fe64 g)` — the product mod `2^256-38`.
fn fe64_mul_arr(f: &Fe64, g: &Fe64) -> Fe64 {
    let p = fe64_full_mul(f, g);
    fe64_fold([p[0], p[1], p[2], p[3]], [p[4], p[5], p[6], p[7]])
}

/// `void x25519_fe64_sqr(fe64 h, const fe64 f)`.
fn fe64_sqr_arr(f: &Fe64) -> Fe64 {
    fe64_mul_arr(f, f)
}

/// `fe64_mul121666` — `x25519-x86_64.pl:731`, as four limbs times 121666.
fn fe64_mul121666_arr(f: &Fe64) -> Fe64 {
    let p = fe64_full_mul(f, &[121666, 0, 0, 0]);
    fe64_fold([p[0], p[1], p[2], p[3]], [p[4], p[5], p[6], p[7]])
}

/// `void x25519_fe64_add(fe64 h, const fe64 f, const fe64 g)` — `x25519-x86_64.pl:768`.
fn fe64_add_arr(f: &Fe64, g: &Fe64) -> Fe64 {
    let mut acc = [0u64; 4];
    let mut c = 0u64;
    for i in 0..4 {
        let v = (f[i] as u128) + (g[i] as u128) + (c as u128);
        acc[i] = v as u64;
        c = (v >> 64) as u64;
    }
    // Two folds of the carry out of bit 256, exactly the asm's two `and $38` passes.
    let mut carry = 38u64.wrapping_mul(c);
    for a in acc.iter_mut() {
        let v = (*a as u128) + (carry as u128);
        *a = v as u64;
        carry = (v >> 64) as u64;
    }
    acc[0] = acc[0].wrapping_add(38u64.wrapping_mul(carry));
    acc
}

/// `void x25519_fe64_sub(fe64 h, const fe64 f, const fe64 g)` — `x25519-x86_64.pl:805`.
fn fe64_sub_arr(f: &Fe64, g: &Fe64) -> Fe64 {
    let mut acc = [0u64; 4];
    let mut b = 0u64;
    for i in 0..4 {
        let v = (f[i] as u128)
            .wrapping_sub(g[i] as u128)
            .wrapping_sub(b as u128);
        acc[i] = v as u64;
        b = ((v >> 64) & 1) as u64;
    }
    let mut borrow = 38u64.wrapping_mul(b);
    for a in acc.iter_mut() {
        let v = (*a as u128).wrapping_sub(borrow as u128);
        *a = v as u64;
        borrow = ((v >> 64) & 1) as u64;
    }
    acc[0] = acc[0].wrapping_sub(38u64.wrapping_mul(borrow));
    acc
}

/// `void x25519_fe64_tobytes(uint8_t *s, const fe64 f)` — canonical mod `2^255-19`.
fn fe64_tobytes_arr(f: &Fe64) -> [u8; 32] {
    // Fold bit 255 down (`2^255 = 19 mod p`) then conditionally subtract `p`, generically:
    // the asm does exactly this with two `sar`-masked passes (`x25519-x86_64.pl:842`).
    let mut t = [0u128; 4];
    for i in 0..4 {
        t[i] = f[i] as u128;
    }
    for _ in 0..2 {
        let hi = t[3] >> 63;
        t[3] &= (1u128 << 63) - 1;
        t[0] += 19 * hi;
        let mut carry = 0u128;
        for v in t.iter_mut() {
            let s = *v + carry;
            *v = s & (u64::MAX as u128);
            carry = s >> 64;
        }
        t[0] += 19 * carry;
    }
    // `p = 2^255 - 19`: subtract if `t >= p`, masked so the branch is not a secret one.
    const P_LO: [u64; 4] = [0xffffffffffffffed, u64::MAX, u64::MAX, 0x7fffffffffffffff];
    let mut sub = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (v, o) = (t[i] as u64).overflowing_sub(P_LO[i]);
        let (v, o2) = v.overflowing_sub(borrow);
        sub[i] = v;
        borrow = (o as u64) | (o2 as u64);
    }
    // borrow == 1 means `t < p`, keep `t`; borrow == 0 means `t >= p`, take `sub`.
    let mask = borrow.wrapping_sub(1); // all-ones when borrow == 0
    let mut out = [0u8; 32];
    for i in 0..4 {
        let v = ((t[i] as u64) & !mask) | (sub[i] & mask);
        out[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// `x25519_fe64_mul` — `x25519-x86_64.pl:510`.
///
/// # Safety
/// `h` must be writable and `f`/`g` readable for four `u64` each.
#[no_mangle]
pub unsafe extern "C" fn x25519_fe64_mul(h: *mut u64, f: *const u64, g: *const u64) {
    // SAFETY: the contract gives each pointer four readable/writable `u64`.
    let ff = unsafe { *(f as *const Fe64) };
    // SAFETY: as above.
    let gg = unsafe { *(g as *const Fe64) };
    let r = fe64_mul_arr(&ff, &gg);
    // SAFETY: `h` is writable for four `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), h, 4) };
}

/// `x25519_fe64_sqr` — `x25519-x86_64.pl:602`.
///
/// # Safety
/// `h` must be writable and `f` readable for four `u64`.
#[no_mangle]
pub unsafe extern "C" fn x25519_fe64_sqr(h: *mut u64, f: *const u64) {
    // SAFETY: the contract gives the pointer four readable `u64`.
    let ff = unsafe { *(f as *const Fe64) };
    let r = fe64_sqr_arr(&ff);
    // SAFETY: `h` is writable for four `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), h, 4) };
}

/// `x25519_fe64_mul121666` — `x25519-x86_64.pl:731`.
///
/// # Safety
/// `h` must be writable and `f` readable for four `u64`.
#[no_mangle]
pub unsafe extern "C" fn x25519_fe64_mul121666(h: *mut u64, f: *const u64) {
    // SAFETY: the contract gives the pointer four readable `u64`.
    let ff = unsafe { *(f as *const Fe64) };
    let r = fe64_mul121666_arr(&ff);
    // SAFETY: `h` is writable for four `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), h, 4) };
}

/// `x25519_fe64_add` — `x25519-x86_64.pl:768`.
///
/// # Safety
/// `h` must be writable and `f`/`g` readable for four `u64` each.
#[no_mangle]
pub unsafe extern "C" fn x25519_fe64_add(h: *mut u64, f: *const u64, g: *const u64) {
    // SAFETY: the contract gives each pointer four readable/writable `u64`.
    let ff = unsafe { *(f as *const Fe64) };
    // SAFETY: as above.
    let gg = unsafe { *(g as *const Fe64) };
    let r = fe64_add_arr(&ff, &gg);
    // SAFETY: `h` is writable for four `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), h, 4) };
}

/// `x25519_fe64_sub` — `x25519-x86_64.pl:805`.
///
/// # Safety
/// `h` must be writable and `f`/`g` readable for four `u64` each.
#[no_mangle]
pub unsafe extern "C" fn x25519_fe64_sub(h: *mut u64, f: *const u64, g: *const u64) {
    // SAFETY: the contract gives each pointer four readable/writable `u64`.
    let ff = unsafe { *(f as *const Fe64) };
    // SAFETY: as above.
    let gg = unsafe { *(g as *const Fe64) };
    let r = fe64_sub_arr(&ff, &gg);
    // SAFETY: `h` is writable for four `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), h, 4) };
}

/// `x25519_fe64_tobytes` — `x25519-x86_64.pl:842`.
///
/// # Safety
/// `s` must be writable for 32 bytes and `f` readable for four `u64`.
#[no_mangle]
pub unsafe extern "C" fn x25519_fe64_tobytes(s: *mut u8, f: *const u64) {
    // SAFETY: the contract gives the pointer four readable `u64`.
    let ff = unsafe { *(f as *const Fe64) };
    let r = fe64_tobytes_arr(&ff);
    // SAFETY: `s` is writable for 32 bytes.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), s, 32) };
}

/// `fe51_mul` — the base-2^51 product with the authority's lazy reduction
/// (`curve25519.c:407`).
fn fe51_mul_arr(f: &Fe51, g: &Fe51) -> Fe51 {
    let g0 = g[0];
    let mut g1 = g[1];
    let mut g2 = g[2];
    let mut g3 = g[3];
    let mut g4 = g[4];
    let mut h0 = (f[0] as u128) * (g0 as u128);
    let mut h1 = (f[0] as u128) * (g1 as u128);
    let mut h2 = (f[0] as u128) * (g2 as u128);
    let mut h3 = (f[0] as u128) * (g3 as u128);
    let mut h4 = (f[0] as u128) * (g4 as u128);

    let fi = f[1] as u128;
    g4 = g4.wrapping_mul(19);
    h0 += fi * (g4 as u128);
    h1 += fi * (g0 as u128);
    h2 += fi * (g1 as u128);
    h3 += fi * (g2 as u128);
    h4 += fi * (g3 as u128);

    let fi = f[2] as u128;
    g3 = g3.wrapping_mul(19);
    h0 += fi * (g3 as u128);
    h1 += fi * (g4 as u128);
    h2 += fi * (g0 as u128);
    h3 += fi * (g1 as u128);
    h4 += fi * (g2 as u128);

    let fi = f[3] as u128;
    g2 = g2.wrapping_mul(19);
    h0 += fi * (g2 as u128);
    h1 += fi * (g3 as u128);
    h2 += fi * (g4 as u128);
    h3 += fi * (g0 as u128);
    h4 += fi * (g1 as u128);

    let fi = f[4] as u128;
    g1 = g1.wrapping_mul(19);
    h0 += fi * (g1 as u128);
    h1 += fi * (g2 as u128);
    h2 += fi * (g3 as u128);
    h3 += fi * (g4 as u128);
    h4 += fi * (g0 as u128);

    h3 += h2 >> 51;
    let mut o2 = (h2 as u64) & MASK51;
    h1 += h0 >> 51;
    let mut o0 = (h0 as u64) & MASK51;

    h4 += h3 >> 51;
    let mut o3 = (h3 as u64) & MASK51;
    o2 = o2.wrapping_add((h1 >> 51) as u64);
    let mut o1 = (h1 as u64) & MASK51;

    o0 = o0.wrapping_add(((h4 >> 51) as u64).wrapping_mul(19));
    let o4 = (h4 as u64) & MASK51;
    o3 = o3.wrapping_add(o2 >> 51);
    o2 &= MASK51;
    o1 = o1.wrapping_add(o0 >> 51);
    o0 &= MASK51;

    [o0, o1, o2, o3, o4]
}

/// `fe51_sqr` — `curve25519.c:472`.
fn fe51_sqr_arr(f: &Fe51) -> Fe51 {
    let mut g0 = f[0];
    let mut g1 = f[1];
    let mut g2 = f[2];
    let mut g3 = f[3];
    let mut g4 = f[4];
    let mut h0: u128;
    let mut h1: u128;
    let mut h2: u128;
    let mut h3: u128;
    let mut h4: u128;

    h0 = (g0 as u128) * (g0 as u128);
    g0 = g0.wrapping_mul(2);
    h1 = (g0 as u128) * (g1 as u128);
    h2 = (g0 as u128) * (g2 as u128);
    h3 = (g0 as u128) * (g3 as u128);
    h4 = (g0 as u128) * (g4 as u128);

    g0 = g4; /* borrow g0 */
    g4 = g4.wrapping_mul(19);
    h3 += (g0 as u128) * (g4 as u128);

    h2 += (g1 as u128) * (g1 as u128);
    g1 = g1.wrapping_mul(2);
    h3 += (g1 as u128) * (g2 as u128);
    h4 += (g1 as u128) * (g3 as u128);
    h0 += (g1 as u128) * (g4 as u128);

    g0 = g3; /* borrow g0 */
    g3 = g3.wrapping_mul(19);
    h1 += (g0 as u128) * (g3 as u128);
    h2 += ((g0 as u128) * 2) * (g4 as u128);

    h4 += (g2 as u128) * (g2 as u128);
    g2 = g2.wrapping_mul(2);
    h0 += (g2 as u128) * (g3 as u128);
    h1 += (g2 as u128) * (g4 as u128);

    h3 += h2 >> 51;
    let mut o2 = (h2 as u64) & MASK51;
    h1 += h0 >> 51;
    let mut o0 = (h0 as u64) & MASK51;

    h4 += h3 >> 51;
    let mut o3 = (h3 as u64) & MASK51;
    o2 = o2.wrapping_add((h1 >> 51) as u64);
    let mut o1 = (h1 as u64) & MASK51;

    o0 = o0.wrapping_add(((h4 >> 51) as u64).wrapping_mul(19));
    let o4 = (h4 as u64) & MASK51;
    o3 = o3.wrapping_add(o2 >> 51);
    o2 &= MASK51;
    o1 = o1.wrapping_add(o0 >> 51);
    o0 &= MASK51;

    [o0, o1, o2, o3, o4]
}

/// `fe51_mul121666` — `curve25519.c:536`.
fn fe51_mul121666_arr(f: &Fe51) -> Fe51 {
    let h0 = (f[0] as u128) * 121666;
    let mut h1 = (f[1] as u128) * 121666;
    let h2 = (f[2] as u128) * 121666;
    let mut h3 = (f[3] as u128) * 121666;
    let mut h4 = (f[4] as u128) * 121666;

    h3 += h2 >> 51;
    let mut o2 = (h2 as u64) & MASK51;
    h1 += h0 >> 51;
    let mut o0 = (h0 as u64) & MASK51;

    h4 += h3 >> 51;
    let mut o3 = (h3 as u64) & MASK51;
    o2 = o2.wrapping_add((h1 >> 51) as u64);
    let mut o1 = (h1 as u64) & MASK51;

    o0 = o0.wrapping_add(((h4 >> 51) as u64).wrapping_mul(19));
    let o4 = (h4 as u64) & MASK51;
    o3 = o3.wrapping_add(o2 >> 51);
    o2 &= MASK51;
    o1 = o1.wrapping_add(o0 >> 51);
    o0 &= MASK51;

    [o0, o1, o2, o3, o4]
}

/// `x25519_fe51_mul` — `curve25519.c:396`.
///
/// # Safety
/// `h` must be writable and `f`/`g` readable for five `u64` each.
#[no_mangle]
pub unsafe extern "C" fn x25519_fe51_mul(h: *mut u64, f: *const u64, g: *const u64) {
    // SAFETY: the contract gives each pointer five readable/writable `u64`.
    let ff = unsafe { *(f as *const Fe51) };
    // SAFETY: as above.
    let gg = unsafe { *(g as *const Fe51) };
    let r = fe51_mul_arr(&ff, &gg);
    // SAFETY: `h` is writable for five `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), h, 5) };
}

/// `x25519_fe51_sqr` — `curve25519.c:398`.
///
/// # Safety
/// `h` must be writable and `f` readable for five `u64`.
#[no_mangle]
pub unsafe extern "C" fn x25519_fe51_sqr(h: *mut u64, f: *const u64) {
    // SAFETY: the contract gives the pointer five readable `u64`.
    let ff = unsafe { *(f as *const Fe51) };
    let r = fe51_sqr_arr(&ff);
    // SAFETY: `h` is writable for five `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), h, 5) };
}

/// `x25519_fe51_mul121666` — `curve25519.c:399`.
///
/// # Safety
/// `h` must be writable and `f` readable for five `u64`.
#[no_mangle]
pub unsafe extern "C" fn x25519_fe51_mul121666(h: *mut u64, f: *const u64) {
    // SAFETY: the contract gives the pointer five readable `u64`.
    let ff = unsafe { *(f as *const Fe51) };
    let r = fe51_mul121666_arr(&ff);
    // SAFETY: `h` is writable for five `u64`.
    unsafe { ptr::copy_nonoverlapping(r.as_ptr(), h, 5) };
}

/// `fe51_frombytes` — `curve25519.c:309`.
fn fe51_frombytes(s: &[u8; 32]) -> Fe51 {
    let load_7 = |at: usize| -> u64 {
        let mut r = 0u64;
        for k in 0..7 {
            r |= (s[at + k] as u64) << (8 * k);
        }
        r
    };
    let load_6 = |at: usize| -> u64 {
        let mut r = 0u64;
        for k in 0..6 {
            r |= (s[at + k] as u64) << (8 * k);
        }
        r
    };
    let mut h0 = load_7(0);
    let mut h1 = load_6(7) << 5;
    let mut h2 = load_7(13) << 2;
    let mut h3 = load_6(20) << 7;
    let mut h4 = (load_6(26) & 0x7fffffffffff) << 4;

    h1 |= h0 >> 51;
    h0 &= MASK51;
    h2 |= h1 >> 51;
    h1 &= MASK51;
    h3 |= h2 >> 51;
    h2 &= MASK51;
    h4 |= h3 >> 51;
    h3 &= MASK51;
    [h0, h1, h2, h3, h4]
}

/// `fe51_tobytes` — `curve25519.c:333`.
fn fe51_tobytes(h: &Fe51) -> [u8; 32] {
    let mut h0 = h[0];
    let mut h1 = h[1];
    let mut h2 = h[2];
    let mut h3 = h[3];
    let mut h4 = h[4];

    let mut q = (h0 + 19) >> 51;
    q = (h1 + q) >> 51;
    q = (h2 + q) >> 51;
    q = (h3 + q) >> 51;
    q = (h4 + q) >> 51;

    h0 += 19 * q;
    h1 += h0 >> 51;
    h0 &= MASK51;
    h2 += h1 >> 51;
    h1 &= MASK51;
    h3 += h2 >> 51;
    h2 &= MASK51;
    h4 += h3 >> 51;
    h3 &= MASK51;
    h4 &= MASK51;

    let mut s = [0u8; 32];
    s[0] = h0 as u8;
    s[1] = (h0 >> 8) as u8;
    s[2] = (h0 >> 16) as u8;
    s[3] = (h0 >> 24) as u8;
    s[4] = (h0 >> 32) as u8;
    s[5] = (h0 >> 40) as u8;
    s[6] = ((h0 >> 48) as u32 | ((h1 as u32) << 3)) as u8;
    s[7] = (h1 >> 5) as u8;
    s[8] = (h1 >> 13) as u8;
    s[9] = (h1 >> 21) as u8;
    s[10] = (h1 >> 29) as u8;
    s[11] = (h1 >> 37) as u8;
    s[12] = ((h1 >> 45) as u32 | ((h2 as u32) << 6)) as u8;
    s[13] = (h2 >> 2) as u8;
    s[14] = (h2 >> 10) as u8;
    s[15] = (h2 >> 18) as u8;
    s[16] = (h2 >> 26) as u8;
    s[17] = (h2 >> 34) as u8;
    s[18] = (h2 >> 42) as u8;
    s[19] = ((h2 >> 50) as u32 | ((h3 as u32) << 1)) as u8;
    s[20] = (h3 >> 7) as u8;
    s[21] = (h3 >> 15) as u8;
    s[22] = (h3 >> 23) as u8;
    s[23] = (h3 >> 31) as u8;
    s[24] = (h3 >> 39) as u8;
    s[25] = ((h3 >> 47) as u32 | ((h4 as u32) << 4)) as u8;
    s[26] = (h4 >> 4) as u8;
    s[27] = (h4 >> 12) as u8;
    s[28] = (h4 >> 20) as u8;
    s[29] = (h4 >> 28) as u8;
    s[30] = (h4 >> 36) as u8;
    s[31] = (h4 >> 44) as u8;
    s
}

/// `fe51_add` — `curve25519.c:570`.
fn fe51_add(f: &Fe51, g: &Fe51) -> Fe51 {
    let mut h = [0u64; 5];
    for i in 0..5 {
        h[i] = f[i].wrapping_add(g[i]);
    }
    h
}

/// `fe51_sub` — `curve25519.c:579`.
fn fe51_sub(f: &Fe51, g: &Fe51) -> Fe51 {
    const ADD: [u64; 5] = [
        0xfffffffffffda,
        0xffffffffffffe,
        0xffffffffffffe,
        0xffffffffffffe,
        0xffffffffffffe,
    ];
    let mut h = [0u64; 5];
    for i in 0..5 {
        h[i] = f[i].wrapping_add(ADD[i]).wrapping_sub(g[i]);
    }
    h
}

/// `fe51_0` — `curve25519.c:592`.
fn fe51_0() -> Fe51 {
    [0u64; 5]
}

/// `fe51_1` — `curve25519.c:601`.
fn fe51_1() -> Fe51 {
    [1, 0, 0, 0, 0]
}

/// `fe51_cswap` — `curve25519.c:619`.
fn fe51_cswap(f: &mut Fe51, g: &mut Fe51, b: u64) {
    let mask = 0u64.wrapping_sub(b);
    for i in 0..5 {
        let x = (f[i] ^ g[i]) & mask;
        f[i] ^= x;
        g[i] ^= x;
    }
}

/// `fe51_invert` — `curve25519.c:632`.
fn fe51_invert(z: &Fe51) -> Fe51 {
    let mut t0 = fe51_sqr_arr(z);
    let mut t1 = fe51_sqr_arr(&t0);
    t1 = fe51_sqr_arr(&t1);
    t1 = fe51_mul_arr(z, &t1);
    t0 = fe51_mul_arr(&t0, &t1);
    let mut t2 = fe51_sqr_arr(&t0);
    t1 = fe51_mul_arr(&t1, &t2);
    t2 = fe51_sqr_arr(&t1);
    for _ in 1..5 {
        t2 = fe51_sqr_arr(&t2);
    }
    t1 = fe51_mul_arr(&t2, &t1);
    t2 = fe51_sqr_arr(&t1);
    for _ in 1..10 {
        t2 = fe51_sqr_arr(&t2);
    }
    t2 = fe51_mul_arr(&t2, &t1);
    let mut t3 = fe51_sqr_arr(&t2);
    for _ in 1..20 {
        t3 = fe51_sqr_arr(&t3);
    }
    t2 = fe51_mul_arr(&t3, &t2);
    for _ in 0..10 {
        t2 = fe51_sqr_arr(&t2);
    }
    t1 = fe51_mul_arr(&t2, &t1);
    t2 = fe51_sqr_arr(&t1);
    for _ in 1..50 {
        t2 = fe51_sqr_arr(&t2);
    }
    t2 = fe51_mul_arr(&t2, &t1);
    t3 = fe51_sqr_arr(&t2);
    for _ in 1..100 {
        t3 = fe51_sqr_arr(&t3);
    }
    t2 = fe51_mul_arr(&t3, &t2);
    for _ in 0..50 {
        t2 = fe51_sqr_arr(&t2);
    }
    t1 = fe51_mul_arr(&t2, &t1);
    for _ in 0..5 {
        t1 = fe51_sqr_arr(&t1);
    }
    fe51_mul_arr(&t1, &t0)
}

/// `fe64_frombytes` — `curve25519.c:70`.
fn fe64_frombytes(s: &[u8; 32]) -> Fe64 {
    let load_8 = |at: usize| -> u64 {
        let mut r = 0u64;
        for k in 0..8 {
            r |= (s[at + k] as u64) << (8 * k);
        }
        r
    };
    [
        load_8(0),
        load_8(8),
        load_8(16),
        load_8(24) & 0x7fffffffffffffff,
    ]
}

/// `fe64_cswap` — `curve25519.c:102`.
fn fe64_cswap(f: &mut Fe64, g: &mut Fe64, b: u64) {
    let mask = 0u64.wrapping_sub(b);
    for i in 0..4 {
        let x = (f[i] ^ g[i]) & mask;
        f[i] ^= x;
        g[i] ^= x;
    }
}

/// `fe64_invert` — `curve25519.c:115`.
fn fe64_invert(z: &Fe64) -> Fe64 {
    let mut t0 = fe64_sqr_arr(z);
    let mut t1 = fe64_sqr_arr(&t0);
    t1 = fe64_sqr_arr(&t1);
    t1 = fe64_mul_arr(z, &t1);
    t0 = fe64_mul_arr(&t0, &t1);
    let mut t2 = fe64_sqr_arr(&t0);
    t1 = fe64_mul_arr(&t1, &t2);
    t2 = fe64_sqr_arr(&t1);
    for _ in 1..5 {
        t2 = fe64_sqr_arr(&t2);
    }
    t1 = fe64_mul_arr(&t2, &t1);
    t2 = fe64_sqr_arr(&t1);
    for _ in 1..10 {
        t2 = fe64_sqr_arr(&t2);
    }
    t2 = fe64_mul_arr(&t2, &t1);
    let mut t3 = fe64_sqr_arr(&t2);
    for _ in 1..20 {
        t3 = fe64_sqr_arr(&t3);
    }
    t2 = fe64_mul_arr(&t3, &t2);
    for _ in 0..10 {
        t2 = fe64_sqr_arr(&t2);
    }
    t1 = fe64_mul_arr(&t2, &t1);
    t2 = fe64_sqr_arr(&t1);
    for _ in 1..50 {
        t2 = fe64_sqr_arr(&t2);
    }
    t2 = fe64_mul_arr(&t2, &t1);
    t3 = fe64_sqr_arr(&t2);
    for _ in 1..100 {
        t3 = fe64_sqr_arr(&t3);
    }
    t2 = fe64_mul_arr(&t3, &t2);
    for _ in 0..50 {
        t2 = fe64_sqr_arr(&t2);
    }
    t1 = fe64_mul_arr(&t2, &t1);
    for _ in 0..5 {
        t1 = fe64_sqr_arr(&t1);
    }
    fe64_mul_arr(&t1, &t0)
}

// =====================================================================================
// The base-2^25.5 field: `fe` (Ed25519, and `ossl_x25519_public_from_private`)
// =====================================================================================

/// `load_3` — `curve25519.c:810`.
fn load_3(s: &[u8], at: usize) -> u64 {
    (s[at] as u64) | ((s[at + 1] as u64) << 8) | ((s[at + 2] as u64) << 16)
}

/// `load_4` — `curve25519.c:820`.
fn load_4(s: &[u8], at: usize) -> u64 {
    (s[at] as u64)
        | ((s[at + 1] as u64) << 8)
        | ((s[at + 2] as u64) << 16)
        | ((s[at + 3] as u64) << 24)
}

/// `fe_frombytes` — `curve25519.c:831`.
fn fe_frombytes(s: &[u8; 32]) -> Fe {
    let mut h0 = load_4(s, 0) as i64;
    let mut h1 = (load_3(s, 4) as i64) << 6;
    let mut h2 = (load_3(s, 7) as i64) << 5;
    let mut h3 = (load_3(s, 10) as i64) << 3;
    let mut h4 = (load_3(s, 13) as i64) << 2;
    let mut h5 = load_4(s, 16) as i64;
    let mut h6 = (load_3(s, 20) as i64) << 7;
    let mut h7 = (load_3(s, 23) as i64) << 5;
    let mut h8 = (load_3(s, 26) as i64) << 4;
    let mut h9 = ((load_3(s, 29) & 0x7fffff) as i64) << 2;

    let c9 = h9 + (1 << 24);
    h0 += (c9 >> 25) * 19;
    h9 -= c9 & K_TOP_39;
    let c1 = h1 + (1 << 24);
    h2 += c1 >> 25;
    h1 -= c1 & K_TOP_39;
    let c3 = h3 + (1 << 24);
    h4 += c3 >> 25;
    h3 -= c3 & K_TOP_39;
    let c5 = h5 + (1 << 24);
    h6 += c5 >> 25;
    h5 -= c5 & K_TOP_39;
    let c7 = h7 + (1 << 24);
    h8 += c7 >> 25;
    h7 -= c7 & K_TOP_39;

    let c0 = h0 + (1 << 25);
    h1 += c0 >> 26;
    h0 -= c0 & K_TOP_38;
    let c2 = h2 + (1 << 25);
    h3 += c2 >> 26;
    h2 -= c2 & K_TOP_38;
    let c4 = h4 + (1 << 25);
    h5 += c4 >> 26;
    h4 -= c4 & K_TOP_38;
    let c6 = h6 + (1 << 25);
    h7 += c6 >> 26;
    h6 -= c6 & K_TOP_38;
    let c8 = h8 + (1 << 25);
    h9 += c8 >> 26;
    h8 -= c8 & K_TOP_38;

    [
        h0 as i32, h1 as i32, h2 as i32, h3 as i32, h4 as i32, h5 as i32, h6 as i32, h7 as i32,
        h8 as i32, h9 as i32,
    ]
}

/// `fe_tobytes` — `curve25519.c:923`.
fn fe_tobytes(h: &Fe) -> [u8; 32] {
    let mut h0 = h[0];
    let mut h1 = h[1];
    let mut h2 = h[2];
    let mut h3 = h[3];
    let mut h4 = h[4];
    let mut h5 = h[5];
    let mut h6 = h[6];
    let mut h7 = h[7];
    let mut h8 = h[8];
    let mut h9 = h[9];

    let mut q = (19 * h9 + (1 << 24)) >> 25;
    q = (h0 + q) >> 26;
    q = (h1 + q) >> 25;
    q = (h2 + q) >> 26;
    q = (h3 + q) >> 25;
    q = (h4 + q) >> 26;
    q = (h5 + q) >> 25;
    q = (h6 + q) >> 26;
    q = (h7 + q) >> 25;
    q = (h8 + q) >> 26;
    q = (h9 + q) >> 25;

    h0 += 19 * q;

    h1 += h0 >> 26;
    h0 &= K_BOTTOM_26;
    h2 += h1 >> 25;
    h1 &= K_BOTTOM_25;
    h3 += h2 >> 26;
    h2 &= K_BOTTOM_26;
    h4 += h3 >> 25;
    h3 &= K_BOTTOM_25;
    h5 += h4 >> 26;
    h4 &= K_BOTTOM_26;
    h6 += h5 >> 25;
    h5 &= K_BOTTOM_25;
    h7 += h6 >> 26;
    h6 &= K_BOTTOM_26;
    h8 += h7 >> 25;
    h7 &= K_BOTTOM_25;
    h9 += h8 >> 26;
    h8 &= K_BOTTOM_26;
    h9 &= K_BOTTOM_25;

    let mut s = [0u8; 32];
    s[0] = h0 as u8;
    s[1] = (h0 >> 8) as u8;
    s[2] = (h0 >> 16) as u8;
    s[3] = ((h0 >> 24) as u32 | ((h1 as u32) << 2)) as u8;
    s[4] = (h1 >> 6) as u8;
    s[5] = (h1 >> 14) as u8;
    s[6] = ((h1 >> 22) as u32 | ((h2 as u32) << 3)) as u8;
    s[7] = (h2 >> 5) as u8;
    s[8] = (h2 >> 13) as u8;
    s[9] = ((h2 >> 21) as u32 | ((h3 as u32) << 5)) as u8;
    s[10] = (h3 >> 3) as u8;
    s[11] = (h3 >> 11) as u8;
    s[12] = ((h3 >> 19) as u32 | ((h4 as u32) << 6)) as u8;
    s[13] = (h4 >> 2) as u8;
    s[14] = (h4 >> 10) as u8;
    s[15] = (h4 >> 18) as u8;
    s[16] = h5 as u8;
    s[17] = (h5 >> 8) as u8;
    s[18] = (h5 >> 16) as u8;
    s[19] = ((h5 >> 24) as u32 | ((h6 as u32) << 1)) as u8;
    s[20] = (h6 >> 7) as u8;
    s[21] = (h6 >> 15) as u8;
    s[22] = ((h6 >> 23) as u32 | ((h7 as u32) << 3)) as u8;
    s[23] = (h7 >> 5) as u8;
    s[24] = (h7 >> 13) as u8;
    s[25] = ((h7 >> 21) as u32 | ((h8 as u32) << 4)) as u8;
    s[26] = (h8 >> 4) as u8;
    s[27] = (h8 >> 12) as u8;
    s[28] = ((h8 >> 20) as u32 | ((h9 as u32) << 6)) as u8;
    s[29] = (h9 >> 2) as u8;
    s[30] = (h9 >> 10) as u8;
    s[31] = (h9 >> 18) as u8;
    s
}

/// `fe_0` — `curve25519.c:1021`.
fn fe_0() -> Fe {
    [0; 10]
}

/// `fe_1` — `curve25519.c:1027`.
fn fe_1() -> Fe {
    let mut h = [0; 10];
    h[0] = 1;
    h
}

/// `fe_add` — `curve25519.c:1045`.
fn fe_add(f: &Fe, g: &Fe) -> Fe {
    let mut h = [0i32; 10];
    for i in 0..10 {
        h[i] = f[i] + g[i];
    }
    h
}

/// `fe_sub` — `curve25519.c:1066`.
fn fe_sub(f: &Fe, g: &Fe) -> Fe {
    let mut h = [0i32; 10];
    for i in 0..10 {
        h[i] = f[i] - g[i];
    }
    h
}

/// `fe_neg` — `curve25519.c:1620`.
fn fe_neg(f: &Fe) -> Fe {
    let mut h = [0i32; 10];
    for i in 0..10 {
        h[i] = -f[i];
    }
    h
}

/// `fe_cmov` — `curve25519.c:1635`.
fn fe_cmov(f: &mut Fe, g: &Fe, b: u32) {
    let m = 0u32.wrapping_sub(b) as i32;
    for i in 0..10 {
        let x = (f[i] ^ g[i]) & m;
        f[i] ^= x;
    }
}

/// `fe_conv` — the ten `h_k` of `fe_mul` (`curve25519.c:1241-1250`), derived from the limb
/// exponents rather than recalled: for a folded `i+j = k+10` term the `2^255 = 19` reduction
/// carries an extra factor two exactly when both `i` and `j` are odd.
#[allow(clippy::needless_range_loop)] // the term's weight depends on both indices
fn fe_conv(f: &Fe, g: &Fe) -> [i64; 10] {
    // `2^{e_i + e_j - e_{(i+j) mod 10}}`; the exponent gap is one exactly when `i` and `j`
    // are both odd, and the fold contributes its own 19.
    let coef = |i: usize, j: usize| -> i64 {
        let base: i64 = if i % 2 == 1 && j % 2 == 1 { 2 } else { 1 };
        if i + j >= 10 {
            19 * base
        } else {
            base
        }
    };
    let mut t = [0i64; 10];
    for k in 0..10usize {
        let mut acc = 0i64;
        for i in 0..=k {
            let j = k - i;
            acc += coef(i, j) * (f[i] as i64) * (g[j] as i64);
        }
        for i in (k + 1)..10 {
            let j = k + 10 - i;
            acc += coef(i, j) * (f[i] as i64) * (g[j] as i64);
        }
        t[k] = acc;
    }
    t
}

/// `fe_reduce` — the carry chain `fe_mul` ends with (`curve25519.c:1267-1343`).
fn fe_reduce(t: [i64; 10]) -> Fe {
    let mut h0 = t[0];
    let mut h1 = t[1];
    let mut h2 = t[2];
    let mut h3 = t[3];
    let mut h4 = t[4];
    let mut h5 = t[5];
    let mut h6 = t[6];
    let mut h7 = t[7];
    let mut h8 = t[8];
    let mut h9 = t[9];

    let c0 = h0 + (1 << 25);
    h1 += c0 >> 26;
    h0 -= c0 & K_TOP_38;
    let c4 = h4 + (1 << 25);
    h5 += c4 >> 26;
    h4 -= c4 & K_TOP_38;

    let c1 = h1 + (1 << 24);
    h2 += c1 >> 25;
    h1 -= c1 & K_TOP_39;
    let c5 = h5 + (1 << 24);
    h6 += c5 >> 25;
    h5 -= c5 & K_TOP_39;

    let c2 = h2 + (1 << 25);
    h3 += c2 >> 26;
    h2 -= c2 & K_TOP_38;
    let c6 = h6 + (1 << 25);
    h7 += c6 >> 26;
    h6 -= c6 & K_TOP_38;

    let c3 = h3 + (1 << 24);
    h4 += c3 >> 25;
    h3 -= c3 & K_TOP_39;
    let c7 = h7 + (1 << 24);
    h8 += c7 >> 25;
    h7 -= c7 & K_TOP_39;

    let c4 = h4 + (1 << 25);
    h5 += c4 >> 26;
    h4 -= c4 & K_TOP_38;
    let c8 = h8 + (1 << 25);
    h9 += c8 >> 26;
    h8 -= c8 & K_TOP_38;

    let c9 = h9 + (1 << 24);
    h0 += (c9 >> 25) * 19;
    h9 -= c9 & K_TOP_39;

    let c0 = h0 + (1 << 25);
    h1 += c0 >> 26;
    h0 -= c0 & K_TOP_38;

    [
        h0 as i32, h1 as i32, h2 as i32, h3 as i32, h4 as i32, h5 as i32, h6 as i32, h7 as i32,
        h8 as i32, h9 as i32,
    ]
}

/// `fe_mul` — `curve25519.c:1105`.
fn fe_mul(f: &Fe, g: &Fe) -> Fe {
    fe_reduce(fe_conv(f, g))
}

/// `fe_sq` — `curve25519.c:1359`; the same integer sum as `fe_mul(f, f)`.
fn fe_sq(f: &Fe) -> Fe {
    fe_mul(f, f)
}

/// `fe_sq2` — `curve25519.c:1692`; the `fe_mul` convolution doubled before its carry.
fn fe_sq2(f: &Fe) -> Fe {
    let mut t = fe_conv(f, f);
    for v in t.iter_mut() {
        *v += *v;
    }
    fe_reduce(t)
}

/// `fe_invert` — `curve25519.c:1515`.
fn fe_invert(z: &Fe) -> Fe {
    let mut t0 = fe_sq(z);
    let mut t1 = fe_sq(&t0);
    t1 = fe_sq(&t1);
    t1 = fe_mul(z, &t1);
    t0 = fe_mul(&t0, &t1);
    let mut t2 = fe_sq(&t0);
    t1 = fe_mul(&t1, &t2);
    t2 = fe_sq(&t1);
    for _ in 1..5 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    t2 = fe_sq(&t1);
    for _ in 1..10 {
        t2 = fe_sq(&t2);
    }
    t2 = fe_mul(&t2, &t1);
    let mut t3 = fe_sq(&t2);
    for _ in 1..20 {
        t3 = fe_sq(&t3);
    }
    t2 = fe_mul(&t3, &t2);
    for _ in 0..10 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    t2 = fe_sq(&t1);
    for _ in 1..50 {
        t2 = fe_sq(&t2);
    }
    t2 = fe_mul(&t2, &t1);
    t3 = fe_sq(&t2);
    for _ in 1..100 {
        t3 = fe_sq(&t3);
    }
    t2 = fe_mul(&t3, &t2);
    for _ in 0..50 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    for _ in 0..5 {
        t1 = fe_sq(&t1);
    }
    fe_mul(&t1, &t0)
}

/// `fe_pow22523` — `curve25519.c:1859`.
fn fe_pow22523(z: &Fe) -> Fe {
    let mut t0 = fe_sq(z);
    let mut t1 = fe_sq(&t0);
    for _ in 1..2 {
        t1 = fe_sq(&t1);
    }
    t1 = fe_mul(z, &t1);
    t0 = fe_mul(&t0, &t1);
    t0 = fe_sq(&t0);
    t0 = fe_mul(&t1, &t0);
    t1 = fe_sq(&t0);
    for _ in 1..5 {
        t1 = fe_sq(&t1);
    }
    t0 = fe_mul(&t1, &t0);
    t1 = fe_sq(&t0);
    for _ in 1..10 {
        t1 = fe_sq(&t1);
    }
    t1 = fe_mul(&t1, &t0);
    let mut t2 = fe_sq(&t1);
    for _ in 1..20 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    t1 = fe_sq(&t1);
    for _ in 1..10 {
        t1 = fe_sq(&t1);
    }
    t0 = fe_mul(&t1, &t0);
    t1 = fe_sq(&t0);
    for _ in 1..50 {
        t1 = fe_sq(&t1);
    }
    t1 = fe_mul(&t1, &t0);
    t2 = fe_sq(&t1);
    for _ in 1..100 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    t1 = fe_sq(&t1);
    for _ in 1..50 {
        t1 = fe_sq(&t1);
    }
    t0 = fe_mul(&t1, &t0);
    t0 = fe_sq(&t0);
    for _ in 1..2 {
        t0 = fe_sq(&t0);
    }
    fe_mul(&t0, z)
}

/// `fe_isnonzero` — `curve25519.c:1654`.
fn fe_isnonzero(f: &Fe) -> c_int {
    let s = fe_tobytes(f);
    let zero = [0u8; 32];
    // SAFETY: both buffers are 32 bytes and live for the call.
    if unsafe { CRYPTO_memcmp(s.as_ptr().cast(), zero.as_ptr().cast(), 32) } != 0 {
        1
    } else {
        0
    }
}

/// `fe_isnegative` — `curve25519.c:1671`.
fn fe_isnegative(f: &Fe) -> c_int {
    (fe_tobytes(f)[0] & 1) as c_int
}

// =====================================================================================
// The Edwards group
// =====================================================================================

/// `ge_tobytes` — `curve25519.c:1963`.
fn ge_tobytes(h: &GeP2) -> [u8; 32] {
    let recip = fe_invert(&h.z);
    let x = fe_mul(&h.x, &recip);
    let y = fe_mul(&h.y, &recip);
    let mut s = fe_tobytes(&y);
    s[31] ^= (fe_isnegative(&x) as u8) << 7;
    s
}

/// `ge_p3_tobytes` — `curve25519.c:1976`.
fn ge_p3_tobytes(h: &GeP3) -> [u8; 32] {
    let recip = fe_invert(&h.z);
    let x = fe_mul(&h.x, &recip);
    let y = fe_mul(&h.y, &recip);
    let mut s = fe_tobytes(&y);
    s[31] ^= (fe_isnegative(&x) as u8) << 7;
    s
}

/// `ge_frombytes_vartime` — `curve25519.c:1999`.
fn ge_frombytes_vartime(s: &[u8; 32]) -> Option<GeP3> {
    let mut h = GeP3 {
        x: fe_0(),
        y: fe_frombytes(s),
        z: fe_1(),
        t: fe_0(),
    };
    let u0 = fe_sq(&h.y);
    let v0 = fe_mul(&u0, &D);
    let u = fe_sub(&u0, &h.z);
    let v = fe_add(&v0, &h.z);

    let w = fe_mul(&u, &v);
    h.x = fe_pow22523(&w);
    h.x = fe_mul(&h.x, &u);

    let vxx = fe_mul(&fe_sq(&h.x), &v);
    let check = fe_sub(&vxx, &u);
    if fe_isnonzero(&check) != 0 {
        let check2 = fe_add(&vxx, &u);
        if fe_isnonzero(&check2) != 0 {
            return None;
        }
        h.x = fe_mul(&h.x, &SQRTM1);
    }

    if fe_isnegative(&h.x) != (s[31] >> 7) as c_int {
        h.x = fe_neg(&h.x);
    }
    h.t = fe_mul(&h.x, &h.y);
    Some(h)
}

/// `ge_p3_to_p2` — `curve25519.c:2061`.
fn ge_p3_to_p2(p: &GeP3) -> GeP2 {
    GeP2 {
        x: p.x,
        y: p.y,
        z: p.z,
    }
}

/// `ge_p3_to_cached` — `curve25519.c:2074`.
fn ge_p3_to_cached(p: &GeP3) -> GeCached {
    GeCached {
        yplusx: fe_add(&p.y, &p.x),
        yminusx: fe_sub(&p.y, &p.x),
        z: p.z,
        t2d: fe_mul(&p.t, &D2),
    }
}

/// `ge_p1p1_to_p2` — `curve25519.c:2083`.
fn ge_p1p1_to_p2(p: &GeP1P1) -> GeP2 {
    GeP2 {
        x: fe_mul(&p.x, &p.t),
        y: fe_mul(&p.y, &p.z),
        z: fe_mul(&p.z, &p.t),
    }
}

/// `ge_p1p1_to_p3` — `curve25519.c:2091`.
fn ge_p1p1_to_p3(p: &GeP1P1) -> GeP3 {
    GeP3 {
        x: fe_mul(&p.x, &p.t),
        y: fe_mul(&p.y, &p.z),
        z: fe_mul(&p.z, &p.t),
        t: fe_mul(&p.x, &p.y),
    }
}

/// `ge_p2_dbl` — `curve25519.c:2100`.
fn ge_p2_dbl(p: &GeP2) -> GeP1P1 {
    let x = fe_sq(&p.x);
    let z = fe_sq(&p.y);
    let t = fe_sq2(&p.z);
    let y0 = fe_add(&p.x, &p.y);
    let t0 = fe_sq(&y0);
    let y = fe_add(&z, &x);
    let zz = fe_sub(&z, &x);
    let xx = fe_sub(&t0, &y);
    let tt = fe_sub(&t, &zz);
    GeP1P1 {
        x: xx,
        y,
        z: zz,
        t: tt,
    }
}

/// `ge_p3_dbl` — `curve25519.c:2116`.
fn ge_p3_dbl(p: &GeP3) -> GeP1P1 {
    ge_p2_dbl(&ge_p3_to_p2(p))
}

/// `ge_madd` — `curve25519.c:2124`.
fn ge_madd(p: &GeP3, q: &GePrecomp) -> GeP1P1 {
    let x0 = fe_add(&p.y, &p.x);
    let y0 = fe_sub(&p.y, &p.x);
    let z0 = fe_mul(&x0, &q.yplusx);
    let y1 = fe_mul(&y0, &q.yminusx);
    let t0 = fe_mul(&q.xy2d, &p.t);
    let t1 = fe_add(&p.z, &p.z);
    GeP1P1 {
        x: fe_sub(&z0, &y1),
        y: fe_add(&z0, &y1),
        z: fe_add(&t1, &t0),
        t: fe_sub(&t1, &t0),
    }
}

/// `ge_msub` — `curve25519.c:2141`.
fn ge_msub(p: &GeP3, q: &GePrecomp) -> GeP1P1 {
    let x0 = fe_add(&p.y, &p.x);
    let y0 = fe_sub(&p.y, &p.x);
    let z0 = fe_mul(&x0, &q.yminusx);
    let y1 = fe_mul(&y0, &q.yplusx);
    let t0 = fe_mul(&q.xy2d, &p.t);
    let t1 = fe_add(&p.z, &p.z);
    GeP1P1 {
        x: fe_sub(&z0, &y1),
        y: fe_add(&z0, &y1),
        z: fe_sub(&t1, &t0),
        t: fe_add(&t1, &t0),
    }
}

/// `ge_add` — `curve25519.c:2158`.
fn ge_add(p: &GeP3, q: &GeCached) -> GeP1P1 {
    let x0 = fe_add(&p.y, &p.x);
    let y0 = fe_sub(&p.y, &p.x);
    let z0 = fe_mul(&x0, &q.yplusx);
    let y1 = fe_mul(&y0, &q.yminusx);
    let t0 = fe_mul(&q.t2d, &p.t);
    let x1 = fe_mul(&p.z, &q.z);
    let t1 = fe_add(&x1, &x1);
    GeP1P1 {
        x: fe_sub(&z0, &y1),
        y: fe_add(&z0, &y1),
        z: fe_add(&t1, &t0),
        t: fe_sub(&t1, &t0),
    }
}

/// `ge_sub` — `curve25519.c:2176`.
fn ge_sub(p: &GeP3, q: &GeCached) -> GeP1P1 {
    let x0 = fe_add(&p.y, &p.x);
    let y0 = fe_sub(&p.y, &p.x);
    let z0 = fe_mul(&x0, &q.yminusx);
    let y1 = fe_mul(&y0, &q.yplusx);
    let t0 = fe_mul(&q.t2d, &p.t);
    let x1 = fe_mul(&p.z, &q.z);
    let t1 = fe_add(&x1, &x1);
    GeP1P1 {
        x: fe_sub(&z0, &y1),
        y: fe_add(&z0, &y1),
        z: fe_sub(&t1, &t0),
        t: fe_add(&t1, &t0),
    }
}

/// `equal` — `curve25519.c:2193`.
fn equal(b: u8, c: u8) -> u8 {
    let x = b ^ c;
    let mut y = x as u32;
    y = y.wrapping_sub(1);
    (y >> 31) as u8
}

/// `negative` — `curve25519.c:4327`.
fn negative(b: i8) -> u8 {
    (((b as i32) as u32) >> 31) as u8
}

/// `cmov` — `curve25519.c:2204`.
fn cmov(t: &mut GePrecomp, u: &GePrecomp, b: u8) {
    fe_cmov(&mut t.yplusx, &u.yplusx, b as u32);
    fe_cmov(&mut t.yminusx, &u.yminusx, b as u32);
    fe_cmov(&mut t.xy2d, &u.xy2d, b as u32);
}

/// The `ge_precomp` at `(pos, j)` of the generated flattened table.
fn precomp_at(pos: usize, j: usize) -> GePrecomp {
    let base = (pos * 8 + j) * 30;
    let read = |off: usize| -> Fe {
        let mut v = [0i32; 10];
        v.copy_from_slice(&K25519_PRECOMP[base + off..base + off + 10]);
        v
    };
    GePrecomp {
        yplusx: read(0),
        yminusx: read(10),
        xy2d: read(20),
    }
}

/// The `ge_precomp` at `j` of the generated `Bi` table.
fn bi_at(j: usize) -> GePrecomp {
    let base = j * 30;
    let read = |off: usize| -> Fe {
        let mut v = [0i32; 10];
        v.copy_from_slice(&BI[base + off..base + off + 10]);
        v
    };
    GePrecomp {
        yplusx: read(0),
        yminusx: read(10),
        xy2d: read(20),
    }
}

/// `table_select` — `curve25519.c:4335`.
fn table_select(pos: usize, b: i8) -> GePrecomp {
    let bnegative = negative(b);
    let m = ((-(bnegative as i32)) & (b as i32)) as u8;
    let babs = (b as i32 - ((m as i32) << 1)) as u8;

    let mut t = GePrecomp {
        yplusx: fe_1(),
        yminusx: fe_1(),
        xy2d: fe_0(),
    };
    for j in 0..8 {
        let u = precomp_at(pos, j);
        cmov(&mut t, &u, equal(babs, (j + 1) as u8));
    }
    let minust = GePrecomp {
        yplusx: t.yminusx,
        yminusx: t.yplusx,
        xy2d: fe_neg(&t.xy2d),
    };
    cmov(&mut t, &minust, bnegative);
    t
}

/// `ge_scalarmult_base` — `curve25519.c:4365`.
#[allow(clippy::needless_range_loop)] // the digit index drives two arrays
fn ge_scalarmult_base(a: &[u8]) -> GeP3 {
    let mut e = [0i8; 64];
    for i in 0..32 {
        e[2 * i] = (a[i] & 15) as i8;
        e[2 * i + 1] = ((a[i] >> 4) & 15) as i8;
    }
    let mut carry: i8 = 0;
    for i in 0..63 {
        e[i] += carry;
        carry = e[i] + 8;
        carry >>= 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;

    let mut h = GeP3 {
        x: fe_0(),
        y: fe_1(),
        z: fe_1(),
        t: fe_0(),
    };
    let mut i = 1;
    while i < 64 {
        let t = table_select(i / 2, e[i]);
        let r = ge_madd(&h, &t);
        h = ge_p1p1_to_p3(&r);
        i += 2;
    }

    let r = ge_p3_dbl(&h);
    let s = ge_p1p1_to_p2(&r);
    let r = ge_p2_dbl(&s);
    let s = ge_p1p1_to_p2(&r);
    let r = ge_p2_dbl(&s);
    let s = ge_p1p1_to_p2(&r);
    let r = ge_p2_dbl(&s);
    h = ge_p1p1_to_p3(&r);

    let mut i = 0;
    while i < 64 {
        let t = table_select(i / 2, e[i]);
        let r = ge_madd(&h, &t);
        h = ge_p1p1_to_p3(&r);
        i += 2;
    }
    // SAFETY: `e` is this function's own 64-byte buffer.
    unsafe { OPENSSL_cleanse(e.as_mut_ptr().cast(), 64) };
    h
}

/// `slide` — `curve25519.c:4583`.
#[allow(clippy::needless_range_loop)] // the carry walk is over fixed indices
fn slide(a: &[u8]) -> [i8; 256] {
    let mut r = [0i8; 256];
    for i in 0..256 {
        r[i] = (1 & (a[i >> 3] >> (i & 7))) as i8;
    }
    for i in 0..256 {
        if r[i] != 0 {
            let mut b = 1;
            while b <= 6 && i + b < 256 {
                if r[i + b] != 0 {
                    if r[i] + (r[i + b] << b) <= 15 {
                        r[i] += r[i + b] << b;
                        r[i + b] = 0;
                    } else if r[i] - (r[i + b] << b) >= -15 {
                        r[i] -= r[i + b] << b;
                        for k in (i + b)..256 {
                            if r[k] == 0 {
                                r[k] = 1;
                                break;
                            }
                            r[k] = 0;
                        }
                    } else {
                        break;
                    }
                }
                b += 1;
            }
        }
    }
    r
}

/// `ge_double_scalarmult_vartime` — `curve25519.c:4692`.
fn ge_double_scalarmult_vartime(a: &[u8], big_a: &GeP3, b: &[u8]) -> GeP2 {
    let aslide = slide(a);
    let bslide = slide(b);

    let mut ai = [GeCached {
        yplusx: fe_0(),
        yminusx: fe_0(),
        z: fe_0(),
        t2d: fe_0(),
    }; 8];
    ai[0] = ge_p3_to_cached(big_a);
    let t = ge_p3_dbl(big_a);
    let a2 = ge_p1p1_to_p3(&t);
    for j in 1..8 {
        let t = ge_add(&a2, &ai[j - 1]);
        let u = ge_p1p1_to_p3(&t);
        ai[j] = ge_p3_to_cached(&u);
    }

    let mut r = GeP2 {
        x: fe_0(),
        y: fe_1(),
        z: fe_1(),
    };

    let mut i: isize = 255;
    while i >= 0 {
        if aslide[i as usize] != 0 || bslide[i as usize] != 0 {
            break;
        }
        i -= 1;
    }

    while i >= 0 {
        let mut t = ge_p2_dbl(&r);
        if aslide[i as usize] > 0 {
            let u = ge_p1p1_to_p3(&t);
            t = ge_add(&u, &ai[(aslide[i as usize] / 2) as usize]);
        } else if aslide[i as usize] < 0 {
            let u = ge_p1p1_to_p3(&t);
            t = ge_sub(&u, &ai[((-aslide[i as usize]) / 2) as usize]);
        }
        if bslide[i as usize] > 0 {
            let u = ge_p1p1_to_p3(&t);
            t = ge_madd(&u, &bi_at((bslide[i as usize] / 2) as usize));
        } else if bslide[i as usize] < 0 {
            let u = ge_p1p1_to_p3(&t);
            t = ge_msub(&u, &bi_at(((-bslide[i as usize]) / 2) as usize));
        }
        r = ge_p1p1_to_p2(&t);
        i -= 1;
    }
    r
}

// =====================================================================================
// The scalar ring Z/l
// =====================================================================================

/// `l = 2^252 + 27742317777372353535851937790883648493` — `curve25519.c:4764`.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// `x mod l` for a little-endian wide integer, by a fixed-iteration masked long division.
///
/// The authority's `x25519_sc_reduce` is an unrolled Barrett-like form; this is the same
/// congruence computed with a fixed `nbits` loop and a masked conditional subtract, so it is
/// constant-time in the same sense (no secret-dependent branch and no secret-dependent
/// memory access) while being short enough to check.
#[allow(clippy::needless_range_loop)] // fixed-width limb arithmetic
fn reduce_wide(x: &[u64], nbits: usize) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in (0..nbits).rev() {
        let bit = (x[i / 64] >> (i % 64)) & 1;
        let mut carry = bit;
        for v in r.iter_mut() {
            let nv = (*v << 1) | carry;
            carry = *v >> 63;
            *v = nv;
        }
        let mut sub = [0u64; 4];
        let mut borrow = 0u64;
        for k in 0..4 {
            let (v, o) = r[k].overflowing_sub(L[k]);
            let (v, o2) = v.overflowing_sub(borrow);
            sub[k] = v;
            borrow = (o as u64) | (o2 as u64);
        }
        let mask = borrow.wrapping_sub(1);
        for k in 0..4 {
            r[k] = (r[k] & !mask) | (sub[k] & mask);
        }
    }
    r
}

/// `x25519_sc_reduce` — `curve25519.c:4774`; reduces the 64-byte value in place.
fn x25519_sc_reduce(s: &mut [u8; 64]) {
    let mut x = [0u64; 8];
    for i in 0..8 {
        let mut w = 0u64;
        for k in 0..8 {
            w |= (s[i * 8 + k] as u64) << (8 * k);
        }
        x[i] = w;
    }
    let r = reduce_wide(&x, 512);
    for i in 0..4 {
        s[i * 8..i * 8 + 8].copy_from_slice(&r[i].to_le_bytes());
    }
}

/// `sc_muladd` — `curve25519.c:5118`; `s = (a*b + c) mod l` over the low 32 bytes of each.
fn sc_muladd(s: &mut [u8; 32], a: &[u8], b: &[u8], c: &[u8]) {
    let load = |v: &[u8]| -> [u64; 4] {
        let mut w = [0u64; 4];
        for i in 0..4 {
            let mut t = 0u64;
            for k in 0..8 {
                t |= (v[i * 8 + k] as u64) << (8 * k);
            }
            w[i] = t;
        }
        w
    };
    let av = load(a);
    let bv = load(b);
    let cv = load(c);

    let mut prod = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let cur = prod[i + j] as u128 + (av[i] as u128) * (bv[j] as u128) + carry;
            prod[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + 4;
        while carry != 0 && k < 8 {
            let cur = prod[k] as u128 + carry;
            prod[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }
    let mut carry = 0u64;
    for i in 0..4 {
        let (v, o) = prod[i].overflowing_add(cv[i]);
        let (v, o2) = v.overflowing_add(carry);
        prod[i] = v;
        carry = (o as u64) + (o2 as u64);
    }
    let mut k = 4;
    while carry != 0 && k < 8 {
        let (v, o) = prod[k].overflowing_add(carry);
        prod[k] = v;
        carry = o as u64;
        k += 1;
    }

    let r = reduce_wide(&prod, 512);
    for i in 0..4 {
        s[i * 8..i * 8 + 8].copy_from_slice(&r[i].to_le_bytes());
    }
}

// =====================================================================================
// The X25519 ladder and the three Ed25519 exports
// =====================================================================================

/// `x25519_scalar_mulx` — the base-2^64 ladder (`curve25519.c:210`).
fn x25519_scalar_mulx(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut e = *scalar;
    e[0] &= 0xf8;
    e[31] &= 0x7f;
    e[31] |= 0x40;

    let x1 = fe64_frombytes(point);
    let mut x2 = [1u64, 0, 0, 0];
    let mut z2 = [0u64; 4];
    let mut x3 = x1;
    let mut z3 = [1u64, 0, 0, 0];
    let mut swap = 0u64;

    for pos in (0..=254).rev() {
        let b = ((e[pos / 8] >> (pos & 7)) & 1) as u64;
        swap ^= b;
        fe64_cswap(&mut x2, &mut x3, swap);
        fe64_cswap(&mut z2, &mut z3, swap);
        swap = b;

        let tmp0 = fe64_sub_arr(&x3, &z3);
        let tmp1 = fe64_sub_arr(&x2, &z2);
        let x2n = fe64_add_arr(&x2, &z2);
        let z2n = fe64_add_arr(&x3, &z3);
        let z3n = fe64_mul_arr(&x2n, &tmp0);
        let z2b = fe64_mul_arr(&z2n, &tmp1);
        let tmp0b = fe64_sqr_arr(&tmp1);
        let tmp1b = fe64_sqr_arr(&x2n);
        let x3b = fe64_add_arr(&z3n, &z2b);
        let z2c = fe64_sub_arr(&z3n, &z2b);
        let x2b = fe64_mul_arr(&tmp1b, &tmp0b);
        let tmp1c = fe64_sub_arr(&tmp1b, &tmp0b);
        let z2d = fe64_sqr_arr(&z2c);
        let z3b = fe64_mul121666_arr(&tmp1c);
        let x3c = fe64_sqr_arr(&x3b);
        let tmp0c = fe64_add_arr(&tmp0b, &z3b);
        let z3c = fe64_mul_arr(&x1, &z2d);
        let z2e = fe64_mul_arr(&tmp1c, &tmp0c);

        x2 = x2b;
        x3 = x3c;
        z2 = z2e;
        z3 = z3c;
    }
    let z2i = fe64_invert(&z2);
    let x2f = fe64_mul_arr(&x2, &z2i);
    let out = fe64_tobytes_arr(&x2f);
    // SAFETY: `e` is this function's own 32-byte buffer.
    unsafe { OPENSSL_cleanse(e.as_mut_ptr().cast(), 32) };
    out
}

/// `x25519_scalar_mult` — `curve25519.c:727`, with the `x25519_fe64_eligible` arm taken when
/// the CPU has `BMI2`+`ADX`.
fn x25519_scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    if x25519_fe64_eligible() != 0 {
        return x25519_scalar_mulx(scalar, point);
    }
    x25519_scalar_mult_fe51(scalar, point)
}

/// The base-2^51 arm of `x25519_scalar_mult` (`curve25519.c:742-783`).
fn x25519_scalar_mult_fe51(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut e = *scalar;
    e[0] &= 0xf8;
    e[31] &= 0x7f;
    e[31] |= 0x40;

    let x1 = fe51_frombytes(point);
    let mut x2 = fe51_1();
    let mut z2 = fe51_0();
    let mut x3 = x1;
    let mut z3 = fe51_1();
    let mut swap = 0u64;

    for pos in (0..=254).rev() {
        let b = ((e[pos / 8] >> (pos & 7)) & 1) as u64;
        swap ^= b;
        fe51_cswap(&mut x2, &mut x3, swap);
        fe51_cswap(&mut z2, &mut z3, swap);
        swap = b;

        let tmp0 = fe51_sub(&x3, &z3);
        let tmp1 = fe51_sub(&x2, &z2);
        let x2n = fe51_add(&x2, &z2);
        let z2n = fe51_add(&x3, &z3);
        let z3n = fe51_mul_arr(&tmp0, &x2n);
        let z2b = fe51_mul_arr(&z2n, &tmp1);
        let tmp0b = fe51_sqr_arr(&tmp1);
        let tmp1b = fe51_sqr_arr(&x2n);
        let x3b = fe51_add(&z3n, &z2b);
        let z2c = fe51_sub(&z3n, &z2b);
        let x2b = fe51_mul_arr(&tmp1b, &tmp0b);
        let tmp1c = fe51_sub(&tmp1b, &tmp0b);
        let z2d = fe51_sqr_arr(&z2c);
        let z3b = fe51_mul121666_arr(&tmp1c);
        let x3c = fe51_sqr_arr(&x3b);
        let tmp0c = fe51_add(&tmp0b, &z3b);
        let z3c = fe51_mul_arr(&x1, &z2d);
        let z2e = fe51_mul_arr(&tmp1c, &tmp0c);

        x2 = x2b;
        x3 = x3c;
        z2 = z2e;
        z3 = z3c;
    }
    let z2i = fe51_invert(&z2);
    let x2f = fe51_mul_arr(&x2, &z2i);
    let out = fe51_tobytes(&x2f);
    // SAFETY: `e` is this function's own 32-byte buffer.
    unsafe { OPENSSL_cleanse(e.as_mut_ptr().cast(), 32) };
    out
}

/// `int ossl_x25519(uint8_t out_shared_key[32], const uint8_t private_key[32],
/// const uint8_t peer_public_value[32])` — `curve25519.c:5844`.
///
/// # Safety
/// `out_shared_key` writable for 32 bytes; the two inputs readable for 32.
#[no_mangle]
pub unsafe extern "C" fn ossl_x25519(
    out_shared_key: *mut u8,
    private_key: *const u8,
    peer_public_value: *const u8,
) -> c_int {
    // SAFETY: the contract gives each pointer 32 readable/writable bytes.
    let (sk, pk) = unsafe {
        (
            *(private_key as *const [u8; 32]),
            *(peer_public_value as *const [u8; 32]),
        )
    };
    let out = x25519_scalar_mult(&sk, &pk);
    // SAFETY: `out_shared_key` is writable for 32 bytes.
    unsafe { ptr::copy_nonoverlapping(out.as_ptr(), out_shared_key, 32) };
    let zeros = [0u8; 32];
    // SAFETY: both buffers are 32 bytes and live for the call.
    (unsafe { CRYPTO_memcmp(out.as_ptr().cast(), zeros.as_ptr().cast(), 32) } != 0) as c_int
}

/// `void ossl_x25519_public_from_private(uint8_t out_public_value[32],
/// const uint8_t private_key[32])` — `curve25519.c:5853`.
///
/// # Safety
/// `out_public_value` writable for 32 bytes; `private_key` readable for 32.
#[no_mangle]
pub unsafe extern "C" fn ossl_x25519_public_from_private(
    out_public_value: *mut u8,
    private_key: *const u8,
) {
    // SAFETY: the contract gives the pointer 32 readable bytes.
    let mut e = unsafe { *(private_key as *const [u8; 32]) };
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    let a = ge_scalarmult_base(&e);
    let zplusy = fe_add(&a.z, &a.y);
    let zminusy = fe_sub(&a.z, &a.y);
    let zminusy_inv = fe_invert(&zminusy);
    let r = fe_mul(&zplusy, &zminusy_inv);
    let out = fe_tobytes(&r);
    // SAFETY: `out_public_value` is writable for 32 bytes.
    unsafe { ptr::copy_nonoverlapping(out.as_ptr(), out_public_value, 32) };
    // SAFETY: `e` is this function's own 32-byte buffer.
    unsafe { OPENSSL_cleanse(e.as_mut_ptr().cast(), 32) };
}

/// `hash_init_with_dom` — `curve25519.c:5591`.
fn hash_init_with_dom(
    hash_ctx: *mut EvpMdCtx,
    sha512: *mut EvpMd,
    dom2flag: u8,
    phflag: u8,
    context: *const u8,
    context_len: usize,
) -> c_int {
    const DOM_S: &[u8; 32] = b"SigEd25519 no Ed25519 collisions";
    // SAFETY: `hash_ctx` and `sha512` are live per the caller's contract.
    if unsafe { EVP_DigestInit_ex(hash_ctx, sha512, ptr::null_mut()) } == 0 {
        return 0;
    }
    if dom2flag == 0 {
        return 1;
    }
    if context_len > u8::MAX as usize {
        return 0;
    }
    let dom = [if phflag >= 1 { 1u8 } else { 0 }, context_len as u8];
    // SAFETY: `hash_ctx` is live, and each buffer is valid for its length.
    let ok = unsafe {
        EVP_DigestUpdate(hash_ctx, DOM_S.as_ptr().cast(), DOM_S.len()) != 0
            && EVP_DigestUpdate(hash_ctx, dom.as_ptr().cast(), dom.len()) != 0
            && EVP_DigestUpdate(hash_ctx, context.cast(), context_len) != 0
    };
    ok as c_int
}

/// `int ossl_ed25519_sign(...)` — `curve25519.c:5626`.
///
/// # Safety
/// `out_sig` writable for 64 bytes; the buffers readable for their lengths; `libctx`/`propq`
/// NULL or live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ed25519_sign(
    out_sig: *mut u8,
    tbs: *const u8,
    tbs_len: usize,
    public_key: *const u8,
    private_key: *const u8,
    dom2flag: u8,
    phflag: u8,
    csflag: u8,
    context: *const u8,
    mut context_len: usize,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut az = [0u8; SHA512_LEN];
    let mut nonce = [0u8; SHA512_LEN];
    let mut hram = [0u8; SHA512_LEN];
    let mut sz: u32 = 0;

    if context.is_null() {
        context_len = 0;
    }
    if csflag != 0 && context_len == 0 {
        return 0;
    }
    if dom2flag == 0 && context_len > 0 {
        return 0;
    }

    // SAFETY: `libctx`/`propq` are the caller's; the name is a compile-time constant.
    let sha512 = unsafe { EVP_MD_fetch(libctx, c"SHA512".as_ptr(), propq) };
    let hash_ctx = EVP_MD_CTX_new();
    if sha512.is_null() || hash_ctx.is_null() {
        // SAFETY: `sha512` is NULL or live; freeing NULL is a no-op.
        unsafe { EVP_MD_free(sha512) };
        // SAFETY: `hash_ctx` is NULL or live; freeing NULL is a no-op.
        unsafe { EVP_MD_CTX_free(hash_ctx) };
        return 0;
    }

    // SAFETY: all pointers are live and each buffer is valid for its length.
    let ok = unsafe {
        EVP_DigestInit_ex(hash_ctx, sha512, ptr::null_mut()) != 0
            && EVP_DigestUpdate(hash_ctx, private_key.cast(), 32) != 0
            && EVP_DigestFinal_ex(hash_ctx, az.as_mut_ptr(), &mut sz) != 0
    };
    if !ok {
        // SAFETY: both are live.
        unsafe {
            EVP_MD_free(sha512);
            EVP_MD_CTX_free(hash_ctx);
        }
        return 0;
    }

    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    // SAFETY: all pointers are live and each buffer is valid for its length.
    let ok = unsafe {
        hash_init_with_dom(hash_ctx, sha512, dom2flag, phflag, context, context_len) != 0
            && EVP_DigestUpdate(hash_ctx, az.as_ptr().add(32).cast(), 32) != 0
            && EVP_DigestUpdate(hash_ctx, tbs.cast(), tbs_len) != 0
            && EVP_DigestFinal_ex(hash_ctx, nonce.as_mut_ptr(), &mut sz) != 0
    };
    if !ok {
        // SAFETY: both are live.
        unsafe {
            EVP_MD_free(sha512);
            EVP_MD_CTX_free(hash_ctx);
        }
        return 0;
    }

    x25519_sc_reduce(&mut nonce);
    let r = ge_scalarmult_base(&nonce);
    let rbytes = ge_p3_tobytes(&r);
    // SAFETY: `out_sig` is writable for 64 bytes.
    unsafe { ptr::copy_nonoverlapping(rbytes.as_ptr(), out_sig, 32) };

    // SAFETY: all pointers are live and each buffer is valid for its length.
    let ok = unsafe {
        hash_init_with_dom(hash_ctx, sha512, dom2flag, phflag, context, context_len) != 0
            && EVP_DigestUpdate(hash_ctx, out_sig.cast(), 32) != 0
            && EVP_DigestUpdate(hash_ctx, public_key.cast(), 32) != 0
            && EVP_DigestUpdate(hash_ctx, tbs.cast(), tbs_len) != 0
            && EVP_DigestFinal_ex(hash_ctx, hram.as_mut_ptr(), &mut sz) != 0
    };
    if !ok {
        // SAFETY: both are live.
        unsafe {
            EVP_MD_free(sha512);
            EVP_MD_CTX_free(hash_ctx);
        }
        return 0;
    }

    x25519_sc_reduce(&mut hram);
    let mut s = [0u8; 32];
    sc_muladd(&mut s, &hram[..32], &az[..32], &nonce[..32]);
    // SAFETY: `out_sig` is writable for 64 bytes and `s` is 32 bytes.
    unsafe { ptr::copy_nonoverlapping(s.as_ptr(), out_sig.add(32), 32) };

    // SAFETY: both buffers are 64 bytes and live.
    unsafe {
        OPENSSL_cleanse(nonce.as_mut_ptr().cast(), SHA512_LEN);
        OPENSSL_cleanse(az.as_mut_ptr().cast(), SHA512_LEN);
        EVP_MD_free(sha512);
        EVP_MD_CTX_free(hash_ctx);
    }
    1
}

/// `int ossl_ed25519_pubkey_verify(const uint8_t *pub, size_t pub_len)` — `curve25519.c:5698`.
///
/// # Safety
/// `pub` readable for `pub_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_ed25519_pubkey_verify(pub_: *const u8, pub_len: usize) -> c_int {
    if pub_len != 32 {
        return 0;
    }
    // SAFETY: `pub_` is readable for 32 bytes per the check above.
    let p = unsafe { *(pub_ as *const [u8; 32]) };
    (ge_frombytes_vartime(&p).is_some()) as c_int
}

/// `int ossl_ed25519_verify(...)` — `curve25519.c:5709`.
///
/// # Safety
/// Each buffer readable for its length; `libctx`/`propq` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ed25519_verify(
    tbs: *const u8,
    tbs_len: usize,
    signature: *const u8,
    public_key: *const u8,
    dom2flag: u8,
    phflag: u8,
    csflag: u8,
    context: *const u8,
    mut context_len: usize,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    const L_LOW: [u8; 16] = [
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE,
        0x14,
    ];
    let mut h = [0u8; SHA512_LEN];
    let mut sz: u32 = 0;

    if context.is_null() {
        context_len = 0;
    }
    if csflag != 0 && context_len == 0 {
        return 0;
    }
    if dom2flag == 0 && context_len > 0 {
        return 0;
    }

    // SAFETY: `signature` is readable for 64 bytes.
    let (r, s) = unsafe { (signature, signature.add(32)) };

    // SAFETY: `s` is readable for 32 bytes per the caller's contract.
    let sbytes = unsafe { *(s as *const [u8; 32]) };
    if sbytes[31] > 0x10 {
        return 0;
    }
    if sbytes[31] == 0x10 {
        if sbytes[16..31].iter().any(|&b| b != 0) {
            return 0;
        }
        let mut i: isize = 15;
        while i >= 0 {
            if sbytes[i as usize] < L_LOW[i as usize] {
                break;
            }
            if sbytes[i as usize] > L_LOW[i as usize] {
                return 0;
            }
            i -= 1;
        }
        if i < 0 {
            return 0;
        }
    }

    // SAFETY: `public_key` is readable for 32 bytes.
    let pk = unsafe { *(public_key as *const [u8; 32]) };
    let a = match ge_frombytes_vartime(&pk) {
        Some(a) => a,
        None => return 0,
    };
    let a = GeP3 {
        x: fe_neg(&a.x),
        y: a.y,
        z: a.z,
        t: fe_neg(&a.t),
    };

    // SAFETY: `libctx`/`propq` are the caller's; the name is a compile-time constant.
    let sha512 = unsafe { EVP_MD_fetch(libctx, c"SHA512".as_ptr(), propq) };
    if sha512.is_null() {
        return 0;
    }
    let hash_ctx = EVP_MD_CTX_new();
    if hash_ctx.is_null() {
        // SAFETY: `sha512` is live.
        unsafe { EVP_MD_free(sha512) };
        return 0;
    }

    // SAFETY: all pointers are live and each buffer is valid for its length.
    let ok = unsafe {
        hash_init_with_dom(hash_ctx, sha512, dom2flag, phflag, context, context_len) != 0
            && EVP_DigestUpdate(hash_ctx, r.cast(), 32) != 0
            && EVP_DigestUpdate(hash_ctx, public_key.cast(), 32) != 0
            && EVP_DigestUpdate(hash_ctx, tbs.cast(), tbs_len) != 0
            && EVP_DigestFinal_ex(hash_ctx, h.as_mut_ptr(), &mut sz) != 0
    };
    if !ok {
        // SAFETY: both are live.
        unsafe {
            EVP_MD_free(sha512);
            EVP_MD_CTX_free(hash_ctx);
        }
        return 0;
    }

    x25519_sc_reduce(&mut h);
    // SAFETY: `hash_ctx`/`sha512` are live.
    unsafe {
        EVP_MD_free(sha512);
        EVP_MD_CTX_free(hash_ctx);
    }

    let rr = ge_double_scalarmult_vartime(&h, &a, &sbytes);
    let rcheck = ge_tobytes(&rr);
    // SAFETY: both buffers are 32 bytes and live.
    (unsafe { CRYPTO_memcmp(rcheck.as_ptr().cast(), r.cast(), 32) } == 0) as c_int
}

/// `int ossl_ed25519_public_from_private(OSSL_LIB_CTX *ctx, uint8_t out_public_key[32],
/// const uint8_t private_key[32], const char *propq)` — `curve25519.c:5814`.
///
/// # Safety
/// `out_public_key` writable for 32 bytes; `private_key` readable for 32; `ctx`/`propq` NULL
/// or live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ed25519_public_from_private(
    ctx: *mut c_void,
    out_public_key: *mut u8,
    private_key: *const u8,
    propq: *const c_char,
) -> c_int {
    let mut az = [0u8; SHA512_LEN];
    // SAFETY: `ctx`/`propq` are the caller's; the name is a compile-time constant.
    let sha512 = unsafe { EVP_MD_fetch(ctx, c"SHA512".as_ptr(), propq) };
    if sha512.is_null() {
        return 0;
    }
    // SAFETY: `private_key` is readable for 32 bytes; `az` is 64 bytes.
    let r = unsafe {
        EVP_Digest(
            private_key.cast(),
            32,
            az.as_mut_ptr(),
            ptr::null_mut(),
            sha512,
            ptr::null_mut(),
        )
    };
    // SAFETY: `sha512` is live.
    unsafe { EVP_MD_free(sha512) };
    if r == 0 {
        // SAFETY: `az` is 64 bytes and live.
        unsafe { OPENSSL_cleanse(az.as_mut_ptr().cast(), SHA512_LEN) };
        return 0;
    }

    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    let a = ge_scalarmult_base(&az);
    let out = ge_p3_tobytes(&a);
    // SAFETY: `out_public_key` is writable for 32 bytes.
    unsafe { ptr::copy_nonoverlapping(out.as_ptr(), out_public_key, 32) };
    // SAFETY: `az` is 64 bytes and live.
    unsafe { OPENSSL_cleanse(az.as_mut_ptr().cast(), SHA512_LEN) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        out
    }

    /// Both ladders answer the RFC 7748 §6.1 shared secret, whichever arm the CPU selects.
    #[test]
    fn x25519_both_ladders_agree() {
        let alice_sk = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_pk = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let want = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519_scalar_mulx(&alice_sk, &bob_pk), want);
        assert_eq!(x25519_scalar_mult_fe51(&alice_sk, &bob_pk), want);
    }

    /// RFC 7748 §6.1 — the two X25519 vectors, `ossl_x25519` on both sides of the exchange.
    #[test]
    fn x25519_rfc7748_section_6_1() {
        let alice_sk = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_sk = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let mut alice_pk = [0u8; 32];
        let mut bob_pk = [0u8; 32];
        // SAFETY: each pointer is live for the lengths used.
        unsafe {
            ossl_x25519_public_from_private(alice_pk.as_mut_ptr(), alice_sk.as_ptr());
            ossl_x25519_public_from_private(bob_pk.as_mut_ptr(), bob_sk.as_ptr());
        }
        assert_eq!(
            alice_pk,
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob_pk,
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let mut a_shared = [0u8; 32];
        let mut b_shared = [0u8; 32];
        // SAFETY: each pointer is live for the lengths used.
        unsafe {
            assert_eq!(
                ossl_x25519(a_shared.as_mut_ptr(), alice_sk.as_ptr(), bob_pk.as_ptr()),
                1
            );
            assert_eq!(
                ossl_x25519(b_shared.as_mut_ptr(), bob_sk.as_ptr(), alice_pk.as_ptr()),
                1
            );
        }
        assert_eq!(a_shared, b_shared);
        assert_eq!(
            a_shared,
            hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    /// RFC 8032 §7.1 — TEST 1, TEST 2 and TEST 3, sign and verify.
    #[test]
    fn ed25519_rfc8032_section_7_1() {
        let cases: [(&str, &str, &[u8], &str); 3] = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                &[],
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                &[0x72],
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                &[0xaf, 0x82],
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (sk_hex, pk_hex, msg, sig_hex) in cases {
            let sk = hex(sk_hex);
            let pk = hex(pk_hex);
            let mut out_pk = [0u8; 32];
            // SAFETY: each pointer is live for the lengths used.
            unsafe {
                assert_eq!(
                    ossl_ed25519_public_from_private(
                        ptr::null_mut(),
                        out_pk.as_mut_ptr(),
                        sk.as_ptr(),
                        ptr::null()
                    ),
                    1
                );
            }
            assert_eq!(out_pk, pk, "public key for {sk_hex}");

            let mut sig = [0u8; 64];
            // SAFETY: each pointer is live for the lengths used.
            unsafe {
                assert_eq!(
                    ossl_ed25519_sign(
                        sig.as_mut_ptr(),
                        msg.as_ptr(),
                        msg.len(),
                        pk.as_ptr(),
                        sk.as_ptr(),
                        0,
                        0,
                        0,
                        ptr::null(),
                        0,
                        ptr::null_mut(),
                        ptr::null(),
                    ),
                    1
                );
            }
            let mut want = [0u8; 64];
            for i in 0..64 {
                want[i] = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
            }
            assert_eq!(sig, want, "signature for {sk_hex}");

            // SAFETY: each pointer is live for the lengths used.
            unsafe {
                assert_eq!(
                    ossl_ed25519_verify(
                        msg.as_ptr(),
                        msg.len(),
                        sig.as_ptr(),
                        pk.as_ptr(),
                        0,
                        0,
                        0,
                        ptr::null(),
                        0,
                        ptr::null_mut(),
                        ptr::null(),
                    ),
                    1
                );
            }
        }
    }
}
