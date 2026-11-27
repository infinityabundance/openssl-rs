//! M-A7 timing harness — carry-save CIOS versus the admitted fixed-width CIOS.
//!
//! This is a **measurement instrument**, not part of the crate. It is built as a
//! standalone release binary in the court and:
//!
//! 1. includes the prototype source directly (`/work/src/bn/carry_save.rs`), so
//!    the timed prototype is the exact source the crate's tests exercise;
//! 2. carries a **verbatim transcription** of the admitted kernel
//!    `src/bn/arith.rs::mont_mul_cios_fixed<const N, const ACC>` with `Limb = u64`;
//! 3. differential-checks the two against each other in the *optimised* build
//!    before timing, so a transcription slip cannot be measured as a result;
//! 4. alternates the two kernels round by round in one process and reports the
//!    median and minimum ns/op.
//!
//! Scope limit: both kernels live in this experiment binary, so no claim is made
//! that the absolute ns/op transfers to the distribution DSO (`DSO_TRANSFER` is
//! `NOT_RUN` in `RECEIPT.md`). The ratio is the measured quantity.

#![forbid(unsafe_code)]

#[path = "/work/src/bn/carry_save.rs"]
mod carry_save;

use carry_save::mont_mul_cs_core;
use std::hint::black_box;
use std::time::Instant;

/// Verbatim transcription of `src/bn/arith.rs::mont_mul_cios_fixed`, with
/// `Limb` spelled `u64` and the mask select inlined exactly as the source does.
#[inline]
fn mont_mul_cios_fixed<const N: usize, const ACC: usize>(
    a: &[u64],
    b: &[u64],
    out: &mut [u64],
    m: &[u64],
    n0: u64,
    t: &mut [u64],
    diff: &mut [u64],
) -> bool {
    if N == 0 || ACC < N + 2 || t.len() < ACC {
        return false;
    }
    let (Ok(a), Ok(b), Ok(m)) = (
        <&[u64; N]>::try_from(a),
        <&[u64; N]>::try_from(b),
        <&[u64; N]>::try_from(m),
    ) else {
        return false;
    };
    let (Ok(out), Ok(diff), Ok(acc)) = (
        <&mut [u64; N]>::try_from(out),
        <&mut [u64; N]>::try_from(diff),
        <&mut [u64; ACC]>::try_from(&mut t[..ACC]),
    ) else {
        return false;
    };

    acc.fill(0);

    for &bi in b {
        let mut carry = 0u64;
        for j in 0..N {
            let v = (a[j] as u128)
                .wrapping_mul(bi as u128)
                .wrapping_add(acc[j] as u128)
                .wrapping_add(carry as u128);
            acc[j] = v as u64;
            carry = (v >> 64) as u64;
        }
        let (hi, overflow) = acc[N].overflowing_add(carry);
        acc[N] = hi;
        acc[N + 1] = u64::from(overflow);

        let u = acc[0].wrapping_mul(n0);
        let v = (u as u128)
            .wrapping_mul(m[0] as u128)
            .wrapping_add(acc[0] as u128);
        let mut carry = (v >> 64) as u64;
        for j in 1..N {
            let v = (u as u128)
                .wrapping_mul(m[j] as u128)
                .wrapping_add(acc[j] as u128)
                .wrapping_add(carry as u128);
            acc[j - 1] = v as u64;
            carry = (v >> 64) as u64;
        }
        let (lo, overflow) = acc[N].overflowing_add(carry);
        acc[N - 1] = lo;
        acc[N] = acc[N + 1].wrapping_add(u64::from(overflow));
    }

    let high = acc[N];
    let mut borrow = 0u64;
    for j in 0..N {
        let (d1, b1) = acc[j].overflowing_sub(m[j]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let keep = high | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(keep);
    for j in 0..N {
        out[j] = (diff[j] & mask) | (acc[j] & !mask);
    }
    true
}

fn n0_for(m0: u64) -> u64 {
    let mut inv = m0;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Odd modulus with the top limb's high bit set, and operands with that bit
/// cleared, so `a, b < m` holds by construction.
fn modulus_4() -> ([u64; 4], [u64; 4], [u64; 4], u64) {
    let mut state = 0x0123_4567_89ab_cdefu64;
    let mut m = [0u64; 4];
    let mut a = [0u64; 4];
    let mut b = [0u64; 4];
    for limb in m.iter_mut() {
        *limb = xorshift(&mut state);
    }
    for limb in a.iter_mut() {
        *limb = xorshift(&mut state);
    }
    for limb in b.iter_mut() {
        *limb = xorshift(&mut state);
    }
    m[0] |= 1;
    m[3] |= 1 << 63;
    a[3] &= !(1 << 63);
    b[3] &= !(1 << 63);
    let n0 = n0_for(m[0]);
    (m, a, b, n0)
}

fn modulus_16() -> ([u64; 16], [u64; 16], [u64; 16], u64) {
    let mut state = 0x0123_4567_89ab_cdefu64;
    let mut m = [0u64; 16];
    let mut a = [0u64; 16];
    let mut b = [0u64; 16];
    for limb in m.iter_mut() {
        *limb = xorshift(&mut state);
    }
    for limb in a.iter_mut() {
        *limb = xorshift(&mut state);
    }
    for limb in b.iter_mut() {
        *limb = xorshift(&mut state);
    }
    m[0] |= 1;
    m[15] |= 1 << 63;
    a[15] &= !(1 << 63);
    b[15] &= !(1 << 63);
    let n0 = n0_for(m[0]);
    (m, a, b, n0)
}

// One timed block per kernel. `black_box` on the arguments and results keeps the
// compiler from hoisting a pure call with loop-invariant inputs out of the loop.

#[inline(never)]
fn round_cios4(iters: u64, a: &[u64; 4], b: &[u64; 4], m: &[u64; 4], n0: u64) -> u64 {
    let mut out = [0u64; 4];
    let mut t = [0u64; 6];
    let mut diff = [0u64; 4];
    let mut acc = 0u64;
    for _ in 0..iters {
        mont_mul_cios_fixed::<4, 6>(
            black_box(&a[..]),
            black_box(&b[..]),
            &mut out[..],
            black_box(&m[..]),
            black_box(n0),
            &mut t[..],
            &mut diff[..],
        );
        acc ^= out[0];
    }
    black_box(acc)
}

#[inline(never)]
fn round_cs4(iters: u64, a: &[u64; 4], b: &[u64; 4], m: &[u64; 4], n0: u64) -> u64 {
    let mut s = [0u64; 10];
    let mut c = [0u64; 10];
    let mut acc = 0u64;
    for _ in 0..iters {
        let out = mont_mul_cs_core::<4, 10>(
            black_box(a),
            black_box(b),
            black_box(m),
            black_box(n0),
            &mut s,
            &mut c,
        )
        .expect("odd modulus");
        acc ^= out[0];
    }
    black_box(acc)
}

#[inline(never)]
fn round_cios16(iters: u64, a: &[u64; 16], b: &[u64; 16], m: &[u64; 16], n0: u64) -> u64 {
    let mut out = [0u64; 16];
    let mut t = [0u64; 18];
    let mut diff = [0u64; 16];
    let mut acc = 0u64;
    for _ in 0..iters {
        mont_mul_cios_fixed::<16, 18>(
            black_box(&a[..]),
            black_box(&b[..]),
            &mut out[..],
            black_box(&m[..]),
            black_box(n0),
            &mut t[..],
            &mut diff[..],
        );
        acc ^= out[0];
    }
    black_box(acc)
}

#[inline(never)]
fn round_cs16(iters: u64, a: &[u64; 16], b: &[u64; 16], m: &[u64; 16], n0: u64) -> u64 {
    let mut s = [0u64; 34];
    let mut c = [0u64; 34];
    let mut acc = 0u64;
    for _ in 0..iters {
        let out = mont_mul_cs_core::<16, 34>(
            black_box(a),
            black_box(b),
            black_box(m),
            black_box(n0),
            &mut s,
            &mut c,
        )
        .expect("odd modulus");
        acc ^= out[0];
    }
    black_box(acc)
}

fn measure<F: FnMut(u64) -> u64>(iters: u64, mut f: F) -> f64 {
    let start = Instant::now();
    let out = f(iters);
    let elapsed = start.elapsed().as_secs_f64();
    black_box(out);
    elapsed * 1e9 / iters as f64
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    v[v.len() / 2]
}

fn minimum(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::INFINITY, f64::min)
}

/// Differential in the same optimised binary the timing uses.
fn differential() {
    let mut state = 0xfeed_face_dead_beefu64;

    let (m, a, b, n0) = modulus_4();
    let mut out_c = [0u64; 4];
    let mut t = [0u64; 6];
    let mut diff = [0u64; 4];
    let mut mismatches = 0usize;
    for _ in 0..20_000 {
        let mut aa = a;
        let mut bb = b;
        for limb in aa.iter_mut() {
            *limb ^= xorshift(&mut state);
        }
        for limb in bb.iter_mut() {
            *limb ^= xorshift(&mut state);
        }
        aa[3] &= !(1 << 63);
        bb[3] &= !(1 << 63);
        mont_mul_cios_fixed::<4, 6>(&aa, &bb, &mut out_c, &m, n0, &mut t, &mut diff);
        let cs = mont_mul_cs_core::<4, 10>(&aa, &bb, &m, n0, &mut [0u64; 10], &mut [0u64; 10])
            .expect("odd modulus");
        if cs != out_c {
            mismatches += 1;
        }
    }
    println!("DIFF width=4 pairs=20000 mismatches={mismatches}");

    let (m, a, b, n0) = modulus_16();
    let mut out_c = [0u64; 16];
    let mut t = [0u64; 18];
    let mut diff = [0u64; 16];
    let mut mismatches = 0usize;
    for _ in 0..20_000 {
        let mut aa = a;
        let mut bb = b;
        for limb in aa.iter_mut() {
            *limb ^= xorshift(&mut state);
        }
        for limb in bb.iter_mut() {
            *limb ^= xorshift(&mut state);
        }
        aa[15] &= !(1 << 63);
        bb[15] &= !(1 << 63);
        mont_mul_cios_fixed::<16, 18>(&aa, &bb, &mut out_c, &m, n0, &mut t, &mut diff);
        let cs = mont_mul_cs_core::<16, 34>(&aa, &bb, &m, n0, &mut [0u64; 34], &mut [0u64; 34])
            .expect("odd modulus");
        if cs != out_c {
            mismatches += 1;
        }
    }
    println!("DIFF width=16 pairs=20000 mismatches={mismatches}");
}

fn main() {
    differential();

    let rounds: usize = 41;
    let iters4: u64 = 300_000;
    let iters16: u64 = 60_000;

    let (m4, a4, b4, n04) = modulus_4();
    let (m16, a16, b16, n016) = modulus_16();

    // Warm-up.
    round_cios4(1_000, &a4, &b4, &m4, n04);
    round_cs4(1_000, &a4, &b4, &m4, n04);
    round_cios16(200, &a16, &b16, &m16, n016);
    round_cs16(200, &a16, &b16, &m16, n016);

    let mut cios4 = Vec::with_capacity(rounds);
    let mut cs4 = Vec::with_capacity(rounds);
    let mut cios16 = Vec::with_capacity(rounds);
    let mut cs16 = Vec::with_capacity(rounds);

    for r in 0..rounds {
        // Alternate the order every round to cancel warm-up/thermal drift.
        let c4 = || measure(iters4, |k| round_cios4(k, &a4, &b4, &m4, n04));
        let s4 = || measure(iters4, |k| round_cs4(k, &a4, &b4, &m4, n04));
        let c16 = || measure(iters16, |k| round_cios16(k, &a16, &b16, &m16, n016));
        let s16 = || measure(iters16, |k| round_cs16(k, &a16, &b16, &m16, n016));
        if r % 2 == 0 {
            cios4.push(c4());
            cs4.push(s4());
            cios16.push(c16());
            cs16.push(s16());
        } else {
            cs4.push(s4());
            cios4.push(c4());
            cs16.push(s16());
            cios16.push(c16());
        }
        println!(
            "SAMPLE round={r} width=4 cios_ns={:.4} cs_ns={:.4} width=16 cios_ns={:.4} cs_ns={:.4}",
            cios4[r], cs4[r], cios16[r], cs16[r]
        );
    }

    for (width, c, s) in [(4, &cios4, &cs4), (16, &cios16, &cs16)] {
        let cm = median(c.clone());
        let cmm = minimum(c);
        let sm = median(s.clone());
        let smm = minimum(s);
        println!("SUMMARY width={width} kernel=cios median_ns={cm:.4} min_ns={cmm:.4}");
        println!("SUMMARY width={width} kernel=carry_save median_ns={sm:.4} min_ns={smm:.4}");
        println!(
            "RATIO width={width} median_cs_over_cios={:.5} min_cs_over_cios={:.5}",
            sm / cm,
            smm / cmm
        );
    }
}
