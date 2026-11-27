//! M-A2 experiment driver.
//!
//! Modes:
//!   check  — differential + independent-oracle correctness over a population
//!            (default; exits 2 on any mismatch, non-canonical output, or a
//!            failed radix conversion).
//!   bench  — interleaved single-multiply timing of the prototypes in one
//!            binary, median per-op times and a paired bootstrap interval.
//!   perf   — a fixed number of ops of one kernel, for `perf stat`.
//!
//! Everything is safe Rust (`#![forbid(unsafe_code)]`); no intrinsics, no
//! assembly. The crate is an experiment and is not linked into the product.

#![forbid(unsafe_code)]
#![allow(clippy::needless_range_loop)]

use std::cmp::Ordering;
use std::hint::black_box;
use std::time::Instant;

use ma2::big;
use ma2::*;

/// Recorded seed, so every population in `RESULTS.md` is reproducible.
const SEED: u64 = 0x4d2d_4132_0000_0001;

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n as u64)) as usize
    }
}

/// Odd modulus with the top 64-bit limb's bit 63 set, so the value is in
/// `[2^(64N-1), 2^(64N))` and one conditional subtraction reduces any
/// `2^(64N)`-bounded random value. `extreme` saturates the top limb.
fn make_modulus<const N: usize>(rng: &mut Rng, extreme: bool) -> [u64; N] {
    let mut m = [0u64; N];
    for limb in m.iter_mut() {
        *limb = rng.next_u64();
    }
    if extreme {
        m[N - 1] = u64::MAX;
    }
    m[N - 1] |= 1 << 63;
    m[0] |= 1;
    m
}

fn subtract_in_place(a: &mut [u64], b: &[u64]) {
    let mut borrow = 0u64;
    for j in 0..a.len() {
        let rhs = if j < b.len() { b[j] } else { 0 };
        let (d1, b1) = a[j].overflowing_sub(rhs);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
}

fn sub_one(a: &[u64]) -> Vec<u64> {
    let mut v = a.to_vec();
    let mut borrow = 1u64;
    for limb in v.iter_mut() {
        let (d, b) = limb.overflowing_sub(borrow);
        *limb = d;
        borrow = u64::from(b);
        if borrow == 0 {
            break;
        }
    }
    v
}

/// Random value in `[0, m)`. Requires `m >= 2^(64N-1)`; one subtraction then
/// suffices because the raw value is below `2^(64N) <= 2m`.
fn rand_below<const N: usize>(rng: &mut Rng, m: &[u64; N]) -> Vec<u64> {
    let mut v = vec![0u64; N];
    for limb in v.iter_mut() {
        *limb = rng.next_u64();
    }
    if big::cmp(&v, m) != Ordering::Less {
        subtract_in_place(&mut v, m);
    }
    v
}

fn push_unique(values: &mut Vec<Vec<u64>>, v: Vec<u64>, m: &[u64]) {
    let r = big::rem(&v, m);
    if !values.iter().any(|x| big::cmp(x, &r) == Ordering::Equal) {
        values.push(r);
    }
}

/// The structured operand population: 0, 1, m-1, all-ones limbs in both
/// representions, and every single-non-zero-limb value in both representations.
fn structured_values<const N64: usize, const N52: usize>(
    m: &[u64; N64],
    m52: &[u64; N52],
) -> Vec<Vec<u64>> {
    let mut values: Vec<Vec<u64>> = Vec::new();
    let zero = vec![0u64; N64];
    let one = {
        let mut v = vec![0u64; N64];
        v[0] = 1;
        v
    };
    push_unique(&mut values, zero, m);
    push_unique(&mut values, one, m);
    push_unique(&mut values, sub_one(m), m);
    push_unique(&mut values, vec![u64::MAX; N64], m);
    let ones52 = [MASK52; N52];
    push_unique(&mut values, value_vec(&ones52, 52), m);
    for j in 0..N64 {
        let mut v = vec![0u64; N64];
        v[j] = 1;
        push_unique(&mut values, v, m);
    }
    for j in 0..N52 {
        let bit = 52 * j;
        let mut v = vec![0u64; N64];
        v[bit / 64] |= 1u64 << (bit % 64);
        push_unique(&mut values, v, m);
    }
    let _ = m52;
    values
}

struct Outcome {
    m64_pair: bool,
    m52_pair: bool,
    m_cross: bool,
    m_oracle: bool,
    oracle_checked: bool,
    nc64: bool,
    nc52: bool,
    conversion_bad: bool,
}

impl Outcome {
    fn mismatch(&self) -> bool {
        self.m64_pair || self.m52_pair || self.m_cross || self.m_oracle
    }
}

fn hexv(v: &[u64]) -> String {
    let mut s = String::new();
    for limb in v.iter().rev() {
        s.push_str(&format!("{:016x}", limb));
    }
    s
}

struct Harness<const N64: usize, const N52: usize, const L64: usize, const LR: usize> {
    m: [u64; N64],
    m52: [u64; N52],
    n0_64: u64,
    n0_52: u64,
    rinv64: Vec<u64>,
    rinv52: Vec<u64>,
    /// `R64 * R52^-1 mod m`: maps a radix-64 Montgomery result to the radix-52
    /// Montgomery result of the same operands.
    c_mul: Vec<u64>,
    acc64: [u64; L64],
    acc52: [u128; N52],
    accr: [u128; LR],
    out64s: Vec<u64>,
    t64s: Vec<u64>,
    diff64s: Vec<u64>,
}

impl<const N64: usize, const N52: usize, const L64: usize, const LR: usize>
    Harness<N64, N52, L64, LR>
{
    fn new(m: [u64; N64]) -> Self {
        let m52: [u64; N52] = repack_fixed(&m, 64, 52);
        let rinv64 = r_inv(64 * N64 as u32, &m);
        let rinv52 = r_inv(52 * N52 as u32, &m);
        let r64 = big::pow2_mod(64 * N64 as u32, &m);
        let c_mul = big::modmul(&r64, &rinv52, &m);
        Self {
            m,
            m52,
            n0_64: n0_64(m[0]),
            n0_52: n0_52(m52[0]),
            rinv64,
            rinv52,
            c_mul,
            acc64: [0u64; L64],
            acc52: [0u128; N52],
            accr: [0u128; LR],
            out64s: vec![0u64; N64],
            t64s: vec![0u64; 2 * N64 + 1],
            diff64s: vec![0u64; N64],
        }
    }

    fn verify(&mut self, a: &[u64], b: &[u64], oracle: bool) -> Outcome {
        let mut out = Outcome {
            m64_pair: false,
            m52_pair: false,
            m_cross: false,
            m_oracle: false,
            oracle_checked: false,
            nc64: false,
            nc52: false,
            conversion_bad: false,
        };

        let a52: [u64; N52] = repack_fixed(a, 64, 52);
        let b52: [u64; N52] = repack_fixed(b, 64, 52);
        let a_back: [u64; N64] = repack_fixed(&a52, 52, 64);
        let b_back: [u64; N64] = repack_fixed(&b52, 52, 64);
        if a_back.as_slice() != a || b_back.as_slice() != b {
            out.conversion_bad = true;
        }

        let a64: [u64; N64] = to_array(a);
        let b64: [u64; N64] = to_array(b);

        let o64f = mont_mul_64_fixed::<N64, L64>(&a64, &b64, &self.m, self.n0_64, &mut self.acc64);
        let slice_ok = mont_mul_64_slice(
            &a64,
            &b64,
            &mut self.out64s,
            &self.m,
            self.n0_64,
            &mut self.t64s,
            &mut self.diff64s,
        );
        if !slice_ok {
            out.m64_pair = true;
        }
        let o52d = mont_mul_52_deferred::<N52>(&a52, &b52, &self.m52, self.n0_52, &mut self.acc52);
        let o52r = mont_mul_52_rotate::<N52, LR>(&a52, &b52, &self.m52, self.n0_52, &mut self.accr);

        // 64-bit fixed and transcribed-slice kernels must agree exactly.
        if big::cmp(&o64f, &self.out64s) != Ordering::Equal {
            out.m64_pair = true;
        }
        // The two radix-52 schedules must agree exactly.
        if o52d != o52r {
            out.m52_pair = true;
        }
        // The two prototypes use different R, so compare through each operand's
        // own R: out52 == out64 * (R64/R52) mod m.
        let mapped = big::modmul(&o64f, &self.c_mul, &self.m);
        let v52 = value_vec(&o52d, 52);
        if big::cmp(&mapped, &v52) != Ordering::Equal {
            out.m_cross = true;
        }

        // Canonical output for every case, from every kernel.
        if big::cmp(&o64f, &self.m) != Ordering::Less
            || big::cmp(&self.out64s, &self.m) != Ordering::Less
        {
            out.nc64 = true;
        }
        if big::cmp(&v52, &self.m) != Ordering::Less
            || o52d.iter().any(|&x| x > MASK52)
            || o52r.iter().any(|&x| x > MASK52)
        {
            out.nc52 = true;
        }

        if oracle {
            out.oracle_checked = true;
            let expect64 = mont_oracle(a, b, &self.m, &self.rinv64);
            let expect52 = mont_oracle(a, b, &self.m, &self.rinv52);
            if big::cmp(&expect64, &o64f) != Ordering::Equal
                || big::cmp(&expect52, &v52) != Ordering::Equal
            {
                out.m_oracle = true;
            }
        }
        out
    }

    fn dump(&mut self, a: &[u64], b: &[u64]) {
        let a52: [u64; N52] = repack_fixed(a, 64, 52);
        let b52: [u64; N52] = repack_fixed(b, 64, 52);
        let a64: [u64; N64] = to_array(a);
        let b64: [u64; N64] = to_array(b);
        let o64f = mont_mul_64_fixed::<N64, L64>(&a64, &b64, &self.m, self.n0_64, &mut self.acc64);
        let _ = mont_mul_64_slice(
            &a64,
            &b64,
            &mut self.out64s,
            &self.m,
            self.n0_64,
            &mut self.t64s,
            &mut self.diff64s,
        );
        let o52d = mont_mul_52_deferred::<N52>(&a52, &b52, &self.m52, self.n0_52, &mut self.acc52);
        let o52r = mont_mul_52_rotate::<N52, LR>(&a52, &b52, &self.m52, self.n0_52, &mut self.accr);
        let v52 = value_vec(&o52d, 52);
        let vr = value_vec(&o52r, 52);
        let mapped = big::modmul(&o64f, &self.c_mul, &self.m);
        let expect64 = mont_oracle(a, b, &self.m, &self.rinv64);
        let expect52 = mont_oracle(a, b, &self.m, &self.rinv52);
        eprintln!(
            "MISMATCH\n  m      = {}\n  a      = {}\n  b      = {}\n  \
 64fixed = {}\n  64slice= {}\n  52def  = {}\n  52rot  = {}\n  \
 value52= {}\n  rotval = {}\n  mapped = {}\n  exp64  = {}\n  exp52  = {}\n  \
 m52    = {:?}",
            hexv(&self.m),
            hexv(a),
            hexv(b),
            hexv(&o64f),
            hexv(&self.out64s),
            hexv(&o52d),
            hexv(&o52r),
            hexv(&v52),
            hexv(&vr),
            hexv(&mapped),
            hexv(&expect64),
            hexv(&expect52),
            self.m52
        );
    }
}

fn to_array<const N: usize>(v: &[u64]) -> [u64; N] {
    let mut out = [0u64; N];
    out.copy_from_slice(&v[..N]);
    out
}

struct WidthSummary {
    width: u32,
    moduli: usize,
    pairs: u64,
    mismatches: u64,
    m64_pair: u64,
    m52_pair: u64,
    m_cross: u64,
    m_oracle: u64,
    oracle_checks: u64,
    noncanonical: u64,
    nc64: u64,
    nc52: u64,
    conversion_failures: u64,
}

fn check_width<const N64: usize, const N52: usize, const L64: usize, const LR: usize>(
    width: u32,
    moduli_count: usize,
    random_pairs: usize,
    oracle_random_per_modulus: usize,
    rng: &mut Rng,
) -> WidthSummary {
    let mut summary = WidthSummary {
        width,
        moduli: moduli_count,
        pairs: 0,
        mismatches: 0,
        m64_pair: 0,
        m52_pair: 0,
        m_cross: 0,
        m_oracle: 0,
        oracle_checks: 0,
        noncanonical: 0,
        nc64: 0,
        nc52: 0,
        conversion_failures: 0,
    };
    let mut dumped = 0u64;
    let record = |s: &mut WidthSummary, o: &Outcome| {
        s.pairs += 1;
        if o.mismatch() {
            s.mismatches += 1;
        }
        s.m64_pair += u64::from(o.m64_pair);
        s.m52_pair += u64::from(o.m52_pair);
        s.m_cross += u64::from(o.m_cross);
        s.m_oracle += u64::from(o.m_oracle);
        s.nc64 += u64::from(o.nc64);
        s.nc52 += u64::from(o.nc52);
        if o.nc64 || o.nc52 {
            s.noncanonical += 1;
        }
        if o.oracle_checked {
            s.oracle_checks += 1;
        }
        if o.conversion_bad {
            s.conversion_failures += 1;
        }
    };

    for mi in 0..moduli_count {
        let extreme = mi < 2;
        let m = make_modulus::<N64>(rng, extreme);
        let m52: [u64; N52] = repack_fixed(&m, 64, 52);
        let m_back: [u64; N64] = repack_fixed(&m52, 52, 64);
        if m_back != m {
            summary.conversion_failures += 1;
        }
        let mut h = Harness::<N64, N52, L64, LR>::new(m);
        // The modulus conversion and the two modular-inverse identities are
        // part of correctness, not just the multiply.
        let r64 = big::pow2_mod(64 * N64 as u32, &h.m);
        let r52 = big::pow2_mod(52 * N52 as u32, &h.m);
        if big::cmp(&big::modmul(&r64, &h.rinv64, &h.m), &[1u64]) != Ordering::Equal
            || big::cmp(&big::modmul(&r52, &h.rinv52, &h.m), &[1u64]) != Ordering::Equal
        {
            summary.mismatches += 1;
        }

        let values = structured_values(&h.m, &h.m52);
        let nv = values.len();
        let structured_total = nv * nv;
        let struct_stride = std::cmp::max(1, structured_total / 64);

        for i in 0..nv {
            for j in 0..nv {
                let every = i < 3 && j < 3;
                let oracle = every || (i * nv + j) % struct_stride == 0;
                let outcome = h.verify(&values[i], &values[j], oracle);
                record(&mut summary, &outcome);
                if outcome.mismatch() && dumped < 4 {
                    dumped += 1;
                    eprintln!("structured mismatch mi={mi} i={i} j={j}");
                    h.dump(&values[i], &values[j]);
                }
            }
        }

        let stride = std::cmp::max(
            1,
            random_pairs / std::cmp::max(1, oracle_random_per_modulus),
        );
        for k in 0..random_pairs {
            let a = rand_below(rng, &h.m);
            let b = rand_below(rng, &h.m);
            let oracle = oracle_random_per_modulus > 0 && k % stride == 0;
            let outcome = h.verify(&a, &b, oracle);
            record(&mut summary, &outcome);
            if outcome.mismatch() && dumped < 4 {
                dumped += 1;
                eprintln!("random mismatch mi={mi} k={k}");
                h.dump(&a, &b);
            }
        }

        // Forced pre-reduction-value family. `a = 1, b = r*R mod m` makes the
        // pre-subtraction value `r` (plus `m` when `r < m^2/R`), so it reaches
        // the conditional-subtraction branch at every width. At 1024 bits the
        // branch has probability about `m/R = 2^-16` under random operands and
        // would otherwise go untested.
        let r_mod = big::pow2_mod(52 * N52 as u32, &h.m);
        let mut one = vec![0u64; N64];
        one[0] = 1;
        let mut targets: Vec<Vec<u64>> = Vec::new();
        for small in 0..4u64 {
            let mut v = vec![0u64; N64];
            v[0] = small;
            targets.push(v);
        }
        targets.push(sub_one(&h.m));
        for r in targets {
            let b = big::modmul(&r_mod, &r, &h.m);
            for (x, y) in [(&one, &b), (&b, &one)] {
                let outcome = h.verify(x, y, true);
                record(&mut summary, &outcome);
                if outcome.mismatch() && dumped < 4 {
                    dumped += 1;
                    eprintln!("forced-reduction mismatch mi={mi}");
                    h.dump(x, y);
                }
            }
        }
    }
    summary
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Setup<const N64: usize, const N52: usize, const L64: usize, const LR: usize> {
    m: [u64; N64],
    m52: [u64; N52],
    a64: [u64; N64],
    b64: [u64; N64],
    a52: [u64; N52],
    b52: [u64; N52],
    n0_64: u64,
    n0_52: u64,
    acc64: [u64; L64],
    acc52: [u128; N52],
    accr: [u128; LR],
    out64s: Vec<u64>,
    t64s: Vec<u64>,
    diff64s: Vec<u64>,
}

impl<const N64: usize, const N52: usize, const L64: usize, const LR: usize>
    Setup<N64, N52, L64, LR>
{
    fn new(rng: &mut Rng) -> Self {
        let m = make_modulus::<N64>(rng, false);
        let a = rand_below(rng, &m);
        let b = rand_below(rng, &m);
        let m52: [u64; N52] = repack_fixed(&m, 64, 52);
        Self {
            m,
            m52,
            a64: to_array(&a),
            b64: to_array(&b),
            a52: repack_fixed(&a, 64, 52),
            b52: repack_fixed(&b, 64, 52),
            n0_64: n0_64(m[0]),
            n0_52: n0_52(m52[0]),
            acc64: [0u64; L64],
            acc52: [0u128; N52],
            accr: [0u128; LR],
            out64s: vec![0u64; N64],
            t64s: vec![0u64; 2 * N64 + 1],
            diff64s: vec![0u64; N64],
        }
    }

    fn run52(&mut self) -> [u64; N52] {
        mont_mul_52_deferred(
            black_box(&self.a52),
            black_box(&self.b52),
            black_box(&self.m52),
            black_box(self.n0_52),
            black_box(&mut self.acc52),
        )
    }

    fn run52r(&mut self) -> [u64; N52] {
        mont_mul_52_rotate(
            black_box(&self.a52),
            black_box(&self.b52),
            black_box(&self.m52),
            black_box(self.n0_52),
            black_box(&mut self.accr),
        )
    }

    fn run64f(&mut self) -> [u64; N64] {
        mont_mul_64_fixed(
            black_box(&self.a64),
            black_box(&self.b64),
            black_box(&self.m),
            black_box(self.n0_64),
            black_box(&mut self.acc64),
        )
    }

    fn run64s(&mut self) -> bool {
        mont_mul_64_slice(
            black_box(&self.a64),
            black_box(&self.b64),
            black_box(&mut self.out64s),
            black_box(&self.m),
            black_box(self.n0_64),
            black_box(&mut self.t64s),
            black_box(&mut self.diff64s),
        )
    }
}

fn time_batch<F: FnMut()>(f: &mut F, batch: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..batch {
        f();
    }
    start.elapsed().as_secs_f64()
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        0.5 * (v[n / 2 - 1] + v[n / 2])
    }
}

fn bench_pair<FA, FB>(
    width: u32,
    name: &str,
    fa: &mut FA,
    fb: &mut FB,
    reps: usize,
    batch: usize,
    rng: &mut Rng,
) where
    FA: FnMut(),
    FB: FnMut(),
{
    // Warm up both kernels before recording anything.
    for _ in 0..3 {
        let _ = time_batch(fa, batch);
        let _ = time_batch(fb, batch);
    }

    let mut ta = Vec::with_capacity(reps);
    let mut tb = Vec::with_capacity(reps);
    for r in 0..reps {
        // Alternate which kernel goes first, so any monotone drift (frequency,
        // cache, host load) is shared rather than attributed to one prototype.
        if r % 2 == 0 {
            ta.push(time_batch(fa, batch) / batch as f64);
            tb.push(time_batch(fb, batch) / batch as f64);
        } else {
            tb.push(time_batch(fb, batch) / batch as f64);
            ta.push(time_batch(fa, batch) / batch as f64);
        }
    }

    let ratios: Vec<f64> = ta.iter().zip(tb.iter()).map(|(x, y)| x / y).collect();
    let mut ratios_for_median = ratios.clone();
    let ratio_median = median(&mut ratios_for_median);
    let mut a_for_median = ta.clone();
    let mut b_for_median = tb.clone();
    let a_median = median(&mut a_for_median);
    let b_median = median(&mut b_for_median);
    // Minimum estimator: interference only adds time, so the per-repetition
    // minimum is robust to a one-sided stall (an alignment/aliasing artifact or
    // host interference), while the median is the primary figure.
    let a_min = ta.iter().cloned().fold(f64::INFINITY, f64::min);
    let b_min = tb.iter().cloned().fold(f64::INFINITY, f64::min);

    // Paired bootstrap over the per-repetition ratios (10,000 resamples).
    const ITERS: usize = 10_000;
    let mut resampled = Vec::with_capacity(ITERS);
    let mut sample = vec![0.0f64; ratios.len()];
    for _ in 0..ITERS {
        for s in sample.iter_mut() {
            *s = ratios[rng.below(ratios.len())];
        }
        resampled.push(median(&mut sample));
    }
    resampled.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let lo = resampled[ITERS * 25 / 1000];
    let hi = resampled[ITERS * 975 / 1000];

    println!(
        "{{\"mode\":\"bench\",\"width\":{},\"pair\":\"{}\",\"reps\":{},\"batch\":{},\
\"a_median_ns\":{:.4},\"b_median_ns\":{:.4},\"ratio_median\":{:.6},\
\"ratio_ci95\":[{:.6},{:.6}],\"a_min_ns\":{:.4},\"b_min_ns\":{:.4},\
\"ratio_min\":{:.6}}}",
        width,
        name,
        reps,
        batch,
        a_median * 1e9,
        b_median * 1e9,
        ratio_median,
        lo,
        hi,
        a_min * 1e9,
        b_min * 1e9,
        a_min / b_min
    );
}

fn bench_width<const N64: usize, const N52: usize, const L64: usize, const LR: usize>(
    width: u32,
    reps: usize,
    batch: usize,
    rng: &mut Rng,
) {
    let base = Setup::<N64, N52, L64, LR>::new(rng);
    let mut s52 = base.clone();
    let mut s52r = base.clone();
    let mut s64f = base.clone();
    let mut s64s = base.clone();

    let mut f52 = move || {
        black_box(s52.run52());
    };
    let mut f52r = move || {
        black_box(s52r.run52r());
    };
    let mut f64f = move || {
        black_box(s64f.run64f());
    };
    let mut f64s = move || {
        black_box(s64s.run64s());
    };

    bench_pair(
        width,
        "52deferred-vs-64fixed",
        &mut f52,
        &mut f64f,
        reps,
        batch,
        rng,
    );
    bench_pair(
        width,
        "52deferred-vs-64slice",
        &mut f52,
        &mut f64s,
        reps,
        batch,
        rng,
    );
    bench_pair(
        width,
        "52rotate-vs-64fixed",
        &mut f52r,
        &mut f64f,
        reps,
        batch,
        rng,
    );
}

fn perf_width<const N64: usize, const N52: usize, const L64: usize, const LR: usize>(
    width: u32,
    kernel: &str,
    ops: usize,
    rng: &mut Rng,
) {
    let mut s = Setup::<N64, N52, L64, LR>::new(rng);
    match kernel {
        "52" => {
            for _ in 0..ops {
                black_box(s.run52());
            }
        }
        "52r" => {
            for _ in 0..ops {
                black_box(s.run52r());
            }
        }
        "64f" => {
            for _ in 0..ops {
                black_box(s.run64f());
            }
        }
        "64s" => {
            for _ in 0..ops {
                black_box(s.run64s());
            }
        }
        other => {
            eprintln!("unknown kernel {other}");
            std::process::exit(2);
        }
    }
    // Keep the setup live for the ops=0 baseline.
    black_box(&s.m[0]);
    println!(
        "{{\"mode\":\"perf\",\"width\":{},\"kernel\":\"{}\",\"ops\":{}}}",
        width, kernel, ops
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut mode = String::from("check");
    let mut width: u32 = 0;
    let mut kernel = String::from("52");
    let mut ops: usize = 0;
    let mut reps: usize = 501;
    let mut batch: usize = 0;

    for arg in &args {
        if let Some((key, value)) = arg.split_once('=') {
            match key {
                "--mode" => mode = value.to_string(),
                "--width" => width = value.parse().unwrap_or(width),
                "--kernel" => kernel = value.to_string(),
                "--ops" => ops = value.parse().unwrap_or(0),
                "--reps" => reps = value.parse().unwrap_or(reps),
                "--batch" => batch = value.parse().unwrap_or(0),
                other => {
                    eprintln!("unknown argument {other}");
                    std::process::exit(2);
                }
            }
        } else if arg == "check" || arg == "bench" || arg == "perf" {
            mode = arg.clone();
        } else {
            eprintln!("unknown argument {arg}");
            std::process::exit(2);
        }
    }

    let mut rng = Rng::new(SEED);
    match mode.as_str() {
        "check" => {
            let s256 = check_width::<4, 5, 6, 8>(256, 6, 10_000, 500, &mut rng);
            let s1024 = check_width::<16, 20, 18, 32>(1024, 4, 2_000, 128, &mut rng);
            let mut failed = false;
            for s in [&s256, &s1024] {
                println!(
                    "{{\"mode\":\"check\",\"width\":{},\"moduli\":{},\"pairs\":{},\"mismatches\":{},\"m64_pair\":{},\"m52_pair\":{},\"m_cross\":{},\"m_oracle\":{},\"oracle_checks\":{},\"noncanonical\":{},\"nc64\":{},\"nc52\":{},\"conversion_failures\":{}}}",
                    s.width,
                    s.moduli,
                    s.pairs,
                    s.mismatches,
                    s.m64_pair,
                    s.m52_pair,
                    s.m_cross,
                    s.m_oracle,
                    s.oracle_checks,
                    s.noncanonical,
                    s.nc64,
                    s.nc52,
                    s.conversion_failures
                );
                if s.mismatches != 0 || s.noncanonical != 0 || s.conversion_failures != 0 {
                    failed = true;
                }
            }
            if failed {
                std::process::exit(2);
            }
        }
        "bench" => {
            let batch256 = if batch == 0 { 2_000 } else { batch };
            bench_width::<4, 5, 6, 8>(256, reps, batch256, &mut rng);
            let batch1024 = if batch == 0 { 200 } else { batch };
            bench_width::<16, 20, 18, 32>(1024, reps, batch1024, &mut rng);
        }
        "perf" => {
            let w = if width == 0 { 256 } else { width };
            match w {
                256 => perf_width::<4, 5, 6, 8>(256, &kernel, ops, &mut rng),
                1024 => perf_width::<16, 20, 18, 32>(1024, &kernel, ops, &mut rng),
                other => {
                    eprintln!("unknown width {other}");
                    std::process::exit(2);
                }
            }
        }
        other => {
            eprintln!("unknown mode {other}");
            std::process::exit(2);
        }
    }
}
