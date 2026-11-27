//! PFP-10 divstep tests: correctness differential, convergence bound, ctgrind and
//! the three-candidate measurement.

use super::*;
use crate::bn::limbs;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn limbs(&mut self, w: usize) -> Vec<Limb> {
        (0..w).map(|_| self.next()).collect()
    }
}

fn from_be(bytes: &[u8]) -> Vec<Limb> {
    let mut out: Vec<Limb> = vec![0];
    for &byte in bytes {
        let mut carry = byte as u64;
        for limb in out.iter_mut() {
            let t = ((*limb as u128) << 8) | carry as u128;
            *limb = t as u64;
            carry = (t >> 64) as u64;
        }
        if carry != 0 {
            out.push(carry);
        }
    }
    limbs::normalise(&mut out);
    out
}

fn reduce(v: &[Limb], m: &[Limb]) -> Vec<Limb> {
    let mut r = limbs::rem(v, m);
    limbs::normalise(&mut r);
    r
}

fn sub_small(m: &[Limb], d: Limb) -> Vec<Limb> {
    let mut out = m.to_vec();
    let mut borrow = d;
    for limb in out.iter_mut() {
        let (v, b) = limb.overflowing_sub(borrow);
        *limb = v;
        borrow = Limb::from(b);
        if borrow == 0 {
            break;
        }
    }
    limbs::normalise(&mut out);
    out
}

fn add_small(m: &[Limb], addend: Limb) -> Option<Vec<Limb>> {
    let mut out = m.to_vec();
    let mut carry = addend;
    for limb in out.iter_mut() {
        let (v, c) = limb.overflowing_add(carry);
        *limb = v;
        carry = Limb::from(c);
        if carry == 0 {
            break;
        }
    }
    if carry != 0 {
        return None;
    }
    Some(out)
}

fn canonical_eq(a: &[Limb], b: &[Limb]) -> bool {
    let (mut x, mut y) = (a.to_vec(), b.to_vec());
    limbs::normalise(&mut x);
    limbs::normalise(&mut y);
    x == y
}

const FIELD: [Limb; 4] = crate::ec::p256::FIELD_MODULUS;
const ORDER: [Limb; 4] = crate::ec::p256::ORDER_MODULUS;

fn dh_1024() -> Vec<Limb> {
    from_be(&crate::bn::dh_data::OSSL_BIGNUM_DH1024_160_P_BYTES)
}

fn dh_2048() -> Vec<Limb> {
    from_be(&crate::bn::dh_data::OSSL_BIGNUM_DH2048_256_P_BYTES)
}

fn exponent_minus_two(m: &[Limb]) -> Vec<Limb> {
    sub_small(m, 2)
}

use crate::ec::p256::{FieldDomain, Mont, P256Field, P256Scalar};

fn field_fermat(a: &[Limb]) -> Vec<Limb> {
    let kernel = Mont::<FieldDomain>::default();
    let mut ordinary = [0u64; 4];
    for (o, &limb) in ordinary.iter_mut().zip(a.iter()) {
        *o = limb;
    }
    let x = P256Field::<Mont<FieldDomain>>::from_canonical(&kernel, &ordinary);
    let inv = crate::ec::p256::fixed_base::invert(&kernel, &x);
    inv.to_canonical(&kernel).as_limbs().to_vec()
}

fn order_fermat(a: &[Limb]) -> Vec<Limb> {
    let mut ordinary = [0u64; 4];
    for (o, &limb) in ordinary.iter_mut().zip(a.iter()) {
        *o = limb;
    }
    let scalar = P256Scalar::from_canonical_reduced(&ordinary);
    scalar.invert().to_canonical().as_limbs().to_vec()
}

fn generic_fermat(a: &[Limb], m: &[Limb], e: &[Limb]) -> Vec<Limb> {
    let mut r = crate::bn::arith::mod_exp_core_consttime(a, e, m).expect("ladder allocation");
    limbs::normalise(&mut r);
    r
}

/// Build the PFP-10 edge population for one modulus: `1`, `2`, `m-1`, `m-2`,
/// each single-non-zero-limb value, top-limb-zero values, non-canonical values,
/// zero and pseudorandom values.
fn population(rng: &mut Rng, m: &[Limb], random_cases: usize) -> Vec<Vec<Limb>> {
    let w = m.len();
    let mut out = vec![vec![1], vec![2], sub_small(m, 1), sub_small(m, 2)];
    for i in 0..w {
        let mut v = vec![0u64; i + 1];
        v[i] = 0x9E37_79B9_7F4A_7C15 | 1;
        out.push(reduce(&v, m));
    }
    for _ in 0..4 {
        let mut v = rng.limbs(w);
        v[w - 1] = 0;
        out.push(reduce(&v, m));
    }
    for t in [0u64, 1, 2, 12_345] {
        if let Some(v) = add_small(m, t) {
            if v.len() <= w {
                out.push(v);
            }
        }
    }
    out.push(Vec::new());
    for _ in 0..random_cases {
        out.push(reduce(&rng.limbs(w), m));
    }
    out
}

// ---------------------------------------------------------------------------
// Small-domain exhaustive correctness
// ---------------------------------------------------------------------------

#[test]
fn small_odd_moduli_match_the_oracle() {
    let mut compared = 0usize;
    let mut non_invertible = 0usize;
    for m in (3u64..600).step_by(2) {
        let modulus = vec![m];
        for a in 0..m {
            let input = if a == 0 { Vec::new() } else { vec![a] };
            let oracle = limbs::mod_inverse(&input, &modulus);
            let (coefficient, invertible) =
                mod_inverse_divstep_with_mask(&input, &modulus).expect("odd modulus");
            match oracle {
                Some(expected) => {
                    assert_ne!(invertible, 0, "m={m} a={a} should invert");
                    assert!(
                        canonical_eq(&coefficient, &expected),
                        "m={m} a={a}: divstep {coefficient:?} != oracle {expected:?}"
                    );
                    compared += 1;
                }
                None => {
                    assert_eq!(invertible, 0, "m={m} a={a} must report no inverse");
                    non_invertible += 1;
                }
            }
        }
    }
    assert!(
        compared > 40_000,
        "only {compared} invertible pairs exercised"
    );
    assert!(non_invertible > 0);
}

#[test]
fn zero_and_non_invertible_behaviour() {
    // Zero modulo a prime: the Fermat path maps 0 to 0. The divstep coefficient is
    // 0 and the mask reports the gcd is not one, matching the binary GCD's mask.
    let order = ORDER.to_vec();
    let (coefficient, mask) = mod_inverse_divstep_with_mask(&[], &order).expect("odd modulus");
    assert_eq!(mask, 0, "zero is not invertible");
    assert!(
        coefficient.iter().all(|&limb| limb == 0),
        "coefficient is zero"
    );
    assert!(canonical_eq(&order_fermat(&[0u64; 4]), &[0u64]));
    assert!(mod_inverse_divstep(&[], &order).is_none());

    // A composite modulus with a shared factor: both the mask and the companion
    // entry point must report failure, and the oracle must agree.
    let p = vec![0xffff_ffff_ffff_ff61u64, 0xffff_ffff_ffff_ffff];
    let q = vec![0xffff_ffff_ffff_ff53u64, 0xffff_ffff_ffff_ffff];
    let composite = limbs::mul(&p, &q);
    let shared = vec![0xffff_ffff_ffff_ff61u64, 0xffff_ffff_ffff_ffff];
    let (_, mask) = mod_inverse_divstep_with_mask(&shared, &composite).expect("odd");
    assert_eq!(mask, 0, "a shared factor is not invertible");
    assert!(mod_inverse_divstep(&shared, &composite).is_none());
    assert!(limbs::mod_inverse(&shared, &composite).is_none());

    // An even modulus is outside the domain: a property of the modulus alone.
    assert!(mod_inverse_divstep_with_mask(&[1], &[4]).is_none());
    assert!(mod_inverse_divstep_with_mask(&[], &[]).is_none());
}

// ---------------------------------------------------------------------------
// Edge and random differential over the four PFP-10 domains
// ---------------------------------------------------------------------------

struct Counts {
    cases: usize,
    non_canonical: usize,
    fermat_agree: usize,
    round_trips: usize,
    mismatches: usize,
}

fn differential_prime<F>(
    label: &str,
    m: &[Limb],
    fermat: F,
    random_cases: usize,
    seed: u64,
) -> Counts
where
    F: Fn(&[Limb]) -> Vec<Limb>,
{
    let mut rng = Rng::new(seed);
    let inputs = population(&mut rng, m, random_cases);
    let mut c = Counts {
        cases: 0,
        non_canonical: 0,
        fermat_agree: 0,
        round_trips: 0,
        mismatches: 0,
    };
    for input in &inputs {
        let canonical = reduce(input, m);
        if input.len() > canonical.len() || !canonical_eq(input, &canonical) {
            c.non_canonical += 1;
        }
        c.cases += 1;
        let (div, mask) = mod_inverse_divstep_with_mask(&canonical, m).expect("modulus is odd");
        let oracle = limbs::mod_inverse(&canonical, m);
        let ferm = fermat(&canonical);
        if canonical.is_empty() {
            // Documented Fermat semantics: 0^(m-2) = 0. The mask says the gcd is
            // not one and the coefficient is 0.
            if mask != 0 || div.iter().any(|&l| l != 0) || !canonical_eq(&ferm, &[]) {
                eprintln!(
                    "MISMATCH {label} zero input={input:?} mask={mask} div={div:?} fermat={ferm:?}"
                );
                c.mismatches += 1;
            }
            continue;
        }
        let Some(expected) = oracle else {
            // The modulus is prime, so this can only be a zero-like input; kept
            // as a hard mismatch rather than silently skipped.
            c.mismatches += 1;
            continue;
        };
        if mask == 0 || !canonical_eq(&div, &expected) {
            eprintln!("MISMATCH {label} input={input:?} canonical={canonical:?} mask={mask} div={div:?} oracle={expected:?}");
            c.mismatches += 1;
            continue;
        }
        if canonical_eq(&ferm, &expected) {
            c.fermat_agree += 1;
        } else {
            c.mismatches += 1;
        }
        let product = limbs::mul(&canonical, &div);
        if canonical_eq(&reduce(&product, m), &[1]) {
            c.round_trips += 1;
        } else {
            c.mismatches += 1;
        }
    }
    println!(
        "DIFFERENTIAL {label} cases={} non_canonical={} fermat_agree={} round_trips={} mismatches={}",
        c.cases, c.non_canonical, c.fermat_agree, c.round_trips, c.mismatches
    );
    c
}

fn differential_composite(label: &str, m: &[Limb], random_cases: usize, seed: u64) -> Counts {
    let mut rng = Rng::new(seed);
    let inputs = population(&mut rng, m, random_cases);
    let mut c = Counts {
        cases: 0,
        non_canonical: 0,
        fermat_agree: 0,
        round_trips: 0,
        mismatches: 0,
    };
    for input in &inputs {
        let canonical = reduce(input, m);
        c.cases += 1;
        let (div, mask) = mod_inverse_divstep_with_mask(&canonical, m).expect("modulus is odd");
        let oracle = limbs::mod_inverse(&canonical, m);
        match oracle {
            Some(expected) => {
                if mask == 0 || !canonical_eq(&div, &expected) {
                    c.mismatches += 1;
                    continue;
                }
                let product = limbs::mul(&canonical, &div);
                if canonical_eq(&reduce(&product, m), &[1]) {
                    c.round_trips += 1;
                } else {
                    c.mismatches += 1;
                }
            }
            None => {
                if mask != 0 {
                    c.mismatches += 1;
                }
            }
        }
    }
    println!(
        "DIFFERENTIAL {label} cases={} non_canonical={} round_trips={} mismatches={}",
        c.cases, c.non_canonical, c.round_trips, c.mismatches
    );
    c
}

#[test]
fn differential_edge_population() {
    let field = FIELD.to_vec();
    let order = ORDER.to_vec();
    let p1024 = dh_1024();
    let p2048 = dh_2048();
    let e1024 = exponent_minus_two(&p1024);
    let e2048 = exponent_minus_two(&p2048);

    let results = vec![
        differential_prime("p256-field", &field, field_fermat, 24, 0x5046_500A_0001),
        differential_prime("p256-order", &order, order_fermat, 24, 0x5046_500A_0002),
        differential_prime(
            "modp-1024",
            &p1024,
            |a| generic_fermat(a, &p1024, &e1024),
            16,
            0x5046_500A_0003,
        ),
        differential_prime(
            "modp-2048",
            &p2048,
            |a| generic_fermat(a, &p2048, &e2048),
            8,
            0x5046_500A_0004,
        ),
    ];
    for c in &results {
        assert_eq!(c.mismatches, 0, "a single mismatch is a STOP");
        assert_eq!(c.fermat_agree, c.round_trips);
    }
}

/// The large population. Run explicitly:
/// `cargo test --lib -- --ignored pfp10_large_differential --nocapture`.
#[test]
#[ignore]
fn pfp10_large_differential() {
    let field = FIELD.to_vec();
    let order = ORDER.to_vec();
    let p1024 = dh_1024();
    let p2048 = dh_2048();
    let e1024 = exponent_minus_two(&p1024);
    let e2048 = exponent_minus_two(&p2048);

    let results = [
        differential_prime("p256-field", &field, field_fermat, 2048, 0x5046_500B_0001),
        differential_prime("p256-order", &order, order_fermat, 2048, 0x5046_500B_0002),
        differential_prime(
            "modp-1024",
            &p1024,
            |a| generic_fermat(a, &p1024, &e1024),
            1024,
            0x5046_500B_0003,
        ),
        differential_prime(
            "modp-2048",
            &p2048,
            |a| generic_fermat(a, &p2048, &e2048),
            512,
            0x5046_500B_0004,
        ),
    ];
    let total: usize = results.iter().map(|c| c.cases).sum();
    let mismatches: usize = results.iter().map(|c| c.mismatches).sum();
    println!("DIFFERENTIAL TOTAL cases={total} mismatches={mismatches}");
    assert_eq!(mismatches, 0, "a single mismatch is a STOP");

    // A composite modulus with non-invertible inputs, at both 256 and 2048 bits.
    let p = vec![0xffff_ffff_ffff_ff61u64, 0xffff_ffff_ffff_ffff];
    let q = vec![0xffff_ffff_ffff_ff53u64, 0xffff_ffff_ffff_ffff];
    let composite = limbs::mul(&p, &q);
    let c = differential_composite("composite-256", &composite, 512, 0x5046_500B_0005);
    assert_eq!(c.mismatches, 0);
}

// ---------------------------------------------------------------------------
// The bound
// ---------------------------------------------------------------------------

#[test]
fn iteration_bounds_are_the_published_half_delta_values() {
    assert_eq!(iteration_bound(4), Some(591));
    assert_eq!(iteration_bound(16), Some(2360));
    assert_eq!(iteration_bound(32), Some(4718));
}

#[test]
fn realised_steps_are_within_the_bound() {
    let mut rng = Rng::new(0x5046_500C);
    let mut worst: f64 = 0.0;
    for w in [4usize, 5, 8, 16] {
        // Odd moduli of the full width, top bit set.
        let mut m = rng.limbs(w);
        m[0] |= 1;
        m[w - 1] |= 1 << 63;
        let bound = iteration_bound(w).expect("bound");
        for _ in 0..64 {
            let a = reduce(&rng.limbs(w), &m);
            let steps = convergence_steps(&a, &m, bound + 1).expect("terminates within bound+1");
            assert!(
                steps <= bound,
                "w={w}: {steps} steps exceeds the bound {bound}"
            );
            worst = worst.max(steps as f64 / bound as f64);
        }
    }
    println!("CONVERGENCE worst_fraction_of_bound={worst:.4}");
}

// ---------------------------------------------------------------------------
// ctgrind: no branch on the secret operand
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[test]
fn ctgrind_secret_mod_inverse_divstep() {
    let order = ORDER.to_vec();
    let mut a = reduce(
        &[
            0x0123_4567_89ab_cdef_u64,
            0x1122_3344_5566_7788,
            0x99aa_bbcc_ddee_ff00,
            0x0fed_cba9_8765_4321,
        ],
        &order,
    );
    if a.is_empty() {
        a = vec![3];
    }
    let a_plain = a.clone();

    // SAFETY: `a` is a live, uniquely borrowed buffer and the client request only
    // marks its bytes' definedness.
    unsafe {
        valgrind_make_mem_undefined(a.as_mut_ptr().cast::<u8>(), a.len() * 8);
    }
    if std::env::var_os("CTGRIND_CONTROL").is_some() {
        // Negative control: memcheck must flag this branch on a marked limb. The
        // limb is read with a volatile load (so the optimiser cannot reuse a
        // pre-taint value) and the taken arm performs a volatile store (so the
        // branch cannot be if-converted).
        let mut acc = 0u64;
        let slot = &mut acc as *mut u64;
        let base = a.as_ptr();
        for i in 0..a.len() {
            // SAFETY: `base` points at the live `a` buffer and `i < a.len()`.
            let limb = unsafe { base.add(i).read_volatile() };
            if core::hint::black_box(limb & 1) == 1 {
                // SAFETY: `slot` points at the live local `acc`; a volatile write
                // of a `u64` is in bounds.
                unsafe {
                    slot.write_volatile(slot.read_volatile().wrapping_add(1));
                }
            }
        }
        core::hint::black_box(acc);
    }

    let (mut inverse, mut mask) = mod_inverse_divstep_with_mask(&a, &order).expect("odd modulus");
    // SAFETY: both are live, uniquely borrowed locals; mark them defined for the
    // assertions only, so the case covers the algorithm and not the caller's
    // authorised decision.
    unsafe {
        valgrind_make_mem_defined(inverse.as_mut_ptr().cast::<u8>(), inverse.len() * 8);
        valgrind_make_mem_defined((&mut mask as *mut u64).cast::<u8>(), 8);
    }
    assert_ne!(mask, 0, "the operand is a non-zero residue modulo a prime");
    assert!(canonical_eq(
        &reduce(&limbs::mul(&a_plain, &inverse), &order),
        &[1]
    ));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn ctgrind_secret_mod_inverse_divstep_1024() {
    // The same taint case at 1024 bits: if the reported contexts scale with the
    // 2360-step bound rather than staying at the 591-step count, the transfer is
    // inside the divstep loop.
    let m = dh_1024();
    let mut a = reduce(&Rng::new(0x5046_500E).limbs(m.len()), &m);
    if a.is_empty() {
        a = vec![3];
    }
    let a_plain = a.clone();

    // SAFETY: `a` is a live, uniquely borrowed buffer and the client request only
    // marks its bytes' definedness.
    unsafe {
        valgrind_make_mem_undefined(a.as_mut_ptr().cast::<u8>(), a.len() * 8);
    }
    let (mut inverse, mut mask) = mod_inverse_divstep_with_mask(&a, &m).expect("odd modulus");
    // SAFETY: both are live, uniquely borrowed locals; mark them defined for the
    // assertions only.
    unsafe {
        valgrind_make_mem_defined(inverse.as_mut_ptr().cast::<u8>(), inverse.len() * 8);
        valgrind_make_mem_defined((&mut mask as *mut u64).cast::<u8>(), 8);
    }
    assert_ne!(mask, 0);
    assert!(canonical_eq(
        &reduce(&limbs::mul(&a_plain, &inverse), &m),
        &[1]
    ));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn ctgrind_control_canary() {
    // Standalone positive control for the instrument: a volatile-read,
    // volatile-store branch on a limb marked undefined must be reported by
    // memcheck. If this test reports zero contexts, the detector cannot see the
    // canary and the absence of findings elsewhere is not evidence.
    let mut a = vec![0xdead_beefu64, 1, 2, 3];
    // SAFETY: `a` is a live, uniquely borrowed buffer; the request only marks it.
    unsafe {
        valgrind_make_mem_undefined(a.as_mut_ptr().cast::<u8>(), a.len() * 8);
    }
    let mut acc = 0u64;
    let slot = &mut acc as *mut u64;
    let base = a.as_ptr();
    for i in 0..a.len() {
        // SAFETY: `base` points at the live `a` buffer and `i < a.len()`.
        let limb = unsafe { base.add(i).read_volatile() };
        if core::hint::black_box(limb & 1) == 1 {
            // SAFETY: `slot` points at the live local `acc`.
            unsafe {
                slot.write_volatile(slot.read_volatile().wrapping_add(1));
            }
        }
    }
    // SAFETY: `slot` is live; declassify only for the assertion.
    unsafe {
        valgrind_make_mem_defined(slot.cast::<u8>(), 8);
    }
    assert!(acc <= 4);
}

#[cfg(target_arch = "x86_64")]
unsafe fn valgrind_make_mem_undefined(addr: *mut u8, len: usize) {
    let args: [usize; 6] = [0x4D43_0001, addr as usize, len, 0, 0, 0];
    let _result: usize;
    // SAFETY: the sequence is the documented valgrind client-request pattern;
    // `args` lives for the duration of the asm and is only read.
    unsafe {
        core::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            in("rax") args.as_ptr(),
            inout("rdx") 0usize => _result,
            out("rdi") _,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn valgrind_make_mem_defined(addr: *mut u8, len: usize) {
    let args: [usize; 6] = [0x4D43_0002, addr as usize, len, 0, 0, 0];
    let _result: usize;
    // SAFETY: as `valgrind_make_mem_undefined`; this only marks definedness.
    unsafe {
        core::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            in("rax") args.as_ptr(),
            inout("rdx") 0usize => _result,
            out("rdi") _,
            options(nostack, preserves_flags)
        );
    }
}

// ---------------------------------------------------------------------------
// PFP-10 measurement: three candidates, four domains, interleaved repetitions
// ---------------------------------------------------------------------------

fn batch_ns<F: FnMut(usize) -> u64>(iterations: usize, width: usize, mut f: F) -> f64 {
    let start = std::time::Instant::now();
    let mut acc = 0u64;
    for k in 0..iterations {
        acc ^= f(k % width);
    }
    let elapsed = start.elapsed().as_nanos() as f64;
    std::hint::black_box(acc);
    elapsed / iterations as f64
}

fn inputs(rng: &mut Rng, m: &[Limb], n: usize) -> Vec<Vec<Limb>> {
    (0..n).map(|_| reduce(&rng.limbs(m.len()), m)).collect()
}

fn checksum(v: &[Limb]) -> u64 {
    v.iter().fold(0u64, |a, &b| a.rotate_left(7) ^ b)
}

struct Emit {
    out: String,
    sink: Option<std::path::PathBuf>,
}

impl Emit {
    fn row(&mut self, domain: &str, size: usize, candidate: &str, rep: usize, ns: f64) {
        self.out
            .push_str(&format!("{domain}\t{size}\t{candidate}\t{rep}\t{ns:.3}\n"));
    }

    fn finish(self) {
        if let Some(path) = self.sink {
            std::fs::write(path, self.out).expect("write raw samples");
        }
    }
}

#[test]
#[ignore]
fn pfp10_bench() {
    const REPS: usize = 15;
    let sink = std::env::var_os("PFP10_RAW").map(std::path::PathBuf::from);
    let mut emit = Emit {
        out: String::new(),
        sink,
    };

    let mut rng = Rng::new(0x5046_500D);

    // 256-bit field and order.
    for (domain, modulus) in [
        ("p256-field", FIELD.to_vec()),
        ("p256-order", ORDER.to_vec()),
    ] {
        let m = modulus;
        let xs = inputs(&mut rng, &m, 32);
        if domain == "p256-field" {
            bench_case(
                &mut emit,
                domain,
                256,
                &xs,
                128,
                REPS,
                |i| checksum(&field_fermat(&xs[i])),
                |i| {
                    checksum(
                        &limbs::mod_inverse_consttime_with_mask(&xs[i], &m)
                            .expect("odd")
                            .0,
                    )
                },
                |i| checksum(&mod_inverse_divstep_with_mask(&xs[i], &m).expect("odd").0),
            );
        } else {
            bench_case(
                &mut emit,
                domain,
                256,
                &xs,
                128,
                REPS,
                |i| checksum(&order_fermat(&xs[i])),
                |i| {
                    checksum(
                        &limbs::mod_inverse_consttime_with_mask(&xs[i], &m)
                            .expect("odd")
                            .0,
                    )
                },
                |i| checksum(&mod_inverse_divstep_with_mask(&xs[i], &m).expect("odd").0),
            );
        }
    }

    // 1024-bit and 2048-bit moduli, generic Fermat ladder.
    for (domain, size, m, iters) in [
        ("modp-1024", 1024, dh_1024(), 24usize),
        ("modp-2048", 2048, dh_2048(), 8usize),
    ] {
        let e = exponent_minus_two(&m);
        let xs = inputs(&mut rng, &m, 8);
        let m2 = m.clone();
        bench_case(
            &mut emit,
            domain,
            size,
            &xs,
            iters,
            REPS,
            |i| checksum(&generic_fermat(&xs[i], &m, &e)),
            |i| {
                checksum(
                    &limbs::mod_inverse_consttime_with_mask(&xs[i], &m2)
                        .expect("odd")
                        .0,
                )
            },
            |i| checksum(&mod_inverse_divstep_with_mask(&xs[i], &m2).expect("odd").0),
        );
    }

    // 521 bits (the Mersenne prime 2^521 - 1) brackets the Fermat/divstep
    // crossover between the 256-bit P-256 domains and the 1024-bit modulus.
    {
        let mut m = vec![u64::MAX; 8];
        m.push(0x1ff);
        let e = exponent_minus_two(&m);
        let xs = inputs(&mut rng, &m, 8);
        let m2 = m.clone();
        bench_case(
            &mut emit,
            "m521",
            521,
            &xs,
            48,
            REPS,
            |i| checksum(&generic_fermat(&xs[i], &m, &e)),
            |i| {
                checksum(
                    &limbs::mod_inverse_consttime_with_mask(&xs[i], &m2)
                        .expect("odd")
                        .0,
                )
            },
            |i| checksum(&mod_inverse_divstep_with_mask(&xs[i], &m2).expect("odd").0),
        );
    }

    emit.finish();
}

#[allow(clippy::too_many_arguments)]
fn bench_case<FF, FG, FD>(
    emit: &mut Emit,
    domain: &str,
    size: usize,
    xs: &[Vec<Limb>],
    iterations: usize,
    reps: usize,
    fermat: FF,
    gcd: FG,
    divstep: FD,
) where
    FF: Fn(usize) -> u64,
    FG: Fn(usize) -> u64,
    FD: Fn(usize) -> u64,
{
    let width = xs.len();
    // Warm-up: one batch per candidate, not recorded.
    std::hint::black_box(batch_ns(iterations, width, &fermat));
    std::hint::black_box(batch_ns(iterations, width, &gcd));
    std::hint::black_box(batch_ns(iterations, width, &divstep));
    for rep in 0..reps {
        for slot in 0..3 {
            let which = (slot + rep) % 3;
            let ns = match which {
                0 => batch_ns(iterations, width, &fermat),
                1 => batch_ns(iterations, width, &gcd),
                _ => batch_ns(iterations, width, &divstep),
            };
            let name = match which {
                0 => "fermat",
                1 => "gcd",
                _ => "divstep",
            };
            emit.row(domain, size, name, rep, ns);
        }
    }
}
