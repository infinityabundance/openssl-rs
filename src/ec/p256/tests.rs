//! PFP-2 engine tests and the per-kernel measurement harness.
//!
//! The differential oracle is the crate's generic `BIGNUM` arithmetic
//! (`bn::limbs`), which is a different implementation of the same mathematics:
//! schoolbook multiply plus Knuth reduction. Agreement with it is bounded
//! differential evidence, not a proof.

use super::*;
use crate::bn::limbs;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn normalised(v: &[Limb]) -> Vec<Limb> {
    let mut v = v.to_vec();
    limbs::normalise(&mut v);
    v
}

fn as_vec(a: &[Limb; LIMBS]) -> Vec<Limb> {
    normalised(a)
}

fn to_array4(v: &[Limb]) -> [Limb; LIMBS] {
    let v = normalised(v);
    assert!(v.len() <= LIMBS, "a reference value wider than four limbs");
    let mut out = [0u64; LIMBS];
    out[..v.len()].copy_from_slice(&v);
    out
}

fn encode<K: FieldKernel<FieldDomain>>(kernel: &K, ordinary: &[Limb; LIMBS]) -> [Limb; LIMBS] {
    let mut repr = [0u64; LIMBS];
    kernel.from_limbs(&mut repr, ordinary);
    repr
}

fn decode<K: FieldKernel<FieldDomain>>(kernel: &K, repr: &[Limb; LIMBS]) -> [Limb; LIMBS] {
    let mut ordinary = [0u64; LIMBS];
    kernel.to_limbs(&mut ordinary, repr);
    ordinary
}

fn oracle_reduce(v: &[Limb], m: &[Limb; LIMBS]) -> Vec<Limb> {
    limbs::rem_fallible(&normalised(v), &as_vec(m)).expect("reference reduction")
}

fn oracle_mul(a: &[Limb; LIMBS], b: &[Limb; LIMBS], m: &[Limb; LIMBS]) -> Vec<Limb> {
    let product = limbs::mul_fallible(&as_vec(a), &as_vec(b)).expect("reference product");
    limbs::rem_fallible(&product, &as_vec(m)).expect("reference reduction")
}

fn oracle_add(a: &[Limb; LIMBS], b: &[Limb; LIMBS], m: &[Limb; LIMBS]) -> Vec<Limb> {
    let sum = limbs::add_fallible(&as_vec(a), &as_vec(b)).expect("reference sum");
    oracle_reduce(&sum, m)
}

fn oracle_sub(a: &[Limb; LIMBS], b: &[Limb; LIMBS], m: &[Limb; LIMBS]) -> Vec<Limb> {
    // a - b mod m = (a + (m - b)) mod m, on reduced operands.
    let a = canonical(a, m);
    let b = canonical(b, m);
    let mb = limbs::sub_fallible(&as_vec(m), &as_vec(&b)).expect("reference negation");
    oracle_add(&a, &to_array4(&mb), m)
}

/// Deterministic pseudo-random limbs (xorshift64), so the sweep is reproducible.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> Limb {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn limbs(&mut self, n: usize) -> Vec<Limb> {
        (0..n).map(|_| self.next()).collect()
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() as usize) % limit
    }
}

fn random_canonical(rng: &mut XorShift, m: &[Limb; LIMBS]) -> [Limb; LIMBS] {
    let v = rng.limbs(LIMBS);
    to_array4(&oracle_reduce(&v, m))
}

fn canonical(v: &[Limb; LIMBS], m: &[Limb; LIMBS]) -> [Limb; LIMBS] {
    to_array4(&oracle_reduce(v, m))
}

/// `R mod m` as four limbs, for the Montgomery reduction's contract check.
fn r_mod(m: &[Limb; LIMBS]) -> [Limb; LIMBS] {
    let mut r = vec![0u64; 5];
    r[4] = 1;
    to_array4(&oracle_reduce(&r, m))
}

/// The adversarial field population the programme's §1b names.
fn field_edge_cases() -> Vec<[Limb; LIMBS]> {
    let p = FIELD_MODULUS;
    let mut p_minus_1 = p;
    p_minus_1[0] -= 1;
    let mut p_minus_2 = p_minus_1;
    p_minus_2[0] -= 1;
    let p_plus_1 = to_array4(&limbs::add_fallible(&as_vec(&p), &[1]).unwrap());
    vec![
        [0; LIMBS],
        [1, 0, 0, 0],
        [2, 0, 0, 0],
        p_minus_2,
        p_minus_1,
        p,
        p_plus_1,
        [Limb::MAX; LIMBS],
        [0, 0, 0, 1 << 63],
        [0, 0, 0, Limb::MAX],
        [
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0x0f0f_0f0f_0f0f_0f0f,
            0xf0f0_f0f0_f0f0_f0f0,
        ],
    ]
}

fn assert_canonical(v: &[Limb; LIMBS], m: &[Limb; LIMBS], what: &str) {
    assert!(
        limbs::cmp(&normalised(v), &as_vec(m)) == core::cmp::Ordering::Less,
        "{what}: not canonical"
    );
}

// ---------------------------------------------------------------------------
// Constants and canonicality
// ---------------------------------------------------------------------------

/// The engine's constants are the curve's, and the Montgomery parameters are
/// derived from them rather than typed values that could drift.
#[test]
fn the_modular_constants_are_consistent() {
    // SAFETY: the prime getter borrows a static; the group is created and
    // released here.
    unsafe {
        let prime = crate::bn::primes::BN_get0_nist_prime_256();
        assert_eq!(&(*prime).d, FIELD_MODULUS.as_slice(), "field modulus");

        let group =
            crate::ec::curve::EC_GROUP_new_by_curve_name(crate::runtime::obj::NID_X9_62_prime256v1);
        assert!(!group.is_null());
        assert_eq!(
            &(*(*group).order).d,
            ORDER_MODULUS.as_slice(),
            "group order"
        );
        assert_eq!(&(*(*group).field).d, FIELD_MODULUS.as_slice(), "field");
        crate::ec::lib::EC_GROUP_free(group);
    }

    assert_eq!(
        FIELD_MODULUS[0].wrapping_mul(FIELD_N0),
        Limb::MAX,
        "p * n0 == -1 mod 2^64"
    );
    assert_eq!(
        ORDER_MODULUS[0].wrapping_mul(ORDER_N0),
        Limb::MAX,
        "q * n0 == -1 mod 2^64"
    );

    // `R^2 mod m` is what the constant claims. `R = 2^256`.
    let mut r = vec![0u64; 5];
    r[4] = 1;
    let two_512 = limbs::mul_fallible(&r, &r).expect("2^512");
    assert_eq!(
        oracle_reduce(&two_512, &FIELD_MODULUS),
        as_vec(&FIELD_R2),
        "R^2 mod p"
    );
    assert_eq!(
        oracle_reduce(&two_512, &ORDER_MODULUS),
        as_vec(&ORDER_R2),
        "R^2 mod q"
    );

    // The Solinas identity: 2^256 == 2^224 - 2^192 - 2^96 + 1 (mod p).
    let mut two_256 = vec![0u64; 5];
    two_256[4] = 1;
    let mut shift = limbs::shl_fallible(&[1u64], 224).expect("2^224");
    shift = limbs::sub_fallible(&shift, &limbs::shl_fallible(&[1u64], 192).unwrap()).unwrap();
    shift = limbs::sub_fallible(&shift, &limbs::shl_fallible(&[1u64], 96).unwrap()).unwrap();
    shift = limbs::add_fallible(&shift, &[1]).unwrap();
    assert_eq!(
        oracle_reduce(&two_256, &FIELD_MODULUS),
        oracle_reduce(&shift, &FIELD_MODULUS),
        "the Solinas relation"
    );
}

/// `from_limbs` reduces arbitrary four-limb input, and `to_limbs` is its
/// inverse on canonical values, for every kernel.
#[test]
fn every_kernel_produces_canonical_residues() {
    let mut rng = XorShift(0x1234_5678_9abc_def0);
    let mut values = field_edge_cases();
    for _ in 0..256 {
        values.push(random_canonical(&mut rng, &FIELD_MODULUS));
    }
    for v in &values {
        let expected = to_array4(&oracle_reduce(v, &FIELD_MODULUS));

        let mont = Mont::<FieldDomain>::default();
        let mut repr = [0u64; LIMBS];
        mont.from_limbs(&mut repr, v);
        let mut back = [0u64; LIMBS];
        mont.to_limbs(&mut back, &repr);
        assert_canonical(&repr, &FIELD_MODULUS, "mont repr");
        assert_eq!(back, expected, "mont round-trip");

        let solinas = Solinas;
        let mut repr = [0u64; LIMBS];
        solinas.from_limbs(&mut repr, v);
        let mut back = [0u64; LIMBS];
        solinas.to_limbs(&mut back, &repr);
        assert_canonical(&repr, &FIELD_MODULUS, "solinas repr");
        assert_eq!(back, expected, "solinas round-trip");

        if let Some(arch) = Arch::new() {
            let mut repr = [0u64; LIMBS];
            arch.from_limbs(&mut repr, v);
            let mut back = [0u64; LIMBS];
            arch.to_limbs(&mut back, &repr);
            assert_eq!(back, expected, "arch round-trip");
        }
    }
}

// ---------------------------------------------------------------------------
// Differential evidence
// ---------------------------------------------------------------------------

fn population() -> Vec<[Limb; LIMBS]> {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let mut values = field_edge_cases();
    for _ in 0..64 {
        values.push(random_canonical(&mut rng, &FIELD_MODULUS));
    }
    values
}

fn check_kernel<K: FieldKernel<FieldDomain>>(label: &str, kernel: &K) {
    let values = population();
    for a in &values {
        let er = encode(kernel, a);
        for b in &values {
            let eb = encode(kernel, b);
            let expects_mul = oracle_mul(a, b, &FIELD_MODULUS);
            let mut got = [0u64; LIMBS];
            kernel.mul(&mut got, &er, &eb);
            assert_canonical(&got, &FIELD_MODULUS, "mul repr");
            let mut dec = [0u64; LIMBS];
            kernel.to_limbs(&mut dec, &got);
            assert_eq!(as_vec(&dec), expects_mul, "{label} mul a={a:?} b={b:?}");

            let mut got = [0u64; LIMBS];
            kernel.add(&mut got, &er, &eb);
            let mut dec = [0u64; LIMBS];
            kernel.to_limbs(&mut dec, &got);
            assert_eq!(
                as_vec(&dec),
                oracle_add(a, b, &FIELD_MODULUS),
                "{label} add a={a:?} b={b:?}"
            );

            let mut got = [0u64; LIMBS];
            kernel.sub(&mut got, &er, &eb);
            let mut dec = [0u64; LIMBS];
            kernel.to_limbs(&mut dec, &got);
            assert_eq!(
                as_vec(&dec),
                oracle_sub(a, b, &FIELD_MODULUS),
                "{label} sub a={a:?} b={b:?} er={er:?} eb={eb:?}"
            );
        }

        let mut got = [0u64; LIMBS];
        kernel.sqr(&mut got, &er);
        assert_canonical(&got, &FIELD_MODULUS, "sqr repr");
        let mut dec = [0u64; LIMBS];
        kernel.to_limbs(&mut dec, &got);
        assert_eq!(
            as_vec(&dec),
            oracle_mul(a, a, &FIELD_MODULUS),
            "{label} sqr"
        );
    }
}

/// Each kernel's `mul`, `sqr`, `add` and `sub` agree with the generic
/// reduction over the adversarial population.
#[test]
fn every_kernel_agrees_with_the_generic_reduction() {
    check_kernel("mont", &Mont::<FieldDomain>::default());
    check_kernel("solinas", &Solinas);
    if let Some(arch) = Arch::new() {
        check_kernel("arch", &arch);
    }
}

/// The reduction kernel alone, over adversarial 512-bit values, a 4096-value
/// pseudorandom sweep and 2048 genuine four-by-four products — the shapes the
/// fold's bounds are argued about.
#[test]
fn every_reduction_matches_the_generic_reduction() {
    let p = FIELD_MODULUS;
    let mut rng = XorShift(0xD1B5_4A32_D192_ED03);

    let mut wides: Vec<Vec<Limb>> = vec![
        Vec::new(),
        vec![0],
        vec![1],
        vec![Limb::MAX; 4],
        vec![Limb::MAX; 8],
        {
            let mut v = vec![0u64; 8];
            v[7] = 1;
            v
        },
        {
            let mut v = vec![0u64; 8];
            v[7] = 1 << 63;
            v
        },
    ];
    // p^2 - 1, p(p-1), (p-1)^2 and 2p-1 are the extremes of the fold's range.
    let p_vec = as_vec(&p);
    let p_minus_1 = limbs::sub_fallible(&p_vec, &[1]).unwrap();
    wides.push(limbs::sub_fallible(&limbs::mul_fallible(&p_vec, &p_vec).unwrap(), &[1]).unwrap());
    wides.push(limbs::mul_fallible(&p_vec, &p_minus_1).unwrap());
    wides.push(limbs::mul_fallible(&p_minus_1, &p_minus_1).unwrap());
    wides.push(limbs::sub_fallible(&limbs::add_fallible(&p_vec, &p_vec).unwrap(), &[1]).unwrap());

    for _ in 0..4096 {
        let width = rng.below(9);
        wides.push(rng.limbs(width));
    }
    for _ in 0..2048 {
        let a = rng.limbs(LIMBS);
        let b = rng.limbs(LIMBS);
        wides.push(limbs::mul_fallible(&a, &b).expect("product"));
    }

    let solinas = Solinas;
    let mont = Mont::<FieldDomain>::default();
    let arch = Arch::new();
    // `Mont::reduce(w)` is the raw REDC value `w·R^-1`, not the Montgomery
    // encoding of `w mod p`; `to_limbs` on that value yields `w·R^-2`.
    let r_inverse = limbs::mod_inverse(&as_vec(&r_mod(&p)), &p_vec).expect("R is invertible");
    let r_inverse = to_array4(&r_inverse);
    let r_inverse_squared = to_array4(&oracle_mul(&r_inverse, &r_inverse, &p));

    let mut checked = 0usize;
    for wide in &wides {
        let mut padded = [0u64; 8];
        assert!(wide.len() <= 8);
        padded[..wide.len()].copy_from_slice(wide);
        let expected = oracle_reduce(wide, &p);

        let mut got = [0u64; LIMBS];
        solinas.reduce(&mut got, &padded);
        assert_canonical(&got, &FIELD_MODULUS, "solinas reduce");
        assert_eq!(as_vec(&got), expected, "solinas reduce");

        // Montgomery's reduction is `wide·R^-1`, so its observation through
        // `to_limbs` is the oracle's `wide mod p` multiplied by `R^-2 mod p`.
        let mut reduced = [0u64; LIMBS];
        mont.reduce(&mut reduced, &padded);
        assert_canonical(&reduced, &FIELD_MODULUS, "mont reduce");
        let mut ordinary = [0u64; LIMBS];
        mont.to_limbs(&mut ordinary, &reduced);
        assert_eq!(
            as_vec(&ordinary),
            oracle_mul(&to_array4(&expected), &r_inverse_squared, &p),
            "mont reduce"
        );

        if let Some(arch) = arch.as_ref() {
            let mut got = [0u64; LIMBS];
            arch.reduce(&mut got, &padded);
            assert_eq!(as_vec(&got), expected, "arch reduce");
        }
        checked += 1;
    }
    assert!(checked >= 4096, "the sweep must cover at least 4096 values");
}

/// The exact eight-limb product, computed into a guarded accumulator.
fn product(a: &[Limb; LIMBS], b: &[Limb; LIMBS]) -> [Limb; 8] {
    let mut acc = SecretWords::<9>::zero();
    wide_mul_into(&mut acc.0, a, b);
    let mut out = [0u64; 8];
    out.copy_from_slice(&acc.0[..8]);
    out
}

/// Squaring is exact for long runs of identical limbs, which is where a
/// symmetric schoolbook expansion loses a doubled cross term. PFP-2 squares with
/// the full product (no symmetry assumption), so the property is by construction;
/// the test still checks every kernel through the public `sqr` entry point.
#[test]
fn squaring_is_exact_for_runs_of_equal_limbs() {
    let runs = [
        0u64,
        1,
        2,
        3,
        Limb::MAX,
        0x8000_0000_0000_0000,
        0x7FFF_FFFF_FFFF_FFFF,
        0x0000_0000_FFFF_FFFF,
        0xFFFF_FFFF_0000_0000,
        0xFFFF_0000_FFFF_0000,
        0x0123_4567_89AB_CDEF,
    ];
    for x in runs {
        let a = [x; LIMBS];
        let expected = oracle_mul(&a, &a, &FIELD_MODULUS);
        let solinas_input = encode(&Solinas, &a);
        let mut got = [0u64; LIMBS];
        Solinas.sqr(&mut got, &solinas_input);
        assert_eq!(as_vec(&decode(&Solinas, &got)), expected, "solinas square");
        let mont_input = encode(&Mont::<FieldDomain>::default(), &a);
        let mut got = [0u64; LIMBS];
        Mont::<FieldDomain>::default().sqr(&mut got, &mont_input);
        assert_eq!(
            as_vec(&decode(&Mont::<FieldDomain>::default(), &got)),
            expected,
            "mont square"
        );
        if let Some(arch) = Arch::new() {
            let arch_input = encode(&arch, &a);
            let mut got = [0u64; LIMBS];
            arch.sqr(&mut got, &arch_input);
            assert_eq!(as_vec(&decode(&arch, &got)), expected, "arch square");
        }
        // The same square through the multiply entry point, so a defect shared
        // only by `sqr` is not hidden.
        let mut via_mul = [0u64; LIMBS];
        Solinas.mul(&mut via_mul, &solinas_input, &solinas_input);
        assert_eq!(
            as_vec(&decode(&Solinas, &via_mul)),
            expected,
            "square through multiply"
        );
    }

    // Equal in runs but not all equal.
    let mut rng = XorShift(0xA5A5_5A5A_1234_9876);
    for _ in 0..1024 {
        let x = rng.next();
        let y = rng.next();
        let a = [x, x, y, y];
        let ea = encode(&Solinas, &a);
        let mut got = [0u64; LIMBS];
        Solinas.sqr(&mut got, &ea);
        assert_eq!(
            as_vec(&decode(&Solinas, &got)),
            oracle_mul(&a, &a, &FIELD_MODULUS)
        );
        let a = [x, y, x, y];
        let ea = encode(&Solinas, &a);
        let mut got = [0u64; LIMBS];
        Solinas.sqr(&mut got, &ea);
        assert_eq!(
            as_vec(&decode(&Solinas, &got)),
            oracle_mul(&a, &a, &FIELD_MODULUS)
        );
    }
}

/// `select` and `cswap` act on a full-width mask and nothing else.
#[test]
fn select_and_cswap_are_masked() {
    let kernel = Solinas;
    let a = [1u64, 2, 3, 4];
    let b = [5u64, 6, 7, 8];
    let mut out = [0u64; LIMBS];
    kernel.select(&mut out, 0, &a, &b);
    assert_eq!(out, b);
    kernel.select(&mut out, Limb::MAX, &a, &b);
    assert_eq!(out, a);

    let mut x = a;
    let mut y = b;
    kernel.cswap(0, &mut x, &mut y);
    assert_eq!((x, y), (a, b));
    kernel.cswap(Limb::MAX, &mut x, &mut y);
    assert_eq!((x, y), (b, a));
    kernel.cswap(Limb::MAX, &mut x, &mut y);
    assert_eq!((x, y), (a, b));
}

// ---------------------------------------------------------------------------
// Types, ownership and cleansing
// ---------------------------------------------------------------------------

/// The field, order and point types keep their domains separate and their
/// canonicality invariants.
#[test]
fn the_field_and_order_domains_stay_separate() {
    let p = FIELD_MODULUS;
    let q = ORDER_MODULUS;

    // `p` is zero in the field; `q` is refused as a secret scalar. No conversion
    // exists between the two types, so the check is behavioural.
    let field = P256Field::<Solinas>::from_be_bytes(&Solinas, &limbs_to_be(&p));
    assert_eq!(field.is_zero_mask(), Limb::MAX, "p is zero modulo p");

    let q_bytes = limbs_to_be(&q);
    assert!(
        P256Scalar::admit_be_bytes(&q_bytes).is_none(),
        "q is refused"
    );
    let mut q_minus_1 = q;
    q_minus_1[0] -= 1;
    let admitted = P256Scalar::admit_be_bytes(&limbs_to_be(&q_minus_1)).expect("q-1 is a scalar");
    assert_eq!(
        admitted.to_canonical().as_limbs(),
        &q_minus_1,
        "q-1 round-trips"
    );

    // A scalar reduced from p has the ordinary value p mod q, not zero.
    let reduced = P256Scalar::from_canonical_reduced(&p);
    assert_eq!(
        as_vec(&to_array4(reduced.to_canonical().as_limbs())),
        oracle_reduce(&p, &q),
        "p mod q"
    );

    // Round-trips through the big-endian ABI representation.
    let value = field_edge_cases()[10];
    let field = P256Field::<Solinas>::from_canonical(&Solinas, &value);
    let bytes = field.to_be_bytes(&Solinas);
    let back = P256Field::<Solinas>::from_be_bytes(&Solinas, bytes.as_bytes());
    assert_eq!(back.to_canonical(&Solinas).as_limbs(), &value);

    // Projective points are built from the field type only.
    let point = P256Projective::infinity(&Solinas);
    assert_eq!(point.z.is_zero_mask(), Limb::MAX, "infinity has z = 0");
    assert_eq!(point.x.is_zero_mask(), Limb::MAX);
}

/// Every secret owner wipes its storage on an early return and during an
/// unwind, not only on the success path.
#[allow(clippy::panic)] // the case exists to exercise `Drop` during unwinding
#[test]
fn secret_storage_is_cleansed_on_every_exit() {
    // Normal drop.
    drop_probe::arm();
    {
        let _owner = SecretLimbs4::new([1, 2, 3, 4]);
    }
    let obs = drop_probe::take().expect("a drop was observed");
    assert_eq!(obs.0, 32, "the whole 32-byte value is cleansed");
    assert_eq!(obs.1, 4, "the value was non-zero before the drop");
    assert!(obs.2, "every byte is zero after the drop");

    // Early return.
    fn early_return() {
        let _owner = SecretLimbs4::new([9, 9, 9, 9]);
        if core::hint::black_box(true) {
            return;
        }
        drop(_owner);
    }
    drop_probe::arm();
    early_return();
    let obs = drop_probe::take().expect("the early return dropped the owner");
    assert!(obs.2, "the early-return path cleanses");

    // Unwind.
    drop_probe::arm();
    let result = std::panic::catch_unwind(|| {
        let _owner = SecretLimbs4::new([7, 7, 7, 7]);
        std::panic::panic_any("deliberate unwind");
    });
    assert!(result.is_err(), "the closure unwound");
    let obs = drop_probe::take().expect("the unwind dropped the owner");
    assert!(obs.2, "the unwind path cleanses");
}

// ---------------------------------------------------------------------------
// The ladder dataflow
// ---------------------------------------------------------------------------

fn ref_mul(a: &[Limb; LIMBS], b: &[Limb; LIMBS]) -> [Limb; LIMBS] {
    to_array4(&oracle_mul(a, b, &FIELD_MODULUS))
}

fn ref_sqr(a: &[Limb; LIMBS]) -> [Limb; LIMBS] {
    ref_mul(a, a)
}

fn ref_add(a: &[Limb; LIMBS], b: &[Limb; LIMBS]) -> [Limb; LIMBS] {
    to_array4(&oracle_add(a, b, &FIELD_MODULUS))
}

fn ref_sub(a: &[Limb; LIMBS], b: &[Limb; LIMBS]) -> [Limb; LIMBS] {
    to_array4(&oracle_sub(a, b, &FIELD_MODULUS))
}

fn ref_double(a: &[Limb; LIMBS]) -> [Limb; LIMBS] {
    ref_add(a, a)
}

/// The authority's step, computed with the generic `BIGNUM` arithmetic.
fn reference_step(
    state: &mut [[Limb; LIMBS]; 4],
    ca: &[Limb; LIMBS],
    cb: &[Limb; LIMBS],
    px: &[Limb; LIMBS],
) {
    let [rx, rz, sx, sz] = state;
    let mut t6 = ref_mul(rx, sx);
    let mut t0 = ref_mul(rz, sz);
    let mut t4 = ref_mul(rx, sz);
    let mut t3 = ref_mul(rz, sx);
    let mut t5 = ref_mul(ca, &t0);
    t5 = ref_add(&t5, &t6);
    t6 = ref_add(&t3, &t4);
    t5 = ref_mul(&t5, &t6);
    t0 = ref_sqr(&t0);
    let mut t2 = *cb;
    t2 = ref_double(&t2);
    t2 = ref_double(&t2);
    t0 = ref_mul(&t0, &t2);
    t5 = ref_double(&t5);
    t3 = ref_sub(&t4, &t3);
    *sz = ref_sqr(&t3);
    t4 = ref_mul(sz, px);
    t0 = ref_add(&t0, &t5);
    *sx = ref_sub(&t0, &t4);
    t4 = ref_sqr(rx);
    t5 = ref_sqr(rz);
    t6 = ref_mul(&t5, ca);
    let mut t1 = ref_add(rx, rz);
    t1 = ref_sqr(&t1);
    t1 = ref_sub(&t1, &t4);
    t1 = ref_sub(&t1, &t5);
    t3 = ref_sub(&t4, &t6);
    t3 = ref_sqr(&t3);
    t0 = ref_mul(&t5, &t1);
    t0 = ref_mul(&t0, &t2);
    *rx = ref_sub(&t3, &t0);
    t3 = ref_add(&t4, &t6);
    t4 = ref_sqr(&t5);
    t4 = ref_mul(&t4, &t2);
    t1 = ref_mul(&t1, &t3);
    t1 = ref_double(&t1);
    *rz = ref_add(&t4, &t1);
}

fn ladder_case<K: FieldKernel<FieldDomain>>(kernel: K, rng: &mut XorShift, label: &str) {
    let neg_three = to_array4(&oracle_sub(&[0; LIMBS], &[3, 0, 0, 0], &FIELD_MODULUS));
    let curve_b = [
        0x3bce_3c3e_27d2_604b,
        0x651d_06b0_cc53_b0f6,
        0xb3eb_bd55_7698_86bc,
        0x5ac6_35d8_aa3a_93e7,
    ];
    let (ca, cb) = if rng.below(2) == 0 {
        (neg_three, canonical(&curve_b, &FIELD_MODULUS))
    } else {
        (
            random_canonical(rng, &FIELD_MODULUS),
            random_canonical(rng, &FIELD_MODULUS),
        )
    };
    let px = random_canonical(rng, &FIELD_MODULUS);
    let state = [
        random_canonical(rng, &FIELD_MODULUS),
        random_canonical(rng, &FIELD_MODULUS),
        random_canonical(rng, &FIELD_MODULUS),
        random_canonical(rng, &FIELD_MODULUS),
    ];
    let mut expected = state;
    reference_step(&mut expected, &ca, &cb, &px);

    let mut ladder = P256Ladder::new(kernel, &ca, &cb, &px);
    ladder.load(&state[0], &state[1], &state[2], &state[3]);
    ladder.step();

    assert_eq!(
        ladder.rx_canonical().as_limbs(),
        &expected[0][..],
        "{label} r->X"
    );
    assert_eq!(
        ladder.rz_canonical().as_limbs(),
        &expected[1][..],
        "{label} r->Z"
    );
    assert_eq!(
        ladder.sx_canonical().as_limbs(),
        &expected[2][..],
        "{label} s->X"
    );
    assert_eq!(
        ladder.sz_canonical().as_limbs(),
        &expected[3][..],
        "{label} s->Z"
    );

    // A second step tracks the reference twice.
    reference_step(&mut expected, &ca, &cb, &px);
    ladder.step();
    assert_eq!(
        ladder.rx_canonical().as_limbs(),
        &expected[0][..],
        "{label} 2 r->X"
    );
    assert_eq!(
        ladder.rz_canonical().as_limbs(),
        &expected[1][..],
        "{label} 2 r->Z"
    );
    assert_eq!(
        ladder.sx_canonical().as_limbs(),
        &expected[2][..],
        "{label} 2 s->X"
    );
    assert_eq!(
        ladder.sz_canonical().as_limbs(),
        &expected[3][..],
        "{label} 2 s->Z"
    );

    // The conditional exchange moves both X/Z pairs and is its own inverse.
    let (rx, rz, sx, sz) = (
        to_array4(ladder.rx_canonical().as_limbs()),
        to_array4(ladder.rz_canonical().as_limbs()),
        to_array4(ladder.sx_canonical().as_limbs()),
        to_array4(ladder.sz_canonical().as_limbs()),
    );
    ladder.cswap(0);
    assert_eq!(to_array4(ladder.rx_canonical().as_limbs()), rx);
    ladder.cswap(1);
    assert_eq!(to_array4(ladder.rx_canonical().as_limbs()), sx);
    assert_eq!(to_array4(ladder.sx_canonical().as_limbs()), rx);
    assert_eq!(to_array4(ladder.rz_canonical().as_limbs()), sz);
    assert_eq!(to_array4(ladder.sz_canonical().as_limbs()), rz);
    ladder.cswap(1);
    assert_eq!(to_array4(ladder.rx_canonical().as_limbs()), rx);
}

/// Each kernel's ladder step agrees with the generic arithmetic, including the
/// curve's own `a = -3` and `b`.
#[test]
fn every_kernel_ladder_step_matches_the_generic_arithmetic() {
    let mut rng = XorShift(0x0BAD_C0DE_DEAD_BEEF);
    for _ in 0..48 {
        ladder_case(Mont::<FieldDomain>::default(), &mut rng, "mont");
        ladder_case(Solinas, &mut rng, "solinas");
        if let Some(arch) = Arch::new() {
            ladder_case(arch, &mut rng, "arch");
        }
    }
}

/// The engine allocates nothing: construction, load, step and swap are all
/// stack-resident, so the ladder's per-bit path cannot abort or fail.
#[test]
fn the_engine_allocates_nothing() {
    use crate::runtime::alloc::test_fail::{tally_start, tally_take};

    let ca = FIELD_MODULUS;
    let cb = [1u64, 0, 0, 0];
    let px = [2u64, 0, 0, 0];
    let state = [[3u64, 0, 0, 0]; 4];

    let guard = tally_start();
    let mut ladder = P256Ladder::new(Solinas, &ca, &cb, &px);
    ladder.load(&state[0], &state[1], &state[2], &state[3]);
    for bit in [0u64, 1, 0, 1] {
        ladder.cswap(bit);
        ladder.step();
    }
    let sites = tally_take();
    drop(guard);
    assert!(
        sites.is_empty(),
        "the engine reached {} allocation sites",
        sites.len()
    );
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// Selection is a function of the public modulus identity and the measured
/// kernel comparison, never of a value; the test-only override is thread-local
/// and restores itself.
#[test]
fn kernel_selection_is_from_public_data_only() {
    assert!(
        matches!(select_field_kernel(), SelectedFieldKernel::Mont(_)),
        "the measured policy selects MONT"
    );

    for id in [KernelId::Mont, KernelId::Solinas] {
        let _guard = test_force::Guard::new(id);
        let selected = select_field_kernel();
        let expected = match id {
            KernelId::Mont => matches!(selected, SelectedFieldKernel::Mont(_)),
            KernelId::Solinas => matches!(selected, SelectedFieldKernel::Solinas(_)),
            KernelId::Arch => false,
        };
        assert!(expected, "the override did not select {id:?}");
    }
    assert!(
        test_force::forced().is_none(),
        "the guard restored the default"
    );
    assert_eq!(FIELD_MODULUS[3], 0xFFFF_FFFF_0000_0001u64);
}

// ---------------------------------------------------------------------------
// Measurement harness
// ---------------------------------------------------------------------------
//
// One process per repetition. The normal test run executes only the cheap smoke
// check at the top; `PFP2_MEASURE=1` turns the process into a measurement run.
// The statistic is the PFP-0 one (median of five batch means), and the paired
// ratios are computed by `courts/performance-frontier/pfp2/analyse_pfp2.py`
// across repetitions, not inside one process.

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite samples"));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

fn batch_ns<F: FnMut() -> u64>(iterations: usize, mut f: F) -> f64 {
    let start = std::time::Instant::now();
    let mut acc = 0u64;
    for _ in 0..iterations {
        acc ^= f();
    }
    let elapsed = start.elapsed().as_nanos() as f64;
    std::hint::black_box(acc);
    elapsed / iterations as f64
}

fn run_op<F: FnMut(usize) -> u64>(
    emit: &mut impl FnMut(&str, &str, f64, &[f64]),
    label: &str,
    op: &str,
    n: usize,
    mut body: F,
) {
    const BATCHES: usize = 5;
    const SWEEPS: usize = 4096;
    let mut samples = Vec::with_capacity(BATCHES);
    for _ in 0..BATCHES {
        let ns = batch_ns(SWEEPS, || {
            let mut acc = 0u64;
            for i in 0..n {
                acc ^= body(i);
            }
            acc
        }) / n as f64;
        samples.push(ns);
    }
    let med = median(samples.clone());
    emit(label, op, med, &samples);
}

fn measure_ops<K: FieldKernel<FieldDomain>>(
    label: &str,
    kernel: &K,
    values: &[[Limb; LIMBS]],
    wide: &[[Limb; 8]],
    emit: &mut impl FnMut(&str, &str, f64, &[f64]),
) {
    let n = values.len();
    run_op(emit, label, "mul", n, |i| {
        let mut out = [0u64; LIMBS];
        kernel.mul(&mut out, &values[i], &values[(i + 1) % n]);
        out[0]
    });
    run_op(emit, label, "sqr", n, |i| {
        let mut out = [0u64; LIMBS];
        kernel.sqr(&mut out, &values[i]);
        out[0]
    });
    run_op(emit, label, "add", n, |i| {
        let mut out = [0u64; LIMBS];
        kernel.add(&mut out, &values[i], &values[(i + 1) % n]);
        out[0]
    });
    run_op(emit, label, "sub", n, |i| {
        let mut out = [0u64; LIMBS];
        kernel.sub(&mut out, &values[i], &values[(i + 1) % n]);
        out[0]
    });
    run_op(emit, label, "reduce", n, |i| {
        let mut out = [0u64; LIMBS];
        kernel.reduce(&mut out, &wide[i]);
        out[0]
    });
}

/// Measure the P-256 ladder through the production entry point with one kernel
/// forced. Returns the median microseconds per multiplication.
fn measure_ladder(id: KernelId) -> Option<f64> {
    use crate::bn::bignum::BigNum;
    use crate::bn::ctx::BN_CTX_new;
    use crate::ec::curve::EC_GROUP_new_by_curve_name;
    use crate::ec::lib::{EC_GROUP_free, EC_POINT_free, EC_POINT_mul, EC_POINT_new};
    use crate::runtime::obj::NID_X9_62_prime256v1;

    const CALLS: usize = 8;
    const BATCHES: usize = 5;

    // SAFETY: every object is created, used and released in this function.
    unsafe {
        let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        assert!(!group.is_null());
        let ctx = BN_CTX_new();
        assert!(!ctx.is_null());
        let r = EC_POINT_new(group);
        assert!(!r.is_null());
        let scalar = BigNum {
            d: vec![
                0x0f1e_2d3c_4b5a_6978,
                0x8796_a5b4_c3d2_e1f0,
                0x1122_3344_5566_7788,
                0x99aa_bbcc_ddee_ff00,
            ],
            neg: 0,
            flags: 0,
        };
        let mut samples = Vec::with_capacity(BATCHES);
        let valid = {
            let _guard = test_force::Guard::new(id);
            let mut ok = true;
            for _ in 0..2 {
                ok &= EC_POINT_mul(
                    group,
                    r,
                    &scalar,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    ctx,
                ) == 1;
            }
            for _ in 0..BATCHES {
                let start = std::time::Instant::now();
                let mut acc = 0u64;
                for _ in 0..CALLS {
                    ok &= EC_POINT_mul(
                        group,
                        r,
                        &scalar,
                        core::ptr::null(),
                        core::ptr::null_mut(),
                        ctx,
                    ) == 1;
                    acc ^= (*(*r).x).d.first().copied().unwrap_or(0);
                }
                std::hint::black_box(acc);
                samples.push(start.elapsed().as_nanos() as f64 / CALLS as f64 / 1000.0);
            }
            ok
        };
        EC_POINT_free(r);
        crate::bn::ctx::BN_CTX_free(ctx);
        EC_GROUP_free(group);
        valid.then(|| median(samples))
    }
}

/// The PFP-2 measurement entry point.
///
/// With `PFP2_MEASURE` unset this is a fast smoke check. With it set, the test
/// measures every kernel in a rotation chosen by `PFP2_MEASURE_REP`, prints
/// `RESULT` lines and appends one raw line per measurement to
/// `PFP2_MEASURE_OUT`.
#[test]
fn pfp2_kernel_measurement() {
    if std::env::var_os("PFP2_MEASURE").is_none() {
        check_kernel("solinas", &Solinas);
        return;
    }

    let rep: u32 = std::env::var("PFP2_MEASURE_REP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let out_path = std::env::var_os("PFP2_MEASURE_OUT");

    let mut rng = XorShift(0x5046_5032_0000_0001);
    let mut values = Vec::with_capacity(64);
    for _ in 0..64 {
        values.push(random_canonical(&mut rng, &FIELD_MODULUS));
    }
    let mut wide = Vec::with_capacity(64);
    for i in 0..64 {
        wide.push(product(&values[i], &values[(i + 1) % 64]));
    }

    let mut lines: Vec<String> = Vec::new();
    {
        let mut emit = |label: &str, op: &str, med: f64, samples: &[f64]| {
            let raw = samples
                .iter()
                .map(|v| format!("{v:.3}"))
                .collect::<Vec<_>>()
                .join(",");
            println!("RESULT\t{label}\t{op}\t{med:.3}\t{raw}\trep={rep}\tunit=ns_per_op");
            lines.push(format!("{rep}\t{label}\t{op}\t{med:.3}\t{raw}"));
        };

        // Balanced rotation: the kernel measured first moves with the repetition
        // so a drift shared by all kernels cancels in the paired ratio.
        let mut order = vec!["MONT", "SOLINAS"];
        if Arch::new().is_some() {
            order.push("ARCH");
        }
        let width = order.len();
        order.rotate_left((rep as usize) % width);

        for label in order {
            match label {
                "MONT" => measure_ops(
                    "MONT",
                    &Mont::<FieldDomain>::default(),
                    &values,
                    &wide,
                    &mut emit,
                ),
                "SOLINAS" => measure_ops("SOLINAS", &Solinas, &values, &wide, &mut emit),
                "ARCH" => {
                    if let Some(arch) = Arch::new() {
                        measure_ops("ARCH", &arch, &values, &wide, &mut emit);
                    }
                }
                _ => {}
            }
        }

        for (id, label) in [
            (KernelId::Mont, "MONT"),
            (KernelId::Solinas, "SOLINAS"),
            (KernelId::Arch, "ARCH"),
        ] {
            if id == KernelId::Arch && Arch::new().is_none() {
                continue;
            }
            if let Some(us) = measure_ladder(id) {
                println!("RESULT\t{label}\tladder\t{us:.3}\trep={rep}\tunit=us_per_call");
                lines.push(format!("{rep}\t{label}\tladder\t{us:.3}\t{us:.3}"));
            }
        }
    }

    if let Some(path) = out_path {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open the measurement output");
        for line in &lines {
            writeln!(file, "{line}").expect("write the measurement output");
        }
    }
}

/// PFP-20: the declassification boundary emits exactly the `normalise`d
/// representation for every shape the engine can write — including coordinates
/// whose top limb is zero — so replacing the loop trim with the branchless one
/// preserved the exported `BIGNUM`, it did not introduce a new representation.
#[test]
fn the_declassification_boundary_preserves_the_normalised_bignum() {
    use crate::bn::bignum::{BN_free, BN_new};

    let cases: [[Limb; LIMBS]; 7] = [
        [0, 0, 0, 0],
        [0x0123_4567_89ab_cdef, 0, 0, 0],
        [0x1111_1111_1111_1111, 0x2222_2222_2222_2222, 0, 0],
        [1, 2, 3, 0],
        [1, 2, 3, 4],
        [0, 0, 0, 1],
        [Limb::MAX, 0, 0, 0],
    ];

    for case in cases {
        let mut want = case.to_vec();
        limbs::normalise(&mut want);

        // SAFETY: `bn` is a fresh, uniquely-owned `BIGNUM`; `canonical` is a live
        // engine value; the boundary writes only into `bn`.
        unsafe {
            let bn = BN_new();
            assert!(!bn.is_null());
            let canonical = Canonical4(case);
            assert!(
                crate::ec::smpl::declassify_coordinate(bn, &canonical),
                "boundary refused {case:?}"
            );
            assert_eq!((*bn).d, want, "magnitude for {case:?}");
            assert_eq!((*bn).neg, 0, "sign for {case:?}");
            BN_free(bn);
        }
    }
}
