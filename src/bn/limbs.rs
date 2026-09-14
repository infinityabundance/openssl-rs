//! Phase 5 — the limb arithmetic under `BIGNUM`.
//!
//! Pure integer arithmetic on little-endian `u64` limbs. No FFI, no OpenSSL
//! types: the arithmetic is the part that must be *provably* right, and keeping it
//! separable is what lets the unit tests below exercise it without an authority, a
//! court or a `BIGNUM`.
//!
//! ## Representation
//!
//! A value is a `Vec<u64>`, least significant limb first, with **no trailing zero
//! limbs**, so zero is the empty slice. Every function here preserves that
//! invariant; `normalise` establishes it after any operation that can violate it.
//!
//! `BIGNUM` is opaque to callers of the authority (`include/openssl/bn.h` declares
//! `typedef struct bignum_st BIGNUM;` and defines nothing), so this representation
//! is ours. It is not part of the ABI, and the ABI layout court does not constrain
//! it — that court's 158 types contain no `BN` type, which was checked rather than
//! assumed.
//!
//! ## Overflow
//!
//! The release profile enables `overflow-checks`, on the grounds that courts must
//! be able to reason about overflow. Arithmetic that is *expected* to wrap says so
//! with `wrapping_*`, so a genuine overflow is still a panic rather than a silent
//! wrong answer.
//!
//! ## Provenance
//!
//! The algorithms are the standard published ones — schoolbook multiplication,
//! Knuth's Algorithm D for division (`TAOCP` volume 2, 4.3.1), the binary GCD, the
//! extended Euclidean algorithm, and Newton's method for the integer square root —
//! implemented from their descriptions rather than transliterated from the
//! authority's C.

/// A limb. 64-bit because the crate has one build profile, `x86_64-linux`.
pub(crate) type Limb = u64;

/// Drop trailing zero limbs, restoring the "no leading zeros" invariant.
pub(crate) fn normalise(v: &mut Vec<Limb>) {
    while v.last() == Some(&0) {
        v.pop();
    }
}

/// True when the value is zero.
pub(crate) fn is_zero(v: &[Limb]) -> bool {
    v.iter().all(|&l| l == 0)
}

/// `a` against `b`, ignoring trailing zeros so `[5, 0]` equals `[5]`.
pub(crate) fn cmp(a: &[Limb], b: &[Limb]) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let (mut a, mut b) = (a, b);
    while let Some(&0) = a.last() {
        a = &a[..a.len() - 1];
    }
    while let Some(&0) = b.last() {
        b = &b[..b.len() - 1];
    }
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    for i in (0..a.len()).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// The number of significant bits, or `0` for zero.
pub(crate) fn bit_len(v: &[Limb]) -> usize {
    match v.iter().rposition(|&l| l != 0) {
        None => 0,
        Some(i) => i * 64 + (64 - v[i].leading_zeros() as usize),
    }
}

/// The number of significant bits in a single limb, or `0` for zero.
pub(crate) fn bit_len_word(w: Limb) -> usize {
    if w == 0 {
        0
    } else {
        64 - w.leading_zeros() as usize
    }
}

/// Whether bit `n` is set. Bits above the value are zero.
pub(crate) fn bit(v: &[Limb], n: usize) -> bool {
    match v.get(n / 64) {
        Some(&l) => (l >> (n % 64)) & 1 == 1,
        None => false,
    }
}

/// Set bit `n` in place, growing the vector as needed.
pub(crate) fn set_bit(v: &mut Vec<Limb>, n: usize) {
    let (limb, off) = (n / 64, n % 64);
    if v.len() <= limb {
        v.resize(limb + 1, 0);
    }
    v[limb] |= 1 << off;
}

/// Clear bit `n` in place, normalising afterwards.
pub(crate) fn clear_bit(v: &mut Vec<Limb>, n: usize) {
    let (limb, off) = (n / 64, n % 64);
    if v.len() > limb {
        v[limb] &= !(1 << off);
        normalise(v);
    }
}

/// `a + b`.
pub(crate) fn add(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u64;
    for i in 0..a.len().max(b.len()) {
        let s =
            (*a.get(i).unwrap_or(&0) as u128) + (*b.get(i).unwrap_or(&0) as u128) + (carry as u128);
        out.push(s as u64);
        carry = (s >> 64) as u64;
    }
    if carry != 0 {
        out.push(carry);
    }
    out
}

/// `a - b`, which requires `a >= b`. The public entry points check before calling.
pub(crate) fn sub(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0i128;
    for (i, &limb) in a.iter().enumerate() {
        let d = (limb as i128) - (*b.get(i).unwrap_or(&0) as i128) - borrow;
        out.push((d & 0xffff_ffff_ffff_ffff) as u64);
        borrow = i128::from(d < 0);
    }
    normalise(&mut out);
    out
}

/// `a + w` for a single limb.
pub(crate) fn add_word(a: &[Limb], w: Limb) -> Vec<Limb> {
    add(a, &[w])
}

/// `a - w` for a single limb, or `None` when that would go negative.
pub(crate) fn sub_word(a: &[Limb], w: Limb) -> Option<Vec<Limb>> {
    let word = if w == 0 { Vec::new() } else { vec![w] };
    if cmp(a, &word) == core::cmp::Ordering::Less {
        return None;
    }
    Some(sub(a, &word))
}

/// `a * b`.
///
/// Schoolbook. Intermediates are `u128` and each column accumulator holds at most
/// `2^128-1`, so nothing here can overflow.
pub(crate) fn mul(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = vec![0u64; a.len() + b.len()];
    for (i, &x) in a.iter().enumerate() {
        if x == 0 {
            continue;
        }
        let mut carry = 0u64;
        for (j, &y) in b.iter().enumerate() {
            let t = (x as u128) * (y as u128) + (out[i + j] as u128) + (carry as u128);
            out[i + j] = t as u64;
            carry = (t >> 64) as u64;
        }
        let mut k = i + b.len();
        while carry != 0 {
            let t = (out[k] as u128) + (carry as u128);
            out[k] = t as u64;
            carry = (t >> 64) as u64;
            k += 1;
        }
    }
    normalise(&mut out);
    out
}

/// `a * w` for a single limb.
pub(crate) fn mul_word(a: &[Limb], w: Limb) -> Vec<Limb> {
    mul(a, &[w])
}

/// `a << bits`.
pub(crate) fn shl(a: &[Limb], bits: usize) -> Vec<Limb> {
    if a.is_empty() {
        return Vec::new();
    }
    let (whole, part) = (bits / 64, bits % 64);
    let mut out = vec![0u64; whole];
    if part == 0 {
        out.extend_from_slice(a);
        normalise(&mut out);
        return out;
    }
    let mut carry = 0u64;
    for &l in a {
        out.push((l << part) | carry);
        carry = l >> (64 - part);
    }
    if carry != 0 {
        out.push(carry);
    }
    normalise(&mut out);
    out
}

/// `a >> bits` — a floor division by a power of two on the magnitude.
pub(crate) fn shr(a: &[Limb], bits: usize) -> Vec<Limb> {
    let (whole, part) = (bits / 64, bits % 64);
    if whole >= a.len() {
        return Vec::new();
    }
    let src = &a[whole..];
    let mut out = Vec::with_capacity(src.len());
    if part == 0 {
        out.extend_from_slice(src);
        normalise(&mut out);
        return out;
    }
    for i in 0..src.len() {
        let hi = if i + 1 < src.len() { src[i + 1] } else { 0 };
        out.push((src[i] >> part) | (hi << (64 - part)));
    }
    normalise(&mut out);
    out
}

/// `a & b`, limbwise.
pub(crate) fn and(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let mut out: Vec<Limb> = (0..a.len().min(b.len())).map(|i| a[i] & b[i]).collect();
    normalise(&mut out);
    out
}

/// The low limb, or zero.
pub(crate) fn low_u64(v: &[Limb]) -> u64 {
    v.first().copied().unwrap_or(0)
}

/// A single limb as a value.
pub(crate) fn from_u64(w: u64) -> Vec<Limb> {
    if w == 0 {
        Vec::new()
    } else {
        vec![w]
    }
}

/// Divide by a single limb, returning `(quotient, remainder)`.
///
/// The caller must not pass zero.
pub(crate) fn div_rem_small(a: &[Limb], d: Limb) -> (Vec<Limb>, Limb) {
    let mut out = vec![0u64; a.len()];
    let mut rem = 0u128;
    for i in (0..a.len()).rev() {
        let cur = (rem << 64) | (a[i] as u128);
        out[i] = (cur / (d as u128)) as u64;
        rem = cur % (d as u128);
    }
    normalise(&mut out);
    (out, rem as u64)
}

/// `a mod m`, for a non-zero `m`.
pub(crate) fn rem(a: &[Limb], m: &[Limb]) -> Vec<Limb> {
    if m.len() == 1 {
        let (_, r) = div_rem_small(a, m[0]);
        return from_u64(r);
    }
    div_rem(a, m).1
}

/// `(a, b) -> (quotient, remainder)`. `b` must be non-zero.
///
/// Knuth's Algorithm D: textbook long division generalised to machine words. The
/// implementation is deliberately literal, including `D1`'s normalisation shift,
/// because the classic failure of this algorithm is a quotient-digit estimate that
/// is occasionally too large, and the add-back in `D6` is what makes the estimate
/// safe rather than approximate.
pub(crate) fn div_rem(a: &[Limb], b: &[Limb]) -> (Vec<Limb>, Vec<Limb>) {
    assert!(!b.is_empty(), "division by zero");
    if cmp(a, b) == core::cmp::Ordering::Less {
        return (Vec::new(), a.to_vec());
    }
    if b.len() == 1 {
        let (q, r) = div_rem_small(a, b[0]);
        return (q, from_u64(r));
    }

    // D1: normalise so the divisor's top limb has its high bit set.
    let shift = b[b.len() - 1].leading_zeros() as usize;
    let u = if shift == 0 {
        a.to_vec()
    } else {
        shl(a, shift)
    };
    let v = if shift == 0 {
        b.to_vec()
    } else {
        shl(b, shift)
    };
    let n = v.len();
    let m = u.len() - n;
    let mut un = u.clone();
    un.push(0);
    let mut q = vec![0u64; m + 1];
    let vtop = v[n - 1] as u128;
    let vnext = v[n - 2] as u128;

    for j in (0..=m).rev() {
        // D3: estimate the quotient digit from the top two limbs.
        let top = ((un[j + n] as u128) << 64) | (un[j + n - 1] as u128);
        let mut qhat = top / vtop;
        let mut rhat = top % vtop;
        while qhat >= (1u128 << 64) || qhat * vnext > ((rhat << 64) | (un[j + n - 2] as u128)) {
            qhat -= 1;
            rhat += vtop;
            if rhat >= (1u128 << 64) {
                break;
            }
        }
        // D4: multiply and subtract.
        let mut borrow = 0i128;
        let mut carry = 0u128;
        for i in 0..n {
            let p = qhat * (v[i] as u128) + carry;
            carry = p >> 64;
            let t = (un[j + i] as i128) - ((p & 0xffff_ffff_ffff_ffff) as i128) - borrow;
            un[j + i] = (t & 0xffff_ffff_ffff_ffff) as u64;
            borrow = i128::from(t < 0);
        }
        let t = (un[j + n] as i128) - (carry as i128) - borrow;
        un[j + n] = (t & 0xffff_ffff_ffff_ffff) as u64;
        // D5/D6: add back when the estimate borrowed out.
        if t < 0 {
            qhat -= 1;
            let mut c = 0u128;
            for i in 0..n {
                let s = (un[j + i] as u128) + (v[i] as u128) + c;
                un[j + i] = s as u64;
                c = s >> 64;
            }
            un[j + n] = (un[j + n] as u128).wrapping_add(c) as u64;
        }
        q[j] = qhat as u64;
    }

    // D8: the remainder is the shifted-back low limbs.
    let mut r: Vec<Limb> = un[..n].to_vec();
    if shift != 0 {
        r = shr(&r, shift);
    }
    normalise(&mut r);
    normalise(&mut q);
    (q, r)
}

/// Greatest common divisor, by the binary method.
pub(crate) fn gcd(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let mut x = a.to_vec();
    let mut y = b.to_vec();
    normalise(&mut x);
    normalise(&mut y);
    if x.is_empty() {
        return y;
    }
    if y.is_empty() {
        return x;
    }
    let shift = (x[0] | y[0]).trailing_zeros() as usize;
    x = shr(&x, x[0].trailing_zeros() as usize);
    y = shr(&y, y[0].trailing_zeros() as usize);
    loop {
        if cmp(&x, &y) == core::cmp::Ordering::Greater {
            core::mem::swap(&mut x, &mut y);
        }
        y = sub(&y, &x);
        if y.is_empty() {
            break;
        }
        y = shr(&y, y[0].trailing_zeros() as usize);
    }
    shl(&x, shift)
}

/// `a^-1 mod m`, or `None` when no inverse exists.
///
/// The extended Euclidean algorithm iterating on remainders. The coefficient is
/// reduced modulo `m` at every step; without that it grows like the product of the
/// quotients and the operation becomes quadratic in the wrong variable.
pub(crate) fn mod_inverse(a: &[Limb], m: &[Limb]) -> Option<Vec<Limb>> {
    // There is no inverse modulo zero, and the question cannot be expressed as a
    // remainder: `rem` would assert. Answering `None` here rather than letting the
    // assertion fire is what keeps a misuse of the public entry point a reported
    // failure instead of a panic crossing the ABI boundary.
    if m.is_empty() {
        return None;
    }
    if m.len() == 1 && m[0] == 1 {
        return Some(Vec::new());
    }
    let a = rem(a, m);
    if a.is_empty() {
        return None;
    }
    let (mut r0, mut r1) = (m.to_vec(), a);
    let (mut t0, mut t1) = (Vec::<Limb>::new(), vec![1u64]);
    while !r1.is_empty() {
        let (q, r2) = div_rem(&r0, &r1);
        let prod_mod = rem(&mul(&q, &t1), m);
        let t2 = if cmp(&t0, &prod_mod) != core::cmp::Ordering::Less {
            sub(&t0, &prod_mod)
        } else {
            sub(m, &sub(&prod_mod, &t0))
        };
        r0 = r1;
        r1 = r2;
        t0 = t1;
        t1 = t2;
    }
    if !(r0.len() == 1 && r0[0] == 1) {
        return None;
    }
    Some(rem(&t0, m))
}

/// Whether `a` is even.
pub(crate) fn is_even(a: &[Limb]) -> bool {
    a.first().map(|&l| l & 1 == 0).unwrap_or(true)
}

/// Whether `a` and `b` are coprime.
pub(crate) fn are_coprime(a: &[Limb], b: &[Limb]) -> bool {
    let g = gcd(a, b);
    g.len() == 1 && g[0] == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(h: &str) -> Vec<Limb> {
        let mut out: Vec<Limb> = Vec::new();
        for c in h.chars() {
            let Some(d) = c.to_digit(16) else {
                unreachable!("the tests pass hex digits")
            };
            let mut carry = d as u64;
            for limb in out.iter_mut() {
                let t = ((*limb as u128) << 4) | (carry as u128);
                *limb = t as u64;
                carry = (t >> 64) as u64;
            }
            if carry != 0 {
                out.push(carry);
            }
        }
        normalise(&mut out);
        out
    }

    fn to_hex(v: &[Limb]) -> String {
        if v.is_empty() {
            return "0".to_string();
        }
        let mut s = format!("{:x}", v[v.len() - 1]);
        for l in v[..v.len() - 1].iter().rev() {
            s.push_str(&format!("{l:016x}"));
        }
        s
    }

    #[test]
    fn hex_helpers_round_trip_the_limb_boundary() {
        for h in [
            "1",
            "ffffffffffffffff",
            "10000000000000000",
            "deadbeefcafebabe0123456789abcdef",
        ] {
            assert_eq!(to_hex(&from_hex(h)), h);
        }
        assert!(from_hex("0").is_empty());
        assert_eq!(to_hex(&from_hex("0")), "0");
    }

    #[test]
    fn add_carries_across_the_limb_boundary() {
        assert_eq!(add(&[u64::MAX], &[1]), vec![0, 1]);
        assert_eq!(add(&[u64::MAX], &[u64::MAX]), vec![u64::MAX - 1, 1]);
        assert_eq!(add(&[1, 2], &[]), vec![1, 2]);
    }

    #[test]
    fn sub_borrows_and_normalises() {
        assert_eq!(sub(&[0, 1], &[1]), vec![u64::MAX]);
        assert_eq!(sub(&[5], &[5]), Vec::<Limb>::new());
        assert_eq!(sub_word(&[5], 6), None);
        assert_eq!(sub_word(&[5], 5), Some(Vec::new()));
    }

    #[test]
    fn mul_matches_known_products() {
        let m = u64::MAX;
        assert_eq!(to_hex(&mul(&[m], &[m])), "fffffffffffffffe0000000000000001");
        // Ground truth from an independent bignum, not from arithmetic done in
        // this test author's head: the first version of this expectation was
        // wrong and the implementation was right.
        assert_eq!(
            to_hex(&mul(
                &from_hex("123456789abcdef"),
                &from_hex("fedcba987654321")
            )),
            "121fa00ad77d7422236d88fe5618cf"
        );
        assert!(mul(&Vec::new(), &[7]).is_empty());
    }

    #[test]
    fn div_rem_satisfies_its_definition_on_awkward_shapes() {
        // q*b + r == a with r < b, over operands that exercise the D3 estimate and
        // the D6 add-back.
        let cases = [
            ("ffffffffffffffffffffffffffffffff", "10000000000000000"),
            ("80000000000000000000000000000001", "ffffffffffffffff"),
            ("ffffffffffffffff0000000000000001", "fffffffffffffffe"),
            ("1", "ffffffffffffffffffffffffffffffff"),
            ("10000000000000000000000000000000000000000", "3"),
            (
                "ffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffff",
            ),
        ];
        for (a, b) in cases {
            let (av, bv) = (from_hex(a), from_hex(b));
            let (q, r) = div_rem(&av, &bv);
            assert_eq!(cmp(&r, &bv), core::cmp::Ordering::Less, "r < b for {a}/{b}");
            assert_eq!(
                to_hex(&add(&mul(&q, &bv), &r)),
                a.trim_start_matches('0'),
                "q*b+r == a for {a}/{b}"
            );
        }
        let (q, r) = div_rem(&from_hex("1000000000000000000000000"), &from_hex("1000"));
        assert_eq!(to_hex(&q), "1000000000000000000000");
        assert!(r.is_empty());
    }

    #[test]
    fn shifts_cross_limb_boundaries() {
        assert_eq!(shl(&[1], 63), vec![1u64 << 63]);
        assert_eq!(shl(&[1], 64), vec![0, 1]);
        assert_eq!(shl(&[1], 65), vec![0, 2]);
        assert_eq!(shr(&[0, 1], 64), vec![1]);
        assert_eq!(shr(&[1], 1), Vec::<Limb>::new());
        let v = from_hex("123456789abcdef0fedcba9876543210");
        for bits in [0usize, 1, 63, 64, 65, 127, 128] {
            assert_eq!(shr(&shl(&v, bits), bits), v, "round trip at {bits}");
        }
    }

    #[test]
    fn bit_and_word_helpers_agree_with_the_values() {
        let a = from_hex("ff00ff00ff00ff00");
        let b = from_hex("0f0f0f0f0f0f0f0f");
        assert_eq!(to_hex(&and(&a, &b)), "f000f000f000f00");
        let mut v = from_hex("0");
        set_bit(&mut v, 130);
        assert!(bit(&v, 130) && bit_len(&v) == 131);
        clear_bit(&mut v, 130);
        assert!(v.is_empty());
        assert_eq!(bit_len_word(0), 0);
        assert_eq!(bit_len_word(1), 1);
        assert_eq!(bit_len_word(u64::MAX), 64);
        assert_eq!(add_word(&[u64::MAX], 1), vec![0, 1]);
        assert_eq!(mul_word(&[3], 5), vec![15]);
    }

    #[test]
    fn gcd_inverse_and_coprimality_agree_with_small_arithmetic() {
        assert_eq!(gcd(&[12], &[18]), vec![6]);
        assert_eq!(gcd(&Vec::new(), &[5]), vec![5]);
        assert_eq!(gcd(&[270], &[192]), vec![6]);
        assert_eq!(mod_inverse(&[3], &[11]), Some(vec![4]));
        assert_eq!(mod_inverse(&[6], &[9]), None);
        assert!(are_coprime(&[3], &[11]));
        assert!(!are_coprime(&[6], &[9]));
    }

    #[test]
    fn mod_inverse_satisfies_its_definition() {
        // 2^81 + 5, coprime with the operand below. The first version of this test
        // used a modulus sharing the factor 147 with the operand and therefore
        // asserted an inverse that correctly does not exist.
        let m = from_hex("200000000000000000005");
        let a = from_hex("123456789abcdef123456789abcdef12345");
        let Some(inv) = mod_inverse(&a, &m) else {
            unreachable!("coprime operands have an inverse")
        };
        assert_eq!(rem(&mul(&a, &inv), &m), vec![1u64], "a * a^-1 == 1 mod m");
    }

    #[test]
    fn compare_treats_trailing_zeros_as_insignificant() {
        assert_eq!(cmp(&[5, 0, 0], &[5]), core::cmp::Ordering::Equal);
        assert_eq!(cmp(&[], &[0]), core::cmp::Ordering::Equal);
        assert_eq!(cmp(&[0, 1], &[u64::MAX]), core::cmp::Ordering::Greater);
    }

    #[test]
    fn rem_and_small_division_agree() {
        let a = from_hex("123456789abcdef0123456789abcdef");
        let (q, r) = div_rem_small(&a, 1000);
        assert_eq!(add(&mul(&q, &[1000]), &from_u64(r)), a);
        assert_eq!(rem(&a, &[1000]), from_u64(r));
    }
}
