#!/usr/bin/env python3
"""PFP-53 bounded substitute: a Python model of the 4-limb CIOS Montgomery multiply.

This is a **model of the algorithm as transcribed from the Rust source**, not a
run of the compiled Rust binary. It faithfully reimplements
`src/bn/arith.rs::mont_mul_cios_fixed::<4, 6>` limb-by-limb with the same 64-bit
wrapping semantics, and compares it against an independent reference
`(a * b * R^-1) mod m` computed with Python big integers and `pow(R, -1, m)`.

What this validates and what it does NOT:

* It validates the **transcribed algorithm**: if this model matches the
  independent oracle on every enumerated edge case and on a large deterministic
  pseudo-random sample, the *algorithm as written down* is consistent with the
  arithmetic definition of Montgomery multiplication over those inputs.
* It does **not** prove anything about the compiled Rust binary, and a
  transcription error — a mistake in copying the Rust source into Python that
  happens to still satisfy the oracle — is exactly the risk this substitute
  cannot rule out. It is a finite sample, not a proof.

Run:

    python3 forensics/tools/pfp53_cios_model.py
"""

from __future__ import annotations

import sys

MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1
R = 1 << 256  # B^4, B = 2^64


# ---------------------------------------------------------------------------
# Faithful transcriptions of the Rust helpers (same wrapping semantics).
# ---------------------------------------------------------------------------

def mac(a: int, b: int, c: int, d: int) -> int:
    """`mul_add_carry(a, b, c, d) = (a*b + c + d) mod 2^128` (u128 wrapping)."""
    return (a * b + c + d) & MASK128


def overflowing_add(x: int, y: int) -> tuple[int, int]:
    """`(x + y) mod 2^64` and the carry-out bit, mirroring `u64::overflowing_add`."""
    s = x + y
    return s & MASK64, 1 if s >= (1 << 64) else 0


def overflowing_sub(x: int, y: int) -> tuple[int, int]:
    """`(x - y) mod 2^64` and the borrow-out bit, mirroring `u64::overflowing_sub`."""
    return (x - y) & MASK64, 1 if x < y else 0


def wrapping_mul(x: int, y: int) -> int:
    return (x * y) & MASK64


def wrapping_add(x: int, y: int) -> int:
    return (x + y) & MASK64


def wrapping_neg(x: int) -> int:
    return (-x) & MASK64


def constant_time_select(mask: int, a: int, b: int) -> int:
    """`(mask & a) | (!mask & b)` on 64-bit values."""
    return ((mask & a) | ((~mask & MASK64) & b)) & MASK64


def n0_of(m0: int) -> int:
    """`-m0^-1 mod 2^64` by the standard Newton iteration (`mont_n0`)."""
    m0 &= MASK64
    inv = m0
    for _ in range(6):
        inv = wrapping_mul(inv, (2 - wrapping_mul(m0, inv)) & MASK64)
    return wrapping_neg(inv)


def cios4(a: list[int], b: list[int], m: list[int], n0: int) -> list[int]:
    """Faithful transcription of `mont_mul_cios_fixed::<4, 6>`.

    `a`, `b`, `m` are 4 little-endian 64-bit limbs; `n0` is `-m0^-1 mod 2^64`.
    Returns the 4-limb result `a * b * 2^-256 mod m`.
    """
    n = 4
    acc = [0] * (n + 2)  # acc[0..=5]

    for bi in b:
        # acc += a * b[i]
        carry = 0
        for j in range(n):
            v = mac(a[j], bi, acc[j], carry)
            acc[j] = v & MASK64
            carry = v >> 64
        acc[n], overflow = overflowing_add(acc[n], carry)
        acc[n + 1] = overflow

        # acc += u * m, with u chosen so the low limb becomes zero (and is dropped).
        u = wrapping_mul(acc[0], n0)
        v = mac(u, m[0], acc[0], 0)
        carry = v >> 64
        for j in range(1, n):
            v = mac(u, m[j], acc[j], carry)
            acc[j - 1] = v & MASK64
            carry = v >> 64
        acc[n - 1], overflow = overflowing_add(acc[n], carry)
        acc[n] = wrapping_add(acc[n + 1], overflow)

    # One masked conditional subtraction (a final borrow, never a branch).
    high = acc[n]
    borrow = 0
    diff = [0] * n
    for j in range(n):
        d1, b1 = overflowing_sub(acc[j], m[j])
        d2, b2 = overflowing_sub(d1, borrow)
        diff[j] = d2
        borrow = b1 | b2
    keep = high | (borrow ^ 1)
    mask = wrapping_neg(keep)
    return [constant_time_select(mask, diff[j], acc[j]) for j in range(n)]


# ---------------------------------------------------------------------------
# Independent oracle (Python big integers; shares no code with the kernel).
# ---------------------------------------------------------------------------

def from_limbs(limbs: list[int]) -> int:
    return sum((limb & MASK64) << (64 * i) for i, limb in enumerate(limbs))


def to_limbs(value: int, n: int) -> list[int]:
    return [(value >> (64 * i)) & MASK64 for i in range(n)]


def reference(a: list[int], b: list[int], m: list[int]) -> list[int]:
    """`(a * b * R^-1) mod m` computed independently, `R = 2^256`."""
    big_a = from_limbs(a)
    big_b = from_limbs(b)
    big_m = from_limbs(m)
    r_inv = pow(R, -1, big_m)  # m is odd, so gcd(R, m) == 1
    return to_limbs((big_a * big_b * r_inv) % big_m, 4)


def lt_limbs(x: list[int], y: list[int]) -> bool:
    """`x < y` as little-endian limb vectors."""
    return from_limbs(x) < from_limbs(y)


# ---------------------------------------------------------------------------
# Case drivers.
# ---------------------------------------------------------------------------

def check_case(a: list[int], b: list[int], m: list[int]) -> tuple[bool, str]:
    """Compare the transcription against the oracle for one admissible case."""
    n0 = n0_of(m[0])
    got = cios4(a, b, m, n0)
    want = reference(a, b, m)
    if got != want:
        return False, f"mismatch a={a!r} b={b!r} m={m!r}: got={got!r} want={want!r}"
    if not lt_limbs(got, m):
        return False, f"range violation (r >= n): a={a!r} b={b!r} m={m!r} r={got!r}"
    return True, ""


def edge_cases() -> list[tuple[list[int], list[int], list[int]]]:
    """Enumerated edge cases covering the required modulus/operand classes."""
    cases: list[tuple[list[int], list[int], list[int]]] = []
    # n a small odd value: every admissible (a, b) below it.
    for small in (3, 5, 7, 9, 11, 13, 15, 17, 31, 33, 255, 257):
        m = to_limbs(small, 4)
        for a in range(small):
            for b in range(small):
                cases.append((to_limbs(a, 4), to_limbs(b, 4), m))

    # n just above 2^255 (bit 255 set, low limbs small).
    n_above_2p255 = (1 << 255) + 1
    m = to_limbs(n_above_2p255, 4)
    for a, b in [(0, 0), (1, 1), (n_above_2p255 - 1, n_above_2p255 - 1),
                 (n_above_2p255 - 2, n_above_2p255 - 1), (1, n_above_2p255 - 1)]:
        cases.append((to_limbs(a, 4), to_limbs(b, 4), m))

    # Top limb all-ones: n = 2^256 - 1 (maximal modulus), including the
    # near-boundary product a*b = (n-1)^2 ~ n*R - 1 for a, b near n.
    n_all_ones = (1 << 256) - 1
    m = to_limbs(n_all_ones, 4)
    for a, b in [(0, 0), (1, 1), (n_all_ones - 1, n_all_ones - 1),
                 (n_all_ones - 2, n_all_ones - 1), (n_all_ones - 1, n_all_ones - 2),
                 (n_all_ones // 2, n_all_ones // 2 + 1)]:
        cases.append((to_limbs(a, 4), to_limbs(b, 4), m))

    # a*b < n: small operands under a full-width modulus.
    m = to_limbs((1 << 256) - 1, 4)
    for a, b in [(0, 0), (1, 2), (2, 3), (7, 11), (123, 456)]:
        cases.append((to_limbs(a, 4), to_limbs(b, 4), m))

    return cases


def random_cases(seed: int, count: int) -> list[tuple[list[int], list[int], list[int]]]:
    """Deterministic pseudo-random admissible cases from a recorded seed."""
    import random

    rng = random.Random(seed)
    cases: list[tuple[list[int], list[int], list[int]]] = []
    for _ in range(count):
        # An odd modulus with a non-zero top limb (2^192 <= m < 2^256).
        m = [rng.getrandbits(64) for _ in range(4)]
        m[0] |= 1
        m[3] |= 1 << 63
        big_m = from_limbs(m)
        a = to_limbs(rng.randrange(big_m), 4)
        b = to_limbs(rng.randrange(big_m), 4)
        cases.append((a, b, m))
    return cases


def run_suite(seed: int, random_count: int) -> dict:
    mismatches = 0
    range_violations = 0
    edge = edge_cases()
    for a, b, m in edge:
        ok, why = check_case(a, b, m)
        if not ok:
            if why.startswith("range violation"):
                range_violations += 1
            else:
                mismatches += 1
            print(f"FAIL: {why}")

    random = random_cases(seed, random_count)
    for a, b, m in random:
        ok, why = check_case(a, b, m)
        if not ok:
            if why.startswith("range violation"):
                range_violations += 1
            else:
                mismatches += 1
            print(f"FAIL: {why}")

    return {
        "seed": seed,
        "edge_cases": len(edge),
        "random_cases": len(random),
        "mismatches": mismatches,
        "range_violations": range_violations,
    }


def main(argv: list[str] | None = None) -> int:
    seed = 20261128
    random_count = 100_000
    result = run_suite(seed, random_count)
    total = result["edge_cases"] + result["random_cases"]
    ok = result["mismatches"] == 0 and result["range_violations"] == 0
    print(
        "PFP-53 CIOS 4x64 model: "
        f"seed={result['seed']} edge_cases={result['edge_cases']} "
        f"random_cases={result['random_cases']} total={total} "
        f"mismatches={result['mismatches']} range_violations={result['range_violations']} "
        f"RESULT={'OK' if ok else 'FAIL'}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
