"""Independent modular arithmetic over the P-256 field prime and group order.

Written from the normative descriptions, not transcribed from the candidate or
from OpenSSL:

* the domain parameters (p, n, a, b, G) are the ones published for
  ``secp256r1`` / NIST P-256 in SEC 2 v2.0 (2010) section 2.4.2 and
  FIPS 186-4 (2013) Appendix D.1.2.3, restated in NIST SP 800-186 (2023)
  section 3.2.1.3;
* modular addition, subtraction and multiplication are the ordinary integer
  operations followed by reduction into ``[0, m)``;
* a modular inverse is defined by ``a * inv(a) == 1 (mod m)``; the reference
  computes it with the extended Euclidean algorithm (the method is an
  implementation choice - the normative documents define the property, not the
  algorithm);
* modular exponentiation is the square-and-multiply method implied by the
  repeated-squaring definition of exponentiation in a finite group.

Every routine here is deterministic.  ``mod_exp`` deliberately does not call
Python's built-in ``pow`` so that it is an independent formulation; a cross
check against ``pow`` is performed by ``make_vectors.py``.
"""

from __future__ import annotations

# SEC 2 v2.0 section 2.4.2 / FIPS 186-4 Appendix D.1.2.3 / SP 800-186 3.2.1.3.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# The field prime and the group order are both prime, which is what makes
# Fermat inversion (a**(m-2) mod m) a valid independent cross check.
assert P % 2 == 1 and N % 2 == 1


def add_mod(a: int, b: int, m: int) -> int:
    """(a + b) mod m, canonical in [0, m)."""
    return (a + b) % m


def sub_mod(a: int, b: int, m: int) -> int:
    """(a - b) mod m, canonical in [0, m)."""
    return (a - b) % m


def mul_mod(a: int, b: int, m: int) -> int:
    """(a * b) mod m, canonical in [0, m)."""
    return (a * b) % m


def inv_mod(a: int, m: int) -> int:
    """Multiplicative inverse of a modulo m (extended Euclid).

    Raises ``ValueError`` when the inverse does not exist.
    """
    a %= m
    if a == 0:
        raise ValueError("zero has no multiplicative inverse")
    old_r, r = a, m
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError("operands are not coprime")
    return old_s % m


def mod_exp(base: int, exp: int, m: int) -> int:
    """base**exp mod m by square-and-multiply (MSB-first)."""
    if exp < 0:
        raise ValueError("negative exponent")
    result = 1 % m
    base %= m
    for bit in bin(exp)[2:]:
        result = (result * result) % m
        if bit == "1":
            result = (result * base) % m
    return result


def is_coprime(a: int, m: int) -> bool:
    a %= m
    while a:
        a, m = m % a, a
    return m == 1
