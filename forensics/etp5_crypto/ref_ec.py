"""P-256 point arithmetic: one affine and one Jacobian representation.

Normative basis
---------------
The curve, its base point and the scalar multiplication are defined by
SEC 2 v2.0 (2010) section 2.4.2, FIPS 186-4 (2013) Appendix D.1.2.3 and NIST
SP 800-186 (2023) section 3.2.1.3.  The group law is the standard
chord-and-tangent law on ``y^2 = x^3 + a*x + b`` over the prime field.

Ambiguity and chosen interpretation
-----------------------------------
The normative documents define the group and the scalar multiplication, but
they do not prescribe a coordinate system or explicit formulas.  Two
independent formulations are implemented here so that they can be checked
against each other:

* affine chord-and-tangent, with a field inversion per step;
* Jacobian projective coordinates ``(X : Y : Z)`` with ``x = X/Z^2`` and
  ``y = Y/Z^3``, using the formulas in Hankerson, Menezes and Vanstone,
  *Guide to Elliptic Curve Cryptography* (2004), Algorithm 3.21 (doubling)
  and Algorithm 3.22 (addition).

The scalar multiplication is a plain left-to-right double-and-add.  It is a
reference, not a constant-time implementation.
"""

from __future__ import annotations

from . import ref_arith as fa

# Affine points are ``(x, y)``; the point at infinity is ``None``.
Point = "tuple[int, int] | None"

# Jacobian points are ``(X, Y, Z)``; ``Z == 0`` is the point at infinity.
JPoint = "tuple[int, int, int]"
INF_J: JPoint = (0, 1, 0)


def is_on_curve(point) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + fa.A * x + fa.B)) % fa.P == 0


def affine_double(point):
    if point is None:
        return None
    x, y = point
    if y % fa.P == 0:
        return None
    lam = ((3 * x * x + fa.A) * fa.inv_mod(2 * y, fa.P)) % fa.P
    x3 = (lam * lam - 2 * x) % fa.P
    y3 = (lam * (x - x3) - y) % fa.P
    return (x3, y3)


def affine_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % fa.P == 0:
            return None
        return affine_double(left)
    lam = ((y2 - y1) * fa.inv_mod(x2 - x1, fa.P)) % fa.P
    x3 = (lam * lam - x1 - x2) % fa.P
    y3 = (lam * (x1 - x3) - y1) % fa.P
    return (x3, y3)


def affine_mul(scalar: int, point):
    """Left-to-right double-and-add in affine coordinates."""
    if scalar < 0:
        raise ValueError("negative scalar")
    result = None
    for bit in bin(scalar)[2:]:
        result = affine_double(result)
        if bit == "1":
            result = affine_add(result, point)
    return result


def jac_is_inf(point: JPoint) -> bool:
    return point[2] % fa.P == 0


def jac_double(point: JPoint) -> JPoint:
    """Hankerson et al., Guide to ECC, Algorithm 3.21 (general ``a``)."""
    x, y, z = point
    if z % fa.P == 0 or y % fa.P == 0:
        return INF_J
    yy = (y * y) % fa.P
    s = (4 * x * yy) % fa.P
    zz = (z * z) % fa.P
    m = (3 * x * x + fa.A * zz * zz) % fa.P
    x3 = (m * m - 2 * s) % fa.P
    y3 = (m * (s - x3) - 8 * yy * yy) % fa.P
    z3 = (2 * y * z) % fa.P
    return (x3, y3, z3)


def jac_add(left: JPoint, right: JPoint) -> JPoint:
    """Hankerson et al., Guide to ECC, Algorithm 3.22."""
    if jac_is_inf(left):
        return right
    if jac_is_inf(right):
        return left
    x1, y1, z1 = left
    x2, y2, z2 = right
    z1z1 = (z1 * z1) % fa.P
    z2z2 = (z2 * z2) % fa.P
    u1 = (x1 * z2z2) % fa.P
    u2 = (x2 * z1z1) % fa.P
    s1 = (y1 * z2 * z2z2) % fa.P
    s2 = (y2 * z1 * z1z1) % fa.P
    h = (u2 - u1) % fa.P
    r = (s2 - s1) % fa.P
    if h == 0:
        if r == 0:
            return jac_double(left)
        return INF_J
    hh = (h * h) % fa.P
    hhh = (h * hh) % fa.P
    v = (u1 * hh) % fa.P
    x3 = (r * r - hhh - 2 * v) % fa.P
    y3 = (r * (v - x3) - s1 * hhh) % fa.P
    z3 = (z1 * z2 * h) % fa.P
    return (x3, y3, z3)


def jac_to_affine(point: JPoint):
    if jac_is_inf(point):
        return None
    x, y, z = point
    zinv = fa.inv_mod(z, fa.P)
    zinv2 = (zinv * zinv) % fa.P
    return ((x * zinv2) % fa.P, (y * zinv2 * zinv) % fa.P)


def jac_mul(scalar: int, point) -> JPoint:
    """Left-to-right double-and-add in Jacobian coordinates."""
    if scalar < 0:
        raise ValueError("negative scalar")
    base = INF_J if point is None else (point[0], point[1], 1)
    result = INF_J
    for bit in bin(scalar)[2:]:
        result = jac_double(result)
        if bit == "1":
            result = jac_add(result, base)
    return result


def mul_g_affine(scalar: int):
    return affine_mul(scalar, (fa.GX, fa.GY))


def mul_g_jacobian(scalar: int):
    return jac_to_affine(jac_mul(scalar, (fa.GX, fa.GY)))


def encode_uncompressed(point) -> bytes:
    """SEC 1 v2.0 section 2.3.3 uncompressed form: 0x04 || X || Y.

    The point at infinity has no SEC 1 octet encoding for a public key; this
    reference uses the single byte 0x00 for it, matching what
    ``EC_POINT_point2oct`` returns for the point at infinity.
    """
    if point is None:
        return b"\x00"
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def decode_uncompressed(data: bytes):
    if data == b"\x00":
        return None
    if len(data) != 65 or data[0] != 4:
        raise ValueError("not an uncompressed P-256 point")
    return (int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:65], "big"))
