"""ECDSA over P-256 with a caller-supplied nonce (FIPS 186-5 section 6.4).

Signature generation, with the nonce supplied rather than generated:

    R = k * G
    r = x(R) mod n                       (reject r == 0)
    s = k^-1 * (z + r * d) mod n         (reject s == 0)

Verification, the defining equation:

    w  = s^-1 mod n
    u1 = z * w mod n
    u2 = r * w mod n
    P  = u1 * G + u2 * Q
    accept iff x(P) mod n == r           (reject P == infinity)

where ``z`` is the leftmost ``min(bitlen(n), bitlen(digest))`` bits of the
digest interpreted as an integer (FIPS 186-5 sections 6.4.1 and 6.4.2).  For
P-256 and SHA-256 both are 256 bits, so ``z = int(digest)``.

The reference also implements the RFC 6979 section 3.2 deterministic nonce
generator (HMAC-SHA-256) so that the published RFC 6979 A.2.5 P-256 vector can
be reproduced.  The differential campaign itself supplies ``k`` directly; the
RFC path exists only as an external cross check.
"""

from __future__ import annotations

from . import ref_arith as fa
from . import ref_ec
from . import ref_symmetric


def digest_to_z(digest: bytes, order_bits: int = 256) -> int:
    value = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - order_bits
    if excess > 0:
        value >>= excess
    return value


def sign(private_key: int, digest: bytes, nonce: int) -> tuple[int, int]:
    """Return ``(r, s)`` for a supplied nonce.

    Raises ``ValueError`` when the nonce produces ``r == 0`` or ``s == 0``;
    the caller must supply a different nonce in that case.
    """
    if not 1 <= private_key < fa.N:
        raise ValueError("private key out of range")
    if not 1 <= nonce < fa.N:
        raise ValueError("nonce out of range")
    point = ref_ec.mul_g_affine(nonce)
    if point is None:
        raise ValueError("nonce produced the point at infinity")
    r = point[0] % fa.N
    if r == 0:
        raise ValueError("nonce produced r == 0")
    z = digest_to_z(digest) % fa.N
    s = (fa.inv_mod(nonce, fa.N) * (z + r * private_key)) % fa.N
    if s == 0:
        raise ValueError("nonce produced s == 0")
    return r, s


def verify(public_point, digest: bytes, r: int, s: int) -> bool:
    """Return whether ``(r, s)`` satisfies the defining ECDSA equation."""
    if public_point is None:
        return False
    if not 1 <= r < fa.N or not 1 <= s < fa.N:
        return False
    z = digest_to_z(digest) % fa.N
    w = fa.inv_mod(s, fa.N)
    u1 = (z * w) % fa.N
    u2 = (r * w) % fa.N
    point = ref_ec.affine_add(
        ref_ec.affine_mul(u1, (fa.GX, fa.GY)),
        ref_ec.affine_mul(u2, public_point),
    )
    if point is None:
        return False
    return point[0] % fa.N == r


def _bits2int(data: bytes, order_bits: int) -> int:
    value = int.from_bytes(data, "big")
    excess = len(data) * 8 - order_bits
    if excess > 0:
        value >>= excess
    return value


def _int2octets(value: int, order_bits: int) -> bytes:
    return value.to_bytes((order_bits + 7) // 8, "big")


def _bits2octets(data: bytes, order: int, order_bits: int) -> bytes:
    return _int2octets(_bits2int(data, order_bits) % order, order_bits)


def rfc6979_nonce(private_key: int, digest: bytes,
                  order: int = fa.N, order_bits: int = 256) -> int:
    """RFC 6979 section 3.2 nonce with HMAC-SHA-256."""
    hlen = 32
    v = b"\x01" * hlen
    k = b"\x00" * hlen
    x_octets = _int2octets(private_key, order_bits)
    h_octets = _bits2octets(digest, order, order_bits)

    k = ref_symmetric.hmac_sha256(k, v + b"\x00" + x_octets + h_octets)
    v = ref_symmetric.hmac_sha256(k, v)
    k = ref_symmetric.hmac_sha256(k, v + b"\x01" + x_octets + h_octets)
    v = ref_symmetric.hmac_sha256(k, v)

    while True:
        t = b""
        while len(t) * 8 < order_bits:
            v = ref_symmetric.hmac_sha256(k, v)
            t += v
        candidate = _bits2int(t, order_bits)
        if 1 <= candidate < order:
            return candidate
        k = ref_symmetric.hmac_sha256(k, v + b"\x00")
        v = ref_symmetric.hmac_sha256(k, v)
