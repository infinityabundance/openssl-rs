"""SHA-256 and HMAC-SHA-256, written from FIPS 180-4 and RFC 2104/4231.

SHA-256 is the control primitive for the differential harness: a symmetric
digest whose result does not depend on field or group arithmetic.  If the
harness agrees on SHA-256 but not on a number-theoretic operation, the defect
is not in the hex/integer transport or the DSO loading path.

Sources
-------
* FIPS 180-4 (2015): section 4.1.3 (SHA-256 initial hash value),
  section 4.2.2 (SHA-256 round constants), section 5.1.1 (padding shared by
  SHA-1, SHA-224 and SHA-256) and section 6.2.2 (SHA-256 hash computation).
* RFC 2104 (1997) and RFC 4231 (2005) for HMAC-SHA-256.
"""

from __future__ import annotations

K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

H0 = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

MASK = 0xFFFFFFFF


def _ror(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & MASK


def _compress(state, block: bytes):
    w = [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(16)]
    for i in range(16, 64):
        s0 = _ror(w[i - 15], 7) ^ _ror(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _ror(w[i - 2], 17) ^ _ror(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = _ror(e, 6) ^ _ror(e, 11) ^ _ror(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + s1 + ch + K[i] + w[i]) & MASK
        s0 = _ror(a, 2) ^ _ror(a, 13) ^ _ror(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & MASK
        h = g
        g = f
        f = e
        e = (d + temp1) & MASK
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK
    return [
        (x + y) & MASK
        for x, y in zip(state, [a, b, c, d, e, f, g, h])
    ]


def sha256(data: bytes) -> bytes:
    """SHA-256 of ``data`` (FIPS 180-4 section 6.2)."""
    state = list(H0)
    padded = bytearray(data)
    bit_length = len(data) * 8
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0x00)
    padded += bit_length.to_bytes(8, "big")
    for offset in range(0, len(padded), 64):
        state = _compress(state, bytes(padded[offset:offset + 64]))
    return b"".join(word.to_bytes(4, "big") for word in state)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA-256 (RFC 2104, section 2; RFC 4231 test vectors)."""
    if len(key) > 64:
        key = sha256(key)
    key = key.ljust(64, b"\x00")
    inner = bytes(byte ^ 0x36 for byte in key)
    outer = bytes(byte ^ 0x5C for byte in key)
    return sha256(outer + sha256(inner + message))
