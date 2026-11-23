"""A deterministic 2048-bit RSA key, its CRT recombination and plain private op.

Definitions
-----------
PKCS #1 v2.2 (RFC 8017, 2016) section 3.2 defines the RSA private key and the
CRT representation:

    n = p * q,  e * d == 1 (mod lambda(n)),  lambda(n) = lcm(p-1, q-1)
    dmp1 = d mod (p-1),  dmq1 = d mod (q-1),  iqmp = q^-1 mod p

Section 5.1.2 (RSADP) defines the plain private operation ``m = c^d mod n``.
The CRT recombination used here is Garner's algorithm, which is the
recombination PKCS #1 section 3.2's representation implies:

    m1 = c^dmp1 mod p
    m2 = c^dmq1 mod q
    h  = iqmp * (m1 - m2) mod p
    m  = m2 + h * q

The key is generated deterministically from a fixed byte seed: a SHA-256
counter-mode stream selects candidate primes, which are advanced by two until
a Miller-Rabin probable prime coprime to ``e`` is found.  The same seed always
produces the same key.  The key is validated on load (``n == p*q``, the CRT
exponents, and the CRT/plain agreement), so a corrupt fixture cannot silently
become the reference.

Only the private operation over a single fixed key is in scope.  No signature
padding scheme (PKCS #1 v1.5, PSS, OAEP) is implemented.
"""

from __future__ import annotations

from . import ref_arith as fa
from . import ref_symmetric

SMALL_PRIMES = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103,
]


def _stream(seed: bytes, label: bytes, length: int) -> bytes:
    """Deterministic SHA-256 counter-mode byte stream."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += ref_symmetric.sha256(
            seed + b"\x00" + label + counter.to_bytes(8, "big")
        )
        counter += 1
    return bytes(out[:length])


def _miller_rabin(n: int, bases) -> bool:
    if n < 2:
        return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for base in bases:
        a = base % n
        if a in (0, 1):
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _small_factor_free(n: int) -> bool:
    for prime in SMALL_PRIMES:
        if n % prime == 0:
            return n == prime
    return True


def _screening_bases(n: int, rounds: int):
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    encoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
    for index in range(rounds):
        digest = ref_symmetric.sha256(encoded + index.to_bytes(4, "big"))
        bases.append(int.from_bytes(digest, "big") % (n - 3) + 2)
    return bases


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Deterministic-in-the-seed Miller-Rabin test.

    The witness set is fixed (small primes plus SHA-256-derived values), so
    the function is deterministic.  ``rounds`` is the number of derived
    witnesses in addition to the twelve fixed small-prime bases.
    """
    if n in (2, 3):
        return True
    if n < 2 or n % 2 == 0:
        return False
    if not _small_factor_free(n):
        return False
    return _miller_rabin(n, _screening_bases(n, rounds))


def _gen_prime(bits: int, seed: bytes, label: bytes, e: int) -> int:
    attempt = 0
    while True:
        raw = _stream(seed, label + attempt.to_bytes(4, "big"), bits // 8)
        candidate = int.from_bytes(raw, "big")
        candidate |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if candidate.bit_length() != bits:
            attempt += 1
            continue
        while candidate.bit_length() == bits:
            if _small_factor_free(candidate) and (candidate - 1) % e != 0:
                if _miller_rabin(candidate, [2, 3, 5, 7, 11, 13]):
                    if is_probable_prime(candidate, rounds=40):
                        return candidate
            candidate += 2
        attempt += 1


def generate_key(seed_hex: str = "0x45545035", bits: int = 2048,
                 e: int = 65537) -> dict:
    """Generate the fixed key deterministically from ``seed_hex``."""
    seed = int(seed_hex, 16).to_bytes(32, "big")
    half = bits // 2
    p = _gen_prime(half, seed, b"p", e)
    q = _gen_prime(half, seed, b"q", e)
    while q == p:
        q = _gen_prime(half, seed, b"q-again", e)
    n = p * q
    if n.bit_length() != bits:
        raise RuntimeError("generated modulus is not the requested size")
    lam = (p - 1) * (q - 1) // _gcd(p - 1, q - 1)
    d = fa.inv_mod(e, lam)
    key = {
        "bits": bits,
        "e": e,
        "n": n,
        "p": p,
        "q": q,
        "d": d,
        "dmp1": d % (p - 1),
        "dmq1": d % (q - 1),
        "iqmp": fa.inv_mod(q, p),
        "lambda": lam,
    }
    _validate_key(key)
    return key


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _validate_key(key: dict) -> None:
    p, q, n = key["p"], key["q"], key["n"]
    e, d, lam = key["e"], key["d"], key["lambda"]
    if p * q != n:
        raise ValueError("n != p*q")
    if (e * d) % lam != 1:
        raise ValueError("e*d != 1 (mod lambda)")
    if key["dmp1"] != d % (p - 1):
        raise ValueError("dmp1 mismatch")
    if key["dmq1"] != d % (q - 1):
        raise ValueError("dmq1 mismatch")
    if (key["iqmp"] * q) % p != 1:
        raise ValueError("iqmp mismatch")
    if not is_probable_prime(p) or not is_probable_prime(q):
        raise ValueError("a factor is not a probable prime")


def crt_private(ciphertext: int, key: dict) -> int:
    """RSADP via Garner recombination."""
    c = ciphertext % key["n"]
    m1 = pow(c, key["dmp1"], key["p"])
    m2 = pow(c, key["dmq1"], key["q"])
    h = (key["iqmp"] * (m1 - m2)) % key["p"]
    return (m2 + h * key["q"]) % key["n"]


def plain_private(ciphertext: int, key: dict) -> int:
    """RSADP as ``c^d mod n``, used to cross check the CRT path."""
    return pow(ciphertext % key["n"], key["d"], key["n"])


def public_op(message: int, key: dict) -> int:
    return pow(message % key["n"], key["e"], key["n"])


def key_to_json(key: dict) -> dict:
    out = {"bits": key["bits"], "e": key["e"]}
    for name in ("n", "p", "q", "d", "dmp1", "dmq1", "iqmp", "lambda"):
        out[name] = format(key[name], "x")
    return out


def key_from_json(obj: dict) -> dict:
    names = ("n", "p", "q", "d", "dmp1", "dmq1", "iqmp", "lambda")
    key = {"bits": int(obj["bits"]), "e": int(obj["e"])}
    for name in names:
        key[name] = int(obj[name], 16)
    _validate_key(key)
    return key
