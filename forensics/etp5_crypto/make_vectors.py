"""Generate the deterministic vector populations for the ETP-T5 campaign.

Every pseudo-random value comes from one seed (``ETP5_SEED``).  Re-running this
script reproduces the files byte for byte; ``--check`` verifies that the
tracked files still match the generator.

Files written under ``vectors/``:

* ``field_order.json`` - modular arithmetic cases over p and n;
* ``scalarmul.json``   - P-256 scalars (boundaries, powers of two, pseudo-random);
* ``ecdsa.json``       - supplied-nonce signing and verification cases;
* ``rsa_key.json``     - the fixed deterministic 2048-bit key;
* ``rsa.json``         - RSA representative / private-operation cases;
* ``sha256.json``      - SHA-256 control inputs (published and random).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from forensics.etp5_crypto import ref_arith as fa
from forensics.etp5_crypto import ref_ec
from forensics.etp5_crypto import ref_ecdsa
from forensics.etp5_crypto import ref_rsa
from forensics.etp5_crypto import ref_symmetric

SEED = "0x45545035"
SEED_INT = int(SEED, 16)
VECTOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")

# RFC 6979 A.2.5, P-256 with SHA-256, message "sample".
RFC6979_D = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
RFC6979_K = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
RFC6979_R = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
RFC6979_S = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8


def hex32(value: int) -> str:
    return format(value, "x")


def boundary_values(modulus: int) -> list[int]:
    values = [
        0, 1, 2, 3,
        modulus - 1, modulus - 2,
        modulus // 2, (modulus - 1) // 2,
        (1 << 255) % modulus,
        ((1 << 256) - 1) % modulus,
        (1 << 128) % modulus,
        (1 << 192) % modulus,
        fa.GX % modulus,
        fa.GY % modulus,
    ]
    return sorted(set(values))


def make_field_order(rng: random.Random) -> list[dict]:
    cases = []
    for label, modulus in (("p", fa.P), ("n", fa.N)):
        bounds = boundary_values(modulus)
        pairs = [(a, b) for a in bounds for b in bounds]
        random_count = 256
        pairs += [(rng.randrange(modulus), rng.randrange(modulus))
                  for _ in range(random_count)]
        index = 0
        for op in ("modadd", "modsub", "modmul"):
            for a, b in pairs:
                cases.append({
                    "id": f"{op}-{label}-{index:04d}",
                    "op": op,
                    "modulus": hex32(modulus),
                    "a": hex32(a),
                    "b": hex32(b),
                })
                index += 1
        nonzero = [v for v in bounds if v % modulus != 0]
        inv_inputs = nonzero + [rng.randrange(1, modulus)
                                for _ in range(random_count)]
        for a in inv_inputs:
            cases.append({
                "id": f"modinv-{label}-{len(cases):04d}",
                "op": "modinv",
                "modulus": hex32(modulus),
                "a": hex32(a),
            })
        exp_bases = nonzero + [rng.randrange(1, modulus)
                               for _ in range(random_count)]
        for base in exp_bases:
            exponent = rng.randrange(1, 1 << 256) % modulus
            if exponent == 0:
                exponent = 1
            cases.append({
                "id": f"modexp-{label}-{len(cases):04d}",
                "op": "modexp",
                "modulus": hex32(modulus),
                "a": hex32(base),
                "e": hex32(exponent),
            })
    return cases


def make_scalarmul(rng: random.Random) -> list[dict]:
    scalars = [0, 1, 2, 3, fa.N - 1, fa.N - 2]
    scalars += [1 << bit for bit in range(256)]
    scalars += [rng.randrange(fa.N) for _ in range(128)]
    seen = set()
    cases = []
    for scalar in scalars:
        if scalar in seen:
            continue
        seen.add(scalar)
        cases.append({"id": f"scalarmul-{len(cases):04d}", "k": hex32(scalar)})
    return cases


def make_ecdsa(rng: random.Random) -> list[dict]:
    cases = []

    def add_case(private_key: int, digest: bytes, nonce: int, source: str):
        point = ref_ec.mul_g_affine(nonce)
        r = point[0] % fa.N
        s = (fa.inv_mod(nonce, fa.N) *
             (ref_ecdsa.digest_to_z(digest) % fa.N + r * private_key)) % fa.N
        if r == 0 or s == 0:
            return False
        public = ref_ec.mul_g_affine(private_key)
        cases.append({
            "id": f"ecdsa-{len(cases):04d}",
            "digest": digest.hex(),
            "d": hex32(private_key),
            "k": hex32(nonce),
            "kinv": hex32(fa.inv_mod(nonce, fa.N)),
            "r": hex32(r),
            "s": hex32(s),
            "qx": hex32(public[0]),
            "qy": hex32(public[1]),
            "source": source,
        })
        return True

    sample_digest = ref_symmetric.sha256(b"sample")
    if not add_case(RFC6979_D, sample_digest, RFC6979_K,
                    "RFC 6979 A.2.5 P-256/SHA-256 \"sample\""):
        raise RuntimeError("RFC 6979 vector did not produce a usable signature")

    fixed = [(1, ref_symmetric.sha256(b"etp5-fixed-1")),
             (fa.N - 1, ref_symmetric.sha256(b"etp5-fixed-2"))]
    for private_key, digest in fixed:
        while True:
            nonce = rng.randrange(1, fa.N)
            if add_case(private_key, digest, nonce, "fixed boundary key"):
                break

    attempts = 0
    while len(cases) < 67 and attempts < 10000:
        attempts += 1
        private_key = rng.randrange(1, fa.N)
        digest = rng.getrandbits(256).to_bytes(32, "big")
        nonce = rng.randrange(1, fa.N)
        add_case(private_key, digest, nonce, "pseudo-random")

    for case in cases:
        r = int(case["r"], 16)
        s = int(case["s"], 16)
        tampered = (s + 1) % fa.N
        if tampered == 0:
            tampered = 1
        case["s_tampered"] = hex32(tampered)
    return cases


def make_rsa(rng: random.Random, key: dict) -> list[dict]:
    values = [0, 1, 2, key["n"] - 1, key["n"] - 2,
              (1 << 2047) % key["n"], ((1 << 2048) - 1) % key["n"]]
    values += [rng.randrange(key["n"]) for _ in range(32)]
    cases = []
    for value in values:
        cases.append({
            "id": f"rsa-{len(cases):04d}",
            "m": hex32(value),
        })
    return cases


def make_sha256(rng: random.Random) -> list[dict]:
    published = [
        (b"", "empty"),
        (b"abc", "FIPS 180-4 example"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "FIPS 180-4 448-bit example"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
         b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "FIPS 180-4 896-bit example"),
    ]
    cases = []
    for data, source in published:
        cases.append({
            "id": f"sha256-{len(cases):04d}",
            "data": data.hex(),
            "source": source,
        })
    for length in list(range(0, 65)) + [127, 128, 129, 255, 256, 1000]:
        data = bytes(rng.getrandbits(8) for _ in range(length))
        cases.append({
            "id": f"sha256-{len(cases):04d}",
            "data": data.hex(),
            "source": f"pseudo-random length {length}",
        })
    return cases


def dump(path: str, obj) -> None:
    text = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    with open(path, "w", encoding="ascii") as handle:
        handle.write(text)


def build_all() -> dict:
    rng = random.Random(SEED_INT)
    key_path = os.path.join(VECTOR_DIR, "rsa_key.json")
    if os.path.exists(key_path):
        with open(key_path, "r", encoding="ascii") as handle:
            key = ref_rsa.key_from_json(json.load(handle))
    else:
        key = ref_rsa.generate_key(SEED)
    return {
        "field_order.json": make_field_order(rng),
        "scalarmul.json": make_scalarmul(rng),
        "ecdsa.json": make_ecdsa(rng),
        "rsa_key.json": ref_rsa.key_to_json(key),
        "rsa.json": make_rsa(rng, key),
        "sha256.json": make_sha256(rng),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="compare against the tracked vectors instead of writing")
    parser.add_argument("--force-key", action="store_true",
                        help="regenerate the RSA key from the seed")
    args = parser.parse_args()

    os.makedirs(VECTOR_DIR, exist_ok=True)
    if args.force_key:
        key = ref_rsa.generate_key(SEED)
        dump(os.path.join(VECTOR_DIR, "rsa_key.json"),
             ref_rsa.key_to_json(key))

    generated = build_all()
    if args.check:
        mismatches = []
        for name, obj in generated.items():
            path = os.path.join(VECTOR_DIR, name)
            expected = json.dumps(obj, indent=2, sort_keys=True) + "\n"
            if not os.path.exists(path):
                mismatches.append(f"{name}: missing")
                continue
            with open(path, "r", encoding="ascii") as handle:
                actual = handle.read()
            if actual != expected:
                mismatches.append(f"{name}: differs")
        if mismatches:
            print("vector check FAILED: " + "; ".join(mismatches))
            return 1
        print(f"vector check OK: {len(generated)} files")
        return 0

    for name, obj in generated.items():
        dump(os.path.join(VECTOR_DIR, name), obj)
        count = len(obj) if isinstance(obj, list) else 1
        print(f"wrote {name}: {count} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
