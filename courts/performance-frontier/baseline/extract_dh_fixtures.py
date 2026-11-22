#!/usr/bin/env python3
"""Derive the real FFDHE/MODP DH fixtures from tracked repository bytes.

The benchmark population must contain real named groups, not only a synthetic
odd composite. The bytes are not fetched and not invented: this tool reads the
arrays in `src/bn/dh_data.rs`, which are tracked and were themselves regenerated
from the admitted authority (`forensics/tools/gen_bn_dh.py`).

Outputs, one per group:

    ffdhe2048.hex    p=<hex>\\nq=<hex>\\n
    ffdhe3072.hex
    modp2048.hex

and a machine-readable `dh-fixtures.json` recording the source file digest, the
array names, the extracted lengths and the output digests. The checks below are
arithmetic facts about safe-prime groups, not authority comparisons:

  * the declared array length equals the extracted byte count;
  * bit lengths match the group name;
  * p == 2*q + 1;
  * p mod 8 == 7 (so g = 2 has order q for these safe primes).

Usage:
    python3 courts/performance-frontier/baseline/extract_dh_fixtures.py \\
        --source src/bn/dh_data.rs --out <directory>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

GROUPS = {
    "ffdhe2048": ("OSSL_BIGNUM_FFDHE2048_P_BYTES", "OSSL_BIGNUM_FFDHE2048_Q_BYTES", 2048),
    "ffdhe3072": ("OSSL_BIGNUM_FFDHE3072_P_BYTES", "OSSL_BIGNUM_FFDHE3072_Q_BYTES", 3072),
    "modp2048": ("OSSL_BIGNUM_MODP_2048_P_BYTES", "OSSL_BIGNUM_MODP_2048_Q_BYTES", 2048),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_array(text: str, name: str) -> bytes:
    pattern = re.compile(
        r"const\s+" + re.escape(name) + r"\s*:\s*\[u8;\s*(\d+)\]\s*=\s*\[(.*?)\];",
        re.DOTALL,
    )
    match = pattern.search(text)
    if match is None:
        raise SystemExit(f"extract_dh_fixtures: array {name} not found")
    declared = int(match.group(1))
    body = match.group(2)
    octets = re.findall(r"0x([0-9A-Fa-f]{2})", body)
    if len(octets) != declared:
        raise SystemExit(
            f"extract_dh_fixtures: {name} declares {declared} bytes, "
            f"extracted {len(octets)}"
        )
    return bytes(int(o, 16) for o in octets)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("src/bn/dh_data.rs"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    source_bytes = args.source.read_bytes()
    text = source_bytes.decode("utf-8")
    args.out.mkdir(parents=True, exist_ok=True)

    manifest = {
        "schema": "openssl-rs/performance/dh-fixtures/v1",
        "source": str(args.source),
        "source_sha256": sha256(source_bytes),
        "groups": {},
    }

    for group, (p_name, q_name, bits) in GROUPS.items():
        p = extract_array(text, p_name)
        q = extract_array(text, q_name)
        p_int = int.from_bytes(p, "big")
        q_int = int.from_bytes(q, "big")

        if p_int.bit_length() != bits:
            raise SystemExit(f"{group}: p is {p_int.bit_length()} bits, not {bits}")
        if p_int != 2 * q_int + 1:
            raise SystemExit(f"{group}: p != 2*q + 1")
        if p_int % 8 != 7:
            raise SystemExit(f"{group}: p mod 8 is {p_int % 8}, not 7")

        body = f"p={p.hex()}\nq={q.hex()}\n"
        dest = args.out / f"{group}.hex"
        dest.write_text(body, encoding="ascii")
        manifest["groups"][group] = {
            "p_array": p_name,
            "q_array": q_name,
            "bits": bits,
            "p_bytes": len(p),
            "q_bytes": len(q),
            "p_sha256": sha256(p),
            "q_sha256": sha256(q),
            "file": dest.name,
            "file_sha256": sha256(body.encode("ascii")),
        }

    (args.out / "dh-fixtures.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
