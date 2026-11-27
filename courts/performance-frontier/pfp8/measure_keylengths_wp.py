#!/usr/bin/env python3
"""measure_keylengths_wp.py — PFP8-WIDTH-POLICY: observe the private-key width
each library actually generates, per prepared group.

Eight real `DH_generate_key` pairs per group per library. The table records the
largest observed bit length and the limb count `ceil(bits / 64)`, which is the
policy width the ladder is allowed to run.

Run inside the court via `run_keylengths_wp.sh`.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

BENCH = os.environ.get("PFP8_BENCH", "/work/court/tmp/pfp8-wp/bench_pfp8_wp")
CAND = os.environ.get(
    "PFP8_CAND", "/work/court/tmp/pfp8-wp-build/cand/distribution/libcrypto.so.3"
)
AUTH = os.environ.get(
    "PFP8_AUTH",
    "/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3",
)
EV = Path("/work/evidence/performance-frontier/campaigns/PFP-8/width-policy")

# name, NID, the authority's `ffc_dh.c` key length (0 = no policy width)
GROUPS = [
    ("ffdhe2048", 1126, 225),
    ("ffdhe3072", 1127, 275),
    ("ffdhe4096", 1128, 325),
    ("ffdhe6144", 1129, 375),
    ("ffdhe8192", 1130, 400),
    ("modp1536", 1212, 200),
    ("modp2048", 1213, 225),
    ("modp3072", 1214, 275),
    ("modp4096", 1215, 325),
    ("modp6144", 1216, 375),
    ("modp8192", 1217, 400),
]
SAMPLES = 8


def _sha256(path: str) -> str:
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def gen(lib: str, nid: int) -> int:
    proc = subprocess.run(
        [BENCH, "--lib", lib, "--op", "keygen-once", "--nid", str(nid)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"keygen-once failed for {lib} nid {nid}")
    for line in proc.stdout.splitlines():
        if line.startswith("CHECK keygen-priv hex="):
            return int(line.split("hex=", 1)[1], 16)
    raise SystemExit(f"no private key for {lib} nid {nid}")


def main() -> int:
    rows = []
    for name, nid, keylength in GROUPS:
        for libname, lib in (("candidate", CAND), ("authority", AUTH)):
            bits = [gen(lib, nid).bit_length() for _ in range(SAMPLES)]
            limbs = (max(bits) + 63) // 64 if max(bits) else 0
            rows.append({
                "group": name,
                "nid": nid,
                "library": libname,
                "keylength": keylength,
                "keylength_limbs": (keylength + 63) // 64 if keylength else 0,
                "max_bits": max(bits),
                "max_limbs": limbs,
            })
            print(f"{name:12s} {libname:10s} keylength={keylength:3d} "
                  f"max_bits={max(bits):3d} limbs={limbs}")
    (EV / "raw" / "keylengths.json").write_text(
        json.dumps(
            {
                "samples": SAMPLES,
                "candidate": CAND,
                "candidate_sha256": _sha256(CAND),
                "authority": AUTH,
                "authority_sha256": _sha256(AUTH),
                "rows": rows,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="ascii",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
