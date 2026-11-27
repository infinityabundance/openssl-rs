#!/usr/bin/env python3
"""PFP8-WIDTH-POLICY differential: key generation and shared secret, candidate
(new policy-width ladder) vs the OpenSSL 3.6.4 authority, over every prepared
named group.

Run inside the court:

  python3 courts/performance-frontier/pfp8/differential_wp.py

For each prepared group (nonzero RFC 7919 / MODP key length) the script compares,
byte for byte:

  * the shared secret for a policy-width private exponent (`PRIV225`, 230 bits:
    the ladder runs the group's declared bound, not the modulus);
  * the shared secret for a full-width benchmark exponent where the modulus is at
    least 2048 bits (the policy falls back; behaviour must be unchanged);
  * `g^priv mod p` for the same private exponent in both libraries — the
    exponentiation key generation performs — including the candidate's and the
    authority's own freshly generated pairs, recomputed by the other library;
  * named vs explicitly-loaded construction for the three tracked fixtures;
  * the 21 malformed-peer return codes of the PFP-8 record.

The pre-existing `PFP8-KEYGEN-PRESET-PRIV` divergence (a caller-supplied private
key is not exponentiated) is re-recorded, not repaired, and not counted as a
mismatch of this change.
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
FIX = Path(
    "/work/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"
)

# Every prepared group: the authority's `ffc_dh.c` key lengths (225/275/325/
# 375/400), expressed as `ceil(bits / 64)` limbs.
GROUPS = [
    ("ffdhe2048", 1126, 2048),
    ("ffdhe3072", 1127, 3072),
    ("ffdhe4096", 1128, 4096),
    ("ffdhe6144", 1129, 6144),
    ("ffdhe8192", 1130, 8192),
    ("modp1536", 1212, 1536),
    ("modp2048", 1213, 2048),
    ("modp3072", 1214, 3072),
    ("modp4096", 1215, 4096),
    ("modp6144", 1216, 6144),
    ("modp8192", 1217, 8192),
]
FIXTURE_GROUPS = [("ffdhe2048", 1126), ("ffdhe3072", 1127), ("modp2048", 1213)]


def fixture(group: str) -> dict[str, int]:
    values = {}
    for line in (FIX / f"{group}.hex").read_text(encoding="ascii").splitlines():
        key, _, raw = line.partition("=")
        if key in ("p", "q"):
            values[key] = int(raw, 16)
    return values


def run(lib: str, op: str, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        [BENCH, "--lib", lib, "--op", op, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout


def hex_of(op: str, output: str) -> str:
    for line in output.splitlines():
        if line.startswith(f"CHECK {op} hex="):
            return line.split("hex=", 1)[1]
    return ""


def compute(lib: str, nid: int, priv: str, peer: str) -> tuple[int, str]:
    rc, out = run(lib, "compute", "--nid", str(nid), "--priv", priv, "--peer", peer,
                  "--iters", "1", "--runs", "1")
    return rc, hex_of("dh-compute-named", out)


def main() -> int:
    operands = {}
    for line in (EV / "raw" / "operands-wp.env").read_text().splitlines():
        key, _, value = line.partition("=")
        operands[key] = value

    rows = []
    mismatches = 0
    stops = []

    def record(case: str, equal: bool, detail: str) -> None:
        nonlocal mismatches
        rows.append({"case": case, "equal": equal, "detail": detail})
        if not equal:
            mismatches += 1
            print(f"MISMATCH {case}: {detail}")

    def record_stop(case: str, detail: str) -> None:
        rows.append({"case": case, "equal": False,
                     "classification": "PFP8-KEYGEN-PRESET-PRIV", "detail": detail})
        stops.append({"case": case, "detail": detail})
        print(f"KNOWN-STOP {case}: {detail}")

    priv225 = operands["PRIV225"]
    peer225 = operands["PEER225"]
    priv2048 = operands.get("PRIV2048", "")
    peer2048 = operands.get("PEER2048", "")

    # --- shared secret and same-exponent public key, per prepared group
    for group, nid, bits in GROUPS:
        # Policy-width exponent (230 bits -> 4 limbs).
        rc_c, c = compute(CAND, nid, priv225, peer225)
        rc_a, a = compute(AUTH, nid, priv225, peer225)
        record(
            f"{group}/ss/priv225",
            rc_c == 0 and rc_a == 0 and c == a and bool(c),
            f"rc_c={rc_c} rc_a={rc_a} len_c={len(c)} len_a={len(a)}",
        )
        # g^priv for the same private exponent: what key generation computes.
        rc_c, c = compute(CAND, nid, priv225, "02")
        rc_a, a = compute(AUTH, nid, priv225, "02")
        record(
            f"{group}/g^priv/priv225",
            rc_c == 0 and rc_a == 0 and c == a and bool(c),
            f"rc_c={rc_c} rc_a={rc_a} len_c={len(c)} len_a={len(a)}",
        )
        if bits >= 2048:
            # Full-width exponent: the policy falls back to the modulus width.
            rc_c, c = compute(CAND, nid, priv2048, peer2048)
            rc_a, a = compute(AUTH, nid, priv2048, peer2048)
            record(
                f"{group}/ss/priv2048",
                rc_c == 0 and rc_a == 0 and c == a and bool(c),
                f"rc_c={rc_c} rc_a={rc_a} len_c={len(c)} len_a={len(a)}",
            )

    # --- key generation: each library's own pair, recomputed by both libraries
    for group, nid, _bits in GROUPS:
        for tag, lib in (("candidate", CAND), ("authority", AUTH)):
            rc, out = run(lib, "keygen-once", "--nid", str(nid))
            priv = hex_of("keygen-priv", out)
            pub = hex_of("keygen-pub", out)
            record(
                f"{group}/keygen/{tag}/shape",
                rc == 0 and bool(priv) and bool(pub),
                f"rc={rc}",
            )
            if rc != 0 or not priv or not pub:
                continue
            rc_c, c = compute(CAND, nid, priv, "02")
            rc_a, a = compute(AUTH, nid, priv, "02")
            record(
                f"{group}/keygen/{tag}/g^priv-identical",
                rc_c == 0 and rc_a == 0 and c == pub and a == pub,
                f"rc_c={rc_c} rc_a={rc_a} len_pub={len(pub)}",
            )

    # --- named vs explicitly-loaded construction (tracked fixtures)
    for group, nid in FIXTURE_GROUPS:
        for priv, peer, label in (
            (priv225, peer225, "priv225"),
            (priv2048, peer2048, "priv2048"),
        ):
            rc_n, named = run(CAND, "compute", "--nid", str(nid), "--priv", priv,
                              "--peer", peer, "--iters", "1", "--runs", "1")
            rc_e, out_e = run(CAND, "compute", "--params", str(FIX / f"{group}.hex"),
                              "--priv", priv, "--peer", peer, "--iters", "1",
                              "--runs", "1")
            named_hex = hex_of("dh-compute-named", named)
            explicit_hex = hex_of("dh-compute-explicit", out_e)
            record(
                f"{group}/named-vs-explicit/{label}",
                rc_n == 0 and rc_e == 0 and named_hex == explicit_hex
                and bool(named_hex),
                f"rc_n={rc_n} rc_e={rc_e} len_n={len(named_hex)} "
                f"len_e={len(explicit_hex)}",
            )

    # --- refusal return codes for malformed peer values (the PFP-8 21)
    for group, nid in FIXTURE_GROUPS:
        p = fixture(group)["p"]
        peers = {
            "zero": 0,
            "one": 1,
            "p-2": p - 2,
            "p-1": p - 1,
            "p": p,
            "p+1": p + 1,
            "two": 2,
        }
        for name, value in peers.items():
            peer_hex = format(value, "x")
            if len(peer_hex) % 2:
                peer_hex = "0" + peer_hex
            rc_c, out_c = run(CAND, "rc", "--nid", str(nid), "--priv", priv2048,
                              "--peer", peer_hex)
            rc_a, out_a = run(AUTH, "rc", "--nid", str(nid), "--priv", priv2048,
                              "--peer", peer_hex)
            c_rc = out_c.strip().split()[-1] if out_c.strip() else "none"
            a_rc = out_a.strip().split()[-1] if out_a.strip() else "none"
            record(
                f"{group}/refusal/{name}",
                rc_c == 0 and rc_a == 0 and c_rc == a_rc,
                f"cand_rc={c_rc} auth_rc={a_rc} exit_c={rc_c} exit_a={rc_a}",
            )

    # --- known, pre-existing divergence: a caller-supplied private key
    for group, nid, _bits in GROUPS[:3]:
        rc_c, out_c = run(CAND, "keygen-fixed", "--nid", str(nid), "--priv",
                          priv225, "--iters", "1", "--runs", "1")
        rc_a, out_a = run(AUTH, "keygen-fixed", "--nid", str(nid), "--priv",
                          priv225, "--iters", "1", "--runs", "1")
        record_stop(
            f"{group}/keygen/preset-private",
            f"rc_c={rc_c} rc_a={rc_a} "
            f"cand_pub={len(hex_of('keygen-fixed', out_c))} "
            f"auth_pub={len(hex_of('keygen-fixed', out_a))}",
        )

    comparisons = len(rows) - len(stops)
    summary = {
        "comparisons": comparisons,
        "mismatches": mismatches,
        "stops": stops,
        "candidate": CAND,
        "authority": AUTH,
        "rows": rows,
    }
    (EV / "raw" / "differential.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    print(f"DIFFERENTIAL comparisons={comparisons} mismatches={mismatches} "
          f"known_stops={len(stops)}")
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
