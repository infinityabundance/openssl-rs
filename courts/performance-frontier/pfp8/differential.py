#!/usr/bin/env python3
"""PFP-8 differential: key generation and shared secret, candidate vs the
OpenSSL 3.6.4 authority, named path vs the explicitly-loaded path.

Run inside the court:

  python3 courts/performance-frontier/pfp8/differential.py

Inputs are the tracked fixtures under campaigns/PFP-1/performance/fixtures and
the deterministic operands written by run_profile.sh.  The candidate's
`DH_generate_key` with a caller-supplied private key is refused by the current
source (PFP8-KEYGEN-PRESET-PRIV); key generation is therefore cross-checked as
`g^priv` through the *other* library's `DH_compute_key(g, priv)`, which is the
same exponentiation the public-key path performs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

BENCH = os.environ.get("PFP8_BENCH", "/work/court/tmp/pfp8/bench_pfp8")
CAND = os.environ.get(
    "PFP8_CAND", "/work/court/tmp/ma1/cand/distribution/libcrypto.so.3"
)
AUTH = os.environ.get(
    "PFP8_AUTH",
    "/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3",
)
EV = Path("/work/evidence/performance-frontier/campaigns/PFP-8")
FIX = Path(
    "/work/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"
)

GROUPS = [("ffdhe2048", 1126), ("ffdhe3072", 1127), ("modp2048", 1213)]


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


def main() -> int:
    operands = {}
    for line in (EV / "raw" / "operands.env").read_text().splitlines():
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
        rows.append(
            {"case": case, "equal": False, "classification": "PFP8-KEYGEN-PRESET-PRIV",
             "detail": detail}
        )
        stops.append({"case": case, "detail": detail})
        print(f"STOP {case}: {detail}")

    # --- shared secret, both exponent widths, named vs named and vs explicit
    for group, nid in GROUPS:
        for bits, priv_key, peer_key in (
            (2048, "PRIV2048", "PEER2048"),
            (225, "PRIV225", "PEER225"),
        ):
            priv, peer = operands[priv_key], operands[peer_key]
            rc_c, out_c = run(CAND, "compute", "--nid", str(nid), "--priv", priv,
                              "--peer", peer, "--iters", "1", "--runs", "1")
            rc_a, out_a = run(AUTH, "compute", "--nid", str(nid), "--priv", priv,
                              "--peer", peer, "--iters", "1", "--runs", "1")
            c, a = hex_of("dh-compute-named", out_c), hex_of("dh-compute-named", out_a)
            record(
                f"{group}/compute/{bits}",
                rc_c == 0 and rc_a == 0 and c == a and bool(c),
                f"rc_c={rc_c} rc_a={rc_a} len_c={len(c)} len_a={len(a)}",
            )
            rc_e, out_e = run(CAND, "compute", "--params", str(FIX / f"{group}.hex"),
                              "--priv", priv, "--peer", peer, "--iters", "1",
                              "--runs", "1")
            e = hex_of("dh-compute-explicit", out_e)
            record(
                f"{group}/compute/{bits}/named-vs-explicit",
                rc_e == 0 and c == e and bool(c),
                f"rc_e={rc_e} len_c={len(c)} len_e={len(e)}",
            )

    # --- key generation: candidate pair verified by the authority and back
    for group, nid in GROUPS:
        rc_c, out_c = run(CAND, "keygen-once", "--nid", str(nid))
        rc_a, out_a = run(AUTH, "keygen-once", "--nid", str(nid))
        c_priv = hex_of("keygen-priv", out_c)
        c_pub = hex_of("keygen-pub", out_c)
        a_priv = hex_of("keygen-priv", out_a)
        a_pub = hex_of("keygen-pub", out_a)
        record(
            f"{group}/keygen/candidate-shaped",
            rc_c == 0 and rc_a == 0 and bool(c_priv) and bool(c_pub)
            and bool(a_priv) and bool(a_pub),
            f"rc_c={rc_c} rc_a={rc_a}",
        )
        if rc_c == 0 and c_priv and c_pub:
            rc_v, out_v = run(AUTH, "compute", "--nid", str(nid), "--priv",
                              c_priv, "--peer", "02", "--iters", "1", "--runs", "1")
            v = hex_of("dh-compute-named", out_v)
            record(
                f"{group}/keygen/candidate-pub-verified-by-authority",
                rc_v == 0 and v == c_pub,
                f"rc_v={rc_v} len_v={len(v)} len_pub={len(c_pub)} "
                f"v={v[:32]} pub={c_pub[:32]}",
            )
        if rc_a == 0 and a_priv and a_pub:
            rc_v, out_v = run(CAND, "compute", "--nid", str(nid), "--priv",
                              a_priv, "--peer", "02", "--iters", "1", "--runs", "1")
            v = hex_of("dh-compute-named", out_v)
            record(
                f"{group}/keygen/authority-pub-verified-by-candidate",
                rc_v == 0 and v == a_pub,
                f"rc_v={rc_v} len_v={len(v)} len_pub={len(a_pub)} "
                f"v={v[:32]} pub={a_pub[:32]}",
            )
        # The preset-private-key key generation path, recorded as a refusal.
        rc_cf, out_cf = run(CAND, "keygen-fixed", "--nid", str(nid), "--priv",
                            operands["PRIV225"], "--iters", "1", "--runs", "1")
        rc_af, out_af = run(AUTH, "keygen-fixed", "--nid", str(nid), "--priv",
                            operands["PRIV225"], "--iters", "1", "--runs", "1")
        preset_ok = (
            rc_cf == 0 and rc_af == 0 and bool(hex_of("keygen-fixed", out_cf))
        )
        preset_detail = (
            f"rc_c={rc_cf} rc_a={rc_af} "
            f"cand_pub={len(hex_of('keygen-fixed', out_cf))} "
            f"auth_pub={len(hex_of('keygen-fixed', out_af))}"
        )
        if preset_ok:
            record(f"{group}/keygen/preset-private", True, preset_detail)
        else:
            record_stop(
                f"{group}/keygen/preset-private",
                preset_detail
                + "; candidate refuses a caller-supplied private key where the "
                "authority computes the public key (PFP8-KEYGEN-PRESET-PRIV)",
            )

    # --- refusal return codes for malformed peer values
    for group, nid in GROUPS:
        vals = fixture(group)
        p = vals["p"]
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
            if not peer_hex:
                peer_hex = "00"
            rc_c, out_c = run(CAND, "rc", "--nid", str(nid), "--priv",
                              operands["PRIV2048"], "--peer", peer_hex)
            rc_a, out_a = run(AUTH, "rc", "--nid", str(nid), "--priv",
                              operands["PRIV2048"], "--peer", peer_hex)
            c_rc = out_c.strip().split()[-1] if out_c.strip() else "none"
            a_rc = out_a.strip().split()[-1] if out_a.strip() else "none"
            record(
                f"{group}/refusal/{name}",
                rc_c == 0 and rc_a == 0 and c_rc == a_rc,
                f"cand_rc={c_rc} auth_rc={a_rc} exit_c={rc_c} exit_a={rc_a}",
            )

    summary = {
        "comparisons": len(rows),
        "mismatches": mismatches,
        "stops": stops,
        "candidate": CAND,
        "authority": AUTH,
        "rows": rows,
    }
    (EV / "raw" / "differential.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    print(f"DIFFERENTIAL comparisons={len(rows)} mismatches={mismatches} "
          f"stops={len(stops)}")
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
