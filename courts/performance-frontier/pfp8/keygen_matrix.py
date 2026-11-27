#!/usr/bin/env python3
"""PFP8-KEYGEN-PRESET-PRIV matrix: the four `DH_generate_key` key-state
combinations, candidate vs the OpenSSL 3.6.4 authority.

The expected values come from the authority: `crypto/dh/dh_key.c:265-387`
calls `ossl_dh_generate_public_key()` *outside* its `if (generate_new_key)`
block, so all four combinations derive `g^priv mod p` and return 1; the only
failure is an allocation/exponentiation failure, which raises
`ERR_LIB_DH:ERR_R_BN_LIB`.

Run inside the court:

  python3 courts/performance-frontier/pfp8/keygen_matrix.py \
      --cand /work/court/tmp/.../libcrypto.so.3 \
      [--old /work/court/tmp/.../old.so.3] \
      --out /work/evidence/.../raw/preset-priv-matrix.json

One probe process per case: no state leaks between rows.  For the from-scratch
rows the public value is random, so it is *not* compared across libraries (only
its presence, the return code and the error queue are); for every preset-private
row the public value is `g^priv mod p` and is compared byte for byte.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

EV = Path("/work/evidence/performance-frontier/campaigns/PFP-8")
FIX = Path(
    "/work/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"
)
PROBE = Path("/work/court/tmp/pfp8/keygen_matrix")

AUTH = "/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
GROUPS = [("ffdhe2048", 1126), ("ffdhe3072", 1127), ("modp2048", 1213)]


def operands() -> dict[str, str]:
    values = {}
    for line in (EV / "raw" / "operands.env").read_text().splitlines():
        key, _, value = line.partition("=")
        values[key] = value
    return values


def priv_specs(ops: dict[str, str]) -> list[tuple[str, str]]:
    """The preset-private-key populations: a group-sized exponent, an exponent
    shorter than any group's declared private-key bound, one longer than that
    bound but within the 2048-bit modulus, and one wider than the modulus."""
    return [
        ("in_bound_225", ops["PRIV225"]),
        ("short_1bit", "01"),
        ("long_modulus_2048", ops["PRIV2048"]),
        ("long_2400bit", "ab" * 300),
    ]


def run_probe(lib: str, group: str, nid: int, case: str, priv: str,
              pub: str) -> dict:
    proc = subprocess.run(
        [str(PROBE), "--lib", lib, "--nid", str(nid), "--case", case,
         "--priv", priv, "--pub", pub],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if not line:
        return {
            "case": case, "rc": None, "pub_present": False,
            "priv_present_after": False, "pub_is_sentinel": False, "errs": [],
            "pub": None, "crash": True, "exit": proc.returncode,
            "stderr": proc.stderr.strip()[-200:],
        }
    row = json.loads(line)
    row["crash"] = False
    row["exit"] = proc.returncode
    return row


def compare(o: dict, a: dict, fields: list[str]) -> tuple[bool, list[str]]:
    diffs = []
    for field in fields:
        if o.get(field) != a.get(field):
            diffs.append(f"{field}: cand={o.get(field)!r} auth={a.get(field)!r}")
    return (not diffs), diffs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cand", required=True)
    ap.add_argument("--auth", default=AUTH)
    ap.add_argument("--old", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--txt", default=None)
    args = ap.parse_args()

    ops = operands()
    presets = priv_specs(ops)
    rows = []
    mismatches = 0

    # (name, priv selector, pub selector, comparable public value)
    combos = [
        ("priv_absent_pub_absent", "absent", "absent", False),
        ("priv_preset_pub_absent", "preset", "absent", True),
        ("priv_absent_pub_present", "absent", "present", False),
        ("priv_preset_pub_present", "preset", "present", True),
    ]

    for group, nid in GROUPS:
        for combo, priv_kind, pub_kind, pub_comparable in combos:
            specs = presets if priv_kind == "preset" else [("none", "absent")]
            for preset_name, priv in specs:
                case = f"{group}/nid/{combo}"
                if priv_kind == "preset":
                    case = f"{group}/nid/{combo}/{preset_name}"
                c = run_probe(args.cand, group, nid, case, priv, pub_kind)
                a = run_probe(args.auth, group, nid, case, priv, pub_kind)
                fields = ["rc", "pub_present", "pub_is_sentinel",
                          "priv_present_after", "errs"]
                if pub_comparable:
                    fields.append("pub")
                equal, diffs = compare(c, a, fields)
                if not equal:
                    mismatches += 1
                row = {
                    "case": case,
                    "group": group,
                    "nid": nid,
                    "combo": combo,
                    "preset": preset_name,
                    "pub_comparable": pub_comparable,
                    "equal": equal,
                    "diffs": diffs,
                    "cand": c,
                    "auth": a,
                }
                if args.old is not None:
                    o = run_probe(args.old, group, nid, case, priv, pub_kind)
                    old_fields = list(fields)
                    old_equal, old_diffs = compare(o, c, old_fields)
                    row["old"] = o
                    row["old_equal"] = old_equal
                    row["old_diffs"] = old_diffs
                rows.append(row)
                status = "OK " if equal else "MISMATCH"
                extra = "" if args.old is None else \
                    (" old==new" if row["old_equal"] else f" OLD_DIFF {row['old_diffs']}")
                print(f"{status} {case}: rc={c.get('rc')} pub={c.get('pub_present')} "
                      f"errs={c.get('errs')}{extra}")
                for d in diffs:
                    print(f"    {d}")

    summary = {
        "authority": args.auth,
        "candidate": args.cand,
        "old": args.old,
        "rows": len(rows),
        "mismatches": mismatches,
        "authority_source": "crypto/dh/dh_key.c:265-387 (call site at :370)",
        "detail": rows,
    }
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                                  encoding="ascii")
    if args.txt:
        Path(args.txt).write_text(
            f"rows={len(rows)} mismatches={mismatches}\n", encoding="ascii")
    print(f"MATRIX rows={len(rows)} mismatches={mismatches}")
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
