#!/usr/bin/env python3
"""openssl-rs -- the Phase-11.2 / Phase-22 X.509 closure gate, and it is fail-closed.

Phase 22 exists because the verification engine is the subsystem where discovering an omitted
callback, config flag, static dispatch path, error path or policy table *after* it is written is
expensive. `docs/PHASE-22-SUBPHASES.md` section 8 makes that a dependency, and
`forensics/tools/phase_state.py`'s `REQUIRES` enforces it at **stratum** granularity: Phase 11
cannot be `complete` while Phase 22 is open.

That is not the whole rule. A stratum-level edge stops a `complete`; it does not stop somebody from
implementing `X509_verify_cert`, `x509_vpm.c` and `pcy_tree.c` tomorrow, which is the actual thing
the dependency is for. This gate is the subphase-level half: it refuses a **newly implemented**
export of Phase 11.2's three units while the Phase-22 X.509 closure slice is unsatisfied.

What it reads
-------------
  * `forensics/atlas/export-defining-units.json` -- the exports `crypto/x509/x509_vfy.c`,
    `crypto/x509/x509_vpm.c` and `crypto/x509/pcy_tree.c` define (Phase 11.2's units);
  * `forensics/phase11-obligations.json` -- which of them are implemented **now**;
  * `forensics/phase22/x509-closure-slice-baseline.json` -- the frozen set that was already
    implemented when Phase 22 was activated. A baseline rather than "zero implemented", because
    Phase 10's pulled-forward subphases legitimately landed part of these units before Phase 22
    existed, and a gate that fired on the work already done would be a gate nobody could pass;
  * `forensics/atlas/phase22/compatibility-closure.json` -- 22.14's closure, whose `body.x509_slice`
    this tool reads. That slice is the contract 22.14 must satisfy:

        body.x509_slice = {
            "roots": [...],            # the X.509 root families the slice covers
            "satisfied": true|false,   # no UNKNOWN residual intersects any of them
            "unknown_residuals": [...] # the residuals that block it when false
        }

The gate passes while the implemented set equals the baseline. It fails the moment the set grows
and the slice is not satisfied, naming the exports that grew. `--freeze` rewrites the baseline from
the current ledger and is for the activation commit only: re-freezing after work has landed is how
a gate stops being a gate.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel, write_json  # noqa: E402

LEDGER = REPO_ROOT / "forensics" / "phase11-obligations.json"
UNITS = REPO_ROOT / "forensics" / "atlas" / "export-defining-units.json"
BASELINE = REPO_ROOT / "forensics" / "phase22" / "x509-closure-slice-baseline.json"
CLOSURE = REPO_ROOT / "forensics" / "atlas" / "phase22" / "compatibility-closure.json"

# Phase 11.2's three units, from `docs/PHASE-11-SUBPHASES.md` section 2's row.
UNITS_11_2 = (
    "crypto/x509/x509_vfy.c",
    "crypto/x509/x509_vpm.c",
    "crypto/x509/pcy_tree.c",
)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def unit_exports() -> list[str]:
    body = read_json(UNITS)["body"]
    out: list[str] = []
    for unit in UNITS_11_2:
        out.extend(body["by_translation_unit"].get(unit, []))
    return sorted(set(out))


def implemented_now(name: str) -> list[str]:
    """The exports of Phase 11.2's units the ledger records as implemented."""
    body = read_json(LEDGER)["body"]
    implemented = set(body["implemented"])
    return [s for s in unit_exports() if s in implemented]


def slice_state() -> tuple[bool, str]:
    """22.14's X.509 closure slice: (satisfied, a sentence saying why)."""
    if not CLOSURE.is_file():
        return False, (f"{rel(CLOSURE)} does not exist yet, so the slice cannot be satisfied "
                       f"(22.14 lands it)")
    body = read_json(CLOSURE).get("body", {})
    slice_ = body.get("x509_slice")
    if not isinstance(slice_, dict):
        return False, (f"{rel(CLOSURE)} carries no `body.x509_slice` block, which is the contract "
                       f"this gate reads (docs/PHASE-11-SUBPHASES.md section 2, row 11.2)")
    if slice_.get("satisfied") is not True:
        unknown = slice_.get("unknown_residuals") or []
        return False, (f"the closure graph records the slice unsatisfied"
                       + (f" with {len(unknown)} blocking residual(s)" if unknown else ""))
    return True, "the closure graph records the X.509 slice satisfied"


def judge(current: list[str], baseline: set[str], satisfied: bool) -> list[str]:
    """The rule, as a pure function: the grown exports that the slice does not excuse.

    Empty when nothing grew, or when the slice is satisfied. A gate is only evidence if it has been
    seen to fire, so this is factored out for `--self-test` rather than buried in `main`.
    """
    grown = sorted(set(current) - baseline)
    if grown and not satisfied:
        return grown
    return []


def self_test() -> int:
    """Reconstruct the shape the gate exists to stop, and require the rule to refuse it.

    The shape is a *new* export of Phase 11.2's units with the closure slice unsatisfied -- the
    thing the stratum-level `REQUIRES` edge cannot see, because it only fires on a `complete`.
    """
    current = implemented_now("")
    baseline = set(current)
    grown_ok = judge(current + ["X509_VERIFY_SELF_TEST"], baseline, False)
    quiet_ok = judge(current, baseline, False)
    excused = judge(current + ["X509_VERIFY_SELF_TEST"], baseline, True)
    failures = []
    if not grown_ok:
        failures.append("a new export with the slice unsatisfied was NOT refused")
    if quiet_ok:
        failures.append("an unchanged set was refused")
    if excused:
        failures.append("a new export was refused although the slice is satisfied")
    if failures:
        print("[x509-gate] self-test: FAIL")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[x509-gate] self-test: ok (the rule refuses a new Phase-11.2 export while the "
          "X.509 closure slice is unsatisfied, and only then)")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--freeze", action="store_true",
                    help="rewrite the baseline from the current ledger (activation only)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the rule refuses a new Phase-11.2 export while the slice is open")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    current = implemented_now("")
    if args.freeze:
        write_json(BASELINE, {
            "schema": "openssl-rs/phase22/x509-closure-slice-baseline/v1",
            "units": list(UNITS_11_2),
            "implemented": current,
            "note": ("the exports of Phase 11.2's three units that were already implemented when "
                     "Phase 22 was activated; a gate fires on a *growth* beyond this set, and "
                     "re-freezing it after work has landed stops it being a gate"),
        })
        print(f"[x509-gate] baseline frozen: {len(current)} implemented export(s) of "
              f"{len(UNITS_11_2)} unit(s) -> {rel(BASELINE)}")
        return 0

    if not BASELINE.is_file():
        print(f"[x509-gate] FAIL: {rel(BASELINE)} is absent, so a growth in Phase 11.2 cannot be "
              f"distinguished from the work already done; run this tool with --freeze once, in the "
              f"commit that activates the gate", file=sys.stderr)
        return 1

    baseline = set(read_json(BASELINE)["implemented"])
    satisfied, why = slice_state()
    grown = judge(current, baseline, satisfied)

    if grown:
        print("[x509-gate] FAIL: Phase 11.2's verification engine has new exports and the "
              "Phase-22 X.509 closure slice is not satisfied", file=sys.stderr)
        print(f"  {why}", file=sys.stderr)
        print(f"  {len(grown)} new export(s) of {len(UNITS_11_2)} unit(s):", file=sys.stderr)
        for name in grown[:20]:
            print(f"    {name}", file=sys.stderr)
        if len(grown) > 20:
            print(f"    ... and {len(grown) - 20} more", file=sys.stderr)
        print("  The dependency is why Phase 22 exists (docs/PHASE-22-SUBPHASES.md section 8, "
              "docs/PHASE-11-SUBPHASES.md section 2 row 11.2): land 22.14's closure for the X.509 "
              "roots first, or move the export's closure into an earlier subphase.", file=sys.stderr)
        return 1

    print(f"[x509-gate] ok: {len(current)} implemented export(s) of Phase 11.2's units, "
          f"{len(grown)} beyond the frozen baseline; {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
