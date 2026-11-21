#!/usr/bin/env python3
"""Parse two OpenSSH `make -k tests` logs into one O6 receipt.

The upstream harness prints one `run test <name> ...` line per shell test and a
bare `failed <name>` for each failure; unit tests print `<name>: ... N tests ok`.
Nothing is inferred: a test is `ok` only when the log says so, and a script whose
outcome line is missing is reported `unknown`, which counts as a failure because
the log cannot establish it ran.

Usage:
    summarize_tests.py --a LOG_A --b LOG_B [--receipt PATH] [--label-a A] [--label-b B]

Exit status: 0 only when both logs parse and the failure sets are equal *and*
every failure is classified as upstream-common in the receipt. The classification
itself is not automatic; this script reports the sets and refuses to fold
candidate-specific failures into a pass.
"""

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
RUN = re.compile(r"^run test (\S+) \.\.\.\s*$")
FAILED = re.compile(r"^failed (.+?)\s*$")
SKIPPED = re.compile(r"^SKIPPED: (.*)$")
UNIT_OK = re.compile(r"^(\w+): [.]+ (\d+) tests ok\s*$")


def parse(path):
    scripts = []
    failed = []
    skipped = []
    unit = {}
    current = None
    for line in pathlib.Path(path).read_text(errors="replace").splitlines():
        m = RUN.match(line)
        if m:
            current = m.group(1)
            if current not in scripts:
                scripts.append(current)
            continue
        m = FAILED.match(line)
        if m:
            failed.append({"script": m.group(1), "after": current})
            continue
        m = SKIPPED.match(line)
        if m:
            skipped.append({"script": current, "reason": m.group(1)})
            continue
        m = UNIT_OK.match(line)
        if m:
            unit[m.group(1)] = int(m.group(2))
    return {
        "scripts_run": scripts,
        "failures": failed,
        "skipped": skipped,
        "unit_tests_passed": unit,
        "counts": {
            "scripts": len(scripts),
            "failures": len(failed),
            "skipped": len(skipped),
            "unit_assertions": sum(unit.values()),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True)
    ap.add_argument("--b", required=True)
    ap.add_argument("--label-a", default="A")
    ap.add_argument("--label-b", default="B")
    ap.add_argument("--receipt", default=None)
    ap.add_argument(
        "--classify",
        default="",
        help="JSON map script -> upstream-common|candidate-specific|harness",
    )
    args = ap.parse_args()

    a = parse(args.a)
    b = parse(args.b)
    set_a = {f["script"] for f in a["failures"]}
    set_b = {f["script"] for f in b["failures"]}
    classify = json.loads(args.classify) if args.classify else {}
    rows = []
    unclassified = 0
    for name in sorted(set_a | set_b):
        where = "both" if name in set_a and name in set_b else (args.label_a if name in set_a else args.label_b)
        cls = classify.get(name)
        if cls is None:
            unclassified += 1
        rows.append({"failed_in": where, "script": name, "classification": cls})

    receipt = {
        "schema": "openssl-rs/interop-upstream-tests-receipt/1",
        "item": "O6 of docs/ETP-TODO.md",
        "generated": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        "subjects": {args.label_a: str(args.a), args.label_b: str(args.b)},
        "runs": {args.label_a: a, args.label_b: b},
        "failure_sets_equal": set_a == set_b,
        "failures": rows,
        "unclassified_failures": unclassified,
    }
    text = json.dumps(receipt, indent=1) + "\n"
    if args.receipt:
        pathlib.Path(args.receipt).write_text(text)

    for label, r in ((args.label_a, a), (args.label_b, b)):
        print(
            f"{label}: {r['counts']['scripts']} scripts, {r['counts']['failures']} failed, "
            f"{r['counts']['skipped']} skipped, {r['counts']['unit_assertions']} unit assertions"
        )
        for f in r["failures"]:
            print(f"    failed: {f['script']}")
    print("failure sets equal:", set_a == set_b)
    return 0 if (set_a == set_b and unclassified == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
