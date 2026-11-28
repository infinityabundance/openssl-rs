#!/usr/bin/env python3
"""PFP-12 cross-library differential comparator.

Compares the candidate and authority `--once` lines for every operation and the
`--kat` boundary/NIST lines. Any differing line is a STOP; a KAT-MISMATCH line
(the hard-coded NIST expected value disagreeing with the computed one) is also
reported independently of the cross-library agreement, because two libraries
can agree on a wrong constant only if the constant is not being checked.
"""
import argparse
import json
import os
import sys


def lines(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return [ln.rstrip("\n") for ln in fh if ln.strip()]


def compare(dirname):
    out = {"pairs": {}, "kat_mismatch_lines": [], "ok": True}
    ops = []
    for name in sorted(os.listdir(dirname)):
        if name.startswith("cand-") and name.endswith(".out"):
            ops.append(name[len("cand-") : -len(".out")])
    for op in ops:
        c = lines(os.path.join(dirname, "cand-%s.out" % op))
        a = lines(os.path.join(dirname, "auth-%s.out" % op))
        if c is None or a is None:
            out["pairs"][op] = {"status": "MISSING"}
            out["ok"] = False
            continue
        same = c == a
        out["pairs"][op] = {
            "status": "IDENTICAL" if same else "MISMATCH",
            "cand_lines": len(c),
            "auth_lines": len(a),
        }
        if not same:
            out["ok"] = False
            for i, (x, y) in enumerate(zip(c, a)):
                if x != y:
                    out["pairs"][op]["first_diff"] = {
                        "line": i,
                        "cand": x[:200],
                        "auth": y[:200],
                    }
                    break
            if len(c) != len(a):
                out["pairs"][op]["first_diff"] = {
                    "line": min(len(c), len(a)),
                    "cand": "<%d lines>" % len(c),
                    "auth": "<%d lines>" % len(a),
                }
    kat = lines(os.path.join(dirname, "cand-kat.out")) or []
    for ln in kat:
        if ln.startswith("KAT-MISMATCH"):
            out["kat_mismatch_lines"].append(ln)
            out["ok"] = False
    a_kat = lines(os.path.join(dirname, "auth-kat.out"))
    if a_kat is not None and kat != a_kat:
        out["ok"] = False
        out["kat_cross_library"] = "MISMATCH"
    else:
        out["kat_cross_library"] = "IDENTICAL"
    out["kat_cases"] = len(kat)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    report = compare(args.dir)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")
    for op, row in report["pairs"].items():
        print("%-16s %s" % (op, row["status"]))
    print("kat cases=%d cross-library=%s mismatches=%d" % (
        report["kat_cases"], report["kat_cross_library"],
        len(report["kat_mismatch_lines"])))
    for ln in report["kat_mismatch_lines"]:
        print(ln)
    print("DIFF_OK" if report["ok"] else "DIFF_FAIL")
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
