#!/usr/bin/env python3
"""PFP-46 paired timing analysis.

Reads the per-repetition outputs written by run_timing.sh and prints, per
workload, the median latency of each arm and the median of the paired
after/before ratios (plus every per-repetition ratio).
"""
import glob
import json
import re
import statistics
import sys
from pathlib import Path

RESULT = re.compile(r"^RESULT (\S+).*?median_us=([0-9.]+)")


def med(path):
    for line in Path(path).read_text().splitlines():
        m = RESULT.match(line)
        if m:
            return float(m.group(2))
    return None


def collect(d):
    out = {}
    for p in glob.glob(str(Path(d) / "p8-*.out")):
        m = re.match(r"p8-([a-z0-9]+)-(before|after)-r(\d+)\.out$", Path(p).name)
        if not m:
            continue
        workload, arm, rep = m.groups()
        v = med(p)
        if v is not None:
            out.setdefault(("p8", workload), {}).setdefault(rep, {})[arm] = v
    for p in glob.glob(str(Path(d) / "p5-*.out")):
        m = re.match(r"p5-(before|after)-r(\d+)\.out$", Path(p).name)
        if not m:
            continue
        arm, rep = m.groups()
        for line in Path(p).read_text().splitlines():
            r = RESULT.match(line)
            if r and r.group(1) in ("modexp2048", "modexp8192", "rsa2048"):
                out.setdefault(("p5", r.group(1)), {}).setdefault(rep, {})[arm] = float(r.group(2))
    return out


def main():
    d = sys.argv[1]
    data = collect(d)
    order = [
        ("p5", "modexp2048", "modexp-2048"),
        ("p5", "modexp8192", "modexp-8192"),
        ("p5", "rsa2048", "RSA-2048"),
        ("p8", "compute2048", "DH shared secret ffdhe2048"),
        ("p8", "keygen", "DH keygen ffdhe2048"),
    ]
    table = []
    print("%-30s %12s %12s %9s  %s" % ("workload", "before_us", "after_us", "ratio", "per-rep ratios"))
    for kind, wl, label in order:
        reps = data.get((kind, wl), {})
        pairs = [(v["before"], v["after"]) for v in reps.values()
                 if "before" in v and "after" in v]
        if not pairs:
            print("%-30s MISSING" % label)
            continue
        before = statistics.median(b for b, _ in pairs)
        after = statistics.median(a for _, a in pairs)
        ratios = [a / b for b, a in pairs]
        table.append({
            "workload": label,
            "reps": len(pairs),
            "before_us_median": before,
            "after_us_median": after,
            "ratio_after_over_before_median": statistics.median(ratios),
            "ratios": ratios,
        })
        print("%-30s %12.3f %12.3f %9.4f  [%s]" % (
            label, before, after, statistics.median(ratios),
            ", ".join("%.4f" % r for r in ratios)))
    Path(d, "timing-summary.json").write_text(json.dumps(table, indent=2) + "\n")


if __name__ == "__main__":
    main()
