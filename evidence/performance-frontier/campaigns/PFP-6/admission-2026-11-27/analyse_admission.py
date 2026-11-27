#!/usr/bin/env python3
"""analyse_admission.py — paired ratios for the PFP-6 CIOS admission.

Reads `timing/raw/<tag>-rNN.out`, extracts each workload's `RESULT ... median_us`,
and for every ordered pair reports absolute medians, the median of the paired
per-repetition ratio, and a 95% percentile bootstrap CI (20,000 resamples, seed
0x50465036).  Ratio < 1 means the first-named arm is faster.
"""
import glob
import json
import os
import random
import statistics

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "timing", "raw")
TAGS = ["cand", "ref", "auth"]
LABEL = {
    "cand": "CIOS default (admitted candidate)",
    "ref": "SOS reference twin",
    "auth": "openssl-3.6.4-production authority",
}
PAIRS = [("cand_over_ref", "cand", "ref"),
         ("cand_over_auth", "cand", "auth"),
         ("ref_over_auth", "ref", "auth")]


def parse(path):
    rows = {}
    for line in open(path):
        if line.startswith("RESULT "):
            p = line.split()
            med = None
            for x in p:
                if x.startswith("median_us="):
                    med = float(x.split("=", 1)[1])
            if med is not None:
                rows[p[1]] = med
    return rows


def main():
    by = {t: {} for t in TAGS}
    for t in TAGS:
        for path in sorted(glob.glob(os.path.join(RAW, f"{t}-r*.out"))):
            rep = os.path.basename(path).split("-r")[1].split(".")[0]
            by[t][rep] = parse(path)
    common = sorted(set.intersection(*(set(v) for t in TAGS for v in by[t].values())))
    rng = random.Random(0x50465036)
    out = {"arms": LABEL, "repetitions": len(by["cand"]), "workloads": {}}
    for ident in common:
        rec = {"absolute_us": {t: statistics.median(by[t][r][ident] for r in sorted(by[t]))
                               for t in TAGS}}
        for name, num, den in PAIRS:
            ratios = [by[num][r][ident] / by[den][r][ident] for r in sorted(by[num])]
            n = len(ratios)
            boots = []
            for _ in range(20000):
                s = sorted(rng.choice(ratios) for _ in range(n))
                boots.append(s[n // 2])
            boots.sort()
            rec[name] = {"median_ratio": statistics.median(ratios),
                         "ci95": [boots[int(0.025 * len(boots))],
                                  boots[int(0.975 * len(boots))]],
                         "n": n}
        out["workloads"][ident] = rec
    path = os.path.join(RAW, "timing-summary.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print("repetitions", out["repetitions"])
    for w, r in out["workloads"].items():
        abs_ = " ".join("%s=%.1f" % (t, r["absolute_us"][t]) for t in TAGS)
        ratios = " ".join("%s=%.4f[%.4f,%.4f]" % (
            k, r[k]["median_ratio"], r[k]["ci95"][0], r[k]["ci95"][1]) for k, _n, _d in PAIRS)
        print("%-14s %s | %s" % (w, abs_, ratios))


if __name__ == "__main__":
    main()
