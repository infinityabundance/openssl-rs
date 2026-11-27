#!/usr/bin/env python3
"""summarize_timing.py — compact human view of timing-summary.json."""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(os.path.join(HERE, "timing", "raw", "timing-summary.json")))
print("repetitions", d["repetitions"])
keys = ["b_over_a", "c_over_a", "d_over_a", "b_over_c", "d_over_c", "c_over_b", "d_over_b"]
for w, r in d["workloads"].items():
    parts = []
    for k in keys:
        if k in r:
            parts.append("%s=%.4f[%.4f,%.4f]" % (
                k, r[k]["median_ratio"], r[k]["ci95"][0], r[k]["ci95"][1]))
    abs_ = " ".join("%s=%.1f" % (t, r["absolute_us"][t]) for t in "abcd")
    print("%-14s %s | %s" % (w, abs_, " ".join(parts)))
