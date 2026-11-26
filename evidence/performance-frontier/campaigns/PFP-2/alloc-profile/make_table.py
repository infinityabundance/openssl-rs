#!/usr/bin/env python3
"""Render the PFP-24 before/after allocation table as Markdown (for ALLOCATIONS.md)."""
import collections
import json
import sys

BEFORE = "raw-base/profile-e93776b4.json"
AFTER = "raw-24/profile-5e75b694.json"


def load(path):
    doc = json.load(open(path))
    groups = {}
    for r in doc["rows"]:
        key = (r["site"], r["caller"])
        g = groups.setdefault(key, [0.0, 0.0])
        g[0] += r["blocks_per_op"]
        g[1] += r["bytes_per_op"]
    return groups, len(doc["rows"])


def name(s):
    return s.replace("openssl_rs::", "") if s else "-"


gb, nb = load(BEFORE)
ga, na = load(AFTER)

print("| # | site | reached from | blocks/op before | bytes/op before "
      "| blocks/op after | delta |")
print("|---|---|---|---:|---:|---:|---:|")
i = 0
for (site, caller), (blk, byt) in sorted(gb.items(), key=lambda kv: -kv[1][0]):
    if blk < 2.5:
        continue
    i += 1
    aft = ga.get((site, caller), [0.0, 0.0])[0]
    print("| {} | `{}` | `{}` | {:.2f} | {:.1f} | {:.2f} | {:+.2f} |".format(
        i, name(site), name(caller), blk, byt, aft, aft - blk))

tb = sum(v[0] for v in gb.values())
ty = sum(v[1] for v in gb.values())
ab = sum(v[0] for v in ga.values())
ay = sum(v[1] for v in ga.values())
print()
print("before: {:.2f} blocks/op, {:.1f} bytes/op, {} program points".format(tb, ty, nb))
print("after:  {:.2f} blocks/op, {:.1f} bytes/op, {} program points".format(ab, ay, na))
print("delta:  {:+.2f} blocks/op ({:+.2f}%), {:+.1f} bytes/op".format(
    ab - tb, 100.0 * (ab - tb) / tb, ay - ty))
rest = sorted(gb.items(), key=lambda kv: -kv[1][0])[i:]
print("rows below 2.5 blocks/op: {:.2f} blocks/op over {} groups".format(
    sum(v[0] for _, v in rest), len(rest)))
