#!/usr/bin/env python3
"""Print the full call stacks of the largest rows in a PFP-24 profile JSON."""
import json
import sys

doc = json.load(open(sys.argv[1]))
limit = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
rows = sorted(doc["rows"], key=lambda r: -r["blocks_per_op"])
seen = set()
for r in rows:
    if r["site"] in seen or r["blocks_per_op"] < limit:
        continue
    seen.add(r["site"])
    print("%7.3f blocks %8.1f bytes/op" % (r["blocks_per_op"], r["bytes_per_op"]))
    print("    " + " <- ".join(r["stack"][2:9]))
    print()
