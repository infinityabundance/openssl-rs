#!/usr/bin/env python3
"""Independent re-computation of every recorded operation-span hash.

The closure tool accepts a boundary's discharge by matching the recorded span
hash against the current content instead of the recorded coordinate.  This
control re-derives the hash rule from the source and applies it to all 65
reviewed obligations, so the "content address" claim is checked outside the
tool that made it.

Rule (derived, then verified): sha256 over "\\n".join(lines[start-1:end]).
"""
import hashlib
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
INV = "court/freeze-b76/review/review-65-inventory.json"


def main():
    with open(os.path.join(ROOT, INV), "r", encoding="utf-8") as f:
        inv = json.load(f)
    cache = {}
    ok = 0
    bad = []
    for o in inv["obligations"]:
        path = o["file"]
        if path not in cache:
            with open(os.path.join(ROOT, path), "r", encoding="utf-8") as f:
                cache[path] = f.read().splitlines()
        lines = cache[path]
        sp = o["recorded_span"]
        start, end = sp["start_line"], sp["end_line"]
        if start is None or end is None:
            bad.append((o["id"], "no span"))
            continue
        got = hashlib.sha256("\n".join(lines[start - 1:end]).encode()).hexdigest()
        if got == sp["sha256"]:
            ok += 1
        else:
            bad.append((o["id"], f"{got[:16]} != {sp['sha256'][:16]}"))
    print(f"span hashes recomputed: {ok}/{len(inv['obligations'])} match")
    for b in bad:
        print("  MISMATCH", b[0], b[1])
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
