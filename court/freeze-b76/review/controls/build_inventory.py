#!/usr/bin/env python3
"""Build court/freeze-b76/review/review-65-inventory.json.

Task 1 of the independent adversarial review: extract every obligation whose
discharge_receipt is openssh-v1l (expected 9), openssh-v1i (expected 56), or
boundary-sweep-B45 (expected none), and report any obligation whose recorded
line no longer holds the recorded item.

Read-only over evidence/ and src/; writes one review artefact.
"""
import json
import re
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
RECEIPTS = [
    "evidence/closure-ssh-b76c.json",
    "evidence/closure-sshd-b76c.json",
]
WANT = ("openssh-v1l", "openssh-v1i", "boundary-sweep-B45")
OUT = "court/freeze-b76/review/review-65-inventory.json"

_src_cache = {}


def src_lines(path):
    if path not in _src_cache:
        with open(os.path.join(ROOT, path), "r", encoding="utf-8") as f:
            _src_cache[path] = f.read().splitlines()
    return _src_cache[path]


def find_def_line(lines, item):
    """First line that looks like a definition of `item`."""
    pat = re.compile(
        r"(?:^|\s)(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:extern\s+\"C\"\s+)?"
        r"(?:fn|static|const)\s+" + re.escape(item) + r"\b"
    )
    for i, line in enumerate(lines, 1):
        if pat.search(line):
            return i
    return None


def word_at(lines, line_no, item):
    if line_no is None or line_no < 1 or line_no > len(lines):
        return False
    return re.search(r"\b" + re.escape(item) + r"\b", lines[line_no - 1]) is not None


def main():
    per_receipt_counts = {}
    canonical = {}
    present_in = {}
    for rel in RECEIPTS:
        with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as f:
            d = json.load(f)
        counts = {}
        for o in d["obligations"]:
            r = o.get("discharge_receipt")
            if r not in WANT:
                continue
            counts[r] = counts.get(r, 0) + 1
            key = o["id"]
            present_in.setdefault(key, [])
            if rel not in present_in[key]:
                present_in[key].append(rel)
            if key in canonical:
                continue
            span = o.get("span_discharge") or {}
            canonical[key] = {
                "id": o["id"],
                "stable_id": o.get("stable_id"),
                "file": o["file"],
                "line": o["line"],
                "kind": o["kind"],
                "item": o["item"],
                "mechanism": o.get("mechanism"),
                "contract": o.get("contract"),
                "contract_basis": o.get("contract_basis"),
                "discharge_receipt": r,
                "discharge_boundary_id": o.get("discharge_boundary_id"),
                "boundary_ids": o.get("boundary_ids"),
                "line_provenance": o.get("line_provenance"),
                "recorded_span": {
                    "start_line": span.get("start_line"),
                    "end_line": span.get("end_line"),
                    "sha256": span.get("sha256"),
                    "qualified_identity": span.get("qualified_identity"),
                    "obligation_qualified_identity": span.get("obligation_qualified_identity"),
                    "binding": span.get("binding"),
                    "resolution": span.get("resolution"),
                },
            }
        per_receipt_counts[rel] = counts

    records = []
    stale = []
    for key in sorted(canonical):
        r = dict(canonical[key])
        lines = src_lines(r["file"])
        recorded_line_ok = word_at(lines, r["line"], r["item"])
        span_start = r["recorded_span"]["start_line"]
        span_start_ok = word_at(lines, span_start, r["item"])
        actual = find_def_line(lines, r["item"])
        r["coordinate_check"] = {
            "file_lines_now": len(lines),
            "recorded_line_holds_item": recorded_line_ok,
            "recorded_span_start_holds_item": span_start_ok,
            "actual_definition_line": actual,
            "stale": not (recorded_line_ok and span_start_ok),
        }
        if r["coordinate_check"]["stale"]:
            stale.append(
                {
                    "id": r["id"],
                    "file": r["file"],
                    "recorded_line": r["line"],
                    "recorded_span_start": span_start,
                    "actual_definition_line": actual,
                }
            )
        r["present_in"] = present_in[key]
        records.append(r)

    by_receipt = {}
    for r in records:
        by_receipt.setdefault(r["discharge_receipt"], []).append(r["id"])

    out = {
        "schema": "safe-c33/b76/review-inventory/v1",
        "task": "review inventory, no judgement",
        "candidate_source_head": "0238c6e4adbc7ed85a42be68b6fb965e139bd93e",
        "receipts": RECEIPTS,
        "counts_found_per_receipt_file": per_receipt_counts,
        "counts_found": {k: len(v) for k, v in by_receipt.items()},
        "boundary_sweep_B45": len(by_receipt.get("boundary-sweep-B45", [])),
        "total_distinct_obligations": len(records),
        "stale_coordinates": stale,
        "obligations": records,
    }
    with open(os.path.join(ROOT, OUT), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=False)
        f.write("\n")

    print("counts per receipt file:")
    for rel, c in per_receipt_counts.items():
        print("  ", rel, dict(sorted(c.items())))
    print("distinct obligations:", len(records))
    print("by receipt:", {k: len(v) for k, v in sorted(by_receipt.items())})
    print("stale coordinates:", len(stale))
    for s in stale:
        print("   STALE", s["id"], "recorded_line", s["recorded_line"],
              "span_start", s["recorded_span_start"], "actual", s["actual_definition_line"])
    print("wrote", OUT)


if __name__ == "__main__":
    main()
