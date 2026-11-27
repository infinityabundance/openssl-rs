#!/usr/bin/env python3
"""Summarise the PFP-3 ctgrind raw outputs.

Reads the runner's `valgrind-exits.tsv` (tag, mode, rep, errors, contexts) and
the unchanged PFP-21 attribution output in `attrib/*.summary.json`, and prints a
compact per-population record.  It aggregates; it never re-classifies.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, required=True)
    args = ap.parse_args()
    ev = args.dir

    exits: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
    for line in (ev / "raw" / "valgrind-exits.tsv").read_text().splitlines():
        tag, mode, rep, errors, contexts = line.split("\t")
        exits[(tag, mode)].append((int(errors), int(contexts)))

    summaries: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for p in sorted((ev / "attrib").glob("*.summary.json")):
        # <tag>-<mode>-r<rep>.summary.json ; modes contain '-', split from the right
        stem = p.name[: -len(".summary.json")]
        tag, rest = stem.split("-", 1)
        mode, rep = rest.rsplit("-r", 1)
        summaries[(tag, mode)].append(json.loads(p.read_text()))

    record = {"candidate_sha256": None, "populations": {}, "sensitivity": {}}
    meta = dict(
        line.split("=", 1)
        for line in (ev / "raw" / "run-meta.env").read_text().splitlines()
        if "=" in line
    )
    record["candidate_sha256"] = meta.get("candidate_sha256")
    record["harness_source_sha256"] = meta.get("harness_source_sha256")
    record["harness_binary_sha256"] = meta.get("harness_binary_sha256")

    print("populations (errors / contexts per repetition; class union; engine)")
    for (tag, mode), reps in sorted(exits.items()):
        ss = summaries[(tag, mode)]
        classes: dict[str, list[int]] = defaultdict(list)
        for s in ss:
            for k, v in s.get("per_class", {}).items():
                classes[k].append(v)
        union = {k: max(v) for k, v in classes.items()}
        engine_path = max((s.get("engine_on_path", 0) for s in ss), default=0)
        origin_engine = max((s.get("origin_in_engine", 0) for s in ss), default=0)
        entry = {
            "errors": [e for e, _ in reps],
            "contexts": [c for _, c in reps],
            "per_class_union": union,
            "engine_on_path_union": engine_path,
            "origin_in_engine_union": origin_engine,
            "top_origins": (ss[0].get("top_origins", [])[:8] if ss else []),
        }
        key = f"{tag}/{mode}"
        if tag == "c":
            record["sensitivity"][key] = entry
        else:
            record["populations"][key] = entry
        print(
            f"  {key:20s} errors={entry['errors']} contexts={entry['contexts']} "
            f"class={union} engine_on_path={engine_path} origin_in_engine={origin_engine}"
        )

    for name in ("a/mul-g-fixed", "a/mul-g", "a/sign"):
        entry = record["populations"].get(name)
        if not entry:
            continue
        print(f"top origins {name}:")
        for row in entry["top_origins"]:
            print(f"  {row['contexts']:4d}  {row['loc']}  {row['fn']}")

    (ev / "raw" / "ctgrind-record.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
