#!/usr/bin/env python3
"""Assemble the PFP-21 record from the raw run artefacts.

Reads only files the runner wrote: raw/dso-digests.txt, raw/run-meta.env,
raw/valgrind-exits.tsv, attrib/<tag>-<mode>-r<N>.{summary.json,tsv},
raw/timing.tsv and raw/callgrind.tsv.

It measures and tabulates.  It makes no constant-time claim: a clean taint run
is not a proof, and the mutation control establishes that the selected kernel is
on the executed path, not that the path is constant time.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


def read_tsv(path: Path) -> list[list[str]]:
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def parse_attrib(path: Path) -> list[dict]:
    rows = read_tsv(path)
    out = []
    for r in rows[1:]:  # header is not trusted; columns are positional
        if len(r) < 10:
            continue
        out.append(
            {
                "kind": r[1],
                "class": r[2],
                "origin_fn": r[4],
                "engine_on_path": int(r[5]),
                "bn_on_path": int(r[6]),
                "stack": r[9],
            }
        )
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, required=True)
    args = ap.parse_args()
    ev = args.dir
    raw = ev / "raw"
    attrib = ev / "attrib"

    digests = {}
    for line in (raw / "dso-digests.txt").read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] in ("a", "b"):
            digests[parts[0]] = {"sha256": parts[1], "size": int(parts[2])}
    sensitivity = None
    sd = raw / "sensitivity-digest.txt"
    if sd.exists():
        parts = sd.read_text().split()
        if len(parts) == 3:
            digests["c"] = {"sha256": parts[1], "size": int(parts[2])}
            sensitivity = dict(digests["c"])

    meta = {}
    for line in (raw / "run-meta.env").read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            meta[k] = v

    runs: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for tag, mode, rep, n, c in read_tsv(raw / "valgrind-exits.tsv"):
        runs[(tag, mode)].append(
            {"rep": int(rep), "errors": int(n), "contexts": int(c)}
        )

    populations = {}
    keysets: dict[tuple[str, str], set] = {}
    for (tag, mode), reps in sorted(runs.items()):
        per_class = Counter()
        eng_on_path = 0
        eng_origin = 0
        origins = Counter()
        keys = set()
        for r in reps:
            base = attrib / ("%s-%s-r%d" % (tag, mode, r["rep"]))
            tsv = base.with_suffix(".tsv")
            if not tsv.exists():
                continue
            rows = parse_attrib(tsv)
            for x in rows:
                per_class[x["class"]] += 1
                eng_on_path += x["engine_on_path"]
                if x["class"] == "B":
                    eng_origin += 1
                origins[x["origin_fn"]] += 1
                keys.add((x["kind"], x["origin_fn"], x["stack"]))
        keysets[(tag, mode)] = keys
        populations["%s/%s" % (tag, mode)] = {
            "dso_sha256": digests[tag]["sha256"],
            "runs": reps,
            "errors": [r["errors"] for r in reps],
            "contexts": [r["contexts"] for r in reps],
            "per_class_union": dict(sorted(per_class.items())),
            "engine_on_path_union": eng_on_path,
            "engine_origins_union": eng_origin,
            "top_origins": [
                {"contexts": n, "fn": f} for f, n in origins.most_common(12)
            ],
        }

    comparison = {}
    for mode in sorted({m for (_t, m) in keysets}):
        a, b = keysets.get(("a", mode), set()), keysets.get(("b", mode), set())
        only_a = sorted({(k, f) for k, f, _s in a - b})
        only_b = sorted({(k, f) for k, f, _s in b - a})
        comparison[mode] = {
            "identical_context_sets": a == b,
            "only_a": only_a,
            "only_b": only_b,
        }

    timing: dict[tuple[str, str], list[float]] = defaultdict(list)
    for tag, mode, _rep, ns in read_tsv(raw / "timing.tsv"):
        timing[(tag, mode)].append(float(ns))

    cg: dict[tuple[str, str, int], int] = {}
    for tag, mode, iters, ir in read_tsv(raw / "callgrind.tsv"):
        cg[(tag, mode, int(iters))] = int(ir)

    mutation = {}
    for mode in ("mul-g", "sign"):
        w = {}
        for tag in ("a", "b"):
            xs = timing.get((tag, mode), [])
            if xs:
                w[tag] = {
                    "median_ns_per_op": statistics.median(xs),
                    "min": min(xs),
                    "max": max(xs),
                    "reps": len(xs),
                }
            if (tag, mode, 0) in cg and (tag, mode, 64) in cg:
                w.setdefault(tag, {})["ir_per_op"] = (
                    cg[(tag, mode, 64)] - cg[(tag, mode, 0)]
                ) / 64.0
        if "a" in w and "b" in w:
            w["wall_ratio_b_over_a"] = (
                w["b"]["median_ns_per_op"] / w["a"]["median_ns_per_op"]
            )
            if "ir_per_op" in w["a"] and "ir_per_op" in w["b"]:
                w["ir_ratio_b_over_a"] = w["b"]["ir_per_op"] / w["a"]["ir_per_op"]
        mutation[mode] = w

    record = {
        "item": "PFP-21",
        "candidate_a": digests["a"],
        "control_b": digests["b"],
        "sensitivity_control_c": sensitivity,
        "run_meta": meta,
        "populations": populations,
        "context_set_comparison": comparison,
        "mutation": mutation,
        "note": (
            "DSO-level taint counts and a two-DSO mutation control. The mutation "
            "difference establishes that the selected kernel is on the executed "
            "path; it is not a constant-time proof. A clean control population is "
            "an instrument/population check, not a safety result. Memcheck reports "
            "conditional jumps and memory uses of undefined data; it cannot see "
            "value-independent-but-secret-dependent arithmetic."
        ),
    }
    (raw / "pfp21-record.json").write_text(json.dumps(record, indent=2) + "\n")

    print("populations (3 repetitions per tainted mode; control once)")
    print("  tag/mode          errors                         contexts")
    for name, p in populations.items():
        print(
            "  %-16s %-30s %s"
            % (name, str(p["errors"]), str(p["contexts"]))
        )
    print("per-class union and engine attribution")
    for name, p in populations.items():
        print(
            "  %-16s class=%-24s engine_on_path=%d engine_origins=%d"
            % (
                name,
                str(p["per_class_union"]),
                p["engine_on_path_union"],
                p["engine_origins_union"],
            )
        )
    print("context-set comparison A vs B")
    for mode, c in comparison.items():
        print(
            "  %-12s identical=%s only_a=%d only_b=%d %s %s"
            % (
                mode,
                c["identical_context_sets"],
                len(c["only_a"]),
                len(c["only_b"]),
                c["only_a"][:3],
                c["only_b"][:3],
            )
        )
    print("mutation")
    for mode, w in mutation.items():
        for tag in ("a", "b"):
            if tag in w:
                print(
                    "  %s %s wall median %.0f ns/op [%.0f, %.0f] n=%d ir/op %.0f"
                    % (
                        mode,
                        tag,
                        w[tag].get("median_ns_per_op", float("nan")),
                        w[tag].get("min", float("nan")),
                        w[tag].get("max", float("nan")),
                        w[tag].get("reps", 0),
                        w[tag].get("ir_per_op", float("nan")),
                    )
                )
        print(
            "  %s B/A wall %.3f  B/A ir %.3f"
            % (
                mode,
                w.get("wall_ratio_b_over_a", float("nan")),
                w.get("ir_ratio_b_over_a", float("nan")),
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
