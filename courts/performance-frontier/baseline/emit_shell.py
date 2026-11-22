#!/usr/bin/env python3
"""Generate the Phase-2 libcrypto shell from a freshly derived surface.

`forensics/tools/phase2_shell.py --emit-shell` reads the *tracked*
`forensics/atlas/implemented-surface.json`.  PFP-0 must not assume that this
tracked file matches the archive built in the campaign, so the fresh surface is
derived first (`implemented_surface.py --out <fresh>`) and this tool patches the
generator's input path before emitting the shell.

It also compares the fresh `implemented_symbols` sets with the tracked manifest
and records the result.  A mismatch is reported, not hidden: it means the
tracked surface is stale relative to the frozen source, and the distribution DSO
below was linked from the fresh surface.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "forensics" / "tools"))

import phase2_shell  # noqa: E402


def symbols(doc: dict) -> dict:
    libs = doc["body"]["libraries"]
    return {
        lib: sorted(info["implemented_symbols"]) for lib, info in libs.items()
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--surface", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--authority", default="openssl-3.6.4-production")
    parser.add_argument("--record", type=Path)
    args = parser.parse_args(argv)

    fresh = json.loads(args.surface.read_text())
    tracked_path = REPO / "forensics" / "atlas" / "implemented-surface.json"
    tracked = json.loads(tracked_path.read_text())
    fresh_symbols = symbols(fresh)
    tracked_symbols = symbols(tracked)
    per_lib = {}
    all_match = True
    for lib in sorted(fresh_symbols):
        same = fresh_symbols[lib] == tracked_symbols.get(lib)
        all_match = all_match and same
        per_lib[lib] = {
            "fresh_count": len(fresh_symbols[lib]),
            "tracked_count": len(tracked_symbols.get(lib, [])),
            "sets_match": same,
        }

    # The generator reads this module-level path (load_implemented uses the
    # global), so patching it is sufficient and leaves the tracked file intact.
    phase2_shell.IMPLEMENTED_SURFACE = args.surface.resolve()
    phase2_shell.emit_shell_only(args.out.resolve(), args.authority)

    record = {
        "schema": "openssl-rs/performance/shell-generation/v1",
        "fresh_surface": str(args.surface),
        "fresh_surface_body_hash": fresh.get("body_hash"),
        "tracked_surface": str(tracked_path.relative_to(REPO)),
        "tracked_surface_body_hash": tracked.get("body_hash"),
        "libraries": per_lib,
        "tracked_surface_matches_fresh": all_match,
        "shell_used": "fresh",
    }
    if args.record:
        args.record.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
