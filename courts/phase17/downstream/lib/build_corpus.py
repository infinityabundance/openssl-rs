#!/usr/bin/env python3
"""openssl-rs -- Phase 17 downstream: aggregate the per-program records into the corpus.

Pure and deterministic: it reads `courts/phase17/downstream/<program>/result.json` (the
measured records the driver writes) and emits `forensics/atlas/downstream-corpus.json`.
It does not run any harness and does not touch the network, so `evidence_determinism.py`
can re-run it on any machine. The `RT-DOWNSTREAM-CORPUS` court then validates the corpus
(required fields, `functional`, candidate freshness, and that each corpus record still
equals its per-program `result.json`).

Usage: python3 lib/build_corpus.py [--out forensics/atlas/downstream-corpus.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROGRAMS = ["curl", "git", "haproxy", "nginx", "openssh", "python"]
SCHEMA = "openssl-rs/downstream-corpus/v1"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="forensics/atlas/downstream-corpus.json")
    args = ap.parse_args(argv)

    root = repo_root()
    down = root / "courts" / "phase17" / "downstream"
    records = []
    for p in PROGRAMS:
        f = down / p / "result.json"
        if not f.is_file():
            raise SystemExit(f"build_corpus: {f} is absent; run courts/phase17/downstream/run_all.sh")
        records.append(json.loads(f.read_text(encoding="utf-8")))

    body = {"schema": SCHEMA, "programs": records}
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[build-corpus] {len(records)} record(s) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
