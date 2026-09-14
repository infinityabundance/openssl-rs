#!/usr/bin/env python3
"""openssl-rs — atlas index, determinism check and evidence receipt.

Walks the derived atlas and emits a content-addressed receipt:

    forensics/atlas/ATLAS_INDEX.json         per-file hashes + aggregate root
    forensics/receipts/EVIDENCE_RECEIPT.<n>.json  immutable run receipt

It also *verifies determinism* rather than asserting it: if a previous index
exists, the aggregate root hash must match byte-for-byte, or the tool reports
which files drifted and exits non-zero. `docs/REPRODUCIBILITY.md` §2 requires
reproducibility to be demonstrated, not claimed.

Receipts are numbered and never overwritten: an earlier receipt is evidence of
what was true at that time and is preserved (`docs/PARITY_MODEL.md` §5).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    AUTH_ROOT,
    ATLAS,
    BUILD_RECORDS,
    FORENSICS,
    REGISTRY,
    content_hash,
    rel,
    sha256_bytes,
    sha256_file,
    write_json,
)

RECEIPTS = FORENSICS / "receipts"
INDEX = ATLAS / "ATLAS_INDEX.json"


def collect_files() -> dict[str, str]:
    """Hash every derived atlas file (JSON and Markdown), plus the registries."""
    files: dict[str, str] = {}
    for path in sorted(ATLAS.rglob("*")):
        if not path.is_file():
            continue
        if path.name == "ATLAS_INDEX.json" or path.name.startswith("EVIDENCE_RECEIPT"):
            continue
        files[rel(path)] = sha256_file(path)
    files[rel(REGISTRY)] = sha256_file(REGISTRY)
    if BUILD_RECORDS.exists():
        files[rel(BUILD_RECORDS)] = sha256_file(BUILD_RECORDS)
    return files


def aggregate(files: dict[str, str]) -> str:
    lines = [f"{files[k]}  {k}\n" for k in sorted(files)]
    return sha256_bytes("".join(lines).encode("utf-8"))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Index and receipt the derived atlas.")
    ap.add_argument("--verify", action="store_true",
                    help="fail if the aggregate hash differs from the existing index")
    args = ap.parse_args(argv)

    files = collect_files()
    root = aggregate(files)

    previous = None
    if INDEX.exists():
        previous = json.loads(INDEX.read_text())

    index = {
        "schema": "openssl-rs/atlas-index/v1",
        "generator": "forensics/tools/atlas_receipt.py",
        "file_count": len(files),
        "aggregate_hash_algorithm": "sha256(<file-sha256>  <path>\\n, lexicographic)",
        "aggregate_hash": root,
        "files": [{"path": k, "sha256": files[k]} for k in sorted(files)],
    }

    drifted: list[str] = []
    if previous and previous.get("aggregate_hash") != root:
        prev_files = {f["path"]: f["sha256"] for f in previous.get("files", [])}
        for k in sorted(set(prev_files) | set(files)):
            if prev_files.get(k) != files.get(k):
                drifted.append(k)

    if args.verify and drifted:
        print("NON-DETERMINISTIC: the derived atlas changed on regeneration",
              file=sys.stderr)
        for d in drifted[:40]:
            print(f"  drifted: {d}", file=sys.stderr)
        return 1

    write_json(INDEX, index)
    print(f"atlas files: {len(files)}")
    print(f"aggregate hash: {root}")

    if args.verify:
        print("DETERMINISTIC: aggregate hash matches the previous index")

    RECEIPTS.mkdir(parents=True, exist_ok=True)
    existing = sorted(RECEIPTS.glob("EVIDENCE_RECEIPT.*.json"))
    n = len(existing) + 1
    receipt = {
        "schema": "openssl-rs/evidence-receipt/v1",
        "receipt_number": n,
        "kind": "phase1-atlas",
        "generator": "forensics/tools/atlas_receipt.py",
        "court": {
            "container": "openssl-rs-court",
            "image": "openssl-rs-court:1",
            "note": "generated inside the court container; never on the host",
        },
        "aggregate_hash": root,
        "file_count": len(files),
        "drift_from_previous": drifted,
        "deterministic": not drifted,
        "files": [{"path": k, "sha256": files[k]} for k in sorted(files)],
        "non_claims": [
            "does not claim cryptographic security",
            "does not claim FIPS validation",
            "does not claim cryptographic-correctness from OpenSSL parity",
        ],
    }
    out = RECEIPTS / f"EVIDENCE_RECEIPT.{n:04d}.json"
    write_json(out, receipt)
    print(f"receipt: {rel(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
