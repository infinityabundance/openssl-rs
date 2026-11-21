#!/usr/bin/env python3
"""Verify every interop input against its pinned digest (O2).

The manifest is the *only* place a digest is written down. This script never
accepts a digest from a downloaded checksum file at run time: the pin is
reviewed and committed, and the run either reproduces it or fails.

Usage:
    verify_pins.py [--manifest PATH] [--work DIR] [--fetch] [--receipt PATH]

Behaviour:
  * with `--fetch`, a missing file is downloaded from its pinned URL;
  * a file that is present is hashed and compared;
  * `required_locally` pins must verify. A pin that is only recorded (the
    OpenSSL authority archive, already verified by the authorities registry)
    may be absent, and is reported `absent-recorded` rather than `verified`.

Exit status: 0 only when every required pin verified and no present file
mismatched. `--fetch` failures, absent required files and digest mismatches all
exit non-zero. There is deliberately no "warn but continue" mode: an interop
campaign whose inputs are not the pinned bytes has no result to report.
"""

import argparse
import hashlib
import json
import pathlib
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST = pathlib.Path(__file__).with_name("MANIFEST.json")
DEFAULT_WORK = ROOT / "court" / "tmp" / "o2"
CHUNK = 1 << 20


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url, dest, timeout=300):
    """Download to `dest`, writing to a temporary name first.

    A partial download must never be mistaken for a verified archive, so the
    final name appears only after the transfer completes.
    """
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url, timeout=timeout) as r, open(tmp, "wb") as f:
        while True:
            chunk = r.read(CHUNK)
            if not chunk:
                break
            f.write(chunk)
    tmp.rename(dest)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ap.add_argument("--work", default=str(DEFAULT_WORK))
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--receipt", default=None)
    args = ap.parse_args()

    manifest = json.loads(pathlib.Path(args.manifest).read_text())
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    try:
        work_rel = str(work.resolve().relative_to(ROOT))
    except ValueError:
        # A work directory outside the repository (a tmpfs, another mount) is
        # recorded absolute rather than silently rewritten.
        work_rel = str(work.resolve())

    rows = []
    failed = 0
    for pin in manifest["pins"]:
        path = work / pin["filename"]
        row = {
            "role": pin["role"],
            "cohort": pin["cohort"],
            "version": pin["version"],
            "filename": pin["filename"],
            "expected_sha256": pin["sha256"],
            "required_locally": pin["required_locally"],
        }
        if not path.exists():
            if not pin["required_locally"]:
                row["status"] = "absent-recorded"
                rows.append(row)
                continue
            if not args.fetch:
                row["status"] = "absent"
                failed += 1
                rows.append(row)
                continue
            try:
                fetch(pin["url"], path)
                row["fetched"] = True
            except Exception as e:  # noqa: BLE001 - reported, never swallowed
                row["status"] = "fetch_error"
                row["error"] = f"{type(e).__name__}: {e}"
                failed += 1
                rows.append(row)
                continue
        observed = sha256_of(path)
        row["observed_sha256"] = observed
        row["size_bytes"] = path.stat().st_size
        if observed == pin["sha256"]:
            row["status"] = "verified"
        else:
            row["status"] = "mismatch"
            failed += 1
        rows.append(row)

    receipt = {
        "schema": "openssl-rs/interop-pin-receipt/1",
        "campaign": manifest["campaign"],
        "manifest": str(pathlib.Path(args.manifest).resolve().relative_to(ROOT)),
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "work": work_rel,
        "counts": {
            "pins": len(rows),
            "verified": sum(1 for r in rows if r["status"] == "verified"),
            "absent_recorded": sum(1 for r in rows if r["status"] == "absent-recorded"),
            "failed": failed,
        },
        "pins": rows,
    }
    text = json.dumps(receipt, indent=1) + "\n"
    if args.receipt:
        pathlib.Path(args.receipt).write_text(text)
    for r in rows:
        print(f"{r['status']:>16}  {r['role']:<18} {r['version']:<8} {r['filename']}")
        if r["status"] == "mismatch":
            print(f"    expected {r['expected_sha256']}")
            print(f"    observed {r['observed_sha256']}")
    print(f"counts: {receipt['counts']}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
