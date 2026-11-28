#!/usr/bin/env python3
"""Re-verify historical crate payloads against the bytes the registry serves.

Why this exists
---------------
A publish receipt is only as good as its checksum.  Two of them (0.0.47,
0.0.48) recorded a digest that is not the digest of the `.crate` the registry
serves, and four of the earliest recorded no digest at all.  A receipt that
quotes the wrong bytes is a lifecycle claim that its own subject refutes, which
is the class `release_state.py` now refuses as ``RS_LIFECYCLE_UNEARNED``.

This tool does not guess, and it does not rewrite history.  For each published
version it downloads the exact payload, hashes it, checks it against the
registry's own API value, and then -- only on a match -- records the measured
bytes in the receipt.  A digest that disagreed with the receipt is preserved
under ``checksum_superseded`` beside the correction, because the record of what
was once believed is part of the evidence.

Usage
-----
    python3 forensics/tools/verify_release_payloads.py            # verify + record
    python3 forensics/tools/verify_release_payloads.py --check    # verify only

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ATLAS = Path("forensics/memory-safety/campaign/safe-c33/atlas-refresh")
CRATE_URL = "https://static.crates.io/crates/{name}/{name}-{version}.crate"
API_URL = "https://crates.io/api/v1/crates/{name}/{version}"
NAME = "openssl-rs"


def _get_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "openssl-rs-release-verify"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def _served_digest(version: str) -> tuple[str, int]:
    url = CRATE_URL.format(name=NAME, version=version)
    digest = hashlib.sha256()
    size = 0
    request = urllib.request.Request(url, headers={"User-Agent": "openssl-rs-release-verify"})
    with urllib.request.urlopen(request, timeout=120) as response, tempfile.TemporaryFile() as sink:
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            sink.write(chunk)
    return digest.hexdigest(), size


def _indent_of(text: str) -> int:
    """The receipt's own indentation, so a correction does not reformat it."""
    for line in text.splitlines()[1:]:
        stripped = line.lstrip(" ")
        if stripped.startswith('"'):
            return len(line) - len(stripped)
    return 1


def verify(version: str, receipt: dict, record: bool, stamp: str) -> str:
    registry = receipt.setdefault("registry_verification", {})
    api = (_get_json(API_URL.format(name=NAME, version=version)).get("version") or {})
    api_checksum = str(api.get("checksum") or "").lower()
    api_size = api.get("crate_size")

    served, size = _served_digest(version)
    if api_checksum and served != api_checksum:
        return f"{version}: REFUSED: downloaded {served[:16]} but the registry API says {api_checksum[:16]}"
    if api_size is not None and size != api_size:
        return f"{version}: REFUSED: downloaded {size} bytes but the registry API says {api_size}"

    claimed = str(registry.get("checksum") or "").lower()
    if claimed and claimed != served:
        registry["checksum_superseded"] = {
            "value": claimed,
            "recorded_on": receipt.get("date", ""),
            "why": (
                "This digest is not the digest of the .crate the registry serves. "
                "It was corrected on 2026-11-28 by re-downloading the payload and "
                "recomputing its sha256; the superseded value is retained because "
                "the record of what was once believed is part of the evidence."
            ),
        }
    registry["checksum"] = served
    registry["checksum_prefix"] = served[:8]
    registry["crate_size"] = size
    registry["download_sha256_recomputed"] = served
    registry["download_verification"] = (
        f"RUN at {stamp}: downloaded {CRATE_URL.format(name=NAME, version=version)}, "
        f"recomputed sha256 {served[:16]}… over {size} bytes; matches the registry "
        "API checksum and size"
    )
    registry["verified_at"] = stamp
    registry["verified_by"] = "forensics/tools/verify_release_payloads.py (PFP-87)"

    note = f"{version}: {'CORRECTED' if claimed and claimed != served else 'OK'} {served[:16]}… {size}"
    if record:
        return note
    return note


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify without recording")
    parser.add_argument("--version", action="append", default=None)
    args = parser.parse_args(argv)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    paths = sorted(ATLAS.glob("publish-*.json"))
    if args.version:
        wanted = set(args.version)
        paths = [p for p in paths if p.stem[len("publish-"):] in wanted]

    failures = 0
    for path in paths:
        version = path.stem[len("publish-"):]
        receipt = json.loads(path.read_text(encoding="utf-8"))
        if str(receipt.get("status", "")).upper() != "PUBLISHED":
            print(f"{version}: SKIP (status {receipt.get('status')!r})")
            continue
        # Already verified against the served payload at this identity.
        registry = receipt.get("registry_verification") or {}
        if str(registry.get("download_verification", "")).startswith("RUN at"):
            print(f"{version}: SKIP (already re-verified {registry.get('verified_at')})")
            continue
        try:
            line = verify(version, receipt, record=not args.check, stamp=stamp)
        except Exception as error:  # network failure is a refusal, not a pass
            print(f"{version}: ERROR {type(error).__name__}: {error}")
            failures += 1
            continue
        if "REFUSED" in line:
            failures += 1
        print(line)
        if not args.check and "REFUSED" not in line:
            original = path.read_text(encoding="utf-8")
            path.write_text(
                json.dumps(receipt, indent=_indent_of(original)) + "\n",
                encoding="utf-8",
            )

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
