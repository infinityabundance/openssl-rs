#!/usr/bin/env python3
"""Re-verify published crate payloads against the bytes the registry serves.

Why this exists
---------------
A publish receipt is only as good as its checksum.  Two of them (0.0.47,
0.0.48) recorded a digest that is not the digest of the `.crate` the registry
serves, and four of the earliest recorded no digest at all.  A receipt that
quotes the wrong bytes is a lifecycle claim that its own subject refutes, which
is the class `release_state.py` refuses as ``RS_LIFECYCLE_UNEARNED``.

This tool does not guess, and it does not rewrite history.  For each published
version it downloads the exact payload, hashes it, checks it against the
registry's own API value, and then records the measured bytes.  A digest that
disagreed is preserved under ``*_superseded`` beside the correction, because the
record of what was once believed is part of the evidence.

Canonical identity
------------------
The registry payload is the single authority for a release's crate digest and
size.  Every duplicate of that identity in a receipt -- ``packaging.crate_sha256``,
``packaging.compressed_bytes``, the API ``endpoint`` -- is reconciled to it, and a
duplicate that disagreed is kept under ``*_superseded`` rather than left as a
second, conflicting assertion.  Leaving one field corrected and another stale is
the defect this tool found in 0.0.47/0.0.48 and must not reintroduce.

Modes
-----
``--check`` performs a **fresh** verification every time (no version is skipped
because it was verified before) and exits non-zero if any receipt would change.
``--write`` records the measurement.

Usage
-----
    python3 forensics/tools/verify_release_payloads.py --check
    python3 forensics/tools/verify_release_payloads.py --write --version 0.0.48

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

SUPERSEDE_WHY = (
    "This value is not what the registry serves. It was corrected on 2026-11-28 "
    "by re-downloading the payload and recomputing its sha256; the superseded "
    "value is retained because the record of what was once believed is part of "
    "the evidence."
)


class Refusal(RuntimeError):
    pass


def _get_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "openssl-rs-release-verify"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def _served_digest(version: str) -> tuple[str, int]:
    url = CRATE_URL.format(name=NAME, version=version)
    digest = hashlib.sha256()
    size = 0
    request = urllib.request.Request(url, headers={"User-Agent": "openssl-rs-release-verify"})
    with urllib.request.urlopen(request, timeout=120) as response:
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _indent_of(text: str) -> int:
    """The receipt's own indentation, so a correction does not reformat it."""
    for line in text.splitlines()[1:]:
        stripped = line.lstrip(" ")
        if stripped.startswith('"'):
            return len(line) - len(stripped)
    return 1


def _supersede(container: dict, key: str, why: str = SUPERSEDE_WHY) -> None:
    if key in container and f"{key}_superseded" not in container:
        container[f"{key}_superseded"] = {"value": container[key], "why": why}


def verify(version: str, receipt: dict, stamp: str) -> tuple[str, bool]:
    """Verify one payload and reconcile every duplicate of its identity.

    Returns ``(line, changed)``.  A refusal is raised, never returned as a pass.
    """
    registry = receipt.setdefault("registry_verification", {})
    try:
        api = _get_json(API_URL.format(name=NAME, version=version)).get("version") or {}
    except Exception as error:
        raise Refusal(f"the registry API could not be read: {error}") from error

    api_checksum = str(api.get("checksum") or "").lower()
    api_size = api.get("crate_size")
    # A missing API field is a refusal, not a version to skip: the registry is
    # the authority, and a measurement without it cannot be reconciled.
    if len(api_checksum) != 64:
        raise Refusal("the registry API returned no 64-hex checksum")
    if not isinstance(api_size, int):
        raise Refusal("the registry API returned no crate_size")

    served, size = _served_digest(version)
    if served != api_checksum:
        raise Refusal(
            f"the downloaded payload hashes to {served[:16]}… but the registry API "
            f"says {api_checksum[:16]}…; the download is not the served payload"
        )
    if size != api_size:
        raise Refusal(
            f"the downloaded payload is {size} bytes but the registry API says "
            f"{api_size}; the download is not the served payload"
        )

    before = json.dumps(receipt, sort_keys=True)

    claimed = registry.get("checksum")
    if claimed and str(claimed).lower() != served:
        _supersede(registry, "checksum")
    registry["checksum"] = served
    registry["checksum_prefix"] = served[:8]
    registry["crate_size"] = size
    registry["download_sha256_recomputed"] = served

    # The endpoint must name this version.  0.0.47 and 0.0.48 both pointed at
    # 0.0.45, which is how a wrong checksum survived unnoticed.
    endpoint = str(registry.get("endpoint") or "")
    if endpoint and not endpoint.rstrip("/").endswith(f"/{version}"):
        _supersede(registry, "endpoint", SUPERSEDE_WHY + " It named another version.")
        registry["endpoint"] = API_URL.format(name=NAME, version=version)

    # Every duplicate of the payload identity is reconciled to the registry.
    packaging = receipt.get("packaging")
    if isinstance(packaging, dict):
        old_sha = packaging.get("crate_sha256")
        if old_sha and str(old_sha).lower() != served:
            _supersede(packaging, "crate_sha256")
        if old_sha is not None:
            packaging["crate_sha256"] = served
        old_size = packaging.get("compressed_bytes")
        if isinstance(old_size, int) and old_size != size:
            _supersede(packaging, "compressed_bytes")
            packaging["compressed_bytes"] = size

    changed = json.dumps(receipt, sort_keys=True) != before

    # The verification stamp records a correction, not a re-check: writing a
    # fresh timestamp on every run would make `--check` always report
    # WOULD_CORRECT even when the identity is already reconciled.
    if changed:
        registry["download_verification"] = (
            f"RUN at {stamp}: downloaded "
            f"{CRATE_URL.format(name=NAME, version=version)}, recomputed sha256 "
            f"{served[:16]}… over {size} bytes; matches the registry API checksum and size"
        )
        registry["verified_at"] = stamp
        registry["verified_by"] = "forensics/tools/verify_release_payloads.py (PFP-87)"

    return f"{version}: {'CORRECTED' if changed else 'OK'} {served[:16]}… {size}", changed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="record the measurement")
    mode.add_argument("--check", action="store_true", help="fresh verification, refuse drift")
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
        try:
            line, changed = verify(version, receipt, stamp)
        except Refusal as refusal:
            print(f"{version}: REFUSED: {refusal}")
            failures += 1
            continue
        except Exception as error:  # a network failure is a refusal, not a pass
            print(f"{version}: ERROR {type(error).__name__}: {error}")
            failures += 1
            continue

        if args.check:
            print(line)
            if changed:
                print(f"{version}: WOULD_CORRECT: the receipt disagrees with the served payload")
                failures += 1
        else:
            print(line)
            if changed:
                original = path.read_text(encoding="utf-8")
                path.write_text(
                    json.dumps(receipt, indent=_indent_of(original)) + "\n",
                    encoding="utf-8",
                )

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
