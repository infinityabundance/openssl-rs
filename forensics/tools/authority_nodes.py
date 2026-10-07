#!/usr/bin/env python3
"""openssl-rs — the authority-node registry, read from the records that carry each build.

Phase 23 is the multitrack authority stratum (`docs/PHASE-23-MULTITRACK-SUBPHASES.md`). 23.2 says
the authority-node registry is *one authority node per built authority*: the release it is built
from, the platform, architecture, build profile, toolchain and build environment, and the binary
and installed hashes that bind the build. This module derives that registry -- `forensics/
authority-nodes.json` -- from the artefacts that already carry those facts, and never types one:

  * `forensics/release-catalog.json` -- the release identity (`release_id`, `upstream_tag`,
    `upstream_commit`) of the release a node is built from;
  * `forensics/authorities/AUTHORITIES.json` -- the admitted pair's source-package identity (the
    verified archive SHA-256, the published SHA-256 and the source-tree root hash);
  * `forensics/atlas/BUILD_RECORDS.json` -- the admitted pair's build profile, configure argv,
    toolchain and platform;
  * `forensics/multitrack/historical-acquisition.json` and
    `forensics/multitrack/historical-build-receipts.json` -- a historical release's acquisition and
    build; and
  * the installed prefixes under `forensics/authorities/prefix/` -- the binary and installed
    hashes, hashed here when the prefix is present and recorded `unknown` when it is not.

Two identities, kept apart
---------------------------
The schema's `release_id` (with the registry's `git` block) is the **release identity**: what
upstream released. `platform`, `arch`, `build_profile`, `toolchain` and `build_environment` are the
**platform/profile identity**: this build, in this venue, with this toolchain. A node names both,
and neither is inferred from the other -- a tag is never assumed to be the release tarball, and a
release is never assumed to have one platform.

Unresolved stays visible
------------------------
A release that could not be acquired or built is not omitted: it is in the registry's `unavailable`
list with its reason, and it is **never** a node. `docs/PARITY_MODEL.md` section 1: unknown stays
unknown.

Outputs
-------
  forensics/authority-nodes.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    write_json,
)

import multitrack_schemas as mts  # noqa: E402

OUT = REPO_ROOT / "forensics" / "authority-nodes.json"
GENERATOR = "forensics/tools/authority_nodes.py"
CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
AUTHORITIES = REPO_ROOT / "forensics" / "authorities" / "AUTHORITIES.json"
BUILD_RECORDS = REPO_ROOT / "forensics" / "atlas" / "BUILD_RECORDS.json"
HIST_ACQ = REPO_ROOT / "forensics" / "multitrack" / "historical-acquisition.json"
HIST_RECEIPTS = REPO_ROOT / "forensics" / "multitrack" / "historical-build-receipts.json"

# The installed public headers whose hashes bind the installed surface, the same set the
# historical build receipt records.
INSTALLED_HEADERS = ("include/openssl/ssl.h", "include/openssl/crypto.h", "include/openssl/evp.h")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"authority-nodes: {rel(path)} is absent")
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def catalog_git(catalog: dict, release_id: str) -> dict:
    for node in catalog["nodes"]:
        if node["release_id"] == release_id:
            return {"tag": node["upstream_tag"], "commit": node["upstream_commit"]}
    return {"tag": "unknown", "commit": "unknown"}


def hashes_from_prefix(prefix: Path, sonames: tuple[str, ...]) -> tuple[dict, dict]:
    """`(binary_hashes, installed_hashes)` read from an installed prefix, or `unknown` values.

    A prefix that is absent still yields the *names* the build is expected to carry, valued the
    literal `unknown`: a missing prefix is a fact to record, not a reason to omit a node.
    """
    libdir = prefix / "lib"
    binary: dict[str, str] = {}
    for name in sonames:
        for candidate in (libdir / name, prefix / name):
            if candidate.is_file() and not candidate.is_symlink():
                binary[name] = sha256_file(candidate)
                break
        else:
            binary[name] = "unknown"
    installed: dict[str, str] = {}
    for relname in INSTALLED_HEADERS:
        header = prefix / relname
        installed[relname] = sha256_file(header) if header.is_file() else "unknown"
    return binary, installed


def admitted_node(rec: dict, build: dict, catalog: dict) -> dict:
    """An authority node for an admitted pair member, from its registry and build record."""
    aid = rec["id"]
    release_id = f"openssl-{rec['version']}"
    prefix = REPO_ROOT / build["prefix"]
    binary, installed = hashes_from_prefix(prefix, ("libcrypto.so.3", "libssl.so.3"))
    tc = build["build_toolchain"]
    return {
        "authority_id": aid,
        "release_id": release_id,
        "platform": "linux",
        "arch": build["build_platform"]["machine"],
        "build_profile": build["profile"],
        "toolchain": tc.get("cc") or tc.get("clang") or "unknown",
        "build_environment": {
            "venue": "openssl-rs-court",
            "image": "openssl-rs-court:1",
            "configure_argv": build["configure_argv"],
            "profile_args": build["profile_args"],
            "captures": build["captures"],
        },
        "binary_hashes": binary,
        "installed_hashes": installed,
        "metadata_provenance": [
            "forensics/authorities/AUTHORITIES.json",
            "forensics/atlas/BUILD_RECORDS.json",
            f"forensics/authorities/{rec['source_tree']['manifest']}",
            "forensics/release-catalog.json",
        ],
        # Release identity, kept separate from the platform/profile identity above.
        "git": catalog_git(catalog, release_id),
        "source_package": {
            "artifact": rec["artifact"]["filename"],
            "sha256": rec["artifact"]["sha256"],
            "published_sha256": rec["artifact"]["published_sha256"],
            "checksum_verified": rec["artifact"]["checksum_verified"],
        },
        "claim": "built-authority",
        "build_receipt": "forensics/atlas/BUILD_RECORDS.json",
        "runtime_evidence": "available",
    }


def historical_node(receipt: dict) -> dict:
    """An authority node for a historical build, from its committed build receipt."""
    return {
        "authority_id": receipt["id"],
        "release_id": receipt["release_id"],
        "platform": "linux",
        "arch": receipt["platform"]["machine"],
        "build_profile": receipt["profile"],
        "toolchain": receipt["toolchain"]["cc"],
        "build_environment": {
            **receipt["build_environment"],
            "configure_argv": receipt["configure_argv"],
            "profile_args": receipt["profile_args"],
        },
        "binary_hashes": dict(receipt["binary_hashes"]),
        "installed_hashes": dict(receipt["installed_hashes"]),
        "metadata_provenance": [
            rel(HIST_RECEIPTS),
            receipt["source_manifest"]["path"],
            rel(HIST_ACQ),
            "forensics/release-catalog.json",
        ],
        "git": dict(receipt["git"]),
        "source_package": {
            "artifact": receipt["source_package"]["artifact"],
            "sha256": receipt["source_package"]["sha256"],
            "published_sha256": receipt["source_package"]["published_sha256"],
            "checksum_verified": receipt["source_package"]["checksum_verified"],
        },
        "claim": "built-authority",
        "build_receipt": rel(HIST_RECEIPTS),
        "runtime_evidence": "available",
    }


def unavailable_row(entry: dict) -> dict:
    """An unavailable release, carried as a fact -- never as a runtime-compatible authority."""
    return {
        "release_id": entry["release_id"],
        "version": entry["version"],
        "git": dict(entry.get("git", {})),
        "outcome": "unavailable",
        "reason": entry["reason"],
        "runtime_evidence": "unavailable",
        "runtime_compatible": False,
        "metadata_provenance": [rel(HIST_ACQ), "forensics/release-catalog.json"],
    }


def build_body() -> dict:
    catalog = load(CATALOG)
    authorities = load(AUTHORITIES)["authorities"]
    builds = {b["id"]: b for b in load(BUILD_RECORDS)["builds"]}
    hist_receipts = load(HIST_RECEIPTS)["receipts"]
    hist_acq = load(HIST_ACQ)

    nodes: list[dict] = []
    for rec in authorities:
        if rec["id"] not in builds:
            raise SystemExit(
                f"authority-nodes: {rec['id']} is admitted but has no build record, so no node "
                f"can be derived; run authority_build.py first"
            )
        nodes.append(admitted_node(rec, builds[rec["id"]], catalog))
    for receipt in hist_receipts:
        nodes.append(historical_node(receipt))
    nodes.sort(key=lambda n: n["authority_id"])

    unavailable = sorted((unavailable_row(e) for e in hist_acq.get("unavailable", [])),
                         key=lambda r: r["release_id"])

    for node in nodes:
        problems = mts.validate_authority_node(node)
        if problems:
            raise SystemExit(f"authority-nodes: derived node {node['authority_id']} is not "
                             f"schema-valid: {problems}")

    counts = {
        "nodes": len(nodes),
        "built": sum(1 for n in nodes if n["claim"] == "built-authority"),
        "admitted": len(authorities),
        "historical_built": len(hist_receipts),
        "unavailable": len(unavailable),
    }
    return {
        "rule": (
            "one authority node per built authority, read from the records that carry each build "
            "-- the release catalogue, AUTHORITIES.json, BUILD_RECORDS.json and the historical "
            "acquisition and build receipts -- and never typed. Each node keeps release identity "
            "(release_id, git) separate from platform/profile identity (platform, arch, "
            "build_profile, toolchain, build_environment), and is content-addressed by its binary "
            "and installed hashes. A release that could not be acquired or built is recorded in "
            "`unavailable` with its reason and is never a node"
        ),
        "nodes": nodes,
        "unavailable": unavailable,
        "counts": counts,
        "content_hash": content_hash({"nodes": nodes, "unavailable": unavailable}),
        "note": (
            "the registry is a registry of *builds*, not of releases: an authority node is what a "
            "court can be run against, and a release node in forensics/release-catalog.json is a "
            "fact about upstream. The admitted pair openssl-3.6.3-historical and "
            "openssl-3.6.4-production are build-compatible in the forensic court "
            "(linux-x86_64-default-shared-legacy-notests); the built historical authority "
            "openssl-0.9.8zh-historical is a pre-1.1.0 source with no out-of-tree build, built in "
            "the separately pinned historical venue (docs/PHASE-23-MULTITRACK-SUBPHASES.md section "
            "2). The unavailable list names the early releases whose official digest could not be "
            "fetched, so they were not admitted: an unavailable authority is never counted as "
            "runtime-compatible"
        ),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    body = build_body()

    inputs = [
        InputRef(name="release-catalog", path=CATALOG),
        InputRef(name="authority-registry", path=AUTHORITIES),
        InputRef(name="build-records", path=BUILD_RECORDS),
        InputRef(name="historical-acquisition", path=HIST_ACQ),
        InputRef(name="historical-build-receipts", path=HIST_RECEIPTS),
    ]
    doc = envelope(kind="authority-nodes", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[authority-nodes] nodes={c['nodes']} built={c['built']} "
          f"admitted={c['admitted']} historical_built={c['historical_built']} "
          f"unavailable={c['unavailable']}")
    for n in body["nodes"]:
        print(f"  {n['authority_id']:<34} release={n['release_id']:<18} "
              f"profile={n['build_profile']} claim={n['claim']} receipt={n['build_receipt']}")
    for u in body["unavailable"]:
        print(f"  {u['release_id']:<34} unavailable: {u['reason']}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
