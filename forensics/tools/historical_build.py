#!/usr/bin/env python3
"""openssl-rs — build an acquired historical OpenSSL release in the historical venue.

Phase 23 is the multitrack authority stratum (`docs/PHASE-23-MULTITRACK-SUBPHASES.md`).
23.2 acquires and builds historical authorities in a dedicated, separately pinned venue
(`docker/openssl-rs-historical.Dockerfile`, `docker/openssl-rs-historical.sh`) so that the
forensic court image never has to change to admit an old release.

This tool is the build half. It reads the acquisition records `authority_acquire.py --historical`
wrote (`forensics/multitrack/historical-acquisition.json`), builds each acquired release with an
era-appropriate configure profile, and records a **build receipt** per release in
`forensics/multitrack/historical-build-receipts.json`: the exact configure/build/install argv, the
toolchain and platform, and the binary and installed hashes the build produced.

Three rules it does not bend
----------------------------
  * **The raw authority tree is never edited.** Old OpenSSL (through 1.0.2) does not build
    out-of-tree, so the tool copies the extracted tree into `forensics/authorities/build/<id>/src`
    and builds **there**. The pristine tree under `forensics/authorities/src/` keeps the root hash
    its source manifest records.
  * **A build is not recorded as built unless it produced its shared objects.** The expected
    sonames must exist under the installed prefix, or the run aborts rather than writing a
    receipt.
  * **The venue is checked.** Builds run only where `docker/openssl-rs-historical.sh` put them:
    the `/historical` marker the image creates. Running this in the court would silently bind the
    wrong toolchain, so it refuses.

Outputs
-------
  forensics/authorities/build/<id>/              the out-of-source build (gitignored)
  forensics/authorities/prefix/<id>/             the installed prefix (gitignored)
  forensics/authorities/captures/<id>/           raw configure/make/install logs (gitignored)
  forensics/multitrack/historical-build-receipts.json   committed build receipts

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel, run as run_tool, write_json  # noqa: E402
from authority_build import run, tool_version  # noqa: E402

AUTH_ROOT = REPO_ROOT / "forensics" / "authorities"
REGISTRY = REPO_ROOT / "forensics" / "multitrack" / "historical-acquisition.json"
RECEIPTS = REPO_ROOT / "forensics" / "multitrack" / "historical-build-receipts.json"
BUILD_ROOT = AUTH_ROOT / "build"
PREFIX_ROOT = AUTH_ROOT / "prefix"
CAPTURE_ROOT = AUTH_ROOT / "captures"

# The venue marker docker/openssl-rs-historical.Dockerfile creates; its absence means this is
# not the historical venue and the toolchain would not be the one the receipt records.
VENUE_MARKER = Path("/historical/toolchain.txt")

# The pinned base of the venue image (docker/openssl-rs-historical.Dockerfile), recorded in the
# receipt so the build environment is content-addressed rather than described.
VENUE_IMAGE = "openssl-rs-historical:1"
VENUE_BASE = "debian@sha256:e5b6442dd2e9684cf5e87d8338b5968f3b348636fc0be6d7850a381e3731a2bd"

# The historical configure profile. Pre-1.1.0 OpenSSL does not build out-of-tree and its
# Makefile.org races under `make -j`, so the build is **serial**; the profile is one named,
# recorded choice, and the sonames carry the release's own `0.9.8`/`1.0.0`-era ABI version.
HISTORICAL_TARGET = "linux-x86_64"
HISTORICAL_PROFILE = "linux-x86_64-historical-shared"
HISTORICAL_PROFILE_ARGS = ["shared"]

# The installed public headers whose hashes bind the installed surface.
INSTALLED_HEADERS = ("include/openssl/ssl.h", "include/openssl/crypto.h", "include/openssl/evp.h")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_acquisitions() -> dict[str, dict]:
    if not REGISTRY.is_file():
        raise SystemExit(
            f"historical-build: {rel(REGISTRY)} is absent; run "
            f"`authority_acquire.py --historical <release>` first"
        )
    doc = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return {r["release_id"]: r for r in doc.get("acquisitions", [])}


def _versioned_so(prefix: Path, stem: str) -> Path:
    """The installed versioned shared object for `stem` (`libcrypto` / `libssl`).

    Prefers a real file over the development symlink, and refuses to guess: a missing expected
    soname is a fatal, not a skip.
    """
    libdir = prefix / "lib"
    candidates = sorted(p for p in libdir.glob(f"{stem}.so.*") if not p.is_symlink())
    if not candidates:
        raise SystemExit(f"historical-build: expected {stem}.so.* under {libdir}, found none")
    return candidates[-1]


def build_release(acq: dict, *, force: bool) -> dict:
    aid = acq["id"]
    release_id = acq["release_id"]
    version = acq["version"]
    src = REPO_ROOT / acq["source_tree"]["path"]
    build_dir = BUILD_ROOT / aid
    src_copy = build_dir / "src"
    prefix = PREFIX_ROOT / aid
    capture = CAPTURE_ROOT / aid

    print(f"[historical-build] {aid}")
    if not src.exists():
        raise SystemExit(f"historical-build: source tree missing for {aid}: {src}")

    if force and build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    capture.mkdir(parents=True, exist_ok=True)

    # Copy, never build in the pristine tree: old OpenSSL builds in-tree and would dirty the
    # tree whose root hash the source manifest records.
    if not src_copy.exists():
        shutil.copytree(src, src_copy, symlinks=True)

    env = {**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}

    configure_argv = [
        "perl", "Configure", HISTORICAL_TARGET,
        f"--prefix={prefix}",
        f"--openssldir={prefix}/ssl",
        *HISTORICAL_PROFILE_ARGS,
    ]
    print("  configure ...")
    if run(configure_argv, cwd=src_copy, env=env, log=capture / "configure.log") != 0:
        raise SystemExit(f"FATAL: Configure failed for {aid} (see {capture / 'configure.log'})")

    # Serial `make`: the pre-1.1.0 Makefile.org has a rule-ordering race under `-j`, so the
    # profile is deliberately serial; a parallel build is not a different result, it is a
    # nondeterministic failure.
    print("  make (serial) ...")
    if run(["make"], cwd=src_copy, env=env, log=capture / "make.log") != 0:
        raise SystemExit(f"FATAL: make failed for {aid} (see {capture / 'make.log'})")

    print("  make install ...")
    if run(["make", "install"], cwd=src_copy, env=env, log=capture / "install.log") != 0:
        raise SystemExit(f"FATAL: make install failed for {aid} (see {capture / 'install.log'})")

    # A build is only "built" if it produced its shared objects under the prefix.
    binary_hashes: dict[str, str] = {}
    artifacts: list[dict] = []
    for stem in ("libcrypto", "libssl"):
        so = _versioned_so(prefix, stem)
        digest = sha256_file(so)
        binary_hashes[so.name] = digest
        artifacts.append({"name": so.name, "path": rel(so),
                          "size_bytes": so.stat().st_size, "sha256": digest})

    installed_hashes: dict[str, str] = {}
    for relname in INSTALLED_HEADERS:
        header = prefix / relname
        if header.is_file():
            installed_hashes[relname] = sha256_file(header)
    if not installed_hashes:
        raise SystemExit(f"FATAL: {aid}: no installed public headers found under {prefix}")

    banner = ""
    openssl_bin = prefix / "bin" / "openssl"
    if openssl_bin.exists():
        res = run_tool([str(openssl_bin), "version"], cwd=prefix)
        banner = (res.stdout or res.stderr).strip()
        (capture / "built-openssl-version.txt").write_text(banner + "\n", encoding="utf-8")

    return {
        "id": aid,
        "release_id": release_id,
        "version": version,
        "git": dict(acq["git"]),
        "source_package": {
            "artifact": acq["artifact"]["filename"],
            "sha256": acq["artifact"]["sha256"],
            "published_sha256": acq["artifact"]["published_sha256"],
            "checksum_verified": acq["artifact"]["checksum_verified"],
            "source_url": acq["upstream"]["source_url"],
        },
        "source_manifest": {
            "path": f"forensics/authorities/{acq['source_tree']['manifest']}",
            "root_hash": acq["source_tree"]["root_hash"],
            "file_count": acq["source_tree"]["file_count"],
        },
        "source_tree_pristine": acq["source_tree"]["path"],
        "profile": HISTORICAL_PROFILE,
        "configure_argv": configure_argv,
        "profile_args": HISTORICAL_PROFILE_ARGS,
        "build_argv": ["make"],
        "install_argv": ["make", "install"],
        "toolchain": {
            "cc": tool_version(["cc", "--version"]),
            "gcc": tool_version(["gcc", "--version"]),
            "ld": tool_version(["ld", "--version"]),
            "make": tool_version(["make", "--version"]),
            "perl": tool_version(["perl", "-e", "print $]"]),
            "python": platform.python_version(),
        },
        "platform": {"machine": platform.machine(), "system": platform.system()},
        "build_environment": {
            "venue": "openssl-rs-historical",
            "image": VENUE_IMAGE,
            "base": VENUE_BASE,
            "locale": "C.UTF-8",
            "parallel_jobs": 1,
        },
        "binary_hashes": binary_hashes,
        "installed_hashes": installed_hashes,
        "artifacts": sorted(artifacts, key=lambda a: a["name"]),
        "banner": banner,
        "outcome": "built",
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--release", action="append", default=[],
                    help="release id to build (repeatable); default: every acquired release")
    ap.add_argument("--force", action="store_true", help="rebuild from a fresh copy")
    args = ap.parse_args(argv)

    if not VENUE_MARKER.is_file():
        raise SystemExit(
            "historical-build: this is not the historical venue (no /historical marker); run it "
            "through `bash docker/openssl-rs-historical.sh exec ...` so the receipt binds the "
            "venue's toolchain rather than the court's"
        )

    acquisitions = load_acquisitions()
    if args.release:
        unknown = [r for r in args.release if r not in acquisitions]
        if unknown:
            raise SystemExit(f"historical-build: not acquired: {unknown}")
        targets = [acquisitions[r] for r in args.release]
    else:
        targets = [acquisitions[k] for k in sorted(acquisitions)]
    if not targets:
        raise SystemExit("historical-build: no acquired release to build")

    out: list[dict] = []
    if RECEIPTS.exists():
        existing = json.loads(RECEIPTS.read_text(encoding="utf-8"))
        out = [r for r in existing.get("receipts", []) if r["release_id"] not in
               {t["release_id"] for t in targets}]
    for acq in targets:
        out.append(build_release(acq, force=args.force))

    RECEIPTS.parent.mkdir(parents=True, exist_ok=True)
    doc = {"schema": "openssl-rs/historical-build-receipts/v1",
           "receipts": sorted(out, key=lambda r: r["release_id"])}
    doc["content_hash"] = hashlib.sha256(
        json.dumps(doc["receipts"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    write_json(RECEIPTS, doc)
    print(f"[historical-build] wrote {rel(RECEIPTS)} "
          f"({len(doc['receipts'])} receipt(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
