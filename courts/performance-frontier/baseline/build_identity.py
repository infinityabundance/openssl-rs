#!/usr/bin/env python3
"""Record the PFP-0 build identity as one JSON document.

Every later number in the campaign is tied to this document: it names the source
commit, the dirty state of the build-relevant inputs, the crate archive, the
distribution DSO that was benchmarked, the separate measurement DSO, the
authority DSO and the harness sources. Paths are repo-relative where possible so
the document stays readable after the court container is removed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build_id(path: Path) -> str | None:
    try:
        text = subprocess.check_output(
            ["readelf", "-n", str(path)], stderr=subprocess.DEVNULL, text=True
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    match = re.search(r"Build ID: ([0-9a-f]+)", text)
    return match.group(1) if match else None


def artefact(path: Path, repo: Path) -> dict:
    resolved = path.resolve()
    try:
        shown = str(resolved.relative_to(repo))
    except ValueError:
        shown = str(resolved)
    return {
        "path": shown,
        "size_bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
        "build_id": build_id(resolved),
    }


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "--no-optional-locks", "-C", str(repo), *args], text=True
    ).strip()


def command(*args: str) -> str:
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        return f"unavailable: {exc}"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("/work"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--measurement-dso", type=Path, required=True)
    parser.add_argument("--distribution-dso", type=Path, required=True)
    parser.add_argument("--authority-dso", type=Path, required=True)
    parser.add_argument("--harness", type=Path, action="append", default=[])
    parser.add_argument("--fixture-manifest", type=Path)
    parser.add_argument("--shell-record", type=Path)
    parser.add_argument("--court-image", default="unknown")
    args = parser.parse_args(argv)

    repo = args.repo.resolve()
    build_relevant = ["src", "Cargo.toml", "Cargo.lock", "build.rs",
                      "rust-toolchain.toml"]
    status = git(repo, "status", "--porcelain")
    build_status = git(repo, "status", "--porcelain", "--", *build_relevant)

    doc = {
        "schema": "openssl-rs/performance/build-identity/v1",
        "campaign": "PFP-0",
        "source": {
            "head": git(repo, "rev-parse", "HEAD"),
            "branch": git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
            "build_relevant_paths": build_relevant,
            "build_relevant_status": build_status,
            "build_relevant_clean": build_status == "",
            "worktree_status": status.splitlines(),
        },
        "build_recipe": [
            "cargo build --release --lib --offline (CARGO_BUILD_JOBS=4, "
            "fresh CARGO_TARGET_DIR)",
            "cc -shared -Wl,--whole-archive <archive> -Wl,--no-whole-archive "
            "-Wl,-soname,libcrypto.so.3 -o <measurement>/libcrypto.so.3",
            "python3 forensics/tools/implemented_surface.py --archive <archive> "
            "--out <fresh-surface>",
            "python3 courts/performance-frontier/baseline/emit_shell.py "
            "--surface <fresh-surface> --out <shell>",
            "rustc --edition 2021 --emit=obj --crate-type lib -O "
            "--crate-name libcrypto_shell -o <shell>/libcrypto.shell.o "
            "<shell>/libcrypto.shell.rs",
            "cc -shared -o <distribution>/libcrypto.so.3 "
            "-Wl,--whole-archive <archive> -Wl,--no-whole-archive "
            "<shell>/libcrypto.shell.o -Wl,--version-script=artifacts/phase2/"
            "libcrypto.ld -Wl,-soname,libcrypto.so.3 -Wl,--as-needed "
            "-lpthread -ldl -lm -lrt -lutil",
        ],
        "artefacts": {
            "crate_archive": artefact(args.archive, repo),
            "measurement_dso": artefact(args.measurement_dso, repo),
            "distribution_dso": artefact(args.distribution_dso, repo),
            "authority_dso": artefact(args.authority_dso, repo),
        },
        "harness": [artefact(path, repo) for path in args.harness],
        "tools": {
            "rustc": command("rustc", "--version"),
            "cargo": command("cargo", "--version"),
            "cc": command("cc", "--version").splitlines()[0] if command("cc", "--version") else "",
            "readelf": command("readelf", "--version").splitlines()[0] if command("readelf", "--version") else "",
        },
        "venue": {
            "court_image": args.court_image,
            "kernel": command("uname", "-r"),
            "machine": command("uname", "-m"),
        },
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    if args.fixture_manifest and args.fixture_manifest.is_file():
        doc["dh_fixtures"] = json.loads(args.fixture_manifest.read_text())
    if args.shell_record and args.shell_record.is_file():
        doc["shell_generation"] = json.loads(args.shell_record.read_text())

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    if not doc["source"]["build_relevant_clean"]:
        print("build_identity: build-relevant worktree is dirty", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
