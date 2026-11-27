#!/usr/bin/env python3
"""Build the timing campaign's identity document at a frozen DSO.

The tracked `build_identity.py` records `git rev-parse HEAD`; that is right for
a campaign that rebuilds, but this timing run deliberately does **not** rebuild.
It benchmarks the frozen distribution DSO at 04611380, whose build-relevant
source is staging commit 289f11187 (the PFP-3 commit).  Recording the
current HEAD instead would misattribute the artefact, so this script takes the
source commit explicitly and records how that attribution was established.

The document keeps the same schema and the same `artefacts`/`harness`/`tools`/
`source` keys the analyser reads, so `analyse_bench_api.py` is used unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--measurement-dso", type=Path, required=True)
    parser.add_argument("--distribution-dso", type=Path, required=True)
    parser.add_argument("--authority-dso", type=Path, required=True)
    parser.add_argument("--harness", type=Path, action="append", default=[])
    parser.add_argument("--fixture-manifest", type=Path)
    parser.add_argument("--court-image", default="unknown")
    args = parser.parse_args(argv)

    repo = args.repo.resolve()
    build_relevant = ["src", "Cargo.toml", "Cargo.lock", "build.rs",
                      "rust-toolchain.toml"]
    status = git(repo, "status", "--porcelain")
    build_status = git(repo, "status", "--porcelain", "--", *build_relevant)
    head = git(repo, "rev-parse", "HEAD")
    head_src = git(repo, "rev-parse", "HEAD:src")
    record_src = git(repo, "rev-parse", f"{args.source_commit}:src")

    doc = {
        "schema": "openssl-rs/performance/build-identity/v1",
        "campaign": "PFP-3",
        "source": {
            "head": args.source_commit,
            "branch": "staging (recorded candidate source)",
            "build_relevant_paths": build_relevant,
            "build_relevant_status": build_status,
            "build_relevant_clean": build_status == "",
            "worktree_status": status.splitlines(),
            "derivation": (
                "This timing run benchmarks the frozen distribution DSO; it does "
                "not rebuild. source.head is the commit whose build-relevant tree "
                "produced that DSO, not the current checkout HEAD."
            ),
            "current_head": head,
            "current_head_src_tree": head_src,
            "recorded_source_src_tree": record_src,
            "current_head_src_matches_recorded": head_src == record_src,
        },
        "build_recipe": [
            "cargo build --release --lib --offline (CARGO_BUILD_JOBS=4, "
            "fresh CARGO_TARGET_DIR) — performed by the campaign that produced "
            "the frozen DSO, not by this timing run",
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

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    if not doc["source"]["build_relevant_clean"]:
        # The PFP-3 conversion is an uncommitted working-tree change by campaign
        # rule.  Record it truthfully (`build_relevant_clean: false` and the
        # exact dirty paths) instead of refusing; the DSO/archive digests are
        # pinned by the runner and the two fresh builds reproduce them, so the
        # measured artefact is still identity-bound.
        print(
            "build_identity: build-relevant worktree is dirty (recorded truthfully; "
            "candidate is an uncommitted conversion)",
            file=sys.stderr,
        )
    if not doc["source"]["current_head_src_matches_recorded"]:
        print(
            "build_identity: current HEAD src tree differs from the recorded "
            "candidate source; the DSO attribution is not established",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
