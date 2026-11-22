#!/usr/bin/env python3
"""etp6_package.py -- build the frozen, self-contained ETP-6 reproduction package.

The package is produced from a named commit with `git archive`, never from a
copy of the working tree.  It carries:

  * the crate source, Cargo.lock, rust-toolchain.toml and the pinned toolchain
    identity;
  * every tracked evidence, receipt, document and verification tool that the
    offline verifier reads;
  * a partial Git object store (`freeze-git`) holding the frozen claim-set
    commit and every blob the claim set cites, so the Git-bound tree check runs
    with no network and no development checkout;
  * MANIFEST.json, listing every input by path and SHA-256 and every
    verification step with its command, expected exit status and what it
    establishes;
  * a top-level verify.sh.

The builder refuses to produce a package when

  * a *required* input is untracked, absent from the commit, or matched by a
    .gitignore rule (including everything under court/tmp/); or
  * an input's SHA-256 does not match the frozen MANIFEST.json (run
    --refreeze only after reviewing the drift).

An input that the claim set merely *cites* but that is untracked or gitignored
is recorded as a refusal and is not placed in the package.  The refusal list is
what converts ETP-0's reconstruction gaps into a named failure instead of a
footnote.  --refreeze writes the manifest; the default mode verifies it.

Usage:
    python3 forensics/tools/etp6_package.py --refreeze
    python3 forensics/tools/etp6_package.py [--out DIR] [--commit REV]
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "evidence/etp6/MANIFEST.json"
VERIFY_SCRIPT = ROOT / "forensics/etp6/verify.sh"
SOURCE_DATE_EPOCH = 1609459200

# (repository path, requires, role) -- a directory selects its tracked files at
# the named commit through `git archive`.
SELECTION: list[tuple[str, bool, str]] = [
    ("src", True, "source"),
    ("Cargo.toml", True, "source"),
    ("Cargo.lock", True, "source"),
    ("rust-toolchain.toml", True, "source"),
    ("build.rs", True, "source"),
    ("tests", False, "source"),
    ("examples", False, "source"),
    ("README.md", True, "doc"),
    ("AGENTS.md", True, "doc"),
    ("docs", True, "doc"),
    ("forensics/tools", True, "tool"),
    ("forensics/etp6/verify.sh", True, "tool"),
    ("forensics/frf/README.md", True, "doc"),
    ("forensics/regression-baseline.json", True, "evidence"),
    ("forensics/phase-state.json", True, "evidence"),
    ("forensics/atlas/implemented-surface.json", True, "evidence"),
    ("forensics/atlas/phase1-completeness.json", True, "evidence"),
    ("forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json", True, "evidence"),
    ("forensics/authorities/AUTHORITIES.json", False, "evidence"),
    ("forensics/multitrack/default-authority.json", False, "evidence"),
    ("forensics/multitrack/abi-facades.json", False, "evidence"),
    ("artifacts/phase2/libcrypto.ld", False, "evidence"),
    ("artifacts/phase2/SHELL_MANIFEST.json", False, "evidence"),
    ("artifacts/phase2/install", True, "artefact"),
    ("courts/phase18/interop", True, "evidence"),
    ("courts/phase18/timing", True, "evidence"),
    ("courts/performance-frontier/baseline", True, "evidence"),
    ("evidence/etp0", True, "evidence"),
    ("evidence/etp", True, "evidence"),
    ("evidence/etp2", True, "evidence"),
    ("evidence/etp3", True, "evidence"),
    ("evidence/etp4", True, "evidence"),
    ("evidence/etp5", True, "evidence"),
]

# Artefacts named by ETP-0 that are absent from a clean checkout.  They are
# probed by the builder and recorded as refusals when they are still ignored.
NAMED_GAPS = [
    ("artifacts/phase2/libcrypto.so.3", "ETP-0 RECEIPT section 6 (distribution DSO)"),
    ("artifacts/phase2/shell/libcrypto.shell.rs",
     "ETP-0 RECEIPT section 6 (historical distribution shell source)"),
    ("court/tmp/t20/NOTES.md", "ETP0-CLM-012 evidence"),
    ("court/tmp/t21/libcrypto.so.3", "ETP0-CLM-014 evidence"),
]

VERIFICATION_STEPS = [
    {
        "id": "digests",
        "command": "./verify.sh --only digests",
        "expected_exit": 0,
        "required": True,
        "establishes": "Every packaged input matches the SHA-256 in this manifest; "
                       "every cited evidence digest with a digest identity is "
                       "re-derived (S from the frozen object store, the historical "
                       "revision from its named commit, E from the package file).",
        "does_not_establish": "That a digest-bound artefact is correct, complete or "
                              "sufficient for the claim that cites it.",
    },
    {
        "id": "claims",
        "command": "./verify.sh --only claims",
        "expected_exit": 0,
        "required": True,
        "establishes": "evidence/etp/claims.json validates against its schema with "
                       "the Git-bound tree check at the frozen source commit.",
        "does_not_establish": "That any claim is true; the algebra checks typing and "
                              "law, never truth.",
    },
    {
        "id": "interop",
        "command": "./verify.sh --only interop",
        "expected_exit": 0,
        "required": True,
        "establishes": "courts/phase18/interop/check_receipts.py finds no R1-R5 "
                       "problem in the tracked interop receipts and manifests, and "
                       "every manifest log is present with the recorded digest.",
        "does_not_establish": "That the interop executions can be repeated here; the "
                              "logs and receipts are re-verified, not re-run.",
    },
    {
        "id": "instruments",
        "command": "./verify.sh --only instruments",
        "expected_exit": 0,
        "required": True,
        "establishes": "The ETP-3 instrument register validates (paths, versions, "
                       "prerequisites, bindings) and every executable control whose "
                       "external tool is installed passes and matches the register. "
                       "Controls whose tool is absent are reported NOT_RUN, never PASS.",
        "does_not_establish": "A security result; instrument qualification is not a "
                              "memory-safety, compatibility or constant-time proof.",
    },
    {
        "id": "docs",
        "command": "./verify.sh --only docs",
        "expected_exit": 0,
        "required": True,
        "establishes": "The named hand-written quantities agree with their generated "
                       "sources, and exemptions still apply to a live contradiction.",
        "does_not_establish": "Consistency of prose outside the registered checks.",
    },
    {
        "id": "reproducibility",
        "command": "./verify.sh --full",
        "expected_exit": 0,
        "required": False,
        "establishes": "Two independently initialised release builds and the "
                       "distribution DSO are byte-identical from this source tree.",
        "does_not_establish": "Reproducibility on another machine, toolchain or "
                              "architecture.",
        "requires": [
            "rust-toolchain.toml channel 1.98.1 (cargo, rustc, rustfmt)",
            "the court container (forensics/tools/require_court.sh exits 97 elsewhere)",
            "CARGO_BUILD_JOBS<=4; the recipe performs two release builds",
        ],
    },
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str, text: bool = True, check: bool = True):
    proc = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True,
                          text=text, check=False)
    if check and proc.returncode != 0:
        message = proc.stderr if text else proc.stderr.decode("utf-8", "replace")
        raise RuntimeError(f"git {' '.join(args)} failed: {message.strip()}")
    return proc


def json_strict(data: bytes):
    def _object(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                raise ValueError(f"duplicate JSON key {key!r}")
            seen.add(key)
        return dict(pairs)

    return json.loads(data.decode("utf-8"), object_pairs_hook=_object)


def reason_tracked(path: str, commit: str) -> str | None:
    proc = git("ls-tree", "-r", "--name-only", commit, "--", path, check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return ("untracked or absent at the named commit "
                "(git ls-tree finds nothing for this path)")
    return None


def reason_ignored(path: str) -> str | None:
    proc = git("check-ignore", "--no-index", "-v", "--", path, check=False)
    if proc.returncode == 0:
        return f"gitignored: {proc.stdout.strip()}"
    return None


def in_commit(commit: str, path: str) -> int:
    proc = git("ls-tree", "-r", "--name-only", commit, "--", path, check=False)
    if proc.returncode != 0:
        return 0
    return len([line for line in proc.stdout.splitlines() if line.strip()])


def object_store(stage: Path, claims: dict) -> dict:
    """Write a partial bare repository holding the frozen claim commit.

    The store carries the commit object, the tree chain for every cited path,
    and the cited blobs.  Parent commits are deliberately absent: `git show
    <commit>:<path>` resolves the commit's own tree and needs no ancestry.  The
    objects are copied from the real repository, so the check is Git object
    identity, not a re-hash of an extracted copy.
    """
    source = claims.get("source_identity", {})
    frozen = source.get("commit")
    if not isinstance(frozen, str):
        raise RuntimeError("claims.json has no source_identity.commit")
    paths: set[str] = set()
    historical: dict[str, str] = {}
    for claim in claims.get("claims", []):
        for evidence in claim.get("evidence", []):
            identity = evidence.get("digest_identity")
            path = evidence.get("path")
            if not isinstance(path, str):
                continue
            if identity == "S":
                paths.add(path)
            elif identity == "historical":
                match = re.search(r"\bat commit ([0-9a-f]{7,40})\b",
                                  str(evidence.get("note", "")))
                if match:
                    commit = git("rev-parse", f"{match.group(1)}^{{commit}}").stdout.strip()
                    historical[commit] = path

    objects: set[str] = set()
    commits = [frozen, *historical]

    def add_commit(commit: str, selected: set[str]) -> None:
        objects.add(commit)
        objects.add(git("rev-parse", f"{commit}^{{tree}}").stdout.strip())
        for path in sorted(selected):
            proc = git("rev-parse", f"{commit}:{path}", check=False)
            if proc.returncode != 0:
                raise RuntimeError(
                    f"cited path {path} does not exist at {commit}; the claim set "
                    "cites evidence the frozen commit does not contain")
            objects.add(proc.stdout.strip())
            parts = path.split("/")
            for index in range(1, len(parts)):
                tree = "/".join(parts[:index])
                objects.add(git("rev-parse", f"{commit}:{tree}").stdout.strip())

    add_commit(frozen, paths)
    for commit, path in historical.items():
        add_commit(commit, {path})

    pack = subprocess.run(["git", "-C", str(ROOT), "pack-objects", "--stdout"],
                          input=("\n".join(sorted(objects)) + "\n").encode(),
                          capture_output=True, check=False)
    if pack.returncode != 0:
        raise RuntimeError(f"git pack-objects failed: {pack.stderr.decode()[:400]}")

    gitdir = stage / "freeze-git"
    subprocess.run(["git", "init", "--bare", "-q", str(gitdir)], check=True)
    packdir = gitdir / "objects/pack"
    packdir.mkdir(parents=True, exist_ok=True)
    packfile = packdir / "pack-etp6.pack"
    packfile.write_bytes(pack.stdout)
    subprocess.run(["git", "-C", str(gitdir), "index-pack",
                    "objects/pack/pack-etp6.pack"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", str(gitdir), "update-ref", "refs/heads/frozen",
                    frozen], check=True)
    for commit in historical:
        subprocess.run(["git", "-C", str(gitdir), "update-ref",
                        f"refs/heads/historical-{commit[:12]}", commit], check=True)
    return {
        "path": "freeze-git",
        "commits": commits,
        "object_count": len(objects),
        "pack": "freeze-git/objects/pack/pack-etp6.pack",
        "pack_sha256": sha256_file(packfile),
        "pack_bytes": packfile.stat().st_size,
        "note": "Partial bare repository: the frozen commit, the cited tree "
                "chains and the cited blobs, copied from the development "
                "repository.  Parent commits are absent by design; git show "
                "<commit>:<path> needs no ancestry.",
    }


def role_for(path: str, declared: dict[str, str]) -> str:
    if path in declared:
        return declared[path]
    if path == ".git" or path.startswith("freeze-git/"):
        return "object-store"
    if path == "verify.sh" or path == "TOOLCHAIN.json":
        return "tool" if path == "verify.sh" else "evidence"
    if path.startswith("evidence/"):
        return "evidence"
    if path.startswith("docs/") or path in {"README.md", "AGENTS.md"}:
        return "doc"
    if path.startswith("src/") or path in {"Cargo.toml", "Cargo.lock", "build.rs",
                                           "rust-toolchain.toml"} or path.startswith(
            ("tests/", "examples/")):
        return "source"
    if path.startswith("artifacts/"):
        return "artefact"
    if path.startswith("courts/"):
        return "tool" if path.endswith((".py", ".sh", ".c")) else "evidence"
    if path.startswith("forensics/"):
        return "tool" if path.endswith((".py", ".sh", ".c")) else "evidence"
    return "evidence"


def git_env(args: list[str], env: dict, text: bool = True):
    proc = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True,
                          text=text, check=False, env=env)
    if proc.returncode != 0:
        message = proc.stderr if text else proc.stderr.decode("utf-8", "replace")
        raise RuntimeError(f"git {' '.join(args)} failed: {message.strip()}")
    return proc


def provisional_commit(paths: list[str]) -> tuple[str, str]:
    """Create a real commit object from HEAD plus the worktree selection paths.

    Used only when the ETP-6 tooling itself has not yet been committed (the
    orchestrator commits the reported change).  A temporary index is built from
    HEAD, `git add -A` stages the selection paths (untracked but not ignored),
    and `git commit-tree` writes a commit object that is not on any branch.  The
    source tree is therefore produced by `git archive` from a commit, never by
    copying the working tree, and the tree hash is recorded in MANIFEST.json.
    """
    handle, index_name = tempfile.mkstemp(prefix="etp6-index-")
    os.close(handle)
    index = Path(index_name)
    env = dict(os.environ)
    env["GIT_INDEX_FILE"] = str(index)
    env["GIT_AUTHOR_NAME"] = "ETP-6 package builder"
    env["GIT_AUTHOR_EMAIL"] = "etp6-builder@localhost"
    env["GIT_COMMITTER_NAME"] = "ETP-6 package builder"
    env["GIT_COMMITTER_EMAIL"] = "etp6-builder@localhost"
    env["GIT_AUTHOR_DATE"] = "1609459200 +0000"
    env["GIT_COMMITTER_DATE"] = "1609459200 +0000"
    try:
        git_env(["read-tree", "HEAD"], env)
        git_env(["add", "-A", "--", *paths], env)
        tree = git_env(["write-tree"], env).stdout.strip()
        commit = git_env(["commit-tree", tree, "-p", "HEAD", "-m",
                          "etp6: provisional package commit (not on a branch)"],
                         env).stdout.strip()
    finally:
        index.unlink(missing_ok=True)
    return commit, tree


def stage_tree(stage: Path, commit: str, paths: list[str]) -> None:
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar",
                              commit, "--", *paths], capture_output=True,
                             check=False)
    if archive.returncode != 0:
        raise RuntimeError(f"git archive failed: {archive.stderr.decode()[:400]}")
    extract = subprocess.run(["tar", "-x", "-C", str(stage)], input=archive.stdout,
                             capture_output=True, check=False)
    if extract.returncode != 0:
        raise RuntimeError(f"tar extraction failed: {extract.stderr.decode()[:400]}")


def toolchain_identity(stage: Path) -> dict:
    pin = stage / "rust-toolchain.toml"
    record = json_stage(stage / "evidence/etp2/reproducibility.json")
    toolchain = record.get("toolchain", {}) if isinstance(record, dict) else {}
    return {
        "pin_file": "rust-toolchain.toml",
        "pin_sha256": sha256_file(pin),
        "channel": "1.98.1",
        "rustc": toolchain.get("rustc"),
        "rustc_commit": toolchain.get("rustc_commit"),
        "cargo": toolchain.get("cargo"),
        "llvm": toolchain.get("llvm"),
        "cc": toolchain.get("cc"),
        "ar": toolchain.get("ar"),
        "ld": toolchain.get("ld"),
        "target_triple": toolchain.get("target_triple"),
        "profile": toolchain.get("profile"),
        "source": "evidence/etp2/reproducibility.json (measured at e9d492b0d)",
        "note": "The reproducibility figure this identity records was measured at "
                "e9d492b0d, not at this package's commit; see "
                "evidence/etp2/RECEIPT.md.",
    }


def json_stage(path: Path):
    return json_strict(path.read_bytes())


def citation_refusals(commit: str, claims: dict) -> tuple[list[dict], dict]:
    refusals: list[dict] = []
    seen: set[str] = set()
    seen_paths: set[str] = set()
    for claim in claims.get("claims", []):
        for evidence in claim.get("evidence", []):
            path = evidence.get("path")
            if not isinstance(path, str):
                continue
            key = f"{claim.get('id')}:{path}"
            ignore = reason_ignored(path)
            tracked = reason_tracked(path, commit)
            present = in_commit(commit, path) > 0
            reason = ignore or tracked
            if reason is None and present:
                continue
            if key in seen:
                continue
            seen.add(key)
            seen_paths.add(path)
            refusals.append({
                "path": path,
                "reason": reason or "absent from the named commit",
                "severity": "soft",
                "referenced_by": f"evidence/etp/claims.json #{claim.get('id')}",
                "in_package": False,
                "consequence": "The cited evidence is not placed in the package. "
                               "Its claim is not reconstructed by this package; "
                               "the verifier reports it as declared absent when the "
                               "claim set already marks present=false.",
            })

    for path, reference in NAMED_GAPS:
        ignore = reason_ignored(path)
        tracked = reason_tracked(path, commit)
        if ignore is None and tracked is None:
            continue
        if path in seen_paths:
            continue
        seen_paths.add(path)
        refusals.append({
            "path": path,
            "reason": ignore or tracked,
            "severity": "soft",
            "referenced_by": reference,
            "in_package": False,
            "consequence": "Named by ETP-0 as a reconstruction gap.  It is not in "
                           "the package and no step reads it.",
        })

    grep_files = git("grep", "-l", "court/tmp/", commit, check=False)
    grep_hits = git("grep", "-o", "court/tmp/", commit, check=False)
    tracked_court_tmp = git("ls-tree", "-r", "--name-only", commit, "--",
                            "court/tmp", check=False)
    summary = {
        "tracked_files_referencing_court_tmp": len(
            [line for line in grep_files.stdout.splitlines() if line.strip()]),
        "tracked_textual_occurrences": len(
            [line for line in grep_hits.stdout.splitlines() if line.strip()]),
        "tracked_files_under_court_tmp": len(
            [line for line in tracked_court_tmp.stdout.splitlines() if line.strip()]),
        "note": "No court/tmp/ file is packaged.  The references live in evidence "
                "records that cite experiments whose logs and binaries were never "
                "tracked; the package can re-verify only the digest-bound artefacts "
                "it carries.",
    }
    return refusals, summary


def collect_inputs(stage: Path, declared: dict[str, str]) -> list[dict]:
    inputs: list[dict] = []
    for path in sorted(p for p in stage.rglob("*") if p.is_file()):
        relative = path.relative_to(stage).as_posix()
        if relative == "MANIFEST.json":
            continue
        inputs.append({
            "path": relative,
            "role": role_for(relative, declared),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    return inputs


def compare_frozen(frozen: dict, inputs: list[dict]) -> list[dict]:
    refusals: list[dict] = []
    expected = {entry["path"]: entry for entry in frozen.get("inputs", [])
                if isinstance(entry, dict)}
    current = {entry["path"]: entry for entry in inputs}
    for path, entry in sorted(expected.items()):
        found = current.get(path)
        if found is None:
            severity = "hard" if entry.get("role") != "tool" else "soft"
            refusals.append({
                "path": path,
                "reason": "frozen input is absent from the staged tree",
                "severity": severity,
                "referenced_by": "evidence/etp6/MANIFEST.json",
                "in_package": False,
                "consequence": "The package would differ from its frozen manifest.",
            })
        elif found["sha256"] != entry["sha256"]:
            refusals.append({
                "path": path,
                "reason": f"digest mismatch: {found['sha256']} != {entry['sha256']}",
                "severity": "hard",
                "referenced_by": "evidence/etp6/MANIFEST.json",
                "in_package": True,
                "consequence": "The input changed after the manifest was frozen; "
                               "review the drift, then --refreeze and re-run the "
                               "full verification and the clean-room replay.",
            })
    for path, entry in sorted(current.items()):
        if path not in expected:
            refusals.append({
                "path": path,
                "reason": "input is present but absent from the frozen manifest",
                "severity": "hard",
                "referenced_by": "evidence/etp6/MANIFEST.json",
                "in_package": True,
                "consequence": "The staged tree gained an input; review it, then "
                               "--refreeze.",
            })
    return refusals


def write_archive(stage: Path, out: Path, commit: str) -> tuple[Path, str]:
    out.mkdir(parents=True, exist_ok=True)
    archive_path = out / f"openssl-rs-etp6-{commit[:9]}.tar.gz"
    names = sorted(p for p in stage.rglob("*") if p.is_file())
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, compresslevel=9) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for path in names:
                    relative = path.relative_to(stage).as_posix()
                    info = tarfile.TarInfo(relative)
                    info.size = path.stat().st_size
                    info.mtime = SOURCE_DATE_EPOCH
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    mode = 0o755 if os.access(path, os.X_OK) else 0o644
                    info.mode = mode
                    with path.open("rb") as handle:
                        tar.addfile(info, handle)
    digest = sha256_file(archive_path)
    return archive_path, digest


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(ROOT / "court/tmp/etp6"),
                        help="directory for the produced archive (gitignored)")
    parser.add_argument("--commit", default="HEAD", help="source commit to package")
    parser.add_argument("--provisional", action="store_true",
                        help="when the ETP-6 tooling is not yet committed, build a "
                             "real commit object from HEAD plus the worktree "
                             "selection paths and package from that commit")
    parser.add_argument("--refreeze", action="store_true",
                        help="write evidence/etp6/MANIFEST.json from this tree")
    parser.add_argument("--keep-staging", action="store_true")
    args = parser.parse_args(argv)

    commit = git("rev-parse", f"{args.commit}^{{commit}}").stdout.strip()
    branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    dirty = git("status", "--porcelain", "--untracked-files=no").stdout.strip()
    dirty_count = len([line for line in dirty.splitlines() if line.strip()])

    hard: list[dict] = []
    soft: list[dict] = []

    declared: dict[str, str] = {path: role for path, _, role in SELECTION}

    # Expand the phase-obligation ledgers the documentation check reads.
    obligations = git("ls-tree", "-r", "--name-only", commit, "--", "forensics")
    paths = [path for path, _, _ in SELECTION]
    for line in obligations.stdout.splitlines():
        if re.fullmatch(r"forensics/phase\d+-obligations\.json", line):
            paths.append(line)
            declared.setdefault(line, "evidence")

    provisional = None
    parent_commit = commit
    tree_hash = git("rev-parse", f"{commit}^{{tree}}").stdout.strip()
    if args.provisional:
        # The provisional commit must contain the final selection, so build it
        # after the ledger expansion and before any trackedness check.
        commit, tree_hash = provisional_commit(paths)
        provisional = commit

    for path in paths:
        ignore = reason_ignored(path)
        tracked = reason_tracked(path, commit)
        if ignore or tracked:
            hard.append({
                "path": path,
                "reason": ignore or tracked,
                "severity": "hard",
                "referenced_by": "builder SELECTION (required input)",
                "in_package": False,
                "consequence": "The builder does not produce a package from a path "
                               "that cannot be reconstructed from the commit.",
            })
            continue
        if in_commit(commit, path) == 0:
            hard.append({
                "path": path,
                "reason": "absent from the named commit",
                "severity": "hard",
                "referenced_by": "builder SELECTION (required input)",
                "in_package": False,
                "consequence": "The builder does not produce a package with a "
                               "missing required input.",
            })

    claims_bytes = git("show", f"{commit}:evidence/etp/claims.json", text=False,
                       check=False)
    if claims_bytes.returncode != 0:
        print("REFUSED: evidence/etp/claims.json is absent from the commit",
              file=sys.stderr)
        return 2
    try:
        claims = json_strict(claims_bytes.stdout)
    except Exception as exc:  # noqa: BLE001 - refusal
        print(f"REFUSED: claims.json does not parse: {exc}", file=sys.stderr)
        return 2

    cited, court_summary = citation_refusals(commit, claims)
    soft.extend(cited)

    frozen = None
    if MANIFEST_PATH.is_file():
        try:
            frozen = json_strict(MANIFEST_PATH.read_bytes())
        except Exception as exc:  # noqa: BLE001 - refusal
            print(f"REFUSED: frozen MANIFEST.json does not parse: {exc}", file=sys.stderr)
            return 2

    if hard:
        print("REFUSED: the package was not produced.", file=sys.stderr)
        for entry in hard:
            print(f"  HARD  {entry['path']}: {entry['reason']}", file=sys.stderr)
        print(f"  {len(hard)} hard refusal(s); no archive written.", file=sys.stderr)
        return 2

    staging = Path(tempfile.mkdtemp(prefix="etp6-stage-"))
    try:
        stage_tree(staging, commit, paths)

        (staging / "TOOLCHAIN.json").write_text(
            json.dumps(toolchain_identity(staging), indent=1, sort_keys=True) + "\n",
            encoding="utf-8")
        shutil.copyfile(VERIFY_SCRIPT, staging / "verify.sh")
        os.chmod(staging / "verify.sh", 0o755)

        store = object_store(staging, claims)
        # A gitfile at the package root makes the unpacked tree a work tree
        # whose object store is the frozen store.  The tracked test suite uses
        # REPO_ROOT, not the explicit --repo-root the verifier passes, so the
        # Git-bound check must resolve through the package root as well.  A
        # gitfile is used instead of a symlink for portability.
        (staging / ".git").write_text("gitdir: freeze-git\n", encoding="utf-8")
        inputs = collect_inputs(staging, declared)

        if frozen is not None and not args.refreeze:
            hard.extend(compare_frozen(frozen, inputs))
            if hard:
                print("REFUSED: the staged tree does not match the frozen manifest.",
                      file=sys.stderr)
                for entry in hard:
                    print(f"  HARD  {entry['path']}: {entry['reason']}", file=sys.stderr)
                print("  no archive written; review the drift, then --refreeze.",
                      file=sys.stderr)
                return 2

        manifest = {
            "schema": "openssl-rs/etp6/package-manifest/1",
            "kind": "etp6-self-contained-reproduction-package",
            "task": "ETP-6: external reproduction readiness",
            "generated_utc": git("show", "-s", "--format=%cI", "HEAD").stdout.strip(),
            "candidate": {
                "commit": commit,
                "branch": branch,
                "provisional": provisional is not None,
                "parent_commit": parent_commit if provisional else None,
                "tree": tree_hash,
                "worktree_tracked_dirty_files": dirty_count,
                "frozen_source_commit": claims.get("source_identity", {}).get("commit"),
                "tracked_file_count_at_commit": len(
                    [line for line in git("ls-tree", "-r", "--name-only", commit)
                     .stdout.splitlines() if line.strip()]),
                "note": ("A provisional commit object is not on any branch: it was "
                         "created by git commit-tree from a temporary index of HEAD "
                         "plus the worktree selection paths, because the ETP-6 "
                         "tooling was not yet committed when the package was built. "
                         "The orchestrator's commit carries the identical tree; "
                         "re-running --refreeze binds the published commit hash."
                         if provisional else
                         "The package is built by git archive from this commit."),
            },
            "toolchain": toolchain_identity(staging),
            "selection": {
                "method": f"git archive {commit} -- <paths> (never a copy of the "
                          "working tree)",
                "paths": paths,
            },
            "object_store": store,
            "input_count": len(inputs),
            "inputs": inputs,
            "refusals": soft,
            "court_tmp_reference_audit": court_summary,
            "verification_steps": VERIFICATION_STEPS,
            "environment": {
                "required": ["python3 (3.11 tested)", "git", "POSIX tar"],
                "instrument_controls": ["cc", "ar", "objdump", "valgrind",
                                        "binsec", "perf"],
                "reproducibility_full": ["rustc/cargo 1.98.1",
                                         "the court container"],
                "network": "no step performs network I/O",
            },
        }
        MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
        if args.refreeze or frozen is None:
            MANIFEST_PATH.write_text(
                json.dumps(manifest, indent=2, sort_keys=False) + "\n",
                encoding="utf-8")
        else:
            manifest["frozen_from"] = "evidence/etp6/MANIFEST.json"
        (staging / "MANIFEST.json").write_text(
            MANIFEST_PATH.read_text(encoding="utf-8"), encoding="utf-8")

        archive_path, digest = write_archive(staging, Path(args.out), commit)
    finally:
        if not args.keep_staging:
            shutil.rmtree(staging, ignore_errors=True)

    print(f"package   {archive_path}")
    print(f"sha256    {digest}")
    print(f"candidate {commit} ({branch}); worktree tracked-dirty files {dirty_count}")
    print(f"inputs    {len(inputs)}; frozen source {manifest['candidate']['frozen_source_commit']}")
    print(f"store     {store['object_count']} objects, "
          f"{store['pack_bytes']} bytes, {store['pack_sha256']}")
    print(f"refusals  {len(soft)} soft (not placed in the package)")
    for entry in soft:
        print(f"  SOFT  {entry['path']}: {entry['reason']}")
    print("build     OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
