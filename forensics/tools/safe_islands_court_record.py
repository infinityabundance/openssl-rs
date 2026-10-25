#!/usr/bin/env python3
"""openssl-rs — court-only recorder for the safe-islands compiler transcript.

`check_safe_islands.py` refuses to certify an enforcement claim from a lexical
check. The authoritative answer is the compiler's, so this tool *records* it: a
disposable copy of the tree is built uncapped with `cargo check --lib` and
`cargo test --lib --no-run`, then a deliberate unsafe canary is inserted into
each registered island and the build is repeated. The resulting diagnostics —
including the `#[forbid(unsafe_code)]` coordinate the compiler blames — are
written as `s69-safe-island-compiler-evidence.json`, which the gate then binds
to the exact source hashes and toolchain before it will certify.

This tool runs cargo, which is why it is separate from the gate. It must only
ever run inside the court container (it refuses to run unless
`OPENSSL_RS_COURT_RECORD=1` is set), and it only ever touches a disposable copy:
the source tree is never modified. `--copy-to` builds that copy from an explicit
allow-list rather than the whole repository (which contains multi-gigabyte
authority trees, `target/` and prior court scratch directories).

Usage (in the court)
--------------------
    OPENSSL_RS_COURT_RECORD=1 CARGO_BUILD_JOBS=4 \
      python3 forensics/tools/safe_islands_court_record.py \
        --repo /work --copy-to /work/court/s69/repo \
        --target-dir /work/court/target/s69 \
        --out forensics/memory-safety/campaign/safe-c33/atlas-refresh/s69-safe-island-compiler-evidence.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_safe_islands as court  # noqa: E402

EVIDENCE_SCHEMA = "openssl-rs/safe-islands-compiler-evidence/v1"
CAP_ENV_KEYS = court.CAP_ENV_KEYS

# Files outside `src/` that the crate compiles or includes. The copy needs them
# and nothing else: the authority source trees are 1.8 GB and are only needed by
# the strong-tier generator, which falls back to the committed artefact.
COPY_TREES = ("src", "courts", "docs", "forensics/tools", "forensics/multitrack",
              "forensics/memory-safety/campaign/safe-c33/atlas-refresh")
COPY_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "build.rs",
              "forensics/authorities/AUTHORITIES.json",
              "forensics/atlas/BUILD_RECORDS.json",
              "forensics/atlas/cipher-tables.json",
              "forensics/atlas/digest-tables.json",
              "forensics/atlas/ctype-table.json")
INCLUDE_GLOBS = (
    "forensics/authorities/src/openssl-3.6.4/test/slh_dsa.inc",
    "forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/*.txt",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def rel(repo: Path, path: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def prepare_copy(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    for name in COPY_TREES:
        source = src / name
        if source.is_dir():
            shutil.copytree(source, dst / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in COPY_FILES:
        source = src / name
        if source.is_file():
            (dst / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dst / name)
    for pattern in INCLUDE_GLOBS:
        for source in src.glob(pattern):
            target = dst / source.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    print(f"[record] disposable copy: {src} -> {dst}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Generators: byte check, else a fresh render for token comparison
# ---------------------------------------------------------------------------

def record_generators(repo: Path, registry: dict) -> dict:
    recorded: dict = {}
    for target in registry["targets"]:
        if not target.get("generated"):
            continue
        module = target["module"]
        gen = target["generator"]
        gen_path = repo / gen["path"]
        source = repo / target["source_path"]
        committed = source.read_bytes()

        check = subprocess.run([sys.executable, str(gen_path), "--check"],
                               cwd=repo, capture_output=True, text=True,
                               timeout=900)
        byte_identical = check.returncode == 0
        rendered = committed
        if not byte_identical:
            snapshots = {source: committed}
            for extra in ("forensics/atlas/cipher-tables.json",
                          "forensics/atlas/digest-tables.json",
                          "forensics/atlas/ctype-table.json"):
                p = repo / extra
                if p.is_file():
                    snapshots[p] = p.read_bytes()
            wrote = subprocess.run([sys.executable, str(gen_path)], cwd=repo,
                                   capture_output=True, text=True, timeout=900)
            if wrote.returncode != 0:
                raise SystemExit(
                    f"[record] {gen['path']} could not render: "
                    f"{wrote.stderr.strip() or wrote.stdout.strip()}")
            rendered = source.read_bytes()
            for path, data in snapshots.items():
                path.write_bytes(data)
            if sha256_file(source) != sha256_bytes(committed):
                raise SystemExit("[record] generator restore failed; copy is dirty")

        committed_tokens = court.canonical_token_digest(
            court.rust_tokens(committed.decode("utf-8")))
        rendered_tokens = court.canonical_token_digest(
            court.rust_tokens(rendered.decode("utf-8")))
        recorded[module] = {
            "generator": gen["path"],
            "generator_sha256": sha256_file(gen_path),
            "argv_check": [sys.executable, gen["path"], "--check"],
            "check_exit_code": check.returncode,
            "check_output": (check.stdout + check.stderr).strip()[:600],
            "byte_identical": byte_identical,
            "token_identical": committed_tokens == rendered_tokens,
            "committed_sha256": sha256_bytes(committed),
            "committed_token_sha256": committed_tokens,
            "rendered_sha256": sha256_bytes(rendered),
            "rendered_token_sha256": rendered_tokens,
            "normalization": "whitespace, comments and rustfmt trailing commas",
        }
        print(f"[record] generator {module}: byte={byte_identical} "
              f"token={committed_tokens == rendered_tokens}", file=sys.stderr)
    return recorded


# ---------------------------------------------------------------------------
# Builds and diagnostics
# ---------------------------------------------------------------------------

def _lint_source_from(message: dict, source_path: str, repo: Path) -> dict | None:
    for child in message.get("children") or []:
        text = child.get("message") or ""
        if "lint level is defined here" in text or "level set at" in text:
            for span in child.get("spans") or []:
                path = span.get("file_name")
                if path:
                    return _lint_source(repo, path, span.get("line_start"),
                                        span.get("column_start"))
    rendered = message.get("rendered") or ""
    # Rustc points at the primary span with `-->` and at a secondary note span
    # with `:::`. E0453 (allow overruled by forbid) uses the `:::` form.
    for match in re.finditer(r"(?:-->|:::)\s+([^:\s]+):(\d+):(\d+)", rendered):
        path, line, column = match.group(1), int(match.group(2)), int(match.group(3))
        if path != source_path:
            return _lint_source(repo, path, line, column)
    return None


def _lint_source(repo: Path, path: str, line: int, column: int) -> dict:
    text = None
    candidate = repo / path
    if candidate.is_file() and line:
        lines = candidate.read_text(encoding="utf-8").splitlines()
        if 0 < line <= len(lines):
            text = lines[line - 1].strip()
    return {"file": path, "line": line, "column": column, "text": text}


def extract_probe(message: dict, target: dict, repo: Path) -> dict | None:
    code = (message.get("code") or {}).get("code")
    primary = next((s for s in message.get("spans") or [] if s.get("is_primary")),
                   None)
    if primary is None or primary.get("file_name") != target["source_path"]:
        return None
    lint = _lint_source_from(message, target["source_path"], repo)
    return {
        "target": target["module"],
        "observed": "REJECTED",
        "diagnostic": {
            "code": code,
            "level": message.get("level"),
            "message": message.get("message"),
            "file": primary.get("file_name"),
            "line": primary.get("line_start"),
            "column": primary.get("column_start"),
            "rendered": (message.get("rendered") or "").strip()[:1200],
            "lint_source": lint,
        },
    }


def run_build(build_id: str, kind: str, profile: str, argv: list[str],
              repo: Path, env: dict, crate: dict, registry: dict,
              targets: list[dict], timeout: int = 3600) -> dict:
    proc = subprocess.run(argv, cwd=repo, env=env, capture_output=True,
                          text=True, timeout=timeout)
    messages: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("reason") == "compiler-message":
            messages.append(obj["message"])
    errors = [m for m in messages if m.get("level") == "error"]
    warnings = [m for m in messages if m.get("level") == "warning"]

    probes: list[dict] = []
    unmatched: list[str] = []
    for message in errors:
        probe = None
        for target in targets:
            probe = extract_probe(message, target, repo)
            if probe is not None:
                break
        if probe is not None:
            probes.append(probe)

    expected_targets = [t for t in targets
                        if kind == "canary" or t.get("_probe_kind") == kind]
    if kind in ("canary", "override"):
        names = {p["target"] for p in probes}
        for target in expected_targets:
            if target["module"] not in names:
                unmatched.append(target["module"])

    if kind == "canary":
        result = "REJECTED_AS_EXPECTED" if not unmatched and proc.returncode != 0 \
            else "UNEXPECTED"
    elif kind == "override":
        result = "REJECTED_AS_EXPECTED" if not unmatched and proc.returncode != 0 \
            else "UNEXPECTED"
    else:
        result = "PASS" if proc.returncode == 0 and not errors else "FAIL"

    record = {
        "id": build_id,
        "kind": kind,
        "profile": profile,
        "argv": argv,
        "command": " ".join(argv[1:]),
        "env": {key: env.get(key) for key in CAP_ENV_KEYS},
        "lint_cap": {"capped": False, "reasons": []},
        "crate": crate,
        "exit_code": proc.returncode,
        "result": result,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "probes": probes,
        "unmatched_targets": unmatched,
        "stderr_tail": "\n".join(proc.stderr.strip().splitlines()[-6:]),
    }
    print(f"[record] {build_id} [{profile}]: exit={proc.returncode} "
          f"errors={len(errors)} warnings={len(warnings)} "
          f"probes={len(probes)} -> {result}", file=sys.stderr)
    return record


CANARY_DEV = (
    "\n\n// S2 court canary — inserted only in this disposable copy.\n"
    "#[allow(dead_code)]\n"
    "fn s69_island_canary() {\n"
    "    unsafe {}\n"
    "}\n"
)
CANARY_TEST = (
    "\n\n// S2 court canary — inserted only in this disposable copy.\n"
    "#[cfg(test)]\n"
    "mod s69_island_canary_tests {\n"
    "    #[test]\n"
    "    fn s69_canary() {\n"
    "        unsafe {}\n"
    "    }\n"
    "}\n"
)
CANARY_OVERRIDE = (
    "\n\n// S2 court canary — an allow() that must not override forbid.\n"
    "#[allow(unsafe_code)]\n"
    "fn s69_allow_override_canary() {}\n"
)
CANARY_OUTSIDE = (
    "\n\n// S2 court canary — outside every island; must compile.\n"
    "#[allow(dead_code)]\n"
    "fn s69_outside_island_canary() {\n"
    "    unsafe {}\n"
    "}\n"
)


def with_insertions(repo: Path, insertions: dict[Path, str]) -> None:
    for path, text in insertions.items():
        original = path.read_bytes()
        path.write_bytes(original + text.encode("utf-8"))


def restore(repo: Path, originals: dict[Path, bytes]) -> None:
    for path, data in originals.items():
        path.write_bytes(data)


def main(argv: list[str]) -> int:
    if os.environ.get("OPENSSL_RS_COURT_RECORD") != "1":
        print("refusing to run: this recorder invokes cargo and must only run in "
              "the court (set OPENSSL_RS_COURT_RECORD=1). The gate, "
              "check_safe_islands.py, never runs cargo.", file=sys.stderr)
        return 2

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default="/work", help="source checkout (read only)")
    ap.add_argument("--copy-to", required=True,
                    help="disposable copy to build in (recreated)")
    ap.add_argument("--registry", default=court.REGISTRY_DEFAULT)
    ap.add_argument("--out", required=True)
    ap.add_argument("--target-dir", default=None)
    ap.add_argument("--jobs", default="4")
    ap.add_argument("--venue", default="openssl-rs-court (docker/openssl-rs-court.sh exec)")
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args(argv)

    source = Path(args.repo).resolve()
    copy_root = Path(args.copy_to).resolve()
    prepare_copy(source, copy_root)

    registry = court.read_json(copy_root / args.registry)
    targets = registry["targets"]
    crate_root = copy_root / registry["crate_root"]

    files = [crate_root, copy_root / "Cargo.toml", copy_root / "Cargo.lock",
             copy_root / "build.rs", copy_root / "rust-toolchain.toml"]
    for target in targets:
        files.append(copy_root / target["declaration_file"])
        files.append(copy_root / target["source_path"])
    hashes = {rel(copy_root, p): sha256_file(p) for p in
              sorted(set(files), key=lambda p: rel(copy_root, p))
              if p.is_file()}

    lib_path, package_name, _ = court.parse_lib_path(copy_root / "Cargo.toml")
    version = None
    for raw in (copy_root / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        m = re.match(r'version\s*=\s*"([^"]+)"', raw.strip())
        if m and version is None:
            version = m.group(1)

    rustc_v = subprocess.run(["rustc", "-V"], capture_output=True, text=True).stdout.strip()
    cargo_v = subprocess.run(["cargo", "-V"], capture_output=True, text=True).stdout.strip()

    env = os.environ.copy()
    env["CARGO_TERM_COLOR"] = "never"
    env["CARGO_BUILD_JOBS"] = str(args.jobs)
    if args.target_dir:
        env["CARGO_TARGET_DIR"] = args.target_dir
    env.setdefault("TMPDIR", str(copy_root / "court" / "tmp"))
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)

    try:
        head = subprocess.run(["git", "--no-pager", "rev-parse", "HEAD"],
                              cwd=source, capture_output=True,
                              text=True).stdout.strip()
    except OSError:
        head = ""

    # 1. Generator state, before any canary touches an island.
    generators = record_generators(copy_root, registry)

    # 2. Baseline builds: the compiler must accept the pristine islands.
    crate = {"name": package_name, "version": version, "lib_path": lib_path}
    builds: list[dict] = []
    builds.append(run_build(
        "baseline-lib", "baseline", "dev-lib",
        ["cargo", "check", "--lib", "--message-format=json"],
        copy_root, env, crate, registry, targets, args.timeout))
    builds.append(run_build(
        "baseline-test", "baseline", "test-lib",
        ["cargo", "test", "--lib", "--no-run", "--message-format=json"],
        copy_root, env, crate, registry, targets, args.timeout))

    # 3. Canary builds: each island must be rejected by the compiler.
    island_paths = {t["module"]: copy_root / t["source_path"] for t in targets}
    dev_originals = {p: p.read_bytes() for p in island_paths.values()}
    with_insertions(copy_root, {p: CANARY_DEV for p in dev_originals})
    builds.append(run_build(
        "canary-lib", "canary", "dev-lib",
        ["cargo", "check", "--lib", "--message-format=json"],
        copy_root, env, crate, registry, targets, args.timeout))
    restore(copy_root, dev_originals)

    test_originals = {p: p.read_bytes() for p in island_paths.values()}
    with_insertions(copy_root, {p: CANARY_TEST for p in test_originals})
    builds.append(run_build(
        "canary-test", "canary", "test-lib",
        ["cargo", "test", "--lib", "--no-run", "--message-format=json"],
        copy_root, env, crate, registry, targets, args.timeout))
    restore(copy_root, test_originals)

    # 4. An `allow(unsafe_code)` must not override the forbid (E0453).
    override_target = dict(next(t for t in targets
                                if t["module"] == "crate::status"))
    override_target["_probe_kind"] = "override"
    override_paths = {copy_root / override_target["source_path"]: CANARY_OVERRIDE}
    originals = {p: p.read_bytes() for p in override_paths}
    with_insertions(copy_root, override_paths)
    builds.append(run_build(
        "override-lib", "override", "dev-lib",
        ["cargo", "check", "--lib", "--message-format=json"],
        copy_root, env, crate, registry, [override_target], args.timeout))
    restore(copy_root, originals)

    # 5. Scope proof: unsafe outside the islands must still compile.
    scope_path = copy_root / "src" / "runtime" / "mod.rs"
    originals = {scope_path: scope_path.read_bytes()}
    with_insertions(copy_root, {scope_path: CANARY_OUTSIDE})
    builds.append(run_build(
        "scope-proof", "scope", "dev-lib",
        ["cargo", "check", "--lib", "--message-format=json"],
        copy_root, env, crate, registry, targets, args.timeout))
    restore(copy_root, originals)

    # The copy must be pristine again before the hashes are taken as identity.
    after = {rel(copy_root, copy_root / t["source_path"]): sha256_file(
        copy_root / t["source_path"]) for t in targets}
    dirty = [k for k, v in after.items() if hashes.get(k) != v]
    if dirty:
        raise SystemExit(f"[record] copy not restored after canaries: {dirty}")

    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "kind": "compiler-enforced-safe-islands-evidence",
        "source_head": head,
        "recorded_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "venue": args.venue,
        "recorder": "forensics/tools/safe_islands_court_record.py",
        "toolchain": {
            "channel": registry["toolchain"]["channel"],
            "rustc": rustc_v,
            "cargo": cargo_v,
            "edition": registry["toolchain"]["edition"],
            "pin_sha256": sha256_file(copy_root / registry["toolchain"]["pin"]),
        },
        "crate": crate,
        "files": hashes,
        "builds": builds,
        "generators": generators,
        "notes": [
            "The canary is inserted into a disposable copy and removed before the "
            "recorded hashes are taken; the source checkout is never modified.",
            "Only the exact `cargo check --lib` and `cargo test --lib --no-run` "
            "product compilations are recorded; no --cap-lints, no RUSTFLAGS cap, "
            "no rustc wrapper.",
            "The generator render was produced in the copy (weak tier, from the "
            "committed artefact); byte equality is checked against the committed "
            "file, and token identity is the formatting-normalized comparison.",
        ],
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(f"[record] wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
