#!/usr/bin/env python3
"""openssl-rs — negative controls for the safe-islands enforcement court.

A gate that has never failed is not evidence. This runner takes a pristine
copy of the tree, proves the court passes on it, then performs one scope
mutation at a time and requires the court to *fail closed and name the module*.
Everything is reinstated between cases, and the final case must pass again.

The copy is built from an explicit allow-list (the same one the compiler
recorder uses) and is required to live outside the source checkout: these
controls mutate `src/`, so they must never run against the repository tree.

Cases
-----
  a. remove one `#[forbid(unsafe_code)]`        -> fail, naming that module
  b. move one declaration to a different parent -> fail closed
  c. add `#[cfg(test)]` to one attribute        -> fail closed
  d. introduce `#[path]` on one declaration     -> fail closed
  e. reinstate everything                       -> pass
  f–j. record a capped or wrapped build          -> refuse to certify
       (RUSTFLAGS cap, CARGO_ENCODED_RUSTFLAGS cap, `--cap-lints` in cargo's
        argv, RUSTC_WRAPPER, and a command that is not cargo)

Usage
-----
    python3 forensics/tools/safe_islands_negative_controls.py \
        --repo /work --copy-to /work/court/s69/negctl

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from safe_islands_court_record import prepare_copy  # noqa: E402


def run_checker(repo: Path, checker: Path) -> tuple[int, str]:
    proc = subprocess.run([sys.executable, str(checker), "--repo-root", str(repo)],
                          capture_output=True, text=True, timeout=1800)
    return proc.returncode, (proc.stdout + proc.stderr)


def apply(repo: Path, edits: list[tuple[str, str, str]],
          appends: list[tuple[str, str]] | None = None) -> dict[Path, bytes]:
    """Apply exact-text substitutions or appends, returning originals."""
    originals: dict[Path, bytes] = {}
    for relpath, old, new in edits:
        path = repo / relpath
        original = path.read_bytes()
        originals[path] = original
        text = original.decode("utf-8")
        if text.count(old) != 1:
            raise SystemExit(f"control: {relpath} has {text.count(old)} copies of "
                             f"{old!r}, expected exactly one")
        path.write_bytes(text.replace(old, new, 1).encode("utf-8"))
    for relpath, text in appends or []:
        path = repo / relpath
        original = path.read_bytes()
        originals[path] = original
        path.write_bytes(original + text.encode("utf-8"))
    return originals


def restore(originals: dict[Path, bytes]) -> None:
    for path, data in originals.items():
        path.write_bytes(data)


FORBID_STATUS = "#[forbid(unsafe_code)]\npub mod status;\n"
DECL_STATUS = "pub mod status;\n"


def mutate_evidence(repo: Path, mutation: str) -> bytes:
    """Rewrite one recorded build to look like a capped/wrapped run.

    The checker must refuse to certify rather than accept the transcript. Only
    the evidence file changes, so the integrity guards still pass and the
    refusal is attributable to the cap check alone (exit 2).
    """
    registry = json.loads((repo / "forensics/tools/safe_islands.json")
                          .read_text(encoding="utf-8"))
    path = repo / registry["evidence"]
    original = path.read_bytes()
    data = json.loads(original)
    build = next(b for b in data["builds"] if b["id"] == "baseline-lib")
    if mutation == "rustflags":
        build["env"]["RUSTFLAGS"] = "--cap-lints=warn"
    elif mutation == "encoded":
        build["env"]["CARGO_ENCODED_RUSTFLAGS"] = "--cap-lints\x1fwarn"
    elif mutation == "argv-cap":
        build["argv"] = ["cargo", "check", "--lib", "--cap-lints=warn",
                         "--message-format=json"]
    elif mutation == "wrapper-env":
        build["env"]["RUSTC_WRAPPER"] = "/usr/local/bin/sccache"
    elif mutation == "wrapper-argv":
        build["argv"] = ["sccache", "cargo", "check", "--lib",
                         "--message-format=json"]
    else:
        raise SystemExit(f"unknown evidence mutation {mutation!r}")
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return original


def cases() -> list[dict]:
    return [
        {
            "id": "a-attribute-removed",
            "why": "one island loses its attribute",
            "edits": [("src/lib.rs", FORBID_STATUS, DECL_STATUS)],
            "expect_exit": 1,
            "must_contain": ["FAIL", "crate::status", "attribute"],
        },
        {
            "id": "b-declaration-moved",
            "why": "the declaration moves to a different parent",
            "edits": [
                ("src/lib.rs", FORBID_STATUS, ""),
                ("src/digest/mod.rs", "pub mod tables;\n", "pub mod tables;\n"
                 "#[forbid(unsafe_code)]\npub mod status;\n"),
            ],
            "expect_exit": 1,
            "must_contain": ["FAIL", "crate::status", "declaration moved"],
        },
        {
            "id": "c-cfg-guard",
            "why": "the attribute becomes conditional on cfg(test)",
            "edits": [("src/lib.rs", FORBID_STATUS,
                       "#[cfg(test)]\n" + FORBID_STATUS)],
            "expect_exit": 1,
            "must_contain": ["FAIL", "crate::status", "cfg"],
        },
        {
            "id": "d-path-attribute",
            "why": "the declaration gains a #[path], moving the source",
            "edits": [("src/lib.rs", FORBID_STATUS,
                       "#[path = \"status.rs\"]\n" + FORBID_STATUS)],
            "expect_exit": 1,
            "must_contain": ["FAIL", "crate::status", "path"],
        },
        {
            "id": "f-cap-rustflags",
            "why": "the recorded build carries RUSTFLAGS=--cap-lints",
            "mutate": "rustflags",
            "expect_exit": 2,
            "must_contain": ["FAIL", "capped"],
        },
        {
            "id": "g-cap-encoded",
            "why": "the recorded build carries CARGO_ENCODED_RUSTFLAGS cap",
            "mutate": "encoded",
            "expect_exit": 2,
            "must_contain": ["FAIL", "capped"],
        },
        {
            "id": "h-cap-argv",
            "why": "the recorded cargo command passes --cap-lints",
            "mutate": "argv-cap",
            "expect_exit": 2,
            "must_contain": ["FAIL", "capped"],
        },
        {
            "id": "i-wrapper-env",
            "why": "the recorded build uses a RUSTC_WRAPPER",
            "mutate": "wrapper-env",
            "expect_exit": 2,
            "must_contain": ["FAIL", "wrapper"],
        },
        {
            "id": "j-wrapper-argv",
            "why": "the recorded command is a cargo wrapper, not cargo",
            "mutate": "wrapper-argv",
            "expect_exit": 2,
            "must_contain": ["FAIL", "cargo"],
        },
        {
            "id": "k-generated-hand-edit",
            "why": "a generated island no longer matches its generator",
            "appends": [("src/cipher_tables.rs",
                         "\npub(crate) const S69_HAND_EDIT: u32 = 0;\n")],
            "expect_exit": 1,
            "must_contain": ["FAIL", "crate::cipher_tables", "generator"],
        },
        {
            "id": "l-include-bang",
            "why": "a bare include! appears inside an island",
            "appends": [("src/status.rs", '\ninclude!("s69_extra.rs");\n')],
            "expect_exit": 1,
            "must_contain": ["FAIL", "crate::status", "include"],
        },
    ]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default="/work", help="source checkout (read only)")
    ap.add_argument("--copy-to", required=True,
                    help="disposable copy (must be outside the source checkout)")
    ap.add_argument("--checker",
                    default="forensics/tools/check_safe_islands.py",
                    help="checker path inside the copy")
    args = ap.parse_args(argv)

    source = Path(args.repo).resolve()
    copy_root = Path(args.copy_to).resolve()
    try:
        copy_root.relative_to(source)
        raise SystemExit("control: the disposable copy is inside the source tree; "
                         "these controls mutate src/ and must never touch it")
    except ValueError:
        pass

    prepare_copy(source, copy_root)
    checker = copy_root / args.checker
    if not checker.is_file():
        raise SystemExit(f"control: checker {checker} is missing from the copy")

    failures = 0
    rc, output = run_checker(copy_root, checker)
    baseline_ok = rc == 0 and "COMPILER_FORBID_CONFIRMED: true" in output
    print(f"[baseline] pristine copy -> {'PASS' if baseline_ok else 'FAIL'} (exit {rc})")
    if not baseline_ok:
        print(output[-4000:])
        failures += 1

    for case in cases():
        if "mutate" in case:
            registry = json.loads((copy_root / "forensics/tools/safe_islands.json")
                                  .read_text(encoding="utf-8"))
            evidence_path = copy_root / registry["evidence"]
            original_evidence = evidence_path.read_bytes()
            mutate_evidence(copy_root, case["mutate"])
            try:
                rc, output = run_checker(copy_root, checker)
            finally:
                evidence_path.write_bytes(original_evidence)
        else:
            originals = apply(copy_root, case.get("edits", []), case.get("appends"))
            try:
                rc, output = run_checker(copy_root, checker)
            finally:
                restore(originals)
        missing = [needle for needle in case["must_contain"] if needle not in output]
        ok = (rc == case["expect_exit"] and not missing)
        named = [line.strip() for line in output.splitlines()
                 if line.strip().startswith("FAIL")]
        print(f"[{case['id']}] {case['why']} -> "
              f"exit {rc}, expected {case['expect_exit']}: "
              f"{'FAIL-CLOSED AS REQUIRED' if ok else 'NOT AS EXPECTED'}")
        for line in named[:3]:
            print(f"    {line}")
        if not ok:
            failures += 1
            if missing:
                print(f"    missing from output: {missing}")
            print(output[-3000:])

    rc, output = run_checker(copy_root, checker)
    reinstated_ok = rc == 0 and "COMPILER_FORBID_CONFIRMED: true" in output
    print(f"[e-reinstated] all files restored -> "
          f"{'PASS' if reinstated_ok else 'FAIL'} (exit {rc})")
    if not reinstated_ok:
        failures += 1
        print(output[-4000:])

    print(f"[controls] {len(cases()) + 2 - failures} of "
          f"{len(cases()) + 2} observations as expected")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
