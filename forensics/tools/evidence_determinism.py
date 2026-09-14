#!/usr/bin/env python3
"""openssl-rs — is the committed evidence what the generators actually produce?

Why this is not a plain `git diff`
---------------------------------
Most derived artefacts are a pure function of committed inputs and must be
byte-identical when regenerated. One field is not: the **crate archive digest**
recorded in `forensics/atlas/implemented-surface.json`'s `inputs`, and therefore
in every ledger that binds that manifest. A Rust static archive is not guaranteed
byte-reproducible across build environments, so a byte comparison would fail for a
reason that has nothing to do with staleness — and a check that cries wolf is a
check nobody trusts.

So this tool compares the committed artefacts against freshly generated ones after
**normalising exactly those archive digests**, and it reports what it normalised so
the exception is visible rather than silent. Everything else — every count, every
symbol name, every phase state, every obligation — is compared exactly.

What it catches
---------------
A committed artefact that has drifted from its generator: a ledger whose counts no
longer match the implemented surface, a `STATUS.md` that was edited by hand, a
phase state that was not re-derived after the evidence changed. Those are the ways
a claim silently becomes unverifiable.

Usage
-----
    python3 forensics/tools/evidence_determinism.py          # regenerate and check
    python3 forensics/tools/evidence_determinism.py --keep   # leave outputs written

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel  # noqa: E402

# The generators, in dependency order: each may consume the previous artefact.
# `implemented_surface.py` needs a built archive, so the build is a precondition
# and the caller runs it first.
GENERATORS = [
    "forensics/tools/implemented_surface.py",
    "forensics/tools/phase3_obligations.py",
    "forensics/tools/phase4_obligations.py",
    "forensics/tools/phase_state.py",
    "forensics/tools/render_status.py",
]

# Derived artefacts that are compared. Anything not listed is not this tool's
# business (court transcripts, staged probe binaries and the ABI shell are
# produced by the court venue, not by these generators).
COMPARED = [
    "forensics/atlas/implemented-surface.json",
    "forensics/phase3-obligations.json",
    "forensics/phase4-obligations.json",
    "forensics/phase-state.json",
    "forensics/phase-state.md",
    "forensics/STATUS.md",
]

# Input names whose digest is a build product rather than a committed input.
BUILD_PRODUCT_INPUTS = {"crate-archive", "extra-object"}


def normalise(doc: object) -> object:
    """Blank the digests of build-product inputs, recursively.

    Returns a copy, so the caller's document is untouched. A JSON string is
    returned unchanged (used for the Markdown artefacts).
    """
    if isinstance(doc, str):
        return doc
    if isinstance(doc, list):
        return [normalise(x) for x in doc]
    if not isinstance(doc, dict):
        return doc
    out: dict = {}
    for k, v in doc.items():
        if k == "inputs" and isinstance(v, list):
            new_inputs = []
            for entry in v:
                if isinstance(entry, dict) and entry.get("name") in BUILD_PRODUCT_INPUTS:
                    entry = {**entry, "sha256": "<build-product-digest-normalised>"}
                new_inputs.append(normalise(entry))
            out[k] = new_inputs
        else:
            out[k] = normalise(v)
    return out


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def first_difference(a: object, b: object, path: str = "") -> str | None:
    """A readable description of the first structural difference, or None."""
    if type(a) is not type(b):
        return f"{path or '<root>'}: {type(a).__name__} vs {type(b).__name__}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k}: only in regenerated"
            if k not in b:
                return f"{path}.{k}: only in committed"
            diff = first_difference(a[k], b[k], f"{path}.{k}")
            if diff:
                return diff
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: {len(a)} entries vs {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            diff = first_difference(x, y, f"{path}[{i}]")
            if diff:
                return diff
        return None
    if a != b:
        ra, rb = repr(a), repr(b)
        if len(ra) > 80:
            ra = ra[:77] + "..."
        if len(rb) > 80:
            rb = rb[:77] + "..."
        return f"{path}: committed {ra} vs regenerated {rb}"
    return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="leave the regenerated artefact in place (default: restore)")
    args = ap.parse_args(argv)

    # Snapshot the committed artefacts, then regenerate.
    committed: dict[str, object] = {}
    for relpath in COMPARED:
        p = REPO_ROOT / relpath
        if not p.is_file():
            raise SystemExit(f"[evidence-determinism] missing artefact: {relpath}")
        committed[relpath] = p.read_text(encoding="utf-8")

    for gen in GENERATORS:
        res = subprocess.run([sys.executable, gen], cwd=REPO_ROOT,
                             capture_output=True, text=True, check=False)
        if res.returncode != 0:
            raise SystemExit(
                f"[evidence-determinism] {gen} failed with {res.returncode}:\n"
                f"{res.stdout}\n{res.stderr}")

    problems: list[str] = []
    normalised: list[str] = []
    for relpath in COMPARED:
        now = (REPO_ROOT / relpath).read_text(encoding="utf-8")
        if relpath.endswith(".json"):
            a = normalise(json.loads(committed[relpath]))
            b = normalise(json.loads(now))
            if a != b:
                problems.append(f"{relpath}: {first_difference(a, b)}")
            if normalise(json.loads(committed[relpath])) != json.loads(committed[relpath]):
                normalised.append(relpath)
        else:
            if committed[relpath] != now:
                problems.append(f"{relpath}: content differs (first line: "
                                f"{now.splitlines()[:1]})")

        if not args.keep:
            (REPO_ROOT / relpath).write_text(committed[relpath], encoding="utf-8")

    if normalised:
        print("[evidence-determinism] normalised build-product input digests in: "
              + ", ".join(normalised))
        print("  (a Rust static archive is not byte-reproducible across build "
              "environments; every other field is compared exactly)")

    if problems:
        print(f"[evidence-determinism] FAIL: {len(problems)} stale artefact(s)")
        for p in problems:
            print(f"  STALE: {p}")
        print("  Regenerate and commit: the generators are the source of truth.")
        return 1

    print(f"[evidence-determinism] ok: {len(COMPARED)} artefact(s) reproduce "
          f"from their generators")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
