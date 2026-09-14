#!/usr/bin/env python3
"""openssl-rs — is the committed evidence what the generators actually produce?

Why this is not a plain `git diff`
---------------------------------
Most derived artefacts are a pure function of committed inputs and must be
byte-identical when regenerated. A few *fields* are not, because they record the
**build product** — the compiler's output — rather than a committed input:

  * `inputs[name=crate-archive|extra-object].sha256` in
    `forensics/atlas/implemented-surface.json`. A Rust static archive is not
    guaranteed byte-reproducible across build environments.
  * `internal_symbols.compiler_emitted_count` in the same artefact. Which global
    symbols a toolchain emits is a property of that toolchain: most of the
    archive's symbol population is LLVM-internalised anonymous data named
    `anon.<hash>.<n>.llvm.<hash>`, and those hashes change from build to build.
    The *names* are not recorded at all for this reason; the stable C-identifier
    subset is (`internal_symbols.c_style`) and **is** compared exactly.
  * `body_hash` is computed over the evidence subset of `body`, so the build
    product cannot propagate into it, and the obligation ledgers bind that
    digest rather than the artefact's file digest.

So this tool compares the committed artefacts against freshly generated ones
after **normalising exactly those declared fields**, and it reports which fields
it normalised and why. Everything else — every count, every symbol name, every
phase state, every obligation — is compared exactly.

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
    "forensics/tools/ownership_audit.py",
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
    "forensics/atlas/ownership-audit.json",
    "forensics/phase3-obligations.json",
    "forensics/phase4-obligations.json",
    "forensics/phase-state.json",
    "forensics/phase-state.md",
    "forensics/STATUS.md",
]

# ---------------------------------------------------------------------------
# The declared build-product surface. Nothing outside this set is normalised.
# ---------------------------------------------------------------------------

NORMALISED_DIGEST = "<build-product-digest-normalised>"
NORMALISED_COUNT = "<build-product-count-normalised>"

# `inputs[]` entries whose `sha256` is a build product, by entry name.
BUILD_PRODUCT_INPUT_NAMES = frozenset({"crate-archive", "extra-object"})

# A compared artefact may itself be an input of another compared artefact --
# `ownership-audit.json` records the hash of `implemented-surface.json`, which it
# reads. That recorded hash cannot be compared exactly on any machine whose
# toolchain produces a different crate archive, because the *artefact* being
# hashed contains the declared build-product fields. Measured: the CI runner's
# `ownership-audit.json` input hash for `implemented-surface.json` differed while
# `implemented-surface.json` itself compared equal modulo normalisation.
#
# The binding is redundant rather than lost: the inner artefact is compared
# directly, so a substantive change to it fails on its own account before the
# outer artefact's input hash is even reached. What is blanked is a hash that
# could only ever match modulo a normalisation the inner artefact already
# declares.
COMPARED_INPUT_PATHS = frozenset(COMPARED)

# `body.internal_symbols.<field>` values that are build products, by field name.
BUILD_PRODUCT_SYMBOL_FIELDS = ("compiler_emitted_count",)

# How many differences to print before truncating. Enough to diagnose, bounded
# so a wholesale drift does not produce an unreadable wall of text.
MAX_REPORTED_DIFFERENCES = 12


def normalise(doc: object, fired: set[str]) -> object:
    """Blank the declared build-product fields, recursively.

    Returns a copy, so the caller's document is untouched. A JSON string is
    returned unchanged (used for the Markdown artefacts). `fired` accumulates the
    names of the normalisations that actually applied, so the exception is
    reported rather than silent.
    """
    if isinstance(doc, str):
        return doc
    if isinstance(doc, list):
        return [normalise(x, fired) for x in doc]
    if not isinstance(doc, dict):
        return doc
    out: dict = {}
    for k, v in doc.items():
        if k == "inputs" and isinstance(v, list):
            new_inputs = []
            for entry in v:
                if isinstance(entry, dict) and entry.get("name") in BUILD_PRODUCT_INPUT_NAMES:
                    fired.add(f"inputs[name={entry.get('name')}].sha256")
                    entry = {**entry, "sha256": NORMALISED_DIGEST}
                elif isinstance(entry, dict) and entry.get("path") in COMPARED_INPUT_PATHS:
                    fired.add(f"inputs[path={entry.get('path')}].sha256")
                    entry = {**entry, "sha256": NORMALISED_DIGEST}
                new_inputs.append(normalise(entry, fired))
            out[k] = new_inputs
        elif k == "internal_symbols" and isinstance(v, dict):
            sub = dict(v)
            for field in BUILD_PRODUCT_SYMBOL_FIELDS:
                if field in sub:
                    fired.add(f"internal_symbols.{field}")
                    sub[field] = NORMALISED_COUNT
            out[k] = normalise(sub, fired)
        else:
            out[k] = normalise(v, fired)
    return out


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def differences(a: object, b: object, path: str = "",
                found: list[str] | None = None) -> list[str]:
    """Every structural difference, as readable `path: detail` strings.

    Reporting *all* of them, not just the first, is deliberate: a gate that names
    only the first divergence costs its reader a regeneration cycle per hidden
    one.
    """
    if found is None:
        found = []
    if len(found) >= MAX_REPORTED_DIFFERENCES:
        return found
    if type(a) is not type(b):
        found.append(f"{path or '<root>'}: {type(a).__name__} vs {type(b).__name__}")
        return found
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                found.append(f"{path}.{k}: only in regenerated")
            elif k not in b:
                found.append(f"{path}.{k}: only in committed")
            else:
                differences(a[k], b[k], f"{path}.{k}", found)
            if len(found) >= MAX_REPORTED_DIFFERENCES:
                break
        return found
    if isinstance(a, list):
        if len(a) != len(b):
            found.append(f"{path}: {len(a)} entries vs {len(b)}")
            only_a = [x for x in a if x not in b][:3]
            only_b = [x for x in b if x not in a][:3]
            if only_a:
                found.append(f"{path}: only in committed, e.g. {only_a}")
            if only_b:
                found.append(f"{path}: only in regenerated, e.g. {only_b}")
            return found
        for i, (x, y) in enumerate(zip(a, b)):
            differences(x, y, f"{path}[{i}]", found)
            if len(found) >= MAX_REPORTED_DIFFERENCES:
                break
        return found
    if a != b:
        ra, rb = repr(a), repr(b)
        if len(ra) > 80:
            ra = ra[:77] + "..."
        if len(rb) > 80:
            rb = rb[:77] + "..."
        found.append(f"{path}: committed {ra} vs regenerated {rb}")
    return found


def artefact_differences(relpath: str, committed_text: str, now_text: str,
                         fired: set[str]) -> list[str]:
    """Differences between a committed and a regenerated artefact, normalised.

    Shared with `check_evidence_portability.py` so that the normalisation policy is
    applied *symmetrically*: a field declared as a build product is not evidence in
    either tool, and every field that **is** evidence must be identical in both. A
    second, drifting comparison policy would be a place for a claim to hide.
    """
    if not relpath.endswith(".json"):
        if committed_text == now_text:
            return []
        return [f"{relpath}: content differs (first line: "
                f"{now_text.splitlines()[:1]})"]
    a = normalise(json.loads(committed_text), fired)
    b = normalise(json.loads(now_text), fired)
    return [f"{relpath}: {d}" for d in differences(a, b)]


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
    fired: set[str] = set()
    for relpath in COMPARED:
        now = (REPO_ROOT / relpath).read_text(encoding="utf-8")
        problems += artefact_differences(relpath, committed[relpath], now, fired)

        if not args.keep:
            (REPO_ROOT / relpath).write_text(committed[relpath], encoding="utf-8")

    if fired:
        print("[evidence-determinism] normalised declared build-product fields: "
              + ", ".join(sorted(fired)))
        print("  a Rust static archive is not byte-reproducible across build "
              "environments, and the archive's compiler-emitted symbol population "
              "is a property of the toolchain;")
        print("  every other field is compared exactly "
              "(docs/DECISIONS.md D30, D33).")

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
