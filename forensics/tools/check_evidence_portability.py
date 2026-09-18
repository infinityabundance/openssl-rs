#!/usr/bin/env python3
"""openssl-rs — the derived evidence must not depend on the host's binutils.

Why this gate exists
--------------------
D33 is the worked example of how a build product became machine-dependent: the
implemented surface was derived by running `nm` over the crate's static archive,
and `nm` reads Rust's LLVM bitcode through a bfd plugin whose availability varies
by host. The *same archive* produced 39 C-identifier internal symbols in the court
and 260 on the CI runner, so the committed artefact was not a function of its
inputs at all.

`evidence_determinism.py` cannot catch a regression of that kind, because on any
single machine the generator and the committed artefact would both use whatever
`nm` the machine has and would agree. The property that actually needs checking is
**independence from those tools**, so this gate checks it behaviourally: it puts
failing stubs for the binutils programs at the front of `PATH`, re-runs every
generator, and requires the compared artefacts to be byte-identical anyway.

The gate then tests itself. A check that cannot detect the defect class it claims
to cover is not evidence, so a seeded generator that *does* call a stubbed tool is
run through the same mechanism and the gate fails unless that is reported as a
failure. The self-test runs on every invocation rather than being asserted in
prose.

Comparison reuses `evidence_determinism.artefact_differences`, so the fields that
tool declares as build products are excluded here too. That is not a weakening: the
question this gate asks is whether the *evidence* changes when the host tools
vanish, and a build-product field is by definition not evidence. Sharing the policy
is also what stops the two tools from drifting apart.

Usage
-----
    python3 forensics/tools/check_evidence_portability.py

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT  # noqa: E402
import evidence_determinism as ed  # noqa: E402

# Programs whose behaviour is a property of the machine rather than the inputs.
# `nm` and `objdump` consult the bfd LTO plugin for Rust objects; `readelf`, `ar`
# and `file` are here because the evidence chain does not need them either, and a
# gate is only as good as its scope.
STUBBED_TOOLS = ("nm", "objdump", "readelf", "ar", "file")

STUB_SOURCE = """#!/bin/sh
# Portability-gate stub: this program must not be needed to derive evidence.
echo "$(basename "$0"): stubbed out by check_evidence_portability.py" >&2
exit 1
"""

# A generator that is *supposed* to fail: it asks a stubbed tool for a fact.
SEEDED_TOOL_USER = """\
import subprocess
out = subprocess.run(["nm", "--version"], capture_output=True, text=True, check=True)
print(out.stdout.splitlines()[0])
"""

# A generator that is *supposed* to be reported: it changes an evidence field.
# The change is semantic rather than textual, because the comparison is semantic.
SEEDED_DRIFTER = """\
import json, pathlib
p = pathlib.Path("forensics/phase-state.json")
doc = json.loads(p.read_text(encoding="utf-8"))
doc["body"]["seeded_drift"] = True
p.write_text(json.dumps(doc, sort_keys=True, indent=2) + "\\n", encoding="utf-8")
"""


class StubEnvironment:
    """A `PATH` prefix in which the binutils programs are failing stubs."""

    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="openssl-rs-nobinutils-"))
        for tool in STUBBED_TOOLS:
            path = self.dir / tool
            path.write_text(STUB_SOURCE, encoding="utf-8")
            path.chmod(0o755)

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["PATH"] = f"{self.dir}{os.pathsep}{env.get('PATH', '')}"
        return env

    def close(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def generators_need_no_stubbed_tool(generators: list[str], stub: StubEnvironment):
    """Run `generators` with the stubs in `PATH`; report what drifted or failed.

    Comparison reuses `evidence_determinism.artefact_differences`, so the fields
    declared there as build products are excluded here too. That is not a
    weakening: the question this gate asks is whether the *evidence* changes when
    the host tools vanish, and a build-product field is by definition not evidence.
    """
    committed: dict[str, str] = {}
    for artefact in ed.COMPARED:
        path = REPO_ROOT / artefact
        if not path.is_file():
            raise SystemExit(f"[evidence-portability] missing artefact: {artefact}")
        committed[artefact] = path.read_text(encoding="utf-8")

    def restore() -> None:
        for artefact, text in committed.items():
            (REPO_ROOT / artefact).write_text(text, encoding="utf-8")

    for generator in generators:
        res = subprocess.run(
            [sys.executable, generator],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env=stub.env(),
            check=False,
        )
        if res.returncode != 0:
            restore()
            stub_named = next(
                (t for t in STUBBED_TOOLS if f"{t}:" in (res.stderr or "")), None)
            if stub_named is not None:
                return False, (f"{generator} needs a stubbed tool ({stub_named}); "
                               f"exit {res.returncode}")
            # A non-stub failure -- a prose check that now disagrees with the evidence, for
            # instance. Report it as itself rather than blaming a binutils stub.
            first = next(iter((res.stdout or res.stderr or "").strip().splitlines()),
                         "(no output)")
            return False, (f"{generator} failed with exit {res.returncode} under the stubs: "
                           f"{first}")

    fired: set[str] = set()
    drifted: list[str] = []
    for artefact in ed.COMPARED:
        now = (REPO_ROOT / artefact).read_text(encoding="utf-8")
        drifted += ed.artefact_differences(artefact, committed[artefact], now, fired)
    restore()
    if drifted:
        return False, "derived evidence changed when the stubs were in PATH: " \
                      + "; ".join(drifted)
    return True, ""


def main() -> int:
    if shutil.which("nm") is None:
        print("[evidence-portability] warning: no `nm` on PATH; the stubs still "
              "apply, but the baseline environment differs")

    stub = StubEnvironment()
    try:
        # The prose checks are not generators, but they read the same generated evidence
        # and must be as independent of the host's binutils as the generators are, so they
        # run through the same mechanism with the stubs in PATH.
        ok, detail = generators_need_no_stubbed_tool(ed.GENERATORS + ed.CHECKS, stub)
        if not ok:
            print(f"[evidence-portability] FAIL: {detail}")
            print("  The generators must derive facts from committed inputs and "
                  "in-repository readers (docs/DECISIONS.md D33).")
            return 1

        # Sensitivity controls: the same mechanism must report both ways this gate
        # can fail -- a generator that needs a stubbed tool, and a generator that
        # changes the evidence. A check that cannot detect its own defect classes
        # is not evidence.
        caught_tool = run_seeded("seeded_tool_user.py", SEEDED_TOOL_USER, stub)
        if caught_tool:
            print("[evidence-portability] FAIL: the gate did not detect a "
                  "generator that calls `nm`; its verdict means nothing")
            return 1
        caught_drift = run_seeded("seeded_drifter.py", SEEDED_DRIFTER, stub)
        if caught_drift:
            print("[evidence-portability] FAIL: the gate did not detect a "
                  "generator that changed an evidence field; its verdict means "
                  "nothing")
            return 1
    finally:
        stub.close()

    print(f"[evidence-portability] ok: {len(ed.COMPARED)} artefact(s) reproduce "
          f"with {', '.join(STUBBED_TOOLS)} unavailable")
    print("[evidence-portability] sensitivity controls: a generator that calls `nm`, "
          "and one that edits the evidence, are both detected")
    return 0


def run_seeded(name: str, source: str, stub: StubEnvironment) -> bool:
    """True when the gate *fails* to report the seeded generator as a failure."""
    seeded = Path(stub.dir) / name
    seeded.write_text(source, encoding="utf-8")
    caught, _ = generators_need_no_stubbed_tool([str(seeded)], stub)
    return caught


if __name__ == "__main__":
    raise SystemExit(main())
