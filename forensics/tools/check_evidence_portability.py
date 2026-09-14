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

# A generator that is *supposed* to fail: it asks a stubbed tool for a fact. Used
# as the gate's own sensitivity control.
SEEDED_GENERATOR = """\
import subprocess
out = subprocess.run(["nm", "--version"], capture_output=True, text=True, check=True)
print(out.stdout.splitlines()[0])
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
    """Run `generators` with the stubs in `PATH`; report what drifted or failed."""
    committed: dict[str, bytes] = {}
    for artefact in ed.COMPARED:
        path = REPO_ROOT / artefact
        if not path.is_file():
            raise SystemExit(f"[evidence-portability] missing artefact: {artefact}")
        committed[artefact] = path.read_bytes()

    def restore() -> None:
        for artefact, blob in committed.items():
            (REPO_ROOT / artefact).write_bytes(blob)

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
                (t for t in STUBBED_TOOLS if f"{t}:" in (res.stderr or "")), "?")
            return False, (f"{generator} needs a stubbed tool ({stub_named}); "
                           f"exit {res.returncode}")

    drifted = [a for a, blob in committed.items()
               if (REPO_ROOT / a).read_bytes() != blob]
    restore()
    if drifted:
        return False, ("derived evidence changed when the stubs were in PATH: "
                       + ", ".join(drifted))
    return True, ""


def main() -> int:
    if shutil.which("nm") is None:
        print("[evidence-portability] warning: no `nm` on PATH; the stubs still "
              "apply, but the baseline environment differs")

    stub = StubEnvironment()
    try:
        ok, detail = generators_need_no_stubbed_tool(ed.GENERATORS, stub)
        if not ok:
            print(f"[evidence-portability] FAIL: {detail}")
            print("  The generators must derive facts from committed inputs and "
                  "in-repository readers (docs/DECISIONS.md D33).")
            return 1

        # Sensitivity control: the same mechanism must report a generator that
        # does depend on a stubbed tool.
        seeded = Path(stub.dir) / "seeded_generator.py"
        seeded.write_text(SEEDED_GENERATOR, encoding="utf-8")
        caught, _ = generators_need_no_stubbed_tool([str(seeded)], stub)
        if caught:
            print("[evidence-portability] FAIL: the gate did not detect a "
                  "generator that calls `nm`; its verdict means nothing")
            return 1
    finally:
        stub.close()

    print(f"[evidence-portability] ok: {len(ed.COMPARED)} artefact(s) reproduce "
          f"with {', '.join(STUBBED_TOOLS)} unavailable")
    print("[evidence-portability] sensitivity control: a generator that calls `nm` "
          "is detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
