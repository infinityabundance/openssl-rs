#!/usr/bin/env python3
"""openssl-rs -- Phase 22.1 built-command normalizer.

Turns the raw execution capture (`forensics/tools/phase22_capture_build.py`) into the
repository's standard, content-addressed atlas document: one row per translation unit
with the exact compile argv the authority's build issued.

Why the input is a capture and not a `Configure` reconstruction
--------------------------------------------------------------
`docs/PHASE-22-SUBPHASES.md` section 6: 22.1 "must capture the compiler invocations the
authority build actually made. It may not reconstruct flags from `Configure`." This tool
therefore reads the wrapper log, and the body records `capture_method` = `"execution-captured"`
so a reader can never mistake it for a synthesised compilation database. The per-object
perlasm defines (the `-DAES_ASM ...` block on the x86_64 assembly units) appear nowhere in
the `Configure` profile; they are only in the log precisely because the build emitted them.

The authority stays a GCC build
-------------------------------
The production authority's own compiler is `gcc` (its pinned `configdata.pm` records
`"CC" => "gcc"`), and the body records `producer` = that value. The `analysis_instrument` is
`clang`, and the body says plainly that Clang is a *shadow* analysis instrument -- the
later 22.3/22.4 planes compile these captured invocations with Clang to read them, but that
never redefines the authority as a Clang build (section 6).

Determinism
-----------
The document is a pure function of the raw log and the pinned `configdata.pm`. No timestamp,
PID or host-varying path is written; the same log always normalises to byte-identical JSON,
which is what lets `forensics/tools/phase22_courts.py` mutate the log in memory and check
that this normalizer's output moves in the expected way.

Output
------
    forensics/atlas/phase22/compile-commands.json

Why the raw log is tracked, unlike the rest of the authority's capture
--------------------------------------------------------------------
`forensics/authorities/captures/` is gitignored on purpose: the authority's build logs are
reproducible from its source, and `BUILD_RECORDS.json` is the tracked record of that build. This
capture is different in one respect that decides where it lives. The court above re-derives the
committed artefact **from the raw log and requires the two to be equal**, so the log is not a
reproducible intermediate -- it is the second half of the comparison. If it were ignored, a fresh
checkout could only assert that some JSON existed. It therefore lives under the atlas, tracked,
and its sha256 is one of this document's own inputs (`forensics/tools/phase22_courts.py`'s
`RT-PHASE22-BUILD-CAPTURE` re-derivation is the freshness gate for this artefact; it runs in every
pipeline because phase 22 is active and has a runner).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    write_json,
)

GENERATOR = "forensics/tools/phase22_build_commands.py"
RAW_REL = "forensics/atlas/phase22/raw/compile-commands.jsonl"
OUT_REL = "forensics/atlas/phase22/compile-commands.json"
BUILD_DIR_REL = "forensics/authorities/build/openssl-3.6.4-production"

# The build-time assembler probes (`gcc -Wa,-v -c -o /dev/null -x assembler /dev/null`) are
# `make` feature tests, not translation units. They carry `-c` and an `-o` bound for /dev/null,
# which is how they are told apart from a real compile.
NULL_PATH = "/dev/null"

_SOURCE_SUFFIXES = (".c", ".s", ".S", ".cc", ".cpp", ".cxx", ".m")


def load_raw(path: Path) -> list[dict]:
    """Every JSON object in the raw capture, in file order."""
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def is_translation_unit(rec: dict) -> bool:
    """Whether a `record="compile"` line built an actual translation unit."""
    source = rec.get("source")
    output = rec.get("output")
    return (
        rec.get("record") == "compile"
        and bool(source)
        and source != NULL_PATH
        and output not in (None, NULL_PATH)
    )


def extract_defines(argv: list[str]) -> list[str]:
    """The `-D` options, in command order, as they appear (prefix kept)."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-D" and i + 1 < len(argv):
            out.append("-D " + argv[i + 1])
            i += 1
        elif a.startswith("-D"):
            out.append(a)
        i += 1
    return out


def extract_includes(argv: list[str]) -> list[str]:
    """The `-I`/`-isystem` options, in command order, as they appear (prefix kept)."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-I" and i + 1 < len(argv):
            out.append("-I " + argv[i + 1])
            i += 1
        elif a.startswith("-I"):
            out.append(a)
        elif a == "-isystem" and i + 1 < len(argv):
            out.append("-isystem " + argv[i + 1])
            i += 1
        i += 1
    return out


def build_body(records: list[dict], producer: str, directory: str | None = None) -> dict:
    """The atlas body for a set of raw records.

    A pure function of its input, so the Phase 22 sensitivity court can call it on a mutated
    copy of the log and compare. `producer` is passed in rather than read here so the court
    and `main` exercise exactly the same code path.
    """
    configure = next((r for r in records if r.get("record") == "configure"), None)
    commands = [
        {
            "source": rec["source"],
            "output": rec["output"],
            "directory": rec.get("directory"),
            "defines": extract_defines(rec.get("argv", [])),
            "includes": extract_includes(rec.get("argv", [])),
            "args": list(rec.get("argv", [])),
        }
        for rec in records
        if is_translation_unit(rec)
    ]
    # A source may be compiled more than once (the shared and static archives both build it), so
    # the sort key is (source, output): deterministic, and "by source" in the reader's sense.
    commands.sort(key=lambda c: (c["source"], c["output"]))

    directs = sorted({c["directory"] for c in commands if c["directory"]})
    return {
        "capture_method": "execution-captured",
        "producer": producer,
        "analysis_instrument": "clang",
        "analysis_instrument_note": (
            "Clang is a shadow analysis instrument only. The production authority is GCC-built "
            f"(configdata.pm CC={producer!r}); the captured invocations are replayed to Clang by "
            "the later 22.3/22.4 planes to read them, which never redefines the authority as a "
            "Clang build (docs/PHASE-22-SUBPHASES.md section 6)."
        ),
        "directory": directory if directory is not None else (configure or {}).get("directory"),
        "build_directories": directs,
        "configure_argv": (configure or {}).get("argv"),
        "wrapper_version": (configure or {}).get("wrapper_version"),
        "counts": {
            "commands": len(commands),
            "distinct_sources": len({c["source"] for c in commands}),
            "with_defines": sum(1 for c in commands if c["defines"]),
        },
        "commands": commands,
    }


def read_producer(configdata: Path) -> str:
    """The authority's own compiler, from its pinned `configdata.pm` (`"CC" => "..."`)."""
    text = configdata.read_text(encoding="utf-8", errors="replace")
    m = re.search(r'^\s*"CC"\s*=>\s*"([^"]*)"', text, re.MULTILINE)
    return m.group(1) if m and m.group(1) else "unknown"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    raw = REPO_ROOT / RAW_REL
    if not raw.is_file():
        raise SystemExit(
            f"phase22-build-commands: raw capture missing: {raw}; run "
            "forensics/tools/phase22_capture_build.py first"
        )

    records = load_raw(raw)
    configdata = REPO_ROOT / BUILD_DIR_REL / "configdata.pm"
    if not configdata.is_file():
        raise SystemExit(
            f"phase22-build-commands: {BUILD_DIR_REL}/configdata.pm is absent, so the "
            "authority's own compiler cannot be read and `producer` would be a guess; build "
            "the authority (forensics/tools/authority_build.py) first"
        )
    producer = read_producer(configdata)
    body = build_body(records, producer)

    doc = envelope(
        kind="phase22-build-commands",
        authority=auth.id,
        inputs=[InputRef(name="raw-compile-commands", path=raw)],
        body=body,
        generator=GENERATOR,
    )
    write_json(REPO_ROOT / OUT_REL, doc)

    c = body["counts"]
    print(f"[phase22-build-commands] capture_method={body['capture_method']} "
          f"producer={body['producer']!r} analysis_instrument={body['analysis_instrument']}")
    print(f"  commands={c['commands']} distinct_sources={c['distinct_sources']} "
          f"with_defines={c['with_defines']}")
    print(f"  -> {rel(REPO_ROOT / OUT_REL)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
