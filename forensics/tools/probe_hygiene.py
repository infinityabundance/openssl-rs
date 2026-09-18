#!/usr/bin/env python3
"""openssl-rs — every differential probe must answer the same at every optimisation level.

Why this exists
---------------
The differential courts observe *the probe's transcript*: the probe is compiled
twice, once against the authority and once against the candidate, and the two
transcripts are compared. That method has one assumption it cannot check from the
outside — that the transcript is a property of the library under test rather than
of the probe's own compiled code.

When a probe reads memory it did not initialise, the transcript is a property of
the compiler's stack layout instead. The failure is silent and it looks exactly
like a candidate defect, which is what makes it expensive:

    `courts/phase6/rt_param_probe.c` handed a sixteen-byte buffer filled with
    0xaa to `OSSL_PARAM_construct_utf8_string(..., buf, 0)`, which measures the
    buffer with `strlen`. The terminator was whatever followed the array on the
    stack. Measured at this repository's committed source: `-O0` answers 22 for
    *both* sides, `-O1` answers 16 for both, and an earlier build of the same
    source answered 24 for the authority against 22 for the candidate — an
    out-of-bounds read reported as a candidate divergence, and diagnosed by
    hand.

A sanitizer would find that class directly, and `-fsanitize=address` cannot be
used here: ASan reserves terabytes of address space for its shadow, which the
court's own OOM protection (a hard `RLIMIT_DATA`, `docker/openssl-rs-court.sh`)
refuses, as it should. This tool needs no runtime support. It recompiles each
probe at several optimisation levels and compares the transcripts:

  * different answers at different levels -> the probe is reading memory whose
    contents the optimizer changed, i.e. uninitialised or out of bounds;
  * different answers between two runs at the *same* level -> the probe is
    nondeterministic for some other reason (an address, a clock, a hash order),
    which no court can compare either.

What it is not
--------------
It is not a proof of memory safety and it is not a substitute for the courts. A
probe can be perfectly deterministic and still measure the wrong thing. It is a
precondition: the transcript has to be a function of the library before a
difference between two libraries means anything.

Scope note
----------
Only `courts/phase<N>/*_probe.c` are subjects, which is the naming convention the
phase runners use for their differential probes. The `discover_*` archaeology
programs next to them are one-shot measurements, not courts, and are not held to
a court's determinism.

    python3 forensics/tools/probe_hygiene.py            # every probe, both sides
    python3 forensics/tools/probe_hygiene.py --list
    python3 forensics/tools/probe_hygiene.py --side authority

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import importlib
import json
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
    run,
    write_json,
)

OUT = REPO_ROOT / "artifacts" / "probe-hygiene.json"
GENERATOR = "forensics/tools/probe_hygiene.py"
COURTS_DIR = REPO_ROOT / "courts"
TOOLS_DIR = REPO_ROOT / "forensics" / "tools"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"

# The phase runners, discovered rather than listed -- for the same reason
# `discover_probes` exists. A runner is where a probe's build definitions live, and a
# definition that has to be carried by a *second* registry is the failure mode this
# project has already paid for three times (D49, D51, D94).
RUNNER_GLOB = "phase[0-9]*_courts.py"

# The phase runners compile at `-O1`. `-O0` is the control and `-O2` adds a
# second, differently-shaped frame. Diffing a level against `-O1` is what
# detects a frame-dependent read; a third level costs one more compile and
# catches reads that `-O1` happens to leave in a benign place.
LEVELS = ("-O0", "-O1", "-O2")
RUNS_PER_LEVEL = 2
RUN_TIMEOUT_S = "60"


def discover_probes() -> list[Path]:
    """Every differential probe, discovered rather than listed.

    A registry of probes is a second place a probe has to be remembered, and this
    project has already paid for that failure mode three times (D49, D51, D94).
    """
    return sorted(p for p in COURTS_DIR.glob("phase[0-9]*/*_probe.c") if p.is_file())


def discover_court_defs(src: Path, libdir: Path) -> list[str]:
    """The build definitions the probe's *own* runner compiles it with.

    Every phase runner is imported and asked; the first one that lists this probe in
    its `COURTS` and exposes an `extra_defs(name, libdir)` answers. A runner that
    exposes neither is compiled with no extra definitions, which is the common case.

    This exists because `RT-DSO` has to be told which library to load -- a `DSO`
    whose subject is a shared library has no successful load to observe otherwise --
    and that path is per side. Compiling it without the definition is a hard error
    (`#error`), which is what the hygiene control reported, and is the right way to
    fail: a probe that silently omitted its definition would compare a load failure
    against a load failure and call it agreement.
    """
    for path in sorted(TOOLS_DIR.glob(RUNNER_GLOB)):
        if path.name == Path(__file__).name:
            continue
        try:
            mod = importlib.import_module(path.stem)
        except Exception:  # a runner that needs an argument to import
            continue
        courts = getattr(mod, "COURTS", None)
        extra = getattr(mod, "extra_defs", None)
        if not courts or extra is None:
            continue
        for row in courts:
            # A runner's `COURTS` rows are `(court, probe)` and may carry a third
            # descriptive field: Phase 7's do, because `docs/DECISIONS.md` D200
            # requires the FRF declaration, the stratum's court table and the seal
            # to carry the same one-line subject. Discovery needs the first two
            # fields, so it reads them by position and tolerates the rest rather
            # than pinning every runner's table to an arity.
            name, filename = row[0], row[1]
            if filename == src.name:
                return list(extra(name, libdir))
    return []


def compile_probe(src: Path, out: Path, include: Path, libdir: Path,
                  level: str, defs: list[str] | None = None) -> tuple[bool, str]:
    res = run([
        "clang", "-std=c11", "-Wall", level, "-D_GNU_SOURCE",
        *(defs or []),
        "-I", str(include),
        "-o", str(out), str(src),
        "-L", str(libdir), "-lcrypto",
        f"-Wl,-rpath,{libdir}",
    ])
    return res.ok, res.stderr.strip()


def run_probe(binary: Path, libdir: Path) -> tuple[str, str, int | None]:
    """One execution, with the library under test bound for this invocation only.

    The binding is per invocation and never exported: Debian's `sha256sum` links
    libcrypto, so an exported binding would make the harness's own tools load the
    library under test (measured, and recorded in `forensics/frf/README.md`).
    """
    env = {
        "LD_LIBRARY_PATH": str(libdir),
        "OPENSSL_CONF": "/dev/null",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    res = run(["timeout", RUN_TIMEOUT_S, str(binary)])
    code = res.returncode
    if code == 124:
        return res.stdout, res.stderr, None
    return res.stdout, res.stderr, code


def observations(text: str) -> dict[str, str]:
    """The `key=value` observations, in first-seen order, duplicates joined.

    The courts compare on the same key rather than on line number, so a missing
    or extra line is one residual instead of a cascade.
    """
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key not in values:
            values[key] = value
        else:
            values[key] = f"{values[key]}|{value}"
    return values


def first_difference(a: dict[str, str], b: dict[str, str]) -> list[dict]:
    """The observations that differ, capped so one catastrophic probe cannot
    produce a hundred-thousand-line report."""
    out: list[dict] = []
    for key in sorted(set(a) | set(b)):
        if a.get(key) != b.get(key):
            out.append({"observation": key, "a": a.get(key), "b": b.get(key)})
            if len(out) >= 20:
                break
    return out


def side_record(src: Path, include: Path, libdir: Path, work: Path,
                side: str) -> dict:
    defs = discover_court_defs(src, libdir)
    transcripts: dict[str, list[tuple[int | None, dict[str, str], str]]] = {}
    for level in LEVELS:
        binary = work / f"{src.stem}.{side}{level}"
        ok, err = compile_probe(src, binary, include, libdir, level, defs)
        if not ok:
            return {"side": side, "verdict": "compile-failed", "level": level,
                    "detail": err.splitlines()[:12]}
        runs = []
        for _ in range(RUNS_PER_LEVEL):
            out, _err, code = run_probe(binary, libdir)
            runs.append((code, observations(out), out))
        transcripts[level] = runs

    # A probe that died on a signal compared only the prefix it managed to print.
    codes = {level: [c for c, _obs, _raw in runs]
             for level, runs in transcripts.items()}
    unstable = any(
        any(c is None or (c is not None and c < 0) for c in cs) for cs in codes.values()
    )

    record: dict = {
        "side": side,
        "levels": list(LEVELS),
        "exit_codes": {level: cs for level, cs in codes.items()},
        "observations": {
            level: len(runs[0][1]) for level, runs in transcripts.items()
        },
        "verdict": "clean",
    }

    # 1. Same level, two runs: nondeterminism with no optimizer involved.
    run_drift = []
    for level, runs in transcripts.items():
        for i in range(1, len(runs)):
            if runs[i][1] != runs[0][1]:
                run_drift.append({"level": level,
                                  "differences": first_difference(runs[0][1],
                                                                  runs[i][1])})
                break
    if run_drift:
        record["run_drift"] = run_drift

    # 2. Different levels: the transcript is a property of the frame.
    base = transcripts[LEVELS[1]][0]
    level_drift = []
    for level in LEVELS:
        if level == LEVELS[1]:
            continue
        cur = transcripts[level][0]
        if cur[1] != base[1]:
            level_drift.append({
                "level": level,
                "against": LEVELS[1],
                "differences": first_difference(base[1], cur[1]),
            })
    if level_drift:
        record["level_drift"] = level_drift

    if run_drift or level_drift or unstable:
        record["verdict"] = "unstable"
    return record


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--side", choices=("both", "authority", "candidate"), default="both")
    ap.add_argument("--list", action="store_true",
                    help="print the probes that would be checked and exit")
    args = ap.parse_args(argv)

    probes = discover_probes()
    if args.list:
        for p in probes:
            print(rel(p))
        print(f"  {len(probes)} probes")
        return 0

    auth = resolve_authority(args.authority)
    auth_include, auth_lib = auth.prefix / "include", auth.prefix / "lib"

    want = (("authority", "candidate") if args.side == "both" else (args.side,))
    if "candidate" in want:
        if not (PHASE2 / "libcrypto.so.3").exists():
            print("probe-hygiene: no built distribution shell at "
                  f"{rel(PHASE2)}; run forensics/tools/build_phase2.sh first",
                  file=sys.stderr)
            return 3

    work = REPO_ROOT / "court" / "probe-hygiene"
    work.mkdir(parents=True, exist_ok=True)

    records = []
    for src in probes:
        entry: dict = {"probe": rel(src), "sides": {}}
        for side in want:
            if side == "authority":
                entry["sides"][side] = side_record(
                    src, auth_include, auth_lib, work, "authority")
            else:
                entry["sides"][side] = side_record(
                    src, PHASE2 / "include", PHASE2, work, "candidate")
        entry["verdict"] = (
            "clean" if all(s["verdict"] == "clean" for s in entry["sides"].values())
            else "unstable"
        )
        records.append(entry)

    unstable = [r for r in records if r["verdict"] == "unstable"]
    body = {
        "all_clean": not unstable,
        "authority": auth.id,
        "method": (
            "Each probe is compiled against each side at "
            + ", ".join(LEVELS)
            + f" and run {RUNS_PER_LEVEL} times per level; the transcripts are "
            "compared between levels (frame dependence) and within a level "
            "(nondeterminism)."
        ),
        "levels": list(LEVELS),
        "runs_per_level": RUNS_PER_LEVEL,
        "probes": records,
        "summary": {"total": len(records), "clean": len(records) - len(unstable),
                    "unstable": len(unstable)},
        "claim": (
            "A clean probe's transcript is a function of the library under test "
            "rather than of its own compiled frame. It is NOT evidence of memory "
            "safety, NOT evidence about the candidate, and NOT a court result."
        ),
    }
    doc = envelope(
        kind="probe-hygiene",
        generator=GENERATOR,
        inputs=[InputRef(name="probe", path=p) for p in probes],
        body=body,
        authority=auth.id,
    )
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "clean":
            obs = ", ".join(f"{s['observations'][LEVELS[1]]}"
                            for s in r["sides"].values())
            print(f"  {r['probe']:<44} clean   ({obs} observations at {LEVELS[1]})")
            continue
        print(f"  {r['probe']:<44} UNSTABLE")
        for side, s in r["sides"].items():
            if s["verdict"] == "clean":
                continue
            if s["verdict"] == "compile-failed":
                print(f"      {side}: compile failed at {s['level']}")
                for line in s["detail"]:
                    print(f"        {line}")
                continue
            print(f"      {side}: exit codes {s['exit_codes']}")
            for d in s.get("run_drift", []):
                print(f"      {side}: differs between runs at {d['level']}")
                for diff in d["differences"][:6]:
                    print(f"        {diff['observation']}: {diff['a']!r} then "
                          f"{diff['b']!r}")
            for d in s.get("level_drift", []):
                print(f"      {side}: {d['level']} differs from {d['against']}")
                for diff in d["differences"][:6]:
                    print(f"        {diff['observation']}: {d['against']}={diff['a']!r} "
                          f"{d['level']}={diff['b']!r}")
            if not s.get("run_drift") and not s.get("level_drift"):
                print(f"      {side}: a run did not exit cleanly (signal or timeout)")
    print(f"  -> {rel(OUT)} all_clean={body['all_clean']}")
    return 0 if body["all_clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
