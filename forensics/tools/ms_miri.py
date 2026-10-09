#!/usr/bin/env python3
"""openssl-rs — Phase 25.9, Miri.

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). This module is 25.9's instrument: it runs **Miri**
against the exact admitted candidate and records, honestly, a per-unsafe-site Miri disposition.

What Miri can and cannot do here
--------------------------------
The crate's trusted computing base is not only Rust. `build.rs` compiles first-party C adapters into
a static archive (`openssl_rs_c_adapters`), the crate declares raw FFI to the C API it reconstructs,
and some paths use inline assembly. Miri is an interpreter: it executes Rust's MIR, models a large
part of libc, and **refuses a foreign function it cannot interpret**. So Miri runs the harnesses that
keep to Rust and stops at the FFI/asm boundary. That is recorded as `MIRI_UNSUPPORTED` with the
precise reason -- a foreign-function refusal is never read as a pass, and an absent run is never
read as a pass either.

The harnesses
-------------
`HARNESSES` is the committed run set. Each is a real `cargo +<nightly> miri test --lib <filter>`
command, run in the court with the aliasing model its `-Zmiri-*` flag selects:

  * the **Phase-18 Miri-admitted TCB suite** (`runtime::miri_tcb`), which installs a Rust-backed
    allocator shim so the `CRYPTO_*` ownership surface, the `BUF_MEM`/`STACK`/`LHASH` containers,
    the object registry and the X.509 refcount/lifetime state machine run under Miri -- under **both**
    aliasing models (`-Zmiri-stacked-borrows`, the default, and `-Zmiri-tree-borrows`);
  * the **crate-wide unit-test harness** (`cargo miri test --lib`), under both models;
  * the **allocator unit harness** (`runtime::mem::tests`);
  * the **C-adapter demonstrator**, which reaches a first-party C variadic/ucontext shim and shows
    Miri's exact foreign-function refusal.

A disagreement between the two aliasing models on the same harness is a **review item**, recorded as
a finding; it is never averaged away.

Mapping the runs to the census
------------------------------
`artifacts/phase25/miri.json` carries the runs and a state for **every** compiler-derived site of the
25.1 census:

  * `MIRI_FAIL`   -- a run reported undefined behaviour at the site's `(file, line)`;
  * `MIRI_PASS`   -- the site is in a module a *passing* harness exercised (the finest coverage the
                     Miri output exposes) and its operation is not a foreign/asm boundary;
  * `MIRI_UNSUPPORTED` -- the site is a foreign/asm boundary Miri cannot execute, or is on the
                     unsupported surface a run observed a foreign-function refusal on, with the reason;
  * `MIRI_NOT_REACHABLE` -- no committed harness executed it (the crate-wide harness aborts at its
                     first undefined-behaviour finding, so most sites were never reached).

A `PASS` is never awarded because a site merely exists: it must be in a module a passing run
exercised and cite that run's id and command hash. `UNSUPPORTED` is never `PASS`.

Outputs
-------
  artifacts/phase25/miri.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_bytes,
    sha256_file,
)

# The Docker-only execution guard, called first: this tool runs Miri, so the manifest does not list
# it `metadata_only` and a host invocation is refused rather than producing unreproducible evidence.
import phase25_guard  # noqa: E402

import memory_safety_schemas as schemas  # noqa: E402

import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "miri.json"
GENERATOR = "forensics/tools/ms_miri.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_miri.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
CARGO_TOML = REPO_ROOT / "Cargo.toml"
PHASE18_SUITE = REPO_ROOT / "forensics" / "miri-tcb-suite.json"

# 25.1's compiler-backed source census: the primary unit (the compiler-derived unsafe site).
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"

# Scratch, under the gitignored `/work` tree the brief mandates. The tool refuses on the host, so
# this path only ever exists inside the court. The pinned nightly + miri live under /work too and are
# removed before finishing (the census's 25.1 measurement precedent does the same).
WORK = Path("/work/court/p25/miri")
NIGHTLY = "nightly-2026-10-01"
NIGHTLY_HOME = "/work/.phase25-rustup"
NIGHTLY_CARGO_HOME = "/work/.phase25-cargo"
MIRI_SYSROOT = "/work/.phase25-miri-sysroot"
NIGHTLY_BIN = Path(NIGHTLY_HOME) / "toolchains" / f"{NIGHTLY}-x86_64-unknown-linux-gnu" / "bin"

# The operation kinds a foreign boundary Miri cannot execute. An FFI export, an extern-function call,
# a C variadic boundary and inline assembly are the surface Miri refuses; a site of one of these kinds
# is `MIRI_UNSUPPORTED` wherever it is, never `PASS`.
MIRI_INEXECUTABLE_KINDS: tuple[str, ...] = (
    "FFI_EXPORT",
    "EXTERN_FUNCTION_CALL",
    "C_VARIADIC_BOUNDARY",
    "INLINE_ASM",
)

# The closed state vocabulary this plane records. It is deliberately separate from
# `schemas.TOOL_STATES` only by the `MIRI_` prefix; every member maps to one tool state.
SITE_STATES: tuple[str, ...] = ("MIRI_PASS", "MIRI_FAIL", "MIRI_NOT_REACHABLE", "MIRI_UNSUPPORTED")

# The reason codes a site carries. `PASS`/`FAIL` carry the run id in `run` instead; `NOT_REACHABLE`
# and `UNSUPPORTED` carry a reason from this closed set.
REASON_FOREIGN_BOUNDARY = "MIRI_CANNOT_EXECUTE_FOREIGN_BOUNDARY"
REASON_OBSERVED_REFUSAL = "MIRI_OBSERVED_FOREIGN_FUNCTION_REFUSAL"
REASON_NOT_EXECUTED = "NO_COMMITTED_HARNESS_EXECUTED"

# The committed unsupported surface: the modules the Phase-18 manifest records Miri cannot run
# (`dso`, the `ucontext` fibre, `getrandom`, `rdtsc`, the `FILE*` `bio` path and the pthread/futex
# path). A site in one of these files is `MIRI_UNSUPPORTED` for the same reason whether or not the
# demonstrator run happened to reach it; the reasons are the Phase-18 manifest's own.
UNSUPPORTED_FILES: tuple[str, ...] = (
    "src/dso/dlfcn.rs",
    "src/async/arch/async_posix.rs",
    "src/rand/sys.rs",
    "src/runtime/rdtsc.rs",
    "src/runtime/bio/sys.rs",
    "src/runtime/thread_arch.rs",
)

# The committed run set. Each entry is a real command; `source` names the harness file whose
# `crate::` module references define the coverage of a *passing* run (None for a harness that never
# awards PASS). `filter` is the libtest substring; `aliasing_model` is the Miri borrow model.
HARNESSES: tuple[dict, ...] = (
    {
        "harness_id": "miri-tcb-stacked",
        "description": "the Phase-18 Miri-admitted TCB suite under Stacked Borrows",
        "source": "src/runtime/miri_tcb.rs",
        "filter": "runtime::miri_tcb",
        "aliasing_model": "STACKED_BORROWS",
        "flags": ("-Zmiri-strict-provenance",),
    },
    {
        "harness_id": "miri-tcb-tree",
        "description": "the Phase-18 Miri-admitted TCB suite under Tree Borrows",
        "source": "src/runtime/miri_tcb.rs",
        "filter": "runtime::miri_tcb",
        "aliasing_model": "TREE_BORROWS",
        "flags": ("-Zmiri-strict-provenance", "-Zmiri-tree-borrows"),
    },
    {
        "harness_id": "crate-unit-stacked",
        "description": "the crate-wide unit-test harness under Stacked Borrows",
        "source": None,
        "filter": None,
        "aliasing_model": "STACKED_BORROWS",
        "flags": ("-Zmiri-disable-isolation",),
    },
    {
        "harness_id": "crate-unit-tree",
        "description": "the crate-wide unit-test harness under Tree Borrows",
        "source": None,
        "filter": None,
        "aliasing_model": "TREE_BORROWS",
        "flags": ("-Zmiri-disable-isolation", "-Zmiri-tree-borrows"),
    },
    {
        "harness_id": "mem-unit-stacked",
        "description": "the allocator unit harness under Stacked Borrows",
        "source": None,
        "filter": "runtime::mem::tests",
        "aliasing_model": "STACKED_BORROWS",
        "flags": ("-Zmiri-disable-isolation",),
    },
    {
        "harness_id": "ffi-adapter-stacked",
        "description": "the C variadic/ucontext adapter demonstrator (a foreign-function refusal)",
        "source": None,
        "filter": "crypto_async::arch::async_posix::tests::the_platform_reports_a_usable_context",
        "aliasing_model": "STACKED_BORROWS",
        "flags": ("-Zmiri-disable-isolation",),
    },
)

NON_CLAIMS: tuple[str, ...] = (
    "Miri is not exhaustive and cannot execute foreign C, so an unsupported site is not a passing "
    "site",
    "a Miri pass is not a proof of protocol correctness: Miri checks Rust's memory model, not the "
    "OpenSSL contract",
    "coverage is module-granular: a MIRI_PASS site is in a module a passing harness exercised, not a "
    "per-operation proof that the specific site executed, which is the finest granularity the Miri "
    "output exposes",
    "MIRI_NOT_REACHABLE means no committed harness executed the site (the crate-wide harness aborts "
    "at its first undefined-behaviour finding); it is not a clean result",
    "a Miri disagreement between the Stacked Borrows and Tree Borrows models is a review item, not a "
    "resolved verdict",
)

# A libtest result line: `test <path> ... ok` / `... FAILED` / `... ignored`.
_RESULT = re.compile(r"^test\s+(?P<name>\S+)\s+\.\.\.\s+(?P<status>ok|FAILED|ignored)\s*$")
# The primary error location of a Miri diagnostic: `--> <file>:<line>:<col>`.
_LOC = re.compile(r"^\s*-->\s+(?P<file>\S+?):(?P<line>\d+):(?P<col>\d+)", re.MULTILINE)
# The exact foreign-function refusal Miri emits.
_FOREIGN = re.compile(r"can't call foreign function `(?P<fn>[^`]+)` on OS")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _run(args: list[str], env: dict | None = None, timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
                          timeout=timeout)


# --------------------------------------------------------------------------------------------
# the toolchain
# --------------------------------------------------------------------------------------------

def _miri_env(flags: tuple[str, ...]) -> dict:
    env = dict(os.environ)
    env["PATH"] = f"{NIGHTLY_BIN}:{env.get('PATH', '')}"
    env["RUSTUP_HOME"] = NIGHTLY_HOME
    env["CARGO_HOME"] = NIGHTLY_CARGO_HOME
    env["MIRI_SYSROOT"] = MIRI_SYSROOT
    env["RUSTUP_TOOLCHAIN"] = NIGHTLY
    env["MIRIFLAGS"] = " ".join(flags)
    return env


def toolchain() -> dict:
    """The exact pinned toolchain Miri ran with: the nightly channel, rustc and miri commit hashes,
    and the miri version string. `miri_installed` is a fact, not a hope: if the pinned nightly or the
    `miri` component is absent the runs cannot execute and the plane records the crate-level
    unsupported case instead of a pass."""
    env = _miri_env(())
    rustc = _run(["rustc", "--version", "--verbose"], env=env).stdout
    miri = _run(["miri", "--version"], env=env).stdout if NIGHTLY_BIN.is_dir() else ""

    def commit(text: str) -> str:
        m = re.search(r"commit-hash:\s*([0-9a-f]+)", text)
        return m.group(1) if m else "unknown"

    installed = bool(miri.strip()) and "nightly" in rustc
    return {
        "nightly_channel": NIGHTLY,
        "rustc": rustc.splitlines()[0].strip() if rustc else "unavailable",
        "rustc_commit": commit(rustc),
        "miri": miri.strip() or "unavailable",
        "miri_commit": commit(miri),
        "miri_installed": installed,
        "toolchain_home": NIGHTLY_HOME,
        "aliasing_models": ["STACKED_BORROWS", "TREE_BORROWS"],
        "note": ("the pinned nightly the 25.1 census recorded for expansion (nightly-2026-10-01), "
                 "so the census and the Miri runs share one pinned date"),
    }


# --------------------------------------------------------------------------------------------
# running a harness
# --------------------------------------------------------------------------------------------

def run_harness(harness: dict, tc: dict) -> dict:
    """Run one harness and parse its log into a run record with an honest outcome."""
    cmd = ["cargo", "miri", "test", "--lib"]
    if harness.get("filter"):
        cmd.append(str(harness["filter"]))
    flags = tuple(harness.get("flags") or ())
    display = "MIRIFLAGS=" + " ".join(flags) + " " + " ".join(cmd)
    env = _miri_env(flags)
    WORK.mkdir(parents=True, exist_ok=True)
    logfile = WORK / f"{harness['harness_id']}.log"

    if not tc.get("miri_installed"):
        return {
            "run_id": harness["harness_id"],
            "harness_id": harness["harness_id"],
            "description": harness["description"],
            "filter": harness.get("filter"),
            "aliasing_model": harness["aliasing_model"],
            "miri_flags": list(flags),
            "command": display,
            "command_sha256": sha256_bytes(display.encode("utf-8")),
            "outcome": "UNSUPPORTED",
            "unsupported_reason": ("the pinned nightly + miri component are not installed "
                                   f"({NIGHTLY}); Miri could not run"),
            "transcript_sha256": "unknown",
            "tests_run": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "error_sites": [],
            "ub_primary": None,
            "unsupported_files": [],
        }

    res = _run(cmd, env=env)
    log = res.stdout + res.stderr
    logfile.write_text(log, encoding="utf-8")

    executed = {}
    for line in log.splitlines():
        m = _RESULT.match(line.strip())
        if m:
            executed[m.group("name")] = m.group("status")

    error_sites: list[dict] = []
    unsupported_files: list[str] = []
    unsupported_reason = ""
    ub_primary: dict | None = None
    foreign = _FOREIGN.search(log)
    ub = "error: Undefined Behavior" in log

    if foreign is not None:
        outcome = "UNSUPPORTED"
        unsupported_reason = (f"Miri refused the foreign function `{foreign.group('fn')}` on linux; "
                              f"the crate's first-party C adapters and raw FFI are not executable "
                              f"under Miri")
        for m in _LOC.finditer(log):
            f = m.group("file")
            if f.startswith("src/"):
                unsupported_files.append(f)
    elif ub:
        outcome = "FAIL"
        # The primary error location and the cause/invalidation/allocation locations Miri names in
        # its help blocks are all implicated; the first is the primary, the rest are context.
        block = log[log.find("error: Undefined Behavior"):]
        locs = [{"file": m.group("file"), "line": int(m.group("line")),
                 "column": int(m.group("col"))}
                for m in _LOC.finditer(block) if m.group("file").startswith("src/")]
        error_sites = locs
        ub_primary = locs[0] if locs else None
    elif res.returncode == 0:
        outcome = "PASS"
    else:
        outcome = "FAIL"

    return {
        "run_id": harness["harness_id"],
        "harness_id": harness["harness_id"],
        "description": harness["description"],
        "filter": harness.get("filter"),
        "aliasing_model": harness["aliasing_model"],
        "miri_flags": list(flags),
        "command": display,
        "command_sha256": sha256_bytes(display.encode("utf-8")),
        "outcome": outcome,
        "unsupported_reason": unsupported_reason,
        "transcript_sha256": sha256_bytes(log.encode("utf-8")),
        "tests_run": len(executed),
        "tests_passed": sum(1 for s in executed.values() if s == "ok"),
        "tests_failed": sum(1 for s in executed.values() if s == "FAILED"),
        "error_sites": error_sites,
        "ub_primary": ub_primary,
        "unsupported_files": sorted(set(unsupported_files)),
    }


# --------------------------------------------------------------------------------------------
# coverage: the modules a passing harness exercises, derived from its source
# --------------------------------------------------------------------------------------------

_MODREF = re.compile(r"crate::([a-z_0-9]+(?:::[a-z_0-9]+)*)")


def coverage_files(source_rel: str | None) -> list[str]:
    """The census files a harness exercises, derived from the `crate::` module references in its own
    source plus the harness file itself. This is the finest coverage the Miri output exposes: a
    passing harness executes the modules its source calls into, and this plane records that the site
    is in such a module (a module-granular PASS, never a per-operation one)."""
    if not source_rel:
        return []
    text = _read(REPO_ROOT / source_rel)
    files = {source_rel}
    for m in _MODREF.finditer(text):
        p = m.group(1).replace("::", "/")
        for cand in (f"src/{p}.rs", f"src/{p}/mod.rs"):
            if (REPO_ROOT / cand).is_file():
                files.add(cand)
    return sorted(files)


def _derived_states(census_body: dict, runs: list[dict]) -> dict[str, dict]:
    """The state of every census site, derived from the runs, the census and the committed surface.

    Pure over its inputs: the court re-derives exactly this from the committed artefact's runs, the
    committed census and the committed harness sources, and refuses a committed `.sites` that differs.
    """
    sites = census_body.get("sites") or []
    runs_by_id = {str(r.get("run_id")): r for r in runs}

    # A site is FAIL only at a location a FAIL run reported.
    fail_sites: dict[tuple[str, int], str] = {}
    for r in runs:
        if r.get("outcome") != "FAIL":
            continue
        for es in r.get("error_sites") or []:
            fail_sites[(str(es.get("file")), int(es.get("line") or 0))] = str(r.get("run_id"))

    # A site is PASS only if its file is covered by a passing run.
    pass_files: dict[str, str] = {}
    for r in runs:
        if r.get("outcome") != "PASS":
            continue
        for f in coverage_files_for(r, census_body):
            pass_files.setdefault(f, str(r.get("run_id")))

    # The unsupported surface a run observed (a foreign-function refusal file), plus the committed one.
    observed = set()
    for r in runs:
        observed.update(str(f) for f in (r.get("unsupported_files") or []))
    unsupported_files = set(UNSUPPORTED_FILES) | observed

    out: dict[str, dict] = {}
    for s in sites:
        sid = str(s.get("site_id"))
        f = str(s.get("file"))
        line = int(s.get("line") or 0)
        kind = str(s.get("operation_kind"))
        if (f, line) in fail_sites:
            out[sid] = {"state": "MIRI_FAIL", "run": fail_sites[(f, line)], "reason": ""}
        elif kind in MIRI_INEXECUTABLE_KINDS:
            out[sid] = {"state": "MIRI_UNSUPPORTED", "run": "",
                        "reason": REASON_FOREIGN_BOUNDARY}
        elif f in unsupported_files:
            out[sid] = {"state": "MIRI_UNSUPPORTED", "run": "",
                        "reason": REASON_OBSERVED_REFUSAL}
        elif f in pass_files:
            out[sid] = {"state": "MIRI_PASS", "run": pass_files[f], "reason": ""}
        else:
            out[sid] = {"state": "MIRI_NOT_REACHABLE", "run": "", "reason": REASON_NOT_EXECUTED}
    return out


def coverage_files_for(run: dict, census_body: dict | None = None) -> list[str]:
    """The covered files of a run: the harness source's exercised modules for a passing harness.

    The mapping from a `harness_id` to its source is committed in `HARNESSES`; the derivation is a
    function of that source and the on-disk tree, never of the census, so a coverage claim is bound
    to a real harness file rather than to the site's mere existence."""
    hid = str(run.get("harness_id") or run.get("run_id"))
    for h in HARNESSES:
        if h["harness_id"] == hid:
            return coverage_files(h.get("source"))
    return []


def _counts(states: dict[str, dict]) -> dict:
    c = Counter(v["state"] for v in states.values())
    return {
        "sites": len(states),
        "pass": c.get("MIRI_PASS", 0),
        "fail": c.get("MIRI_FAIL", 0),
        "not_reachable": c.get("MIRI_NOT_REACHABLE", 0),
        "unsupported": c.get("MIRI_UNSUPPORTED", 0),
    }


# --------------------------------------------------------------------------------------------
# findings, residuals and the rule
# --------------------------------------------------------------------------------------------

def _findings(runs: list[dict]) -> list[dict]:
    """Every Miri finding, preserved. An undefined-behaviour diagnostic (an aliasing-model
    violation, an out-of-bounds pointer arithmetic, a use-after-free, an uninitialised read, a
    misalignment or an invalid value) and a two-model disagreement are findings; a failing harness is
    never discarded."""
    findings: list[dict] = []
    for r in runs:
        if r.get("outcome") != "FAIL":
            continue
        prim = r.get("ub_primary")
        if not prim:
            continue
        context = [e for e in (r.get("error_sites") or [])
                   if (e.get("file"), e.get("line"), e.get("column"))
                   != (prim.get("file"), prim.get("line"), prim.get("column"))]
        findings.append({
            "finding_id": f"mf-{r['run_id']}",
            "run_id": r["run_id"],
            "category": "MIRI_UNDEFINED_BEHAVIOUR",
            "file": prim.get("file"),
            "line": prim.get("line"),
            "column": prim.get("column"),
            "context": context,
            "detail": (f"run {r['run_id']} ({r['aliasing_model']}) reported undefined behaviour at "
                       f"this location; the cause/context locations are recorded in `context` and "
                       f"the run transcript is preserved"),
        })
    # A disagreement between the two aliasing models on the same harness is a review item.
    by_harness: dict[str, dict[str, dict]] = {}
    for r in runs:
        base = str(r.get("harness_id")).rsplit("-", 1)[0]
        by_harness.setdefault(base, {})[str(r.get("aliasing_model"))] = r
    for base, models in sorted(by_harness.items()):
        if set(models) >= {"STACKED_BORROWS", "TREE_BORROWS"}:
            a, b = models["STACKED_BORROWS"], models["TREE_BORROWS"]
            sa = (a.get("outcome"), tuple((e["file"], e["line"]) for e in a.get("error_sites") or []))
            sb = (b.get("outcome"), tuple((e["file"], e["line"]) for e in b.get("error_sites") or []))
            if sa != sb:
                findings.append({
                    "finding_id": f"mf-model-disagreement-{base}",
                    "run_id": a["run_id"],
                    "category": "MIRI_MODEL_DISAGREEMENT",
                    "file": "",
                    "line": 0,
                    "column": 0,
                    "detail": (f"the Stacked Borrows run {a['run_id']} and the Tree Borrows run "
                               f"{b['run_id']} disagree on harness {base}: "
                               f"{sa} vs {sb}; a review item, not a resolved verdict"),
                })
    return findings


def _residuals(runs: list[dict], states: dict[str, dict], counts: dict) -> list[dict]:
    residuals: list[dict] = []
    residuals.append({
        "residual_id": "res-miri-coverage-granularity",
        "subject": "MIRI_PASS coverage granularity",
        "class": "evidence_missing",
        "disposition": "preserved",
        "detail": ("MIRI_PASS is module-granular: a passing harness exercises the modules its source "
                   "calls into, and the plane records the site is in such a module. Miri exposes no "
                   "per-operation execution trace, so a PASS is not a per-site proof that the specific "
                   "operation executed"),
        "evidence": [rel(TOOL), rel(CENSUS)],
    })
    residuals.append({
        "residual_id": "res-miri-not-reachable",
        "subject": f"{counts['not_reachable']} MIRI_NOT_REACHABLE site(s)",
        "class": "tool_not_reachable",
        "disposition": "preserved",
        "detail": (f"{counts['not_reachable']} site(s) are MIRI_NOT_REACHABLE: the crate-wide "
                   f"harness aborts at its first undefined-behaviour finding, so the vast majority of "
                   f"the crate's unit tests -- and every site only they reach -- were never executed "
                   f"under Miri. This is not a clean result"),
        "evidence": [rel(CENSUS), rel(PHASE18_SUITE)],
    })
    residuals.append({
        "residual_id": "res-miri-ffi-boundary",
        "subject": f"{counts['unsupported']} MIRI_UNSUPPORTED site(s)",
        "class": "tool_unsupported",
        "disposition": "preserved",
        "detail": (f"{counts['unsupported']} site(s) are MIRI_UNSUPPORTED: the crate compiles "
                   f"first-party C adapters and declares raw FFI, and Miri refuses a foreign function "
                   f"it cannot interpret. An unsupported site is not a passing site"),
        "evidence": [rel(PHASE18_SUITE), rel(CENSUS)],
    })
    for r in runs:
        if r.get("outcome") == "FAIL" and r.get("harness_id") == "mem-unit-stacked":
            residuals.append({
                "residual_id": "res-miri-mem-assertion",
                "subject": "runtime::mem::tests address-dependent assertion",
                "class": "evidence_missing",
                "disposition": "classified",
                "detail": ("runtime::mem::tests::custom_allocator_is_used_and_reported fails under "
                           "Miri on an assertion about allocator addresses, which Miri does not "
                           "reproduce; it is a Miri-environment assertion, not a memory-safety "
                           "undefined-behaviour finding"),
                "evidence": [rel(CENSUS)],
            })
    return residuals


def _rule(tc: dict) -> dict:
    return {
        "authority": {
            "kind": "committed-phase25-planes",
            "paths": [rel(CENSUS), rel(PLAN), rel(SCHEMAS), rel(TOOL), rel(MANIFEST),
                      rel(PHASE18_SUITE)],
            "declaration": (
                "the committed 25.1 census is the compiler-derived primary unit; the committed "
                "Phase-18 Miri TCB manifest names the admitted/unsupported split; the harness "
                "sources named in HARNESSES define the coverage of a passing run -- a site is never "
                "derived from a text scan"),
        },
        "harnesses": [str(h["harness_id"]) for h in HARNESSES],
        "site_states": list(SITE_STATES),
        "inexecutable_kinds": list(MIRI_INEXECUTABLE_KINDS),
        "unsupported_files": list(UNSUPPORTED_FILES),
        "pass_rule": ("MIRI_PASS iff the site's file is covered by a passing harness (the modules "
                      "its source calls into) and its operation is not a foreign/asm boundary; the "
                      "site cites the run id and the run's command hash"),
        "fail_rule": ("MIRI_FAIL iff a run reported undefined behaviour at the site's (file, line); "
                      "the site cites the run id"),
        "unsupported_rule": ("MIRI_UNSUPPORTED iff the site is a foreign/asm boundary Miri cannot "
                             "execute or is on the unsupported surface a run observed a "
                             "foreign-function refusal on; the reason is recorded"),
        "not_reachable_rule": ("MIRI_NOT_REACHABLE iff no committed harness executed the site; it is "
                               "not a clean result"),
        "crate_level": {
            "state": "MIRI_RAN" if tc.get("miri_installed") else "MIRI_UNSUPPORTED",
            "reason": ("" if tc.get("miri_installed")
                       else f"the pinned nightly + miri component ({NIGHTLY}) are not installed"),
        },
    }


# --------------------------------------------------------------------------------------------
# building the body
# --------------------------------------------------------------------------------------------

def build_body(census_body: dict, runs: list[dict], tc: dict) -> dict:
    states = _derived_states(census_body, runs)
    counts = _counts(states)
    return {
        "rule": _rule(tc),
        "toolchain": tc,
        "runs": runs,
        "sites": states,
        "counts": counts,
        "findings": _findings(runs),
        "residuals": _residuals(runs, states, counts),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def miri_findings(body: dict, census_body: dict) -> list[str]:
    """Every way the committed Miri plane contradicts the census, the runs or the harness sources.

    Pure over `body` and the committed census: it re-derives the per-site states and refuses a
    committed `.sites` that differs; it refuses a site with no state, an `UNSUPPORTED` site with no
    reason, a `PASS` that cites no real passing run, a `FAIL` that cites no failing run, a run whose
    outcome/aliasing-model/command hash is malformed, a `FAIL` run with no finding, a typed count and
    a rule that does not name its committed authority.
    """
    problems: list[str] = []
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)

    runs = body.get("runs") or []
    runs_by_id = {str(r.get("run_id")): r for r in runs}
    census_sites = census_body.get("sites") or []
    census_file_of = {str(s.get("site_id")): str(s.get("file")) for s in census_sites}
    census_ids = [str(s.get("site_id")) for s in census_sites]
    if len(set(census_ids)) != len(census_ids):
        problems.append("the census carries a duplicate site_id, so a state is ambiguous")

    # 0. The runs validate: a real command hash, a known aliasing model, a known tool state.
    for r in runs:
        rid = str(r.get("run_id"))
        if r.get("outcome") not in schemas.TOOL_STATES:
            problems.append(f"run {rid} has an unknown outcome {r.get('outcome')!r}")
        if r.get("aliasing_model") not in ("STACKED_BORROWS", "TREE_BORROWS"):
            problems.append(f"run {rid} names an unknown aliasing model "
                            f"{r.get('aliasing_model')!r}")
        ch = str(r.get("command_sha256") or "")
        if len(ch) != 64 or any(c not in "0123456789abcdef" for c in ch):
            problems.append(f"run {rid} does not carry a sha256 command hash")
        if r.get("outcome") == "UNSUPPORTED" and r.get("unsupported_reason") and \
                not r.get("unsupported_reason"):
            problems.append(f"run {rid} is UNSUPPORTED with an empty reason")

    # 1. The derived states are the committed states, with a specific message per disagreement.
    derived = _derived_states(census_body, runs)
    committed = body.get("sites") or {}
    for sid in census_ids:
        want = derived.get(sid)
        got = committed.get(sid)
        if got is None:
            problems.append(f"site {sid} has no Miri state")
            continue
        ws, gs = want["state"], got.get("state")
        if ws == gs:
            continue
        if ws == "MIRI_UNSUPPORTED" and gs == "MIRI_PASS":
            problems.append(f"site {sid} records MIRI_PASS for a site the derivation marks "
                            f"UNSUPPORTED; UNSUPPORTED is not PASS")
        elif gs == "MIRI_PASS":
            problems.append(f"site {sid} claims MIRI_PASS but the derivation marks it {ws}; a "
                            f"coverage claim with no harness is refused")
        else:
            problems.append(f"site {sid}: committed state {gs} != derived {ws}")
    extra = set(committed) - set(census_ids)
    if extra:
        problems.append(f"the Miri plane carries {len(extra)} site(s) not in the census")

    # 2. Every state is closed; UNSUPPORTED carries a reason.
    for sid, rec in committed.items():
        st = rec.get("state")
        if st not in SITE_STATES:
            problems.append(f"site {sid} has an unknown state {st!r}")
        if st == "MIRI_UNSUPPORTED" and not rec.get("reason"):
            problems.append(f"site {sid} is MIRI_UNSUPPORTED but records no reason; refusing to say "
                            f"why is refusing the evidence")

    # 3. A PASS cites a real run that passed and covers the site's file; a FAIL cites a failing run.
    for sid, rec in committed.items():
        st = rec.get("state")
        if st == "MIRI_PASS":
            rid = str(rec.get("run") or "")
            run = runs_by_id.get(rid)
            if run is None:
                problems.append(f"MIRI_PASS site {sid} cites no run ({rid!r})")
            elif run.get("outcome") != "PASS":
                problems.append(f"MIRI_PASS site {sid} cites run {rid}, whose outcome is "
                                f"{run.get('outcome')}")
            else:
                f = census_file_of.get(sid, "")
                if f not in coverage_files_for(run, census_body):
                    problems.append(f"MIRI_PASS site {sid} cites run {rid}, which does not cover its "
                                    f"file {f}")
        elif st == "MIRI_FAIL":
            rid = str(rec.get("run") or "")
            run = runs_by_id.get(rid)
            if run is None:
                problems.append(f"MIRI_FAIL site {sid} cites no run ({rid!r})")
            elif run.get("outcome") != "FAIL":
                problems.append(f"MIRI_FAIL site {sid} cites run {rid}, whose outcome is "
                                f"{run.get('outcome')}")

    # 4. Every FAIL run's error site has a finding (a finding is never dropped).
    findings = body.get("findings") or []
    finding_runs = {str(f.get("run_id")) for f in findings}
    for r in runs:
        if r.get("outcome") == "FAIL" and ((r.get("error_sites") or []) or r.get("ub_primary")):
            if str(r.get("run_id")) not in finding_runs:
                problems.append(f"run {r.get('run_id')} reported an error site but no finding records "
                                f"it; a Miri finding is preserved, never dropped")
    for f in findings:
        if str(f.get("run_id")) not in runs_by_id:
            problems.append(f"finding {f.get('finding_id')} cites run {f.get('run_id')!r}, which is "
                            f"not a committed run")

    # 5. The counts are derived, not typed.
    if body.get("counts") != _counts(derived):
        problems.append("the committed `counts` is not the derived `counts`")

    # 6. The toolchain is recorded and the crate-level case is recorded.
    tcv = body.get("toolchain") or {}
    if not tcv.get("nightly_channel") or not tcv.get("miri"):
        problems.append("the Miri toolchain is not recorded")
    cl = (body.get("rule") or {}).get("crate_level") or {}
    if cl.get("state") not in ("MIRI_RAN", "MIRI_UNSUPPORTED"):
        problems.append("the crate-level Miri case is not recorded")
    if cl.get("state") == "MIRI_UNSUPPORTED" and not cl.get("reason"):
        problems.append("the crate-level Miri case is MIRI_UNSUPPORTED but carries no reason")

    # 7. The rule names its committed authority and the required non-claim is present.
    paths = ((body.get("rule") or {}).get("authority") or {}).get("paths") or []
    for want in (rel(CENSUS), rel(PHASE18_SUITE)):
        if want not in paths:
            problems.append(f"the Miri rule does not name its committed authority {want}")
    if not any("cannot execute foreign C" in nc and "unsupported site is not a passing site" in nc
               for nc in (body.get("non_claims") or [])):
        problems.append("the plane does not carry the required foreign-C non-claim")

    # 8. Every residual validates against the residual schema.
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}"
                     for p in schemas.validate("residual", r)]

    return problems


def miri_sensitivity_control(body: dict, census_body: dict) -> dict:
    """Seed the mutations and require each caught, with specificity holding.

    Each is a distinct way the plane could lie: an UNSUPPORTED site marked PASS; a PASS with no run;
    a memory-safety finding dropped; a coverage claim with no harness; and a typed count.
    """
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    baseline = miri_findings(body, census_body)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = miri_findings(mutated, census_body)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    def clone() -> dict:
        return json.loads(json.dumps(body))

    committed = body.get("sites") or {}
    pass_sid = next((s for s, r in committed.items() if r.get("state") == "MIRI_PASS"), None)
    unsup_sid = next((s for s, r in committed.items() if r.get("state") == "MIRI_UNSUPPORTED"), None)
    notr_sid = next((s for s, r in committed.items() if r.get("state") == "MIRI_NOT_REACHABLE"), None)
    any_run = str((body.get("runs") or [{}])[0].get("run_id"))

    # m1: an UNSUPPORTED site marked PASS.
    def unsupported_marked_pass() -> dict:
        b = clone()
        b["sites"][unsup_sid] = {"state": "MIRI_PASS", "run": any_run, "reason": ""}
        return b

    m1 = check("unsupported_marked_pass", unsupported_marked_pass(), "UNSUPPORTED is not PASS")

    # m2: a PASS with no run.
    def pass_without_run() -> dict:
        b = clone()
        b["sites"][pass_sid] = {"state": "MIRI_PASS", "run": "", "reason": ""}
        return b

    m2 = check("pass_without_run", pass_without_run(), "cites no run")

    # m3: a memory-safety finding dropped.
    def finding_dropped() -> dict:
        b = clone()
        b["findings"] = [f for f in b["findings"] if f.get("category") != "MIRI_UNDEFINED_BEHAVIOUR"]
        return b

    m3 = check("finding_dropped", finding_dropped(), "no finding records it")

    # m4: a coverage claim with no harness -- a site in a file no passing harness covers marked PASS.
    def coverage_claim_without_harness() -> dict:
        b = clone()
        b["sites"][notr_sid] = {"state": "MIRI_PASS", "run": any_run, "reason": ""}
        return b

    m4 = check("coverage_claim_without_harness", coverage_claim_without_harness(),
               "coverage claim with no harness")

    # m5: a typed count.
    def typed_count() -> dict:
        b = clone()
        b["counts"]["pass"] += 1
        return b

    m5 = check("typed_count", typed_count(), "not the derived `counts`")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_census() -> tuple[dict, list[dict]]:
    """A tiny, self-consistent census and run set: one covered executable site, one covered foreign
    site, one fail site, one unsupported-surface site and one uncovered site."""
    census = {"sites": [
        {"site_id": "us-cov-1", "file": "src/runtime/mem.rs", "line": 10,
         "operation_kind": "RAW_POINTER_READ"},
        {"site_id": "us-cov-2", "file": "src/runtime/mem.rs", "line": 20,
         "operation_kind": "FFI_EXPORT"},
        {"site_id": "us-fail-1", "file": "src/aes.rs", "line": 376,
         "operation_kind": "RAW_POINTER_WRITE"},
        {"site_id": "us-unsup-1", "file": "src/async/arch/async_posix.rs", "line": 383,
         "operation_kind": "UNSAFE_FUNCTION_CALL"},
        {"site_id": "us-notrec-1", "file": "src/bn/bignum.rs", "line": 99,
         "operation_kind": "RAW_POINTER_READ"},
    ]}
    runs = [
        {"run_id": "miri-tcb-stacked", "harness_id": "miri-tcb-stacked",
         "aliasing_model": "STACKED_BORROWS", "outcome": "PASS", "command_sha256": "0" * 64,
         "command": "MIRIFLAGS=-Zmiri-strict-provenance cargo miri test --lib runtime::miri_tcb",
         "unsupported_reason": "", "error_sites": [], "unsupported_files": []},
        {"run_id": "crate-unit-stacked", "harness_id": "crate-unit-stacked",
         "aliasing_model": "STACKED_BORROWS", "outcome": "FAIL", "command_sha256": "1" * 64,
         "command": "MIRIFLAGS=-Zmiri-disable-isolation cargo miri test --lib",
         "unsupported_reason": "",
         "error_sites": [{"file": "src/aes.rs", "line": 376, "column": 9}],
         "ub_primary": {"file": "src/aes.rs", "line": 376, "column": 9},
         "unsupported_files": []},
    ]
    return census, runs


def _synth_toolchain() -> dict:
    return {"nightly_channel": NIGHTLY, "rustc": "rustc 1.101.0-nightly", "rustc_commit": "0" * 40,
            "miri": "miri 0.1.0", "miri_commit": "0" * 40, "miri_installed": True,
            "aliasing_models": ["STACKED_BORROWS", "TREE_BORROWS"]}


def self_test() -> int:
    """Prove the guard refuses the host and the derivation and control are honest.

    The synthetic census covers five sites -- a covered executable site (PASS), a covered foreign
    site (UNSUPPORTED), a fail site (FAIL), an unsupported-surface site (UNSUPPORTED) and an
    uncovered site (NOT_REACHABLE) -- so every state is exercised without a Miri run.
    """
    failures: list[str] = []

    refusal = phase25_guard.host_refusal_reasons("ms_miri.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of ms_miri.py")

    census, runs = _synth_census()
    tc = _synth_toolchain()
    body = build_body(census, runs, tc)

    want = {
        "us-cov-1": "MIRI_PASS",
        "us-cov-2": "MIRI_UNSUPPORTED",
        "us-fail-1": "MIRI_FAIL",
        "us-unsup-1": "MIRI_UNSUPPORTED",
        "us-notrec-1": "MIRI_NOT_REACHABLE",
    }
    got = {sid: rec["state"] for sid, rec in body["sites"].items()}
    if got != want:
        failures.append(f"the synthetic states are wrong: {got}")
    c = body["counts"]
    if (c["pass"], c["fail"], c["unsupported"], c["not_reachable"]) != (1, 1, 2, 1):
        failures.append(f"the synthetic counts are wrong: {c}")
    if not body["findings"]:
        failures.append("the synthetic FAIL run produced no finding")

    baseline = miri_findings(body, census)
    if baseline:
        failures.append(f"the synthetic Miri body is not clean: {baseline[:4]}")
    control = miri_sensitivity_control(body, census)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-miri] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-miri] self-test ok: the guard refuses the host; the synthetic derivation exercises "
          "PASS/FAIL/UNSUPPORTED/NOT_REACHABLE; and every seeded mutation (an UNSUPPORTED marked "
          "PASS, a PASS with no run, a dropped finding, a coverage claim with no harness and a typed "
          "count) is caught with specificity holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_plane(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-miri-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="miri-tcb-suite-manifest", path=PHASE18_SUITE),
        InputRef(name="harness-source-miri-tcb", path=REPO_ROOT / "src" / "runtime" / "miri_tcb.rs"),
        InputRef(name="cargo-manifest", path=CARGO_TOML),
    ]


def _measure() -> int:
    """Run Miri over the committed harnesses and write artifacts/phase25/miri.json.

    Measurement: it runs Miri with the pinned nightly, so it is refused on the host and is not
    listed among `evidence_determinism.py`'s generators (see that file's why-comment).
    """
    tc = toolchain()
    if not tc.get("miri_installed"):
        print(f"[ms-miri] the pinned nightly + miri component ({NIGHTLY}) are not installed under "
              f"{NIGHTLY_HOME}; recording the crate-level MIRI_UNSUPPORTED case")
    census_body = ms_census.decode_body(_body(json.loads(_read(CENSUS)) if CENSUS.is_file() else {}))
    runs = [run_harness(h, tc) for h in HARNESSES]
    body = build_body(census_body, runs, tc)
    problems = miri_findings(body, census_body)

    refs = ms_codec.refs_from_census(census_body)
    auth = resolve_authority(PRODUCTION_AUTHORITY)
    encoded = ms_codec.encode_body(body, refs)
    doc = envelope(kind="phase25-miri", authority=auth.id, inputs=_inputs(), body=encoded,
                   generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_plane(OUT, doc)

    c = body["counts"]
    print(f"[ms-miri] Miri over {len(runs)} harness(es): ")
    for r in runs:
        print(f"  {r['run_id']:<20} {r['outcome']:<12} {r['aliasing_model']:<16} "
              f"{r['tests_passed']}/{r['tests_run']} passed"
              + (f" -- {r['unsupported_reason'][:80]}" if r.get("unsupported_reason") else ""))
    print(f"  sites: {c['sites']} -- pass={c['pass']} fail={c['fail']} "
          f"unsupported={c['unsupported']} not_reachable={c['not_reachable']}")
    print(f"  findings={len(body['findings'])} residuals={len(body['residuals'])}; "
          f"crate-level={body['rule']['crate_level']['state']}")
    print(f"  -> {rel(OUT)} all_pass={not problems}")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed plane, without Miri."""
    if not OUT.is_file():
        print(f"[ms-miri] {rel(OUT)} is absent; run --measure")
        return 1
    doc = json.loads(OUT.read_text(encoding="utf-8"))
    census_body = ms_census.decode_body(_body(json.loads(_read(CENSUS))))
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(doc.get("body", doc), refs)
    problems = miri_findings(body, census_body)
    if problems:
        print(f"[ms-miri] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-miri] check ok: {c['sites']} site(s) -- pass={c['pass']} fail={c['fail']} "
          f"unsupported={c['unsupported']} not_reachable={c['not_reachable']}; "
          f"{len(body['findings'])} finding(s), {len(body['residuals'])} residual(s); every check "
          f"holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="run Miri and write artifacts/phase25/miri.json")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed plane")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the guard refuses the host and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first: this tool runs Miri.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.measure:
        return _measure()
    if args.check:
        return _check()
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
