#!/usr/bin/env python3
"""openssl-rs — Phase 25.11, TSan.

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). This module is 25.11's instrument: it builds the exact
admitted candidate under **ThreadSanitizer** and records, honestly, a per-site ThreadSanitizer
disposition over the **concurrency-relevant surface** of the 25.1 census.

The concurrency-relevant surface, and why it is derived rather than typed
------------------------------------------------------------------------
TSan answers one question: *is there a data race here?* That question is only meaningful where the
candidate's operation carries a concurrency obligation -- a thread-affinity, a `Send`/`Sync` and
init-once property. The 25.1 census classifies every site's operation kind and names no other
dimension, so the surface is derived from the committed kind -> dimension rule the 25.3 obligation
plane records (`ms_obligations.KIND_DIMENSIONS`): a site is on the surface iff its operation kind
requires one of `THREAD_AFFINITY`, `SEND_SYNC` or `INIT_ONCE`. That is the unsafe `Send`/`Sync` impls
(`UNSAFE_IMPL`) and the mutable statics (`STATIC_MUT_ACCESS`) and nothing else -- the operations whose
soundness *is* a concurrency property. Every other census site is out of TSan's subject (its
concurrency question is not expressible, and the 25.10 plane carries it); the plane records the
derivation and the court re-derives it, so the surface is a fact rather than a hand list.

The venue, and the one dimension it differs from the court's `exec`
------------------------------------------------------------------
TSan maps a **tera-byte-scale sparse shadow** before it instruments anything. Measured in this venue,
`ThreadSanitizer failed to allocate 0x200000000000 (35184372088832) bytes` -- a ~35.1 TB
`MAP_NORESERVE` virtual reservation -- so a TSan binary cannot *start* under the court's per-process
`RLIMIT_DATA` (default 4 GiB, `docker/openssl-rs-court.sh`), exactly as ASan cannot (25.10). The cap
is kept for the hostile courts (it is what keeps a runaway court off the host, D105), so 25.11 does
not weaken it. The TSan environment is a **derivation of the admitted court venue**: the same
admitted image (`openssl-rs-court:1`, `forensics/memory-safety/container.json`) executed with the
venue's own documented `OPENSSL_RS_COURT_DATA` override, which removes *only* the per-process
`RLIMIT_DATA` for the sanitizer run. Every bound that bounds *real* resources -- the container cgroup
memory cap, PIDs, CPUs, the wall clock -- is unchanged, because TSan's shadow is `PROT_NONE` +
`MAP_NORESERVE` virtual address space the cgroup does not count as resident. The plane records this
venue, the exact command and the measured shadow size, so the choice is auditable rather than
implied.

The deterministic schedule, and the honest bound it places on a clean result
---------------------------------------------------------------------------
TSan observes the schedule the run happened to take, so a race it did not observe is not absent.
`docs/CONCURRENCY_MODEL.md` section 6 therefore fixes the method: "deterministic scheduling for
reproducibility where the mechanism permits it, with the schedule recorded as part of the run". The
libtest schedule is pinned to one thread (`--test-threads=1`), so the executed set and the
observation are a deterministic function of the committed candidate, and every run records its
schedule. The crate's *own* thread tests still spawn and join threads; only the test harness's
parallel scheduling is removed. A clean result is therefore a claim about **this recorded schedule**,
never that the candidate is globally race-free -- which is why the plane's `pass_semantics` and
non-claims state it.

The instrument
--------------
The crate and `std` are rebuilt under TSan (`-Zsanitizer=thread -Zbuild-std` with the pinned
nightly), the first-party C adapters `build.rs` compiles go through a `CC` wrapper that appends
`-fsanitize=thread`, and the instrumented test binary is run over the crate's concurrency-relevant
subsystems with the recorded schedule. A deliberate data-race **canary** must be diagnosed
(`data race` + nonzero exit) before any no-race result is trusted, and every run's transcript is
preserved. The instrumentation is closed over the Rust crate, `std`, and the first-party C adapters;
libc is runtime-intercepted, which is the designed closure.

Mapping the runs to the census
------------------------------
`artifacts/phase25/tsan.json` carries the runs and a state for **every** site of the concurrency-
relevant surface:

  * `TSAN_FAIL` -- a run reported a ThreadSanitizer data race at the site's `(file, line)`;
  * `TSAN_PASS` -- the site's file is covered by a *passing* TSan run (a file some executed test
                    lives in) and its operation is not an opaque foreign boundary;
  * `TSAN_UNSUPPORTED` -- the site is on the committed foreign/uninstrumented surface (a module the
                    sanitizer cannot instrument across), or the venue could not run the instrument,
                    or the positive control did not fire -- with the reason;
  * `TSAN_NOT_REACHABLE` -- no committed harness executed the site (it is not a clean result).

A `PASS` is never awarded because a site merely exists: it must be in a file a *passing* run
executed and cite that run's id and command hash. `UNSUPPORTED` is never `PASS`.

Outputs
-------
  artifacts/phase25/tsan.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
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

# The Docker-only execution guard, called first: this tool builds and instruments the candidate, so
# the manifest does not list it `metadata_only` and a host invocation is refused rather than producing
# unreproducible evidence.
import phase25_guard  # noqa: E402

import memory_safety_schemas as schemas  # noqa: E402

import ms_census  # noqa: E402
import ms_codec  # noqa: E402
import ms_obligations  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "tsan.json"
GENERATOR = "forensics/tools/ms_tsan.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_tsan.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
CARGO_TOML = REPO_ROOT / "Cargo.toml"
CANARY_SRC = REPO_ROOT / "forensics" / "tools" / "tsan_canary.c"
CANARY_RS = REPO_ROOT / "forensics" / "tools" / "tsan_canary.rs"

# 25.1's compiler-backed source census: the primary unit (the compiler-derived unsafe site), and
# 25.3's obligation plane: the committed kind -> dimension rule that defines the surface.
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
OBLIGATIONS = REPO_ROOT / "artifacts" / "phase25" / "safety-obligations.json"
MS_OBLIGATIONS_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_obligations.py"

# Scratch, under the gitignored `/work` tree the brief mandates. The tool refuses on the host, so this
# path only ever exists inside the court. The pinned nightly lives under /work and is never removed.
WORK = Path("/work/court/p25/tsan")
NIGHTLY = "nightly-2026-10-01"
NIGHTLY_HOME = "/work/.phase25-rustup"
NIGHTLY_CARGO_HOME = "/work/.phase25-cargo"
NIGHTLY_BIN = Path(NIGHTLY_HOME) / "toolchains" / f"{NIGHTLY}-x86_64-unknown-linux-gnu" / "bin"

TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
TARGET_DIR = WORK / "target-dev"
CC_WRAPPER = WORK / "bin" / "tsan-cc"
# The instrumented schedule. `-Ccodegen-units=16` keeps the per-CGU LLVM module small enough to fit the
# admitted container's cgroup memory cap (a single codegen unit OOMs LLVM on this crate); it is
# recorded, not assumed. `-Cdebuginfo=1` is what makes a TSan report name `file:line`.
RUSTFLAGS = "-Zsanitizer=thread -Cdebuginfo=1 -Clinker=clang -Ccodegen-units=16"
PROFILE = "dev"
TSAN_OPTIONS = "halt_on_error=1:exit_code=66"
# The deterministic schedule `docs/CONCURRENCY_MODEL.md` section 6 fixes: the libtest harness runs one
# test at a time, so the executed set and the observation are a function of the committed candidate
# rather than of the machine's load. The crate's own thread tests still spawn and join threads.
SCHEDULE: tuple[str, ...] = ("--test-threads=1",)
BUILD_TIMEOUT = 2400
RUN_TIMEOUT = 1800
CANARY_TIMEOUT = 180
# TSan changes Rust's ABI (it instruments memory accesses), so a standalone canary built without
# `-Zbuild-std` links a pre-built `std` whose ABI differs. The canary is not product code; the
# mismatch-allow flag is the documented way to build a standalone TSan probe, and it is recorded.
CANARY_ABI_ALLOW = "-Cunsafe-allow-abi-mismatch=sanitizer"

# The operation kinds TSan cannot see through: it instruments Rust and the first-party C adapters, but
# an `asm!` block is opaque, so a race inside one is invisible. A site of one of these kinds is
# `TSAN_UNSUPPORTED` wherever it is, never `PASS`. The census carries none on the surface today; the
# rule is kept so one cannot be silently counted clean if it appears.
TSAN_INEXECUTABLE_KINDS: tuple[str, ...] = ("INLINE_ASM",)

# The committed foreign/uninstrumented surface. TSan instruments the Rust crate, `std` (rebuilt with
# `-Zbuild-std`), the first-party C adapters and the interceptable libc; it cannot instrument a module
# resolved and loaded at run time, so a race originating in a `dlopen`'d module (or in a callback it
# invokes) is invisible. `src/dso/dlfcn.rs` is the crate's dynamic-loading boundary, so its sites are
# `TSAN_UNSUPPORTED` -- a conservative record, never a pass.
UNSUPPORTED_FILES: tuple[str, ...] = ("src/dso/dlfcn.rs",)

# The dimensions whose presence on an operation kind makes the site's concurrency question expressible
# to TSan. They are the closed obligation dimensions of `memory_safety_schemas.OBLIGATION_DIMENSIONS`.
CONCURRENCY_DIMENSIONS: tuple[str, ...] = ("THREAD_AFFINITY", "SEND_SYNC", "INIT_ONCE")

# The closed state vocabulary this plane records. It is deliberately separate from
# `schemas.TOOL_STATES` only by the `TSAN_` prefix; every member maps to one tool state.
SITE_STATES: tuple[str, ...] = ("TSAN_PASS", "TSAN_FAIL", "TSAN_NOT_REACHABLE", "TSAN_UNSUPPORTED")

# The reason codes a site carries. `PASS`/`FAIL` carry the run id in `run` instead; `NOT_REACHABLE` and
# `UNSUPPORTED` carry a reason from this closed set.
REASON_OPAQUE = "TSAN_CANNOT_INSTRUMENT_OPAQUE_OPERATION"
REASON_FOREIGN_MODULE = "TSAN_CANNOT_INSTRUMENT_FOREIGN_DYNAMIC_MODULE"
REASON_NOT_EXECUTED = "NO_COMMITTED_HARNESS_EXECUTED"
REASON_VENUE = "TSAN_VENUE_CANNOT_RUN_THE_INSTRUMENT"
REASON_POSITIVE_CONTROL = "TSAN_POSITIVE_CONTROL_DID_NOT_FIRE"

# The top-level semantics of a TSAN_PASS, stated once for the whole plane. TSan exposes no
# per-operation execution trace, and it observes only the recorded schedule, so a PASS is a
# file-granular instrument/coverage claim under that schedule, never a per-operation race-freedom
# guarantee and never a claim about a schedule the run did not take.
PASS_SEMANTICS = (
    "TSAN_PASS means the site's source FILE was instrumented, had a covering run under the recorded "
    "one-thread libtest schedule, and produced no ThreadSanitizer data-race report -- it is not a "
    "claim that the specific unsafe operation executed race-free, and it is not a claim about a "
    "schedule the run did not take; every TSan result records `coverage_granularity: file` and every "
    "run records its schedule, so a PASS is a file-granular instrument/coverage claim under that "
    "schedule, never a per-operation race-freedom guarantee")

NON_CLAIMS: tuple[str, ...] = (
    "TSan is not exhaustive: it instruments a run and reports the races it observed in the schedule "
    "that run took, so NOT_REACHABLE and UNSUPPORTED are not clean results, and a run that observed "
    "no race is not a proof that no schedule races",
    "the TSan runs use a recorded deterministic one-thread libtest schedule (`--test-threads=1`), so "
    "a race the crate's own thread tests did not exercise under that schedule is not read as absent; "
    "the schedule is recorded on every run and is the bound on what a clean result claims",
    "a zero-findings TSan result is trusted only because the canary is known to fire; the canary "
    "proves the instrument can detect a deliberate data race in this venue, not that the candidate "
    "is race-free",
    "coverage is file-granular: a TSAN_PASS site is in a file a passing run executed, not a "
    "per-operation proof that the specific site executed concurrently",
    "TSAN_NOT_REACHABLE means no committed harness executed the site's file; it is not a clean "
    "result",
    "the TSan environment removes only the venue's per-process RLIMIT_DATA, because TSan's shadow is "
    "a ~35.1 TB PROT_NONE + MAP_NORESERVE virtual reservation the cgroup does not count as resident; "
    "the container cgroup memory cap, PIDs, CPUs and the wall clock are unchanged, so no bound on "
    "resident resources is weakened",
    "a TSAN_UNSUPPORTED site is not a passing site: the instrument could not express the question "
    "there, and it is recorded with its reason",
    "the surface is the compiler-derived census sites whose operation kind requires a concurrency "
    "obligation (thread-affinity, Send/Sync or init-once); every other census site is not restated "
    "here and is the 25.10 plane's subject, not a TSan pass",
)

# The committed run set. Each entry is a real command; `source` names the harness file whose `crate::`
# module references extend the coverage of a *passing* run (None for a harness that grants coverage
# only from the tests it executes). `filter` is the libtest substring. The four subsystems the crate's
# concurrency surfaces live in are each exercised under the recorded deterministic schedule.
HARNESSES: tuple[dict, ...] = (
    {
        "harness_id": "tsan-runtime",
        "description": ("the runtime subsystem's unit tests under ThreadSanitizer with the recorded "
                        "one-thread schedule (thread primitives, locks, RCU, thread-local state and "
                        "init)"),
        "source": None,
        "filter": "runtime::",
    },
    {
        "harness_id": "tsan-context",
        "description": ("the context/namemap/thread-data unit tests under ThreadSanitizer with the "
                        "recorded one-thread schedule"),
        "source": None,
        "filter": "context::",
    },
    {
        "harness_id": "tsan-digest",
        "description": ("the digest subsystem's unit tests under ThreadSanitizer with the recorded "
                        "one-thread schedule (the digest tables carry unsafe Send/Sync impls)"),
        "source": None,
        "filter": "digest::",
    },
    {
        "harness_id": "tsan-evp",
        "description": ("the EVP method/fetch unit tests under ThreadSanitizer with the recorded "
                        "one-thread schedule (the EVP tables carry unsafe Send/Sync impls)"),
        "source": None,
        "filter": "evp::",
    },
)

# A libtest result line: `test <path> ... ok` / `... FAILED` / `... ignored`.
_RESULT = re.compile(r"^test\s+(?P<name>\S+)\s+\.\.\.\s+(?P<status>ok|FAILED|ignored)\s*$")
# The primary crate frame a TSan report names: `/work/src/<file>.rs:<line>` (a TSan frame carries no
# column). The column is optional so an ASan-style frame would also resolve.
_FRAME = re.compile(r"(?:/work/)?(src/[A-Za-z0-9_/.+-]+\.rs):(?P<line>\d+)(?::(?P<col>\d+))?")
# The TSan race class, e.g. `ThreadSanitizer: data race`. A TSan startup warning
# (`unexpected memory mapping`) also matches a naive pattern, so it is filtered by name below.
_TSAN_ERROR = re.compile(r"ThreadSanitizer:\s*(?P<kind>[a-z][a-z0-9-]*(?: [a-z][a-z0-9-]*)*)")
_MODREF = re.compile(r"crate::([a-z_0-9]+(?:::[a-z_0-9]+)*)")
# The benign startup warning that is not an observation about the candidate.
_UNEXPECTED_MAPPING = "unexpected memory mapping"
# Volatile bytes that must never enter the plane: every TSan log carries the run's own process id
# (`(pid=1409165)`), thread ids (`tid=...`, `thread T36`, `(1473492) panicked`), heap/stack/global
# addresses (`0x7bf0af1e0010`) and, in the wall-clock summary, a duration (`finished in 2.34s`). None
# of it is evidence. `--measure` is byte-for-byte reproducible only if these are normalised before
# they are hashed or stored.
_VOLATILE_PID = re.compile(r"==\d+==")
_VOLATILE_PID_EQ = re.compile(r"\bpid=\d+\b")
_VOLATILE_TID_EQ = re.compile(r"\btid=\d+\b")
_VOLATILE_THREAD = re.compile(r"thread T\d+")
_VOLATILE_TESTTID = re.compile(r"\(\d+\) panicked")
_VOLATILE_ADDR = re.compile(r"0x[0-9a-fA-F]+")
_VOLATILE_SECONDS = re.compile(r"\bin \d+(?:\.\d+)?s\b")
# libtest emits a progress notice for a test that runs long (`test <name> has been running for over
# 60 seconds`); whether it fires is a wall-clock accident, not an observation about the candidate.
_VOLATILE_PROGRESS = re.compile(r"has been running for over \d+(?:\.\d+)? seconds")


def _scrub_volatile(text: str) -> str:
    """Blank the per-run process/thread ids, addresses and durations in one line of tool output."""
    text = _VOLATILE_PID.sub("==PID==", text)
    text = _VOLATILE_PID_EQ.sub("pid=PID", text)
    text = _VOLATILE_TID_EQ.sub("tid=TID", text)
    text = _VOLATILE_THREAD.sub("thread T#", text)
    text = _VOLATILE_TESTTID.sub("(TID) panicked", text)
    text = _VOLATILE_ADDR.sub("0xADDR", text)
    return _VOLATILE_SECONDS.sub("in Ns", text)


def _normalise_log(text: str) -> str:
    """Canonicalise a tool log so its digest is reproducible run to run.

    The digest is taken over the log with PIDs, thread ids, addresses, durations and libtest's
    long-running progress notices blanked or dropped, and the lines sorted, because libtest executes
    tests in a nondeterministic order. Every substantive byte -- every test name, every status and
    every diagnostic -- is preserved; only the run's incidental bytes are lost.
    """
    lines = [ln for ln in _scrub_volatile(text).splitlines() if not _VOLATILE_PROGRESS.search(ln)]
    return "\n".join(sorted(lines))


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _run(args: list[str], env: dict | None = None, timeout: int = RUN_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
                          timeout=timeout)


def _tsan_env(extra: dict | None = None) -> dict:
    env = dict(os.environ)
    env["PATH"] = f"{NIGHTLY_BIN}:{env.get('PATH', '')}"
    env["RUSTUP_HOME"] = NIGHTLY_HOME
    env["CARGO_HOME"] = NIGHTLY_CARGO_HOME
    env["RUSTUP_TOOLCHAIN"] = NIGHTLY
    env["RUSTFLAGS"] = RUSTFLAGS
    env["CARGO_TARGET_DIR"] = str(TARGET_DIR)
    env["CC"] = str(CC_WRAPPER)
    env["AR"] = "ar"
    env["CARGO_INCREMENTAL"] = "0"
    env["TSAN_OPTIONS"] = TSAN_OPTIONS
    if extra:
        env.update(extra)
    return env


# --------------------------------------------------------------------------------------------
# the concurrency-relevant surface
# --------------------------------------------------------------------------------------------

def kind_is_concurrency_relevant(kind: str) -> bool:
    """Whether TSan's data-race question is expressible at an operation of this kind.

    A site's operation kind requires a set of safety obligations (`ms_obligations.KIND_DIMENSIONS`,
    the committed rule the 25.3 plane records). The site is on the concurrency-relevant surface iff
    that set includes one of the closed concurrency dimensions. Pure over the committed rule, so the
    court re-derives exactly this.
    """
    dims = ms_obligations.KIND_DIMENSIONS.get(kind) or []
    return bool(set(dims) & set(CONCURRENCY_DIMENSIONS))


def surface_sites(census_body: dict) -> list[dict]:
    """The census sites on the concurrency-relevant surface, in census order."""
    return [s for s in census_body.get("sites") or []
            if kind_is_concurrency_relevant(str(s.get("operation_kind")))]


# --------------------------------------------------------------------------------------------
# the toolchain and the venue
# --------------------------------------------------------------------------------------------

def _commit(text: str) -> str:
    m = re.search(r"commit-hash:\s*([0-9a-f]+)", text)
    return m.group(1) if m else "unknown"


def toolchain() -> dict:
    """The exact pinned toolchain and the sanitizer runtimes the measurement used.

    `nightly_installed` is a fact, not a hope: if the pinned nightly (with `rust-src`) is absent the
    build cannot run and the plane records the crate-level unsupported case instead of a pass.
    """
    env = _tsan_env()
    rustc = _run(["rustc", "--version", "--verbose"], env=env, timeout=120).stdout
    clang = _run(["clang", "--version"], env=env, timeout=120).stdout
    sysroot = _run(["rustc", "--print", "sysroot"], env=env, timeout=120).stdout.strip()
    tsan_rt = Path(sysroot) / "lib" / "rustlib" / TARGET_TRIPLE / "lib" / "librustc-nightly_rt.tsan.a"
    clang_rt = _run(["clang", "-print-file-name=libclang_rt.tsan-x86_64.a"], env=env,
                    timeout=120).stdout.strip()
    installed = bool(rustc.strip()) and "nightly" in rustc
    llvm = ""
    m = re.search(r"LLVM version:\s*([0-9.]+)", rustc)
    if m:
        llvm = m.group(1)
    return {
        "nightly_channel": NIGHTLY,
        "rustc": rustc.splitlines()[0].strip() if rustc else "unavailable",
        "rustc_commit": _commit(rustc),
        "llvm": llvm or "unknown",
        "clang": clang.splitlines()[0].strip() if clang else "unavailable",
        "sanitizer": "TSAN",
        "tsan_runtime": rel(tsan_rt) if tsan_rt.is_file() else str(tsan_rt),
        "tsan_runtime_sha256": sha256_file(tsan_rt) if tsan_rt.is_file() else "absent",
        "clang_tsan_runtime": clang_rt or "absent",
        "clang_tsan_runtime_sha256": (sha256_file(Path(clang_rt))
                                      if clang_rt and Path(clang_rt).is_file() else "absent"),
        "target_triple": TARGET_TRIPLE,
        "profile": PROFILE,
        "rustflags": RUSTFLAGS,
        "cc_wrapper": "clang -fsanitize=thread -fno-omit-frame-pointer -g",
        "tsan_options": TSAN_OPTIONS,
        "schedule": list(SCHEDULE),
        "nightly_installed": installed,
        "toolchain_home": NIGHTLY_HOME,
        "note": ("the pinned nightly the 25.1 census and the 25.9 Miri runs share "
                 "(nightly-2026-10-01), so the census, Miri and TSan share one pinned date"),
    }


def venue() -> dict:
    """The environment the sanitizer ran in: a derivation of the admitted court venue.

    It records the admitted image and base from the committed manifest, and, honestly, the one
    dimension in which the sanitizer environment differs from the court's `exec`: the venue's
    documented per-process `RLIMIT_DATA` override, required because TSan's shadow is a
    MAP_NORESERVE virtual reservation. Every bound that bounds resident resources is unchanged.
    """
    man = phase25_guard.load_manifest()
    return {
        "admitted_image": str(man.get("image")),
        "canonical_base": str(man.get("canonical_base")),
        "platform": str(man.get("platform")),
        "kind": "reused-court-venue-with-documented-data-override",
        "environment": str(os.environ.get("PHASE25_IMAGE") or man.get("image")),
        "derived_from": str(man.get("image")),
        "data_limit_override": "OPENSSL_RS_COURT_DATA=unlimited",
        "cgroup_memory_cap": _cgroup_memory(),
        "measured_shadow_bytes": 35184372088832,
        "reason": (
            "TSan reserves a ~35.1 TB sparse shadow (PROT_NONE + MAP_NORESERVE) before it "
            "instruments anything (`ThreadSanitizer failed to allocate 0x200000000000 "
            "(35184372088832) bytes ... can not mmap the shadow memory`), which the court's "
            "per-process RLIMIT_DATA (4 GiB) refuses, so the instrument cannot start under the "
            "default `exec`; the venue's own OPENSSL_RS_COURT_DATA override removes only that "
            "virtual-space cap, exactly as the Phase-18 ASan venue and 25.10 record. The container "
            "cgroup memory cap, PIDs, CPUs and the wall clock are unchanged, so no bound on resident "
            "resources is weakened."),
        "note": ("a derived environment from the one admitted image, recorded rather than a second "
                 "mutable image; openssl-rs-court:1 is not modified"),
    }


def _cgroup_memory() -> str:
    try:
        cur = Path("/sys/fs/cgroup/memory.max").read_text(encoding="utf-8").strip()
        return cur
    except OSError:
        return "unknown"


# --------------------------------------------------------------------------------------------
# the canary: the instrument must be known to fire
# --------------------------------------------------------------------------------------------

def _canary_run(label: str, build_cmd: list[str], run_env: dict) -> dict:
    """Build and run one canary, returning whether it fired and whether the shadow mapped."""
    try:
        b = _run(build_cmd, env=_tsan_env(), timeout=CANARY_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"built": False, "detected": False, "shadow_mapped": False,
                "command": " ".join(build_cmd), "reason": "the canary build timed out"}
    blog = b.stdout + b.stderr
    if b.returncode != 0:
        return {"built": False, "detected": False, "shadow_mapped": False,
                "command": " ".join(build_cmd),
                "reason": (f"the canary failed to build (rc={b.returncode}): "
                           f"{_scrub_volatile(blog.strip()[-300:])}")}
    out = WORK / "bin" / label
    try:
        r = _run([str(out)], env=run_env, timeout=CANARY_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"built": True, "detected": False, "shadow_mapped": False,
                "command": " ".join(build_cmd), "reason": "the canary run timed out"}
    log = r.stdout + r.stderr
    detected = r.returncode != 0 and "ThreadSanitizer" in log and "data race" in log
    shadow_mapped = ("can not mmap the shadow memory" not in log
                     and "failed to allocate" not in log)
    diag = [_scrub_volatile(ln.strip()) for ln in log.splitlines()
            if "ThreadSanitizer" in ln or "SUMMARY" in ln or "data race" in ln
            or "can not mmap the shadow memory" in ln or "failed to allocate" in ln][:6]
    return {
        "built": True, "detected": detected, "shadow_mapped": shadow_mapped,
        "build_command": " ".join(build_cmd), "command": str(out), "exit_code": r.returncode,
        "diagnostic": diag, "log_sha256": sha256_bytes(_normalise_log(log).encode("utf-8")),
        "reason": "",
    }


def canary() -> dict:
    """Prove the instrument fires, with the *same* `-Zsanitizer=thread` the harness runs use.

    The primary canary is the committed Rust `tsan_canary.rs`, built by the pinned nightly with the
    exact instrument the crate is built with (and `-Cunsafe-allow-abi-mismatch=sanitizer`, because
    TSan changes the ABI a standalone probe would otherwise mix against a pre-built `std`); the
    committed C `tsan_canary.c` is run under gcc's libtsan as an independent cross-check. A
    no-race result is only trustworthy if the instrument is known to fire, and the canary also proves
    the TSan shadow can be mapped in this venue (the shadow failing to map is the venue-level
    unsupported case, not a pass).
    """
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "bin").mkdir(parents=True, exist_ok=True)

    rust_bin = WORK / "bin" / "tsan_canary_rs"
    rust_cmd = ["rustc", "--edition", "2021", "-Zsanitizer=thread", "-Cdebuginfo=1",
                "-Clinker=clang", CANARY_ABI_ALLOW, "-o", str(rust_bin), str(CANARY_RS)]
    rust = _canary_run("tsan_canary_rs", rust_cmd, _tsan_env({"TSAN_OPTIONS": TSAN_OPTIONS}))

    c_bin = WORK / "bin" / "tsan_canary"
    c_cmd = ["gcc", "-std=c11", "-O0", "-D_GNU_SOURCE", "-fsanitize=thread",
             "-fno-omit-frame-pointer", "-g", "-pthread", "-o", str(c_bin), str(CANARY_SRC)]
    c = _canary_run("tsan_canary", c_cmd, _tsan_env({"TSAN_OPTIONS": TSAN_OPTIONS}))

    built = bool(rust.get("built")) or bool(c.get("built"))
    detected = bool(rust.get("detected"))
    shadow_mapped = bool(rust.get("shadow_mapped"))
    reason = ""
    if not detected:
        reason = (str(rust.get("reason") or "")
                  or "the Rust TSan canary did not diagnose the deliberate data race")
    if not shadow_mapped and rust.get("built"):
        reason = ("TSan's shadow could not be mapped: the venue's per-process RLIMIT_DATA is still in "
                  "force (run the measurement with OPENSSL_RS_COURT_DATA=unlimited, the venue's own "
                  "documented override)")
    return {
        "instrument": "-Zsanitizer=thread (rustc) -- the same instrument the harness runs use",
        "built": built,
        "detected": detected,
        "shadow_mapped": shadow_mapped,
        "as_expected": "nonzero exit with a ThreadSanitizer 'data race' report",
        "rust": rust,
        "c": c,
        "reason": reason,
    }


# --------------------------------------------------------------------------------------------
# building and running the instrumented candidate
# --------------------------------------------------------------------------------------------

def write_cc_wrapper() -> None:
    (WORK / "bin").mkdir(parents=True, exist_ok=True)
    CC_WRAPPER.write_text(
        "#!/bin/sh\n"
        "# openssl-rs TSan venue: every C compilation (build.rs adapters) is instrumented.\n"
        'exec clang -fsanitize=thread -fno-omit-frame-pointer -g "$@"\n',
        encoding="utf-8")
    CC_WRAPPER.chmod(0o755)


def fresh_target() -> None:
    """Remove the instrumented target directory so every `--measure` builds from scratch.

    `--measure` is byte-for-byte reproducible only if the instrumented binary and the build transcript
    are a function of the committed inputs rather than of whether a previous run left a warm target
    directory behind (a warm `cargo` build prints no `Compiling` lines, a cold one does). The pinned
    nightly and the cargo registry under `/work` are never removed; only this stratum's scratch target
    directory is.
    """
    if TARGET_DIR.exists():
        shutil.rmtree(TARGET_DIR, ignore_errors=True)


def _build_command() -> list[str]:
    return ["cargo", "test", "-Zbuild-std", "--lib", "--target", TARGET_TRIPLE, "--no-run"]


def build_instrumented(tc: dict) -> dict:
    """Build the TSan-instrumented test binary once and produce an instrumentation-closure receipt."""
    write_cc_wrapper()
    cmd = _build_command()
    display = f"RUSTFLAGS='{RUSTFLAGS}' CC={CC_WRAPPER} " + " ".join(cmd)
    if not tc.get("nightly_installed"):
        return {"state": "UNSUPPORTED", "reason": f"the pinned nightly ({NIGHTLY}) is not installed",
                "command": display, "command_sha256": sha256_bytes(display.encode()),
                "test_binary": "", "test_binary_sha256": "unknown", "tsan_refs": 0}
    try:
        res = _run(cmd, env=_tsan_env(), timeout=BUILD_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"state": "UNSUPPORTED", "reason": f"the instrumented build exceeded {BUILD_TIMEOUT}s",
                "command": display, "command_sha256": sha256_bytes(display.encode()),
                "test_binary": "", "test_binary_sha256": "unknown", "tsan_refs": 0}
    log = res.stdout + res.stderr
    (WORK / "build.log").write_text(log, encoding="utf-8")
    m = re.search(r"Executable unittests [^\n]*\(([^)]+)\)", log)
    binary = ""
    if m:
        p = Path(m.group(1).strip())
        binary = str(p if p.is_absolute() else (REPO_ROOT / p))
    if res.returncode != 0 or not binary or not Path(binary).is_file():
        tail = "\n".join(_scrub_volatile(ln) for ln in log.splitlines()[-24:])
        return {"state": "UNSUPPORTED",
                "reason": (f"the TSan-instrumented test binary did not build (rc={res.returncode}); "
                           f"{'no executable was named by cargo' if not binary else 'the named path is absent'}"),
                "command": display, "command_sha256": sha256_bytes(display.encode()),
                "test_binary": binary, "test_binary_sha256": "unknown", "tsan_refs": 0,
                "log_sha256": sha256_bytes(_normalise_log(log).encode()),
                "tail": tail}
    bp = Path(binary)
    nm = _run(["nm", str(bp)], env=_tsan_env(), timeout=300)
    tsan_refs = sum(1 for ln in (nm.stdout + nm.stderr).splitlines() if "__tsan" in ln)
    return {
        "state": "BUILT",
        "reason": "",
        "command": display,
        "command_sha256": sha256_bytes(display.encode()),
        "test_binary": rel(bp) if str(bp).startswith(str(REPO_ROOT)) else str(bp),
        "test_binary_sha256": sha256_file(bp),
        "test_binary_bytes": bp.stat().st_size,
        "tsan_refs": tsan_refs,
        "log_sha256": sha256_bytes(_normalise_log(log).encode()),
        "closure": ("the Rust crate and `std` are rebuilt with -Zbuild-std under -Zsanitizer=thread; "
                    "the first-party C adapters the crate's build.rs compiles go through a CC wrapper "
                    "that appends -fsanitize=thread; libc is runtime-intercepted, which is the "
                    "designed closure"),
    }


def run_harness(harness: dict, tc: dict, tsan_runnable: bool) -> dict:
    """Run one harness and parse its transcript into a run record with an honest outcome."""
    cmd = ["cargo", "test", "-Zbuild-std", "--lib", "--target", TARGET_TRIPLE, "--"]
    cmd.extend(SCHEDULE)
    if harness.get("filter"):
        cmd.append(str(harness["filter"]))
    display = f"TSAN_OPTIONS={TSAN_OPTIONS} RUSTFLAGS='{RUSTFLAGS}' " + " ".join(cmd)
    base = {
        "run_id": harness["harness_id"],
        "harness_id": harness["harness_id"],
        "description": harness["description"],
        "filter": harness.get("filter"),
        "schedule": list(SCHEDULE),
        "command": display,
        "command_sha256": sha256_bytes(display.encode("utf-8")),
        "unsupported_files": [],
        "error_sites": [],
        "tests": [],
    }
    if not tc.get("nightly_installed"):
        return dict(base, outcome="UNSUPPORTED",
                    unsupported_reason=f"the pinned nightly ({NIGHTLY}) is not installed",
                    transcript_sha256="unknown", tests_run=0, tests_passed=0, tests_failed=0,
                    bound_to={})
    if not tsan_runnable:
        return dict(base, outcome="UNSUPPORTED",
                    unsupported_reason=REASON_VENUE, transcript_sha256="unknown",
                    tests_run=0, tests_passed=0, tests_failed=0, bound_to={})
    WORK.mkdir(parents=True, exist_ok=True)
    try:
        res = _run(cmd, env=_tsan_env(), timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return dict(base, outcome="UNSUPPORTED",
                    unsupported_reason=f"the harness exceeded {RUN_TIMEOUT}s",
                    transcript_sha256="unknown", tests_run=0, tests_passed=0, tests_failed=0,
                    bound_to={})
    log = res.stdout + res.stderr
    (WORK / f"{harness['harness_id']}.log").write_text(log, encoding="utf-8")

    tests: list[dict] = []
    for line in log.splitlines():
        m = _RESULT.match(line.strip())
        if m:
            tests.append({"name": m.group("name"), "status": m.group("status")})
    # libtest schedules tests in a nondeterministic order; the executed set is the evidence, so the
    # list is sorted by name rather than recorded in the order this run happened to execute.
    tests.sort(key=lambda t: t["name"])

    error_sites: list[dict] = []
    unsupported_reason = ""
    tsan_err = _TSAN_ERROR.search(log)
    if tsan_err is not None and _UNEXPECTED_MAPPING not in (tsan_err.group("kind") or ""):
        outcome = "FAIL"
        # Every crate frame the report names is implicated; the first is the primary location.
        seen: set[tuple] = set()
        for m in _FRAME.finditer(log):
            f = m.group(1)
            if f.startswith("src/"):
                key = (f, int(m.group("line")), int(m.group("col") or 0))
                if key not in seen:
                    seen.add(key)
                    error_sites.append({"file": f, "line": key[1], "column": key[2],
                                        "class": tsan_err.group("kind")})
    elif res.returncode == 0:
        outcome = "PASS"
    else:
        outcome = "FAIL"
    return dict(base,
                outcome=outcome,
                unsupported_reason=unsupported_reason,
                unsupported_files=[],
                transcript_sha256=sha256_bytes(_normalise_log(log).encode("utf-8")),
                tests_run=len(tests),
                tests_passed=sum(1 for t in tests if t["status"] == "ok"),
                tests_failed=sum(1 for t in tests if t["status"] == "FAILED"),
                tests=tests,
                error_sites=error_sites,
                bound_to={f: sha256_file(REPO_ROOT / f) for f in (harness.get("bound_files") or ())})


# --------------------------------------------------------------------------------------------
# coverage: the files a passing harness executed
# --------------------------------------------------------------------------------------------

def _test_file(name: str, root: Path) -> str | None:
    """The source file a libtest test name lives in, by the longest existing module prefix.

    `runtime::thread::tests::foo` -> `src/runtime/thread.rs` (the inline `tests` module lives in that
    file); `digest::sha2::tests::foo` -> `src/digest/sha2.rs`. Pure over the on-disk tree, so the
    court re-derives it.
    """
    parts = name.split("::")
    for k in range(len(parts), 0, -1):
        p = "/".join(parts[:k])
        for cand in (f"src/{p}.rs", f"src/{p}/mod.rs"):
            if (root / cand).is_file():
                return cand
    return None


def _source_refs(source_rel: str | None, root: Path) -> set[str]:
    """The modules a harness source file calls into, from its `crate::` references."""
    if not source_rel:
        return set()
    text = _read(root / source_rel)
    files = {source_rel}
    for m in _MODREF.finditer(text):
        p = m.group(1).replace("::", "/")
        for cand in (f"src/{p}.rs", f"src/{p}/mod.rs"):
            if (root / cand).is_file():
                files.add(cand)
    return files


def coverage_files(run: dict, root: Path) -> list[str]:
    """The files a passing harness executed: the files its tests live in, plus the modules its source
    calls into. This is the finest coverage TSan's run record exposes; it is file-granular, never a
    per-operation claim."""
    hid = str(run.get("harness_id") or run.get("run_id"))
    h = next((x for x in HARNESSES if x["harness_id"] == hid), None)
    files: set[str] = set()
    for t in run.get("tests") or []:
        if t.get("status") == "ok":
            f = _test_file(str(t.get("name")), root)
            if f:
                files.add(f)
    if h is not None:
        files |= _source_refs(h.get("source"), root)
    return sorted(files)


def _attribute(sites: list[dict], file: str, line: int) -> list[str]:
    """The census site ids a TSan error location is attributed to (nearest line at or before it)."""
    same = [s for s in sites if str(s.get("file")) == file]
    on_line = [s for s in same if int(s.get("line") or 0) == line]
    if on_line:
        return [str(s.get("site_id")) for s in on_line]
    before = [s for s in same if int(s.get("line") or 0) <= line]
    if not before:
        return []
    near = max(int(s.get("line") or 0) for s in before)
    return [str(s.get("site_id")) for s in before if int(s.get("line") or 0) == near]


def _crate_reason_code(tc: dict, can: dict) -> str:
    """The closed reason a surface site carries when the TSan question is not expressible."""
    if not tc.get("nightly_installed"):
        return REASON_VENUE
    if not can.get("built") or not can.get("shadow_mapped"):
        return REASON_VENUE
    if not can.get("detected"):
        return REASON_POSITIVE_CONTROL
    return ""


def derived_states(census_body: dict, runs: list[dict], crate_ran: bool, reason: str,
                   root: Path) -> dict[str, dict]:
    """The TSan state of every surface census site, derived purely from the runs, the census and the
    tree.

    Pure over its inputs: the court re-derives exactly this from the committed artefact's runs, the
    committed census and the committed harness sources, and refuses a committed `.sites` that differs.
    """
    sites = surface_sites(census_body)

    fail_sites: dict[str, str] = {}
    for r in runs:
        if r.get("outcome") != "FAIL":
            continue
        for es in r.get("error_sites") or []:
            for sid in _attribute(sites, str(es.get("file")), int(es.get("line") or 0)):
                fail_sites[sid] = str(r.get("run_id"))

    pass_files: dict[str, str] = {}
    if crate_ran:
        for r in runs:
            if r.get("outcome") != "PASS":
                continue
            for f in coverage_files(r, root):
                pass_files.setdefault(f, str(r.get("run_id")))

    observed = set()
    for r in runs:
        observed.update(str(f) for f in (r.get("unsupported_files") or []))
    unsupported_files = set(UNSUPPORTED_FILES) | observed

    out: dict[str, dict] = {}
    for s in sites:
        sid = str(s.get("site_id"))
        f = str(s.get("file"))
        kind = str(s.get("operation_kind"))
        if not crate_ran:
            out[sid] = {"state": "TSAN_UNSUPPORTED", "run": "", "reason": reason or REASON_VENUE}
        elif sid in fail_sites:
            out[sid] = {"state": "TSAN_FAIL", "run": fail_sites[sid], "reason": ""}
        elif kind in TSAN_INEXECUTABLE_KINDS:
            out[sid] = {"state": "TSAN_UNSUPPORTED", "run": "", "reason": REASON_OPAQUE}
        elif f in unsupported_files:
            out[sid] = {"state": "TSAN_UNSUPPORTED", "run": "", "reason": REASON_FOREIGN_MODULE}
        elif f in pass_files:
            out[sid] = {"state": "TSAN_PASS", "run": pass_files[f], "reason": ""}
        else:
            out[sid] = {"state": "TSAN_NOT_REACHABLE", "run": "", "reason": REASON_NOT_EXECUTED}
    return out


def _counts(states: dict[str, dict]) -> dict:
    c = Counter(v["state"] for v in states.values())
    return {
        "sites": len(states),
        "pass": c.get("TSAN_PASS", 0),
        "fail": c.get("TSAN_FAIL", 0),
        "not_reachable": c.get("TSAN_NOT_REACHABLE", 0),
        "unsupported": c.get("TSAN_UNSUPPORTED", 0),
    }


# --------------------------------------------------------------------------------------------
# findings, results, residuals and the rule
# --------------------------------------------------------------------------------------------

def _findings(runs: list[dict]) -> list[dict]:
    """Every TSan finding, preserved. A failing run that reported a data race is a finding; a failing
    harness is never discarded."""
    findings: list[dict] = []
    for r in runs:
        if r.get("outcome") != "FAIL":
            continue
        sites = r.get("error_sites") or []
        if not sites:
            findings.append({
                "finding_id": f"tf-{r['run_id']}",
                "run_id": r["run_id"],
                "category": "TSAN_HARNESS_FAILURE",
                "file": "",
                "line": 0,
                "column": 0,
                "detail": (f"run {r['run_id']} failed without a ThreadSanitizer data-race report "
                           f"({r.get('tests_failed', 0)} of {r.get('tests_run', 0)} test(s) failed); "
                           f"it is not a concurrency finding"),
            })
            continue
        prim = sites[0]
        context = sites[1:]
        findings.append({
            "finding_id": f"tf-{r['run_id']}",
            "run_id": r["run_id"],
            "category": f"TSAN_{str(prim.get('class', 'error')).upper().replace(' ', '_').replace('-', '_')}",
            "file": prim.get("file"),
            "line": prim.get("line"),
            "column": prim.get("column"),
            "context": context,
            "detail": (f"run {r['run_id']} reported a ThreadSanitizer data race at this location "
                       f"under the recorded schedule; the report context is recorded in `context` "
                       f"and the run transcript is preserved"),
        })
    return findings


def _results(runs: list[dict]) -> list[dict]:
    """The sanitizer_result records the schema validates: one per TSan run."""
    out: list[dict] = []
    for r in runs:
        st = {"PASS": "PASS", "FAIL": "FAIL", "UNSUPPORTED": "UNSUPPORTED"}.get(str(r.get("outcome")),
                                                                              "UNSUPPORTED")
        out.append({
            "result_id": f"tsan-{r['run_id']}",
            "sanitizer": "TSAN",
            "target": str(r.get("description")),
            "tool_state": st,
            # TSan observes only the recorded schedule, so a PASS is a file-granular claim under that
            # schedule, stated explicitly rather than left to the reader of `pass_semantics`.
            "coverage_granularity": "file",
            "findings": [f"tf-{r['run_id']}"] if r.get("outcome") == "FAIL" else [],
            "unsupported_reason": str(r.get("unsupported_reason") or ""),
            "evidence": [rel(OUT), rel(TOOL), rel(CENSUS)],
        })
    return out


def _residuals(states: dict[str, dict], counts: dict, runs: list[dict]) -> list[dict]:
    residuals: list[dict] = []
    residuals.append({
        "residual_id": "res-tsan-schedule-bound",
        "subject": "the TSan runs use a recorded deterministic one-thread schedule",
        "class": "evidence_missing",
        "disposition": "preserved",
        "detail": ("the runs pin the libtest schedule to one thread (`--test-threads=1`), which "
                   "docs/CONCURRENCY_MODEL.md section 6 sanctions for reproducibility and which makes "
                   "the executed set and the observation a function of the committed candidate; the "
                   "bound is that a race the crate's own thread tests did not exercise under that "
                   "schedule is not read as absent, and every run records its schedule"),
        "evidence": [rel(TOOL), rel(PLAN)],
    })
    residuals.append({
        "residual_id": "res-tsan-coverage-granularity",
        "subject": "TSAN_PASS coverage granularity",
        "class": "evidence_missing",
        "disposition": "preserved",
        "detail": ("TSAN_PASS is file-granular: the site is in a file a passing run executed. TSan "
                   "exposes no per-operation execution trace, so a PASS is not a per-site proof that "
                   "the specific operation executed concurrently"),
        "evidence": [rel(TOOL), rel(CENSUS)],
    })
    residuals.append({
        "residual_id": "res-tsan-not-reachable",
        "subject": f"{counts['not_reachable']} TSAN_NOT_REACHABLE site(s)",
        "class": "tool_not_reachable",
        "disposition": "preserved",
        "detail": (f"{counts['not_reachable']} surface site(s) are TSAN_NOT_REACHABLE: no committed "
                   f"harness executed their file. This is not a clean result"),
        "evidence": [rel(CENSUS)],
    })
    residuals.append({
        "residual_id": "res-tsan-unsupported",
        "subject": f"{counts['unsupported']} TSAN_UNSUPPORTED site(s)",
        "class": "tool_unsupported",
        "disposition": "preserved",
        "detail": (f"{counts['unsupported']} surface site(s) are TSAN_UNSUPPORTED. TSan instruments "
                   f"the Rust crate, `std` (rebuilt with -Zbuild-std), the first-party C adapters and "
                   f"the interceptable libc; it cannot instrument a module resolved and loaded at run "
                   f"time (`src/dso/dlfcn.rs`) or see through opaque operations. An unsupported site "
                   f"is not a passing site"),
        "evidence": [rel(TOOL), rel(CENSUS)],
    })
    residuals.append({
        "residual_id": "res-tsan-venue-data-override",
        "subject": "the TSan venue removes only the venue's per-process RLIMIT_DATA",
        "class": "evidence_missing",
        "disposition": "preserved",
        "detail": ("TSan's shadow is a ~35.1 TB PROT_NONE + MAP_NORESERVE virtual reservation, so the "
                   "sanitizer environment is the admitted court image with the venue's documented "
                   "OPENSSL_RS_COURT_DATA override; the container cgroup memory cap, PIDs, CPUs and "
                   "the wall clock are unchanged. Under the *default* court `exec` the instrument "
                   "cannot start, and the crate-level state records that as UNSUPPORTED"),
        "evidence": [rel(MANIFEST), rel(TOOL)],
    })
    if any(r.get("outcome") == "PASS" for r in runs):
        residuals.append({
            "residual_id": "res-tsan-canary",
            "subject": "the TSan canary fires in this venue",
            "class": "evidence_missing",
            "disposition": "preserved",
            "detail": ("a no-race result is trusted only because the deliberate data-race canary is "
                       "diagnosed with a nonzero exit; the canary proves the instrument can fire "
                       "here, not that the candidate is race-free"),
            "evidence": [rel(CANARY_SRC), rel(TOOL)],
        })
    return residuals


def _rule(tc: dict, ven: dict, crate_ran: bool, reason: str) -> dict:
    return {
        "authority": {
            "kind": "committed-phase25-planes",
            "paths": [rel(CENSUS), rel(PLAN), rel(SCHEMAS), rel(TOOL), rel(MANIFEST),
                      rel(CANARY_SRC), rel(OBLIGATIONS), rel(MS_OBLIGATIONS_TOOL)],
            "declaration": (
                "the committed 25.1 census is the compiler-derived primary unit; the committed 25.3 "
                "obligation rule (ms_obligations.KIND_DIMENSIONS) defines the concurrency-relevant "
                "surface; the committed venue manifest names the admitted image and base the TSan "
                "environment is derived from; the harness sources named in HARNESSES define the "
                "coverage of a passing run -- a site is never derived from a text scan"),
        },
        "harnesses": [str(h["harness_id"]) for h in HARNESSES],
        "schedule": list(SCHEDULE),
        "site_states": list(SITE_STATES),
        "concurrency_dimensions": list(CONCURRENCY_DIMENSIONS),
        "inexecutable_kinds": list(TSAN_INEXECUTABLE_KINDS),
        "unsupported_files": list(UNSUPPORTED_FILES),
        "surface_rule": ("a census site is on the concurrency-relevant surface iff the site's "
                         "operation kind requires one of THREAD_AFFINITY, SEND_SYNC or INIT_ONCE in "
                         "the committed ms_obligations.KIND_DIMENSIONS rule; the plane carries one "
                         "state per surface site and restates no other census site"),
        "pass_rule": ("TSAN_PASS iff the site's file is covered by a passing TSan run (a file an "
                      "executed test lives in, or a module the harness source calls into) and its "
                      "operation is not an opaque/foreign boundary; the site cites the run id and the "
                      "run's command hash"),
        "fail_rule": ("TSAN_FAIL iff a run reported a ThreadSanitizer data race at the site's "
                      "(file, line); the site cites the run id"),
        "unsupported_rule": ("TSAN_UNSUPPORTED iff the site is on the committed foreign/uninstrumented "
                             "surface or is an opaque operation TSan cannot see through, or the venue "
                             "could not run the instrument, or the positive control did not fire; the "
                             "reason is recorded"),
        "not_reachable_rule": ("TSAN_NOT_REACHABLE iff no committed harness executed the site's file; "
                               "it is not a clean result"),
        "venue_rule": (
            "the TSan environment is the admitted court image executed with the venue's documented "
            "OPENSSL_RS_COURT_DATA override, which removes only the per-process RLIMIT_DATA that would "
            "refuse TSan's ~35.1 TB MAP_NORESERVE shadow; the container cgroup memory cap, PIDs, CPUs "
            "and the wall clock are unchanged"),
        "crate_level": {
            "state": "TSAN_RAN" if crate_ran else "TSAN_UNSUPPORTED",
            "reason": ("" if crate_ran
                       else (reason or tc.get("_crate_reason") or
                             "the TSan instrument did not run in this venue; see the venue and "
                             "canary records")),
        },
        "venue": ven,
    }


def build_body(census_body: dict, runs: list[dict], tc: dict, ven: dict, can: dict,
               build: dict, crate_ran: bool, reason: str, root: Path) -> dict:
    states = derived_states(census_body, runs, crate_ran, reason, root)
    counts = _counts(states)
    findings = _findings(runs)
    return {
        "rule": _rule(tc, ven, crate_ran, reason),
        "pass_semantics": PASS_SEMANTICS,
        "toolchain": tc,
        "venue": ven,
        "instrumentation": build,
        "canary": can,
        "runs": runs,
        "sites": states,
        "counts": counts,
        "findings": findings,
        "results": _results(runs),
        "residuals": _residuals(states, counts, runs),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def tsan_findings(body: dict, census_body: dict, root: Path | None = None) -> list[str]:
    """Every way the committed TSan plane contradicts the census, the runs or the harness sources.

    Pure over `body` and the committed census: it re-derives the surface and the per-site states and
    refuses a committed `.sites` that differs; it refuses a site with no state, an `UNSUPPORTED` site
    with no reason, a `PASS` that cites no real passing run covering its file, a `FAIL` that cites no
    failing run, a run whose outcome/command hash is malformed, a `FAIL` run with no finding, a
    dropped result, a typed count, a rule that does not name its committed authority, and a `PASS`
    recorded while the positive control did not fire.
    """
    root = root or REPO_ROOT
    problems: list[str] = []
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)

    runs = body.get("runs") or []
    runs_by_id = {str(r.get("run_id")): r for r in runs}
    surface_site_recs = surface_sites(census_body)
    surface_ids = [str(s.get("site_id")) for s in surface_site_recs]
    census_file_of = {str(s.get("site_id")): str(s.get("file")) for s in surface_site_recs}
    if len(set(surface_ids)) != len(surface_ids):
        problems.append("the census carries a duplicate surface site_id, so a state is ambiguous")

    cl = (body.get("rule") or {}).get("crate_level") or {}
    crate_ran = cl.get("state") == "TSAN_RAN"

    # 0. The runs validate.
    for r in runs:
        rid = str(r.get("run_id"))
        if r.get("outcome") not in schemas.TOOL_STATES:
            problems.append(f"run {rid} has an unknown outcome {r.get('outcome')!r}")
        ch = str(r.get("command_sha256") or "")
        if len(ch) != 64 or any(c not in "0123456789abcdef" for c in ch):
            problems.append(f"run {rid} does not carry a sha256 command hash")
        if r.get("outcome") == "UNSUPPORTED" and not r.get("unsupported_reason"):
            problems.append(f"run {rid} is UNSUPPORTED with an empty reason")
        if list(r.get("schedule") or []) != list(SCHEDULE):
            problems.append(f"run {rid} does not record the committed schedule {list(SCHEDULE)}")

    # 1. The derived states are the committed states, with a specific message per disagreement.
    reason = _crate_reason_code(body.get("toolchain") or {}, body.get("canary") or {})
    derived = derived_states(census_body, runs, crate_ran, reason, root)
    committed = body.get("sites") or {}
    for sid in surface_ids:
        want = derived.get(sid)
        got = committed.get(sid)
        if got is None:
            problems.append(f"surface site {sid} has no TSan state; a surface site is never dropped")
            continue
        ws, gs = want["state"], got.get("state")
        if ws == gs:
            continue
        if ws == "TSAN_UNSUPPORTED" and gs == "TSAN_PASS":
            problems.append(f"site {sid} records TSAN_PASS for a site the derivation marks "
                            f"UNSUPPORTED; UNSUPPORTED is not PASS")
        elif ws == "TSAN_FAIL" and gs == "TSAN_PASS":
            problems.append(f"site {sid} records TSAN_PASS but the derivation marks it TSAN_FAIL; a "
                            f"PASS with a finding at it is refused")
        elif gs == "TSAN_PASS":
            problems.append(f"site {sid} claims TSAN_PASS but the derivation marks it {ws}; a coverage "
                            f"claim with no covering run is refused")
        else:
            problems.append(f"site {sid}: committed state {gs} != derived {ws}")
    extra = set(committed) - set(surface_ids)
    if extra:
        problems.append(f"the TSan plane carries {len(extra)} site(s) not on the concurrency-relevant "
                        f"surface")

    # 2. Every state is closed; UNSUPPORTED carries a reason.
    for sid, rec in committed.items():
        st = rec.get("state")
        if st not in SITE_STATES:
            problems.append(f"site {sid} has an unknown state {st!r}")
        if st == "TSAN_UNSUPPORTED" and not rec.get("reason"):
            problems.append(f"site {sid} is TSAN_UNSUPPORTED but records no reason; refusing to say "
                            f"why is refusing the evidence")

    # 3. A PASS cites a real run that passed and covers the site's file; a FAIL cites a failing run.
    coverage_by_run = {str(r.get("run_id")): coverage_files(r, root)
                      for r in runs if r.get("outcome") == "PASS"}
    for sid, rec in committed.items():
        st = rec.get("state")
        if st == "TSAN_PASS":
            rid = str(rec.get("run") or "")
            run = runs_by_id.get(rid)
            if run is None:
                problems.append(f"TSAN_PASS site {sid} cites no run ({rid!r})")
            elif run.get("outcome") != "PASS":
                problems.append(f"TSAN_PASS site {sid} cites run {rid}, whose outcome is "
                                f"{run.get('outcome')}")
            else:
                f = census_file_of.get(sid, "")
                if f not in coverage_by_run.get(rid, []):
                    problems.append(f"TSAN_PASS site {sid} cites run {rid}, which does not cover its "
                                    f"file {f}")
        elif st == "TSAN_FAIL":
            rid = str(rec.get("run") or "")
            run = runs_by_id.get(rid)
            if run is None:
                problems.append(f"TSAN_FAIL site {sid} cites no run ({rid!r})")
            elif run.get("outcome") != "FAIL":
                problems.append(f"TSAN_FAIL site {sid} cites run {rid}, whose outcome is "
                                f"{run.get('outcome')}")

    # 4. Every FAIL run's error site has a finding (a finding is never dropped).
    findings = body.get("findings") or []
    finding_runs = {str(f.get("run_id")) for f in findings}
    for r in runs:
        if r.get("outcome") == "FAIL":
            if str(r.get("run_id")) not in finding_runs:
                problems.append(f"run {r.get('run_id')} failed but no finding records it; a TSan "
                                f"finding is preserved, never dropped")
    for f in findings:
        if str(f.get("run_id")) not in runs_by_id:
            problems.append(f"finding {f.get('finding_id')} cites run {f.get('run_id')!r}, which is "
                            f"not a committed run")

    # 5. The counts are derived, not typed.
    if body.get("counts") != _counts(derived):
        problems.append("the committed `counts` is not the derived `counts`")

    # 6. The toolchain, the venue, the canary and the positive control are recorded.
    tcv = body.get("toolchain") or {}
    if not tcv.get("nightly_channel") or not tcv.get("rustc"):
        problems.append("the TSan toolchain is not recorded")
    if list(tcv.get("schedule") or []) != list(SCHEDULE):
        problems.append("the TSan toolchain does not record the committed schedule")
    venv = body.get("venue") or {}
    for key in ("admitted_image", "canonical_base", "data_limit_override"):
        if not venv.get(key):
            problems.append(f"the TSan venue does not record {key}")
    can = body.get("canary") or {}
    if not can.get("built"):
        problems.append("the TSan canary is not recorded as built; a no-race result is trusted only "
                        "if the instrument is known to fire")
    elif crate_ran and not can.get("detected"):
        problems.append("the crate-level state is TSAN_RAN but the positive control did not fire")
    if cl.get("state") not in ("TSAN_RAN", "TSAN_UNSUPPORTED"):
        problems.append("the crate-level TSan case is not recorded")
    if cl.get("state") == "TSAN_UNSUPPORTED" and not cl.get("reason"):
        problems.append("the crate-level TSan case is TSAN_UNSUPPORTED but carries no reason")
    if not crate_ran:
        for sid, rec in committed.items():
            if rec.get("state") == "TSAN_PASS":
                problems.append(f"site {sid} records TSAN_PASS but the crate-level TSan case is "
                                f"UNSUPPORTED; a PASS requires the instrument to be known to fire")

    # 7. The sanitizer_result records validate, and every TSan result states its coverage granularity.
    results = body.get("results") or []
    for r in results:
        problems += [f"result[{r.get('result_id')}]: {p}"
                     for p in schemas.validate("sanitizer_result", r)]
    if not results:
        problems.append("the plane carries no sanitizer_result record")
    for r in results:
        if str(r.get("sanitizer")) != "TSAN":
            problems.append(f"result {r.get('result_id')} is not a TSAN sanitizer result")
        if r.get("coverage_granularity") != "file":
            problems.append(f"TSan result {r.get('result_id')} does not record its coverage "
                            f"granularity (`file`)")
    if not str(body.get("pass_semantics") or "").strip():
        problems.append("the plane does not carry its top-level `pass_semantics` statement")

    # 8. The rule names its committed authority and the required non-claims are present.
    rule = body.get("rule") or {}
    paths = (rule.get("authority") or {}).get("paths") or []
    for want in (rel(CENSUS), rel(PLAN), rel(OBLIGATIONS), rel(MS_OBLIGATIONS_TOOL)):
        if want not in paths:
            problems.append(f"the TSan rule does not name its committed authority {want}")
    if list(rule.get("concurrency_dimensions") or []) != list(CONCURRENCY_DIMENSIONS):
        problems.append("the TSan rule does not record the concurrency dimensions")
    if not str(rule.get("surface_rule") or "").strip():
        problems.append("the TSan rule does not record how the surface is derived")
    ncs = body.get("non_claims") or []
    if not any("UNSUPPORTED" in nc and "not a passing site" in nc for nc in ncs):
        problems.append("the plane does not carry the required unsupported-is-not-pass non-claim")
    if not any("schedule" in nc for nc in ncs):
        problems.append("the plane does not carry the schedule-dependence non-claim")

    # 9. Every residual validates against the residual schema.
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}"
                     for p in schemas.validate("residual", r)]

    return problems


def tsan_sensitivity_control(body: dict, census_body: dict, root: Path | None = None) -> dict:
    """Seed the mutations and require each caught, with specificity holding.

    Each is a distinct way the plane could lie: a site marked PASS without the covering run executed;
    a site marked PASS with a finding at it; a dropped site; an UNSUPPORTED site marked PASS; a typed
    count; a run that is UNSUPPORTED with no reason; and a PASS recorded while the positive control
    did not fire.
    """
    root = root or REPO_ROOT
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    baseline = tsan_findings(body, census_body, root)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = tsan_findings(mutated, census_body, root)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    def clone() -> dict:
        return json.loads(json.dumps(body))

    committed = body.get("sites") or {}
    surface_site_recs = surface_sites(census_body)
    census_file_of = {str(s.get("site_id")): str(s.get("file")) for s in surface_site_recs}
    pass_sid = next((s for s, r in committed.items() if r.get("state") == "TSAN_PASS"), None)
    unsup_sid = next((s for s, r in committed.items() if r.get("state") == "TSAN_UNSUPPORTED"), None)
    any_run = str((body.get("runs") or [{}])[0].get("run_id"))

    # m1: a PASS with no run.
    def pass_without_run() -> dict:
        b = clone()
        b["sites"][pass_sid] = {"state": "TSAN_PASS", "run": "", "reason": ""}
        return b

    m1 = check("pass_without_run", pass_without_run(), "cites no run")

    # m2: a PASS with a finding at it -- a FAIL run is added at the PASS site's location while the site
    #     still claims PASS; the derivation must mark it FAIL and refuse the PASS.
    def pass_with_finding() -> dict:
        b = clone()
        src = next((s for s in surface_site_recs if str(s.get("site_id")) == pass_sid), {})
        f = census_file_of.get(str(pass_sid), "")
        b["runs"].append({
            "run_id": "mutant-fail", "harness_id": "mutant-fail", "description": "mutant",
            "filter": None, "schedule": list(SCHEDULE), "command": "mutant",
            "command_sha256": "f" * 64, "outcome": "FAIL", "unsupported_reason": "",
            "transcript_sha256": "0" * 64, "tests_run": 1, "tests_passed": 0, "tests_failed": 1,
            "tests": [], "unsupported_files": [],
            "error_sites": [{"file": f, "line": int(src.get("line") or 1), "column": 1,
                             "class": "data race"}],
            "bound_to": {},
        })
        b["findings"] = list(b.get("findings") or []) + [{
            "finding_id": "tf-mutant-fail", "run_id": "mutant-fail", "category": "TSAN_DATA_RACE",
            "file": f, "line": int(src.get("line") or 1), "column": 1, "detail": "mutant"}]
        return b

    m2 = check("pass_with_finding", pass_with_finding(), "PASS with a finding at it is refused")

    # m3: a dropped site.
    def dropped_site() -> dict:
        b = clone()
        b["sites"].pop(pass_sid, None)
        return b

    m3 = check("dropped_site", dropped_site(), "has no TSan state")

    # m4: an UNSUPPORTED site marked PASS.
    def unsupported_marked_pass() -> dict:
        b = clone()
        b["sites"][unsup_sid] = {"state": "TSAN_PASS", "run": any_run, "reason": ""}
        return b

    m4 = check("unsupported_marked_pass", unsupported_marked_pass(), "UNSUPPORTED is not PASS")

    # m5: a typed count.
    def typed_count() -> dict:
        b = clone()
        b["counts"]["pass"] += 1
        return b

    m5 = check("typed_count", typed_count(), "not the derived `counts`")

    # m6: a run that is UNSUPPORTED with no reason.
    def unsupported_without_reason() -> dict:
        b = clone()
        b["runs"][0]["outcome"] = "UNSUPPORTED"
        b["runs"][0]["unsupported_reason"] = ""
        return b

    m6 = check("unsupported_without_reason", unsupported_without_reason(), "UNSUPPORTED with an empty "
                                                                          "reason")

    # m7: a PASS recorded while the positive control did not fire -- refused because a no-race result
    #     is trusted only if the instrument is known to detect a race.
    def pass_without_positive_control() -> dict:
        b = clone()
        b["canary"]["detected"] = False
        return b

    m7 = check("pass_without_positive_control", pass_without_positive_control(),
               "positive control did not fire")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and m7 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_census() -> tuple[dict, list[dict]]:
    """A tiny, self-consistent census and run set: two covered surface sites, a foreign-surface site,
    an uncovered surface site and a non-surface site."""
    census = {"sites": [
        {"site_id": "us-impl-1", "file": "src/aes.rs", "line": 70, "column": 9,
         "operation_kind": "UNSAFE_IMPL"},
        {"site_id": "us-static-1", "file": "src/runtime/thread.rs", "line": 12, "column": 1,
         "operation_kind": "STATIC_MUT_ACCESS"},
        {"site_id": "us-foreign-1", "file": "src/dso/dlfcn.rs", "line": 40, "column": 1,
         "operation_kind": "UNSAFE_IMPL"},
        {"site_id": "us-notrec-1", "file": "src/bn/bignum.rs", "line": 99, "column": 1,
         "operation_kind": "STATIC_MUT_ACCESS"},
        {"site_id": "us-nonsurf-1", "file": "src/aes.rs", "line": 376, "column": 9,
         "operation_kind": "RAW_POINTER_WRITE"},
    ]}
    runs = [
        {"run_id": "tsan-runtime", "harness_id": "tsan-runtime", "description": "runtime",
         "filter": "runtime::", "schedule": list(SCHEDULE), "outcome": "PASS",
         "command_sha256": "0" * 64, "command": "cargo test", "unsupported_reason": "",
         "transcript_sha256": "1" * 64,
         "tests": [{"name": "runtime::thread::tests::atomic_add64_is_visible_across_threads",
                    "status": "ok"},
                   {"name": "aes::tests::rfc5649_wrap_pad_vectors", "status": "ok"}],
         "tests_run": 2, "tests_passed": 2, "tests_failed": 0,
         "error_sites": [], "unsupported_files": [], "bound_to": {}},
    ]
    return census, runs


def _synth_toolchain() -> dict:
    return {"nightly_channel": NIGHTLY, "rustc": "rustc 1.101.0-nightly", "rustc_commit": "0" * 40,
            "llvm": "23.1.1", "clang": "Debian clang version 14.0.6", "sanitizer": "TSAN",
            "tsan_runtime": "librustc-nightly_rt.tsan.a", "tsan_runtime_sha256": "0" * 64,
            "clang_tsan_runtime": "libclang_rt.tsan-x86_64.a", "clang_tsan_runtime_sha256": "0" * 64,
            "schedule": list(SCHEDULE), "nightly_installed": True}


def _synth_venue() -> dict:
    man = phase25_guard.load_manifest()
    return {"admitted_image": str(man.get("image")), "canonical_base": str(man.get("canonical_base")),
            "platform": str(man.get("platform")),
            "kind": "reused-court-venue-with-documented-data-override",
            "data_limit_override": "OPENSSL_RS_COURT_DATA=unlimited", "reason": "synthetic"}


def _synth_canary() -> dict:
    return {"built": True, "detected": True, "shadow_mapped": True, "command": "tsan_canary",
            "diagnostic": ["SUMMARY: ThreadSanitizer: data race"]}


def self_test() -> int:
    """Prove the guard refuses the host and the derivation and control are honest.

    The synthetic census covers every state without a TSan run: two covered surface sites (PASS), a
    foreign-surface site (UNSUPPORTED), an uncovered surface site (NOT_REACHABLE) and a non-surface
    site the plane must not restate.
    """
    failures: list[str] = []

    refusal = phase25_guard.host_refusal_reasons("ms_tsan.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of ms_tsan.py")

    census, runs = _synth_census()
    tc, ven, can = _synth_toolchain(), _synth_venue(), _synth_canary()
    build = {"state": "BUILT", "test_binary": "synthetic", "tsan_refs": 1}
    body = build_body(census, runs, tc, ven, can, build, True, "", REPO_ROOT)

    want = {
        "us-impl-1": "TSAN_PASS",
        "us-static-1": "TSAN_PASS",
        "us-foreign-1": "TSAN_UNSUPPORTED",
        "us-notrec-1": "TSAN_NOT_REACHABLE",
    }
    got = {sid: rec["state"] for sid, rec in body["sites"].items()}
    if got != want:
        failures.append(f"the synthetic states are wrong: {got}")
    if "us-nonsurf-1" in body["sites"]:
        failures.append("the synthetic plane restated a non-surface census site")
    c = body["counts"]
    if (c["pass"], c["fail"], c["unsupported"], c["not_reachable"], c["sites"]) != (2, 0, 1, 1, 4):
        failures.append(f"the synthetic counts are wrong: {c}")

    baseline = tsan_findings(body, census, REPO_ROOT)
    if baseline:
        failures.append(f"the synthetic TSan body is not clean: {baseline[:4]}")
    control = tsan_sensitivity_control(body, census, REPO_ROOT)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-tsan] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-tsan] self-test ok: the guard refuses the host; the synthetic derivation exercises "
          "PASS/UNSUPPORTED/NOT_REACHABLE over the concurrency-relevant surface and every seeded "
          "mutation (a PASS with no run, a PASS with a finding at it, a dropped site, an UNSUPPORTED "
          "marked PASS, a typed count, an UNSUPPORTED run with no reason and a PASS with no positive "
          "control) is caught with specificity holding")
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
        InputRef(name="ms-tsan-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="safety-obligations", path=OBLIGATIONS),
        InputRef(name="ms-obligations-tool", path=MS_OBLIGATIONS_TOOL),
        InputRef(name="tsan-canary-source", path=CANARY_SRC),
        InputRef(name="tsan-canary-rust-source", path=CANARY_RS),
        InputRef(name="harness-source-runtime-thread", path=REPO_ROOT / "src" / "runtime" / "thread.rs"),
        InputRef(name="cargo-manifest", path=CARGO_TOML),
    ]


def _measure() -> int:
    """Run TSan over the concurrency-relevant surface and write artifacts/phase25/tsan.json.

    Measurement: it builds and runs the instrumented candidate with the pinned nightly, so it is
    refused on the host and is not listed among `evidence_determinism.py`'s generators (see that
    file's why-comment). `fresh_target()` removes this stratum's scratch target directory first, so
    the instrumented binary and the build transcript are a function of the committed inputs rather
    than of a warm incremental directory -- which is what makes two `--measure` runs byte-for-byte
    identical.
    """
    tc = toolchain()
    ven = venue()
    can = canary()
    reason = _crate_reason_code(tc, can)
    crate_ran = not reason
    tc = dict(tc)
    tc["_crate_reason"] = can.get("reason", "")
    if not tc.get("nightly_installed"):
        print(f"[ms-tsan] the pinned nightly ({NIGHTLY}) is not installed under {NIGHTLY_HOME}; "
              f"recording the crate-level TSAN_UNSUPPORTED case")
    elif not crate_ran:
        print(f"[ms-tsan] the TSan instrument cannot run in this venue: {can.get('reason')}")

    if crate_ran:
        fresh_target()
        build = build_instrumented(tc)
        if build.get("state") != "BUILT":
            crate_ran = False
            tc["_crate_reason"] = str(build.get("reason") or "the instrumented build failed")
            reason = _crate_reason_code(tc, can) or REASON_VENUE
            print(f"[ms-tsan] instrumented build failed: {tc['_crate_reason']}")
    else:
        build = {"state": "UNSUPPORTED", "reason": can.get("reason", ""),
                 "command": " ".join(_build_command()), "tsan_refs": 0}

    runs = [run_harness(h, tc, crate_ran) for h in HARNESSES]

    census_body = ms_census.decode_body(_body(json.loads(_read(CENSUS)) if CENSUS.is_file() else {}))
    body = build_body(census_body, runs, tc, ven, can, build, crate_ran, reason, REPO_ROOT)
    problems = tsan_findings(body, census_body, REPO_ROOT)

    refs = ms_codec.refs_from_census(census_body)
    auth = resolve_authority(PRODUCTION_AUTHORITY)
    encoded = ms_codec.encode_body(body, refs)
    doc = envelope(kind="phase25-tsan", authority=auth.id, inputs=_inputs(), body=encoded,
                   generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_plane(OUT, doc)

    c = body["counts"]
    print(f"[ms-tsan] {'TSAN_RAN' if crate_ran else 'TSAN_UNSUPPORTED'}; canary "
          f"detected={can.get('detected')} shadow_mapped={can.get('shadow_mapped')}; "
          f"{len(runs)} harness(es)")
    for r in runs:
        print(f"  {r['run_id']:<20} {r['outcome']:<12} {r['tests_passed']}/{r['tests_run']} passed"
              + (f" -- {r['unsupported_reason'][:70]}" if r.get("unsupported_reason") else ""))
    print(f"  surface: {c['sites']} -- pass={c['pass']} fail={c['fail']} "
          f"unsupported={c['unsupported']} not_reachable={c['not_reachable']}")
    print(f"  findings={len(body['findings'])} results={len(body['results'])} "
          f"residuals={len(body['residuals'])}")
    print(f"  -> {rel(OUT)} all_pass={not problems} body_hash={doc['body_hash'][:16]}")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed plane, without TSan."""
    if not OUT.is_file():
        print(f"[ms-tsan] {rel(OUT)} is absent; run --measure")
        return 1
    doc = json.loads(OUT.read_text(encoding="utf-8"))
    census_body = ms_census.decode_body(_body(json.loads(_read(CENSUS))))
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(doc.get("body", doc), refs)
    problems = tsan_findings(body, census_body, REPO_ROOT)
    if problems:
        print(f"[ms-tsan] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-tsan] check ok: {c['sites']} surface site(s) -- pass={c['pass']} fail={c['fail']} "
          f"unsupported={c['unsupported']} not_reachable={c['not_reachable']}; "
          f"{len(body['findings'])} finding(s), {len(body['results'])} result(s), "
          f"{len(body['residuals'])} residual(s); every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="build+run TSan over the concurrency-relevant surface and write "
                         "artifacts/phase25/tsan.json")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed plane")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the guard refuses the host and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first: this tool builds and instruments the candidate.
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
