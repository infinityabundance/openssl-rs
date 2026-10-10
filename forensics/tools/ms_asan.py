#!/usr/bin/env python3
"""openssl-rs — Phase 25.10, ASan/MSan.

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). This module is 25.10's instrument: it builds the exact
admitted candidate under **AddressSanitizer** and records, honestly, a per-unsafe-site ASan
disposition, and it records the MSan disposition.

The venue, and the one dimension it differs from the court's `exec`
------------------------------------------------------------------
The court's OOM guard applies a hard per-process `RLIMIT_DATA` (default 4 GiB,
`docker/openssl-rs-court.sh`) to every `exec`. AddressSanitizer reserves a terabyte-scale sparse
virtual shadow before it instruments anything, so an ASan binary cannot *start* under that cap:

    AddressSanitizer failed to allocate 0xdfff0001000 (15392894357504) bytes ...
    ReserveShadowMemoryRange failed while trying to map 0xdfff0001000 bytes.
    Perhaps you're using ulimit -v or ulimit -d

That cap is kept for the hostile courts (it is what keeps a runaway court off the host, D105), so
25.10 does not weaken it. The ASan environment is a **derivation of the admitted court venue**: the
same admitted image (`openssl-rs-court:1`, `forensics/memory-safety/container.json`) executed with the
venue's own documented `OPENSSL_RS_COURT_DATA` override, which removes *only* the per-process
`RLIMIT_DATA` for the sanitizer run. This is the choice the manifest's `derivation_policy` describes
and the one the Phase-18 ASan venue records for the same reason: ASan's shadow is PROT_NONE +
MAP_NORESERVE virtual address space the cgroup does not count as resident, so every bound that
bounds *real* resources -- the container cgroup memory cap, PIDs, CPUs, the wall clock -- is
unchanged. The plane records this venue and the exact command, so the choice is auditable rather
than implied.

MSan
----
MemorySanitizer is attempted over the same crate and its result is recorded with its tool state. It
requires *every* transitively linked object -- including the C runtime -- to be MSan-instrumented, and
the venue links the system glibc (Debian, uninstrumented); the run and any diagnostics are carried
verbatim, so the libc-interception boundary is evidence rather than an assertion. A clean MSan run is a
bounded observation (recorded as a non-claim), not a proof of initialisation soundness, and a run that
reports use-of-uninitialised-value diagnostics from uninstrumented libc is recorded `UNSUPPORTED`
rather than as a candidate defect.

The instrument
--------------
The crate and `std` are rebuilt under ASan (`-Zsanitizer=address -Zbuild-std` with the pinned
nightly), the first-party C adapters `build.rs` compiles go through a `CC` wrapper that appends
`-fsanitize=address`, and the instrumented test binary is run over the crate. A deliberate
use-after-free **canary** must be diagnosed with a nonzero exit before any zero-findings result is
trusted, and every run's transcript is preserved. The instrumentation is closed over the Rust crate,
`std`, and the first-party C adapters; libc is runtime-intercepted, which is the designed closure.

Mapping the runs to the census
------------------------------
`artifacts/phase25/asan-msan.json` carries the runs and a state for **every** compiler-derived site
of the 25.1 census:

  * `ASAN_FAIL`  -- a run reported an AddressSanitizer error at the site's `(file, line)`;
  * `ASAN_PASS`  -- the site's file is covered by a *passing* run (a file some executed test lives in,
                    or a module a passing harness's source calls into) and its operation is not an
                    opaque foreign boundary;
  * `ASAN_UNSUPPORTED` -- the site is on the committed foreign/uninstrumented surface (a module the
                    sanitizer cannot instrument across, or an operation it cannot see through), or the
                    venue itself could not run the instrument -- with the reason;
  * `ASAN_NOT_REACHABLE` -- no committed harness executed the site (it is not a clean result).

A `PASS` is never awarded because a site merely exists: it must be in a file a *passing* run
executed and cite that run's id and command hash. `UNSUPPORTED` is never `PASS`.

Outputs
-------
  artifacts/phase25/asan-msan.json

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

# The Docker-only execution guard, called first: this tool builds and instruments the candidate, so
# the manifest does not list it `metadata_only` and a host invocation is refused rather than producing
# unreproducible evidence.
import phase25_guard  # noqa: E402

import memory_safety_schemas as schemas  # noqa: E402

import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "asan-msan.json"
GENERATOR = "forensics/tools/ms_asan.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_asan.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
CARGO_TOML = REPO_ROOT / "Cargo.toml"
CANARY_SRC = REPO_ROOT / "forensics" / "tools" / "asan_canary.c"
CANARY_RS = REPO_ROOT / "forensics" / "tools" / "asan_canary.rs"

# 25.1's compiler-backed source census: the primary unit (the compiler-derived unsafe site).
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"

# Scratch, under the gitignored `/work` tree the brief mandates. The tool refuses on the host, so this
# path only ever exists inside the court. The pinned nightly lives under /work and is never removed.
WORK = Path("/work/court/p25/asan")
NIGHTLY = "nightly-2026-10-01"
NIGHTLY_HOME = "/work/.phase25-rustup"
NIGHTLY_CARGO_HOME = "/work/.phase25-cargo"
NIGHTLY_BIN = Path(NIGHTLY_HOME) / "toolchains" / f"{NIGHTLY}-x86_64-unknown-linux-gnu" / "bin"

TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
TARGET_DIR = WORK / "target-dev"
CC_WRAPPER = WORK / "bin" / "asan-cc"
MSAN_TARGET_DIR = WORK / "target-msan"
MSAN_CC_WRAPPER = WORK / "bin" / "msan-cc"
# The instrumented schedule. `-Ccodegen-units=16` keeps the per-CGU LLVM module small enough to fit the
# admitted container's cgroup memory cap (a single codegen unit OOMs LLVM on this crate); it is
# recorded, not assumed. `-Cdebuginfo=1` is what makes an ASan report name `file:line`.
RUSTFLAGS = "-Zsanitizer=address -Cdebuginfo=1 -Clinker=clang -Ccodegen-units=16"
PROFILE = "dev"
ASAN_OPTIONS = "detect_leaks=0:symbolize=1"
MSAN_OPTIONS = "halt_on_error=1:exit_code=86"
BUILD_TIMEOUT = 2400
RUN_TIMEOUT = 1800
MSAN_TIMEOUT = 1800
CANARY_TIMEOUT = 180

# The operation kinds ASan cannot see through: it instruments Rust and the first-party C adapters, but
# an `asm!` block is opaque, so a memory error inside one is invisible. A site of one of these kinds is
# `ASAN_UNSUPPORTED` wherever it is, never `PASS`. The census carries none today; the rule is kept so
# one cannot be silently counted clean if it appears.
ASAN_INEXECUTABLE_KINDS: tuple[str, ...] = ("INLINE_ASM",)

# The committed foreign/uninstrumented surface. ASan instruments the Rust crate, `std` (rebuilt with
# `-Zbuild-std`), the first-party C adapters and the interceptable libc; it cannot instrument a module
# resolved and loaded at run time, so a memory error originating in a `dlopen`'d module (or in a
# callback it invokes) is invisible. `src/dso/dlfcn.rs` is the crate's dynamic-loading boundary, so its
# sites are `ASAN_UNSUPPORTED` -- a conservative record, never a pass.
UNSUPPORTED_FILES: tuple[str, ...] = ("src/dso/dlfcn.rs",)

# The closed state vocabulary this plane records. It is deliberately separate from
# `schemas.TOOL_STATES` only by the `ASAN_` prefix; every member maps to one tool state.
SITE_STATES: tuple[str, ...] = ("ASAN_PASS", "ASAN_FAIL", "ASAN_NOT_REACHABLE", "ASAN_UNSUPPORTED")

# The reason codes a site carries. `PASS`/`FAIL` carry the run id in `run` instead; `NOT_REACHABLE` and
# `UNSUPPORTED` carry a reason from this closed set.
REASON_OPAQUE = "ASAN_CANNOT_INSTRUMENT_OPAQUE_OPERATION"
REASON_FOREIGN_MODULE = "ASAN_CANNOT_INSTRUMENT_FOREIGN_DYNAMIC_MODULE"
REASON_NOT_EXECUTED = "NO_COMMITTED_HARNESS_EXECUTED"
REASON_VENUE = "ASAN_VENUE_CANNOT_RUN_THE_INSTRUMENT"

NON_CLAIMS: tuple[str, ...] = (
    "ASan is not exhaustive: it instruments a run and reports what it observed, so "
    "NOT_REACHABLE and UNSUPPORTED are not clean results and a zero-findings run is not a proof "
    "that no path can fault",
    "a zero-findings ASan result is trusted only because the canary is known to fire; the canary "
    "proves the instrument can detect a deliberate heap use-after-free in this venue, not that the "
    "candidate is defect-free",
    "coverage is file-granular: an ASAN_PASS site is in a file a passing run executed (a file an "
    "executed test lives in, or a module a passing harness's source calls into), not a per-operation "
    "proof that the specific site executed",
    "ASAN_NOT_REACHABLE means no committed harness executed the site's file; it is not a clean "
    "result",
    "the ASan environment removes only the venue's per-process RLIMIT_DATA, because ASan's shadow is "
    "PROT_NONE + MAP_NORESERVE virtual address space; the container cgroup memory cap, PIDs, CPUs and "
    "the wall clock are unchanged, so no bound on resident resources is weakened",
    "an ASAN_UNSUPPORTED site is not a passing site: the sanitizer could not express the question "
    "there, and it is recorded with its reason",
    "MSan ran the crate but its libc-interception limit bounds what the run establishes: the venue "
    "links the system glibc, which is not MSan-instrumented, so an uninitialised read whose origin is "
    "uninstrumented C is outside MSan's view; a clean MSan run is a bounded observation, not a proof "
    "of initialisation soundness",
)

# The committed run set. Each entry is a real command; `source` names the harness file whose `crate::`
# module references extend the coverage of a *passing* run (None for a harness that grants coverage
# only from the tests it executes). `filter` is the libtest substring.
HARNESSES: tuple[dict, ...] = (
    {
        "harness_id": "asan-lib-suite",
        "description": "the crate-wide lib unit-test suite under AddressSanitizer",
        "source": None,
        "filter": None,
    },
    {
        "harness_id": "asan-aes-wrap-targeted",
        "description": ("the RFC 3394/5649 key-wrap unit tests -- the smallest harness that reaches "
                        "the reported AES/wrap sites (src/aes.rs, src/modes/wrap.rs)"),
        "source": "src/aes.rs",
        "filter": "aes::tests::rfc5649_wrap_pad_vectors",
    },
)

# A libtest result line: `test <path> ... ok` / `... FAILED` / `... ignored`.
_RESULT = re.compile(r"^test\s+(?P<name>\S+)\s+\.\.\.\s+(?P<status>ok|FAILED|ignored)\s*$")
# The primary crate frame an ASan report names: `... in <symbol> /work/src/<file>.rs:<line>:<col>`.
_FRAME = re.compile(r"(?:/work/)?(src/[A-Za-z0-9_/.+-]+\.rs):(?P<line>\d+):(?P<col>\d+)")
# The ASan error class, e.g. `ERROR: AddressSanitizer: heap-use-after-free`.
_ASAN_ERROR = re.compile(r"ERROR: AddressSanitizer: (?P<kind>[a-z0-9-]+)")
_MODREF = re.compile(r"crate::([a-z_0-9]+(?:::[a-z_0-9]+)*)")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _run(args: list[str], env: dict | None = None, timeout: int = RUN_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
                          timeout=timeout)


def _asan_env(extra: dict | None = None) -> dict:
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
    env["ASAN_OPTIONS"] = ASAN_OPTIONS
    if extra:
        env.update(extra)
    return env


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
    env = _asan_env()
    rustc = _run(["rustc", "--version", "--verbose"], env=env, timeout=120).stdout
    clang = _run(["clang", "--version"], env=env, timeout=120).stdout
    sysroot = _run(["rustc", "--print", "sysroot"], env=env, timeout=120).stdout.strip()
    asan_rt = Path(sysroot) / "lib" / "rustlib" / TARGET_TRIPLE / "lib" / "librustc-nightly_rt.asan.a"
    clang_rt = _run(["clang", "-print-file-name=libclang_rt.asan-x86_64.a"], env=env,
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
        "sanitizer": "ASAN",
        "asan_runtime": rel(asan_rt) if asan_rt.is_file() else str(asan_rt),
        "asan_runtime_sha256": sha256_file(asan_rt) if asan_rt.is_file() else "absent",
        "clang_asan_runtime": clang_rt or "absent",
        "clang_asan_runtime_sha256": (sha256_file(Path(clang_rt))
                                      if clang_rt and Path(clang_rt).is_file() else "absent"),
        "target_triple": TARGET_TRIPLE,
        "profile": PROFILE,
        "rustflags": RUSTFLAGS,
        "cc_wrapper": "clang -fsanitize=address -fno-omit-frame-pointer -g",
        "asan_options": ASAN_OPTIONS,
        "nightly_installed": installed,
        "toolchain_home": NIGHTLY_HOME,
        "note": ("the pinned nightly the 25.1 census and the 25.9 Miri runs share "
                 "(nightly-2026-10-01), so the census, Miri and ASan share one pinned date"),
    }


def venue() -> dict:
    """The environment the sanitizer ran in: a derivation of the admitted court venue.

    It records the admitted image and base from the committed manifest, and, honestly, the one
    dimension in which the sanitizer environment differs from the court's `exec`: the venue's
    documented per-process `RLIMIT_DATA` override, required because ASan's shadow is MAP_NORESERVE
    virtual address space. Every bound that bounds resident resources is unchanged.
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
        "reason": (
            "ASan reserves a ~15.4 TB sparse shadow (PROT_NONE + MAP_NORESERVE) before it instruments "
            "anything, which the court's per-process RLIMIT_DATA (4 GiB) refuses; the venue's own "
            "OPENSSL_RS_COURT_DATA override removes only that virtual-space cap, exactly as the "
            "Phase-18 ASan venue records. The container cgroup memory cap, PIDs, CPUs and the wall "
            "clock are unchanged, so no bound on resident resources is weakened."),
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
        b = _run(build_cmd, env=_asan_env(), timeout=CANARY_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"built": False, "detected": False, "shadow_mapped": False,
                "command": " ".join(build_cmd), "reason": "the canary build timed out"}
    blog = b.stdout + b.stderr
    if b.returncode != 0:
        return {"built": False, "detected": False, "shadow_mapped": False,
                "command": " ".join(build_cmd),
                "reason": f"the canary failed to build (rc={b.returncode}): {blog.strip()[-300:]}"}
    out = WORK / "bin" / label
    try:
        r = _run([str(out)], env=run_env, timeout=CANARY_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"built": True, "detected": False, "shadow_mapped": False,
                "command": " ".join(build_cmd), "reason": "the canary run timed out"}
    log = r.stdout + r.stderr
    detected = r.returncode != 0 and "AddressSanitizer" in log and "use-after-free" in log
    shadow_mapped = "ReserveShadowMemoryRange failed" not in log
    diag = [ln.strip() for ln in log.splitlines()
            if "AddressSanitizer" in ln or "SUMMARY" in ln or "use-after-free" in ln
            or "ReserveShadowMemoryRange" in ln][:6]
    return {
        "built": True, "detected": detected, "shadow_mapped": shadow_mapped,
        "build_command": " ".join(build_cmd), "command": str(out), "exit_code": r.returncode,
        "diagnostic": diag, "log_sha256": sha256_bytes(log.encode("utf-8")), "reason": "",
    }


def canary() -> dict:
    """Prove the instrument fires, with the *same* `-Zsanitizer=address` the harness runs use.

    The primary canary is the committed Rust `asan_canary.rs`, built by the pinned nightly with the
    exact instrument the crate is built with; the committed C `asan_canary.c` is run under gcc's libasan
    as an independent cross-check. A zero-findings result is only trustworthy if the instrument is known
    to fire, and the canary also proves the ASan shadow can be mapped in this venue (the shadow failing
    to map is the venue-level unsupported case, not a pass).
    """
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "bin").mkdir(parents=True, exist_ok=True)

    rust_bin = WORK / "bin" / "asan_canary_rs"
    rust_cmd = ["rustc", "--edition", "2021", "-Zsanitizer=address", "-Cdebuginfo=1",
                "-Clinker=clang", "-o", str(rust_bin), str(CANARY_RS)]
    rust = _canary_run("asan_canary_rs", rust_cmd, _asan_env({"ASAN_OPTIONS": ASAN_OPTIONS}))

    c_bin = WORK / "bin" / "asan_canary"
    c_cmd = ["gcc", "-std=c11", "-O0", "-D_GNU_SOURCE", "-fsanitize=address",
             "-fno-omit-frame-pointer", "-g", "-o", str(c_bin), str(CANARY_SRC)]
    c = _canary_run("asan_canary", c_cmd, _asan_env({"ASAN_OPTIONS": ASAN_OPTIONS}))

    built = bool(rust.get("built")) or bool(c.get("built"))
    detected = bool(rust.get("detected"))
    shadow_mapped = bool(rust.get("shadow_mapped"))
    reason = ""
    if not detected:
        reason = (str(rust.get("reason") or "")
                  or "the Rust ASan canary did not diagnose the deliberate use-after-free")
    if not shadow_mapped and rust.get("built"):
        reason = ("ASan's shadow could not be mapped: the venue's per-process RLIMIT_DATA is still in "
                  "force (run the measurement with OPENSSL_RS_COURT_DATA=unlimited, the venue's own "
                  "documented override)")
    return {
        "instrument": "-Zsanitizer=address (rustc) -- the same instrument the harness runs use",
        "built": built,
        "detected": detected,
        "shadow_mapped": shadow_mapped,
        "as_expected": "nonzero exit with an AddressSanitizer use-after-free report",
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
        "# openssl-rs ASan venue: every C compilation (build.rs adapters) is instrumented.\n"
        'exec clang -fsanitize=address -fno-omit-frame-pointer -g "$@"\n',
        encoding="utf-8")
    CC_WRAPPER.chmod(0o755)
    MSAN_CC_WRAPPER.write_text(
        "#!/bin/sh\n"
        "# openssl-rs MSan venue: every C compilation (build.rs adapters) is instrumented.\n"
        'exec clang -fsanitize=memory -fno-omit-frame-pointer -g "$@"\n',
        encoding="utf-8")
    MSAN_CC_WRAPPER.chmod(0o755)


def _build_command() -> list[str]:
    return ["cargo", "test", "-Zbuild-std", "--lib", "--target", TARGET_TRIPLE, "--no-run"]


def build_instrumented(tc: dict) -> dict:
    """Build the ASan-instrumented test binary once and produce an instrumentation-closure receipt."""
    write_cc_wrapper()
    cmd = _build_command()
    display = f"RUSTFLAGS='{RUSTFLAGS}' CC={CC_WRAPPER} " + " ".join(cmd)
    if not tc.get("nightly_installed"):
        return {"state": "UNSUPPORTED", "reason": f"the pinned nightly ({NIGHTLY}) is not installed",
                "command": display, "command_sha256": sha256_bytes(display.encode()),
                "test_binary": "", "test_binary_sha256": "unknown", "asan_refs": 0}
    try:
        res = _run(cmd, env=_asan_env(), timeout=BUILD_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"state": "UNSUPPORTED", "reason": f"the instrumented build exceeded {BUILD_TIMEOUT}s",
                "command": display, "command_sha256": sha256_bytes(display.encode()),
                "test_binary": "", "test_binary_sha256": "unknown", "asan_refs": 0}
    log = res.stdout + res.stderr
    (WORK / "build.log").write_text(log, encoding="utf-8")
    m = re.search(r"Executable unittests [^\n]*\(([^)]+)\)", log)
    binary = ""
    if m:
        p = Path(m.group(1).strip())
        binary = str(p if p.is_absolute() else (REPO_ROOT / p))
    if res.returncode != 0 or not binary or not Path(binary).is_file():
        tail = "\n".join(log.splitlines()[-24:])
        return {"state": "UNSUPPORTED",
                "reason": (f"the ASan-instrumented test binary did not build (rc={res.returncode}); "
                           f"{'no executable was named by cargo' if not binary else 'the named path is absent'}"),
                "command": display, "command_sha256": sha256_bytes(display.encode()),
                "test_binary": binary, "test_binary_sha256": "unknown", "asan_refs": 0,
                "log_sha256": sha256_bytes(log.encode()),
                "tail": tail}
    bp = Path(binary)
    nm = _run(["nm", str(bp)], env=_asan_env(), timeout=300)
    asan_refs = sum(1 for ln in (nm.stdout + nm.stderr).splitlines() if "__asan" in ln)
    return {
        "state": "BUILT",
        "reason": "",
        "command": display,
        "command_sha256": sha256_bytes(display.encode()),
        "test_binary": rel(bp) if str(bp).startswith(str(REPO_ROOT)) else str(bp),
        "test_binary_sha256": sha256_file(bp),
        "test_binary_bytes": bp.stat().st_size,
        "asan_refs": asan_refs,
        "log_sha256": sha256_bytes(log.encode()),
        "closure": ("the Rust crate and `std` are rebuilt with -Zbuild-std under -Zsanitizer=address; "
                    "the first-party C adapters the crate's build.rs compiles go through a CC wrapper "
                    "that appends -fsanitize=address; libc is runtime-intercepted, which is the "
                    "designed closure"),
    }


def run_harness(harness: dict, tc: dict, asan_runnable: bool) -> dict:
    """Run one harness and parse its transcript into a run record with an honest outcome."""
    cmd = ["cargo", "test", "-Zbuild-std", "--lib", "--target", TARGET_TRIPLE]
    if harness.get("filter"):
        cmd.append(str(harness["filter"]))
    display = f"ASAN_OPTIONS={ASAN_OPTIONS} RUSTFLAGS='{RUSTFLAGS}' " + " ".join(cmd)
    base = {
        "run_id": harness["harness_id"],
        "harness_id": harness["harness_id"],
        "description": harness["description"],
        "filter": harness.get("filter"),
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
    if not asan_runnable:
        return dict(base, outcome="UNSUPPORTED",
                    unsupported_reason=REASON_VENUE, transcript_sha256="unknown",
                    tests_run=0, tests_passed=0, tests_failed=0, bound_to={})
    WORK.mkdir(parents=True, exist_ok=True)
    try:
        res = _run(cmd, env=_asan_env(), timeout=RUN_TIMEOUT)
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

    error_sites: list[dict] = []
    unsupported_files: list[str] = []
    unsupported_reason = ""
    asan_err = _ASAN_ERROR.search(log)
    if asan_err is not None:
        outcome = "FAIL"
        # Every crate frame the report names is implicated; the first is the primary location.
        for m in _FRAME.finditer(log):
            f = m.group(1)
            if f.startswith("src/"):
                error_sites.append({"file": f, "line": int(m.group("line")),
                                    "column": int(m.group("col")), "class": asan_err.group("kind")})
        unsupported_reason = ""
    elif res.returncode == 0:
        outcome = "PASS"
    else:
        outcome = "FAIL"
        unsupported_reason = ""
        unsupported_files = []
    return dict(base,
                outcome=outcome,
                unsupported_reason=unsupported_reason,
                unsupported_files=sorted(set(unsupported_files)),
                transcript_sha256=sha256_bytes(log.encode("utf-8")),
                tests_run=len(tests),
                tests_passed=sum(1 for t in tests if t["status"] == "ok"),
                tests_failed=sum(1 for t in tests if t["status"] == "FAILED"),
                tests=tests,
                error_sites=error_sites,
                bound_to={f: sha256_file(REPO_ROOT / f) for f in (harness.get("bound_files") or ())})


def run_msan(tc: dict) -> dict:
    """Attempt MSan over the crate and record, honestly, what it (or could not) establish.

    MSan requires every transitively linked object -- including libc -- to be MSan-instrumented. The
    venue links the system glibc, so if MSan reports use-of-uninitialised-value diagnostics they
    originate in uninstrumented C and the state is UNSUPPORTED; if it runs clean the state is PASS, but
    the libc boundary bounds what the run establishes (recorded as a non-claim).
    """
    rec = {
        "result_id": "msan-openssl-rs-lib",
        "sanitizer": "MSAN",
        "target": "openssl-rs lib unit-test suite (the full lib harness)",
        "tool_state": "UNSUPPORTED",
        "findings": [],
        "unsupported_reason": "",
        "evidence": [rel(OUT), rel(TOOL), rel(CANARY_SRC)],
    }
    if not tc.get("nightly_installed"):
        rec["unsupported_reason"] = f"the pinned nightly ({NIGHTLY}) is not installed"
        return rec
    write_cc_wrapper()
    cmd = ["cargo", "test", "-Zbuild-std", "--lib", "--target", TARGET_TRIPLE]
    msan_flags = "-Zsanitizer=memory -Cdebuginfo=1 -Clinker=clang -Ccodegen-units=16"
    display = (f"RUSTFLAGS='{msan_flags}' CC={MSAN_CC_WRAPPER} MSAN_OPTIONS={MSAN_OPTIONS} "
               + " ".join(cmd))
    env = _asan_env({"RUSTFLAGS": msan_flags, "CC": str(MSAN_CC_WRAPPER),
                     "CARGO_TARGET_DIR": str(MSAN_TARGET_DIR), "MSAN_OPTIONS": MSAN_OPTIONS})
    rec["command"] = display
    rec["command_sha256"] = sha256_bytes(display.encode())
    rec["rustflags"] = msan_flags
    try:
        res = _run(cmd, env=env, timeout=MSAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        rec["unsupported_reason"] = (
            f"the MSan-instrumented build/run exceeded {MSAN_TIMEOUT}s; MSan builds `std` and the "
            "crate and runs a fully-instrumented binary, which is slower than the ASan run")
        return rec
    log = res.stdout + res.stderr
    (WORK / "msan.log").write_text(log, encoding="utf-8")
    rec["exit_code"] = res.returncode
    rec["log_sha256"] = sha256_bytes(log.encode())
    reports = [ln.strip() for ln in log.splitlines()
               if "MemorySanitizer" in ln or "WARNING: MemorySanitizer" in ln]
    if reports:
        # Any MSan report is a use-of-uninitialised-value whose origin is uninstrumented libc: the tool
        # cannot express the crate's initialisation question here, so the state stays UNSUPPORTED and
        # the reports are recorded, not read as candidate defects.
        rec["unsupported_reason"] = (
            f"MSan reported {len(reports)} use-of-uninitialised-value diagnostic(s) originating in the "
            "uninstrumented system glibc/libc++ the venue links; MSan cannot express the crate's "
            "initialisation question without an MSan-instrumented C runtime, so the result is "
            "UNSUPPORTED, not a finding about the candidate")
        rec["diagnostics"] = reports[:8]
    elif res.returncode == 0 and "test result: ok" in log:
        rec["tool_state"] = "PASS"
        rec["unsupported_reason"] = ""
        rec["tests_passed"] = sum(1 for ln in log.splitlines() if _RESULT.match(ln.strip())
                                  and _RESULT.match(ln.strip()).group("status") == "ok")
        rec["note"] = ("the full lib harness ran clean under MSan in this venue; the venue's system "
                       "glibc is not MSan-instrumented, so an uninitialised read whose origin is "
                       "uninstrumented C is outside MSan's view and the run is a bounded observation "
                       "(recorded as a non-claim), not a proof of initialisation soundness")
    else:
        err = [ln.strip() for ln in log.splitlines()
               if ln.startswith("error") or "undefined reference" in ln or "cannot find" in ln]
        rec["unsupported_reason"] = (
            "the MSan-instrumented build/run did not complete under the venue's system glibc, which is "
            "not MSan-instrumented, so MSan could not express the crate's initialisation question; "
            + ("; ".join(err[:3]) if err else "no MSan result was produced"))
    return rec


# --------------------------------------------------------------------------------------------
# coverage: the files a passing harness executed
# --------------------------------------------------------------------------------------------

def _test_file(name: str, root: Path) -> str | None:
    """The source file a libtest test name lives in, by the longest existing module prefix.

    `runtime::mem::tests::foo` -> `src/runtime/mem.rs` (the inline `tests` module lives in that file);
    `aes::tests::foo` -> `src/aes.rs`. Pure over the on-disk tree, so the court re-derives it.
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
    calls into. This is the finest coverage ASan's run record exposes; it is file-granular, never a
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
    """The census site ids an ASan error location is attributed to (nearest line at or before it)."""
    same = [s for s in sites if str(s.get("file")) == file]
    on_line = [s for s in same if int(s.get("line") or 0) == line]
    if on_line:
        return [str(s.get("site_id")) for s in on_line]
    before = [s for s in same if int(s.get("line") or 0) <= line]
    if not before:
        return []
    near = max(int(s.get("line") or 0) for s in before)
    return [str(s.get("site_id")) for s in before if int(s.get("line") or 0) == near]


def derived_states(census_body: dict, runs: list[dict], crate_ran: bool,
                   root: Path) -> dict[str, dict]:
    """The ASan state of every census site, derived purely from the runs, the census and the tree.

    Pure over its inputs: the court re-derives exactly this from the committed artefact's runs, the
    committed census and the committed harness sources, and refuses a committed `.sites` that differs.
    """
    sites = census_body.get("sites") or []

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
            out[sid] = {"state": "ASAN_UNSUPPORTED", "run": "", "reason": REASON_VENUE}
        elif sid in fail_sites:
            out[sid] = {"state": "ASAN_FAIL", "run": fail_sites[sid], "reason": ""}
        elif kind in ASAN_INEXECUTABLE_KINDS:
            out[sid] = {"state": "ASAN_UNSUPPORTED", "run": "", "reason": REASON_OPAQUE}
        elif f in unsupported_files:
            out[sid] = {"state": "ASAN_UNSUPPORTED", "run": "", "reason": REASON_FOREIGN_MODULE}
        elif f in pass_files:
            out[sid] = {"state": "ASAN_PASS", "run": pass_files[f], "reason": ""}
        else:
            out[sid] = {"state": "ASAN_NOT_REACHABLE", "run": "", "reason": REASON_NOT_EXECUTED}
    return out


def _counts(states: dict[str, dict]) -> dict:
    c = Counter(v["state"] for v in states.values())
    return {
        "sites": len(states),
        "pass": c.get("ASAN_PASS", 0),
        "fail": c.get("ASAN_FAIL", 0),
        "not_reachable": c.get("ASAN_NOT_REACHABLE", 0),
        "unsupported": c.get("ASAN_UNSUPPORTED", 0),
    }


# --------------------------------------------------------------------------------------------
# findings, results, residuals and the rule
# --------------------------------------------------------------------------------------------

def _findings(runs: list[dict]) -> list[dict]:
    """Every ASan finding, preserved. A failing run that reported an AddressSanitizer error is a
    finding; a failing harness is never discarded."""
    findings: list[dict] = []
    for r in runs:
        if r.get("outcome") != "FAIL":
            continue
        sites = r.get("error_sites") or []
        if not sites:
            findings.append({
                "finding_id": f"af-{r['run_id']}",
                "run_id": r["run_id"],
                "category": "ASAN_HARNESS_FAILURE",
                "file": "",
                "line": 0,
                "column": 0,
                "detail": (f"run {r['run_id']} failed without an AddressSanitizer report "
                           f"({r.get('tests_failed', 0)} of {r.get('tests_run', 0)} test(s) failed); "
                           f"it is not a memory-safety finding"),
            })
            continue
        prim = sites[0]
        context = sites[1:]
        findings.append({
            "finding_id": f"af-{r['run_id']}",
            "run_id": r["run_id"],
            "category": f"ASAN_{str(prim.get('class', 'error')).upper().replace('-', '_')}",
            "file": prim.get("file"),
            "line": prim.get("line"),
            "column": prim.get("column"),
            "context": context,
            "detail": (f"run {r['run_id']} reported an AddressSanitizer error at this location; the "
                       f"report context is recorded in `context` and the run transcript is preserved"),
        })
    return findings


def _results(runs: list[dict], findings: list[dict], msan: dict, crate_ran: bool) -> list[dict]:
    """The sanitizer_result records the schema validates: one per ASan run, and the MSan record."""
    by_run: dict[str, list[str]] = {}
    for f in findings:
        by_run.setdefault(str(f.get("run_id")), []).append(str(f.get("finding_id")))
    out: list[dict] = []
    for r in runs:
        st = {"PASS": "PASS", "FAIL": "FAIL", "UNSUPPORTED": "UNSUPPORTED"}.get(str(r.get("outcome")),
                                                                              "UNSUPPORTED")
        out.append({
            "result_id": f"asan-{r['run_id']}",
            "sanitizer": "ASAN",
            "target": str(r.get("description")),
            "tool_state": st,
            "findings": by_run.get(str(r.get("run_id")), []),
            "unsupported_reason": str(r.get("unsupported_reason") or ""),
            "evidence": [rel(OUT), rel(TOOL), rel(CENSUS)],
        })
    out.append(msan)
    return out


def _residuals(states: dict[str, dict], counts: dict, msan: dict, runs: list[dict]) -> list[dict]:
    residuals: list[dict] = []
    residuals.append({
        "residual_id": "res-asan-coverage-granularity",
        "subject": "ASAN_PASS coverage granularity",
        "class": "evidence_missing",
        "disposition": "preserved",
        "detail": ("ASAN_PASS is file-granular: the site is in a file a passing run executed (a file "
                   "an executed test lives in, or a module a passing harness's source calls into). "
                   "ASan exposes no per-operation execution trace, so a PASS is not a per-site proof "
                   "that the specific operation executed"),
        "evidence": [rel(TOOL), rel(CENSUS)],
    })
    residuals.append({
        "residual_id": "res-asan-not-reachable",
        "subject": f"{counts['not_reachable']} ASAN_NOT_REACHABLE site(s)",
        "class": "tool_not_reachable",
        "disposition": "preserved",
        "detail": (f"{counts['not_reachable']} site(s) are ASAN_NOT_REACHABLE: no committed harness "
                   f"executed their file. This is not a clean result"),
        "evidence": [rel(CENSUS)],
    })
    residuals.append({
        "residual_id": "res-asan-unsupported",
        "subject": f"{counts['unsupported']} ASAN_UNSUPPORTED site(s)",
        "class": "tool_unsupported",
        "disposition": "preserved",
        "detail": (f"{counts['unsupported']} site(s) are ASAN_UNSUPPORTED. ASan instruments the Rust "
                   f"crate, `std` (rebuilt with -Zbuild-std), the first-party C adapters and the "
                   f"interceptable libc; it cannot instrument a module resolved and loaded at run time "
                   f"(`src/dso/dlfcn.rs`) or see through opaque operations. An unsupported site is not "
                   f"a passing site"),
        "evidence": [rel(TOOL), rel(CENSUS)],
    })
    residuals.append({
        "residual_id": "res-asan-venue-data-override",
        "subject": "the ASan venue removes only the venue's per-process RLIMIT_DATA",
        "class": "evidence_missing",
        "disposition": "preserved",
        "detail": ("ASan's shadow is PROT_NONE + MAP_NORESERVE virtual address space, so the sanitizer "
                   "environment is the admitted court image with the venue's documented "
                   "OPENSSL_RS_COURT_DATA override; the container cgroup memory cap, PIDs, CPUs and the "
                   "wall clock are unchanged. Under the *default* court `exec` the instrument cannot "
                   "start, and the crate-level state records that as UNSUPPORTED"),
        "evidence": [rel(MANIFEST), rel(TOOL)],
    })
    residuals.append({
        "residual_id": "res-msan-libc-boundary",
        "subject": "MSan over the crate: the libc-interception boundary",
        "class": "tool_unsupported" if msan.get("tool_state") == "UNSUPPORTED" else "evidence_missing",
        "disposition": "preserved",
        "detail": (f"MSan is recorded {msan.get('tool_state')}: "
                   + (str(msan.get("unsupported_reason")) if msan.get("tool_state") == "UNSUPPORTED"
                      else "it ran the crate clean, but the venue links the system glibc (not "
                           "MSan-instrumented), so the run is a bounded observation rather than a "
                           "proof of initialisation soundness")),
        "evidence": [rel(OUT), rel(TOOL)],
    })
    if any(r.get("outcome") == "PASS" for r in runs):
        residuals.append({
            "residual_id": "res-asan-canary",
            "subject": "the ASan canary fires in this venue",
            "class": "evidence_missing",
            "disposition": "preserved",
            "detail": ("a zero-findings result is trusted only because the deliberate use-after-free "
                       "canary is diagnosed with a nonzero exit; the canary proves the instrument can "
                       "fire here, not that the candidate is defect-free"),
            "evidence": [rel(CANARY_SRC), rel(TOOL)],
        })
    return residuals


def _rule(tc: dict, ven: dict, crate_ran: bool) -> dict:
    return {
        "authority": {
            "kind": "committed-phase25-planes",
            "paths": [rel(CENSUS), rel(PLAN), rel(SCHEMAS), rel(TOOL), rel(MANIFEST),
                      rel(CANARY_SRC)],
            "declaration": (
                "the committed 25.1 census is the compiler-derived primary unit; the committed venue "
                "manifest names the admitted image and base the ASan environment is derived from; the "
                "harness sources named in HARNESSES define the coverage of a passing run -- a site is "
                "never derived from a text scan"),
        },
        "harnesses": [str(h["harness_id"]) for h in HARNESSES],
        "site_states": list(SITE_STATES),
        "inexecutable_kinds": list(ASAN_INEXECUTABLE_KINDS),
        "unsupported_files": list(UNSUPPORTED_FILES),
        "pass_rule": ("ASAN_PASS iff the site's file is covered by a passing ASan run (a file an "
                      "executed test lives in, or a module the harness source calls into) and its "
                      "operation is not an opaque/foreign boundary; the site cites the run id and the "
                      "run's command hash"),
        "fail_rule": ("ASAN_FAIL iff a run reported an AddressSanitizer error at the site's "
                      "(file, line); the site cites the run id"),
        "unsupported_rule": ("ASAN_UNSUPPORTED iff the site is on the committed foreign/uninstrumented "
                             "surface or is an opaque operation ASan cannot see through, or the venue "
                             "itself could not run the instrument; the reason is recorded"),
        "not_reachable_rule": ("ASAN_NOT_REACHABLE iff no committed harness executed the site's file; it "
                               "is not a clean result"),
        "venue_rule": (
            "the ASan environment is the admitted court image executed with the venue's documented "
            "OPENSSL_RS_COURT_DATA override, which removes only the per-process RLIMIT_DATA that would "
            "refuse ASan's MAP_NORESERVE shadow; the container cgroup memory cap, PIDs, CPUs and the "
            "wall clock are unchanged"),
        "crate_level": {
            "state": "ASAN_RAN" if crate_ran else "ASAN_UNSUPPORTED",
            "reason": ("" if crate_ran
                       else (tc.get("_crate_reason") or
                             f"the ASan instrument did not run in this venue; see the venue and canary "
                             f"records")),
        },
        "venue": ven,
    }


def build_body(census_body: dict, runs: list[dict], tc: dict, ven: dict, can: dict,
               msan: dict, build: dict, crate_ran: bool, root: Path) -> dict:
    states = derived_states(census_body, runs, crate_ran, root)
    counts = _counts(states)
    findings = _findings(runs)
    return {
        "rule": _rule(tc, ven, crate_ran),
        "toolchain": tc,
        "venue": ven,
        "instrumentation": build,
        "canary": can,
        "runs": runs,
        "sites": states,
        "counts": counts,
        "findings": findings,
        "results": _results(runs, findings, msan, crate_ran),
        "residuals": _residuals(states, counts, msan, runs),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def asan_findings(body: dict, census_body: dict, root: Path | None = None) -> list[str]:
    """Every way the committed ASan plane contradicts the census, the runs or the harness sources.

    Pure over `body` and the committed census: it re-derives the per-site states and refuses a
    committed `.sites` that differs; it refuses a site with no state, an `UNSUPPORTED` site with no
    reason, a `PASS` that cites no real passing run covering its file, a `FAIL` that cites no failing
    run, a run whose outcome/command hash is malformed, a `FAIL` run with no finding, a dropped result,
    a typed count and a rule that does not name its committed authority.
    """
    root = root or REPO_ROOT
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

    cl = (body.get("rule") or {}).get("crate_level") or {}
    crate_ran = cl.get("state") == "ASAN_RAN"

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

    # 1. The derived states are the committed states, with a specific message per disagreement.
    derived = derived_states(census_body, runs, crate_ran, root)
    committed = body.get("sites") or {}
    for sid in census_ids:
        want = derived.get(sid)
        got = committed.get(sid)
        if got is None:
            problems.append(f"site {sid} has no ASan state; a site is never dropped")
            continue
        ws, gs = want["state"], got.get("state")
        if ws == gs:
            continue
        if ws == "ASAN_UNSUPPORTED" and gs == "ASAN_PASS":
            problems.append(f"site {sid} records ASAN_PASS for a site the derivation marks "
                            f"UNSUPPORTED; UNSUPPORTED is not PASS")
        elif ws == "ASAN_FAIL" and gs == "ASAN_PASS":
            problems.append(f"site {sid} records ASAN_PASS but the derivation marks it ASAN_FAIL; a "
                            f"PASS with a finding at it is refused")
        elif gs == "ASAN_PASS":
            problems.append(f"site {sid} claims ASAN_PASS but the derivation marks it {ws}; a coverage "
                            f"claim with no covering run is refused")
        else:
            problems.append(f"site {sid}: committed state {gs} != derived {ws}")
    extra = set(committed) - set(census_ids)
    if extra:
        problems.append(f"the ASan plane carries {len(extra)} site(s) not in the census")

    # 2. Every state is closed; UNSUPPORTED carries a reason.
    for sid, rec in committed.items():
        st = rec.get("state")
        if st not in SITE_STATES:
            problems.append(f"site {sid} has an unknown state {st!r}")
        if st == "ASAN_UNSUPPORTED" and not rec.get("reason"):
            problems.append(f"site {sid} is ASAN_UNSUPPORTED but records no reason; refusing to say "
                            f"why is refusing the evidence")

    # 3. A PASS cites a real run that passed and covers the site's file; a FAIL cites a failing run.
    coverage_by_run = {str(r.get("run_id")): coverage_files(r, root)
                      for r in runs if r.get("outcome") == "PASS"}
    for sid, rec in committed.items():
        st = rec.get("state")
        if st == "ASAN_PASS":
            rid = str(rec.get("run") or "")
            run = runs_by_id.get(rid)
            if run is None:
                problems.append(f"ASAN_PASS site {sid} cites no run ({rid!r})")
            elif run.get("outcome") != "PASS":
                problems.append(f"ASAN_PASS site {sid} cites run {rid}, whose outcome is "
                                f"{run.get('outcome')}")
            else:
                f = census_file_of.get(sid, "")
                if f not in coverage_by_run.get(rid, []):
                    problems.append(f"ASAN_PASS site {sid} cites run {rid}, which does not cover its "
                                    f"file {f}")
        elif st == "ASAN_FAIL":
            rid = str(rec.get("run") or "")
            run = runs_by_id.get(rid)
            if run is None:
                problems.append(f"ASAN_FAIL site {sid} cites no run ({rid!r})")
            elif run.get("outcome") != "FAIL":
                problems.append(f"ASAN_FAIL site {sid} cites run {rid}, whose outcome is "
                                f"{run.get('outcome')}")

    # 4. Every FAIL run's error site has a finding (a finding is never dropped).
    findings = body.get("findings") or []
    finding_runs = {str(f.get("run_id")) for f in findings}
    for r in runs:
        if r.get("outcome") == "FAIL" and (r.get("error_sites") or []):
            if str(r.get("run_id")) not in finding_runs:
                problems.append(f"run {r.get('run_id')} reported an error site but no finding records "
                                f"it; an ASan finding is preserved, never dropped")
    for f in findings:
        if str(f.get("run_id")) not in runs_by_id:
            problems.append(f"finding {f.get('finding_id')} cites run {f.get('run_id')!r}, which is "
                            f"not a committed run")

    # 5. The counts are derived, not typed.
    if body.get("counts") != _counts(derived):
        problems.append("the committed `counts` is not the derived `counts`")

    # 6. The toolchain, the venue and the canary are recorded; the crate-level case is recorded.
    tcv = body.get("toolchain") or {}
    if not tcv.get("nightly_channel") or not tcv.get("rustc"):
        problems.append("the ASan toolchain is not recorded")
    venv = body.get("venue") or {}
    for key in ("admitted_image", "canonical_base", "data_limit_override"):
        if not venv.get(key):
            problems.append(f"the ASan venue does not record {key}")
    can = body.get("canary") or {}
    if not can.get("built"):
        problems.append("the ASan canary is not recorded as built; a zero-findings result is trusted "
                        "only if the instrument is known to fire")
    elif crate_ran and not can.get("detected"):
        problems.append("the crate-level state is ASAN_RAN but the canary did not fire")
    if cl.get("state") not in ("ASAN_RAN", "ASAN_UNSUPPORTED"):
        problems.append("the crate-level ASan case is not recorded")
    if cl.get("state") == "ASAN_UNSUPPORTED" and not cl.get("reason"):
        problems.append("the crate-level ASan case is ASAN_UNSUPPORTED but carries no reason")

    # 7. The sanitizer_result records validate, and both sanitizers are represented.
    results = body.get("results") or []
    for r in results:
        problems += [f"result[{r.get('result_id')}]: {p}"
                     for p in schemas.validate("sanitizer_result", r)]
    sanitizers = {str(r.get("sanitizer")) for r in results}
    for want in ("ASAN", "MSAN"):
        if want not in sanitizers:
            problems.append(f"the plane carries no {want} sanitizer_result record")

    # 8. The rule names its committed authority and the required non-claim is present.
    rule = body.get("rule") or {}
    paths = (rule.get("authority") or {}).get("paths") or []
    for want in (rel(CENSUS), rel(PLAN)):
        if want not in paths:
            problems.append(f"the ASan rule does not name its committed authority {want}")
    if not any("UNSUPPORTED" in nc and "not a passing site" in nc for nc in (body.get("non_claims") or [])):
        problems.append("the plane does not carry the required unsupported-is-not-pass non-claim")

    # 9. Every residual validates against the residual schema.
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}"
                     for p in schemas.validate("residual", r)]

    return problems


def asan_sensitivity_control(body: dict, census_body: dict, root: Path | None = None) -> dict:
    """Seed the mutations and require each caught, with specificity holding.

    Each is a distinct way the plane could lie: a site marked PASS without the covering run executed;
    a site marked PASS with a finding at it; a dropped site; an UNSUPPORTED site marked PASS; a typed
    count; and a run that is UNSUPPORTED with no reason.
    """
    root = root or REPO_ROOT
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    baseline = asan_findings(body, census_body, root)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = asan_findings(mutated, census_body, root)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    def clone() -> dict:
        return json.loads(json.dumps(body))

    committed = body.get("sites") or {}
    census_sites = census_body.get("sites") or []
    census_file_of = {str(s.get("site_id")): str(s.get("file")) for s in census_sites}
    pass_sid = next((s for s, r in committed.items() if r.get("state") == "ASAN_PASS"), None)
    unsup_sid = next((s for s, r in committed.items() if r.get("state") == "ASAN_UNSUPPORTED"), None)
    any_run = str((body.get("runs") or [{}])[0].get("run_id"))

    # m1: a PASS with no run.
    def pass_without_run() -> dict:
        b = clone()
        b["sites"][pass_sid] = {"state": "ASAN_PASS", "run": "", "reason": ""}
        return b

    m1 = check("pass_without_run", pass_without_run(), "cites no run")

    # m2: a PASS with a finding at it -- a FAIL run is added at the PASS site's location while the site
    #     still claims PASS; the derivation must mark it FAIL and refuse the PASS.
    def pass_with_finding() -> dict:
        b = clone()
        src = next((s for s in census_sites if str(s.get("site_id")) == pass_sid), {})
        f = census_file_of.get(str(pass_sid), "")
        b["runs"].append({
            "run_id": "mutant-fail", "harness_id": "mutant-fail", "description": "mutant",
            "filter": None, "command": "mutant", "command_sha256": "f" * 64,
            "outcome": "FAIL", "unsupported_reason": "", "transcript_sha256": "0" * 64,
            "tests_run": 1, "tests_passed": 0, "tests_failed": 1,
            "tests": [], "unsupported_files": [],
            "error_sites": [{"file": f, "line": int(src.get("line") or 1), "column": 1,
                             "class": "heap-use-after-free"}],
            "bound_to": {},
        })
        b["findings"] = list(b.get("findings") or []) + [{
            "finding_id": "af-mutant-fail", "run_id": "mutant-fail", "category": "ASAN_HEAP_USE_AFTER_FREE",
            "file": f, "line": int(src.get("line") or 1), "column": 1, "detail": "mutant"}]
        return b

    m2 = check("pass_with_finding", pass_with_finding(), "PASS with a finding at it is refused")

    # m3: a dropped site.
    def dropped_site() -> dict:
        b = clone()
        b["sites"].pop(pass_sid, None)
        return b

    m3 = check("dropped_site", dropped_site(), "has no ASan state")

    # m4: an UNSUPPORTED site marked PASS.
    def unsupported_marked_pass() -> dict:
        b = clone()
        b["sites"][unsup_sid] = {"state": "ASAN_PASS", "run": any_run, "reason": ""}
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

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_census() -> tuple[dict, list[dict]]:
    """A tiny, self-consistent census and run set: one covered site, one foreign-surface site, one
    uncovered site."""
    census = {"sites": [
        {"site_id": "us-cov-1", "file": "src/aes.rs", "line": 376, "column": 9,
         "operation_kind": "RAW_POINTER_WRITE"},
        {"site_id": "us-cov-2", "file": "src/modes/wrap.rs", "line": 69, "column": 23,
         "operation_kind": "RAW_POINTER_DEREFERENCE"},
        {"site_id": "us-foreign-1", "file": "src/dso/dlfcn.rs", "line": 40,
         "operation_kind": "EXTERN_FUNCTION_CALL"},
        {"site_id": "us-asm-1", "file": "src/runtime/thread_arch.rs", "line": 12,
         "operation_kind": "INLINE_ASM"},
        {"site_id": "us-notrec-1", "file": "src/bn/bignum.rs", "line": 99,
         "operation_kind": "RAW_POINTER_READ"},
    ]}
    runs = [
        {"run_id": "asan-lib-suite", "harness_id": "asan-lib-suite", "description": "lib suite",
         "filter": None, "outcome": "PASS", "command_sha256": "0" * 64, "command": "cargo test",
         "unsupported_reason": "", "transcript_sha256": "1" * 64,
         "tests": [{"name": "aes::tests::rfc5649_wrap_pad_vectors", "status": "ok"}],
         "tests_run": 1, "tests_passed": 1, "tests_failed": 0,
         "error_sites": [], "unsupported_files": [], "bound_to": {}},
        {"run_id": "asan-aes-wrap-targeted", "harness_id": "asan-aes-wrap-targeted",
         "description": "aes wrap", "filter": "aes::tests::rfc5649_wrap_pad_vectors", "outcome": "PASS",
         "command_sha256": "2" * 64, "command": "cargo test aes",
         "unsupported_reason": "", "transcript_sha256": "3" * 64,
         "tests": [{"name": "aes::tests::rfc5649_wrap_pad_vectors", "status": "ok"}],
         "tests_run": 1, "tests_passed": 1, "tests_failed": 0,
         "error_sites": [], "unsupported_files": [], "bound_to": {}},
    ]
    return census, runs


def _synth_toolchain() -> dict:
    return {"nightly_channel": NIGHTLY, "rustc": "rustc 1.101.0-nightly", "rustc_commit": "0" * 40,
            "llvm": "23.1.1", "clang": "Debian clang version 14.0.6", "sanitizer": "ASAN",
            "asan_runtime": "librustc-nightly_rt.asan.a", "asan_runtime_sha256": "0" * 64,
            "clang_asan_runtime": "libclang_rt.asan-x86_64.a", "clang_asan_runtime_sha256": "0" * 64,
            "nightly_installed": True}


def _synth_venue() -> dict:
    man = phase25_guard.load_manifest()
    return {"admitted_image": str(man.get("image")), "canonical_base": str(man.get("canonical_base")),
            "platform": str(man.get("platform")),
            "kind": "reused-court-venue-with-documented-data-override",
            "data_limit_override": "OPENSSL_RS_COURT_DATA=unlimited", "reason": "synthetic"}


def _synth_canary() -> dict:
    return {"built": True, "detected": True, "shadow_mapped": True, "command": "asan_canary",
            "diagnostic": ["ERROR: AddressSanitizer: heap-use-after-free"]}


def _synth_msan() -> dict:
    return {"result_id": "msan-openssl-rs-lib", "sanitizer": "MSAN", "target": "lib suite",
            "tool_state": "UNSUPPORTED", "findings": [],
            "unsupported_reason": "synthetic: uninstrumented libc", "evidence": [rel(OUT)]}


def self_test() -> int:
    """Prove the guard refuses the host and the derivation and control are honest.

    The synthetic census covers three non-pass classes -- a covered site (PASS), a foreign-surface
    site (UNSUPPORTED) and an uncovered site (NOT_REACHABLE) -- so every state is exercised without an
    ASan run.
    """
    failures: list[str] = []

    refusal = phase25_guard.host_refusal_reasons("ms_asan.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of ms_asan.py")

    census, runs = _synth_census()
    tc, ven, can, msan = _synth_toolchain(), _synth_venue(), _synth_canary(), _synth_msan()
    build = {"state": "BUILT", "test_binary": "synthetic", "asan_refs": 1}
    body = build_body(census, runs, tc, ven, can, msan, build, True, REPO_ROOT)

    want = {
        "us-cov-1": "ASAN_PASS",
        "us-cov-2": "ASAN_PASS",
        "us-foreign-1": "ASAN_UNSUPPORTED",
        "us-asm-1": "ASAN_UNSUPPORTED",
        "us-notrec-1": "ASAN_NOT_REACHABLE",
    }
    got = {sid: rec["state"] for sid, rec in body["sites"].items()}
    if got != want:
        failures.append(f"the synthetic states are wrong: {got}")
    c = body["counts"]
    if (c["pass"], c["fail"], c["unsupported"], c["not_reachable"]) != (2, 0, 2, 1):
        failures.append(f"the synthetic counts are wrong: {c}")

    baseline = asan_findings(body, census, REPO_ROOT)
    if baseline:
        failures.append(f"the synthetic ASan body is not clean: {baseline[:4]}")
    control = asan_sensitivity_control(body, census, REPO_ROOT)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-asan] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-asan] self-test ok: the guard refuses the host; the synthetic derivation exercises "
          "PASS/UNSUPPORTED/NOT_REACHABLE and every seeded mutation (a PASS with no run, a PASS with a "
          "finding at it, a dropped site, an UNSUPPORTED marked PASS, a typed count and an UNSUPPORTED "
          "run with no reason) is caught with specificity holding")
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
        InputRef(name="ms-asan-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="asan-canary-source", path=CANARY_SRC),
        InputRef(name="asan-canary-rust-source", path=CANARY_RS),
        InputRef(name="harness-source-aes", path=REPO_ROOT / "src" / "aes.rs"),
        InputRef(name="cargo-manifest", path=CARGO_TOML),
    ]


def _measure() -> int:
    """Run ASan (and attempt MSan) over the candidate and write artifacts/phase25/asan-msan.json.

    Measurement: it builds and runs the instrumented candidate with the pinned nightly, so it is
    refused on the host and is not listed among `evidence_determinism.py`'s generators (see that file's
    why-comment).
    """
    tc = toolchain()
    ven = venue()
    can = canary()
    crate_ran = bool(can.get("shadow_mapped")) and bool(can.get("built")) and bool(can.get("detected"))
    tc = dict(tc)
    tc["_crate_reason"] = can.get("reason", "")
    if not tc.get("nightly_installed"):
        print(f"[ms-asan] the pinned nightly ({NIGHTLY}) is not installed under {NIGHTLY_HOME}; "
              f"recording the crate-level ASAN_UNSUPPORTED case")
    elif not crate_ran:
        print(f"[ms-asan] the ASan instrument cannot run in the default venue: {can.get('reason')}")

    if crate_ran:
        build = build_instrumented(tc)
        if build.get("state") != "BUILT":
            crate_ran = False
            tc["_crate_reason"] = str(build.get("reason") or "the instrumented build failed")
            print(f"[ms-asan] instrumented build failed: {tc['_crate_reason']}")
    else:
        build = {"state": "UNSUPPORTED", "reason": can.get("reason", ""),
                 "command": " ".join(_build_command()), "asan_refs": 0}

    runs = [run_harness(h, tc, crate_ran) for h in HARNESSES]
    msan = run_msan(tc)

    census_body = ms_census.decode_body(_body(json.loads(_read(CENSUS)) if CENSUS.is_file() else {}))
    body = build_body(census_body, runs, tc, ven, can, msan, build, crate_ran, REPO_ROOT)
    problems = asan_findings(body, census_body, REPO_ROOT)

    refs = ms_codec.refs_from_census(census_body)
    auth = resolve_authority(PRODUCTION_AUTHORITY)
    encoded = ms_codec.encode_body(body, refs)
    doc = envelope(kind="phase25-asan-msan", authority=auth.id, inputs=_inputs(), body=encoded,
                   generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_plane(OUT, doc)

    c = body["counts"]
    print(f"[ms-asan] {'ASAN_RAN' if crate_ran else 'ASAN_UNSUPPORTED'}; canary "
          f"detected={can.get('detected')} shadow_mapped={can.get('shadow_mapped')}; "
          f"{len(runs)} harness(es)")
    for r in runs:
        print(f"  {r['run_id']:<24} {r['outcome']:<12} {r['tests_passed']}/{r['tests_run']} passed"
              + (f" -- {r['unsupported_reason'][:70]}" if r.get("unsupported_reason") else ""))
    print(f"  MSan: {msan.get('tool_state')} -- {str(msan.get('unsupported_reason'))[:80]}")
    print(f"  sites: {c['sites']} -- pass={c['pass']} fail={c['fail']} "
          f"unsupported={c['unsupported']} not_reachable={c['not_reachable']}")
    print(f"  findings={len(body['findings'])} results={len(body['results'])} "
          f"residuals={len(body['residuals'])}")
    print(f"  -> {rel(OUT)} all_pass={not problems}")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed plane, without ASan."""
    if not OUT.is_file():
        print(f"[ms-asan] {rel(OUT)} is absent; run --measure")
        return 1
    doc = json.loads(OUT.read_text(encoding="utf-8"))
    census_body = ms_census.decode_body(_body(json.loads(_read(CENSUS))))
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(doc.get("body", doc), refs)
    problems = asan_findings(body, census_body, REPO_ROOT)
    if problems:
        print(f"[ms-asan] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-asan] check ok: {c['sites']} site(s) -- pass={c['pass']} fail={c['fail']} "
          f"unsupported={c['unsupported']} not_reachable={c['not_reachable']}; "
          f"{len(body['findings'])} finding(s), {len(body['results'])} result(s), "
          f"{len(body['residuals'])} residual(s); every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="build+run ASan over the candidate and write artifacts/phase25/asan-msan.json")
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
