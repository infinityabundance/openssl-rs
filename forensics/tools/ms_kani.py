#!/usr/bin/env python3
"""openssl-rs — Phase 25.12, Kani.

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). This module is 25.12's instrument: it runs the
**committed Kani proof harnesses** over the exact admitted candidate with the pinned Kani release
and records, honestly, a per-harness disposition from the closed tool-state vocabulary.

What Kani is, and what the plane can honestly claim
---------------------------------------------------
Kani is a **bounded model checker**: a harness states a property over symbolic inputs and Kani
proves it for *all* inputs in the harness's bounded domain (it additionally checks the reachable
path for assertion failure, arithmetic overflow, pointer validity and array bounds). That is a
formal proof over the harness's domain -- **not** a proof about unbounded, concurrent or
whole-program behaviour, and **not** a claim about any target no harness names. The plane carries
one state per *stated harness and its target*, and states this once as `pass_semantics`.

A `PASS` is therefore a claim about a harness, never about a census site. It requires a real Kani
run whose transcript reports the harness's assertions SUCCESSFUL with zero failures; a target Kani
cannot express is `UNSUPPORTED` with its reason, never a pass.

The committed harnesses, and the two honest classes they fall into
------------------------------------------------------------------
The harnesses live in `tests/kani_proofs.rs` (compiled only under `--cfg kani`, so the crate's
ordinary test suite is untouched). They fall into exactly two classes, and the plane records the
class by measurement rather than by assertion:

  * the **pure public surface** proves: `digest::blake2::blake2b::{param_init,
    param_set_personal}` are pure functions that do not cross the FFI panic guard, so Kani compiles
    and proves them (`KANI_PASS`);
  * the **exported FFI surface** is `UNSUPPORTED`: every `extern "C"` entry point runs inside
    `ffi::guard_ffi`, whose `std::panic::catch_unwind` makes Kani 0.68.0 abort with an internal
    compiler error while lowering this nightly's `catch_unwind` intrinsic
    (`kani-compiler/src/intrinsics.rs`: it asserts the intrinsic output is `i32`, and this nightly's
    is not). A harness that reaches the guard -- e.g. `asn1::der::ASN1_object_size`, the ASN.1 length
    path -- cannot even be compiled. The plane records that as `KANI_UNSUPPORTED` with the reason
    and the exact command, and the documented target stays in the tree so the limit is a fact.

The instrument, and the environment it needs
--------------------------------------------
Kani is a heavy tool and is installed into the gitignored `/work` scratch by the documented route
(the upstream `kani-0.68.0` release bundle for `x86_64-unknown-linux-gnu`, plus its pinned toolchain
`nightly-2026-08-21`). The release bundle expects a `toolchain/` symlink into the rustup toolchain
(created by `cargo kani setup`); the tool creates it and the `cargo-kani` plugin symlink itself, and
runs `cargo-kani kani --tests --harness <fn>`. The environment differs from the court's `exec` only
in the Kani bundle and toolchain paths it puts on `PATH`/`LD_LIBRARY_PATH`; it weakens no bound (the
`RLIMIT_DATA` override ASan/TSan need is *not* used here, because Kani's proofs fit the court's
default cap).

Determinism
-----------
`--measure` is byte-for-byte reproducible: the transcript of each run is normalised to its
*decisive* lines (harness name, result token, check counts, and the compiler's error lines on an
`UNSUPPORTED` run), with addresses, thread ids and timings blanked; the tool reuses one target
directory so a warm/cold build does not change the decisive lines; and runs are recorded in the
fixed `HARNESSES` order.

Outputs
-------
  artifacts/phase25/kani.json

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

# The Docker-only execution guard, called first: this tool builds and model-checks the candidate, so
# the manifest does not list it `metadata_only` and a host invocation is refused rather than producing
# unreproducible evidence.
import phase25_guard  # noqa: E402

import memory_safety_schemas as schemas  # noqa: E402

import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "kani.json"
GENERATOR = "forensics/tools/ms_kani.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_kani.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
CARGO_TOML = REPO_ROOT / "Cargo.toml"

# 25.1's compiler-backed source census: the primary unit the plane cross-references its targets to.
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"

# The committed proof harnesses (compiled only under `--cfg kani`), and the crate sources the plane
# names as the harnesses' targets.
HARNESS_SOURCE = REPO_ROOT / "tests" / "kani_proofs.rs"
BLAKE2_SOURCE = REPO_ROOT / "src" / "digest" / "blake2.rs"
DER_SOURCE = REPO_ROOT / "src" / "asn1" / "der.rs"

# Scratch, under the gitignored `/work` tree the brief mandates. The tool refuses on the host, so this
# path only ever exists inside the court. The pinned Kani bundle and toolchain live under /work and
# are never removed.
WORK = Path("/work/court/p25/kani")
KANI_HOME = Path("/work/.phase25-kani")
KANI_VERSION = "0.68.0"
KANI_BUNDLE = KANI_HOME / f"kani-{KANI_VERSION}"
KANI_BIN = KANI_BUNDLE / "bin"
KANI_DRIVER = KANI_BIN / "kani-driver"
KANI_TOOLCHAIN = "nightly-2026-08-21"
RUSTUP_HOME = "/work/.phase25-rustup"
CARGO_HOME = "/work/.phase25-cargo"
KANI_TOOLCHAIN_HOME = Path(RUSTUP_HOME) / "toolchains" / f"{KANI_TOOLCHAIN}-x86_64-unknown-linux-gnu"
PLUGIN_DIR = WORK / "bin"
CARGO_KANI = PLUGIN_DIR / "cargo-kani"
TARGET_DIR = WORK / "target"
MANIFEST_PATH = str(CARGO_TOML)

# The pinned nightly the 25.1 census, 25.9 Miri and 25.10/25.11 sanitizers share; Kani pins its own
# rolder nightly (below) and CBMC ships with the release bundle.
CENSUS_NIGHTLY = "nightly-2026-10-01"
CBMC_VERSION_NOTE = "shipped with the Kani release bundle"

RUN_TIMEOUT = 1500

# The closed state vocabulary this plane records. It is deliberately separate from
# `schemas.TOOL_STATES` only by the `KANI_` prefix; every member maps to one tool state.
SITE_STATES: tuple[str, ...] = ("KANI_PASS", "KANI_FAIL", "KANI_NOT_REACHABLE", "KANI_UNSUPPORTED")

# The reason codes a harness carries. `PASS`/`FAIL` carry the run id in `run` instead; `NOT_REACHABLE`
# and `UNSUPPORTED` carry a reason from this closed set.
REASON_PANIC_GUARD = "KANI_CANNOT_LOWER_THE_CRATE_PANIC_GUARD"
REASON_NOT_VERIFIED = "KANI_HARNESS_DID_NOT_VERIFY"
REASON_NOT_REACHABLE = "NO_COMMITTED_HARNESS_EXECUTED"
REASON_VENUE = "KANI_VENUE_CANNOT_RUN_THE_INSTRUMENT"

# A Kani proof is per-harness: the finest claim the tool makes is "this harness's property holds for
# its domain". The plane states that granularity on every result rather than leaving it implied.
COVERAGE_GRANULARITY = "harness"

# The top-level semantics of a KANI_PASS, stated once for the whole plane. Kani proves only what a
# harness expresses, over its bounded domain, and only where the tool can lower the target.
PASS_SEMANTICS = (
    "KANI_PASS means the named harness was run by the installed Kani (0.68.0, CBMC 6.11.0, its "
    "pinned nightly toolchain) against the exact admitted candidate and the bounded model checker "
    "reported the harness's assertions SUCCESSFUL with zero failures for ALL inputs in the "
    "harness's bounded domain -- a formal proof over that domain, never a claim about unbounded or "
    "concurrent behaviour, and never a claim about any target no harness names; every Kani result "
    "records `coverage_granularity: harness`")

NON_CLAIMS: tuple[str, ...] = (
    "Kani proves only the properties the committed harnesses express, over their bounded domains; a "
    "green harness is not a proof that the crate is memory safe and not a proof about any unharnessed "
    "target",
    "a KANI_UNSUPPORTED target is not a passing target: the tool could not express or compile the "
    "question there, and it is recorded with its reason rather than counted clean",
    "Kani 0.68.0 cannot lower the crate's `ffi::guard_ffi` on its pinned toolchain, whose "
    "`std::panic::catch_unwind` aborts the compiler; every exported `extern \"C\"` entry point runs "
    "inside that guard, so the whole FFI surface is UNSUPPORTED here and the ASN.1 length-path target "
    "is an example, not the only one",
    "a bounded model check is not a whole-program proof: the harnesses here have no concurrency and "
    "unwind every loop to a stated bound, so concurrency, unbounded loops and unbounded heap are "
    "outside what they prove",
    "KANI_NOT_REACHABLE means no committed harness names the target; it is not a clean result",
    "a zero-failure Kani result is trusted only because the deliberate-failure positive control is "
    "known to fire in this venue; the control proves the tool detects a violation, not that the "
    "candidate is correct",
    "the Kani environment is the admitted court image with the Kani bundle and its pinned toolchain "
    "added to PATH/LD_LIBRARY_PATH only; it does not remove the court's per-process RLIMIT_DATA (the "
    "ASan/TSan override) and weakens no bound on resident resources",
)

# The committed harness set: one entry per harness in `tests/kani_proofs.rs`. `role` is the class the
# plane measured the harness to fall into (`proved` or `unsupported`); it is documentation only -- the
# recorded state is derived from the run, never from this field.
HARNESSES: tuple[dict, ...] = (
    {
        "harness_id": "kani-blake2b-param-init",
        "function": "blake2b_param_init_sets_the_documented_prefix",
        "target_file": "src/digest/blake2.rs",
        "target_function": "ossl_blake2b_param_init",
        "role": "proved",
        "property": ("blake2b::param_init always produces the documented parameter prefix "
                     "(digest_length, zero key_length, fanout == 1, depth == 1) over an arbitrary "
                     "64-byte starting block"),
        "domain": "all 64-byte starting parameter blocks",
    },
    {
        "harness_id": "kani-blake2b-param-set-personal",
        "function": "blake2b_param_set_personal_is_bounded_and_zero_filled",
        "target_file": "src/digest/blake2.rs",
        "target_function": "ossl_blake2b_param_set_personal",
        "role": "proved",
        "property": ("blake2b::param_set_personal writes exactly n input bytes followed by "
                     "PERSONALBYTES - n zero bytes and touches no other byte of the parameter block, "
                     "for every n <= PERSONALBYTES (no panic, underflow or overrun)"),
        "domain": "all n in 0..=PERSONALBYTES and all input bytes",
    },
    {
        "harness_id": "kani-asn1-object-size-overhead",
        "function": "asn1_object_size_always_has_encoding_overhead",
        "target_file": "src/asn1/der.rs",
        "target_function": "ASN1_object_size",
        "role": "unsupported",
        "property": ("ASN1_object_size answers a size at least a tag octet and a length octet larger "
                     "than any non-negative content length it accepts"),
        "domain": "all c_int constructed/length/tag",
    },
    {
        "harness_id": "kani-asn1-object-size-negative-length",
        "function": "asn1_object_size_rejects_negative_length",
        "target_file": "src/asn1/der.rs",
        "target_function": "ASN1_object_size",
        "role": "unsupported",
        "property": "ASN1_object_size rejects a negative content length with -1",
        "domain": "all c_int constructed/tag",
    },
)

# The positive control: a harness whose assertion is false for every input, so Kani must report it
# FAILED. A no-violation result is trusted only if this control is known to fire.
CANARY: dict = {
    "harness_id": "kani-positive-control",
    "function": "kani_positive_control_deliberate_failure",
    "target_file": "tests/kani_proofs.rs",
    "target_function": "kani_positive_control_deliberate_failure",
    "property": "a deliberate false assertion, which Kani must report FAILED",
    "as_expected": "the harness is reported FAILED (Kani detected the violated assertion)",
}

# Volatile bytes that must never enter the plane: every Kani/CBMC transcript carries the run's solver
# timings, heap/stack addresses and, on an internal compiler error, the panicking thread id. None of
# it is evidence. `--measure` is byte-for-byte reproducible only if these are normalised before the
# transcript is hashed or stored.
_VOLATILE_ADDR = re.compile(r"0x[0-9a-fA-F]+")
_VOLATILE_PID = re.compile(r"\(\d+\) panicked")
_VOLATILE_VTIME = re.compile(r"Verification Time:\s*\d+(?:\.\d+)?s")
_VOLATILE_IN = re.compile(r"\bin \d+(?:\.\d+)?s\b")
# The decisive lines: the harness name, the result token, the check counts, and the compiler's error
# lines (only present on an UNSUPPORTED/internal-error run). Everything else -- the CBMC solver
# progress and timings -- is a function of the machine, not of the candidate, and is dropped.
_DECISIVE = re.compile(
    r"^(Checking harness |VERIFICATION RESULT:|VERIFICATION:-|Manual Harness Summary:"
    r"|Complete - |\*\* \d+ of \d+ failed|error:|assertion failed:|thread 'rustc'|Caused by:)"
)


def _scrub_volatile(text: str) -> str:
    """Blank the per-run addresses, thread ids and timings in one line of tool output."""
    text = _VOLATILE_ADDR.sub("0xADDR", text)
    text = _VOLATILE_PID.sub("(PID) panicked", text)
    text = _VOLATILE_VTIME.sub("Verification Time: Ns", text)
    return _VOLATILE_IN.sub("in Ns", text)


def _normalise_log(text: str) -> str:
    """Canonicalise a Kani transcript so its digest is reproducible run to run.

    The digest is taken over the transcript's *decisive* lines with addresses, thread ids and timings
    blanked, sorted for stability. Every substantive byte -- the harness name, the result and count,
    and the compiler's error lines -- is preserved; only the solver's incidental output is lost.
    """
    kept = [ln.strip() for ln in _scrub_volatile(text).splitlines()
            if _DECISIVE.match(ln.strip())]
    return "\n".join(sorted(kept))


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _run(args: list[str], env: dict | None = None, timeout: int = RUN_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
                          timeout=timeout)


# --------------------------------------------------------------------------------------------
# the toolchain, the environment and the venue
# --------------------------------------------------------------------------------------------

def _kani_env(extra: dict | None = None) -> dict:
    env = dict(os.environ)
    env["RUSTUP_HOME"] = RUSTUP_HOME
    env["CARGO_HOME"] = CARGO_HOME
    env["LD_LIBRARY_PATH"] = f"{KANI_TOOLCHAIN_HOME / 'lib'}:{env.get('LD_LIBRARY_PATH', '')}"
    env["PATH"] = f"{PLUGIN_DIR}:{KANI_BIN}:{KANI_TOOLCHAIN_HOME / 'bin'}:{env.get('PATH', '')}"
    env["CARGO_TARGET_DIR"] = str(TARGET_DIR)
    if extra:
        env.update(extra)
    return env


def ensure_plugin() -> None:
    """Create the two symlinks a release-bundle Kani needs, exactly as `cargo kani setup` would.

    The release bundle resolves `cargo` and the rustc sysroot through a `toolchain/` symlink into the
    rustup toolchain, and expects a `cargo-kani` plugin on `PATH`. Both are derived from the pinned
    bundle and the pinned toolchain, so they are facts of the environment rather than state.
    """
    PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
    link = KANI_BUNDLE / "toolchain"
    if not link.exists() and KANI_TOOLCHAIN_HOME.is_dir():
        link.symlink_to(KANI_TOOLCHAIN_HOME)
    if not CARGO_KANI.exists() and KANI_DRIVER.is_file():
        CARGO_KANI.symlink_to(KANI_DRIVER)


def toolchain() -> dict:
    """The exact pinned Kani and CBMC the measurement used.

    `kani_installed` is a fact, not a hope: if the release bundle (and its `toolchain` symlink) is
    absent the harnesses cannot run and the plane records the crate-level unsupported case instead of
    a pass.
    """
    ensure_plugin()
    env = _kani_env()
    kani_ver = _run([str(KANI_DRIVER), "--version"], env=env, timeout=120).stdout.strip()
    cbmc = KANI_BIN / "cbmc"
    cbmc_ver = (_run([str(cbmc), "--version"], env=env, timeout=120).stdout.strip()
                if cbmc.is_file() else "")
    installed = bool(kani_ver) and KANI_DRIVER.is_file() and (KANI_BUNDLE / "toolchain").exists()
    return {
        "tool": "KANI",
        "kani_version": KANI_VERSION,
        "kani_driver": kani_ver or "unavailable",
        "cbmc": f"CBMC {cbmc_ver}" if cbmc_ver else "unavailable",
        "kani_toolchain": KANI_TOOLCHAIN,
        "kani_rustc": _read(KANI_BUNDLE / "rustc-version").strip() or "unavailable",
        "census_nightly": CENSUS_NIGHTLY,
        "cbmc_version_note": CBMC_VERSION_NOTE,
        "backend": "bounded-model-checking",
        "kani_bundle": str(KANI_BUNDLE),
        "kani_home": str(KANI_HOME),
        "harness_source": rel(HARNESS_SOURCE),
        "harness_source_sha256": sha256_file(HARNESS_SOURCE),
        "kani_installed": installed,
        "note": ("a release-bundle Kani (the upstream kani-0.68.0 tarball and its pinned toolchain "
                 "nightly-2026-08-21) installed into the /work scratch; the crate's own pinned "
                 f"nightly is {CENSUS_NIGHTLY}, so the census and Kani do NOT share one date"),
    }


def venue() -> dict:
    """The environment Kani ran in: the admitted court venue with the Kani bundle on PATH only.

    It records the admitted image and base from the committed manifest, and, honestly, the one
    dimension in which the Kani environment differs from the court's `exec`: the Kani bundle/toolchain
    paths. It removes no resource bound -- in particular it does NOT apply the ASan/TSan
    `OPENSSL_RS_COURT_DATA` override.
    """
    man = phase25_guard.load_manifest()
    return {
        "admitted_image": str(man.get("image")),
        "canonical_base": str(man.get("canonical_base")),
        "platform": str(man.get("platform")),
        "kind": "reused-court-venue-with-recorded-kani-install",
        "environment": str(os.environ.get("PHASE25_IMAGE") or man.get("image")),
        "derived_from": str(man.get("image")),
        "data_limit_override": "",
        "kani_bundle": str(KANI_BUNDLE),
        "kani_toolchain_link": str(KANI_BUNDLE / "toolchain"),
        "ld_library_path": f"{KANI_TOOLCHAIN_HOME / 'lib'}",
        "path_prefix": [str(PLUGIN_DIR), str(KANI_BIN), str(KANI_TOOLCHAIN_HOME / "bin")],
        "cgroup_memory_cap": _cgroup_memory(),
        "reason": (
            "Kani and its CBMC backend are installed into the /work scratch and added to "
            "PATH/LD_LIBRARY_PATH; unlike the ASan and TSan environments this adds no "
            "RLIMIT_DATA override, because a Kani proof fits the court's default per-process cap. The "
            "container cgroup memory cap, PIDs, CPUs and the wall clock are unchanged, so no bound on "
            "resident resources is weakened."),
        "note": ("a derived environment from the one admitted image, recorded rather than a second "
                 "mutable image; openssl-rs-court:1 is not modified"),
    }


def _cgroup_memory() -> str:
    try:
        return Path("/sys/fs/cgroup/memory.max").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"


# --------------------------------------------------------------------------------------------
# running one harness
# --------------------------------------------------------------------------------------------

def run_harness(harness: dict, tc: dict) -> dict:
    """Run one committed harness with Kani and parse its transcript into a run record."""
    run_id = str(harness["harness_id"])
    cmd = [str(CARGO_KANI), "kani", "--tests", "--harness", str(harness["function"]),
           "--manifest-path", MANIFEST_PATH, "--target-dir", str(TARGET_DIR),
           "--output-format", "terse"]
    display = (f"LD_LIBRARY_PATH={_kani_env()['LD_LIBRARY_PATH']} "
               f"RUSTUP_HOME={RUSTUP_HOME} CARGO_HOME={CARGO_HOME} " + " ".join(cmd))
    base = {
        "run_id": run_id,
        "harness_id": run_id,
        "function": harness["function"],
        "target_file": harness["target_file"],
        "target_function": harness["target_function"],
        "command": display,
        "command_sha256": sha256_bytes(display.encode("utf-8")),
        "verification_successful": False,
        "internal_error": False,
    }
    if not tc.get("kani_installed"):
        return dict(base, outcome="UNSUPPORTED",
                    unsupported_reason=(f"the pinned Kani {KANI_VERSION} bundle "
                                        f"({KANI_BUNDLE}) or its toolchain is not installed"),
                    transcript_sha256="unknown")
    WORK.mkdir(parents=True, exist_ok=True)
    try:
        res = _run(cmd, env=_kani_env(), timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return dict(base, outcome="UNSUPPORTED",
                    unsupported_reason=f"the harness exceeded {RUN_TIMEOUT}s", transcript_sha256="unknown")
    log = res.stdout + res.stderr
    (WORK / f"{run_id}.log").write_text(log, encoding="utf-8")
    ice = ("internal compiler error" in log) or ("Kani unexpectedly panicked" in log)
    successful = "VERIFICATION:- SUCCESSFUL" in log
    failed = "VERIFICATION:- FAILED" in log
    if ice:
        outcome = "UNSUPPORTED"
        reason = REASON_PANIC_GUARD
    elif successful and not failed:
        outcome = "PASS"
        reason = ""
    elif failed:
        outcome = "FAIL"
        reason = ""
    else:
        outcome = "UNSUPPORTED"
        reason = REASON_NOT_VERIFIED
    return dict(base,
                outcome=outcome,
                unsupported_reason=reason,
                verification_successful=bool(successful and not failed),
                internal_error=bool(ice),
                exit_code=res.returncode,
                transcript_sha256=sha256_bytes(_normalise_log(log).encode("utf-8")))


# --------------------------------------------------------------------------------------------
# the derived states: one per stated harness and its target
# --------------------------------------------------------------------------------------------

def derived_states(harnesses: tuple[dict, ...], runs: list[dict]) -> dict[str, dict]:
    """The Kani state of every stated harness, derived purely from its run.

    Pure over its inputs: the court re-derives exactly this from the committed artefact's runs and
    the committed harness set, and refuses a committed `.sites` that differs. A harness with no run
    record is `NOT_REACHABLE` -- not a pass.
    """
    by_id = {str(h["harness_id"]): h for h in harnesses}
    run_by_id = {str(r.get("run_id")): r for r in runs}
    out: dict[str, dict] = {}
    for hid, h in by_id.items():
        r = run_by_id.get(hid)
        if r is None:
            out[hid] = {"state": "KANI_NOT_REACHABLE", "run": "", "reason": REASON_NOT_REACHABLE}
            continue
        outcome = str(r.get("outcome"))
        if outcome == "PASS":
            out[hid] = {"state": "KANI_PASS", "run": hid, "reason": ""}
        elif outcome == "FAIL":
            out[hid] = {"state": "KANI_FAIL", "run": hid, "reason": ""}
        else:
            out[hid] = {"state": "KANI_UNSUPPORTED", "run": hid,
                        "reason": str(r.get("unsupported_reason") or REASON_NOT_VERIFIED)}
    return out


def _counts(states: dict[str, dict]) -> dict:
    c = Counter(v["state"] for v in states.values())
    return {
        "harnesses": len(states),
        "pass": c.get("KANI_PASS", 0),
        "fail": c.get("KANI_FAIL", 0),
        "not_reachable": c.get("KANI_NOT_REACHABLE", 0),
        "unsupported": c.get("KANI_UNSUPPORTED", 0),
    }


# --------------------------------------------------------------------------------------------
# findings, results, residuals and the rule
# --------------------------------------------------------------------------------------------

def _findings(runs: list[dict]) -> list[dict]:
    """Every Kani finding, preserved. There is no finding for a PASS or an UNSUPPORTED run."""
    findings: list[dict] = []
    for r in runs:
        if r.get("outcome") != "FAIL":
            continue
        findings.append({
            "finding_id": f"kf-{r['run_id']}",
            "run_id": r["run_id"],
            "category": "KANI_HARNESS_FAILED",
            "file": str(r.get("target_file") or ""),
            "line": 0,
            "column": 0,
            "detail": (f"Kani reported harness {r['run_id']} "
                       f"({r.get('function')}) as FAILED on the exact admitted candidate: the bounded "
                       f"model checker found a counterexample to the harness's assertion. The harness "
                       f"target is {r.get('target_file')}::{r.get('target_function')}; the run "
                       f"transcript is preserved"),
        })
    return findings


def _results(harnesses: tuple[dict, ...], states: dict[str, dict]) -> list[dict]:
    """The `kani_result` records the schema validates: one per stated harness."""
    out: list[dict] = []
    for h in harnesses:
        hid = str(h["harness_id"])
        st = str((states.get(hid) or {}).get("state") or "KANI_UNSUPPORTED")
        tool_state = {"KANI_PASS": "PASS", "KANI_FAIL": "FAIL",
                      "KANI_NOT_REACHABLE": "NOT_REACHABLE",
                      "KANI_UNSUPPORTED": "UNSUPPORTED"}[st]
        reason = str((states.get(hid) or {}).get("reason") or "")
        out.append({
            "result_id": f"kani-{hid}",
            "harness": str(h["function"]),
            "target": f"{h['target_file']}::{h['target_function']}",
            "tool_state": tool_state,
            "coverage_granularity": COVERAGE_GRANULARITY,
            "findings": [f"kf-{hid}"] if st == "KANI_FAIL" else [],
            "unsupported_reason": reason,
            "evidence": [rel(OUT), rel(TOOL), rel(HARNESS_SOURCE)],
        })
    return out


def _residuals(states: dict[str, dict], counts: dict, runs: list[dict]) -> list[dict]:
    residuals: list[dict] = []
    residuals.append({
        "residual_id": "res-kani-harness-coverage",
        "subject": "Kani proves only the stated harnesses and their targets",
        "class": "evidence_missing",
        "disposition": "preserved",
        "detail": ("the plane carries exactly the harnesses committed in tests/kani_proofs.rs and "
                   "makes no claim about any target no harness names; a green harness is not a proof "
                   "that the crate is memory safe"),
        "evidence": [rel(TOOL), rel(HARNESS_SOURCE)],
    })
    residuals.append({
        "residual_id": "res-kani-ffi-panic-guard",
        "subject": "Kani 0.68.0 cannot lower the crate's FFI panic guard",
        "class": "tool_unsupported",
        "disposition": "preserved",
        "detail": ("every exported `extern \"C\"` entry point runs inside `ffi::guard_ffi`, whose "
                   "`std::panic::catch_unwind` makes Kani 0.68.0 abort with an internal compiler "
                   "error while lowering this nightly's `catch_unwind` intrinsic "
                   "(kani-compiler/src/intrinsics.rs: the intrinsic output is asserted to be i32). "
                   "Any harness that reaches the guard cannot be compiled, so the whole FFI surface "
                   "-- including the ASN.1 length path -- is KANI_UNSUPPORTED here, recorded with the "
                   "exact command and message"),
        "evidence": [rel(TOOL), rel(HARNESS_SOURCE), rel(DER_SOURCE)],
    })
    residuals.append({
        "residual_id": "res-kani-bounded",
        "subject": "a Kani proof is bounded, not whole-program",
        "class": "evidence_missing",
        "disposition": "preserved",
        "detail": ("a Kani harness proves its property for all inputs in its bounded domain and "
                   "unwinds every loop to a stated bound; it does not prove unbounded loops, "
                   "unbounded heap or concurrent behaviour, so those are outside what any harness "
                   "here proves"),
        "evidence": [rel(TOOL), rel(HARNESS_SOURCE)],
    })
    residuals.append({
        "residual_id": "res-kani-not-reachable",
        "subject": f"{counts['not_reachable']} KANI_NOT_REACHABLE harness(es)",
        "class": "tool_not_reachable",
        "disposition": "preserved",
        "detail": (f"{counts['not_reachable']} stated harness(es) have no run record; this is not a "
                   f"clean result"),
        "evidence": [rel(TOOL)],
    })
    residuals.append({
        "residual_id": "res-kani-unsupported",
        "subject": f"{counts['unsupported']} KANI_UNSUPPORTED harness(es)",
        "class": "tool_unsupported",
        "disposition": "preserved",
        "detail": (f"{counts['unsupported']} stated harness(es) are KANI_UNSUPPORTED: the tool could "
                   f"not compile or express the target, and each is recorded with its reason rather "
                   f"than counted clean"),
        "evidence": [rel(TOOL), rel(DER_SOURCE)],
    })
    if any(r.get("outcome") == "PASS" for r in runs):
        residuals.append({
            "residual_id": "res-kani-positive-control",
            "subject": "the Kani positive control fires in this venue",
            "class": "evidence_missing",
            "disposition": "preserved",
            "detail": ("a zero-failure result is trusted only because the deliberate-failure control "
                       "is reported FAILED; the control proves the tool detects a violation, not that "
                       "the candidate is correct"),
            "evidence": [rel(TOOL), rel(HARNESS_SOURCE)],
        })
    return residuals


def _rule(tc: dict, ven: dict, crate_ran: bool, can: dict) -> dict:
    return {
        "authority": {
            "kind": "committed-phase25-planes",
            "paths": [rel(PLAN), rel(SCHEMAS), rel(TOOL), rel(MANIFEST), rel(HARNESS_SOURCE),
                      rel(CENSUS)],
            "declaration": (
                "the committed harnesses in tests/kani_proofs.rs are the targets; the committed venue "
                "manifest names the admitted image the Kani environment is derived from; the "
                "committed 25.1 census is the primary unit the targets' files belong to -- no state "
                "is derived from a text scan"),
        },
        "harnesses": [str(h["harness_id"]) for h in HARNESSES],
        "harness_functions": [str(h["function"]) for h in HARNESSES],
        "canary": str(CANARY["function"]),
        "site_states": list(SITE_STATES),
        "coverage_granularity": COVERAGE_GRANULARITY,
        "pass_rule": ("KANI_PASS iff the named harness was run by the installed Kani against the exact "
                      "admitted candidate and the transcript reports its assertions SUCCESSFUL with "
                      "zero failures; the harness cites the run id and the run's command hash"),
        "fail_rule": ("KANI_FAIL iff Kani reported the harness FAILED (a counterexample to its "
                      "assertion); the run id is cited and a finding is preserved"),
        "unsupported_rule": ("KANI_UNSUPPORTED iff Kani could not compile or express the target (e.g. "
                             "the crate's FFI panic guard) or the venue could not run the instrument; "
                             "the reason is recorded"),
        "not_reachable_rule": ("KANI_NOT_REACHABLE iff a stated harness has no run record; it is not a "
                               "clean result"),
        "venue_rule": (
            "the Kani environment is the admitted court image with the pinned Kani bundle and its "
            "toolchain added to PATH/LD_LIBRARY_PATH only; it removes no resource bound and does NOT "
            "apply the ASan/TSan RLIMIT_DATA override"),
        "crate_level": {
            "state": "KANI_RAN" if crate_ran else "KANI_UNSUPPORTED",
            "reason": ("" if crate_ran
                       else ("the Kani instrument did not produce any verdict in this venue; see the "
                             "toolchain, venue and canary records")),
        },
        "venue": ven,
    }


def build_body(harnesses: tuple[dict, ...], runs: list[dict], tc: dict, ven: dict, can: dict,
               crate_ran: bool) -> dict:
    states = derived_states(harnesses, runs)
    counts = _counts(states)
    findings = _findings(runs)
    return {
        "rule": _rule(tc, ven, crate_ran, can),
        "pass_semantics": PASS_SEMANTICS,
        "toolchain": tc,
        "venue": ven,
        "canary": can,
        "harnesses": [
            {"harness_id": str(h["harness_id"]), "function": str(h["function"]),
             "target_file": str(h["target_file"]), "target_function": str(h["target_function"]),
             "role": str(h["role"]), "property": str(h["property"]), "domain": str(h["domain"])}
            for h in harnesses
        ],
        "runs": runs,
        "sites": states,
        "counts": counts,
        "findings": findings,
        "results": _results(harnesses, states),
        "residuals": _residuals(states, counts, runs),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def kani_findings(body: dict, harness_source: str, root: Path | None = None) -> list[str]:
    """Every way the committed Kani plane contradicts the harnesses, the runs or the toolchain.

    Pure over `body` and the committed harness source: it re-derives the per-harness states and
    refuses a committed `.sites` that differs; it refuses a harness with no state, an `UNSUPPORTED`
    harness with no reason, a `PASS` that cites no successful run, a `FAIL` run with no finding, a
    dropped result, a typed count, a result that does not validate, a rule that does not name its
    committed authority, and a `PASS` recorded while the positive control did not fire.
    """
    root = root or REPO_ROOT
    problems: list[str] = []
    body = ms_codec.decode_body(_body(body))

    runs = body.get("runs") or []
    runs_by_id = {str(r.get("run_id")): r for r in runs}
    committed = body.get("sites") or {}

    cl = (body.get("rule") or {}).get("crate_level") or {}
    crate_ran = cl.get("state") == "KANI_RAN"

    # 0. Every stated harness is present, and the harness source names it.
    harness_ids = [str(h.get("harness_id")) for h in HARNESSES]
    if len(set(harness_ids)) != len(harness_ids):
        problems.append("the committed harness set carries a duplicate harness_id")

    # 1. The runs validate.
    for r in runs:
        rid = str(r.get("run_id"))
        if r.get("outcome") not in schemas.TOOL_STATES:
            problems.append(f"run {rid} has an unknown outcome {r.get('outcome')!r}")
        ch = str(r.get("command_sha256") or "")
        if len(ch) != 64 or any(c not in "0123456789abcdef" for c in ch):
            problems.append(f"run {rid} does not carry a sha256 command hash")
        if r.get("outcome") == "UNSUPPORTED" and not r.get("unsupported_reason"):
            problems.append(f"run {rid} is UNSUPPORTED with an empty reason")

    # 2. The derived states are the committed states, with a specific message per disagreement.
    derived = derived_states(HARNESSES, runs)
    for hid in harness_ids:
        want = derived.get(hid)
        got = committed.get(hid)
        if got is None:
            problems.append(f"harness {hid} has no Kani state; a stated harness is never dropped")
            continue
        ws, gs = want["state"], got.get("state")
        if ws == gs:
            continue
        if ws == "KANI_UNSUPPORTED" and gs == "KANI_PASS":
            problems.append(f"harness {hid} records KANI_PASS for a target the derivation marks "
                            f"UNSUPPORTED; UNSUPPORTED is not PASS")
        elif gs == "KANI_PASS":
            problems.append(f"harness {hid} claims KANI_PASS but the derivation marks it {ws}; a "
                            f"pass with no successful run is refused")
        else:
            problems.append(f"harness {hid}: committed state {gs} != derived {ws}")
    extra = set(committed) - set(harness_ids)
    if extra:
        problems.append(f"the Kani plane carries {len(extra)} harness(es) not in the committed set")

    # 3. Every state is closed; UNSUPPORTED carries a reason.
    for hid, rec in committed.items():
        st = rec.get("state")
        if st not in SITE_STATES:
            problems.append(f"harness {hid} has an unknown state {st!r}")
        if st == "KANI_UNSUPPORTED" and not rec.get("reason"):
            problems.append(f"harness {hid} is KANI_UNSUPPORTED but records no reason; refusing to "
                            f"say why is refusing the evidence")

    # 4. A PASS cites a successful run; a FAIL run has a finding.
    for hid, rec in committed.items():
        st = rec.get("state")
        if st == "KANI_PASS":
            run = runs_by_id.get(str(rec.get("run") or ""))
            if run is None:
                problems.append(f"KANI_PASS harness {hid} cites no run")
            elif run.get("outcome") != "PASS" or not run.get("verification_successful"):
                problems.append(f"KANI_PASS harness {hid} cites run {run.get('run_id')}, which did "
                                f"not report a successful verification")
        elif st == "KANI_FAIL":
            run = runs_by_id.get(str(rec.get("run") or ""))
            if run is None or run.get("outcome") != "FAIL":
                problems.append(f"KANI_FAIL harness {hid} cites no failing run")
    findings = body.get("findings") or []
    finding_runs = {str(f.get("run_id")) for f in findings}
    for r in runs:
        if r.get("outcome") == "FAIL" and str(r.get("run_id")) not in finding_runs:
            problems.append(f"run {r.get('run_id')} failed but no finding records it; a Kani failure "
                            f"is preserved, never dropped")
    for f in findings:
        if str(f.get("run_id")) not in runs_by_id:
            problems.append(f"finding {f.get('finding_id')} cites run {f.get('run_id')!r}, which is "
                            f"not a committed run")

    # 5. The counts are derived, not typed.
    if body.get("counts") != _counts(derived):
        problems.append("the committed `counts` is not the derived `counts`")

    # 6. The toolchain, the venue, the canary and the crate-level case are recorded.
    tcv = body.get("toolchain") or {}
    if tcv.get("tool") != "KANI" or not tcv.get("kani_version") or not tcv.get("kani_driver"):
        problems.append("the Kani toolchain is not recorded")
    if str(tcv.get("harness_source_sha256") or "") != sha256_file(HARNESS_SOURCE):
        problems.append("the recorded harness-source digest does not match tests/kani_proofs.rs; a "
                        "run whose committed harness has moved is refused")
    venv = body.get("venue") or {}
    for key in ("admitted_image", "canonical_base", "kani_bundle"):
        if not venv.get(key):
            problems.append(f"the Kani venue does not record {key}")
    if venv.get("data_limit_override"):
        problems.append("the Kani venue records a data_limit_override; Kani does not need one")
    can = body.get("canary") or {}
    if not can.get("built"):
        problems.append("the Kani positive control is not recorded as built; a no-violation result is "
                        "trusted only if the tool is known to detect a violation")
    elif crate_ran and not can.get("detected"):
        problems.append("the crate-level state is KANI_RAN but the positive control did not fire")
    if cl.get("state") not in ("KANI_RAN", "KANI_UNSUPPORTED"):
        problems.append("the crate-level Kani case is not recorded")
    if cl.get("state") == "KANI_UNSUPPORTED" and not cl.get("reason"):
        problems.append("the crate-level Kani case is KANI_UNSUPPORTED but carries no reason")
    if not crate_ran:
        for hid, rec in committed.items():
            if rec.get("state") == "KANI_PASS":
                problems.append(f"harness {hid} records KANI_PASS but the crate-level Kani case is "
                                f"UNSUPPORTED; a pass requires the instrument to be known to fire")

    # 7. The harness source names every committed harness function; the kani_result records validate.
    for h in HARNESSES:
        if f"fn {h['function']}" not in harness_source:
            problems.append(f"the committed harness source does not define {h['function']}")
    if f"fn {CANARY['function']}" not in harness_source:
        problems.append(f"the committed harness source does not define the control "
                        f"{CANARY['function']}")
    results = body.get("results") or []
    for r in results:
        problems += [f"result[{r.get('result_id')}]: {p}"
                     for p in schemas.validate("kani_result", r)]
    if not results:
        problems.append("the plane carries no kani_result record")
    for r in results:
        if str(r.get("coverage_granularity")) != COVERAGE_GRANULARITY:
            problems.append(f"Kani result {r.get('result_id')} does not record its coverage "
                            f"granularity (`{COVERAGE_GRANULARITY}`)")
    if not str(body.get("pass_semantics") or "").strip():
        problems.append("the plane does not carry its top-level `pass_semantics` statement")

    # 8. The rule names its committed authority and the required non-claims are present.
    rule = body.get("rule") or {}
    paths = (rule.get("authority") or {}).get("paths") or []
    for want in (rel(PLAN), rel(TOOL), rel(HARNESS_SOURCE)):
        if want not in paths:
            problems.append(f"the Kani rule does not name its committed authority {want}")
    if list(rule.get("site_states") or []) != list(SITE_STATES):
        problems.append("the Kani rule does not record the closed site-state vocabulary")
    if str(rule.get("coverage_granularity")) != COVERAGE_GRANULARITY:
        problems.append("the Kani rule does not record the coverage granularity")
    ncs = body.get("non_claims") or []
    if not any("UNSUPPORTED" in nc and "not a passing target" in nc for nc in ncs):
        problems.append("the plane does not carry the required unsupported-is-not-pass non-claim")
    if not any("guard_ffi" in nc for nc in ncs):
        problems.append("the plane does not carry the FFI-panic-guard non-claim")

    # 9. Every residual validates against the residual schema.
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}"
                     for p in schemas.validate("residual", r)]

    return problems


def kani_sensitivity_control(body: dict, harness_source: str, root: Path | None = None) -> dict:
    """Seed the mutations and require each caught, with specificity holding.

    Each is a distinct way the plane could lie: a harness marked PASS with no successful run; an
    UNSUPPORTED target marked PASS; a dropped harness; a typed count; an UNSUPPORTED run with no
    reason; a FAIL run with no finding; a crate-level UNSUPPORTED with no reason; and a PASS
    recorded while the positive control did not fire.
    """
    root = root or REPO_ROOT
    body = ms_codec.decode_body(_body(body))
    baseline = kani_findings(body, harness_source, root)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = kani_findings(mutated, harness_source, root)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    def clone() -> dict:
        return json.loads(json.dumps(body))

    committed = body.get("sites") or {}
    pass_hid = next((h for h, r in committed.items() if r.get("state") == "KANI_PASS"), None)
    unsup_hid = next((h for h, r in committed.items() if r.get("state") == "KANI_UNSUPPORTED"), None)
    any_run = str((body.get("runs") or [{}])[0].get("run_id"))

    # m1: a PASS whose run did not report a successful verification.
    def pass_without_run() -> dict:
        b = clone()
        for r in b["runs"]:
            if r.get("run_id") == pass_hid:
                r["verification_successful"] = False
        return b

    m1 = check("pass_without_successful_run", pass_without_run(),
               "did not report a successful verification")

    # m2: an UNSUPPORTED harness marked PASS.
    def unsupported_marked_pass() -> dict:
        b = clone()
        b["sites"][unsup_hid] = {"state": "KANI_PASS", "run": any_run, "reason": ""}
        return b

    m2 = check("unsupported_marked_pass", unsupported_marked_pass(), "UNSUPPORTED is not PASS")

    # m3: a dropped harness.
    def dropped_harness() -> dict:
        b = clone()
        b["sites"].pop(pass_hid, None)
        return b

    m3 = check("dropped_harness", dropped_harness(), "has no Kani state")

    # m4: a typed count.
    def typed_count() -> dict:
        b = clone()
        b["counts"]["pass"] += 1
        return b

    m4 = check("typed_count", typed_count(), "not the derived `counts`")

    # m5: an UNSUPPORTED run with no reason.
    def unsupported_without_reason() -> dict:
        b = clone()
        for r in b["runs"]:
            if r.get("outcome") == "UNSUPPORTED":
                r["unsupported_reason"] = ""
        return b

    m5 = check("unsupported_without_reason", unsupported_without_reason(),
               "UNSUPPORTED with an empty reason")

    # m6: a FAIL run with no finding.
    def fail_without_finding() -> dict:
        b = clone()
        if pass_hid is not None:
            b["sites"][pass_hid] = {"state": "KANI_FAIL", "run": pass_hid, "reason": ""}
        for r in b["runs"]:
            if r.get("run_id") == pass_hid:
                r["outcome"] = "FAIL"
                r["verification_successful"] = False
        b["findings"] = []
        return b

    m6 = check("fail_without_finding", fail_without_finding(), "no finding records it")

    # m7: a crate-level UNSUPPORTED with no reason.
    def crate_unsupported_without_reason() -> dict:
        b = clone()
        b["rule"]["crate_level"] = {"state": "KANI_UNSUPPORTED", "reason": ""}
        return b

    m7 = check("crate_unsupported_without_reason", crate_unsupported_without_reason(),
               "carries no reason")

    # m8: a PASS recorded while the positive control did not fire.
    def pass_without_control() -> dict:
        b = clone()
        b["canary"]["detected"] = False
        return b

    m8 = check("pass_without_control", pass_without_control(), "positive control did not fire")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and m7 and m8
                                        and pass_hid is not None and unsup_hid is not None
                                        and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_runs() -> tuple[list[dict], dict]:
    """A self-consistent run set: the two pure harnesses PASS, the two FFI harnesses UNSUPPORTED,
    and the control fires."""
    runs: list[dict] = []
    for h in HARNESSES:
        if h["role"] == "proved":
            runs.append({"run_id": h["harness_id"], "harness_id": h["harness_id"],
                         "function": h["function"], "target_file": h["target_file"],
                         "target_function": h["target_function"], "command": "kani",
                         "command_sha256": "0" * 64, "outcome": "PASS",
                         "unsupported_reason": "", "verification_successful": True,
                         "internal_error": False, "transcript_sha256": "1" * 64})
        else:
            runs.append({"run_id": h["harness_id"], "harness_id": h["harness_id"],
                         "function": h["function"], "target_file": h["target_file"],
                         "target_function": h["target_function"], "command": "kani",
                         "command_sha256": "0" * 64, "outcome": "UNSUPPORTED",
                         "unsupported_reason": REASON_PANIC_GUARD, "verification_successful": False,
                         "internal_error": True, "transcript_sha256": "1" * 64})
    canary = {"built": True, "detected": True, "outcome": "FAIL", "command": "kani",
              "command_sha256": "2" * 64}
    return runs, canary


def _synth_toolchain() -> dict:
    return {"tool": "KANI", "kani_version": KANI_VERSION, "kani_driver": "Kani Rust Verifier 0.68.0",
            "cbmc": "CBMC 6.11.0", "kani_toolchain": KANI_TOOLCHAIN,
            "kani_rustc": "rustc 1.100.0-nightly", "census_nightly": CENSUS_NIGHTLY,
            "backend": "bounded-model-checking", "kani_bundle": str(KANI_BUNDLE),
            "harness_source": rel(HARNESS_SOURCE),
            "harness_source_sha256": sha256_file(HARNESS_SOURCE), "kani_installed": True}


def _synth_venue() -> dict:
    man = phase25_guard.load_manifest()
    return {"admitted_image": str(man.get("image")), "canonical_base": str(man.get("canonical_base")),
            "platform": str(man.get("platform")),
            "kind": "reused-court-venue-with-recorded-kani-install",
            "data_limit_override": "", "kani_bundle": str(KANI_BUNDLE), "reason": "synthetic"}


def self_test() -> int:
    """Prove the guard refuses the host and the derivation and control are honest.

    The synthetic run set exercises every state without a Kani run: two covered harnesses (PASS), two
    FFI-surface harnesses (UNSUPPORTED), and a firing control.
    """
    failures: list[str] = []

    refusal = phase25_guard.host_refusal_reasons("ms_kani.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of ms_kani.py")

    runs, canary = _synth_runs()
    tc, ven = _synth_toolchain(), _synth_venue()
    body = build_body(HARNESSES, runs, tc, ven, canary, True)

    want = {"kani-blake2b-param-init": "KANI_PASS",
            "kani-blake2b-param-set-personal": "KANI_PASS",
            "kani-asn1-object-size-overhead": "KANI_UNSUPPORTED",
            "kani-asn1-object-size-negative-length": "KANI_UNSUPPORTED"}
    got = {hid: rec["state"] for hid, rec in body["sites"].items()}
    if got != want:
        failures.append(f"the synthetic states are wrong: {got}")
    c = body["counts"]
    if (c["pass"], c["fail"], c["unsupported"], c["not_reachable"], c["harnesses"]) != (2, 0, 2, 0, 4):
        failures.append(f"the synthetic counts are wrong: {c}")

    harness_source = _read(HARNESS_SOURCE)
    baseline = kani_findings(body, harness_source, REPO_ROOT)
    if baseline:
        failures.append(f"the synthetic Kani body is not clean: {baseline[:4]}")
    control = kani_sensitivity_control(body, harness_source, REPO_ROOT)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-kani] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-kani] self-test ok: the guard refuses the host; the synthetic derivation exercises "
          "PASS/UNSUPPORTED over the stated harnesses and every seeded mutation (a PASS with no "
          "successful run, an UNSUPPORTED marked PASS, a dropped harness, a typed count, an "
          "UNSUPPORTED run with no reason, a FAIL with no finding, a crate-level UNSUPPORTED with no "
          "reason and a PASS with no positive control) is caught with specificity holding")
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
        InputRef(name="ms-kani-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="kani-harness-source", path=HARNESS_SOURCE),
        InputRef(name="kani-target-blake2-source", path=BLAKE2_SOURCE),
        InputRef(name="kani-target-der-source", path=DER_SOURCE),
        InputRef(name="cargo-manifest", path=CARGO_TOML),
    ]


def _measure() -> int:
    """Run the committed Kani harnesses and write artifacts/phase25/kani.json.

    Measurement: it model-checks the exact admitted candidate with the pinned Kani release, so it is
    refused on the host and is not listed among `evidence_determinism.py`'s generators (see that
    file's why-comment). All runs reuse one target directory under the scratch so a warm/cold build
    does not change the decisive transcript lines -- which is what makes two `--measure` runs
    byte-for-byte identical.
    """
    tc = toolchain()
    ven = venue()
    crate_ran = bool(tc.get("kani_installed"))
    if not crate_ran:
        print(f"[ms-kani] the pinned Kani bundle ({KANI_BUNDLE}) or its toolchain is not installed; "
              f"recording the crate-level KANI_UNSUPPORTED case")

    runs = [run_harness(h, tc) for h in HARNESSES]
    canary_run = run_harness(CANARY, tc)
    detected = canary_run.get("outcome") == "FAIL"
    can = {
        "harness_id": str(CANARY["harness_id"]),
        "function": str(CANARY["function"]),
        "built": canary_run.get("outcome") != "UNSUPPORTED",
        "detected": bool(detected),
        "outcome": str(canary_run.get("outcome")),
        "as_expected": str(CANARY["as_expected"]),
        "command_sha256": str(canary_run.get("command_sha256")),
        "reason": ("" if detected else
                   "the deliberate-failure control was not reported FAILED; a no-violation result is "
                   "not trusted"),
    }
    crate_ran = crate_ran and any(r.get("outcome") in ("PASS", "FAIL") for r in runs)

    body = build_body(HARNESSES, runs, tc, ven, can, crate_ran)
    problems = kani_findings(body, _read(HARNESS_SOURCE), REPO_ROOT)

    refs = ms_codec.refs_from_census(ms_census.decode_body(_body(json.loads(_read(CENSUS)))
                                                           if CENSUS.is_file() else {}))
    auth = resolve_authority(PRODUCTION_AUTHORITY)
    encoded = ms_codec.encode_body(body, refs)
    doc = envelope(kind="phase25-kani", authority=auth.id, inputs=_inputs(), body=encoded,
                   generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_plane(OUT, doc)

    c = body["counts"]
    print(f"[ms-kani] {'KANI_RAN' if crate_ran else 'KANI_UNSUPPORTED'}; control "
          f"built={can['built']} detected={can['detected']}; {len(runs)} harness(es)")
    for r in runs:
        print(f"  {r['run_id']:<40} {r['outcome']:<12}"
              + (f" -- {r['unsupported_reason'][:60]}" if r.get("unsupported_reason") else ""))
    print(f"  harnesses: {c['harnesses']} -- pass={c['pass']} fail={c['fail']} "
          f"unsupported={c['unsupported']} not_reachable={c['not_reachable']}")
    print(f"  findings={len(body['findings'])} results={len(body['results'])} "
          f"residuals={len(body['residuals'])}")
    print(f"  -> {rel(OUT)} all_ok={not problems} body_hash={doc['body_hash'][:16]}")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed plane, without Kani."""
    if not OUT.is_file():
        print(f"[ms-kani] {rel(OUT)} is absent; run --measure")
        return 1
    doc = json.loads(OUT.read_text(encoding="utf-8"))
    body = ms_codec.decode_body(_body(doc.get("body", doc)))
    problems = kani_findings(body, _read(HARNESS_SOURCE), REPO_ROOT)
    if problems:
        print(f"[ms-kani] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-kani] check ok: {c['harnesses']} harness(es) -- pass={c['pass']} fail={c['fail']} "
          f"unsupported={c['unsupported']} not_reachable={c['not_reachable']}; "
          f"{len(body['findings'])} finding(s), {len(body['results'])} result(s), "
          f"{len(body['residuals'])} residual(s); every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="run the committed Kani harnesses and write artifacts/phase25/kani.json")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed plane")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the guard refuses the host and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first: this tool model-checks the candidate.
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
