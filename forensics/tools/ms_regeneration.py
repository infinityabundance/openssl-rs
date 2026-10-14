#!/usr/bin/env python3
"""Phase 25.19 -- the full clean regeneration.

Re-runs the *measurement* planes of the memory-safety stratum from the frozen candidate and the
frozen toolchain and records, as evidence, that each plane still binds the **current** venue
manifest and still reproduces its **evidence** on a second `--measure`, so the atlas is
*reproducible* rather than assembled, and a `PASS` that does not survive the regeneration is a
finding.

Why this exists
---------------
Every measurement plane the stratum ships records `forensics/memory-safety/container.json` as an
input, by content-addressed digest:

  * `artifacts/phase25/source-census.json`           (25.1, `ms_census.py`)
  * `artifacts/phase25/non-rust-tcb.json`            (25.2, `ms_non_rust_tcb.py`)
  * `artifacts/phase25/miri.json`                    (25.9, `ms_miri.py`)
  * `artifacts/phase25/asan-msan.json`               (25.10, `ms_asan.py`)
  * `artifacts/phase25/tsan.json`                    (25.11, `ms_tsan.py`)
  * `artifacts/phase25/kani.json`                    (25.12, `ms_kani.py`)
  * `artifacts/phase25/cve-replay/index.json`        (25.16, `ms_cve_replay.py`)

The manifest gained `environment_derivations` as 25.10-25.16 landed their instruments, so the
planes measured before those derivations landed now bind a **superseded** manifest hash. That is not
a semantic error in any plane, but it is exactly the kind of drift that makes an atlas "assembled"
rather than "reproduced": a reader cannot recompute the planes from the current manifest and expect
the committed bytes. 25.19 closes it by **re-running** each plane's own `--measure` (never editing a
plane by hand) and confirming the identity holds on a second run.

What "reproducible" means here, precisely
-----------------------------------------
A measurement plane is not a pure function of committed inputs: it runs a compiler, a sanitizer, a
model checker or a CVE replay, so its bytes carry the run itself. The stratum already separates the
two: the tools hash their evidence into `body_hash` and normalise the run's incidental bytes (ASan,
TSan and Kani blank the process ids, addresses and durations in the transcript they hash; the
census, non-Rust TCB, Kani and CVE-replay planes record the raw compiler streams they derived from as
**pathless inputs** with a note, outside `body_hash`). 25.19 therefore verifies two identities per
plane and records both:

  * **`reproduced`** -- the plane's *evidence* reproduces: its `body`, with the fields the plane
    declares as **per-run** normalised, is byte-identical between the committed plane and this run's
    re-measure. This is the determinism claim.
  * **`bytes_identical`** -- the whole artefact, envelope and all, is byte-identical. It is recorded
    as a fact but is **not** the claim: an envelope legitimately differs in the pathless non-committed
    inputs a tool records (e.g. the raw clippy JSON stream) and in Miri's raw transcript digest, which
    `ms_miri.py` records verbatim where its ASan/TSan/Kani siblings normalise theirs. Where the two
    disagree the plane names the exact per-run fields, so a reader sees what is incidental and what
    is evidence.

For each plane, in dependency order, this tool:

  1. records the plane's **evidence** digest *before* the re-run (the committed plane -- the first
     `--measure`'s output) and *after* (this run -- the second `--measure`);
  2. records the plane's own `--measure` **exit code**, so "the generator was re-run" is a fact with
     an outcome rather than an assertion;
  3. reads back the manifest digest the plane now records and requires it to be the **current**
     manifest -- a plane still binding a superseded digest is refused by name;
  4. records whether the plane's evidence survived from the last commit (`git show HEAD:`), so a
     `PASS` that does not survive the regeneration is a *finding* rather than a silent change;
  5. requires `reproduced == (evidence_before == evidence_after)`: a determinism claim is only
     admitted when the second run actually exists and its evidence digest equals the first's.

It is a **measurement tool that orchestrates the re-runs**: it executes the compiler, Miri, ASan,
TSan, Kani and the CVE-replay compiles (through each plane's own `--measure`, never a second
implementation of any of them), so the manifest does **not** list it `metadata_only`, the guard
refuses a host invocation, and it follows the `ms_census.py`/`ms_asan.py` measurement precedent --
`evidence_determinism.py` documents it as such and does not list it among its generators, because a
tool that re-runs the sanitizers is not a pure function of committed inputs. The pure checks the
`MS-CLEAN-REGEN` court runs (`regen_findings` and `regen_sensitivity_control`) read only the
committed `artifacts/phase25/regeneration.json` and the committed manifest -- no compiler, no tool.

Venue
-----
ASan and TSan need the manifest's own documented per-process `RLIMIT_DATA` override
(`OPENSSL_RS_COURT_DATA=unlimited`); every other plane fits the court's default 4 GiB cap. The
orchestrator must be launched inside the court with `OPENSSL_RS_COURT_DATA=unlimited` (as the
`OPENSSL_RS_COURT_DATA=unlimited bash docker/openssl-rs-court.sh exec ...` shape), and it lowers the
per-process `RLIMIT_DATA` back to the court's default for every plane that does **not** carry the
override, so each plane runs in exactly the venue its own subphase admitted. If the orchestrator's
hard limit is bounded, it records the ASan/TSan planes un-re-measured with that exact reason and a
stale-bound residual -- it never silently accepts them.

Usage:
  OPENSSL_RS_COURT_DATA=unlimited python3 forensics/tools/ms_regeneration.py --measure
  python3 forensics/tools/ms_regeneration.py --check       # re-run the pure checks
  python3 forensics/tools/ms_regeneration.py --self-test   # guard refusal + control
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import resource
import subprocess
import sys
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
)

# The Docker-only execution guard, called first. This tool executes compilers and sanitizers, so the
# manifest does not list it `metadata_only` and a host invocation is refused.
import phase25_guard  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "regeneration.json"
GENERATOR = "forensics/tools/ms_regeneration.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_regeneration.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

MANIFEST_REL = "forensics/memory-safety/container.json"

# The court's documented default per-process RLIMIT_DATA (`docker/openssl-rs-court.sh`,
# `OPENSSL_RS_COURT_DATA` default), in KiB. A plane that carries no override runs under this cap even
# when the orchestrator itself was launched with the wider one.
DEFAULT_RLIMIT_DATA_KIB = 4194304
DEFAULT_RLIMIT_DATA_BYTES = DEFAULT_RLIMIT_DATA_KIB * 1024

# The manifest's documented per-process data override ASan and TSan need, verbatim.
DATA_OVERRIDE = "OPENSSL_RS_COURT_DATA=unlimited"

_PER_RUN_MARKER = "<per-run-byte>"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# The per-run fields a plane records **inside its `body`** (as opposed to the pathless non-committed
# inputs it records in its envelope). `transcript_sha256` in Miri's `runs` table is the digest of the
# raw Miri transcript, which carries the run's process id, its allocated addresses and its durations:
# exactly the bytes ASan, TSan and Kani blank before hashing theirs, and Miri does not. 25.19 declares
# it per-run here rather than editing 25.9's instrument; where a plane records no per-run body field,
# it contributes none. Given as `(columnar table, column)`.
PER_RUN_BODY: dict[str, tuple[tuple[str, str], ...]] = {
    "artifacts/phase25/miri.json": (("runs", "transcript_sha256"),),
}

# The build-product fields a plane records **inside its `body`**: the instrumented test binary ASan
# and TSan build, whose path carries cargo's build fingerprint and whose bytes are not reproducible
# across builds. A build product is by definition not evidence -- `evidence_determinism.py` normalises
# the same class for `implemented-surface.json` (`crate-archive`/`extra-object`) -- so 25.19 declares
# these by dotted scalar path and normalises them. Given as dotted `body.<key>...` paths.
BUILD_PRODUCT_BODY: dict[str, tuple[str, ...]] = {
    "artifacts/phase25/asan-msan.json": ("instrumentation.test_binary",
                                         "instrumentation.test_binary_sha256",
                                         "instrumentation.test_binary_bytes"),
    "artifacts/phase25/tsan.json": ("instrumentation.test_binary",
                                    "instrumentation.test_binary_sha256",
                                    "instrumentation.test_binary_bytes"),
}

# The ordered clean-regeneration procedure: the measurement planes, in dependency order, each with
# the subphase that owns it, the tool that regenerates it, the documented environment its own
# subphase admitted, the planes it consumes (all regenerated before it here), and the per-run body
# columns it records.
PROCEDURE: tuple[dict, ...] = (
    {
        "plane": "artifacts/phase25/source-census.json",
        "tool": "forensics/tools/ms_census.py",
        "subphase": "25.1",
        "env": "",
        "depends_on": [],
    },
    {
        "plane": "artifacts/phase25/non-rust-tcb.json",
        "tool": "forensics/tools/ms_non_rust_tcb.py",
        "subphase": "25.2",
        "env": "",
        "depends_on": ["artifacts/phase25/source-census.json"],
    },
    {
        "plane": "artifacts/phase25/miri.json",
        "tool": "forensics/tools/ms_miri.py",
        "subphase": "25.9",
        "env": "",
        "depends_on": ["artifacts/phase25/source-census.json"],
    },
    {
        "plane": "artifacts/phase25/asan-msan.json",
        "tool": "forensics/tools/ms_asan.py",
        "subphase": "25.10",
        "env": DATA_OVERRIDE,
        "depends_on": ["artifacts/phase25/source-census.json"],
    },
    {
        "plane": "artifacts/phase25/tsan.json",
        "tool": "forensics/tools/ms_tsan.py",
        "subphase": "25.11",
        "env": DATA_OVERRIDE,
        "depends_on": ["artifacts/phase25/source-census.json"],
    },
    {
        "plane": "artifacts/phase25/kani.json",
        "tool": "forensics/tools/ms_kani.py",
        "subphase": "25.12",
        "env": "",
        "depends_on": ["artifacts/phase25/source-census.json"],
    },
    {
        "plane": "artifacts/phase25/cve-replay/index.json",
        "tool": "forensics/tools/ms_cve_replay.py",
        "subphase": "25.16",
        "env": "",
        "depends_on": ["artifacts/phase25/non-rust-tcb.json"],
    },
)

PROCEDURE_PLANES: tuple[str, ...] = tuple(p["plane"] for p in PROCEDURE)

# The residual classes this tool can record: a leftover the regeneration did not close.
RESIDUAL_CLASS_STALE_BINDING = "stale_manifest_binding"
RESIDUAL_CLASS_NOT_RE_RUN = "plane_not_re_measured"
RESIDUAL_CLASS_NOT_REPRODUCIBLE = "evidence_not_reproducible"
RESIDUAL_CLASS_NONZERO_EXIT = "generator_exit_nonzero"

NON_CLAIMS = (
    "a passing regeneration records that the measurement planes were re-run from the frozen "
    "candidate and the frozen toolchain, that each now binds the current venue manifest and that "
    "each reproduced its evidence on a second run; it is a reproducibility statement, never a "
    "memory-safety claim, and it is never read as 'the candidate is memory safe'",
    "the determinism claim is on each plane's *evidence* (its `body`, with the per-run fields the "
    "plane declares normalised), not on its whole envelope: a plane's envelope legitimately differs "
    "in the pathless non-committed inputs a tool records, so `bytes_identical` is recorded as a fact "
    "and never read as the claim",
    "it re-runs the planes' own `--measure` and never edits a plane by hand, so it can neither "
    "widen nor narrow what a plane reports; the planes' own findings survive the regeneration "
    "unchanged, and a `PASS` that did not survive is recorded as a finding rather than suppressed",
    "a plane whose instrument the venue cannot run is recorded un-re-measured with its exact reason "
    "and an open residual, never silently accepted and never counted clean; the `MS-CLEAN-REGEN` "
    "court refuses such a plane that is not so recorded",
    "reproducibility is not reproducibility across venues: it shows the committed evidence is what "
    "the toolchain on the admitted base derives, not that a different toolchain or machine would "
    "derive the same evidence",
    "the regeneration re-runs the measurement planes; it does not re-run the pure derivation planes "
    "(25.3-25.8, 25.13-25.15, 25.17-25.18), which `evidence_determinism.py` already re-derives from "
    "committed inputs without a compiler",
)


# --------------------------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _manifest_digest() -> str:
    return _sha(_read(MANIFEST))


def _plane_binding(text: str) -> str:
    """The container.json digest a plane's `inputs` records, or `` when it records none."""
    if not text:
        return ""
    try:
        doc = json.loads(text)
    except ValueError:
        return ""
    for entry in doc.get("inputs") or []:
        if str(entry.get("path") or "").endswith(MANIFEST_REL):
            return str(entry.get("sha256") or "")
    return ""


def _plane_meta(text: str) -> tuple[str, str, str]:
    """`(generator, kind, body_hash)` a plane records, for the evidence record."""
    if not text:
        return "", "", ""
    try:
        doc = json.loads(text)
    except ValueError:
        return "", "", ""
    return (str(doc.get("generator") or ""), str(doc.get("kind") or ""),
            str(doc.get("body_hash") or ""))


def _per_run_fields(relpath: str) -> list[str]:
    return [f"body.{table}.rows[*].{c}" for table, c in PER_RUN_BODY.get(relpath, ())]


def _build_product_fields(relpath: str) -> list[str]:
    return [f"body.{p}" for p in BUILD_PRODUCT_BODY.get(relpath, ())]


def _blank_scalar(body: dict, dotted: str) -> None:
    parts = dotted.split(".")
    node: object = body
    for part in parts[:-1]:
        if not isinstance(node, dict) or part not in node:
            return
        node = node[part]
    if isinstance(node, dict) and parts[-1] in node:
        node[parts[-1]] = _PER_RUN_MARKER


def _evidence_digest(text: str, relpath: str) -> str:
    """The plane's evidence digest: its `body`, with the declared non-evidence body bytes normalised.

    For a plane that declares no per-run or build-product body field this is exactly the tool's own
    `body_hash`; for Miri it is `body_hash` with the raw transcript digest blanked, and for ASan/TSan
    with the instrumented test binary's build-product fields blanked.
    """
    if not text:
        return ""
    try:
        doc = json.loads(text)
    except ValueError:
        return ""
    body = doc.get("body", doc)
    per_run = PER_RUN_BODY.get(relpath, ())
    build = BUILD_PRODUCT_BODY.get(relpath, ())
    if not per_run and not build:
        return content_hash(body)
    body = copy.deepcopy(body)
    for table, name in per_run:
        node = body.get(table)
        if not isinstance(node, dict):
            continue
        columns = node.get("columns") or []
        if name not in columns:
            continue
        i = columns.index(name)
        for row in node.get("rows") or []:
            if isinstance(row, list) and i < len(row):
                row[i] = _PER_RUN_MARKER
    for dotted in build:
        _blank_scalar(body, dotted)
    return content_hash(body)


def _git_head_text(relpath: str) -> str:
    """The committed text of `relpath` at HEAD, or `` when git cannot answer."""
    res = subprocess.run(["git", "show", f"HEAD:{relpath}"], cwd=str(REPO_ROOT),
                         capture_output=True, text=True)
    return res.stdout if res.returncode == 0 else ""


def _lower_data_limit() -> None:
    """Child pre-exec: pin RLIMIT_DATA to the court's documented default cap."""
    resource.setrlimit(resource.RLIMIT_DATA,
                       (DEFAULT_RLIMIT_DATA_BYTES, DEFAULT_RLIMIT_DATA_BYTES))


def _hard_data_is_unlimited() -> bool:
    return resource.getrlimit(resource.RLIMIT_DATA)[1] == resource.RLIM_INFINITY


# --------------------------------------------------------------------------------------------
# the orchestration: re-run a plane's own `--measure`
# --------------------------------------------------------------------------------------------

def _run_measure(tool: str, needs_override: bool) -> int:
    """Run `<tool> --measure` in the venue its own subphase admitted, and return its exit code.

    A plane that does not carry the manifest's data override runs under the court's default
    per-process cap even when the orchestrator was launched with the wider one, via a child
    `RLIMIT_DATA`; the override planes need the wider cap, which the orchestrator itself must have
    been launched with (it cannot raise its own hard limit).
    """
    argv = [sys.executable, str(REPO_ROOT / tool), "--measure"]
    env = dict(os.environ)
    preexec = None if needs_override else _lower_data_limit
    res = subprocess.run(argv, cwd=str(REPO_ROOT), env=env, preexec_fn=preexec)
    return res.returncode


def _regenerate(step: int, spec: dict, manifest_digest: str) -> dict:
    """Re-run one plane's `--measure` and record the evidence of that re-run."""
    relpath = str(spec["plane"])
    path = REPO_ROOT / relpath
    needs_override = bool(spec["env"])

    head_text = _git_head_text(relpath)
    head_sha = _sha(head_text)
    head_evidence = _evidence_digest(head_text, relpath)
    head_binding = _plane_binding(head_text)

    before_text = _read(path)
    before_sha = _sha(before_text)
    before_evidence = _evidence_digest(before_text, relpath)
    before_binding = _plane_binding(before_text)

    reason = ""
    exit_code = None
    if needs_override and not _hard_data_is_unlimited():
        reason = (
            f"{relpath} needs the manifest's documented per-process data override "
            f"({DATA_OVERRIDE}) because ASan/TSan reserve a sparse shadow the court's default "
            f"4 GiB RLIMIT_DATA refuses, but this orchestrator's hard RLIMIT_DATA is bounded; "
            f"launch it inside the court with {DATA_OVERRIDE}"
        )
    else:
        exit_code = _run_measure(str(spec["tool"]), needs_override)

    re_measured = exit_code is not None
    after_text = _read(path)
    after_sha = _sha(after_text)
    after_evidence = _evidence_digest(after_text, relpath)
    binding = _plane_binding(after_text) or before_binding
    gen, kind, body_hash = _plane_meta(after_text) if after_text else ("", "", "")

    reproduced = (before_evidence == after_evidence) if re_measured else None
    survived = (head_evidence == after_evidence) if (head_evidence and after_evidence) else None

    return {
        "step": step,
        "plane": relpath,
        "tool": str(spec["tool"]),
        "subphase": str(spec["subphase"]),
        "env": str(spec["env"]),
        "depends_on": list(spec["depends_on"]),
        "re_measured": re_measured,
        "exit": exit_code,
        "reason": reason,
        "committed_sha256": before_sha,
        "rerun_sha256": after_sha,
        "bytes_identical": bool(before_sha) and before_sha == after_sha,
        "evidence_before": before_evidence,
        "evidence_after": after_evidence,
        "reproduced": reproduced,
        "per_run_fields": _per_run_fields(relpath),
        "build_product_fields": _build_product_fields(relpath),
        "head_sha256": head_sha,
        "head_evidence": head_evidence,
        "survived_from_head": survived,
        "manifest_binding": binding,
        "manifest_binding_head": head_binding,
        "manifest_current": bool(binding) and binding == manifest_digest,
        "binding_was_superseded": bool(head_binding) and head_binding != manifest_digest,
        "generator": gen,
        "kind": kind,
        "body_hash": body_hash,
    }


# --------------------------------------------------------------------------------------------
# the derived body
# --------------------------------------------------------------------------------------------

def _derived(planes: list[dict]) -> dict:
    n = len(planes)
    re_measured = sum(1 for q in planes if q.get("re_measured"))
    reproduced = sum(1 for q in planes
                     if q.get("re_measured") and q.get("reproduced") is True)
    superseded = sum(1 for q in planes if q.get("binding_was_superseded"))
    all_reproduced = bool(n) and re_measured == n and reproduced == n
    return {
        "planes": n,
        "re_measured": re_measured,
        "unmeasured": n - re_measured,
        "reproduced": reproduced,
        "superseded_bindings": superseded,
        "planes_total": n,
        "planes_re_measured": re_measured,
        "planes_reproduced": reproduced,
        "all_reproduced": all_reproduced,
    }


def _residual_for(plane_row: dict, manifest_digest: str, index: int) -> dict | None:
    """The open residual a plane owes, or None when the plane is clean."""
    name = plane_row["plane"]
    if not plane_row.get("re_measured"):
        return {
            "residual_id": f"res-regen-{index}-not-re-run",
            "subject": name,
            "class": RESIDUAL_CLASS_NOT_RE_RUN,
            "disposition": "open",
            "reason": (plane_row.get("reason")
                       or "the plane was not re-run and records no reason"),
            "detail": (f"the committed plane binds {plane_row.get('manifest_binding') or 'no'} "
                       f"manifest digest and was not re-measured"),
        }
    if plane_row.get("exit"):
        return {
            "residual_id": f"res-regen-{index}-exit",
            "subject": name,
            "class": RESIDUAL_CLASS_NONZERO_EXIT,
            "disposition": "open",
            "reason": f"the plane's --measure exited {plane_row['exit']}",
            "detail": (f"the generator {plane_row['tool']} did not complete cleanly, so the plane "
                       f"is not trusted as regenerated"),
        }
    if plane_row.get("reproduced") is False:
        return {
            "residual_id": f"res-regen-{index}-drift",
            "subject": name,
            "class": RESIDUAL_CLASS_NOT_REPRODUCIBLE,
            "disposition": "open",
            "reason": "the second --measure did not reproduce the plane's evidence",
            "detail": (f"evidence {plane_row.get('evidence_before')} -> "
                       f"{plane_row.get('evidence_after')}"),
        }
    if plane_row.get("manifest_binding") and not plane_row.get("manifest_current"):
        return {
            "residual_id": f"res-regen-{index}-stale",
            "subject": name,
            "class": RESIDUAL_CLASS_STALE_BINDING,
            "disposition": "open",
            "reason": "the plane still binds a superseded manifest digest after the regeneration",
            "detail": (f"the plane records {plane_row.get('manifest_binding')} for {MANIFEST_REL}, "
                       f"not the current {manifest_digest}"),
        }
    return None


def _findings(planes: list[dict], manifest_digest: str) -> list[str]:
    n = len(planes)
    re_measured = sum(1 for q in planes if q.get("re_measured"))
    reproduced = sum(1 for q in planes if q.get("re_measured") and q.get("reproduced") is True)
    byte_same = sum(1 for q in planes if q.get("re_measured") and q.get("bytes_identical"))
    findings = [
        f"the clean regeneration re-ran {re_measured} of {n} measurement plane(s); {reproduced} "
        f"reproduced their evidence on a second --measure, and {byte_same} reproduced whole-file "
        f"(the rest differ only in the non-evidence bytes their envelope or per-run fields carry)",
    ]
    if all(q.get("manifest_current") for q in planes if q.get("re_measured")):
        findings.append(
            f"every re-measured plane now binds the current venue manifest {manifest_digest} as an "
            f"input, so the measurement planes are mutually consistent on the manifest"
        )
    for q in planes:
        name = q["plane"]
        if q.get("binding_was_superseded"):
            findings.append(
                f"{name} bound a superseded manifest digest ({q.get('manifest_binding_head')}) as "
                f"committed at HEAD and was re-bound to the current {manifest_digest} by the "
                f"regeneration"
            )
        if q.get("head_evidence") and q.get("survived_from_head") is False:
            findings.append(
                f"{name} did not survive the regeneration: its committed evidence "
                f"({q.get('head_evidence')}) differs from the regenerated evidence "
                f"({q.get('evidence_after')}), so a PASS read off the committed bytes had to be "
                f"re-read off the regenerated ones"
            )
        if q.get("re_measured") and q.get("reproduced") is False:
            findings.append(
                f"{name} was re-run twice and the second --measure did not reproduce the first's "
                f"evidence, so it is recorded a non-reproducible finding rather than a pass"
            )
        if (q.get("re_measured") and q.get("reproduced") is True
                and not q.get("bytes_identical")
                and (q.get("per_run_fields") or q.get("build_product_fields"))):
            declared = list(q.get("per_run_fields") or []) + list(q.get("build_product_fields") or [])
            findings.append(
                f"{name} reproduced its evidence while its whole file differs, because it records "
                f"the declared non-evidence field(s) {declared} -- a per-run transcript digest or a "
                f"build product -- whose bytes are not reproducible; the difference is confined to "
                f"those declared fields"
            )
        if (q.get("re_measured") and q.get("reproduced") is True
                and not q.get("bytes_identical")
                and not q.get("per_run_fields") and not q.get("build_product_fields")):
            findings.append(
                f"{name} reproduced its evidence while its whole file differs only in the pathless "
                f"non-committed inputs its envelope records (the raw tool stream it derived from)"
            )
    return findings


def build_body(manifest_digest: str, planes: list[dict]) -> dict:
    derived = _derived(planes)
    residuals = []
    for i, q in enumerate(planes, start=1):
        r = _residual_for(q, manifest_digest, i)
        if r is not None:
            residuals.append(r)
    return {
        "rule": _rule(),
        "procedure": [
            {
                "step": i,
                "plane": q["plane"],
                "tool": q["tool"],
                "subphase": q["subphase"],
                "env": q["env"],
                "depends_on": q["depends_on"],
            }
            for i, q in enumerate(planes, start=1)
        ],
        "manifest": {"path": MANIFEST_REL, "sha256": manifest_digest},
        "planes": planes,
        "determinism": {
            "planes_total": derived["planes_total"],
            "planes_re_measured": derived["planes_re_measured"],
            "planes_reproduced": derived["planes_reproduced"],
            "all_reproduced": derived["all_reproduced"],
            "second_run_required": True,
            "rule": (
                "a determinism claim is admitted only with the second run: `reproduced` must equal "
                "`evidence_before == evidence_after`, and a plane not re-run records no `reproduced` "
                "claim at all"
            ),
        },
        "counts": {
            "planes": derived["planes"],
            "re_measured": derived["re_measured"],
            "unmeasured": derived["unmeasured"],
            "reproduced": derived["reproduced"],
            "superseded_bindings": derived["superseded_bindings"],
            "findings": 0,  # set below once the findings list exists
            "residuals": len(residuals),
        },
        "findings": [],
        "residuals": sorted(residuals, key=lambda r: r["residual_id"]),
        "non_claims": list(NON_CLAIMS),
    }


def _rule() -> dict:
    return {
        "subject": (
            "the measurement planes the memory-safety stratum ships: the source census, the "
            "non-Rust TCB, Miri, ASan/MSan, TSan, Kani and the CVE-replay index"
        ),
        "procedure_rule": (
            "each plane is regenerated by its own `--measure`, in dependency order (the census "
            "first, then the planes that consume it), and never edited by hand: the regeneration "
            "can neither widen nor narrow what a plane reports"
        ),
        "venue_rule": (
            "each plane runs in exactly the venue its own subphase admitted: the court's default "
            "per-process RLIMIT_DATA, except ASan and TSan, which take the manifest's documented "
            f"`{DATA_OVERRIDE}` override"
        ),
        "determinism_rule": (
            "a plane is reproducible when the second `--measure` derives the same evidence as the "
            "committed plane -- its `body`, with the declared per-run fields normalised; the claim "
            "is admitted only when both evidence digests exist and agree"
        ),
        "evidence_rule": (
            "the determinism claim is on the plane's evidence, not its whole envelope: the pathless "
            "non-committed inputs a tool records (a raw compiler stream), the per-run transcript "
            "digest Miri records and the build-product test-binary fields ASan/TSan record are not "
            "evidence, and the plane names each one"
        ),
        "manifest_rule": (
            "every plane must record the current `forensics/memory-safety/container.json` digest as "
            "an input; a plane still binding a superseded digest is a residual, never a pass"
        ),
        "survival_rule": (
            "a plane's evidence is compared with the evidence committed at HEAD; a plane that did "
            "not survive is a finding, so a PASS that did not survive the regeneration is named "
            "rather than silently replaced"
        ),
        "evidence": [MANIFEST_REL, *PROCEDURE_PLANES],
        "per_run_body_fields": {k: list(v) for k, v in PER_RUN_BODY.items()},
        "build_product_body_fields": {k: list(v) for k, v in BUILD_PRODUCT_BODY.items()},
        "sort_key": "planes in procedure order; residuals by residual_id",
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def _hex(value: object) -> bool:
    return isinstance(value, str) and bool(_HEX64.match(value))


def regen_findings(body: dict, manifest_digest: str) -> list:
    """Every way the committed regeneration fails. Pure over its inputs, so the control can mutate.

    It refuses: a plane binding a superseded manifest digest that is not recorded as a residual; a
    measurement plane that was not re-run and carries no exact reason or residual; a determinism
    claim with no second run; a plane whose evidence did not survive the regeneration but is not
    named in a finding; and a typed count (the counts and the determinism block must equal their
    derivation).
    """
    problems: list[str] = []

    manifest = body.get("manifest") or {}
    if manifest.get("sha256") != manifest_digest:
        problems.append(
            f"the plane records the venue manifest {manifest.get('sha256')!r}, not the current "
            f"{manifest_digest!r}")

    proc = body.get("procedure") or []
    proc_names = [p.get("plane") for p in proc]
    if proc_names != list(PROCEDURE_PLANES):
        problems.append(
            f"the procedure is not the {len(PROCEDURE_PLANES)} measurement planes in order "
            f"(found {proc_names})")
    steps = [p.get("step") for p in proc]
    if steps != list(range(1, len(proc) + 1)):
        problems.append(f"the procedure steps are not 1..{len(proc)} in order (found {steps})")
    seen: list = []
    for p in proc:
        for dep in p.get("depends_on") or []:
            if dep not in seen:
                problems.append(
                    f"procedure step {p.get('plane')} depends on {dep}, which is not an earlier "
                    f"step")
        seen.append(p.get("plane"))

    planes = body.get("planes") or []
    plane_names = [q.get("plane") for q in planes]
    if sorted(n for n in plane_names if n) != sorted(PROCEDURE_PLANES):
        problems.append(f"the plane records are not exactly the {len(PROCEDURE_PLANES)} procedure "
                        f"planes (found {plane_names})")
    if len(plane_names) != len(set(plane_names)):
        problems.append("a plane is recorded twice")

    residuals = body.get("residuals") or []
    residual_subjects = {str(r.get("subject")) for r in residuals}
    finding_text = " | ".join(str(f) for f in (body.get("findings") or []))

    for q in planes:
        name = q.get("plane")
        if not name:
            problems.append("a plane record has no `plane`")
            continue
        if q.get("manifest_binding") and q["manifest_binding"] != manifest_digest:
            if q.get("manifest_current"):
                problems.append(f"{name} binds the superseded manifest {q['manifest_binding']} but "
                                f"records manifest_current=true")
            if name not in residual_subjects:
                problems.append(f"{name} binds a superseded manifest digest "
                                f"({q['manifest_binding']}) with no residual")
        if q.get("re_measured"):
            if not isinstance(q.get("exit"), int):
                problems.append(f"{name} is recorded re-measured with no integer exit")
            for field in ("committed_sha256", "rerun_sha256", "evidence_before",
                          "evidence_after"):
                if not _hex(q.get(field)):
                    problems.append(f"{name} is recorded re-measured with no {field}")
            claim = q.get("reproduced")
            truth = q.get("evidence_before") == q.get("evidence_after")
            if claim is not True and claim is not False:
                problems.append(f"{name} records a `reproduced` that is not a boolean")
            elif bool(claim) != bool(truth):
                problems.append(
                    f"{name} claims reproduced={claim!r} but its two evidence digests "
                    f"{'agree' if truth else 'differ'}")
            if not q.get("reason") and q.get("exit"):
                problems.append(f"{name} re-ran with a non-zero exit and no reason")
        else:
            if not str(q.get("reason") or "").strip():
                problems.append(f"{name} was not re-measured and records no reason")
            if name not in residual_subjects:
                problems.append(f"{name} was not re-measured with no residual")
            if q.get("reproduced"):
                problems.append(f"{name} claims reproducibility without a second run")
        if q.get("head_evidence") and q.get("survived_from_head") is not None:
            truth = q.get("head_evidence") == q.get("evidence_after")
            if bool(q.get("survived_from_head")) != bool(truth):
                problems.append(f"{name} records survived_from_head inconsistent with its evidence "
                                f"digests")
            if not truth and name not in finding_text:
                problems.append(f"{name} did not survive the regeneration and is not named in a "
                                f"finding")

    derived = _derived(planes)
    det = body.get("determinism") or {}
    for key in ("planes_total", "planes_re_measured", "planes_reproduced"):
        if det.get(key) != derived[key]:
            problems.append(f"determinism.{key} is typed ({det.get(key)!r} != {derived[key]})")
    if bool(det.get("all_reproduced")) != derived["all_reproduced"]:
        problems.append(f"determinism.all_reproduced is typed ({det.get('all_reproduced')!r} != "
                        f"{derived['all_reproduced']})")

    counts = body.get("counts") or {}
    derived_counts = {
        "planes": derived["planes"],
        "re_measured": derived["re_measured"],
        "unmeasured": derived["unmeasured"],
        "reproduced": derived["reproduced"],
        "superseded_bindings": derived["superseded_bindings"],
        "findings": len(body.get("findings") or []),
        "residuals": len(residuals),
    }
    for key, want in derived_counts.items():
        if counts.get(key) != want:
            problems.append(f"counts.{key} is typed ({counts.get(key)!r} != {want})")

    for r in residuals:
        if not str(r.get("reason") or "").strip():
            problems.append(f"residual {r.get('residual_id')} records no reason")
        if not str(r.get("subject") or "").strip():
            problems.append(f"residual {r.get('residual_id')} records no subject")

    return problems


def regen_sensitivity_control(body: dict, manifest_digest: str) -> dict:
    """Seed each way this plane can lie and require every one caught with specificity holding."""
    base = regen_findings(body, manifest_digest)
    seeded: list[tuple[str, list]] = []

    def caught(label: str, fn) -> None:
        doc = copy.deepcopy(body)
        fn(doc)
        seeded.append((label, regen_findings(doc, manifest_digest)))

    def _no_second_run(doc: dict) -> None:
        doc["planes"][0]["evidence_after"] = ""
        doc["planes"][0]["reproduced"] = True
    caught("determinism_with_no_second_run", _no_second_run)

    def _stale_binding(doc: dict) -> None:
        doc["planes"][1]["manifest_binding"] = "f" * 64
        doc["planes"][1]["manifest_current"] = True
    caught("stale_manifest_binding", _stale_binding)

    def _not_re_run_no_reason(doc: dict) -> None:
        doc["planes"][2]["re_measured"] = False
        doc["planes"][2]["reason"] = ""
        doc["planes"][2]["exit"] = None
    caught("not_re_run_with_no_reason", _not_re_run_no_reason)

    def _typed_count(doc: dict) -> None:
        doc["counts"]["planes"] = int(doc["counts"]["planes"]) + 1
    caught("typed_count", _typed_count)

    def _dropped_plane(doc: dict) -> None:
        doc["planes"] = doc["planes"][:-1]
    caught("dropped_plane", _dropped_plane)

    def _determinism_lie(doc: dict) -> None:
        doc["determinism"]["all_reproduced"] = not doc["determinism"]["all_reproduced"]
    caught("determinism_all_reproduced_lie", _determinism_lie)

    def _residual_no_reason(doc: dict) -> None:
        doc["residuals"].append({"residual_id": "res-x", "subject": "s", "class": "c",
                                 "disposition": "open", "reason": "", "detail": "d"})
    caught("residual_with_no_reason", _residual_no_reason)

    def _dependency_after(doc: dict) -> None:
        doc["procedure"].reverse()
        for i, p in enumerate(doc["procedure"], start=1):
            p["step"] = i
    caught("procedure_out_of_dependency_order", _dependency_after)

    def _reproduced_lie(doc: dict) -> None:
        doc["planes"][0]["evidence_after"] = "e" * 64
    caught("reproduced_claim_contradicts_evidence", _reproduced_lie)

    control: dict = {"baseline_findings": len(base), "specificity_holds": not base,
                     "seeded": len(seeded)}
    caught_n = 0
    for label, found in seeded:
        control[f"caught_{label}"] = len(found)
        if found:
            caught_n += 1
    control["caught"] = caught_n
    control["honest"] = (not base) and caught_n == len(seeded)
    return control


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_plane(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _inputs() -> list:
    refs = [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-regeneration-tool", path=TOOL),
    ]
    for p in PROCEDURE:
        refs.append(InputRef(name=f"plane-{p['subphase']}-tool", path=REPO_ROOT / p["tool"]))
        refs.append(InputRef(name=f"plane-{p['subphase']}", path=REPO_ROOT / p["plane"]))
    return refs


def _measure() -> int:
    """Re-run every measurement plane's `--measure` and write artifacts/phase25/regeneration.json."""
    manifest_digest = _manifest_digest()
    planes = [_regenerate(i, spec, manifest_digest)
              for i, spec in enumerate(PROCEDURE, start=1)]
    body = build_body(manifest_digest, planes)
    body["findings"] = _findings(planes, manifest_digest)
    body["counts"]["findings"] = len(body["findings"])
    problems = regen_findings(body, manifest_digest)
    control = regen_sensitivity_control(body, manifest_digest)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-regeneration", authority=auth.id, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    _write_plane(OUT, doc)

    print(f"[ms-regeneration] {rel(OUT)} -- manifest {manifest_digest[:16]}")
    for q in planes:
        state = ("re-run exit=%s" % (q["exit"],)) if q["re_measured"] else "NOT-RE-RUN"
        rep = ("reproduced" if q["reproduced"] else
               ("NOT-REPRODUCED" if q["reproduced"] is False else "-"))
        print(f"  {q['subphase']:<6} {q['plane'].split('/')[-1]:<20} {state:<16} {rep:<15} "
              f"bytes_same={q['bytes_identical']} binding_current={q['manifest_current']} "
              f"survived={q['survived_from_head']}"
              + (f" -- {q['reason'][:60]}" if q["reason"] else ""))
    c = body["counts"]
    print(f"  planes={c['planes']} re_measured={c['re_measured']} reproduced={c['reproduced']} "
          f"unmeasured={c['unmeasured']} superseded_bindings={c['superseded_bindings']} "
          f"findings={c['findings']} residuals={c['residuals']}")
    print(f"  -> body_hash={doc['body_hash'][:16]} all_checks={not problems} "
          f"control honest={control['honest']} specificity={control['specificity_holds']}")
    for p in problems[:24]:
        print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed plane, without a compiler or a tool."""
    if not OUT.is_file():
        print(f"[ms-regeneration] {rel(OUT)} is absent; run --measure")
        return 1
    body = _body(_load(OUT))
    manifest_digest = _manifest_digest()
    problems = regen_findings(body, manifest_digest)
    control = regen_sensitivity_control(body, manifest_digest)
    if problems or not control["honest"]:
        print(f"[ms-regeneration] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-regeneration] check ok: {c['planes']} plane(s), {c['re_measured']} re-measured, "
          f"{c['reproduced']} reproducible, {c['superseded_bindings']} superseded binding(s) "
          f"closed; {c['residuals']} residual(s); every check holds")
    return 0


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_body(manifest_digest: str) -> dict:
    """A tiny, self-consistent regeneration body covering a clean re-measure and a non-re-measure.

    It exercises every shape the real plane can take -- a clean re-measure, a superseded binding
    that closed, a plane that failed to survive, a per-run field that left the whole file differing
    while the evidence reproduced, and a recorded non-re-measure -- with no compiler.
    """
    clean = "a" * 64
    head = "b" * 64
    planes: list[dict] = []
    for i, spec in enumerate(PROCEDURE, start=1):
        planes.append({
            "step": i, "plane": spec["plane"], "tool": spec["tool"],
            "subphase": spec["subphase"], "env": spec["env"],
            "depends_on": list(spec["depends_on"]),
            "re_measured": True, "exit": 0, "reason": "",
            "committed_sha256": clean, "rerun_sha256": clean, "bytes_identical": True,
            "evidence_before": clean, "evidence_after": clean, "reproduced": True,
            "per_run_fields": _per_run_fields(spec["plane"]),
            "build_product_fields": _build_product_fields(spec["plane"]),
            "head_sha256": "", "head_evidence": "", "survived_from_head": None,
            "manifest_binding": manifest_digest, "manifest_binding_head": "",
            "manifest_current": True, "binding_was_superseded": False,
            "generator": spec["tool"], "kind": "synthetic", "body_hash": clean,
        })
    # (1) a plane re-bound from a superseded manifest whose evidence changed since HEAD.
    planes[0]["head_sha256"] = head
    planes[0]["head_evidence"] = head
    planes[0]["survived_from_head"] = False
    planes[0]["manifest_binding_head"] = "c" * 64
    planes[0]["binding_was_superseded"] = True
    # (2) a plane whose evidence reproduced while its whole file differs in a declared non-evidence
    # field (a build product or a per-run transcript digest).
    planes[1]["bytes_identical"] = False
    planes[1]["per_run_fields"] = ["body.runs.rows[*].transcript_sha256"]
    # (3) a plane the venue cannot re-run: exact reason, an open residual, and a stale binding.
    planes[2]["re_measured"] = False
    planes[2]["exit"] = None
    planes[2]["reason"] = "the tool is absent in this synthetic venue"
    planes[2]["reproduced"] = None
    planes[2]["manifest_binding"] = "d" * 64
    planes[2]["manifest_current"] = False
    body = build_body(manifest_digest, planes)
    body["findings"] = _findings(planes, manifest_digest)
    body["counts"]["findings"] = len(body["findings"])
    return body


def self_test() -> int:
    """Prove the guard refuses the host and the checks and control are honest."""
    failures: list[str] = []

    refusal = phase25_guard.host_refusal_reasons("ms_regeneration.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of ms_regeneration.py")

    manifest_digest = _manifest_digest()
    body = _synth_body(manifest_digest)
    baseline = regen_findings(body, manifest_digest)
    if baseline:
        failures.append(f"the synthetic regeneration body is not clean: {baseline[:4]}")

    control = regen_sensitivity_control(body, manifest_digest)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    c = body["counts"]
    if (c["planes"], c["re_measured"], c["unmeasured"], c["reproduced"]) != (7, 6, 1, 6):
        failures.append(f"the synthetic counts are wrong: {c}")
    if body["determinism"]["all_reproduced"]:
        failures.append("the synthetic with an unmeasurable plane claims all_reproduced")
    if not any(not q["re_measured"] for q in body["planes"]):
        failures.append("the synthetic exercises no un-re-measured plane")
    if not any(q["binding_was_superseded"] for q in body["planes"]):
        failures.append("the synthetic exercises no superseded binding")
    if not any(q["survived_from_head"] is False for q in body["planes"]):
        failures.append("the synthetic exercises no plane that failed to survive")
    if not any(q["reproduced"] and not q["bytes_identical"] for q in body["planes"]):
        failures.append("the synthetic exercises no per-run-field plane")

    if failures:
        print("[ms-regeneration] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-regeneration] self-test ok: the guard refuses the host; the synthetic regeneration "
          f"({c['planes']} plane(s): {c['re_measured']} re-measured, {c['unmeasured']} un-re-measured, "
          f"{c['reproduced']} reproducible) is clean; and all {control['seeded']} seeded mutations "
          "(a determinism claim with no second run, a stale manifest binding, an un-re-measured plane "
          "with no reason, a typed count, a dropped plane, an all_reproduced lie, a residual with no "
          "reason, a procedure out of dependency order and a reproduced claim that contradicts the "
          "evidence) are caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="re-run every measurement plane and write artifacts/phase25/regeneration.json")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed plane")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the guard refusal and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool executes the compiler and the
    # sanitizers, so the manifest does not list it `metadata_only` and a host invocation is refused.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return _check()
    return _measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
