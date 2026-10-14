#!/usr/bin/env python3
"""Phase 25.16 -- the historical CVE replay.

Replays the historical memory-safety-relevant OpenSSL CVEs the 25.15 census classified
(`artifacts/phase25/historical-cves.json`) against the **exact admitted candidate** and records,
for each CVE, the candidate's disposition in the closed `CVE_REPLAY_STATES` vocabulary together
with the command that ran and the behaviour it observed.

It is a **measurement**: for every memory-safety CVE it compiles the committed replay probe
(`courts/phase25/cve_replay_probe.c`) against the candidate (`artifacts/phase2`, the exact admitted
candidate's built C ABI) and, where the CVE's affected range has a built vulnerable historical
authority, against that authority too -- the **positive control** -- then runs the case and reads
what each library did. A replay may only claim a positive result if the harness actually ran and
its outcome is recorded; a case whose shape cannot be expressed through the public C ABI (or whose
control cannot fire) is recorded `UNKNOWN` with its reason, never a pass.

Because it compiles and runs probes, the Docker-only execution guard
(`forensics/tools/phase25_guard.py`) is called first and the committed manifest
`forensics/memory-safety/container.json` does not list it `metadata_only`: a host invocation is
refused rather than producing unreproducible evidence. It is therefore **not** an input to
`evidence_determinism.py`'s generator registry (see that file's why-comment); the `MS-CVE-REPLAY`
court re-runs only its pure checks (`cve_replay_findings` and `cve_replay_sensitivity_control`)
over the committed plane, the committed 25.15 census and the committed probe source.

Usage:
  python3 forensics/tools/ms_cve_replay.py --measure     # replay and write the plane
  python3 forensics/tools/ms_cve_replay.py --check       # re-run the pure checks over the plane
  python3 forensics/tools/ms_cve_replay.py --self-test   # guard refusal + sensitivity honesty
"""

from __future__ import annotations

import argparse
import json
import os
import re
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
    sha256_file,
)

# The Docker-only execution guard, called first: this tool compiles and runs probes against the
# candidate, so the manifest does not list it `metadata_only` and a host invocation is refused
# rather than producing unreproducible evidence.
import phase25_guard  # noqa: E402

import memory_safety_schemas as schemas  # noqa: E402

import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT_DIR = REPO_ROOT / "artifacts" / "phase25" / "cve-replay"
INDEX = OUT_DIR / "index.json"
REPLAYS_DIR = OUT_DIR / "replays"
GENERATOR = "forensics/tools/ms_cve_replay.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_cve_replay.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

# The committed replay harness every measurement compiles against a target's C ABI.
PROBE = REPO_ROOT / "courts" / "phase25" / "cve_replay_probe.c"

# 25.15's census (the historical CVEs and their candidate regions) and its committed evidence.
HISTORICAL_CVES = REPO_ROOT / "artifacts" / "phase25" / "historical-cves.json"
SECURITY_SOURCE = REPO_ROOT / "forensics" / "multitrack" / "security-source.json"
SECURITY_LINEAGE = REPO_ROOT / "forensics" / "multitrack" / "security-lineage.json"
SOURCE_CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
NON_RUST_TCB = REPO_ROOT / "artifacts" / "phase25" / "non-rust-tcb.json"

# The exact admitted candidate's built C ABI (Phase 2's link/export prefix) and the vulnerable
# historical authorities, each pinned by version under `forensics/authorities/prefix`.
CANDIDATE_PREFIX = REPO_ROOT / "artifacts" / "phase2"
AUTHORITY_PREFIXES = REPO_ROOT / "forensics" / "authorities" / "prefix"

# Scratch, under the gitignored `/work` tree the brief mandates. The tool refuses on the host, so
# this path only ever exists inside the court.
WORK = Path("/work/court/p25/cve-replay")

# The venial budget for one probe run; the guard-page control faults immediately and the candidate
# paths are single library calls.
RUN_TIMEOUT = 120

# The state vocabulary the plane records: the schema's own closed set, reused rather than
# retyped, so the plane cannot record a state the schema does not define.
POSITIVE_STATES = frozenset({
    "CANDIDATE_STRUCTURALLY_EXCLUDED",
    "CANDIDATE_SAFE_REJECTION",
    "CANDIDATE_NO_MEMORY_FAULT_OBSERVED",
    "CANDIDATE_FEATURE_NOT_APPLICABLE",
})

# The replay cases: one per memory-safety-relevant historical CVE. `control` names where the
# positive control comes from -- a built vulnerable historical authority that must exhibit the
# mechanism, or `embedded` (the deliberately-broken variant of the same input shape compiled into
# the probe). A case with no `control` is one whose shape the public C ABI cannot express; it is
# recorded `UNKNOWN` with its reason. `structure`, where present, is the structure that makes the
# mechanism inexpressible -- the evidence a `CANDIDATE_STRUCTURALLY_EXCLUDED` replay must cite.
CASES: tuple[dict, ...] = (
    {
        "cve_id": "CVE-2023-0286",
        "taxonomy": "TYPE_CONFUSION",
        "case": "x509_x400_general_name",
        "control": None,
        "structure": None,
        "unsupported": (
            "the x400Address field of GENERAL_NAME is opaque in the admitted 3.0/3.6 ABI and no "
            "public constructor or accessor exposes a GEN_X400 GeneralName, so the advisory's "
            "crafted GENERAL_NAME_cmp shape cannot be expressed against the public C ABI"
        ),
    },
    {
        "cve_id": "CVE-2024-0727",
        "taxonomy": "NULL_DEREFERENCE",
        "case": "pkcs12_null_octet_string",
        "control": ("authority", "openssl-3.0.0-historical"),
        "structure": None,
        "unsupported": None,
    },
    {
        "cve_id": "CVE-2024-9143",
        "taxonomy": "BUFFER_OVERFLOW",
        "case": "gf2m_invalid_field_polynomial",
        "control": ("authority", "openssl-3.0.0-historical"),
        "structure": None,
        "unsupported": None,
    },
    {
        "cve_id": "CVE-2025-15467",
        "taxonomy": "STACK_OOB_WRITE",
        "case": "cms_aead_parameters",
        "control": None,
        "structure": None,
        "unsupported": (
            "the advisory's shape is a crafted CMS AuthEnvelopedData/EnvelopedData AEAD parameter "
            "set; reaching the parameter-copy path needs a full CMS decode with a recipient and a "
            "content-encryption key, which is not expressible as a bounded single-input probe"
        ),
    },
    {
        "cve_id": "CVE-2026-34180",
        "taxonomy": "HEAP_OOB_READ",
        "case": "asn1_oversized_length",
        "control": ("embedded", None),
        "structure": (
            "the candidate parses an ASN.1 length into a u64 and bounds it against c_long::MAX and "
            "the input extent (src/asn1/der.rs, get_length), so the 32-bit content-length "
            "truncation the advisory describes is inexpressible"
        ),
        "unsupported": None,
    },
    {
        "cve_id": "CVE-2026-63072",
        "taxonomy": "HEAP_OOB_WRITE",
        "case": "cms_key_unwrap_aead",
        "control": None,
        "structure": None,
        "unsupported": (
            "the advisory's shape is a CMS EnvelopedData whose AES-WRAP-PAD key unwrap writes and "
            "cleanses eight bytes past the queried buffer; it needs a full key-transport recipient "
            "and unwrap path, which is not expressible as a bounded single-input probe"
        ),
    },
    {
        "cve_id": "CVE-2026-84782",
        "taxonomy": "HEAP_OOB_READ",
        "case": "dtls_retransmission",
        "control": None,
        "structure": None,
        "unsupported": (
            "the advisory's shape is a DTLS handshake write suspended part-way and retransmitted "
            "from a stale buffer offset; the candidate has no committed region for ssl/dtls in the "
            "25.15 census (the region is unjoined) and the stateful handshake engine is not "
            "reachable through a bounded single-input probe"
        ),
    },
)

NON_CLAIMS = (
    "a replay is a statement about one historical CVE's input shape, not a proof that no "
    "memory-safety bug exists and not a prediction of a future CVE count",
    "a CANDIDATE_SAFE_REJECTION is the candidate's answer to one shape, not a proof that every "
    "path in the subsystem is sound",
    "a CANDIDATE_STRUCTURALLY_EXCLUDED is a claim about a mechanism -- the candidate's structure "
    "makes it inexpressible -- and cites that structure; it is not a claim about the whole "
    "subsystem",
    "a CANDIDATE_NO_MEMORY_FAULT_OBSERVED is an observation on the recorded run and is not a "
    "proof that no path can fault",
    "an UNKNOWN replay is a shape the court could not express or whose control could not fire; it "
    "is recorded with its reason and is never a pass",
    "the positive control shows the replay method can detect the vulnerable behaviour (the "
    "authority faults or diverges, or the embedded broken variant of the same shape faults); it "
    "does not make the candidate's exclusion a whole-program proof",
)


# --------------------------------------------------------------------------------------------
# the toolchain and the venue
# --------------------------------------------------------------------------------------------

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _run(args: list[str], timeout: int = RUN_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(REPO_ROOT), capture_output=True, text=True,
                          timeout=timeout)


def cc_version() -> str:
    try:
        cp = _run(["gcc", "--version"])
        return (cp.stdout or "").splitlines()[0].strip() if cp.returncode == 0 else "unavailable"
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def candidate_identity() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', _read(REPO_ROOT / "Cargo.toml"), re.M)
    version = m.group(1) if m else "unknown"
    return f"openssl-rs {version} (reconstructing {resolve_authority(PRODUCTION_AUTHORITY).id})"


def venue() -> dict:
    man = json.loads(_read(MANIFEST)) if MANIFEST.is_file() else {}
    return {
        "admitted_image": os.environ.get("PHASE25_IMAGE", man.get("env_image", "")),
        "platform": os.environ.get("PHASE25_PLATFORM", ""),
        "canonical_base": man.get("canonical_base"),
        "derived_from": "openssl-rs-court:1",
        "kind": "reused-court-venue",
        "cc": cc_version(),
        "candidate_prefix": rel(CANDIDATE_PREFIX),
        "authority_prefix_root": rel(AUTHORITY_PREFIXES),
        "note": (
            "one derived environment per instrument: the CVE replay compiles the committed probe "
            "against the candidate's built C ABI and against a vulnerable historical authority "
            "with the venue's own gcc, adding no tool and removing no bound"
        ),
    }


# --------------------------------------------------------------------------------------------
# building and running the probe
# --------------------------------------------------------------------------------------------

def _prefix_layout(prefix: Path) -> tuple[Path, Path]:
    """`(include_dir, lib_dir)` for a prefix: the candidate C ABI or a historical authority."""
    if prefix == CANDIDATE_PREFIX:
        return prefix / "include", prefix
    return prefix / "include", prefix / "lib"


def build_probe(prefix: Path, out: Path) -> dict:
    inc, lib = _prefix_layout(prefix)
    cmd = ["gcc", "-O1", "-w", "-I", str(inc), "-o", str(out), str(PROBE),
           "-L", str(lib), "-lcrypto", f"-Wl,-rpath,{lib}"]
    cp = _run(cmd)
    return {
        "command": " ".join(cmd),
        "built": cp.returncode == 0,
        "reason": "" if cp.returncode == 0 else (cp.stderr or "").splitlines()[-1][:200],
    }


def run_case(binary: Path, case: str, variant: str) -> dict:
    cmd = [str(binary), case, variant]
    try:
        cp = _run(cmd)
    except subprocess.TimeoutExpired:
        return {"command": " ".join(cmd), "completed": False, "fault": False, "timeout": True,
                "accepted": None, "unsupported": False, "detail": "timeout", "rc": None}
    obs = {
        "command": " ".join(cmd),
        "completed": False,
        "fault": cp.returncode is not None and cp.returncode < 0,
        "timeout": False,
        "accepted": None,
        "unsupported": False,
        "detail": "",
        "rc": cp.returncode,
    }
    if obs["fault"]:
        obs["detail"] = f"signal:{-cp.returncode}"
        return obs
    line = ""
    for ln in (cp.stdout or "").splitlines():
        if ln.strip():
            line = ln.strip()
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        obs["detail"] = "no-transcript"
        return obs
    obs["completed"] = True
    if obj.get("unsupported"):
        obs["unsupported"] = True
        obs["detail"] = "unsupported"
    else:
        obs["accepted"] = bool(obj.get("accepted"))
        obs["detail"] = str(obj.get("detail", ""))[:80]
    return obs


def harness_ran(cand: dict) -> bool:
    return bool(cand.get("completed")) and not cand.get("unsupported") \
        and cand.get("accepted") is not None


def control_fired(cand: dict, ctl: dict | None) -> bool:
    if not ctl:
        return False
    if ctl.get("fault"):
        return True
    if ctl.get("completed") and not ctl.get("unsupported") \
            and ctl.get("accepted") is not None and cand.get("accepted") is not None:
        return bool(ctl["accepted"]) != bool(cand["accepted"])
    return False


def derive_state(case: dict, cand: dict, ctl: dict | None) -> tuple[str, str, bool]:
    """`(state, reason, fired)` from the recorded observations, never from a typed expectation."""
    if not harness_ran(cand):
        if cand.get("unsupported") or case.get("unsupported"):
            return "UNKNOWN", case.get("unsupported") or "the case is not expressible", False
        return "UNKNOWN", f"the candidate harness did not run ({cand.get('detail')})", False
    if cand.get("fault"):
        return "CANDIDATE_REPRODUCES_MEMORY_FAULT", "the candidate faulted on the input shape", False
    fired = control_fired(cand, ctl)
    if not fired:
        return "UNKNOWN", "the positive control did not fire for this shape", False
    if not cand.get("accepted"):
        if case.get("structure"):
            return "CANDIDATE_STRUCTURALLY_EXCLUDED", case["structure"], True
        return "CANDIDATE_SAFE_REJECTION", "the candidate safely refused the input shape", True
    return "CANDIDATE_NO_MEMORY_FAULT_OBSERVED", "the candidate ran the shape without a fault", True


def replay_case(case: dict, cand_id: str) -> dict:
    """Run one case against the candidate and its control; return the `cve_replay` record."""
    cve_id = case["cve_id"]
    name = case["case"]
    WORK.mkdir(parents=True, exist_ok=True)

    cand_bin = WORK / f"{name}-candidate"
    built = build_probe(CANDIDATE_PREFIX, cand_bin)
    if not built["built"]:
        cand = {"command": built["command"], "completed": False, "fault": False, "timeout": False,
                "accepted": None, "unsupported": False, "detail": "probe-build-failed", "rc": None}
    else:
        cand = run_case(cand_bin, name, "candidate")

    ctl = None
    ctl_block: dict = {"kind": "none", "command": "", "outcome": "no control"}
    control = case.get("control")
    if control is not None and control[0] == "authority":
        prefix = AUTHORITY_PREFIXES / control[1]
        auth_bin = WORK / f"{name}-{control[1]}"
        ab = build_probe(prefix, auth_bin)
        if ab["built"]:
            ctl = run_case(auth_bin, name, "candidate")
            ctl_block = {
                "kind": f"authority:{control[1]}",
                "command": " ".join([str(auth_bin), name, "candidate"]),
                "outcome": _outcome(ctl),
                "faulted": bool(ctl.get("fault")),
                "accepted": ctl.get("accepted"),
            }
        else:
            ctl_block = {"kind": f"authority:{control[1]}", "command": ab["command"],
                         "outcome": "authority-build-failed", "faulted": False, "accepted": None}
    elif control is not None and control[0] == "embedded":
        if cand_bin.is_file():
            ctl = run_case(cand_bin, name, "control")
            ctl_block = {
                "kind": "embedded",
                "command": " ".join([str(cand_bin), name, "control"]),
                "outcome": _outcome(ctl),
                "faulted": bool(ctl.get("fault")),
                "accepted": ctl.get("accepted"),
            }

    state, reason, fired = derive_state(case, cand, ctl)
    evidence = [
        rel(HISTORICAL_CVES),
        rel(PROBE),
        rel(SOURCE_CENSUS),
        rel(NON_RUST_TCB),
        rel(SECURITY_SOURCE),
        rel(SECURITY_LINEAGE),
    ]
    if ctl_block["kind"].startswith("authority:"):
        evidence.append(rel(AUTHORITY_PREFIXES))
    record = {
        "replay_id": f"replay-{cve_id}",
        "cve_id": cve_id,
        "taxonomy": case["taxonomy"],
        "state": state,
        "candidate_identity": cand_id,
        "harness_ran": harness_ran(cand),
        "control_fired": fired,
        "case": name,
        "command": cand.get("command", ""),
        "control": ctl_block,
        "observed": {
            "completed": bool(cand.get("completed")),
            "faulted": bool(cand.get("fault")),
            "accepted": cand.get("accepted"),
            "unsupported": bool(cand.get("unsupported")),
            "detail": cand.get("detail", ""),
        },
        "structure": case.get("structure"),
        "reason": reason,
        "evidence": evidence,
    }
    return record


def _outcome(obs: dict) -> str:
    if obs.get("fault"):
        return f"faulted({obs.get('detail')})"
    if obs.get("unsupported"):
        return "unsupported"
    if obs.get("completed"):
        return "accepted" if obs.get("accepted") else "refused"
    return f"incomplete({obs.get('detail')})"


# --------------------------------------------------------------------------------------------
# counts, body and rule
# --------------------------------------------------------------------------------------------

def _memory_safety_cves(historical_body: dict) -> list[str]:
    return sorted(c["cve_id"] for c in historical_body.get("cves", []) if c.get("memory_safety"))


def recompute_counts(replays: list[dict], historical_body: dict) -> dict:
    by_state: dict[str, int] = {}
    by_taxonomy: dict[str, int] = {}
    for r in replays:
        by_state[r.get("state", "")] = by_state.get(r.get("state", ""), 0) + 1
        by_taxonomy[r.get("taxonomy", "")] = by_taxonomy.get(r.get("taxonomy", ""), 0) + 1
    ms = _memory_safety_cves(historical_body)
    return {
        "memory_safety_cves": len(ms),
        "replays": len(replays),
        "replayed": sum(1 for r in replays if r.get("harness_ran")),
        "positive": sum(1 for r in replays if r.get("state") in POSITIVE_STATES),
        "unknown": sum(1 for r in replays if r.get("state") == "UNKNOWN"),
        "control_fired": sum(1 for r in replays if r.get("control_fired")),
        "by_state": dict(sorted(by_state.items())),
        "by_taxonomy": dict(sorted(by_taxonomy.items())),
    }


def _findings(replays: list[dict], historical_body: dict) -> list[dict]:
    out: list[dict] = []
    for r in replays:
        if r.get("state") == "UNKNOWN":
            out.append({"finding": "replay_unestablished", "cve_id": r.get("cve_id"),
                        "detail": r.get("reason", "")})
        elif not r.get("control_fired"):
            out.append({"finding": "control_not_fired", "cve_id": r.get("cve_id"),
                        "detail": "a positive replay whose control did not fire"})
    return out


def _residuals(replays: list[dict]) -> list[dict]:
    out: list[dict] = []
    for r in replays:
        if r.get("state") == "UNKNOWN":
            out.append({"residual_id": f"residual-{r['cve_id']}",
                        "subject": r["cve_id"],
                        "class": "historical_cve_unreplayed",
                        "disposition": "open",
                        "detail": r.get("reason", ""),
                        "evidence": list(r.get("evidence") or [])})
    return out


def _rule(ven: dict) -> dict:
    return {
        "authority": {
            "declaration": (
                "the 25.15 historical CVE census (`artifacts/phase25/historical-cves.json`), the "
                "frozen official vulnerability index and the advisories it carries "
                "(`forensics/multitrack/security-source.json`), the committed security lineage "
                "that binds the CVE records (`forensics/multitrack/security-lineage.json`), the "
                "committed 25.1 census and 25.2 non-Rust TCB (the candidate regions), the exact "
                "admitted candidate's built C ABI (`artifacts/phase2`) and the committed vulnerable "
                "historical authorities (`forensics/authorities/prefix/openssl-*-historical`) are "
                "the authority this plane reads: the census names the memory-safety CVEs, the "
                "advisory names each vulnerable input shape, the candidate C ABI answers each "
                "shape and the historical authority (or the embedded broken variant of the same "
                "shape) is the control. No state, command or outcome is typed here"
            ),
            "candidate": rel(CANDIDATE_PREFIX),
            "authority_prefixes": rel(AUTHORITY_PREFIXES),
            "probe": rel(PROBE),
            "census": rel(HISTORICAL_CVES),
        },
        "venue": ven,
        "states": list(schemas.CVE_REPLAY_STATES),
        "positive_states": sorted(POSITIVE_STATES),
    }


def build_body(replays: list[dict], historical_body: dict, cand_id: str, ven: dict) -> dict:
    counts = recompute_counts(replays, historical_body)
    return {
        "counts": counts,
        "candidate_identity": cand_id,
        "replays": replays,
        "findings": _findings(replays, historical_body),
        "residuals": _residuals(replays),
        "non_claims": list(NON_CLAIMS),
        "rule": _rule(ven),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def _replay_cves(replays: list[dict]) -> list[str]:
    return sorted(str(r.get("cve_id") or "") for r in replays)


def cve_replay_findings(body: dict, historical_body: dict) -> list[str]:
    """Every way the committed replay plane is internally inconsistent, without a compiler.

    It establishes that every memory-safety CVE of the committed 25.15 census has exactly one
    replay and no replay names a CVE the census does not classify; that every replay validates
    against the schema; that a replay in a positive state actually ran and its control actually
    fired; that a `CANDIDATE_STRUCTURALLY_EXCLUDED` replay cites its structure; that the state is
    a member of the closed vocabulary; and that the counts equal their re-derivation.
    """
    problems: list[str] = []
    replays = body.get("replays") or []
    if not isinstance(replays, list):
        return ["the replay plane's `replays` is not a list"]

    expected = _memory_safety_cves(historical_body)
    got = _replay_cves(replays)
    if len(got) != len(set(got)):
        problems.append("a CVE carries more than one replay record")
    if set(got) != set(expected):
        dropped = sorted(set(expected) - set(got))
        fabricated = sorted(set(got) - set(expected))
        if dropped:
            problems.append(f"memory-safety CVEs with no replay: {dropped}")
        if fabricated:
            problems.append(f"replays for CVEs the census does not classify: {fabricated}")

    for r in replays:
        cve = r.get("cve_id")
        for p in schemas.validate_cve_replay(r):
            problems.append(f"{cve}: {p}")
        state = r.get("state")
        if state is not None and state not in schemas.CVE_REPLAY_STATES:
            problems.append(f"{cve}: state={state!r} is not a CVE replay state")
        if state in POSITIVE_STATES:
            if not r.get("harness_ran"):
                problems.append(
                    f"{cve}: state {state} is a positive disposition but its harness did not run")
            if not r.get("control_fired"):
                problems.append(
                    f"{cve}: state {state} is a positive disposition but its control did not fire")
        if state == "CANDIDATE_STRUCTURALLY_EXCLUDED" and not str(r.get("structure") or "").strip():
            problems.append(
                f"{cve}: a CANDIDATE_STRUCTURALLY_EXCLUDED replay must cite the structure that "
                f"makes the mechanism inexpressible")

    derived = recompute_counts(replays, historical_body)
    counts = body.get("counts") or {}
    for key in sorted(set(derived) | set(counts)):
        if counts.get(key) != derived.get(key):
            problems.append(
                f"counts.{key}: {counts.get(key)!r} typed, {derived.get(key)!r} re-derived")

    rule = body.get("rule") or {}
    auth = rule.get("authority") or {}
    for key in ("declaration", "candidate", "authority_prefixes", "probe", "census"):
        if not str(auth.get(key) or "").strip():
            problems.append(f"the rule's authority does not name its `{key}`")
    return problems


def cve_replay_sensitivity_control(body: dict, historical_body: dict) -> dict:
    """Prove the pure checks catch a dropped replay, an unrun pass, a typed count and a control
    that did not fire, each with specificity holding."""
    base = cve_replay_findings(body, historical_body)
    if base:
        return {"honest": False, "specificity_holds": False, "base_problems": base[:6],
                "seeded": []}

    replays = [dict(r) for r in (body.get("replays") or [])]
    positive = next((r for r in replays if r.get("state") in POSITIVE_STATES), None)
    structural = next((r for r in replays
                       if r.get("state") == "CANDIDATE_STRUCTURALLY_EXCLUDED"), None)

    def mutant(mut) -> list[str]:
        b = dict(body)
        b["replays"] = [dict(r) for r in replays]
        b["counts"] = dict(body.get("counts") or {})
        mut(b)
        return cve_replay_findings(b, historical_body)

    seeded: list[dict] = []

    def add(name: str, mutate, keyword: str) -> None:
        probs = mutant(mutate)
        caught = bool(probs) and any(keyword in p for p in probs)
        seeded.append({"seed": name, "caught": caught,
                       "problem": next((p for p in probs if keyword in p), probs[0] if probs else "")})

    add("drop-replay",
        lambda b: b["replays"].pop(),
        "no replay")
    if positive is not None:
        add("pass-without-run",
            lambda b: _set_field(b["replays"], positive["replay_id"], "harness_ran", False),
            "harness did not run")
        add("control-did-not-fire",
            lambda b: _set_field(b["replays"], positive["replay_id"], "control_fired", False),
            "control did not fire")
    add("typed-count",
        lambda b: b["counts"].__setitem__("replays", int(b["counts"].get("replays", 0)) + 1),
        "typed")
    if structural is not None:
        add("structure-without-evidence",
            lambda b: _set_field(b["replays"], structural["replay_id"], "structure", ""),
            "must cite the structure")

    honest = all(s["caught"] for s in seeded) and bool(seeded)
    return {"honest": honest, "specificity_holds": honest, "base_problems": [],
            "seeded": seeded}


def _set_field(records: list[dict], replay_id: str, key: str, value) -> None:
    for r in records:
        if r.get("replay_id") == replay_id:
            r[key] = value
            return


# --------------------------------------------------------------------------------------------
# writing and reading the plane
# --------------------------------------------------------------------------------------------

def _write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _load_historical() -> dict:
    return _body(json.loads(_read(HISTORICAL_CVES))) if HISTORICAL_CVES.is_file() else {}


def _census_refs() -> ms_codec.Refs:
    census_body = ms_census.decode_body(
        _body(json.loads(_read(SOURCE_CENSUS))) if SOURCE_CENSUS.is_file() else {})
    return ms_codec.refs_from_census(census_body)


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-cve-replay-tool", path=TOOL),
        InputRef(name="cve-replay-probe", path=PROBE),
        InputRef(name="historical-cves", path=HISTORICAL_CVES),
        InputRef(name="source-census", path=SOURCE_CENSUS),
        InputRef(name="non-rust-tcb", path=NON_RUST_TCB),
        InputRef(name="security-source", path=SECURITY_SOURCE),
        InputRef(name="security-lineage", path=SECURITY_LINEAGE),
        InputRef(name="cargo-manifest", path=REPO_ROOT / "Cargo.toml"),
    ]


def _measure() -> int:
    """Replay every memory-safety CVE against the candidate and write the plane."""
    ven = venue()
    cand_id = candidate_identity()
    historical_body = _load_historical()
    if not historical_body.get("cves"):
        print(f"[ms-cve-replay] {rel(HISTORICAL_CVES)} is absent or empty; run 25.15 --measure")
        return 1

    replays = [replay_case(case, cand_id) for case in CASES]
    body = build_body(replays, historical_body, cand_id, ven)
    problems = cve_replay_findings(body, historical_body)
    control = cve_replay_sensitivity_control(body, historical_body)

    refs = _census_refs()
    encoded = ms_codec.encode_body(body, refs)
    auth = resolve_authority(PRODUCTION_AUTHORITY)
    index = envelope(kind="phase25-cve-replay", authority=auth.id, inputs=_inputs(),
                     body=encoded, generator=GENERATOR)
    index["body_hash"] = content_hash(encoded)

    # The per-CVE dispositions, one `cve_replay` record per file, sorted for reproducibility.
    for r in body["replays"]:
        _write_json(REPLAYS_DIR / f"{r['cve_id']}.json", r)
    _write_json(INDEX, index)

    c = body["counts"]
    print(f"[ms-cve-replay] {rel(INDEX)} -- {c['memory_safety_cves']} memory-safety CVE(s): "
          f"positive={c['positive']} unknown={c['unknown']} replayed={c['replayed']} "
          f"control_fired={c['control_fired']}")
    for r in body["replays"]:
        print(f"  {r['cve_id']:<15} {r['state']:<30} case={r['case']:<28} "
              f"ran={int(bool(r['harness_ran']))} control={int(bool(r['control_fired']))}")
    print(f"  findings={len(body['findings'])} residuals={len(body['residuals'])} "
          f"control honest={control['honest']} specificity={control['specificity_holds']}")
    print(f"  -> body_hash={index['body_hash'][:16]} all_checks={not problems}")
    for p in problems[:24]:
        print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed plane, without compiling anything."""
    if not INDEX.is_file():
        print(f"[ms-cve-replay] {rel(INDEX)} is absent; run --measure")
        return 1
    doc = json.loads(INDEX.read_text(encoding="utf-8"))
    historical_body = _load_historical()
    body = ms_codec.decode_body(_body(doc), _census_refs())
    problems = cve_replay_findings(body, historical_body)
    control = cve_replay_sensitivity_control(body, historical_body)

    # The per-CVE record files must agree with the index, so a file drifting is caught here.
    for r in body.get("replays", []):
        f = REPLAYS_DIR / f"{r['cve_id']}.json"
        if not f.is_file():
            problems.append(f"the per-CVE record {rel(f)} is absent")
        elif json.loads(f.read_text(encoding="utf-8")) != r:
            problems.append(f"the per-CVE record {rel(f)} disagrees with the index")

    if problems or not control["honest"]:
        print(f"[ms-cve-replay] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-cve-replay] check ok: {c['memory_safety_cves']} memory-safety CVE(s); "
          f"positive={c['positive']} unknown={c['unknown']} control_fired={c['control_fired']}; "
          f"{len(body['findings'])} finding(s), {len(body['residuals'])} residual(s); "
          f"body_hash={doc.get('body_hash', '')[:16]}")
    return 0


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def self_test() -> int:
    refusal = phase25_guard.host_refusal_reasons("ms_cve_replay.py")
    if not refusal:
        print("[ms-cve-replay] self-test FAILED: the guard admitted a host invocation")
        return 1
    man = phase25_guard.load_manifest()
    joined = " ".join(refusal)
    if str(man.get("marker")) not in joined or str(man.get("env_flag")) not in joined:
        print("[ms-cve-replay] self-test FAILED: the refusal does not name the marker and flag")
        return 1

    historical = {"cves": [
        {"cve_id": "CVE-2024-9143", "memory_safety": True, "taxonomy": "BUFFER_OVERFLOW"},
        {"cve_id": "CVE-2024-0727", "memory_safety": True, "taxonomy": "NULL_DEREFERENCE"},
        {"cve_id": "CVE-2022-0778", "memory_safety": False, "taxonomy": "ALGORITHM_COMPLEXITY"},
    ]}
    good = [
        {"replay_id": "replay-CVE-2024-9143", "cve_id": "CVE-2024-9143",
         "taxonomy": "BUFFER_OVERFLOW", "state": "CANDIDATE_SAFE_REJECTION",
         "candidate_identity": "cand", "harness_ran": True, "control_fired": True,
         "structure": None, "evidence": ["x"]},
        {"replay_id": "replay-CVE-2024-0727", "cve_id": "CVE-2024-0727",
         "taxonomy": "NULL_DEREFERENCE", "state": "CANDIDATE_STRUCTURALLY_EXCLUDED",
         "candidate_identity": "cand", "harness_ran": True, "control_fired": True,
         "structure": "the mechanism is inexpressible", "evidence": ["x"]},
    ]
    body = {"replays": good, "counts": recompute_counts(good, historical),
            "rule": {"authority": {"declaration": "d", "candidate": "c",
                                   "authority_prefixes": "a", "probe": "p", "census": "h"}}}
    if cve_replay_findings(body, historical):
        print(f"[ms-cve-replay] self-test FAILED: a clean plane reported problems: "
              f"{cve_replay_findings(body, historical)[:3]}")
        return 1
    ctrl = cve_replay_sensitivity_control(body, historical)
    if not (ctrl["honest"] and ctrl["specificity_holds"]):
        print(f"[ms-cve-replay] self-test FAILED: the control did not fire on every seed: "
              f"{ctrl['seeded']}")
        return 1
    print(f"[ms-cve-replay] self-test ok: guard refuses a host invocation ({len(refusal)} "
          f"reason(s)); {len(ctrl['seeded'])} seeded mutation(s) each caught with specificity")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="replay the historical CVEs and write artifacts/phase25/cve-replay/")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed plane")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the guard refuses the host and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first: this tool compiles and runs probes.
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
