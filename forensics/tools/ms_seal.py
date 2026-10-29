#!/usr/bin/env python3
"""Phase 25.21 -- the memory-safety seal.

`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` section 2's 25.21 row gives this subphase one
obligation: **the seal**, *the closure of the bounded claim and the non-claims it never exceeds*,
with the evidence `docs/PHASE-25-MEMORY-SAFETY-SEAL.md` (at the seal). It is the last of the
stratum's twenty-two contract units, so its court, `MS-SEAL`, is the last row of
`artifacts/phase25/COURTS.json` and the ledger's `open_in_this_stratum` closes to zero when it
lands.

What the seal is, and what it is not
------------------------------------
The seal consolidates, from the committed evidence, **the bounded claim** the stratum records --
in the plan, not as a proof:

    the memory-safety-relevant trusted computing base of the exact admitted candidate has been
    exhaustively inventoried over its first-party shipped source/build surface; unsafe operations
    are mapped to their safety contracts, Phase-22 reachability, Phase-24 downstream usage and
    available dynamic/formal evidence, with no unexplained reachable unsafe site in the claimed
    profile.

It is **not** "no memory-safety bug can exist" and it is **not** "100% memory safe". A passing seal
is an **instrument** plus an **observation record**: the court passes while the atlas carries open
residuals, and the seal records those residuals, the non-claims and the withheld parity claim as
findings, so a green seal is never read as the property it does not carry (the two-axis split of
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` section 3.8).

The four parts, and they are not interchangeable
------------------------------------------------
1. **The courts.** One row per Phase-25 court that has landed (25.0 through 25.20, twenty-one of
   them), each carrying the verdict the court *re-derives* (the seal re-runs each court's own
   handler over the committed planes rather than reading `artifacts/phase25/COURTS.json`, which the
   runner deletes and rewrites), its committed artefact and that artefact's digest. A court whose
   result is missing from the seal is a finding.

2. **The residual census.** Every residual the committed planes carry, classified from the closed
   vocabulary (`memory_safety_schemas.RESIDUAL_CLASSES`) and disposed from
   `RESIDUAL_DISPOSITIONS`, with the open ones named. The seal publishes the census rather than a
   count, so an unknown is never read as a zero.

3. **The bounded claim and the parity status.** The claim is stated verbatim; `PARITY_VERIFIED` is
   **WITHHELD** (the plan requires it, and the stratum's courts stage no probe pair and so declare
   no parity), and the seal records that rather than silently omitting it.

4. **The non-claims.** The nine non-claims of section 0, plus the four the seal adds (that
   Miri/sanitizer/Kani are complementary evidence and not whole-program proofs; that matching
   transcripts are not memory-safety proofs; that a green instrument is not a proof of absence; and
   that the bounded claim is not "no bug can exist"). A non-claim dropped from the seal is a
   finding.

Why `passed` is False
---------------------
The seal-class summary record (`memory_safety_schemas.validate_summary`) refuses `passed=true`
while an externally reachable unsafe site carries tool state `UNSUPPORTED`. The committed tool
planes record exactly that: `MS-ASAN-MSMAN` (183 sites), `MS-MIRI` (7,014 sites) and `MS-TSAN`
(1 site) could not instrument or express foreign dynamic boundaries, and a subset of those sites is
externally reachable. So this seal records `passed=false` with the count named, and the court still
passes as an instrument. That is the whole point of the rule: a tool state of `UNSUPPORTED` is
never `PASS` (section 3.6).

Determinism and the regeneration policy
---------------------------------------
Everything this file reads is a committed artefact: the Phase-25 court handlers over their
committed planes, the committed `forensics/phase25-obligations.json`, and the committed venue
manifest. It fetches nothing, compiles nothing, links nothing, runs no tool and no probe, so it is
a **pure derivation** -- the same class as `ms_red_team.py` and `ms_frf_closure.py`. It is therefore
wired into `evidence_determinism.py`'s `GENERATORS_BEFORE_LEDGERS`/`COMPARED` and declared
`metadata_only` in `forensics/memory-safety/container.json`; the guard's `require_admitted()` is
still called first, so the admission is the committed manifest's and not a special case in this
file.

Output
------
    artifacts/phase25/summary.json                 (the seal-class closure record, kind `summary`)
    docs/PHASE-25-MEMORY-SAFETY-SEAL.md            (the human-readable seal, generated here)

Usage:
  python3 forensics/tools/ms_seal.py --measure     # derive and write the summary and the seal
  python3 forensics/tools/ms_seal.py --check       # re-run the pure checks over the committed seal
  python3 forensics/tools/ms_seal.py --self-test   # metadata-only + a synthetic seal + the control

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    artefact_evidence_digest,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    write_json,
    write_text,
)

# The Docker-only execution guard, called first. This tool executes nothing -- it reads committed
# atlases and re-runs pure checks -- so the manifest lists it `metadata_only` and the guard admits
# it on any host.
import phase25_guard  # noqa: E402

import memory_safety_schemas as schemas  # noqa: E402

import ms_frf_closure  # noqa: E402

import phase25_obligations as po  # noqa: E402

GENERATOR = "forensics/tools/ms_seal.py"
ARTEFACT_REL = "artifacts/phase25/summary.json"
OUT = REPO_ROOT / ARTEFACT_REL
SEAL_DOC_REL = "docs/PHASE-25-MEMORY-SAFETY-SEAL.md"
SEAL_DOC = REPO_ROOT / SEAL_DOC_REL
COURT = "MS-SEAL"
PHASE = 25

PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
LEDGER = REPO_ROOT / "forensics" / "phase25-obligations.json"
REGISTRY = REPO_ROOT / "artifacts" / "phase25" / "COURTS.json"


def registry_counts() -> dict:
    """The runner's own Phase-25 registry, read **only** to state the disagreement.

    The seal re-derives the courts from their committed planes and deliberately does not adopt
    this file's verdicts: the runner deletes and rewrites it, and it currently records every row
    as `pass` while the re-derivation fails six. Reading it here keeps that discrepancy visible in
    the generated seal instead of letting one record silently stand for the other.
    """
    try:
        body = _body(_load(REGISTRY))
    except (OSError, ValueError, KeyError):
        return {}
    rows = body.get("courts") or []
    passed = [r for r in rows if str(r.get("verdict")) == "pass"]
    failed = [r for r in rows if str(r.get("verdict")) != "pass"]
    return {
        "rows": len(rows),
        "pass": len(passed),
        "fail": len(failed),
        "failed": sorted(str(r.get("court")) for r in failed),
    }

# The unit whose evidence is this very seal. Its artefact is the seal document; its own summary is
# the derivation, so the courts table excludes it (the seal does not summarise itself).
SELF_UNIT = "memory-safety-seal"

# The tool planes whose per-site state is joined to the census, in a fixed order so the derivation
# is deterministic, with the prefix each plane stamps on its state.
TOOL_PLANES: tuple[tuple[str, str], ...] = (
    ("miri", "MIRI_"),
    ("asan-msan", "ASAN_"),
    ("tsan", "TSAN_"),
    ("kani", "KANI_"),
)

# The strength order for a site's aggregate dynamic/formal tool state: a FAIL is a genuine finding
# and dominates; a PASS is coverage; a NOT_REACHABLE tool looked and did not execute the site; an
# UNSUPPORTED tool could not express the question. The aggregate is the strongest evidence any tool
# carries, so a site covered by ASan is not read UNSUPPORTED merely because Miri could not build it.
STATE_RANK: dict[str, int] = {"FAIL": 3, "PASS": 2, "NOT_REACHABLE": 1, "UNSUPPORTED": 0}

# How many externally reachable unsupported/FAIL sites to name, so the seal grounds `passed=false`
# in rows without restating 7,100 ids. The full count is carried in `counts`.
SITE_SAMPLE = 64

# The plan's bounded claim, verbatim (docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 0).
BOUNDED_CLAIM = (
    "the memory-safety-relevant trusted computing base of the exact admitted candidate has been "
    "exhaustively inventoried over its first-party shipped source/build surface; unsafe operations "
    "are mapped to their safety contracts, Phase-22 reachability, Phase-24 downstream usage and "
    "available dynamic/formal evidence, with no unexplained reachable unsafe site in the claimed "
    "profile"
)

# The nine non-claims of section 0, plus the four the seal adds. A seal that drops one is refused.
NON_CLAIMS: tuple[str, ...] = (
    "safe Rust does not prove protocol correctness: memory safety is not behavioural correctness, "
    "and a sound unsafe site is not a correct protocol",
    "unsafe Rust is not inherently vulnerable: an unsafe operation with a discharged contract is a "
    "sound operation, so an unsafe site is not a defect",
    "unsafe LOC is not a vulnerability count: lines of unsafe code are a secondary projection of "
    "the compiler-derived census, and a count is not a risk",
    "Miri, ASan and TSan are not exhaustive: a tool that instruments a target records what it "
    "observed, and NOT_REACHABLE and UNSUPPORTED are not clean results",
    "Kani does not prove unsupported or concurrent whole-program behaviour: a proof is only as wide "
    "as the harness that expresses it",
    "historical CVE extinction does not predict a future CVE count: replaying the past is not a "
    "statement about an unmeasured future",
    "compatibility is not security: passing the compatibility strata is not memory safety",
    "memory safety is not cryptographic correctness: a sound implementation can still be "
    "cryptographically wrong",
    "absence of a crash is not structural proof: a run that did not crash is not a proof that no "
    "path can",
    "Miri, the sanitizers and Kani are complementary evidence, not whole-program proofs: each "
    "covers the profile, harness and schedule it ran, and none of them proves the candidate",
    "matching transcripts are not memory-safety proofs: a differential replay matching the "
    "authority is evidence about behaviour, not a proof about memory",
    "a green instrument is not a proof of absence: a passing court records that the instrument ran "
    "and its control was honest, not that no unsafe path exists",
    "the bounded claim is not a claim that no bug can exist: it is a statement about the inventory "
    "of a fixed candidate's first-party surface in the claimed profile",
)

# Phrases a bounded claim must never contain: the seal is the place the stratum states what it does
# not say, so an overclaim here is refused by name rather than left to a reader.
FORBIDDEN_CLAIM_PHRASES: tuple[str, ...] = (
    "100%",
    "100 percent",
    "no memory-safety bug",
    "no memory safety bug",
    "fully memory safe",
    "completely memory safe",
    "proves memory safety",
    "proves the candidate is memory safe",
    "cannot have a memory",
)

WHAT_THIS_IS = (
    "Phase 25.21's memory-safety seal: the courts (the twenty-one landed Phase-25 courts, each "
    "re-derived from the committed planes and joined to its committed artefact and digest), the "
    "residual census (every residual classified and disposed, the open ones named), the bounded "
    "claim (stated verbatim), the withheld parity claim and the non-claims. It is an instrument "
    "plus an observation record, and it records passed=false because externally reachable unsafe "
    "sites carry tool state UNSUPPORTED; it is never read as 'the candidate is memory safe'."
)

SORT_KEY = (
    "courts by the plan's subphase order; residual_census by class and by disposition; "
    "open_items by id; reachable_unsafe_sites by site id; counts/courts/census/parity/claim the "
    "derivation of the committed planes; every list sorted"
)


class NotDriven(Exception):
    """The seal could not be constructed from the committed evidence."""


# --------------------------------------------------------------------------------------------
# reading and decoding
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise NotDriven(f"committed artefact missing: {rel(path)}")
    return json.loads(path.read_text(encoding="utf-8"))


def _body(doc: dict) -> dict:
    return doc.get("body", doc) if isinstance(doc, dict) else doc


_EVIDENCE_CACHE: dict = {}


def collect_evidence() -> dict:
    """The live committed evidence every derivation is pure over.

    The decoded planes come from `ms_frf_closure.collect_evidence` (one decoder for every plane);
    the courts come from re-running each landed Phase-25 court's own handler over those committed
    planes -- never from `artifacts/phase25/COURTS.json`, which `run_courts.py` deletes and rewrites,
    so a court that read it back would form a cycle with its own writer. No compiler, no tool, no
    probe, no `.gemel` store is touched.
    """
    key = id(REPO_ROOT)
    if key in _EVIDENCE_CACHE:
        return _EVIDENCE_CACHE[key]

    fc = ms_frf_closure.collect_evidence()
    planes = fc["planes"]

    # The landed courts, re-derived. Imported lazily: `phase25_courts` imports this module's court
    # handler lazily, so the lazy import here keeps the two modules acyclic at load time.
    import phase25_courts as pc  # noqa: E402

    court_results: dict[str, dict] = {}
    for name, handler in pc.COURTS:
        if name == COURT:
            continue
        fn = getattr(pc, handler, None)
        if fn is None:
            court_results[name] = {"court": name, "verdict": "fail", "problems": ["handler missing"],
                                   "findings": [], "control": {}, "counts": {}}
            continue
        court_results[name] = fn(name)

    # Each court's artefact is bound by its **evidence** digest (`body_hash`), not its file
    # digest. The derived planes record the file digest of the downstream chain, and that chain
    # records `implemented-surface.json`'s build product, so a file-digest binding is not
    # reproducible across machines. `artefact_evidence_digest` is the shared policy (D30).
    artefact_path: dict[str, str | None] = {}
    artefact_sha: dict[str, str | None] = {}
    for unit, (relpath, _kinds) in ms_frf_closure.RECORD_EVIDENCE.items():
        artefact_path[unit] = relpath
        p = REPO_ROOT / relpath if relpath else None
        artefact_sha[unit] = (artefact_evidence_digest(p)
                             if (p is not None and p.is_file()) else None)

    candidate_identity = None
    for p in planes.values():
        if isinstance(p, dict) and p.get("candidate_identity"):
            candidate_identity = p["candidate_identity"]
            break

    ledger_body = _body(_load(LEDGER)) if LEDGER.is_file() else {}

    evidence = {
        "planes": planes,
        "court_results": court_results,
        "court_units": list(po.COURT_UNITS),
        "artefact_path": artefact_path,
        "artefact_sha": artefact_sha,
        "candidate_identity": candidate_identity,
        "venue_image": _venue_image(planes),
        "cargo_profile": _cargo_profile(planes),
        "ledger": {
            "artefact": rel(LEDGER),
            # The ledger's digest is deliberately **not** bound: summary.json's own digest reaches
            # this registry through `forensics/phase-state.json` (the phase's `seal_sha256`), the
            # registry feeds the ledger, and the ledger feeds back into the planes the seal
            # summarises through the security lineage -- so binding the ledger's digest here would
            # re-close that digest cycle. The ledger's *counts* are recorded (they are the derived
            # states, which are stable), never its bytes.
            "counts": _ledger_counts(ledger_body),
        },
        "existing": sorted(fc.get("existing") or []),
    }
    _EVIDENCE_CACHE[key] = evidence
    return evidence


def _venue_image(planes: dict) -> str:
    for unit, _prefix in TOOL_PLANES:
        venue = (planes.get(unit) or {}).get("venue") or {}
        if venue.get("admitted_image"):
            return str(venue["admitted_image"])
    return "openssl-rs-court:1"


def _cargo_profile(planes: dict) -> str | None:
    for unit, _prefix in TOOL_PLANES:
        tc = (planes.get(unit) or {}).get("toolchain") or {}
        if tc.get("profile"):
            return str(tc["profile"])
    return None


def _ledger_counts(ledger_body: dict) -> dict:
    counts = (ledger_body or {}).get("counts") or {}
    return {
        "owned": counts.get("owned"),
        "implemented": counts.get("implemented"),
        "open_in_this_stratum": counts.get("open_in_this_stratum"),
        "contract_units": counts.get("contract_units"),
    }


# --------------------------------------------------------------------------------------------
# the derivations
# --------------------------------------------------------------------------------------------

def derive_court_rows(evidence: dict) -> list[dict]:
    """One row per landed Phase-25 court, re-derived, joined to its artefact and digest.

    Ordered as the plan orders the subphases (`phase25_obligations.COURT_UNITS`), excluding the
    seal itself. The verdict is the court's own re-derived verdict, not a value read from the
    runner's registry.
    """
    results = evidence.get("court_results") or {}
    paths = evidence.get("artefact_path") or {}
    shas = evidence.get("artefact_sha") or {}
    rows: list[dict] = []
    for unit, court, _closure, _what in evidence["court_units"]:
        if unit == SELF_UNIT:
            continue
        r = results.get(court) or {}
        ctrl = r.get("control") or {}
        rows.append({
            "court": court,
            "unit": unit,
            "verdict": str(r.get("verdict") or "fail"),
            "artefact": paths.get(unit),
            "artefact_sha256": shas.get(unit),
            "findings": len(r.get("findings") or []),
            "control_honest": bool(ctrl.get("honest")),
            "control_specificity": bool(ctrl.get("specificity_holds")),
        })
    return rows


def _site_states(planes: dict) -> dict[str, str]:
    """The strongest dynamic/formal tool state any tool plane records for each census site."""
    out: dict[str, str] = {}
    for unit, prefix in TOOL_PLANES:
        sites = (planes.get(unit) or {}).get("sites") or {}
        if not isinstance(sites, dict):
            continue
        for sid, row in sites.items():
            if not isinstance(row, dict):
                continue
            state = str(row.get("state") or "")
            suffix = state[len(prefix):] if state.startswith(prefix) else state
            if suffix not in schemas.TOOL_STATES:
                continue
            prev = out.get(sid)
            if prev is None or STATE_RANK[suffix] > STATE_RANK[prev]:
                out[sid] = suffix
    return out


def derive_tool_surface(evidence: dict) -> dict:
    """The externally reachable census sites and their aggregate tool state.

    The exposure plane gives every census site exactly one exposure class; the tool planes give the
    per-site instrument state. The seal joins them, so a site is externally reachable by the
    committed measurement and its coverage is the committed instrument's, not a typed one.
    """
    planes = evidence.get("planes") or {}
    exposure = (planes.get("exposure-classification") or {}).get("sites") or {}
    states = _site_states(planes)
    by_state: Counter = Counter()
    ext_by_state: Counter = Counter()
    ext_unsupported: list[str] = []
    ext_fail: list[str] = []
    if isinstance(exposure, dict):
        for sid, row in exposure.items():
            cls = str((row or {}).get("e")) if isinstance(row, dict) else ""
            state = states.get(sid, "UNSUPPORTED")
            by_state[state] += 1
            if cls in schemas.EXTERNALLY_REACHABLE_EXPOSURE:
                ext_by_state[state] += 1
                if state == "UNSUPPORTED":
                    ext_unsupported.append(sid)
                elif state == "FAIL":
                    ext_fail.append(sid)
    return {
        "sites_by_tool_state": {k: by_state[k] for k in sorted(by_state)},
        "externally_reachable_by_tool_state": {k: ext_by_state[k] for k in sorted(ext_by_state)},
        "externally_reachable": sum(ext_by_state.values()),
        "externally_reachable_unsupported": len(ext_unsupported),
        "externally_reachable_fail": len(ext_fail),
        "externally_reachable_unsupported_ids": sorted(ext_unsupported),
        "externally_reachable_fail_ids": sorted(ext_fail),
    }


def derive_reachable_sample(evidence: dict, tool: dict) -> list[dict]:
    """A bounded sample of externally reachable sites that carry no expressing instrument.

    One row per site, tool state `UNSUPPORTED`, claimed_pass false, naming the tools that could not
    express it. It grounds `passed=false` in rows (the seal-class summary refuses a pass while such
    a site exists) without restating thousands of ids; the full counts are in `counts`.
    """
    planes = evidence.get("planes") or {}
    exposure = (planes.get("exposure-classification") or {}).get("sites") or {}
    unsupported_by_site: dict[str, set[str]] = {}
    for unit, prefix in TOOL_PLANES:
        sites = (planes.get(unit) or {}).get("sites") or {}
        if not isinstance(sites, dict):
            continue
        for sid, row in sites.items():
            if not isinstance(row, dict):
                continue
            state = str(row.get("state") or "")
            suffix = state[len(prefix):] if state.startswith(prefix) else state
            if suffix == "UNSUPPORTED":
                unsupported_by_site.setdefault(sid, set()).add(unit)
    rows: list[dict] = []
    for sid in tool["externally_reachable_unsupported_ids"][:SITE_SAMPLE]:
        cls = str((exposure.get(sid) or {}).get("e")) if isinstance(exposure, dict) else ""
        tools = ", ".join(sorted(unsupported_by_site.get(sid, set())))
        rows.append({
            "unsafe_site_id": sid,
            "exposure_class": cls,
            "tool_state": "UNSUPPORTED",
            "claimed_pass": False,
            "explanation": (
                f"no dynamic/formal instrument expressed this externally reachable site "
                f"(tool plane(s) {tools} could not instrument or execute it); UNSUPPORTED is never "
                f"a pass (docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 3.6)"
            ),
        })
    return rows


def derive_open_items(evidence: dict, census: dict, tool: dict) -> list[dict]:
    """The honest open items, named (not smoothed to a count).

    Each item is a leftover the seal does not resolve: the TSan default-libctx data race, the four
    replay UNKNOWN CVEs, the three HIDDEN and the one UNRESOLVED mechanism, the red-team
    inconclusive attempt, the census's UNKNOWN reachability and unresolved mappings, the cargo-geiger
    cross-check the venue could not run, and the externally reachable sites no instrument expressed.
    """
    planes = evidence.get("planes") or {}
    items: list[dict] = []

    # The TSan default-libctx namemap data race (an open product residual).
    tsan_res = (planes.get("tsan") or {}).get("residuals") or []
    for r in tsan_res:
        if isinstance(r, dict) and r.get("residual_id") == "res-tsan-default-libctx-race":
            items.append({
                "id": "res-tsan-default-libctx-race",
                "kind": "product_residual",
                "disposition": str(r.get("disposition") or "open"),
                "summary": "a TSan data race on the default OSSL_LIB_CTX namemap counter",
                "detail": str(r.get("detail") or "")[:400],
                "evidence": ["artifacts/phase25/tsan.json"],
            })

    # The replay UNKNOWN CVEs.
    cr = planes.get("cve-replay") or {}
    unknown = []
    reps = cr.get("replays")
    if isinstance(reps, list):
        unknown = sorted(str(x.get("cve_id")) for x in reps
                         if isinstance(x, dict) and x.get("state") == "UNKNOWN")
    if unknown:
        items.append({
            "id": "cve-replay-unknown",
            "kind": "cve_replay_unknown",
            "disposition": "open",
            "summary": f"{len(unknown)} historical CVE(s) the public ABI cannot express",
            "detail": ", ".join(unknown),
            "evidence": ["artifacts/phase25/cve-replay/index.json"],
        })

    # The mechanism reconciliation's HIDDEN and UNRESOLVED mechanisms.
    mech = planes.get("mechanism-reconciliation") or {}
    hidden, unresolved = [], []
    for m in mech.get("mechanisms") or []:
        if not isinstance(m, dict):
            continue
        if m.get("disposition") == "HIDDEN":
            hidden.append(str(m.get("mechanism_id")))
        elif m.get("disposition") == "UNRESOLVED":
            unresolved.append(str(m.get("mechanism_id")))
    if hidden or unresolved:
        items.append({
            "id": "mechanism-reconciliation-open",
            "kind": "mechanism_unreconciled",
            "disposition": "open",
            "summary": f"{len(hidden)} HIDDEN and {len(unresolved)} UNRESOLVED mechanism(s)",
            "detail": "; ".join(sorted(hidden) + sorted(unresolved)),
            "evidence": ["artifacts/phase25/mechanisms.json"],
        })

    # The red-team inconclusive attempt.
    rt = planes.get("red-team") or {}
    for a in rt.get("attacks") or []:
        if isinstance(a, dict) and a.get("outcome") == "INCONCLUSIVE":
            items.append({
                "id": str(a.get("attack_id")),
                "kind": "red_team_inconclusive",
                "disposition": "open",
                "summary": (f"an inconclusive attack over {a.get('amount')} site(s); an "
                            f"inconclusive attack is not a pass"),
                "detail": str(a.get("detail") or "")[:400],
                "evidence": ["artifacts/phase25/red-team.json"],
            })

    # The census's unresolved / UNKNOWN reachability mappings.
    p22 = (planes.get("phase22-crosswalk") or {}).get("counts") or {}
    exp_counts = (planes.get("exposure-classification") or {}).get("counts") or {}
    items.append({
        "id": "census-unresolved-reachability",
        "kind": "evidence_missing",
        "disposition": "open",
        "summary": (f"{p22.get('sites_unresolved')} census site(s) have no resolved Phase-22 "
                    f"authority mapping and {exp_counts.get('sites_unknown_reachability')} site(s) "
                    f"are UNKNOWN_REACHABILITY"),
        "detail": f"phase22 unresolved_by_class={p22.get('unresolved_by_class')}",
        "evidence": ["artifacts/phase25/phase22-crosswalk.json", "artifacts/phase25/exposure.json"],
    })

    # The cargo-geiger cross-check the venue could not run.
    geiger = ((planes.get("source-census") or {}).get("crosschecks") or {}).get("geiger") or {}
    if geiger:
        items.append({
            "id": "census-geiger-unavailable",
            "kind": "tool_unsupported",
            "disposition": "open",
            "summary": f"the {geiger.get('tool')} cross-check is {geiger.get('status')}",
            "detail": str(geiger.get("note") or "")[:400],
            "evidence": ["artifacts/phase25/source-census.json"],
        })

    # The externally reachable sites no instrument expressed.
    if tool.get("externally_reachable_unsupported"):
        items.append({
            "id": "externally-reachable-unsupported",
            "kind": "tool_unsupported",
            "disposition": "open",
            "summary": (f"{tool['externally_reachable_unsupported']} externally reachable site(s) "
                        f"carry tool state UNSUPPORTED"),
            "detail": ("the tool planes could not instrument or execute this many externally "
                       "reachable sites, so the seal records passed=false"),
            "evidence": ["artifacts/phase25/miri.json", "artifacts/phase25/asan-msan.json",
                         "artifacts/phase25/tsan.json", "artifacts/phase25/exposure.json"],
        })
    if tool.get("externally_reachable_fail"):
        items.append({
            "id": "externally-reachable-fail",
            "kind": "unexplained_reachable_unsafe",
            "disposition": "classified",
            "summary": (f"{tool['externally_reachable_fail']} externally reachable site(s) carry "
                        f"tool state FAIL (each dispositioned in its plane)"),
            "detail": ", ".join(tool["externally_reachable_fail_ids"][:SITE_SAMPLE]),
            "evidence": ["artifacts/phase25/miri.json", "artifacts/phase25/tsan.json"],
        })
    return sorted(items, key=lambda x: x["id"])


def derive_counts(evidence: dict, courts: list[dict], census: dict, tool: dict) -> dict:
    planes = evidence.get("planes") or {}
    ccounts = (planes.get("source-census") or {}).get("counts") or {}
    ecounts = (planes.get("exposure-classification") or {}).get("counts") or {}
    mech = (planes.get("mechanism-reconciliation") or {}).get("counts") or {}
    cr = (planes.get("cve-replay") or {}).get("counts") or {}
    rt = (planes.get("red-team") or {}).get("counts") or {}
    geiger = ((planes.get("source-census") or {}).get("crosschecks") or {}).get("geiger") or {}
    return {
        "courts": len(courts),
        "courts_pass": sum(1 for c in courts if c["verdict"] == "pass"),
        "courts_fail": sum(1 for c in courts if c["verdict"] != "pass"),
        "unsafe_sites": ccounts.get("sites"),
        "unsafe_contexts": ccounts.get("unsafe_contexts"),
        "first_party_files": ccounts.get("files"),
        "externally_reachable": tool["externally_reachable"],
        "externally_reachable_unsupported": tool["externally_reachable_unsupported"],
        "externally_reachable_fail": tool["externally_reachable_fail"],
        "sites_by_tool_state": tool["sites_by_tool_state"],
        "sites_unknown_reachability": ecounts.get("sites_unknown_reachability"),
        "residual_total": census["total"],
        "residual_records": census["records"],
        "residual_crosscheck": census["crosscheck"],
        "residual_disposed": census["disposed"],
        "residual_open": census["open"],
        "residual_undisposed": census["undisposed"],
        "residuals_by_class": census["by_class"],
        "residuals_by_disposition": census["by_disposition"],
        "unknown_cves": (cr.get("by_state") or {}).get("UNKNOWN", 0),
        "mechanisms_hidden": (mech.get("by_disposition") or {}).get("HIDDEN", 0),
        "mechanisms_unresolved": (mech.get("by_disposition") or {}).get("UNRESOLVED", 0),
        "mechanisms_eliminated": (mech.get("by_disposition") or {}).get("ELIMINATED", 0),
        "red_team_inconclusive": rt.get("inconclusive", 0),
        "red_team_found_gap": rt.get("found_gap", 0),
        "geiger_status": geiger.get("status"),
        "reachable_sample": SITE_SAMPLE,
        "parity_status": "WITHHELD",
        "passed": tool["externally_reachable_unsupported"] == 0,
        "ledger": evidence["ledger"]["counts"],
    }


def derive_parity() -> dict:
    """`PARITY_VERIFIED` is withheld by the plan; the seal records the withholding, not a grant."""
    return {
        "status": "WITHHELD",
        "reason": (
            "docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md requires PARITY_VERIFIED to be withheld: the "
            "stratum's courts stage no artifacts/phase25/probes/<probe>.{authority,candidate} pair, "
            "so no Phase-25 court is FRF-declarable and no parity between an authority and the "
            "candidate is declared here. A memory-safety inventory is not a parity claim"
        ),
    }


def derive_claim(counts: dict, census: dict, tool: dict) -> dict:
    complete = bool(
        counts["courts_fail"] == 0
        and counts["residual_open"] == 0
        and counts["residual_undisposed"] == 0
        and tool["externally_reachable_unsupported"] == 0
    )
    return {
        "complete": complete,
        "reason": (
            "the seal records a complete closure only when every court passes and no residual is "
            "open or undisposed and no externally reachable site is UNSUPPORTED. The atlas carries "
            f"{counts['residual_open']} open residual(s), {counts['residual_undisposed']} "
            f"undisposed residual(s) and {tool['externally_reachable_unsupported']} externally "
            f"reachable UNSUPPORTED site(s), so the closure is not complete and the bounded claim "
            f"is recorded rather than a stronger one"
        ) if not complete else "every court passes and no residual is open or undisposed",
    }


def derive_property_findings(counts: dict, census: dict, open_items: list[dict],
                            courts: list[dict]) -> list[str]:
    out: list[str] = []
    failed = [str(c["court"]) for c in courts if c["verdict"] != "pass"]
    registry = registry_counts()
    out.append(
        f"the seal re-derives {counts['courts']} non-`MS-SEAL` Phase-25 court result(s) from their "
        f"committed planes: {counts['courts_pass']} pass, {counts['courts_fail']} fail"
        + (f" ({', '.join(failed)})" if failed else "")
        + "; the runner's registry "
        f"artifacts/phase25/COURTS.json records {registry.get('rows', '?')} court row(s), "
        f"{registry.get('pass', '?')} pass and {registry.get('fail', '?')} fail, and is not this "
        "seal's input, so the two records disagree and the seal states the disagreement rather "
        "than adopting the registry's verdicts"
    )
    out.append(
        f"the residual census classifies and disposes {counts['residual_records']} residual "
        f"record(s) plus {counts['residual_crosscheck']} light cross-check leftover(s); "
        f"{counts['residual_open']} are open and {counts['residual_undisposed']} undisposed"
    )
    out.append(
        f"the seal records passed=false because {counts['externally_reachable_unsupported']} "
        f"externally reachable site(s) carry tool state UNSUPPORTED; UNSUPPORTED is never PASS "
        f"(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 3.6)"
    )
    if open_items:
        named = ", ".join(str(i["id"]) for i in open_items)
        out.append(f"the open items are named rather than smoothed to a zero: {named}")
    out.append(
        "the bounded claim is the inventory of a fixed candidate's first-party surface in the "
        "claimed profile; it is NOT 'no memory-safety bug can exist' and NOT '100% memory safe'"
    )
    out.append(
        "PARITY_VERIFIED is WITHHELD: the stratum stages no probe pair, so no Phase-25 court is "
        "parity-declarable"
    )
    out.append(
        "the non-claims are recorded as findings (safe Rust does not prove protocol correctness; "
        "unsafe Rust is not inherently vulnerable; unsafe LOC is not a vulnerability count; "
        "Miri/ASan/TSan are not exhaustive; Kani does not prove unsupported or concurrent "
        "whole-program behaviour; historical CVE extinction does not predict a future CVE count; "
        "compatibility is not security; memory safety is not cryptographic correctness; absence of "
        "a crash is not structural proof), so a passing seal is never 'the candidate is memory safe'"
    )
    return out


_DERIVED_CACHE: dict = {}


def derive(evidence: dict) -> dict:
    """The whole seal derived once (cached), so the court's control does not re-run the courts."""
    key = id(evidence)
    if key in _DERIVED_CACHE:
        return _DERIVED_CACHE[key]
    courts = derive_court_rows(evidence)
    census = ms_frf_closure.derive_residual_census(evidence)
    tool = derive_tool_surface(evidence)
    sample = derive_reachable_sample(evidence, tool)
    open_items = derive_open_items(evidence, census, tool)
    counts = derive_counts(evidence, courts, census, tool)
    d = {
        "courts": courts,
        "residual_census": census,
        "tool_surface": tool,
        "reachable_unsafe_sites": sample,
        "open_items": open_items,
        "counts": counts,
        "parity": derive_parity(),
        "claim": derive_claim(counts, census, tool),
        "passed": bool(counts["passed"]),
        "property_status": "NOT_CLAIMED",
        "property_findings": derive_property_findings(counts, census, open_items, courts),
    }
    _DERIVED_CACHE[key] = d
    return d


def build_body(evidence: dict) -> dict:
    """Assemble the seal-class summary body from committed evidence. Pure, no writes."""
    d = derive(evidence)
    t = d["tool_surface"]
    c = d["counts"]
    profile = f"{evidence.get('venue_image') or 'openssl-rs-court'} · cargo-profile " \
              f"{evidence.get('cargo_profile') or 'unknown'}"
    body: dict = {
        "what_this_is": WHAT_THIS_IS,
        "sort_key": SORT_KEY,
        "summary_id": "phase25-memory-safety-seal",
        "profile": profile,
        "candidate_identity": evidence.get("candidate_identity") or "openssl-rs (unknown)",
        "bounded_claim": BOUNDED_CLAIM,
        "courts": d["courts"],
        "residual_census": d["residual_census"],
        "open_items": d["open_items"],
        "reachable_unsafe_sites": d["reachable_unsafe_sites"],
        "tool_surface": {
            "externally_reachable": t["externally_reachable"],
            "externally_reachable_unsupported": t["externally_reachable_unsupported"],
            "externally_reachable_fail": t["externally_reachable_fail"],
            "externally_reachable_by_tool_state": t["externally_reachable_by_tool_state"],
            "sites_by_tool_state": t["sites_by_tool_state"],
        },
        "parity": d["parity"],
        "ledger": evidence["ledger"],
        "counts": c,
        "claim": d["claim"],
        "passed": d["passed"],
        "property_status": d["property_status"],
        "property_findings": d["property_findings"],
        "non_claims": list(NON_CLAIMS),
        "evidence": _evidence_paths(evidence),
    }
    return body


def _evidence_paths(evidence: dict) -> list[str]:
    paths: list[str] = [ARTEFACT_REL, SEAL_DOC_REL, rel(LEDGER)]
    for unit, _court, _cl, _what in evidence["court_units"]:
        if unit == SELF_UNIT:
            continue
        p = (evidence.get("artefact_path") or {}).get(unit)
        if p and p not in paths:
            paths.append(p)
    return sorted(paths)


# --------------------------------------------------------------------------------------------
# the human-readable seal, generated from the same derivation
# --------------------------------------------------------------------------------------------

def render_seal(evidence: dict, body: dict) -> str:
    """Render `docs/PHASE-25-MEMORY-SAFETY-SEAL.md` from the derived body. Deterministic.

    It renders the *body* it is given and does not re-derive: the body is either the fresh
    derivation (`--measure`) or the committed `artifacts/phase25/summary.json` (`--render`), and
    rendering must not turn a documentation correction into a re-measurement of the stratum.
    """
    c = body["counts"]
    led = body["ledger"]["counts"]
    lines: list[str] = []
    A = lines.append

    A("# Phase 25 — the memory-safety stratum: seal")
    A("")
    A("**STATUS: derived.** This document is **generated** by `forensics/tools/ms_seal.py` from the")
    A("committed Phase-25 evidence planes; it is not hand-written, so it cannot drift from them.")
    A("`forensics/tools/evidence_determinism.py` re-runs `ms_seal.py` and byte-compares this file.")
    A("The stratum's obligation ledger is")
    A(f"`forensics/phase25-obligations.json` — `owned` {led.get('owned')}, `implemented`")
    A(f"{led.get('implemented')}, `open_in_this_stratum` {led.get('open_in_this_stratum')}; the")
    A("seal is the last of its twenty-two contract units and the `MS-SEAL` court row is the last of")
    A("`artifacts/phase25/COURTS.json`.")
    A("")
    A("## The bounded claim")
    A("")
    A("> " + body["bounded_claim"] + ".")
    A("")
    A("It is **not** \"no memory-safety bug can exist\" and it is **not** \"100% memory safe\". A")
    A("passing seal is an **instrument** plus an **observation record**: the court passes while the")
    A("atlas carries open residuals, and the seal records those residuals, the withheld parity claim")
    A("and the non-claims as findings, so a green seal is never read as the property it does not")
    A("carry (docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 3.8). This seal records")
    A(f"`passed = {str(body['passed']).lower()}` because")
    A(f"{c['externally_reachable_unsupported']} externally reachable site(s) carry tool state")
    A("`UNSUPPORTED`, and a tool state of `UNSUPPORTED` is never `PASS` (section 3.6).")
    A("")
    A("- Authority: the admitted venue `" + str(evidence.get("venue_image")) + "`; the frozen")
    A("  candidate is `" + str(body["candidate_identity"]) + "`, not live HEAD.")
    A(f"- Court results: this seal re-derives **{c['courts']}** non-`MS-SEAL` Phase-25 courts")
    A(f"  from their committed planes: **{c['courts_pass']} pass, {c['courts_fail']} fail**.")
    failed = [str(x['court']) for x in body['courts'] if x['verdict'] != 'pass']
    if failed:
        A("  The failing courts are " + ", ".join(f"`{n}`" for n in failed) + ".")
    registry = registry_counts()
    A(f"  The runner's registry `artifacts/phase25/COURTS.json` records **{registry.get('rows')} court")
    A(f"  rows, {registry.get('pass')} pass and {registry.get('fail')} fail**; it is not this seal's")
    A("  input (the runner deletes and rewrites it), so the two records disagree and this seal")
    A("  records the disagreement rather than adopting the registry's verdicts. **The seal therefore")
    A(f"  records `passed = {str(body['passed']).lower()}`.** No court is FRF-declarable: each reads")
    A("  committed evidence and stages no")
    A("  `artifacts/phase25/probes/<probe>.{authority,candidate}` pair.")
    A(f"- Obligation ledger: `forensics/phase25-obligations.json` — `owned` {led.get('owned')},")
    A(f"  `implemented` {led.get('implemented')}, `open_in_this_stratum`")
    A(f"  {led.get('open_in_this_stratum')}. Its unit is `memory-safety contract`, a non-export unit.")
    A("- Derived state: `forensics/phase-state.json`, phase 25, from artefact existence. It owns no")
    A("  exported symbol, so its `atlas_owned` count is 0 and it registers no provider row.")
    A("")
    A("## 1. The courts")
    A("")
    A("One row per landed Phase-25 court (25.0 through 25.20). The verdict is the court's own")
    A("re-derived verdict and the finding count is its own, so the row is a re-derivation, not a")
    A("reading of `artifacts/phase25/COURTS.json` (which the runner deletes and rewrites). Where the")
    A("two disagree, section 'The bounded claim' states both counts and names the failing courts;")
    A("the registry is the runner's record, not an adjudication of the re-derivation. Each")
    A("court's committed artefact **evidence** digest is carried by the machine artefact")
    A("`artifacts/phase25/summary.json`, whose `courts[].artefact_sha256` is that artefact's")
    A("`body_hash` (its evidence digest), not its file digest -- the file digest moves with the")
    A("build product the derived planes carry (docs/DECISIONS.md D30), so binding it would make")
    A("this seal irreproducible across machines. It is deliberately not restated here, because this")
    A("document's own digest is what `forensics/phase-state.json` records as the phase's")
    A("`seal_sha256`, and rendering a digest here would form a digest cycle the pipeline could not")
    A("reproduce.")
    A("")
    A("| court | unit | verdict | finding(s) | control | artefact |")
    A("|---|---|---|---|---|---|")
    for row in body["courts"]:
        ctrl = ("honest" if row.get("control_honest") and row.get("control_specificity")
                else "NOT-honest")
        A(f"| `{row['court']}` | `{row['unit']}` | {row['verdict']} | {row['findings']} | {ctrl} |")
        A(f" `{row.get('artefact')}` |")
    A("")
    A("## 2. The residual census")
    A("")
    A(f"Every residual the committed planes carry, classified from")
    A("`memory_safety_schemas.RESIDUAL_CLASSES` and disposed from `RESIDUAL_DISPOSITIONS`:")
    A("")
    A(f"- total {c['residual_total']} residual(s): {c['residual_records']} schema record(s) plus")
    A(f"  {c['residual_crosscheck']} light cross-check leftover(s);")
    A(f"- {c['residual_disposed']} disposed, {c['residual_open']} open, {c['residual_undisposed']}")
    A("  undisposed.")
    A("")
    A("By class:")
    A("")
    for k, v in sorted((c.get("residuals_by_class") or {}).items()):
        A(f"- `{k}`: {v}")
    A("")
    A("By disposition:")
    A("")
    for k, v in sorted((c.get("residuals_by_disposition") or {}).items()):
        A(f"- `{k}`: {v}")
    A("")
    A("## 3. The open items")
    A("")
    A("The leftovers the seal does not resolve, named rather than smoothed to a zero:")
    A("")
    for item in body["open_items"]:
        A(f"- **{item['id']}** (`{item['kind']}`, {item['disposition']}): {item['summary']}")
    A("")
    A("## 4. Parity")
    A("")
    A(f"`PARITY_VERIFIED` is **{body['parity']['status']}**. {body['parity']['reason']}.")
    A("")
    A("## 5. The non-claims")
    A("")
    for nc in body["non_claims"]:
        A(f"- {nc}")
    A("")
    A("## 6. The two axes")
    A("")
    A("`measurement_state` (the instrument ran) and `property_status` (what is claimed) are")
    A("deliberately distinct. This seal's court passes as an instrument while its property is")
    A(f"**{body['property_status']}**, and its claim is `complete = {str(body['claim']['complete']).lower()}`.")
    A("For every count in this document, read")
    A("`artifacts/phase25/summary.json` and `docs/SEAL-CENSUS.md`; this seal cites the court records")
    A("rather than restating their arithmetic (D97).")
    A("")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed seal
# --------------------------------------------------------------------------------------------

def seal_findings(body: dict, evidence: dict) -> list:
    """Every way the committed seal contradicts the committed evidence.

    Pure over `body` and `evidence` (the committed planes and the re-derived court results): it is
    what the `MS-SEAL` court runs. It establishes that every landed court's result is present and
    equal to its re-derivation, that the residual census is the derived census, that the bounded
    claim is the plan's claim and carries no overclaim, that `PARITY_VERIFIED` is withheld, that no
    non-claim has been dropped, and that the counts, the claim, `passed` and the property status
    equal their derivation. It is an **instrument**: it passes while the seal records the open
    residuals and `passed=false`, so a passing seal is never read as "the candidate is memory safe".
    """
    problems: list = []
    d = derive(evidence)

    # 0. The record validates against the seal-class summary schema.
    problems += [f"schema: {p}" for p in schemas.validate("summary", body)]

    # 1. The courts: every landed court present, with the re-derived verdict.
    courts = body.get("courts")
    if not isinstance(courts, list):
        return problems + ["the seal's `courts` is not a list"]
    named = [str(r.get("court")) for r in courts]
    if len(set(named)) != len(named):
        problems.append("the seal records a court more than once")
    derived_courts = {r["court"]: r for r in d["courts"]}
    for court in sorted(set(derived_courts) - set(named)):
        problems.append(f"the seal omits the derived court result {court} (dropped)")
    for court in sorted(set(named) - set(derived_courts)):
        problems.append(f"the seal records the court {court}, which the committed evidence does "
                        f"not derive")
    for row in courts:
        court = str(row.get("court"))
        want = derived_courts.get(court)
        if want is None:
            continue
        if row.get("verdict") != want["verdict"]:
            problems.append(f"{court}: the seal records verdict {row.get('verdict')!r}, but the "
                            f"court re-derives {want['verdict']!r}")
        if row.get("artefact") != want["artefact"]:
            problems.append(f"{court}: the seal's artefact {row.get('artefact')!r} is not the "
                            f"derived {want['artefact']!r}")
        if row.get("artefact_sha256") != want["artefact_sha256"]:
            problems.append(f"{court}: the seal's artefact digest is not the committed artefact's")

    # 2. The residual census must be the derived census (a dropped residual is a finding).
    if body.get("residual_census") != d["residual_census"]:
        problems.append("the committed `residual_census` is not the derived census")

    # 3. The bounded claim is the plan's claim and carries no overclaim.
    if body.get("bounded_claim") != BOUNDED_CLAIM:
        problems.append("the bounded claim is not the plan's bounded claim (it was edited)")
    claim_text = str(body.get("bounded_claim") or "").lower()
    for phrase in FORBIDDEN_CLAIM_PHRASES:
        if phrase in claim_text:
            problems.append(f"the bounded claim contains the overclaim {phrase!r}")

    # 4. PARITY_VERIFIED is withheld, never granted.
    parity = body.get("parity") or {}
    if parity != d["parity"]:
        problems.append("the recorded parity status is not the withheld derivation (PARITY must be "
                        "WITHHELD)")
    if parity.get("status") != "WITHHELD":
        problems.append(f"the seal grants parity {parity.get('status')!r}; the plan requires "
                        f"PARITY_VERIFIED to be WITHHELD")

    # 5. No non-claim dropped, and the list is the derived one.
    if body.get("non_claims") != list(NON_CLAIMS):
        problems.append("the seal's non-claims are not the derived non-claims (a non-claim was "
                        "dropped or edited)")

    # 6. The count object, the claim, `passed` and the property status equal their derivation.
    if body.get("counts") != d["counts"]:
        problems.append("the committed `counts` is not the derived `counts` (a typed count)")
    if body.get("claim") != d["claim"]:
        problems.append("the committed `claim` is not the derived claim")
    if bool(body.get("claim", {}).get("complete")) and d["counts"]["residual_open"]:
        problems.append("the seal claims a complete closure while an open residual exists")
    if bool(body.get("passed")) != d["passed"]:
        problems.append(f"the seal records passed={body.get('passed')}, but the derivation is "
                        f"passed={d['passed']}")
    if body.get("property_status") != d["property_status"]:
        problems.append("the committed `property_status` is not the derived status")
    if body.get("reachable_unsafe_sites") != d["reachable_unsafe_sites"]:
        problems.append("the committed `reachable_unsafe_sites` is not the derived sample")
    for field in ("summary_id", "profile", "candidate_identity"):
        if not body.get(field):
            problems.append(f"the seal does not record {field!r}")
    return problems


def seal_sensitivity_control(body: dict, evidence: dict) -> dict:
    """Seed six mutations and require each caught, with specificity holding.

    Each is a distinct way the seal could lie: a court result silently dropped; a residual dropped
    from the census; a claim of completeness/overclaim; PARITY granted; a typed count; and a
    non-claim removed.
    """
    baseline = seal_findings(body, evidence)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def clone() -> dict:
        return copy.deepcopy(body)

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = seal_findings(mutated, evidence)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    # m1: a court result dropped from the seal.
    def drop_court() -> dict:
        b = clone()
        b["courts"] = b["courts"][1:]
        return b

    m1 = check("court_result_dropped", drop_court(), "omits the derived court result")

    # m2: a residual dropped from the census.
    def drop_residual_class() -> dict:
        b = clone()
        by_class = b["residual_census"]["by_class"]
        if by_class:
            by_class.pop(sorted(by_class)[0])
        return b

    m2 = check("residual_dropped", drop_residual_class(), "not the derived census")

    # m3: a claim of completeness (an overclaim in the bounded claim).
    def overclaim() -> dict:
        b = clone()
        b["bounded_claim"] = b["bounded_claim"] + "; the candidate is 100% memory safe"
        return b

    m3 = check("claim_of_completeness", overclaim(), "overclaim")

    # m4: PARITY granted.
    def grant_parity() -> dict:
        b = clone()
        b["parity"] = dict(b["parity"])
        b["parity"]["status"] = "VERIFIED"
        return b

    m4 = check("parity_granted", grant_parity(), "grants parity")

    # m5: a typed count.
    def typed_count() -> dict:
        b = clone()
        b["counts"]["courts_pass"] = int(b["counts"].get("courts_pass", 0)) + 1
        return b

    m5 = check("typed_count", typed_count(), "not the derived `counts`")

    # m6: a non-claim removed.
    def drop_non_claim() -> dict:
        b = clone()
        b["non_claims"] = b["non_claims"][:-1]
        return b

    m6 = check("non_claim_removed", drop_non_claim(), "non-claims")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# writing, reading and the entry points
# --------------------------------------------------------------------------------------------

def _inputs(evidence: dict) -> list:
    inputs = [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-frf-closure-tool", path=REPO_ROOT / ms_frf_closure.GENERATOR),
        InputRef(name="ms-seal-tool", path=REPO_ROOT / GENERATOR),
    ]
    seen = {i.path for i in inputs if i.path is not None}
    for unit, _court, _cl, _what in evidence["court_units"]:
        if unit == SELF_UNIT:
            continue
        p = (evidence.get("artefact_path") or {}).get(unit)
        if not p:
            continue
        path = REPO_ROOT / p
        if path.is_file() and path not in seen:
            seen.add(path)
            inputs.append(InputRef(name=unit, path=path))
    return inputs


def cmd_measure() -> int:
    evidence = collect_evidence()
    body = build_body(evidence)
    seal_md = render_seal(evidence, body)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-summary", authority=auth.id, inputs=_inputs(evidence),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)
    write_text(SEAL_DOC, seal_md)

    findings = seal_findings(body, evidence)
    control = seal_sensitivity_control(body, evidence)

    c = body["counts"]
    print(f"[ms-seal] {rel(OUT)} -- courts={c['courts']} pass={c['courts_pass']} "
          f"fail={c['courts_fail']} | sites={c['unsafe_sites']} "
          f"externally_reachable={c['externally_reachable']} "
          f"unsupported={c['externally_reachable_unsupported']}")
    print(f"  residuals total={c['residual_total']} disposed={c['residual_disposed']} "
          f"open={c['residual_open']} undisposed={c['residual_undisposed']} "
          f"crosscheck={c['residual_crosscheck']}")
    print(f"  unknown_cves={c['unknown_cves']} mechanisms_hidden={c['mechanisms_hidden']} "
          f"mechanisms_unresolved={c['mechanisms_unresolved']} "
          f"red_team_inconclusive={c['red_team_inconclusive']} geiger={c['geiger_status']}")
    print(f"  parity={body['parity']['status']} claim.complete={body['claim']['complete']} "
          f"passed={body['passed']} property_status={body['property_status']}")
    print(f"  -> wrote {rel(SEAL_DOC)}  body_hash={doc['body_hash'][:16]} "
          f"all_checks={not findings} control honest={control['honest']} "
          f"specificity={control['specificity_holds']}")
    for f in findings[:24]:
        print(f"    {f}")
    return 0 if (not findings and control["honest"]) else 1


def cmd_check() -> int:
    if not OUT.is_file():
        print(f"[ms-seal] {rel(OUT)} is absent; run --measure")
        return 1
    body = _body(_load(OUT))
    evidence = collect_evidence()
    findings = seal_findings(body, evidence)
    control = seal_sensitivity_control(body, evidence)
    c = body.get("counts") or {}
    for f in findings[:24]:
        print(f"  finding: {f}")
    print(f"[ms-seal] courts={c.get('courts')} pass={c.get('courts_pass')} "
          f"residuals_open={c.get('residual_open')} "
          f"unsupported={c.get('externally_reachable_unsupported')} "
          f"parity={(body.get('parity') or {}).get('status')} passed={body.get('passed')} "
          f"findings={len(findings)} control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def _synth_evidence() -> dict:
    """A small, self-consistent synthetic evidence set for the self-test.

    It mirrors the shapes the derivation reads (a census, an exposure plane, the tool planes, the
    mechanism/CVE/red-team planes and a court result per unit) without touching the multi-megabyte
    committed planes, so the derivation, findings and control run without the real artefact.
    """
    units = [(u, c) for u, c, _cl, _w in po.COURT_UNITS if u != SELF_UNIT]
    return {
        "planes": {
            "source-census": {
                "counts": {"sites": 3, "unsafe_contexts": 2, "files": 1},
                "crosschecks": {"geiger": {"tool": "cargo-geiger", "status": "unavailable",
                                           "note": "absent"}},
                "residuals": [],
            },
            "exposure-classification": {
                "counts": {"externally_reachable": 2, "sites_unknown_reachability": 1,
                           "census_sites": 3},
                "sites": {
                    "us-a": {"e": "CLI_INPUT_REACHABLE", "j": "j", "r": "S1"},
                    "us-b": {"e": "UNKNOWN_REACHABILITY", "j": "j", "r": "SU"},
                    "us-c": {"e": "NETWORK_SERVER_REACHABLE", "j": "j", "r": "S2"},
                },
                "residuals": [],
            },
            "miri": {
                "sites": {"us-a": {"state": "MIRI_UNSUPPORTED"},
                          "us-b": {"state": "MIRI_NOT_REACHABLE"},
                          "us-c": {"state": "MIRI_PASS"}},
                "residuals": [{"residual_id": "res-miri-x", "class": "out_of_scope",
                               "disposition": "preserved", "detail": "d", "evidence": ["x"]}],
            },
            "asan-msan": {
                "sites": {"us-a": {"state": "ASAN_UNSUPPORTED"},
                          "us-b": {"state": "ASAN_NOT_REACHABLE"},
                          "us-c": {"state": "ASAN_PASS"}},
                "residuals": [],
            },
            "tsan": {
                "sites": {},
                "residuals": [{"residual_id": "res-tsan-default-libctx-race", "class": "unknown",
                               "disposition": "open", "detail": "d", "evidence": ["x"]}],
            },
            "kani": {"sites": {}, "residuals": []},
            "mechanism-reconciliation": {
                "counts": {"by_disposition": {"HIDDEN": 1, "UNRESOLVED": 1, "ELIMINATED": 1}},
                "mechanisms": [{"mechanism_id": "m-hidden", "disposition": "HIDDEN"},
                               {"mechanism_id": "m-unresolved", "disposition": "UNRESOLVED"},
                               {"mechanism_id": "m-elim", "disposition": "ELIMINATED"}],
                "residuals": [],
            },
            "cve-replay": {
                "candidate_identity": "openssl-rs test",
                "counts": {"by_state": {"UNKNOWN": 1}},
                "replays": [{"cve_id": "CVE-2099-0001", "state": "UNKNOWN"}],
                "residuals": [],
            },
            "red-team": {
                "counts": {"inconclusive": 1, "found_gap": 1},
                "attacks": [{"attack_id": "rt-x", "outcome": "INCONCLUSIVE", "amount": 7,
                             "detail": "d"}],
                "residuals": [],
            },
            "phase22-crosswalk": {
                "counts": {"sites_unresolved": 3, "unresolved_by_class": {"evidence_missing": 1}},
                "residuals": [],
            },
        },
        "court_results": {c: {"court": c, "verdict": "pass", "findings": [],
                              "control": {"honest": True, "specificity_holds": True},
                              "counts": {}} for _u, c in units},
        "court_units": list(po.COURT_UNITS),
        "artefact_path": {u: f"artifacts/phase25/{u}.json" for u, _c in units},
        "artefact_sha": {u: "0" * 64 for u, _c in units},
        "candidate_identity": "openssl-rs test",
        "venue_image": "openssl-rs-court:1",
        "cargo_profile": "dev",
        "ledger": {"artefact": rel(LEDGER), "sha256": None,
                   "counts": {"owned": 22, "implemented": 22, "open_in_this_stratum": 0,
                              "contract_units": 22}},
        "existing": [],
    }


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation runs and the control is honest."""
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_seal.py", env={}, dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_seal.py is not admitted as a metadata-only generator on a host")

    evidence = _synth_evidence()
    body = build_body(evidence)
    baseline = seal_findings(body, evidence)
    if baseline:
        failures.append(f"the synthetic seal is not clean: {baseline[:4]}")
    control = seal_sensitivity_control(body, evidence)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")
    if body["passed"] is not False:
        failures.append("the synthetic seal did not record passed=false with an UNSUPPORTED site")

    # A rubber-stamp control must be able to fail.
    original = globals()["seal_findings"]
    globals()["seal_findings"] = lambda b, e: []
    try:
        broken = seal_sensitivity_control(body, evidence)
    finally:
        globals()["seal_findings"] = original
    if broken.get("honest") and broken.get("caught") == broken.get("seeded"):
        failures.append("the sensitivity control PASSED with a rubber-stamp findings function")

    if failures:
        print("[ms-seal] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    c = body["counts"]
    print(f"[ms-seal] self-test ok: the guard admits it as metadata-only; the synthetic seal is "
          f"clean (courts={c['courts']} pass={c['courts_pass']}, residuals_open={c['residual_open']}, "
          f"unsupported={c['externally_reachable_unsupported']}, passed={body['passed']}); and all "
          f"{control['seeded']} seeded mutations (a dropped court, a dropped residual, a claim of "
          f"completeness, a granted parity, a typed count and a removed non-claim) are caught with "
          f"specificity holding")
    return 0


def cmd_render() -> int:
    """Re-render the seal document from the **committed** summary body.

    `--measure` re-derives the courts over the live committed planes, which is a measurement at
    the live tree: for a seal whose candidate identity is frozen elsewhere, running it here would
    silently move the recorded verdicts. `--render` therefore separates transcription from
    measurement: it reads `artifacts/phase25/summary.json` as committed and renders the same
    document from it, so a documentation correction to the generator can be applied without
    re-measuring the stratum. The rendered text is still a pure function of committed evidence.
    """
    body = _body(_load(OUT))
    profile = str(body.get("profile") or "")
    venue = profile.split(" \u00b7 ", 1)[0] if profile else None
    evidence = {"venue_image": venue, "court_units": list(po.COURT_UNITS)}
    write_text(SEAL_DOC, render_seal(evidence, body))
    print(f"[ms-seal] re-rendered {rel(SEAL_DOC)} from the committed {rel(OUT)} "
          f"(no re-derivation, no measurement)")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/summary.json and the seal document")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed seal without regenerating")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the metadata-only admission and the control is honest")
    ap.add_argument("--render", action="store_true",
                    help="re-render the seal document from the committed summary, no measurement")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool executes nothing, so the manifest
    # lists it `metadata_only` and the guard admits it on any host.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check()
    if args.render:
        return cmd_render()
    # The default action is the derivation (and `--measure` names it): `evidence_determinism.py`
    # regenerates every generator with no flags and compares the bytes.
    return cmd_measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
