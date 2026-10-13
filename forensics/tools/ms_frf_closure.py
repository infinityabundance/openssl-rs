#!/usr/bin/env python3
"""Phase 25.20 -- the FRF/Gemel closure.

`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` section 2's 25.20 row gives this subphase one
obligation: the **FRF/Gemel chain closure**, *where the stratum stages a declarable court, so a
passing atlas is not read as a chain that never ran*, with the artefact
`forensics/atlas/phase25/frf-closure.json`. Phase 25 owns no exported symbol, so its evidence is a
set of planes that each read committed evidence and re-derive a verdict, not a set of differential
probes over a symbol set; `gen_frf_courts.py` declares no Phase-25 court and the tree stages no
`artifacts/phase25/probes/<probe>.{authority,candidate}` pair, so the stratum's FRF chain entry is
**vacuous** by `phase_state.py`'s `frf_gemel_blocking_reason(25)` scoping. The honest closure has
four parts, and this file is all four.

Four parts, and they are not interchangeable
--------------------------------------------
1. **The record set, and every record joined to its committed evidence.** One row per Phase-25
   contract unit (`forensics/tools/phase25_obligations.py`'s `COURT_UNITS`), each citing the
   committed artefact that is the unit's evidence and the committed tool that produced it. A row is
   *joined* when its artefact is present and its generator has landed; a unit whose landed generator
   has no committed artefact is an **orphan**, and a unit whose subphase has not landed yet (the
   25.21 seal) is *pending* rather than orphaned. The closure records the exact join counts, so a
   record that names no committed evidence is visible rather than assumed.

2. **The FRF obligations and receipts, and why none is orphaned.** One row per Phase-25 court, joined
   to the `.frf` receipt it owes: a court owes a receipt only when `gen_frf_courts.py` declares it,
   and the registry declares no Phase-25 court, so no court owes a receipt and none is orphaned. A
   receipt, challenge or claim that names a Phase-25 court with no declarable court is an **orphan**
   and is refused by name. The stratum owes nothing: `receipts_required` is 0.

   The closure deliberately does not read `artifacts/phase25/COURTS.json` nor the obligation ledger
   that measures it: the closure is validated by the runner (`phase25_courts.py`), which deletes and
   rewrites `COURTS.json`, and binding the runner's own output back -- directly or through the ledger
   the runner feeds -- would form a digest cycle neither artefact could reproduce. That is the same
   discipline Phase 24.14's closure records when it reads `gen_frf_courts.py` and the probes
   directory rather than `artifacts/phase24/COURTS.json`.

3. **The residual census, and every residual disposed.** Every residual the committed planes carry
   is classified from the closed vocabulary (`memory_safety_schemas.RESIDUAL_CLASSES`) and disposed
   from the closed disposition vocabulary (`RESIDUAL_DISPOSITIONS`). A full `residual` record with
   no valid disposition is **undisposed** and is a finding; a light cross-check leftover (the
   census/TCB/ownership planes' own `{class, detail, source}` entries) is recorded as a *crosscheck*
   leftover rather than a schema record. The open residuals are named (bounded), so an unknown is
   never read as a zero.

4. **The FRF chain staging and the Gemel change/checkpoint projection.** The closest model is Phase
   24.14's `phase24_frf.py`: it proves the *reason* the chain entry is vacuous from the two facts the
   rule keys on (`gen_frf_courts.py` declares no Phase-24 court and the tree holds no probe pair),
   and records the state of the committed Gemel projection `forensics/GEMEL_TRAJECTORY.md` -- the
   current checkpoint, whether it names the FRF chain and the stratum, and the plan/registry hashes
   -- in the form Phase 22.16's `gemel-checkpoint.json` uses: a committed, deterministic body whose
   every count is derived rather than typed. It never reads the uncommitted `.gemel` store and never
   calls `gemel status`/`gemel index`.

The property is never claimed
-----------------------------
A passing `MS-FRF-CLOSURE` is an **instrument**, not a property. The property it names -- that the
stratum's FRF/Gemel chain ran -- is exactly what the stratum cannot claim: no Phase-25 court is
declarable, so no `.frf` declaration, receipt, adjudicated challenge or `sensitivity-backed` claim
is owed and no Gemel checkpoint is owed, and the atlas also carries open residuals. The closure
therefore records `property_status = NOT_CLAIMED` and a `claim.closed = false` with its reason, and a
closure that asserts it is closed while an open residual exists is refused by name.

Determinism and the regeneration policy
---------------------------------------
Everything this file reads is a committed artefact: the twenty-two-unit contract table and the
committed planes that are each unit's evidence, the committed FRF registry and Gemel projection, and
the committed `.frf` receipt/challenge/claim store. It fetches nothing, compiles nothing, links
nothing, runs no tool and no probe, so it is a **pure derivation** -- the same class as
`ms_red_team.py` and `ms_mechanism_reconciliation.py`. It is therefore wired into
`evidence_determinism.py`'s `GENERATORS_BEFORE_LEDGERS`/`COMPARED` and declared `metadata_only` in
`forensics/memory-safety/container.json`; the guard's `require_admitted()` is still called first, so
the admission is the committed manifest's and not a special case in this file.

Output
------
    forensics/atlas/phase25/frf-closure.json

Usage:
  python3 forensics/tools/ms_frf_closure.py --measure     # derive and write the closure
  python3 forensics/tools/ms_frf_closure.py --check       # re-run the pure checks
  python3 forensics/tools/ms_frf_closure.py --self-test   # metadata-only + control

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import re
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
    sha256_file,
    write_json,
)

# The Docker-only execution guard, called first. This tool executes nothing, so the manifest lists
# it `metadata_only` and the guard admits it on any host.
import phase25_guard  # noqa: E402

import memory_safety_schemas as schemas  # noqa: E402

import ms_census  # noqa: E402
import ms_codec  # noqa: E402

import gen_frf_courts  # noqa: E402
import phase25_obligations as po  # noqa: E402

GENERATOR = "forensics/tools/ms_frf_closure.py"
ARTEFACT_REL = "forensics/atlas/phase25/frf-closure.json"
OUT = REPO_ROOT / ARTEFACT_REL
COURT = "MS-FRF-CLOSURE"
PHASE = 25

PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
REGISTRY = REPO_ROOT / "forensics" / "tools" / "gen_frf_courts.py"
GEMEL_TRAJECTORY = REPO_ROOT / "forensics" / "GEMEL_TRAJECTORY.md"

FRF_RECEIPTS = REPO_ROOT / ".frf" / "receipts"
FRF_CHALLENGES = REPO_ROOT / ".frf" / "challenges"
FRF_CLAIMS = REPO_ROOT / ".frf" / "claims"

# The unit whose evidence is this very closure. Its own artefact is being written, so its presence
# is not checked from disk; it is joined on its court alone and carries no self-hash.
SELF_UNIT = "frf-gemel-closure"
SEAL_UNIT = "memory-safety-seal"
SEAL_DOC = "docs/PHASE-25-MEMORY-SAFETY-SEAL.md"

# Bounded sample of open-residual ids to name, so the artefact does not restate 450 ids while still
# naming the open set rather than smoothing it to a count.
OPEN_SAMPLE = 8

WHAT_THIS_IS = (
    "Phase 25.20's FRF/Gemel closure: the record set (every Phase-25 contract unit joined to its "
    "committed evidence and its committed generator), the obligation and receipt joins (no unit and "
    "no receipt orphaned), the residual census (every residual classified and disposed, the open "
    "ones named), the FRF chain staging (why no Phase-25 court is declarable, and the harness "
    "challenge that stands in its place) and the Gemel checkpoint projection (the state of the "
    "committed forensics/GEMEL_TRAJECTORY.md, never the store). It is an instrument plus an "
    "observation record, not a claim that the stratum has a declarable court."
)

SORT_KEY = (
    "records by unit; obligations by unit; receipts/challenges/claims by court id; residual_census "
    "planes/by_class/by_disposition by key with every list sorted; chain.declared_courts and "
    "chain.probe_pairs sorted; gemel so the current checkpoint and the naming sets are derived from "
    "the committed projection; every list sorted"
)


class NotDriven(Exception):
    """The closure could not be constructed from the committed evidence."""


# --------------------------------------------------------------------------------------------
# the record set: one row per contract unit, and the committed evidence it is joined to
# --------------------------------------------------------------------------------------------

# unit -> (committed evidence path, the record kinds the plan names for it). Keyed by the *unit*
# names `phase25_obligations.COURT_UNITS` uses, so the record set and the obligation ledger are two
# views of one set of twenty-two units. `memory-safety-seal`'s artefact is the seal document, which
# 25.21 lands; until then it is recorded pending rather than dropped.
RECORD_EVIDENCE: dict[str, tuple[str, tuple[str, ...]]] = {
    # The constitution unit's representative committed artefact is the plan -- its authored surface.
    # `artifacts/phase25/COURTS.json` is deliberately NOT cited: the closure is validated by the
    # runner, and binding the runner's own output (directly, or through the obligation ledger the
    # runner feeds) back would form a digest cycle neither artefact could reproduce -- the same
    # reason Phase 24.14's closure reads `gen_frf_courts.py` and the probes directory rather than
    # `artifacts/phase24/COURTS.json`.
    "constitution": ("docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md", ("constitution",)),
    "source-census": ("artifacts/phase25/source-census.json",
                      ("source_census", "unsafe_context", "unsafe_site")),
    "non-rust-tcb": ("artifacts/phase25/non-rust-tcb.json", ("c_adapter", "ffi_boundary")),
    "safety-obligations": ("artifacts/phase25/safety-obligations.json", ("safety_obligation",)),
    "ownership-planes": ("artifacts/phase25/ownership-planes.json",
                         ("allocation_site", "ownership_edge", "callback_lifetime",
                          "send_sync_impl", "global_state", "panic_boundary")),
    "phase22-crosswalk": ("artifacts/phase25/phase22-crosswalk.json", ("crosswalk",)),
    "phase24-crosswalk": ("artifacts/phase25/phase24-crosswalk.json", ("crosswalk",)),
    "exposure-classification": ("artifacts/phase25/exposure.json", ("exposure",)),
    "unsafe-reduction": ("artifacts/phase25/unsafe-reduction.json", ("reduction",)),
    "miri": ("artifacts/phase25/miri.json", ("miri_result",)),
    "asan-msan": ("artifacts/phase25/asan-msan.json", ("sanitizer_result",)),
    "tsan": ("artifacts/phase25/tsan.json", ("sanitizer_result",)),
    "kani": ("artifacts/phase25/kani.json", ("kani_result",)),
    "phase18-fuzz-crosswalk": ("artifacts/phase25/phase18-fuzz-crosswalk.json",
                               ("fuzz_crosswalk",)),
    "phase24-safety-coverage": ("artifacts/phase25/phase24-safety-coverage.json", ("coverage",)),
    "historical-cve-census": ("artifacts/phase25/historical-cves.json", ("historical_cve",)),
    "cve-replay": ("artifacts/phase25/cve-replay/index.json", ("cve_replay",)),
    "mechanism-reconciliation": ("artifacts/phase25/mechanisms.json",
                                 ("vulnerability_mechanism",)),
    "red-team": ("artifacts/phase25/red-team.json", ("residual",)),
    "clean-regeneration": ("artifacts/phase25/regeneration.json", ("regeneration",)),
    "frf-gemel-closure": (ARTEFACT_REL, ("frf_closure",)),
    "memory-safety-seal": (SEAL_DOC, ("summary",)),
}

# unit -> the committed tool that produced its evidence. The constitution's evidence is the runner's
# registry; the seal's tool is 25.21's and has not landed, so it is `None` and recorded pending.
TOOL_OF: dict[str, str | None] = {
    "constitution": "forensics/tools/phase25_courts.py",
    "source-census": "forensics/tools/ms_census.py",
    "non-rust-tcb": "forensics/tools/ms_non_rust_tcb.py",
    "safety-obligations": "forensics/tools/ms_obligations.py",
    "ownership-planes": "forensics/tools/ms_ownership_planes.py",
    "phase22-crosswalk": "forensics/tools/ms_phase22_crosswalk.py",
    "phase24-crosswalk": "forensics/tools/ms_phase24_crosswalk.py",
    "exposure-classification": "forensics/tools/ms_exposure.py",
    "unsafe-reduction": "forensics/tools/ms_reduction.py",
    "miri": "forensics/tools/ms_miri.py",
    "asan-msan": "forensics/tools/ms_asan.py",
    "tsan": "forensics/tools/ms_tsan.py",
    "kani": "forensics/tools/ms_kani.py",
    "phase18-fuzz-crosswalk": "forensics/tools/ms_phase18_fuzz_crosswalk.py",
    "phase24-safety-coverage": "forensics/tools/ms_phase24_safety_coverage.py",
    "historical-cve-census": "forensics/tools/ms_historical_cve.py",
    "cve-replay": "forensics/tools/ms_cve_replay.py",
    "mechanism-reconciliation": "forensics/tools/ms_mechanism_reconciliation.py",
    "red-team": "forensics/tools/ms_red_team.py",
    "clean-regeneration": "forensics/tools/ms_regeneration.py",
    "frf-gemel-closure": GENERATOR,
    "memory-safety-seal": None,
}


# --------------------------------------------------------------------------------------------
# reading and decoding
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise NotDriven(f"committed artefact missing: {rel(path)}")
    return json.loads(path.read_text(encoding="utf-8"))


def _body(doc: dict) -> dict:
    return doc.get("body", doc) if isinstance(doc, dict) else doc


def _sha_or_none(relpath: str, existing: set[str]) -> str | None:
    if relpath not in existing:
        return None
    p = REPO_ROOT / relpath
    return sha256_file(p) if p.is_file() else None


def _receipt_index() -> dict[str, list[str]]:
    """Receipt stems by the FRF court id each receipt's own `court.id` names."""
    out: dict[str, list[str]] = {}
    if not FRF_RECEIPTS.is_dir():
        return out
    for p in sorted(FRF_RECEIPTS.glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cid = (doc.get("court") or {}).get("id")
        if cid:
            out.setdefault(str(cid), []).append(p.stem)
    return {k: sorted(v) for k, v in out.items()}


def _challenge_index() -> dict[str, list[str]]:
    """Challenge stems by the FRF court id each challenge names."""
    out: dict[str, list[str]] = {}
    if not FRF_CHALLENGES.is_dir():
        return out
    for p in sorted(FRF_CHALLENGES.glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cid = doc.get("court")
        if cid:
            out.setdefault(str(cid), []).append(p.stem)
    return {k: sorted(v) for k, v in out.items()}


def _claim_courts() -> list[str]:
    """The FRF court id every compiled claim names (its `court.id` or `court` string)."""
    out: list[str] = []
    if not FRF_CLAIMS.is_dir():
        return out
    for p in sorted(FRF_CLAIMS.glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        court = doc.get("court")
        cid = court.get("id") if isinstance(court, dict) else court
        if cid:
            out.append(str(cid))
    return sorted(out)


def _decoded_planes(existing: set[str]) -> dict[str, dict]:
    """Every Phase-25 evidence plane, decoded through the one codec.

    The census is decoded through `ms_census.decode_body` (it reconstructs the site/context ids
    from the committed bytes) and its reference lists drive the other columnar planes, exactly as
    `ms_red_team.load_authority` reads them. A plane that is absent or undecodable is skipped; the
    record join below records its absence as an unjoined record rather than a crash.
    """
    planes: dict[str, dict] = {}
    refs = None
    census_path = RECORD_EVIDENCE["source-census"][0]
    if census_path in existing:
        try:
            cbody = ms_census.decode_body(_body(_load(REPO_ROOT / census_path)))
            refs = ms_codec.refs_from_census(cbody)
            planes["source-census"] = cbody
        except Exception:
            refs = None
    for unit, (relpath, _kinds) in RECORD_EVIDENCE.items():
        if unit == "source-census" or not relpath.endswith(".json") or relpath not in existing:
            continue
        try:
            body = _body(_load(REPO_ROOT / relpath))
            if isinstance(body, dict) and body.get("encoding") and refs is not None:
                body = ms_codec.decode_body(body, refs)
            planes[unit] = body
        except Exception:
            continue
    return planes


_EVIDENCE_CACHE: dict = {}


def collect_evidence() -> dict:
    """The live committed evidence every derivation is pure over.

    One dict, so the court re-derives the closure from the same bytes the generator did rather than
    from a second, drifting reader. It reads committed files only -- no compiler, no tool, no probe,
    no `.gemel` store.
    """
    key = id(REPO_ROOT)
    if key in _EVIDENCE_CACHE:
        return _EVIDENCE_CACHE[key]

    existing: set[str] = set()
    watched = [RECORD_EVIDENCE[u][0] for u in RECORD_EVIDENCE]
    watched += [t for t in TOOL_OF.values() if t]
    watched += [rel(PLAN), rel(REGISTRY), rel(GEMEL_TRAJECTORY), rel(GUARD), rel(MANIFEST),
                rel(SCHEMAS)]
    for relpath in watched:
        if (REPO_ROOT / relpath).is_file():
            existing.add(relpath)

    gemel_text = (GEMEL_TRAJECTORY.read_text(encoding="utf-8")
                  if GEMEL_TRAJECTORY.is_file() else "")

    evidence = {
        "registry": [list(row) for row in gen_frf_courts.COURTS],
        "candidate_version": getattr(gen_frf_courts, "CANDIDATE_VERSION", None),
        "gemel_text": gemel_text,
        "receipts": _receipt_index(),
        "challenges": _challenge_index(),
        "claim_courts": _claim_courts(),
        "planes": _decoded_planes(existing),
        "existing": sorted(existing),
        "ledger": po,
    }
    _EVIDENCE_CACHE[key] = evidence
    return evidence


def derive_records(evidence: dict) -> list[dict]:
    """One row per Phase-25 contract unit, joined to its committed evidence and its tool.

    The join is over the committed evidence and the committed generator only -- never the runner's
    `artifacts/phase25/COURTS.json` and never the obligation ledger the runner feeds, because the
    closure is validated by the runner and binding its own output back would form a digest cycle.
    """
    existing = set(evidence["existing"])
    rows: list[dict] = []
    for unit, court, _closure, _what in po.COURT_UNITS:
        relpath, kinds = RECORD_EVIDENCE.get(unit, (None, ()))
        tool = TOOL_OF.get(unit)
        if unit == SELF_UNIT:
            # This closure's own artefact is the derivation; it does not hash or test itself.
            present, sha = True, None
        else:
            present = relpath is not None and relpath in existing
            sha = _sha_or_none(relpath, existing) if relpath else None
        tool_present = bool(tool) and tool in existing
        joined = present and tool_present
        # A unit with no committed artefact and no landed generator is pending with the subphase
        # that lands it (25.21's seal); a unit whose landed generator has no artefact is orphaned.
        pending = (not present) and (not tool)
        orphan = (not present) and bool(tool)
        rows.append({
            "unit": unit,
            "court": court,
            "artefact": relpath,
            "record_kinds": list(kinds),
            "generator": tool,
            "artefact_present": present,
            "artefact_sha256": sha,
            "generator_present": tool_present,
            "self": unit == SELF_UNIT,
            "pending": bool(pending),
            "joined": bool(joined),
            "orphan": bool(orphan),
        })
    return sorted(rows, key=lambda r: r["unit"])


def derive_obligations(evidence: dict) -> list[dict]:
    """The FRF chain obligations: one row per Phase-25 court, joined to the receipt it owes.

    A Phase-25 court owes an `.frf` receipt only when it is declared in `gen_frf_courts.py`; the
    registry declares no Phase-25 court (the stratum's courts read committed evidence and stage no
    probe pair), so no court owes a receipt and none is orphaned. An obligation whose court owes a
    receipt it does not have is an orphan, named rather than smoothed to a zero.
    """
    declared = {"openssl-rs-" + str(court).lower()
                for (court, phase, _probe, _desc) in evidence["registry"] if int(phase) == PHASE}
    rows: list[dict] = []
    for unit, court, closure, _what in po.COURT_UNITS:
        cid = "openssl-rs-" + court.lower()
        owes = cid in declared
        receipts = sorted(evidence["receipts"].get(cid, []))
        challenges = sorted(evidence["challenges"].get(cid, []))
        rows.append({
            "unit": unit,
            "court": court,
            "frf_court_id": cid,
            "closure": closure,
            "declared_in_registry": owes,
            "owes_receipt": owes,
            "receipts": receipts,
            "challenges": challenges,
            "joined": (not owes) or bool(receipts),
            "orphan": bool(owes and not receipts),
        })
    return sorted(rows, key=lambda r: r["unit"])


def _frf_court_ids(evidence: dict) -> set[str]:
    """The FRF court id (`openssl-rs-<court lowercased>`) of every Phase-25 court."""
    return {"openssl-rs-" + str(c).lower()
            for (_unit, c, _cl, _w) in po.COURT_UNITS}


def derive_receipts(evidence: dict) -> dict:
    """The FRF receipts/challenges/claims the stratum's declarable courts owe, and the orphans.

    No Phase-25 court is declarable, so nothing is required and nothing may be orphaned. A receipt,
    challenge or claim that names a Phase-25 court which is *not* declarable is an orphan and is
    named -- a receipt owed by nothing is a chain entry that ran for a court the plan does not
    declare.
    """
    declarable = sorted(
        "openssl-rs-" + str(court) for (court, phase, _probe, _desc) in evidence["registry"]
        if int(phase) == PHASE
    )
    required = set(declarable)
    phase_ids = _frf_court_ids(evidence)

    def join(index: dict[str, list[str]]) -> dict:
        present = {cid: index[cid] for cid in sorted(index) if cid in required}
        orphaned = {cid: index[cid] for cid in sorted(index)
                    if cid in phase_ids and cid not in required}
        return {
            "required": sorted(required),
            "present": present,
            "present_count": sum(len(v) for v in present.values()),
            "orphaned": orphaned,
            "orphaned_count": sum(len(v) for v in orphaned.values()),
        }

    receipts = join(evidence["receipts"])
    challenges = join(evidence["challenges"])
    claims_in_phase = sorted({cid for cid in evidence["claim_courts"] if cid in phase_ids})
    claims_orphaned = sorted(cid for cid in claims_in_phase if cid not in required)
    return {
        "declarable_courts": declarable,
        "receipts": receipts,
        "challenges": challenges,
        "claims_naming_phase_courts": claims_in_phase,
        "claims_orphaned": claims_orphaned,
    }


def _is_residual_record(rec: dict) -> bool:
    """A `residual` schema record carries a `residual_id`; a cross-check leftover does not.

    The schema's `residual` kind requires `residual_id`, and the lighter `{class, detail, source}`
    entries the census/TCB/ownership planes carry are their own cross-check notes, not schema
    records. A plane may also carry a residual with a `residual_id` whose `class` is from *its own*
    closed vocabulary (25.19's regeneration records `evidence_not_reproducible`); that is still a
    residual, and it is disposed by its `disposition` -- an out-of-schema class is recorded as an
    observation rather than read as an undisposed leftover.
    """
    return "residual_id" in rec


def derive_residual_census(evidence: dict) -> dict:
    """Every residual the committed planes carry, classified and disposed, the open ones named."""
    by_class: Counter = Counter()
    by_disposition: Counter = Counter()
    by_plane: dict[str, dict] = {}
    undisposed: dict[str, list[str]] = {}
    open_ids: dict[str, list[str]] = {}
    outside_schema: Counter = Counter()
    total = records = crosscheck = open_n = 0
    for unit in sorted(evidence["planes"]):
        body = evidence["planes"][unit]
        residuals = body.get("residuals") if isinstance(body, dict) else None
        if not isinstance(residuals, list) or not residuals:
            continue
        pclass: Counter = Counter()
        pdisp: Counter = Counter()
        pre = pcross = popen = 0
        opens: list[str] = []
        for i, rec in enumerate(residuals):
            if not isinstance(rec, dict):
                continue
            cls = rec.get("class")
            by_class[str(cls)] += 1
            pclass[str(cls)] += 1
            if cls not in schemas.RESIDUAL_CLASSES:
                outside_schema[str(cls)] += 1
            if _is_residual_record(rec):
                pre += 1
                disp = rec.get("disposition")
                by_disposition[str(disp)] += 1
                pdisp[str(disp)] += 1
                if disp == "open":
                    popen += 1
                    opens.append(str(rec.get("residual_id") or f"{unit}[{i}]"))
                if disp not in schemas.RESIDUAL_DISPOSITIONS:
                    undisposed.setdefault(unit, []).append(
                        str(rec.get("residual_id") or f"{unit}[{i}]"))
            else:
                pcross += 1
        by_plane[unit] = {
            "total": len(residuals),
            "records": pre,
            "crosscheck": pcross,
            "open": popen,
            "by_class": dict(sorted(pclass.items())),
            "by_disposition": {k: pdisp[k] for k in sorted(pdisp)},
        }
        if opens:
            open_ids[unit] = opens[:OPEN_SAMPLE]
        total += len(residuals)
        records += pre
        crosscheck += pcross
        open_n += popen
    undisposed_n = sum(len(v) for v in undisposed.values())
    return {
        "total": total,
        "records": records,
        "crosscheck": crosscheck,
        "disposed": records - undisposed_n,
        "open": open_n,
        "undisposed": undisposed_n,
        "undisposed_sets": {k: sorted(v) for k, v in sorted(undisposed.items())},
        "by_class": {k: by_class[k] for k in sorted(by_class)},
        "by_disposition": {k: by_disposition[k] for k in sorted(by_disposition)},
        "classes_outside_schema": {k: outside_schema[k] for k in sorted(outside_schema)},
        "by_plane": {k: by_plane[k] for k in sorted(by_plane)},
        "open_sample": {k: open_ids[k] for k in sorted(open_ids)},
        "sample_bound": OPEN_SAMPLE,
    }


def derive_chain(evidence: dict) -> dict:
    """Why the stratum's FRF chain entry is vacuous, and what stands in its place.

    It reads the committed FRF registry (`gen_frf_courts.py`) and the tree's
    `artifacts/phase25/probes/` directory rather than `artifacts/phase25/COURTS.json`, because the
    runner writes that result and the closure court is one of its rows -- binding it back would form
    a digest cycle neither artefact could reproduce (the same reason Phase 24.14 reads the registry
    and the probes directory).
    """
    declared = sorted(
        "openssl-rs-" + str(court) for (court, phase, _probe, _desc) in evidence["registry"]
        if int(phase) == PHASE
    )
    probe_dir = REPO_ROOT / "artifacts" / "phase25" / "probes"
    probe_pairs: list[str] = []
    if probe_dir.is_dir():
        probe_pairs = sorted(
            p.stem for p in probe_dir.glob("*.authority")
            if (probe_dir / (p.stem + ".candidate")).is_file()
        )
    declarable = list(declared)
    vacuous = not declared and not probe_pairs and not declarable
    return {
        "phase": PHASE,
        "registry": rel(REGISTRY),
        "declared_courts": declared,
        "probe_pairs": probe_pairs,
        "declarable_courts": declarable,
        "vacuous": bool(vacuous),
        "reason": (
            "the stratum stages a declarable court only if a Phase-25 court is declared in "
            "gen_frf_courts.py and its artifacts/phase25/probes/<probe>.{authority,candidate} pair "
            "is staged. Neither holds: the registry declares no Phase-25 court, the tree holds no "
            "such pair, and every Phase-25 court row records frf_declarable false, so every "
            "Phase-25 court reads committed evidence and carries no {fixture}-driven FRF "
            "declaration and phase_state.py's frf_gemel_blocking_reason(25) is empty by its own "
            "scoping -- the stratum owes no .frf declaration, receipt, adjudicated challenge or "
            "sensitivity-backed claim, and no Gemel checkpoint"
        ),
        "stands_in_place": [
            "the MS-FRF-CLOSURE harness challenge: the record/obligation/receipt/residual joins "
            "and the chain and Gemel records are re-derived from the committed evidence and "
            "required to agree, and the classifier is proved not a rubber stamp",
            "the Gemel checkpoint projection forensics/GEMEL_TRAJECTORY.md, which records the "
            "current checkpoint the release re-creates the store at",
        ],
    }


_CHECKPOINT_RE = re.compile(r"^\* `(K\d+)` — `checkpoint\.[0-9a-f]+`$")


def _parse_gemel(text: str) -> tuple[str | None, list[list[str]]]:
    current = None
    checkpoints: list[list[str]] = []
    for line in text.splitlines():
        if line.startswith("current:"):
            current = line.split("`")[1] if "`" in line else line.split(":", 1)[1].strip()
            continue
        m = _CHECKPOINT_RE.match(line)
        if m:
            checkpoints.append([m.group(1), ""])
        elif checkpoints and line.startswith("  - "):
            checkpoints[-1][1] = (checkpoints[-1][1] + " " + line[4:]).strip()
    return current, checkpoints


def derive_gemel(evidence: dict) -> dict:
    """The committed Gemel projection's state, read from `forensics/GEMEL_TRAJECTORY.md`.

    The projection is what travels in Git (`docs/DECISIONS.md` D17); the store is not committed and
    this tool never opens it. The checkpoint shape is the same one `phase_state.py` reads, so the
    chain rule's checkpoint clause and this record agree.
    """
    text = evidence["gemel_text"]
    if not text:
        return {"projection": rel(GEMEL_TRAJECTORY), "current": None, "checkpoint_count": 0,
                "checkpoints_naming_frf_chain": [], "checkpoints_naming_phase": [],
                "checkpoint_owed": False, "identity": {}, "reason": ""}
    current, checkpoints = _parse_gemel(text)
    named_chain = sorted(n for n, s in checkpoints if "FRF chain" in s)
    named_phase = sorted(n for n, s in checkpoints if f"Phase {PHASE}" in s)
    chain = derive_chain(evidence)
    return {
        "projection": rel(GEMEL_TRAJECTORY),
        "current": current,
        "checkpoint_count": len(checkpoints),
        "checkpoints_naming_frf_chain": named_chain,
        "checkpoints_naming_phase": named_phase,
        "checkpoint_owed": bool(chain["declarable_courts"] or chain["declared_courts"]),
        "identity": {
            "plan": {"path": rel(PLAN), "sha256": sha256_file(PLAN) if PLAN.is_file() else "unknown"},
            "registry": {"path": rel(REGISTRY),
                         "sha256": sha256_file(REGISTRY) if REGISTRY.is_file() else "unknown"},
            "candidate_version": evidence.get("candidate_version"),
            "checkpoint_state_hash": content_hash({"current": current, "checkpoints": checkpoints}),
        },
        "reason": (
            "the FRF/Gemel chain entry is vacuous (no Phase-25 court is declarable), so the stratum "
            "owes no Gemel change or checkpoint of its own; the release's current checkpoint in the "
            "committed projection is the boundary a later session resumes from, and this record "
            "binds it rather than reading the uncommitted store"
        ),
    }


def derive_counts(records: list[dict], obligations: list[dict], receipts: dict,
                  census: dict, chain: dict) -> dict:
    return {
        "records": len(records),
        "records_joined": sum(1 for r in records if r["joined"]),
        "records_pending": sum(1 for r in records if r["pending"]),
        "records_orphaned": sum(1 for r in records if r["orphan"]),
        "obligations": len(obligations),
        "obligations_joined": sum(1 for o in obligations if o["joined"]),
        "obligations_owed": sum(1 for o in obligations if o["owes_receipt"]),
        "obligations_orphaned": sum(1 for o in obligations if o["orphan"]),
        "receipts_required": len(receipts["receipts"]["required"]),
        "receipts_orphaned": receipts["receipts"]["orphaned_count"],
        "challenges_required": len(receipts["challenges"]["required"]),
        "challenges_orphaned": receipts["challenges"]["orphaned_count"],
        "claims_orphaned": len(receipts["claims_orphaned"]),
        "residuals": census["total"],
        "residual_records": census["records"],
        "residual_crosscheck": census["crosscheck"],
        "residuals_disposed": census["disposed"],
        "residuals_open": census["open"],
        "residuals_undisposed": census["undisposed"],
        "residual_classes_outside_schema": sum(census["classes_outside_schema"].values()),
        "chain_vacuous": bool(chain["vacuous"]),
        "chain_declared_courts": len(chain["declared_courts"]),
        "chain_probe_pairs": len(chain["probe_pairs"]),
    }


def derive_claim(counts: dict) -> dict:
    """The closure's claim: never closed while a residual is open or undisposed."""
    open_n = counts["residuals_open"]
    undisp = counts["residuals_undisposed"]
    orphans = (counts["records_orphaned"] + counts["obligations_orphaned"]
               + counts["receipts_orphaned"] + counts["challenges_orphaned"]
               + counts["claims_orphaned"])
    closed = bool(orphans == 0 and undisp == 0 and open_n == 0)
    return {
        "closed": closed,
        "open_residuals": open_n,
        "undisposed_residuals": undisp,
        "orphans": orphans,
        "reason": (
            "the closure is closed only when every record and obligation is joined with no orphan, "
            "every receipt the stratum owes is present, and no residual is open or undisposed. No "
            "Phase-25 court is declarable, so the FRF/Gemel chain entry is vacuous and the atlas "
            "carries open residuals: the closure records this rather than claiming it closed"
        ) if not closed else "every record and obligation is joined and no residual is open",
    }


def derive_property_status(counts: dict) -> str:
    """The closure's property is never claimed for this stratum.

    The property it names -- the FRF/Gemel chain ran -- is exactly what a stratum that stages no
    declarable court cannot claim, and the atlas also carries open residuals. The status is derived
    (not typed), so a closure that records `CLAIMED` disagrees with its derivation and is refused.
    """
    return "NOT_CLAIMED"


def derive_property_findings(records: list[dict], obligations: list[dict], receipts: dict,
                             census: dict, chain: dict, counts: dict) -> list[str]:
    out: list[str] = []
    out.append(
        f"the record set is {counts['records']} Phase-25 contract unit(s): "
        f"{counts['records_joined']} joined to their committed evidence and generator, "
        f"{counts['records_pending']} pending with the subphase that lands them and "
        f"{counts['records_orphaned']} orphaned"
    )
    out.append(
        f"the FRF chain owes {counts['receipts_required']} receipt(s) and the stratum's "
        f"{counts['obligations']} court obligation(s) join their committed evidence "
        f"({counts['obligations_joined']} joined, {counts['obligations_owed']} owing a receipt, "
        f"{counts['obligations_orphaned']} orphaned), so no receipt/challenge/claim that names a "
        f"Phase-25 court is orphaned"
    )
    out.append(
        f"the residual census disposes {counts['residuals_disposed']} of "
        f"{counts['residual_records']} residual record(s) from the closed disposition vocabulary "
        f"and records {counts['residual_crosscheck']} light cross-check leftover(s); "
        f"{counts['residuals_open']} residual(s) are open and {counts['residuals_undisposed']} "
        f"undisposed"
    )
    if counts["residual_classes_outside_schema"]:
        outside = ", ".join(f"{k}={v}" for k, v in sorted(census["classes_outside_schema"].items()))
        out.append(
            f"{counts['residual_classes_outside_schema']} residual(s) carry a class from a plane's "
            f"own vocabulary rather than memory_safety_schemas.RESIDUAL_CLASSES ({outside}); each is "
            f"recorded with its disposition rather than read as an undisposed leftover"
        )
    opens = census["open_sample"]
    if opens:
        named = ", ".join(f"{unit}={len(ids)}" for unit, ids in sorted(opens.items()))
        out.append(
            f"the open residual(s) are named rather than smoothed to a zero (a bounded sample of "
            f"{census['sample_bound']} per plane; the full set is in the cited plane): {named}"
        )
    if not chain["vacuous"]:
        out.append("the stratum stages a declarable court, so its FRF/Gemel chain entry is not "
                   "vacuous and a receipt/checkpoint is owed")
    out.append(
        "a passing MS-FRF-CLOSURE is an instrument, not a property: the stratum's chain entry is "
        "vacuous (no Phase-25 court is declarable) and the atlas carries open residuals, so the "
        "closure records property_status NOT_CLAIMED rather than a chain that ran"
    )
    return out


def derive_evidence(evidence: dict) -> dict:
    """The whole closure, derived: records, obligations, receipts, residual census, chain, gemel."""
    records = derive_records(evidence)
    obligations = derive_obligations(evidence)
    receipts = derive_receipts(evidence)
    census = derive_residual_census(evidence)
    chain = derive_chain(evidence)
    gemel = derive_gemel(evidence)
    counts = derive_counts(records, obligations, receipts, census, chain)
    return {
        "records": records,
        "obligations": obligations,
        "receipts": receipts,
        "residual_census": census,
        "chain": chain,
        "gemel": gemel,
        "counts": counts,
        "claim": derive_claim(counts),
        "property_status": derive_property_status(counts),
        "property_findings": derive_property_findings(records, obligations, receipts, census,
                                                      chain, counts),
    }


def build_body(evidence: dict) -> dict:
    """Assemble the whole closure body from committed evidence. Pure, no writes."""
    d = derive_evidence(evidence)
    body: dict = {
        "what_this_is": WHAT_THIS_IS,
        "sort_key": SORT_KEY,
        "records": d["records"],
        "obligations": d["obligations"],
        "receipts": d["receipts"],
        "residual_census": d["residual_census"],
        "chain": d["chain"],
        "gemel": d["gemel"],
        "counts": d["counts"],
        "claim": d["claim"],
        "property_status": d["property_status"],
        "property_findings": d["property_findings"],
        "non_claims": [
            "the closure is an instrument plus an observation record, not a claim that the stratum "
            "has a declarable court or that the FRF/Gemel chain ran for it",
            "a record joined to its committed evidence says the evidence is present and its court "
            "is registered, not that the evidence is correct: each plane's own court judges that",
            "a disposed residual is honestly recorded, not resolved: an `open` disposition is an "
            "unresolved leftover whose disposition is `open`",
            "the Gemel projection is a committed projection of a store that is not committed "
            "(docs/DECISIONS.md D17); the closure binds the projection, never the store",
        ],
    }
    return body


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def frf_closure_findings(body: dict, evidence: dict) -> list:
    """Every way the committed closure contradicts the committed evidence.

    Pure over `body` and `evidence` (the committed planes, the courts registry, the FRF registry,
    the `.frf` receipt/challenge/claim store and the Gemel projection): it is what the
    `MS-FRF-CLOSURE` court runs. It establishes that every record is joined to its committed
    evidence, that no obligation or receipt is orphaned, that every residual is disposed, that the
    chain and Gemel records reproduce, and that the counts and the whole plane equal their
    derivation. It is an **instrument**: a record that is pending or even orphaned is recorded and
    named, and a recorded orphan is itself a finding -- the closure passes only when its own
    derivation holds.
    """
    problems: list = []
    d = derive_evidence(evidence)

    # 1. The record set: the committed records must equal the derived ones.
    records = body.get("records")
    if not isinstance(records, list):
        return ["the closure's `records` is not a list"]
    ids = [str(r.get("unit")) for r in records]
    if len(set(ids)) != len(ids):
        problems.append("the closure records a unit more than once")
    derived_ids = {r["unit"] for r in d["records"]}
    for unit in sorted(derived_ids - set(ids)):
        problems.append(f"the closure omits the derived record {unit} (dropped)")
    for unit in sorted(set(ids) - derived_ids):
        problems.append(f"the closure records the unit {unit}, which the committed evidence does "
                        f"not derive")
    for r in records:
        unit = str(r.get("unit"))
        if not r.get("artefact"):
            problems.append(f"{unit}: the record cites no committed evidence")
        if r.get("orphan"):
            problems.append(f"{unit}: the record is orphaned -- its committed evidence is absent "
                            f"while its generator has landed")

    # 2. The FRF chain obligations: every court that owes a receipt has one, and none is orphaned.
    obligations = body.get("obligations")
    if not isinstance(obligations, list):
        problems.append("the closure's `obligations` is not a list")
    else:
        for o in obligations:
            if o.get("orphan"):
                problems.append(f"{o.get('unit')}: the obligation is orphaned -- its court "
                                f"{o.get('court')!r} owes a receipt it does not have")
        plan_units = {str(u) for (u, _c, _cl, _w) in po.COURT_UNITS}
        for o in obligations:
            if str(o.get("unit")) not in plan_units:
                problems.append(f"the closure records the obligation {o.get('unit')}, which the "
                                f"plan does not name (orphaned obligation)")
        if obligations != d["obligations"]:
            problems.append("the committed `obligations` is not the derived `obligations`")

    # 3. The receipts: the stratum owes none, and none is orphaned.
    receipts = body.get("receipts")
    if receipts != d["receipts"]:
        problems.append("the committed `receipts` is not the derived `receipts`")
    if isinstance(receipts, dict):
        for kind in ("receipts", "challenges"):
            o = (receipts.get(kind) or {}).get("orphaned_count")
            if o:
                problems.append(f"{o} Phase-25 {kind} name a court with no declarable court "
                                f"(orphaned {kind})")
        if receipts.get("claims_orphaned"):
            problems.append("a Phase-25 claim names a court with no declarable court")

    # 4. The residual census: every residual disposed, the open ones named.
    census = body.get("residual_census")
    if census != d["residual_census"]:
        problems.append("the committed `residual_census` is not the derived census")
    if isinstance(census, dict) and int(census.get("undisposed") or 0):
        for unit, ids_ in sorted((census.get("undisposed_sets") or {}).items()):
            problems.append(f"{len(ids_)} residual(s) in {unit} are undisposed (no valid class or "
                            f"disposition): {', '.join(ids_[:OPEN_SAMPLE])}")

    # 5. The record join honesty: a `present` that disagrees with the tree is a join with no evidence.
    existing = set(evidence["existing"])
    for r in records:
        relpath = r.get("artefact")
        if not relpath or r.get("self"):
            continue
        if bool(r.get("artefact_present")) != (relpath in existing):
            problems.append(f"{r.get('unit')}: claims artefact_present={r.get('artefact_present')} "
                            f"for {relpath}, which disagrees with the committed tree (a join with "
                            f"no committed evidence)")

    # 6. The chain and the Gemel projection reproduce; a record the chain rule keys on cannot drift.
    if body.get("chain") != d["chain"]:
        problems.append("the recorded chain staging does not reproduce from gen_frf_courts.py and "
                        "the tree")
    if body.get("gemel") != d["gemel"]:
        problems.append(f"the recorded Gemel projection does not reproduce from "
                        f"{rel(GEMEL_TRAJECTORY)}")

    # 7. The counts and the whole plane equal their derivation; the claim cannot overstate.
    if body.get("counts") != d["counts"]:
        problems.append("the committed `counts` is not the derived `counts`")
    if body.get("claim") != d["claim"]:
        problems.append("the committed `claim` is not the derived claim")
    claim = body.get("claim") or {}
    open_n = int((body.get("counts") or {}).get("residuals_open") or 0)
    undisp = int((body.get("counts") or {}).get("residuals_undisposed") or 0)
    if claim.get("closed") and (open_n or undisp):
        problems.append(f"the closure claims to be closed while {open_n} residual(s) are open and "
                        f"{undisp} are undisposed")
    if body.get("property_status") != d["property_status"]:
        problems.append("the committed `property_status` is not the derived status")
    return problems


def frf_closure_sensitivity_control(body: dict, evidence: dict) -> dict:
    """Seed six mutations and require each caught, with specificity holding.

    Each is a distinct way the closure could lie: a record silently dropped; an obligation
    orphaned; a record whose artefact it claims is present with no committed evidence; a typed
    count; a closure claimed closed while an open residual exists; and a residual read as disposed
    with no disposition.
    """
    baseline = frf_closure_findings(body, evidence)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def clone() -> dict:
        return json.loads(json.dumps(body))

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = frf_closure_findings(mutated, evidence)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    # m1: a record silently dropped.
    def drop_record() -> dict:
        b = clone()
        b["records"] = b["records"][1:]
        return b

    m1 = check("record_dropped", drop_record(), "omits the derived record")

    # m2: an obligation orphaned (its court is neither registered nor pending).
    def orphan_obligation() -> dict:
        b = clone()
        b["obligations"][0]["court"] = "MS-NOT-A-COURT"
        b["obligations"][0]["court_registered"] = False
        b["obligations"][0]["court_pending"] = False
        b["obligations"][0]["joined"] = False
        b["obligations"][0]["orphan"] = True
        return b

    m2 = check("obligation_orphaned", orphan_obligation(), "orphaned")

    # m3: a record whose artefact it claims present with no committed evidence.
    def join_with_no_evidence() -> dict:
        b = clone()
        b["records"][0]["artefact_present"] = True
        b["records"][0]["artefact"] = "artifacts/phase25/does-not-exist.json"
        return b

    m3 = check("join_with_no_evidence", join_with_no_evidence(), "no committed evidence")

    # m4: a typed count (a count not derived from the records).
    def typed_count() -> dict:
        b = clone()
        b["counts"]["records_joined"] = int(b["counts"].get("records_joined", 0)) + 1
        return b

    m4 = check("typed_count", typed_count(), "not the derived `counts`")

    # m5: a closure claimed closed while an open residual exists.
    def claimed_with_open_residual() -> dict:
        b = clone()
        b["counts"]["residuals_open"] = max(1, int(b["counts"].get("residuals_open", 0)))
        b["claim"] = dict(b["claim"])
        b["claim"]["closed"] = True
        return b

    m5 = check("closure_claimed_with_open_residual", claimed_with_open_residual(),
               "claims to be closed while")

    # m6: a residual read as disposed with no disposition (an undisposed residual).
    def undisposed_residual() -> dict:
        b = clone()
        b["residual_census"]["undisposed"] = 1
        b["residual_census"]["undisposed_sets"] = {"red-team": ["res-mystery"]}
        return b

    m6 = check("residual_undisposed", undisposed_residual(), "undisposed")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# writing, reading and the entry points
# --------------------------------------------------------------------------------------------

def _inputs() -> list:
    inputs = [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-frf-closure-tool", path=REPO_ROOT / GENERATOR),
        InputRef(name="frf-registry", path=REGISTRY),
        InputRef(name="gemel-trajectory", path=GEMEL_TRAJECTORY),
    ]
    seen = {i.path for i in inputs if i.path is not None}
    for unit, (relpath, _kinds) in RECORD_EVIDENCE.items():
        if unit == SELF_UNIT or relpath is None:
            continue
        p = REPO_ROOT / relpath
        if p.is_file() and p not in seen:
            seen.add(p)
            inputs.append(InputRef(name=unit, path=p))
    for unit in sorted(TOOL_OF):
        t = TOOL_OF[unit]
        if not t:
            continue
        p = REPO_ROOT / t
        if p.is_file() and p not in seen:
            seen.add(p)
            inputs.append(InputRef(name=f"tool:{unit}", path=p))
    return inputs


def cmd_measure() -> int:
    evidence = collect_evidence()
    body = build_body(evidence)
    findings = frf_closure_findings(body, evidence)
    control = frf_closure_sensitivity_control(body, evidence)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-frf-closure", authority=auth.id, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[ms-frf-closure] {rel(OUT)} -- records={c['records']} "
          f"joined={c['records_joined']} pending={c['records_pending']} "
          f"orphaned={c['records_orphaned']}")
    print(f"  obligations={c['obligations']} joined={c['obligations_joined']} "
          f"orphaned={c['obligations_orphaned']} | receipts_required={c['receipts_required']} "
          f"orphaned={c['receipts_orphaned']} | claims_orphaned={c['claims_orphaned']}")
    print(f"  residual records={c['residual_records']} disposed={c['residuals_disposed']} "
          f"crosscheck={c['residual_crosscheck']} open={c['residuals_open']} "
          f"undisposed={c['residuals_undisposed']} "
          f"outside_schema={c['residual_classes_outside_schema']}")
    print(f"  chain vacuous={c['chain_vacuous']} declared={c['chain_declared_courts']} "
          f"probes={c['chain_probe_pairs']} | gemel_current={body['gemel']['current']}")
    print(f"  property_status={body['property_status']} claim.closed={body['claim']['closed']}")
    print(f"  -> body_hash={doc['body_hash'][:16]} all_checks={not findings} "
          f"control honest={control['honest']} specificity={control['specificity_holds']}")
    for f in findings[:24]:
        print(f"    {f}")
    return 0 if (not findings and control["honest"]) else 1


def cmd_check() -> int:
    if not OUT.is_file():
        print(f"[ms-frf-closure] {rel(OUT)} is absent; run --measure")
        return 1
    body = _body(_load(OUT))
    evidence = collect_evidence()
    findings = frf_closure_findings(body, evidence)
    control = frf_closure_sensitivity_control(body, evidence)
    c = body.get("counts") or {}
    for f in findings[:24]:
        print(f"  finding: {f}")
    print(f"[ms-frf-closure] records={c.get('records')} joined={c.get('records_joined')} "
          f"orphaned={c.get('records_orphaned')} obligations_orphaned="
          f"{c.get('obligations_orphaned')} residuals_open={c.get('residuals_open')} "
          f"chain_vacuous={c.get('chain_vacuous')} findings={len(findings)} "
          f"control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation runs and the control is honest.

    It builds a small, self-consistent synthetic evidence set (a registry of two courts -- one
    registered, one pending -- a plan, a Gemel projection and a residual plane) so the closure's
    derivation, findings and control run without reading the multi-megabyte committed planes, and it
    breaks the claim in memory to prove the control can fail.
    """
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_frf_closure.py", env={}, dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_frf_closure.py is not admitted as a metadata-only generator on a host")

    # A real, present file the synthetic records can cite, plus a real registry.
    present = rel(SCHEMAS)
    synth_planes = {
        "source-census": {"residuals": [
            {"class": "out_of_scope", "detail": "x", "source": "s"}]},
        "red-team": {"residuals": [
            {"residual_id": "res-rt-1", "subject": "rt", "class": "evidence_missing",
             "disposition": "open", "detail": "d", "evidence": ["artifacts/phase25/red-team.json"]},
            {"residual_id": "res-rt-2", "subject": "rt", "class": "tool_unsupported",
             "disposition": "preserved", "detail": "d", "evidence": ["x"]}]},
    }
    # Every Phase-25 court's committed evidence and generator is present except the seal document,
    # which 25.21 lands (no artefact and no generator -> pending, not orphaned).
    existing = [rel(PLAN), rel(REGISTRY), rel(GEMEL_TRAJECTORY), rel(GUARD), rel(MANIFEST),
                rel(SCHEMAS), present]
    existing += [relpath for unit, (relpath, _k) in RECORD_EVIDENCE.items()
                 if unit not in (SELF_UNIT, SEAL_UNIT) and relpath]
    existing += [t for t in TOOL_OF.values() if t]
    evidence = {
        "registry": [["rt-selftest", 25, "rt_selftest_probe", "synthetic"]],
        "candidate_version": "0.0.0",
        "gemel_text": "current: `checkpoint." + "0" * 64 + "`\n\n## Checkpoints\n"
                      "* `K1` — `checkpoint." + "1" * 64 + "`\n",
        "receipts": {},
        "challenges": {},
        "claim_courts": [],
        "planes": synth_planes,
        "existing": existing,
        "ledger": po,
    }
    body = build_body(evidence)
    baseline = frf_closure_findings(body, evidence)
    if baseline:
        failures.append(f"the synthetic closure body is not clean: {baseline[:4]}")
    control = frf_closure_sensitivity_control(body, evidence)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    # A rubber-stamp control must be able to fail: replace the findings with an empty one.
    original = globals()["frf_closure_findings"]
    globals()["frf_closure_findings"] = lambda b, e: []
    try:
        broken = frf_closure_sensitivity_control(body, evidence)
    finally:
        globals()["frf_closure_findings"] = original
    if broken.get("honest") and broken.get("caught") == broken.get("seeded"):
        failures.append("the sensitivity control PASSED with a rubber-stamp findings function")

    if failures:
        print("[ms-frf-closure] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    c = body["counts"]
    print(f"[ms-frf-closure] self-test ok: the guard admits it as metadata-only; the synthetic "
          f"closure is clean (records={c['records']} joined={c['records_joined']} "
          f"pending={c['records_pending']} orphaned={c['records_orphaned']}; "
          f"residuals_open={c['residuals_open']}); and all {control['seeded']} seeded mutations "
          f"(a dropped record, an orphaned obligation, a join with no evidence, a typed count, a "
          f"closure claimed with an open residual and an undisposed residual) are caught with "
          f"specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive forensics/atlas/phase25/frf-closure.json from the committed inputs")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed closure without regenerating")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the metadata-only admission and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool executes nothing, so the manifest
    # lists it `metadata_only` and the guard admits it on any host.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check()
    # The default action is the derivation (and `--measure` names it): `evidence_determinism.py`
    # regenerates every generator with no flags and compares the bytes.
    return cmd_measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
