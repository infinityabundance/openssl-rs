#!/usr/bin/env python3
"""openssl-rs — the Phase-24 downstream safety coverage (Phase 25.14).

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). 25.1 enumerates the compiler-derived unsafe
operations, 25.2 records the non-Rust trusted computing base, 25.3 gives every site an obligation,
25.4 models the ownership/allocation/callback machinery, 25.5 maps every site to the Phase-22
reachability roots that reach it, 25.6 maps every site to the Phase-24 downstream population, 25.7
classifies every site's exposure and 25.8 records the reduction worklist and the safe-core
reconstruction. This subphase is 25.14: it **measures the coverage of the unreduced unsafe sites by
the Phase-24 downstream runs**, naming the reachable sites no downstream measurement observes, so a
reachable site is never assumed exercised.

The rule, and the authority it reads
------------------------------------
    unreduced unsafe site -> its 25.7 exposure (is it externally reachable at all?) -> the 25.6
       measured consumers that reach it -> the Phase-24 downstream run (the runtime-functional
       atlas candidate run, or the p1000 drop-in receipt) whose family exercised the consumer ->
       the site is `DOWNSTREAM_OBSERVED`; a reachable site no run observes is
       `REACHABLE_UNOBSERVED`

Each step is a fact a committed plane measured, and none of it is typed here:

  * the **unreduced unsafe sites** are the live census's own records (`source-census.json`): 25.8
    applied no worklist reduction and re-derived the census after its safe-core reconstruction, so
    the committed census *is* the unreduced set, and this plane requires the census count to equal
    25.8's post-reduction `sites_after` (`artifacts/phase25/unsafe-reduction.json`) rather than
    assuming it;
  * the **exposure** of a site is the 25.7 classification's own (`artifacts/phase25/exposure.json`):
    a site is externally reachable when its committed class is in
    `memory_safety_schemas.EXTERNALLY_REACHABLE_EXPOSURE`, and its risk tier is the plane's;
  * the **consumers** that reach a site are the 25.6 Phase-24 downstream crosswalk's own
    (`artifacts/phase25/phase24-crosswalk.json`): its `runtime_consumers` are the measured
    consumers a functional Phase-24 run observed, its `consumers` are the measured consumers whose
    imports point at the site's surface, and neither is recomputed here;
  * the **Phase-24 downstream runs** are the committed measurement
    (`forensics/downstream/runtime-functional-atlas.json` for the runtime runs -- the candidate run
    rows at a functional level -- and `forensics/downstream/p1000-run.json` for the drop-in ladder,
    its per-consumer receipts and the `DROP_IN_PASS` verdicts); the **fingerprints**
    (`usage-fingerprints.json`) decide which run families carry a symbol-level join, and the
    **counted population** is the frozen P1000 (`family-freeze.json`).

The join is the Phase-24 measurement's answer, not a second one
--------------------------------------------------------------
For every unreduced site this plane reads the 25.6 crosswalk's own consumers and the Phase-24 run
evidence. It reads no source, runs no compiler and drives no workload: the exposure, the imports,
the run levels, the drop-in verdicts and the population are the committed planes', and a run the
Phase-24 measurement does not record is not invented to fill a gap.

Partial joins and coverage gaps are residuals, never zeros or guesses
--------------------------------------------------------------------
Where the join cannot be closed it is recorded rather than defaulted:

  * a **reachable site no downstream run observes** gets an explicit `evidence_missing` residual,
    with its exposure class, so a reachable site is never read as exercised;
  * a **run family with no committed usage fingerprint** has a runtime observation but no
    symbol-level import to attribute it to, so it is a `join_evidence_missing` residual rather than
    guessed onto a site;
  * the **census sites outside the externally reachable set** are `out_of_scope`: no downstream run
    is expected to observe them, and this is said rather than zeroed.

The frozen P1000 holdout discipline is preserved
------------------------------------------------
The Phase-24 population was frozen before any candidate result (`family-freeze.json`,
`forensics/downstream/holdout.json`, 24.4/24.5), and the holdout was run exactly once against the
frozen candidate. This plane is a **post-freeze measurement** over that frozen population: it reads
the committed run evidence as it stands, including the once-run holdout, and it selects and excludes
nothing by a family's holdout label, so reading held-out families here is a measurement and never
development feedback. The rule records the frozen partition and the discipline; the court refuses a
plane whose rule does not carry it.

A pure derivation, so it executes nothing
-----------------------------------------
It reads committed planes and writes a derived plane; it runs no compiler, no tool and no probe, so
`forensics/memory-safety/container.json` lists it `metadata_only` and the Docker-only guard admits it
on any host (it still calls the guard first, so the rule is never optional).

Outputs
-------
  artifacts/phase25/phase24-safety-coverage.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
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

# The Docker-only execution guard, called first. This tool executes nothing -- it derives a plane
# from committed planes -- so the manifest lists it `metadata_only` and the guard admits it on any
# host exactly as `ms_phase24_crosswalk.py` is.
import phase25_guard  # noqa: E402

# The coverage and residual schemas and their closed vocabularies. Imported, never restated.
import memory_safety_schemas as schemas  # noqa: E402

# The census (for the site universe and its ordered id lists) and the lossless columnar codec.
import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "phase24-safety-coverage.json"
GENERATOR = "forensics/tools/ms_phase24_safety_coverage.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_phase24_safety_coverage.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

# 25.1's compiler-backed source census: the unreduced site universe.
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
# 25.6's Phase-24 downstream crosswalk: the measured consumers that reach each site.
PHASE24_CROSSWALK = REPO_ROOT / "artifacts" / "phase25" / "phase24-crosswalk.json"
# 25.7's exposure classification: whether a site is externally reachable, and its risk tier.
EXPOSURE = REPO_ROOT / "artifacts" / "phase25" / "exposure.json"
# 25.8's unsafe reduction: the post-reduction census counts the unreduced universe is tied to.
UNSAFE_REDUCTION = REPO_ROOT / "artifacts" / "phase25" / "unsafe-reduction.json"

# The Phase-24 downstream measurement. The committed measurement is the authority this plane reads.
DS = REPO_ROOT / "forensics" / "downstream"
USAGE_FINGERPRINTS = DS / "usage-fingerprints.json"
RUNTIME_ATLAS = DS / "runtime-functional-atlas.json"
P1000_RUN = DS / "p1000-run.json"
FAMILY_FREEZE = DS / "family-freeze.json"
HOLDOUT = DS / "holdout.json"

CENSUS_REL = rel(CENSUS)
PHASE24_CROSSWALK_REL = rel(PHASE24_CROSSWALK)
EXPOSURE_REL = rel(EXPOSURE)
UNSAFE_REDUCTION_REL = rel(UNSAFE_REDUCTION)
USAGE_FINGERPRINTS_REL = rel(USAGE_FINGERPRINTS)
RUNTIME_ATLAS_REL = rel(RUNTIME_ATLAS)
P1000_RUN_REL = rel(P1000_RUN)
FAMILY_FREEZE_REL = rel(FAMILY_FREEZE)
HOLDOUT_REL = rel(HOLDOUT)

# The claimed profile the Phase-24 downstream runs measured (the same `dev` profile the sanitizer
# planes record).
PROFILE = "dev"

# The Phase-24 downstream run instruments this plane records a `coverage` row for. Each is a
# committed Phase-24 measurement: the runtime-functional atlas candidate runs, and the p1000
# drop-in ladder. The instrument's run families decide which sites it observes.
RUNTIME_INSTRUMENT = "phase24-runtime-functional-atlas"
P1000_INSTRUMENT = "phase24-p1000-run"
INSTRUMENTS: tuple[str, ...] = (RUNTIME_INSTRUMENT, P1000_INSTRUMENT)

# The site dispositions. `REACHABLE_UNOBSERVED` is a recorded state with a reason, never an
# omission.
STATES: tuple[str, ...] = ("DOWNSTREAM_OBSERVED", "REACHABLE_UNOBSERVED")

# Why a reachable site is `REACHABLE_UNOBSERVED`: the closed reasons, so an unobserved reachable
# site is explained rather than merely counted.
UNOBSERVED_REASONS: tuple[str, ...] = (
    "no_downstream_run_observes_the_site",
)

# The residual class for a reachable site no downstream run observes: the downstream evidence is
# missing for it. It is a member of the schema's residual vocabulary.
UNOBSERVED_RESIDUAL_CLASS = "evidence_missing"
# The residual class for a run family with no committed usage fingerprint: the run observed a
# surface with no symbol-level import to attribute it to. It is a member of the schema's residual
# vocabulary (added by 25.6).
RUN_JOIN_RESIDUAL_CLASS = "join_evidence_missing"
# The residual class for the census sites outside the externally reachable set: no downstream run
# is expected to observe them.
OUT_OF_SCOPE_RESIDUAL_CLASS = "out_of_scope"

NON_CLAIMS = (
    "a downstream run's observation is a bounded differential result over the workload it drove: a "
    "site observed by a run is exercised by that run's surface classes, not proven safe, and the "
    "observation is not a coverage claim about every input to the site or a memory-safety proof",
    "a reachable site no downstream run observes is recorded, not zeroed: it carries an "
    "`evidence_missing` residual with its exposure class, and the record is not a claim that the "
    "site is safe, nor that no possible consumer ever exercises it -- it is the measured "
    "population's answer",
    "the observation is import-anchored and population-bounded: the join reaches a site through its "
    "authority unit's imported symbols, so a consumer linked statically, through a private library "
    "copy or via a dlsym/loader path is not observed here, and only the measured fingerprinted "
    "cohort carries symbol-level evidence",
    "the counted population is a selected population, not a random sample: the frozen 1,000 "
    "families chosen from committed ranking evidence do not generalise to all downstream software, "
    "and the coverage inherits that selection",
    "the coverage is a post-freeze measurement over the frozen population, including the once-run "
    "holdout: it is read as committed evidence and never used as development feedback, and no "
    "family is selected or excluded by its holdout label",
)


# --------------------------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-phase24-safety-coverage] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def load_authority() -> dict:
    """The committed planes this plane reads, loaded once so the generator and the court share bytes.

    The census, the 25.6 crosswalk, the 25.7 exposure classification and the 25.8 reduction are
    columnar artefacts from this stratum, so their bodies are decoded here (the census supplies the
    ordered id lists the others reference by index); the Phase-24 atlases are not this stratum's
    encoding and are used as loaded.
    """
    census_doc = _load(CENSUS)
    census_body = ms_census.decode_body(census_doc.get("body", census_doc))
    refs = ms_codec.refs_from_census(census_body)

    def decoded(path: Path) -> dict:
        doc = _load(path)
        return {**doc, "body": ms_codec.decode_body(doc.get("body", doc), refs)}

    return {
        "census": {**census_doc, "body": census_body},
        "phase24_crosswalk": decoded(PHASE24_CROSSWALK),
        "exposure": decoded(EXPOSURE),
        "unsafe_reduction": decoded(UNSAFE_REDUCTION),
        "usage_fingerprints": _load(USAGE_FINGERPRINTS),
        "runtime": _load(RUNTIME_ATLAS),
        "p1000": _load(P1000_RUN),
        "family_freeze": _load(FAMILY_FREEZE),
        "holdout": _load(HOLDOUT),
    }


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _family_names(authority: dict) -> dict:
    """`family_id -> canonical_name` from the committed planes that carry both, never typed."""
    names: dict = {}
    freeze = _body(authority["family_freeze"])
    for row in freeze.get("p1000") or []:
        fid = str(row.get("family_id"))
        if row.get("canonical_name"):
            names.setdefault(fid, str(row["canonical_name"]))
    fps = _body(authority["usage_fingerprints"])
    for row in fps.get("fingerprints") or []:
        fid = str(row.get("family_id"))
        if row.get("canonical_name"):
            names.setdefault(fid, str(row["canonical_name"]))
    p1000 = _body(authority["p1000"])
    for row in p1000.get("per_consumer_receipts") or []:
        fid = str(row.get("family_id"))
        if row.get("canonical_name"):
            names.setdefault(fid, str(row["canonical_name"]))
    return names


def _candidate_levels(authority: dict) -> tuple[set, dict]:
    """`(functional levels, family_id -> level)` from the committed runtime atlas, never typed.

    A family's level is the deepest candidate run at a functional level the atlas gives it (the
    atlas records one level per family; a functional level wins a non-functional one).
    """
    rt = _body(authority["runtime"])
    functional = set((rt.get("rule") or {}).get("levels") or [])
    level: dict = {}
    for run in rt.get("runs") or []:
        if run.get("subject") != "candidate":
            continue
        fid = str(run.get("family_id"))
        lvl = run.get("level")
        prev = level.get(fid)
        if prev is None or (lvl in functional and prev not in functional):
            level[fid] = lvl
    return functional, level


# --------------------------------------------------------------------------------------------
# the derivation
# --------------------------------------------------------------------------------------------

_DERIVE_CACHE: dict = {}


def derive_cached(census_body: dict, authority: dict) -> dict:
    """`derive` memoised by the identity of its two arguments (pure and deterministic)."""
    key = (id(census_body), id(authority))
    if key not in _DERIVE_CACHE:
        _DERIVE_CACHE[key] = derive(census_body, authority)
    return _DERIVE_CACHE[key]


def derive(census_body: dict, authority: dict) -> dict:
    """The whole coverage, derived: instruments, the inverse site/consumer views, counts, residuals."""
    census_ids = [str(s["site_id"]) for s in (census_body.get("sites") or [])]
    census_set = set(census_ids)

    exposure = _body(authority["exposure"])
    exp_sites = exposure.get("sites") or {}
    reachable = sorted(sid for sid in census_ids
                       if (exp_sites.get(sid) or {}).get("e") in
                       schemas.EXTERNALLY_REACHABLE_EXPOSURE)
    reachable_set = set(reachable)

    xw = _body(authority["phase24_crosswalk"])
    xw_sites = xw.get("sites") or {}
    xw_consumers = xw.get("consumers") or {}

    # The Phase-24 run evidence: the runtime atlas's functional candidate families, the p1000 drop-in
    # verdicts and the committed fingerprints that carry a symbol-level join.
    functional, family_level = _candidate_levels(authority)
    names = _family_names(authority)
    functional_families = sorted(fid for fid, lvl in family_level.items() if lvl in functional)
    p1000 = _body(authority["p1000"])
    receipts = {str(r.get("family_id")): r for r in (p1000.get("per_consumer_receipts") or [])}
    drop_in_pass_families = sorted(fid for fid, r in receipts.items()
                                   if r.get("result") == "DROP_IN_PASS")
    fps = _body(authority["usage_fingerprints"])
    fingerprinted = sorted({str(f.get("family_id")) for f in (fps.get("fingerprints") or [])})
    fingerprinted_set = set(fingerprinted)
    counted = {str(f.get("family_id"))
               for f in (_body(authority["family_freeze"]).get("p1000") or [])}

    # Per-consumer detail: the 25.6 measurement's own consumers, enriched with the Phase-24 run
    # evidence (the runtime level, the drop-in verdict, the fingerprint).
    consumers: dict = {}
    for name in sorted(xw_consumers):
        c = xw_consumers[name]
        fid = str(c.get("family_id"))
        rec = receipts.get(fid) or {}
        consumers[name] = {
            "family_id": fid,
            "cluster": c.get("cluster"),
            "counted": bool(c.get("counted")),
            "runtime_level": c.get("runtime_level"),
            "runtime_observed": bool(c.get("runtime_observed")),
            "drop_in_result": (rec.get("result") if rec else None),
            "drop_in_pass": rec.get("result") == "DROP_IN_PASS",
            "fingerprinted": fid in fingerprinted_set,
        }

    # The site views: `observed_by` are the 25.6 runtime consumers that reach a site, `reaches_by`
    # the 25.6 measured consumers whose imports point at it. Both are 25.6's answer, not recomputed.
    observed_by: dict = {}
    reaches_by: dict = {}
    observed: set = set()
    for sid in reachable:
        e = xw_sites.get(sid) or {}
        obs = sorted({str(n) for n in (e.get("runtime_consumers") or [])})
        rea = sorted({str(n) for n in (e.get("consumers") or [])})
        if obs:
            observed_by[sid] = obs
            observed.add(sid)
        if rea:
            reaches_by[sid] = rea

    # The instrument coverage. An instrument observes a site when one of its run families carries
    # the symbol-level join (the fingerprint) and a Phase-24 run observed the site: a run family
    # that exercised a consumer is what makes the observation, so every covered site carries
    # runtime evidence. Every set is recomputed from the site view above, never typed.
    def instrument_sites(run_families: list) -> tuple[set, list]:
        joined_names = sorted(n for n, c in consumers.items()
                              if c["family_id"] in set(run_families) and c["fingerprinted"])
        covered: set = set()
        for n in joined_names:
            for sid in observed:
                if n in observed_by[sid]:
                    covered.add(sid)
        return covered, joined_names

    runtime_covered, runtime_joined = instrument_sites(functional_families)
    p1000_covered, p1000_joined = instrument_sites(drop_in_pass_families)

    def coverage_rec(name: str, covered: set, run_families: list, joined: list,
                     levels: dict, evidence: list) -> dict:
        uncovered = sorted(reachable_set - covered)
        return {
            "coverage_id": "cov:" + name,
            "profile": PROFILE,
            "tool": name,
            "covered_sites": sorted(covered),
            "uncovered_sites": uncovered,
            "tool_state": "PASS" if covered else "NOT_REACHABLE",
            "evidence": list(evidence),
            "run_families": [names.get(fid, fid) for fid in run_families],
            "joined_families": joined,
            "run_levels": dict(sorted(levels.items())),
            "covered_count": len(covered),
            "uncovered_count": len(uncovered),
        }

    runs: dict = {}
    runs[RUNTIME_INSTRUMENT] = coverage_rec(
        RUNTIME_INSTRUMENT, runtime_covered, functional_families, runtime_joined,
        Counter(lvl for lvl in family_level.values() if lvl in functional),
        [USAGE_FINGERPRINTS_REL, RUNTIME_ATLAS_REL, PHASE24_CROSSWALK_REL, EXPOSURE_REL, CENSUS_REL],
    )
    runs[P1000_INSTRUMENT] = coverage_rec(
        P1000_INSTRUMENT, p1000_covered, drop_in_pass_families, p1000_joined,
        Counter(str((receipts[fid].get("what_ran") or {}).get("level"))
                for fid in drop_in_pass_families),
        [USAGE_FINGERPRINTS_REL, P1000_RUN_REL, PHASE24_CROSSWALK_REL, EXPOSURE_REL, CENSUS_REL],
    )

    # The inverse site view: per reachable site, its exposure, risk tier, the measured consumers that
    # reach it, the runtime-observed ones, and its coverage state. Every field is recomputed from the
    # forward maps above, never typed.
    sites: dict = {}
    for sid in reachable:
        obs = observed_by.get(sid, [])
        rec = {
            "exposure": (exp_sites.get(sid) or {}).get("e"),
            "risk": (exp_sites.get(sid) or {}).get("r"),
            "reaches": reaches_by.get(sid, []),
            "observed_by": obs,
            "state": "DOWNSTREAM_OBSERVED" if obs else "REACHABLE_UNOBSERVED",
        }
        if not obs:
            rec["reason"] = "no_downstream_run_observes_the_site"
        sites[sid] = rec

    # The inverse consumer view: per measured consumer, the sites it observes. Recomputed from the
    # site view above, never typed.
    consumer_view: dict = {}
    for name in sorted(consumers):
        c = consumers[name]
        rec_sites = sorted(sid for sid in reachable if name in (observed_by.get(sid) or []))
        consumer_view[name] = {
            "family_id": c["family_id"],
            "cluster": c["cluster"],
            "counted": c["counted"],
            "runtime_level": c["runtime_level"],
            "runtime_observed": c["runtime_observed"],
            "drop_in_result": c["drop_in_result"],
            "fingerprinted": c["fingerprinted"],
            "sites": rec_sites,
        }

    # The residuals. A partial join or a coverage gap is recorded, never zeroed or guessed.
    unobserved = sorted(reachable_set - observed)
    unobserved_by_class = Counter((exp_sites.get(sid) or {}).get("e") for sid in unobserved)
    not_reachable = sorted(census_set - reachable_set)
    not_reachable_by_class = Counter((exp_sites.get(sid) or {}).get("e") for sid in not_reachable)

    residuals: list = []
    for cls, n in sorted(unobserved_by_class.items()):
        residuals.append({
            "residual_id": "rx:" + hashlib.sha256(
                f"{UNOBSERVED_RESIDUAL_CLASS}|exposure|{cls}".encode("utf-8")).hexdigest()[:16],
            "subject": f"reachable unsafe sites no downstream run observes ({cls})",
            "class": UNOBSERVED_RESIDUAL_CLASS,
            "disposition": "open",
            "detail": ("the site is externally reachable in the claimed profile, but no measured "
                       "Phase-24 downstream run observes it: no fingerprinted run family reaches "
                       "its surface, so its downstream evidence is missing; preserved rather than "
                       "read as exercised"),
            "evidence": [EXPOSURE_REL, PHASE24_CROSSWALK_REL, USAGE_FINGERPRINTS_REL],
            "exposure_class": cls,
            "site_count": n,
        })
    if not_reachable:
        residuals.append({
            "residual_id": "rx:" + hashlib.sha256(
                f"{OUT_OF_SCOPE_RESIDUAL_CLASS}|not-externally-reachable".encode("utf-8")
            ).hexdigest()[:16],
            "subject": "census sites outside the externally reachable set",
            "class": OUT_OF_SCOPE_RESIDUAL_CLASS,
            "disposition": "open",
            "detail": ("the census sites are not externally reachable in the claimed profile, so no "
                       "downstream run is expected to observe them; recorded rather than dropped and "
                       "never defaulted to a coverage claim"),
            "evidence": [EXPOSURE_REL, CENSUS_REL],
            "site_count": len(not_reachable),
            "by_exposure": dict(sorted(not_reachable_by_class.items())),
        })
    for instrument, run_families in ((RUNTIME_INSTRUMENT, functional_families),
                                     (P1000_INSTRUMENT, drop_in_pass_families)):
        unjoined = sorted(fid for fid in run_families if fid not in fingerprinted_set)
        if not unjoined:
            continue
        residuals.append({
            "residual_id": "rx:" + hashlib.sha256(
                f"{RUN_JOIN_RESIDUAL_CLASS}|{instrument}".encode("utf-8")).hexdigest()[:16],
            "subject": "phase24-run-families-without-a-fingerprint:" + instrument,
            "class": RUN_JOIN_RESIDUAL_CLASS,
            "disposition": "open",
            "detail": ("the run family was measured by the Phase-24 downstream runs but carries no "
                       "committed usage fingerprint, so its runtime surface has no symbol-level "
                       "import to attribute to an unsafe site; recorded rather than attributed to a "
                       "site"),
            "evidence": [RUNTIME_ATLAS_REL, P1000_RUN_REL, USAGE_FINGERPRINTS_REL],
            "instrument": instrument,
            "run_families": [names.get(fid, fid) for fid in unjoined],
            "family_count": len(unjoined),
        })

    # The reduction tie: the unreduced universe is the live census, and 25.8 records the same count
    # as its post-reduction one. A census that grew would break the tie, so it is re-derived.
    red = _body(authority["unsafe_reduction"])
    red_counts = red.get("counts") or {}
    recon = red.get("reconstruction") or {}
    eliminated = int(((recon.get("operations") or {}).get("by_class") or {}).get("ELIMINATED") or 0)

    holdout = _body(authority["holdout"])
    holdout_counts = holdout.get("counts") or {}

    counts = {
        "census_sites": len(census_ids),
        "unreduced_sites": len(census_ids),
        "reduction_sites_after": int(red_counts.get("sites_after") or 0),
        "reduction_eliminated": eliminated,
        "sites_reachable": len(reachable),
        "reduction_reachable_after": int(red_counts.get("reachable_after") or 0),
        "sites_observed": len(observed),
        "sites_reachable_unobserved": len(unobserved),
        "reachable_unobserved_by_exposure": dict(sorted(unobserved_by_class.items())),
        "sites_not_reachable": len(not_reachable),
        "not_reachable_by_exposure": dict(sorted(not_reachable_by_class.items())),
        "measured_consumers": len(consumers),
        "consumers_runtime_observed": sum(1 for c in consumers.values() if c["runtime_observed"]),
        "consumers_drop_in_pass": sum(1 for c in consumers.values() if c["drop_in_pass"]),
        "consumers_counted": sum(1 for c in consumers.values() if c["counted"]),
        "functional_candidate_runs": len(functional_families),
        "drop_in_pass_families": len(drop_in_pass_families),
        "fingerprinted_families": len(fingerprinted),
        "counted_families": len(counted),
        "observed_by_consumer": {n: len(consumer_view[n]["sites"]) for n in sorted(consumer_view)},
        "family_level": {names.get(fid, fid): lvl for fid, lvl in sorted(family_level.items())
                         if lvl in _candidate_levels(authority)[0]},
        "downstream_runs": {inst: {
            "covered": runs[inst]["covered_count"],
            "uncovered": runs[inst]["uncovered_count"],
            "run_families": len(runs[inst]["run_families"]),
            "joined_families": len(runs[inst]["joined_families"]),
            "tool_state": runs[inst]["tool_state"],
        } for inst in INSTRUMENTS},
        "holdout": {"development": int(holdout_counts.get("development") or 0),
                    "holdout": int(holdout_counts.get("holdout") or 0),
                    "status": str(holdout.get("holdout_status") or "")},
        "residuals": len(residuals),
        "states": sorted(STATES),
    }

    return {
        "runs": runs,
        "sites": sites,
        "consumers": consumer_view,
        "counts": counts,
        "residuals": residuals,
        "unobserved": unobserved,
        "unobserved_by_class": dict(sorted(unobserved_by_class.items())),
        "not_reachable_count": len(not_reachable),
        "not_reachable_by_class": dict(sorted(not_reachable_by_class.items())),
        "runtime_covered": runtime_covered,
        "p1000_covered": p1000_covered,
        "instrument_unjoined": {
            RUNTIME_INSTRUMENT: sorted(fid for fid in functional_families
                                       if fid not in fingerprinted_set),
            P1000_INSTRUMENT: sorted(fid for fid in drop_in_pass_families
                                     if fid not in fingerprinted_set),
        },
        "observed": observed,
        "reachable_set": reachable_set,
    }


def _rule(authority: dict) -> dict:
    red = _body(authority["unsafe_reduction"])
    holdout = _body(authority["holdout"])
    return {
        "authority": {
            "kind": "phase24-downstream-safety-evidence",
            "paths": [PHASE24_CROSSWALK_REL, EXPOSURE_REL, UNSAFE_REDUCTION_REL,
                      USAGE_FINGERPRINTS_REL, RUNTIME_ATLAS_REL, P1000_RUN_REL,
                      FAMILY_FREEZE_REL, HOLDOUT_REL],
            "declaration": (
                "the committed 25.6 Phase-24 downstream crosswalk, the 25.7 exposure "
                "classification, the 25.8 post-reduction census counts and the committed Phase-24 "
                "downstream measurement are the authority this plane reads: the exposure says "
                "whether a site is externally reachable, the crosswalk names the measured consumers "
                "that reach it, and the run evidence (the runtime-functional atlas, the p1000 "
                "drop-in receipts and the usage fingerprints) says which run family observed it; no "
                "reachability, consumer, verdict or count is typed here"
            ),
        },
        "mapping_rule": (
            "unreduced unsafe site -> its 25.7 exposure (externally reachable?) -> the 25.6 measured "
            "consumers that reach it -> the Phase-24 downstream run (the runtime atlas candidate "
            "run, or the p1000 drop-in receipt) whose fingerprinted family observed the consumer -> "
            "the site is `DOWNSTREAM_OBSERVED`; a reachable site no run observes is "
            "`REACHABLE_UNOBSERVED`"
        ),
        "unreduced_authority": {
            "rule": (
                "the unreduced unsafe sites are the live census's own records: 25.8 applied no "
                "worklist reduction and re-derived the census after its safe-core reconstruction, so "
                "the committed census is the unreduced set, and this plane requires its count to "
                "equal 25.8's post-reduction `sites_after` rather than assuming it"
            ),
            "input": UNSAFE_REDUCTION_REL,
            "sites_after": int((red.get("counts") or {}).get("sites_after") or 0),
        },
        "reachability_authority": {
            "rule": (
                "a site is externally reachable when its 25.7 exposure class is in "
                "`memory_safety_schemas.EXTERNALLY_REACHABLE_EXPOSURE`, and its risk tier is the "
                "plane's; the reachable set is the coverage question's universe and is never typed"
            ),
            "input": EXPOSURE_REL,
        },
        "downstream_authority": {
            "rule": (
                "the consumers that reach a site are the 25.6 crosswalk's own `consumers`/ "
                "`runtime_consumers`, and the runs are the committed Phase-24 measurement's; a run "
                "family with no committed usage fingerprint cannot be joined to a site and is a "
                "recorded residual, never a guess"
            ),
            "inputs": [PHASE24_CROSSWALK_REL, USAGE_FINGERPRINTS_REL, RUNTIME_ATLAS_REL,
                       P1000_RUN_REL, FAMILY_FREEZE_REL],
        },
        "holdout_discipline": {
            "rule": (
                "the frozen P1000 and its precommitted holdout were fixed before any candidate "
                "result and the holdout was run exactly once; this plane is a post-freeze "
                "measurement over the frozen population, reading the committed run evidence as it "
                "stands (the once-run holdout included), and it selects and excludes nothing by a "
                "family's holdout label -- so reading held-out families here is a measurement, "
                "never development feedback"
            ),
            "input": HOLDOUT_REL,
            "status": str(holdout.get("holdout_status") or ""),
            "frozen_population": FAMILY_FREEZE_REL,
        },
        "run_disposition": (
            "every Phase-24 downstream run instrument is present in `.runs`: it carries the sites its "
            "fingerprinted run families observe (`covered_sites`), the reachable sites no such run "
            "observes (`uncovered_sites`), its run families, its joined families, its run levels and "
            "a tool state; an instrument the Phase-24 measurement does not record is not invented"
        ),
        "site_disposition": (
            "every reachable census site is present in `.sites`: a `DOWNSTREAM_OBSERVED` site names "
            "the runtime-observed consumers that reach it, and a `REACHABLE_UNOBSERVED` site names "
            "its cause with a closed reason; a site is never dropped"
        ),
        "partial_join": (
            "a partial join or a coverage gap is a residual, never a zero or a guess: a reachable "
            "site no run observes is `evidence_missing` per exposure class, a run family with no "
            "fingerprint is `join_evidence_missing`, and the sites outside the externally reachable "
            "set are `out_of_scope`"
        ),
        "sort_key": ("runs by instrument; sites by id; consumers by name; residuals by id; every list "
                     "sorted"),
    }


def _property_findings(d: dict) -> list:
    c = d["counts"]
    per_consumer = ", ".join(f"{n}={k}" for n, k in sorted(c["observed_by_consumer"].items()))
    by_class = ", ".join(f"{k}={v}" for k, v in sorted(c["reachable_unobserved_by_exposure"].items()))
    return [
        f"{c['sites_observed']} of {c['sites_reachable']} externally reachable compiler-derived "
        f"unsafe site(s) are observed by a Phase-24 downstream run across "
        f"{c['consumers_runtime_observed']} runtime-observed measured consumer(s) ({per_consumer}); "
        f"{c['sites_reachable_unobserved']} are externally reachable but observed by no downstream "
        f"run and are recorded as `evidence_missing` residuals ({by_class}), never zeroed",
        f"the unreduced universe is the live census's {c['unreduced_sites']} site(s), tied to 25.8's "
        f"post-reduction `sites_after`={c['reduction_sites_after']} and its "
        f"{c['reduction_eliminated']} ELIMINATED operation(s); {c['sites_not_reachable']} site(s) "
        f"are outside the externally reachable set and are `out_of_scope`, never read as observed",
        f"the runtime-functional atlas records {c['functional_candidate_runs']} functional candidate "
        f"run(s) and the p1000 ladder {c['drop_in_pass_families']} `DROP_IN_PASS` family(ies); "
        f"{c['fingerprinted_families']} of the {c['counted_families']} frozen families carry a "
        f"committed usage fingerprint, so a run family without one is a `join_evidence_missing` "
        f"residual rather than a site attribution",
        f"the coverage is a post-freeze measurement over the frozen population (holdout status "
        f"`{c['holdout']['status']}`: {c['holdout']['development']} development + "
        f"{c['holdout']['holdout']} holdout) and selects nothing by a holdout label",
        "a downstream observation is a bounded result over the workload it drove, not a coverage or "
        "memory-safety claim: a site observed by a passing run is exercised by that run's surface "
        "classes, never proven safe",
    ]


def build_body(census_body: dict, authority: dict) -> dict:
    """The coverage body: the rule, the instruments, the views, counts, residuals and findings."""
    d = derive_cached(census_body, authority)
    return {
        "rule": _rule(authority),
        "runs": d["runs"],
        "sites": d["sites"],
        "consumers": d["consumers"],
        "counts": d["counts"],
        "residuals": d["residuals"],
        "findings": _property_findings(d),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def crosswalk_findings(body: dict, census_body: dict, authority: dict) -> list:
    """Every way the committed coverage contradicts the census, the exposure or the Phase-24 evidence.

    Pure over `body`, the census and the authority (the 25.6 crosswalk, the 25.7 exposure, the 25.8
    reduction and the committed Phase-24 measurement): it is what the
    `MS-PHASE24-SAFETY-COVERAGE` court runs. It checks that the unreduced universe is the census tied
    to 25.8's post-reduction count; that every instrument is present with its run families; that a
    `covered_sites` claim names only externally reachable sites, carries a runtime-observed consumer
    and is exactly its derivation; that the uncovered sites are the rest of the reachable set; that
    the inverse site and consumer views reproduce from the forward maps; that the counts and the
    residuals equal their derivation; that every coverage gap is a residual; and that the rule names
    the committed authorities and the holdout discipline.
    """
    problems: list = []
    # A fresh measurement passes the views; the committed artefact is columnar, so decode through the
    # same codec the writer used.
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    d = derive_cached(census_body, authority)

    census_ids = [str(s["site_id"]) for s in (census_body.get("sites") or [])]
    census_set = set(census_ids)
    runs = body.get("runs") or {}
    sites = body.get("sites") or {}
    consumers = body.get("consumers") or {}

    # 1. The census site ids are unique.
    if len(census_set) != len(census_ids):
        problems.append("the census carries a duplicate site_id, so a coverage disposition is "
                        "ambiguous")

    # 2. The unreduced universe is tied to 25.8's post-reduction count.
    red_counts = (_body(authority["unsafe_reduction"]).get("counts") or {})
    if len(census_ids) != int(red_counts.get("sites_after") or -1):
        problems.append(
            f"the census carries {len(census_ids)} site(s), not 25.8's post-reduction "
            f"`sites_after`={red_counts.get('sites_after')}, so the universe is not the unreduced set"
        )
    if len(d["reachable_set"]) != int(red_counts.get("reachable_after") or -1):
        problems.append(
            f"the externally reachable set is {len(d['reachable_set'])} site(s), not 25.8's "
            f"`reachable_after`={red_counts.get('reachable_after')}"
        )

    # 3. Every derived instrument is present, and every present instrument is a derived one.
    for inst in sorted(set(INSTRUMENTS) - set(runs)):
        problems.append(f"the Phase-24 instrument {inst} has no coverage record (dropped)")
    for inst in sorted(set(runs) - set(INSTRUMENTS)):
        problems.append(f"the coverage records the instrument {inst}, which no Phase-24 plane drives")

    # 4. Each instrument's coverage is exactly its derivation, and a covered site carries evidence.
    derived_covered = {RUNTIME_INSTRUMENT: d["runtime_covered"],
                       P1000_INSTRUMENT: d["p1000_covered"]}
    for inst in sorted(set(INSTRUMENTS) & set(runs)):
        rec = runs[inst]
        covered = list(rec.get("covered_sites") or [])
        uncovered = list(rec.get("uncovered_sites") or [])
        if len(set(covered)) != len(covered):
            problems.append(f"{inst}: `covered_sites` carries a duplicate site")
        if len(set(uncovered)) != len(uncovered):
            problems.append(f"{inst}: `uncovered_sites` carries a duplicate site")
        for sid in sorted(set(covered) | set(uncovered)):
            if sid not in census_set:
                problems.append(f"{inst}: names {sid}, which is not a census site")
        if set(covered) & set(uncovered):
            problems.append(f"{inst}: `covered_sites` and `uncovered_sites` overlap")
        # A covered site must be externally reachable and carry a runtime-observed consumer.
        for sid in sorted(set(covered) - d["reachable_set"]):
            problems.append(f"{inst}: claims to cover {sid}, which is not externally reachable")
        for sid in sorted(sid for sid in covered if not (sites.get(sid) or {}).get("observed_by")):
            problems.append(f"{inst}: claims to cover {sid}, which carries no runtime-observed "
                            f"consumer")
        if sorted(set(covered)) != sorted(derived_covered[inst]):
            missing = sorted(derived_covered[inst] - set(covered))
            extra = sorted(set(covered) - derived_covered[inst])
            problems.append(
                f"{inst}: its covered sites are not the derived covered set "
                f"(missing {missing[:4]}, extra {extra[:4]})"
            )
        want_uncovered = sorted(d["reachable_set"] - derived_covered[inst])
        if sorted(set(uncovered)) != want_uncovered:
            problems.append(f"{inst}: its uncovered sites are not the externally reachable sites it "
                            f"does not cover")
        if rec.get("tool_state") != d["runs"][inst]["tool_state"]:
            problems.append(f"{inst}: the tool state {rec.get('tool_state')!r} is not the derived "
                            f"{d['runs'][inst]['tool_state']!r}")
        if rec.get("tool_state") not in schemas.TOOL_STATES:
            problems.append(f"{inst}: the tool state {rec.get('tool_state')!r} is not a tool state")
        if not rec.get("evidence"):
            problems.append(f"{inst}: names no Phase-24 downstream evidence")
        elif not any(e in rec.get("evidence") or []
                     for e in (USAGE_FINGERPRINTS_REL, RUNTIME_ATLAS_REL, P1000_RUN_REL)):
            problems.append(f"{inst}: names no committed Phase-24 downstream evidence")
        problems += [f"{inst}: schema: {p}" for p in schemas.validate("coverage", rec)]

    # 5. The inverse site view reproduces, and its state matches the observation.
    for sid in sorted(d["reachable_set"] - set(sites)):
        problems.append(f"the reachable census site {sid} has no coverage disposition (dropped)")
    for sid in sorted(set(sites) - d["reachable_set"]):
        problems.append(f"the coverage maps {sid}, which is not externally reachable")
    for sid in sorted(set(sites) & d["reachable_set"]):
        e = sites[sid]
        obs = sorted({str(n) for n in (e.get("observed_by") or [])})
        if e.get("state") not in STATES:
            problems.append(f"{sid}: the state {e.get('state')!r} is not a coverage disposition")
            continue
        if obs and e["state"] != "DOWNSTREAM_OBSERVED":
            problems.append(f"{sid}: names the runtime-observed consumer(s) {obs[:4]} but is not "
                            f"`DOWNSTREAM_OBSERVED`")
        if e["state"] == "DOWNSTREAM_OBSERVED" and not obs:
            problems.append(f"{sid}: is DOWNSTREAM_OBSERVED but names no runtime-observed consumer")
        if e["state"] == "REACHABLE_UNOBSERVED":
            if obs:
                problems.append(f"{sid}: is REACHABLE_UNOBSERVED but names the runtime-observed "
                                f"consumer(s) {obs[:4]}")
            if e.get("reason") not in UNOBSERVED_REASONS:
                problems.append(f"{sid}: REACHABLE_UNOBSERVED without a closed reason")

    # 6. The forward consumer view reproduces from the site view (the inverse of the inverse).
    xw_consumers = set((_body(authority["phase24_crosswalk"]).get("consumers") or {}))
    for name in sorted(xw_consumers - set(consumers)):
        problems.append(f"the measured consumer {name} has no coverage record (dropped)")
    for name in sorted(set(consumers) - xw_consumers):
        problems.append(f"the coverage records the consumer {name}, which 25.6 does not measure")
    for name in sorted(set(consumers) & xw_consumers):
        want = sorted(sid for sid in d["reachable_set"]
                      if name in ((sites.get(sid) or {}).get("observed_by") or []))
        got = sorted((consumers[name].get("sites") or []))
        if got != want:
            problems.append(f"{name}: the forward site list disagrees with the site view")

    # 7. Every coverage gap is a residual: each unobserved exposure class, each unjoined run set.
    residual_classes = {r.get("class") for r in (body.get("residuals") or [])}
    residual_exposure = {r.get("exposure_class") for r in (body.get("residuals") or [])
                         if r.get("class") == UNOBSERVED_RESIDUAL_CLASS}
    for cls in sorted(d["unobserved_by_class"]):
        if cls not in residual_exposure:
            problems.append(f"the reachable unobserved exposure class {cls} has no residual")
    if d["not_reachable_count"] and OUT_OF_SCOPE_RESIDUAL_CLASS not in residual_classes:
        problems.append("the census sites outside the externally reachable set have no residual")
    residual_instruments = {r.get("instrument") for r in (body.get("residuals") or [])
                            if r.get("class") == RUN_JOIN_RESIDUAL_CLASS}
    for inst in sorted(d["instrument_unjoined"]):
        if d["instrument_unjoined"][inst] and inst not in residual_instruments:
            problems.append(f"{inst}: run families without a fingerprint have no residual")

    # 8. Every plane equals its derivation.
    for key in ("runs", "sites", "consumers", "counts", "residuals"):
        if body.get(key) != d[key]:
            problems.append(f"the committed `{key}` is not the derived `{key}`")

    # 9. The rule names the committed authorities and the holdout discipline.
    rule = body.get("rule") or {}
    auth_paths = (rule.get("authority") or {}).get("paths") or []
    for want in (PHASE24_CROSSWALK_REL, EXPOSURE_REL, UNSAFE_REDUCTION_REL):
        if want not in auth_paths:
            problems.append(f"the mapping rule does not name the committed {want} as its authority")
    if (rule.get("reachability_authority") or {}).get("input") != EXPOSURE_REL:
        problems.append("the rule does not name the committed 25.7 exposure as its reachability "
                        "authority")
    if (rule.get("unreduced_authority") or {}).get("input") != UNSAFE_REDUCTION_REL:
        problems.append("the rule does not name the committed 25.8 reduction as its unreduced "
                        "authority")
    if not (rule.get("holdout_discipline") or {}).get("rule"):
        problems.append("the rule does not carry the frozen P1000 holdout discipline")

    # 10. Every residual validates against the residual schema.
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}"
                     for p in schemas.validate("residual", r)]

    return problems


def crosswalk_sensitivity_control(body: dict, census_body: dict, authority: dict) -> dict:
    """Seed six mutations and require each caught, with specificity holding.

    Each is a distinct way the coverage could lie: a site silently dropped from an instrument's
    covered set; a site claimed covered with no runtime evidence; the inverse consumer view
    disagreeing with the site view; a typed count; a coverage gap with no residual; and a tool state
    that is not the instrument's.
    """
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    baseline = crosswalk_findings(body, census_body, authority)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = crosswalk_findings(mutated, census_body, authority)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    def clone() -> dict:
        return json.loads(json.dumps(body))

    inst = RUNTIME_INSTRUMENT
    covered = sorted(body["runs"][inst]["covered_sites"])
    unobserved = sorted(sid for sid, e in body["sites"].items()
                        if e["state"] == "REACHABLE_UNOBSERVED")
    consumers = sorted(n for n, c in body["consumers"].items() if c["sites"])

    # m1: a site silently dropped from an instrument's covered set.
    def drop_site() -> dict:
        b = clone()
        b["runs"][inst]["covered_sites"].pop()
        return b

    m1 = check("site_dropped", drop_site(), "its covered sites are not the derived covered set")

    # m2: a site claimed covered with no runtime evidence.
    def covered_without_evidence() -> dict:
        b = clone()
        sid = unobserved[0]
        b["sites"][sid]["state"] = "DOWNSTREAM_OBSERVED"
        b["sites"][sid]["observed_by"] = []
        b["runs"][inst]["covered_sites"] = sorted(set(covered) | {sid})
        return b

    m2 = check("coverage_without_runtime_evidence", covered_without_evidence(),
               "carries no runtime-observed consumer")

    # m3: the forward consumer view disagreeing with the site view.
    def inverse_disagrees() -> dict:
        b = clone()
        b["consumers"][consumers[0]]["sites"] = sorted(
            set(b["consumers"][consumers[0]]["sites"]) | {unobserved[0]})
        return b

    m3 = check("inverse_view_disagrees", inverse_disagrees(),
               ": the forward site list disagrees with the site view")

    # m4: a typed count (a count not derived from the site map).
    def typed_count() -> dict:
        b = clone()
        b["counts"]["sites_observed"] += 1
        return b

    m4 = check("typed_count", typed_count(), "not the derived `counts`")

    # m5: a coverage gap with no residual (the unobserved exposure-class residuals removed).
    def residual_omitted() -> dict:
        b = clone()
        b["residuals"] = [r for r in b["residuals"]
                          if r.get("class") != UNOBSERVED_RESIDUAL_CLASS]
        return b

    m5 = check("residual_omitted", residual_omitted(),
               "reachable unobserved exposure class")

    # m6: a tool state that is not the instrument's (a typed verdict).
    def typed_verdict() -> dict:
        b = clone()
        b["runs"][inst]["tool_state"] = "NOT_REACHABLE"
        return b

    m6 = check("typed_tool_state", typed_verdict(), "is not the derived")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_authority() -> dict:
    """A tiny, self-consistent set of planes: two contracts, two run families, one unjoined run."""
    census = {"sites": [{"site_id": f"us-s{i}"} for i in range(1, 7)]}
    crosswalk = {"body": {
        "sites": {
            "us-s1": {"unit": "u1", "consumers": ["app"], "runtime_consumers": ["app"],
                      "state": "DOWNSTREAM_RUNTIME_OBSERVED"},
            "us-s2": {"unit": "u2", "consumers": ["app"], "runtime_consumers": ["app"],
                      "state": "DOWNSTREAM_RUNTIME_OBSERVED"},
            "us-s3": {"unit": "u3", "consumers": ["app"], "state": "DOWNSTREAM_IMPORT_OBSERVED"},
            "us-s4": {"unit": None, "consumers": [], "state": "NOT_OBSERVED"},
            "us-s5": {"unit": None, "consumers": [], "state": "NOT_OBSERVED"},
            "us-s6": {"unit": None, "consumers": [], "state": "NOT_OBSERVED"},
        },
        "consumers": {"app": {"family_id": "family:app", "cluster": "cluster:app",
                              "counted": True, "runtime_level": "L7-functional",
                              "runtime_observed": True}},
    }}
    exposure = {"body": {
        "sites": {
            "us-s1": {"e": "CLI_INPUT_REACHABLE", "r": "S1"},
            "us-s2": {"e": "CLI_INPUT_REACHABLE", "r": "S1"},
            "us-s3": {"e": "LOCAL_FILE_INPUT_REACHABLE", "r": "S2"},
            "us-s4": {"e": "UNKNOWN_REACHABILITY", "r": "SU"},
            "us-s5": {"e": "UNKNOWN_REACHABILITY", "r": "SU"},
            "us-s6": {"e": "UNKNOWN_REACHABILITY", "r": "SU"},
        },
    }}
    reduction = {"body": {
        "counts": {"sites_after": 6, "reachable_after": 3},
        "reconstruction": {"operations": {"by_class": {"ELIMINATED": 1,
                                                       "RELOCATED_TO_BOUNDARY": 1}}},
    }}
    fingerprints = {"body": {"fingerprints": [
        {"family_id": "family:app", "canonical_name": "app"},
    ]}}
    runtime = {"body": {
        "rule": {"levels": ["L5-loaded", "L6-runtime", "L7-functional"]},
        "runs": [
            {"subject": "candidate", "family_id": "family:app", "level": "L7-functional",
             "canonical_name": "app"},
            {"subject": "candidate", "family_id": "family:other", "level": "L7-functional",
             "canonical_name": "other"},
        ],
    }}
    p1000 = {"body": {"per_consumer_receipts": [
        {"family_id": "family:app", "canonical_name": "app", "result": "DROP_IN_PASS",
         "what_ran": {"level": "L7-functional"}},
        {"family_id": "family:other", "canonical_name": "other", "result": "DROP_IN_PASS",
         "what_ran": {"level": "L7-functional"}},
    ]}}
    family_freeze = {"body": {"p1000": [
        {"family_id": "family:app", "canonical_name": "app"},
        {"family_id": "family:other", "canonical_name": "other"},
    ]}}
    holdout = {"body": {"holdout_status": "opened",
                        "counts": {"development": 1, "holdout": 1}}}
    return {
        "census": census,
        "phase24_crosswalk": crosswalk,
        "exposure": exposure,
        "unsafe_reduction": reduction,
        "usage_fingerprints": fingerprints,
        "runtime": runtime,
        "p1000": p1000,
        "family_freeze": family_freeze,
        "holdout": holdout,
    }


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation is clean and the control is honest."""
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_phase24_safety_coverage.py", env={},
                                       dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_phase24_safety_coverage.py is not admitted as a metadata-only generator "
                        "on a host")

    census = _synth_authority()["census"]
    authority = _synth_authority()
    body = build_body(census, authority)
    baseline = crosswalk_findings(body, census, authority)
    if baseline:
        failures.append(f"the synthetic coverage body is not clean: {baseline[:4]}")
    c = body["counts"]
    if (c["sites_reachable"], c["sites_observed"], c["sites_reachable_unobserved"]) != (3, 2, 1):
        failures.append(f"the synthetic coverage counts are wrong: {c}")
    if c["sites_not_reachable"] != 3 or c["census_sites"] != 6:
        failures.append(f"the synthetic universe counts are wrong: {c}")
    if c["functional_candidate_runs"] != 2 or c["drop_in_pass_families"] != 2:
        failures.append(f"the synthetic run counts are wrong: {c}")
    # The synthetic must exercise both residual classes and the runtime instrument.
    classes = {r["class"] for r in body["residuals"]}
    if UNOBSERVED_RESIDUAL_CLASS not in classes or OUT_OF_SCOPE_RESIDUAL_CLASS not in classes \
            or RUN_JOIN_RESIDUAL_CLASS not in classes:
        failures.append(f"the synthetic residuals do not carry every class: {sorted(classes)}")
    if body["runs"][RUNTIME_INSTRUMENT]["uncovered_count"] != 1:
        failures.append("the synthetic runtime instrument does not leave one uncovered site")
    control = crosswalk_sensitivity_control(body, census, authority)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-phase24-safety-coverage] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-phase24-safety-coverage] self-test ok: the guard admits it as metadata-only; the "
          "synthetic coverage body is clean (3 reachable sites, 2 observed, 1 reachable-unobserved, "
          "3 out_of_scope, 2 run families with 1 unjoined, an `evidence_missing`, an `out_of_scope` "
          "and a `join_evidence_missing` residual); and all six seeded mutations (a dropped site, a "
          "coverage claim with no runtime evidence, an inverse view that disagrees, a typed count, a "
          "coverage gap with no residual and a typed tool state) are caught with specificity holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_planes(path: Path, doc: dict) -> None:
    """Write the plane compactly, key-sorted and deterministic.

    The plane carries hundreds of thousands of site rows, so pretty-printing would multiply the file
    without adding evidence; determinism is preserved (sorted keys, fixed separators).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-phase24-safety-coverage-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="phase24-crosswalk", path=PHASE24_CROSSWALK),
        InputRef(name="exposure-classification", path=EXPOSURE),
        InputRef(name="unsafe-reduction", path=UNSAFE_REDUCTION),
        InputRef(name="downstream-usage-fingerprints", path=USAGE_FINGERPRINTS),
        InputRef(name="downstream-runtime-functional-atlas", path=RUNTIME_ATLAS),
        InputRef(name="downstream-p1000-run", path=P1000_RUN),
        InputRef(name="downstream-family-freeze", path=FAMILY_FREEZE),
        InputRef(name="downstream-holdout", path=HOLDOUT),
    ]


def _measure() -> int:
    """Derive the coverage from the committed planes, and write it."""
    census_body = ms_census.decode_body(_load(CENSUS).get("body", {}))
    refs = ms_codec.refs_from_census(census_body)
    authority = load_authority()
    body = build_body(census_body, authority)
    problems = crosswalk_findings(body, census_body, authority)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    encoded = ms_codec.encode_body(body, refs)
    doc = envelope(kind="phase25-phase24-safety-coverage", authority=auth.id, inputs=_inputs(),
                   body=encoded, generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_planes(OUT, doc)

    c = body["counts"]
    print(f"[ms-phase24-safety-coverage] {c['sites_observed']} of {c['sites_reachable']} reachable "
          f"site(s) observed by a Phase-24 downstream run; {c['sites_reachable_unobserved']} "
          f"reachable but unobserved; {c['sites_not_reachable']} not reachable")
    print("  observed by consumer: "
          + ", ".join(f"{n}={k}" for n, k in sorted(c["observed_by_consumer"].items())))
    print(f"  unreduced universe: {c['unreduced_sites']} site(s) (25.8 sites_after="
          f"{c['reduction_sites_after']}); residuals: {len(body['residuals'])}")
    print(f"  -> {rel(OUT)} all_pass={not problems} (findings={len(body['findings'])})")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed coverage, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-phase24-safety-coverage] {rel(OUT)} is absent; run --measure")
        return 1
    census_body = ms_census.decode_body(_load(CENSUS).get("body", {}))
    body = _load(OUT).get("body", {})
    authority = load_authority()
    problems = crosswalk_findings(body, census_body, authority)
    if problems:
        print(f"[ms-phase24-safety-coverage] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = derive_cached(census_body, authority)["counts"]
    print(f"[ms-phase24-safety-coverage] check ok: {c['sites_observed']} observed, "
          f"{c['sites_reachable_unobserved']} reachable-unobserved, "
          f"{len(INSTRUMENTS)} instrument(s); every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/phase24-safety-coverage.json from the committed "
                         "inputs")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed coverage")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the metadata-only admission and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool executes nothing, so the manifest
    # lists it `metadata_only` and the guard admits it on any host.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return _check()
    # The default action is the derivation (and `--measure` names it): `evidence_determinism.py`
    # regenerates every generator with no flags and compares the bytes.
    return _measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
