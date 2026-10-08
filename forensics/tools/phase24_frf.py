#!/usr/bin/env python3
"""openssl-rs -- Phase 24.14 the FRF/Gemel chain closure.

`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` section 2's 24.14 row gives this subphase one
obligation: the FRF/Gemel chain closure, *where the stratum stages a declarable court, so a passing
atlas is not read as a chain that never ran*. Phase 24 owns no exported symbol, so its evidence is
not a set of differential probes over a symbol set -- it is a set of planes that each read committed
evidence and re-derive a verdict -- and the plan's own row for every Phase-24 court records
`frf_declarable: false` because no court stages an `artifacts/phase24/probes/<probe>.{authority,
candidate}` pair (D13, D201). The honest closure therefore has three parts, and this file is all
three.

Three kinds of evidence, and they are not interchangeable
---------------------------------------------------------
1. The **per-plane challenges**. The closest model is Phase 22.15's `phase22_frf.py`: it imports
   each plane module, drives that plane's own pure builder over the committed artefact and over a
   controlled mutation of the defect class the plane claims to detect, and records the observed
   delta rather than the phrase "a court exists". This file does the same for the thirteen Phase-24
   planes: for each it runs the plane's *own* pure checker -- its `*_findings` and its
   `*_sensitivity_control` -- over the committed artefact, and reports `DETECTED` when the honest
   artefact yields zero findings, specificity holds, and every mutation the plane's own control
   seeds is caught; `NOT_DETECTED` when a seeded mutation is missed (the most valuable finding in
   the stratum); and `NOT_DRIVEN` when the challenge cannot be constructed at all, which is never a
   pass. The per-mutation caught/not-caught map is the observed delta.

2. The **FRF chain staging, and why it is vacuous**. Phase 24's courts stage no probe pair, so no
   Phase-24 court can carry a `{fixture}`-driven declaration and `phase_state.py`'s
   `frf_gemel_blocking_reason(24)` is empty by its own scoping -- the stratum owes no `.frf`
   declaration, receipt, adjudicated challenge or `sensitivity-backed` claim, and no Gemel
   checkpoint. That is not the same as a chain that never ran: this file proves the *reason* from
   the two facts the rule keys on -- `gen_frf_courts.py` declares no Phase-24 court, and the tree
   holds no `artifacts/phase24/probes/` pair -- and it stages what stands in the place of a
   declarable court: the `RT-FRF-CLOSURE` harness challenge (a challenge over this closure itself,
   exactly as Phase 22.15's `RT-PHASE22-FRF` is), which fails if the classifier is a rubber stamp.

3. The **Gemel change/checkpoint as a deterministic projection**. Gemel's store is not committed
   (`docs/DECISIONS.md` D17), so what travels is the *projection* `forensics/GEMEL_TRAJECTORY.md`.
   This file records that projection's state -- the current checkpoint, whether it names the FRF
   chain and the stratum, the content hashes of the plan and the registry -- in the same form
   Phase 22.16's `gemel-checkpoint.json` uses: a committed, deterministic body whose every count is
   derived rather than typed. It never reads the store and never calls `gemel status`/`gemel index`.

The court `RT-FRF-CLOSURE` challenges this harness. It re-runs the classifier over a registered
challenge whose observed result is mutated in memory and requires `NOT_DETECTED` (a harness that
always answers `DETECTED` is a rubber stamp and the court fails on that check), and it seeds the
chain and the Gemel projection with in-memory mutations -- an injected Phase-24 declaration, an
injected probe pair, a stripped current checkpoint -- and requires each to be caught.

Output
------
    forensics/atlas/phase24/frf-closure.json

Determinism and the regeneration policy
---------------------------------------
Everything this file reads is a committed artefact: the thirteen committed Phase-24 planes, the
committed plan and FRF registry, the committed Gemel projection and the committed candidate install
(`artifacts/phase2/install`, which the frozen candidate identity reproduces from). It fetches
nothing, compiles nothing, links nothing and runs no downstream program, so it is a **pure
derivation** of committed evidence -- the same class as `downstream_freeze.py`,
`downstream_holdout.py`, `downstream_failures.py` and `downstream_reconciliation.py`. It is
therefore wired into `evidence_determinism.py`'s `GENERATORS`/`COMPARED` and declared
`metadata_only` in `forensics/downstream/container.json`, so it is admitted host-side in CI's static
job exactly as those four are (the guard's `require_admitted()` is still called first, so the
admission is the committed manifest's and not a special case in this file).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import re
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
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`. This tool only derives
# from committed artefacts, so the committed manifest lists it `metadata_only` and the guard admits
# it on any host (docs/REPRODUCIBILITY.md section 1, and the manifest's `metadata_only_rule`).
import phase24_guard  # noqa: E402

# The thirteen Phase-24 plane modules, imported so the closure drives *their* pure checkers rather
# than a second, drifting predicate. Each exposes `*_findings` and `*_sensitivity_control` over the
# committed artefact the plane's own court re-reads.
import downstream_build_link as bl  # noqa: E402
import downstream_candidate_freeze as cf  # noqa: E402
import downstream_census as census  # noqa: E402
import downstream_failures as pfail  # noqa: E402
import downstream_freeze as pfreeze  # noqa: E402
import downstream_high_value as phv  # noqa: E402
import downstream_holdout as phold  # noqa: E402
import downstream_hostility as phost  # noqa: E402
import downstream_p1000_run as pp1000  # noqa: E402
import downstream_reconciliation as prec  # noqa: E402
import downstream_runtime as prt  # noqa: E402
import downstream_sources as psrc  # noqa: E402
import downstream_universe as puni  # noqa: E402

# The FRF declaration registry (`D58`). It is the set of courts a `{fixture}`-driven declaration
# exists for, so it is the independent record of whether any Phase-24 court is declarable.
import gen_frf_courts  # noqa: E402

GENERATOR = "forensics/tools/phase24_frf.py"
ARTEFACT_REL = "forensics/atlas/phase24/frf-closure.json"
OUT = REPO_ROOT / ARTEFACT_REL
COURT = "RT-FRF-CLOSURE"
PHASE = 24

DETECTED = "DETECTED"
NOT_DETECTED = "NOT_DETECTED"
NOT_DRIVEN = "NOT_DRIVEN"

PLAN = REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"
REGISTRY = REPO_ROOT / "forensics" / "tools" / "gen_frf_courts.py"
GEMEL_TRAJECTORY = REPO_ROOT / "forensics" / "GEMEL_TRAJECTORY.md"
CONTAINER_MANIFEST = REPO_ROOT / "forensics" / "downstream" / "container.json"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"

DOWNSTREAM = REPO_ROOT / "forensics" / "downstream"
RANKING_SOURCES = DOWNSTREAM / "ranking-sources.json"
CANDIDATES = DOWNSTREAM / "candidates.json"
FAMILIES = DOWNSTREAM / "families.json"
AUTHORITY_BASELINES = DOWNSTREAM / "authority-baselines.jsonl"
USAGE_FINGERPRINTS = DOWNSTREAM / "usage-fingerprints.json"
FAMILY_FREEZE = DOWNSTREAM / "family-freeze.json"
HOLDOUT = DOWNSTREAM / "holdout.json"
BUILD_LINK_ATLAS = DOWNSTREAM / "build-link-atlas.json"
RUNTIME_FUNCTIONAL_ATLAS = DOWNSTREAM / "runtime-functional-atlas.json"
DOWNSTREAM_FAILURES = DOWNSTREAM / "failures.json"
HIGH_VALUE_TIER = DOWNSTREAM / "high-value-tier.json"
HOSTILITY_CORPUS = DOWNSTREAM / "hostility-corpus.json"
CANDIDATE_FREEZE = DOWNSTREAM / "candidate-freeze.json"
P1000_RUN = DOWNSTREAM / "p1000-run.json"
RECONCILIATION = DOWNSTREAM / "reconciliation.json"

WHAT_THIS_IS = (
    "Phase 24.14's FRF/Gemel closure: the per-plane FRF challenges (each Phase-24 plane's own pure "
    "checker driven over its committed artefact and over the controlled mutations its own "
    "sensitivity control seeds, with the caught/not-caught delta recorded), the FRF chain staging "
    "(why no Phase-24 court is declarable, and what stands in its place), and the Gemel checkpoint "
    "projection (the state of the committed forensics/GEMEL_TRAJECTORY.md, never the store). It is "
    "an instrument plus an observation record, not a claim that the stratum has a declarable court."
)

SORT_KEY = (
    "challenges by plane (numeric); mutations by name; counts numeric; chain.declared_courts and "
    "chain.probe_pairs sorted; gemel so the current checkpoint and the naming sets are derived from "
    "the committed projection; every list sorted"
)


class NotDriven(Exception):
    """The challenge for a plane could not be constructed from the committed evidence."""


# ---------------------------------------------------------------------------
# harness core -- one classification, used by the drivers and by the court
# ---------------------------------------------------------------------------

def classify_challenge(expected: dict, observed: dict) -> str:
    """The harness verdict: exactly the expected deltas, or the instrument is insensitive.

    Deliberately the smallest possible classifier so that the court can mutate a record's `observed`
    in memory and *prove* the harness reports a `NOT_DETECTED`. A harness that returned `DETECTED`
    for a mismatched observed value would pass every challenge and be no evidence at all.
    """
    if expected is None or observed is None:
        return NOT_DRIVEN
    return DETECTED if expected == observed else NOT_DETECTED


def _body(path: Path) -> dict:
    """A committed artefact's body, or `NotDriven` when it is absent."""
    if not path.is_file():
        raise NotDriven(f"artefact missing: {rel(path)}")
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def _drive(artefact: Path, findings_fn, control_fn) -> tuple[dict, dict, dict, dict]:
    """Drive a plane's own checker and its own sensitivity control over the committed artefact.

    The plane's `*_sensitivity_control` already seeds a controlled mutation per defect class and
    records a `caught_<name>` boolean for each; this driver turns that into the `expected`/`observed`
    pair the classifier compares, and carries the per-mutation delta beside it. A control that seeds
    no named mutation cannot be evidence, so it is `NOT_DRIVEN` rather than a vacuous pass.
    """
    if not artefact.is_file():
        raise NotDriven(f"artefact missing: {rel(artefact)}")
    base = findings_fn()
    control = control_fn()
    mutations = {k[len("caught_"):]: bool(v) for k, v in control.items()
                 if k.startswith("caught_")}
    seeded = len(mutations)
    if seeded == 0:
        raise NotDriven("the plane's sensitivity control seeds no named mutation")
    caught = sum(1 for v in mutations.values() if v)
    expected = {
        "baseline_findings": 0,
        "specificity_holds": True,
        "mutations_seeded": seeded,
        "mutations_caught": seeded,
        "honest": True,
    }
    observed = {
        "baseline_findings": len(base),
        "specificity_holds": bool(control.get("specificity_holds")),
        "mutations_seeded": seeded,
        "mutations_caught": caught,
        "honest": bool(control.get("honest")),
    }
    return expected, observed, control, mutations


# ---------------------------------------------------------------------------
# the thirteen in-memory drivers: one controlled mutation per plane's defect class
# ---------------------------------------------------------------------------

def drive_24_1() -> tuple[dict, dict, dict, dict]:
    """24.1 -- the ranking-source acquisition: strip a source's hash, mutate a payload, and more."""
    manifest = _body(RANKING_SOURCES)
    normalized = psrc.load_committed(manifest)
    return _drive(RANKING_SOURCES,
                  lambda: psrc.ranking_source_findings(manifest, normalized),
                  lambda: psrc.ranking_sensitivity_control(manifest, normalized))


def drive_24_2() -> tuple[dict, dict, dict, dict]:
    """24.2 -- the candidate universe: double-count an alias, promote a transitive, and more."""
    manifest = _body(RANKING_SOURCES)
    candidates_body = _body(CANDIDATES)
    families_body = _body(FAMILIES)
    return _drive(CANDIDATES,
                  lambda: puni.universe_findings(manifest, candidates_body, families_body),
                  lambda: puni.universe_sensitivity_control(manifest, candidates_body, families_body))


def drive_24_3() -> tuple[dict, dict, dict, dict]:
    """24.3 -- the authority census: a system-libssl linkage, a failure misclassified, and more."""
    families_body = _body(FAMILIES)
    rows = census._load_outcomes()
    body = census._load_fingerprints()
    return _drive(AUTHORITY_BASELINES,
                  lambda: census.census_findings(families_body, rows, body),
                  lambda: census.census_sensitivity_control(families_body, rows, body))


def drive_24_4() -> tuple[dict, dict, dict, dict]:
    """24.4 -- the P1000 freeze: reorder, delete, overlap, mutate the root, inject a candidate row."""
    families_body = _body(FAMILIES)
    freeze_body = _body(FAMILY_FREEZE)
    return _drive(FAMILY_FREEZE,
                  lambda: pfreeze.freeze_findings(families_body, freeze_body),
                  lambda: pfreeze.freeze_sensitivity_control(families_body, freeze_body))


def drive_24_5() -> tuple[dict, dict, dict, dict]:
    """24.5 -- the holdout partition: move a member, duplicate one, mutate the root, and more."""
    families_body = _body(FAMILIES)
    freeze_body = _body(FAMILY_FREEZE)
    holdout_body = _body(HOLDOUT)
    return _drive(HOLDOUT,
                  lambda: phold.holdout_findings(families_body, freeze_body, holdout_body),
                  lambda: phold.holdout_sensitivity_control(families_body, freeze_body,
                                                            holdout_body))


def drive_24_6() -> tuple[dict, dict, dict, dict]:
    """24.6 -- the build/link atlas: a linkage resolving the authority, a missing row, and more."""
    families_body = _body(FAMILIES)
    freeze_body = _body(FAMILY_FREEZE)
    atlas_body = bl._load_atlas()
    return _drive(BUILD_LINK_ATLAS,
                  lambda: bl.build_link_findings(families_body, freeze_body, atlas_body),
                  lambda: bl.build_link_sensitivity_control(families_body, freeze_body, atlas_body))


def drive_24_7() -> tuple[dict, dict, dict, dict]:
    """24.7 -- the runtime/functional atlas: an inflated baseline, a missing proof, and more."""
    families_body = _body(FAMILIES)
    freeze_body = _body(FAMILY_FREEZE)
    build_link_body = bl._load_atlas()
    atlas_body = prt._load_atlas()
    return _drive(RUNTIME_FUNCTIONAL_ATLAS,
                  lambda: prt.runtime_findings(families_body, freeze_body, build_link_body,
                                               atlas_body),
                  lambda: prt.runtime_sensitivity_control(families_body, freeze_body,
                                                          build_link_body, atlas_body))


def drive_24_8() -> tuple[dict, dict, dict, dict]:
    """24.8 -- the failures plane: a mislabeled candidate-specific, a missing fixture, and more."""
    freeze_body = _body(FAMILY_FREEZE)
    build_link_body = bl._load_atlas()
    runtime_body = prt._load_atlas()
    failures_body = pfail._load_json(DOWNSTREAM_FAILURES)
    return _drive(DOWNSTREAM_FAILURES,
                  lambda: pfail.failure_findings(freeze_body, build_link_body, runtime_body,
                                                 failures_body),
                  lambda: pfail.failure_sensitivity_control(freeze_body, build_link_body,
                                                           runtime_body, failures_body))


def drive_24_9() -> tuple[dict, dict, dict, dict]:
    """24.9 -- the high-value deep tier: a member dropped, a candidate-added family, and more."""
    fingerprints_body = _body(USAGE_FINGERPRINTS)
    runtime_body = prt._load_atlas()
    families_body = _body(FAMILIES)
    freeze_body = _body(FAMILY_FREEZE)
    tier_body = _body(HIGH_VALUE_TIER)
    return _drive(HIGH_VALUE_TIER,
                  lambda: phv.high_value_findings(fingerprints_body, runtime_body, families_body,
                                                  freeze_body, tier_body),
                  lambda: phv.high_value_sensitivity_control(fingerprints_body, runtime_body,
                                                             families_body, freeze_body, tier_body))


def drive_24_10() -> tuple[dict, dict, dict, dict]:
    """24.10 -- the hostility corpus: a member injected into the P1000, an unnormalised transcript."""
    inputs = phost.load_inputs()
    corpus_body = _body(HOSTILITY_CORPUS)
    return _drive(HOSTILITY_CORPUS,
                  lambda: phost.hostility_findings(inputs, corpus_body),
                  lambda: phost.hostility_sensitivity_control(inputs, corpus_body))


def drive_24_11() -> tuple[dict, dict, dict, dict]:
    """24.11 -- the candidate freeze: a swapped holdout member, a rewritten first_run, and more."""
    inputs = cf.load_inputs()
    body = _body(CANDIDATE_FREEZE)
    return _drive(CANDIDATE_FREEZE,
                  lambda: cf.candidate_freeze_findings(inputs, body),
                  lambda: cf.candidate_freeze_sensitivity_control(inputs, body))


def drive_24_12() -> tuple[dict, dict, dict, dict]:
    """24.12 -- the final P1000 run: a PASS without a baseline, a duplicate verdict, and more."""
    inputs = pp1000.load_inputs()
    body = _body(P1000_RUN)
    return _drive(P1000_RUN,
                  lambda: pp1000.p1000_findings(inputs, body),
                  lambda: pp1000.p1000_sensitivity_control(inputs, body))


def drive_24_13() -> tuple[dict, dict, dict, dict]:
    """24.13 -- the atlas reconciliation: a family without a verdict, an unknown residual, and more."""
    inputs = prec.load_inputs()
    body = _body(RECONCILIATION)
    return _drive(RECONCILIATION,
                  lambda: prec.reconciliation_findings(inputs, body),
                  lambda: prec.reconciliation_sensitivity_control(inputs, body))


# (plane, instrument, one-line defect class, driver, artefact the driver binds)
CHALLENGES: tuple[dict, ...] = (
    {"plane": "24.1", "instrument": "ranking-sources",
     "defect_class": ("a source whose raw or normalization digest is missing or whose committed "
                      "normalized bytes do not hash to it, an unavailable source counted present, "
                      "a missing retrieval timestamp"),
     "driver": drive_24_1, "artefact": rel(RANKING_SOURCES)},
    {"plane": "24.2", "instrument": "candidate-universe",
     "defect_class": ("a distro alias double-counted, a transitive consumer promoted to direct, a "
                      "fork counted independent with no evidence, a family with no provenance"),
     "driver": drive_24_2, "artefact": rel(CANDIDATES)},
    {"plane": "24.3", "instrument": "authority-census",
     "defect_class": ("an authority-linkage claim resolving a system library, an authority failure "
                      "counted as a candidate failure, a cohort member with no source hash, a "
                      "fingerprint with no imported symbols claimed as a pass"),
     "driver": drive_24_3, "artefact": rel(AUTHORITY_BASELINES)},
    {"plane": "24.4", "instrument": "family-freeze",
     "defect_class": ("two P1000 members reordered, a P1000 member deleted, a family shared with "
                      "the reserve, a mutated selection root, a fabricated candidate-subject run"),
     "driver": drive_24_4, "artefact": rel(FAMILY_FREEZE)},
    {"plane": "24.5", "instrument": "holdout-partition",
     "defect_class": ("a development family moved into the holdout, a holdout member deleted, a "
                      "family_id in both cohorts, a P1000-external family added, a mutated root"),
     "driver": drive_24_5, "artefact": rel(HOLDOUT)},
    {"plane": "24.6", "instrument": "build-link-atlas",
     "defect_class": ("a candidate L4 row resolving the authority, a missing authority row, a "
                      "positive patch count, a failed row with no residual, a system-libssl "
                      "linkage"),
     "driver": drive_24_6, "artefact": rel(BUILD_LINK_ATLAS)},
    {"plane": "24.7", "instrument": "runtime-functional-atlas",
     "defect_class": ("a candidate level above the authority baseline, a load proof missing, an "
                      "empty transcript, a missing authority runtime row, a normalisation that "
                      "erases a return code, a row above its build/link permit"),
     "driver": drive_24_7, "artefact": rel(RUNTIME_FUNCTIONAL_ATLAS)},
    {"plane": "24.8", "instrument": "failure-minimization",
     "defect_class": ("a candidate-specific label without an authority failure, a venue-limited "
                      "record with no authority failure, an unclassified or omitted leftover, a "
                      "missing minimized fixture, a fabricated fix commit"),
     "driver": drive_24_8, "artefact": rel(DOWNSTREAM_FAILURES)},
    {"plane": "24.9", "instrument": "high-value-tier",
     "defect_class": ("a tier member dropped, a family added by a candidate result, a candidate "
                      "level above the baseline, a load proof missing, an empty transcript, a "
                      "not-selected family with no reason"),
     "driver": drive_24_9, "artefact": rel(HIGH_VALUE_TIER)},
    {"plane": "24.10", "instrument": "hostility-augmentation",
     "defect_class": ("a hostility member injected into the P1000 counts, a member with no new "
                      "entity, a candidate row resolving the authority, a missing authority run, "
                      "an unnormalised transcript, a member beyond the bound"),
     "driver": drive_24_10, "artefact": rel(HOSTILITY_CORPUS)},
    {"plane": "24.11", "instrument": "candidate-freeze",
     "defect_class": ("a precommitted holdout member swapped for a development member, a mutated "
                      "partition root, a first_run rewritten after a rerun, a level above the "
                      "baseline, a holdout family cited as a fix source, a mutated count"),
     "driver": drive_24_11, "artefact": rel(CANDIDATE_FREEZE)},
    {"plane": "24.12", "instrument": "p1000-run",
     "defect_class": ("a PASS without an authority baseline, a PASS with a positive patch count, a "
                      "duplicated verdict, a level below the baseline marked PASS, a mismatched "
                      "candidate identity"),
     "driver": drive_24_12, "artefact": rel(P1000_RUN)},
    {"plane": "24.13", "instrument": "atlas-reconciliation",
     "defect_class": ("a counted family with no verdict, a residual left unknown, a failure dropped "
                      "from the summary, a hostility result mixed into the P1000 rate, a typed "
                      "rate, a failure not preserved"),
     "driver": drive_24_13, "artefact": rel(RECONCILIATION)},
)


def build_challenges() -> list[dict]:
    """One challenge record per Phase-24 plane, with the observed delta (never "a court exists")."""
    out: list[dict] = []
    for spec in CHALLENGES:
        record = {
            "plane": spec["plane"],
            "instrument": spec["instrument"],
            "defect_class": spec["defect_class"],
            "artefact": spec["artefact"],
            "expected": None,
            "observed": None,
            "mutations": {},
            "status": NOT_DRIVEN,
            "reason": None,
        }
        try:
            expected, observed, _control, mutations = spec["driver"]()
            record["expected"] = expected
            record["observed"] = observed
            record["mutations"] = mutations
            record["status"] = classify_challenge(expected, observed)
            if record["status"] == NOT_DETECTED:
                record["reason"] = ("the plane's own checker did not move as its own defect class "
                                    "requires")
        except NotDriven as exc:
            record["status"] = NOT_DRIVEN
            record["reason"] = str(exc)
        except Exception as exc:  # any failure to drive is NOT_DRIVEN, never a pass
            record["status"] = NOT_DRIVEN
            record["reason"] = f"{type(exc).__name__}: {exc}"
        out.append(record)
    return sorted(out, key=lambda r: [int(x) for x in r["plane"].split(".")])


def _counts(challenges: list[dict]) -> dict:
    return {
        "planes": len(challenges),
        "detected": sum(1 for c in challenges if c["status"] == DETECTED),
        "not_detected": sum(1 for c in challenges if c["status"] == NOT_DETECTED),
        "not_driven": sum(1 for c in challenges if c["status"] == NOT_DRIVEN),
    }


# ---------------------------------------------------------------------------
# the FRF chain staging -- why the stratum's chain entry is vacuous, and what stands in its place
# ---------------------------------------------------------------------------

def collect_chain_evidence() -> dict:
    """The two facts `frf_gemel_blocking_reason(24)` keys on, read from the committed tree.

    It reads the FRF declaration registry (`gen_frf_courts.py`) and the tree's
    `artifacts/phase24/probes/` directory rather than `artifacts/phase24/COURTS.json`, because the
    runner writes that result and the closure court is one of its rows -- binding it back would form
    a digest cycle neither artefact could reproduce.
    """
    rows = [{"court_id": str(cid), "phase": int(phase), "probe": str(probe)}
            for (cid, phase, probe, _desc) in gen_frf_courts.COURTS]
    probe_dir = REPO_ROOT / "artifacts" / "phase24" / "probes"
    pairs: list[str] = []
    if probe_dir.is_dir():
        pairs = sorted(p.stem for p in probe_dir.glob("*.authority")
                       if (probe_dir / (p.stem + ".candidate")).is_file())
    return {"frf_courts": rows, "probe_pairs": pairs}


def chain_findings(evidence: dict) -> list[str]:
    """Every way the stratum's chain entry would not be vacuous (i.e. it stages a declarable court)."""
    out: list[str] = []
    declared = sorted(r["court_id"] for r in evidence["frf_courts"] if int(r["phase"]) == PHASE)
    if declared:
        out.append(
            f"{len(declared)} Phase-24 court(s) are declared in gen_frf_courts.py "
            f"({', '.join(declared)}), so the stratum stages a declarable court and its FRF/Gemel "
            f"chain entry is not vacuous"
        )
    if evidence["probe_pairs"]:
        out.append(
            f"the tree stages {len(evidence['probe_pairs'])} artifacts/phase24/probes/"
            f"<probe>.{{authority,candidate}} pair(s) "
            f"({', '.join(evidence['probe_pairs'])}), so a Phase-24 court stages a probe"
        )
    return out


def chain_record(evidence: dict) -> dict:
    """The committed record of the chain staging, derived (not typed) from the evidence."""
    declared = sorted(r["court_id"] for r in evidence["frf_courts"] if int(r["phase"]) == PHASE)
    probes = list(evidence["probe_pairs"])
    return {
        "phase": PHASE,
        "registry": rel(REGISTRY),
        "declared_courts": declared,
        "probe_pairs": probes,
        "declarable_courts": declared,
        "vacuous": not declared and not probes,
        "reason": (
            "the stratum stages a declarable court only if a Phase-24 court is declared in "
            "gen_frf_courts.py and its artifacts/phase24/probes/<probe>.{authority,candidate} pair "
            "is staged. Neither holds: the registry declares no Phase-24 court and the tree holds no "
            "such pair, so every Phase-24 court reads committed evidence and carries no "
            "{fixture}-driven FRF declaration (D13, D201) and phase_state.py's "
            "frf_gemel_blocking_reason(24) is empty by its own scoping -- the stratum owes no .frf "
            "declaration, receipt, adjudicated challenge or sensitivity-backed claim, and no Gemel "
            "checkpoint"
        ),
        "stands_in_place": [
            "the RT-FRF-CLOSURE harness challenge: each Phase-24 plane's own pure checker is driven "
            "over its committed artefact and over the controlled mutations its own sensitivity "
            "control seeds, and the classifier is proved not a rubber stamp",
            "the Gemel checkpoint projection forensics/GEMEL_TRAJECTORY.md, which records the "
            "current checkpoint the release re-creates the store at",
        ],
    }


# ---------------------------------------------------------------------------
# the Gemel change/checkpoint -- a committed, deterministic projection (never the store)
# ---------------------------------------------------------------------------

_CHECKPOINT_RE = re.compile(r"^\* `(K\d+)` — `checkpoint\.[0-9a-f]+`$")


def collect_gemel_evidence() -> dict:
    """The committed Gemel projection's state, read from `forensics/GEMEL_TRAJECTORY.md`.

    The projection is what travels in Git (`docs/DECISIONS.md` D17); the store is not committed and
    this tool never opens it. The checkpoint shape is the same one `phase_state.py` reads, so the
    chain rule's checkpoint clause and this record agree.
    """
    if not GEMEL_TRAJECTORY.is_file():
        return {"path": rel(GEMEL_TRAJECTORY), "text": None, "current": None, "checkpoints": []}
    text = GEMEL_TRAJECTORY.read_text(encoding="utf-8")
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
    return {"path": rel(GEMEL_TRAJECTORY), "text": text, "current": current,
            "checkpoints": checkpoints}


def gemel_findings(evidence: dict) -> list[str]:
    """Every way the committed Gemel projection fails to carry a legible current checkpoint."""
    out: list[str] = []
    if not evidence.get("text"):
        out.append(f"{rel(GEMEL_TRAJECTORY)} is absent, so the Gemel projection cannot be read")
        return out
    if not evidence.get("current"):
        out.append(f"{rel(GEMEL_TRAJECTORY)} records no current checkpoint")
    if not evidence.get("checkpoints"):
        out.append(f"{rel(GEMEL_TRAJECTORY)} records no checkpoint")
    return out


def gemel_record(evidence: dict) -> dict:
    """The committed projection of the Gemel checkpoint state, derived (not typed)."""
    checkpoints = evidence.get("checkpoints") or []
    named_chain = sorted(n for n, s in checkpoints if "FRF chain" in s)
    named_phase = sorted(n for n, s in checkpoints if f"Phase {PHASE}" in s)
    current = evidence.get("current")
    return {
        "projection": rel(GEMEL_TRAJECTORY),
        "current": current,
        "checkpoint_count": len(checkpoints),
        "checkpoints_naming_frf_chain": named_chain,
        "checkpoints_naming_phase": named_phase,
        "checkpoint_owed": bool(chain_record(collect_chain_evidence())["declarable_courts"]),
        "identity": {
            "plan": {"path": rel(PLAN), "sha256": sha256_file(PLAN) if PLAN.is_file() else "unknown"},
            "registry": {"path": rel(REGISTRY),
                         "sha256": sha256_file(REGISTRY) if REGISTRY.is_file() else "unknown"},
            "checkpoint_state_hash": content_hash({"current": current, "checkpoints": checkpoints}),
        },
        "reason": (
            "the FRF/Gemel chain entry is vacuous (no Phase-24 court is declarable), so the stratum "
            "owes no Gemel change or checkpoint of its own; the release's current checkpoint in the "
            "committed projection is the boundary a later session resumes from, and this record "
            "binds it rather than reading the uncommitted store"
        ),
    }


# ---------------------------------------------------------------------------
# the evidence, and the findings/control the court re-runs
# ---------------------------------------------------------------------------

def collect_evidence() -> dict:
    """The live evidence the findings and the sensitivity control are pure over."""
    return {"chain": collect_chain_evidence(), "gemel": collect_gemel_evidence()}


def frf_closure_findings(body: dict, evidence: dict) -> list[str]:
    """Every way the committed closure fails its own subject -- the instrument findings.

    It re-runs the classifier over the recorded challenges (self-consistency), requires every plane
    to have detected its own defect class, re-derives the chain and Gemel records from the live
    committed evidence and requires the recorded ones to agree, and re-checks the Gemel projection.
    """
    out: list[str] = []
    challenges = body.get("challenges") or []
    counts = body.get("counts") or {}
    planes = [c.get("plane") for c in challenges]
    if len(set(planes)) != len(planes):
        out.append("the closure records a plane more than once")
    if counts.get("planes") != len(challenges):
        out.append("the closure's plane count does not equal its challenge records")
    for key, status in (("detected", DETECTED), ("not_detected", NOT_DETECTED),
                        ("not_driven", NOT_DRIVEN)):
        if counts.get(key) != sum(1 for c in challenges if c.get("status") == status):
            out.append(f"the closure's {key} count does not agree with its records")
    undetected = [c.get("plane") for c in challenges if c.get("status") != DETECTED]
    if undetected:
        out.append(
            f"{len(undetected)} Phase-24 plane checker(s) did not detect their own defect class: "
            f"{', '.join(str(p) for p in undetected)}"
        )
    for c in challenges:
        # Re-run the classifier over the recorded expected/observed, so a record whose status was
        # typed rather than derived is a finding.
        if c.get("status") is not None and classify_challenge(c.get("expected"), c.get("observed")) \
                != c.get("status"):
            out.append(f"{c.get('plane')}: the recorded status does not match its expected/observed "
                       f"classification")
    out += chain_findings(evidence["chain"])
    if body.get("chain") != chain_record(evidence["chain"]):
        out.append("the recorded chain staging does not reproduce from gen_frf_courts.py and the tree")
    out += gemel_findings(evidence["gemel"])
    if body.get("gemel") != gemel_record(evidence["gemel"]):
        out.append(f"the recorded Gemel checkpoint projection does not reproduce from "
                   f"{rel(GEMEL_TRAJECTORY)}")
    return out


def frf_closure_property(body: dict, evidence: dict) -> dict:
    """The property the subphase names, and the gaps the closure genuinely carries.

    A passing instrument is not the property. The property here -- "the stratum's FRF/Gemel chain
    ran" -- is exactly what the stratum cannot claim: no Phase-24 court is declarable, so the chain
    entry is vacuous. That gap is a finding, and the property reads `NOT_CLAIMED` while it is
    present, so a passing `RT-FRF-CLOSURE` can never be read as a chain that ran.
    """
    findings: list[str] = []
    chain = body.get("chain") or {}
    if chain.get("vacuous"):
        findings.append(
            "the stratum stages no declarable court: the registry declares no Phase-24 court and no "
            "artifacts/phase24/probes/<probe>.{authority,candidate} pair is staged, so by "
            "phase_state.py's frf_gemel_blocking_reason scoping the FRF/Gemel chain entry is vacuous "
            "and no .frf object or Gemel checkpoint is owed; the RT-FRF-CLOSURE harness challenge "
            "and the Gemel projection stand in its place, and a passing atlas is not a chain that "
            "ran"
        )
    undetected = [c.get("plane") for c in body.get("challenges") or []
                  if c.get("status") != DETECTED]
    if undetected:
        findings.append(
            f"{len(undetected)} Phase-24 plane checker(s) did not detect their own defect class: "
            f"{', '.join(str(p) for p in undetected)}"
        )
    gemel = body.get("gemel") or {}
    if not gemel.get("current"):
        findings.append(f"{rel(GEMEL_TRAJECTORY)} records no current checkpoint")
    return {
        "property_status": "NOT_CLAIMED" if findings else "not_claimed",
        "property_findings": findings,
    }


def frf_closure_sensitivity_control(body: dict, evidence: dict) -> dict:
    """Prove the harness and the chain staging can fail: seed mutations and require each caught.

    The honest closure must yield **zero** instrument findings (specificity), and each seeded
    mutation -- a registered challenge whose observed result is mutated in memory, a Phase-24 court
    injected into the FRF registry, a probe pair injected into the tree, a current checkpoint
    stripped from the Gemel projection, a checkpoint removed entirely, and a recorded challenge
    status flipped -- must be caught with a finding that names it.
    """
    base = frf_closure_findings(body, evidence)
    control: dict = {"baseline_findings": len(base), "specificity_holds": not base}
    honest = not base

    # 1. the harness classifier is not a rubber stamp.
    challenges = body.get("challenges") or []
    detected = [c for c in challenges if c.get("status") == DETECTED]
    sample = detected[0] if detected else (challenges[0] if challenges else None)
    if sample is not None and sample.get("observed"):
        mutated = copy.deepcopy(sample)
        key = sorted(mutated["observed"])[0]
        mutated["observed"][key] = mutated["observed"][key] + 1
        mutated_verdict = classify_challenge(mutated["expected"], mutated["observed"])
    else:
        mutated_verdict = classify_challenge({"x": 1}, {"x": 0})
    caught_mutated_observed = (mutated_verdict == NOT_DETECTED)
    control["injected_mutated_observed"] = sample.get("plane") if sample else None
    control["caught_mutated_observed"] = caught_mutated_observed

    # 2. a Phase-24 court injected into the FRF registry must be caught.
    inj = copy.deepcopy(evidence)
    inj["chain"]["frf_courts"] = list(inj["chain"]["frf_courts"]) + [
        {"court_id": "openssl-rs-rt-frf-closure", "phase": PHASE, "probe": "frf_closure_probe"}]
    caught_injected_declaration = any("declared in gen_frf_courts.py" in f
                                      for f in chain_findings(inj["chain"]))
    control["caught_injected_declaration"] = caught_injected_declaration

    # 3. a staged probe pair must be caught.
    inj = copy.deepcopy(evidence)
    inj["chain"]["probe_pairs"] = list(inj["chain"]["probe_pairs"]) + ["rt_frf_closure_probe"]
    caught_injected_probe = any("stages a probe" in f for f in chain_findings(inj["chain"]))
    control["caught_injected_probe"] = caught_injected_probe

    # 4. a stripped current checkpoint must be caught.
    inj = copy.deepcopy(evidence)
    inj["gemel"]["current"] = None
    caught_missing_checkpoint = any("no current checkpoint" in f
                                    for f in gemel_findings(inj["gemel"]))
    control["caught_missing_checkpoint"] = caught_missing_checkpoint

    # 5. a projection with no checkpoints at all must be caught.
    inj = copy.deepcopy(evidence)
    inj["gemel"]["checkpoints"] = []
    caught_missing_checkpoints = any("records no checkpoint" in f
                                     for f in gemel_findings(inj["gemel"]))
    control["caught_missing_checkpoints"] = caught_missing_checkpoints

    # 6. a recorded challenge status flipped must be caught by the self-consistency re-check.
    if challenges:
        flipped = copy.deepcopy(body)
        flipped["challenges"][0]["status"] = NOT_DETECTED
        caught_flipped_status = bool(frf_closure_findings(flipped, evidence))
    else:
        caught_flipped_status = False
    control["caught_flipped_status"] = caught_flipped_status

    honest = honest and all((caught_mutated_observed, caught_injected_declaration,
                             caught_injected_probe, caught_missing_checkpoint,
                             caught_missing_checkpoints, caught_flipped_status))
    control["honest"] = bool(honest)
    return control


# ---------------------------------------------------------------------------
# assembly
# ---------------------------------------------------------------------------

def assemble(authority: str) -> dict:
    """Assemble the whole closure body from committed evidence. Pure, no writes."""
    challenges = build_challenges()
    evidence = collect_evidence()
    body: dict = {
        "what_this_is": WHAT_THIS_IS,
        "sort_key": SORT_KEY,
        "challenges": challenges,
        "counts": _counts(challenges),
        "harness": {
            "classifier": "DETECTED iff expected == observed, NOT_DETECTED otherwise",
            "statuses": [DETECTED, NOT_DETECTED, NOT_DRIVEN],
            "court": ("RT-FRF-CLOSURE mutates a registered challenge's observed result in memory and "
                      "requires NOT_DETECTED, proving the classifier is not a rubber stamp"),
        },
        "chain": chain_record(evidence["chain"]),
        "gemel": gemel_record(evidence["gemel"]),
    }
    prop = frf_closure_property(body, evidence)
    body["property_status"] = prop["property_status"]
    body["property_findings"] = prop["property_findings"]
    return body


def _envelope_inputs() -> list[InputRef]:
    """Every committed artefact and tool the closure reads, content-addressed."""
    inputs: list[InputRef] = []
    seen: set[str] = set()

    def add(name: str, path: Path) -> None:
        if path.is_file() and rel(path) not in seen:
            seen.add(rel(path))
            inputs.append(InputRef(name=name, path=path))

    add("phase-24-plan", PLAN)
    add("frf-registry", REGISTRY)
    add("gemel-trajectory", GEMEL_TRAJECTORY)
    add("phase24-guard", GUARD)
    add("phase24-container-manifest", CONTAINER_MANIFEST)
    add("downstream-schemas", SCHEMAS)
    tools = {
        "downstream-sources": psrc, "downstream-universe": puni, "downstream-census": census,
        "downstream-freeze": pfreeze, "downstream-holdout": phold,
        "downstream-build-link": bl, "downstream-runtime": prt, "downstream-failures": pfail,
        "downstream-high-value": phv, "downstream-hostility": phost,
        "downstream-candidate-freeze": cf, "downstream-p1000-run": pp1000,
        "downstream-reconciliation": prec,
    }
    for name, module in tools.items():
        add(name, Path(str(module.__file__)))
    for name, path in (
        ("ranking-sources", RANKING_SOURCES), ("candidates", CANDIDATES), ("families", FAMILIES),
        ("authority-baselines", AUTHORITY_BASELINES), ("usage-fingerprints", USAGE_FINGERPRINTS),
        ("family-freeze", FAMILY_FREEZE), ("holdout", HOLDOUT), ("build-link-atlas", BUILD_LINK_ATLAS),
        ("runtime-functional-atlas", RUNTIME_FUNCTIONAL_ATLAS), ("failures", DOWNSTREAM_FAILURES),
        ("high-value-tier", HIGH_VALUE_TIER), ("hostility-corpus", HOSTILITY_CORPUS),
        ("candidate-freeze", CANDIDATE_FREEZE), ("p1000-run", P1000_RUN),
        ("reconciliation", RECONCILIATION),
    ):
        add(name, path)
    return inputs


def cmd_generate(authority: str) -> int:
    body = assemble(authority)
    evidence = collect_evidence()
    findings = frf_closure_findings(body, evidence)
    control = frf_closure_sensitivity_control(body, evidence)
    doc = envelope(kind="phase24-frf-closure", authority=authority, inputs=_envelope_inputs(),
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase24-frf] planes={c['planes']} detected={c['detected']} "
          f"not_detected={c['not_detected']} not_driven={c['not_driven']} "
          f"chain_vacuous={body['chain']['vacuous']} "
          f"gemel_current={body['gemel']['current']} -> {rel(OUT)}")
    for ch in body["challenges"]:
        caught = sum(1 for v in ch["mutations"].values() if v)
        print(f"  {ch['plane']:<6} {ch['instrument']:<26} {ch['status']:<12} "
              f"baseline={ch['observed']['baseline_findings'] if ch['observed'] else '?'} "
              f"mutations={caught}/{len(ch['mutations'])}"
              + (f"  reason={ch['reason']}" if ch["reason"] else ""))
    print(f"  chain: declared={len(body['chain']['declared_courts'])} "
          f"probes={len(body['chain']['probe_pairs'])} vacuous={body['chain']['vacuous']}")
    print(f"  gemel: current={body['gemel']['current']} "
          f"checkpoints={body['gemel']['checkpoint_count']} "
          f"chain_named={len(body['gemel']['checkpoints_naming_frf_chain'])} "
          f"owed={body['gemel']['checkpoint_owed']}")
    print(f"  property_status={body['property_status']} "
          f"property_findings={len(body['property_findings'])}")
    if findings:
        print(f"[phase24-frf] {len(findings)} instrument finding(s):")
        for f in findings:
            print(f"  - {f}")
    if not control["honest"]:
        print(f"[phase24-frf] the sensitivity control is not honest: {control}")
    return 0 if (not findings and control["honest"]) else 1


def cmd_check() -> int:
    if not OUT.is_file():
        print(f"[phase24-frf] {ARTEFACT_REL} is absent")
        return 1
    body = json.loads(OUT.read_text(encoding="utf-8"))["body"]
    evidence = collect_evidence()
    findings = frf_closure_findings(body, evidence)
    control = frf_closure_sensitivity_control(body, evidence)
    c = body.get("counts") or {}
    for f in findings:
        print(f"  finding: {f}")
    print(f"[phase24-frf] planes={c.get('planes')} detected={c.get('detected')} "
          f"chain_vacuous={(body.get('chain') or {}).get('vacuous')} "
          f"gemel_current={(body.get('gemel') or {}).get('current')} "
          f"findings={len(findings)} control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard admits this metadata-only tool, the artefact reproduces, and it can fail.

    A court that has never been seen to fail is not evidence, so this breaks the classifier in
    memory -- replace `classify_challenge` with one that always answers `DETECTED` -- and requires
    the sensitivity control to become dishonest. Restoring it must return the control to honest.
    """
    failures: list[str] = []

    # 1. The guard admits this tool as metadata-only on a host (it is declared in the manifest).
    res = phase24_guard.evaluate(env={}, dockerenv=False, entry_point="phase24_frf.py")
    if not res["admitted"] or res["venue"] != "metadata-only":
        failures.append(
            "the guard did not admit phase24_frf.py as a metadata-only generator, so a host "
            "invocation would be refused where CI's static job needs it"
        )

    # 2. The committed artefact reproduces with zero instrument findings and every plane detected.
    if not OUT.is_file():
        failures.append(f"{ARTEFACT_REL} is absent; run --measure")
        body: dict = {}
        evidence: dict = {}
    else:
        body = json.loads(OUT.read_text(encoding="utf-8"))["body"]
        evidence = collect_evidence()
        findings = frf_closure_findings(body, evidence)
        if findings:
            failures.append(f"the committed closure has findings: {findings[:3]}")
        control = frf_closure_sensitivity_control(body, evidence)
        if not control["honest"]:
            failures.append(f"the sensitivity control is not honest: {control}")
        undetected = [c["plane"] for c in body.get("challenges") or []
                      if c["status"] != DETECTED]
        if undetected:
            failures.append(f"the committed closure has undetected plane(s): {undetected}")
        chain = body.get("chain") or {}
        if not chain.get("vacuous"):
            failures.append("the committed closure does not record the chain entry as vacuous")
        if not (body.get("gemel") or {}).get("current"):
            failures.append("the committed closure records no current Gemel checkpoint")

    # 3. A rubber-stamp classifier must make the control dishonest (the harness can fail).
    if body:
        original = globals()["classify_challenge"]
        globals()["classify_challenge"] = lambda expected, observed: DETECTED
        try:
            broken = frf_closure_sensitivity_control(body, evidence)
        finally:
            globals()["classify_challenge"] = original
        if broken.get("honest"):
            failures.append("the sensitivity control PASSED with a rubber-stamp classifier")
        restored = frf_closure_sensitivity_control(body, evidence)
        if not restored.get("honest"):
            failures.append("the sensitivity control did not return to honest after restore")

    if failures:
        print("[phase24-frf] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[phase24-frf] self-test ok: the guard admits this tool as metadata-only on a host, the "
          "committed closure reproduces with every Phase-24 plane detecting its own defect class and "
          "the chain entry recorded vacuous, and a rubber-stamp classifier makes the sensitivity "
          "control dishonest")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--measure", action="store_true",
                    help="derive the closure from the committed planes and write it (default)")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed closure without regenerating")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the guard admits this metadata-only tool and the harness can fail")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool reads committed evidence and writes
    # one aggregate, so the committed manifest lists it `metadata_only` and the guard admits it on
    # any host; a host invocation of an execution entry point is still refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check()
    return cmd_generate(args.authority)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
