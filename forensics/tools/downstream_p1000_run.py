#!/usr/bin/env python3
"""openssl-rs — Phase-24.12 final full P1000 run: every family measured at the frozen candidate.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over the
frozen P1000 (`forensics/downstream/family-freeze.json`). 24.6 built and linked the population, 24.7
loaded and drove it, 24.8 classified/preserved/minimized the failures, 24.9 measured the deep tier
and 24.10 the separate hostility corpus, and 24.11 froze the candidate identity and ran the
precommitted holdout against it. This module is the **final full P1000 run**: the whole frozen
population is measured under both subjects **against the frozen candidate**, so every family's
drop-in verdict is measured against the same candidate rather than a moving one.

The frozen candidate is asserted, never re-frozen
--------------------------------------------------
The run must be against the candidate 24.11 content-addressed, so this module re-derives the live
candidate install's identity and refuses to run when it does not match the frozen
`forensics/downstream/candidate-freeze.json`. A mismatch is a **finding**, not a silent re-freeze:
the point of freezing a candidate is that the run that follows is measured against exactly it.

The run and the verdicts
------------------------
The run reuses 24.6's and 24.7's machinery -- the recipe catalogue, the specimen/variant
construction, the pristine-source acquisition, the build/link rows and the local runtime/functional
workloads are **imported, not re-implemented** -- so a family's level is the level the same
instrument would have measured. Every frozen P1000 family gets exactly one run row under each
subject; a family with no admitted recipe gets an honest `not_attempted` row with a reason rather
than being omitted. From those rows, the authority-applicable baseline, the linkage proof, the
candidate-specific patch count and the residual class, exactly one `drop_in_verdict` is **derived**
per counted family -- never typed. `DROP_IN_PASS` requires all five of the brief's section 20: the
same pristine source, a succeeded authority baseline that reached at least `L4-linked`, the candidate
reaching the authority-applicable level, candidate linkage proven, and zero candidate-specific
patches. A family whose authority baseline did not reach `L4-linked` is `DROP_IN_NOT_APPLICABLE` with
the reason -- not `DROP_IN_UNKNOWN`, and never a pass.

The result is a ladder, never one percentage
---------------------------------------------
The brief's section 52: the population is reported as a ladder -- per-level family counts
(configured, built, linked, loaded, runtime, functional) and the verdict histogram -- with the raw
family count visible, so a single rate cannot hide where the population actually stands. `UNKNOWN`
is 0: every family is measured, and a family this venue cannot pose the drop-in question for is an
honest non-applicability, not an unknown (the brief's section 55).

Per-consumer auditability
-------------------------
The brief's section 71: every family carries a receipt naming **why it was selected** (its frozen
ranking signal), **which source** was used, whether it **passed against the authority** (the
authority-applicable baseline it reached), **which candidate libraries loaded**, **what surface it
used**, **what ran**, its **result** and its **residual** -- so a reader can audit any one family
without reconstructing the run.

Nothing here is a security proof, and the batch is honest about its venue
------------------------------------------------------------------------
A result over a selected population is a measurement of **that population**, not of all downstream
software, and a **venue-limited** family -- one with no admitted recipe or workload in this venue --
is neither a pass nor a fail. The ladder is over a selected population of 1,000 families, not a
percentage of all downstream software.

This tool fetches, compiles and runs real downstream releases, so `phase24_guard.require_admitted()`
is the first statement of `main` and a host invocation is refused (`docs/REPRODUCIBILITY.md`
section 1).

Why this artefact is not in `evidence_determinism.py`'s `GENERATORS` or `COMPARED`
----------------------------------------------------------------------------------
It is **measurement**, not a pure function of committed inputs: it fetches, compiles and drives real
downstream releases inside the court container against the frozen candidate, so the level a run
reaches and its normalised transcript are a function of the court's toolchain and of the network, not
of committed inputs -- the same precedent as 24.6's build/link atlas, 24.7's runtime/functional
atlas, 24.9's high-value tier, 24.10's hostility corpus, 24.11's candidate freeze and the Phase-17
measured corpus. Regenerating it needs a compiler, a prefix and the network, none of which a host CI
runner has, and the Docker-only guard refuses a host invocation before it builds anything. The court
`RT-P1000-RUN` re-runs only this module's **pure** functions over the committed artefact and never
rebuilds.

Outputs
-------
  forensics/downstream/p1000-run.json   the final full P1000 run and the derived drop-in verdicts

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
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
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool fetches,
# compiles and runs, so it is an execution entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The record schemas the rows are validated against, imported rather than restated so the vocabulary
# cannot drift from the module the court checks it with.
import downstream_schemas  # noqa: E402

# The 24.3 census primitives (fetch/extract/run/ELF inspection/resource limits) are reused through
# 24.6/24.7, which re-export none of them themselves: importing both keeps one code path.
import downstream_census as census  # noqa: E402

# The 24.6 build/link atlas: its recipe catalogue, its specimen/variant/run construction, its
# source-root hash and its `measure_family` orchestration are **imported and reused**, so the run
# builds exactly the build the atlas built (the brief's "no divergent predicate").
import downstream_build_link as bl  # noqa: E402

# The 24.7 runtime/functional atlas: its workload helpers, its load proof, its normaliser and its
# `run` construction are imported and reused, so a P1000 run is the exact workload machinery 24.7
# measured with.
import downstream_runtime as rt  # noqa: E402

# The 24.11 candidate freeze: its `candidate_identity` (and `identity_content`, the reproducible
# install identity that excludes the recorded provenance) and its baseline-normalized
# `derive_verdict_for` are imported, so the final run's identity and drop-in rule cannot drift from
# the freeze they must match.
import downstream_candidate_freeze as cf  # noqa: E402

# The stratum's four non-claims, imported from 24.4 so the run and the population cannot drift.
from downstream_freeze import NON_CLAIMS as STRATUM_NON_CLAIMS  # noqa: E402

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
HOLDOUT = REPO_ROOT / "forensics" / "downstream" / "holdout.json"
CANDIDATE_FREEZE = REPO_ROOT / "forensics" / "downstream" / "candidate-freeze.json"
CONTAINER_MANIFEST = REPO_ROOT / "forensics" / "downstream" / "container.json"
OUT = REPO_ROOT / "forensics" / "downstream" / "p1000-run.json"

CANDIDATE_PREFIX = bl.CANDIDATE_PREFIX

GENERATOR = "forensics/tools/downstream_p1000_run.py"
PARSER_VERSION = "downstream-p1000-run/1"

L0 = "L0-catalogued"
L1 = "L1-admitted-source"
L2 = "L2-configured"
L3 = "L3-built"
L4 = "L4-linked"
L5 = "L5-loaded"
L6 = "L6-runtime"
L7 = "L7-functional"
L8 = "L8-authority-equivalent"
RANK = downstream_schemas.EXECUTION_LEVEL_RANK

SUBJECTS = ("authority", "candidate")

# The ladder's monitored rungs, in order: the run reports how many of the frozen families reached
# each, never a single percentage.
LADDER_RUNGS = (L2, L3, L4, L5, L6, L7)

NO_RECIPE_REASON = (
    "no admitted pristine-source build recipe is recorded for this family in this venue, so the run "
    "does not manufacture a source URL; the family is venue-limited and its verdict is "
    "DROP_IN_NOT_APPLICABLE with this reason"
)

# The stratum's four non-claims (imported from 24.4 so the two cannot drift) plus the one this
# subphase's measurement adds: the ladder is over a selected population, not all downstream software.
NON_CLAIMS: list[str] = list(STRATUM_NON_CLAIMS) + [
    "the ladder is over a selected population of 1,000 families, not a percentage of all downstream "
    "software",
]


# ---------------------------------------------------------------------------------------------------
# the frozen rule: the population, the subjects, the baseline-normalized verdict and the ladder.
# Recorded verbatim in the artefact and re-derived by the court.
# ---------------------------------------------------------------------------------------------------

RULE: dict = {
    "id": "downstream-p1000-run/1",
    "name": "the final full P1000 run at the frozen candidate",
    "population": (
        "the counted population is the frozen P1000 forensics/downstream/family-freeze.json: a "
        "selected population of 1,000 downstream project families frozen before any candidate "
        "result, whose holdout is the precommitted 24.5 partition. The run is measured against the "
        "candidate 24.11 content-addressed, so a family's verdict is against the same candidate"
    ),
    "subjects": list(SUBJECTS),
    "levels": list(LADDER_RUNGS),
    "verdict": (
        "exactly one drop_in_verdict per counted family, purely derived from the run rows, the "
        "authority-applicable baseline, the linkage proof, the candidate-specific patch count and "
        "the residual class -- never typed. DROP_IN_PASS requires all five of the brief's section "
        "20: the same pristine source, a succeeded authority baseline that reached at least "
        "L4-linked, the candidate reaching the authority-applicable level, candidate linkage proven "
        "and zero candidate-specific patches. A family whose authority baseline did not reach "
        "L4-linked is DROP_IN_NOT_APPLICABLE with the reason, never DROP_IN_UNKNOWN and never a pass"
    ),
    "ladder": (
        "the result is a ladder, never one percentage (the brief's section 52): per-level family "
        "counts over the frozen population (configured, built, linked, loaded, runtime, functional) "
        "and the verdict histogram, with the raw family count visible. UNKNOWN is 0: every family is "
        "measured, and a family this venue cannot pose the drop-in question for is an honest "
        "non-applicability, not an unknown"
    ),
    "baseline_normalization": (
        "a family's authority-applicable baseline is the highest level its authority runs reached; "
        "the candidate is judged against what the authority itself achieved, never a higher "
        "aspirational level"
    ),
    "accounting": (
        "every frozen P1000 family has exactly one run row under each subject: a family with no "
        "admitted recipe reads not_attempted with a reason rather than being omitted, and its "
        "verdict is DROP_IN_NOT_APPLICABLE"
    ),
    "per_consumer_receipts": (
        "every family carries a receipt naming why it was selected, which source was used, whether "
        "it passed against the authority, which candidate libraries loaded, what surface it used, "
        "what ran, its result and its residual, so any one family can be audited on its own"
    ),
    "confinement": (
        "each fetch, build and run runs inside the admitted court container under its cgroup caps and "
        "this tool's own wall-clock bounds; scratch is under /work/court and removed afterwards"
    ),
    "constants": {"make_jobs": census.MAKE_JOBS, "step_timeout_seconds": census.STEP_TIMEOUT,
                  "fetch_timeout_seconds": census.FETCH_TIMEOUT,
                  "launch_timeout_seconds": census.LAUNCH_TIMEOUT},
}


# ---------------------------------------------------------------------------------------------------
# the full P1000 run (the same machinery 24.6/24.7 use, over the whole frozen population)
# ---------------------------------------------------------------------------------------------------

def measure_p1000(p1000: list[dict], authority_id: str) -> dict:
    """Run the frozen P1000 under both subjects and return the run rows, specimens and variants.

    A family with an admitted recipe is acquired once and built against both subjects with 24.6's
    exact intent; when the build linked and an admitted runtime intent exists, 24.7's workload is
    driven. A family that built/linked but has no admitted runtime workload records the build/link
    level it reached (so the ladder's configured/built/linked rungs are real), and a family with no
    recipe records an honest `not_attempted` row under each subject.
    """
    auth_prefix = resolve_authority(authority_id).prefix
    if not (CANDIDATE_PREFIX / "lib" / "libssl.so.3").is_file():
        raise SystemExit(f"[downstream-p1000-run] the candidate install prefix "
                         f"{rel(CANDIDATE_PREFIX)} holds no lib/libssl.so.3")
    limits = census.resource_limits()
    auth_defined = census.authority_defined_symbols(auth_prefix)
    cand_defined = census.authority_defined_symbols(CANDIDATE_PREFIX)

    rows: list[dict] = []
    specimens: dict[str, dict] = {}
    variants: dict[str, dict] = {}
    started = time.monotonic()
    try:
        for entry in p1000:
            name = str(entry.get("canonical_name"))
            fam = {
                "family_id": entry.get("family_id"),
                "canonical_name": name,
                "openssl_linkage": entry.get("openssl_linkage"),
                "directness_class": entry.get("directness_class"),
                "_rank": entry.get("p1000_rank"),
            }
            recipe = bl._RECIPE_BY_FAMILY.get(name)
            if recipe is None:
                for subject in SUBJECTS:
                    rows.append(rt._not_attempted(
                        fam, subject, level=L0, failure_class="acquire-failure",
                        residual="unavailable", reason=NO_RECIPE_REASON, recipe=None,
                        specimen_id=None, variant_id=None, source_sha256=None, limits=limits,
                        prefix=auth_prefix))
                continue

            # The exact build intent 24.6/24.7 used: the pristine source acquired once and built
            # against both subjects with the single {prefix} substitution.
            bl_rows, specimen, variant = bl.measure_family(
                fam, recipe, auth_prefix, CANDIDATE_PREFIX, auth_defined, cand_defined, limits)
            if specimen:
                specimens[specimen["specimen_id"]] = specimen
            if variant:
                variants[variant["variant_id"]] = variant
            bl_by_subject = {str(r.get("subject")): r for r in bl_rows}
            source_sha = next((r.get("source_sha256") for r in bl_rows if r.get("source_sha256")),
                              None)
            root_hash = next((r.get("source_root_hash") for r in bl_rows
                              if r.get("source_root_hash")), None)
            spec_id = f"specimen:{name}:{recipe['version']}"
            variant_id = f"variant:{name}:{recipe['version']}:pristine"

            for subject in SUBJECTS:
                blrow = bl_by_subject.get(subject) or {}
                prefix = auth_prefix if subject == "authority" else CANDIDATE_PREFIX
                if name in rt.PROGRAMS and RANK.get(str(blrow.get("level")), -1) >= RANK[L4]:
                    root = census._single_source_root(bl.SCRATCH / name / subject / "src")
                    if root is None:
                        rows.append(rt._not_attempted(
                            fam, subject, level=L4, failure_class="load-failure",
                            residual="runtime-failure",
                            reason="the run produced no source tree to load from", recipe=recipe,
                            specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha,
                            limits=limits, prefix=auth_prefix))
                    else:
                        rows.append(rt._measure_subject_runtime(
                            fam, recipe, subject, prefix, auth_prefix, root, source_sha, root_hash,
                            limits))
                else:
                    # No admitted runtime workload (or the build did not link): the deepest evidence
                    # this run has is the build/link row itself, recorded verbatim rather than
                    # flattened to a lower level.
                    rows.append(dict(blrow))
                last = rows[-1]
                print(f"  [p1000 {entry.get('p1000_rank'):>4}] {name:<12} {subject:<9} "
                      f"{last.get('level'):<16} {str(last.get('reason') or '')[:60]}"[:150],
                      flush=True)
    finally:
        census._cleanup(bl.SCRATCH)
        census._cleanup(rt.SCRATCH)

    for row in rows:
        row["run_id"] = f"run:p1000:{row.get('subject')}:{row.get('canonical_name')}"
        row["p1000_run"] = True
        ev = list(row.get("evidence") or [])
        row["evidence"] = ev + ["p1000"]
    rt._apply_baseline(rows)
    rows.sort(key=lambda r: (str(r.get("family_id")), str(r.get("subject"))))
    return {"runs": rows,
            "specimens": sorted(specimens.values(), key=lambda s: str(s["specimen_id"])),
            "variants": sorted(variants.values(), key=lambda v: str(v["variant_id"])),
            "limits": limits, "elapsed_seconds": round(time.monotonic() - started, 3),
            "authority_prefix": rel(auth_prefix)}


# ---------------------------------------------------------------------------------------------------
# the derived drop-in verdicts, the ladder and the receipts (pure over the run rows)
# ---------------------------------------------------------------------------------------------------

def _verdict_reason(base: str, cand_row: dict, verdict: str) -> str | None:
    """The reason a verdict carries: the failing row's own reason, or the baseline's, never typed."""
    if verdict == "DROP_IN_PASS":
        return None
    reason = str((cand_row or {}).get("reason") or "")
    if reason:
        return reason
    if RANK.get(base, -1) < RANK[L4]:
        return (f"the authority-applicable baseline reached {base}, below L4-linked, so the drop-in "
                f"question is not posed for this family in this venue")
    return (f"the candidate reached {(cand_row or {}).get('level')!r} against the "
            f"authority-applicable baseline {base!r}; no positive drop-in evidence is recorded")


def derive_verdicts(p1000: list[dict], rows: list[dict]) -> list[dict]:
    """Exactly one schema-valid `drop_in_verdict` per counted family, purely derived from the rows."""
    baseline = cf._baseline_map(rows)
    cand = {str(r.get("family_id")): r for r in rows if r.get("subject") == "candidate"}
    out: list[dict] = []
    for entry in p1000:
        fid = str(entry.get("family_id"))
        name = str(entry.get("canonical_name"))
        c = cand.get(fid) or {}
        base = baseline.get(fid, L0)
        verdict = cf.derive_verdict_for(base, c)
        spec_id = str(c.get("specimen_id") or f"specimen:absent:{fid}")
        variant_id = str(c.get("variant_id") or f"variant:absent:{fid}:pristine")
        out.append({
            "verdict_id": f"verdict:p1000:{name}",
            "family_id": fid,
            "canonical_name": name,
            "p1000_rank": entry.get("p1000_rank"),
            "specimen_id": spec_id,
            "variant_id": variant_id,
            "verdict": verdict,
            "pristine_source_id": spec_id,
            "authority_baseline": base,
            "authority_applicable_level": base,
            "candidate_level": str(c.get("level") or L0),
            "linkage_proven": bool(c.get("linkage_proven")),
            "candidate_specific_patch_count": int(c.get("candidate_specific_patch_count") or 0),
            "residual_class": c.get("residual_class"),
            "reason": _verdict_reason(base, c, verdict),
            "evidence": [f"family:{fid}", f"run_id:{c.get('run_id')}", f"baseline:{base}",
                         f"population:{rel(FAMILY_FREEZE)}"],
        })
    out.sort(key=lambda v: str(v["verdict_id"]))
    return out


def _verdict_histogram(verdicts: list[dict]) -> dict[str, int]:
    out = {v: 0 for v in downstream_schemas.DROP_IN_VERDICTS}
    for rec in verdicts:
        v = str(rec.get("verdict"))
        out[v] = out.get(v, 0) + 1
    return out


def derive_ladder(p1000: list[dict], rows: list[dict], verdicts: list[dict]) -> dict:
    """The brief's section 52 ladder: per-level counts and the verdict histogram, never a rate."""
    cand_rows = [r for r in rows if r.get("subject") == "candidate"]
    baseline = cf._baseline_map(rows)
    measurable = sum(1 for e in p1000
                     if RANK.get(baseline.get(str(e.get("family_id")), L0), -1) >= RANK[L4])
    return {
        "population": "the frozen P1000",
        "families": len(p1000),
        "measurable_families": measurable,
        "not_applicable_families": len(p1000) - measurable,
        "levels": {
            rung: sum(1 for r in cand_rows if RANK.get(str(r.get("level")), -1) >= RANK[rung])
            for rung in LADDER_RUNGS
        },
        "verdicts": _verdict_histogram(verdicts),
    }


def derive_counts(p1000: list[dict], rows: list[dict], verdicts: list[dict], ladder: dict) -> dict:
    """Every count, computed from the rows, the verdicts and the ladder -- never typed."""
    baseline = cf._baseline_map(rows)
    cand = {str(r.get("family_id")): r for r in rows if r.get("subject") == "candidate"}
    measurable = [str(e.get("family_id")) for e in p1000
                  if RANK.get(baseline.get(str(e.get("family_id")), L0), -1) >= RANK[L4]]
    recipe_families = {r["family"] for r in bl.RECIPES}
    reaches = sum(
        1 for fid in measurable
        if RANK.get(str((cand.get(fid) or {}).get("level")), -1) >= RANK.get(baseline.get(fid, L0), -1)
    )
    return {
        "families": len(p1000),
        "rows": len(rows),
        "recipe_backed_families": sum(1 for e in p1000
                                      if str(e.get("canonical_name")) in recipe_families),
        "measurable_families": len(measurable),
        "not_applicable_families": len(p1000) - len(measurable),
        "measurable_reaches_baseline": reaches,
        "candidate_specific_patch_count": sum(
            int(r.get("candidate_specific_patch_count") or 0) for r in rows),
        "verdicts": _verdict_histogram(verdicts),
    }


def _loaded_sonames(row: dict) -> list[dict]:
    """The OpenSSL sonames the candidate loaded/resolved, from the runtime proof or the link proof."""
    proof = row.get("load_proof") or {}
    sonames = proof.get("sonames") or {}
    if not sonames:
        sonames = (row.get("link") or row.get("linkage") or {}).get("sonames") or {}
    out = []
    for soname, entry in sorted(sonames.items()):
        resolved = entry.get("resolved") if isinstance(entry, dict) else entry
        out.append({"soname": soname, "resolved": resolved})
    return out


def derive_receipts(p1000: list[dict], rows: list[dict], verdicts: list[dict]) -> list[dict]:
    """The brief's section 71 per-consumer receipts: one per counted family, from the run rows."""
    cand = {str(r.get("family_id")): r for r in rows if r.get("subject") == "candidate"}
    vmap = {str(v.get("family_id")): v for v in verdicts}
    out: list[dict] = []
    for entry in p1000:
        fid = str(entry.get("family_id"))
        name = str(entry.get("canonical_name"))
        c = cand.get(fid) or {}
        v = vmap.get(fid) or {}
        out.append({
            "family_id": fid,
            "canonical_name": name,
            "p1000_rank": entry.get("p1000_rank"),
            "openssl_linkage": entry.get("openssl_linkage"),
            "why_selected": {
                "family_role": entry.get("family_role"),
                "selection_status": entry.get("selection_status"),
                "source_breadth": entry.get("source_breadth"),
                "distro_breadth": entry.get("distro_breadth"),
                "popularity": entry.get("popularity"),
            },
            "which_source": {
                "recipe_id": c.get("recipe_id"),
                "source_url": c.get("source_url"),
                "source_sha256": c.get("source_sha256"),
                "specimen_id": c.get("specimen_id"),
            },
            "passed_against_the_authority": {
                "authority_applicable_level": c.get("authority_applicable_level"),
                "reaches_baseline": bool(c.get("reaches_baseline")),
            },
            "candidate_libs_loaded": _loaded_sonames(c),
            "surface_used": c.get("workload") or (c.get("linkage") or {}).get("artifact_rel")
            or c.get("program"),
            "what_ran": {
                "level": c.get("level"),
                "outcome": c.get("outcome"),
                "transcript_sha256": c.get("transcript_sha256") or "",
            },
            "result": v.get("verdict"),
            "residual": c.get("residual_class"),
        })
    out.sort(key=lambda r: (int(r["p1000_rank"]) if r.get("p1000_rank") is not None else 10 ** 9,
                            str(r["family_id"])))
    return out


# ---------------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefact (pure; never rebuilding)
# ---------------------------------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def load_inputs() -> dict:
    """Every committed input the derivation and the court re-read."""
    return {
        "family_freeze": _load_json(FAMILY_FREEZE),
        "candidate_freeze": _load_json(CANDIDATE_FREEZE),
        "holdout": _load_json(HOLDOUT),
    }


def p1000_findings(inputs: dict, body: dict) -> list[str]:
    """Every way the recorded final P1000 run fails its own subject.

    Pure over the committed frozen P1000, the committed 24.11 candidate freeze and the run rows the
    artefact carries, so the court re-runs it without rebuilding. Every check is a re-derivation:
    the candidate identity equals 24.11's (excluding the recorded provenance); there is exactly one
    verdict per counted family, with none missing, extra or fabricated; a `DROP_IN_PASS` is refused
    without all five of the brief's section 20 conditions; `DROP_IN_UNKNOWN` is 0; the ladder equals
    the derived levels and the verdict histogram; a non-measurable family is
    `DROP_IN_NOT_APPLICABLE` with a reason; `candidate_specific_patch_count` is 0; and the counts
    are derived, not typed.
    """
    findings: list[str] = []
    p1000 = inputs["family_freeze"].get("p1000") or []
    members = {str(e.get("family_id")) for e in p1000}

    # 1. The recorded rule and non-claims are the frozen ones.
    if body.get("rule") != RULE:
        findings.append("the recorded rule is not the frozen final-P1000-run rule")
    if body.get("non_claims") != NON_CLAIMS:
        findings.append("the recorded non_claims are not the stratum's four plus the "
                        "selected-population non-claim")

    # 2. The candidate identity equals the frozen 24.11 one, excluding the recorded provenance.
    frozen_ident = inputs["candidate_freeze"].get("candidate_identity") or {}
    recorded_ident = body.get("candidate_identity") or {}
    if cf.identity_content(recorded_ident) != cf.identity_content(frozen_ident):
        findings.append("the candidate identity does not equal the frozen 24.11 candidate identity "
                        "(the run is against a different candidate than the freeze)")
    if recorded_ident.get("identity_hash") != content_hash(cf.identity_content(recorded_ident)):
        findings.append("candidate_identity.identity_hash does not reproduce from its own record")

    # 3. The run rows: every frozen family has both-subject rows, schema-valid, patch count 0.
    rows = body.get("runs") or []
    if not rows:
        return findings + ["the final P1000 run records no run"]
    seen_ids: set[str] = set()
    by_fs: dict[tuple[str, str], dict] = {}
    for row in rows:
        fid = str(row.get("family_id"))
        subject = str(row.get("subject"))
        name = str(row.get("canonical_name"))
        findings += [f"{name}/{subject}: {p}" for p in downstream_schemas.validate_run(row)]
        rid = str(row.get("run_id"))
        if rid in seen_ids:
            findings.append(f"two run rows share run_id {rid!r}")
        seen_ids.add(rid)
        if fid not in members:
            findings.append(f"{name}: a run row is not a frozen P1000 family")
        if int(row.get("candidate_specific_patch_count") or 0) != 0:
            findings.append(f"{name}/{subject}: candidate_specific_patch_count is "
                            f"{row.get('candidate_specific_patch_count')!r}, not 0")
        by_fs[(fid, subject)] = row
    for e in p1000:
        fid = str(e.get("family_id"))
        name = str(e.get("canonical_name"))
        for subject in SUBJECTS:
            if (fid, subject) not in by_fs:
                findings.append(f"{name}: no {subject} run row")

    # 4. Exactly one derived verdict per counted family: none missing, extra or fabricated.
    verdicts = body.get("verdicts") or []
    baseline = cf._baseline_map(rows)
    cand = {str(r.get("family_id")): r for r in rows if r.get("subject") == "candidate"}
    by_family: dict[str, dict] = {}
    seen_verdict_ids: set[str] = set()
    for rec in verdicts:
        findings += [f"verdict {rec.get('verdict_id')}: {p}"
                     for p in downstream_schemas.validate_drop_in_verdict(rec)]
        vid = str(rec.get("verdict_id"))
        if vid in seen_verdict_ids:
            findings.append(f"two verdicts share verdict_id {vid!r}")
        seen_verdict_ids.add(vid)
        fid = str(rec.get("family_id"))
        if fid in by_family:
            findings.append(f"the counted family {fid} carries more than one verdict")
        by_family[fid] = rec
        if fid not in members:
            findings.append(f"{vid}: a verdict is not a counted P1000 family")
    missing = sorted(members - set(by_family))
    if missing:
        findings.append(f"{len(missing)} counted family(ies) have no verdict (e.g. {missing[:3]})")
    extra = sorted(set(by_family) - members)
    if extra:
        findings.append(f"{len(extra)} verdict(s) are for a family outside the frozen P1000 "
                        f"(e.g. {extra[:3]})")

    for e in p1000:
        fid = str(e.get("family_id"))
        name = str(e.get("canonical_name"))
        rec = by_family.get(fid)
        if rec is None:
            continue
        c = cand.get(fid)
        base = baseline.get(fid, L0)
        want = cf.derive_verdict_for(base, c)
        if str(rec.get("verdict")) != want:
            findings.append(f"{rec.get('verdict_id')}: verdict {rec.get('verdict')!r} is not the "
                            f"derived {want!r}")
        if str(rec.get("authority_applicable_level")) != base:
            findings.append(f"{rec.get('verdict_id')}: records authority_applicable_level "
                            f"{rec.get('authority_applicable_level')!r}, but the authority rows "
                            f"reached {base!r}")
        if str(rec.get("candidate_level")) != str((c or {}).get("level") or L0):
            findings.append(f"{rec.get('verdict_id')}: candidate_level "
                            f"{rec.get('candidate_level')!r} is not the candidate row's "
                            f"{(c or {}).get('level')!r}")
        # A PASS is refused without all five section-20 conditions, by name.
        if rec.get("verdict") == "DROP_IN_PASS":
            if RANK.get(base, -1) < RANK[L4]:
                findings.append(f"{rec.get('verdict_id')}: a DROP_IN_PASS without an authority "
                                f"baseline that reached at least L4-linked")
            if not rec.get("authority_baseline"):
                findings.append(f"{rec.get('verdict_id')}: a DROP_IN_PASS without an authority "
                                f"baseline it was normalized against")
            if int(rec.get("candidate_specific_patch_count") or 0) != 0:
                findings.append(f"{rec.get('verdict_id')}: a DROP_IN_PASS with a positive "
                                f"candidate_specific_patch_count")
            if rec.get("linkage_proven") is not True:
                findings.append(f"{rec.get('verdict_id')}: a DROP_IN_PASS without proven candidate "
                                f"linkage")
            if rec.get("residual_class") not in (None, "none"):
                findings.append(f"{rec.get('verdict_id')}: a DROP_IN_PASS with residual class "
                                f"{rec.get('residual_class')!r}")
            if (RANK.get(str(rec.get("candidate_level")), -1)
                    < RANK.get(str(rec.get("authority_applicable_level")), -1)):
                findings.append(f"{rec.get('verdict_id')}: a DROP_IN_PASS whose candidate level "
                                f"{rec.get('candidate_level')!r} does not reach the "
                                f"authority-applicable level "
                                f"{rec.get('authority_applicable_level')!r}")
        # A family whose authority baseline did not link is NOT_APPLICABLE with a reason.
        if RANK.get(base, -1) < RANK[L4]:
            if str(rec.get("verdict")) != "DROP_IN_NOT_APPLICABLE":
                findings.append(f"{rec.get('verdict_id')}: a non-measurable family "
                                f"({name}) is {rec.get('verdict')!r}, not DROP_IN_NOT_APPLICABLE")
            if not rec.get("reason"):
                findings.append(f"{rec.get('verdict_id')}: a DROP_IN_NOT_APPLICABLE family carries "
                                f"no reason")

    # 5. UNKNOWN is 0 (the brief's section 55).
    unknown = sum(1 for r in verdicts if r.get("verdict") == "DROP_IN_UNKNOWN")
    if unknown:
        findings.append(f"{unknown} verdict(s) are DROP_IN_UNKNOWN; every counted family must be "
                        f"measured or honestly non-applicable")

    # 6. Zero candidate-specific patches, over the rows and the recorded count.
    if int((body.get("counts") or {}).get("candidate_specific_patch_count") or 0) != 0:
        findings.append("counts.candidate_specific_patch_count is not 0")

    # 7. The ladder equals the derived levels and the verdict histogram; the counts are derived.
    derived_ladder = derive_ladder(p1000, rows, verdicts)
    ladder = body.get("ladder") or {}
    for key in ("families", "measurable_families", "not_applicable_families"):
        if ladder.get(key) != derived_ladder[key]:
            findings.append(f"ladder.{key} {ladder.get(key)!r} disagrees with the derived "
                            f"{derived_ladder[key]!r}")
    for rung, n in derived_ladder["levels"].items():
        if (ladder.get("levels") or {}).get(rung) != n:
            findings.append(f"ladder.levels.{rung} {(ladder.get('levels') or {}).get(rung)!r} "
                            f"disagrees with the derived {n!r}")
    for verdict, n in derived_ladder["verdicts"].items():
        if (ladder.get("verdicts") or {}).get(verdict) != n:
            findings.append(f"ladder.verdicts.{verdict} "
                            f"{(ladder.get('verdicts') or {}).get(verdict)!r} disagrees with the "
                            f"derived {n!r}")

    derived_counts = derive_counts(p1000, rows, verdicts, derived_ladder)
    recorded_counts = body.get("counts") or {}
    for key, want in derived_counts.items():
        if recorded_counts.get(key) != want:
            findings.append(f"counts.{key} {recorded_counts.get(key)!r} disagrees with the derived "
                            f"{want!r}")
    return findings


def _mutations(inputs: dict, body: dict) -> list[tuple[str, str, dict, dict]]:
    """`(name, needle, mutated_inputs, mutated_body)` for each seeded mutation."""
    out: list[tuple[str, str, dict, dict]] = []
    verdicts = body.get("verdicts") or []
    # A verdict whose authority baseline actually linked, so the PASS mutations pose the section-20
    # conditions rather than tripping a weaker check first.
    measurable = next((v for v in verdicts
                       if RANK.get(str(v.get("authority_applicable_level")), -1) >= RANK[L4]), None)
    first = measurable or (verdicts[0] if verdicts else None)

    # (1) a PASS asserted without an authority baseline.
    m1 = copy.deepcopy(body)
    v1 = next((v for v in m1["verdicts"] if v["verdict_id"] == first["verdict_id"]), None)
    if v1 is not None:
        v1["verdict"] = "DROP_IN_PASS"
        v1["authority_baseline"] = ""
    out.append(("pass_without_authority_baseline", "authority baseline", inputs, m1))

    # (2) a PASS with a positive candidate-specific patch count.
    m2 = copy.deepcopy(body)
    v2 = next((v for v in m2["verdicts"] if v["verdict_id"] == first["verdict_id"]), None)
    if v2 is not None:
        v2["verdict"] = "DROP_IN_PASS"
        v2["candidate_specific_patch_count"] = 1
        v2["residual_class"] = "none"
        v2["linkage_proven"] = True
        v2["authority_baseline"] = v2.get("authority_applicable_level")
    out.append(("pass_with_positive_patch_count", "candidate_specific_patch_count", inputs, m2))

    # (3) a duplicate verdict.
    m3 = copy.deepcopy(body)
    if first is not None:
        dup = copy.deepcopy(first)
        m3["verdicts"] = list(m3["verdicts"]) + [dup]
    out.append(("duplicated_verdict", "share verdict_id", inputs, m3))

    # (4) a candidate level below the authority-applicable level marked PASS.
    m4 = copy.deepcopy(body)
    v4 = next((v for v in m4["verdicts"] if v["verdict_id"] == first["verdict_id"]), None)
    if v4 is not None:
        v4["verdict"] = "DROP_IN_PASS"
        v4["candidate_level"] = L1
        v4["authority_baseline"] = v4.get("authority_applicable_level")
        v4["linkage_proven"] = True
        v4["residual_class"] = "none"
        v4["candidate_specific_patch_count"] = 0
    out.append(("candidate_level_below_baseline_marked_pass", "does not reach the "
                "authority-applicable level", inputs, m4))

    # (5) a candidate identity that does not match the frozen one.
    m5 = copy.deepcopy(body)
    ident = dict(m5.get("candidate_identity") or {})
    ident["libssl_sha256"] = "0" * 64
    m5["candidate_identity"] = ident
    out.append(("mismatched_candidate_identity", "does not equal the frozen 24.11 candidate identity",
                inputs, m5))
    return out


def p1000_sensitivity_control(inputs: dict, body: dict) -> dict:
    """Prove the court can fail: seed five mutations and require each caught with specificity.

    The honest run must yield **zero** findings (specificity), and each seeded mutation -- a PASS
    asserted without an authority baseline, a PASS with a positive patch count, a missing/duplicate
    verdict, a candidate level below the authority-applicable level marked PASS, and a mismatched
    candidate identity -- must be caught with a finding naming it.
    """
    base = p1000_findings(inputs, body)
    control: dict = {"baseline_findings": len(base), "specificity_holds": not base}
    honest = not base
    for name, needle, mi, mb in _mutations(inputs, body):
        caught = any(needle in f for f in p1000_findings(mi, mb))
        control[f"injected_{name}"] = name
        control[f"caught_{name}"] = caught
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# ---------------------------------------------------------------------------------------------------
# the artefact
# ---------------------------------------------------------------------------------------------------

def _inputs_list() -> list[InputRef]:
    return [
        InputRef(name="family-freeze", path=FAMILY_FREEZE),
        InputRef(name="candidate-freeze", path=CANDIDATE_FREEZE),
        InputRef(name="holdout", path=HOLDOUT),
        InputRef(name="families", path=FAMILIES),
        InputRef(name="container-manifest", path=CONTAINER_MANIFEST),
        InputRef(name="downstream-p1000-run",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_p1000_run.py"),
        InputRef(name="downstream-candidate-freeze",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_candidate_freeze.py"),
        InputRef(name="downstream-build-link",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_build_link.py"),
        InputRef(name="downstream-runtime",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_runtime.py"),
        InputRef(name="downstream-census",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_census.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]


def write_outputs(body: dict, authority_id: str) -> None:
    doc = envelope(kind="downstream-p1000-run", authority=authority_id,
                   inputs=_inputs_list(), body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


def _compose_body(inputs: dict, authority_id: str, measurement: dict, ident: dict) -> dict:
    """Compose the artefact body from the measured rows and the frozen candidate identity."""
    p1000 = inputs["family_freeze"].get("p1000") or []
    rows = measurement["runs"]
    verdicts = derive_verdicts(p1000, rows)
    ladder = derive_ladder(p1000, rows, verdicts)
    counts = derive_counts(p1000, rows, verdicts, ladder)
    receipts = derive_receipts(p1000, rows, verdicts)
    return {
        "rule": RULE,
        "authority": authority_id,
        "authority_prefix": measurement["authority_prefix"],
        "candidate_identity": ident,
        "population": {
            "source": rel(FAMILY_FREEZE),
            "rule_id": (inputs["family_freeze"].get("rule") or {}).get("id"),
            "selection_root_hash": inputs["family_freeze"].get("selection_root_hash"),
            "p1000": len(p1000),
        },
        "specimens": measurement["specimens"],
        "variants": measurement["variants"],
        "runs": rows,
        "verdicts": verdicts,
        "ladder": ladder,
        "counts": counts,
        "per_consumer_receipts": receipts,
        "resource_limits": measurement["limits"],
        "elapsed_seconds": measurement["elapsed_seconds"],
        "non_claims": NON_CLAIMS,
    }


def _assert_frozen_candidate(frozen_body: dict) -> dict:
    """Refuse to run against a candidate that does not match the frozen 24.11 identity."""
    live = cf.candidate_identity()
    frozen = frozen_body.get("candidate_identity") or {}
    if cf.identity_content(live) != cf.identity_content(frozen):
        raise SystemExit(
            "[downstream-p1000-run] the current candidate install does not match the frozen 24.11 "
            "identity (the run must be against the frozen candidate; a mismatch is a finding, not a "
            f"silent re-freeze): live identity_hash {live.get('identity_hash')!r} vs frozen "
            f"{frozen.get('identity_hash')!r}")
    return live


def _load_all_inputs() -> dict:
    for path, what, sub in ((FAMILY_FREEZE, "frozen P1000", "24.4"),
                            (CANDIDATE_FREEZE, "candidate freeze", "24.11"),
                            (HOLDOUT, "holdout partition", "24.5")):
        if not path.is_file():
            raise SystemExit(f"[downstream-p1000-run] {rel(path)} is absent; run {sub} first")
    return load_inputs()


def cmd_measure(authority_id: str) -> int:
    inputs = _load_all_inputs()
    p1000 = inputs["family_freeze"].get("p1000") or []
    if len(p1000) != 1000:
        print(f"[downstream-p1000-run] the frozen P1000 carries {len(p1000)} family(ies), not 1000")
        return 1
    ident = _assert_frozen_candidate(inputs["candidate_freeze"])
    print(f"[downstream-p1000-run] running the frozen P1000 ({len(p1000)} families) against the "
          f"frozen candidate {rel(CANDIDATE_PREFIX)} (identity {ident['identity_hash'][:16]}..., "
          f"version {ident['crate_version']}, commit {ident['source_commit'][:12]})", flush=True)
    measurement = measure_p1000(p1000, authority_id)
    body = _compose_body(inputs, authority_id, measurement, ident)
    findings = p1000_findings(inputs, body)
    control = p1000_sensitivity_control(inputs, body)
    if findings or not control["honest"]:
        print("[downstream-p1000-run] the measured run fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body, authority_id)
    c = body["counts"]
    lad = body["ladder"]
    print(f"[downstream-p1000-run] families={c['families']} recipe_backed={c['recipe_backed_families']} "
          f"measurable={c['measurable_families']} not_applicable={c['not_applicable_families']} "
          f"reaches_baseline={c['measurable_reaches_baseline']} patches="
          f"{c['candidate_specific_patch_count']}")
    print(f"  ladder: families={lad['families']} levels={lad['levels']}")
    print(f"  verdicts: {lad['verdicts']}")
    print(f"  identity_hash={ident['identity_hash']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check(authority_id: str) -> int:
    del authority_id
    if not OUT.is_file():
        print(f"[downstream-p1000-run] {rel(OUT)} is absent")
        return 1
    inputs = _load_all_inputs()
    body = _load_json(OUT)
    findings = p1000_findings(inputs, body)
    control = p1000_sensitivity_control(inputs, body)
    if findings:
        print(f"[downstream-p1000-run] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = body.get("counts") or {}
    print(f"[downstream-p1000-run] families={c.get('families')} "
          f"measurable={c.get('measurable_families')} "
          f"not_applicable={c.get('not_applicable_families')} "
          f"verdicts={(body.get('ladder') or {}).get('verdicts')} findings={len(findings)} "
          f"control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_p1000_run.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_p1000_run.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. `p1000-run.json` is in the freeze's candidate-result artefact set, so a later freeze's scan
    #    excludes it exactly as it excludes the other post-freeze candidate artefacts.
    from downstream_freeze import CANDIDATE_RESULT_ARTEFACTS  # noqa: E402
    if "p1000-run.json" not in CANDIDATE_RESULT_ARTEFACTS:
        failures.append("p1000-run.json is not in downstream_freeze.CANDIDATE_RESULT_ARTEFACTS")

    # 3. The recipe/workload machinery is reused, not re-implemented.
    if not hasattr(bl, "measure_family") or not hasattr(rt, "_measure_subject_runtime"):
        failures.append("the 24.6/24.7 build/runtime machinery is not the imported one")

    # 4. The pure functions behave over the committed evidence.
    missing = [rel(p) for p in (FAMILY_FREEZE, CANDIDATE_FREEZE, HOLDOUT) if not p.is_file()]
    if missing:
        failures.append(f"{', '.join(missing)} is absent")
    else:
        inputs = _load_all_inputs()
        p1000 = inputs["family_freeze"].get("p1000") or []
        if len(p1000) != 1000:
            failures.append("the frozen P1000 does not carry 1,000 family(ies)")
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run --measure")
        else:
            body = _load_json(OUT)
            findings = p1000_findings(inputs, body)
            if findings:
                failures.append(f"the committed run has findings: {findings[:3]}")
            control = p1000_sensitivity_control(inputs, body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[downstream-p1000-run] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-p1000-run] self-test ok: the guard refuses a host invocation of this tool "
          "(marker and flag both named), the frozen P1000 carries 1,000 family(ies), the committed "
          "run reproduces with zero findings, and every seeded mutation (a PASS without an authority "
          "baseline, a PASS with a positive patch count, a duplicated verdict, a candidate level "
          "below the baseline marked PASS, and a mismatched candidate identity) is caught with "
          "specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--measure", action="store_true",
                    help="run the full P1000 against the frozen candidate (in-container)")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed run without rebuilding (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool fetches, compiles and runs, so it is an
    # execution entry point and a host invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check(args.authority)
    return cmd_measure(args.authority)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
