#!/usr/bin/env python3
"""openssl-rs — Phase-24.13 atlas reconciliation: one accounted view of the whole downstream plane.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over the
frozen P1000 (`forensics/downstream/family-freeze.json`). Thirteen commits have landed planes: the
frozen ranking evidence, the candidate universe and its families, the authority census, the frozen
P1000 and precommitted holdout, the build/link atlas, the runtime/functional atlas, the classified
and preserved failures, the high-value deep tier, the separate hostility corpus, the frozen candidate
and the once-run holdout, and the final full P1000 run. This module is the **reconciliation**: it
reads **every** committed plane and reconciles them into one accounted view, so a reader can ask a
single question -- "does the atlas add up?" -- and get a machine-checkable answer rather than a
hand-count.

What "reconciled" means here
----------------------------
The reconciliation is a **pure function of the committed planes**: it configures nothing, builds
nothing, links nothing and runs nothing, and it types no count it can derive. It establishes:

  * **every counted family has exactly one `drop_in_verdict`**, re-derived from the committed
    24.12 run rows by the 24.11 baseline-normalized rule (never copied, never typed), and the count
    of `DROP_IN_UNKNOWN` is 0 -- a family this venue cannot pose the drop-in question for is an
    honest `DROP_IN_NOT_APPLICABLE`, not an unknown (the brief's sections 20 and 55);
  * **every residual across every plane is classified** from the closed residual vocabulary, and the
    count of an unclassified or `unknown` residual is 0; a genuinely unclassifiable leftover is a
    `finding`, never silently dropped (the brief's section 30, and the plan's section 3.5);
  * **every failure is preserved** -- the counted P1000 measured set's failures (from 24.8's plane)
    **and** the separate hostility corpus's two candidate failures (24.10's `hostility:static`
    link-failure and `hostility:tls` TLS-1.2 runtime-failure), classified from the failure taxonomy,
    with the hostility ones clearly scoped as **not** P1000 rates (the brief's sections 31/32/44 and
    the plan's section 3.7);
  * **the drop-in rates are computed over the frozen population** from the verdicts -- unweighted,
    with any weighted summary kept separate -- and the direct and transitive consumers are **never
    summed** (the plan's section 3.6). The frozen P1000 is all-direct (1,000 direct, 0 transitive by
    measurement), so the transitive rate is empty rather than zero, and that is recorded;
  * the **§52 ladder** is a per-level family-count ladder plus the verdict status histogram, with the
    raw family count visible and `UNKNOWN = 0`, never one misleading percentage;
  * the **§35 coverage** reports the unique public symbols, headers and API families the measured set
    actually exercised against the Phase-22 known-universe denominators, with the measured/inferred
    distinction explicit;
  * the **§34 Phase-22 integration** reports the directly-referenced public entities and the
    graph-reachable inferred internal entities **separately** -- the latter is a read of the
    committed Phase-22 reachability closure, which is inference and never execution;
  * the **§36/§37 marginal-consumer and usage-cluster analysis** over the measured set, honestly
    revealing how many *distinct* stressors the counted families really are rather than treating each
    as independent.

Instrument versus property, and no fake statistical confidence
--------------------------------------------------------------
The court is an **instrument**: it re-runs this module's pure functions over the committed artefact
and passes when the reconciliation is *self-consistent*. It is not the property. The property the
subphase names -- a fully reconciled atlas, a fully classified residual set, a population-wide drop-in
rate -- is carried by `property_status` and `property_findings`, so a passing court can coexist with
an atlas that carries real findings (a large `NOT_APPLICABLE` share, a thin measured surface, a
non-empty residual set). Those are recorded as findings, never traded for a green light.

The population is **selected**, not sampled, so no population-wide confidence interval is computed:
the brief's section 53 forbids manufacturing statistical confidence a selected population cannot
carry, and the non-claims say so. This tool never reports one misleading percentage; the headline is
the ladder, and the rates are labelled as over the selected population.

Why this artefact is a pure function (and so is a determinism generator)
------------------------------------------------------------------------
Unlike 24.6/24.7/24.9/24.10/24.11/24.12, this module **executes nothing**: it reads the committed
planes and writes one aggregate, so it is exactly the "pure aggregate derived from the measured
atlases" the 24.6, 24.7 and 24.8 comments in `evidence_determinism.py` anticipated. It is therefore
wired into that tool's `GENERATORS` and `COMPARED` with a why-comment, exactly as 24.4's freeze, 24.5's
partition and 24.8's failures plane are: a stale committed reconciliation is a failure rather than a
silent divergence. `main` still calls `phase24_guard.require_admitted()` first, as every Phase-24
entry point does (`docs/REPRODUCIBILITY.md` section 1).

Outputs
-------
  forensics/downstream/reconciliation.json   the reconciled verdicts, residuals, failures, rates,
                                             ladder, coverage, Phase-22 projection and clusters

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import itertools
import json
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
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool reads
# committed evidence and writes one aggregate, so it executes nothing itself, but it is a Phase-24
# entry point and the guard refuses a host invocation exactly as every other one is.
import phase24_guard  # noqa: E402

# The record schemas and the closed vocabularies, imported rather than restated so they cannot drift.
import downstream_schemas  # noqa: E402

# The 24.11 baseline-normalized verdict rule is reused (never re-implemented) so a family's verdict
# here is the exact verdict the freeze and the final P1000 run derive.
import downstream_candidate_freeze as cf  # noqa: E402

# The 24.10 covered-surface function is reused (never re-implemented) so the coverage this module
# reports is exactly the surface the hostility corpus was selected against.
import downstream_hostility as hostility  # noqa: E402

# The stratum's four non-claims, imported from 24.4 so the reconciliation and the population cannot
# drift; the fifth (the selected-population non-claim) is added here.
from downstream_freeze import NON_CLAIMS as STRATUM_NON_CLAIMS  # noqa: E402

DOWNSTREAM = REPO_ROOT / "forensics" / "downstream"
ATLAS = REPO_ROOT / "forensics" / "atlas"

FAMILY_FREEZE = DOWNSTREAM / "family-freeze.json"
HOLDOUT = DOWNSTREAM / "holdout.json"
BUILD_LINK_ATLAS = DOWNSTREAM / "build-link-atlas.json"
RUNTIME_FUNCTIONAL_ATLAS = DOWNSTREAM / "runtime-functional-atlas.json"
FAILURES = DOWNSTREAM / "failures.json"
HIGH_VALUE_TIER = DOWNSTREAM / "high-value-tier.json"
HOSTILITY_CORPUS = DOWNSTREAM / "hostility-corpus.json"
CANDIDATE_FREEZE = DOWNSTREAM / "candidate-freeze.json"
P1000_RUN = DOWNSTREAM / "p1000-run.json"
USAGE_FINGERPRINTS = DOWNSTREAM / "usage-fingerprints.json"
FAMILIES = DOWNSTREAM / "families.json"
CANDIDATES = DOWNSTREAM / "candidates.json"
OUT = DOWNSTREAM / "reconciliation.json"

# The Phase-22 known-universe denominators and the graph-reachability closure. The production
# authority directory is the admitted production authority; `reconciliation_findings` fails closed if
# `implemented-surface.json`'s recorded authority no longer names it.
IMPLEMENTED_SURFACE = ATLAS / "implemented-surface.json"
SYMBOL_OWNERSHIP = ATLAS / "symbol-ownership.json"
INTERNAL_SYMBOLS = ATLAS / "internal-symbols.json"
COMPATIBILITY_CLOSURE = ATLAS / "phase22" / "compatibility-closure.json"
COMPATIBILITY_VIEWS = REPO_ROOT / "forensics" / "multitrack" / "compatibility-views.json"
PRODUCTION_AUTHORITY_DIR = ATLAS / "openssl-3.6.4-production"
PRODUCTION_COVERAGE = PRODUCTION_AUTHORITY_DIR / "coverage.json"
PRODUCTION_SURFACE_RECON = PRODUCTION_AUTHORITY_DIR / "surface-reconciliation.json"

GENERATOR = "forensics/tools/downstream_reconciliation.py"
PARSER_VERSION = "downstream-atlas-reconciliation/1"

L0 = "L0-catalogued"
L4 = "L4-linked"
RANK = downstream_schemas.EXECUTION_LEVEL_RANK

# The ladder's run rungs, in order (the §52 ladder: configured/compiled/linked/loaded/runtime/
# functional). `compiled` maps to the atlas's `L3-built`.
LADDER_RUNGS = ("L2-configured", "L3-built", "L4-linked", "L5-loaded", "L6-runtime", "L7-functional")

# The verdict status names the ladder reports alongside the raw counts.
STATUS_OF_VERDICT = {
    "DROP_IN_PASS": "PASS",
    "DROP_IN_PARTIAL": "PARTIAL",
    "DROP_IN_FAIL": "FAIL",
    "DROP_IN_UNKNOWN": "UNKNOWN",
    "DROP_IN_NOT_APPLICABLE": "NOT_APPLICABLE",
}
STATUS_NAMES = ("PASS", "PARTIAL", "FAIL", "UNKNOWN", "NOT_APPLICABLE")

# The usage-cluster threshold. Two fingerprints are the same *stressor* when their imported-symbol
# Jaccard similarity is at least this. The pairwise similarities are recorded so a reader can
# re-cluster at any threshold rather than trusting one.
CLUSTER_THRESHOLD = 0.20

# The stratum's four non-claims plus the one this subphase's rates add: a selected population admits
# no population-wide percentage, and NOT_APPLICABLE is not a pass.
NON_CLAIMS: list[str] = list(STRATUM_NON_CLAIMS) + [
    "the rates are over a selected population of 1,000 families, not a percentage of all downstream "
    "software, and NOT_APPLICABLE is not a pass",
]

# The frozen reconciliation rule, recorded verbatim in the artefact and re-derived by the court.
RULE: dict = {
    "id": "downstream-atlas-reconciliation/1",
    "name": "the atlas reconciliation",
    "population": (
        "the counted population is the frozen P1000 forensics/downstream/family-freeze.json: a "
        "selected population of 1,000 downstream project families, not a random sample"
    ),
    "verdict": (
        "exactly one drop_in_verdict per counted family, re-derived from the committed 24.12 run "
        "rows by the 24.11 baseline-normalized rule, never copied and never typed; DROP_IN_UNKNOWN "
        "is 0, because a family this venue cannot pose the drop-in question for is an honest "
        "DROP_IN_NOT_APPLICABLE"
    ),
    "residuals": (
        "every residual across every committed plane is classified from the closed residual "
        "vocabulary, and the count of an unclassified or unknown residual is 0: a genuinely "
        "unclassifiable leftover is a finding, never silently dropped"
    ),
    "failures": (
        "every failure is preserved: the counted P1000 measured set's failures from 24.8's plane "
        "and the separate hostility corpus's two candidate failures, classified from the failure "
        "taxonomy, with the hostility ones clearly scoped as not P1000 rates"
    ),
    "rates": (
        "the drop-in rates are computed over the frozen population from the derived verdicts -- "
        "unweighted, with any weighted summary kept separate -- and the direct and transitive "
        "consumers are never summed; the frozen P1000 is all-direct, so the transitive rate is "
        "empty rather than zero"
    ),
    "ladder": (
        "the result is a ladder, never one percentage (the brief's section 52): per-level family "
        "counts (configured, compiled/built, linked, loaded, runtime, functional) and the verdict "
        "status histogram (PASS/PARTIAL/FAIL/UNKNOWN/NOT_APPLICABLE), with the raw family count "
        "visible and UNKNOWN 0"
    ),
    "coverage": (
        "the measured set's unique public symbols, headers and API families against the Phase-22 "
        "known-universe denominators, with the measured/inferred distinction explicit (the brief's "
        "section 35)"
    ),
    "phase22": (
        "the directly-referenced public entities and the graph-reachable inferred internal entities "
        "are reported separately and never summed; reachability is a read of the committed Phase-22 "
        "closure, not execution (the brief's section 34)"
    ),
    "clusters": (
        "the marginal-consumer and usage-cluster analysis over the measured set, so the counted "
        "families are not read as that many independent stressors (the brief's sections 36 and 37)"
    ),
    "no_statistical_confidence": (
        "the population is selected, not sampled, so no population-wide confidence interval or test "
        "statistic is computed; the brief's section 53 forbids manufacturing confidence a selected "
        "population cannot carry"
    ),
    "constants": {"cluster_threshold": CLUSTER_THRESHOLD, "ladder_rungs": list(LADDER_RUNGS)},
}


# ---------------------------------------------------------------------------------------------------
# reading the committed planes (pure; the court re-reads the same files)
# ---------------------------------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def load_inputs() -> dict:
    """Every committed plane the reconciliation reads and the court re-reads."""
    return {
        "family_freeze": _load_json(FAMILY_FREEZE),
        "holdout": _load_json(HOLDOUT),
        "build_link": _load_json(BUILD_LINK_ATLAS),
        "runtime": _load_json(RUNTIME_FUNCTIONAL_ATLAS),
        "failures": _load_json(FAILURES),
        "high_value": _load_json(HIGH_VALUE_TIER),
        "hostility": _load_json(HOSTILITY_CORPUS),
        "candidate_freeze": _load_json(CANDIDATE_FREEZE),
        "p1000_run": _load_json(P1000_RUN),
        "usage_fingerprints": _load_json(USAGE_FINGERPRINTS),
        "families": _load_json(FAMILIES),
        "candidates": _load_json(CANDIDATES),
        "implemented_surface": _load_json(IMPLEMENTED_SURFACE),
        "symbol_ownership": _load_json(SYMBOL_OWNERSHIP),
        "internal_symbols": _load_json(INTERNAL_SYMBOLS),
        "compatibility_closure": _load_json(COMPATIBILITY_CLOSURE),
        "compatibility_views": _load_json(COMPATIBILITY_VIEWS),
        "production_coverage": _load_json(PRODUCTION_COVERAGE),
        "production_surface_reconciliation": _load_json(PRODUCTION_SURFACE_RECON),
    }


def _p1000(inputs: dict) -> list[dict]:
    return list(inputs["family_freeze"].get("p1000") or [])


def _hist(values) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        key = str(v)
        out[key] = out.get(key, 0) + 1
    return {k: out[k] for k in sorted(out)}


# ---------------------------------------------------------------------------------------------------
# the verdicts, the ladder, the rates (pure over the committed 24.12 run rows)
# ---------------------------------------------------------------------------------------------------

def derive_verdicts(inputs: dict) -> list[dict]:
    """Exactly one `drop_in_verdict` projection per counted family, re-derived from the 24.12 rows.

    The verdict is re-derived by 24.11's `derive_verdict_for` from the committed run rows (the
    authority baseline and the candidate row), never copied from the recorded 24.12 verdicts; the
    recorded verdict is carried beside it so the court can check the two agree.
    """
    rows = list(inputs["p1000_run"].get("runs") or [])
    recorded = {str(v.get("family_id")): v for v in inputs["p1000_run"].get("verdicts") or []}
    baseline = cf._baseline_map(rows)
    cand = {str(r.get("family_id")): r for r in rows if r.get("subject") == "candidate"}
    out: list[dict] = []
    for entry in _p1000(inputs):
        fid = str(entry.get("family_id"))
        name = str(entry.get("canonical_name"))
        c = cand.get(fid) or {}
        base = baseline.get(fid, L0)
        verdict = cf.derive_verdict_for(base, c)
        out.append({
            "family_id": fid,
            "canonical_name": name,
            "p1000_rank": entry.get("p1000_rank"),
            "openssl_linkage": entry.get("openssl_linkage"),
            "directness_class": entry.get("directness_class"),
            "verdict": verdict,
            "residual_class": c.get("residual_class"),
            "authority_applicable_level": base,
            "candidate_level": str(c.get("level") or L0),
            "linkage_proven": bool(c.get("linkage_proven")),
            "candidate_specific_patch_count": int(c.get("candidate_specific_patch_count") or 0),
            "recorded_verdict": (recorded.get(fid) or {}).get("verdict"),
        })
    out.sort(key=lambda v: (int(v["p1000_rank"]) if v.get("p1000_rank") is not None else 10 ** 9,
                            str(v["family_id"])))
    return out


def derive_ladder(inputs: dict, verdicts: list[dict]) -> dict:
    """The §52 ladder: per-level family counts and the verdict status histogram, never a rate."""
    cand_rows = [r for r in inputs["p1000_run"].get("runs") or []
                 if r.get("subject") == "candidate"]
    total = len(verdicts)
    measurable = sum(1 for v in verdicts
                     if RANK.get(str(v.get("authority_applicable_level")), -1) >= RANK[L4])
    status = {name: 0 for name in STATUS_NAMES}
    for v in verdicts:
        s = STATUS_OF_VERDICT.get(str(v.get("verdict")))
        if s is not None:
            status[s] = status.get(s, 0) + 1
    return {
        "population": "the frozen P1000",
        "families": total,
        "raw_family_count": total,
        "measurable_families": measurable,
        "not_applicable_families": total - measurable,
        "levels": {
            rung: sum(1 for r in cand_rows
                      if RANK.get(str(r.get("level")), -1) >= RANK[rung])
            for rung in LADDER_RUNGS
        },
        "status": status,
        "unknown": status.get("UNKNOWN", 0),
    }


def derive_rates(inputs: dict, verdicts: list[dict], ladder: dict) -> dict:
    """The drop-in rates computed over the frozen population from the verdicts, never typed."""
    total = len(verdicts)
    counts = {name: 0 for name in STATUS_NAMES}
    for v in verdicts:
        s = STATUS_OF_VERDICT.get(str(v.get("verdict")))
        if s is not None:
            counts[s] = counts.get(s, 0) + 1

    def block(subset: list[dict]) -> dict:
        denom = len(subset)
        sub = {name: 0 for name in STATUS_NAMES}
        for v in subset:
            s = STATUS_OF_VERDICT.get(str(v.get("verdict")))
            if s is not None:
                sub[s] = sub.get(s, 0) + 1
        return {
            "denominator": denom,
            **{name: {"count": sub[name],
                      "rate": (round(sub[name] / denom, 6) if denom else None)}
               for name in STATUS_NAMES},
        }

    direct = [v for v in verdicts if v.get("openssl_linkage") == "direct"]
    transitive = [v for v in verdicts if v.get("openssl_linkage") == "transitive"]

    # The weighted summary, kept separate from the headline. The weight is the frozen selection
    # signal `source_breadth`; it is a summary of the same verdicts, never the headline rate.
    weights = {str(e.get("family_id")): int(e.get("source_breadth") or 0) for e in _p1000(inputs)}
    total_weight = sum(weights.values())
    weighted = None
    if total_weight:
        wcounts = {name: 0 for name in STATUS_NAMES}
        for v in verdicts:
            s = STATUS_OF_VERDICT.get(str(v.get("verdict")))
            if s is not None:
                wcounts[s] += weights.get(str(v.get("family_id")), 0)
        weighted = {
            "signal": "source_breadth",
            "denominator": total_weight,
            **{name: {"weight": wcounts[name],
                      "rate": round(wcounts[name] / total_weight, 6)}
               for name in STATUS_NAMES},
        }

    measurable = ladder["measurable_families"]
    return {
        "population": {
            "source": rel(FAMILY_FREEZE),
            "families": total,
            "measurable_families": measurable,
            "not_applicable_families": total - measurable,
            "selection": "a selected population, not a random sample",
        },
        "unweighted": block(verdicts),
        "measurable": {
            "denominator": measurable,
            **{name: {"count": counts[name],
                      "rate": (round(counts[name] / measurable, 6) if measurable else None)}
               for name in ("PASS", "PARTIAL", "FAIL", "UNKNOWN")},
            "note": ("the drop-in question was posed for this many of the counted families: "
                     "NOT_APPLICABLE is not a pass"),
        },
        "direct": block(direct),
        "transitive": block(transitive),
        "direct_and_transitive_summed": False,
        "all_direct": len(transitive) == 0,
        "weighted": weighted,
        "weighted_is_the_headline": False,
        "statistical_confidence": {
            "computed": False,
            "reason": ("the population is selected, not sampled, so no population-wide confidence "
                       "interval or test statistic is computed (the brief's section 53)"),
        },
    }


# ---------------------------------------------------------------------------------------------------
# the residuals and the failures (pure over every plane)
# ---------------------------------------------------------------------------------------------------

def _residual_rows(inputs: dict) -> list[tuple[str, str, str, str, str, list[str]]]:
    """`(plane, kind, id, class, detail, evidence)` for every residual-bearing record."""
    out: list[tuple[str, str, str, str, str, list[str]]] = []

    def from_runs(plane: str, body: dict) -> None:
        for r in body.get("runs") or []:
            out.append((plane, "run", str(r.get("run_id")), r.get("residual_class"),
                        str(r.get("reason") or ""), list(r.get("evidence") or [])))

    from_runs("build-link-atlas", inputs["build_link"])
    from_runs("runtime-functional-atlas", inputs["runtime"])
    from_runs("high-value-tier", inputs["high_value"])
    from_runs("hostility-corpus", inputs["hostility"])
    from_runs("p1000-run", inputs["p1000_run"])
    holdout_run = inputs["candidate_freeze"].get("holdout_run") or {}
    from_runs("candidate-freeze", holdout_run)

    for v in inputs["p1000_run"].get("verdicts") or []:
        out.append(("p1000-run", "verdict", str(v.get("verdict_id")), v.get("residual_class"),
                    str(v.get("reason") or ""), list(v.get("evidence") or [])))
    for v in holdout_run.get("verdicts") or []:
        out.append(("candidate-freeze", "verdict", str(v.get("verdict_id")), v.get("residual_class"),
                    str(v.get("reason") or ""), list(v.get("evidence") or [])))
    for rec in inputs["failures"].get("failures") or []:
        out.append(("failures", "failure", str(rec.get("failure_id")), rec.get("residual_class"),
                    str(rec.get("detail") or ""), list(rec.get("evidence") or [])))
    return out


def derive_residuals(inputs: dict) -> dict:
    """Every residual classified from the closed vocabulary, with unknown and unclassified 0."""
    rows = _residual_rows(inputs)
    vocab = tuple(downstream_schemas.RESIDUAL_CLASSES)
    histogram = {cls: 0 for cls in vocab}
    by_plane: dict[str, dict[str, int]] = {}
    unclassified = 0
    for plane, _kind, _rid, cls, _detail, _ev in rows:
        key = str(cls)
        if key not in histogram:
            unclassified += 1
            by_plane.setdefault(plane, {}).setdefault("<unclassified>", 0)
            by_plane[plane]["<unclassified>"] += 1
            continue
        histogram[key] += 1
        by_plane.setdefault(plane, {}).setdefault(key, 0)
        by_plane[plane][key] += 1
    for plane in by_plane:
        by_plane[plane] = {k: by_plane[plane][k] for k in sorted(by_plane[plane])}

    # One schema-valid residual record per observed class, from a representative row, so a reader
    # can see the classification rather than only its count.
    records: list[dict] = []
    seen: set[str] = set()
    for plane, kind, rid, cls, detail, ev in rows:
        key = str(cls)
        if key not in histogram or key in seen:
            continue
        seen.add(key)
        disposition = ("none" if key == "none"
                       else "unknown" if key == "unknown" else "classified")
        records.append({
            "residual_id": f"residual:{plane}:{kind}:{key}",
            "run_id": rid or f"{plane}:{kind}",
            "class": key,
            "disposition": disposition,
            "detail": detail or f"a {key} residual is recorded in {plane}",
            "evidence": ev or [f"plane:{plane}", f"residual_class:{key}"],
        })
    records.sort(key=lambda r: (r["class"], r["residual_id"]))

    total = sum(histogram.values()) + unclassified
    resolved = histogram.get("none", 0)
    return {
        "classes": list(vocab),
        "total": total,
        "unresolved": total - resolved,
        "resolved": resolved,
        "unknown": histogram.get("unknown", 0),
        "unclassified": unclassified,
        "histogram": histogram,
        "by_plane": by_plane,
        "records": records,
    }


def _hostility_failure_record(row: dict) -> dict:
    """One schema-valid `failure` record for a hostility candidate failure (preserved, scoped)."""
    rid = str(row.get("run_id"))
    cls = str(row.get("failure_class"))
    detail = (
        f"the separate hostility corpus's candidate run {rid!r} failed ({row.get('reason')}); "
        f"classified {cls} from the failure taxonomy and preserved as a hostility diagnostic. This "
        f"is not a counted P1000 family failure and it is excluded from every P1000 rate"
    )
    evidence = list(row.get("evidence") or []) + [
        f"corpus:{rel(HOSTILITY_CORPUS)}",
        f"subject:{row.get('subject')}",
        f"level:{row.get('level')}",
        "scoped:not-a-p1000-rate",
    ]
    return {
        "failure_id": f"failure:hostility:{cls}:{rid}",
        "run_id": rid,
        "class": cls,
        "preserved": True,
        "minimized": False,
        "detail": detail,
        "evidence": evidence,
    }


def derive_failures_summary(inputs: dict) -> dict:
    """Every failure preserved: the P1000 plane's plus the separate hostility corpus's two."""
    fails = list(inputs["failures"].get("failures") or [])
    p1000 = {
        "source": rel(FAILURES),
        "total": len(fails),
        "preserved": sum(1 for r in fails if r.get("preserved") is True),
        "minimized": sum(1 for r in fails if r.get("minimized") is True),
        "candidate_specific": sum(1 for r in fails
                                  if r.get("disposition") == "candidate-specific"),
        "by_failure_class": _hist(r.get("class") for r in fails),
        "by_disposition": _hist(r.get("disposition") for r in fails),
        "by_residual_class": _hist(r.get("residual_class") for r in fails),
        "divergences": len(inputs["failures"].get("divergences") or []),
        "atlas_sources": list((inputs["failures"].get("rule") or {}).get("atlas_sources") or []),
    }
    sample = sorted(fails, key=lambda r: str(r.get("failure_id")))[:6]
    p1000["sample"] = [
        {k: r.get(k) for k in ("failure_id", "class", "disposition", "residual_class",
                               "preserved", "minimized", "detail")}
        for r in sample
    ]

    host_rows = sorted(
        [r for r in inputs["hostility"].get("runs") or []
         if r.get("subject") == "candidate" and r.get("outcome") == "failed"],
        key=lambda r: str(r.get("run_id")),
    )
    host_records = [_hostility_failure_record(r) for r in host_rows]
    hostility_summary = {
        "source": rel(HOSTILITY_CORPUS),
        "total": len(host_records),
        "preserved": sum(1 for r in host_records if r["preserved"]),
        "minimized": sum(1 for r in host_records if r["minimized"]),
        "candidate_specific": 0,
        "scoped": ("the separate hostility corpus is not the counted P1000 population: these "
                   "candidate failures are classified and preserved, and excluded from every P1000 "
                   "rate (the plan's section 3.7)"),
        "records": host_records,
    }
    return {
        "p1000": p1000,
        "hostility": hostility_summary,
        "taxonomy": list(downstream_schemas.FAILURE_CLASSES),
        "all_preserved": (p1000["preserved"] == p1000["total"]
                          and hostility_summary["preserved"] == hostility_summary["total"]),
    }


# ---------------------------------------------------------------------------------------------------
# coverage, the Phase-22 projection, and the marginal/cluster analysis (pure)
# ---------------------------------------------------------------------------------------------------

def _covered_surface(inputs: dict) -> dict:
    """The measured set's covered surface, reusing 24.10's function over the committed planes."""
    return hostility.covered_surface({
        "usage_fingerprints": inputs["usage_fingerprints"],
        "build_link": inputs["build_link"],
        "runtime": inputs["runtime"],
        "high_value": inputs["high_value"],
    })


def _exported_symbols(inputs: dict) -> set[str]:
    out: set[str] = set()
    for val in (inputs["implemented_surface"].get("libraries") or {}).values():
        out.update(str(s) for s in val.get("implemented_symbols") or [])
    return out


def derive_coverage(inputs: dict) -> dict:
    """The measured set's surface against the Phase-22 known-universe denominators (§35)."""
    covered = _covered_surface(inputs)
    exports = _exported_symbols(inputs)
    api_families_universe = {s.split("_", 1)[0] for s in exports if s}
    known = {
        "exported_symbols": int((inputs["symbol_ownership"].get("universe") or {}).get("exports") or 0),
        "public_functions": int(
            ((inputs["production_surface_reconciliation"].get("function_vs_symbol") or {})
             .get("declared_and_exported")) or 0),
        "headers": len(inputs["symbol_ownership"].get("headers") or {}),
        "api_families": len(api_families_universe),
    }
    measured = {
        "symbols": int(covered["symbol_count"]),
        "headers": int(covered["header_count"]),
        "api_families": int(covered["api_family_count"]),
    }
    ratios = {
        "exported_symbols": (round(measured["symbols"] / known["exported_symbols"], 6)
                              if known["exported_symbols"] else None),
        "headers": round(measured["headers"] / known["headers"], 6) if known["headers"] else None,
        "api_families": (round(measured["api_families"] / known["api_families"], 6)
                         if known["api_families"] else None),
    }
    return {
        "measured": {
            **measured,
            "label": ("measured: the unique public entities the committed usage fingerprints and "
                      "atlases record the counted consumers actually importing (execution/import "
                      "evidence)"),
            "surface_hash": covered["hash"],
        },
        "known_universe": {
            **known,
            "authority": inputs["implemented_surface"].get("authority"),
            "label": ("known universe: the Phase-22 authority atlases' exported symbols, exported "
                      "public functions, public headers and the API families derived from the "
                      "exported symbols"),
        },
        "ratios": ratios,
        "measured_vs_inferred": (
            "the measured surface is what the counted consumers are observed to import; the "
            "inferred surface is the Phase-22 reachability closure, which is inference from the "
            "committed reference graph and is never execution"
        ),
    }


def derive_phase22_projection(inputs: dict, coverage: dict) -> dict:
    """§34: directly-referenced public entities and graph-reachable inferred entities, separately."""
    closure = inputs["compatibility_closure"]
    counts = closure.get("counts") or {}
    views = inputs["compatibility_views"]
    return {
        "direct": {
            "label": ("directly-referenced public entities: the measured set's imported symbols, "
                      "headers and derived API families (execution/import evidence)"),
            "symbols": coverage["measured"]["symbols"],
            "headers": coverage["measured"]["headers"],
            "api_families": coverage["measured"]["api_families"],
            "source": "the committed 24.3 usage fingerprints and the 24.6/24.7/24.9 atlases",
        },
        "inferred": {
            "label": ("graph-reachable inferred internal entities: a read of the committed Phase-22 "
                      "reachability closure, which is inference and never execution"),
            "reachable_entities": int(counts.get("reachable_entities") or 0),
            "root_members": int(counts.get("root_members") or 0),
            "roots": int(counts.get("roots") or 0),
            "edges": int(counts.get("edges") or 0),
            "internal_symbols": int((inputs["internal_symbols"].get("universe") or {}).get("internal")
                                    or 0),
            "unpopulated_families": [str(u.get("family")) for u in closure.get("unpopulated") or []],
            "source": rel(COMPATIBILITY_CLOSURE),
        },
        "compatibility_views": {
            "views": len(views.get("views") or []),
            "by_status": _hist(v.get("status") for v in views.get("views") or []),
            "not_derivable": len(views.get("not_derivable") or []),
            "source": rel(COMPATIBILITY_VIEWS),
        },
        "separated": True,
        "never_summed": True,
        "note": ("reachability is reported beside direct use and never added to it: the two are "
                 "different evidence, and a reachability closure is not an execution"),
    }


def _union_find(names: list[str], edges: list[tuple[str, str]]) -> dict[str, str]:
    parent = {n: n for n in names}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in edges:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra
    return {n: find(n) for n in names}


def derive_clusters(inputs: dict) -> dict:
    """§36/§37: the marginal-consumer analysis and the usage clusters over the measured set."""
    fps = sorted(inputs["usage_fingerprints"].get("fingerprints") or [],
                 key=lambda f: str(f.get("canonical_name")))
    sets = {str(fp.get("canonical_name")): set(str(s) for s in fp.get("imported_openssl_symbols") or [])
            for fp in fps}
    names = sorted(sets)
    pairwise: list[dict] = []
    edges: list[tuple[str, str]] = []
    for a, b in itertools.combinations(names, 2):
        inter = len(sets[a] & sets[b])
        union = len(sets[a] | sets[b])
        jac = round(inter / union, 4) if union else 0.0
        pairwise.append({"a": a, "b": b, "jaccard": jac})
        if jac >= CLUSTER_THRESHOLD:
            edges.append((a, b))
    root = _union_find(names, edges)
    groups: dict[str, list[str]] = {}
    for n in names:
        groups.setdefault(root[n], []).append(n)
    clusters = sorted(
        ({"cluster_id": f"cluster:{min(members)}", "members": sorted(members),
          "size": len(members)} for members in groups.values()),
        key=lambda c: c["cluster_id"],
    )

    marginal: list[dict] = []
    for n in names:
        others: set[str] = set()
        for m in names:
            if m != n:
                others |= sets[m]
        marginal.append({
            "family": n,
            "symbols": len(sets[n]),
            "marginal_symbols": len(sets[n] - others),
        })
    marginal_consumers = sum(1 for m in marginal if m["marginal_symbols"] > 0)
    return {
        "method": ("connected components over the measured consumers by the Jaccard similarity of "
                   "their imported-symbol sets"),
        "threshold": CLUSTER_THRESHOLD,
        "fingerprinted_consumers": len(names),
        "consumers": names,
        "pairwise": pairwise,
        "clusters": clusters,
        "cluster_count": len(clusters),
        "marginal": marginal,
        "marginal_consumers": marginal_consumers,
        "redundant_consumers": len(marginal) - marginal_consumers,
        "distinct_stressors": len(clusters),
        "note": ("the counted population is 1,000 families, but only the families with a committed "
                 "usage fingerprint carry a measured surface; among those, the usage clusters are "
                 "the honest count of distinct stressors, so the families are not read as that many "
                 "independent consumers (the brief's sections 36 and 37)"),
    }


# ---------------------------------------------------------------------------------------------------
# the whole body (a pure function of the committed planes; the court re-derives it)
# ---------------------------------------------------------------------------------------------------

def _candidate_specific_patch_count(inputs: dict) -> int:
    total = 0
    for key in ("build_link", "runtime", "high_value", "hostility", "p1000_run"):
        for r in inputs[key].get("runs") or []:
            total += int(r.get("candidate_specific_patch_count") or 0)
    for r in (inputs["candidate_freeze"].get("holdout_run") or {}).get("runs") or []:
        total += int(r.get("candidate_specific_patch_count") or 0)
    return total


def derive_counts(verdicts, ladder, residuals, failures_summary, coverage, phase22,
                  clusters, inputs) -> dict:
    """Every count, computed from the derivation -- never typed."""
    return {
        "families": len(verdicts),
        "measurable_families": ladder["measurable_families"],
        "not_applicable_families": ladder["not_applicable_families"],
        "verdicts": _hist(v.get("verdict") for v in verdicts),
        "status": ladder["status"],
        "candidate_specific_patch_count": _candidate_specific_patch_count(inputs),
        "residuals_total": residuals["total"],
        "residuals_unresolved": residuals["unresolved"],
        "residuals_unknown": residuals["unknown"],
        "residuals_unclassified": residuals["unclassified"],
        "failures_p1000": failures_summary["p1000"]["total"],
        "failures_p1000_preserved": failures_summary["p1000"]["preserved"],
        "failures_hostility": failures_summary["hostility"]["total"],
        "failures_preserved": (failures_summary["p1000"]["preserved"]
                               + failures_summary["hostility"]["preserved"]),
        "coverage_symbols": coverage["measured"]["symbols"],
        "coverage_headers": coverage["measured"]["headers"],
        "coverage_api_families": coverage["measured"]["api_families"],
        "phase22_reachable_entities": phase22["inferred"]["reachable_entities"],
        "usage_clusters": clusters["cluster_count"],
        "distinct_stressors": clusters["distinct_stressors"],
        "marginal_consumers": clusters["marginal_consumers"],
    }


def _population(inputs: dict) -> dict:
    p1000 = _p1000(inputs)
    counts = inputs["family_freeze"].get("counts") or {}
    linkage = _hist(e.get("openssl_linkage") for e in p1000)
    return {
        "source": rel(FAMILY_FREEZE),
        "rule_id": (inputs["family_freeze"].get("rule") or {}).get("id"),
        "selection_root_hash": inputs["family_freeze"].get("selection_root_hash"),
        "families": len(p1000),
        "reserve": counts.get("reserve"),
        "universe": counts.get("universe"),
        "linkage": linkage,
        "all_direct": linkage.get("direct") == len(p1000),
        "selection": "a selected population of 1,000 families frozen before any candidate result",
    }


def reconcile(inputs: dict) -> dict:
    """Derive the whole reconciliation body from the committed planes. Pure and deterministic."""
    verdicts = derive_verdicts(inputs)
    ladder = derive_ladder(inputs, verdicts)
    residuals = derive_residuals(inputs)
    failures_summary = derive_failures_summary(inputs)
    rates = derive_rates(inputs, verdicts, ladder)
    coverage = derive_coverage(inputs)
    phase22 = derive_phase22_projection(inputs, coverage)
    clusters = derive_clusters(inputs)
    counts = derive_counts(verdicts, ladder, residuals, failures_summary, coverage, phase22,
                           clusters, inputs)
    body = {
        "rule": RULE,
        "population": _population(inputs),
        "verdicts": verdicts,
        "residuals": residuals,
        "failures_summary": failures_summary,
        "rates": rates,
        "ladder": ladder,
        "coverage": coverage,
        "phase22_projection": phase22,
        "clusters": clusters,
        "counts": counts,
        "non_claims": NON_CLAIMS,
    }
    prop = reconciliation_property(body)
    body["property_status"] = prop["property_status"]
    body["property_findings"] = prop["property_findings"]
    return body


# ---------------------------------------------------------------------------------------------------
# the property (the instrument passes; the property is honest about what the atlas carries)
# ---------------------------------------------------------------------------------------------------

def reconciliation_property(body: dict) -> dict:
    """The property the subphase names, and the gaps the atlas genuinely carries.

    A passing instrument is not the property: an atlas can be fully self-consistent and still speak
    for a thin slice, pose the drop-in question for few families, or carry a non-empty residual set.
    Those gaps are findings, and the property reads `NOT_CLAIMED` when any is present.
    """
    findings: list[str] = []
    lad = body.get("ladder") or {}
    total = int(lad.get("families") or 0)
    measurable = int(lad.get("measurable_families") or 0)
    if total and (total - measurable) * 2 >= total:
        findings.append(
            f"{total - measurable}/{total} counted families are DROP_IN_NOT_APPLICABLE: the frozen "
            f"venue admitted a pristine-source recipe and an authority-applicable baseline for only "
            f"{measurable} of {total}, so the drop-in rate is measured over {measurable} families "
            f"and is not a population-wide rate")
    cov = body.get("coverage") or {}
    measured = cov.get("measured") or {}
    known = cov.get("known_universe") or {}
    if known.get("exported_symbols") and measured.get("symbols") is not None:
        findings.append(
            f"the measured set exercised {measured.get('symbols')}/"
            f"{known.get('exported_symbols')} exported symbols, {measured.get('headers')}/"
            f"{known.get('headers')} public headers and {measured.get('api_families')}/"
            f"{known.get('api_families')} API families, so the atlas speaks for a thin slice of the "
            f"authority's public surface")
    counts = body.get("counts") or {}
    fs = body.get("failures_summary") or {}
    p1000 = fs.get("p1000") or {}
    host = fs.get("hostility") or {}
    findings.append(
        f"{p1000.get('total')} counted leftovers are classified and preserved "
        f"({p1000.get('candidate_specific')} candidate-specific, so {p1000.get('minimized')} "
        f"minimized reproducer(s)); the separate hostility corpus adds {host.get('total')} preserved "
        f"candidate failures excluded from every P1000 rate")
    if int(counts.get("residuals_unresolved") or 0):
        findings.append(
            f"{counts.get('residuals_unresolved')} unresolved residual(s) remain classified in the "
            f"closed vocabulary (unknown is 0), so the residual set is accounted for but not empty")
    status = "NOT_CLAIMED" if findings else "not_claimed"
    return {"property_status": status, "property_findings": findings}


# ---------------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefact (pure; never rebuilding)
# ---------------------------------------------------------------------------------------------------

def _diff(a, b, prefix: str = "") -> str:
    """The first differing dotted path between two derived structures, or '' when equal."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return f"{prefix}{k}"
            d = _diff(a[k], b[k], f"{prefix}{k}.")
            if d:
                return d
        return ""
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{prefix}(len {len(a)} vs {len(b)})"
        for i, (x, y) in enumerate(zip(a, b)):
            d = _diff(x, y, f"{prefix}{i}.")
            if d:
                return d
        return ""
    if a != b:
        return prefix.rstrip(".")
    return ""


def reconciliation_findings(inputs: dict, body: dict) -> list[str]:
    """Every way the recorded reconciliation fails its own subject, re-derived purely.

    The court re-derives the whole reconciliation from the committed planes and requires every
    derived field to agree with the recorded one; it additionally checks the load-bearing
    invariants by name -- one verdict per counted family with UNKNOWN 0, every residual classified
    with unknown 0, every failure preserved and the hostility failures scoped out of the P1000
    rates, the rates equal to the derived rates, the ladder equal to the verdict counts, the
    coverage and the Phase-22 projection consistent with the planes, and the counts derived rather
    than typed.
    """
    findings: list[str] = []
    derived = reconcile(inputs)
    p1000 = _p1000(inputs)
    members = {str(e.get("family_id")) for e in p1000}

    # 1. The recorded rule and non-claims are the frozen ones.
    if body.get("rule") != RULE:
        findings.append("the recorded rule is not the frozen reconciliation rule")
    if body.get("non_claims") != NON_CLAIMS:
        findings.append("the recorded non_claims are not the stratum's four plus the "
                        "selected-population non-claim")

    # 2. Coverage denominators: the admitted production authority is the one this module reads.
    if (inputs["implemented_surface"].get("authority")
            != PRODUCTION_AUTHORITY_DIR.name):
        findings.append("the implemented surface's authority does not name the production authority "
                        "directory the known-universe denominators are read from")

    # 3. Exactly one verdict per counted family, re-derived, with UNKNOWN 0.
    recorded = {v.get("family_id"): v for v in body.get("verdicts") or []}
    if len(recorded) != len(body.get("verdicts") or []):
        for fid in {v.get("family_id") for v in body.get("verdicts") or []}:
            if sum(1 for v in body.get("verdicts") or [] if v.get("family_id") == fid) > 1:
                findings.append(f"the counted family {fid} carries more than one verdict")
    missing = sorted(members - set(recorded))
    if missing:
        findings.append(f"{len(missing)} counted family(ies) have no verdict (e.g. {missing[:3]})")
    extra = sorted(set(recorded) - members)
    if extra:
        findings.append(f"{len(extra)} verdict(s) are for a family outside the frozen P1000 "
                        f"(e.g. {extra[:3]})")
    unknown = sum(1 for v in body.get("verdicts") or []
                  if str(v.get("verdict")) == "DROP_IN_UNKNOWN")
    if unknown:
        findings.append(f"{unknown} verdict(s) are DROP_IN_UNKNOWN; every counted family must be "
                        f"measured or honestly non-applicable")
    derived_v = {v["family_id"]: v for v in derived["verdicts"]}
    for fid in sorted(members & set(recorded)):
        rec = recorded[fid]
        want = derived_v.get(fid) or {}
        if rec.get("verdict") != want.get("verdict"):
            findings.append(f"verdict for {rec.get('canonical_name')} is {rec.get('verdict')!r}, "
                            f"not the derived {want.get('verdict')!r}")
        if rec.get("recorded_verdict") is not None \
                and rec.get("recorded_verdict") != want.get("recorded_verdict"):
            findings.append(f"verdict for {rec.get('canonical_name')} records the 24.12 verdict "
                            f"{rec.get('recorded_verdict')!r}, but the committed run records "
                            f"{want.get('recorded_verdict')!r}")

    # 4. Every residual classified, unclassified/unknown 0, each record schema-valid.
    if list(body.get("residuals", {}).get("classes") or []) != list(
            downstream_schemas.RESIDUAL_CLASSES):
        findings.append("the residual classes are not the closed residual vocabulary")
    for cls, want in derived["residuals"]["histogram"].items():
        got = (body.get("residuals", {}).get("histogram") or {}).get(cls)
        if got != want:
            findings.append(f"residuals.histogram[{cls}] {got!r} disagrees with the re-derived "
                            f"{want!r}")
    got_unknown = (body.get("residuals") or {}).get("unknown")
    if got_unknown != 0:
        findings.append(f"residuals.unknown is {got_unknown!r}, not 0: an unknown residual is a "
                        f"recorded class, never traded for confidence")
    got_unclass = (body.get("residuals") or {}).get("unclassified")
    if got_unclass != 0:
        findings.append(f"{got_unclass} residual(s) are not classified from the closed vocabulary")
    for rec in body.get("residuals", {}).get("records") or []:
        findings += [f"residual {rec.get('residual_id')}: {p}"
                     for p in downstream_schemas.validate_residual(rec)]
    observed = {c for c, n in derived["residuals"]["histogram"].items() if n}
    covered = {str(r.get("class")) for r in body.get("residuals", {}).get("records") or []}
    if not observed <= covered:
        findings.append(f"the residual records do not cover every observed class "
                        f"(missing {sorted(observed - covered)[:3]})")

    # 5. Every failure preserved; the hostility failures scoped out of the P1000 rates.
    for key in ("total", "preserved", "minimized", "candidate_specific", "by_failure_class",
                "by_disposition", "by_residual_class", "divergences"):
        got = (body.get("failures_summary", {}).get("p1000") or {}).get(key)
        want = derived["failures_summary"]["p1000"][key]
        if got != want:
            findings.append(f"failures_summary.p1000.{key} {got!r} disagrees with the re-derived "
                            f"{want!r}")
    if not (body.get("failures_summary", {}).get("all_preserved")):
        findings.append("a failure is not preserved: every discovered failure must be preserved")
    hp = body.get("failures_summary", {}).get("hostility") or {}
    if hp.get("total") != derived["failures_summary"]["hostility"]["total"]:
        findings.append(f"failures_summary.hostility.total {hp.get('total')!r} disagrees with the "
                        f"re-derived {derived['failures_summary']['hostility']['total']!r}")
    if hp.get("preserved") != hp.get("total"):
        findings.append("a hostility corpus failure is not preserved")
    if hp.get("records") != derived["failures_summary"]["hostility"]["records"]:
        findings.append("failures_summary.hostility.records are not the preserved hostility "
                        "candidate failure records")
    for rec in hp.get("records") or []:
        findings += [f"hostility failure {rec.get('failure_id')}: {p}"
                     for p in downstream_schemas.validate_failure(rec)]
    if any(str(v.get("family_id", "")).startswith("hostility:") for v in body.get("verdicts") or []):
        findings.append("a hostility corpus result is mixed into the P1000 verdicts")
    if (body.get("rates", {}).get("population") or {}).get("families") != len(p1000):
        findings.append("the P1000 rate denominator is not the frozen population")

    # 6. Zero candidate-specific patches (over every plane and the recorded count).
    if int((body.get("counts") or {}).get("candidate_specific_patch_count") or 0) != 0:
        findings.append("counts.candidate_specific_patch_count is not 0")

    # 7. Every other derived field agrees exactly with the re-derivation.
    for key in ("population", "residuals", "failures_summary", "rates", "ladder", "coverage",
                "phase22_projection", "clusters", "counts"):
        if body.get(key) != derived[key]:
            findings.append(f"{key} disagrees with the re-derived {key} at "
                            f"{_diff(body.get(key), derived[key]) or '<root>'}")

    # 8. The property status and findings are the derived ones (honest, never asserted).
    if body.get("property_status") != derived["property_status"]:
        findings.append(f"property_status {body.get('property_status')!r} disagrees with the "
                        f"derived {derived['property_status']!r}")
    if body.get("property_findings") != derived["property_findings"]:
        findings.append("property_findings disagree with the derived property findings")
    return findings


def _mutations(inputs: dict, body: dict) -> list[tuple[str, str, dict]]:
    """`(name, needle, mutated_body)` for each seeded mutation."""
    out: list[tuple[str, str, dict]] = []

    # (1) a counted family with no verdict.
    m1 = copy.deepcopy(body)
    if m1.get("verdicts"):
        m1["verdicts"] = m1["verdicts"][:-1]
    out.append(("counted_family_without_a_verdict", "have no verdict", m1))

    # (2) a residual left unknown.
    m2 = copy.deepcopy(body)
    m2["residuals"]["unknown"] = 1
    m2["residuals"]["histogram"]["unknown"] = 1
    out.append(("residual_left_unknown", "residuals.unknown", m2))

    # (3) a failure dropped from the summary.
    m3 = copy.deepcopy(body)
    m3["failures_summary"]["p1000"]["total"] -= 1
    out.append(("failure_dropped_from_summary", "failures_summary.p1000.total", m3))

    # (4) a hostility result mixed into the P1000 rate.
    m4 = copy.deepcopy(body)
    m4["verdicts"] = list(m4["verdicts"]) + [{
        "family_id": "hostility:static", "canonical_name": "hostility:static",
        "p1000_rank": None, "openssl_linkage": "direct", "directness_class": None,
        "verdict": "DROP_IN_PASS", "residual_class": "none",
        "authority_applicable_level": L4, "candidate_level": L4, "linkage_proven": True,
        "candidate_specific_patch_count": 0, "recorded_verdict": None,
    }]
    m4["rates"]["unweighted"]["PASS"]["count"] += 1
    out.append(("hostility_mixed_into_p1000_rate", "hostility", m4))

    # (5) a typed rate that disagrees with the verdicts.
    m5 = copy.deepcopy(body)
    m5["rates"]["unweighted"]["FAIL"]["count"] = 3
    out.append(("typed_rate_disagrees_with_verdicts", "rates", m5))

    # (6) a hostility failure recorded as not preserved.
    m6 = copy.deepcopy(body)
    if m6["failures_summary"]["hostility"]["records"]:
        m6["failures_summary"]["hostility"]["records"][0]["preserved"] = False
        m6["failures_summary"]["hostility"]["preserved"] -= 1
    out.append(("failure_not_preserved", "not preserved", m6))
    return out


def reconciliation_sensitivity_control(inputs: dict, body: dict) -> dict:
    """Prove the court can fail: seed six mutations and require each caught with specificity."""
    base = reconciliation_findings(inputs, body)
    control: dict = {"baseline_findings": len(base), "specificity_holds": not base}
    honest = not base
    for name, needle, mutated in _mutations(inputs, body):
        caught = any(needle in f for f in reconciliation_findings(inputs, mutated))
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
        InputRef(name="holdout", path=HOLDOUT),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="runtime-functional-atlas", path=RUNTIME_FUNCTIONAL_ATLAS),
        InputRef(name="failures", path=FAILURES),
        InputRef(name="high-value-tier", path=HIGH_VALUE_TIER),
        InputRef(name="hostility-corpus", path=HOSTILITY_CORPUS),
        InputRef(name="candidate-freeze", path=CANDIDATE_FREEZE),
        InputRef(name="p1000-run", path=P1000_RUN),
        InputRef(name="usage-fingerprints", path=USAGE_FINGERPRINTS),
        InputRef(name="families", path=FAMILIES),
        InputRef(name="candidates", path=CANDIDATES),
        InputRef(name="implemented-surface", path=IMPLEMENTED_SURFACE),
        InputRef(name="symbol-ownership", path=SYMBOL_OWNERSHIP),
        InputRef(name="internal-symbols", path=INTERNAL_SYMBOLS),
        InputRef(name="compatibility-closure", path=COMPATIBILITY_CLOSURE),
        InputRef(name="compatibility-views", path=COMPATIBILITY_VIEWS),
        InputRef(name="production-coverage", path=PRODUCTION_COVERAGE),
        InputRef(name="production-surface-reconciliation", path=PRODUCTION_SURFACE_RECON),
        InputRef(name="downstream-reconciliation",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_reconciliation.py"),
        InputRef(name="downstream-hostility",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_hostility.py"),
        InputRef(name="downstream-candidate-freeze",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_candidate_freeze.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]


def _missing_inputs() -> list[str]:
    required = [
        FAMILY_FREEZE, HOLDOUT, BUILD_LINK_ATLAS, RUNTIME_FUNCTIONAL_ATLAS, FAILURES,
        HIGH_VALUE_TIER, HOSTILITY_CORPUS, CANDIDATE_FREEZE, P1000_RUN, USAGE_FINGERPRINTS,
        FAMILIES, CANDIDATES, IMPLEMENTED_SURFACE, SYMBOL_OWNERSHIP, INTERNAL_SYMBOLS,
        COMPATIBILITY_CLOSURE, COMPATIBILITY_VIEWS, PRODUCTION_COVERAGE, PRODUCTION_SURFACE_RECON,
    ]
    return [rel(p) for p in required if not p.is_file()]


def write_outputs(body: dict) -> None:
    doc = envelope(kind="downstream-atlas-reconciliation", authority=PRODUCTION_AUTHORITY,
                   inputs=_inputs_list(), body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


def cmd_measure() -> int:
    if not FAMILY_FREEZE.is_file():
        print(f"[downstream-reconciliation] {rel(FAMILY_FREEZE)} is absent; run 24.4 first")
        return 1
    missing = _missing_inputs()
    if missing:
        print(f"[downstream-reconciliation] {', '.join(missing)} is absent; run the earlier "
              f"subphase(s) first")
        return 1
    inputs = load_inputs()
    body = reconcile(inputs)
    findings = reconciliation_findings(inputs, body)
    control = reconciliation_sensitivity_control(inputs, body)
    if findings or not control["honest"]:
        print("[downstream-reconciliation] the derived reconciliation fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body)
    c = body["counts"]
    lad = body["ladder"]
    r = body["rates"]["unweighted"]
    print(f"[downstream-reconciliation] families={c['families']} measurable="
          f"{c['measurable_families']} not_applicable={c['not_applicable_families']} "
          f"verdicts={lad['status']}")
    print(f"  unweighted: PASS={r['PASS']['count']}({r['PASS']['rate']}) "
          f"PARTIAL={r['PARTIAL']['count']}({r['PARTIAL']['rate']}) "
          f"FAIL={r['FAIL']['count']} UNKNOWN={r['UNKNOWN']['count']} "
          f"NOT_APPLICABLE={r['NOT_APPLICABLE']['count']}({r['NOT_APPLICABLE']['rate']})")
    print(f"  ladder: levels={lad['levels']} raw_family_count={lad['raw_family_count']} "
          f"UNKNOWN={lad['unknown']}")
    cov = body["coverage"]
    print(f"  coverage: symbols={cov['measured']['symbols']}/{cov['known_universe']['exported_symbols']}"
          f" headers={cov['measured']['headers']}/{cov['known_universe']['headers']} "
          f"api_families={cov['measured']['api_families']}/{cov['known_universe']['api_families']}")
    print(f"  residuals: total={body['residuals']['total']} unresolved="
          f"{body['residuals']['unresolved']} unknown={body['residuals']['unknown']} "
          f"failures: p1000={body['failures_summary']['p1000']['total']} "
          f"hostility={body['failures_summary']['hostility']['total']}")
    print(f"  clusters: {c['usage_clusters']} distinct_stressor(s) over "
          f"{body['clusters']['fingerprinted_consumers']} fingerprinted consumer(s); "
          f"marginal_consumers={c['marginal_consumers']}")
    print(f"  property_status={body['property_status']} findings="
          f"{len(body['property_findings'])}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check() -> int:
    if not OUT.is_file():
        print(f"[downstream-reconciliation] {rel(OUT)} is absent")
        return 1
    missing = _missing_inputs()
    if missing:
        print(f"[downstream-reconciliation] {', '.join(missing)} is absent")
        return 1
    inputs = load_inputs()
    body = _load_json(OUT)
    findings = reconciliation_findings(inputs, body)
    control = reconciliation_sensitivity_control(inputs, body)
    if findings:
        print(f"[downstream-reconciliation] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = body.get("counts") or {}
    print(f"[downstream-reconciliation] families={c.get('families')} "
          f"verdicts={(body.get('ladder') or {}).get('status')} "
          f"property_status={body.get('property_status')} findings={len(findings)} "
          f"control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_reconciliation.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_reconciliation.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. `reconciliation.json` is in the freeze's candidate-result artefact set, so a later freeze's
    #    scan excludes it exactly as it excludes the other post-freeze candidate artefacts.
    from downstream_freeze import CANDIDATE_RESULT_ARTEFACTS  # noqa: E402
    if "reconciliation.json" not in CANDIDATE_RESULT_ARTEFACTS:
        failures.append("reconciliation.json is not in downstream_freeze.CANDIDATE_RESULT_ARTEFACTS")

    # 3. The reuse: the 24.11 verdict rule and the 24.10 covered surface are the imported ones.
    if not hasattr(cf, "derive_verdict_for") or not hasattr(hostility, "covered_surface"):
        failures.append("the 24.11/24.10 machinery is not the imported one")

    # 4. The pure functions behave over the committed evidence.
    missing = _missing_inputs()
    if missing:
        failures.append(f"{', '.join(missing)} is absent")
    else:
        inputs = load_inputs()
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run --measure")
        else:
            body = _load_json(OUT)
            findings = reconciliation_findings(inputs, body)
            if findings:
                failures.append(f"the committed reconciliation has findings: {findings[:3]}")
            control = reconciliation_sensitivity_control(inputs, body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")
            if body.get("counts", {}).get("residuals_unknown") != 0:
                failures.append("the committed reconciliation reports a non-zero unknown residual "
                                "count")
            if body.get("ladder", {}).get("unknown") != 0:
                failures.append("the committed ladder reports a non-zero UNKNOWN")

    if failures:
        print("[downstream-reconciliation] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-reconciliation] self-test ok: the guard refuses a host invocation of this "
          "tool (marker and flag both named), the committed reconciliation reproduces with zero "
          "findings, the residual and ladder UNKNOWN counts are 0, and every seeded mutation (a "
          "counted family with no verdict, a residual left unknown, a dropped failure, a hostility "
          "result mixed into the P1000 rate, a typed rate that disagrees with the verdicts, and a "
          "failure not preserved) is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive the reconciliation from the committed planes and write it")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed reconciliation without regenerating")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool reads committed evidence and writes
    # one aggregate, so it executes nothing itself, but it is a Phase-24 entry point and a host
    # invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check()
    return cmd_measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
