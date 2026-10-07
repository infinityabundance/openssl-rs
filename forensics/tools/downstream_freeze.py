#!/usr/bin/env python3
"""openssl-rs — Phase-24.4 P1000 + reserve freeze: the population is frozen before any result.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over a
**frozen population of 1,000 counted families**. This module owns that freeze: it takes the 2,100
deduplicated project families 24.2 built (`forensics/downstream/families.json`) and the frozen 24.1
ranking evidence (`forensics/downstream/ranking-sources.json`), ranks the whole universe by a
recorded selection rule and cuts off the first 1,000 as the **P1000** and the remaining ranked tail
as the **reserve**.

The population is a pure function of committed evidence, frozen before any candidate result
---------------------------------------------------------------------------------------------
Nothing here reads a candidate outcome, and nothing here may: `docs/PHASE-24-DOWNSTREAM-1000-
SUBPHASES.md` section 3.4 says the population is frozen before any candidate result, so a family
typed into the 1,000 *because a candidate passed it* would be a rigged population. The freeze is a
pure function of the two committed inputs, and `freeze_findings` additionally scans the whole
downstream plane for a run or variant row with a candidate subject and fails if one is present --
so a candidate result existing at freeze time is a finding, not a silent influence.

The signal is reused, never re-implemented
------------------------------------------
The selection signal is the committed 24.3 consensus signal, imported from `downstream_census`
(`consensus_signal`) rather than restated here, so the freeze and the court re-derive it through the
same code path and the two can never drift. A family's signal is `source_breadth` (the number of
distinct `source_id`s in its `selection_provenance`), `distro_breadth` (the number of distinct
`ecosystem`s in its `distro_packages`) and `popularity` (the summed `value` over its
`popularity_signals`).

The frozen rule
---------------
The universe is sorted by `(-source_breadth, -distro_breadth, -popularity, canonical_name,
family_id)`; `family_id` is the final tiebreak, so the order is **total** and the cut is
deterministic. The first 1,000 families are the P1000; the entire remaining ranked tail is the
**reserve**, the precommitted replacement pool -- a family that later fails authority-baseline
admission is replaced by taking the next reserve family in frozen rank order, so no replacement is a
post-hoc choice. The rule is recorded verbatim in the artefact and re-derived by the court
`RT-FAMILY-FREEZE`.

The selection root binds the population to its inputs
-----------------------------------------------------
`selection_input_root` binds the frozen 24.1 `selection_input_root_hash`, the sha256 of the committed
`families.json`, and the sha256 of this tool's own recorded rule, through `atlas_common.content_hash`
into `selection_root_hash`; the court re-checks the recorded root reproduces and its components match
the committed files, so the population cannot be re-selected without changing the root.

The Docker-only guard is called first
--------------------------------------
This module reads committed evidence and writes one artefact; it executes nothing. Its `main` still
calls `phase24_guard.require_admitted()` first, so a host invocation is refused exactly as every
Phase-24 entry point is (`docs/REPRODUCIBILITY.md` section 1). `--self-test` proves the guard refuses
a host invocation of this tool, and `--check` re-runs the pure validation over the committed
artefact without regenerating.

Outputs
-------
  forensics/downstream/family-freeze.json   the frozen P1000 + reserve (a population, not results)

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
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

# The Docker-only execution guard. Its call is the first statement of `main`, exactly as it is for
# every Phase-24 entry point.
import phase24_guard  # noqa: E402

# The committed 24.3 consensus signal, imported rather than re-implemented so the freeze and the
# court re-derive the counted signal through the same code path (never a second, drifting predicate).
from downstream_census import consensus_signal  # noqa: E402

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
RANKING_SOURCES = REPO_ROOT / "forensics" / "downstream" / "ranking-sources.json"
OUT = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
DOWNSTREAM = REPO_ROOT / "forensics" / "downstream"
GENERATOR = "forensics/tools/downstream_freeze.py"

# The artefacts that legitimately carry **candidate results**, and are produced only **after** the
# freeze. 24.6's build/link atlas is the first: the freeze enables candidate execution, so the
# candidate rows it records are the measurement the freeze made possible, not a candidate result
# that existed *before* the freeze. The freeze-time scan (`candidate_subject_findings`) therefore
# excludes these artefacts -- the property that matters is that no candidate result existed at
# freeze time, and that is preserved -- while a candidate row in any other artefact is still a
# finding, and a fabricated row injected under any other path is still caught by the sensitivity
# control. The population's own frozen-before-any-candidate property is separately enforced: the
# freeze is a pure function of the committed families and ranking evidence, and the court re-derives
# 24.6 records this time-scoping correction
# (docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md section 4.9), rather than the freeze asking a later
# stratum's artefacts never to contain the candidate runs it enabled.
CANDIDATE_RESULT_ARTEFACTS = frozenset({
    "build-link-atlas.json",
    "runtime-functional-atlas.json",
    "failures.json",
    "high-value-tier.json",
    "hostility-corpus.json",
    "candidate-freeze.json",
    "p1000-run.json",
    "reconciliation.json",
})

# The P1000 size: the first 1,000 families of the ranked universe are the counted population, and
# the entire remaining ranked tail is the reserve. The constant is recorded in the artefact's rule.
P1000_SIZE = 1000

# The frozen selection rule, recorded verbatim in the artefact and re-derived by the court. The rank
# key is `(-source_breadth, -distro_breadth, -popularity, canonical_name, family_id)`: `family_id`
# last, so the order is total.
RULE: dict = {
    "id": "downstream-p1000-freeze/1",
    "name": "the downstream-1000 P1000 + reserve freeze",
    "rank_key": ["-source_breadth", "-distro_breadth", "-popularity", "canonical_name",
                 "family_id"],
    "signal": (
        "downstream_census.consensus_signal: source_breadth = number of distinct source_id in "
        "selection_provenance, distro_breadth = number of distinct ecosystem in distro_packages, "
        "popularity = sum of value over popularity_signals"
    ),
    "p1000_size": P1000_SIZE,
    "reserve_rule": "the remaining ranked tail",
    "tiebreak": "canonical_name then family_id last, so the ranked order is total",
    "constants": {"p1000_size": P1000_SIZE},
}

# The stratum's four non-claims, recorded on the population so a P1000 is never read as more than a
# selected population measured (docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md section 0).
NON_CLAIMS: list[str] = [
    "a selected population is not a random sample: the 1,000 families chosen from frozen ranking "
    "evidence are a selected population, and their rates do not generalise to all downstream "
    "software",
    "1000/1000 is not a security proof: a full pass is not a guarantee that any consumer is safe, "
    "and it makes no statement about an unmeasured consumer",
    "a build is not a functional proof: reaching the built or linked levels is not behaving, and "
    "only the functional levels are behavioural evidence",
    "transitive and direct consumers are different evidence: a project that only links a library "
    "transitively is a different measurement from one that calls the API directly, and the two are "
    "never summed",
]


# --------------------------------------------------------------------------------------------
# the frozen selection rule (pure; re-derived by the court)
# --------------------------------------------------------------------------------------------

def rank_key(fam: dict) -> tuple:
    """The frozen total sort the recorded rule makes over one family.

    `(-source_breadth, -distro_breadth, -popularity, canonical_name, family_id)`. The final
    `family_id` tiebreak is what makes the order total: no two families share a `family_id`, so the
    cut between the P1000 and the reserve is deterministic.
    """
    sig = consensus_signal(fam)
    return (-sig["source_breadth"], -sig["distro_breadth"], -sig["popularity"],
            str(fam.get("canonical_name")), str(fam.get("family_id")))


def ranked_universe(families_body: dict) -> list[dict]:
    """Every committed family, in the order the frozen rule induces."""
    families = families_body.get("families") or []
    return sorted(families, key=rank_key)


def _selection_input_root(rankings_body: dict) -> dict:
    """The frozen binding of the population to its inputs.

    The 24.1 `selection_input_root_hash`, the sha256 of the committed `families.json`, and the
    sha256 of this tool's own recorded rule, bound together so the population cannot be re-selected
    without changing the root.
    """
    return {
        "selection_input_root_hash": rankings_body.get("selection_input_root_hash"),
        "families_sha256": sha256_file(FAMILIES),
        "rule_sha256": content_hash(RULE),
    }


def derive_freeze(families_body: dict, rankings_body: dict) -> dict:
    """The `body` of the frozen P1000 + reserve, a pure function of the committed evidence."""
    ranked = ranked_universe(families_body)
    p1000_fams = ranked[:P1000_SIZE]
    reserve_fams = ranked[P1000_SIZE:]

    p1000 = []
    for i, fam in enumerate(p1000_fams, 1):
        sig = consensus_signal(fam)
        p1000.append({
            "p1000_rank": i,
            "family_id": str(fam.get("family_id")),
            "canonical_name": str(fam.get("canonical_name")),
            "openssl_linkage": fam.get("openssl_linkage"),
            "directness_class": fam.get("directness_class"),
            "selection_status": "selected",
            "source_breadth": sig["source_breadth"],
            "distro_breadth": sig["distro_breadth"],
            "popularity": sig["popularity"],
            "family_role": "p1000",
        })

    # The reserve is the whole remaining ranked tail, in rank order; `replacement_cursor` is the
    # 0-based index a later subphase takes the next reserve family from, so no replacement is a
    # post-hoc choice.
    reserve = []
    for i, fam in enumerate(reserve_fams, 1):
        sig = consensus_signal(fam)
        reserve.append({
            "reserve_rank": i,
            "family_id": str(fam.get("family_id")),
            "canonical_name": str(fam.get("canonical_name")),
            "openssl_linkage": fam.get("openssl_linkage"),
            "directness_class": fam.get("directness_class"),
            "replacement_cursor": i - 1,
            "source_breadth": sig["source_breadth"],
            "distro_breadth": sig["distro_breadth"],
            "popularity": sig["popularity"],
            "family_role": "reserve",
        })

    by_directness = {
        "direct": sum(1 for r in p1000 if r["openssl_linkage"] == "direct"),
        "transitive": sum(1 for r in p1000 if r["openssl_linkage"] == "transitive"),
    }
    counts = {
        "p1000": len(p1000),
        "reserve": len(reserve),
        "universe": len(ranked),
        "by_directness": by_directness,
        "candidate_results_present": False,
    }

    selection_input_root = _selection_input_root(rankings_body)
    return {
        "rule": RULE,
        "selection_input_root": selection_input_root,
        "selection_root_hash": content_hash(selection_input_root),
        "p1000": p1000,
        "reserve": reserve,
        "counts": counts,
        "non_claims": NON_CLAIMS,
    }


# --------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefact (pure; no candidate result ever)
# --------------------------------------------------------------------------------------------

def _families_by_id(families_body: dict) -> dict[str, dict]:
    return {str(f.get("family_id")): f for f in families_body.get("families") or []}


def _candidate_rows(doc: object, where: str) -> list[str]:
    """Every run/variant row in one document that carries a **candidate** subject.

    A `run` row names a subject, and a `subject: candidate` row is a candidate result; a `variant`
    row names a `patch_set`, and a `candidate-specific` variant is a candidate-side artifact. Both
    are candidate results that must not exist at freeze time (section 3.4).
    """
    out: list[str] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            if node.get("subject") == "candidate":
                out.append(f"{where}:{path} names subject `candidate`")
            if node.get("patch_set") == "candidate-specific":
                out.append(f"{where}:{path} is a `candidate-specific` variant")
            for k, v in node.items():
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, x in enumerate(node):
                walk(x, f"{path}[{i}]")

    walk(doc, "$")
    return out


def load_plane() -> list[tuple[str, object]]:
    """The committed **pre-freeze** downstream plane: every `forensics/downstream/*.json*` document,
    parsed, minus the candidate-result artefacts the stratum produces after the freeze (24.6 onward,
    the first being the build/link atlas). The candidate-subject scan this feeds asks whether a
    candidate result existed *before* the freeze, which is the property that matters, so the
    candidate runs the freeze enabled are not read as pre-freeze contamination. A fabricated
    candidate row injected under any other path is still caught (see `candidate_subject_findings`
    and the sensitivity control).
    """
    docs: list[tuple[str, object]] = []
    for path in sorted(DOWNSTREAM.glob("*.json*")):
        if path.name in CANDIDATE_RESULT_ARTEFACTS:
            continue
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".jsonl":
            docs.extend((rel(path), json.loads(line))
                        for line in text.splitlines() if line.strip())
        else:
            docs.append((rel(path), json.loads(text)))
    return docs


def candidate_subject_findings(plane: list[tuple[str, object]]) -> list[str]:
    """The finding for a candidate result existing anywhere in the downstream plane."""
    hits: list[str] = []
    for where, doc in plane:
        hits += _candidate_rows(doc, where)
    if not hits:
        return []
    return [f"candidate results present in the downstream plane before the freeze: {len(hits)} "
            f"candidate-subject row(s) ({'; '.join(hits[:3])})"]


def freeze_findings(families_body: dict, freeze_body: dict, *,
                    plane: list[tuple[str, object]] | None = None) -> list[str]:
    """Every way the recorded freeze fails to reproduce from the frozen families.

    Pure over the committed families body and the committed freeze body, so the court re-runs it
    without regenerating and the sensitivity control can mutate an in-memory copy. `plane` overrides
    the committed downstream plane the candidate-subject scan reads, so a fabricated candidate row
    can be injected in the control.
    """
    findings: list[str] = []
    families = families_body.get("families") or []
    by_id = _families_by_id(families_body)

    if len(families) < P1000_SIZE:
        findings.append(f"the committed families carry {len(families)} family(ies), fewer than the "
                        f"{P1000_SIZE} the P1000 selects")

    ranked = ranked_universe(families_body)
    derived_p1000 = ranked[:P1000_SIZE]
    derived_reserve = ranked[P1000_SIZE:]

    # The recorded rule is the frozen rule: a different rule would re-select the population.
    if freeze_body.get("rule") != RULE:
        findings.append("the recorded selection rule is not the frozen rule, so the population "
                        "could be re-selected without changing the rule")

    p1000 = freeze_body.get("p1000") or []
    reserve = freeze_body.get("reserve") or []
    counts = freeze_body.get("counts") or {}

    if len(p1000) != P1000_SIZE:
        findings.append(f"the recorded P1000 carries {len(p1000)} row(s), not the frozen "
                        f"{P1000_SIZE}")

    p1000_ids = [str(r.get("family_id")) for r in p1000]
    reserve_ids = [str(r.get("family_id")) for r in reserve]
    if len(set(p1000_ids)) != len(p1000_ids):
        dup = sorted({fid for fid in p1000_ids if p1000_ids.count(fid) > 1})
        findings.append(f"the recorded P1000 names a family twice: {dup[:3]}")
    overlap = sorted(set(p1000_ids) & set(reserve_ids))
    if overlap:
        findings.append(f"{overlap[0]} is in both the P1000 and the reserve: the two must be "
                        f"disjoint (overlap {overlap[:3]})")
    outside = sorted((set(p1000_ids) | set(reserve_ids)) - set(by_id))
    for fid in outside:
        findings.append(f"{fid} is in the freeze but not in the committed family universe")

    # The P1000 is the derived top-1,000 and the reserve the derived remainder, both in rank order.
    got_p = [(str(r.get("family_id")), str(r.get("canonical_name"))) for r in p1000]
    want_p = [(str(f.get("family_id")), str(f.get("canonical_name"))) for f in derived_p1000]
    if got_p != want_p:
        findings.append("the recorded P1000 does not reproduce from the frozen families by the "
                        f"frozen rank key (recorded {len(got_p)}, derived {len(want_p)})")
    got_r = [(str(r.get("family_id")), str(r.get("canonical_name"))) for r in reserve]
    want_r = [(str(f.get("family_id")), str(f.get("canonical_name"))) for f in derived_reserve]
    if got_r != want_r:
        findings.append("the recorded reserve does not reproduce from the frozen families by the "
                        f"frozen rank key (recorded {len(got_r)}, derived {len(want_r)})")

    # Ranks are positions, roles are named, and every recorded signal is the family's own.
    for i, row in enumerate(p1000, 1):
        fid = str(row.get("family_id"))
        if row.get("p1000_rank") != i:
            findings.append(f"P1000 member {fid} records p1000_rank {row.get('p1000_rank')!r}, "
                            f"not its position {i}")
        if row.get("family_role") != "p1000":
            findings.append(f"P1000 member {fid} records family_role {row.get('family_role')!r}, "
                            f"not `p1000`")
        if row.get("selection_status") != "selected":
            findings.append(f"P1000 member {fid} records selection_status "
                            f"{row.get('selection_status')!r}, not `selected`")
        fam = by_id.get(fid)
        if fam is None:
            continue
        sig = consensus_signal(fam)
        for field in ("source_breadth", "distro_breadth", "popularity"):
            if row.get(field) != sig[field]:
                findings.append(f"{fid}: recorded {field} {row.get(field)!r} disagrees with the "
                                f"family's consensus signal {sig[field]!r}")
        if row.get("openssl_linkage") != fam.get("openssl_linkage"):
            findings.append(f"{fid}: recorded openssl_linkage {row.get('openssl_linkage')!r} "
                            f"disagrees with the family")
        if row.get("directness_class") != fam.get("directness_class"):
            findings.append(f"{fid}: recorded directness_class {row.get('directness_class')!r} "
                            f"disagrees with the family")

    for i, row in enumerate(reserve, 1):
        fid = str(row.get("family_id"))
        if row.get("reserve_rank") != i:
            findings.append(f"reserve member {fid} records reserve_rank {row.get('reserve_rank')!r}"
                            f", not its position {i}")
        if row.get("replacement_cursor") != i - 1:
            findings.append(f"reserve member {fid} records replacement_cursor "
                            f"{row.get('replacement_cursor')!r}, not its position {i - 1}")
        if row.get("family_role") != "reserve":
            findings.append(f"reserve member {fid} records family_role {row.get('family_role')!r}"
                            f", not `reserve`")
        fam = by_id.get(fid)
        if fam is None:
            continue
        sig = consensus_signal(fam)
        for field in ("source_breadth", "distro_breadth", "popularity"):
            if row.get(field) != sig[field]:
                findings.append(f"{fid}: reserve {field} {row.get(field)!r} disagrees with the "
                                f"family's consensus signal {sig[field]!r}")

    # The selection root reproduces, and its bound components match the committed files.
    sir = freeze_body.get("selection_input_root") or {}
    if not RANKING_SOURCES.is_file():
        findings.append(f"{rel(RANKING_SOURCES)} is absent, so the frozen selection input root "
                        f"cannot be re-checked")
    else:
        committed_root = json.loads(RANKING_SOURCES.read_text(encoding="utf-8"))["body"].get(
            "selection_input_root_hash")
        if sir.get("selection_input_root_hash") != committed_root:
            findings.append("the recorded selection_input_root.selection_input_root_hash does not "
                            "match the committed 24.1 selection_input_root_hash")
    if FAMILIES.is_file() and sir.get("families_sha256") != sha256_file(FAMILIES):
        findings.append("the recorded selection_input_root.families_sha256 does not match the "
                        "committed families.json")
    if sir.get("rule_sha256") != content_hash(freeze_body.get("rule")):
        findings.append("the recorded selection_input_root.rule_sha256 does not bind the recorded "
                        "rule")
    if freeze_body.get("selection_root_hash") != content_hash(sir):
        findings.append("the recorded selection_root_hash does not reproduce from its bound "
                        "components")

    # Counts are read, not typed.
    if counts.get("p1000") != len(p1000):
        findings.append(f"counts.p1000 {counts.get('p1000')!r} disagrees with the {len(p1000)} "
                        f"recorded P1000 row(s)")
    if counts.get("reserve") != len(reserve):
        findings.append(f"counts.reserve {counts.get('reserve')!r} disagrees with the "
                        f"{len(reserve)} recorded reserve row(s)")
    if counts.get("universe") != len(families):
        findings.append(f"counts.universe {counts.get('universe')!r} disagrees with the "
                        f"{len(families)} committed family record(s)")
    derived_by_directness = {
        "direct": sum(1 for r in p1000 if r.get("openssl_linkage") == "direct"),
        "transitive": sum(1 for r in p1000 if r.get("openssl_linkage") == "transitive"),
    }
    if counts.get("by_directness") != derived_by_directness:
        findings.append("counts.by_directness disagrees with the recorded P1000 rows, or sums the "
                        "direct and transitive counts, which are never summed")
    if counts.get("candidate_results_present"):
        findings.append("counts.candidate_results_present is true, but the freeze records the "
                        "population before any candidate result")

    # The population is frozen before any candidate result: no candidate-subject row may exist.
    plane_docs = load_plane() if plane is None else plane
    findings += candidate_subject_findings(plane_docs)
    return findings


def _mutations(families_body: dict, freeze_body: dict, plane: list[tuple[str, object]]
               ) -> list[tuple[str, str, dict, dict, list[tuple[str, object]]]]:
    """`(name, needle, mutated_families, mutated_freeze, mutated_plane)` for each seeded mutation."""
    out: list[tuple[str, str, dict, dict, list[tuple[str, object]]]] = []

    # (1) two P1000 members' rows swapped, so the recorded order disagrees with the derived order.
    m1 = copy.deepcopy(freeze_body)
    rows = m1.get("p1000") or []
    if len(rows) >= 2:
        rows[0], rows[1] = rows[1], rows[0]
    out.append(("p1000_order_swapped", "does not reproduce from the frozen families",
                families_body, m1, plane))

    # (2) one P1000 member deleted, so the count is no longer 1,000.
    m2 = copy.deepcopy(freeze_body)
    m2["p1000"] = (m2.get("p1000") or [])[:-1]
    out.append(("p1000_short", "not the frozen 1000", families_body, m2, plane))

    # (3) a family id shared between the P1000 and the reserve.
    m3 = copy.deepcopy(freeze_body)
    if m3.get("p1000") and m3.get("reserve"):
        m3["reserve"][0]["family_id"] = m3["p1000"][0]["family_id"]
    out.append(("p1000_reserve_overlap", "both the P1000 and the reserve",
                families_body, m3, plane))

    # (4) a mutated selection root.
    m4 = copy.deepcopy(freeze_body)
    m4["selection_root_hash"] = "0" * 64
    out.append(("mutated_selection_root", "selection_root_hash", families_body, m4, plane))

    # (5) a fabricated candidate-subject run row injected into the downstream plane.
    injected = list(plane) + [(
        f"{rel(DOWNSTREAM)}/fabricated.jsonl",
        {"run_id": "r-fabricated-candidate", "specimen_id": "s-fabricated",
         "variant_id": "v-fabricated", "subject": "candidate", "level": "L4-linked",
         "outcome": "reached", "residual_class": "none", "evidence": []},
    )]
    out.append(("candidate_result_present", "candidate results present",
                families_body, freeze_body, injected))
    return out


def freeze_sensitivity_control(families_body: dict, freeze_body: dict, *,
                               plane: list[tuple[str, object]] | None = None) -> dict:
    """Prove the court can fail: seed five mutations and require each to be caught.

    The honest freeze must yield **zero** findings (specificity), and each seeded mutation -- two
    P1000 members' order swapped, a P1000 member deleted so the count is wrong, a family id shared
    between the P1000 and the reserve, a mutated selection root, and a fabricated candidate-subject
    run row in the downstream plane -- must be caught with a finding that names what it is.
    """
    plane_docs = load_plane() if plane is None else plane
    base = freeze_findings(families_body, freeze_body, plane=plane_docs)
    specificity = not base
    control: dict = {"baseline_findings": len(base), "specificity_holds": specificity}
    honest = specificity
    for name, needle, mf, mfr, mplane in _mutations(families_body, freeze_body, plane_docs):
        caught = any(needle in f for f in freeze_findings(mf, mfr, plane=mplane))
        control[f"injected_{name}"] = name
        control[f"caught_{name}"] = caught
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# --------------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------------

def _inputs() -> list[InputRef]:
    return [
        InputRef(name="families", path=FAMILIES),
        InputRef(name="ranking-sources", path=RANKING_SOURCES),
        InputRef(name="downstream-census",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_census.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]


def cmd_generate() -> int:
    if not (FAMILIES.is_file() and RANKING_SOURCES.is_file()):
        missing = [rel(p) for p in (FAMILIES, RANKING_SOURCES) if not p.is_file()]
        print(f"[downstream-freeze] {', '.join(missing)} is absent; run 24.2/24.3 first")
        return 1
    families_doc = json.loads(FAMILIES.read_text(encoding="utf-8"))
    families_body = families_doc["body"]
    rankings_body = json.loads(RANKING_SOURCES.read_text(encoding="utf-8"))["body"]
    body = derive_freeze(families_body, rankings_body)

    findings = freeze_findings(families_body, body)
    control = freeze_sensitivity_control(families_body, body)
    if findings or not control["honest"]:
        print("[downstream-freeze] the derived freeze fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1

    authority = families_doc.get("authority") or PRODUCTION_AUTHORITY
    doc = envelope(kind="downstream-family-freeze", authority=authority, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[downstream-freeze] universe={c['universe']} p1000={c['p1000']} "
          f"reserve={c['reserve']} by_directness={c['by_directness']} "
          f"candidate_results_present={c['candidate_results_present']}")
    print(f"  selection_root_hash={body['selection_root_hash']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check() -> int:
    """Re-run the pure validation over the committed freeze without regenerating."""
    if not (FAMILIES.is_file() and OUT.is_file()):
        missing = [rel(p) for p in (FAMILIES, OUT) if not p.is_file()]
        print(f"[downstream-freeze] {', '.join(missing)} is absent")
        return 1
    families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    freeze_body = json.loads(OUT.read_text(encoding="utf-8"))["body"]
    findings = freeze_findings(families_body, freeze_body)
    control = freeze_sensitivity_control(families_body, freeze_body)
    if findings:
        print(f"[downstream-freeze] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = freeze_body.get("counts") or {}
    print(f"[downstream-freeze] universe={c.get('universe')} p1000={c.get('p1000')} "
          f"reserve={c.get('reserve')} findings={len(findings)} "
          f"control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_freeze.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_freeze.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. The pure functions behave over the committed evidence.
    if not FAMILIES.is_file():
        failures.append(f"{rel(FAMILIES)} is absent")
    else:
        families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
        ranked = ranked_universe(families_body)
        if len(ranked) < P1000_SIZE:
            failures.append(f"the committed universe carries {len(ranked)} family(ies), fewer "
                            f"than the {P1000_SIZE} the P1000 selects")
        ids = [str(f.get("family_id")) for f in families_body.get("families") or []]
        if len(set(ids)) != len(ids):
            failures.append("the committed universe has duplicate family_id, so the order is not "
                            "total")
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run the generator")
        else:
            freeze_body = json.loads(OUT.read_text(encoding="utf-8"))["body"]
            findings = freeze_findings(families_body, freeze_body)
            if findings:
                failures.append(f"the committed freeze has findings: {findings[:3]}")
            control = freeze_sensitivity_control(families_body, freeze_body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[downstream-freeze] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-freeze] self-test ok: the guard refuses a host invocation of this tool "
          "(marker and flag both named), the committed P1000+reserve reproduces with zero findings, "
          "and every seeded mutation (order swap, short P1000, P1000/reserve overlap, mutated "
          "selection root, fabricated candidate result) is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="validate the committed freeze without regenerating (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first, exactly as every Phase-24 entry point does.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check()
    return cmd_generate()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
