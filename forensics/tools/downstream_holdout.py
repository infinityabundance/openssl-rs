#!/usr/bin/env python3
"""openssl-rs — Phase-24.5 holdout partition: the split is fixed before any candidate result.

Phase 24's development cohort is what the compatibility defects are found and fixed against; the
**holdout** is the part of the frozen P1000 that is *never* looked at while a patch is chosen, and is
run against the frozen candidate **exactly once** (that run is 24.11). For that to be a real
out-of-sample measurement the split must be fixed **before** any candidate result exists, and by a
rule that names no candidate outcome. This module owns that precommitment: it takes the frozen P1000
from `forensics/downstream/family-freeze.json` (the 24.4 population, already in frozen rank order)
and partitions it by a recorded rule into 800 development / 200 holdout families.

The partition rule, frozen before the holdout is ever run
---------------------------------------------------------
The rule is a pure function of the frozen P1000 and a seed string, and is recorded verbatim in the
artefact and re-derived by the court `RT-HOLDOUT-PARTITION`:

  * the strata are **rank bands of 100** over the frozen P1000 ranks 1..1000: band `b` in 1..10
    covers ranks `100*(b-1)+1 .. 100*b`;
  * within a band the 100 families are ordered by `content_hash(PARTITION_SEED + ":" + family_id)`
    ascending, tiebroken by `family_id`, and the first `HOLDOUT_PER_BAND = 20` are **holdout** and
    the remaining 80 **development**.

So the partition is exactly 200 holdout / 800 development, 20/80 in every band, and reproducible
from the seed and the frozen population alone. `PARTITION_SEED = "phase24-holdout-v1"` and
`HOLDOUT_FRACTION = "1/5"`.

What the rule does **not** stratify, recorded honestly
-----------------------------------------------------
All 1000 frozen families are `direct`, so a direct/transitive split is **degenerate** -- the rule
records that observation rather than pretending there is a direct/transitive distinction. Usage
clusters do not exist at freeze time (they are computed later, in the runtime/functional atlas), so
`usage_cluster_stratification` reads `"unavailable at freeze time"` and no usage cluster is invented.

The partition is a pure function of the frozen P1000, frozen before any candidate result
--------------------------------------------------------------------------------------------
Nothing here reads a candidate outcome, and nothing here may: a holdout selected *after* seeing a
candidate failure would make the out-of-sample measurement a fiction. `holdout_findings` fails if
the partition references **any family outside the frozen P1000**, and reuses
`downstream_freeze.candidate_subject_findings` (and its plane loader) -- the same predicate 24.4
uses -- to fail if **any candidate-subject run exists in the downstream plane**, so a candidate
result existing at freeze time is a finding, not a silent influence.

The Docker-only guard is called first
--------------------------------------
This module reads committed evidence and writes one artefact; it executes nothing. Its `main` still
calls `phase24_guard.require_admitted()` first, so a host invocation is refused exactly as every
Phase-24 entry point is (`docs/REPRODUCIBILITY.md` section 1). `--self-test` proves the guard refuses
a host invocation of this tool, and `--check` re-runs the pure validation over the committed
artefact without regenerating.

Outputs
-------
  forensics/downstream/holdout.json   the precommitted development/holdout partition (not results)

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
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`, exactly as it is for
# every Phase-24 entry point.
import phase24_guard  # noqa: E402

# The 24.4 freeze tool, imported so the candidate-subject scan and the downstream-plane loader the
# partition re-checks are the **same** predicate the freeze uses, never a second, drifting one. The
# stratum's four non-claims are imported for the same reason: the partition carries them, and its
# own extra non-claim, so the two cannot disagree about what the model never claims.
from downstream_freeze import (  # noqa: E402
    NON_CLAIMS as STRATUM_NON_CLAIMS,
    candidate_subject_findings,
    load_plane,
)

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
OUT = REPO_ROOT / "forensics" / "downstream" / "holdout.json"
DOWNSTREAM = REPO_ROOT / "forensics" / "downstream"
GENERATOR = "forensics/tools/downstream_holdout.py"

# The frozen partition constants, recorded verbatim in the artefact (rule) and re-derived by the
# court. `PARTITION_SEED` salts the content hash that orders each band; `HOLDOUT_PER_BAND` is the
# holdout size in every band of 100, so the partition is 20/80 per band and 200/800 overall.
PARTITION_SEED = "phase24-holdout-v1"
HOLDOUT_FRACTION = "1/5"
HOLDOUT_PER_BAND = 20
BAND_SIZE = 100
BANDS = 10
P1000_SIZE = 1000

# The frozen partition rule, recorded verbatim in the artefact and re-derived by the court. The
# honest `usage_cluster_stratification` note records what the rule does **not** stratify: usage
# clusters do not exist at freeze time, and the directness split is degenerate because all 1000
# frozen families are `direct`.
RULE: dict = {
    "id": "downstream-holdout-partition/1",
    "name": "the precommitted holdout partition of the frozen P1000",
    "seed": PARTITION_SEED,
    "fraction": HOLDOUT_FRACTION,
    "band_structure": (
        "rank band of 100: band b in 1..10 covers frozen P1000 ranks 100*(b-1)+1 .. 100*b"
    ),
    "band_size": BAND_SIZE,
    "bands": BANDS,
    "per_band_holdout": HOLDOUT_PER_BAND,
    "ordering": (
        "within each band, order the 100 families by content_hash(PARTITION_SEED + ':' + "
        "family_id) ascending, tiebreak by family_id; the first per_band_holdout are holdout and "
        "the remaining are development"
    ),
    "directness_stratification": (
        "degenerate: all 1000 frozen families are `direct`, so a direct/transitive split carries "
        "no information and is not pretended"
    ),
    "usage_cluster_stratification": (
        "unavailable at freeze time: usage clusters are computed later, in the runtime/functional "
        "atlas, so the partition is stratified by rank band only and no usage cluster is invented"
    ),
    "constants": {
        "partition_seed": PARTITION_SEED,
        "holdout_fraction": HOLDOUT_FRACTION,
        "holdout_per_band": HOLDOUT_PER_BAND,
        "band_size": BAND_SIZE,
        "bands": BANDS,
        "p1000_size": P1000_SIZE,
    },
}

# The stratum's four non-claims (imported from 24.4 so the two cannot drift) plus the one this
# stratum adds: the holdout is a precommitted subset of a selected population, never a random
# sample of downstream software.
NON_CLAIMS: list[str] = list(STRATUM_NON_CLAIMS) + [
    "the holdout is not a random sample of downstream software: it is a precommitted subset of a "
    "selected population, so a holdout pass rate is a measurement of that subset and does not "
    "generalise to the whole ecosystem",
]


# --------------------------------------------------------------------------------------------
# the frozen partition rule (pure; re-derived by the court)
# --------------------------------------------------------------------------------------------

def band_of(rank: int) -> int:
    """The rank band of one frozen P1000 position: band `b` covers ranks `100*(b-1)+1 .. 100*b`."""
    return (rank - 1) // BAND_SIZE + 1


def order_key(family_id: str) -> tuple:
    """The frozen ordering within a band: `content_hash(seed:family_id)` ascending, then family_id.

    `family_id` last makes the order total, so the cut between holdout and development in a band is
    deterministic even if two salted hashes collide.
    """
    return (content_hash(f"{PARTITION_SEED}:{family_id}"), str(family_id))


def classify_p1000(p1000: list[dict]) -> dict[str, str]:
    """`family_id -> `holdout`/`development` for every frozen P1000 family, by the frozen rule."""
    by_band: dict[int, list[dict]] = {}
    for row in p1000:
        by_band.setdefault(band_of(int(row["p1000_rank"])), []).append(row)
    cohort: dict[str, str] = {}
    for members in by_band.values():
        ordered = sorted(members, key=lambda r: order_key(str(r.get("family_id"))))
        for i, row in enumerate(ordered):
            cohort[str(row.get("family_id"))] = (
                "holdout" if i < HOLDOUT_PER_BAND else "development"
            )
    return cohort


def p1000_tag(freeze_body: dict) -> dict:
    """The frozen P1000 tag the partition root binds, so the root names the population it divided.

    It binds the freeze's own `selection_root_hash`, the content hash of the frozen P1000 member
    list, and the P1000 size, so the partition root cannot be reproduced against a different
    population under the same rule.
    """
    p1000 = freeze_body.get("p1000") or []
    return {
        "source": "forensics/downstream/family-freeze.json",
        "selection_root_hash": freeze_body.get("selection_root_hash"),
        "p1000_content_hash": content_hash(p1000),
        "p1000_size": len(p1000),
    }


def derive_partition(freeze_body: dict) -> tuple[list[dict], list[dict]]:
    """The `(development, holdout)` rows, each list in frozen rank order, a pure function of the P1000.

    Every row is `{p1000_rank, band, family_id, canonical_name, openssl_linkage, cohort}`, and the
    two cohorts together are exactly the frozen P1000, split by `classify_p1000`.
    """
    p1000 = freeze_body.get("p1000") or []
    cohort = classify_p1000(p1000)
    development: list[dict] = []
    holdout: list[dict] = []
    for row in p1000:  # already frozen rank order 1..1000
        fid = str(row.get("family_id"))
        rank = int(row["p1000_rank"])
        c = cohort[fid]
        rec = {
            "p1000_rank": rank,
            "band": band_of(rank),
            "family_id": fid,
            "canonical_name": str(row.get("canonical_name")),
            "openssl_linkage": row.get("openssl_linkage"),
            "cohort": c,
        }
        (holdout if c == "holdout" else development).append(rec)
    return development, holdout


def _partition_root(rule: dict, development: list[dict], holdout: list[dict], tag: dict) -> str:
    """`content_hash(rule + the two cohorts + the frozen P1000 tag)`, the partition's root."""
    return content_hash({
        "rule": rule,
        "development": development,
        "holdout": holdout,
        "p1000_tag": tag,
    })


def derive_holdout(freeze_body: dict) -> dict:
    """The `body` of the precommitted holdout partition, a pure function of the frozen P1000."""
    development, holdout = derive_partition(freeze_body)
    tag = p1000_tag(freeze_body)
    counts = {
        "p1000": len(freeze_body.get("p1000") or []),
        "development": len(development),
        "holdout": len(holdout),
        "per_band_holdout": HOLDOUT_PER_BAND,
    }
    return {
        "rule": RULE,
        "p1000_tag": tag,
        "partition": {"development": development, "holdout": holdout},
        "partition_root_hash": _partition_root(RULE, development, holdout, tag),
        "counts": counts,
        "holdout_status": "unopened",
        "non_claims": NON_CLAIMS,
    }


# --------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefact (pure; no candidate result ever)
# --------------------------------------------------------------------------------------------

def _families_by_id(families_body: dict) -> dict[str, dict]:
    return {str(f.get("family_id")): f for f in families_body.get("families") or []}


def holdout_findings(families_body: dict, freeze_body: dict, holdout_body: dict, *,
                     plane: list[tuple[str, object]] | None = None) -> list[str]:
    """Every way the recorded partition fails to reproduce from the frozen P1000.

    Pure over the committed families body, the frozen P1000 body and the committed holdout body, so
    the court re-runs it without regenerating and the sensitivity control can mutate an in-memory
    copy. `plane` overrides the committed downstream plane the candidate-subject scan reads, so a
    fabricated candidate row can be injected in the control.
    """
    findings: list[str] = []
    by_id = _families_by_id(families_body)

    p1000 = freeze_body.get("p1000") or []
    p1000_ids = [str(r.get("family_id")) for r in p1000]
    p1000_id_set = set(p1000_ids)
    rank_of = {str(r.get("family_id")): int(r["p1000_rank"])
               for r in p1000 if r.get("p1000_rank") is not None}
    freeze_row = {str(r.get("family_id")): r for r in p1000}

    if len(p1000) != P1000_SIZE:
        findings.append(f"the frozen P1000 carries {len(p1000)} row(s), not the frozen "
                        f"{P1000_SIZE} the partition divides")

    # The recorded rule is the frozen rule: a different rule would re-divide the population.
    if holdout_body.get("rule") != RULE:
        findings.append("the recorded partition rule is not the frozen rule, so the partition "
                        "could be re-divided without changing the rule")

    partition = holdout_body.get("partition") or {}
    dev = partition.get("development") or []
    hol = partition.get("holdout") or []
    counts = holdout_body.get("counts") or {}

    dev_ids = [str(r.get("family_id")) for r in dev]
    hol_ids = [str(r.get("family_id")) for r in hol]
    recorded_ids = dev_ids + hol_ids

    # Every family_id must be a real committed family.
    for fid in recorded_ids:
        if fid not in by_id:
            findings.append(f"{fid} is in the partition but not in the committed family universe")

    # No family_id may appear more than once across the two cohorts combined.
    seen: dict[str, int] = {}
    for fid in recorded_ids:
        seen[fid] = seen.get(fid, 0) + 1
    for fid, n in seen.items():
        if n > 1:
            findings.append(f"family_id {fid} appears {n} times across the two cohorts, not exactly "
                            f"once")

    # The two cohorts must be disjoint.
    for fid in sorted(set(dev_ids) & set(hol_ids)):
        findings.append(f"{fid} is in both the development and the holdout cohort: they must be "
                        f"disjoint")

    # The two cohorts must union to exactly the frozen P1000: no missing, no extra.
    union = set(recorded_ids)
    missing = sorted(p1000_id_set - union)
    if missing:
        findings.append(f"the two cohorts do not union to the frozen P1000: {len(missing)} P1000 "
                        f"family(ies) missing ({missing[:3]})")
    for fid in sorted(union - p1000_id_set):
        findings.append(f"{fid} is outside the frozen P1000: the partition must be a pure function "
                        f"of the frozen P1000")

    # The cohorts must reproduce from the frozen rule, per family.
    cohort = classify_p1000(p1000)
    for row in dev + hol:
        fid = str(row.get("family_id"))
        recorded = row.get("cohort")
        if fid in cohort and recorded != cohort[fid]:
            findings.append(f"{fid} is recorded {recorded}, but the frozen rule assigns it "
                            f"{cohort[fid]}")

    # Each band must contribute exactly 20 holdout and 80 development.
    band_holdout = {b: 0 for b in range(1, BANDS + 1)}
    band_dev = {b: 0 for b in range(1, BANDS + 1)}
    for row in hol:
        b = row.get("band")
        if b in band_holdout:
            band_holdout[b] += 1
    for row in dev:
        b = row.get("band")
        if b in band_dev:
            band_dev[b] += 1
    for b in range(1, BANDS + 1):
        if band_holdout[b] != HOLDOUT_PER_BAND or band_dev[b] != BAND_SIZE - HOLDOUT_PER_BAND:
            findings.append(f"band {b} contributes {band_holdout[b]} holdout and {band_dev[b]} "
                            f"development, not the frozen {HOLDOUT_PER_BAND}/"
                            f"{BAND_SIZE - HOLDOUT_PER_BAND}")

    # Each cohort must be in frozen rank order.
    for rows, label in ((dev, "development"), (hol, "holdout")):
        ranks = [r.get("p1000_rank") for r in rows]
        if ranks != sorted(ranks):
            findings.append(f"the {label} cohort is not in frozen rank order")

    # Ranks are positions, bands follow from the rank, and the copied fields are the P1000's own.
    for row in dev + hol:
        fid = str(row.get("family_id"))
        if fid in rank_of:
            if row.get("p1000_rank") != rank_of[fid]:
                findings.append(f"{fid} records p1000_rank {row.get('p1000_rank')!r}, not its "
                                f"frozen rank {rank_of[fid]}")
            if row.get("band") != band_of(rank_of[fid]):
                findings.append(f"{fid} records band {row.get('band')!r}, not the band "
                                f"{band_of(rank_of[fid])} its frozen rank falls in")
        frow = freeze_row.get(fid)
        if frow is not None:
            if str(row.get("canonical_name")) != str(frow.get("canonical_name")):
                findings.append(f"{fid}: recorded canonical_name {row.get('canonical_name')!r} "
                                f"disagrees with the frozen P1000")
            if row.get("openssl_linkage") != frow.get("openssl_linkage"):
                findings.append(f"{fid}: recorded openssl_linkage {row.get('openssl_linkage')!r} "
                                f"disagrees with the frozen P1000")

    # The partition root reproduces from the frozen rule, the two cohorts and the frozen P1000 tag.
    tag = p1000_tag(freeze_body)
    if holdout_body.get("p1000_tag") != tag:
        findings.append("the recorded p1000_tag does not reproduce from the frozen P1000")
    if holdout_body.get("partition_root_hash") != _partition_root(RULE, dev, hol, tag):
        findings.append("the recorded partition_root_hash does not reproduce from the frozen rule "
                        "and the two cohorts")

    # Counts are read, not typed.
    if counts.get("p1000") != len(p1000):
        findings.append(f"counts.p1000 {counts.get('p1000')!r} disagrees with the {len(p1000)} "
                        f"frozen P1000 row(s)")
    if counts.get("development") != len(dev):
        findings.append(f"counts.development {counts.get('development')!r} disagrees with the "
                        f"{len(dev)} recorded development row(s)")
    if counts.get("holdout") != len(hol):
        findings.append(f"counts.holdout {counts.get('holdout')!r} disagrees with the {len(hol)} "
                        f"recorded holdout row(s)")
    if counts.get("per_band_holdout") != HOLDOUT_PER_BAND:
        findings.append(f"counts.per_band_holdout {counts.get('per_band_holdout')!r} is not the "
                        f"frozen {HOLDOUT_PER_BAND}")

    # The holdout has not been run against any candidate yet, and the model's non-claims hold.
    if holdout_body.get("holdout_status") != "unopened":
        findings.append(f"the holdout_status is {holdout_body.get('holdout_status')!r}, not "
                        f"`unopened`: the holdout is run exactly once, and only in 24.11")
    if holdout_body.get("non_claims") != NON_CLAIMS:
        findings.append("the recorded non_claims are not the stratum's four non-claims plus the "
                        "holdout-specific non-claim")

    # The partition is frozen before any candidate result: no candidate-subject row may exist.
    plane_docs = load_plane() if plane is None else plane
    findings += candidate_subject_findings(plane_docs)
    return findings


def _mutations(freeze_body: dict, holdout_body: dict, plane: list[tuple[str, object]]
               ) -> list[tuple[str, str, dict, dict, list[tuple[str, object]]]]:
    """`(name, needle, mutated_freeze, mutated_holdout, mutated_plane)` for each seeded mutation."""
    out: list[tuple[str, str, dict, dict, list[tuple[str, object]]]] = []

    # (1) one development family moved into the holdout cohort: band counts and the root disagree,
    #     and the frozen rule assigns the family to the cohort it was moved out of.
    m1 = copy.deepcopy(holdout_body)
    dev = m1["partition"]["development"]
    hol = m1["partition"]["holdout"]
    if dev:
        row = dev.pop(0)
        row["cohort"] = "holdout"
        hol.append(row)
    out.append(("holdout_member_moved", "but the frozen rule assigns it", freeze_body, m1, plane))

    # (2) one holdout member deleted: the two cohorts no longer union to the frozen P1000.
    m2 = copy.deepcopy(holdout_body)
    m2["partition"]["holdout"] = m2["partition"]["holdout"][:-1]
    out.append(("holdout_member_deleted", "do not union to the frozen P1000",
                freeze_body, m2, plane))

    # (3) a family_id duplicated into both cohorts: the cohorts are no longer disjoint.
    m3 = copy.deepcopy(holdout_body)
    if m3["partition"]["holdout"]:
        dup = copy.deepcopy(m3["partition"]["holdout"][0])
        dup["cohort"] = "development"
        m3["partition"]["development"].append(dup)
    out.append(("family_id_in_both_cohorts", "both the development and the holdout",
                freeze_body, m3, plane))

    # (4) a P1000-external family added: the partition is no longer a function of the frozen P1000.
    m4 = copy.deepcopy(holdout_body)
    m4["partition"]["holdout"].append({
        "p1000_rank": P1000_SIZE + 1, "band": BANDS + 1,
        "family_id": "family:__p1000-external__", "canonical_name": "__p1000-external__",
        "openssl_linkage": "direct", "cohort": "holdout",
    })
    out.append(("p1000_external_family", "outside the frozen P1000", freeze_body, m4, plane))

    # (5) a mutated partition root.
    m5 = copy.deepcopy(holdout_body)
    m5["partition_root_hash"] = "0" * 64
    out.append(("mutated_partition_root", "partition_root_hash", freeze_body, m5, plane))

    # (6) a fabricated candidate-subject run row injected into the downstream plane.
    injected = list(plane) + [(
        f"{rel(DOWNSTREAM)}/fabricated.jsonl",
        {"run_id": "r-fabricated-candidate", "specimen_id": "s-fabricated",
         "variant_id": "v-fabricated", "subject": "candidate", "level": "L4-linked",
         "outcome": "reached", "residual_class": "none", "evidence": []},
    )]
    out.append(("candidate_result_present", "candidate results present",
                freeze_body, holdout_body, injected))
    return out


def holdout_sensitivity_control(families_body: dict, freeze_body: dict, holdout_body: dict, *,
                                plane: list[tuple[str, object]] | None = None) -> dict:
    """Prove the court can fail: seed six mutations and require each to be caught.

    The honest partition must yield **zero** findings (specificity), and each seeded mutation -- one
    development family moved into the holdout cohort, one holdout member deleted, a family_id
    duplicated into both cohorts, a P1000-external family added, a mutated partition root, and a
    fabricated candidate-subject run row in the downstream plane -- must be caught with a finding
    that names what it is.
    """
    plane_docs = load_plane() if plane is None else plane
    base = holdout_findings(families_body, freeze_body, holdout_body, plane=plane_docs)
    specificity = not base
    control: dict = {"baseline_findings": len(base), "specificity_holds": specificity}
    honest = specificity
    for name, needle, mf, mh, mplane in _mutations(freeze_body, holdout_body, plane_docs):
        caught = any(needle in f for f in holdout_findings(families_body, mf, mh, plane=mplane))
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
        InputRef(name="family-freeze", path=FAMILY_FREEZE),
        InputRef(name="downstream-freeze",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_freeze.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]


def cmd_generate() -> int:
    if not (FAMILIES.is_file() and FAMILY_FREEZE.is_file()):
        missing = [rel(p) for p in (FAMILIES, FAMILY_FREEZE) if not p.is_file()]
        print(f"[downstream-holdout] {', '.join(missing)} is absent; run 24.2/24.4 first")
        return 1
    families_doc = json.loads(FAMILIES.read_text(encoding="utf-8"))
    families_body = families_doc["body"]
    freeze_doc = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))
    freeze_body = freeze_doc["body"]
    body = derive_holdout(freeze_body)

    findings = holdout_findings(families_body, freeze_body, body)
    control = holdout_sensitivity_control(families_body, freeze_body, body)
    if findings or not control["honest"]:
        print("[downstream-holdout] the derived partition fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1

    authority = freeze_doc.get("authority") or families_doc.get("authority") \
        or PRODUCTION_AUTHORITY
    doc = envelope(kind="downstream-holdout", authority=authority, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[downstream-holdout] p1000={c['p1000']} development={c['development']} "
          f"holdout={c['holdout']} per_band_holdout={c['per_band_holdout']} "
          f"status={body['holdout_status']}")
    print(f"  partition_root_hash={body['partition_root_hash']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check() -> int:
    """Re-run the pure validation over the committed partition without regenerating."""
    if not (FAMILIES.is_file() and FAMILY_FREEZE.is_file() and OUT.is_file()):
        missing = [rel(p) for p in (FAMILIES, FAMILY_FREEZE, OUT) if not p.is_file()]
        print(f"[downstream-holdout] {', '.join(missing)} is absent")
        return 1
    families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
    holdout_body = json.loads(OUT.read_text(encoding="utf-8"))["body"]
    findings = holdout_findings(families_body, freeze_body, holdout_body)
    control = holdout_sensitivity_control(families_body, freeze_body, holdout_body)
    if findings:
        print(f"[downstream-holdout] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = holdout_body.get("counts") or {}
    print(f"[downstream-holdout] p1000={c.get('p1000')} development={c.get('development')} "
          f"holdout={c.get('holdout')} findings={len(findings)} control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_holdout.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_holdout.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. The pure functions behave over the committed evidence.
    if not (FAMILIES.is_file() and FAMILY_FREEZE.is_file()):
        failures.append(f"{rel(FAMILIES)} or {rel(FAMILY_FREEZE)} is absent")
    else:
        families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
        freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
        p1000 = freeze_body.get("p1000") or []
        if len(p1000) != P1000_SIZE:
            failures.append(f"the frozen P1000 carries {len(p1000)} family(ies), not the "
                            f"{P1000_SIZE} the partition divides")
        direct = sum(1 for r in p1000 if r.get("openssl_linkage") == "direct")
        if direct != len(p1000):
            failures.append(f"only {direct} of {len(p1000)} frozen families are `direct`, so the "
                            f"recorded degenerate directness stratification would be false")
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run the generator")
        else:
            holdout_body = json.loads(OUT.read_text(encoding="utf-8"))["body"]
            findings = holdout_findings(families_body, freeze_body, holdout_body)
            if findings:
                failures.append(f"the committed partition has findings: {findings[:3]}")
            control = holdout_sensitivity_control(families_body, freeze_body, holdout_body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[downstream-holdout] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-holdout] self-test ok: the guard refuses a host invocation of this tool "
          "(marker and flag both named), the committed 800/200 partition reproduces with zero "
          "findings, and every seeded mutation (a moved holdout member, a deleted holdout member, a "
          "family_id in both cohorts, a P1000-external family, a mutated partition root, a "
          "fabricated candidate result) is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="validate the committed partition without regenerating (in-container)")
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
