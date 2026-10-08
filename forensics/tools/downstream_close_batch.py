#!/usr/bin/env python3
"""openssl-rs — Phase-24.19 the close-candidate reclamation: the second bounded admission batch.

Why this exists
---------------
24.18 ran a bounded admission campaign over recipe-less counted families and admitted ten. Its own
record names the closest misses: thirty-one families the venue *reached* (it fetched, configured or
built them) but that linked no OpenSSL subject, thirteen whose pinned release URL no longer
resolved, and fifteen whose build system the venue cannot execute. This subphase attacks those close
candidates directly -- it **fixes the argv** where the recipe's flags failed to enable the project's
TLS support, finds a **correct official release URL** where the pin had died, and draws a **fresh
deterministic batch** from the remaining recipe-less counted families -- and records every outcome,
admitted or not.

The three classifications (honest, never forced)
------------------------------------------------
Each attempted family is placed in exactly one of three states, and none is manufactured:

  * **admitted** -- the recipe was actually configured, built and **linked against both subjects**
    under the identical-build-intent rule; it enters the shared catalogue and the build/link tool
    imports it.
  * **classification finding** -- the family **built** in this venue but its artifact declares no
    `libssl`/`libcrypto` `DT_NEEDED`: the counted family is a transitive or optional consumer, not a
    direct one, in this configuration. It is recorded as a finding, never forced to link a library it
    does not use.
  * **rejected / not-venue-buildable / fetch-failed** -- it did not reach both-subject linkage, with
    the exact reason (a configure failure, a build failure, a dependency the venue does not admit, a
    build system the venue cannot execute, or a release URL that does not resolve).

Nothing is faked. A family that does not link OpenSSL is never recorded as a pass, and a family the
venue cannot build carries the reason rather than a fabricated build.

The priority rule (a heuristic, honestly labelled)
--------------------------------------------------
The candidate list is bounded and deterministic: the thirty-one 24.18 linkage misses, the thirteen
24.18 fetch-failures, and a fresh draw -- the next recipe-less counted families in the frozen 24.16
recipe-queue order (source breadth descending, then distro breadth descending, then popularity
descending, then canonical name ascending, then family_id ascending) that ship a stable upstream C
release tarball. It is a **heuristic** ranking over frozen breadth signals, never a measurement of
buildability: the batch's yield is a property of this venue and this batch, not of the whole 980.

The identical-build-intent rule
-------------------------------
One recipe per family; the same `acquire -> configure -> make` argv (and the same prefix-derived
environment) is run for both subjects with the single substitution `{prefix}` = the subject's
OpenSSL install prefix. No candidate-specific source patch is applied; `candidate_specific_patch_count`
is 0. The working source tree is the released tarball unmodified.

What is measured, and what is not
---------------------------------
`before` is the pre-batch blocker summary, captured once (before the planes are re-measured) and
preserved as a committed input. `after` is re-derived from the committed (re-measured) planes through
24.16's own code path. The `movement` is the subtraction of two measured figures. The `attempts` are
the batch's own record: every family tried, admitted or not, with its outcome and reason. A passing
record is an **instrument**: it says what was admitted and what the planes then measured, not that the
population now passes.

It executes nothing: it reads committed Phase-24 planes, the preserved pre-batch baseline, its own
authored attempt record and the admitted recipes' argv, and writes one derived record, so it is
declared `metadata_only` in `forensics/downstream/container.json` and `evidence_determinism.py`
regenerates it host-side. The recipes it admits are built by `downstream_build_link.py`, which imports
this module's catalogue.

Outputs
-------
  forensics/downstream/close-batch.json

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

# The Docker-only execution guard. Called first in `main`; this tool executes nothing, but it is a
# Phase-24 entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The 24.16 analysis, so the `after` partition is re-derived through the same code path 24.16
# produced it with, and the two can never drift.
import downstream_blockers as blockers  # noqa: E402

from downstream_schemas import BLOCKER_CLASSES, EXECUTION_LEVEL_RANK  # noqa: E402

OUT = REPO_ROOT / "forensics" / "downstream" / "close-batch.json"
# The preserved pre-batch baseline: the 24.18-state blocker summary captured once, before the planes
# are re-measured, and committed, so the record's `before` is a measured input rather than a figure
# the record carries against planes that no longer exist.
BASELINE = REPO_ROOT / "forensics" / "downstream" / "close-batch-baseline.json"
# The authored attempt record: the batch's own measurement (fetch, extract, classify, build against
# both subjects, read the ELF), fixed at capture beside the module rather than transcribed into it.
ATTEMPTS_FILE = REPO_ROOT / "forensics" / "downstream" / "close-batch-attempts.json"
GENERATOR = "forensics/tools/downstream_close_batch.py"

BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
P1000_RUN = REPO_ROOT / "forensics" / "downstream" / "p1000-run.json"
SHARED_BLOCKERS = blockers.OUT

L4 = "L4-linked"
L3 = "L3-built"

# The closed outcome vocabulary this record partitions its attempts against. `admitted` reached
# both-subject linkage; `classification-finding` built in the venue but links no OpenSSL subject;
# `not-venue-buildable` and `fetch-failed` name why the venue could not pose the question.
OUTCOMES: tuple[str, ...] = (
    "admitted",
    "classification-finding",
    "rejected",
    "not-venue-buildable",
    "fetch-failed",
)

# The closed finding vocabulary: the one way a family reaches a build in this venue without linking
# an OpenSSL subject -- it is a transitive or optional consumer, not a direct one.
FINDING_CLASSES: tuple[str, ...] = ("no-openssl-linkage",)


def load_attempts() -> tuple[dict, ...]:
    """The authored attempt record, read from the committed input file."""
    if not ATTEMPTS_FILE.is_file():
        return ()
    rows = json.loads(ATTEMPTS_FILE.read_text(encoding="utf-8"))
    return tuple(rows)


ATTEMPTS: tuple[dict, ...] = load_attempts()


def admitted_recipe_specs() -> tuple[dict, ...]:
    """The admitted recipes, in the shape `downstream_build_link._build_catalogue` consumes.

    Derived from `ATTEMPTS` (only the entries marked admitted), with a `recipe_id` and a note. This is
    the single source of truth for the shared recipe catalogue, so the catalogue and the record cannot
    disagree about which families were admitted.
    """
    out: list[dict] = []
    for a in ATTEMPTS:
        if not a["admitted"]:
            continue
        r = a["recipe"]
        out.append({
            "family": a["family"],
            "version": a["version"],
            "url": a["tarball_url"],
            "archive": a["archive"],
            "sha256": a["sha256"],
            "build_system": r["build_system"],
            "configure": r.get("configure"),
            "make": r["make"],
            "artifact": r["artifact"],
            "launch": r.get("launch"),
            "env_extra": r.get("env_extra"),
            "recipe_id": f"recipe:{a['family']}:{a['version']}",
            "note": (f"{a['family']} {a['version']} links the subject OpenSSL (24.19 close-candidate "
                     f"reclamation; build system {r['build_system']} classified empirically)"),
        })
    out.sort(key=lambda d: str(d["family"]))
    return tuple(out)


ADMITTED = admitted_recipe_specs()
ADMITTED_FAMILIES = frozenset(r["family"] for r in ADMITTED)

NON_CLAIMS: list[str] = [
    "a selected population is not a random sample: the 1,000 counted families are selected from "
    "frozen ranking evidence, so their blocker shares do not generalise to all downstream software",
    "1000/1000 is not a security proof: a full pass is not a guarantee that any consumer is safe, "
    "and the analysis makes no statement about an unmeasured consumer",
    "a build is not a functional proof: reaching the configured/built/linked rungs is not behaving, "
    "and only the functional levels are behavioural evidence",
    "direct and transitive consumers are different evidence: the two are never summed",
    "the batch's yield is a property of this venue and this batch, not of the whole set: the attempted "
    "families are the 24.18 linkage misses, its dead-URL pins and a bounded heuristic-ordered fresh "
    "draw, and the venue admits only a compiler, make, pkg-config and zlib, so the admission rate does "
    "not extrapolate to the recipe-less population",
]

RULE: dict = {
    "id": "downstream-close-batch/1",
    "name": "the close-candidate reclamation batch",
    "priority_rule": (
        "the 24.18 linkage misses, the 24.18 fetch-failures, and the next recipe-less counted "
        "families in the frozen 24.16 recipe-queue order -- source breadth descending, then distro "
        "breadth descending, then popularity descending, then canonical name ascending, then "
        "family_id ascending -- that ship a stable upstream C release tarball. It is a **heuristic** "
        "ranking over frozen breadth signals, never a measurement of buildability"
    ),
    "admission_criterion": (
        "a recipe is admissible when its pinned release tarball ships a build entry point the venue "
        "can execute (a generated `configure`, or a plain `Makefile`), needs no tool the venue lacks, "
        "and its built artifact declares and resolves an OpenSSL soname under both subjects; the "
        "venue is fixed (a C compiler, make, pkg-config, zlib -- and no autoconf/automake/libtool, no "
        "cmake, no meson/ninja, no scdoc, no libnl3). A recipe is admitted only if it was actually "
        "built and linked against both subjects; a non-admitted family carries the exact reason"
    ),
    "classification": (
        "a family that builds in this venue but whose artifact declares no libssl/libcrypto "
        "DT_NEEDED is a **classification finding** -- the counted family is a transitive or optional "
        "consumer, not a direct one -- recorded and never forced to link a library it does not use"
    ),
    "identical_intent": (
        "one recipe per family; the same acquire -> configure -> make argv (and the same prefix-derived "
        "environment) is run for both subjects with the single substitution {prefix} = the subject's "
        "OpenSSL install prefix and no other difference; no candidate-specific source patch is "
        "applied, so candidate_specific_patch_count is 0"
    ),
    "local_only": (
        "the batch fetches each candidate's released tarball, extracts it and builds it inside the "
        "admitted court container under its cgroup caps and the build/link tool's own wall-clock "
        "bounds; scratch is under /work/court and removed afterwards. Nothing is fetched or compiled "
        "outside the venue"
    ),
    "normalisation": (
        "the record is a pure function of committed inputs: the attempt pins and classifications are "
        "authored evidence fixed at capture, the levels are re-read from the committed re-measured "
        "build/link atlas, and the movement is the subtraction of two measured blocker summaries"
    ),
    "movement": (
        "the per-metric difference between the re-derived `after` blocker summary and the preserved "
        "pre-batch `before`, over the frozen P1000, computed as a subtraction of two measured figures: "
        "the family count with an admitted recipe, the measurable count, the candidate-linked count and "
        "the DROP_IN_PASS count (plus the `no-admitted-recipe` and resolved class counts)"
    ),
    "honesty_labels": [
        "the priority rule is a heuristic ranking, never a measurement of buildability",
        "the batch's yield is a property of this venue and this batch, not of the whole set",
        "a build/link is not a functional proof",
        "a family that does not link OpenSSL is classified, never forced to link it",
    ],
}


# ---------------------------------------------------------------------------------------------------
# reading the committed planes (pure; the court re-reads the same files)
# ---------------------------------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def _missing_inputs() -> list[str]:
    required = [SHARED_BLOCKERS, BUILD_LINK_ATLAS, P1000_RUN, BASELINE, ATTEMPTS_FILE,
                blockers.FAMILY_FREEZE, blockers.FAMILIES]
    return [rel(p) for p in required if not p.is_file()]


def _baseline() -> dict | None:
    if not BASELINE.is_file():
        return None
    try:
        return _load_json(BASELINE)
    except (json.JSONDecodeError, OSError):
        return None


def load_inputs() -> dict:
    """Every committed plane this record reads and the court re-reads."""
    bi = blockers.load_inputs()
    return {
        **bi,
        "shared_blockers_body": _load_json(SHARED_BLOCKERS),
        "build_link_body": _load_json(BUILD_LINK_ATLAS),
        "p1000_body": _load_json(P1000_RUN),
        "baseline_body": _baseline(),
        "attempts_authority": ATTEMPTS,
    }


# ---------------------------------------------------------------------------------------------------
# the derivation
# ---------------------------------------------------------------------------------------------------

def _class_counts(partition: dict) -> dict:
    counts = {c: 0 for c in BLOCKER_CLASSES}
    for cls in partition.values():
        counts[cls] = counts.get(cls, 0) + 1
    return counts


def _summarise(analysis: dict) -> dict:
    """The comparable figures of one blocker analysis: the class counts and the funnel rungs."""
    partition = analysis.get("partition") or {}
    counts = analysis.get("counts") or {}
    funnel = {f["step"]: f["families"] for f in analysis.get("funnel") or []}
    return {
        "class_counts": _class_counts(partition),
        "families": counts.get("families"),
        "measurable_families": counts.get("measurable_families"),
        "recipe_backed_families": counts.get("recipe_backed_families"),
        "recipe_less_families": counts.get("recipe_less_families"),
        "linked": funnel.get("linked"),
        "drop_in_pass": funnel.get("drop-in-pass"),
    }


def _atlas_levels(build_link_body: dict) -> dict:
    """`(family, subject) -> level` and `(family, subject) -> linkage_proven` from the atlas."""
    levels: dict[tuple[str, str], str] = {}
    linkage: dict[tuple[str, str], bool] = {}
    for r in build_link_body.get("runs") or []:
        key = (str(r.get("canonical_name")), str(r.get("subject")))
        levels[key] = r.get("level")
        linkage[key] = bool(r.get("linkage_proven"))
    return {"levels": levels, "linkage": linkage}


def derive_close_batch(inputs: dict) -> dict:
    """The whole record: rule, attempts, admitted recipes, classification findings, counts, movement."""
    analysis = blockers.derive_blockers(inputs)
    after = _summarise(analysis)
    before = inputs.get("baseline_body")
    if not before:
        before = dict(_summarise(inputs["shared_blockers_body"]),
                      source="24.18 post-campaign planes (not captured)")
    else:
        before = dict(before)
        before.setdefault("source", "24.18 post-campaign planes, captured as close-batch-baseline")

    atlas = _atlas_levels(inputs["build_link_body"])
    levels = atlas["levels"]
    linkage = atlas["linkage"]

    attempts: list[dict] = []
    admitted_recipes: list[dict] = []
    classification_findings: list[dict] = []
    for a in ATTEMPTS:
        fam = a["family"]
        probe = a.get("probe") or {}
        auth_level = levels.get((fam, "authority"), probe.get("authority"))
        cand_level = levels.get((fam, "candidate"), probe.get("candidate"))
        rec = {
            "family": fam, "family_id": a.get("family_id"), "canonical_name": fam,
            "version": a["version"], "tarball_url": a.get("tarball_url"),
            "sha256": a.get("sha256"), "build_system": a.get("build_system"),
            "admitted": bool(a["admitted"]), "outcome": a.get("outcome"),
            "failure_class": a.get("failure_class"), "finding_class": a.get("finding_class"),
            "reason": a.get("reason"),
            "authority_level": auth_level, "candidate_level": cand_level,
            "probe": {"authority": probe.get("authority"), "candidate": probe.get("candidate")},
        }
        attempts.append(rec)
        if a["admitted"]:
            admitted_recipes.append({
                "family": fam, "version": a["version"], "url": a.get("tarball_url"),
                "sha256": a.get("sha256"), "build_system": a.get("build_system"),
                "artifact": (a.get("recipe") or {}).get("artifact"),
                "recipe_id": f"recipe:{fam}:{a['version']}",
                "authority_level": auth_level, "candidate_level": cand_level,
                "linkage_proven": linkage.get((fam, "candidate"), False),
            })
        if a.get("finding_class"):
            classification_findings.append({
                "family": fam, "version": a["version"], "url": a.get("tarball_url"),
                "sha256": a.get("sha256"), "build_system": a.get("build_system"),
                "finding_class": a["finding_class"], "reason": a.get("reason"),
                "probe": {"authority": probe.get("authority"), "candidate": probe.get("candidate")},
            })
    admitted_recipes.sort(key=lambda d: str(d["family"]))
    classification_findings.sort(key=lambda d: str(d["family"]))

    def count_level(subject: str, rung: str) -> int:
        return sum(1 for r in admitted_recipes
                   if EXECUTION_LEVEL_RANK.get(str(r.get(f"{subject}_level")), -1)
                   >= EXECUTION_LEVEL_RANK[rung])

    by_outcome: dict[str, int] = {o: 0 for o in OUTCOMES}
    for a in attempts:
        by_outcome[str(a.get("outcome"))] = by_outcome.get(str(a.get("outcome")), 0) + 1
    failure_histogram: dict[str, int] = {}
    for a in attempts:
        if a.get("failure_class"):
            failure_histogram[a["failure_class"]] = failure_histogram.get(a["failure_class"], 0) + 1

    counts = {
        "attempted": len(attempts),
        "admitted": len(admitted_recipes),
        "classification_findings": len(classification_findings),
        "built": count_level("candidate", L3),
        "linked": count_level("candidate", L4),
        "authority_linked": count_level("authority", L4),
        "by_outcome": by_outcome,
        "by_failure_class": failure_histogram,
        "per_subject": {
            subject: {
                "configured": count_level(subject, "L2-configured"),
                "built": count_level(subject, L3),
                "linked": count_level(subject, L4),
            } for subject in ("authority", "candidate")
        },
        "yield": {
            "admitted_per_attempted": f"{len(admitted_recipes)}/{len(attempts)}",
            "linked_per_attempted": f"{count_level('candidate', L4)}/{len(attempts)}",
            "admission_rate": round(len(admitted_recipes) / len(attempts), 4) if attempts else 0.0,
        },
    }

    movement: dict[str, dict] = {}
    for metric in ("recipe_backed_families", "measurable_families", "linked", "drop_in_pass",
                   "no_admitted_recipe", "resolved_none"):
        if metric == "no_admitted_recipe":
            b = int((before.get("class_counts") or {}).get("no-admitted-recipe") or 0)
            a2 = int((after.get("class_counts") or {}).get("no-admitted-recipe") or 0)
        elif metric == "resolved_none":
            b = int((before.get("class_counts") or {}).get("none") or 0)
            a2 = int((after.get("class_counts") or {}).get("none") or 0)
        else:
            b = int(before.get(metric) or 0)
            a2 = int(after.get(metric) or 0)
        movement[metric] = {"before": b, "after": a2, "delta": a2 - b}

    return {
        "rule": RULE,
        "before": before,
        "after": after,
        "movement": movement,
        "attempts": attempts,
        "admitted_recipes": admitted_recipes,
        "classification_findings": classification_findings,
        "counts": counts,
        "non_claims": NON_CLAIMS,
    }


# ---------------------------------------------------------------------------------------------------
# findings and the sensitivity control (the court's own checks over the committed record)
# ---------------------------------------------------------------------------------------------------

def close_batch_findings(inputs: dict, body: dict) -> list[str]:
    """Every way the recorded batch fails its own derivation."""
    out: list[str] = []
    derived = derive_close_batch(inputs)

    if body.get("rule") != RULE:
        out.append("the recorded rule is not the frozen close-batch rule")
    if body.get("non_claims") != NON_CLAIMS:
        out.append("the recorded non_claims are not the close-batch non-claims")
    if body.get("before") != derived["before"]:
        out.append("the recorded `before` does not reproduce from the preserved baseline")
    if body.get("after") != derived["after"]:
        out.append("the recorded `after` does not reproduce from the committed planes")
    if body.get("movement") != derived["movement"]:
        out.append("the recorded `movement` does not reproduce from before/after")
    if body.get("attempts") != derived["attempts"]:
        out.append("the recorded `attempts` do not reproduce from the attempt record")
    if body.get("admitted_recipes") != derived["admitted_recipes"]:
        out.append("the recorded `admitted_recipes` do not reproduce from the attempt record")
    if body.get("classification_findings") != derived["classification_findings"]:
        out.append("the recorded `classification_findings` do not reproduce from the attempt record")
    if body.get("counts") != derived["counts"]:
        out.append("the recorded `counts` do not reproduce from the record")

    recorded = body.get("attempts") or []
    if len(recorded) != len(ATTEMPTS):
        out.append(f"the record accounts for {len(recorded)} attempts but {len(ATTEMPTS)} were made")
    want = [a["family"] for a in ATTEMPTS]
    got = [r.get("family") for r in recorded]
    if got != want:
        out.append("the recorded attempts do not account for every attempted family once, in order")

    # Every admitted recipe was really built and linked against both subjects.
    atlas = _atlas_levels(inputs["build_link_body"])
    levels = atlas["levels"]
    linkage = atlas["linkage"]
    for r in body.get("admitted_recipes") or []:
        fam = r.get("family")
        a = levels.get((fam, "authority"))
        c = levels.get((fam, "candidate"))
        if a != L4:
            out.append(f"admitted recipe {fam!r} did not reach {L4} against the authority "
                       f"(recorded {a!r})")
        if c != L4:
            out.append(f"admitted recipe {fam!r} did not reach {L4} against the candidate "
                       f"(recorded {c!r})")
        if not linkage.get((fam, "candidate"), False):
            out.append(f"admitted recipe {fam!r} did not prove candidate linkage")

    # Admission set equals the ATTEMPTS marked admitted, and equals the module catalogue.
    want_adm = sorted(a["family"] for a in ATTEMPTS if a["admitted"])
    got_adm = sorted(r["family"] for r in body.get("admitted_recipes") or [])
    if want_adm != got_adm:
        out.append("the admitted recipes are not exactly the attempts marked admitted")
    if {r["family"] for r in ADMITTED} != set(want_adm):
        out.append("the module catalogue is not exactly the attempts marked admitted")

    # The classification findings are exactly the attempts carrying a finding class, and each is
    # honestly labelled from the closed vocabulary.
    want_find = sorted(a["family"] for a in ATTEMPTS if a.get("finding_class"))
    got_find = sorted(r["family"] for r in body.get("classification_findings") or [])
    if want_find != got_find:
        out.append("the classification findings are not exactly the attempts carrying a finding class")
    for r in body.get("classification_findings") or []:
        if r.get("finding_class") not in FINDING_CLASSES:
            out.append(f"classification finding {r.get('family')!r} carries an unknown finding "
                       f"class {r.get('finding_class')!r}")
        if not r.get("reason"):
            out.append(f"classification finding {r.get('family')!r} carries no reason")
        if (r.get("probe") or {}).get("candidate") != L3:
            out.append(f"classification finding {r.get('family')!r} was not recorded as built in "
                       f"the venue")

    # A non-admitted family carries an outcome from the closed vocabulary and a reason, and is
    # neither admitted nor a finding by accident.
    for r in body.get("attempts") or []:
        if r.get("outcome") not in OUTCOMES:
            out.append(f"attempt {r.get('family')!r} carries an unknown outcome {r.get('outcome')!r}")
        if r.get("admitted") and (r.get("outcome") != "admitted" or r.get("failure_class")):
            out.append(f"attempt {r.get('family')!r} is admitted but is not a clean admission")
        if not r.get("admitted") and not r.get("finding_class") \
                and not (r.get("reason") or r.get("failure_class")):
            out.append(f"non-admitted family {r.get('family')!r} carries no reason and no failure "
                       f"class")

    # The movement is the arithmetic of the two measured summaries, never typed.
    for metric, m in (body.get("movement") or {}).items():
        if m.get("delta") != int(m.get("after") or 0) - int(m.get("before") or 0):
            out.append(f"movement[{metric}].delta {m.get('delta')!r} is not after - before")
    if (body.get("counts") or {}).get("linked") != derived["counts"]["linked"]:
        out.append("counts.linked is not the derived count")
    return out


def close_batch_sensitivity_control(inputs: dict, body: dict) -> dict:
    """Prove the record can fail: seed five mutations and require each caught."""
    base = close_batch_findings(inputs, body)
    specificity = not base

    def caught(mutated: dict) -> int:
        return len(close_batch_findings(inputs, mutated))

    # 1. A rejected family marked admitted with no recipe.
    m1 = copy.deepcopy(body)
    for a in m1.get("attempts") or []:
        if not a.get("admitted") and not a.get("finding_class"):
            a["admitted"] = True
            break

    # 2. An admitted recipe dropped from the record.
    m2 = copy.deepcopy(body)
    if m2.get("admitted_recipes"):
        m2["admitted_recipes"].pop()

    # 3. A movement figure that disagrees with the planes.
    m3 = copy.deepcopy(body)
    if m3.get("movement"):
        first = sorted(m3["movement"])[0]
        m3["movement"][first]["delta"] = int(m3["movement"][first]["delta"]) + 7

    # 4. A classification finding stripped of its finding class.
    m4 = copy.deepcopy(body)
    for r in m4.get("classification_findings") or []:
        r["finding_class"] = None
        break

    # 5. A typed count that disagrees with the derivation.
    m5 = copy.deepcopy(body)
    m5["counts"]["linked"] = int(m5["counts"].get("linked") or 0) + 9

    return {
        "baseline_findings": len(base),
        "specificity_holds": specificity,
        "caught_rejected_marked_admitted": caught(m1),
        "caught_admitted_recipe_dropped": caught(m2),
        "caught_movement_disagrees": caught(m3),
        "caught_finding_stripped": caught(m4),
        "caught_typed_count": caught(m5),
        "honest": bool(specificity and all(caught(m) for m in (m1, m2, m3, m4, m5))),
    }


# ---------------------------------------------------------------------------------------------------
# the artefact
# ---------------------------------------------------------------------------------------------------

def _inputs_list() -> list[InputRef]:
    return [
        InputRef(name="close-batch-attempts", path=ATTEMPTS_FILE),
        InputRef(name="close-batch-baseline", path=BASELINE),
        InputRef(name="shared-blockers", path=SHARED_BLOCKERS),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="p1000-run", path=P1000_RUN),
        InputRef(name="family-freeze", path=blockers.FAMILY_FREEZE),
        InputRef(name="families", path=blockers.FAMILIES),
        InputRef(name="downstream-close-batch",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_close_batch.py"),
        InputRef(name="downstream-blockers",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_blockers.py"),
        InputRef(name="downstream-build-link",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_build_link.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard", path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]


def write_outputs(body: dict) -> None:
    doc = envelope(kind="downstream-close-batch", authority=PRODUCTION_AUTHORITY,
                   inputs=_inputs_list(), body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


def _baseline_doc(summary: dict) -> dict:
    body = dict(summary,
                source="24.18 post-campaign planes",
                captured_by="forensics/tools/downstream_close_batch.py --capture-baseline",
                captured_note=("the 24.16 blocker summary of the 24.18 post-campaign planes, captured "
                               "once before the planes were re-measured and committed as the record's "
                               "`before`"))
    doc = envelope(kind="downstream-close-batch-baseline", authority=PRODUCTION_AUTHORITY,
                   inputs=[InputRef(name="shared-blockers", path=SHARED_BLOCKERS)],
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    return doc


def cmd_capture_baseline() -> int:
    """Capture the post-24.18 24.16 blocker summary as the committed `before` input.

    Run once, before the planes are re-measured. It reads the committed planes through 24.16's own
    derivation and freezes the summary; the record then reads it rather than a plane that no longer
    exists.
    """
    missing = [rel(p) for p in (SHARED_BLOCKERS, BUILD_LINK_ATLAS, P1000_RUN, blockers.FAMILY_FREEZE,
                                blockers.FAMILIES) if not p.is_file()]
    if missing:
        print(f"[downstream-close-batch] {', '.join(missing)} is absent; cannot capture a baseline")
        return 1
    inputs = load_inputs()
    analysis = blockers.derive_blockers(inputs)
    if not analysis.get("partition"):
        print("[downstream-close-batch] the derived 24.16 partition is empty; cannot capture a "
              "baseline")
        return 1
    write_json(BASELINE, _baseline_doc(_summarise(analysis)))
    print(f"[downstream-close-batch] captured the pre-batch baseline "
          f"({len(analysis['partition'])} families) -> {rel(BASELINE)}")
    return 0


def cmd_measure() -> int:
    missing = _missing_inputs()
    if missing:
        print(f"[downstream-close-batch] {', '.join(missing)} is absent; run the earlier "
              f"subphase(s) first")
        return 1
    inputs = load_inputs()
    body = derive_close_batch(inputs)
    findings = close_batch_findings(inputs, body)
    control = close_batch_sensitivity_control(inputs, body)
    if findings or not control["honest"]:
        print("[downstream-close-batch] the derived record fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body)
    c = body["counts"]
    print(f"[downstream-close-batch] attempted={c['attempted']} admitted={c['admitted']} "
          f"findings={c['classification_findings']} built={c['built']} linked={c['linked']} "
          f"authority_linked={c['authority_linked']} "
          f"yield={c['yield']['admitted_per_attempted']}")
    print(f"  by_outcome: {c['by_outcome']}")
    for metric in ("recipe_backed_families", "measurable_families", "linked", "drop_in_pass",
                   "no_admitted_recipe", "resolved_none"):
        m = body["movement"][metric]
        print(f"  {metric:<26} before={m['before']:<5} after={m['after']:<5} delta={m['delta']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check() -> int:
    if not OUT.is_file():
        print(f"[downstream-close-batch] {rel(OUT)} is absent")
        return 1
    missing = _missing_inputs()
    if missing:
        print(f"[downstream-close-batch] {', '.join(missing)} is absent")
        return 1
    inputs = load_inputs()
    body = _load_json(OUT)
    findings = close_batch_findings(inputs, body)
    control = close_batch_sensitivity_control(inputs, body)
    if findings:
        print(f"[downstream-close-batch] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    print(f"[downstream-close-batch] findings={len(findings)} control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard admits this metadata-only generator and the pure functions behave."""
    failures: list[str] = []

    admission = phase24_guard.evaluate(env={}, dockerenv=False,
                                       manifest=phase24_guard.load_manifest(),
                                       entry_point="downstream_close_batch.py")
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append(
            "the guard did not admit downstream_close_batch.py as metadata-only on a host")

    if set(BLOCKER_CLASSES) != set(blockers.CLASS_RULE):
        failures.append("the blocker vocabulary this record partitions against is not the schema's")

    missing = _missing_inputs()
    if missing:
        failures.append(f"{', '.join(missing)} is absent")
    elif not OUT.is_file():
        failures.append(f"{rel(OUT)} is absent; run --measure")
    else:
        inputs = load_inputs()
        body = _load_json(OUT)
        findings = close_batch_findings(inputs, body)
        if findings:
            failures.append(f"the committed record has findings: {findings[:3]}")
        control = close_batch_sensitivity_control(inputs, body)
        if not control["honest"]:
            failures.append(f"the sensitivity control is not honest: {control}")
        if len(body.get("attempts") or []) < 40:
            failures.append(f"the record accounts for only {len(body.get('attempts') or [])} "
                            f"attempts, below the batch's 40-family floor")
        if {r["family"] for r in ADMITTED} != {r["family"] for r in body.get("admitted_recipes") or []}:
            failures.append("the module catalogue is not exactly the record's admitted recipes")

    if failures:
        print("[downstream-close-batch] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-close-batch] self-test ok: the guard admits this metadata-only generator on a "
          "host, the vocabulary matches the schema, the committed record reproduces with zero "
          "findings, every admitted recipe really built and linked against both subjects, every "
          "classification finding built in the venue without an OpenSSL subject, the record accounts "
          "for at least 40 attempts, and every seeded mutation (a rejected family marked admitted, a "
          "dropped admitted recipe, a movement figure disagreeing with the planes, a classification "
          "finding stripped of its class and a typed count) is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive the record from the committed planes and write it")
    ap.add_argument("--capture-baseline", action="store_true",
                    help="capture the post-24.18 24.16 summary as the committed before input")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed record without regenerating")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool reads committed evidence and writes one
    # record, so it executes nothing itself, but it is a Phase-24 entry point and a host invocation is
    # refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check()
    if args.capture_baseline:
        return cmd_capture_baseline()
    return cmd_measure()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
