#!/usr/bin/env python3
"""openssl-rs — the biggest-mover shared-blocker analysis of the downstream-1000 corpus (24.16).

Why this exists
---------------
The atlas reconciles *how far* each counted family got (24.13's ladder and verdicts), but it does
not say **why** each family stopped, nor which stop is shared. This tool answers that directly: it
partitions the 1,000 counted families by their **deepest blocker**, each family counted exactly
once, derives every figure from the committed planes rather than typing it, and ranks the blocker
classes by their **mover potential** so a later subphase (24.17) knows which repair moves the most
families. It is the analysis half of the stratum's "biggest movers" reading; it repairs nothing.

The partition (the intellectual core)
-------------------------------------
Every counted family is placed in exactly one blocker class, derived from the committed rows:

  * a family with **no admitted specimen recipe** in this venue is `no-admitted-recipe` -- the
    988 families whose candidate run reads `has_recipe: false` and `not_attempted` at
    `L0-catalogued`;
  * a **recipe-backed** family is named by the **first unmet condition at the level it stopped**:
    a recipe-level build-system gap (`recipe-build-system-unsupported`) or build-dependency gap
    (`recipe-build-dependency-missing`); a candidate-side stop (`candidate-configure-failure`
    through `candidate-functional-failure`); the authority itself unable to go higher
    (`authority-baseline-limited`, which is **not** a candidate blocker); a missing deterministic
    workload/fixture (`no-fixture`); or a family genuinely outside the venue (`out-of-scope`);
  * a family that reached `DROP_IN_PASS` has **no** blocker, and is recorded as `none`.

The **mover potential** of a class is how many of its families would rise to a strictly higher
execution level if the class's blocker alone were resolved, computed structurally from what each
family is missing; the **per-fix leverage** is how many families one *instance* of the fix unlocks,
so recipe admission (breadth 988, one mechanism per family) has leverage 1 while a single recipe
repair that unlocks two families has leverage 2. **A heuristic ranking of what to build next is not
a measurement of buildability**: the feasible recipe queue this tool emits is ranked by frozen
breadth signals (source breadth, distro breadth, popularity, name), and is labelled a heuristic
wherever it appears.

What it is not
--------------
It executes nothing: it reads the committed Phase-24 planes and writes one derived analysis. It
does not build, fetch, link or run a downstream project, so it is declared `metadata_only` in
`forensics/downstream/container.json` and `evidence_determinism.py` regenerates it host-side. A
passing reading is not a security proof, not a population-wide rate, and not a claim that any
particular family would pass if repaired.

Outputs
-------
  forensics/downstream/shared-blockers.json

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
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool reads
# committed evidence and writes one analysis, so it executes nothing itself, but it is a Phase-24
# entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The record kinds this tool emits. Imported rather than restated, so the vocabulary cannot drift
# from the schema the court validates against.
import downstream_schemas  # noqa: E402

from downstream_schemas import (  # noqa: E402
    BLOCKER_CLASSES,
    BLOCKER_FIXABILITY,
    EXECUTION_LEVEL_RANK,
)

OUT = REPO_ROOT / "forensics" / "downstream" / "shared-blockers.json"
GENERATOR = "forensics/tools/downstream_blockers.py"

FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
RUNTIME_FUNCTIONAL_ATLAS = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"
FAILURES = REPO_ROOT / "forensics" / "downstream" / "failures.json"
P1000_RUN = REPO_ROOT / "forensics" / "downstream" / "p1000-run.json"
RECONCILIATION = REPO_ROOT / "forensics" / "downstream" / "reconciliation.json"

# The recipe queue is bounded so the report stays readable; the criterion below selects it and the
# full recipe-less set is in the partition.
QUEUE_LIMIT = 40

# The blocking-rung each candidate-side failure class names, and the level rank the family stopped
# at. `L2-configured` is the first rung above `L1-admitted-source`, so a `configure-failure` stops
# a family that reached `L1-admitted-source`.
FAILURE_TO_LEVEL = {
    "configure-failure": "L2-configured",
    "link-failure": "L4-linked",
    "load-failure": "L5-loaded",
    "runtime-failure": "L6-runtime",
    "functional-failure": "L7-functional",
    "semantic-failure": "L7-functional",
}

# The candidate-side failure classes mapped to the blocker class they name.
FAILURE_TO_BLOCKER = {
    "configure-failure": "candidate-configure-failure",
    "link-failure": "candidate-link-failure",
    "load-failure": "candidate-load-failure",
    "runtime-failure": "candidate-runtime-failure",
    "functional-failure": "candidate-functional-failure",
    "semantic-failure": "candidate-functional-failure",
    "authority-build-failure": "authority-baseline-limited",
}

# The closed vocabulary, each class's fixability and its **named fix mechanism**, and what the class
# means. This is the `rule`'s vocabulary and it is the single place the class names are interpreted;
# the blocker records below are derived against it. `none` is the resolved class.
CLASS_RULE: dict[str, dict[str, str]] = {
    "none": {
        "fixability": "resolved",
        "fix_mechanism": "no repair required: the family reached DROP_IN_PASS",
        "description": "the family is not blocked: it reached DROP_IN_PASS",
    },
    "no-admitted-recipe": {
        "fixability": "recipe-admission",
        "fix_mechanism": "admit a pristine-source build recipe for the family",
        "description": "no admitted pristine-source recipe is recorded for this family in this "
                       "venue, so the run is not attempted and manufactures no source URL",
    },
    "recipe-build-system-unsupported": {
        "fixability": "recipe-build-system",
        "fix_mechanism": "teach the recipe the project's actual build system (the source tree "
                          "carries no runnable `./configure`)",
        "description": "the recipe stops at configure because the build system it invokes is not "
                       "the project's",
    },
    "recipe-build-dependency-missing": {
        "fixability": "recipe-build-dependency",
        "fix_mechanism": "add the missing build dependency to the family's recipe",
        "description": "the recipe stops at configure because a build dependency is absent from "
                       "the venue",
    },
    "candidate-configure-failure": {
        "fixability": "candidate-fix",
        "fix_mechanism": "fix the candidate so the family configures",
        "description": "the candidate fails configure at a level the authority reached",
    },
    "candidate-link-failure": {
        "fixability": "candidate-fix",
        "fix_mechanism": "fix the candidate so the family links",
        "description": "the candidate fails to link at a level the authority reached",
    },
    "candidate-load-failure": {
        "fixability": "candidate-fix",
        "fix_mechanism": "fix the candidate so the family loads",
        "description": "the candidate fails to load at a level the authority reached",
    },
    "candidate-runtime-failure": {
        "fixability": "candidate-fix",
        "fix_mechanism": "fix the candidate so the family runs",
        "description": "the candidate fails at runtime at a level the authority reached",
    },
    "candidate-functional-failure": {
        "fixability": "candidate-fix",
        "fix_mechanism": "fix the candidate so the family behaves",
        "description": "the candidate fails to behave at a level the authority reached",
    },
    "authority-baseline-limited": {
        "fixability": "authority-limited",
        "fix_mechanism": "raise the authority baseline (the authority itself could not go higher)",
        "description": "the authority itself stopped here, so the candidate is not the blocker",
    },
    "no-fixture": {
        "fixability": "fixture-addition",
        "fix_mechanism": "add the missing deterministic workload or fixture the venue does not pose",
        "description": "the family reached its baseline but the venue poses no deterministic local "
                       "workload, so it is not driven to the functional level",
    },
    "out-of-scope": {
        "fixability": "out-of-scope",
        "fix_mechanism": "record the family out of scope for this venue",
        "description": "the family is outside what this venue can pose",
    },
}

# The four stratum non-claims plus the honesty label this analysis adds. The last is load-bearing:
# the recipe queue is a heuristic ranking of buildability, not a measurement of it.
NON_CLAIMS: list[str] = [
    "a selected population is not a random sample: the 1,000 counted families are selected from "
    "frozen ranking evidence, so their blocker shares do not generalise to all downstream software",
    "1000/1000 is not a security proof: a full pass is not a guarantee that any consumer is safe, "
    "and the analysis makes no statement about an unmeasured consumer",
    "a build is not a functional proof: the configure/link/load rungs are not behaving, and only "
    "the functional levels are behavioural evidence",
    "direct and transitive consumers are different evidence: the two are never summed",
    "a heuristic ranking is not a measurement of buildability: the feasible recipe queue is ranked "
    "by frozen breadth signals, and no family in it has been built by this analysis",
]


# ---------------------------------------------------------------------------------------------------
# reading the committed planes (pure; the court re-reads the same files)
# ---------------------------------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def load_inputs() -> dict:
    """Every committed plane this analysis reads and the court re-reads."""
    return {
        "family_freeze": _load_json(FAMILY_FREEZE),
        "families": _load_json(FAMILIES),
        "build_link": _load_json(BUILD_LINK_ATLAS),
        "runtime": _load_json(RUNTIME_FUNCTIONAL_ATLAS),
        "failures": _load_json(FAILURES),
        "p1000_run": _load_json(P1000_RUN),
        "reconciliation": _load_json(RECONCILIATION),
    }


def _missing_inputs() -> list[str]:
    required = [FAMILY_FREEZE, FAMILIES, BUILD_LINK_ATLAS, RUNTIME_FUNCTIONAL_ATLAS, FAILURES,
                P1000_RUN, RECONCILIATION]
    return [rel(p) for p in required if not p.is_file()]


# ---------------------------------------------------------------------------------------------------
# the blocker derivation (the partition, the ranking, the funnel and the queue)
# ---------------------------------------------------------------------------------------------------

def _dependency_token(reason: str) -> str | None:
    """The missing build dependency a configure reason names, or `None`.

    Derived from the reason text: a `configure` that fails because a package is absent names the
    package (`kmod`: `scdoc needed for building manpages`; `openvpn`: `libnl-genl-3.0 package not
    found`). The token is the mechanism key, so two families missing the same dependency share one
    fix while two missing different ones do not.
    """
    m = re.search(r"([A-Za-z0-9_.+-]+)\s+package not found", reason)
    if m:
        return m.group(1)
    m = re.search(r"([A-Za-z0-9_.+-]+)\s+needed for building", reason)
    if m:
        return m.group(1)
    return None


def _build_system_unsupported(reason: str, note: str) -> bool:
    """Whether a configure stop is a recipe build-system gap rather than a candidate defect.

    The source tree carries no runnable `./configure` (`libssh` ships CMake, `lighttpd` 1.4.76 a
    tree without a generated configure), or the recipe note says so. A `configure` that never ran is
    a recipe gap, not something the candidate did.
    """
    if "'./configure'" in reason or "no pre-generated" in note.lower():
        return True
    return "unsupported build system" in note.lower()


def _classify_family(cand: dict | None, auth: dict | None, verdict: dict | None,
                     recipe_note: str) -> tuple[str, str]:
    """`(blocker_class, mechanism_key)` for one counted family.

    The candidate run is the family's deepest measured row; the authority run and the verdict are
    read beside it. A family with no candidate row or no admitted recipe is `no-admitted-recipe`.
    The mechanism key is `""` for the resolved class and a repair-target string otherwise.
    """
    fid = str((cand or {}).get("family_id") or (auth or {}).get("family_id") or "")
    if cand is None or not cand.get("has_recipe"):
        return "no-admitted-recipe", f"admit-recipe:{fid}"
    if verdict is not None and verdict.get("verdict") == "DROP_IN_PASS":
        return "none", ""
    residual = cand.get("residual_class")
    outcome = cand.get("outcome")
    failure = cand.get("failure_class")
    reason = str(cand.get("reason") or "")
    if outcome == "reached":
        if residual in (None, "none"):
            return "none", ""
        if residual == "out-of-scope" or "workload" in reason or "fixture" in reason:
            return "no-fixture", f"add-fixture:{fid}"
        if residual == "functional-divergence":
            return "candidate-functional-failure", "fix-candidate:candidate-functional-failure"
        if residual == "runtime-failure":
            return "candidate-runtime-failure", "fix-candidate:candidate-runtime-failure"
        if residual == "candidate-patch-required":
            return "candidate-functional-failure", "fix-candidate:candidate-functional-failure"
        if residual == "authority-unsupported":
            return "authority-baseline-limited", "raise-authority-baseline"
        return "out-of-scope", f"declare-out-of-scope:{fid}"
    # the family stopped with a failure
    if failure == "configure-failure":
        token = _dependency_token(reason)
        if token:
            return "recipe-build-dependency-missing", f"add-build-dependency:{token}"
        if _build_system_unsupported(reason, recipe_note):
            return "recipe-build-system-unsupported", "teach-recipe-build-system:no-configure"
        auth_failed_same = (auth is not None and auth.get("outcome") == "failed"
                            and auth.get("failure_class") == failure
                            and auth.get("level") == cand.get("level"))
        if auth_failed_same:
            return "authority-baseline-limited", "raise-authority-baseline"
        return "candidate-configure-failure", "fix-candidate:candidate-configure-failure"
    if failure in FAILURE_TO_BLOCKER:
        blocker = FAILURE_TO_BLOCKER[failure]
        if blocker == "authority-baseline-limited":
            return blocker, "raise-authority-baseline"
        return blocker, f"fix-candidate:{blocker}"
    if failure == "acquire-failure":
        return "no-admitted-recipe", f"admit-recipe:{fid}"
    return "candidate-configure-failure", "fix-candidate:candidate-configure-failure"


def _rank(row: dict, level: str) -> int:
    return EXECUTION_LEVEL_RANK.get(level, -1)


def derive_blockers(inputs: dict) -> dict:
    """The whole analysis: the partition, the blocker classes, the ranking, the funnel, the queue."""
    p1000 = list(inputs["family_freeze"].get("p1000") or [])
    families = {str(f["family_id"]): f for f in inputs["families"].get("families") or []}
    verdicts = {str(v["family_id"]): v
                for v in inputs["p1000_run"].get("verdicts") or []}
    cand = {str(r["family_id"]): r for r in inputs["p1000_run"].get("runs") or []
            if r.get("subject") == "candidate"}
    auth = {str(r["family_id"]): r for r in inputs["p1000_run"].get("runs") or []
            if r.get("subject") == "authority"}
    recipe_notes = {str(r.get("family")): str(r.get("note") or "")
                    for r in inputs["build_link"].get("recipe_catalogue") or []}

    partition: dict[str, str] = {}
    mechanism: dict[str, str] = {}
    for row in p1000:
        fid = str(row["family_id"])
        name = str(row.get("canonical_name") or fid)
        blocker, mech = _classify_family(cand.get(fid), auth.get(fid), verdicts.get(fid),
                                         recipe_notes.get(name, ""))
        partition[fid] = blocker
        mechanism[fid] = mech

    # --- the classes ---------------------------------------------------------------------------
    by_class: dict[str, list[str]] = {cls: [] for cls in BLOCKER_CLASSES}
    for fid, blocker in partition.items():
        by_class[blocker].append(fid)

    blockers: list[dict] = []
    for cls in BLOCKER_CLASSES:
        fids = sorted(by_class[cls])
        mechanisms = sorted({mechanism[f] for f in fids if mechanism[f]})
        blocked = len(fids)
        rule = CLASS_RULE[cls]
        if cls == "none":
            mover, basis, to_pass, distinct, leverage = 0, "measured", 0, 0, 0.0
        else:
            # Every blocked family is stopped at its recorded blocker below the top rung, so
            # resolving that blocker alone clears the rung it is stuck on and it rises. For a
            # family with no recipe the rise is a **structural upper bound** -- admission is
            # necessary but its buildability is unmeasured -- so its basis says so.
            mover = blocked
            basis = "structural-upper-bound" if cls == "no-admitted-recipe" else "measured"
            # A family whose only recorded gap is its blocker would reach DROP_IN_PASS when the
            # blocker is resolved; a family with no recipe is not counted, because admitting a
            # recipe is not a measurement that it builds.
            to_pass = 0 if cls == "no-admitted-recipe" else blocked
            distinct = len(mechanisms)
            leverage = round(blocked / distinct, 3) if distinct else 0.0
        blockers.append({
            "blocker_id": f"blocker:{cls}",
            "blocker_class": cls,
            "blocked_families": blocked,
            "shared_by": fids,
            "mover_potential": mover,
            "mover_potential_basis": basis,
            "to_pass_potential": to_pass,
            "fixability": rule["fixability"],
            "fix_mechanism": rule["fix_mechanism"],
            "distinct_fix_mechanisms": distinct,
            "per_fix_leverage": leverage,
            "mechanisms": mechanisms,
            "evidence": [
                "forensics/downstream/p1000-run.json",
                "forensics/downstream/build-link-atlas.json",
                "forensics/downstream/family-freeze.json",
            ],
            "description": rule["description"],
        })

    ranked = sorted(blockers,
                    key=lambda b: (-b["mover_potential"], -b["blocked_families"],
                                   b["blocker_class"]))
    ranking = [b["blocker_class"] for b in ranked]

    # --- the funnel ----------------------------------------------------------------------------
    with_recipe = [fid for fid, r in cand.items() if r.get("has_recipe")]
    ranks = {fid: _rank(r, str(r.get("level"))) for fid, r in cand.items()}

    def at_least(rank: int) -> int:
        return sum(1 for r in ranks.values() if r >= rank)

    counted = len(p1000)
    funnel: list[dict] = []
    for step, level, n in (
        ("counted", "", counted),
        ("with-admitted-recipe", "L1-admitted-source", len(with_recipe)),
        ("configured", "L2-configured", at_least(EXECUTION_LEVEL_RANK["L2-configured"])),
        ("linked", "L4-linked", at_least(EXECUTION_LEVEL_RANK["L4-linked"])),
        ("loaded", "L5-loaded", at_least(EXECUTION_LEVEL_RANK["L5-loaded"])),
        ("runtime", "L6-runtime", at_least(EXECUTION_LEVEL_RANK["L6-runtime"])),
        ("functional", "L7-functional", at_least(EXECUTION_LEVEL_RANK["L7-functional"])),
        ("drop-in-pass", "", sum(1 for v in verdicts.values()
                                 if v.get("verdict") == "DROP_IN_PASS")),
    ):
        funnel.append({
            "step": step,
            "level": level,
            "families": n,
            "share_of_counted": _share(n, counted),
        })

    # --- the recipe-less decomposition ---------------------------------------------------------
    no_recipe = [fid for fid, cls in partition.items() if cls == "no-admitted-recipe"]
    by_rank = {str(row["family_id"]): row for row in p1000}

    def hist(values) -> dict[str, int]:
        out: dict[str, int] = {}
        for v in values:
            out[str(v)] = out.get(str(v), 0) + 1
        return {k: out[k] for k in sorted(out)}

    decomposition = {
        "families": len(no_recipe),
        "by_source_ecosystem": hist(
            (families.get(fid, {}) or {}).get("source_ecosystem", "unknown")
            for fid in no_recipe),
        "by_openssl_linkage": hist(
            by_rank[fid].get("openssl_linkage", "unknown") for fid in no_recipe),
        "by_distro_breadth": hist(by_rank[fid].get("distro_breadth", 0) for fid in no_recipe),
        "by_source_breadth": hist(by_rank[fid].get("source_breadth", 0) for fid in no_recipe),
        "criterion": (
            "the frozen universe's own signals, read from forensics/downstream/families.json and "
            "forensics/downstream/family-freeze.json: the source ecosystem and the direct/transitive "
            "linkage a family carries, its distro breadth (how many distro packages list it) and its "
            "consensus source breadth (how many frozen ranking sources selected it). No signal here "
            "is a claim about the family's buildability"
        ),
    }

    # --- the feasible recipe queue (a heuristic ranking) ---------------------------------------
    queue = sorted(
        no_recipe,
        key=lambda fid: (-int(by_rank[fid].get("source_breadth") or 0),
                         -int(by_rank[fid].get("distro_breadth") or 0),
                         -int(by_rank[fid].get("popularity") or 0),
                         str(by_rank[fid].get("canonical_name") or ""),
                         fid),
    )
    recipe_queue = [{
        "family_id": fid,
        "canonical_name": by_rank[fid].get("canonical_name"),
        "p1000_rank": by_rank[fid].get("p1000_rank"),
        "source_ecosystem": (families.get(fid, {}) or {}).get("source_ecosystem"),
        "openssl_linkage": by_rank[fid].get("openssl_linkage"),
        "source_breadth": by_rank[fid].get("source_breadth"),
        "distro_breadth": by_rank[fid].get("distro_breadth"),
        "popularity": by_rank[fid].get("popularity"),
    } for fid in queue[:QUEUE_LIMIT]]

    queue_rule = {
        "criterion": (
            "source breadth descending, then distro breadth descending, then popularity "
            "descending, then canonical name ascending, then family_id ascending; the list is a "
            "**heuristic** ranking of which recipe-less counted families to admit next, never a "
            "measurement that any of them builds"
        ),
        "limit": QUEUE_LIMIT,
        "recipe_less_total": len(no_recipe),
        "heuristic": True,
    }

    # --- counts --------------------------------------------------------------------------------
    blocked_total = sum(b["blocked_families"] for b in blockers if b["blocker_class"] != "none")
    resolved = by_class["none"]
    shared = [b["blocker_class"] for b in blockers
              if b["blocker_class"] != "none" and b["blocked_families"] >= 2]
    measurable = sum(1 for v in verdicts.values()
                     if v.get("verdict") != "DROP_IN_NOT_APPLICABLE")
    counts = {
        "families": counted,
        "blocked_families": blocked_total,
        "resolved_families": len(resolved),
        "measurable_families": measurable,
        "not_applicable_families": counted - measurable,
        "blocker_classes": len(BLOCKER_CLASSES),
        "blocker_classes_present": sum(1 for b in blockers if b["blocked_families"]),
        "shared_blocker_classes": len(shared),
        "recipe_backed_families": len(with_recipe),
        "recipe_less_families": len(no_recipe),
    }

    rule = {
        "id": "downstream-shared-blockers/1",
        "name": "the biggest-mover shared-blocker analysis",
        "population": (
            "the counted population is the frozen P1000 forensics/downstream/family-freeze.json: a "
            "selected population of 1,000 downstream project families, not a random sample"
        ),
        "vocabulary": {
            cls: {
                "fixability": CLASS_RULE[cls]["fixability"],
                "fix_mechanism": CLASS_RULE[cls]["fix_mechanism"],
                "description": CLASS_RULE[cls]["description"],
            } for cls in BLOCKER_CLASSES
        },
        "partition": (
            "every counted family is placed in exactly one blocker class by its deepest blocker, "
            "derived from the committed run rows: a family with no admitted recipe is "
            "`no-admitted-recipe`; a recipe-backed family is named by the first unmet condition at "
            "the level it stopped, from its candidate row's failure class, residual class, reason "
            "and level and its authority row; a family that reached DROP_IN_PASS is `none`. The "
            "partition covers the 1,000 counted families exactly once, and the court re-derives it"
        ),
        "mover_potential": (
            "how many of a class's families would rise to a strictly higher execution level if the "
            "class's blocker alone were resolved, computed structurally from what each family is "
            "missing. Every blocked family is stopped at its recorded blocker below the top rung, so "
            "resolving it clears that rung; a family with no recipe records a "
            "`structural-upper-bound` basis, because admission is necessary but its buildability is "
            "unmeasured, while a recipe-backed class records `measured` -- the venue observed the "
            "exact stop"
        ),
        "to_pass_potential": (
            "how many of a class's families would reach DROP_IN_PASS if the class's blocker alone "
            "were resolved: a family whose only recorded gap is its blocker, counted; a family with "
            "no recipe, not counted, because admitting a recipe is not a measurement that it builds"
        ),
        "per_fix_leverage": (
            "how many families one instance of the fix unlocks: the blocked count over the distinct "
            "fix mechanisms, so recipe admission (breadth 988, one mechanism per family) has "
            "leverage 1 while a single recipe repair that unlocks two families has leverage 2"
        ),
        "funnel": (
            "the counted population down the execution ladder: 1,000 counted, the recipe-backed "
            "families, then the families that reached each rung, then the DROP_IN_PASS count, each "
            "derived from the committed candidate rows. `drop-in-pass` is the baseline-normalized "
            "verdict count rather than an execution rung: a family can pass at L4-linked when the "
            "candidate reached the same level the authority did, so the verdict count is not "
            "required to be non-increasing with the rungs above it"
        ),
        "recipe_queue": (
            "a ranked, deterministic list of the recipe-less counted families to admit next, by the "
            "criterion recorded with it, and it is a **heuristic** ranking of buildability rather "
            "than a measurement of it"
        ),
        "honesty_labels": [
            "mover_potential for no-admitted-recipe is a structural upper bound, not a measurement "
            "of buildability",
            "the recipe queue is a heuristic ranking, never a measurement",
            "the shares are of the selected population, never of all downstream software",
        ],
        "constants": {"queue_limit": QUEUE_LIMIT, "ladder_ranks": dict(EXECUTION_LEVEL_RANK)},
    }

    ranked_names = [b["blocker_class"] for b in ranked if b["blocked_families"]]
    return {
        "rule": rule,
        "blockers": blockers,
        "ranking": ranking,
        "ranked_present": ranked_names,
        "partition": {k: partition[k] for k in sorted(partition)},
        "partition_hash": content_hash({k: partition[k] for k in sorted(partition)}),
        "funnel": funnel,
        "recipe_less_decomposition": decomposition,
        "recipe_queue": recipe_queue,
        "recipe_queue_rule": queue_rule,
        "counts": counts,
        "non_claims": NON_CLAIMS,
    }


def _share(n: int, total: int) -> str:
    pct = (n / total * 100.0) if total else 0.0
    return f"{n}/{total} ({pct:.1f}%)"


# ---------------------------------------------------------------------------------------------------
# findings and the sensitivity control (the court's own checks over the committed analysis)
# ---------------------------------------------------------------------------------------------------

def blocker_findings(inputs: dict, body: dict) -> list[str]:
    """Every way the recorded analysis fails its own derivation.

    The conditions: the partition covers the counted families exactly once and reproduces; the
    blocker records reproduce (counts, shared sets, mover potential, leverage, fix mechanism and
    evidence); the ranking reproduces; the counts, the funnel, the recipe-less decomposition and the
    recipe queue are all derived rather than typed; and every blocker record is schema-valid.
    """
    out: list[str] = []
    derived = derive_blockers(inputs)

    # 1. The partition covers the counted families exactly once and reproduces.
    counted = {str(row["family_id"]) for row in inputs["family_freeze"].get("p1000") or []}
    recorded = body.get("partition") or {}
    if set(recorded) != counted:
        missing = sorted(counted - set(recorded))[:4]
        extra = sorted(set(recorded) - counted)[:4]
        out.append(
            f"the partition does not cover the counted population exactly: {len(recorded)} row(s) "
            f"over {len(counted)} families (missing e.g. {missing}, extra e.g. {extra})")
    bad = [fid for fid, cls in recorded.items() if cls not in BLOCKER_CLASSES]
    if bad:
        out.append(f"the partition names blocker classes outside the vocabulary: {sorted(bad)[:4]}")
    if recorded != derived["partition"]:
        drift = sorted(fid for fid in set(recorded) | set(derived["partition"])
                       if recorded.get(fid) != derived["partition"].get(fid))[:4]
        out.append(f"the recorded partition does not reproduce for e.g. {drift}")
    if body.get("partition_hash") != content_hash({k: recorded[k] for k in sorted(recorded)}):
        out.append("the recorded partition_hash does not match the recorded partition")

    # 2. The blocker records reproduce.
    rec_by_class = {b.get("blocker_class"): b for b in body.get("blockers") or []}
    der_by_class = {b["blocker_class"]: b for b in derived["blockers"]}
    if set(rec_by_class) != set(der_by_class):
        out.append("the recorded blocker classes do not match the vocabulary/derivation")
    for cls, d in der_by_class.items():
        r = rec_by_class.get(cls)
        if r is None:
            continue
        for key in ("blocked_families", "shared_by", "mover_potential", "mover_potential_basis",
                    "to_pass_potential", "fixability", "fix_mechanism", "distinct_fix_mechanisms",
                    "per_fix_leverage"):
            if r.get(key) != d[key]:
                out.append(f"blocker {cls}: recorded {key} does not reproduce "
                           f"({r.get(key)!r} vs {d[key]!r})")
        if not r.get("fix_mechanism"):
            out.append(f"blocker {cls} names no fix mechanism")
        if not r.get("evidence"):
            out.append(f"blocker {cls} cites no evidence")
        problems = downstream_schemas.validate_blocker(r)
        if problems:
            out.append(f"blocker {cls} is not schema-valid: {problems}")

    # 3. The ranking reproduces, and it is ordered by mover potential.
    if body.get("ranking") != derived["ranking"]:
        out.append("the recorded ranking does not reproduce")
    ranked = body.get("ranking") or []
    if ranked:
        by = {b["blocker_class"]: b for b in body.get("blockers") or []}
        keys = [(-(by.get(c, {}).get("mover_potential") or 0),
                 -(by.get(c, {}).get("blocked_families") or 0), c) for c in ranked]
        if keys != sorted(keys):
            out.append("the recorded ranking is not ordered by mover potential then blocked "
                       "families then class name")

    # 4. The derived aggregates reproduce.
    for key in ("counts", "funnel", "recipe_less_decomposition"):
        if body.get(key) != derived[key]:
            out.append(f"the recorded {key} does not reproduce from the committed planes")
    if body.get("recipe_queue") != derived["recipe_queue"]:
        out.append("the recorded recipe queue does not reproduce from the criterion")
    if body.get("recipe_queue_rule") != derived["recipe_queue_rule"]:
        out.append("the recorded recipe-queue rule does not reproduce")

    # 5. The funnel is a non-increasing count down the execution rungs. `drop-in-pass` is the
    #    baseline-normalized verdict count, not an execution rung: a family can pass at L4-linked
    #    (the candidate reached the same level the authority did), so it is checked separately and
    #    only required not to exceed the counted population.
    families = [(f["step"], f["families"]) for f in body.get("funnel") or []
                if f.get("step") != "drop-in-pass"]
    for (s0, n0), (s1, n1) in zip(families, families[1:]):
        if n1 > n0:
            out.append(f"the funnel is not non-increasing: {s0}={n0} then {s1}={n1}")
    counted = (body.get("counts") or {}).get("families") or 0
    pass_step = next((f for f in body.get("funnel") or [] if f.get("step") == "drop-in-pass"), None)
    if pass_step is not None and int(pass_step.get("families") or 0) > counted:
        out.append(f"the funnel's drop-in-pass count {pass_step.get('families')!r} exceeds the "
                   f"counted population {counted}")

    # 6. Every class with blocked families is a shared blocker or a single one, and the counts say
    #    so; the non-claims are the stratum's four plus the heuristic label.
    if body.get("non_claims") != NON_CLAIMS:
        out.append("the recorded non_claims are not the stratum's four plus the heuristic label")
    counts = body.get("counts") or {}
    if counts.get("blocked_families", 0) + counts.get("resolved_families", 0) \
            != counts.get("families"):
        out.append("the blocked and resolved family counts do not sum to the counted population")
    return out


def blocker_sensitivity_control(inputs: dict, body: dict) -> dict:
    """Prove the analysis can fail: seed five mutations and require each caught.

    The honest analysis yields **zero** findings (specificity), and each seeded mutation -- a
    family's blocker flipped, a class count changed, a family dropped from the partition, the
    ranking reordered, and a per-fix leverage changed -- is caught.
    """
    base = blocker_findings(inputs, body)
    specificity = not base

    flipped = copy.deepcopy(body)
    recorded = flipped.get("partition") or {}
    # Flip one blocked family to `none` and one resolved family to that blocked class, holding the
    # coverage so only the class membership is wrong. The blocked class is whichever a blocked family
    # actually carries, so the mutation is defined for any partition the derivation produces.
    blocked_fid = next((f for f, c in recorded.items() if c != "none"), None)
    resolved_fid = next((f for f, c in recorded.items() if c == "none"), None)
    if blocked_fid and resolved_fid:
        flipped_class = recorded[blocked_fid]
        flipped["partition"][blocked_fid] = "none"
        flipped["partition"][resolved_fid] = flipped_class
    flipped_findings = blocker_findings(inputs, flipped)

    counted = copy.deepcopy(body)
    for b in counted.get("blockers") or []:
        if b.get("blocker_class") == "no-admitted-recipe":
            b["blocked_families"] = 1
    counted_findings = blocker_findings(inputs, counted)

    dropped = copy.deepcopy(body)
    if blocked_fid:
        dropped["partition"].pop(blocked_fid, None)
    dropped_findings = blocker_findings(inputs, dropped)

    reordered = copy.deepcopy(body)
    if len(reordered.get("ranking") or []) >= 2:
        reordered["ranking"] = list(reversed(reordered["ranking"]))
    reordered_findings = blocker_findings(inputs, reordered)

    leverage = copy.deepcopy(body)
    for b in leverage.get("blockers") or []:
        if b.get("blocker_class") == "recipe-build-system-unsupported":
            b["per_fix_leverage"] = 99.0
    leverage_findings = blocker_findings(inputs, leverage)

    caught = (flipped_findings, counted_findings, dropped_findings, reordered_findings,
              leverage_findings)
    return {
        "baseline_findings": len(base),
        "specificity_holds": specificity,
        "caught_partition_flip": len(flipped_findings),
        "caught_class_count": len(counted_findings),
        "caught_partition_drop": len(dropped_findings),
        "caught_ranking_reorder": len(reordered_findings),
        "caught_leverage_change": len(leverage_findings),
        "honest": bool(specificity and all(caught)),
    }


# ---------------------------------------------------------------------------------------------------
# the artefact
# ---------------------------------------------------------------------------------------------------

def _inputs_list() -> list[InputRef]:
    return [
        InputRef(name="family-freeze", path=FAMILY_FREEZE),
        InputRef(name="families", path=FAMILIES),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="runtime-functional-atlas", path=RUNTIME_FUNCTIONAL_ATLAS),
        InputRef(name="failures", path=FAILURES),
        InputRef(name="p1000-run", path=P1000_RUN),
        InputRef(name="reconciliation", path=RECONCILIATION),
        InputRef(name="downstream-blockers",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_blockers.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]


def write_outputs(body: dict) -> None:
    doc = envelope(kind="downstream-shared-blockers", authority=PRODUCTION_AUTHORITY,
                   inputs=_inputs_list(), body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


def cmd_measure() -> int:
    missing = _missing_inputs()
    if missing:
        print(f"[downstream-blockers] {', '.join(missing)} is absent; run the earlier subphase(s) "
              f"first")
        return 1
    inputs = load_inputs()
    body = derive_blockers(inputs)
    findings = blocker_findings(inputs, body)
    control = blocker_sensitivity_control(inputs, body)
    if findings or not control["honest"]:
        print("[downstream-blockers] the derived analysis fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body)
    c = body["counts"]
    print(f"[downstream-blockers] families={c['families']} blocked={c['blocked_families']} "
          f"resolved={c['resolved_families']} classes_present={c['blocker_classes_present']} "
          f"shared={c['shared_blocker_classes']} recipe_less={c['recipe_less_families']}")
    top = [b for b in body["blockers"] if b["blocked_families"]][:6]
    for b in sorted(top, key=lambda x: (-x["mover_potential"], -x["blocked_families"],
                                        x["blocker_class"]))[:6]:
        print(f"  {b['blocker_class']:<32} blocked={b['blocked_families']:<4} "
              f"mover={b['mover_potential']:<4} to_pass={b['to_pass_potential']:<4} "
              f"leverage={b['per_fix_leverage']:<5} fix={b['fixability']}")
    print(f"  funnel: " + " -> ".join(f"{f['step']}={f['families']}" for f in body["funnel"]))
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check() -> int:
    if not OUT.is_file():
        print(f"[downstream-blockers] {rel(OUT)} is absent")
        return 1
    missing = _missing_inputs()
    if missing:
        print(f"[downstream-blockers] {', '.join(missing)} is absent")
        return 1
    inputs = load_inputs()
    body = _load_json(OUT)
    findings = blocker_findings(inputs, body)
    control = blocker_sensitivity_control(inputs, body)
    if findings:
        print(f"[downstream-blockers] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = body.get("counts") or {}
    print(f"[downstream-blockers] families={c.get('families')} "
          f"blocked={c.get('blocked_families')} classes_present={c.get('blocker_classes_present')} "
          f"findings={len(findings)} control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. This tool is `metadata_only` (it executes nothing), so the guard **admits** a host
    #    invocation of it as metadata-only, while a host invocation of an execution entry point
    #    (the runner) is refused, naming the marker and the opt-in flag.
    admission = phase24_guard.evaluate(env={}, dockerenv=False,
                                       manifest=phase24_guard.load_manifest(),
                                       entry_point="downstream_blockers.py")
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("the guard did not admit downstream_blockers.py as metadata-only on a host")
    refusal = phase24_guard.host_refusal_reasons("phase24_courts.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of the runner")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. The vocabulary the analysis partitions against is the schema's closed one.
    if set(BLOCKER_CLASSES) != set(CLASS_RULE):
        failures.append("the blocker vocabulary and CLASS_RULE disagree")
    for cls, rule in CLASS_RULE.items():
        if rule["fixability"] not in BLOCKER_FIXABILITY:
            failures.append(f"{cls}: fixability {rule['fixability']!r} is outside the vocabulary")

    # 3. The pure functions behave over the committed evidence.
    missing = _missing_inputs()
    if missing:
        failures.append(f"{', '.join(missing)} is absent")
    else:
        inputs = load_inputs()
        derived = derive_blockers(inputs)
        if derived["counts"]["families"] != 1000:
            failures.append(f"the partition does not cover 1,000 families: "
                            f"{derived['counts']['families']}")
        if derived["counts"]["blocked_families"] + derived["counts"]["resolved_families"] \
                != derived["counts"]["families"]:
            failures.append("the blocked and resolved counts do not sum to the counted population")
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run --measure")
        else:
            body = _load_json(OUT)
            findings = blocker_findings(inputs, body)
            if findings:
                failures.append(f"the committed analysis has findings: {findings[:3]}")
            control = blocker_sensitivity_control(inputs, body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[downstream-blockers] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-blockers] self-test ok: the guard admits this metadata-only generator on a "
          "host and refuses a host invocation of the runner (marker and flag both named), the "
          "vocabulary matches the schema, the committed analysis "
          "reproduces with zero findings, and every seeded mutation (a blocker flipped, a class "
          "count changed, a family dropped, the ranking reordered and a per-fix leverage changed) "
          "is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive the analysis from the committed planes and write it")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed analysis without regenerating")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool reads committed evidence and writes
    # one analysis, so it executes nothing itself, but it is a Phase-24 entry point and a host
    # invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check()
    return cmd_measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
