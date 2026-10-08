#!/usr/bin/env python3
"""openssl-rs — render the biggest-mover shared-blocker report, and the README block (24.16).

Why this exists
---------------
`forensics/tools/downstream_blockers.py` derives the shared-blocker analysis into
`forensics/downstream/shared-blockers.json`; this generator renders it into the two places a reader
meets it -- a detailed report, `docs/PHASE-24-BIGGEST-MOVERS.md`, and a compact, marker-bounded
table in `README.md` -- from that artefact **only**, so a hand-edited summary cannot drift from the
derivation. The README block is bounded by

    <!-- BEGIN GENERATED: downstream-blockers -->
    <!-- END GENERATED: downstream-blockers -->

and everything outside the markers is preserved byte-for-byte; a missing or duplicated marker is a
hard failure rather than a silent overwrite. The report links to `docs/SEAL-CENSUS.md`, whose
generated "Biggest movers" section links back, so the analysis is reachable from all three places.

This generator executes nothing: it reads the committed analysis and the final P1000 run (for the
baseline-normalized pass split it states), and writes prose. It is therefore
declared `metadata_only` in `forensics/downstream/container.json` and `evidence_determinism.py`
regenerates it host-side.

Outputs
-------
  docs/PHASE-24-BIGGEST-MOVERS.md
  README.md (the marker-bounded block only)

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel, write_text  # noqa: E402

# The Docker-only execution guard. Its call is the first statement of `main`: this generator reads
# one committed artefact and writes prose, so it executes nothing itself, but it is a Phase-24
# entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

SHARED = REPO_ROOT / "forensics" / "downstream" / "shared-blockers.json"
REPORT = REPO_ROOT / "docs" / "PHASE-24-BIGGEST-MOVERS.md"
README = REPO_ROOT / "README.md"
GENERATOR = "forensics/tools/render_biggest_movers.py"

README_BEGIN = "<!-- BEGIN GENERATED: downstream-blockers -->"
README_END = "<!-- END GENERATED: downstream-blockers -->"

# The report path and the census path, as literal strings the court requires both documents to
# carry, so a broken cross-link is a finding rather than a plausible report.
REPORT_PATH = "docs/PHASE-24-BIGGEST-MOVERS.md"
CENSUS_PATH = "docs/SEAL-CENSUS.md"
README_URL = "https://github.com/infinityabundance/openssl-rs/blob/main/docs/PHASE-24-BIGGEST-MOVERS.md"

# The final full P1000 run: the pass-level split the caveat states is derived from its verdict rows'
# `candidate_level`, never typed. This generator reads committed evidence and writes prose, so this
# is a committed-evidence read, not an execution (see the module docstring).
P1000_RUN = REPO_ROOT / "forensics" / "downstream" / "p1000-run.json"

# The funnel's baseline-normalized verdict step, the `kind` labels that separate it from the rungs,
# and the level at which a baseline-normalized pass has no runtime workload behind it.
VERDICT_STEP = "drop-in-pass"
RUNG_KIND = "rung"
VERDICT_KIND = "verdict"
NO_RUNTIME_LEVEL = "L4-linked"


def load_shared() -> dict:
    """The committed analysis body, or an empty dict when the artefact is absent."""
    if not SHARED.is_file():
        return {}
    return json.loads(SHARED.read_text(encoding="utf-8")).get("body", {})


def _share(n: int, total: int) -> str:
    pct = (n / total * 100.0) if total else 0.0
    return f"{n}/{total} ({pct:.1f}%)"


def _blocker_rows(body: dict, *, include_resolved: bool = False) -> list[dict]:
    """The blocker classes with at least one counted family, in ranked order.

    `none` is the resolved class rather than a blocker, so it is excluded unless the caller asks
    for it (the partition table needs it so the shares sum to the counted population).
    """
    by = {b["blocker_class"]: b for b in body.get("blockers") or []}
    out = [by[c] for c in body.get("ranking") or [] if c in by and by[c]["blocked_families"]]
    if not include_resolved:
        out = [b for b in out if b["blocker_class"] != "none"]
    return out


def funnel_kind(step: str) -> str:
    """The `kind` of a funnel entry: an execution `rung`, or the baseline-normalized `verdict`.

    `drop-in-pass` is the baseline-normalized verdict count, not a rung: a family can pass at
    `L4-linked` when the candidate reached exactly the level the authority did, so the verdict count
    is not required to be non-increasing with the rungs above it and the funnel is not a nested
    ladder. The `kind` column makes that visible in the rendered table.
    """
    return VERDICT_KIND if step == VERDICT_STEP else RUNG_KIND


def pass_level_split(p1000: dict) -> dict:
    """How the `DROP_IN_PASS` families split by the level the candidate reached.

    Derived from `forensics/downstream/p1000-run.json`'s verdict rows' `candidate_level`, never
    typed. A pass at `L4-linked` is baseline-normalized with **no admitted runtime workload** for that
    family -- the candidate reached exactly the level the authority itself reached -- while a pass at
    `L5` or above reached a runtime level. `p1000` is that artefact's `body`.
    """
    passes = [v for v in p1000.get("verdicts") or []
              if str(v.get("verdict")) == "DROP_IN_PASS"]
    at_linked = sum(1 for v in passes if str(v.get("candidate_level")) == NO_RUNTIME_LEVEL)
    return {"passes": len(passes), "at_linked": at_linked, "at_l5_plus": len(passes) - at_linked}


def pass_split_sentence(split: dict) -> str:
    """The derived caveat clause, reused by the report, the census section and the seal marker.

    A single sentence, lower-cased at the start so it reads after a colon, stating how many passes
    sit at `L4-linked` with no admitted runtime workload versus how many reach `L5` or above.
    """
    return (f"of the {split['passes']} drop-in passes, {split['at_linked']} are at "
            f"{NO_RUNTIME_LEVEL} with no admitted runtime workload for those families and "
            f"{split['at_l5_plus']} reach L5 or above")


def readme_block(body: dict, p1000: dict) -> str:
    """The compact generated README block, a pure function of the analysis and the final run."""
    rows = _blocker_rows(body)
    counts = body.get("counts") or {}
    split = pass_level_split(p1000)
    lines: list[str] = [README_BEGIN, ""]
    lines.append("## Downstream-1000 biggest movers (generated)")
    lines.append("")
    lines.append(
        "Every one of the "
        f"{counts.get('families')} counted families, partitioned by its **deepest blocker** and "
        "the classes ranked by **mover potential**, with the feasible recipe queue, is in the")
    lines.append(f"[generated report]({README_URL}) (`{REPORT_PATH}`); the same table is cited by")
    lines.append(f"`{CENSUS_PATH}`. This block is generated from")
    lines.append("`forensics/downstream/shared-blockers.json` — **do not edit it by hand.**")
    lines.append("")
    lines.append("| blocker class | families | mover potential | fixability | per-fix leverage |")
    lines.append("|---|---|---|---|---|")
    for b in rows:
        lines.append(
            f"| `{b['blocker_class']}` | {b['blocked_families']} | {b['mover_potential']} | "
            f"`{b['fixability']}` | {b['per_fix_leverage']} |")
    lines.append("")
    lines.append(
        f"**{counts.get('blocked_families')} of the {counts.get('families')} counted families are "
        f"blocked; {counts.get('resolved_families')} are `DROP_IN_PASS`** "
        f"({counts.get('not_applicable_families')} are `DROP_IN_NOT_APPLICABLE`, "
        f"{counts.get('measurable_families')} measurable). The `{VERDICT_STEP}` figure is a "
        f"baseline-normalized verdict count, not a rung: {pass_split_sentence(split)}.")
    lines.append("")
    for claim in body.get("non_claims") or []:
        lines.append(f"* {claim}")
    lines.append("")
    lines.append(README_END)
    return "\n".join(lines)


def render_report(body: dict, p1000: dict) -> str:
    """The detailed generated report, a pure function of the analysis and the final run."""
    rule = body.get("rule") or {}
    counts = body.get("counts") or {}
    rows = _blocker_rows(body)
    funnel = body.get("funnel") or []
    dec = body.get("recipe_less_decomposition") or {}
    queue = body.get("recipe_queue") or []
    qrule = body.get("recipe_queue_rule") or {}
    L: list[str] = []
    L.append("# Phase 24 — the downstream-1000 biggest movers (generated)")
    L.append("")
    L.append(f"**STATUS: derived.** Generated by `{GENERATOR}` from")
    L.append("`forensics/downstream/shared-blockers.json`, which")
    L.append("`forensics/tools/downstream_blockers.py` derives from the committed Phase-24 planes.")
    L.append("**Do not edit this document by hand.** It is the detailed companion to the compact")
    L.append(f"table in `../README.md` and to the `Biggest movers` section of `{CENSUS_PATH}`; the")
    L.append("same figure regenerates in all three, so none can drift from the derivation.")
    L.append("")
    L.append("## The honest accounting")
    L.append("")
    L.append(
        f"Of the **{counts.get('families')} counted families**, only "
        f"**{counts.get('recipe_backed_families')} have an admitted pristine-source recipe** in this")
    L.append(
        f"venue, and **{counts.get('recipe_less_families')} have none** (`no-admitted-recipe`); "
        f"**{counts.get('not_applicable_families')} of the "
        f"{counts.get('families')}** are `DROP_IN_NOT_APPLICABLE`, so the drop-in measurement reaches "
        f"a small measured surface of **{counts.get('measurable_families')} measurable families**. "
        "The **mechanically-shared**")
    L.append("blockers — the classes where one fix unlocks several families — are the recipe-backed")
    L.append("failures, not the breadth of recipe admission. This is a measurement of a *selected*")
    L.append("population, not a rate over all downstream software.")
    L.append("")
    L.append("## The partition")
    L.append("")
    L.append("Every counted family is placed in exactly one blocker class by its deepest blocker,")
    L.append("derived from the committed run rows (never typed). The partition covers the counted")
    L.append(
        f"families exactly once, and its content hash is `{body.get('partition_hash')}`.")
    L.append("")
    L.append("| blocker class | families | share of the counted population |")
    L.append("|---|---|---|")
    for b in sorted(_blocker_rows(body, include_resolved=True),
                    key=lambda x: (-x["blocked_families"], x["blocker_class"])):
        L.append(f"| `{b['blocker_class']}` | {b['blocked_families']} | "
                 f"{_share(b['blocked_families'], counts.get('families') or 0)} |")
    L.append("")
    L.append(f"**{counts.get('blocked_families')} of the {counts.get('families')} counted families "
             f"are blocked; {counts.get('resolved_families')} reached `DROP_IN_PASS`.**")
    L.append("")
    L.append("## The ranked shared blockers")
    L.append("")
    L.append("Ranked by **mover potential** (ties by blocked families, then class name). *Mover")
    L.append("potential* is how many families rise a level if this blocker alone is resolved;")
    L.append("*to-pass potential* is how many would then reach `DROP_IN_PASS`; *per-fix leverage* is")
    L.append("how many families one instance of the fix unlocks, so a single recipe repair that")
    L.append("unlocks two families has leverage 2 while recipe admission (one recipe per family) has")
    L.append("leverage 1.")
    L.append("")
    L.append("| rank | blocker class | blocked families | mover potential | to-pass potential | "
             "fixability | per-fix leverage | fix mechanism |")
    L.append("|---|---|---|---|---|---|---|---|")
    for i, b in enumerate(rows, start=1):
        L.append(
            f"| {i} | `{b['blocker_class']}` | {b['blocked_families']} | "
            f"{b['mover_potential']} ({b['mover_potential_basis']}) | {b['to_pass_potential']} | "
            f"`{b['fixability']}` | {b['per_fix_leverage']} | {b['fix_mechanism']} |")
    L.append("")
    L.append("**A shared blocker** is a class with two or more counted families. "
             f"There are {counts.get('shared_blocker_classes')} of them; the rest are single-family "
             "classes.")
    L.append("")
    L.append("### The mechanism behind each shared blocker")
    L.append("")
    for b in rows:
        if b["blocked_families"] < 2:
            continue
        L.append(f"* `{b['blocker_class']}` — {b['description']}")
        L.append(f"  * fixability `{b['fixability']}`, {b['distinct_fix_mechanisms']} distinct "
                 f"mechanism(s), per-fix leverage {b['per_fix_leverage']}: {b['fix_mechanism']}")
        if b["mechanisms"] and b["blocked_families"] < 50:
            L.append(f"  * mechanisms: {', '.join('`' + m + '`' for m in b['mechanisms'])}")
        if b["blocked_families"] < 50:
            L.append(f"  * families: {', '.join(b['shared_by'])}")
    L.append("")
    L.append("## The funnel")
    L.append("")
    L.append("The counted population down the execution ladder, each step derived from the")
    L.append("committed candidate rows. A rung is not a behaviour: only the functional level is")
    L.append("behavioural evidence, and `with-admitted-recipe` is a property of the venue, not of")
    L.append("the families. The `kind` column separates the **execution rungs** from the")
    L.append("**baseline-normalized verdict count**: `drop-in-pass` is not nested under the rungs")
    L.append("above it, so the figure is visibly not a single monotone funnel.")
    L.append("")
    L.append("| kind | step | families | share of the counted population |")
    L.append("|---|---|---|---|")
    for f in funnel:
        L.append(f"| {funnel_kind(f['step'])} | {f['step']} | {f['families']} | "
                 f"{f['share_of_counted']} |")
    L.append("")
    L.append("The material caveat this makes visible: " + pass_split_sentence(pass_level_split(p1000))
             + ".")
    L.append("")
    L.append("## The recipe-less decomposition")
    L.append("")
    L.append(f"The **{dec.get('families')}** `no-admitted-recipe` families are the dominant class, "
             "broken")
    L.append("down by what the frozen universe already knows about them — never by a claim about")
    L.append("their buildability:")
    L.append("")
    L.append(f"* **source ecosystem**: " + ", ".join(
        f"`{k}` {v}" for k, v in (dec.get("by_source_ecosystem") or {}).items()))
    L.append(f"* **direct/transitive linkage**: " + ", ".join(
        f"`{k}` {v}" for k, v in (dec.get("by_openssl_linkage") or {}).items()))
    L.append(f"* **distro breadth**: " + ", ".join(
        f"{k} → {v}" for k, v in sorted(
            (dec.get("by_distro_breadth") or {}).items(), key=lambda kv: int(kv[0]))))
    L.append(f"* **consensus source breadth**: " + ", ".join(
        f"{k} → {v}" for k, v in sorted(
            (dec.get("by_source_breadth") or {}).items(), key=lambda kv: int(kv[0]))))
    L.append("")
    L.append(f"* criterion: {dec.get('criterion')}")
    L.append("")
    L.append("## The feasible recipe queue (a heuristic)")
    L.append("")
    L.append("This is a **heuristic** ranking of which recipe-less counted families to admit next, "
             "and")
    L.append("it is **not a measurement of buildability**: no family in it has been built by this")
    L.append("analysis. The criterion is recorded with the artefact and repeated here.")
    L.append("")
    L.append(f"* criterion: {qrule.get('criterion')}")
    L.append(f"* showing the first {qrule.get('limit')} of "
             f"{qrule.get('recipe_less_total')} recipe-less families, `heuristic: "
             f"{str(qrule.get('heuristic')).lower()}`")
    L.append("")
    L.append("| rank | family | p1000 rank | ecosystem | linkage | source breadth | distro breadth "
             "| popularity |")
    L.append("|---|---|---|---|---|---|---|---|")
    for i, q in enumerate(queue, start=1):
        L.append(f"| {i} | {q.get('canonical_name')} | {q.get('p1000_rank')} | "
                 f"{q.get('source_ecosystem')} | {q.get('openssl_linkage')} | "
                 f"{q.get('source_breadth')} | {q.get('distro_breadth')} | {q.get('popularity')} |")
    L.append("")
    L.append("## Non-claims")
    L.append("")
    for claim in body.get("non_claims") or []:
        L.append(f"* {claim}")
    L.append("")
    L.append("## Where else this is generated")
    L.append("")
    L.append(f"* `{CENSUS_PATH}` — the generated seal census carries the ranked blocker table, "
             "the funnel and a link back to this report.")
    L.append("* `../README.md` — the marker-bounded `downstream-blockers` block carries the top")
    L.append("  shared blockers and links here.")
    L.append("* `forensics/downstream/shared-blockers.json` — the machine-readable analysis the")
    L.append("  `RT-BLOCKER-LEVERAGE` court re-derives.")
    L.append("")
    return "\n".join(L)


def extract_readme_block(readme_text: str) -> str:
    """The marker-bounded block, or a hard error when the markers are missing or duplicated."""
    if readme_text.count(README_BEGIN) != 1 or readme_text.count(README_END) != 1:
        raise ValueError(
            f"{rel(README)} must carry exactly one {README_BEGIN!r} and one {README_END!r}; "
            f"found {readme_text.count(README_BEGIN)} and {readme_text.count(README_END)}")
    start = readme_text.index(README_BEGIN)
    end = readme_text.index(README_END) + len(README_END)
    if end < start:
        raise ValueError(f"{rel(README)} markers are out of order")
    return readme_text[start:end]


def apply_readme_block(readme_text: str, block: str) -> str:
    """Replace the marker-bounded block, preserving everything else byte-for-byte."""
    start = readme_text.index(README_BEGIN)
    end = readme_text.index(README_END) + len(README_END)
    # `extract_readme_block` is the marker validation; calling it here keeps one definition.
    extract_readme_block(readme_text)
    return readme_text[:start] + block + readme_text[end:]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="validate the committed report and README block without writing")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This generator reads committed evidence and
    # writes prose, so it executes nothing itself, but it is a Phase-24 entry point and a host
    # invocation is refused.
    phase24_guard.require_admitted()

    body = load_shared()
    if not body:
        print(f"[render-biggest-movers] {rel(SHARED)} is absent; run "
              f"forensics/tools/downstream_blockers.py --measure first")
        return 1
    p1000 = (json.loads(P1000_RUN.read_text(encoding="utf-8")).get("body", {})
             if P1000_RUN.is_file() else {})

    report = render_report(body, p1000)
    block = readme_block(body, p1000)
    readme = README.read_text(encoding="utf-8")
    try:
        new_readme = apply_readme_block(readme, block)
    except ValueError as exc:
        print(f"[render-biggest-movers] {exc}")
        return 1

    if args.check:
        problems: list[str] = []
        if not REPORT.is_file() or REPORT.read_text(encoding="utf-8") != report:
            problems.append(f"{rel(REPORT)} does not reproduce from {rel(SHARED)}")
        if new_readme != readme:
            problems.append(f"{rel(README)}'s downstream-blockers block does not reproduce")
        if problems:
            print("[render-biggest-movers] FAIL:")
            for p in problems:
                print(f"  - {p}")
            return 1
        print(f"[render-biggest-movers] ok: {rel(REPORT)} and the {rel(README)} block reproduce "
              f"from {rel(SHARED)}")
        return 0

    write_text(REPORT, report)
    if new_readme != readme:
        README.write_text(new_readme, encoding="utf-8")
    print(f"[render-biggest-movers] {rel(REPORT)} and the {rel(README)} block -> from "
          f"{rel(SHARED)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
