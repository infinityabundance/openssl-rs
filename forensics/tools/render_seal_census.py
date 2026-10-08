#!/usr/bin/env python3
"""openssl-rs — the seal census, generated so a seal never restates a number.

Why this exists
---------------
Each stratum's seal document (`docs/PHASE-3-CORE-RUNTIME-SEAL.md` and its
successors) carries a census: how many exports the stratum owns, how many are
implemented, how many are handed on, how many courts observed them. Those numbers
were **prose**, typed by hand at seal time, and prose does not regenerate. The
consequence was measured: `docs/PHASE-5-BN-ASN1-PEM-SEAL.md` opened by saying ASN.1
and PEM were "entirely open", that 5,271 libcrypto exports remained scaffolded, and
that the stratum owned 513 exports, while a later section of *the same document*
correctly said 155 open -- and the generated `forensics/STATUS.md` said something
else again. That is precisely the internal record contradiction this project exists
to prevent, and it happened inside the document that is supposed to be the record.

The fix is not to type the numbers more carefully. It is to stop typing them. This
tool renders **one** census for every stratum, from the ledgers and the court
results, and the seals cite it. A seal's prose is then free to be about what was
established; the arithmetic lives where it regenerates.

    forensics/STATUS.md          derived state and per-stratum ledgers
    docs/SEAL-CENSUS.md          the arithmetic a seal cites, in one place

Outputs
-------
  docs/SEAL-CENSUS.md

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    REPO_ROOT,
    SEAL_DOCS,
    contract_unit_lines,
    court_observations,
    has_transcript,
    rel,
)

OUT = REPO_ROOT / "docs" / "SEAL-CENSUS.md"
GENERATOR = "forensics/tools/render_seal_census.py"


def load(relpath: str):
    p = REPO_ROOT / relpath
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None


def _share(n: int, total: int) -> str:
    """`n` of `total` as a fraction and a **computed** percentage, never a typed rate."""
    pct = (n / total * 100.0) if total else 0.0
    return f"{n}/{total} ({pct:.1f}%)"


def _downstream_outcome_lines(p1000: dict) -> list[str]:
    """The generated downstream-1000 outcome section: how many of the 1,000 were successful.

    Every figure is read from the committed final full P1000 run
    `forensics/downstream/p1000-run.json` or computed from its verdict histogram. The shares are
    computed rather than typed, and the successful count is the `DROP_IN_PASS` bucket of that
    histogram rather than a literal, so a stale sentence cannot survive a regeneration. This is
    the census's one view of the Phase-24 population; the seal cites it rather than restating it.
    """
    body = p1000.get("body") or {}
    counts = body.get("counts") or {}
    ladder = body.get("ladder") or {}
    levels = ladder.get("levels") or {}
    families = counts.get("families") or 0
    measurable = counts.get("measurable_families") or 0
    not_applicable = counts.get("not_applicable_families") or 0
    recipe = counts.get("recipe_backed_families") or 0
    reaches = counts.get("measurable_reaches_baseline") or 0
    verdicts = counts.get("verdicts") or {}
    non_claims = body.get("non_claims") or []
    successful = verdicts.get("DROP_IN_PASS") or 0

    def rate(n: int, d: int) -> str:
        return f"{n}/{d} = {n / d * 100.0:.1f}%" if d else "n/a"

    L: list[str] = []
    L.append("## Downstream-1000 outcomes (generated)")
    L.append("")
    L.append("How many of the counted population the frozen candidate passed, from the committed")
    L.append("final full P1000 run `forensics/downstream/p1000-run.json`. The counted population is")
    L.append(f"the frozen P1000: **{families}** selected project families, each measured under both")
    L.append("subjects exactly once. This is the arithmetic the Phase-24 seal cites; the seal's")
    L.append("prose is about what was established, not about these counts.")
    L.append("")
    L.append("| outcome | families | share of the 1,000 |")
    L.append("|---|---|---|")
    for verdict in ("DROP_IN_PASS", "DROP_IN_PARTIAL", "DROP_IN_FAIL",
                    "DROP_IN_UNKNOWN", "DROP_IN_NOT_APPLICABLE"):
        n = verdicts.get(verdict) or 0
        L.append(f"| `{verdict}` | {n} | {_share(n, families)} |")
    L.append(f"| **total** | **{families}** | **{_share(families, families)}** |")
    L.append("")
    L.append(f"**{successful} of the {families} counted families are `DROP_IN_PASS`.** That is")
    L.append(f"{rate(successful, families)} of the counted population, "
             f"{rate(successful, measurable)}")
    L.append(f"of the {measurable} measurable families, and {rate(successful, recipe)} of the")
    L.append(f"{recipe} recipe-backed families. A `DROP_IN_NOT_APPLICABLE` family is **neither a")
    L.append("success nor a failure**: it is a counted family this venue could not pose the")
    L.append("drop-in question for because it has no admitted pristine-source recipe, so its")
    L.append(f"{not_applicable} rows are neither passes nor failures.")
    L.append("")
    L.append("### The measurable families, in detail")
    L.append("")
    L.append("Every family whose verdict is not `DROP_IN_NOT_APPLICABLE`, sorted by the frozen")
    L.append("`p1000_rank`. The authority-applicable baseline is the highest level the authority")
    L.append("itself reached, and the candidate is judged against it, so a `DROP_IN_PASS` is")
    L.append("baseline-normalized rather than an aspirational claim.")
    L.append("")
    L.append("| family | verdict | authority-applicable baseline | candidate level | "
             "linkage proven | residual |")
    L.append("|---|---|---|---|---|---|")
    measurable_rows = [v for v in (body.get("verdicts") or [])
                       if v.get("verdict") != "DROP_IN_NOT_APPLICABLE"]
    for v in sorted(measurable_rows, key=lambda r: r.get("p1000_rank") or 0):
        L.append(
            f"| {v.get('canonical_name')} | `{v.get('verdict')}` | "
            f"{v.get('authority_applicable_level')} | {v.get('candidate_level')} | "
            f"{'yes' if v.get('linkage_proven') else 'no'} | {v.get('residual_class')} |")
    L.append("")
    L.append("### The ladder")
    L.append("")
    L.append("| level | families |")
    L.append("|---|---|")
    for level in (body.get("rule") or {}).get("levels") or list(levels):
        L.append(f"| {level} | {levels.get(level)} |")
    L.append("")
    L.append(f"The ladder is over the frozen P1000: {families} counted families, {measurable}")
    L.append(f"measurable and {not_applicable} not applicable. **UNKNOWN is 0** -- every counted")
    L.append("family is measured, and a family this venue cannot pose the drop-in question for is")
    L.append("an honest non-applicability, not an unknown.")
    L.append("")
    L.append("### Authority baseline and the non-claims")
    L.append("")
    L.append(f"The candidate reached its authority-applicable baseline for **all {measurable}")
    L.append(f"measurable families** ({reaches}/{measurable}). The {len(non_claims)} non-claims")
    L.append("recorded with the run apply in full:")
    L.append("")
    for claim in non_claims:
        L.append(f"* {claim}")
    L.append("")
    return L


def _biggest_movers_lines(shared: dict) -> list[str]:
    """The generated biggest-movers section: the ranked blocker classes, the funnel and a link.

    Every figure is read from the committed analysis `forensics/downstream/shared-blockers.json`
    (24.16), which `forensics/tools/downstream_blockers.py` derives from the Phase-24 planes. The
    section renders **nothing** when the analysis is absent, so an earlier branch produces no
    section rather than an empty one. It is the census's detailed view of the shared blockers; the
    compact view is the `downstream-blockers` block in `README.md`, and both link to the report.
    """
    body = (shared or {}).get("body") or {}
    if not body:
        return []
    counts = body.get("counts") or {}
    by = {b["blocker_class"]: b for b in body.get("blockers") or []}
    rows = [by[c] for c in body.get("ranking") or []
            if c in by and by[c]["blocked_families"] and c != "none"]
    funnel = body.get("funnel") or []
    L: list[str] = []
    L.append("## Biggest movers (generated)")
    L.append("")
    L.append("Every one of the "
             f"{counts.get('families')} counted families is partitioned by its **deepest "
             "blocker**, each counted exactly once, and the classes are ranked by **mover "
             "potential** (how many families rise a level if the blocker alone is resolved), with "
             "the **per-fix leverage** (how many families one instance of the fix unlocks). The "
             "detailed report is "
             "[`docs/PHASE-24-BIGGEST-MOVERS.md`](https://github.com/infinityabundance/openssl-rs/"
             "blob/main/docs/PHASE-24-BIGGEST-MOVERS.md); the compact table is the "
             "`downstream-blockers` block in `README.md`. Every figure is derived from "
             "`forensics/downstream/shared-blockers.json` and none is typed here.")
    L.append("")
    L.append("| rank | blocker class | blocked families | mover potential | to-pass potential | "
             "fixability | per-fix leverage |")
    L.append("|---|---|---|---|---|---|---|")
    for i, b in enumerate(rows, start=1):
        L.append(f"| {i} | `{b['blocker_class']}` | {b['blocked_families']} | "
                 f"{b['mover_potential']} | {b['to_pass_potential']} | `{b['fixability']}` | "
                 f"{b['per_fix_leverage']} |")
    L.append("")
    L.append(f"**{counts.get('blocked_families')} of the {counts.get('families')} counted families "
             f"are blocked; {counts.get('resolved_families')} are `DROP_IN_PASS`.** The "
             f"{counts.get('shared_blocker_classes')} shared blocker classes are the recipe-backed "
             "failures and the missing fixtures, not the breadth of recipe admission "
             f"(`no-admitted-recipe`, {counts.get('recipe_less_families')} families, has per-fix "
             "leverage 1).")
    L.append("")
    L.append("The funnel, from the committed candidate rows:")
    L.append("")
    L.append("| step | families | share of the counted population |")
    L.append("|---|---|---|")
    for f in funnel:
        L.append(f"| {f['step']} | {f['families']} | {f['share_of_counted']} |")
    L.append("")
    L.append("The recipe-less decomposition and the (heuristic) feasible recipe queue are in the "
             "detailed report; a heuristic ranking of buildability is not a measurement of it.")
    L.append("")
    return L


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args(argv)

    ownership = load("forensics/atlas/symbol-ownership.json")
    state = load("forensics/phase-state.json")
    audit = load("forensics/atlas/ownership-audit.json")

    if ownership is None or state is None:
        raise SystemExit(
            "[seal-census] forensics/atlas/symbol-ownership.json and "
            "forensics/phase-state.json are both required; run the generators first"
        )

    phases = {int(r["phase"]): r for r in state["body"]["phases"]}
    by_phase = {int(k): v for k, v in ownership["body"]["by_phase"].items()}

    ledgers: dict[int, dict] = {}
    for p in sorted((REPO_ROOT / "forensics").glob("phase*-obligations.json")):
        m = re.fullmatch(r"phase(\d+)-obligations\.json", p.name)
        if m:
            ledgers[int(m.group(1))] = json.loads(p.read_text(encoding="utf-8"))["body"]

    courts: dict[int, dict] = {}
    for p in sorted((REPO_ROOT / "artifacts").glob("phase*/COURTS.json")):
        m = re.fullmatch(r"phase(\d+)", p.parent.name)
        if m:
            courts[int(m.group(1))] = json.loads(p.read_text(encoding="utf-8"))["body"]

    surface = load("forensics/atlas/implemented-surface.json")
    coverage = load("forensics/atlas/court-coverage.json")

    L: list[str] = []
    L.append("# Seal census (generated)")
    L.append("")
    L.append("Generated by `forensics/tools/render_seal_census.py` from")
    L.append("`forensics/atlas/symbol-ownership.json`, `forensics/phase-state.json`,")
    L.append("the `forensics/phase<N>-obligations.json` ledgers and the")
    L.append("`artifacts/phase<N>/COURTS.json` results. **Do not edit by hand, and do")
    L.append("not restate these numbers in a seal.** A seal cites this document; the")
    L.append("arithmetic lives here, where it regenerates")
    L.append("(docs/DECISIONS.md D97).")
    L.append("")
    L.append("Nothing here is a parity claim. `implemented` means a symbol with that")
    L.append("name is defined; `open` means the stratum owns it and has not built it;")
    L.append("`deferred` means a recorded hand-off with the dependency named. See")
    L.append("`docs/PARITY_MODEL.md`.")
    L.append("")

    if surface is not None:
        t = surface["body"]["totals"]
        L.append("## Library totals")
        L.append("")
        L.append("| library | authority exports | implemented | scaffolded |")
        L.append("|---|---|---|---|")
        for lib in ("libcrypto", "libssl"):
            row = surface["body"]["libraries"][lib]
            L.append(f"| {lib} | {row['authority_exports']} | {row['implemented']} | "
                     f"{row['scaffolded']} |")
        L.append(f"| **total** | **{t['authority_exports']}** | "
                 f"**{t['implemented']}** | **{t['scaffolded']}** |")
        L.append("")

    L.append("## Ownership atlas, by stratum")
    L.append("")
    L.append("Every one of the authority's "
             f"{ownership['body']['universe']['exports']} exports has exactly one")
    L.append("declared owner; this is that assignment.")
    L.append("")
    L.append("| phase | stratum | state | atlas-owned | ledger owned | implemented | deferred | open |")
    L.append("|---|---|---|---|---|---|---|---|")
    for phase in sorted(phases):
        if phase < 3:
            continue
        ledger = ledgers.get(phase)
        counts = (ledger or {}).get("counts", {})
        deferred = counts.get("deferred", counts.get("deferred_to_later_phase"))
        L.append(
            f"| {phase} | {phases[phase]['stratum']} | `{phases[phase]['state']}` | "
            f"{by_phase.get(phase, 0)} | {counts.get('owned', '—')} | "
            f"{counts.get('implemented', '—')} | "
            f"{deferred if deferred is not None else '—'} | "
            f"{counts.get('open_in_this_stratum', '—')} |"
        )
    L.append("")

    for phase in sorted(ledgers):
        ledger = ledgers[phase]
        counts = ledger["counts"]
        row = phases.get(phase, {})
        L.append(f"## Phase {phase} — {row.get('stratum', '(unknown stratum)')}")
        L.append("")
        L.append(f"* state: `{row.get('state', 'unknown')}`")
        if row.get("blocking"):
            L.append(f"* blocking: {row['blocking']}")
        # A stratum with no seal yet is rendered from its ledger and says so, rather than
        # being omitted: an omitted stratum reads as a stratum with nothing to say.
        seal = SEAL_DOCS.get(phase)
        if seal and (REPO_ROOT / seal).is_file():
            L.append(f"* seal: `{seal}`")
        else:
            L.append(f"* seal: none written yet (`{seal or 'unnamed'}`)")
        L.append(f"* ledger: `forensics/phase{phase}-obligations.json`")
        L.append(f"* atlas-owned: {counts.get('atlas_owned', counts.get('owned'))}")
        L.append(f"* owned working set: {counts['owned']}")
        L.append(f"* implemented: {counts['implemented']}")
        deferred_count = counts.get("deferred", counts.get("deferred_to_later_phase"))
        if deferred_count is not None:
            L.append(f"* deferred to a later stratum with a stated reason: "
                     f"{deferred_count}")
        if "open_in_this_stratum" in counts:
            L.append(f"* **open in this stratum: {counts['open_in_this_stratum']}**")
        L.append("")

        # A non-export stratum's working set lives in its contract units, so they are rendered
        # here with both axes. Without this, a passing `CT-PRIMITIVES` and a not-claimed
        # constant-time property would look identical to a reader of this census.
        L.extend(contract_unit_lines(ledger))

        by_owner: dict[int, list[dict]] = {}
        for r in ledger.get("deferred", []):
            by_owner.setdefault(int(r["owning_phase"]), []).append(r)
        if by_owner:
            L.append("Deferred out, by receiving stratum:")
            L.append("")
            for owner in sorted(by_owner):
                rows = by_owner[owner]
                discharged = sum(1 for r in rows if r.get("implemented_by_owner"))
                L.append(f"* to phase {owner}: {len(rows)} symbol(s)"
                         + (f", {discharged} already discharged by that stratum"
                            if discharged else ""))
                L.append("  " + ", ".join(f"`{r['symbol']}`" for r in rows))
            L.append("")

        discharged_in = ledger.get("handoffs_discharged") or {}
        if discharged_in:
            L.append("Hand-offs received and discharged:")
            L.append("")
            for source in sorted(discharged_in):
                syms = discharged_in[source]
                L.append(f"* from phase {source}: {len(syms)} symbol(s) — "
                         + ", ".join(f"`{s}`" for s in syms))
            L.append("")

        if phase in courts:
            c = courts[phase]
            rows = c.get("courts", [])
            total = sum(court_observations(x) for x in rows)
            transcript = sum(1 for x in rows if has_transcript(x))
            L.append(f"Courts: `{c.get('all_pass') and 'all pass' or 'NOT ALL PASS'}`"
                     f", {len(rows)} court(s), "
                     f"**{total}** authority observation(s) over {transcript} "
                     f"transcript court(s).")
            if transcript != len(rows):
                L.append("")
                L.append(f"The other {len(rows) - transcript} compare ELF structure rather "
                         f"than a transcript and observe nothing line-wise; they are counted "
                         f"as zero for that reason and not by default.")
            L.append("")
            L.append("| court | verdict | observations |")
            L.append("|---|---|---|")
            for x in rows:
                n = court_observations(x)
                L.append(f"| {x['court']} | `{x['verdict']}` | "
                         f"{n if has_transcript(x) else '— (structural)'} |")
            L.append("")

    # The Phase-24 downstream-1000 outcomes. Rendered only when the committed final run is
    # present, so an earlier branch -- which has no frozen P1000 -- produces no section at all
    # rather than an empty one. Driven only by the committed artefact, and placed here, beside
    # the other global sections, rather than inside the per-phase loop whose per-stratum courts
    # cannot state how many of the 1,000 passed.
    p1000 = load("forensics/downstream/p1000-run.json")
    if p1000 is not None:
        L.extend(_downstream_outcome_lines(p1000))

    # The Phase-24 biggest-mover shared-blocker analysis (24.16). Rendered only when the committed
    # analysis is present, so an earlier branch produces no section rather than an empty one. It is
    # the census's link to `docs/PHASE-24-BIGGEST-MOVERS.md`, so the analysis is reachable from the
    # seal, this census and `README.md` alike.
    shared = load("forensics/downstream/shared-blockers.json")
    if shared is not None:
        L.extend(_biggest_movers_lines(shared))

    if coverage is not None:
        L.append("## Court coverage")
        L.append("")
        L.append("From `forensics/atlas/court-coverage.json`, generated by")
        L.append("`forensics/tools/court_coverage.py`. Every implemented export of a stratum")
        L.append("that has begun -- in-progress or complete -- is in exactly one of the three")
        L.append("sets, so an export cannot be landed without an edge and wait for the seal.")
        L.append("**`directly_courted`")
        L.append("means referenced by a staged candidate probe that ran; it does not mean")
        L.append("every arm of the symbol was driven**, and the `referenced` column is how many")
        L.append("are proofs of reference only. See `docs/DECISIONS.md` D199 and D236.")
        L.append("")
        L.append("| phase | implemented | directly courted | of which called | of which referenced | indirect | non-observable | unmatched |")
        L.append("|---|---|---|---|---|---|---|---|")
        for s in coverage["body"]["strata"]:
            c = s["counts"]
            L.append(
                f"| {s['phase']} | {c['implemented']} | {c['directly_courted']} | "
                f"{c['directly_courted_called']} | {c['directly_courted_referenced']} | "
                f"{c['indirectly_courted']} | {c['non_observable']} | {c['unmatched']} |"
            )
        t = coverage["body"]["totals"]
        L.append(
            f"| **total** | **{t['implemented']}** | **{t['directly_courted']}** | "
            f"**{t['directly_courted_called']}** | **{t['directly_courted_referenced']}** | "
            f"**{t['indirectly_courted']}** | **{t['non_observable']}** | **0** |"
        )
        L.append("")

    if audit is not None:
        L.append("## Atlas/ledger reconciliation")
        L.append("")
        L.append("From `forensics/atlas/ownership-audit.json`: every export the atlas")
        L.append("assigns a stratum appears in that stratum's ledger, and every ledger")
        L.append("row for another stratum's export is a hand-off that stratum recorded.")
        L.append("")
        L.append("| phase | atlas-owned | ledger rows | only in atlas | only in ledger |")
        L.append("|---|---|---|---|---|")
        for r in audit["body"]["ledger_agreement"]:
            L.append(f"| {r['phase']} | {r['atlas']} | {r['ledger']} | "
                     f"{r['only_in_atlas']} | {r['only_in_ledger']} |")
        L.append("")
        L.append(f"Problems recorded by the audit: "
                 f"{len(audit['body']['problems'])}.")
        L.append("")

    OUT.write_text("\n".join(L), encoding="utf-8")
    print(f"[seal-census] {len(ledgers)} ledger(s), {len(courts)} court result(s)")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
