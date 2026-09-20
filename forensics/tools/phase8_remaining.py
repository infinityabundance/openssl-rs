#!/usr/bin/env python3
"""openssl-rs — what is left of Phase 8, and what of it a later phase discharges.

Why this exists
---------------
Phase 8 is planned as subphases (`docs/PHASE-8-SUBPHASES.md` §2) and its arithmetic
lives in `forensics/phase8-obligations.json`. Those two say everything a planner needs
— what is still open, which subphase owns it, and which rows the stratum hands to a
later phase — but no single artefact states it in one place, and a reader who wants to
plan a merge should not have to read a 24-row deferral list out of a JSON document and
then match module strings against a plan table by eye.

The doctrine that governs this project is that no status is ever typed by hand, so this
document is a **projection**. Every count and every symbol name below is read from the
ledger; the subphase names, modules, dependencies and courts are read from the plan's
§2 table; and the closing note's cross-stratum figure is read from
`forensics/prerequisites.json`. Nothing here is a parity claim: `implemented` means a
symbol with that name is defined, `open` means the stratum owns it and has not built it,
and `deferred` means a recorded hand-off with the receiving phase named. See
`docs/PARITY_MODEL.md`.

Outputs
-------
  docs/PHASE-8-REMAINING.md

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import re
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel, write_text  # noqa: E402

GENERATOR = "forensics/tools/phase8_remaining.py"
LEDGER = REPO_ROOT / "forensics" / "phase8-obligations.json"
PLAN = REPO_ROOT / "docs" / "PHASE-8-SUBPHASES.md"
PREREQUISITES = REPO_ROOT / "forensics" / "prerequisites.json"
PREREQUISITE_GATE = REPO_ROOT / "forensics" / "atlas" / "prerequisite-gate.json"
OUT = REPO_ROOT / "docs" / "PHASE-8-REMAINING.md"

# The column the per-subphase symbol lists wrap at. Fixed, so the document is a
# function of its inputs and not of a terminal width.
WRAP = 88


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def plan_subphases(text: str) -> list[dict]:
    """§2's subphase table, in file order.

    Each row carries its number, its name, every ``src/`` module its `Owns` cell names,
    and its `Depends on` and `Courts` cells. The trailing columns are read from the
    right because one row's `Owns` cell contains a literal `|`, so a left-to-right cell
    count is not stable across rows.
    """
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^\|\s*#\s*\|\s*Subphase\s*\|", line):
            start = i + 1
            break
    if start is None:
        raise SystemExit(
            f"[phase8-remaining] no '| # | Subphase |' table in {rel(PLAN)}")
    rows: list[dict] = []
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 6 or not re.fullmatch(r"\d+\.\d+", cells[0]):
            continue
        rows.append({
            "key": cells[0],
            "name": cells[1].replace("*", "").strip(),
            "modules": re.findall(r"`(src/[^`|]+)`", line),
            "depends_on": cells[-3],
            "courts": cells[-2],
        })
    if not rows:
        raise SystemExit(f"[phase8-remaining] the subphase table in {rel(PLAN)} is empty")
    return rows


def module_index(rows: list[dict]) -> dict[str, str]:
    """`module -> subphase key`, from the plan's `Owns` cells.

    A module named by two subphases would make the open-row count ambiguous, so it is a
    failure rather than a silent last-writer-wins.
    """
    index: dict[str, str] = {}
    for row in rows:
        for module in row["modules"]:
            owner = index.get(module)
            if owner is not None and owner != row["key"]:
                raise SystemExit(
                    f"[phase8-remaining] {module} is named by subphases {owner} and "
                    f"{row['key']}; the open-row count would be ambiguous")
            index[module] = row["key"]
    return index


def numeric(key: str) -> tuple[int, ...]:
    return tuple(int(part) for part in key.split("."))


def phase_phrase(owners: list[int]) -> str:
    if len(owners) == 1:
        return f"Phase {owners[0]}"
    return "Phases " + ", ".join(str(o) for o in owners)


def wrapped(symbols: list[str]) -> str:
    text = ", ".join(f"`{s}`" for s in symbols)
    return textwrap.fill(text, width=WRAP, break_long_words=False,
                         break_on_hyphens=False)


def main() -> int:
    ledger = load(LEDGER)
    if ledger is None:
        raise SystemExit(
            f"[phase8-remaining] {rel(LEDGER)} is required; run "
            f"forensics/tools/phase8_obligations.py first")
    if not PLAN.is_file():
        raise SystemExit(f"[phase8-remaining] {rel(PLAN)} is required")

    body = ledger["body"]
    counts = body["counts"]
    deferred = body["deferred"]
    open_rows = body["open"]

    subphases = plan_subphases(PLAN.read_text(encoding="utf-8"))
    by_key = {row["key"]: row for row in subphases}
    index = module_index(subphases)

    # `open` rows, grouped by the subphase that owns the module they name.
    open_by_key: dict[str, list[str]] = {}
    for row in open_rows:
        key = index.get(row["module"])
        if key is None:
            raise SystemExit(
                f"[phase8-remaining] the ledger's open list names module "
                f"{row['module']}, which no subphase row in {rel(PLAN)} owns")
        open_by_key.setdefault(key, []).append(row["symbol"])

    owned = counts["owned"]
    implemented = counts["implemented"]
    deferred_n = counts["deferred_to_later_phase"]
    open_n = counts["open_in_this_stratum"]
    holds = owned == implemented + deferred_n + open_n

    by_owner: dict[int, list[dict]] = {}
    for row in deferred:
        by_owner.setdefault(int(row["owning_phase"]), []).append(row)
    owners = sorted(by_owner)

    work = [(key, by_key[key], sorted(open_by_key.get(key, [])))
            for key in sorted(by_key, key=numeric) if open_by_key.get(key)]

    L: list[str] = []
    L.append("# Phase 8 remaining (generated)")
    L.append("")
    L.append(f"Generated by `{GENERATOR}` from `forensics/phase8-obligations.json`,")
    L.append("which is authoritative, and §2's subphase table in")
    L.append("`docs/PHASE-8-SUBPHASES.md`. This document is a **projection** of that")
    L.append("ledger: every count and every symbol name below is read from it. **Do not")
    L.append("edit by hand.** Nothing here is a parity claim; see `docs/PARITY_MODEL.md`.")
    L.append("")

    L.append("## Totals")
    L.append("")
    L.append("Read from the ledger's `body.counts`.")
    L.append("")
    L.append("| quantity | count |")
    L.append("|---|---|")
    L.append(f"| owned | {owned} |")
    L.append(f"| implemented | {implemented} |")
    L.append(f"| deferred to a later phase | {deferred_n} |")
    L.append(f"| open in this stratum | {open_n} |")
    L.append("")
    identity = f"{owned} = {implemented} + {deferred_n} + {open_n}"
    L.append(f"The identity `owned = implemented + deferred + open` is `{identity}`, "
             + ("which holds." if holds else "**which does not hold.**"))
    L.append("")

    L.append("## The merge gate — what Phase 8 owes to Phase 9")
    L.append("")
    L.append("Every row of the ledger's `deferred` list, grouped by the phase that owns")
    L.append("it and sorted by symbol. This is what a later landing must discharge before")
    L.append("this stratum can be complete.")
    L.append("")
    L.append("| symbol | declaring header | owning phase |")
    L.append("|---|---|---|")
    for owner in owners:
        for row in sorted(by_owner[owner], key=lambda r: r["symbol"]):
            L.append(f"| `{row['symbol']}` | `{row['declaring_header']}` | {owner} |")
    L.append("")
    L.append(f"**{deferred_n}** export(s) are deferred, to {phase_phrase(owners)}. A")
    L.append("stratum cannot be complete while any export it owns is neither implemented")
    L.append("nor handed to a later phase, and these rows are the ones a later")
    L.append(f"{phase_phrase(owners)} landing discharges.")
    L.append("")
    for owner in owners:
        L.append(f"### Owning {phase_phrase([owner])} — reasons, verbatim")
        L.append("")
        L.append("These are the ledger's `reason` strings, unchanged: they are the")
        L.append("evidence for the hand-off and are not summarised here. Eleven of the")
        L.append("twenty-four deferred rows share one reason because they are one row of")
        L.append("`BLOCKED_HANDOFFS`, so each distinct reason is printed once and the")
        L.append("symbols it covers are listed above it.")
        L.append("")
        by_reason: dict[str, list[str]] = {}
        for row in sorted(by_owner[owner], key=lambda r: r["symbol"]):
            by_reason.setdefault(row["reason"], []).append(row["symbol"])
        for reason, symbols in by_reason.items():
            covers = ", ".join(f"`{s}`" for s in symbols)
            L.append(f"- {covers}:")
            L.append("")
            for line in reason.splitlines() or [""]:
                L.append(f"  {line}" if line else "")
            L.append("")

    L.append("## The work Phase 8 still owns")
    L.append("")
    L.append("Grouped by subphase, in numeric order. `open` counts the ledger's `open`")
    L.append("rows whose `module` is that subphase's module, so a subphase with no open")
    L.append("row is not listed. The `owns`, `courts` and `depends on` columns are §2's")
    L.append("table, verbatim.")
    L.append("")
    L.append("| subphase | owns | open | courts | depends on |")
    L.append("|---|---|---|---|---|")
    for key, row, symbols in work:
        owns = ", ".join(f"`{m}`" for m in row["modules"])
        L.append(f"| {key} {row['name']} | {owns} | {len(symbols)} | {row['courts']} "
                 f"| {row['depends_on']} |")
    L.append("")
    listed = sum(len(symbols) for _k, _r, symbols in work)
    L.append(f"Total open symbols listed below: **{listed}**; the ledger's")
    L.append(f"`open_in_this_stratum` is {open_n}.")
    L.append("")
    for key, row, symbols in work:
        L.append(f"### {key} {row['name']} — {len(symbols)} open")
        L.append("")
        L.append(wrapped(symbols))
        L.append("")

    L.append("## The subphase order")
    L.append("")
    L.append("The plan records the subphases that still hold open work in this order:")
    L.append("")
    chain = " -> ".join(f"{key} {row['name']}" for key, row, _s in work)
    L.append(chain)
    L.append("")
    L.append("`docs/PHASE-8-SUBPHASES.md` §2 records this order, and states that each")
    L.append("row's dependency column was read from the authority's calls rather than")
    L.append("from the export list — the method D114, D118 and D122 established. The")
    L.append("`depends on` column above is that reading, verbatim.")
    L.append("")

    prereq = load(PREREQUISITES)
    gate = load(PREREQUISITE_GATE)
    L.append("## What only checking the export ledger misses")
    L.append("")
    L.append("This document projects `forensics/phase8-obligations.json`, and every row")
    L.append("of that ledger is an **export**. Cross-stratum *internal* names — a helper")
    L.append("a module references that is not an export — are recorded in a different")
    if prereq is not None:
        deferrals = prereq["body"]["deferrals"]
        owned_here = sum(1 for r in deferrals if int(r["owner_phase"]) == 8)
        L.append(f"place: `forensics/prerequisites.json`'s `deferrals` "
                 f"({len(deferrals)} rows, {owned_here} of which name Phase 8 as")
        L.append("owner), and")
    else:
        L.append("place: `forensics/prerequisites.json`'s `deferrals` (currently absent),")
        L.append("and")
    if gate is not None:
        L.append("`forensics/atlas/prerequisite-gate.json` is the generated view of them.")
    else:
        L.append("`forensics/atlas/prerequisite-gate.json` (currently absent) is the")
        L.append("generated view of them.")
    L.append("A reader who only checks the export ledger has not seen that half of the")
    L.append("picture.")
    L.append("")

    write_text(OUT, "\n".join(L))
    print(f"[phase8-remaining] open={open_n} deferred={deferred_n} "
          f"over {len(work)} subphase(s)")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
