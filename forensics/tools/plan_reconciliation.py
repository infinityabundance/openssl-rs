#!/usr/bin/env python3
"""openssl-rs — plan reconciliation: does every stratum's plan reach the crate?

Why this exists
---------------
`prerequisite_gate.py` answers *"does every name the crate references have an owner?"*.
D132 found that rule's blind spot by hand: `crypto/core_algorithm.c`'s
`ossl_algorithm_do_all` was named by subphase rows 6.6f and 6.8f, was genuinely unbuilt, and
**nothing referenced it** — its only authority caller is Phase 7's `core_fetch.c`. So:

* no court could reach it, because it has no export and no caller;
* no ledger could see it, because the symbol-ownership atlas classifies exports; and
* the gate did not report it, because the gate's universe is the set of names the crate
  *references*, and a name nothing references is invisible to it.

A whole authority translation unit can therefore sit unnamed while a stratum reports
`complete`, and the only thing that caught it was reading the plan against the crate by hand.
This tool is that reading, mechanised. Its universe is not what the crate references but what
the plan **promises**, which is the other half of the same reconciliation.

The three things it checks
--------------------------
**P1 `plan_named_unit_not_reached`** — an authority translation unit a subphase row names, in a
stratum that is `complete` or `in-progress`, that no crate module transcribes and no record
names. That is work the plan claims and nothing reaches.

**P2 `plan_named_symbol_not_reached`** — an authority-internal function a subphase row names,
in such a stratum, that the crate does not build, no deferral records, and no divergence
covers. This is the gate's direction A with the *reference* set replaced by the plan's name
set, and it is the exact shape of the `ossl_algorithm_do_all` finding.

**P3 `plan_unit_record_is_stale`** — the reverse. A record that names an authority unit which
no subphase row in a complete or in-progress stratum mentions is a record about work the plan
no longer claims, and it is reported so that the mechanism cannot quietly widen. This is the
same fail-closed rule `prerequisite_gate.py` applies to divergence coverage.

Why the name set has to be extracted from prose
----------------------------------------------
The rows are a markdown table and their authority-file cells are written the way a person
writes them: `` `crypto/provider_core.c` §§947–2,300 ``, `` `core_algorithm.c` (199) ``,
`` `crypto/threads_common.c` ``, `` the `ASN1_STRING` family ``. A bare basename and a full path
both appear, and both have to resolve. Resolution is against the **committed**
`forensics/authorities/SOURCE_MANIFEST.<authority>.json`, never against the authority source
tree, which is not committed and would make this fail in CI.

What it deliberately does not check
-----------------------------------
Every identifier in a row. The rows name C language words, macro names, enum values, court
names, decision numbers and English words inside backticks, and a check over all of them would
be noise that gets suppressed — which is how a real finding hides. The universe is
`internal-symbols.json`'s authority-internal *functions*, which is the same universe
`prerequisite_gate.py` uses for its direction A, so the two tools agree about what a
"prerequisite" is and disagree only about where the list of promises comes from.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    write_json,
)

# The crate's own definition and reference sets are the gate's, deliberately: the two tools
# must agree about what "the crate builds this name" means, or a disagreement between them
# would be a disagreement about vocabulary rather than about the plan.
from prerequisite_gate import crate_source  # noqa: E402

GENERATOR = "forensics/tools/plan_reconciliation.py"
OUT = ATLAS / "plan-reconciliation.json"

# The classes a `units` record may declare, and what each one has to prove. The vocabulary is
# closed for the same reason `prerequisite_gate.DIVERGENCE_CLASSES` is closed: a record whose
# class can be invented is a record whose class cannot be checked. Every class names the fields
# it requires, and the tool fails a record that omits one, so a record is a claim that can be
# **falsified** rather than a sentence that can be believed.
UNIT_CLASSES = {
    # The unit is reached, but not in a way the three mechanical signals can see -- its content
    # is exports, a variable, or a macro-generated entry point. It must name the crate module
    # and the crate's own names for what it builds, and every one of those names must actually
    # be built. `crypto/provider.c` is the worked example: its twenty-two exports are thin
    # wrappers, `provider_core.c` dominates the module that defines them, and the file has no
    # authority-internal function of its own.
    "reached_by_a_named_construct": ("crate_module", "names"),
    # The unit is a later stratum's work. The phase must not already be complete, or the record
    # is a stale deferral -- the same rule `prerequisite_gate.py` applies to symbol deferrals.
    "deferred_to_later_stratum": ("owner_phase",),
    # Nothing the unit contributes is compiled in this profile. The guard is the preprocessor or
    # configure fact that empties it, and it is required because "not in this profile" is
    # otherwise indistinguishable from "we did not look".
    "not_in_this_profile": ("guard",),
    # The plan names a file the authority does not have -- normally in order to say so. The tool
    # verifies the absence against the committed manifest, so the claim is checked rather than
    # taken.
    "does_not_exist_in_this_authority": (),
}

INTERNAL = ATLAS / "internal-symbols.json"
EDGES = ATLAS / "transcription-edges.json"
SURFACE = ATLAS / "implemented-surface.json"
PHASE_STATE = REPO_ROOT / "forensics" / "phase-state.json"
PREREQUISITES = REPO_ROOT / "forensics" / "prerequisites.json"
DOCS = REPO_ROOT / "docs"

# The strata this tool judges. A `not-started` stratum's plan names work nothing has claimed to
# have done, so calling it unreached would be calling a plan a lie. An `in-progress` stratum is
# judged differently from a `complete` one, and the difference is the whole of this tool's
# contract:
#
#   * `complete` -- a plan-named unit or symbol that nothing reaches is a **finding**. The
#     stratum is claiming the work is done, and this is the check that `crypto/core_algorithm.c`
#     fell through until D134 built it.
#   * `in-progress` -- the same names are reported as a **census**, per stratum, and are not a
#     failure. A plan names the work a stratum *will* do; a stratum in its first subphase has
#     done none of it, and failing it for that is failing it for having a plan. The census is
#     published so the distance is visible, and `open_in_this_stratum` in the stratum's own
#     ledger is what holds it to account.
#
# This is the arrangement `prerequisite_gate.py` already uses for its sealed-stratum census:
# report, do not fail, and let the number be visible rather than inferred.
JUDGED = ("complete",)
CENSUSED = ("in-progress",)
JUDGED_OR_CENSUSED = JUDGED + CENSUSED

# `crypto/provider_core.c`, `` `core_algorithm.c` ``, `providers/defltprov.c`,
# `./crypto/x509/x_x509.c`. The trailing-boundary group keeps `a.c` inside a longer word
# (`openssl.cnf`, `libcrypto.so`) out: a match must not be followed by a word, dot or dash
# character, which is what makes `openssl.cnf` and `libcrypto.so.3` non-matches.
_UNIT = re.compile(r"(?<![\w./-])([A-Za-z0-9_][A-Za-z0-9_/.\-]*\.c)(?![\w.\-])")

# A backticked identifier: `` ossl_algorithm_do_all ``, `` provider_init ``, `` ASN1_STRING ``.
_BACKTICKED = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")

# A markdown table row's cells. Rows are `| a | b | ... |`, and a `\|` inside a cell is an
# escaped pipe that does not split. Splitting on an unescaped `|` and dropping the empty first
# and last fields is the whole parse.
_ROW = re.compile(r"^\s*\|")


def cells(line: str) -> list[str]:
    """The cells of a markdown table row, with escaped pipes left intact."""
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|"):
        body = body[:-1]
    out: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            cur.append(body[i + 1])
            i += 2
            continue
        if c == "|":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return [c.strip() for c in out]


def subphase_rows(text: str) -> list[tuple[str, list[str]]]:
    """Every row of a subphase plan, as `(first_cell, cells)`.

    A row is a markdown table line whose **first cell** looks like a subphase id: `5.1`,
    `6.6f`, `6.10a`. The header separator and the header itself are skipped by that test, which
    is why it is the first cell rather than the second: the title can be anything.
    """
    rows: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        if not _ROW.match(line):
            continue
        cs = cells(line)
        if not cs:
            continue
        head = cs[0]
        if re.fullmatch(r"\d+\.\d+[a-z]?", head):
            rows.append((head, cs))
    return rows


def load(path: Path, what: str) -> dict:
    if not path.is_file():
        print(f"[{GENERATOR}] fatal: {what} is missing at {rel(path)}", file=sys.stderr)
        raise SystemExit(1)
    return json.loads(path.read_text())


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--no-write", action="store_true", help="report only")
    ap.add_argument("--authority", default="openssl-3.6.4-production")
    args = ap.parse_args(argv)

    internal_doc = load(INTERNAL, "the internal symbol universe")
    edges_doc = load(EDGES, "the module-to-unit map")
    surface_doc = load(SURFACE, "the implemented surface")
    prereq_doc = load(PREREQUISITES, "the recorded prerequisites")
    # The manifest's filename carries the released version and not the authority id
    # (`SOURCE_MANIFEST.3.6.4.json`), so it is looked up through the registry rather than
    # composed -- composing it is how the first version of this tool failed on its own first run.
    authorities = load(
        REPO_ROOT / "forensics" / "authorities" / "AUTHORITIES.json",
        "the authority registry",
    )["authorities"]
    rows = [a for a in authorities if a["id"] == args.authority]
    if not rows:
        print(
            f"[{GENERATOR}] fatal: {args.authority} is not in the authority registry",
            file=sys.stderr,
        )
        return 1
    manifest_name = rows[0]["source_tree"]["manifest"]
    manifest_path = REPO_ROOT / "forensics" / "authorities" / manifest_name
    manifest = load(manifest_path, "the authority source manifest")

    states = {
        int(r["phase"]): r["state"]
        for r in load(PHASE_STATE, "the derived phase state")["body"]["phases"]
    }

    # --- the universes ------------------------------------------------------
    internal = {
        r["symbol"]: r["translation_unit"] for r in internal_doc["body"]["records"]
    }
    transcribed: dict[str, list[str]] = {
        u["tu"]: u["modules"] for u in edges_doc["body"]["units"]
    }
    # Which authority-internal functions each unit defines, and which identifiers each unit's
    # row lists. Both are needed: `transcription-edges.json` maps a module to its **dominant**
    # unit on purpose (a module whose definitions are spread across units appears once), so
    # "not a dominant unit of any module" is not the same as "nothing reaches this file".
    # `crypto/provider.c` is the worked example -- its twenty-two exports are thin wrappers and
    # `provider_core.c` dominates the module that defines them, so the file is invisible to that
    # map while every one of its exports is implemented.
    unit_symbols: dict[str, set[str]] = defaultdict(set)
    for name, tu in internal.items():
        unit_symbols[tu].add(name)
    unit_identifiers: dict[str, set[str]] = {
        u["tu"]: set(u["identifiers"]) for u in edges_doc["body"]["units"]
    }
    surface = surface_doc["body"]
    implemented = set()
    for lib in ("libcrypto", "libssl"):
        implemented |= set(surface["libraries"][lib]["implemented_symbols"])
    implemented |= set(surface["internal_symbols"]["c_style"])

    refs, defs = crate_source()
    built = set(defs) | implemented
    refs_anywhere: set[str] = set()
    for names in refs.values():
        refs_anywhere |= names

    # Basename -> the authority paths that end with it. A basename that is unique resolves; one
    # that is not is reported rather than guessed, because the plan's own precision is part of
    # what this tool is for.
    by_basename: dict[str, list[str]] = defaultdict(list)
    for row in manifest["files"]:
        p = row["path"] if isinstance(row, dict) else row
        by_basename[Path(p).name].append(p)

    body = prereq_doc["body"]
    deferrals = {r["symbol"]: r for r in body["deferrals"]}
    divergences = list(body["divergences"])
    # A divergence covers the names it lists, for the same reason the gate lets it: the crate
    # builds the behaviour under another name and the record is what says so.
    covered = {n for row in divergences for n in row["covers"]}

    # Which authority units a record names **explicitly**. Prose is not a naming: a record's
    # `reason` mentioning a file tells a reader something, but it cannot be checked, and a check
    # that can be satisfied by prose is a check that will be. So the field is the contract, and
    # there are two places to put it -- a symbol deferral may carry `authority_unit`, and the
    # `units` block is for units that no single symbol can stand for.
    recorded_units: dict[str, str] = {}
    for r in body["deferrals"]:
        if r.get("authority_unit"):
            recorded_units.setdefault(r["authority_unit"], f"deferral:{r['symbol']}")
    for r in body["divergences"]:
        for u in r.get("authority_units", []):
            recorded_units.setdefault(u, f"divergence:{r['owner_module']}")
    unit_records: dict[str, dict] = {}
    unit_record_findings: list[dict] = []
    for r in body.get("units", []):
        u = r["unit"]
        if u in unit_records or u in recorded_units:
            unit_record_findings.append(
                {
                    "kind": "unit_record_claimed_twice",
                    "direction": "P3",
                    "unit": u,
                    "detail": (
                        "a unit must have exactly one owner record, so that the record which "
                        "covers it cannot be ambiguous between two claims"
                    ),
                }
            )
            continue
        unit_records[u] = r
        recorded_units.setdefault(u, f"units:{u}")

        cls = r.get("class")
        if cls not in UNIT_CLASSES:
            unit_record_findings.append(
                {
                    "kind": "unit_record_class_is_not_one_of_the_fixed_set",
                    "direction": "P3",
                    "unit": u,
                    "class": cls,
                    "detail": f"allowed: {sorted(UNIT_CLASSES)}",
                }
            )
            continue
        missing = [f for f in UNIT_CLASSES[cls] if not r.get(f)]
        if missing or not r.get("reason") or not r.get("evidence"):
            unit_record_findings.append(
                {
                    "kind": "unit_record_is_unfalsifiable",
                    "direction": "P3",
                    "unit": u,
                    "class": cls,
                    "missing": missing + [f for f in ("reason", "evidence") if not r.get(f)],
                    "detail": (
                        "a record must carry everything its class claims to prove, so that a "
                        "wrong record fails rather than reads plausibly"
                    ),
                }
            )
            continue

        # --- each class's own claim, checked ---
        if cls == "reached_by_a_named_construct":
            mod = REPO_ROOT / r["crate_module"]
            if not mod.is_file():
                unit_record_findings.append(
                    {
                        "kind": "unit_record_names_a_module_that_does_not_exist",
                        "direction": "P3",
                        "unit": u,
                        "crate_module": r["crate_module"],
                        "detail": "the record's evidence must be a file this crate has",
                    }
                )
                continue
            absent = sorted(n for n in r["names"] if n not in built)
            if absent:
                unit_record_findings.append(
                    {
                        "kind": "unit_record_claims_a_construct_the_crate_does_not_build",
                        "direction": "P3",
                        "unit": u,
                        "names_not_built": absent,
                        "detail": (
                            "this record says the crate reaches the unit through these names, "
                            "and the crate does not build them; either the record is wrong or "
                            "the work was removed, and both are findings"
                        ),
                    }
                )
        elif cls == "deferred_to_later_stratum":
            owner = int(r["owner_phase"])
            if states.get(owner) == "complete":
                unit_record_findings.append(
                    {
                        "kind": "unit_record_defers_to_a_stratum_that_has_sealed",
                        "direction": "P3",
                        "unit": u,
                        "owner_phase": owner,
                        "detail": (
                            "a deferral whose owner has already sealed is stale: the stratum "
                            "either built this unit or sealed without it"
                        ),
                    }
                )
        elif cls == "does_not_exist_in_this_authority":
            if u in by_basename.get(Path(u).name, []) or u in by_basename.get(u, []):
                unit_record_findings.append(
                    {
                        "kind": "unit_record_denies_a_file_the_authority_has",
                        "direction": "P3",
                        "unit": u,
                        "detail": (
                            "this record says the authority has no such file and the committed "
                            "manifest lists one; the record is wrong"
                        ),
                    }
                )

    # --- what the plan promises --------------------------------------------
    named_units: dict[str, list[str]] = defaultdict(list)   # tu -> subphase rows
    named_symbols: dict[str, list[str]] = defaultdict(list)  # symbol -> subphase rows
    # The row's stratum state travels with the row, so a name can be a finding in one stratum
    # and a census entry in another without the caller having to re-derive which stratum owns
    # which row.
    row_state: dict[str, str] = {}
    row_phase: dict[str, int] = {}
    unresolvable: list[dict] = []
    ambiguous: list[dict] = []
    judged_rows = 0

    plans = sorted(DOCS.glob("PHASE-*-SUBPHASES.md"))
    if not plans:
        print(f"[{GENERATOR}] fatal: no subphase plans under {rel(DOCS)}", file=sys.stderr)
        return 1

    plan_files: list[Path] = []
    for plan in plans:
        m = re.search(r"PHASE-(\d+)-SUBPHASES\.md$", plan.name)
        if m is None:
            continue
        phase = int(m.group(1))
        if states.get(phase) not in JUDGED_OR_CENSUSED:
            continue
        plan_files.append(plan)
        text = plan.read_text()
        for head, cs in subphase_rows(text):
            judged_rows += 1
            row_state[head] = states.get(phase, "not-started")
            row_phase[head] = phase
            blob = " ".join(cs[1:])
            for raw in _UNIT.findall(blob):
                if raw.startswith("./"):
                    raw = raw[2:]
                # A row may name a file in order to say the authority does not have it, and
                # `crypto/rcu.c` is the worked example: *"there is no `crypto/rcu.c`"*. That
                # row is a finding the plan is recording, not a claim, so a
                # `does_not_exist_in_this_authority` record is what settles it -- and the tool
                # verifies that absence against the committed manifest, so the record fails if
                # the file ever appears. The name is still registered as promised, which is
                # what keeps P3 from calling the record stale.
                if raw in unit_records and (
                    unit_records[raw].get("class") == "does_not_exist_in_this_authority"
                ):
                    if head not in named_units[raw]:
                        named_units[raw].append(head)
                    continue
                if "/" in raw:
                    tu = raw
                    if tu not in by_basename.get(Path(raw).name, []):
                        unresolvable.append(
                            {"subphase": head, "plan": rel(plan), "unit": raw}
                        )
                        continue
                else:
                    hit = by_basename.get(raw, [])
                    if not hit:
                        unresolvable.append(
                            {"subphase": head, "plan": rel(plan), "unit": raw}
                        )
                        continue
                    if len(hit) > 1:
                        ambiguous.append(
                            {"subphase": head, "plan": rel(plan), "basename": raw,
                             "candidates": sorted(hit)}
                        )
                        continue
                    tu = hit[0]
                if head not in named_units[tu]:
                    named_units[tu].append(head)
            for name in _BACKTICKED.findall(blob):
                if name not in internal:
                    continue
                if head not in named_symbols[name]:
                    named_symbols[name].append(head)

    # --- P1: a promised unit nothing reaches -------------------------------
    findings: list[dict] = []
    # The same two conditions as a finding, split by the state of the row's stratum. A
    # `complete` stratum is claiming the work; an `in-progress` one is not yet.
    census: dict[str, set[str]] = defaultdict(set)
    census_by_stratum: dict[int, set[str]] = defaultdict(set)

    def cense(kind: str, name: str, heads: list[str]) -> None:
        """Record an unreached name in the census: once by kind, once per stratum.

        Both readings are kept because they answer different questions. By kind, so the
        totals are comparable across runs; by stratum, so a stratum's distance from its
        own plan is a number rather than something a reader derives by filtering.
        """
        census[kind].add(name)
        for head in heads:
            phase = row_phase.get(head)
            if phase is not None:
                census_by_stratum[phase].add(f"{kind}:{name}")
    for d in unresolvable:
        if row_state.get(d["subphase"], "not-started") in JUDGED:
            findings.append(
                {
                    "kind": "plan_names_a_file_the_authority_does_not_have",
                    "direction": "P1",
                    "unit": d["unit"],
                    "subphase": d["subphase"],
                    "plan": d["plan"],
                    "detail": (
                        "this row names a `.c` file that is not in the authority's own "
                        "manifest, so either the row is wrong or the authority id is"
                    ),
                }
            )
        else:
            cense("names_a_file_the_authority_does_not_have",
                  f"{d['plan']}:{d['subphase']}:{d['unit']}", [d["subphase"]])
    for d in ambiguous:
        if row_state.get(d["subphase"], "not-started") in JUDGED:
            findings.append(
                {
                    "kind": "plan_names_a_basename_the_authority_repeats",
                    "direction": "P1",
                    "unit": d["basename"],
                    "subphase": d["subphase"],
                    "plan": d["plan"],
                    "candidates": d["candidates"],
                    "detail": (
                        "this row names a bare basename and more than one authority file has "
                        "it; the row must say which one, because the tool will not guess and a "
                        "guess is exactly the sort of unexamined transcription this project "
                        "removes"
                    ),
                }
            )
        else:
            cense("names_a_basename_the_authority_repeats",
                  f"{d['plan']}:{d['subphase']}:{d['basename']}", [d["subphase"]])

    reached_units: set[str] = set()
    for tu, rows in sorted(named_units.items()):
        if transcribed.get(tu) or tu in recorded_units:
            reached_units.add(tu)
            continue
        # A unit is reached if the crate builds one of the internal functions it defines, or
        # references one of the identifiers its own row lists. The second half is what catches a
        # reason-code file, whose only content is `ERR_load_*_strings` and a table of numbers.
        if unit_symbols.get(tu, set()) & built:
            reached_units.add(tu)
            continue
        if unit_identifiers.get(tu, set()) & refs_anywhere:
            reached_units.add(tu)
            continue
        if row_state.get(rows[0], "not-started") in JUDGED:
            findings.append(
                {
                    "kind": "plan_named_unit_not_reached",
                    "direction": "P1",
                    "unit": tu,
                    "subphases": sorted(rows),
                    "defines": sorted(unit_symbols.get(tu, set()))[:20],
                    "detail": (
                        "a subphase row of a stratum that is **complete** names this "
                        "authority translation unit, no crate module transcribes it, the crate "
                        "builds none of the internal functions it defines, references none of "
                        "the identifiers its row lists, and no record names it: the plan claims "
                        "work that nothing reaches. `ossl_algorithm_do_all` in "
                        "`crypto/core_algorithm.c` is the worked example (docs/DECISIONS.md "
                        "D132)"
                    ),
                }
            )
        else:
            cense("units_not_reached", tu, rows)

    # --- P2: a promised symbol nothing reaches -----------------------------
    reached_symbols: set[str] = set()
    for name, rows in sorted(named_symbols.items()):
        if name in built or name in deferrals or name in covered:
            reached_symbols.add(name)
            continue
        if row_state.get(rows[0], "not-started") not in JUDGED:
            cense("symbols_not_reached", name, rows)
            continue
        findings.append(
            {
                "kind": "plan_named_symbol_not_reached",
                "direction": "P2",
                "name": name,
                "defines_it": internal[name],
                "subphases": sorted(rows),
                "detail": (
                    "a subphase row of a stratum that is **complete** names this "
                    "authority-internal function, the crate builds nothing by that name, no "
                    "deferral records it and no divergence covers it -- the same shape as "
                    "`ossl_algorithm_do_all` (docs/DECISIONS.md D132)"
                ),
            }
        )

    # --- P3: a record about a unit the plan no longer promises --------------
    #
    # Only the `units` block is judged here. A symbol deferral's `authority_unit` is
    # **supplementary** -- it says where the name lives, so that the unit is reached by the same
    # row -- and it is not a claim that the plan names the file. Requiring a plan row behind it
    # would make the field unusable for exactly the case it exists for: `OSSL_provider_init` is
    # in `providers/legacy/legacyprov.c`, and no subphase row names that file.
    for tu in sorted(unit_records):
        if tu in named_units:
            continue
        findings.append(
            {
                "kind": "plan_unit_record_is_stale",
                "direction": "P3",
                "unit": tu,
                "recorded_by": recorded_units[tu],
                "detail": (
                    "this record names an authority unit that no subphase row of a complete or "
                    "in-progress stratum mentions; the record is about a promise the plan no "
                    "longer makes, so retire it rather than let it cover the next real gap"
                ),
            }
        )

    # --- the reverse direction for divergences -----------------------------
    # A divergence that covers a name the plan never promises is not this tool's business --
    # the gate checks that direction against what the *crate* references. What this tool adds
    # is that a divergence which names `authority_units` must have a plan row behind it, which
    # P3 above already reports.

    by_kind: dict[str, int] = defaultdict(int)
    for f in unit_record_findings:
        by_kind[f["kind"]] += 1
    for f in findings:
        by_kind[f["kind"]] += 1
    findings = unit_record_findings + findings

    rec_body = {
        "rule": (
            "every authority translation unit and every authority-internal function named by "
            "a subphase row of a **complete** stratum must be transcribed by a crate module or "
            "named by an explicit record field; and an explicit record field naming an "
            "authority unit must have a subphase row behind it. An `in-progress` stratum's "
            "unreached names are published as a census and are not a failure, because a plan "
            "names the work a stratum will do"
        ),
        "judged_states": list(JUDGED),
        "censed_states": list(CENSUSED),
        "universes": {
            "authority_files": len(manifest["files"]),
            "transcribed_units": len(transcribed),
            "internal_functions": len(internal),
        },
        "checked": {
            "plans_read": [rel(p) for p in plan_files],
            "rows_judged": judged_rows,
            "units_named_by_a_row": len(named_units),
            "units_reached": len(reached_units),
            "symbols_named_by_a_row": len(named_symbols),
            "symbols_reached": len(reached_symbols),
            "units_named_by_a_record": len(recorded_units),
            "unit_records": len(unit_records),
        },
        "counts": dict(sorted(by_kind.items())),
        "census": {k: len(v) for k, v in sorted(census.items())},
        "census_by_stratum": {
            str(phase): len(names) for phase, names in sorted(census_by_stratum.items())
        },
        "census_samples": {k: sorted(v)[:60] for k, v in sorted(census.items())},
        "census_not_a_failure": (
            "a name an `in-progress` stratum's plan promises and nothing yet reaches is "
            "counted here and not failed: a plan names the work a stratum will do, and the "
            "stratum's own ledger's `open_in_this_stratum` is what holds it to account. The "
            "census exists so the distance is visible rather than inferred"
        ),
        # Published for a reader rather than a check: this is what the plan is understood to
        # promise, so a disagreement about the plan can be argued against a list instead of
        # against a reading.
        "promised_units": {
            tu: {"subphases": sorted(rows),
                 "transcribed_by": sorted(transcribed.get(tu, [])),
                 "defines": sorted(unit_symbols.get(tu, set()))[:20],
                 "recorded_by": recorded_units.get(tu)}
            for tu, rows in sorted(named_units.items())
        },
        "unit_records": {
            u: {"class": r["class"], "owner_phase": r.get("owner_phase"),
                "crate_module": r.get("crate_module")}
            for u, r in sorted(unit_records.items())
        },
        "findings": findings,
        "claim": (
            "A structural reconciliation, not a parity claim. It answers whether the plan and "
            "the crate agree about what a stratum promises; it says nothing about whether any "
            "of it behaves as the authority's does."
        ),
    }

    if not args.no_write:
        doc = envelope(
            "plan-reconciliation",
            GENERATOR,
            [
                InputRef(name="internal-symbols", path=INTERNAL),
                InputRef(name="transcription-edges", path=EDGES),
                InputRef(name="implemented-surface", path=SURFACE),
                InputRef(name="phase-state", path=PHASE_STATE),
                InputRef(name="prerequisites", path=PREREQUISITES),
                InputRef(name="source-manifest", path=manifest_path),
                *[InputRef(name=f"plan-{p.stem}", path=p) for p in plan_files],
            ],
            rec_body,
            authority=internal_doc.get("authority"),
        )
        doc["body_hash"] = content_hash(rec_body)
        write_json(OUT, doc)

    print(f"[plan-reconciliation] {len(plan_files)} plan(s), {judged_rows} row(s) of a "
          f"judged or censused stratum")
    print(f"  units named by a row:   {len(named_units)} "
          f"({len(reached_units)} reached, "
          f"{len(named_units) - len(reached_units)} not)")
    print(f"  symbols named by a row: {len(named_symbols)} "
          f"({len(reached_symbols)} reached, "
          f"{len(named_symbols) - len(reached_symbols)} not)")
    print(f"  units named by a record: {len(recorded_units)} "
          f"({len(unit_records)} of them through the `units` block)")
    for k in sorted(by_kind):
        print(f"  {k}: {by_kind[k]}")
    for k in sorted(census):
        print(f"  census {k}: {len(census[k])} (not a failure)")
    if census_by_stratum:
        print("  census by stratum: "
              + ", ".join(f"phase {p}: {len(names)}"
                          for p, names in sorted(census_by_stratum.items())))

    for f in findings:
        print(f"[{f['kind']}]", file=sys.stderr)
        where = f.get("subphases") or ([f["subphase"]] if f.get("subphase") else None)
        if "unit" in f:
            print(
                f"    {f['unit']} "
                f"({', '.join(where) if where else f.get('recorded_by')})",
                file=sys.stderr,
            )
            if f.get("candidates"):
                print(f"      candidates: {', '.join(f['candidates'])}", file=sys.stderr)
        else:
            print(f"    {f['name']} -> {f['defines_it']} "
                  f"(rows {', '.join(f['subphases'])})", file=sys.stderr)

    if findings:
        print(f"[{GENERATOR}] {len(findings)} finding(s): {', '.join(sorted(by_kind))}",
              file=sys.stderr)
        return 1
    where = "not written (--no-write)" if args.no_write else rel(OUT)
    print(f"[{GENERATOR}] ok: every unit and every internal function a complete "
          f"stratum's plan names is reached, every unit-naming record has a row behind it, "
          f"and the in-progress strata's distance is published as a census -> {where}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
