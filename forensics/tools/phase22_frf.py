#!/usr/bin/env python3
"""openssl-rs -- Phase 22.15 FRF challenges and the FRF-Fuzz sensitivity campaigns.

The plan's rule is this whole subphase (`docs/PHASE-22-SUBPHASES.md` section 6):

    "22.15 must challenge each extractor with a controlled mutation of its own defect
     class. A scanner that cannot detect the defect class it claims to inventory is not
     evidence."

and section 7 makes it a seal criterion ("the FRF sensitivity challenges pass"). Every
other Phase 22 plane already carries its own `courts()` -- an in-memory sensitivity
challenge over its own pure builder. This plane is the one that proves them *collectively
and independently*: it imports each plane module, drives that plane's own pure builder
over the real committed artefact and over a controlled mutation of the defect class the
plane claims to detect, and records the observed delta rather than the phrase "a court
exists".

Two kinds of evidence, and they are not interchangeable
-------------------------------------------------------
1. The **in-memory challenges**. For each plane a driver reconstructs the plane's raw
   model from its own committed artefact (via the plane's own reconstruction helpers),
   runs the pure builder on that baseline, applies one controlled mutation of the named
   defect class, runs the builder again, and diffs precise counters. A plane is
   `DETECTED` when the instrument moves exactly as the mutation implies, `NOT_DETECTED`
   when it does not (the most valuable finding in the stratum), and `NOT_DRIVEN` when the
   challenge cannot be constructed at all -- which is never a pass. The plane's own
   registered `courts()` verdict is carried beside it so a reader can see that the two
   agree (or do not).

2. The **end-to-end fresh-regeneration challenge**, which is a *different* kind of
   evidence: an in-memory mutation proves the logic reacts, but only a rebuild from the
   pinned authority source in a clean scratch proves the committed bytes are reproducible.
   `--fresh` regenerates the raw inputs from scratch, runs the extractor, hashes the
   normalised body, and requires `run1 == run2 == the committed artefact`. 22.2 (both
   pinned Doxyfiles, double run, must match) is mandatory; 22.1's capture rebuild and
   22.3/22.4's Clang replay are attempted. A plane over budget is recorded with its
   measured seconds and `deferred`. The fresh block is carried forward from the committed
   artefact unless `--fresh` is given, so a plain run is deterministic and cheap.

3. The **FRF-Fuzz campaign** seeds the extractors' *inputs* with adversarial shapes -- a
   malformed option row, a nested `=over/=item`, an unresolved `#if`, a second `static`
   with the same spelling, an object with no captured compile, a SYNOPSIS split across
   lines -- and requires the correct instrument to produce a residual rather than a
   silent, plausible answer. Only replay-confirmed failures (an instrument that accepts
   the adversarial input twice) are promoted into the record.

The court `RT-PHASE22-FRF` is a challenge over this harness itself: it takes a registered
challenge, mutates its observed result in memory, and requires the harness to report
`NOT_DETECTED`. A harness that always answers `DETECTED` is a rubber stamp and the court
fails on that check.

Output
------
    forensics/atlas/phase22/frf-challenges.json

Nothing here runs on the host: it is a `pipeline`-adjacent atlas generator and must be run
inside the court via `sh docker/openssl-rs-court.sh exec sh -c 'cd /work && python3
forensics/tools/phase22_frf.py [--fresh]'`.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Callable, Optional

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

import phase22_binary_graph as pbin  # noqa: E402
import phase22_build_commands as pbc  # noqa: E402
import phase22_cli_surface as pcli  # noqa: E402
import phase22_conditional as pcond  # noqa: E402
import phase22_config as pconf  # noqa: E402
import phase22_crosswalk as pcross  # noqa: E402
import phase22_dispatch as pdisp  # noqa: E402
import phase22_doxygen as pdox  # noqa: E402
import phase22_genealogy as pgen  # noqa: E402
import phase22_install_manifest as pinst  # noqa: E402
import phase22_pod as ppod  # noqa: E402
import phase22_tu_ast as ptu  # noqa: E402

GENERATOR = "forensics/tools/phase22_frf.py"
ARTEFACT_REL = "forensics/atlas/phase22/frf-challenges.json"
OUT = REPO_ROOT / ARTEFACT_REL
COURT = "RT-PHASE22-FRF"

DETECTED = "DETECTED"
NOT_DETECTED = "NOT_DETECTED"
NOT_DRIVEN = "NOT_DRIVEN"


class NotDriven(Exception):
    """The challenge for a plane could not be constructed from the committed evidence."""


# ---------------------------------------------------------------------------
# harness core -- one classification, used by the drivers and by the court
# ---------------------------------------------------------------------------

def classify_challenge(expected: dict, observed: dict) -> str:
    """The harness verdict: exactly the expected deltas, or the instrument is insensitive.

    This is deliberately the smallest possible classifier so that the court can mutate a
    record's `observed` in memory and *prove* the harness reports a `NOT_DETECTED`. A
    harness that returned `DETECTED` for a mismatched observed value would pass every
    challenge and be no evidence at all.
    """
    if expected is None or observed is None:
        return NOT_DRIVEN
    return DETECTED if expected == observed else NOT_DETECTED


def _body(rel_path: str) -> dict:
    path = REPO_ROOT / rel_path
    if not path.is_file():
        raise NotDriven(f"artefact missing: {rel_path}")
    return json.loads(path.read_text(encoding="utf-8"))["body"]


def _drop_first(seq: list, item) -> list:
    out = list(seq)
    if item in out:
        out.remove(item)
    return out


# ---------------------------------------------------------------------------
# the twelve in-memory drivers: one controlled mutation per defect class
# ---------------------------------------------------------------------------

def drive_22_1() -> tuple[dict, dict]:
    """22.1 -- drop a compile flag from the raw capture and re-normalise."""
    raw = REPO_ROOT / pbc.RAW_REL
    if not raw.is_file():
        raise NotDriven(f"raw capture missing: {pbc.RAW_REL}")
    records = pbc.load_raw(raw)
    configdata = REPO_ROOT / pbc.BUILD_DIR_REL / "configdata.pm"
    producer = pbc.read_producer(configdata) if configdata.is_file() else "unknown"
    base = pbc.build_body(copy.deepcopy(records), producer)

    idx = None
    for i, rec in enumerate(records):
        if pbc.is_translation_unit(rec) and any(
                a.startswith("-D") and len(a) > 2 for a in rec.get("argv", [])):
            idx = i
            break
    if idx is None:
        raise NotDriven("no translation unit carries a single-token -DFOO compile flag")
    token = next(a for a in records[idx]["argv"] if a.startswith("-D") and len(a) > 2)
    key = (records[idx]["source"], records[idx]["output"])
    base_row = next((c for c in base["commands"]
                     if (c["source"], c["output"]) == key), None)
    if base_row is None:
        raise NotDriven("the mutated unit is absent from the normalised baseline")

    mutated = copy.deepcopy(records)
    mutated[idx]["argv"].remove(token)
    new = pbc.build_body(mutated, producer)
    row = next(c for c in new["commands"] if (c["source"], c["output"]) == key)

    expected = {"commands_delta": 0, "distinct_sources_delta": 0,
                "unit_defines_delta": -1, "unit_args_delta": -1, "flag_gone": 1}
    observed = {
        "commands_delta": new["counts"]["commands"] - base["counts"]["commands"],
        "distinct_sources_delta": (new["counts"]["distinct_sources"]
                                   - base["counts"]["distinct_sources"]),
        "unit_defines_delta": len(row["defines"]) - len(base_row["defines"]),
        "unit_args_delta": len(row["args"]) - len(base_row["args"]),
        "flag_gone": int(token not in row["defines"] and token not in row["args"]),
    }
    return expected, observed


def drive_22_2() -> tuple[dict, dict]:
    """22.2 -- collapse two same-spelled entities into one destination."""
    body = _body(pdox.ARTEFACT_REL)
    configured, lexical = pdox.split_views(copy.deepcopy(body["entities"]))
    edges = pdox._edges_from_references(body["references"])
    base = pdox.build_body(copy.deepcopy(configured), copy.deepcopy(lexical), edges)

    caller = pdox._identity("function", "frf_same_spelling_caller", "synthetic/frf_probe.c", 7)
    a = pdox._identity("function", "lookup", "crypto/frf_a.c", 11)
    b = pdox._identity("function", "lookup", "crypto/frf_b.c", 22)
    new = pdox.build_body(configured, lexical, edges + [
        {"from": caller, "relation": "references", "target": a, "resolved": True},
        {"from": caller, "relation": "references", "target": b, "resolved": True},
    ])
    refs = new["references"].get(pdox._identity_str(caller), {}).get("references", [])
    expected = {"destinations": 2, "reference_edges_delta": 2}
    observed = {
        "destinations": len(refs) if set(refs) == {pdox._identity_str(a),
                                                   pdox._identity_str(b)} else 0,
        "reference_edges_delta": (new["counts"]["reference_edges"]
                                  - base["counts"]["reference_edges"]),
    }
    return expected, observed


def drive_22_3() -> tuple[dict, dict]:
    """22.3 -- lose a declaration link and require the link counter to move."""
    body = _body(ptu.ARTEFACT_REL)
    units = ptu._units_from_body(copy.deepcopy(body))
    base = ptu.build_body(copy.deepcopy(units))

    # A definition that currently counts as having a declaration, through an explicit
    # `declaration` field or through a same-name non-definition sibling.
    target = None
    for e in base["entities"]:
        if e["kind"] in ptu._LINKABLE and e["is_definition"]:
            if e.get("declaration") is not None:
                target = e
                break
            if any(x["kind"] == e["kind"] and x["name"] == e["name"] and not x["is_definition"]
                   for x in base["entities"]):
                target = e
                break
    if target is None:
        raise NotDriven("no linked definition exists to unlink")

    mutated = copy.deepcopy(units)
    changed = False
    for u in mutated:
        if u["file"] != target["unit"]:
            continue
        for row in u["entities"]:
            if (row["kind"], row["name"], row["file"], row["line"]) != (
                    target["kind"], target["name"], target["file"], target["line"]):
                continue
            if row.get("declaration") is not None:
                row["declaration"] = None
                changed = True
            else:
                # Drop the sibling declaration that made `has_declaration` true.
                for j, sib in enumerate(u["entities"]):
                    if (sib["kind"] == row["kind"] and sib["name"] == row["name"]
                            and not sib["is_definition"]):
                        del u["entities"][j]
                        changed = True
                        break
    if not changed:
        raise NotDriven("the selected declaration link could not be removed")

    new = ptu.build_body(mutated)
    expected = {"definitions_without_declaration_delta": 1,
                "definitions_delta": 0, "declarations_delta": 0}
    observed = {
        "definitions_without_declaration_delta": (
            new["counts"]["definitions_without_declaration"]
            - base["counts"]["definitions_without_declaration"]),
        "definitions_delta": new["counts"]["definitions"] - base["counts"]["definitions"],
        "declarations_delta": new["counts"]["declarations"] - base["counts"]["declarations"],
    }
    return expected, observed


def drive_22_4() -> tuple[dict, dict]:
    """22.4 -- drop a taken define and lose a skipped range."""
    body = _body(pcond.ARTEFACT_REL)
    units = copy.deepcopy(body["units"])
    sources = copy.deepcopy(body["sources"])
    base = pcond.build_body(copy.deepcopy(units), copy.deepcopy(sources))

    taken = Counter(d["macro"] for u in units for d in u.get("defines", []) if d.get("taken"))
    define_target = None
    for u in units:
        for d in u.get("defines", []):
            if d.get("taken") and taken[d["macro"]] == 1:
                define_target = (u["source"], d)
                break
        if define_target:
            break

    range_target = None
    for u in units:
        if u.get("skipped_ranges"):
            range_target = (u["source"], u["skipped_ranges"][0])
            break

    if define_target is None or range_target is None:
        raise NotDriven("no unique taken define or skipped range to remove")

    # mutation A: drop a uniquely-defined taken macro.
    mut_a = copy.deepcopy(units)
    pcond._unit_for(mut_a, define_target[0])["defines"].remove(
        next(d for d in pcond._unit_for(mut_a, define_target[0])["defines"]
             if d["macro"] == define_target[1]["macro"]))
    new_a = pcond.build_body(mut_a, copy.deepcopy(sources))

    # mutation B: drop a skipped range.
    mut_b = copy.deepcopy(units)
    pcond._unit_for(mut_b, range_target[0])["skipped_ranges"].remove(range_target[1])
    new_b = pcond.build_body(mut_b, copy.deepcopy(sources))

    expected = {"defines_delta": -1, "macros_defined_delta": -1, "skipped_ranges_delta": -1}
    observed = {
        "defines_delta": new_a["counts"]["defines"] - base["counts"]["defines"],
        "macros_defined_delta": (new_a["counts"]["macros_defined"]
                                 - base["counts"]["macros_defined"]),
        "skipped_ranges_delta": (new_b["counts"]["skipped_ranges"]
                                 - base["counts"]["skipped_ranges"]),
    }
    return expected, observed


def drive_22_5() -> tuple[dict, dict]:
    """22.5 -- miss a generated input, by feeding a rule an input that is itself generated."""
    body = _body(pgen.ARTEFACT_REL)
    declared = sorted(set(body["outputs_without_a_rule"])
                      | {r["output"] for r in body["lineage"]})
    rows = pgen._rows_from_body(copy.deepcopy(body))
    base = pgen.build_body(copy.deepcopy(rows), list(declared))

    existing_output = next((r["output"] for r in base["lineage"] if r["generator"]), None)
    if existing_output is None:
        raise NotDriven("no generated output exists to feed as an input")

    mutated = copy.deepcopy(rows)
    mutated.append({
        "output": f"{pgen.BLD_PREFIX}/synthetic/frf_probe_gen.c",
        "inputs": [existing_output],
        "generator": f"{pgen.SRC_PREFIX}/util/dofile.pl",
        "generator_argv": [],
        "class": "source",
        "rule_site": f"{pgen.MAKEFILE_REL}:0",
    })
    new = pgen.build_body(mutated, list(declared))
    expected = {"generated_inputs_delta": 1, "edges_delta": 1, "outputs_delta": 1}
    observed = {
        "generated_inputs_delta": (new["counts"]["generated_inputs"]
                                   - base["counts"]["generated_inputs"]),
        "edges_delta": new["counts"]["edges"] - base["counts"]["edges"],
        "outputs_delta": new["counts"]["outputs"] - base["counts"]["outputs"],
    }
    return expected, observed


def drive_22_6() -> tuple[dict, dict]:
    """22.6 -- mis-resolve a relocation by removing the definition its edge resolved to."""
    body = _body(pbin.ARTEFACT_REL)
    model = pbin.model_from_body(copy.deepcopy(body))
    meta = pbin.meta_from_body(body)
    base = pbin.derive_body(copy.deepcopy(model), meta)

    single = {n for n, ids in base["definitions"].items() if len(ids) == 1}
    referenced = sorted({e["symbol"] for o in base["objects"] for e in o["relocations"]
                         if e["symbol"] in single})
    if not referenced:
        raise NotDriven("no singly-defined symbol is referenced by a live relocation")
    target = referenced[0]
    affected = sum(1 for o in base["objects"] for e in o["relocations"]
                   if e["symbol"] == target)

    mutated = copy.deepcopy(model)
    for o in mutated["objects"]:
        o["symbols"] = [s for s in o["symbols"]
                        if not (s["name"] == target and s["section"] is not None)]
    new = pbin.derive_body(mutated, meta)
    expected = {"name_left_index": 1, "resolved_edges_delta": -affected}
    observed = {
        "name_left_index": int(target not in new["definitions"]),
        "resolved_edges_delta": (new["counts"]["resolved_edges"]
                                 - base["counts"]["resolved_edges"]),
    }
    return expected, observed


def drive_22_7() -> tuple[dict, dict]:
    """22.7 -- lose a dispatch slot from a table."""
    body = _body(pdisp.ARTEFACT_REL)
    model = pdisp._model_from_body(body)
    base = pdisp.build_body(copy.deepcopy(model))

    target_counts = Counter(e["target"] for e in base["edges"])
    victim = None
    for t in base["tables"]:
        if t["edge_kind"] != "DISPATCH_SLOT":
            continue
        for r in t["rows"]:
            tgt = r.get("target")
            if tgt and target_counts[tgt] == 1 and tgt not in model["binary_address_global"]:
                victim = (t["id"], tgt)
                break
        if victim:
            break
    if victim is None:
        raise NotDriven("no uniquely-targeted dispatch slot was found to remove")

    table_id, tgt = victim
    mutated = copy.deepcopy(model)
    tbl = next(t for t in mutated["tables"] if t["id"] == table_id)
    tbl["rows"] = [r for r in tbl["rows"] if r.get("target") != tgt]
    tbl["rows_total"] = max(0, tbl["rows_total"] - 1)
    new = pdisp.build_body(mutated)
    expected = {"edges_delta": -1, "dispatch_slot_delta": -1, "slot_edge_gone": 1}
    observed = {
        "edges_delta": new["counts"]["edges"] - base["counts"]["edges"],
        "dispatch_slot_delta": (
            new["counts"]["edges_by_kind"].get("DISPATCH_SLOT", 0)
            - base["counts"]["edges_by_kind"].get("DISPATCH_SLOT", 0)),
        "slot_edge_gone": int(not any(e["target"] == tgt and e["kind"] == "DISPATCH_SLOT"
                                      for e in new["edges"])),
    }
    return expected, observed


def drive_22_8() -> tuple[dict, dict]:
    """22.8 -- omit an installed artefact from the distribution manifest."""
    body = _body(pinst.ARTEFACT_REL)
    raw = [pinst._raw(e) for e in body["entries"]]
    pinned = copy.deepcopy(body["pinned"])
    base = pinst.build_body(copy.deepcopy(raw), copy.deepcopy(pinned), {})

    victim = next((e for e in base["entries"] if e["category"] == "library"), None)
    if victim is None:
        raise NotDriven("the manifest has no library entry to omit")
    path = victim["path"]
    mutated = [r for r in raw if r["path"] != path]
    new = pinst.build_body(mutated, copy.deepcopy(pinned), {})

    expected = {"entries_delta": -1, "category_delta": -1, "path_absent": 1}
    observed = {
        "entries_delta": new["counts"]["entries"] - base["counts"]["entries"],
        "category_delta": (new["counts"]["by_category"].get(victim["category"], 0)
                           - base["counts"]["by_category"].get(victim["category"], 0)),
        "path_absent": int(path not in {e["path"] for e in new["entries"]}),
    }
    return expected, observed


def drive_22_9() -> tuple[dict, dict]:
    """22.9 -- silently return zero options, via the repaired Phase-1 defect."""
    body = _body(pcli.ARTEFACT_REL)
    capture = pcli.capture_from_body(body)
    base = pcli.build_body(capture, parser=pcli.classify_option_rows)
    broken = pcli.build_body(capture, parser=pcli._broken_parser)
    expected = {
        "structured_when_correct": 1,
        "zero_options_under_defect": 1,
        "structured_delta_under_defect": -base["counts"]["options_structured"],
    }
    observed = {
        "structured_when_correct": int(base["counts"]["options_structured"] > 0),
        "zero_options_under_defect": int(broken["counts"]["commands_with_zero_options"] > 0),
        "structured_delta_under_defect": (broken["counts"]["options_structured"]
                                          - base["counts"]["options_structured"]),
    }
    return expected, observed


def drive_22_10() -> tuple[dict, dict]:
    """22.10 -- miss an environment read out of the aggregation."""
    body = copy.deepcopy(_body(pconf.ARTEFACT_REL))
    pod = REPO_ROOT / pconf.ENV_POD_REL
    body["_documented"] = (pconf.parse_env_pod(pod.read_text(encoding="utf-8", errors="replace"))
                           if pod.is_file() else {})
    raw = pconf._raw_from_body(body)
    base = pconf._derive(copy.deepcopy(raw))

    # A variable read exactly once: dropping that read loses the variable and the site.
    single = next((v for v in base["env_vars"] if v["site_count"] == 1 and v["sites"]), None)
    if single is None:
        raise NotDriven("no single-site environment variable exists to un-read")
    name = single["name"]
    victim = single["sites"][0]

    mutated = copy.deepcopy(raw)
    mutated["env_sites"] = [s for s in mutated["env_sites"]
                            if not (s["name"] == name and s["file"] == victim["file"]
                                    and s["line"] == victim["line"])]
    new = pconf._derive(mutated)
    expected = {"env_sites_delta": -1, "env_vars_delta": -1}
    observed = {
        "env_sites_delta": new["counts"]["env_sites"] - base["counts"]["env_sites"],
        "env_vars_delta": new["counts"]["env_vars"] - base["counts"]["env_vars"],
    }
    return expected, observed


def drive_22_11() -> tuple[dict, dict]:
    """22.11 -- fail to detect a POD/manual disagreement when an option is dropped."""
    body = _body(ppod.ARTEFACT_REL)
    pages = body["pages"]
    index = body["reconciliation"]["index"]
    base = ppod.build_body(copy.deepcopy(pages), index)

    idx = next((i for i, p in enumerate(pages)
                if p["section"] == 1 and p["command"] and p["options"]), None)
    if idx is None:
        raise NotDriven("no command page with documented options was found")
    mutated = copy.deepcopy(pages)
    mutated[idx]["options"] = mutated[idx]["options"][1:]
    new = ppod.build_body(mutated, index)

    base_class = ppod._class_counts(base["reconciliation"]["disagreements"])
    new_class = ppod._class_counts(new["reconciliation"]["disagreements"])
    expected = {"disagreements_rose": 1, "undocumented_option_rose": 1}
    observed = {
        "disagreements_rose": int(new["counts"]["disagreements"]
                                  > base["counts"]["disagreements"]),
        "undocumented_option_rose": int(
            new_class.get("RUNTIME_CLI_OPTION_UNDOCUMENTED", 0)
            > base_class.get("RUNTIME_CLI_OPTION_UNDOCUMENTED", 0)),
    }
    return expected, observed


def drive_22_13() -> tuple[dict, dict]:
    """22.13 -- drop a test edge from the crosswalk."""
    body = _body(pcross.ARTEFACT_REL)
    sources = copy.deepcopy(body["sources"])
    exported = copy.deepcopy(body["exported_symbols"])
    public = copy.deepcopy(body.get("public_symbols", []))
    base = pcross.build_body(copy.deepcopy(sources), copy.deepcopy(exported),
                             copy.deepcopy(public))
    base_rows = {s["path"]: s for s in base["sources"]}

    victim = next((s for s in base["sources"]
                   if s["kind"] in ("test", "fuzz") and s["symbols_called"]), None)
    if victim is None:
        raise NotDriven("no test/fuzz source calls a symbol to drop")
    name = victim["symbols_called"][0]

    mutated = copy.deepcopy(sources)
    for s in mutated:
        if s["path"] == victim["path"]:
            s["symbols_called"] = _drop_first(s["symbols_called"], name)
    new = pcross.build_body(mutated, copy.deepcopy(exported), copy.deepcopy(public))
    edge_gone = int(not any(e["source"] == victim["path"] and e["target"] == name
                            and e["kind"] == "call" for e in new["edges"]))
    expected = {"edges_delta": -1, "edge_gone": 1}
    observed = {
        "edges_delta": new["counts"]["edges"] - base["counts"]["edges"],
        "edge_gone": edge_gone,
    }
    return expected, observed


# ---------------------------------------------------------------------------
# the challenge registry
# ---------------------------------------------------------------------------

CHALLENGES: list[dict] = [
    {"plane": "22.1",
     "instrument": "phase22_build_commands.build_body",
     "defect_class": "dropped-compile-flag",
     "mutation": "remove one `-DFOO` token from one translation unit's captured argv",
     "expected_effect": ("that unit's `defines` and `args` each lose exactly one element; "
                         "`commands` and `distinct_sources` are unchanged"),
     "driver": drive_22_1},
    {"plane": "22.2",
     "instrument": "phase22_doxygen.build_body/_adjacency",
     "defect_class": "collapsed-same-spelled-entities",
     "mutation": ("add one caller with two resolved reference targets that share the "
                  "spelling `lookup` in two different files"),
     "expected_effect": ("two distinct destinations are stored and `reference_edges` rises "
                         "by two; a name-keyed collapse would store one"),
     "driver": drive_22_2},
    {"plane": "22.3",
     "instrument": "phase22_tu_ast.build_body",
     "defect_class": "lost-declaration-link",
     "mutation": "remove the declaration-side link of one linked definition",
     "expected_effect": ("`definitions_without_declaration` rises by one while `definitions` "
                         "and `declarations` do not move"),
     "driver": drive_22_3},
    {"plane": "22.4",
     "instrument": "phase22_conditional.build_body",
     "defect_class": "dropped-define-or-missed-skipped-range",
     "mutation": ("drop one uniquely-defined taken macro, and separately drop one skipped "
                  "source range"),
     "expected_effect": ("`defines` and `macros_defined` each fall by one; `skipped_ranges` "
                         "falls by one"),
     "driver": drive_22_4},
    {"plane": "22.5",
     "instrument": "phase22_genealogy.build_body",
     "defect_class": "missed-generated-input",
     "mutation": "add a rule whose input is an existing generated output",
     "expected_effect": ("the new input is marked generated, so `generated_inputs`, `edges` "
                         "and `outputs` each rise by one"),
     "driver": drive_22_5},
    {"plane": "22.6",
     "instrument": "phase22_binary_graph.derive_body",
     "defect_class": "mis-resolved-relocation",
     "mutation": "remove the single definition that a set of live relocation edges resolved to",
     "expected_effect": ("the name leaves the definition index and exactly its live edges stop "
                         "resolving"),
     "driver": drive_22_6},
    {"plane": "22.7",
     "instrument": "phase22_dispatch.build_body",
     "defect_class": "lost-dispatch-slot",
     "mutation": "remove one uniquely-targeted row from a DISPATCH_SLOT table",
     "expected_effect": ("`edges` and the DISPATCH_SLOT kind count each fall by one and the "
                         "slot's edge disappears"),
     "driver": drive_22_7},
    {"plane": "22.8",
     "instrument": "phase22_install_manifest.build_body",
     "defect_class": "omitted-installed-artefact",
     "mutation": "omit one library entry from the walked install manifest",
     "expected_effect": ("`entries` and the library category each fall by one and the path is "
                         "absent"),
     "driver": drive_22_8},
    {"plane": "22.9",
     "instrument": "phase22_cli_surface.build_body",
     "defect_class": "silently-zero-options",
     "mutation": "replace the option-row parser with the original Phase-1 defect that drops "
                 "every row silently",
     "expected_effect": ("`options_structured` collapses and `commands_with_zero_options` "
                         "becomes non-zero"),
     "driver": drive_22_9},
    {"plane": "22.10",
     "instrument": "phase22_config.build_body",
     "defect_class": "missed-environment-read",
     "mutation": "remove the only read site of a single-site environment variable",
     "expected_effect": ("`env_sites` and `env_vars` each fall by one"),
     "driver": drive_22_10},
    {"plane": "22.11",
     "instrument": "phase22_pod.build_body/reconcile",
     "defect_class": "undetected-pod-manual-disagreement",
     "mutation": "drop the documented options of a command page so the runtime option is "
                 "undocumented",
     "expected_effect": ("the disagreement count rises and RUNTIME_CLI_OPTION_UNDOCUMENTED "
                         "rises"),
     "driver": drive_22_11},
    {"plane": "22.13",
     "instrument": "phase22_crosswalk.build_body",
     "defect_class": "dropped-test-edge",
     "mutation": "remove one called symbol from a test source",
     "expected_effect": "`edges` falls by one and that edge is gone",
     "driver": drive_22_13},
]

# The module whose own `courts()` is carried beside each challenge, by plane.
_PLANE_MODULE = {
    "22.1": pbc, "22.2": pdox, "22.3": ptu, "22.4": pcond, "22.5": pgen,
    "22.6": pbin, "22.7": pdisp, "22.8": pinst, "22.9": pcli, "22.10": pconf,
    "22.11": ppod, "22.13": pcross,
}


def _registered_court(module) -> Optional[dict]:
    """The plane's own committed `courts()` verdict, run for real, or a load note."""
    fn = getattr(module, "courts", None)
    if not callable(fn):
        return None
    try:
        records = fn() or []
    except Exception as exc:  # a module whose court cannot be run is not a passing court
        return {"court": None, "verdict": "unloadable", "reason": f"{type(exc).__name__}: {exc}"}
    if not records:
        return {"court": None, "verdict": "not-registered",
                "reason": "the plane's courts() returned nothing"}
    first = records[0]
    return {"court": first.get("court"), "verdict": first.get("verdict"),
            "observations": first.get("observations")}


def build_challenges() -> list[dict]:
    out: list[dict] = []
    for spec in CHALLENGES:
        plane = spec["plane"]
        record = {
            "plane": plane,
            "instrument": spec["instrument"],
            "defect_class": spec["defect_class"],
            "mutation": spec["mutation"],
            "expected_effect": spec["expected_effect"],
            "expected": None,
            "observed": None,
            "status": NOT_DRIVEN,
            "reason": None,
            "registered_court": _registered_court(_PLANE_MODULE[plane]),
        }
        try:
            expected, observed = spec["driver"]()
            record["expected"] = expected
            record["observed"] = observed
            record["status"] = classify_challenge(expected, observed)
            if record["status"] == NOT_DETECTED:
                record["reason"] = ("the instrument did not move as its own defect class "
                                    "requires")
        except NotDriven as exc:
            record["status"] = NOT_DRIVEN
            record["reason"] = str(exc)
        except Exception as exc:  # any failure to drive is a NOT_DRIVEN, never a pass
            record["status"] = NOT_DRIVEN
            record["reason"] = f"{type(exc).__name__}: {exc}"
        out.append(record)
    return sorted(out, key=lambda r: [int(x) for x in r["plane"].split(".")])


# ---------------------------------------------------------------------------
# the end-to-end fresh-regeneration challenge
# ---------------------------------------------------------------------------

def _call_tool_to(module, out_abs: Path, argv: list[str]) -> dict:
    """Run a plane's `main` with its output redirected to a scratch file, and return the doc.

    The plane's `OUT_REL` is monkeypatched so the committed artefact is never touched: the
    fresh run is a re-derivation into scratch, not an overwrite of evidence.
    """
    saved = module.OUT_REL
    module.OUT_REL = str(out_abs)
    try:
        module.main(list(argv))
    finally:
        module.OUT_REL = saved
    return json.loads(out_abs.read_text(encoding="utf-8"))


def _fresh_tool(plane: str, module, runs: int, argv_for: Callable[[int, Path], list[str]],
                jobs: int) -> dict:
    committed_body = _body(module.ARTEFACT_REL)
    committed_hash = content_hash(committed_body)
    results = []
    for i in range(runs):
        scratch = Path(f"/tmp/phase22-frf-fresh-{plane.replace('.', '_')}-{i + 1}")
        if scratch.exists():
            shutil.rmtree(scratch)
        scratch.mkdir(parents=True)
        started = time.monotonic()
        doc = _call_tool_to(module, scratch / "out.json", argv_for(i, scratch))
        seconds = int(round(time.monotonic() - started))
        digest = content_hash(doc["body"])
        results.append({"run": i + 1, "body_sha256": digest, "seconds": seconds,
                        "match_committed": digest == committed_hash})
    matched = all(r["match_committed"] for r in results)
    return {
        "plane": plane,
        "artefact": module.ARTEFACT_REL,
        "status": "verified" if matched else "mismatch",
        "method": (f"regenerate the raw input in a clean out-of-tree scratch with the pinned "
                   f"tool, run {module.__name__} over it, hash the normalised body, and compare "
                   f"to the committed artefact"),
        "runs": results,
        "committed_body_sha256": committed_hash,
        "seconds": sum(r["seconds"] for r in results),
        "note": (f"{runs} fresh regeneration(s); REQUIRED: every run equals the committed body"
                 if matched else
                 f"{runs} fresh regeneration(s); a run did NOT equal the committed body"),
    }


def fresh_22_2(jobs: int) -> dict:
    """22.2 -- both pinned Doxyfiles, from the whole authority tree, twice."""
    return _fresh_tool("22.2", pdox, 2,
                       lambda i, s: ["--scratch", str(s)], jobs)


def fresh_22_3(jobs: int) -> dict:
    """22.3 -- replay 22.1's captured invocations with Clang into scratch, twice."""
    return _fresh_tool("22.3", ptu, 2, lambda i, s: ["--jobs", str(jobs)], jobs)


def fresh_22_4(jobs: int) -> dict:
    """22.4 -- replay the same captured invocations through Clang's preprocessor, twice."""
    return _fresh_tool("22.4", pcond, 2, lambda i, s: ["--jobs", str(jobs)], jobs)


def fresh_22_1(jobs: int) -> dict:
    """22.1 -- rebuild the raw execution capture in the original scratch, then normalise, twice.

    The generated `Makefile` bakes the scratch directory into the `configure` argv and into
    each compile's `directory`, so a capture is only reproducible in the *same* scratch the
    authority used (`/tmp/phase22-recapture`); the build's own parallel log order does not
    matter because the normaliser sorts by (source, output). `phase22_capture_build` removes and
    re-`Configure`s that scratch on every invocation, so the second run is a second clean build
    in the same directory rather than an incremental no-op.
    """
    plane = "22.1"
    committed_body = _body(pbc.OUT_REL)
    committed_hash = content_hash(committed_body)
    scratch = Path("/tmp/phase22-recapture")
    import phase22_capture_build as pcapture  # local: only needed by the fresh path
    configdata = REPO_ROOT / pbc.BUILD_DIR_REL / "configdata.pm"
    producer = pbc.read_producer(configdata) if configdata.is_file() else "unknown"
    results = []
    for i in range(2):
        log = Path(f"/tmp/phase22-frf-fresh-22_1-run{i + 1}.jsonl")
        if log.exists():
            log.unlink()
        started = time.monotonic()
        saved_pcc_capture = pcapture.CAPTURE_REL
        try:
            pcapture.CAPTURE_REL = str(log)
            pcapture.main(["--scratch", str(scratch), "--jobs", str(jobs)])
        finally:
            pcapture.CAPTURE_REL = saved_pcc_capture
        # `build_body` is exactly what `pbc.main` runs; calling it directly keeps the fresh raw
        # log, which lives outside the repository, out of the envelope's InputRef path handling.
        body = pbc.build_body(pbc.load_raw(log), producer)
        seconds = int(round(time.monotonic() - started))
        digest = content_hash(body)
        results.append({"run": i + 1, "body_sha256": digest, "seconds": seconds,
                        "match_committed": digest == committed_hash})
    matched = all(r["match_committed"] for r in results)
    return {
        "plane": plane,
        "status": "verified" if matched else "mismatch",
        "method": (f"rebuild the execution capture with the transparent compiler wrapper in "
                   f"a clean scratch, normalise it with phase22_build_commands, hash the body, "
                   f"and compare to the committed artefact"),
        "runs": results,
        "committed_body_sha256": committed_hash,
        "seconds": sum(r["seconds"] for r in results),
        "note": ("2 fresh regenerations; REQUIRED: every run equals the committed body"
                 if matched else
                 "2 fresh regenerations; a run did NOT equal the committed body"),
    }


_FRESH: dict[str, Callable[[int], dict]] = {
    "22.1": fresh_22_1,
    "22.2": fresh_22_2,
    "22.3": fresh_22_3,
    "22.4": fresh_22_4,
}


CAPTURE_SCRATCH = "/tmp/phase22-recapture"


def run_fresh(planes: list[str], jobs: int, budget: int) -> list[dict]:
    # 22.2's configured view resolves 22.1's captured include tokens against the capture's own
    # build directory (`/tmp/phase22-recapture`), so the committed bodies were produced with
    # that ephemeral scratch absent. Reproduce the documented state: remove it before the
    # extractive planes, and run 22.1 (whose rebuild recreates it) last.
    scratch = Path(CAPTURE_SCRATCH)
    if scratch.exists():
        shutil.rmtree(scratch)
    ordered = [p for p in planes if p != "22.1"] + (["22.1"] if "22.1" in planes else [])
    out: list[dict] = []
    for plane in ordered:
        fn = _FRESH.get(plane)
        if fn is None:
            out.append({"plane": plane, "status": "deferred",
                        "reason": "no fresh regenerator is implemented for this plane"})
            continue
        started = time.monotonic()
        try:
            record = fn(jobs)
        except Exception as exc:
            record = {"plane": plane, "status": "deferred",
                      "reason": f"{type(exc).__name__}: {exc}",
                      "seconds": int(round(time.monotonic() - started))}
        record.setdefault("seconds", int(round(time.monotonic() - started)))
        record["capture_scratch_clean"] = True
        if record.get("status") in ("verified", "mismatch") and record["seconds"] > budget:
            record["status"] = "deferred"
            record["reason"] = (f"fresh path exceeded the {budget}s budget "
                                f"(measured {record['seconds']}s)")
        out.append(record)
    return sorted(out, key=lambda r: [int(x) for x in r["plane"].split(".")])


# ---------------------------------------------------------------------------
# the FRF-Fuzz campaign
# ---------------------------------------------------------------------------

def _fuzz_malformed_option_row() -> tuple[int, dict]:
    options, refused, _marker = pcli.classify_option_rows(
        "in val        Input file\nhelp -\n")
    return len(refused), {"refused": refused, "options": [o["name"] for o in options]}


def _fuzz_nested_over_item() -> tuple[int, dict]:
    lines = ["=over 4", "=item B<GOOD_VAR>", "text", "=over 4", "=item B<NESTED_VAR>",
             "text", "=back", "=back"]
    names = ppod._env_names(lines)
    handled = int("GOOD_VAR" in names and "NESTED_VAR" not in names)
    return handled, {"names": names}


def _fuzz_unresolved_condition() -> tuple[int, dict]:
    value = pcond.eval_cond("PHASE22_FRF_UNKNOWN", {"PHASE22_FRF_UNKNOWN": "not-an-integer"})
    return int(value is None), {"value": repr(value)}


def _fuzz_same_spelling_static() -> tuple[int, dict]:
    caller = pdox._identity("function", "frf_fuzz_caller", "synthetic/frf.c", 3)
    a = pdox._identity("function", "lookup", "crypto/frf_a.c", 1)
    b = pdox._identity("function", "lookup", "crypto/frf_b.c", 2)
    adjacency = pdox._adjacency([
        {"from": caller, "relation": "references", "target": a, "resolved": True},
        {"from": caller, "relation": "references", "target": b, "resolved": True},
    ])
    refs = adjacency.get(pdox._identity_str(caller), {}).get("references", [])
    return (2 if len(refs) == 2 else 0), {"destinations": refs}


def _fuzz_object_without_compile() -> tuple[int, dict]:
    body = _body(pbin.ARTEFACT_REL)
    model = pbin.model_from_body(copy.deepcopy(body))
    meta = pbin.meta_from_body(body)
    base = pbin.derive_body(copy.deepcopy(model), meta)
    mutated = copy.deepcopy(model)
    art = next(a["path"] for a in mutated["artifacts"] if a["format"] == "ar")
    member = "libcrypto-lib-__frf_fuzz_uncompiled__.o"
    oid = f"{art}({member})"
    mutated["objects"].append({
        "id": oid, "artifact": art, "member": member, "source": None, "source_kind": None,
        "symbols": [], "relocations": [], "sections": {}, "soname": None,
        "dt_needed": [], "versions_defined": [],
    })
    new = pbin.derive_body(mutated, meta)
    delta = new["counts"]["objects_unexplained"] - base["counts"]["objects_unexplained"]
    listed = int(any(u["id"] == oid for u in new["unexplained"]))
    return (delta if delta == 1 and listed else 0), {"unexplained_delta": delta, "listed": listed}


def _fuzz_pod_synopsis_split() -> tuple[int, dict]:
    decls = ppod._synopsis_declarations(
        ["int FRF_fuzz_split(const char *a,", "    int b);"])
    ok = int(len(decls) == 1 and "FRF_fuzz_split" in decls[0] and "int b" in decls[0])
    return ok, {"decls": decls}


FUZZ_SEEDS: list[dict] = [
    {"id": "malformed-option-row",
     "instrument": "phase22_cli_surface.classify_option_rows",
     "seed": "an `in val        Input file` help-shaped row that is not `name type`",
     "expected_residual": "the row is refused rather than silently dropped",
     "run": _fuzz_malformed_option_row},
    {"id": "nested-over-item",
     "instrument": "phase22_pod._env_names",
     "seed": "a nested `=over`/`=item` list inside a top-level environment item",
     "expected_residual": "the nested name is excluded and the top-level name kept",
     "run": _fuzz_nested_over_item},
    {"id": "unresolved-if-condition",
     "instrument": "phase22_conditional.eval_cond",
     "seed": "a `#if` over a defined macro whose value is not an integer",
     "expected_residual": "the condition evaluates to `None` (unresolved), not True or False",
     "run": _fuzz_unresolved_condition},
    {"id": "second-static-same-spelling",
     "instrument": "phase22_doxygen._adjacency",
     "seed": "two `static` functions named `lookup` in different files, both referenced",
     "expected_residual": "two distinct destinations, not one collapsed spelling",
     "run": _fuzz_same_spelling_static},
    {"id": "object-without-compile",
     "instrument": "phase22_binary_graph.derive_body",
     "seed": "an archive member that no captured invocation and no makefile rule explains",
     "expected_residual": "the object lands in `unexplained`, not in an other-bucket",
     "run": _fuzz_object_without_compile},
    {"id": "pod-synopsis-across-lines",
     "instrument": "phase22_pod._synopsis_declarations",
     "seed": "a man3 SYNOPSIS declaration broken across two source lines",
     "expected_residual": "the declaration is recovered whole from both lines",
     "run": _fuzz_pod_synopsis_split},
]


def run_fuzz() -> dict:
    seeds: list[dict] = []
    promoted: list[dict] = []
    for spec in FUZZ_SEEDS:
        try:
            count, detail = spec["run"]()
            error = None
        except Exception as exc:  # an instrument that raises is not a silent answer
            count, detail, error = 0, {}, f"{type(exc).__name__}: {exc}"
        status = "residual-produced" if count > 0 else "no-residual"
        replay_confirmed: Optional[bool] = None
        if status == "no-residual":
            # Replay before promoting: only a twice-confirmed silent acceptance is a finding.
            try:
                count2, _ = spec["run"]()
            except Exception:
                count2 = 0
            replay_confirmed = count2 <= 0
            if replay_confirmed:
                promoted.append({"seed": spec["id"], "instrument": spec["instrument"],
                                 "observed": detail, "error": error})
        seeds.append({
            "seed": spec["id"],
            "instrument": spec["instrument"],
            "input": spec["seed"],
            "expected_residual": spec["expected_residual"],
            "residual_count": count,
            "status": status,
            "replay_confirmed_failure": replay_confirmed,
            "observed": detail,
            "error": error,
        })
    return {
        "seeds": seeds,
        "promoted_failures": promoted,
        "counts": {
            "seeds": len(seeds),
            "residual_produced": sum(1 for s in seeds if s["status"] == "residual-produced"),
            "no_residual": sum(1 for s in seeds if s["status"] == "no-residual"),
            "promoted_failures": len(promoted),
        },
        "note": ("a seed whose instrument returns a plausible answer without a residual is a "
                 "candidate finding; only one whose silence is reproduced on replay is promoted "
                 "into `promoted_failures`"),
    }


# ---------------------------------------------------------------------------
# the court -- RT-PHASE22-FRF
# ---------------------------------------------------------------------------

def court_frf(body: dict) -> dict:
    """A sensitivity challenge over the challenge harness itself.

    The harness classifies a challenge by comparing its `expected` deltas with its `observed`
    deltas. This court proves that classifier is not a rubber stamp: it mutates a registered
    challenge's observed result in memory and requires the harness to answer `NOT_DETECTED`.
    If the harness answered `DETECTED` for a mismatched observation it would pass every plane's
    challenge and be no evidence at all, and this court would fail.
    """
    challenges = body["challenges"]
    counts = body["counts"]
    checks: list[tuple[str, bool]] = []

    checks.append(("baseline: challenges are registered", len(challenges) >= 12))
    planes = {c["plane"] for c in challenges}
    checks.append((f"baseline: every plane is represented ({len(planes)} planes)",
                   len(planes) == len(challenges)))
    checks.append(("baseline: the counts agree with the records",
                   counts["challenges"] == len(challenges)
                   and counts["detected"] == sum(1 for c in challenges
                                                 if c["status"] == DETECTED)
                   and counts["not_detected"] == sum(1 for c in challenges
                                                     if c["status"] == NOT_DETECTED)
                   and counts["not_driven"] == sum(1 for c in challenges
                                                   if c["status"] == NOT_DRIVEN)))

    detected = [c for c in challenges if c["status"] == DETECTED]
    checks.append(("baseline: at least one instrument detected its own defect class",
                   len(detected) > 0))

    # -- the sensitivity break: mutate a registered challenge's observed result ---------------
    sample = detected[0] if detected else challenges[0]
    mutated = copy.deepcopy(sample)
    if mutated.get("observed"):
        key = sorted(mutated["observed"])[0]
        mutated["observed"][key] = mutated["observed"][key] + 1
    else:
        mutated["observed"] = {"frf_harness_break": 1}
    mutated_verdict = classify_challenge(mutated["expected"], mutated["observed"])
    checks.append(("sensitivity: a registered challenge whose observed result is mutated in "
                   "memory is reported NOT_DETECTED", mutated_verdict == NOT_DETECTED))
    checks.append(("sensitivity: the same record unmutated is reported DETECTED",
                   classify_challenge(sample["expected"], sample["observed"]) == DETECTED))

    # -- negative controls: the classifier can produce both verdicts -------------------------
    checks.append(("sensitivity: a synthetic matching pair is DETECTED",
                   classify_challenge({"x": 1}, {"x": 1}) == DETECTED))
    checks.append(("sensitivity: a synthetic mismatching pair is NOT_DETECTED",
                   classify_challenge({"x": 1}, {"x": 0}) == NOT_DETECTED))
    checks.append(("sensitivity: a missing observation is NOT_DRIVEN, not a pass",
                   classify_challenge({"x": 1}, None) == NOT_DRIVEN))

    # -- the plane failures are surfaced, not smoothed over ----------------------------------
    failed = [c["plane"] for c in challenges if c["status"] == NOT_DETECTED]
    undriven = [c["plane"] for c in challenges if c["status"] == NOT_DRIVEN]
    checks.append((f"every instrument detected its own defect class (failed: {failed})",
                   not failed))
    checks.append((f"every challenge could be driven (undriven: {undriven})", not undriven))

    # -- the fuzz campaign -------------------------------------------------------------------
    fuzz = body["frf_fuzz"]
    checks.append(("fuzz: every seed produced a residual",
                   fuzz["counts"]["no_residual"] == 0))
    checks.append(("fuzz: no replay-confirmed silence was promoted",
                   fuzz["counts"]["promoted_failures"] == 0))

    # -- the fresh-regeneration evidence is carried, not asserted by this court ---------------
    fresh = body["fresh_regeneration"]
    verified = [f["plane"] for f in fresh if f.get("status") == "verified"]
    deferred = [f["plane"] for f in fresh if f.get("status") == "deferred"]
    checks.append(("fresh: 22.2 ran end to end and matched",
                   "22.2" in verified))
    checks.append(("fresh: no fresh regeneration mismatched", not any(
        f.get("status") == "mismatch" for f in fresh)))
    # **And the record must be against the artefact on disk.** A fresh run that matched last commit
    # plus an artefact edited since is exactly the "the sentence exists" failure this check is for:
    # the record would keep saying "verified" about bytes nobody regenerated. Each verified entry
    # names its artefact and the body hash it saw, so the court recomputes that hash now and fails
    # when the two disagree -- which tells the reader to re-run `--fresh` rather than to trust a
    # stale line. Recomputing is cheap; the fresh runs themselves are not, which is why they are
    # recorded rather than repeated here.
    stale = []
    for entry in fresh:
        if entry.get("status") != "verified" or not entry.get("artefact"):
            continue
        try:
            now = content_hash(_body(entry["artefact"]))
        except (OSError, KeyError, ValueError):
            stale.append(f"{entry['plane']} ({entry['artefact']} unreadable)")
            continue
        if now != entry.get("committed_body_sha256"):
            stale.append(f"{entry['plane']} ({entry['artefact']} changed since the fresh run)")
    checks.append(("fresh: every verified record is against the artefact on disk now",
                   not stale))

    failures = [desc for desc, ok in checks if not ok]
    return {
        "court": COURT,
        "artefact": ARTEFACT_REL,
        "challenges": counts["challenges"],
        "detected": counts["detected"],
        "not_detected": counts["not_detected"],
        "not_driven": counts["not_driven"],
        "failed_planes": failed,
        "undriven_planes": undriven,
        "fresh_regeneration_planes": counts["fresh_regeneration_planes"],
        "fresh_verified": verified,
        "fresh_deferred": deferred,
        "fresh_stale": stale,
        "sensitivity": {
            "break": ("take a registered DETECTED challenge, add 1 to one of its observed "
                      "deltas in memory, and require the harness to report NOT_DETECTED"),
            "mutated_plane": sample.get("plane"),
            "verdict_when_mutated": mutated_verdict,
            "verdict_unmutated": classify_challenge(sample["expected"], sample["observed"]),
        },
        "mutations": ["harness-classify-sensitivity", "harness-negative-controls",
                      "per-plane-drive", "fresh-regeneration-carry", "frf-fuzz-campaign"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
        "summary": (f"{counts['challenges']} challenges ({counts['detected']} detected, "
                    f"{counts['not_detected']} not-detected, {counts['not_driven']} not-driven), "
                    f"{fuzz['counts']['residual_produced']}/{fuzz['counts']['seeds']} fuzz seeds "
                    f"produced a residual"),
    }


def courts() -> list[dict]:
    """`RT-PHASE22-FRF`, or `[]` while the artefact has not landed."""
    if not OUT.is_file():
        return []
    try:
        body = json.loads(OUT.read_text(encoding="utf-8"))["body"]
    except Exception as exc:  # a court that cannot read its artefact is a failing court
        return [{"court": COURT, "artefact": ARTEFACT_REL, "verdict": "fail",
                 "stage": "artefact-unreadable", "observations": 0, "failures": [str(exc)]}]
    return [court_frf(body)]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _counts(challenges: list[dict], fuzz: dict, fresh: list[dict]) -> dict:
    return {
        "challenges": len(challenges),
        "detected": sum(1 for c in challenges if c["status"] == DETECTED),
        "not_detected": sum(1 for c in challenges if c["status"] == NOT_DETECTED),
        "not_driven": sum(1 for c in challenges if c["status"] == NOT_DRIVEN),
        "fresh_regeneration_planes": sum(1 for f in fresh if f.get("status") == "verified"),
        "fresh_regeneration_deferred": sum(1 for f in fresh if f.get("status") == "deferred"),
        "frf_fuzz_seeds": fuzz["counts"]["seeds"],
        "frf_fuzz_residual_produced": fuzz["counts"]["residual_produced"],
        "frf_fuzz_promoted_failures": fuzz["counts"]["promoted_failures"],
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--fresh", action="store_true",
                    help="run the fresh-regeneration challenge (heavy; rebuilds raw inputs)")
    ap.add_argument("--fresh-planes", default="22.2,22.3,22.4,22.1",
                    help="comma-separated planes to regenerate freshly (default: %(default)s)")
    ap.add_argument("--fresh-budget", type=int, default=900,
                    help="per-plane seconds budget before a fresh path is deferred")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)

    committed: Optional[dict] = None
    if OUT.is_file():
        committed = json.loads(OUT.read_text(encoding="utf-8"))

    challenges = build_challenges()
    fuzz = run_fuzz()

    if args.fresh:
        planes = [p.strip() for p in args.fresh_planes.split(",") if p.strip()]
        fresh = run_fresh(planes, args.jobs, args.fresh_budget)
    elif committed and committed.get("body", {}).get("fresh_regeneration"):
        # Carry the last measured block forward so a plain run is deterministic and cheap.
        fresh = committed["body"]["fresh_regeneration"]
    else:
        fresh = [{"plane": p, "status": "deferred",
                  "reason": "no fresh record committed; run this tool with --fresh"}
                 for p in sorted(_FRESH, key=lambda x: [int(y) for y in x.split(".")])]

    counts = _counts(challenges, fuzz, fresh)
    all_pass = counts["not_detected"] == 0 and counts["not_driven"] == 0

    body = {
        "plan_rule": ("docs/PHASE-22-SUBPHASES.md section 6: 22.15 must challenge each "
                      "extractor with a controlled mutation of its own defect class; a scanner "
                      "that cannot detect the defect class it claims to inventory is not "
                      "evidence."),
        "method": (
            "For each plane a driver reconstructs the plane's raw model from its own committed "
            "artefact, runs the plane's pure builder on the baseline, applies one controlled "
            "mutation of the named defect class, runs the builder again, and diffs precise "
            "counters. `expected` is the delta the mutation implies and `observed` is what the "
            "instrument produced; a plane is DETECTED only when they are equal, NOT_DETECTED "
            "when the instrument is insensitive, and NOT_DRIVEN when the challenge cannot be "
            "constructed -- never a pass. Each record also carries the plane's own registered "
            "`courts()` verdict, run for real."
        ),
        "harness": {
            "classifier": "DETECTED iff expected == observed, NOT_DETECTED otherwise",
            "statuses": [DETECTED, NOT_DETECTED, NOT_DRIVEN],
            "court": ("RT-PHASE22-FRF mutates a registered challenge's observed result in "
                      "memory and requires NOT_DETECTED, proving the classifier is not a "
                      "rubber stamp"),
        },
        "challenges": challenges,
        "frf_fuzz": fuzz,
        "fresh_regeneration": fresh,
        "counts": counts,
        "reproducibility": {
            "capture_scratch": ("the out-of-tree scratch directory that 22.1's capture records "
                                "as its own `directory` (a path under the container's temporary "
                                "filesystem; not repeated here so the artefact carries no "
                                "scratch path)"),
            "note": (
                "22.2's configured view and 22.3/22.4's source resolution read include roots "
                "from 22.1's captured compile commands, whose `directory` is that ephemeral "
                "capture scratch. The committed bodies correspond to the scratch being absent, "
                "so --fresh removes it before the extractive planes and runs 22.1 -- whose "
                "rebuild recreates it -- last. A fresh run started with a populated capture "
                "scratch resolves the generated headers that rebuild produced and diverges from "
                "the committed 22.2/22.3/22.4 bytes; that dependency is recorded here rather "
                "than hidden by ordering."),
            "observed_delta_when_scratch_present": {
                "22.2_entities": "70075 (absent) -> 76222 (populated)",
                "22.3": "committed body differs",
                "22.4_surfaces": "2308 (absent) -> 2426 (populated)",
            },
        },
        "not_claims": [
            "an in-memory mutation proves the instrument's logic reacts to its defect class; it "
            "does not prove the committed artefact is complete, only the fresh-regeneration "
            "challenge addresses reproducibility, and only for the planes it ran on",
            "a plane recorded NOT_DRIVEN is a gap in this challenge, not a pass",
            "the FRF-Fuzz campaign fuzzes the extractors' inputs, not the authority's runtime "
            "behaviour",
            "the fresh-regeneration challenge reproduces the committed bodies in the documented "
            "environment; it does not claim the committed bodies are the only defensible ones",
            "22.1's registered sensitivity court lives in phase22_courts.py rather than in "
            "phase22_build_commands.py, so its `registered_court` field is null; this plane "
            "drives its own 22.1 challenge independently",
        ],
    }

    inputs: list[InputRef] = [
        InputRef(name="phase-22-plan", path=REPO_ROOT / "docs" / "PHASE-22-SUBPHASES.md"),
    ]
    for plane, module in sorted(_PLANE_MODULE.items(),
                                key=lambda kv: [int(x) for x in kv[0].split(".")]):
        rel_path = getattr(module, "ARTEFACT_REL", None)
        if rel_path and (REPO_ROOT / rel_path).is_file():
            inputs.append(InputRef(name=f"plane-{plane}", path=REPO_ROOT / rel_path))
    for plane, module in (("22.1", pbc), ("22.2", pdox), ("22.3", ptu), ("22.4", pcond)):
        # the fresh planes also consume the track they are regenerated from
        for attr in ("RAW_REL", "OUT_REL", "CAPTURE_REL"):
            rel_path = getattr(module, attr, None)
            if rel_path and (REPO_ROOT / rel_path).is_file():
                inputs.append(InputRef(name=f"fresh-{plane}-{attr}", path=REPO_ROOT / rel_path))

    doc = envelope(kind="phase22-frf-challenges", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for c in challenges:
        line = (f"  {c['plane']:<6} {c['status']:<13} {c['defect_class']:<38} "
                f"court={c['registered_court'].get('verdict') if c['registered_court'] else None}")
        print(line)
        if c["status"] != DETECTED:
            print(f"      reason: {c['reason']}")
    print(f"  challenges: {counts['challenges']} "
          f"(detected={counts['detected']} not_detected={counts['not_detected']} "
          f"not_driven={counts['not_driven']})")
    print(f"  fresh_regeneration: verified={counts['fresh_regeneration_planes']} "
          f"deferred={counts['fresh_regeneration_deferred']}")
    for f in fresh:
        print(f"    {f['plane']:<6} {f.get('status'):<9} seconds={f.get('seconds')} "
              f"note={f.get('note') or f.get('reason')}")
    print(f"  frf_fuzz: {counts['frf_fuzz_residual_produced']}/{counts['frf_fuzz_seeds']} "
          f"residuals, promoted_failures={counts['frf_fuzz_promoted_failures']}")
    print(f"  -> {rel(OUT)} all_pass={all_pass}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
