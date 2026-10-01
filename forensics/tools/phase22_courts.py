#!/usr/bin/env python3
"""openssl-rs -- Phase 22 courts: the instruments' sensitivity challenges.

Phase 22's courts are not behavioural probes: the stratum adds no code to the crate, so there is
nothing to run both against the authority and against the candidate. What each Phase 22 court
must establish is that an *instrument* finds its own defect class. `docs/PHASE-22-SUBPHASES.md`
section 6: "A scanner that cannot detect the defect class it claims to inventory is not
evidence." A court that only asserted a file exists would pass on an empty file, so this runner
never does that.

`RT-PHASE22-BUILD-CAPTURE`
--------------------------
The first court is 22.1's. It exercises `forensics/tools/phase22_build_commands.py`'s own
`build_body`, on the real raw capture (`compile-commands.jsonl`) and on **controlled mutations
of that capture in memory**:

  * drop one `-D` from one translation unit -- the normalizer's `defines` and `args` for that
    unit must lose exactly that one element, and nothing else may move;
  * swap two `-I` options on one unit -- its `includes` order must follow, its `defines` must
    not, and nothing else may move;
  * append a synthetic translation unit -- `commands` and `distinct_sources` must rise by one;
  * append a synthetic build-time assembler probe (`-o /dev/null`) -- which is **not** a
    translation unit, so the normalizer must be completely insensitive to it.

The court FAILS if the normalizer ignores any of those. `observations` is the number of
assertions made; each mutation contributes several.

`RT-PHASE22-DOXYGEN`
--------------------
The second court is 22.2's. It exercises `forensics/tools/phase22_doxygen.py`'s own view-merge
and classification logic, on the committed `forensics/atlas/phase22/doxygen-entities.json` and on
controlled in-memory mutations of its rows:

  * round-trip: reconstruct the two per-view row sets from the artefact's own `entities`, re-derive
    the whole body (entities, references, the `lexical_only`/`configured_only` differences, every
    count) and require it to equal the committed artefact -- so the court judges the logic that
    built the artefact, not a stale copy of its output;
  * add a configured entity -- `entities`, `configured` and `configured_only` rise by one;
  * add a lexical-only entity -- `entities`, `lexical` and `lexical_only` rise by one;
  * clear one entity's `documented` flag -- `documented` falls by one and nothing else moves;
  * move one shared entity's line -- its two views stop joining, so `shared` falls by one while
    `entities`, `configured_only` and `lexical_only` each rise by one;
  * add one reference edge -- `reference_sources` and `reference_edges` rise by one.

It FAILS if the extractor is insensitive to any of those. What it does **not** claim is that the
Doxygen corpus is complete or that the committed XML matches the tree: the XML is a scratch
product and is not tracked, so no fresh-checkout re-derivation is possible, and `doxygen` absence
must never be read as surface absence (`docs/PHASE-22-SUBPHASES.md` section 6).

A court the plan gives a later subphase is named in `pending_courts` with that subphase and
printed on every run, so "not run yet" cannot be read as "passed" -- the contract Phase 8's
`PENDING_CORRECTNESS_COURTS` and every later activation established.

Output
------
    artifacts/phase22/COURTS.json

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
    envelope,
    rel,
    resolve_authority,
    write_json,
)

import phase22_build_commands as pbc  # noqa: E402
import phase22_doxygen as pdox  # noqa: E402

GENERATOR = "forensics/tools/phase22_courts.py"
OUT = REPO_ROOT / "artifacts" / "phase22" / "COURTS.json"
RAW = REPO_ROOT / pbc.RAW_REL
NORMALIZED = REPO_ROOT / pbc.OUT_REL
DOXYGEN_ARTEFACT = REPO_ROOT / pdox.OUT_REL

# The courts this stratum has landed, in the order the subphases land them.
COURTS = ["RT-PHASE22-BUILD-CAPTURE", "RT-PHASE22-DOXYGEN"]

# A court the plan gives a later subphase. Named here with the subphase and the instrument it will
# challenge, and printed on each run. The names follow the plan's own vocabulary; section 5 is
# where each artefact is named.
PENDING_COURTS: dict[str, str] = {
    "RT-PHASE22-TU-AST": "22.3 -- the every-translation-unit Clang AST and declaration/definition "
                         "graph (`tu-ast.json`), replayed from 22.1's captured invocations",
    "RT-PHASE22-CONDITIONAL": "22.4 -- the preprocessor and conditional-compilation graph "
                              "(`conditional-surface.json`)",
    "RT-PHASE22-GENEALOGY": "22.5 -- generated-source provenance (`generated-lineage.json`)",
    "RT-PHASE22-BINARY": "22.6 -- the object/archive/DSO/module graph "
                         "(`binary-reference-graph.json`)",
    "RT-PHASE22-DISPATCH": "22.7 -- the indirect dispatch, callback and registration graph "
                           "(`dispatch-graph.json`)",
    "RT-PHASE22-INSTALL": "22.8 -- the installed-distribution manifest (`install-manifest.json`)",
    "RT-PHASE22-CLI": "22.9 -- the CLI grammar, aliases and pseudo-command surface "
                      "(`cli-surface.json`)",
    "RT-PHASE22-CONFIG": "22.10 -- the configuration, environment and default-path surface "
                         "(`config-surface.json`)",
    "RT-PHASE22-POD": "22.11 -- the POD contract oracle and the POD<->runtime differential "
                      "(`pod-contract.json`)",
    "RT-PHASE22-RECONCILE": "22.12 -- the cross-plane reconciliation (`reconciliation.json`)",
    "RT-PHASE22-CROSSWALK": "22.13 -- the test/demo/fuzz semantic crosswalk "
                            "(`test-crosswalk.json`)",
    "RT-PHASE22-CLOSURE": "22.14 -- the external-root reachability closure "
                          "(`compatibility-closure.json`)",
    "RT-PHASE22-FRF": "22.15 -- the FRF challenges and FRF-Fuzz sensitivity campaigns "
                      "(`frf-challenges.json`)",
    "RT-PHASE22-GEMEL": "22.16 -- the Gemel checkpoint and regenerated ledgers "
                        "(`gemel-checkpoint.json`)",
    "RT-PHASE22-SEAL": "22.17 -- the Phase-22 seal (`docs/PHASE-22-ATLAS-SEAL.md`)",
}


def _first_unit_with(records: list[dict], predicate) -> int | None:
    for i, rec in enumerate(records):
        if pbc.is_translation_unit(rec) and predicate(rec.get("argv", [])):
            return i
    return None


def _by_key(body: dict) -> dict[tuple[str, str], dict]:
    return {(c["source"], c["output"]): c for c in body["commands"]}


def _drop_first(seq: list, item) -> list:
    out = list(seq)
    if item in out:
        out.remove(item)
    return out


def _unchanged(base: dict, new: dict, keys: set) -> bool:
    """Every command except those named by `keys` is byte-for-byte the same."""
    a, b = _by_key(base), _by_key(new)
    if set(a) != set(b):
        return False
    return all(a[k] == b[k] for k in a if k not in keys)


def _mutation_drop_define(records, base, producer, directory, checks) -> None:
    j = _first_unit_with(records, lambda argv: any(x.startswith("-D") for x in argv))
    if j is None:
        checks.append(("drop-define: a unit with a -D was found", False))
        return
    mutated = copy.deepcopy(records)
    argv = mutated[j]["argv"]
    token = next(x for x in argv if x.startswith("-D"))
    key = (mutated[j]["source"], mutated[j]["output"])
    base_map = _by_key(base)
    if key not in base_map:
        checks.append(("drop-define: baseline contains the mutated unit", False))
        return
    base_row = base_map[key]
    checks.append(("drop-define: baseline recorded the -D in defines",
                   token in base_row["defines"]))
    argv.remove(token)
    new = pbc.build_body(mutated, producer, directory)
    row = _by_key(new)[key]

    expected_defines = _drop_first(base_row["defines"], token)
    expected_args = _drop_first(base_row["args"], token)

    checks.append(("drop-define: command count unchanged", new["counts"]["commands"]
                   == base["counts"]["commands"]))
    checks.append((f"drop-define: {token} left the define list",
                   row["defines"] == expected_defines))
    checks.append(("drop-define: argv lost exactly that element", row["args"] == expected_args))
    checks.append(("drop-define: no other unit moved", _unchanged(base, new, {key})))


def _mutation_reorder_includes(records, base, producer, directory, checks) -> None:
    j = _first_unit_with(
        records, lambda argv: len([x for x in argv if x.startswith("-I")]) >= 2)
    if j is None:
        checks.append(("reorder-includes: a unit with two -I options was found", False))
        return
    mutated = copy.deepcopy(records)
    argv = mutated[j]["argv"]
    idx = [i for i, x in enumerate(argv) if x.startswith("-I")][:2]
    key = (mutated[j]["source"], mutated[j]["output"])
    base_map = _by_key(base)
    if key not in base_map:
        checks.append(("reorder-includes: baseline contains the mutated unit", False))
        return
    base_row = base_map[key]
    checks.append(("reorder-includes: baseline recorded two -I options",
                   len(base_row["includes"]) >= 2))
    argv[idx[0]], argv[idx[1]] = argv[idx[1]], argv[idx[0]]
    new = pbc.build_body(mutated, producer, directory)
    row = _by_key(new)[key]

    expected_includes = list(base_row["includes"])
    if len(expected_includes) >= 2:
        expected_includes[0], expected_includes[1] = expected_includes[1], expected_includes[0]

    checks.append(("reorder-includes: include order followed the swap",
                   row["includes"] == expected_includes))
    checks.append(("reorder-includes: argv changed", row["args"] != base_row["args"]))
    checks.append(("reorder-includes: defines untouched", row["defines"] == base_row["defines"]))
    checks.append(("reorder-includes: no other unit moved", _unchanged(base, new, {key})))


def _mutation_synthetic_unit(records, base, producer, directory, checks) -> None:
    source = "synthetic/phase22_probe_unit.c"
    mutated = copy.deepcopy(records)
    mutated.append({
        "record": "compile",
        "argv": ["-Iinclude", "-DOPENSSL_SYNTHETIC=1", "-c", "-o",
                 "synthetic/phase22_probe_unit.o", source],
        "directory": directory,
        "source": source,
        "output": "synthetic/phase22_probe_unit.o",
        "wrapper_version": base.get("wrapper_version"),
    })
    new = pbc.build_body(mutated, producer, directory)
    base_sources = {c["source"] for c in base["commands"]}
    new_sources = {c["source"] for c in new["commands"]}

    checks.append(("synthetic-unit: command count rose by one",
                   new["counts"]["commands"] == base["counts"]["commands"] + 1))
    checks.append(("synthetic-unit: distinct_sources rose by one",
                   new["counts"]["distinct_sources"] == base["counts"]["distinct_sources"] + 1))
    checks.append(("synthetic-unit: the unit is present", source in new_sources))
    checks.append(("synthetic-unit: every captured source survived",
                   base_sources <= new_sources))


def _mutation_assembler_probe(records, base, producer, directory, checks) -> None:
    """A build-time `-o /dev/null` assembler probe is not a translation unit: no effect."""
    mutated = copy.deepcopy(records)
    mutated.append({
        "record": "compile",
        "argv": ["-Wa,-v", "-c", "-o", "/dev/null", "-x", "assembler", "/dev/null"],
        "directory": directory,
        "source": None,
        "output": "/dev/null",
        "wrapper_version": base.get("wrapper_version"),
    })
    new = pbc.build_body(mutated, producer, directory)
    checks.append(("assembler-probe: counts unchanged", new["counts"] == base["counts"]))
    checks.append(("assembler-probe: command list unchanged", new["commands"] == base["commands"]))


def court_build_capture(records: list[dict], producer: str, directory: str | None) -> dict:
    checks: list[tuple[str, bool]] = []
    base = pbc.build_body(copy.deepcopy(records), producer, directory)

    checks.append(("baseline: the capture has translation units", base["counts"]["commands"] > 0))
    checks.append(("baseline: capture_method is execution-captured",
                   base["capture_method"] == "execution-captured"))

    _mutation_drop_define(records, base, producer, directory, checks)
    _mutation_reorder_includes(records, base, producer, directory, checks)
    _mutation_synthetic_unit(records, base, producer, directory, checks)
    _mutation_assembler_probe(records, base, producer, directory, checks)

    # The committed normalised artefact must be exactly what the logic produces from the raw log.
    if NORMALIZED.is_file():
        committed = json.loads(NORMALIZED.read_text(encoding="utf-8"))
        checks.append(("artefact: committed compile-commands.json body equals the normalizer's "
                       "output", committed.get("body") == base))
    else:
        checks.append((f"artefact: {rel(NORMALIZED)} exists", False))

    failures = [desc for desc, ok in checks if not ok]
    return {
        "court": "RT-PHASE22-BUILD-CAPTURE",
        "producer": producer,
        "raw_capture": rel(RAW),
        "captured_commands": base["counts"]["commands"],
        "distinct_sources": base["counts"]["distinct_sources"],
        "mutations": ["drop-define", "reorder-includes", "synthetic-unit", "assembler-probe"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def _identity(row: dict) -> list:
    return [row["kind"], row["name"], row["file"], row["line"]]


def _entities_by_identity(entities: list[dict]) -> dict[tuple, dict]:
    return {tuple(_identity(e)): e for e in entities}


def _edges_from_references(references: dict) -> list[dict]:
    """Rebuild the flat edge list the artefact's adjacency was collapsed from.

    The key is `kind|file|line|name`; file paths contain no `|` and the line is empty for an
    entity Doxygen gave no line. This is what lets the round-trip re-derive the adjacency from
    the committed artefact and compare, rather than trusting the stored copy.
    """
    out: list[dict] = []
    for key, slot in references.items():
        kind, file, line, name = key.split("|", 3)
        for rel in ("references", "referenced_by"):
            for target in slot.get(rel, []):
                out.append({"from_kind": kind, "from_file": file or None, "from_name": name,
                            "from_line": int(line) if line else None, "relation": rel,
                            "name": target})
    return out


def _mutation_add_entity(configured, lexical, edges, base, checks) -> None:
    synth = {"kind": "function", "name": "phase22_synthetic_probe",
             "file": "synthetic/phase22_probe.c", "line": 1, "brief": "",
             "is_static": True, "documented": False}
    new = pdox.build_body(configured + [synth], lexical, edges)
    checks.append(("add-entity: entities rose by one",
                   new["counts"]["entities"] == base["counts"]["entities"] + 1))
    checks.append(("add-entity: configured rose by one",
                   new["counts"]["configured"] == base["counts"]["configured"] + 1))
    checks.append(("add-entity: configured_only rose by one",
                   new["counts"]["configured_only"] == base["counts"]["configured_only"] + 1))
    row = _entities_by_identity(new["entities"]).get(tuple(_identity(synth)))
    checks.append(("add-entity: the unit is present and configured-only",
                   row is not None and row["views"] == ["configured"]))
    checks.append(("add-entity: nothing else moved",
                   _stable(base, new, {tuple(_identity(synth))})))


def _mutation_add_lexical_only(configured, lexical, edges, base, checks) -> None:
    synth = {"kind": "function", "name": "phase22_synthetic_lexical_probe",
             "file": "synthetic/phase22_probe.c", "line": 2, "brief": "",
             "is_static": False, "documented": False}
    new = pdox.build_body(configured, lexical + [synth], edges)
    checks.append(("add-lexical-only: entities rose by one",
                   new["counts"]["entities"] == base["counts"]["entities"] + 1))
    checks.append(("add-lexical-only: lexical_only rose by one",
                   new["counts"]["lexical_only"] == base["counts"]["lexical_only"] + 1))
    row = _entities_by_identity(new["entities"]).get(tuple(_identity(synth)))
    checks.append(("add-lexical-only: the unit is present and lexical-only",
                   row is not None and row["views"] == ["lexical"]))


def _mutation_clear_documented(configured, lexical, edges, base, checks) -> None:
    idx = next((i for i, e in enumerate(configured) if e["documented"]), None)
    if idx is None:
        checks.append(("clear-documented: a documented configured entity was found", False))
        return
    target = tuple(_identity(configured[idx]))
    mutated = copy.deepcopy(configured)
    mutated[idx]["documented"] = False
    new = pdox.build_body(mutated, lexical, edges)
    checks.append(("clear-documented: documented count fell by one",
                   new["counts"]["documented"] == base["counts"]["documented"] - 1))
    row = _entities_by_identity(new["entities"]).get(target)
    checks.append(("clear-documented: the entity now reads undocumented",
                   row is not None and not row["documented"]))
    checks.append(("clear-documented: entity count unchanged",
                   new["counts"]["entities"] == base["counts"]["entities"]))
    checks.append(("clear-documented: no other entity moved",
                   _stable(base, new, {target})))


def _mutation_move_location(configured, lexical, edges, base, checks) -> None:
    """Moving a shared entity's line breaks the identity join between the two views."""
    configured_keys = {tuple(_identity(e)) for e in configured}
    idx = next((i for i, e in enumerate(lexical) if tuple(_identity(e)) in configured_keys), None)
    if idx is None:
        checks.append(("move-location: a shared entity was found", False))
        return
    mutated = copy.deepcopy(lexical)
    old = tuple(_identity(mutated[idx]))
    mutated[idx]["line"] = (mutated[idx]["line"] or 0) + 10_000_000
    new = pdox.build_body(configured, mutated, edges)
    checks.append(("move-location: entities rose by one (the join split)",
                   new["counts"]["entities"] == base["counts"]["entities"] + 1))
    checks.append(("move-location: shared fell by one",
                   new["counts"]["shared"] == base["counts"]["shared"] - 1))
    checks.append(("move-location: lexical_only rose by one",
                   new["counts"]["lexical_only"] == base["counts"]["lexical_only"] + 1))
    checks.append(("move-location: configured_only rose by one",
                   new["counts"]["configured_only"] == base["counts"]["configured_only"] + 1))
    by_id = _entities_by_identity(new["entities"])
    old_row = by_id.get(old)
    new_row = by_id.get(tuple(_identity(mutated[idx])))
    checks.append(("move-location: the original key is now configured-only",
                   old_row is not None and old_row["views"] == ["configured"]))
    checks.append(("move-location: the moved key is now lexical-only",
                   new_row is not None and new_row["views"] == ["lexical"]))


def _mutation_add_edge(configured, lexical, edges, base, checks) -> None:
    edge = {"from_kind": "function", "from_name": "phase22_probe_fn",
            "from_file": "synthetic/phase22_probe.c", "from_line": 3,
            "relation": "references", "name": "EVP_DigestInit_ex"}
    new = pdox.build_body(configured, lexical, edges + [edge])
    checks.append(("add-edge: reference_sources rose by one",
                   new["counts"]["reference_sources"] == base["counts"]["reference_sources"] + 1))
    checks.append(("add-edge: reference_edges rose by one",
                   new["counts"]["reference_edges"] == base["counts"]["reference_edges"] + 1))
    key = "function|synthetic/phase22_probe.c|3|phase22_probe_fn"
    checks.append(("add-edge: the adjacency gained the source",
                   key in new["references"]
                   and new["references"][key]["references"] == ["EVP_DigestInit_ex"]))


def _stable(base: dict, new: dict, moved: set) -> bool:
    """Every entity except those named by `moved` is byte-for-byte identical.

    `moved` names the identities a mutation is *allowed* to add, remove or change; every other
    identity must appear on both sides with the same row.
    """
    a, b = _entities_by_identity(base["entities"]), _entities_by_identity(new["entities"])
    return all(a.get(k) == b.get(k) for k in (set(a) | set(b)) - moved)


def court_doxygen() -> dict:
    """`RT-PHASE22-DOXYGEN`: the Doxygen extractor's own view-merge and classification logic."""
    if not DOXYGEN_ARTEFACT.is_file():
        return {"court": "RT-PHASE22-DOXYGEN", "verdict": "fail",
                "stage": "doxygen-artefact-missing", "observations": 0,
                "failures": [f"artefact missing: {rel(DOXYGEN_ARTEFACT)}"]}

    body = json.loads(DOXYGEN_ARTEFACT.read_text(encoding="utf-8"))["body"]
    configured, lexical = pdox.split_views(copy.deepcopy(body["entities"]))
    edges = _edges_from_references(body["references"])
    checks: list[tuple[str, bool]] = []

    checks.append(("baseline: the artefact has entities", body["counts"]["entities"] > 0))
    checks.append(("baseline: the artefact has reference edges",
                   body["counts"]["reference_edges"] > 0))
    checks.append(("baseline: both views contributed entities",
                   len(configured) > 0 and len(lexical) > 0))

    # Round-trip: re-derive the whole body from the artefact's own rows. This is the freshness
    # gate a tracked raw input would give 22.1; here it ties the committed artefact to the logic
    # that produced it rather than to a copy of its output.
    rebuilt = pdox.build_body(copy.deepcopy(configured), copy.deepcopy(lexical), edges)
    checks.append(("round-trip: entities equal", rebuilt["entities"] == body["entities"]))
    checks.append(("round-trip: references equal", rebuilt["references"] == body["references"]))
    checks.append(("round-trip: lexical_only equal",
                   rebuilt["lexical_only"] == body["lexical_only"]))
    checks.append(("round-trip: configured_only equal",
                   rebuilt["configured_only"] == body["configured_only"]))
    checks.append(("round-trip: counts equal", rebuilt["counts"] == body["counts"]))

    base = pdox.build_body(copy.deepcopy(configured), copy.deepcopy(lexical), edges)
    _mutation_add_entity(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base, checks)
    _mutation_add_lexical_only(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base,
                               checks)
    _mutation_clear_documented(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base,
                               checks)
    _mutation_move_location(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base,
                            checks)
    _mutation_add_edge(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base, checks)

    failures = [desc for desc, ok in checks if not ok]
    return {
        "court": "RT-PHASE22-DOXYGEN",
        "artefact": rel(DOXYGEN_ARTEFACT),
        "doxygen_version": body.get("doxygen_version"),
        "entities": body["counts"]["entities"],
        "lexical_only": body["counts"]["lexical_only"],
        "reference_edges": body["counts"]["reference_edges"],
        "mutations": ["round-trip", "add-entity", "add-lexical-only", "clear-documented",
                      "move-location", "add-edge"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def _summary(r: dict) -> str:
    """A one-line, court-specific figure for the pass line.

    Courts differ, and a court that carries an explicit `summary` is preferred; the fallbacks below
    assemble one from whatever keys the record has, so a court that adds a figure does not have to
    edit this function to appear in the line. The fallbacks exist because a court printed as
    "35 observations; 35 observations" or "35838 entities, None lexical-only" is a court whose own
    line misrepresents it, and the pass line is evidence a reader reads first.
    """
    if "summary" in r:
        return str(r["summary"])
    parts: list[str] = []
    if "captured_commands" in r:
        parts.append(f"{r['captured_commands']} commands / {r.get('distinct_sources')} sources")
    if "entities" in r:
        parts.append(f"{r['entities']} entities")
        for key, label in (("lexical_only", "lexical-only"),
                           ("reference_edges", "reference edges")):
            if r.get(key) is not None:
                parts.append(f"{r[key]} {label}")
    if "objects" in r:
        parts.append(f"{r['objects']} objects")
    if "defined" in r:
        parts.append(f"{r['defined']} defined")
    if "relocation_edges" in r:
        parts.append(f"{r['relocation_edges']} relocation edges")
    if "entries" in r:
        parts.append(f"{r['entries']} entries")
    if "commands" in r and "captured_commands" not in r:
        parts.append(f"{r['commands']} commands")
    return ", ".join(parts) if parts else f"{r.get('observations', 0)} observations"


# ---------------------------------------------------------------------------------------------
# The plane courts, discovered rather than listed
# ---------------------------------------------------------------------------------------------
#
# Every Phase 22 plane owns exactly one file and exposes `courts()` from it, returning a list of
# court records once its artefact exists and `None` or `[]` while the plane has not landed. This
# runner discovers those modules instead of listing them, so a new plane adds a file and nothing
# else -- which is also what lets several planes be built at once without every one of them editing
# this runner. A module that raises on import is a hard failure and not a silently skipped court,
# because a court that cannot be loaded is not a court that passed.
#
# `ARTEFACT_REL` is optional and, when a module declares it, the artefact is content-addressed into
# this document's `inputs` the way the two built-in courts' artefacts already are.
PLANE_MODULES_EXCLUDED = {"phase22_courts.py", "phase22_obligations.py"}


def plane_modules() -> list:
    """Every `phase22_*.py` plane tool, imported."""
    import importlib

    out = []
    for path in sorted((REPO_ROOT / "forensics" / "tools").glob("phase22_*.py")):
        if path.name in PLANE_MODULES_EXCLUDED:
            continue
        out.append(importlib.import_module(path.stem))
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)

    records: list[dict] = []
    if RAW.is_file():
        records = pbc.load_raw(RAW)
    producer = pbc.read_producer(REPO_ROOT / pbc.BUILD_DIR_REL / "configdata.pm")

    if records:
        directory = next((r.get("directory") for r in records
                          if r.get("record") == "configure"), None)
        record = court_build_capture(records, producer, directory)
    else:
        record = {"court": "RT-PHASE22-BUILD-CAPTURE", "verdict": "fail",
                  "stage": "raw-capture-missing", "raw_capture": rel(RAW), "observations": 0,
                  "failures": [f"raw capture missing: {rel(RAW)}"]}

    planes = plane_modules()
    records_out = [record, court_doxygen()]
    for module in planes:
        fn = getattr(module, "courts", None)
        if callable(fn):
            records_out.extend(fn() or [])

    registered = {r["court"] for r in records_out}
    pending = {name: needs for name, needs in PENDING_COURTS.items() if name not in registered}
    passed = sum(1 for r in records_out if r["verdict"] == "pass")
    body = {
        "all_pass": passed == len(records_out),
        "authority": auth.id,
        "courts": records_out,
        "summary": {"total": len(records_out), "pass": passed,
                    "fail": len(records_out) - passed},
        "pending_courts": pending,
        "claim": (
            f"{len(records_out)} courts, each an FRF-style sensitivity challenge rather than a "
            "file existence check. `RT-PHASE22-BUILD-CAPTURE` runs "
            "`forensics/tools/phase22_build_commands.py`'s own `build_body` on the real raw "
            "capture and on controlled mutations of it in memory: dropping one `-D` removes "
            "exactly that element from the unit's `defines` and `args`; swapping two `-I` options "
            "reorders that unit's `includes` and leaves its `defines`; appending a synthetic unit "
            "raises `commands` and `distinct_sources` by one; and appending a build-time "
            "`-o /dev/null` assembler probe -- which is not a translation unit -- changes "
            "nothing. It also re-derives the committed "
            "`forensics/atlas/phase22/compile-commands.json` body from the raw log and requires "
            "they be equal. The other courts are each exposed by their own plane's module as "
            "`courts()` and discovered by this runner rather than listed here, and each carries "
            "the same obligation: it drives its instrument over the real artefact and over "
            "controlled mutations of it, and fails if the instrument is insensitive to its own "
            "defect class. No court claims the authority surface is complete: a plane's raw "
            "input is often a scratch product and is not tracked, so the courts tie committed "
            "artefacts to the logic that built them rather than to a fresh re-derivation, and "
            "Doxygen absence is never surface absence (docs/PHASE-22-SUBPHASES.md section 6). "
            "`pending_courts` names the courts the plan gives later subphases and every name is "
            "printed on each run, so 'not run yet' cannot be read as 'passed'."
        ),
    }

    inputs = [
        InputRef(name="raw-compile-commands", path=RAW),
        InputRef(name="normalized-compile-commands", path=NORMALIZED),
        InputRef(name="doxygen-entities", path=DOXYGEN_ARTEFACT),
        InputRef(name="phase-22-plan", path=REPO_ROOT / "docs" / "PHASE-22-SUBPHASES.md"),
    ]
    for module in planes:
        rel_ = getattr(module, "ARTEFACT_REL", None)
        if rel_ and (REPO_ROOT / rel_).exists():
            inputs.append(InputRef(name=module.__name__, path=REPO_ROOT / rel_))
    doc = envelope(kind="phase22-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records_out:
        if r["verdict"] == "pass":
            print(f"  {r['court']:<28} pass   ({r['observations']} observations; "
                  f"{_summary(r)})")
        else:
            print(f"  {r['court']:<28} FAIL   "
                  f"stage={r.get('stage', 'sensitivity')}")
            for f in r.get("failures", []):
                print(f"      {f}")
    for name, needs in pending.items():
        print(f"  {name:<28} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records_out)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
