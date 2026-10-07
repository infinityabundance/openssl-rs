#!/usr/bin/env python3
"""openssl-rs — the delta engine (Phase 23.6).

Phase 23 is the multitrack authority stratum. 23.4 typed the relationships between *releases*,
23.5 recorded what became of each public *entity* across the authorities that carry declaration
evidence. This module lands the third plane: the **semantic compatibility delta** between two
nodes — the added / removed / changed surface between them, computed mechanically from the
per-authority atlases and the entity lineage, in the direction the lineage edge names, and never
hand-listed.

What the delta is, and the substitution it refuses
---------------------------------------------------
The delta is *not* a source-line diff. A source diff answers "which bytes changed"; the delta
answers "which externally relevant obligation changed", and the two are different questions
(`docs/PARITY_MODEL.md` section 3). A source or implementation difference is **supporting
evidence** a delta row may cite, never the delta itself, so this engine never reads a patch, never
shells out to `diff`, and its rows are keyed by *entity* and *dimension* rather than by hunk.

Every row says what the brief requires: the entity-lineage id, the two authorities, the dimension,
`before`, `after`, the classification (`added` / `removed` / `changed`), the evidence, a
confidence and an adjudication. A dimension the available evidence cannot support is recorded
**absent with a reason**, never asserted (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 3.6).

Two layers of dimension, deliberately distinct
----------------------------------------------
  * the **fine dimension** is one of the brief's twenty-four delta dimensions
    (`DELTA_DIMENSIONS`): `api_presence`, `macro_value`, `public_layout`, `abi_symbol_version`,
    `deprecation_state`, ... It is what a *row* names.
  * the **coarse dimension** is the schema's closed compatibility vocabulary
    (`multitrack_schemas.COMPAT_DIMENSIONS`): `source_api`, `abi`, `semantic`, ... It is what a
    *receipt* names, and every fine dimension maps onto exactly one coarse dimension.

A receipt is therefore the coarse bucket (a `delta_receipt`, validated by
`multitrack_schemas.validate_delta_receipt`, with `added` / `removed` / `changed` row lists) and a
row is the fine, directed, evidence-bearing record.

Canonical edge deltas, and composition instead of a pairwise database
---------------------------------------------------------------------
A delta is stored on the **release-graph edge** it was computed over:
`forensics/deltas/<from_release>--<to_release>.json`. A longer path is **composed** from the edge
deltas it traverses (`compose`), and an important anchor may be cached, but no pairwise
combination is committed: the artefact set is the canonical edges, never their product. An edge
whose pair is not covered by both authorities' declaration planes is recorded uncovered with its
reason rather than guessed at.

Commands
--------
  authority_delta <a> <b> [--dimension D] [--json]     the direct edge delta between two nodes
  authority_delta <a> <b> --compose [--dimension D]    the delta composed along the lineage path
  authority_delta --write-all                          write every canonical edge delta
  authority_delta --edges                              list the committed edge deltas

`<a>` and `<b>` are a `release_id` (`openssl-3.6.3`) or an authority id
(`openssl-3.6.3-historical`).

Outputs
-------
  forensics/deltas/<from_release>--<to_release>.json   the canonical edge deltas

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
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

import multitrack_schemas as mts  # noqa: E402
import entity_lineage  # noqa: E402
import authority_graph  # noqa: E402

GENERATOR = "forensics/tools/authority_delta.py"
DELTAS = REPO_ROOT / "forensics" / "deltas"
CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
LINEAGE = REPO_ROOT / "forensics" / "authority-lineage.json"
AUTHORITY_NODES = REPO_ROOT / "forensics" / "authority-nodes.json"
ENTITY_LINEAGE = REPO_ROOT / "forensics" / "multitrack" / "entity-lineage.json"

DECLARATION_PLANES = entity_lineage.DECLARATION_PLANES
SYMBOL_LIBRARIES = entity_lineage.SYMBOL_LIBRARIES

# The fine delta dimensions the brief names, each mapped onto the coarse compatibility dimension a
# receipt is validated against. Keeping the two vocabularies apart is what lets a row be precise
# ("macro_value") while a receipt stays in the schema's closed compatibility vocabulary
# ("source_api").
DELTA_DIMENSIONS: dict[str, str] = {
    "api_presence": "source_api",
    "api_declaration": "source_api",
    "abi_symbol_presence": "abi",
    "abi_symbol_version": "abi",
    "prototype": "source_api",
    "public_layout": "abi",
    "macro_value": "source_api",
    "enum_value": "source_api",
    "typedef": "source_api",
    "ownership_contract": "ownership",
    "error_behavior": "error",
    "initialization_behavior": "concurrency",
    "threading_behavior": "concurrency",
    "provider_engine_architecture": "provider_registration",
    "algorithm_availability": "provider_registration",
    "default_behavior": "behavioural",
    "configuration": "cli_config",
    "cli": "cli_config",
    "environment": "cli_config",
    "filesystem_distribution": "cli_config",
    "protocol_behavior": "protocol",
    "security_policy": "semantic",
    "deprecation_state": "semantic",
    "documentation_claims": "semantic",
}

# The brief's order, preserved so the human form reads in the order the plan names the dimensions.
DIMENSION_ORDER: tuple[str, ...] = tuple(DELTA_DIMENSIONS)

# The dimensions the committed per-authority atlases carry evidence for, and the planes each reads.
# A dimension whose evidence plane is absent for either side is moved to the absent set with a
# reason rather than measured zero (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 3.6).
MEASURED_PLANES: dict[str, tuple[str, ...]] = {
    "api_presence": ("functions", "variables", "structs", "typedefs", "enums", "macros"),
    "api_declaration": ("functions", "variables", "structs", "typedefs", "enums", "macros"),
    "prototype": ("functions", "macros"),
    "public_layout": ("structs", "enums", "abi-layout"),
    "macro_value": ("macros",),
    "enum_value": ("enums",),
    "typedef": ("typedefs",),
    "abi_symbol_presence": ("symbols-libcrypto", "symbols-libssl"),
    "abi_symbol_version": ("symbols-libcrypto", "symbols-libssl"),
    "deprecation_state": ("functions", "symbols-libcrypto", "symbols-libssl"),
    "ownership_contract": ("ownership-obligations",),
    "provider_engine_architecture": ("provider-inventory",),
    "algorithm_availability": ("provider-inventory",),
    "configuration": ("configs",),
    "cli": ("cli-commands",),
}

# The dimensions the brief names but the committed atlases carry no structured evidence for. Each
# is recorded absent with the gap named, so an unmeasured dimension is a stated absence rather than
# a silently omitted one.
ABSENT_DIMENSIONS: dict[str, str] = {
    "error_behavior": (
        "no per-authority error-code or raise-site plane is committed; the error plane is "
        "crate-side (forensics/atlas/err-raise-sites.json), so the two authorities are not "
        "compared on it here"
    ),
    "initialization_behavior": (
        "no per-authority initialization / epoch observation plane is committed, so the two "
        "authorities are not compared on their initialization behaviour"
    ),
    "threading_behavior": (
        "no per-authority threading / locking observation plane is committed, so the two "
        "authorities are not compared on their threading behaviour"
    ),
    "default_behavior": (
        "no structured per-authority runtime-default plane is committed; a default is a runtime "
        "observation, not a declaration, and the behavioural probes that would measure it are a "
        "later subphase's (23.8)"
    ),
    "environment": (
        "no per-authority environment-variable plane is committed, so the two authorities are not "
        "compared on the environment they read"
    ),
    "filesystem_distribution": (
        "no per-authority installed-tree / distribution plane beyond the authority node's build "
        "hashes is committed; a build-product hash is not a compatibility delta"
    ),
    "protocol_behavior": (
        "no per-authority protocol-behaviour plane is committed; the corpus plane records test "
        "inputs, not behaviour, so the two authorities are not compared on TLS/DTLS/QUIC behaviour"
    ),
    "security_policy": (
        "no per-authority security-policy plane is committed; the security history is the "
        "separate observation record 23.14 lands, not a declaration plane"
    ),
    "documentation_claims": (
        "no structured per-authority documentation plane is committed; the atlases' prose is not "
        "compared as a delta"
    ),
}

# The identity body's content hash is taken over these keys, so the receipts, the stated absences
# and the counts are content-addressed together. The court imports this tuple and re-seals a
# mutated body with it, so a sensitivity control isolates the semantic check rather than the hash.
HASH_KEYS: tuple[str, ...] = (
    "edge", "measured_dimensions", "absent_dimensions", "receipts", "counts",
)

CANONICAL_KINDS = ("branch_fork", "chronological_successor", "maintenance_successor")

# The one adjudication carried by a change that is measured but is not an externally relevant
# compatibility obligation: an exported symbol's machine-code size. It is recorded because the
# atlas exposes it, and it is labelled so a reader never reads it as an ABI contract change.
IMPLEMENTATION_ADJUDICATION = (
    "recorded: the exported symbol's ELF symbol-table size changed; an implementation-size "
    "observation carried by the ABI symbol plane, not an ABI contract change"
)


def _read(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"authority-delta: {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def _body(path: Path) -> dict:
    doc = _read(path)
    return doc.get("body", doc)


def _plane_records(authority_id: str, plane: str) -> list[dict]:
    path = ATLAS / authority_id / f"{plane}.json"
    if not path.is_file():
        return []
    return _body(path).get("records") or []


def _render(value: object) -> str:
    """A stable string rendering of a before/after value."""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True)


def plane_available(authority_id: str, plane: str) -> bool:
    return (ATLAS / authority_id / f"{plane}.json").is_file()


def authority_index() -> dict[str, dict]:
    """`release_id -> {authority_id, claim}` for the built authorities, from the registry."""
    out: dict[str, dict] = {}
    for node in _body(AUTHORITY_NODES).get("nodes") or []:
        out[node["release_id"]] = {"authority_id": node["authority_id"], "claim": node.get("claim")}
    return out


def resolve_authority(name: str) -> dict:
    """Resolve a release id, a display version or an authority id to `{release_id, authority_id}`.

    A name that is already an authority id is mapped through the registry; a release id or display
    version is resolved through the release catalogue and then the registry. A name neither names
    a release nor an authority is a fatal rather than a silent empty delta.
    """
    index = authority_index()
    for release_id, entry in index.items():
        if name == release_id or name == entry["authority_id"]:
            return {"release_id": release_id, "authority_id": entry["authority_id"]}
    if (REPO_ROOT / "forensics" / "release-catalog.json").is_file():
        node = authority_graph.resolve(authority_graph.load_catalog(), name)
        release_id = node["release_id"]
        if release_id in index:
            return {"release_id": release_id, "authority_id": index[release_id]["authority_id"]}
    raise SystemExit(f"authority-delta: {name!r} names no built authority or catalogued release")


def canonical_edge(lineage: dict, a_release: str, b_release: str) -> dict | None:
    """The canonical lineage edge between two releases, in the sense it is read.

    `branch_fork`, `chronological_successor` and `maintenance_successor` are the canonical kinds
    (`authority_graph.canonical_kinds`); the edge's `direction` decides which endpoint is the
    predecessor. A pair with no canonical edge has no delta edge to store a delta on.
    """
    for edge in lineage["edges"]:
        if edge["kind"] not in CANONICAL_KINDS:
            continue
        if {edge["from_id"], edge["to_id"]} != {a_release, b_release}:
            continue
        pred, succ = authority_graph._read_pair(edge)
        return {**edge, "predecessor": pred, "successor": succ}
    return None


def direction_for(sense: str) -> str:
    """The coarse compatibility direction a lineage edge's sense reads as.

    `forward` reads the predecessor toward the successor, so the predecessor is the reference and
    the successor the subject: `reference_to_candidate`. `reverse` reads the other way.
    """
    return "reference_to_candidate" if sense == "forward" else "candidate_to_reference"


def _provenance(authority_id: str, plane: str) -> str:
    return rel(ATLAS / authority_id / f"{plane}.json")


# --------------------------------------------------------------------------------------------
# the row: one directed, dimension-specific, evidence-bearing change
# --------------------------------------------------------------------------------------------

def make_row(entity_id: str, entity_kind: str, classification: str, dimension: str, facet: str,
             before: object, after: object, from_id: str, to_id: str, sense: str,
             evidence: list[str], confidence: str, adjudication: str) -> dict:
    """One delta row, with every field the brief requires and a deterministic id."""
    return {
        "row_id": f"R-{from_id}-{to_id}-{entity_id}-{dimension}-{facet}",
        "entity_id": entity_id,
        "entity_kind": entity_kind,
        "classification": classification,
        "dimension": dimension,
        "facet": facet,
        "from_id": from_id,
        "to_id": to_id,
        "direction": direction_for(sense),
        "sense": sense,
        "before": before if before is None else _render(before),
        "after": after if after is None else _render(after),
        "evidence": sorted(set(evidence)),
        "confidence": confidence,
        "adjudication": adjudication,
    }


def _declaration_name_to_eid(declared: dict[str, dict]) -> dict[str, str]:
    """`name -> entity_id` for the **declaration** entities, excluding symbol-only exports.

    `entity_lineage.load_universe` folds an exported name with no declaration into the universe as
    a `symbol:NAME` entity. Those names are the symbol plane's business here, so they are excluded
    from the declaration mapping; a declared name keeps its `function:`/`macro:`/... id, which is
    the id a symbol-plane row about the same export attaches to.
    """
    return {rec["name"]: eid for eid, rec in declared.items() if rec["entity_kind"] != "symbol"}


# --------------------------------------------------------------------------------------------
# the declaration plane: presence, declaration form, prototype, layout, value, typedef
# --------------------------------------------------------------------------------------------

def load_side(authority_id: str) -> dict:
    """One authority's universe and its raw declaration records."""
    declared, symbols = entity_lineage.load_universe(authority_id)
    raw: dict[tuple[str, str], dict] = {}
    for plane, _kind in DECLARATION_PLANES:
        for rec in _plane_records(authority_id, plane):
            raw[(plane, rec["name"])] = rec
    return {"authority_id": authority_id, "declared": declared, "symbols": symbols, "raw": raw}


def _declared_rows(eid: str, from_decl: dict, to_decl: dict, from_side: dict, to_side: dict,
                   from_id: str, to_id: str, sense: str) -> list[dict]:
    """The rows a common declared entity's change yields, one per changed facet."""
    kind = from_decl["entity_kind"]
    name = from_decl["name"]
    fa, ta = from_id, to_id
    a_id, b_id = from_decl["identity"], to_decl["identity"]
    pa, pb = from_decl["properties"], to_decl["properties"]
    prov = sorted({from_decl["provenance"], to_decl["provenance"]})
    rows: list[dict] = []

    def add(dimension: str, facet: str, before: object, after: object, adj: str) -> None:
        rows.append(make_row(eid, kind, "changed", dimension, facet, before, after, fa, ta, sense,
                             prov, "established", adj))

    if kind == "function":
        if a_id[1:] != b_id[1:]:
            add("prototype", "prototype", a_id[1:], b_id[1:],
                "the declared prototype (return type and parameter types) changed")
        if a_id[0] != b_id[0]:
            add("api_declaration", "header", a_id[0], b_id[0],
                "the declaration moved header; the entity remains public")
        if pa.get("variadic") != pb.get("variadic"):
            add("prototype", "variadic", pa.get("variadic"), pb.get("variadic"),
                "the function became or ceased to be variadic")
        if pa.get("deprecated") != pb.get("deprecated"):
            add("deprecation_state", "deprecated", pa.get("deprecated"), pb.get("deprecated"),
                "the public deprecation state changed")
        raw_a = from_side["raw"].get((from_decl["plane"], name)) or {}
        raw_b = to_side["raw"].get((to_decl["plane"], name)) or {}
        form_a = {k: raw_a.get(k) for k in ("storage_class", "inline", "attributes")}
        form_b = {k: raw_b.get(k) for k in ("storage_class", "inline", "attributes")}
        if form_a != form_b:
            add("api_declaration", "declaration_form", form_a, form_b,
                "the declaration's storage class / inline / attribute form changed")
    elif kind == "variable":
        if a_id[1:] != b_id[1:]:
            add("api_declaration", "declared_type", a_id[1:], b_id[1:],
                "the variable's declared type or storage class changed")
        if a_id[0] != b_id[0]:
            add("api_declaration", "header", a_id[0], b_id[0], "the declaration moved header")
    elif kind == "typedef":
        if a_id[1:] != b_id[1:]:
            add("typedef", "underlying_type", a_id[1:], b_id[1:],
                "the typedef's underlying type changed")
        if a_id[0] != b_id[0]:
            add("api_declaration", "header", a_id[0], b_id[0], "the declaration moved header")
    elif kind == "struct":
        if a_id[1:] != b_id[1:]:
            add("public_layout", "layout", a_id[1:], b_id[1:],
                "the public struct's member layout changed")
        if pa.get("complete") != pb.get("complete"):
            add("public_layout", "completeness", pa.get("complete"), pb.get("complete"),
                "the struct became complete or opaque")
        if a_id[0] != b_id[0]:
            add("api_declaration", "header", a_id[0], b_id[0], "the declaration moved header")
    elif kind == "enum":
        if a_id[1:] != b_id[1:]:
            add("enum_value", "enumeration", a_id[1:], b_id[1:],
                "the enum's public constant values changed")
        if a_id[0] != b_id[0]:
            add("api_declaration", "header", a_id[0], b_id[0], "the declaration moved header")
    elif kind == "macro":
        if a_id[1] != b_id[1]:
            add("api_declaration", "macro_kind", a_id[1], b_id[1],
                "the macro changed between object-like and function-like")
        if a_id[2] != b_id[2]:
            add("prototype", "parameters", a_id[2], b_id[2],
                "the macro's parameter spelling changed")
        if a_id[0] != b_id[0]:
            add("api_declaration", "header", a_id[0], b_id[0],
                "the macro moved the headers it is defined in")
        if pa.get("value") != pb.get("value"):
            add("macro_value", "value", pa.get("value"), pb.get("value"),
                "the macro's public value changed")
    elif kind == "symbol":
        if a_id[2] != b_id[2]:
            add("abi_symbol_version", "version_node", a_id[2], b_id[2],
                "the exported symbol's version node changed")
        if a_id[1] != b_id[1]:
            add("abi_symbol_presence", "library", a_id[1], b_id[1],
                "the exported symbol moved library namespace")
    return rows


def declaration_rows(from_side: dict, to_side: dict, from_id: str, to_id: str,
                     sense: str) -> list[dict]:
    """The added / removed / changed declared surface between two authorities."""
    rows: list[dict] = []
    f_decl, t_decl = from_side["declared"], to_side["declared"]
    for eid in sorted(set(f_decl) | set(t_decl)):
        in_from, in_to = eid in f_decl, eid in t_decl
        kind = (f_decl.get(eid) or t_decl[eid])["entity_kind"]
        if kind == "symbol":
            continue  # the symbol plane owns the exported names, declaration or not
        if in_from and not in_to:
            rec = f_decl[eid]
            rows.append(make_row(
                eid, kind, "removed", "api_presence", "entity", None, rec["name"],
                from_id, to_id, sense, [rec["provenance"]], "established",
                f"`{rec['name']}` is public in the reference and absent from the subject"))
            continue
        if in_to and not in_from:
            rec = t_decl[eid]
            rows.append(make_row(
                eid, kind, "added", "api_presence", "entity", None, rec["name"],
                from_id, to_id, sense, [rec["provenance"]], "established",
                f"`{rec['name']}` is public in the subject and absent from the reference"))
            continue
        rows += _declared_rows(eid, f_decl[eid], t_decl[eid], from_side, to_side,
                               from_id, to_id, sense)
    return rows


# --------------------------------------------------------------------------------------------
# the symbol plane: presence, version node, machine-code size, deprecation
# --------------------------------------------------------------------------------------------

def symbol_rows(from_side: dict, to_side: dict, from_id: str, to_id: str, sense: str) -> list[dict]:
    """The exported-symbol surface between two authorities, keyed by the entity-lineage id.

    An exported name that a declaration already carries is attached to that declaration's entity id;
    a name exported without a declaration keeps its `symbol:` identity, so every row still names an
    id the entity lineage uses.
    """
    rows: list[dict] = []
    f_syms, t_syms = from_side["symbols"], to_side["symbols"]
    decl_names = {**_declaration_name_to_eid(from_side["declared"]),
                  **_declaration_name_to_eid(to_side["declared"])}
    for name in sorted(set(f_syms) | set(t_syms)):
        eid = decl_names.get(name) or f"symbol:{name}"
        in_from, in_to = name in f_syms, name in t_syms
        declared = name in decl_names
        if in_from and not in_to and not declared:
            rows.append(make_row(eid, "symbol", "removed", "abi_symbol_presence", "symbol",
                                 None, name, from_id, to_id, sense, [f_syms[name]["provenance"]],
                                 "established",
                                 f"`{name}` is exported by the reference and absent from the "
                                 f"subject"))
            continue
        if in_to and not in_from and not declared:
            rows.append(make_row(eid, "symbol", "added", "abi_symbol_presence", "symbol",
                                 None, name, from_id, to_id, sense, [t_syms[name]["provenance"]],
                                 "established",
                                 f"`{name}` is exported by the subject and absent from the "
                                 f"reference"))
            continue
        if not (in_from and in_to):
            continue
        fa, ta = f_syms[name], t_syms[name]
        prov = sorted({fa["provenance"], ta["provenance"]})
        if fa.get("version") != ta.get("version"):
            rows.append(make_row(
                eid, "symbol", "changed", "abi_symbol_version", "version_node",
                fa.get("version"), ta.get("version"), from_id, to_id, sense, prov, "established",
                "the exported symbol's version node changed"))
        if fa.get("lib") != ta.get("lib"):
            rows.append(make_row(
                eid, "symbol", "changed", "abi_symbol_presence", "library",
                fa.get("lib"), ta.get("lib"), from_id, to_id, sense, prov, "established",
                "the exported symbol moved library namespace"))
        if fa.get("size") is not None and ta.get("size") is not None \
                and fa["size"] != ta["size"]:
            rows.append(make_row(
                eid, "symbol", "changed", "abi_symbol_presence", "st_size",
                fa["size"], ta["size"], from_id, to_id, sense, prov, "established",
                IMPLEMENTATION_ADJUDICATION))
        if fa.get("deprecated") != ta.get("deprecated"):
            rows.append(make_row(
                eid, "symbol", "changed", "deprecation_state", "deprecated",
                fa.get("deprecated"), ta.get("deprecated"), from_id, to_id, sense, prov,
                "established", "the exported symbol's deprecation state changed"))
    return rows


# --------------------------------------------------------------------------------------------
# the plane dimensions: ownership, provider/ENGINE, algorithm availability, configuration, CLI
# --------------------------------------------------------------------------------------------

def _diff_plane(from_id: str, to_id: str, sense: str, dimension: str, from_authority: str,
                to_authority: str, entries_a: dict, entries_b: dict, prov: list[str],
                kind: str = "record") -> list[dict]:
    """A keyed-plane diff over two already-read mappings: added / removed / changed rows."""
    rows: list[dict] = []
    for k in sorted(set(entries_a) | set(entries_b), key=str):
        eid = f"{dimension}:{k}"
        if k in entries_a and k not in entries_b:
            rows.append(make_row(eid, kind, "removed", dimension, "record", entries_a[k], None,
                                 from_id, to_id, sense, prov, "established",
                                 f"{dimension} row `{k}` is present in the reference and absent "
                                 f"from the subject"))
        elif k in entries_b and k not in entries_a:
            rows.append(make_row(eid, kind, "added", dimension, "record", None, entries_b[k],
                                 from_id, to_id, sense, prov, "established",
                                 f"{dimension} row `{k}` is present in the subject and absent from "
                                 f"the reference"))
        elif entries_a[k] != entries_b[k]:
            rows.append(make_row(eid, kind, "changed", dimension, "record", entries_a[k],
                                 entries_b[k], from_id, to_id, sense, prov, "established",
                                 f"{dimension} row `{k}` changed between the reference and the "
                                 f"subject"))
    return rows


def _ownership_entries(authority: str) -> dict:
    return {r.get("symbol"): {k: v for k, v in r.items() if k != "line"}
            for r in _plane_records(authority, "ownership-obligations")}


def _provider_entries(authority: str) -> dict:
    """The published providers and the ENGINE architecture entries, as one provider/ENGINE plane.

    The provider's own `build info` field is the authority's version stamp, not its architecture, so
    it is normalised out exactly as the entity lineage normalises the authority-scoped install
    prefix: a version stamp is evidence, never an architecture change.
    """
    info = _body(ATLAS / authority / "provider-inventory.json")
    out = {p.get("name"): {k: v for k, v in (p.get("fields") or {}).items() if k != "build info"}
           for p in info.get("providers") or []}
    engines = (info.get("algorithm_classes") or {}).get("engines") or {}
    out["#engines"] = sorted(e.get("name") if isinstance(e, dict) else e
                             for e in (engines.get("entries") or []))
    return out


def _algorithm_entries(authority: str) -> dict:
    info = _body(ATLAS / authority / "provider-inventory.json")
    classes = info.get("algorithm_classes") or {}
    return {cls: sorted(e if isinstance(e, str) else e.get("name")
                        for e in (classes.get(cls) or {}).get("entries") or [])
            for cls in classes}


def _config_entries(authority: str) -> dict:
    body = _body(ATLAS / authority / "configs.json")
    return {Path(f.get("path", "")).name: (f.get("sha256"), f.get("size_bytes"),
                                            f.get("template"))
            for f in body.get("config_files") or []}


def _cli_entries(authority: str) -> dict:
    body = _body(ATLAS / authority / "cli-commands.json")
    return {c.get("name"): c.get("option_listing") for c in body.get("commands") or []}


def plane_dimension_rows(from_id: str, to_id: str, sense: str, from_authority: str,
                         to_authority: str, measured: set[str]) -> list[dict]:
    """The rows the non-declaration atlas planes yield, one derivation per dimension."""
    rows: list[dict] = []
    derivations = {
        "ownership_contract": ("ownership-obligations", _ownership_entries, "obligation"),
        "provider_engine_architecture": ("provider-inventory", _provider_entries, "provider"),
        "algorithm_availability": ("provider-inventory", _algorithm_entries, "algorithm"),
        "configuration": ("configs", _config_entries, "config_file"),
        "cli": ("cli-commands", _cli_entries, "command"),
    }
    for dimension, (plane, reader, kind) in derivations.items():
        if dimension not in measured:
            continue
        prov = [_provenance(from_authority, plane), _provenance(to_authority, plane)]
        rows += _diff_plane(from_id, to_id, sense, dimension, from_authority, to_authority,
                            reader(from_authority), reader(to_authority), prov, kind)
    return rows


# --------------------------------------------------------------------------------------------
# the whole edge delta: rows, receipts, the measured / absent split, counts
# --------------------------------------------------------------------------------------------

def measured_dimensions(from_authority: str, to_authority: str) -> tuple[set[str], dict[str, str]]:
    """`(measured, absent)` for a pair, decided by whether each dimension's evidence is committed.

    A dimension is measured only when **both** authorities carry every plane it reads; otherwise it
    is absent with the plane that is missing named, so an unmeasured dimension is never a silent
    zero.
    """
    measured: set[str] = set()
    absent: dict[str, str] = dict(ABSENT_DIMENSIONS)
    for dim, planes in MEASURED_PLANES.items():
        missing = [p for p in planes
                   if not plane_available(from_authority, p) or not plane_available(to_authority, p)]
        if missing:
            absent[dim] = (
                f"the evidence plane(s) {missing} are not committed for both authorities, so the "
                f"two nodes cannot be compared on this dimension")
        else:
            measured.add(dim)
    return measured, absent


def recompute_rows(from_authority: str, to_authority: str, sense: str = "forward",
                   from_id: str | None = None, to_id: str | None = None) -> list[dict]:
    """Every delta row the committed atlases and entity lineage support, deterministically.

    This is the court's independent predicate: it re-derives the rows through the same identity
    shapes the entity lineage uses, so a committed row that disagrees with the atlases is a finding
    rather than a restatement of the row.
    """
    from_id = from_id or from_authority
    to_id = to_id or to_authority
    measured, _absent = measured_dimensions(from_authority, to_authority)
    from_side = load_side(from_authority)
    to_side = load_side(to_authority)
    rows = declaration_rows(from_side, to_side, from_id, to_id, sense)
    rows += symbol_rows(from_side, to_side, from_id, to_id, sense)
    rows += plane_dimension_rows(from_id, to_id, sense, from_authority, to_authority, measured)
    return rows


def receipts_from_rows(rows: list[dict], from_id: str, to_id: str, sense: str,
                       measured: set[str], absent: dict[str, str]) -> list[dict]:
    """Group rows into one `delta_receipt` per coarse dimension, each schema-validated.

    A receipt with an empty axis still carries its evidence, so a dimension that was measured and
    found unchanged is a record rather than an omission.
    """
    by_dimension: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_dimension[row["dimension"]].append(row)
    evidence_by_coarse: dict[str, set[str]] = defaultdict(set)
    for dim in sorted(measured):
        for plane in MEASURED_PLANES.get(dim, ()):
            for authority in (from_id, to_id):
                path = ATLAS / authority / f"{plane}.json"
                if path.is_file():
                    evidence_by_coarse[DELTA_DIMENSIONS[dim]].add(rel(path))
    receipts: list[dict] = []
    for coarse in sorted(set(DELTA_DIMENSIONS[d] for d in measured)):
        added, removed, changed = [], [], []
        for dim in DIMENSIONS_FOR_COARSE.get(coarse, ()):
            for row in sorted(by_dimension.get(dim, []), key=lambda r: (r["row_id"])):
                {"added": added, "removed": removed, "changed": changed}[row["classification"]] \
                    .append(row)
        receipt = {
            "receipt_id": f"D-{from_id}-{to_id}-{coarse}",
            "from_id": from_id,
            "to_id": to_id,
            "dimension": coarse,
            "direction": direction_for(sense),
            "sense": sense,
            "added": added,
            "removed": removed,
            "changed": changed,
            "evidence": sorted(evidence_by_coarse.get(coarse) or []),
        }
        problems = mts.validate_delta_receipt(receipt)
        if problems:
            raise SystemExit(f"authority-delta: a receipt failed delta_receipt: {problems}")
        receipts.append(receipt)
    return receipts


# `coarse -> the fine dimensions that bucket into it`, derived from `DELTA_DIMENSIONS`, so the two
# vocabularies cannot drift.
DIMENSIONS_FOR_COARSE: dict[str, tuple[str, ...]] = {}
for _dim, _coarse in DELTA_DIMENSIONS.items():
    DIMENSIONS_FOR_COARSE[_coarse] = tuple(
        sorted({*DIMENSIONS_FOR_COARSE.get(_coarse, ()), _dim})
    )
del _dim, _coarse


def counts_of(rows: list[dict]) -> dict:
    """The added / removed / changed counts, overall and per fine dimension."""
    overall = {"added": 0, "removed": 0, "changed": 0}
    by_dimension: dict[str, dict[str, int]] = {}
    for row in rows:
        overall[row["classification"]] += 1
        bucket = by_dimension.setdefault(
            row["dimension"], {"added": 0, "removed": 0, "changed": 0})
        bucket[row["classification"]] += 1
    return {
        **overall,
        "by_dimension": {k: by_dimension[k] for k in sorted(by_dimension)},
    }


def edge_meta(edge: dict, from_release: str, to_release: str) -> dict:
    """The edge a delta is stored on, in the sense it is read."""
    return {
        "edge_id": edge["edge_id"],
        "kind": edge["kind"],
        "from_release": edge["predecessor"],
        "to_release": edge["successor"],
        "from_id": edge["predecessor"],
        "to_id": edge["successor"],
        "direction": edge.get("direction", "forward"),
        "requested_from": from_release,
        "requested_to": to_release,
    }


def build_body(from_authority: str, to_authority: str, sense: str, edge: dict,
               from_release: str, to_release: str) -> dict:
    """The canonical body of one edge delta."""
    from_id, to_id = (from_authority, to_authority) if sense == "forward" \
        else (to_authority, from_authority)
    measured, absent = measured_dimensions(from_authority, to_authority)
    rows = recompute_rows(from_authority, to_authority, sense=sense, from_id=from_id, to_id=to_id)
    receipts = receipts_from_rows(rows, from_id, to_id, sense, measured, absent)
    body = {
        "edge": edge_meta(edge, from_release, to_release),
        "from_id": from_id,
        "to_id": to_id,
        "from_authority": from_authority,
        "to_authority": to_authority,
        "from_release": from_release,
        "to_release": to_release,
        "direction": direction_for(sense),
        "sense": sense,
        "dimensions": list(DIMENSION_ORDER),
        "measured_dimensions": sorted(measured),
        "absent_dimensions": {k: absent[k] for k in sorted(absent)},
        "receipts": receipts,
        "counts": counts_of(rows),
    }
    body["content_hash"] = content_hash({k: body.get(k) for k in HASH_KEYS})
    return body


def edge_filename(from_release: str, to_release: str) -> str:
    return f"{from_release}--{to_release}.json"


def delta_uncovered(from_release: str, to_release: str, reason: str) -> dict:
    """A requested edge the atlases cannot support: recorded, never asserted."""
    return {
        "edge": {"from_release": from_release, "to_release": to_release},
        "covered": False,
        "reason": reason,
        "receipts": [],
        "absent_dimensions": {k: ABSENT_DIMENSIONS[k] for k in sorted(ABSENT_DIMENSIONS)},
    }


def direct_delta(a_name: str, b_name: str) -> dict:
    """The direct edge delta between two named nodes, or an uncovered record with its reason.

    The delta is read in the direction the lineage edge names: the edge's own `direction` decides
    which endpoint is the predecessor, so a request naming the pair in either order returns the
    same canonical orientation. A pair with no canonical edge, or with an authority that carries no
    declaration plane, is recorded uncovered rather than guessed at.
    """
    lineage = authority_graph.load_lineage()
    a = resolve_authority(a_name)
    b = resolve_authority(b_name)
    edge = canonical_edge(lineage, a["release_id"], b["release_id"])
    if edge is None:
        return delta_uncovered(
            a["release_id"], b["release_id"],
            f"no canonical lineage edge joins {a['release_id']} and {b['release_id']}")
    from_release, to_release = edge["predecessor"], edge["successor"]
    index = authority_index()
    from_auth = index[from_release]["authority_id"]
    to_auth = index[to_release]["authority_id"]
    if not (entity_lineage.has_declaration_planes(from_auth)
            and entity_lineage.has_declaration_planes(to_auth)):
        return delta_uncovered(
            from_release, to_release,
            f"at least one authority ({from_auth} / {to_auth}) carries no committed declaration "
            f"plane, so no entity identity can be established and the delta is recorded uncovered "
            f"rather than guessed at")
    body = build_body(from_auth, to_auth, "forward", edge, from_release, to_release)
    body["covered"] = True
    body["requested_from"] = a["release_id"]
    body["requested_to"] = b["release_id"]
    return body


# --------------------------------------------------------------------------------------------
# composition: a path delta from the edge deltas it traverses
# --------------------------------------------------------------------------------------------

def _invert_body(body: dict) -> dict:
    """The body read in the opposite sense: added and removed swap, before and after swap."""
    out = json.loads(json.dumps(body))
    out["sense"] = "reverse" if body.get("sense") == "forward" else "forward"
    out["direction"] = direction_for(out["sense"])
    for receipt in out.get("receipts") or []:
        receipt["sense"] = out["sense"]
        receipt["direction"] = out["direction"]
        receipt["added"], receipt["removed"] = receipt.get("removed", []), receipt.get("added", [])
        for row in (receipt.get("added") or []) + (receipt.get("changed") or []):
            row["sense"] = out["sense"]
            row["direction"] = out["direction"]
            row["before"], row["after"] = row.get("after"), row.get("before")
        for row in receipt.get("changed") or []:
            row["classification"] = "changed"
    return out


def compose_rows(row_lists: list[list[dict]]) -> list[dict]:
    """Compose ordered per-edge row lists into the longer-path rows.

    An entity/dimension/facet key is followed along the path: a key absent at the start and present
    at the end is `added`, present then absent is `removed`, and present throughout with a changed
    value is `changed`. A key added and later removed cancels to nothing, so the composition never
    reports a transient that did not survive the path.
    """
    state: dict[tuple, dict] = {}
    for rows in row_lists:
        for row in rows:
            key = (row["entity_id"], row["dimension"], row["facet"])
            st = state.get(key)
            if st is None:
                st = {
                    "start_present": row["classification"] != "added",
                    "present": row["classification"] != "removed",
                    "start_value": row["before"] if row["classification"] != "added" else None,
                    "value": row["after"] if row["classification"] != "removed" else None,
                    "template": row,
                    "evidence": set(row["evidence"]),
                }
                state[key] = st
                continue
            st["evidence"] |= set(row["evidence"])
            if row["classification"] == "added":
                st["present"] = True
                st["value"] = row["after"]
            elif row["classification"] == "removed":
                st["present"] = False
                st["value"] = None
            else:  # changed
                if st["start_value"] is None and st["start_present"]:
                    st["start_value"] = row["before"]
                st["value"] = row["after"]
    out: list[dict] = []
    for key, st in state.items():
        template = dict(st["template"])
        if st["start_present"] and st["present"]:
            if st["start_value"] == st["value"]:
                continue
            template["classification"] = "changed"
            template["before"], template["after"] = st["start_value"], st["value"]
        elif not st["start_present"] and st["present"]:
            template["classification"] = "added"
            template["before"], template["after"] = None, st["value"]
        elif st["start_present"] and not st["present"]:
            template["classification"] = "removed"
            template["before"], template["after"] = st["start_value"], None
        else:
            continue
        template["evidence"] = sorted(st["evidence"])
        template["adjudication"] = (
            "composed along the lineage path from the edge deltas it traverses")
        out.append(template)
    return sorted(out, key=lambda r: (r["entity_id"], r["dimension"], r["facet"]))


def committed_edges() -> dict[tuple[str, str], dict]:
    """`(from_release, to_release) -> body` for every committed canonical edge delta."""
    out: dict[tuple[str, str], dict] = {}
    if not DELTAS.is_dir():
        return out
    for path in sorted(DELTAS.glob("*.json")):
        body = _body(path)
        edge = body.get("edge") or {}
        key = (edge.get("from_release"), edge.get("to_release"))
        if all(key):
            out[key] = body
    return out


def compose_path(a_name: str, b_name: str) -> dict:
    """Compose the delta along the canonical lineage path between two releases.

    Each traversal step is served by the committed edge delta for its pair; a step with no committed
    delta is recorded as a gap, and only the covered steps contribute rows. The result equals the
    composition of the edge deltas it traversed, by construction and by the court's check.
    """
    catalog = authority_graph.load_catalog()
    lineage = authority_graph.load_lineage()
    a = _release_id(catalog, a_name)
    b = _release_id(catalog, b_name)
    path = authority_graph.path_between(catalog, lineage, a, b)
    committed = committed_edges()
    index = authority_index()
    steps: list[dict] = []
    row_lists: list[list[dict]] = []
    if not path.get("found"):
        return {"from_release": a, "to_release": b, "found": False, "steps": [],
                "counts": counts_of([]), "receipts": []}
    for step in path["steps"]:
        pred, succ = step["from_id"], step["to_id"]
        body = committed.get((pred, succ))
        if body is None:
            reason = (
                "the pair is not a committed canonical edge delta; it is recorded as a gap rather "
                "than recomputed pairwise (docs/PHASE-23-MULTITRACK-SUBPHASES.md section 3.6)")
            authority = index.get(succ, {}).get("authority_id")
            if authority and not entity_lineage.has_declaration_planes(authority):
                reason = (f"the successor authority {authority} carries no committed declaration "
                          f"plane, so the edge has no delta")
            steps.append({"from_id": pred, "to_id": succ, "kind": step["kind"],
                          "read": step["read"], "covered": False, "reason": reason})
            continue
        if step["read"] == "reverse":
            body = _invert_body(body)
        rows = [r for rc in body["receipts"] for axis in ("added", "removed", "changed")
                for r in rc[axis]]
        row_lists.append(rows)
        steps.append({"from_id": pred, "to_id": succ, "kind": step["kind"],
                      "read": step["read"], "covered": True,
                      "dimensions": sorted({r["dimension"] for r in rows})})
    composed_rows = compose_rows(row_lists)
    composed = {
        "found": True,
        "from_release": a,
        "to_release": b,
        "from_id": a,
        "to_id": b,
        "from_authority": index.get(a, {}).get("authority_id"),
        "to_authority": index.get(b, {}).get("authority_id"),
        "direction": "reference_to_candidate",
        "sense": "forward",
        "steps": steps,
        "counts": counts_of(composed_rows),
        "receipts": _composed_receipts(composed_rows, a, b),
    }
    return composed


def _composed_receipts(rows: list[dict], from_id: str, to_id: str) -> list[dict]:
    """Receipts for a composed path, grouped by coarse dimension like a direct edge."""
    by_dimension: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_dimension[row["dimension"]].append(row)
    receipts: list[dict] = []
    for coarse in sorted({DELTA_DIMENSIONS[r["dimension"]] for r in rows}):
        added, removed, changed = [], [], []
        for dim in DIMENSIONS_FOR_COARSE.get(coarse, ()):
            for row in sorted(by_dimension.get(dim, []), key=lambda r: r["row_id"]):
                {"added": added, "removed": removed, "changed": changed}[row["classification"]] \
                    .append(row)
        receipts.append({
            "receipt_id": f"C-{from_id}-{to_id}-{coarse}",
            "from_id": from_id, "to_id": to_id, "dimension": coarse,
            "direction": "reference_to_candidate", "sense": "forward",
            "added": added, "removed": removed, "changed": changed,
            "evidence": sorted({e for r in added + removed + changed for e in r["evidence"]}),
        })
    return receipts


def filter_rows(body: dict, dimension: str) -> list[dict]:
    return [r for rc in body.get("receipts") or []
            for axis in ("added", "removed", "changed") for r in rc[axis]
            if r["dimension"] == dimension]


def rows_of(body: dict) -> list[dict]:
    """Every row of a delta body, across all receipts and axes."""
    return [r for rc in body.get("receipts") or []
            for axis in ("added", "removed", "changed") for r in rc[axis]]


def _release_id(catalog: dict, name: str) -> str:
    """A release id from a display version / release id, or from an authority id."""
    try:
        return authority_graph.resolve(catalog, name)["release_id"]
    except SystemExit:
        return resolve_authority(name)["release_id"]


# --------------------------------------------------------------------------------------------
# writing the canonical edges
# --------------------------------------------------------------------------------------------

def canonical_edges_to_write() -> list[dict]:
    """One entry per canonical lineage edge whose two authorities both carry declaration planes."""
    lineage = authority_graph.load_lineage()
    index = authority_index()
    out: list[dict] = []
    for edge in lineage["edges"]:
        if edge["kind"] not in CANONICAL_KINDS:
            continue
        pred, succ = authority_graph._read_pair(edge)
        a, b = index.get(pred), index.get(succ)
        if not a or not b:
            continue
        if not (entity_lineage.has_declaration_planes(a["authority_id"])
                and entity_lineage.has_declaration_planes(b["authority_id"])):
            continue
        out.append({"edge": {**edge, "predecessor": pred, "successor": succ},
                    "from_release": pred, "to_release": succ,
                    "from_authority": a["authority_id"], "to_authority": b["authority_id"]})
    return out


def write_all() -> list[Path]:
    """Write every canonical edge delta, deterministically, and return the paths written."""
    written: list[Path] = []
    for entry in canonical_edges_to_write():
        body = build_body(entry["from_authority"], entry["to_authority"], "forward",
                          entry["edge"], entry["from_release"], entry["to_release"])
        body["covered"] = True
        inputs = [
            InputRef(name="release-catalog", path=CATALOG),
            InputRef(name="authority-lineage", path=LINEAGE),
            InputRef(name="authority-nodes", path=AUTHORITY_NODES),
            InputRef(name="entity-lineage", path=ENTITY_LINEAGE),
        ]
        for plane, _kind in DECLARATION_PLANES:
            for authority in (entry["from_authority"], entry["to_authority"]):
                inputs.append(InputRef(name=f"{authority}/{plane}",
                                       path=ATLAS / authority / f"{plane}.json"))
        for lib in SYMBOL_LIBRARIES:
            for authority in (entry["from_authority"], entry["to_authority"]):
                inputs.append(InputRef(name=f"{authority}/symbols-{lib}",
                                       path=ATLAS / authority / f"symbols-{lib}.json"))
        for plane in ("ownership-obligations", "provider-inventory", "configs", "cli-commands"):
            for authority in (entry["from_authority"], entry["to_authority"]):
                path = ATLAS / authority / f"{plane}.json"
                if path.is_file():
                    inputs.append(InputRef(name=f"{authority}/{plane}", path=path))
        doc = envelope(kind="delta-receipts", generator=GENERATOR, inputs=inputs, body=body)
        out = DELTAS / edge_filename(entry["from_release"], entry["to_release"])
        write_json(out, doc)
        written.append(out)
    return written


# --------------------------------------------------------------------------------------------
# the human form
# --------------------------------------------------------------------------------------------

def _print_body(body: dict, dimension: str | None) -> None:
    edge = body.get("edge") or {}
    if body.get("covered") is False:
        print(f"{edge.get('from_release')} -> {edge.get('to_release')}: UNCOVERED -- "
              f"{body.get('reason')}")
        return
    print(f"delta {body['from_id']} -> {body['to_id']}  "
          f"(edge {edge.get('edge_id')} [{edge.get('kind')}], sense={body['sense']})")
    counts = body["counts"]
    absent = body.get("absent_dimensions") or {}
    dims = [dimension] if dimension else [d for d in DIMENSION_ORDER if d not in absent]
    for dim in dims:
        bucket = counts["by_dimension"].get(dim, {"added": 0, "removed": 0, "changed": 0})
        if dim in absent:
            print(f"  {dim:<28} ABSENT   {absent[dim]}")
        else:
            print(f"  {dim:<28} +{bucket['added']} -{bucket['removed']} ~{bucket['changed']}")
    print(f"  total +{counts['added']} -{counts['removed']} ~{counts['changed']}  "
          f"({len(body['receipts'])} receipt(s); {len(absent)} dimension(s) absent: "
          f"{', '.join(sorted(absent))})")


def _print_composed(composed: dict, dimension: str | None) -> None:
    if not composed.get("found"):
        print(f"{composed['from_release']} -> {composed['to_release']}: no canonical path")
        return
    print(f"composed {composed['from_release']} -> {composed['to_release']}")
    for step in composed["steps"]:
        status = "covered" if step["covered"] else "GAP"
        print(f"  {step['from_id']} -> {step['to_id']} [{step['kind']}] read {step['read']}: "
              f"{status}" + ("" if step["covered"] else f" -- {step['reason']}"))
    counts = composed["counts"]
    dims = [dimension] if dimension else list(DIMENSION_ORDER)
    for dim in dims:
        bucket = counts["by_dimension"].get(dim, {"added": 0, "removed": 0, "changed": 0})
        print(f"  {dim:<28} +{bucket['added']} -{bucket['removed']} ~{bucket['changed']}")
    print(f"  total +{counts['added']} -{counts['removed']} ~{counts['changed']}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("a", nargs="?")
    ap.add_argument("b", nargs="?")
    ap.add_argument("--compose", action="store_true",
                    help="compose the delta along the canonical lineage path between a and b")
    ap.add_argument("--dimension", default=None,
                    help=f"filter to one of: {', '.join(DIMENSION_ORDER)}")
    ap.add_argument("--json", action="store_true", help="emit the authoritative JSON")
    ap.add_argument("--write-all", action="store_true",
                    help="write every canonical edge delta and exit")
    ap.add_argument("--edges", action="store_true", help="list the committed edge deltas")
    args = ap.parse_args(argv)

    if args.dimension is not None and args.dimension not in DELTA_DIMENSIONS:
        raise SystemExit(f"authority-delta: no such dimension {args.dimension!r}; "
                         f"known: {', '.join(DIMENSION_ORDER)}")

    # The generator form: a bare invocation (no nodes, no --edges) writes every canonical edge
    # delta, so `evidence_determinism.py` regenerates the artefact set with no arguments exactly as
    # it does for every other generator.
    if args.write_all or (not args.a and not args.b and not args.edges):
        written = write_all()
        for path in written:
            print(f"[authority-delta] wrote {rel(path)}")
        return 0

    if args.edges:
        committed = committed_edges()
        for (frm, to), body in sorted(committed.items()):
            counts = body["counts"]
            print(f"{frm:<24} -> {to:<24} "
                  f"+{counts['added']} -{counts['removed']} ~{counts['changed']}")
        print(f"-- {len(committed)} canonical edge delta(s)")
        return 0

    if not args.a or not args.b:
        raise SystemExit("authority-delta: name two nodes, or pass --write-all / --edges")

    if args.compose:
        composed = compose_path(args.a, args.b)
        if args.dimension is not None:
            composed["receipts"] = [
                {**rc, "added": [r for r in rc["added"] if r["dimension"] == args.dimension],
                 "removed": [r for r in rc["removed"] if r["dimension"] == args.dimension],
                 "changed": [r for r in rc["changed"] if r["dimension"] == args.dimension]}
                for rc in composed.get("receipts") or []]
            composed["counts"] = counts_of(
                [r for rc in composed["receipts"] for axis in ("added", "removed", "changed")
                 for r in rc[axis]])
        if args.json:
            print(json.dumps(composed, indent=2, sort_keys=True))
        else:
            _print_composed(composed, args.dimension)
        return 0

    body = direct_delta(args.a, args.b)
    if args.dimension is not None and body.get("covered") is not False:
        body = json.loads(json.dumps(body))
        body["receipts"] = [
            {**rc, "added": [r for r in rc["added"] if r["dimension"] == args.dimension],
             "removed": [r for r in rc["removed"] if r["dimension"] == args.dimension],
             "changed": [r for r in rc["changed"] if r["dimension"] == args.dimension]}
            for rc in body["receipts"]]
        body["counts"] = counts_of(
            [r for rc in body["receipts"] for axis in ("added", "removed", "changed")
             for r in rc[axis]])
    if args.json:
        print(json.dumps(body, indent=2, sort_keys=True))
    else:
        _print_body(body, args.dimension)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
