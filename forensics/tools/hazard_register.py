#!/usr/bin/env python3
"""hazard_register.py -- validate the ETP-T2 security hazard register.

The register (`evidence/etp-t2/HAZARDS.json`) is the machine-readable half of
`docs/HAZARD-REGISTER.md`.  It carries:

  * the three-way input classification and the per-family guarantee;
  * the hazards, each with one API-family scope, one primary input class, the
    input classes that can trigger it, and a barrier state;
  * the fault trees, FMEA, STPA-Sec control structure and attack graphs;
  * the T1 edges each hazard adds to `evidence/etp-t1/TRACEABILITY.json`.

The validator refuses (exit 1) when a hazard has no scope, no input class, or
claims memory safety while a contract-violating input can trigger it; when a
fault-tree leaf names neither a mechanism nor a recorded assumption; when a
FMEA row claims an evidenced control with no evidence id; and when the register
and the traceability graph disagree about any projected field or edge.

Usage:

    python3 forensics/tools/hazard_register.py validate [--register PATH] [--graph PATH] [--json]
    python3 forensics/tools/hazard_register.py report   [--register PATH] [--graph PATH] [--json]
    python3 forensics/tools/hazard_register.py counts   [--register PATH] [--graph PATH]

Exit status: 0 only when the register is valid and matches the graph; 1 for a
refusal; 2 for a usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import traceability  # noqa: E402  (same-directory tool import)

REPO_ROOT = traceability.REPO_ROOT
DEFAULT_REGISTER = REPO_ROOT / "evidence" / "etp-t2" / "HAZARDS.json"
DEFAULT_GRAPH = REPO_ROOT / "evidence" / "etp-t1" / "TRACEABILITY.json"

REGISTER_SCHEMA = "openssl-rs/etp/hazards/1"
INPUT_CLASSES = traceability.INPUT_CLASSES
API_FAMILIES = traceability.API_FAMILIES
CLASS3_DISPOSITIONS = traceability.CLASS3_DISPOSITIONS
BARRIER_STATES = traceability.BARRIER_STATES
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
EVIDENCE_STATUS = {"EVIDENCED", "CLAIMED_NO_EVIDENCE", "NONE"}
LEAF_KINDS = {"mechanism", "assumption"}
GATES = {"AND", "OR"}

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2


class Refusal(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def load_register(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal("HR_UNREADABLE", f"{path}: {exc}") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=traceability._reject_duplicate_keys,
            parse_constant=traceability._reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise Refusal("HR_MALFORMED", f"{path}: {exc}") from exc
    if not isinstance(document, dict):
        raise Refusal("HR_SCHEMA", f"{path}: top level is not an object")
    if document.get("schema") != REGISTER_SCHEMA:
        raise Refusal(
            "HR_SCHEMA",
            f"schema is {document.get('schema')!r}, expected {REGISTER_SCHEMA!r}",
        )
    if document.get("kind") != "security-hazard-register":
        raise Refusal("HR_SCHEMA", "kind is not 'security-hazard-register'")
    return document


def _require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise Refusal(code, detail)


def _require_string(obj: dict[str, Any], key: str, code: str, where: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise Refusal(code, f"{where}: {key} must be a non-empty string")
    return value


def _require_string_list(
    obj: dict[str, Any], key: str, code: str, where: str, allow_empty: bool = False
) -> list[str]:
    value = obj.get(key)
    if not isinstance(value, list) or (not value and not allow_empty):
        raise Refusal(code, f"{where}: {key} must be a {'possibly empty ' if allow_empty else ''}array of strings")
    if any(not isinstance(item, str) or not item for item in value):
        raise Refusal(code, f"{where}: {key} contains a non-string item")
    if len(set(value)) != len(value):
        raise Refusal(code, f"{where}: {key} contains a duplicate")
    return value


def validate_structure(document: dict[str, Any], repo: Path) -> None:
    identity = document.get("identity")
    _require(isinstance(identity, dict), "HR_SCHEMA", "identity is absent")
    blobs = traceability.Blobs(repo)
    for key in ("analysis_candidate", "graph_commit"):
        commit = identity.get(key)
        _require(
            isinstance(commit, str) and blobs.has_commit(commit),
            "HR_IDENTITY_UNRESOLVED",
            f"identity.{key} {commit!r} does not resolve",
        )
    _require(
        isinstance(identity.get("settling_method"), str) and identity["settling_method"],
        "HR_SCHEMA",
        "identity.settling_method is absent",
    )

    input_model = document.get("input_model")
    _require(isinstance(input_model, dict), "HR_SCHEMA", "input_model is absent")
    classes = input_model.get("classes")
    _require(isinstance(classes, list) and classes, "HR_SCHEMA", "input_model.classes is absent")
    class_ids = set()
    for entry in classes:
        _require(isinstance(entry, dict), "HR_SCHEMA", "an input class is not an object")
        cid = _require_string(entry, "id", "HR_SCHEMA", "input class")
        _require(cid in INPUT_CLASSES, "HR_SCHEMA", f"input class {cid!r} is unknown")
        _require(cid not in class_ids, "HR_DUPLICATE_ID", f"input class {cid!r} is duplicated")
        class_ids.add(cid)
        for key in ("definition", "implementation_guarantee"):
            _require_string(entry, key, "HR_SCHEMA", f"input class {cid}")
    _require(
        class_ids == INPUT_CLASSES,
        "HR_SCHEMA",
        f"input classes are {sorted(class_ids)}, expected {sorted(INPUT_CLASSES)}",
    )

    families = input_model.get("families")
    _require(isinstance(families, list) and families, "HR_SCHEMA", "input_model.families is absent")
    family_ids = set()
    for entry in families:
        _require(isinstance(entry, dict), "HR_SCHEMA", "an API family is not an object")
        fid = _require_string(entry, "id", "HR_UNKNOWN_API_FAMILY", "API family")
        _require(fid in API_FAMILIES, "HR_UNKNOWN_API_FAMILY", f"API family {fid!r} is unknown")
        _require(fid not in family_ids, "HR_DUPLICATE_ID", f"API family {fid!r} is duplicated")
        family_ids.add(fid)
        _require_string_list(entry, "entry_points", "HR_UNSCOPED_HAZARD", f"family {fid}")
        for key in ("legal", "class2", "class3"):
            _require_string(entry, key, "HR_SCHEMA", f"family {fid}")
    _require(
        family_ids == API_FAMILIES,
        "HR_UNKNOWN_API_FAMILY",
        f"families are {sorted(family_ids)}, expected {sorted(API_FAMILIES)}",
    )

    top_events = document.get("top_events")
    _require(isinstance(top_events, list) and top_events, "HR_SCHEMA", "top_events is absent")
    top_ids = set()
    for entry in top_events:
        _require(isinstance(entry, dict), "HR_SCHEMA", "a top event is not an object")
        tid = _require_string(entry, "id", "HR_SCHEMA", "top event")
        _require(tid not in top_ids, "HR_DUPLICATE_ID", f"top event {tid!r} is duplicated")
        _require_string(entry, "title", "HR_SCHEMA", f"top event {tid}")
        top_ids.add(tid)

    assumptions = document.get("assumptions")
    _require(isinstance(assumptions, list) and assumptions, "HR_SCHEMA", "assumptions is absent")
    assumption_ids = set()
    for entry in assumptions:
        _require(isinstance(entry, dict), "HR_SCHEMA", "an assumption is not an object")
        aid = _require_string(entry, "id", "HR_SCHEMA", "assumption")
        _require(aid not in assumption_ids, "HR_DUPLICATE_ID", f"assumption {aid!r} is duplicated")
        assumption_ids.add(aid)
        _require_string(entry, "statement", "HR_SCHEMA", f"assumption {aid}")
        source = entry.get("source")
        _require(isinstance(source, dict), "HR_SCHEMA", f"assumption {aid} has no source")
        path = _require_string(source, "path", "HR_SCHEMA", f"assumption {aid} source")
        _require(
            (repo / path).is_file(),
            "HR_ASSUMPTION_SOURCE",
            f"assumption {aid} names absent source {path!r}",
        )

    hazards = document.get("hazards")
    _require(isinstance(hazards, list) and hazards, "HR_SCHEMA", "hazards is absent")
    hazard_ids: set[str] = set()
    for entry in hazards:
        _require(isinstance(entry, dict), "HR_SCHEMA", "a hazard is not an object")
        hid = _require_string(entry, "id", "HR_SCHEMA", "hazard")
        _require(hid.startswith("HAZ-"), "HR_SCHEMA", f"hazard id {hid!r} is not stable (HAZ-*)")
        _require(hid not in hazard_ids, "HR_DUPLICATE_ID", f"hazard {hid!r} is duplicated")
        hazard_ids.add(hid)
        _validate_hazard(entry, hid, family_ids, top_ids)
        for tid in entry.get("top_events", []):
            _require(tid in top_ids, "HR_TOP_EVENT_UNCOVERED", f"{hid} names unknown top event {tid!r}")

    _require(
        isinstance(document.get("fault_trees"), list) and document["fault_trees"],
        "HR_SCHEMA",
        "fault_trees is absent",
    )
    _validate_fault_trees(document, top_ids, hazard_ids, assumption_ids)
    _require(
        isinstance(document.get("fmea"), list) and document["fmea"],
        "HR_SCHEMA",
        "fmea is absent",
    )
    _validate_fmea(document, hazard_ids, top_ids)
    _validate_stpa(document, top_ids, hazard_ids)
    _validate_attack_graphs(document, top_ids, hazard_ids)


def _validate_hazard(
    entry: dict[str, Any], hid: str, family_ids: set[str], top_ids: set[str]
) -> None:
    _require_string(entry, "title", "HR_SCHEMA", hid)
    _require_string(entry, "description", "HR_SCHEMA", hid)
    source = entry.get("source")
    _require(isinstance(source, dict), "HR_SCHEMA", f"{hid} has no source")
    for key in ("path", "span", "quote"):
        _require_string(source, key, "HR_SCHEMA", f"{hid} source")
    _require(
        isinstance(source.get("quote_kind"), str) and source["quote_kind"],
        "HR_SCHEMA",
        f"{hid} source.quote_kind is absent",
    )

    scope = entry.get("scope")
    if not isinstance(scope, dict):
        raise Refusal("HR_UNSCOPED_HAZARD", f"{hid} has no scope")
    family = scope.get("api_family")
    if family not in family_ids:
        raise Refusal("HR_UNKNOWN_API_FAMILY", f"{hid} names api_family {family!r}")
    if scope.get("input_class") not in INPUT_CLASSES:
        raise Refusal(
            "HR_UNSCOPED_HAZARD",
            f"{hid} scope.input_class {scope.get('input_class')!r} is not an input class",
        )
    _require_string_list(scope, "entry_points", "HR_UNSCOPED_HAZARD", f"{hid} scope")

    triggers = _require_string_list(entry, "trigger_classes", "HR_NO_INPUT_CLASS", hid)
    unknown = [t for t in triggers if t not in INPUT_CLASSES]
    if unknown:
        raise Refusal("HR_NO_INPUT_CLASS", f"{hid} names unknown input class {unknown[0]!r}")

    memory_safe = entry.get("memory_safe_claim")
    _require(
        isinstance(memory_safe, bool),
        "HR_NO_INPUT_CLASS",
        f"{hid} must state memory_safe_claim as a boolean",
    )
    if "contract_violation" in triggers:
        disposition = entry.get("class3_disposition")
        if disposition not in CLASS3_DISPOSITIONS:
            raise Refusal(
                "HR_CLASS3_DISPOSITION",
                f"{hid} is reachable from a contract-violating input and must state a class-3 disposition",
            )
        if memory_safe:
            raise Refusal(
                "HR_CLASS3_SAFE_CLAIM",
                f"{hid} claims memory safety while a contract-violating input can trigger it",
            )

    barrier = entry.get("barrier")
    if not isinstance(barrier, dict) or barrier.get("state") not in BARRIER_STATES:
        raise Refusal("HR_BARRIER_INVALID", f"{hid} has no valid barrier state")
    _require_string(barrier, "control", "HR_BARRIER_INVALID", f"{hid} barrier")
    evidence = barrier.get("evidence")
    if not isinstance(evidence, list):
        raise Refusal("HR_BARRIER_INVALID", f"{hid} barrier.evidence is not an array")
    if barrier["state"] == "EVIDENCED":
        if not evidence:
            raise Refusal("HR_BARRIER_UNEVIDENCED", f"{hid} records EVIDENCED with no evidence id")
    else:
        if evidence:
            raise Refusal(
                "HR_BARRIER_UNEVIDENCED",
                f"{hid} records {barrier['state']} but cites evidence {evidence!r}",
            )
        _require_string(barrier, "would_close", "HR_BARRIER_INVALID", f"{hid} barrier")

    t1 = entry.get("t1_edges")
    if not isinstance(t1, dict):
        raise Refusal("HR_SCHEMA", f"{hid} has no t1_edges")
    for key in ("motivates", "obligations", "evidence", "release_claims"):
        _require_string_list(t1, key, "HR_SCHEMA", f"{hid} t1_edges", allow_empty=True)
    if not t1["motivates"]:
        raise Refusal("HR_UNMOTIVATED_HAZARD", f"{hid} motivates no requirement")

    tops = _require_string_list(entry, "top_events", "HR_TOP_EVENT_UNCOVERED", hid)
    for tid in tops:
        if tid not in top_ids:
            raise Refusal("HR_TOP_EVENT_UNCOVERED", f"{hid} names unknown top event {tid!r}")


def _tree_index(tree: dict[str, Any], tid: str) -> dict[str, dict[str, Any]]:
    nodes = tree.get("nodes")
    _require(isinstance(nodes, list) and nodes, "HR_TREE_UNKNOWN_REF", f"{tid} has no nodes")
    index: dict[str, dict[str, Any]] = {}
    for node in nodes:
        _require(isinstance(node, dict), "HR_TREE_UNKNOWN_REF", f"{tid} has a non-object node")
        nid = _require_string(node, "id", "HR_TREE_UNKNOWN_REF", f"{tid} node")
        _require(nid not in index, "HR_DUPLICATE_ID", f"{tid} node {nid!r} is duplicated")
        index[nid] = node
    return index


def _validate_fault_trees(
    document: dict[str, Any],
    top_ids: set[str],
    hazard_ids: set[str],
    assumption_ids: set[str],
) -> None:
    trees = document["fault_trees"]
    tree_ids: set[str] = set()
    hazard_leaves: set[str] = set()
    for tree in trees:
        _require(isinstance(tree, dict), "HR_SCHEMA", "a fault tree is not an object")
        tid = _require_string(tree, "id", "HR_SCHEMA", "fault tree")
        _require(tid not in tree_ids, "HR_DUPLICATE_ID", f"fault tree {tid!r} is duplicated")
        tree_ids.add(tid)
        _require(tid in top_ids, "HR_TOP_EVENT_UNCOVERED", f"fault tree {tid!r} is not a top event")
        _require(tree.get("top_event") == tid, "HR_TREE_UNKNOWN_REF", f"{tid} top_event does not name itself")
        _require_string(tree, "description", "HR_SCHEMA", f"fault tree {tid}")
        _require_string(tree, "diagram", "HR_SCHEMA", f"fault tree {tid}")
        root = _require_string(tree, "root", "HR_TREE_UNKNOWN_REF", f"fault tree {tid}")
        index = _tree_index(tree, tid)
        _require(root in index, "HR_TREE_UNKNOWN_REF", f"{tid} root {root!r} is absent")
        for nid, node in index.items():
            kind = node.get("kind")
            if kind == "gate":
                _require(node.get("gate") in GATES, "HR_TREE_UNKNOWN_REF", f"{tid}:{nid} has an unknown gate")
                inputs = _require_string_list(node, "inputs", "HR_TREE_UNKNOWN_REF", f"{tid}:{nid}", allow_empty=False)
                for target in inputs:
                    _require(target in index, "HR_TREE_UNKNOWN_REF", f"{tid}:{nid} input {target!r} is absent")
            elif kind == "leaf":
                leaf_type = node.get("leaf_type")
                _require(leaf_type in LEAF_KINDS, "HR_TREE_LEAF_UNNAMED", f"{tid}:{nid} has no leaf type")
                _require_string(node, "statement", "HR_TREE_LEAF_UNNAMED", f"{tid}:{nid}")
                if leaf_type == "mechanism":
                    hazard = node.get("hazard")
                    mechanism = node.get("mechanism")
                    if not hazard and not mechanism:
                        raise Refusal(
                            "HR_TREE_LEAF_UNNAMED",
                            f"{tid}:{nid} names neither a hazard nor a mechanism; a leaf may not say 'bug'",
                        )
                    if hazard:
                        _require(
                            hazard in hazard_ids,
                            "HR_TREE_HAZARD_UNKNOWN",
                            f"{tid}:{nid} names unknown hazard {hazard!r}",
                        )
                        hazard_leaves.add(hazard)
                else:
                    aid = node.get("assumption_id")
                    _require(
                        aid in assumption_ids,
                        "HR_TREE_ASSUMPTION_UNKNOWN",
                        f"{tid}:{nid} names unknown assumption {aid!r}",
                    )
            else:
                raise Refusal("HR_TREE_UNKNOWN_REF", f"{tid}:{nid} has kind {kind!r}")

        # Reachability and acyclicity.
        seen: set[str] = set()
        stack = [root]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            node = index[current]
            if node.get("kind") == "gate":
                stack.extend(node["inputs"])
        unreachable = sorted(set(index) - seen)
        _require(
            not unreachable,
            "HR_TREE_UNKNOWN_REF",
            f"{tid} has nodes unreachable from the root: {unreachable}",
        )
        _require(
            not _has_cycle(index, root),
            "HR_TREE_CYCLE",
            f"{tid} has a cycle in its gate structure",
        )

    _require(
        tree_ids == top_ids,
        "HR_TOP_EVENT_UNCOVERED",
        f"trees cover {sorted(tree_ids)}, top events are {sorted(top_ids)}",
    )
    uncovered = sorted(hazard_ids - hazard_leaves)
    _require(
        not uncovered,
        "HR_HAZARD_WITHOUT_TREE",
        f"hazards absent from every fault tree: {uncovered}",
    )


def _has_cycle(index: dict[str, dict[str, Any]], root: str) -> bool:
    visiting: set[str] = set()
    done: set[str] = set()

    def visit(nid: str) -> bool:
        if nid in done:
            return False
        if nid in visiting:
            return True
        visiting.add(nid)
        node = index[nid]
        if node.get("kind") == "gate":
            for target in node["inputs"]:
                if visit(target):
                    return True
        visiting.discard(nid)
        done.add(nid)
        return False

    return visit(root)


def _validate_fmea(document: dict[str, Any], hazard_ids: set[str], top_ids: set[str]) -> None:
    rows = document["fmea"]
    row_ids: set[str] = set()
    covered: set[str] = set()
    for row in rows:
        _require(isinstance(row, dict), "HR_SCHEMA", "an FMEA row is not an object")
        fid = _require_string(row, "id", "HR_SCHEMA", "FMEA row")
        _require(fid not in row_ids, "HR_DUPLICATE_ID", f"FMEA row {fid!r} is duplicated")
        row_ids.add(fid)
        for key in ("component", "api_family", "failure_mode", "local_effect", "control", "residual"):
            _require_string(row, key, "HR_SCHEMA", f"FMEA row {fid}")
        _require(
            row["api_family"] in API_FAMILIES,
            "HR_UNKNOWN_API_FAMILY",
            f"FMEA row {fid} names unknown family {row['api_family']!r}",
        )
        _require(row.get("severity") in SEVERITIES, "HR_FMEA_SEVERITY", f"FMEA row {fid} has no severity")
        tops = _require_string_list(row, "top_events", "HR_FMEA_TOP_EVENT", fid)
        for tid in tops:
            _require(tid in top_ids, "HR_FMEA_TOP_EVENT", f"FMEA row {fid} names unknown top event {tid!r}")
        hazards = _require_string_list(row, "hazards", "HR_FMEA_UNKNOWN_HAZARD", fid, allow_empty=True)
        for hid in hazards:
            _require(hid in hazard_ids, "HR_FMEA_UNKNOWN_HAZARD", f"FMEA row {fid} names unknown hazard {hid!r}")
            covered.add(hid)
        status = row.get("evidence_status")
        _require(status in EVIDENCE_STATUS, "HR_FMEA_EVIDENCE", f"FMEA row {fid} has no evidence status")
        evidence = _require_string_list(row, "control_evidence", "HR_FMEA_EVIDENCE", fid, allow_empty=True)
        if status == "EVIDENCED":
            _require(
                bool(evidence),
                "HR_FMEA_EVIDENCE",
                f"FMEA row {fid} claims an evidenced control with no evidence id",
            )
        else:
            _require(
                not evidence,
                "HR_FMEA_EVIDENCE",
                f"FMEA row {fid} is {status} but cites evidence {evidence!r}",
            )
    uncovered = sorted(hazard_ids - covered)
    _require(not uncovered, "HR_FMEA_UNKNOWN_HAZARD", f"hazards absent from every FMEA row: {uncovered}")


def _validate_stpa(document: dict[str, Any], top_ids: set[str], hazard_ids: set[str]) -> None:
    stpa = document.get("stpa")
    _require(isinstance(stpa, dict), "HR_SCHEMA", "stpa is absent")
    structure = stpa.get("control_structure")
    _require(isinstance(structure, dict), "HR_SCHEMA", "stpa.control_structure is absent")
    nodes = structure.get("nodes")
    _require(isinstance(nodes, list) and nodes, "HR_STPA_UCA_INCOMPLETE", "control structure has no nodes")
    node_ids: set[str] = set()
    for node in nodes:
        _require(isinstance(node, dict), "HR_STPA_UCA_INCOMPLETE", "a control-structure node is not an object")
        nid = _require_string(node, "id", "HR_STPA_UCA_INCOMPLETE", "control-structure node")
        _require(nid not in node_ids, "HR_DUPLICATE_ID", f"control-structure node {nid!r} is duplicated")
        node_ids.add(nid)
        for key in ("role", "description"):
            _require_string(node, key, "HR_STPA_UCA_INCOMPLETE", f"control-structure node {nid}")
    edges = structure.get("edges")
    _require(isinstance(edges, list) and edges, "HR_STPA_UCA_INCOMPLETE", "control structure has no edges")
    for edge in edges:
        _require(isinstance(edge, dict), "HR_STPA_UCA_INCOMPLETE", "a control edge is not an object")
        for key in ("from", "to"):
            endpoint = _require_string(edge, key, "HR_STPA_UCA_INCOMPLETE", "control edge")
            _require(endpoint in node_ids, "HR_STPA_UCA_INCOMPLETE", f"control edge names absent node {endpoint!r}")
        _require_string(edge, "action", "HR_STPA_UCA_INCOMPLETE", "control edge")

    ucas = stpa.get("ucas")
    _require(isinstance(ucas, list) and ucas, "HR_STPA_UCA_INCOMPLETE", "stpa.ucas is absent")
    uca_ids: set[str] = set()
    for uca in ucas:
        _require(isinstance(uca, dict), "HR_STPA_UCA_INCOMPLETE", "a UCA is not an object")
        uid = _require_string(uca, "id", "HR_STPA_UCA_INCOMPLETE", "UCA")
        _require(uid not in uca_ids, "HR_DUPLICATE_ID", f"UCA {uid!r} is duplicated")
        uca_ids.add(uid)
        for key in ("control_action", "context", "loss", "barrier"):
            _require_string(uca, key, "HR_STPA_UCA_INCOMPLETE", f"UCA {uid}")
        controller = _require_string(uca, "controller", "HR_STPA_UCA_INCOMPLETE", f"UCA {uid}")
        _require(controller in node_ids, "HR_STPA_UCA_INCOMPLETE", f"UCA {uid} names absent controller {controller!r}")
        hazard = _require_string(uca, "hazard", "HR_STPA_UCA_INCOMPLETE", f"UCA {uid}")
        _require(hazard in hazard_ids, "HR_STPA_UCA_INCOMPLETE", f"UCA {uid} names unknown hazard {hazard!r}")
        tops = _require_string_list(uca, "top_events", "HR_STPA_UCA_INCOMPLETE", f"UCA {uid}")
        for tid in tops:
            _require(tid in top_ids, "HR_STPA_UCA_INCOMPLETE", f"UCA {uid} names unknown top event {tid!r}")


def _validate_attack_graphs(
    document: dict[str, Any], top_ids: set[str], hazard_ids: set[str]
) -> None:
    graphs = document.get("attack_graphs")
    _require(isinstance(graphs, list) and graphs, "HR_AG_INCOMPLETE", "attack_graphs is absent")
    graph_ids: set[str] = set()
    for graph in graphs:
        _require(isinstance(graph, dict), "HR_AG_INCOMPLETE", "an attack graph is not an object")
        gid = _require_string(graph, "id", "HR_AG_INCOMPLETE", "attack graph")
        _require(gid not in graph_ids, "HR_DUPLICATE_ID", f"attack graph {gid!r} is duplicated")
        graph_ids.add(gid)
        _require_string(graph, "title", "HR_AG_INCOMPLETE", f"attack graph {gid}")
        pre = _require_string_list(graph, "preconditions", "HR_AG_INCOMPLETE", f"attack graph {gid}")
        _require(len(pre) >= 1, "HR_AG_INCOMPLETE", f"attack graph {gid} has no preconditions")
        steps = _require_string_list(graph, "steps", "HR_AG_INCOMPLETE", f"attack graph {gid}")
        _require(len(steps) >= 2, "HR_AG_INCOMPLETE", f"attack graph {gid} has fewer than two steps")
        _require_string(graph, "barrier", "HR_AG_INCOMPLETE", f"attack graph {gid}")
        _require_string(graph, "residual", "HR_AG_INCOMPLETE", f"attack graph {gid}")
        _require(
            isinstance(graph.get("barrier_evidenced"), bool),
            "HR_AG_INCOMPLETE",
            f"attack graph {gid} must state barrier_evidenced as a boolean",
        )
        evidence = _require_string_list(graph, "evidence", "HR_AG_INCOMPLETE", f"attack graph {gid}", allow_empty=True)
        if graph["barrier_evidenced"]:
            _require(
                bool(evidence),
                "HR_AG_INCOMPLETE",
                f"attack graph {gid} claims an evidenced barrier with no evidence id",
            )
        hazards = _require_string_list(graph, "hazards", "HR_AG_INCOMPLETE", f"attack graph {gid}")
        for hid in hazards:
            _require(hid in hazard_ids, "HR_AG_INCOMPLETE", f"attack graph {gid} names unknown hazard {hid!r}")
        tops = _require_string_list(graph, "top_events", "HR_AG_INCOMPLETE", f"attack graph {gid}")
        for tid in tops:
            _require(tid in top_ids, "HR_AG_INCOMPLETE", f"attack graph {gid} names unknown top event {tid!r}")


# --------------------------------------------------------------------------
# Cross-check against the traceability graph
# --------------------------------------------------------------------------


def _graph_hazards(graph: traceability.Graph) -> dict[str, dict[str, Any]]:
    return {
        nid: node for nid, node in graph.nodes.items() if node["type"] == "hazard"
    }


def _edge_targets(graph: traceability.Graph, nid: str, etype: str) -> set[str]:
    return {edge["to"] for edge in graph.out.get(nid, []) if edge["type"] == etype}


def cross_check(
    document: dict[str, Any], register_path: Path, graph_path: Path, repo: Path
) -> None:
    try:
        graph = traceability.load_graph(graph_path, repo)
    except traceability.Refusal as refusal:
        raise Refusal("HR_GRAPH_INVALID", f"{refusal.code}: {refusal.detail}") from refusal

    declared = graph.document.get("hazard_register")
    _require(
        isinstance(declared, dict),
        "HR_GRAPH_MISSING",
        "the traceability graph does not record a hazard_register",
    )
    _require(
        declared.get("sha256") == hashlib.sha256(register_path.read_bytes()).hexdigest(),
        "HR_GRAPH_FIELD_MISMATCH",
        "the graph's recorded register digest does not match the register bytes",
    )
    _require(
        document["identity"]["graph_commit"] == graph.commit,
        "HR_GRAPH_COMMIT_MISMATCH",
        f"register names graph commit {document['identity']['graph_commit']}, graph is {graph.commit}",
    )

    projected = _graph_hazards(graph)
    register_hazards = {entry["id"]: entry for entry in document["hazards"]}
    missing = sorted(set(register_hazards) - set(projected))
    _require(not missing, "HR_GRAPH_NODE_MISSING", f"hazards absent from the graph: {missing}")
    extra = sorted(set(projected) - set(register_hazards))
    _require(not extra, "HR_GRAPH_NODE_MISSING", f"graph hazards absent from the register: {extra}")

    for hid, entry in register_hazards.items():
        node = projected[hid]
        for field in ("scope", "trigger_classes", "memory_safe_claim"):
            _require(
                node.get(field) == entry.get(field),
                "HR_GRAPH_FIELD_MISMATCH",
                f"{hid}: graph {field} is {node.get(field)!r}, register is {entry.get(field)!r}",
            )
        _require(
            node.get("affected_release_claims") == entry["t1_edges"]["release_claims"],
            "HR_GRAPH_FIELD_MISMATCH",
            f"{hid}: graph affected_release_claims {node.get('affected_release_claims')!r} "
            f"disagrees with the register {entry['t1_edges']['release_claims']!r}",
        )
        _require(
            node.get("class3_disposition") == entry.get("class3_disposition"),
            "HR_GRAPH_FIELD_MISMATCH",
            f"{hid}: graph class3_disposition disagrees with the register",
        )
        node_barrier = node.get("barrier", {})
        entry_barrier = entry["barrier"]
        for field in ("state", "control", "evidence", "would_close"):
            _require(
                node_barrier.get(field) == entry_barrier.get(field),
                "HR_GRAPH_FIELD_MISMATCH",
                f"{hid}: graph barrier.{field} disagrees with the register",
            )

        t1 = entry["t1_edges"]
        for etype, key in (
            ("motivates", "motivates"),
            ("raises", "obligations"),
            ("evidenced_by", "evidence"),
        ):
            actual = _edge_targets(graph, hid, etype)
            _require(
                actual == set(t1[key]),
                "HR_GRAPH_EDGE_MISMATCH",
                f"{hid}: graph {etype} edges {sorted(actual)} disagree with the register {sorted(t1[key])}",
            )

        for rid in t1["motivates"]:
            _require(
                rid in graph.nodes and graph.nodes[rid]["type"] == "requirement",
                "HR_GRAPH_EDGE_MISMATCH",
                f"{hid} motivates {rid!r}, which is not a requirement node",
            )
        for oid in t1["obligations"]:
            _require(
                oid in graph.nodes and graph.nodes[oid]["type"] == "obligation",
                "HR_GRAPH_EDGE_MISMATCH",
                f"{hid} raises {oid!r}, which is not an obligation node",
            )
        for eid in t1["evidence"]:
            _require(
                eid in graph.nodes and graph.nodes[eid]["type"] == "evidence",
                "HR_GRAPH_EDGE_MISMATCH",
                f"{hid} cites {eid!r}, which is not an evidence node",
            )
        for cid in t1["release_claims"]:
            _require(
                cid in graph.nodes and graph.nodes[cid]["type"] == "release_claim",
                "HR_GRAPH_EDGE_MISMATCH",
                f"{hid} names {cid!r}, which is not a release claim",
            )

    # FMEA evidence ids and attack-graph evidence ids must name real evidence nodes.
    for row in document["fmea"]:
        for eid in row.get("control_evidence", []):
            _require(
                eid in graph.nodes and graph.nodes[eid]["type"] == "evidence",
                "HR_EVIDENCE_UNKNOWN",
                f"FMEA row {row['id']} cites {eid!r}, which is not an evidence node",
            )
    for graph_entry in document["attack_graphs"]:
        for eid in graph_entry["evidence"]:
            _require(
                eid in graph.nodes and graph.nodes[eid]["type"] == "evidence",
                "HR_EVIDENCE_UNKNOWN",
                f"attack graph {graph_entry['id']} cites {eid!r}, which is not an evidence node",
            )
    for entry in document["hazards"]:
        for eid in entry["barrier"].get("evidence", []):
            _require(
                eid in graph.nodes and graph.nodes[eid]["type"] == "evidence",
                "HR_EVIDENCE_UNKNOWN",
                f"{entry['id']} barrier cites {eid!r}, which is not an evidence node",
            )


# --------------------------------------------------------------------------
# Summaries and commands
# --------------------------------------------------------------------------


def summarise(document: dict[str, Any]) -> dict[str, Any]:
    hazards = document["hazards"]
    by_top: dict[str, int] = {entry["id"]: 0 for entry in document["top_events"]}
    for hazard in hazards:
        for tid in hazard["top_events"]:
            by_top[tid] += 1
    barrier: dict[str, int] = {state: 0 for state in sorted(BARRIER_STATES)}
    for hazard in hazards:
        barrier[hazard["barrier"]["state"]] += 1
    input_class: dict[str, int] = {cid: 0 for cid in sorted(INPUT_CLASSES)}
    for hazard in hazards:
        for cid in hazard["trigger_classes"]:
            input_class[cid] += 1
    fmea_status = {status: 0 for status in sorted(EVIDENCE_STATUS)}
    for row in document["fmea"]:
        fmea_status[row["evidence_status"]] += 1
    return {
        "hazards": len(hazards),
        "top_events": len(document["top_events"]),
        "fault_trees": len(document["fault_trees"]),
        "fmea_rows": len(document["fmea"]),
        "ucas": len(document["stpa"]["ucas"]),
        "attack_graphs": len(document["attack_graphs"]),
        "hazards_by_top_event": by_top,
        "hazards_by_barrier_state": barrier,
        "hazards_by_trigger_class": input_class,
        "fmea_by_evidence_status": fmea_status,
        "barrier_absent": sorted(
            h["id"] for h in hazards if h["barrier"]["state"] == "BARRIER_ABSENT"
        ),
        "class3_hazards": sorted(
            h["id"] for h in hazards if "contract_violation" in h["trigger_classes"]
        ),
        "hazards_without_release_claim": sorted(
            h["id"] for h in hazards if not h["t1_edges"]["release_claims"]
        ),
    }


def command_validate(args: argparse.Namespace) -> int:
    document = load_register(args.register)
    validate_structure(document, args.repo_root)
    cross_check(document, args.register, args.graph, args.repo_root)
    summary = summarise(document)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return EXIT_OK
    print(
        f"hazard register {args.register}: {summary['hazards']} hazards, "
        f"{summary['fault_trees']} fault trees, {summary['fmea_rows']} FMEA rows, "
        f"{summary['ucas']} UCAs, {summary['attack_graphs']} attack graphs"
    )
    print(
        "barrier states: "
        + ", ".join(f"{k}={v}" for k, v in summary["hazards_by_barrier_state"].items())
        + "; FMEA evidence: "
        + ", ".join(f"{k}={v}" for k, v in summary["fmea_by_evidence_status"].items())
    )
    print(
        f"BARRIER_ABSENT: {', '.join(summary['barrier_absent']) or 'none'}; "
        f"no release claim: {', '.join(summary['hazards_without_release_claim']) or 'none'}"
    )
    print("register and traceability graph agree")
    return EXIT_OK


def command_report(args: argparse.Namespace) -> int:
    document = load_register(args.register)
    validate_structure(document, args.repo_root)
    cross_check(document, args.register, args.graph, args.repo_root)
    print(json.dumps(summarise(document), indent=2, sort_keys=True))
    return EXIT_OK


def command_counts(args: argparse.Namespace) -> int:
    document = load_register(args.register)
    validate_structure(document, args.repo_root)
    print(json.dumps(summarise(document), indent=2, sort_keys=True))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("validate", "report", "counts"))
    parser.add_argument("--register", type=Path, default=DEFAULT_REGISTER)
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            return command_validate(args)
        if args.command == "report":
            return command_report(args)
        return command_counts(args)
    except Refusal as refusal:
        print(f"{refusal.code}: {refusal.detail}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
