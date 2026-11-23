#!/usr/bin/env python3
"""traceability.py -- validate the requirements traceability graph and detect orphans.

The graph (`evidence/etp-t1/TRACEABILITY.json`, ETP-T1) is a typed directed graph
over twelve node types:

    threat | hazard -> requirement -> specification -> implementation
        -> artefact -> obligation -> evidence -> adjudication -> release_claim

and, since ETP-T3, a refinement chain over six adjacent levels:

    refinement_level -> refinement_edge -> refinement_level -> ...

Every edge points along that trace direction and states the provider-to-candidate
relation it records (`motivates`, `refines`, `satisfied_by`, `realised_by`,
`raises`, `evidenced_by`, `assessed_by`, `releases`, `constrains`, and the
refinement relations `refines_to`, `discharges`, `obligates`).  The graph
is bound to an exact commit; node source digests and evidence digests are read
from that commit, never from the working tree, so later documentation commits
cannot silently rebind the evidence.

This tool is the executable half of the model.  It refuses (exit 1) when the
graph is malformed, when an edge breaks a declared cardinality rule, or when a
discovered orphan is not declared in the graph's own `orphans` register.  A
declared orphan that no longer reproduces is also refused: a gap register that
drifts away from the graph is not evidence.

The thirteen orphan classes are fixed:

  1  requirement without an implementation edge                 ORPHAN-1:<req>
  2  implementation without an artefact                          ORPHAN-2:<impl>
  3  release claim without a supporting independent adjudication ORPHAN-3:<claim>
  4  evidence bound to a different artefact identity             ORPHAN-4:<node>
  5  blocking obligation not reachable from its release claim    ORPHAN-5:<obl>:<claim>
  6  specification coverage gap                                  ORPHAN-6:SPEC:<id>
                                                                 ORPHAN-6:REQ:<id>
  7  cycle in the support direction                              ORPHAN-7:<scc>
  8  dangling artefact or evidence path                          ORPHAN-8:<node>:<path>
  9  refinement level with no obligation                         ORPHAN-9:<level>
  10 refinement obligation with no artefact                     ORPHAN-10:<edge>
  11 refinement edge with no discharge                          ORPHAN-11:<edge>
  12 unsafe obligation node whose inventory has a site with no   ORPHAN-12:<obligation>
     validity argument and no control
  13 closure exclusion that fails the independently checkable   ORPHAN-13:<obligation>
     bar, or a SAFE_COMPATIBLE release claim constrained by one ORPHAN-13:CLAIM:<claim>

Every refusal names the node, the edge rule and the artefact.  Output is sorted
and serialised with sorted keys and fixed separators, so two runs over the same
graph and repository produce byte-identical output.

Usage:

    python3 forensics/tools/traceability.py validate [--graph PATH]
    python3 forensics/tools/traceability.py report   [--graph PATH] [--json]

Exit status: 0 only when every requested check passed; 1 for a refusal or an
undeclared/stale orphan; 2 for a usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GRAPH = REPO_ROOT / "evidence" / "etp-t1" / "TRACEABILITY.json"

GRAPH_SCHEMA = "openssl-rs/etp/traceability/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

NODE_TYPES = {
    "threat",
    "hazard",
    "requirement",
    "specification",
    "implementation",
    "artefact",
    "obligation",
    "evidence",
    "adjudication",
    "release_claim",
    "refinement_level",
    "refinement_edge",
}

# edge type -> (allowed source types, allowed target types)
EDGE_RULES: dict[str, tuple[set[str], set[str]]] = {
    "motivates": ({"hazard", "threat"}, {"requirement"}),
    "refines": ({"requirement"}, {"specification"}),
    "satisfied_by": ({"requirement", "specification"}, {"implementation"}),
    "realised_by": ({"implementation"}, {"artefact"}),
    "raises": ({"hazard", "implementation", "artefact"}, {"obligation"}),
    "evidenced_by": (
        {"hazard", "requirement", "implementation", "artefact", "obligation", "adjudication"},
        {"evidence"},
    ),
    "assessed_by": ({"evidence", "requirement"}, {"adjudication"}),
    "releases": ({"adjudication"}, {"release_claim"}),
    "constrains": ({"obligation"}, {"release_claim"}),
    "refines_to": ({"refinement_level"}, {"refinement_edge"}),
    "discharges": ({"refinement_edge"}, {"refinement_level"}),
    "obligates": ({"refinement_edge"}, {"obligation"}),
}

# A refinement edge's discharge state.  NONE is the honest "no discharge"; a
# bounded population is named only when one was actually checked; PARTIAL names
# what is missing.
REFINEMENT_STATUSES = {"NONE", "BOUNDED", "PARTIAL"}

# ETP-T2's three-way input classification.  A hazard is scoped by the API family
# it belongs to and by the most adversarial input class that can trigger it.
INPUT_CLASSES = {
    "legal",
    "adversarial_contract_valid",
    "contract_violation",
}
API_FAMILIES = {
    "bn",
    "rsa",
    "ec",
    "evp",
    "bio",
    "x509",
    "runtime_mem",
    "provider_dispatch",
}
CLASS3_DISPOSITIONS = {
    "DEFINED_ERROR",
    "ABORT",
    "UB_NOT_CLAIMED_SAFE",
    "DEFERRED_CRYPTOGRAPHIC_FAILURE",
    "NOT_REACHABLE_FROM_CLASS_3",
}
BARRIER_STATES = {"EVIDENCED", "CLAIMED_NO_EVIDENCE", "BARRIER_ABSENT"}

CLASS_NAMES = {
    1: "requirement_without_implementation",
    2: "implementation_without_artefact",
    3: "release_claim_without_supporting_independent_adjudication",
    4: "evidence_artefact_identity_mismatch",
    5: "obligation_unreachable_from_release_claim",
    6: "specification_coverage_gap",
    7: "support_cycle",
    8: "dangling_artefact_reference",
    9: "refinement_level_without_obligation",
    10: "refinement_obligation_without_artefact",
    11: "refinement_edge_without_discharge",
    12: "unsafe_site_without_contract_or_control",
    13: "closure_exclusion_fails_checkable_bar",
}

# A positive release claim needs a positive adjudication verdict.  A negative
# release claim (a recorded refusal) is supported by a refusal.
POSITIVE_VERDICTS = {"ESTABLISHED", "SAFE_COMPATIBLE", "PASS", "ACCEPTED", "ESTABLISHED (SCOPED)"}
NEGATIVE_VERDICTS = {
    "NOT_ESTABLISHED",
    "NOT_GRADUATED",
    "REFUSED",
    "REFUSED (SINGLE-SOURCE CONTRADICTION AND PROMOTION); ONE ACCEPTED PROBE IS FINDING F4",
    "NON_PROMOTED",
    "CONTRADICTED",
    "WITHDRAWN",
    "SUPERSEDED",
    "PARTIAL",
}


class Refusal(Exception):
    """A named, deterministic refusal.  The code is a stable identifier."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Orphan:
    id: str
    cls: int
    node: str
    reason: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "class": self.cls,
            "class_name": CLASS_NAMES[self.cls],
            "node": self.node,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass
class Graph:
    document: dict[str, Any]
    commit: str
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)
    out: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    inc: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Git-bound blob access
# --------------------------------------------------------------------------


class Blobs:
    """Read blobs at a named commit; cache results for the process lifetime."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self._cache: dict[tuple[str, str], bytes | None] = {}
        self._commits: set[str] = set()

    def _git(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                "git",
                "-c",
                "safe.directory=*",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(self.repo),
                *args,
            ],
            capture_output=True,
            check=False,
        )

    def has_commit(self, commit: str) -> bool:
        if commit in self._commits:
            return True
        if len(commit) < 7 or any(c not in "0123456789abcdef" for c in commit.lower()):
            return False
        result = self._git("cat-file", "-e", f"{commit}^{{commit}}")
        if result.returncode == 0:
            self._commits.add(commit)
            return True
        return False

    def blob(self, commit: str, path: str) -> bytes | None:
        key = (commit, path)
        if key in self._cache:
            return self._cache[key]
        result = self._git("cat-file", "blob", f"{commit}:{path}")
        data = result.stdout if result.returncode == 0 else None
        self._cache[key] = data
        return data

    def sha256(self, commit: str, path: str) -> str | None:
        data = self.blob(commit, path)
        return hashlib.sha256(data).hexdigest() if data is not None else None


# --------------------------------------------------------------------------
# Loading and structural validation
# --------------------------------------------------------------------------


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise Refusal("TG_JSON_DUPLICATE_KEY", f"duplicate object key {key!r}")
        seen[key] = value
    return seen


def _reject_constant(name: str) -> Any:
    raise Refusal("TG_JSON_NON_FINITE", f"non-finite number {name!r}")


def load_graph(path: Path, repo: Path = REPO_ROOT) -> Graph:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal("TG_GRAPH_UNREADABLE", f"{path}: {exc}") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise Refusal("TG_GRAPH_MALFORMED", f"{path}: {exc}") from exc
    if not isinstance(document, dict):
        raise Refusal("TG_GRAPH_MALFORMED", f"{path}: top level is not an object")
    if document.get("schema") != GRAPH_SCHEMA:
        raise Refusal(
            "TG_SCHEMA",
            f"schema is {document.get('schema')!r}, expected {GRAPH_SCHEMA!r}",
        )
    identity = document.get("identity")
    if not isinstance(identity, dict):
        raise Refusal("TG_SCHEMA", "identity is absent")
    commit = identity.get("commit")
    if not isinstance(commit, str) or not commit:
        raise Refusal("TG_SCHEMA", "identity.commit is absent")

    blobs = Blobs(repo)
    if not blobs.has_commit(commit):
        raise Refusal(
            "TG_COMMIT_UNRESOLVED",
            f"identity.commit {commit!r} does not resolve in {repo}",
        )

    graph = Graph(document=document, commit=commit)
    _index(graph)
    _check_structural(graph)
    return graph


def _index(graph: Graph) -> None:
    nodes = graph.document.get("nodes")
    edges = graph.document.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise Refusal("TG_SCHEMA", "nodes and edges must be arrays")
    for node in nodes:
        if not isinstance(node, dict):
            raise Refusal("TG_SCHEMA", "a node is not an object")
        nid = node.get("id")
        ntype = node.get("type")
        if not isinstance(nid, str) or not nid:
            raise Refusal("TG_SCHEMA", "a node has no string id")
        if nid in graph.nodes:
            raise Refusal("TG_DUPLICATE_ID", f"node id {nid!r} is duplicated")
        if ntype not in NODE_TYPES:
            raise Refusal("TG_UNKNOWN_NODE_TYPE", f"node {nid!r} has type {ntype!r}")
        graph.nodes[nid] = node

    for edge in edges:
        if not isinstance(edge, dict):
            raise Refusal("TG_SCHEMA", "an edge is not an object")
        etype = edge.get("type")
        src = edge.get("from")
        dst = edge.get("to")
        if etype not in EDGE_RULES:
            raise Refusal("TG_UNKNOWN_EDGE_TYPE", f"edge type {etype!r}")
        if src not in graph.nodes:
            raise Refusal("TG_DANGLING_EDGE", f"{etype}: source {src!r} does not exist")
        if dst not in graph.nodes:
            raise Refusal("TG_DANGLING_EDGE", f"{etype}: target {dst!r} does not exist")
        allowed_src, allowed_dst = EDGE_RULES[etype]
        src_type = graph.nodes[src]["type"]
        dst_type = graph.nodes[dst]["type"]
        if src_type not in allowed_src or dst_type not in allowed_dst:
            raise Refusal(
                "TG_ILLEGAL_EDGE",
                f"{etype}: {src} ({src_type}) -> {dst} ({dst_type}) is not a legal pair",
            )
        graph.edges.append(edge)

    seen: set[tuple[str, str, str]] = set()
    for edge in graph.edges:
        key = (edge["from"], edge["type"], edge["to"])
        if key in seen:
            raise Refusal("TG_DUPLICATE_EDGE", f"{key[1]}: {key[0]} -> {key[2]} is duplicated")
        seen.add(key)
        graph.out.setdefault(edge["from"], []).append(edge)
        graph.inc.setdefault(edge["to"], []).append(edge)

    for edges_at in graph.out.values():
        edges_at.sort(key=lambda e: (e["type"], e["to"]))
    for edges_at in graph.inc.values():
        edges_at.sort(key=lambda e: (e["type"], e["from"]))


def _check_structural(graph: Graph) -> None:
    """Referential and field rules that are not the thirteen orphan classes."""
    for nid, node in graph.nodes.items():
        source = node.get("source")
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise Refusal("TG_SCHEMA", f"node {nid!r} has no source.path")
        digest = source.get("sha256")
        if digest is None:
            raise Refusal("TG_SCHEMA", f"node {nid!r} has no source.sha256")
        if digest != "UNKNOWN" and not _is_sha256(digest):
            raise Refusal("TG_SCHEMA", f"node {nid!r} source.sha256 is not a SHA-256")
        if digest == "UNKNOWN":
            if not source.get("settling_method"):
                raise Refusal(
                    "TG_UNSETTLED_FIELD",
                    f"node {nid!r} records an UNKNOWN digest without a settling method",
                )
        bound = source.get("bound_commit", graph.commit)
        if not isinstance(bound, str) or not bound:
            raise Refusal("TG_SCHEMA", f"node {nid!r} has a non-string bound_commit")

        if node["type"] == "release_claim":
            claimed = node.get("claimed_verdict")
            if not isinstance(claimed, str) or not claimed:
                raise Refusal("TG_SCHEMA", f"release claim {nid!r} has no claimed_verdict")
            reqs = node.get("scope_requirements")
            if not isinstance(reqs, list) or not reqs:
                raise Refusal("TG_SCHEMA", f"release claim {nid!r} has no scope_requirements")
            for rid in reqs:
                target = graph.nodes.get(rid)
                if target is None:
                    raise Refusal(
                        "TG_RELEASE_SCOPE_UNKNOWN",
                        f"release claim {nid!r} names absent requirement {rid!r}",
                    )
                if target["type"] != "requirement":
                    raise Refusal(
                        "TG_RELEASE_SCOPE_UNKNOWN",
                        f"release claim {nid!r} scope {rid!r} is a {target['type']}, not a requirement",
                    )
            if not isinstance(node.get("requires_independent_adjudication"), bool):
                raise Refusal(
                    "TG_SCHEMA",
                    f"release claim {nid!r} must state requires_independent_adjudication as a boolean",
                )

        if node["type"] == "obligation":
            blocks = node.get("blocks_release_claims", [])
            if not isinstance(blocks, list):
                raise Refusal("TG_SCHEMA", f"obligation {nid!r} blocks_release_claims is not an array")
            inventory = node.get("unsafe_site_inventory")
            if inventory is not None:
                if not isinstance(inventory, dict):
                    raise Refusal(
                        "TG_UNSAFE_INVENTORY",
                        f"obligation {nid!r} unsafe_site_inventory is not an object",
                    )
                for key in ("sites", "sites_without_contract_or_control"):
                    value = inventory.get(key)
                    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                        raise Refusal(
                            "TG_UNSAFE_INVENTORY",
                            f"obligation {nid!r} unsafe_site_inventory.{key} is not a "
                            "non-negative integer",
                        )
                if inventory.get("sites_without_contract_or_control", 0) > inventory.get("sites", 0):
                    raise Refusal(
                        "TG_UNSAFE_INVENTORY",
                        f"obligation {nid!r} claims more uncovered sites than sites",
                    )
            for cid in blocks:
                target = graph.nodes.get(cid)
                if target is None:
                    raise Refusal(
                        "TG_UNKNOWN_BLOCK_TARGET",
                        f"obligation {nid!r} names absent release claim {cid!r}",
                    )
                if target["type"] != "release_claim":
                    raise Refusal(
                        "TG_UNKNOWN_BLOCK_TARGET",
                        f"obligation {nid!r} blocks {cid!r} ({target['type']}), not a release claim",
                    )
            closure_exclusions = node.get("closure_exclusions")
            if closure_exclusions is not None:
                if not isinstance(closure_exclusions, dict):
                    raise Refusal(
                        "TG_CLOSURE_EXCLUSIONS",
                        f"obligation {nid!r} closure_exclusions is not an object",
                    )
                for key in ("rows", "failing_rows"):
                    value = closure_exclusions.get(key)
                    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                        raise Refusal(
                            "TG_CLOSURE_EXCLUSIONS",
                            f"obligation {nid!r} closure_exclusions.{key} is not a "
                            "non-negative integer",
                        )
                if (closure_exclusions.get("failing_rows", 0)
                        > closure_exclusions.get("rows", 0)):
                    raise Refusal(
                        "TG_CLOSURE_EXCLUSIONS",
                        f"obligation {nid!r} claims more failing exclusions than rows",
                    )
                ids = closure_exclusions.get("failing_ids") or []
                if not isinstance(ids, list):
                    raise Refusal(
                        "TG_CLOSURE_EXCLUSIONS",
                        f"obligation {nid!r} closure_exclusions.failing_ids is not an array",
                    )
                if len(ids) != closure_exclusions.get("failing_rows", 0):
                    raise Refusal(
                        "TG_CLOSURE_EXCLUSIONS",
                        f"obligation {nid!r} failing_ids does not match failing_rows",
                    )

        if node["type"] == "requirement":
            if not isinstance(node.get("specification_required"), bool):
                raise Refusal(
                    "TG_SCHEMA",
                    f"requirement {nid!r} must state specification_required as a boolean",
                )

        if node["type"] == "hazard":
            _check_hazard(graph, nid, node)

    _check_refinement(graph)

    # A `constrains` edge must be justified by the obligation's own register.
    for edge in graph.edges:
        if edge["type"] != "constrains":
            continue
        obligation = graph.nodes[edge["from"]]
        if edge["to"] not in obligation.get("blocks_release_claims", []):
            raise Refusal(
                "TG_UNJUSTIFIED_BLOCK_EDGE",
                f"obligation {edge['from']!r} -> {edge['to']!r}: the obligation does not "
                "declare that it blocks the claim",
            )


def _check_hazard(graph: Graph, nid: str, node: dict[str, Any]) -> None:
    """ETP-T2 hazard contract: a scope, an input classification, a barrier.

    A hazard that is reachable only through a contract-violating input may not
    claim memory safety: the API does not enforce the contract, so no caller
    obligation can reduce the severity.  A barrier that is claimed but has no
    evidence must be recorded as ``CLAIMED_NO_EVIDENCE`` rather than silently
    upgraded to ``EVIDENCED``.
    """
    scope = node.get("scope")
    if not isinstance(scope, dict):
        raise Refusal("TG_HAZARD_UNSCOPED", f"hazard {nid!r} has no scope")
    family = scope.get("api_family")
    if family not in API_FAMILIES:
        raise Refusal(
            "TG_HAZARD_UNSCOPED",
            f"hazard {nid!r} names api_family {family!r}, not one of "
            f"{', '.join(sorted(API_FAMILIES))}",
        )
    if scope.get("input_class") not in INPUT_CLASSES:
        raise Refusal(
            "TG_HAZARD_UNSCOPED",
            f"hazard {nid!r} scope.input_class {scope.get('input_class')!r} is not an "
            "input class",
        )
    if not isinstance(scope.get("entry_points"), list) or not scope["entry_points"]:
        raise Refusal(
            "TG_HAZARD_UNSCOPED", f"hazard {nid!r} names no scoped entry point"
        )

    triggers = node.get("trigger_classes")
    if (
        not isinstance(triggers, list)
        or not triggers
        or len(set(triggers)) != len(triggers)
        or any(t not in INPUT_CLASSES for t in triggers)
    ):
        raise Refusal(
            "TG_HAZARD_NO_INPUT_CLASS",
            f"hazard {nid!r} must name a non-empty, duplicate-free set of input "
            f"classes from {', '.join(sorted(INPUT_CLASSES))}",
        )

    memory_safe = node.get("memory_safe_claim")
    if not isinstance(memory_safe, bool):
        raise Refusal(
            "TG_HAZARD_NO_INPUT_CLASS",
            f"hazard {nid!r} must state memory_safe_claim as a boolean",
        )
    if "contract_violation" in triggers:
        disposition = node.get("class3_disposition")
        if disposition not in CLASS3_DISPOSITIONS:
            raise Refusal(
                "TG_HAZARD_CLASS3_DISPOSITION",
                f"hazard {nid!r} is reachable from a contract-violating input and must "
                f"state a class-3 disposition from {', '.join(sorted(CLASS3_DISPOSITIONS))}",
            )
        if memory_safe:
            raise Refusal(
                "TG_HAZARD_CLASS3_SAFE_CLAIM",
                f"hazard {nid!r} claims memory safety while a contract-violating input "
                "can trigger it; the API does not enforce the contract",
            )

    barrier = node.get("barrier")
    if not isinstance(barrier, dict) or barrier.get("state") not in BARRIER_STATES:
        raise Refusal(
            "TG_HAZARD_BARRIER",
            f"hazard {nid!r} must state a barrier state from "
            f"{', '.join(sorted(BARRIER_STATES))}",
        )
    evidence = barrier.get("evidence", [])
    if not isinstance(evidence, list):
        raise Refusal("TG_HAZARD_BARRIER", f"hazard {nid!r} barrier.evidence is not an array")
    if barrier["state"] == "EVIDENCED":
        if not evidence:
            raise Refusal(
                "TG_HAZARD_BARRIER_UNEVIDENCED",
                f"hazard {nid!r} records an EVIDENCED barrier with no evidence id",
            )
        for eid in evidence:
            target = graph.nodes.get(eid)
            if target is None or target["type"] != "evidence":
                raise Refusal(
                    "TG_HAZARD_BARRIER_UNEVIDENCED",
                    f"hazard {nid!r} barrier cites {eid!r}, which is not an evidence node",
                )
    else:
        if evidence:
            raise Refusal(
                "TG_HAZARD_BARRIER_UNEVIDENCED",
                f"hazard {nid!r} records a {barrier['state']} barrier but cites evidence "
                f"{evidence!r}; a claimed or absent barrier is not evidenced by definition",
            )
        if not isinstance(barrier.get("would_close"), str) or not barrier["would_close"]:
            raise Refusal(
                "TG_HAZARD_BARRIER",
                f"hazard {nid!r} records a {barrier['state']} barrier without stating "
                "what would close it",
            )

    if not isinstance(barrier.get("control"), str) or not barrier["control"]:
        raise Refusal("TG_HAZARD_BARRIER", f"hazard {nid!r} does not name its control")

    motivated = {
        edge["to"] for edge in graph.out.get(nid, []) if edge["type"] == "motivates"
    }
    if not motivated:
        raise Refusal(
            "TG_HAZARD_UNMOTIVATED",
            f"hazard {nid!r} motivates no requirement; a hazard may not sit beside the model",
        )

    derived_claims: set[str] = set()
    for cid, cnode in graph.nodes.items():
        if cnode["type"] != "release_claim":
            continue
        if motivated & set(cnode.get("scope_requirements", [])):
            derived_claims.add(cid)
    for obligation in [
        edge["to"] for edge in graph.out.get(nid, []) if edge["type"] == "raises"
    ]:
        derived_claims.update(
            edge["to"]
            for edge in graph.out.get(obligation, [])
            if edge["type"] == "constrains"
        )

    affected = node.get("affected_release_claims")
    if not isinstance(affected, list) or len(set(affected)) != len(affected):
        raise Refusal(
            "TG_HAZARD_CLAIM_UNRELATED",
            f"hazard {nid!r} must name affected_release_claims as a duplicate-free array",
        )
    unknown = [cid for cid in affected if cid not in graph.nodes]
    if unknown:
        raise Refusal(
            "TG_HAZARD_CLAIM_UNRELATED",
            f"hazard {nid!r} names absent release claim {unknown[0]!r}",
        )
    if set(affected) != derived_claims:
        raise Refusal(
            "TG_HAZARD_CLAIM_UNRELATED",
            f"hazard {nid!r} names release claims {sorted(affected)} but its motivated "
            f"requirements and raised obligations reach {sorted(derived_claims)}",
        )


def _check_refinement(graph: Graph) -> None:
    """The refinement chain: six levels and five ordered edges.

    The structure is checked here; the three refinement orphan classes check the
    connections that the structure permits to be absent.  A level's rank is the
    only ordering fact: an edge connects rank ``n`` to rank ``n+1``.  An
    ``obligation`` and an ``obligation_artefact`` that do not resolve are class
    10, not a structural refusal, so the omission is named as an orphan.
    """
    levels = {
        nid: node for nid, node in graph.nodes.items()
        if node["type"] == "refinement_level"
    }
    if not levels:
        if any(node["type"] == "refinement_edge" for node in graph.nodes.values()):
            raise Refusal(
                "TG_REFINEMENT_SHAPE",
                "a refinement_edge exists but no refinement_level does",
            )
        return

    by_rank: dict[int, str] = {}
    for nid, node in levels.items():
        rank = node.get("rank")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1:
            raise Refusal("TG_REFINEMENT_LEVEL", f"level {nid!r} has no positive integer rank")
        if rank in by_rank:
            raise Refusal(
                "TG_REFINEMENT_LEVEL",
                f"levels {by_rank[rank]!r} and {nid!r} share rank {rank}",
            )
        by_rank[rank] = nid
        if not isinstance(node.get("name"), str) or not node["name"].strip():
            raise Refusal("TG_REFINEMENT_LEVEL", f"level {nid!r} has no name")
    if sorted(by_rank) != list(range(1, len(by_rank) + 1)):
        raise Refusal(
            "TG_REFINEMENT_LEVEL",
            f"ranks {sorted(by_rank)} are not the consecutive set 1..{len(by_rank)}",
        )

    for nid, node in graph.nodes.items():
        if node["type"] != "refinement_edge":
            continue
        src = node.get("from_level")
        dst = node.get("to_level")
        if src not in levels or dst not in levels:
            raise Refusal(
                "TG_REFINEMENT_SHAPE",
                f"refinement edge {nid!r} names an absent level ({src!r} -> {dst!r})",
            )
        if levels[src]["rank"] + 1 != levels[dst]["rank"]:
            raise Refusal(
                "TG_REFINEMENT_SHAPE",
                f"refinement edge {nid!r} connects rank {levels[src]['rank']} to "
                f"rank {levels[dst]['rank']}; adjacent ranks are required",
            )
        if node.get("status") not in REFINEMENT_STATUSES:
            raise Refusal(
                "TG_REFINEMENT_EDGE",
                f"refinement edge {nid!r} status {node.get('status')!r} is not "
                f"one of {', '.join(sorted(REFINEMENT_STATUSES))}",
            )
        if not isinstance(node.get("discharged_by"), str):
            raise Refusal("TG_REFINEMENT_EDGE", f"edge {nid!r} has no discharged_by string")
        for key in ("invalidation_rule", "does_not_establish"):
            value = node.get(key)
            if not isinstance(value, str) or not value.strip():
                raise Refusal(
                    "TG_REFINEMENT_EDGE",
                    f"edge {nid!r} must state {key} as a non-empty string",
                )
        if not isinstance(node.get("bounded_population", []), list):
            raise Refusal("TG_REFINEMENT_EDGE", f"edge {nid!r} bounded_population is not an array")
        for key in ("obligation", "obligation_artefact"):
            if key in node and not isinstance(node[key], str):
                raise Refusal("TG_REFINEMENT_OBLIGATION", f"edge {nid!r} {key} is not a string")
        if node.get("discharge_artefact") is not None and not isinstance(
            node.get("discharge_artefact"), str
        ):
            raise Refusal(
                "TG_REFINEMENT_EDGE", f"edge {nid!r} discharge_artefact is neither a string nor null"
            )

    # Edge/level consistency and cardinality.
    out_refines: dict[str, list[str]] = {lvl: [] for lvl in levels}
    in_discharges: dict[str, list[str]] = {lvl: [] for lvl in levels}
    for edge in graph.edges:
        if edge["type"] == "refines_to":
            level = edge["from"]
            target = graph.nodes[edge["to"]]
            if target["type"] != "refinement_edge" or target.get("from_level") != level:
                raise Refusal(
                    "TG_REFINEMENT_SHAPE",
                    f"refines_to {level} -> {edge['to']} disagrees with the edge's from_level",
                )
            out_refines.setdefault(level, []).append(edge["to"])
        elif edge["type"] == "discharges":
            level = edge["to"]
            source = graph.nodes[edge["from"]]
            if source["type"] != "refinement_edge" or source.get("to_level") != level:
                raise Refusal(
                    "TG_REFINEMENT_SHAPE",
                    f"discharges {edge['from']} -> {level} disagrees with the edge's to_level",
                )
            in_discharges.setdefault(level, []).append(edge["from"])
        elif edge["type"] == "obligates":
            source = graph.nodes[edge["from"]]
            if source.get("obligation") != edge["to"]:
                raise Refusal(
                    "TG_REFINEMENT_OBLIGATION",
                    f"obligates {edge['from']} -> {edge['to']} disagrees with the edge's obligation",
                )
    for level, edges in out_refines.items():
        if len(edges) > 1:
            raise Refusal(
                "TG_REFINEMENT_SHAPE", f"level {level!r} has {len(edges)} outgoing refines_to edges"
            )
    for level, edges in in_discharges.items():
        if len(edges) > 1:
            raise Refusal(
                "TG_REFINEMENT_SHAPE", f"level {level!r} has {len(edges)} incoming discharges edges"
            )


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value
    )


# --------------------------------------------------------------------------
# Orphan detection
# --------------------------------------------------------------------------


def detect_orphans(graph: Graph, repo: Path = REPO_ROOT) -> list[Orphan]:
    blobs = Blobs(repo)
    orphans: list[Orphan] = []
    orphans.extend(_class_1(graph))
    orphans.extend(_class_2(graph))
    orphans.extend(_class_3(graph))
    orphans.extend(_class_4_and_8(graph, blobs))
    orphans.extend(_class_5(graph))
    orphans.extend(_class_6(graph))
    orphans.extend(_class_7(graph))
    orphans.extend(_class_9(graph))
    orphans.extend(_class_10(graph))
    orphans.extend(_class_11(graph))
    orphans.extend(_class_12(graph))
    orphans.extend(_class_13(graph))
    orphans.sort(key=lambda o: (o.cls, o.id))
    unique: dict[str, Orphan] = {}
    for orphan in orphans:
        unique.setdefault(orphan.id, orphan)
    return sorted(unique.values(), key=lambda o: (o.cls, o.id))


def _out(graph: Graph, nid: str, etype: str) -> list[str]:
    return [e["to"] for e in graph.out.get(nid, []) if e["type"] == etype]


def _in(graph: Graph, nid: str, etype: str) -> list[str]:
    return [e["from"] for e in graph.inc.get(nid, []) if e["type"] == etype]


def _class_1(graph: Graph) -> Iterable[Orphan]:
    for nid, node in graph.nodes.items():
        if node["type"] != "requirement" or _out(graph, nid, "satisfied_by"):
            continue
        yield Orphan(
            id=f"ORPHAN-1:{nid}",
            cls=1,
            node=nid,
            reason="no_implementation",
            detail=f"requirement {nid} has no satisfied_by edge to an implementation",
        )


def _class_2(graph: Graph) -> Iterable[Orphan]:
    for nid, node in graph.nodes.items():
        if node["type"] != "implementation" or _out(graph, nid, "realised_by"):
            continue
        yield Orphan(
            id=f"ORPHAN-2:{nid}",
            cls=2,
            node=nid,
            reason="no_artefact",
            detail=f"implementation {nid} has no realised_by edge to an artefact",
        )


def _class_3(graph: Graph) -> Iterable[Orphan]:
    for nid, node in graph.nodes.items():
        if node["type"] != "release_claim":
            continue
        adjudicators = _in(graph, nid, "releases")
        claimed = node["claimed_verdict"]
        positive = claimed in POSITIVE_VERDICTS
        allowed = POSITIVE_VERDICTS if positive else NEGATIVE_VERDICTS
        reasons: list[str] = []
        if not adjudicators:
            reasons.append("no_adjudication")
        else:
            adjudications = [graph.nodes[a] for a in adjudicators]
            if node["requires_independent_adjudication"] and not any(
                a.get("independence") == "INDEPENDENT" for a in adjudications
            ):
                reasons.append("not_independent")
            if not any(a.get("verdict") in allowed for a in adjudications):
                reasons.append("adjudication_refuses")
        if not reasons:
            continue
        reasons.sort()
        yield Orphan(
            id=f"ORPHAN-3:{nid}",
            cls=3,
            node=nid,
            reason="+".join(reasons),
            detail=(
                f"release claim {nid} claims {claimed!r} with "
                f"{len(adjudicators)} adjudication(s); unsatisfied: {', '.join(reasons)}"
            ),
        )


def _class_4_and_8(graph: Graph, blobs: Blobs) -> Iterable[Orphan]:
    for nid, node in graph.nodes.items():
        source = node["source"]
        commit = source.get("bound_commit", graph.commit)
        path = source["path"]
        if not blobs.has_commit(commit):
            raise Refusal(
                "TG_COMMIT_UNRESOLVED",
                f"node {nid!r} names bound_commit {commit!r}, which does not resolve",
            )
        data = blobs.blob(commit, path)
        if data is None:
            yield Orphan(
                id=f"ORPHAN-8:{nid}:{path}",
                cls=8,
                node=nid,
                reason="path_absent",
                detail=f"{path} does not exist at {commit}",
            )
            continue
        recorded = source.get("sha256")
        if recorded == "UNKNOWN" or not _is_sha256(recorded):
            continue
        actual = hashlib.sha256(data).hexdigest()
        if actual != recorded:
            yield Orphan(
                id=f"ORPHAN-4:{nid}",
                cls=4,
                node=nid,
                reason="digest_mismatch",
                detail=(
                    f"{path} at {commit}: recorded {recorded}, actual {actual} "
                    f"(the node is bound to a different artefact identity)"
                ),
            )
        # An evidence node that names the artefact it was produced from must
        # agree with that artefact's recorded digest.
        bound = node.get("bound_artefact")
        if node["type"] == "evidence" and isinstance(bound, str):
            artefact = graph.nodes.get(bound)
            if artefact is None:
                raise Refusal(
                    "TG_UNKNOWN_ARTEFACT",
                    f"evidence {nid!r} names absent artefact {bound!r}",
                )
            if artefact.get("digest") != recorded:
                yield Orphan(
                    id=f"ORPHAN-4:{nid}",
                    cls=4,
                    node=nid,
                    reason="bound_artefact_mismatch",
                    detail=(
                        f"evidence {nid} records {recorded} but its bound artefact "
                        f"{bound} records {artefact.get('digest')}"
                    ),
                )

    # Evidence cited by an implementation must be bound to the same identity
    # as that implementation.  A different bound commit is a different
    # artefact: the evidence may still be real, but it supports a different
    # candidate and cannot support this implementation.
    for edge in graph.edges:
        if edge["type"] != "evidenced_by":
            continue
        source = graph.nodes[edge["from"]]
        target = graph.nodes[edge["to"]]
        if source["type"] != "implementation" or target["type"] != "evidence":
            continue
        impl_commit = source["source"].get("bound_commit", graph.commit)
        ev_commit = target["source"].get("bound_commit", graph.commit)
        if impl_commit != ev_commit:
            yield Orphan(
                id=f"ORPHAN-4:{edge['to']}",
                cls=4,
                node=edge["to"],
                reason="support_identity_mismatch",
                detail=(
                    f"evidence {edge['to']} is cited by implementation {edge['from']} but is "
                    f"bound to {ev_commit}, while the implementation is bound to {impl_commit}"
                ),
            )


def _class_5(graph: Graph) -> Iterable[Orphan]:
    for nid, node in graph.nodes.items():
        if node["type"] != "obligation":
            continue
        reachable = set(_out(graph, nid, "constrains"))
        for claim in node.get("blocks_release_claims", []):
            if claim in reachable:
                continue
            yield Orphan(
                id=f"ORPHAN-5:{nid}:{claim}",
                cls=5,
                node=nid,
                reason="unreachable_block",
                detail=(
                    f"obligation {nid} declares that it blocks {claim}, but there is no "
                    "constrains edge, so the omission is invisible from the claim"
                ),
            )


def _class_6(graph: Graph) -> Iterable[Orphan]:
    for nid, node in graph.nodes.items():
        if node["type"] == "requirement" and node.get("specification_required"):
            if not _out(graph, nid, "refines"):
                yield Orphan(
                    id=f"ORPHAN-6:REQ:{nid}",
                    cls=6,
                    node=nid,
                    reason="requirement_without_specification",
                    detail=(
                        f"requirement {nid} declares that an independent specification is "
                        "required, but no specification refines it"
                    ),
                )
        if node["type"] == "specification":
            if not _reaches_type(graph, nid, "implementation"):
                yield Orphan(
                    id=f"ORPHAN-6:SPEC:{nid}",
                    cls=6,
                    node=nid,
                    reason="specification_without_implementation",
                    detail=(
                        f"specification {nid} reaches no implementation along the trace direction"
                    ),
                )


def _reaches_type(graph: Graph, start: str, wanted: str) -> bool:
    seen = {start}
    stack = [start]
    while stack:
        current = stack.pop()
        for edge in graph.out.get(current, []):
            target = edge["to"]
            if target in seen:
                continue
            if graph.nodes[target]["type"] == wanted:
                return True
            seen.add(target)
            stack.append(target)
    return False


def _class_9(graph: Graph) -> Iterable[Orphan]:
    """A level with no obligation: the chain does not connect it."""
    levels = {
        nid: node for nid, node in graph.nodes.items()
        if node["type"] == "refinement_level"
    }
    if not levels:
        return
    ranks = sorted(node["rank"] for node in levels.values())
    low, high = ranks[0], ranks[-1]
    for nid, node in levels.items():
        rank = node["rank"]
        if rank > low and not _in(graph, nid, "discharges"):
            yield Orphan(
                id=f"ORPHAN-9:{nid}",
                cls=9,
                node=nid,
                reason="level_without_obligation",
                detail=(
                    f"level {nid} (rank {rank}) has no incoming discharges edge, so the "
                    "obligation that connects it to the previous level is absent"
                ),
            )
        if rank < high and not _out(graph, nid, "refines_to"):
            yield Orphan(
                id=f"ORPHAN-9:{nid}",
                cls=9,
                node=nid,
                reason="level_without_obligation",
                detail=(
                    f"level {nid} (rank {rank}) has no outgoing refines_to edge, so no "
                    "refinement obligation leaves it"
                ),
            )


def _class_10(graph: Graph) -> Iterable[Orphan]:
    """A refinement obligation with no artefact that records it."""
    for nid, node in graph.nodes.items():
        if node["type"] != "refinement_edge":
            continue
        obligation = node.get("obligation")
        target = graph.nodes.get(obligation) if isinstance(obligation, str) else None
        if target is None or target["type"] != "obligation":
            yield Orphan(
                id=f"ORPHAN-10:{nid}",
                cls=10,
                node=nid,
                reason="obligation_without_artefact",
                detail=f"refinement edge {nid} names no resolvable obligation ({obligation!r})",
            )
            continue
        artefact = node.get("obligation_artefact")
        artefact_node = graph.nodes.get(artefact) if isinstance(artefact, str) else None
        if artefact_node is None or artefact_node["type"] != "artefact":
            yield Orphan(
                id=f"ORPHAN-10:{nid}",
                cls=10,
                node=nid,
                reason="obligation_without_artefact",
                detail=(
                    f"obligation {obligation} on edge {nid} names no resolvable "
                    f"artefact ({artefact!r})"
                ),
            )


def _class_12(graph: Graph) -> Iterable[Orphan]:
    """An unsafe-obligation node whose inventory still holds uncovered sites.

    ETP-T4's inventory records, per obligation class, how many sites have a
    validity argument or a control that could fail and how many do not.  A class
    with at least one site in the second set is an omission from the graph, not
    a satisfied obligation.
    """
    for nid, node in graph.nodes.items():
        if node["type"] != "obligation":
            continue
        inventory = node.get("unsafe_site_inventory")
        if not isinstance(inventory, dict):
            continue
        uncovered = inventory.get("sites_without_contract_or_control")
        if not isinstance(uncovered, int) or isinstance(uncovered, bool):
            raise Refusal(
                "TG_UNSAFE_INVENTORY",
                f"obligation {nid!r} unsafe_site_inventory.sites_without_contract_or_control "
                "is not an integer",
            )
        if uncovered > 0:
            yield Orphan(
                id=f"ORPHAN-12:{nid}",
                cls=12,
                node=nid,
                reason="no_contract_or_control",
                detail=(
                    f"obligation {nid} covers {inventory.get('sites')} site(s) of class "
                    f"{inventory.get('class')}; {uncovered} have neither a validity argument "
                    "nor a control that could fail"
                ),
            )


def _class_13(graph: Graph) -> Iterable[Orphan]:
    """A closure omission that fails the independently checkable bar.

    ETP-T10 requires every omitted edge to carry an exclusion argument a third
    party can check.  An obligation node carrying ``closure_exclusions`` with a
    positive ``failing_rows`` count names omissions that do not meet the bar; a
    release claim that asserts ``SAFE_COMPATIBLE`` while such an obligation
    constrains it is the same failure seen from the claim.  Both are recorded
    as orphans rather than dropped, so the omission is visible from the claim.
    """
    for nid, node in graph.nodes.items():
        if node["type"] == "obligation":
            exclusions = node.get("closure_exclusions")
            if not isinstance(exclusions, dict):
                continue
            failing = exclusions.get("failing_rows", 0)
            if failing > 0:
                yield Orphan(
                    id=f"ORPHAN-13:{nid}",
                    cls=13,
                    node=nid,
                    reason="exclusion_fails_bar",
                    detail=(
                        f"obligation {nid} records {failing} of "
                        f"{exclusions.get('rows', 0)} exclusion(s) in category "
                        f"{exclusions.get('category')!r} that fail the checkable "
                        "bar"),
                )
        elif node["type"] == "release_claim":
            if node.get("claimed_verdict") not in POSITIVE_VERDICTS:
                continue
            failing = [
                source for source in _in(graph, nid, "constrains")
                if isinstance(graph.nodes[source].get("closure_exclusions"), dict)
                and graph.nodes[source]["closure_exclusions"].get("failing_rows", 0) > 0
            ]
            if failing:
                yield Orphan(
                    id=f"ORPHAN-13:CLAIM:{nid}",
                    cls=13,
                    node=nid,
                    reason="safe_compatible_with_failing_exclusion",
                    detail=(
                        f"release claim {nid} asserts {node.get('claimed_verdict')} "
                        "while constrained by obligations with failing closure "
                        f"exclusions: {', '.join(sorted(failing))}"),
                )


def _class_11(graph: Graph) -> Iterable[Orphan]:
    """A refinement edge with no discharge of its obligation."""
    for nid, node in graph.nodes.items():
        if node["type"] != "refinement_edge":
            continue
        status = node.get("status")
        if status == "NONE":
            yield Orphan(
                id=f"ORPHAN-11:{nid}",
                cls=11,
                node=nid,
                reason="edge_without_discharge",
                detail=(
                    f"refinement edge {nid} is recorded as NONE; no discharge of its "
                    "obligation exists"
                ),
            )
            continue
        if status not in ("BOUNDED", "PARTIAL"):
            continue
        discharged_by = node.get("discharged_by", "")
        artefact = node.get("discharge_artefact")
        target = graph.nodes.get(artefact) if isinstance(artefact, str) else None
        if not discharged_by.strip() or discharged_by == "UNASSIGNED":
            yield Orphan(
                id=f"ORPHAN-11:{nid}",
                cls=11,
                node=nid,
                reason="edge_without_discharge",
                detail=f"refinement edge {nid} claims {status} but names no discharger",
            )
        elif target is None or target["type"] != "artefact":
            yield Orphan(
                id=f"ORPHAN-11:{nid}",
                cls=11,
                node=nid,
                reason="edge_without_discharge",
                detail=(
                    f"refinement edge {nid} claims {status} but names no resolvable "
                    f"discharge artefact ({artefact!r})"
                ),
            )
        elif status == "BOUNDED" and not node.get("bounded_population"):
            yield Orphan(
                id=f"ORPHAN-11:{nid}",
                cls=11,
                node=nid,
                reason="edge_without_population",
                detail=f"refinement edge {nid} claims BOUNDED but names no bounded population",
            )


def _class_7(graph: Graph) -> Iterable[Orphan]:
    """Tarjan's strongly connected components; every SCC of size > 1 is a cycle."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    counter = [0]
    components: list[list[str]] = []

    def strongconnect(root: str) -> None:
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, position = work[-1]
            if position == 0:
                index[node] = counter[0]
                low[node] = counter[0]
                counter[0] += 1
                stack.append(node)
                on_stack.add(node)
            advanced = False
            neighbours = [
                e["to"] for e in sorted(graph.out.get(node, []), key=lambda e: (e["type"], e["to"]))
            ]
            while position < len(neighbours):
                target = neighbours[position]
                position += 1
                if target not in index:
                    work[-1] = (node, position)
                    work.append((target, 0))
                    advanced = True
                    break
                if target in on_stack:
                    low[node] = min(low[node], index[target])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                if len(component) > 1 or any(
                    e["to"] == component[0] for e in graph.out.get(component[0], [])
                ):
                    components.append(sorted(component))

    for nid in sorted(graph.nodes):
        if nid not in index:
            strongconnect(nid)

    for component in sorted(components):
        members = "+".join(component)
        yield Orphan(
            id=f"ORPHAN-7:{members}",
            cls=7,
            node=component[0],
            reason="support_cycle",
            detail="cycle in the support direction: " + " -> ".join(component + component[:1]),
        )


# --------------------------------------------------------------------------
# Orphan register reconciliation
# --------------------------------------------------------------------------


def declared_orphans(graph: Graph) -> dict[str, dict[str, Any]]:
    declared = graph.document.get("orphans")
    if not isinstance(declared, list):
        raise Refusal("TG_SCHEMA", "orphans must be an array")
    result: dict[str, dict[str, Any]] = {}
    for entry in declared:
        oid = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(oid, str) or not oid:
            raise Refusal("TG_SCHEMA", "a declared orphan has no id")
        if oid in result:
            raise Refusal("TG_DUPLICATE_ORPHAN", f"declared orphan {oid!r} is duplicated")
        if not isinstance(entry.get("would_close"), str) or not entry["would_close"]:
            raise Refusal(
                "TG_ORPHAN_UNSETTLED",
                f"declared orphan {oid!r} does not state what would close it",
            )
        result[oid] = entry
    return result


def reconcile(
    discovered: list[Orphan], declared: dict[str, dict[str, Any]]
) -> tuple[list[str], list[str], list[str]]:
    errors: list[str] = []
    found = {o.id: o for o in discovered}
    for oid in sorted(found):
        if oid not in declared:
            errors.append(
                f"TG_UNDECLARED_ORPHAN: {oid} [{found[oid].reason}] ({found[oid].detail}); "
                "record it in the orphans register with what would close it"
            )
    for oid in sorted(declared):
        if oid not in found:
            errors.append(
                f"TG_STALE_ORPHAN: {oid} is declared but no longer reproduces; "
                "remove it or correct the graph"
            )
            continue
        if declared[oid].get("reason") != found[oid].reason:
            errors.append(
                f"TG_ORPHAN_REASON: {oid} declares reason {declared[oid].get('reason')!r}, "
                f"the graph produces {found[oid].reason!r}"
            )
    return errors, sorted(found), sorted(declared)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def counts(graph: Graph, orphans: list[Orphan]) -> dict[str, Any]:
    node_counts = {t: 0 for t in sorted(NODE_TYPES)}
    for node in graph.nodes.values():
        node_counts[node["type"]] += 1
    edge_counts: dict[str, int] = {t: 0 for t in sorted(EDGE_RULES)}
    for edge in graph.edges:
        edge_counts[edge["type"]] += 1
    orphan_counts = {c: 0 for c in sorted(CLASS_NAMES)}
    for orphan in orphans:
        orphan_counts[orphan.cls] += 1
    unsettled = [
        nid
        for nid, node in graph.nodes.items()
        if node["source"].get("sha256") == "UNKNOWN"
    ]
    return {
        "commit": graph.commit,
        "nodes": node_counts,
        "edges": edge_counts,
        "orphans": orphan_counts,
        "total_nodes": len(graph.nodes),
        "total_edges": len(graph.edges),
        "total_orphans": len(orphans),
        "unsettled_digests": sorted(unsettled),
    }


def command_validate(graph_path: Path, repo: Path) -> int:
    graph = load_graph(graph_path, repo)
    discovered = detect_orphans(graph, repo)
    declared = declared_orphans(graph)
    errors, found_ids, declared_ids = reconcile(discovered, declared)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return EXIT_REFUSED
    summary = counts(graph, discovered)
    node_total = ", ".join(
        f"{t}={n}" for t, n in summary["nodes"].items() if n
    )
    edge_total = ", ".join(
        f"{t}={n}" for t, n in summary["edges"].items() if n
    )
    print(
        f"traceability graph at {summary['commit']}: "
        f"{summary['total_nodes']} nodes ({node_total}); "
        f"{summary['total_edges']} edges ({edge_total})"
    )
    print(
        f"orphans: {summary['total_orphans']} declared and reproduced "
        f"({len(found_ids)} ids), 0 undeclared, 0 stale"
    )
    return EXIT_OK


def command_report(graph_path: Path, repo: Path, as_json: bool) -> int:
    graph = load_graph(graph_path, repo)
    discovered = detect_orphans(graph, repo)
    declared = declared_orphans(graph)
    errors, _, _ = reconcile(discovered, declared)
    summary = counts(graph, discovered)
    payload = dict(summary)
    payload["orphan_register_errors"] = errors
    payload["orphans_detail"] = [o.as_dict() for o in discovered]
    payload["declared_would_close"] = {
        oid: declared[oid]["would_close"] for oid in sorted(declared)
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return EXIT_OK if not errors else EXIT_REFUSED

    print(f"graph: {graph_path}")
    print(f"commit: {summary['commit']}")
    print("nodes by type:")
    for ntype, count in summary["nodes"].items():
        print(f"  {ntype:16s} {count}")
    print("edges by type:")
    for etype, count in summary["edges"].items():
        print(f"  {etype:16s} {count}")
    print("orphans by class:")
    for cls, count in summary["orphans"].items():
        print(f"  {cls} {CLASS_NAMES[cls]:58s} {count}")
    print(f"total orphans: {summary['total_orphans']}")
    for orphan in discovered:
        print(f"  {orphan.id}  [{orphan.reason}]")
    if summary["unsettled_digests"]:
        print("unsettled digests:")
        for nid in summary["unsettled_digests"]:
            print(f"  {nid}")
    if errors:
        print("orphan register errors:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return EXIT_REFUSED
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "command", choices=("validate", "report"), help="validate, or summarise orphans"
    )
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            return command_validate(args.graph, args.repo_root)
        return command_report(args.graph, args.repo_root, args.json)
    except Refusal as refusal:
        print(f"{refusal.code}: {refusal.detail}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
