#!/usr/bin/env python3
"""frc_registers.py -- validate the FRC-0 registers of what is and is not established.

Why this tool exists
--------------------
FRC-0 asks three questions and refuses to answer any of them by assertion:

  * for each reference result, what it proves, what it assumes, what this project
    currently proves, and which additional theorem would be a genuine improvement;
  * a specification hierarchy for P-256 field and scalar arithmetic whose every
    level is anchored in a normative source, never in the implementation;
  * for each candidate prover, whether it is admitted, with a pinned version and
    digest, a theorem class, a TCB, a positive and a negative control, and the
    rustc range it actually supports.

The registers are prose-shaped claims, so this tool enforces the rules that keep a
prose claim honest:

  * every entry is classified, and an unverified entry names the method that
    would settle it;
  * a project that records ``NONE`` claims nothing, and one that records evidence
    must cite a path that exists;
  * a claim to exceed the frontier names BOTH the matched property and the added
    property, and the matched property must itself be established -- matching is
    the precondition for exceeding (FRC programme section 9);
  * a tool is admitted only with every admission field present, and a refused
    tool says why;
  * a recorded digest must occur in the record that is cited for it, so a digest
    cannot be invented;
  * a specification level is never sourced from the implementation (Earned Trust
    Article 6), and a refinement edge is never ``DISCHARGED`` without a
    machine-checked proof artefact;
  * the hierarchy agrees with the authoritative ETP-T3 refinement record, and a
    DO-178C entry records objective satisfaction rather than certification;
  * the normative document names every level, edge, frontier entry, tool and
    refusal code the machine record contains, so the two cannot drift apart.

What this tool does not do
--------------------------
It does not read a standard, run a prover, build a binary, measure a channel or
decide whether a cited experiment occurred. It checks that the registers do not
claim more than their own evidence, not that the evidence is sufficient. An
admission is still a review act: this tool can refuse an incomplete admission, but
it cannot certify that a complete-looking one is true.

Determinism
-----------
``check`` reads only its inputs and returns refusals sorted by (code, detail).
The CLI prints one line per refusal and a final ``codes=`` line. No timestamp is
written by the validator, and the summary is serialised with sorted keys.

Usage
-----
    python3 forensics/tools/frc_registers.py check [--json]
    python3 forensics/tools/frc_registers.py inventory [--json]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

FRONTIER = "evidence/frc/FRONTIER-GAPS.json"
HIERARCHY = "evidence/frc/SPECIFICATION-HIERARCHY.json"
TOOLS = "forensics/frc/TOOLS.json"
DOCUMENT = "docs/SPECIFICATION-HIERARCHY.md"
REFINEMENT = "evidence/etp-t3/REFINEMENT.json"

SCHEMA_FRONTIER = "openssl-rs/frc/frontier-gaps/1"
SCHEMA_HIERARCHY = "openssl-rs/frc/specification-hierarchy/1"
SCHEMA_TOOLS = "openssl-rs/frc/tool-admission/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "FR_OK"
CODE_USAGE = "FR_REFUSED_USAGE"

# A project-state value that means "this project claims to prove something" must
# carry evidence; ESTABLISHED additionally carries a proof artefact.
PROJECT_STATES = ("NONE", "BOUNDED_EVIDENCE", "PARTIAL", "ESTABLISHED")
PROVEN_STATES = {"BOUNDED_EVIDENCE", "PARTIAL", "ESTABLISHED"}
EDGE_STATES = ("NONE", "PARTIAL", "NOT_ESTABLISHED", "DISCHARGED")
VERIFICATION_STATES = ("OBSERVED_THIS_SESSION", "RECORDED_BY_THIS_PROJECT", "UNVERIFIED")
CLASSIFICATIONS = (
    "REFERENCE_PROOF",
    "REFERENCE_RESIDUAL_RISK",
    "REFERENCE_ENVIRONMENT_ASSUMPTION",
    "PROJECT_GAP",
    "DO_178C_OBJECTIVE",
    "FRONTIER_DIMENSION",
)
ADMISSIONS = ("ADMITTED", "REFUSED")
PROOF_KINDS = ("MACHINE_CHECKED_THEOREM", "TRANSLATION_VALIDATION")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ENTRY_ID = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$")

# ---------------------------------------------------------------------------
# Refusal codes.  Each names the wrong conclusion it prevents.  The normative
# document must name every code here; the test suite refuses drift between the
# two, and each code has a negative control that fires it.
# ---------------------------------------------------------------------------

REFUSALS: dict[str, dict[str, str]] = {
    "FR_REFUSED_SCHEMA": {
        "condition": "a register has the wrong schema, a missing or mistyped field, "
                     "a malformed identifier, or an enum value outside its closed set",
        "prevents": "that an unreadable or out-of-vocabulary entry is read as a claim",
    },
    "FR_REFUSED_DUPLICATE_KEY": {
        "condition": "a JSON object repeats a key at any depth",
        "prevents": "that last-wins parsing silently drops one of two values",
    },
    "FR_REFUSED_UNCLASSIFIED_CLAIM": {
        "condition": "a frontier entry has no classification, or a refinement edge "
                     "has no status in the declared vocabulary",
        "prevents": "that a claim sits outside the typology and is never examined",
    },
    "FR_REFUSED_UNVERIFIED_WITHOUT_METHOD": {
        "condition": "a verification block is UNVERIFIED and names no settling method",
        "prevents": "that an unverified item is presented as settled by omission",
    },
    "FR_REFUSED_VERIFICATION_WITHOUT_SOURCE": {
        "condition": "a verification block claims an observation or a project record "
                     "but names no witness, or names a witness that does not exist",
        "prevents": "that verification is asserted without a readable witness",
    },
    "FR_REFUSED_PROVEN_WITHOUT_EVIDENCE": {
        "condition": "this project records BOUNDED_EVIDENCE, PARTIAL or ESTABLISHED "
                     "with no evidence path, a missing evidence path, or ESTABLISHED "
                     "with no proof artefact",
        "prevents": "that a claim of proof outruns the evidence that could support it",
    },
    "FR_REFUSED_FRONTIER_WITHOUT_BOTH_PROPERTIES": {
        "condition": "a beyond-frontier claim does not name both the matched property "
                     "and the added property",
        "prevents": "that exceeding the frontier is claimed without stating what was "
                    "matched and what was added",
    },
    "FR_REFUSED_EXCEEDS_FRONTIER_UNPROVEN": {
        "condition": "a beyond-frontier claim names a matched entry that is unresolved "
                     "or is not ESTABLISHED for this project",
        "prevents": "that exceeding the frontier is claimed before the frontier was matched",
    },
    "FR_REFUSED_TOOL_ADMITTED_INCOMPLETE": {
        "condition": "a tool is ADMITTED without a pinned version, a sourced digest, a "
                     "theorem class, a TCB, a positive control, a negative control, a "
                     "supported rustc range, or support for the pinned compiler",
        "prevents": "that a tool is admitted on reputation rather than on its controls",
    },
    "FR_REFUSED_TOOL_REFUSAL_WITHOUT_REASON": {
        "condition": "a tool is REFUSED and the record states no reason",
        "prevents": "that a refusal is recorded as an unexplained absence",
    },
    "FR_REFUSED_SPECIFICATION_RESTATES_IMPLEMENTATION": {
        "condition": "a hierarchy level is marked implementation-derived, or a "
                     "normative source or the document names an internal source path",
        "prevents": "that a specification is generated by restating the implementation",
    },
    "FR_REFUSED_REFINEMENT_DISCHARGED_WITHOUT_PROOF": {
        "condition": "a refinement edge is DISCHARGED without a machine-checked or "
                     "translation-validation proof artefact",
        "prevents": "that a differential, a test or a build identity is recorded as a "
                    "discharged refinement edge",
    },
    "FR_REFUSED_HIERARCHY_DRIFT": {
        "condition": "a hierarchy level or edge disagrees with the authoritative ETP-T3 "
                     "refinement record in identity, direction or status",
        "prevents": "that the FRC hierarchy claims a different refinement state from the "
                    "one the project already records",
    },
    "FR_REFUSED_DIGEST_UNSOURCED": {
        "condition": "a tool digest is malformed, or does not occur in the record cited "
                     "for it",
        "prevents": "that a digest is invented or attached to the wrong tool",
    },
    "FR_REFUSED_DO178_CERTIFICATION": {
        "condition": "a DO-178C entry claims certification rather than objective "
                     "satisfaction, or the document omits that distinction",
        "prevents": "that satisfying objectives is reported as certification",
    },
    "FR_REFUSED_DOCUMENT_DRIFT": {
        "condition": "the normative document does not name a level, edge, frontier "
                     "entry, tool or refusal code the machine record contains",
        "prevents": "that the prose and the machine record describe different claims",
    },
    "FR_REFUSED_USAGE": {
        "condition": "the command line is malformed or names an unknown subcommand",
        "prevents": "that a refusal is read as a pass by exit-status confusion",
    },
}


class Refusal(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise Refusal("FR_REFUSED_DUPLICATE_KEY", f"duplicate object key {key!r}")
        seen[key] = value
    return seen


def _reject_nonfinite(token: str) -> Any:
    raise Refusal("FR_REFUSED_SCHEMA", f"non-finite number {token!r}")


def load_json_strict(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal("FR_REFUSED_SCHEMA", f"{path}: unreadable: {exc}") from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate,
                          parse_constant=_reject_nonfinite)
    except json.JSONDecodeError as exc:
        raise Refusal("FR_REFUSED_SCHEMA", f"{path}: malformed JSON: {exc}") from exc


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _list(value: Any) -> bool:
    return isinstance(value, list)


def _exists(repo: Path, relpath: str) -> bool:
    candidate = Path(relpath)
    if candidate.is_absolute() or ".." in candidate.parts or not relpath:
        return False
    return (repo / relpath).is_file()


def _verification_problems(
    blocks: list[tuple[str, Any]], repo: Path
) -> list[tuple[str, str]]:
    """The two verification laws, shared by frontier entries and tools."""
    out: list[tuple[str, str]] = []
    for where, block in blocks:
        if not isinstance(block, dict):
            out.append(("FR_REFUSED_SCHEMA", f"{where}: verification is not an object"))
            continue
        state = block.get("state")
        if state not in VERIFICATION_STATES:
            out.append(("FR_REFUSED_SCHEMA", f"{where}: verification state {state!r}"))
            continue
        if state == "UNVERIFIED" and not _text(block.get("settling_method")):
            out.append(("FR_REFUSED_UNVERIFIED_WITHOUT_METHOD",
                        f"{where}: UNVERIFIED with no settling method"))
        if state != "UNVERIFIED":
            witness = block.get("witness")
            if not _text(witness) or not _exists(repo, witness):
                out.append(("FR_REFUSED_VERIFICATION_WITHOUT_SOURCE",
                            f"{where}: {state} cites no readable witness"))
    return out


# ---------------------------------------------------------------------------
# Frontier register
# ---------------------------------------------------------------------------


def validate_frontier(doc: Any, repo: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not isinstance(doc, dict):
        return [("FR_REFUSED_SCHEMA", "frontier register is not an object")]
    if doc.get("schema") != SCHEMA_FRONTIER:
        out.append(("FR_REFUSED_SCHEMA", f"frontier schema is {doc.get('schema')!r}"))
    if not COMMIT.match(str(doc.get("base_commit", ""))):
        out.append(("FR_REFUSED_SCHEMA", "frontier base_commit is not a 40-hex commit"))
    entries = doc.get("entries")
    if not _list(entries) or not entries:
        return out + [("FR_REFUSED_SCHEMA", "frontier entries must be a non-empty array")]

    ids: set[str] = set()
    by_id: dict[str, Any] = {}
    blocks: list[tuple[str, Any]] = []
    for index, entry in enumerate(entries):
        where = f"frontier[{index}]"
        if not isinstance(entry, dict):
            out.append(("FR_REFUSED_SCHEMA", f"{where}: not an object"))
            continue
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not ENTRY_ID.match(entry_id):
            out.append(("FR_REFUSED_SCHEMA", f"{where}: bad id {entry_id!r}"))
            continue
        if entry_id in ids:
            out.append(("FR_REFUSED_SCHEMA", f"{where}: duplicate id {entry_id}"))
        ids.add(entry_id)
        by_id[entry_id] = entry
        for field in ("reference", "proves", "assumes", "additional_theorem"):
            if not _text(entry.get(field)):
                out.append(("FR_REFUSED_SCHEMA", f"{entry_id}: {field} is empty"))
        classification = entry.get("classification")
        if classification not in CLASSIFICATIONS:
            out.append(("FR_REFUSED_UNCLASSIFIED_CLAIM",
                        f"{entry_id}: classification {classification!r}"))
        verification = entry.get("verification")
        blocks.append((entry_id, verification))

        project = entry.get("this_project")
        if not isinstance(project, dict):
            out.append(("FR_REFUSED_SCHEMA", f"{entry_id}: this_project is not an object"))
        else:
            state = project.get("state")
            if state not in PROJECT_STATES:
                out.append(("FR_REFUSED_SCHEMA", f"{entry_id}: project state {state!r}"))
            else:
                if not _text(project.get("basis")):
                    out.append(("FR_REFUSED_SCHEMA", f"{entry_id}: project basis is empty"))
                evidence = project.get("evidence")
                if state in PROVEN_STATES and (not _list(evidence) or not evidence):
                    out.append(("FR_REFUSED_PROVEN_WITHOUT_EVIDENCE",
                                f"{entry_id}: {state} with no evidence path"))
                if _list(evidence):
                    for path in evidence:
                        if not _text(path) or not _exists(repo, path):
                            out.append(("FR_REFUSED_PROVEN_WITHOUT_EVIDENCE",
                                        f"{entry_id}: evidence {path!r} is not a file"))
                if state == "ESTABLISHED" and not _text(project.get("proof_artefact")):
                    out.append(("FR_REFUSED_PROVEN_WITHOUT_EVIDENCE",
                                f"{entry_id}: ESTABLISHED with no proof artefact"))

        beyond = entry.get("beyond_frontier")
        if beyond is not None:
            if not isinstance(beyond, dict):
                out.append(("FR_REFUSED_SCHEMA", f"{entry_id}: beyond_frontier is not an object"))
            elif beyond.get("claim") is True:
                matched = beyond.get("matched_property")
                added = beyond.get("added_property")
                if not _text(matched) or not _text(added):
                    out.append(("FR_REFUSED_FRONTIER_WITHOUT_BOTH_PROPERTIES",
                                f"{entry_id}: beyond-frontier claim names "
                                "matched_property and added_property required"))
                target = beyond.get("matched_entry")
                if not _text(target) or target not in by_id:
                    out.append(("FR_REFUSED_EXCEEDS_FRONTIER_UNPROVEN",
                                f"{entry_id}: matched_entry {target!r} does not resolve"))
                elif by_id[target].get("this_project", {}).get("state") != "ESTABLISHED":
                    out.append(("FR_REFUSED_EXCEEDS_FRONTIER_UNPROVEN",
                                f"{entry_id}: matched entry {target} is not ESTABLISHED "
                                "for this project"))

        if classification == "DO_178C_OBJECTIVE":
            if entry.get("certification_claimed") is not False or \
                    entry.get("objective_satisfaction_only") is not True:
                out.append(("FR_REFUSED_DO178_CERTIFICATION",
                            f"{entry_id}: a DO-178C entry must record objective "
                            "satisfaction and not certification"))

    out.extend(_verification_problems(blocks, repo))
    return out


# ---------------------------------------------------------------------------
# Specification hierarchy
# ---------------------------------------------------------------------------


def _load_refinement(repo: Path) -> dict[str, Any] | None:
    path = repo / REFINEMENT
    if not path.is_file():
        return None
    return load_json_strict(path)


def validate_hierarchy(
    doc: Any, repo: Path, refinement: dict[str, Any] | None = None
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not isinstance(doc, dict):
        return [("FR_REFUSED_SCHEMA", "hierarchy register is not an object")]
    if doc.get("schema") != SCHEMA_HIERARCHY:
        out.append(("FR_REFUSED_SCHEMA", f"hierarchy schema is {doc.get('schema')!r}"))
    levels = doc.get("levels")
    edges = doc.get("edges")
    if not _list(levels) or not levels:
        return out + [("FR_REFUSED_SCHEMA", "hierarchy levels must be a non-empty array")]
    if not _list(edges) or not edges:
        return out + [("FR_REFUSED_SCHEMA", "hierarchy edges must be a non-empty array")]

    level_ids: list[str] = []
    blocks: list[tuple[str, Any]] = []
    for index, level in enumerate(levels):
        where = f"hierarchy.level[{index}]"
        if not isinstance(level, dict) or not _text(level.get("id")):
            out.append(("FR_REFUSED_SCHEMA", f"{where}: no string id"))
            continue
        level_id = level["id"]
        level_ids.append(level_id)
        for field in ("name", "constrains"):
            if not _text(level.get(field)):
                out.append(("FR_REFUSED_SCHEMA", f"{level_id}: {field} is empty"))
        if level.get("implementation_derived") is not False:
            out.append(("FR_REFUSED_SPECIFICATION_RESTATES_IMPLEMENTATION",
                        f"{level_id}: implementation_derived must be false"))
        sources = level.get("normative_sources")
        if not _list(sources) or not sources:
            out.append(("FR_REFUSED_SCHEMA", f"{level_id}: no normative source"))
            continue
        for source in sources:
            if not isinstance(source, dict):
                out.append(("FR_REFUSED_SCHEMA", f"{level_id}: source is not an object"))
                continue
            for field in ("document", "clause", "edition"):
                if not _text(source.get(field)):
                    out.append(("FR_REFUSED_SCHEMA", f"{level_id}: source {field} is empty"))
            blob = " ".join(str(source.get(field, "")) for field in
                            ("document", "clause", "edition", "locator"))
            if "src/" in blob or "crate::" in blob or "super::" in blob or "self::" in blob:
                out.append(("FR_REFUSED_SPECIFICATION_RESTATES_IMPLEMENTATION",
                            f"{level_id}: a normative source names an implementation path"))
            blocks.append((f"{level_id}.source", source.get("verification")))

    if len(set(level_ids)) != len(level_ids):
        out.append(("FR_REFUSED_SCHEMA", "hierarchy levels repeat an id"))

    edge_ids: list[str] = []
    for index, edge in enumerate(edges):
        where = f"hierarchy.edge[{index}]"
        if not isinstance(edge, dict) or not _text(edge.get("id")):
            out.append(("FR_REFUSED_SCHEMA", f"{where}: no string id"))
            continue
        edge_id = edge["id"]
        edge_ids.append(edge_id)
        for field in ("from", "to", "obligation", "reason"):
            if not _text(edge.get(field)):
                out.append(("FR_REFUSED_SCHEMA", f"{edge_id}: {field} is empty"))
        for endpoint in ("from", "to"):
            if edge.get(endpoint) not in level_ids:
                out.append(("FR_REFUSED_SCHEMA",
                            f"{edge_id}: {endpoint} {edge.get(endpoint)!r} is not a level"))
        status = edge.get("status")
        if status not in EDGE_STATES:
            out.append(("FR_REFUSED_UNCLASSIFIED_CLAIM",
                        f"{edge_id}: edge status {status!r}"))
        elif status == "DISCHARGED":
            proof = edge.get("proof")
            if not isinstance(proof, dict):
                out.append(("FR_REFUSED_REFINEMENT_DISCHARGED_WITHOUT_PROOF",
                            f"{edge_id}: DISCHARGED with no proof object"))
            else:
                if proof.get("kind") not in PROOF_KINDS:
                    out.append(("FR_REFUSED_REFINEMENT_DISCHARGED_WITHOUT_PROOF",
                                f"{edge_id}: proof kind {proof.get('kind')!r}"))
                artefact = proof.get("artefact")
                if not _text(artefact) or not _exists(repo, artefact):
                    out.append(("FR_REFUSED_REFINEMENT_DISCHARGED_WITHOUT_PROOF",
                                f"{edge_id}: proof artefact {artefact!r} is not a file"))
        evidence = edge.get("evidence", [])
        if not _list(evidence):
            out.append(("FR_REFUSED_SCHEMA", f"{edge_id}: evidence is not an array"))
        else:
            for path in evidence:
                if not _text(path) or not _exists(repo, path):
                    out.append(("FR_REFUSED_PROVEN_WITHOUT_EVIDENCE",
                                f"{edge_id}: evidence {path!r} is not a file"))

    if len(set(edge_ids)) != len(edge_ids):
        out.append(("FR_REFUSED_SCHEMA", "hierarchy edges repeat an id"))

    if refinement is not None:
        out.extend(_hierarchy_drift(level_ids, edges, refinement))
    out.extend(_verification_problems(blocks, repo))
    return out


def _hierarchy_drift(
    level_ids: list[str], edges: list[Any], refinement: dict[str, Any]
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    recorded_levels = [entry.get("id") for entry in refinement.get("levels", [])
                       if isinstance(entry, dict)]
    if len(recorded_levels) != len(level_ids):
        out.append(("FR_REFUSED_HIERARCHY_DRIFT",
                    f"{len(level_ids)} levels against {len(recorded_levels)} recorded"))
    recorded_edges = {entry.get("id"): entry for entry in refinement.get("edges", [])
                      if isinstance(entry, dict)}
    by_id = {entry.get("id"): entry for entry in edges if isinstance(entry, dict)}
    for etp_id, recorded in recorded_edges.items():
        mine = by_id.get(etp_id)
        if not isinstance(mine, dict):
            out.append(("FR_REFUSED_HIERARCHY_DRIFT", f"recorded edge {etp_id} is absent"))
            continue
        for field in ("from", "to", "status"):
            if mine.get(field) != recorded.get(field):
                out.append(("FR_REFUSED_HIERARCHY_DRIFT",
                            f"{etp_id}: {field} is {mine.get(field)!r}, "
                            f"recorded {recorded.get(field)!r}"))
    for mine_id in by_id:
        if mine_id not in recorded_edges:
            out.append(("FR_REFUSED_HIERARCHY_DRIFT",
                        f"edge {mine_id} has no recorded counterpart"))
    return out


# ---------------------------------------------------------------------------
# Tool admission register
# ---------------------------------------------------------------------------


def validate_tools(doc: Any, repo: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not isinstance(doc, dict):
        return [("FR_REFUSED_SCHEMA", "tool register is not an object")]
    if doc.get("schema") != SCHEMA_TOOLS:
        out.append(("FR_REFUSED_SCHEMA", f"tool schema is {doc.get('schema')!r}"))
    toolchain = doc.get("pinned_toolchain")
    if not isinstance(toolchain, dict):
        out.append(("FR_REFUSED_SCHEMA", "pinned_toolchain is not an object"))
    else:
        for field in ("channel", "source"):
            if not _text(toolchain.get(field)):
                out.append(("FR_REFUSED_SCHEMA", f"pinned_toolchain.{field} is empty"))
        if _text(toolchain.get("source")) and not _exists(repo, toolchain["source"]):
            out.append(("FR_REFUSED_SCHEMA", "pinned_toolchain.source is not a file"))
    tools = doc.get("tools")
    if not _list(tools) or not tools:
        return out + [("FR_REFUSED_SCHEMA", "tools must be a non-empty array")]

    names: set[str] = set()
    blocks: list[tuple[str, Any]] = []
    for index, tool in enumerate(tools):
        where = f"tool[{index}]"
        if not isinstance(tool, dict) or not _text(tool.get("name")):
            out.append(("FR_REFUSED_SCHEMA", f"{where}: no string name"))
            continue
        name = tool["name"]
        if name in names:
            out.append(("FR_REFUSED_SCHEMA", f"{where}: duplicate tool {name}"))
        names.add(name)
        for field in ("purpose", "theorem_class", "source"):
            if not _text(tool.get(field)):
                out.append(("FR_REFUSED_SCHEMA", f"{name}: {field} is empty"))
        if _text(tool.get("source")) and not _exists(repo, tool["source"]):
            out.append(("FR_REFUSED_SCHEMA", f"{name}: source {tool['source']!r} is not a file"))
        admission = tool.get("admission")
        if admission not in ADMISSIONS:
            out.append(("FR_REFUSED_SCHEMA", f"{name}: admission {admission!r}"))
        blocks.append((name, tool.get("verification")))

        digests = tool.get("digests", [])
        if not _list(digests):
            out.append(("FR_REFUSED_SCHEMA", f"{name}: digests is not an array"))
            digests = []
        for digest in digests:
            if not isinstance(digest, dict):
                out.append(("FR_REFUSED_SCHEMA", f"{name}: digest is not an object"))
                continue
            value = digest.get("sha256")
            recorded_in = digest.get("recorded_in")
            if not isinstance(value, str) or not SHA256.match(value):
                out.append(("FR_REFUSED_DIGEST_UNSOURCED",
                            f"{name}: sha256 {value!r} is not 64 lowercase hex"))
                continue
            if not _text(recorded_in) or not _exists(repo, recorded_in):
                out.append(("FR_REFUSED_DIGEST_UNSOURCED",
                            f"{name}: digest cites no readable record"))
                continue
            if value not in (repo / recorded_in).read_text(encoding="utf-8"):
                out.append(("FR_REFUSED_DIGEST_UNSOURCED",
                            f"{name}: digest does not occur in {recorded_in}"))

        if admission == "ADMITTED":
            missing: list[str] = []
            if not _text(tool.get("pinned_version")):
                missing.append("pinned_version")
            if not digests:
                missing.append("digest")
            if not _list(tool.get("tcb")) or not tool.get("tcb"):
                missing.append("tcb")
            verification = tool.get("verification")
            if not isinstance(verification, dict) or \
                    verification.get("state") == "UNVERIFIED":
                missing.append("observation")
            for control in ("positive_control", "negative_control"):
                block = tool.get(control)
                if not isinstance(block, dict) or not _text(block.get("observed")):
                    missing.append(control)
            supported = tool.get("supported_rustc")
            if not isinstance(supported, dict):
                missing.append("supported_rustc")
            else:
                if not _text(supported.get("pinned")) or not _text(supported.get("supported")):
                    missing.append("supported_rustc")
                if supported.get("supports_pinned") is not True:
                    missing.append("supports_pinned")
            if missing:
                out.append(("FR_REFUSED_TOOL_ADMITTED_INCOMPLETE",
                            f"{name}: admitted without {', '.join(sorted(set(missing)))}"))
        elif admission == "REFUSED" and not _text(tool.get("refusal_reason")):
            out.append(("FR_REFUSED_TOOL_REFUSAL_WITHOUT_REASON",
                        f"{name}: refused with no reason"))

    selection = doc.get("selection")
    if selection is not None:
        if not isinstance(selection, dict) or not selection:
            out.append(("FR_REFUSED_SCHEMA", "selection is not a non-empty object"))
        else:
            for purpose, candidates in selection.items():
                if not _list(candidates) or not candidates:
                    out.append(("FR_REFUSED_SCHEMA",
                                f"selection[{purpose!r}] is not a non-empty array"))
                    continue
                for candidate in candidates:
                    if candidate not in names:
                        out.append(("FR_REFUSED_SCHEMA",
                                    f"selection[{purpose!r}] names unregistered tool {candidate!r}"))

    out.extend(_verification_problems(blocks, repo))
    return out


# ---------------------------------------------------------------------------
# Document synchronisation
# ---------------------------------------------------------------------------


def validate_document(
    text: str,
    frontier: Any,
    hierarchy: Any,
    tools: Any,
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not text.strip():
        return [("FR_REFUSED_DOCUMENT_DRIFT", "the normative document is empty")]
    tokens: list[tuple[str, str]] = []
    for entry in frontier.get("entries", []) if isinstance(frontier, dict) else []:
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            tokens.append(("frontier", entry["id"]))
    for level in hierarchy.get("levels", []) if isinstance(hierarchy, dict) else []:
        if isinstance(level, dict) and isinstance(level.get("id"), str):
            tokens.append(("level", level["id"]))
    for edge in hierarchy.get("edges", []) if isinstance(hierarchy, dict) else []:
        if isinstance(edge, dict) and isinstance(edge.get("id"), str):
            tokens.append(("edge", edge["id"]))
    for tool in tools.get("tools", []) if isinstance(tools, dict) else []:
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            tokens.append(("tool", tool["name"]))
    for code in REFUSALS:
        tokens.append(("code", code))
    for kind, token in tokens:
        if token not in text:
            out.append(("FR_REFUSED_DOCUMENT_DRIFT", f"{kind} {token} is not named"))
    if "src/" in text or "crate::" in text:
        out.append(("FR_REFUSED_SPECIFICATION_RESTATES_IMPLEMENTATION",
                    "the document names an implementation source path"))
    if "is not certification" not in text:
        out.append(("FR_REFUSED_DO178_CERTIFICATION",
                    "the document omits that objective satisfaction is not certification"))
    return out


# ---------------------------------------------------------------------------
# Composition, summary and CLI
# ---------------------------------------------------------------------------


def check(
    frontier: Any,
    hierarchy: Any,
    tools: Any,
    document_text: str,
    repo: Path = REPO_ROOT,
    refinement: dict[str, Any] | None = None,
) -> list[str]:
    problems: list[tuple[str, str]] = []
    problems.extend(validate_frontier(frontier, repo))
    problems.extend(validate_hierarchy(hierarchy, repo, refinement))
    problems.extend(validate_tools(tools, repo))
    problems.extend(validate_document(document_text, frontier, hierarchy, tools))
    return [f"{code}: {detail}" for code, detail in sorted(set(problems))]


def summary(
    frontier: dict[str, Any], hierarchy: dict[str, Any], tools: dict[str, Any]
) -> dict[str, Any]:
    entries = [e for e in frontier.get("entries", []) if isinstance(e, dict)]
    tool_rows = [t for t in tools.get("tools", []) if isinstance(t, dict)]
    admitted = sum(1 for t in tool_rows if t.get("admission") == "ADMITTED")
    refused = sum(1 for t in tool_rows if t.get("admission") == "REFUSED")
    unverified = sum(1 for t in tool_rows
                     if isinstance(t.get("verification"), dict)
                     and t["verification"].get("state") == "UNVERIFIED")
    edges = [e for e in hierarchy.get("edges", []) if isinstance(e, dict)]
    return {
        "frontier_entries": len(entries),
        "frontier_classified": sum(1 for e in entries
                                   if e.get("classification") in CLASSIFICATIONS),
        "frontier_project_none": sum(
            1 for e in entries
            if isinstance(e.get("this_project"), dict)
            and e["this_project"].get("state") == "NONE"),
        "levels": len(hierarchy.get("levels", [])),
        "edges": len(edges),
        "edges_discharged": sum(1 for e in edges if e.get("status") == "DISCHARGED"),
        "edges_none": sum(1 for e in edges if e.get("status") == "NONE"),
        "edges_partial": sum(1 for e in edges if e.get("status") == "PARTIAL"),
        "tools": len(tool_rows),
        "tools_admitted": admitted,
        "tools_refused": refused,
        "tools_unverified": unverified,
        "refusal_codes": len(REFUSALS),
    }


def _resolve(repo: Path, override: str | None, default: str) -> Path:
    return Path(override) if override else repo / default


def run_check(args: argparse.Namespace) -> int:
    repo = Path(args.repo_root).resolve() if args.repo_root else REPO_ROOT
    frontier = load_json_strict(_resolve(repo, args.frontier, FRONTIER))
    hierarchy = load_json_strict(_resolve(repo, args.hierarchy, HIERARCHY))
    tools = load_json_strict(_resolve(repo, args.tools, TOOLS))
    document = _resolve(repo, args.document, DOCUMENT)
    try:
        text = document.read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal("FR_REFUSED_SCHEMA", f"{document}: unreadable: {exc}") from exc
    refinement = _load_refinement(repo)
    refusals = check(frontier, hierarchy, tools, text, repo, refinement)
    counts = summary(frontier, hierarchy, tools)
    if args.json:
        print(json.dumps({"ok": not refusals, "refusals": refusals,
                          "summary": counts}, indent=2, sort_keys=True))
    else:
        for line in refusals:
            print(line)
        print("frc: frontier={frontier_entries} levels={levels} edges={edges} "
              "tools={tools} admitted={tools_admitted} refused={tools_refused} "
              "unverified={tools_unverified} codes={codes}".format(
                  codes=CODE_OK if not refusals else "REFUSED", **counts))
    return EXIT_OK if not refusals else EXIT_REFUSED


def run_inventory(args: argparse.Namespace) -> int:
    repo = Path(args.repo_root).resolve() if args.repo_root else REPO_ROOT
    frontier = load_json_strict(_resolve(repo, args.frontier, FRONTIER))
    hierarchy = load_json_strict(_resolve(repo, args.hierarchy, HIERARCHY))
    tools = load_json_strict(_resolve(repo, args.tools, TOOLS))
    counts = summary(frontier, hierarchy, tools)
    if args.json:
        print(json.dumps(counts, indent=2, sort_keys=True))
    else:
        print(" ".join(f"{key}={value}" for key, value in sorted(counts.items())))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(dest="command")
    for name, handler in (("check", run_check), ("inventory", run_inventory)):
        command = sub.add_parser(name)
        command.add_argument("--repo-root", default=None)
        command.add_argument("--frontier", default=None)
        command.add_argument("--hierarchy", default=None)
        command.add_argument("--tools", default=None)
        command.add_argument("--document", default=None)
        command.add_argument("--json", action="store_true")
        command.set_defaults(handler=handler)
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        print(f"{CODE_USAGE}: a subcommand is required (check, inventory)")
        return EXIT_USAGE
    try:
        return args.handler(args)
    except Refusal as refusal:
        print(f"{refusal.code}: {refusal.detail}")
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
