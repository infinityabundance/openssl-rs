#!/usr/bin/env python3
"""Deterministic producer of the FRC-8 DO-178C objective-conformance matrix.

The matrix is a declaration of what this repository can and cannot show against
the programme's section 6 assurance areas, for one declared context.  It proves
nothing, certifies nothing and assigns no development assurance level:

  * every objective records the substance as the programme states it, the
    evidence that exists for it today, the independence it requires, the
    independence actually held, and a status from a closed vocabulary;
  * every exact DO-178C objective identifier and wording is ``UNVERIFIED``
    because DO-178C, AC 20-115D, DO-330 and DO-333 were not read in the
    producing session, and each names the reading that would settle it;
  * every required missing item is registered with its reason and its settling
    method, and each unmet objective names the items that block it.

Every cited path is a real file.  Every count in the independence block is
copied from ``evidence/etp-t15/INDEPENDENCE.json`` and the validator refuses a
number that disagrees with that record.  No timestamp is written: ``recorded_at``
is a declared date, not a clock reading.  Two runs over the same tree reproduce
the same bytes.

Usage:

    python3 evidence/frc8/build_evidence.py [--out DIR]
    python3 evidence/frc8/build_evidence.py --check

The default output directory is this file's directory.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import do178c_matrix  # noqa: E402

HERE = Path(__file__).resolve().parent
BASE_COMMIT = "7bcf7befa249b32f85e10d09b7795f7a891617fa"
RECORDED_AT = "2026-11-25"
PROGRAMME = "docs/FORMAL-REFINEMENT-CERTIFICATION.md"

CITED = (
    "docs/FORMAL-REFINEMENT-CERTIFICATION.md",
    "docs/FRC-TODO.md",
    "docs/DO178C-CONFORMANCE.md",
    "docs/REQUIREMENTS-TRACEABILITY.md",
    "docs/RELEASE_GATES.md",
    "docs/FFI-FAILURE-ATOMICITY.md",
    "docs/PARSER-HARDENING.md",
    "docs/INSTRUMENT-QUALIFICATION.md",
    "evidence/etp-t1/TRACEABILITY.json",
    "evidence/etp-t3/REFINEMENT.json",
    "evidence/etp-t4/SAFETY-SITES.json",
    "evidence/etp-t5/RESULTS.json",
    "evidence/etp-t6/TCB.json",
    "evidence/etp-t6/CLAIM-MATRIX.json",
    "evidence/etp-t7/ERASURE-AUDIT.json",
    "evidence/etp-t9/IDENTITY-TRIAGE.json",
    "evidence/etp-t11/TIERS.json",
    "evidence/etp-t15/INDEPENDENCE.json",
    "evidence/etp2/reproducibility.json",
    "evidence/etp3/instruments.json",
    "evidence/etp4/VERIFICATION-RECEIPT.md",
    "evidence/etp7/RECEIPT.md",
    "forensics/frc/TOOLS.json",
    "forensics/tools/do178c_matrix.py",
)

INDEPENDENCE_WITNESS = "evidence/etp-t15/INDEPENDENCE.json"
PROGRAMME_SOURCE = "docs/FORMAL-REFINEMENT-CERTIFICATION.md section 6"
PROGRAMME_EXTRA = ("docs/FORMAL-REFINEMENT-CERTIFICATION.md section 6, paragraph "
                   "after the assurance table")

INDEPENDENCE_SETTLE = (
    "Read the objective's independence attribute in the DO-178C objective tables at "
    "the published revision, record the table, the objective number and its "
    "independence attribute, and compare it with evidence/etp-t15/INDEPENDENCE.json."
)
NORMATIVE_SETTLE = (
    "Read the DO-178C objective tables (A-1 to A-10), AC 20-115D, DO-330 and DO-333 "
    "at their published revisions, record the objective identifiers, exact wording and "
    "independence attributes for the declared context, and update this row with the "
    "reading and its date. This session read none of them."
)


def held_same_party() -> dict[str, Any]:
    return {
        "state": "SAME_PARTY_ONLY",
        "witness": INDEPENDENCE_WITNESS,
        "trust_domain": None,
        "external_parties": 0,
        "distinct_from_author": False,
    }


def required_unverified(basis: str) -> dict[str, Any]:
    return {"state": "UNVERIFIED", "basis": basis,
            "settling_method": INDEPENDENCE_SETTLE}


def evidence(path: str, kind: str, check: str) -> dict[str, str]:
    return {"path": path, "kind": kind, "check": check}


def objective(
    objective_id: str,
    area: str,
    substance: str,
    status: str,
    basis: str,
    items: list[dict[str, str]],
    blocked_by: list[str],
    required: dict[str, Any],
    source: str = PROGRAMME_SOURCE,
    settling_method: str | None = None,
) -> dict[str, Any]:
    return {
        "id": objective_id,
        "area": area,
        "substance": substance,
        "substance_source": source,
        "normative_objective_ids": "UNVERIFIED",
        "normative_settling_method": NORMATIVE_SETTLE,
        "status": status,
        "basis": basis,
        "evidence": items,
        "required_independence": required,
        "independence_held": held_same_party(),
        "blocked_by": blocked_by,
        "settling_method": settling_method,
    }


def missing(item_id: str, item: str, why: str, settle: str) -> dict[str, str]:
    return {"id": item_id, "item": item, "why_required": why, "settling_method": settle}


def missing_items() -> list[dict[str, str]]:
    return [
        missing(
            "MI-PLANNING",
            "Configuration-specific assurance, development and verification plans",
            "The programme states a queue and a set of gates, not a plan for a declared "
            "system. DO-178C planning objectives begin from a plan for a configuration.",
            "Write and review a plan for the declared context, naming the lifecycle, "
            "the verification methods and the configuration index; bind it to a date "
            "and a reviewer."),
        missing(
            "MI-REQUIREMENT-BASELINE",
            "High-level and low-level requirements with unambiguous acceptance criteria",
            "ETP-T1 records 21 requirement nodes and 0 specification nodes; no negotiated "
            "requirement baseline exists for the declared context.",
            "Establish an HLR and LLR baseline from normative sources, with acceptance "
            "criteria per requirement, and register it in the traceability graph."),
        missing(
            "MI-REQUIREMENTS-BASED-TESTS",
            "Verification cases derived from the requirements, not from the source",
            "ETP-T11 records 78 requirements with 0 SATISFIED, 59 NOT_RUN and 19 REFUSED. "
            "The existing tests and the ETP-T5 differential court were not derived from a "
            "requirement baseline.",
            "Derive a verification case per requirement, execute it at a bound identity, "
            "and record the requirement-to-case-to-result trace."),
        missing(
            "MI-STRUCTURAL-COVERAGE",
            "MC/DC and object-code coverage where the declared level requires it",
            "No MC/DC or object-code coverage record exists. The traceability document "
            "states that MC/DC is not measured anywhere and is not claimed.",
            "Select the required structural coverage for the declared level, name the "
            "instrument, the decision population and the measured result, and run it at "
            "the exact artefact."),
        missing(
            "MI-SYSTEM-SAFETY-ASSESSMENT",
            "A system safety assessment and the DAL it would assign",
            "No system safety assessment exists and no DAL is assigned. The declared "
            "context is non-airborne, so this item is named as absent rather than "
            "borrowed from another system.",
            "Declare a system context with airborne applicability, perform the safety "
            "assessment, and record the assigned level. This matrix does not do that."),
        missing(
            "MI-TOOL-QUALIFICATION",
            "DO-330 assessment for every tool whose output the argument depends on",
            "The instrument register is explicitly not a DO-330 qualification, and FRC-0 "
            "records 15 candidate provers with 0 admitted because none was tested against "
            "the pinned compiler.",
            "For each tool the argument depends on, record its intended use, qualification "
            "basis, version, digest, positive and negative controls, and a DO-330 "
            "assessment at the pinned toolchain."),
        missing(
            "MI-TARGET-EXECUTION",
            "Verification executed on the declared target hardware",
            "Every cited record was produced on x86_64-unknown-linux-gnu on the "
            "development host or in the court container. No target hardware is declared "
            "and no cross-target execution exists.",
            "Declare the target hardware and build identity, execute the verification "
            "suite there, and bind each result to the target artefact digest."),
        missing(
            "MI-CONFIGURATION-INDEX",
            "A complete configuration index for the declared context",
            "ETP-2 records byte-identical builds at one host, image, toolchain and target, "
            "and ETP-T9 classifies 118 of 231 evidence items as UNCERTIFIABLE. No complete "
            "index binds every input and artefact of the declared context.",
            "Build a configuration index from source and toolchain through every executed "
            "artefact, with a digest per input, and record the uncertifiable items as "
            "gaps rather than defaults."),
        missing(
            "MI-INDEPENDENT-REVIEW",
            "Independent review and quality assurance by a distinct trust domain",
            "The independence record has 50 assignments, all 50 adjudicated by the "
            "author's party, 0 declared parties and 0 external parties; the one asserted "
            "independence was refused.",
            "Name a party outside the project with its own infrastructure and signing "
            "identity, have it review the work products, and record the review artefact "
            "and its distinctness evidence."),
        missing(
            "MI-FORMAL-METHODS-JUSTIFICATION",
            "A DO-333 justification, its assumptions and its proof artefacts",
            "No proof artefact exists. ETP-T3 records no discharged refinement edge and "
            "FRC-0 records no admitted prover. A bounded test is not a formal result.",
            "Write the DO-333 justification for each formal method used, state its "
            "assumptions and TCB, and bind each proof artefact to the exact source and "
            "binary identity."),
        missing(
            "MI-TARGET-TIMING",
            "Bounded execution, deadline analysis and worst-case execution time",
            "No execution-time bound, deadline or WCET analysis exists. A constant-time "
            "instrument result is not a WCET result, and the court venue has no PMU.",
            "Declare the execution-time budget, measure the bound on the target, and "
            "record the analysis with its assumptions and its uncovered paths."),
        missing(
            "MI-PROBLEM-REPORTING",
            "Problem reporting and change control under a governing plan",
            "ETP-T11 records 6 change sets with 0 SATISFIED and status REFUSED. There is "
            "machine-readable impact analysis, but no problem-reporting process under a "
            "DO-178C plan and no selective proof invalidation because no proof exists.",
            "Establish a problem-report process, bind each change to its impact analysis, "
            "and record the change decision and its verification at the new identity."),
    ]


def system_context() -> dict[str, Any]:
    return {
        "id": "CTX-FRC8-NONAIRBORNE-LIBRARY",
        "product": "the libcrypto-compatible shared library built from this repository "
                   "for x86_64-unknown-linux-gnu in the release profile",
        "statement": (
            "The software item is the libcrypto-compatible shared library built from this "
            "repository for the x86_64-unknown-linux-gnu target in the release profile, "
            "considered as a standalone library under its declared C ABI on the "
            "development host and in the court container. The context assigns no "
            "aircraft, engine or spacecraft function, no system safety assessment, no "
            "development assurance level and no target hardware."),
        "scope_choice_not_compliance": True,
        "evidence_basis": (
            "Every record the matrix cites was produced on the development host or in "
            "the court container for x86_64-unknown-linux-gnu; nothing in this repository "
            "is bound to an airborne target, an airborne environment or a DAL."),
        "excludes": [
            {
                "id": "XCE-TARGET-HARDWARE",
                "category": "TARGET_HARDWARE",
                "exclusion": "No airborne, embedded or production target hardware is in "
                             "scope; every cited record is from x86_64-unknown-linux-gnu "
                             "on the development host or in the court container.",
            },
            {
                "id": "XCE-AIRBORNE",
                "category": "AIRBORNE_APPLICABILITY",
                "exclusion": "No aircraft, engine or spacecraft installation, environment "
                             "or lifecycle is claimed; DO-178C is used here as a checklist "
                             "of objectives, not as an invoked certification basis.",
            },
            {
                "id": "XCE-DAL",
                "category": "DAL",
                "exclusion": "No development assurance level is assigned, proposed or "
                             "claimed, including DAL A, B, C, D and E.",
            },
            {
                "id": "XCE-CERTIFICATION",
                "category": "CERTIFICATION_CONSEQUENCE",
                "exclusion": "No airworthiness finding, approval, compliance statement or "
                             "system-level safety result follows from this matrix, and "
                             "none is claimed.",
            },
            {
                "id": "XCE-WCET",
                "category": "WORST_CASE_EXECUTION",
                "exclusion": "Bounded execution, deadline analysis and worst-case "
                             "execution time are excluded; a constant-time instrument "
                             "result is not a WCET result.",
            },
            {
                "id": "XCE-ENVIRONMENT",
                "category": "ENVIRONMENTAL_QUALIFICATION",
                "exclusion": "Environmental qualification, including temperature, "
                             "vibration, radiation and electromagnetic effects, is "
                             "excluded.",
            },
        ],
    }


def objectives() -> list[dict[str, Any]]:
    indep_unread = (
        "The programme's section 6 does not state this objective's independence "
        "attribute, and the DO-178C objective tables were not read. Nothing about the "
        "required independence is established.")
    trace = "evidence/etp-t1/TRACEABILITY.json"
    tiers = "evidence/etp-t11/TIERS.json"

    return [
        objective(
            "DO8-PLANNING", "planning",
            "Configuration-specific assurance, development and verification plans.",
            "NOT_SATISFIED",
            "The programme states a queue, gates and a non-claim discipline; it is not a "
            "plan for a declared system and names no lifecycle, method or reviewer. No "
            "plan artefact exists.",
            [evidence(PROGRAMME, "RECORD",
                      "the programme's section 6 planning row and section 4 queue, read "
                      "as a statement of work rather than a plan"),
             evidence("docs/FRC-TODO.md", "RECORD",
                      "the FRC-8 acceptance criterion, which requires the declared "
                      "context this row now supplies")],
            ["MI-PLANNING", "MI-SYSTEM-SAFETY-ASSESSMENT"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-HLR", "high-level requirements",
            "Externally observable functional and safety requirements.",
            "PARTIAL",
            "ETP-T1's traceability graph holds 21 requirement nodes and 7 hazard nodes "
            "with typed edges, but 0 specification nodes and no negotiated baseline for "
            "the declared context. Project requirements are not HLRs with a safety "
            "assessment behind them.",
            [evidence(trace, "RECORD",
                      "node counts: 21 requirement, 0 specification, 7 hazard"),
             evidence("docs/REQUIREMENTS-TRACEABILITY.md", "RECORD",
                      "the traceability description and its stated coverage limits")],
            ["MI-REQUIREMENT-BASELINE", "MI-SYSTEM-SAFETY-ASSESSMENT"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-LLR", "low-level requirements",
            "Traceable implementation obligations with unambiguous acceptance criteria.",
            "NOT_SATISFIED",
            "ETP-T1 records 78 open obligation nodes, not a low-level requirement "
            "baseline with acceptance criteria, and ETP-T11 binds 78 requirements with 0 "
            "satisfied. No LLR set exists for the declared context.",
            [evidence(trace, "RECORD",
                      "the 78 obligation nodes and the graph's zero specification nodes"),
             evidence(tiers, "RECORD",
                      "totals: 78 requirements, 0 SATISFIED, 59 NOT_RUN, 19 REFUSED")],
            ["MI-REQUIREMENT-BASELINE"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-ARCH", "architecture",
            "Verified boundaries, partitioning, dependency and failure-propagation "
            "analysis.",
            "PARTIAL",
            "ETP-T3 records six refinement levels and five edges, all NONE or PARTIAL with "
            "0 discharged. ETP-T4 inventories 51,703 unsafe sites as boundary-unconfined. "
            "The architecture is documented; its boundaries are not verified and no "
            "failure-propagation analysis exists.",
            [evidence("evidence/etp-t3/REFINEMENT.json", "RECORD",
                      "levels and edges: 0 DISCHARGED; four of five edges NONE or PARTIAL"),
             evidence("evidence/etp-t4/SAFETY-SITES.json", "RECORD",
                      "summary.boundary_unconfined = 51703")],
            ["MI-FORMAL-METHODS-JUSTIFICATION", "MI-INDEPENDENT-REVIEW"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-REQVER", "requirements-based verification",
            "Tests and formal analyses derived from requirements, not from the source.",
            "NOT_SATISFIED",
            "ETP-T11 records 0 of 78 requirements satisfied (59 NOT_RUN, 19 REFUSED). The "
            "ETP-T5 differential court reached AGREEMENT on P-256 and RSA cases, but it "
            "was derived from an executable reference and a population, not from a "
            "requirement baseline.",
            [evidence(tiers, "RECORD",
                      "totals.by_state: SATISFIED 0, NOT_RUN 59, REFUSED 19"),
             evidence("evidence/etp-t5/RESULTS.json", "RECORD",
                      "status = AGREEMENT; differences.counts_by_class is empty")],
            ["MI-REQUIREMENTS-BASED-TESTS", "MI-REQUIREMENT-BASELINE"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-COVERAGE", "structural coverage",
            "MC/DC and object-code coverage where required.",
            "NOT_SATISFIED",
            "No MC/DC or object-code coverage record exists. The traceability document "
            "states that MC/DC is not measured anywhere in ETP-T1 and is not claimed, and "
            "that a release claim citing it would have to name the instrument, population "
            "and measured result.",
            [evidence("docs/REQUIREMENTS-TRACEABILITY.md", "RECORD",
                      "section 8: 'MC/DC is not measured anywhere in this item, and it is "
                      "not claimed.'")],
            ["MI-STRUCTURAL-COVERAGE"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-ROBUST", "robustness",
            "Defined failure behaviour, resource exhaustion and environmental faults.",
            "PARTIAL",
            "Failure atomicity and parser hardening are documented, and ETP-T7 audits 15 "
            "clear-free arms with 7 findings of which 0 are repaired and 1 is HIGH. "
            "Resource exhaustion and environmental faults are not analysed, and the "
            "unrepaired findings are not a defined failure behaviour.",
            [evidence("evidence/etp-t7/ERASURE-AUDIT.json", "RECORD",
                      "summary: findings 7, repaired 0, findings_by_severity.HIGH 1, "
                      "clear_free_arms_lost 1"),
             evidence("docs/FFI-FAILURE-ATOMICITY.md", "RECORD",
                      "the documented failure-atomicity rules for the FFI boundary"),
             evidence("docs/PARSER-HARDENING.md", "RECORD",
                      "the documented parser-hardening rules")],
            ["MI-SYSTEM-SAFETY-ASSESSMENT", "MI-TARGET-EXECUTION"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-CM", "configuration management",
            "Exact source, toolchain, build and verified-artefact identities.",
            "PARTIAL",
            "ETP-2 records two independently initialised release builds as ALL_IDENTICAL "
            "at one host, image, toolchain and target, and ETP-T6 records the toolchain "
            "components with digests. No complete configuration index covers the declared "
            "context, and ETP-T9 classifies 118 of 231 evidence items as UNCERTIFIABLE.",
            [evidence("evidence/etp2/reproducibility.json", "RECORD",
                      "comparison_outcome = ALL_IDENTICAL at one host and target"),
             evidence("evidence/etp-t6/TCB.json", "RECORD",
                      "components with digests; target_triple = x86_64-unknown-linux-gnu"),
             evidence("evidence/etp-t9/IDENTITY-TRIAGE.json", "RECORD",
                      "counts: 118 UNCERTIFIABLE of 231 evidence items")],
            ["MI-CONFIGURATION-INDEX", "MI-TARGET-EXECUTION"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-QA", "quality assurance",
            "Independent checks against the governing process.",
            "NOT_SATISFIED",
            "The release gate and the documentation checks exist, but independence is the "
            "substance of this objective and it is absent: 50 of 50 recorded assignments "
            "have an adjudicator from the author's party, 0 parties are declared, 0 are "
            "external, and the one asserted independence was refused. The release gate "
            "also refuses this candidate.",
            [evidence(INDEPENDENCE_WITNESS, "RECORD",
                      "summary: assignments 50, same_party_adjudicator 50, "
                      "declared_parties 0, external_parties 0"),
             evidence("evidence/etp7/RECEIPT.md", "RECORD",
                      "the release-gate run and its recorded refusals at 2d31a23fb"),
             evidence("docs/RELEASE_GATES.md", "RECORD",
                      "the governing release-gate list")],
            ["MI-INDEPENDENT-REVIEW"],
            {"state": "INDEPENDENT_REQUIRED",
             "basis": "the programme's section 6 requires independent checks for quality "
                      "assurance",
             "settling_method": INDEPENDENCE_SETTLE},
        ),
        objective(
            "DO8-TOOL", "tool qualification",
            "DO-330 assessment for the tools whose output the argument depends on.",
            "NOT_SATISFIED",
            "The instrument register qualifies 11 instruments for their own controls (9 "
            "PASS, 2 RECORDED) and says the result is not a security result and not a "
            "DO-330 qualification. FRC-0 records 15 candidate provers with 0 admitted. No "
            "tool has a DO-330 assessment.",
            [evidence("docs/INSTRUMENT-QUALIFICATION.md", "RECORD",
                      "the instrument register, including section 0's statement that "
                      "qualification is not a security result"),
             evidence("evidence/etp3/instruments.json", "RECORD",
                      "11 instruments; 9 sensitivity controls PASS and 2 RECORDED"),
             evidence("forensics/frc/TOOLS.json", "RECORD",
                      "15 tools, 0 ADMITTED, 15 REFUSED")],
            ["MI-TOOL-QUALIFICATION"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-FORMAL", "formal methods",
            "DO-333 justification, assumptions and proof artefacts.",
            "NOT_SATISFIED",
            "No proof artefact exists. ETP-4 records bounded tests and no prover proof; "
            "the Kani run uses a non-pinned compiler and is not citable. ETP-T3 records 0 "
            "discharged refinement edges and FRC-0 records 0 admitted provers.",
            [evidence("evidence/etp4/VERIFICATION-RECEIPT.md", "RECORD",
                      "bounded cleansing and REDC observations; no prover proof"),
             evidence("evidence/etp-t3/REFINEMENT.json", "RECORD",
                      "no edge is DISCHARGED"),
             evidence("forensics/frc/TOOLS.json", "RECORD",
                      "15 tools, 0 ADMITTED")],
            ["MI-FORMAL-METHODS-JUSTIFICATION", "MI-TOOL-QUALIFICATION"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-CHANGE", "change control",
            "Machine-readable impact analysis and selective proof invalidation.",
            "PARTIAL",
            "ETP-T11 records 6 change sets with machine-readable impact analysis, but 0 "
            "requirements are SATISFIED and the tier report is REFUSED. Selective proof "
            "invalidation cannot exist while no proof exists; ETP-T9 records 118 of 231 "
            "evidence items as UNCERTIFIABLE.",
            [evidence(tiers, "RECORD",
                      "change_sets 6, totals.by_state.SATISFIED 0, status REFUSED"),
             evidence("evidence/etp-t9/IDENTITY-TRIAGE.json", "RECORD",
                      "counts: 118 UNCERTIFIABLE of 231")],
            ["MI-CONFIGURATION-INDEX", "MI-PROBLEM-REPORTING"],
            required_unverified(indep_unread),
        ),
        objective(
            "DO8-TARGET-VALIDATION", "target-hardware validation",
            "Verification executed on the declared target hardware.",
            "UNVERIFIED",
            "No target hardware is declared in the context and every cited record is "
            "x86_64-unknown-linux-gnu. Whether this objective applies, and what its "
            "normative wording is, was not read; the row records the absence and the "
            "reading that would settle it.",
            [evidence("evidence/etp-t6/CLAIM-MATRIX.json", "RECORD",
                      "one target, x86_64-unknown-linux-gnu; no cross-target claim")],
            ["MI-TARGET-EXECUTION", "MI-TARGET-TIMING"],
            required_unverified(indep_unread),
            source=PROGRAMME_EXTRA,
            settling_method="Declare whether a target hardware is in scope, then read the "
                            "target-validation objective and execute the verification on "
                            "that target at a bound artefact digest.",
        ),
        objective(
            "DO8-BOUNDED-EXECUTION", "bounded execution and WCET",
            "Bounded execution, deadline analysis and worst-case execution time.",
            "UNVERIFIED",
            "No execution-time bound, deadline or WCET analysis exists. The instrument "
            "register's venue has no PMU and its timing rows are SCOPED_OBSERVATION. The "
            "normative wording and applicability of an execution-time objective were not "
            "read.",
            [evidence("docs/INSTRUMENT-QUALIFICATION.md", "RECORD",
                      "venue limitations: no hardware PMU; timing rows are "
                      "SCOPED_OBSERVATION")],
            ["MI-TARGET-TIMING"],
            required_unverified(indep_unread),
            source=PROGRAMME_EXTRA,
            settling_method="Declare the execution-time budget and the worst-case path, "
                            "read the applicable objective, and measure the bound on the "
                            "declared target with its assumptions recorded.",
        ),
    ]


def matrix() -> dict[str, Any]:
    return {
        "schema": do178c_matrix.SCHEMA,
        "item": "FRC-8 of docs/FRC-TODO.md",
        "kind": "do178c-objective-conformance-matrix",
        "base_commit": BASE_COMMIT,
        "recorded_at": RECORDED_AT,
        "programme": PROGRAMME,
        "certification_claimed": False,
        "dal_claimed": False,
        "assurance_level": None,
        "objective_satisfaction_only": True,
        "system_context": system_context(),
        "independence_record": {
            "path": INDEPENDENCE_WITNESS,
            "assignments": 50,
            "same_party_adjudicator": 50,
            "declared_parties": 0,
            "external_parties": 0,
            "statement": (
                "Every recorded adjudication is same-party: all 50 assignments have an "
                "adjudicator from the author's party, no party outside the project is "
                "declared, and the one asserted independence was refused. No objective "
                "row records independence as held."),
        },
        "objectives": objectives(),
        "missing_items": missing_items(),
        "non_claim": {
            "statement": (
                "Objective satisfaction is not certification. This matrix establishes "
                "only which of the programme's section 6 objectives are unmet, partly met "
                "or unverified in the declared context. It records no certification, no "
                "DO-178C level and no development assurance level, and no row may be "
                "cited as a certification result."),
            "what_this_establishes": (
                "which objectives of the programme's section 6 have supporting evidence "
                "in this repository today, and which required items are absent"),
            "what_this_does_not_establish": [
                "certification, an airworthiness finding or an approval of any kind",
                "a DO-178C level or a development assurance level (DAL)",
                "that the cited evidence is sufficient for the objective it is attached to",
                "that any objective identifier or wording matches DO-178C: every exact "
                "identifier is UNVERIFIED because the standard was not read",
                "that the declared context is sufficient for any certification basis",
            ],
        },
        "status_vocabulary": list(do178c_matrix.STATUSES),
    }


def _write(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", default=None,
                        help="also write a second copy here, for a two-run comparison")
    parser.add_argument("--check", action="store_true",
                        help="compare with the committed bytes instead of writing")
    args = parser.parse_args(argv)
    out = Path(args.out) if args.out else HERE
    out.mkdir(parents=True, exist_ok=True)

    unavailable = [path for path in CITED if not (REPO / path).is_file()]
    if unavailable:
        print("frc-8: a cited path does not exist: " + ", ".join(unavailable))
        return 1

    document = matrix()
    target = out / "DO178C-MATRIX.json"
    expected = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not target.is_file() or target.read_text(encoding="utf-8") != expected:
            print(f"frc-8: {target} differs from the produced bytes")
            return 1
    else:
        _write(target, document)

    counts = do178c_matrix.summary(
        document, do178c_matrix.load_independence(REPO))
    print("frc-8: " + " ".join(f"{key}={counts[key]}" for key in sorted(counts)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
