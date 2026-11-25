#!/usr/bin/env python3
"""Deterministic producer of the FRC-0 registers.

The three registers are declarations written before any proof exists, so that a
later proof has a stated thing to prove.  They contain no theorem, no
measurement and no digest that is not copied from a cited record:

  * ``evidence/frc/FRONTIER-GAPS.json`` -- per reference result, what it proves,
    what it assumes, what this project proves, and the additional theorem that
    would be a genuine improvement; every entry classified, every external claim
    ``UNVERIFIED`` with the method that would settle it.
  * ``evidence/frc/SPECIFICATION-HIERARCHY.json`` -- the P-256 instantiation of
    the ETP-T3 refinement levels and edges, with normative sources and the
    recorded status of each edge.
  * ``forensics/frc/TOOLS.json`` -- one row per candidate prover with its
    admission decision and the fields the decision is allowed to rest on.

Every external source in this producer was located from the programme's own
transcription or from general knowledge of the standard, and NONE WAS READ IN
THE PRODUCING SESSION.  Each is therefore ``UNVERIFIED`` with a settling method
that names the clause to read.  The two tool digests are copied from
``evidence/etp4/VERIFICATION-RECEIPT.md`` and the validator checks that each
digest actually occurs in that file.

Usage:

    python3 evidence/frc/build_evidence.py [--out DIR]
    python3 evidence/frc/build_evidence.py --check

The default output directory is this file's directory.  No timestamp is
written: ``recorded_at`` is a declared date, not a clock reading.  Two runs over
the same tree reproduce the same bytes.

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

import frc_registers  # noqa: E402

HERE = Path(__file__).resolve().parent
BASE_COMMIT = "829483c8121381e0a035f6d0cd08613b2755f7f8"
RECORDED_AT = "2026-11-25"
PROGRAMME = "docs/FORMAL-REFINEMENT-CERTIFICATION.md"

# Paths that the records cite.  Kept here so a broken citation fails at
# production, before a register is written.
CITED = (
    "docs/FORMAL-REFINEMENT-CERTIFICATION.md",
    "docs/ETP-TODO.md",
    "docs/ABI_POLICY.md",
    "docs/CRYPTOGRAPHIC-REFERENCE.md",
    "docs/OPENSSH-COHORT.md",
    "evidence/etp-t3/REFINEMENT.json",
    "evidence/etp-t4/SAFETY-SITES.json",
    "evidence/etp-t5/RESULTS.json",
    "evidence/etp-t6/CLAIM-MATRIX.json",
    "evidence/etp-t6/TCB.json",
    "evidence/etp-t7/DUDECT-ETP-T7.json",
    "evidence/etp-t7/ERASURE-AUDIT.json",
    "evidence/etp4/VERIFICATION-RECEIPT.md",
    "courts/phase18/timing/RECEIPT-timing-unified.json",
    "rust-toolchain.toml",
)


def unverified(settling_method: str, witness: str | None = PROGRAMME) -> dict[str, Any]:
    return {"state": "UNVERIFIED", "witness": witness,
            "settling_method": settling_method}


def recorded(settling_method: str, witness: str) -> dict[str, Any]:
    return {"state": "RECORDED_BY_THIS_PROJECT", "witness": witness,
            "settling_method": settling_method}


def project_none(basis: str, evidence: list[str]) -> dict[str, Any]:
    return {"state": "NONE", "basis": basis, "evidence": evidence,
            "proof_artefact": None}


def project_bounded(basis: str, evidence: list[str]) -> dict[str, Any]:
    return {"state": "BOUNDED_EVIDENCE", "basis": basis, "evidence": evidence,
            "proof_artefact": None}


def entry(
    entry_id: str,
    reference: str,
    classification: str,
    proves: str,
    assumes: str,
    project: dict[str, Any],
    additional_theorem: str,
    settling_method: str,
) -> dict[str, Any]:
    return {
        "id": entry_id,
        "reference": reference,
        "classification": classification,
        "proves": proves,
        "assumes": assumes,
        "this_project": project,
        "additional_theorem": additional_theorem,
        "beyond_frontier": {"claim": False, "matched_property": None,
                            "added_property": None, "matched_entry": None},
        "verification": unverified(settling_method),
    }


def frontier_register() -> dict[str, Any]:
    s2n = "s2n-bignum (as transcribed in the programme's section 1.1, read 2026-11-22)"
    s2n_settle = ("Re-read s2n-bignum/SOUNDNESS.md at a pinned commit, record the exact "
                  "clause and its digest, and record the date it was read.")
    no_kernel = ("No P-256 kernel in this project has a functional specification, a "
                 "machine-checked correctness theorem or a source-to-binary correspondence. "
                 "ETP-T5 supplies a differential reference; a differential is not a proof.")
    kernel_evidence = ["evidence/etp-t5/RESULTS.json",
                       "evidence/etp-t4/SAFETY-SITES.json",
                       "evidence/etp-t3/REFINEMENT.json"]

    entries = [
        entry(
            "FG-S2N-A1", s2n, "REFERENCE_PROOF",
            "An instruction sequence satisfies a HOL Light Hoare triple relating it to a "
            "functional specification, over the object-code bytes the build produces.",
            "The functional specification itself is correct. A typo, a wrong constant or a "
            "wrong definition is invisible to the proof.",
            project_none(no_kernel, kernel_evidence),
            "An independently written, machine-checked functional specification for each "
            "shipped P-256 kernel, tied to the named standard clause, so specification error "
            "is a checked property rather than an assumption.",
            s2n_settle,
        ),
        entry(
            "FG-S2N-A2", s2n, "REFERENCE_RESIDUAL_RISK",
            "Functional correctness of a routine under stated preconditions (aliasing, "
            "reduced operands, excluded degenerate points).",
            "Callers satisfy those preconditions. There is no complete machine-checked link "
            "between the public header and the formal statements.",
            project_none(no_kernel, kernel_evidence),
            "The FRC-5 obligation for each kernel: every reachable call site, including FFI "
            "and callback reachability, establishes Pre(c), and the postcondition Q is "
            "sufficient for the next consumer.",
            s2n_settle,
        ),
        entry(
            "FG-S2N-A3", s2n, "REFERENCE_ENVIRONMENT_ASSUMPTION",
            "The instruction sequence and all memory addresses are independent of secret "
            "inputs, and no variable-timing microarchitectural event occurs, under the "
            "model recorded in SOUNDNESS.md.",
            "Hardware executes those instructions in constant time (Hertzbleed-class and "
            "variable-latency instructions are excluded by assumption); DIT/DOITM help where "
            "present; power and frequency channels are out of scope.",
            project_bounded(
                "Bounded instrument evidence exists at named DSOs (dudect, ctgrind, a binary "
                "branch audit), and every such result states that it is not a physical "
                "guarantee and not a proof about the binary's semantics.",
                ["courts/phase18/timing/RECEIPT-timing-unified.json",
                 "evidence/etp-t7/DUDECT-ETP-T7.json"]),
            "A relational timing theorem for the exact compiled artefact under a declared "
            "leakage model, plus separately measured physical-channel evidence for the "
            "declared platform.",
            s2n_settle,
        ),
        entry(
            "FG-S2N-A4", s2n, "REFERENCE_RESIDUAL_RISK",
            "The functional Hoare triple constrains the specified memory; frame conditions "
            "state what may change.",
            "Out-of-bounds reads, transient writes and stack discipline below the stack "
            "pointer are not excluded by functional correctness alone; they rely on "
            "discipline and external memory checking.",
            project_none(
                "No proof excludes out-of-bounds reads or transient writes. ETP-T4 "
                "classifies the unsafe population and records that no site is "
                "SAFETY_DISCHARGED; ETP-4 records bounded cleansing and REDC observations.",
                ["evidence/etp-t4/SAFETY-SITES.json",
                 "evidence/etp4/VERIFICATION-RECEIPT.md"]),
            "A whole-path memory-safety argument (FRC-2) with per-boundary contracts and a "
            "refusal control for each contract class, including transient and stack accesses.",
            s2n_settle,
        ),
        entry(
            "FG-S2N-B1", s2n, "REFERENCE_ENVIRONMENT_ASSUMPTION",
            "The routine's behaviour under the hand-written instruction-set model.",
            "The instruction-set model is correct; co-simulation is a mitigation and is "
            "inherently incomplete.",
            project_none("No instruction-set model is used or validated by this project.",
                         ["evidence/etp-t6/TCB.json"]),
            "An independently validated ISA model, or translation validation against the "
            "produced object code, with a stated co-simulation population.",
            s2n_settle,
        ),
        entry(
            "FG-S2N-B2", s2n, "REFERENCE_ENVIRONMENT_ASSUMPTION",
            "The proof is about the bytes the ELF loader extracts from the object file.",
            "The loader extracts the intended bytes.",
            project_none("No ELF extraction step is part of any proof here; ETP-T6 records "
                         "the object-code correspondence as absent.",
                         ["evidence/etp-t6/CLAIM-MATRIX.json"]),
            "A check that the shipped bytes are the proved bytes, with the extraction tool "
            "content-addressed and controlled (FRC-4).",
            s2n_settle,
        ),
        entry(
            "FG-S2N-B3", s2n, "REFERENCE_ENVIRONMENT_ASSUMPTION",
            "A sequential, user-mode, single-core execution model.",
            "No caches, interrupts, virtual memory, speculation, privilege levels or "
            "physical faults are modelled.",
            project_none("No model of any kind is claimed here; timing instruments observe "
                         "one machine and state their limits.",
                         ["evidence/etp-t7/DUDECT-ETP-T7.json"]),
            "A threat model that states each excluded mechanism explicitly, so absence of a "
            "proof about it is visible (FRC-3).",
            s2n_settle,
        ),
        entry(
            "FG-S2N-C1", s2n, "REFERENCE_ENVIRONMENT_ASSUMPTION",
            "The theorem is checked by the HOL Light kernel running on OCaml.",
            "The proof kernel and the OCaml runtime are correct and are trusted.",
            project_none("No trusted proof kernel is used by this project.",
                         ["evidence/etp-t6/TCB.json"]),
            "A recorded TCB with each component identified by version and digest, and an "
            "independent proof-trace checker where one exists (FRC-7).",
            s2n_settle,
        ),
        entry(
            "FG-S2N-D1", s2n, "REFERENCE_ENVIRONMENT_ASSUMPTION",
            "The proof applies to a 64-bit, little-endian target with alignment checking off "
            "and mapped memory.",
            "The deployment environment matches those assumptions.",
            project_none("ETP-T6 records one target (x86_64-unknown-linux-gnu) and no "
                         "cross-target inheritance; this is an identity result, not a "
                         "correspondence proof.",
                         ["evidence/etp-t6/CLAIM-MATRIX.json"]),
            "Per-target, per-profile claims with the TCB recorded for each, and no claim "
            "inherited across targets (FRC-4).",
            s2n_settle,
        ),
        entry(
            "FG-S2N-D2", s2n, "REFERENCE_RESIDUAL_RISK",
            "The assembly routine's signature agrees with the C header used by the build.",
            "The C header and the assembly signature agree; the check is heuristic and not "
            "machine-checked.",
            project_none("No header/assembly signature agreement is machine-checked; the "
                         "exported ABI is checked separately at the ABI layer only.",
                         ["docs/ABI_POLICY.md", "evidence/etp-t6/CLAIM-MATRIX.json"]),
            "A machine-checked signature agreement between the public declaration and the "
            "proved routine, closing D2.",
            s2n_settle,
        ),
        entry(
            "FG-S2N-D3", s2n, "PROJECT_GAP",
            "Each routine in isolation, from its own specification to its object code.",
            "There is no end-to-end machine-checked proof from the C API through assembly to "
            "the cryptographic specification; the mlkem-native bridge is manual.",
            project_none("This is also this project's gap: ETP-T3 records no discharged "
                         "refinement edge, and ETP-T6 records no source-to-binary "
                         "correspondence.",
                         ["evidence/etp-t3/REFINEMENT.json",
                          "evidence/etp-t6/CLAIM-MATRIX.json"]),
            "An end-to-end machine-checked chain from the OpenSSL-compatible API to the "
            "cryptographic specification, which is the FRC-5 and FRC-10 campaign, not a "
            "single routine proof.",
            s2n_settle,
        ),
        entry(
            "FG-S2N-REASSEMBLY", s2n, "REFERENCE_ENVIRONMENT_ASSUMPTION",
            "The proof covers the bytes produced by the reference build of the reference "
            "toolchain.",
            "Downstream projects that import the assembly and assemble it elsewhere produce "
            "the same bytes; this is not checked by the upstream proof.",
            project_none("No reassembly check exists for this project; nothing is imported "
                         "as assembly, so the gap is inherited rather than reproduced.",
                         ["evidence/etp-t6/TCB.json"]),
            "A check that a downstream build reproduces the proved instruction bytes, or a "
            "proof of the imported source rather than the reference bytes (FRC-4).",
            s2n_settle,
        ),
        entry(
            "FG-AWSLC-END-TO-END", "AWS-LC (programme section 1.1 and 1.4)", "FRONTIER_DIMENSION",
            "Machine-checked arithmetic, constant-time and memory-safety proofs for the "
            "assembly routines AWS-LC uses, on the stated platforms.",
            "The C and API layers around those routines, and their composition into an "
            "operation, are outside the per-routine proof.",
            project_none("This project proves no end-to-end correctness or security property "
                         "through the complete crypto API; only bounded differential and "
                         "instrument evidence exists.",
                         ["evidence/etp-t5/RESULTS.json",
                          "evidence/etp-t3/REFINEMENT.json"]),
            "Stronger applicable end-to-end correctness and security properties through the "
            "complete API, not only the assembly kernels (the programme's 'beyond AWS-LC' "
            "requirement).",
            "Read the AWS-LC published verification statement at a pinned revision and record "
            "the exact scope and assumptions it states.",
        ),
        entry(
            "FG-SEL4-REFINEMENT", "seL4 (programme section 1.2)", "FRONTIER_DIMENSION",
            "Refinement from an abstract specification to an implementation, binary "
            "correctness connecting the executable to the proof, and confidentiality and "
            "integrity theorems for supported configurations.",
            "A declared configuration, a small trusted kernel and a specification written "
            "independently of the implementation.",
            project_none("No refinement, binary-correctness, confidentiality or integrity "
                         "theorem exists for this project.",
                         ["evidence/etp-t3/REFINEMENT.json",
                          "evidence/etp-t6/CLAIM-MATRIX.json"]),
            "The shape of the argument -- specification, implementation, binary -- applied to "
            "a declared configuration of this crate, not the size of the proof.",
            "Read the seL4 verification statement for the named release and record which "
            "configurations and properties it covers.",
        ),
        entry(
            "FG-DO178C-OBJECTIVES", "DO-178C, DO-330 and DO-333 (programme section 1.3)",
            "DO_178C_OBJECTIVE",
            "Objective-based assurance tied to a system's assigned safety level: planning, "
            "requirements, architecture, requirements-based verification, structural "
            "coverage, robustness, configuration management, quality assurance, tool "
            "qualification and formal-methods justification.",
            "A declared system context and a system safety assessment. Satisfying "
            "objectives is not certification, and constant-time behaviour is not "
            "worst-case execution time.",
            project_none("No objective-by-objective matrix for a declared system context "
                         "exists yet; FRC-8 is open.",
                         ["docs/ETP-TODO.md"]),
            "An objective-by-objective matrix with the evidence for each objective, the "
            "required independence, and every missing qualification or target-execution "
            "item named (FRC-8).",
            "Read AC 20-115D and the DO-178C objective tables at their published revisions "
            "and record the exact objective set for the declared assurance level.",
        ),
    ]
    for item in entries:
        if item["classification"] == "DO_178C_OBJECTIVE":
            item["certification_claimed"] = False
            item["objective_satisfaction_only"] = True
    return {
        "schema": frc_registers.SCHEMA_FRONTIER,
        "item": "FRC-0 of docs/FRC-TODO.md",
        "kind": "frontier-gap-register",
        "base_commit": BASE_COMMIT,
        "recorded_at": RECORDED_AT,
        "programme": PROGRAMME,
        "typing_rule": (
            "Every entry is classified and every external claim is UNVERIFIED with a "
            "settling method. this_project.state NONE means this project proves nothing "
            "for that dimension; BOUNDED_EVIDENCE means bounded observations exist that "
            "are not a proof. No entry claims to exceed the frontier."
        ),
        "beyond_frontier_claims": 0,
        "entries": entries,
    }


def source(document: str, clause: str, edition: str, settling_method: str) -> dict[str, Any]:
    return {
        "document": document,
        "clause": clause,
        "edition": edition,
        "verification": unverified(settling_method, witness=None),
    }


def hierarchy_register() -> dict[str, Any]:
    standard_settle = ("Read the named clause of the named edition, record its exact text, "
                       "edition and digest, and the date it was read. This session did not "
                       "read it; the locator is stated so the reading is checkable.")
    return {
        "schema": frc_registers.SCHEMA_HIERARCHY,
        "item": "FRC-0 of docs/FRC-TODO.md",
        "kind": "specification-hierarchy",
        "base_commit": BASE_COMMIT,
        "recorded_at": RECORDED_AT,
        "target": {
            "name": "P-256 field and scalar arithmetic",
            "scope": "the prime field of the P-256 base point, the scalar field modulo the "
                     "group order, point arithmetic, scalar multiplication and ECDSA "
                     "signing with a deterministic nonce",
            "not_in_scope": "key generation, verification-only paths, other curves, TLS "
                            "record protection and every non-arithmetic concern",
        },
        "typing_rule": (
            "The level identifiers are the ETP-T3 refinement levels; FRC-0 instantiates "
            "them for P-256 rather than inventing a second taxonomy. The edge identifiers "
            "and statuses are the recorded ETP-T3 edge statuses and are checked against "
            "that record. No edge is DISCHARGED."
        ),
        "levels": [
            {
                "id": "LVL-L1",
                "name": "abstract specification",
                "frc_scope": "the P-256 mathematical object and the field, scalar, group and "
                             "signing operations stated abstractly, with no representation",
                "constrains": "the functional statement a kernel must satisfy",
                "implementation_derived": False,
                "realisation": "no separate artefact exists; the standard clauses are the "
                               "only statement of this level",
                "normative_sources": [
                    source("FIPS 186-4", "Appendix D.1.2.3 (Curve P-256)",
                           "FIPS 186-4 (2013)", standard_settle),
                    source("FIPS 186-4", "Section 6.4 (ECDSA)",
                           "FIPS 186-4 (2013)", standard_settle),
                    source("NIST SP 800-186", "the P-256 domain-parameter table",
                           "SP 800-186 (2023)", standard_settle),
                    source("SEC 1", "Section 2.4 (elliptic curve arithmetic) and Section 4.1 "
                                    "(ECDSA)",
                           "SEC 1 version 2.0", standard_settle),
                    source("RFC 6979", "Section 3.2 (generation of k)",
                           "RFC 6979 (2013)", standard_settle),
                ],
            },
            {
                "id": "LVL-L2",
                "name": "executable reference",
                "frc_scope": "a P-256 implementation readable without the crate, written "
                             "from the L1 clauses",
                "constrains": "the reference an implementation is compared with",
                "implementation_derived": False,
                "realisation": "forensics/etp5_crypto/ (P-256 field and order arithmetic, "
                               "affine and Jacobian group law, supplied-nonce ECDSA)",
                "normative_sources": [
                    source("FIPS 186-4", "Section 6.4 (ECDSA)",
                           "FIPS 186-4 (2013)", standard_settle),
                    source("RFC 6979", "Section 3.2 (generation of k)",
                           "RFC 6979 (2013)", standard_settle),
                ],
            },
            {
                "id": "LVL-L3",
                "name": "Rust implementation",
                "frc_scope": "the crate's P-256 field, scalar and signing path",
                "constrains": "must refine LVL-L2 under stated Rust semantics, including "
                              "every unsafe contract on the path",
                "implementation_derived": False,
                "realisation": "the crate implementation; its identifiers are deliberately "
                               "not named here, because a specification that names them is "
                               "implementation-shaped",
                "normative_sources": [
                    source("FIPS 186-4", "Section 6.4 (ECDSA)",
                           "FIPS 186-4 (2013)", standard_settle),
                    source("NIST SP 800-186", "the P-256 domain-parameter table",
                           "SP 800-186 (2023)", standard_settle),
                ],
            },
            {
                "id": "LVL-L4",
                "name": "ABI contract",
                "frc_scope": "the exported symbols, buffer contracts, ownership rules and "
                             "error behaviour of the P-256 and ECDSA entry points",
                "constrains": "the observable behaviour a C caller may rely on",
                "implementation_derived": False,
                "realisation": "docs/ABI_POLICY.md is this project's declared contract",
                "normative_sources": [
                    source("RFC 5480", "the SubjectPublicKeyInfo encoding of elliptic-curve "
                                       "public keys",
                           "RFC 5480 (2009)", standard_settle),
                    source("docs/ABI_POLICY.md", "the exported-symbol and ownership rules",
                           "the tracked revision", standard_settle),
                ],
            },
            {
                "id": "LVL-L5",
                "name": "machine code",
                "frc_scope": "the instructions and object code the pinned toolchain emits "
                             "for the P-256 and ECDSA path",
                "constrains": "must preserve the LVL-L4 properties, including the timing "
                              "discipline where one is claimed",
                "implementation_derived": False,
                "realisation": "the release artefact; ETP-T6 records its TCB and the absence "
                               "of a correspondence claim",
                "normative_sources": [
                    source("System V Application Binary Interface, AMD64 Architecture "
                           "Processor Supplement", "the calling convention and ELF object "
                                                    "format",
                           "the revision named in ETP-T6", standard_settle),
                    source("rust-toolchain.toml", "the pinned compiler channel",
                           "the tracked revision", standard_settle),
                ],
            },
            {
                "id": "LVL-L6",
                "name": "consumer composition",
                "frc_scope": "the P-256 and ECDSA signing path executed by OpenSSH",
                "constrains": "the real caller must respect every precondition and boundary",
                "implementation_derived": False,
                "realisation": "docs/OPENSSH-COHORT.md is the declared consumer cohort",
                "normative_sources": [
                    source("RFC 4253", "the SSH transport layer",
                           "RFC 4253 (2006)", standard_settle),
                    source("RFC 5656", "the ECDSA host-key and user-authentication algorithms",
                           "RFC 5656 (2009)", standard_settle),
                    source("docs/OPENSSH-COHORT.md", "the consumer cohort rule",
                           "the tracked revision", standard_settle),
                ],
            },
        ],
        "edges": [
            {
                "id": "RFE-1", "from": "LVL-L1", "to": "LVL-L2", "status": "NONE",
                "obligation": "a separately written abstract specification, and a proof that "
                              "the executable reference refines it",
                "evidence": ["evidence/etp-t5/RESULTS.json",
                             "evidence/etp-t3/REFINEMENT.json"],
                "proof": None,
                "reason": "ETP-T5 supplies an executable reference written from the "
                          "normative documents, so the substrate exists, but no separate "
                          "abstract-specification artefact is defined for it to refine. The "
                          "obligation is undischarged.",
            },
            {
                "id": "RFE-2", "from": "LVL-L2", "to": "LVL-L3", "status": "NONE",
                "obligation": "a refinement proof from the executable reference to the crate",
                "evidence": ["evidence/etp-t5/RESULTS.json",
                             "evidence/etp4/VERIFICATION-RECEIPT.md"],
                "proof": None,
                "reason": "ETP-T5 records 0 differences over 4,326 sampled cases, which is "
                          "differential evidence and not a refinement proof. The ETP-4 REDC "
                          "congruence is an internal cross-check.",
            },
            {
                "id": "RFE-3", "from": "LVL-L3", "to": "LVL-L4", "status": "PARTIAL",
                "obligation": "the crate preserves the declared ABI contract",
                "evidence": ["evidence/etp-t3/REFINEMENT.json", "docs/ABI_POLICY.md"],
                "proof": None,
                "reason": "symbols, versions and layouts are checked; ownership, error-queue "
                          "ordering and callback semantics are not established.",
            },
            {
                "id": "RFE-4", "from": "LVL-L4", "to": "LVL-L5", "status": "NONE",
                "obligation": "the machine code preserves the verified source properties",
                "evidence": ["evidence/etp-t6/TCB.json",
                             "evidence/etp-t6/CLAIM-MATRIX.json"],
                "proof": None,
                "reason": "ETP-2's byte-identical builds are a build-identity result, not "
                          "source-to-binary correspondence. No object-code correspondence "
                          "exists.",
            },
            {
                "id": "RFE-5", "from": "LVL-L5", "to": "LVL-L6", "status": "PARTIAL",
                "obligation": "the real caller establishes every precondition of the "
                              "machine-code path",
                "evidence": ["evidence/etp-t6/CLAIM-MATRIX.json",
                             "docs/OPENSSH-COHORT.md"],
                "proof": None,
                "reason": "bounded consumer closures exist, but none establishes Pre(c) => P, "
                          "both report safe_compatible false, and the OpenSSH adjudication is "
                          "NOT ESTABLISHED.",
            },
        ],
        "status_vocabulary": ["NONE", "PARTIAL", "NOT_ESTABLISHED", "DISCHARGED"],
        "discharged_edges": 0,
    }


def tool(
    name: str,
    purpose: str,
    theorem_class: str,
    admission: str,
    source_path: str,
    refusal_reason: str,
    verification: dict[str, Any],
    pinned_version: str | None = None,
    digests: list[dict[str, str]] | None = None,
    tcb: list[str] | None = None,
    positive: dict[str, str] | None = None,
    negative: dict[str, str] | None = None,
    supported: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "purpose": purpose,
        "theorem_class": theorem_class,
        "pinned_version": pinned_version,
        "digests": digests or [],
        "tcb": tcb or [],
        "positive_control": positive,
        "negative_control": negative,
        "supported_rustc": supported,
        "admission": admission,
        "refusal_reason": refusal_reason,
        "verification": verification,
        "source": source_path,
    }


def tools_register() -> dict[str, Any]:
    etp4 = "evidence/etp4/VERIFICATION-RECEIPT.md"
    not_tested = ("not installed in the pinned environment and no admission test was run in "
                  "this session, so nothing about it was measured; denial by default")
    settle = ("Install the tool at a pinned version, record its digest and TCB, read its "
              "supported rustc range, and run a positive control (a true theorem it proves) "
              "and a negative control (a false near-miss it refuses) against the pinned "
              "1.98.1 in the court.")
    tools = [
        tool(
            "Kani", "Rust source verification (bounded model checking)",
            "bounded model checking of a Rust harness under declared unwind and size bounds; "
            "a SUCCESSFUL result is a theorem about that harness and those bounds, not a "
            "universal statement",
            "REFUSED", etp4,
            "It does not support the pinned rustc 1.98.1: it runs on its bundled "
            "nightly-2026-08-21 (rustc 1.100.0-nightly), so a Kani result describes a "
            "different compilation unit from the pinned candidate. The programme forbids "
            "citing it for the binary.",
            recorded("Re-run the recorded positive and negative controls in the court if a "
                     "Kani release supports the pinned toolchain; until then it is admitted "
                     "for nothing.", etp4),
            pinned_version="0.68.0",
            digests=[
                {"path": "/usr/local/cargo/bin/kani",
                 "sha256": "1bbdab14d231b24474e7ccbc306d619cb4205601ac7db71eb9f3cd4bbe364ca0",
                 "recorded_in": etp4},
                {"path": "/usr/local/cargo/bin/cargo-kani",
                 "sha256": "a262fbecf63abb280c87bbe5cb772b24786f58cb0dc2b0cce148c16a0214dcf6",
                 "recorded_in": etp4},
            ],
            tcb=["Kani 0.68.0 frontend", "CBMC 6.11.0 backend",
                 "bundled nightly-2026-08-21 (rustc 1.100.0-nightly)",
                 "the harness and its declared bounds"],
            positive={"command": "kani --harness admission_positive",
                      "observed": "exit 0, VERIFICATION:- SUCCESSFUL, 1 successfully "
                                  "verified harness"},
            negative={"command": "kani --harness admission_negative_must_fail",
                      "observed": "exit 1, VERIFICATION:- FAILED, Status: FAILURE at the "
                                  "assertion"},
            supported={"pinned": "1.98.1",
                       "supported": "nightly-2026-08-21 / rustc 1.100.0-nightly",
                       "supports_pinned": False},
        ),
        tool(
            "z3", "cryptographic specification and symbolic equivalence (SMT backend)",
            "SMT decision procedure over an externally supplied encoding; it has no Rust "
            "semantics of its own",
            "REFUSED", etp4,
            "It has no Rust front-end and no verified encoding of the crate's semantics was "
            "built, so it can establish nothing about the crate by itself. ETP-4 admitted it "
            "for nothing.",
            recorded("Add a separately verified encoding of the property and re-run; the "
                     "solver alone remains unadmitted for Rust claims.", etp4),
            pinned_version="4.8.12",
            digests=[{"path": "/usr/bin/z3",
                      "sha256": "5def71f04f8df16e633c084f611a7cd9fbe633cd87d5016e980ee18949e769b5",
                      "recorded_in": etp4}],
            tcb=["Z3 4.8.12", "the encoding, which does not exist"],
            supported={"pinned": "1.98.1", "supported": "(no Rust front-end)",
                       "supports_pinned": False},
        ),
        tool(
            "SAW", "cryptographic specification and symbolic equivalence",
            "symbolic execution and equivalence checking over LLVM or MIR against a Cryptol "
            "specification",
            "REFUSED",
            "docs/FORMAL-REFINEMENT-CERTIFICATION.md",
            "The reported SAW 1.5 support for Rust MIR beyond experimental status, and its "
            "supported rustc range, were not read, and no admission test was run. The "
            "programme records the claim as UNVERIFIED. A tool that cannot process the "
            "pinned 1.98.1 is not admitted.",
            unverified("Read the SAW 1.5 release notes at a pinned version, record the "
                       "supported rustc range and digest, and run a positive and a negative "
                       "admission control against rustc 1.98.1 in the court."),
        ),
        tool(
            "Verus", "Rust source verification",
            "deductive verification of Rust source with machine-checked preconditions and "
            "postconditions",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "Creusot", "Rust source verification",
            "deductive verification by translation to Why3",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "Aeneas", "Rust source verification",
            "functional translation of Rust to a proof assistant's model",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "Charon", "Rust source verification (Aeneas frontend)",
            "extraction of a Rust program into Aeneas' intermediate representation",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "Lean", "Rust source verification and mathematical formalisation",
            "dependent type theory with a small trusted kernel; a proof is about the "
            "formalised model",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "Rocq (Coq)", "Rust source verification and mathematical formalisation",
            "dependent type theory with a small trusted kernel; a proof is about the "
            "formalised model",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "Cryptol", "cryptographic specification and symbolic equivalence",
            "an executable specification language with a symbolic evaluator; it specifies, "
            "it does not prove the implementation",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "HOL Light", "machine-code proof",
            "a Hoare triple over an instruction sequence checked by a small LCF kernel; it "
            "says nothing about whether the model matches the hardware",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "Isabelle/HOL", "machine-code proof",
            "higher-order logic with a small trusted kernel; a proof is about the "
            "formalised model",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "Translation validation", "machine-code proof",
            "a per-run check that the produced code preserves the source semantics; it is a "
            "mechanism, not a tool, and no implementation was selected",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "Candle", "independent kernel checking",
            "an independent HOL Light proof-trace checker; it checks a proof, not the "
            "property's relevance",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
        tool(
            "Proof-trace checkers", "independent kernel checking",
            "independent re-checking of a proof trace against a small kernel",
            "REFUSED", "docs/ETP-TODO.md", not_tested, unverified(settle),
        ),
    ]
    return {
        "schema": frc_registers.SCHEMA_TOOLS,
        "item": "FRC-0 of docs/FRC-TODO.md",
        "kind": "tool-admission-register",
        "base_commit": BASE_COMMIT,
        "recorded_at": RECORDED_AT,
        "pinned_toolchain": {
            "channel": "1.98.1",
            "source": "rust-toolchain.toml",
            "rule": "A tool that cannot process the pinned compiler is not admitted, and this "
                    "is not a reason to change the pinned compiler without a separate "
                    "decision.",
        },
        "selection": {
            "Rust source verification": ["Verus", "Kani", "Creusot", "Aeneas", "Lean",
                                         "Rocq (Coq)"],
            "cryptographic specification and symbolic equivalence": ["Cryptol", "SAW"],
            "machine-code proof": ["HOL Light", "Isabelle/HOL", "Translation validation"],
            "independent kernel checking": ["Candle", "Proof-trace checkers"],
        },
        "admission_rule": (
            "Admission requires a pinned version and digest, the theorem class it is "
            "entitled to establish, its TCB, a positive and a negative control, and the "
            "rustc range it actually supports. A tool that was not tested is refused, not "
            "admitted by default. No tool is admitted in this record."
        ),
        "tools": tools,
    }


def documents() -> list[tuple[str, dict[str, Any]]]:
    return [
        ("FRONTIER-GAPS.json", frontier_register()),
        ("SPECIFICATION-HIERARCHY.json", hierarchy_register()),
    ]


def tools_document() -> dict[str, Any]:
    return tools_register()


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

    missing = [path for path in CITED if not (REPO / path).is_file()]
    if missing:
        print("frc-0: a cited path does not exist: " + ", ".join(missing))
        return 1

    written: list[Path] = []
    for name, document in documents():
        target = out / name
        if args.check:
            if not target.is_file() or target.read_text(encoding="utf-8") != \
                    json.dumps(document, indent=2, sort_keys=True) + "\n":
                print(f"frc-0: {target} differs from the produced bytes")
                return 1
        else:
            _write(target, document)
        written.append(target)

    tools_target = (out / "TOOLS.json") if args.out else \
        (REPO / "forensics" / "frc" / "TOOLS.json")
    tools_target.parent.mkdir(parents=True, exist_ok=True)
    tools_doc = tools_document()
    if args.check:
        if not tools_target.is_file() or tools_target.read_text(encoding="utf-8") != \
                json.dumps(tools_doc, indent=2, sort_keys=True) + "\n":
            print(f"frc-0: {tools_target} differs from the produced bytes")
            return 1
    else:
        _write(tools_target, tools_doc)
    written.append(tools_target)

    frontier = frontier_register()
    hierarchy = hierarchy_register()
    counts = frc_registers.summary(frontier, hierarchy, tools_doc)
    print("frc-0: " + " ".join(f"{key}={counts[key]}" for key in sorted(counts)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
