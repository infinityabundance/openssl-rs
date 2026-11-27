#!/usr/bin/env python3
"""PFP-9 kernel provenance and no-inheritance validator.

The problem this tool exists for
--------------------------------
`docs/PERFORMANCE-FRONTIER.md` §8 asks for a provenance decision and the PFP-9
queue row asks for per-platform evidence with **no inheritance across targets**.
Neither was executable, so a kernel's differential court, binary audit or
measurement could be cited at a different target, profile, compiler or artefact
from the one that produced it. This tool reads the machine-readable per-kernel
table (`forensics/performance/KERNELS.json`), the same table
`docs/KERNEL-VERIFICATION.md` renders, and refuses by name:

* an evidence digest that differs from the digest its campaign recorded;
* a kernel target or profile that differs from its campaign artefact's;
* an audit whose digest differs from the evidence record's artefact (an audit
  inherited from another digest is not an audit of this artefact);
* a kernel entry with no explicit proof status, or a proof field that is neither
  `NO_PROOF` nor a bound `MACHINE_CHECKED` entry;
* a kernel entry that does not enumerate the targets for which no evidence
  exists, including the hardware-absent AArch64 and AVX-512/IFMA arms;
* an assurance class that is absent, misbound, missing its required evidence, or
  carried only as a prose assertion: `SOURCE_TAINT_TESTED` needs taint evidence
  with a firing negative control; `ARTEFACT_AUDITED` needs a structured `PASS`
  audit and a subject the checker hashes itself; `MACHINE_CHECKED` needs an
  existing harness and digest; and `PASS_WITH_STOP` / `PASS_WITH_RESIDUAL` are
  refused above `SOURCE_REVIEWED`;
* a claim that cites a kernel across a different target, profile or artefact.

A kernel with no court or no audit is accepted as `NO_PROOF` when the claim
asserts no assurance dimension. That is a recorded absence, not a pass.

Assurance is a set of complementary dimensions, not a ladder. Each kernel
carries an `assurance` list; each entry names a class, a scope, a subject
(source identity and/or artefact digest), its assumptions, result, instrument,
negative control and evidence path. Claims name the classes they rely on.

What this tool does not decide
------------------------------
It does not run the courts, the audits or the benchmarks it reads about. Passing
is a well-bound register, not a proof: every kernel is `NO_PROOF`, the audits are
review aids, and the venue has no PMU. It does not turn a source-bound reading
into artefact evidence.

Exit codes
----------
  0  every entry accepted
  1  at least one entry refused
  2  usage error

Usage
-----
    python3 forensics/tools/kernel_verification.py check
    python3 forensics/tools/kernel_verification.py check --register PATH
    python3 forensics/tools/kernel_verification.py rules [--json]
    python3 forensics/tools/kernel_verification.py self-test

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTER = REPO_ROOT / "forensics" / "performance" / "KERNELS.json"
DEFAULT_DOC = REPO_ROOT / "docs" / "KERNEL-VERIFICATION.md"
SCHEMA = "openssl-rs/performance/kernel-register/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BINDINGS = ("ARTEFACT", "MIXED", "SOURCE")
COURT_RESULTS = ("PASS", "PASS_WITH_STOP", "PASS_WITH_RESIDUAL", "FAIL", "NOT_RUN")

# Assurance is a set of complementary dimensions, not a ladder.  A kernel may
# hold several entries at once; a claim names the dimensions it relies on.
ASSURANCE_CLASSES = (
    "UNASSESSED",
    "SOURCE_REVIEWED",
    "SOURCE_TAINT_TESTED",
    "ARTEFACT_AUDITED",
    "ARTEFACT_TAINT_TESTED",
    "STATISTICALLY_TESTED",
    "MACHINE_CHECKED",
    "INDEPENDENTLY_REPRODUCED",
)
ASSURANCE_RESULTS = ("PASS", "PASS_WITH_STOP", "PASS_WITH_RESIDUAL", "FAIL", "NOT_RUN")
# Classes that assert something about a built artefact and therefore require an
# artefact-bound evidence record and a subject the checker can hash itself.
ARTEFACT_CLASSES = frozenset(
    {
        "ARTEFACT_AUDITED",
        "ARTEFACT_TAINT_TESTED",
        "STATISTICALLY_TESTED",
        "MACHINE_CHECKED",
        "INDEPENDENTLY_REPRODUCED",
    }
)
TAINT_CLASSES = frozenset({"SOURCE_TAINT_TESTED", "ARTEFACT_TAINT_TESTED"})
# `PASS_WITH_STOP` and `PASS_WITH_RESIDUAL` are admissible only at
# SOURCE_REVIEWED or below; every stronger dimension must be a clean PASS.
INADMISSIBLE_RESULTS = frozenset({"PASS_WITH_STOP", "PASS_WITH_RESIDUAL"})
PROOF_STATES = ("NO_PROOF", "MACHINE_CHECKED")
NO_EVIDENCE_STATUSES = (
    "NOT_APPLICABLE_HARDWARE",
    "NOT_RUN",
    "MEASURED_REJECTED",
    "NO_EVIDENCE",
)

KV_JSON_MALFORMED = "KV_JSON_MALFORMED"
KV_JSON_DUPLICATE_KEY = "KV_JSON_DUPLICATE_KEY"
KV_JSON_NON_FINITE = "KV_JSON_NON_FINITE"
KV_SCHEMA = "KV_SCHEMA"
KV_DUPLICATE_ID = "KV_DUPLICATE_ID"
KV_UNKNOWN_CAMPAIGN = "KV_UNKNOWN_CAMPAIGN"
KV_EVIDENCE_DIGEST_MISMATCH = "KV_EVIDENCE_DIGEST_MISMATCH"
KV_TARGET_MISMATCH = "KV_TARGET_MISMATCH"
KV_PROFILE_MISMATCH = "KV_PROFILE_MISMATCH"
KV_AUDIT_DIGEST_MISMATCH = "KV_AUDIT_DIGEST_MISMATCH"
KV_PROOF_ABSENT = "KV_PROOF_ABSENT"
KV_NO_EVIDENCE_TARGETS_ABSENT = "KV_NO_EVIDENCE_TARGETS_ABSENT"
KV_NO_EVIDENCE_TARGET_UNDECLARED = "KV_NO_EVIDENCE_TARGET_UNDECLARED"
KV_CLAIM_UNKNOWN_KERNEL = "KV_CLAIM_UNKNOWN_KERNEL"
KV_CLAIM_UNKNOWN_EVIDENCE = "KV_CLAIM_UNKNOWN_EVIDENCE"
KV_CLAIM_IDENTITY_MISMATCH = "KV_CLAIM_IDENTITY_MISMATCH"
KV_CT_CLAIM_WITHOUT_COURT = "KV_CT_CLAIM_WITHOUT_COURT"
KV_CT_CLAIM_WITHOUT_AUDIT = "KV_CT_CLAIM_WITHOUT_AUDIT"
KV_SOURCE_BOUND_CT_CLAIM = "KV_SOURCE_BOUND_CT_CLAIM"
KV_DOC_KERNEL_MISSING = "KV_DOC_KERNEL_MISSING"
KV_DOC_NO_INHERITANCE_MISSING = "KV_DOC_NO_INHERITANCE_MISSING"
KV_ASSURANCE_CLASS_ABSENT = "KV_ASSURANCE_CLASS_ABSENT"
KV_ASSURANCE_BINDING_MISMATCH = "KV_ASSURANCE_BINDING_MISMATCH"
KV_AUDIT_VERDICT_NOT_PASS = "KV_AUDIT_VERDICT_NOT_PASS"
KV_ASSURANCE_TAINT_ABSENT = "KV_ASSURANCE_TAINT_ABSENT"
KV_ASSURANCE_NO_FIRING_CONTROL = "KV_ASSURANCE_NO_FIRING_CONTROL"
KV_PROOF_UNBOUND = "KV_PROOF_UNBOUND"
KV_ASSURANCE_OUTCOME_INADMISSIBLE = "KV_ASSURANCE_OUTCOME_INADMISSIBLE"
KV_ARTEFACT_SUBJECT_MISMATCH = "KV_ARTEFACT_SUBJECT_MISMATCH"
KV_ASSURANCE_INCOMPLETE = "KV_ASSURANCE_INCOMPLETE"

CODES = (
    KV_JSON_MALFORMED,
    KV_JSON_DUPLICATE_KEY,
    KV_JSON_NON_FINITE,
    KV_SCHEMA,
    KV_DUPLICATE_ID,
    KV_UNKNOWN_CAMPAIGN,
    KV_EVIDENCE_DIGEST_MISMATCH,
    KV_TARGET_MISMATCH,
    KV_PROFILE_MISMATCH,
    KV_AUDIT_DIGEST_MISMATCH,
    KV_PROOF_ABSENT,
    KV_NO_EVIDENCE_TARGETS_ABSENT,
    KV_NO_EVIDENCE_TARGET_UNDECLARED,
    KV_CLAIM_UNKNOWN_KERNEL,
    KV_CLAIM_UNKNOWN_EVIDENCE,
    KV_CLAIM_IDENTITY_MISMATCH,
    KV_CT_CLAIM_WITHOUT_COURT,
    KV_CT_CLAIM_WITHOUT_AUDIT,
    KV_SOURCE_BOUND_CT_CLAIM,
    KV_DOC_KERNEL_MISSING,
    KV_DOC_NO_INHERITANCE_MISSING,
    KV_ASSURANCE_CLASS_ABSENT,
    KV_ASSURANCE_BINDING_MISMATCH,
    KV_AUDIT_VERDICT_NOT_PASS,
    KV_ASSURANCE_TAINT_ABSENT,
    KV_ASSURANCE_NO_FIRING_CONTROL,
    KV_PROOF_UNBOUND,
    KV_ASSURANCE_OUTCOME_INADMISSIBLE,
    KV_ARTEFACT_SUBJECT_MISMATCH,
    KV_ASSURANCE_INCOMPLETE,
)

RULES: dict[str, str] = {
    KV_JSON_MALFORMED: "the register is not parseable JSON",
    KV_JSON_DUPLICATE_KEY: "the register repeats an object key",
    KV_JSON_NON_FINITE: "the register carries NaN or Infinity",
    KV_SCHEMA: "the register or an entry is malformed or of the wrong schema",
    KV_DUPLICATE_ID: "two campaigns, kernels or claims share an id",
    KV_UNKNOWN_CAMPAIGN: "a kernel evidence record names no registered campaign",
    KV_EVIDENCE_DIGEST_MISMATCH: (
        "a kernel evidence digest differs from the digest its campaign recorded"
    ),
    KV_TARGET_MISMATCH: "a kernel target differs from its campaign artefact's target",
    KV_PROFILE_MISMATCH: "a kernel profile differs from its campaign artefact's profile",
    KV_AUDIT_DIGEST_MISMATCH: (
        "an audit digest differs from the evidence record's artefact: an audit is "
        "never inherited from another digest"
    ),
    KV_PROOF_ABSENT: "a kernel entry has no explicit proof status (use NO_PROOF)",
    KV_NO_EVIDENCE_TARGETS_ABSENT: (
        "a kernel entry does not enumerate the targets for which no evidence exists"
    ),
    KV_NO_EVIDENCE_TARGET_UNDECLARED: (
        "a kernel does not declare the hardware-absent AArch64 and AVX-512/IFMA arms"
    ),
    KV_CLAIM_UNKNOWN_KERNEL: "a claim cites an unregistered kernel",
    KV_CLAIM_UNKNOWN_EVIDENCE: "a claim cites an evidence index that does not exist",
    KV_CLAIM_IDENTITY_MISMATCH: (
        "a claim cites a kernel across a different target, profile or artefact"
    ),
    KV_CT_CLAIM_WITHOUT_COURT: (
        "a constant-time claim cites a kernel with no differential court"
    ),
    KV_CT_CLAIM_WITHOUT_AUDIT: (
        "a constant-time claim cites a kernel with no binary audit at that artefact"
    ),
    KV_SOURCE_BOUND_CT_CLAIM: (
        "a constant-time claim cites source-bound evidence, not an artefact"
    ),
    KV_DOC_KERNEL_MISSING: "the document does not name a kernel in the register",
    KV_DOC_NO_INHERITANCE_MISSING: "the document does not state the no-inheritance rule",
    KV_ASSURANCE_CLASS_ABSENT: (
        "a claim names an assurance class its kernel does not hold at the cited evidence"
    ),
    KV_ASSURANCE_BINDING_MISMATCH: (
        "an artefact-level assurance class cites evidence that is not purely artefact-bound"
    ),
    KV_AUDIT_VERDICT_NOT_PASS: (
        "an audit record does not carry a structured PASS verdict"
    ),
    KV_ASSURANCE_TAINT_ABSENT: (
        "a taint-tested class has no taint evidence bound to its subject"
    ),
    KV_ASSURANCE_NO_FIRING_CONTROL: (
        "taint evidence is claimed without a firing negative control"
    ),
    KV_PROOF_UNBOUND: (
        "the proof field is neither NO_PROOF nor a MACHINE_CHECKED entry with a "
        "checkable harness"
    ),
    KV_ASSURANCE_OUTCOME_INADMISSIBLE: (
        "a class above SOURCE_REVIEWED carries PASS_WITH_STOP or PASS_WITH_RESIDUAL"
    ),
    KV_ARTEFACT_SUBJECT_MISMATCH: (
        "an artefact subject is absent or does not hash to its declared digest"
    ),
    KV_ASSURANCE_INCOMPLETE: (
        "an assurance entry is missing a required field or its evidence path is absent"
    ),
}

NO_INHERITANCE_RULE = (
    "Evidence for one target, profile, compiler or artefact never transfers to "
    "another. A claim that cites evidence from a different identity is refused."
)


@dataclass(frozen=True, order=True)
class Problem:
    pointer: str
    code: str
    detail: str


class Refusal(Exception):
    def __init__(self, code: str, pointer: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.pointer = pointer
        self.detail = detail


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise Refusal(KV_JSON_DUPLICATE_KEY, "/", f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


def _non_finite(value: Any) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, dict):
        return any(_non_finite(v) for v in value.values())
    if isinstance(value, list):
        return any(_non_finite(v) for v in value)
    return False


def loads_document(text: str) -> Any:
    try:
        document = json.loads(text, object_pairs_hook=_pairs)
    except Refusal:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise Refusal(KV_JSON_MALFORMED, "/", str(exc)) from exc
    if _non_finite(document):
        raise Refusal(KV_JSON_NON_FINITE, "/", "NaN or Infinity in the register")
    return document


def load_document(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal(KV_JSON_MALFORMED, "/", f"{path}: {exc}") from exc
    return loads_document(text)


def _text(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _sha(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.match(value) is not None


def _hash_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _subject_path(root: Path, value: Any) -> Path | None:
    if not _text(value):
        return None
    path = Path(value)
    return path if path.is_absolute() else root / path


def _add(problems: list[Problem], code: str, pointer: str, detail: str) -> None:
    problems.append(Problem(pointer, code, detail))


def _check_hardware(document: dict, problems: list[Problem]) -> None:
    pointer = "/hardware"
    hardware = document.get("hardware")
    if not isinstance(hardware, dict):
        _add(problems, KV_SCHEMA, pointer, "hardware must be an object")
        return
    for key in ("machine", "cpu", "pmu", "aarch64_target"):
        if not _text(hardware.get(key)):
            _add(problems, KV_SCHEMA, f"{pointer}/{key}", "missing or empty")
    absent = hardware.get("features_absent")
    if not isinstance(absent, list) or not all(isinstance(item, str) for item in absent):
        _add(problems, KV_SCHEMA, f"{pointer}/features_absent", "must be an array of strings")


def _check_provenance(document: dict, problems: list[Problem]) -> None:
    pointer = "/provenance_decision"
    decision = document.get("provenance_decision")
    if not isinstance(decision, dict):
        _add(problems, KV_SCHEMA, pointer, "provenance_decision must be an object")
        return
    for key in ("id", "decision", "section_8_route"):
        if not _text(decision.get(key)):
            _add(problems, KV_SCHEMA, f"{pointer}/{key}", "missing or empty")
    for key in ("rationale", "invalidated_by", "rejected_arms"):
        value = decision.get(key)
        if not isinstance(value, list) or not value:
            _add(problems, KV_SCHEMA, f"{pointer}/{key}", "must be a non-empty array")
    if not _text(document.get("no_inheritance_rule")):
        _add(problems, KV_SCHEMA, "/no_inheritance_rule", "missing or empty")


def _check_campaigns(
    document: dict, problems: list[Problem]
) -> dict[str, dict]:
    campaigns = document.get("campaigns")
    if not isinstance(campaigns, dict) or not campaigns:
        _add(problems, KV_SCHEMA, "/campaigns", "must be a non-empty object")
        return {}
    for name, campaign in campaigns.items():
        pointer = f"/campaigns/{name}"
        if not isinstance(campaign, dict):
            _add(problems, KV_SCHEMA, pointer, "must be an object")
            continue
        artefact = campaign.get("artefact")
        if not isinstance(artefact, dict):
            _add(problems, KV_SCHEMA, f"{pointer}/artefact", "must be an object")
            continue
        binding = artefact.get("binding")
        digest = artefact.get("sha256")
        if binding == "ARTEFACT":
            if not _sha(digest):
                _add(
                    problems,
                    KV_SCHEMA,
                    f"{pointer}/artefact/sha256",
                    "an artefact-bound campaign needs a full SHA-256",
                )
        elif binding == "SOURCE":
            if digest is not None:
                _add(
                    problems,
                    KV_SCHEMA,
                    f"{pointer}/artefact/sha256",
                    "a source-bound campaign must not claim an artefact digest",
                )
        else:
            _add(
                problems,
                KV_SCHEMA,
                f"{pointer}/artefact/binding",
                f"{binding!r} is not ARTEFACT or SOURCE",
            )
        for key in ("target", "profile", "source"):
            if not _text(artefact.get(key)):
                _add(problems, KV_SCHEMA, f"{pointer}/artefact/{key}", "missing or empty")
    return campaigns


def _check_evidence(
    evidence: Any,
    pointer: str,
    campaigns: dict[str, dict],
    problems: list[Problem],
) -> dict | None:
    if not isinstance(evidence, dict):
        _add(problems, KV_SCHEMA, pointer, "must be an object")
        return None
    campaign_name = evidence.get("campaign")
    campaign = campaigns.get(campaign_name) if isinstance(campaign_name, str) else None
    if campaign is None:
        _add(
            problems,
            KV_UNKNOWN_CAMPAIGN,
            f"{pointer}/campaign",
            f"{campaign_name!r} is not a registered campaign",
        )
        return None
    artefact = campaign["artefact"]
    binding = evidence.get("binding")
    if binding not in BINDINGS:
        _add(problems, KV_SCHEMA, f"{pointer}/binding", f"{binding!r} is not a binding")
        return None
    digest = evidence.get("artefact_sha256")
    if artefact["binding"] == "SOURCE":
        if digest is not None or binding != "SOURCE":
            _add(
                problems,
                KV_EVIDENCE_DIGEST_MISMATCH,
                f"{pointer}/artefact_sha256",
                "a source-bound campaign's evidence must carry no artefact digest",
            )
    else:
        if digest != artefact["sha256"]:
            _add(
                problems,
                KV_EVIDENCE_DIGEST_MISMATCH,
                f"{pointer}/artefact_sha256",
                f"evidence {digest!r} != campaign {artefact['sha256']!r}",
            )
        if binding == "SOURCE":
            _add(
                problems,
                KV_EVIDENCE_DIGEST_MISMATCH,
                f"{pointer}/binding",
                "an artefact-bound campaign's evidence cannot be SOURCE-bound",
            )
    if evidence.get("target") != artefact["target"]:
        _add(
            problems,
            KV_TARGET_MISMATCH,
            f"{pointer}/target",
            f"{evidence.get('target')!r} != artefact target {artefact['target']!r}",
        )
    if evidence.get("profile") != artefact["profile"]:
        _add(
            problems,
            KV_PROFILE_MISMATCH,
            f"{pointer}/profile",
            f"{evidence.get('profile')!r} != artefact profile {artefact['profile']!r}",
        )
    court = evidence.get("differential")
    if court is not None:
        if not isinstance(court, dict):
            _add(problems, KV_SCHEMA, f"{pointer}/differential", "must be an object or null")
        else:
            if not _text(court.get("court")):
                _add(problems, KV_SCHEMA, f"{pointer}/differential/court", "missing")
            result = court.get("result")
            if result not in COURT_RESULTS:
                _add(
                    problems,
                    KV_SCHEMA,
                    f"{pointer}/differential/result",
                    f"{result!r} is not a court result",
                )
            if court.get("binding") not in BINDINGS:
                _add(
                    problems,
                    KV_SCHEMA,
                    f"{pointer}/differential/binding",
                    "missing or invalid",
                )
    audit = evidence.get("audit")
    if audit is not None:
        if not isinstance(audit, dict):
            _add(problems, KV_SCHEMA, f"{pointer}/audit", "must be an object or null")
        else:
            for key in ("kind", "result"):
                if not _text(audit.get(key)):
                    _add(problems, KV_SCHEMA, f"{pointer}/audit/{key}", "missing")
            verdict = audit.get("verdict")
            if verdict not in ASSURANCE_RESULTS:
                _add(
                    problems,
                    KV_AUDIT_VERDICT_NOT_PASS,
                    f"{pointer}/audit/verdict",
                    f"{verdict!r} is not a structured verdict (need one of "
                    f"{', '.join(ASSURANCE_RESULTS)})",
                )
            audit_digest = audit.get("digest")
            if not _sha(audit_digest):
                _add(
                    problems,
                    KV_SCHEMA,
                    f"{pointer}/audit/digest",
                    "not a full SHA-256",
                )
            elif digest is None or audit_digest != digest:
                _add(
                    problems,
                    KV_AUDIT_DIGEST_MISMATCH,
                    f"{pointer}/audit/digest",
                    f"audit {audit_digest!r} != evidence artefact {digest!r}",
                )
            if audit.get("binding") != "ARTEFACT":
                _add(
                    problems,
                    KV_SCHEMA,
                    f"{pointer}/audit/binding",
                    "a binary audit is ARTEFACT-bound",
                )
    return evidence


def _check_no_evidence_targets(
    kernel: dict,
    pointer: str,
    hardware: dict,
    problems: list[Problem],
) -> None:
    targets = kernel.get("no_evidence_targets")
    if not isinstance(targets, list) or not targets:
        _add(
            problems,
            KV_NO_EVIDENCE_TARGETS_ABSENT,
            f"{pointer}/no_evidence_targets",
            "must be a non-empty array",
        )
        return
    seen: set[str] = set()
    for index, entry in enumerate(targets):
        where = f"{pointer}/no_evidence_targets/{index}"
        if not isinstance(entry, dict):
            _add(problems, KV_SCHEMA, where, "must be an object")
            continue
        target = entry.get("target")
        status = entry.get("status")
        feature = entry.get("missing_feature")
        if not _text(target):
            _add(problems, KV_SCHEMA, f"{where}/target", "missing")
        else:
            seen.add(target)
        if status not in NO_EVIDENCE_STATUSES:
            _add(problems, KV_SCHEMA, f"{where}/status", f"{status!r} is not a status")
        if not _text(feature):
            _add(problems, KV_SCHEMA, f"{where}/missing_feature", "missing")
    absent = {item for item in hardware.get("features_absent", []) if isinstance(item, str)}
    required: list[str] = []
    if "avx512ifma" in absent or "avx512f" in absent:
        required.append("avx512ifma")
    if str(hardware.get("aarch64_target", "")).startswith("NOT_PRESENT"):
        required.append("aarch64")
    for feature in required:
        if not any(feature in target for target in seen):
            _add(
                problems,
                KV_NO_EVIDENCE_TARGET_UNDECLARED,
                f"{pointer}/no_evidence_targets",
                f"no target names the hardware-absent {feature} arm",
            )


def _campaign_source(campaigns: dict[str, dict], evidence: dict) -> str | None:
    name = evidence.get("campaign")
    campaign = campaigns.get(name) if isinstance(name, str) else None
    if not isinstance(campaign, dict):
        return None
    artefact = campaign.get("artefact")
    return artefact.get("source") if isinstance(artefact, dict) else None


def _check_proof(kernel: dict, pointer: str, problems: list[Problem]) -> None:
    proof = kernel.get("proof")
    if not _text(proof):
        _add(
            problems,
            KV_PROOF_ABSENT,
            f"{pointer}/proof",
            "use NO_PROOF or a proof reference; never leave the field blank",
        )
        return
    if proof == "NO_PROOF":
        return
    if proof != "MACHINE_CHECKED":
        _add(
            problems,
            KV_PROOF_UNBOUND,
            f"{pointer}/proof",
            f"{proof!r} is not NO_PROOF or MACHINE_CHECKED; an arbitrary prose "
            "string is not a bound proof",
        )
        return
    entries = kernel.get("assurance")
    if not isinstance(entries, list) or not any(
        isinstance(entry, dict) and entry.get("class") == "MACHINE_CHECKED"
        for entry in entries
    ):
        _add(
            problems,
            KV_PROOF_UNBOUND,
            f"{pointer}/proof",
            "MACHINE_CHECKED needs a MACHINE_CHECKED assurance entry with a harness",
        )


def _check_assurance(
    kernel: dict,
    pointer: str,
    campaigns: dict[str, dict],
    root: Path,
    problems: list[Problem],
) -> None:
    entries = kernel.get("assurance")
    if not isinstance(entries, list) or not entries:
        _add(
            problems,
            KV_ASSURANCE_INCOMPLETE,
            f"{pointer}/assurance",
            "must be a non-empty array; an unassessed kernel says UNASSESSED explicitly",
        )
        return
    evidence_list = kernel.get("evidence") if isinstance(kernel.get("evidence"), list) else []
    for index, entry in enumerate(entries):
        where = f"{pointer}/assurance/{index}"
        if not isinstance(entry, dict):
            _add(problems, KV_ASSURANCE_INCOMPLETE, where, "must be an object")
            continue
        assurance_class = entry.get("class")
        if assurance_class not in ASSURANCE_CLASSES:
            _add(
                problems,
                KV_SCHEMA,
                f"{where}/class",
                f"{assurance_class!r} is not an assurance class",
            )
            continue
        if not _text(entry.get("scope")):
            _add(
                problems,
                KV_ASSURANCE_INCOMPLETE,
                f"{where}/scope",
                "the scope and invariant argument are missing",
            )
        result = entry.get("result")
        if result not in ASSURANCE_RESULTS:
            _add(
                problems,
                KV_ASSURANCE_INCOMPLETE,
                f"{where}/result",
                f"{result!r} is not an assurance result",
            )
            result = "NOT_RUN"
        if assurance_class == "UNASSESSED":
            if result not in ("NOT_RUN", "FAIL"):
                _add(
                    problems,
                    KV_ASSURANCE_OUTCOME_INADMISSIBLE,
                    f"{where}/result",
                    "UNASSESSED cannot carry a passing result",
                )
            continue
        assumptions = entry.get("assumptions")
        if (
            not isinstance(assumptions, list)
            or not assumptions
            or not all(_text(item) for item in assumptions)
        ):
            _add(
                problems,
                KV_ASSURANCE_INCOMPLETE,
                f"{where}/assumptions",
                "a non-empty written invariant argument is required",
            )
        if assurance_class != "SOURCE_REVIEWED" and result in INADMISSIBLE_RESULTS:
            _add(
                problems,
                KV_ASSURANCE_OUTCOME_INADMISSIBLE,
                f"{where}/result",
                f"{result} is admissible only at SOURCE_REVIEWED or below",
            )
        evidence_index = entry.get("evidence")
        if (
            not isinstance(evidence_index, int)
            or isinstance(evidence_index, bool)
            or not (0 <= evidence_index < len(evidence_list))
        ):
            _add(
                problems,
                KV_ASSURANCE_INCOMPLETE,
                f"{where}/evidence",
                f"{evidence_index!r} is not an evidence index",
            )
            continue
        evidence = evidence_list[evidence_index]
        if not isinstance(evidence, dict):
            continue
        source = _campaign_source(campaigns, evidence)
        subject = entry.get("subject")
        if not isinstance(subject, dict):
            _add(problems, KV_ASSURANCE_INCOMPLETE, f"{where}/subject", "must be an object")
            continue
        evidence_path = entry.get("evidence_path")
        declared_path = _subject_path(root, evidence_path)
        if declared_path is None or not declared_path.is_file():
            _add(
                problems,
                KV_ASSURANCE_INCOMPLETE,
                f"{where}/evidence_path",
                f"{evidence_path!r} does not name an existing file",
            )
        instrument = entry.get("instrument")
        if not _text(instrument):
            _add(
                problems,
                KV_ASSURANCE_INCOMPLETE,
                f"{where}/instrument",
                "the instrument identity is missing",
            )
        if assurance_class in ("SOURCE_REVIEWED", "SOURCE_TAINT_TESTED"):
            subject_source = subject.get("source")
            if not _text(subject_source):
                _add(
                    problems,
                    KV_ASSURANCE_INCOMPLETE,
                    f"{where}/subject/source",
                    "the source identity is missing",
                )
            else:
                if source is not None and subject_source != source:
                    _add(
                        problems,
                        KV_ASSURANCE_CLASS_ABSENT,
                        f"{where}/subject/source",
                        "the subject source is not the cited evidence campaign's source",
                    )
                commit = re.search(r"\b[0-9a-f]{7,40}\b", subject_source)
                if commit and commit.group(0)[:8] not in str(entry.get("scope", "")):
                    _add(
                        problems,
                        KV_ASSURANCE_INCOMPLETE,
                        f"{where}/scope",
                        "the written invariant argument does not name the reviewed source",
                    )
        artefact_subject = subject.get("artefact")
        if assurance_class in ARTEFACT_CLASSES:
            if not isinstance(artefact_subject, dict):
                _add(
                    problems,
                    KV_ASSURANCE_INCOMPLETE,
                    f"{where}/subject/artefact",
                    "an artefact subject is required",
                )
                continue
            declared = artefact_subject.get("sha256")
            subject_path = _subject_path(root, artefact_subject.get("path"))
            if not _sha(declared):
                _add(
                    problems,
                    KV_ASSURANCE_INCOMPLETE,
                    f"{where}/subject/artefact/sha256",
                    "not a full SHA-256",
                )
                continue
            if subject_path is None:
                _add(
                    problems,
                    KV_ASSURANCE_INCOMPLETE,
                    f"{where}/subject/artefact/path",
                    "the subject path is missing",
                )
                continue
            if evidence.get("binding") != "ARTEFACT":
                _add(
                    problems,
                    KV_ASSURANCE_BINDING_MISMATCH,
                    f"{where}/evidence",
                    f"{assurance_class} requires an ARTEFACT-bound evidence record, "
                    f"not {evidence.get('binding')!r}",
                )
            if declared != evidence.get("artefact_sha256"):
                _add(
                    problems,
                    KV_ASSURANCE_CLASS_ABSENT,
                    f"{where}/subject/artefact/sha256",
                    "the subject digest is not the cited evidence digest",
                )
            actual = _hash_file(subject_path)
            if actual is None or actual != declared:
                _add(
                    problems,
                    KV_ARTEFACT_SUBJECT_MISMATCH,
                    f"{where}/subject/artefact/path",
                    f"{artefact_subject.get('path')!r} hashes to {actual!r}, not the "
                    f"declared {declared!r}",
                )
        if assurance_class == "ARTEFACT_AUDITED":
            audit = evidence.get("audit")
            if not isinstance(audit, dict):
                _add(
                    problems,
                    KV_AUDIT_VERDICT_NOT_PASS,
                    f"{where}/evidence/audit",
                    "no audit record at the cited evidence",
                )
            else:
                if audit.get("verdict") != "PASS":
                    _add(
                        problems,
                        KV_AUDIT_VERDICT_NOT_PASS,
                        f"{where}/evidence/audit/verdict",
                        f"audit verdict is {audit.get('verdict')!r}, not PASS",
                    )
                if (
                    isinstance(artefact_subject, dict)
                    and artefact_subject.get("sha256") not in (None, audit.get("digest"))
                ):
                    _add(
                        problems,
                        KV_AUDIT_DIGEST_MISMATCH,
                        f"{where}/subject/artefact/sha256",
                        "the audit is not of the subject digest",
                    )
        if assurance_class in TAINT_CLASSES:
            taint = evidence.get("ctgrind")
            if not isinstance(taint, dict) or not _text(taint.get("result")):
                _add(
                    problems,
                    KV_ASSURANCE_TAINT_ABSENT,
                    f"{where}/evidence/ctgrind",
                    "no taint record at the cited evidence",
                )
            else:
                taint_binding = taint.get("binding")
                if assurance_class == "SOURCE_TAINT_TESTED" and taint_binding not in (
                    "SOURCE",
                    "MIXED",
                ):
                    _add(
                        problems,
                        KV_ASSURANCE_TAINT_ABSENT,
                        f"{where}/evidence/ctgrind/binding",
                        f"source taint evidence is {taint_binding!r}, not SOURCE or MIXED",
                    )
                if assurance_class == "ARTEFACT_TAINT_TESTED" and taint_binding != "ARTEFACT":
                    _add(
                        problems,
                        KV_ASSURANCE_TAINT_ABSENT,
                        f"{where}/evidence/ctgrind/binding",
                        f"artefact taint evidence is {taint_binding!r}, not ARTEFACT",
                    )
            if not _text(instrument) or not any(
                word in instrument.lower() for word in ("ctgrind", "taint", "valgrind")
            ):
                _add(
                    problems,
                    KV_ASSURANCE_INCOMPLETE,
                    f"{where}/instrument",
                    "a taint-tested class must name a taint instrument",
                )
            control = entry.get("negative_control")
            control_path = (
                _subject_path(root, control.get("evidence_path"))
                if isinstance(control, dict)
                else None
            )
            if (
                not isinstance(control, dict)
                or control.get("fired") is not True
                or not _text(control.get("detail"))
                or control_path is None
                or not control_path.is_file()
            ):
                _add(
                    problems,
                    KV_ASSURANCE_NO_FIRING_CONTROL,
                    f"{where}/negative_control",
                    "taint evidence needs a firing negative control with an existing "
                    "evidence path",
                )
        if assurance_class == "STATISTICALLY_TESTED":
            experiment = entry.get("experiment")
            if not isinstance(experiment, dict):
                _add(
                    problems,
                    KV_ASSURANCE_INCOMPLETE,
                    f"{where}/experiment",
                    "a declared experiment is required",
                )
            else:
                samples = experiment.get("samples")
                if (
                    not isinstance(samples, int)
                    or isinstance(samples, bool)
                    or samples <= 0
                ):
                    _add(
                        problems,
                        KV_ASSURANCE_INCOMPLETE,
                        f"{where}/experiment/samples",
                        "a positive sample count is required",
                    )
                for key in ("statistic", "threshold", "environment"):
                    if not _text(experiment.get(key)):
                        _add(
                            problems,
                            KV_ASSURANCE_INCOMPLETE,
                            f"{where}/experiment/{key}",
                            "missing",
                        )
        if assurance_class == "MACHINE_CHECKED":
            harness = entry.get("harness")
            if not isinstance(harness, dict):
                _add(
                    problems,
                    KV_ASSURANCE_INCOMPLETE,
                    f"{where}/harness",
                    "a checkable harness is required",
                )
            else:
                harness_path = _subject_path(root, harness.get("path"))
                harness_digest = harness.get("sha256")
                if harness_path is None or not harness_path.is_file():
                    _add(
                        problems,
                        KV_ASSURANCE_INCOMPLETE,
                        f"{where}/harness/path",
                        "the harness path is absent",
                    )
                elif not _sha(harness_digest):
                    _add(
                        problems,
                        KV_ASSURANCE_INCOMPLETE,
                        f"{where}/harness/sha256",
                        "not a full SHA-256",
                    )
                elif _hash_file(harness_path) != harness_digest:
                    _add(
                        problems,
                        KV_ASSURANCE_INCOMPLETE,
                        f"{where}/harness/sha256",
                        "the harness does not hash to its declared digest",
                    )
        if assurance_class == "INDEPENDENTLY_REPRODUCED":
            reproduction = entry.get("reproduction")
            if not isinstance(reproduction, dict):
                _add(
                    problems,
                    KV_ASSURANCE_INCOMPLETE,
                    f"{where}/reproduction",
                    "a reproduction record is required",
                )
            else:
                party = reproduction.get("party")
                producer = reproduction.get("producer")
                if not _text(party) or not _text(producer):
                    _add(
                        problems,
                        KV_ASSURANCE_INCOMPLETE,
                        f"{where}/reproduction",
                        "party and producer must both be named",
                    )
                elif party.strip().casefold() == producer.strip().casefold():
                    _add(
                        problems,
                        KV_ASSURANCE_INCOMPLETE,
                        f"{where}/reproduction/party",
                        "the reproducing party must differ from the producer",
                    )


def _check_kernels(
    document: dict, campaigns: dict[str, dict], problems: list[Problem], root: Path
) -> dict[str, dict]:
    kernels = document.get("kernels")
    if not isinstance(kernels, list) or not kernels:
        _add(problems, KV_SCHEMA, "/kernels", "must be a non-empty array")
        return {}
    by_id: dict[str, dict] = {}
    hardware = document.get("hardware") if isinstance(document.get("hardware"), dict) else {}
    for index, kernel in enumerate(kernels):
        pointer = f"/kernels/{index}"
        if not isinstance(kernel, dict):
            _add(problems, KV_SCHEMA, pointer, "must be an object")
            continue
        kernel_id = kernel.get("id")
        if not _text(kernel_id):
            _add(problems, KV_SCHEMA, f"{pointer}/id", "missing")
            continue
        if kernel_id in by_id:
            _add(problems, KV_DUPLICATE_ID, f"{pointer}/id", f"duplicate {kernel_id!r}")
        by_id[kernel_id] = kernel
        for key in ("label", "ships"):
            if not _text(kernel.get(key)):
                _add(problems, KV_SCHEMA, f"{pointer}/{key}", "missing or empty")
        _check_proof(kernel, pointer, problems)
        evidence = kernel.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            _add(problems, KV_SCHEMA, f"{pointer}/evidence", "must be a non-empty array")
        else:
            for ev_index, record in enumerate(evidence):
                _check_evidence(record, f"{pointer}/evidence/{ev_index}", campaigns, problems)
        _check_assurance(kernel, pointer, campaigns, root, problems)
        _check_no_evidence_targets(kernel, pointer, hardware, problems)
    return by_id


def _check_claims(
    document: dict, kernels: dict[str, dict], problems: list[Problem]
) -> None:
    claims = document.get("claims")
    if not isinstance(claims, list) or not claims:
        _add(problems, KV_SCHEMA, "/claims", "must be a non-empty array")
        return
    seen: set[str] = set()
    for index, claim in enumerate(claims):
        pointer = f"/claims/{index}"
        if not isinstance(claim, dict):
            _add(problems, KV_SCHEMA, pointer, "must be an object")
            continue
        claim_id = claim.get("id")
        if not _text(claim_id):
            _add(problems, KV_SCHEMA, f"{pointer}/id", "missing")
        elif claim_id in seen:
            _add(problems, KV_DUPLICATE_ID, f"{pointer}/id", f"duplicate {claim_id!r}")
        else:
            seen.add(claim_id)
        assurance = claim.get("assurance")
        if not isinstance(assurance, list):
            _add(
                problems,
                KV_SCHEMA,
                f"{pointer}/assurance",
                "must be an array of assurance classes (empty for no assurance claim)",
            )
            assurance = []
        for class_index, assurance_class in enumerate(assurance):
            if assurance_class not in ASSURANCE_CLASSES or assurance_class == "UNASSESSED":
                _add(
                    problems,
                    KV_SCHEMA,
                    f"{pointer}/assurance/{class_index}",
                    f"{assurance_class!r} is not a claimable assurance class",
                )
        target = claim.get("target")
        profile = claim.get("profile")
        digest = claim.get("artefact_sha256")
        if not _text(target):
            _add(problems, KV_SCHEMA, f"{pointer}/target", "missing")
        if not _text(profile):
            _add(problems, KV_SCHEMA, f"{pointer}/profile", "missing")
        if any(
            assurance_class in ARTEFACT_CLASSES
            for assurance_class in assurance
            if isinstance(assurance_class, str)
        ) and not _sha(digest):
            _add(
                problems,
                KV_SOURCE_BOUND_CT_CLAIM,
                f"{pointer}/artefact_sha256",
                "an artefact-level assurance claim needs a full artefact digest",
            )
        cited = claim.get("kernels")
        if not isinstance(cited, list) or not cited:
            _add(problems, KV_SCHEMA, f"{pointer}/kernels", "must be a non-empty array")
            continue
        for cite_index, citation in enumerate(cited):
            where = f"{pointer}/kernels/{cite_index}"
            if not isinstance(citation, dict):
                _add(problems, KV_SCHEMA, where, "must be an object")
                continue
            kernel = kernels.get(citation.get("id"))
            if kernel is None:
                _add(
                    problems,
                    KV_CLAIM_UNKNOWN_KERNEL,
                    f"{where}/id",
                    f"{citation.get('id')!r} is not a registered kernel",
                )
                continue
            ev_index = citation.get("evidence")
            evidence_list = kernel.get("evidence")
            if not isinstance(ev_index, int) or not isinstance(evidence_list, list) or not (
                0 <= ev_index < len(evidence_list)
            ):
                _add(
                    problems,
                    KV_CLAIM_UNKNOWN_EVIDENCE,
                    f"{where}/evidence",
                    f"{ev_index!r} is not an evidence index",
                )
                continue
            evidence = evidence_list[ev_index]
            if not isinstance(evidence, dict):
                continue
            if (
                claim.get("target") != evidence.get("target")
                or claim.get("profile") != evidence.get("profile")
                or claim.get("artefact_sha256") != evidence.get("artefact_sha256")
            ):
                _add(
                    problems,
                    KV_CLAIM_IDENTITY_MISMATCH,
                    where,
                    "claim identity differs from the cited evidence record",
                )
            for assurance_class in assurance:
                if assurance_class not in ASSURANCE_CLASSES or assurance_class == "UNASSESSED":
                    continue
                if assurance_class in ARTEFACT_CLASSES:
                    binding = evidence.get("binding")
                    if binding == "SOURCE" or evidence.get("artefact_sha256") is None:
                        _add(
                            problems,
                            KV_SOURCE_BOUND_CT_CLAIM,
                            f"{where}/evidence",
                            "artefact-level assurance must be artefact-bound",
                        )
                    elif binding != "ARTEFACT":
                        _add(
                            problems,
                            KV_ASSURANCE_BINDING_MISMATCH,
                            f"{where}/evidence",
                            f"{assurance_class} requires ARTEFACT-bound evidence, not "
                            f"{binding!r}",
                        )
                    court = evidence.get("differential")
                    if not isinstance(court, dict) or court.get("result") not in (
                        "PASS",
                        "PASS_WITH_STOP",
                        "PASS_WITH_RESIDUAL",
                    ):
                        _add(
                            problems,
                            KV_CT_CLAIM_WITHOUT_COURT,
                            f"{where}/evidence",
                            "no passing differential court at this evidence record",
                        )
                    audit = evidence.get("audit")
                    if not isinstance(audit, dict):
                        _add(
                            problems,
                            KV_CT_CLAIM_WITHOUT_AUDIT,
                            f"{where}/evidence",
                            "no binary audit at this evidence record",
                        )
                    elif audit.get("verdict") != "PASS":
                        _add(
                            problems,
                            KV_AUDIT_VERDICT_NOT_PASS,
                            f"{where}/evidence/audit/verdict",
                            f"audit verdict is {audit.get('verdict')!r}, not PASS",
                        )
                held = None
                entries = kernel.get("assurance")
                if isinstance(entries, list):
                    for entry in entries:
                        if (
                            isinstance(entry, dict)
                            and entry.get("class") == assurance_class
                            and entry.get("evidence") == ev_index
                        ):
                            held = entry
                            break
                if held is None:
                    _add(
                        problems,
                        KV_ASSURANCE_CLASS_ABSENT,
                        where,
                        f"{assurance_class} is not held at evidence {ev_index}",
                    )
                elif (
                    assurance_class != "SOURCE_REVIEWED"
                    and held.get("result") in INADMISSIBLE_RESULTS
                ):
                    _add(
                        problems,
                        KV_ASSURANCE_OUTCOME_INADMISSIBLE,
                        where,
                        f"{held.get('result')} is admissible only at SOURCE_REVIEWED or "
                        "below",
                    )


def check_document(
    document: Any,
    hardware: dict | None = None,
    doc_text: str | None = None,
    root: Path = REPO_ROOT,
) -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(document, dict):
        _add(problems, KV_SCHEMA, "", "the register must be an object")
        return sorted(set(problems))
    if document.get("schema") != SCHEMA:
        _add(
            problems,
            KV_SCHEMA,
            "/schema",
            f"expected {SCHEMA!r}, found {document.get('schema')!r}",
        )
    _check_hardware(document, problems)
    _check_provenance(document, problems)
    campaigns = _check_campaigns(document, problems)
    kernels = _check_kernels(document, campaigns, problems, root)
    _check_claims(document, kernels, problems)
    if doc_text is not None:
        for kernel in document.get("kernels", []) if isinstance(document.get("kernels"), list) else []:
            kernel_id = kernel.get("id") if isinstance(kernel, dict) else None
            if _text(kernel_id) and kernel_id not in doc_text:
                _add(
                    problems,
                    KV_DOC_KERNEL_MISSING,
                    "/kernels",
                    f"docs/KERNEL-VERIFICATION.md does not name {kernel_id!r}",
                )
        if "no-inheritance" not in doc_text.lower():
            _add(
                problems,
                KV_DOC_NO_INHERITANCE_MISSING,
                "/no_inheritance_rule",
                "docs/KERNEL-VERIFICATION.md does not state the no-inheritance rule",
            )
    return sorted(set(problems))


def check_root(root: Path = REPO_ROOT) -> list[Problem]:
    """The gate hook: validate the register a repository root actually carries.

    `docs_consistency.py` (release-gate item 6) calls this, so the register cannot
    be edited into an acceptance the standalone command would refuse while the
    gate still passes.  A parse refusal is returned as a `Problem`, not raised.
    """
    register = root / "forensics" / "performance" / "KERNELS.json"
    doc = root / "docs" / "KERNEL-VERIFICATION.md"
    try:
        document = load_document(register)
    except Refusal as exc:
        return [Problem(exc.pointer, exc.code, exc.detail)]
    doc_text = doc.read_text(encoding="utf-8") if doc.is_file() else None
    return check_document(document, doc_text=doc_text, root=root)


# ---------------------------------------------------------------------------
# Self-test controls
# ---------------------------------------------------------------------------

_FIXTURE_ARTEFACT = Path(__file__).resolve()
_A = hashlib.sha256(_FIXTURE_ARTEFACT.read_bytes()).hexdigest()
_B = "b" * 64
_AUDIT_EVIDENCE = "docs/KERNEL-VERIFICATION.md"
_TS = "x86_64-unknown-linux-gnu release"
_TP = "release, x86_64-unknown-linux-gnu, rustc 1.98.1"
_NO_EVIDENCE = [
    {
        "target": "aarch64-unknown-linux-gnu",
        "status": "NOT_APPLICABLE_HARDWARE",
        "missing_feature": "aarch64",
    },
    {
        "target": "x86_64-avx512ifma",
        "status": "NOT_APPLICABLE_HARDWARE",
        "missing_feature": "avx512f, avx512ifma",
    },
    {
        "target": "x86_64-avx2",
        "status": "NOT_RUN",
        "missing_feature": "no AVX2 backend",
    },
]


def _valid_document() -> dict:
    return {
        "schema": SCHEMA,
        "hardware": {
            "machine": "x86_64",
            "cpu": "test",
            "features_present": ["adx", "bmi2", "avx2"],
            "features_absent": ["avx512f", "avx512ifma"],
            "pmu": "NOT_PRESENT",
            "aarch64_target": "NOT_PRESENT",
        },
        "provenance_decision": {
            "id": "TEST-PROVENANCE",
            "decision": "portable Rust ships",
            "section_8_route": "recorded, not adopted",
            "rationale": ["measured alternatives lost"],
            "invalidated_by": ["a compiler change"],
            "rejected_arms": [{"arm": "test", "campaign": "A", "result": "slower"}],
        },
        "no_inheritance_rule": NO_INHERITANCE_RULE,
        "campaigns": {
            "A": {
                "artefact": {
                    "sha256": _A,
                    "target": _TS,
                    "profile": _TP,
                    "source": "source A",
                    "binding": "ARTEFACT",
                }
            },
            "S": {
                "artefact": {
                    "sha256": None,
                    "target": "test-binary target",
                    "profile": "test binary",
                    "source": "source S",
                    "binding": "SOURCE",
                }
            },
        },
        "kernels": [
            {
                "id": "k-artefact",
                "label": "artefact-bound kernel",
                "ships": "SHIPPED",
                "proof": "NO_PROOF",
                "evidence": [
                    {
                        "campaign": "A",
                        "artefact_sha256": _A,
                        "target": _TS,
                        "profile": _TP,
                        "binding": "ARTEFACT",
                        "differential": {
                            "court": "test court",
                            "result": "PASS",
                            "binding": "ARTEFACT",
                        },
                        "audit": {
                            "kind": "BINARY_BRANCH_AUDIT",
                            "result": "0 secret-derived",
                            "verdict": "PASS",
                            "digest": _A,
                            "binding": "ARTEFACT",
                        },
                        "ctgrind": {
                            "result": "0 errors / 0 contexts; the negative control fires",
                            "binding": "MIXED",
                        },
                    }
                ],
                "assurance": [
                    {
                        "class": "ARTEFACT_AUDITED",
                        "scope": "source A: mont_mul_ladder_into has no secret-derived transfer",
                        "evidence": 0,
                        "subject": {
                            "source": "source A",
                            "artefact": {
                                "path": str(_FIXTURE_ARTEFACT),
                                "sha256": _A,
                            },
                        },
                        "assumptions": [
                            "carry and borrow flags are consumed arithmetically"
                        ],
                        "result": "PASS",
                        "instrument": "objdump plus dataflow review",
                        "negative_control": {
                            "fired": True,
                            "detail": "a branchy canary produces a secret-derived jcc",
                            "evidence_path": _AUDIT_EVIDENCE,
                        },
                        "evidence_path": _AUDIT_EVIDENCE,
                    },
                    {
                        "class": "SOURCE_TAINT_TESTED",
                        "scope": "source A: secret-exponent taint is 0/0 on the source build",
                        "evidence": 0,
                        "subject": {"source": "source A", "artefact": None},
                        "assumptions": [
                            "the harness marks the exponent limb values undefined"
                        ],
                        "result": "PASS",
                        "instrument": "valgrind memcheck ctgrind",
                        "negative_control": {
                            "fired": True,
                            "detail": "CTGRIND_CONTROL=1 fires on a tainted limb",
                            "evidence_path": _AUDIT_EVIDENCE,
                        },
                        "evidence_path": _AUDIT_EVIDENCE,
                    },
                ],
                "no_evidence_targets": [dict(item) for item in _NO_EVIDENCE],
            },
            {
                "id": "k-source",
                "label": "source-bound kernel",
                "ships": "NOT_SHIPPED",
                "proof": "NO_PROOF",
                "evidence": [
                    {
                        "campaign": "S",
                        "artefact_sha256": None,
                        "target": "test-binary target",
                        "profile": "test binary",
                        "binding": "SOURCE",
                        "differential": {
                            "court": "test source court",
                            "result": "PASS",
                            "binding": "SOURCE",
                        },
                        "audit": None,
                    }
                ],
                "assurance": [
                    {
                        "class": "UNASSESSED",
                        "scope": "source S: no audit or firing taint control is recorded",
                        "assumptions": [],
                        "result": "NOT_RUN",
                    }
                ],
                "no_evidence_targets": [dict(item) for item in _NO_EVIDENCE],
            },
        ],
        "claims": [
            {
                "id": "c-ct",
                "assurance": ["ARTEFACT_AUDITED", "SOURCE_TAINT_TESTED"],
                "target": _TS,
                "profile": _TP,
                "artefact_sha256": _A,
                "kernels": [{"id": "k-artefact", "evidence": 0}],
            },
            {
                "id": "c-no-proof",
                "assurance": [],
                "target": "test-binary target",
                "profile": "test binary",
                "artefact_sha256": None,
                "kernels": [{"id": "k-source", "evidence": 0}],
            },
        ],
    }


def _mutate(function: Callable[[dict], None]) -> dict:
    document = _valid_document()
    function(document)
    return document


def _controls() -> list[tuple[str, dict, str | None]]:
    def set_kernel(field: str, value: Any) -> Callable[[dict], None]:
        def apply(document: dict) -> None:
            document["kernels"][0][field] = value

        return apply

    def set_evidence(field: str, value: Any) -> Callable[[dict], None]:
        def apply(document: dict) -> None:
            document["kernels"][0]["evidence"][0][field] = value

        return apply

    def set_claim(field: str, value: Any) -> Callable[[dict], None]:
        def apply(document: dict) -> None:
            document["claims"][0][field] = value

        return apply

    controls: list[tuple[str, dict, str | None]] = [
        ("valid-register", _valid_document(), None),
        (
            "non-vacuity-artefact-bound-ct",
            _valid_document(),
            None,
        ),
        (
            "non-ct-no-proof-accepted",
            _valid_document(),
            None,
        ),
        (
            KV_EVIDENCE_DIGEST_MISMATCH,
            _mutate(set_evidence("artefact_sha256", _B)),
            KV_EVIDENCE_DIGEST_MISMATCH,
        ),
        (
            KV_TARGET_MISMATCH,
            _mutate(set_evidence("target", "another-target")),
            KV_TARGET_MISMATCH,
        ),
        (
            KV_PROFILE_MISMATCH,
            _mutate(set_evidence("profile", "another-profile")),
            KV_PROFILE_MISMATCH,
        ),
        (
            KV_AUDIT_DIGEST_MISMATCH,
            _mutate(lambda d: d["kernels"][0]["evidence"][0]["audit"].update(digest=_B)),
            KV_AUDIT_DIGEST_MISMATCH,
        ),
        (
            KV_PROOF_ABSENT,
            _mutate(set_kernel("proof", "")),
            KV_PROOF_ABSENT,
        ),
        (
            KV_NO_EVIDENCE_TARGETS_ABSENT,
            _mutate(set_kernel("no_evidence_targets", [])),
            KV_NO_EVIDENCE_TARGETS_ABSENT,
        ),
        (
            KV_NO_EVIDENCE_TARGET_UNDECLARED,
            _mutate(
                lambda d: d["kernels"][0].update(
                    no_evidence_targets=[
                        {
                            "target": "x86_64-avx2",
                            "status": "NOT_RUN",
                            "missing_feature": "none",
                        }
                    ]
                )
            ),
            KV_NO_EVIDENCE_TARGET_UNDECLARED,
        ),
        (
            KV_UNKNOWN_CAMPAIGN,
            _mutate(set_evidence("campaign", "missing")),
            KV_UNKNOWN_CAMPAIGN,
        ),
        (
            KV_CLAIM_IDENTITY_MISMATCH,
            _mutate(set_claim("target", "another-target")),
            KV_CLAIM_IDENTITY_MISMATCH,
        ),
        (
            KV_CT_CLAIM_WITHOUT_COURT,
            _mutate(lambda d: d["kernels"][0]["evidence"][0].update(differential=None)),
            KV_CT_CLAIM_WITHOUT_COURT,
        ),
        (
            KV_CT_CLAIM_WITHOUT_AUDIT,
            _mutate(lambda d: d["kernels"][0]["evidence"][0].update(audit=None)),
            KV_CT_CLAIM_WITHOUT_AUDIT,
        ),
        (
            KV_SOURCE_BOUND_CT_CLAIM,
            _mutate(
                lambda d: d["claims"][0].update(
                    target="test-binary target",
                    profile="test binary",
                    artefact_sha256=None,
                    kernels=[{"id": "k-source", "evidence": 0}],
                )
            ),
            KV_SOURCE_BOUND_CT_CLAIM,
        ),
        (
            KV_CLAIM_UNKNOWN_KERNEL,
            _mutate(
                lambda d: d["claims"][0].update(
                    kernels=[{"id": "missing-kernel", "evidence": 0}]
                )
            ),
            KV_CLAIM_UNKNOWN_KERNEL,
        ),
        (
            KV_CLAIM_UNKNOWN_EVIDENCE,
            _mutate(
                lambda d: d["claims"][0].update(
                    kernels=[{"id": "k-artefact", "evidence": 9}]
                )
            ),
            KV_CLAIM_UNKNOWN_EVIDENCE,
        ),
        (
            KV_DUPLICATE_ID,
            _mutate(lambda d: d["kernels"].append(dict(d["kernels"][0]))),
            KV_DUPLICATE_ID,
        ),
        (
            KV_SCHEMA,
            _mutate(lambda d: d.update(schema="wrong")),
            KV_SCHEMA,
        ),
        (
            KV_ASSURANCE_CLASS_ABSENT,
            _mutate(set_claim("assurance", ["MACHINE_CHECKED"])),
            KV_ASSURANCE_CLASS_ABSENT,
        ),
        (
            KV_ASSURANCE_BINDING_MISMATCH,
            _mutate(set_evidence("binding", "MIXED")),
            KV_ASSURANCE_BINDING_MISMATCH,
        ),
        (
            KV_AUDIT_VERDICT_NOT_PASS,
            _mutate(
                lambda d: d["kernels"][0]["evidence"][0]["audit"].update(
                    verdict="NOT_RUN"
                )
            ),
            KV_AUDIT_VERDICT_NOT_PASS,
        ),
        (
            KV_ASSURANCE_TAINT_ABSENT,
            _mutate(set_evidence("ctgrind", None)),
            KV_ASSURANCE_TAINT_ABSENT,
        ),
        (
            KV_ASSURANCE_NO_FIRING_CONTROL,
            _mutate(
                lambda d: d["kernels"][0]["assurance"][1]["negative_control"].update(
                    fired=False
                )
            ),
            KV_ASSURANCE_NO_FIRING_CONTROL,
        ),
        (
            KV_PROOF_UNBOUND,
            _mutate(set_kernel("proof", "checked by inspection")),
            KV_PROOF_UNBOUND,
        ),
        (
            KV_ASSURANCE_OUTCOME_INADMISSIBLE,
            _mutate(
                lambda d: d["kernels"][0]["assurance"][0].update(result="PASS_WITH_STOP")
            ),
            KV_ASSURANCE_OUTCOME_INADMISSIBLE,
        ),
        (
            KV_ARTEFACT_SUBJECT_MISMATCH,
            _mutate(
                lambda d: d["kernels"][0]["assurance"][0]["subject"]["artefact"].update(
                    path="docs/KERNEL-VERIFICATION.md"
                )
            ),
            KV_ARTEFACT_SUBJECT_MISMATCH,
        ),
        (
            KV_ASSURANCE_INCOMPLETE,
            _mutate(
                lambda d: d["kernels"][0]["assurance"][0].update(
                    evidence_path="evidence/does-not-exist.md"
                )
            ),
            KV_ASSURANCE_INCOMPLETE,
        ),
    ]
    return controls


def _codes(document: dict, doc_text: str | None = None) -> set[str]:
    return {problem.code for problem in check_document(document, doc_text=doc_text)}


def self_test() -> int:
    failures: list[str] = []
    controls = _controls()
    for name, document, expected in controls:
        found = _codes(document)
        if expected is None:
            if found:
                failures.append(f"{name}: expected acceptance, got {sorted(found)}")
        elif expected not in found:
            failures.append(f"{name}: expected {expected}, got {sorted(found)}")
    doc_text = " ".join(kernel["id"] for kernel in _valid_document()["kernels"]) + \
        " no-inheritance rule"
    if _codes(_valid_document(), doc_text):
        failures.append("doc-positive: a complete document text was refused")
    if KV_DOC_KERNEL_MISSING not in _codes(_valid_document(), "no-inheritance"):
        failures.append("doc-kernel-missing: expected KV_DOC_KERNEL_MISSING")
    if KV_DOC_NO_INHERITANCE_MISSING not in _codes(
        _valid_document(), "k-artefact k-source"
    ):
        failures.append("doc-rule-missing: expected KV_DOC_NO_INHERITANCE_MISSING")
    for name, document, expected in _controls()[:3]:
        if expected is None and _codes(document):
            failures.append(f"{name}: positive control refused")
    if failures:
        print(f"kernel_verification self-test: FAIL ({len(failures)})")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print(
        f"kernel_verification self-test: ok ({len(controls)} controls, "
        f"{len(CODES)} refusal codes, 2 document controls, 3 positive controls)"
    )
    return 0


def mode_check(paths: list[Path], doc_path: Path) -> int:
    if not paths:
        paths = [DEFAULT_REGISTER]
    doc_text = doc_path.read_text(encoding="utf-8") if doc_path.is_file() else None
    refused = 0
    for path in paths:
        try:
            document = load_document(path)
        except Refusal as exc:
            print(f"REFUSED {path}: {exc.code} {exc.pointer}: {exc.detail}")
            refused += 1
            continue
        problems = check_document(document, doc_text=doc_text)
        if problems:
            refused += 1
            print(f"REFUSED {path}: {len(problems)} problem(s)")
            for problem in problems:
                print(f"  {problem.code} {problem.pointer}: {problem.detail}")
        else:
            print(f"accepted {path}")
    print(f"{len(paths) - refused} register(s) accepted, {refused} refused")
    return 0 if refused == 0 else 1


def mode_rules(as_json: bool) -> int:
    if as_json:
        print(json.dumps({"rule": NO_INHERITANCE_RULE, "codes": RULES}, indent=2, sort_keys=True))
    else:
        print(NO_INHERITANCE_RULE)
        print()
        for code in CODES:
            print(f"{code}: {RULES[code]}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    check = sub.add_parser("check", help="validate a kernel register")
    check.add_argument("--register", action="append", type=Path, default=[])
    check.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    sub.add_parser("rules", help="print the no-inheritance rule and refusal codes")
    sub.add_parser("self-test", help="run one positive and one negative control per code")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode == "check":
        return mode_check(args.register, args.doc)
    if args.mode == "rules":
        return mode_rules(False)
    if args.mode == "self-test":
        return self_test()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
