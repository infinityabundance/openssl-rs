#!/usr/bin/env python3
"""openssl-rs — the ETP claim algebra: typed claims, validation, conjunction.

A claim is a conjunction of independent obligations, never a scalar score
--------------------------------------------------------------------------------
The type in `evidence/etp/claim.schema.json` gives every claim orthogonal axes:
what is asserted (`property`), what that means operationally (`interpretation`),
over which population (`quantification`), over which code/artefacts
(`scope`), under which adversary (`threat_model`), bound to which source and
build identity and artefact digests (`identity`), against which normative
source (`authority`), about which object (`target`), under which checked
premises (`assumptions`), with which artefacts (`evidence`), trusting which
components (`tcb`), carrying which open items (`obligations`), invalidated by
which identities (`invalidation`), at which strength of method (`modality`),
with which reproduction state (`reproduction`), and with which decision
(`verdict`).

No axis is derived from another. There is no numeric field that combines
axes, no weighting, no ranking and no confidence value: `measure` carries a
recorded observation as an opaque string together with the constant
`"aggregation": "forbidden"`, and this tool refuses a document that introduces
a score or a modality ranking. In particular `BINARY_REFINEMENT_VERIFIED`
does not imply `SAFE_COMPATIBLE`, a `TESTED` claim with an open obligation
cannot carry a graduated verdict, and `ESTABLISHED` is not a §7 graduation
state.

What the tool decides
---------------------
  * schema conformance, with a self-contained JSON Schema 2020-12 subset
    checker (`jsonschema` is not installed in the court image and is not
    required);
  * the cross-field laws: verdict outrunning modality, graduated verdict with
    an open obligation or an incomplete dependency closure, unreconstructable
    evidence, missing threat model, self-declared acceptance policy, evidence
    aliasing, invalidation cycles, modality ranking, multiple candidate
    identities in one claim without a stated relationship, incomplete
    population coverage, an evidence record whose declared state contradicts a
    positive verdict, an evidence record whose declared typed measure contradicts
    the claim's own named measure, an aggregate claim that does not name its cell
    receipt digests, and a comparative measure that is untyped or contradicts
    another claim's value;
  * `conjoin`: the cohort verdict is the meet of member verdicts plus the
    union of their obligations, with every blocked member named;
  * `invalidate`: transitive, conservative invalidation from a changed
    identity;
  * `propagate`: obligations on a dependency reach dependents unless an
    independently checkable exclusion is attached;
  * `contradictions`: two claims with the same property/scope/identity and
    incompatible verdicts are a hard error.

What the tool does not decide
-----------------------------
It does not build, execute, sign, timestamp or adjudicate. It does not decide
whether a cited experiment actually occurred, whether an instrument is
sensitive to the defect it claims to detect, or whether two non-identical
identities are equivalent. It refuses rather than guesses (denial by default):
a claim that the schema cannot express is not a claim, and an input that
cannot be evaluated is not a pass.

Determinism
-----------
Validation returns refusals sorted by (path, rule, detail). The CLI serialises
with sorted keys and fixed separators, so the same input produces
byte-identical output. No timestamp is written by the validator.

Usage
-----
    python3 forensics/tools/etp_claims.py validate
    python3 forensics/tools/etp_claims.py validate --document PATH --check
    python3 forensics/tools/etp_claims.py conjoin --document PATH
    python3 forensics/tools/etp_claims.py invalidate --document PATH --changed ID
    python3 forensics/tools/etp_claims.py propagate --document PATH
    python3 forensics/tools/etp_claims.py contradictions --document PATH

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

import finding_identity

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "evidence/etp/claim.schema.json"
DEFAULT_CLAIMS = REPO_ROOT / "evidence/etp/claims.json"

# Properties whose claim is about an adversary or an observation that an
# adversary can exploit. A claim of one of these kinds must state its threat or
# leakage model; the other properties may legitimately leave the field null.
SECURITY_PROPERTIES = frozenset(
    {
        "identity",
        "provenance",
        "memory-safety",
        "timing",
        "cryptographic-assurance",
        "reproducibility",
        "consumer-graduation",
    }
)

# Modalities that assert an executed measurement, a discharged proof
# obligation or a verified binary refinement. None of them may be carried
# without evidence that is present.
VERIFICATION_MODALITIES = frozenset(
    {
        "TESTED",
        "INSTRUMENTED",
        "PROOF_OBLIGATIONS_DISCHARGED",
        "BINARY_REFINEMENT_VERIFIED",
    }
)

# The only §7 graduation verdict in this vocabulary. `ESTABLISHED` is an
# ordinary positive claim verdict, not a graduation state; a §7
# `SAFE_COMPATIBLE` verdict additionally needs a complete, named dependency
# closure and zero open obligations.
GRADUATED_VERDICTS = frozenset({"SAFE_COMPATIBLE"})
GRADUATED_MODALITIES = frozenset(
    {"PROOF_OBLIGATIONS_DISCHARGED", "BINARY_REFINEMENT_VERIFIED"}
)

# Fixed mapping from the ETP-0 inventory vocabulary. Conversion may rename
# SUPPORTED to ESTABLISHED and must preserve every other state. A document
# whose recorded ETP-0 verdict disagrees with the mapping is refused: the
# mapping is not a place to promote a claim silently.
ETP0_VERDICT_MAP = {
    "SUPPORTED": "ESTABLISHED",
    "PARTIAL": "PARTIAL",
    "CONTRADICTED": "CONTRADICTED",
    "SUPERSEDED": "SUPERSEDED",
    "WITHDRAWN": "WITHDRAWN",
    "UNKNOWN": "UNKNOWN",
}

# Conjunction order for non-absorbing verdicts, weakest first. UNKNOWN is
# weakest because a member that cannot be evaluated is a refusal, and a
# refusal cannot be combined into a stronger result.
VERDICT_STRENGTH = {
    "UNKNOWN": 0,
    "NOT_ESTABLISHED": 1,
    "RISK_ACCEPTED": 1,
    "PARTIAL": 2,
    "ESTABLISHED": 3,
    "SAFE_COMPATIBLE": 4,
}
# Absorbing verdicts, highest priority first. A conjunction containing one of
# these cannot be better than that state, and a stronger neighbour cannot hide
# it.
ABSORBING_VERDICTS = ("CONTRADICTED", "REFUTED", "WITHDRAWN", "SUPERSEDED")

# Verdicts that assert a positive result. A graduation modality is also a
# positive assertion even when the verdict is weaker, because it claims a
# discharged proof obligation or a verified binary refinement.
POSITIVE_VERDICTS = frozenset({"ESTABLISHED", "SAFE_COMPATIBLE"})

# ETP-T15: a claim derived from a CONTRADICTED ETP-0 verdict may be reclassified
# only by an explicit reconciliation record owned by the reconciliation item.  The
# new state is never a positive verdict: a reconciliation may move a contradiction
# to a recorded risk acceptance or to a superseded record, never to ESTABLISHED,
# PARTIAL or SAFE_COMPATIBLE.
RECONCILIATION_OWNER = "ETP-T15"
RECONCILABLE_STATES = frozenset({"RISK_ACCEPTED", "SUPERSEDED"})

# ETP-T10 section 1c: a cell state that a positive aggregate may not summarise
# away.  A cell that declares any of these states is a blocked row; an
# aggregate that reports a pass while containing one is refused.
BLOCKED_CELL_STATES = frozenset({
    "BLOCKED",
    "UNKNOWN",
    "NOT_ESTABLISHED",
    "NOT_GRADUATED",
    "REFUSED",
    "CONTRADICTED",
    "FAIL",
    "FAILED",
    "WITHDRAWN",
    "PARTIAL",
    "NOT_RUN",
})

# An evidence record's declared state that contradicts a positive verdict. The
# state comes from the tracked artefact and is copied into the claim; it is
# never inferred from the claim's own verdict or from the artefact's name.
CONTRADICTING_EVIDENCE_STATES = frozenset(
    {"WITHDRAWN", "REFUTED", "NOT_ESTABLISHED"}
)
# States that are not a current assertion of the cited artefact. `SUPERSEDED`
# is not itself a contradiction (the artefact was once current); it only means
# the entry cannot be the sole support for a positive verdict.
NON_CURRENT_EVIDENCE_STATES = CONTRADICTING_EVIDENCE_STATES | {"SUPERSEDED"}

# Keys that would introduce a permissive acceptance policy chosen by the
# candidate, or a modality ranking that could promote a claim. The schema is
# closed, so these keys are also schema violations; the pre-scan exists to
# name the precise refusal rule rather than a generic additional-property
# error.
FORBIDDEN_POLICY_KEYS = frozenset(
    {
        "policy",
        "acceptance",
        "acceptance_policy",
        "promotion_policy",
        "acceptance_rule",
        "thresholds",
        "trust_threshold",
    }
)
FORBIDDEN_RANKING_KEYS = frozenset(
    {
        "score",
        "scores",
        "weight",
        "weights",
        "confidence",
        "modality_rank",
        "modality_order",
        "ranking",
        "aggregate",
        "composite",
        "grade",
        "level_score",
    }
)

UNCHECKABLE_MARKERS = frozenset({"", "none", "unknown", "n/a", "not stated", "tbd"})


class Refusal(dict):
    """A refusal record: a rule identifier, the offending field, and a detail."""

    def __init__(self, rule: str, path: str, field: str, detail: str) -> None:
        super().__init__(rule=rule, path=path, field=field, detail=detail)


class AlgebraError(Exception):
    """A hard algebra error that no preference may resolve."""


class JsonIntegrityError(Exception):
    """A document was read with an ambiguous or non-finite JSON encoding."""

    def __init__(self, findings: list[Refusal]) -> None:
        ordered = sorted(
            findings, key=lambda item: (item["path"], item["rule"], item["detail"])
        )
        super().__init__("; ".join(item["detail"] for item in ordered))
        self.findings = ordered


# ---------------------------------------------------------------------------
# JSON loading and canonical helpers
# ---------------------------------------------------------------------------


class _JsonPairs:
    """An object's ordered key/value pairs, kept before duplicate keys collapse."""

    __slots__ = ("pairs",)

    def __init__(self, pairs: list[tuple[str, Any]]) -> None:
        self.pairs = pairs


class _JsonNonFinite:
    """A NaN or Infinity token, retained so its JSON pointer can be reported."""

    __slots__ = ("token",)

    def __init__(self, token: str) -> None:
        self.token = token


def _normalise_json(value: Any, path: str, findings: list[Refusal]) -> Any:
    """Rebuild plain JSON values, refusing duplicate keys and non-finite numbers."""
    if isinstance(value, _JsonPairs):
        rebuilt: dict[str, Any] = {}
        for key, item in value.pairs:
            if key in rebuilt:
                findings.append(
                    Refusal(
                        "EG_JSON_DUPLICATE_KEY",
                        _ptr(path, key),
                        key,
                        f"duplicate object key '{key}' at {_ptr(path, key)}; "
                        "a repeated key makes the document ambiguous",
                    )
                )
            rebuilt[key] = _normalise_json(item, _ptr(path, key), findings)
        return rebuilt
    if isinstance(value, list):
        return [
            _normalise_json(item, _ptr(path, str(index)), findings)
            for index, item in enumerate(value)
        ]
    if isinstance(value, _JsonNonFinite):
        findings.append(
            Refusal(
                "EG_JSON_NON_FINITE",
                path,
                _field_name(path),
                f"non-finite number {value.token!r} at {path}; "
                "JSON numbers must be finite",
            )
        )
        return None
    if isinstance(value, float) and not math.isfinite(value):
        findings.append(
            Refusal(
                "EG_JSON_NON_FINITE",
                path,
                _field_name(path),
                f"non-finite number {value!r} at {path}; "
                "JSON numbers must be finite",
            )
        )
        return None
    return value


def loads_strict(text: str, *, source: str = "<string>") -> Any:
    """Parse JSON without duplicate keys or non-finite numbers.

    Python's standard decoder silently keeps the last of two identical keys and
    accepts `NaN`/`Infinity`, either of which would let a document mean different
    things to different readers. Both are refused with the offending key path.
    """
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_JsonPairs,
            parse_constant=_JsonNonFinite,
        )
    except json.JSONDecodeError as exc:
        raise JsonIntegrityError(
            [
                Refusal(
                    "EG_JSON_MALFORMED",
                    "$",
                    "document",
                    f"{source}: malformed JSON at line {exc.lineno} column "
                    f"{exc.colno}: {exc.msg}",
                )
            ]
        ) from exc
    findings: list[Refusal] = []
    document = _normalise_json(parsed, "$", findings)
    if findings:
        raise JsonIntegrityError(findings)
    return document


def load_json(path: Path) -> Any:
    return loads_strict(path.read_text(encoding="utf-8"), source=str(path))


def canonical(value: Any) -> str:
    return finding_identity.canonical_json(value)


def _json_equal(left: Any, right: Any) -> bool:
    """JSON equality that does not conflate true with 1."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right)
        )
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    return left == right


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _matches_type(value: Any, expected: str) -> bool:
    actual = _json_type(value)
    if expected == "number":
        return actual in ("number", "integer")
    if expected == "integer":
        return actual == "integer"
    return actual == expected


def _ptr(path: str, token: str) -> str:
    return f"{path}/{token}"


def _field_name(path: str) -> str:
    return path.rsplit("/", 1)[-1]


# ---------------------------------------------------------------------------
# Self-contained JSON Schema 2020-12 subset checker
# ---------------------------------------------------------------------------


def _resolve_ref(root: dict, ref: str) -> dict:
    if not ref.startswith("#/"):
        raise ValueError(f"only local references are supported: {ref}")
    target: Any = root
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or token not in target:
            raise ValueError(f"unresolvable reference: {ref}")
        target = target[token]
    if not isinstance(target, dict):
        raise ValueError(f"reference is not a schema object: {ref}")
    return target


def check_schema(
    instance: Any,
    schema: dict,
    root: dict,
    path: str = "$",
    refusals: list[Refusal] | None = None,
) -> list[Refusal]:
    """Validate `instance` against the supported schema subset, deterministically."""
    if refusals is None:
        refusals = []
    if not isinstance(schema, dict):
        return refusals

    if "$ref" in schema:
        target = _resolve_ref(root, schema["$ref"])
        check_schema(instance, target, root, path, refusals)

    if "type" in schema:
        expected = schema["type"]
        alternatives = expected if isinstance(expected, list) else [expected]
        if not any(_matches_type(instance, option) for option in alternatives):
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    f"expected type {canonical(expected)}, got {_json_type(instance)}",
                )
            )

    if "const" in schema and not _json_equal(instance, schema["const"]):
        refusals.append(
            Refusal(
                "EG_SCHEMA_VIOLATION",
                path,
                _field_name(path),
                f"must equal {canonical(schema['const'])}",
            )
        )

    if "enum" in schema:
        allowed = schema["enum"]
        if not any(_json_equal(instance, option) for option in allowed):
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    f"value {canonical(instance)} is not one of {canonical(allowed)}",
                )
            )

    if "allOf" in schema:
        for sub in schema["allOf"]:
            check_schema(instance, sub, root, path, refusals)

    if "anyOf" in schema:
        outcomes = [
            check_schema(instance, sub, root, path, [])
            for sub in schema["anyOf"]
        ]
        if not any(not outcome for outcome in outcomes):
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    "matches no alternative of anyOf",
                )
            )

    if "oneOf" in schema:
        outcomes = [
            check_schema(instance, sub, root, path, [])
            for sub in schema["oneOf"]
        ]
        matched = sum(1 for outcome in outcomes if not outcome)
        if matched != 1:
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    f"matches {matched} alternatives of oneOf; exactly one is required",
                )
            )

    if "not" in schema:
        if not check_schema(instance, schema["not"], root, path, []):
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    "matches a schema that must not match",
                )
            )

    if "if" in schema:
        condition_holds = not check_schema(instance, schema["if"], root, path, [])
        branch = schema.get("then") if condition_holds else schema.get("else")
        if isinstance(branch, dict):
            check_schema(instance, branch, root, path, refusals)

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for name in required:
            if name not in instance:
                refusals.append(
                    Refusal(
                        "EG_SCHEMA_VIOLATION",
                        _ptr(path, name),
                        name,
                        "required property is absent",
                    )
                )
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for name in sorted(properties):
                if name in instance:
                    check_schema(
                        instance[name], properties[name], root, _ptr(path, name), refusals
                    )
        additional = schema.get("additionalProperties", True)
        if additional is False:
            for name in sorted(instance):
                if name not in properties:
                    refusals.append(
                        Refusal(
                            "EG_SCHEMA_VIOLATION",
                            _ptr(path, name),
                            name,
                            "additional property is not permitted by the closed type",
                        )
                    )
        elif isinstance(additional, dict):
            for name in sorted(instance):
                if name not in properties:
                    check_schema(
                        instance[name], additional, root, _ptr(path, name), refusals
                    )
        dependent = schema.get("dependentRequired", {})
        if isinstance(dependent, dict):
            for name in sorted(dependent):
                if name in instance:
                    for other in dependent[name]:
                        if other not in instance:
                            refusals.append(
                                Refusal(
                                    "EG_SCHEMA_VIOLATION",
                                    _ptr(path, other),
                                    other,
                                    f"required when '{name}' is present",
                                )
                            )

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    f"has {len(instance)} item(s); at least {schema['minItems']} required",
                )
            )
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    f"has {len(instance)} item(s); at most {schema['maxItems']} allowed",
                )
            )
        if schema.get("uniqueItems") is True:
            seen: dict[str, int] = {}
            for index, item in enumerate(instance):
                key = canonical(item)
                if key in seen:
                    refusals.append(
                        Refusal(
                            "EG_SCHEMA_VIOLATION",
                            _ptr(path, str(index)),
                            _field_name(path),
                            f"duplicates item {seen[key]} (uniqueItems)",
                        )
                    )
                else:
                    seen[key] = index
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(instance):
                check_schema(item, items, root, _ptr(path, str(index)), refusals)

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    f"length {len(instance)} is below minLength {schema['minLength']}",
                )
            )
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    f"length {len(instance)} exceeds maxLength {schema['maxLength']}",
                )
            )
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    f"does not match pattern {schema['pattern']}",
                )
            )

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            refusals.append(
                Refusal(
                    "EG_SCHEMA_VIOLATION",
                    path,
                    _field_name(path),
                    f"value {instance} is below minimum {schema['minimum']}",
                )
            )

    return refusals


# ---------------------------------------------------------------------------
# Pre-scan: forbidden policy, forbidden ranking, multiple candidate identities
# ---------------------------------------------------------------------------


def _walk_keys(value: Any, path: str = "$") -> Iterable[tuple[str, str]]:
    """Yield (json-pointer, key) for every object key, in canonical order."""
    if isinstance(value, dict):
        for key in sorted(value):
            yield _ptr(path, key), key
            yield from _walk_keys(value[key], _ptr(path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_keys(item, _ptr(path, str(index)))


def prescan_forbidden(doc: dict) -> list[Refusal]:
    refusals: list[Refusal] = []
    for path, key in _walk_keys(doc):
        if key in FORBIDDEN_POLICY_KEYS:
            refusals.append(
                Refusal(
                    "EG_SELF_DECLARED_POLICY",
                    path,
                    key,
                    "a candidate document may not declare its own acceptance policy",
                )
            )
        if key in FORBIDDEN_RANKING_KEYS:
            refusals.append(
                Refusal(
                    "EG_MODALITY_RANKING",
                    path,
                    key,
                    "a score or modality ranking would silently promote a claim",
                )
            )
    return refusals


def prescan_multiple_candidates(doc: dict) -> list[Refusal]:
    """Refuse more than one candidate identity with no stated relationship.

    A multi-candidate identity is permitted by the closed type only when the
    claim also states how the candidates relate (for example, two digests of
    one archive, or one source built twice). Naming two candidates without that
    relationship is an unexplained disjunction: a reader may substitute one for
    the other, so the claim is refused.
    """
    refusals: list[Refusal] = []
    for index, claim in enumerate(doc.get("claims", []) if isinstance(doc, dict) else []):
        if not isinstance(claim, dict):
            continue
        base = f"$.claims/{index}"
        source = claim.get("identity", {})
        if not isinstance(source, dict):
            continue
        source = source.get("source", {})
        if not isinstance(source, dict):
            continue
        relationship = source.get("candidate_relationship")
        stated = isinstance(relationship, str) and bool(relationship.strip())
        declared = source.get("candidates")
        if isinstance(declared, list):
            distinct = {item for item in declared if isinstance(item, str) and item}
            if len(distinct) > 1 and not stated:
                refusals.append(
                    Refusal(
                        "EG_MULTIPLE_CANDIDATES",
                        _ptr(_ptr(base, "identity"), "source"),
                        "candidates",
                        "the claim names "
                        f"{len(distinct)} different candidate identities without a "
                        "stated relationship: "
                        + ", ".join(sorted(distinct)),
                    )
                )
        candidate = source.get("candidate")
        commit = source.get("commit")
        if (
            not stated
            and isinstance(candidate, str)
            and isinstance(commit, str)
            and re.fullmatch(r"[0-9a-f]{40}", candidate)
            and re.fullmatch(r"[0-9a-f]{40}", commit)
            and candidate != commit
        ):
            refusals.append(
                Refusal(
                    "EG_MULTIPLE_CANDIDATES",
                    _ptr(_ptr(base, "identity"), "source"),
                    "candidate",
                    "candidate and commit are two different full commit identities "
                    "without a stated relationship",
                )
            )
    return refusals


# ---------------------------------------------------------------------------
# Cross-field laws
# ---------------------------------------------------------------------------


def _open_obligations(claim: dict) -> list[dict]:
    return [
        obligation
        for obligation in claim.get("obligations", [])
        if isinstance(obligation, dict) and obligation.get("state") == "OPEN"
    ]


def _present_evidence(claim: dict) -> list[dict]:
    return [
        entry
        for entry in claim.get("evidence", [])
        if isinstance(entry, dict) and entry.get("present") is True
    ]


def _declared_evidence_state(entry: dict) -> str | None:
    """The state the tracked artefact declares, as copied into the evidence record.

    Absence is not a state: it means the producer did not record what the
    artefact says, so the validator neither infers a state nor treats the entry
    as current support for a positive verdict beyond the ordinary presence rule.
    """
    state = entry.get("state")
    if isinstance(state, dict):
        value = state.get("value")
        if isinstance(value, str) and value:
            return value
    return None


def _declared_evidence_measure(entry: dict) -> tuple[str, tuple] | None:
    """The typed measure a current evidence record says the cited bytes record.

    Only a named typed measure (a `counter` or a numeric value with a unit) can
    be compared. A free-text or absent measure is not a contradiction because
    the algebra has nothing to join it to; it remains an obligation to record
    one, exactly as an undeclared `state` remains unknown.
    """
    state = entry.get("state")
    measure = state.get("measure") if isinstance(state, dict) else None
    if not isinstance(measure, dict):
        return None
    name = measure.get("name")
    value = _typed_measure_value(measure)
    if isinstance(name, str) and name and value is not None:
        return name, value
    return None


def _claim_typed_measure(claim: dict) -> tuple[str, tuple] | None:
    """The claim's own named typed measure, when it has one to compare."""
    quantification = claim.get("quantification")
    measure = quantification.get("measure") if isinstance(quantification, dict) else None
    if not isinstance(measure, dict):
        return None
    name = measure.get("name")
    value = _typed_measure_value(measure)
    if isinstance(name, str) and name and value is not None:
        return name, value
    return None


def _measure_name(claim: dict) -> str | None:
    quantification = claim.get("quantification")
    if not isinstance(quantification, dict):
        return None
    measure = quantification.get("measure")
    if not isinstance(measure, dict):
        return None
    name = measure.get("name")
    if isinstance(name, str) and name:
        return name
    return None


def _typed_measure_value(measure: dict) -> tuple | None:
    """The comparable value of a named measure, or None when it is free text.

    A `counter` is a typed single-valued observation. A numeric `value` with a
    `unit` is typed as well. A named free-text `value` is schema-valid but not
    comparable: the algebra refuses it when another claim names the same
    measure.
    """
    counter = measure.get("counter")
    if isinstance(counter, dict):
        numerator = counter.get("numerator")
        denominator = counter.get("denominator")
        if (
            isinstance(numerator, int)
            and not isinstance(numerator, bool)
            and isinstance(denominator, int)
            and not isinstance(denominator, bool)
        ):
            return ("counter", numerator, denominator)
        return None
    value = measure.get("value")
    unit = measure.get("unit")
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and isinstance(unit, str)
        and unit
    ):
        return ("numeric", value, unit)
    return None


def _measure_observations(claims: list[dict]) -> list[dict]:
    observations: list[dict] = []
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            continue
        name = _measure_name(claim)
        if name is None:
            continue
        identity = claim.get("identity", {})
        source = identity.get("source", {}) if isinstance(identity, dict) else {}
        scope = claim.get("scope", {})
        key = (
            str(claim.get("property")),
            str(scope.get("subject")) if isinstance(scope, dict) else "",
            str(source.get("candidate")) if isinstance(source, dict) else "",
            str(source.get("commit")) if isinstance(source, dict) else "",
            name,
        )
        quantification = claim.get("quantification", {})
        measure = (
            quantification.get("measure")
            if isinstance(quantification, dict)
            else None
        )
        observations.append(
            {
                "index": index,
                "id": str(claim.get("id")),
                "key": key,
                "name": name,
                "typed": _typed_measure_value(measure) if isinstance(measure, dict) else None,
            }
        )
    return observations


def _measure_conflicts(claims: list[dict]) -> list[dict]:
    """Same property, scope, identity and measure name with incompatible values.

    A single-valued counter cannot hold two values. Two named measures with the
    same value are one observation repeated, not a contradiction. A compared
    measure that is free text cannot be compared at all, so it is refused
    rather than treated as equal.
    """
    grouped: dict[tuple, list[dict]] = {}
    for observation in _measure_observations(claims):
        grouped.setdefault(observation["key"], []).append(observation)
    conflicts: list[dict] = []
    for key in sorted(grouped):
        members = grouped[key]
        if len(members) < 2:
            continue
        claim_ids = sorted({member["id"] for member in members})
        base = {
            "property": key[0],
            "scope_subject": key[1],
            "candidate": key[2],
            "commit": key[3],
            "measure": key[4],
            "claims": claim_ids,
        }
        if any(member["typed"] is None for member in members):
            conflicts.append(
                {
                    **base,
                    "kind": "untyped",
                    "resolution": "hard error: a compared measure must be typed",
                }
            )
            continue
        values = sorted({member["typed"] for member in members}, key=repr)
        if len(values) > 1:
            conflicts.append(
                {
                    **base,
                    "kind": "value",
                    "values": values,
                    "resolution": "hard error: preference may not resolve it",
                }
            )
    return conflicts


def _claim_candidate_tokens(claim: dict) -> set[str]:
    """The candidate identities a claim states, used to bind an exclusion witness."""
    identity = claim.get("identity", {})
    source = identity.get("source", {}) if isinstance(identity, dict) else {}
    tokens: set[str] = set()
    if isinstance(source, dict):
        for key in ("candidate", "commit"):
            value = source.get(key)
            if isinstance(value, str) and value:
                tokens.add(value)
    return tokens


def _witness_findings(
    claim: dict, obligation: dict, exclusion: dict, path: str
) -> list[Refusal]:
    """Check an exclusion witness binds the obligation, candidate and reviewer.

    A discussion string plus a procedure name is not evidence that the exclusion
    was verified. The witness must name the obligation, the candidate, the
    procedure, an independently produced result with its own digest, and a
    reviewer whose declared role and identity are not the claim author's.
    """
    findings: list[Refusal] = []

    def refuse(rule: str, field: str, detail: str) -> None:
        findings.append(Refusal(rule, path, field, detail))

    witness = exclusion.get("witness")
    if not isinstance(witness, dict):
        refuse(
            "EG_EXCLUSION_WITNESS_MISSING",
            "witness",
            "an exclusion needs an admitted witness record, not only an argument",
        )
        return findings

    obligation_id = obligation.get("id")
    if witness.get("obligation") != obligation_id:
        refuse(
            "EG_EXCLUSION_WITNESS_UNBOUND",
            "obligation",
            f"witness names obligation {witness.get('obligation')!r}, "
            f"not {obligation_id!r}",
        )

    candidate = witness.get("candidate")
    allowed = _claim_candidate_tokens(claim)
    if not isinstance(candidate, str) or not candidate:
        refuse(
            "EG_EXCLUSION_WITNESS_UNBOUND",
            "candidate",
            "witness does not state the candidate identity it was produced against",
        )
    elif not allowed:
        refuse(
            "EG_EXCLUSION_WITNESS_UNBOUND",
            "candidate",
            "the claim states no candidate identity for the witness to bind to",
        )
    elif candidate not in allowed:
        refuse(
            "EG_EXCLUSION_WITNESS_CANDIDATE",
            "candidate",
            f"witness is bound to candidate {candidate!r}, not this claim's "
            + ", ".join(sorted(allowed)),
        )

    procedure = str(witness.get("procedure", "")).strip()
    if not procedure or procedure.lower() in UNCHECKABLE_MARKERS:
        refuse(
            "EG_EXCLUSION_WITNESS_UNBOUND",
            "procedure",
            "witness names no verification procedure",
        )

    reviewer = witness.get("reviewer")
    author = claim.get("author")
    if (
        not isinstance(reviewer, dict)
        or not str(reviewer.get("role", "")).strip()
        or not str(reviewer.get("identity", "")).strip()
    ):
        refuse(
            "EG_EXCLUSION_WITNESS_UNBOUND",
            "reviewer",
            "witness needs a reviewer role and identity",
        )
    elif (
        not isinstance(author, dict)
        or not str(author.get("role", "")).strip()
        or not str(author.get("identity", "")).strip()
    ):
        refuse(
            "EG_EXCLUSION_WITNESS_SELF_AUTHORED",
            "reviewer",
            "the claim states no author, so reviewer independence cannot be established",
        )
    elif (
        str(reviewer.get("role")).strip().lower()
        == str(author.get("role")).strip().lower()
        or str(reviewer.get("identity")).strip().lower()
        == str(author.get("identity")).strip().lower()
    ):
        refuse(
            "EG_EXCLUSION_WITNESS_SELF_AUTHORED",
            "reviewer",
            "the reviewer role or identity is the claim author's; an exclusion "
            "cannot review itself",
        )

    result = witness.get("result")
    if not isinstance(result, dict):
        refuse(
            "EG_EXCLUSION_WITNESS_RESULT_ABSENT",
            "result",
            "the witness carries no independently produced result",
        )
        return findings
    if result.get("present") is not True:
        refuse(
            "EG_EXCLUSION_WITNESS_RESULT_ABSENT",
            "result",
            "the witness result is not present",
        )
    if not isinstance(result.get("path"), str) or not result.get("path"):
        refuse(
            "EG_EXCLUSION_WITNESS_RESULT_ABSENT",
            "path",
            "the witness result has no path, so its presence cannot be established",
        )
    digest = result.get("sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        refuse(
            "EG_EXCLUSION_WITNESS_RESULT_ABSENT",
            "sha256",
            "the witness result has no SHA-256 digest of its own",
        )
    if result.get("digest_identity") not in ("S", "E"):
        refuse(
            "EG_EXCLUSION_WITNESS_RESULT_ABSENT",
            "digest_identity",
            "the witness result does not declare the identity its digest binds",
        )
    return findings


def check_claim_laws(claim: dict, base: str) -> list[Refusal]:
    refusals: list[Refusal] = []

    def refuse(rule: str, location: str, field: str, detail: str) -> None:
        refusals.append(Refusal(rule, f"{base}/{location}", field, detail))

    verdict = claim.get("verdict", {})
    state = verdict.get("state") if isinstance(verdict, dict) else None
    modality = claim.get("modality")
    evidence = claim.get("evidence", [])
    evidence = evidence if isinstance(evidence, list) else []
    present = _present_evidence(claim)
    open_obligations = _open_obligations(claim)

    # 1. A verdict or modality may not outrun the evidence.
    if state in ("ESTABLISHED", "SAFE_COMPATIBLE") and not present:
        refuse(
            "EG_VERDICT_MODALITY",
            "verdict/state",
            "state",
            f"{state} requires at least one evidence entry with present=true",
        )
    if modality in VERIFICATION_MODALITIES and not present:
        refuse(
            "EG_VERDICT_MODALITY",
            "modality",
            "modality",
            f"{modality} requires at least one evidence entry with present=true",
        )

    # 1b. An evidence record's declared state must agree with a positive verdict.
    # The state is read from the tracked artefact and copied into the record; it
    # is never inferred. A present entry declaring WITHDRAWN, REFUTED or
    # NOT_ESTABLISHED cannot support an ESTABLISHED or SAFE_COMPATIBLE verdict or
    # a graduation modality.
    positive = state in POSITIVE_VERDICTS or modality in GRADUATED_MODALITIES
    if positive:
        usable: list[dict] = []
        has_contradicting = False
        has_non_current = False
        for index, entry in enumerate(evidence):
            if not isinstance(entry, dict) or entry.get("present") is not True:
                continue
            declared = _declared_evidence_state(entry)
            if declared in CONTRADICTING_EVIDENCE_STATES:
                has_contradicting = True
                refuse(
                    "EG_EVIDENCE_CONTRADICTS_VERDICT",
                    f"evidence/{index}/state",
                    "state",
                    f"evidence {entry.get('id')!r} at {entry.get('path')!r} declares "
                    f"state {declared}, which cannot support "
                    f"{state if state in POSITIVE_VERDICTS else modality}",
                )
                continue
            if declared in NON_CURRENT_EVIDENCE_STATES:
                has_non_current = True
                continue
            usable.append(entry)
        if not usable and has_non_current and not has_contradicting:
            refuse(
                "EG_EVIDENCE_CONTRADICTS_VERDICT",
                "evidence",
                "state",
                f"{state if state in POSITIVE_VERDICTS else modality} requires at least "
                "one present evidence entry whose declared state is not withdrawn, "
                "refuted, not established or superseded",
            )

    # 1c. A current evidence record may not record a different value for the
    # same named typed measure than the claim asserts. The record's value is
    # copied from the tracked artefact, never inferred; a non-current record
    # (SUPERSEDED, WITHDRAWN, REFUTED, NOT_ESTABLISHED) is history and may
    # legitimately record the earlier value, which is why the repaired claim
    # carries both the historical S record and the live record.
    asserted = _claim_typed_measure(claim)
    if asserted is not None:
        asserted_name, asserted_value = asserted
        for index, entry in enumerate(evidence):
            if not isinstance(entry, dict) or entry.get("present") is not True:
                continue
            if _declared_evidence_state(entry) in NON_CURRENT_EVIDENCE_STATES:
                continue
            recorded = _declared_evidence_measure(entry)
            if recorded is None:
                continue
            recorded_name, recorded_value = recorded
            if recorded_name == asserted_name and recorded_value != asserted_value:
                refuse(
                    "EG_EVIDENCE_CONTRADICTS_ASSERTION",
                    f"evidence/{index}/state/measure",
                    "measure",
                    f"evidence {entry.get('id')!r} at {entry.get('path')!r} declares "
                    f"that its cited revision records {asserted_name} = "
                    f"{recorded_value}, but the claim asserts {asserted_value}",
                )

    # 2. A graduated verdict is a §7 graduation: complete closure, no open item.
    if state in GRADUATED_VERDICTS:
        if modality not in GRADUATED_MODALITIES:
            refuse(
                "EG_VERDICT_MODALITY",
                "modality",
                "modality",
                f"{state} requires a graduation modality {sorted(GRADUATED_MODALITIES)}",
            )
        if open_obligations:
            refuse(
                "EG_GRADUATED_WITH_OPEN_OBLIGATION",
                "obligations",
                "obligations",
                f"{state} has {len(open_obligations)} open obligation(s): "
                + ", ".join(sorted(str(item.get("id")) for item in open_obligations)),
            )
        closure = claim.get("closure")
        if not isinstance(closure, dict):
            refuse(
                "EG_GRADUATED_WITHOUT_CLOSURE",
                "closure",
                "closure",
                f"{state} requires a named dependency closure",
            )
        else:
            unresolved = closure.get("unresolved_dependencies", [])
            if (
                closure.get("complete") is not True
                or not closure.get("dependencies")
                or unresolved
            ):
                refuse(
                    "EG_GRADUATED_WITHOUT_CLOSURE",
                    "closure",
                    "closure",
                    f"{state} requires complete=true, a non-empty dependency list "
                    "and an empty unresolved_dependencies list",
                )

    # 3. Evidence must be reconstructable, and absent evidence needs an obligation.
    for index, entry in enumerate(evidence):
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        digest = entry.get("sha256")
        if not path and not digest:
            refuse(
                "EG_EVIDENCE_UNRECONSTRUCTABLE",
                f"evidence/{index}",
                "path",
                "evidence has neither a path nor a digest, so it cannot be reconstructed",
            )
        if entry.get("present") is True and not path:
            refuse(
                "EG_EVIDENCE_UNRECONSTRUCTABLE",
                f"evidence/{index}",
                "path",
                "evidence marked present has no path",
            )
        if entry.get("present") is not True or entry.get("reconstructable") is False:
            covered = any(
                entry.get("id") in obligation.get("evidence", [])
                for obligation in claim.get("obligations", [])
                if isinstance(obligation, dict)
            )
            if not covered:
                refuse(
                    "EG_EVIDENCE_ABSENT_NO_OBLIGATION",
                    f"evidence/{index}",
                    "id",
                    "evidence that is absent or not reconstructable must be covered "
                    "by a named obligation",
                )

    # 4. Security-relevant properties require a threat/leakage model.
    property_name = claim.get("property")
    threat_model = claim.get("threat_model")
    if property_name in SECURITY_PROPERTIES:
        if not isinstance(threat_model, dict):
            refuse(
                "EG_THREAT_MODEL_MISSING",
                "threat_model",
                "threat_model",
                f"property '{property_name}' is security-relevant and needs a threat model",
            )
        elif not str(threat_model.get("adversary", "")).strip() or not str(
            threat_model.get("observation_model", "")
        ).strip():
            refuse(
                "EG_THREAT_MODEL_MISSING",
                "threat_model",
                "threat_model",
                "adversary and observation_model must both be stated",
            )

    # 5. Evidence may not be aliased as two independent pieces.
    by_path: dict[str, str] = {}
    by_digest: dict[str, str] = {}
    by_id: dict[str, int] = {}
    for index, entry in enumerate(evidence):
        if not isinstance(entry, dict):
            continue
        evidence_id = entry.get("id")
        if isinstance(evidence_id, str):
            if evidence_id in by_id:
                refuse(
                    "EG_EVIDENCE_ALIAS",
                    f"evidence/{index}",
                    "id",
                    f"duplicate evidence id '{evidence_id}' is not an independent source",
                )
            else:
                by_id[evidence_id] = index
        path = entry.get("path")
        if isinstance(path, str) and path:
            prior = by_path.get(path)
            historical_pair = (
                prior is not None
                and (
                    entry.get("kind") == "commit"
                    or any(
                        isinstance(other, dict)
                        and other.get("id") == prior
                        and other.get("kind") == "commit"
                        for other in evidence
                    )
                )
            )
            if prior is not None and not historical_pair:
                refuse(
                    "EG_EVIDENCE_ALIAS",
                    f"evidence/{index}",
                    "path",
                    f"path '{path}' already appears as evidence {prior}; "
                    "two entries for one artefact are not two sources",
                )
            elif prior is None:
                by_path[path] = str(evidence_id)
        digest = entry.get("sha256")
        if isinstance(digest, str) and digest:
            if digest in by_digest:
                refuse(
                    "EG_EVIDENCE_ALIAS",
                    f"evidence/{index}",
                    "sha256",
                    f"digest already appears as evidence {by_digest[digest]}; "
                    "the same bytes are not two independent observations",
                )
            else:
                by_digest[digest] = str(evidence_id)

    # 6. Quantification coverage.
    quantification = claim.get("quantification", {})
    if isinstance(quantification, dict) and quantification.get("kind") == "enumerated":
        members = quantification.get("members", [])
        population_size = quantification.get("population_size")
        members = members if isinstance(members, list) else []
        if not isinstance(population_size, int) or isinstance(population_size, bool):
            refuse(
                "EG_QUANTIFICATION_COVERAGE",
                "quantification/population_size",
                "population_size",
                "an enumerated quantification needs an integer population_size",
            )
        elif len(members) != population_size:
            refuse(
                "EG_QUANTIFICATION_COVERAGE",
                "quantification/members",
                "members",
                f"member list covers {len(set(members))} of {population_size} "
                "population members",
            )

    # 7. A partially established or unknown claim must say what is open.
    if state == "PARTIAL" and not open_obligations:
        refuse(
            "EG_PARTIAL_NO_OBLIGATION",
            "obligations",
            "obligations",
            "a PARTIAL verdict must record what remains open as an open obligation",
        )
    if state == "RISK_ACCEPTED" and not open_obligations:
        refuse(
            "EG_RISK_ACCEPTED_WITHOUT_OBLIGATION",
            "obligations",
            "obligations",
            "a RISK_ACCEPTED verdict must name the unresolved obligations the "
            "decision accepts; an acceptance with nothing open is a positive claim",
        )
    if state in ("UNKNOWN", "NOT_ESTABLISHED") and not open_obligations:
        refuse(
            "EG_VERDICT_MISSING_SETTLING_OBLIGATION",
            "obligations",
            "obligations",
            f"{state} requires at least one OPEN obligation naming what would settle it",
        )

    # 8. A contradiction keeps both sides, not a preference.
    if state == "CONTRADICTED":
        contradiction = claim.get("contradiction")
        if isinstance(contradiction, dict):
            parties = contradiction.get("parties", [])
            sources = {
                party.get("source")
                for party in parties
                if isinstance(party, dict)
            }
            if len(sources) < 2:
                refuse(
                    "EG_CONTRADICTION_PARTIES",
                    "contradiction/parties",
                    "parties",
                    "a contradiction needs at least two distinct sources, so both sides "
                    "are identified rather than one being preferred",
                )

    # 8b. A reconciliation is an explicit, bound governance record.  It may not
    # be a free-text claim, it may not change the recorded ETP-0 verdict, and it
    # must preserve both original parties.
    reconciliation = claim.get("reconciliation")
    if reconciliation is not None:
        if not isinstance(reconciliation, dict):
            refuse(
                "EG_RECONCILIATION_UNBOUND",
                "reconciliation",
                "reconciliation",
                "a reconciliation must be a record",
            )
        else:
            problems: list[str] = []
            if reconciliation.get("resolution_owner") != RECONCILIATION_OWNER:
                problems.append(
                    f"resolution_owner is {reconciliation.get('resolution_owner')!r}, "
                    f"not {RECONCILIATION_OWNER!r}"
                )
            if reconciliation.get("classification") != state:
                problems.append(
                    f"classification {reconciliation.get('classification')!r} does not "
                    f"match verdict state {state!r}"
                )
            lineage = claim.get("derived_from", {})
            original_verdict = (
                lineage.get("verdict") if isinstance(lineage, dict) else None
            )
            if reconciliation.get("original_verdict") != original_verdict:
                problems.append(
                    f"original_verdict {reconciliation.get('original_verdict')!r} does "
                    f"not match the recorded ETP-0 verdict {original_verdict!r}"
                )
            parties = reconciliation.get("original_parties", [])
            sources = {
                party.get("source")
                for party in parties
                if isinstance(party, dict)
            }
            if len(sources) < 2:
                problems.append("fewer than two distinct original parties")
            for field in ("historical_record", "superseding_record"):
                record = reconciliation.get(field)
                if not isinstance(record, dict) or not isinstance(
                    record.get("path"), str
                ) or not isinstance(record.get("sha256"), str):
                    problems.append(f"{field} names no path and digest")
            if problems:
                refuse(
                    "EG_RECONCILIATION_UNBOUND",
                    "reconciliation",
                    "reconciliation",
                    "; ".join(problems),
                )

    # 9. Conversion may not promote a claim.  The one permitted movement is an
    # explicit ETP-T15 reconciliation of a CONTRADICTED claim to RISK_ACCEPTED or
    # SUPERSEDED, and that record is checked above and in the tree check.
    lineage = claim.get("derived_from", {})
    if isinstance(lineage, dict) and lineage.get("verdict") in ETP0_VERDICT_MAP:
        expected = ETP0_VERDICT_MAP[lineage["verdict"]]
        if state != expected:
            bound = (
                isinstance(reconciliation, dict)
                and state in RECONCILABLE_STATES
                and reconciliation.get("resolution_owner") == RECONCILIATION_OWNER
                and reconciliation.get("classification") == state
                and reconciliation.get("original_verdict") == lineage["verdict"]
            )
            if not bound:
                refuse(
                    "EG_DERIVED_VERDICT_MISMATCH",
                    "verdict/state",
                    "state",
                    f"ETP-0 verdict {lineage['verdict']} maps to {expected}, not {state}",
                )
                if state in POSITIVE_VERDICTS:
                    refuse(
                        "EG_RECONCILIATION_PROMOTION",
                        "verdict/state",
                        "state",
                        f"a reconciliation may not raise a CONTRADICTED claim to {state}",
                    )
        if lineage.get("property") != property_name:
            refuse(
                "EG_DERIVED_PROPERTY_MISMATCH",
                "property",
                "property",
                f"property changed from ETP-0 value '{lineage.get('property')}'",
            )

    # 10. Assumptions and exclusion arguments must be independently checkable.
    for index, assumption in enumerate(claim.get("assumptions", [])):
        if not isinstance(assumption, dict):
            continue
        checkable = str(assumption.get("checkable_by", "")).strip().lower()
        if checkable in UNCHECKABLE_MARKERS:
            refuse(
                "EG_ASSUMPTION_UNCHECKABLE",
                f"assumptions/{index}",
                "checkable_by",
                "an assumption without an independently checkable procedure is an "
                "unresolved obligation",
            )
    for o_index, obligation in enumerate(claim.get("obligations", [])):
        if not isinstance(obligation, dict):
            continue
        for e_index, exclusion in enumerate(obligation.get("exclusions", [])):
            if not isinstance(exclusion, dict):
                continue
            location = f"obligations/{o_index}/exclusions/{e_index}"
            if (
                str(exclusion.get("argument", "")).strip().lower() in UNCHECKABLE_MARKERS
                or str(exclusion.get("checkable_by", "")).strip().lower()
                in UNCHECKABLE_MARKERS
            ):
                refuse(
                    "EG_EXCLUSION_UNCHECKABLE",
                    location,
                    "argument",
                    "an exclusion needs an argument and an independently checkable procedure",
                )
            refusals.extend(
                _witness_findings(
                    claim, obligation, exclusion, f"{base}/{location}/witness"
                )
            )

    # 11. Measure is an observation, never a score.
    measure = quantification.get("measure") if isinstance(quantification, dict) else None
    if isinstance(measure, dict) and measure.get("aggregation") != "forbidden":
        refuse(
            "EG_MEASURE_AGGREGATION",
            "quantification/measure",
            "aggregation",
            "a measure must declare aggregation=forbidden; no axis is combined",
        )

    # 12. Authority is stated or explicitly absent.
    authority = claim.get("authority", {})
    if isinstance(authority, dict):
        if authority.get("kind") == "openssl-authority" and not authority.get("version"):
            refuse(
                "EG_AUTHORITY_MISSING_VERSION",
                "authority/version",
                "version",
                "an OpenSSL authority claim must name the authority version",
            )

    return refusals


def check_aggregates(doc: dict, repo_root: Path | None = None) -> list[Refusal]:
    """Bind an aggregate claim to the per-cell receipts it claims to summarise.

    An aggregate that claims to summarise cells must name each cell's receipt
    path and digest. A named digest is re-derived from the tracked receipt when
    the tree check is enabled; a disagreement is refused. An aggregate that
    names no cell at all is unbound: its summary cannot be reconstructed from
    the cells, so it is refused rather than trusted. Log contents are not
    compared here; the defect this rule closes is an unbound aggregate.
    """
    refusals: list[Refusal] = []
    for index, claim in enumerate(doc.get("claims", []) if isinstance(doc, dict) else []):
        if not isinstance(claim, dict):
            continue
        aggregate = claim.get("aggregate_cells")
        if not isinstance(aggregate, dict):
            continue
        if aggregate.get("summarises_cells") is not True:
            continue
        base = f"$.claims/{index}/aggregate_cells"
        cells = aggregate.get("cells")
        if not isinstance(cells, list) or not cells:
            refusals.append(
                Refusal(
                    "EG_AGGREGATE_UNBOUND",
                    f"{base}/cells",
                    "cells",
                    "an aggregate claim names no cell receipt digests, so it is not "
                    "bound to the cells it summarises",
                )
            )
            continue
        for c_index, cell in enumerate(cells):
            location = f"{base}/cells/{c_index}"
            if not isinstance(cell, dict):
                refusals.append(
                    Refusal(
                        "EG_AGGREGATE_UNBOUND",
                        location,
                        "cells",
                        "a cell entry is not an object, so the aggregate is unbound",
                    )
                )
                continue
            path = cell.get("receipt_path")
            digest = cell.get("receipt_sha256")
            if (
                not isinstance(path, str)
                or not path
                or not isinstance(digest, str)
                or not digest
            ):
                refusals.append(
                    Refusal(
                        "EG_AGGREGATE_UNBOUND",
                        location,
                        "receipt_sha256",
                        f"cell {cell.get('id')!r} names no receipt path and digest, "
                        "so the aggregate is unbound",
                    )
                )
                continue
            if repo_root is None:
                continue
            target = repo_root / path
            if not target.is_file():
                refusals.append(
                    Refusal(
                        "EG_AGGREGATE_UNBOUND",
                        location,
                        "receipt_path",
                        f"cell {cell.get('id')!r} names receipt '{path}', which is "
                        "absent from the tracked tree",
                    )
                )
                continue
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual != digest:
                refusals.append(
                    Refusal(
                        "EG_AGGREGATE_DIGEST_MISMATCH",
                        location,
                        "receipt_sha256",
                        f"cell {cell.get('id')!r} receipt '{path}' hashes to {actual}, "
                        f"not the recorded {digest}",
                    )
                )

        # ETP-T10 section 1c: a summary may not be stronger than its members.
        # A positive aggregate claim whose cells declare a blocked, unresolved
        # or not-established state is refused; the cell is never dropped to let
        # the aggregate pass.
        verdict = claim.get("verdict", {})
        claim_state = verdict.get("state") if isinstance(verdict, dict) else verdict
        if claim_state in POSITIVE_VERDICTS:
            blocked_cells = [
                cell for cell in cells
                if isinstance(cell, dict)
                and cell.get("declared_state") in BLOCKED_CELL_STATES
            ]
            if blocked_cells:
                refusals.append(
                    Refusal(
                        "EG_AGGREGATE_PASS_HIDES_BLOCKED_CELL",
                        f"{base}/cells",
                        "declared_state",
                        f"aggregate claim asserts {claim_state} while containing "
                        f"blocked cell(s): "
                        + ", ".join(
                            f"{c.get('id')}={c.get('declared_state')}"
                            for c in blocked_cells),
                    )
                )
            undeclared = [
                cell for cell in cells
                if isinstance(cell, dict) and "declared_state" not in cell
            ]
            if undeclared:
                # An undeclared cell state is not evidence that the cell is not
                # blocked.  A positive aggregate that omits it could otherwise
                # hide a blocked row by saying nothing, so it is refused.
                refusals.append(
                    Refusal(
                        "EG_AGGREGATE_CELL_STATE_UNDECLARED",
                        f"{base}/cells",
                        "declared_state",
                        f"aggregate claim asserts {claim_state} while "
                        + ", ".join(
                            f"cell {c.get('id')!r} declares no state"
                            for c in undeclared),
                    )
                )
    return refusals


def _is_closure_receipt(dependency: str) -> bool:
    name = Path(dependency).name
    return name.startswith("closure-") and name.endswith(".json")


def check_closure_exclusions(
    doc: dict, *, repo_root: Path | None = None
) -> list[Refusal]:
    """ETP-T10 section 1d: a SAFE_COMPATIBLE verdict requires a clean bar.

    A graduated verdict names its dependency closure.  Every dependency that
    is a consumer-closure receipt must be auditable, and no exclusion in it may
    fail the independently checkable bar.  This is the claim-algebra half of
    the rule; the traceability graph projects the same exclusions as nodes and
    edges, so the same omission is visible there.
    """
    refusals: list[Refusal] = []
    claims = doc.get("claims", []) if isinstance(doc, dict) else []
    if not isinstance(claims, list):
        return refusals
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            continue
        verdict = claim.get("verdict", {})
        state = verdict.get("state") if isinstance(verdict, dict) else verdict
        if state not in GRADUATED_VERDICTS:
            continue
        closure = claim.get("closure")
        dependencies = (
            closure.get("dependencies", []) if isinstance(closure, dict) else []
        )
        receipts = [
            dependency for dependency in dependencies
            if isinstance(dependency, str) and _is_closure_receipt(dependency)
        ]
        base = f"$.claims/{index}/closure/dependencies"
        if not receipts:
            refusals.append(
                Refusal(
                    "EG_SAFE_COMPATIBLE_CLOSURE_UNBOUND",
                    base,
                    "dependencies",
                    "a SAFE_COMPATIBLE verdict names no consumer-closure receipt, "
                    "so its exclusions cannot be audited against the bar",
                )
            )
            continue
        if repo_root is None:
            continue
        source = (claim.get("identity") or {}).get("source") or {}
        claim_commit = source.get("commit") if isinstance(source, dict) else None
        for dependency in receipts:
            path = repo_root / dependency
            if not path.is_file():
                refusals.append(
                    Refusal(
                        "EG_SAFE_COMPATIBLE_CLOSURE_UNBOUND",
                        base,
                        dependency,
                        f"closure receipt '{dependency}' is absent from the tracked tree",
                    )
                )
                continue
            try:
                tools = Path(__file__).resolve().parent
                if str(tools) not in sys.path:
                    sys.path.insert(0, str(tools))
                import closure_discipline  # lazy: same tool directory
                audit = closure_discipline.closure_receipt_failure(
                    path, repo=repo_root, commit=claim_commit
                )
            except Exception as exc:  # fail closed, never silently pass
                refusals.append(
                    Refusal(
                        "EG_SAFE_COMPATIBLE_CLOSURE_UNBOUND",
                        base,
                        dependency,
                        f"closure receipt '{dependency}' could not be audited: {exc}",
                    )
                )
                continue
            if audit["exclusions_failing"] > 0:
                sample = ", ".join(audit["failing_ids"][:5])
                refusals.append(
                    Refusal(
                        "EG_SAFE_COMPATIBLE_EXCLUSION_FAILS_BAR",
                        base,
                        dependency,
                        f"closure receipt '{dependency}' has "
                        f"{audit['exclusions_failing']} exclusion(s) that fail the "
                        f"independently checkable bar (sample: {sample})",
                    )
                )
    return refusals


def check_document_laws(doc: dict, *, repo_root: Path | None = None) -> list[Refusal]:
    refusals: list[Refusal] = []
    claims = doc.get("claims", [])
    if not isinstance(claims, list):
        return refusals

    seen_ids: dict[str, int] = {}
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            continue
        claim_id = claim.get("id")
        if isinstance(claim_id, str):
            if claim_id in seen_ids:
                refusals.append(
                    Refusal(
                        "EG_DUPLICATE_CLAIM_ID",
                        f"$.claims/{index}/id",
                        "id",
                        f"claim id '{claim_id}' already used at index {seen_ids[claim_id]}",
                    )
                )
            else:
                seen_ids[claim_id] = index

    # Unknown claim dependencies and invalidation cycles.
    graph: dict[str, list[str]] = {}
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict) or not isinstance(claim.get("id"), str):
            continue
        node = claim["id"]
        graph.setdefault(node, [])
        invalidation = claim.get("invalidation", {})
        dependencies = invalidation.get("depends_on", []) if isinstance(invalidation, dict) else []
        for dep_index, dependency in enumerate(dependencies):
            if not isinstance(dependency, dict):
                continue
            if dependency.get("kind") == "claim":
                target = dependency.get("id")
                if target not in seen_ids:
                    refusals.append(
                        Refusal(
                            "EG_UNKNOWN_CLAIM_DEPENDENCY",
                            f"$.claims/{index}/invalidation/depends_on/{dep_index}",
                            "id",
                            f"depends on unknown claim '{target}'",
                        )
                    )
                elif isinstance(target, str):
                    graph[node].append(target)

    for cycle in _find_cycles(graph):
        refusals.append(
            Refusal(
                "EG_INVALIDATION_CYCLE",
                "$.claims",
                "invalidation/depends_on",
                "invalidation cycle: " + " -> ".join(cycle),
            )
        )

    # Hard contradiction: same property, scope subject and identity, different verdict.
    keys: dict[tuple[str, str, str, str], tuple[str, str]] = {}
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            continue
        identity = claim.get("identity", {})
        source = identity.get("source", {}) if isinstance(identity, dict) else {}
        scope = claim.get("scope", {})
        verdict = claim.get("verdict", {})
        key = (
            str(claim.get("property")),
            str(scope.get("subject")) if isinstance(scope, dict) else "",
            str(source.get("candidate")) if isinstance(source, dict) else "",
            str(source.get("commit")) if isinstance(source, dict) else "",
        )
        state = verdict.get("state") if isinstance(verdict, dict) else None
        if key in keys and keys[key][1] != state:
            refusals.append(
                Refusal(
                    "EG_CONTRADICTION_UNRESOLVED",
                    f"$.claims/{index}/verdict/state",
                    "state",
                    f"claim {claim.get('id')} and {keys[key][0]} share property, scope "
                    f"and identity but assert {state} and {keys[key][1]}",
                )
            )
        else:
            keys[key] = (str(claim.get("id")), str(state))

    # A comparative measure with the same property, scope, identity and name is
    # a single-valued observation. Two typed values that differ are a
    # contradiction; a named free-text measure cannot be compared at all.
    index_by_id = {str(claim.get("id")): index for index, claim in enumerate(claims) if isinstance(claim, dict)}
    for conflict in _measure_conflicts(claims):
        for claim_id in conflict["claims"]:
            index = index_by_id.get(claim_id)
            if index is None:
                continue
            if conflict["kind"] == "untyped":
                refusals.append(
                    Refusal(
                        "EG_MEASURE_UNTYPED",
                        f"$.claims/{index}/quantification/measure",
                        "measure",
                        f"measure '{conflict['measure']}' is compared across claims "
                        f"{', '.join(conflict['claims'])} but carries no typed counter "
                        "or numeric value",
                    )
                )
            else:
                refusals.append(
                    Refusal(
                        "EG_CONTRADICTION_UNRESOLVED",
                        f"$.claims/{index}/quantification/measure",
                        "measure",
                        f"claim {claim_id} and the other claim(s) "
                        f"{', '.join(other for other in conflict['claims'] if other != claim_id)} "
                        f"share property, scope, identity and measure "
                        f"'{conflict['measure']}' but assert different values "
                        f"{conflict['values']}",
                    )
                )

    if repo_root is not None:
        refusals.extend(check_evidence_tree(doc, repo_root))
    return refusals


def check_evidence_tree(doc: dict, repo_root: Path) -> list[Refusal]:
    """Fail closed when a cited digest cannot be re-derived from the stated identity."""
    refusals: list[Refusal] = []

    def require_sha256(digest: str, location: str) -> bool:
        """The identity model names a content digest and a commit id separately.

        A cited digest that is not full-length SHA-256 cannot be the bytes of the
        cited file, so it is refused before any re-derivation is attempted. A Git
        object id recorded in a `sha256` field is a scope confusion, not a
        mismatch to be discovered later.
        """
        if finding_identity.identity_token_kind(digest) == (
            finding_identity.ALGORITHM_SHA256
        ):
            return True
        refusals.append(
            Refusal(
                "EG_EVIDENCE_DIGEST_FORM",
                location,
                "sha256",
                f"the recorded digest {digest!r} is not a full sha-256 content "
                "digest; a Git object id names a commit, not file bytes",
            )
        )
        return False

    source = doc.get("source_identity", {})
    source_commit = source.get("commit") if isinstance(source, dict) else None
    for c_index, claim in enumerate(doc.get("claims", [])):
        if not isinstance(claim, dict):
            continue
        for e_index, entry in enumerate(claim.get("evidence", [])):
            if not isinstance(entry, dict):
                continue
            path = entry.get("path")
            digest = entry.get("sha256")
            identity = entry.get("digest_identity")
            if not isinstance(path, str) or not path or not isinstance(digest, str):
                continue
            if not require_sha256(digest, f"$.claims/{c_index}/evidence/{e_index}"):
                continue
            actual: str | None = None
            if identity == "S" and isinstance(source_commit, str):
                actual = _git_blob_sha256(repo_root, source_commit, path)
            elif identity == "E":
                target = repo_root / path
                if target.is_file():
                    actual = hashlib.sha256(target.read_bytes()).hexdigest()
            else:
                continue
            if actual is None:
                refusals.append(
                    Refusal(
                        "EG_EVIDENCE_CHECK_UNAVAILABLE",
                        f"$.claims/{c_index}/evidence/{e_index}",
                        "digest_identity",
                        f"cannot re-derive '{path}' under identity {identity!r}",
                    )
                )
            elif actual != digest:
                refusals.append(
                    Refusal(
                        "EG_EVIDENCE_DIGEST_MISMATCH",
                        f"$.claims/{c_index}/evidence/{e_index}",
                        "sha256",
                        f"'{path}' hashes to {actual}, not the recorded {digest}",
                    )
                )
        reconciliation = claim.get("reconciliation")
        if isinstance(reconciliation, dict):
            for field in ("historical_record", "superseding_record"):
                record = reconciliation.get(field)
                if not isinstance(record, dict):
                    continue
                path = record.get("path")
                digest = record.get("sha256")
                if not isinstance(path, str) or not isinstance(digest, str):
                    continue
                if not require_sha256(
                    digest, f"$.claims/{c_index}/reconciliation/{field}"
                ):
                    continue
                target = repo_root / path
                actual = (
                    hashlib.sha256(target.read_bytes()).hexdigest()
                    if target.is_file()
                    else None
                )
                if actual is None:
                    refusals.append(
                        Refusal(
                            "EG_RECONCILIATION_UNBOUND",
                            f"$.claims/{c_index}/reconciliation/{field}",
                            "path",
                            f"the reconciliation record '{path}' is absent; a "
                            "reconciliation must name bytes that exist",
                        )
                    )
                elif actual != digest:
                    refusals.append(
                        Refusal(
                            "EG_RECONCILIATION_UNBOUND",
                            f"$.claims/{c_index}/reconciliation/{field}",
                            "sha256",
                            f"the reconciliation record '{path}' hashes to {actual}, "
                            f"not the recorded {digest}",
                        )
                    )
        for o_index, obligation in enumerate(claim.get("obligations", [])):
            if not isinstance(obligation, dict):
                continue
            for x_index, exclusion in enumerate(obligation.get("exclusions", [])):
                if not isinstance(exclusion, dict):
                    continue
                witness = exclusion.get("witness")
                result = witness.get("result") if isinstance(witness, dict) else None
                if not isinstance(result, dict):
                    continue
                path = result.get("path")
                digest = result.get("sha256")
                identity = result.get("digest_identity")
                if not isinstance(path, str) or not path or not isinstance(digest, str):
                    continue
                location = (
                    f"$.claims/{c_index}/obligations/{o_index}/exclusions/"
                    f"{x_index}/witness/result"
                )
                if not require_sha256(digest, location):
                    continue
                actual: str | None = None
                if identity == "S" and isinstance(source_commit, str):
                    actual = _git_blob_sha256(repo_root, source_commit, path)
                elif identity == "E":
                    target = repo_root / path
                    if target.is_file():
                        actual = hashlib.sha256(target.read_bytes()).hexdigest()
                else:
                    continue
                if actual is None:
                    refusals.append(
                        Refusal(
                            "EG_EXCLUSION_WITNESS_RESULT_ABSENT",
                            location,
                            "path",
                            f"cannot re-derive the witness result '{path}' under "
                            f"identity {identity!r}",
                        )
                    )
                elif actual != digest:
                    refusals.append(
                        Refusal(
                            "EG_EXCLUSION_WITNESS_DIGEST",
                            location,
                            "sha256",
                            f"witness result '{path}' hashes to {actual}, not the "
                            f"recorded {digest}",
                        )
                    )
    return refusals


def _git_blob_sha256(repo_root: Path, commit: str, path: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), "show", f"{commit}:{path}"],
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return hashlib.sha256(completed.stdout).hexdigest()


def _find_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    cycles: list[list[str]] = []
    state: dict[str, int] = {node: 0 for node in graph}
    stack: list[str] = []

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for neighbour in sorted(graph.get(node, [])):
            if state.get(neighbour, 0) == 0:
                visit(neighbour)
            elif state.get(neighbour) == 1:
                start = stack.index(neighbour)
                cycle = stack[start:] + [neighbour]
                if cycle not in cycles:
                    cycles.append(cycle)
        stack.pop()
        state[node] = 2

    for node in sorted(graph):
        if state[node] == 0:
            visit(node)
    return cycles


# ---------------------------------------------------------------------------
# Top-level validation
# ---------------------------------------------------------------------------


def validate_document(
    doc: Any,
    schema: dict,
    *,
    repo_root: Path | None = None,
) -> list[Refusal]:
    """Validate a document against the closed type and the algebra's laws."""
    refusals: list[Refusal] = []
    if not isinstance(doc, dict):
        return [
            Refusal(
                "EG_SCHEMA_VIOLATION",
                "$",
                "document",
                "the claim document must be a JSON object",
            )
        ]
    refusals.extend(prescan_forbidden(doc))
    refusals.extend(prescan_multiple_candidates(doc))
    refusals.extend(check_schema(doc, schema, schema))
    for index, claim in enumerate(doc.get("claims", [])):
        if isinstance(claim, dict):
            refusals.extend(check_claim_laws(claim, f"$.claims/{index}"))
    refusals.extend(check_aggregates(doc, repo_root))
    refusals.extend(check_closure_exclusions(doc, repo_root=repo_root))
    refusals.extend(check_document_laws(doc, repo_root=repo_root))
    return sorted(refusals, key=lambda item: (item["path"], item["rule"], item["detail"]))


def load_and_validate(
    document: Path,
    schema_path: Path = DEFAULT_SCHEMA,
    *,
    repo_root: Path | None = None,
) -> list[Refusal]:
    return validate_document(load_json(document), load_json(schema_path), repo_root=repo_root)


# ---------------------------------------------------------------------------
# Algebra operations
# ---------------------------------------------------------------------------


def _meet_verdicts(states: list[str]) -> str:
    for absorbing in ABSORBING_VERDICTS:
        if absorbing in states:
            return absorbing
    if not states:
        raise AlgebraError("a conjunction needs at least one member")
    return min(states, key=lambda state: (VERDICT_STRENGTH.get(state, -1), state))


def conjoin(claims: list[dict]) -> dict:
    """The cohort verdict: meet of members plus union of obligations.

    No member is summarised away. Every blocked member and every open
    obligation is returned by name, and the cohort verdict is never stronger
    than its weakest member.
    """
    if not claims:
        raise AlgebraError("a conjunction needs at least one member")
    states: list[str] = []
    obligations: dict[str, dict] = {}
    blocked: list[dict] = []
    members: list[dict] = []
    measure_conflicts = _measure_conflicts(claims)
    for claim in claims:
        verdict = claim.get("verdict", {})
        state = str(verdict.get("state"))
        if state not in VERDICT_STRENGTH and state not in ABSORBING_VERDICTS:
            raise AlgebraError(f"unknown verdict state {state!r} in {claim.get('id')}")
        states.append(state)
        members.append({"id": claim.get("id"), "verdict": state, "modality": claim.get("modality")})
        for obligation in claim.get("obligations", []):
            if isinstance(obligation, dict) and obligation.get("state") == "OPEN":
                obligations[str(obligation.get("id"))] = obligation
        open_for_claim = [
            obligation.get("id")
            for obligation in claim.get("obligations", [])
            if isinstance(obligation, dict) and obligation.get("state") == "OPEN"
        ]
        if (
            open_for_claim
            or state in ABSORBING_VERDICTS
            or VERDICT_STRENGTH.get(state, -1) < VERDICT_STRENGTH["ESTABLISHED"]
        ):
            blocked.append(
                {
                    "id": claim.get("id"),
                    "verdict": state,
                    "open_obligations": sorted(str(item) for item in open_for_claim),
                }
            )
    conflicted_ids = sorted(
        {claim_id for conflict in measure_conflicts for claim_id in conflict["claims"]}
    )
    if measure_conflicts:
        # Two members assert incompatible values for one single-valued measure.
        # Their conjunction is a contradiction; a member's positive verdict may
        # not absorb it.
        states.append("CONTRADICTED")
        for claim_id in conflicted_ids:
            if not any(str(item["id"]) == claim_id for item in blocked):
                member = next(
                    (item for item in members if str(item["id"]) == claim_id), None
                )
                blocked.append(
                    {
                        "id": claim_id,
                        "verdict": member["verdict"] if member else "UNKNOWN",
                        "open_obligations": [],
                        "measure_conflict": True,
                    }
                )
    result = _meet_verdicts(states)
    weakest = sorted(
        member["id"]
        for member in members
        if member["verdict"] == result
        or member["verdict"] in ABSORBING_VERDICTS
        or str(member["id"]) in conflicted_ids
    )
    payload = {
        "verdict": result,
        "obligations": [obligations[key] for key in sorted(obligations)],
        "blocked_by": sorted(blocked, key=lambda item: str(item["id"])),
        "weakest": weakest,
        "members": sorted(members, key=lambda item: str(item["id"])),
        "aggregation": "forbidden",
    }
    if measure_conflicts:
        payload["measure_conflicts"] = measure_conflicts
    return payload


def invalidated_claims(claims: list[dict], changed: Iterable[str]) -> dict:
    """Conservative transitive invalidation.

    A claim is invalidated when a changed identity matches any dependency it
    names, any evidence path it cites, its source commit, or any artefact
    digest it binds. Dependents are then invalidated transitively. No
    non-impact is inferred: only an explicit, independently checkable
    exclusion would prevent propagation, and invalidation accepts none.
    """
    changed_set = {item for item in changed if isinstance(item, str) and item}
    direct: set[str] = set()
    dependents: dict[str, list[str]] = {}
    for claim in claims:
        claim_id = str(claim.get("id"))
        invalidation = claim.get("invalidation", {})
        dependencies = invalidation.get("depends_on", []) if isinstance(invalidation, dict) else []
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                continue
            if dependency.get("kind") == "claim":
                dependents.setdefault(str(dependency.get("id")), []).append(claim_id)
            for token in (dependency.get("id"), dependency.get("sha256")):
                if isinstance(token, str) and token in changed_set:
                    direct.add(claim_id)
        identity = claim.get("identity", {})
        source = identity.get("source", {}) if isinstance(identity, dict) else {}
        for token in (source.get("commit"), source.get("candidate"), source.get("tree_sha256")):
            if isinstance(token, str) and token in changed_set:
                direct.add(claim_id)
        for artefact in identity.get("artefacts", []) if isinstance(identity, dict) else []:
            if not isinstance(artefact, dict):
                continue
            for token in (artefact.get("sha256"), artefact.get("label"), artefact.get("path")):
                if isinstance(token, str) and token in changed_set:
                    direct.add(claim_id)
        for entry in claim.get("evidence", []):
            if not isinstance(entry, dict):
                continue
            for token in (entry.get("path"), entry.get("sha256")):
                if isinstance(token, str) and token in changed_set:
                    direct.add(claim_id)
        authority = claim.get("authority", {})
        if isinstance(authority, dict) and isinstance(authority.get("path"), str):
            if authority["path"] in changed_set:
                direct.add(claim_id)
        target = claim.get("target", {})
        if isinstance(target, dict) and isinstance(target.get("path"), str):
            if target["path"] in changed_set:
                direct.add(claim_id)

    invalidated = set(direct)
    frontier = sorted(direct)
    while frontier:
        node = frontier.pop()
        for dependent in dependents.get(node, []):
            if dependent not in invalidated:
                invalidated.add(dependent)
                frontier.append(dependent)
    return {
        "changed": sorted(changed_set),
        "invalidated": sorted(invalidated),
        "direct": sorted(direct),
        "transitive_only": sorted(invalidated - direct),
        "aggregation": "forbidden",
    }


def propagated_obligations(claims: list[dict]) -> dict:
    """Propagate a dependency's open obligations to its dependents.

    An exclusion is honoured only when it names the dependent, gives an
    argument and names an independently checkable procedure. Evidence is
    otherwise inherited, never waived.
    """
    by_id = {str(claim.get("id")): claim for claim in claims}
    dependents: dict[str, list[str]] = {}
    for claim in claims:
        invalidation = claim.get("invalidation", {})
        dependencies = invalidation.get("depends_on", []) if isinstance(invalidation, dict) else []
        for dependency in dependencies:
            if isinstance(dependency, dict) and dependency.get("kind") == "claim":
                dependents.setdefault(str(dependency.get("id")), []).append(str(claim.get("id")))

    propagated: dict[str, list[dict]] = {claim_id: [] for claim_id in by_id}
    # Fixpoint: an obligation travels along each non-excluded edge. The owning
    # claim travels with it, because the exclusion witness binds that claim's
    # author and candidate, not the dependent's.
    frontier = [
        (claim_id, obligation, claim_id)
        for claim_id, claim in by_id.items()
        for obligation in claim.get("obligations", [])
        if isinstance(obligation, dict) and obligation.get("state") == "OPEN"
    ]
    seen: set[tuple[str, str, str]] = set()
    while frontier:
        source_id, obligation, owner_id = frontier.pop()
        for dependent in sorted(dependents.get(source_id, [])):
            key = (source_id, dependent, str(obligation.get("id")))
            if key in seen:
                continue
            seen.add(key)
            if _excluded(obligation, dependent, by_id.get(owner_id, {})):
                continue
            propagated[dependent].append(
                {
                    "from_claim": source_id,
                    "obligation": obligation,
                }
            )
            frontier.append((dependent, obligation, owner_id))
    def sort_key(item: dict) -> tuple[str, str]:
        return (str(item["from_claim"]), str(item["obligation"].get("id")))

    return {
        "propagated": {
            claim_id: sorted(items, key=sort_key)
            for claim_id, items in sorted(propagated.items())
            if items
        },
        "aggregation": "forbidden",
    }


def _excluded(obligation: dict, dependent: str, claim: dict) -> bool:
    """An exclusion stops propagation only when its witness is admitted.

    The argument and procedure strings are necessary but not sufficient: the
    witness must be bound to this obligation and this candidate, carry a present
    result with its own digest, and name a reviewer other than the claim author.
    """
    for exclusion in obligation.get("exclusions", []):
        if not isinstance(exclusion, dict) or exclusion.get("claim") != dependent:
            continue
        argument = str(exclusion.get("argument", "")).strip()
        checkable = str(exclusion.get("checkable_by", "")).strip().lower()
        if not argument or checkable in UNCHECKABLE_MARKERS:
            continue
        if _witness_findings(claim, obligation, exclusion, "$"):
            continue
        return True
    return False


def contradiction_conflicts(claims: list[dict]) -> list[dict]:
    """Same property, scope subject and identity with different verdicts."""
    keys: dict[tuple[str, str, str, str], dict] = {}
    conflicts: list[dict] = []
    for claim in claims:
        identity = claim.get("identity", {})
        source = identity.get("source", {}) if isinstance(identity, dict) else {}
        scope = claim.get("scope", {})
        verdict = claim.get("verdict", {})
        key = (
            str(claim.get("property")),
            str(scope.get("subject")) if isinstance(scope, dict) else "",
            str(source.get("candidate")) if isinstance(source, dict) else "",
            str(source.get("commit")) if isinstance(source, dict) else "",
        )
        state = verdict.get("state") if isinstance(verdict, dict) else None
        if key in keys and keys[key]["verdict"] != state:
            conflicts.append(
                {
                    "property": key[0],
                    "scope_subject": key[1],
                    "candidate": key[2],
                    "commit": key[3],
                    "claims": sorted(
                        [
                            {"id": keys[key]["id"], "verdict": keys[key]["verdict"]},
                            {"id": claim.get("id"), "verdict": state},
                        ],
                        key=lambda item: str(item["id"]),
                    ),
                    "resolution": "hard error: preference may not resolve it",
                }
            )
        else:
            keys[key] = {"id": claim.get("id"), "verdict": state}
    conflicts.extend(_measure_conflicts(claims))
    return sorted(conflicts, key=lambda item: canonical(item))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def _payload(document: str, refusals: list[Refusal], claim_count: int) -> dict:
    by_rule: dict[str, int] = {}
    for refusal in refusals:
        by_rule[refusal["rule"]] = by_rule.get(refusal["rule"], 0) + 1
    return {
        "document": document,
        "valid": not refusals,
        "refusal_count": len(refusals),
        "refusals_by_rule": by_rule,
        "refusals": refusals,
        "claims": claim_count,
    }


def _validate(args: argparse.Namespace) -> int:
    document = Path(args.document).resolve()
    try:
        schema = load_json(Path(args.schema).resolve())
        doc = load_json(document)
    except JsonIntegrityError as exc:
        _emit(_payload(str(document), exc.findings, 0))
        return 1
    repo_root = None
    if not args.no_tree_check:
        repo_root = Path(args.repo_root).resolve() if args.repo_root else REPO_ROOT
    refusals = validate_document(doc, schema, repo_root=repo_root)
    claim_count = len(doc.get("claims", [])) if isinstance(doc, dict) else 0
    _emit(_payload(str(document), refusals, claim_count))
    return 0 if not refusals else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")
    for name in ("validate", "conjoin", "invalidate", "propagate", "contradictions"):
        command = sub.add_parser(name)
        command.add_argument("--document", default=str(DEFAULT_CLAIMS))
        command.add_argument("--schema", default=str(DEFAULT_SCHEMA))
        command.add_argument("--repo-root", default=None)
        command.add_argument(
            "--no-tree-check",
            action="store_true",
            help="do not re-derive cited digests from the stated identities",
        )
        if name == "invalidate":
            command.add_argument("--changed", action="append", default=[])
    args = parser.parse_args(argv)
    if args.command in (None, "validate"):
        if args.command is None:
            args.document = str(DEFAULT_CLAIMS)
            args.schema = str(DEFAULT_SCHEMA)
            args.repo_root = str(REPO_ROOT)
            args.no_tree_check = False
        return _validate(args)

    # Every operation answers only about a document that passed the same schema
    # and law validation as `validate`; an invalid document is refused, not
    # interpreted. Otherwise a subcommand could report a verdict from bytes the
    # validator would have rejected.
    document = Path(args.document).resolve()
    try:
        schema = load_json(Path(args.schema).resolve())
        doc = load_json(document)
    except JsonIntegrityError as exc:
        _emit(_payload(str(document), exc.findings, 0))
        return 1
    repo_root = None
    if not args.no_tree_check:
        repo_root = Path(args.repo_root).resolve() if args.repo_root else REPO_ROOT
    refusals = validate_document(doc, schema, repo_root=repo_root)
    if refusals:
        claim_count = len(doc.get("claims", [])) if isinstance(doc, dict) else 0
        _emit(_payload(str(document), refusals, claim_count))
        return 1

    claims = doc.get("claims", []) if isinstance(doc, dict) else []
    if args.command == "conjoin":
        _emit(conjoin(claims))
    elif args.command == "invalidate":
        _emit(invalidated_claims(claims, args.changed))
    elif args.command == "propagate":
        _emit(propagated_obligations(claims))
    elif args.command == "contradictions":
        conflicts = contradiction_conflicts(claims)
        _emit({"conflicts": conflicts, "hard_error": bool(conflicts)})
        return 0 if not conflicts else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
